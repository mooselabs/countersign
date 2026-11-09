//! Chain verification for `cn audit verify` (audit.md, "Verifying").
//!
//! Input is the concatenated JSONL that `audit_segments` streams, or the
//! segment files read directly. Every line must be the canonical form of its
//! record; every `hash` must recompute; `seq` must be contiguous and `prev`
//! must equal the previous `hash`. The first failure is reported with its
//! line and `seq`.

use std::fmt;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use super::{GENESIS_PREV, checkpoint_payload, record_hash};
use crate::encoding::{canonical_json, unb64};

/// What to check besides the chain.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions<'a> {
    /// Checkpoint public key; when set, every checkpoint signature is
    /// checked.
    pub pubkey: Option<[u8; 32]>,
    /// Exported checkpoint lines (JSONL) to compare with the chain.
    pub exported_checkpoints: Option<&'a [u8]>,
}

/// The last checkpoint seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointInfo {
    /// The checkpoint record's own `seq`.
    pub seq: u64,
    /// The record it covers.
    pub upto_seq: u64,
    /// Its `ts`.
    pub ts: String,
}

/// A chain that verified.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifyReport {
    /// Records checked.
    pub records: u64,
    /// First `seq` (0 when there were no records).
    pub first_seq: u64,
    /// Last `seq`.
    pub last_seq: u64,
    /// Hash of the last record.
    pub head_hash: String,
    /// Whether the input starts at `seq` 1. If not, the first record's
    /// `prev` is taken on trust.
    pub from_genesis: bool,
    /// `segment.open` records seen.
    pub segment_opens: u64,
    /// Checkpoint records seen.
    pub checkpoints: u64,
    /// Checkpoints whose signature was checked (0 without a public key).
    pub signatures_verified: u64,
    /// The last checkpoint.
    pub last_checkpoint: Option<CheckpointInfo>,
    /// Exported checkpoints that matched the chain.
    pub exported_matched: u64,
    /// Exported checkpoints that fall before the first record checked.
    pub exported_not_covered: u64,
}

/// Why a chain failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    /// Not a JSON object with the common fields.
    Malformed(String),
    /// Valid JSON, but not the canonical bytes of that record: the line was
    /// edited.
    NotCanonical,
    /// `hash` does not match the record: the record was edited.
    Hash,
    /// `prev` is not the previous record's `hash`: a record before it was
    /// removed, reordered or rewritten.
    Prev,
    /// `seq` is not one more than the previous record's.
    Seq {
        /// The `seq` that should follow.
        expected: u64,
    },
    /// A checkpoint does not cover the record before it.
    CheckpointLink,
    /// A checkpoint signature does not verify.
    Signature,
    /// An exported checkpoint does not match the chain as it is now.
    Exported,
    /// An exported checkpoint covers records the chain no longer has: the
    /// log was truncated.
    Truncated,
}

/// A chain that did not verify. `line` counts from 1 in the input, or in
/// the exported checkpoint file for [`BreakKind::Exported`] and
/// [`BreakKind::Truncated`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct VerifyError {
    /// Line of the failure.
    pub line: usize,
    /// `seq` of the failing record, when it could be read.
    pub seq: Option<u64>,
    /// What failed.
    pub kind: BreakKind,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match &self.kind {
            BreakKind::Malformed(m) => format!("malformed record: {m}"),
            BreakKind::NotCanonical => "line is not in canonical form (edited)".into(),
            BreakKind::Hash => "hash does not match the record (edited)".into(),
            BreakKind::Prev => {
                "prev does not match the previous record (removed, reordered or rewritten)".into()
            }
            BreakKind::Seq { expected } => format!("expected seq {expected}"),
            BreakKind::CheckpointLink => "checkpoint does not cover the record before it".into(),
            BreakKind::Signature => "checkpoint signature does not verify".into(),
            BreakKind::Exported => "exported checkpoint does not match the chain".into(),
            BreakKind::Truncated => {
                "exported checkpoint covers records the log no longer has (truncated)".into()
            }
        };
        match self.seq {
            Some(s) => write!(f, "line {}, seq {s}: {what}", self.line),
            None => write!(f, "line {}: {what}", self.line),
        }
    }
}

/// Parses `checkpoint.pub`: `ed25519:<base64>` or bare base64 of 32 bytes.
pub fn parse_pubkey(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let b = unb64(s.strip_prefix("ed25519:").unwrap_or(s))?;
    b.try_into().ok()
}

/// Verifies the hash chain in `bytes`. Checkpoint signatures are not
/// checked; use [`verify_segments_with`] and a public key for that.
pub fn verify_segments(bytes: &[u8]) -> Result<VerifyReport, VerifyError> {
    verify_segments_with(bytes, &VerifyOptions::default())
}

/// Verifies the hash chain in `bytes`, checkpoint signatures when
/// `opts.pubkey` is set, and exported checkpoints when given.
pub fn verify_segments_with(
    bytes: &[u8],
    opts: &VerifyOptions<'_>,
) -> Result<VerifyReport, VerifyError> {
    let key = match opts.pubkey {
        Some(k) => Some(VerifyingKey::from_bytes(&k).map_err(|_| VerifyError {
            line: 0,
            seq: None,
            kind: BreakKind::Malformed("the public key is not an Ed25519 key".into()),
        })?),
        None => None,
    };
    let mut r = VerifyReport::default();
    let mut hashes: Vec<String> = Vec::new();
    let mut lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    if lines.last() == Some(&&b""[..]) {
        lines.pop();
    }
    for (i, line) in lines.into_iter().enumerate() {
        let lineno = i + 1;
        let fail = |seq, kind| VerifyError {
            line: lineno,
            seq,
            kind,
        };
        let malformed = |seq, m: &str| fail(seq, BreakKind::Malformed(m.to_owned()));
        let v: Value = serde_json::from_slice(line).map_err(|e| malformed(None, &e.to_string()))?;
        let Value::Object(rec) = &v else {
            return Err(malformed(None, "not an object"));
        };
        let seq = rec
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed(None, "no seq"))?;
        let str_field = |k: &str| {
            rec.get(k)
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(Some(seq), &format!("no {k}")))
        };
        let (prev, hash) = (str_field("prev")?, str_field("hash")?);
        let canon = canonical_json(&v).map_err(|e| malformed(Some(seq), &e.to_string()))?;
        if canon != line {
            return Err(fail(Some(seq), BreakKind::NotCanonical));
        }
        let want = record_hash(rec).map_err(|e| malformed(Some(seq), &e.to_string()))?;
        if want != hash {
            return Err(fail(Some(seq), BreakKind::Hash));
        }
        if r.records == 0 {
            r.first_seq = seq;
            r.from_genesis = seq == 1;
            if seq == 0 || (seq == 1 && prev != GENESIS_PREV) {
                return Err(fail(Some(seq), BreakKind::Prev));
            }
        } else {
            if seq != r.last_seq + 1 {
                return Err(fail(
                    Some(seq),
                    BreakKind::Seq {
                        expected: r.last_seq + 1,
                    },
                ));
            }
            if prev != r.head_hash {
                return Err(fail(Some(seq), BreakKind::Prev));
            }
        }
        match rec.get("event").and_then(Value::as_str) {
            Some("checkpoint") => {
                let upto_seq = rec.get("upto_seq").and_then(Value::as_u64);
                let upto_hash = rec.get("upto_hash").and_then(Value::as_str);
                if upto_seq != Some(seq - 1) || upto_hash != Some(prev) {
                    return Err(fail(Some(seq), BreakKind::CheckpointLink));
                }
                if let Some(key) = &key {
                    let host = str_field("host")?;
                    let ts = str_field("ts")?;
                    let payload = checkpoint_payload(host, seq - 1, prev, ts);
                    let sig = str_field("sig")?
                        .strip_prefix("ed25519:")
                        .and_then(unb64)
                        .and_then(|b| Signature::from_slice(&b).ok())
                        .ok_or_else(|| fail(Some(seq), BreakKind::Signature))?;
                    key.verify(&payload, &sig)
                        .map_err(|_| fail(Some(seq), BreakKind::Signature))?;
                    r.signatures_verified += 1;
                }
                r.checkpoints += 1;
                r.last_checkpoint = Some(CheckpointInfo {
                    seq,
                    upto_seq: seq - 1,
                    ts: str_field("ts")?.to_owned(),
                });
            }
            Some("segment.open") => {
                if rec.get("prev_segment_last_hash").and_then(Value::as_str) != Some(prev) {
                    return Err(fail(Some(seq), BreakKind::Prev));
                }
                r.segment_opens += 1;
            }
            Some(_) => {}
            None => return Err(malformed(Some(seq), "no event")),
        }
        r.records += 1;
        r.last_seq = seq;
        r.head_hash = hash.to_owned();
        hashes.push(hash.to_owned());
    }
    if let Some(exported) = opts.exported_checkpoints {
        check_exported(&mut r, &hashes, exported)?;
    }
    Ok(r)
}

fn check_exported(
    r: &mut VerifyReport,
    hashes: &[String],
    exported: &[u8],
) -> Result<(), VerifyError> {
    for (i, line) in exported.split(|&b| b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let fail = |seq, kind| VerifyError {
            line: i + 1,
            seq,
            kind,
        };
        let v: Value = serde_json::from_slice(line)
            .map_err(|e| fail(None, BreakKind::Malformed(e.to_string())))?;
        let (Some(upto_seq), Some(upto_hash)) = (
            v.get("upto_seq").and_then(Value::as_u64),
            v.get("upto_hash").and_then(Value::as_str),
        ) else {
            return Err(fail(
                None,
                BreakKind::Malformed("not a checkpoint record".into()),
            ));
        };
        if r.records == 0 || upto_seq > r.last_seq {
            return Err(fail(Some(upto_seq), BreakKind::Truncated));
        }
        if upto_seq < r.first_seq {
            r.exported_not_covered += 1;
            continue;
        }
        if hashes[(upto_seq - r.first_seq) as usize] != upto_hash {
            return Err(fail(Some(upto_seq), BreakKind::Exported));
        }
        r.exported_matched += 1;
    }
    Ok(())
}
