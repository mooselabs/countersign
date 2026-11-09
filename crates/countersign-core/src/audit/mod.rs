//! The audit log (audit.md): an append-only, hash-chained JSONL log in
//! numbered segments, with signed checkpoints.
//!
//! ```text
//! hash_n = SHA-256("countersign/audit/v1\0" || JCS(record_n without "hash"))
//! record_n.prev = hash_{n-1}       (64 zeros for seq 1)
//! ```
//!
//! Each line on disk is the JCS form of the record with `hash` included.
//! [`AuditLog`] writes it, [`verify_segments`] checks it, and
//! [`AuditLog::query`] reads it back with filters.

mod coalesce;
mod event;
mod query;
mod verify;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub use coalesce::{ListCoalescer, ListRecord};
pub use event::{ChainLink, Event, SessionRef, StoreChange};
pub use query::Query;
pub use verify::{
    BreakKind, CheckpointInfo, VerifyError, VerifyOptions, VerifyReport, parse_pubkey,
    verify_segments, verify_segments_with,
};

use countersign_proto::jcs::{self, JcsError};

use crate::encoding::b64;
use crate::time::{Clock, format_rfc3339_micros};
use event::Internal;

/// Record schema version.
pub const SCHEMA_VERSION: u64 = 1;
/// `prev` of the first record.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Name of the checkpoint public key file in the audit directory.
pub const PUBKEY_FILE: &str = "checkpoint.pub";
/// Default segment size limit.
pub const MAX_SEGMENT_BYTES: u64 = 64 << 20;

const HASH_DOMAIN: &[u8] = b"countersign/audit/v1\0";
const CHECKPOINT_DOMAIN: &str = "countersign/audit-checkpoint/v1";

/// An audit operation that failed. A failed append means the action it
/// records must not happen.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The existing log is not readable as a chain.
    #[error("audit log is damaged: {0}")]
    Corrupt(String),
    /// A record could not be encoded.
    #[error("audit record: {0}")]
    Encode(String),
    /// `checkpoint.pub` belongs to another key.
    #[error("{0} holds a different checkpoint key; this audit log belongs to another store")]
    KeyMismatch(PathBuf),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> AuditError + '_ {
    move |source| AuditError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Settings for [`AuditLog::open`].
#[derive(Debug, Clone)]
pub struct Options {
    /// Machine id, signed into checkpoints.
    pub host: String,
    /// Boot id; records carry its first 8 hex characters.
    pub boot_id: String,
    /// Checkpoint after this many records.
    pub checkpoint_every_records: u64,
    /// Checkpoint at least this often when records were written.
    pub checkpoint_interval: Duration,
    /// Close a segment at this size.
    pub max_segment_bytes: u64,
}

impl Options {
    /// Defaults from audit.md for this host and boot.
    pub fn new(host: impl Into<String>, boot_id: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            boot_id: boot_id.into(),
            checkpoint_every_records: 1000,
            checkpoint_interval: Duration::from_secs(3600),
            max_segment_bytes: MAX_SEGMENT_BYTES,
        }
    }
}

/// The position of a written record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// Its sequence number.
    pub seq: u64,
    /// Its hash, hex.
    pub hash: String,
}

/// The writer. One per audit directory; `cnd` owns it.
pub struct AuditLog {
    dir: PathBuf,
    opts: Options,
    clock: Arc<dyn Clock>,
    signer: Option<SigningKey>,
    file: File,
    segment: u32,
    segment_bytes: u64,
    segment_month: Option<String>,
    seq: u64,
    hash: String,
    since_checkpoint: u64,
    last_checkpoint_at: SystemTime,
    truncated: u64,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("dir", &self.dir)
            .field("segment", &self.segment)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

fn segment_name(n: u32) -> String {
    format!("{n:06}.jsonl")
}

/// Segment numbers present in `dir`, ascending.
pub(crate) fn list_segments(dir: &Path) -> Result<Vec<u32>, AuditError> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir).map_err(io_err(dir))? {
        let name = e.map_err(io_err(dir))?.file_name();
        let name = name.to_string_lossy();
        let num = name
            .strip_suffix(".jsonl")
            .filter(|n| n.len() == 6)
            .and_then(|n| n.parse().ok());
        if let Some(n) = num {
            v.push(n);
        }
    }
    v.sort_unstable();
    Ok(v)
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err(path))
}

impl AuditLog {
    /// Opens the log in `dir` (created 0700 if missing), continuing the chain
    /// from the last record. An unterminated last line, left by a crash
    /// during a write, is cut off; [`AuditLog::truncated_bytes`] says how
    /// much. Any other damage is an error.
    pub fn open(dir: &Path, opts: Options, clock: Arc<dyn Clock>) -> Result<Self, AuditError> {
        {
            use std::os::unix::fs::DirBuilderExt;
            if !dir.exists() {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .recursive(true)
                    .create(dir)
                    .map_err(io_err(dir))?;
            }
        }
        let now = clock.now();
        let segments = list_segments(dir)?;
        let segment = segments.last().copied().unwrap_or(1);
        let path = dir.join(segment_name(segment));
        let mut truncated = 0;
        let (mut seq, mut hash) = (0, GENESIS_PREV.to_owned());
        let (mut since_checkpoint, mut segment_month) = (0, None);
        if path.exists() {
            let mut bytes = fs::read(&path).map_err(io_err(&path))?;
            let keep = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
            if keep < bytes.len() {
                truncated = (bytes.len() - keep) as u64;
                bytes.truncate(keep);
                let f = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(io_err(&path))?;
                f.set_len(keep as u64).map_err(io_err(&path))?;
                f.sync_all().map_err(io_err(&path))?;
            }
            for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                let r: Value = serde_json::from_slice(line)
                    .map_err(|e| AuditError::Corrupt(format!("{}: {e}", path.display())))?;
                let field = |k: &str| {
                    r.get(k).cloned().ok_or_else(|| {
                        AuditError::Corrupt(format!("{}: record without {k}", path.display()))
                    })
                };
                seq = field("seq")?
                    .as_u64()
                    .ok_or_else(|| AuditError::Corrupt("seq is not a number".into()))?;
                hash = field("hash")?.as_str().unwrap_or_default().to_owned();
                let ts = field("ts")?.as_str().unwrap_or_default().to_owned();
                segment_month.get_or_insert_with(|| ts.get(..7).unwrap_or("").to_owned());
                if r.get("event").and_then(Value::as_str) == Some("checkpoint") {
                    since_checkpoint = 0;
                } else {
                    since_checkpoint += 1;
                }
            }
            if seq == 0 && segments.len() > 1 {
                return Err(AuditError::Corrupt(format!(
                    "{} is empty but earlier segments exist",
                    path.display()
                )));
            }
        }
        let file = open_append(&path)?;
        let segment_bytes = file.metadata().map_err(io_err(&path))?.len();
        Ok(Self {
            dir: dir.to_owned(),
            opts,
            clock,
            signer: None,
            file,
            segment,
            segment_bytes,
            segment_month,
            seq,
            hash,
            since_checkpoint,
            last_checkpoint_at: now,
            truncated,
        })
    }

    /// Bytes of an unterminated last line removed by [`AuditLog::open`].
    pub fn truncated_bytes(&self) -> u64 {
        self.truncated
    }

    /// The audit directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The last record's sequence number (0 when empty) and hash.
    pub fn head(&self) -> (u64, &str) {
        (self.seq, &self.hash)
    }

    /// Sets the checkpoint signing key from its seed
    /// ([`crate::store::Store::checkpoint_seed`]) and writes
    /// `checkpoint.pub` if it is missing. Refuses if `checkpoint.pub` holds
    /// another key. Until this is called, checkpoints are deferred.
    pub fn set_signer(&mut self, seed: &[u8; 32]) -> Result<String, AuditError> {
        let key = SigningKey::from_bytes(seed);
        let public = format!("ed25519:{}", b64(key.verifying_key().as_bytes()));
        let path = self.dir.join(PUBKEY_FILE);
        match fs::read_to_string(&path) {
            Ok(existing) if existing.trim() == public => {}
            Ok(_) => return Err(AuditError::KeyMismatch(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(&path)
                    .map_err(io_err(&path))?;
                f.write_all(format!("{public}\n").as_bytes())
                    .and_then(|()| f.sync_all())
                    .map_err(io_err(&path))?;
            }
            Err(e) => return Err(io_err(&path)(e)),
        }
        self.signer = Some(key);
        Ok(public)
    }

    /// Appends one record and `fdatasync`s it. Writes a checkpoint after it
    /// when `checkpoint_every_records` is reached, and rotates the segment
    /// first when it is full or a new month began.
    pub fn append(
        &mut self,
        session: Option<&SessionRef>,
        event: &Event,
    ) -> Result<Written, AuditError> {
        let now = self.clock.now();
        self.rotate_if_needed(now)?;
        let w = self.write_record(now, session, event)?;
        self.since_checkpoint += 1;
        if self.since_checkpoint >= self.opts.checkpoint_every_records {
            self.checkpoint()?;
        }
        Ok(w)
    }

    /// Writes a checkpoint if the interval has passed since the last one and
    /// records were written since. `cnd` calls this from a timer.
    pub fn maybe_checkpoint(&mut self) -> Result<Option<Written>, AuditError> {
        let due = self
            .clock
            .now()
            .duration_since(self.last_checkpoint_at)
            .unwrap_or_default()
            >= self.opts.checkpoint_interval;
        if due && self.since_checkpoint > 0 {
            self.checkpoint()
        } else {
            Ok(None)
        }
    }

    /// Writes a checkpoint now (for `daemon.stop`), unless there is no
    /// signing key yet or nothing to cover.
    pub fn checkpoint(&mut self) -> Result<Option<Written>, AuditError> {
        let Some(key) = &self.signer else {
            return Ok(None);
        };
        if self.seq == 0 {
            return Ok(None);
        }
        let now = self.clock.now();
        let ts = format_rfc3339_micros(now);
        let payload = checkpoint_payload(&self.opts.host, self.seq, &self.hash, &ts);
        let sig = key.sign(&payload);
        let body = Internal::Checkpoint {
            upto_seq: self.seq,
            upto_hash: self.hash.clone(),
            host: self.opts.host.clone(),
            sig: format!("ed25519:{}", b64(&sig.to_bytes())),
        };
        let w = self.write_record_at(&ts, None, &body)?;
        self.since_checkpoint = 0;
        self.last_checkpoint_at = now;
        Ok(Some(w))
    }

    fn rotate_if_needed(&mut self, now: SystemTime) -> Result<(), AuditError> {
        if self.segment_bytes == 0 {
            return Ok(());
        }
        let month = format_rfc3339_micros(now)[..7].to_owned();
        let full = self.segment_bytes >= self.opts.max_segment_bytes;
        let new_month = self.segment_month.as_deref().is_some_and(|m| m != month);
        if !full && !new_month {
            return Ok(());
        }
        if self.since_checkpoint > 0 {
            self.checkpoint()?;
        }
        let last_hash = self.hash.clone();
        let next = self.segment + 1;
        let path = self.dir.join(segment_name(next));
        self.file = open_append(&path)?;
        File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(io_err(&self.dir))?;
        self.segment = next;
        self.segment_bytes = 0;
        self.segment_month = None;
        let body = Internal::SegmentOpen {
            segment: segment_name(next),
            prev_segment_last_hash: last_hash,
        };
        self.write_record(now, None, &body)?;
        Ok(())
    }

    fn write_record(
        &mut self,
        now: SystemTime,
        session: Option<&SessionRef>,
        body: &impl Serialize,
    ) -> Result<Written, AuditError> {
        let ts = format_rfc3339_micros(now);
        self.write_record_at(&ts, session, body)
    }

    fn write_record_at(
        &mut self,
        ts: &str,
        session: Option<&SessionRef>,
        body: &impl Serialize,
    ) -> Result<Written, AuditError> {
        let Value::Object(mut rec) =
            serde_json::to_value(body).map_err(|e| AuditError::Encode(e.to_string()))?
        else {
            return Err(AuditError::Encode("event is not an object".into()));
        };
        let seq = self.seq + 1;
        let boot: String = self
            .opts
            .boot_id
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let common = [
            ("v", Value::from(SCHEMA_VERSION)),
            ("seq", Value::from(seq)),
            ("ts", Value::from(ts)),
            ("boot", Value::from(boot)),
            (
                "session",
                serde_json::to_value(session).map_err(|e| AuditError::Encode(e.to_string()))?,
            ),
            ("prev", Value::from(self.hash.clone())),
        ];
        for (k, v) in common {
            if rec.insert(k.to_owned(), v).is_some() {
                return Err(AuditError::Encode(format!("event field {k} is reserved")));
            }
        }
        let hash = record_hash(&rec).map_err(|e| AuditError::Encode(e.to_string()))?;
        rec.insert("hash".into(), Value::from(hash.clone()));
        let mut line = jcs::value_to_vec(&Value::Object(rec))
            .map_err(|e| AuditError::Encode(e.to_string()))?;
        line.push(b'\n');
        let path = self.dir.join(segment_name(self.segment));
        self.file
            .write_all(&line)
            .and_then(|()| self.file.sync_data())
            .map_err(io_err(&path))?;
        self.segment_bytes += line.len() as u64;
        self.segment_month
            .get_or_insert_with(|| ts.get(..7).unwrap_or("").to_owned());
        self.seq = seq;
        self.hash = hash.clone();
        Ok(Written { seq, hash })
    }

    /// Raw lines of every record with `seq >= from_seq`, in order, for
    /// `audit_segments`. The bytes are what [`verify_segments`] reads.
    pub fn segments_from(&self, from_seq: u64) -> Result<Vec<u8>, AuditError> {
        let mut out = Vec::new();
        for n in list_segments(&self.dir)? {
            let path = self.dir.join(segment_name(n));
            let bytes = fs::read(&path).map_err(io_err(&path))?;
            for line in bytes.split_inclusive(|&b| b == b'\n') {
                let seq = serde_json::from_slice::<Value>(line)
                    .ok()
                    .and_then(|v| v.get("seq").and_then(Value::as_u64));
                // A line that does not parse is passed through, so the
                // verifier reports it.
                if seq.is_none_or(|s| s >= from_seq) {
                    out.extend_from_slice(line);
                }
            }
        }
        Ok(out)
    }
}

/// `SHA-256("countersign/audit/v1\0" || JCS(record without "hash"))`, hex.
pub(crate) fn record_hash(rec: &Map<String, Value>) -> Result<String, JcsError> {
    let mut rec = rec.clone();
    rec.remove("hash");
    let mut h = Sha256::new();
    h.update(HASH_DOMAIN);
    h.update(jcs::value_to_vec(&Value::Object(rec))?);
    Ok(hex(&h.finalize()))
}

pub(crate) fn checkpoint_payload(host: &str, upto_seq: u64, upto_hash: &str, ts: &str) -> Vec<u8> {
    let v = serde_json::json!({
        "domain": CHECKPOINT_DOMAIN,
        "host": host,
        "upto_seq": upto_seq,
        "upto_hash": upto_hash,
        "ts": ts,
    });
    jcs::value_to_vec(&v).expect("small integers and strings only")
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
