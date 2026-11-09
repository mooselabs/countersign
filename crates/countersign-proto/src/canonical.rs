//! The canonical request and its digest (design.md §6, "Request digest").
//!
//! `cnd` builds a [`CanonicalRequest`] when it creates a request and hashes
//! its JCS bytes. The approver signs that digest and the human compares its
//! short form across every display. `cn` gets the same struct back from
//! `get_request` and recomputes the digest, so both sides must produce the
//! same bytes; that is why the type lives here.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::jcs::{self, JcsError};
use crate::{CROCKFORD, Mode, Timestamp};

/// The `domain` of every canonical request.
pub const APPROVE_DOMAIN: &str = "countersign/approve/v1";

/// What an approval allows. `use` and `reveal` create grants; `mutate`
/// changes the store; `export` writes the store out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// A `use` grant.
    Use,
    /// A `reveal` grant.
    Reveal,
    /// A store change (`add`, `set`, `edit`, `rm`, `import`).
    Mutate,
    /// An export of the whole store.
    Export,
}

impl ApprovalKind {
    /// Every kind.
    pub const ALL: [ApprovalKind; 4] = [Self::Use, Self::Reveal, Self::Mutate, Self::Export];

    /// The wire, config and audit name: `use`, `reveal`, `mutate`, `export`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Use => "use",
            Self::Reveal => "reveal",
            Self::Mutate => "mutate",
            Self::Export => "export",
        }
    }
}

impl From<Mode> for ApprovalKind {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Use => Self::Use,
            Mode::Reveal => Self::Reveal,
        }
    }
}

impl fmt::Display for ApprovalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A session anchor as `cnd` resolved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Process id.
    pub pid: u32,
    /// Start time, field 22 of `/proc/PID/stat` (clock ticks since boot).
    pub starttime: u64,
    /// `/proc/PID/comm` at discovery.
    pub comm: String,
    /// True when `cn session exec` registered it; false when a matcher found it.
    pub registered: bool,
}

/// The request an approver signs, field for field as in design.md §6.
///
/// Optional fields: `cwd` is `null` when the client reported none;
/// `ttl_seconds` is present for `use` and `reveal` only; `operation` is
/// present for `mutate` and `export` only (e.g. `add clickhouse-prod`). An
/// absent optional field is left out of the canonical bytes, not written as
/// `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalRequest {
    /// Always [`APPROVE_DOMAIN`].
    pub domain: String,
    /// 128-bit random id, `r_` plus base32.
    pub request_id: String,
    /// The human-facing code, `K7M-Q2X`.
    pub code: String,
    /// `/etc/machine-id`.
    pub host: String,
    /// `/proc/sys/kernel/random/boot_id`.
    pub boot_id: String,
    /// Session id, `s_...`.
    pub session: String,
    /// The session's anchor.
    pub anchor: Anchor,
    /// Client-reported working directory (untrusted).
    pub cwd: Option<String>,
    /// Secret names. Sorted when canonicalised.
    pub secrets: Vec<String>,
    /// What the approval allows.
    pub mode: ApprovalKind,
    /// Grant lifetime, for `use` and `reveal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// The store operation, for `mutate` and `export`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Agent-supplied reason (untrusted).
    pub reason: String,
    /// When the request was created.
    pub created_at: Timestamp,
    /// When the pending request lapses.
    pub expires_at: Timestamp,
    /// 256-bit random value from `cnd`, base64url without padding.
    pub nonce: String,
}

impl CanonicalRequest {
    /// The RFC 8785 bytes the digest covers. `secrets` is sorted by byte
    /// value first, so the order the caller kept does not matter.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JcsError> {
        let mut sorted = self.clone();
        sorted.secrets.sort();
        jcs::to_vec(&sorted)
    }

    /// `SHA-256(JCS(request))`.
    pub fn digest(&self) -> Result<Digest, JcsError> {
        Ok(Digest::of(&self.canonical_bytes()?))
    }
}

/// A SHA-256 request digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// SHA-256 of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Lower-case hex, as the audit log records it.
    pub fn hex(&self) -> String {
        use fmt::Write;
        self.0.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// The short form for humans: the first 8 Crockford base32 characters of
    /// the digest (its first 40 bits, most significant bit first), shown as
    /// `XXXX-XXXX`.
    pub fn short(&self) -> String {
        let bits = self.0[..5]
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let mut out = String::with_capacity(9);
        for i in 0..8 {
            if i == 4 {
                out.push('-');
            }
            let index = (bits >> (35 - 5 * i)) & 0x1f;
            out.push(char::from(CROCKFORD[index as usize]));
        }
        out
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> CanonicalRequest {
        CanonicalRequest {
            domain: APPROVE_DOMAIN.into(),
            request_id: "r_q4m8a1b2c3d4e5f6g7h8j9k0mn".into(),
            code: "K7M-Q2X".into(),
            host: "4f1c2a9e0b7d4e3f8a6b5c4d3e2f1a0b".into(),
            boot_id: "5e1c9a07-1d2e-4f3a-9b8c-7d6e5f4a3b2c".into(),
            session: "s_7k2mq9d4x1ha".into(),
            anchor: Anchor {
                pid: 41210,
                starttime: 8_812_345,
                comm: "claude".into(),
                registered: true,
            },
            cwd: Some("/home/patrick/projects/x".into()),
            secrets: vec!["github-token".into(), "clickhouse-prod".into()],
            mode: ApprovalKind::Use,
            ttl_seconds: Some(3600),
            operation: None,
            reason: "run the drift report against prod".into(),
            created_at: "2026-11-08T09:20:11Z".parse().unwrap(),
            expires_at: "2026-11-08T09:25:11Z".parse().unwrap(),
            nonce: "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9z0x1c".into(),
        }
    }

    const EXAMPLE_JCS: &str = concat!(
        r#"{"anchor":{"comm":"claude","pid":41210,"registered":true,"starttime":8812345},"#,
        r#""boot_id":"5e1c9a07-1d2e-4f3a-9b8c-7d6e5f4a3b2c","code":"K7M-Q2X","#,
        r#""created_at":"2026-11-08T09:20:11Z","cwd":"/home/patrick/projects/x","#,
        r#""domain":"countersign/approve/v1","expires_at":"2026-11-08T09:25:11Z","#,
        r#""host":"4f1c2a9e0b7d4e3f8a6b5c4d3e2f1a0b","mode":"use","#,
        r#""nonce":"q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9z0x1c","#,
        r#""reason":"run the drift report against prod","#,
        r#""request_id":"r_q4m8a1b2c3d4e5f6g7h8j9k0mn","#,
        r#""secrets":["clickhouse-prod","github-token"],"session":"s_7k2mq9d4x1ha","#,
        r#""ttl_seconds":3600}"#
    );

    #[test]
    fn canonical_bytes_are_golden() {
        let bytes = example().canonical_bytes().unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), EXAMPLE_JCS);
    }

    #[test]
    fn digest_is_sha256_of_the_canonical_bytes() {
        let d = example().digest().unwrap();
        assert_eq!(d, Digest::of(EXAMPLE_JCS.as_bytes()));
        // Pinned so an accidental change to the encoding shows up here.
        assert_eq!(d.hex(), GOLDEN_HEX);
        assert_eq!(d.short(), GOLDEN_SHORT);
    }

    // Computed independently: Python's hashlib.sha256 over EXAMPLE_JCS, and
    // Crockford base32 of its first 40 bits.
    const GOLDEN_HEX: &str = "011be541ce798b10dbe98ce97acbe961eb327ab157e0965a956cd3013d2d4465";
    const GOLDEN_SHORT: &str = "04DY-AGEE";

    #[test]
    fn secret_order_and_round_trip_do_not_change_the_digest() {
        let a = example();
        let mut b = a.clone();
        b.secrets.reverse();
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());

        let json = serde_json::to_string(&a).unwrap();
        let back: CanonicalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.digest().unwrap(), a.digest().unwrap());
    }

    #[test]
    fn optional_fields_are_left_out_not_null() {
        let mut r = example();
        r.mode = ApprovalKind::Mutate;
        r.ttl_seconds = None;
        r.operation = Some("add clickhouse-prod".into());
        r.cwd = None;
        let text = String::from_utf8(r.canonical_bytes().unwrap()).unwrap();
        assert!(!text.contains("ttl_seconds"), "{text}");
        assert!(
            text.contains(r#""operation":"add clickhouse-prod""#),
            "{text}"
        );
        assert!(text.contains(r#""cwd":null"#), "{text}");
        assert!(text.contains(r#""mode":"mutate""#), "{text}");
    }

    #[test]
    fn short_digest_takes_the_first_forty_bits() {
        let mut bytes = [0u8; 32];
        assert_eq!(Digest(bytes).short(), "0000-0000");
        bytes[..5].copy_from_slice(&[0xff; 5]);
        assert_eq!(Digest(bytes).short(), "ZZZZ-ZZZZ");
        // 0x08 0x42 0x10 0x84 0x21 = 00001 00001 00001 00001 00001 00001 00001 00001
        bytes[..5].copy_from_slice(&[0x08, 0x42, 0x10, 0x84, 0x21]);
        bytes[5] = 0xff;
        assert_eq!(Digest(bytes).short(), "1111-1111");
    }
}
