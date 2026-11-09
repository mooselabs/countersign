//! The request an approver is given.

use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::display::{self, DisplayView};

/// What a request asks for. Config chooses a chain per kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalKind {
    /// Inject values into a child process for a TTL.
    Use,
    /// Print a raw value to the caller.
    Reveal,
    /// Change the store.
    Mutate,
    /// Export the whole store.
    Export,
}

impl ApprovalKind {
    /// The config and wire name: "use", "reveal", "mutate", "export".
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalKind::Use => "use",
            ApprovalKind::Reveal => "reveal",
            ApprovalKind::Mutate => "mutate",
            ApprovalKind::Export => "export",
        }
    }
}

impl fmt::Display for ApprovalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The session a request came from, as `cnd` resolved it from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRef {
    /// countersign session id, e.g. "s_7k2mq9d4x1ha".
    pub session_id: String,
    /// The developer's uid (the anchor's uid).
    pub uid: u32,
    /// The anchor process: the long-lived agent, e.g. `claude`.
    pub anchor_pid: u32,
    /// Field 22 of `/proc/PID/stat` for the anchor, in clock ticks since boot.
    /// polkit compares it to detect pid reuse.
    pub anchor_start_time: u64,
    /// The anchor's `comm`. Shown for display only.
    pub anchor_comm: String,
    /// The uid's logind graphical session, if cnd resolved one. Needed only by
    /// the polkit `session` subject mode.
    pub logind_session: Option<String>,
}

/// Everything an approver is given. Built once per request by `cnd`.
///
/// The digest is computed from the canonical bytes here, so the two cannot
/// disagree. Fields are read through accessors.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    request_id: String,
    canonical: Vec<u8>,
    digest: [u8; 32],
    digest_short: String,
    code: String,
    kind: ApprovalKind,
    display: DisplayView,
    session: SessionRef,
    expires_at: SystemTime,
}

impl ApprovalRequest {
    /// Builds a request. `canonical` is the RFC 8785 (JCS) encoding of the
    /// canonical request (design.md section 6); `request_id` and `code` are
    /// the ones inside it.
    pub fn new(
        request_id: impl Into<String>,
        canonical: Vec<u8>,
        code: &str,
        kind: ApprovalKind,
        display: DisplayView,
        session: SessionRef,
        expires_at: SystemTime,
    ) -> Self {
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        Self {
            request_id: request_id.into(),
            digest_short: digest_short(&digest),
            canonical,
            digest,
            // Daemon-generated, but it goes into a dialog, so clean it anyway.
            code: display::clean_limited(code, 16),
            kind,
            display,
            session,
            expires_at,
        }
    }

    /// The request id from the canonical request.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The JCS bytes of the canonical request.
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// SHA-256 of [`Self::canonical`]. The FIDO2 clientDataHash in Phase 2.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// "3QF8-ZK2M": the digest's first 8 Crockford base32 characters.
    pub fn digest_short(&self) -> &str {
        &self.digest_short
    }

    /// The request code, e.g. "K7M-Q2X".
    pub fn code(&self) -> &str {
        &self.code
    }

    /// What the request asks for.
    pub fn kind(&self) -> ApprovalKind {
        self.kind
    }

    /// The sanitised strings an approver may show.
    pub fn display(&self) -> &DisplayView {
        &self.display
    }

    /// The session the request came from.
    pub fn session(&self) -> &SessionRef {
        &self.session
    }

    /// When the request stops being approvable.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The human form of a digest: its first 40 bits as 8 Crockford base32
/// characters, most significant bits first, shown as `XXXX-XXXX`.
pub fn digest_short(digest: &[u8; 32]) -> String {
    let bits = digest[..5]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut out = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            out.push('-');
        }
        let idx = (bits >> (35 - 5 * i)) & 0x1f;
        out.push(char::from(CROCKFORD[idx as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_short_takes_the_first_40_bits() {
        let mut d = [0u8; 32];
        assert_eq!(digest_short(&d), "0000-0000");
        d[..5].copy_from_slice(&[0xff; 5]);
        assert_eq!(digest_short(&d), "ZZZZ-ZZZZ");
        // 0x08 0x86 0x42 0x98 0xE8 = 00001 00010 00011 00100 00101 00110 00111 01000
        d[..5].copy_from_slice(&[0x08, 0x86, 0x42, 0x98, 0xE8]);
        assert_eq!(digest_short(&d), "1234-5678");
        // Bytes after the fifth do not matter.
        d[5] = 0xff;
        assert_eq!(digest_short(&d), "1234-5678");
    }

    #[test]
    fn digest_is_sha256_of_canonical() {
        let req = ApprovalRequest::new(
            "r1",
            b"abc".to_vec(),
            "K7M-Q2X",
            ApprovalKind::Use,
            DisplayView::default(),
            SessionRef {
                session_id: "s_x".into(),
                uid: 1000,
                anchor_pid: 1,
                anchor_start_time: 2,
                anchor_comm: "claude".into(),
                logind_session: None,
            },
            SystemTime::now(),
        );
        // SHA-256("abc") = ba7816bf8f01cfea...
        assert_eq!(req.digest()[..4], [0xba, 0x78, 0x16, 0xbf]);
        assert_eq!(req.digest_short(), digest_short(req.digest()));
        assert_eq!(req.code(), "K7M-Q2X");
    }
}
