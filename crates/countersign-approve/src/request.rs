//! The request an approver is given.

use std::time::SystemTime;

use countersign_proto::{ApprovalKind, Digest};

use crate::display::{self, DisplayView};

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
    /// A logind session for the `session` subject mode. When `None`, the
    /// polkit adapter uses the uid's graphical session (logind's `Display`),
    /// which is also the session `require_wayland` checks.
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
        let digest = Digest::of(&canonical);
        Self {
            request_id: request_id.into(),
            digest_short: digest.short(),
            canonical,
            digest: digest.0,
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

    /// "3QF8-ZK2M": [`countersign_proto::Digest::short`] of the digest, the
    /// same function `cn` uses, so the dialog and `cn approve` agree.
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(req.digest_short(), Digest(*req.digest()).short());
        assert_eq!(req.code(), "K7M-Q2X");
    }
}
