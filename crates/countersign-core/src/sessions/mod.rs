//! Session anchor discovery (design.md section 5).
//!
//! From the connecting process, `cnd` walks parent links in `/proc` to the
//! *anchor*: the process a session belongs to.
//!
//! 1. A process registered by `cn session exec` (`session_register`) is an
//!    anchor. The nearest registered process on the walk wins.
//! 2. If the walk finds none, the nearest process that a configured matcher
//!    accepts (`comm`, `cmdline_regex`) is the anchor.
//! 3. Otherwise there is no session (`no_session`).
//!
//! The walk stops at pid 1, at a process of another uid, or after
//! [`MAX_STEPS`] steps. Each step requires the parent to have started no
//! later than the child, and re-reads the child afterwards to confirm it was
//! not reparented meanwhile; a failed check fails closed.
//!
//! The session id is derived from (boot id, anchor pid, anchor start time),
//! all read from the kernel, so it is stable for the anchor's life and
//! cannot be chosen by the client. `cnd` keeps a pidfd for the anchor and
//! checks liveness with it; [`Session::anchor`] gives it the pid and start
//! time to open and confirm one.
//!
//! **Human sessions.** design.md tells humans to run mutations (`cn add`,
//! `set`, `edit`, `rm`) "from a terminal outside any agent session", where
//! the walk finds no anchor. For that case [`human_session`] makes a pseudo
//! session anchored at the peer's parent (normally the human's shell), with
//! an `h_` id. `cnd` should accept it for mutation requests (and read-only
//! calls) only, never for `use` or `reveal` grants; [`crate::grants`]
//! enforces the grant half.

mod procfs;

use std::collections::{BTreeMap, HashMap};

use countersign_proto::ErrorCode;
use sha2::{Digest, Sha256};

pub use procfs::{ProcError, ProcFs, ProcInfo, parse_stat};

use crate::audit::{ChainLink, SessionRef};
use crate::config::Matcher;
use crate::encoding::crockford;

/// Most parent steps in one walk.
pub const MAX_STEPS: usize = 64;
/// Most labels kept per session.
pub const MAX_LABELS: usize = 8;
/// Longest label value kept, in bytes.
pub const MAX_LABEL_LEN: usize = 128;

/// Why discovery failed.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The walk found no anchor. Carries the chain it walked.
    #[error("no session anchor above pid {}", .chain.first().map_or(0, |p| p.pid))]
    NoSession {
        /// Peer first, then its ancestors.
        chain: Vec<ProcInfo>,
    },
    /// The peer's `/proc` uid is not the uid the socket reported.
    #[error("peer {pid} has uid {found}, the socket said {expected}")]
    PeerMismatch {
        /// Peer pid.
        pid: u32,
        /// Uid from `SO_PEERCRED`.
        expected: u32,
        /// Uid in `/proc`.
        found: u32,
    },
    /// A parent started after its child (pid reuse), or a process was
    /// reparented during the walk.
    #[error("process chain changed during discovery at pid {0}")]
    ChainChanged(u32),
    /// Reading `/proc` failed (including the peer having exited).
    #[error(transparent)]
    Proc(#[from] ProcError),
}

impl SessionError {
    /// The protocol error code to send the client.
    pub fn code(&self) -> ErrorCode {
        match self {
            SessionError::PeerMismatch { .. } => ErrorCode::ForbiddenPeer,
            SessionError::Proc(ProcError::Io { .. } | ProcError::Format(_)) => ErrorCode::Internal,
            _ => ErrorCode::NoSession,
        }
    }
}

/// Anchors registered with `session_register`, keyed by (pid, start time).
#[derive(Debug, Default)]
pub struct Anchors {
    map: HashMap<(u32, u64), Option<String>>,
}

impl Anchors {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a process as an anchor, with an optional human label.
    pub fn register(&mut self, pid: u32, start_time: u64, label: Option<String>) {
        self.map.insert((pid, start_time), label);
    }

    /// Removes a registration (when the anchor exits).
    pub fn unregister(&mut self, pid: u32, start_time: u64) {
        self.map.remove(&(pid, start_time));
    }

    /// The registration for a process, if it has one: `Some(label)`.
    pub fn get(&self, pid: u32, start_time: u64) -> Option<&Option<String>> {
        self.map.get(&(pid, start_time))
    }

    /// Number of registrations.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// How a session's anchor was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorKind {
    /// Registered by `cn session exec`.
    Registered {
        /// The `--label` given.
        label: Option<String>,
    },
    /// Accepted by a configured matcher (shown as in config).
    Matched {
        /// The matcher, e.g. `comm = "claude"`.
        matcher: String,
    },
    /// No anchor: a human's pseudo session (see the module docs).
    Human,
}

/// A resolved session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// `s_` + 12 base32 characters, or `h_` + 12 for a human session.
    pub id: String,
    /// How the anchor was found.
    pub kind: AnchorKind,
    /// The anchor process.
    pub anchor: ProcInfo,
    /// The peer first, then each parent up to and including the anchor.
    pub chain: Vec<ProcInfo>,
    /// The boot id the id was derived from.
    pub boot_id: String,
}

impl Session {
    /// Whether this is a human pseudo session.
    pub fn is_human(&self) -> bool {
        self.kind == AnchorKind::Human
    }

    /// Whether the anchor was registered by `cn session exec`.
    pub fn registered(&self) -> bool {
        matches!(self.kind, AnchorKind::Registered { .. })
    }

    /// The `session` object for audit records.
    pub fn audit_ref(&self, labels: &BTreeMap<String, String>) -> SessionRef {
        SessionRef {
            id: self.id.clone(),
            anchor_pid: self.anchor.pid,
            anchor_comm: self.anchor.comm.clone(),
            registered: self.registered(),
            labels: labels.clone(),
        }
    }

    /// The chain as `session.start` records it.
    pub fn chain_links(&self) -> Vec<ChainLink> {
        self.chain
            .iter()
            .map(|p| ChainLink {
                pid: p.pid,
                comm: p.comm.clone(),
            })
            .collect()
    }
}

/// `prefix` + the first 12 lower-case base32 characters of
/// `SHA-256("countersign/session/v1\0" || boot_id || "\0" || pid || "\0" || start_time)`,
/// with pid and start time in decimal.
pub fn session_id(prefix: &str, boot_id: &str, pid: u32, start_time: u64) -> String {
    let mut h = Sha256::new();
    h.update(b"countersign/session/v1\0");
    h.update(boot_id.as_bytes());
    h.update(format!("\0{pid}\0{start_time}").as_bytes());
    let mut s = crockford(&h.finalize()[..8]).to_ascii_lowercase();
    s.truncate(12);
    format!("{prefix}{s}")
}

/// Keeps the labels named in `label_env`: at most [`MAX_LABELS`], values
/// cut to [`MAX_LABEL_LEN`] bytes of printable ASCII (other characters
/// dropped). Labels are untrusted; this only bounds what reaches the audit
/// log and the approval display.
pub fn filter_labels(
    label_env: &[String],
    labels: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    labels
        .iter()
        .filter(|(k, _)| label_env.iter().any(|e| e == *k))
        .take(MAX_LABELS)
        .map(|(k, v)| {
            let mut clean: String = v
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .collect();
            clean.truncate(MAX_LABEL_LEN);
            (k.clone(), clean)
        })
        .collect()
}

/// Inputs to discovery.
#[derive(Debug, Clone, Copy)]
pub struct Discovery<'a> {
    /// Where `/proc` is.
    pub proc: &'a ProcFs,
    /// Registered anchors.
    pub anchors: &'a Anchors,
    /// Configured matchers.
    pub matchers: &'a [Matcher],
}

impl Discovery<'_> {
    /// Finds the session of the peer `pid`, whose uid the socket reported
    /// as `uid`.
    pub fn discover(&self, pid: u32, uid: u32) -> Result<Session, SessionError> {
        let boot_id = self.proc.boot_id()?;
        let chain = self.walk(pid, uid, |p, _| {
            self.anchors.get(p.pid, p.start_time).is_some()
        })?;
        let last = chain.last().expect("chain has the peer");
        if let Some(label) = self.anchors.get(last.pid, last.start_time) {
            let kind = AnchorKind::Registered {
                label: label.clone(),
            };
            return Ok(self.session(&boot_id, &chain, kind));
        }
        let matched = chain.iter().enumerate().find_map(|(i, p)| {
            let cmdline = self.proc.cmdline(p.pid).unwrap_or_default();
            self.matchers
                .iter()
                .find(|m| m.matches(&p.comm, &cmdline))
                .map(|m| (i, m.to_string()))
        });
        match matched {
            Some((i, matcher)) => {
                Ok(self.session(&boot_id, &chain[..=i], AnchorKind::Matched { matcher }))
            }
            None => Err(SessionError::NoSession { chain }),
        }
    }

    fn session(&self, boot_id: &str, chain: &[ProcInfo], kind: AnchorKind) -> Session {
        let anchor = chain.last().expect("chain has the peer").clone();
        let prefix = if kind == AnchorKind::Human {
            "h_"
        } else {
            "s_"
        };
        Session {
            id: session_id(prefix, boot_id, anchor.pid, anchor.start_time),
            kind,
            anchor,
            chain: chain.to_vec(),
            boot_id: boot_id.to_owned(),
        }
    }

    /// The peer and its same-uid ancestors, below pid 1, at most
    /// [`MAX_STEPS`] steps, ending early at the first process for which
    /// `stop(process, chain length)` is true.
    fn walk(
        &self,
        pid: u32,
        uid: u32,
        mut stop: impl FnMut(&ProcInfo, usize) -> bool,
    ) -> Result<Vec<ProcInfo>, SessionError> {
        let peer = self.proc.process(pid)?;
        if peer.uid != uid || peer.euid != uid {
            return Err(SessionError::PeerMismatch {
                pid,
                expected: uid,
                found: peer.euid,
            });
        }
        let mut chain = vec![peer];
        for _ in 0..MAX_STEPS {
            let child = chain.last().expect("non-empty");
            if stop(child, chain.len()) || child.pid == 1 || child.ppid <= 1 {
                break;
            }
            let parent = match self.proc.process(child.ppid) {
                Ok(p) => p,
                // The parent exited, so the child is being reparented.
                Err(ProcError::Gone(p)) => return Err(SessionError::ChainChanged(p)),
                Err(e) => return Err(e.into()),
            };
            if parent.start_time > child.start_time {
                return Err(SessionError::ChainChanged(parent.pid));
            }
            let again = self.proc.process(child.pid)?;
            if again.start_time != child.start_time || again.ppid != child.ppid {
                return Err(SessionError::ChainChanged(child.pid));
            }
            if parent.uid != uid || parent.euid != uid {
                break;
            }
            chain.push(parent);
        }
        Ok(chain)
    }

    /// A human pseudo session for a peer with no anchor: anchored at the
    /// peer's parent when it has the same uid (the shell that ran `cn`),
    /// else at the peer itself. Call only after [`Discovery::discover`]
    /// returned [`SessionError::NoSession`], and only for requests a human
    /// session may make.
    pub fn human_session(&self, pid: u32, uid: u32) -> Result<Session, SessionError> {
        let boot_id = self.proc.boot_id()?;
        let chain = self.walk(pid, uid, |_, len| len == 2)?;
        Ok(self.session(&boot_id, &chain, AnchorKind::Human))
    }
}

#[cfg(test)]
mod tests;
