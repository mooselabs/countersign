//! Approvers for countersign. See `docs/approvers.md`.
//!
//! An approver turns a pending request into a human decision. `cnd` builds an
//! [`ApprovalRequest`] once per request, [`evaluate`]s the configured chain
//! (`countersign_core::config::Chain`) for the request's kind against a
//! [`Registry`] of approver instances, and audits every member's result from
//! the [`ChainReport`].
//!
//! Config types (chains, the polkit and insecure-auto settings) belong to
//! `countersign_core::config`; the request kind and digest to
//! `countersign_proto`. This crate only runs them.
//!
//! Phase 1 has one real adapter, [`polkit::PolkitApprover`], used for every
//! kind. The FIDO2 (`ClientApprover`) and `command` adapters come in Phase 2.
//! With the `insecure-test` feature, debug builds also get
//! `insecure::InsecureAutoApprover` for end-to-end tests.

#[cfg(all(feature = "insecure-test", not(debug_assertions)))]
compile_error!(
    "the insecure-test feature approves requests without a human; it is for debug builds only"
);

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

pub use tokio_util::sync::CancellationToken;

mod chain;
pub mod display;
#[cfg(feature = "insecure-test")]
pub mod insecure;
pub mod polkit;
mod request;

pub use chain::{ChainReport, Decision, MemberResult, Registry, evaluate};
pub use display::{DisplayInput, DisplayView};
pub use request::{ApprovalRequest, SessionRef};

/// A boxed, `Send` future, as returned by [`DaemonApprover::present`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A decision a human made through one approver.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The human approved this request.
    Approved(Evidence),
    /// The human said no (pressed Cancel, refused, failed to authenticate).
    Denied(Evidence),
}

impl Outcome {
    /// The evidence, whichever way the decision went.
    pub fn evidence(&self) -> &Evidence {
        match self {
            Outcome::Approved(e) | Outcome::Denied(e) => e,
        }
    }

    /// True for [`Outcome::Approved`].
    pub fn is_approved(&self) -> bool {
        matches!(self, Outcome::Approved(_))
    }
}

/// Why an approver gave no decision.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApproverError {
    /// Cannot run here: no polkit agent for the subject, polkitd not running,
    /// no graphical session. An `any_of` chain skips the member.
    #[error("approver unavailable: {0}")]
    Unavailable(String),
    /// The request expired before the human answered.
    #[error("the request expired before it was answered")]
    Timeout,
    /// The caller cancelled through the [`CancellationToken`]: another chain
    /// member decided, or `cnd` withdrew the request.
    #[error("cancelled")]
    Cancelled,
    /// A response arrived and failed verification. Audited as
    /// `request.approve_fail`. No Phase 1 adapter returns it.
    #[error("invalid approval: {0}")]
    Invalid(String),
    /// Bug, misconfiguration or system fault. Fails closed.
    #[error("approver failed: {0}")]
    Internal(String),
}

/// What an approver recorded about its decision. Goes into the audit log
/// with the `request.approve` / `request.deny` record.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// Configured instance name, e.g. "polkit".
    pub approver: String,
    /// Adapter type, e.g. "polkit" or "insecure-auto".
    pub adapter: &'static str,
    /// When the decision arrived.
    pub at: SystemTime,
    /// Adapter-specific detail. Never contains secret values.
    pub detail: serde_json::Value,
}

/// Describes an approver instance for `cn doctor` and the daemon log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverInfo {
    /// Configured instance name.
    pub name: String,
    /// Adapter type.
    pub adapter: &'static str,
    /// True when the request is shown on a surface the developer's uid cannot
    /// alter (see "The trusted-display problem" in docs/approvers.md).
    pub trusted_display: bool,
    /// One-line notes on strength and limits, for `cn doctor`.
    pub notes: String,
}

/// An approver that `cnd` drives from start to end (polkit; later `command`).
///
/// Phase 2 adds `ClientApprover` (FIDO2 through `cn approve`) and an
/// `Approver` enum over both; Phase 1 has daemon-driven approvers only.
pub trait DaemonApprover: Send + Sync {
    /// Name, adapter and strength notes.
    fn info(&self) -> ApproverInfo;

    /// Shows `req` to the human and waits for a decision.
    ///
    /// The future must end with [`ApproverError::Cancelled`] soon after
    /// `cancel` fires, and with [`ApproverError::Timeout`] at
    /// `req.expires_at()`. Dropping it must withdraw any prompt it raised.
    fn present<'a>(
        &'a self,
        req: &'a ApprovalRequest,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Outcome, ApproverError>>;
}
