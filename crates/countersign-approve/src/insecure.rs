//! The `insecure-auto` approver: decides without a human, after a delay.
//!
//! Only for end-to-end tests. It exists only with the `insecure-test` feature,
//! and that feature does not compile in release builds.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::{
    ApprovalRequest, ApproverError, ApproverInfo, BoxFuture, DaemonApprover, Evidence, Outcome,
};

/// What the approver answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InsecureDecision {
    /// Approve every request.
    #[default]
    Approve,
    /// Deny every request.
    Deny,
    /// Return [`ApproverError::Unavailable`], to test `any_of` fallbacks.
    Unavailable,
}

impl InsecureDecision {
    fn as_str(self) -> &'static str {
        match self {
            InsecureDecision::Approve => "approve",
            InsecureDecision::Deny => "deny",
            InsecureDecision::Unavailable => "unavailable",
        }
    }
}

/// Settings for one `insecure-auto` instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsecureAutoConfig {
    /// Instance name used in chains and evidence.
    pub name: String,
    /// What to answer.
    pub decision: InsecureDecision,
    /// How long to wait before answering.
    pub delay: Duration,
}

/// Answers every request with a fixed decision after a delay. Honours
/// cancellation and expiry like a real approver.
pub struct InsecureAutoApprover {
    config: InsecureAutoConfig,
}

impl InsecureAutoApprover {
    /// An approver with these settings.
    pub fn new(config: InsecureAutoConfig) -> Self {
        Self { config }
    }
}

impl DaemonApprover for InsecureAutoApprover {
    fn info(&self) -> ApproverInfo {
        ApproverInfo {
            name: self.config.name.clone(),
            adapter: "insecure-auto",
            trusted_display: false,
            notes: "insecure-test build: no human is asked".into(),
        }
    }

    fn present<'a>(
        &'a self,
        req: &'a ApprovalRequest,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Outcome, ApproverError>> {
        Box::pin(async move {
            let remaining = match req.expires_at().duration_since(SystemTime::now()) {
                Ok(d) if !d.is_zero() => d,
                _ => return Err(ApproverError::Timeout),
            };
            if self.config.delay >= remaining {
                tokio::select! {
                    _ = cancel.cancelled() => return Err(ApproverError::Cancelled),
                    _ = tokio::time::sleep(remaining) => return Err(ApproverError::Timeout),
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return Err(ApproverError::Cancelled),
                _ = tokio::time::sleep(self.config.delay) => {}
            }
            let evidence = Evidence {
                approver: self.config.name.clone(),
                adapter: "insecure-auto",
                at: SystemTime::now(),
                detail: serde_json::json!({
                    "mode": "insecure-test",
                    "decision": self.config.decision.as_str(),
                    "delay_ms": u64::try_from(self.config.delay.as_millis()).unwrap_or(u64::MAX),
                }),
            };
            match self.config.decision {
                InsecureDecision::Approve => Ok(Outcome::Approved(evidence)),
                InsecureDecision::Deny => Ok(Outcome::Denied(evidence)),
                InsecureDecision::Unavailable => Err(ApproverError::Unavailable(
                    "insecure-auto configured as unavailable".into(),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApprovalKind, DisplayView, SessionRef};

    fn request(expires_in: Duration) -> ApprovalRequest {
        ApprovalRequest::new(
            "r1",
            b"{}".to_vec(),
            "K7M-Q2X",
            ApprovalKind::Use,
            DisplayView::default(),
            SessionRef {
                session_id: "s_x".into(),
                uid: 1000,
                anchor_pid: 1,
                anchor_start_time: 1,
                anchor_comm: "claude".into(),
                logind_session: None,
            },
            SystemTime::now() + expires_in,
        )
    }

    fn approver(decision: InsecureDecision, delay_ms: u64) -> InsecureAutoApprover {
        InsecureAutoApprover::new(InsecureAutoConfig {
            name: "auto".into(),
            decision,
            delay: Duration::from_millis(delay_ms),
        })
    }

    #[tokio::test]
    async fn approves_and_denies_after_the_delay() {
        let req = request(Duration::from_secs(60));
        let out = approver(InsecureDecision::Approve, 10)
            .present(&req, CancellationToken::new())
            .await
            .unwrap();
        assert!(out.is_approved());
        assert_eq!(out.evidence().adapter, "insecure-auto");
        assert_eq!(out.evidence().detail["mode"], "insecure-test");
        let out = approver(InsecureDecision::Deny, 0)
            .present(&req, CancellationToken::new())
            .await
            .unwrap();
        assert!(!out.is_approved());
        let err = approver(InsecureDecision::Unavailable, 0)
            .present(&req, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, ApproverError::Unavailable(_)));
    }

    #[tokio::test]
    async fn honours_cancel_and_expiry() {
        let req = request(Duration::from_secs(60));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = approver(InsecureDecision::Approve, 10_000)
            .present(&req, cancel)
            .await
            .unwrap_err();
        assert_eq!(err, ApproverError::Cancelled);

        let req = request(Duration::from_millis(50));
        let err = approver(InsecureDecision::Approve, 10_000)
            .present(&req, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(err, ApproverError::Timeout);
    }
}
