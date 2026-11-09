//! The `insecure-auto` approver: decides without a human, after a delay.
//!
//! Only for end-to-end tests. It exists only with the `insecure-test` feature,
//! and that feature does not compile in release builds.

use std::time::SystemTime;

use countersign_core::config::{AutoDecision, InsecureAutoConfig};
use tokio_util::sync::CancellationToken;

use crate::{
    ApprovalRequest, ApproverError, ApproverInfo, BoxFuture, DaemonApprover, Evidence, Outcome,
};

/// Answers every request with a fixed decision after a delay. Honours
/// cancellation and expiry like a real approver.
pub struct InsecureAutoApprover {
    name: String,
    config: InsecureAutoConfig,
}

impl InsecureAutoApprover {
    /// The instance `[approvers.NAME]` with these settings.
    pub fn new(name: impl Into<String>, config: InsecureAutoConfig) -> Self {
        Self {
            name: name.into(),
            config,
        }
    }
}

fn decision_str(d: AutoDecision) -> &'static str {
    match d {
        AutoDecision::Approve => "approve",
        AutoDecision::Deny => "deny",
        AutoDecision::Unavailable => "unavailable",
    }
}

impl DaemonApprover for InsecureAutoApprover {
    fn info(&self) -> ApproverInfo {
        ApproverInfo {
            name: self.name.clone(),
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
                approver: self.name.clone(),
                adapter: "insecure-auto",
                at: SystemTime::now(),
                detail: serde_json::json!({
                    "mode": "insecure-test",
                    "decision": decision_str(self.config.decision),
                    "delay_ms": u64::try_from(self.config.delay.as_millis()).unwrap_or(u64::MAX),
                }),
            };
            match self.config.decision {
                AutoDecision::Approve => Ok(Outcome::Approved(evidence)),
                AutoDecision::Deny => Ok(Outcome::Denied(evidence)),
                AutoDecision::Unavailable => Err(ApproverError::Unavailable(
                    "insecure-auto configured as unavailable".into(),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use countersign_proto::ApprovalKind;

    use super::*;
    use crate::{DisplayView, SessionRef};

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

    fn approver(decision: AutoDecision, delay_ms: u64) -> InsecureAutoApprover {
        InsecureAutoApprover::new(
            "auto",
            InsecureAutoConfig {
                decision,
                delay: Duration::from_millis(delay_ms),
            },
        )
    }

    #[tokio::test]
    async fn approves_and_denies_after_the_delay() {
        let req = request(Duration::from_secs(60));
        let out = approver(AutoDecision::Approve, 10)
            .present(&req, CancellationToken::new())
            .await
            .unwrap();
        assert!(out.is_approved());
        assert_eq!(out.evidence().adapter, "insecure-auto");
        assert_eq!(out.evidence().detail["mode"], "insecure-test");
        let out = approver(AutoDecision::Deny, 0)
            .present(&req, CancellationToken::new())
            .await
            .unwrap();
        assert!(!out.is_approved());
        let err = approver(AutoDecision::Unavailable, 0)
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
        let err = approver(AutoDecision::Approve, 10_000)
            .present(&req, cancel)
            .await
            .unwrap_err();
        assert_eq!(err, ApproverError::Cancelled);

        let req = request(Duration::from_millis(50));
        let err = approver(AutoDecision::Approve, 10_000)
            .present(&req, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(err, ApproverError::Timeout);
    }
}
