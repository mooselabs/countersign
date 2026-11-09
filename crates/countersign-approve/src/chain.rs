//! Chains: which approvers a request needs, and how their answers combine.

use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;
use std::time::Duration;

use countersign_core::config::Chain;

use crate::{
    ApprovalRequest, ApproverError, BoxFuture, CancellationToken, DaemonApprover, Outcome,
};

/// How long an `any_of` waits for its other members to finish after it
/// cancelled them. Members still running after that are dropped, which makes
/// the polkit adapter withdraw its prompt in the background.
const DRAIN: Duration = Duration::from_secs(5);

/// Runs `chain` for `req`.
///
/// `all_of` members run one at a time, in order; the first denial or error
/// ends the chain. `any_of` members run at the same time; the first approval
/// or denial decides and cancels the rest, and unavailable members are
/// skipped. Cancelling `cancel` cancels every running member; the result is
/// then [`ApproverError::Cancelled`]. Each member honours `req.expires_at()`
/// itself. The future is `Send`; spawn it or await it in place.
pub async fn evaluate(
    chain: &Chain,
    registry: &Registry,
    req: &ApprovalRequest,
    cancel: &CancellationToken,
) -> ChainReport {
    let members = Mutex::new(Vec::new());
    let result = eval(chain, registry, req, cancel.child_token(), &members).await;
    ChainReport {
        result,
        members: members.into_inner().unwrap_or_else(PoisonError::into_inner),
    }
}

/// The approvers `cnd` configured, by instance name.
#[derive(Default, Clone)]
pub struct Registry {
    approvers: HashMap<String, Arc<dyn DaemonApprover>>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an approver under its `info().name`, returning any it replaced.
    pub fn insert(&mut self, approver: Arc<dyn DaemonApprover>) -> Option<Arc<dyn DaemonApprover>> {
        self.approvers.insert(approver.info().name, approver)
    }

    /// The approver with this instance name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn DaemonApprover>> {
        self.approvers.get(name)
    }

    /// Every configured approver.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn DaemonApprover>> {
        self.approvers.values()
    }
}

/// The chain's overall decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Create the grant (or apply the mutation).
    Approved,
    /// Deny the request.
    Denied,
}

/// One member's result, for the audit log.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberResult {
    /// Approver instance name.
    pub approver: String,
    /// What it returned. Members cancelled after the chain decided show
    /// [`ApproverError::Cancelled`].
    pub result: Result<Outcome, ApproverError>,
}

/// What a chain evaluation produced.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainReport {
    /// The decision, or why there is none.
    ///
    /// - `Err(Unavailable)`: no member could run (`approver_unavailable`).
    /// - `Err(Timeout)`: the request expired unanswered.
    /// - `Err(Cancelled)`: the caller cancelled.
    /// - `Err(Internal)`: a fault; fail closed (deny).
    /// - `Err(Invalid)`: a response failed verification.
    ///
    /// `cnd` decides which of these leave the request pending for a retry.
    pub result: Result<Decision, ApproverError>,
    /// Every member that ran, in the order it finished.
    pub members: Vec<MemberResult>,
}

type Log = Mutex<Vec<MemberResult>>;

fn eval<'a>(
    chain: &'a Chain,
    registry: &'a Registry,
    req: &'a ApprovalRequest,
    cancel: CancellationToken,
    log: &'a Log,
) -> BoxFuture<'a, Result<Decision, ApproverError>> {
    Box::pin(async move {
        match chain {
            Chain::One(name) => one(name, registry, req, cancel, log).await,
            Chain::AllOf(list) => {
                for member in list {
                    match eval(member, registry, req, cancel.child_token(), log).await? {
                        Decision::Approved => {}
                        Decision::Denied => return Ok(Decision::Denied),
                    }
                }
                Ok(Decision::Approved)
            }
            Chain::AnyOf(list) => any_of(list, registry, req, cancel, log).await,
        }
    })
}

async fn one(
    name: &str,
    registry: &Registry,
    req: &ApprovalRequest,
    cancel: CancellationToken,
    log: &Log,
) -> Result<Decision, ApproverError> {
    let Some(approver) = registry.get(name) else {
        return Err(ApproverError::Internal(format!(
            "no approver named {name:?}"
        )));
    };
    if cancel.is_cancelled() {
        return Err(ApproverError::Cancelled);
    }
    let result = approver.present(req, cancel).await;
    let decision = match &result {
        Ok(Outcome::Approved(_)) => Ok(Decision::Approved),
        Ok(Outcome::Denied(_)) => Ok(Decision::Denied),
        Err(e) => Err(e.clone()),
    };
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(MemberResult {
            approver: name.to_string(),
            result,
        });
    decision
}

async fn any_of(
    list: &[Chain],
    registry: &Registry,
    req: &ApprovalRequest,
    cancel: CancellationToken,
    log: &Log,
) -> Result<Decision, ApproverError> {
    let members = cancel.child_token();
    let mut running: Vec<Option<BoxFuture<'_, Result<Decision, ApproverError>>>> = list
        .iter()
        .map(|c| Some(eval(c, registry, req, members.clone(), log)))
        .collect();
    let mut errors = Vec::new();

    let result = poll_fn(|cx| {
        for slot in running.iter_mut() {
            let Some(fut) = slot else { continue };
            let Poll::Ready(r) = fut.as_mut().poll(cx) else {
                continue;
            };
            *slot = None;
            match r {
                // An approval or a denial decides; an explicit no is never
                // overridden by another member.
                Ok(decision) => return Poll::Ready(Ok(decision)),
                // Fail closed on a fault.
                Err(e @ ApproverError::Internal(_)) => return Poll::Ready(Err(e)),
                Err(e) => errors.push(e),
            }
        }
        if running.iter().all(Option::is_none) {
            Poll::Ready(Err(no_decision(&errors, &cancel)))
        } else {
            Poll::Pending
        }
    })
    .await;

    // Cancel the members still running and let them withdraw their prompts.
    members.cancel();
    let drain = poll_fn(|cx| {
        for slot in running.iter_mut() {
            if slot
                .as_mut()
                .is_some_and(|fut| fut.as_mut().poll(cx).is_ready())
            {
                *slot = None;
            }
        }
        if running.iter().all(Option::is_none) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    });
    let _ = tokio::time::timeout(DRAIN, drain).await;
    result
}

/// The error an `any_of` returns when no member decided.
fn no_decision(errors: &[ApproverError], cancel: &CancellationToken) -> ApproverError {
    if cancel.is_cancelled() {
        return ApproverError::Cancelled;
    }
    if let Some(e) = errors
        .iter()
        .find(|e| !matches!(e, ApproverError::Unavailable(_)))
    {
        return e.clone();
    }
    let reasons: Vec<String> = errors
        .iter()
        .map(|e| match e {
            ApproverError::Unavailable(why) => why.clone(),
            other => other.to_string(),
        })
        .collect();
    ApproverError::Unavailable(format!(
        "every any_of member is unavailable: {}",
        reasons.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use countersign_proto::ApprovalKind;

    use super::*;
    use crate::{ApproverInfo, DisplayView, Evidence, SessionRef};

    #[derive(Clone, Copy)]
    enum Act {
        Approve(u64),
        Deny(u64),
        Unavailable,
        Internal,
        Hang,
    }

    struct Fake {
        name: &'static str,
        act: Act,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl DaemonApprover for Fake {
        fn info(&self) -> ApproverInfo {
            ApproverInfo {
                name: self.name.into(),
                adapter: "fake",
                trusted_display: false,
                notes: String::new(),
            }
        }

        fn present<'a>(
            &'a self,
            _req: &'a ApprovalRequest,
            cancel: CancellationToken,
        ) -> BoxFuture<'a, Result<Outcome, ApproverError>> {
            Box::pin(async move {
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("{} start", self.name));
                let evidence = Evidence {
                    approver: self.name.into(),
                    adapter: "fake",
                    at: SystemTime::UNIX_EPOCH,
                    detail: serde_json::Value::Null,
                };
                let (ms, result) = match self.act {
                    Act::Approve(ms) => (ms, Ok(Outcome::Approved(evidence))),
                    Act::Deny(ms) => (ms, Ok(Outcome::Denied(evidence))),
                    Act::Unavailable => (0, Err(ApproverError::Unavailable(self.name.into()))),
                    Act::Internal => (0, Err(ApproverError::Internal(self.name.into()))),
                    Act::Hang => (u64::MAX / 4, Err(ApproverError::Timeout)),
                };
                tokio::select! {
                    _ = cancel.cancelled() => {
                        self.events.lock().unwrap().push(format!("{} cancelled", self.name));
                        Err(ApproverError::Cancelled)
                    }
                    _ = tokio::time::sleep(Duration::from_millis(ms)) => result,
                }
            })
        }
    }

    fn setup(fakes: &[(&'static str, Act)]) -> (Registry, Arc<Mutex<Vec<String>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut reg = Registry::new();
        for &(name, act) in fakes {
            reg.insert(Arc::new(Fake {
                name,
                act,
                events: events.clone(),
            }));
        }
        (reg, events)
    }

    fn request() -> ApprovalRequest {
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
            SystemTime::now() + Duration::from_secs(300),
        )
    }

    /// A chain as config writes it, e.g. `{ all_of = ["a", "b"] }`.
    fn chain(json: serde_json::Value) -> Chain {
        match json {
            serde_json::Value::String(s) => Chain::One(s),
            serde_json::Value::Object(m) => {
                let (k, v) = m.into_iter().next().unwrap();
                let list = v.as_array().unwrap().iter().cloned().map(chain).collect();
                match k.as_str() {
                    "all_of" => Chain::AllOf(list),
                    "any_of" => Chain::AnyOf(list),
                    other => panic!("{other}"),
                }
            }
            other => panic!("{other}"),
        }
    }

    fn names(report: &ChainReport) -> Vec<(&str, bool)> {
        report
            .members
            .iter()
            .map(|m| {
                (
                    m.approver.as_str(),
                    matches!(m.result, Ok(Outcome::Approved(_))),
                )
            })
            .collect()
    }

    async fn run(c: &Chain, reg: &Registry) -> ChainReport {
        evaluate(c, reg, &request(), &CancellationToken::new()).await
    }

    #[tokio::test(start_paused = true)]
    async fn all_of_needs_every_member_in_order() {
        let (reg, events) = setup(&[("a", Act::Approve(10)), ("b", Act::Approve(1))]);
        let report = run(&chain(serde_json::json!({"all_of": ["a", "b"]})), &reg).await;
        assert_eq!(report.result, Ok(Decision::Approved));
        assert_eq!(names(&report), [("a", true), ("b", true)]);
        // One at a time: b starts after a finished.
        assert_eq!(*events.lock().unwrap(), ["a start", "b start"]);
    }

    #[tokio::test(start_paused = true)]
    async fn all_of_stops_at_the_first_denial() {
        let (reg, events) = setup(&[("a", Act::Deny(1)), ("b", Act::Approve(1))]);
        let report = run(&chain(serde_json::json!({"all_of": ["a", "b"]})), &reg).await;
        assert_eq!(report.result, Ok(Decision::Denied));
        assert_eq!(*events.lock().unwrap(), ["a start"]);
    }

    #[tokio::test(start_paused = true)]
    async fn all_of_ends_on_an_unavailable_member() {
        let (reg, events) = setup(&[
            ("a", Act::Approve(1)),
            ("b", Act::Unavailable),
            ("c", Act::Approve(1)),
        ]);
        let report = run(&chain(serde_json::json!({"all_of": ["a", "b", "c"]})), &reg).await;
        assert!(matches!(report.result, Err(ApproverError::Unavailable(_))));
        assert_eq!(*events.lock().unwrap(), ["a start", "b start"]);
    }

    #[tokio::test(start_paused = true)]
    async fn any_of_first_approval_wins_and_cancels_the_rest() {
        let (reg, events) = setup(&[("slow", Act::Hang), ("fast", Act::Approve(100))]);
        let report = run(
            &chain(serde_json::json!({"any_of": ["slow", "fast"]})),
            &reg,
        )
        .await;
        assert_eq!(report.result, Ok(Decision::Approved));
        assert_eq!(names(&report), [("fast", true), ("slow", false)]);
        assert_eq!(report.members[1].result, Err(ApproverError::Cancelled));
        assert!(
            events
                .lock()
                .unwrap()
                .contains(&"slow cancelled".to_string())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn any_of_denial_is_not_overridden() {
        let (reg, events) = setup(&[("a", Act::Approve(500)), ("b", Act::Deny(100))]);
        let report = run(&chain(serde_json::json!({"any_of": ["a", "b"]})), &reg).await;
        assert_eq!(report.result, Ok(Decision::Denied));
        assert!(events.lock().unwrap().contains(&"a cancelled".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn any_of_skips_unavailable_members() {
        let (reg, _) = setup(&[("gone", Act::Unavailable), ("ok", Act::Approve(100))]);
        let report = run(&chain(serde_json::json!({"any_of": ["gone", "ok"]})), &reg).await;
        assert_eq!(report.result, Ok(Decision::Approved));
        assert_eq!(names(&report), [("gone", false), ("ok", true)]);
    }

    #[tokio::test(start_paused = true)]
    async fn any_of_with_every_member_unavailable_is_unavailable() {
        let (reg, _) = setup(&[("x", Act::Unavailable), ("y", Act::Unavailable)]);
        let report = run(&chain(serde_json::json!({"any_of": ["x", "y"]})), &reg).await;
        let Err(ApproverError::Unavailable(why)) = report.result else {
            panic!("{:?}", report.result)
        };
        assert!(why.contains('x') && why.contains('y'), "{why}");
    }

    #[tokio::test(start_paused = true)]
    async fn any_of_fails_closed_on_a_fault() {
        let (reg, events) = setup(&[("bug", Act::Internal), ("slow", Act::Hang)]);
        let report = run(&chain(serde_json::json!({"any_of": ["slow", "bug"]})), &reg).await;
        assert!(matches!(report.result, Err(ApproverError::Internal(_))));
        assert!(
            events
                .lock()
                .unwrap()
                .contains(&"slow cancelled".to_string())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn nested_chains() {
        let (reg, _) = setup(&[
            ("a", Act::Unavailable),
            ("b", Act::Approve(1)),
            ("c", Act::Approve(1)),
        ]);
        let c = chain(serde_json::json!({"all_of": [{"any_of": ["a", "b"]}, "c"]}));
        let report = run(&c, &reg).await;
        assert_eq!(report.result, Ok(Decision::Approved));
        assert_eq!(names(&report), [("a", false), ("b", true), ("c", true)]);
    }

    #[tokio::test(start_paused = true)]
    async fn caller_cancel_reaches_every_member() {
        let (reg, events) = setup(&[("a", Act::Hang), ("b", Act::Hang)]);
        let c = chain(serde_json::json!({"any_of": ["a", "b"]}));
        let cancel = CancellationToken::new();
        let req = request();
        let fire = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            fire.cancel();
        });
        let report = evaluate(&c, &reg, &req, &cancel).await;
        assert_eq!(report.result, Err(ApproverError::Cancelled));
        let ev = events.lock().unwrap();
        assert!(ev.contains(&"a cancelled".to_string()) && ev.contains(&"b cancelled".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_names_fail_closed() {
        let (reg, _) = setup(&[]);
        let report = run(&Chain::One("nope".into()), &reg).await;
        assert!(matches!(report.result, Err(ApproverError::Internal(_))));
    }
}
