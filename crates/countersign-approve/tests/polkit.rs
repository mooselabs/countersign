//! The polkit adapter against a fake `org.freedesktop.PolicyKit1` authority
//! on a private `dbus-daemon` that each test starts. These tests never touch
//! the system bus or the real polkitd: a real check would put a dialog on the
//! developer's desktop.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use countersign_approve::polkit::{Bus, PolkitApprover};
use countersign_approve::{
    ApprovalRequest, ApproverError, CancellationToken, DaemonApprover, DisplayInput, DisplayView,
    Outcome, SessionRef,
};
use countersign_core::config::{OnDismiss, PolkitConfig, PolkitSubject as SubjectMode};
use countersign_proto::{APPROVE_DOMAIN, Anchor, ApprovalKind, CanonicalRequest};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use zvariant::{OwnedValue, Type, Value};

/// A private message bus, killed and cleaned up on drop.
struct PrivateBus {
    child: Child,
    dir: PathBuf,
    address: String,
}

impl PrivateBus {
    /// Starts `dbus-daemon` with a minimal config: no service activation, no
    /// system services, a socket in a fresh temporary directory. `None` (and
    /// a message) when `dbus-daemon` is not installed.
    fn start() -> Option<Self> {
        if Command::new("dbus-daemon")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("SKIPPED: dbus-daemon is not on PATH; polkit bus tests need it");
            return None;
        }
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "countersign-approve-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}/bus</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                dir.display()
            ),
        )
        .unwrap();
        let mut child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .args(["--print-address=1", "--nofork", "--nopidfile"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line.trim().to_string();
        assert!(
            address.starts_with("unix:"),
            "dbus-daemon printed {address:?}"
        );
        Some(Self {
            child,
            dir,
            address,
        })
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[derive(Debug, Deserialize, Type)]
struct ReceivedSubject {
    kind: String,
    details: HashMap<String, OwnedValue>,
}

#[derive(Debug, Serialize, Type)]
struct AuthResult {
    is_authorized: bool,
    is_challenge: bool,
    details: HashMap<String, String>,
}

#[derive(Debug)]
struct Call {
    subject: ReceivedSubject,
    action_id: String,
    details: HashMap<String, String>,
    flags: u32,
    cancellation_id: String,
}

#[derive(Clone)]
enum Reply {
    Result(bool, bool, &'static [(&'static str, &'static str)]),
    NotAuthorized,
    /// Wait until CancelCheckAuthorization names this call.
    Hang,
}

struct State {
    reply: Reply,
    calls: Vec<Call>,
    cancels: Vec<String>,
    waiters: HashMap<String, oneshot::Sender<()>>,
}

#[derive(Clone)]
struct FakeAuthority(Arc<Mutex<State>>);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
enum PkError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NotAuthorized(String),
    Cancelled(String),
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl FakeAuthority {
    async fn check_authorization(
        &self,
        subject: ReceivedSubject,
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> Result<AuthResult, PkError> {
        let (reply, waiter) = {
            let mut s = self.0.lock().unwrap();
            let reply = s.reply.clone();
            let waiter = if matches!(reply, Reply::Hang) {
                let (tx, rx) = oneshot::channel();
                s.waiters.insert(cancellation_id.clone(), tx);
                Some(rx)
            } else {
                None
            };
            s.calls.push(Call {
                subject,
                action_id,
                details,
                flags,
                cancellation_id,
            });
            (reply, waiter)
        };
        match reply {
            Reply::Result(is_authorized, is_challenge, details) => Ok(AuthResult {
                is_authorized,
                is_challenge,
                details: details
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }),
            Reply::NotAuthorized => Err(PkError::NotAuthorized(
                "Only trusted callers (e.g. uid 0 or an action owner) can use \
                 CheckAuthorization() and pass details"
                    .into(),
            )),
            Reply::Hang => {
                let _ = waiter.unwrap().await;
                Err(PkError::Cancelled(
                    "Authorization request was cancelled".into(),
                ))
            }
        }
    }

    async fn cancel_check_authorization(&self, cancellation_id: String) -> Result<(), PkError> {
        let mut s = self.0.lock().unwrap();
        s.cancels.push(cancellation_id.clone());
        if let Some(tx) = s.waiters.remove(&cancellation_id) {
            let _ = tx.send(());
        }
        Ok(())
    }

    #[zbus(property)]
    async fn backend_version(&self) -> String {
        "128-fake".into()
    }
}

/// A private bus with the fake authority on it.
struct Fixture {
    bus: PrivateBus,
    state: Arc<Mutex<State>>,
    _server: zbus::Connection,
}

impl Fixture {
    async fn start(reply: Reply) -> Option<Self> {
        let bus = PrivateBus::start()?;
        let state = Arc::new(Mutex::new(State {
            reply,
            calls: Vec::new(),
            cancels: Vec::new(),
            waiters: HashMap::new(),
        }));
        let server = zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("org.freedesktop.PolicyKit1")
            .unwrap()
            .serve_at(
                "/org/freedesktop/PolicyKit1/Authority",
                FakeAuthority(state.clone()),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        Some(Self {
            bus,
            state,
            _server: server,
        })
    }

    fn approver(&self, subject: SubjectMode, on_dismiss: OnDismiss) -> PolkitApprover {
        PolkitApprover::new(
            "polkit",
            PolkitConfig {
                subject,
                on_dismiss,
                // The private bus has no logind; require_wayland has its own test.
                require_wayland: false,
                ..PolkitConfig::default()
            },
            Bus::Address(self.bus.address.clone()),
        )
    }

    fn default_approver(&self) -> PolkitApprover {
        self.approver(SubjectMode::Process, OnDismiss::Deny)
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }
}

fn session() -> SessionRef {
    SessionRef {
        session_id: "s_7k2mq9d4x1ha".into(),
        uid: 1000,
        anchor_pid: 41210,
        anchor_start_time: 8_812_345,
        anchor_comm: "claude".into(),
        logind_session: Some("3".into()),
    }
}

fn use_request(expires_in: Duration) -> ApprovalRequest {
    let display = DisplayView::new(&DisplayInput {
        anchor_comm: "claude".into(),
        anchor_pid: 41210,
        label: None,
        cwd: Some("/home/patrick/projects/x".into()),
        home: Some("/home/patrick".into()),
        secrets: vec!["clickhouse-password".into(), "github-token".into()],
        ttl: Some(Duration::from_secs(1800)),
        reason: Some("row counts\nfor the \x1b[31mcost report".into()),
        operation: None,
    });
    ApprovalRequest::new(
        "r_9w1k",
        br#"{"domain":"countersign/approve/v1"}"#.to_vec(),
        "K7M-Q2X",
        ApprovalKind::Use,
        display,
        session(),
        SystemTime::now() + expires_in,
    )
}

fn mutate_request() -> ApprovalRequest {
    let display = DisplayView::new(&DisplayInput {
        anchor_comm: "claude".into(),
        anchor_pid: 41210,
        operation: Some("ADD secret typesafe-api-key (32 bytes, from stdin)".into()),
        ..DisplayInput::default()
    });
    ApprovalRequest::new(
        "r_m",
        b"{}".to_vec(),
        "ABC-DEF",
        ApprovalKind::Mutate,
        display,
        session(),
        SystemTime::now() + Duration::from_secs(60),
    )
}

const MINUTE: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread")]
async fn authorized_is_approved_with_evidence() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    let req = use_request(MINUTE);
    let out = fx
        .default_approver()
        .present(&req, CancellationToken::new())
        .await
        .unwrap();
    let Outcome::Approved(ev) = out else {
        panic!("{out:?}")
    };
    assert_eq!(ev.approver, "polkit");
    assert_eq!(ev.adapter, "polkit");
    assert_eq!(
        ev.detail["action_id"],
        "computer.mooselabs.countersign.approve"
    );
    assert_eq!(ev.detail["is_authorized"], true);
    assert_eq!(ev.detail["dismissed"], false);
    assert_eq!(
        ev.detail["subject"],
        serde_json::json!({"kind": "unix-process", "pid": 41210, "start-time": 8812345, "uid": 1000})
    );
    assert!(ev.detail["duration_ms"].is_u64());

    fx.with(|s| {
        assert_eq!(s.calls.len(), 1);
        let call = &s.calls[0];
        assert_eq!(call.action_id, "computer.mooselabs.countersign.approve");
        assert_eq!(call.flags, 1, "AllowUserInteraction");
        assert!(call.cancellation_id.contains("r_9w1k"));
        assert!(s.cancels.is_empty());
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn details_map_is_exact() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    let approver = fx.default_approver();
    let req = use_request(MINUTE);
    approver
        .present(&req, CancellationToken::new())
        .await
        .unwrap();
    let mutate = mutate_request();
    approver
        .present(&mutate, CancellationToken::new())
        .await
        .unwrap();

    let expected_use: HashMap<String, String> = [
        ("code", "K7M-Q2X"),
        ("digest", req.digest_short()),
        ("secrets", "clickhouse-password, github-token"),
        ("ttl", "30m"),
        ("session", "agent claude (pid 41210) in ~/projects/x"),
        ("reason", "row counts for the cost report"),
        ("operation", "none"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let expected_mutate: HashMap<String, String> = [
        ("code", "ABC-DEF"),
        ("digest", mutate.digest_short()),
        ("secrets", "none"),
        ("ttl", "none"),
        ("session", "agent claude (pid 41210)"),
        ("reason", "none"),
        (
            "operation",
            "ADD secret typesafe-api-key (32 bytes, from stdin)",
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    fx.with(|s| {
        assert_eq!(s.calls[0].details, expected_use);
        assert_eq!(s.calls[1].details, expected_mutate);
        assert_eq!(
            s.calls[1].action_id,
            "computer.mooselabs.countersign.mutate"
        );
        for call in &s.calls {
            assert!(call.details.keys().all(|k| !k.starts_with("polkit.")));
        }
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn action_follows_the_kind() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    let approver = fx.default_approver();
    for kind in [ApprovalKind::Reveal, ApprovalKind::Export] {
        let req = ApprovalRequest::new(
            "r",
            b"{}".to_vec(),
            "AAA-AAA",
            kind,
            DisplayView::default(),
            session(),
            SystemTime::now() + MINUTE,
        );
        approver
            .present(&req, CancellationToken::new())
            .await
            .unwrap();
    }
    fx.with(|s| {
        assert_eq!(
            s.calls[0].action_id,
            "computer.mooselabs.countersign.reveal"
        );
        assert_eq!(
            s.calls[1].action_id,
            "computer.mooselabs.countersign.mutate"
        );
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn process_subject_shape() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    fx.default_approver()
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap();
    fx.with(|s| {
        let subject = &s.calls[0].subject;
        assert_eq!(subject.kind, "unix-process");
        assert_eq!(subject.details.len(), 3);
        assert_eq!(*subject.details["pid"], Value::U32(41210));
        assert_eq!(*subject.details["start-time"], Value::U64(8_812_345));
        assert_eq!(*subject.details["uid"], Value::I32(1000));
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn session_subject_shape() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    let approver = fx.approver(SubjectMode::Session, OnDismiss::Deny);
    let out = approver
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        out.evidence().detail["subject"],
        serde_json::json!({"kind": "unix-session", "session-id": "3"})
    );
    fx.with(|s| {
        let subject = &s.calls[0].subject;
        assert_eq!(subject.kind, "unix-session");
        assert_eq!(subject.details.len(), 1);
        assert_eq!(*subject.details["session-id"], Value::from("3"));
    });

    // Without a logind session there is nothing to ask about.
    let mut session = session();
    session.logind_session = None;
    let req = ApprovalRequest::new(
        "r",
        b"{}".to_vec(),
        "AAA-AAA",
        ApprovalKind::Use,
        DisplayView::default(),
        session,
        SystemTime::now() + MINUTE,
    );
    let err = approver
        .present(&req, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, ApproverError::Unavailable(_)), "{err:?}");
    fx.with(|s| assert_eq!(s.calls.len(), 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn dismissed_is_denied_unless_ignored() {
    let Some(fx) = Fixture::start(Reply::Result(
        false,
        false,
        &[("polkit.result", "auth_self"), ("polkit.dismissed", "true")],
    ))
    .await
    else {
        return;
    };
    let req = use_request(MINUTE);
    let out = fx
        .default_approver()
        .present(&req, CancellationToken::new())
        .await
        .unwrap();
    let Outcome::Denied(ev) = out else {
        panic!("{out:?}")
    };
    assert_eq!(ev.detail["dismissed"], true);
    assert_eq!(ev.detail["is_authorized"], false);

    let err = fx
        .approver(SubjectMode::Process, OnDismiss::Ignore)
        .present(&req, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, ApproverError::Unavailable(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn not_authorized_result_is_denied() {
    let Some(fx) = Fixture::start(Reply::Result(false, false, &[])).await else {
        return;
    };
    let out = fx
        .default_approver()
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap();
    let Outcome::Denied(ev) = out else {
        panic!("{out:?}")
    };
    assert_eq!(ev.detail["dismissed"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_means_no_agent() {
    let Some(fx) = Fixture::start(Reply::Result(
        false,
        true,
        &[("polkit.result", "auth_self")],
    ))
    .await
    else {
        return;
    };
    let err = fx
        .default_approver()
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, ApproverError::Unavailable(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn not_authorized_error_fails_closed() {
    let Some(fx) = Fixture::start(Reply::NotAuthorized).await else {
        return;
    };
    let err = fx
        .default_approver()
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap_err();
    let ApproverError::Internal(msg) = err else {
        panic!("{err:?}")
    };
    assert!(msg.contains("Only trusted callers"), "{msg}");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_polkitd_is_unavailable() {
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let approver = PolkitApprover::new(
        "polkit",
        PolkitConfig {
            require_wayland: false,
            ..PolkitConfig::default()
        },
        Bus::Address(bus.address.clone()),
    );
    let err = approver
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, ApproverError::Unavailable(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_bus_is_unavailable() {
    let approver = PolkitApprover::new(
        "polkit",
        PolkitConfig::default(),
        Bus::Address("unix:path=/nonexistent/countersign-test-bus".into()),
    );
    let err = approver
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, ApproverError::Unavailable(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_cancels_the_check() {
    let Some(fx) = Fixture::start(Reply::Hang).await else {
        return;
    };
    let req = use_request(Duration::from_millis(500));
    let err = fx
        .default_approver()
        .present(&req, CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err, ApproverError::Timeout);
    fx.with(|s| {
        assert_eq!(s.calls.len(), 1);
        assert_eq!(s.cancels, [s.calls[0].cancellation_id.clone()]);
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_token_cancels_the_check() {
    let Some(fx) = Fixture::start(Reply::Hang).await else {
        return;
    };
    let req = use_request(MINUTE);
    let cancel = CancellationToken::new();
    let fire = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        fire.cancel();
    });
    let err = fx
        .default_approver()
        .present(&req, cancel)
        .await
        .unwrap_err();
    assert_eq!(err, ApproverError::Cancelled);
    fx.with(|s| assert_eq!(s.cancels, [s.calls[0].cancellation_id.clone()]));
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_future_cancels_the_check() {
    let Some(fx) = Fixture::start(Reply::Hang).await else {
        return;
    };
    let approver = fx.default_approver();
    let req = use_request(MINUTE);
    let r = tokio::time::timeout(
        Duration::from_millis(300),
        approver.present(&req, CancellationToken::new()),
    )
    .await;
    assert!(r.is_err(), "the fake never answers");
    // The cancel call runs in the background after the drop.
    for _ in 0..100 {
        if fx.with(|s| !s.cancels.is_empty()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    fx.with(|s| assert_eq!(s.cancels, [s.calls[0].cancellation_id.clone()]));
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_requests_never_reach_polkitd() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    let mut req = use_request(MINUTE);
    req = ApprovalRequest::new(
        req.request_id(),
        req.canonical().to_vec(),
        req.code(),
        req.kind(),
        req.display().clone(),
        req.session().clone(),
        SystemTime::now() - Duration::from_secs(1),
    );
    let err = fx
        .default_approver()
        .present(&req, CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err, ApproverError::Timeout);
    fx.with(|s| assert!(s.calls.is_empty()));
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_ids_are_unique_per_call() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    let approver = fx.default_approver();
    let req = use_request(MINUTE);
    approver
        .present(&req, CancellationToken::new())
        .await
        .unwrap();
    approver
        .present(&req, CancellationToken::new())
        .await
        .unwrap();
    fx.with(|s| assert_ne!(s.calls[0].cancellation_id, s.calls[1].cancellation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn backend_version_is_readable() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    assert_eq!(
        fx.default_approver().backend_version().await.unwrap(),
        "128-fake"
    );
}

/// The digest the dialog shows is the one `cn approve` computes from the
/// request `get_request` returns: both come from `countersign_proto`.
#[test]
fn dialog_digest_matches_what_cn_approve_computes() {
    let canonical = CanonicalRequest {
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
    };
    let req = ApprovalRequest::new(
        canonical.request_id.clone(),
        canonical.canonical_bytes().unwrap(),
        &canonical.code,
        canonical.mode,
        DisplayView::default(),
        session(),
        SystemTime::now() + MINUTE,
    );
    // What `cn approve` does: recompute from the fields `get_request` sent,
    // after a round trip through JSON.
    let json = serde_json::to_string(&canonical).unwrap();
    let as_cn_sees_it: CanonicalRequest = serde_json::from_str(&json).unwrap();
    let cn_digest = as_cn_sees_it.digest().unwrap();
    let details = PolkitApprover::details(&req);
    assert_eq!(details["digest"], cn_digest.short());
    assert_eq!(req.digest(), &cn_digest.0);
    assert_eq!(cn_digest.short(), "04DY-AGEE");
}

/// With `require_wayland`, a bus with no logind (so no session type) makes
/// polkit unavailable, and no check reaches polkitd.
#[tokio::test(flavor = "multi_thread")]
async fn require_wayland_without_logind_is_unavailable() {
    let Some(fx) = Fixture::start(Reply::Result(true, false, &[])).await else {
        return;
    };
    let approver = PolkitApprover::new(
        "polkit",
        PolkitConfig::default(),
        Bus::Address(fx.bus.address.clone()),
    );
    let err = approver
        .present(&use_request(MINUTE), CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ApproverError::Unavailable(why) if why.contains("require_wayland")),
        "{err:?}"
    );
    assert!(fx.with(|s| s.calls.is_empty()));
}
