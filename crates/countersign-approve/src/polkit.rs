//! The `polkit` approver: `cnd` asks polkitd to authorize a countersign action
//! for the developer, and the desktop's authentication agent (gnome-shell)
//! shows the request and collects the human's factor.
//!
//! See docs/approvers.md ("Adapter: polkit") and spikes/polkit-dialog for what
//! was measured on polkit 128 and GNOME 51:
//!
//! - polkitd expands `$(key)` in the action's message from the details `cnd`
//!   passes, and only an action owner (`unix-user:countersign`) may pass them.
//! - `auth_self` does not cache, so every request prompts.
//! - Cancel returns `(false, false, {"polkit.dismissed": "true"})`.
//! - With a YubiKey factor GNOME retries forever, so this adapter enforces the
//!   request's expiry itself with `CancelCheckAuthorization`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use countersign_core::config::{OnDismiss, PolkitConfig, PolkitSubject};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use zbus::DBusError as _;
use zvariant::{Type, Value};

use crate::{
    ApprovalRequest, ApproverError, ApproverInfo, BoxFuture, DaemonApprover, Evidence, Outcome,
};

/// The keys the actions' messages use. Every one is always set.
pub const DETAIL_KEYS: [&str; 7] = [
    "code",
    "digest",
    "secrets",
    "ttl",
    "session",
    "reason",
    "operation",
];

/// `CheckAuthorization` flag: polkitd may ask the authentication agent.
const ALLOW_USER_INTERACTION: u32 = 1;

/// How long a `CancelCheckAuthorization` call may take.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

/// Which bus polkitd is on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Bus {
    /// The system bus. Production.
    #[default]
    System,
    /// A bus at this D-Bus address. For tests against a private bus with a
    /// fake authority; never point it at the real system bus in tests.
    Address(String),
}

/// polkit's `(sa{sv})` subject.
#[derive(Debug, Serialize, Type)]
struct Subject {
    kind: &'static str,
    details: HashMap<&'static str, Value<'static>>,
}

/// polkit's `(bba{ss})` result.
#[derive(Debug, Deserialize, Type)]
struct AuthorizationResult {
    is_authorized: bool,
    is_challenge: bool,
    details: HashMap<String, String>,
}

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority",
    gen_blocking = false
)]
trait Authority {
    fn check_authorization(
        &self,
        subject: &Subject,
        action_id: &str,
        details: &HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<AuthorizationResult>;

    fn cancel_check_authorization(&self, cancellation_id: &str) -> zbus::Result<()>;

    #[zbus(property)]
    fn backend_version(&self) -> zbus::Result<String>;
}

/// The polkit approver.
pub struct PolkitApprover {
    name: String,
    config: PolkitConfig,
    bus: Bus,
    conn: tokio::sync::Mutex<Option<zbus::Connection>>,
}

impl PolkitApprover {
    /// The instance `[approvers.NAME]` with these settings, talking to
    /// polkitd on `bus`. Connects on first use.
    pub fn new(name: impl Into<String>, config: PolkitConfig, bus: Bus) -> Self {
        Self {
            name: name.into(),
            config,
            bus,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// The settings it was built with.
    pub fn config(&self) -> &PolkitConfig {
        &self.config
    }

    /// polkitd's `BackendVersion` property, e.g. "128", for the daemon log.
    pub async fn backend_version(&self) -> Result<String, ApproverError> {
        let conn = self.connection().await?;
        let proxy = authority(&conn).await.map_err(|e| self.map_error(&e))?;
        proxy
            .backend_version()
            .await
            .map_err(|e| self.map_error(&e))
    }

    /// The details map passed to polkitd for `req`: every key in
    /// [`DETAIL_KEYS`], "none" for an empty value, never a `polkit.` key.
    /// Values come from the request's cleaned [`crate::DisplayView`].
    pub fn details(req: &ApprovalRequest) -> HashMap<&'static str, String> {
        let d = req.display();
        let or_none = |v: Option<&str>| match v {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "none".to_string(),
        };
        let secrets = d.secrets_summary();
        HashMap::from([
            ("code", or_none(Some(req.code()))),
            ("digest", or_none(Some(req.digest_short()))),
            ("secrets", or_none(Some(&secrets))),
            ("ttl", or_none(d.ttl())),
            ("session", or_none(Some(d.session()))),
            ("reason", or_none(d.reason())),
            ("operation", or_none(d.operation())),
        ])
    }

    /// The subject polkitd is asked about. `display` is the uid's graphical
    /// session, used by the `session` mode when cnd resolved none.
    fn subject(
        &self,
        req: &ApprovalRequest,
        display: Option<&str>,
    ) -> Result<Subject, ApproverError> {
        let s = req.session();
        match self.config.subject {
            PolkitSubject::Process => {
                let uid = i32::try_from(s.uid).map_err(|_| {
                    ApproverError::Internal(format!("uid {} does not fit polkit's int32", s.uid))
                })?;
                Ok(Subject {
                    kind: "unix-process",
                    details: HashMap::from([
                        ("pid", Value::from(s.anchor_pid)),
                        ("start-time", Value::from(s.anchor_start_time)),
                        ("uid", Value::from(uid)),
                    ]),
                })
            }
            PolkitSubject::Session => {
                let Some(id) = s.logind_session.clone().or(display.map(str::to_owned)) else {
                    return Err(ApproverError::Unavailable(
                        "no logind graphical session for the developer".into(),
                    ));
                };
                Ok(Subject {
                    kind: "unix-session",
                    details: HashMap::from([("session-id", Value::from(id))]),
                })
            }
        }
    }

    async fn connection(&self) -> Result<zbus::Connection, ApproverError> {
        let mut slot = self.conn.lock().await;
        if let Some(conn) = &*slot {
            return Ok(conn.clone());
        }
        let conn = match &self.bus {
            Bus::System => zbus::Connection::system().await,
            Bus::Address(addr) => match zbus::connection::Builder::address(addr.as_str()) {
                Ok(b) => b.build().await,
                Err(e) => Err(e),
            },
        }
        .map_err(|e| ApproverError::Unavailable(format!("cannot connect to D-Bus: {e}")))?;
        *slot = Some(conn.clone());
        Ok(conn)
    }

    fn map_error(&self, e: &zbus::Error) -> ApproverError {
        let (name, message) = match e {
            zbus::Error::MethodError(name, msg, _) => {
                (name.as_str().to_string(), msg.clone().unwrap_or_default())
            }
            zbus::Error::FDO(fdo) => (fdo.name().as_str().to_string(), fdo.to_string()),
            other => {
                return ApproverError::Internal(format!("D-Bus call to polkitd failed: {other}"));
            }
        };
        match name.as_str() {
            // cnd is not an action owner: the policy is missing or names
            // another owner. A fault in the install, so fail closed.
            "org.freedesktop.PolicyKit1.Error.NotAuthorized" => ApproverError::Internal(format!(
                "polkitd refused cnd as a caller ({message}); is the countersign policy installed \
                 with owner unix-user:countersign?"
            )),
            "org.freedesktop.PolicyKit1.Error.Cancelled" => ApproverError::Cancelled,
            "org.freedesktop.DBus.Error.ServiceUnknown"
            | "org.freedesktop.DBus.Error.NameHasNoOwner"
            | "org.freedesktop.DBus.Error.Spawn.ServiceNotFound" => {
                ApproverError::Unavailable(format!("polkitd is not on the bus: {message}"))
            }
            "org.freedesktop.DBus.Error.NoReply" => {
                let hint = match self.config.subject {
                    PolkitSubject::Session => {
                        " (polkitd 127/128 abort on unix-session subjects, polkit-org/polkit#699)"
                    }
                    PolkitSubject::Process => "",
                };
                ApproverError::Internal(format!("polkitd did not reply: {message}{hint}"))
            }
            _ => ApproverError::Internal(format!("polkitd returned {name}: {message}")),
        }
    }

    async fn run(
        &self,
        req: &ApprovalRequest,
        cancel: CancellationToken,
    ) -> Result<Outcome, ApproverError> {
        let started = Instant::now();
        let remaining = match req.expires_at().duration_since(SystemTime::now()) {
            Ok(d) if !d.is_zero() => d,
            _ => return Err(ApproverError::Timeout),
        };
        // One dialog stays open at most `timeout`, even if the request
        // lives longer.
        let remaining = remaining.min(self.config.timeout);
        if cancel.is_cancelled() {
            return Err(ApproverError::Cancelled);
        }
        let deadline = tokio::time::Instant::now() + remaining;
        let action = self.config.action(req.kind()).to_owned();
        let details = Self::details(req);
        let details: HashMap<&str, &str> = details.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let conn = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(ApproverError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(ApproverError::Timeout),
            conn = self.connection() => conn?,
        };
        // The uid's graphical session: what polkit itself asks the
        // authentication agent of, for a process outside any login session
        // (an agent started from a terminal is in the user manager's).
        let need_display = self.config.require_wayland
            || (self.config.subject == PolkitSubject::Session
                && req.session().logind_session.is_none());
        let display = if need_display {
            Some(tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(ApproverError::Cancelled),
                _ = tokio::time::sleep_until(deadline) => return Err(ApproverError::Timeout),
                found = display_session(&conn, req.session().uid) => found?,
            })
        } else {
            None
        };
        if self.config.require_wayland {
            let (id, ty) = display.as_ref().expect("looked up above");
            if ty != "wayland" {
                return Err(ApproverError::Unavailable(format!(
                    "require_wayland: the graphical session {id} is {ty:?}, not wayland"
                )));
            }
        }
        let subject = self.subject(req, display.as_ref().map(|(id, _)| id.as_str()))?;
        let subject_json = subject_json(&subject);
        let proxy = authority(&conn).await.map_err(|e| self.map_error(&e))?;
        let id = cancellation_id(req);
        let mut guard = CancelGuard {
            conn: Some(conn.clone()),
            id: id.clone(),
        };
        let reply = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                guard.cancel_now().await;
                return Err(ApproverError::Cancelled);
            }
            _ = tokio::time::sleep_until(deadline) => {
                guard.cancel_now().await;
                return Err(ApproverError::Timeout);
            }
            reply = proxy.check_authorization(&subject, &action, &details, ALLOW_USER_INTERACTION, &id) => {
                guard.disarm();
                reply
            }
        };
        let r = match reply {
            Ok(r) => r,
            Err(e) => {
                if matches!(e, zbus::Error::InputOutput(_)) {
                    // The bus connection broke; reconnect next time.
                    self.conn.lock().await.take();
                }
                return Err(self.map_error(&e));
            }
        };

        // An answer that arrives after expiry does not count.
        if SystemTime::now() >= req.expires_at() {
            return Err(ApproverError::Timeout);
        }
        let dismissed = r
            .details
            .get("polkit.dismissed")
            .is_some_and(|v| v == "true");
        let evidence = Evidence {
            approver: self.name.clone(),
            adapter: "polkit",
            at: SystemTime::now(),
            detail: serde_json::json!({
                "action_id": action,
                "subject": subject_json,
                "is_authorized": r.is_authorized,
                "dismissed": dismissed,
                "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            }),
        };
        if r.is_authorized {
            Ok(Outcome::Approved(evidence))
        } else if dismissed {
            match self.config.on_dismiss {
                OnDismiss::Deny => Ok(Outcome::Denied(evidence)),
                OnDismiss::Ignore => Err(ApproverError::Unavailable(
                    "the dialog was dismissed and on_dismiss = \"ignore\"".into(),
                )),
            }
        } else if r.is_challenge {
            // With AllowUserInteraction set, a challenge means polkitd found
            // no authentication agent for the subject.
            Err(ApproverError::Unavailable(
                "polkit has no authentication agent for the subject".into(),
            ))
        } else {
            Ok(Outcome::Denied(evidence))
        }
    }
}

impl DaemonApprover for PolkitApprover {
    fn info(&self) -> ApproverInfo {
        let (trusted_display, notes) = match self.config.subject {
            PolkitSubject::Process => (
                false,
                "polkit dialog for the session anchor process; a same-uid agent can register \
                 its own authentication agent and draw the prompt (it still needs the human's \
                 factor)",
            ),
            PolkitSubject::Session => (
                true,
                "polkit dialog for the logind session; polkitd 127/128 abort on this subject \
                 (polkit-org/polkit#699)",
            ),
        };
        ApproverInfo {
            name: self.name.clone(),
            adapter: "polkit",
            trusted_display,
            notes: notes.into(),
        }
    }

    fn present<'a>(
        &'a self,
        req: &'a ApprovalRequest,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Outcome, ApproverError>> {
        Box::pin(self.run(req, cancel))
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    gen_blocking = false
)]
trait Logind {
    fn get_user(&self, uid: u32) -> zbus::Result<zvariant::OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.User",
    default_service = "org.freedesktop.login1",
    gen_blocking = false
)]
trait LoginUser {
    #[zbus(property)]
    fn display(&self) -> zbus::Result<(String, zvariant::OwnedObjectPath)>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1",
    gen_blocking = false
)]
trait LoginSession {
    #[zbus(property, name = "Type")]
    fn session_type(&self) -> zbus::Result<String>;
}

/// The id and type (`wayland`, `x11`, `tty`...) of the uid's graphical
/// session: logind's `Display` property of the user. No session, or no
/// answer from logind, makes polkit unavailable rather than trusted.
async fn display_session(
    conn: &zbus::Connection,
    uid: u32,
) -> Result<(String, String), ApproverError> {
    let unavailable = |e: zbus::Error| ApproverError::Unavailable(format!("logind: {e}"));
    let user = LogindProxy::new(conn)
        .await
        .map_err(unavailable)?
        .get_user(uid)
        .await
        .map_err(unavailable)?;
    let (id, path) = LoginUserProxy::builder(conn)
        .path(user)
        .map_err(unavailable)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(unavailable)?
        .display()
        .await
        .map_err(unavailable)?;
    if id.is_empty() {
        return Err(ApproverError::Unavailable(format!(
            "uid {uid} has no graphical session"
        )));
    }
    let ty = LoginSessionProxy::builder(conn)
        .path(path)
        .map_err(unavailable)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(unavailable)?
        .session_type()
        .await
        .map_err(unavailable)?;
    Ok((id, ty))
}

async fn authority(conn: &zbus::Connection) -> zbus::Result<AuthorityProxy<'static>> {
    AuthorityProxy::builder(conn)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
}

/// A cancellation id unique among this process's calls: polkitd refuses a
/// second in-flight check with the same id from one caller.
fn cancellation_id(req: &ApprovalRequest) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("countersign-{}-{n}", req.request_id())
}

fn subject_json(subject: &Subject) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("kind".into(), subject.kind.into());
    for (k, v) in &subject.details {
        let v = match v {
            Value::U32(n) => serde_json::Value::from(*n),
            Value::U64(n) => serde_json::Value::from(*n),
            Value::I32(n) => serde_json::Value::from(*n),
            Value::Str(s) => serde_json::Value::from(s.as_str()),
            other => serde_json::Value::from(other.to_string()),
        };
        map.insert((*k).into(), v);
    }
    serde_json::Value::Object(map)
}

/// Withdraws a pending check: explicitly on expiry or cancel, or in the
/// background when the `present` future is dropped mid-call.
struct CancelGuard {
    conn: Option<zbus::Connection>,
    id: String,
}

impl CancelGuard {
    fn disarm(&mut self) {
        self.conn = None;
    }

    async fn cancel_now(&mut self) {
        if let Some(conn) = self.conn.take() {
            cancel_call(conn, std::mem::take(&mut self.id)).await;
        }
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else { return };
        // Without a runtime there is nothing to run the call on; the check
        // then ends when polkitd or the human ends it.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(cancel_call(conn, std::mem::take(&mut self.id)));
        }
    }
}

/// Best effort: the check may already have finished, and the caller has
/// already decided the outcome.
async fn cancel_call(conn: zbus::Connection, id: String) {
    let _ = tokio::time::timeout(CANCEL_TIMEOUT, async {
        authority(&conn)
            .await?
            .cancel_check_authorization(&id)
            .await
    })
    .await;
}

#[cfg(test)]
mod tests {
    use countersign_proto::ApprovalKind;

    use super::*;

    #[test]
    fn actions_come_from_the_config() {
        let c = PolkitConfig::default();
        assert_eq!(
            c.action(ApprovalKind::Use),
            "computer.mooselabs.countersign.approve"
        );
        assert_eq!(
            c.action(ApprovalKind::Export),
            "computer.mooselabs.countersign.mutate"
        );
        let a = PolkitApprover::new("polkit", c, Bus::default());
        assert_eq!(a.info().name, "polkit");
        assert!(!a.info().trusted_display);
    }
}
