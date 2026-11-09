//! The running daemon: its shared state, startup, the accept loop, timers,
//! signals, sessions and shutdown (design.md sections 1, 2, 5 and 6).
//!
//! All state sits behind one mutex. Every operation on it is short and
//! synchronous (the store and audit writes `fsync`, which is fine at the
//! volume a developer produces); nothing awaits while holding it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::unix::net::UnixListener as StdListener;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use countersign_core::audit::{AuditLog, Event, ListCoalescer, SessionRef};
use countersign_core::grants::{Grants, Policy};
use countersign_core::sessions::{Anchors, ProcFs, Session};
use countersign_core::store::Store;
use countersign_core::time::{Clock, SystemClock};
use countersign_proto::{ErrorBody, ErrorCode, LastUse, RequestState, Timestamp};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::Paths;
use crate::log::{error, info, warning};
use crate::requests::RequestRecord;
use crate::setup::{self, Runtime};
use crate::sys;
use crate::watch::Watcher;

/// How often the timer runs even when nothing is due: list coalescing
/// windows and hourly checkpoints are checked at this pace.
const TICK: Duration = Duration::from_secs(30);

/// Worker threads. `cnd` serves one developer; two keep a slow `fsync`
/// from stalling every other connection.
const WORKERS: usize = 2;

/// Grant bookkeeping the core grant table does not keep.
#[derive(Debug, Clone, Default)]
pub struct GrantInfo {
    /// Approver instances that approved it.
    pub approved_by: Vec<String>,
    /// Values issued under it (`run` and `reveal`).
    pub uses: u64,
}

/// A session `cnd` has seen and is watching.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    /// As discovery resolved it.
    pub session: Session,
    /// The anchor's uid.
    pub uid: u32,
    /// When the anchor started.
    pub started_at: Timestamp,
    /// The `session` object of its audit records (labels from the
    /// connection that first saw it).
    pub audit: SessionRef,
}

/// A `cn run` between `run` and `run_finish`.
#[derive(Debug, Clone)]
pub struct RunEntry {
    /// The session it ran in.
    pub session: SessionRef,
}

/// Everything behind the daemon's lock.
pub struct State {
    /// The store.
    pub store: Store,
    /// The audit log.
    pub audit: AuditLog,
    /// Pending requests and grants.
    pub grants: Grants,
    /// Anchors registered by `cn session exec`.
    pub anchors: Anchors,
    /// Live sessions, by id.
    pub sessions: HashMap<String, SessionEntry>,
    /// Requests by id, kept for `pending_expiry` after they are decided.
    pub requests: HashMap<String, RequestRecord>,
    /// Request code (`K7M-Q2X`) to request id.
    pub codes: HashMap<String, String>,
    /// Per-grant bookkeeping.
    pub grant_info: HashMap<String, GrantInfo>,
    /// Runs in progress, by run id.
    pub runs: HashMap<String, RunEntry>,
    /// `list` coalescing.
    pub lists: ListCoalescer,
    /// The `session` object for each session's coalesced `list` records.
    pub list_refs: HashMap<String, SessionRef>,
    /// `list` calls per session in the last minute.
    pub list_rate: HashMap<String, VecDeque<SystemTime>>,
    /// `hide` stream starts per session in the last minute.
    pub hide_streams: HashMap<String, VecDeque<SystemTime>>,
    /// `hide` bytes per session in the last minute.
    pub hide_bytes: HashMap<String, VecDeque<(SystemTime, u64)>>,
    /// The last time each secret's value was issued.
    pub last_use: HashMap<String, LastUse>,
}

impl State {
    /// Appends an audit record. A failure is logged and returned as false;
    /// the caller decides whether the action may go ahead.
    pub fn record(&mut self, session: Option<&SessionRef>, event: &Event) -> bool {
        match self.audit.append(session, event) {
            Ok(_) => true,
            Err(e) => {
                error!("audit write failed: {e}");
                false
            }
        }
    }

    /// Appends an audit record the action depends on: on failure the
    /// client gets `internal` and the action must not happen.
    pub fn must_record(
        &mut self,
        session: Option<&SessionRef>,
        event: &Event,
    ) -> Result<(), ErrorBody> {
        if self.record(session, event) {
            Ok(())
        } else {
            Err(internal("the audit log could not be written"))
        }
    }

    /// Whether a session is live.
    pub fn alive(&self, id: &str) -> bool {
        self.sessions.contains_key(id)
    }
}

/// An error body with no detail.
pub fn err(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        code,
        message: message.into(),
        detail: serde_json::Value::Null,
    }
}

/// `internal`, with the cause left to the daemon log.
pub fn internal(message: impl Into<String>) -> ErrorBody {
    err(ErrorCode::Internal, message)
}

/// The daemon, shared by every task.
pub struct Daemon {
    rt: RwLock<Arc<Runtime>>,
    state: Mutex<State>,
    /// Woken whenever a request is decided or expires.
    pub decided: Notify,
    /// Wakes the timer when a new deadline may be earlier.
    pub wake: Notify,
    /// `/etc/machine-id`.
    pub host: String,
    /// The boot id.
    pub boot_id: String,
    /// `/proc`.
    pub proc: ProcFs,
    /// The clock the core tables use.
    pub clock: Arc<dyn Clock>,
    /// Command-line paths, for reload.
    pub paths: Paths,
    /// Fired on SIGTERM.
    pub shutdown: CancellationToken,
    /// Anchor liveness.
    pub watcher: Watcher,
}

impl Daemon {
    /// The config in force.
    pub fn rt(&self) -> Arc<Runtime> {
        self.rt
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The state lock.
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Now, by the daemon's clock.
    pub fn now(&self) -> SystemTime {
        self.clock.now()
    }

    /// Records a newly seen session and starts watching its anchor. Returns
    /// false when the anchor has already exited.
    pub fn ensure_session(
        self: &Arc<Self>,
        session: &Session,
        uid: u32,
        labels: &BTreeMap<String, String>,
    ) -> bool {
        {
            let mut st = self.lock();
            if st.sessions.contains_key(&session.id) {
                return true;
            }
            let started_at = self.proc.started_at(session.anchor.start_time).map_or_else(
                || Timestamp::from_system_time(self.now()),
                Timestamp::from_system_time,
            );
            let audit = session.audit_ref(labels);
            st.record(
                Some(&audit),
                &Event::SessionStart {
                    chain: session.chain_links(),
                },
            );
            st.sessions.insert(
                session.id.clone(),
                SessionEntry {
                    session: session.clone(),
                    uid,
                    started_at,
                    audit,
                },
            );
        }
        let anchor = session.anchor.clone();
        let Ok(fd) = sys::open_pidfd(anchor.pid) else {
            self.end_session(&session.id);
            return false;
        };
        // The pid may have been reused before the pidfd was opened.
        let same = self
            .proc
            .process(anchor.pid)
            .is_ok_and(|p| p.start_time == anchor.start_time);
        if !same || sys::pidfd_exited(&fd) {
            self.end_session(&session.id);
            return false;
        }
        if let Err(e) = self.watcher.watch(fd, session.id.clone()) {
            error!("watching anchor {}: {e}", anchor.pid);
            self.end_session(&session.id);
            return false;
        }
        true
    }

    /// The session's anchor exited: its pending requests expire, its grants
    /// end, and `session.end` is written.
    pub fn end_session(&self, id: &str) {
        let mut st = self.lock();
        let Some(entry) = st.sessions.remove(id) else {
            return;
        };
        let expired = st.grants.end_session(id);
        for r in &expired.requests {
            st.close_request(&r.id, RequestState::Expired, None);
        }
        let grants_expired = u32::try_from(expired.grants.len()).unwrap_or(u32::MAX);
        for g in expired.grants {
            st.grant_info.remove(&g.id);
            st.record(
                Some(&entry.audit),
                &Event::GrantExpire {
                    grant_id: g.id,
                    secrets: g.names,
                    by: "anchor_exit".into(),
                },
            );
        }
        if let Some(rec) = st.lists.end_session(id) {
            st.record(Some(&entry.audit), &rec.event());
        }
        st.record(Some(&entry.audit), &Event::SessionEnd { grants_expired });
        if entry.session.registered() {
            st.anchors
                .unregister(entry.session.anchor.pid, entry.session.anchor.start_time);
        }
        st.list_refs.remove(id);
        st.list_rate.remove(id);
        st.hide_streams.remove(id);
        st.hide_bytes.remove(id);
        drop(st);
        self.decided.notify_waiters();
    }

    /// Expiry sweep, coalesced `list` records, retention of decided
    /// requests, and checkpoints.
    fn tick(&self) {
        let rt = self.rt();
        let now = self.now();
        let mut st = self.lock();
        let ex = st.grants.sweep();
        let changed = !ex.requests.is_empty();
        for r in &ex.requests {
            st.close_request(&r.id, RequestState::Expired, None);
        }
        for g in ex.grants {
            st.grant_info.remove(&g.id);
            let sref = st.sessions.get(&g.session).map(|s| s.audit.clone());
            st.record(
                sref.as_ref(),
                &Event::GrantExpire {
                    grant_id: g.id,
                    secrets: g.names,
                    by: "ttl".into(),
                },
            );
        }
        let keep = rt.config.grants.pending_expiry;
        let stale: Vec<String> = st
            .requests
            .values()
            .filter(|r| {
                r.decided_at
                    .is_some_and(|at| now.duration_since(at).unwrap_or_default() >= keep)
            })
            .map(|r| r.view.request.request_id.clone())
            .collect();
        for id in stale {
            if let Some(r) = st.requests.remove(&id) {
                st.codes.remove(&r.view.request.code);
            }
        }
        for (sid, rec) in st.lists.flush(now) {
            let sref = st.list_refs.get(&sid).cloned();
            st.record(sref.as_ref(), &rec.event());
        }
        if let Err(e) = st.audit.maybe_checkpoint() {
            error!("audit checkpoint failed: {e}");
        }
        drop(st);
        if changed {
            self.decided.notify_waiters();
        }
    }

    /// When the timer should next run.
    fn next_tick(&self) -> Duration {
        let now = self.now();
        let st = self.lock();
        let deadline = st
            .grants
            .next_deadline()
            .map(|t| t.duration_since(now).unwrap_or_default());
        deadline.map_or(TICK, |d| d.min(TICK))
    }

    /// Re-reads the config (SIGHUP, `systemctl reload`). On an error the
    /// old config stays in force.
    fn reload(&self) {
        let _ = sys::notify(&format!(
            "RELOADING=1\nMONOTONIC_USEC={}",
            sys::monotonic_usec()
        ));
        match setup::load_runtime(&self.paths)
            .and_then(|rt| setup::check_own_uid(&self.paths, Some(&rt.uids)).map(|()| rt))
        {
            Ok(rt) => {
                let mut st = self.lock();
                st.grants.set_policy(Policy::from_config(&rt.config));
                st.record(
                    None,
                    &Event::ConfigLoad {
                        path: rt.path.display().to_string(),
                        sha256: rt.sha256.clone(),
                        approvers: rt.approvers_summary(),
                    },
                );
                drop(st);
                *self.rt.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(rt);
                info!("config reloaded from {}", self.paths.config.display());
            }
            Err(e) => error!("reload failed; the previous config stays in force: {e}"),
        }
        let _ = sys::notify("READY=1");
    }

    /// Writes what a stop owes the audit log: pending `list` counts, the
    /// grants a restart drops, `daemon.stop` and a final checkpoint.
    fn stop(&self, reason: &str) {
        let mut st = self.lock();
        let far = self.now() + Duration::from_secs(365 * 86_400);
        for (sid, rec) in st.lists.flush(far) {
            let sref = st.list_refs.get(&sid).cloned();
            st.record(sref.as_ref(), &rec.event());
        }
        let ids: Vec<String> = st.sessions.keys().cloned().collect();
        for sid in ids {
            let sref = st.sessions.get(&sid).map(|s| s.audit.clone());
            for g in st.grants.revoke(&sid, None).unwrap_or_default() {
                st.record(
                    sref.as_ref(),
                    &Event::GrantRevoke {
                        grant_id: g.id,
                        secrets: g.names,
                        by: "restart".into(),
                    },
                );
            }
        }
        st.record(
            None,
            &Event::DaemonStop {
                reason: reason.into(),
            },
        );
        if let Err(e) = st.audit.checkpoint() {
            error!("final audit checkpoint failed: {e}");
        }
    }
}

/// `cnd serve`.
pub fn serve(paths: Paths) -> Result<(), String> {
    sys::check_kernel()?;
    match sys::lock_memory() {
        (true, line) => info!("{line}"),
        (false, line) => warning!("{line}"),
    }
    let rt = setup::load_runtime(&paths)?;
    setup::check_own_uid(&paths, Some(&rt.uids))?;
    let mk = setup::master_key(&paths)?;
    let store = Store::open(&paths.state_dir, &mk)
        .map_err(|e| format!("store {}: {e}", paths.state_dir.display()))?;
    drop(mk);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let host = setup::machine_id();
    let boot_id = setup::boot_id()?;
    let mut audit =
        setup::open_audit(&rt.config, &paths.state_dir, &host, &boot_id, clock.clone())?;
    if audit.truncated_bytes() > 0 {
        warning!(
            "audit log: cut {} bytes of an unfinished last record (a crash during a write)",
            audit.truncated_bytes()
        );
    }
    audit
        .set_signer(&store.checkpoint_seed())
        .map_err(|e| format!("audit log: {e}"))?;
    let listener = listener(&paths)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .max_blocking_threads(WORKERS)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio: {e}"))?;
    let rt_config = &rt.config;
    let state = State {
        grants: Grants::new(Policy::from_config(rt_config), clock.clone()),
        lists: ListCoalescer::new(rt_config.audit.list_coalesce),
        store,
        audit,
        anchors: Anchors::new(),
        sessions: HashMap::new(),
        requests: HashMap::new(),
        codes: HashMap::new(),
        grant_info: HashMap::new(),
        runs: HashMap::new(),
        list_refs: HashMap::new(),
        list_rate: HashMap::new(),
        hide_streams: HashMap::new(),
        hide_bytes: HashMap::new(),
        last_use: HashMap::new(),
    };
    let daemon = Arc::new(Daemon {
        rt: RwLock::new(Arc::new(rt)),
        state: Mutex::new(state),
        decided: Notify::new(),
        wake: Notify::new(),
        host,
        boot_id,
        proc: ProcFs::default(),
        clock,
        paths,
        shutdown: CancellationToken::new(),
        watcher: Watcher::new().map_err(|e| format!("epoll: {e}"))?,
    });
    let watching = daemon.clone();
    std::thread::Builder::new()
        .name("anchors".into())
        .spawn(move || watching.watcher.run(|id| watching.end_session(id)))
        .map_err(|e| format!("anchor watcher thread: {e}"))?;
    runtime.block_on(run(daemon, listener))
}

/// The socket systemd passed, or in test builds the `--socket` path.
fn listener(paths: &Paths) -> Result<StdListener, String> {
    if let Some(l) = sys::listen_fd::take()? {
        return Ok(l);
    }
    match &paths.socket {
        Some(path) => {
            let _ = std::fs::remove_file(path);
            StdListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))
        }
        None => {
            Err("no socket: cnd is socket activated; start it through countersign.socket".into())
        }
    }
}

async fn run(d: Arc<Daemon>, listener: StdListener) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("socket: {e}"))?;
    let listener = UnixListener::from_std(listener).map_err(|e| format!("socket: {e}"))?;
    let rt = d.rt();
    {
        let mut st = d.lock();
        let generation = st.store.generation();
        let count = st.store.list().count();
        let starts = [
            Event::DaemonStart {
                version: env!("CARGO_PKG_VERSION").into(),
                pid: std::process::id(),
                unseal: "systemd-creds".into(),
            },
            Event::StoreUnseal {
                slot: "systemd-creds".into(),
            },
            Event::ConfigLoad {
                path: rt.path.display().to_string(),
                sha256: rt.sha256.clone(),
                approvers: rt.approvers_summary(),
            },
        ];
        for ev in &starts {
            if !st.record(None, ev) {
                return Err("cannot write the audit log; refusing to serve".into());
            }
        }
        info!(
            "cnd {} serving: store generation {generation}, {count} secrets, {} allowed uids",
            env!("CARGO_PKG_VERSION"),
            rt.uids.len()
        );
    }
    for p in &rt.polkit {
        let p = p.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(5), p.backend_version()).await {
                Ok(Ok(v)) => info!("polkit backend version {v}"),
                Ok(Err(e)) => warning!("polkit: {e}"),
                Err(_) => warning!("polkit: no answer to BackendVersion within 5s"),
            }
        });
    }
    drop(rt);

    let timers = tokio::spawn(timer_loop(d.clone()));
    let signals = tokio::spawn(signal_loop(d.clone()));
    let _ = sys::notify("READY=1\nSTATUS=serving");

    loop {
        tokio::select! {
            () = d.shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(crate::conn::handle(d.clone(), stream));
                }
                Err(e) => {
                    warning!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
    let _ = sys::notify("STOPPING=1");
    d.stop("signal");
    timers.abort();
    signals.abort();
    info!("cnd stopped");
    Ok(())
}

async fn timer_loop(d: Arc<Daemon>) {
    loop {
        let wait = d.next_tick();
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = d.wake.notified() => {}
            () = d.shutdown.cancelled() => return,
        }
        d.tick();
    }
}

async fn signal_loop(d: Arc<Daemon>) {
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        error!("cannot install signal handlers");
        return;
    };
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = int.recv() => break,
            _ = hup.recv() => d.reload(),
        }
    }
    d.shutdown.cancel();
}
