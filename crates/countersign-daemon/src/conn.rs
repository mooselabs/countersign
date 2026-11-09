//! One client connection (design.md section 4): peer credentials, the
//! handshake, session discovery, then one request at a time.
//!
//! The peer is identified by the kernel: `SO_PEERCRED` for its uid and pid,
//! `SO_PEERPIDFD` for a pidfd that proves the pid still names the process
//! that connected. Nothing the client says about itself is trusted; its
//! labels and cwd are carried as untrusted text.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use countersign_core::audit::Event;
use countersign_core::sessions::{Discovery, ProcInfo, Session, SessionError, filter_labels};
use countersign_proto::{ErrorBody, ErrorCode, PROTOCOL_VERSION, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream;

use crate::daemon::{Daemon, err, prune, prune_bytes};
use crate::frames::{self, Frame};
use crate::log::{info, warning};
use crate::requests::{Asker, Change};
use crate::sys;
use crate::views;

/// Longest cwd kept from `hello`, in bytes.
const MAX_CWD: usize = 4096;

/// A client has this long to send `hello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// A client over its connection limit has this long to send `hello` and
/// be told why it is refused; then it is dropped.
const REFUSED_HELLO_TIMEOUT: Duration = Duration::from_millis(200);

/// A handshaken connection.
pub struct Conn {
    /// The daemon.
    pub d: Arc<Daemon>,
    /// Peer uid, from `SO_PEERCRED`.
    pub uid: u32,
    /// Peer pid, from `SO_PEERCRED`.
    pub pid: u32,
    /// Peer pidfd, from `SO_PEERPIDFD`.
    pub pidfd: OwnedFd,
    /// Labels the client reported, filtered by `label_env`.
    pub labels: BTreeMap<String, String>,
    /// The cwd the client reported.
    pub cwd: Option<String>,
    /// The agent session discovery found, if any.
    pub session: Option<Session>,
    /// The process chain discovery walked.
    pub chain: Vec<ProcInfo>,
    /// The peer user's home directory.
    pub home: Option<String>,
    /// The run this connection started and has not finished.
    pub run: Option<String>,
    /// Why the session discovery found could not be used (too many live
    /// sessions for the uid): the error calls that need it get.
    pub refused: Option<ErrorBody>,
}

impl Conn {
    /// The caller's agent session, or `no_session` / `session_dead`.
    pub fn agent(&self) -> Result<&Session, ErrorBody> {
        if let Some(e) = &self.refused {
            return Err(e.clone());
        }
        let s = self.session.as_ref().ok_or_else(views::no_session)?;
        if s.is_human() {
            return Err(views::no_session());
        }
        if !self.d.lock().alive(&s.id) {
            return Err(err(
                ErrorCode::SessionDead,
                "the session's anchor has exited",
            ));
        }
        Ok(s)
    }

    /// The agent session, or a human pseudo session (`h_`) when there is
    /// none: for store changes and read-only calls only.
    pub fn caller(&self) -> Result<Session, ErrorBody> {
        if self.session.is_some() || self.refused.is_some() {
            return self.agent().cloned();
        }
        let rt = self.d.rt();
        let st = self.d.lock();
        let discovery = Discovery {
            proc: &self.d.proc,
            anchors: &st.anchors,
            matchers: &rt.config.sessions.matchers,
        };
        discovery
            .human_session(self.pid, self.uid)
            .map_err(|e| session_error(&e))
    }

    /// Who is asking, for a request.
    pub fn asker<'a>(&'a self, session: &'a Session) -> Asker<'a> {
        Asker {
            session,
            uid: self.uid,
            labels: &self.labels,
            cwd: self.cwd.as_deref(),
            home: self.home.as_deref(),
        }
    }

    /// Finds the peer's session and starts watching it.
    fn discover(&mut self) {
        let rt = self.d.rt();
        let found = {
            let st = self.d.lock();
            let discovery = Discovery {
                proc: &self.d.proc,
                anchors: &st.anchors,
                matchers: &rt.config.sessions.matchers,
            };
            discovery.discover(self.pid, self.uid)
        };
        // The walk read /proc by pid; the pidfd shows the pid still named the
        // peer when it finished.
        if sys::pidfd_exited(&self.pidfd) {
            return;
        }
        // Labels are agent text: redact the session's values from them
        // before they reach a dialog or the audit log.
        let sid = found.as_ref().map_or("", |s| s.id.as_str());
        self.labels = {
            let st = self.d.lock();
            views::redact_labels(&st, &rt, sid, &self.labels)
        };
        match found {
            Ok(s) => {
                self.chain = s.chain.clone();
                match self.d.ensure_session(&s, self.uid, &self.labels) {
                    Ok(()) => self.session = Some(s),
                    Err(e) if e.code == ErrorCode::RateLimited => self.refused = Some(e),
                    Err(_) => {}
                }
            }
            Err(SessionError::NoSession { chain }) => self.chain = chain,
            Err(e) => warning!("session discovery for pid {}: {e}", self.pid),
        }
    }
}

/// The protocol error for a discovery failure.
pub fn session_error(e: &SessionError) -> ErrorBody {
    match e.code() {
        ErrorCode::Internal => {
            warning!("session discovery: {e}");
            err(ErrorCode::Internal, "session discovery failed")
        }
        code => err(code, e.to_string()),
    }
}

/// The home directory of `uid` from `/etc/passwd`.
fn home_of(uid: u32) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[2].parse() == Ok(uid)).then(|| f[5].to_owned())
    })
}

/// Counts a uid's open connection while it lives.
struct Slot {
    d: Arc<Daemon>,
    uid: u32,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut st = self.d.lock();
        if let Some(n) = st.connections.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.connections.remove(&self.uid);
            }
        }
    }
}

/// Takes a connection slot for `uid`, or says how many it already holds.
fn take_slot(d: &Arc<Daemon>, uid: u32) -> Result<Slot, usize> {
    let max = d.rt().config.limits.max_connections_per_uid;
    let mut st = d.lock();
    let n = st.connections.entry(uid).or_default();
    if *n >= max {
        return Err(*n);
    }
    *n += 1;
    Ok(Slot { d: d.clone(), uid })
}

/// Serves one connection until it closes.
pub async fn handle(d: Arc<Daemon>, stream: UnixStream) {
    let Ok(cred) = stream.peer_cred() else {
        return;
    };
    let uid = cred.uid();
    let pid = cred.pid().and_then(|p| u32::try_from(p).ok()).unwrap_or(0);
    let slot = take_slot(&d, uid);
    let (mut r, mut w) = stream.into_split();
    let wait = if slot.is_ok() {
        HELLO_TIMEOUT
    } else {
        REFUSED_HELLO_TIMEOUT
    };
    let hello = tokio::time::timeout(wait, frames::read(&mut r)).await;
    let Ok(Ok(Some(Frame::Request(id, hello)))) = hello else {
        return;
    };
    let _slot = match slot {
        Ok(slot) => slot,
        Err(n) => {
            let body = err(
                ErrorCode::RateLimited,
                format!(
                    "uid {uid} already has {n} connections open ([limits] max_connections_per_uid)"
                ),
            );
            let _ = frames::write_message(&mut w, id, &Response::Error(body)).await;
            return;
        }
    };
    let Ok(pidfd) = sys::peer_pidfd(r.as_ref()) else {
        warning!("connection from uid {uid}: no SO_PEERPIDFD");
        return;
    };
    let Request::Hello {
        protocols,
        labels,
        cwd,
        ..
    } = *hello
    else {
        return;
    };
    let rt = d.rt();
    if !rt.allows(uid) {
        d.lock().record(
            None,
            &Event::PeerReject {
                uid,
                pid,
                code: "forbidden_peer".into(),
            },
        );
        let body = err(
            ErrorCode::ForbiddenPeer,
            format!("uid {uid} is not in [access] users"),
        );
        let _ = frames::write_message(&mut w, id, &Response::Error(body)).await;
        return;
    }
    if !protocols.contains(&PROTOCOL_VERSION) {
        let body = err(
            ErrorCode::UnsupportedVersion,
            format!("cnd speaks protocol {PROTOCOL_VERSION}"),
        );
        let _ = frames::write_message(&mut w, id, &Response::Error(body)).await;
        return;
    }
    let mut conn = Conn {
        labels: filter_labels(&rt.config.sessions.label_env, &labels),
        cwd: cwd.map(|c| views::truncate_utf8(&c, MAX_CWD)),
        d,
        uid,
        pid,
        pidfd,
        session: None,
        chain: Vec::new(),
        home: home_of(uid),
        run: None,
        refused: None,
    };
    drop(rt);
    conn.discover();
    let view = conn.session_view();
    let hello_ok = Response::HelloOk {
        protocol: PROTOCOL_VERSION,
        server: concat!("cnd/", env!("CARGO_PKG_VERSION")).into(),
        session: view,
    };
    if frames::write_message(&mut w, id, &hello_ok).await.is_err() {
        return;
    }
    loop {
        let idle = conn.d.rt().config.limits.idle_timeout;
        // A connection waiting on its `cn run` child may be quiet for as
        // long as the child runs.
        let waiting_on_run = conn.run.is_some();
        let read = tokio::select! {
            read = frames::read(&mut r) => read,
            () = conn.d.shutdown.cancelled() => break,
            () = tokio::time::sleep(idle), if !waiting_on_run => {
                info!("closing a connection from pid {pid}: idle for {}s", idle.as_secs());
                break;
            }
        };
        let frame = match read {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::InvalidData {
                    info!("closing a connection from pid {pid}: {e}");
                }
                break;
            }
        };
        // The process that connected is gone (the socket was passed on or
        // outlived it): the connection and its session go with it.
        if sys::pidfd_exited(&conn.pidfd) {
            info!("closing a connection from pid {pid}: the process has exited");
            break;
        }
        let (id, request) = match frame {
            Frame::Request(id, req) => (id, req),
            Frame::Bad(id, body) => {
                if frames::write_message(&mut w, id, &Response::Error(body))
                    .await
                    .is_err()
                {
                    break;
                }
                continue;
            }
            Frame::Stream(_) => break,
        };
        let response = match *request {
            Request::Hide { secrets } => match conn.hide(id, &secrets, &mut r, &mut w).await {
                Ok(()) => continue,
                Err(()) => break,
            },
            other => conn.dispatch(other).await,
        };
        let response = response.unwrap_or_else(Response::Error);
        if frames::write_message(&mut w, id, &response).await.is_err() {
            break;
        }
    }
    conn.client_lost();
}

impl Conn {
    async fn dispatch(&mut self, request: Request) -> Result<Response, ErrorBody> {
        match request {
            Request::Hello { .. } => Err(err(ErrorCode::BadRequest, "hello was already sent")),
            Request::Session => self.session(),
            Request::List { all_projects } => self.list(all_projects),
            Request::Request {
                names,
                mode,
                ttl_seconds,
                reason,
            } => {
                let s = self.agent()?.clone();
                self.d
                    .create_grant(&self.asker(&s), &names, mode, ttl_seconds, &reason)
            }
            Request::GetRequest { code, wait_seconds } => {
                self.d.get_request(&code, wait_seconds).await
            }
            Request::Approve { .. } => Err(err(
                ErrorCode::BadRequest,
                "this version has no approver that cn approve drives; answer the desktop dialog",
            )),
            Request::Deny { code, reason } => {
                let who = self.denier();
                self.d.deny(&code, reason, &who)
            }
            Request::Grants { all_sessions } => self.grants(all_sessions),
            Request::Revoke {
                grant_ids,
                secret,
                all,
                all_sessions,
            } => self.revoke(&grant_ids, secret.as_deref(), all, all_sessions),
            Request::Run { uses, argv0, argc } => self.start_run(&uses, &argv0, argc),
            Request::RunFinish {
                run_id,
                exit,
                signal,
                duration_ms,
                hits,
            } => self.finish_run(&run_id, exit, signal, duration_ms, hits),
            Request::Hide { .. } | Request::HideEnd => {
                Err(err(ErrorCode::BadRequest, "hide_end outside a hide stream"))
            }
            Request::Reveal { name } => self.reveal(&name),
            Request::Add {
                meta,
                value_b64,
                source,
            } => self.change(Change::Add {
                meta,
                value: value_b64,
                source,
            }),
            Request::Set {
                name,
                value_b64,
                source,
            } => self.change(Change::Set {
                name,
                value: value_b64,
                source,
            }),
            Request::Edit { meta } => self.change(Change::Edit { meta }),
            Request::Rm { names } => self.change(Change::Rm { names }),
            Request::Import { secrets } => self.change(Change::Import { items: secrets }),
            Request::AuditQuery {
                session,
                secret,
                events,
                since,
                until,
                after_seq,
                limit,
            } => {
                self.audit_query(session, secret, events, since, until, after_seq, limit)
                    .await
            }
            Request::AuditSegments { from_seq } => self.audit_segments(from_seq).await,
            Request::SessionRegister { label } => self.register(label),
            Request::Unlock { .. } => Err(err(
                ErrorCode::UnknownRequest,
                "unlock (FIDO2 store unlock) is not in this version",
            )),
        }
    }

    fn change(&self, change: Change) -> Result<Response, ErrorBody> {
        let s = self.caller()?;
        if s.is_human() {
            self.d.ensure_session(&s, self.uid, &self.labels)?;
        }
        self.d.create_change(&self.asker(&s), change)
    }

    /// Who sent a `cn deny`, for its audit record.
    fn denier(&self) -> Denier {
        let comm = self
            .chain
            .first()
            .filter(|p| p.pid == self.pid)
            .map(|p| p.comm.clone())
            .or_else(|| self.d.proc.process(self.pid).ok().map(|p| p.comm));
        Denier {
            uid: self.uid,
            pid: self.pid,
            comm,
            session: self.caller().ok(),
        }
    }

    /// The connection closed: a run it started is recorded as `client_lost`.
    fn client_lost(&mut self) {
        let Some(run_id) = self.run.take() else {
            return;
        };
        let mut st = self.d.lock();
        if let Some(run) = st.runs.remove(&run_id) {
            st.record(
                Some(&run.session),
                &Event::UseEnd {
                    run_id,
                    status: "client_lost".into(),
                    exit: None,
                    signal: None,
                    duration_ms: 0,
                    hits: BTreeMap::new(),
                },
            );
        }
    }

    /// A `cn hide` stream: stream frames in, scrubbed stream frames out,
    /// `hide_end`, then `hide_summary`. `Err` closes the connection.
    async fn hide(
        &mut self,
        id: u64,
        extra: &[String],
        r: &mut (impl AsyncRead + Unpin),
        w: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), ()> {
        let started = match self.start_hide(extra) {
            Ok(x) => x,
            Err(body) => {
                return frames::write_message(w, id, &Response::Error(body))
                    .await
                    .map_err(|_| ());
            }
        };
        let (session, sref, redactor) = started;
        frames::write_message(w, id, &Response::HideOk)
            .await
            .map_err(|_| ())?;
        let mut stream = redactor.stream();
        let (mut bytes_in, mut bytes_out) = (0u64, 0u64);
        let mut out = Vec::new();
        // Every stream is audited, also one the client abandons: hit counts
        // are how probing shows up (design.md section 8).
        let record = |bytes_in, hits: &countersign_hide::Hits| {
            self.d.lock().record(
                Some(&sref),
                &Event::Hide {
                    bytes_in,
                    hits: hits.clone(),
                    patterns: redactor.patterns() as u64,
                },
            );
        };
        loop {
            let frame = tokio::select! {
                frame = frames::read(r) => frame,
                () = self.d.shutdown.cancelled() => {
                    let hits = stream.finish(&mut out);
                    zeroize::Zeroize::zeroize(&mut out);
                    record(bytes_in, &hits);
                    return Err(());
                }
            };
            match frame {
                Ok(Some(Frame::Stream(mut data))) => {
                    if let Err(body) = self.hide_budget(&session, data.len() as u64) {
                        zeroize::Zeroize::zeroize(&mut data);
                        let mut rest = Vec::new();
                        let hits = stream.finish(&mut rest);
                        zeroize::Zeroize::zeroize(&mut rest);
                        record(bytes_in, &hits);
                        let _ = frames::write_message(w, id, &Response::Error(body)).await;
                        return Err(());
                    }
                    bytes_in += data.len() as u64;
                    stream.push(&data, &mut out);
                    zeroize::Zeroize::zeroize(&mut data);
                    if !out.is_empty() {
                        bytes_out += out.len() as u64;
                        let sent = frames::write_stream(w, &out).await;
                        zeroize::Zeroize::zeroize(&mut out);
                        out.clear();
                        if sent.is_err() {
                            let hits = stream.finish(&mut out);
                            zeroize::Zeroize::zeroize(&mut out);
                            record(bytes_in, &hits);
                            return Err(());
                        }
                    }
                }
                Ok(Some(Frame::Request(end_id, req))) if matches!(*req, Request::HideEnd) => {
                    let hits = stream.finish(&mut out);
                    bytes_out += out.len() as u64;
                    let sent = frames::write_stream(w, &out).await;
                    zeroize::Zeroize::zeroize(&mut out);
                    record(bytes_in, &hits);
                    sent.map_err(|_| ())?;
                    let summary = Response::HideSummary {
                        bytes_in,
                        bytes_out,
                        hits,
                    };
                    return frames::write_message(w, end_id, &summary)
                        .await
                        .map_err(|_| ());
                }
                // Anything else ends the stream and the connection. The
                // carried tail is never sent.
                _ => {
                    let hits = stream.finish(&mut out);
                    zeroize::Zeroize::zeroize(&mut out);
                    record(bytes_in, &hits);
                    return Err(());
                }
            }
        }
    }

    fn start_hide(
        &self,
        extra: &[String],
    ) -> Result<
        (
            String,
            countersign_core::audit::SessionRef,
            countersign_hide::Redactor,
        ),
        ErrorBody,
    > {
        let s = self.caller()?;
        let rt = self.d.rt();
        let now = self.d.now();
        let mut st = self.d.lock();
        let limit = |what: &str| {
            err(
                ErrorCode::RateLimited,
                format!("too many hide streams {what}"),
            )
        };
        let session = st.hide_streams.entry(s.id.clone()).or_default();
        prune(session, now);
        if session.len() >= rt.config.hide.max_streams_per_minute as usize {
            return Err(limit("in this session in the last minute"));
        }
        let user = st.uid_hide_streams.entry(self.uid).or_default();
        prune(user, now);
        if user.len() >= rt.config.hide.max_streams_per_minute_per_uid as usize {
            return Err(limit("from this user in the last minute"));
        }
        user.push_back(now);
        st.hide_streams
            .entry(s.id.clone())
            .or_default()
            .push_back(now);
        let redactor = views::hide_redactor(&st, &rt, &s.id, extra)?;
        Ok((s.id.clone(), s.audit_ref(&self.labels), redactor))
    }

    fn hide_budget(&self, session: &str, n: u64) -> Result<(), ErrorBody> {
        let rt = self.d.rt();
        let now = self.d.now();
        let mut st = self.d.lock();
        let spent = || {
            err(
                ErrorCode::RateLimited,
                "hide byte budget for this minute is spent",
            )
        };
        let used = prune_bytes(st.hide_bytes.entry(session.to_owned()).or_default(), now);
        if used + n > rt.config.hide.max_bytes_per_minute {
            return Err(spent());
        }
        let used_uid = prune_bytes(st.uid_hide_bytes.entry(self.uid).or_default(), now);
        if used_uid + n > rt.config.hide.max_bytes_per_minute_per_uid {
            return Err(spent());
        }
        st.hide_bytes
            .entry(session.to_owned())
            .or_default()
            .push_back((now, n));
        st.uid_hide_bytes
            .entry(self.uid)
            .or_default()
            .push_back((now, n));
        Ok(())
    }
}

/// Who sent a `cn deny`.
pub struct Denier {
    /// Peer uid.
    pub uid: u32,
    /// Peer pid.
    pub pid: u32,
    /// The peer's `comm`, read from `/proc`.
    pub comm: Option<String>,
    /// The peer's session: an agent session, or a terminal (`h_`) one.
    pub session: Option<Session>,
}
