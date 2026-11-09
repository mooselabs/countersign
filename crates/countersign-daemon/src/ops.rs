//! The requests that need no approval: sessions, `list`, `grants`,
//! `revoke`, `run`, `reveal` and the audit reads (design.md sections 4, 5,
//! 7 and audit.md).
//!
//! A value leaves `cnd` only for `run` (into the child's environment) and
//! `reveal`, after its audit record is written; if that write fails the
//! value is not sent.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use countersign_core::audit::{Event, PUBKEY_FILE, Query};
use countersign_core::config::ListScope;
use countersign_core::random_id;
use countersign_core::sessions::{AnchorKind, Discovery};
use countersign_core::store::valid_name;
use countersign_proto::{
    ErrorBody, ErrorCode, GrantView, LastUse, MAX_MESSAGE_LEN, Mode, Response, RunValue,
    ScrubValue, SessionView, Timestamp, Use, ValueB64,
};
use serde_json::Value;

use crate::conn::{Conn, session_error};
use crate::daemon::{RunEntry, err, internal, prune};
use crate::log::error;
use crate::requests::store_error;
use crate::sys;
use crate::views;

/// Most audit records one `audit_query` returns.
const MAX_QUERY: usize = 1000;
/// Raw bytes per `audit_segments` answer; base64 and the envelope must fit
/// one 1 MiB frame.
const SEGMENT_BYTES: usize = 700 << 10;
/// Longest `argv0` recorded.
const MAX_ARGV0: usize = 256;
/// Longest `cn session exec --label` kept.
const MAX_LABEL: usize = 128;

impl Conn {
    /// The view `hello` and `session` report for the agent session.
    pub fn session_view(&self) -> Option<SessionView> {
        let s = self.session.as_ref()?;
        let st = self.d.lock();
        let entry = st.sessions.get(&s.id)?;
        let grants = st.grants.grants_for(&s.id).len();
        Some(views::session_view(
            entry,
            s,
            &self.chain,
            &self.labels,
            self.cwd.as_deref(),
            grants,
        ))
    }

    /// `session`.
    pub fn session(&self) -> Result<Response, ErrorBody> {
        self.agent()?;
        self.session_view()
            .map(|session| Response::Session { session })
            .ok_or_else(|| err(ErrorCode::SessionDead, "the session's anchor has exited"))
    }

    /// `session_register`: the caller becomes an anchor. `cn session exec`
    /// then `exec`s the agent, which keeps the pid and start time.
    pub fn register(&mut self, label: Option<String>) -> Result<Response, ErrorBody> {
        let rt = self.d.rt();
        // The new session does not exist yet. The caller may already be in
        // one (an agent running cn session exec), holding grants whose
        // values it could paste into the label: redact with that session's
        // hide set, which also holds the values that need no grant.
        let caller = self
            .session
            .as_ref()
            .map(|s| s.id.clone())
            .or_else(|| self.caller().ok().map(|s| s.id))
            .unwrap_or_default();
        let label = label
            .map(|l| {
                let clean: String = l
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .collect();
                let clean = views::truncate_utf8(clean.trim(), MAX_LABEL);
                views::redact_label(&self.d.lock(), &rt, &caller, &clean)
            })
            .filter(|l| !l.is_empty());
        let me = self.d.proc.process(self.pid).map_err(|e| {
            error!("session_register: /proc/{}: {e}", self.pid);
            err(
                ErrorCode::NoSession,
                "the calling process could not be read",
            )
        })?;
        if me.uid != self.uid || me.euid != self.uid || sys::pidfd_exited(&self.pidfd) {
            return Err(err(
                ErrorCode::ForbiddenPeer,
                "the calling process changed during registration",
            ));
        }
        let found = {
            let mut st = self.d.lock();
            st.anchors.register(me.pid, me.start_time, label);
            let discovery = Discovery {
                proc: &self.d.proc,
                anchors: &st.anchors,
                matchers: &rt.config.sessions.matchers,
            };
            discovery.discover(self.pid, self.uid)
        };
        let session = found.map_err(|e| session_error(&e))?;
        if !matches!(session.kind, AnchorKind::Registered { .. }) || session.anchor.pid != me.pid {
            return Err(internal("registration did not take"));
        }
        if let Err(e) = self.d.ensure_session(&session, self.uid, &self.labels) {
            let mut st = self.d.lock();
            st.anchors.unregister(me.pid, me.start_time);
            return Err(e);
        }
        self.refused = None;
        self.chain = session.chain.clone();
        self.session = Some(session);
        let view = self
            .session_view()
            .ok_or_else(|| err(ErrorCode::SessionDead, "the caller exited"))?;
        Ok(Response::Registered { session: view })
    }

    /// `list`: metadata only, never a value or its length.
    pub fn list(&self, all_projects: bool) -> Result<Response, ErrorBody> {
        let s = self.caller()?;
        let rt = self.d.rt();
        let now = self.d.now();
        let all = all_projects || rt.config.list.default_scope == ListScope::All;
        let mut st = self.d.lock();
        let calls = st.list_rate.entry(s.id.clone()).or_default();
        prune(calls, now);
        if calls.len() >= rt.config.limits.list_calls_per_minute as usize {
            return Err(err(
                ErrorCode::RateLimited,
                "too many list calls in the last minute",
            ));
        }
        let user = st.uid_list_rate.entry(self.uid).or_default();
        prune(user, now);
        if user.len() >= rt.config.limits.list_calls_per_minute_per_uid as usize {
            return Err(err(
                ErrorCode::RateLimited,
                "too many list calls from this user in the last minute",
            ));
        }
        user.push_back(now);
        st.list_rate.entry(s.id.clone()).or_default().push_back(now);
        let sref = s.audit_ref(&self.labels);
        st.list_refs.insert(s.id.clone(), sref.clone());
        if let Some(rec) = st.lists.on_list(&s.id, now) {
            st.record(Some(&sref), &rec.event());
        }
        let home = self.home.as_deref().map(std::path::Path::new);
        let grant_session = (!s.is_human()).then_some(s.id.as_str());
        let secrets = st
            .store
            .list()
            .map(|info| {
                let here = views::in_project(&info.meta.projects, self.cwd.as_deref(), home);
                (info, here)
            })
            .filter(|(_, here)| all || *here)
            .map(|(info, here)| views::secret_view(&st, info, grant_session, here))
            .collect();
        Ok(Response::List {
            session: grant_session.map(str::to_owned),
            secrets,
        })
    }

    /// Ids of the sessions a call covers: the caller's, or with
    /// `all_sessions` every live session of the caller's uid.
    fn sessions_for(&self, all_sessions: bool) -> Result<Vec<String>, ErrorBody> {
        if all_sessions {
            let st = self.d.lock();
            let mut ids: Vec<String> = st
                .sessions
                .values()
                .filter(|e| e.uid == self.uid)
                .map(|e| e.session.id.clone())
                .collect();
            ids.sort();
            return Ok(ids);
        }
        Ok(vec![self.caller()?.id])
    }

    /// `grants`.
    pub fn grants(&self, all_sessions: bool) -> Result<Response, ErrorBody> {
        let ids = self.sessions_for(all_sessions)?;
        let st = self.d.lock();
        let grants = ids
            .iter()
            .flat_map(|sid| st.grants.grants_for(sid))
            .map(|g| views::grant_view(g, st.grant_info.get(&g.id)))
            .collect();
        Ok(Response::Grants { grants })
    }

    /// `revoke`: exactly one selector.
    pub fn revoke(
        &self,
        grant_ids: &[String],
        secret: Option<&str>,
        all: bool,
        all_sessions: bool,
    ) -> Result<Response, ErrorBody> {
        let selectors =
            usize::from(!grant_ids.is_empty()) + usize::from(secret.is_some()) + usize::from(all);
        if selectors != 1 {
            return Err(err(
                ErrorCode::BadRequest,
                "revoke takes exactly one of: grant ids, a secret, or all",
            ));
        }
        let ids = self.sessions_for(all_sessions)?;
        let mut st = self.d.lock();
        let mut revoked: Vec<GrantView> = Vec::new();
        for sid in &ids {
            let chosen: Vec<String> = st
                .grants
                .grants_for(sid)
                .into_iter()
                .filter(|g| {
                    all || grant_ids.contains(&g.id)
                        || secret.is_some_and(|n| g.names.iter().any(|x| x == n))
                })
                .map(|g| g.id.clone())
                .collect();
            let sref = st.sessions.get(sid).map(|e| e.audit.clone());
            for gid in chosen {
                if let Ok(gone) = st.grants.revoke(sid, Some(&gid)) {
                    for g in gone {
                        let info = st.grant_info.remove(&g.id);
                        revoked.push(views::grant_view(&g, info.as_ref()));
                        st.record(
                            sref.as_ref(),
                            &Event::GrantRevoke {
                                grant_id: g.id,
                                secrets: g.names,
                                by: "client".into(),
                            },
                        );
                    }
                }
            }
        }
        if revoked.is_empty() && !grant_ids.is_empty() {
            return Err(err(
                ErrorCode::GrantRequired,
                format!("no such grant here: {}", grant_ids.join(", ")),
            ));
        }
        Ok(Response::Revoked { grants: revoked })
    }

    /// `run`: values for the child's environment, after `use.start`.
    pub fn start_run(
        &mut self,
        uses: &[Use],
        argv0: &str,
        argc: u32,
    ) -> Result<Response, ErrorBody> {
        if self.run.is_some() {
            return Err(err(ErrorCode::BadRequest, "a run is already in progress"));
        }
        let s = self.agent()?.clone();
        let names: Vec<String> = uses.iter().map(|u| u.name.clone()).collect();
        let mut st = self.d.lock();
        let unknown: Vec<String> = names
            .iter()
            .filter(|n| !valid_name(n) || !st.store.contains(n))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(ErrorBody {
                code: ErrorCode::UnknownSecret,
                message: format!("no secret named {}", unknown.join(", ")),
                detail: serde_json::json!({ "names": unknown }),
            });
        }
        st.grants
            .check_use(&s.id, &names)
            .map_err(|e| e.to_body())?;
        let mut values = Vec::with_capacity(uses.len());
        for u in uses {
            let v = st.store.value(&u.name).map_err(|e| store_error(&e))?;
            values.push(RunValue {
                name: u.name.clone(),
                env: u.env.clone(),
                value_b64: ValueB64::encode(v.as_bytes()),
            });
        }
        // Other secrets this session may already use: cn scrubs them too.
        let used: BTreeSet<&String> = names.iter().collect();
        let mut extra = Vec::new();
        let others: Vec<String> = st
            .grants
            .grants_for(&s.id)
            .into_iter()
            .filter(|g| g.mode == Mode::Use)
            .flat_map(|g| g.names.iter().cloned())
            .filter(|n| !used.contains(n))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for n in others {
            if let Ok(v) = st.store.value(&n) {
                extra.push(ScrubValue {
                    name: n,
                    value_b64: ValueB64::encode(v.as_bytes()),
                });
            }
        }
        let run_id = random_id("u_", 16);
        let sref = s.audit_ref(&self.labels);
        st.must_record(
            Some(&sref),
            &Event::UseStart {
                run_id: run_id.clone(),
                secrets: names.clone(),
                env: uses.iter().map(|u| u.env.clone()).collect(),
                argv0: views::truncate_utf8(argv0, MAX_ARGV0),
                argc,
                cwd: self.cwd.clone(),
                pid: self.pid,
            },
        )?;
        let at = Timestamp::from_system_time(self.d.now());
        for n in &names {
            let gid = st
                .grants
                .grants_for(&s.id)
                .into_iter()
                .find(|g| g.mode == Mode::Use && g.names.contains(n))
                .map(|g| g.id.clone());
            if let Some(info) = gid.and_then(|g| st.grant_info.get_mut(&g)) {
                info.uses += 1;
            }
            st.last_use.insert(
                n.clone(),
                LastUse {
                    at,
                    session: s.id.clone(),
                    argv0: Some(views::truncate_utf8(argv0, MAX_ARGV0)),
                },
            );
        }
        st.runs.insert(run_id.clone(), RunEntry { session: sref });
        self.run = Some(run_id.clone());
        Ok(Response::RunOk {
            run_id,
            values,
            patterns_extra: extra,
        })
    }

    /// `run_finish`.
    pub fn finish_run(
        &mut self,
        run_id: &str,
        exit: Option<i32>,
        signal: Option<i32>,
        duration_ms: u64,
        hits: BTreeMap<String, u64>,
    ) -> Result<Response, ErrorBody> {
        if self.run.as_deref() != Some(run_id) {
            return Err(err(ErrorCode::BadRequest, "no such run on this connection"));
        }
        self.run = None;
        let hits: BTreeMap<String, u64> = hits
            .into_iter()
            .filter(|(k, _)| valid_name(k))
            .take(64)
            .collect();
        let mut st = self.d.lock();
        if let Some(run) = st.runs.remove(run_id) {
            st.record(
                Some(&run.session),
                &Event::UseEnd {
                    run_id: run_id.to_owned(),
                    status: if signal.is_some() {
                        "signaled"
                    } else {
                        "exited"
                    }
                    .into(),
                    exit,
                    signal,
                    duration_ms,
                    hits,
                },
            );
        }
        Ok(Response::Ok)
    }

    /// `reveal`: uses one reveal of a grant.
    pub fn reveal(&self, name: &str) -> Result<Response, ErrorBody> {
        let s = self.agent()?.clone();
        let mut st = self.d.lock();
        if !valid_name(name) || !st.store.contains(name) {
            return Err(ErrorBody {
                code: ErrorCode::UnknownSecret,
                message: format!("no secret named {name}"),
                detail: serde_json::json!({ "names": [name] }),
            });
        }
        let (grant_id, left) = st
            .grants
            .consume_reveal(&s.id, name)
            .map_err(|e| e.to_body())?;
        let value = st.store.value(name).map_err(|e| store_error(&e))?;
        let sref = s.audit_ref(&self.labels);
        st.must_record(
            Some(&sref),
            &Event::Reveal {
                secret: name.to_owned(),
                grant_id: grant_id.clone(),
                uses_left: left,
            },
        )?;
        if let Some(info) = st.grant_info.get_mut(&grant_id) {
            info.uses += 1;
        }
        if left == 0 {
            st.grant_info.remove(&grant_id);
            st.record(
                Some(&sref),
                &Event::GrantExpire {
                    grant_id,
                    secrets: vec![name.to_owned()],
                    by: "uses".into(),
                },
            );
        }
        st.last_use.insert(
            name.to_owned(),
            LastUse {
                at: Timestamp::from_system_time(self.d.now()),
                session: s.id.clone(),
                argv0: None,
            },
        );
        Ok(Response::Reveal {
            name: name.to_owned(),
            value_b64: ValueB64::encode(value.as_bytes()),
            reveals_left: Some(left),
        })
    }

    /// `audit_query`: newest matching records, trimmed to fit one frame.
    /// The log is read from a snapshot, without the state lock, on a
    /// blocking thread.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per audit_query field"
    )]
    pub async fn audit_query(
        &self,
        session: Option<String>,
        secret: Option<String>,
        events: Vec<String>,
        since: Option<Timestamp>,
        until: Option<Timestamp>,
        after_seq: Option<u64>,
        limit: Option<u32>,
    ) -> Result<Response, ErrorBody> {
        let q = Query {
            session,
            secret,
            events,
            since: since.map(Timestamp::to_system_time),
            until: until.map(Timestamp::to_system_time),
            after_seq,
            limit: Some(
                limit
                    .map_or(Query::DEFAULT_LIMIT, |l| l as usize)
                    .min(MAX_QUERY),
            ),
        };
        let reader = self.d.lock().audit.reader();
        let mut records = tokio::task::spawn_blocking(move || reader.query(&q))
            .await
            .map_err(|e| {
                error!("audit query: {e}");
                internal("the audit log could not be read")
            })?
            .map_err(|e| {
                error!("audit query: {e}");
                internal("the audit log could not be read")
            })?;
        let budget = MAX_MESSAGE_LEN - (64 << 10);
        let mut size: usize = records.iter().map(record_size).sum();
        let mut drop_front = 0;
        while size > budget && drop_front < records.len() {
            size -= record_size(&records[drop_front]);
            drop_front += 1;
        }
        records.drain(..drop_front);
        Ok(Response::AuditRecords { records })
    }

    /// `audit_segments`: raw lines from `from_seq`, at most one frame's
    /// worth, read like `audit_query`.
    pub async fn audit_segments(&self, from_seq: u64) -> Result<Response, ErrorBody> {
        let reader = self.d.lock().audit.reader();
        let read = tokio::task::spawn_blocking(move || {
            let (bytes, next_seq) = reader.segments_from(from_seq, SEGMENT_BYTES)?;
            let pubkey = std::fs::read_to_string(reader.dir().join(PUBKEY_FILE))
                .ok()
                .map(|s| s.trim().to_owned());
            Ok::<_, countersign_core::audit::AuditError>((bytes, next_seq, pubkey))
        })
        .await;
        let (bytes, next_seq, pubkey) = match read {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => {
                error!("audit segments: {e}");
                return Err(internal("the audit log could not be read"));
            }
            Err(e) => {
                error!("audit segments: {e}");
                return Err(internal("the audit log could not be read"));
            }
        };
        Ok(Response::AuditSegments {
            data_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            next_seq,
            checkpoint_pubkey: pubkey,
        })
    }
}

fn record_size(v: &Value) -> usize {
    serde_json::to_vec(v).map_or(0, |b| b.len() + 1)
}
