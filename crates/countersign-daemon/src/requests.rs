//! Requests (design.md sections 6 and 9): creating a grant or store-change
//! request, running its approver chain, recording the decision, and the
//! client's view of it (`get_request`, `deny`).
//!
//! A request is created, audited (`request.create`) and answered at once;
//! its chain starts in its own task. The decision is applied under the
//! state lock: a grant becomes active, or the held store change commits
//! (`store.*`, with `store.v1.prev` restored if the audit write fails).
//! Expiry, `cn deny` and the anchor's exit cancel the chain, which makes
//! the polkit adapter withdraw its dialog (`CancelCheckAuthorization`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use countersign_approve::display::{clean_limited, clean_quoted};
use countersign_approve::{
    ApprovalRequest, ApproverError, ChainReport, Decision as ChainDecision, DisplayInput,
    DisplayView, Evidence, Found, Outcome, SessionRef as ApproveSession,
};
use countersign_core::audit::{Event, SessionRef};
use countersign_core::config::{Chain, CrossProject};
use countersign_core::grants::{GrantAsk, PendingRequest, RequestKind};
use countersign_core::sessions::{AnchorKind, Session};
use countersign_core::store::{Mutation, SecretValue, StoreError};
use countersign_proto::{
    APPROVE_DOMAIN, Anchor, ApprovalKind, CanonicalRequest, Decision, Digest, ErrorBody, ErrorCode,
    ImportItem, Mode, RequestCode, RequestState, RequestView, Response, SecretMeta, Timestamp,
    ValueB64, ValueSource,
};
use tokio_util::sync::CancellationToken;

use crate::conn::Denier;
use crate::daemon::{Daemon, GrantInfo, State, err, internal};
use crate::log::error;
use crate::setup::Runtime;
use crate::views;

/// Longest single wait a `get_request` may ask for.
const MAX_WAIT: Duration = Duration::from_secs(60);

/// A request as `cnd` keeps it, from creation until `pending_expiry`
/// after its decision.
#[derive(Debug, Clone)]
pub struct RequestRecord {
    /// What clients see.
    pub view: RequestView,
    /// The `session` object of its audit records.
    pub session: SessionRef,
    /// Cancels the approver chain.
    pub cancel: CancellationToken,
    /// When it left `pending`.
    pub decided_at: Option<SystemTime>,
    /// Whether it is an `import` (one `import` record after the `store.add`s).
    pub import: bool,
}

/// Who is asking: the session and what the connection reported.
pub struct Asker<'a> {
    /// The caller's session (an agent session, or a human one for store
    /// changes).
    pub session: &'a Session,
    /// The peer uid.
    pub uid: u32,
    /// Untrusted labels, filtered by `label_env`.
    pub labels: &'a BTreeMap<String, String>,
    /// Client-reported working directory (untrusted).
    pub cwd: Option<&'a str>,
    /// The peer user's home directory, for `~` in project globs and the
    /// dialog.
    pub home: Option<&'a str>,
}

/// A store change a client proposed.
pub enum Change {
    /// `cn add`.
    Add {
        /// Metadata.
        meta: SecretMeta,
        /// Value.
        value: ValueB64,
        /// Where it came from.
        source: Option<ValueSource>,
    },
    /// `cn set`.
    Set {
        /// Secret.
        name: String,
        /// Value.
        value: ValueB64,
        /// Where it came from.
        source: Option<ValueSource>,
    },
    /// `cn edit`.
    Edit {
        /// The full new metadata.
        meta: SecretMeta,
    },
    /// `cn rm`.
    Rm {
        /// Secrets.
        names: Vec<String>,
    },
    /// `cn import`.
    Import {
        /// The secrets.
        items: Vec<ImportItem>,
    },
}

/// What a request will show and sign, besides its kind.
struct Prepared {
    kind: ApprovalKind,
    operation: Option<String>,
    import: bool,
}

/// `K7M-Q2X`, from whatever case and dashes the client sent.
fn normal_code(code: &str) -> Result<String, ErrorBody> {
    code.parse::<RequestCode>()
        .map(|c| c.to_string())
        .map_err(|_| err(ErrorCode::RequestNotFound, "not a request code"))
}

/// The protocol error for a store refusal. Faults stay in the daemon log.
pub fn store_error(e: &StoreError) -> ErrorBody {
    match e.code() {
        ErrorCode::Internal => {
            error!("store: {e}");
            internal("the store could not be read or written")
        }
        code => err(code, e.to_string()),
    }
}

/// `under 16 bytes`, ...: what the dialog says about a value's size. Never
/// written to the audit log.
fn length_class(n: usize) -> &'static str {
    match n {
        0..16 => "under 16 bytes",
        16..64 => "16 to 63 bytes",
        64..1024 => "64 to 1023 bytes",
        _ => "1 KiB or more",
    }
}

fn source_word(s: Option<ValueSource>) -> &'static str {
    match s {
        Some(ValueSource::Prompt) => "typed at a prompt",
        Some(ValueSource::Clipboard) => "from the clipboard",
        Some(ValueSource::File) => "from a file",
        Some(ValueSource::Stdin) => "from stdin",
        None => "source not given",
    }
}

fn decode(v: &ValueB64) -> Result<SecretValue, ErrorBody> {
    v.decode()
        .map(SecretValue::from)
        .map_err(|_| err(ErrorCode::BadRequest, "the value is not valid base64"))
}

fn names_text(names: &[String], limit: usize) -> String {
    let mut s = names
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > limit {
        s.push_str(&format!(" and {} more", names.len() - limit));
    }
    s
}

/// Longest quoted short field (description, one usage side) in a dialog.
const FIELD_LIMIT: usize = 60;
/// Longest new usage text shown when a usage is long.
const USAGE_LIMIT: usize = 120;
/// List items (projects, tags) shown before "and N more".
const ITEMS_SHOWN: usize = 5;

/// `[~/a, ~/b]`, each item cleaned and bounded.
fn items_text(items: &[String]) -> String {
    let mut shown: Vec<String> = items
        .iter()
        .take(ITEMS_SHOWN)
        .map(|i| clean_limited(i, FIELD_LIMIT))
        .collect();
    if items.len() > ITEMS_SHOWN {
        shown.push(format!("and {} more", items.len() - ITEMS_SHOWN));
    }
    format!("[{}]", shown.join(", "))
}

fn entropy_word(on: bool) -> &'static str {
    if on {
        "on (cn hide matches it without a grant)"
    } else {
        "off (cn hide matches it only when granted)"
    }
}

/// The dialog text for `cn add`: what `cnd` knows (the value's size class
/// and source) first, then the metadata the client sent.
fn add_text(meta: &SecretMeta, len: usize, source: Option<ValueSource>) -> String {
    let mut parts = vec![format!(
        "description {}",
        if meta.description.is_empty() {
            "none".to_owned()
        } else {
            clean_quoted(&meta.description, FIELD_LIMIT)
        }
    )];
    if !meta.usage.is_empty() {
        parts.push(format!("usage {}", clean_quoted(&meta.usage, USAGE_LIMIT)));
    }
    parts.push(format!(
        "projects {}",
        if meta.projects.is_empty() {
            "any".to_owned()
        } else {
            items_text(&meta.projects)
        }
    ));
    if !meta.tags.is_empty() {
        parts.push(format!("tags {}", items_text(&meta.tags)));
    }
    format!(
        "ADD secret {} (value {}, {}{}): {}",
        meta.name,
        length_class(len),
        source_word(source),
        if meta.high_entropy {
            ", high entropy"
        } else {
            ""
        },
        parts.join("; ")
    )
}

/// The dialog text for `cn edit`: each changed field, old -> new.
fn edit_text(cur: &SecretMeta, new: &SecretMeta) -> String {
    let mut parts = Vec::new();
    if cur.description != new.description {
        parts.push(format!(
            "description {} -> {}",
            clean_quoted(&cur.description, FIELD_LIMIT),
            clean_quoted(&new.description, FIELD_LIMIT)
        ));
    }
    if cur.usage != new.usage {
        let short = |u: &str| u.chars().count() <= FIELD_LIMIT;
        if short(&cur.usage) && short(&new.usage) {
            parts.push(format!(
                "usage {} -> {}",
                clean_quoted(&cur.usage, FIELD_LIMIT),
                clean_quoted(&new.usage, FIELD_LIMIT)
            ));
        } else {
            parts.push(format!(
                "usage becomes {}",
                clean_quoted(&new.usage, USAGE_LIMIT)
            ));
        }
    }
    if cur.projects != new.projects {
        parts.push(format!(
            "projects {} -> {}",
            items_text(&cur.projects),
            items_text(&new.projects)
        ));
    }
    if cur.tags != new.tags {
        parts.push(format!(
            "tags {} -> {}",
            items_text(&cur.tags),
            items_text(&new.tags)
        ));
    }
    if cur.high_entropy != new.high_entropy {
        parts.push(format!("high entropy {}", entropy_word(new.high_entropy)));
    }
    if parts.is_empty() {
        format!("EDIT {}: no field changes", new.name)
    } else {
        format!("EDIT {}: {}", new.name, parts.join("; "))
    }
}

impl State {
    /// Moves a pending request's record to `state`, withdraws its approvers
    /// and, for an expiry, writes `request.expire`. The caller writes the
    /// approve and deny records, which need the evidence.
    pub fn close_request(&mut self, id: &str, state: RequestState, decision: Option<Decision>) {
        let Some(rec) = self.requests.get_mut(id) else {
            return;
        };
        if rec.view.state != RequestState::Pending {
            return;
        }
        rec.cancel.cancel();
        rec.decided_at = Some(SystemTime::now());
        rec.view.state = state;
        rec.view.queued = false;
        for a in &mut rec.view.approvers {
            a.prompted = false;
        }
        rec.view.decision = Some(decision.unwrap_or_else(|| Decision {
            at: Timestamp::now(),
            by: vec!["expiry".into()],
            reason: None,
            grant: None,
            grants_revoked: 0,
            error: None,
        }));
        if state == RequestState::Expired {
            let sref = rec.session.clone();
            self.record(
                Some(&sref),
                &Event::RequestExpire {
                    request_id: id.to_owned(),
                },
            );
        }
    }

    fn deny_decision(by: Vec<String>, reason: Option<String>) -> Decision {
        Decision {
            at: Timestamp::now(),
            by,
            reason,
            grant: None,
            grants_revoked: 0,
            error: None,
        }
    }

    /// Writes one record per chain member that answered: `request.approve`
    /// or `request.deny`, and `request.approve_fail` for an invalid answer.
    /// The last approval carries `grant_ids`. False if a write failed.
    fn record_members(
        &mut self,
        id: &str,
        digest: &str,
        sref: &SessionRef,
        report: &ChainReport,
        grant_ids: &[String],
    ) -> bool {
        let last_approved = report
            .members
            .iter()
            .rposition(|m| matches!(m.result, Ok(Outcome::Approved(_))));
        let mut ok = true;
        for (i, m) in report.members.iter().enumerate() {
            let event = match &m.result {
                Ok(Outcome::Approved(ev)) => Event::RequestApprove {
                    request_id: id.to_owned(),
                    digest: digest.to_owned(),
                    approver: m.approver.clone(),
                    credential_id: None,
                    grant_ids: if Some(i) == last_approved {
                        grant_ids.to_vec()
                    } else {
                        Vec::new()
                    },
                    evidence: evidence_json(ev),
                },
                Ok(Outcome::Denied(ev)) => Event::RequestDeny {
                    request_id: id.to_owned(),
                    digest: digest.to_owned(),
                    approver: m.approver.clone(),
                    credential_id: None,
                    grant_ids: Vec::new(),
                    evidence: evidence_json(ev),
                },
                Err(countersign_approve::ApproverError::Invalid(why)) => {
                    Event::RequestApproveFail {
                        request_id: id.to_owned(),
                        approver: m.approver.clone(),
                        credential_id: None,
                        error: why.clone(),
                    }
                }
                Err(_) => continue,
            };
            ok &= self.record(Some(sref), &event);
        }
        ok
    }

    /// The chain approved: activate the grant, or commit the store change.
    fn apply_approval(&mut self, id: &str, report: &ChainReport) {
        let Some(rec) = self.requests.get(id) else {
            return;
        };
        let (sref, digest, import) = (rec.session.clone(), rec.view.digest.clone(), rec.import);
        let approved = match self.grants.approve(id) {
            Ok(a) => a,
            Err(e) if e.code == ErrorCode::RequestExpired => {
                self.close_request(id, RequestState::Expired, None);
                return;
            }
            Err(e) => {
                error!("request {id}: approval found no pending request: {e}");
                let d = State::deny_decision(vec!["cnd".into()], Some(e.message));
                self.close_request(id, RequestState::Denied, Some(d));
                return;
            }
        };
        let by: Vec<String> = report
            .members
            .iter()
            .filter(|m| matches!(m.result, Ok(Outcome::Approved(_))))
            .map(|m| m.approver.clone())
            .collect();
        let unrecorded = || {
            State::deny_decision(
                vec!["cnd".into()],
                Some("internal: the approval could not be written to the audit log".into()),
            )
        };
        match approved.request.kind {
            RequestKind::Grant { .. } => {
                let Some(g) = approved.grant else {
                    return;
                };
                if !self.record_members(id, &digest, &sref, report, std::slice::from_ref(&g.id)) {
                    let _ = self.grants.revoke(&g.session, Some(&g.id));
                    self.close_request(id, RequestState::Denied, Some(unrecorded()));
                    return;
                }
                let info = GrantInfo {
                    approved_by: by.clone(),
                    uses: 0,
                };
                let view = views::grant_view(&g, Some(&info));
                self.grant_info.insert(g.id.clone(), info);
                let d = Decision {
                    at: Timestamp::now(),
                    by,
                    reason: None,
                    grant: Some(view),
                    grants_revoked: 0,
                    error: None,
                };
                self.close_request(id, RequestState::Approved, Some(d));
            }
            RequestKind::Mutation(ms) => {
                if !self.record_members(id, &digest, &sref, report, &[]) {
                    self.close_request(id, RequestState::Denied, Some(unrecorded()));
                    return;
                }
                let changes = match self.store.apply_all(&ms, SystemTime::now()) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("request {id}: the approved change did not apply: {e}");
                        let d = State::deny_decision(
                            vec!["cnd".into()],
                            Some(format!("the change could not be applied: {e}")),
                        );
                        self.close_request(id, RequestState::Denied, Some(d));
                        return;
                    }
                };
                // One write for every record of the change: all of them are
                // in the log, or none and the store change is undone.
                let mut events: Vec<Event> = changes.iter().map(|c| Event::store(c, id)).collect();
                if import {
                    events.push(Event::Import {
                        request_id: id.to_owned(),
                        count: changes.len() as u64,
                    });
                }
                if !self.record_all(Some(&sref), &events) {
                    // audit.md, "Writes": the store change is undone. If that
                    // fails the store refuses further changes until a restart.
                    if let Err(e) = self.store.rollback() {
                        error!(
                            "request {id}: rolling back the store failed; store changes are \
                             refused until cnd restarts: {e}"
                        );
                    }
                    self.close_request(id, RequestState::Denied, Some(unrecorded()));
                    return;
                }
                let mut revoked = 0u32;
                for m in ms.iter().filter(|m| m.invalidates_grants()) {
                    for g in self.grants.revoke_secret(m.name()) {
                        self.grant_info.remove(&g.id);
                        let gref = self.sessions.get(&g.session).map(|s| s.audit.clone());
                        self.record(
                            gref.as_ref(),
                            &Event::GrantRevoke {
                                grant_id: g.id,
                                secrets: g.names,
                                by: "store_change".into(),
                            },
                        );
                        revoked += 1;
                    }
                }
                let d = Decision {
                    at: Timestamp::now(),
                    by,
                    reason: None,
                    grant: None,
                    grants_revoked: revoked,
                    error: None,
                };
                self.close_request(id, RequestState::Approved, Some(d));
            }
        }
    }
}

/// `{adapter, at, detail}`: the audit record's `evidence`.
fn evidence_json(ev: &Evidence) -> serde_json::Value {
    serde_json::json!({
        "adapter": ev.adapter,
        "at": Timestamp::from_system_time(ev.at).to_string(),
        "detail": ev.detail,
    })
}

impl Daemon {
    fn canonical(
        &self,
        session: &Session,
        cwd: Option<&str>,
        p: &PendingRequest,
        operation: Option<String>,
    ) -> CanonicalRequest {
        let (secrets, mode, ttl) = match &p.kind {
            RequestKind::Grant { names, mode, ttl } => (
                names.clone(),
                ApprovalKind::from(*mode),
                Some(ttl.as_secs()),
            ),
            RequestKind::Mutation(_) => (p.kind.names(), ApprovalKind::Mutate, None),
        };
        CanonicalRequest {
            domain: APPROVE_DOMAIN.into(),
            request_id: p.id.clone(),
            code: p.code.to_string(),
            host: self.host.clone(),
            boot_id: self.boot_id.clone(),
            session: session.id.clone(),
            anchor: Anchor {
                pid: session.anchor.pid,
                starttime: session.anchor.start_time,
                comm: session.anchor.comm.clone(),
                registered: session.registered(),
            },
            cwd: cwd.map(str::to_owned),
            secrets,
            mode,
            ttl_seconds: ttl,
            operation,
            reason: p.reason.clone(),
            created_at: Timestamp::from_system_time(p.created_at),
            expires_at: Timestamp::from_system_time(p.expires_at),
            nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(p.nonce),
        }
    }

    /// `cn request`.
    pub fn create_grant(
        self: &Arc<Self>,
        a: &Asker<'_>,
        names: &[String],
        mode: Mode,
        ttl_seconds: Option<u64>,
        reason: &str,
    ) -> Result<Response, ErrorBody> {
        let rt = self.rt();
        let mut guard = self.lock();
        let st = &mut *guard;
        let sid = &a.session.id;
        if !st.alive(sid) {
            return Err(err(
                ErrorCode::SessionDead,
                "the session's anchor has exited",
            ));
        }
        if !a.session.is_human() {
            if let Some(g) = views::covering_grant(st, sid, names, mode) {
                return Ok(Response::AlreadyGranted { grant: g });
            }
        }
        let reason = views::redact_text(st, &rt, sid, reason);
        let home = a.home.map(std::path::Path::new);
        let other: Vec<String> = names
            .iter()
            .filter(|n| {
                st.store
                    .get(n)
                    .is_some_and(|i| !views::in_project(&i.meta.projects, a.cwd, home))
            })
            .cloned()
            .collect();
        if !other.is_empty() && rt.config.grants.cross_project == CrossProject::Deny {
            return Err(ErrorBody {
                code: ErrorCode::LimitExceeded,
                message: format!(
                    "{} belong to other projects, and cross_project = \"deny\"",
                    other.join(", ")
                ),
                detail: serde_json::json!({ "names": other }),
            });
        }
        let ask = GrantAsk {
            names,
            mode,
            ttl: ttl_seconds.map(Duration::from_secs),
            reason: &reason,
        };
        let p = st
            .grants
            .request_grant(
                a.session,
                a.uid,
                ask,
                |n| st.store.contains(n),
                |p| digest_of(&self.canonical(a.session, a.cwd, p, None)),
            )
            .map_err(|e| e.to_body())?
            .clone();
        let secrets: Vec<String> = p
            .kind
            .names()
            .into_iter()
            .map(|n| {
                if other.contains(&n) {
                    format!("{n} (other project)")
                } else {
                    n
                }
            })
            .collect();
        let ttl = match &p.kind {
            RequestKind::Grant { ttl, .. } => Some(*ttl),
            RequestKind::Mutation(_) => None,
        };
        let display = self.display(a, secrets, ttl, Some(reason.clone()), None);
        let prepared = Prepared {
            kind: ApprovalKind::from(mode),
            operation: None,
            import: false,
        };
        self.start(st, &rt, a, p, prepared, display)
    }

    /// `cn add`, `set`, `edit`, `rm` and `import`.
    pub fn create_change(
        self: &Arc<Self>,
        a: &Asker<'_>,
        change: Change,
    ) -> Result<Response, ErrorBody> {
        let rt = self.rt();
        let mut guard = self.lock();
        let st = &mut *guard;
        if !st.alive(&a.session.id) {
            return Err(err(
                ErrorCode::SessionDead,
                "the session's anchor has exited",
            ));
        }
        let (ms, operation, display_operation, import) = match change {
            Change::Add {
                meta,
                value,
                source,
            } => {
                let value = decode(&value)?;
                let shown = add_text(&meta, value.len(), source);
                let op = format!("add {}", meta.name);
                (vec![Mutation::Add { meta, value }], op, shown, false)
            }
            Change::Set {
                name,
                value,
                source,
            } => {
                let value = decode(&value)?;
                let shown = format!(
                    "SET a new value for {name} ({}, {}); grants for it are revoked",
                    length_class(value.len()),
                    source_word(source)
                );
                let op = format!("set {name}");
                (vec![Mutation::Set { name, value }], op, shown, false)
            }
            Change::Edit { meta } => {
                let shown = match st.store.get(&meta.name) {
                    Some(cur) => edit_text(&cur.meta, &meta),
                    // check_all below refuses it.
                    None => format!("EDIT {}", meta.name),
                };
                let op = format!("edit {}", meta.name);
                (vec![Mutation::Edit { meta }], op, shown, false)
            }
            Change::Rm { mut names } => {
                names.sort();
                names.dedup();
                let shown = format!(
                    "REMOVE {} secret{}: {}",
                    names.len(),
                    if names.len() == 1 { "" } else { "s" },
                    names_text(&names, 10)
                );
                let op = format!("rm {}", names.join(" "));
                let ms = names
                    .into_iter()
                    .map(|name| Mutation::Rm { name })
                    .collect();
                (ms, op, shown, false)
            }
            Change::Import { items } => {
                let max = rt.config.limits.max_names_per_import.max(1);
                if items.is_empty() || items.len() > max {
                    return Err(err(
                        ErrorCode::LimitExceeded,
                        format!(
                            "an import names 1 to {max} secrets ([limits] max_names_per_import); \
                             import the rest in another request"
                        ),
                    ));
                }
                let names: Vec<String> = items.iter().map(|i| i.meta.name.clone()).collect();
                let shown = format!("IMPORT {} secrets: {}", names.len(), names_text(&names, 10));
                let op = format!("import {}", names.join(" "));
                let mut ms = Vec::with_capacity(items.len());
                for i in items {
                    let value = decode(&i.value_b64)?;
                    ms.push(Mutation::Add {
                        meta: i.meta,
                        value,
                    });
                }
                (ms, op, shown, true)
            }
        };
        let max = rt.config.limits.max_names_per_request.max(1);
        if !import && ms.len() > max {
            return Err(err(
                ErrorCode::LimitExceeded,
                format!("a request names 1 to {max} secrets"),
            ));
        }
        st.store.check_all(&ms).map_err(|e| store_error(&e))?;
        let names: Vec<String> = ms.iter().map(|m| m.name().to_owned()).collect();
        let canonical_op = operation.clone();
        let p = st
            .grants
            .request_mutation(a.session, a.uid, ms, "", |p| {
                digest_of(&self.canonical(a.session, a.cwd, p, Some(canonical_op)))
            })
            .map_err(|e| e.to_body())?
            .clone();
        let display = self.display(a, names, None, None, Some(display_operation));
        let prepared = Prepared {
            kind: ApprovalKind::Mutate,
            operation: Some(operation),
            import,
        };
        self.start(st, &rt, a, p, prepared, display)
    }

    fn display(
        &self,
        a: &Asker<'_>,
        secrets: Vec<String>,
        ttl: Option<Duration>,
        reason: Option<String>,
        operation: Option<String>,
    ) -> DisplayView {
        let label = match &a.session.kind {
            AnchorKind::Registered { label } => label.clone(),
            _ => a.labels.values().next().cloned(),
        };
        let found = match &a.session.kind {
            AnchorKind::Registered { .. } => Found::Registered,
            AnchorKind::Matched { matcher } => Found::Matched(matcher.clone()),
            AnchorKind::Human => Found::Terminal,
        };
        DisplayView::new(&DisplayInput {
            found,
            anchor_comm: a.session.anchor.comm.clone(),
            anchor_pid: a.session.anchor.pid,
            label,
            cwd: a.cwd.map(str::to_owned),
            home: a.home.map(str::to_owned),
            secrets,
            ttl,
            reason: reason.filter(|r| !r.is_empty()),
            operation,
        })
    }

    /// Audits a new request, records it and starts its chain.
    fn start(
        self: &Arc<Self>,
        st: &mut State,
        rt: &Arc<Runtime>,
        a: &Asker<'_>,
        p: PendingRequest,
        prepared: Prepared,
        display: DisplayView,
    ) -> Result<Response, ErrorBody> {
        let canon = self.canonical(a.session, a.cwd, &p, prepared.operation.clone());
        let Ok(bytes) = canon.canonical_bytes() else {
            let _ = st.grants.expire(&p.id);
            return Err(internal("the request could not be canonicalised"));
        };
        let digest = Digest::of(&bytes);
        let chain: Chain = rt.config.chain(prepared.kind).clone();
        // At most max_prompts_per_uid dialogs at once for a uid; this one
        // waits its turn if they are taken.
        let slots = self.prompt_slots(a.uid, rt);
        let permit = slots.clone().try_acquire_owned().ok();
        let queued = permit.is_none();
        let mut approvers = views::approver_views(rt, &chain);
        if queued {
            for v in &mut approvers {
                v.prompted = false;
            }
        }
        let view = RequestView {
            request: canon.clone(),
            state: RequestState::Pending,
            digest: digest.hex(),
            digest_short: digest.short(),
            approvers,
            decision: None,
            queued,
        };
        let sref = a.session.audit_ref(a.labels);
        let created = Event::RequestCreate {
            request_id: p.id.clone(),
            code: canon.code.clone(),
            secrets: canon.secrets.clone(),
            mode: prepared.kind.as_str().into(),
            operation: prepared.operation.clone(),
            ttl_seconds: canon.ttl_seconds.unwrap_or(0),
            reason: canon.reason.clone(),
            cwd: canon.cwd.clone(),
            digest: digest.hex(),
            canonical: base64::engine::general_purpose::STANDARD.encode(&bytes),
        };
        if let Err(e) = st.must_record(Some(&sref), &created) {
            let _ = st.grants.expire(&p.id);
            return Err(e);
        }
        let cancel = CancellationToken::new();
        st.codes.insert(canon.code.clone(), p.id.clone());
        st.requests.insert(
            p.id.clone(),
            RequestRecord {
                view: view.clone(),
                session: sref,
                cancel: cancel.clone(),
                decided_at: None,
                import: prepared.import,
            },
        );
        let areq = ApprovalRequest::new(
            p.id.clone(),
            bytes,
            &canon.code,
            prepared.kind,
            display,
            ApproveSession {
                session_id: a.session.id.clone(),
                uid: a.uid,
                anchor_pid: a.session.anchor.pid,
                anchor_start_time: a.session.anchor.start_time,
                anchor_comm: a.session.anchor.comm.clone(),
                logind_session: None,
            },
            p.expires_at,
        );
        self.wake.notify_one();
        let d = self.clone();
        let rt = rt.clone();
        self.spawn_approval(async move {
            let _permit = match permit {
                Some(p) => p,
                None => {
                    let p = tokio::select! {
                        p = slots.acquire_owned() => p,
                        // Expiry, cn deny or the anchor's exit closed it.
                        () = cancel.cancelled() => return,
                    };
                    let Ok(p) = p else { return };
                    if !d.dequeue(areq.request_id(), &rt, &chain) {
                        return;
                    }
                    p
                }
            };
            let report = countersign_approve::evaluate(&chain, &rt.registry, &areq, &cancel).await;
            d.finish(areq.request_id(), &report);
        });
        Ok(Response::RequestCreated(view))
    }

    /// A queued request got a dialog slot: its view shows the dialog open.
    /// False if it is no longer pending.
    fn dequeue(&self, id: &str, rt: &Runtime, chain: &Chain) -> bool {
        let mut st = self.lock();
        if st.stopping {
            return false;
        }
        let Some(rec) = st.requests.get_mut(id) else {
            return false;
        };
        if rec.view.state != RequestState::Pending {
            return false;
        }
        rec.view.queued = false;
        rec.view.approvers = views::approver_views(rt, chain);
        drop(st);
        self.decided.notify_waiters();
        true
    }

    /// Applies a chain's result to its request.
    fn finish(&self, id: &str, report: &ChainReport) {
        let mut guard = self.lock();
        let st = &mut *guard;
        if st.stopping {
            return;
        }
        let Some(rec) = st.requests.get(id) else {
            return;
        };
        if rec.view.state != RequestState::Pending {
            return;
        }
        let (sref, digest) = (rec.session.clone(), rec.view.digest.clone());
        match &report.result {
            Ok(ChainDecision::Approved) => st.apply_approval(id, report),
            Ok(ChainDecision::Denied) => {
                let _ = st.grants.deny(id);
                st.record_members(id, &digest, &sref, report, &[]);
                let mut by = Vec::new();
                let mut reason = None;
                for m in &report.members {
                    if let Ok(Outcome::Denied(ev)) = &m.result {
                        by.push(m.approver.clone());
                        if ev.detail["dismissed"] == true {
                            reason = Some("the dialog was dismissed".to_owned());
                        }
                    }
                }
                let d = State::deny_decision(by, reason);
                st.close_request(id, RequestState::Denied, Some(d));
            }
            // Whoever cancelled (deny, expiry, the anchor's exit) closed it.
            Err(countersign_approve::ApproverError::Cancelled) => {}
            Err(countersign_approve::ApproverError::Timeout) => {
                let _ = st.grants.expire(id);
                st.close_request(id, RequestState::Expired, None);
            }
            Err(e) => {
                // No decision is possible: unavailable approver, a fault, or
                // an invalid answer. The request ends without a grant and
                // without a deny cooldown, and the reason is shown.
                let _ = st.grants.expire(id);
                st.record_members(id, &digest, &sref, report, &[]);
                st.record(
                    Some(&sref),
                    &Event::RequestDeny {
                        request_id: id.to_owned(),
                        digest,
                        approver: "cnd".into(),
                        credential_id: None,
                        grant_ids: Vec::new(),
                        evidence: serde_json::json!({ "error": e.to_string() }),
                    },
                );
                let mut d = State::deny_decision(vec!["cnd".into()], Some(e.to_string()));
                // No approver could run: the client says so (exit 14, see
                // cn doctor), not that a human denied.
                if matches!(e, ApproverError::Unavailable(_)) {
                    d.error = Some(ErrorCode::ApproverUnavailable);
                }
                st.close_request(id, RequestState::Denied, Some(d));
            }
        }
        drop(guard);
        self.decided.notify_waiters();
    }

    /// `get_request`: the request's view, waiting up to `wait_seconds`
    /// (at most a minute) while it is pending.
    pub async fn get_request(
        &self,
        code: &str,
        wait_seconds: Option<u64>,
    ) -> Result<Response, ErrorBody> {
        let code = normal_code(code)?;
        let wait = Duration::from_secs(wait_seconds.unwrap_or(0)).min(MAX_WAIT);
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.decided.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let st = self.lock();
                let rec = st
                    .codes
                    .get(&code)
                    .and_then(|id| st.requests.get(id))
                    .ok_or_else(|| err(ErrorCode::RequestNotFound, "no request with that code"))?;
                // On shutdown, answer now with what is known.
                if rec.view.state != RequestState::Pending
                    || tokio::time::Instant::now() >= deadline
                    || self.shutdown.is_cancelled()
                {
                    return Ok(Response::RequestStatus(rec.view.clone()));
                }
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep_until(deadline) => {}
                () = self.shutdown.cancelled() => {}
            }
        }
    }

    /// `cn deny`: anyone allowed on the socket may refuse a request. The
    /// audit record says who: the peer's uid, pid and comm, and whether it
    /// came from the request's own session, another session or a terminal.
    pub fn deny(
        &self,
        code: &str,
        reason: Option<String>,
        who: &Denier,
    ) -> Result<Response, ErrorBody> {
        let code = normal_code(code)?;
        let reason =
            reason.map(|r| views::truncate_utf8(&r, countersign_core::grants::MAX_REASON_BYTES));
        let rt = self.rt();
        let mut st = self.lock();
        let id = st
            .codes
            .get(&code)
            .cloned()
            .ok_or_else(|| err(ErrorCode::RequestNotFound, "no request with that code"))?;
        let rec = st.requests.get(&id).cloned().ok_or_else(internal_gone)?;
        match rec.view.state {
            RequestState::Pending => {}
            RequestState::Expired => {
                return Err(err(ErrorCode::RequestExpired, "the request expired"));
            }
            _ => {
                return Err(err(
                    ErrorCode::RequestNotFound,
                    "the request was already decided",
                ));
            }
        }
        // The reason is free text: values of the request's session are
        // redacted from it like from a request reason.
        let reason = reason.map(|r| views::redact_text(&st, &rt, &rec.session.id, &r));
        let from = match &who.session {
            Some(s) if s.id == rec.session.id => "own_session",
            Some(s) if s.is_human() => "terminal",
            Some(_) => "other_session",
            None => "no_session",
        };
        if st.grants.deny(&id).is_err() {
            let _ = st.grants.expire(&id);
            st.close_request(&id, RequestState::Expired, None);
            drop(st);
            self.decided.notify_waiters();
            return Err(err(ErrorCode::RequestExpired, "the request expired"));
        }
        st.record(
            Some(&rec.session),
            &Event::RequestDeny {
                request_id: id.clone(),
                digest: rec.view.digest.clone(),
                approver: "client".into(),
                credential_id: None,
                grant_ids: Vec::new(),
                evidence: serde_json::json!({
                    "reason": reason,
                    "peer": { "uid": who.uid, "pid": who.pid, "comm": who.comm },
                    "from": from,
                    "session": who.session.as_ref().map(|s| s.id.clone()),
                }),
            },
        );
        let d = State::deny_decision(vec!["client".into()], reason);
        st.close_request(&id, RequestState::Denied, Some(d));
        drop(st);
        self.decided.notify_waiters();
        Ok(Response::Denied {
            request_id: id,
            code,
        })
    }
}

fn internal_gone() -> ErrorBody {
    internal("the request record is missing")
}

fn digest_of(c: &CanonicalRequest) -> [u8; 32] {
    // Canonicalisation fails only on numbers above 2^53, which a request
    // never holds; `start` checks the bytes again and refuses on failure.
    c.digest().map(|d| d.0).unwrap_or([0; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_classes_hide_the_exact_length() {
        assert_eq!(length_class(8), "under 16 bytes");
        assert_eq!(length_class(40), "16 to 63 bytes");
        assert_eq!(length_class(5000), "1 KiB or more");
    }

    fn meta(name: &str) -> SecretMeta {
        SecretMeta {
            name: name.into(),
            ..SecretMeta::default()
        }
    }

    #[test]
    fn add_shows_what_cnd_knows_first_then_the_metadata() {
        let mut m = meta("db");
        m.description = format!("{}\x1b[31m", "d".repeat(400));
        m.usage = "psql with it".into();
        m.projects = vec!["~/p/a".into()];
        m.high_entropy = true;
        let t = add_text(&m, 40, Some(ValueSource::Stdin));
        assert!(
            t.starts_with(
                "ADD secret db (value 16 to 63 bytes, from stdin, high entropy): description \""
            ),
            "{t}"
        );
        assert!(t.contains("(cut from 400 characters)"), "{t}");
        assert!(
            t.ends_with("; usage \"psql with it\"; projects [~/p/a]"),
            "{t}"
        );
        assert!(!t.contains('\x1b'));
        let t = add_text(&meta("x"), 3, None);
        assert_eq!(
            t,
            "ADD secret x (value under 16 bytes, source not given): description none; projects any"
        );
    }

    #[test]
    fn edit_shows_each_changed_field_old_and_new() {
        let mut old = meta("db");
        old.description = "prod".into();
        old.usage = "read only".into();
        old.tags = vec!["a".into()];
        let mut new = old.clone();
        assert_eq!(edit_text(&old, &new), "EDIT db: no field changes");
        new.description = "prod\nprimary".into();
        new.usage = "write too".into();
        new.projects = vec!["~/x".into()];
        new.tags = vec![];
        new.high_entropy = true;
        assert_eq!(
            edit_text(&old, &new),
            "EDIT db: description \"prod\" -> \"prod primary\"; usage \"read only\" -> \
             \"write too\"; projects [] -> [~/x]; tags [a] -> []; high entropy on (cn hide \
             matches it without a grant)"
        );
        // A long usage shows its new text, cut with a marker.
        new = old.clone();
        new.usage = "u".repeat(500);
        let t = edit_text(&old, &new);
        assert!(t.starts_with("EDIT db: usage becomes \"uuu"), "{t}");
        assert!(t.ends_with("(cut from 500 characters)"), "{t}");
        // Turning high entropy off is shown too: hide stops matching it.
        old.high_entropy = true;
        new = old.clone();
        new.high_entropy = false;
        assert!(edit_text(&old, &new).contains("high entropy off"));
    }

    #[test]
    fn codes_are_normalised() {
        assert_eq!(normal_code("k7mq2x").unwrap(), "K7M-Q2X");
        assert_eq!(
            normal_code("nope").unwrap_err().code,
            ErrorCode::RequestNotFound
        );
    }
}
