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
use countersign_approve::display::{clean_quoted, clean_quoted_item, clean_quoted_path};
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

/// Secret names a `rm` or `import` dialog lists before "and N more". With
/// names of at most 64 characters the text stays under
/// [`countersign_approve::display::OPERATION_LIMIT`] (a test checks).
const NAMES_SHOWN: usize = 8;

/// `a, b and 3 more`. Names are checked (`a-z 0-9 . _ -`) before a dialog
/// shows them, so they need no quotes.
fn names_text(names: &[String]) -> String {
    let mut s = names
        .iter()
        .take(NAMES_SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > NAMES_SHOWN {
        s.push_str(&format!(" and {} more", names.len() - NAMES_SHOWN));
    }
    s
}

// The agent-supplied parts of a store-change dialog are bounded so that the
// whole text, at its longest, stays under OPERATION_LIMIT and is never cut
// by the display (a test checks every kind). Limits count characters
// between the quotes, escapes included.

/// Longest quoted description in an `add` dialog.
const ADD_DESCRIPTION_LIMIT: usize = 60;
/// Longest quoted usage in an `add` dialog.
const ADD_USAGE_LIMIT: usize = 120;
/// Longest quoted description or usage in an `edit` dialog: each side of
/// old -> new, or the new text alone when a side is longer.
const EDIT_FIELD_LIMIT: usize = 40;
/// Projects and tags listed before "and N more".
const ITEMS_SHOWN: usize = 2;
/// Longest quoted project; a longer one loses its middle.
const PROJECT_LIMIT: usize = 24;
/// Longest quoted tag.
const TAG_LIMIT: usize = 12;

/// `["~/a", "~/b", and 3 more]`, each item quoted and bounded.
fn items_text(items: &[String], quote: impl Fn(&str) -> String) -> String {
    let mut shown: Vec<String> = items.iter().take(ITEMS_SHOWN).map(|i| quote(i)).collect();
    if items.len() > ITEMS_SHOWN {
        shown.push(format!("and {} more", items.len() - ITEMS_SHOWN));
    }
    format!("[{}]", shown.join(", "))
}

/// No projects means every project, so it reads "any (all projects)".
fn projects_text(projects: &[String]) -> String {
    if projects.is_empty() {
        "any (all projects)".to_owned()
    } else {
        items_text(projects, |p| clean_quoted_path(p, PROJECT_LIMIT))
    }
}

fn tags_text(tags: &[String]) -> String {
    if tags.is_empty() {
        "none".to_owned()
    } else {
        items_text(tags, |t| clean_quoted_item(t, TAG_LIMIT))
    }
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
            clean_quoted(&meta.description, ADD_DESCRIPTION_LIMIT)
        }
    )];
    if !meta.usage.is_empty() {
        parts.push(format!(
            "usage {}",
            clean_quoted(&meta.usage, ADD_USAGE_LIMIT)
        ));
    }
    parts.push(format!("projects {}", projects_text(&meta.projects)));
    if !meta.tags.is_empty() {
        parts.push(format!("tags {}", tags_text(&meta.tags)));
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

/// The dialog text for `cn set`.
fn set_text(name: &str, len: usize, source: Option<ValueSource>) -> String {
    format!(
        "SET a new value for {name} ({}, {}); grants for it are revoked",
        length_class(len),
        source_word(source)
    )
}

/// The dialog text for `cn rm`.
fn rm_text(names: &[String]) -> String {
    format!(
        "REMOVE {} secret{}: {}",
        names.len(),
        if names.len() == 1 { "" } else { "s" },
        names_text(names)
    )
}

/// The dialog text for `cn import`.
fn import_text(names: &[String]) -> String {
    format!("IMPORT {} secrets: {}", names.len(), names_text(names))
}

/// `description "a" -> "b"`, or `description becomes "..."` when a side
/// does not fit [`EDIT_FIELD_LIMIT`].
fn changed_text(what: &str, cur: &str, new: &str) -> String {
    // Uncut, the quoted text ends with its quote; a cut adds a note after.
    let fits = |s: &str| clean_quoted(s, EDIT_FIELD_LIMIT).ends_with('"');
    if fits(cur) && fits(new) {
        format!(
            "{what} {} -> {}",
            clean_quoted(cur, EDIT_FIELD_LIMIT),
            clean_quoted(new, EDIT_FIELD_LIMIT)
        )
    } else {
        format!("{what} becomes {}", clean_quoted(new, EDIT_FIELD_LIMIT))
    }
}

/// The dialog text for `cn edit`: each changed field, old -> new. What
/// `cnd` acts on comes first (high entropy, then projects), then the
/// client's text, so a cut, were there one, would never hide it.
fn edit_text(cur: &SecretMeta, new: &SecretMeta) -> String {
    let mut parts = Vec::new();
    if cur.high_entropy != new.high_entropy {
        parts.push(format!("high entropy {}", entropy_word(new.high_entropy)));
    }
    if cur.projects != new.projects {
        parts.push(format!(
            "projects {} -> {}",
            projects_text(&cur.projects),
            projects_text(&new.projects)
        ));
    }
    if cur.tags != new.tags {
        parts.push(format!(
            "tags {} -> {}",
            tags_text(&cur.tags),
            tags_text(&new.tags)
        ));
    }
    if cur.description != new.description {
        parts.push(changed_text(
            "description",
            &cur.description,
            &new.description,
        ));
    }
    if cur.usage != new.usage {
        parts.push(changed_text("usage", &cur.usage, &new.usage));
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
                let shown = set_text(&name, value.len(), source);
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
                let shown = rm_text(&names);
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
                let shown = import_text(&names);
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
        // The reason is free text: values of the request's session, and of
        // the denier's, which may be another session holding other grants,
        // are redacted from it like from a request reason.
        let mut sessions = vec![rec.session.id.as_str()];
        if let Some(s) = &who.session {
            sessions.push(s.id.as_str());
        }
        let reason = reason.map(|r| views::redact_for_sessions(&st, &rt, &sessions, &r, "reason"));
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
    use countersign_approve::display::OPERATION_LIMIT;

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
            t.ends_with("; usage \"psql with it\"; projects [\"~/p/a\"]"),
            "{t}"
        );
        assert!(!t.contains('\x1b'));
        let t = add_text(&meta("x"), 3, None);
        assert_eq!(
            t,
            "ADD secret x (value under 16 bytes, source not given): description none; \
             projects any (all projects)"
        );
    }

    #[test]
    fn edit_shows_what_cnd_acts_on_first_then_each_changed_field() {
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
            "EDIT db: high entropy on (cn hide matches it without a grant); projects any \
             (all projects) -> [\"~/x\"]; tags [\"a\"] -> none; description \"prod\" -> \
             \"prod primary\"; usage \"read only\" -> \"write too\""
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
        // Emptied projects widen the secret to every project.
        old.projects = vec!["~/work/prod".into()];
        new = old.clone();
        new.projects = vec![];
        assert_eq!(
            edit_text(&old, &new),
            "EDIT db: projects [\"~/work/prod\"] -> any (all projects)"
        );
    }

    /// `t` with every quoted part removed, escapes honoured; None if a
    /// quote is left open.
    fn outside_quotes(t: &str) -> Option<String> {
        let (mut out, mut quoted, mut escaped) = (String::new(), false, false);
        for c in t.chars() {
            match (quoted, c) {
                (true, _) if escaped => escaped = false,
                (true, '\\') => escaped = true,
                (_, '"') => quoted = !quoted,
                (false, c) => out.push(c),
                (true, _) => {}
            }
        }
        (!quoted).then_some(out)
    }

    #[test]
    fn agent_text_cannot_pose_as_a_change() {
        // The re-review probe: a description that closes its quote and adds
        // a high entropy change, with long projects and tags after it.
        let old = meta("clickhouse-prod");
        let mut new = old.clone();
        new.projects = (0..6)
            .map(|i| format!("~/projects/{i}{}", "x".repeat(70)))
            .collect();
        new.high_entropy = true;
        new.description = "ok\"; high entropy off (cn hide matches it only when granted".into();
        new.tags = (0..6).map(|i| format!("t{i}{}", "z".repeat(70))).collect();
        countersign_core::store::check_meta(&new).unwrap();
        let t = edit_text(&old, &new);
        assert!(
            t.starts_with(
                "EDIT clickhouse-prod: high entropy on (cn hide matches it without a grant); \
                 projects any (all projects) -> [\""
            ),
            "{t}"
        );
        assert!(
            t.contains("description becomes \"ok\\\"; high entropy off"),
            "{t}"
        );
        let outside = outside_quotes(&t).unwrap();
        assert_eq!(outside.matches("high entropy").count(), 1, "{t}");
        assert!(t.chars().count() < OPERATION_LIMIT);
        // Nothing in the display cuts it.
        let shown = DisplayView::new(&DisplayInput {
            operation: Some(t.clone()),
            ..DisplayInput::default()
        });
        assert_eq!(shown.operation(), Some(t.as_str()));

        // The same for add, and for a project or tag that holds quotes.
        let mut m = new.clone();
        m.usage = "x\"; projects any (all projects".into();
        m.projects = vec!["~/a\", \"~/b".into()];
        m.tags = vec!["t\\".into()];
        let t = add_text(&m, 40, None);
        let outside = outside_quotes(&t).unwrap();
        assert_eq!(outside.matches("projects").count(), 1, "{t}");
        assert!(
            t.ends_with("projects [\"~/a\\\", \\\"~/b\"]; tags [\"t\\\\\"]"),
            "{t}"
        );
    }

    /// Agent text at its longest once quoted: every character escaped.
    fn quotes(n: usize) -> String {
        "\"".repeat(n)
    }

    /// The pair from `candidates` whose `edit` text is longest when only
    /// the field `set` writes differs.
    fn longest_pair<T: Clone>(candidates: &[T], set: impl Fn(&mut SecretMeta, T)) -> (T, T) {
        let base = meta(&"n".repeat(64));
        let mut best = (0, candidates[0].clone(), candidates[0].clone());
        for a in candidates {
            for b in candidates {
                let (mut cur, mut new) = (base.clone(), base.clone());
                set(&mut cur, a.clone());
                set(&mut new, b.clone());
                countersign_core::store::check_meta(&cur).unwrap();
                countersign_core::store::check_meta(&new).unwrap();
                let n = edit_text(&cur, &new).chars().count();
                if n > best.0 {
                    best = (n, a.clone(), b.clone());
                }
            }
        }
        (best.1, best.2)
    }

    #[test]
    fn every_store_change_dialog_fits_under_the_operation_limit() {
        use countersign_core::store::{
            MAX_DESCRIPTION_CHARS, MAX_ITEM_BYTES, MAX_LIST_ITEMS, MAX_USAGE_BYTES,
        };
        let fit = EDIT_FIELD_LIMIT;
        let mut texts = vec![
            String::new(),
            "a".repeat(fit),
            quotes(fit / 2),
            "a".repeat(fit + 1),
            quotes(fit / 2 + 1),
            "a".repeat(MAX_DESCRIPTION_CHARS),
            quotes(MAX_DESCRIPTION_CHARS),
        ];
        let descriptions = texts.clone();
        texts.extend(["a".repeat(MAX_USAGE_BYTES), quotes(MAX_USAGE_BYTES)]);
        let usages = texts;
        let lists: Vec<Vec<String>> = vec![
            vec![],
            vec![quotes(MAX_ITEM_BYTES)],
            vec![quotes(MAX_ITEM_BYTES); ITEMS_SHOWN],
            vec![quotes(MAX_ITEM_BYTES); MAX_LIST_ITEMS],
        ];
        let name = "n".repeat(64);

        // edit: every field changes, each in its longest way.
        let (dc, dn) = longest_pair(&descriptions, |m, v| m.description = v);
        let (uc, un) = longest_pair(&usages, |m, v| m.usage = v);
        let (pc, pn) = longest_pair(&lists, |m, v| m.projects = v);
        let (tc, tn) = longest_pair(&lists, |m, v| m.tags = v);
        let cur = SecretMeta {
            name: name.clone(),
            description: dc,
            usage: uc,
            projects: pc,
            tags: tc,
            high_entropy: true,
        };
        let new = SecretMeta {
            description: dn,
            usage: un,
            projects: pn,
            tags: tn,
            high_entropy: false,
            ..cur.clone()
        };
        countersign_core::store::check_meta(&new).unwrap();
        let edit = edit_text(&cur, &new);

        // add: the longest of everything.
        let add = add_text(
            &SecretMeta {
                name: name.clone(),
                description: quotes(MAX_DESCRIPTION_CHARS),
                usage: quotes(MAX_USAGE_BYTES),
                projects: vec![quotes(MAX_ITEM_BYTES); MAX_LIST_ITEMS],
                tags: vec![quotes(MAX_ITEM_BYTES); MAX_LIST_ITEMS],
                high_entropy: true,
            },
            1000,
            Some(ValueSource::Clipboard),
        );

        // rm names at most 16 secrets ([limits] max_names_per_request);
        // import any number, so its two counts may each grow to 20 digits.
        let names = vec![name.clone(); 16];
        let rm = rm_text(&names);
        let digits = |n: usize| n.to_string().len();
        let import = import_text(&names);
        let import_len = import.chars().count() + 2 * (digits(usize::MAX) - digits(names.len()));
        let set = set_text(&name, 1000, Some(ValueSource::Clipboard));

        for (what, n) in [
            ("add", add.chars().count()),
            ("edit", edit.chars().count()),
            ("rm", rm.chars().count()),
            ("import", import_len),
            ("set", set.chars().count()),
        ] {
            assert!(n < OPERATION_LIMIT, "{what}: {n}");
        }
        for t in [&add, &edit, &rm, &import, &set] {
            assert!(outside_quotes(t).is_some(), "{t}");
        }
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
