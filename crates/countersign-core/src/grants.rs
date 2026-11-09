//! Requests and grants (design.md section 6).
//!
//! ```text
//!   pending ── approve ──► grant active ── ttl / revoke / anchor exit ──► gone
//!      │ ─── deny ──► denied
//!      │ ─── pending_expiry or anchor exit ──► expired
//! ```
//!
//! A request either asks for a grant (`use` or `reveal` on some secrets) or
//! carries store [`Mutation`]s that apply once approved. Grants live only
//! in memory; a `cnd` restart drops them. Time comes from the injected
//! [`Clock`], so tests are deterministic.
//!
//! `cnd` runs the approver chain; this module only records the outcome. It
//! also does not know the store: callers pass `known` to check names, and
//! check a mutation with [`crate::store::Store::check`] before submitting it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use countersign_proto::{ErrorBody, ErrorCode, Mode, RequestCode};

use crate::config::Config;
use crate::encoding::{random_array, random_id};
use crate::sessions::Session;
use crate::store::{Mutation, valid_name};
use crate::time::Clock;

/// Longest `reason`, in bytes.
pub const MAX_REASON_BYTES: usize = 2048;

/// Limits that apply to requests and grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// `use` TTL when the request gives none.
    pub default_ttl: Duration,
    /// Longest `use` grant.
    pub max_ttl: Duration,
    /// Longest `reveal` grant.
    pub max_reveal_ttl: Duration,
    /// Reveals per `reveal` grant.
    pub max_reveal_uses: u32,
    /// Whether `reveal` requests are accepted.
    pub allow_reveal: bool,
    /// How long a request waits for approval.
    pub pending_expiry: Duration,
    /// Names per request.
    pub max_names_per_request: usize,
    /// Pending requests per session.
    pub max_pending_requests: usize,
    /// Requests per session per hour.
    pub requests_per_hour: u32,
    /// After a deny, the same secrets are refused this long in that session.
    pub deny_cooldown: Duration,
}

impl Policy {
    /// The policy a config sets.
    pub fn from_config(c: &Config) -> Self {
        Self {
            default_ttl: c.grants.default_ttl,
            max_ttl: c.grants.max_ttl,
            max_reveal_ttl: c.grants.max_reveal_ttl,
            max_reveal_uses: c.grants.max_reveal_uses,
            allow_reveal: c.grants.allow_reveal,
            pending_expiry: c.grants.pending_expiry,
            max_names_per_request: c.limits.max_names_per_request,
            max_pending_requests: c.limits.max_pending_requests,
            requests_per_hour: c.limits.requests_per_hour,
            deny_cooldown: c.limits.deny_cooldown,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

/// A refused operation, with the protocol code to send.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct GrantError {
    /// Protocol error code.
    pub code: ErrorCode,
    /// Human-readable message.
    pub message: String,
    /// Secret names involved, for `detail.names`.
    pub names: Vec<String>,
}

impl GrantError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            names: Vec::new(),
        }
    }

    fn with_names(mut self, names: Vec<String>) -> Self {
        self.names = names;
        self
    }

    /// The protocol error body.
    pub fn to_body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code,
            message: self.message.clone(),
            detail: if self.names.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!({ "names": self.names })
            },
        }
    }
}

/// A grant request as the client sent it.
#[derive(Debug, Clone, Copy)]
pub struct GrantAsk<'a> {
    /// Secrets.
    pub names: &'a [String],
    /// Mode.
    pub mode: Mode,
    /// Requested lifetime; `None` takes the default.
    pub ttl: Option<Duration>,
    /// Agent-supplied reason.
    pub reason: &'a str,
}

/// What a request asks for.
#[derive(Debug, Clone, PartialEq)]
pub enum RequestKind {
    /// A grant.
    Grant {
        /// Secrets, sorted and unique.
        names: Vec<String>,
        /// Mode.
        mode: Mode,
        /// Lifetime from approval.
        ttl: Duration,
    },
    /// Store changes, held until approved and applied together
    /// ([`crate::store::Store::apply_all`]).
    Mutation(Vec<Mutation>),
}

impl RequestKind {
    /// The secrets the request names.
    pub fn names(&self) -> Vec<String> {
        match self {
            RequestKind::Grant { names, .. } => names.clone(),
            RequestKind::Mutation(ms) => ms.iter().map(|m| m.name().to_owned()).collect(),
        }
    }

    /// The approval kind: `use`, `reveal` or `mutate`.
    pub fn approval_kind(&self) -> countersign_proto::ApprovalKind {
        match self {
            RequestKind::Grant {
                mode: Mode::Use, ..
            } => countersign_proto::ApprovalKind::Use,
            RequestKind::Grant {
                mode: Mode::Reveal, ..
            } => countersign_proto::ApprovalKind::Reveal,
            RequestKind::Mutation(_) => countersign_proto::ApprovalKind::Mutate,
        }
    }
}

/// A request waiting for approval.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingRequest {
    /// `r_` + 26 base32 characters (128 random bits). Also the polkit
    /// cancellation id.
    pub id: String,
    /// The human-facing code, unique among pending requests.
    pub code: RequestCode,
    /// The session that asked.
    pub session: String,
    /// What it asks for.
    pub kind: RequestKind,
    /// Agent-supplied reason (untrusted).
    pub reason: String,
    /// 256 random bits for the canonical request.
    pub nonce: [u8; 32],
    /// When it was created.
    pub created_at: SystemTime,
    /// When it lapses unless approved.
    pub expires_at: SystemTime,
    /// SHA-256 of the canonical request, set by the caller's digest
    /// function at creation.
    pub digest: [u8; 32],
}

/// A permission to obtain values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// `g_` + 16 base32 characters.
    pub id: String,
    /// The session it belongs to.
    pub session: String,
    /// Secrets it covers.
    pub names: Vec<String>,
    /// Mode.
    pub mode: Mode,
    /// The request it came from.
    pub request_id: String,
    /// When it was approved.
    pub issued_at: SystemTime,
    /// When it ends.
    pub expires_at: SystemTime,
    /// Reveals left, for a `reveal` grant.
    pub uses_left: Option<u32>,
}

/// An approved request: the request, and the grant it created (none for a
/// mutation, whose [`Mutation`] is in `request.kind`).
#[derive(Debug, Clone, PartialEq)]
pub struct Approved {
    /// The request, removed from the pending table.
    pub request: PendingRequest,
    /// The new grant.
    pub grant: Option<Grant>,
}

/// What [`Grants::sweep`] or [`Grants::end_session`] removed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Expired {
    /// Requests that lapsed (`request.expire`; cancel their approvers).
    pub requests: Vec<PendingRequest>,
    /// Grants that ended (`grant.expire`).
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Approved,
    Denied,
    Expired,
}

/// The request and grant tables.
pub struct Grants {
    policy: Policy,
    clock: Arc<dyn Clock>,
    pending: BTreeMap<String, PendingRequest>,
    by_code: HashMap<RequestCode, String>,
    ended: HashMap<RequestCode, (Ended, SystemTime)>,
    grants: BTreeMap<String, Grant>,
    recent: HashMap<String, VecDeque<SystemTime>>,
    cooldown: HashMap<(String, String), SystemTime>,
}

impl std::fmt::Debug for Grants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grants")
            .field("pending", &self.pending.len())
            .field("grants", &self.grants.len())
            .finish_non_exhaustive()
    }
}

fn not_found() -> GrantError {
    GrantError::new(
        ErrorCode::RequestNotFound,
        "no pending request with that code",
    )
}

impl Grants {
    /// Empty tables.
    pub fn new(policy: Policy, clock: Arc<dyn Clock>) -> Self {
        Self {
            policy,
            clock,
            pending: BTreeMap::new(),
            by_code: HashMap::new(),
            ended: HashMap::new(),
            grants: BTreeMap::new(),
            recent: HashMap::new(),
            cooldown: HashMap::new(),
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Replaces the policy (config reload). Existing grants keep their
    /// expiry.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// Creates a grant request. `known` says whether a secret exists;
    /// `digest` computes the canonical request digest from the new request
    /// (whose `digest` field is still zero).
    ///
    /// Refuses: a human session (`no_session`), unknown or malformed names
    /// (`unknown_secret`), too many names, a TTL above the limit, reveal
    /// when disabled, an over-long reason (`limit_exceeded`), and too many
    /// pending or recent requests or a secret in deny cooldown
    /// (`rate_limited`).
    pub fn request_grant(
        &mut self,
        session: &Session,
        ask: GrantAsk<'_>,
        known: impl Fn(&str) -> bool,
        digest: impl FnOnce(&PendingRequest) -> [u8; 32],
    ) -> Result<&PendingRequest, GrantError> {
        let GrantAsk {
            names,
            mode,
            ttl,
            reason,
        } = ask;
        if session.is_human() {
            return Err(GrantError::new(
                ErrorCode::NoSession,
                "grants belong to an agent session; start the agent with `cn session exec`",
            ));
        }
        let mut names = names.to_vec();
        names.sort();
        names.dedup();
        let p = &self.policy;
        if names.is_empty() || names.len() > p.max_names_per_request {
            return Err(GrantError::new(
                ErrorCode::LimitExceeded,
                format!("a request names 1 to {} secrets", p.max_names_per_request),
            ));
        }
        let unknown: Vec<String> = names
            .iter()
            .filter(|n| !valid_name(n) || !known(n))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(GrantError::new(
                ErrorCode::UnknownSecret,
                format!("no secret named {}", unknown.join(", ")),
            )
            .with_names(unknown));
        }
        let (default, max) = match mode {
            Mode::Use => (p.default_ttl, p.max_ttl),
            Mode::Reveal => {
                if !p.allow_reveal {
                    return Err(GrantError::new(
                        ErrorCode::LimitExceeded,
                        "reveal is disabled by policy",
                    ));
                }
                (p.default_ttl.min(p.max_reveal_ttl), p.max_reveal_ttl)
            }
        };
        let ttl = ttl.unwrap_or(default);
        if ttl.is_zero() || ttl > max {
            return Err(GrantError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "ttl must be between 1s and {}",
                    crate::time::format_duration(max)
                ),
            ));
        }
        let kind = RequestKind::Grant { names, mode, ttl };
        self.create(&session.id, kind, reason, digest)
    }

    /// Creates a mutation request. Check it against the store first
    /// ([`crate::store::Store::check_all`]). Human sessions may make these.
    pub fn request_mutation(
        &mut self,
        session: &Session,
        mutations: Vec<Mutation>,
        reason: &str,
        digest: impl FnOnce(&PendingRequest) -> [u8; 32],
    ) -> Result<&PendingRequest, GrantError> {
        if mutations.is_empty() {
            return Err(GrantError::new(
                ErrorCode::BadRequest,
                "a store change names at least one secret",
            ));
        }
        self.create(
            &session.id,
            RequestKind::Mutation(mutations),
            reason,
            digest,
        )
    }

    fn create(
        &mut self,
        session: &str,
        kind: RequestKind,
        reason: &str,
        digest: impl FnOnce(&PendingRequest) -> [u8; 32],
    ) -> Result<&PendingRequest, GrantError> {
        let now = self.clock.now();
        if reason.len() > MAX_REASON_BYTES {
            return Err(GrantError::new(
                ErrorCode::LimitExceeded,
                format!("reason is longer than {MAX_REASON_BYTES} bytes"),
            ));
        }
        let pending = self
            .pending
            .values()
            .filter(|r| r.session == session)
            .count();
        if pending >= self.policy.max_pending_requests {
            return Err(GrantError::new(
                ErrorCode::RateLimited,
                format!("{pending} requests are already pending in this session"),
            ));
        }
        let hour = Duration::from_secs(3600);
        let recent = self.recent.entry(session.to_owned()).or_default();
        while recent
            .front()
            .is_some_and(|t| now.duration_since(*t).unwrap_or_default() >= hour)
        {
            recent.pop_front();
        }
        if recent.len() >= self.policy.requests_per_hour as usize {
            return Err(GrantError::new(
                ErrorCode::RateLimited,
                "too many requests in the last hour",
            ));
        }
        let cooling: Vec<String> = kind
            .names()
            .into_iter()
            .filter(|n| {
                self.cooldown
                    .get(&(session.to_owned(), n.clone()))
                    .is_some_and(|until| now < *until)
            })
            .collect();
        if !cooling.is_empty() {
            return Err(GrantError::new(
                ErrorCode::RateLimited,
                "a request for these secrets was denied a moment ago",
            )
            .with_names(cooling));
        }
        let code = loop {
            let bits = u32::from_le_bytes(random_array());
            let code = RequestCode::from_bits(bits);
            if !self.by_code.contains_key(&code) && !self.ended.contains_key(&code) {
                break code;
            }
        };
        let mut req = PendingRequest {
            id: random_id("r_", 26),
            code,
            session: session.to_owned(),
            kind,
            reason: reason.to_owned(),
            nonce: random_array(),
            created_at: now,
            expires_at: now + self.policy.pending_expiry,
            digest: [0; 32],
        };
        req.digest = digest(&req);
        self.recent
            .entry(session.to_owned())
            .or_default()
            .push_back(now);
        self.by_code.insert(code, req.id.clone());
        let id = req.id.clone();
        Ok(self.pending.entry(id).or_insert(req))
    }

    /// The pending request with this code (any case, dash optional).
    /// An unparseable or unknown code is `request_not_found`; one that
    /// lapsed recently is `request_expired`.
    pub fn get(&self, code: &str) -> Result<&PendingRequest, GrantError> {
        let code: RequestCode = code.parse().map_err(|_| not_found())?;
        if let Some(r) = self.by_code.get(&code).and_then(|id| self.pending.get(id)) {
            if self.clock.now() >= r.expires_at {
                return Err(GrantError::new(
                    ErrorCode::RequestExpired,
                    "the request expired",
                ));
            }
            return Ok(r);
        }
        match self.ended.get(&code) {
            Some((Ended::Expired, _)) => Err(GrantError::new(
                ErrorCode::RequestExpired,
                "the request expired",
            )),
            Some((Ended::Approved, _)) => Err(GrantError::new(
                ErrorCode::RequestNotFound,
                "the request was already approved",
            )),
            Some((Ended::Denied, _)) => Err(GrantError::new(
                ErrorCode::RequestNotFound,
                "the request was denied",
            )),
            None => Err(not_found()),
        }
    }

    /// The pending request with this id.
    pub fn get_by_id(&self, id: &str) -> Option<&PendingRequest> {
        self.pending.get(id)
    }

    /// Pending requests of a session.
    pub fn pending_for(&self, session: &str) -> Vec<&PendingRequest> {
        self.pending
            .values()
            .filter(|r| r.session == session)
            .collect()
    }

    fn take(&mut self, id: &str, how: Ended) -> Result<PendingRequest, GrantError> {
        let r = self.pending.remove(id).ok_or_else(not_found)?;
        self.by_code.remove(&r.code);
        self.ended.insert(r.code, (how, self.clock.now()));
        Ok(r)
    }

    /// Approves a pending request (when its whole approver chain has
    /// approved). A grant request becomes an active grant whose TTL counts
    /// from now. A request past its expiry is `request_expired`.
    pub fn approve(&mut self, request_id: &str) -> Result<Approved, GrantError> {
        let now = self.clock.now();
        let r = self.pending.get(request_id).ok_or_else(not_found)?;
        if now >= r.expires_at {
            self.take(request_id, Ended::Expired)?;
            return Err(GrantError::new(
                ErrorCode::RequestExpired,
                "the request expired",
            ));
        }
        let request = self.take(request_id, Ended::Approved)?;
        let grant = match &request.kind {
            RequestKind::Grant { names, mode, ttl } => {
                let g = Grant {
                    id: random_id("g_", 16),
                    session: request.session.clone(),
                    names: names.clone(),
                    mode: *mode,
                    request_id: request.id.clone(),
                    issued_at: now,
                    expires_at: now + *ttl,
                    uses_left: (*mode == Mode::Reveal).then_some(self.policy.max_reveal_uses),
                };
                self.grants.insert(g.id.clone(), g.clone());
                Some(g)
            }
            RequestKind::Mutation(_) => None,
        };
        Ok(Approved { request, grant })
    }

    /// Ends a pending request without a decision: no grant and no deny
    /// cooldown; its code reads as expired. For a request whose approver
    /// timed out ahead of [`Grants::sweep`], or one `cnd` could not record
    /// (its `request.create` audit write failed).
    pub fn expire(&mut self, request_id: &str) -> Result<PendingRequest, GrantError> {
        self.take(request_id, Ended::Expired)
    }

    /// Denies a pending request. Its secrets go into deny cooldown for the
    /// session.
    pub fn deny(&mut self, request_id: &str) -> Result<PendingRequest, GrantError> {
        let r = self.take(request_id, Ended::Denied)?;
        let until = self.clock.now() + self.policy.deny_cooldown;
        for n in r.kind.names() {
            self.cooldown.insert((r.session.clone(), n), until);
        }
        Ok(r)
    }

    /// Whether `session` holds a live grant covering `name` in `mode`.
    pub fn has_grant(&self, session: &str, name: &str, mode: Mode) -> bool {
        self.find(session, name, mode).is_some()
    }

    fn find(&self, session: &str, name: &str, mode: Mode) -> Option<&Grant> {
        let now = self.clock.now();
        self.grants.values().find(|g| {
            g.session == session
                && g.mode == mode
                && now < g.expires_at
                && g.uses_left != Some(0)
                && g.names.iter().any(|n| n == name)
        })
    }

    /// For `run`: every name needs a live `use` grant. Otherwise
    /// `grant_required`, naming the missing ones.
    pub fn check_use(&self, session: &str, names: &[String]) -> Result<(), GrantError> {
        let missing: Vec<String> = names
            .iter()
            .filter(|n| !self.has_grant(session, n, Mode::Use))
            .cloned()
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(GrantError::new(
                ErrorCode::GrantRequired,
                format!("no active use grant for {}", missing.join(", ")),
            )
            .with_names(missing))
        }
    }

    /// For `reveal`: uses one reveal of a live grant. Returns the grant id
    /// and the reveals left; a grant with none left is removed.
    pub fn consume_reveal(
        &mut self,
        session: &str,
        name: &str,
    ) -> Result<(String, u32), GrantError> {
        let id = self
            .find(session, name, Mode::Reveal)
            .map(|g| g.id.clone())
            .ok_or_else(|| {
                GrantError::new(
                    ErrorCode::GrantRequired,
                    format!("no active reveal grant for {name}"),
                )
                .with_names(vec![name.to_owned()])
            })?;
        let g = self.grants.get_mut(&id).expect("found");
        let left = g.uses_left.unwrap_or(1).saturating_sub(1);
        g.uses_left = Some(left);
        if left == 0 {
            self.grants.remove(&id);
        }
        Ok((id, left))
    }

    /// Live grants of a session.
    pub fn grants_for(&self, session: &str) -> Vec<&Grant> {
        let now = self.clock.now();
        self.grants
            .values()
            .filter(|g| g.session == session && now < g.expires_at)
            .collect()
    }

    /// Names with a live grant in a session (any mode), for the `hide`
    /// pattern set.
    pub fn granted_names(&self, session: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .grants_for(session)
            .into_iter()
            .flat_map(|g| g.names.iter().cloned())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Revokes one grant of the session, or all of them. Revoking an id the
    /// session does not hold is `grant_required`.
    pub fn revoke(
        &mut self,
        session: &str,
        grant_id: Option<&str>,
    ) -> Result<Vec<Grant>, GrantError> {
        match grant_id {
            Some(id) => match self.grants.get(id) {
                Some(g) if g.session == session => {
                    Ok(vec![self.grants.remove(id).expect("present")])
                }
                _ => Err(GrantError::new(
                    ErrorCode::GrantRequired,
                    format!("this session holds no grant {id}"),
                )),
            },
            None => Ok(self.remove_grants(|g| g.session == session)),
        }
    }

    /// Revokes every grant that covers `name`, after its value changed or
    /// it was removed (`by: store_change`).
    pub fn revoke_secret(&mut self, name: &str) -> Vec<Grant> {
        self.remove_grants(|g| g.names.iter().any(|n| n == name))
    }

    fn remove_grants(&mut self, f: impl Fn(&Grant) -> bool) -> Vec<Grant> {
        let ids: Vec<String> = self
            .grants
            .values()
            .filter(|g| f(g))
            .map(|g| g.id.clone())
            .collect();
        ids.iter().filter_map(|id| self.grants.remove(id)).collect()
    }

    /// The session's anchor exited: its pending requests and grants end.
    pub fn end_session(&mut self, session: &str) -> Expired {
        let ids: Vec<String> = self
            .pending
            .values()
            .filter(|r| r.session == session)
            .map(|r| r.id.clone())
            .collect();
        let requests = ids
            .iter()
            .filter_map(|id| self.take(id, Ended::Expired).ok())
            .collect();
        let grants = self.remove_grants(|g| g.session == session);
        self.recent.remove(session);
        self.cooldown.retain(|(s, _), _| s != session);
        Expired { requests, grants }
    }

    /// Removes lapsed requests and grants. Call when
    /// [`Grants::next_deadline`] passes.
    pub fn sweep(&mut self) -> Expired {
        let now = self.clock.now();
        let ids: Vec<String> = self
            .pending
            .values()
            .filter(|r| now >= r.expires_at)
            .map(|r| r.id.clone())
            .collect();
        let requests = ids
            .iter()
            .filter_map(|id| self.take(id, Ended::Expired).ok())
            .collect();
        let grants = self.remove_grants(|g| now >= g.expires_at);
        let keep = self.policy.pending_expiry;
        self.ended
            .retain(|_, (_, at)| now.duration_since(*at).unwrap_or_default() < keep);
        self.cooldown.retain(|_, until| now < *until);
        Expired { requests, grants }
    }

    /// The earliest time a request or grant lapses.
    pub fn next_deadline(&self) -> Option<SystemTime> {
        let r = self.pending.values().map(|r| r.expires_at);
        let g = self.grants.values().map(|g| g.expires_at);
        r.chain(g).min()
    }
}

#[cfg(test)]
mod tests;
