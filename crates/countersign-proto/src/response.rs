//! Messages from `cnd` to `cn`.
//!
//! Every response is a JSON message whose `type` names the variant, with the
//! request's `id` beside it (see [`crate::Envelope`]). Which request gets
//! which response:
//!
//! | Request | Response |
//! | --- | --- |
//! | `hello` | `hello_ok` |
//! | `session` | `session` |
//! | `list` | `list` |
//! | `request` | `request_created`, or `already_granted` |
//! | `get_request` | `request_status` |
//! | `approve` | `approved`, or `pending` while other chain members are outstanding |
//! | `deny` | `denied` |
//! | `grants` | `grants` |
//! | `revoke` | `revoked` |
//! | `run` | `run_ok` |
//! | `run_finish` | `ok` |
//! | `hide` | `hide_ok`, then stream frames both ways |
//! | `hide_end` | the remaining stream frames, then `hide_summary` |
//! | `reveal` | `reveal` |
//! | `add`, `set`, `edit`, `rm`, `import` | `request_created` (kind `mutate`) |
//! | `audit_query` | `audit_records` |
//! | `audit_segments` | `audit_segments` |
//! | `session_register` | `registered` |
//! | `unlock` | `unsealed` |
//!
//! Any request may instead get `error`.
//!
//! Waiting for a decision (`cn request --wait`, `cn add --wait`): the client
//! sends `get_request` with `wait_seconds`. `cnd` answers as soon as the
//! request leaves `pending`, or when the wait (capped by `cnd`) runs out,
//! with `request_status` either way. The client repeats until the state is
//! not `pending` or its own deadline passes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::{Anchor, CanonicalRequest};
use crate::request::{Mode, SecretMeta, ValueB64};
use crate::{ErrorBody, Timestamp};

/// A process in the chain from the caller to the anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Process id.
    pub pid: u32,
    /// `/proc/PID/comm`.
    pub comm: String,
    /// Start time, clock ticks since boot (field 22 of `/proc/PID/stat`).
    pub starttime: u64,
}

/// What `cnd` resolved the caller's session to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    /// Session id, `s_...`.
    pub id: String,
    /// The anchor process.
    pub anchor: Anchor,
    /// When the anchor started.
    pub started_at: Timestamp,
    /// Label given to `cn session exec --label`.
    #[serde(default)]
    pub label: Option<String>,
    /// From the caller (first) to the anchor (last), as seen at discovery.
    #[serde(default)]
    pub chain: Vec<ChainEntry>,
    /// Untrusted labels the client reported (e.g. `CLAUDE_CODE_SESSION_ID`).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Client-reported working directory (untrusted).
    #[serde(default)]
    pub cwd: Option<String>,
    /// False once the anchor has exited.
    pub alive: bool,
    /// Active grants in this session.
    pub active_grants: u32,
}

/// An active grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    /// Grant id, `g_...`.
    pub id: String,
    /// Secrets it covers.
    pub secrets: Vec<String>,
    /// Grant mode.
    pub mode: Mode,
    /// When it expires.
    pub expires_at: Timestamp,
    /// Approver instances that approved it.
    pub approved_by: Vec<String>,
    /// Values issued under it so far (`run` and `reveal`).
    #[serde(default)]
    pub uses: u64,
    /// For `reveal` grants: reveals left before it is consumed.
    #[serde(default)]
    pub reveals_left: Option<u32>,
    /// The session it belongs to.
    pub session: String,
}

/// The last time a secret's value was issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastUse {
    /// When.
    pub at: Timestamp,
    /// In which session.
    pub session: String,
    /// The program name `cn run` reported, if it was a run.
    #[serde(default)]
    pub argv0: Option<String>,
}

/// One secret as `list` shows it. Never a value or a value length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretView {
    /// Name, description, usage, projects, tags, `high_entropy`.
    #[serde(flatten)]
    pub meta: SecretMeta,
    /// Whether `projects` matches the session's cwd (or is empty).
    pub in_project: bool,
    /// The default environment variable for `cn run --use NAME`.
    pub default_env: String,
    /// The session's active grant covering it, if any (the widest mode, then
    /// the latest expiry).
    #[serde(default)]
    pub grant: Option<GrantView>,
    /// Creation time.
    #[serde(default)]
    pub created: Option<Timestamp>,
    /// Last change of any field.
    #[serde(default)]
    pub updated: Option<Timestamp>,
    /// Last change of the value.
    #[serde(default)]
    pub rotated: Option<Timestamp>,
    /// Last issuance of the value, in any session.
    #[serde(default)]
    pub last_use: Option<LastUse>,
}

/// Where a request is in its lifecycle (design.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    /// Waiting for approvers.
    Pending,
    /// Every required approver approved. For `use`/`reveal` a grant is now
    /// active; for `mutate` the change is committed.
    Approved,
    /// Denied by a human, an approver, or a dismissed dialog.
    Denied,
    /// Lapsed before a decision, or its anchor exited.
    Expired,
}

/// Who drives an approver (approvers.md, "Daemon-driven and client-driven").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Driven {
    /// `cnd` runs it (polkit, command).
    Daemon,
    /// The human runs `/usr/bin/cn approve CODE` (fido2).
    Client,
}

/// One approver instance in a request's chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverView {
    /// Instance name from the config, e.g. `polkit` or `desk-key`.
    pub name: String,
    /// Adapter, e.g. `polkit`.
    pub adapter: String,
    /// Who drives it.
    pub driven: Driven,
    /// For a daemon-driven approver: whether its prompt is up now.
    #[serde(default)]
    pub prompted: bool,
}

/// How a request was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// When.
    pub at: Timestamp,
    /// Approver instances, or `client` for `cn deny`, or `expiry`.
    pub by: Vec<String>,
    /// Reason given with `cn deny`, or why an approver denied.
    #[serde(default)]
    pub reason: Option<String>,
    /// The grant an approved `use`/`reveal` request created.
    #[serde(default)]
    pub grant: Option<GrantView>,
    /// Grants revoked by an approved store change (`set`, `rm`).
    #[serde(default)]
    pub grants_revoked: u32,
}

/// A request, as `request_created` and `request_status` carry it. The
/// canonical request's fields sit at the top level beside the state, so a
/// client can rebuild the canonical bytes and check `digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestView {
    /// The fields the digest covers.
    #[serde(flatten)]
    pub request: CanonicalRequest,
    /// Lifecycle state.
    pub state: RequestState,
    /// Hex SHA-256 of the canonical bytes.
    pub digest: String,
    /// `XXXX-XXXX`, see [`crate::Digest::short`].
    pub digest_short: String,
    /// The approver chain for this request's kind.
    pub approvers: Vec<ApproverView>,
    /// Set once the request has left `pending`.
    #[serde(default)]
    pub decision: Option<Decision>,
}

/// A value issued for `cn run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunValue {
    /// Secret name, for the redaction marker and hit counts.
    pub name: String,
    /// Environment variable to set in the child.
    pub env: String,
    /// The value.
    pub value_b64: ValueB64,
}

/// An extra value `cn run` scrubs from output but does not inject (other
/// secrets granted to the session, and `high_entropy` secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubValue {
    /// Secret name.
    pub name: String,
    /// The value.
    pub value_b64: ValueB64,
}

/// A message from `cnd` to `cn`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Answer to `hello`.
    HelloOk {
        /// The protocol version chosen.
        protocol: u32,
        /// Server name and version, e.g. `cnd/0.1.0`.
        server: String,
        /// The caller's session, or `None` when no anchor was found. A
        /// connection without a session can still `deny`, `session_register`
        /// and read the audit log; anything that needs one fails with
        /// `no_session`.
        #[serde(default)]
        session: Option<SessionView>,
    },
    /// Answer to `session`. Not a newtype: the view's `id` would collide
    /// with the envelope's.
    Session {
        /// The caller's session.
        session: SessionView,
    },
    /// Answer to `list`.
    List {
        /// The caller's session id, if it has one.
        #[serde(default)]
        session: Option<String>,
        /// Visible secrets, sorted by name.
        secrets: Vec<SecretView>,
    },
    /// A request (grant or store change) was created and is pending.
    RequestCreated(RequestView),
    /// Answer to `request` when an existing grant already covers it; nothing
    /// was created.
    AlreadyGranted {
        /// The covering grant.
        grant: GrantView,
    },
    /// Answer to `get_request`.
    RequestStatus(RequestView),
    /// The approval completed the chain.
    Approved {
        /// Request id.
        request_id: String,
        /// Request code.
        code: String,
        /// Grants created (empty for a store change).
        grant_ids: Vec<String>,
    },
    /// The approval was accepted; other chain members are still outstanding.
    Pending {
        /// Request id.
        request_id: String,
        /// Request code.
        code: String,
        /// Approver instances still needed.
        waiting_for: Vec<String>,
    },
    /// Answer to `deny`.
    Denied {
        /// Request id.
        request_id: String,
        /// Request code.
        code: String,
    },
    /// Answer to `grants`.
    Grants {
        /// Active grants.
        grants: Vec<GrantView>,
    },
    /// Answer to `revoke`: the grants that were revoked.
    Revoked {
        /// Revoked grants, as they were just before revocation.
        grants: Vec<GrantView>,
    },
    /// Answer to `run`. The connection stays open until `run_finish`.
    RunOk {
        /// Id for `run_finish` and the audit log, `u_...`.
        run_id: String,
        /// Values to inject.
        values: Vec<RunValue>,
        /// Values to scrub but not inject.
        #[serde(default)]
        patterns_extra: Vec<ScrubValue>,
    },
    /// Generic success (e.g. for `run_finish`).
    Ok,
    /// Answer to `hide`; stream frames follow.
    HideOk,
    /// Final message of a `hide` stream, after the last stream frame.
    HideSummary {
        /// Bytes received from the client.
        bytes_in: u64,
        /// Bytes sent back.
        bytes_out: u64,
        /// Redaction hits per secret.
        #[serde(default)]
        hits: BTreeMap<String, u64>,
    },
    /// Answer to `reveal`.
    Reveal {
        /// Secret name.
        name: String,
        /// The value.
        value_b64: ValueB64,
        /// Reveals left on the grant.
        #[serde(default)]
        reveals_left: Option<u32>,
    },
    /// Answer to `audit_query`: records in `seq` order, as stored (audit.md).
    AuditRecords {
        /// The records.
        records: Vec<serde_json::Value>,
    },
    /// Answer to `audit_segments`: raw log bytes, complete JSONL lines
    /// starting at the record with `seq == from_seq` (or the oldest retained
    /// record after it). `cnd` limits each answer to fit one frame.
    AuditSegments {
        /// The bytes, standard base64.
        data_b64: String,
        /// `Some(seq)` when more records follow: ask again from there.
        #[serde(default)]
        next_seq: Option<u64>,
        /// Contents of `audit/checkpoint.pub`, if present.
        #[serde(default)]
        checkpoint_pubkey: Option<String>,
    },
    /// Answer to `session_register`.
    Registered {
        /// The new session, anchored at the caller.
        session: SessionView,
    },
    /// Answer to `unlock`.
    Unsealed {
        /// The key slot that unsealed the store.
        slot: String,
    },
    /// The request failed.
    Error(ErrorBody),
}
