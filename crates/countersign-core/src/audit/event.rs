//! Audit record bodies (audit.md, "Record schema").
//!
//! Every event carries metadata only. There is deliberately no field that
//! could hold a value, a hash of a value or a value's length.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::store::Change;

/// The `session` object of a record. Labels are untrusted and stored as
/// reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionRef {
    /// Session id, e.g. `s_7k2mq9d4x1ha`.
    pub id: String,
    /// Anchor pid.
    pub anchor_pid: u32,
    /// Anchor `comm`.
    pub anchor_comm: String,
    /// Whether the anchor was registered by `cn session exec`.
    pub registered: bool,
    /// Untrusted labels from `label_env`.
    pub labels: BTreeMap<String, String>,
}

/// One process in a session's ancestry, for `session.start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainLink {
    /// Process id.
    pub pid: u32,
    /// `/proc/PID/comm`.
    pub comm: String,
}

/// An event to record. The writer adds `v`, `seq`, `ts`, `boot`,
/// `session`, `prev` and `hash`.
///
/// `evidence` and `approvers` are free-form JSON from other components and
/// must not contain floating-point numbers (the chain uses canonical JSON).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event")]
pub enum Event {
    /// `cnd` started.
    #[serde(rename = "daemon.start")]
    DaemonStart {
        /// `cnd` version.
        version: String,
        /// `cnd` pid.
        pid: u32,
        /// `systemd-creds` or `sealed`.
        unseal: String,
    },
    /// `cnd` is stopping.
    #[serde(rename = "daemon.stop")]
    DaemonStop {
        /// Why.
        reason: String,
    },
    /// A config was loaded.
    #[serde(rename = "config.load")]
    ConfigLoad {
        /// Config path.
        path: String,
        /// Hex SHA-256 of the file.
        sha256: String,
        /// Approver instances and their state.
        approvers: serde_json::Value,
    },
    /// `cnd init` created the store. Not in audit.md; the first record of a
    /// new log.
    #[serde(rename = "store.init")]
    StoreInit {
        /// Key slots written.
        slots: Vec<String>,
    },
    /// The store was unsealed.
    #[serde(rename = "store.unseal")]
    StoreUnseal {
        /// The slot used.
        slot: String,
    },
    /// A session was discovered.
    #[serde(rename = "session.start")]
    SessionStart {
        /// Ancestry from the peer to the anchor.
        chain: Vec<ChainLink>,
    },
    /// A session's anchor exited.
    #[serde(rename = "session.end")]
    SessionEnd {
        /// Grants that expired with it.
        grants_expired: u32,
    },
    /// Coalesced `list` calls.
    #[serde(rename = "list")]
    List {
        /// Calls covered.
        count: u64,
        /// First call covered (RFC 3339).
        window_start: String,
        /// Last call covered (RFC 3339).
        window_end: String,
    },
    /// A request was created.
    #[serde(rename = "request.create")]
    RequestCreate {
        /// Request id.
        request_id: String,
        /// Human code.
        code: String,
        /// Secrets named.
        secrets: Vec<String>,
        /// `use`, `reveal`, `mutate` or `export`.
        mode: String,
        /// For mutations: `add`, `set`, `edit` or `rm`. Not in audit.md.
        #[serde(skip_serializing_if = "Option::is_none")]
        operation: Option<String>,
        /// Grant TTL (0 for mutations).
        ttl_seconds: u64,
        /// Agent-supplied reason (untrusted).
        reason: String,
        /// Client-reported cwd (untrusted).
        cwd: Option<String>,
        /// Hex SHA-256 of the canonical request.
        digest: String,
        /// Base64 of the canonical request bytes.
        canonical: String,
    },
    /// A request was approved.
    #[serde(rename = "request.approve")]
    RequestApprove {
        /// Request id.
        request_id: String,
        /// Hex digest the approver saw.
        digest: String,
        /// Approver instance.
        approver: String,
        /// FIDO2 credential id (Phase 2).
        credential_id: Option<String>,
        /// Grants created.
        grant_ids: Vec<String>,
        /// Adapter evidence.
        evidence: serde_json::Value,
    },
    /// A request was denied.
    #[serde(rename = "request.deny")]
    RequestDeny {
        /// Request id.
        request_id: String,
        /// Hex digest the approver saw.
        digest: String,
        /// Approver instance, or `client` for `cn deny`.
        approver: String,
        /// FIDO2 credential id (Phase 2).
        credential_id: Option<String>,
        /// Always empty.
        grant_ids: Vec<String>,
        /// Adapter evidence.
        evidence: serde_json::Value,
    },
    /// An approval failed verification.
    #[serde(rename = "request.approve_fail")]
    RequestApproveFail {
        /// Request id.
        request_id: String,
        /// Approver instance.
        approver: String,
        /// FIDO2 credential id (Phase 2).
        credential_id: Option<String>,
        /// What failed.
        error: String,
    },
    /// A request lapsed.
    #[serde(rename = "request.expire")]
    RequestExpire {
        /// Request id.
        request_id: String,
    },
    /// A grant was revoked.
    #[serde(rename = "grant.revoke")]
    GrantRevoke {
        /// Grant id.
        grant_id: String,
        /// Secrets it covered.
        secrets: Vec<String>,
        /// `client`, `anchor_exit`, `store_change` or `restart`.
        by: String,
    },
    /// A grant expired.
    #[serde(rename = "grant.expire")]
    GrantExpire {
        /// Grant id.
        grant_id: String,
        /// Secrets it covered.
        secrets: Vec<String>,
        /// `ttl`, `anchor_exit` or `uses`.
        by: String,
    },
    /// `cn run` received values.
    #[serde(rename = "use.start")]
    UseStart {
        /// Run id.
        run_id: String,
        /// Secrets injected.
        secrets: Vec<String>,
        /// Environment variable names.
        env: Vec<String>,
        /// Program name (untrusted).
        argv0: String,
        /// Argument count.
        argc: u32,
        /// Client-reported cwd (untrusted).
        cwd: Option<String>,
        /// Peer pid.
        pid: u32,
    },
    /// A `cn run` child finished.
    #[serde(rename = "use.end")]
    UseEnd {
        /// Run id.
        run_id: String,
        /// `exited`, `signaled` or `client_lost`.
        status: String,
        /// Exit code.
        exit: Option<i32>,
        /// Signal number.
        signal: Option<i32>,
        /// Wall time.
        duration_ms: u64,
        /// Redaction hits per secret.
        hits: BTreeMap<String, u64>,
    },
    /// A raw value was revealed.
    #[serde(rename = "reveal")]
    Reveal {
        /// Secret name.
        secret: String,
        /// Grant id.
        grant_id: String,
        /// Reveals left on the grant.
        uses_left: u32,
    },
    /// A `cn hide` stream ended.
    #[serde(rename = "hide")]
    Hide {
        /// Bytes read.
        bytes_in: u64,
        /// Bytes written.
        bytes_out: u64,
        /// Hits per secret.
        hits: BTreeMap<String, u64>,
        /// Patterns in the engine.
        patterns: u64,
    },
    /// A secret was added.
    #[serde(rename = "store.add")]
    StoreAdd(StoreChange),
    /// A value was replaced.
    #[serde(rename = "store.set")]
    StoreSet(StoreChange),
    /// Metadata was replaced.
    #[serde(rename = "store.edit")]
    StoreEdit(StoreChange),
    /// A secret was removed.
    #[serde(rename = "store.rm")]
    StoreRm(StoreChange),
    /// `cnd recover` re-wrapped the machine key slot.
    #[serde(rename = "keyslot.add")]
    KeyslotAdd {
        /// Slot type.
        slot: String,
        /// FIDO2 credential id (Phase 2).
        credential_id: Option<String>,
        /// Request id, when approved through a request.
        request_id: Option<String>,
    },
    /// The store was exported.
    #[serde(rename = "export")]
    Export {
        /// Request id.
        request_id: String,
        /// Secrets exported.
        count: u64,
        /// age recipient.
        recipient: String,
    },
    /// Secrets were imported.
    #[serde(rename = "import")]
    Import {
        /// Request id.
        request_id: String,
        /// Secrets imported.
        count: u64,
    },
    /// An unlock attempt.
    #[serde(rename = "unlock")]
    Unlock {
        /// Slot.
        slot: String,
        /// Outcome.
        result: String,
    },
    /// A peer was refused.
    #[serde(rename = "peer.reject")]
    PeerReject {
        /// Peer uid.
        uid: u32,
        /// Peer pid.
        pid: u32,
        /// Error code sent.
        code: String,
    },
}

/// The body of a `store.*` record.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StoreChange {
    /// Secret name.
    pub secret: String,
    /// The approved request.
    pub request_id: String,
    /// Fields that changed.
    pub fields_changed: Vec<String>,
    /// Whether the value changed.
    pub value_changed: bool,
    /// Store generation after the change.
    pub generation: u64,
    /// New metadata, for `add` and `edit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl Event {
    /// The `store.*` event for a committed change.
    pub fn store(change: &Change, request_id: &str) -> Event {
        let body = StoreChange {
            secret: change.secret.clone(),
            request_id: request_id.to_owned(),
            fields_changed: change
                .fields_changed
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            value_changed: change.value_changed,
            generation: change.generation,
            metadata: change
                .metadata
                .as_ref()
                .map(|m| serde_json::to_value(m).expect("metadata serializes")),
        };
        match change.op {
            "add" => Event::StoreAdd(body),
            "set" => Event::StoreSet(body),
            "edit" => Event::StoreEdit(body),
            _ => Event::StoreRm(body),
        }
    }
}

/// Events only the writer produces.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event")]
pub(crate) enum Internal {
    #[serde(rename = "checkpoint")]
    Checkpoint {
        upto_seq: u64,
        upto_hash: String,
        host: String,
        sig: String,
    },
    #[serde(rename = "segment.open")]
    SegmentOpen {
        segment: String,
        prev_segment_last_hash: String,
    },
}
