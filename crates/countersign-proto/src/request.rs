//! Messages from `cn` to `cnd`.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::Timestamp;

/// Grant mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Values are injected into a child process by `cn run`.
    Use,
    /// The raw value may be printed by `cn reveal`.
    Reveal,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Use => "use",
            Self::Reveal => "reveal",
        })
    }
}

/// One secret to inject for `cn run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Use {
    /// Secret name.
    pub name: String,
    /// Environment variable the child sees.
    pub env: String,
}

/// Secret metadata. Never carries a value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    /// Secret name.
    pub name: String,
    /// One-line description.
    #[serde(default)]
    pub description: String,
    /// Prose on how the secret should be used.
    #[serde(default)]
    pub usage: String,
    /// Project path globs the secret belongs to (organizational only).
    #[serde(default)]
    pub projects: Vec<String>,
    /// Free-form tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether `cn hide` matches it without a grant.
    #[serde(default)]
    pub high_entropy: bool,
}

/// A secret value, standard base64 with padding. `Debug` prints no value and
/// the string is zeroized on drop. Copies made by serde while encoding or
/// decoding a frame are not covered; callers zeroize their frame buffers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValueB64(String);

impl ValueB64 {
    /// Encodes raw bytes.
    pub fn encode(value: &[u8]) -> Self {
        Self(STANDARD.encode(value))
    }

    /// Wraps an already-encoded string.
    pub fn from_encoded(encoded: String) -> Self {
        Self(encoded)
    }

    /// Decodes to raw bytes, which are zeroized on drop.
    pub fn decode(&self) -> Result<Zeroizing<Vec<u8>>, base64::DecodeError> {
        STANDARD.decode(&self.0).map(Zeroizing::new)
    }

    /// The encoded string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ValueB64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValueB64(<redacted>)")
    }
}

impl Drop for ValueB64 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Where a value for `add`, `set` or `import` came from. Shown in the
/// approval display so the human can tell a typed value from a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueSource {
    /// Typed at a no-echo prompt.
    Prompt,
    /// Read from the Wayland clipboard.
    Clipboard,
    /// Read from a file named on the command line.
    File,
    /// Read from standard input.
    Stdin,
}

/// One secret in an `import` batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportItem {
    /// Metadata for the new secret.
    pub meta: SecretMeta,
    /// The value.
    pub value_b64: ValueB64,
}

/// A message from `cn` to `cnd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// First frame on every connection.
    Hello {
        /// Protocol versions the client speaks.
        protocols: Vec<u32>,
        /// Client name and version, e.g. `cn/0.1.0`.
        client: String,
        /// Untrusted labels such as an agent session id, for the audit log.
        #[serde(default)]
        labels: BTreeMap<String, String>,
        /// Client-reported working directory (an untrusted label).
        #[serde(default)]
        cwd: Option<String>,
    },
    /// Describe the caller's session.
    Session,
    /// List secrets.
    List {
        /// Include secrets scoped to other projects.
        #[serde(default)]
        all_projects: bool,
    },
    /// Ask for a grant. Answered with `request_created`, or `already_granted`
    /// when an active grant of the same or a wider mode covers every name.
    Request {
        /// Secrets requested.
        names: Vec<String>,
        /// Grant mode.
        mode: Mode,
        /// Requested lifetime; `None` takes the configured default for the mode.
        #[serde(default)]
        ttl_seconds: Option<u64>,
        /// Why, shown to the approver.
        reason: String,
    },
    /// Fetch a request for display, or wait for it to be decided. Answered
    /// with `request_status`. A request stays findable by its code for the
    /// pending lifetime after it leaves `pending`, and its code is not
    /// reused during that time.
    GetRequest {
        /// The human-facing code.
        code: String,
        /// Block up to this many seconds while the request is pending. `cnd`
        /// may answer earlier (it caps a single wait); the client repeats.
        #[serde(default)]
        wait_seconds: Option<u64>,
    },
    /// Approve a pending request.
    Approve {
        /// The human-facing code.
        code: String,
        /// Approver instance name from the config (e.g. `desk-key`).
        approver: String,
        /// FIDO2 assertion, base64url, for client-driven approvers.
        #[serde(default)]
        assertion: Option<String>,
    },
    /// Deny a pending request.
    Deny {
        /// The human-facing code.
        code: String,
        /// Why, for the audit log.
        #[serde(default)]
        reason: Option<String>,
    },
    /// List active grants.
    Grants {
        /// Every live session of the caller's uid, not only the caller's.
        #[serde(default)]
        all_sessions: bool,
    },
    /// Revoke grants. Exactly one selector: `grant_ids` non-empty, `secret`,
    /// or `all`; anything else is `bad_request`.
    Revoke {
        /// These grants.
        #[serde(default)]
        grant_ids: Vec<String>,
        /// Every grant covering this secret.
        #[serde(default)]
        secret: Option<String>,
        /// Every grant.
        #[serde(default)]
        all: bool,
        /// Apply the selector to every live session of the caller's uid.
        #[serde(default)]
        all_sessions: bool,
    },
    /// Start `cn run`.
    Run {
        /// Secrets to inject.
        uses: Vec<Use>,
        /// Program name, for the audit log.
        argv0: String,
        /// Argument count, for the audit log.
        argc: u32,
    },
    /// Report the end of a `cn run` child.
    RunFinish {
        /// From the `run` response.
        run_id: String,
        /// Exit status, if the child exited.
        #[serde(default)]
        exit: Option<i32>,
        /// Signal number, if the child was killed.
        #[serde(default)]
        signal: Option<i32>,
        /// Wall time.
        duration_ms: u64,
        /// Redaction hits per secret.
        #[serde(default)]
        hits: BTreeMap<String, u64>,
    },
    /// Start a `cn hide` stream.
    Hide {
        /// Granted secrets to match besides the default pattern set.
        #[serde(default)]
        secrets: Vec<String>,
    },
    /// End a `cn hide` stream.
    HideEnd,
    /// Print a raw value (needs a `reveal` grant).
    Reveal {
        /// Secret name.
        name: String,
    },
    /// Propose a new secret (needs approval).
    Add {
        /// Metadata.
        meta: SecretMeta,
        /// Value.
        value_b64: ValueB64,
        /// Where the value came from.
        #[serde(default)]
        source: Option<ValueSource>,
    },
    /// Propose a new value for an existing secret (needs approval).
    Set {
        /// Secret name.
        name: String,
        /// Value.
        value_b64: ValueB64,
        /// Where the value came from.
        #[serde(default)]
        source: Option<ValueSource>,
    },
    /// Propose a metadata change (needs approval).
    Edit {
        /// The new metadata; `name` selects the secret.
        meta: SecretMeta,
    },
    /// Propose removing secrets (one approval for all of them).
    Rm {
        /// Secret names.
        names: Vec<String>,
    },
    /// Propose adding a batch of secrets (one approval for the batch).
    Import {
        /// The secrets.
        secrets: Vec<ImportItem>,
    },
    /// Query the audit log. Answered with `audit_records`.
    AuditQuery {
        /// Filter by session id.
        #[serde(default)]
        session: Option<String>,
        /// Filter by secret name.
        #[serde(default)]
        secret: Option<String>,
        /// Filter by event type; empty means every event.
        #[serde(default)]
        events: Vec<String>,
        /// Lower bound on `ts`.
        #[serde(default)]
        since: Option<Timestamp>,
        /// Upper bound on `ts`.
        #[serde(default)]
        until: Option<Timestamp>,
        /// Only records with a larger `seq` (for `cn audit --follow`).
        #[serde(default)]
        after_seq: Option<u64>,
        /// Most records to return: the newest ones, in `seq` order.
        #[serde(default)]
        limit: Option<u32>,
    },
    /// Fetch raw audit segments for `cn audit verify`.
    AuditSegments {
        /// First sequence number wanted.
        from_seq: u64,
    },
    /// Register the caller as a session anchor (`cn session exec`).
    SessionRegister {
        /// Human label for the session.
        #[serde(default)]
        label: Option<String>,
    },
    /// Unseal the store.
    Unlock {
        /// FIDO2 hmac-secret output for client-side unlock, base64url.
        #[serde(default)]
        hmac_output: Option<String>,
    },
}
