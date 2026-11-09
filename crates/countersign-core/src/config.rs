//! `/etc/countersign/config.toml`: parsing, defaults and validation.
//!
//! Every section is optional and has the defaults a fresh install ships: the
//! `polkit` approver for every approval kind. Unknown keys are errors, so a
//! typo cannot silently weaken policy. Phase 1 knows the `polkit` adapter
//! (and `insecure-auto` in builds with the `insecure-test` feature); `fido2`
//! and `command` are refused with a clear message.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use countersign_proto::ApprovalKind;
use serde::Deserialize;
use serde::de::{self, Deserializer};
use sha2::{Digest, Sha256};

use crate::time::{parse_duration, parse_size};

/// The polkit action for `use` requests.
pub const ACTION_USE: &str = "computer.mooselabs.countersign.approve";
/// The polkit action for `reveal` requests.
pub const ACTION_REVEAL: &str = "computer.mooselabs.countersign.reveal";
/// The polkit action for store mutations and export.
pub const ACTION_MUTATE: &str = "computer.mooselabs.countersign.mutate";

/// The most names one request may carry. Config may lower it.
pub const MAX_NAMES_PER_REQUEST: usize = 16;

/// How deep `all_of` / `any_of` may nest.
pub const MAX_CHAIN_DEPTH: usize = 3;

/// A config that could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// Not valid TOML, or a key or value of the wrong shape.
    #[error("{0}")]
    Toml(#[from] toml::de::Error),
    /// Well-formed but not acceptable.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

/// The whole configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Who may connect.
    pub access: Access,
    /// How the store is unsealed.
    pub unlock: Unlock,
    /// How sessions are found.
    pub sessions: Sessions,
    /// Grant lifetimes.
    pub grants: Grants,
    /// Approval chain per kind.
    pub approval: Approval,
    /// Approver instances, by name.
    pub approvers: BTreeMap<String, ApproverConfig>,
    /// `cn list` defaults.
    pub list: List,
    /// `cn hide` settings.
    pub hide: Hide,
    /// Rate and size limits.
    pub limits: Limits,
    /// Audit log settings.
    pub audit: Audit,
    /// Settings that were parsed but have no effect in this version.
    pub warnings: Vec<String>,
}

/// A loaded config and the SHA-256 of the file, for the `config.load` record.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The config.
    pub config: Config,
    /// Lower-case hex SHA-256 of the file bytes.
    pub sha256: String,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_toml("").expect("the built-in defaults are valid")
    }
}

impl Config {
    /// Reads and validates a config file.
    pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
        let bytes = std::fs::read(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| invalid(format!("{} is not UTF-8", path.display())))?;
        let config = Self::from_toml(text)?;
        let sha256 = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Loaded { config, sha256 })
    }

    /// Parses and validates config text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text)?;
        let mut warnings = Vec::new();
        let approvers = match raw.approvers {
            None => default_approvers(),
            Some(tables) => tables
                .into_iter()
                .map(|(name, table)| Ok((name.clone(), ApproverConfig::parse(&name, table)?)))
                .collect::<Result<_, ConfigError>>()?,
        };
        if !raw.standing.is_empty() {
            warnings.push("[[standing]] grants are not in this version; ignored".into());
        }
        let config = Config {
            access: raw.access,
            unlock: raw.unlock.validate()?,
            sessions: raw.sessions.validate()?,
            grants: raw.grants,
            approval: raw.approval.validate()?,
            approvers,
            list: raw.list,
            hide: raw.hide,
            limits: raw.limits,
            audit: raw.audit,
            warnings,
        };
        config.validate()
    }

    fn validate(mut self) -> Result<Self, ConfigError> {
        for name in self.approvers.keys() {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(invalid(format!(
                    "approver name {name:?}: use lower-case letters, digits and '-'"
                )));
            }
        }
        for kind in ApprovalKind::ALL {
            for name in self.approval.chain(kind).names() {
                if !self.approvers.contains_key(name) {
                    return Err(invalid(format!(
                        "[approval] {kind} names approver {name:?}, which no [approvers.{name}] defines"
                    )));
                }
            }
        }
        let g = &self.grants;
        for (key, d) in [
            ("default_ttl", g.default_ttl),
            ("max_ttl", g.max_ttl),
            ("max_reveal_ttl", g.max_reveal_ttl),
            ("pending_expiry", g.pending_expiry),
        ] {
            if d.is_zero() {
                return Err(invalid(format!("[grants] {key} must be longer than 0s")));
            }
        }
        if g.default_ttl > g.max_ttl {
            return Err(invalid("[grants] default_ttl is longer than max_ttl"));
        }
        if g.max_reveal_uses == 0 {
            return Err(invalid("[grants] max_reveal_uses must be at least 1"));
        }
        let l = &self.limits;
        if l.max_names_per_request == 0 || l.max_names_per_request > MAX_NAMES_PER_REQUEST {
            return Err(invalid(format!(
                "[limits] max_names_per_request must be 1 to {MAX_NAMES_PER_REQUEST}"
            )));
        }
        for (key, n) in [
            ("max_pending_requests", l.max_pending_requests),
            (
                "max_pending_requests_per_uid",
                l.max_pending_requests_per_uid,
            ),
            ("max_prompts_per_uid", l.max_prompts_per_uid),
            ("max_names_per_import", l.max_names_per_import),
            ("max_connections_per_uid", l.max_connections_per_uid),
            ("max_sessions_per_uid", l.max_sessions_per_uid),
        ] {
            if n == 0 {
                return Err(invalid(format!("[limits] {key} must be at least 1")));
            }
        }
        if l.idle_timeout.is_zero() {
            return Err(invalid("[limits] idle_timeout must be longer than 0s"));
        }
        if l.approval_failures_per_10m.is_some() {
            self.warnings.push(
                "[limits] approval_failures_per_10m is not in this version: no approver here \
                 can fail verification; ignored"
                    .into(),
            );
        }
        if !self.list.show_usage {
            self.warnings.push(
                "[list] show_usage is not in this version: cn list shows usage only with \
                 --long; ignored"
                    .into(),
            );
        }
        if self.audit.checkpoint_every_records == 0 || self.audit.checkpoint_interval.is_zero() {
            return Err(invalid(
                "[audit] checkpoint_every_records and checkpoint_interval must be positive",
            ));
        }
        if self.audit.retention.is_some() {
            self.warnings
                .push("[audit] retention is not in this version; nothing is pruned".into());
        }
        if self.audit.checkpoint_command.is_some() {
            self.warnings
                .push("[audit] checkpoint_command is not in this version; ignored".into());
        }
        if self.access.users.is_empty() {
            self.warnings
                .push("[access] users is empty: no client may connect".into());
        }
        Ok(self)
    }

    /// The approver chain for a kind.
    pub fn chain(&self, kind: ApprovalKind) -> &Chain {
        self.approval.chain(kind)
    }
}

/// Checks that a config file is owned by root and not writable by group or
/// others. `cnd` refuses a config anyone else could edit (threat model T13).
pub fn check_file_owner(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).map_err(|source| ConfigError::Io {
        path: path.to_owned(),
        source,
    })?;
    if md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(invalid(format!(
            "{} must be owned by root and not writable by group or others",
            path.display()
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    access: Access,
    #[serde(default)]
    unlock: RawUnlock,
    #[serde(default)]
    sessions: RawSessions,
    #[serde(default)]
    grants: Grants,
    #[serde(default)]
    approval: RawApproval,
    approvers: Option<BTreeMap<String, toml::Table>>,
    #[serde(default)]
    list: List,
    #[serde(default)]
    hide: Hide,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    audit: Audit,
    #[serde(default)]
    standing: Vec<toml::Value>,
}

// ---------------------------------------------------------------------------

/// `[access]`: who may connect to the socket.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    /// User names (or numeric uids) allowed on the socket.
    #[serde(default)]
    pub users: Vec<String>,
    /// Whether uid 0 may connect.
    #[serde(default)]
    pub allow_root_clients: bool,
}

impl Access {
    /// Resolves `users` to uids with a passwd-format file (normally
    /// `/etc/passwd`). A numeric entry is taken as a uid. An unknown name is
    /// an error, so a typo does not silently lock the developer out.
    pub fn allowed_uids(&self, passwd: &Path) -> Result<BTreeSet<u32>, ConfigError> {
        let text = std::fs::read_to_string(passwd).map_err(|source| ConfigError::Io {
            path: passwd.to_owned(),
            source,
        })?;
        let table: BTreeMap<&str, u32> = text
            .lines()
            .filter_map(|line| {
                let mut f = line.split(':');
                let name = f.next()?;
                let uid = f.nth(1)?.parse().ok()?;
                Some((name, uid))
            })
            .collect();
        self.users
            .iter()
            .map(|u| {
                u.parse::<u32>()
                    .ok()
                    .or_else(|| table.get(u.as_str()).copied())
                    .ok_or_else(|| invalid(format!("[access] users: no user {u:?}")))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------

/// A store key slot kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// The master key sealed with `systemd-creds`.
    SystemdCreds,
    /// A key derived from the recovery phrase.
    Recovery,
}

/// `[unlock]`: which key slots exist.
#[derive(Debug, Clone)]
pub struct Unlock {
    /// Slots in use. Phase 1: `systemd-creds`, plus `recovery`.
    pub slots: Vec<SlotKind>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnlock {
    #[serde(default = "default_slots")]
    slots: Vec<String>,
    fido2_side: Option<toml::Value>,
}

impl Default for RawUnlock {
    fn default() -> Self {
        Self {
            slots: default_slots(),
            fido2_side: None,
        }
    }
}

fn default_slots() -> Vec<String> {
    vec!["systemd-creds".into(), "recovery".into()]
}

impl RawUnlock {
    fn validate(self) -> Result<Unlock, ConfigError> {
        if self.fido2_side.is_some() {
            return Err(invalid(
                "[unlock] fido2_side: FIDO2 unlock is not in this version (phase 2)",
            ));
        }
        let mut slots = Vec::new();
        for s in &self.slots {
            let slot = match s.as_str() {
                "systemd-creds" => SlotKind::SystemdCreds,
                "recovery" => SlotKind::Recovery,
                "fido2" => {
                    return Err(invalid(
                        "[unlock] slots: \"fido2\" is not in this version (phase 2)",
                    ));
                }
                other => return Err(invalid(format!("[unlock] slots: unknown slot {other:?}"))),
            };
            if !slots.contains(&slot) {
                slots.push(slot);
            }
        }
        if !slots.contains(&SlotKind::SystemdCreds) {
            return Err(invalid(
                "[unlock] slots must include \"systemd-creds\" in this version",
            ));
        }
        Ok(Unlock { slots })
    }
}

// ---------------------------------------------------------------------------

/// A rule that marks a process as a session anchor.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// `/proc/PID/comm` equals this.
    Comm(String),
    /// `/proc/PID/cmdline`, arguments joined by spaces, matches this.
    CmdlineRegex(regex::Regex),
}

impl Matcher {
    /// Whether a process with this `comm` and `cmdline` (NUL-separated, as
    /// in `/proc`) matches.
    pub fn matches(&self, comm: &str, cmdline: &[u8]) -> bool {
        match self {
            Matcher::Comm(c) => c == comm,
            Matcher::CmdlineRegex(re) => {
                let joined: Vec<u8> = cmdline
                    .strip_suffix(b"\0")
                    .unwrap_or(cmdline)
                    .iter()
                    .map(|&b| if b == 0 { b' ' } else { b })
                    .collect();
                re.is_match(&String::from_utf8_lossy(&joined))
            }
        }
    }
}

impl fmt::Display for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Matcher::Comm(c) => write!(f, "comm = {c:?}"),
            Matcher::CmdlineRegex(r) => write!(f, "cmdline_regex = {:?}", r.as_str()),
        }
    }
}

/// `[sessions]`.
#[derive(Debug, Clone)]
pub struct Sessions {
    /// Fallback anchor rules for agents not started with `cn session exec`.
    pub matchers: Vec<Matcher>,
    /// Environment variables recorded as untrusted session labels.
    pub label_env: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSessions {
    #[serde(default = "default_matchers")]
    matchers: Vec<RawMatcher>,
    #[serde(default = "default_label_env")]
    label_env: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMatcher {
    comm: Option<String>,
    cmdline_regex: Option<String>,
}

impl Default for RawSessions {
    fn default() -> Self {
        Self {
            matchers: default_matchers(),
            label_env: default_label_env(),
        }
    }
}

fn default_matchers() -> Vec<RawMatcher> {
    let comm = |c: &str| RawMatcher {
        comm: Some(c.into()),
        cmdline_regex: None,
    };
    vec![
        comm("claude"),
        RawMatcher {
            comm: None,
            cmdline_regex: Some(r"(^|/)codex(\s|$)".into()),
        },
        comm("grok"),
    ]
}

fn default_label_env() -> Vec<String> {
    vec!["CLAUDE_CODE_SESSION_ID".into(), "CODEX_SESSION_ID".into()]
}

impl RawSessions {
    fn validate(self) -> Result<Sessions, ConfigError> {
        let matchers = self
            .matchers
            .into_iter()
            .map(|m| match (m.comm, m.cmdline_regex) {
                (Some(c), None) if !c.is_empty() && c.len() <= 15 => Ok(Matcher::Comm(c)),
                (Some(c), None) => Err(invalid(format!(
                    "[sessions] matcher comm {c:?}: the kernel keeps 1 to 15 bytes of comm"
                ))),
                (None, Some(r)) => regex::Regex::new(&r)
                    .map(Matcher::CmdlineRegex)
                    .map_err(|e| invalid(format!("[sessions] cmdline_regex {r:?}: {e}"))),
                _ => Err(invalid(
                    "[sessions] each matcher has exactly one of comm or cmdline_regex",
                )),
            })
            .collect::<Result<_, _>>()?;
        Ok(Sessions {
            matchers,
            label_env: self.label_env,
        })
    }
}

// ---------------------------------------------------------------------------

/// What to do with a request naming a secret scoped to another project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossProject {
    /// Allow it and say "other project" in the approval display.
    #[default]
    Flag,
    /// Refuse it.
    Deny,
}

/// `[grants]`: lifetimes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    /// TTL of a `use` grant when the request names none.
    #[serde(default = "d_1h", deserialize_with = "de_duration")]
    pub default_ttl: Duration,
    /// Longest `use` grant.
    #[serde(default = "d_8h", deserialize_with = "de_duration")]
    pub max_ttl: Duration,
    /// Longest `reveal` grant.
    #[serde(default = "d_10m", deserialize_with = "de_duration")]
    pub max_reveal_ttl: Duration,
    /// Reveals one `reveal` grant allows.
    #[serde(default = "one")]
    pub max_reveal_uses: u32,
    /// Whether `reveal` requests are accepted at all.
    #[serde(default = "yes")]
    pub allow_reveal: bool,
    /// How long a request may wait for approval.
    #[serde(default = "d_5m", deserialize_with = "de_duration")]
    pub pending_expiry: Duration,
    /// Requests for secrets of another project.
    #[serde(default)]
    pub cross_project: CrossProject,
}

impl Default for Grants {
    fn default() -> Self {
        Self {
            default_ttl: d_1h(),
            max_ttl: d_8h(),
            max_reveal_ttl: d_10m(),
            max_reveal_uses: 1,
            allow_reveal: true,
            pending_expiry: d_5m(),
            cross_project: CrossProject::Flag,
        }
    }
}

// ---------------------------------------------------------------------------

/// An approver chain: one instance, or all / any of nested chains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chain {
    /// An approver instance name.
    One(String),
    /// Every member, in order.
    AllOf(Vec<Chain>),
    /// The first decisive member.
    AnyOf(Vec<Chain>),
}

impl Chain {
    /// Every instance name in the chain, in order, with repeats.
    pub fn names(&self) -> Vec<&str> {
        match self {
            Chain::One(n) => vec![n.as_str()],
            Chain::AllOf(v) | Chain::AnyOf(v) => v.iter().flat_map(Chain::names).collect(),
        }
    }

    fn parse(v: &toml::Value, depth: usize, at: &str) -> Result<Chain, ConfigError> {
        match v {
            toml::Value::String(s) => Ok(Chain::One(s.clone())),
            toml::Value::Table(t) => {
                if depth >= MAX_CHAIN_DEPTH {
                    return Err(invalid(format!(
                        "[approval] {at}: chains nest at most {MAX_CHAIN_DEPTH} levels"
                    )));
                }
                let (key, members) = match (t.len(), t.iter().next()) {
                    (1, Some((k, toml::Value::Array(a)))) => (k.as_str(), a),
                    _ => {
                        return Err(invalid(format!(
                            "[approval] {at}: a table must be {{ all_of = [...] }} or {{ any_of = [...] }}"
                        )));
                    }
                };
                if members.is_empty() {
                    return Err(invalid(format!("[approval] {at}: {key} is empty")));
                }
                let members = members
                    .iter()
                    .map(|m| Chain::parse(m, depth + 1, at))
                    .collect::<Result<Vec<_>, _>>()?;
                match key {
                    "all_of" => Ok(Chain::AllOf(members)),
                    "any_of" => Ok(Chain::AnyOf(members)),
                    other => Err(invalid(format!(
                        "[approval] {at}: unknown combinator {other:?} (all_of or any_of)"
                    ))),
                }
            }
            _ => Err(invalid(format!(
                "[approval] {at}: expected an approver name or a table"
            ))),
        }
    }
}

/// `[approval]`.
#[derive(Debug, Clone)]
pub struct Approval {
    /// Chain for `use`.
    pub use_: Chain,
    /// Chain for `reveal`.
    pub reveal: Chain,
    /// Chain for store mutations.
    pub mutate: Chain,
    /// Chain for export.
    pub export: Chain,
    /// Whether `list`/`show` need a use-level approval once per session.
    pub list_requires_approval: bool,
}

impl Approval {
    /// The chain for a kind.
    pub fn chain(&self, kind: ApprovalKind) -> &Chain {
        match kind {
            ApprovalKind::Use => &self.use_,
            ApprovalKind::Reveal => &self.reveal,
            ApprovalKind::Mutate => &self.mutate,
            ApprovalKind::Export => &self.export,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApproval {
    #[serde(rename = "use")]
    use_: Option<toml::Value>,
    reveal: Option<toml::Value>,
    mutate: Option<toml::Value>,
    export: Option<toml::Value>,
    #[serde(default)]
    list_requires_approval: bool,
}

impl RawApproval {
    fn validate(self) -> Result<Approval, ConfigError> {
        let chain = |v: Option<toml::Value>, at: &str| match v {
            None => Ok(Chain::One("polkit".into())),
            Some(v) => Chain::parse(&v, 0, at),
        };
        Ok(Approval {
            use_: chain(self.use_, "use")?,
            reveal: chain(self.reveal, "reveal")?,
            mutate: chain(self.mutate, "mutate")?,
            export: chain(self.export, "export")?,
            list_requires_approval: self.list_requires_approval,
        })
    }
}

// ---------------------------------------------------------------------------

/// One `[approvers.NAME]` instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverConfig {
    /// A polkit dialog raised by `cnd`.
    Polkit(PolkitConfig),
    /// Decides on its own after a delay. Test builds only.
    #[cfg(feature = "insecure-test")]
    InsecureAuto(InsecureAutoConfig),
}

impl ApproverConfig {
    /// The adapter name, as in `type = "..."`.
    pub fn adapter(&self) -> &'static str {
        match self {
            ApproverConfig::Polkit(_) => "polkit",
            #[cfg(feature = "insecure-test")]
            ApproverConfig::InsecureAuto(_) => "insecure-auto",
        }
    }

    fn parse(name: &str, mut table: toml::Table) -> Result<Self, ConfigError> {
        let at = format!("[approvers.{name}]");
        let ty = match table.remove("type") {
            Some(toml::Value::String(s)) => s,
            Some(_) => return Err(invalid(format!("{at} type must be a string"))),
            None => return Err(invalid(format!("{at} needs type = \"polkit\""))),
        };
        let wrap = |e: toml::de::Error| invalid(format!("{at} {}", e.message()));
        match ty.as_str() {
            "polkit" => Ok(ApproverConfig::Polkit(
                PolkitConfig::deserialize(table).map_err(wrap)?,
            )),
            "fido2" | "command" => Err(invalid(format!(
                "{at} type = {ty:?} is not in this version (phase 2); use \"polkit\""
            ))),
            #[cfg(feature = "insecure-test")]
            "insecure-auto" => Ok(ApproverConfig::InsecureAuto(
                InsecureAutoConfig::deserialize(table).map_err(wrap)?,
            )),
            #[cfg(not(feature = "insecure-test"))]
            "insecure-auto" => Err(invalid(format!(
                "{at} type = \"insecure-auto\" exists only in test builds"
            ))),
            other => Err(invalid(format!("{at} unknown approver type {other:?}"))),
        }
    }
}

fn default_approvers() -> BTreeMap<String, ApproverConfig> {
    BTreeMap::from([(
        "polkit".to_owned(),
        ApproverConfig::Polkit(PolkitConfig::default()),
    )])
}

/// The polkit subject `cnd` asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolkitSubject {
    /// `unix-process` for the session anchor (pid, start time, uid). The
    /// default, because a `unix-session` subject aborts polkitd
    /// (polkit-org/polkit#699).
    #[default]
    Process,
    /// `unix-session` for the developer's graphical logind session.
    Session,
}

/// What a dismissed polkit dialog means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDismiss {
    /// The request is denied.
    #[default]
    Deny,
    /// No answer; another `any_of` member may decide.
    Ignore,
}

/// `[approvers.NAME] type = "polkit"`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolkitConfig {
    /// Action for `use`.
    #[serde(default = "action_use")]
    pub action_use: String,
    /// Action for `reveal`.
    #[serde(default = "action_reveal")]
    pub action_reveal: String,
    /// Action for mutations and export.
    #[serde(default = "action_mutate")]
    pub action_mutate: String,
    /// Which subject polkitd is asked about.
    #[serde(default)]
    pub subject: PolkitSubject,
    /// Refuse to ask unless the graphical session is Wayland.
    #[serde(default = "yes")]
    pub require_wayland: bool,
    /// What a dismissed dialog means.
    #[serde(default)]
    pub on_dismiss: OnDismiss,
    /// Longest a dialog may stay open. Unset (the default), a dialog stays
    /// until the request's `pending_expiry`; set, the request lapses at
    /// whichever comes first.
    #[serde(default, deserialize_with = "de_opt_duration")]
    pub timeout: Option<Duration>,
}

impl Default for PolkitConfig {
    fn default() -> Self {
        Self {
            action_use: action_use(),
            action_reveal: action_reveal(),
            action_mutate: action_mutate(),
            subject: PolkitSubject::Process,
            require_wayland: true,
            on_dismiss: OnDismiss::Deny,
            timeout: None,
        }
    }
}

impl PolkitConfig {
    /// The action id for a kind.
    pub fn action(&self, kind: ApprovalKind) -> &str {
        match kind {
            ApprovalKind::Use => &self.action_use,
            ApprovalKind::Reveal => &self.action_reveal,
            ApprovalKind::Mutate | ApprovalKind::Export => &self.action_mutate,
        }
    }
}

/// The decision an `insecure-auto` approver gives.
#[cfg(feature = "insecure-test")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoDecision {
    /// Approve.
    #[default]
    Approve,
    /// Deny.
    Deny,
    /// Give no decision (`approver_unavailable`), to test `any_of`.
    Unavailable,
}

/// `[approvers.NAME] type = "insecure-auto"`. Test builds only.
#[cfg(feature = "insecure-test")]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsecureAutoConfig {
    /// What it answers.
    #[serde(default)]
    pub decision: AutoDecision,
    /// How long it waits before answering.
    #[serde(default, deserialize_with = "de_duration")]
    pub delay: Duration,
}

// ---------------------------------------------------------------------------

/// Default scope of `cn list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListScope {
    /// Secrets matching the session's cwd, plus unscoped ones.
    #[default]
    Project,
    /// Every secret.
    All,
}

/// `[list]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct List {
    /// Default scope.
    #[serde(default)]
    pub default_scope: ListScope,
    /// Whether `cn list` shows usage prose.
    #[serde(default = "yes")]
    pub show_usage: bool,
}

impl Default for List {
    fn default() -> Self {
        Self {
            default_scope: ListScope::Project,
            show_usage: true,
        }
    }
}

/// Which secrets `cn hide` matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HideInclude {
    /// Secrets granted to the calling session.
    Granted,
    /// Secrets marked `high_entropy`.
    HighEntropy,
}

/// `[hide]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hide {
    /// Pattern set.
    #[serde(default = "default_include")]
    pub include: Vec<HideInclude>,
    /// Shortest value that becomes a pattern.
    #[serde(default = "eight")]
    pub min_value_len: usize,
    /// New hide streams per session per minute.
    #[serde(default = "thirty")]
    pub max_streams_per_minute: u32,
    /// Bytes per session per minute.
    #[serde(default = "mib_256", deserialize_with = "de_size")]
    pub max_bytes_per_minute: u64,
    /// New hide streams per uid per minute, over all its sessions.
    #[serde(default = "one_twenty")]
    pub max_streams_per_minute_per_uid: u32,
    /// Bytes per uid per minute, over all its sessions.
    #[serde(default = "gib_1", deserialize_with = "de_size")]
    pub max_bytes_per_minute_per_uid: u64,
}

impl Default for Hide {
    fn default() -> Self {
        Self {
            include: default_include(),
            min_value_len: 8,
            max_streams_per_minute: 30,
            max_bytes_per_minute: mib_256(),
            max_streams_per_minute_per_uid: one_twenty(),
            max_bytes_per_minute_per_uid: gib_1(),
        }
    }
}

fn default_include() -> Vec<HideInclude> {
    vec![HideInclude::Granted, HideInclude::HighEntropy]
}

/// `[limits]`. Each per-session limit has a per-uid one beside it, so a
/// client cannot escape a limit by opening new sessions; the per-uid
/// defaults leave room for several agent sessions working at once.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Pending requests a session may have at once.
    #[serde(default = "three")]
    pub max_pending_requests: usize,
    /// Pending requests a uid may have at once, over all its sessions.
    #[serde(default = "ten")]
    pub max_pending_requests_per_uid: usize,
    /// Requests a session may create per hour.
    #[serde(default = "thirty")]
    pub requests_per_hour: u32,
    /// Requests a uid may create per hour, over all its sessions.
    #[serde(default = "one_twenty")]
    pub requests_per_hour_per_uid: u32,
    /// Dialogs open at once for one uid. Further requests wait, in order;
    /// their expiry still counts from creation.
    #[serde(default = "two")]
    pub max_prompts_per_uid: usize,
    /// After a deny, new requests from the same uid for the same secrets
    /// are refused this long, in every session.
    #[serde(default = "d_2m", deserialize_with = "de_duration")]
    pub deny_cooldown: Duration,
    /// Failed approval verifications per 10 minutes before a cooldown. Not
    /// in this version: no Phase 1 approver can fail verification.
    #[serde(default)]
    pub approval_failures_per_10m: Option<u32>,
    /// `list` calls per session per minute.
    #[serde(default = "sixty")]
    pub list_calls_per_minute: u32,
    /// `list` calls per uid per minute.
    #[serde(default = "two_forty")]
    pub list_calls_per_minute_per_uid: u32,
    /// Names per request, at most 16.
    #[serde(default = "sixteen")]
    pub max_names_per_request: usize,
    /// Secrets per `cn import` request.
    #[serde(default = "twenty")]
    pub max_names_per_import: usize,
    /// Open connections per uid.
    #[serde(default = "one_twenty_eight")]
    pub max_connections_per_uid: usize,
    /// Live sessions per uid (each holds a pidfd for its anchor).
    #[serde(default = "one_twenty_eight")]
    pub max_sessions_per_uid: usize,
    /// A connection that sends nothing this long is closed, unless it is
    /// waiting on a `cn run` child or streaming `cn hide`.
    #[serde(default = "d_10m", deserialize_with = "de_duration")]
    pub idle_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pending_requests: 3,
            max_pending_requests_per_uid: ten(),
            requests_per_hour: 30,
            requests_per_hour_per_uid: one_twenty(),
            max_prompts_per_uid: two(),
            deny_cooldown: d_2m(),
            approval_failures_per_10m: None,
            list_calls_per_minute: 60,
            list_calls_per_minute_per_uid: two_forty(),
            max_names_per_request: MAX_NAMES_PER_REQUEST,
            max_names_per_import: twenty(),
            max_connections_per_uid: one_twenty_eight(),
            max_sessions_per_uid: one_twenty_eight(),
            idle_timeout: d_10m(),
        }
    }
}

/// How much a journald sink receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkLevel {
    /// Every record.
    #[default]
    Full,
    /// Checkpoints and approvals only.
    Checkpoints,
}

/// An extra copy of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Sink {
    /// journald, native protocol.
    Journald {
        /// What it receives.
        #[serde(default)]
        level: SinkLevel,
    },
    /// Another file.
    File {
        /// Where.
        path: PathBuf,
    },
}

/// `[audit]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    /// Segment directory. Default: `audit/` in the state directory.
    pub dir: Option<PathBuf>,
    /// Write a checkpoint at least this often when records were written.
    #[serde(default = "d_1h", deserialize_with = "de_duration")]
    pub checkpoint_interval: Duration,
    /// Write a checkpoint after this many records.
    #[serde(default = "thousand")]
    pub checkpoint_every_records: u64,
    /// `list` coalescing window.
    #[serde(default = "d_10m", deserialize_with = "de_duration")]
    pub list_coalesce: Duration,
    /// Pass agent-supplied text through redaction before writing it.
    #[serde(default = "yes")]
    pub redact_agent_text: bool,
    /// Delete covered closed segments older than this. Not in Phase 1.
    #[serde(default, deserialize_with = "de_opt_duration")]
    pub retention: Option<Duration>,
    /// Command fed each checkpoint line. Not in Phase 1.
    pub checkpoint_command: Option<Vec<String>>,
    /// Extra copies.
    #[serde(default)]
    pub sink: Vec<Sink>,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            dir: None,
            checkpoint_interval: d_1h(),
            checkpoint_every_records: 1000,
            list_coalesce: d_10m(),
            redact_agent_text: true,
            retention: None,
            checkpoint_command: None,
            sink: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------

fn de_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    parse_duration(&s).map_err(de::Error::custom)
}

fn de_opt_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    de_duration(d).map(Some)
}

fn de_size<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Size {
        N(u64),
        S(String),
    }
    match Size::deserialize(d)? {
        Size::N(n) => Ok(n),
        Size::S(s) => parse_size(&s).map_err(de::Error::custom),
    }
}

fn action_use() -> String {
    ACTION_USE.into()
}
fn action_reveal() -> String {
    ACTION_REVEAL.into()
}
fn action_mutate() -> String {
    ACTION_MUTATE.into()
}
fn d_2m() -> Duration {
    Duration::from_secs(120)
}
fn d_5m() -> Duration {
    Duration::from_secs(300)
}
fn d_10m() -> Duration {
    Duration::from_secs(600)
}
fn d_1h() -> Duration {
    Duration::from_secs(3600)
}
fn d_8h() -> Duration {
    Duration::from_secs(8 * 3600)
}
fn yes() -> bool {
    true
}
fn one() -> u32 {
    1
}
fn three() -> usize {
    3
}
fn eight() -> usize {
    8
}
fn sixteen() -> usize {
    MAX_NAMES_PER_REQUEST
}
fn thirty() -> u32 {
    30
}
fn sixty() -> u32 {
    60
}
fn two() -> usize {
    2
}
fn ten() -> usize {
    10
}
fn twenty() -> usize {
    20
}
fn one_twenty() -> u32 {
    120
}
fn one_twenty_eight() -> usize {
    128
}
fn two_forty() -> u32 {
    240
}
fn gib_1() -> u64 {
    1 << 30
}
fn thousand() -> u64 {
    1000
}
fn mib_256() -> u64 {
    256 << 20
}

#[cfg(test)]
mod tests {
    use super::*;

    fn polkit(a: &ApproverConfig) -> &PolkitConfig {
        match a {
            ApproverConfig::Polkit(p) => p,
            #[cfg(feature = "insecure-test")]
            _ => panic!("not polkit"),
        }
    }

    fn err(text: &str) -> String {
        Config::from_toml(text).unwrap_err().to_string()
    }

    #[test]
    fn per_uid_limits_have_defaults_and_bounds() {
        let c = Config::default();
        let l = &c.limits;
        assert_eq!(l.max_pending_requests_per_uid, 10);
        assert_eq!(l.requests_per_hour_per_uid, 120);
        assert_eq!(l.max_prompts_per_uid, 2);
        assert_eq!(l.max_names_per_import, 20);
        assert_eq!(l.max_connections_per_uid, 128);
        assert_eq!(l.max_sessions_per_uid, 128);
        assert_eq!(l.idle_timeout, Duration::from_secs(600));
        assert_eq!(c.hide.max_bytes_per_minute_per_uid, 1 << 30);
        let c = Config::from_toml(
            "[limits]\nmax_prompts_per_uid = 1\nidle_timeout = \"1m\"\n\
             [hide]\nmax_bytes_per_minute_per_uid = \"2GiB\"",
        )
        .unwrap();
        assert_eq!(c.limits.max_prompts_per_uid, 1);
        assert_eq!(c.limits.idle_timeout, Duration::from_secs(60));
        assert_eq!(c.hide.max_bytes_per_minute_per_uid, 2 << 30);
        assert!(err("[limits]\nmax_prompts_per_uid = 0").contains("at least 1"));
        assert!(err("[limits]\nmax_connections_per_uid = 0").contains("at least 1"));
    }

    #[test]
    fn settings_not_in_this_version_warn() {
        let quiet = Config::default();
        assert!(
            !quiet
                .warnings
                .iter()
                .any(|w| w.contains("not in this version"))
        );
        let c = Config::from_toml(
            "[limits]\napproval_failures_per_10m = 5\n[list]\nshow_usage = false",
        )
        .unwrap();
        assert!(
            c.warnings
                .iter()
                .any(|w| w.contains("approval_failures_per_10m"))
        );
        assert!(c.warnings.iter().any(|w| w.contains("show_usage")));
        // expect_pam_u2f is gone.
        assert!(
            err("[approvers.polkit]\ntype = \"polkit\"\nexpect_pam_u2f = true")
                .contains("expect_pam_u2f")
        );
        // The polkit timeout is unset unless given.
        assert_eq!(polkit(&Config::default().approvers["polkit"]).timeout, None);
    }

    #[test]
    fn empty_file_is_the_phase1_default() {
        let c = Config::default();
        for kind in ApprovalKind::ALL {
            assert_eq!(c.chain(kind), &Chain::One("polkit".into()));
        }
        assert_eq!(
            c.approvers["polkit"],
            ApproverConfig::Polkit(PolkitConfig::default())
        );
        let p = polkit(&c.approvers["polkit"]);
        assert_eq!(p.subject, PolkitSubject::Process);
        assert_eq!(p.action(ApprovalKind::Export), ACTION_MUTATE);
        assert_eq!(c.unlock.slots, [SlotKind::SystemdCreds, SlotKind::Recovery]);
        assert_eq!(c.grants.max_ttl, Duration::from_secs(8 * 3600));
        assert_eq!(c.limits.max_names_per_request, 16);
        assert_eq!(c.sessions.matchers.len(), 3);
        assert_eq!(
            c.warnings,
            ["[access] users is empty: no client may connect"]
        );
    }

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../examples/config.toml");
        let c = Config::from_toml(text).unwrap();
        assert_eq!(c.access.users, ["patrick"]);
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        assert_eq!(c.approvers.len(), 1);
    }

    #[test]
    fn chains_parse_and_nest() {
        let c = Config::from_toml(
            r#"
            [approval]
            use = "a"
            reveal = { all_of = ["a", { any_of = ["b", "a"] }] }
            [approvers.a]
            type = "polkit"
            [approvers.b]
            type = "polkit"
            subject = "session"
            on_dismiss = "ignore"
            timeout = "90s"
            "#,
        );
        let err_text = c
            .as_ref()
            .map(|_| String::new())
            .unwrap_or_else(|e| e.to_string());
        // mutate and export default to "polkit", which this file does not define.
        assert!(
            err_text.contains("mutate names approver \"polkit\""),
            "{err_text}"
        );

        let c = Config::from_toml(
            r#"
            [approval]
            use = "a"
            reveal = { all_of = ["a", { any_of = ["b", "a"] }] }
            mutate = "a"
            export = "a"
            [approvers.a]
            type = "polkit"
            [approvers.b]
            type = "polkit"
            subject = "session"
            on_dismiss = "ignore"
            timeout = "90s"
            "#,
        )
        .unwrap();
        assert_eq!(
            c.chain(ApprovalKind::Reveal),
            &Chain::AllOf(vec![
                Chain::One("a".into()),
                Chain::AnyOf(vec![Chain::One("b".into()), Chain::One("a".into())])
            ])
        );
        assert_eq!(c.chain(ApprovalKind::Reveal).names(), ["a", "b", "a"]);
        let b = polkit(&c.approvers["b"]);
        assert_eq!(b.subject, PolkitSubject::Session);
        assert_eq!(b.on_dismiss, OnDismiss::Ignore);
        assert_eq!(b.timeout, Some(Duration::from_secs(90)));
    }

    #[test]
    fn bad_chains_are_refused() {
        assert!(err("[approval]\nuse = \"nobody\"").contains("no [approvers.nobody]"));
        assert!(err("[approval]\nuse = { one_of = [\"polkit\"] }").contains("unknown combinator"));
        assert!(err("[approval]\nuse = { all_of = [] }").contains("empty"));
        assert!(err("[approval]\nuse = 3").contains("approver name or a table"));
        let deep = "[approval]\nuse = { all_of = [{ all_of = [{ all_of = [{ all_of = [\"polkit\"] }] }] }] }";
        assert!(err(deep).contains("nest at most 3"));
        let ok = "[approval]\nuse = { all_of = [{ all_of = [{ all_of = [\"polkit\"] }] }] }";
        assert!(Config::from_toml(ok).is_ok());
    }

    #[test]
    fn phase2_adapters_are_refused_clearly() {
        let e = err("[approvers.desk-key]\ntype = \"fido2\"\ncredential = \"desk-key\"");
        assert!(e.contains("not in this version"), "{e}");
        let e = err("[approvers.phone]\ntype = \"command\"\nargv = [\"/bin/true\"]");
        assert!(e.contains("not in this version"), "{e}");
        assert!(err("[unlock]\nslots = [\"fido2\"]").contains("not in this version"));
        assert!(err("[unlock]\nfido2_side = \"client\"").contains("not in this version"));
        assert!(err("[unlock]\nslots = [\"recovery\"]").contains("systemd-creds"));
        assert!(err("[approvers.x]\ntype = \"magic\"").contains("unknown approver type"));
        assert!(err("[approvers.x]\nsubject = \"process\"").contains("needs type"));
    }

    #[cfg(not(feature = "insecure-test"))]
    #[test]
    fn insecure_auto_needs_the_test_feature() {
        assert!(err("[approvers.x]\ntype = \"insecure-auto\"").contains("only in test builds"));
    }

    #[cfg(feature = "insecure-test")]
    #[test]
    fn insecure_auto_parses_in_test_builds() {
        let c = Config::from_toml(
            "[approvers.polkit]\ntype = \"insecure-auto\"\ndecision = \"deny\"\ndelay = \"2s\"",
        )
        .unwrap();
        assert_eq!(
            c.approvers["polkit"],
            ApproverConfig::InsecureAuto(InsecureAutoConfig {
                decision: AutoDecision::Deny,
                delay: Duration::from_secs(2),
            })
        );
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        assert!(err("[grants]\nmax_tll = \"8h\"").contains("max_tll"));
        assert!(
            err("[approvers.polkit]\ntype = \"polkit\"\nsubjekt = \"session\"").contains("subjekt")
        );
        assert!(err("[grants]\nmax_ttl = \"eight hours\"").contains("not a valid duration"));
        assert!(err("[grants]\ndefault_ttl = \"9h\"").contains("longer than max_ttl"));
        assert!(err("[grants]\npending_expiry = \"0s\"").contains("longer than 0s"));
        assert!(err("[limits]\nmax_names_per_request = 17").contains("1 to 16"));
        assert!(
            err("[sessions]\nmatchers = [{ comm = \"a\", cmdline_regex = \"b\" }]")
                .contains("exactly one")
        );
        assert!(
            err("[sessions]\nmatchers = [{ cmdline_regex = \"(\" }]").contains("cmdline_regex")
        );
        assert!(err("[approvers.Bad]\ntype = \"polkit\"").contains("lower-case"));
        assert!(err("[nonsense]\n").contains("nonsense"));
    }

    #[test]
    fn standing_grants_are_ignored_with_a_warning() {
        let c = Config::from_toml(
            "[access]\nusers=[\"1000\"]\n[[standing]]\nid = \"x\"\nsecrets = [\"a\"]",
        )
        .unwrap();
        assert_eq!(c.warnings.len(), 1);
        assert!(c.warnings[0].contains("standing"));
    }

    #[test]
    fn matchers_match_comm_and_cmdline() {
        let c = Config::default();
        let m = &c.sessions.matchers;
        assert!(m[0].matches("claude", b"claude\0--resume\0"));
        assert!(!m[0].matches("claude-x", b""));
        assert!(m[1].matches("node", b"/usr/bin/codex\0exec\0"));
        assert!(m[1].matches("node", b"codex\0"));
        assert!(!m[1].matches("node", b"/usr/bin/codexx\0"));
        assert_eq!(m[1].to_string(), r#"cmdline_regex = "(^|/)codex(\\s|$)""#);
    }

    #[test]
    fn users_resolve_through_passwd() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0:root:/root:/bin/bash\npatrick:x:1000:1000::/home/patrick:/usr/bin/fish\n",
        )
        .unwrap();
        let access = Access {
            users: vec!["patrick".into(), "1001".into()],
            allow_root_clients: false,
        };
        assert_eq!(
            access.allowed_uids(&passwd).unwrap(),
            BTreeSet::from([1000, 1001])
        );
        let access = Access {
            users: vec!["nobody-here".into()],
            allow_root_clients: false,
        };
        assert!(access.allowed_uids(&passwd).is_err());
    }

    #[test]
    fn load_hashes_the_file_and_checks_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(
            loaded.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // A temp file is owned by the test user, not root.
        assert!(check_file_owner(&path).is_err());
    }
}
