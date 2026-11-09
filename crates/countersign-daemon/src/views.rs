//! What clients see: grants, sessions and secrets as protocol views, the
//! approvers of a chain, project matching, and the `hide` pattern set
//! (design.md section 8), which also redacts agent-supplied text.

use std::collections::BTreeMap;
use std::path::Path;

use countersign_core::config::{Chain, HideInclude};
use countersign_core::grants::Grant;
use countersign_core::sessions::{AnchorKind, ProcInfo, Session};
use countersign_core::store::SecretInfo;
use countersign_hide::{Builder, Redactor, Secret};
use countersign_proto::{
    Anchor, ApproverView, ChainEntry, Driven, ErrorBody, ErrorCode, GrantView, Mode, SecretView,
    SessionView, Timestamp, default_env,
};

use crate::daemon::{GrantInfo, SessionEntry, State, err, internal};
use crate::log::error;
use crate::setup::Runtime;

/// The protocol view of a grant.
pub fn grant_view(g: &Grant, info: Option<&GrantInfo>) -> GrantView {
    GrantView {
        id: g.id.clone(),
        secrets: g.names.clone(),
        mode: g.mode,
        expires_at: Timestamp::from_system_time(g.expires_at),
        approved_by: info.map(|i| i.approved_by.clone()).unwrap_or_default(),
        uses: info.map_or(0, |i| i.uses),
        reveals_left: g.uses_left,
        session: g.session.clone(),
    }
}

/// A live grant of the session, in `mode`, covering every name.
pub fn covering_grant(
    st: &State,
    session: &str,
    names: &[String],
    mode: Mode,
) -> Option<GrantView> {
    st.grants
        .grants_for(session)
        .into_iter()
        .filter(|g| g.mode == mode && g.uses_left != Some(0))
        .find(|g| names.iter().all(|n| g.names.contains(n)))
        .map(|g| grant_view(g, st.grant_info.get(&g.id)))
}

/// The session's best grant for one secret: the widest mode (reveal),
/// then the latest expiry.
pub fn best_grant(st: &State, session: &str, name: &str) -> Option<GrantView> {
    st.grants
        .grants_for(session)
        .into_iter()
        .filter(|g| g.names.iter().any(|n| n == name) && g.uses_left != Some(0))
        .max_by_key(|g| (g.mode == Mode::Reveal, g.expires_at))
        .map(|g| grant_view(g, st.grant_info.get(&g.id)))
}

/// What `hello`, `session` and `session_register` report. `s` is the
/// session as this connection's discovery found it, so the anchor's `comm`
/// is current (a registered anchor changes it when it `exec`s the agent).
pub fn session_view(
    entry: &SessionEntry,
    s: &Session,
    chain: &[ProcInfo],
    labels: &BTreeMap<String, String>,
    cwd: Option<&str>,
    active_grants: usize,
) -> SessionView {
    SessionView {
        id: s.id.clone(),
        anchor: Anchor {
            pid: s.anchor.pid,
            starttime: s.anchor.start_time,
            comm: s.anchor.comm.clone(),
            registered: s.registered(),
        },
        started_at: entry.started_at,
        label: match &s.kind {
            AnchorKind::Registered { label } => label.clone(),
            _ => None,
        },
        chain: chain
            .iter()
            .map(|p| ChainEntry {
                pid: p.pid,
                comm: p.comm.clone(),
                starttime: p.start_time,
            })
            .collect(),
        labels: labels.clone(),
        cwd: cwd.map(str::to_owned),
        alive: true,
        active_grants: u32::try_from(active_grants).unwrap_or(u32::MAX),
    }
}

/// One secret as `list` shows it.
pub fn secret_view(
    st: &State,
    info: &SecretInfo,
    session: Option<&str>,
    in_project: bool,
) -> SecretView {
    let name = &info.meta.name;
    SecretView {
        meta: info.meta.clone(),
        in_project,
        default_env: default_env(name),
        grant: session.and_then(|s| best_grant(st, s, name)),
        created: Some(Timestamp::from_system_time(info.created)),
        updated: Some(Timestamp::from_system_time(info.updated)),
        rotated: Some(Timestamp::from_system_time(info.rotated)),
        last_use: st.last_use.get(name).cloned(),
    }
}

/// The approver instances of a chain, each once. Daemon-driven members
/// that start as soon as the request exists are marked prompted: every
/// member of an `any_of`, the first of an `all_of`.
pub fn approver_views(rt: &Runtime, chain: &Chain) -> Vec<ApproverView> {
    fn first_wave<'a>(c: &'a Chain, out: &mut Vec<&'a str>) {
        match c {
            Chain::One(n) => out.push(n),
            Chain::AllOf(v) => {
                if let Some(first) = v.first() {
                    first_wave(first, out);
                }
            }
            Chain::AnyOf(v) => v.iter().for_each(|m| first_wave(m, out)),
        }
    }
    let mut prompted = Vec::new();
    first_wave(chain, &mut prompted);
    let mut out: Vec<ApproverView> = Vec::new();
    for name in chain.names() {
        if out.iter().any(|a| a.name == name) {
            continue;
        }
        out.push(ApproverView {
            name: name.to_owned(),
            adapter: rt
                .config
                .approvers
                .get(name)
                .map_or("unknown", |a| a.adapter())
                .to_owned(),
            driven: Driven::Daemon,
            prompted: prompted.contains(&name),
        });
    }
    out
}

/// Whether a secret's `projects` globs cover the client's working
/// directory (or one of its parents). No globs, or no reported cwd, counts
/// as in the project. `~` is the peer user's home. Organizational only:
/// the cwd is the client's claim.
pub fn in_project(projects: &[String], cwd: Option<&str>, home: Option<&Path>) -> bool {
    let Some(cwd) = cwd else { return true };
    if projects.is_empty() {
        return true;
    }
    projects.iter().any(|p| {
        let expanded = match (p.strip_prefix("~/"), home) {
            (Some(rest), Some(h)) => h.join(rest).to_string_lossy().into_owned(),
            _ => p.clone(),
        };
        let Ok(pattern) = glob::Pattern::new(expanded.trim_end_matches('/')) else {
            return false;
        };
        Path::new(cwd).ancestors().any(|a| pattern.matches_path(a))
    })
}

/// At most `max` bytes of `s`, cut at a character boundary.
pub fn truncate_utf8(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// The redaction engine for a session (design.md section 8): secrets it
/// holds a grant for, secrets marked `high_entropy`, and `extra` named
/// secrets, which must be granted. A low-entropy secret that is not granted
/// is never a pattern, so `hide` is not a guessing oracle for it.
pub fn hide_redactor(
    st: &State,
    rt: &Runtime,
    session: &str,
    extra: &[String],
) -> Result<Redactor, ErrorBody> {
    let granted = st.grants.granted_names(session);
    let not_granted: Vec<String> = extra
        .iter()
        .filter(|n| !granted.contains(n))
        .cloned()
        .collect();
    if !not_granted.is_empty() {
        return Err(ErrorBody {
            code: ErrorCode::GrantRequired,
            message: format!("hide --secret needs a grant for {}", not_granted.join(", ")),
            detail: serde_json::json!({ "names": not_granted }),
        });
    }
    let include = &rt.config.hide.include;
    let mut names: Vec<String> = extra.to_vec();
    if include.contains(&HideInclude::Granted) {
        names.extend(granted);
    }
    if include.contains(&HideInclude::HighEntropy) {
        names.extend(
            st.store
                .list()
                .filter(|i| i.meta.high_entropy)
                .map(|i| i.meta.name.clone()),
        );
    }
    names.sort();
    names.dedup();
    let mut values = Vec::with_capacity(names.len());
    for n in &names {
        match st.store.value(n) {
            Ok(v) => values.push((n.as_str(), v)),
            Err(e) => {
                error!("hide: opening {n}: {e}");
                return Err(internal("the store could not be read"));
            }
        }
    }
    Builder::default()
        .min_len(rt.config.hide.min_value_len)
        .build(values.iter().map(|(name, v)| Secret {
            name,
            value: v.as_bytes(),
        }))
        .map_err(|e| {
            error!("hide: building the redaction engine: {e}");
            internal("the redaction engine could not be built")
        })
}

/// Redacts client-supplied text with a session's hide set, when
/// `[audit] redact_agent_text` is on, so a value pasted into it reaches
/// neither a dialog nor the audit log. Built once for several texts.
pub enum TextRedactor {
    /// `redact_agent_text = false`.
    Off,
    /// The session's hide set.
    On(Redactor),
    /// The hide set could not be built: texts are withheld, not passed.
    Failed,
}

impl TextRedactor {
    /// For `session` (`""` for none: only `high_entropy` secrets match).
    pub fn new(st: &State, rt: &Runtime, session: &str) -> Self {
        if !rt.config.audit.redact_agent_text {
            return Self::Off;
        }
        match hide_redactor(st, rt, session, &[]) {
            Ok(r) => Self::On(r),
            Err(_) => Self::Failed,
        }
    }

    /// `text` with values replaced; `what` names it in the withheld text.
    pub fn apply(&self, text: &str, what: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        match self {
            Self::Off => text.to_owned(),
            Self::On(r) => String::from_utf8_lossy(&r.redact(text.as_bytes()).0).into_owned(),
            Self::Failed => format!("[{what} withheld: it could not be checked for secret values]"),
        }
    }
}

/// A request reason, redacted ([`TextRedactor`]).
pub fn redact_text(st: &State, rt: &Runtime, session: &str, text: &str) -> String {
    TextRedactor::new(st, rt, session).apply(text, "reason")
}

/// A session label, redacted ([`TextRedactor`]).
pub fn redact_label(st: &State, rt: &Runtime, session: &str, text: &str) -> String {
    TextRedactor::new(st, rt, session).apply(text, "label")
}

/// `text` redacted with the hide set of each of `sessions` in turn, for a
/// text more than one session may have seen values of. `what` names it in
/// the withheld text.
pub fn redact_for_sessions(
    st: &State,
    rt: &Runtime,
    sessions: &[&str],
    text: &str,
    what: &str,
) -> String {
    sessions.iter().fold(text.to_owned(), |t, s| {
        TextRedactor::new(st, rt, s).apply(&t, what)
    })
}

/// Every label value, redacted ([`TextRedactor`]).
pub fn redact_labels(
    st: &State,
    rt: &Runtime,
    session: &str,
    labels: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    if labels.is_empty() {
        return BTreeMap::new();
    }
    let r = TextRedactor::new(st, rt, session);
    labels
        .iter()
        .map(|(k, v)| (k.clone(), r.apply(v, "label")))
        .collect()
}

/// `no_session`, for a request that needs an agent session.
pub fn no_session() -> ErrorBody {
    err(
        ErrorCode::NoSession,
        "no session anchor for this process; start the agent with cn session exec",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_match_the_cwd_or_a_parent() {
        let home = Path::new("/home/dev");
        let p = vec!["~/projects/x".to_owned()];
        assert!(in_project(&p, Some("/home/dev/projects/x"), Some(home)));
        assert!(in_project(&p, Some("/home/dev/projects/x/sub"), Some(home)));
        assert!(!in_project(&p, Some("/home/dev/projects/y"), Some(home)));
        let p = vec!["/srv/*/app".to_owned()];
        assert!(in_project(&p, Some("/srv/a/app/src"), None));
        assert!(in_project(&[], Some("/anywhere"), None));
        assert!(in_project(&p, None, None));
    }

    #[test]
    fn truncation_keeps_characters_whole() {
        assert_eq!(truncate_utf8("héllo", 2), "h");
        assert_eq!(truncate_utf8("abc", 10), "abc");
    }
}
