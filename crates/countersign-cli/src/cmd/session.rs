//! `cn session` and `cn session exec`.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;

use countersign_proto::{Request, Response, SessionView};
use serde_json::json;

use crate::client::{Client, unexpected};
use crate::cmd::run::{EXIT_CANNOT_EXECUTE, EXIT_NOT_FOUND};
use crate::env::stripped_env;
use crate::error::CnError;
use crate::output::{Ctx, Done, clean_line, quoted_line};

/// The text `cn session` prints.
pub fn describe(s: &SessionView) -> String {
    let how = if s.anchor.registered {
        match &s.label {
            Some(l) => format!("registered by cn session exec, label {}", quoted_line(l)),
            None => "registered by cn session exec".into(),
        }
    } else {
        "found by a matcher".into()
    };
    let chain = s
        .chain
        .iter()
        .map(|c| format!("{} {}", c.pid, clean_line(&c.comm)))
        .collect::<Vec<_>>()
        .join(" <- ");
    let labels = if s.labels.is_empty() {
        "none".into()
    } else {
        format!(
            "{} (untrusted)",
            s.labels
                .iter()
                .map(|(k, v)| format!("{}={}", clean_line(k), clean_line(v)))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let mut out = String::new();
    let mut line = |k: &str, v: String| out.push_str(&format!("{k:<10}{v}\n"));
    line("session", format!("{}  ({how})", clean_line(&s.id)));
    line(
        "anchor",
        format!(
            "pid {}  comm {}  started {}{}",
            s.anchor.pid,
            clean_line(&s.anchor.comm),
            s.started_at,
            if s.alive { "" } else { "  (exited)" }
        ),
    );
    if !chain.is_empty() {
        line("chain", chain);
    }
    if let Some(cwd) = &s.cwd {
        line(
            "cwd",
            format!("{}  (reported, untrusted)", quoted_line(cwd)),
        );
    }
    line("labels", labels);
    line("grants", format!("{} active", s.active_grants));
    out
}

/// `cn session`.
pub fn show(ctx: &Ctx) -> Result<Done, CnError> {
    let mut client = Client::connect(ctx)?;
    match client.call(Request::Session)? {
        Response::Session { session } => {
            let text = describe(&session);
            Ok(Done::ok(json!({"session": session}), text))
        }
        other => Err(unexpected("session", &other)),
    }
}

/// `cn session exec`: register this process as an anchor, then `exec` the
/// command so the agent keeps this pid and start time.
pub fn exec(ctx: &Ctx, label: Option<&str>, command: &[OsString]) -> Result<Done, CnError> {
    let mut client = Client::connect(ctx)?;
    let session = match client.call(Request::SessionRegister {
        label: label.map(str::to_owned),
    })? {
        Response::Registered { session } => session,
        other => return Err(unexpected("registered", &other)),
    };
    drop(client);
    ctx.info(&format!(
        "countersign session {} (pid {})",
        clean_line(&session.id),
        std::process::id()
    ));

    let err = Command::new(&command[0])
        .args(&command[1..])
        .env_clear()
        .envs(stripped_env())
        .exec();
    eprintln!("cn: {}: {err}", clean_line(&command[0].to_string_lossy()));
    Ok(Done::Exit(if err.kind() == std::io::ErrorKind::NotFound {
        EXIT_NOT_FOUND
    } else {
        EXIT_CANNOT_EXECUTE
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_proto::{Anchor, Timestamp};

    #[test]
    fn the_label_and_cwd_cannot_close_their_quotes() {
        let s = SessionView {
            id: "s_1".into(),
            anchor: Anchor {
                pid: 1,
                starttime: 1,
                comm: "claude".into(),
                registered: true,
            },
            started_at: Timestamp::now(),
            label: Some("x\", matched \\".into()),
            chain: vec![],
            labels: Default::default(),
            cwd: Some("x\"  (reported, untrusted)".into()),
            alive: true,
            active_grants: 0,
        };
        let text = describe(&s);
        assert!(
            text.contains("registered by cn session exec, label \"x\\\", matched \\\\\""),
            "{text}"
        );
        assert!(
            text.contains("\ncwd       \"x\\\"  (reported, untrusted)\"  (reported, untrusted)\n"),
            "{text}"
        );
    }
}
