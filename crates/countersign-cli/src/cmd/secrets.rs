//! `cn list` and `cn show`.

use countersign_proto::{GrantView, Request, Response, SecretView};
use serde_json::json;

use crate::cli::ListArgs;
use crate::client::{Client, unexpected};
use crate::error::CnError;
use crate::output::{Ctx, Done, clean, clean_line, left, table};

fn fetch(ctx: &Ctx, all_projects: bool) -> Result<(Option<String>, Vec<SecretView>), CnError> {
    let mut client = Client::connect(ctx)?;
    match client.call(Request::List { all_projects })? {
        Response::List { session, secrets } => Ok((session, secrets)),
        other => Err(unexpected("list", &other)),
    }
}

/// `use 41m left`, or `-`.
pub fn grant_cell(grant: Option<&GrantView>) -> String {
    grant.map_or_else(
        || "-".into(),
        |g| format!("{} {} left", g.mode, left(g.expires_at)),
    )
}

/// `cn list`.
pub fn list(ctx: &Ctx, args: &ListArgs) -> Result<Done, CnError> {
    let (session, secrets) = fetch(ctx, args.all)?;
    let data = json!({"session": session, "secrets": secrets});

    let rows: Vec<Vec<String>> = secrets
        .iter()
        .map(|s| {
            let mut description = clean_line(&s.meta.description);
            if !s.in_project {
                description.push_str("  (other project)");
            }
            vec![
                clean_line(&s.meta.name),
                grant_cell(s.grant.as_ref()),
                description,
            ]
        })
        .collect();
    // With --long, each row is followed by its usage prose, indented.
    let mut text = String::new();
    for (i, line) in table(&["NAME", "GRANT", "DESCRIPTION"], &rows)
        .lines()
        .enumerate()
    {
        text.push_str(line);
        text.push('\n');
        if let Some(s) = i.checked_sub(1).filter(|_| args.long).map(|i| &secrets[i]) {
            for usage in clean(&s.meta.usage, true).lines() {
                text.push_str("    ");
                text.push_str(usage);
                text.push('\n');
            }
        }
    }
    if secrets.is_empty() {
        text = if args.all {
            "no secrets in the store\n".into()
        } else {
            "no secrets for this project (cn list --all shows every project)\n".into()
        };
    }
    Ok(Done::ok(data, text))
}

/// `cn show NAME`.
pub fn show(ctx: &Ctx, name: &str) -> Result<Done, CnError> {
    let (session, secrets) = fetch(ctx, true)?;
    let secret = secrets
        .into_iter()
        .find(|s| s.meta.name == name)
        .ok_or_else(|| {
            CnError::new(
                "unknown_secret",
                format!("no secret named '{}'", clean_line(name)),
            )
            .with_hint("cn list --all")
        })?;

    let m = &secret.meta;
    let mut text = String::new();
    let mut line = |k: &str, v: String| text.push_str(&format!("{k:<14}{v}\n"));
    line("name", clean_line(&m.name));
    line("description", clean_line(&m.description));
    line(
        "projects",
        if m.projects.is_empty() {
            "all".into()
        } else {
            clean_line(&m.projects.join(", "))
        },
    );
    if !m.tags.is_empty() {
        line("tags", clean_line(&m.tags.join(", ")));
    }
    line(
        "high_entropy",
        if m.high_entropy {
            "yes  (redacted by `cn hide` even when not granted)".into()
        } else {
            "no   (not redacted by `cn hide` unless granted)".into()
        },
    );
    line("env", clean_line(&secret.default_env));
    if let Some(t) = secret.created {
        line("created", t.to_string());
    }
    if let Some(t) = secret.updated {
        line("updated", t.to_string());
    }
    if let Some(t) = secret.rotated {
        line("rotated", t.to_string());
    }
    match &secret.last_use {
        Some(u) => line(
            "last use",
            format!(
                "{}  session {}{}",
                u.at,
                clean_line(&u.session),
                u.argv0
                    .as_deref()
                    .map(|a| format!("  argv0 {}", clean_line(a)))
                    .unwrap_or_default()
            ),
        ),
        None => line("last use", "never".into()),
    }
    text.push_str("usage\n");
    for l in clean(&m.usage, true).lines() {
        text.push_str("  ");
        text.push_str(l);
        text.push('\n');
    }
    let grant = match &secret.grant {
        Some(g) => format!(
            "{} {}, {} left, approved by {}",
            g.id,
            g.mode,
            left(g.expires_at),
            g.approved_by.join(", ")
        ),
        None => "none in this session".into(),
    };
    text.push_str(&format!("{:<14}{grant}\n", "grant"));

    let mut data = serde_json::to_value(&secret).map_err(|e| CnError::internal(e.to_string()))?;
    data["session"] = json!(session);
    Ok(Done::ok(data, text))
}
