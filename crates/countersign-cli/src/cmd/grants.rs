//! `cn request`, `approve`, `deny`, `grants`, `revoke`, and the shared code
//! that shows a request and waits for its decision (also used by the store
//! mutations).

use std::time::{Duration, Instant};

use countersign_proto::{
    ApprovalKind, Driven, ErrorCode, Mode, Request, RequestCode, RequestState, RequestView,
    Response, Timestamp,
};
use serde_json::{Value, json};

use crate::cli::{ApproveArgs, DenyArgs, GrantsArgs, ModeArg, RequestArgs, RevokeArgs};
use crate::client::{Client, unexpected};
use crate::duration::{self, Secs};
use crate::env::valid_secret_name;
use crate::error::CnError;
use crate::output::{Ctx, Done, clean_line, clock, left, out, table, truncate};
use crate::sys;

/// Checks the names the user typed.
pub fn check_names(names: &[String]) -> Result<(), CnError> {
    match names.iter().find(|n| !valid_secret_name(n)) {
        Some(bad) => Err(CnError::usage(format!(
            "{:?} is not a secret name (lower-case letters, digits, '.', '_', '-')",
            bad
        ))),
        None => Ok(()),
    }
}

/// Parses a request code typed by a human.
pub fn parse_code(code: &str) -> Result<RequestCode, CnError> {
    code.parse()
        .map_err(|_| CnError::usage(format!("{code:?} is not a request code (like K7M-Q2X)")))
}

/// Recomputes the digest from the canonical fields and compares it with the
/// one `cnd` reported. Protects against a confused or mismatched daemon, not
/// against a shadowed `cn`.
pub fn check_digest(view: &RequestView) -> Result<(), CnError> {
    let digest = view.request.digest().map_err(|e| {
        CnError::new(
            "approval_invalid",
            format!("cannot canonicalise the request: {e}"),
        )
    })?;
    if digest.hex() != view.digest || digest.short() != view.digest_short {
        return Err(CnError::new(
            "approval_invalid",
            format!(
                "the digest cnd reported for request {} does not match the request it sent",
                view.request.code
            ),
        )
        .with_hint("cn doctor"));
    }
    Ok(())
}

/// `use clickhouse-password for 30m`, or `mutate: add NAME`.
pub fn summary(view: &RequestView) -> String {
    let r = &view.request;
    match r.mode {
        ApprovalKind::Use | ApprovalKind::Reveal => format!(
            "{} {}{}",
            r.mode,
            clean_line(&r.secrets.join(", ")),
            r.ttl_seconds
                .map(|t| format!(" for {}", duration::format(t)))
                .unwrap_or_default()
        ),
        ApprovalKind::Mutate | ApprovalKind::Export => format!(
            "{}: {}",
            r.mode,
            clean_line(r.operation.as_deref().unwrap_or("(no operation given)"))
        ),
    }
}

fn approve_command(view: &RequestView) -> String {
    format!("! /usr/bin/cn approve {}", view.request.code)
}

/// What the human has to do, for the `approve` line.
fn approve_line(view: &RequestView) -> String {
    if view.approvers.iter().any(|a| a.driven == Driven::Client) {
        format!("the human runs:  {}", approve_command(view))
    } else if view.queued {
        "queued: its dialog opens when an earlier one is answered".into()
    } else if view.approvers.iter().any(|a| a.prompted) {
        "a desktop dialog is open".into()
    } else {
        "no dialog is open yet; see cn doctor".into()
    }
}

/// The lines `cn request` prints for a new request.
pub fn request_lines(view: &RequestView) -> String {
    let r = &view.request;
    let expires_in = Timestamp::now().seconds_until(r.expires_at);
    format!(
        "request {} {}  {}\ndigest  {}\napprove {}\nexpires {} ({})\n",
        r.code,
        state_word(view.state),
        summary(view),
        view.digest_short,
        approve_line(view),
        r.expires_at,
        duration::format(expires_in),
    )
}

fn state_word(state: RequestState) -> &'static str {
    match state {
        RequestState::Pending => "pending",
        RequestState::Approved => "approved",
        RequestState::Denied => "denied",
        RequestState::Expired => "expired",
    }
}

/// The `--json` data for a request: every field of the view, plus
/// `approve_command` and, once approved, `grant` at the top level.
pub fn request_data(view: &RequestView) -> Value {
    let mut data = serde_json::to_value(view).unwrap_or(Value::Null);
    data["approve_command"] = Value::from(approve_command(view));
    if let Some(grant) = view.decision.as_ref().and_then(|d| d.grant.as_ref()) {
        data["grant"] = serde_json::to_value(grant).unwrap_or(Value::Null);
    }
    data
}

/// In human mode, prints the request now, before a wait, so the human can
/// compare the code and digest with the dialog while `cn` waits.
pub fn announce(ctx: &Ctx, view: &RequestView) {
    if !ctx.json {
        out(&request_lines(view));
    }
}

/// Waits for a decision, up to `limit` (default: until the request lapses).
pub fn wait(
    ctx: &Ctx,
    client: &mut Client,
    view: RequestView,
    limit: Option<Secs>,
) -> Result<RequestView, CnError> {
    let total = limit.map_or_else(
        || Timestamp::now().seconds_until(view.request.expires_at),
        |s| s.0,
    );
    ctx.info(&format!("waiting up to {}...", duration::format(total)));
    let deadline = Instant::now() + Duration::from_secs(total);
    let mut view = view;
    while view.state == RequestState::Pending {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let secs = remaining.as_secs().max(1);
        client.set_timeout(Some(Duration::from_secs(secs + 30)))?;
        let asked = Instant::now();
        let next = match client.call(Request::GetRequest {
            code: view.request.code.clone(),
            wait_seconds: Some(secs),
        })? {
            Response::RequestStatus(next) => next,
            other => return Err(unexpected("request_status", &other)),
        };
        if next.request.request_id != view.request.request_id {
            return Err(CnError::new(
                "request_not_found",
                format!("request {} is gone", view.request.code),
            ));
        }
        view = next;
        // A daemon that answers a wait at once must not make this spin.
        if view.state == RequestState::Pending && asked.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(view)
}

/// Turns a decided (or still pending) request into the command's result.
/// `approved` is the line to print on approval.
pub fn outcome(
    view: &RequestView,
    approved: impl FnOnce(&RequestView) -> String,
) -> Result<Done, CnError> {
    let code = &view.request.code;
    let by = view
        .decision
        .as_ref()
        .map(|d| clean_line(&d.by.join(", ")))
        .filter(|s| !s.is_empty());
    let data = request_data(view);
    match view.state {
        RequestState::Approved => Ok(Done::ok(data, approved(view))),
        RequestState::Denied
            if view.decision.as_ref().and_then(|d| d.error)
                == Some(ErrorCode::ApproverUnavailable) =>
        {
            let why = view
                .decision
                .as_ref()
                .and_then(|d| d.reason.as_deref())
                .map(|r| format!(": {}", clean_line(r)))
                .unwrap_or_default();
            Err(CnError::new(
                "approver_unavailable",
                format!("request {code} could not be shown to the human{why}"),
            )
            .with_hint("cn doctor")
            .with_detail(data))
        }
        RequestState::Denied => {
            let reason = view
                .decision
                .as_ref()
                .and_then(|d| d.reason.as_deref())
                .map(|r| format!(": {}", clean_line(r)))
                .unwrap_or_default();
            Err(CnError::new(
                "denied",
                format!(
                    "request {code} was denied{}{reason}",
                    by.map(|b| format!(" by {b}")).unwrap_or_default()
                ),
            )
            .with_hint("do not retry without asking the human")
            .with_detail(data))
        }
        RequestState::Expired => Err(CnError::new(
            "request_expired",
            format!("request {code} expired before it was decided"),
        )
        .with_hint("cn request again")
        .with_detail(data)),
        RequestState::Pending => Err(CnError::new(
            "pending",
            format!(
                "request {code} (digest {}) is still pending",
                view.digest_short
            ),
        )
        .with_hint("ask the human to approve, then check with cn grants")
        .with_detail(data)),
    }
}

/// The approval line for a grant request.
pub fn grant_approved_line(view: &RequestView) -> String {
    let decision = view.decision.as_ref();
    let by = decision
        .map(|d| clean_line(&d.by.join(", ")))
        .unwrap_or_default();
    match decision.and_then(|d| d.grant.as_ref()) {
        Some(g) => format!(
            "approved by {by}  grant {} active until {}\n",
            clean_line(&g.id),
            clock(g.expires_at)
        ),
        None => format!("approved by {by}\n"),
    }
}

/// `cn request`.
pub fn request(ctx: &Ctx, args: &RequestArgs) -> Result<Done, CnError> {
    check_names(&args.names)?;
    let mode = match args.mode {
        ModeArg::Use => Mode::Use,
        ModeArg::Reveal => Mode::Reveal,
    };
    let mut client = Client::connect(ctx)?;
    let response = client.call(Request::Request {
        names: args.names.clone(),
        mode,
        ttl_seconds: args.ttl.map(|t| t.0),
        reason: args.reason.clone(),
    })?;
    let view = match response {
        Response::AlreadyGranted { grant } => {
            let text = format!(
                "granted already  {} {} {}, {} left\n",
                clean_line(&grant.id),
                grant.mode,
                clean_line(&grant.secrets.join(", ")),
                left(grant.expires_at)
            );
            let data = json!({"state": "approved", "existing": true, "grant": grant});
            return Ok(Done::ok(data, text));
        }
        Response::RequestCreated(view) => view,
        other => return Err(unexpected("request_created", &other)),
    };
    check_digest(&view)?;
    match args.wait {
        None => Ok(Done::ok(request_data(&view), request_lines(&view))),
        Some(limit) => {
            announce(ctx, &view);
            let view = wait(ctx, &mut client, view, limit)?;
            outcome(&view, grant_approved_line)
        }
    }
}

/// The request as the human checks it before approving.
fn display(view: &RequestView) -> String {
    let r = &view.request;
    let anchor = format!(
        "anchor {} pid {} ({})",
        clean_line(&r.anchor.comm),
        r.anchor.pid,
        if r.anchor.registered {
            "registered by cn session exec"
        } else {
            "found by a matcher"
        }
    );
    let mut out = format!("countersign request {}\n", r.code);
    let mut line = |k: &str, v: String| out.push_str(&format!("  {k:<10}{v}\n"));
    line("session", format!("{}  {anchor}", clean_line(&r.session)));
    line(
        "cwd",
        format!(
            "{}   (reported, untrusted)",
            clean_line(r.cwd.as_deref().unwrap_or("none"))
        ),
    );
    line("secrets", clean_line(&r.secrets.join(", ")));
    line("mode", r.mode.to_string());
    if let Some(ttl) = r.ttl_seconds {
        line("ttl", duration::format(ttl));
    }
    if let Some(op) = &r.operation {
        line("operation", clean_line(op));
    }
    line(
        "reason",
        format!("(agent-supplied) {}", truncate(&clean_line(&r.reason), 300)),
    );
    line("digest", view.digest_short.clone());
    line("state", state_word(view.state).into());
    out
}

/// `cn approve CODE`. Phase 1 approvers are all daemon-driven (polkit), so
/// this shows the request for cross-checking and waits for the dialog's
/// answer; it does not approve anything itself.
pub fn approve(ctx: &Ctx, args: &ApproveArgs) -> Result<Done, CnError> {
    let code = parse_code(&args.code)?;
    if let Some(pid) = sys::tracer_pid().filter(|&p| p != 0) {
        return Err(CnError::internal(format!(
            "refusing to run under a tracer (TracerPid {pid})"
        )));
    }
    let mut client = Client::connect(ctx)?;
    let view = match client.call(Request::GetRequest {
        code: code.to_string(),
        wait_seconds: None,
    })? {
        Response::RequestStatus(view) => view,
        other => return Err(unexpected("request_status", &other)),
    };
    check_digest(&view)?;
    if let Some(name) = &args.approver {
        return match view.approvers.iter().find(|a| &a.name == name) {
            None => Err(CnError::usage(format!(
                "approver {name:?} is not in this request's chain"
            ))),
            Some(a) if a.driven == Driven::Client => {
                Err(CnError::later("FIDO2 approval with cn approve"))
            }
            Some(_) => Err(CnError::usage(format!(
                "approver {name:?} is daemon-driven: answer its desktop dialog"
            ))),
        };
    }
    if !ctx.json {
        out(&display(&view));
    }
    if view.state == RequestState::Pending {
        if view.approvers.iter().any(|a| a.driven == Driven::Client) {
            return Err(CnError::later(
                "FIDO2 approval with cn approve (this request's chain needs a security key)",
            ));
        }
        if !ctx.json {
            out(&format!(
                "Approve it in the desktop dialog. Check that the dialog shows request {} and digest {}.\n\
                 To refuse, cancel the dialog or run: cn deny {}\n",
                view.request.code, view.digest_short, view.request.code
            ));
        }
    }
    let view = wait(ctx, &mut client, view, Some(args.timeout))?;
    outcome(&view, |v| match v.request.mode {
        ApprovalKind::Use | ApprovalKind::Reveal => grant_approved_line(v),
        _ => format!(
            "approved by {}\n",
            v.decision
                .as_ref()
                .map(|d| clean_line(&d.by.join(", ")))
                .unwrap_or_default()
        ),
    })
}

/// `cn deny CODE`.
pub fn deny(ctx: &Ctx, args: &DenyArgs) -> Result<Done, CnError> {
    let code = parse_code(&args.code)?;
    let mut client = Client::connect(ctx)?;
    match client.call(Request::Deny {
        code: code.to_string(),
        reason: args.reason.clone(),
    })? {
        Response::Denied { request_id, code } => Ok(Done::ok(
            json!({"request_id": request_id, "code": code, "state": "denied"}),
            format!("denied {}\n", clean_line(&code)),
        )),
        other => Err(unexpected("denied", &other)),
    }
}

/// `cn grants`.
pub fn grants(ctx: &Ctx, args: &GrantsArgs) -> Result<Done, CnError> {
    let mut client = Client::connect(ctx)?;
    let grants = match client.call(Request::Grants {
        all_sessions: args.all_sessions,
    })? {
        Response::Grants { grants } => grants,
        other => return Err(unexpected("grants", &other)),
    };
    let text = if grants.is_empty() {
        "no active grants\n".to_owned()
    } else {
        let mut header = vec!["GRANT", "SECRETS", "MODE", "LEFT", "APPROVED BY", "USES"];
        if args.all_sessions {
            header.push("SESSION");
        }
        let rows: Vec<Vec<String>> = grants
            .iter()
            .map(|g| {
                let mut row = vec![
                    clean_line(&g.id),
                    clean_line(&g.secrets.join(",")),
                    g.mode.to_string(),
                    left(g.expires_at),
                    clean_line(&g.approved_by.join(",")),
                    g.reveals_left
                        .map_or_else(|| g.uses.to_string(), |r| format!("{} ({r} left)", g.uses)),
                ];
                if args.all_sessions {
                    row.push(clean_line(&g.session));
                }
                row
            })
            .collect();
        table(&header, &rows)
    };
    Ok(Done::ok(json!({"grants": grants}), text))
}

/// `cn revoke`.
pub fn revoke(ctx: &Ctx, args: &RevokeArgs) -> Result<Done, CnError> {
    if let Some(name) = &args.secret {
        check_names(std::slice::from_ref(name))?;
    }
    let mut client = Client::connect(ctx)?;
    let revoked = match client.call(Request::Revoke {
        grant_ids: args.grant_ids.clone(),
        secret: args.secret.clone(),
        all: args.all,
        all_sessions: args.all_sessions,
    })? {
        Response::Revoked { grants } => grants,
        other => return Err(unexpected("revoked", &other)),
    };
    let text = if revoked.is_empty() {
        "nothing to revoke\n".to_owned()
    } else {
        revoked
            .iter()
            .map(|g| {
                format!(
                    "revoked {} ({})\n",
                    clean_line(&g.id),
                    clean_line(&g.secrets.join(", "))
                )
            })
            .collect()
    };
    Ok(Done::ok(json!({"revoked": revoked}), text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_parse_leniently_and_names_strictly() {
        assert_eq!(parse_code("k7mq2x").unwrap().to_string(), "K7M-Q2X");
        assert_eq!(parse_code("nope").unwrap_err().exit(), 2);
        assert!(check_names(&["clickhouse-password".into()]).is_ok());
        assert_eq!(check_names(&["Bad Name".into()]).unwrap_err().code, "usage");
    }
}
