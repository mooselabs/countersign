//! `cn audit` (query through `cnd`) and `cn audit verify` (fetch the raw
//! segments and check the hash chain in `cn`, audit.md).

use std::time::Duration;

use base64::Engine as _;
use countersign_proto::{Request, Response, Timestamp};
use serde_json::{Value, json};

use crate::cli::{AuditQueryArgs, VerifyArgs};
use crate::client::{Client, unexpected};
use crate::duration::Secs;
use crate::error::CnError;
use crate::output::{Ctx, Done, clean_line, out, println_value, table, truncate};

/// Parses `--since`/`--until`: RFC 3339, or a duration back from now.
pub fn parse_time(text: &str, now: Timestamp) -> Result<Timestamp, CnError> {
    if let Ok(t) = text.parse::<Timestamp>() {
        return Ok(t);
    }
    match text.parse::<Secs>() {
        Ok(Secs(back)) => Ok(Timestamp::from_unix(
            now.unix()
                .saturating_sub(i64::try_from(back).unwrap_or(i64::MAX)),
        )),
        Err(_) => Err(CnError::usage(format!(
            "{text:?} is neither an RFC 3339 time nor a duration like 2h"
        ))),
    }
}

/// `cn audit`.
pub fn query(ctx: &Ctx, args: &AuditQueryArgs) -> Result<Done, CnError> {
    let now = Timestamp::now();
    let since = args
        .since
        .as_deref()
        .map(|t| parse_time(t, now))
        .transpose()?;
    let until = args
        .until
        .as_deref()
        .map(|t| parse_time(t, now))
        .transpose()?;
    let mut client = Client::connect(ctx)?;
    let session = if args.current {
        Some(client.session_id()?.to_owned())
    } else {
        args.session.clone()
    };
    let ask = |after_seq: Option<u64>, limit: Option<u32>| Request::AuditQuery {
        session: session.clone(),
        secret: args.secret.clone(),
        events: args.events.clone(),
        since,
        until,
        after_seq,
        limit,
    };

    let records = fetch(&mut client, ask(None, Some(args.limit)))?;
    let show_session = !args.current && args.session.is_none();
    let mut last = print_records(ctx, &records, show_session, true);
    if !args.follow {
        return Ok(Done::Exit(0));
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let records = fetch(&mut client, ask(last, None))?;
        if let Some(seq) = print_records(ctx, &records, show_session, false) {
            last = Some(seq);
        }
    }
}

fn fetch(client: &mut Client, request: Request) -> Result<Vec<Value>, CnError> {
    match client.call(request)? {
        Response::AuditRecords { records } => Ok(records),
        other => Err(unexpected("audit_records", &other)),
    }
}

/// Prints records (JSON Lines under `--json`, else a table) and returns the
/// last `seq` printed.
fn print_records(ctx: &Ctx, records: &[Value], show_session: bool, header: bool) -> Option<u64> {
    if ctx.json {
        for r in records {
            println_value(r);
        }
    } else {
        let rows: Vec<Vec<String>> = records
            .iter()
            .map(|r| {
                let mut row = vec![
                    r["seq"].as_u64().map(|s| s.to_string()).unwrap_or_default(),
                    r["ts"]
                        .as_str()
                        .and_then(|t| t.get(11..19))
                        .unwrap_or("")
                        .to_owned(),
                ];
                if show_session {
                    row.push(clean_line(r["session"]["id"].as_str().unwrap_or("-")));
                }
                row.push(clean_line(r["event"].as_str().unwrap_or("?")));
                row.push(clean_line(&detail(r)));
                row
            })
            .collect();
        let mut head = vec!["SEQ", "TIME"];
        if show_session {
            head.push("SESSION");
        }
        head.extend(["EVENT", "DETAIL"]);
        let text = table(&head, &rows);
        let text = if header {
            text
        } else {
            text.split_once('\n')
                .map(|(_, rest)| rest.to_owned())
                .unwrap_or_default()
        };
        if header && records.is_empty() {
            out("no matching records\n");
        } else {
            out(&text);
        }
    }
    records.last().and_then(|r| r["seq"].as_u64())
}

fn list(v: &Value) -> String {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

fn hits(v: &Value) -> String {
    v.as_object()
        .map(|m| {
            let inner = m
                .iter()
                .map(|(k, n)| format!("{k}:{n}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inner}}}")
        })
        .unwrap_or_else(|| "{}".into())
}

/// The DETAIL column: the fields that matter for each event. Agent-supplied
/// fields (`reason`, `argv0`, `cwd`) are shown as recorded.
fn detail(r: &Value) -> String {
    let s = |k: &str| r[k].as_str().unwrap_or("").to_owned();
    match r["event"].as_str().unwrap_or("") {
        "request.create" => format!(
            "{} {} {} {} \"{}\"",
            s("code"),
            s("mode"),
            list(&r["secrets"]),
            r["ttl_seconds"]
                .as_u64()
                .map(crate::duration::format)
                .unwrap_or_default(),
            truncate(&s("reason"), 40)
        ),
        "request.approve" | "request.deny" => format!(
            "{} {} -> {}",
            s("request_id"),
            s("approver"),
            list(&r["grant_ids"])
        ),
        "request.approve_fail" => format!("{} {} {}", s("request_id"), s("approver"), s("error")),
        "request.expire" => s("request_id"),
        "use.start" => format!(
            "{} {} argv0={} pid={}",
            s("run_id"),
            list(&r["secrets"]),
            s("argv0"),
            r["pid"]
        ),
        "use.end" => format!(
            "{} {} exit={} signal={} {}ms hits={}",
            s("run_id"),
            s("status"),
            r["exit"],
            r["signal"],
            r["duration_ms"],
            hits(&r["hits"])
        ),
        "reveal" => format!(
            "{} {} uses_left={}",
            s("secret"),
            s("grant_id"),
            r["uses_left"]
        ),
        "hide" => format!("{} B in, hits={}", r["bytes_in"], hits(&r["hits"])),
        "grant.revoke" | "grant.expire" => {
            format!("{} {} by={}", s("grant_id"), list(&r["secrets"]), s("by"))
        }
        e if e.starts_with("store.") => format!("{} {}", s("secret"), s("request_id")),
        "list" => format!("count={}", r["count"]),
        "session.start" | "session.end" => String::new(),
        _ => String::new(),
    }
}

/// What the chain verifier reports. Mirrors the report of
/// `countersign_core::audit::verify_segments` (see [`verify_segments`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Records checked.
    pub records: u64,
    /// First `seq` checked.
    pub first_seq: u64,
    /// Last `seq` checked.
    pub last_seq: u64,
    /// `hash` of the last record.
    pub head: String,
    /// Checkpoint records seen.
    pub checkpoints: u64,
}

/// Why verification did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailure {
    /// The chain is broken at `seq`.
    #[expect(
        dead_code,
        reason = "built by the countersign-core verifier once verify_segments is wired"
    )]
    Broken {
        /// First bad record.
        seq: u64,
        /// What is wrong (chain, hash, seq gap).
        reason: String,
    },
    /// No verifier is linked into this build.
    NotWired,
}

/// The hash-chain verifier.
///
/// NOT WIRED YET. The verifier belongs in countersign-core, which is being
/// written in parallel; the integration step replaces this body with a call
/// to `countersign_core::audit::verify_segments(data)` (expected signature:
/// `fn verify_segments(data: &[u8]) -> Result<VerifyReport, VerifyError>`,
/// where `data` is the concatenated JSONL bytes from `audit_segments`) and
/// maps its report and error into the two types above.
pub fn verify_segments(data: &[u8]) -> Result<VerifyReport, VerifyFailure> {
    let _ = data;
    Err(VerifyFailure::NotWired)
}

/// `cn audit verify`.
pub fn verify(ctx: &Ctx, args: &VerifyArgs) -> Result<Done, CnError> {
    if args.approvals {
        return Err(CnError::later("cn audit verify --approvals"));
    }
    if args.pubkey.is_some() || args.checkpoints.is_some() {
        return Err(CnError::later(
            "checkpoint signature checks (--pubkey, --checkpoints)",
        ));
    }
    if args.dir.is_some() {
        return Err(CnError::later("cn audit verify --dir"));
    }
    let mut client = Client::connect(ctx)?;
    let mut data = Vec::new();
    let mut from_seq = args.from.unwrap_or(1);
    loop {
        match client.call(Request::AuditSegments { from_seq })? {
            Response::AuditSegments {
                data_b64, next_seq, ..
            } => {
                let chunk = base64::engine::general_purpose::STANDARD
                    .decode(data_b64)
                    .map_err(|e| {
                        CnError::internal(format!("protocol error: bad segment encoding: {e}"))
                    })?;
                data.extend_from_slice(&chunk);
                match next_seq {
                    Some(next) if next > from_seq => from_seq = next,
                    Some(_) => {
                        return Err(CnError::internal(
                            "protocol error: audit_segments did not advance",
                        ));
                    }
                    None => break,
                }
            }
            other => return Err(unexpected("audit_segments", &other)),
        }
    }
    match verify_segments(&data) {
        Ok(r) => Ok(Done::ok(
            json!({"result": "ok", "records": r.records, "first_seq": r.first_seq,
                   "last_seq": r.last_seq, "head": r.head, "checkpoints": r.checkpoints}),
            format!(
                "chain ok: {} records ({}..{}), {} checkpoints, head {}\n",
                r.records,
                r.first_seq,
                r.last_seq,
                r.checkpoints,
                truncate(&r.head, 12)
            ),
        )),
        Err(VerifyFailure::Broken { seq, reason }) => Err(CnError::new(
            "audit_broken",
            format!("the audit chain is broken at seq {seq}: {reason}"),
        )
        .with_hint("investigate; do not ignore")
        .with_detail(json!({"seq": seq, "reason": reason}))),
        Err(VerifyFailure::NotWired) => Err(CnError::internal(format!(
            "fetched {} bytes of audit log, but this build has no chain verifier yet \
             (countersign_core::audit::verify_segments is not wired)",
            data.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_rfc3339_or_durations_back() {
        let now = Timestamp::from_unix(10_000);
        assert_eq!(parse_time("2h", now).unwrap().unix(), 2800);
        assert_eq!(
            parse_time("2026-11-08T09:25:11Z", now).unwrap().to_string(),
            "2026-11-08T09:25:11Z"
        );
        assert!(parse_time("yesterday", now).is_err());
    }

    #[test]
    fn details_summarise_common_events() {
        let r = json!({"event":"use.end","run_id":"u_1","status":"exited","exit":0,
                       "signal":null,"duration_ms":6100,"hits":{"db":1}});
        assert_eq!(
            detail(&r),
            "u_1 exited exit=0 signal=null 6100ms hits={db:1}"
        );
        let r = json!({"event":"request.create","code":"K7M-Q2X","mode":"use",
                       "secrets":["db"],"ttl_seconds":1800,"reason":"row counts"});
        assert_eq!(detail(&r), "K7M-Q2X use db 30m \"row counts\"");
    }

    #[test]
    fn the_verifier_says_it_is_not_wired() {
        assert_eq!(verify_segments(b""), Err(VerifyFailure::NotWired));
    }
}
