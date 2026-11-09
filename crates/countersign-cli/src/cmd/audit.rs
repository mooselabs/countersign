//! `cn audit` (query through `cnd`) and `cn audit verify` (fetch the raw
//! segments and check the hash chain in `cn`, audit.md).

use std::time::Duration;

use base64::Engine as _;
use countersign_core::audit::{VerifyOptions, parse_pubkey, verify_segments_with};
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

/// The raw log: from `cnd` (`audit_segments`, with its `checkpoint.pub`),
/// or with `--dir` from the segment files (root).
fn fetch_segments(ctx: &Ctx, args: &VerifyArgs) -> Result<(Vec<u8>, Option<String>), CnError> {
    if let Some(dir) = &args.dir {
        return read_dir_segments(dir, args.from.unwrap_or(1));
    }
    let mut client = Client::connect(ctx)?;
    let mut data = Vec::new();
    let mut pubkey = None;
    let mut from_seq = args.from.unwrap_or(1);
    loop {
        match client.call(Request::AuditSegments { from_seq })? {
            Response::AuditSegments {
                data_b64,
                next_seq,
                checkpoint_pubkey,
            } => {
                let chunk = base64::engine::general_purpose::STANDARD
                    .decode(data_b64)
                    .map_err(|e| {
                        CnError::internal(format!("protocol error: bad segment encoding: {e}"))
                    })?;
                data.extend_from_slice(&chunk);
                pubkey = pubkey.or(checkpoint_pubkey);
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
    Ok((data, pubkey))
}

/// `NNNNNN.jsonl` files in `dir`, in order, from the record `from` on, and
/// `checkpoint.pub`.
fn read_dir_segments(
    dir: &std::path::Path,
    from: u64,
) -> Result<(Vec<u8>, Option<String>), CnError> {
    let read_err = |e: std::io::Error| CnError::internal(format!("{}: {e}", dir.display()));
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(read_err)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| {
            n.strip_suffix(".jsonl")
                .is_some_and(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    names.sort();
    let mut data = Vec::new();
    for name in names {
        let bytes = std::fs::read(dir.join(&name)).map_err(read_err)?;
        for line in bytes.split_inclusive(|&b| b == b'\n') {
            let seq = serde_json::from_slice::<Value>(line)
                .ok()
                .and_then(|v| v["seq"].as_u64());
            if seq.is_none_or(|s| s >= from) {
                data.extend_from_slice(line);
            }
        }
    }
    let pubkey = std::fs::read_to_string(dir.join("checkpoint.pub")).ok();
    Ok((data, pubkey))
}

/// `cn audit verify`.
pub fn verify(ctx: &Ctx, args: &VerifyArgs) -> Result<Done, CnError> {
    if args.approvals {
        return Err(CnError::later("cn audit verify --approvals"));
    }
    let (data, served_key) = fetch_segments(ctx, args)?;
    let key_text = match &args.pubkey {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| CnError::usage(format!("--pubkey {}: {e}", path.display())))?,
        ),
        None => served_key,
    };
    let pubkey = match key_text.as_deref() {
        Some(text) => Some(
            parse_pubkey(text)
                .ok_or_else(|| CnError::usage("the checkpoint public key is not an ed25519 key"))?,
        ),
        None => None,
    };
    let exported = match &args.checkpoints {
        Some(path) => Some(
            std::fs::read(path)
                .map_err(|e| CnError::usage(format!("--checkpoints {}: {e}", path.display())))?,
        ),
        None => None,
    };
    // Without --from the log must start at seq 1: a log whose first
    // segments were deleted does not verify from wherever it now starts.
    let opts = VerifyOptions {
        pubkey,
        exported_checkpoints: exported.as_deref(),
        expect_first_seq: Some(args.from.unwrap_or(1)),
    };
    match verify_segments_with(&data, &opts) {
        Ok(r) => {
            let last = r
                .last_checkpoint
                .as_ref()
                .map(|c| format!(", last checkpoint {}", clean_line(&c.ts)))
                .unwrap_or_default();
            let exported = if args.checkpoints.is_some() {
                format!(", {} exported checkpoints match", r.exported_matched)
            } else {
                String::new()
            };
            Ok(Done::ok(
                json!({"result": "ok", "records": r.records, "first_seq": r.first_seq,
                       "last_seq": r.last_seq, "head": r.head_hash,
                       "from_genesis": r.from_genesis, "checkpoints": r.checkpoints,
                       "signatures_verified": r.signatures_verified,
                       "exported_matched": r.exported_matched,
                       "exported_not_covered": r.exported_not_covered}),
                format!(
                    "chain ok: {} records ({}..{}), {} checkpoints ({} signatures verified), head {}{last}{exported}\n",
                    r.records,
                    r.first_seq,
                    r.last_seq,
                    r.checkpoints,
                    r.signatures_verified,
                    truncate(&r.head_hash, 12)
                ),
            ))
        }
        Err(e) => Err(
            CnError::new("audit_broken", format!("the audit chain is broken: {e}"))
                .with_hint("investigate; do not ignore")
                .with_detail(json!({"seq": e.seq, "line": e.line, "reason": e.to_string()})),
        ),
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
    fn segments_are_read_from_a_directory_in_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("000002.jsonl"), "{\"seq\":3}\n").unwrap();
        std::fs::write(
            dir.path().join("000001.jsonl"),
            "{\"seq\":1}\n{\"seq\":2}\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "x").unwrap();
        let (data, key) = read_dir_segments(dir.path(), 2).unwrap();
        assert_eq!(data, b"{\"seq\":2}\n{\"seq\":3}\n");
        assert_eq!(key, None);
    }
}
