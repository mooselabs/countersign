//! `cn hide` (design.md §8): stream stdin through `cnd`'s redaction and
//! write what comes back to stdout. Values never enter this process.
//!
//! One thread forwards stdin as stream frames as soon as each read returns
//! (so a line written by the producer is sent at once) and sends `hide_end`
//! at EOF. The main thread writes returned stream frames to stdout, flushing
//! each, until `hide_summary` arrives. `cnd` holds back at most a partial
//! last line; that rule is the engine's, not this client's.

use std::io::{self, Read, Write};
use std::net::Shutdown;

use countersign_proto::{MAX_STREAM_LEN, Request, Response};
use serde_json::json;
use zeroize::Zeroize;

use crate::cli::HideArgs;
use crate::client::{Client, Incoming, send_message, send_stream, unexpected};
use crate::cmd::grants::check_names;
use crate::error::CnError;
use crate::output::{Ctx, Done, clean_line};

/// `cn hide`.
pub fn hide(ctx: &Ctx, args: &HideArgs) -> Result<Done, CnError> {
    check_names(&args.secrets)?;
    let mut client = Client::connect(ctx)?;
    match client.call(Request::Hide {
        secrets: args.secrets.clone(),
    })? {
        Response::HideOk => {}
        other => return Err(unexpected("hide_ok", &other)),
    }
    client.set_timeout(None)?;

    let writer = client.try_clone_stream()?;
    let end_id = client.reserve_id();
    // Not joined on error paths: it may be blocked reading stdin, and the
    // process exits right after.
    let sender = std::thread::spawn(move || -> Result<u64, CnError> {
        let mut stdin = io::stdin().lock();
        let mut buf = vec![0u8; MAX_STREAM_LEN];
        let mut sent = 0u64;
        let result = loop {
            match stdin.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    if let Err(e) = send_stream(&writer, &buf[..n]) {
                        break Err(e);
                    }
                    sent += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(CnError::internal(format!("reading stdin: {e}"))),
            }
        };
        buf.zeroize();
        result?;
        send_message(&writer, end_id, &Request::HideEnd)?;
        Ok(sent)
    });

    let mut stdout = io::stdout().lock();
    let summary = loop {
        match client.recv()? {
            Incoming::Stream(mut data) => {
                let written = stdout.write_all(&data).and_then(|()| stdout.flush());
                data.zeroize();
                if written.is_err() {
                    // The reader went away (`| head`). Stop quietly.
                    let _ = client.try_clone_stream()?.shutdown(Shutdown::Both);
                    return Ok(Done::Exit(0));
                }
            }
            Incoming::Message(msg) => match msg.body {
                Response::HideSummary {
                    bytes_in,
                    bytes_out,
                    hits,
                } => break (bytes_in, bytes_out, hits),
                Response::Error(body) => return Err(body.into()),
                other => return Err(unexpected("hide_summary", &other)),
            },
        }
    };
    drop(stdout);
    match sender.join() {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(CnError::internal("the stdin thread panicked")),
    }

    if args.stats {
        let (bytes_in, bytes_out, hits) = summary;
        if ctx.json {
            eprintln!(
                "{}",
                json!({"cn": 1, "ok": true, "data": {
                    "bytes_in": bytes_in, "bytes_out": bytes_out, "hits": hits}})
            );
        } else {
            let hits = if hits.is_empty() {
                "none".to_owned()
            } else {
                hits.iter()
                    .map(|(k, v)| format!("{}={v}", clean_line(k)))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            eprintln!("cn hide: {bytes_in} bytes in, {bytes_out} out, hits: {hits}");
        }
    }
    Ok(Done::Exit(0))
}
