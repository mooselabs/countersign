//! `cn reveal NAME`: print a raw value under a `reveal` grant.

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

use countersign_proto::{Request, Response};
use serde_json::json;
use zeroize::Zeroize;

use crate::cli::RevealArgs;
use crate::client::{Client, unexpected};
use crate::cmd::grants::check_names;
use crate::error::CnError;
use crate::output::{Ctx, Done, clean_line};

/// Seconds a revealed value stays on the clipboard.
const CLIPBOARD_SECONDS: u32 = 30;

/// `cn reveal`.
pub fn reveal(ctx: &Ctx, args: &RevealArgs) -> Result<Done, CnError> {
    check_names(std::slice::from_ref(&args.name))?;
    let mut client = Client::connect(ctx)?;
    let (name, value_b64, reveals_left) = match client.call(Request::Reveal {
        name: args.name.clone(),
    })? {
        Response::Reveal {
            name,
            value_b64,
            reveals_left,
        } => (name, value_b64, reveals_left),
        other => return Err(unexpected("reveal", &other)),
    };
    let value = value_b64
        .decode()
        .map_err(|e| CnError::internal(format!("protocol error: bad value encoding: {e}")))?;

    if args.clipboard {
        copy_to_clipboard(&value)?;
        let text = format!(
            "copied {} to the clipboard; clears in {CLIPBOARD_SECONDS}s\n",
            clean_line(&name)
        );
        return Ok(Done::ok(
            json!({"name": name, "clipboard": true, "clears_in_seconds": CLIPBOARD_SECONDS,
                   "reveals_left": reveals_left}),
            text,
        ));
    }

    if ctx.json {
        let mut text = std::str::from_utf8(&value).ok().map(str::to_owned);
        let data = json!({"name": name, "value": text, "value_b64": value_b64.as_str(),
                          "reveals_left": reveals_left});
        if let Some(t) = text.as_mut() {
            t.zeroize();
        }
        return Ok(Done::ok(data, String::new()));
    }
    let mut stdout = std::io::stdout().lock();
    let newline = stdout.is_terminal() && !value.ends_with(b"\n");
    stdout
        .write_all(&value)
        .and_then(|()| {
            if newline {
                stdout.write_all(b"\n")
            } else {
                Ok(())
            }
        })
        .and_then(|()| stdout.flush())
        .map_err(|e| CnError::internal(format!("writing stdout: {e}")))?;
    Ok(Done::Exit(0))
}

/// Puts the value on the Wayland clipboard and clears it later from a
/// detached process.
fn copy_to_clipboard(value: &[u8]) -> Result<(), CnError> {
    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| CnError::internal(format!("wl-copy: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(value)
            .map_err(|e| CnError::internal(format!("wl-copy: {e}")))?;
    }
    let status = child
        .wait()
        .map_err(|e| CnError::internal(format!("wl-copy: {e}")))?;
    if !status.success() {
        return Err(CnError::internal(format!("wl-copy failed: {status}")));
    }
    let _ = std::os::unix::process::CommandExt::process_group(
        Command::new("sh")
            .arg("-c")
            .arg(format!("sleep {CLIPBOARD_SECONDS}; wl-copy --clear"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
        0,
    )
    .spawn();
    Ok(())
}
