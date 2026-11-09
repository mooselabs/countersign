//! `cn add`, `set`, `edit`, `rm`: store changes. Each creates a `mutate`
//! request that the human approves; values travel with the request and are
//! never taken from argv.

use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use countersign_proto::{
    Request, RequestState, RequestView, Response, SecretMeta, ValueB64, ValueSource,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{AddArgs, EditArgs, RmArgs, SetArgs, UsageArgs, ValueSourceArgs};
use crate::client::{Client, unexpected};
use crate::cmd::grants::{
    announce, check_digest, check_names, outcome, request_data, request_lines, wait,
};
use crate::duration::Secs;
use crate::error::CnError;
use crate::output::{Ctx, Done};

/// Largest value the store accepts (design.md §3).
pub const MAX_VALUE_LEN: usize = 64 << 10;
/// Longest description, in characters.
pub const MAX_DESCRIPTION: usize = 200;
/// Longest usage prose, in bytes.
pub const MAX_USAGE: usize = 4 << 10;
/// Shortest value `cn hide` and `cn run` redact.
pub const MIN_REDACTED_LEN: usize = countersign_hide::DEFAULT_MIN_LEN;

/// A value read from one of the allowed sources.
pub struct ReadValue {
    /// The bytes; zeroized on drop.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Where they came from.
    pub source: ValueSource,
    /// The file, for `--from-file`.
    pub file: Option<PathBuf>,
}

/// Removes one trailing `\n` (or `\r\n`).
pub fn strip_one_newline(v: &mut Vec<u8>) {
    if v.ends_with(b"\r\n") {
        v.truncate(v.len() - 2);
    } else if v.ends_with(b"\n") {
        v.truncate(v.len() - 1);
    }
}

/// Reads a value from `--from-stdin`, `--from-file`, `--from-clipboard`, or
/// a no-echo prompt when stdin is a terminal. Refuses with `no_tty` when a
/// prompt is needed and there is no terminal.
pub fn read_value(src: &ValueSourceArgs, name: &str) -> Result<ReadValue, CnError> {
    let mut bytes = Zeroizing::new(Vec::new());
    let (source, file) = if src.from_stdin {
        io::stdin()
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|e| CnError::internal(format!("reading stdin: {e}")))?;
        strip_one_newline(&mut bytes);
        (ValueSource::Stdin, None)
    } else if let Some(path) = &src.from_file {
        let mut f =
            fs::File::open(path).map_err(|e| CnError::usage(format!("{}: {e}", path.display())))?;
        f.read_to_end(&mut bytes)
            .map_err(|e| CnError::usage(format!("{}: {e}", path.display())))?;
        strip_one_newline(&mut bytes);
        (ValueSource::File, Some(path.clone()))
    } else if src.from_clipboard {
        let out = Command::new("wl-paste")
            .arg("--no-newline")
            .output()
            .map_err(|e| CnError::internal(format!("wl-paste: {e}")))?;
        if !out.status.success() {
            return Err(CnError::internal(format!(
                "wl-paste failed: {}",
                out.status
            )));
        }
        *bytes = out.stdout;
        let _ = Command::new("wl-copy").arg("--clear").status();
        (ValueSource::Clipboard, None)
    } else {
        if !io::stdin().is_terminal() {
            return Err(CnError::new(
                "no_tty",
                "no value source given and no terminal for a prompt",
            )
            .with_hint("use --from-stdin, --from-file PATH or --from-clipboard"));
        }
        let typed = rpassword::prompt_password(format!("value for {name} (not echoed): "))
            .map_err(|e| CnError::internal(format!("reading the value: {e}")))?;
        *bytes = typed.into_bytes();
        (ValueSource::Prompt, None)
    };
    if bytes.is_empty() {
        return Err(CnError::usage("the value is empty"));
    }
    if bytes.len() > MAX_VALUE_LEN {
        return Err(CnError::usage(format!(
            "the value is larger than {} KiB",
            MAX_VALUE_LEN >> 10
        )));
    }
    Ok(ReadValue {
        bytes,
        source,
        file,
    })
}

/// A rough entropy estimate in bits: length times log2 of the alphabet the
/// value's character classes suggest.
pub fn entropy_bits(value: &[u8]) -> f64 {
    let has = |f: fn(&u8) -> bool| value.iter().any(f);
    let mut alphabet = 0u32;
    if has(u8::is_ascii_lowercase) {
        alphabet += 26;
    }
    if has(u8::is_ascii_uppercase) {
        alphabet += 26;
    }
    if has(u8::is_ascii_digit) {
        alphabet += 10;
    }
    if has(u8::is_ascii_punctuation) || has(|b| *b == b' ') {
        alphabet += 33;
    }
    if has(|b| !b.is_ascii()) {
        alphabet += 128;
    }
    value.len() as f64 * f64::from(alphabet.max(2)).log2()
}

/// `Some(true)` for clearly random-looking values (at least 80 bits),
/// `Some(false)` for clearly guessable ones (under 50 bits), `None` between.
pub fn entropy_class(value: &[u8]) -> Option<bool> {
    let bits = entropy_bits(value);
    if bits >= 80.0 {
        Some(true)
    } else if bits < 50.0 {
        Some(false)
    } else {
        None
    }
}

fn read_usage(args: &UsageArgs) -> Result<Option<String>, CnError> {
    let usage = match (&args.usage, &args.usage_file) {
        (Some(text), _) => Some(text.clone()),
        (None, Some(path)) => Some(
            fs::read_to_string(path)
                .map_err(|e| CnError::usage(format!("{}: {e}", path.display())))?,
        ),
        (None, None) => None,
    };
    if let Some(u) = &usage {
        if u.len() > MAX_USAGE {
            return Err(CnError::usage(format!(
                "usage prose is longer than {} KiB",
                MAX_USAGE >> 10
            )));
        }
    }
    Ok(usage)
}

fn check_description(d: &str) -> Result<(), CnError> {
    if d.trim().is_empty() {
        return Err(CnError::usage("the description is empty"));
    }
    if d.contains('\n') {
        return Err(CnError::usage("the description must be one line"));
    }
    if d.chars().count() > MAX_DESCRIPTION {
        return Err(CnError::usage(format!(
            "the description is longer than {MAX_DESCRIPTION} characters"
        )));
    }
    Ok(())
}

/// Sends a store change and, with `--wait`, waits for its decision.
/// Returns the request as last seen and whether a wait happened.
pub fn submit(
    ctx: &Ctx,
    request: Request,
    wait_for: Option<Option<Secs>>,
) -> Result<(RequestView, bool), CnError> {
    let mut client = Client::connect(ctx)?;
    let view = match client.call(request)? {
        Response::RequestCreated(view) => view,
        other => return Err(unexpected("request_created", &other)),
    };
    check_digest(&view)?;
    match wait_for {
        None => Ok((view, false)),
        Some(limit) => {
            announce(ctx, &view);
            Ok((wait(ctx, &mut client, view, limit)?, true))
        }
    }
}

/// The result of a submitted change: the request lines when not waiting,
/// else the outcome.
pub fn report(
    view: &RequestView,
    waited: bool,
    approved: impl FnOnce(&RequestView) -> String,
) -> Result<Done, CnError> {
    if waited {
        outcome(view, approved)
    } else {
        Ok(Done::ok(request_data(view), request_lines(view)))
    }
}

/// Overwrites a file with zeros and unlinks it. On copy-on-write
/// filesystems and SSDs the old blocks may survive (docs/cli.md).
pub fn shred(path: &Path) -> io::Result<()> {
    let len = fs::metadata(path)?.len();
    let mut f = OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0u8; 64 << 10];
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left.min(zeros.len() as u64)).unwrap_or(zeros.len());
        f.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)
}

/// After a `--from-file` change: shred the file once the change is
/// committed, else say it was kept.
fn settle_file(ctx: &Ctx, file: Option<&Path>, view: &RequestView) {
    let Some(path) = file else { return };
    if view.state == RequestState::Approved {
        match shred(path) {
            Ok(()) => ctx.info(&format!("overwrote and removed {}", path.display())),
            Err(e) => ctx.info(&format!(
                "cn: warning: could not remove {}: {e}",
                path.display()
            )),
        }
    } else {
        ctx.info(&format!(
            "kept {}: delete it after the change is approved (or use --wait next time)",
            path.display()
        ));
    }
}

/// `cn add`.
pub fn add(ctx: &Ctx, args: &AddArgs) -> Result<Done, CnError> {
    check_names(std::slice::from_ref(&args.name))?;
    check_description(&args.description)?;
    let usage = read_usage(&args.usage)?.unwrap_or_default();
    let value = read_value(&args.source, &args.name)?;
    if value.bytes.len() < MIN_REDACTED_LEN {
        ctx.info(&format!(
            "cn: warning: values shorter than {MIN_REDACTED_LEN} bytes are never redacted by cn run or cn hide"
        ));
    }
    let high_entropy = match args
        .entropy
        .choice()
        .or_else(|| entropy_class(&value.bytes))
    {
        Some(h) => h,
        None => {
            return Err(CnError::usage(format!(
                "cannot tell whether the value is random enough to redact without a grant \
                 (estimate {:.0} bits); choose --high-entropy or --low-entropy",
                entropy_bits(&value.bytes)
            )));
        }
    };
    let meta = SecretMeta {
        name: args.name.clone(),
        description: args.description.clone(),
        usage,
        projects: args.projects.clone(),
        tags: args.tags.clone(),
        high_entropy,
    };
    let request = Request::Add {
        meta,
        value_b64: ValueB64::encode(&value.bytes),
        source: Some(value.source),
    };
    let file = value.file.clone();
    drop(value);
    let (view, waited) = submit(ctx, request, args.wait)?;
    settle_file(ctx, file.as_deref(), &view);
    report(&view, waited, |_| format!("added {}\n", args.name))
}

/// `cn set`.
pub fn set(ctx: &Ctx, args: &SetArgs) -> Result<Done, CnError> {
    check_names(std::slice::from_ref(&args.name))?;
    let value = read_value(&args.source, &args.name)?;
    if value.bytes.len() < MIN_REDACTED_LEN {
        ctx.info(&format!(
            "cn: warning: values shorter than {MIN_REDACTED_LEN} bytes are never redacted by cn run or cn hide"
        ));
    }
    let request = Request::Set {
        name: args.name.clone(),
        value_b64: ValueB64::encode(&value.bytes),
        source: Some(value.source),
    };
    let file = value.file.clone();
    drop(value);
    let (view, waited) = submit(ctx, request, args.wait)?;
    settle_file(ctx, file.as_deref(), &view);
    report(&view, waited, |v| {
        let revoked = v.decision.as_ref().map_or(0, |d| d.grants_revoked);
        format!(
            "set {}; {revoked} grant{} revoked\n",
            args.name,
            if revoked == 1 { "" } else { "s" }
        )
    })
}

/// `cn rm`.
pub fn rm(ctx: &Ctx, args: &RmArgs) -> Result<Done, CnError> {
    check_names(&args.names)?;
    let (view, waited) = submit(
        ctx,
        Request::Rm {
            names: args.names.clone(),
        },
        args.wait,
    )?;
    report(&view, waited, |_| {
        format!("removed {}\n", args.names.join(", "))
    })
}

/// The metadata `cn edit` opens in `$EDITOR`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Editable {
    description: String,
    usage: String,
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    high_entropy: bool,
}

/// `cn edit`.
pub fn edit(ctx: &Ctx, args: &EditArgs) -> Result<Done, CnError> {
    check_names(std::slice::from_ref(&args.name))?;
    if let Some(d) = &args.description {
        check_description(d)?;
    }
    let usage = read_usage(&args.usage)?;
    let current = {
        let mut client = Client::connect(ctx)?;
        match client.call(Request::List { all_projects: true })? {
            Response::List { secrets, .. } => {
                secrets
                    .into_iter()
                    .find(|s| s.meta.name == args.name)
                    .ok_or_else(|| {
                        CnError::new("unknown_secret", format!("no secret named '{}'", args.name))
                            .with_hint("cn list --all")
                    })?
                    .meta
            }
            other => return Err(unexpected("list", &other)),
        }
    };

    let meta = if args.no_flags() {
        edit_in_editor(&current)?
    } else {
        let mut meta = current.clone();
        if let Some(d) = &args.description {
            meta.description.clone_from(d);
        }
        if let Some(u) = usage {
            meta.usage = u;
        }
        meta.projects.retain(|p| !args.rm_projects.contains(p));
        for p in &args.add_projects {
            if !meta.projects.contains(p) {
                meta.projects.push(p.clone());
            }
        }
        meta.tags.retain(|t| !args.untags.contains(t));
        for t in &args.tags {
            if !meta.tags.contains(t) {
                meta.tags.push(t.clone());
            }
        }
        if let Some(h) = args.entropy.choice() {
            meta.high_entropy = h;
        }
        meta
    };
    if meta == current {
        return Ok(Done::ok(
            json!({"name": args.name, "changed": false}),
            "no changes\n".into(),
        ));
    }
    let (view, waited) = submit(ctx, Request::Edit { meta }, args.wait)?;
    report(&view, waited, |_| format!("edited {}\n", args.name))
}

fn edit_in_editor(current: &SecretMeta) -> Result<SecretMeta, CnError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(CnError::new(
            "no_tty",
            "cn edit with no flags opens $EDITOR and needs a terminal",
        )
        .with_hint("pass the change as flags, e.g. --usage-file PATH"));
    }
    let editable = Editable {
        description: current.description.clone(),
        usage: current.usage.clone(),
        projects: current.projects.clone(),
        tags: current.tags.clone(),
        high_entropy: current.high_entropy,
    };
    let body = toml::to_string(&editable).map_err(|e| CnError::internal(e.to_string()))?;
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!(
        "cn-edit-{}-{}.toml",
        std::process::id(),
        current.name
    ));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| CnError::internal(format!("{}: {e}", path.display())))?;
    let header = format!(
        "# Metadata of {}. Save and quit to submit the change for approval.\n\
         # The value is not here; use cn set to change it.\n\n",
        current.name
    );
    f.write_all(header.as_bytes())
        .and_then(|()| f.write_all(body.as_bytes()))
        .map_err(|e| CnError::internal(format!("{}: {e}", path.display())))?;
    drop(f);

    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(&path)
        .status();
    let mut text = fs::read_to_string(&path);
    let _ = fs::remove_file(&path);
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return Err(CnError::usage(format!(
                "the editor exited with {s}; nothing changed"
            )));
        }
        Err(e) => return Err(CnError::internal(format!("starting {editor}: {e}"))),
    }
    let text = text
        .as_mut()
        .map_err(|e| CnError::internal(format!("{}: {e}", path.display())))?;
    let parsed: Editable = toml::from_str(text)
        .map_err(|e| CnError::usage(format!("the edited file is not valid: {e}")))?;
    text.zeroize();
    check_description(&parsed.description)?;
    if parsed.usage.len() > MAX_USAGE {
        return Err(CnError::usage("usage prose is longer than 4 KiB"));
    }
    Ok(SecretMeta {
        name: current.name.clone(),
        description: parsed.description,
        usage: parsed.usage,
        projects: parsed.projects,
        tags: parsed.tags,
        high_entropy: parsed.high_entropy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_trailing_newline_is_stripped() {
        for (input, want) in [
            (&b"abc\n"[..], &b"abc"[..]),
            (b"abc\r\n", b"abc"),
            (b"abc\n\n", b"abc\n"),
            (b"abc", b"abc"),
            (b"", b""),
        ] {
            let mut v = input.to_vec();
            strip_one_newline(&mut v);
            assert_eq!(v, want);
        }
    }

    #[test]
    fn entropy_estimate_separates_the_obvious_cases() {
        assert_eq!(entropy_class(b"hunter2"), Some(false));
        assert_eq!(entropy_class(b"password"), Some(false));
        assert_eq!(
            entropy_class(b"ghp_9f3cK2m8QxZ1aB7dE4fG6hJ0kL5nP3rS"),
            Some(true)
        );
        assert_eq!(entropy_class(b"correcthorse"), None);
    }

    #[test]
    fn descriptions_are_one_short_line() {
        assert!(check_description("ClickHouse, read-only").is_ok());
        assert!(check_description("").is_err());
        assert!(check_description("two\nlines").is_err());
        assert!(check_description(&"x".repeat(201)).is_err());
    }

    #[test]
    fn shred_overwrites_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".secret-x");
        fs::write(&path, b"value").unwrap();
        shred(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn editable_metadata_round_trips_through_toml() {
        let e = Editable {
            description: "d".into(),
            usage: "line one\nline \"two\"".into(),
            projects: vec!["~/p/*".into()],
            tags: vec![],
            high_entropy: true,
        };
        let text = toml::to_string(&e).unwrap();
        assert_eq!(toml::from_str::<Editable>(&text).unwrap(), e);
    }
}
