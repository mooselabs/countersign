//! `cn run` (design.md §7): fetch values, start the child with them in its
//! environment, and scrub its stdout and stderr.
//!
//! Exit codes follow `env(1)`: the child's code; 128+N when a signal killed
//! it; 125 when `cn` failed before starting it; 126 when the command could
//! not be executed; 127 when it was not found. Every error this module
//! returns becomes 125 in `main`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Instant;

use countersign_hide::{Builder, Hits, Redactor, Secret};
use countersign_proto::{Request, Response, RunValue, ScrubValue};
use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGWINCH};
use signal_hook::iterator::Signals;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::RunArgs;
use crate::client::{Client, unexpected};
use crate::env::{Injected, build_env, parse_uses};
use crate::error::CnError;
use crate::output::{Ctx, clean_line};

/// Signals forwarded to the child. SIGINT is caught and dropped: the child
/// gets it from the terminal, and `cn` keeps scrubbing until the child exits.
const FORWARDED: [i32; 6] = [SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGWINCH];

/// Exit code when the command was found but could not be executed.
pub const EXIT_CANNOT_EXECUTE: i32 = 126;
/// Exit code when the command was not found.
pub const EXIT_NOT_FOUND: i32 = 127;

/// A decoded value. Zeroized on drop.
struct Value {
    name: String,
    env: Option<String>,
    bytes: Zeroizing<Vec<u8>>,
}

/// `cn run`. Returns the exit code; an error means exit 125.
pub fn run(ctx: &Ctx, args: &RunArgs) -> Result<i32, CnError> {
    let uses = parse_uses(&args.uses)?;
    let program = &args.command[0];
    let argc = u32::try_from(args.command.len() - 1).unwrap_or(u32::MAX);

    let mut client = Client::connect(ctx)?;
    let (run_id, values, extra) = match client.call(Request::Run {
        uses: uses.clone(),
        argv0: program.to_string_lossy().into_owned(),
        argc,
    })? {
        Response::RunOk {
            run_id,
            values,
            patterns_extra,
        } => (run_id, values, patterns_extra),
        other => return Err(unexpected("run_ok", &other)),
    };
    let values = decode(&uses, values, extra)?;

    let redactor = Builder::default()
        .build(values.iter().map(|v| Secret {
            name: &v.name,
            value: &v.bytes,
        }))
        .map_err(|e| CnError::internal(format!("building the redaction engine: {e}")))?;
    let injected: Vec<Injected<'_>> = values
        .iter()
        .filter_map(|v| {
            v.env.as_deref().map(|env| Injected {
                env,
                value: &v.bytes,
            })
        })
        .collect();
    let env = build_env(std::env::vars_os(), &injected)?;

    let mut command = Command::new(program);
    command
        .args(&args.command[1..])
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, OsStr::from_bytes(v))))
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let spawned = command.spawn();
    // The values now live in the child's environment and in the engine's
    // patterns; drop cn's own copies.
    drop(command);
    drop(env);
    drop(injected);
    drop(values);

    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            let code = if e.kind() == io::ErrorKind::NotFound {
                EXIT_NOT_FOUND
            } else {
                EXIT_CANNOT_EXECUTE
            };
            eprintln!("cn: {}: {e}", clean_line(&program.to_string_lossy()));
            finish(
                ctx,
                &mut client,
                &run_id,
                Some(code),
                None,
                started,
                Hits::new(),
            );
            return Ok(code);
        }
    };

    let forwarder = Forwarder::start(&child);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (status, hits) = std::thread::scope(|s| {
        let out = s.spawn(|| stdout.map(|r| pump(r, io::stdout(), &redactor)));
        let err = s.spawn(|| stderr.map(|r| pump(r, io::stderr(), &redactor)));
        let status = child.wait();
        let mut hits = out.join().ok().flatten().unwrap_or_default();
        for (name, n) in err.join().ok().flatten().unwrap_or_default() {
            *hits.entry(name).or_insert(0) += n;
        }
        (status, hits)
    });
    if let Some(f) = forwarder {
        f.stop();
    }
    let status = status.map_err(|e| CnError::internal(format!("waiting for the child: {e}")))?;
    let (code, exit, signal) = exit_code(status);
    finish(ctx, &mut client, &run_id, exit, signal, started, hits);
    Ok(code)
}

/// Checks the daemon issued exactly the variables asked for, and decodes.
fn decode(
    uses: &[countersign_proto::Use],
    values: Vec<RunValue>,
    extra: Vec<ScrubValue>,
) -> Result<Vec<Value>, CnError> {
    let mut wanted: BTreeMap<&str, &str> = uses
        .iter()
        .map(|u| (u.env.as_str(), u.name.as_str()))
        .collect();
    let mut out = Vec::with_capacity(values.len() + extra.len());
    for v in values {
        if wanted.remove(v.env.as_str()) != Some(v.name.as_str()) {
            return Err(CnError::internal(format!(
                "protocol error: cnd issued {} for {}, which was not asked for",
                clean_line(&v.name),
                clean_line(&v.env)
            )));
        }
        let bytes = v
            .value_b64
            .decode()
            .map_err(|e| CnError::internal(format!("protocol error: bad value encoding: {e}")))?;
        out.push(Value {
            name: v.name.clone(),
            env: Some(v.env.clone()),
            bytes,
        });
    }
    if let Some((env, name)) = wanted.into_iter().next() {
        return Err(CnError::internal(format!(
            "protocol error: cnd issued no value for {name} ({env})"
        )));
    }
    for x in extra {
        let bytes = x
            .value_b64
            .decode()
            .map_err(|e| CnError::internal(format!("protocol error: bad value encoding: {e}")))?;
        out.push(Value {
            name: x.name.clone(),
            env: None,
            bytes,
        });
    }
    Ok(out)
}

/// Copies one child stream through its own redaction stream, flushing after
/// every chunk. Stops writing (and closes the child's pipe) if the
/// destination fails, e.g. `cn run ... | head`.
fn pump(mut src: impl Read, mut dst: impl Write, redactor: &Redactor) -> Hits {
    let mut stream = redactor.stream();
    let mut buf = vec![0u8; 64 << 10];
    let mut out = Vec::with_capacity(buf.len());
    let mut open = true;
    while open {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        out.clear();
        stream.push(&buf[..n], &mut out);
        if !out.is_empty() && dst.write_all(&out).and_then(|()| dst.flush()).is_err() {
            open = false;
        }
    }
    drop(src);
    out.clear();
    let hits = stream.finish(&mut out);
    if open && !out.is_empty() {
        let _ = dst.write_all(&out).and_then(|()| dst.flush());
    }
    buf.zeroize();
    out.zeroize();
    hits
}

/// Exit code, exit status and signal of a finished child.
pub fn exit_code(status: ExitStatus) -> (i32, Option<i32>, Option<i32>) {
    if let Some(code) = status.code() {
        (code, Some(code), None)
    } else if let Some(sig) = status.signal() {
        (128 + sig, None, Some(sig))
    } else {
        (EXIT_CANNOT_EXECUTE, None, None)
    }
}

/// Sends `run_finish`. A failure here does not change the exit code: the
/// child already ran, and `cnd` records `client_lost` if it never hears.
fn finish(
    ctx: &Ctx,
    client: &mut Client,
    run_id: &str,
    exit: Option<i32>,
    signal: Option<i32>,
    started: Instant,
    hits: Hits,
) {
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let result = client.call(Request::RunFinish {
        run_id: run_id.to_owned(),
        exit,
        signal,
        duration_ms,
        hits,
    });
    if let Err(e) = result {
        ctx.info(&format!(
            "cn: warning: could not report the end of the run to cnd: {}",
            clean_line(&e.message)
        ));
    }
}

/// Forwards signals to the child through a pidfd, so a reused pid can never
/// receive one.
struct Forwarder {
    handle: signal_hook::iterator::Handle,
    thread: std::thread::JoinHandle<()>,
}

impl Forwarder {
    fn start(child: &std::process::Child) -> Option<Self> {
        let pid = rustix::process::Pid::from_child(child);
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()?;
        let mut signals = Signals::new(FORWARDED.iter().copied().chain([SIGINT])).ok()?;
        let handle = signals.handle();
        let thread = std::thread::spawn(move || {
            for sig in signals.forever() {
                if sig == SIGINT {
                    continue;
                }
                if let Some(sig) = rustix::process::Signal::from_named_raw(sig) {
                    let _ = rustix::process::pidfd_send_signal(&pidfd, sig);
                }
            }
        });
        Some(Self { handle, thread })
    }

    fn stop(self) {
        self.handle.close();
        let _ = self.thread.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_env1() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), (0, Some(0), None));
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), (3, Some(3), None));
        assert_eq!(exit_code(ExitStatus::from_raw(15)), (143, None, Some(15)));
        assert_eq!(exit_code(ExitStatus::from_raw(9)), (137, None, Some(9)));
    }

    #[test]
    fn pump_scrubs_across_chunks_and_counts_hits() {
        let redactor = Builder::default()
            .build([Secret {
                name: "db",
                value: b"correct-horse-battery",
            }])
            .unwrap();
        let input = b"pw=correct-horse-battery\nagain correct-horse-battery".repeat(3);
        let mut out = Vec::new();
        let hits = pump(io::Cursor::new(input), &mut out, &redactor);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("correct-horse"), "{text}");
        assert_eq!(text.matches("[countersign:db]").count(), 6);
        assert_eq!(hits.get("db"), Some(&6));
    }

    #[test]
    fn decode_refuses_values_not_asked_for() {
        let uses = vec![countersign_proto::Use {
            name: "db".into(),
            env: "DB".into(),
        }];
        let ok = decode(
            &uses,
            vec![RunValue {
                name: "db".into(),
                env: "DB".into(),
                value_b64: countersign_proto::ValueB64::encode(b"v"),
            }],
            vec![],
        );
        assert_eq!(ok.unwrap()[0].bytes.as_slice(), b"v");
        let wrong_env = decode(
            &uses,
            vec![RunValue {
                name: "db".into(),
                env: "LD_PRELOAD".into(),
                value_b64: countersign_proto::ValueB64::encode(b"v"),
            }],
            vec![],
        );
        assert!(wrong_env.is_err());
        assert!(decode(&uses, vec![], vec![]).is_err());
    }
}
