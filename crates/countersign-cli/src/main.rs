//! `cn`: the countersign command-line client. The reference is docs/cli.md.

mod cli;
mod client;
mod cmd;
mod duration;
mod env;
mod error;
mod output;
mod sys;

use std::ffi::OsString;

use clap::Parser;
use clap::error::ErrorKind;

use crate::cli::{Cli, Command};
use crate::error::CnError;
use crate::output::{Ctx, Done};

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    std::process::exit(real_main(&args));
}

fn real_main(args: &[OsString]) -> i32 {
    let run = cli::is_run_invocation(args);
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => return usage_error(args, run, &e),
    };

    // Before anything touches a value: no core dumps, no same-uid ptrace
    // attach or /proc/PID/environ reads of cn itself (threat model T6).
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);

    let ctx = Ctx {
        json: cli.json,
        quiet: cli.quiet,
        #[cfg(debug_assertions)]
        socket: cli.socket.clone(),
    };
    let _ = cli.no_color; // cn prints no colour.

    if let Command::Run(args) = cli.command {
        return match cmd::run::run(&ctx, &args) {
            Ok(code) => code,
            Err(e) => {
                output::print_error(ctx.json, true, &e);
                125
            }
        };
    }

    match cmd::dispatch(&ctx, cli.command) {
        Ok(Done::Exit(code)) => code,
        Ok(Done::Report {
            data,
            text,
            failure,
        }) => {
            if ctx.json {
                match &failure {
                    None => output::print_json(&data),
                    Some(err) => {
                        let mut env = err.envelope();
                        env["data"] = data;
                        output::println_value(&env);
                    }
                }
            } else {
                output::out(&text);
                if let Some(err) = &failure {
                    output::print_error(false, true, err);
                }
            }
            failure.map_or(0, |e| e.exit())
        }
        Err(e) => {
            output::print_error(ctx.json, false, &e);
            e.exit()
        }
    }
}

/// Help and version print normally. Other parse errors exit 2 (125 for
/// `cn run`, as `env(1)` does), as an envelope when `--json` was given.
fn usage_error(args: &[OsString], run: bool, e: &clap::Error) -> i32 {
    if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
        let _ = e.print();
        return 0;
    }
    let json = args
        .iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--json");
    if !json {
        let _ = e.print();
        return if run { 125 } else { 2 };
    }
    let message = e
        .to_string()
        .lines()
        .next()
        .unwrap_or("bad arguments")
        .trim_start_matches("error: ")
        .to_owned();
    let err = CnError::usage(message);
    output::print_error(true, run, &err);
    if run { 125 } else { err.exit() }
}
