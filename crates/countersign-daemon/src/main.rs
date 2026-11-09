//! `cnd`: the countersign daemon. The specification is `docs/design.md`.
//!
//! ```text
//! cnd [serve]     serve on the socket systemd passes (socket activation)
//! cnd init        create the store and its audit log; print the recovery phrase
//! cnd recover     re-wrap the machine key slot with the recovery phrase (stdin)
//! ```
//!
//! The master key comes from `$CREDENTIALS_DIRECTORY/countersign-mk`
//! (`LoadCredentialEncrypted=` in the unit). With the debug-only
//! `insecure-test` feature, `--insecure-mk-file`, `--socket` and
//! `--polkit-bus` let end-to-end tests run `cnd` without root.

#[cfg(all(feature = "insecure-test", not(debug_assertions)))]
compile_error!(
    "the insecure-test feature runs cnd without its protections; it is for debug builds only"
);

mod conn;
mod daemon;
mod frames;
mod log;
mod ops;
mod requests;
mod setup;
mod sys;
mod views;
mod watch;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::log::error;

/// Default configuration file.
pub const DEFAULT_CONFIG: &str = "/etc/countersign/config.toml";
/// Default state directory, when `$STATE_DIRECTORY` is not set.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/countersign";
/// Name of the master key credential.
pub const MK_CREDENTIAL: &str = "countersign-mk";

#[derive(Debug, Parser)]
#[command(name = "cnd", version, about = "countersign daemon")]
struct Args {
    /// Configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// State directory (default: $STATE_DIRECTORY, else /var/lib/countersign).
    #[arg(long, global = true, value_name = "PATH")]
    state_dir: Option<PathBuf>,
    /// Test builds: listen on this socket instead of the one systemd passes.
    #[cfg(feature = "insecure-test")]
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Test builds: read the master key from this plain file.
    #[cfg(feature = "insecure-test")]
    #[arg(long, global = true, value_name = "PATH")]
    insecure_mk_file: Option<PathBuf>,
    /// Test builds: talk to polkitd on this D-Bus address, not the system bus.
    #[cfg(feature = "insecure-test")]
    #[arg(long, global = true, value_name = "ADDRESS")]
    polkit_bus: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve clients (the default).
    Serve,
    /// Create the store and its audit log, and print the recovery phrase once.
    Init,
    /// Read the recovery phrase from stdin and re-wrap the store for the
    /// current master key.
    Recover,
}

/// Where things are, from the command line and the environment.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The config file.
    pub config: PathBuf,
    /// Whether `--config` named it. `init` and `recover` accept a missing
    /// default config; `serve` does not.
    pub config_given: bool,
    /// The state directory.
    pub state_dir: PathBuf,
    /// The master key file.
    pub master_key: Option<PathBuf>,
    /// Test builds: the socket to listen on.
    pub socket: Option<PathBuf>,
    /// Test builds: the polkit bus address.
    pub polkit_bus: Option<String>,
    /// The insecure test mode (`--insecure-mk-file` given): `cnd` may run as
    /// its clients' uid and the config need not be root-owned.
    pub insecure: bool,
}

impl Paths {
    fn from_args(args: &Args) -> Self {
        let state_dir = args.state_dir.clone().unwrap_or_else(|| {
            // systemd may pass several directories, colon-separated.
            std::env::var_os("STATE_DIRECTORY")
                .and_then(|v| {
                    v.to_string_lossy()
                        .split(':')
                        .next()
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from)
                })
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR))
        });
        let credential =
            std::env::var_os("CREDENTIALS_DIRECTORY").map(|d| PathBuf::from(d).join(MK_CREDENTIAL));
        #[cfg(feature = "insecure-test")]
        let (master_key, socket, polkit_bus, insecure) = (
            args.insecure_mk_file.clone().or(credential),
            args.socket.clone(),
            args.polkit_bus.clone(),
            args.insecure_mk_file.is_some(),
        );
        #[cfg(not(feature = "insecure-test"))]
        let (master_key, socket, polkit_bus, insecure) = (credential, None, None, false);
        Paths {
            config: args
                .config
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG)),
            config_given: args.config.is_some(),
            state_dir,
            master_key,
            socket,
            polkit_bus,
            insecure,
        }
    }
}

fn main() -> ExitCode {
    // Before anything else: no core dumps and no ptrace by other processes
    // of this user.
    if let Err(e) = sys::set_not_dumpable() {
        error!("prctl(PR_SET_DUMPABLE, 0): {e}");
        return ExitCode::FAILURE;
    }
    let args = Args::parse();
    let paths = Paths::from_args(&args);
    let result = match args.command.unwrap_or(Command::Serve) {
        Command::Init => setup::init(&paths),
        Command::Recover => setup::recover(&paths),
        Command::Serve => daemon::serve(paths),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}
