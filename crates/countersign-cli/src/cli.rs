//! Command-line syntax, as docs/cli.md lists it.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::duration::Secs;

/// `cn --version` output: the version and the protocols it speaks.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (protocol 1)");

/// countersign client: use secrets without reading them.
#[derive(Debug, Parser)]
#[command(
    name = "cn",
    version = VERSION,
    disable_help_subcommand = true,
    after_help = "Docs: docs/cli.md. Exit codes (cn run passes the child's through): \
                  0 ok, 1 internal or doctor failed, 2 usage, 3 daemon, 4 no grant, \
                  5 denied, 6 pending, 7 expired or not found, 8 unknown secret, \
                  9 limit exceeded, 10 rate limited, 11 no session, 12 store sealed, \
                  13 audit broken, 14 approval invalid or approver unavailable."
)]
pub struct Cli {
    /// Machine-readable output (one JSON object on stdout).
    #[arg(long, global = true)]
    pub json: bool,

    /// Socket path (debug builds only; also COUNTERSIGN_SOCKET).
    #[cfg(debug_assertions)]
    #[arg(long, global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// No ANSI colour (cn prints none).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Suppress informational lines on stderr.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// A request's grant mode on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ModeArg {
    /// Values may be injected by `cn run`.
    Use,
    /// Values may be printed by `cn reveal`.
    Reveal,
}

/// Every command.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List secrets visible to this session.
    List(ListArgs),
    /// Show one secret's metadata and usage notes.
    Show {
        /// Secret name.
        name: String,
    },
    /// Ask for a grant.
    Request(RequestArgs),
    /// Show a pending request so the human can check it (approval is in the desktop dialog).
    Approve(ApproveArgs),
    /// Deny a pending request.
    Deny(DenyArgs),
    /// List active grants.
    Grants(GrantsArgs),
    /// End grants before their TTL.
    Revoke(RevokeArgs),
    /// Run a command with secrets in its environment and scrub its output.
    Run(RunArgs),
    /// Filter stdin to stdout, replacing secret values.
    Hide(HideArgs),
    /// Print a raw value (needs a reveal grant).
    Reveal(RevealArgs),
    /// Add a secret (needs approval).
    Add(AddArgs),
    /// Replace a secret's value (needs approval).
    Set(SetArgs),
    /// Change a secret's metadata (needs approval).
    Edit(EditArgs),
    /// Remove secrets (needs approval).
    Rm(RmArgs),
    /// Move plaintext secret files into the store (needs approval).
    Import(ImportArgs),
    /// Show this session, or start a command as a session anchor.
    Session(SessionArgs),
    /// Query or verify the audit log.
    Audit(AuditArgs),
    /// Check the installation and environment.
    Doctor,
    /// Write the store to an age recipient (not in this version).
    Export(LaterArgs),
    /// Unseal a FIDO2-sealed store (not in this version).
    Unlock(LaterArgs),
    /// Enrol or list FIDO2 approvers (not in this version).
    Approver(LaterArgs),
    /// Run one approved command as root (not in this version).
    Sudo(LaterArgs),
}

/// Arguments of a command this version does not provide.
#[derive(Debug, Args)]
pub struct LaterArgs {
    /// Ignored.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    pub rest: Vec<OsString>,
}

/// `cn list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Include secrets scoped to other projects.
    #[arg(long)]
    pub all: bool,
    /// Print the full usage prose for each secret.
    #[arg(short, long)]
    pub long: bool,
}

/// `cn request`.
#[derive(Debug, Args)]
pub struct RequestArgs {
    /// Secrets to request.
    #[arg(required = true, value_name = "NAME")]
    pub names: Vec<String>,
    /// What will be run and why (shown to the human as agent-supplied).
    #[arg(long, required = true)]
    pub reason: String,
    /// Grant lifetime, counted from approval (default: the daemon's).
    #[arg(long, value_name = "DUR")]
    pub ttl: Option<Secs>,
    /// Grant mode.
    #[arg(long, value_enum, default_value_t = ModeArg::Use)]
    pub mode: ModeArg,
    /// Block until decided, up to DUR (default: the request's lifetime).
    #[arg(long, value_name = "DUR", num_args = 0..=1)]
    pub wait: Option<Option<Secs>>,
}

/// `cn approve`.
#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Request code, e.g. K7M-Q2X.
    pub code: String,
    /// Approver instance (FIDO2 approvers are not in this version).
    #[arg(long, value_name = "NAME")]
    pub approver: Option<String>,
    /// How long to wait for the decision.
    #[arg(long, value_name = "DUR", default_value = "60s")]
    pub timeout: Secs,
}

/// `cn deny`.
#[derive(Debug, Args)]
pub struct DenyArgs {
    /// Request code.
    pub code: String,
    /// Why, for the audit log.
    #[arg(long)]
    pub reason: Option<String>,
}

/// `cn grants`.
#[derive(Debug, Args)]
pub struct GrantsArgs {
    /// Every live session of this user.
    #[arg(long)]
    pub all_sessions: bool,
}

/// `cn revoke`.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("which").required(true).args(["grant_ids", "secret", "all"])))]
pub struct RevokeArgs {
    /// Grant ids.
    #[arg(value_name = "GRANT_ID")]
    pub grant_ids: Vec<String>,
    /// Every grant covering this secret.
    #[arg(long, value_name = "NAME")]
    pub secret: Option<String>,
    /// Every grant.
    #[arg(long)]
    pub all: bool,
    /// In every live session of this user.
    #[arg(long)]
    pub all_sessions: bool,
}

/// `cn run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Inject NAME as its default variable, or as ENVVAR. Repeatable.
    #[arg(long = "use", value_name = "NAME[=ENVVAR]", required = true)]
    pub uses: Vec<String>,
    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

/// `cn hide`.
#[derive(Debug, Args)]
pub struct HideArgs {
    /// Also match this granted secret. Repeatable.
    #[arg(long = "secret", value_name = "NAME")]
    pub secrets: Vec<String>,
    /// Print hit counts to stderr at EOF.
    #[arg(long)]
    pub stats: bool,
}

/// `cn reveal`.
#[derive(Debug, Args)]
pub struct RevealArgs {
    /// Secret name.
    pub name: String,
    /// Copy to the Wayland clipboard (cleared after 30s) instead of printing.
    #[arg(long)]
    pub clipboard: bool,
}

/// Where a typed value comes from. None of them is argv.
#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct ValueSourceArgs {
    /// Read the Wayland clipboard, then clear it.
    #[arg(long)]
    pub from_clipboard: bool,
    /// Read this file; overwrite and unlink it after the change is approved.
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<PathBuf>,
    /// Read stdin to EOF; one trailing newline is stripped.
    #[arg(long)]
    pub from_stdin: bool,
}

/// `--high-entropy` / `--low-entropy`.
#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct EntropyArgs {
    /// `cn hide` matches it even when not granted.
    #[arg(long)]
    pub high_entropy: bool,
    /// `cn hide` matches it only when granted.
    #[arg(long)]
    pub low_entropy: bool,
}

impl EntropyArgs {
    /// The choice made, if any.
    pub fn choice(&self) -> Option<bool> {
        match (self.high_entropy, self.low_entropy) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        }
    }
}

/// `--usage TEXT` / `--usage-file PATH`.
#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct UsageArgs {
    /// How agents should use this secret (at most 4 KiB).
    #[arg(long, value_name = "TEXT")]
    pub usage: Option<String>,
    /// Read the usage prose from a file.
    #[arg(long, value_name = "PATH")]
    pub usage_file: Option<PathBuf>,
}

/// `cn add`.
#[derive(Debug, Args)]
pub struct AddArgs {
    /// Secret name.
    pub name: String,
    /// One line, at most 200 characters.
    #[arg(long, required = true)]
    pub description: String,
    /// Usage prose.
    #[command(flatten)]
    pub usage: UsageArgs,
    /// Project glob, matched against the session's cwd. Repeatable.
    #[arg(long = "project", value_name = "GLOB")]
    pub projects: Vec<String>,
    /// Tag. Repeatable.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Entropy class.
    #[command(flatten)]
    pub entropy: EntropyArgs,
    /// Value source.
    #[command(flatten)]
    pub source: ValueSourceArgs,
    /// Block until decided, up to DUR.
    #[arg(long, value_name = "DUR", num_args = 0..=1)]
    pub wait: Option<Option<Secs>>,
}

/// `cn set`.
#[derive(Debug, Args)]
pub struct SetArgs {
    /// Secret name.
    pub name: String,
    /// Value source.
    #[command(flatten)]
    pub source: ValueSourceArgs,
    /// Block until decided, up to DUR.
    #[arg(long, value_name = "DUR", num_args = 0..=1)]
    pub wait: Option<Option<Secs>>,
}

/// `cn edit`.
#[derive(Debug, Args)]
pub struct EditArgs {
    /// Secret name.
    pub name: String,
    /// New description.
    #[arg(long)]
    pub description: Option<String>,
    /// New usage prose.
    #[command(flatten)]
    pub usage: UsageArgs,
    /// Add a project glob. Repeatable.
    #[arg(long = "add-project", value_name = "GLOB")]
    pub add_projects: Vec<String>,
    /// Remove a project glob. Repeatable.
    #[arg(long = "rm-project", value_name = "GLOB")]
    pub rm_projects: Vec<String>,
    /// Add a tag. Repeatable.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Remove a tag. Repeatable.
    #[arg(long = "untag", value_name = "TAG")]
    pub untags: Vec<String>,
    /// Entropy class.
    #[command(flatten)]
    pub entropy: EntropyArgs,
    /// Block until decided, up to DUR.
    #[arg(long, value_name = "DUR", num_args = 0..=1)]
    pub wait: Option<Option<Secs>>,
}

impl EditArgs {
    /// True when no change flag was given (then `$EDITOR` opens).
    pub fn no_flags(&self) -> bool {
        self.description.is_none()
            && self.usage.usage.is_none()
            && self.usage.usage_file.is_none()
            && self.add_projects.is_empty()
            && self.rm_projects.is_empty()
            && self.tags.is_empty()
            && self.untags.is_empty()
            && self.entropy.choice().is_none()
    }
}

/// `cn rm`.
#[derive(Debug, Args)]
pub struct RmArgs {
    /// Secret names.
    #[arg(required = true, value_name = "NAME")]
    pub names: Vec<String>,
    /// Block until decided, up to DUR.
    #[arg(long, value_name = "DUR", num_args = 0..=1)]
    pub wait: Option<Option<Secs>>,
}

/// `cn import`.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("input").required(true).args(["glob", "from"])))]
pub struct ImportArgs {
    /// Files to import, relative to --dir.
    #[arg(long, value_name = "GLOB")]
    pub glob: Option<String>,
    /// Directory the glob is relative to (default: cwd).
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// TOML file with description, usage, projects and entropy per name.
    #[arg(long, value_name = "FILE")]
    pub metadata: Option<PathBuf>,
    /// Removed from each file name to make the secret name.
    #[arg(long, value_name = "PREFIX", default_value = ".secret-")]
    pub strip_prefix: String,
    /// Overwrite and unlink each source file after the import is approved.
    #[arg(long, conflicts_with = "keep")]
    pub shred: bool,
    /// Leave the source files.
    #[arg(long)]
    pub keep: bool,
    /// Print what would be imported; create no request.
    #[arg(long)]
    pub dry_run: bool,
    /// Block until decided, up to DUR.
    #[arg(long, value_name = "DUR", num_args = 0..=1)]
    pub wait: Option<Option<Secs>>,
    /// Restore an age backup (not in this version).
    #[arg(long, value_name = "BACKUP.age")]
    pub from: Option<PathBuf>,
}

/// `cn session`.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SessionArgs {
    /// `exec`.
    #[command(subcommand)]
    pub command: Option<SessionCommand>,
}

/// `cn session exec`.
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Register this process as a session anchor, then exec COMMAND (same pid).
    Exec {
        /// Label shown in approval displays.
        #[arg(long)]
        label: Option<String>,
        /// The command, after `--`.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
}

/// `cn audit`.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct AuditArgs {
    /// Filters.
    #[command(flatten)]
    pub query: AuditQueryArgs,
    /// `verify`, `checkpoints`, `pubkey`.
    #[command(subcommand)]
    pub command: Option<AuditCommand>,
}

/// Filters for `cn audit`.
#[derive(Debug, Args)]
pub struct AuditQueryArgs {
    /// Only this session.
    #[arg(long, conflicts_with = "session")]
    pub current: bool,
    /// Only session ID.
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,
    /// Only records about this secret.
    #[arg(long, value_name = "NAME")]
    pub secret: Option<String>,
    /// Only this event type. Repeatable.
    #[arg(long = "event", value_name = "KIND")]
    pub events: Vec<String>,
    /// RFC 3339 time, or a duration back from now (2h).
    #[arg(long, value_name = "TIME|DUR")]
    pub since: Option<String>,
    /// RFC 3339 time, or a duration back from now.
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,
    /// Most records (the newest).
    #[arg(long, value_name = "N", default_value_t = 50)]
    pub limit: u32,
    /// Keep printing new records.
    #[arg(long)]
    pub follow: bool,
}

/// `cn audit` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Recompute the hash chain locally.
    Verify(VerifyArgs),
    /// Print checkpoint records (not in this version).
    Checkpoints(LaterArgs),
    /// Print the checkpoint public key (not in this version).
    Pubkey(LaterArgs),
}

/// `cn audit verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// First sequence number to fetch.
    #[arg(long, value_name = "SEQ")]
    pub from: Option<u64>,
    /// Re-verify FIDO2 approvals (not in this version).
    #[arg(long)]
    pub approvals: bool,
    /// Checkpoint public key file (default: the daemon's checkpoint.pub).
    #[arg(long, value_name = "FILE")]
    pub pubkey: Option<PathBuf>,
    /// Exported checkpoints (JSONL) to compare with the chain.
    #[arg(long, value_name = "FILE")]
    pub checkpoints: Option<PathBuf>,
    /// Read the segment files from this directory instead of asking cnd
    /// (root, or the countersign user).
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,
}

/// True when the invocation's subcommand is `run`, whose errors exit 125.
pub fn is_run_invocation(args: &[OsString]) -> bool {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        let Some(s) = arg.to_str() else { return false };
        if s == "--" {
            return false;
        }
        if s == "--socket" {
            it.next();
            continue;
        }
        if s.starts_with('-') {
            continue;
        }
        return s == "run";
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("cn").chain(args.iter().copied()))
    }

    #[test]
    fn the_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_help_footer_lists_every_exit_code() {
        let footer = Cli::command()
            .get_after_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        let listed: Vec<&str> = footer
            .split([':', ','])
            .filter_map(|part| part.split_whitespace().next())
            .filter(|word| word.chars().all(|c| c.is_ascii_digit()))
            .collect();
        let expected: Vec<String> = (0..=14).map(|n| n.to_string()).collect();
        assert_eq!(listed, expected, "{footer}");
    }

    #[test]
    fn request_wait_takes_an_optional_duration() {
        let Command::Request(r) = parse(&["request", "db", "--reason", "x", "--wait"])
            .unwrap()
            .command
        else {
            panic!()
        };
        assert_eq!(r.wait, Some(None));
        assert_eq!(r.mode, ModeArg::Use);
        let Command::Request(r) = parse(&["request", "db", "--reason", "x", "--wait", "3m"])
            .unwrap()
            .command
        else {
            panic!()
        };
        assert_eq!(r.wait, Some(Some(Secs(180))));
        let Command::Request(r) = parse(&[
            "request", "a", "b", "--reason", "x", "--ttl", "1h30m", "--mode", "reveal",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(r.names, ["a", "b"]);
        assert_eq!(r.ttl, Some(Secs(5400)));
        assert_eq!(r.mode, ModeArg::Reveal);
        assert!(parse(&["request", "db"]).is_err(), "reason is required");
    }

    #[test]
    fn run_needs_uses_and_a_command_after_dashes() {
        let cli = parse(&[
            "--json", "run", "--use", "db", "--use", "gh=GH", "--", "env", "-0",
        ])
        .unwrap();
        assert!(cli.json);
        let Command::Run(r) = cli.command else {
            panic!()
        };
        assert_eq!(r.uses, ["db", "gh=GH"]);
        assert_eq!(r.command, ["env", "-0"]);
        assert!(parse(&["run", "--use", "db"]).is_err());
        assert!(parse(&["run", "--", "env"]).is_err());
    }

    #[test]
    fn revoke_needs_exactly_one_selector_kind() {
        assert!(parse(&["revoke"]).is_err());
        assert!(parse(&["revoke", "g_1", "g_2"]).is_ok());
        assert!(parse(&["revoke", "--all", "--all-sessions"]).is_ok());
        assert!(parse(&["revoke", "--secret", "db"]).is_ok());
        assert!(parse(&["revoke", "--all", "--secret", "db"]).is_err());
    }

    #[test]
    fn value_sources_are_exclusive() {
        assert!(parse(&["set", "db", "--from-stdin"]).is_ok());
        assert!(parse(&["set", "db", "--from-stdin", "--from-clipboard"]).is_err());
        assert!(
            parse(&[
                "add",
                "db",
                "--description",
                "d",
                "--high-entropy",
                "--low-entropy"
            ])
            .is_err()
        );
    }

    #[test]
    fn session_and_audit_take_optional_subcommands() {
        let Command::Session(s) = parse(&["session"]).unwrap().command else {
            panic!()
        };
        assert!(s.command.is_none());
        let Command::Session(s) = parse(&["session", "exec", "--label", "x", "--", "claude"])
            .unwrap()
            .command
        else {
            panic!()
        };
        assert!(
            matches!(s.command, Some(SessionCommand::Exec { ref command, .. }) if command == &["claude"])
        );
        let Command::Audit(a) =
            parse(&["audit", "--current", "--since", "1h", "--event", "reveal"])
                .unwrap()
                .command
        else {
            panic!()
        };
        assert!(a.query.current && a.command.is_none());
        assert!(matches!(
            parse(&["audit", "verify"]).unwrap().command,
            Command::Audit(AuditArgs {
                command: Some(AuditCommand::Verify(_)),
                ..
            })
        ));
    }

    #[test]
    fn later_commands_accept_anything() {
        assert!(parse(&["approver", "enroll", "--name", "desk-key"]).is_ok());
        assert!(parse(&["sudo", "--", "systemctl", "restart", "caddy"]).is_ok());
        assert!(parse(&["export", "--recipient", "age1xyz"]).is_ok());
    }

    #[test]
    fn detects_run_invocations() {
        let os = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(is_run_invocation(&os(&["cn", "run", "--use", "x"])));
        assert!(is_run_invocation(&os(&["cn", "--json", "run"])));
        assert!(is_run_invocation(&os(&["cn", "--socket", "/s", "run"])));
        assert!(!is_run_invocation(&os(&["cn", "list"])));
        assert!(!is_run_invocation(&os(&["cn", "--", "run"])));
    }
}
