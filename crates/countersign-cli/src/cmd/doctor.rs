//! `cn doctor`, Phase 1 subset: binary, kernel, group membership, daemon,
//! session, polkit agent, environment, leftover `.secret-*` files. The
//! privilege audit (paths from the agent's uid to root) is Phase 2.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use serde::Serialize;
use serde_json::json;

use crate::client::{self, Client, DAEMON_USER};
use crate::error::CnError;
use crate::output::{Ctx, Done, clean_line};
use crate::sys;

/// The socket group.
const SOCKET_GROUP: &str = "countersign-users";
/// Oldest kernel `cnd` runs on (`SO_PEERPIDFD`).
const MIN_KERNEL: (u32, u32) = (6, 5);
/// `/proc/PID/comm` of known polkit authentication agents (15 characters
/// at most, as the kernel truncates).
const POLKIT_AGENTS: &[&str] = &[
    "gnome-shell",
    "polkit-gnome-au",
    "polkit-kde-auth",
    "polkit-mate-aut",
    "lxpolkit",
    "lxqt-policykit-",
    "xfce-polkit",
    "hyprpolkitagent",
    "polkit-agent",
    "soteria",
    "cosmic-osd",
];

/// One check result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Check {
    /// Short name.
    pub name: &'static str,
    /// `ok`, `warn` or `fail`.
    pub status: &'static str,
    /// What was found.
    pub message: String,
    /// What to do, for `warn` and `fail`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

fn ok(name: &'static str, message: impl Into<String>) -> Check {
    Check {
        name,
        status: "ok",
        message: message.into(),
        fix: None,
    }
}

fn warn(name: &'static str, message: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        name,
        status: "warn",
        message: message.into(),
        fix: Some(fix.into()),
    }
}

fn fail(name: &'static str, message: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        name,
        status: "fail",
        message: message.into(),
        fix: Some(fix.into()),
    }
}

/// `6.5.0-1-default` to `(6, 5)`.
pub fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()?;
    Some((major, minor))
}

fn check_binary() -> Check {
    let installed = Path::new("/usr/bin/cn");
    let running = std::env::current_exe().ok();
    match fs::metadata(installed) {
        Err(_) => warn(
            "binary",
            "/usr/bin/cn is not installed",
            "install countersign with packaging/install.sh",
        ),
        Ok(m) if m.uid() != 0 || m.permissions().mode() & 0o022 != 0 => fail(
            "binary",
            format!(
                "/usr/bin/cn is owned by uid {} with mode {:o}",
                m.uid(),
                m.permissions().mode() & 0o7777
            ),
            "reinstall: it must be root-owned and not group- or world-writable",
        ),
        Ok(_) if running.as_deref() != Some(installed) => warn(
            "binary",
            format!(
                "running {}, not /usr/bin/cn",
                running.map_or_else(|| "an unknown path".into(), |p| p.display().to_string())
            ),
            "humans should type /usr/bin/cn for approve, add, set, edit, rm and import",
        ),
        Ok(_) => ok("binary", "/usr/bin/cn, root-owned"),
    }
}

fn check_kernel() -> Check {
    let uname = rustix::system::uname();
    let release = uname.release().to_string_lossy().into_owned();
    match kernel_version(&release) {
        Some(v) if v >= MIN_KERNEL => ok("kernel", format!("Linux {release}")),
        Some(_) => fail(
            "kernel",
            format!("Linux {release} is older than 6.5"),
            "cnd needs SO_PEERPIDFD (Linux 6.5 or later)",
        ),
        None => warn(
            "kernel",
            format!("cannot read the kernel version from {release:?}"),
            "cnd needs Linux 6.5 or later",
        ),
    }
}

fn check_group() -> Check {
    let Some((gid, members)) = sys::group(SOCKET_GROUP) else {
        return fail(
            "group",
            format!("the {SOCKET_GROUP} group does not exist"),
            "install countersign with packaging/install.sh",
        );
    };
    let uid = rustix::process::getuid().as_raw();
    let in_process = rustix::process::getgid().as_raw() == gid
        || rustix::process::getgroups()
            .map(|g| g.iter().any(|g| g.as_raw() == gid))
            .unwrap_or(false);
    let user = sys::user_name(uid).unwrap_or_default();
    if in_process {
        ok("group", format!("member of {SOCKET_GROUP}"))
    } else if members.contains(&user) {
        warn(
            "group",
            format!("{user} is in {SOCKET_GROUP}, but this login session predates it"),
            "log out and in again (or start a new login shell)",
        )
    } else {
        fail(
            "group",
            format!("{user} is not in {SOCKET_GROUP}, so the socket refuses you"),
            format!("sudo usermod -aG {SOCKET_GROUP} {user}, then log in again"),
        )
    }
}

fn check_daemon(ctx: &Ctx) -> (Check, Option<Client>) {
    match Client::connect(ctx) {
        Ok(c) => {
            let msg = format!(
                "{} at {}, protocol {}",
                clean_line(&c.server),
                c.path.display(),
                c.protocol
            );
            (ok("daemon", msg), Some(c))
        }
        Err(e) => {
            let (path, _) = client::socket_path(ctx);
            let fix = match e.code.as_str() {
                "bad_peer" => format!(
                    "the socket is not served by the {DAEMON_USER} user; check for a fake socket and reinstall"
                ),
                "daemon_unreachable" if !path.exists() => {
                    "sudo systemctl enable --now countersign.socket".into()
                }
                "daemon_unreachable" => e.hint.clone().unwrap_or_else(|| {
                    "sudo systemctl status countersign.socket countersign.service".into()
                }),
                _ => e
                    .hint
                    .clone()
                    .unwrap_or_else(|| "see the daemon log".into()),
            };
            (
                fail(
                    "daemon",
                    format!("{}: {}", e.code, clean_line(&e.message)),
                    fix,
                ),
                None,
            )
        }
    }
}

fn check_session(client: Option<&Client>) -> Check {
    let Some(client) = client else {
        return warn(
            "session",
            "not checked (no daemon)",
            "fix the daemon check first",
        );
    };
    match &client.session {
        Some(s) if s.anchor.registered => ok(
            "session",
            format!(
                "{} anchored at {} pid {} (registered by cn session exec)",
                clean_line(&s.id),
                clean_line(&s.anchor.comm),
                s.anchor.pid
            ),
        ),
        Some(s) => ok(
            "session",
            format!(
                "{} anchored at {} pid {} (found by a matcher; cn session exec is preferred)",
                clean_line(&s.id),
                clean_line(&s.anchor.comm),
                s.anchor.pid
            ),
        ),
        None => warn(
            "session",
            "no session anchor above this shell (no_session)",
            "start the agent with: cn session exec -- AGENT",
        ),
    }
}

fn check_polkit_agent() -> Check {
    let uid = rustix::process::getuid().as_raw();
    let found = fs::read_dir("/proc").ok().and_then(|entries| {
        entries.flatten().find_map(|e| {
            let name = e.file_name();
            let pid = name.to_str()?;
            if !pid.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            if fs::metadata(e.path()).ok()?.uid() != uid {
                return None;
            }
            let comm = fs::read_to_string(e.path().join("comm")).ok()?;
            let comm = comm.trim_end();
            POLKIT_AGENTS.contains(&comm).then(|| comm.to_owned())
        })
    });
    match found {
        Some(comm) => ok("polkit", format!("authentication agent candidate: {comm}")),
        None => warn(
            "polkit",
            "no polkit authentication agent found among your processes",
            "approval dialogs need a graphical session with a polkit agent (GNOME Shell has one)",
        ),
    }
}

fn check_environment() -> Vec<Check> {
    let mut out = Vec::new();
    if std::env::var("XDG_SESSION_TYPE").is_ok_and(|t| t == "x11") {
        out.push(warn(
            "x11",
            "X11 session: any client can synthesize input to the polkit dialog",
            "use a Wayland session",
        ));
    }
    match fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(v) if v.trim() == "0" => out.push(warn(
            "ptrace",
            "kernel.yama.ptrace_scope is 0: any process of your uid can attach to a cn run child",
            "sysctl kernel.yama.ptrace_scope=1",
        )),
        _ => out.push(ok("ptrace", "kernel.yama.ptrace_scope is not 0")),
    }
    out
}

fn check_leftovers() -> Check {
    let count = fs::read_dir(".")
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(".secret-"))
                .count()
        })
        .unwrap_or(0);
    if count == 0 {
        ok("leftovers", "no .secret-* files in the current directory")
    } else {
        warn(
            "leftovers",
            format!("{count} .secret-* file(s) in the current directory"),
            "/usr/bin/cn import --glob '.secret-*' --dry-run, then import and rotate them",
        )
    }
}

/// `cn doctor`.
pub fn doctor(ctx: &Ctx) -> Result<Done, CnError> {
    let mut checks = vec![check_binary(), check_kernel(), check_group()];
    let (daemon, client) = check_daemon(ctx);
    checks.push(daemon);
    checks.push(check_session(client.as_ref()));
    checks.push(check_polkit_agent());
    checks.extend(check_environment());
    checks.push(check_leftovers());

    let failures = checks.iter().filter(|c| c.status == "fail").count();
    let mut text = String::new();
    for c in &checks {
        text.push_str(&format!("{:<5} {:<10} {}\n", c.status, c.name, c.message));
        if let Some(fix) = &c.fix {
            text.push_str(&format!("{:<16} fix: {fix}\n", ""));
        }
    }
    text.push_str(
        "not checked in this version: privilege audit, polkit policy and PAM, audit chain\n",
    );
    let data = json!({"checks": checks, "failures": failures});
    let failure = (failures > 0).then(|| {
        CnError::new(
            "doctor_failed",
            format!(
                "{failures} check{} failed",
                if failures == 1 { "" } else { "s" }
            ),
        )
    });
    Ok(Done::Report {
        data,
        text,
        failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_versions_parse() {
        assert_eq!(kernel_version("7.3.0-1-default"), Some((7, 3)));
        assert_eq!(kernel_version("6.5.0"), Some((6, 5)));
        assert_eq!(kernel_version("6.10rc1"), Some((6, 10)));
        assert_eq!(kernel_version("garbage"), None);
        assert!((6, 4) < MIN_KERNEL && (6, 10) >= MIN_KERNEL && (7, 0) >= MIN_KERNEL);
    }
}
