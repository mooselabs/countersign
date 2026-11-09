//! Reading `/proc`, or a directory laid out like it for tests.
//!
//! Only world-readable files are used (`stat`, `status`, `cmdline`), because
//! `cnd` runs as another uid with no capabilities (design.md section 2).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// What `cnd` knows about one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process id.
    pub pid: u32,
    /// Parent process id (field 4 of `stat`).
    pub ppid: u32,
    /// Start time in clock ticks since boot (field 22 of `stat`).
    pub start_time: u64,
    /// `comm`, as the process set it.
    pub comm: String,
    /// Real uid.
    pub uid: u32,
    /// Effective uid.
    pub euid: u32,
}

/// A `/proc` read that failed.
#[derive(Debug, thiserror::Error)]
pub enum ProcError {
    /// The process does not exist (or exited).
    #[error("process {0} is gone")]
    Gone(u32),
    /// A file did not have the expected format.
    #[error("/proc/{0}: unexpected format")]
    Format(u32),
    /// Any other read error.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
}

/// The `/proc` root.
#[derive(Debug, Clone)]
pub struct ProcFs {
    root: PathBuf,
}

impl Default for ProcFs {
    fn default() -> Self {
        Self::new("/proc")
    }
}

/// `USER_HZ`: the unit of `stat` times on every Linux ABI countersign runs on.
const USER_HZ: u64 = 100;

impl ProcFs {
    /// A `/proc`-like tree at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn read(&self, pid: u32, file: &str) -> Result<Vec<u8>, ProcError> {
        let path = self.root.join(pid.to_string()).join(file);
        std::fs::read(&path).map_err(|source| match source.kind() {
            // ESRCH shows up as NotFound or as a read error on a dead pid.
            std::io::ErrorKind::NotFound => ProcError::Gone(pid),
            _ if source.raw_os_error() == Some(3) => ProcError::Gone(pid),
            _ => ProcError::Io { path, source },
        })
    }

    /// Reads `stat` and `status` of a process.
    pub fn process(&self, pid: u32) -> Result<ProcInfo, ProcError> {
        let stat = self.read(pid, "stat")?;
        let (comm, ppid, start_time) = parse_stat(&stat).ok_or(ProcError::Format(pid))?;
        let status = self.read(pid, "status")?;
        let (uid, euid) = parse_uids(&status).ok_or(ProcError::Format(pid))?;
        Ok(ProcInfo {
            pid,
            ppid,
            start_time,
            comm,
            uid,
            euid,
        })
    }

    /// `cmdline`: NUL-separated arguments as the process set them.
    pub fn cmdline(&self, pid: u32) -> Result<Vec<u8>, ProcError> {
        self.read(pid, "cmdline")
    }

    /// The process's login session id (`sessionid`, the audit session that
    /// logind names its sessions by), or `None` outside a login session.
    pub fn login_session(&self, pid: u32) -> Option<String> {
        let text = String::from_utf8(self.read(pid, "sessionid").ok()?).ok()?;
        let id: u32 = text.trim().parse().ok()?;
        // (u32)-1 is AUDIT_SID_UNSET.
        (id != u32::MAX).then(|| id.to_string())
    }

    /// The boot id from `sys/kernel/random/boot_id`, trimmed.
    pub fn boot_id(&self) -> Result<String, ProcError> {
        let path = self.root.join("sys/kernel/random/boot_id");
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_owned())
            .map_err(|source| ProcError::Io { path, source })
    }

    /// The wall-clock time a process started, from `btime` in `stat` and
    /// its start ticks. For display only.
    pub fn started_at(&self, start_time: u64) -> Option<SystemTime> {
        let stat = std::fs::read_to_string(self.root.join("stat")).ok()?;
        let btime: u64 = stat
            .lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()?;
        Some(
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(btime)
                + Duration::from_millis(start_time * 1000 / USER_HZ),
        )
    }
}

/// Parses `comm`, `ppid` and `starttime` from `/proc/PID/stat`.
///
/// `comm` sits in parentheses and may itself contain spaces and
/// parentheses, so the fixed fields are read after the *last* `)`.
pub fn parse_stat(stat: &[u8]) -> Option<(String, u32, u64)> {
    let open = stat.iter().position(|&b| b == b'(')?;
    let close = stat.iter().rposition(|&b| b == b')')?;
    if close < open {
        return None;
    }
    let comm = String::from_utf8_lossy(&stat[open + 1..close]).into_owned();
    let rest = std::str::from_utf8(&stat[close + 1..]).ok()?;
    let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
    // fields[0] is field 3 (state), so field N is fields[N - 3].
    let ppid = fields.get(1)?.parse().ok()?;
    let start_time = fields.get(19)?.parse().ok()?;
    Some((comm, ppid, start_time))
}

fn parse_uids(status: &[u8]) -> Option<(u32, u32)> {
    let s = std::str::from_utf8(status).ok()?;
    let line = s.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    let mut it = line.split_ascii_whitespace();
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parses_awkward_comm() {
        let s = b"41210 (my (odd) ) prog) S 41000 41210 41000 34816 41210 4194304 1 2 3 4 5 6 7 8 20 0 12 0 8812345 1000 200 18446744073709551615";
        assert_eq!(
            parse_stat(s),
            Some(("my (odd) ) prog".into(), 41000, 8_812_345))
        );
        assert_eq!(parse_stat(b"1 (init) S"), None);
        assert_eq!(parse_stat(b"garbage"), None);
        assert_eq!(parse_stat(b"1 )x( S 0"), None);
    }

    #[test]
    fn uids_come_from_status() {
        let s = b"Name:\tbash\nUid:\t1000\t0\t1000\t1000\nGid:\t100\t100\t100\t100\n";
        assert_eq!(parse_uids(s), Some((1000, 0)));
        assert_eq!(parse_uids(b"Name:\tx\n"), None);
    }

    #[test]
    fn the_real_proc_is_readable() {
        let p = ProcFs::default();
        let me = p.process(std::process::id()).unwrap();
        assert_eq!(me.pid, std::process::id());
        assert!(me.start_time > 0);
        assert_eq!(p.boot_id().unwrap().len(), 36);
        let started = p.started_at(me.start_time).unwrap();
        let age = SystemTime::now()
            .duration_since(started)
            .unwrap_or_default();
        assert!(age < Duration::from_secs(3600), "{age:?}");
        assert!(matches!(p.process(u32::MAX - 1), Err(ProcError::Gone(_))));
    }
}
