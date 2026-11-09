//! What `cnd` asks of the kernel and of systemd: the kernel floor, peer
//! pidfds, process liveness, memory protection, socket activation and
//! `sd_notify`.
//!
//! Everything here is a safe wrapper except taking over the socket systemd
//! passes in, which is in [`listen_fd`].

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixStream};

use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{
    DumpableBehavior, Pid, PidfdFlags, Resource, getrlimit, pidfd_open, set_dumpable_behavior,
};

pub mod listen_fd;

/// The oldest kernel with `SO_PEERPIDFD` (decision 16).
const MIN_KERNEL: (u32, u32) = (6, 5);

/// Refuses a kernel older than 6.5, or one where `SO_PEERPIDFD` does not
/// work (a seccomp filter, a compatibility layer).
pub fn check_kernel() -> Result<(), String> {
    let uname = rustix::system::uname();
    let release = uname.release().to_string_lossy().into_owned();
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let version = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if version < MIN_KERNEL {
        return Err(format!(
            "Linux {release} is too old: cnd needs {}.{} or later for SO_PEERPIDFD",
            MIN_KERNEL.0, MIN_KERNEL.1
        ));
    }
    let (a, _b) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    peer_pidfd(&a).map_err(|e| format!("SO_PEERPIDFD does not work here: {e}"))?;
    Ok(())
}

/// A pidfd for the process at the other end of a connected Unix socket,
/// taken by the kernel at `connect()`.
pub fn peer_pidfd(sock: &impl AsFd) -> io::Result<OwnedFd> {
    getsockopt(sock, PeerPidfd).map_err(io::Error::from)
}

/// A pidfd for `pid`. Check afterwards that the process is the one meant
/// (its start time), because the pid may have been reused before the call.
pub fn open_pidfd(pid: u32) -> io::Result<OwnedFd> {
    let pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from)
}

/// Whether the process behind a pidfd has exited (the pidfd is readable).
pub fn pidfd_exited(fd: &OwnedFd) -> bool {
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    let zero = rustix::time::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    match poll(&mut fds, Some(&zero)) {
        Ok(0) => false,
        Ok(_) => true,
        // A pidfd that cannot be polled says nothing good about the process.
        Err(_) => true,
    }
}

/// No core dumps, no `/proc/PID/mem` or ptrace from other processes of the
/// `countersign` user.
pub fn set_not_dumpable() -> io::Result<()> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(io::Error::from)
}

/// Locks memory so values are not written to swap, without ever making an
/// allocation fail. Returns whether anything was locked, and a line for the
/// log.
///
/// With no `RLIMIT_MEMLOCK` limit, everything is locked, now and in future
/// (`MCL_FUTURE`). Under a limit (systemd's default is 8 MiB) `MCL_FUTURE`
/// would make any mapping beyond the limit fail, tokio's thread stacks
/// included, so only the pages mapped now are locked, as they are touched
/// (`MCL_ONFAULT`); if even that is over the limit, nothing is locked.
pub fn lock_memory() -> (bool, String) {
    let limit = getrlimit(Resource::Memlock).current;
    match limit {
        None => {
            match mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE | MlockAllFlags::ONFAULT)
            {
                Ok(()) => (true, "memory locked (no memlock limit)".into()),
                Err(e) => (false, format!("memory not locked: mlockall failed: {e}")),
            }
        }
        Some(bytes) => match mlockall(MlockAllFlags::CURRENT | MlockAllFlags::ONFAULT) {
            Ok(()) => (
                true,
                format!(
                    "memlock limit {} KiB: current mappings locked, later allocations are not; \
                     set LimitMEMLOCK=infinity to lock everything",
                    bytes / 1024
                ),
            ),
            Err(e) => (
                false,
                format!(
                    "memlock limit {} KiB: memory not locked ({e}); set LimitMEMLOCK=infinity \
                     to lock it",
                    bytes / 1024
                ),
            ),
        },
    }
}

/// `CLOCK_MONOTONIC` in microseconds, for `RELOADING=1`.
pub fn monotonic_usec() -> u64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(t.tv_sec).unwrap_or(0) * 1_000_000 + u64::try_from(t.tv_nsec).unwrap_or(0) / 1_000
}

/// Sends `state` (e.g. `READY=1`) to systemd's notification socket. Does
/// nothing when `cnd` was not started by systemd with `NOTIFY_SOCKET`.
pub fn notify(state: &str) -> io::Result<()> {
    match std::env::var_os("NOTIFY_SOCKET") {
        Some(path) => notify_to(&path.to_string_lossy(), state),
        None => Ok(()),
    }
}

/// Sends `state` to the notification socket at `path` (`@name` for an
/// abstract socket).
fn notify_to(path: &str, state: &str) -> io::Result<()> {
    let addr = match path.strip_prefix('@') {
        Some(name) => {
            use std::os::linux::net::SocketAddrExt;
            SocketAddr::from_abstract_name(name.as_bytes())?
        }
        None => SocketAddr::from_pathname(path)?,
    };
    let sock = UnixDatagram::unbound()?;
    sock.send_to_addr(state.as_bytes(), &addr)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_kernel_has_peer_pidfds() {
        // The test machine is the deployment target (Linux >= 6.5).
        check_kernel().unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        let fd = peer_pidfd(&a).unwrap();
        assert!(!pidfd_exited(&fd), "our own process is alive");
    }

    #[test]
    fn an_exited_child_reads_as_exited() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let fd = open_pidfd(child.id()).unwrap();
        child.wait().unwrap();
        assert!(pidfd_exited(&fd));
    }

    #[test]
    fn notify_without_systemd_is_a_no_op() {
        if std::env::var_os("NOTIFY_SOCKET").is_none() {
            notify("READY=1").unwrap();
        }
    }

    #[test]
    fn notify_reaches_a_datagram_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let server = UnixDatagram::bind(&path).unwrap();
        notify_to(path.to_str().unwrap(), "READY=1").unwrap();
        let mut buf = [0u8; 16];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }
}
