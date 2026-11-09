//! The listening socket systemd passes with socket activation
//! (`sd_listen_fds(3)`): fd 3, announced by `LISTEN_FDS` and `LISTEN_PID`.
//!
//! The one place in `cnd` that needs `unsafe`: turning a raw descriptor
//! number into an owned socket.

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};

/// `SD_LISTEN_FDS_START`.
const FIRST_FD: i32 = 3;

static TAKEN: AtomicBool = AtomicBool::new(false);

/// Takes the socket systemd passed, if `LISTEN_PID` names this process and
/// `LISTEN_FDS` is 1. Returns `Ok(None)` when `cnd` was not socket
/// activated. Works once per process.
pub fn take() -> Result<Option<UnixListener>, String> {
    let (Some(pid), Some(fds)) = (
        std::env::var_os("LISTEN_PID"),
        std::env::var_os("LISTEN_FDS"),
    ) else {
        return Ok(None);
    };
    if pid.to_str().and_then(|p| p.parse::<u32>().ok()) != Some(std::process::id()) {
        return Ok(None);
    }
    match fds.to_str().and_then(|n| n.parse::<u32>().ok()) {
        Some(1) => {}
        Some(n) => {
            return Err(format!(
                "systemd passed {n} sockets; cnd expects exactly one"
            ));
        }
        None => return Err("LISTEN_FDS is not a number".into()),
    }
    if TAKEN.swap(true, Ordering::SeqCst) {
        return Err("the activation socket was already taken".into());
    }
    #[expect(
        unsafe_code,
        reason = "fd 3 is handed over by systemd; std has no safe constructor for it"
    )]
    // SAFETY: systemd's socket activation protocol gives this process (we
    // checked LISTEN_PID) exactly one open descriptor at fd 3 (we checked
    // LISTEN_FDS), and nothing else in cnd uses fd 3. TAKEN makes sure it is
    // wrapped, and so closed on drop, only once.
    let fd = unsafe { OwnedFd::from_raw_fd(FIRST_FD) };
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC).map_err(|e| format!("fd 3: {e}"))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| format!("fd 3: {e}"))?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::Socket {
        return Err("fd 3 from systemd is not a socket".into());
    }
    Ok(Some(UnixListener::from(fd)))
}
