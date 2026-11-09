//! Session liveness (design.md section 5): one thread waits in `epoll` on
//! the pidfd of every session anchor. A pidfd becomes readable when its
//! process exits, and the session ends then.

use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use rustix::buffer::spare_capacity;
use rustix::event::epoll;

/// The anchors being watched.
pub struct Watcher {
    epoll: OwnedFd,
    anchors: Mutex<HashMap<u64, (OwnedFd, String)>>,
    next: AtomicU64,
}

impl Watcher {
    /// An empty watcher.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            epoll: epoll::create(epoll::CreateFlags::CLOEXEC)?,
            anchors: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    /// Watches an anchor's pidfd for `session`.
    pub fn watch(&self, pidfd: OwnedFd, session: String) -> io::Result<()> {
        let token = self.next.fetch_add(1, Ordering::Relaxed);
        let mut anchors = self.anchors.lock().unwrap_or_else(PoisonError::into_inner);
        epoll::add(
            &self.epoll,
            &pidfd,
            epoll::EventData::new_u64(token),
            epoll::EventFlags::IN | epoll::EventFlags::ONESHOT,
        )?;
        anchors.insert(token, (pidfd, session));
        Ok(())
    }

    /// Waits for anchors to exit and calls `ended` with each one's session
    /// id. Runs for the life of the process.
    pub fn run(&self, ended: impl Fn(&str)) {
        let mut events = Vec::with_capacity(16);
        loop {
            events.clear();
            match epoll::wait(&self.epoll, spare_capacity(&mut events), None) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => {
                    crate::log::error!("anchor watcher: epoll_wait: {e}");
                    return;
                }
            }
            for ev in &events {
                let token = ev.data.u64();
                let gone = self
                    .anchors
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&token);
                if let Some((fd, session)) = gone {
                    let _ = epoll::delete(&self.epoll, &fd);
                    drop(fd);
                    ended(&session);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn an_exiting_anchor_ends_its_session() {
        let w = Arc::new(Watcher::new().unwrap());
        let (tx, rx) = mpsc::channel();
        let runner = w.clone();
        std::thread::spawn(move || runner.run(|s| tx.send(s.to_owned()).unwrap()));
        let mut child = std::process::Command::new("sleep")
            .arg("0.2")
            .spawn()
            .unwrap();
        let fd = crate::sys::open_pidfd(child.id()).unwrap();
        w.watch(fd, "s_test".into()).unwrap();
        let ended = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(ended, "s_test");
        child.wait().unwrap();
    }
}
