use std::path::Path;

use super::*;
use crate::config::Config;

const BOOT: &str = "5e1c9a07-1111-2222-3333-444455556666";
const ME: u32 = 1000;

/// A fake `/proc`.
struct FakeProc {
    dir: tempfile::TempDir,
}

impl FakeProc {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sys/kernel/random");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("boot_id"), format!("{BOOT}\n")).unwrap();
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Adds a process.
    fn add(&self, pid: u32, ppid: u32, start: u64, comm: &str, uid: u32, cmdline: &[&str]) {
        let d = self.root().join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("stat"),
            format!(
                "{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 {start} 1000 100 0"
            ),
        )
        .unwrap();
        std::fs::write(
            d.join("status"),
            format!("Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )
        .unwrap();
        let mut cl = cmdline.join("\0");
        if !cl.is_empty() {
            cl.push('\0');
        }
        std::fs::write(d.join("cmdline"), cl).unwrap();
    }

    fn remove(&self, pid: u32) {
        std::fs::remove_dir_all(self.root().join(pid.to_string())).unwrap();
    }

    /// systemd (1) -> tmux server (900, uid ME) -> fish (1200) -> claude
    /// (1300) -> bash (1400) -> cn (1500).
    fn agent_tree() -> Self {
        let p = Self::new();
        p.add(1, 0, 1, "systemd", 0, &["/sbin/init"]);
        p.add(900, 1, 50, "tmux: server", ME, &["tmux"]);
        p.add(1200, 900, 100, "fish", ME, &["-fish"]);
        p.add(1300, 1200, 200, "claude", ME, &["claude", "--resume"]);
        p.add(1400, 1300, 300, "bash", ME, &["/bin/bash", "-c", "cn list"]);
        p.add(1500, 1400, 301, "cn", ME, &["cn", "list"]);
        p
    }
}

fn discover(p: &FakeProc, anchors: &Anchors, pid: u32) -> Result<Session, SessionError> {
    let proc = ProcFs::new(p.root());
    let config = Config::default();
    Discovery {
        proc: &proc,
        anchors,
        matchers: &config.sessions.matchers,
    }
    .discover(pid, ME)
}

fn pids(s: &Session) -> Vec<u32> {
    s.chain.iter().map(|p| p.pid).collect()
}

#[test]
fn a_matcher_finds_the_agent() {
    let p = FakeProc::agent_tree();
    let s = discover(&p, &Anchors::new(), 1500).unwrap();
    assert_eq!(s.anchor.pid, 1300);
    assert_eq!(s.anchor.start_time, 200);
    assert_eq!(pids(&s), [1500, 1400, 1300]);
    assert_eq!(
        s.kind,
        AnchorKind::Matched {
            matcher: "comm = \"claude\"".into()
        }
    );
    assert_eq!(s.id, session_id("s_", BOOT, 1300, 200));
    assert!(s.id.starts_with("s_") && s.id.len() == 14);
    assert!(!s.registered() && !s.is_human());
}

#[test]
fn ids_are_stable_and_bound_to_boot_pid_and_start() {
    let a = session_id("s_", BOOT, 1300, 200);
    assert_eq!(a, session_id("s_", BOOT, 1300, 200));
    assert_ne!(a, session_id("s_", BOOT, 1300, 201));
    assert_ne!(a, session_id("s_", BOOT, 1301, 200));
    assert_ne!(a, session_id("s_", "another-boot", 1300, 200));
    // No ambiguity between pid and start time digits.
    assert_ne!(session_id("s_", BOOT, 12, 3), session_id("s_", BOOT, 1, 23));
    assert!(
        a[2..]
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    );
}

#[test]
fn a_registered_anchor_wins_over_a_nearer_matcher() {
    let p = FakeProc::agent_tree();
    // `cn session exec -- fish` registered the shell; claude runs below it.
    let mut anchors = Anchors::new();
    anchors.register(1200, 100, Some("orchestrator".into()));
    let s = discover(&p, &anchors, 1500).unwrap();
    assert_eq!(s.anchor.pid, 1200);
    assert_eq!(
        s.kind,
        AnchorKind::Registered {
            label: Some("orchestrator".into())
        }
    );
    assert_eq!(pids(&s), [1500, 1400, 1300, 1200]);
}

#[test]
fn the_nearest_registered_anchor_wins() {
    let p = FakeProc::agent_tree();
    let mut anchors = Anchors::new();
    anchors.register(1200, 100, None);
    anchors.register(1300, 200, None);
    let s = discover(&p, &anchors, 1500).unwrap();
    assert_eq!(s.anchor.pid, 1300);
    assert!(s.registered());
}

#[test]
fn a_registration_names_one_process_instance() {
    let p = FakeProc::agent_tree();
    let mut anchors = Anchors::new();
    // Registered with another start time: an earlier process with this pid.
    anchors.register(1200, 99, None);
    let s = discover(&p, &anchors, 1500).unwrap();
    assert_eq!(s.anchor.pid, 1300);
    assert!(!s.registered());
}

#[test]
fn a_cmdline_matcher_works() {
    let p = FakeProc::new();
    p.add(1, 0, 1, "systemd", 0, &[]);
    p.add(
        500,
        1,
        10,
        "node",
        ME,
        &["node", "/usr/lib/node_modules/.bin/codex", "exec"],
    );
    p.add(600, 500, 20, "cn", ME, &["cn", "list"]);
    let s = discover(&p, &Anchors::new(), 600).unwrap();
    assert_eq!(s.anchor.pid, 500);
}

#[test]
fn no_anchor_is_no_session_with_the_chain() {
    let p = FakeProc::new();
    p.add(1, 0, 1, "systemd", 0, &[]);
    p.add(1200, 1, 100, "fish", ME, &["-fish"]);
    p.add(1500, 1200, 300, "cn", ME, &["cn", "add", "x"]);
    let e = discover(&p, &Anchors::new(), 1500).unwrap_err();
    assert_eq!(e.code(), ErrorCode::NoSession);
    let SessionError::NoSession { chain } = e else {
        panic!("{e}")
    };
    assert_eq!(
        chain.iter().map(|p| p.pid).collect::<Vec<_>>(),
        [1500, 1200]
    );

    // The human pseudo session for mutations: anchored at the shell.
    let proc = ProcFs::new(p.root());
    let anchors = Anchors::new();
    let d = Discovery {
        proc: &proc,
        anchors: &anchors,
        matchers: &[],
    };
    let h = d.human_session(1500, ME).unwrap();
    assert!(h.is_human());
    assert_eq!(h.anchor.pid, 1200);
    assert_eq!(h.id, session_id("h_", BOOT, 1200, 100));
}

#[test]
fn the_walk_stops_at_a_uid_change() {
    let p = FakeProc::new();
    p.add(1, 0, 1, "systemd", 0, &[]);
    // A root-owned "claude" above sshd must not become the anchor.
    p.add(700, 1, 5, "claude", 0, &["claude"]);
    p.add(800, 700, 10, "sshd", 0, &["sshd: patrick"]);
    p.add(1200, 800, 100, "fish", ME, &["-fish"]);
    p.add(1500, 1200, 300, "cn", ME, &["cn"]);
    let e = discover(&p, &Anchors::new(), 1500).unwrap_err();
    let SessionError::NoSession { chain } = e else {
        panic!("{e}")
    };
    assert_eq!(chain.len(), 2);
}

#[test]
fn a_reparented_orphan_has_no_session() {
    let p = FakeProc::agent_tree();
    // A double-forked daemon whose parent exited, now under pid 1.
    p.add(1600, 1, 400, "sleep", ME, &["sleep", "inf"]);
    p.add(1700, 1600, 401, "cn", ME, &["cn", "run"]);
    assert!(matches!(
        discover(&p, &Anchors::new(), 1700),
        Err(SessionError::NoSession { .. })
    ));
}

#[test]
fn pid_reuse_fails_closed() {
    let p = FakeProc::agent_tree();
    // The parent 1400 exited and an unrelated process took its pid later.
    p.remove(1400);
    p.add(1400, 1300, 999, "bash", ME, &["bash"]);
    let e = discover(&p, &Anchors::new(), 1500).unwrap_err();
    assert!(matches!(e, SessionError::ChainChanged(1400)), "{e}");
    assert_eq!(e.code(), ErrorCode::NoSession);
}

#[test]
fn a_vanished_parent_fails_closed() {
    let p = FakeProc::agent_tree();
    p.remove(1400);
    assert!(matches!(
        discover(&p, &Anchors::new(), 1500),
        Err(SessionError::ChainChanged(1400))
    ));
}

#[test]
fn a_dead_or_foreign_peer_is_refused() {
    let p = FakeProc::agent_tree();
    assert!(matches!(
        discover(&p, &Anchors::new(), 4242),
        Err(SessionError::Proc(ProcError::Gone(4242)))
    ));
    p.add(1800, 1300, 500, "cn", 1001, &["cn"]);
    let e = discover(&p, &Anchors::new(), 1800).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ForbiddenPeer);
}

#[test]
fn the_walk_is_bounded() {
    let p = FakeProc::new();
    p.add(1, 0, 1, "systemd", 0, &[]);
    p.add(2, 1, 2, "claude", ME, &["claude"]);
    for pid in 3..100u32 {
        p.add(pid, pid - 1, u64::from(pid), "sh", ME, &["sh"]);
    }
    // The anchor at pid 2 is more than 64 steps above pid 99.
    assert!(discover(&p, &Anchors::new(), 99).is_err());
    assert_eq!(discover(&p, &Anchors::new(), 60).unwrap().anchor.pid, 2);
}

#[test]
fn comm_with_parens_and_spaces_is_read_whole() {
    let p = FakeProc::new();
    p.add(1, 0, 1, "systemd", 0, &[]);
    p.add(500, 1, 10, "claude", ME, &["claude"]);
    p.add(600, 500, 20, "evil) S 1 (x", ME, &["x"]);
    p.add(700, 600, 30, "cn", ME, &["cn"]);
    let s = discover(&p, &Anchors::new(), 700).unwrap();
    assert_eq!(s.anchor.pid, 500);
    assert_eq!(s.chain[1].comm, "evil) S 1 (x");
    assert_eq!(s.chain[1].ppid, 500);
}

#[test]
fn audit_views_carry_the_anchor() {
    let p = FakeProc::agent_tree();
    let s = discover(&p, &Anchors::new(), 1500).unwrap();
    let r = s.audit_ref(&BTreeMap::new());
    assert_eq!(
        (r.anchor_pid, r.anchor_comm.as_str(), r.registered),
        (1300, "claude", false)
    );
    let links = s.chain_links();
    assert_eq!(links.last().unwrap().comm, "claude");
}

#[test]
fn labels_are_filtered_and_bounded() {
    let env = vec!["CLAUDE_CODE_SESSION_ID".to_owned(), "X".to_owned()];
    let labels = BTreeMap::from([
        (
            "CLAUDE_CODE_SESSION_ID".to_owned(),
            format!("9f3c\u{1b}[2J{}", "a".repeat(200)),
        ),
        ("OTHER".to_owned(), "dropped".to_owned()),
        ("X".to_owned(), "naïve value".to_owned()),
    ]);
    let out = filter_labels(&env, &labels);
    assert_eq!(out.len(), 2);
    let v = &out["CLAUDE_CODE_SESSION_ID"];
    assert_eq!(v.len(), MAX_LABEL_LEN);
    assert!(v.starts_with("9f3c[2Jaaa"));
    assert_eq!(out["X"], "nave value");
}
