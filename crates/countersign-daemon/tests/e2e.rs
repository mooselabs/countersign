//! End-to-end: the real `cnd` (insecure-test build) on a temporary state
//! directory and socket, driven by the real `cn`.
//!
//! Each test starts its own daemon with `--insecure-mk-file` and the
//! `insecure-auto` approver (or polkit against a fake authority on a
//! private bus). Sessions: a `comm` matcher makes this test process the
//! anchor of every `cn` it runs; the anchor-exit test uses
//! `cn session exec` instead. Sockets are relative paths, because
//! temporary directories can be longer than a socket path may be.
//!
//! Nothing here touches the system bus, polkitd, /etc or systemd.

#![cfg(feature = "insecure-test")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

const V_DB: &str = "s3cret-db-value-e2e-0123456789";
const V_API: &str = "lowentropy-api-v2";
const V_DB2: &str = "rotated-db-value-e2e-9876543210";
const V_FILE: &str = "imported-from-a-file-555666777";

fn cnd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cnd"))
}

fn cn_bin() -> PathBuf {
    let p = cnd_bin().with_file_name("cn");
    assert!(
        p.exists(),
        "{} is missing: build it first (cargo build -p countersign-cli --all-features)",
        p.display()
    );
    p
}

/// This process's `comm`, which the daemon's matcher accepts, so this
/// process is the anchor of every `cn` it runs.
fn my_comm() -> String {
    std::fs::read_to_string("/proc/self/comm")
        .unwrap()
        .trim()
        .to_owned()
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// A running `cnd` and its state directory.
struct Cnd {
    dir: tempfile::TempDir,
    child: Option<Child>,
    phrase: String,
    extra_args: Vec<String>,
}

impl Cnd {
    /// Writes the config (access and the matcher, then `body`), runs
    /// `cnd init` and starts the daemon.
    fn start(body: &str) -> Self {
        Self::start_with(body, &[])
    }

    fn start_with(body: &str, extra_args: &[String]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        write_key(&dir.path().join("mk"));
        let config = format!(
            "[access]\nusers = [\"{}\"]\n\n[sessions]\nmatchers = [{{ comm = \"{}\" }}]\n\n{body}",
            uid(),
            my_comm()
        );
        std::fs::write(dir.path().join("config.toml"), config).unwrap();
        let out = Command::new(cnd_bin())
            .args(base_args("mk"))
            .arg("init")
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "cnd init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        let phrase = text
            .lines()
            .find_map(|l| l.strip_prefix("    "))
            .expect("init prints the phrase indented")
            .trim()
            .to_owned();
        let mut cnd = Cnd {
            dir,
            child: None,
            phrase,
            extra_args: extra_args.to_vec(),
        };
        cnd.spawn("mk").expect("cnd starts");
        cnd
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Starts `cnd` with this master key file; waits for its socket.
    fn spawn(&mut self, mk: &str) -> Result<(), String> {
        let _ = std::fs::remove_file(self.path().join("sock"));
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path().join("cnd.log"))
            .unwrap();
        let mut child = Command::new(cnd_bin())
            .args(base_args(mk))
            .args(["--socket", "sock"])
            .args(&self.extra_args)
            .current_dir(self.path())
            .stdin(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                return Err(format!("cnd exited: {status}; log:\n{}", self.log()));
            }
            if self.path().join("sock").exists() {
                self.child = Some(child);
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        Err(format!("cnd did not start; log:\n{}", self.log()))
    }

    /// SIGTERM, then wait.
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = rustix::process::Pid::from_child(&child);
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            let _ = child.wait();
        }
    }

    fn signal(&self, sig: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_child(self.child.as_ref().unwrap());
        rustix::process::kill_process(pid, sig).unwrap();
    }

    /// One request on a raw connection, after `hello`; the response as JSON.
    fn raw_call(&self, req: countersign_proto::Request) -> Value {
        use countersign_proto::{Envelope, Request, write_message};
        let mut s = std::os::unix::net::UnixStream::connect(self.path().join("sock")).unwrap();
        let hello = Request::Hello {
            protocols: vec![1],
            client: "e2e".into(),
            labels: Default::default(),
            cwd: None,
        };
        write_message(&mut s, &Envelope { id: 1, body: hello }).unwrap();
        countersign_proto::read_frame(&mut s).unwrap().unwrap();
        write_message(&mut s, &Envelope { id: 2, body: req }).unwrap();
        let (_, body) = countersign_proto::read_frame(&mut s).unwrap().unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path().join("cnd.log")).unwrap_or_default()
    }

    fn cn(&self, args: &[&str]) -> Output {
        self.cn_in(args, b"")
    }

    fn cn_in(&self, args: &[&str], stdin: &[u8]) -> Output {
        self.cn_env(args, stdin, &[])
    }

    fn cn_env(&self, args: &[&str], stdin: &[u8], env: &[(&str, &str)]) -> Output {
        let mut child = Command::new(cn_bin())
            .args(["--socket", "sock"])
            .args(args)
            .current_dir(self.path())
            .env_remove("COUNTERSIGN_SOCKET")
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Write stdin on its own thread: cn may write output before it has
        // read all its input, and a large input would then deadlock.
        let mut pipe = child.stdin.take().unwrap();
        let input = stdin.to_vec();
        let writer = std::thread::spawn(move || {
            // cn may exit without reading everything; that is its business.
            let _ = pipe.write_all(&input);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        out
    }

    /// Runs `cn`, asserts the exit code, returns stdout.
    fn ok(&self, args: &[&str]) -> String {
        self.expect(args, b"", 0)
    }

    fn expect(&self, args: &[&str], stdin: &[u8], code: i32) -> String {
        let out = self.cn_in(args, stdin);
        assert_eq!(
            out.status.code(),
            Some(code),
            "cn {args:?}\nstdout: {}\nstderr: {}\ncnd log:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            self.log()
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        serde_json::from_str(&self.ok(&a)).unwrap()
    }

    /// Every audit record, read from the files.
    fn audit_records(&self) -> Vec<Value> {
        let dir = self.path().join("state/audit");
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".jsonl"))
            .collect();
        names.sort();
        names
            .iter()
            .flat_map(|n| {
                std::fs::read_to_string(dir.join(n))
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect::<Vec<Value>>()
            })
            .collect()
    }

    fn events(&self) -> Vec<String> {
        self.audit_records()
            .iter()
            .map(|r| r["event"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Waits until the audit log has a record for which `f` is true.
    fn wait_for_record(&self, f: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(r) = self.audit_records().into_iter().find(|r| f(r)) {
                return r;
            }
            assert!(
                Instant::now() < deadline,
                "record not found; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Cnd {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn base_args(mk: &str) -> Vec<String> {
    [
        "--config",
        "config.toml",
        "--state-dir",
        "state",
        "--insecure-mk-file",
        mk,
    ]
    .map(str::to_owned)
    .to_vec()
}

fn write_key(path: &Path) {
    let mut key = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut key)
        .unwrap();
    std::fs::write(path, key).unwrap();
}

/// Every approval kind approved at once by insecure-auto.
const APPROVE_ALL: &str = r#"
[approval]
use = "auto"
reveal = "auto"
mutate = "auto"
export = "auto"

[approvers.auto]
type = "insecure-auto"
delay = "0s"
"#;

fn add(cnd: &Cnd, name: &str, value: &str, entropy: &str) {
    cnd.expect(
        &[
            "add",
            name,
            "--description",
            "an e2e secret",
            "--from-stdin",
            entropy,
            "--wait",
        ],
        value.as_bytes(),
        0,
    );
}

/// Files under `dir` whose bytes contain `needle`.
fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            hits.extend(files_containing(&p, needle));
        } else if let Ok(bytes) = std::fs::read(&p) {
            if bytes.windows(needle.len()).any(|w| w == needle) {
                hits.push(p);
            }
        }
    }
    hits
}

#[test]
fn the_whole_flow() {
    let mut cnd = Cnd::start(APPROVE_ALL);

    // Store changes go through the mutate chain.
    add(&cnd, "db-pass", V_DB, "--high-entropy");
    add(&cnd, "api-key", V_API, "--low-entropy");
    let out = cnd.cn_in(
        &[
            "add",
            "db-pass",
            "--description",
            "again",
            "--from-stdin",
            "--high-entropy",
            "--wait",
        ],
        V_DB.as_bytes(),
    );
    assert_eq!(out.status.code(), Some(2), "a second add is secret_exists");
    assert!(String::from_utf8_lossy(&out.stderr).contains("secret_exists"));

    // list and show: metadata, never values.
    let list = cnd.json(&["list"]);
    let names: Vec<&str> = list["data"]["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["api-key", "db-pass"]);
    assert!(!list.to_string().contains(V_DB));
    cnd.ok(&["show", "db-pass"]);

    // No grant yet: run refuses (exit 125, grant_required).
    let out = cnd.cn(&["run", "--use", "db-pass", "--", "true"]);
    assert_eq!(out.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&out.stderr).contains("grant_required"));

    // request --wait, then run: the value is in the child's environment and
    // scrubbed from its output.
    cnd.ok(&["request", "db-pass", "--reason", "e2e run", "--wait"]);
    let out = cnd.ok(&[
        "run",
        "--use",
        "db-pass",
        "--",
        "sh",
        "-c",
        &format!("test \"$DB_PASS\" = '{V_DB}' && echo injected; echo \"$DB_PASS\""),
    ]);
    assert_eq!(out, "injected\n[countersign:db-pass]\n");
    let again = cnd.json(&["request", "db-pass", "--reason", "again"]);
    assert_eq!(again["data"]["existing"], true, "{again}");

    // hide: a granted (and high-entropy) value is scrubbed; a low-entropy
    // secret with no grant passes through (hide is no guessing oracle).
    let out = cnd.expect(
        &["hide"],
        format!("a {V_DB} b\nc {V_API} d\n").as_bytes(),
        0,
    );
    assert_eq!(out, format!("a [countersign:db-pass] b\nc {V_API} d\n"));

    // reveal needs its own grant, used once.
    cnd.expect(&["reveal", "api-key"], b"", 4);
    cnd.ok(&[
        "request", "api-key", "--mode", "reveal", "--reason", "show it", "--wait",
    ]);
    assert_eq!(cnd.ok(&["reveal", "api-key"]), V_API);
    cnd.expect(&["reveal", "api-key"], b"", 4);

    // revoke ends the use grant.
    let grants = cnd.json(&["grants"]);
    assert_eq!(grants["data"]["grants"].as_array().unwrap().len(), 1);
    cnd.ok(&["revoke", "--secret", "db-pass"]);
    assert_eq!(
        cnd.cn(&["run", "--use", "db-pass", "--", "true"])
            .status
            .code(),
        Some(125)
    );

    // set rotates the value and revokes grants for it.
    cnd.ok(&["request", "db-pass", "--reason", "before set", "--wait"]);
    let set = cnd.expect(
        &["--json", "set", "db-pass", "--from-stdin", "--wait"],
        V_DB2.as_bytes(),
        0,
    );
    let set: Value = serde_json::from_str(&set).unwrap();
    assert_eq!(set["data"]["decision"]["grants_revoked"], 1, "{set}");
    cnd.ok(&["edit", "db-pass", "--description", "edited", "--wait"]);

    // rm and import.
    cnd.ok(&["rm", "api-key", "--wait"]);
    let import_dir = cnd.path().join("project");
    std::fs::create_dir(&import_dir).unwrap();
    std::fs::write(import_dir.join(".secret-file-token"), V_FILE).unwrap();
    cnd.ok(&[
        "import",
        "--glob",
        ".secret-*",
        "--dir",
        import_dir.to_str().unwrap(),
        "--keep",
        "--wait",
    ]);
    let list = cnd.json(&["list", "--all"]);
    let names: Vec<&str> = list["data"]["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["db-pass", "file-token"]);

    // The audit log has every step, and no value anywhere in the state
    // directory in plaintext or in base64.
    let events = cnd.events();
    for e in [
        "store.init",
        "daemon.start",
        "session.start",
        "list",
        "request.create",
        "request.approve",
        "store.add",
        "use.start",
        "use.end",
        "hide",
        "reveal",
        "grant.revoke",
        "store.set",
        "store.edit",
        "store.rm",
        "import",
    ] {
        assert!(events.iter().any(|x| x == e), "no {e} in {events:?}");
    }
    let b64 = |v: &str| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(v)
    };
    for v in [V_DB, V_API, V_DB2, V_FILE] {
        for needle in [v.to_owned(), b64(v)] {
            let hits = files_containing(&cnd.path().join("state"), needle.as_bytes());
            assert!(hits.is_empty(), "{needle} found in {hits:?}");
        }
    }
    let query = cnd.ok(&["--json", "audit", "--limit", "500"]);
    assert!(!query.contains(V_DB) && !query.contains(V_API));

    // audit verify passes, also across a restart (daemon.stop, checkpoint).
    cnd.ok(&["audit", "verify"]);
    cnd.stop();
    assert!(cnd.events().iter().any(|e| e == "daemon.stop"));
    cnd.spawn("mk").unwrap();
    let verified = cnd.json(&["audit", "verify"]);
    assert!(
        verified["data"]["signatures_verified"].as_u64().unwrap() >= 2,
        "{verified}"
    );
    cnd.ok(&[
        "audit",
        "verify",
        "--dir",
        cnd.path().join("state/audit").to_str().unwrap(),
    ]);

    // A changed byte breaks the chain: exit 13.
    let seg = cnd.path().join("state/audit/000001.jsonl");
    let text = std::fs::read_to_string(&seg).unwrap();
    let tampered = text.replacen("\"reason\":\"e2e run\"", "\"reason\":\"e2e fun\"", 1);
    assert_ne!(text, tampered);
    std::fs::write(&seg, tampered).unwrap();
    let out = cnd.cn(&["audit", "verify"]);
    assert_eq!(out.status.code(), Some(13));
    assert!(String::from_utf8_lossy(&out.stderr).contains("audit_broken"));
}

#[test]
fn deny_expiry_and_a_denying_approver() {
    let cnd = Cnd::start(
        r#"
[grants]
pending_expiry = "3s"

[approval]
use = "slow"
reveal = "no"
mutate = "auto"
export = "auto"

[approvers.auto]
type = "insecure-auto"

[approvers.slow]
type = "insecure-auto"
delay = "1h"

[approvers.no]
type = "insecure-auto"
decision = "deny"
"#,
    );
    add(&cnd, "one", "value-one-0123456789", "--high-entropy");
    add(&cnd, "two", "value-two-0123456789", "--high-entropy");
    add(&cnd, "three", "value-three-0123456789", "--high-entropy");

    // cn deny ends a pending request.
    let created = cnd.json(&["request", "one", "--reason", "to be denied"]);
    let code = created["data"]["code"].as_str().unwrap().to_owned();
    assert_eq!(created["data"]["state"], "pending");
    cnd.ok(&["deny", &code, "--reason", "not now"]);
    // cn approve on a denied request reports the denial (exit 5).
    cnd.expect(&["approve", &code, "--timeout", "1s"], b"", 5);
    let rec = cnd.wait_for_record(|r| r["event"] == "request.deny");
    assert_eq!(rec["approver"], "client");

    // An unanswered request expires (exit 7).
    let out = cnd.cn(&["request", "two", "--reason", "will lapse", "--wait"]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    cnd.wait_for_record(|r| r["event"] == "request.expire");

    // A denying approver denies (exit 5).
    let out = cnd.cn(&[
        "request", "three", "--mode", "reveal", "--reason", "no", "--wait",
    ]);
    assert_eq!(out.status.code(), Some(5));
    let deny = cnd.wait_for_record(|r| r["event"] == "request.deny" && r["approver"] == "no");
    assert_eq!(deny["evidence"]["adapter"], "insecure-auto");
}

#[test]
fn an_exiting_anchor_takes_its_grants() {
    let cnd = Cnd::start(APPROVE_ALL);
    add(
        &cnd,
        "sess-secret",
        "session-bound-0123456789",
        "--high-entropy",
    );
    let cn = cn_bin();
    let script = format!(
        "{cn} --socket sock request sess-secret --reason anchored --wait >/dev/null && {cn} --socket sock --json grants",
        cn = cn.display()
    );
    let out = Command::new(&cn)
        .args([
            "--socket", "sock", "session", "exec", "--label", "e2e", "--", "sh", "-c", &script,
        ])
        .current_dir(cnd.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let grants: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(grants["data"]["grants"].as_array().unwrap().len(), 1);

    let end = cnd.wait_for_record(|r| r["event"] == "session.end" && r["grants_expired"] == 1);
    assert_eq!(end["session"]["registered"], true);
    let exp = cnd.wait_for_record(|r| r["event"] == "grant.expire");
    assert_eq!(exp["by"], "anchor_exit");
    let all = cnd.json(&["grants", "--all-sessions"]);
    assert!(all["data"]["grants"].as_array().unwrap().is_empty());
}

#[test]
fn recover_with_the_phrase_after_the_machine_key_changes() {
    let mut cnd = Cnd::start(APPROVE_ALL);
    add(&cnd, "kept", "kept-across-recovery-0123", "--high-entropy");
    cnd.stop();

    // A new machine key cannot open the store.
    write_key(&cnd.path().join("mk2"));
    assert!(cnd.spawn("mk2").is_err());

    // A wrong phrase is refused; the right one re-wraps the store.
    let recover = |phrase: &str| {
        let mut child = Command::new(cnd_bin())
            .args(base_args("mk2"))
            .arg("recover")
            .current_dir(cnd.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(phrase.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    assert!(
        !recover("0000-0000-0000-0000-0000-0000-0000-0000-0000")
            .status
            .success()
    );
    let phrase = cnd.phrase.clone();
    let out = recover(&format!("{}\n", phrase.to_lowercase()));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    cnd.spawn("mk2").unwrap();
    let list = cnd.json(&["list"]);
    assert_eq!(list["data"]["secrets"][0]["name"], "kept");
    assert!(cnd.events().iter().any(|e| e == "keyslot.add"));
    cnd.ok(&["audit", "verify"]);
}

#[test]
fn peers_outside_access_users_are_refused() {
    let cnd = Cnd::start(APPROVE_ALL);
    let config = std::fs::read_to_string(cnd.path().join("config.toml")).unwrap();
    // A second daemon on the same store dir is not needed: rewrite the
    // config and reload is enough.
    std::fs::write(
        cnd.path().join("config.toml"),
        config.replace(&format!("users = [\"{}\"]", uid()), "users = [\"0\"]"),
    )
    .unwrap();
    let pid = rustix::process::Pid::from_child(cnd.child.as_ref().unwrap());
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
    cnd.wait_for_record(|r| r["event"] == "config.load" && r["seq"].as_u64() > Some(5));
    let out = cnd.cn(&["list"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("forbidden_peer"));
    cnd.wait_for_record(|r| r["event"] == "peer.reject");
}

// ---------------------------------------------------------------------------
// polkit against a fake authority on a private bus.

mod fake_polkit {
    use super::*;
    use serde::{Deserialize, Serialize};
    use zvariant::{OwnedValue, Type};

    /// A private message bus, killed on drop.
    pub struct PrivateBus {
        child: Child,
        pub address: String,
        _dir: tempfile::TempDir,
    }

    impl PrivateBus {
        pub fn start() -> Option<Self> {
            if Command::new("dbus-daemon")
                .arg("--version")
                .stdout(Stdio::null())
                .status()
                .is_err()
            {
                eprintln!("SKIPPED: dbus-daemon is not on PATH");
                return None;
            }
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("bus.conf");
            // Relative paths do not work for a bus socket, so it goes in an
            // abstract-free short directory under the temp dir.
            std::fs::write(
                &config,
                format!(
                    r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                    dir.path().display()
                ),
            )
            .unwrap();
            let mut child = Command::new("dbus-daemon")
                .arg(format!("--config-file={}", config.display()))
                .args(["--print-address=1", "--nofork", "--nopidfile"])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            Some(Self {
                child,
                address: line.trim().to_owned(),
                _dir: dir,
            })
        }
    }

    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[derive(Debug, Deserialize, Type)]
    pub struct Subject {
        pub kind: String,
        pub details: HashMap<String, OwnedValue>,
    }

    #[derive(Debug, Serialize, Type)]
    pub struct AuthResult {
        is_authorized: bool,
        is_challenge: bool,
        details: HashMap<String, String>,
    }

    pub struct Call {
        pub subject: Subject,
        pub action: String,
        pub details: HashMap<String, String>,
        pub cancellation_id: String,
    }

    #[derive(Default)]
    pub struct State {
        pub hang: bool,
        pub calls: Vec<Call>,
        pub cancels: Vec<String>,
        pub waiters: HashMap<String, tokio::sync::oneshot::Sender<()>>,
    }

    #[derive(Clone)]
    pub struct Authority(pub Arc<Mutex<State>>);

    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
    pub enum PkError {
        #[zbus(error)]
        ZBus(zbus::Error),
        Cancelled(String),
    }

    #[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
    impl Authority {
        async fn check_authorization(
            &self,
            subject: Subject,
            action_id: String,
            details: HashMap<String, String>,
            _flags: u32,
            cancellation_id: String,
        ) -> Result<AuthResult, PkError> {
            let waiter = {
                let mut s = self.0.lock().unwrap();
                let waiter = s.hang.then(|| {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    s.waiters.insert(cancellation_id.clone(), tx);
                    rx
                });
                s.calls.push(Call {
                    subject,
                    action: action_id,
                    details,
                    cancellation_id,
                });
                waiter
            };
            match waiter {
                Some(rx) => {
                    let _ = rx.await;
                    Err(PkError::Cancelled("cancelled".into()))
                }
                None => Ok(AuthResult {
                    is_authorized: true,
                    is_challenge: false,
                    details: HashMap::new(),
                }),
            }
        }

        async fn cancel_check_authorization(&self, cancellation_id: String) -> Result<(), PkError> {
            let mut s = self.0.lock().unwrap();
            s.cancels.push(cancellation_id.clone());
            if let Some(tx) = s.waiters.remove(&cancellation_id) {
                let _ = tx.send(());
            }
            Ok(())
        }

        #[zbus(property)]
        async fn backend_version(&self) -> String {
            "128-fake".into()
        }
    }
}

#[test]
fn polkit_dialog_shows_the_digest_cn_computes_and_expiry_withdraws_it() {
    use fake_polkit::*;
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let _server = rt.block_on(async {
        zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("org.freedesktop.PolicyKit1")
            .unwrap()
            .serve_at(
                "/org/freedesktop/PolicyKit1/Authority",
                Authority(state.clone()),
            )
            .unwrap()
            .build()
            .await
            .unwrap()
    });
    let cnd = Cnd::start_with(
        r#"
[grants]
pending_expiry = "3s"

[approval]
use = "polkit"
reveal = "polkit"
mutate = "auto"
export = "auto"

[approvers.auto]
type = "insecure-auto"

[approvers.polkit]
type = "polkit"
# The private bus has no logind to ask.
require_wayland = false
"#,
        &["--polkit-bus".into(), bus.address.clone()],
    );
    add(
        &cnd,
        "pk-secret",
        "polkit-guarded-0123456789",
        "--high-entropy",
    );

    let created = cnd.json(&["request", "pk-secret", "--reason", "via polkit"]);
    let code = created["data"]["code"].as_str().unwrap().to_owned();
    let digest_short = created["data"]["digest_short"].as_str().unwrap().to_owned();
    // cn approve recomputes the digest from get_request and waits.
    let approved = cnd.json(&["approve", &code, "--timeout", "10s"]);
    assert_eq!(approved["data"]["state"], "approved", "{approved}");
    assert_eq!(approved["data"]["digest_short"], digest_short.as_str());
    {
        let s = state.lock().unwrap();
        let call = &s.calls[0];
        assert_eq!(call.action, "computer.mooselabs.countersign.approve");
        assert_eq!(call.details["digest"], digest_short);
        assert_eq!(call.details["code"], code);
        assert_eq!(call.details["secrets"], "pk-secret");
        // Who is asking: what cnd found first, the client's cwd marked.
        let who = &call.details["session"];
        assert!(
            who.starts_with(&format!(
                "agent {} (pid {}, matched comm = ",
                my_comm(),
                std::process::id()
            )),
            "{who}"
        );
        assert!(
            who.contains("; agent-reported: ") && who.contains("cwd "),
            "{who}"
        );
        assert_eq!(call.subject.kind, "unix-process");
        let pid: u32 = call.subject.details["pid"]
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(pid, std::process::id(), "the anchor is this test process");
        assert!(!call.details.keys().any(|k| k.starts_with("polkit.")));
    }

    // An unanswered dialog is withdrawn when the request expires.
    state.lock().unwrap().hang = true;
    let out = cnd.cn(&[
        "request",
        "pk-secret",
        "--mode",
        "reveal",
        "--reason",
        "hangs",
        "--wait",
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = state.lock().unwrap();
        if let Some(call) = s.calls.get(1) {
            if s.cancels.contains(&call.cancellation_id) {
                assert!(call.cancellation_id.starts_with("countersign-r_"));
                assert_eq!(call.action, "computer.mooselabs.countersign.reveal");
                break;
            }
        }
        drop(s);
        assert!(Instant::now() < deadline, "the check was not cancelled");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn an_abandoned_hide_stream_is_still_audited() {
    use countersign_proto::{Envelope, Kind, Request, write_frame, write_message};
    let cnd = Cnd::start(APPROVE_ALL);
    add(
        &cnd,
        "probe-target",
        "high-entropy-probe-0123456789",
        "--high-entropy",
    );
    let mut s = std::os::unix::net::UnixStream::connect(cnd.path().join("sock")).unwrap();
    let hello = Request::Hello {
        protocols: vec![1],
        client: "e2e".into(),
        labels: Default::default(),
        cwd: None,
    };
    write_message(&mut s, &Envelope { id: 1, body: hello }).unwrap();
    countersign_proto::read_frame(&mut s).unwrap().unwrap();
    let hide = Request::Hide { secrets: vec![] };
    write_message(&mut s, &Envelope { id: 2, body: hide }).unwrap();
    countersign_proto::read_frame(&mut s).unwrap().unwrap();
    write_frame(
        &mut s,
        Kind::Stream,
        b"guess high-entropy-probe-0123456789\n",
    )
    .unwrap();
    let (_, echoed) = countersign_proto::read_frame(&mut s).unwrap().unwrap();
    assert_eq!(echoed, b"guess [countersign:probe-target]\n");
    drop(s);
    let rec = cnd.wait_for_record(|r| r["event"] == "hide");
    assert_eq!(rec["hits"]["probe-target"], 1);
    // bytes_out with bytes_in and the hits would give away the value's length.
    assert!(rec.get("bytes_out").is_none(), "{rec}");
}

// ---------------------------------------------------------------------------
// Limits, shutdown, init and the other review fixes.

/// A `cn session exec` session that makes one request, then lives on (its
/// anchor execs `sleep`) so the request stays pending. Returns the anchor
/// and cn's exit code and stdout.
#[expect(
    clippy::zombie_processes,
    reason = "the anchor is returned; the caller kills and waits for it"
)]
fn session_request(cnd: &Cnd, i: usize, secret: &str) -> (Child, i32, String) {
    let cn = cn_bin();
    let script = format!(
        "{cn} --socket sock --json request {secret} --reason r{i} > out{i}.json 2> err{i}; \
         echo $? > rc{i}; exec sleep 120",
        cn = cn.display()
    );
    let mut child = Command::new(&cn)
        .args(["--socket", "sock", "session", "exec", "--label"])
        .arg(format!("s{i}"))
        .args(["--", "sh", "-c", &script])
        .current_dir(cnd.path())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let rc = cnd.path().join(format!("rc{i}"));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(text) = std::fs::read_to_string(&rc) {
            if let Ok(code) = text.trim().parse() {
                let out = std::fs::read_to_string(cnd.path().join(format!("out{i}.json")))
                    .unwrap_or_default()
                    + &std::fs::read_to_string(cnd.path().join(format!("err{i}")))
                        .unwrap_or_default();
                return (child, code, out);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("session {i} did not finish; log:\n{}", cnd.log());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn limits_hold_across_sessions_and_dialogs_queue() {
    let cnd = Cnd::start(
        r#"
[approval]
use = "slow"
reveal = "slow"
mutate = "auto"
export = "auto"

[approvers.auto]
type = "insecure-auto"

[approvers.slow]
type = "insecure-auto"
delay = "1h"

[limits]
max_pending_requests_per_uid = 4
max_prompts_per_uid = 2
list_calls_per_minute_per_uid = 3

[hide]
max_streams_per_minute_per_uid = 1
"#,
    );
    add(&cnd, "a", "value-a-0123456789", "--high-entropy");
    let mut anchors = Vec::new();
    let mut codes = Vec::new();
    // Each session is new, but the uid's limits count them all: two
    // dialogs open, two requests wait their turn, the fifth is refused.
    for i in 0..5 {
        let (child, rc, out) = session_request(&cnd, i, "a");
        anchors.push(child);
        if i < 4 {
            assert_eq!(rc, 0, "{out}");
            let v: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(
                v["data"]["queued"].as_bool().unwrap_or(false),
                i >= 2,
                "{v}"
            );
            codes.push(v["data"]["code"].as_str().unwrap().to_owned());
        } else {
            assert_eq!(rc, 10, "{out}");
            assert!(out.contains("of this user are already pending"), "{out}");
        }
    }

    // A deny from another session frees a dialog slot: the first queued
    // request's dialog opens.
    cnd.ok(&["deny", &codes[0], "--reason", "no"]);
    let deny = cnd.wait_for_record(|r| r["event"] == "request.deny");
    assert_eq!(deny["evidence"]["from"], "other_session", "{deny}");
    assert_eq!(deny["evidence"]["peer"]["uid"], uid());
    assert_eq!(deny["evidence"]["peer"]["comm"], "cn");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let v = cnd.raw_call(countersign_proto::Request::GetRequest {
            code: codes[2].clone(),
            wait_seconds: Some(1),
        });
        if v["queued"].as_bool() != Some(true) {
            assert_eq!(v["state"], "pending", "{v}");
            assert_eq!(v["approvers"][0]["prompted"], true, "{v}");
            break;
        }
        assert!(Instant::now() < deadline, "{v}");
    }
    let v = cnd.raw_call(countersign_proto::Request::GetRequest {
        code: codes[3].clone(),
        wait_seconds: Some(0),
    });
    assert_eq!(v["queued"], true, "{v}");

    // The deny cools the secret down for the uid: a new session is refused.
    let (child, rc, out) = session_request(&cnd, 9, "a");
    anchors.push(child);
    assert_eq!(rc, 10, "{out}");
    assert!(out.contains("denied a moment ago"), "{out}");

    // list and hide count per uid too.
    for _ in 0..3 {
        cnd.ok(&["list"]);
    }
    let out = cnd.cn(&["list"]);
    assert_eq!(out.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("from this user"));
    cnd.expect(&["hide"], b"x\n", 0);
    let out = cnd.cn_in(&["hide"], b"x\n");
    assert_eq!(
        out.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    for mut a in anchors {
        let _ = a.kill();
        let _ = a.wait();
    }
}

#[test]
fn connections_are_capped_and_quiet_ones_closed() {
    use countersign_proto::{Envelope, Request, write_message};
    let cnd = Cnd::start(&format!(
        "{APPROVE_ALL}\n[limits]\nmax_connections_per_uid = 3\nidle_timeout = \"2s\"\n"
    ));
    // Three sockets that never say hello hold every slot.
    let silent: Vec<_> = (0..3)
        .map(|_| std::os::unix::net::UnixStream::connect(cnd.path().join("sock")).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let out = cnd.cn(&["list"]);
    assert_eq!(
        out.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("connections open"));
    // After the hello timeout (5 s) they are closed and cn works again.
    std::thread::sleep(Duration::from_secs(6));
    cnd.ok(&["list"]);
    drop(silent);

    // A handshaken connection that stays quiet past idle_timeout is closed.
    let mut s = std::os::unix::net::UnixStream::connect(cnd.path().join("sock")).unwrap();
    let hello = Request::Hello {
        protocols: vec![1],
        client: "e2e".into(),
        labels: Default::default(),
        cwd: None,
    };
    write_message(&mut s, &Envelope { id: 1, body: hello }).unwrap();
    countersign_proto::read_frame(&mut s).unwrap().unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let started = Instant::now();
    assert!(countersign_proto::read_frame(&mut s).unwrap().is_none());
    assert!(started.elapsed() >= Duration::from_millis(1500));
}

/// The process that connected exits; whoever holds the socket now gets
/// nothing more from it.
#[test]
fn a_connection_ends_with_the_process_that_made_it() {
    let script = r#"
import json, os, socket, struct, sys, time
def send(s, obj):
    b = json.dumps(obj).encode()
    s.sendall(struct.pack(">I", len(b) + 1) + b"\x01" + b)
def recv(s):
    hdr = b""
    while len(hdr) < 4:
        try:
            c = s.recv(4 - len(hdr))
        except ConnectionResetError:
            return None
        if not c:
            return None
        hdr += c
    n = struct.unpack(">I", hdr)[0]
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            return None
        body += c
    return body
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
send(s, {"id": 1, "type": "hello", "protocols": [1], "client": "py", "labels": {}, "cwd": None})
recv(s)
if os.fork():
    os._exit(0)
time.sleep(0.5)
send(s, {"id": 2, "type": "list", "all_projects": True})
print("answered" if recv(s) else "closed", flush=True)
"#;
    if Command::new("python3")
        .arg("-c")
        .arg("pass")
        .status()
        .is_err()
    {
        eprintln!("SKIPPED: python3 is not on PATH");
        return;
    }
    let cnd = Cnd::start(APPROVE_ALL);
    let out = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(cnd.path().join("sock"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "closed",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_approver_able_to_run_is_approver_unavailable() {
    let cnd = Cnd::start(
        r#"
[approval]
use = "gone"
reveal = "gone"
mutate = "auto"
export = "auto"

[approvers.auto]
type = "insecure-auto"

[approvers.gone]
type = "insecure-auto"
decision = "unavailable"
"#,
    );
    add(&cnd, "u", "value-u-0123456789", "--high-entropy");
    let out = cnd.cn(&["request", "u", "--reason", "x", "--wait"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(14), "{err}");
    assert!(
        err.contains("approver_unavailable") && err.contains("cn doctor"),
        "{err}"
    );
    // No deny cooldown: asking again gets the same answer, not rate_limited.
    let out = cnd.cn(&["request", "u", "--reason", "x", "--wait"]);
    assert_eq!(out.status.code(), Some(14));
}

#[test]
fn a_stop_does_not_wait_on_a_pending_request() {
    let mut cnd = Cnd::start(
        r#"
[approval]
use = "slow"
reveal = "slow"
mutate = "auto"
export = "auto"

[approvers.auto]
type = "insecure-auto"

[approvers.slow]
type = "insecure-auto"
delay = "1h"
"#,
    );
    add(&cnd, "w", "value-w-0123456789", "--high-entropy");
    let mut waiting = Command::new(cn_bin())
        .args([
            "--socket", "sock", "request", "w", "--reason", "wait", "--wait",
        ])
        .current_dir(cnd.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    cnd.wait_for_record(|r| r["event"] == "request.create");
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    cnd.stop();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "stop took {:?}",
        started.elapsed()
    );
    let _ = waiting.kill();
    let _ = waiting.wait();
    // daemon.stop and the final checkpoint are the last records.
    let events = cnd.events();
    let n = events.len();
    assert_eq!(events[n - 2..], ["daemon.stop", "checkpoint"], "{events:?}");
}

#[test]
fn a_failed_init_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    write_key(&dir.path().join("mk"));
    std::fs::write(
        dir.path().join("config.toml"),
        format!("[access]\nusers = [\"{}\"]\n", uid()),
    )
    .unwrap();
    let init = |stdout: Stdio| {
        Command::new(cnd_bin())
            .args(base_args("mk"))
            .arg("init")
            .current_dir(dir.path())
            .stdout(stdout)
            .stderr(Stdio::piped())
            .output()
            .unwrap()
    };
    // The phrase cannot be shown: no store may be left behind.
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let out = init(Stdio::from(full));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("recovery phrase"));
    let state = dir.path().join("state");
    for f in [
        "store.v1",
        "keyslots.json",
        "audit/checkpoint.pub",
        "audit/000001.jsonl",
    ] {
        assert!(!state.join(f).exists(), "{f} was left behind");
    }
    // So init can simply run again.
    let out = init(Stdio::piped());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(state.join("store.v1").exists());
}

#[test]
fn verify_fails_when_the_start_of_the_log_is_gone() {
    let mut cnd = Cnd::start(APPROVE_ALL);
    add(&cnd, "v", "value-v-0123456789", "--high-entropy");
    cnd.stop();
    let copy = cnd.path().join("copy");
    std::fs::create_dir(&copy).unwrap();
    let audit = cnd.path().join("state/audit");
    std::fs::copy(audit.join("checkpoint.pub"), copy.join("checkpoint.pub")).unwrap();
    let text = std::fs::read_to_string(audit.join("000001.jsonl")).unwrap();
    let tail: String = text.lines().skip(2).map(|l| format!("{l}\n")).collect();
    std::fs::write(copy.join("000001.jsonl"), tail).unwrap();
    let dir = copy.to_str().unwrap();
    let out = cnd.cn(&["audit", "verify", "--dir", dir]);
    assert_eq!(
        out.status.code(),
        Some(13),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not start at seq 1"));
    cnd.ok(&["audit", "verify", "--dir", dir, "--from", "3"]);
}

#[test]
fn labels_and_deny_reasons_are_redacted_and_imports_are_capped() {
    let cnd = Cnd::start(&format!(
        "{}\n[limits]\nmax_names_per_import = 2\n",
        APPROVE_ALL.replace("use = \"auto\"", "use = \"slow\"")
            + "\n[approvers.slow]\ntype = \"insecure-auto\"\ndelay = \"1h\"\n"
    ));
    const V: &str = "label-pasted-value-0123456789";
    add(&cnd, "pasted", V, "--high-entropy");
    let out = cnd.cn_env(
        &["--json", "request", "pasted", "--reason", "x"],
        b"",
        &[("CLAUDE_CODE_SESSION_ID", V)],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let code = v["data"]["code"].as_str().unwrap().to_owned();
    cnd.ok(&["deny", &code, "--reason", &format!("it was {V}")]);
    let created = cnd.wait_for_record(|r| r["event"] == "request.create" && r["mode"] == "use");
    assert_eq!(
        created["session"]["labels"]["CLAUDE_CODE_SESSION_ID"],
        "[countersign:pasted]"
    );
    let deny = cnd.wait_for_record(|r| r["event"] == "request.deny");
    assert_eq!(deny["evidence"]["reason"], "it was [countersign:pasted]");
    assert_eq!(deny["evidence"]["from"], "own_session");
    let hits = files_containing(&cnd.path().join("state"), V.as_bytes());
    assert!(hits.is_empty(), "{hits:?}");

    // One approval adds at most max_names_per_import secrets.
    let import_dir = cnd.path().join("many");
    std::fs::create_dir(&import_dir).unwrap();
    for n in ["one", "two", "three"] {
        std::fs::write(
            import_dir.join(format!(".secret-{n}")),
            format!("value-{n}-0123456789"),
        )
        .unwrap();
    }
    let out = cnd.cn(&[
        "import",
        "--glob",
        ".secret-*",
        "--dir",
        import_dir.to_str().unwrap(),
        "--keep",
        "--wait",
    ]);
    assert_eq!(
        out.status.code(),
        Some(9),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn labels_and_deny_reasons_are_redacted_with_the_callers_grants() {
    // use is approved at once, reveal stays pending.
    let cnd = Cnd::start(
        &(APPROVE_ALL.replace("reveal = \"auto\"", "reveal = \"slow\"")
            + "\n[approvers.slow]\ntype = \"insecure-auto\"\ndelay = \"1h\"\n"),
    );
    // Low entropy: only a session granted it redacts it.
    const V: &str = "granted-low-entropy-0123456789";
    add(&cnd, "low", V, "--low-entropy");
    add(&cnd, "other", "other-value-0123456789", "--high-entropy");
    cnd.ok(&["request", "low", "--reason", "r", "--wait"]);

    // An agent in this session registers a new one, pasting the value into
    // its label.
    let cn = cn_bin();
    let out = Command::new(&cn)
        .args(["--socket", "sock", "session", "exec", "--label"])
        .arg(format!("label {V}"))
        .args([
            "--",
            cn.to_str().unwrap(),
            "--socket",
            "sock",
            "--json",
            "session",
        ])
        .current_dir(cnd.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(!text.contains(V), "{text}");
    assert!(text.contains("label [countersign:low]"), "{text}");

    // A request from another session, denied from this one with the value
    // in the reason.
    let script = format!(
        "{cn} --socket sock --json request other --mode reveal --reason x > req.json; \
         exec sleep 120",
        cn = cn.display()
    );
    let mut anchor = Command::new(&cn)
        .args(["--socket", "sock", "session", "exec", "--label", "a"])
        .args(["--", "sh", "-c", &script])
        .current_dir(cnd.path())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let code = loop {
        let text = std::fs::read_to_string(cnd.path().join("req.json")).unwrap_or_default();
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            break v["data"]["code"].as_str().unwrap().to_owned();
        }
        assert!(Instant::now() < deadline, "no request; log:\n{}", cnd.log());
        std::thread::sleep(Duration::from_millis(50));
    };
    cnd.ok(&["deny", &code, "--reason", &format!("it was {V}")]);
    let deny = cnd.wait_for_record(|r| r["event"] == "request.deny");
    assert_eq!(deny["evidence"]["reason"], "it was [countersign:low]");
    assert_eq!(deny["evidence"]["from"], "other_session");
    let _ = anchor.kill();
    let _ = anchor.wait();
    let hits = files_containing(&cnd.path().join("state"), V.as_bytes());
    assert!(hits.is_empty(), "{hits:?}");
}

#[test]
fn a_reload_applies_the_audit_settings() {
    let cnd = Cnd::start(APPROVE_ALL);
    let checkpoints = || cnd.events().iter().filter(|e| *e == "checkpoint").count();
    let config = std::fs::read_to_string(cnd.path().join("config.toml")).unwrap();
    std::fs::write(
        cnd.path().join("config.toml"),
        format!("{config}\n[audit]\ncheckpoint_every_records = 2\n"),
    )
    .unwrap();
    cnd.signal(rustix::process::Signal::HUP);
    cnd.wait_for_record(|r| r["event"] == "config.load" && r["seq"].as_u64() > Some(4));
    let before = checkpoints();
    add(&cnd, "r1", "value-r1-0123456789", "--high-entropy");
    add(&cnd, "r2", "value-r2-0123456789", "--high-entropy");
    assert!(checkpoints() >= before + 2, "{:?}", cnd.events());
}
