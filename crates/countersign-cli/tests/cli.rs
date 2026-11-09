//! The `cn` binary against a fake daemon. Only debug builds of `cn` honour
//! `COUNTERSIGN_SOCKET`, so these tests do not exist in release builds.
#![cfg(debug_assertions)]

mod fake;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};

use countersign_proto::Request;
use fake::{DB_VALUE, Decide, Fake, TOKEN_VALUE};
use serde_json::Value;

fn run(cmd: &mut Command) -> Output {
    cmd.stdin(Stdio::null()).output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn json_line(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap_or_else(|e| panic!("{e}: {}", text(b)))
}

fn db() -> String {
    text(DB_VALUE)
}

#[test]
fn list_prints_a_table_and_json() {
    let fake = Fake::start();
    fake.grant("db");
    let out = run(fake.cn().arg("list"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("NAME"), "{stdout}");
    assert!(
        stdout.contains("db  ")
            && (stdout.contains("use 30m left") || stdout.contains("use 29m left")),
        "{stdout}"
    );
    assert!(
        stdout.contains("gh-token") && stdout.contains("GitHub token"),
        "{stdout}"
    );

    let out = run(fake.cn().args(["list", "--json"]));
    let v = json_line(&out.stdout);
    assert_eq!(v["cn"], 1);
    assert_eq!(v["ok"], true);
    assert_eq!(v["data"]["session"], "s_fake0000test");
    assert_eq!(v["data"]["secrets"][0]["name"], "db");
    assert_eq!(v["data"]["secrets"][0]["default_env"], "DB");
    assert_eq!(v["data"]["secrets"][0]["grant"]["id"], "g_test1");
    assert_eq!(v["data"]["secrets"][1]["grant"], Value::Null);

    let out = run(fake.cn().args(["list", "--long"]));
    assert!(text(&out.stdout).contains("    Never log it."));
}

#[test]
fn show_of_an_unknown_secret_exits_8() {
    let fake = Fake::start();
    let out = run(fake.cn().args(["show", "nope"]));
    assert_eq!(out.status.code(), Some(8));
    assert!(text(&out.stderr).contains("error[unknown_secret]"));
    let out = run(fake.cn().args(["show", "db"]));
    assert!(out.status.success());
    assert!(text(&out.stdout).contains("Test database password"));
}

#[test]
fn request_prints_code_digest_and_approve_line() {
    let fake = Fake::start();
    let out = run(fake
        .cn()
        .args(["request", "db", "--ttl", "30m", "--reason", "row counts"]));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with("request K7M-Q2X pending  use db for 30m\n"),
        "{stdout}"
    );
    assert!(stdout.contains("\ndigest  ") && stdout.contains("approve a desktop dialog is open"));
    assert!(matches!(
        &fake.log()[0],
        Request::Request { ttl_seconds: Some(1800), reason, .. } if reason == "row counts"
    ));

    let out = run(fake.cn().args(["--json", "request", "db", "--reason", "x"]));
    let v = json_line(&out.stdout);
    let d = &v["data"];
    assert_eq!(d["code"], "K7M-Q2X");
    assert_eq!(d["state"], "pending");
    assert_eq!(d["mode"], "use");
    assert_eq!(d["approvers"][0]["driven"], "daemon");
    assert_eq!(d["approve_command"], "! /usr/bin/cn approve K7M-Q2X");
    assert_eq!(d["digest_short"].as_str().unwrap().len(), 9);
}

#[test]
fn request_wait_reports_approval_denial_and_timeout() {
    let fake = Fake::start();
    let out = run(fake
        .cn()
        .args(["request", "db", "--reason", "x", "--wait", "5s"]));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("approved by polkit  grant g_test1 active until"),
        "{stdout}"
    );

    fake.decide(Decide::Deny);
    let out = run(fake
        .cn()
        .args(["--json", "request", "db", "--reason", "x", "--wait"]));
    assert_eq!(out.status.code(), Some(5));
    let v = json_line(&out.stdout);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "denied");
    assert_eq!(v["error"]["exit"], 5);

    fake.decide(Decide::Stay);
    let out = run(fake
        .cn()
        .args(["-q", "request", "db", "--reason", "x", "--wait=1s"]));
    assert_eq!(out.status.code(), Some(6), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("error[pending]"));
}

#[test]
fn run_injects_and_scrubs_and_passes_the_exit_code() {
    let fake = Fake::start();
    fake.grant("db");
    let out = run(fake.cn().args([
        "run",
        "--use",
        "db",
        "--",
        "sh",
        "-c",
        "echo \"pw=$DB\"; echo \"$DB\" >&2; env | grep -c '^COUNTERSIGN_' ; exit 3",
    ]));
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(!stdout.contains(&db()) && !stderr.contains(&db()));
    assert_eq!(stdout, "pw=[countersign:db]\n0\n");
    assert_eq!(stderr, "[countersign:db]\n");

    let finish = fake.log().into_iter().find_map(|r| match r {
        Request::RunFinish {
            exit, signal, hits, ..
        } => Some((exit, signal, hits)),
        _ => None,
    });
    let (exit, signal, hits) = finish.expect("run_finish sent");
    assert_eq!((exit, signal), (Some(3), None));
    assert_eq!(hits.get("db"), Some(&2));
    assert!(matches!(
        &fake.log()[0],
        Request::Run { argv0, argc: 2, uses } if argv0 == "sh" && uses[0].env == "DB"
    ));
}

#[test]
fn run_maps_a_named_variable() {
    let fake = Fake::start();
    fake.grant("db");
    let out = run(fake.cn().args([
        "run",
        "--use",
        "db=PGPASSWORD",
        "--",
        "sh",
        "-c",
        "test -n \"$PGPASSWORD\" && test -z \"$DB\"",
    ]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn run_reports_a_signal_as_128_plus_n() {
    let fake = Fake::start();
    fake.grant("db");
    let out = run(fake
        .cn()
        .args(["run", "--use", "db", "--", "sh", "-c", "kill -TERM $$"]));
    assert_eq!(out.status.code(), Some(143));
    let signal = fake.log().into_iter().find_map(|r| match r {
        Request::RunFinish { signal, .. } => Some(signal),
        _ => None,
    });
    assert_eq!(signal, Some(Some(15)));
}

#[test]
fn run_forwards_sigterm_to_the_child() {
    let fake = Fake::start();
    fake.grant("db");
    let mut child = fake
        .cn()
        .args([
            "run",
            "--use",
            "db",
            "--",
            "sh",
            "-c",
            "trap 'echo got-term; exit 7' TERM; echo ready; while :; do sleep 0.05; done",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "ready");
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(lines.next().unwrap().unwrap(), "got-term");
    assert_eq!(child.wait().unwrap().code(), Some(7));
}

#[test]
fn run_without_a_grant_exits_125_with_json_on_stderr() {
    let fake = Fake::start();
    let out = run(fake
        .cn()
        .args(["--json", "run", "--use", "db", "--", "true"]));
    assert_eq!(out.status.code(), Some(125));
    assert!(out.stdout.is_empty());
    let v = json_line(&out.stderr);
    assert_eq!(v["error"]["code"], "grant_required");
    assert_eq!(v["error"]["exit"], 4);
    assert_eq!(v["error"]["hint"], "cn request db --reason \"...\"");

    let out = run(fake.cn().args(["run", "--use", "db", "--", "true"]));
    assert_eq!(out.status.code(), Some(125));
    assert!(text(&out.stderr).starts_with("cn: error[grant_required]: no active grant"));
}

#[test]
fn run_exit_codes_for_missing_and_unexecutable_commands() {
    let fake = Fake::start();
    fake.grant("db");
    let out = run(fake
        .cn()
        .args(["run", "--use", "db", "--", "/nonexistent/cn-test-cmd"]));
    assert_eq!(out.status.code(), Some(127));

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("not-executable");
    std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
    let out = run(fake.cn().args(["run", "--use", "db", "--"]).arg(&script));
    assert_eq!(out.status.code(), Some(126));
}

#[test]
fn run_refuses_bad_uses_before_contacting_the_daemon() {
    let fake = Fake::start();
    let out = run(fake
        .cn()
        .args(["run", "--use", "a=X", "--use", "b=X", "--", "true"]));
    assert_eq!(out.status.code(), Some(125));
    assert!(text(&out.stderr).contains("two secrets map to X"));
    let out = run(fake.cn().args(["run", "--use", "db"]));
    assert_eq!(out.status.code(), Some(125), "usage errors in run exit 125");
    assert!(fake.log().is_empty());
}

#[test]
fn hide_scrubs_stdin() {
    let fake = Fake::start();
    let mut child = fake
        .cn()
        .args(["hide", "--stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = format!("token={}\nplain line\npw {}", text(TOKEN_VALUE), db());
    stdin.write_all(input.as_bytes()).unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "token=[countersign:gh-token]\nplain line\npw [countersign:db]"
    );
    assert!(
        text(&out.stderr).contains("hits: db=1 gh-token=1"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn an_unreachable_daemon_exits_3() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cn"));
    cmd.env("COUNTERSIGN_SOCKET", "/nonexistent/cnd.sock")
        .args(["--json", "grants"]);
    let out = run(&mut cmd);
    assert_eq!(out.status.code(), Some(3));
    let v = json_line(&out.stdout);
    assert_eq!(v["error"]["code"], "daemon_unreachable");
}

#[test]
fn session_exec_registers_then_execs_in_place() {
    let fake = Fake::start();
    let child = fake
        .cn()
        .args([
            "-q",
            "session",
            "exec",
            "--label",
            "tests",
            "--",
            "sh",
            "-c",
            "echo $$; env",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout = text(&out.stdout);
    assert_eq!(
        stdout.lines().next().unwrap(),
        pid.to_string(),
        "same pid after exec"
    );
    assert!(!stdout.contains("COUNTERSIGN_"), "{stdout}");
    assert!(matches!(
        &fake.log()[0],
        Request::SessionRegister { label: Some(l) } if l == "tests"
    ));
}

#[test]
fn approve_shows_the_request_and_waits_for_the_dialog() {
    let fake = Fake::start();
    fake.decide(Decide::Stay);
    assert!(
        run(fake.cn().args(["request", "db", "--reason", "x"]))
            .status
            .success()
    );
    fake.decide(Decide::Approve);
    let out = run(fake.cn().args(["approve", "k7mq2x"]));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with("countersign request K7M-Q2X\n"),
        "{stdout}"
    );
    assert!(stdout.contains("reason    (agent-supplied) x"), "{stdout}");
    assert!(
        stdout.contains("Approve it in the desktop dialog"),
        "{stdout}"
    );
    assert!(stdout.contains("approved by polkit"), "{stdout}");

    let out = run(fake.cn().args(["approve", "not-a-code"]));
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn add_reads_the_value_from_stdin_never_argv() {
    let fake = Fake::start();
    let mut child = fake
        .cn()
        .args([
            "add",
            "new-key",
            "--description",
            "A new key",
            "--from-stdin",
            "--high-entropy",
            "--wait",
            "5s",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"a-brand-new-value\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("mutate: add new-key"));
    assert!(text(&out.stdout).ends_with("added new-key\n"));
    let value = fake.log().into_iter().find_map(|r| match r {
        Request::Add {
            value_b64, source, ..
        } => Some((value_b64.decode().unwrap().to_vec(), source)),
        _ => None,
    });
    let (value, source) = value.unwrap();
    assert_eq!(value, b"a-brand-new-value", "one trailing newline stripped");
    assert_eq!(source, Some(countersign_proto::ValueSource::Stdin));

    let out = run(fake.cn().args(["set", "db"]));
    assert_eq!(out.status.code(), Some(2), "no TTY and no source: no_tty");
    assert!(text(&out.stderr).contains("error[no_tty]"));
}

#[test]
fn audit_prints_a_table_or_json_lines() {
    let fake = Fake::start();
    let out = run(fake.cn().args(["audit", "--current"]));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("SEQ"), "{stdout}");
    assert!(
        stdout.contains("09:20:11  request.create  K7M-Q2X use db 30m \"row counts\""),
        "{stdout}"
    );
    let out = run(fake.cn().args(["audit", "--json"]));
    let lines: Vec<Value> = text(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["event"], "use.end");
}

#[test]
fn later_commands_say_so_with_exit_2() {
    let fake = Fake::start();
    for args in [
        &["approver", "enroll", "--name", "k"][..],
        &["unlock"],
        &["export", "--recipient", "age1x"],
        &["sudo", "--", "true"],
    ] {
        let out = run(fake.cn().arg("--json").args(args));
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let v = json_line(&out.stdout);
        assert_eq!(v["error"]["code"], "not_in_this_version");
    }
}

#[test]
fn version_names_the_protocol() {
    let out = run(Command::new(env!("CARGO_BIN_EXE_cn")).arg("--version"));
    assert!(out.status.success());
    assert!(text(&out.stdout).contains("(protocol 1)"));
    let out = run(Command::new(env!("CARGO_BIN_EXE_cn")).args(["--json", "list", "--bogus"]));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_line(&out.stdout)["error"]["code"], "usage");
}
