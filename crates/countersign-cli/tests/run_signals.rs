//! `cn run` and signals once the child has exited but a process it started
//! still holds its stdout and stderr. Only debug builds of `cn` honour
//! `COUNTERSIGN_SOCKET`, so these tests do not exist in release builds.
#![cfg(debug_assertions)]

#[expect(
    dead_code,
    reason = "the fake daemon is shared with cli.rs; this file uses part of it"
)]
mod fake;

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use countersign_proto::Request;
use fake::{DB_VALUE, Fake};

#[test]
fn sigterm_after_the_child_exited_ends_cn_without_waiting_for_its_background_job() {
    let fake = Fake::start();
    fake.grant("db");
    // The child starts a background job that keeps the pipes open, prints
    // the value once now and again in 3 seconds, and exits at once.
    let mut cn = fake
        .cn()
        .args([
            "run",
            "--use",
            "db",
            "--",
            "sh",
            "-c",
            "(echo \"bg=$DB\"; sleep 3; echo \"late=$DB\"; echo \"late=$DB\" >&2) & echo ready; exit 0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let mut stdout = BufReader::new(cn.stdout.take().unwrap());
    let mut seen = Vec::new();
    while seen.len() < 2 {
        let mut line = String::new();
        assert_ne!(
            stdout.read_line(&mut line).unwrap(),
            0,
            "early EOF: {seen:?}"
        );
        seen.push(line);
    }
    seen.sort();
    assert_eq!(seen, ["bg=[countersign:db]\n", "ready\n"]);
    // Let the child exit and be reaped; the background job still runs.
    std::thread::sleep(Duration::from_millis(300));

    let status = Command::new("kill")
        .args(["-TERM", &cn.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = cn.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "cn still running after SIGTERM");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(143));

    // cn's ends of the pipes are closed: reading reaches EOF before the
    // background job writes again, so its later output cannot come out.
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    let mut stderr = Vec::new();
    cn.stderr.take().unwrap().read_to_end(&mut stderr).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "took {:?}",
        started.elapsed()
    );
    let (rest, stderr) = (
        String::from_utf8_lossy(&rest),
        String::from_utf8_lossy(&stderr),
    );
    let value = String::from_utf8_lossy(DB_VALUE);
    assert!(!rest.contains("late") && !rest.contains(&*value), "{rest}");
    assert!(!stderr.contains(&*value), "{stderr}");
    assert!(stderr.contains("stopped by signal 15"), "{stderr}");

    let finish = fake.log().into_iter().find_map(|r| match r {
        Request::RunFinish { exit, signal, .. } => Some((exit, signal)),
        _ => None,
    });
    assert_eq!(
        finish,
        Some((Some(0), None)),
        "run_finish has the child's status"
    );
}
