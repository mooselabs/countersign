use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::*;
use crate::time::ManualClock;

const SEED: [u8; 32] = [9; 32];

fn start() -> SystemTime {
    // 2026-11-08T09:00:00Z
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_128_400)
}

fn session(id: &str) -> SessionRef {
    SessionRef {
        id: id.into(),
        anchor_pid: 41210,
        anchor_comm: "claude".into(),
        registered: true,
        labels: BTreeMap::from([("CLAUDE_CODE_SESSION_ID".into(), "9f3c".into())]),
    }
}

fn request(code: &str, secret: &str) -> Event {
    Event::RequestCreate {
        request_id: format!("r_{code}"),
        code: code.into(),
        secrets: vec![secret.into()],
        mode: "use".into(),
        operation: None,
        ttl_seconds: 3600,
        reason: "run the drift report\nagainst \"prod\" \u{1b}[31m".into(),
        cwd: Some("/home/patrick/projects/x".into()),
        digest: "6f2a".into(),
        canonical: "eyJ9".into(),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    log: AuditLog,
}

fn fixture(opts: impl FnOnce(&mut Options)) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(start()));
    let mut o = Options::new("machine-1", "5e1c9a07-1111-2222-3333-444455556666");
    opts(&mut o);
    let mut log = AuditLog::open(&dir.path().join("audit"), o, clock.clone()).unwrap();
    log.set_signer(&SEED).unwrap();
    Fixture {
        _dir: dir,
        clock,
        log,
    }
}

fn fill(f: &mut Fixture, n: usize) {
    for i in 0..n {
        f.clock.advance(Duration::from_millis(1500));
        let s = session(if i % 2 == 0 { "s_a" } else { "s_b" });
        let ev = match i % 3 {
            0 => request(&format!("C{i:05}"), "db"),
            1 => Event::Reveal {
                secret: "token".into(),
                grant_id: format!("g_{i}"),
                uses_left: 0,
            },
            _ => Event::Hide {
                bytes_in: 10,
                bytes_out: 10,
                hits: BTreeMap::from([("db".into(), 2)]),
                patterns: 4,
            },
        };
        f.log.append(Some(&s), &ev).unwrap();
    }
}

fn all(f: &Fixture) -> Vec<u8> {
    f.log.segments_from(0).unwrap()
}

fn pubkey(f: &Fixture) -> [u8; 32] {
    parse_pubkey(&std::fs::read_to_string(f.log.dir().join(PUBKEY_FILE)).unwrap()).unwrap()
}

#[test]
fn records_follow_the_schema() {
    let mut f = fixture(|_| {});
    f.log
        .append(
            None,
            &Event::DaemonStart {
                version: "0.1.0".into(),
                pid: 812,
                unseal: "systemd-creds".into(),
            },
        )
        .unwrap();
    f.log
        .append(Some(&session("s_a")), &request("K7M-Q2X", "db"))
        .unwrap();
    let bytes = all(&f);
    let lines: Vec<Value> = bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(lines[0]["v"], 1);
    assert_eq!(lines[0]["seq"], 1);
    assert_eq!(lines[0]["event"], "daemon.start");
    assert_eq!(lines[0]["session"], Value::Null);
    assert_eq!(lines[0]["prev"], GENESIS_PREV);
    assert_eq!(lines[0]["boot"], "5e1c9a07");
    assert_eq!(lines[0]["ts"], "2026-11-08T09:00:00.000000Z");
    assert_eq!(lines[1]["prev"], lines[0]["hash"]);
    assert_eq!(lines[1]["session"]["anchor_comm"], "claude");
    assert_eq!(
        lines[1]["reason"],
        "run the drift report\nagainst \"prod\" \u{1b}[31m"
    );
    assert!(lines[1].get("operation").is_none());
    // Lines are canonical JSON with sorted keys.
    let first = bytes.split(|&b| b == b'\n').next().unwrap();
    assert!(first.starts_with(br#"{"boot":"5e1c9a07","event":"daemon.start","hash":""#));
}

#[test]
fn a_written_chain_verifies() {
    let mut f = fixture(|_| {});
    fill(&mut f, 50);
    let r = verify_segments(&all(&f)).unwrap();
    assert_eq!((r.records, r.first_seq, r.last_seq), (50, 1, 50));
    assert!(r.from_genesis);
    assert_eq!(r.head_hash, f.log.head().1);
    assert_eq!(r.signatures_verified, 0);
    let r = verify_segments_with(
        &all(&f),
        &VerifyOptions {
            pubkey: Some(pubkey(&f)),
            exported_checkpoints: None,
        },
    )
    .unwrap();
    assert_eq!(r.checkpoints, 0);
    assert_eq!(verify_segments(b"").unwrap().records, 0);
}

fn lines_of(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn join(lines: &[Vec<u8>]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|l| [l.as_slice(), b"\n"].concat())
        .collect()
}

#[test]
fn an_edited_record_is_found() {
    let mut f = fixture(|_| {});
    fill(&mut f, 20);
    let mut lines = lines_of(&all(&f));
    // Record 8 is a reveal.
    let s = String::from_utf8(lines[7].clone()).unwrap();
    lines[7] = s.replace("\"uses_left\":0", "\"uses_left\":5").into_bytes();
    assert_ne!(lines[7], s.as_bytes());
    let e = verify_segments(&join(&lines)).unwrap_err();
    assert_eq!(
        (e.line, e.seq, e.kind.clone()),
        (8, Some(8), BreakKind::Hash)
    );
    assert!(e.to_string().contains("seq 8"));
}

#[test]
fn an_edited_record_with_a_recomputed_hash_breaks_the_next_link() {
    let mut f = fixture(|_| {});
    fill(&mut f, 20);
    let mut lines = lines_of(&all(&f));
    let Value::Object(mut rec) = serde_json::from_slice(&lines[4]).unwrap() else {
        unreachable!()
    };
    rec.insert("reason".into(), "innocent".into());
    let h = record_hash(&rec).unwrap();
    rec.insert("hash".into(), h.into());
    lines[4] = countersign_proto::jcs::value_to_vec(&Value::Object(rec)).unwrap();
    let e = verify_segments(&join(&lines)).unwrap_err();
    assert_eq!((e.line, e.seq, e.kind), (6, Some(6), BreakKind::Prev));
}

#[test]
fn removed_reordered_and_duplicated_records_are_found() {
    let mut f = fixture(|_| {});
    fill(&mut f, 20);
    let lines = lines_of(&all(&f));

    let mut removed = lines.clone();
    removed.remove(9);
    let e = verify_segments(&join(&removed)).unwrap_err();
    assert_eq!(
        (e.line, e.seq, e.kind),
        (10, Some(11), BreakKind::Seq { expected: 10 })
    );

    let mut swapped = lines.clone();
    swapped.swap(3, 4);
    let e = verify_segments(&join(&swapped)).unwrap_err();
    assert_eq!((e.line, e.seq), (4, Some(5)));

    let mut dup = lines.clone();
    dup.insert(12, lines[11].clone());
    let e = verify_segments(&join(&dup)).unwrap_err();
    assert_eq!((e.line, e.seq), (13, Some(12)));

    let mut first_gone = lines.clone();
    first_gone.remove(0);
    let r = verify_segments(&join(&first_gone)).unwrap();
    // A log that does not start at seq 1 verifies only from its first record.
    assert!(!r.from_genesis);
    let mut fake_genesis = lines;
    fake_genesis.remove(0);
    let s = String::from_utf8(fake_genesis[0].clone()).unwrap();
    fake_genesis[0] = s.replace("\"seq\":2", "\"seq\":1").into_bytes();
    assert!(verify_segments(&join(&fake_genesis)).is_err());
}

#[test]
fn whitespace_edits_are_found() {
    let mut f = fixture(|_| {});
    fill(&mut f, 5);
    let mut lines = lines_of(&all(&f));
    let s = String::from_utf8(lines[2].clone()).unwrap();
    lines[2] = s.replacen(",", ", ", 1).into_bytes();
    let e = verify_segments(&join(&lines)).unwrap_err();
    assert_eq!((e.line, e.kind), (3, BreakKind::NotCanonical));
}

#[test]
fn any_single_byte_change_is_found_on_its_line() {
    let mut f = fixture(|_| {});
    fill(&mut f, 30);
    f.log.checkpoint().unwrap();
    let bytes = all(&f);
    let key = pubkey(&f);
    let opts = VerifyOptions {
        pubkey: Some(key),
        exported_checkpoints: None,
    };
    assert!(verify_segments_with(&bytes, &opts).is_ok());
    let mut rnd = [0u8; 4 * 300];
    crate::encoding::fill_random(&mut rnd);
    for chunk in rnd.chunks(4) {
        let pos = u32::from_le_bytes(chunk.try_into().unwrap()) as usize % bytes.len();
        if bytes[pos] == b'\n' {
            continue;
        }
        let mut bad = bytes.clone();
        bad[pos] = if bad[pos] == b'a' { b'b' } else { b'a' };
        let line = bytes[..pos].iter().filter(|&&b| b == b'\n').count() + 1;
        let e = verify_segments_with(&bad, &opts).unwrap_err();
        assert_eq!(e.line, line, "byte {pos}: {e}");
    }
}

#[test]
fn checkpoints_are_signed_and_checked() {
    let mut f = fixture(|o| o.checkpoint_every_records = 10);
    fill(&mut f, 25);
    let bytes = all(&f);
    let opts = VerifyOptions {
        pubkey: Some(pubkey(&f)),
        exported_checkpoints: None,
    };
    let r = verify_segments_with(&bytes, &opts).unwrap();
    assert_eq!((r.checkpoints, r.signatures_verified), (2, 2));
    assert_eq!(r.records, 27);
    let cp = r.last_checkpoint.unwrap();
    assert_eq!((cp.seq, cp.upto_seq), (22, 21));

    let wrong = VerifyOptions {
        pubkey: Some(*SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes()),
        exported_checkpoints: None,
    };
    let e = verify_segments_with(&bytes, &wrong).unwrap_err();
    assert_eq!((e.seq, e.kind), (Some(11), BreakKind::Signature));
}

#[test]
fn checkpoints_wait_for_a_key_and_follow_the_interval() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(start()));
    let mut log = AuditLog::open(dir.path(), Options::new("m", "5e1c9a07"), clock.clone()).unwrap();
    log.append(None, &Event::DaemonStop { reason: "x".into() })
        .unwrap();
    // No signing key yet: deferred.
    assert_eq!(log.checkpoint().unwrap(), None);
    log.set_signer(&SEED).unwrap();
    assert_eq!(log.maybe_checkpoint().unwrap(), None);
    clock.advance(Duration::from_secs(3600));
    assert_eq!(log.maybe_checkpoint().unwrap().unwrap().seq, 2);
    // Nothing written since: no new checkpoint.
    clock.advance(Duration::from_secs(7200));
    assert_eq!(log.maybe_checkpoint().unwrap(), None);
    // checkpoint.pub belongs to the first key.
    assert!(matches!(
        log.set_signer(&[2; 32]),
        Err(AuditError::KeyMismatch(_))
    ));
}

#[test]
fn exported_checkpoints_catch_rewrites_and_truncation() {
    let mut f = fixture(|o| o.checkpoint_every_records = 10);
    fill(&mut f, 25);
    let bytes = all(&f);
    let exported: Vec<u8> = lines_of(&bytes)
        .into_iter()
        .filter(|l| l.windows(12).any(|w| w == b"\"checkpoint\""))
        .flat_map(|l| [l, b"\n".to_vec()].concat())
        .collect();
    let opts = VerifyOptions {
        pubkey: None,
        exported_checkpoints: Some(&exported),
    };
    assert_eq!(
        verify_segments_with(&bytes, &opts)
            .unwrap()
            .exported_matched,
        2
    );

    // Truncate the log after the second checkpoint's covered record.
    let lines = lines_of(&bytes);
    let e = verify_segments_with(&join(&lines[..15]), &opts).unwrap_err();
    assert_eq!((e.line, e.seq, e.kind), (2, Some(21), BreakKind::Truncated));

    // Rewrite history from record 5 on, recomputing every hash: the chain
    // verifies on its own, the exported checkpoints do not.
    let mut rewritten = Vec::new();
    let mut prev = GENESIS_PREV.to_owned();
    for (i, l) in lines.iter().enumerate() {
        let Value::Object(mut rec) = serde_json::from_slice(l).unwrap() else {
            unreachable!()
        };
        if i == 4 {
            rec.insert("reason".into(), "rewritten".into());
        }
        rec.insert("prev".into(), prev.clone().into());
        if rec["event"] == "checkpoint" {
            rec.insert("upto_hash".into(), prev.clone().into());
        }
        let h = record_hash(&rec).unwrap();
        rec.insert("hash".into(), h.clone().into());
        prev = h;
        rewritten.push(countersign_proto::jcs::value_to_vec(&Value::Object(rec)).unwrap());
    }
    let rewritten = join(&rewritten);
    assert!(verify_segments(&rewritten).is_ok());
    let e = verify_segments_with(&rewritten, &opts).unwrap_err();
    assert_eq!((e.line, e.seq, e.kind), (1, Some(10), BreakKind::Exported));
}

#[test]
fn segments_rotate_by_size_and_month_and_the_chain_runs_across() {
    let mut f = fixture(|o| o.max_segment_bytes = 4096);
    fill(&mut f, 40);
    // Into December.
    f.clock.advance(Duration::from_secs(30 * 86_400));
    f.log
        .append(
            None,
            &Event::DaemonStop {
                reason: "month".into(),
            },
        )
        .unwrap();
    let segs = list_segments(f.log.dir()).unwrap();
    assert!(segs.len() >= 4, "{segs:?}");
    let last =
        std::fs::read_to_string(f.log.dir().join(segment_name(*segs.last().unwrap()))).unwrap();
    assert!(last.starts_with(r#"{"boot""#));
    assert!(
        last.lines()
            .next()
            .unwrap()
            .contains("\"event\":\"segment.open\"")
    );
    assert!(last.contains("2026-12-"));
    let r = verify_segments_with(
        &all(&f),
        &VerifyOptions {
            pubkey: Some(pubkey(&f)),
            exported_checkpoints: None,
        },
    )
    .unwrap();
    assert_eq!(r.segment_opens, segs.len() as u64 - 1);
    // Closing a segment writes a checkpoint first.
    assert_eq!(r.checkpoints, r.segment_opens);
}

#[test]
fn reopening_continues_the_chain_and_cuts_a_torn_line() {
    let mut f = fixture(|_| {});
    fill(&mut f, 5);
    let dir = f.log.dir().to_owned();
    let seg = dir.join(segment_name(1));
    // A crash mid-write leaves an unterminated line.
    let mut torn = std::fs::read(&seg).unwrap();
    torn.extend_from_slice(br#"{"boot":"5e1c9a07","eve"#);
    std::fs::write(&seg, &torn).unwrap();
    let mut log =
        AuditLog::open(&dir, Options::new("machine-1", "5e1c9a07"), f.clock.clone()).unwrap();
    assert_eq!(log.truncated_bytes(), 23);
    assert_eq!(log.head().0, 5);
    log.set_signer(&SEED).unwrap();
    log.append(
        None,
        &Event::DaemonStop {
            reason: "again".into(),
        },
    )
    .unwrap();
    let r = verify_segments(&log.segments_from(1).unwrap()).unwrap();
    assert_eq!(r.records, 6);
}

#[test]
fn segments_from_starts_mid_chain() {
    let mut f = fixture(|_| {});
    fill(&mut f, 12);
    let r = verify_segments(&f.log.segments_from(8).unwrap()).unwrap();
    assert_eq!((r.first_seq, r.last_seq, r.from_genesis), (8, 12, false));
    assert!(f.log.segments_from(13).unwrap().is_empty());
}

#[test]
fn queries_filter_and_limit() {
    let mut f = fixture(|_| {});
    fill(&mut f, 30);
    let q = |q: Query| f.log.query(&q).unwrap();
    assert_eq!(q(Query::default()).len(), 30);
    let last5 = q(Query {
        limit: Some(5),
        ..Default::default()
    });
    assert_eq!(
        last5
            .iter()
            .map(|r| r["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [26, 27, 28, 29, 30]
    );
    let a = q(Query {
        session: Some("s_a".into()),
        ..Default::default()
    });
    assert_eq!(a.len(), 15);
    assert!(a.iter().all(|r| r["session"]["id"] == "s_a"));
    let reveals = q(Query {
        events: vec!["reveal".into()],
        ..Default::default()
    });
    assert_eq!(reveals.len(), 10);
    // "db" is in request.create's secrets and in hide's hits.
    let db = q(Query {
        secret: Some("db".into()),
        ..Default::default()
    });
    assert_eq!(db.len(), 20);
    let since = start() + Duration::from_millis(1500 * 21);
    let late = q(Query {
        since: Some(since),
        ..Default::default()
    });
    assert_eq!(late.first().unwrap()["seq"], 21);
    let early = q(Query {
        until: Some(start() + Duration::from_secs(3)),
        ..Default::default()
    });
    assert_eq!(early.len(), 2);
    assert!(
        q(Query {
            limit: Some(0),
            ..Default::default()
        })
        .is_empty()
    );
}

#[test]
fn floats_are_refused() {
    let mut f = fixture(|_| {});
    let ev = Event::ConfigLoad {
        path: "/etc/countersign/config.toml".into(),
        sha256: "00".into(),
        approvers: serde_json::json!({"polkit": {"timeout": 1.5}}),
    };
    assert!(matches!(
        f.log.append(None, &ev),
        Err(AuditError::Encode(_))
    ));
    assert_eq!(f.log.head().0, 0);
}

#[test]
fn files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = fixture(|_| {});
    fill(&mut f, 1);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(f.log.dir()), 0o700);
    assert_eq!(mode(&f.log.dir().join(segment_name(1))), 0o600);
}

#[test]
fn store_changes_become_store_events() {
    let change = crate::store::Change {
        op: "set",
        secret: "db".into(),
        fields_changed: vec!["value", "rotated"],
        value_changed: true,
        generation: 43,
        metadata: None,
    };
    let v = serde_json::to_value(Event::store(&change, "r_1")).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"event": "store.set", "secret": "db", "request_id": "r_1",
            "fields_changed": ["value", "rotated"], "value_changed": true, "generation": 43})
    );
}
