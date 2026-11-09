use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};

use super::*;

fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_762_000_000 + secs)
}

fn meta(name: &str) -> SecretMeta {
    SecretMeta {
        name: name.into(),
        description: format!("{name} for tests"),
        usage: "Only in tests.\nNever log it.".into(),
        projects: vec!["~/projects/x/*".into()],
        tags: vec!["test".into()],
        high_entropy: true,
    }
}

fn val(s: &str) -> SecretValue {
    SecretValue::new(s.as_bytes().to_vec())
}

fn new_store() -> (tempfile::TempDir, MasterKey, Store, RecoveryPhrase) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let mk = MasterKey::generate();
    let (store, phrase) = Store::init_with(&state, &mk, KdfParams::INSECURE_FAST).unwrap();
    (dir, mk, store, phrase)
}

#[test]
fn round_trip_through_disk() {
    let (_d, mk, mut s, _) = new_store();
    let c = s
        .add(meta("db-password"), val("correct horse battery"), t(1))
        .unwrap();
    assert_eq!((c.op, c.generation, c.value_changed), ("add", 1, true));
    assert_eq!(c.metadata, Some(meta("db-password")));
    s.add(meta("api.key"), val("k-123456789"), t(2)).unwrap();

    let s2 = Store::open(s.dir(), &mk).unwrap();
    assert_eq!(s2.generation(), 2);
    let names: Vec<_> = s2.list().map(|i| i.meta.name.as_str()).collect();
    assert_eq!(names, ["api.key", "db-password"]);
    let info = s2.get("db-password").unwrap();
    assert_eq!(info.meta, meta("db-password"));
    assert_eq!(
        (info.created, info.updated, info.rotated),
        (t(1), t(1), t(1))
    );
    assert_eq!(
        s2.value("db-password").unwrap().as_bytes(),
        b"correct horse battery"
    );
    assert!(matches!(s2.value("nope"), Err(StoreError::Unknown(_))));
}

#[test]
fn set_edit_rm_change_what_they_say() {
    let (_d, mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();

    let c = s.set("a", val("value-two-2"), t(5)).unwrap();
    assert_eq!(c.fields_changed, ["value", "rotated"]);
    assert!(c.value_changed && c.metadata.is_none());
    let i = s.get("a").unwrap();
    assert_eq!((i.created, i.updated, i.rotated), (t(1), t(5), t(5)));

    let mut m = meta("a");
    m.usage = "new prose".into();
    m.high_entropy = false;
    let c = s.edit(m.clone(), t(9)).unwrap();
    assert_eq!(c.fields_changed, ["usage", "high_entropy"]);
    assert!(!c.value_changed);
    let i = s.get("a").unwrap();
    assert_eq!((i.updated, i.rotated), (t(9), t(5)));

    let s2 = Store::open(s.dir(), &mk).unwrap();
    assert_eq!(s2.get("a").unwrap().meta, m);
    assert_eq!(s2.value("a").unwrap().as_bytes(), b"value-two-2");

    let c = s.rm("a", t(10)).unwrap();
    assert_eq!((c.op, c.generation), ("rm", 4));
    assert!(!Store::open(s.dir(), &mk).unwrap().contains("a"));
}

#[test]
fn invalid_mutations_change_nothing() {
    let (_d, mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
    let before = std::fs::read(s.dir().join(STORE_FILE)).unwrap();
    let cases = [
        Mutation::Add {
            meta: meta("a"),
            value: val("x"),
        },
        Mutation::Add {
            meta: meta("Bad"),
            value: val("x"),
        },
        Mutation::Add {
            meta: meta("b"),
            value: val(""),
        },
        Mutation::Set {
            name: "zz".into(),
            value: val("x"),
        },
        Mutation::Edit { meta: meta("zz") },
        Mutation::Rm { name: "zz".into() },
    ];
    let codes: Vec<_> = cases
        .iter()
        .map(|m| s.apply(m, t(2)).unwrap_err().code())
        .collect();
    use countersign_proto::ErrorCode::*;
    assert_eq!(
        codes,
        [
            SecretExists,
            BadRequest,
            BadRequest,
            UnknownSecret,
            UnknownSecret,
            UnknownSecret
        ]
    );
    assert_eq!(std::fs::read(s.dir().join(STORE_FILE)).unwrap(), before);
    assert_eq!(s.generation(), 1);
    assert_eq!(Store::open(s.dir(), &mk).unwrap().generation(), 1);
}

#[test]
fn wrong_master_key_fails_closed() {
    let (_d, _mk, s, _) = new_store();
    assert!(matches!(
        Store::open(s.dir(), &MasterKey::generate()),
        Err(StoreError::WrongKey)
    ));
}

#[test]
fn tampering_is_detected() {
    let (_d, mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
    let path = s.dir().join(STORE_FILE);
    let good = std::fs::read(&path).unwrap();
    let nl = good.iter().position(|&b| b == b'\n').unwrap();

    // Flip a bit anywhere in the ciphertext.
    for i in [nl + 1, nl + 20, good.len() - 1] {
        let mut bad = good.clone();
        bad[i] ^= 0x40;
        std::fs::write(&path, &bad).unwrap();
        assert!(
            matches!(Store::open(s.dir(), &mk), Err(StoreError::WrongKey)),
            "{i}"
        );
    }
    // Change the header (it is the AAD): roll the generation back.
    let header = String::from_utf8(good[..nl].to_vec()).unwrap();
    let edited = header.replace("\"generation\":1", "\"generation\":0");
    assert_ne!(edited, header);
    let mut bad = edited.into_bytes();
    bad.extend_from_slice(&good[nl..]);
    std::fs::write(&path, &bad).unwrap();
    assert!(matches!(
        Store::open(s.dir(), &mk),
        Err(StoreError::WrongKey)
    ));
    // Truncation.
    std::fs::write(&path, &good[..good.len() - 10]).unwrap();
    assert!(Store::open(s.dir(), &mk).is_err());
    std::fs::write(&path, &good).unwrap();
    assert!(Store::open(s.dir(), &mk).is_ok());
}

#[test]
fn a_value_cannot_be_moved_to_another_name() {
    let (_d, mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-of-a-1"), t(1)).unwrap();
    s.add(meta("b"), val("value-of-b-1"), t(1)).unwrap();
    // Swap the sealed values in memory, as an edit of the body would.
    let va = s.secrets["a"].value.clone();
    let vb = s.secrets["b"].value.clone();
    s.secrets.get_mut("a").unwrap().value = vb;
    s.secrets.get_mut("b").unwrap().value = va;
    assert!(matches!(s.value("a"), Err(StoreError::WrongKey)));
    let _ = mk;
}

#[test]
fn every_write_uses_a_fresh_nonce() {
    let (_d, _mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
    let one = std::fs::read(s.dir().join(STORE_FILE)).unwrap();
    s.edit(meta("a"), t(2)).unwrap();
    let two = std::fs::read(s.dir().join(STORE_FILE)).unwrap();
    let nonce = |b: &[u8]| {
        let nl = b.iter().position(|&c| c == b'\n').unwrap();
        let h: serde_json::Value = serde_json::from_slice(&b[..nl]).unwrap();
        h["nonce"].as_str().unwrap().to_owned()
    };
    assert_ne!(nonce(&one), nonce(&two));
    assert!(!two.windows(11).any(|w| w == b"value-one-1"));
}

#[test]
fn recovery_rewraps_the_machine_slot() {
    let (_d, old_mk, mut s, phrase) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
    let dir = s.dir().to_owned();
    let new_mk = MasterKey::generate();

    assert!(matches!(
        Store::recover(&dir, &RecoveryPhrase::generate(), &new_mk),
        Err(StoreError::WrongKey)
    ));
    // A typed phrase works too.
    let typed: RecoveryPhrase = phrase.to_string().to_lowercase().parse().unwrap();
    let r = Store::recover(&dir, &typed, &new_mk).unwrap();
    assert_eq!(r.value("a").unwrap().as_bytes(), b"value-one-1");
    // Same data key: the checkpoint key survives recovery.
    assert_eq!(*r.checkpoint_seed(), *s.checkpoint_seed());

    assert!(matches!(
        Store::open(&dir, &old_mk),
        Err(StoreError::WrongKey)
    ));
    assert_eq!(
        Store::open(&dir, &new_mk)
            .unwrap()
            .value("a")
            .unwrap()
            .as_bytes(),
        b"value-one-1"
    );
    assert!(!dir.join("keyslots.json.prev").exists());
    // The recovery slot still works after the rewrap.
    assert!(Store::recover(&dir, &phrase, &MasterKey::generate()).is_ok());
}

#[test]
fn init_refuses_an_existing_store_and_open_needs_one() {
    let (_d, mk, s, _) = new_store();
    assert!(matches!(
        Store::init_with(s.dir(), &mk, KdfParams::INSECURE_FAST),
        Err(StoreError::AlreadyInitialized(_))
    ));
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        Store::open(empty.path(), &mk),
        Err(StoreError::NotInitialized(_))
    ));
}

#[test]
fn an_interrupted_init_can_be_rerun() {
    let (_d, mk, s, _) = new_store();
    let dir = s.dir().to_owned();
    drop(s);
    // As if init stopped after writing keyslots.json.
    std::fs::remove_file(dir.join(STORE_FILE)).unwrap();
    let (s, _) = Store::init_with(&dir, &mk, KdfParams::INSECURE_FAST).unwrap();
    assert_eq!(s.generation(), 0);
    assert!(Store::open(&dir, &mk).is_ok());
}

#[test]
fn files_are_private() {
    let (_d, _mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
    s.add(meta("b"), val("value-two-2"), t(1)).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(s.dir()), 0o700);
    for f in [STORE_FILE, STORE_PREV_FILE, KEYSLOTS_FILE] {
        assert_eq!(mode(&s.dir().join(f)), 0o600, "{f}");
    }
}

#[test]
fn prev_holds_the_last_generation_and_rollback_restores_it() {
    let (_d, mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
    s.set("a", val("value-two-2"), t(2)).unwrap();
    s.rollback().unwrap();
    assert_eq!(s.generation(), 1);
    assert_eq!(s.value("a").unwrap().as_bytes(), b"value-one-1");
    let s2 = Store::open(s.dir(), &mk).unwrap();
    assert_eq!(s2.generation(), 1);
    assert_eq!(s2.value("a").unwrap().as_bytes(), b"value-one-1");
}

#[test]
fn a_failed_write_leaves_disk_and_memory_unchanged() {
    use fsio::{FAIL_AT, Step};
    // SyncDir fails after the new file is in place: the old one goes back.
    for step in [Step::WriteTmp, Step::LinkPrev, Step::Rename, Step::SyncDir] {
        let (_d, mk, mut s, _) = new_store();
        s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
        FAIL_AT.with(|f| f.set(Some(step)));
        let r = s.set("a", val("value-two-2"), t(2));
        FAIL_AT.with(|f| f.set(None));
        assert!(r.is_err(), "{step:?}");
        assert_eq!(s.generation(), 1, "{step:?}");
        assert_eq!(s.value("a").unwrap().as_bytes(), b"value-one-1");
        let s2 = Store::open(s.dir(), &mk).unwrap();
        assert_eq!(
            s2.value("a").unwrap().as_bytes(),
            b"value-one-1",
            "{step:?}"
        );
        assert_eq!(Store::open(s.dir(), &mk).unwrap().generation(), 1);
        assert!(s.poisoned().is_none());
        // The next write succeeds.
        s.set("a", val("value-three"), t(3)).unwrap();
        assert_eq!(Store::open(s.dir(), &mk).unwrap().generation(), 2);
    }
}

#[test]
fn a_failed_rollback_refuses_later_changes() {
    let (_d, _mk, mut s, _) = new_store();
    s.add(meta("a"), val("value-one-1"), t(1)).unwrap();
    std::fs::remove_file(s.dir().join(STORE_PREV_FILE)).unwrap();
    assert!(s.rollback().is_err());
    assert!(s.poisoned().is_some());
    let e = s.set("a", val("value-two-2"), t(2)).unwrap_err();
    assert!(matches!(e, StoreError::Poisoned(_)), "{e:?}");
    assert_eq!(e.code(), countersign_proto::ErrorCode::Internal);
}

#[test]
fn values_never_reach_disk_in_the_clear() {
    let (_d, _mk, mut s, _) = new_store();
    let secret = "plaintext-marker-6c1f";
    s.add(meta("a"), val(secret), t(1)).unwrap();
    s.set("a", val("another-marker-77"), t(2)).unwrap();
    for f in [STORE_FILE, STORE_PREV_FILE, KEYSLOTS_FILE] {
        let bytes = std::fs::read(s.dir().join(f)).unwrap();
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{f}"
        );
    }
}

#[test]
fn a_batch_commits_whole_or_not_at_all() {
    let (_d, mk, mut s, _) = new_store();
    s.add(meta("a"), val("aaaaaaaaaa"), t(1)).unwrap();
    let add = |n: &str| Mutation::Add {
        meta: meta(n),
        value: val("bbbbbbbbbb"),
    };
    // The second add of "b" fails against the first: nothing is written.
    let bad = [add("b"), add("b")];
    assert!(matches!(s.check_all(&bad), Err(StoreError::Exists(_))));
    assert!(matches!(
        s.apply_all(&bad, t(2)),
        Err(StoreError::Exists(_))
    ));
    assert_eq!(s.generation(), 1);
    assert!(!s.contains("b"));

    let good = [add("b"), add("c"), Mutation::Rm { name: "a".into() }];
    s.check_all(&good).unwrap();
    let changes = s.apply_all(&good, t(3)).unwrap();
    assert_eq!(changes.len(), 3);
    assert!(changes.iter().all(|c| c.generation == 2));
    let s2 = Store::open(s.dir(), &mk).unwrap();
    let names: Vec<_> = s2.list().map(|i| i.meta.name.as_str()).collect();
    assert_eq!(names, ["b", "c"]);
    assert_eq!(s2.generation(), 2);

    // Rollback restores the store before the whole batch.
    s.rollback().unwrap();
    assert_eq!(s.generation(), 1);
    assert!(s.contains("a") && !s.contains("b"));
}
