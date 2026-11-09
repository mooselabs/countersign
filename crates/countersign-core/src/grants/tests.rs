use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::*;
use crate::sessions::{AnchorKind, ProcInfo};
use crate::store::SecretValue;
use crate::time::ManualClock;

fn start() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_128_400)
}

fn session(id: &str, kind: AnchorKind) -> Session {
    let anchor = ProcInfo {
        pid: 41210,
        ppid: 1,
        start_time: 8_812_345,
        comm: "claude".into(),
        uid: 1000,
        euid: 1000,
    };
    Session {
        id: id.into(),
        kind,
        anchor: anchor.clone(),
        chain: vec![anchor],
        boot_id: "b".into(),
    }
}

fn agent(id: &str) -> Session {
    session(id, AnchorKind::Registered { label: None })
}

struct T {
    clock: Arc<ManualClock>,
    g: Grants,
}

fn setup() -> T {
    let clock = Arc::new(ManualClock::new(start()));
    let g = Grants::new(Policy::default(), clock.clone());
    T { clock, g }
}

fn known(n: &str) -> bool {
    ["db", "token", "api.key", "a", "b", "c", "d"].contains(&n)
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

fn ask<'a>(n: &'a [String], mode: Mode, ttl: Option<u64>) -> GrantAsk<'a> {
    GrantAsk {
        names: n,
        mode,
        ttl: ttl.map(Duration::from_secs),
        reason: "drift report",
    }
}

fn digest(_: &PendingRequest) -> [u8; 32] {
    [7; 32]
}

impl T {
    fn request(
        &mut self,
        s: &Session,
        n: &[&str],
        mode: Mode,
        ttl: Option<u64>,
    ) -> Result<String, GrantError> {
        let n = names(n);
        self.g
            .request_grant(s, 1000, ask(&n, mode, ttl), known, digest)
            .map(|r| r.id.clone())
    }

    fn code(&self, id: &str) -> String {
        self.g.get_by_id(id).unwrap().code.to_string()
    }
}

#[test]
fn approve_creates_a_grant_that_expires() {
    let mut t = setup();
    let s = agent("s_1");
    let id = t
        .request(&s, &["db", "token", "db"], Mode::Use, Some(1800))
        .unwrap();
    let r = t.g.get(&t.code(&id)).unwrap();
    assert_eq!(
        r.kind,
        RequestKind::Grant {
            names: names(&["db", "token"]),
            mode: Mode::Use,
            ttl: Duration::from_secs(1800)
        }
    );
    assert_eq!(r.digest, [7; 32]);
    assert_eq!(r.expires_at, start() + Duration::from_secs(300));
    assert!(r.id.starts_with("r_") && r.id.len() == 28);
    assert!(!t.g.has_grant("s_1", "db", Mode::Use));

    t.clock.advance(Duration::from_secs(60));
    let a = t.g.approve(&id).unwrap();
    let g = a.grant.unwrap();
    // TTL counts from approval.
    assert_eq!(g.expires_at, start() + Duration::from_secs(60 + 1800));
    assert_eq!(g.uses_left, None);
    assert!(t.g.has_grant("s_1", "db", Mode::Use));
    assert!(t.g.has_grant("s_1", "token", Mode::Use));
    assert!(!t.g.has_grant("s_1", "db", Mode::Reveal));
    assert!(!t.g.has_grant("s_2", "db", Mode::Use));
    assert!(!t.g.has_grant("s_1", "api.key", Mode::Use));
    assert_eq!(t.g.granted_names("s_1"), ["db", "token"]);
    assert!(t.g.check_use("s_1", &names(&["db", "token"])).is_ok());
    let e =
        t.g.check_use("s_1", &names(&["db", "api.key"]))
            .unwrap_err();
    assert_eq!(
        (e.code, e.names.clone()),
        (ErrorCode::GrantRequired, names(&["api.key"]))
    );
    assert_eq!(e.to_body().detail["names"][0], "api.key");

    assert_eq!(t.g.next_deadline(), Some(g.expires_at));
    t.clock.advance(Duration::from_secs(1799));
    assert!(t.g.has_grant("s_1", "db", Mode::Use));
    t.clock.advance(Duration::from_secs(1));
    assert!(!t.g.has_grant("s_1", "db", Mode::Use));
    let ex = t.g.sweep();
    assert_eq!(ex.grants.len(), 1);
    assert!(t.g.grants_for("s_1").is_empty());
}

#[test]
fn the_approved_code_cannot_be_used_again() {
    let mut t = setup();
    let id = t.request(&agent("s_1"), &["db"], Mode::Use, None).unwrap();
    let code = t.code(&id);
    t.g.approve(&id).unwrap();
    assert_eq!(t.g.get(&code).unwrap_err().code, ErrorCode::RequestNotFound);
    assert_eq!(
        t.g.approve(&id).unwrap_err().code,
        ErrorCode::RequestNotFound
    );
}

#[test]
fn codes_parse_leniently_and_unknown_codes_are_not_found() {
    let mut t = setup();
    let id = t.request(&agent("s_1"), &["db"], Mode::Use, None).unwrap();
    let code = t.code(&id);
    let loose = code.replace('-', "").to_lowercase();
    assert_eq!(t.g.get(&loose).unwrap().id, id);
    assert_eq!(
        t.g.get("nonsense").unwrap_err().code,
        ErrorCode::RequestNotFound
    );
    assert_eq!(
        t.g.get("000-000").unwrap_err().code,
        ErrorCode::RequestNotFound
    );
}

#[test]
fn pending_requests_expire() {
    let mut t = setup();
    let id = t.request(&agent("s_1"), &["db"], Mode::Use, None).unwrap();
    let code = t.code(&id);
    t.clock.advance(Duration::from_secs(300));
    assert_eq!(t.g.get(&code).unwrap_err().code, ErrorCode::RequestExpired);
    assert_eq!(
        t.g.approve(&id).unwrap_err().code,
        ErrorCode::RequestExpired
    );
    // Still reported as expired, not unknown, for a while.
    assert_eq!(t.g.get(&code).unwrap_err().code, ErrorCode::RequestExpired);
    assert!(!t.g.has_grant("s_1", "db", Mode::Use));

    let id2 = t.request(&agent("s_1"), &["db"], Mode::Use, None).unwrap();
    t.clock.advance(Duration::from_secs(301));
    let ex = t.g.sweep();
    assert_eq!(ex.requests.len(), 1);
    assert_eq!(ex.requests[0].id, id2);
    // Tombstones are forgotten after another pending_expiry.
    t.clock.advance(Duration::from_secs(600));
    t.g.sweep();
    assert_eq!(t.g.get(&code).unwrap_err().code, ErrorCode::RequestNotFound);
}

#[test]
fn default_ttls_follow_policy() {
    let mut t = setup();
    let s = agent("s_1");
    let id = t.request(&s, &["db"], Mode::Use, None).unwrap();
    assert!(
        matches!(t.g.get_by_id(&id).unwrap().kind, RequestKind::Grant { ttl, .. } if ttl == Duration::from_secs(3600))
    );
    let id = t.request(&s, &["token"], Mode::Reveal, None).unwrap();
    assert!(
        matches!(t.g.get_by_id(&id).unwrap().kind, RequestKind::Grant { ttl, .. } if ttl == Duration::from_secs(600))
    );
}

#[test]
fn limits_give_the_matching_error_codes() {
    let mut t = setup();
    let s = agent("s_1");
    let code = |r: Result<String, GrantError>| r.unwrap_err().code;
    assert_eq!(
        code(t.request(&s, &["db", "nope"], Mode::Use, None)),
        ErrorCode::UnknownSecret
    );
    assert_eq!(
        code(t.request(&s, &["Bad Name"], Mode::Use, None)),
        ErrorCode::UnknownSecret
    );
    assert_eq!(
        code(t.request(&s, &[], Mode::Use, None)),
        ErrorCode::LimitExceeded
    );
    assert_eq!(
        code(t.request(&s, &["db"], Mode::Use, Some(8 * 3600 + 1))),
        ErrorCode::LimitExceeded
    );
    assert_eq!(
        code(t.request(&s, &["db"], Mode::Use, Some(0))),
        ErrorCode::LimitExceeded
    );
    assert_eq!(
        code(t.request(&s, &["db"], Mode::Reveal, Some(601))),
        ErrorCode::LimitExceeded
    );
    assert!(t.request(&s, &["db"], Mode::Use, Some(8 * 3600)).is_ok());

    let many: Vec<String> = (0..17).map(|i| format!("s{i}")).collect();
    let all_known = |_: &str| true;
    let e =
        t.g.request_grant(&s, 1000, ask(&many, Mode::Use, None), all_known, digest)
            .unwrap_err();
    assert_eq!(e.code, ErrorCode::LimitExceeded);

    let long = "x".repeat(MAX_REASON_BYTES + 1);
    let n = names(&["db"]);
    let a = GrantAsk {
        reason: &long,
        ..ask(&n, Mode::Use, None)
    };
    assert_eq!(
        t.g.request_grant(&s, 1000, a, known, digest)
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );

    t.g.set_policy(Policy {
        allow_reveal: false,
        ..Policy::default()
    });
    assert_eq!(
        code(t.request(&s, &["db"], Mode::Reveal, None)),
        ErrorCode::LimitExceeded
    );
}

#[test]
fn human_sessions_cannot_hold_grants_but_can_mutate() {
    let mut t = setup();
    let h = session("h_1", AnchorKind::Human);
    let e = t.request(&h, &["db"], Mode::Use, None).unwrap_err();
    assert_eq!(e.code, ErrorCode::NoSession);
    let m = Mutation::Set {
        name: "db".into(),
        value: SecretValue::new(b"new-value-1".to_vec()),
    };
    let id =
        t.g.request_mutation(&h, 1000, vec![m.clone()], "rotate", digest)
            .unwrap()
            .id
            .clone();
    assert_eq!(
        t.g.get_by_id(&id).unwrap().kind.approval_kind(),
        countersign_proto::ApprovalKind::Mutate
    );
    let a = t.g.approve(&id).unwrap();
    assert!(a.grant.is_none());
    assert_eq!(a.request.kind, RequestKind::Mutation(vec![m]));
}

#[test]
fn pending_and_hourly_caps_and_deny_cooldown() {
    let mut t = setup();
    let s = agent("s_1");
    let ids: Vec<String> = ["a", "b", "c"]
        .iter()
        .map(|n| t.request(&s, &[n], Mode::Use, None).unwrap())
        .collect();
    assert_eq!(
        t.request(&s, &["d"], Mode::Use, None).unwrap_err().code,
        ErrorCode::RateLimited
    );
    // Another session is not affected.
    assert!(t.request(&agent("s_2"), &["d"], Mode::Use, None).is_ok());

    let denied = t.g.deny(&ids[0]).unwrap();
    assert_eq!(denied.kind.names(), ["a"]);
    let e = t.request(&s, &["a", "d"], Mode::Use, None).unwrap_err();
    assert_eq!((e.code, e.names), (ErrorCode::RateLimited, names(&["a"])));
    assert!(t.request(&s, &["d"], Mode::Use, None).is_ok());
    t.clock.advance(Duration::from_secs(120));
    t.g.sweep();
    assert!(
        t.request(&agent("s_1"), &["a"], Mode::Use, None).is_err(),
        "still 3 pending"
    );
    for id in
        t.g.pending_for("s_1")
            .into_iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>()
    {
        t.g.deny(&id).unwrap();
    }
    t.clock.advance(Duration::from_secs(120));
    assert!(t.request(&s, &["a"], Mode::Use, None).is_ok());

    // 30 requests per hour.
    let mut t = setup();
    let mut made = 0;
    for _ in 0..40 {
        if let Ok(id) = t.request(&s, &["db"], Mode::Use, None) {
            t.g.approve(&id).unwrap();
            made += 1;
        }
    }
    assert_eq!(made, 30);
    t.clock.advance(Duration::from_secs(3600));
    assert!(t.request(&s, &["db"], Mode::Use, None).is_ok());
}

#[test]
fn reveal_grants_are_consumed() {
    let mut t = setup();
    let id = t
        .request(&agent("s_1"), &["token"], Mode::Reveal, None)
        .unwrap();
    let g = t.g.approve(&id).unwrap().grant.unwrap();
    assert_eq!(g.uses_left, Some(1));
    assert_eq!(
        t.g.consume_reveal("s_1", "token").unwrap(),
        (g.id.clone(), 0)
    );
    let e = t.g.consume_reveal("s_1", "token").unwrap_err();
    assert_eq!(e.code, ErrorCode::GrantRequired);
    assert!(!t.g.has_grant("s_1", "token", Mode::Reveal));
}

#[test]
fn revoke_one_all_by_secret_and_by_session_end() {
    let mut t = setup();
    let s = agent("s_1");
    let g1 = {
        let id = t.request(&s, &["a", "b"], Mode::Use, None).unwrap();
        t.g.approve(&id).unwrap().grant.unwrap()
    };
    let id = t.request(&s, &["c"], Mode::Use, None).unwrap();
    t.g.approve(&id).unwrap();
    let id = t.request(&agent("s_2"), &["a"], Mode::Use, None).unwrap();
    t.g.approve(&id).unwrap();

    assert_eq!(
        t.g.revoke("s_2", Some(&g1.id)).unwrap_err().code,
        ErrorCode::GrantRequired
    );
    assert_eq!(t.g.revoke("s_1", Some(&g1.id)).unwrap(), vec![g1]);
    assert!(!t.g.has_grant("s_1", "a", Mode::Use));
    assert!(t.g.has_grant("s_1", "c", Mode::Use));

    let gone = t.g.revoke_secret("a");
    assert_eq!(gone.len(), 1);
    assert_eq!(gone[0].session, "s_2");

    let pending = t.request(&s, &["d"], Mode::Use, None).unwrap();
    let ended = t.g.end_session("s_1");
    assert_eq!(ended.requests.len(), 1);
    assert_eq!(ended.requests[0].id, pending);
    assert_eq!(ended.grants.len(), 1);
    assert!(t.g.grants_for("s_1").is_empty());
    assert!(t.g.revoke("s_1", None).unwrap().is_empty());
}

#[test]
fn codes_are_unique_among_pending_requests() {
    let p = Policy {
        max_pending_requests: 10_000,
        max_pending_requests_per_uid: 10_000,
        requests_per_hour: 10_000,
        requests_per_hour_per_uid: 10_000,
        ..Policy::default()
    };
    let clock = Arc::new(ManualClock::new(start()));
    let mut g = Grants::new(p, clock);
    let n = names(&["db"]);
    let mut codes = std::collections::HashSet::new();
    for i in 0..2000 {
        let s = agent(&format!("s_{i}"));
        let r = g
            .request_grant(&s, 1000, ask(&n, Mode::Use, None), known, digest)
            .unwrap();
        assert!(codes.insert(r.code), "duplicate code");
    }
}

#[test]
fn the_digest_function_sees_the_final_request() {
    let mut t = setup();
    let n = names(&["db"]);
    let r =
        t.g.request_grant(&agent("s_1"), 1000, ask(&n, Mode::Use, None), known, |r| {
            assert_eq!(r.digest, [0; 32]);
            let mut d = [0; 32];
            d[..8].copy_from_slice(
                &r.created_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_be_bytes(),
            );
            d[8..].copy_from_slice(&r.nonce[..24]);
            d
        })
        .unwrap();
    assert_eq!(r.digest[8..], r.nonce[..24]);
}

#[test]
fn new_sessions_do_not_escape_the_per_uid_limits() {
    let mut t = setup();
    // Ten pending per uid, however many sessions ask.
    let mut ok = 0;
    for i in 0..20 {
        if t.request(&agent(&format!("s_{i}")), &["db"], Mode::Use, None)
            .is_ok()
        {
            ok += 1;
        }
    }
    assert_eq!(ok, 10);
    let e = t
        .request(&agent("s_new"), &["db"], Mode::Use, None)
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::RateLimited);
    // Another uid is not affected.
    let n = names(&["db"]);
    assert!(
        t.g.request_grant(
            &agent("s_other"),
            1001,
            ask(&n, Mode::Use, None),
            known,
            digest
        )
        .is_ok()
    );

    // A deny cools the secret down for the uid, in every session.
    let mut t = setup();
    let id = t.request(&agent("s_1"), &["a"], Mode::Use, None).unwrap();
    t.g.deny(&id).unwrap();
    t.g.end_session("s_1");
    let e = t
        .request(&agent("s_2"), &["a"], Mode::Use, None)
        .unwrap_err();
    assert_eq!((e.code, e.names), (ErrorCode::RateLimited, names(&["a"])));
    t.clock.advance(Duration::from_secs(120));
    assert!(t.request(&agent("s_2"), &["a"], Mode::Use, None).is_ok());

    // 120 requests per uid per hour, spread over sessions of 30 each.
    let mut t = setup();
    let mut made = 0;
    for i in 0..200 {
        let s = agent(&format!("s_{}", i / 30));
        if let Ok(id) = t.request(&s, &["db"], Mode::Use, None) {
            t.g.approve(&id).unwrap();
            made += 1;
        }
    }
    assert_eq!(made, 120);
    t.clock.advance(Duration::from_secs(3600));
    t.g.sweep();
    assert!(t.request(&agent("s_99"), &["db"], Mode::Use, None).is_ok());
}
