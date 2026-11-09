//! Round trips for every message variant, and golden JSON for a few.

use std::collections::BTreeMap;

use countersign_proto::{
    APPROVE_DOMAIN, Anchor, ApprovalKind, ApproverView, CanonicalRequest, ChainEntry, Decision,
    Driven, Envelope, ErrorBody, ErrorCode, GrantView, ImportItem, LastUse, Mode, Request,
    RequestState, RequestView, Response, RunValue, ScrubValue, SecretMeta, SecretView, SessionView,
    Timestamp, Use, ValueB64, ValueSource, default_env, read_frame, write_message,
};
use serde_json::{Value, json};

fn ts(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn anchor() -> Anchor {
    Anchor {
        pid: 41210,
        starttime: 8_812_345,
        comm: "claude".into(),
        registered: true,
    }
}

fn meta() -> SecretMeta {
    SecretMeta {
        name: "clickhouse-password".into(),
        description: "ClickHouse analytics, read-only user `reporter`".into(),
        usage: "Read-only queries from scripts/clickhouse_*.py.".into(),
        projects: vec!["~/projects/moose/*".into()],
        tags: vec!["db".into()],
        high_entropy: false,
    }
}

fn session() -> SessionView {
    SessionView {
        id: "s_7k2mq9d4x1ha".into(),
        anchor: anchor(),
        started_at: ts("2026-11-08T09:14:03Z"),
        label: Some("orchestrator".into()),
        chain: vec![
            ChainEntry {
                pid: 41377,
                comm: "cn".into(),
                starttime: 8_900_000,
            },
            ChainEntry {
                pid: 41210,
                comm: "claude".into(),
                starttime: 8_812_345,
            },
        ],
        labels: BTreeMap::from([("CLAUDE_CODE_SESSION_ID".into(), "9f3c".into())]),
        cwd: Some("/home/patrick/projects/x".into()),
        alive: true,
        active_grants: 1,
    }
}

fn grant() -> GrantView {
    GrantView {
        id: "g_4hx2".into(),
        secrets: vec!["clickhouse-password".into()],
        mode: Mode::Use,
        expires_at: ts("2026-11-08T09:51:40Z"),
        approved_by: vec!["polkit".into()],
        uses: 2,
        reveals_left: None,
        session: "s_7k2mq9d4x1ha".into(),
    }
}

fn canonical() -> CanonicalRequest {
    CanonicalRequest {
        domain: APPROVE_DOMAIN.into(),
        request_id: "r_9w1k".into(),
        code: "K7M-Q2X".into(),
        host: "4f1c".into(),
        boot_id: "5e1c".into(),
        session: "s_7k2mq9d4x1ha".into(),
        anchor: anchor(),
        cwd: Some("/home/patrick/projects/x".into()),
        secrets: vec!["clickhouse-password".into()],
        mode: ApprovalKind::Use,
        ttl_seconds: Some(1800),
        operation: None,
        reason: "row counts".into(),
        created_at: ts("2026-11-08T09:20:11Z"),
        expires_at: ts("2026-11-08T09:25:11Z"),
        nonce: "bm9uY2U".into(),
    }
}

fn request_view(state: RequestState) -> RequestView {
    let request = canonical();
    let digest = request.digest().unwrap();
    RequestView {
        request,
        state,
        digest: digest.hex(),
        digest_short: digest.short(),
        approvers: vec![ApproverView {
            name: "polkit".into(),
            adapter: "polkit".into(),
            driven: Driven::Daemon,
            prompted: true,
        }],
        decision: (state != RequestState::Pending).then(|| Decision {
            at: ts("2026-11-08T09:21:40Z"),
            by: vec!["polkit".into()],
            reason: None,
            grant: Some(grant()),
            grants_revoked: 0,
            error: None,
        }),
        queued: false,
    }
}

fn all_requests() -> Vec<Request> {
    vec![
        Request::Hello {
            protocols: vec![1],
            client: "cn/0.1.0".into(),
            labels: BTreeMap::from([("CLAUDE_CODE_SESSION_ID".into(), "9f3c".into())]),
            cwd: Some("/home/patrick/projects/x".into()),
        },
        Request::Session,
        Request::List { all_projects: true },
        Request::Request {
            names: vec!["clickhouse-password".into()],
            mode: Mode::Reveal,
            ttl_seconds: Some(600),
            reason: "the human asked".into(),
        },
        Request::Request {
            names: vec!["a".into(), "b".into()],
            mode: Mode::Use,
            ttl_seconds: None,
            reason: "default ttl".into(),
        },
        Request::GetRequest {
            code: "K7M-Q2X".into(),
            wait_seconds: Some(60),
        },
        Request::Approve {
            code: "K7M-Q2X".into(),
            approver: "desk-key".into(),
            assertion: Some("YXNzZXJ0aW9u".into()),
        },
        Request::Deny {
            code: "K7M-Q2X".into(),
            reason: Some("wrong secret".into()),
        },
        Request::Grants { all_sessions: true },
        Request::Revoke {
            grant_ids: vec!["g_4hx2".into()],
            secret: None,
            all: false,
            all_sessions: false,
        },
        Request::Revoke {
            grant_ids: vec![],
            secret: Some("clickhouse-password".into()),
            all: false,
            all_sessions: true,
        },
        Request::Run {
            uses: vec![Use {
                name: "clickhouse-password".into(),
                env: "CLICKHOUSE_PASSWORD".into(),
            }],
            argv0: "python3".into(),
            argc: 3,
        },
        Request::RunFinish {
            run_id: "u_8d1e".into(),
            exit: None,
            signal: Some(15),
            duration_ms: 6100,
            hits: BTreeMap::from([("clickhouse-password".into(), 1)]),
        },
        Request::Hide {
            secrets: vec!["clickhouse-password".into()],
        },
        Request::HideEnd,
        Request::Reveal {
            name: "github-token".into(),
        },
        Request::Add {
            meta: meta(),
            value_b64: ValueB64::encode(b"hunter2hunter2"),
            source: Some(ValueSource::Clipboard),
        },
        Request::Set {
            name: "github-token".into(),
            value_b64: ValueB64::encode(b"ghp_new"),
            source: Some(ValueSource::Stdin),
        },
        Request::Edit { meta: meta() },
        Request::Rm {
            names: vec!["old-key".into(), "older-key".into()],
        },
        Request::Import {
            secrets: vec![ImportItem {
                meta: meta(),
                value_b64: ValueB64::encode(b"imported value"),
            }],
        },
        Request::AuditQuery {
            session: Some("s_7k2mq9d4x1ha".into()),
            secret: Some("clickhouse-password".into()),
            events: vec!["use.start".into(), "reveal".into()],
            since: Some(ts("2026-11-08T08:00:00Z")),
            until: None,
            after_seq: Some(18330),
            limit: Some(50),
        },
        Request::AuditSegments { from_seq: 1 },
        Request::SessionRegister {
            label: Some("liskov drift".into()),
        },
        Request::Unlock { hmac_output: None },
    ]
}

fn all_responses() -> Vec<Response> {
    vec![
        Response::HelloOk {
            protocol: 1,
            server: "cnd/0.1.0".into(),
            session: Some(session()),
        },
        Response::HelloOk {
            protocol: 1,
            server: "cnd/0.1.0".into(),
            session: None,
        },
        Response::Session { session: session() },
        Response::List {
            session: Some("s_7k2mq9d4x1ha".into()),
            secrets: vec![SecretView {
                meta: meta(),
                in_project: true,
                default_env: "CLICKHOUSE_PASSWORD".into(),
                grant: Some(grant()),
                created: Some(ts("2026-10-02T11:40:00Z")),
                updated: Some(ts("2026-10-02T11:40:00Z")),
                rotated: Some(ts("2026-10-02T11:40:00Z")),
                last_use: Some(LastUse {
                    at: ts("2026-11-08T09:31:12Z"),
                    session: "s_7k2mq9d4x1ha".into(),
                    argv0: Some("python3".into()),
                }),
            }],
        },
        Response::RequestCreated(request_view(RequestState::Pending)),
        Response::AlreadyGranted { grant: grant() },
        Response::RequestStatus(request_view(RequestState::Approved)),
        Response::RequestStatus(request_view(RequestState::Expired)),
        Response::Approved {
            request_id: "r_9w1k".into(),
            code: "K7M-Q2X".into(),
            grant_ids: vec!["g_4hx2".into()],
        },
        Response::Pending {
            request_id: "r_9w1k".into(),
            code: "K7M-Q2X".into(),
            waiting_for: vec!["desk-key".into()],
        },
        Response::Denied {
            request_id: "r_9w1k".into(),
            code: "K7M-Q2X".into(),
        },
        Response::Grants {
            grants: vec![grant()],
        },
        Response::Revoked {
            grants: vec![grant()],
        },
        Response::RunOk {
            run_id: "u_8d1e".into(),
            values: vec![RunValue {
                name: "clickhouse-password".into(),
                env: "CLICKHOUSE_PASSWORD".into(),
                value_b64: ValueB64::encode(b"correct horse battery"),
            }],
            patterns_extra: vec![ScrubValue {
                name: "github-token".into(),
                value_b64: ValueB64::encode(b"ghp_0123456789"),
            }],
        },
        Response::Ok,
        Response::HideOk,
        Response::HideSummary {
            bytes_in: 14336,
            bytes_out: 14310,
            hits: BTreeMap::from([("clickhouse-password".into(), 1)]),
        },
        Response::Reveal {
            name: "github-token".into(),
            value_b64: ValueB64::encode(b"ghp_0123456789"),
            reveals_left: Some(0),
        },
        Response::AuditRecords {
            records: vec![json!({"v":1,"seq":1,"event":"daemon.start","session":null})],
        },
        Response::AuditSegments {
            data_b64: "eyJ2IjoxfQo=".into(),
            next_seq: Some(1001),
            checkpoint_pubkey: None,
        },
        Response::Registered { session: session() },
        Response::Unsealed {
            slot: "systemd-creds".into(),
        },
        Response::Error(ErrorBody {
            code: ErrorCode::GrantRequired,
            message: "no active grant for 'clickhouse-prod' in session s_7k2mq9d4x1ha".into(),
            detail: json!({"names": ["clickhouse-prod"]}),
        }),
    ]
}

fn round_trip<T>(body: T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug + Clone,
{
    let msg = Envelope { id: 42, body };
    let mut frame = Vec::new();
    write_message(&mut frame, &msg).unwrap();
    let (_, payload) = read_frame(&mut frame.as_slice()).unwrap().unwrap();
    let back: Envelope<T> = serde_json::from_slice(&payload).unwrap();
    assert_eq!(back, msg, "{}", String::from_utf8_lossy(&payload));

    let value: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(value["id"], 42);
    let tag = value["type"].as_str().unwrap();
    assert!(
        tag.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
        "tag {tag} is not snake_case"
    );
}

#[test]
fn every_request_round_trips() {
    let requests = all_requests();
    let tags: std::collections::BTreeSet<String> = requests
        .iter()
        .map(|r| {
            serde_json::to_value(r).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        tags.len(),
        23,
        "a Request variant is missing here: {tags:?}"
    );
    for r in requests {
        round_trip(r);
    }
}

#[test]
fn every_response_round_trips() {
    let responses = all_responses();
    let tags: std::collections::BTreeSet<String> = responses
        .iter()
        .map(|r| {
            serde_json::to_value(r).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        tags.len(),
        21,
        "a Response variant is missing here: {tags:?}"
    );
    for r in responses {
        round_trip(r);
    }
}

#[test]
fn golden_error_matches_the_design_example() {
    let text = r#"{"type":"error","id":7,"code":"grant_required","message":"no active grant for 'clickhouse-prod' in session s_7k2mq9d4x1ha","detail":{"names":["clickhouse-prod"]}}"#;
    let msg: Envelope<Response> = serde_json::from_str(text).unwrap();
    assert_eq!(msg.id, 7);
    let Response::Error(body) = &msg.body else {
        panic!("{msg:?}")
    };
    assert_eq!(body.code, ErrorCode::GrantRequired);
    assert_eq!(
        serde_json::to_value(&msg).unwrap(),
        serde_json::from_str::<Value>(text).unwrap()
    );
}

#[test]
fn golden_hello_ok_without_a_session() {
    let msg = Envelope {
        id: 1,
        body: Response::HelloOk {
            protocol: 1,
            server: "cnd/0.1.0".into(),
            session: None,
        },
    };
    assert_eq!(
        serde_json::to_string(&msg).unwrap(),
        r#"{"id":1,"type":"hello_ok","protocol":1,"server":"cnd/0.1.0","session":null}"#
    );
    // A server may leave the field out.
    let short: Envelope<Response> =
        serde_json::from_str(r#"{"type":"hello_ok","id":1,"protocol":1,"server":"cnd/0.1.0"}"#)
            .unwrap();
    assert_eq!(short, msg);
}

#[test]
fn golden_run_ok() {
    let msg = Envelope {
        id: 3,
        body: Response::RunOk {
            run_id: "u_8d1e".into(),
            values: vec![RunValue {
                name: "db".into(),
                env: "DB".into(),
                value_b64: ValueB64::encode(b"s3cret-value"),
            }],
            patterns_extra: vec![],
        },
    };
    assert_eq!(
        serde_json::to_string(&msg).unwrap(),
        r#"{"id":3,"type":"run_ok","run_id":"u_8d1e","values":[{"name":"db","env":"DB","value_b64":"czNjcmV0LXZhbHVl"}],"patterns_extra":[]}"#
    );
}

#[test]
fn golden_request_created_flattens_the_canonical_fields() {
    let value = serde_json::to_value(Envelope {
        id: 5,
        body: Response::RequestCreated(request_view(RequestState::Pending)),
    })
    .unwrap();
    assert_eq!(value["type"], "request_created");
    assert_eq!(value["request_id"], "r_9w1k");
    assert_eq!(value["code"], "K7M-Q2X");
    assert_eq!(value["state"], "pending");
    assert_eq!(value["mode"], "use");
    assert_eq!(value["ttl_seconds"], 1800);
    assert_eq!(value["expires_at"], "2026-11-08T09:25:11Z");
    assert_eq!(value["approvers"][0]["driven"], "daemon");
    assert_eq!(value["decision"], Value::Null);
    assert!(value.get("operation").is_none());

    // A client rebuilds the canonical request from the view and gets the
    // digest the server reported.
    let back: Envelope<Response> = serde_json::from_value(value).unwrap();
    let Response::RequestCreated(view) = back.body else {
        panic!()
    };
    let digest = view.request.digest().unwrap();
    assert_eq!(digest.hex(), view.digest);
    assert_eq!(digest.short(), view.digest_short);
}

#[test]
fn golden_request_from_the_cli_example() {
    let text = r#"{"type":"request","id":2,"names":["clickhouse-password"],"mode":"use","ttl_seconds":1800,"reason":"row counts"}"#;
    let msg: Envelope<Request> = serde_json::from_str(text).unwrap();
    assert_eq!(
        msg.body,
        Request::Request {
            names: vec!["clickhouse-password".into()],
            mode: Mode::Use,
            ttl_seconds: Some(1800),
            reason: "row counts".into(),
        }
    );
    // Unit-like variants accept the bare tag; defaulted fields may be absent.
    let hide: Envelope<Request> = serde_json::from_str(r#"{"type":"hide","id":9}"#).unwrap();
    assert_eq!(hide.body, Request::Hide { secrets: vec![] });
}

#[test]
fn unknown_error_codes_and_fields_are_tolerated() {
    let text = r#"{"type":"error","id":1,"code":"brand_new_code","message":"m","extra":1}"#;
    let msg: Envelope<Response> = serde_json::from_str(text).unwrap();
    let Response::Error(body) = msg.body else {
        panic!()
    };
    assert_eq!(body.code, ErrorCode::Unknown);
    assert_eq!(body.detail, Value::Null);
}

#[test]
fn values_never_appear_in_debug_output() {
    let r = Request::Set {
        name: "x".into(),
        value_b64: ValueB64::encode(b"do-not-print-me"),
        source: None,
    };
    let debug = format!("{r:?}");
    assert!(
        !debug.contains(ValueB64::encode(b"do-not-print-me").as_str()),
        "{debug}"
    );
    assert!(debug.contains("<redacted>"));
    assert_eq!(
        ValueB64::encode(b"do-not-print-me")
            .decode()
            .unwrap()
            .as_slice(),
        b"do-not-print-me"
    );
}

#[test]
fn default_env_is_upper_snake_case() {
    assert_eq!(default_env("clickhouse-prod"), "CLICKHOUSE_PROD");
    assert_eq!(default_env("typesafe.api-key"), "TYPESAFE_API_KEY");
    assert_eq!(default_env("a1"), "A1");
}
