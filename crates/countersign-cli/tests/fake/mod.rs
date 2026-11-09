//! A fake `cnd` for integration tests: a thread per connection on a temp
//! Unix socket, speaking countersign-proto. `cn` reaches it through
//! `COUNTERSIGN_SOCKET`, which debug builds honour.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use countersign_hide::{Builder, Secret};
use countersign_proto::{
    APPROVE_DOMAIN, Anchor, ApprovalKind, ApproverView, CanonicalRequest, ChainEntry, Decision,
    Driven, Envelope, ErrorBody, ErrorCode, GrantView, Kind, Mode, Request, RequestState,
    RequestView, Response, RunValue, SecretMeta, SecretView, SessionView, Timestamp, ValueB64,
    default_env, read_frame, write_frame, write_message,
};
use serde_json::json;

/// What `get_request` with a wait decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decide {
    Approve,
    Deny,
    Stay,
}

pub struct State {
    pub secrets: Vec<(SecretMeta, Vec<u8>)>,
    pub granted: BTreeSet<String>,
    pub decide: Decide,
    pub log: Vec<Request>,
    pub requests: BTreeMap<String, RequestView>,
}

pub struct Fake {
    _dir: tempfile::TempDir,
    pub socket: PathBuf,
    pub state: Arc<Mutex<State>>,
}

pub const DB_VALUE: &[u8] = b"s3cret-db-password-77";
pub const TOKEN_VALUE: &[u8] = b"ghp_0123456789abcdefABCDEF";

fn meta(name: &str, description: &str, high_entropy: bool) -> SecretMeta {
    SecretMeta {
        name: name.into(),
        description: description.into(),
        usage: format!("Use {name} only from scripts.\nNever log it."),
        projects: vec![],
        tags: vec![],
        high_entropy,
    }
}

pub fn session() -> SessionView {
    SessionView {
        id: "s_fake0000test".into(),
        anchor: Anchor {
            pid: 4242,
            starttime: 1000,
            comm: "claude".into(),
            registered: true,
        },
        started_at: "2026-11-08T09:14:03Z".parse().unwrap(),
        label: Some("tests".into()),
        chain: vec![
            ChainEntry {
                pid: 4300,
                comm: "cn".into(),
                starttime: 2000,
            },
            ChainEntry {
                pid: 4242,
                comm: "claude".into(),
                starttime: 1000,
            },
        ],
        labels: BTreeMap::new(),
        cwd: Some("/home/dev/project".into()),
        alive: true,
        active_grants: 0,
    }
}

fn grant(names: &[String]) -> GrantView {
    GrantView {
        id: "g_test1".into(),
        secrets: names.to_vec(),
        mode: Mode::Use,
        expires_at: Timestamp::now().plus_seconds(1800),
        approved_by: vec!["polkit".into()],
        uses: 0,
        reveals_left: None,
        session: session().id,
    }
}

fn new_view(
    names: Vec<String>,
    mode: ApprovalKind,
    ttl: Option<u64>,
    op: Option<String>,
    reason: String,
) -> RequestView {
    let now = Timestamp::now();
    let request = CanonicalRequest {
        domain: APPROVE_DOMAIN.into(),
        request_id: "r_fake1".into(),
        code: "K7M-Q2X".into(),
        host: "machine".into(),
        boot_id: "boot".into(),
        session: session().id,
        anchor: session().anchor,
        cwd: Some("/home/dev/project".into()),
        secrets: names,
        mode,
        ttl_seconds: ttl,
        operation: op,
        reason,
        created_at: now,
        expires_at: now.plus_seconds(300),
        nonce: "bm9uY2U".into(),
    };
    let digest = request.digest().unwrap();
    RequestView {
        request,
        state: RequestState::Pending,
        digest: digest.hex(),
        digest_short: digest.short(),
        approvers: vec![ApproverView {
            name: "polkit".into(),
            adapter: "polkit".into(),
            driven: Driven::Daemon,
            prompted: true,
        }],
        decision: None,
        queued: false,
    }
}

fn error(code: ErrorCode, message: &str, detail: serde_json::Value) -> Response {
    Response::Error(ErrorBody {
        code,
        message: message.into(),
        detail,
    })
}

impl Fake {
    pub fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("cnd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let state = Arc::new(Mutex::new(State {
            secrets: vec![
                (
                    meta("db", "Test database password", false),
                    DB_VALUE.to_vec(),
                ),
                (meta("gh-token", "GitHub token", true), TOKEN_VALUE.to_vec()),
            ],
            granted: BTreeSet::new(),
            decide: Decide::Approve,
            log: Vec::new(),
            requests: BTreeMap::new(),
        }));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { break };
                let state = Arc::clone(&shared);
                std::thread::spawn(move || serve(conn, &state));
            }
        });
        Self {
            _dir: dir,
            socket,
            state,
        }
    }

    pub fn grant(&self, name: &str) {
        self.state.lock().unwrap().granted.insert(name.into());
    }

    pub fn decide(&self, d: Decide) {
        self.state.lock().unwrap().decide = d;
    }

    pub fn log(&self) -> Vec<Request> {
        self.state.lock().unwrap().log.clone()
    }

    pub fn cn(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_cn"));
        c.env("COUNTERSIGN_SOCKET", &self.socket);
        c
    }
}

fn send(stream: &UnixStream, id: u64, body: Response) {
    let mut w = stream;
    let _ = write_message(&mut w, &Envelope { id, body });
}

fn serve(stream: UnixStream, state: &Mutex<State>) {
    let mut r = &stream;
    // A hide stream: the redactor, the input so far, and its length. The
    // fake answers everything at `hide_end`, in small frames; the real
    // daemon streams as it goes, which cn handles the same way.
    let mut hide: Option<(countersign_hide::Redactor, Vec<u8>, u64)> = None;
    while let Ok(Some((kind, payload))) = read_frame(&mut r) {
        if kind == Kind::Stream {
            if let Some((_, input, bytes_in)) = hide.as_mut() {
                input.extend_from_slice(&payload);
                *bytes_in += payload.len() as u64;
            }
            continue;
        }
        let msg: Envelope<Request> = match serde_json::from_slice(&payload) {
            Ok(m) => m,
            Err(_) => return,
        };
        let id = msg.id;
        if !matches!(msg.body, Request::Hello { .. }) {
            state.lock().unwrap().log.push(msg.body.clone());
        }
        let reply = match msg.body {
            Request::Hello { .. } => Response::HelloOk {
                protocol: 1,
                server: "cnd/fake".into(),
                session: Some(session()),
            },
            Request::Session => Response::Session { session: session() },
            Request::SessionRegister { .. } => Response::Registered { session: session() },
            Request::List { .. } => {
                let st = state.lock().unwrap();
                Response::List {
                    session: Some(session().id),
                    secrets: st
                        .secrets
                        .iter()
                        .map(|(m, _)| SecretView {
                            meta: m.clone(),
                            in_project: true,
                            default_env: default_env(&m.name),
                            grant: st
                                .granted
                                .contains(&m.name)
                                .then(|| grant(std::slice::from_ref(&m.name))),
                            created: None,
                            updated: None,
                            rotated: None,
                            last_use: None,
                        })
                        .collect(),
                }
            }
            Request::Request {
                names,
                mode,
                ttl_seconds,
                reason,
            } => {
                let mut st = state.lock().unwrap();
                if let Some(bad) = names
                    .iter()
                    .find(|n| !st.secrets.iter().any(|(m, _)| &m.name == *n))
                {
                    error(
                        ErrorCode::UnknownSecret,
                        &format!("no secret named '{bad}'"),
                        json!({"names": [bad]}),
                    )
                } else {
                    let view =
                        new_view(names, mode.into(), ttl_seconds.or(Some(3600)), None, reason);
                    st.requests.insert(view.request.code.clone(), view.clone());
                    Response::RequestCreated(view)
                }
            }
            Request::Add { meta, .. } => {
                let mut st = state.lock().unwrap();
                let view = new_view(
                    vec![meta.name.clone()],
                    ApprovalKind::Mutate,
                    None,
                    Some(format!("add {}", meta.name)),
                    String::new(),
                );
                st.requests.insert(view.request.code.clone(), view.clone());
                Response::RequestCreated(view)
            }
            Request::GetRequest { code, wait_seconds } => {
                let mut st = state.lock().unwrap();
                let decide = st.decide;
                match st.requests.get_mut(&code) {
                    None => error(ErrorCode::RequestNotFound, "no such request", json!(null)),
                    Some(view) => {
                        if wait_seconds.is_some() && view.state == RequestState::Pending {
                            match decide {
                                Decide::Approve => {
                                    view.state = RequestState::Approved;
                                    view.decision = Some(Decision {
                                        at: Timestamp::now(),
                                        by: vec!["polkit".into()],
                                        reason: None,
                                        grant: (view.request.mode != ApprovalKind::Mutate)
                                            .then(|| grant(&view.request.secrets)),
                                        grants_revoked: 0,
                                        error: None,
                                    });
                                }
                                Decide::Deny => {
                                    view.state = RequestState::Denied;
                                    view.decision = Some(Decision {
                                        at: Timestamp::now(),
                                        by: vec!["polkit".into()],
                                        reason: Some("dialog dismissed".into()),
                                        grant: None,
                                        grants_revoked: 0,
                                        error: None,
                                    });
                                }
                                Decide::Stay => {}
                            }
                        }
                        Response::RequestStatus(view.clone())
                    }
                }
            }
            Request::Deny { code, .. } => Response::Denied {
                request_id: "r_fake1".into(),
                code,
            },
            Request::Grants { .. } => {
                let st = state.lock().unwrap();
                Response::Grants {
                    grants: st
                        .granted
                        .iter()
                        .map(|n| grant(std::slice::from_ref(n)))
                        .collect(),
                }
            }
            Request::Revoke { .. } => {
                let mut st = state.lock().unwrap();
                let grants = st
                    .granted
                    .iter()
                    .map(|n| grant(std::slice::from_ref(n)))
                    .collect();
                st.granted.clear();
                Response::Revoked { grants }
            }
            Request::Run { uses, .. } => {
                let st = state.lock().unwrap();
                let missing: Vec<&str> = uses
                    .iter()
                    .filter(|u| !st.granted.contains(&u.name))
                    .map(|u| u.name.as_str())
                    .collect();
                if missing.is_empty() {
                    Response::RunOk {
                        run_id: "u_fake1".into(),
                        values: uses
                            .iter()
                            .map(|u| RunValue {
                                name: u.name.clone(),
                                env: u.env.clone(),
                                value_b64: ValueB64::encode(
                                    &st.secrets.iter().find(|(m, _)| m.name == u.name).unwrap().1,
                                ),
                            })
                            .collect(),
                        patterns_extra: vec![],
                    }
                } else {
                    error(
                        ErrorCode::GrantRequired,
                        &format!(
                            "no active grant for '{}' in session s_fake0000test",
                            missing[0]
                        ),
                        json!({"names": missing}),
                    )
                }
            }
            Request::RunFinish { .. } => Response::Ok,
            Request::Hide { .. } => {
                let st = state.lock().unwrap();
                let redactor = Builder::default()
                    .build(st.secrets.iter().map(|(m, v)| Secret {
                        name: &m.name,
                        value: v,
                    }))
                    .unwrap();
                hide = Some((redactor, Vec::new(), 0));
                Response::HideOk
            }
            Request::HideEnd => {
                let Some((redactor, input, bytes_in)) = hide.take() else {
                    return;
                };
                let (out, hits) = redactor.redact(&input);
                let mut w = &stream;
                for chunk in out.chunks(7) {
                    let _ = write_frame(&mut w, Kind::Stream, chunk);
                }
                Response::HideSummary {
                    bytes_in,
                    bytes_out: out.len() as u64,
                    hits,
                }
            }
            Request::AuditQuery { .. } => Response::AuditRecords {
                records: vec![
                    json!({"v":1,"seq":1,"ts":"2026-11-08T09:20:11.000001Z","event":"request.create",
                           "session":{"id":"s_fake0000test"},"code":"K7M-Q2X","mode":"use",
                           "secrets":["db"],"ttl_seconds":1800,"reason":"row counts"}),
                    json!({"v":1,"seq":2,"ts":"2026-11-08T09:21:40.000001Z","event":"use.end",
                           "session":{"id":"s_fake0000test"},"run_id":"u_1","status":"exited",
                           "exit":0,"signal":null,"duration_ms":6100,"hits":{"db":1}}),
                ],
            },
            _ => error(ErrorCode::UnknownRequest, "not in the fake", json!(null)),
        };
        send(&stream, id, reply);
    }
}
