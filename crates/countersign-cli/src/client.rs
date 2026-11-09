//! The connection to `cnd`: socket choice, the peer check, the handshake,
//! and one request at a time.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use countersign_proto::{
    Envelope, FrameError, Kind, PROTOCOL_VERSION, Request, Response, SessionView, read_frame,
    write_frame,
};
use zeroize::Zeroize;

use crate::error::CnError;
use crate::output::Ctx;

/// The only socket a release build talks to.
pub const DEFAULT_SOCKET: &str = "/run/countersign/cnd.sock";

/// The system user `cnd` runs as.
pub const DAEMON_USER: &str = "countersign";

/// Environment variables sent as untrusted session labels. `cnd` keeps the
/// ones its `[sessions] label_env` lists.
pub const LABEL_ENV: &[&str] = &["CLAUDE_CODE_SESSION_ID", "CODEX_SESSION_ID"];

/// How long to wait for an ordinary answer.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The socket to use and whether it was overridden. Release builds always
/// use [`DEFAULT_SOCKET`]; debug builds honour `--socket` and then
/// `$COUNTERSIGN_SOCKET`, so tests can run a fake daemon.
pub fn socket_path(ctx: &Ctx) -> (PathBuf, bool) {
    #[cfg(debug_assertions)]
    {
        if let Some(path) = &ctx.socket {
            return (path.clone(), true);
        }
        if let Some(path) = std::env::var_os("COUNTERSIGN_SOCKET") {
            return (PathBuf::from(path), true);
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = ctx;
    (PathBuf::from(DEFAULT_SOCKET), false)
}

/// A frame from the daemon.
pub enum Incoming {
    /// A JSON message.
    Message(Box<Envelope<Response>>),
    /// Stream bytes (inside `hide`).
    Stream(Vec<u8>),
}

/// An open, handshaken connection.
pub struct Client {
    stream: UnixStream,
    next_id: u64,
    /// Protocol version the daemon chose.
    pub protocol: u32,
    /// Daemon name and version, e.g. `cnd/0.1.0`.
    pub server: String,
    /// The caller's session as `cnd` resolved it, if it found one.
    pub session: Option<SessionView>,
    /// The socket path used.
    pub path: PathBuf,
}

impl Client {
    /// Connects, checks the peer, and sends `hello`.
    pub fn connect(ctx: &Ctx) -> Result<Self, CnError> {
        let (path, overridden) = socket_path(ctx);
        let stream = UnixStream::connect(&path).map_err(|e| unreachable(&path, &e))?;
        check_peer(&stream, overridden)?;
        stream
            .set_read_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(|e| CnError::internal(format!("socket: {e}")))?;
        let mut client = Self {
            stream,
            next_id: 1,
            protocol: 0,
            server: String::new(),
            session: None,
            path,
        };
        let labels: BTreeMap<String, String> = LABEL_ENV
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_owned(), v)))
            .collect();
        let hello = Request::Hello {
            protocols: vec![PROTOCOL_VERSION],
            client: concat!("cn/", env!("CARGO_PKG_VERSION")).into(),
            labels,
            cwd: std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
        };
        match client.call(hello)? {
            Response::HelloOk {
                protocol,
                server,
                session,
            } => {
                if protocol != PROTOCOL_VERSION {
                    return Err(CnError::new(
                        "unsupported_version",
                        format!("cnd chose protocol {protocol}; cn speaks {PROTOCOL_VERSION}"),
                    )
                    .with_hint("cn doctor"));
                }
                client.protocol = protocol;
                client.server = server;
                client.session = session;
                Ok(client)
            }
            other => Err(unexpected("hello_ok", &other)),
        }
    }

    /// Sends a request and returns its id.
    pub fn send(&mut self, request: &Request) -> Result<u64, CnError> {
        let id = self.next_id;
        self.next_id += 1;
        send_message(&self.stream, id, request)?;
        Ok(id)
    }

    /// Reserves an id for a message another thread will send.
    pub fn reserve_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Reads one frame. A daemon `error` message is returned as a message;
    /// [`Client::call`] turns it into an error.
    pub fn recv(&mut self) -> Result<Incoming, CnError> {
        recv_frame(&self.stream)
    }

    /// Sends a request and reads its answer.
    pub fn call(&mut self, request: Request) -> Result<Response, CnError> {
        let id = self.send(&request)?;
        drop(request);
        match self.recv()? {
            Incoming::Message(msg) if msg.id == id => match msg.body {
                Response::Error(body) => Err(body.into()),
                body => Ok(body),
            },
            Incoming::Message(msg) => Err(CnError::internal(format!(
                "protocol error: answer to request {} arrived for request {id}",
                msg.id
            ))),
            Incoming::Stream(_) => Err(CnError::internal(
                "protocol error: stream data outside a hide stream",
            )),
        }
    }

    /// Sets how long a read may block (`None`: forever).
    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<(), CnError> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|e| CnError::internal(format!("socket: {e}")))
    }

    /// The socket, for a second thread (`hide`).
    pub fn try_clone_stream(&self) -> Result<UnixStream, CnError> {
        self.stream
            .try_clone()
            .map_err(|e| CnError::internal(format!("socket: {e}")))
    }

    /// The caller's session id, or `no_session`.
    pub fn session_id(&self) -> Result<&str, CnError> {
        self.session.as_ref().map(|s| s.id.as_str()).ok_or_else(|| {
            CnError::new("no_session", "cnd found no session anchor for this process")
                .with_hint("start the agent under a session anchor: cn session exec -- AGENT")
        })
    }
}

/// Writes one JSON message, then zeroizes the buffer (it may hold a value).
pub fn send_message(mut w: &UnixStream, id: u64, request: &Request) -> Result<(), CnError> {
    let mut payload = serde_json::to_vec(&Envelope { id, body: request })
        .map_err(|e| CnError::internal(e.to_string()))?;
    let mut frame = Vec::with_capacity(payload.len() + 5);
    let result = write_frame(&mut frame, Kind::Message, &payload)
        .map_err(frame_error)
        .and_then(|()| w.write_all(&frame).map_err(|e| io_error(&e)));
    payload.zeroize();
    frame.zeroize();
    result
}

/// Writes one stream frame.
pub fn send_stream(mut w: &UnixStream, data: &[u8]) -> Result<(), CnError> {
    let mut frame = Vec::with_capacity(data.len() + 5);
    write_frame(&mut frame, Kind::Stream, data).map_err(frame_error)?;
    let result = w.write_all(&frame).map_err(|e| io_error(&e));
    frame.zeroize();
    result
}

/// Reads one frame, zeroizing a message payload after parsing it.
pub fn recv_frame(mut r: &UnixStream) -> Result<Incoming, CnError> {
    match read_frame(&mut r).map_err(frame_error)? {
        None => Err(
            CnError::new("daemon_unreachable", "cnd closed the connection").with_hint("cn doctor"),
        ),
        Some((Kind::Stream, data)) => Ok(Incoming::Stream(data)),
        Some((Kind::Message, mut payload)) => {
            let parsed = serde_json::from_slice::<Envelope<Response>>(&payload);
            payload.zeroize();
            parsed.map(|m| Incoming::Message(Box::new(m))).map_err(|e| {
                CnError::internal(format!("protocol error: unreadable message from cnd: {e}"))
            })
        }
    }
}

/// The error for an answer of the wrong type.
pub fn unexpected(wanted: &str, got: &Response) -> CnError {
    let tag = serde_json::to_value(got)
        .ok()
        .and_then(|v| v["type"].as_str().map(str::to_owned))
        .unwrap_or_default();
    CnError::internal(format!(
        "protocol error: expected {wanted} from cnd, got {tag}"
    ))
}

fn frame_error(e: FrameError) -> CnError {
    match e {
        FrameError::Io(e) => io_error(&e),
        other => CnError::internal(format!("protocol error: {other}")),
    }
}

fn io_error(e: &io::Error) -> CnError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            CnError::internal("cnd did not answer in time")
        }
        _ => CnError::new("daemon_unreachable", format!("connection to cnd: {e}"))
            .with_hint("cn doctor"),
    }
}

fn unreachable(path: &Path, e: &io::Error) -> CnError {
    let hint = if e.kind() == io::ErrorKind::PermissionDenied {
        "join the countersign-users group and log in again; see cn doctor"
    } else {
        "is countersign.socket running? see cn doctor"
    };
    CnError::new(
        "daemon_unreachable",
        format!("cannot connect to {}: {e}", path.display()),
    )
    .with_hint(hint)
}

/// Refuses a daemon that is not running as the `countersign` user. With an
/// overridden socket (debug builds only) the caller's own uid is accepted
/// too, so tests can run a fake daemon.
fn check_peer(stream: &UnixStream, overridden: bool) -> Result<(), CnError> {
    let cred = rustix::net::sockopt::socket_peercred(stream).map_err(|e| {
        CnError::new(
            "bad_peer",
            format!("cannot read the daemon's credentials: {e}"),
        )
    })?;
    let peer = cred.uid.as_raw();
    let expected = crate::sys::user_uid(DAEMON_USER);
    if expected == Some(peer) {
        return Ok(());
    }
    if overridden && peer == rustix::process::getuid().as_raw() {
        return Ok(());
    }
    let message = match expected {
        Some(uid) => format!(
            "the socket's server runs as uid {peer}, not as {DAEMON_USER} (uid {uid}); refusing to talk to it"
        ),
        None => format!(
            "there is no {DAEMON_USER} system user, so the server (uid {peer}) cannot be cnd"
        ),
    };
    Err(CnError::new("bad_peer", message).with_hint("cn doctor"))
}
