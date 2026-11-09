//! Wire protocol between `cn` and `cnd`, as specified in `docs/design.md` §4.
//!
//! Frames are `u32` big-endian length (of kind + payload), a `u8` kind, then
//! the payload. JSON messages carry a `type` tag and an `id` that the response
//! echoes. Unknown fields are ignored.
//!
//! - [`Request`] and [`Response`] are the messages; the response module's
//!   docs list which response answers which request.
//! - Times are RFC 3339 UTC strings with whole seconds ([`Timestamp`]);
//!   durations are integer seconds in fields ending `_seconds`.
//! - Secret values travel as standard base64 in [`ValueB64`], which never
//!   prints its contents and is zeroized on drop.
//! - [`CanonicalRequest`] is what approvers sign; [`jcs`] is its RFC 8785
//!   encoding, also used for audit record hashes.

mod canonical;
pub mod jcs;
mod request;
mod response;
mod time;

pub use canonical::{APPROVE_DOMAIN, Anchor, ApprovalKind, CanonicalRequest, Digest};
pub use request::{ImportItem, Mode, Request, SecretMeta, Use, ValueB64, ValueSource};
pub use response::{
    ApproverView, ChainEntry, Decision, Driven, GrantView, LastUse, RequestState, RequestView,
    Response, RunValue, ScrubValue, SecretView, SessionView,
};
pub use time::{BadTimestamp, Timestamp};

use std::fmt;
use std::io::{self, Read, Write};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Highest protocol version this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest JSON message payload.
pub const MAX_MESSAGE_LEN: usize = 1 << 20;

/// Largest stream-data payload (inside a `hide` stream).
pub const MAX_STREAM_LEN: usize = 64 << 10;

/// Frame kind byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A JSON message.
    Message = 0x01,
    /// Raw bytes inside a `hide` stream.
    Stream = 0x02,
}

/// Framing errors.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The underlying reader or writer failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A frame declared a length of zero.
    #[error("empty frame")]
    Empty,
    /// The kind byte is not known.
    #[error("unknown frame kind {0:#04x}")]
    UnknownKind(u8),
    /// The payload exceeds the limit for its kind.
    #[error("{kind:?} frame of {len} bytes exceeds the {max}-byte limit")]
    TooLarge {
        /// Frame kind.
        kind: Kind,
        /// Payload length.
        len: usize,
        /// Limit for the kind.
        max: usize,
    },
    /// A message frame did not hold valid JSON for the expected type.
    #[error("bad message: {0}")]
    Json(#[from] serde_json::Error),
}

fn limit(kind: Kind) -> usize {
    match kind {
        Kind::Message => MAX_MESSAGE_LEN,
        Kind::Stream => MAX_STREAM_LEN,
    }
}

/// Writes one frame.
pub fn write_frame(w: &mut impl Write, kind: Kind, payload: &[u8]) -> Result<(), FrameError> {
    let max = limit(kind);
    if payload.len() > max {
        return Err(FrameError::TooLarge {
            kind,
            len: payload.len(),
            max,
        });
    }
    let len = u32::try_from(payload.len() + 1).expect("bounded by the frame limit");
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&[kind as u8])?;
    w.write_all(payload)?;
    Ok(())
}

/// Reads one frame. Returns `None` on a clean end of stream before a frame.
pub fn read_frame(r: &mut impl Read) -> Result<Option<(Kind, Vec<u8>)>, FrameError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(FrameError::Empty);
    }
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind)?;
    let kind = match kind[0] {
        0x01 => Kind::Message,
        0x02 => Kind::Stream,
        other => return Err(FrameError::UnknownKind(other)),
    };
    let max = limit(kind);
    if len - 1 > max {
        return Err(FrameError::TooLarge {
            kind,
            len: len - 1,
            max,
        });
    }
    let mut payload = vec![0u8; len - 1];
    r.read_exact(&mut payload)?;
    Ok(Some((kind, payload)))
}

/// Writes a JSON message frame.
pub fn write_message<T: Serialize>(
    w: &mut impl Write,
    msg: &Envelope<T>,
) -> Result<(), FrameError> {
    write_frame(w, Kind::Message, &serde_json::to_vec(msg)?)
}

/// A message with its request id. The body's `type` tag sits beside `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Request id, echoed by the response.
    pub id: u64,
    /// The message.
    #[serde(flatten)]
    pub body: T,
}

/// Error codes from `cnd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No common protocol version.
    UnsupportedVersion,
    /// Peer uid not allowed on the socket.
    ForbiddenPeer,
    /// No anchor found for the caller.
    NoSession,
    /// Anchor exited during the request.
    SessionDead,
    /// Name not in the store.
    UnknownSecret,
    /// No active grant covering the name and mode.
    GrantRequired,
    /// The approval code expired.
    RequestExpired,
    /// The approval code is not known.
    RequestNotFound,
    /// An assertion failed verification.
    ApprovalInvalid,
    /// The store is not unlocked.
    StoreSealed,
    /// A rate limit was exceeded.
    RateLimited,
    /// TTL, name count or frame size above its limit.
    LimitExceeded,
    /// No approver in the configured chain can run (e.g. no graphical session).
    ApproverUnavailable,
    /// The request type is not known.
    UnknownRequest,
    /// The arguments are invalid: a bad name, a value too large, a secret
    /// that already exists, a `revoke` without exactly one selector.
    BadRequest,
    /// Server fault; details only in the daemon log.
    Internal,
    /// A code this version does not know (sent by a newer `cnd`). Never sent.
    #[serde(other)]
    Unknown,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned));
        f.write_str(s.as_deref().unwrap_or("internal"))
    }
}

/// An error response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// Human-readable message.
    pub message: String,
    /// Extra structured detail.
    #[serde(default)]
    pub detail: serde_json::Value,
}

/// The default environment variable for a secret: its name in upper snake
/// case, `.` and `-` becoming `_` (`clickhouse-prod` maps to `CLICKHOUSE_PROD`).
pub fn default_env(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '.' | '-' => '_',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}

/// A human-facing request code: 6 Crockford base32 characters shown as
/// `K7M-Q2X`. A handle, not a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestCode([u8; 6]);

pub(crate) const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A string that is not a valid request code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a request code (expected 6 characters like K7M-Q2X)")]
pub struct BadCode;

impl RequestCode {
    /// Builds a code from 30 random bits (the high bits are ignored).
    pub fn from_bits(bits: u32) -> Self {
        let mut out = [0u8; 6];
        for (i, c) in out.iter_mut().enumerate() {
            *c = CROCKFORD[(bits >> (25 - 5 * i) & 0x1f) as usize];
        }
        Self(out)
    }
}

impl fmt::Display for RequestCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = std::str::from_utf8(&self.0).expect("ASCII");
        write!(f, "{}-{}", &s[..3], &s[3..])
    }
}

impl FromStr for RequestCode {
    type Err = BadCode;

    /// Accepts any case, with or without the hyphen. Per Crockford, `O` reads
    /// as `0` and `I`/`L` as `1`.
    fn from_str(s: &str) -> Result<Self, BadCode> {
        let mut out = [0u8; 6];
        let mut n = 0;
        for ch in s.bytes().filter(|&b| b != b'-') {
            let ch = match ch.to_ascii_uppercase() {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                other => other,
            };
            if n == 6 || !CROCKFORD.contains(&ch) {
                return Err(BadCode);
            }
            out[n] = ch;
            n += 1;
        }
        if n == 6 { Ok(Self(out)) } else { Err(BadCode) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, Kind::Message, b"{}").unwrap();
        write_frame(&mut buf, Kind::Stream, b"raw").unwrap();
        let mut r = buf.as_slice();
        assert_eq!(
            read_frame(&mut r).unwrap(),
            Some((Kind::Message, b"{}".to_vec()))
        );
        assert_eq!(
            read_frame(&mut r).unwrap(),
            Some((Kind::Stream, b"raw".to_vec()))
        );
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    #[test]
    fn rejects_oversized_and_unknown_frames() {
        let big = vec![0u8; MAX_STREAM_LEN + 1];
        assert!(matches!(
            write_frame(&mut Vec::new(), Kind::Stream, &big),
            Err(FrameError::TooLarge { .. })
        ));

        let mut header = ((MAX_MESSAGE_LEN + 2) as u32).to_be_bytes().to_vec();
        header.push(0x01);
        assert!(matches!(
            read_frame(&mut header.as_slice()),
            Err(FrameError::TooLarge { .. })
        ));

        let bad = [0, 0, 0, 1, 0x7f];
        assert!(matches!(
            read_frame(&mut bad.as_slice()),
            Err(FrameError::UnknownKind(0x7f))
        ));
    }

    #[test]
    fn hello_matches_the_design_example() {
        let json = r#"{"type":"hello","id":1,"protocols":[1],"client":"cn/0.1.0",
            "labels":{"CLAUDE_CODE_SESSION_ID":"9f3c"},"cwd":"/home/patrick/projects/x","future_field":true}"#;
        let msg: Envelope<Request> = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, 1);
        assert!(matches!(msg.body, Request::Hello { ref protocols, .. } if protocols == &[1]));
    }

    #[test]
    fn requests_round_trip_with_snake_case_tags() {
        let msg = Envelope {
            id: 7,
            body: Request::Request {
                names: vec!["clickhouse-prod".into()],
                mode: Mode::Use,
                ttl_seconds: Some(3600),
                reason: "drift report".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            json.contains(r#""type":"request""#) && json.contains(r#""mode":"use""#),
            "{json}"
        );
        assert_eq!(
            serde_json::from_str::<Envelope<Request>>(&json).unwrap(),
            msg
        );
        assert_eq!(ErrorCode::GrantRequired.to_string(), "grant_required");
    }

    #[test]
    fn request_codes_parse_leniently() {
        let code = RequestCode::from_bits(0x3fff_ffff);
        assert_eq!(code.to_string(), "ZZZ-ZZZ");
        let code: RequestCode = "k7m-q2x".parse().unwrap();
        assert_eq!(code.to_string(), "K7M-Q2X");
        assert_eq!("K7MQ2X".parse::<RequestCode>().unwrap(), code);
        assert_eq!(
            "ol1-234".parse::<RequestCode>().unwrap().to_string(),
            "011-234"
        );
        assert_eq!("K7M-Q2".parse::<RequestCode>(), Err(BadCode));
        assert_eq!("K7M-Q2XX".parse::<RequestCode>(), Err(BadCode));
        assert_eq!("K7M-Q2U".parse::<RequestCode>(), Err(BadCode));
    }
}
