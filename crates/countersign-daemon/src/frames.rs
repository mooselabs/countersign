//! The frame codec of `countersign_proto` over tokio sockets.
//!
//! Message payloads may hold secret values (`add`, `set`, `import`, `run_ok`,
//! `reveal`), so every buffer that held one is zeroized after use.

use std::io;

use countersign_proto::{
    ErrorBody, ErrorCode, Kind, MAX_MESSAGE_LEN, MAX_STREAM_LEN, Request, Response,
};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

/// One frame from a client.
pub enum Frame {
    /// A parsed request, with its id.
    Request(u64, Box<Request>),
    /// A message that did not parse: its id (0 if unreadable) and the error
    /// to answer with.
    Bad(u64, ErrorBody),
    /// Raw bytes inside a `hide` stream.
    Stream(Vec<u8>),
}

/// The `type` values this version knows; a message with another type is
/// `unknown_request`, one with a known type but a bad shape `bad_request`.
const KNOWN: &[&str] = &[
    "hello",
    "session",
    "list",
    "request",
    "get_request",
    "approve",
    "deny",
    "grants",
    "revoke",
    "run",
    "run_finish",
    "hide",
    "hide_end",
    "reveal",
    "add",
    "set",
    "edit",
    "rm",
    "import",
    "audit_query",
    "audit_segments",
    "session_register",
    "unlock",
];

/// Reads one frame. `Ok(None)` on a clean end of stream before a frame;
/// an oversized or unknown frame is an `InvalidData` error (the connection
/// is closed, since its framing can no longer be trusted).
pub async fn read(r: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Frame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty frame"));
    }
    let kind = r.read_u8().await?;
    let max = match kind {
        0x01 => MAX_MESSAGE_LEN,
        0x02 => MAX_STREAM_LEN,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown frame kind {other:#04x}"),
            ));
        }
    };
    if len - 1 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame larger than its limit",
        ));
    }
    let mut payload = vec![0u8; len - 1];
    r.read_exact(&mut payload).await?;
    if kind == 0x02 {
        return Ok(Some(Frame::Stream(payload)));
    }
    let frame = parse(&payload);
    payload.zeroize();
    Ok(Some(frame))
}

fn parse(payload: &[u8]) -> Frame {
    match serde_json::from_slice::<countersign_proto::Envelope<Request>>(payload) {
        Ok(e) => Frame::Request(e.id, Box::new(e.body)),
        Err(e) => {
            let v: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
            let id = v["id"].as_u64().unwrap_or(0);
            let ty = v["type"].as_str().unwrap_or("");
            let body = if KNOWN.contains(&ty) {
                ErrorBody {
                    code: ErrorCode::BadRequest,
                    message: format!("malformed {ty} message: {}", strip_values(&e)),
                    detail: Value::Null,
                }
            } else {
                ErrorBody {
                    code: ErrorCode::UnknownRequest,
                    message: format!(
                        "unknown request type {:?}",
                        ty.chars().take(64).collect::<String>()
                    ),
                    detail: Value::Null,
                }
            };
            Frame::Bad(id, body)
        }
    }
}

/// A serde error message without the input it quotes (which may be a
/// value): only its category and position.
fn strip_values(e: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {} column {}",
        e.classify(),
        e.line(),
        e.column()
    )
}

/// Writes a JSON message frame and zeroizes the encoded bytes.
pub async fn write_message(
    w: &mut (impl AsyncWrite + Unpin),
    id: u64,
    body: &Response,
) -> io::Result<()> {
    let mut payload = serde_json::to_vec(&countersign_proto::Envelope { id, body })
        .map_err(|e| io::Error::other(e.to_string()))?;
    let result = write_frame(w, Kind::Message, &payload).await;
    payload.zeroize();
    result
}

/// Writes stream bytes, split into frames of at most 64 KiB.
pub async fn write_stream(w: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> io::Result<()> {
    for chunk in data.chunks(MAX_STREAM_LEN) {
        write_frame(w, Kind::Stream, chunk).await?;
    }
    Ok(())
}

async fn write_frame(
    w: &mut (impl AsyncWrite + Unpin),
    kind: Kind,
    payload: &[u8],
) -> io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    countersign_proto::write_frame(&mut frame, kind, payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let result = w.write_all(&frame).await;
    frame.zeroize();
    result?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(bytes: &[u8]) -> Frame {
        let mut frame = Vec::new();
        countersign_proto::write_frame(&mut frame, Kind::Message, bytes).unwrap();
        read(&mut frame.as_slice()).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn known_unknown_and_malformed_messages() {
        match roundtrip(br#"{"type":"list","id":4}"#).await {
            Frame::Request(4, r) => assert!(matches!(*r, Request::List { .. })),
            _ => panic!(),
        }
        match roundtrip(br#"{"type":"teleport","id":5}"#).await {
            Frame::Bad(5, e) => assert_eq!(e.code, ErrorCode::UnknownRequest),
            _ => panic!(),
        }
        // A malformed add must not echo its value back.
        match roundtrip(br#"{"type":"add","id":6,"value_b64":"c2VjcmV0LXZhbHVl"}"#).await {
            Frame::Bad(6, e) => {
                assert_eq!(e.code, ErrorCode::BadRequest);
                assert!(!e.message.contains("c2VjcmV0"), "{}", e.message);
            }
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn oversized_frames_are_refused() {
        let mut header = ((MAX_STREAM_LEN + 2) as u32).to_be_bytes().to_vec();
        header.push(0x02);
        let err = read(&mut header.as_slice()).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
