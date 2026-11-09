//! The audit log (audit.md): an append-only, hash-chained JSONL log in
//! numbered segments, with signed checkpoints.
//!
//! ```text
//! hash_n = SHA-256("countersign/audit/v1\0" || JCS(record_n without "hash"))
//! record_n.prev = hash_{n-1}       (64 zeros for seq 1)
//! ```
//!
//! Each line on disk is the JCS form of the record with `hash` included.
//! [`AuditLog`] writes it, [`verify_segments`] checks it, and
//! [`AuditLog::query`] reads it back with filters.

mod coalesce;
mod event;
mod query;
mod verify;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub use coalesce::{ListCoalescer, ListRecord};
pub use event::{ChainLink, Event, SessionRef, StoreChange};
pub use query::Query;
pub use verify::{
    BreakKind, CheckpointInfo, VerifyError, VerifyOptions, VerifyReport, parse_pubkey,
    verify_segments, verify_segments_with,
};

use countersign_proto::jcs::{self, JcsError};

use crate::encoding::b64;
use crate::time::{Clock, format_rfc3339_micros};
use event::Internal;

/// Record schema version.
pub const SCHEMA_VERSION: u64 = 1;
/// `prev` of the first record.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Name of the checkpoint public key file in the audit directory.
pub const PUBKEY_FILE: &str = "checkpoint.pub";
/// Default segment size limit.
pub const MAX_SEGMENT_BYTES: u64 = 64 << 20;

const HASH_DOMAIN: &[u8] = b"countersign/audit/v1\0";
const CHECKPOINT_DOMAIN: &str = "countersign/audit-checkpoint/v1";

/// An audit operation that failed. A failed append means the action it
/// records must not happen.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The existing log is not readable as a chain.
    #[error("audit log is damaged: {0}")]
    Corrupt(String),
    /// A record could not be encoded.
    #[error("audit record: {0}")]
    Encode(String),
    /// `checkpoint.pub` belongs to another key.
    #[error("{0} holds a different checkpoint key; this audit log belongs to another store")]
    KeyMismatch(PathBuf),
    /// A failed write left bytes that could not be cut off again. Every
    /// later write fails until the log is reopened (a `cnd` restart), which
    /// cuts the unfinished line.
    #[error("the audit log refuses writes after a failed write it could not undo: {0}")]
    Broken(String),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> AuditError + '_ {
    move |source| AuditError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Settings for [`AuditLog::open`].
#[derive(Debug, Clone)]
pub struct Options {
    /// Machine id, signed into checkpoints.
    pub host: String,
    /// Boot id; records carry its first 8 hex characters.
    pub boot_id: String,
    /// Checkpoint after this many records.
    pub checkpoint_every_records: u64,
    /// Checkpoint at least this often when records were written.
    pub checkpoint_interval: Duration,
    /// Close a segment at this size.
    pub max_segment_bytes: u64,
}

impl Options {
    /// Defaults from audit.md for this host and boot.
    pub fn new(host: impl Into<String>, boot_id: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            boot_id: boot_id.into(),
            checkpoint_every_records: 1000,
            checkpoint_interval: Duration::from_secs(3600),
            max_segment_bytes: MAX_SEGMENT_BYTES,
        }
    }
}

/// The position of a written record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// Its sequence number.
    pub seq: u64,
    /// Its hash, hex.
    pub hash: String,
}

/// The writer. One per audit directory; `cnd` owns it.
pub struct AuditLog {
    dir: PathBuf,
    opts: Options,
    clock: Arc<dyn Clock>,
    signer: Option<SigningKey>,
    file: File,
    segment: u32,
    segment_bytes: u64,
    segment_month: Option<String>,
    seq: u64,
    hash: String,
    since_checkpoint: u64,
    last_checkpoint_at: SystemTime,
    truncated: u64,
    broken: Option<String>,
    checkpoint_error: Option<AuditError>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("dir", &self.dir)
            .field("segment", &self.segment)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

fn segment_name(n: u32) -> String {
    format!("{n:06}.jsonl")
}

/// Segment numbers present in `dir`, ascending.
pub(crate) fn list_segments(dir: &Path) -> Result<Vec<u32>, AuditError> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir).map_err(io_err(dir))? {
        let name = e.map_err(io_err(dir))?.file_name();
        let name = name.to_string_lossy();
        let num = name
            .strip_suffix(".jsonl")
            .filter(|n| n.len() == 6)
            .and_then(|n| n.parse().ok());
        if let Some(n) = num {
            v.push(n);
        }
    }
    v.sort_unstable();
    Ok(v)
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err(path))
}

impl AuditLog {
    /// Opens the log in `dir` (created 0700 if missing), continuing the chain
    /// from the last record. An unterminated last line, left by a crash
    /// during a write, is cut off; [`AuditLog::truncated_bytes`] says how
    /// much. Any other damage is an error.
    pub fn open(dir: &Path, opts: Options, clock: Arc<dyn Clock>) -> Result<Self, AuditError> {
        {
            use std::os::unix::fs::DirBuilderExt;
            if !dir.exists() {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .recursive(true)
                    .create(dir)
                    .map_err(io_err(dir))?;
            }
        }
        let now = clock.now();
        let mut segments = list_segments(dir)?;
        let mut truncated = 0;
        let (mut seq, mut hash) = (0, GENESIS_PREV.to_owned());
        let (mut since_checkpoint, mut segment_month) = (0, None);
        let (segment, path) = loop {
            let segment = segments.last().copied().unwrap_or(1);
            let path = dir.join(segment_name(segment));
            if !path.exists() {
                break (segment, path);
            }
            let mut bytes = fs::read(&path).map_err(io_err(&path))?;
            let keep = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
            if keep < bytes.len() {
                truncated += (bytes.len() - keep) as u64;
                bytes.truncate(keep);
                let f = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(io_err(&path))?;
                f.set_len(keep as u64).map_err(io_err(&path))?;
                f.sync_all().map_err(io_err(&path))?;
            }
            if bytes.is_empty() && segments.len() > 1 {
                // A crash during rotation: the new segment never got its
                // `segment.open`. It holds nothing, so it goes, and the next
                // append rotates again.
                fs::remove_file(&path).map_err(io_err(&path))?;
                File::open(dir)
                    .and_then(|d| d.sync_all())
                    .map_err(io_err(dir))?;
                segments.pop();
                continue;
            }
            for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                let r: Value = serde_json::from_slice(line)
                    .map_err(|e| AuditError::Corrupt(format!("{}: {e}", path.display())))?;
                let field = |k: &str| {
                    r.get(k).cloned().ok_or_else(|| {
                        AuditError::Corrupt(format!("{}: record without {k}", path.display()))
                    })
                };
                seq = field("seq")?
                    .as_u64()
                    .ok_or_else(|| AuditError::Corrupt("seq is not a number".into()))?;
                hash = field("hash")?.as_str().unwrap_or_default().to_owned();
                let ts = field("ts")?.as_str().unwrap_or_default().to_owned();
                segment_month.get_or_insert_with(|| ts.get(..7).unwrap_or("").to_owned());
                if r.get("event").and_then(Value::as_str) == Some("checkpoint") {
                    since_checkpoint = 0;
                } else {
                    since_checkpoint += 1;
                }
            }
            break (segment, path);
        };
        let file = open_append(&path)?;
        let segment_bytes = file.metadata().map_err(io_err(&path))?.len();
        Ok(Self {
            dir: dir.to_owned(),
            opts,
            clock,
            signer: None,
            file,
            segment,
            segment_bytes,
            segment_month,
            seq,
            hash,
            since_checkpoint,
            last_checkpoint_at: now,
            truncated,
            broken: None,
            checkpoint_error: None,
        })
    }

    /// Bytes of an unterminated last line removed by [`AuditLog::open`].
    pub fn truncated_bytes(&self) -> u64 {
        self.truncated
    }

    /// The audit directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The last record's sequence number (0 when empty) and hash.
    pub fn head(&self) -> (u64, &str) {
        (self.seq, &self.hash)
    }

    /// Sets the checkpoint signing key from its seed
    /// ([`crate::store::Store::checkpoint_seed`]) and writes
    /// `checkpoint.pub` if it is missing. Refuses if `checkpoint.pub` holds
    /// another key. Until this is called, checkpoints are deferred.
    pub fn set_signer(&mut self, seed: &[u8; 32]) -> Result<String, AuditError> {
        let key = SigningKey::from_bytes(seed);
        let public = format!("ed25519:{}", b64(key.verifying_key().as_bytes()));
        let path = self.dir.join(PUBKEY_FILE);
        match fs::read_to_string(&path) {
            Ok(existing) if existing.trim() == public => {}
            Ok(_) => return Err(AuditError::KeyMismatch(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(&path)
                    .map_err(io_err(&path))?;
                f.write_all(format!("{public}\n").as_bytes())
                    .and_then(|()| f.sync_all())
                    .map_err(io_err(&path))?;
            }
            Err(e) => return Err(io_err(&path)(e)),
        }
        self.signer = Some(key);
        Ok(public)
    }

    /// Appends one record and `fdatasync`s it. Writes a checkpoint after it
    /// when `checkpoint_every_records` is reached, and rotates the segment
    /// first when it is full or a new month began.
    ///
    /// On an error nothing of the record stays in the log: a partly written
    /// line is cut off again. If that cut fails, the log refuses every later
    /// write ([`AuditError::Broken`]).
    pub fn append(
        &mut self,
        session: Option<&SessionRef>,
        event: &Event,
    ) -> Result<Written, AuditError> {
        let mut w = self.append_all(session, std::slice::from_ref(event))?;
        Ok(w.pop().expect("one record"))
    }

    /// Appends several records of one session with one write and one
    /// `fdatasync`: all of them are in the log, or none (a batch of `store.*`
    /// records for one approved change).
    pub fn append_all(
        &mut self,
        session: Option<&SessionRef>,
        events: &[Event],
    ) -> Result<Vec<Written>, AuditError> {
        if let Some(why) = &self.broken {
            return Err(AuditError::Broken(why.clone()));
        }
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let now = self.clock.now();
        self.rotate_if_needed(now)?;
        let ts = format_rfc3339_micros(now);
        let (mut seq, mut hash) = (self.seq, self.hash.clone());
        let mut bytes = Vec::new();
        let mut written = Vec::with_capacity(events.len());
        for event in events {
            let (line, h) = self.encode(seq + 1, &hash, &ts, session, event)?;
            bytes.extend_from_slice(&line);
            seq += 1;
            hash = h;
            written.push(Written {
                seq,
                hash: hash.clone(),
            });
        }
        self.write_lines(&bytes, &ts, seq, hash)?;
        self.since_checkpoint += events.len() as u64;
        if self.since_checkpoint >= self.opts.checkpoint_every_records {
            // The records are written; a failed checkpoint must not make the
            // caller think they are not. It is retried on the next append
            // and by the timer, and kept for the daemon log.
            if let Err(e) = self.checkpoint() {
                self.checkpoint_error = Some(e);
            }
        }
        Ok(written)
    }

    /// A checkpoint that failed after [`AuditLog::append`] wrote its record,
    /// for the caller to log.
    pub fn take_checkpoint_error(&mut self) -> Option<AuditError> {
        self.checkpoint_error.take()
    }

    /// Changes when checkpoints are written (config reload).
    pub fn set_checkpoint_policy(&mut self, every_records: u64, interval: Duration) {
        self.opts.checkpoint_every_records = every_records;
        self.opts.checkpoint_interval = interval;
    }

    /// Writes a checkpoint if the interval has passed since the last one and
    /// records were written since. `cnd` calls this from a timer.
    pub fn maybe_checkpoint(&mut self) -> Result<Option<Written>, AuditError> {
        let due = self
            .clock
            .now()
            .duration_since(self.last_checkpoint_at)
            .unwrap_or_default()
            >= self.opts.checkpoint_interval;
        let owed = self.since_checkpoint >= self.opts.checkpoint_every_records;
        if (due || owed) && self.since_checkpoint > 0 {
            self.checkpoint()
        } else {
            Ok(None)
        }
    }

    /// Writes a checkpoint now (for `daemon.stop`), unless there is no
    /// signing key yet or nothing to cover.
    pub fn checkpoint(&mut self) -> Result<Option<Written>, AuditError> {
        if let Some(why) = &self.broken {
            return Err(AuditError::Broken(why.clone()));
        }
        let Some(key) = &self.signer else {
            return Ok(None);
        };
        if self.seq == 0 {
            return Ok(None);
        }
        let now = self.clock.now();
        let ts = format_rfc3339_micros(now);
        let payload = checkpoint_payload(&self.opts.host, self.seq, &self.hash, &ts);
        let sig = key.sign(&payload);
        let body = Internal::Checkpoint {
            upto_seq: self.seq,
            upto_hash: self.hash.clone(),
            host: self.opts.host.clone(),
            sig: format!("ed25519:{}", b64(&sig.to_bytes())),
        };
        let w = self.write_record_at(&ts, None, &body)?;
        self.since_checkpoint = 0;
        self.last_checkpoint_at = now;
        Ok(Some(w))
    }

    fn rotate_if_needed(&mut self, now: SystemTime) -> Result<(), AuditError> {
        if self.segment_bytes == 0 {
            // An empty segment after records: a rotation whose
            // `segment.open` failed. Write it now.
            if self.seq > 0 {
                self.write_segment_open(now)?;
            }
            return Ok(());
        }
        let month = format_rfc3339_micros(now)[..7].to_owned();
        let full = self.segment_bytes >= self.opts.max_segment_bytes;
        let new_month = self.segment_month.as_deref().is_some_and(|m| m != month);
        if !full && !new_month {
            return Ok(());
        }
        if self.since_checkpoint > 0 {
            self.checkpoint()?;
        }
        let next = self.segment + 1;
        let path = self.dir.join(segment_name(next));
        self.file = open_append(&path)?;
        File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(io_err(&self.dir))?;
        self.segment = next;
        self.segment_bytes = 0;
        self.segment_month = None;
        self.write_segment_open(now)
    }

    fn write_segment_open(&mut self, now: SystemTime) -> Result<(), AuditError> {
        let body = Internal::SegmentOpen {
            segment: segment_name(self.segment),
            prev_segment_last_hash: self.hash.clone(),
        };
        self.write_record_at(&format_rfc3339_micros(now), None, &body)?;
        Ok(())
    }

    fn write_record_at(
        &mut self,
        ts: &str,
        session: Option<&SessionRef>,
        body: &impl Serialize,
    ) -> Result<Written, AuditError> {
        if let Some(why) = &self.broken {
            return Err(AuditError::Broken(why.clone()));
        }
        let seq = self.seq + 1;
        let (line, hash) = self.encode(seq, &self.hash, ts, session, body)?;
        self.write_lines(&line, ts, seq, hash.clone())?;
        Ok(Written { seq, hash })
    }

    /// The JCS line (newline included) and hash of record `seq`.
    fn encode(
        &self,
        seq: u64,
        prev: &str,
        ts: &str,
        session: Option<&SessionRef>,
        body: &impl Serialize,
    ) -> Result<(Vec<u8>, String), AuditError> {
        let Value::Object(mut rec) =
            serde_json::to_value(body).map_err(|e| AuditError::Encode(e.to_string()))?
        else {
            return Err(AuditError::Encode("event is not an object".into()));
        };
        let boot: String = self
            .opts
            .boot_id
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let common = [
            ("v", Value::from(SCHEMA_VERSION)),
            ("seq", Value::from(seq)),
            ("ts", Value::from(ts)),
            ("boot", Value::from(boot)),
            (
                "session",
                serde_json::to_value(session).map_err(|e| AuditError::Encode(e.to_string()))?,
            ),
            ("prev", Value::from(prev)),
        ];
        for (k, v) in common {
            if rec.insert(k.to_owned(), v).is_some() {
                return Err(AuditError::Encode(format!("event field {k} is reserved")));
            }
        }
        let hash = record_hash(&rec).map_err(|e| AuditError::Encode(e.to_string()))?;
        rec.insert("hash".into(), Value::from(hash.clone()));
        let mut line = jcs::value_to_vec(&Value::Object(rec))
            .map_err(|e| AuditError::Encode(e.to_string()))?;
        line.push(b'\n');
        Ok((line, hash))
    }

    /// Writes whole lines and `fdatasync`s them; `seq` and `hash` are those
    /// of the last line. On any error the file is cut back to where it was,
    /// so a later append never follows a fragment.
    fn write_lines(
        &mut self,
        bytes: &[u8],
        ts: &str,
        seq: u64,
        hash: String,
    ) -> Result<(), AuditError> {
        let path = self.dir.join(segment_name(self.segment));
        let res = write_failpoint(&mut self.file, bytes).and_then(|()| self.file.sync_data());
        if let Err(e) = res {
            let undo = self
                .file
                .set_len(self.segment_bytes)
                .and_then(|()| self.file.sync_data());
            if let Err(u) = undo {
                self.broken = Some(format!(
                    "{}: {e}; cutting off the partial record failed: {u}",
                    path.display()
                ));
            }
            return Err(io_err(&path)(e));
        }
        self.segment_bytes += bytes.len() as u64;
        self.segment_month
            .get_or_insert_with(|| ts.get(..7).unwrap_or("").to_owned());
        self.seq = seq;
        self.hash = hash;
        Ok(())
    }

    /// A reader for the records written so far. It needs no access to the
    /// writer, so it can run without the lock that guards it.
    pub fn reader(&self) -> AuditReader {
        AuditReader {
            dir: self.dir.clone(),
            upto_seq: self.seq,
        }
    }

    /// Raw lines of every record with `seq >= from_seq`, in order. The bytes
    /// are what [`verify_segments`] reads.
    pub fn segments_from(&self, from_seq: u64) -> Result<Vec<u8>, AuditError> {
        Ok(self.reader().segments_from(from_seq, usize::MAX)?.0)
    }
}

/// Writes `bytes`. Tests make it fail part way through.
fn write_failpoint(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(n) = FAIL_WRITE_AFTER.with(std::cell::Cell::take) {
        file.write_all(&bytes[..n.min(bytes.len())])?;
        return Err(std::io::Error::other("injected write failure"));
    }
    file.write_all(bytes)
}

#[cfg(test)]
thread_local! {
    /// The next write writes this many bytes, then fails.
    pub(crate) static FAIL_WRITE_AFTER: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Reads the records an [`AuditLog`] had written when [`AuditLog::reader`]
/// was called. Records written later, and an unfinished last line, are
/// left out.
#[derive(Debug, Clone)]
pub struct AuditReader {
    dir: PathBuf,
    upto_seq: u64,
}

/// Lines of one segment file, read in order.
fn segment_lines(path: &Path, start: u64) -> Result<Vec<u8>, AuditError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path).map_err(io_err(path))?;
    f.seek(SeekFrom::Start(start)).map_err(io_err(path))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(io_err(path))?;
    // A line still being written is not a record yet.
    let keep = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
    bytes.truncate(keep);
    Ok(bytes)
}

fn line_seq(line: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Value>(line)
        .ok()
        .and_then(|v| v.get("seq").and_then(Value::as_u64))
}

/// The offset of a line start at or before the first record with
/// `seq >= from_seq` in a segment, found by bisecting on byte offsets.
fn seek_seq(path: &Path, from_seq: u64) -> Result<u64, AuditError> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    const LINEAR: u64 = 64 << 10;
    let f = File::open(path).map_err(io_err(path))?;
    let len = f.metadata().map_err(io_err(path))?.len();
    let mut r = BufReader::new(f);
    let (mut lo, mut hi) = (0u64, len);
    let mut buf = Vec::new();
    while hi - lo > LINEAR {
        let mid = lo + (hi - lo) / 2;
        r.seek(SeekFrom::Start(mid)).map_err(io_err(path))?;
        buf.clear();
        // Skip to the next line start.
        let skipped = r.read_until(b'\n', &mut buf).map_err(io_err(path))? as u64;
        let start = mid + skipped;
        buf.clear();
        r.read_until(b'\n', &mut buf).map_err(io_err(path))?;
        match line_seq(&buf) {
            Some(seq) if seq < from_seq && start < hi => lo = start,
            _ => hi = mid,
        }
    }
    Ok(lo)
}

impl AuditReader {
    /// The last `seq` this reader covers.
    pub fn upto_seq(&self) -> u64 {
        self.upto_seq
    }

    /// The audit directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Raw lines of the records with `seq >= from_seq`, in order, up to
    /// about `max_bytes` (at least one line), and the `seq` to ask for next
    /// when more remain. Starts in the segment that holds `from_seq`
    /// instead of reading the log from the beginning. A line that does not
    /// parse is passed through, so the verifier reports it.
    pub fn segments_from(
        &self,
        from_seq: u64,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Option<u64>), AuditError> {
        let segments = list_segments(&self.dir)?;
        // The last segment whose first record is at or before from_seq.
        let mut first = 0;
        for (i, n) in segments.iter().enumerate() {
            let path = self.dir.join(segment_name(*n));
            let head = segment_first_seq(&path)?;
            if head.is_some_and(|s| s <= from_seq) {
                first = i;
            } else if head.is_some() {
                break;
            }
        }
        let mut out = Vec::new();
        for n in &segments[first.min(segments.len())..] {
            let path = self.dir.join(segment_name(*n));
            let start = if out.is_empty() {
                seek_seq(&path, from_seq)?
            } else {
                0
            };
            let bytes = segment_lines(&path, start)?;
            for line in bytes.split_inclusive(|&b| b == b'\n') {
                let seq = line_seq(line);
                if seq.is_some_and(|s| s > self.upto_seq) {
                    return Ok((out, None));
                }
                if seq.is_some_and(|s| s < from_seq) {
                    continue;
                }
                if !out.is_empty() && out.len() + line.len() > max_bytes {
                    if let Some(s) = seq {
                        return Ok((out, Some(s)));
                    }
                }
                out.extend_from_slice(line);
            }
        }
        Ok((out, None))
    }
}

/// The `seq` of a segment's first record.
fn segment_first_seq(path: &Path) -> Result<Option<u64>, AuditError> {
    use std::io::{BufRead, BufReader};
    let f = File::open(path).map_err(io_err(path))?;
    let mut line = Vec::new();
    BufReader::new(f)
        .read_until(b'\n', &mut line)
        .map_err(io_err(path))?;
    Ok(line_seq(&line))
}

/// `SHA-256("countersign/audit/v1\0" || JCS(record without "hash"))`, hex.
pub(crate) fn record_hash(rec: &Map<String, Value>) -> Result<String, JcsError> {
    let mut rec = rec.clone();
    rec.remove("hash");
    let mut h = Sha256::new();
    h.update(HASH_DOMAIN);
    h.update(jcs::value_to_vec(&Value::Object(rec))?);
    Ok(hex(&h.finalize()))
}

pub(crate) fn checkpoint_payload(host: &str, upto_seq: u64, upto_hash: &str, ts: &str) -> Vec<u8> {
    let v = serde_json::json!({
        "domain": CHECKPOINT_DOMAIN,
        "host": host,
        "upto_seq": upto_seq,
        "upto_hash": upto_hash,
        "ts": ts,
    });
    jcs::value_to_vec(&v).expect("small integers and strings only")
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
