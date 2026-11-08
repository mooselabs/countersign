//! Streaming redaction of secret values, as specified in `docs/design.md` §8.
//!
//! `cnd` uses this to serve `cn hide`, and `cn run` uses it to scrub a child
//! process's stdout and stderr. Matches are replaced with `[countersign:NAME]`.
//!
//! For each value the engine matches:
//!
//! - the raw bytes (a multi-line value is split into per-line patterns of at
//!   least [`MIN_LINE_LEN`] bytes, so no pattern contains a newline);
//! - base64, standard and URL-safe, padded and unpadded, plus the three
//!   alignment variants of the value embedded in a longer base64 string (this
//!   covers `Authorization: Basic` headers);
//! - percent-encoding with upper- and lower-case hex;
//! - JSON string escaping;
//! - hex, lower and upper case.
//!
//! Values shorter than [`DEFAULT_MIN_LEN`] bytes are never patterns: they
//! cause false positives and are guessable. [`Redactor::skipped`] names them.
//!
//! The engine works on a byte stream delivered in arbitrary chunks and gives
//! the same output as redacting the whole input in one pass. Output is held
//! back by a rule that depends only on the input's length and newlines, never
//! on whether a match is pending, so the timing of output says nothing about
//! the secrets: everything up to the last newline is released at once, and at
//! most `longest_pattern - 1` bytes of a partial last line are held until more
//! input arrives or the stream finishes.

use std::collections::BTreeMap;

use aho_corasick::{AhoCorasick, MatchKind};

/// Shortest value that becomes a pattern.
pub const DEFAULT_MIN_LEN: usize = 8;

/// Shortest line of a multi-line value that becomes a pattern.
pub const MIN_LINE_LEN: usize = 16;

/// A secret to redact.
#[derive(Debug, Clone, Copy)]
pub struct Secret<'a> {
    /// Name shown in the replacement marker.
    pub name: &'a str,
    /// The value to find.
    pub value: &'a [u8],
}

/// Errors building a [`Redactor`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The matcher could not be built.
    #[error("building matcher: {0}")]
    Build(#[from] aho_corasick::BuildError),
}

/// Builds a [`Redactor`].
#[derive(Debug, Clone)]
pub struct Builder {
    min_len: usize,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            min_len: DEFAULT_MIN_LEN,
        }
    }
}

impl Builder {
    /// Sets the shortest value that becomes a pattern (at least 1).
    pub fn min_len(mut self, min_len: usize) -> Self {
        self.min_len = min_len.max(1);
        self
    }

    /// Builds the redactor. When two secrets share a value or an encoding,
    /// the first one listed names the marker.
    pub fn build<'a>(
        self,
        secrets: impl IntoIterator<Item = Secret<'a>>,
    ) -> Result<Redactor, Error> {
        let mut names = Vec::new();
        let mut skipped = Vec::new();
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut owner = Vec::new();

        for secret in secrets {
            if secret.value.len() < self.min_len {
                skipped.push(secret.name.to_owned());
                continue;
            }
            let index = names.len();
            names.push(secret.name.to_owned());
            for form in forms(secret.value) {
                debug_assert!(
                    !form.contains(&b'\n'),
                    "the newline flush rule needs newline-free patterns"
                );
                if !form.is_empty() && !form.contains(&b'\n') && !patterns.contains(&form) {
                    patterns.push(form);
                    owner.push(index);
                }
            }
        }

        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)?;
        let markers = names
            .iter()
            .map(|n| format!("[countersign:{n}]").into_bytes())
            .collect();

        Ok(Redactor {
            matcher,
            owner,
            names,
            markers,
            skipped,
            max_len,
        })
    }
}

/// Every form of `value` to match.
fn forms(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    if value.contains(&b'\n') {
        for line in value.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.len() >= MIN_LINE_LEN {
                out.push(line.to_vec());
            }
        }
    } else {
        out.push(value.to_vec());
    }

    for alphabet in [STANDARD, URL_SAFE] {
        let unpadded = base64(value, alphabet);
        let mut padded = unpadded.clone();
        padded.resize(value.len().div_ceil(3) * 4, b'=');
        out.push(padded);
        out.push(unpadded);
        for prefix in 0..3 {
            out.push(base64_embedded(value, prefix, alphabet));
        }
    }

    out.push(percent(value, UPPER_HEX));
    out.push(percent(value, LOWER_HEX));
    out.push(json_escape(value));
    out.push(hex(value, LOWER_HEX));
    out.push(hex(value, UPPER_HEX));
    out
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Unpadded base64.
fn base64(input: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(alphabet[(n >> (18 - 6 * i) & 0x3f) as usize]);
        }
    }
    out
}

/// The base64 characters that encode `value` alone when it sits `prefix`
/// bytes (mod 3) into a longer base64 string. Characters that also depend on
/// the unknown bytes before or after the value are dropped.
fn base64_embedded(value: &[u8], prefix: usize, alphabet: &[u8; 64]) -> Vec<u8> {
    let mut padded = vec![0u8; prefix];
    padded.extend_from_slice(value);
    let encoded = base64(&padded, alphabet);
    // A prefix of 1 byte taints the first 2 characters; 2 bytes taint 3.
    let lead = [0, 2, 3][prefix];
    // A partial final group's last character depends on the next byte.
    let tail = usize::from(padded.len() % 3 != 0);
    encoded[lead..encoded.len() - tail].to_vec()
}

fn percent(input: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(&[
                b'%',
                digits[usize::from(b >> 4)],
                digits[usize::from(b & 0xf)],
            ]);
        }
    }
    out
}

fn hex(input: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    input
        .iter()
        .flat_map(|&b| [digits[usize::from(b >> 4)], digits[usize::from(b & 0xf)]])
        .collect()
}

fn json_escape(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1f => out.extend_from_slice(format!("\\u{b:04x}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

/// A compiled set of secrets to redact. Each stream holds its own buffer.
#[derive(Debug, Clone)]
pub struct Redactor {
    matcher: AhoCorasick,
    /// Pattern index to secret index.
    owner: Vec<usize>,
    names: Vec<String>,
    markers: Vec<Vec<u8>>,
    skipped: Vec<String>,
    max_len: usize,
}

/// How many times each secret was redacted. Only secrets with at least one hit
/// appear. Recorded in the audit log; never contains values.
pub type Hits = BTreeMap<String, u64>;

impl Redactor {
    /// Starts a new stream.
    pub fn stream(&self) -> Stream<'_> {
        Stream {
            redactor: self,
            carry: Vec::new(),
            hits: vec![0; self.names.len()],
        }
    }

    /// Redacts a complete input in one pass.
    pub fn redact(&self, input: &[u8]) -> (Vec<u8>, Hits) {
        let mut out = Vec::with_capacity(input.len());
        let mut stream = self.stream();
        stream.push(input, &mut out);
        let hits = stream.finish(&mut out);
        (out, hits)
    }

    /// Secrets left out because their value is shorter than the minimum.
    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }
}

/// One redaction stream over chunked input.
#[derive(Debug)]
pub struct Stream<'r> {
    redactor: &'r Redactor,
    carry: Vec<u8>,
    hits: Vec<u64>,
}

impl Stream<'_> {
    /// Feeds a chunk and appends whatever output is now safe to emit.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        self.carry.extend_from_slice(chunk);
        // Any match that starts before `by_length` ends inside the buffer, and
        // no pattern contains a newline, so both bounds can be decided now.
        let by_length = self
            .carry
            .len()
            .saturating_sub(self.redactor.max_len.saturating_sub(1));
        let by_newline = self
            .carry
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        let safe = by_length.max(by_newline);
        if safe == 0 {
            return;
        }
        let consumed = emit_until(self.redactor, &self.carry, safe, &mut self.hits, out);
        self.carry.drain(..consumed);
    }

    /// Emits the rest of the input and returns the hit counts.
    pub fn finish(mut self, out: &mut Vec<u8>) -> Hits {
        let len = self.carry.len();
        emit_until(self.redactor, &self.carry, len, &mut self.hits, out);
        self.redactor
            .names
            .iter()
            .zip(self.hits)
            .filter(|(_, n)| *n > 0)
            .map(|(name, n)| (name.clone(), n))
            .collect()
    }
}

/// Writes `buf[..safe]` to `out` with matches replaced, extending past `safe`
/// to finish a match that starts before it. Returns the bytes consumed.
fn emit_until(r: &Redactor, buf: &[u8], safe: usize, hits: &mut [u64], out: &mut Vec<u8>) -> usize {
    let mut pos = 0;
    for m in r.matcher.find_iter(buf) {
        if m.start() >= safe {
            break;
        }
        let secret = r.owner[m.pattern().as_usize()];
        out.extend_from_slice(&buf[pos..m.start()]);
        out.extend_from_slice(&r.markers[secret]);
        hits[secret] += 1;
        pos = m.end();
    }
    let end = pos.max(safe);
    out.extend_from_slice(&buf[pos..end]);
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor(secrets: &[(&str, &str)]) -> Redactor {
        Builder::default()
            .build(secrets.iter().map(|(n, v)| Secret {
                name: n,
                value: v.as_bytes(),
            }))
            .unwrap()
    }

    fn redact(r: &Redactor, input: &str) -> String {
        String::from_utf8(r.redact(input.as_bytes()).0).unwrap()
    }

    #[test]
    fn replaces_raw_value_and_counts_hits() {
        let r = redactor(&[("db-password", "hunter2hunter2")]);
        let (out, hits) = r.redact(b"pw=hunter2hunter2 again hunter2hunter2");
        assert_eq!(
            out,
            b"pw=[countersign:db-password] again [countersign:db-password]"
        );
        assert_eq!(hits.get("db-password"), Some(&2));
    }

    #[test]
    fn passes_through_without_secrets() {
        let r = Builder::default().build([]).unwrap();
        assert_eq!(redact(&r, "nothing to see"), "nothing to see");
    }

    #[test]
    fn matches_standalone_encodings() {
        let r = redactor(&[("token", "a+b/c?d=e\"f")]);
        // Padded base64 of the value is YStiL2M/ZD1lImY=, and the padding goes too.
        assert_eq!(
            redact(&r, "x YStiL2M/ZD1lImY= y"),
            "x [countersign:token] y"
        );
        assert_eq!(redact(&r, "YStiL2M_ZD1lImY"), "[countersign:token]");
        assert_eq!(
            redact(&r, "q=a%2Bb%2Fc%3Fd%3De%22f&"),
            "q=[countersign:token]&"
        );
        assert_eq!(
            redact(&r, "q=a%2bb%2fc%3fd%3de%22f&"),
            "q=[countersign:token]&"
        );
        assert_eq!(
            redact(&r, r#"{"t":"a+b/c?d=e\"f"}"#),
            r#"{"t":"[countersign:token]"}"#
        );
        assert_eq!(redact(&r, "612b622f633f643d652266"), "[countersign:token]");
        assert_eq!(redact(&r, "612B622F633F643D652266"), "[countersign:token]");
    }

    #[test]
    fn finds_value_inside_basic_auth_header() {
        let r = redactor(&[("pw", "correct-horse-battery")]);
        for user in ["a", "ab", "abc", "alice"] {
            let header = format!(
                "Authorization: Basic {}",
                reference_base64(format!("{user}:correct-horse-battery").as_bytes())
            );
            let out = redact(&r, &header);
            assert!(out.contains("[countersign:pw]"), "user {user:?}: {out}");
            // Only the encoded username and the final partial group with its
            // padding remain around the marker.
            let leftover = out.len() - "Authorization: Basic [countersign:pw]".len();
            assert!(
                leftover <= (user.len() + 1).div_ceil(3) * 4 + 4,
                "user {user:?}: {out}"
            );
        }
    }

    #[test]
    fn splits_multi_line_values_into_lines() {
        let pem = "-----BEGIN KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n-----END KEY-----\n";
        let r = redactor(&[("tls-key", pem)]);
        let out = redact(&r, &format!("dump:\n{pem}"));
        assert_eq!(out.matches("[countersign:tls-key]").count(), 4, "{out}");
        assert!(!out.contains("MIIEvQIBADANBgkq"));
    }

    #[test]
    fn longest_overlapping_secret_wins() {
        let r = redactor(&[("short", "abcdefgh"), ("long", "abcdefghij")]);
        assert_eq!(
            redact(&r, "abcdefghij abcdefgh"),
            "[countersign:long] [countersign:short]"
        );
    }

    #[test]
    fn skips_short_values() {
        let r = Builder::default()
            .build([Secret {
                name: "pin",
                value: b"1234",
            }])
            .unwrap();
        assert_eq!(r.skipped(), ["pin"]);
        assert_eq!(redact(&r, "pin 1234"), "pin 1234");
    }

    #[test]
    fn releases_complete_lines_immediately() {
        let r = redactor(&[("k", "a-fairly-long-secret-value-here")]);
        let mut out = Vec::new();
        let mut s = r.stream();
        s.push(b"line one\nline two\npartial", &mut out);
        assert_eq!(out, b"line one\nline two\n");
    }

    #[test]
    fn chunking_never_changes_output() {
        let r = redactor(&[
            ("a", "s3cr3t-value"),
            ("b", "another-secret-xyz"),
            ("c", "s3cr3t-value-long"),
        ]);
        let input = b"start s3cr3t-value mid\nanother-secret-xyz s3cr3t-value-long\nend czNjcjN0LXZhbHVl s3cr3t-valu";
        let (expected, expected_hits) = r.redact(input);
        assert_eq!(expected_hits.values().sum::<u64>(), 4);

        for split in 0..=input.len() {
            let mut out = Vec::new();
            let mut s = r.stream();
            s.push(&input[..split], &mut out);
            s.push(&input[split..], &mut out);
            assert_eq!(s.finish(&mut out), expected_hits, "split at {split}");
            assert_eq!(out, expected, "split at {split}");
        }

        for size in 1..8 {
            let mut out = Vec::new();
            let mut s = r.stream();
            for chunk in input.chunks(size) {
                s.push(chunk, &mut out);
            }
            assert_eq!(s.finish(&mut out), expected_hits, "chunk size {size}");
            assert_eq!(out, expected, "chunk size {size}");
        }
    }

    #[test]
    fn base64_matches_reference_vectors() {
        assert_eq!(base64(b"f", STANDARD), b"Zg");
        assert_eq!(base64(b"fo", STANDARD), b"Zm8");
        assert_eq!(base64(b"foo", STANDARD), b"Zm9v");
        assert_eq!(base64(b"foobar", STANDARD), b"Zm9vYmFy");
        assert_eq!(base64(&[0xfb, 0xff], URL_SAFE), b"-_8");
    }

    /// Padded standard base64, written independently of the code under test.
    fn reference_base64(input: &[u8]) -> String {
        let mut bits = String::new();
        for b in input {
            bits.push_str(&format!("{b:08b}"));
        }
        while bits.len() % 6 != 0 {
            bits.push('0');
        }
        let mut out: String = bits
            .as_bytes()
            .chunks(6)
            .map(|c| {
                STANDARD[usize::from_str_radix(std::str::from_utf8(c).unwrap(), 2).unwrap()] as char
            })
            .collect();
        while out.len() % 4 != 0 {
            out.push('=');
        }
        out
    }
}
