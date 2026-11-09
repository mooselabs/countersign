//! Small encodings: Crockford base32, base64, RFC 8785 canonical JSON, and
//! random bytes.

use base64::Engine as _;
use serde_json::Value;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encodes bytes as upper-case Crockford base32, without padding.
pub(crate) fn crockford(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[(acc >> bits) as usize & 31] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[(acc << (5 - bits)) as usize & 31] as char);
    }
    out
}

/// The 5-bit value of a Crockford character, reading `O` as `0` and `I`/`L`
/// as `1`, in either case.
pub(crate) fn crockford_value(c: u8) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        c => c,
    };
    CROCKFORD.iter().position(|&x| x == c).map(|p| p as u8)
}

/// A random id: `prefix` followed by `n` lower-case Crockford characters.
pub(crate) fn random_id(prefix: &str, n: usize) -> String {
    let bytes = random_vec(n.div_ceil(8) * 5);
    let mut s = crockford(&bytes).to_ascii_lowercase();
    s.truncate(n);
    format!("{prefix}{s}")
}

/// Fills `buf` from the OS random source. Panics if the kernel cannot give
/// randomness, because nothing safe can continue without it.
pub(crate) fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS random source failed");
}

/// `n` random bytes.
pub(crate) fn random_vec(n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    fill_random(&mut v);
    v
}

/// `N` random bytes.
pub(crate) fn random_array<const N: usize>() -> [u8; N] {
    let mut a = [0; N];
    fill_random(&mut a);
    a
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// A JSON value with no RFC 8785 form here: a non-integer number.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("canonical JSON supports integers only, found {0}")]
pub struct NotCanonical(pub String);

/// Serializes `v` as RFC 8785 (JCS) canonical JSON: object keys sorted by
/// UTF-16 code units, no whitespace, UTF-8.
///
/// Numbers must be integers (every number countersign writes is one); a
/// float is refused rather than risk a form another JCS encoder would not
/// produce. String escaping matches JCS: `"`, `\`, and control characters,
/// with `\b \t \n \f \r` short forms and lower-case `\u00xx` otherwise.
pub fn canonical_json(v: &Value) -> Result<Vec<u8>, NotCanonical> {
    let mut out = Vec::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<(), NotCanonical> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                out.extend_from_slice(n.to_string().as_bytes());
            } else {
                return Err(NotCanonical(n.to_string()));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_canonical(&m[k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn crockford_matches_known_values() {
        assert_eq!(crockford(&[]), "");
        assert_eq!(crockford(&[0xff]), "ZW");
        assert_eq!(crockford(&[0, 0, 0, 0, 0]), "00000000");
        assert_eq!(crockford(&[0xff; 5]), "ZZZZZZZZ");
        assert_eq!(crockford_value(b'o'), Some(0));
        assert_eq!(crockford_value(b'L'), Some(1));
        assert_eq!(crockford_value(b'U'), None);
    }

    #[test]
    fn random_ids_have_the_asked_shape() {
        let id = random_id("r_", 26);
        assert_eq!(id.len(), 28);
        assert!(id[2..].bytes().all(|c| crockford_value(c).is_some()));
        assert_ne!(random_id("r_", 26), id);
    }

    #[test]
    fn canonical_json_sorts_and_escapes() {
        let v = json!({"b": 1, "a": [true, null, "x\"\\\n\u{1}é"], "A": {"z": -2, "y": 0}});
        assert_eq!(
            String::from_utf8(canonical_json(&v).unwrap()).unwrap(),
            r#"{"A":{"y":0,"z":-2},"a":[true,null,"x\"\\\n\u0001é"],"b":1}"#
        );
        assert!(canonical_json(&json!({"f": 1.5})).is_err());
    }

    #[test]
    fn canonical_json_sorts_by_utf16_units() {
        // U+1F600 sorts after U+FF61 in UTF-8 byte order, before it in UTF-16.
        let v = json!({"\u{1F600}": 1, "\u{FF61}": 2});
        let s = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
        assert!(
            s.find('\u{1F600}').unwrap() < s.find('\u{FF61}').unwrap(),
            "{s}"
        );
    }
}
