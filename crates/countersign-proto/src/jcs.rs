//! RFC 8785 JSON Canonicalization Scheme (JCS), for the values countersign
//! hashes: the canonical request (design.md §6) and audit records (audit.md).
//!
//! Supported: `null`, booleans, strings, arrays, objects, and integers with an
//! absolute value up to 2^53 - 1. Anything else is refused rather than
//! encoded in a way another JCS implementation might not reproduce:
//! non-integer numbers need the ECMAScript number formatting the RFC
//! prescribes, and larger integers lose precision in I-JSON.
//!
//! Output rules (RFC 8785 §3.2): no whitespace; object members sorted by the
//! UTF-16 code units of their names; strings escape only `"`, `\` and
//! U+0000..U+001F, using `\b \t \n \f \r` where they exist and lower-case
//! `\u00xx` otherwise; everything else is written as UTF-8.

use serde::Serialize;
use serde_json::Value;

/// Largest integer magnitude JCS can carry exactly (2^53 - 1).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A value JCS cannot encode here.
#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    /// A number that is not an integer.
    #[error("non-integer number {0} cannot be canonicalised here")]
    NotInteger(String),
    /// An integer above 2^53 - 1 in magnitude.
    #[error("integer {0} is outside the I-JSON safe range")]
    OutOfRange(String),
    /// The value could not be turned into JSON.
    #[error(transparent)]
    Serialize(#[from] serde_json::Error),
}

/// Canonical bytes of any serialisable value.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, JcsError> {
    let value = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_value(&value, &mut out)?;
    Ok(out)
}

/// Canonical bytes of a JSON value.
pub fn value_to_vec(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(JcsError::OutOfRange(n.to_string()));
                }
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(JcsError::OutOfRange(n.to_string()));
                }
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(JcsError::NotInteger(n.to_string()));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (i, (key, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut start = 0;
    for (i, b) in s.bytes().enumerate() {
        let escape: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            0x08 => b"\\b",
            0x09 => b"\\t",
            0x0a => b"\\n",
            0x0c => b"\\f",
            0x0d => b"\\r",
            0x00..=0x1f => &[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[usize::from(b >> 4)],
                HEX[usize::from(b & 0xf)],
            ],
            _ => continue,
        };
        out.extend_from_slice(&s.as_bytes()[start..i]);
        out.extend_from_slice(escape);
        start = i + 1;
    }
    out.extend_from_slice(&s.as_bytes()[start..]);
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jcs(text: &str) -> String {
        let value: Value = serde_json::from_str(text).unwrap();
        String::from_utf8(value_to_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn rfc8785_string_and_literal_example() {
        // RFC 8785 §3.2.2.2 and §3.2.2.1, without the float array of §3.2.2.3.
        let input = r#"{
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
            "literals": [null, true, false]
        }"#;
        assert_eq!(
            jcs(input),
            r#"{"literals":[null,true,false],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    #[test]
    fn rfc8785_sorting_example() {
        // RFC 8785 §3.2.3: members sort by UTF-16 code units, so the emoji
        // (surrogates D83D DE00) sorts before U+FB33, unlike UTF-8 order.
        let input = r#"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        assert_eq!(
            jcs(input),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
             \"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\
             \"😀\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    #[test]
    fn nested_values_have_no_whitespace() {
        let v = json!({"b": [1, {"z": -2, "a": "x"}], "a": {}, "c": []});
        assert_eq!(
            String::from_utf8(to_vec(&v).unwrap()).unwrap(),
            r#"{"a":{},"b":[1,{"a":"x","z":-2}],"c":[]}"#
        );
    }

    #[test]
    fn control_characters_use_short_or_hex_escapes() {
        let v = json!("\u{0}\u{8}\t\n\u{b}\u{c}\r\u{1f}\u{7f}\u{2028}");
        assert_eq!(
            String::from_utf8(to_vec(&v).unwrap()).unwrap(),
            "\"\\u0000\\b\\t\\n\\u000b\\f\\r\\u001f\u{7f}\u{2028}\""
        );
    }

    #[test]
    fn refuses_numbers_it_cannot_reproduce() {
        assert!(matches!(to_vec(&json!(4.5)), Err(JcsError::NotInteger(_))));
        assert!(matches!(
            to_vec(&json!(MAX_SAFE_INTEGER + 1)),
            Err(JcsError::OutOfRange(_))
        ));
        assert!(matches!(
            to_vec(&json!(-(MAX_SAFE_INTEGER as i64) - 1)),
            Err(JcsError::OutOfRange(_))
        ));
        assert_eq!(
            to_vec(&json!(MAX_SAFE_INTEGER)).unwrap(),
            b"9007199254740991"
        );
        assert_eq!(to_vec(&json!(0)).unwrap(), b"0");
    }

    #[test]
    fn agrees_with_serde_json_on_string_escapes() {
        // serde_json escapes the same set, the same way; the canonical form
        // only adds key ordering. Checked across every ASCII byte.
        let all: String = (0u8..0x80).map(char::from).collect();
        let ours = String::from_utf8(to_vec(&all).unwrap()).unwrap();
        assert_eq!(ours, serde_json::to_string(&all).unwrap());
    }
}
