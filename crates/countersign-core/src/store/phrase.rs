//! The recovery phrase.
//!
//! 160 random bits written as 32 Crockford base32 characters in groups of
//! four, followed by one checksum group:
//!
//! ```text
//! 7K2M-Q9D4-X1HA-3QF8-ZK2M-W41C-P2D8-TW6B-R9C2
//! ```
//!
//! The checksum group is the first 20 bits of
//! `SHA-256("countersign/recovery/v1\0" || secret bytes)`, so a mistyped or
//! swapped character is caught before Argon2id runs (a random error passes
//! with probability 2^-20). Input is case-insensitive, dashes and spaces are
//! ignored, and per Crockford `O` reads as `0` and `I`/`L` as `1`. The key is
//! derived from the 20 decoded bytes, so how the phrase was typed does not
//! matter.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{crockford, crockford_value, fill_random};

/// Bytes of secret in a phrase.
pub const PHRASE_BYTES: usize = 20;
const DATA_CHARS: usize = 32;
const CHECK_CHARS: usize = 4;

/// A recovery phrase. Zeroized on drop; `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPhrase(Zeroizing<[u8; PHRASE_BYTES]>);

/// A string that is not a recovery phrase.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PhraseError {
    /// Not 36 characters once dashes and spaces are removed.
    #[error("a recovery phrase has 36 characters in 9 groups; found {0}")]
    Length(usize),
    /// A character outside Crockford base32.
    #[error("character {0} is not part of a recovery phrase")]
    Char(usize),
    /// The checksum group does not match: a typo.
    #[error("the recovery phrase checksum does not match; check for a typo")]
    Checksum,
}

impl RecoveryPhrase {
    /// A new random phrase.
    pub fn generate() -> Self {
        let mut b = Zeroizing::new([0; PHRASE_BYTES]);
        fill_random(&mut b[..]);
        Self(b)
    }

    /// The secret bytes the recovery key is derived from.
    pub(crate) fn secret(&self) -> &[u8; PHRASE_BYTES] {
        &self.0
    }

    fn checksum(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(b"countersign/recovery/v1\0");
        h.update(bytes);
        let d = h.finalize();
        let mut s = crockford(&d[..3]);
        s.truncate(CHECK_CHARS);
        s
    }
}

impl fmt::Display for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut chars = Zeroizing::new(crockford(&self.0[..]));
        chars.push_str(&Self::checksum(&self.0[..]));
        for (i, group) in chars.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            f.write_str(std::str::from_utf8(group).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(..)")
    }
}

impl FromStr for RecoveryPhrase {
    type Err = PhraseError;

    fn from_str(s: &str) -> Result<Self, PhraseError> {
        let mut vals = Zeroizing::new(Vec::with_capacity(DATA_CHARS + CHECK_CHARS));
        for (i, c) in s.bytes().enumerate() {
            if c == b'-' || c.is_ascii_whitespace() {
                continue;
            }
            vals.push(crockford_value(c).ok_or(PhraseError::Char(i + 1))?);
        }
        if vals.len() != DATA_CHARS + CHECK_CHARS {
            return Err(PhraseError::Length(vals.len()));
        }
        let mut bytes = Zeroizing::new([0u8; PHRASE_BYTES]);
        let (mut acc, mut bits, mut n) = (0u64, 0, 0);
        for &v in &vals[..DATA_CHARS] {
            acc = (acc << 5) | u64::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes[n] = (acc >> bits) as u8;
                n += 1;
            }
        }
        acc.zeroize();
        let expected = Self::checksum(&bytes[..]);
        let given: Vec<u8> = vals[DATA_CHARS..].to_vec();
        let expected_vals: Vec<u8> = expected.bytes().filter_map(crockford_value).collect();
        if given != expected_vals {
            return Err(PhraseError::Checksum);
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrases_round_trip_in_any_case_and_spacing() {
        for _ in 0..200 {
            let p = RecoveryPhrase::generate();
            let s = p.to_string();
            assert_eq!(s.len(), 36 + 8);
            assert_eq!(s.split('-').count(), 9);
            assert_eq!(s.parse::<RecoveryPhrase>(), Ok(p.clone()));
            let loose = s.to_ascii_lowercase().replace('-', " ");
            assert_eq!(loose.parse::<RecoveryPhrase>(), Ok(p.clone()));
            let squashed = s.replace('-', "").replace('0', "o").replace('1', "l");
            assert_eq!(squashed.parse::<RecoveryPhrase>(), Ok(p));
        }
    }

    #[test]
    fn typos_are_caught() {
        let p = RecoveryPhrase::generate();
        let s = p.to_string();
        let mut caught = 0;
        for i in (0..s.len()).filter(|&i| s.as_bytes()[i] != b'-') {
            let mut b = s.clone().into_bytes();
            b[i] = if b[i] == b'7' { b'8' } else { b'7' };
            let r = String::from_utf8(b).unwrap().parse::<RecoveryPhrase>();
            if r == Err(PhraseError::Checksum) {
                caught += 1;
            }
        }
        // A change slips past the 20-bit check with probability 2^-20.
        assert_eq!(caught, 36);
        assert_eq!(
            s[..s.len() - 5].parse::<RecoveryPhrase>(),
            Err(PhraseError::Length(32))
        );
        assert_eq!(
            format!("U{}", &s[1..]).parse::<RecoveryPhrase>(),
            Err(PhraseError::Char(1))
        );
    }

    #[test]
    fn debug_hides_the_phrase() {
        assert_eq!(
            format!("{:?}", RecoveryPhrase::generate()),
            "RecoveryPhrase(..)"
        );
    }
}
