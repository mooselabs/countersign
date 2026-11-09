//! Small encodings: Crockford base32, base64 and random bytes. Canonical
//! JSON (RFC 8785) is `countersign_proto::jcs`.

use base64::Engine as _;

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

/// A random id: `prefix` followed by `n` lower-case Crockford characters
/// (5 random bits each). Request, grant and run ids use it.
pub fn random_id(prefix: &str, n: usize) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
