//! Keys and key slots.
//!
//! ```text
//! DK (data key, 32 random bytes, made at init; never on disk in the clear)
//!  ├─ wrapped in keyslots.json, any one slot unwraps it:
//!  │    systemd-creds  KEK = HKDF-SHA256(MK, "countersign/v1/kek/systemd-creds")
//!  │                   MK = the 32-byte master key systemd-creds unseals
//!  │    recovery       KEK = Argon2id(recovery phrase bytes, salt)
//!  ├─ FK = HKDF-SHA256(DK, "countersign/v1/file")       seals store.v1
//!  ├─ VK = HKDF-SHA256(DK, "countersign/v1/value")      seals each value
//!  └─ AK = HKDF-SHA256(DK, "countersign/v1/audit-sign") Ed25519 checkpoint seed
//! ```
//!
//! A slot is `XChaCha20-Poly1305(KEK, nonce, aad = "countersign/v1/keyslot\0"
//! || slot type, DK)`. Deriving the store keys from DK rather than MK means
//! replacing the machine key (`cnd recover`) re-wraps one slot and keeps the
//! store and the checkpoint key unchanged.

use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::StoreError;
use super::phrase::RecoveryPhrase;
use crate::encoding::{b64, random_array, unb64};

/// Length of every symmetric key.
pub const KEY_LEN: usize = 32;

/// The machine master key: 32 raw bytes from the `countersign-mk`
/// credential. Zeroized on drop.
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    /// Wraps 32 bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Reads the key from a file that holds exactly 32 bytes, such as
    /// `$CREDENTIALS_DIRECTORY/countersign-mk`.
    pub fn read(path: &Path) -> Result<Self, StoreError> {
        let bytes = Zeroizing::new(std::fs::read(path).map_err(StoreError::io(path))?);
        let arr: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
            StoreError::Corrupt(format!(
                "{} holds {} bytes; a master key is {KEY_LEN}",
                path.display(),
                bytes.len()
            ))
        })?;
        Ok(Self::from_bytes(arr))
    }

    /// A random key. For tests and for tooling that seals a fresh key.
    pub fn generate() -> Self {
        Self::from_bytes(random_array())
    }

    fn kek(&self) -> Zeroizing<[u8; KEY_LEN]> {
        hkdf(&self.0[..], b"countersign/v1/kek/systemd-creds")
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(..)")
    }
}

/// Keys derived from the data key.
pub(crate) struct Keys {
    pub(crate) file: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) value: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) audit_seed: Zeroizing<[u8; KEY_LEN]>,
}

impl Keys {
    pub(crate) fn derive(dk: &[u8; KEY_LEN]) -> Self {
        Self {
            file: hkdf(dk, b"countersign/v1/file"),
            value: hkdf(dk, b"countersign/v1/value"),
            audit_seed: hkdf(dk, b"countersign/v1/audit-sign"),
        }
    }
}

fn hkdf(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut out = Zeroizing::new([0; KEY_LEN]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut out[..])
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// Seals with XChaCha20-Poly1305 under a fresh random nonce.
pub(crate) fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> ([u8; 24], Vec<u8>) {
    let nonce: [u8; 24] = random_array();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption does not fail for in-memory buffers");
    (nonce, ct)
}

/// Opens what [`seal`] made. Any change to key, nonce, aad or ciphertext
/// fails.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if nonce.len() != 24 {
        return None;
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

/// Argon2id cost parameters, stored in the slot so they can be raised later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// The parameters `cnd init` uses: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };

    /// Cheap parameters for tests. Never use them for a real store.
    pub const INSECURE_FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
}

fn recovery_kek(
    phrase: &RecoveryPhrase,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| StoreError::Corrupt(format!("recovery slot parameters: {e}")))?;
    let mut out = Zeroizing::new([0; KEY_LEN]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p)
        .hash_password_into(phrase.secret(), salt, &mut out[..])
        .map_err(|e| StoreError::Corrupt(format!("recovery slot: {e}")))?;
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotFile {
    format: u32,
    slots: Vec<Slot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum Slot {
    SystemdCreds {
        nonce: String,
        wrapped: String,
    },
    Recovery {
        kdf: String,
        params: KdfParams,
        salt: String,
        nonce: String,
        wrapped: String,
    },
}

const SYSTEMD_CREDS: &str = "systemd-creds";
const RECOVERY: &str = "recovery";

fn slot_aad(kind: &str) -> Vec<u8> {
    [b"countersign/v1/keyslot\0".as_slice(), kind.as_bytes()].concat()
}

fn wrap(kek: &[u8; KEY_LEN], kind: &str, dk: &[u8; KEY_LEN]) -> (String, String) {
    let (nonce, ct) = seal(kek, &slot_aad(kind), dk);
    (b64(&nonce), b64(&ct))
}

fn unwrap(
    kek: &[u8; KEY_LEN],
    kind: &str,
    nonce: &str,
    wrapped: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    let bad = || StoreError::Corrupt(format!("keyslots.json: {kind} slot is malformed"));
    let nonce = unb64(nonce).ok_or_else(bad)?;
    let ct = unb64(wrapped).ok_or_else(bad)?;
    let pt = open(kek, &nonce, &slot_aad(kind), &ct).ok_or(StoreError::WrongKey)?;
    let mut dk = Zeroizing::new([0; KEY_LEN]);
    if pt.len() != KEY_LEN {
        return Err(bad());
    }
    dk.copy_from_slice(&pt);
    Ok(dk)
}

/// The parsed `keyslots.json`.
pub(crate) struct KeySlots(SlotFile);

impl KeySlots {
    /// Wraps `dk` in a `systemd-creds` slot and a recovery slot.
    pub(crate) fn new(
        dk: &[u8; KEY_LEN],
        mk: &MasterKey,
        phrase: &RecoveryPhrase,
        params: KdfParams,
    ) -> Result<Self, StoreError> {
        let (nonce, wrapped) = wrap(&mk.kek(), SYSTEMD_CREDS, dk);
        let salt: [u8; 16] = random_array();
        let kek = recovery_kek(phrase, &salt, params)?;
        let (rnonce, rwrapped) = wrap(&kek, RECOVERY, dk);
        Ok(Self(SlotFile {
            format: 1,
            slots: vec![
                Slot::SystemdCreds { nonce, wrapped },
                Slot::Recovery {
                    kdf: "argon2id".into(),
                    params,
                    salt: b64(&salt),
                    nonce: rnonce,
                    wrapped: rwrapped,
                },
            ],
        }))
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, StoreError> {
        let f: SlotFile = serde_json::from_slice(bytes)
            .map_err(|e| StoreError::Corrupt(format!("keyslots.json: {e}")))?;
        if f.format != 1 {
            return Err(StoreError::Corrupt(format!(
                "keyslots.json: unknown format {}",
                f.format
            )));
        }
        Ok(Self(f))
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(&self.0).expect("slots serialize");
        v.push(b'\n');
        v
    }

    /// Unwraps the data key with the master key.
    pub(crate) fn unwrap_master(
        &self,
        mk: &MasterKey,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
        for s in &self.0.slots {
            if let Slot::SystemdCreds { nonce, wrapped } = s {
                return unwrap(&mk.kek(), SYSTEMD_CREDS, nonce, wrapped);
            }
        }
        Err(StoreError::Corrupt(
            "keyslots.json has no systemd-creds slot".into(),
        ))
    }

    /// Unwraps the data key with the recovery phrase.
    pub(crate) fn unwrap_recovery(
        &self,
        phrase: &RecoveryPhrase,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
        for s in &self.0.slots {
            if let Slot::Recovery {
                kdf,
                params,
                salt,
                nonce,
                wrapped,
            } = s
            {
                if kdf != "argon2id" {
                    return Err(StoreError::Corrupt(format!(
                        "recovery slot: unknown kdf {kdf}"
                    )));
                }
                let salt = unb64(salt)
                    .ok_or_else(|| StoreError::Corrupt("recovery slot: bad salt".into()))?;
                let kek = recovery_kek(phrase, &salt, *params)?;
                return unwrap(&kek, RECOVERY, nonce, wrapped);
            }
        }
        Err(StoreError::Corrupt(
            "keyslots.json has no recovery slot".into(),
        ))
    }

    /// Replaces the `systemd-creds` slot with one for `mk`.
    pub(crate) fn rewrap_master(&mut self, dk: &[u8; KEY_LEN], mk: &MasterKey) {
        let (nonce, wrapped) = wrap(&mk.kek(), SYSTEMD_CREDS, dk);
        self.0
            .slots
            .retain(|s| !matches!(s, Slot::SystemdCreds { .. }));
        self.0
            .slots
            .insert(0, Slot::SystemdCreds { nonce, wrapped });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_binds_key_nonce_and_aad() {
        let key = [7u8; KEY_LEN];
        let (nonce, ct) = seal(&key, b"aad", b"hello");
        assert_eq!(
            open(&key, &nonce, b"aad", &ct).unwrap().as_slice(),
            b"hello"
        );
        assert!(open(&[8u8; KEY_LEN], &nonce, b"aad", &ct).is_none());
        assert!(open(&key, &nonce, b"aae", &ct).is_none());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&key, &nonce, b"aad", &bad).is_none());
        assert!(open(&key, &nonce[..23], b"aad", &ct).is_none());
        // A fresh nonce per seal.
        assert_ne!(seal(&key, b"aad", b"hello").0, nonce);
    }

    #[test]
    fn slots_unwrap_with_either_key_and_not_otherwise() {
        let dk = [3u8; KEY_LEN];
        let mk = MasterKey::generate();
        let phrase = RecoveryPhrase::generate();
        let slots = KeySlots::new(&dk, &mk, &phrase, KdfParams::INSECURE_FAST).unwrap();
        let slots = KeySlots::parse(&slots.to_bytes()).unwrap();
        assert_eq!(*slots.unwrap_master(&mk).unwrap(), dk);
        assert_eq!(*slots.unwrap_recovery(&phrase).unwrap(), dk);
        assert!(matches!(
            slots.unwrap_master(&MasterKey::generate()),
            Err(StoreError::WrongKey)
        ));
        assert!(matches!(
            slots.unwrap_recovery(&RecoveryPhrase::generate()),
            Err(StoreError::WrongKey)
        ));
    }

    #[test]
    fn master_key_file_must_be_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mk");
        std::fs::write(&p, [1u8; 31]).unwrap();
        assert!(MasterKey::read(&p).is_err());
        std::fs::write(&p, [1u8; 32]).unwrap();
        assert!(MasterKey::read(&p).is_ok());
        assert_eq!(format!("{:?}", MasterKey::generate()), "MasterKey(..)");
    }
}
