//! The encrypted secret store (design.md section 3).
//!
//! Files in the state directory, all mode 0600:
//!
//! - `keyslots.json`: the data key wrapped by each key slot ([`keys`]).
//! - `store.v1`: one header line, then the sealed body:
//!
//!   ```text
//!   {"magic":"countersign-store","format":1,"generation":42,"nonce":"<b64>"}\n
//!   XChaCha20-Poly1305(FK, nonce, aad = the header line, body)
//!   body  = {"secrets":[{name, description, usage, projects, tags,
//!            high_entropy, created, updated, rotated,
//!            value: {"nonce": "<b64>", "ct": "<b64>"}}]}
//!   value.ct = XChaCha20-Poly1305(VK, nonce, aad = "countersign/v1/value\0" || name, value)
//!   ```
//!
//! - `store.v1.prev`: the store before the last mutation.
//!
//! Every write is a whole-file replacement ([`fsio`]) with a fresh nonce.
//! The decrypted index stays in memory with values still sealed; a value is
//! opened only by [`Store::value`].

mod fsio;
pub mod keys;
mod model;
mod phrase;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use countersign_proto::{ErrorCode, SecretMeta};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use keys::{KdfParams, MasterKey};
pub use model::{
    Change, MAX_DESCRIPTION_CHARS, MAX_USAGE_BYTES, MAX_VALUE_LEN, Mutation, SecretInfo,
    SecretValue, check_meta, check_value, default_env, meta_diff, valid_name,
};
pub use phrase::{PhraseError, RecoveryPhrase};

use crate::encoding::{b64, random_array, unb64};
use crate::time::{format_rfc3339_micros, parse_rfc3339};
use keys::{KEY_LEN, KeySlots, Keys};

/// The store file.
pub const STORE_FILE: &str = "store.v1";
/// The store before the last mutation.
pub const STORE_PREV_FILE: &str = "store.v1.prev";
/// The key slot file.
pub const KEYSLOTS_FILE: &str = "keyslots.json";

const MAGIC: &str = "countersign-store";
const VALUE_AAD: &[u8] = b"countersign/v1/value\0";

/// A store operation that failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// A file is not in the expected format.
    #[error("store files are damaged: {0}")]
    Corrupt(String),
    /// Decryption failed: wrong key, or the file was altered.
    #[error("wrong key, or the store was altered")]
    WrongKey,
    /// `init` found an existing store.
    #[error("a store already exists in {0}")]
    AlreadyInitialized(PathBuf),
    /// There is no store.
    #[error("no store in {0}; run `cnd init`")]
    NotInitialized(PathBuf),
    /// `add` of a name that exists.
    #[error("secret {0:?} already exists")]
    Exists(String),
    /// A name that is not in the store.
    #[error("no secret {0:?}")]
    Unknown(String),
    /// Metadata or a value that breaks a data-model rule.
    #[error("{0}")]
    Invalid(String),
    /// A failed write or rollback left the files in a state this process
    /// could not confirm. Changes are refused until `cnd` restarts and
    /// reads the store again.
    #[error("the store refuses changes until cnd restarts: {0}")]
    Poisoned(String),
}

impl StoreError {
    fn io(path: &Path) -> impl FnOnce(std::io::Error) -> StoreError + '_ {
        move |source| StoreError::Io {
            path: path.to_owned(),
            source,
        }
    }

    /// The protocol error code to send a client.
    pub fn code(&self) -> ErrorCode {
        match self {
            StoreError::Unknown(_) => ErrorCode::UnknownSecret,
            StoreError::Exists(_) => ErrorCode::SecretExists,
            StoreError::Invalid(_) => ErrorCode::BadRequest,
            _ => ErrorCode::Internal,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    magic: String,
    format: u32,
    generation: u64,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    secrets: Vec<Record>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    usage: String,
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    high_entropy: bool,
    created: String,
    updated: String,
    rotated: String,
    value: Sealed,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    nonce: String,
    ct: String,
}

#[derive(Clone)]
struct Entry {
    info: SecretInfo,
    value: Sealed,
}

/// An open store.
pub struct Store {
    dir: PathBuf,
    keys: Keys,
    generation: u64,
    secrets: BTreeMap<String, Entry>,
    poisoned: Option<String>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("dir", &self.dir)
            .field("generation", &self.generation)
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Creates an empty store in `dir` (made 0700 if missing): a new data
    /// key, a `systemd-creds` slot for `mk` and a recovery slot for a new
    /// phrase, which is returned to be shown once. Refuses if `store.v1`
    /// exists. `keyslots.json` is written first and `store.v1` last, so an
    /// interrupted init can be run again.
    pub fn init(dir: &Path, mk: &MasterKey) -> Result<(Store, RecoveryPhrase), StoreError> {
        Self::init_with(dir, mk, KdfParams::DEFAULT)
    }

    /// [`Store::init`] with chosen Argon2id parameters. Tests use
    /// [`KdfParams::INSECURE_FAST`].
    pub fn init_with(
        dir: &Path,
        mk: &MasterKey,
        kdf: KdfParams,
    ) -> Result<(Store, RecoveryPhrase), StoreError> {
        fsio::ensure_private_dir(dir).map_err(StoreError::io(dir))?;
        if dir.join(STORE_FILE).exists() {
            return Err(StoreError::AlreadyInitialized(dir.to_owned()));
        }
        let dk = Zeroizing::new(random_array::<KEY_LEN>());
        let phrase = RecoveryPhrase::generate();
        let slots = KeySlots::new(&dk, mk, &phrase, kdf)?;
        fsio::replace(dir, KEYSLOTS_FILE, &slots.to_bytes(), false)
            .map_err(StoreError::io(&dir.join(KEYSLOTS_FILE)))?;
        let store = Store {
            dir: dir.to_owned(),
            keys: Keys::derive(&dk),
            generation: 0,
            secrets: BTreeMap::new(),
            poisoned: None,
        };
        let bytes = store.encode(0)?;
        fsio::replace(dir, STORE_FILE, &bytes, false)
            .map_err(StoreError::io(&dir.join(STORE_FILE)))?;
        Ok((store, phrase))
    }

    /// Opens the store with the master key.
    pub fn open(dir: &Path, mk: &MasterKey) -> Result<Store, StoreError> {
        let slots = Self::read_slots(dir)?;
        let dk = slots.unwrap_master(mk)?;
        Self::load(dir, &dk)
    }

    /// Opens the store with the recovery phrase and replaces the
    /// `systemd-creds` slot with one for `new_mk` (`cnd recover`).
    pub fn recover(
        dir: &Path,
        phrase: &RecoveryPhrase,
        new_mk: &MasterKey,
    ) -> Result<Store, StoreError> {
        let mut slots = Self::read_slots(dir)?;
        let dk = slots.unwrap_recovery(phrase)?;
        let store = Self::load(dir, &dk)?;
        slots.rewrap_master(&dk, new_mk);
        // No `.prev` copy: the old slot is wrapped with the key being replaced.
        fsio::replace(dir, KEYSLOTS_FILE, &slots.to_bytes(), false)
            .map_err(StoreError::io(&dir.join(KEYSLOTS_FILE)))?;
        Ok(store)
    }

    fn read_slots(dir: &Path) -> Result<KeySlots, StoreError> {
        let path = dir.join(KEYSLOTS_FILE);
        if !dir.join(STORE_FILE).exists() {
            return Err(StoreError::NotInitialized(dir.to_owned()));
        }
        KeySlots::parse(&std::fs::read(&path).map_err(StoreError::io(&path))?)
    }

    fn load(dir: &Path, dk: &[u8; KEY_LEN]) -> Result<Store, StoreError> {
        let path = dir.join(STORE_FILE);
        let bytes = std::fs::read(&path).map_err(StoreError::io(&path))?;
        let keys = Keys::derive(dk);
        let (generation, secrets) = decode(&keys, &bytes)?;
        Ok(Store {
            dir: dir.to_owned(),
            keys,
            generation,
            secrets,
            poisoned: None,
        })
    }

    /// The state directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Increases by one with every committed mutation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Every secret's metadata, by name.
    pub fn list(&self) -> impl Iterator<Item = &SecretInfo> {
        self.secrets.values().map(|e| &e.info)
    }

    /// One secret's metadata.
    pub fn get(&self, name: &str) -> Option<&SecretInfo> {
        self.secrets.get(name).map(|e| &e.info)
    }

    /// Whether a secret exists.
    pub fn contains(&self, name: &str) -> bool {
        self.secrets.contains_key(name)
    }

    /// Opens a value. The caller zeroizes it by dropping it.
    pub fn value(&self, name: &str) -> Result<SecretValue, StoreError> {
        let e = self
            .secrets
            .get(name)
            .ok_or_else(|| StoreError::Unknown(name.to_owned()))?;
        open_value(&self.keys, name, &e.value).map(SecretValue::from)
    }

    /// The seed of the Ed25519 audit checkpoint key.
    pub fn checkpoint_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.keys.audit_seed)
    }

    /// Checks that a mutation would apply, without applying it. Run when a
    /// mutation request is created, so the human is not asked to approve
    /// something that cannot commit.
    pub fn check(&self, m: &Mutation) -> Result<(), StoreError> {
        check_in(&self.secrets, m)
    }

    /// Checks a batch the way [`Store::apply_all`] would apply it: in order,
    /// each against the store as the earlier ones left it.
    pub fn check_all(&self, ms: &[Mutation]) -> Result<(), StoreError> {
        let mut next = self.secrets.clone();
        for m in ms {
            check_in(&next, m)?;
            apply_in(&self.keys, &mut next, m, SystemTime::UNIX_EPOCH);
        }
        Ok(())
    }

    /// Applies a mutation and writes the store. On error nothing changes, on
    /// disk or in memory.
    pub fn apply(&mut self, m: &Mutation, now: SystemTime) -> Result<Change, StoreError> {
        let mut changes = self.apply_all(std::slice::from_ref(m), now)?;
        Ok(changes.pop().expect("one change per mutation"))
    }

    /// Applies a batch (`rm` of several names, `import`) in order and writes
    /// the store once: all of it commits or none of it. The changes share
    /// the new generation.
    ///
    /// A write can fail after the new file was renamed into place (the
    /// directory `fsync`). Then the old file is put back, so what is on disk
    /// matches memory and the change does not appear at the next start. If
    /// that is not possible the store is poisoned ([`StoreError::Poisoned`]).
    pub fn apply_all(
        &mut self,
        ms: &[Mutation],
        now: SystemTime,
    ) -> Result<Vec<Change>, StoreError> {
        if let Some(why) = &self.poisoned {
            return Err(StoreError::Poisoned(why.clone()));
        }
        let mut next = self.secrets.clone();
        let mut changes = Vec::with_capacity(ms.len());
        let generation = self.generation + 1;
        for m in ms {
            check_in(&next, m)?;
            let (fields_changed, value_changed, metadata) = apply_in(&self.keys, &mut next, m, now);
            changes.push(Change {
                op: m.op(),
                secret: m.name().to_owned(),
                fields_changed,
                value_changed,
                generation,
                metadata,
            });
        }
        if changes.is_empty() {
            return Ok(changes);
        }
        if let Err(e) = self.write(generation, &next) {
            self.undo_write(generation, &e);
            return Err(e);
        }
        self.secrets = next;
        self.generation = generation;
        Ok(changes)
    }

    /// Adds a secret. Shorthand for [`Store::apply`].
    pub fn add(
        &mut self,
        meta: SecretMeta,
        value: SecretValue,
        now: SystemTime,
    ) -> Result<Change, StoreError> {
        self.apply(&Mutation::Add { meta, value }, now)
    }

    /// Replaces a value. Shorthand for [`Store::apply`].
    pub fn set(
        &mut self,
        name: &str,
        value: SecretValue,
        now: SystemTime,
    ) -> Result<Change, StoreError> {
        let name = name.to_owned();
        self.apply(&Mutation::Set { name, value }, now)
    }

    /// Replaces metadata. Shorthand for [`Store::apply`].
    pub fn edit(&mut self, meta: SecretMeta, now: SystemTime) -> Result<Change, StoreError> {
        self.apply(&Mutation::Edit { meta }, now)
    }

    /// Removes a secret. Shorthand for [`Store::apply`].
    pub fn rm(&mut self, name: &str, now: SystemTime) -> Result<Change, StoreError> {
        let name = name.to_owned();
        self.apply(&Mutation::Rm { name }, now)
    }

    /// After a failed write of generation `generation`: if the new file is
    /// in place anyway, put the old one back.
    fn undo_write(&mut self, generation: u64, cause: &StoreError) {
        let path = self.dir.join(STORE_FILE);
        let on_disk = std::fs::read(&path)
            .map_err(StoreError::io(&path))
            .and_then(|b| decode(&self.keys, &b));
        match on_disk {
            Ok((g, _)) if g == self.generation => {}
            Ok((g, _)) if g == generation => {
                let restored = self.restore_prev();
                if let Err(e) = restored {
                    self.poisoned = Some(format!(
                        "a write failed after the new store was in place ({cause}), and \
                         restoring the previous one failed: {e}"
                    ));
                }
            }
            Ok((g, _)) => {
                self.poisoned = Some(format!(
                    "after a failed write ({cause}) the store on disk is generation {g}, \
                     memory has {}",
                    self.generation
                ));
            }
            Err(e) => {
                self.poisoned = Some(format!(
                    "after a failed write ({cause}) the store could not be read back: {e}"
                ));
            }
        }
    }

    /// Whether changes are refused, and why.
    pub fn poisoned(&self) -> Option<&str> {
        self.poisoned.as_deref()
    }

    /// Puts `store.v1.prev` back as the store, on disk and in memory. `cnd`
    /// calls this when the audit record for a mutation cannot be written
    /// (audit.md, "Writes"). If it fails, the store is poisoned: memory and
    /// disk may disagree, so later changes are refused.
    pub fn rollback(&mut self) -> Result<(), StoreError> {
        let r = self.restore_prev();
        if let Err(e) = &r {
            self.poisoned = Some(format!("rolling back a change failed: {e}"));
        }
        r
    }

    fn restore_prev(&mut self) -> Result<(), StoreError> {
        let prev = self.dir.join(STORE_PREV_FILE);
        let bytes = std::fs::read(&prev).map_err(StoreError::io(&prev))?;
        let (generation, secrets) = decode(&self.keys, &bytes)?;
        fsio::replace(&self.dir, STORE_FILE, &bytes, false)
            .map_err(StoreError::io(&self.dir.join(STORE_FILE)))?;
        self.generation = generation;
        self.secrets = secrets;
        Ok(())
    }

    fn write(&self, generation: u64, secrets: &BTreeMap<String, Entry>) -> Result<(), StoreError> {
        let bytes = encode(&self.keys, generation, secrets)?;
        fsio::replace(&self.dir, STORE_FILE, &bytes, true)
            .map_err(StoreError::io(&self.dir.join(STORE_FILE)))
    }

    fn encode(&self, generation: u64) -> Result<Vec<u8>, StoreError> {
        encode(&self.keys, generation, &self.secrets)
    }
}

fn check_in(secrets: &BTreeMap<String, Entry>, m: &Mutation) -> Result<(), StoreError> {
    let require = |name: &str| {
        if secrets.contains_key(name) {
            Ok(())
        } else {
            Err(StoreError::Unknown(name.to_owned()))
        }
    };
    match m {
        Mutation::Add { meta, value } => {
            check_meta(meta)?;
            check_value(value)?;
            if secrets.contains_key(&meta.name) {
                return Err(StoreError::Exists(meta.name.clone()));
            }
        }
        Mutation::Set { name, value } => {
            check_value(value)?;
            require(name)?;
        }
        Mutation::Edit { meta } => {
            check_meta(meta)?;
            require(&meta.name)?;
        }
        Mutation::Rm { name } => require(name)?,
    }
    Ok(())
}

/// Applies a checked mutation to `next`. Returns the changed fields, whether
/// the value changed, and the new metadata for `add` and `edit`.
fn apply_in(
    keys: &Keys,
    next: &mut BTreeMap<String, Entry>,
    m: &Mutation,
    now: SystemTime,
) -> (Vec<&'static str>, bool, Option<SecretMeta>) {
    match m {
        Mutation::Add { meta, value } => {
            let info = SecretInfo {
                meta: meta.clone(),
                created: now,
                updated: now,
                rotated: now,
            };
            let value = seal_value(keys, &meta.name, value.as_bytes());
            next.insert(meta.name.clone(), Entry { info, value });
            (vec![], true, Some(meta.clone()))
        }
        Mutation::Set { name, value } => {
            let e = next.get_mut(name).expect("checked");
            e.value = seal_value(keys, name, value.as_bytes());
            e.info.updated = now;
            e.info.rotated = now;
            (vec!["value", "rotated"], true, None)
        }
        Mutation::Edit { meta } => {
            let e = next.get_mut(&meta.name).expect("checked");
            let changed = model::meta_diff(&e.info.meta, meta);
            e.info.meta = meta.clone();
            e.info.updated = now;
            (changed, false, Some(meta.clone()))
        }
        Mutation::Rm { name } => {
            next.remove(name);
            (vec![], false, None)
        }
    }
}

fn seal_value(keys: &Keys, name: &str, value: &[u8]) -> Sealed {
    let aad = [VALUE_AAD, name.as_bytes()].concat();
    let (nonce, ct) = keys::seal(&keys.value, &aad, value);
    Sealed {
        nonce: b64(&nonce),
        ct: b64(&ct),
    }
}

fn open_value(keys: &Keys, name: &str, s: &Sealed) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let bad = || StoreError::Corrupt(format!("value of {name:?} is malformed"));
    let nonce = unb64(&s.nonce).ok_or_else(bad)?;
    let ct = unb64(&s.ct).ok_or_else(bad)?;
    let aad = [VALUE_AAD, name.as_bytes()].concat();
    keys::open(&keys.value, &nonce, &aad, &ct).ok_or(StoreError::WrongKey)
}

fn encode(
    keys: &Keys,
    generation: u64,
    secrets: &BTreeMap<String, Entry>,
) -> Result<Vec<u8>, StoreError> {
    let body = Body {
        secrets: secrets
            .values()
            .map(|e| Record {
                name: e.info.meta.name.clone(),
                description: e.info.meta.description.clone(),
                usage: e.info.meta.usage.clone(),
                projects: e.info.meta.projects.clone(),
                tags: e.info.meta.tags.clone(),
                high_entropy: e.info.meta.high_entropy,
                created: format_rfc3339_micros(e.info.created),
                updated: format_rfc3339_micros(e.info.updated),
                rotated: format_rfc3339_micros(e.info.rotated),
                value: e.value.clone(),
            })
            .collect(),
    };
    let plain =
        Zeroizing::new(serde_json::to_vec(&body).map_err(|e| StoreError::Corrupt(e.to_string()))?);
    // The nonce is in the header, and the header is the AAD, so the nonce
    // is chosen before sealing rather than by `keys::seal`.
    let nonce: [u8; 24] = random_array();
    let header = serde_json::to_vec(&Header {
        magic: MAGIC.into(),
        format: 1,
        generation,
        nonce: b64(&nonce),
    })
    .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let ct = seal_with_nonce(&keys.file, &nonce, &header, &plain);
    let mut out = header;
    out.push(b'\n');
    out.extend_from_slice(&ct);
    Ok(out)
}

fn seal_with_nonce(key: &[u8; KEY_LEN], nonce: &[u8; 24], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    chacha20poly1305::XChaCha20Poly1305::new(key.into())
        .encrypt(nonce.into(), Payload { msg: pt, aad })
        .expect("XChaCha20-Poly1305 encryption does not fail for in-memory buffers")
}

fn decode(keys: &Keys, bytes: &[u8]) -> Result<(u64, BTreeMap<String, Entry>), StoreError> {
    let nl = bytes
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| StoreError::Corrupt("store.v1 has no header line".into()))?;
    let (header_bytes, ct) = (&bytes[..nl], &bytes[nl + 1..]);
    let header: Header = serde_json::from_slice(header_bytes)
        .map_err(|e| StoreError::Corrupt(format!("store.v1 header: {e}")))?;
    if header.magic != MAGIC || header.format != 1 {
        return Err(StoreError::Corrupt("store.v1: not a format 1 store".into()));
    }
    let nonce =
        unb64(&header.nonce).ok_or_else(|| StoreError::Corrupt("store.v1: bad nonce".into()))?;
    let plain = keys::open(&keys.file, &nonce, header_bytes, ct).ok_or(StoreError::WrongKey)?;
    let body: Body = serde_json::from_slice(&plain)
        .map_err(|e| StoreError::Corrupt(format!("store.v1 body: {e}")))?;
    let time = |s: &str| parse_rfc3339(s).map_err(|e| StoreError::Corrupt(e.to_string()));
    let mut secrets = BTreeMap::new();
    for r in body.secrets {
        let meta = SecretMeta {
            name: r.name,
            description: r.description,
            usage: r.usage,
            projects: r.projects,
            tags: r.tags,
            high_entropy: r.high_entropy,
        };
        let info = SecretInfo {
            created: time(&r.created)?,
            updated: time(&r.updated)?,
            rotated: time(&r.rotated)?,
            meta,
        };
        let name = info.meta.name.clone();
        if secrets
            .insert(
                name.clone(),
                Entry {
                    info,
                    value: r.value,
                },
            )
            .is_some()
        {
            return Err(StoreError::Corrupt(format!("store.v1: {name:?} twice")));
        }
    }
    Ok((header.generation, secrets))
}

#[cfg(test)]
mod tests;
