//! The data model: secret values, metadata rules, and mutations.

use std::fmt;
use std::time::SystemTime;

use countersign_proto::SecretMeta;
use zeroize::Zeroizing;

use super::StoreError;

/// Longest value, in bytes.
pub const MAX_VALUE_LEN: usize = 64 * 1024;
/// Longest description, in characters.
pub const MAX_DESCRIPTION_CHARS: usize = 200;
/// Longest usage prose, in bytes.
pub const MAX_USAGE_BYTES: usize = 4096;
/// Most project globs or tags on one secret.
pub const MAX_LIST_ITEMS: usize = 32;
/// Longest project glob or tag, in bytes.
pub const MAX_ITEM_BYTES: usize = 256;

/// A secret value. Zeroized on drop; `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Takes ownership of the bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Zeroizing<Vec<u8>>> for SecretValue {
    fn from(v: Zeroizing<Vec<u8>>) -> Self {
        Self(v)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(..)")
    }
}

/// Whether `name` matches `^[a-z0-9][a-z0-9._-]{0,63}$`.
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

/// The default environment variable for a secret: upper snake case, `.` and
/// `-` become `_`.
pub fn default_env(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '.' | '-' => '_',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}

fn bad(msg: String) -> StoreError {
    StoreError::Invalid(msg)
}

fn has_control(s: &str, allow_newline: bool) -> bool {
    s.chars()
        .any(|c| c.is_control() && !(allow_newline && (c == '\n' || c == '\t')))
}

/// Checks a value's size.
pub fn check_value(v: &SecretValue) -> Result<(), StoreError> {
    if v.is_empty() {
        return Err(bad("a value cannot be empty".into()));
    }
    if v.len() > MAX_VALUE_LEN {
        return Err(bad(format!("a value is at most {MAX_VALUE_LEN} bytes")));
    }
    Ok(())
}

/// Checks metadata against the data-model rules (design.md section 3).
pub fn check_meta(m: &SecretMeta) -> Result<(), StoreError> {
    if !valid_name(&m.name) {
        return Err(bad(format!(
            "name {:?}: use 1 to 64 of a-z 0-9 . _ -, starting with a letter or digit",
            m.name
        )));
    }
    if m.description.chars().count() > MAX_DESCRIPTION_CHARS || has_control(&m.description, false) {
        return Err(bad(format!(
            "description: one line of at most {MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    if m.usage.len() > MAX_USAGE_BYTES || has_control(&m.usage, true) {
        return Err(bad(format!(
            "usage: at most {MAX_USAGE_BYTES} bytes, no control characters"
        )));
    }
    for (what, items) in [("projects", &m.projects), ("tags", &m.tags)] {
        if items.len() > MAX_LIST_ITEMS {
            return Err(bad(format!("{what}: at most {MAX_LIST_ITEMS} entries")));
        }
        for item in items {
            if item.is_empty() || item.len() > MAX_ITEM_BYTES || has_control(item, false) {
                return Err(bad(format!(
                    "{what}: {item:?} must be 1 to {MAX_ITEM_BYTES} bytes, no control characters"
                )));
            }
        }
    }
    Ok(())
}

/// A secret's metadata and times. Never holds the value.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretInfo {
    /// Name and prose.
    pub meta: SecretMeta,
    /// When it was added.
    pub created: SystemTime,
    /// Last change of any kind.
    pub updated: SystemTime,
    /// Last change of the value.
    pub rotated: SystemTime,
}

/// A change to the store. Held with a pending request until it is approved,
/// so the approval applies to exactly the value submitted.
#[derive(Debug, Clone, PartialEq)]
pub enum Mutation {
    /// Add a new secret.
    Add {
        /// Metadata, including the name.
        meta: SecretMeta,
        /// The value.
        value: SecretValue,
    },
    /// Replace a value.
    Set {
        /// Secret name.
        name: String,
        /// The new value.
        value: SecretValue,
    },
    /// Replace metadata; `meta.name` selects the secret.
    Edit {
        /// The full new metadata.
        meta: SecretMeta,
    },
    /// Remove a secret.
    Rm {
        /// Secret name.
        name: String,
    },
}

impl Mutation {
    /// The secret it changes.
    pub fn name(&self) -> &str {
        match self {
            Mutation::Add { meta, .. } | Mutation::Edit { meta } => &meta.name,
            Mutation::Set { name, .. } | Mutation::Rm { name } => name,
        }
    }

    /// The operation: `add`, `set`, `edit` or `rm`.
    pub fn op(&self) -> &'static str {
        match self {
            Mutation::Add { .. } => "add",
            Mutation::Set { .. } => "set",
            Mutation::Edit { .. } => "edit",
            Mutation::Rm { .. } => "rm",
        }
    }

    /// Whether it changes or removes a value, so existing grants for the
    /// secret must be revoked once it commits.
    pub fn invalidates_grants(&self) -> bool {
        matches!(self, Mutation::Set { .. } | Mutation::Rm { .. })
    }
}

/// What a committed mutation changed, for the `store.*` audit record.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    /// `add`, `set`, `edit` or `rm`; the audit event is `store.<op>`.
    pub op: &'static str,
    /// Secret name.
    pub secret: String,
    /// Fields that changed.
    pub fields_changed: Vec<&'static str>,
    /// Whether the value changed.
    pub value_changed: bool,
    /// Store generation after the change.
    pub generation: u64,
    /// The new metadata, for `add` and `edit`.
    pub metadata: Option<SecretMeta>,
}

/// The metadata fields that differ between `a` and `b`.
pub(crate) fn meta_diff(a: &SecretMeta, b: &SecretMeta) -> Vec<&'static str> {
    let mut v = Vec::new();
    if a.description != b.description {
        v.push("description");
    }
    if a.usage != b.usage {
        v.push("usage");
    }
    if a.projects != b.projects {
        v.push("projects");
    }
    if a.tags != b.tags {
        v.push("tags");
    }
    if a.high_entropy != b.high_entropy {
        v.push("high_entropy");
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str) -> SecretMeta {
        SecretMeta {
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn names_follow_the_rule() {
        for ok in ["a", "0", "clickhouse-prod", "a.b_c-d", &"a".repeat(64)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-a",
            ".a",
            "_a",
            "A",
            "a b",
            "a/b",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn env_names_are_upper_snake_case() {
        assert_eq!(default_env("clickhouse-prod"), "CLICKHOUSE_PROD");
        assert_eq!(default_env("a.b_c-d"), "A_B_C_D");
    }

    #[test]
    fn metadata_limits_hold() {
        assert!(check_meta(&meta("ok")).is_ok());
        let mut m = meta("ok");
        m.description = "two\nlines".into();
        assert!(check_meta(&m).is_err());
        m.description = "x".repeat(201);
        assert!(check_meta(&m).is_err());
        m.description = "é".repeat(200);
        assert!(check_meta(&m).is_ok());
        m.usage = "line one\nline two\twith tab".into();
        assert!(check_meta(&m).is_ok());
        m.usage = "\u{1b}[2J".into();
        assert!(check_meta(&m).is_err());
        m.usage = "x".repeat(4097);
        assert!(check_meta(&m).is_err());
        m.usage.clear();
        m.tags = vec![String::new()];
        assert!(check_meta(&m).is_err());
        m.tags = vec!["t".into(); 33];
        assert!(check_meta(&m).is_err());
        assert!(check_meta(&meta("Bad")).is_err());
    }

    #[test]
    fn values_have_bounds_and_hide_in_debug() {
        assert!(check_value(&SecretValue::new(vec![])).is_err());
        assert!(check_value(&SecretValue::new(vec![0; MAX_VALUE_LEN])).is_ok());
        assert!(check_value(&SecretValue::new(vec![0; MAX_VALUE_LEN + 1])).is_err());
        assert_eq!(
            format!("{:?}", SecretValue::new(b"hunter2".to_vec())),
            "SecretValue(..)"
        );
    }
}
