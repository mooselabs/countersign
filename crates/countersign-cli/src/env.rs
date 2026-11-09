//! Names, `--use` parsing, and the environment `cn` gives a child.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use countersign_proto::{Use, default_env};
use zeroize::Zeroizing;

use crate::error::CnError;

/// Prefix of variables `cn` never passes to a child.
pub const STRIPPED_PREFIX: &[u8] = b"COUNTERSIGN_";

/// `^[a-z0-9][a-z0-9._-]{0,63}$`
pub fn valid_secret_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// A portable environment variable name: `^[A-Za-z_][A-Za-z0-9_]*$`.
pub fn valid_env_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Parses `--use NAME[=ENVVAR]` arguments. Refuses a bad name, a bad or
/// `COUNTERSIGN_*` variable, and two uses mapped to one variable.
pub fn parse_uses(args: &[String]) -> Result<Vec<Use>, CnError> {
    let mut seen = BTreeSet::new();
    let mut uses = Vec::with_capacity(args.len());
    for arg in args {
        let (name, env) = match arg.split_once('=') {
            Some((name, env)) => (name, env.to_owned()),
            None => (arg.as_str(), default_env(arg)),
        };
        if !valid_secret_name(name) {
            return Err(CnError::usage(format!(
                "--use {arg}: {name:?} is not a secret name"
            )));
        }
        if !valid_env_name(&env) {
            return Err(CnError::usage(format!(
                "--use {arg}: {env:?} is not a valid environment variable name"
            )));
        }
        if env.as_bytes().starts_with(STRIPPED_PREFIX) {
            return Err(CnError::usage(format!(
                "--use {arg}: COUNTERSIGN_* variables are reserved"
            )));
        }
        if !seen.insert(env.clone()) {
            return Err(CnError::usage(format!(
                "--use {arg}: two secrets map to {env}"
            )));
        }
        uses.push(Use {
            name: name.to_owned(),
            env,
        });
    }
    Ok(uses)
}

/// One variable to inject: its name and value.
pub struct Injected<'a> {
    /// Variable name.
    pub env: &'a str,
    /// Value bytes.
    pub value: &'a [u8],
}

/// A child's environment. Values are zeroized on drop.
pub type ChildEnv = Vec<(OsString, Zeroizing<Vec<u8>>)>;

/// The child's environment: `base` without `COUNTERSIGN_*` variables and
/// without any variable being injected, then each injected variable. A
/// value containing a NUL byte cannot be put in an environment and is
/// refused.
pub fn build_env(
    base: impl IntoIterator<Item = (OsString, OsString)>,
    injected: &[Injected<'_>],
) -> Result<ChildEnv, CnError> {
    let names: BTreeSet<&[u8]> = injected.iter().map(|i| i.env.as_bytes()).collect();
    let mut out: ChildEnv = base
        .into_iter()
        .filter(|(k, _)| {
            let k = k.as_bytes();
            !k.starts_with(STRIPPED_PREFIX) && !names.contains(k)
        })
        .map(|(k, v)| (k, Zeroizing::new(v.into_vec())))
        .collect();
    for i in injected {
        if i.value.contains(&0) {
            return Err(CnError::usage(format!(
                "the value for {} contains a NUL byte and cannot be put in an environment variable",
                i.env
            )));
        }
        out.push((OsString::from(i.env), Zeroizing::new(i.value.to_vec())));
    }
    Ok(out)
}

/// The current environment without `COUNTERSIGN_*` variables.
pub fn stripped_env() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(k, _)| !k.as_bytes().starts_with(STRIPPED_PREFIX))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["a", "clickhouse-prod", "typesafe.api_key", "0x"] {
            assert!(valid_secret_name(ok), "{ok}");
        }
        for bad in ["", "-a", "A", "a b", "a/b", &"a".repeat(65)] {
            assert!(!valid_secret_name(bad), "{bad}");
        }
        for ok in ["A", "_X", "GH_TOKEN2", "lower"] {
            assert!(valid_env_name(ok), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A=B", "A B"] {
            assert!(!valid_env_name(bad), "{bad}");
        }
    }

    #[test]
    fn uses_default_to_upper_snake_case() {
        let uses =
            parse_uses(&["clickhouse-password".into(), "github-token=GH_TOKEN".into()]).unwrap();
        assert_eq!(uses[0].env, "CLICKHOUSE_PASSWORD");
        assert_eq!(uses[1].name, "github-token");
        assert_eq!(uses[1].env, "GH_TOKEN");
    }

    #[test]
    fn uses_refuse_duplicates_and_bad_variables() {
        assert!(parse_uses(&["a=X".into(), "b=X".into()]).is_err());
        assert!(parse_uses(&["a-b".into(), "c=A_B".into()]).is_err());
        assert!(parse_uses(&["a=1X".into()]).is_err());
        assert!(parse_uses(&["a=".into()]).is_err());
        assert!(parse_uses(&["A".into()]).is_err());
        assert!(parse_uses(&["a=COUNTERSIGN_SOCKET".into()]).is_err());
        assert_eq!(
            parse_uses(&["a=X".into(), "b=X".into()]).unwrap_err().code,
            "usage"
        );
    }

    #[test]
    fn env_drops_countersign_variables_and_overrides() {
        let base = vec![
            (OsString::from("PATH"), OsString::from("/usr/bin")),
            (
                OsString::from("COUNTERSIGN_SOCKET"),
                OsString::from("/tmp/s"),
            ),
            (OsString::from("DB"), OsString::from("stale")),
        ];
        let env = build_env(
            base,
            &[Injected {
                env: "DB",
                value: b"fresh",
            }],
        )
        .unwrap();
        let pairs: Vec<(String, Vec<u8>)> = env
            .iter()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_vec()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("PATH".into(), b"/usr/bin".to_vec()),
                ("DB".into(), b"fresh".to_vec())
            ]
        );
    }

    #[test]
    fn env_refuses_nul_values() {
        let err = build_env(
            vec![],
            &[Injected {
                env: "DB",
                value: b"a\0b",
            }],
        )
        .err()
        .unwrap();
        assert_eq!(err.code, "usage");
    }
}
