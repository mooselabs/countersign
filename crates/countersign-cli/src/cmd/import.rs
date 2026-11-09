//! `cn import --glob`: move plaintext secret files into the store as one
//! `mutate` request. Values come from the files only; the metadata file
//! holds descriptions and usage, never values.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use countersign_proto::{ImportItem, Request, RequestState, SecretMeta, ValueB64};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::cli::ImportArgs;
use crate::cmd::mutate::{MAX_VALUE_LEN, entropy_class, report, shred, strip_one_newline, submit};
use crate::env::valid_secret_name;
use crate::error::CnError;
use crate::output::{Ctx, Done, clean_line, table};

/// One entry of the `--metadata` TOML file.
#[derive(Debug, Default, Deserialize)]
struct MetaEntry {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    usage: Option<String>,
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    high_entropy: Option<bool>,
}

/// A file found by the glob.
struct Found {
    name: String,
    path: PathBuf,
    size: u64,
    git_tracked: bool,
    in_history: bool,
    world_readable: bool,
}

/// The secret name for a file name: the prefix removed.
pub fn name_for(file_name: &str, prefix: &str) -> String {
    file_name
        .strip_prefix(prefix)
        .unwrap_or(file_name)
        .to_owned()
}

fn find(args: &ImportArgs, glob_text: &str) -> Result<Vec<Found>, CnError> {
    let dir = match &args.dir {
        Some(d) => d.clone(),
        None => std::env::current_dir().map_err(|e| CnError::internal(e.to_string()))?,
    };
    let pattern = dir.join(glob_text);
    let pattern = pattern
        .to_str()
        .ok_or_else(|| CnError::usage("the glob is not valid UTF-8"))?;
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let paths =
        glob::glob_with(pattern, options).map_err(|e| CnError::usage(format!("--glob: {e}")))?;
    let mut found = Vec::new();
    for path in paths.flatten() {
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| CnError::usage(format!("{}: not a UTF-8 file name", path.display())))?;
        let name = name_for(file_name, &args.strip_prefix);
        if !valid_secret_name(&name) {
            return Err(CnError::usage(format!(
                "{}: {name:?} is not a secret name; rename the file or set --strip-prefix",
                path.display()
            )));
        }
        found.push(Found {
            name,
            git_tracked: git_ok(&dir, &["ls-files", "--error-unmatch", "--"], &path),
            in_history: git_has_history(&dir, &path),
            world_readable: meta.permissions().mode() & 0o004 != 0,
            size: meta.len(),
            path,
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    if let Some(w) = found.windows(2).find(|w| w[0].name == w[1].name) {
        return Err(CnError::usage(format!(
            "two files map to the secret name {}",
            w[0].name
        )));
    }
    Ok(found)
}

fn git_ok(dir: &Path, args: &[&str], path: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn git_has_history(dir: &Path, path: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["log", "--all", "--format=%H", "-1", "--"])
        .arg(path)
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
}

fn warnings(f: &Found) -> Vec<&'static str> {
    let mut w = Vec::new();
    if f.git_tracked {
        w.push("tracked by git");
    }
    if f.in_history {
        w.push("in git history");
    }
    if f.world_readable {
        w.push("world-readable");
    }
    w
}

fn prompt_line(question: &str) -> Result<String, CnError> {
    eprint!("{question}");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CnError::internal(format!("reading stdin: {e}")))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

/// `cn import`.
pub fn import(ctx: &Ctx, args: &ImportArgs) -> Result<Done, CnError> {
    if args.from.is_some() {
        return Err(CnError::later("cn import --from (age backups)"));
    }
    let glob_text = args
        .glob
        .as_deref()
        .ok_or_else(|| CnError::usage("--glob is required"))?;
    let found = find(args, glob_text)?;
    if found.is_empty() {
        return Err(CnError::usage(format!("no files match {glob_text}")));
    }

    let listing: Vec<_> = found
        .iter()
        .map(|f| {
            json!({"name": f.name, "path": f.path, "size": f.size,
                   "git_tracked": f.git_tracked, "in_history": f.in_history,
                   "world_readable": f.world_readable})
        })
        .collect();
    if args.dry_run {
        let rows: Vec<Vec<String>> = found
            .iter()
            .map(|f| {
                vec![
                    f.name.clone(),
                    f.size.to_string(),
                    warnings(f).join(", "),
                    clean_line(&f.path.display().to_string()),
                ]
            })
            .collect();
        return Ok(Done::ok(
            json!({"dry_run": true, "secrets": listing}),
            table(&["NAME", "BYTES", "WARNINGS", "SOURCE"], &rows),
        ));
    }

    for f in &found {
        let w = warnings(f);
        if !w.is_empty() {
            ctx.info(&format!(
                "cn: warning: {} is {}; rotate {} after importing",
                f.path.display(),
                w.join(", "),
                f.name
            ));
        }
    }

    let metadata: BTreeMap<String, MetaEntry> = match &args.metadata {
        Some(path) => {
            let text = fs::read_to_string(path)
                .map_err(|e| CnError::usage(format!("{}: {e}", path.display())))?;
            toml::from_str(&text).map_err(|e| CnError::usage(format!("{}: {e}", path.display())))?
        }
        None => BTreeMap::new(),
    };
    let interactive = args.metadata.is_none() && io::stdin().is_terminal();

    let mut items = Vec::with_capacity(found.len());
    for f in &found {
        let mut value = Zeroizing::new(
            fs::read(&f.path).map_err(|e| CnError::usage(format!("{}: {e}", f.path.display())))?,
        );
        strip_one_newline(&mut value);
        if value.is_empty() || value.len() > MAX_VALUE_LEN {
            return Err(CnError::usage(format!(
                "{}: the value is empty or larger than 64 KiB",
                f.path.display()
            )));
        }
        let entry = metadata.get(&f.name);
        let placeholder = format!("imported from {}", f.path.display());
        let (description, usage) = match entry {
            Some(e) => (
                e.description.clone().unwrap_or(placeholder),
                e.usage.clone().unwrap_or_default(),
            ),
            None if interactive => {
                let d = prompt_line(&format!("{}: description (one line): ", f.name))?;
                let u = prompt_line(&format!("{}: usage (one line, may be empty): ", f.name))?;
                (if d.is_empty() { placeholder } else { d }, u)
            }
            None => (placeholder, String::new()),
        };
        let high_entropy = entry
            .and_then(|e| e.high_entropy)
            .or_else(|| entropy_class(&value))
            .unwrap_or(false);
        items.push(ImportItem {
            meta: SecretMeta {
                name: f.name.clone(),
                description,
                usage,
                projects: entry.map(|e| e.projects.clone()).unwrap_or_default(),
                tags: entry.map(|e| e.tags.clone()).unwrap_or_default(),
                high_entropy,
            },
            value_b64: ValueB64::encode(&value),
        });
    }

    let (view, waited) = submit(ctx, Request::Import { secrets: items }, args.wait)?;

    let approved = view.state == RequestState::Approved;
    let do_shred = approved
        && (args.shred
            || (!args.keep
                && io::stdin().is_terminal()
                && prompt_line(&format!(
                    "overwrite and remove the {} source file(s)? [y/N] ",
                    found.len()
                ))?
                .eq_ignore_ascii_case("y")));
    let mut shredded = Vec::new();
    if do_shred {
        for f in &found {
            match shred(&f.path) {
                Ok(()) => shredded.push(f.path.clone()),
                Err(e) => ctx.info(&format!(
                    "cn: warning: could not remove {}: {e}",
                    f.path.display()
                )),
            }
        }
    } else if !approved || !args.keep {
        ctx.info("source files kept; remove them once the import is approved (--shred)");
    }

    let count = found.len();
    let mut done = report(&view, waited, |_| {
        format!(
            "imported {count} secret{}{}\n",
            if count == 1 { "" } else { "s" },
            if shredded.is_empty() {
                String::new()
            } else {
                format!("; removed {} source file(s)", shredded.len())
            }
        )
    })?;
    if let Done::Report { data, .. } = &mut done {
        data["sources"] = json!(listing);
        data["shredded"] = json!(shredded);
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_drop_the_prefix() {
        assert_eq!(
            name_for(".secret-typesafe-api-key", ".secret-"),
            "typesafe-api-key"
        );
        assert_eq!(name_for("other", ".secret-"), "other");
    }

    #[test]
    fn metadata_files_parse_without_values() {
        let text = r#"
[typesafe-api-key]
description = "Typesafe API, production account"
usage = """
Used by scripts/typesafe_*.py.
"""
projects = ["~/projects/moose/*"]
high_entropy = true

[clickhouse-password]
description = "ClickHouse analytics"
"#;
        let m: BTreeMap<String, MetaEntry> = toml::from_str(text).unwrap();
        assert_eq!(m["typesafe-api-key"].high_entropy, Some(true));
        assert_eq!(m["clickhouse-password"].high_entropy, None);
        assert_eq!(m["clickhouse-password"].projects.len(), 0);
    }
}
