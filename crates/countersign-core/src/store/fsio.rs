//! Crash-safe file replacement.
//!
//! [`replace`] writes `NAME` so that at every instant `NAME` is either the
//! complete old file or the complete new one:
//!
//! 1. Write `NAME.tmp` (mode 0600) and `fsync` it.
//! 2. With `keep_prev`, hard-link the current `NAME` to `NAME.prev.tmp` and
//!    rename that over `NAME.prev`.
//! 3. Rename `NAME.tmp` over `NAME`.
//! 4. `fsync` the directory.
//!
//! design.md section 3 renames `NAME` to `NAME.prev` before renaming the new
//! file in, which leaves a moment with no `NAME`. The hard link keeps the
//! same `.prev` result without that gap.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The steps of [`replace`], for failure injection in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    WriteTmp,
    LinkPrev,
    Rename,
    SyncDir,
}

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_AT: std::cell::Cell<Option<Step>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn failpoint(step: Step) -> io::Result<()> {
    // One shot: the failure fires once, so recovery code can run after it.
    if FAIL_AT.with(|f| f.get()) == Some(step) {
        FAIL_AT.with(|f| f.set(None));
        return Err(io::Error::other(format!("injected failure at {step:?}")));
    }
    Ok(())
}

#[cfg(not(test))]
#[inline(always)]
fn failpoint(_: Step) -> io::Result<()> {
    Ok(())
}

/// Atomically replaces `dir/name` with `bytes` (mode 0600). With `keep_prev`
/// the old file, if any, is kept as `dir/name.prev`.
pub(crate) fn replace(dir: &Path, name: &str, bytes: &[u8], keep_prev: bool) -> io::Result<()> {
    let target = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        failpoint(Step::WriteTmp)?;
        f.sync_all()?;
    }
    if keep_prev && target.exists() {
        let prev_tmp = dir.join(format!("{name}.prev.tmp"));
        match fs::remove_file(&prev_tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        fs::hard_link(&target, &prev_tmp)?;
        failpoint(Step::LinkPrev)?;
        fs::rename(&prev_tmp, dir.join(format!("{name}.prev")))?;
    }
    failpoint(Step::Rename)?;
    fs::rename(&tmp, &target)?;
    failpoint(Step::SyncDir)?;
    File::open(dir)?.sync_all()
}

/// Creates `dir` with mode 0700 if it does not exist.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(dir)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replace_keeps_prev_and_sets_mode() {
        let dir = tempfile::tempdir().unwrap();
        replace(dir.path(), "f", b"one", true).unwrap();
        assert!(!dir.path().join("f.prev").exists());
        replace(dir.path(), "f", b"two", true).unwrap();
        assert_eq!(fs::read(dir.path().join("f")).unwrap(), b"two");
        assert_eq!(fs::read(dir.path().join("f.prev")).unwrap(), b"one");
        let mode = fs::metadata(dir.path().join("f"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!dir.path().join("f.tmp").exists());
        assert!(!dir.path().join("f.prev.tmp").exists());
    }

    #[test]
    fn a_failure_at_any_step_leaves_a_whole_file() {
        for step in [Step::WriteTmp, Step::LinkPrev, Step::Rename, Step::SyncDir] {
            let dir = tempfile::tempdir().unwrap();
            replace(dir.path(), "f", b"old", true).unwrap();
            FAIL_AT.with(|f| f.set(Some(step)));
            let r = replace(dir.path(), "f", b"new", true);
            FAIL_AT.with(|f| f.set(None));
            assert!(r.is_err(), "{step:?}");
            let now = fs::read(dir.path().join("f")).unwrap();
            // Before the rename the old file is in place; after it, the new.
            let expect: &[u8] = if step == Step::SyncDir {
                b"new"
            } else {
                b"old"
            };
            assert_eq!(now, expect, "{step:?}");
            // A retry after any failure succeeds and cleans up.
            replace(dir.path(), "f", b"newer", true).unwrap();
            assert_eq!(fs::read(dir.path().join("f")).unwrap(), b"newer");
            assert!(!dir.path().join("f.tmp").exists());
        }
    }
}
