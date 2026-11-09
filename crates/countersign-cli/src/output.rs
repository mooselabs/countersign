//! Output: the `--json` envelope, plain tables, and escaping of text that
//! came from `cnd` or the agent before it reaches a terminal (threat model
//! T17).

use std::io::{self, Write};

use countersign_proto::Timestamp;
use serde_json::Value;

use crate::duration;
use crate::error::CnError;

/// Options every command sees.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// `--json`.
    pub json: bool,
    /// `-q`: no informational lines on stderr.
    pub quiet: bool,
    /// `--socket` (debug builds only).
    #[cfg(debug_assertions)]
    pub socket: Option<std::path::PathBuf>,
}

impl Ctx {
    /// Prints an informational line on stderr unless `--quiet`.
    pub fn info(&self, line: &str) {
        if !self.quiet {
            eprintln!("{line}");
        }
    }
}

/// What a command produced.
pub enum Done {
    /// Print `text` (or the envelope with `data` under `--json`). With a
    /// `failure`, exit with its code; under `--json` the envelope is then
    /// `ok: false` and carries both `data` and `error` (only `cn doctor`
    /// reports this way).
    Report {
        /// The JSON `data`.
        data: Value,
        /// Human output for stdout.
        text: String,
        /// Set when the command ran but its result is a failure.
        failure: Option<CnError>,
    },
    /// The command did its own output; exit with this code.
    Exit(i32),
}

impl Done {
    /// A successful report.
    pub fn ok(data: Value, text: String) -> Self {
        Self::Report {
            data,
            text,
            failure: None,
        }
    }
}

/// Writes text to stdout. A closed stdout (`cn list | head`) is not an
/// error worth reporting, so failures are ignored rather than panicking as
/// `print!` would.
pub fn out(text: &str) {
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

/// Writes the success envelope as one line.
pub fn print_json(data: &Value) {
    println_value(&serde_json::json!({"cn": 1, "ok": true, "data": data}));
}

/// Writes one JSON value as one line on stdout.
pub fn println_value(value: &Value) {
    let mut out = io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, value);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Prints an error: the envelope (on stdout, or stderr when `to_stderr`)
/// under `--json`, else `cn: error[code]: message` and a hint on stderr.
pub fn print_error(json: bool, to_stderr: bool, err: &CnError) {
    if json {
        let line = err.envelope().to_string();
        if to_stderr {
            eprintln!("{line}");
        } else {
            out(&format!("{line}\n"));
        }
        return;
    }
    eprintln!("cn: error[{}]: {}", err.code, clean_line(&err.message));
    if let Some(hint) = &err.hint {
        eprintln!("hint: {}", clean_line(hint));
    }
}

/// Removes characters that could rewrite what a human reads: C0 and C1
/// controls (escape sequences start with ESC or CSI), DEL, and Unicode
/// bidirectional overrides and isolates. Newlines and tabs are kept only
/// when `multiline` is set.
pub fn clean(s: &str, multiline: bool) -> String {
    s.chars()
        .filter_map(|c| match c {
            '\n' | '\t' if multiline => Some(c),
            '\n' | '\t' => Some(' '),
            c if c.is_control() => None,
            '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => None,
            c => Some(c),
        })
        .collect()
}

/// [`clean`] for a single line.
pub fn clean_line(s: &str) -> String {
    clean(s, false)
}

/// [`clean_line`], then in double quotes with `"` and `\` escaped, so
/// agent text cannot close its quotes and pose as the words after it.
pub fn quoted_line(s: &str) -> String {
    let mut out = String::from('"');
    for c in clean_line(s).chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Truncates to at most `max` characters, marking the cut with `...`.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

/// A plain table: columns separated by two spaces, the last unpadded.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let cols = header.len();
    let mut width = vec![0; cols];
    for row in std::iter::once(header.iter().map(|s| (*s).to_owned()).collect())
        .chain(rows.iter().cloned())
    {
        let row: Vec<String> = row;
        for (i, cell) in row.iter().enumerate().take(cols) {
            width[i] = width[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cells: &[String]| {
        let mut l = String::new();
        for (i, cell) in cells.iter().enumerate().take(cols) {
            if i + 1 == cols {
                l.push_str(cell);
            } else {
                l.push_str(cell);
                l.push_str(&" ".repeat(width[i] - cell.chars().count() + 2));
            }
        }
        out.push_str(l.trim_end());
        out.push('\n');
    };
    line(&header.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
    for row in rows {
        line(row);
    }
    out
}

/// `09:51:40` from a timestamp (UTC).
pub fn clock(t: Timestamp) -> String {
    t.to_string()[11..19].to_owned()
}

/// `41m left`-style remaining time, or `expired`.
pub fn left(expires_at: Timestamp) -> String {
    let secs = Timestamp::now().seconds_until(expires_at);
    if secs == 0 {
        "expired".into()
    } else {
        duration::format_short(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_strips_escapes_and_bidi() {
        assert_eq!(clean_line("ok\x1b[31mred\x1b[0m"), "ok[31mred[0m");
        assert_eq!(clean_line("a\u{202e}b\u{2066}c"), "abc");
        assert_eq!(clean_line("two\nlines\ttab"), "two lines tab");
        assert_eq!(clean("two\nlines", true), "two\nlines");
        assert_eq!(clean_line("\u{9b}2J"), "2J");
        assert_eq!(clean_line("héllo €"), "héllo €");
    }

    #[test]
    fn quoted_lines_cannot_close_their_quotes() {
        assert_eq!(quoted_line("~/p"), "\"~/p\"");
        assert_eq!(quoted_line("x\"\n\\"), "\"x\\\" \\\\\"");
    }

    #[test]
    fn tables_align_and_trim() {
        let t = table(
            &["NAME", "GRANT", "DESCRIPTION"],
            &[
                vec!["a".into(), "-".into(), "first".into()],
                vec!["longer-name".into(), "use 41m".into(), "".into()],
            ],
        );
        assert_eq!(
            t,
            "NAME         GRANT    DESCRIPTION\n\
             a            -        first\n\
             longer-name  use 41m\n"
        );
    }

    #[test]
    fn truncate_marks_the_cut() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("0123456789abc", 10), "0123456...");
    }
}
