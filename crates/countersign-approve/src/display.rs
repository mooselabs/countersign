//! The strings an approver may show a human, cleaned and length-limited.
//!
//! Every field that reaches a dialog passes through [`clean`]: terminal
//! escape sequences (CSI, OSC, DCS and the rest, 7-bit and C1 forms) are
//! removed whole, control and format characters are removed (this includes
//! Unicode bidi overrides and isolates, zero-width characters and tag
//! characters), line breaks and other spaces become one ASCII space, and long
//! runs of combining marks are cut. Then each field is length-limited as
//! docs/approvers.md says. Limits count Unicode scalar values.
//!
//! Fields an agent chose (reason, cwd, label) are listed in
//! [`DisplayView::agent_supplied`] so a display can label them as the agent's.

use std::time::Duration;

use serde::Serialize;

/// Longest reason shown, in characters.
pub const REASON_LIMIT: usize = 300;
/// Longest cwd shown; longer paths lose their middle. In the session line
/// the cwd is quoted, and the limit counts escapes inside the quotes.
pub const CWD_LIMIT: usize = 120;
/// Longest operation text shown (mutate and export). `cnd` limits each
/// agent-chosen part of it first ([`clean_quoted`]), so one long field
/// cannot push the others out.
pub const OPERATION_LIMIT: usize = 600;
/// Longest matcher text shown in the session line.
pub const MATCHER_LIMIT: usize = 48;
/// Longest single secret name shown: a 64-character name and the
/// " (other project)" `cnd` may add to it.
pub const SECRET_NAME_LIMIT: usize = 80;
/// Secret names listed before "and N more".
pub const SECRETS_SHOWN: usize = 10;
/// Longest secret list ([`DisplayView::secrets_summary`]). The names and
/// their count are bounded so the list never reaches it (a test checks).
pub const SECRETS_LIMIT: usize = 850;
/// Longest session label shown, inside its quotes.
pub const LABEL_LIMIT: usize = 40;
/// Longest session line ([`DisplayView::session`]). Its parts are bounded
/// so it never reaches it (a test checks).
pub const SESSION_LIMIT: usize = 320;
/// Longest anchor `comm` shown (the kernel keeps 15 bytes; this is a backstop).
pub const COMM_LIMIT: usize = 32;

/// Combining marks kept after one base character. More are dropped, so a
/// string cannot stack marks over neighbouring text.
const MAX_COMBINING: usize = 2;

const ELLIPSIS: char = '\u{2026}';

/// Removes escape sequences, control and format characters, and turns line
/// breaks and runs of spaces into one space. Leading and trailing spaces go.
pub fn clean(input: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Text,
        /// After ESC.
        Esc,
        /// ESC followed by intermediate bytes (0x20-0x2F).
        EscIntermediate,
        /// Inside a CSI sequence.
        Csi,
        /// Inside an OSC, DCS, SOS, PM or APC string.
        Str,
        /// ESC inside such a string: `\` ends it, anything else starts a new
        /// escape.
        StrEsc,
    }

    let mut out = Text::default();
    let mut state = State::Text;
    for c in input.chars() {
        // A character may need handling in two states (the end of one escape
        // and the start of the next), so loop until it is consumed.
        let mut ch = Some(c);
        while let Some(c) = ch.take() {
            state = match state {
                State::Text => match c {
                    '\u{1b}' => State::Esc,
                    '\u{9b}' => State::Csi,
                    '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => State::Str,
                    _ => {
                        out.push(c);
                        State::Text
                    }
                },
                State::Esc => match c {
                    '[' => State::Csi,
                    ']' | 'P' | 'X' | '^' | '_' => State::Str,
                    '\u{20}'..='\u{2f}' => State::EscIntermediate,
                    '\u{30}'..='\u{7e}' => State::Text,
                    '\u{1b}' => State::Esc,
                    _ => {
                        ch = Some(c);
                        State::Text
                    }
                },
                State::EscIntermediate => match c {
                    '\u{20}'..='\u{2f}' => State::EscIntermediate,
                    '\u{30}'..='\u{7e}' => State::Text,
                    '\u{1b}' => State::Esc,
                    _ => {
                        ch = Some(c);
                        State::Text
                    }
                },
                State::Csi => match c {
                    '\u{20}'..='\u{3f}' => State::Csi,
                    '\u{40}'..='\u{7e}' => State::Text,
                    '\u{1b}' => State::Esc,
                    _ => {
                        ch = Some(c);
                        State::Text
                    }
                },
                State::Str => match c {
                    '\u{07}' | '\u{9c}' => State::Text,
                    '\u{1b}' => State::StrEsc,
                    _ => State::Str,
                },
                State::StrEsc => match c {
                    '\\' => State::Text,
                    _ => {
                        ch = Some(c);
                        State::Esc
                    }
                },
            };
        }
    }
    // An unterminated string sequence hides the rest of the input. That only
    // hides text from the field's own author.
    out.finish()
}

/// [`clean`], then cut to `limit` characters with a trailing ellipsis.
pub fn clean_limited(input: &str, limit: usize) -> String {
    truncate_end(clean(input), limit)
}

/// [`clean`], then cut to `limit` characters by replacing the middle with an
/// ellipsis. The end is kept longer than the start, which suits paths.
pub fn clean_elided(input: &str, limit: usize) -> String {
    let s = clean(input);
    let n = s.chars().count();
    if n <= limit || limit < 3 {
        return truncate_end(s, limit);
    }
    let head = (limit - 1) / 3;
    let tail = limit - 1 - head;
    let mut out: String = s.chars().take(head).collect();
    out.push(ELLIPSIS);
    out.extend(s.chars().skip(n - tail));
    out
}

fn truncate_end(s: String, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s;
    }
    if limit == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(limit - 1).collect();
    out.truncate(out.trim_end().len());
    out.push(ELLIPSIS);
    out
}

/// [`clean`], then in double quotes with `"` and `\` escaped, so the text
/// cannot close its quotes and pose as the words around it. At most `limit`
/// characters between the quotes, counting escapes; a cut keeps whole
/// escapes, ends with an ellipsis and says how long the text was, so a human
/// sees that something is missing.
pub fn clean_quoted(input: &str, limit: usize) -> String {
    let s = clean(input);
    match escape_within(&s, limit, false) {
        (e, false) => format!("\"{e}\""),
        (e, true) => format!("\"{e}\" (cut from {} characters)", s.chars().count()),
    }
}

/// [`clean_quoted`] without the note: a cut shows only as the ellipsis.
/// For list items and labels, where the note would cost more than the item.
pub fn clean_quoted_item(input: &str, limit: usize) -> String {
    format!("\"{}\"", escape_within(&clean(input), limit, false).0)
}

/// [`clean_quoted_item`], but a cut loses the middle, which suits paths.
pub fn clean_quoted_path(input: &str, limit: usize) -> String {
    format!("\"{}\"", escape_within(&clean(input), limit, true).0)
}

/// How many characters `c` takes between double quotes.
fn quoted_width(c: char) -> usize {
    if matches!(c, '"' | '\\') { 2 } else { 1 }
}

fn push_escaped(out: &mut String, c: char) {
    if matches!(c, '"' | '\\') {
        out.push('\\');
    }
    out.push(c);
}

/// `s` with `"` and `\` escaped, at most `limit` characters. A cut keeps
/// whole escapes and puts an ellipsis at the end, or, with `middle`, in the
/// middle (the end kept longer). True when cut.
fn escape_within(s: &str, limit: usize, middle: bool) -> (String, bool) {
    let mut out = String::new();
    if s.chars().map(quoted_width).sum::<usize>() <= limit {
        s.chars().for_each(|c| push_escaped(&mut out, c));
        return (out, false);
    }
    if limit == 0 {
        return (out, true);
    }
    let budget = limit - 1;
    let (head, tail) = if middle && limit >= 3 {
        (budget / 3, budget - budget / 3)
    } else {
        (budget, 0)
    };
    let mut used = 0;
    for c in s.chars() {
        used += quoted_width(c);
        if used > head {
            break;
        }
        push_escaped(&mut out, c);
    }
    if tail == 0 {
        // Escapes are `\\` and `\"`, never a backslash and a space, so
        // trimming spaces cannot split one.
        out.truncate(out.trim_end().len());
        out.push(ELLIPSIS);
        return (out, true);
    }
    let mut kept = Vec::new();
    let mut used = 0;
    for c in s.chars().rev() {
        used += quoted_width(c);
        if used > tail {
            break;
        }
        kept.push(c);
    }
    out.push(ELLIPSIS);
    kept.into_iter()
        .rev()
        .for_each(|c| push_escaped(&mut out, c));
    (out, true)
}

/// Formats a TTL the way `cn` accepts it: "30m", "1h", "1h30m", "45s".
pub fn format_ttl(ttl: Duration) -> String {
    let secs = ttl.as_secs();
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 || out.is_empty() {
        out.push_str(&format!("{s}s"));
    }
    out
}

/// Output buffer for [`clean`]: applies the per-character rules.
#[derive(Default)]
struct Text {
    out: String,
    pending_space: bool,
    marks: usize,
}

impl Text {
    fn push(&mut self, c: char) {
        if is_space(c) {
            self.pending_space = true;
            self.marks = 0;
            return;
        }
        if is_dropped(c) {
            return;
        }
        if is_combining(c) {
            if self.marks >= MAX_COMBINING {
                return;
            }
            self.marks += 1;
        } else {
            self.marks = 0;
        }
        if self.pending_space && !self.out.is_empty() {
            self.out.push(' ');
        }
        self.pending_space = false;
        self.out.push(c);
    }

    fn finish(self) -> String {
        self.out
    }
}

/// Line breaks, tabs and Unicode space separators: shown as one space.
fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{0b}'
            | '\u{0c}'
            | '\r'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// Characters never shown: controls (Cc), format characters (Cf, which
/// includes the bidi controls, zero-width characters and tag characters),
/// invisible fillers and joiners, variation selectors, private use and
/// noncharacters.
fn is_dropped(c: char) -> bool {
    let u = u32::from(c);
    // Cc: C0, DEL, C1.
    u < 0x20
        || (0x7f..=0x9f).contains(&u)
        // Cf (Unicode 16).
        || matches!(
            u,
            0x00ad
                | 0x0600..=0x0605
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x0890..=0x0891
                | 0x08e2
                | 0x180e
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x2064
                | 0x2066..=0x206f
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd
                | 0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
        )
        // Invisible marks and fillers that are not Cf: combining grapheme
        // joiner, Khmer inherent vowels, Mongolian variation selectors, Hangul
        // fillers, variation selectors.
        || matches!(
            u,
            0x034f
                | 0x17b4..=0x17b5
                | 0x180b..=0x180f
                | 0x115f..=0x1160
                | 0x3164
                | 0xffa0
                | 0xfe00..=0xfe0f
                | 0xe0100..=0xe01ef
        )
        // Private use.
        || (0xe000..=0xf8ff).contains(&u)
        || u >= 0xf0000
        // Noncharacters.
        || (0xfdd0..=0xfdef).contains(&u)
        || (u & 0xfffe) == 0xfffe
}

/// The combining-mark blocks used to stack marks ("zalgo" text).
fn is_combining(c: char) -> bool {
    matches!(
        u32::from(c),
        0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff | 0x20d0..=0x20ff | 0xfe20..=0xfe2f
    )
}

/// How `cnd` found the session a request came from. Read from the kernel
/// and `cnd`'s own tables, never from the client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Found {
    /// An agent session whose anchor `cn session exec` registered.
    #[default]
    Registered,
    /// An agent session whose anchor a configured matcher accepted, e.g.
    /// `comm = "claude"`.
    Matched(String),
    /// No agent anchor above the caller: a terminal (`h_`) session anchored
    /// at the caller's parent, normally a shell.
    Terminal,
}

/// What `cnd` knows about a request, before cleaning. Fields an agent chose
/// are marked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisplayInput {
    /// How the session was found.
    pub found: Found,
    /// The anchor's `comm`, e.g. "claude" (for a terminal session, the
    /// shell's).
    pub anchor_comm: String,
    /// The anchor's pid.
    pub anchor_pid: u32,
    /// Session label (agent-supplied, from `label_env` or `cn session exec`).
    pub label: Option<String>,
    /// The requesting process's working directory (agent-supplied).
    pub cwd: Option<String>,
    /// The developer's home directory; a cwd under it is shown as `~/...`.
    pub home: Option<String>,
    /// Secret names in the request.
    pub secrets: Vec<String>,
    /// Grant TTL, for `use` and `reveal`.
    pub ttl: Option<Duration>,
    /// The agent's reason (agent-supplied).
    pub reason: Option<String>,
    /// For `mutate` and `export`: what changes, written by `cnd`, e.g.
    /// "ADD secret clickhouse-prod (value 16 to 63 bytes, from stdin)".
    /// Names and quoted fields in it come from the client; it is cleaned
    /// like everything else.
    pub operation: Option<String>,
}

/// The cleaned, length-limited strings an approver may show. Built only by
/// [`DisplayView::new`], so every field has been cleaned. An empty field is
/// `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DisplayView {
    session: String,
    secrets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    agent_supplied: Vec<&'static str>,
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

impl DisplayView {
    /// Cleans and limits every field of `input`.
    pub fn new(input: &DisplayInput) -> Self {
        let shown_cwd = input.cwd.as_deref().map(|cwd| match input.home.as_deref() {
            Some(home) if !home.is_empty() && home != "/" => {
                let home = home.trim_end_matches('/');
                match cwd.strip_prefix(home) {
                    Some("") => "~".to_string(),
                    Some(rest) if rest.starts_with('/') => format!("~{rest}"),
                    _ => cwd.to_string(),
                }
            }
            _ => cwd.to_string(),
        });
        let cwd = shown_cwd
            .as_deref()
            .map(|c| clean_elided(c, CWD_LIMIT))
            .and_then(non_empty);
        let label = input
            .label
            .as_deref()
            .map(|l| clean_limited(l, LABEL_LIMIT))
            .and_then(non_empty);
        let reason = input
            .reason
            .as_deref()
            .map(|r| clean_limited(r, REASON_LIMIT))
            .and_then(non_empty);
        let operation = input
            .operation
            .as_deref()
            .map(|o| clean_limited(o, OPERATION_LIMIT))
            .and_then(non_empty);
        let secrets = input
            .secrets
            .iter()
            .map(|s| clean_limited(s, SECRET_NAME_LIMIT))
            .filter(|s| !s.is_empty())
            .collect();

        let mut comm = clean_limited(&input.anchor_comm, COMM_LIMIT);
        if comm.is_empty() {
            comm = "unknown".into();
        }
        let pid = input.anchor_pid;
        let (mut session, reporter) = match &input.found {
            Found::Registered => (
                format!("agent {comm} (pid {pid}, registered by cn session exec)"),
                "agent-reported",
            ),
            Found::Matched(m) => (
                format!(
                    "agent {comm} (pid {pid}, matched {})",
                    clean_limited(m, MATCHER_LIMIT)
                ),
                "agent-reported",
            ),
            Found::Terminal => (
                format!("terminal, no agent session (shell {comm}, pid {pid})"),
                "client-reported",
            ),
        };
        let mut reported = Vec::new();
        // Both quoted, so neither can pose as the text after it: the cwd
        // after the label, and the "Agent's reason:" the polkit message puts
        // after the session line.
        if label.is_some() {
            let quoted = clean_quoted_item(input.label.as_deref().unwrap_or(""), LABEL_LIMIT);
            reported.push(format!("label {quoted}"));
        }
        if cwd.is_some() {
            let quoted = clean_quoted_path(shown_cwd.as_deref().unwrap_or(""), CWD_LIMIT);
            reported.push(format!("cwd {quoted}"));
        }
        if !reported.is_empty() {
            session.push_str(&format!("; {reporter}: {}", reported.join(", ")));
        }
        debug_assert!(session.chars().count() <= SESSION_LIMIT, "{session}");

        let mut agent_supplied = Vec::new();
        if reason.is_some() {
            agent_supplied.push("reason");
        }
        if cwd.is_some() {
            agent_supplied.push("cwd");
        }
        if label.is_some() {
            agent_supplied.push("label");
        }

        Self {
            session,
            secrets,
            ttl_seconds: input.ttl.map(|t| t.as_secs()),
            ttl: input.ttl.map(format_ttl),
            cwd,
            label,
            reason,
            operation,
            agent_supplied,
        }
    }

    /// Who is asking: "agent claude (pid 41210, registered by cn session
    /// exec); agent-reported: label "x", cwd "~/projects/x"". What `cnd`
    /// found comes first; the client's label and cwd follow, quoted and
    /// marked as reported.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Every secret name, cleaned.
    pub fn secrets(&self) -> &[String] {
        &self.secrets
    }

    /// Up to ten names, then "and N more". Empty when there are none.
    pub fn secrets_summary(&self) -> String {
        let shown = self.secrets.len().min(SECRETS_SHOWN);
        let mut out = self.secrets[..shown].join(", ");
        if self.secrets.len() > shown {
            out.push_str(&format!(" and {} more", self.secrets.len() - shown));
        }
        debug_assert!(out.chars().count() <= SECRETS_LIMIT, "{out}");
        out
    }

    /// The TTL, formatted ("30m").
    pub fn ttl(&self) -> Option<&str> {
        self.ttl.as_deref()
    }

    /// The TTL in seconds.
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl_seconds
    }

    /// The working directory, `~`-abbreviated and middle-elided.
    /// Agent-supplied.
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    /// The session label. Agent-supplied.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The agent's reason. Agent-supplied: show it as "Agent's reason: ...".
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// What a mutate or export changes.
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }

    /// Names of the fields present that an agent chose: a subset of
    /// "reason", "cwd", "label".
    pub fn agent_supplied(&self) -> &[&'static str] {
        &self.agent_supplied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_kept() {
        assert_eq!(
            clean("row counts for the cost report"),
            "row counts for the cost report"
        );
        assert_eq!(clean("Zürich 東京 café"), "Zürich 東京 café");
        assert_eq!(clean(""), "");
    }

    #[test]
    fn csi_sequences_are_removed_whole() {
        assert_eq!(clean("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(clean("a\x1b[1;31;48;5;196mb"), "ab");
        assert_eq!(clean("\x1b[2J\x1b[Hcleared"), "cleared");
        assert_eq!(clean("\x1b[?25lhidden cursor"), "hidden cursor");
        // C1 CSI.
        assert_eq!(clean("\u{9b}31mX"), "X");
        // Cursor movement used to overwrite earlier text.
        assert_eq!(clean("deny\x1b[4Dallow"), "denyallow");
    }

    #[test]
    fn osc_and_other_strings_are_removed_whole() {
        // Hyperlink, BEL-terminated.
        assert_eq!(
            clean("\x1b]8;;https://evil.example\x07click\x1b]8;;\x07"),
            "click"
        );
        // Title, ST-terminated.
        assert_eq!(clean("\x1b]0;title\x1b\\text"), "text");
        // C1 OSC and C1 ST.
        assert_eq!(clean("a\u{9d}0;t\u{9c}b"), "ab");
        // DCS, APC, PM, SOS.
        assert_eq!(clean("a\x1bPq#0;2;0;0;0\x1b\\b"), "ab");
        assert_eq!(
            clean("a\x1b_apc\x1b\\b\x1b^pm\x1b\\c\x1bXsos\x1b\\d"),
            "abcd"
        );
        // Unterminated: the rest is hidden.
        assert_eq!(clean("safe\x1b]0;rest of it"), "safe");
        // ESC inside a string that is not ST starts a new escape.
        assert_eq!(clean("a\x1b]0;x\x1b[31mb"), "ab");
    }

    #[test]
    fn short_escapes_are_removed() {
        assert_eq!(clean("a\x1bcb"), "ab"); // reset
        assert_eq!(clean("a\x1b7b\x1b8c"), "abc"); // save/restore cursor
        assert_eq!(clean("a\x1b(Bb"), "ab"); // charset
        assert_eq!(clean("a\x1b#8b"), "ab");
        assert_eq!(clean("end\x1b"), "end");
        assert_eq!(clean("\x1b\x1b[0mx"), "x");
        // ESC followed by a non-ASCII character: ESC dropped, character kept.
        assert_eq!(clean("a\x1bé"), "aé");
    }

    #[test]
    fn controls_are_removed() {
        assert_eq!(clean("a\0b\x07c\x08d\x7fe"), "abcde");
        assert_eq!(clean("a\u{80}b\u{8f}c"), "abc");
    }

    #[test]
    fn line_breaks_and_spaces_collapse() {
        assert_eq!(clean("a\nb\r\nc"), "a b c");
        assert_eq!(clean("  lead\t\ttrail \n"), "lead trail");
        assert_eq!(clean("Approve?\n\n\n\nYes"), "Approve? Yes");
        assert_eq!(clean("a\u{2028}b\u{2029}c\u{85}d"), "a b c d");
        assert_eq!(clean("a\u{a0}\u{3000}\u{2003}b"), "a b");
    }

    #[test]
    fn bidi_controls_are_removed() {
        // RLO would show "secret-txt.exe" as "secret-exe.txt".
        assert_eq!(clean("secret-\u{202e}txt.exe"), "secret-txt.exe");
        for c in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}', '\u{200e}', '\u{200f}', '\u{61c}',
        ] {
            assert_eq!(clean(&format!("a{c}b")), "ab", "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn invisible_format_characters_are_removed() {
        assert_eq!(clean("cl\u{200b}au\u{200c}d\u{200d}e"), "claude");
        assert_eq!(clean("\u{feff}bom"), "bom");
        assert_eq!(clean("soft\u{ad}hyphen"), "softhyphen");
        assert_eq!(clean("word\u{2060}joiner"), "wordjoiner");
        // Tag characters can carry hidden ASCII ("ASCII smuggling").
        assert_eq!(clean("hi\u{e0001}\u{e0041}\u{e0042}\u{e007f}"), "hi");
        assert_eq!(clean("a\u{fe0f}b\u{e0100}c"), "abc");
        assert_eq!(clean("a\u{3164}b\u{115f}c"), "abc");
        assert_eq!(clean("a\u{e000}b\u{f0000}c"), "abc");
        assert_eq!(clean("a\u{fffe}b\u{fdd0}c\u{1ffff}d"), "abcd");
        assert_eq!(clean("a\u{34f}b"), "ab");
    }

    #[test]
    fn combining_mark_runs_are_cut() {
        let zalgo = format!("a{}b", "\u{301}".repeat(50));
        assert_eq!(clean(&zalgo), "a\u{301}\u{301}b");
        // Ordinary accents survive.
        assert_eq!(clean("e\u{301}te\u{301}"), "e\u{301}te\u{301}");
    }

    #[test]
    fn limits_cut_with_an_ellipsis() {
        let long = "a".repeat(400);
        let cut = clean_limited(&long, REASON_LIMIT);
        assert_eq!(cut.chars().count(), REASON_LIMIT);
        assert!(cut.ends_with('\u{2026}'));
        assert_eq!(clean_limited("short", 300), "short");
        // Counted in characters, never splitting one.
        let wide = "東".repeat(400);
        assert_eq!(clean_limited(&wide, 10).chars().count(), 10);
        // A cut does not leave a space before the ellipsis.
        assert_eq!(clean_limited("abc def", 5), "abc\u{2026}");
        // Limits apply after cleaning: escapes do not use up the budget.
        let padded = format!("{}ok", "\x1b[0m".repeat(500));
        assert_eq!(clean_limited(&padded, 10), "ok");
    }

    #[test]
    fn cwd_loses_its_middle() {
        let path = format!("/home/p/{}/end-of-path", "x".repeat(300));
        let shown = clean_elided(&path, CWD_LIMIT);
        assert_eq!(shown.chars().count(), CWD_LIMIT);
        assert!(shown.starts_with("/home/p/"));
        assert!(shown.ends_with("/end-of-path"));
        assert_eq!(shown.matches('\u{2026}').count(), 1);
        assert_eq!(clean_elided("/short", CWD_LIMIT), "/short");
    }

    #[test]
    fn ttl_formats() {
        assert_eq!(format_ttl(Duration::from_secs(1800)), "30m");
        assert_eq!(format_ttl(Duration::from_secs(3600)), "1h");
        assert_eq!(format_ttl(Duration::from_secs(5400)), "1h30m");
        assert_eq!(format_ttl(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_ttl(Duration::from_secs(0)), "0s");
        assert_eq!(format_ttl(Duration::from_secs(8 * 3600 + 5)), "8h5s");
    }

    fn input() -> DisplayInput {
        DisplayInput {
            found: Found::Registered,
            anchor_comm: "claude".into(),
            anchor_pid: 41210,
            label: None,
            cwd: Some("/home/patrick/projects/x".into()),
            home: Some("/home/patrick".into()),
            secrets: vec!["clickhouse-password".into()],
            ttl: Some(Duration::from_secs(1800)),
            reason: Some("row counts".into()),
            operation: None,
        }
    }

    #[test]
    fn view_builds_the_session_line() {
        let v = DisplayView::new(&input());
        assert_eq!(
            v.session(),
            "agent claude (pid 41210, registered by cn session exec); agent-reported: cwd \"~/projects/x\""
        );
        assert_eq!(v.cwd(), Some("~/projects/x"));
        assert_eq!(v.ttl(), Some("30m"));
        assert_eq!(v.ttl_seconds(), Some(1800));
        assert_eq!(v.secrets_summary(), "clickhouse-password");
        assert_eq!(v.agent_supplied(), ["reason", "cwd"]);

        let mut i = input();
        i.label = Some("orch\nestrator".into());
        i.cwd = None;
        let v = DisplayView::new(&i);
        assert_eq!(
            v.session(),
            "agent claude (pid 41210, registered by cn session exec); agent-reported: label \"orch estrator\""
        );
        assert_eq!(v.agent_supplied(), ["reason", "label"]);
    }

    #[test]
    fn the_session_line_says_how_the_session_was_found() {
        let mut i = input();
        i.found = Found::Matched("comm = \"claude\"\n".into());
        assert_eq!(
            DisplayView::new(&i).session(),
            "agent claude (pid 41210, matched comm = \"claude\"); agent-reported: cwd \"~/projects/x\""
        );
        i.found = Found::Terminal;
        i.anchor_comm = "bash".into();
        i.anchor_pid = 3001;
        assert_eq!(
            DisplayView::new(&i).session(),
            "terminal, no agent session (shell bash, pid 3001); client-reported: cwd \"~/projects/x\""
        );
        // A label cannot pose as what cnd found: it comes after, marked.
        i.found = Found::Registered;
        i.cwd = None;
        i.label = Some("registered by cn session exec)".into());
        assert!(
            DisplayView::new(&i)
                .session()
                .ends_with("; agent-reported: label \"registered by cn session exec)\"")
        );
        // Nor as the cwd: it is quoted, and its quotes are escaped.
        i.cwd = Some("/home/patrick/projects/x".into());
        i.label = Some("x\", cwd ~/safe".into());
        assert_eq!(
            DisplayView::new(&i).session(),
            "agent bash (pid 3001, registered by cn session exec); agent-reported: \
             label \"x\\\", cwd ~/safe\", cwd \"~/projects/x\""
        );
    }

    #[test]
    fn a_cwd_cannot_pose_as_the_reason() {
        // The polkit message is "... $(session). Agent's reason: $(reason)".
        let mut i = input();
        i.cwd = Some("x. Agent's reason: rotate test fixtures".into());
        let v = DisplayView::new(&i);
        assert_eq!(
            v.session(),
            "agent claude (pid 41210, registered by cn session exec); agent-reported: \
             cwd \"x. Agent's reason: rotate test fixtures\""
        );
        // Nor can it close its quotes, before or after a cut.
        for cwd in [
            "x\". Agent's reason: rotate test fixtures".to_string(),
            format!(
                "{}\". Agent's reason: rotate test fixtures",
                "\\".repeat(300)
            ),
        ] {
            i.cwd = Some(cwd);
            let v = DisplayView::new(&i);
            let quoted = v.session().split_once("; agent-reported: cwd ").unwrap().1;
            let body = inner(quoted).unwrap_or_else(|| panic!("{quoted}"));
            assert_eq!(body.len() + 2, quoted.len(), "{quoted}");
            assert!(body.chars().count() <= CWD_LIMIT, "{quoted}");
        }
    }

    #[test]
    fn quoted_fields_say_when_they_were_cut() {
        assert_eq!(clean_quoted("a\nb", 10), "\"a b\"");
        assert_eq!(
            clean_quoted(&"x".repeat(50), 10),
            format!("\"{}\u{2026}\" (cut from 50 characters)", "x".repeat(9))
        );
        assert_eq!(
            clean_quoted_item(&"x".repeat(50), 10),
            format!("\"{}\u{2026}\"", "x".repeat(9))
        );
        assert_eq!(clean_quoted_item("short", 10), "\"short\"");
        // A path loses its middle.
        assert_eq!(
            clean_quoted_path("~/projects/moose/countersign", 16),
            "\"~/pro\u{2026}ountersign\""
        );
    }

    /// The text between the outer quotes of `quoted`, which must start with
    /// `"`; None if a `"` inside is not escaped.
    fn inner(quoted: &str) -> Option<&str> {
        let body = quoted.strip_prefix('"')?;
        let mut escaped = false;
        for (i, c) in body.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => return Some(&body[..i]),
                _ => {}
            }
        }
        None
    }

    #[test]
    fn quotes_and_backslashes_are_escaped() {
        assert_eq!(
            clean_quoted("ok\"; high entropy off \\ x", 60),
            "\"ok\\\"; high entropy off \\\\ x\""
        );
        // A cut keeps whole escapes and counts them.
        assert_eq!(
            clean_quoted(&"\"".repeat(50), 10),
            "\"\\\"\\\"\\\"\\\"\u{2026}\" (cut from 50 characters)"
        );
        assert_eq!(clean_quoted_item("a\\", 2), "\"a\u{2026}\"");
        assert_eq!(clean_quoted_item("\\a", 2), "\"\u{2026}\"");
        assert_eq!(clean_quoted_item("a\\", 3), "\"a\\\\\"");
    }

    #[test]
    fn a_quoted_field_cannot_close_its_quotes() {
        let spoofs = [
            "ok\"; high entropy off (cn hide matches it only when granted",
            "\\\"",
            "x\\",
            "\\",
            "\"",
            "a\\\\\"b\"c\\",
            "\u{201d}\u{ff02}\"",
        ];
        for spoof in spoofs {
            for n in 1..8 {
                let text = spoof.repeat(n);
                for limit in 0..40 {
                    for q in [
                        clean_quoted(&text, limit),
                        clean_quoted_item(&text, limit),
                        clean_quoted_path(&text, limit),
                    ] {
                        let body = inner(&q).unwrap_or_else(|| panic!("{q}"));
                        assert!(body.chars().count() <= limit, "{q}");
                        let rest = &q[body.len() + 2..];
                        assert!(rest.is_empty() || rest.starts_with(" (cut from "), "{q}");
                    }
                }
            }
        }
    }

    #[test]
    fn the_session_line_and_secret_list_stay_under_their_limits() {
        // Plain text fills a quoted limit exactly; escapes may leave one
        // character over. Both are tried.
        let worst = |found: Found, fill: &str| DisplayInput {
            found,
            anchor_comm: "c".repeat(100),
            anchor_pid: u32::MAX,
            label: Some(fill.repeat(200)),
            cwd: Some(fill.repeat(500)),
            home: None,
            secrets: (0..1000)
                .map(|n| format!("{:064} (other project)", n))
                .collect(),
            ttl: None,
            reason: None,
            operation: None,
        };
        let mut longest = 0;
        for found in [
            Found::Registered,
            Found::Matched("m".repeat(100)),
            Found::Terminal,
        ] {
            for fill in ["\"", "x", "\\x"] {
                let v = DisplayView::new(&worst(found.clone(), fill));
                longest = longest.max(v.session().chars().count());
                // The marker cnd adds survives the name limit.
                assert!(v.secrets()[0].ends_with(" (other project)"));
                // A count of usize::MAX would add 16 digits.
                assert!(v.secrets_summary().chars().count() + 16 < SECRETS_LIMIT);
            }
        }
        // "agent " + comm 32 + " (pid 4294967295, matched " + matcher 48
        // + ")" is 113; "; agent-reported: " 18; "label " and the label
        // in quotes 6 + 42; ", cwd " and the cwd in quotes 6 + 122.
        assert_eq!(longest, 113 + 18 + 48 + 128);
        assert!(longest < SESSION_LIMIT, "{longest}");
    }

    #[test]
    fn home_abbreviation_needs_a_path_boundary() {
        let mut i = input();
        i.cwd = Some("/home/patrickx/p".into());
        assert_eq!(DisplayView::new(&i).cwd(), Some("/home/patrickx/p"));
        i.cwd = Some("/home/patrick".into());
        assert_eq!(DisplayView::new(&i).cwd(), Some("~"));
        i.home = Some("/home/patrick/".into());
        i.cwd = Some("/home/patrick/a".into());
        assert_eq!(DisplayView::new(&i).cwd(), Some("~/a"));
        i.home = Some("/".into());
        assert_eq!(DisplayView::new(&i).cwd(), Some("/home/patrick/a"));
    }

    #[test]
    fn secrets_list_stops_at_ten() {
        let mut i = input();
        i.secrets = (0..15).map(|n| format!("s{n}")).collect();
        let v = DisplayView::new(&i);
        assert_eq!(
            v.secrets_summary(),
            "s0, s1, s2, s3, s4, s5, s6, s7, s8, s9 and 5 more"
        );
        i.secrets = (0..10).map(|n| format!("s{n}")).collect();
        assert!(!DisplayView::new(&i).secrets_summary().contains("more"));
        i.secrets = vec![];
        assert_eq!(DisplayView::new(&i).secrets_summary(), "");
    }

    #[test]
    fn adversarial_fields_are_cleaned() {
        let mut i = input();
        i.anchor_comm = "\x1b[2Jclaude\u{202e}".into();
        i.reason = Some(
            "fine\n\nAPPROVED BY ADMIN\x1b[8m hidden \x1b]8;;https://x\x07link\x1b]8;;\x07".into(),
        );
        i.secrets = vec![
            "prod\u{200b}-db\nx".into(),
            "\u{200b}".into(),
            "y".repeat(100),
        ];
        i.cwd = Some("/tmp/\x1b[31mred\u{2066}".into());
        i.operation = Some("ADD\rsecret".into());
        let v = DisplayView::new(&i);
        assert_eq!(
            v.session(),
            "agent claude (pid 41210, registered by cn session exec); agent-reported: cwd \"/tmp/red\""
        );
        assert_eq!(v.reason(), Some("fine APPROVED BY ADMIN hidden link"));
        assert_eq!(v.secrets()[0], "prod-db x");
        // A name that cleans to nothing is dropped.
        assert_eq!(v.secrets().len(), 2);
        assert_eq!(v.secrets()[1].chars().count(), SECRET_NAME_LIMIT);
        assert_eq!(v.operation(), Some("ADD secret"));
        for s in [v.session(), v.reason().unwrap(), &v.secrets_summary()] {
            assert!(s.chars().all(|c| !c.is_control()), "{s:?}");
        }
    }

    #[test]
    fn empty_fields_become_none() {
        let mut i = input();
        i.reason = Some("\n\x1b[0m\u{200b} ".into());
        i.cwd = Some(String::new());
        i.anchor_comm = "\x07".into();
        let v = DisplayView::new(&i);
        assert_eq!(v.reason(), None);
        assert_eq!(v.cwd(), None);
        assert_eq!(
            v.session(),
            "agent unknown (pid 41210, registered by cn session exec)"
        );
        assert!(v.agent_supplied().is_empty());
    }

    #[test]
    fn view_serialises_with_agent_markers() {
        let v = DisplayView::new(&input());
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "session": "agent claude (pid 41210, registered by cn session exec); agent-reported: cwd \"~/projects/x\"",
                "secrets": ["clickhouse-password"],
                "ttl_seconds": 1800,
                "ttl": "30m",
                "cwd": "~/projects/x",
                "reason": "row counts",
                "agent_supplied": ["reason", "cwd"],
            })
        );
    }
}
