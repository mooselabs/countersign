//! The daemon log: one line per message on stderr, which systemd sends to
//! the journal. Each line starts with an `sd-daemon(3)` priority prefix
//! (`<3>` error, `<4>` warning, `<6>` info), which journald turns into the
//! entry's priority.
//!
//! Never log a secret value, or anything built from one.

/// Logs an error.
macro_rules! error {
    ($($arg:tt)*) => { eprintln!("<3>{}", format_args!($($arg)*)) };
}

/// Logs a warning.
macro_rules! warning {
    ($($arg:tt)*) => { eprintln!("<4>{}", format_args!($($arg)*)) };
}

/// Logs an informational message.
macro_rules! info {
    ($($arg:tt)*) => { eprintln!("<6>{}", format_args!($($arg)*)) };
}

pub(crate) use {error, info, warning};
