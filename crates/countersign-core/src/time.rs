//! Clocks, durations like `1h30m`, byte sizes like `256MiB`, and RFC 3339.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// A source of the current time. Injected so tests are deterministic.
pub trait Clock: Send + Sync {
    /// The current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that moves only when told to. For tests.
#[derive(Debug)]
pub struct ManualClock(Mutex<SystemTime>);

impl ManualClock {
    /// A clock stopped at `at`.
    pub fn new(at: SystemTime) -> Self {
        Self(Mutex::new(at))
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        let mut t = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *t += by;
    }

    /// Sets the clock.
    pub fn set(&self, at: SystemTime) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = at;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now(&self) -> SystemTime {
        (**self).now()
    }
}

/// A string that is not a duration or size.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a valid {1} (examples: {2})")]
pub struct ParseError(String, &'static str, &'static str);

/// Parses a duration such as `90s`, `30m`, `1h30m`, `8h` or `400d`.
///
/// Units are `d`, `h`, `m` and `s`, largest first, each at most once. Zero is
/// allowed here; callers that need a positive duration check it.
pub fn parse_duration(s: &str) -> Result<Duration, ParseError> {
    let err = || ParseError(s.to_owned(), "duration", "90s, 30m, 1h30m, 8h");
    const UNITS: [(u8, u64); 4] = [(b'd', 86_400), (b'h', 3600), (b'm', 60), (b's', 1)];
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(err());
    }
    let (mut i, mut total, mut next_unit) = (0, 0u64, 0);
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || i == bytes.len() || i - start > 9 {
            return Err(err());
        }
        let n: u64 = s[start..i].parse().map_err(|_| err())?;
        let pos = UNITS[next_unit..]
            .iter()
            .position(|&(u, _)| u == bytes[i])
            .ok_or_else(err)?;
        let (_, secs) = UNITS[next_unit + pos];
        next_unit += pos + 1;
        total = total.checked_add(n * secs).ok_or_else(err)?;
        i += 1;
    }
    Ok(Duration::from_secs(total))
}

/// Formats a duration in the form [`parse_duration`] reads, e.g. `1h30m`.
pub fn format_duration(d: Duration) -> String {
    let mut s = d.as_secs();
    if s == 0 {
        return "0s".into();
    }
    let mut out = String::new();
    for (unit, secs) in [("d", 86_400), ("h", 3600), ("m", 60), ("s", 1)] {
        if s >= secs {
            out.push_str(&format!("{}{unit}", s / secs));
            s %= secs;
        }
    }
    out
}

/// Parses a byte size such as `256MiB`, `64KiB`, `1GiB` or `4096` (bytes).
pub fn parse_size(s: &str) -> Result<u64, ParseError> {
    let err = || ParseError(s.to_owned(), "size", "4096, 64KiB, 256MiB");
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > 12 {
        return Err(err());
    }
    let n: u64 = s[..digits].parse().map_err(|_| err())?;
    let mult = match &s[digits..] {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        _ => return Err(err()),
    };
    n.checked_mul(mult).ok_or_else(err)
}

/// Formats a time as RFC 3339 UTC with microseconds, as audit records use.
pub fn format_rfc3339_micros(t: SystemTime) -> String {
    humantime::format_rfc3339_micros(t).to_string()
}

/// Formats a time as RFC 3339 UTC with whole seconds.
pub fn format_rfc3339(t: SystemTime) -> String {
    humantime::format_rfc3339_seconds(t).to_string()
}

/// Parses an RFC 3339 UTC time (`Z` suffix, optional fraction).
pub fn parse_rfc3339(s: &str) -> Result<SystemTime, ParseError> {
    humantime::parse_rfc3339(s)
        .map_err(|_| ParseError(s.to_owned(), "time", "2026-11-08T09:20:11Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_duration("1h30m"), Ok(Duration::from_secs(5400)));
        assert_eq!(
            parse_duration("400d"),
            Ok(Duration::from_secs(400 * 86_400))
        );
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
        for bad in [
            "",
            "1",
            "h",
            "1x",
            "30m1h",
            "1h1h",
            "1 h",
            "-1s",
            "1.5h",
            "9999999999s",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn durations_round_trip() {
        for secs in [0, 1, 59, 60, 61, 3599, 3600, 5400, 86_400, 90_061] {
            let d = Duration::from_secs(secs);
            assert_eq!(parse_duration(&format_duration(d)), Ok(d), "{secs}");
        }
        assert_eq!(format_duration(Duration::from_secs(5400)), "1h30m");
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("256MiB"), Ok(256 << 20));
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size("1GiB"), Ok(1 << 30));
        for bad in ["", "MiB", "1MB", "1 MiB", "-1"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rfc3339_round_trips() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_micros(1_762_593_601_120_044);
        let s = format_rfc3339_micros(t);
        assert_eq!(s, "2025-11-08T09:20:01.120044Z");
        assert_eq!(parse_rfc3339(&s), Ok(t));
        assert!(parse_rfc3339("yesterday").is_err());
    }
}
