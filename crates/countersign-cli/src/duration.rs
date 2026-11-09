//! Durations as `cn` reads and writes them: `90s`, `30m`, `1h`, `1h30m`, `8h`.

use std::fmt;
use std::str::FromStr;

/// A duration in whole seconds, parsed from `1h30m`-style text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secs(pub u64);

impl FromStr for Secs {
    type Err = String;

    /// Accepts one or more `<number><unit>` parts with units `d`, `h`, `m`,
    /// `s`, largest first, or a bare number of seconds.
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("not a duration: {s:?} (expected e.g. 90s, 30m, 1h30m)");
        if s.is_empty() {
            return Err(bad());
        }
        if s.bytes().all(|b| b.is_ascii_digit()) {
            return s.parse().map(Secs).map_err(|_| bad());
        }
        let mut total: u64 = 0;
        let mut number: Option<u64> = None;
        let mut last_unit = u64::MAX;
        for c in s.chars() {
            if let Some(d) = c.to_digit(10) {
                let n = number.unwrap_or(0);
                number = Some(
                    n.checked_mul(10)
                        .and_then(|n| n.checked_add(u64::from(d)))
                        .ok_or_else(bad)?,
                );
                continue;
            }
            let unit = match c {
                'd' => 86_400,
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return Err(bad()),
            };
            if unit >= last_unit {
                return Err(bad());
            }
            last_unit = unit;
            let n = number.take().ok_or_else(bad)?;
            total = n
                .checked_mul(unit)
                .and_then(|v| total.checked_add(v))
                .ok_or_else(bad)?;
        }
        if number.is_some() {
            return Err(bad());
        }
        Ok(Secs(total))
    }
}

impl fmt::Display for Secs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format(self.0))
    }
}

/// Exact form: `1h30m`, `5m`, `90s` becomes `1m30s`, `0s`.
pub fn format(secs: u64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let mut out = String::new();
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 {
        out.push_str(&format!("{s}s"));
    }
    out
}

/// Rounded form for "time left": `45s`, `41m`, `2h05m`.
pub fn format_short(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        _ => format!("{}h{:02}m", secs / 3600, secs / 60 % 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_forms() {
        for (text, secs) in [
            ("90s", 90),
            ("30m", 1800),
            ("1h", 3600),
            ("1h30m", 5400),
            ("8h", 28_800),
            ("1d2h", 93_600),
            ("120", 120),
            ("0s", 0),
        ] {
            assert_eq!(text.parse::<Secs>(), Ok(Secs(secs)), "{text}");
        }
    }

    #[test]
    fn rejects_malformed_durations() {
        for bad in [
            "",
            "m",
            "1x",
            "30m1h",
            "1h1h",
            "1h30",
            "1.5h",
            "-1m",
            "1h 30m",
            "99999999999999999999d",
        ] {
            assert!(bad.parse::<Secs>().is_err(), "{bad}");
        }
    }

    #[test]
    fn formats() {
        assert_eq!(format(0), "0s");
        assert_eq!(format(90), "1m30s");
        assert_eq!(format(1800), "30m");
        assert_eq!(format(5400), "1h30m");
        assert_eq!(format_short(45), "45s");
        assert_eq!(format_short(2460), "41m");
        assert_eq!(format_short(7500), "2h05m");
    }
}
