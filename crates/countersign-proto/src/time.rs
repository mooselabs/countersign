//! Times on the wire.
//!
//! Every time in the protocol is an RFC 3339 UTC string with whole seconds,
//! `YYYY-MM-DDTHH:MM:SSZ`. [`Timestamp`] always writes that one form, so `cn`
//! and `cnd` produce the same bytes for the canonical request. When parsing it
//! also accepts a fraction (dropped) and a numeric offset (applied), so a
//! human can type `2026-11-08T10:25:11+01:00` into `cn audit --since`.
//! Durations are integer seconds in fields ending `_seconds`.

use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A point in time: whole seconds since the Unix epoch, UTC. Years 0000 to
/// 9999 format and parse; nothing else is meaningful on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

/// A string that is not an RFC 3339 time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an RFC 3339 time (expected e.g. 2026-11-08T09:25:11Z)")]
pub struct BadTimestamp;

impl Timestamp {
    /// From seconds since the Unix epoch.
    pub const fn from_unix(secs: i64) -> Self {
        Self(secs)
    }

    /// Seconds since the Unix epoch.
    pub const fn unix(self) -> i64 {
        self.0
    }

    /// The current time, truncated to whole seconds.
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    /// From a [`SystemTime`], truncated towards the past.
    pub fn from_system_time(t: SystemTime) -> Self {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Self(i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
            Err(e) => {
                let d = e.duration();
                let whole = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                Self(-whole - i64::from(d.subsec_nanos() > 0))
            }
        }
    }

    /// As a [`SystemTime`].
    pub fn to_system_time(self) -> SystemTime {
        if self.0 >= 0 {
            UNIX_EPOCH + Duration::from_secs(self.0.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_secs(self.0.unsigned_abs())
        }
    }

    /// This time plus `secs` seconds, saturating.
    pub fn plus_seconds(self, secs: u64) -> Self {
        Self(
            self.0
                .saturating_add(i64::try_from(secs).unwrap_or(i64::MAX)),
        )
    }

    /// Seconds from `self` until `later`; zero if `later` is not later.
    pub fn seconds_until(self, later: Timestamp) -> u64 {
        u64::try_from(later.0.saturating_sub(self.0)).unwrap_or(0)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.0.div_euclid(86_400);
        let secs = self.0.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }
}

impl FromStr for Timestamp {
    type Err = BadTimestamp;

    fn from_str(s: &str) -> Result<Self, BadTimestamp> {
        let b = s.as_bytes();
        if b.len() < 20 {
            return Err(BadTimestamp);
        }
        let num = |range: std::ops::Range<usize>| -> Result<i64, BadTimestamp> {
            let part = &b[range];
            if part.iter().all(u8::is_ascii_digit) {
                Ok(part.iter().fold(0, |n, &c| n * 10 + i64::from(c - b'0')))
            } else {
                Err(BadTimestamp)
            }
        };
        let sep = |i: usize, c: &[u8]| {
            if c.contains(&b[i]) {
                Ok(())
            } else {
                Err(BadTimestamp)
            }
        };
        let year = num(0..4)?;
        sep(4, b"-")?;
        let month = num(5..7)?;
        sep(7, b"-")?;
        let day = num(8..10)?;
        sep(10, b"Tt")?;
        let hour = num(11..13)?;
        sep(13, b":")?;
        let minute = num(14..16)?;
        sep(16, b":")?;
        let second = num(17..19)?;

        let mut rest = &b[19..];
        if let [b'.', tail @ ..] = rest {
            let digits = tail.iter().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 {
                return Err(BadTimestamp);
            }
            rest = &tail[digits..];
        }
        let offset = match rest {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
                let digits = [*h1, *h2, *m1, *m2];
                if !digits.iter().all(u8::is_ascii_digit) {
                    return Err(BadTimestamp);
                }
                let v = |i: usize| i64::from(digits[i] - b'0');
                let (h, m) = (v(0) * 10 + v(1), v(2) * 10 + v(3));
                if h > 23 || m > 59 {
                    return Err(BadTimestamp);
                }
                let off = h * 3600 + m * 60;
                if *sign == b'+' { off } else { -off }
            }
            _ => return Err(BadTimestamp),
        };

        let month = u32::try_from(month).map_err(|_| BadTimestamp)?;
        let day = u32::try_from(day).map_err(|_| BadTimestamp)?;
        if !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(BadTimestamp);
        }
        let days = days_from_civil(year, month, day);
        Ok(Self(
            days * 86_400 + hour * 3600 + minute * 60 + second - offset,
        ))
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = std::borrow::Cow::<str>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's civil-date algorithms (public domain), on the proleptic
// Gregorian calendar.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    // `d` is 1..=31 and `m` is 1..=12, so the casts cannot truncate.
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(Timestamp::from_unix(0).to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(
            Timestamp::from_unix(1_762_593_911).to_string(),
            "2025-11-08T09:25:11Z"
        );
        assert_eq!(
            Timestamp::from_unix(951_782_400).to_string(),
            "2000-02-29T00:00:00Z"
        );
        assert_eq!(Timestamp::from_unix(-1).to_string(), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn parses_what_it_formats_and_common_variants() {
        for secs in [0, 1, -1, 951_782_400, 1_794_129_911, 4_102_444_799] {
            let t = Timestamp::from_unix(secs);
            assert_eq!(t.to_string().parse::<Timestamp>(), Ok(t));
        }
        let t: Timestamp = "2026-11-08T09:25:11Z".parse().unwrap();
        assert_eq!("2026-11-08T09:25:11.120044Z".parse(), Ok(t));
        assert_eq!("2026-11-08t09:25:11z".parse(), Ok(t));
        assert_eq!("2026-11-08T10:25:11+01:00".parse(), Ok(t));
        assert_eq!("2026-11-08T04:55:11-04:30".parse(), Ok(t));
    }

    #[test]
    fn rejects_malformed_times() {
        for bad in [
            "",
            "2026-11-08",
            "2026-11-08 09:25:11Z",
            "2026-13-08T09:25:11Z",
            "2026-02-29T09:25:11Z",
            "2026-11-08T24:00:00Z",
            "2026-11-08T09:25:60Z",
            "2026-11-08T09:25:11",
            "2026-11-08T09:25:11.Z",
            "2026-11-08T09:25:11+0100",
            "2026-11-08T09:25:11Zjunk",
            "+026-11-08T09:25:11Z",
        ] {
            assert_eq!(bad.parse::<Timestamp>(), Err(BadTimestamp), "{bad}");
        }
    }

    #[test]
    fn serializes_as_a_string() {
        let t = Timestamp::from_unix(1_794_129_911);
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#""2026-11-08T09:25:11Z""#);
        assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), t);
        assert!(serde_json::from_str::<Timestamp>("1794129911").is_err());
    }

    #[test]
    fn arithmetic_saturates() {
        let t = Timestamp::from_unix(100);
        assert_eq!(t.plus_seconds(5).unix(), 105);
        assert_eq!(t.seconds_until(Timestamp::from_unix(160)), 60);
        assert_eq!(t.seconds_until(Timestamp::from_unix(10)), 0);
        assert_eq!(
            Timestamp::from_unix(i64::MAX).plus_seconds(1).unix(),
            i64::MAX
        );
        let st = Timestamp::from_unix(-5).to_system_time();
        assert_eq!(Timestamp::from_system_time(st).unix(), -5);
    }
}
