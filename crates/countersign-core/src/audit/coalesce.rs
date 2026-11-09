//! Coalescing of `list` records (audit.md, "Coalescing").
//!
//! The first `list` of a session opens a window and is recorded at once.
//! Further calls inside the window are counted, not written. The first call
//! after the window ends is recorded with the count of everything not yet
//! recorded, and opens the next window. So each window has at most one
//! record, written at its start, and no call goes uncounted.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use super::Event;
use crate::time::format_rfc3339_micros;

/// A `list` record to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRecord {
    /// Calls it covers.
    pub count: u64,
    /// First call covered.
    pub window_start: SystemTime,
    /// Last call covered.
    pub window_end: SystemTime,
}

impl ListRecord {
    /// The audit event.
    pub fn event(&self) -> Event {
        Event::List {
            count: self.count,
            window_start: format_rfc3339_micros(self.window_start),
            window_end: format_rfc3339_micros(self.window_end),
        }
    }
}

#[derive(Debug)]
struct Window {
    opened: SystemTime,
    unrecorded: u64,
    first_unrecorded: Option<SystemTime>,
    last: SystemTime,
}

/// Per-session `list` coalescing.
#[derive(Debug)]
pub struct ListCoalescer {
    window: Duration,
    sessions: HashMap<String, Window>,
}

impl ListCoalescer {
    /// A coalescer with this window (`[audit] list_coalesce`).
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            sessions: HashMap::new(),
        }
    }

    /// Counts one `list` call. Returns the record to write, if any.
    pub fn on_list(&mut self, session: &str, now: SystemTime) -> Option<ListRecord> {
        let window = self.window;
        match self.sessions.get_mut(session) {
            Some(w) if now.duration_since(w.opened).unwrap_or_default() < window => {
                w.unrecorded += 1;
                w.first_unrecorded.get_or_insert(now);
                w.last = now;
                None
            }
            Some(w) => {
                let rec = ListRecord {
                    count: w.unrecorded + 1,
                    window_start: w.first_unrecorded.unwrap_or(now),
                    window_end: now,
                };
                *w = Window {
                    opened: now,
                    unrecorded: 0,
                    first_unrecorded: None,
                    last: now,
                };
                Some(rec)
            }
            None => {
                self.sessions.insert(
                    session.to_owned(),
                    Window {
                        opened: now,
                        unrecorded: 0,
                        first_unrecorded: None,
                        last: now,
                    },
                );
                Some(ListRecord {
                    count: 1,
                    window_start: now,
                    window_end: now,
                })
            }
        }
    }

    /// Ends a session; returns a record for its uncounted calls, if any.
    pub fn end_session(&mut self, session: &str) -> Option<ListRecord> {
        self.sessions.remove(session).and_then(Self::leftover)
    }

    /// Records for sessions whose window ended with uncounted calls, and
    /// forgets those sessions. Call from a timer and at shutdown (with a
    /// `now` far enough ahead to flush everything).
    pub fn flush(&mut self, now: SystemTime) -> Vec<(String, ListRecord)> {
        let window = self.window;
        let done: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, w)| now.duration_since(w.opened).unwrap_or_default() >= window)
            .map(|(s, _)| s.clone())
            .collect();
        let mut out: Vec<(String, ListRecord)> = done
            .into_iter()
            .filter_map(|s| {
                let w = self.sessions.remove(&s)?;
                Self::leftover(w).map(|r| (s, r))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn leftover(w: Window) -> Option<ListRecord> {
        (w.unrecorded > 0).then(|| ListRecord {
            count: w.unrecorded,
            window_start: w.first_unrecorded.unwrap_or(w.last),
            window_end: w.last,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + s)
    }

    #[test]
    fn first_call_is_written_and_the_rest_are_counted() {
        let mut c = ListCoalescer::new(Duration::from_secs(600));
        let first = c.on_list("s_a", t(0)).unwrap();
        assert_eq!((first.count, first.window_start), (1, t(0)));
        assert_eq!(c.on_list("s_a", t(10)), None);
        assert_eq!(c.on_list("s_a", t(599)), None);
        // Another session has its own window.
        assert_eq!(c.on_list("s_b", t(20)).unwrap().count, 1);
        // The window ended: one record covering the two counted calls and this one.
        let r = c.on_list("s_a", t(600)).unwrap();
        assert_eq!(
            r,
            ListRecord {
                count: 3,
                window_start: t(10),
                window_end: t(600)
            }
        );
        assert_eq!(c.on_list("s_a", t(601)), None);
        assert_eq!(
            c.end_session("s_a"),
            Some(ListRecord {
                count: 1,
                window_start: t(601),
                window_end: t(601)
            })
        );
        assert_eq!(c.end_session("s_b"), None);
    }

    #[test]
    fn counts_are_never_lost() {
        let mut c = ListCoalescer::new(Duration::from_secs(60));
        let mut recorded = 0;
        let calls = 1000;
        for i in 0..calls {
            if let Some(r) = c.on_list("s", t(i * 7)) {
                recorded += r.count;
            }
        }
        recorded += c
            .flush(t(1_000_000))
            .iter()
            .map(|(_, r)| r.count)
            .sum::<u64>();
        assert_eq!(recorded, calls);
    }

    #[test]
    fn flush_writes_only_ended_windows() {
        let mut c = ListCoalescer::new(Duration::from_secs(60));
        c.on_list("a", t(0));
        c.on_list("a", t(1));
        c.on_list("b", t(30));
        c.on_list("b", t(31));
        let out = c.flush(t(60));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "a");
        assert_eq!(out[0].1.count, 1);
        // a's window is gone, so its next call is written at once.
        assert_eq!(c.on_list("a", t(61)).unwrap().count, 1);
        assert!(matches!(out[0].1.event(), Event::List { count: 1, .. }));
    }
}
