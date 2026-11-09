//! `audit_query`: filtered reads of the log.

use std::collections::VecDeque;
use std::time::SystemTime;

use serde_json::Value;

use super::{AuditError, AuditLog, io_err, list_segments, segment_name};
use crate::time::parse_rfc3339;

/// Filters for [`AuditLog::query`]. Every set filter must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// Session id.
    pub session: Option<String>,
    /// Secret name, matched against `secret`, `secrets` and `hits`.
    pub secret: Option<String>,
    /// Event types; empty means all.
    pub events: Vec<String>,
    /// Records at or after this time.
    pub since: Option<SystemTime>,
    /// Records at or before this time.
    pub until: Option<SystemTime>,
    /// The newest this many matches (default [`Query::DEFAULT_LIMIT`]).
    pub limit: Option<usize>,
}

impl Query {
    /// Records returned when no limit is given.
    pub const DEFAULT_LIMIT: usize = 50;

    /// Whether a record matches.
    pub fn matches(&self, r: &Value) -> bool {
        let session = r.pointer("/session/id").and_then(Value::as_str);
        if self
            .session
            .as_deref()
            .is_some_and(|id| session != Some(id))
        {
            return false;
        }
        if !self.events.is_empty() {
            let ev = r.get("event").and_then(Value::as_str).unwrap_or("");
            if !self.events.iter().any(|e| e == ev) {
                return false;
            }
        }
        if let Some(name) = &self.secret {
            let one = r.get("secret").and_then(Value::as_str) == Some(name.as_str());
            let many = r
                .get("secrets")
                .and_then(Value::as_array)
                .is_some_and(|a| a.iter().any(|s| s.as_str() == Some(name.as_str())));
            let hit = r
                .get("hits")
                .and_then(Value::as_object)
                .is_some_and(|h| h.contains_key(name));
            if !(one || many || hit) {
                return false;
            }
        }
        if self.since.is_some() || self.until.is_some() {
            let Some(ts) = r
                .get("ts")
                .and_then(Value::as_str)
                .and_then(|s| parse_rfc3339(s).ok())
            else {
                return false;
            };
            if self.since.is_some_and(|s| ts < s) || self.until.is_some_and(|u| ts > u) {
                return false;
            }
        }
        true
    }
}

impl AuditLog {
    /// The newest records matching `q`, oldest first.
    pub fn query(&self, q: &Query) -> Result<Vec<Value>, AuditError> {
        let limit = q.limit.unwrap_or(Query::DEFAULT_LIMIT);
        let mut out = VecDeque::with_capacity(limit.min(1024));
        if limit == 0 {
            return Ok(Vec::new());
        }
        for n in list_segments(&self.dir)? {
            let path = self.dir.join(segment_name(n));
            let bytes = std::fs::read(&path).map_err(io_err(&path))?;
            for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                let Ok(r) = serde_json::from_slice::<Value>(line) else {
                    continue;
                };
                if q.matches(&r) {
                    if out.len() == limit {
                        out.pop_front();
                    }
                    out.push_back(r);
                }
            }
        }
        Ok(out.into())
    }
}
