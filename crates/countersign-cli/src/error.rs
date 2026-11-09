//! Errors, their exit codes (docs/cli.md "Exit codes") and their hints.

use countersign_proto::ErrorBody;
use serde_json::Value;

/// A failed command. `code` is a stable string from docs/cli.md, matching
/// the daemon's error code where one exists.
#[derive(Debug, Clone)]
pub struct CnError {
    /// Stable machine-readable code.
    pub code: String,
    /// One line for humans.
    pub message: String,
    /// What to do next, if there is something useful to say.
    pub hint: Option<String>,
    /// Structured detail, passed through from `cnd` where it came from there.
    pub detail: Value,
}

impl CnError {
    /// A new error with no hint and no detail.
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            hint: None,
            detail: Value::Null,
        }
    }

    /// Bad arguments.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new("usage", message)
    }

    /// An unexpected failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }

    /// A command or option that a later version provides.
    pub fn later(what: &str) -> Self {
        Self::new(
            "not_in_this_version",
            format!("{what} is not in this version of countersign (planned for Phase 2)"),
        )
    }

    /// Adds a hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Adds detail.
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    /// The exit code for this error (all commands except `cn run`).
    pub fn exit(&self) -> i32 {
        exit_for(&self.code)
    }

    /// The error envelope `--json` prints.
    pub fn envelope(&self) -> Value {
        let mut error = serde_json::json!({
            "code": self.code,
            "exit": self.exit(),
            "message": self.message,
        });
        if let Some(hint) = &self.hint {
            error["hint"] = Value::from(hint.as_str());
        }
        if !self.detail.is_null() {
            error["detail"] = self.detail.clone();
        }
        serde_json::json!({"cn": 1, "ok": false, "error": error})
    }
}

impl From<ErrorBody> for CnError {
    fn from(body: ErrorBody) -> Self {
        let code = body.code.to_string();
        let hint = hint_for(&code, &body.detail);
        Self {
            code,
            message: body.message,
            hint,
            detail: body.detail,
        }
    }
}

/// Exit code for an error code, per docs/cli.md. Unknown codes are 1.
pub fn exit_for(code: &str) -> i32 {
    match code {
        "usage" | "no_tty" | "bad_request" | "not_in_this_version" => 2,
        "daemon_unreachable"
        | "unsupported_version"
        | "unknown_request"
        | "forbidden_peer"
        | "bad_peer" => 3,
        "grant_required" => 4,
        "denied" => 5,
        "pending" => 6,
        "request_expired" | "request_not_found" => 7,
        "unknown_secret" => 8,
        "limit_exceeded" => 9,
        "rate_limited" => 10,
        "no_session" | "session_dead" => 11,
        "store_sealed" => 12,
        "audit_broken" => 13,
        "approval_invalid" | "approver_unavailable" => 14,
        _ => 1,
    }
}

/// A next step for codes where there is a useful one.
pub fn hint_for(code: &str, detail: &Value) -> Option<String> {
    let hint = match code {
        "grant_required" => {
            let names = detail["names"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "NAME".into());
            format!("cn request {names} --reason \"...\"")
        }
        "no_session" | "session_dead" => {
            "start the agent under a session anchor: cn session exec -- AGENT".into()
        }
        "daemon_unreachable"
        | "bad_peer"
        | "unsupported_version"
        | "forbidden_peer"
        | "unknown_request"
        | "approver_unavailable"
        | "approval_invalid" => "cn doctor".into(),
        "unknown_secret" => "cn list --all".into(),
        "request_expired" | "request_not_found" => "cn request again".into(),
        "pending" => "ask the human to approve, then check with cn grants".into(),
        "denied" => "do not retry without asking the human".into(),
        "rate_limited" => "wait a minute and try again".into(),
        "store_sealed" => "the human unseals the store; see cn doctor".into(),
        "no_tty" => "use --from-stdin, --from-file PATH or --from-clipboard".into(),
        _ => return None,
    };
    Some(hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_proto::ErrorCode;
    use serde_json::json;

    #[test]
    fn exit_codes_follow_the_table() {
        let table = [
            ("internal", 1),
            ("usage", 2),
            ("no_tty", 2),
            ("daemon_unreachable", 3),
            ("unsupported_version", 3),
            ("unknown_request", 3),
            ("forbidden_peer", 3),
            ("bad_peer", 3),
            ("grant_required", 4),
            ("denied", 5),
            ("pending", 6),
            ("request_expired", 7),
            ("request_not_found", 7),
            ("unknown_secret", 8),
            ("limit_exceeded", 9),
            ("rate_limited", 10),
            ("no_session", 11),
            ("session_dead", 11),
            ("store_sealed", 12),
            ("audit_broken", 13),
            ("approval_invalid", 14),
            ("approver_unavailable", 14),
            ("something_new", 1),
        ];
        for (code, exit) in table {
            assert_eq!(exit_for(code), exit, "{code}");
        }
    }

    #[test]
    fn every_daemon_code_has_an_exit() {
        for code in [
            ErrorCode::UnsupportedVersion,
            ErrorCode::ForbiddenPeer,
            ErrorCode::NoSession,
            ErrorCode::SessionDead,
            ErrorCode::UnknownSecret,
            ErrorCode::GrantRequired,
            ErrorCode::RequestExpired,
            ErrorCode::RequestNotFound,
            ErrorCode::ApprovalInvalid,
            ErrorCode::StoreSealed,
            ErrorCode::RateLimited,
            ErrorCode::LimitExceeded,
            ErrorCode::ApproverUnavailable,
            ErrorCode::UnknownRequest,
            ErrorCode::BadRequest,
        ] {
            assert_ne!(exit_for(&code.to_string()), 1, "{code}");
        }
        assert_eq!(exit_for(&ErrorCode::Internal.to_string()), 1);
    }

    #[test]
    fn daemon_errors_keep_detail_and_gain_hints() {
        let err = CnError::from(ErrorBody {
            code: ErrorCode::GrantRequired,
            message: "no active grant".into(),
            detail: json!({"names": ["clickhouse-password"]}),
        });
        assert_eq!(err.exit(), 4);
        assert_eq!(
            err.hint.as_deref(),
            Some("cn request clickhouse-password --reason \"...\"")
        );
        let env = err.envelope();
        assert_eq!(env["ok"], false);
        assert_eq!(env["error"]["code"], "grant_required");
        assert_eq!(env["error"]["exit"], 4);
        assert_eq!(env["error"]["detail"]["names"][0], "clickhouse-password");
    }
}
