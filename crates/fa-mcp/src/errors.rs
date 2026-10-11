//! The structured error (plan §15.4): `{type, message, recoverable,
//! fix_hint, suggested_tool_calls, …}`, mapped from the robot envelope's one
//! `error` event (`{class, exit, refusal_id, message, cite, fix, detail}`).
//!
//! - `type` is the exit's class (`exit_codes.toml`: usage, refusal,
//!   environment, foundation, conflict, safety, verification);
//! - `fix_hint` is the refusal's `fix`, byte for byte — the same words the
//!   CLI prints;
//! - `suggested_tool_calls` are the `fa …` commands the fix names (and, for
//!   a catalog refusal, the catalog row's fix template names), each
//!   translated into the tool call that runs it;
//! - `recoverable` says whether a changed call can succeed: true for usage,
//!   refusal, environment, conflict and safety; false for a foundation
//!   failure and a verification failure, which need an operator;
//! - `never`, on a period-law refusal, states what no fix ever means:
//!   re-dating the entry.
//!
//! The mistake detectors produce the same shape with `detector` set and the
//! usage class (exit 2), so an agent handles both alike.

use fa_cli::json::Json;
use fa_cli::verbs::Registry;
use fastmcp_rust::{JsonValue, json};

use crate::dispatch::to_wire;
use crate::registry::{McpRegistry, ToolCall};

/// Exit codes that mean "change the call" rather than "call an operator".
#[must_use]
pub fn recoverable(exit: u8) -> bool {
    matches!(exit, 2 | 3 | 4 | 6 | 7)
}

/// The refusal codes and citations that are the period law.
fn is_period_law(refusal_id: Option<&str>, cite: Option<&str>) -> bool {
    matches!(refusal_id, Some("FA-REF-010" | "FA-REF-011" | "FA-REF-021"))
        || cite.is_some_and(|c| c.contains("admissibility"))
}

/// What a period-law refusal never means.
pub const NEVER_REDATE: &str = "re-date the entry: its effective date is a fact; the admissible path is the class or capability the cited cell admits, or leaving it unposted";

#[derive(Clone, Debug, PartialEq)]
pub struct StructuredError {
    /// The exit's class (`exit_codes.toml`), the JSON `type`.
    pub kind: String,
    pub message: String,
    pub recoverable: bool,
    pub fix_hint: Option<String>,
    pub suggested_tool_calls: Vec<ToolCall>,
    pub exit: u8,
    pub refusal_id: Option<String>,
    pub cite: Option<String>,
    pub detail: JsonValue,
    /// The mistake detector that refused, before dispatch.
    pub detector: Option<String>,
    /// What no fix ever means (period law: never re-date).
    pub never: Option<String>,
}

impl StructuredError {
    /// The structured error of one `error` event's `data`.
    #[must_use]
    pub fn from_error_event(mcp: &McpRegistry, reg: &Registry, data: &Json) -> Self {
        let text = |k: &str| data.get(k).and_then(Json::as_str).map(str::to_string);
        let exit = data
            .get("exit")
            .and_then(|v| match v {
                Json::Int(i) => u8::try_from(*i).ok(),
                _ => None,
            })
            .unwrap_or(5);
        let kind = text("class").unwrap_or_else(|| exit_class(exit));
        let fix = text("fix");
        let refusal_id = text("refusal_id");
        let cite = text("cite");
        let mut calls = fix
            .as_deref()
            .map(|f| mcp.calls_in_text(reg, f))
            .unwrap_or_default();
        if let Some(id) = &refusal_id
            && let Ok(catalog) = fa_registry::refusal_catalog::RefusalCatalog::embedded()
            && let Some(row) = catalog.by_code(id)
        {
            for call in mcp.calls_in_text(reg, &row.fix) {
                if !calls.iter().any(|c| c.tool == call.tool) {
                    calls.push(call);
                }
            }
        }
        let never =
            is_period_law(refusal_id.as_deref(), cite.as_deref()).then(|| NEVER_REDATE.to_string());
        Self {
            kind,
            message: text("message").unwrap_or_default(),
            recoverable: recoverable(exit),
            fix_hint: fix,
            suggested_tool_calls: calls,
            exit,
            refusal_id,
            cite,
            detail: data.get("detail").map_or(JsonValue::Null, to_wire),
            detector: None,
            never,
        }
    }

    /// A mistake a detector caught before dispatch (usage class, exit 2).
    #[must_use]
    pub fn detected(
        detector: &str,
        message: impl Into<String>,
        fix_hint: impl Into<String>,
        calls: Vec<ToolCall>,
    ) -> Self {
        Self {
            kind: exit_class(2),
            message: message.into(),
            recoverable: true,
            fix_hint: Some(fix_hint.into()),
            suggested_tool_calls: calls,
            exit: 2,
            refusal_id: None,
            cite: None,
            detail: JsonValue::Null,
            detector: Some(detector.to_string()),
            never: None,
        }
    }

    /// An argument the mapping could not accept (usage class, exit 2).
    #[must_use]
    pub fn arguments(message: impl Into<String>, fix_hint: impl Into<String>) -> Self {
        Self::detected("arguments", message, fix_hint, Vec::new())
    }

    /// The dispatcher itself failed (foundation class, exit 5).
    #[must_use]
    pub fn foundation(message: impl Into<String>) -> Self {
        Self {
            kind: exit_class(5),
            message: message.into(),
            recoverable: false,
            fix_hint: None,
            suggested_tool_calls: Vec::new(),
            exit: 5,
            refusal_id: None,
            cite: None,
            detail: JsonValue::Null,
            detector: None,
            never: None,
        }
    }

    /// Add what a period-law refusal never means.
    #[must_use]
    pub fn never(mut self, what: &str) -> Self {
        self.never = Some(what.to_string());
        self
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        let mut v = json!({
            "type": self.kind,
            "message": self.message,
            "recoverable": self.recoverable,
            "fix_hint": self.fix_hint,
            "suggested_tool_calls": self.suggested_tool_calls.iter().map(ToolCall::to_json).collect::<Vec<_>>(),
            "exit": self.exit,
            "refusal_id": self.refusal_id,
            "cite": self.cite,
            "detail": self.detail,
        });
        if let Some(d) = &self.detector {
            v["detector"] = JsonValue::String(d.clone());
        }
        if let Some(n) = &self.never {
            v["never"] = JsonValue::String(n.clone());
        }
        v
    }

    /// The error as the tool error's text.
    #[must_use]
    pub fn render(&self) -> String {
        self.to_json().to_string()
    }
}

/// An exit code's class name (`exit_codes.toml`); `exit-<n>` when unknown.
#[must_use]
pub fn exit_class(exit: u8) -> String {
    fa_registry::ExitCodes::embedded()
        .ok()
        .and_then(|codes| {
            codes
                .rows
                .into_iter()
                .find(|r| r.code == exit)
                .map(|r| r.name)
        })
        .unwrap_or_else(|| format!("exit-{exit}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embedded() -> (McpRegistry, &'static Registry) {
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        (McpRegistry::embedded().expect("[mcp]"), reg)
    }

    /// A planted `error` event's data, as the CLI would emit it.
    fn planted(
        class: &str,
        exit: i128,
        refusal_id: Option<&str>,
        cite: Option<&str>,
        fix: Option<&str>,
    ) -> Json {
        Json::Obj(vec![
            ("class".into(), Json::Str(class.into())),
            ("exit".into(), Json::Int(exit)),
            (
                "refusal_id".into(),
                refusal_id.map_or(Json::Null, |s| Json::Str(s.into())),
            ),
            ("message".into(), Json::Str("planted".into())),
            (
                "cite".into(),
                cite.map_or(Json::Null, |s| Json::Str(s.into())),
            ),
            (
                "fix".into(),
                fix.map_or(Json::Null, |s| Json::Str(s.into())),
            ),
            ("detail".into(), Json::Null),
        ])
    }

    #[test]
    fn a_dangerous_operation_refusal_maps_to_the_safe_alternative_as_a_tool_call() {
        let (mcp, reg) = embedded();
        let fix = "`fa period soft-close FY2026-P03` stops ordinary postings and stays reopenable without approvals; or, when the operation is intended, rerun the same command with --yes";
        let e = StructuredError::from_error_event(
            &mcp,
            reg,
            &planted(
                "safety",
                7,
                Some("FA-REF-007"),
                Some("Appendix D FA-REF-007"),
                Some(fix),
            ),
        );
        assert_eq!(e.kind, "safety");
        assert_eq!(e.exit, 7);
        assert!(e.recoverable);
        assert_eq!(e.fix_hint.as_deref(), Some(fix), "byte for byte");
        assert_eq!(
            e.suggested_tool_calls.len(),
            1,
            "{:?}",
            e.suggested_tool_calls
        );
        assert_eq!(e.suggested_tool_calls[0].tool, "fa_time_period_transition");
        assert_eq!(
            e.suggested_tool_calls[0].arguments,
            json!({"transition": "soft-close", "code": "FY2026-P03"})
        );
        assert_eq!(e.never, None);
        let j = e.to_json();
        assert_eq!(j["type"], json!("safety"));
        assert_eq!(j["refusal_id"], json!("FA-REF-007"));
        assert!(j.get("detector").is_none());
        for key in [
            "type",
            "message",
            "recoverable",
            "fix_hint",
            "suggested_tool_calls",
            "exit",
            "refusal_id",
            "cite",
            "detail",
        ] {
            assert!(j.get(key).is_some(), "{key}");
        }
    }

    #[test]
    fn a_period_law_refusal_says_what_it_never_means_and_a_catalog_fix_becomes_a_call() {
        let (mcp, reg) = embedded();
        let e = StructuredError::from_error_event(
            &mcp,
            reg,
            &planted(
                "safety",
                7,
                Some("FA-REF-010"),
                Some("admissibility.toml (Original, Closed)"),
                Some("post in an Open period, or use the class and capability the cell admits"),
            ),
        );
        assert_eq!(e.never.as_deref(), Some(NEVER_REDATE));
        assert!(
            e.suggested_tool_calls.is_empty(),
            "no `fa …` command in that fix: {:?}",
            e.suggested_tool_calls
        );
        // FA-REF-021's catalog template names `fa period create --fiscal-year <FY>`.
        let e = StructuredError::from_error_event(
            &mcp,
            reg,
            &planted(
                "safety",
                7,
                Some("FA-REF-021"),
                Some("plan §7.3"),
                Some("no period admits 2031-01-01"),
            ),
        );
        assert_eq!(
            e.suggested_tool_calls.len(),
            1,
            "{:?}",
            e.suggested_tool_calls
        );
        assert_eq!(e.suggested_tool_calls[0].tool, "fa_time_create_periods");
        assert_eq!(
            e.suggested_tool_calls[0].arguments,
            json!({"fiscal_year": "<FY>"})
        );
        assert!(e.never.is_some());
        // A lease conflict is recoverable; a verification failure and a
        // foundation failure are not.
        let e = StructuredError::from_error_event(
            &mcp,
            reg,
            &planted("conflict", 6, Some("FA-REF-018"), None, None),
        );
        assert!(e.recoverable);
        let e = StructuredError::from_error_event(
            &mcp,
            reg,
            &planted("verification", 8, None, None, None),
        );
        assert!(!e.recoverable && e.fix_hint.is_none() && e.suggested_tool_calls.is_empty());
        let e = StructuredError::from_error_event(
            &mcp,
            reg,
            &planted("foundation", 5, None, None, None),
        );
        assert!(!e.recoverable);
        let e = StructuredError::from_error_event(
            &mcp,
            reg,
            &planted("usage", 2, None, None, Some("did you mean --json?")),
        );
        assert!(e.recoverable && e.suggested_tool_calls.is_empty());
    }

    #[test]
    fn a_detected_mistake_has_the_same_shape_with_its_detector_named() {
        let e = StructuredError::detected(
            "float_amount",
            "legs[0].amount is a JSON number",
            "write \"12.50 USD\"",
            Vec::new(),
        );
        let j = e.to_json();
        assert_eq!(j["type"], json!("usage"));
        assert_eq!(j["exit"], json!(2));
        assert_eq!(j["detector"], json!("float_amount"));
        assert_eq!(j["recoverable"], json!(true));
        assert_eq!(j["fix_hint"], json!("write \"12.50 USD\""));
        assert!(e.render().starts_with('{'));
    }
}
