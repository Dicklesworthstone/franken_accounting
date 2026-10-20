//! `registries/reason_codes.toml`: the registered reasons a principal may
//! give, by scope (plan §7.3, §8.2 and §9.2). Supersessions,
//! ManualAssertions and period transitions each require a reason registered
//! for that scope.

use std::collections::BTreeSet;

use crate::{RegistryError, invalid, load, req_int, req_str};

const REASON_CODES: &str = include_str!("../../../registries/reason_codes.toml");
const R: &str = "reason_codes.toml";

/// The closed set of scopes a reason may belong to.
pub const SCOPES: [&str; 4] = [
    "manual_assertion",
    "supersession",
    "period_control",
    "period_reopen",
];

/// Stable supersession reason for the kernel's scheduled accrual reversal.
pub const SCHEDULED_ACCRUAL_REVERSAL: u16 = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    pub code: u16,
    pub scope: String,
    pub name: String,
    pub meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReasonCodes {
    pub rows: Vec<Reason>,
}

impl ReasonCodes {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(REASON_CODES)
    }

    pub fn from_text(text: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let empty = Vec::new();
        let mut codes = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut rows = Vec::new();
        for t in doc.arrays.get("reason").unwrap_or(&empty) {
            let raw = req_int(R, t, "code")?;
            let code = u16::try_from(raw)
                .ok()
                .filter(|c| *c >= 1)
                .ok_or_else(|| invalid(R, format!("code {raw} is not in 1..=65535")))?;
            let scope = req_str(R, t, "scope")?.to_string();
            if !SCOPES.contains(&scope.as_str()) {
                return Err(invalid(R, format!("code {code}: unknown scope `{scope}`")));
            }
            let name = req_str(R, t, "name")?.to_string();
            let meaning = req_str(R, t, "meaning")?.to_string();
            if name.is_empty() || meaning.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("code {code}: name and meaning are required"),
                ));
            }
            if !codes.insert((scope.clone(), code)) {
                return Err(invalid(R, format!("{scope} code {code} is listed twice")));
            }
            if !names.insert((scope.clone(), name.clone())) {
                return Err(invalid(R, format!("{scope} name `{name}` is listed twice")));
            }
            rows.push(Reason {
                code,
                scope,
                name,
                meaning,
            });
        }
        for scope in SCOPES {
            if !rows.iter().any(|r| r.scope == scope) {
                return Err(invalid(R, format!("scope `{scope}` has no reasons")));
            }
        }
        Ok(Self { rows })
    }

    #[must_use]
    pub fn get(&self, scope: &str, code: u16) -> Option<&Reason> {
        self.rows
            .iter()
            .find(|r| r.scope == scope && r.code == code)
    }

    /// `code name` pairs of a scope, for refusal text.
    #[must_use]
    pub fn listing(&self, scope: &str) -> String {
        self.rows
            .iter()
            .filter(|r| r.scope == scope)
            .map(|r| format!("{} {}", r.code, r.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_reasons_load_and_answer_by_scope() {
        let r = ReasonCodes::embedded().expect("reason_codes.toml");
        assert_eq!(
            r.get("manual_assertion", 1).map(|x| x.name.as_str()),
            Some("NoDocumentIssued")
        );
        assert!(r.get("manual_assertion", 0).is_none());
        assert_eq!(
            r.get("supersession", 1).map(|x| x.name.as_str()),
            Some("DataEntryError")
        );
        assert_eq!(
            r.get("supersession", SCHEDULED_ACCRUAL_REVERSAL)
                .map(|x| x.name.as_str()),
            Some("ScheduledAccrualReversal")
        );
        assert!(r.get("supersession", 0).is_none());
        assert!(
            r.listing("manual_assertion")
                .starts_with("1 NoDocumentIssued")
        );
        assert_eq!(
            r.get("period_control", 1).map(|x| x.name.as_str()),
            Some("Scheduled")
        );
        assert_eq!(
            r.get("period_reopen", 3).map(|x| x.name.as_str()),
            Some("ErrorCorrection")
        );
        assert!(r.get("period_control", 0).is_none());
        assert!(r.get("period_control", 4).is_none());
        assert!(r.get("period_reopen", 0).is_none());
    }

    #[test]
    fn malformed_reason_tables_are_refused() {
        let good = REASON_CODES;
        for (what, from, to) in [
            ("a zero code", "code = 1\n", "code = 0\n"),
            ("a duplicated code", "code = 2\n", "code = 1\n"),
            (
                "a duplicated name",
                "name = \"DocumentLost\"",
                "name = \"NoDocumentIssued\"",
            ),
            (
                "an unknown scope",
                "scope = \"manual_assertion\"\nname = \"OralAgreement\"",
                "scope = \"vibes\"\nname = \"OralAgreement\"",
            ),
            (
                "an empty meaning",
                "meaning = \"the transaction rests on an oral agreement; no written instrument exists\"",
                "meaning = \" \"",
            ),
        ] {
            let text = good.replacen(from, to, 1);
            assert_ne!(text, good, "{what}: the planted edit did not apply");
            assert!(
                ReasonCodes::from_text(&text).is_err(),
                "{what} must be refused"
            );
        }
    }
}
