//! K-REASON (§3.2a, §3.6; bead fa-yugf.9, A3c): no intent carries a reason
//! that is a legal conclusion, and every reason a correction carries is a
//! declared default with its rationale.
//!
//! `Fraud` (`registries/reason_codes.toml`, supersession code 8) is refused
//! by name or by code: the doctrine never calls a hash or a correction a
//! legal conclusion. Every intent with a `reason` is covered by its
//! variant's `[[default]] attribute = "reason"` row (A1b), which the
//! sentence renders with its rationale.

use fa_registry::toml::Value as TomlValue;

use super::{CheckReport, Context};

const REASON_CODES: &str = include_str!("../../../../../registries/reason_codes.toml");

/// The supersession reasons that are legal conclusions, by name.
const LEGAL_CONCLUSIONS: [&str; 1] = ["Fraud"];

/// The registered supersession codes of the legal-conclusion names.
fn conclusion_codes() -> Vec<i128> {
    let Ok(doc) = fa_registry::toml::parse(REASON_CODES) else {
        return Vec::new();
    };
    doc.arrays
        .get("reason")
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter(|t| t.get("scope").and_then(TomlValue::as_str) == Some("supersession"))
        .filter(|t| {
            t.get("name")
                .and_then(TomlValue::as_str)
                .is_some_and(|n| LEGAL_CONCLUSIONS.contains(&n))
        })
        .filter_map(|t| t.get("code").and_then(TomlValue::as_int))
        .collect()
}

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let with_reason: Vec<_> = case
        .books
        .values()
        .flat_map(|b| {
            b.intents
                .iter()
                .filter_map(move |i| i.reason.as_deref().map(|reason| (b, i, reason)))
        })
        .collect();
    let mut r = CheckReport::new("K-REASON", with_reason.len());
    let codes = conclusion_codes();
    for (book, it, reason) in with_reason {
        let file = format!("books/{}.toml", book.stem);
        r.examined(format!("{}:{reason}", it.id));
        let is_conclusion = LEGAL_CONCLUSIONS
            .iter()
            .any(|n| n.eq_ignore_ascii_case(reason.trim()))
            || reason
                .trim()
                .parse::<i128>()
                .is_ok_and(|c| codes.contains(&c));
        if is_conclusion {
            r.fail(
                &file,
                it.line,
                &it.id,
                format!(
                    "`reason = \"{reason}\"` is a legal conclusion; a correction names its technical reason (WrongAccount, …)"
                ),
            );
        }
        let declared = book
            .defaults
            .iter()
            .any(|d| d.attribute == "reason" && !d.rationale.trim().is_empty());
        if !declared {
            r.fail(
                &file,
                it.line,
                &it.id,
                "a reason is a declared default: the variant needs `[[default]] attribute = \"reason\"` with its rationale (§3.2a)",
            );
        }
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::super::super::tests::pilot_planted;
    use super::super::Verdict;
    use super::*;

    fn intent_line(case: &crate::cases::Case, id: &str) -> String {
        case.books["native"]
            .intents
            .iter()
            .find(|i| i.id == id)
            .and_then(|i| i.line)
            .map_or_else(|| "-".into(), |l| l.to_string())
    }

    #[test]
    fn pilot_reasons_are_declared_defaults() {
        let case = pilot_planted(&[]);
        let r = check(&Context::new(&case));
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
        assert_eq!(r.examined, 3);
    }

    #[test]
    fn intent_with_reason_fraud_fails_k_reason() {
        let case = pilot_planted(&[(
            "books/native.toml",
            "target = \"F4\"\ntarget_kind = \"restates\"\nreason = \"WrongAccount\"",
            "target = \"F4\"\ntarget_kind = \"restates\"\nreason = \"Fraud\"",
        )]);
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let want = format!(
            "FAIL K-REASON books/native.toml:{} delta-F4: `reason = \"Fraud\"` is a legal conclusion; a correction names its technical reason (WrongAccount, …)",
            intent_line(&case, "delta-F4")
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
        assert_eq!(
            text.lines().filter(|l| l.starts_with("FAIL ")).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn correction_reason_without_a_declared_default_fails_k_reason() {
        let case = pilot_planted(&[(
            "books/native.toml",
            "[[default]]\nattribute = \"reason\"\nrule = \"WrongAccount\"\nrationale = \"the entries moved line costs into asset accounts; the correction's reason is the account, never Fraud (K-REASON)\"\n",
            "",
        )]);
        assert!(
            !case.books["native"]
                .defaults
                .iter()
                .any(|d| d.attribute == "reason")
        );
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        for id in ["delta-F4", "delta-F9", "delta-F12"] {
            let want = format!(
                "FAIL K-REASON books/native.toml:{} {id}: a reason is a declared default: the variant needs `[[default]] attribute = \"reason\"` with its rationale (§3.2a)",
                intent_line(&case, id)
            );
            assert!(text.lines().any(|l| l == want), "{want}\n{text}");
        }
    }
}
