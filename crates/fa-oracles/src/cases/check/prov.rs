//! K-PROV (§2.1, §3.6): every fact has exactly one provenance kind with its
//! required fields, and its values come from the closed sets. The loader
//! already refuses a row that mixes two kinds and a value outside a closed
//! set (A1a); K-PROV re-checks the parsed facts, so an edited or constructed
//! [`Case`](super::Case) cannot slip past, and reports what it examined.

use super::super::fact::Provenance;
use super::{CheckReport, Context, FACTS};

/// The closed set of a sourced fact's `role`.
const ROLES: [&str; 1] = ["oracle_output"];

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let mut r = CheckReport::new("K-PROV", case.facts.len());
    for f in &case.facts {
        let mut problems: Vec<String> = Vec::new();
        let mut need = |field: &str, value: &str| {
            if value.trim().is_empty() {
                problems.push(format!("`{field}` is empty"));
            }
        };
        match &f.provenance {
            Provenance::Sourced(s) => {
                need("source", &s.source);
                need("anchor", &s.anchor);
                need("quote_sha256", &s.quote_sha256);
                need("about_scope", &s.about_scope);
                if let Some(role) = &s.role
                    && !ROLES.contains(&role.as_str())
                {
                    problems.push(format!("`role = \"{role}\"` is not one of {ROLES:?}"));
                }
            }
            Provenance::Interpretation(x) => {
                need("reader", &x.reader);
                need("second_reader", &x.second_reader);
                need("rationale", &x.rationale);
                if x.reader == x.second_reader {
                    problems.push(format!(
                        "an interpretation rests on two readers; `reader` and `second_reader` are both `{}`",
                        x.reader
                    ));
                }
                if x.from.is_empty() {
                    problems.push("an interpretation reads at least one sourced fact".into());
                }
                for from in &x.from {
                    if !case
                        .facts
                        .iter()
                        .any(|g| g.id == *from && g.sourced().is_some())
                    {
                        problems.push(format!(
                            "`from` names `{from}`, which is not a sourced fact"
                        ));
                    }
                }
            }
            Provenance::Derived(x) => {
                need("rule", &x.rule);
                if x.from.is_empty() {
                    problems.push("a derived fact is computed from at least one fact".into());
                }
            }
            Provenance::Synthetic(x) => {
                need("reason", &x.reason);
                need("discipline", &x.discipline);
            }
        }
        r.examined(f.id.clone());
        for p in problems {
            r.fail(FACTS, f.line, &f.id, p);
        }
    }
    r.finish()
}
