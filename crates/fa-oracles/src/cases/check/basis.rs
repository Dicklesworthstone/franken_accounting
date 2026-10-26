//! K-BASIS (§3.6; bead fa-yugf.8, A3b): every expectation's basis, taken
//! transitively over `derived.from` and `interpretation.from`, contains at
//! least one sourced fact and no synthetic fact. The interpretation and
//! derived facts in the closure are its premises, which the report lists
//! per expectation for the renderer. A `harness_selftest` case is exempt by
//! kind (A8a): UNRUN with that reason, never PASS.

use std::collections::BTreeSet;

use super::super::EXPECTATIONS_FILE;
use super::super::fact::Provenance;
use super::super::header::CaseKind;
use super::super::trace::fact_closure;
use super::{CheckReport, Context};

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let Some(set) = &case.expectations else {
        return CheckReport::new("K-BASIS", 0).finish();
    };
    if case.header.kind == CaseKind::HarnessSelftest {
        let mut r = CheckReport::new("K-BASIS", 0);
        r.reason = Some("exempt: harness_selftest".into());
        return r.finish();
    }
    let mut r = CheckReport::new("K-BASIS", set.expectations.len());
    for e in &set.expectations {
        let mut basis: BTreeSet<String> = e
            .fields
            .strs("basis")
            .unwrap_or(&[])
            .iter()
            .cloned()
            .collect();
        for t in set.targets_of(&e.id) {
            basis.extend(t.fields.strs("basis").unwrap_or(&[]).iter().cloned());
        }
        let closure: BTreeSet<String> = basis.iter().flat_map(|b| fact_closure(case, b)).collect();
        let kind_of = |id: &String| {
            case.facts
                .iter()
                .find(|f| &f.id == id)
                .map(|f| &f.provenance)
        };
        let sourced = closure
            .iter()
            .any(|f| matches!(kind_of(f), Some(Provenance::Sourced(_))));
        let synthetic: Vec<&str> = closure
            .iter()
            .filter(|f| matches!(kind_of(f), Some(Provenance::Synthetic(_))))
            .map(String::as_str)
            .collect();
        let premises: Vec<&str> = closure
            .iter()
            .filter(|f| {
                matches!(
                    kind_of(f),
                    Some(Provenance::Derived(_) | Provenance::Interpretation(_))
                )
            })
            .map(String::as_str)
            .collect();
        r.examined(if premises.is_empty() {
            e.id.clone()
        } else {
            format!("{} premises={}", e.id, premises.join(","))
        });
        if !sourced {
            r.fail(
                EXPECTATIONS_FILE,
                e.fields.line,
                &e.id,
                format!("the basis closure {:?} has no sourced fact", closure),
            );
        }
        if !synthetic.is_empty() {
            r.fail(
                EXPECTATIONS_FILE,
                e.fields.line,
                &e.id,
                format!("the basis closure reaches synthetic fact(s) {synthetic:?}"),
            );
        }
    }
    r.finish()
}
