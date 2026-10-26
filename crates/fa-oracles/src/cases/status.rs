//! Component statuses and the row-level D rules
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.6 rules 1-4 and 7-9, §5.2; bead
//! fa-yugf.13, A5b).
//!
//! `closed_cites` (A5b's row-level rule). A D compares per target, so a
//! finding that cites an entry none of its targets names is invisible to the
//! per-target evaluation. A D expectation with `closed_cites = true` states
//! that its targets are every documented or Δ entry its run's findings cite:
//! after the per-target evaluation, every cited intent whose fact is sourced
//! or an interpretation, or that is a case Δ (`restates`/`revises`), and that
//! no target names, fails the row on a line of its own. Filler and other
//! synthetic intents are never in scope (A11a's filler witness covers them).
//! The default is false: a D that claims findings on some entries claims
//! nothing about the others.

use std::collections::BTreeSet;

use super::Case;
use super::expect::Expectation;
use super::fact::ProvenanceKind;

/// Whether `expectation` declares `closed_cites = true`.
#[must_use]
pub fn closed_cites(expectation: &Expectation) -> bool {
    expectation.fields.bool("closed_cites") == Some(true)
}

/// The intents of `cited` (the intent ids the expectation's run's findings
/// cite, as the runner maps them) that a `closed_cites` D did not expect:
/// documented (sourced or interpretation fact) or Δ intents of its book
/// variant that none of its targets names. Empty when the expectation does
/// not declare `closed_cites`.
#[must_use]
pub fn unexpected_cites(
    case: &Case,
    expectation: &Expectation,
    cited: &BTreeSet<String>,
) -> Vec<String> {
    if !closed_cites(expectation) {
        return Vec::new();
    }
    let Some(set) = case.expectations.as_ref() else {
        return Vec::new();
    };
    let Some(book) = expectation
        .fields
        .str("book_variant")
        .and_then(|v| case.books.get(v))
    else {
        return Vec::new();
    };
    let named: BTreeSet<&str> = set
        .targets_of(&expectation.id)
        .map(|t| t.fact.as_str())
        .collect();
    let documented = |fact: &str| {
        case.facts.iter().any(|f| {
            f.id == fact
                && matches!(
                    f.provenance.kind(),
                    ProvenanceKind::Sourced | ProvenanceKind::Interpretation
                )
        })
    };
    book.intents
        .iter()
        .filter(|i| cited.contains(&i.id))
        .filter(|i| documented(&i.fact) || i.is_delta())
        .filter(|i| !named.contains(i.id.as_str()) && !named.contains(i.fact.as_str()))
        .map(|i| i.id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::tests::pilot_planted;

    /// W-D-01 (targets F4 and F9) with `closed_cites` as given.
    fn w_d_01(closed: Option<bool>) -> Case {
        let anchor = "capabilities = [\"procedure:expense.capitalization@2\"]\nprocedure = \"expense.capitalization\"\nversion = 2\n";
        let with = closed.map_or_else(
            || anchor.to_string(),
            |c| format!("{anchor}closed_cites = {c}\n"),
        );
        pilot_planted(&[("expectations.toml", anchor, &with)])
    }

    fn cited(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    /// A5b's row-level rule on synthetic observations: a `closed_cites` D
    /// whose run also cites a documented entry (F12) and a Δ (delta-F4) no
    /// target names lists both; the same observations without the field list
    /// nothing; a cite of a non-documented intent is never in scope.
    #[test]
    fn unexpected_cite_fails_a_closed_cites_row() {
        let case = w_d_01(Some(true));
        let e = case.expectations.as_ref().unwrap().get("W-D-01").unwrap();
        assert!(closed_cites(e));
        let run = cited(&["F4", "F9", "F12", "delta-F4"]);
        assert_eq!(unexpected_cites(&case, e, &run), vec!["F12", "delta-F4"]);
        // Only the targets' own entries: nothing unexpected.
        assert!(unexpected_cites(&case, e, &cited(&["F4", "F9"])).is_empty());
        // An intent the book does not hold (a filler id) is never in scope.
        assert!(unexpected_cites(&case, e, &cited(&["F4", "filler-fv1-1-0"])).is_empty());
        for closed in [None, Some(false)] {
            let case = w_d_01(closed);
            let e = case.expectations.as_ref().unwrap().get("W-D-01").unwrap();
            assert!(!closed_cites(e));
            assert!(unexpected_cites(&case, e, &run).is_empty(), "{closed:?}");
        }
    }
}
