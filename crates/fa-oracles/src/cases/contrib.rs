//! The contributing-entry witness for T rows (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.7 item 2; bead fa-yugf.26, A11b): the dynamic half of K-TAUT.
//!
//! A T holds only if none of the postings its certified value folds carries
//! the published comparison value B (directly, or through a derivation that
//! traces to B), those postings are exactly the ones its predicate names as
//! inputs, and they re-add to the certified value, checked in that order. Any failure re-types the T
//! as R, its condition named: `extra contribution <id>`, `missing named
//! input <id>`, `contribution carries B` or `does not re-add`.
//!
//! The named inputs are computed, never authored: every intent of the T's
//! `basis` facts other than its `published` one, every intent (or intent of
//! a fact) its `inputs_named` lists, and every delta (`restates` or
//! `revises`) whose target is one of those. A `delta` T's named inputs are
//! its deltas alone: an A posting does not move a delta.

use std::collections::BTreeSet;

use super::Case;
use super::book::BookVariant;
use super::check::taut::published_closure;
use super::expect::TKind;
use super::trace::{Read, posted_from};

/// One leg a certified read folded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    /// The entry's vid.
    pub entry: String,
    /// The intent that posted it, when the run can name one.
    pub intent: Option<String>,
    /// The leg's account code.
    pub account: String,
    /// Its amount in minor units, debits positive.
    pub signed: i128,
}

/// The witness's verdict on one T read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContribVerdict {
    Holds,
    Retype { condition: String },
}

impl ContribVerdict {
    /// `holds` or `retyped(<condition>)`, the row's `contrib=` token.
    #[must_use]
    pub fn token(&self) -> String {
        match self {
            Self::Holds => "holds".to_string(),
            Self::Retype { condition } => format!("retyped({condition})"),
        }
    }

    fn retype(condition: impl Into<String>) -> Self {
        Self::Retype {
            condition: condition.into(),
        }
    }
}

/// The intent ids a T read names as its inputs (module doc).
#[must_use]
pub fn named_inputs(book: &BookVariant, read: &Read<'_>) -> BTreeSet<String> {
    let published = read.str("published");
    let basis = read
        .expectation
        .fields
        .strs("basis")
        .unwrap_or_default()
        .to_vec();
    let mut named: BTreeSet<String> = book
        .intents
        .iter()
        .filter(|i| basis.contains(&i.fact) && Some(i.fact.as_str()) != published)
        .map(|i| i.id.clone())
        .collect();
    for id in read
        .expectation
        .fields
        .strs("inputs_named")
        .unwrap_or_default()
    {
        if book.intents.iter().any(|i| &i.id == id) {
            named.insert(id.clone());
        } else {
            named.extend(
                book.intents
                    .iter()
                    .filter(|i| &i.fact == id)
                    .map(|i| i.id.clone()),
            );
        }
    }
    let deltas: BTreeSet<String> = book
        .intents
        .iter()
        .filter(|i| i.is_delta() && i.target.as_deref().is_some_and(|t| named.contains(t)))
        .map(|i| i.id.clone())
        .collect();
    if read.kind() == Some(TKind::Delta) {
        return book
            .intents
            .iter()
            .filter(|i| i.is_delta() && (named.contains(&i.id) || deltas.contains(&i.id)))
            .map(|i| i.id.clone())
            .collect();
    }
    named.extend(deltas);
    named
}

/// The witness (module doc). `b` is the published value in minor units, when
/// it states one in the read's unit.
#[must_use]
pub fn witness(
    case: &Case,
    book: &BookVariant,
    read: &Read<'_>,
    contributions: &[Contribution],
    certified: i128,
    b: Option<i128>,
) -> ContribVerdict {
    if let Some(b) = b
        && contributions
            .iter()
            .any(|c| c.signed.unsigned_abs() == b.unsigned_abs())
    {
        return ContribVerdict::retype("contribution carries B");
    }
    if let Some(published) = read.str("published") {
        let contributing: BTreeSet<String> = contributions
            .iter()
            .filter_map(|c| c.intent.clone())
            .collect();
        let carried = published_closure(case, published);
        let accounts: BTreeSet<String> = contributions.iter().map(|c| c.account.clone()).collect();
        if posted_from(case, book, &accounts)
            .iter()
            .any(|p| contributing.contains(&p.intent) && !p.facts.is_disjoint(&carried))
        {
            return ContribVerdict::retype("contribution carries B");
        }
    }
    if let Some(c) = contributions.iter().find(|c| c.intent.is_none()) {
        return ContribVerdict::retype(format!("extra contribution {}", c.entry));
    }
    let contributing: BTreeSet<String> = contributions
        .iter()
        .filter_map(|c| c.intent.clone())
        .collect();
    let named = named_inputs(book, read);
    if let Some(extra) = contributing.difference(&named).next() {
        return ContribVerdict::retype(format!("extra contribution {extra}"));
    }
    if let Some(missing) = named.difference(&contributing).next() {
        return ContribVerdict::retype(format!("missing named input {missing}"));
    }
    let sum = contributions
        .iter()
        .try_fold(0_i128, |acc, c| acc.checked_add(c.signed));
    if sum != Some(certified) {
        return ContribVerdict::retype("does not re-add");
    }
    ContribVerdict::Holds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::embedded::SELFTEST;
    use crate::cases::trace::t_reads;

    fn selftest() -> Case {
        crate::cases::load(&SELFTEST.case_files()).expect("the self-test loads")
    }

    fn with_read<R>(case: &Case, f: impl FnOnce(&BookVariant, &Read<'_>) -> R) -> R {
        let set = case.expectations.as_ref().expect("expectations");
        let book = case.books.get("native").expect("native");
        let reads = t_reads(set);
        let read = reads
            .iter()
            .find(|r| r.expectation.id == "_selftest-T-01")
            .expect("the bridge T");
        f(book, read)
    }

    fn c(entry: &str, intent: Option<&str>, signed: i128) -> Contribution {
        Contribution {
            entry: entry.to_string(),
            intent: intent.map(str::to_string),
            account: "1100".to_string(),
            signed,
        }
    }

    /// The bridge's A (1,000.00 Dr) and delta (100.00 Cr), re-adding to B.
    fn bridge() -> Vec<Contribution> {
        vec![
            c("a", Some("A-1"), 100_000),
            c("d", Some("delta-A-1"), -10_000),
        ]
    }

    #[test]
    fn named_inputs_are_basis_intents_their_deltas_and_inputs_named() {
        let case = selftest();
        with_read(&case, |book, read| {
            let named = named_inputs(book, read);
            assert_eq!(
                named,
                ["A-1", "delta-A-1"].map(str::to_string).into(),
                "B-1 is published, not an input"
            );
        });
    }

    #[test]
    fn witness_holds_when_contributions_are_exactly_the_named_inputs() {
        let case = selftest();
        with_read(&case, |book, read| {
            assert_eq!(
                witness(&case, book, read, &bridge(), 90_000, Some(90_000)),
                ContribVerdict::Holds
            );
        });
    }

    #[test]
    fn extra_contributing_entry_retypes_r() {
        let case = selftest();
        with_read(&case, |book, read| {
            let mut cs = bridge();
            cs.push(c("x", Some("S-1"), 0));
            assert_eq!(
                witness(&case, book, read, &cs, 90_000, Some(90_000)).token(),
                "retyped(extra contribution S-1)"
            );
            let mut cs = bridge();
            cs.push(c("unmapped-vid", None, 0));
            assert_eq!(
                witness(&case, book, read, &cs, 90_000, Some(90_000)).token(),
                "retyped(extra contribution unmapped-vid)"
            );
        });
    }

    #[test]
    fn missing_named_input_retypes_r() {
        let case = selftest();
        with_read(&case, |book, read| {
            let cs = vec![c("a", Some("A-1"), 100_000)];
            assert_eq!(
                witness(&case, book, read, &cs, 100_000, Some(90_000)).token(),
                "retyped(missing named input delta-A-1)"
            );
        });
    }

    #[test]
    fn contribution_equal_to_b_retypes_r() {
        let case = selftest();
        with_read(&case, |book, read| {
            let cs = vec![
                c("a", Some("A-1"), 100_000),
                c("d", Some("delta-A-1"), -90_000),
            ];
            assert_eq!(
                witness(&case, book, read, &cs, 10_000, Some(90_000)).token(),
                "retyped(contribution carries B)"
            );
        });
    }

    #[test]
    fn contribution_tracing_to_b_through_a_derivation_retypes_r() {
        let mut case = selftest();
        // A's legs post B's value: a read-back dressed as a bridge.
        let book = case.books.get_mut("native").expect("native");
        for leg in book.legs.iter_mut().filter(|l| l.intent == "A-1") {
            leg.amount_rule = "value:B-1#1".into();
        }
        with_read(&case, |book, read| {
            assert_eq!(
                witness(&case, book, read, &bridge(), 90_000, Some(91_000)).token(),
                "retyped(contribution carries B)"
            );
        });
    }

    #[test]
    fn contributions_that_do_not_re_add_fail() {
        let case = selftest();
        with_read(&case, |book, read| {
            assert_eq!(
                witness(&case, book, read, &bridge(), 90_001, Some(90_001)).token(),
                "retyped(does not re-add)"
            );
        });
    }

    #[test]
    fn delta_read_names_only_the_delta_intents() {
        let mut case = selftest();
        let set = case.expectations.as_mut().expect("expectations");
        let t = set
            .expectations
            .iter_mut()
            .find(|e| e.id == "_selftest-T-01")
            .expect("the bridge T");
        t.fields.map.insert(
            "kind".into(),
            crate::cases::expect::Field::Str("delta".into()),
        );
        with_read(&case, |book, read| {
            assert_eq!(
                named_inputs(book, read),
                ["delta-A-1"].map(str::to_string).into()
            );
            assert_eq!(
                witness(&case, book, read, &bridge(), 90_000, None).token(),
                "retyped(extra contribution A-1)"
            );
        });
    }
}
