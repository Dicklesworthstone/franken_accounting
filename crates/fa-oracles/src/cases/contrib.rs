//! The contributing-entry witness for T rows (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.7 item 2; bead fa-yugf.26, A11b): the dynamic half of K-TAUT.
//!
//! A T holds only if none of the postings its certified value folds carries
//! the published comparison value B (directly, or through a derivation that
//! traces to B), those postings are exactly the ones its predicate names as
//! inputs, and they re-add to the certified value, checked in that order.
//! Any failure re-types the T as R, its condition named: `extra
//! contribution <id>`, `missing named input <id>`, `contribution carries B`
//! or `does not re-add`.
//!
//! The named inputs are computed, never authored: every intent of the T's
//! `basis` facts other than its `published` one, every intent (or intent of
//! a fact) its `inputs_named` lists, and every delta (`restates` or
//! `revises`) whose target is one of those. A `delta` T's named inputs are
//! its deltas alone: an A posting does not move a delta.
//!
//! The fold is the read's, never the account's. `fa explain balance`
//! explains one period's cells, so a stock read is explained in every
//! declared period through its own and a flow read in its own periods
//! only ([`fold_periods`]). A statement line folds each account its
//! registered definition maps to it, signed as the line signs it
//! ([`line_terms`]), on the definition's basis: a balance sheet is stock,
//! and maps the Revenue and Expense accounts as unclosed earnings of every
//! year; an income statement is activity, with Closing entries set aside.

use std::collections::{BTreeMap, BTreeSet};

use super::Case;
use super::book::{BookVariant, PeriodDef};
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

/// The registered standard statement definition a read verb names.
#[must_use]
pub fn definition(verb: &str) -> Option<&'static str> {
    match verb {
        "balance-sheet" => Some(include_str!(
            "../../../../registries/statements/balance-sheet.toml"
        )),
        "income-statement" => Some(include_str!(
            "../../../../registries/statements/income-statement.toml"
        )),
        _ => None,
    }
}

/// Whether a statement definition's basis is stock (`basis = "stock"`).
#[must_use]
pub fn stock_basis(definition: &str) -> bool {
    fa_registry::toml::parse(definition)
        .ok()
        .and_then(|d| {
            d.root
                .get("basis")
                .and_then(|b| b.as_str().map(str::to_string))
        })
        .as_deref()
        == Some("stock")
}

/// The entry classes a statement definition sets aside
/// (`excluded_classes`): Closing, on the income statement.
#[must_use]
pub fn excluded_classes(definition: &str) -> Vec<String> {
    fa_registry::toml::parse(definition)
        .ok()
        .and_then(|d| d.root.get("excluded_classes").cloned())
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// A statement line's terms: each account type it folds and the sign it
/// applies to that type's debit-positive net (+1 for a `debit` line, -1 for
/// a `credit` one), through the `add` and `subtract` lines it composes.
///
/// # Errors
/// The definition does not parse, names no such line, or composes in a
/// cycle.
pub fn line_terms(definition: &str, line: &str) -> Result<BTreeMap<String, i128>, String> {
    let doc = fa_registry::toml::parse(definition).map_err(|e| format!("definition: {e:?}"))?;
    let lines = doc
        .arrays
        .get("line")
        .ok_or("a definition with no [[line]]")?;
    let mut terms = BTreeMap::new();
    add_terms(lines, line, 1, 0, &mut terms)?;
    terms.retain(|_, m| *m != 0);
    Ok(terms)
}

fn add_terms(
    lines: &[fa_registry::toml::Table],
    code: &str,
    sign: i128,
    depth: usize,
    terms: &mut BTreeMap<String, i128>,
) -> Result<(), String> {
    if depth > 16 {
        return Err(format!("line {code} composes in a cycle"));
    }
    let row = lines
        .iter()
        .find(|l| l.get("code").and_then(|c| c.as_str()) == Some(code))
        .ok_or_else(|| format!("no line {code}"))?;
    let strs = |key: &str| -> Vec<String> {
        row.get(key)
            .and_then(|v| v.as_array())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    };
    let types = strs("account_types");
    if !types.is_empty() {
        let side = if row.get("sign").and_then(|s| s.as_str()) == Some("credit") {
            -1
        } else {
            1
        };
        for ty in types {
            *terms.entry(ty).or_insert(0) += sign * side;
        }
        return Ok(());
    }
    for part in strs("add") {
        add_terms(lines, &part, sign, depth + 1, terms)?;
    }
    for part in strs("subtract") {
        add_terms(lines, &part, -sign, depth + 1, terms)?;
    }
    Ok(())
}

/// Whether account `code` is a stock account (Asset, Liability, Equity).
#[must_use]
pub fn is_stock(book: &BookVariant, code: &str) -> bool {
    book.accounts.iter().any(|a| {
        a.code == code && matches!(a.account_type.as_str(), "Asset" | "Liability" | "Equity")
    })
}

/// The declared periods a read at `coordinate` folds, in calendar order:
/// every period through the read's end for a stock fold, the read's own
/// periods for a flow fold (a fiscal year, `FY<yyyy>`, is each of its).
#[must_use]
pub fn fold_periods(book: &BookVariant, stock: bool, coordinate: &str) -> Option<Vec<String>> {
    let own: Vec<&PeriodDef> = match book.periods.iter().find(|p| p.code == coordinate) {
        Some(p) => vec![p],
        None => {
            let fy: i128 = coordinate.strip_prefix("FY")?.parse().ok()?;
            book.periods
                .iter()
                .filter(|p| p.fiscal_year == fy)
                .collect()
        }
    };
    let end = own.iter().map(|p| p.end.as_str()).max()?;
    let mut periods: Vec<&PeriodDef> = if stock {
        book.periods
            .iter()
            .filter(|p| p.end.as_str() <= end)
            .collect()
    } else {
        own
    };
    periods.sort_by(|a, b| a.end.cmp(&b.end));
    Some(periods.into_iter().map(|p| p.code.clone()).collect())
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

    fn two_quarters() -> BookVariant {
        selftest().books.get("native").expect("native").clone()
    }

    #[test]
    fn stock_read_unions_every_period_through_the_t_period() {
        let book = two_quarters();
        assert_eq!(
            fold_periods(&book, true, "2026Q2"),
            Some(vec!["2026Q1".to_string(), "2026Q2".to_string()])
        );
        assert_eq!(
            fold_periods(&book, true, "2026Q1"),
            Some(vec!["2026Q1".to_string()])
        );
        assert!(is_stock(&book, "1100"));
        assert!(!is_stock(&book, "4000"));
    }

    #[test]
    fn flow_read_explains_only_its_coordinates_periods() {
        let book = two_quarters();
        assert_eq!(
            fold_periods(&book, false, "2026Q2"),
            Some(vec!["2026Q2".to_string()])
        );
        // A fiscal-year flow read is each of the year's periods.
        assert_eq!(
            fold_periods(&book, false, "FY2026"),
            Some(vec!["2026Q1".to_string(), "2026Q2".to_string()])
        );
        assert_eq!(fold_periods(&book, false, "2027Q1"), None);
    }

    #[test]
    fn balance_sheet_total_equity_unions_its_unclosed_earnings_accounts() {
        let bs = definition("balance-sheet").expect("the balance sheet");
        assert!(stock_basis(bs));
        assert!(excluded_classes(bs).is_empty());
        assert_eq!(
            // Credit equity plus credit revenue less debit expense, in
            // debit-positive terms: every type at -1.
            line_terms(bs, "total_equity").expect("total_equity"),
            [("Equity", -1), ("Expense", -1), ("Revenue", -1)]
                .map(|(t, m)| (t.to_string(), m))
                .into()
        );
        assert_eq!(
            line_terms(bs, "assets").expect("assets"),
            [("Asset".to_string(), 1)].into()
        );
        let is = definition("income-statement").expect("the income statement");
        assert!(!stock_basis(is));
        assert_eq!(excluded_classes(is), ["Closing".to_string()]);
        assert_eq!(
            line_terms(is, "net_income").expect("net_income"),
            [("Expense", -1), ("Revenue", -1)]
                .map(|(t, m)| (t.to_string(), m))
                .into()
        );
        assert!(line_terms(is, "goodwill").is_err());
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
