//! Which facts a fact rests on, and which facts the book's postings trace
//! to (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.6, §3.8; bead fa-yugf.8, A3b).
//! K-BASIS, K-TAUT and K-ORACLE share these walks.

use std::collections::{BTreeMap, BTreeSet};

use super::Case;
use super::book::BookVariant;
use super::expect::{Expectation, ExpectationType, Expectations, Fields, TKind, Target};
use super::fact::Provenance;

/// One read of a T row: on the expectation, or on one of its targets when
/// the read fields sit there (A1c).
#[derive(Clone, Copy, Debug)]
pub struct Read<'e> {
    pub expectation: &'e Expectation,
    pub target: Option<&'e Target>,
    pub fields: &'e Fields,
}

impl Read<'_> {
    /// `<expectation>` or `<expectation>/<target fact>`.
    #[must_use]
    pub fn row(&self) -> String {
        match self.target {
            Some(t) => format!("{}/{}", self.expectation.id, t.fact),
            None => self.expectation.id.clone(),
        }
    }

    /// The fields of the read, then the expectation's.
    #[must_use]
    pub fn str(&self, key: &str) -> Option<&str> {
        self.fields
            .str(key)
            .or_else(|| self.expectation.fields.str(key))
    }

    #[must_use]
    pub fn kind(&self) -> Option<TKind> {
        self.expectation.fields.str("kind").and_then(TKind::parse)
    }

    /// The line the read's row starts on.
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        self.fields.line
    }
}

/// Every read of every T row, in file order.
#[must_use]
pub fn t_reads(set: &Expectations) -> Vec<Read<'_>> {
    let mut out = Vec::new();
    for e in set
        .expectations
        .iter()
        .filter(|e| e.kind == ExpectationType::T)
    {
        let on_targets: Vec<&Target> = set.targets_of(&e.id).filter(|t| t.reads_here()).collect();
        if on_targets.is_empty() {
            out.push(Read {
                expectation: e,
                target: None,
                fields: &e.fields,
            });
        } else {
            out.extend(on_targets.into_iter().map(|t| Read {
                expectation: e,
                target: Some(t),
                fields: &t.fields,
            }));
        }
    }
    out
}

/// The accounts a read selects in its variant: the account its
/// `read_target` names; for an account type (a type-level line), every
/// account of that type; for any other line or exported concept, every
/// account of the variant (the conservative reading, plan §3.8).
#[must_use]
pub fn read_accounts(book: &BookVariant, read_target: &str) -> BTreeSet<String> {
    if book.accounts.iter().any(|a| a.code == read_target) {
        return [read_target.to_string()].into();
    }
    let typed: BTreeSet<String> = book
        .accounts
        .iter()
        .filter(|a| a.account_type.eq_ignore_ascii_case(read_target))
        .map(|a| a.code.clone())
        .collect();
    if !typed.is_empty() {
        return typed;
    }
    book.accounts.iter().map(|a| a.code.clone()).collect()
}

/// The facts `fact` rests on, itself included: transitive over
/// `derived.from` and `interpretation.from`.
#[must_use]
pub fn fact_closure(case: &Case, fact: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut todo = vec![fact.to_string()];
    while let Some(id) = todo.pop() {
        if !out.insert(id.clone()) {
            continue;
        }
        if let Some(f) = case.facts.iter().find(|f| f.id == id) {
            todo.extend(from_of(&f.provenance).iter().cloned());
        }
    }
    out
}

/// The facts a fact is computed or read from.
#[must_use]
pub fn from_of(p: &Provenance) -> &[String] {
    match p {
        Provenance::Derived(d) => &d.from,
        Provenance::Interpretation(i) => &i.from,
        Provenance::Sourced(_) | Provenance::Synthetic(_) => &[],
    }
}

/// A chain of fact ids from `from` (which the closure of `to` contains) up
/// to `to`, along `from` edges: `[from, …, to]`.
#[must_use]
pub fn chain(case: &Case, from: &str, to: &str) -> Vec<String> {
    // Breadth-first from `to` down its from-edges, remembering each fact's
    // child, then read the path back.
    let mut child: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<String> = [to.to_string()].into();
    let mut queue = std::collections::VecDeque::from([to.to_string()]);
    while let Some(id) = queue.pop_front() {
        if id == from {
            let mut path = vec![id.clone()];
            let mut at = id;
            while let Some(c) = child.get(&at) {
                path.push(c.clone());
                at = c.clone();
            }
            return path;
        }
        if let Some(f) = case.facts.iter().find(|f| f.id == id) {
            for parent in from_of(&f.provenance) {
                if seen.insert(parent.clone()) {
                    child.insert(parent.clone(), id.clone());
                    queue.push_back(parent.clone());
                }
            }
        }
    }
    vec![from.to_string(), to.to_string()]
}

/// One posting and the facts its amount traces to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posted {
    /// The intent id, or `ledger_map:<source>:<account>` for rows the
    /// runner renders from a `[[ledger_map]]` row (M0).
    pub intent: String,
    pub ordinal: i128,
    pub account: String,
    /// The fact the amount rule names (empty for a negation, whose facts
    /// are its target leg's, and for `branch:`/`synthetic` amounts).
    pub named: Option<String>,
    pub facts: BTreeSet<String>,
}

/// The fact a leg's `amount_rule` names: `value:<fact>#<n>` or
/// `derived:<fact>` (never `derived:negate`).
#[must_use]
pub fn named_fact(rule: &str) -> Option<&str> {
    rule.strip_prefix("value:")
        .and_then(|v| v.split_once('#').map(|(f, _)| f))
        .or_else(|| rule.strip_prefix("derived:").filter(|n| *n != "negate"))
}

/// For each leg of `book` on one of `accounts`, the facts its amount traces
/// to: through `value:` and `derived:` rules to the named fact's closure, and
/// through `derived:negate` to the negated target leg's. A `[[ledger_map]]`
/// row posting to one of the accounts traces to its complaint's rows facts.
#[must_use]
pub fn posted_from(case: &Case, book: &BookVariant, accounts: &BTreeSet<String>) -> Vec<Posted> {
    let mut out = Vec::new();
    for leg in book.legs.iter().filter(|l| accounts.contains(&l.account)) {
        let (named, facts) = leg_facts(case, book, &leg.intent, leg.ordinal, &leg.amount_rule, 0);
        out.push(Posted {
            intent: leg.intent.clone(),
            ordinal: leg.ordinal,
            account: leg.account.clone(),
            named,
            facts,
        });
    }
    for lm in &book.ledger_maps {
        for account in [&lm.book_account, &lm.cash_account, &lm.transfer_account] {
            if !accounts.contains(account) {
                continue;
            }
            let mut facts = BTreeSet::new();
            let mut named = None;
            for f in &case.facts {
                if f.sourced().is_some_and(|s| {
                    s.rows_file.is_some() && s.complaint.as_deref() == Some(lm.source.as_str())
                }) {
                    named.get_or_insert_with(|| f.id.clone());
                    facts.extend(fact_closure(case, &f.id));
                }
            }
            out.push(Posted {
                intent: format!("ledger_map:{}:{}", lm.source, lm.account),
                ordinal: 0,
                account: account.clone(),
                named,
                facts,
            });
        }
    }
    out
}

fn leg_facts(
    case: &Case,
    book: &BookVariant,
    intent: &str,
    ordinal: i128,
    rule: &str,
    depth: usize,
) -> (Option<String>, BTreeSet<String>) {
    if let Some(f) = named_fact(rule) {
        return (Some(f.to_string()), fact_closure(case, f));
    }
    if rule == "derived:negate" && depth < 8 {
        let target = book
            .intents
            .iter()
            .find(|i| i.id == intent)
            .and_then(|i| i.target.as_deref());
        if let Some(target) = target
            && let Some(mirror) = book
                .legs
                .iter()
                .find(|l| l.intent == target && l.ordinal == ordinal)
        {
            return leg_facts(case, book, target, ordinal, &mirror.amount_rule, depth + 1);
        }
    }
    (None, BTreeSet::new())
}
