//! K-VINTAGE (§3.6, §5.3, §10.4, §2.7; bead fa-yugf.8, A3b): a tie-out is
//! pinned to accession-named, latest vintages.
//!
//! - **Roles per kind.** `bridge` names `A:`, `D:` and `B:`; `footing`
//!   `exhibit:`; `per_account`, `allocation` and `rule` `source:`; `delta`
//!   `D:` and no `A:` or `B:` (E-T-03); `round_trip` `B:`. A missing role is
//!   refused.
//! - **The published source.** Each kind's published value comes from its
//!   publishing role (`B` for `bridge` and `round_trip`, `exhibit` for
//!   `footing`, `source` for `per_account`, `allocation` and `rule`, `D` for
//!   `delta`): every sourced fact the published fact rests on must come from
//!   a source named under that role.
//! - **Latest vintage.** A source S′ supersedes the published fact's source
//!   S on its `cell` when S′ is filed later, restates the same figures (its
//!   `restates` closure contains S, or contains a source S's closure
//!   contains: a co-restater, E4), and has a fact with that cell and another
//!   value. A superseded T is refused unless its `read_selector` is
//!   `reported_in:<period>[#<n>]` and that `issue` step files a stub of S.
//! - **The A posting** (`bridge`): every intent outside a case Δ that posts
//!   to an account the read selects posts the `A:` filing's figure. On a
//!   `statement` or `ledger` stem its `evidence` document is a stub of an
//!   `A:` source (§2.7); on a `native` or `migration` stem, whose documented
//!   entries never cite a stub (K-EVID, A3c), its fact is a sourced fact of
//!   an `A:` source.

use std::collections::BTreeSet;

use super::super::book::{BookVariant, StepKind, VariantKind};
use super::super::expect::TKind;
use super::super::fact::Provenance;
use super::super::trace::{Read, fact_closure, read_accounts, t_reads};
use super::super::{Case, EXPECTATIONS_FILE};
use super::{CheckReport, Context};

/// The roles a kind must name, and its publishing role.
const fn roles(kind: TKind) -> (&'static [&'static str], &'static str) {
    match kind {
        TKind::Bridge => (&["A", "D", "B"], "B"),
        TKind::Footing => (&["exhibit"], "exhibit"),
        TKind::PerAccount | TKind::Allocation | TKind::Rule => (&["source"], "source"),
        TKind::Delta => (&["D"], "D"),
        TKind::RoundTrip => (&["B"], "B"),
    }
}

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let reads = case.expectations.as_ref().map(t_reads).unwrap_or_default();
    let mut r = CheckReport::new("K-VINTAGE", reads.len());
    let mut role_checked: BTreeSet<String> = BTreeSet::new();
    for read in &reads {
        r.examined(read.row());
        let mut problems = Vec::new();
        if role_checked.insert(read.expectation.id.clone()) {
            problems.extend(role_problems(read));
        }
        problems.extend(read_problems(case, read));
        for p in problems {
            r.fail(EXPECTATIONS_FILE, read.line(), &read.row(), p);
        }
    }
    r.finish()
}

/// The `(role, source)` pairs of a T's `vintages`.
fn vintages<'e>(read: &Read<'e>) -> Vec<(&'e str, &'e str)> {
    read.expectation
        .fields
        .strs("vintages")
        .unwrap_or(&[])
        .iter()
        .filter_map(|v| v.split_once(':'))
        .collect()
}

fn sources_under<'e>(read: &Read<'e>, role: &str) -> BTreeSet<&'e str> {
    vintages(read)
        .into_iter()
        .filter(|(r, _)| *r == role)
        .map(|(_, s)| s)
        .collect()
}

fn role_problems(read: &Read<'_>) -> Vec<String> {
    let Some(kind) = read.kind() else {
        return vec!["a T row names its `kind`".into()];
    };
    let (need, _) = roles(kind);
    let mut out = Vec::new();
    for role in need {
        if sources_under(read, role).is_empty() {
            out.push(format!("{} names no {role}: accession", kind.as_str()));
        }
    }
    if kind == TKind::Delta {
        for role in ["A", "B"] {
            if !sources_under(read, role).is_empty() {
                out.push(format!(
                    "a delta names its D: accession(s) and no {role}: accession (E-T-03)"
                ));
            }
        }
    }
    out
}

fn read_problems(case: &Case, read: &Read<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let (Some(kind), Some(published)) = (read.kind(), read.str("published")) else {
        return out;
    };
    let (_, role) = roles(kind);
    let named = sources_under(read, role);
    // Every sourced fact the published value rests on comes from a source
    // its publishing role names.
    for f in fact_closure(case, published) {
        if let Some(s) = case
            .facts
            .iter()
            .find(|x| x.id == f)
            .and_then(|x| x.sourced())
            && !named.contains(s.source.as_str())
        {
            out.push(format!(
                "published fact {f} comes from {}, which the T's vintages do not name under {role}:",
                s.source
            ));
        }
    }
    if let Some(problem) = superseded(case, read, published) {
        out.push(problem);
    }
    if kind == TKind::Bridge {
        out.extend(a_posting_problems(case, read));
    }
    out
}

/// The sources `source` restates, transitively.
fn restates_closure(case: &Case, source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut todo = vec![source.to_string()];
    while let Some(s) = todo.pop() {
        let Some(row) = case.sources.iter().find(|x| x.id == s) else {
            continue;
        };
        for r in row.restates.iter().flatten() {
            if out.insert(r.clone()) {
                todo.push(r.clone());
            }
        }
    }
    out
}

fn first_value<'c>(case: &'c Case, fact: &str) -> Option<&'c str> {
    case.values
        .iter()
        .filter(|v| v.fact == fact)
        .min_by_key(|v| v.ordinal)
        .map(|v| v.value.as_str())
}

/// The refusal when a later restating vintage differs on the published
/// fact's cell and the read does not name an issuance of the earlier one.
fn superseded(case: &Case, read: &Read<'_>, published: &str) -> Option<String> {
    let fact = case.facts.iter().find(|f| f.id == published)?;
    let Provenance::Sourced(s) = &fact.provenance else {
        return None;
    };
    let cell = s.cell.as_deref()?;
    let src = case.sources.iter().find(|x| x.id == s.source)?;
    let filed = src.filed_on.as_deref()?;
    let ours = restates_closure(case, &src.id);
    let value = first_value(case, published);
    let later = case.sources.iter().find(|other| {
        let theirs = restates_closure(case, &other.id);
        other.id != src.id
            && other.filed_on.as_deref().is_some_and(|d| d > filed)
            && (theirs.contains(&src.id) || !theirs.is_disjoint(&ours))
            && case.facts.iter().any(|g| {
                g.sourced()
                    .is_some_and(|gs| gs.source == other.id && gs.cell.as_deref() == Some(cell))
                    && first_value(case, &g.id) != value
            })
    })?;
    let book = case.books.get(read.str("book_variant").unwrap_or_default());
    match read
        .str("read_selector")
        .and_then(|sel| sel.strip_prefix("reported_in:"))
    {
        Some(rest) => {
            let stub = book.and_then(|b| issuance_stub(b, rest));
            match stub {
                Some(stub) if stub == src.id => None,
                Some(stub) => Some(format!(
                    "`reported_in:{rest}` names an issuance that files {stub}, not {} (the vintage the T reads; superseded on {cell} by {})",
                    src.id, later.id
                )),
                None => Some(format!(
                    "`reported_in:{rest}` names no issuance with a filing stub"
                )),
            }
        }
        None => Some(format!(
            "B source {} is superseded on cell {cell} by {} (filed {}); read it with `reported_in:<period>[#<n>]` naming an issuance of {}",
            src.id,
            later.id,
            later.filed_on.as_deref().unwrap_or("?"),
            src.id
        )),
    }
}

/// The source whose stub the n-th `issue` step of a period files
/// (`<period>[#<n>]`).
fn issuance_stub(book: &BookVariant, selector: &str) -> Option<String> {
    let (label, n) = match selector.split_once('#') {
        Some((l, n)) => (l, n.parse::<usize>().ok()?),
        None => (selector, 1),
    };
    let step = book
        .steps
        .iter()
        .filter(|s| s.step_kind() == Some(StepKind::Issue) && s.reference == label)
        .nth(n.checked_sub(1)?)?;
    let doc = step.document.as_deref()?;
    book.documents
        .iter()
        .find(|d| d.id == doc)
        .map(|d| d.stub_of.clone())
}

/// A bridge's A postings post an `A:` source's figure: by their evidence
/// stub on a statement or ledger stem, by their fact on an entry-level one.
fn a_posting_problems(case: &Case, read: &Read<'_>) -> Vec<String> {
    let Some(book) = case.books.get(read.str("book_variant").unwrap_or_default()) else {
        return Vec::new();
    };
    let a_sources = sources_under(read, "A");
    let accounts = read_accounts(book, read.str("read_target").unwrap_or_default());
    let intents: BTreeSet<&str> = book
        .legs
        .iter()
        .filter(|l| accounts.contains(&l.account))
        .map(|l| l.intent.as_str())
        .collect();
    let mut out = Vec::new();
    for it in book
        .intents
        .iter()
        .filter(|i| intents.contains(i.id.as_str()) && !i.is_delta())
    {
        if matches!(book.kind, VariantKind::Native | VariantKind::Migration) {
            let source = case
                .facts
                .iter()
                .find(|f| f.id == it.fact)
                .and_then(|f| f.sourced())
                .map(|s| s.source.as_str());
            match source {
                Some(s) if a_sources.contains(s) => {}
                Some(s) => out.push(format!(
                    "A intent {} posts {} of {s}, not of the A: source {a_sources:?}",
                    it.id, it.fact
                )),
                None => out.push(format!(
                    "A intent {} posts {}, not a sourced fact of the A: source {a_sources:?}",
                    it.id, it.fact
                )),
            }
            continue;
        }
        let cites = it
            .evidence
            .as_deref()
            .and_then(|e| book.documents.iter().find(|d| d.id == e))
            .map(|d| d.stub_of.as_str());
        match cites {
            Some(stub) if a_sources.contains(stub) => {}
            Some(stub) => out.push(format!(
                "A intent {} cites a stub of {stub}, not the A: source {a_sources:?}",
                it.id
            )),
            None => out.push(format!(
                "A intent {} cites no filing stub; the A posting cites its A: source {a_sources:?}",
                it.id
            )),
        }
    }
    out
}
