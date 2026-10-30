//! The committed Enron case at load time (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §7.1, §15 E1): the sources ledger and its four assurance facts load and
//! bind offline, and each planted negative edits an in-memory copy of the
//! embedded case text and is refused by the check that owns it. The
//! committed files are never edited. E2a-E2d and E4 add theirs here: the
//! books load and balance, every posted amount derives from as-filed cells
//! and published adjustments (K-TAUT), the stock changes recompute
//! (K-DERIVE), and the superseded 8-K vintage needs its issuance
//! (K-VINTAGE).

use std::collections::{BTreeMap, BTreeSet};

use fa_oracles::cases::amount::parse_amount;
use fa_oracles::cases::book::LegDef;
use fa_oracles::cases::check::{CheckReport, Verdict, run_load_checks};
use fa_oracles::cases::embedded::ENRON;
use fa_oracles::cases::error::{LoadError, LoadErrorKind};
use fa_oracles::cases::expect::ExpectationType;
use fa_oracles::cases::fact::{self, Granularity};
use fa_oracles::cases::source::{self, AnchorKind, Assurance, SourceStatus};
use fa_oracles::cases::trace::fact_closure;
use fa_oracles::cases::{Case, CaseFiles, load};

type Files = Vec<(&'static str, String)>;

/// The ledger's six rows, in file order.
const SOURCES: [&str; 6] = [
    "SRC-ENR-001",
    "SRC-ENR-002",
    "SRC-ENR-003",
    "SRC-ENR-005",
    "SRC-ENR-008",
    "SRC-ENR-402",
];

fn enron() -> Files {
    ENRON
        .files
        .iter()
        .map(|(path, text)| (*path, (*text).to_string()))
        .collect()
}

fn text<'a>(files: &'a Files, file: &str) -> &'a str {
    &files
        .iter()
        .find(|(p, _)| *p == file)
        .expect("a case file")
        .1
}

fn text_mut<'a>(files: &'a mut Files, file: &str) -> &'a mut String {
    &mut files
        .iter_mut()
        .find(|(p, _)| *p == file)
        .expect("a case file")
        .1
}

/// The row of `file` that holds `marker` (from its `[[...]]` header to the
/// next one) with `old` replaced by `new`; `marker` occurs once in the file
/// and `old` once in that row, so a stale plant never silently tests nothing.
fn edit_row(files: &mut Files, file: &str, marker: &str, old: &str, new: &str) {
    let t = text_mut(files, file);
    assert_eq!(t.matches(marker).count(), 1, "marker `{marker}` in {file}");
    let at = t.find(marker).expect("the marker");
    let start = t[..at].rfind("[[").expect("a row header");
    let end = t[at..].find("\n[[").map_or(t.len(), |e| at + e);
    let row = &t[start..end];
    assert_eq!(
        row.matches(old).count(),
        1,
        "plant `{old}` in the `{marker}` row"
    );
    let edited = row.replacen(old, new, 1);
    t.replace_range(start..end, &edited);
}

/// The 1-based line of the `[[...]]` header of the row holding `marker`.
fn row_header_line(files: &Files, file: &str, marker: &str) -> usize {
    let t = text(files, file);
    let at = t.find(marker).expect("the marker");
    let start = t[..at].rfind("[[").expect("a row header");
    t[..start].matches('\n').count() + 1
}

fn load_copy(files: &Files) -> Result<Case, Vec<LoadError>> {
    let view: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
    load(&CaseFiles {
        id: ENRON.id,
        files: &view,
    })
}

/// The load is refused with an error of `kind` in `file` on row `row` at
/// `line` whose detail contains every `needle`.
fn refused(
    files: &Files,
    kind: LoadErrorKind,
    file: &str,
    row: &str,
    line: usize,
    needles: &[&str],
) {
    let errs = load_copy(files).err().unwrap_or_default();
    assert!(
        errs.iter().any(|e| e.kind == kind
            && e.file == file
            && e.row.as_deref() == Some(row)
            && e.line == Some(line)
            && needles.iter().all(|n| e.detail.contains(n))),
        "no {kind:?} in {file}:{line} on {row} naming {needles:?}: {errs:#?}"
    );
}

/// The committed case loads, and every load check that has input rows
/// passes: the four assurance facts lead the facts, every sourced fact
/// (E2d's 2000-12-31 balance-sheet cells included) binds offline through
/// its receipt, and each vintage prints 35 lines and 3 totals.
#[test]
fn enron_ledger_binds_offline() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let ids: Vec<&str> = case.facts.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids[..4],
        [
            "ASSUR-ENR-002",
            "ASSUR-ENR-003",
            "ASSUR-ENR-008",
            "ASSUR-ENR-402"
        ]
    );
    let sourced = case.facts.iter().filter(|f| f.sourced().is_some()).count();
    assert_eq!(case.receipts.len(), sourced);
    for prefix in ["BS10K-", "BS10Q-"] {
        let cells = ids
            .iter()
            .filter(|id| id.starts_with(prefix) && !id.ends_with("-SFC"))
            .count();
        assert_eq!(cells, 38, "{prefix}");
    }
    for report in run_load_checks(&case) {
        assert_ne!(
            report.verdict,
            Verdict::Fail,
            "{}",
            report.render(Some("enron"))
        );
    }
}

#[test]
fn enron_sources_roundtrip() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let parsed = fa_registry::toml::parse(text(&enron(), "sources.toml"))
        .expect("parses")
        .canonical_bytes();
    assert_eq!(source::to_document(&case.sources).canonical_bytes(), parsed);
}

/// Each row is OK and carries every §4.1 field; each filer row names its
/// assurance and the fact establishing it, and each anchor scheme draws on
/// the §4.1 kinds the row's facts use.
#[test]
fn enron_sources_all_ok_rows_have_fields() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let ids: Vec<&str> = case.sources.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, SOURCES);
    for s in &case.sources {
        assert_eq!(s.status, SourceStatus::Ok, "{}", s.id);
        for (field, value) in [
            ("title", Some(s.title.as_str())),
            ("publisher", Some(s.publisher.as_str())),
            ("original_url", Some(s.original_url.as_str())),
            ("retrieved_utc", Some(s.retrieved_utc.as_str())),
            ("sha256", Some(s.sha256.as_str())),
            ("filed_on", s.filed_on.as_deref()),
            ("notes", s.notes.as_deref()),
        ] {
            assert!(value.is_some_and(|v| !v.is_empty()), "{} {field}", s.id);
        }
        assert_eq!(s.extraction.as_ref().map(Vec::len), Some(3), "{}", s.id);
        assert!(!s.anchor_scheme.is_empty(), "{}", s.id);
        let filer = s.assertion_status.is_filer_statement();
        let assured = s.assurance.is_some_and(|a| a != Assurance::NotApplicable);
        assert_eq!(filer, assured, "{}", s.id);
        assert_eq!(filer, s.assurance_fact.is_some(), "{}", s.id);
    }
    let scheme = |id: &str| {
        case.sources
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.anchor_scheme.clone())
            .expect("a row")
    };
    assert_eq!(
        scheme("SRC-ENR-001"),
        [AnchorKind::Paragraph, AnchorKind::Page]
    );
    assert_eq!(scheme("SRC-ENR-005"), [AnchorKind::Page]);
    for id in ["SRC-ENR-002", "SRC-ENR-003", "SRC-ENR-008", "SRC-ENR-402"] {
        assert_eq!(
            scheme(id),
            [AnchorKind::TableCell, AnchorKind::Line],
            "{id}"
        );
    }
}

#[test]
fn enron_fact_citing_blocked_row_refused() {
    let mut files = enron();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-ENR-003\"\n",
        "status = \"OK\"",
        "status = \"BLOCKED\"\nstatus_reason = \"test\"",
    );
    let line = row_header_line(&files, "facts.toml", "id = \"ASSUR-ENR-003\"\n");
    refused(
        &files,
        LoadErrorKind::UnknownValue,
        "facts.toml",
        "ASSUR-ENR-003",
        line,
        &["SRC-ENR-003", "BLOCKED"],
    );
}

/// A receipt copies its source row's `original_hash_compared`; it is not a
/// binding boolean, so a receipt that differs is refused.
#[test]
fn enron_receipt_hash_compared_must_match_source() {
    let mut files = enron();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"ASSUR-ENR-008\"\n",
        "original_hash_compared = false",
        "original_hash_compared = true",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"ASSUR-ENR-008\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "ASSUR-ENR-008",
        line,
        &["original_hash_compared = true", "SRC-ENR-008"],
    );
}

/// ASSUR-ENR-003 anchored by a paragraph, a prose kind SRC-ENR-003's
/// scheme does not name, fails K-ANCHOR (its receipt's sentence alignment
/// still matches, so the loader does not stop the copy first).
#[test]
fn enron_anchor_kind_outside_scheme_refused() {
    let mut files = enron();
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"ASSUR-ENR-003\"\n",
        "anchor_kind = \"line\"\nanchor = \"l497-503\"",
        "anchor_kind = \"paragraph\"\nanchor = \"para1\"",
    );
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"ASSUR-ENR-003\"\n",
        "anchor = \"l497-503\"",
        "anchor = \"para1\"",
    );
    let case = load_copy(&files).expect("the planted copy loads");
    let report = run_load_checks(&case)
        .into_iter()
        .find(|r| r.check == "K-ANCHOR")
        .expect("K-ANCHOR ran");
    assert_eq!(
        report.verdict,
        Verdict::Fail,
        "{}",
        report.render(Some("enron"))
    );
    assert!(
        report.failures.iter().any(|f| f.row == "ASSUR-ENR-003"
            && f.reason
                .contains("`paragraph` is not in source SRC-ENR-003's anchor_scheme")),
        "{:#?}",
        report.failures
    );
}

/// A prose fact's receipt claiming value alignment is refused by the
/// receipt cross-check, naming the fact, its anchor kind and the field.
#[test]
fn enron_receipt_alignment_wrong_for_anchor_kind_refused() {
    let mut files = enron();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"ASSUR-ENR-008\"\n",
        "alignment = \"sentence\"",
        "alignment = \"value\"",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"ASSUR-ENR-008\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "ASSUR-ENR-008",
        line,
        &[
            "alignment = \"value\"",
            "`line` fact",
            "expected `sentence`",
        ],
    );
}

/// What K-VINTAGE orders by: the 8-K and the later 10-Q each restate the
/// as-filed 10-Ks, the FY2000 10-K restates (reclassifies) the FY1999
/// one, and no other row restates anything.
#[test]
fn enron_sources_vintage_order() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let row = |id: &str| {
        case.sources
            .iter()
            .find(|s| s.id == id)
            .expect("a row")
            .clone()
    };
    let (eight_k, ten_q) = (row("SRC-ENR-002"), row("SRC-ENR-003"));
    let restates = |r: &source::Source| r.restates.clone().unwrap_or_default();
    for r in [&eight_k, &ten_q] {
        assert_eq!(restates(r), ["SRC-ENR-008", "SRC-ENR-402"], "{}", r.id);
    }
    assert_eq!(eight_k.filed_on.as_deref(), Some("2001-11-08"));
    assert_eq!(ten_q.filed_on.as_deref(), Some("2001-11-19"));
    assert!(ten_q.filed_on > eight_k.filed_on);
    assert_eq!(restates(&row("SRC-ENR-008")), ["SRC-ENR-402"]);
    for id in ["SRC-ENR-001", "SRC-ENR-005", "SRC-ENR-402"] {
        assert!(restates(&row(id)).is_empty(), "{id}");
    }
    // A copy whose 10-Q restates a source the ledger lacks is refused,
    // naming the row.
    let mut files = enron();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-ENR-003\"\n",
        "restates = [\"SRC-ENR-008\", \"SRC-ENR-402\"]",
        "restates = [\"SRC-ENR-499\"]",
    );
    let line = row_header_line(&files, "sources.toml", "id = \"SRC-ENR-003\"\n");
    refused(
        &files,
        LoadErrorKind::DanglingKey,
        "sources.toml",
        "SRC-ENR-003",
        line,
        &["SRC-ENR-499"],
    );
}

/// A fact's first value, in minor units.
fn minor(case: &Case, fact: &str) -> i128 {
    case.values
        .iter()
        .find(|v| v.fact == fact && v.ordinal == 1)
        .and_then(|v| v.value.parse().ok())
        .unwrap_or_else(|| panic!("a value of {fact}"))
}

/// A leg's amount in minor units, debits positive.
fn signed(leg: &LegDef) -> i128 {
    let amount = parse_amount(&leg.amount_literal, 2).expect("an amount literal");
    if leg.side == "Dr" { amount } else { -amount }
}

/// The report of `check` over `case`.
fn report(case: &Case, check: &str) -> CheckReport {
    run_load_checks(case)
        .into_iter()
        .find(|r| r.check == check)
        .unwrap_or_else(|| panic!("{check} ran"))
}

/// A bridge cell's role by its id (E2d): `A` for an as-filed figure (the
/// FY2000 10-K's, its balance-sheet totals included), `D` for a published
/// adjustment (`D<k>` columns and the Raptor line), `B` for a restated one.
fn role(fact: &str) -> &str {
    if fact.starts_with("BS10K-") {
        return "A";
    }
    if fact.contains("-RAPTOR-") {
        return "D";
    }
    let parts: Vec<&str> = fact.split('-').collect();
    match parts.len().checked_sub(2).map(|i| parts[i]) {
        Some(r) if r.starts_with('D') && r.len() == 2 => "D",
        Some("A") => "A",
        Some("B") => "B",
        _ => "-",
    }
}

/// The fact a leg's `value:<fact>#<n>` or `derived:<fact>` rule names.
fn rule_fact(rule: &str) -> &str {
    rule.strip_prefix("value:")
        .and_then(|v| v.split_once('#').map(|(f, _)| f))
        .or_else(|| rule.strip_prefix("derived:"))
        .unwrap_or_else(|| panic!("a value: or derived: rule, not {rule}"))
}

/// The 10-Q bridge book's stock lines: account, natural sign, and the
/// as-filed year-end figure each year posts (FY1997-FY2000).
const STOCKS: [(&str, i128, [&str; 4]); 3] = [
    (
        "1000",
        1,
        [
            "10K-TA-A-FY1997",
            "10K-TA-A-FY1998",
            "10K-TA-A-FY1999",
            "BS10K-TOTAL-ASSETS",
        ],
    ),
    (
        "2100",
        -1,
        [
            "10K-DEBT-A-FY1997",
            "10K-DEBT-A-FY1998",
            "10K-DEBT-A-FY1999",
            "10K-DEBT-A-FY2000",
        ],
    ),
    (
        "3000",
        -1,
        [
            "10K-EQ-A-FY1997",
            "10K-EQ-A-FY1998",
            "10K-EQ-A-FY1999",
            "BS10K-TOTAL-EQUITY",
        ],
    ),
];
const YEAR_ENDS: [&str; 4] = ["1997-12-31", "1998-12-31", "1999-12-31", "2000-12-31"];

/// E4's books load (A1b): the two footing books and the two bridge books,
/// every intent of each balancing per unit in exact minor units; the
/// 10-Q's bridge book holds FY1997-FY2000, fifteen as-filed postings and
/// twenty-two restating ones.
#[test]
fn enron_e4_books_load() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let stems: Vec<&str> = case.books.keys().map(String::as_str).collect();
    assert_eq!(
        stems,
        [
            "statement-10k2000",
            "statement-10q2001q3",
            "statement-bridge-10q",
            "statement-bridge-8k-fy1999"
        ]
    );
    for book in case.books.values() {
        for it in &book.intents {
            let mut net: BTreeMap<&str, i128> = BTreeMap::new();
            for leg in book.legs.iter().filter(|l| l.intent == it.id) {
                *net.entry(leg.unit.as_str()).or_default() += signed(leg);
            }
            assert!(
                !net.is_empty() && net.values().all(|v| *v == 0),
                "{} {}: {net:?}",
                book.stem,
                it.id
            );
        }
    }
    let ten_q = &case.books["statement-bridge-10q"];
    let periods: Vec<&str> = ten_q.periods.iter().map(|p| p.code.as_str()).collect();
    assert_eq!(periods, ["FY1997", "FY1998", "FY1999", "FY2000"]);
    let class = |c: &str| ten_q.intents.iter().filter(|i| i.class == c).count();
    assert_eq!((class("Original"), class("Restatement")), (15, 22));
}

/// K-TAUT (§3.8): on the bridge books every leg's amount is an as-filed
/// value, a published adjustment, or a sum or difference of those, never a
/// restated figure, so no T read is re-typed. A copy that derives FY1999's
/// total-assets change from the restated N3-TA-B-FY1999 instead of the
/// as-filed figure (its amounts moved with it, so it still balances and
/// recomputes) is re-typed R at load, the path naming that cell and leg.
#[test]
fn enron_e4_postings_from_a_and_delta_only() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let taut = report(&case, "K-TAUT");
    assert_ne!(
        taut.verdict,
        Verdict::Fail,
        "{}",
        taut.render(Some("enron"))
    );
    assert!(taut.retypes.is_empty(), "{:?}", taut.retypes);
    let set = case.expectations.as_ref().expect("expectations");
    let restated: BTreeSet<&str> = set
        .expectations
        .iter()
        .filter(|e| matches!(e.id.as_str(), "E-T-01" | "E-T-04"))
        .flat_map(|e| set.targets_of(&e.id))
        .map(|t| t.fact.as_str())
        .collect();
    assert_eq!(restated.len(), 18);
    for stem in ["statement-bridge-10q", "statement-bridge-8k-fy1999"] {
        for leg in &case.books[stem].legs {
            let closure = fact_closure(&case, rule_fact(&leg.amount_rule));
            for f in &closure {
                assert!(!restated.contains(f.as_str()), "{stem} {}: {f}", leg.intent);
                let sourced = case
                    .facts
                    .iter()
                    .any(|x| &x.id == f && x.sourced().is_some());
                assert!(
                    !sourced || matches!(role(f), "A" | "D"),
                    "{stem} {}: {f} is neither an as-filed figure nor an adjustment",
                    leg.intent
                );
            }
        }
    }
    let mut files = enron();
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"10K-TA-A-CHG-FY1999\"\n",
        "from = [\"10K-TA-A-FY1999\", \"10K-TA-A-FY1998\"]",
        "from = [\"N3-TA-B-FY1999\", \"10K-TA-A-FY1998\"]",
    );
    edit_row(
        &mut files,
        "facts.toml",
        "fact = \"10K-TA-A-CHG-FY1999\"\n",
        "literal = \"403100000000\"\nrule = \"scale\"\nparam = 0\nvalue = \"403100000000\"",
        "literal = \"392200000000\"\nrule = \"scale\"\nparam = 0\nvalue = \"392200000000\"",
    );
    for ordinal in [0, 1] {
        edit_row(
            &mut files,
            "books/statement-bridge-10q.toml",
            &format!("intent = \"10K-TA-A-FY1999\"\nordinal = {ordinal}\n"),
            "amount_literal = \"4031000000.00\"",
            "amount_literal = \"3922000000.00\"",
        );
    }
    let planted = load_copy(&files).expect("the planted copy loads");
    assert_ne!(report(&planted, "K-DERIVE").verdict, Verdict::Fail);
    let retypes = report(&planted, "K-TAUT").retypes;
    assert!(
        retypes.iter().any(|r| r.expectation == "E-T-01"
            && r.target.as_deref() == Some("N3-TA-B-FY1999")
            && r.to == ExpectationType::R
            && r.path.iter().any(|p| p == "N3-TA-B-FY1999")
            && r.path.iter().any(|p| p.starts_with("leg 10K-TA-A-FY1999#"))),
        "{retypes:?}"
    );
}

/// The stock postings (E4): each stock line of the 10-Q's bridge book posts
/// its FY1997 figure and then each year's change from consecutive as-filed
/// cells, so its as-filed legs through every year-end re-add to that year's
/// printed figure; a change below zero posts on the other side (FY1998's
/// total-assets adjustment, 92 - 372 = -280 $M, credits total assets). A
/// copy with one change off by 1,000,000.00 fails K-DERIVE, naming it.
#[test]
fn enron_e4_stock_differences() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let book = &case.books["statement-bridge-10q"];
    let intent = |id: &str| {
        book.intents
            .iter()
            .find(|i| i.id == id)
            .expect("the leg's intent")
    };
    for (account, sign, figures) in STOCKS {
        for (end, figure) in YEAR_ENDS.iter().zip(figures) {
            let net: i128 = book
                .legs
                .iter()
                .filter(|l| l.account == account)
                .filter(|l| {
                    let it = intent(&l.intent);
                    it.class == "Original" && it.effective_date.as_str() <= *end
                })
                .map(signed)
                .sum();
            assert_eq!(net * sign, minor(&case, figure), "{account} at {end}");
        }
    }
    assert_eq!(minor(&case, "N3-TA-D-CHG-FY1998"), -28_000_000_000);
    let leg = book
        .legs
        .iter()
        .find(|l| l.intent == "delta-10K-TA-A-FY1998" && l.account == "1000")
        .expect("the FY1998 total-assets adjustment's leg");
    assert_eq!((leg.side.as_str(), signed(leg)), ("Cr", -28_000_000_000));
    assert_ne!(
        report(&case, "K-DERIVE").verdict,
        Verdict::Fail,
        "the committed derivations recompute"
    );
    let mut files = enron();
    edit_row(
        &mut files,
        "facts.toml",
        "fact = \"10K-DEBT-A-CHG-FY1999\"\n",
        "literal = \"79500000000\"\nrule = \"scale\"\nparam = 0\nvalue = \"79500000000\"",
        "literal = \"79600000000\"\nrule = \"scale\"\nparam = 0\nvalue = \"79600000000\"",
    );
    let planted = load_copy(&files).expect("the planted copy loads");
    let derive = report(&planted, "K-DERIVE");
    assert_eq!(derive.verdict, Verdict::Fail);
    assert!(
        derive
            .failures
            .iter()
            .any(|f| f.file == "facts.toml" && f.row == "10K-DEBT-A-CHG-FY1999"),
        "{}",
        derive.render(Some("enron"))
    );
}

/// Equity and net income post apart (ENR-BRIDGE-10Q): no net-income leg
/// touches the equity account, whose legs are equity's own (as filed and
/// restated) and re-add to each year's restated equity alone; net income
/// posts on its revenue account against its own equity offset (3900),
/// which no read selects.
#[test]
fn enron_e4_equity_excludes_year_ni() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let book = &case.books["statement-bridge-10q"];
    let line_of = |intent: &str| {
        let it = book
            .intents
            .iter()
            .find(|i| i.id == intent)
            .expect("an intent");
        let fact = it.target.as_deref().unwrap_or(it.fact.as_str());
        if fact.contains("-NI-") {
            "NI"
        } else if fact.contains("-EQ-") || fact == "BS10K-TOTAL-EQUITY" {
            "EQ"
        } else {
            "other"
        }
    };
    for leg in &book.legs {
        match line_of(&leg.intent) {
            "NI" => assert!(
                matches!(leg.account.as_str(), "3900" | "4000"),
                "{}",
                leg.intent
            ),
            _ => assert_ne!(leg.account, "3900", "{}", leg.intent),
        }
        if leg.account == "3000" {
            assert_eq!(line_of(&leg.intent), "EQ", "{}", leg.intent);
        }
    }
    for (end, b) in YEAR_ENDS.iter().zip([
        "N3-EQ-B-FY1997",
        "N3-EQ-B-FY1998",
        "N3-EQ-B-FY1999",
        "BS10Q-TOTAL-EQUITY",
    ]) {
        let net: i128 = book
            .legs
            .iter()
            .filter(|l| l.account == "3000")
            .filter(|l| {
                book.intents
                    .iter()
                    .any(|i| i.id == l.intent && i.effective_date.as_str() <= *end)
            })
            .map(signed)
            .sum();
        assert_eq!(-net, minor(&case, b), "equity at {end}");
    }
    let set = case.expectations.as_ref().expect("expectations");
    assert!(
        set.expectations
            .iter()
            .flat_map(|e| set.targets_of(&e.id))
            .all(|t| t.fields.str("read_target") != Some("3900"))
    );
}

/// K-VINTAGE (§10.4): the 10-Q restates the 8-K's FY1999 cells eleven days
/// later with other values, so E-T-04 reads the 8-K's issuance. A copy
/// reading its total assets as currently stated fails K-VINTAGE on that
/// read.
#[test]
fn enron_e4_8k_vintage_without_as_reported_in_refused() {
    let case = load_copy(&enron()).expect("the committed case loads");
    assert_ne!(report(&case, "K-VINTAGE").verdict, Verdict::Fail);
    let mut files = enron();
    edit_row(
        &mut files,
        "expectations.toml",
        "published = \"8K-TA-B-FY1999\"",
        "read_selector = \"reported_in:FY1999#2\"",
        "read_selector = \"currently_stated\"",
    );
    let planted = load_copy(&files).expect("the planted copy loads");
    let vintage = report(&planted, "K-VINTAGE");
    assert_eq!(vintage.verdict, Verdict::Fail);
    assert!(
        vintage
            .failures
            .iter()
            .any(|f| f.row == "E-T-04/8K-TA-B-FY1999"),
        "{}",
        vintage.render(Some("enron"))
    );
}

/// The 8-K's FY1999 cells foot, a check of the extracted values against the
/// filing's own arithmetic (no claim): 893 - 153 - 95 - 2 = 643; 33,381 +
/// 187 - 222 - 147 = 33,199; 9,570 - 540 - 166 - 128 = 8,736 ($M; the
/// Raptor column prints a dash for FY1999). A copy reading the first
/// net-income adjustment as -152 fails K-BIND, naming 8K-NI-D1-FY1999, and
/// breaks the footing.
#[test]
fn enron_e2d_8k_fy1999_arithmetic() {
    let foots = |case: &Case| -> Vec<(&'static str, i128, i128)> {
        ["NI", "TA", "EQ"]
            .into_iter()
            .map(|line| {
                let a = minor(case, &format!("10K-{line}-A-FY1999"));
                let d: i128 = ["D1", "D2", "D4"]
                    .iter()
                    .map(|k| minor(case, &format!("8K-{line}-{k}-FY1999")))
                    .sum();
                (line, a + d, minor(case, &format!("8K-{line}-B-FY1999")))
            })
            .collect()
    };
    let case = load_copy(&enron()).expect("the committed case loads");
    for (line, sum, b) in foots(&case) {
        assert_eq!(sum, b, "{line}");
    }
    assert_eq!(minor(&case, "8K-NI-B-FY1999"), 64_300_000_000);
    let mut files = enron();
    edit_row(
        &mut files,
        "facts.toml",
        "fact = \"8K-NI-D1-FY1999\"\n",
        "literal = \"(153)\"\nrule = \"scale\"\nparam = 6\nvalue = \"-15300000000\"",
        "literal = \"(152)\"\nrule = \"scale\"\nparam = 6\nvalue = \"-15200000000\"",
    );
    let planted = load_copy(&files).expect("the planted copy loads");
    let bind = report(&planted, "K-BIND");
    assert_eq!(bind.verdict, Verdict::Fail);
    assert!(
        bind.failures.iter().any(|f| f.row == "8K-NI-D1-FY1999"),
        "{}",
        bind.render(Some("enron"))
    );
    let broken: Vec<&str> = foots(&planted)
        .into_iter()
        .filter(|(_, sum, b)| sum != b)
        .map(|(line, ..)| line)
        .collect();
    assert_eq!(broken, ["NI"]);
}

/// A table cell's receipt claiming sentence alignment is refused by the
/// receipt cross-check, naming the fact, its anchor kind and the field
/// (the cell half of enron_receipt_alignment_wrong_for_anchor_kind_refused).
#[test]
fn enron_e2d_cell_receipt_sentence_alignment_refused() {
    let mut files = enron();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"8K-NI-D1-FY1999\"\n",
        "alignment = \"value\"",
        "alignment = \"sentence\"",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"8K-NI-D1-FY1999\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "8K-NI-D1-FY1999",
        line,
        &[
            "alignment = \"sentence\"",
            "`table_cell` fact",
            "expected `value`",
        ],
    );
}

/// E2d's sourced cells load and re-serialize to the committed file's
/// canonical bytes; every table cell names its source, a `table_cell`
/// anchor, `granularity = statement_line` and (but the EX-27 MULTIPLIER, a
/// unitless scale factor) a `cell` key, and its source row carries an
/// assurance and its assurance fact.
#[test]
fn enron_e2d_facts_load() {
    let files = enron();
    let case = load_copy(&files).expect("the committed case loads");
    assert_eq!(
        fact::to_document(&case.facts, &case.values).canonical_bytes(),
        fa_registry::toml::parse(text(&files, "facts.toml"))
            .expect("facts.toml parses")
            .canonical_bytes()
    );
    let cells: Vec<_> = case
        .facts
        .iter()
        .filter_map(|f| f.sourced().map(|s| (f, s)))
        .filter(|(_, s)| s.anchor_kind == AnchorKind::TableCell)
        .collect();
    assert!(cells.len() > 150, "{}", cells.len());
    for (f, s) in cells {
        assert_eq!(s.granularity, Granularity::StatementLine, "{}", f.id);
        assert_eq!(s.cell.is_none(), f.id == "EX27-MULT", "{}", f.id);
        let row = case
            .sources
            .iter()
            .find(|r| r.id == s.source)
            .expect("its source row");
        assert!(
            row.assurance.is_some() && row.assurance_fact.is_some(),
            "{}",
            row.id
        );
    }
}

/// The FY1999 total-assets cell in its four vintages (§3.6, §10.4): the
/// EX-27 (33,381), the FY2000 10-K's comparatives (33,381), the 8-K's
/// restated (33,199) and Note 3's restated (33,272) all carry
/// `total_assets@1999-12-31`, and their sources order SRC-ENR-402,
/// SRC-ENR-008, SRC-ENR-002, SRC-ENR-003 by `filed_on`. The two restated
/// vintages differ, the input K-VINTAGE uses to make E-T-04 read the 8-K's
/// issuance. Each Raptor cell carries the same key in both vintages, and the
/// EX-27's BONDS is `bonds@1999-12-31`, never debt.
#[test]
fn enron_e2d_cell_keys_pair_the_vintages() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let cell = |id: &str| {
        case.facts
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.sourced())
            .and_then(|s| s.cell.clone())
            .unwrap_or_else(|| panic!("a cell key on {id}"))
    };
    let source = |id: &str| {
        case.facts
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.sourced())
            .map(|s| s.source.clone())
            .expect("a sourced fact")
    };
    let vintages = [
        "EX27-TA-A-FY1999",
        "10K-TA-A-FY1999",
        "8K-TA-B-FY1999",
        "N3-TA-B-FY1999",
    ];
    for id in vintages {
        assert_eq!(cell(id), "total_assets@1999-12-31", "{id}");
    }
    let filed: Vec<String> = vintages
        .iter()
        .map(|id| {
            let s = source(id);
            case.sources
                .iter()
                .find(|r| r.id == s)
                .and_then(|r| r.filed_on.clone())
                .expect("filed_on")
        })
        .collect();
    assert_eq!(
        vintages.map(source),
        ["SRC-ENR-402", "SRC-ENR-008", "SRC-ENR-002", "SRC-ENR-003"]
    );
    assert!(filed.windows(2).all(|w| w[0] < w[1]), "{filed:?}");
    assert_eq!(
        vintages.map(|id| minor(&case, id) / 100_000_000),
        [33_381, 33_381, 33_199, 33_272]
    );
    for line in ["TA", "EQ"] {
        for period in ["FY2000", "2001Q1", "2001Q2"] {
            assert_eq!(
                cell(&format!("8K-RAPTOR-{line}-{period}")),
                cell(&format!("N3-RAPTOR-{line}-{period}")),
                "{line} {period}"
            );
        }
    }
    assert_eq!(cell("EX27-BONDS-FY1999"), "bonds@1999-12-31");
}

/// The EX-27's three equity tags (PREFERRED 1,130, COMMON 6,637, OTHER-SE
/// 1,803) sum to the as-filed equity, 9,570, the FY2000 10-K's FY1999
/// comparative. A copy declaring the sum 9,571 fails K-DERIVE, naming it.
#[test]
fn enron_e2d_ex27_equity_sum() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let tags: i128 = [
        "EX27-EQ1-A-FY1999",
        "EX27-EQ2-A-FY1999",
        "EX27-EQ3-A-FY1999",
    ]
    .iter()
    .map(|id| minor(&case, id))
    .sum();
    assert_eq!(tags, 957_000_000_000);
    assert_eq!(minor(&case, "EX27-EQ-A-FY1999"), tags);
    assert_eq!(minor(&case, "10K-EQ-A-FY1999"), tags);
    let mut files = enron();
    edit_row(
        &mut files,
        "facts.toml",
        "fact = \"EX27-EQ-A-FY1999\"\n",
        "literal = \"957000000000\"\nrule = \"scale\"\nparam = 0\nvalue = \"957000000000\"",
        "literal = \"957100000000\"\nrule = \"scale\"\nparam = 0\nvalue = \"957100000000\"",
    );
    let planted = load_copy(&files).expect("the planted copy loads");
    let derive = report(&planted, "K-DERIVE");
    assert_eq!(derive.verdict, Verdict::Fail);
    assert!(
        derive.failures.iter().any(|f| f.row == "EX27-EQ-A-FY1999"),
        "{}",
        derive.render(Some("enron"))
    );
}

/// Every EX-27 amount is read at the schedule's MULTIPLIER: its `scale`
/// param k satisfies 10^k = EX27-MULT (1,000,000). A copy reading
/// TOTAL-ASSETS at 10^9 (its value a thousand times larger) fails this check
/// and K-BIND, whose receipt bound the value at 10^6. No foundation check
/// ties one fact's param to another fact, so the multiplier check is this
/// test's own.
#[test]
fn enron_e2d_ex27_multiplier_wrong_refused() {
    let at_multiplier = |case: &Case| -> Vec<String> {
        let mult = minor(case, "EX27-MULT");
        case.values
            .iter()
            .filter(|v| {
                v.fact.starts_with("EX27-") && v.fact != "EX27-MULT" && v.fact != "EX27-EQ-A-FY1999"
            })
            .filter(|v| {
                v.param
                    .and_then(|k| u32::try_from(k).ok())
                    .map(|k| 10_i128.pow(k))
                    != Some(mult)
            })
            .map(|v| v.fact.clone())
            .collect()
    };
    let case = load_copy(&enron()).expect("the committed case loads");
    assert_eq!(minor(&case, "EX27-MULT"), 1_000_000);
    assert!(at_multiplier(&case).is_empty());
    let mut files = enron();
    edit_row(
        &mut files,
        "facts.toml",
        "fact = \"EX27-TA-A-FY1999\"\n",
        "param = 6\nvalue = \"3338100000000\"",
        "param = 9\nvalue = \"3338100000000000\"",
    );
    let planted = load_copy(&files).expect("the planted copy loads");
    assert_eq!(at_multiplier(&planted), ["EX27-TA-A-FY1999"]);
    let bind = report(&planted, "K-BIND");
    assert_eq!(bind.verdict, Verdict::Fail);
    assert!(
        bind.failures.iter().any(|f| f.row == "EX27-TA-A-FY1999"),
        "{}",
        bind.render(Some("enron"))
    );
}

/// The Raptor equity adjustment line in both restating vintages (E-T-03's
/// published delta): total assets and equity, -172 at 2000-12-31 and -1,000
/// at each of the first two 2001 quarter-ends ($M), the 8-K's Table 1 and
/// Note 3 agreeing cell for cell.
#[test]
fn enron_e2d_raptor_line_both_vintages() {
    let case = load_copy(&enron()).expect("the committed case loads");
    for line in ["TA", "EQ"] {
        for (period, want) in [("FY2000", -172), ("2001Q1", -1_000), ("2001Q2", -1_000)] {
            for vintage in ["8K", "N3"] {
                assert_eq!(
                    minor(&case, &format!("{vintage}-RAPTOR-{line}-{period}")),
                    want * 100_000_000,
                    "{vintage} {line} {period}"
                );
            }
        }
    }
}

/// The EX-27's BONDS (7,151) is the schedule's long-term bonds, not the
/// restatements' debt (short-term and long-term, 8,152 as filed): it keys
/// `bonds@1999-12-31` and no expectation's basis names it.
#[test]
fn enron_e2d_bonds_excluded() {
    let case = load_copy(&enron()).expect("the committed case loads");
    assert_eq!(minor(&case, "EX27-BONDS-FY1999"), 715_100_000_000);
    assert_ne!(
        minor(&case, "EX27-BONDS-FY1999"),
        minor(&case, "10K-DEBT-A-FY1999")
    );
    let set = case.expectations.as_ref().expect("expectations");
    let named = set
        .expectations
        .iter()
        .flat_map(|e| e.fields.strs("basis").unwrap_or_default().iter())
        .chain(
            set.expectations
                .iter()
                .flat_map(|e| set.targets_of(&e.id))
                .flat_map(|t| t.fields.strs("basis").unwrap_or_default().iter()),
        )
        .any(|f| f == "EX27-BONDS-FY1999");
    assert!(!named);
}
