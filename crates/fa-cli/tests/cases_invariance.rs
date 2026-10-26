//! The invariance witness's extremal runs (bead fa-yugf.25, A11a), in a
//! test binary of their own. Each builds a book whose extremal filler
//! variant is 2,000 entries (10^3 x a two-leg target, §3.7). At the current
//! batch admission throughput (fa-q7vt: the substrate re-prepares the whole
//! staged program for every member, and each posting call replays the
//! journal from genesis) that takes tens of minutes on the debug binary, so
//! both tests are `#[ignore]`d until fa-q7vt lands. They are the witness at
//! the plan's volume: run them with
//! `cargo test -p fa-cli --test cases_invariance -- --ignored`. The
//! mechanism at small volume runs in `--test cases`.

// The shared runner modules serve tests/cases.rs as well; each binary uses
// part of them.
#![allow(dead_code)]

#[path = "cases/budget.rs"]
mod budget;
#[path = "cases/cells.rs"]
mod cells;
#[path = "cases/evaluate.rs"]
mod evaluate;
#[path = "cases/invariance.rs"]
mod invariance;
#[path = "cases/run.rs"]
mod run;

use fa_oracles::cases::harness_verbs::HARNESS_VERBS;
use run::run_files;

/// The invariance fixture (`crates/fa-oracles/tests/fixtures/invariance/`):
/// A6's filler fixture with a D row on jet.round_amounts (A11a).
const INVARIANCE: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/expectations.toml"),
    ),
];

/// A11a (§3.7 item 1): the D row's single components agree on the seeded
/// filler variants, the empty variant (run twice: two book ids) and the
/// extremal variant of each tier the case claims, so it reads PASS; so does
/// the SELF row.
#[test]
#[ignore = "fa-q7vt: the 2,000-entry extremal variant takes tens of minutes at current batch throughput; run with --ignored"]
fn invariance_d_row_agrees_across_filler_variants_and_book_ids() {
    // The extremal variants post 2,000 (C) and 1,000 (S-rel) filler
    // entries. At the measured admission throughput the case runs past its
    // 60 s budget (2,094,796 ms, 225 invocations, on hz3), which the run
    // reports as its own `FAIL budget` line: a runtime finding about the
    // kernel, not this witness's verdict. No row fails.
    let o = match run_files("invariance", &INVARIANCE, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) => *o,
    };
    let text = o.text();
    assert!(
        !o.lines
            .iter()
            .any(|l| l.starts_with("FAIL ") && !l.starts_with("FAIL budget ")),
        "{text}"
    );
    let row = o.row("invariance-D-01").expect("the D row");
    assert!(
        row.starts_with(
            "PASS invariance-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 invariance=agree(variants="
        ),
        "{text}"
    );
    // Five seeded variants, the empty one, and one extremal per claimed tier
    // (C for jet.round_amounts, S-rel for jet.self_sourced_evidence); the
    // empty one ran twice, so every run has its own book id.
    let token = row
        .split(' ')
        .find(|t| t.starts_with("invariance="))
        .expect("the token");
    assert_eq!(token, "invariance=agree(variants=8,book_ids=9)", "{text}");
    assert!(
        o.row("invariance-SELF-native")
            .is_some_and(|l| l.starts_with("PASS ") && l.contains(" invariance=agree(")),
        "{text}"
    );
    // The filler posted: chunks labelled by variant.
    for variant in ["fv1@extremal-C", "fv1@extremal-S-rel"] {
        assert!(
            o.steps
                .iter()
                .any(|s| s.filler_variant.as_deref() == Some(variant)),
            "{variant}\n{text}"
        );
    }
}

/// A test-only tier table declaring numbers.round_amount_density tier L:
/// its finding moves with the book's round share, so the L-discipline
/// filler changes the projection, and the row fails naming the tier row.
/// Every filler spec runs, the extremal one included.
#[test]
#[ignore = "fa-q7vt: the 2,000-entry extremal variant takes tens of minutes at current batch throughput; run with --ignored"]
fn tier_l_row_for_round_amount_density_fails_naming_the_row() {
    let (tiers, line) = invariance::round_density_tier_l();
    let w = invariance::witness(
        "invariance_negative",
        &invariance::NEGATIVE,
        &tiers,
        &|_| true,
    );
    let text = w.text();
    let row = w.row("invariance_negative-D-01").expect("the D row");
    assert!(
        row.starts_with("FAIL invariance_negative-D-01 D native N-1/default "),
        "{text}"
    );
    assert!(
        row.contains(" invariance=disagree(numbers.round_amount_density@1,severity,fv1@empty/"),
        "{text}"
    );
    assert!(
        row.ends_with(&format!(
            " reason=tier row case_procedure_tiers.toml:{line} declares L"
        )),
        "{text}"
    );
}
