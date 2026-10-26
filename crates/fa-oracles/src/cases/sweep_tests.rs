//! A7c's planning tests (bead fa-yugf.17): the pilot's P cells of F4 are
//! grouped on one book and ordered by period state, one representative per
//! authored outcome, every cell under its own key that fits in 64 bytes,
//! record-inconsistent cells kept; a plan reusing a committed key is
//! refused; the combination rule runs filler on the default cell only.

use super::*;
use crate::cases::branch::enumerate;
use crate::cases::tests::pilot_planted;
use crate::cases::{CaseFiles, EXPECTATIONS_FILE, load};

/// A5a's tables of the pilot's P targets of F4 (W-P-02, W-P-03).
fn p_tables(case: &Case) -> Vec<Enumeration> {
    let set = case.expectations.as_ref().expect("expectations");
    ["W-P-02", "W-P-03"]
        .iter()
        .map(|id| {
            let e = set.get(id).expect("the expectation");
            let t = set.targets_of(id).find(|t| t.fact == "F4").expect("F4");
            enumerate(case, e, t).expect("its table")
        })
        .collect()
}

fn labels(g: &SweepGroup) -> Vec<String> {
    g.cells
        .iter()
        .map(|c| format!("{}:{}@{}", c.expectation, c.key.join("/"), c.state.as_str()))
        .collect()
}

/// Two more authored outcomes on W-P-03: Original in Open admits, and
/// Adjusting in Closed shares Original-in-Closed's refusal.
const AUTHORED: &str = "\n[[branch_cell]]\nexpectation = \"W-P-03\"\ntarget = \"F4\"\ncell = [\"Original\", \"Open\"]\nexpect = \"admit\"\nrecord_consistent = false\n\n[[branch_cell]]\nexpectation = \"W-P-03\"\ntarget = \"F4\"\ncell = [\"Adjusting\", \"Closed\"]\nexpect = \"FA-REF-010\"\nrecord_consistent = false\n";

#[test]
fn sweep_plan_orders_cells_by_period_state_and_picks_one_representative_per_outcome() {
    let case = pilot_planted(&[(EXPECTATIONS_FILE, "", AUTHORED)]);
    let plan = sweep_plan(&case, "native", &p_tables(&case)).expect("a plan");
    assert_eq!(plan.groups.len(), 1, "one entry, one group: {plan:?}");
    let g = &plan.groups[0];
    assert_eq!((g.variant.as_str(), g.intent.as_str()), ("native", "F4"));
    // W-P-02 has no period-state attribute: its cells run where the history
    // posts F4 (seq 20, after 2001Q2 opens).
    assert_eq!(
        labels(g),
        [
            "W-P-03:Original/Future@Future",
            "W-P-03:Adjusting/Future@Future",
            "W-P-02:none@Open",
            "W-P-02:placeholder_unreviewed@Open",
            "W-P-02:placeholder_reviewed@Open",
            "W-P-03:Original/Open@Open",
            "W-P-03:Adjusting/Open@Open",
            "W-P-03:Original/SoftClosed@SoftClosed",
            "W-P-03:Adjusting/SoftClosed@SoftClosed",
            "W-P-03:Original/Closed@Closed",
            "W-P-03:Adjusting/Closed@Closed",
            "W-P-03:Original/Locked@Locked",
            "W-P-03:Adjusting/Locked@Locked",
        ]
    );
    assert_eq!(g.states(), PeriodState::ALL);
    let reps: Vec<(String, Option<String>)> = g
        .representatives()
        .into_iter()
        .map(|i| (g.cells[i].key.join("/"), g.cells[i].expect.clone()))
        .collect();
    assert_eq!(
        reps,
        [
            ("none".to_string(), Some("FA-REF-080".to_string())),
            ("Original/Open".to_string(), Some("admit".to_string())),
            (
                "Original/Closed".to_string(),
                Some("FA-REF-010".to_string())
            ),
        ],
        "the first cell of each authored outcome; Adjusting/Closed shares FA-REF-010"
    );
}

#[test]
fn sweep_plan_includes_the_record_inconsistent_locked_cells() {
    let case = pilot_planted(&[]);
    let plan = sweep_plan(&case, "native", &p_tables(&case)).expect("a plan");
    let locked: Vec<&SweepCell> = plan.groups[0]
        .cells
        .iter()
        .filter(|c| c.state == PeriodState::Locked)
        .collect();
    assert_eq!(locked.len(), 2);
    assert!(locked.iter().all(|c| !c.record_consistent));
    // The authored Original/Closed cell is the record-consistent one.
    let consistent: Vec<String> = plan.groups[0]
        .cells
        .iter()
        .filter(|c| c.record_consistent)
        .map(|c| format!("{}:{}", c.expectation, c.key.join("/")))
        .collect();
    assert_eq!(consistent, ["W-P-02:none", "W-P-03:Original/Closed"]);
}

#[test]
fn cell_keys_are_distinct_and_fit_in_64_bytes() {
    // A1b's cap on an authored key leaves exactly the suffix's 13 bytes.
    let longest = "k".repeat(64 - CELL_KEY_SUFFIX_BYTES);
    let key = cell_key(&longest, &["Original".into(), "Closed".into()]);
    assert_eq!(key.len(), 64);
    assert!(key.starts_with(&format!("{longest}.")));
    assert_ne!(
        key,
        cell_key(&longest, &["Original".into(), "Locked".into()])
    );
    let case = pilot_planted(&[]);
    let plan = sweep_plan(&case, "native", &p_tables(&case)).expect("a plan");
    let keys: BTreeSet<&str> = plan.groups[0]
        .cells
        .iter()
        .map(|c| c.idempotency_key.as_str())
        .collect();
    assert_eq!(keys.len(), plan.groups[0].cells.len(), "distinct");
    assert!(
        keys.iter()
            .all(|k| k.starts_with("wc-pilot-F4.") && k.len() <= 64)
    );
}

#[test]
fn cell_reusing_the_intent_key_after_a_commit_is_refused_by_the_planner() {
    let case = pilot_planted(&[]);
    let book = &case.books["native"];
    let mut plan = sweep_plan(&case, "native", &p_tables(&case)).expect("a plan");
    assert_eq!(plan.check(book), Ok(()));
    // A sweep that drops cell_key: the cell's dry run would replay the
    // history's commit of F4 as an idempotent retry.
    let mut dropped = plan.clone();
    dropped.groups[0].cells[3].idempotency_key = "wc-pilot-F4".into();
    let refused = dropped.check(book).expect_err("refused before it runs");
    assert!(
        refused.contains("key `wc-pilot-F4` is an intent key the history commits"),
        "{refused}"
    );
    // Two cells under one key.
    let first = plan.groups[0].cells[0].idempotency_key.clone();
    plan.groups[0].cells[1].idempotency_key = first;
    let refused = plan.check(book).expect_err("refused");
    assert!(refused.contains("is another cell's"), "{refused}");
}

#[test]
fn combination_rule_runs_filler_only_on_the_default_cell() {
    const FILES: [(&str, &str); 4] = [
        (
            "case.toml",
            include_str!("../../tests/fixtures/filler/case.toml"),
        ),
        (
            "roles.toml",
            include_str!("../../tests/fixtures/filler/roles.toml"),
        ),
        (
            "facts.toml",
            include_str!("../../tests/fixtures/filler/facts.toml"),
        ),
        (
            "books/native.toml",
            include_str!("../../tests/fixtures/filler/books/native.toml"),
        ),
    ];
    let case = load(&CaseFiles {
        id: "filler",
        files: &FILES,
    })
    .expect("the filler fixture loads");
    let runs = runs(&case, &crate::cases::tiers::tiers().expect("tiers")).expect("runs");
    let seeded = runs
        .iter()
        .filter(|r| matches!(r.filler.kind, FillerKind::Seeded(_)))
        .count();
    assert_eq!(seeded, 5, "K = 5 seeded variants: {runs:?}");
    let all: Vec<&RunSpec> = runs.iter().filter(|r| r.cells == Cells::All).collect();
    assert_eq!(all.len(), 1, "branch cells run once: {runs:?}");
    assert_eq!(all[0].filler.kind, FillerKind::Empty);
    assert!(
        runs.iter()
            .filter(|r| r.filler.kind != FillerKind::Empty)
            .all(|r| r.cells == Cells::DefaultOnly)
    );
    // The pilot declares no filler variant: only its empty run, which runs
    // every branch cell.
    let pilot = pilot_planted(&[]);
    let runs = super::runs(&pilot, &crate::cases::tiers::tiers().expect("tiers")).expect("runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(
        (runs[0].filler.kind, runs[0].cells),
        (FillerKind::Empty, Cells::All)
    );
}
