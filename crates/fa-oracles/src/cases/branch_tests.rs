//! A5a's tests (bead fa-yugf.12): the committed rules resolve, F4's
//! three credit legs enumerate exactly the feasible residue cells, cell keys
//! load as A1c's `[[branch_cell]]`, witnesses are deterministic members of
//! their cells, and every planted defect is refused.

use super::*;
use crate::cases::tests::{load_files, pilot, pilot_planted};
use crate::cases::{CASE_EXTENSIONS, EXPECTATIONS_FILE, LoadErrorKind};

const M: i128 = 100_000; // 10^3 units at USD's scale of 2.
const F4_TOTAL: i128 = 56_000_000_000;

fn table(case: &Case, expectation: &str, target: &str) -> Result<Enumeration, LoadError> {
    let set = case.expectations.as_ref().expect("expectations");
    let e = set.get(expectation).expect("the expectation");
    let t = set
        .targets_of(expectation)
        .find(|t| t.fact == target)
        .expect("the target");
    enumerate(case, e, t)
}

fn keys(e: &Enumeration) -> Vec<String> {
    e.cells.iter().map(|c| c.key.join("/")).collect()
}

fn edited_rules(old: &str, new: &str) -> Result<BranchRules, Vec<LoadError>> {
    assert!(TABLE.contains(old), "`{old}` in the table");
    let text = TABLE.replacen(old, new, 1);
    let procedures = Procedures::embedded().expect("procedures.toml");
    BranchRules::from_text(
        &text,
        &procedures,
        &crate::cases::tiers::tiers().expect("tiers"),
    )
}

#[track_caller]
fn refused(errs: &[LoadError], kind: LoadErrorKind, part: &str) {
    assert!(
        errs.iter()
            .any(|e| e.kind == kind && e.detail.contains(part)),
        "no {kind} containing {part:?} in {errs:?}"
    );
}

#[test]
fn every_seeded_rule_resolves() {
    let rules = rules().expect("the committed table loads");
    assert_eq!(rules.cap, 256);
    for id in [
        "round_residue_legs",
        "round_residue_amount",
        "capitalized_debit_legs",
        "period_end_window",
        "entry_class_admission",
        "period_state_admission",
        "evidence_minimum",
    ] {
        assert!(rules.get(id).is_some(), "{id}");
    }
    assert_eq!(
        rules.get("round_residue_legs").map(|r| &r.class_rule),
        Some(&ClassRule::ResidueMod { power: 3 }),
        "round_power's registered default"
    );
    assert_eq!(
        rules.get("period_end_window").map(|r| &r.class_rule),
        Some(&ClassRule::InsideWindow { window_days: 3 })
    );
    // The pilot's branch classes all name a rule of their attribute.
    let case = pilot_planted(&[]);
    for class in &case.books["native"].branch_classes {
        assert_eq!(class_problem(&rules, class), None, "{}", class.id);
    }
}

#[test]
fn f4_leg_split_enumerates_exactly_the_feasible_cells() {
    let e = table(&pilot_planted(&[]), "W-D-03", "F4").expect("W-D-03's F4 table");
    assert_eq!(e.attrs, [BranchAttribute::LegSplit]);
    assert_eq!(keys(&e), ["mmm", "nnm", "nmn", "mnn", "nnn"]);
    assert_eq!(
        e.infeasible,
        ["leg_split=nmm", "leg_split=mnm", "leg_split=mmn"],
        "exactly one non-multiple cannot balance a whole-multiple total"
    );
    assert_eq!(e.class_counts, [5]);
    assert!(!e.capped);
    assert_eq!(
        e.log_line(),
        "ENUM W-D-03 F4 attrs=[leg_split] counts=[5] cells=5 infeasible=[leg_split=nmm,leg_split=mnm,leg_split=mmn] capped=false order=[mmm:all_multiples,nnm:two_non_multiples,nmn:two_non_multiples,mnn:two_non_multiples,nnn:three_non_multiples]"
    );
    // The authored nnn row is read, not invented: no cell is record-
    // consistent and none is a default.
    assert!(e.cells.iter().all(|c| !c.record_consistent && !c.default));
    assert_eq!(e.default_cell, None);
}

#[test]
fn cell_keys_match_the_a1c_branch_cell_form() {
    let case = pilot_planted(&[]);
    let f4 = table(&case, "W-D-03", "F4").expect("W-D-03");
    for c in &f4.cells {
        let legs: Vec<(Vec<i128>, i128, i128)> = c
            .parts
            .iter()
            .filter_map(|p| match p {
                CellPart::Legs {
                    ordinals,
                    total,
                    modulus,
                    ..
                } => Some((ordinals.clone(), *total, *modulus)),
                _ => None,
            })
            .collect();
        // F4's credit legs, after the CIP debit at ordinal 0.
        assert_eq!(legs, [(vec![1, 2, 3], F4_TOTAL, M)], "{c:?}");
    }
    // Every emitted key, authored as a `[[branch_cell]]`, loads.
    let mut rows = String::new();
    for (expectation, target, expect) in [
        ("W-D-03", "F4", "finding"),
        ("W-P-03", "F4", "FA-REF-010"),
        ("W-P-02", "F4", "FA-REF-080"),
        ("W-D-01", "F9", "finding"),
    ] {
        let e = table(&case, expectation, target).expect(expectation);
        let authored = &case.expectations.as_ref().expect("set").branch_cells;
        for c in &e.cells {
            if authored
                .iter()
                .any(|a| a.expectation == expectation && a.target == target && a.cell == c.key)
            {
                continue;
            }
            let cell: Vec<String> = c.key.iter().map(|k| format!("\"{k}\"")).collect();
            rows.push_str(&format!(
                "\n[[branch_cell]]\nexpectation = \"{expectation}\"\ntarget = \"{target}\"\ncell = [{}]\nexpect = \"{expect}\"\nrecord_consistent = false\n",
                cell.join(", ")
            ));
        }
    }
    let planted = pilot_planted(&[(EXPECTATIONS_FILE, "", rows.as_str())]);
    assert!(
        planted.expectations.expect("set").branch_cells.len() > 10,
        "every emitted cell loaded as a row"
    );
}

#[test]
fn witness_seeds_are_deterministic() {
    let e = table(&pilot_planted(&[]), "W-D-03", "F4").expect("W-D-03");
    let cell = |k: &str| e.cells.iter().find(|c| c.key == [k]).expect(k);
    let a = witnesses("worldcom", "W-D-03", cell("nnm"), 64);
    assert_eq!(a, witnesses("worldcom", "W-D-03", cell("nnm"), 64));
    assert_ne!(a, witnesses("worldcom", "W-D-03", cell("nmn"), 64));
    assert_ne!(a, witnesses("worldcom", "W-D-04", cell("nnm"), 64));
    assert_eq!(a.len(), 64);
    // Every witness of every cell is a member: its legs carry the cell's
    // residues and sum to the sourced total.
    for c in &e.cells {
        let letters = c.key[0].as_str();
        for w in witnesses("worldcom", "W-D-03", c, 64) {
            assert_eq!(w.values.len(), 1, "{w:?}");
            let legs: Vec<(i128, i128)> = w
                .values
                .iter()
                .filter_map(|v| match v {
                    WitnessValue::Legs(legs) => Some(legs.clone()),
                    _ => None,
                })
                .flatten()
                .collect();
            assert_eq!(legs.iter().map(|(o, _)| *o).collect::<Vec<_>>(), [1, 2, 3]);
            assert_eq!(legs.iter().map(|(_, a)| a).sum::<i128>(), F4_TOTAL, "{w:?}");
            for ((_, amount), letter) in legs.iter().zip(letters.chars()) {
                assert!(*amount >= 1, "{w:?}");
                assert_eq!(amount % M == 0, letter == 'm', "{letters} {w:?}");
            }
        }
    }
}

#[test]
fn emptied_branch_set_is_refused() {
    let mut files = pilot();
    let book = files
        .iter_mut()
        .find(|(p, _)| *p == "books/native.toml")
        .expect("the book");
    let old = "rule = \"round_residue_legs\"\nvalues = [\"multiple\", \"non_multiple\"]";
    assert_eq!(book.1.matches(old).count(), 1);
    book.1 = book
        .1
        .replacen(old, "rule = \"round_residue_legs\"\nvalues = []", 1);
    let errs = load_files("worldcom", &files, CASE_EXTENSIONS).expect_err("refused");
    refused(
        &errs,
        LoadErrorKind::MissingField,
        "a branch class lists its values",
    );
}

#[test]
fn branch_class_naming_no_rule_or_a_foreign_value_is_refused() {
    for (old, new, part) in [
        (
            "rule = \"round_residue_legs\"",
            "rule = \"f4_three_line_cost_credits\"",
            "names no rule of case_branch_rules.toml",
        ),
        (
            "rule = \"period_end_window\"",
            "rule = \"round_residue_legs\"",
            "branches `effective_date`, but rule `round_residue_legs` branches `leg_split`",
        ),
        (
            "values = [\"Future\", \"Open\", \"SoftClosed\", \"Closed\", \"Locked\"]",
            "values = [\"Open\", \"Reopened\"]",
            "`Reopened` is not a class of rule `period_state_admission`",
        ),
    ] {
        let mut files = pilot();
        let book = files
            .iter_mut()
            .find(|(p, _)| *p == "books/native.toml")
            .expect("the book");
        assert_eq!(book.1.matches(old).count(), 1, "{old}");
        book.1 = book.1.replacen(old, new, 1);
        let errs = load_files("worldcom", &files, CASE_EXTENSIONS).expect_err("refused");
        refused(&errs, LoadErrorKind::UnknownValue, part);
    }
}

#[test]
fn capped_enumeration_never_yields_a_single_verdict() {
    let rules = edited_rules("cap = 256", "cap = 4").expect("a capped copy");
    // With every component of W-D-03's F4 target a branch, the enumeration
    // is capped: 5 feasible cells exceed 4.
    let case = pilot_planted(&[(
        EXPECTATIONS_FILE,
        "cite_status = \"Sd\"\nseverity_status = \"B(leg_split)\"",
        "cite_status = \"B(leg_split)\"\nseverity_status = \"B(leg_split)\"",
    )]);
    let set = case.expectations.as_ref().expect("set");
    let e = set.get("W-D-03").expect("W-D-03");
    let t = set
        .targets_of("W-D-03")
        .find(|t| t.fact == "F4")
        .expect("F4");
    let capped = enumerate_with(&rules, &case, e, t).expect("all-branch components");
    assert!(capped.capped);
    assert_eq!(capped.cells.len(), 4);
    // A declared single component on a capped target is refused.
    let case = pilot_planted(&[(
        EXPECTATIONS_FILE,
        "cite_status = \"Sd\"\nseverity_status = \"B(leg_split)\"\nstatistic_status = \"B(leg_split)\"",
        "cite_status = \"B(leg_split)\"\nseverity_status = \"B(leg_split)\"\nstatistic_status = \"Sd\"\nstatistic_value = \"1\"",
    )]);
    let set = case.expectations.as_ref().expect("set");
    let e = set.get("W-D-03").expect("W-D-03");
    let t = set
        .targets_of("W-D-03")
        .find(|t| t.fact == "F4")
        .expect("F4");
    let err = enumerate_with(&rules, &case, e, t).expect_err("a single statistic");
    assert_eq!(err.kind, LoadErrorKind::WrongType);
    assert!(
        err.detail
            .contains("5 cells exceed the cap of 4, so its statistic is a branch"),
        "{err}"
    );
}

#[test]
fn feasibility_rejects_a_total_below_the_leg_count() {
    use ResidueClass::{Multiple as Mu, NonMultiple as Nm};
    assert!(
        !feasible(2, &[Nm, Nm, Nm], M),
        "three legs need three minor units"
    );
    assert!(feasible(3, &[Nm, Nm, Nm], M));
    // A whole-multiple total: one non-multiple can never balance.
    assert!(!feasible(F4_TOTAL, &[Nm, Mu, Mu], M));
    assert!(feasible(F4_TOTAL, &[Nm, Nm, Mu], M));
    assert!(feasible(F4_TOTAL, &[Mu, Mu, Mu], M));
    // Multiples need at least one modulus each.
    assert!(!feasible(150_000, &[Mu, Mu], M));
    assert!(feasible(200_000, &[Mu, Mu], M));
    // Total M + 1 over [n, n, m]: the multiple takes M, leaving one minor
    // unit for two non-multiples.
    assert!(!feasible(M + 1, &[Nm, Nm, Mu], M));
}

#[test]
fn class_rule_naming_an_unregistered_parameter_is_refused() {
    let errs = edited_rules(
        "class_param = \"round_power\"\nparameters = [\"round_power\"]",
        "class_param = \"round_powr\"\nparameters = [\"round_powr\"]",
    )
    .expect_err("refused");
    refused(
        &errs,
        LoadErrorKind::UnknownValue,
        "`round_powr` is not a registered parameter of the reader",
    );
}

#[test]
fn reader_without_a_tier_row_at_its_version_is_refused() {
    let errs = edited_rules(
        "reader = \"jet.round_amounts@1\"",
        "reader = \"jet.round_amounts@2\"",
    )
    .expect_err("refused");
    refused(
        &errs,
        LoadErrorKind::DanglingKey,
        "reader `jet.round_amounts@2` has no tier row at its version",
    );
    let errs = edited_rules(
        "reader = \"jet.round_amounts@1\"",
        "reader = \"jet.no_such@1\"",
    )
    .expect_err("refused");
    refused(&errs, LoadErrorKind::DanglingKey, "has no tier row (A4)");
}

#[test]
fn record_inconsistent_locked_cell_is_enumerated_not_dropped() {
    let case = pilot_planted(&[]);
    let e = table(&case, "W-P-03", "F4").expect("W-P-03's table");
    assert_eq!(
        e.attrs,
        [
            BranchAttribute::EntryClass,
            BranchAttribute::PeriodStateAtCommit
        ]
    );
    assert_eq!(e.class_counts, [2, 5]);
    assert_eq!(e.cells.len(), 10);
    assert!(e.infeasible.is_empty());
    let locked: Vec<&Cell> = e.cells.iter().filter(|c| c.key[1] == "Locked").collect();
    assert_eq!(locked.len(), 2);
    assert!(locked.iter().all(|c| !c.record_consistent));
    // The authored Original/Closed cell is the record-consistent one.
    let consistent: Vec<String> = e
        .cells
        .iter()
        .filter(|c| c.record_consistent)
        .map(|c| c.key.join("/"))
        .collect();
    assert_eq!(consistent, ["Original/Closed"]);
    // An enum leg_split (W-D-01's F9) keeps its authored default.
    let f9 = table(&case, "W-D-01", "F9").expect("W-D-01's F9 table");
    assert_eq!(keys(&f9), ["one_debit_leg", "two_debit_legs"]);
    assert_eq!(f9.default_cell, Some(vec!["one_debit_leg".to_string()]));
}
