//! A5b's checks over the pilot (bead fa-yugf.13): the pilot's component
//! statuses are §6.4's and pass K-BRANCH, K-PRED and K-JOINT; each planted
//! violation fails its check, naming the row and the reason.

use super::super::Case;
use super::super::branch::BranchRules;
use super::super::status::{component_statuses, spell};
use super::super::tests::pilot_planted;
use super::*;

/// One of A5b's checks.
type Check = fn(&Context<'_>) -> CheckReport;
const K_BRANCH: Check = branch::check;
const K_PRED: Check = pred::check;
const K_JOINT: Check = joint::check;

const EXP: &str = "expectations.toml";
const BOOK: &str = "books/native.toml";

fn rules() -> BranchRules {
    crate::cases::branch::rules().expect("the committed rules load")
}

/// Each component's derived status and covariates for one target.
fn derived(case: &Case, expectation: &str, fact: &str) -> Vec<(String, String, Vec<String>)> {
    let set = case.expectations.as_ref().expect("expectations");
    let e = set.get(expectation).expect("the expectation");
    let t = set
        .targets_of(expectation)
        .find(|t| t.fact == fact)
        .expect("the target");
    component_statuses(case, &rules(), e, t)
        .into_iter()
        .map(|d| {
            (
                d.component.to_string(),
                d.status.as_ref().map_or_else(|| "none".to_string(), spell),
                d.covariates,
            )
        })
        .collect()
}

fn report(case: &Case, check: Check) -> CheckReport {
    check(&Context::new(case))
}

#[track_caller]
fn fails(case: &Case, check: Check, row: &str, part: &str) {
    let r = report(case, check);
    assert!(
        r.failures
            .iter()
            .any(|f| f.row == row && f.reason.contains(part)),
        "expected a {} failure on {row} containing `{part}`:\n{}",
        r.check,
        r.render(None)
    );
}

#[track_caller]
fn passes(case: &Case, check: Check) {
    let r = report(case, check);
    assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
}

/// §6.4 (derived from the plan's table): W-D-01 on F4 is cite Sd, severity
/// S, statistic Sd (560,000,000.00 under one_leg_per_named_account); on F9
/// the cite is relational to account-VId order (its rule reads a covariate)
/// over B(leg_split), severity S and statistic B(leg_split); W-D-03 on F4 is
/// cite Sd, severity and statistic B(leg_split). All three checks pass.
#[test]
fn pilot_statuses_match_section_6_4() {
    let case = pilot_planted(&[]);
    let s = |c: &str, st: &str| (c.to_string(), st.to_string());
    let strip = |v: Vec<(String, String, Vec<String>)>| {
        v.into_iter().map(|(c, st, _)| (c, st)).collect::<Vec<_>>()
    };
    assert_eq!(
        strip(derived(&case, "W-D-01", "F4")),
        vec![s("cite", "Sd"), s("severity", "S"), s("statistic", "Sd")]
    );
    let f9 = derived(&case, "W-D-01", "F9");
    assert_eq!(
        f9.iter()
            .map(|(c, st, cov)| (c.as_str(), st.as_str(), cov.clone()))
            .collect::<Vec<_>>(),
        vec![
            (
                "cite",
                "B(leg_split)",
                vec!["account_vid_order".to_string()]
            ),
            ("severity", "S", vec![]),
            (
                "statistic",
                "B(leg_split)",
                vec!["account_vid_order".to_string()]
            ),
        ]
    );
    assert_eq!(
        strip(derived(&case, "W-D-03", "F4")),
        vec![
            s("cite", "Sd"),
            s("severity", "B(leg_split)"),
            s("statistic", "B(leg_split)")
        ]
    );
    for check in [K_BRANCH, K_PRED, K_JOINT] {
        passes(&case, check);
    }
    let rendered = report(&case, K_BRANCH).render(None);
    assert!(
        rendered
            .contains("W-D-01/F9 cite=Rel(account_vid_order) severity=S statistic=B(leg_split)"),
        "{rendered}"
    );
}

/// K-PRED: F4's three credit legs constrained to whole multiples by a
/// round_dollar_lower_bound constraint leave only the all-multiples cell; as
/// D.detection that is refused, as D.restates_characterization admitted.
#[test]
fn constraint_that_collapses_the_predicate_is_refused() {
    let constrained = (
        EXP,
        "expectation = \"W-D-03\"\nfact = \"F4\"\nbasis = [\"F4\", \"F4-p26\"]\n",
        "expectation = \"W-D-03\"\nfact = \"F4\"\nbasis = [\"F4\", \"F4-p26\"]\nconstraints = [\"round_dollar_lower_bound:F4-p26\"]\n",
    );
    let case = pilot_planted(&[constrained]);
    fails(
        &case,
        K_PRED,
        "W-D-03/F4",
        "collapses residue≠0: of the feasible cells only [mmm] remain",
    );
    let restated = pilot_planted(&[
        constrained,
        (
            EXP,
            "statement_template = \"D.detection\"\nbasis = [\"F4\", \"F4-p26\"]\ngranularity = \"journal_entry\"\ncapabilities = [\"procedure:jet.round_amounts@1\"]",
            "statement_template = \"D.restates_characterization\"\nbasis = [\"F4\", \"F4-p26\"]\ngranularity = \"journal_entry\"\ncapabilities = [\"procedure:jet.round_amounts@1\"]",
        ),
    ]);
    passes(&restated, K_PRED);
}

/// K-PRED: with W-D-03/F4's credit split left to the book's leg_split
/// default instead of branched, a statistic declared Sd is decided by the
/// default: the count of round legs differs across the feasible cells.
#[test]
fn default_that_decides_the_predicate_is_refused() {
    let case = pilot_planted(&[
        (
            EXP,
            "expectation = \"W-D-03\"\nfact = \"F4\"\nbasis = [\"F4\", \"F4-p26\"]\nbranch_attrs = [\"leg_split\"]\n",
            "expectation = \"W-D-03\"\nfact = \"F4\"\nbasis = [\"F4\", \"F4-p26\"]\n",
        ),
        (
            EXP,
            "severity_status = \"B(leg_split)\"\nstatistic_status = \"B(leg_split)\"\n",
            "severity = \"Medium\"\nseverity_status = \"Sd\"\nstatistic_name = \"round_legs\"\nstatistic_value = \"4\"\nstatistic_scale = 0\nstatistic_status = \"Sd\"\n",
        ),
        (
            EXP,
            "[[branch_cell]]\nexpectation = \"W-D-03\"\ntarget = \"F4\"\ncell = [\"nnn\"]\nexpect = \"finding\"\nseverity = \"Low\"\nstatistic_value = \"1\"\nrecord_consistent = false\n",
            "",
        ),
    ]);
    // The derivation itself admits Sd: the default declares the split.
    passes(&case, K_BRANCH);
    fails(
        &case,
        K_PRED,
        "W-D-03/F4",
        "the default decides the predicate: statistic is declared single",
    );
    fails(
        &case,
        K_PRED,
        "W-D-03/F4",
        "the default decides the predicate: severity is declared single",
    );
}

/// K-JOINT: a D target names the admitted cell it runs on.
#[test]
fn d_target_without_an_admitted_cell_is_refused() {
    let case = pilot_planted(&[(
        EXP,
        "basis = [\"F4\", \"F4-p26\"]\nadmitted_cell = [\"evidence_attached=placeholder_reviewed\"]\ncite = [\"F4#0\"]\ncite_status = \"Sd\"\nseverity = \"High\"",
        "basis = [\"F4\", \"F4-p26\"]\ncite = [\"F4#0\"]\ncite_status = \"Sd\"\nseverity = \"High\"",
    )]);
    fails(
        &case,
        K_JOINT,
        "W-D-01/F4",
        "a D target names the admitted cell it runs on",
    );
}

/// K-JOINT: W-D-01/F4's admitted cell set to `evidence_attached = none`
/// lies in W-P-02's FA-REF-080 cell.
#[test]
fn d_and_p_with_overlapping_scopes_are_refused() {
    let case = pilot_planted(&[(
        EXP,
        "basis = [\"F4\", \"F4-p26\"]\nadmitted_cell = [\"evidence_attached=placeholder_reviewed\"]\ncite = [\"F4#0\"]\ncite_status = \"Sd\"\nseverity = \"High\"",
        "basis = [\"F4\", \"F4-p26\"]\nadmitted_cell = [\"evidence_attached=none\"]\ncite = [\"F4#0\"]\ncite_status = \"Sd\"\nseverity = \"High\"",
    )]);
    fails(
        &case,
        K_JOINT,
        "W-D-01/F4",
        "the admitted cell lies in W-P-02's refusal cell [none] (expects FA-REF-080)",
    );
}

const CF: &str = "\n[[expectation]]\nid = \"W-P-03-CF-01\"\ntype = \"CF\"\nbook_variant = \"native\"\nstatement_template = \"CF.counterfactual\"\nbasis = [\"F4\"]\nparent = \"W-P-03\"\nchanged_attribute = \"effective_date\"\nchanged_value = \"2001-07-17\"\nexpect = \"admit\"\n";

/// K-BRANCH: a CF row changes one attribute its parent reads. W-P-03's
/// kernel steps read entry_class, period_state_at_commit and
/// evidence_attached, not the effective date.
#[test]
fn cf_row_changing_an_attribute_its_parent_does_not_read_is_refused() {
    let case = pilot_planted(&[(EXP, "", CF)]);
    fails(
        &case,
        K_BRANCH,
        "W-P-03-CF-01",
        "`effective_date` is not read by W-P-03",
    );
    let read = CF
        .replace("\"effective_date\"", "\"period_state_at_commit\"")
        .replace("\"2001-07-17\"", "\"Open\"");
    passes(&pilot_planted(&[(EXP, "", &read)]), K_BRANCH);
}

const ROUND_DOLLAR: (&str, &str, &str) = (
    EXP,
    "expectation = \"W-D-03\"\nfact = \"F4\"\nbasis = [\"F4\", \"F4-p26\"]\n",
    "expectation = \"W-D-03\"\nfact = \"F4\"\nbasis = [\"F4\", \"F4-p26\"]\nconstraints = [\"round_dollar_lower_bound:F4-p26\"]\n",
);

/// K-BRANCH: under a round-dollar constraint, W-D-03/F4's non-multiple
/// cell marked record-consistent is refused.
#[test]
fn branch_value_contradicting_a_sourced_constraint_is_refused() {
    let case = pilot_planted(&[
        ROUND_DOLLAR,
        (
            EXP,
            "cell = [\"nnn\"]\nexpect = \"finding\"\nseverity = \"Low\"\nstatistic_value = \"1\"\nrecord_consistent = false\n",
            "cell = [\"nnn\"]\nexpect = \"finding\"\nseverity = \"Low\"\nstatistic_value = \"1\"\nrecord_consistent = true\n",
        ),
    ]);
    fails(
        &case,
        K_BRANCH,
        "W-D-03/F4",
        "branch cell [nnn] has a non-multiple leg, which contradicts the sourced constraint `round_dollar_lower_bound:F4-p26`",
    );
    // Marked record-inconsistent, the same cell passes K-BRANCH.
    let marked = pilot_planted(&[ROUND_DOLLAR]);
    let r = report(&marked, K_BRANCH);
    assert!(
        !r.failures.iter().any(|f| f.reason.contains("contradicts")),
        "{}",
        r.render(None)
    );
}

/// A record-inconsistent cell (W-P-03's Locked column) loads, passes
/// K-BRANCH, and is enumerated and evaluated with `record_consistent =
/// false`; a CF row whose value contradicts the record passes too.
#[test]
fn record_inconsistent_cell_is_admitted_and_evaluated() {
    let locked = "\n[[branch_cell]]\nexpectation = \"W-P-03\"\ntarget = \"F4\"\ncell = [\"Original\", \"Locked\"]\nexpect = \"FA-REF-010\"\nrecord_consistent = false\n";
    let cf = "\n[[expectation]]\nid = \"W-D-03-CF-01\"\ntype = \"CF\"\nbook_variant = \"native\"\nstatement_template = \"CF.counterfactual\"\nbasis = [\"F4\"]\nparent = \"W-D-03\"\nchanged_attribute = \"leg_split\"\nchanged_value = \"nnn\"\nexpect = \"finding\"\n";
    let case = pilot_planted(&[ROUND_DOLLAR, (EXP, "", locked), (EXP, "", cf)]);
    passes(&case, K_BRANCH);
    let set = case.expectations.as_ref().unwrap();
    let e = set.get("W-P-03").unwrap();
    let t = set.targets_of("W-P-03").next().unwrap();
    let en = crate::cases::branch::enumerate_with(&rules(), &case, e, t).expect("enumerates");
    let cell = en
        .cells
        .iter()
        .find(|c| c.key == ["Original", "Locked"])
        .expect("the Locked cell is enumerated");
    assert!(!cell.record_consistent);
}

/// K-BRANCH: a D on jet.period_end_timing reads the effective date; with no
/// effective_date default, branch or fact it has no status.
#[test]
fn unanchored_attribute_without_a_status_is_refused() {
    let w_d_04 = "\n[[expectation]]\nid = \"W-D-04\"\ntype = \"D\"\nbook_variant = \"native\"\nstatement_template = \"D.detection\"\nbasis = [\"F4\"]\ngranularity = \"journal_entry\"\ncapabilities = [\"procedure:jet.period_end_timing@1\"]\nprocedure = \"jet.period_end_timing\"\nversion = 1\n\n[[target]]\nexpectation = \"W-D-04\"\nfact = \"F4\"\nbasis = [\"F4\"]\nadmitted_cell = [\"evidence_attached=placeholder_reviewed\"]\ncite = [\"F4#0\"]\ncite_status = \"Sd\"\nseverity = \"Low\"\nseverity_status = \"S\"\nstatistic_status = \"X\"\n";
    let undefaulted = (
        BOOK,
        "[[default]]\nattribute = \"effective_date\"\nrule = \"reporting_period_last_day\"\n",
        "[[default]]\nattribute = \"document_date\"\nrule = \"reporting_period_last_day\"\n",
    );
    let case = pilot_planted(&[(EXP, "", w_d_04), undefaulted]);
    fails(
        &case,
        K_BRANCH,
        "W-D-04/F4",
        "cite: an unanchored attribute without a status: effective_date is read by rule `period_end_window`",
    );
    // With the default declared, the cite is Sd.
    passes(&pilot_planted(&[(EXP, "", w_d_04)]), K_BRANCH);
}

/// K-PRED: R-QUAL may not constrain a target that lists a documented
/// exception (F1's p.105 sentence, here a planted F2 exception on F4).
#[test]
fn r_qual_on_a_target_with_a_documented_exception_is_refused() {
    let anchor = "expectation = \"W-D-01\"\nfact = \"F4\"\nbasis = [\"F4\", \"F4-p26\"]\n";
    let case = pilot_planted(&[(
        EXP,
        anchor,
        &format!(
            "{anchor}constraints = [\"round_dollar_lower_bound:F4-p26\"]\nexceptions = [\"F2\"]\n"
        ),
    )]);
    fails(
        &case,
        K_PRED,
        "W-D-01/F4",
        "R-QUAL on a target with a documented exception (F2)",
    );
    // Without the exception the constraint is admitted (F4-p26 covers F4).
    let admitted = pilot_planted(&[(
        EXP,
        anchor,
        &format!("{anchor}constraints = [\"round_dollar_lower_bound:F4-p26\"]\n"),
    )]);
    passes(&admitted, K_PRED);
}

/// K-BRANCH: F9's statistic declared Sd, where its inputs derive
/// B(leg_split).
#[test]
fn authored_status_differing_from_the_derived_status_is_refused() {
    let case = pilot_planted(&[(
        EXP,
        "statistic_name = \"capitalized_amount\"\nstatistic_scale = 2\nstatistic_status = \"B(leg_split)\"\n",
        "statistic_name = \"capitalized_amount\"\nstatistic_value = \"74272500000\"\nstatistic_scale = 2\nstatistic_status = \"Sd\"\n",
    )]);
    fails(
        &case,
        K_BRANCH,
        "W-D-01/F9",
        "statistic_status = \"Sd\", but its inputs derive B(leg_split)",
    );
}

/// K-BRANCH: under a table capped below W-D-03/F4's eight cells, its single
/// cite is refused (a capped enumeration never yields a single verdict).
#[test]
fn capped_target_with_a_single_status_is_refused() {
    let case = pilot_planted(&[]);
    let mut capped = rules();
    capped.cap = 4;
    let r = branch::check_with(&Context::new(&case), &capped);
    assert!(
        r.failures.iter().any(|f| f.row == "W-D-03/F4"
            && f.reason
                .contains("cells exceed the cap of 4, so its cite is a branch, never single")),
        "{}",
        r.render(None)
    );
}
