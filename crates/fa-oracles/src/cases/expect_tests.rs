//! A1c's tests (bead fa-yugf.5): the pilot's expectations load with its
//! native book, every key resolves, the file round-trips through canonical
//! bytes, and every planted edit is refused with its named kind.

use super::*;
use crate::cases::{CASE_EXTENSIONS, Case, CaseFiles, LoadError, LoadErrorKind, load_with};

const CASE: &str = include_str!("../../tests/fixtures/pilot/case.toml");
const SOURCES: &str = include_str!("../../tests/fixtures/pilot/sources.toml");
const FACTS: &str = include_str!("../../tests/fixtures/pilot/facts.toml");
const RECEIPTS: &str = include_str!("../../tests/fixtures/pilot/receipts.toml");
const ROLES: &str = include_str!("../../tests/fixtures/pilot/roles.toml");
const NATIVE: &str = include_str!("../../tests/fixtures/pilot/books/native.toml");
const EXPECTATIONS: &str = include_str!("../../tests/fixtures/pilot/expectations.toml");
const MIGRATION_MIN: &str = include_str!("../../tests/fixtures/migration_min/books/migration.toml");

type Files = Vec<(String, String)>;

/// The pilot with its native book and the given case, book and expectations
/// texts.
fn files(case: &str, book: &str, expectations: &str) -> Files {
    vec![
        ("case.toml".into(), case.into()),
        ("sources.toml".into(), SOURCES.into()),
        ("facts.toml".into(), FACTS.into()),
        ("receipts.toml".into(), RECEIPTS.into()),
        ("roles.toml".into(), ROLES.into()),
        ("books/native.toml".into(), book.into()),
        ("expectations.toml".into(), expectations.into()),
    ]
}

fn load(files: &Files) -> Result<Case, Vec<LoadError>> {
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    load_with(
        &CaseFiles {
            id: "worldcom",
            files: &refs,
        },
        CASE_EXTENSIONS,
    )
}

fn render(errs: &[LoadError]) -> String {
    errs.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

#[track_caller]
fn loads(files: &Files, what: &str) -> Case {
    load(files).map_err(|errs| render(&errs)).expect(what)
}

/// `text` with `old`, which must occur exactly once, replaced by `new`.
fn once(text: &str, old: &str, new: &str) -> String {
    assert_eq!(text.matches(old).count(), 1, "`{old}` occurs exactly once");
    text.replacen(old, new, 1)
}

fn with_expectations(text: &str) -> Files {
    files(CASE, NATIVE, text)
}

fn edited(old: &str, new: &str) -> Files {
    with_expectations(&once(EXPECTATIONS, old, new))
}

fn appended(extra: &str) -> Files {
    with_expectations(&format!("{EXPECTATIONS}\n{extra}"))
}

#[track_caller]
fn refused<'e>(
    errs: &'e [LoadError],
    file: &str,
    kind: LoadErrorKind,
    part: &str,
) -> &'e LoadError {
    errs.iter()
        .find(|e| e.file == file && e.kind == kind && e.detail.contains(part))
        .ok_or_else(|| render(errs))
        .expect("an error of the named kind, file and detail")
}

#[track_caller]
fn refused_exp(files: &Files, kind: LoadErrorKind, part: &str) -> LoadError {
    let errs = load(files).expect_err("the planted edit is refused");
    refused(&errs, "expectations.toml", kind, part).clone()
}

/// The 1-based line of the one line of `text` containing `needle`.
fn line_of(text: &str, needle: &str) -> usize {
    let hits: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(needle))
        .map(|(n, _)| n + 1)
        .collect();
    assert_eq!(hits.len(), 1, "`{needle}` is on exactly one line");
    hits[0]
}

#[test]
fn pilot_expectations_load_and_every_key_resolves() {
    let case = loads(&with_expectations(EXPECTATIONS), "the pilot loads");
    let set = case.expectations.as_ref().expect("expectations.toml");
    assert_eq!(set.expectations.len(), 5);
    assert_eq!(set.targets.len(), 5);
    assert_eq!(set.branch_cells.len(), 5);
    assert_eq!(set.notes.len(), 1);
    let d = set.get("W-D-01").expect("W-D-01");
    assert_eq!(d.kind, ExpectationType::D);
    assert_eq!(d.known_at(), KnownAt::PreCase, "a D defaults to pre_case");
    let f4 = set
        .targets_of("W-D-01")
        .find(|t| t.fact == "F4")
        .expect("F4");
    let p = f4.projection(d).expect("a D target projects");
    assert_eq!(p.procedure, "expense.capitalization");
    assert_eq!(p.version, 2);
    assert_eq!(p.cite.status, Status::Sd);
    assert_eq!(p.statistic.value.as_deref(), Some("56000000000"));
    let f9 = set
        .targets_of("W-D-01")
        .find(|t| t.fact == "F9")
        .expect("F9");
    let p9 = f9.projection(d).expect("F9 projects");
    assert_eq!(
        p9.statistic.status,
        Status::B(vec![BranchAttribute::LegSplit])
    );
    assert_eq!(p9.cite.status, Status::Rel("account_vid_order".into()));
    assert_eq!(
        set.to_document().canonical_bytes(),
        fa_registry::toml::parse(EXPECTATIONS)
            .expect("parses")
            .canonical_bytes(),
        "expectations.toml round-trips"
    );
}

#[test]
fn target_with_unknown_expectation_is_refused() {
    let files = edited(
        "expectation = \"W-P-02\"\nfact = \"F4\"\nbranch_attrs",
        "expectation = \"W-D-99\"\nfact = \"F4\"\nbranch_attrs",
    );
    let e = refused_exp(
        &files,
        LoadErrorKind::DanglingKey,
        "`expectation = \"W-D-99\"` names no expectation",
    );
    assert_eq!(e.line, Some(line_of(&files[6].1, "\"W-D-99\"") - 1));
}

#[test]
fn branch_cell_with_unknown_target_is_refused() {
    refused_exp(
        &edited(
            "expectation = \"W-P-03\"\ntarget = \"F4\"",
            "expectation = \"W-P-03\"\ntarget = \"F9\"",
        ),
        LoadErrorKind::DanglingKey,
        "`target = \"F9\"` is not a target of W-P-03",
    );
}

#[test]
fn expectation_with_unknown_book_variant_is_refused() {
    refused_exp(
        &edited(
            "id = \"W-D-03\"\ntype = \"D\"\nbook_variant = \"native\"",
            "id = \"W-D-03\"\ntype = \"D\"\nbook_variant = \"statment\"",
        ),
        LoadErrorKind::DanglingKey,
        "has no books/statment.toml",
    );
}

#[test]
fn note_naming_a_verdict_is_refused() {
    let e = refused_exp(
        &edited(
            "template = \"NOTE.observation\"",
            "template = \"NOTE.observation\"\nverdict = \"PASS\"",
        ),
        LoadErrorKind::NoteWithVerdict,
        "a note has no verdict",
    );
    assert_eq!(e.row.as_deref(), Some("W-NOTE-01"));
}

#[test]
fn p_row_with_exit_field_is_refused() {
    refused_exp(
        &edited(
            "refusal = \"FA-REF-080\"",
            "refusal = \"FA-REF-080\"\nexit = 3",
        ),
        LoadErrorKind::ExitIsCatalogs,
        "the expected exit is registries/refusal_catalog.toml's",
    );
}

#[test]
fn expected_value_on_excluded_field_is_refused() {
    refused_exp(
        &edited(
            "statistic_scale = 2\nstatistic_status = \"Sd\"",
            "statistic_scale = 2\nstatistic_status = \"Sd\"\nstatistic_population = 12",
        ),
        LoadErrorKind::ExcludedField,
        "`statistic_population`",
    );
    refused_exp(
        &edited(
            "statistic_scale = 2\nstatistic_status = \"Sd\"",
            "statistic_scale = 2\nstatistic_status = \"Sd\"\nfinding_vid = \"7\"",
        ),
        LoadErrorKind::ExcludedField,
        "`finding_vid`",
    );
}

const EXACT_GAP: &str = "[[expectation]]\nid = \"W-N-02\"\ntype = \"N\"\nbook_variant = \"native\"\nstatement_template = \"N.exact_gap\"\nbasis = [\"F4\"]\nkind = \"exact_gap\"\ntarget = \"F4\"\nprocedure = \"expense.capitalization\"\nversion = 2\nmechanism = \"crates/fa-lantern/src/cutoff.rs:1100\"\ntwin_kind = \"mutation\"\ntwin_expect = \"gap_zero\"\n";

#[test]
fn exact_gap_without_gap_amount_or_twin_target_is_refused() {
    let errs = load(&appended(EXACT_GAP)).expect_err("refused");
    refused(
        &errs,
        "expectations.toml",
        LoadErrorKind::MissingField,
        "`gap_amount` is required on an exact_gap N",
    );
    refused(
        &errs,
        "expectations.toml",
        LoadErrorKind::MissingField,
        "`twin_target` is required on an exact_gap N",
    );
    loads(
        &appended(&format!(
            "{EXACT_GAP}gap_amount = \"0.01\"\ngap_unit = \"USD\"\ntwin_target = \"F2\"\n{EXACT_GAP_SOURCED}"
        )),
        "a complete exact_gap N",
    );
}

/// The sourced values an exact_gap N's gap is measured from: one target row
/// for its `target` (F4) and one for its `twin_target` (F2).
const EXACT_GAP_SOURCED: &str = "\n[[target]]\nexpectation = \"W-N-02\"\nfact = \"F4\"\nstatistic_name = \"capitalized_amount\"\nstatistic_value = \"40000\"\nstatistic_scale = 2\n\n[[target]]\nexpectation = \"W-N-02\"\nfact = \"F2\"\nstatistic_name = \"capitalized_amount\"\nstatistic_value = \"0\"\n";

#[test]
fn exact_gap_without_its_sourced_target_rows_is_refused() {
    let complete =
        format!("{EXACT_GAP}gap_amount = \"0.01\"\ngap_unit = \"USD\"\ntwin_target = \"F2\"\n");
    let errs = load(&appended(&complete)).expect_err("refused");
    for (key, fact) in [("target", "F4"), ("twin_target", "F2")] {
        refused(
            &errs,
            "expectations.toml",
            LoadErrorKind::MissingField,
            &format!("states its `{key}` {fact}'s sourced value in a [[target]] row"),
        );
    }
    // The target's row alone still leaves the twin target unsourced.
    let target_only = EXACT_GAP_SOURCED
        .split("\n\n[[target]]")
        .next()
        .expect("the first row");
    let errs = load(&appended(&format!("{complete}{target_only}\n"))).expect_err("refused");
    refused(
        &errs,
        "expectations.toml",
        LoadErrorKind::MissingField,
        "states its `twin_target` F2's sourced value",
    );
    // A sourced row on a fact that is neither the target nor the twin target.
    let stray = "\n[[target]]\nexpectation = \"W-N-02\"\nfact = \"F9\"\nstatistic_name = \"capitalized_amount\"\nstatistic_value = \"1\"\n";
    refused_exp(
        &appended(&format!("{complete}{EXACT_GAP_SOURCED}{stray}")),
        LoadErrorKind::DanglingKey,
        "an exact_gap N's target row is its `target` or `twin_target`, not `F9`",
    );
}

#[test]
fn a_sourced_value_on_a_no_finding_n_target_is_refused() {
    refused_exp(
        &appended(
            "\n[[target]]\nexpectation = \"W-N-01\"\nfact = \"F2\"\nstatistic_value = \"1\"\n",
        ),
        LoadErrorKind::UnknownField,
        "`statistic_value` on an N target belongs to an exact_gap N",
    );
}

#[test]
fn n_kind_outside_the_closed_set_is_refused() {
    refused_exp(
        &edited("kind = \"no_finding\"", "kind = \"no_alarm\""),
        LoadErrorKind::UnknownValue,
        "`kind = \"no_alarm\"` is no_refusal, no_finding or exact_gap",
    );
}

const CF: &str = "[[expectation]]\nid = \"W-P-03-CF-01\"\ntype = \"CF\"\nbook_variant = \"native\"\nstatement_template = \"CF.counterfactual\"\nbasis = [\"F4\"]\nparent = \"W-P-03\"\nchanged_attribute = \"effective_date\"\nchanged_value = \"2001-07-17\"\nexpect = \"admit\"\n";

#[test]
fn cf_row_changing_two_attributes_is_refused() {
    loads(&appended(CF), "a CF changing one attribute loads");
    let two = CF.replace(
        "changed_attribute = \"effective_date\"",
        "changed_attribute = [\"effective_date\", \"entry_class\"]",
    );
    refused_exp(
        &appended(&two),
        LoadErrorKind::WrongType,
        "`changed_attribute` must be a string",
    );
    let joined = CF.replace(
        "\"effective_date\"\nchanged_value",
        "\"effective_date,entry_class\"\nchanged_value",
    );
    refused_exp(
        &appended(&joined),
        LoadErrorKind::UnknownValue,
        "a CF changes exactly one",
    );
}

#[test]
fn authored_self_row_is_refused() {
    refused_exp(
        &edited("id = \"W-D-03\"", "id = \"W-SELF-native\""),
        LoadErrorKind::ReservedId,
        "`W-SELF-native` is a generated row",
    );
}

#[test]
fn authored_guidance_n_is_refused() {
    refused_exp(
        &edited("id = \"W-N-01\"", "id = \"W-N-90\""),
        LoadErrorKind::ReservedId,
        "`W-N-90` is a generated row",
    );
}

#[test]
fn authored_case_show_row_is_refused() {
    refused_exp(
        &edited("id = \"W-D-03\"", "id = \"W-CASE-wc-restatement\""),
        LoadErrorKind::ReservedId,
        "`W-CASE-wc-restatement` is a generated row",
    );
}

#[test]
fn id_with_wrong_case_prefix_is_refused() {
    refused_exp(
        &with_expectations(&EXPECTATIONS.replace("\"W-D-03\"", "\"E-D-01\"")),
        LoadErrorKind::BadId,
        "a D row of case `W` is `W-D-NN`",
    );
    // An id whose type letter differs from its row's type.
    refused_exp(
        &edited("id = \"W-N-01\"", "id = \"W-D-09\""),
        LoadErrorKind::BadId,
        "a N row of case `W` is `W-N-NN`",
    );
}

#[test]
fn all_x_expectation_is_refused() {
    let note_row = "[[expectation]]\nid = \"W-D-09\"\ntype = \"D\"\nbook_variant = \"native\"\nstatement_template = \"D.detection\"\nbasis = [\"F4\"]\nprocedure = \"jet.post_closing\"\nversion = 1\n\n\
                    [[target]]\nexpectation = \"W-D-09\"\nfact = \"F4\"\ncite_status = \"X\"\nseverity_status = \"X\"\nstatistic_status = \"X\"\n";
    let procedures = fa_registry::procedures::Procedures::embedded().expect("procedures.toml");
    let version = procedures
        .get("jet.post_closing")
        .expect("registered")
        .version;
    let row = note_row.replace("version = 1", &format!("version = {version}"));
    refused_exp(
        &appended(&row),
        LoadErrorKind::AllComponentsX,
        "it is a [[note]]",
    );
}

const T_RULE: &str = "[[expectation]]\nid = \"W-T-01\"\ntype = \"T\"\nbook_variant = \"native\"\nstatement_template = \"T.rule\"\nbasis = [\"W406-TA-2000\"]\nkind = \"rule\"\nvintages = [\"source:SRC-WC-406\"]\nread_verb = \"balance\"\nread_target = \"1500\"\nread_coordinate = \"2001Q2\"\npublished = \"W406-TA-2000\"\n";

#[test]
fn t_rule_kind_without_its_rule_is_refused() {
    refused_exp(
        &appended(T_RULE),
        LoadErrorKind::MissingField,
        "a `rule` T names its derivation",
    );
    refused_exp(
        &appended(&format!("{T_RULE}rule = \"made_up_rule\"\n")),
        LoadErrorKind::DanglingKey,
        "`rule = \"made_up_rule\"` is not a rule of data/case_derivations.toml",
    );
}

#[test]
fn t_rule_kind_names_a_registered_derivation() {
    loads(
        &appended(&format!("{T_RULE}rule = \"trustee_transfer_credit\"\n")),
        "a rule T naming a §2.4 derivation",
    );
}

#[test]
fn unknown_template_id_is_refused() {
    refused_exp(
        &edited(
            "id = \"W-D-03\"\ntype = \"D\"\nbook_variant = \"native\"\nstatement_template = \"D.detection\"",
            "id = \"W-D-03\"\ntype = \"D\"\nbook_variant = \"native\"\nstatement_template = \"D.made_up\"",
        ),
        LoadErrorKind::UnknownValue,
        "`statement_template = \"D.made_up\"` is not a template id",
    );
    refused_exp(
        &edited(
            "id = \"W-D-03\"\ntype = \"D\"\nbook_variant = \"native\"\nstatement_template = \"D.detection\"",
            "id = \"W-D-03\"\ntype = \"D\"\nbook_variant = \"native\"\nstatement_template = \"P.first_refusal\"",
        ),
        LoadErrorKind::UnknownValue,
        "a D row takes a `D.` template, not `P.first_refusal`",
    );
}

fn claiming(claims: &str, expectations: &str) -> Files {
    files(
        &once(CASE, "claims = []", &format!("claims = [{claims}]")),
        NATIVE,
        expectations,
    )
}

#[test]
fn claimed_expectation_with_a_pending_cell_is_refused() {
    let pending = once(
        EXPECTATIONS,
        "cell = [\"none\"]\nexpect = \"FA-REF-080\"\nrecord_consistent = true",
        "cell = [\"none\"]\nexpect = \"FA-REF-080\"\nrecord_consistent = true\npending = \"fa-yugf.39: W5's ManualAssertion probe\"",
    );
    let errs = load(&claiming("\"W-P-02\"", &pending)).expect_err("a claimed pending cell");
    refused(
        &errs,
        "expectations.toml",
        LoadErrorKind::PendingClaimed,
        "W-P-02 is claimed",
    );
}

#[test]
fn pending_cell_on_an_unclaimed_expectation_loads() {
    let pending = once(
        EXPECTATIONS,
        "cell = [\"none\"]\nexpect = \"FA-REF-080\"\nrecord_consistent = true",
        "cell = [\"none\"]\nexpect = \"FA-REF-080\"\nrecord_consistent = true\npending = \"fa-yugf.39: W5's ManualAssertion probe\"",
    );
    let case = loads(
        &claiming("\"W-P-03\"", &pending),
        "an unclaimed pending cell",
    );
    let set = case.expectations.expect("expectations");
    assert!(set.branch_cells.iter().any(|c| c.pending().is_some()));
}

#[test]
fn claimed_expectation_loads_once_pending_is_removed() {
    loads(
        &claiming("\"W-P-02\"", EXPECTATIONS),
        "claimed, with no pending cell",
    );
}

#[test]
fn law_row_in_neither_form_is_refused() {
    refused_exp(
        &edited(
            "law_row = \"evidence_policy.toml#Original\"",
            "law_row = \"plan §14.3\"",
        ),
        LoadErrorKind::WrongType,
        "`plan:§<section>` (no space)",
    );
}

#[test]
fn law_row_naming_a_plan_section_loads() {
    loads(
        &edited(
            "law_row = \"evidence_policy.toml#Original\"",
            "law_row = \"plan:§14.3\"",
        ),
        "a plan-section law_row",
    );
}

#[test]
fn no_finding_n_without_its_procedure_is_refused() {
    refused_exp(
        &edited(
            "procedure = \"expense.capitalization\"\nversion = 2\nmechanism",
            "mechanism",
        ),
        LoadErrorKind::MissingField,
        "`procedure` is required on a no_finding or exact_gap N",
    );
}

#[test]
fn no_refusal_n_naming_a_procedure_is_refused() {
    let text = once(
        &once(
            EXPECTATIONS,
            "kind = \"no_finding\"",
            "kind = \"no_refusal\"",
        ),
        "statement_template = \"N.no_finding\"",
        "statement_template = \"N.no_refusal\"",
    );
    refused_exp(
        &with_expectations(&text),
        LoadErrorKind::UnknownField,
        "a no_refusal N observes the kernel's admission; it names no `procedure`",
    );
}

const T_ONE: &str = "[[expectation]]\nid = \"W-T-01\"\ntype = \"T\"\nbook_variant = \"native\"\nstatement_template = \"T.per_account\"\nbasis = [\"W406-TA-2000\"]\nkind = \"per_account\"\nvintages = [\"source:SRC-WC-406\"]\nread_verb = \"balance\"\nread_target = \"1500\"\nread_coordinate = \"2001Q2\"\npublished = \"W406-TA-2000\"\n";

#[test]
fn t_read_fields_on_expectation_and_target_both_are_refused() {
    let both = format!(
        "{T_ONE}\n[[target]]\nexpectation = \"W-T-01\"\nfact = \"F4\"\nread_verb = \"balance\"\nread_target = \"1500\"\nread_coordinate = \"2001Q2\"\npublished = \"W406-TA-2000\"\n"
    );
    refused_exp(
        &appended(&both),
        LoadErrorKind::ReadFieldsTwice,
        "never both",
    );
}

#[test]
fn multi_read_t_with_read_fields_on_each_target_loads() {
    let header = "[[expectation]]\nid = \"W-T-01\"\ntype = \"T\"\nbook_variant = \"native\"\nstatement_template = \"T.per_account\"\nbasis = [\"W406-TA-2000\"]\nkind = \"per_account\"\nvintages = [\"source:SRC-WC-406\"]\n";
    let targets = ["F4", "F9"]
        .iter()
        .map(|f| format!("\n[[target]]\nexpectation = \"W-T-01\"\nfact = \"{f}\"\nread_verb = \"balance\"\nread_target = \"1500\"\nread_coordinate = \"2001Q2\"\npublished = \"W406-TA-2000\"\n"))
        .collect::<String>();
    loads(
        &appended(&format!("{header}{targets}")),
        "reads on each target",
    );
}

#[test]
fn t_round_trip_kind_loads_with_its_template() {
    let rt = T_ONE
        .replace("T.per_account", "T.round_trip")
        .replace("kind = \"per_account\"", "kind = \"round_trip\"")
        .replace("source:SRC-WC-406", "B:SRC-WC-406");
    loads(&appended(&rt), "a round_trip T with T.round_trip");
}

#[test]
fn round_trip_named_with_another_template_is_refused() {
    let rt = T_ONE
        .replace("T.per_account", "T.bridge")
        .replace("kind = \"per_account\"", "kind = \"round_trip\"");
    refused_exp(
        &appended(&rt),
        LoadErrorKind::UnknownValue,
        "renders with `T.round_trip`, not `T.bridge`",
    );
}

#[test]
fn inputs_named_entry_naming_neither_a_fact_nor_an_intent_is_refused() {
    refused_exp(
        &appended(&format!(
            "{T_ONE}inputs_named = [\"nothing-of-the-sort\"]\n"
        )),
        LoadErrorKind::DanglingKey,
        "`inputs_named` entry `nothing-of-the-sort`",
    );
}

#[test]
fn inputs_named_and_d_target_may_name_a_delta_intent() {
    let rows = format!(
        "{T_ONE}inputs_named = [\"delta-F12\"]\n\n[[target]]\nexpectation = \"W-D-03\"\nfact = \"delta-F4\"\ncite = [\"delta-F4#0\"]\ncite_status = \"Sd\"\nseverity = \"Low\"\nseverity_status = \"S\"\nstatistic_value = \"1\"\nstatistic_status = \"S\"\n"
    );
    loads(&appended(&rows), "Δ intents as inputs and as a D target");
}

#[test]
fn reported_in_selector_with_no_such_issue_step_is_refused() {
    let issue = "\n[[step]]\nseq = 72\nkind = \"issue\"\nref = \"2002Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\"]\ndocument = \"DOC-406\"\n";
    let book = format!("{NATIVE}{issue}");
    let t1 = format!("{T_ONE}read_selector = \"reported_in:2002Q1\"\n");
    loads(
        &files(CASE, &book, &format!("{EXPECTATIONS}\n{t1}")),
        "issuance #1 exists",
    );
    let t2 = format!("{T_ONE}read_selector = \"reported_in:2002Q1#2\"\n");
    let errs = load(&files(CASE, &book, &format!("{EXPECTATIONS}\n{t2}"))).expect_err("refused");
    refused(
        &errs,
        "expectations.toml",
        LoadErrorKind::DanglingKey,
        "names issuance #2 of `2002Q1`",
    );
}

fn with_assert(reference: &str, extra_expectations: &str) -> Files {
    let step = format!(
        "\n[[step]]\nseq = 72\nkind = \"assert_balance\"\nref = \"{reference}\"\nprincipal = \"examiner-1\"\nevidence = \"DOC-406\"\n"
    );
    files(
        CASE,
        &format!("{NATIVE}{step}"),
        &format!("{EXPECTATIONS}\n{extra_expectations}"),
    )
}

const T_TARGETED: &str = "[[expectation]]\nid = \"W-R-04\"\ntype = \"R\"\nbook_variant = \"native\"\nstatement_template = \"R.read_back\"\nbasis = [\"F4\"]\n\n[[target]]\nexpectation = \"W-R-04\"\nfact = \"F4\"\nread_verb = \"balance\"\nread_target = \"1500\"\nread_coordinate = \"2001Q2\"\nposted = \"F4\"\n";

#[test]
fn assert_balance_ref_naming_an_unknown_target_is_refused() {
    let errs = load(&with_assert("W-R-04#F99", T_TARGETED)).expect_err("refused");
    refused(
        &errs,
        "books/native.toml",
        LoadErrorKind::DanglingKey,
        "`#F99` is not a [[target]] of W-R-04",
    );
}

#[test]
fn assert_balance_ref_naming_a_d_expectation_is_refused() {
    let errs = load(&with_assert("W-D-01", "")).expect_err("refused");
    refused(
        &errs,
        "books/native.toml",
        LoadErrorKind::WrongType,
        "it asserts a T or R's read",
    );
}

#[test]
fn assert_balance_ref_with_a_target_resolves() {
    loads(
        &with_assert("W-R-04#F4", T_TARGETED),
        "an assert_balance on a target",
    );
    let errs =
        load(&with_assert("W-R-04", T_TARGETED)).expect_err("a multi-read row needs its target");
    refused(
        &errs,
        "books/native.toml",
        LoadErrorKind::MissingField,
        "W-R-04 reads on its targets",
    );
}

#[test]
fn engagement_file_finding_ref_naming_a_non_d_expectation_is_refused() {
    let book = once(
        NATIVE,
        "ref = \"finding:W-D-01\"",
        "ref = \"finding:W-P-03\"",
    );
    let errs = load(&files(CASE, &book, EXPECTATIONS)).expect_err("refused");
    refused(
        &errs,
        "books/native.toml",
        LoadErrorKind::WrongType,
        "`finding:W-P-03` names a P row",
    );
}

#[test]
fn engagement_file_finding_ref_without_an_earlier_finding_record_step_is_refused() {
    let book = once(
        NATIVE,
        "ref = \"finding:W-D-01\"",
        "ref = \"finding:W-D-03\"",
    );
    let errs = load(&files(CASE, &book, EXPECTATIONS)).expect_err("refused");
    refused(
        &errs,
        "books/native.toml",
        LoadErrorKind::DanglingKey,
        "`jet.round_amounts@1` has no earlier finding_record step",
    );
}

#[test]
fn finding_review_naming_an_unknown_expectation_is_refused() {
    let step = "\n[[step]]\nseq = 72\nkind = \"finding_review\"\nref = \"W-D-77\"\n";
    let book = format!("{NATIVE}{step}");
    let errs = load(&files(CASE, &book, EXPECTATIONS)).expect_err("refused");
    refused(
        &errs,
        "books/native.toml",
        LoadErrorKind::DanglingKey,
        "finding_review names no expectation `W-D-77`",
    );
    let ok = format!("{NATIVE}{}", step.replace("W-D-77", "W-D-01"));
    loads(
        &files(CASE, &ok, EXPECTATIONS),
        "a finding_review of W-D-01 (default principal case-second-reader)",
    );
}

#[test]
fn claims_naming_an_unknown_id_is_refused() {
    let errs = load(&claiming("\"W-D-77\"", EXPECTATIONS)).expect_err("refused");
    refused(
        &errs,
        "case.toml",
        LoadErrorKind::DanglingKey,
        "claim `W-D-77`",
    );
}

#[test]
fn claims_may_name_generated_self_case_and_guidance_rows() {
    loads(
        &claiming(
            "\"W-SELF-native\", \"W-CASE-R1\", \"W-N-90\", \"W-D-01\"",
            EXPECTATIONS,
        ),
        "generated rows are claimable",
    );
    let errs = load(&claiming("\"W-CASE-R9\"", EXPECTATIONS)).expect_err("no case R9");
    refused(
        &errs,
        "case.toml",
        LoadErrorKind::DanglingKey,
        "claim `W-CASE-R9`",
    );
}

#[test]
fn known_at_pre_case_resolves_before_case_open_or_at_the_step() {
    let case = loads(&with_expectations(EXPECTATIONS), "the pilot loads");
    let book = &case.books["native"];
    let record = book
        .steps
        .iter()
        .position(|s| s.reference == "expense.capitalization@2")
        .expect("the finding_record step");
    let open = book
        .steps
        .iter()
        .position(|s| s.kind == "case_open")
        .expect("the case_open step");
    assert!(record < open);
    assert_eq!(
        frontier(book, KnownAt::PreCase, record),
        open,
        "the head just before case_open"
    );
    assert_eq!(frontier(book, KnownAt::Head, record), record);
    // A variant with no [[case]]: pre_case is the finding_record step itself.
    let record_step = "\n[[step]]\nseq = 4\nkind = \"finding_record\"\nref = \"expense.capitalization@2\"\nprincipal = \"case-closer-1\"\n";
    let mig = format!("{MIGRATION_MIN}{record_step}");
    let files: Files = vec![
        (
            "case.toml".into(),
            once(
                CASE,
                "variants = [\"native\"]",
                "variants = [\"migration\"]",
            ),
        ),
        ("sources.toml".into(), SOURCES.into()),
        ("facts.toml".into(), FACTS.into()),
        ("receipts.toml".into(), RECEIPTS.into()),
        ("roles.toml".into(), ROLES.into()),
        ("books/migration.toml".into(), mig),
    ];
    let case = loads(&files, "the migration fixture with a finding_record step");
    let book = &case.books["migration"];
    assert!(book.cases.is_empty());
    let at = book
        .steps
        .iter()
        .position(|s| s.kind == "finding_record")
        .expect("the step");
    assert_eq!(frontier(book, KnownAt::PreCase, at), at);
}

/// A5b (§2.6 rule 9): a `rel_rule` outside rel.rs's closed list is refused
/// at load, as is a role the registry does not list; a Rel component without
/// its rule, and a rule on a target with no Rel component, are refused too.
#[test]
fn rel_rule_outside_the_closed_list_is_refused() {
    const RULE: &str = "rel_rule = \"min_vid_debit_leg{fixed_asset}\"\n";
    let e = refused_exp(
        &edited(RULE, "rel_rule = \"median_vid_debit_leg{fixed_asset}\"\n"),
        LoadErrorKind::UnknownValue,
        "`median_vid_debit_leg` is outside the closed list (min_vid_debit_leg, max_vid_debit_leg)",
    );
    assert_eq!(e.row.as_deref(), Some("F9"));
    refused_exp(
        &edited(RULE, "rel_rule = \"min_vid_debit_leg{fixed_assets}\"\n"),
        LoadErrorKind::UnknownValue,
        "`fixed_assets` is not a role of registries/account_roles.toml",
    );
    refused_exp(
        &edited(RULE, ""),
        LoadErrorKind::MissingField,
        "a Rel(account_vid_order) component names its `rel_rule`",
    );
    refused_exp(
        &edited(
            "cite_status = \"Sd\"\nseverity = \"High\"",
            "cite_status = \"Sd\"\nrel_rule = \"max_vid_debit_leg{fixed_asset}\"\nseverity = \"High\"",
        ),
        LoadErrorKind::UnknownField,
        "on a target with no Rel(…) component",
    );
    // The listed maximum rule loads.
    loads(
        &edited(RULE, "rel_rule = \"max_vid_debit_leg{fixed_asset}\"\n"),
        "max_vid_debit_leg is listed",
    );
}
