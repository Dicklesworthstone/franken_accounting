//! The loaders over the pilot fixture (`tests/fixtures/pilot/`): it loads and
//! round-trips through the parser's canonical bytes, and each planted edit is
//! refused with its named error, file and line.

use super::fact::{self, LiteralRule};
use super::header::CaseExtension;
use super::rows::row_line;
use super::*;
use crate::sha256;

const CASE: &str = include_str!("../../tests/fixtures/pilot/case.toml");
const SOURCES: &str = include_str!("../../tests/fixtures/pilot/sources.toml");
const FACTS: &str = include_str!("../../tests/fixtures/pilot/facts.toml");
const RECEIPTS: &str = include_str!("../../tests/fixtures/pilot/receipts.toml");
const ROLES: &str = include_str!("../../tests/fixtures/pilot/roles.toml");
const NATIVE: &str = include_str!("../../tests/fixtures/pilot/books/native.toml");
const BINDING: &str = include_str!("../../data/binding_fixtures.toml");

pub(crate) type Files = Vec<(&'static str, String)>;

pub(crate) fn pilot() -> Files {
    vec![
        (CASE_FILE, CASE.to_string()),
        (SOURCES_FILE, SOURCES.to_string()),
        (FACTS_FILE, FACTS.to_string()),
        (RECEIPTS_FILE, RECEIPTS.to_string()),
        (ROLES_FILE, ROLES.to_string()),
        ("books/native.toml", NATIVE.to_string()),
    ]
}

pub(crate) fn load_files(
    id: &str,
    files: &Files,
    extensions: &[CaseExtension],
) -> Result<Case, Vec<LoadError>> {
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
    load_with(&CaseFiles { id, files: &refs }, extensions)
}

/// The pilot's expectations (A1c), which [`pilot`] leaves out.
pub(crate) const PILOT_EXPECTATIONS: &str =
    include_str!("../../tests/fixtures/pilot/expectations.toml");

/// The pilot with its expectations and each `(file, old, new)` edit applied
/// in order: `old` occurs exactly once in the file as it then stands, or is
/// empty to append `new`.
pub(crate) fn pilot_planted(edits: &[(&str, &str, &str)]) -> Case {
    let mut files = pilot();
    files.push((EXPECTATIONS_FILE, PILOT_EXPECTATIONS.to_string()));
    for (file, old, new) in edits {
        let entry = files
            .iter_mut()
            .find(|(p, _)| p == file)
            .expect("a pilot file");
        if old.is_empty() {
            entry.1.push_str(new);
        } else {
            assert_eq!(entry.1.matches(old).count(), 1, "`{old}` in {file}");
            entry.1 = entry.1.replacen(old, new, 1);
        }
    }
    load_files("worldcom", &files, CASE_EXTENSIONS).expect("the planted pilot loads")
}

/// The pilot with one file edited: `old` must occur exactly once in it.
fn edited(file: &str, old: &str, new: &str) -> Files {
    let mut files = pilot();
    let entry = files
        .iter_mut()
        .find(|(p, _)| *p == file)
        .expect("a pilot file");
    assert_eq!(
        entry.1.matches(old).count(),
        1,
        "plant `{old}` must occur once in {file}"
    );
    entry.1 = entry.1.replacen(old, new, 1);
    files
}

fn text_of<'a>(files: &'a Files, file: &str) -> &'a str {
    &files.iter().find(|(p, _)| *p == file).expect("a file").1
}

/// The line of the last `[[value]]` row (the one a test appended).
fn last_value_line(files: &Files) -> Option<usize> {
    let text = text_of(files, FACTS_FILE);
    let rows = text.lines().filter(|l| l.trim() == "[[value]]").count();
    row_line(text, "value", rows - 1)
}

/// The 1-based line of the first line of `needle` in `text`.
fn line_of(text: &str, needle: &str) -> usize {
    let at = text.find(needle).expect("the planted text");
    text[..at].matches('\n').count() + 1
}

/// The load is refused with an error of `kind` in `file` at `line`.
fn refused(
    result: Result<Case, Vec<LoadError>>,
    file: &str,
    kind: LoadErrorKind,
    line: Option<usize>,
) -> LoadError {
    let errs = result.expect_err("the planted edit must be refused");
    let found = errs
        .iter()
        .find(|e| e.file == file && e.kind == kind && (line.is_none() || e.line == line))
        .cloned();
    assert!(
        found.is_some(),
        "no {kind} in {file} at {line:?}; got: {errs:#?}"
    );
    found.expect("asserted above")
}

#[test]
fn pilot_fixture_loads() {
    let case = load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("the pilot loads");
    assert_eq!(case.header.id, "worldcom");
    assert_eq!(case.header.letter.as_deref(), Some("W"));
    assert_eq!(case.header.kind, CaseKind::Case);
    assert_eq!(case.sources.len(), 3);
    assert_eq!(case.facts.len(), 8);
    assert_eq!(
        case.values.len(),
        7,
        "A1b added F2#1 and F9#1 for the pilot book"
    );
    assert_eq!(case.receipts.len(), 7);
    assert!(case.receipts.iter().all(Receipt::binds));
    assert_eq!(
        case.roles.roles.len(),
        10,
        "A1b added six harness roles for the pilot book"
    );
    assert_eq!(case.books.len(), 1);
}

#[test]
fn pilot_fixture_round_trips_through_canonical_bytes() {
    let case = load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("the pilot loads");
    let parsed = |text: &str| {
        fa_registry::toml::parse(text)
            .expect("parses")
            .canonical_bytes()
    };
    assert_eq!(
        case.header.to_document().canonical_bytes(),
        parsed(CASE),
        "case.toml"
    );
    assert_eq!(
        source::to_document(&case.sources).canonical_bytes(),
        parsed(SOURCES),
        "sources.toml"
    );
    assert_eq!(
        fact::to_document(&case.facts, &case.values).canonical_bytes(),
        parsed(FACTS),
        "facts.toml"
    );
    assert_eq!(
        receipt::to_document(&case.receipts).canonical_bytes(),
        parsed(RECEIPTS),
        "receipts.toml"
    );
    assert_eq!(
        case.roles.to_document().canonical_bytes(),
        parsed(ROLES),
        "roles.toml"
    );
}

fn values_from_lines(fact: &str, lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 7, "{l:?}");
            let opt = |s: &str| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.parse::<i128>().expect("an integer"))
                }
            };
            Value {
                fact: fact.to_string(),
                ordinal: f[0].parse().expect("an ordinal"),
                literal: f[1].to_string(),
                rule: LiteralRule::parse(f[2]).expect("a rule"),
                param: opt(f[3]),
                value: f[4].to_string(),
                unit: f[5].to_string(),
                precision: opt(f[6]),
                line: None,
            }
        })
        .collect()
}

#[test]
fn values_canonical_matches_the_shared_fixture_rows() {
    let doc = fa_registry::toml::parse(BINDING).expect("binding_fixtures.toml parses");
    let rows = doc.arrays.get("values").expect("[[values]] rows");
    assert!(
        rows.iter().any(|r| r
            .get("value_lines")
            .and_then(|v| v.as_array())
            .is_some_and(<[_]>::is_empty)),
        "a boundary row with no values"
    );
    for row in rows {
        let s = |k: &str| row.get(k).and_then(|v| v.as_str()).expect(k).to_string();
        let lines: Vec<String> = row
            .get("value_lines")
            .and_then(|v| v.as_array())
            .expect("value_lines")
            .iter()
            .map(|v| v.as_str().expect("a line").to_string())
            .collect();
        let values = values_from_lines(&s("id"), &lines);
        let refs: Vec<&Value> = values.iter().collect();
        let bytes = fact::values_canonical(&s("about_scope"), &refs);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, s("canonical_hex"), "row {}", s("id"));
        assert_eq!(
            sha256::hex(&sha256::digest(&bytes)),
            s("values_sha256"),
            "row {}",
            s("id")
        );
    }
    // The pilot's receipts carry the same digests the shared rows define.
    let case = load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("the pilot loads");
    for r in &case.receipts {
        let fact = case
            .facts
            .iter()
            .find(|f| f.id == r.fact)
            .and_then(Fact::sourced)
            .expect("a sourced fact");
        let refs: Vec<&Value> = case.values.iter().filter(|v| v.fact == r.fact).collect();
        let digest = sha256::hex(&sha256::digest(&fact::values_canonical(
            &fact.about_scope,
            &refs,
        )));
        assert_eq!(digest, r.values_sha256, "receipt for {}", r.fact);
    }
}

// --- §15 negatives: one planted edit each -----------------------------------

#[test]
fn fact_with_two_provenance_kinds_is_refused() {
    let files = edited(
        FACTS_FILE,
        "anchor = \"p108:l20-22\"",
        "anchor = \"p108:l20-22\"\nrule = \"sum\"",
    );
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 1);
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::TwoProvenanceKinds,
        line,
    );
    assert_eq!(e.row.as_deref(), Some("F4"));
    assert!(
        e.to_string().starts_with(&format!(
            "facts.toml:{}: TwoProvenanceKinds: ",
            line.unwrap()
        )),
        "{e}"
    );
}

#[test]
fn value_with_missing_fact_is_refused() {
    let plant = "\n[[value]]\nfact = \"F99\"\nordinal = 1\nliteral = \"three\"\nrule = \"number_word\"\nvalue = \"3\"\nunit = \"\"\n";
    let mut files = pilot();
    files[2].1.push_str(plant);
    let line = last_value_line(&files);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::DanglingKey,
        line,
    );
}

fn toml_refused(file: &str, old: &str, new: &str, needle: &str, message: &str) {
    let files = edited(file, old, new);
    let line = line_of(text_of(&files, file), needle);
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        file,
        LoadErrorKind::Toml,
        Some(line),
    );
    assert!(e.detail.contains(message), "{e}");
}

#[test]
fn dotted_key_is_refused() {
    toml_refused(
        SOURCES_FILE,
        "id = \"SRC-WC-401\"",
        "id = \"SRC-WC-401\"\nsource.id = \"x\"",
        "source.id",
        "dotted",
    );
}

#[test]
fn multi_line_array_is_refused() {
    toml_refused(
        FACTS_FILE,
        "from = [\"F4\", \"F4-p26\"]",
        "from = [\n\"F4\",\n\"F4-p26\"]",
        "from = [",
        "unsupported value",
    );
}

#[test]
fn float_is_refused() {
    toml_refused(
        FACTS_FILE,
        "param = 6\nvalue = \"71800000000\"",
        "param = 6.0\nvalue = \"71800000000\"",
        "param = 6.0",
        "6.0",
    );
}

#[test]
fn toml_date_is_refused() {
    toml_refused(
        SOURCES_FILE,
        "retrieved_utc = \"2026-10-24T17:05:00Z\"",
        "retrieved_utc = 2026-10-24",
        "retrieved_utc = 2026",
        "2026-10-24",
    );
}

// --- derived negatives ---------------------------------------------------------

#[test]
fn case_kind_outside_the_closed_set_is_refused() {
    let files = edited(CASE_FILE, "kind = \"case\"", "kind = \"demo\"");
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        CASE_FILE,
        LoadErrorKind::UnknownValue,
        None,
    );
}

#[test]
fn deny_list_entry_in_clear_is_refused() {
    let files = edited(ROLES_FILE, "hashes = [\"", "hashes = [\"john smith\", \"");
    let line = line_of(text_of(&files, ROLES_FILE), "[deny]");
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        ROLES_FILE,
        LoadErrorKind::NotSha256Hex,
        Some(line),
    );
}

#[test]
fn receipt_missing_a_binding_boolean_is_refused() {
    let mut files = pilot();
    files[3].1 = files[3].1.replacen("scope_ok = true\n", "", 1);
    let line = row_line(text_of(&files, RECEIPTS_FILE), "receipt", 0);
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        RECEIPTS_FILE,
        LoadErrorKind::MissingField,
        line,
    );
    assert!(e.detail.contains("scope_ok"), "{e}");
}

#[test]
fn receipt_original_hash_compared_mismatch_is_refused() {
    let mut files = pilot();
    files[3].1 = files[3].1.replacen(
        "original_hash_compared = false",
        "original_hash_compared = true",
        1,
    );
    let line = row_line(text_of(&files, RECEIPTS_FILE), "receipt", 0);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        RECEIPTS_FILE,
        LoadErrorKind::ReceiptMismatch,
        line,
    );
}

#[test]
fn misspelled_field_is_refused() {
    let mut files = pilot();
    files[2].1 = files[2].1.replacen("quote_sha256 =", "qoute_sha256 =", 1);
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 0);
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::UnknownField,
        line,
    );
    assert!(e.detail.contains("qoute_sha256"), "{e}");
}

#[test]
fn anchor_string_that_does_not_parse_is_refused() {
    let files = edited(FACTS_FILE, "anchor = \"p106:l10-12\"", "anchor = \"111\"");
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 0);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::WrongType,
        line,
    );
}

#[test]
fn case_id_differing_from_its_directory_is_refused() {
    refused(
        load_files("enron", &pilot(), CASE_EXTENSIONS),
        CASE_FILE,
        LoadErrorKind::UnknownValue,
        None,
    );
}

#[test]
fn case_without_a_letter_is_refused() {
    let files = edited(CASE_FILE, "letter = \"W\"\n", "");
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        CASE_FILE,
        LoadErrorKind::MissingField,
        None,
    );
    assert!(e.detail.contains("letter"), "{e}");
}

#[test]
fn case_letter_outside_the_six_is_refused() {
    let files = edited(CASE_FILE, "letter = \"W\"", "letter = \"Q\"");
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        CASE_FILE,
        LoadErrorKind::UnknownValue,
        None,
    );
}

#[test]
fn letter_on_a_harness_selftest_case_is_refused() {
    let files = edited(CASE_FILE, "kind = \"case\"", "kind = \"harness_selftest\"");
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        CASE_FILE,
        LoadErrorKind::UnknownValue,
        None,
    );
    assert!(e.detail.contains("harness_selftest"), "{e}");
}

#[test]
fn receipt_alignment_not_matching_its_anchor_kind_is_refused() {
    let files = edited(
        RECEIPTS_FILE,
        "alignment = \"value\"",
        "alignment = \"sentence\"",
    );
    // The receipt that was value-aligned (the pilot's one table_cell fact).
    let text = text_of(&files, RECEIPTS_FILE);
    let index = text
        .split("[[receipt]]")
        .skip(1)
        .position(|row| row.contains("fact = \"W406-TA-2000\""))
        .expect("W406-TA-2000's receipt");
    let line = row_line(text, "receipt", index);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        RECEIPTS_FILE,
        LoadErrorKind::ReceiptMismatch,
        line,
    );
}

#[test]
fn receipt_values_sha256_not_hex_is_refused() {
    let mut files = pilot();
    let at = files[3]
        .1
        .find("values_sha256 = \"")
        .expect("a values_sha256")
        + "values_sha256 = \"".len();
    files[3].1.replace_range(at..at + 64, "not-a-digest");
    let line = row_line(text_of(&files, RECEIPTS_FILE), "receipt", 0);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        RECEIPTS_FILE,
        LoadErrorKind::NotSha256Hex,
        line,
    );
}

#[test]
fn unknown_case_key_without_an_extension_row_is_refused() {
    let files = edited(
        CASE_FILE,
        "variants = [\"native\"]",
        "variants = [\"native\"]\ncensus_count = 1",
    );
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        CASE_FILE,
        LoadErrorKind::UnknownField,
        None,
    );
    assert!(
        e.detail.contains("census_count") && e.detail.contains("worldcom"),
        "{e}"
    );
    // The same key is admitted under a (test-only) extension row of its case.
    let rows = [CaseExtension {
        case: "worldcom",
        table: "case",
        keys: &["census_count"],
    }];
    let case = load_files("worldcom", &files, &rows).expect("admitted under its extension row");
    assert_eq!(
        case.header.extensions.get("census_count"),
        Some(&fa_registry::toml::Value::Int(1))
    );
}

const LEDGER_FACT: &str = "\n[[fact]]\nid = \"EXB\"\nprovenance = \"sourced\"\nsource = \"SRC-WC-001\"\nanchor_kind = \"exhibit\"\nanchor = \"Exhibit B-1|p3-41\"\nquote_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nabout_scope = \"a table of rows\"\ngranularity = \"GRAN\"\nrows_file = \"exhibit_b_rows.toml\"\ncomplaint = \"SRC-WC-001\"\n";

fn with_ledger_fact(granularity: &str) -> Files {
    let mut files = pilot();
    files[2]
        .1
        .push_str(&LEDGER_FACT.replace("GRAN", granularity));
    files
}

#[test]
fn rows_file_on_a_journal_entry_fact_is_refused() {
    let files = with_ledger_fact("journal_entry");
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 8);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::UnknownField,
        line,
    );
}

#[test]
fn ledger_row_fact_with_an_uncommitted_rows_file_loads_with_rows_committed_false() {
    let files = with_ledger_fact("ledger_row");
    let case = load_files("worldcom", &files, CASE_EXTENSIONS).expect("loads");
    let f = case
        .facts
        .iter()
        .find(|f| f.id == "EXB")
        .and_then(Fact::sourced)
        .expect("EXB");
    assert!(!f.rows_committed);
    // With the rows file present, the same fact is committed.
    let mut with_rows = files;
    with_rows.push(("exhibit_b_rows.toml", String::new()));
    let case = load_files("worldcom", &with_rows, CASE_EXTENSIONS).expect("loads");
    assert!(
        case.facts
            .iter()
            .find(|f| f.id == "EXB")
            .and_then(Fact::sourced)
            .expect("EXB")
            .rows_committed
    );
}

#[test]
fn dated_aggregate_series_fact_with_an_uncommitted_rows_file_loads_with_rows_committed_false() {
    let case = load_files(
        "worldcom",
        &with_ledger_fact("dated_aggregate"),
        CASE_EXTENSIONS,
    )
    .expect("loads");
    let f = case
        .facts
        .iter()
        .find(|f| f.id == "EXB")
        .and_then(Fact::sourced)
        .expect("EXB");
    assert!(!f.rows_committed);
}

#[test]
fn exhibit_anchor_on_a_fact_without_rows_file_is_refused() {
    let files = edited(
        FACTS_FILE,
        "anchor_kind = \"page\"\nanchor = \"p106:l10-12\"",
        "anchor_kind = \"exhibit\"\nanchor = \"Exhibit B-1|p3-41\"",
    );
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 0);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::WrongType,
        line,
    );
}

#[test]
fn rows_file_fact_with_a_table_cell_anchor_is_refused() {
    let mut files = with_ledger_fact("ledger_row");
    files[2].1 = files[2].1.replacen(
        "anchor_kind = \"exhibit\"\nanchor = \"Exhibit B-1|p3-41\"",
        "anchor_kind = \"table_cell\"\nanchor = \"B-1|row|col\"",
        1,
    );
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 8);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::WrongType,
        line,
    );
}

#[test]
fn exhibit_anchor_parses_its_page_range() {
    assert!(fact::check_anchor(source::AnchorKind::Exhibit, "Exhibits B-1 to B-6|p3-41").is_ok());
    assert!(fact::check_anchor(source::AnchorKind::Exhibit, "Exhibit B-1|p41-3").is_err());
}

fn with_value(value_row: &str) -> Files {
    let mut files = pilot();
    files[2].1.push_str(value_row);
    files
}

#[test]
fn unitless_ratio_value_in_tenths_loads() {
    let files = with_value(
        "\n[[value]]\nfact = \"F12\"\nordinal = 2\nliteral = \"13.9x\"\nrule = \"scale\"\nvalue = \"139\"\nunit = \"\"\nprecision = -1\n",
    );
    let case =
        load_files("worldcom", &files, CASE_EXTENSIONS).expect("a unitless ratio in tenths loads");
    assert!(
        case.values
            .iter()
            .any(|v| v.value == "139" && v.precision == Some(-1))
    );
}

#[test]
fn negative_precision_on_a_currency_value_is_refused() {
    let files = with_value(
        "\n[[value]]\nfact = \"F12\"\nordinal = 2\nliteral = \"$718 million\"\nrule = \"scale\"\nvalue = \"71800000000\"\nunit = \"USD\"\nprecision = -1\n",
    );
    let line = last_value_line(&files);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::WrongType,
        line,
    );
}

#[test]
fn unitless_value_that_is_not_an_integer_is_refused() {
    let files = with_value(
        "\n[[value]]\nfact = \"F12\"\nordinal = 2\nliteral = \"13.9x\"\nrule = \"scale\"\nvalue = \"13.9\"\nunit = \"\"\nprecision = -1\n",
    );
    let line = last_value_line(&files);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::WrongType,
        line,
    );
}

#[test]
fn duplicate_cell_within_one_source_is_refused() {
    let mut files = pilot();
    files[2].1.push_str("\n[[fact]]\nid = \"W406-TA-2000-again\"\nprovenance = \"sourced\"\nsource = \"SRC-WC-406\"\nanchor_kind = \"table_cell\"\nanchor = \"Balance Sheet|Total assets|2000\"\nquote_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\nabout_scope = \"again\"\ngranularity = \"statement_line\"\ncell = \"total_assets@2000-12-31\"\n");
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 8);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::DuplicateId,
        line,
    );
}

#[test]
fn fact_assurance_without_its_assurance_fact_is_refused() {
    let files = edited(FACTS_FILE, "assurance_fact = \"W406-ITEM6\"\n", "");
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 7);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::MissingField,
        line,
    );
}

#[test]
fn fact_assurance_fact_of_another_source_is_refused() {
    let files = edited(
        FACTS_FILE,
        "assurance_fact = \"W406-ITEM6\"",
        "assurance_fact = \"F2\"",
    );
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 7);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::DanglingKey,
        line,
    );
}

#[test]
fn fact_assurance_on_a_non_filer_source_is_refused() {
    let files = edited(
        FACTS_FILE,
        "anchor = \"p113:l3-4\"",
        "anchor = \"p113:l3-4\"\nassurance = \"audited\"\nassurance_fact = \"F2\"",
    );
    let line = row_line(text_of(&files, FACTS_FILE), "fact", 3);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        FACTS_FILE,
        LoadErrorKind::UnknownValue,
        line,
    );
}

#[test]
fn selected_data_fact_narrows_its_audited_row() {
    let case = load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("loads");
    let src = case
        .sources
        .iter()
        .find(|s| s.id == "SRC-WC-406")
        .expect("the restating 10-K");
    assert_eq!(src.assurance, Some(Assurance::Audited));
    let f = case
        .facts
        .iter()
        .find(|f| f.id == "W406-TA-2000")
        .and_then(Fact::sourced)
        .expect("the cell fact");
    assert_eq!(f.assurance, Some(Assurance::NotFromAudited));
    assert_eq!(f.assurance_fact.as_deref(), Some("W406-ITEM6"));
}

#[test]
fn case_header_missing_a_required_field_is_refused() {
    let files = edited(CASE_FILE, "pinned_commit = \"8196f5e40\"\n", "");
    let e = refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        CASE_FILE,
        LoadErrorKind::MissingField,
        None,
    );
    assert!(e.detail.contains("pinned_commit"), "{e}");
}

#[test]
fn case_header_with_empty_claims_capabilities_and_variants_loads() {
    let mut files = edited(CASE_FILE, "variants = [\"native\"]", "variants = []");
    // A case with no variants has no books (A1b refuses an undeclared one).
    files.retain(|(p, _)| !p.starts_with("books/"));
    files[0].1 = files[0].1.replacen(
        "capabilities = [\"procedure:expense.capitalization@2\", \"refusal:FA-REF-080\", \"verb:post\"]",
        "capabilities = []",
        1,
    );
    let case = load_files("worldcom", &files, CASE_EXTENSIONS).expect("empty arrays load");
    assert!(
        case.header.claims.is_empty()
            && case.header.capabilities.is_empty()
            && case.header.variants.is_empty()
    );
}

#[test]
fn restates_naming_an_unknown_source_is_refused() {
    let files = edited(
        SOURCES_FILE,
        "restates = [\"SRC-WC-401\"]",
        "restates = [\"SRC-WC-999\"]",
    );
    let line = row_line(text_of(&files, SOURCES_FILE), "source", 2);
    refused(
        load_files("worldcom", &files, CASE_EXTENSIONS),
        SOURCES_FILE,
        LoadErrorKind::DanglingKey,
        line,
    );
}

#[test]
fn every_error_is_reported_not_only_the_first() {
    // Two independent plants in two files: both are reported, sorted by file.
    let mut files = edited(CASE_FILE, "letter = \"W\"", "letter = \"Q\"");
    files[3].1 = files[3].1.replacen(
        "original_hash_compared = false",
        "original_hash_compared = true",
        1,
    );
    let errs = load_files("worldcom", &files, CASE_EXTENSIONS).expect_err("two plants are refused");
    assert!(
        errs.iter()
            .any(|e| e.file == CASE_FILE && e.kind == LoadErrorKind::UnknownValue)
    );
    assert!(
        errs.iter()
            .any(|e| e.file == RECEIPTS_FILE && e.kind == LoadErrorKind::ReceiptMismatch)
    );
    let files_in_order: Vec<&str> = errs.iter().map(|e| e.file.as_str()).collect();
    let mut sorted = files_in_order.clone();
    sorted.sort_unstable();
    assert_eq!(files_in_order, sorted, "errors are sorted by file");
}
