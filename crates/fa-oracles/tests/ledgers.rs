//! The offline ledger gate (docs/FORENSIC_CASE_STUDIES_PLAN.md §4.6, §15
//! A10a). Every committed case loads; every sourced fact is bound by its
//! receipt; every load-time check from K-PROV through K-JOINT, and each case's
//! own registered checks, passes or has no input rows; the excerpt policy
//! (OD 2a) holds; the harness tables load; and every marker in committed case
//! data and case READMEs resolves against the registries. No network and no
//! fetch cache: source fidelity rests on the receipts (§4.3).
//!
//! The transcript uses the gate vocabulary: one `CHECK <case> <K-ID>` line
//! per check (A3a's line with the case id), `SOURCE`, `EXCERPTS` and `TABLE`
//! lines, an anchored `FAIL ` line per failing row, and a final `LEDGERS`
//! line. A check is UNRUN only when its case has no rows of its input kind;
//! one that examined fewer rows than its inputs fails (`CheckReport::finish`),
//! except for inputs pending owner decision 2b, which it reports
//! `unrun=<k> (OD 2b)`.

use std::collections::BTreeSet;
use std::path::Path;

use fa_oracles::cases::check::{CASE_CHECKS, CaseCheck, CheckReport, Context, Verdict};
use fa_oracles::cases::embedded::{CASES, WORLDCOM};
use fa_oracles::cases::policy::{MAX_QUOTE_WORDS, QUOTE_TEXT_ALLOWED};
use fa_oracles::cases::{Case, CaseFiles, branch, check, derive, load, tiers};
use fa_registry::toml::{Document, parse};

/// The registries a `[[marker_family]]` row may name, embedded so the
/// crate's verdict hash covers them.
const REGISTRIES: [(&str, &str); 9] = [
    (
        "claims_lint.toml",
        include_str!("../../../registries/claims_lint.toml"),
    ),
    (
        "constitution.toml",
        include_str!("../../../registries/constitution.toml"),
    ),
    (
        "invariants.toml",
        include_str!("../../../registries/invariants.toml"),
    ),
    (
        "evidence.toml",
        include_str!("../../../registries/evidence.toml"),
    ),
    (
        "refusal_catalog.toml",
        include_str!("../../../registries/refusal_catalog.toml"),
    ),
    (
        "threat_model.toml",
        include_str!("../../../registries/threat_model.toml"),
    ),
    (
        "proof_lanes.toml",
        include_str!("../../../registries/proof_lanes.toml"),
    ),
    ("slo.toml", include_str!("../../../registries/slo.toml")),
    (
        "evidence_artifacts.toml",
        include_str!("../../../registries/evidence_artifacts.toml"),
    ),
];

const BINDING_FIXTURES: &str = include_str!("../data/binding_fixtures.toml");

#[derive(Default)]
struct Transcript {
    lines: Vec<String>,
}

impl Transcript {
    fn line(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    fn fails(&self) -> Vec<&str> {
        self.lines
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("FAIL "))
            .collect()
    }

    fn text(&self) -> String {
        self.lines.join("\n")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Pass,
    Fail,
    Unrun,
}

/// One case's ledger verdict, its lines appended to `t`.
fn validate_case(
    id: &str,
    files: &[(&str, &str)],
    case_checks: &[CaseCheck],
    t: &mut Transcript,
) -> Outcome {
    let case = match load(&CaseFiles { id, files }) {
        Ok(case) => case,
        Err(errs) => {
            for e in errs {
                let line = e.line.map_or_else(|| "-".to_string(), |l| l.to_string());
                let row = e.row.unwrap_or_else(|| "-".into());
                t.line(format!(
                    "FAIL {id} load {}:{line} {row}: {:?}: {}",
                    e.file, e.kind, e.detail
                ));
            }
            return Outcome::Fail;
        }
    };
    for s in &case.sources {
        t.line(format!(
            "SOURCE {} original_hash_compared={} route={}",
            s.id,
            s.original_hash_compared,
            s.retrieval_route.as_str()
        ));
    }
    let reports = check::run_load_checks_with(&Context::new(&case), case_checks);
    let mut failed = false;
    for report in &reports {
        failed |= report.verdict == Verdict::Fail;
        emit(id, report, t);
    }
    failed |= excerpts(id, &case, t);
    if failed {
        Outcome::Fail
    } else if reports.iter().all(|r| r.verdict == Verdict::Unrun) {
        Outcome::Unrun
    } else {
        Outcome::Pass
    }
}

/// A report's lines with the case id in its `CHECK` and `FAIL` lines.
fn emit(id: &str, report: &CheckReport, t: &mut Transcript) {
    for line in report.render(Some(id)).lines() {
        match line.strip_prefix("FAIL ") {
            Some(rest) => t.line(format!("FAIL {id} {rest}")),
            None => t.line(line),
        }
    }
}

/// The excerpt volume (§4.2) and the OD 2a policy; true on a violation.
fn excerpts(id: &str, case: &Case, t: &mut Transcript) -> bool {
    let quoted: Vec<(&str, &str)> = case
        .facts
        .iter()
        .filter_map(|f| Some((f.id.as_str(), f.sourced()?.quote.as_deref()?)))
        .collect();
    let words: usize = quoted
        .iter()
        .map(|(_, q)| q.split_whitespace().count())
        .sum();
    t.line(format!(
        "EXCERPTS {id} facts_with_quote={} words={words}",
        quoted.len()
    ));
    let mut violated = false;
    for (fact, quote) in quoted {
        let n = quote.split_whitespace().count();
        if !QUOTE_TEXT_ALLOWED {
            t.line(format!(
                "FAIL {id} EXCERPTS facts.toml {fact}: a committed `quote` while owner decision 2a is undecided (QUOTE_TEXT_ALLOWED = false)"
            ));
            violated = true;
        } else if n > MAX_QUOTE_WORDS {
            t.line(format!(
                "FAIL {id} EXCERPTS facts.toml {fact}: the quote has {n} words, over {MAX_QUOTE_WORDS}"
            ));
            violated = true;
        }
    }
    violated
}

/// The harness tables under `data/` load; true when every one does.
fn validate_tables(t: &mut Transcript) -> bool {
    let mut ok = true;
    let mut table = |file: &str, result: Result<(), Vec<String>>| match result {
        Ok(()) => t.line(format!("TABLE {file} PASS")),
        Err(problems) => {
            ok = false;
            for p in problems {
                t.line(format!("FAIL table {file}: {p}"));
            }
        }
    };
    let shown = |errs: Vec<fa_oracles::cases::error::LoadError>| {
        errs.iter().map(ToString::to_string).collect::<Vec<_>>()
    };
    table(
        "case_derivations.toml",
        derive::Rules::embedded().map(|_| ()).map_err(shown),
    );
    table(
        "case_procedure_tiers.toml",
        tiers::tiers().map(|_| ()).map_err(shown),
    );
    table(
        "case_branch_rules.toml",
        branch::rules().map(|_| ()).map_err(shown),
    );
    table(
        "binding_fixtures.toml",
        parse(BINDING_FIXTURES)
            .map(|_| ())
            .map_err(|e| vec![e.to_string()]),
    );
    ok
}

/// The whole gate over `cases`: the transcript and its verdict.
fn validate(cases: &[(&str, Vec<(&str, &str)>)], case_checks: &[CaseCheck]) -> Transcript {
    let mut t = Transcript::default();
    let tables_ok = validate_tables(&mut t);
    let (mut pass, mut fail, mut unrun) = (0, 0, 0);
    for (id, files) in cases {
        match validate_case(id, files, case_checks, &mut t) {
            Outcome::Pass => pass += 1,
            Outcome::Fail => fail += 1,
            Outcome::Unrun => unrun += 1,
        }
    }
    if !tables_ok {
        fail += 1;
    }
    t.line(format!(
        "LEDGERS cases={} pass={pass} fail={fail} unrun={unrun}",
        cases.len()
    ));
    t
}

fn committed() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    CASES.iter().map(|c| (c.id, c.files.to_vec())).collect()
}

#[test]
fn ledgers_validate_offline() {
    let t = validate(&committed(), CASE_CHECKS);
    println!("{}", t.text());
    assert!(t.fails().is_empty(), "{}", t.text());
    let last = t.lines.last().expect("the LEDGERS line");
    assert!(
        last.starts_with(&format!("LEDGERS cases={} ", CASES.len())) && last.contains(" fail=0 "),
        "{last}"
    );
    // WorldCom's binding lines: every fact (74) and every sourced fact (52) examined.
    for (check, n) in [
        ("K-PROV", 74),
        ("K-BIND", 52),
        ("K-SCOPE", 52),
        ("K-ANCHOR", 52),
    ] {
        let line = format!("CHECK worldcom {check} PASS examined={n}/{n}");
        assert!(t.lines.contains(&line), "{line}\n{}", t.text());
    }
    assert!(t.lines.contains(
        &"SOURCE SRC-WC-001 original_hash_compared=false route=archive_capture".to_string()
    ));
    assert!(
        t.lines
            .contains(&"EXCERPTS worldcom facts_with_quote=0 words=0".to_string())
    );
}

// --- planted negatives through the gate's entry point ----------------------

/// WorldCom's files with one edit, for a planted negative.
fn worldcom_with(file: &str, old: &str, new: &str) -> Vec<(&'static str, String)> {
    WORLDCOM
        .files
        .iter()
        .map(|(path, text)| {
            let text = if *path == file {
                assert_eq!(text.matches(old).count(), 1, "plant `{old}` in {file}");
                text.replacen(old, new, 1)
            } else {
                (*text).to_string()
            };
            (*path, text)
        })
        .collect()
}

fn validate_copy(files: &[(&'static str, String)], case_checks: &[CaseCheck]) -> Transcript {
    let view: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
    validate(&[("worldcom", view)], case_checks)
}

fn assert_fails(t: &Transcript, needles: &[&str]) {
    assert!(
        t.fails()
            .iter()
            .any(|l| needles.iter().all(|n| l.contains(n))),
        "no FAIL line naming {needles:?}:\n{}",
        t.text()
    );
    assert!(t.lines.last().unwrap().contains(" fail=1 "), "{}", t.text());
}

/// F9's receipt row in receipts.toml, for planting on it.
fn f9_receipt() -> &'static str {
    let text = WORLDCOM
        .files
        .iter()
        .find(|(p, _)| *p == "receipts.toml")
        .unwrap()
        .1;
    let at = text.find("fact = \"F9\"\n").unwrap();
    let start = text[..at].rfind("[[receipt]]").unwrap();
    let end = text[at..]
        .find("\n[[receipt]]")
        .map_or(text.len(), |e| at + e + 1);
    &text[start..end]
}

#[test]
fn sourced_fact_without_a_receipt_fails() {
    let files = worldcom_with("receipts.toml", f9_receipt(), "");
    let t = validate_copy(&files, CASE_CHECKS);
    assert_fails(
        &t,
        &["FAIL worldcom K-BIND", "F9", "no receipt binds the fact"],
    );
}

#[test]
fn receipt_whose_quote_sha256_disagrees_fails() {
    let files = worldcom_with(
        "receipts.toml",
        "quote_sha256 = \"eddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aadf\"",
        "quote_sha256 = \"eddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aade\"",
    );
    let t = validate_copy(&files, CASE_CHECKS);
    assert_fails(&t, &["FAIL worldcom K-BIND", "F9", "quote_sha256"]);
}

#[test]
fn fact_value_edited_after_verify_fails_through_values_sha256() {
    let files = worldcom_with(
        "facts.toml",
        "value = \"74272500000\"",
        "value = \"74272500001\"",
    );
    let t = validate_copy(&files, CASE_CHECKS);
    assert_fails(
        &t,
        &["FAIL worldcom K-BIND", "F9", "values_sha256 mismatch"],
    );
}

#[test]
fn receipt_for_a_non_sourced_fact_fails() {
    // An interpretation joining two sourced facts, given a receipt it may not have.
    let mut files = worldcom_with(
        "facts.toml",
        "[[value]]\nfact = \"F2-period\"",
        "[[fact]]\nid = \"W-PLANT-JOIN\"\nprovenance = \"interpretation\"\nfrom = [\"F2\", \"F2-period\"]\nreader = \"case-author-1\"\nsecond_reader = \"case-second-reader\"\nrationale = \"planted\"\n\n[[value]]\nfact = \"F2-period\"",
    );
    let receipt = f9_receipt().replace("fact = \"F9\"", "fact = \"W-PLANT-JOIN\"");
    files
        .iter_mut()
        .find(|(p, _)| *p == "receipts.toml")
        .unwrap()
        .1
        .push_str(&format!("\n{receipt}"));
    let t = validate_copy(&files, CASE_CHECKS);
    assert_fails(
        &t,
        &[
            "FAIL worldcom load receipts.toml",
            "W-PLANT-JOIN",
            "not sourced",
        ],
    );
}

#[test]
fn committed_quote_text_fails_while_od_2a_is_undecided() {
    let files = worldcom_with(
        "facts.toml",
        "quote_sha256 = \"eddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aadf\"\nabout_scope = \"entry:F9\"\n",
        "quote_sha256 = \"eddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aadf\"\nquote = \"planted quote text\"\nabout_scope = \"entry:F9\"\n",
    );
    let t = validate_copy(&files, CASE_CHECKS);
    assert!(
        t.lines
            .contains(&"EXCERPTS worldcom facts_with_quote=1 words=3".to_string()),
        "{}",
        t.text()
    );
    let refused = ["FAIL worldcom EXCERPTS facts.toml F9", "owner decision 2a"];
    if QUOTE_TEXT_ALLOWED {
        // Once OD 2a is recorded, a three-word quote is within the bound.
        assert!(
            !t.fails().iter().any(|l| l.contains(refused[0])),
            "{}",
            t.text()
        );
    } else {
        assert_fails(&t, &refused);
    }
}

#[test]
fn a_quote_over_the_word_bound_is_refused_once_quotes_are_allowed() {
    let long = vec!["word"; MAX_QUOTE_WORDS + 1].join(" ");
    let files = worldcom_with(
        "facts.toml",
        "quote_sha256 = \"eddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aadf\"\nabout_scope = \"entry:F9\"\n",
        &format!(
            "quote_sha256 = \"eddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aadf\"\nquote = \"{long}\"\nabout_scope = \"entry:F9\"\n"
        ),
    );
    let t = validate_copy(&files, CASE_CHECKS);
    // Refused either way: by OD 2a now, by the word bound once it is allowed.
    let reason = if QUOTE_TEXT_ALLOWED {
        format!("{} words, over {MAX_QUOTE_WORDS}", MAX_QUOTE_WORDS + 1)
    } else {
        "owner decision 2a".to_string()
    };
    assert_fails(&t, &["FAIL worldcom EXCERPTS facts.toml F9", &reason]);
}

/// A test-only check that examines one row fewer than its inputs.
fn skipping_check(case: &Case) -> CheckReport {
    let mut r = CheckReport::new("K-SKIP", case.facts.len());
    for f in case.facts.iter().skip(1) {
        r.examined(f.id.clone());
    }
    r.finish()
}

#[test]
fn check_examining_fewer_rows_than_its_input_fails() {
    let skip = [CaseCheck {
        case: "worldcom",
        name: "skip",
        run: skipping_check,
    }];
    let files: Vec<(&'static str, String)> = WORLDCOM
        .files
        .iter()
        .map(|(p, t)| (*p, (*t).to_string()))
        .collect();
    let t = validate_copy(&files, &skip);
    let facts = load(&CaseFiles {
        id: WORLDCOM.id,
        files: WORLDCOM.files,
    })
    .expect("the committed case loads")
    .facts
    .len();
    let skipped = format!(
        "examined {} + pending 0 < inputs {facts} (a skipped row)",
        facts - 1
    );
    assert_fails(&t, &["FAIL worldcom case:worldcom:skip", &skipped]);
}

// --- markers -----------------------------------------------------------------

/// One marker family of claims_lint.toml and the ids its registry declares.
struct Family {
    prefix: String,
    registry: String,
    known: BTreeSet<String>,
}

fn registry(name: &str) -> Document {
    let text = REGISTRIES
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("registry {name} is not embedded in tests/ledgers.rs"))
        .1;
    parse(text).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn column<'a>(doc: &'a Document, table: &str, key: &str) -> impl Iterator<Item = String> + 'a {
    let key = key.to_string();
    doc.arrays
        .get(table)
        .into_iter()
        .flatten()
        .filter_map(move |row| row.get(&key)?.as_str().map(str::to_string))
}

/// Every `[[marker_family]]`, resolved against its registry/table/key; the
/// refusal family also admits the catalog's reserved codes (as
/// registry-check does).
fn families() -> Vec<Family> {
    let lint = registry("claims_lint.toml");
    let mut out = Vec::new();
    for row in lint.arrays.get("marker_family").expect("marker families") {
        let field = |k: &str| row.get(k).and_then(|v| v.as_str()).expect(k).to_string();
        let (prefix, reg, table, key) = (
            field("prefix"),
            field("registry"),
            field("table"),
            field("key"),
        );
        let doc = registry(&reg);
        let mut known: BTreeSet<String> = column(&doc, &table, &key).collect();
        if reg == "refusal_catalog.toml" {
            known.extend(column(&doc, "reserved", "code"));
        }
        out.push(Family {
            prefix,
            registry: reg,
            known,
        });
    }
    out
}

/// Markers in `text` under registry-check's `extract_markers` rule: a family
/// prefix at a word start, at least two digits, not followed by a letter or
/// `_`.
fn markers(text: &str, families: &[Family]) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (i, _) in text.match_indices("FA-") {
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            continue;
        }
        for f in families {
            let Some(after) = text[i..].strip_prefix(f.prefix.as_str()) else {
                continue;
            };
            let digits = after.bytes().take_while(u8::is_ascii_digit).count();
            let next = after.as_bytes().get(digits).copied();
            if digits >= 2 && !next.is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') {
                found.push(text[i..i + f.prefix.len() + digits].to_string());
            }
        }
    }
    found
}

/// The `FAIL markers` lines for `text` (shown as `file`), and how many
/// markers it holds.
fn unresolved(file: &str, text: &str, families: &[Family]) -> (usize, Vec<String>) {
    let mut n = 0;
    let mut fails = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for marker in markers(line, families) {
            n += 1;
            let family = families
                .iter()
                .filter(|f| marker.starts_with(f.prefix.as_str()))
                .max_by_key(|f| f.prefix.len())
                .expect("a marker matched a family");
            if !family.known.contains(&marker) {
                fails.push(format!(
                    "FAIL markers {file}:{} {marker} has no row in {}",
                    i + 1,
                    family.registry
                ));
            }
        }
    }
    (n, fails)
}

/// Every committed case README (`cases/<case>/README.md`).
fn readmes() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("cases");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&root).expect("cases/").flatten() {
        let path = entry.path().join("README.md");
        if let Ok(text) = std::fs::read_to_string(&path) {
            let name = entry.file_name().to_string_lossy().into_owned();
            out.push((format!("cases/{name}/README.md"), text));
        }
    }
    out.sort();
    out
}

/// The marker transcript over case data files and READMEs.
fn check_markers(data: &[(String, String)], readmes: &[(String, String)]) -> Transcript {
    let families = families();
    let mut t = Transcript::default();
    for (label, files) in [("data", data), ("readmes", readmes)] {
        let mut n = 0;
        let mut fails = Vec::new();
        for (file, text) in files {
            let (k, f) = unresolved(file, text, &families);
            n += k;
            fails.extend(f);
        }
        let verdict = if !fails.is_empty() {
            "FAIL"
        } else if files.is_empty() {
            "UNRUN"
        } else {
            "PASS"
        };
        t.line(format!(
            "CHECK markers {label} {verdict} files={} markers={n}",
            files.len()
        ));
        for f in fails {
            t.line(f);
        }
    }
    t
}

fn case_data() -> Vec<(String, String)> {
    CASES
        .iter()
        .flat_map(|c| {
            c.files
                .iter()
                .map(move |(p, text)| (format!("cases/{}/{p}", c.id), (*text).to_string()))
        })
        .collect()
}

#[test]
fn renderer_and_readme_markers_resolve() {
    let t = check_markers(&case_data(), &readmes());
    println!("{}", t.text());
    assert!(t.fails().is_empty(), "{}", t.text());
    // The committed self-test names refusal codes, so the data half examines markers.
    assert!(
        t.lines
            .iter()
            .any(|l| l.starts_with("CHECK markers data PASS") && !l.ends_with(" markers=0")),
        "{}",
        t.text()
    );
}

#[test]
fn unresolved_marker_fails_the_marker_test() {
    let mut data = case_data();
    let at = data
        .iter()
        .position(|(f, _)| f == "cases/worldcom/facts.toml")
        .unwrap();
    data[at].1.push_str("# planted: FA-REF-999\n");
    let line = data[at].1.lines().count();
    let t = check_markers(&data, &[]);
    let want = format!(
        "FAIL markers cases/worldcom/facts.toml:{line} FA-REF-999 has no row in refusal_catalog.toml"
    );
    assert!(t.lines.contains(&want), "{want}\n{}", t.text());

    let readme = vec![(
        "cases/worldcom/README.md".to_string(),
        "# WorldCom\n\nRefused with FA-REF-999.\n".to_string(),
    )];
    let t = check_markers(&case_data(), &readme);
    let want =
        "FAIL markers cases/worldcom/README.md:3 FA-REF-999 has no row in refusal_catalog.toml";
    assert!(t.lines.iter().any(|l| l == want), "{want}\n{}", t.text());
    assert!(
        t.lines
            .iter()
            .any(|l| l.starts_with("CHECK markers readmes FAIL files=1")),
        "{}",
        t.text()
    );
    // A resolved marker passes: FA-REF-010 is a catalog row.
    let ok = vec![(
        "cases/worldcom/README.md".to_string(),
        "Refused with FA-REF-010.\n".to_string(),
    )];
    let t = check_markers(&case_data(), &ok);
    assert!(t.fails().is_empty(), "{}", t.text());
}

#[test]
fn readmes_absent_report_unrun_never_pass() {
    let t = check_markers(&case_data(), &[]);
    assert!(
        t.lines
            .contains(&"CHECK markers readmes UNRUN files=0 markers=0".to_string()),
        "{}",
        t.text()
    );
}
