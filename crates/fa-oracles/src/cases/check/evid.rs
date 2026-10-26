//! K-EVID (§2.7, §3.2, §3.6; bead fa-yugf.9, A3c): provenance documents
//! never stand in for an entry's evidence, and each book variant carries
//! only the claims its evidence can bear.
//!
//! A `[[document]]`'s `stub_of` sorts it: a source or fact id is a citation
//! stub (provenance), `placeholder:<fact>` a reconstruction placeholder,
//! `filler:<variant>` the filler document, `rows:<fact>` an import's input
//! data, `legacy_tb` a migration run's derived legacy trial balances. The
//! rules:
//!
//! - On `native` and `migration` stems a documented entry (its fact sourced
//!   or interpreted) and a filler intent never cite a citation stub, nor a
//!   document an `engagement_file` step files; filler cites only a
//!   `filler:` document; a case Δ (`derived:` fact, Restatement, Revision or
//!   PriorPeriodAdjustment) cites the restating filing's stub, the `stub_of`
//!   of a `[[case]]`'s disclosure document.
//! - On `statement` and `ledger` stems every posting cites the citation stub
//!   of the filing that publishes it (a Δ the restating filing's); each
//!   `[[ledger_map]]` row has a stub of its source fact's source.
//! - A `rows:` document is never evidence and never filed; a `legacy_tb`
//!   document is cited only by a Migration intent and never filed; a
//!   placeholder is never filed.
//! - A `statement` stem carries no P, N or CF and no D unless
//!   `about = "reconstruction"`; a `ledger` stem no P, CF, `no_refusal` N or
//!   evidence-reading D/N (A4's `reads_evidence`). A D or N there whose
//!   procedure has no tier row is refused, never exempted. Rows with
//!   `about = "reconstruction"` (the runner's SELF rows included) are exempt
//!   from the variant bars.

use super::super::book::{BookVariant, StepKind, VariantKind};
use super::super::expect::{Expectation, ExpectationType};
use super::super::fact::Provenance;
use super::super::{Case, EXPECTATIONS_FILE};
use super::{CheckReport, Context};

/// What a `[[document]]` is, by its `stub_of`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DocClass {
    /// A citation stub of this source.
    Stub(String),
    Placeholder,
    Filler,
    Rows,
    LegacyTb,
    Unknown,
}

fn doc_class(case: &Case, stub_of: &str) -> DocClass {
    if stub_of.starts_with("placeholder:") {
        DocClass::Placeholder
    } else if stub_of.starts_with("filler:") {
        DocClass::Filler
    } else if stub_of.starts_with("rows:") {
        DocClass::Rows
    } else if stub_of == "legacy_tb" {
        DocClass::LegacyTb
    } else if case.sources.iter().any(|s| s.id == stub_of) {
        DocClass::Stub(stub_of.to_string())
    } else if let Some(s) = case
        .facts
        .iter()
        .find(|f| f.id == stub_of)
        .and_then(|f| f.sourced())
    {
        DocClass::Stub(s.source.clone())
    } else {
        DocClass::Unknown
    }
}

const DELTA_CLASSES: [&str; 3] = ["Restatement", "Revision", "PriorPeriodAdjustment"];

/// The inputs K-EVID examines in one book variant.
fn inputs(case: &Case, book: &BookVariant) -> usize {
    let filings = book
        .steps
        .iter()
        .filter(|s| s.step_kind() == Some(StepKind::EngagementFile))
        .filter(|s| !s.reference.starts_with("finding:"))
        .count();
    let rows = expectations_of(case, &book.stem).len();
    book.intents.len() + filings + book.ledger_maps.len() + rows
}

fn expectations_of<'c>(case: &'c Case, stem: &str) -> Vec<&'c Expectation> {
    case.expectations
        .iter()
        .flat_map(|s| s.expectations.iter())
        .filter(|e| e.fields.str("book_variant") == Some(stem))
        .collect()
}

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let total = case.books.values().map(|b| inputs(case, b)).sum();
    let mut r = CheckReport::new("K-EVID", total);
    for book in case.books.values() {
        book_evidence(cx, book, &mut r);
        variant_bars(cx, book, &mut r);
    }
    r.finish()
}

fn book_evidence(cx: &Context<'_>, book: &BookVariant, r: &mut CheckReport) {
    let case = cx.case;
    let file = format!("books/{}.toml", book.stem);
    let class_of = |doc: &str| {
        book.documents
            .iter()
            .find(|d| d.id == doc)
            .map(|d| doc_class(case, &d.stub_of))
    };
    // The stubs of the restating filings, from each [[case]]'s disclosure.
    let restating: Vec<String> = book
        .cases
        .iter()
        .filter_map(|c| book.documents.iter().find(|d| d.id == c.disclosure))
        .map(|d| d.stub_of.clone())
        .collect();
    let mut filed: Vec<&str> = Vec::new();
    for s in book
        .steps
        .iter()
        .filter(|s| s.step_kind() == Some(StepKind::EngagementFile))
        .filter(|s| !s.reference.starts_with("finding:"))
    {
        let doc = s.reference.as_str();
        filed.push(doc);
        r.examined(format!("{}:filed:{doc}", book.stem));
        let never = match class_of(doc) {
            Some(DocClass::Placeholder) => Some("a placeholder"),
            Some(DocClass::Rows) => Some("a rows: document"),
            Some(DocClass::LegacyTb) => Some("a legacy_tb document"),
            _ => None,
        };
        if let Some(what) = never {
            r.fail(
                &file,
                s.line,
                &format!("step {}", s.seq),
                format!("{doc} is {what}, never filed in the provenance engagement (§2.7)"),
            );
        }
    }
    for it in &book.intents {
        r.examined(format!("{}:{}", book.stem, it.id));
        let evidence = it.evidence.as_deref().unwrap_or_default();
        let manual = evidence.starts_with("manual_assertion:");
        let class = if manual { None } else { class_of(evidence) };
        let mut fail = |reason: String| r.fail(&file, it.line, &it.id, reason);
        match &class {
            Some(DocClass::Rows) => fail(format!(
                "cites {evidence}, a rows: document: an import's input data is never evidence"
            )),
            Some(DocClass::LegacyTb) if it.class != "Migration" => fail(format!(
                "cites {evidence}, a legacy_tb document, which only a Migration chunk cites (§6.6)"
            )),
            _ => {}
        }
        let fact = case.facts.iter().find(|f| f.id == it.fact);
        // A case Δ: A1b's restates/revises target, or a derived fact in a
        // correction class.
        let delta = it.is_delta()
            || (it.fact.starts_with("derived:") && DELTA_CLASSES.contains(&it.class.as_str()));
        if delta {
            let stub_of = book
                .documents
                .iter()
                .find(|d| d.id == evidence)
                .map(|d| d.stub_of.as_str());
            if !stub_of.is_some_and(|s| restating.iter().any(|x| x == s)) {
                fail(format!(
                    "a case Δ cites the restating filing's stub ({}), not {evidence}",
                    if restating.is_empty() {
                        "no [[case]] disclosure document".to_string()
                    } else {
                        restating.join(", ")
                    }
                ));
            }
            continue;
        }
        match book.kind {
            VariantKind::Native | VariantKind::Migration => {
                let documented = fact.is_some_and(|f| {
                    matches!(
                        f.provenance,
                        Provenance::Sourced(_) | Provenance::Interpretation(_)
                    )
                });
                let filler = it.fact == "synthetic";
                if documented || filler {
                    if let Some(DocClass::Stub(source)) = &class {
                        fail(format!(
                            "cites {evidence}, a citation stub of {source}: provenance is never an entry's evidence (§2.7)"
                        ));
                    }
                    if !manual && filed.contains(&evidence) {
                        fail(format!(
                            "cites {evidence}, a document filed in the provenance engagement"
                        ));
                    }
                }
                if filler && class != Some(DocClass::Filler) {
                    fail(format!(
                        "a filler intent cites only its variant's filler: document, not {evidence}"
                    ));
                }
            }
            VariantKind::Statement | VariantKind::Ledger => {
                let want = fact.and_then(|f| f.sourced()).map(|s| s.source.clone());
                match (&class, &want) {
                    (Some(DocClass::Stub(got)), Some(want)) if got != want => fail(format!(
                        "a {} posting cites the stub of the filing that publishes it ({want}), not {evidence} ({got})",
                        book.kind.as_str()
                    )),
                    (Some(DocClass::Stub(_)), _) => {}
                    _ => fail(format!(
                        "a {} posting cites a citation stub, not {}",
                        book.kind.as_str(),
                        if evidence.is_empty() {
                            "nothing"
                        } else {
                            evidence
                        }
                    )),
                }
            }
        }
    }
    for m in &book.ledger_maps {
        r.examined(format!("{}:ledger_map:{}", book.stem, m.account));
        let want = case
            .facts
            .iter()
            .find(|f| f.id == m.source)
            .and_then(|f| f.sourced())
            .map(|s| s.source.clone());
        let has_stub = want.as_ref().is_some_and(|w| {
            book.documents
                .iter()
                .any(|d| doc_class(case, &d.stub_of) == DocClass::Stub(w.clone()))
        });
        if !has_stub {
            r.fail(
                &file,
                m.line,
                &m.account,
                format!(
                    "a [[ledger_map]] row's rendered intents cite the stub of its source fact's source ({}), and the variant has none",
                    want.as_deref().unwrap_or("no sourced fact")
                ),
            );
        }
    }
}

fn variant_bars(cx: &Context<'_>, book: &BookVariant, r: &mut CheckReport) {
    let case = cx.case;
    for e in expectations_of(case, &book.stem) {
        let exempt = e.fields.str("about") == Some("reconstruction");
        r.examined(format!(
            "{}:{}{}",
            book.stem,
            e.id,
            if exempt { " (reconstruction)" } else { "" }
        ));
        if exempt {
            continue;
        }
        let mut fail = |reason: String| r.fail(EXPECTATIONS_FILE, e.fields.line, &e.id, reason);
        let kind = e.kind;
        let stem = book.stem.as_str();
        match book.kind {
            VariantKind::Statement => match kind {
                ExpectationType::P | ExpectationType::N | ExpectationType::Cf => fail(format!(
                    "a statement variant ({stem}) carries no P, N or CF (§3.2)"
                )),
                ExpectationType::D => fail(format!(
                    "a D on a statement variant ({stem}) is only about = \"reconstruction\" (§3.2)"
                )),
                _ => {}
            },
            VariantKind::Ledger => {
                match kind {
                    ExpectationType::P | ExpectationType::Cf => {
                        fail(format!(
                            "a ledger variant ({stem}) carries no P or CF (§3.6)"
                        ));
                    }
                    ExpectationType::N if e.fields.str("kind") == Some("no_refusal") => {
                        fail(format!(
                            "a ledger variant ({stem}) carries no no_refusal N (§3.6)"
                        ));
                    }
                    _ => {}
                }
                if matches!(kind, ExpectationType::D | ExpectationType::N)
                    && let Some(procedure) = e.fields.str("procedure")
                {
                    match cx.tiers.as_ref().ok().and_then(|t| t.get(procedure)) {
                        None => fail(format!(
                            "{procedure} has no tier row, so whether it reads evidence is unknown: refused on a ledger variant ({stem}), never exempted"
                        )),
                        Some(row) if row.reads_evidence => fail(format!(
                            "{procedure} reads evidence (its tier row), so no D or N on a ledger variant ({stem}) rests on it (§3.6)"
                        )),
                        Some(_) => {}
                    }
                }
            }
            VariantKind::Native | VariantKind::Migration => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::book::{DocumentDef, LedgerMapDef};
    use super::super::super::expect::Field;
    use super::super::super::tests::pilot_planted;
    use super::super::{Verdict, run_load_checks};
    use super::*;

    fn pilot() -> Case {
        pilot_planted(&[])
    }

    fn native(case: &mut Case) -> &mut BookVariant {
        case.books.get_mut("native").expect("the native book")
    }

    fn add_doc(case: &mut Case, id: &str, stub_of: &str) {
        native(case).documents.push(DocumentDef {
            id: id.into(),
            stub_of: stub_of.into(),
            grade: "AgentUpload".into(),
            reviewed_by: None,
            line: None,
        });
    }

    fn set_evidence(case: &mut Case, intent: &str, doc: &str) {
        native(case)
            .intents
            .iter_mut()
            .find(|i| i.id == intent)
            .expect("an intent")
            .evidence = Some(doc.into());
    }

    /// An `engagement_file` step filing `doc`, appended to the native book.
    fn file_step(case: &mut Case, doc: &str) -> String {
        let book = native(case);
        let mut s = book
            .steps
            .iter()
            .find(|s| s.step_kind() == Some(StepKind::EngagementFile))
            .expect("the pilot's engagement_file step")
            .clone();
        s.seq = 999;
        s.reference = doc.into();
        s.line = None;
        book.steps.push(s);
        "step 999".into()
    }

    /// An empty variant `stem` of `kind` beside the native book.
    fn empty_variant(case: &mut Case, stem: &str, kind: VariantKind) {
        let mut b = case.books["native"].clone();
        b.stem = stem.into();
        b.kind = kind;
        b.intents.clear();
        b.steps.clear();
        b.legs.clear();
        b.cases.clear();
        b.ledger_maps.clear();
        case.books.insert(stem.into(), b);
    }

    /// A copy of expectation `from` as `id` on `variant`, with `fields` set.
    fn add_exp(
        case: &mut Case,
        from: &str,
        id: &str,
        kind: Option<ExpectationType>,
        variant: &str,
        fields: &[(&str, &str)],
    ) {
        let set = case.expectations.as_mut().expect("expectations");
        let mut e = set.get(from).expect("a template").clone();
        e.id = id.into();
        if let Some(k) = kind {
            e.kind = k;
        }
        e.fields
            .map
            .insert("book_variant".into(), Field::Str(variant.into()));
        for (k, v) in fields {
            e.fields.map.insert((*k).into(), Field::Str((*v).into()));
        }
        set.expectations.push(e);
    }

    fn intent_line(case: &Case, id: &str) -> String {
        case.books["native"]
            .intents
            .iter()
            .find(|i| i.id == id)
            .and_then(|i| i.line)
            .map_or_else(|| "-".into(), |l| l.to_string())
    }

    fn exp_line(case: &Case, id: &str) -> String {
        case.expectations
            .as_ref()
            .and_then(|s| s.get(id))
            .and_then(|e| e.fields.line)
            .map_or_else(|| "-".into(), |l| l.to_string())
    }

    #[track_caller]
    fn fails_with(case: &Case, want: &str) {
        let r = check(&Context::new(case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }

    #[test]
    fn pilot_passes_k_assert_errrate_names_evid_reason() {
        let case = pilot();
        let reports = run_load_checks(&case);
        let text: String = reports.iter().map(|r| r.render(None)).collect();
        println!("{text}");
        for (id, examined) in [
            ("K-ASSERT", "examined=5/5"),
            ("K-ERRRATE", "examined=2/2"),
            ("K-NAMES", "examined=34/34"),
            ("K-EVID", "examined=12/12"),
            ("K-REASON", "examined=3/3"),
        ] {
            assert!(
                text.contains(&format!("CHECK {id} PASS {examined}\n")),
                "{id}:\n{text}"
            );
        }
        assert!(
            text.contains(
                "W-D-01 expense.capitalization@2 uncalibrated: its thresholds are pinned, not measured"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "W-D-03 jet.round_amounts@1 corpus: measured on fa-gen's labelled synthetic corpora"
            ),
            "{text}"
        );
        assert!(
            text.contains("SRC-WC-001 \"the committee found\""),
            "{text}"
        );
    }

    #[test]
    fn native_intent_citing_a_provenance_stub_fails_k_evid() {
        let mut case = pilot();
        add_doc(&mut case, "DOC-001", "SRC-WC-001");
        set_evidence(&mut case, "F4", "DOC-001");
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:{} F4: cites DOC-001, a citation stub of SRC-WC-001: provenance is never an entry's evidence (§2.7)",
                intent_line(&case, "F4")
            ),
        );
    }

    #[test]
    fn rows_document_cited_as_evidence_fails_k_evid() {
        let mut case = pilot();
        add_doc(&mut case, "DOC-ROWS", "rows:F2");
        set_evidence(&mut case, "F4", "DOC-ROWS");
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:{} F4: cites DOC-ROWS, a rows: document: an import's input data is never evidence",
                intent_line(&case, "F4")
            ),
        );
    }

    #[test]
    fn rows_document_filed_in_the_engagement_fails_k_evid() {
        let mut case = pilot();
        add_doc(&mut case, "DOC-ROWS", "rows:F2");
        let row = file_step(&mut case, "DOC-ROWS");
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:- {row}: DOC-ROWS is a rows: document, never filed in the provenance engagement (§2.7)"
            ),
        );
    }

    #[test]
    fn legacy_tb_document_cited_by_a_non_migration_intent_fails_k_evid() {
        let mut case = pilot();
        add_doc(&mut case, "DOC-LTB", "legacy_tb");
        set_evidence(&mut case, "F4", "DOC-LTB");
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:{} F4: cites DOC-LTB, a legacy_tb document, which only a Migration chunk cites (§6.6)",
                intent_line(&case, "F4")
            ),
        );
    }

    #[test]
    fn legacy_tb_document_filed_in_the_engagement_fails_k_evid() {
        let mut case = pilot();
        add_doc(&mut case, "DOC-LTB", "legacy_tb");
        let row = file_step(&mut case, "DOC-LTB");
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:- {row}: DOC-LTB is a legacy_tb document, never filed in the provenance engagement (§2.7)"
            ),
        );
    }

    #[test]
    fn placeholder_filed_in_the_engagement_fails_k_evid() {
        let mut case = pilot();
        let row = file_step(&mut case, "DOC-PH-F2");
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:- {row}: DOC-PH-F2 is a placeholder, never filed in the provenance engagement (§2.7)"
            ),
        );
    }

    #[test]
    fn filler_intent_citing_a_placeholder_fails_k_evid() {
        let mut case = pilot();
        native(&mut case)
            .intents
            .iter_mut()
            .find(|i| i.id == "F4")
            .expect("F4")
            .fact = "synthetic".into();
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:{} F4: a filler intent cites only its variant's filler: document, not DOC-PH-F4",
                intent_line(&case, "F4")
            ),
        );
    }

    #[test]
    fn case_delta_citing_a_stub_other_than_the_restating_filing_fails_k_evid() {
        let mut case = pilot();
        add_doc(&mut case, "DOC-001", "SRC-WC-001");
        set_evidence(&mut case, "delta-F4", "DOC-001");
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID books/native.toml:{} delta-F4: a case Δ cites the restating filing's stub (SRC-WC-406), not DOC-001",
                intent_line(&case, "delta-F4")
            ),
        );
    }

    #[test]
    fn no_refusal_n_on_a_ledger_variant_fails_k_evid() {
        let mut case = pilot();
        empty_variant(&mut case, "ledger", VariantKind::Ledger);
        add_exp(
            &mut case,
            "W-N-01",
            "M-N-90",
            None,
            "ledger",
            &[("kind", "no_refusal")],
        );
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID expectations.toml:{} M-N-90: a ledger variant (ledger) carries no no_refusal N (§3.6)",
                exp_line(&case, "M-N-90")
            ),
        );
    }

    #[test]
    fn d_or_n_on_ledger_without_a_tier_row_fails_k_evid() {
        let mut case = pilot();
        empty_variant(&mut case, "ledger", VariantKind::Ledger);
        add_exp(
            &mut case,
            "W-D-01",
            "M-D-90",
            None,
            "ledger",
            &[("procedure", "trace.libr")],
        );
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID expectations.toml:{} M-D-90: trace.libr has no tier row, so whether it reads evidence is unknown: refused on a ledger variant (ledger), never exempted",
                exp_line(&case, "M-D-90")
            ),
        );
    }

    #[test]
    fn evidence_reading_d_on_a_statement_variant_fails_k_evid() {
        let mut case = pilot();
        empty_variant(&mut case, "statement-bridge", VariantKind::Statement);
        add_exp(
            &mut case,
            "W-D-01",
            "W-D-90",
            None,
            "statement-bridge",
            &[("procedure", "jet.self_sourced_evidence")],
        );
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID expectations.toml:{} W-D-90: a D on a statement variant (statement-bridge) is only about = \"reconstruction\" (§3.2)",
                exp_line(&case, "W-D-90")
            ),
        );
    }

    #[test]
    fn d_on_a_statement_variant_without_about_reconstruction_fails_k_evid() {
        let mut case = pilot();
        empty_variant(&mut case, "statement-bridge", VariantKind::Statement);
        add_exp(&mut case, "W-D-03", "W-D-91", None, "statement-bridge", &[]);
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID expectations.toml:{} W-D-91: a D on a statement variant (statement-bridge) is only about = \"reconstruction\" (§3.2)",
                exp_line(&case, "W-D-91")
            ),
        );
        // The same D about the reconstruction is exempt.
        let mut exempt = pilot();
        empty_variant(&mut exempt, "statement-bridge", VariantKind::Statement);
        add_exp(
            &mut exempt,
            "W-D-03",
            "W-D-91",
            None,
            "statement-bridge",
            &[("about", "reconstruction")],
        );
        let r = check(&Context::new(&exempt));
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
    }

    #[test]
    fn p_row_on_a_statement_suffix_stem_fails_k_evid() {
        let mut case = pilot();
        empty_variant(&mut case, "statement-bridge", VariantKind::Statement);
        add_exp(&mut case, "W-P-02", "W-P-90", None, "statement-bridge", &[]);
        fails_with(
            &case,
            &format!(
                "FAIL K-EVID expectations.toml:{} W-P-90: a statement variant (statement-bridge) carries no P, N or CF (§3.2)",
                exp_line(&case, "W-P-90")
            ),
        );
    }

    #[test]
    fn ledger_row_citing_another_stub_fails_k_evid() {
        let mut case = pilot();
        empty_variant(&mut case, "ledger", VariantKind::Ledger);
        // The ledger's only stub is SRC-WC-406's; the map reads F2 of SRC-WC-001.
        case.books
            .get_mut("ledger")
            .expect("ledger")
            .ledger_maps
            .push(LedgerMapDef {
                source: "F2".into(),
                account: "1ZR176".into(),
                book_account: "2000".into(),
                party: "P1".into(),
                cash_account: "1000".into(),
                transfer_account: "2900".into(),
                amount_columns: vec!["CASH DEPOSITS".into()],
                line: None,
            });
        fails_with(
            &case,
            "FAIL K-EVID books/ledger.toml:- 1ZR176: a [[ledger_map]] row's rendered intents cite the stub of its source fact's source (SRC-WC-001), and the variant has none",
        );
    }
}
