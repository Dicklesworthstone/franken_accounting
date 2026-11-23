//! Weekend audit observations replay from an authenticated portable journal,
//! without trusting the producer's dates, narrative, selected rows or totals.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture) -> ProcedureRequest {
    let mut request = ProcedureRequest::new("jet.weekend", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request
}

fn dated(f: &mut Fixture, source: VId, key: &[u8], effective: u8, document: DateDay) -> VId {
    let mut proposal = template(f, source, key, effective);
    proposal.document_date = Some(document);
    post(f, proposal)
}

#[test]
fn weekend_exports_original_document_dates_and_reversal_liveness_without_the_source_book() {
    let mut f = Fixture::new(186);
    let (source, _) = f.post(1, "3000", "1000", 100, false); // Thursday.
    let (saturday, _) = f.post(3, "3000", "1000", 100, false);
    let (sunday, _) = f.post(4, "3000", "1000", 100, false);
    f.post(5, "3000", "1000", 100, false);
    dated(&mut f, source, b"weekend-overridden-by-document", 3, day(5));
    let document_sunday = dated(&mut f, source, b"weekend-document-on-sunday", 5, day(4));
    // The weekday of a civil date needs no fiscal-period declaration for its
    // year. This is a Sunday before the Unix epoch, in an undeclared year.
    let old_document = dated(
        &mut f,
        source,
        b"weekend-before-epoch-document",
        7,
        DateDay::from_ymd(1969, 12, 28).unwrap(),
    );
    let (cancelled, _) = f.post(10, "3000", "1000", 100, false);
    reverse(&mut f, cancelled, b"weekend-cancelled", 12);
    let historical = f.certify(&request(&f));
    assert_eq!(historical.report.findings.len(), 4);
    assert_eq!(historical.report.work.entries, 7);
    let found: BTreeSet<_> = historical
        .report
        .findings
        .iter()
        .map(|finding| {
            assert_eq!(finding.severity, Severity::Low);
            assert_eq!(finding.statistic.name, "iso_weekday");
            assert_eq!(finding.statistic.population, 7);
            let [Cite::Entry(entry)] = finding.cites.as_slice() else {
                panic!("weekend cites exactly one entry");
            };
            (*entry, finding.statistic.value)
        })
        .collect();
    assert_eq!(
        found,
        BTreeSet::from([
            (saturday, 6),
            (sunday, 7),
            (document_sunday, 7),
            (old_document, 7),
        ])
    );
    let saved_frontier = historical.certificate.known_at();
    let undo = reverse(&mut f, saturday, b"weekend-later-undo", 13);
    let corrected = f.certify(&request(&f));
    assert_eq!(corrected.report.findings.len(), 3);
    assert_eq!(corrected.report.work.entries, 6);
    reverse(&mut f, undo, b"weekend-undo-reversal", 14);
    let restored = f.certify(&request(&f));
    assert_eq!(restored.report.findings, historical.report.findings);
    let key = f.book.checkpoint_public_key();
    let mut artifacts = Vec::new();
    for certified in [historical, corrected, restored] {
        certified.certificate.check_offline_profile().unwrap();
        let produced = produce(&mut f, &certified.certificate);
        artifacts.push((certified, produced));
    }
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > saved_frontier.0);
        let procedure = verified.procedure.unwrap();
        assert_eq!(procedure.parameters, VerifiedProcedureParameters::Weekend);
        assert_eq!(procedure.findings.len(), certified.report.findings.len());
        assert_eq!(procedure.live_entries, certified.report.work.entries);
        assert_eq!((procedure.live_legs, procedure.comparisons), (0, 0));
        for finding in &procedure.findings {
            assert!(matches!(
                finding.statistic,
                VerifiedProcedureStatistic::IsoWeekday { iso: 6 | 7 }
            ));
        }
        let cli = fa_verify::cli::run(
            &[
                "report".into(),
                "weekend.fab".into(),
                "--key".into(),
                key.iter().map(|byte| format!("{byte:02x}")).collect(),
                "--json".into(),
            ],
            &|path| match path {
                "weekend.fab" => Ok(produced.bundle.bytes.clone()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "unexpected input",
                )),
            },
        );
        assert_eq!(cli.exit, 0, "{}", cli.stdout);
        assert!(
            cli.stdout.contains("\"statistic\":\"iso_weekday\""),
            "{}",
            cli.stdout
        );
    }
}

#[test]
fn weekend_rejects_resealed_false_weekdays_citations_population_work_and_unsupported_profiles() {
    let mut f = Fixture::new(187);
    let (weekday, _) = f.post(1, "3000", "1000", 100, false);
    f.post(3, "3000", "1000", 100, false);
    let certified = f.certify(&request(&f));
    assert_eq!(certified.report.findings.len(), 1);
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    drop(f);
    verify(&produced, &certified.certificate, key);
    for variant in [
        "weekday",
        "citation",
        "population",
        "severity",
        "narrative",
        "omitted",
        "work",
        "cutoff",
        "parameter",
        "version",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "weekday" => report.findings[0].statistic.value = 7,
            "citation" => report.findings[0].cites[0] = Cite::Entry(weekday),
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::High,
            "narrative" => report.findings[0].narrative.push_str(" changed"),
            "omitted" => report.findings.clear(),
            "work" => report.work.entries += 1,
            "cutoff" => report.coordinate.effective_through = Some(day(31)),
            "parameter" => report.parameters.push(("window_days".into(), 7)),
            "version" => {
                report.version = 2;
                report.findings[0].version = 2;
            }
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        let expected = if matches!(variant, "cutoff" | "parameter" | "version") {
            "procedure_profile"
        } else {
            "procedure_recomputation"
        };
        assert_eq!(
            verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
                .unwrap_err()
                .predicate,
            expected,
            "resealed {variant}"
        );
    }
}

#[test]
fn weekend_empty_results_are_still_bound_to_the_complete_saved_population() {
    let mut f = Fixture::new(188);
    f.post(1, "3000", "1000", 100, false);
    let certified = f.certify(&request(&f));
    assert!(certified.report.findings.is_empty());
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    drop(f);
    let verified = verify(&produced, &certified.certificate, key);
    let procedure = verified.procedure.unwrap();
    assert!(procedure.findings.is_empty());
    assert_eq!(procedure.live_entries, 1);
    let mut forged = certified.certificate.clone();
    forged.report.work.entries = 0;
    reseal(&mut forged);
    let bundle = replace_certificate(&produced.bundle.bytes, &forged);
    assert_eq!(
        verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );
}
