//! Native cutoff findings cross the independent boundary with original date
//! facts and calendar declarations, including a deliberately absent year.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("cutoff.period_boundary", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request
}

fn dated(f: &mut Fixture, source: VId, key: &[u8], effective: u8, document: DateDay) -> VId {
    let mut proposal = template(f, source, key, effective);
    proposal.document_date = Some(document);
    post(f, proposal)
}

fn refused(f: &mut Fixture, certificate: &ProcedureCertificate) -> Refusal {
    let cx = f.cx();
    f.runtime
        .block_on(f.book.checkpoint(&cx, PRINCIPAL, &cap(&["witness"])))
        .unwrap()
        .unwrap();
    let before = f.head();
    let refusal = f
        .runtime
        .block_on(f.book.produce_procedure_report_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            certificate,
        ))
        .unwrap()
        .err()
        .expect("incomplete calendar closure must refuse export");
    assert_eq!(f.head(), before);
    assert_eq!(refusal.code, fa_notary::code::SCOPE_UNSUPPORTED);
    refusal
}

#[test]
fn cutoff_exports_dated_live_population_and_ignores_reversed_missing_years() {
    let mut f = Fixture::new(198);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let hit = dated(
        &mut f,
        source,
        b"cutoff-future-document",
        10,
        DateDay::from_ymd(2026, 2, 1).unwrap(),
    );
    dated(&mut f, source, b"cutoff-same-period", 7, day(1));
    let cancelled = dated(
        &mut f,
        source,
        b"cutoff-cancelled-old-document",
        5,
        DateDay::from_ymd(2025, 12, 31).unwrap(),
    );
    reverse(&mut f, cancelled, b"cutoff-cancellation", 6);
    let certified = f.certify(&request(&f));
    assert_eq!(certified.report.findings.len(), 1);
    assert_eq!(certified.report.work.entries, 3);
    let finding = &certified.report.findings[0];
    assert_eq!(finding.statistic.name, "days_between_dates");
    assert_eq!(finding.statistic.value, 22);
    assert_eq!(finding.statistic.population, 2);
    assert_eq!(
        finding.cites,
        vec![
            Cite::Entry(hit),
            Cite::Period("FY2026-P01".into()),
            Cite::Period("FY2026-P02".into()),
        ]
    );
    certified.certificate.check_offline_profile().unwrap();
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    drop(f);
    let verified = verify(&produced, &certified.certificate, key);
    let procedure = verified.procedure.unwrap();
    assert_eq!(
        procedure.parameters,
        VerifiedProcedureParameters::PeriodBoundary
    );
    assert_eq!(
        (
            procedure.live_entries,
            procedure.live_legs,
            procedure.comparisons
        ),
        (3, 0, 0)
    );
    assert_eq!(
        procedure.findings[0].statistic,
        VerifiedProcedureStatistic::DaysBetweenPeriods {
            effective_period: "FY2026-P01".into(),
            document_period: "FY2026-P02".into(),
            days: 22,
        }
    );
    assert_eq!(procedure.findings[0].population, 2);
    let json = fa_verify::cli::run(
        &[
            "report".into(),
            "cutoff.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--json".into(),
        ],
        &|path| match path {
            "cutoff.fab" => Ok(produced.bundle.bytes.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(json.exit, 0, "{}", json.stdout);
    for expected in [
        "\"statistic\":\"days_between_dates\"",
        "\"effective_period\":\"FY2026-P01\"",
        "\"document_period\":\"FY2026-P02\"",
    ] {
        assert!(
            json.stdout.contains(expected),
            "{expected}: {}",
            json.stdout
        );
    }
}

#[test]
fn cutoff_requires_adjacent_year_at_the_original_frontier_then_accepts_a_fresh_certificate() {
    let mut f = Fixture::new(199);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    dated(
        &mut f,
        source,
        b"cutoff-previous-year",
        1,
        DateDay::from_ymd(2025, 12, 31).unwrap(),
    );
    let historical = f.certify(&request(&f));
    assert_eq!(historical.report.findings[0].cites.len(), 2);
    let refusal = refused(&mut f, &historical.certificate);
    assert!(refusal.message.contains("FY2025-P12"));
    assert!(refusal.fix.contains("fa period create --fiscal-year 2025"));
    assert!(
        refusal
            .fix
            .contains("fresh cutoff.period_boundary certificate")
    );
    let cx = f.cx();
    f.runtime
        .block_on(
            f.book
                .create_periods(&cx, 2025, PRINCIPAL, &cap(&["schema_change"])),
        )
        .unwrap()
        .unwrap();
    // A longer checkpoint is not authority to change the certificate's old
    // calendar facts or add a citation absent at its original frontier.
    let still_refused = refused(&mut f, &historical.certificate);
    assert!(
        still_refused
            .message
            .contains(&historical.certificate.known_at().0.to_string())
    );
    let fresh = f.certify(&request(&f));
    assert_eq!(fresh.report.findings[0].cites.len(), 3);
    let produced = produce(&mut f, &fresh.certificate);
    let key = f.book.checkpoint_public_key();
    drop(f);
    let result = verify(&produced, &fresh.certificate, key);
    assert_eq!(
        result.procedure.unwrap().findings[0].statistic,
        VerifiedProcedureStatistic::DaysBetweenPeriods {
            effective_period: "FY2026-P01".into(),
            document_period: "FY2025-P12".into(),
            days: 1,
        }
    );
}

#[test]
fn cutoff_rejects_resealed_period_citations_statistics_population_work_and_profile_changes() {
    let mut f = Fixture::new(200);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    dated(
        &mut f,
        source,
        b"cutoff-tamper-source",
        10,
        DateDay::from_ymd(2026, 2, 1).unwrap(),
    );
    let certified = f.certify(&request(&f));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    drop(f);
    verify(&produced, &certified.certificate, key);
    for variant in [
        "distance",
        "population",
        "severity",
        "effective period",
        "document period",
        "missing document citation",
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
            "distance" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::Info,
            "effective period" => report.findings[0].cites[1] = Cite::Period("FY2026-P03".into()),
            "document period" => report.findings[0].cites[2] = Cite::Period("FY2026-P03".into()),
            "missing document citation" => {
                report.findings[0].cites.pop();
            }
            "narrative" => report.findings[0].narrative.push_str(" changed"),
            "omitted" => {
                report.findings.clear();
            }
            "work" => report.work.entries += 1,
            "cutoff" => report.coordinate.effective_through = Some(day(31)),
            "parameter" => report.parameters.push(("window_days".into(), 1)),
            "version" => {
                report.version = 2;
                for finding in &mut report.findings {
                    finding.version = 2;
                }
            }
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        assert!(
            verify_report_expected(&bundle, &[key], None, None, Some(forged.digest())).is_err(),
            "resealed {variant}"
        );
    }
}
