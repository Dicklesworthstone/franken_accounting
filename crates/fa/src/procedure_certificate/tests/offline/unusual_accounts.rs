//! Native account-pair findings must remain independently reproducible after
//! later corrections. Repaired public digests must not conceal changed pairs,
//! frequencies, populations, work, or missing findings.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture, maximum: i128, minimum: i128) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("jet.unusual_accounts", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request.parameters = request
        .parameters
        .set("max_pair_count", maximum)
        .unwrap()
        .set("min_population", minimum)
        .unwrap();
    request
}

fn population(f: &mut Fixture) -> (VId, VId, VId) {
    let (first, _) = f.post(2, "3000", "1000", 100, false);
    f.post(3, "3000", "1000", 100, false);
    f.post(4, "3000", "1000", 100, false);
    let (rare, _) = f.post(5, "3000", "6000", 100, false);
    let mut split = template(f, first, b"rare-pair-split", 6);
    split.legs = vec![
        LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(f.unit, 30)),
        LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(f.unit, 70)),
        LegPayload::simple(Side::Credit, f.id("3000"), Amount::new(f.unit, 100)),
    ];
    split.unit_totals = EntryPayload::fold_unit_totals(&split.legs).unwrap();
    post(f, split);
    let mut reciprocal = template(f, first, b"rare-pair-reciprocal", 7);
    reciprocal.legs = vec![
        LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(f.unit, 50)),
        LegPayload::simple(Side::Debit, f.id("3000"), Amount::new(f.unit, 50)),
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(f.unit, 50)),
        LegPayload::simple(Side::Credit, f.id("3000"), Amount::new(f.unit, 50)),
    ];
    reciprocal.unit_totals = EntryPayload::fold_unit_totals(&reciprocal.legs).unwrap();
    (first, rare, post(f, reciprocal))
}

#[test]
fn unusual_account_pairs_export_historical_frequencies_and_reversal_parity() {
    let mut f = Fixture::new(243);
    let (_, rare, reciprocal) = population(&mut f);
    let pair = (
        f.id("3000").0.min(f.id("6000").0),
        f.id("3000").0.max(f.id("6000").0),
    );
    let self_account = f.id("1000").0.min(f.id("3000").0);
    let historical = f.certify(&request(&f, 1, 6));
    assert_eq!(historical.report.findings.len(), 2);
    assert_eq!(
        (
            historical.report.work.entries,
            historical.report.work.legs,
            historical.report.work.comparisons
        ),
        (6, 15, 24)
    );
    let frontier = f.head();
    let undo = reverse(&mut f, rare, b"rare-pair-undo", 8);
    let reversed = f.certify(&request(&f, 1, 0));
    assert_eq!(reversed.report.findings.len(), 1);
    assert_eq!(
        reversed.report.findings[0].cites[0],
        Cite::Entry(reciprocal)
    );
    reverse(&mut f, undo, b"rare-pair-restore", 9);
    let restored = f.certify(&request(&f, 1, 6));
    assert_eq!(restored.report.findings, historical.report.findings);
    let insufficient = f.certify(&request(&f, 1, 7));
    assert!(insufficient.report.findings.is_empty());
    assert_eq!(insufficient.report.work, Work::default());
    let disabled = f.certify(&request(&f, 0, 0));
    assert!(disabled.report.findings.is_empty());
    assert_eq!(disabled.report.work, historical.report.work);
    let key = f.book.checkpoint_public_key();
    let mut artifacts = Vec::new();
    for certified in [historical, reversed, restored, insufficient, disabled] {
        assert_eq!(
            certified.certificate.format(),
            EXTENDED_PROCEDURE_CERTIFICATE_FORMAT
        );
        assert_eq!(certified.certificate.supplemental_inputs().len(), 6);
        certified.certificate.check_offline_profile().unwrap();
        assert_eq!(
            f.book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
        let produced = produce(&mut f, &certified.certificate);
        artifacts.push((certified, produced));
    }
    // Everything below receives only portable artifacts and the trust anchor.
    // Neither a source book nor native replay can supply the computed rows.
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > frontier.0);
        let procedure = verified.procedure.unwrap();
        assert_eq!(procedure.version, 2);
        assert_eq!(
            (
                procedure.live_entries,
                procedure.live_legs,
                procedure.comparisons
            ),
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            )
        );
        for finding in &procedure.findings {
            let expected_pair = if finding.entry == Some(rare.0) {
                pair
            } else {
                assert_eq!(finding.entry, Some(reciprocal.0));
                (self_account, self_account)
            };
            assert_eq!(
                finding.statistic,
                VerifiedProcedureStatistic::AccountPairOccurrences {
                    first_account: expected_pair.0,
                    second_account: expected_pair.1,
                    count: 1,
                }
            );
            assert_eq!(finding.population, procedure.live_entries);
        }
        if procedure.findings.len() == 2 {
            assert_eq!(
                procedure.parameters,
                VerifiedProcedureParameters::UnusualAccounts {
                    max_pair_count: 1,
                    min_population: 6,
                }
            );
            let command = fa_verify::cli::run(
                &[
                    "report".into(),
                    "pairs.fab".into(),
                    "--key".into(),
                    key.iter().map(|byte| format!("{byte:02x}")).collect(),
                    "--receipt".into(),
                    "pairs.receipt".into(),
                    "--json".into(),
                ],
                &|path| match path {
                    "pairs.fab" => Ok(produced.bundle.bytes.clone()),
                    "pairs.receipt" => Ok(produced.receipt.clone()),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "unexpected input",
                    )),
                },
            );
            assert_eq!(command.exit, 0, "{}", command.stdout);
            for expected in [
                "\"first_account\"",
                "\"second_account\"",
                "\"statistic\":\"pair_occurrences\"",
                "\"value\":1",
            ] {
                assert!(
                    command.stdout.contains(expected),
                    "{expected}: {}",
                    command.stdout
                );
            }
        }
    }
}

#[test]
fn unusual_account_pairs_reject_resealed_findings_parameters_and_work() {
    let mut f = Fixture::new(244);
    let (common, _, _) = population(&mut f);
    let certified = f.certify(&request(&f, 1, 6));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "count",
        "population",
        "severity",
        "pair",
        "entry",
        "narrative",
        "omitted",
        "invented",
        "comparisons",
        "legs",
        "entries",
        "threshold",
        "minimum",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "count" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::High,
            "pair" => report.findings[0].cites[1] = Cite::Account(f.id("1010")),
            "entry" => report.findings[0].cites[0] = Cite::Entry(common),
            "narrative" => report.findings[0].narrative.push_str(" changed"),
            "omitted" => {
                report.findings.pop();
            }
            "invented" => {
                let mut extra = report.findings[0].clone();
                extra.cites[0] = Cite::Entry(common);
                report.findings.push(extra);
            }
            "comparisons" => report.work.comparisons -= 1,
            "legs" => report.work.legs -= 1,
            "entries" => report.work.entries -= 1,
            "threshold" => report.parameters[0].1 = 0,
            "minimum" => report.parameters[1].1 = 7,
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        assert_eq!(
            verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                .unwrap_err()
                .predicate,
            "procedure_recomputation",
            "{variant}"
        );
    }
    for variant in [
        "legacy version",
        "cutoff",
        "handle",
        "missing parameter",
        "negative",
        "overflow",
    ] {
        let mut forged = certified.certificate.clone();
        match variant {
            "legacy version" => {
                forged.report.version = 1;
                for finding in &mut forged.report.findings {
                    finding.version = 1;
                }
            }
            "cutoff" => forged.report.coordinate.effective_through = Some(day(6)),
            "handle" => forged.report.inputs.push(("account".into(), "1000".into())),
            "missing parameter" => {
                forged.report.parameters.pop();
            }
            "negative" => forged.report.parameters[0].1 = -1,
            "overflow" => forged.report.parameters[1].1 = i128::from(u32::MAX) + 1,
            _ => unreachable!(),
        }
        assert_eq!(
            forged.check_offline_profile().unwrap_err().code,
            fa_notary::code::SCOPE_UNSUPPORTED,
            "{variant}"
        );
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        let failure = verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
            .unwrap_err();
        assert!(
            matches!(
                failure.predicate,
                "procedure_profile" | "canonical_encoding"
            ),
            "{variant}: {failure}"
        );
    }
    let mut duplicate = certified.certificate.clone();
    duplicate.report.parameters[1].0 = "max_pair_count".into();
    assert_eq!(
        duplicate.check_offline_profile().unwrap_err().code,
        fa_notary::code::SCOPE_UNSUPPORTED
    );
    assert!(
        verify_report_expected(&produced.bundle.bytes, &[key], None, None, None).is_err(),
        "untrusted output must not select its own scope"
    );
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[],
            None,
            None,
            Some(certified.certificate.digest())
        )
        .is_err(),
        "a producer cannot choose the recipient's trust anchor"
    );
}
