//! Extended native certificates must reach the independent digit computation,
//! including historical populations and public hashes repaired after tampering.

use super::*;
use fa_verify::report::VerifiedProcedureStatistic;

fn request(f: &Fixture, id: &str, parameters: &[(&str, i128)]) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(id, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    for &(name, value) in parameters {
        request.parameters = request.parameters.set(name, value).unwrap();
    }
    request
}

fn histogram(id: &str, digits: &[usize]) -> Vec<u64> {
    let pairs = id == "benford.first_two_digits";
    let mut counts = vec![0; if pairs { 90 } else { 10 }];
    for &digit in digits {
        counts[if pairs { digit - 10 } else { digit % 10 }] += 1;
    }
    counts
}

#[test]
fn additional_benford_profiles_export_historical_currency_side_and_account_populations() {
    let mut f = Fixture::new(241);
    let (first, _) = f.post(5, "3000", "6000", 1_000, false);
    f.post(6, "3000", "6000", 4_299, false);
    f.post(7, "3000", "6000", 999, false);
    f.post(8, "3000", "1000", 5_600, false);
    let mut jpy = template(&f, first, b"second-digit-yen", 9);
    let yen = f.book.context().units.lookup("JPY").unwrap();
    for leg in &mut jpy.legs {
        leg.amount = Amount::new(yen, 17);
    }
    jpy.unit_totals = EntryPayload::fold_unit_totals(&jpy.legs).unwrap();
    post(&mut f, jpy);
    let mut cases = Vec::new();
    for id in ["benford.second_digit", "benford.first_two_digits"] {
        for (name, parameters, digits, scored) in [
            (
                "expense",
                vec![("account_type", 5), ("min_population", 1)],
                vec![10, 42],
                true,
            ),
            (
                "equity credits",
                vec![("account_type", 3), ("side", 1), ("min_population", 1)],
                vec![10, 42, 56],
                true,
            ),
            (
                "empty expense credits",
                vec![("account_type", 5), ("side", 1), ("min_population", 1)],
                vec![],
                false,
            ),
            (
                "JPY",
                vec![
                    ("account_type", 5),
                    ("currency_iso4217", 392),
                    ("min_population", 1),
                ],
                vec![17],
                true,
            ),
            (
                "below minimum",
                vec![("account_type", 5)],
                vec![10, 42],
                false,
            ),
        ] {
            cases.push((
                name,
                f.certify(&request(&f, id, &parameters)),
                histogram(id, &digits),
                scored,
            ));
        }
    }
    let old_frontier = f.head();
    let undo = reverse(&mut f, first, b"second-digit-undo", 10);
    f.post(11, "3000", "6000", 987_654, false);
    for id in ["benford.second_digit", "benford.first_two_digits"] {
        cases.push((
            "corrected",
            f.certify(&request(
                &f,
                id,
                &[("account_type", 5), ("min_population", 1)],
            )),
            histogram(id, &[42, 98]),
            true,
        ));
    }
    reverse(&mut f, undo, b"second-digit-restore", 12);
    for id in ["benford.second_digit", "benford.first_two_digits"] {
        cases.push((
            "restored",
            f.certify(&request(
                &f,
                id,
                &[("account_type", 5), ("min_population", 1)],
            )),
            histogram(id, &[10, 42, 98]),
            true,
        ));
    }
    let key = f.book.checkpoint_public_key();
    for (name, certified, counts, scored) in cases {
        let id = certified.report.procedure.as_str();
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
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > old_frontier.0);
        let procedure = verified.procedure.unwrap();
        assert_eq!(
            (
                procedure.live_entries,
                procedure.live_legs,
                procedure.comparisons
            ),
            (certified.report.work.entries, certified.report.work.legs, 0)
        );
        let finding = &procedure.findings[0];
        assert_eq!(
            finding.population,
            counts.iter().sum::<u64>(),
            "{id}: {name}"
        );
        match &finding.statistic {
            VerifiedProcedureStatistic::DigitMad { counts: actual, .. } => {
                assert!(scored, "{id}: {name}");
                assert_eq!(actual, &counts, "{id}: {name}");
            }
            VerifiedProcedureStatistic::DigitPopulation { counts: actual } => {
                assert!(!scored, "{id}: {name}");
                assert_eq!(actual, &counts, "{id}: {name}");
                assert_eq!(finding.severity, 0);
            }
            other => panic!("unexpected digit statistic: {other:?}"),
        }
        if name == "expense" {
            let command = fa_verify::cli::run(
                &[
                    "report".into(),
                    "digits.fab".into(),
                    "--key".into(),
                    key.iter().map(|byte| format!("{byte:02x}")).collect(),
                    "--receipt".into(),
                    "digits.receipt".into(),
                    "--json".into(),
                ],
                &|path| match path {
                    "digits.fab" => Ok(produced.bundle.bytes.clone()),
                    "digits.receipt" => Ok(produced.receipt.clone()),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "unexpected input",
                    )),
                },
            );
            assert_eq!(command.exit, 0, "{}", command.stdout);
            let field = if id == "benford.second_digit" {
                "second_digit_counts"
            } else {
                "first_two_digits_counts"
            };
            for expected in [
                format!("\"{field}\""),
                "\"conformity_scored\":true".into(),
                "\"max_z_milli\"".into(),
                "\"scale\":9".into(),
            ] {
                assert!(
                    command.stdout.contains(&expected),
                    "{expected}: {}",
                    command.stdout
                );
            }
        }
    }
}

#[test]
fn additional_benford_profiles_reject_resealed_scores_population_and_selection() {
    let mut f = Fixture::new(242);
    let (first, _) = f.post(5, "3000", "6000", 1_000, false);
    f.post(6, "3000", "6000", 4_200, false);
    f.post(7, "3000", "1000", 9_900, false);
    for id in ["benford.second_digit", "benford.first_two_digits"] {
        let certified = f.certify(&request(
            &f,
            id,
            &[("account_type", 5), ("min_population", 1)],
        ));
        let produced = produce(&mut f, &certified.certificate);
        let key = f.book.checkpoint_public_key();
        verify(&produced, &certified.certificate, key);
        for variant in [
            "MAD",
            "scale",
            "population",
            "Z",
            "KS",
            "chi-square",
            "citation",
            "work",
            "account",
            "currency",
            "side",
            "minimum",
        ] {
            let mut forged = certified.certificate.clone();
            let report = &mut forged.report;
            match variant {
                "MAD" => report.findings[0].statistic.value += 1,
                "scale" => report.findings[0].statistic.scale = 0,
                "population" => report.findings[0].statistic.population += 1,
                "Z" => {
                    report.findings[0].narrative = report.findings[0]
                        .narrative
                        .replacen("max Z ", "max Z 1", 1)
                }
                "KS" => {
                    report.findings[0].narrative =
                        report.findings[0].narrative.replacen("KS ", "KS 1", 1)
                }
                "chi-square" => {
                    report.findings[0].narrative =
                        report.findings[0]
                            .narrative
                            .replacen("chi-square ", "chi-square 1", 1)
                }
                "citation" => report.findings[0].cites.push(Cite::Entry(first)),
                "work" => report.work.legs -= 1,
                "account" => report.parameters[0].1 = 1,
                "currency" => report.parameters[1].1 = 392,
                "side" => report.parameters[6].1 = 1,
                "minimum" => report.parameters[5].1 = 500,
                _ => unreachable!(),
            }
            reseal(&mut forged);
            let changed = replace_certificate(&produced.bundle.bytes, &forged);
            assert_eq!(
                verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                    .unwrap_err()
                    .predicate,
                "procedure_recomputation",
                "{id}: {variant}"
            );
        }
        for variant in [
            "version",
            "cutoff",
            "handle",
            "account bound",
            "currency bound",
            "side bound",
            "parameter inventory",
        ] {
            let mut forged = certified.certificate.clone();
            match variant {
                "version" => {
                    forged.report.version = 1;
                    forged.report.findings[0].version = 1;
                }
                "cutoff" => forged.report.coordinate.effective_through = Some(day(6)),
                "handle" => forged.report.inputs.push(("account".into(), "1000".into())),
                "account bound" => forged.report.parameters[0].1 = 9,
                "currency bound" => forged.report.parameters[1].1 = 0,
                "side bound" => forged.report.parameters[6].1 = 2,
                "parameter inventory" => {
                    forged.report.parameters.pop();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                forged.check_offline_profile().unwrap_err().code,
                fa_notary::code::SCOPE_UNSUPPORTED,
                "{id}: {variant}"
            );
            reseal(&mut forged);
            let changed = replace_certificate(&produced.bundle.bytes, &forged);
            let refused =
                verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                    .unwrap_err();
            assert!(
                matches!(
                    refused.predicate,
                    "procedure_profile" | "canonical_encoding"
                ),
                "{id}: {variant}: {refused}"
            );
        }
    }
}
