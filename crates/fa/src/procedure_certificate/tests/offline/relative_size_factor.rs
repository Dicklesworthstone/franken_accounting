//! Real native RSF artifacts must be reconstructible from their authenticated
//! legs, including party grouping, units, deterministic ties and corrections.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture, threshold: i128, minimum: i128) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("numbers.relative_size_factor", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request.parameters = request
        .parameters
        .set("min_rsf_bps", threshold)
        .unwrap()
        .set("min_subset_size", minimum)
        .unwrap();
    request
}

fn party(f: &mut Fixture, code: &str) -> VId {
    let cx = f.cx();
    let spec = fa_model::PartySpec {
        code: code.into(),
        kind: fa_model::PartyKind::Vendor,
        name: f.book.seal_text(&cx, code).unwrap(),
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    f.runtime
        .block_on(f.book.create_party(
            &cx,
            &spec,
            PRINCIPAL,
            day(1),
            code.as_bytes(),
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    fa_model::party_value_vid(f.book.context().book_id, code)
}

fn population(f: &mut Fixture) -> (VId, VId) {
    let a = party(f, "RSF-A");
    let b = party(f, "RSF-B");
    let yen = f.book.context().units.lookup("JPY").unwrap();
    let (source, _) = f.post(2, "3000", "1020", 1, false);
    let mut largest_a = None;
    for (group, dimension, unit, magnitudes) in [
        ("account", None, f.unit, [900, 90, 80]),
        ("party-a", Some(a), f.unit, [1_000, 100, 90]),
        ("party-b", Some(b), f.unit, [500, 100, 90]),
        ("yen-a", Some(a), yen, [2_000, 1_000, 900]),
    ] {
        for (index, amount) in magnitudes.into_iter().enumerate() {
            let mut proposal = template(f, source, format!("rsf:{group}:{index}").as_bytes(), 3);
            // The same party spans accounts. The same account holds both
            // party-attributed and unattributed amounts. Neither may pool.
            let account = if group == "party-a" && index == 1 {
                "1010"
            } else {
                "6000"
            };
            let mut debit =
                LegPayload::simple(Side::Debit, f.id(account), Amount::new(unit, amount));
            if let Some(value) = dimension {
                debit.dimension_set.push((fa_model::PARTY_DIMENSION, value));
            }
            proposal.legs = vec![
                debit,
                LegPayload::simple(Side::Credit, f.id("3000"), Amount::new(unit, amount)),
            ];
            proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
            let vid = post(f, proposal);
            if group == "party-a" && index == 0 {
                largest_a = Some(vid);
            }
        }
    }
    (source, largest_a.unwrap())
}

#[test]
fn relative_size_factor_exports_party_unit_and_historical_populations() {
    let mut f = Fixture::new(245);
    let (_, largest) = population(&mut f);
    let historical = f.certify(&request(&f, 50_000, 3));
    assert_eq!(historical.report.findings.len(), 3);
    assert_eq!(
        historical
            .report
            .findings
            .iter()
            .map(|finding| finding.statistic.value)
            .collect::<Vec<_>>(),
        vec![100_000, 100_000, 50_000]
    );
    assert!(
        historical
            .report
            .findings
            .iter()
            .all(|finding| finding.statistic.population == 13)
    );
    let frontier = f.head();
    let undo = reverse(&mut f, largest, b"rsf-undo", 7);
    let corrected = f.certify(&request(&f, 50_000, 3));
    assert_eq!(corrected.report.findings.len(), 2);
    reverse(&mut f, undo, b"rsf-restore", 8);
    let restored = f.certify(&request(&f, 50_000, 3));
    assert_eq!(restored.report.findings, historical.report.findings);
    let below_minimum = f.certify(&request(&f, 50_000, 4));
    assert!(below_minimum.report.findings.is_empty());
    let key = f.book.checkpoint_public_key();
    for certified in [historical, corrected, restored, below_minimum] {
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
        assert!(verified.checkpoint.checkpoint.through_seq > frontier.0);
        let procedure = verified.procedure.unwrap();
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
        assert_eq!(procedure.findings.len(), certified.report.findings.len());
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::RelativeSizeFactor {
                min_rsf_bps: 50_000,
                min_subset_size: if procedure.findings.is_empty() { 4 } else { 3 },
            }
        );
        for finding in &procedure.findings {
            match finding.statistic {
                VerifiedProcedureStatistic::RelativeSizeFactor {
                    basis_points,
                    largest_entry,
                    second_entry,
                    account,
                } => {
                    assert!(matches!(basis_points, 50_000 | 100_000));
                    assert_eq!(Some(largest_entry), finding.entry);
                    assert!(second_entry != finding.entry.unwrap());
                    if let Some(account) = account {
                        assert_eq!(account, f.id("6000").0);
                    }
                }
                ref other => panic!("unexpected RSF statistic: {other:?}"),
            }
        }
        let command = fa_verify::cli::run(
            &[
                "report".into(),
                "rsf.fab".into(),
                "--key".into(),
                key.iter().map(|byte| format!("{byte:02x}")).collect(),
                "--receipt".into(),
                "rsf.receipt".into(),
                "--json".into(),
            ],
            &|path| match path {
                "rsf.fab" => Ok(produced.bundle.bytes.clone()),
                "rsf.receipt" => Ok(produced.receipt.clone()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "unexpected input",
                )),
            },
        );
        assert_eq!(command.exit, 0, "{}", command.stdout);
        if !procedure.findings.is_empty() {
            assert!(
                command.stdout.contains("\"statistic\":\"rsf_bps\""),
                "{}",
                command.stdout
            );
            assert!(
                command.stdout.contains("\"second_entry\""),
                "{}",
                command.stdout
            );
        }
    }
}

#[test]
fn relative_size_factor_exports_full_citation_ties_and_wide_ratios() {
    let mut f = Fixture::new(246);
    let (source, _) = f.post(2, "3000", "1020", 1, false);
    for (index, (first, second)) in [(900, 800), (90, 80), (80, 70)].into_iter().enumerate() {
        let mut proposal = template(&f, source, format!("rsf-tie:{index}").as_bytes(), 3);
        proposal.legs = vec![
            LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(f.unit, first)),
            LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(f.unit, second)),
            LegPayload::simple(
                Side::Credit,
                f.id("3000"),
                Amount::new(f.unit, first + second),
            ),
        ];
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        post(&mut f, proposal);
    }
    let tied = f.certify(&request(&f, 50_000, 3));
    assert_eq!(tied.report.findings.len(), 2);
    assert_eq!(
        tied.report.findings[0].cites[..2],
        tied.report.findings[1].cites[..2]
    );
    assert_ne!(
        tied.report.findings[0].cites[2],
        tied.report.findings[1].cites[2]
    );
    let key = f.book.checkpoint_public_key();
    let produced = produce(&mut f, &tied.certificate);
    verify(&produced, &tied.certificate, key);

    let mut wide = Fixture::new(247);
    for amount in [i128::MAX / 2, i128::MAX / 4, i128::MAX / 8] {
        wide.post(3, "3000", "6000", amount, false);
    }
    let certified = wide.certify(&request(&wide, 20_000, 3));
    assert_eq!(certified.report.findings.len(), 1);
    assert_eq!(certified.report.findings[0].statistic.value, 20_000);
    let key = wide.book.checkpoint_public_key();
    let produced = produce(&mut wide, &certified.certificate);
    verify(&produced, &certified.certificate, key);
}

#[test]
fn relative_size_factor_rejects_resealed_results_and_unsupported_profiles() {
    let mut f = Fixture::new(248);
    let (unrelated, _) = population(&mut f);
    let certified = f.certify(&request(&f, 50_000, 3));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "ratio",
        "population",
        "severity",
        "citation",
        "narrative",
        "omitted",
        "work",
        "threshold",
        "minimum",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "ratio" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::Low,
            "citation" => report.findings[0].cites[0] = Cite::Entry(unrelated),
            "narrative" => report.findings[0].narrative.push_str(" altered"),
            "omitted" => {
                report.findings.pop();
            }
            "work" => report.work.comparisons += 1,
            "threshold" => report.parameters[0].1 = 1_000_000,
            "minimum" => report.parameters[1].1 = 100,
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
        "version",
        "cutoff",
        "handles",
        "negative",
        "bound",
        "singleton",
        "inventory",
    ] {
        let mut forged = certified.certificate.clone();
        match variant {
            "version" => {
                forged.report.version = 2;
                for finding in &mut forged.report.findings {
                    finding.version = 2;
                }
            }
            "cutoff" => forged.report.coordinate.effective_through = Some(day(3)),
            "handles" => forged.report.inputs.push(("account".into(), "6000".into())),
            "negative" => forged.report.parameters[0].1 = -1,
            "bound" => forged.report.parameters[0].1 = i128::from(u32::MAX) + 1,
            "singleton" => forged.report.parameters[1].1 = 1,
            "inventory" => {
                forged.report.parameters.pop();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            forged.check_offline_profile().unwrap_err().code,
            fa_notary::code::SCOPE_UNSUPPORTED,
            "{variant}"
        );
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        let refusal = verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
            .unwrap_err();
        assert!(
            matches!(
                refusal.predicate,
                "procedure_profile" | "canonical_encoding"
            ),
            "{variant}: {refusal}"
        );
    }
}
