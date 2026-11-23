//! A recipient reconstructs numeric audit findings from portable authenticated
//! inputs, including group boundaries and corrections at the saved frontier.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture, id: &str, parameters: &[(&str, i128)]) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(id, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    for &(name, value) in parameters {
        request.parameters = request.parameters.set(name, value).unwrap();
    }
    request
}

fn party(f: &mut Fixture, code: &str) {
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
}

fn movement(
    f: &mut Fixture,
    source: VId,
    key: &[u8],
    date: u8,
    accounts: (&str, &str),
    amount: Amount,
    party: Option<&str>,
) -> VId {
    let mut proposal = template(f, source, key, date);
    proposal.legs = vec![
        LegPayload::simple(Side::Credit, f.id(accounts.0), amount),
        LegPayload::simple(Side::Debit, f.id(accounts.1), amount),
    ];
    if let Some(party) = party {
        let value = fa_model::party_value_vid(f.book.context().book_id, party);
        for leg in &mut proposal.legs {
            leg.dimension_set.push((fa_model::PARTY_DIMENSION, value));
        }
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post(f, proposal)
}

fn export(f: &mut Fixture, certified: &CertifiedProcedure) -> crate::ProducedBundle {
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
    produce(f, &certified.certificate)
}

#[test]
fn relative_size_factor_exports_party_account_and_unit_groups_at_original_frontier() {
    let mut f = Fixture::new(245);
    party(&mut f, "RSF-A");
    party(&mut f, "RSF-B");
    let usd = f.unit;
    let yen = f.book.context().units.lookup("JPY").unwrap();
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let mut anonymous_largest = VId(0);
    for (prefix, currency, counterparty, values) in [
        ("usd", usd, None, [100, 100, 1_000]),
        ("yen", yen, None, [10, 100, 1_000]),
        ("a", usd, Some("RSF-A"), [40, 50, 400]),
        ("b", usd, Some("RSF-B"), [80, 90, 100]),
    ] {
        for (index, value) in values.into_iter().enumerate() {
            let debit = if counterparty.is_some() && index == 1 {
                "1010"
            } else {
                "6000"
            };
            let vid = movement(
                &mut f,
                source,
                format!("rsf-{prefix}-{index}").as_bytes(),
                2 + index as u8,
                ("3000", debit),
                Amount::new(currency, value),
                counterparty,
            );
            if prefix == "usd" && index == 2 {
                anonymous_largest = vid;
            }
        }
    }
    let historical = f.certify(&request(&f, "numbers.relative_size_factor", &[]));
    assert_eq!(historical.report.findings.len(), 3);
    assert_eq!(
        historical
            .report
            .findings
            .iter()
            .map(|finding| finding.statistic.value)
            .collect::<std::collections::BTreeSet<_>>(),
        [80_000, 100_000].into_iter().collect()
    );
    let original_frontier = f.head();
    let undo = reverse(&mut f, anonymous_largest, b"rsf-undo", 10);
    let corrected = f.certify(&request(&f, "numbers.relative_size_factor", &[]));
    assert_eq!(corrected.report.findings.len(), 2);
    reverse(&mut f, undo, b"rsf-restore", 11);
    let restored = f.certify(&request(&f, "numbers.relative_size_factor", &[]));
    assert_eq!(restored.report.findings, historical.report.findings);
    let key = f.book.checkpoint_public_key();
    let mut artifacts = Vec::new();
    for certified in [historical, corrected, restored] {
        let produced = export(&mut f, &certified);
        artifacts.push((certified, produced));
    }
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > original_frontier.0);
        let procedure = verified.procedure.unwrap();
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::RelativeSizeFactor {
                min_rsf_bps: 50_000,
                min_subset_size: 3,
            }
        );
        assert_eq!(procedure.findings.len(), certified.report.findings.len());
        assert_eq!(procedure.live_entries, certified.report.work.entries);
        assert_eq!(procedure.live_legs, certified.report.work.legs);
        assert_eq!(procedure.comparisons, certified.report.work.comparisons);
        let mut party_findings = 0;
        for finding in &procedure.findings {
            match finding.statistic {
                VerifiedProcedureStatistic::RelativeSizeFactor {
                    basis_points,
                    account,
                    ..
                } => {
                    if account.is_none() {
                        party_findings += 1;
                        assert_eq!(basis_points, 80_000);
                    } else {
                        assert_eq!(basis_points, 100_000);
                    }
                }
                ref other => panic!("unexpected number statistic: {other:?}"),
            }
        }
        assert_eq!(party_findings, 1, "a different party cannot dilute RSF-A");
    }
}

#[test]
fn relative_size_factor_preserves_equal_value_ties_and_same_entry_legs() {
    let mut f = Fixture::new(246);
    let (first, _) = f.post(2, "3000", "1000", 70, false);
    let (second, _) = f.post(3, "3000", "1000", 70, false);
    f.post(4, "3000", "1000", 1, false);
    let mut split = template(&f, first, b"rsf-same-entry-legs", 5);
    split.legs = vec![
        LegPayload::simple(Side::Debit, f.id("1020"), Amount::new(f.unit, 90)),
        LegPayload::simple(Side::Debit, f.id("1020"), Amount::new(f.unit, 10)),
        LegPayload::simple(Side::Credit, f.id("3000"), Amount::new(f.unit, 100)),
    ];
    split.unit_totals = EntryPayload::fold_unit_totals(&split.legs).unwrap();
    let split = post(&mut f, split);
    let certified = f.certify(&request(
        &f,
        "numbers.relative_size_factor",
        &[("min_rsf_bps", 10_000), ("min_subset_size", 2)],
    ));
    let produced = export(&mut f, &certified);
    let verified = verify(
        &produced,
        &certified.certificate,
        f.book.checkpoint_public_key(),
    );
    let findings = verified.procedure.unwrap().findings;
    assert_eq!(findings.len(), 2);
    for finding in findings {
        assert_eq!(finding.population, 5);
        match finding.statistic {
            VerifiedProcedureStatistic::RelativeSizeFactor {
                basis_points,
                largest_entry,
                second_entry,
                account,
            } if account == Some(f.id("1000").0) => {
                assert_eq!(basis_points, 10_000);
                assert_eq!(largest_entry, first.min(second).0);
                assert_eq!(second_entry, first.max(second).0);
            }
            VerifiedProcedureStatistic::RelativeSizeFactor {
                basis_points,
                largest_entry,
                second_entry,
                account,
            } => {
                assert_eq!(account, Some(f.id("1020").0));
                assert_eq!(basis_points, 90_000);
                assert_eq!((largest_entry, second_entry), (split.0, split.0));
            }
            other => panic!("unexpected number statistic: {other:?}"),
        }
    }
}

#[test]
fn threshold_splitting_exports_complete_windows_party_boundaries_and_currency() {
    let mut f = Fixture::new(247);
    party(&mut f, "SPLIT-A");
    party(&mut f, "SPLIT-B");
    let usd = f.unit;
    let yen = f.book.context().units.lookup("JPY").unwrap();
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let mut first = VId(0);
    for (index, (date, value)) in [(2, 600), (3, 500), (7, 400), (14, 900), (20, 300)]
        .into_iter()
        .enumerate()
    {
        let vid = movement(
            &mut f,
            source,
            format!("split-account-{index}").as_bytes(),
            date,
            ("3000", "1000"),
            Amount::new(usd, value),
            None,
        );
        if index == 0 {
            first = vid;
        }
    }
    for (key, date, accounts, value, unit, counterparty) in [
        ("party-a1", 3, ("3000", "1000"), 600, usd, Some("SPLIT-A")),
        ("party-a2", 4, ("6000", "1010"), 500, usd, Some("SPLIT-A")),
        ("party-b", 3, ("3000", "1000"), 700, usd, Some("SPLIT-B")),
        ("other-pair1", 4, ("6000", "1010"), 600, usd, None),
        ("other-pair2", 5, ("6000", "1010"), 500, usd, None),
        ("yen1", 4, ("3000", "1000"), 600, yen, None),
        ("yen2", 5, ("3000", "1000"), 500, yen, None),
        ("floor-excluded", 6, ("3000", "1000"), 199, usd, None),
        ("threshold-excluded", 6, ("3000", "1000"), 1_000, usd, None),
    ] {
        movement(
            &mut f,
            source,
            key.as_bytes(),
            date,
            accounts,
            Amount::new(unit, value),
            counterparty,
        );
    }
    let parameters = [("threshold", 1_000), ("floor", 200)];
    let historical = f.certify(&request(&f, "numbers.threshold_splitting", &parameters));
    let totals = |run: &ProcedureRun| {
        let mut totals: Vec<_> = run.findings.iter().map(|row| row.statistic.value).collect();
        totals.sort();
        totals
    };
    assert_eq!(totals(&historical.report), vec![1_100, 1_100, 1_500]);
    let mut yen_request = request(&f, "numbers.threshold_splitting", &parameters);
    yen_request.parameters = yen_request.parameters.set("currency_iso4217", 392).unwrap();
    let yen_report = f.certify(&yen_request);
    assert_eq!(totals(&yen_report.report), vec![1_100]);
    assert_eq!(yen_report.report.findings[0].statistic.scale, 0);
    let mut wide = request(&f, "numbers.threshold_splitting", &parameters);
    wide.parameters = wide
        .parameters
        .set("window_days", i128::from(u32::MAX))
        .unwrap();
    let wide = f.certify(&wide);
    assert_eq!(totals(&wide.report), vec![1_100, 1_100, 2_700]);
    let mut zero = request(&f, "numbers.threshold_splitting", &parameters);
    zero.parameters = zero.parameters.set("window_days", 0).unwrap();
    let zero = f.certify(&zero);
    assert!(zero.report.findings.is_empty());
    let original_frontier = f.head();
    let undo = reverse(&mut f, first, b"split-undo", 21);
    let corrected = f.certify(&request(&f, "numbers.threshold_splitting", &parameters));
    assert_eq!(totals(&corrected.report), vec![1_100, 1_100]);
    reverse(&mut f, undo, b"split-restore", 22);
    let restored = f.certify(&request(&f, "numbers.threshold_splitting", &parameters));
    assert_eq!(restored.report.findings, historical.report.findings);
    let key = f.book.checkpoint_public_key();
    let mut artifacts = Vec::new();
    for certified in [historical, yen_report, wide, zero, corrected, restored] {
        let produced = export(&mut f, &certified);
        artifacts.push((certified, produced));
    }
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > original_frontier.0);
        let procedure = verified.procedure.unwrap();
        assert_eq!(procedure.live_entries, certified.report.work.entries);
        assert_eq!(procedure.live_legs, certified.report.work.legs);
        assert_eq!(procedure.comparisons, certified.report.work.comparisons);
        for finding in procedure.findings {
            assert!(matches!(
                finding.statistic,
                VerifiedProcedureStatistic::SplitTotal { .. }
            ));
        }
    }
}

#[test]
fn numeric_audit_bundles_reject_resealed_results_and_invalid_profiles() {
    let mut f = Fixture::new(248);
    let (source, _) = f.post(2, "3000", "1000", 600, false);
    f.post(3, "3000", "1000", 100, false);
    f.post(4, "3000", "1000", 100, false);
    for (id, parameters) in [
        ("numbers.relative_size_factor", Vec::new()),
        (
            "numbers.threshold_splitting",
            vec![("threshold", 800), ("floor", 50)],
        ),
    ] {
        let certified = f.certify(&request(&f, id, &parameters));
        assert_eq!(certified.report.findings.len(), 1);
        let produced = export(&mut f, &certified);
        let key = f.book.checkpoint_public_key();
        verify(&produced, &certified.certificate, key);
        for variant in [
            "value",
            "population",
            "severity",
            "entry",
            "narrative",
            "omitted",
            "invented",
            "comparisons",
            "legs",
            "entries",
            "threshold",
        ] {
            let mut forged = certified.certificate.clone();
            let report = &mut forged.report;
            match variant {
                "value" => report.findings[0].statistic.value += 1,
                "population" => report.findings[0].statistic.population += 1,
                "severity" => report.findings[0].severity = Severity::Info,
                "entry" => report.findings[0].cites[0] = Cite::Entry(VId(1)),
                "narrative" => report.findings[0].narrative.push_str(" changed"),
                "omitted" => report.findings.clear(),
                "invented" => {
                    let mut extra = report.findings[0].clone();
                    extra.cites[0] = Cite::Entry(VId(2));
                    report.findings.push(extra);
                }
                "comparisons" => report.work.comparisons += 1,
                "legs" => report.work.legs += 1,
                "entries" => report.work.entries += 1,
                "threshold" => {
                    let name = if id == "numbers.relative_size_factor" {
                        "min_rsf_bps"
                    } else {
                        "threshold"
                    };
                    report
                        .parameters
                        .iter_mut()
                        .find(|(key, _)| key == name)
                        .unwrap()
                        .1 = if name == "threshold" { 801 } else { 70_000 };
                }
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
        for variant in ["version", "cutoff", "handle", "missing", "range"] {
            let mut forged = certified.certificate.clone();
            match variant {
                "version" => change_report_version(&mut forged, 2),
                "cutoff" => forged.report.coordinate.effective_through = Some(day(31)),
                "handle" => forged
                    .report
                    .inputs
                    .push(("account".into(), source.0.to_string())),
                "missing" => {
                    forged.report.parameters.pop();
                }
                "range" => {
                    let name = if id == "numbers.relative_size_factor" {
                        "min_subset_size"
                    } else {
                        "floor"
                    };
                    forged
                        .report
                        .parameters
                        .iter_mut()
                        .find(|(key, _)| key == name)
                        .unwrap()
                        .1 = 0;
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
            let error = verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                .unwrap_err();
            assert!(
                matches!(error.predicate, "procedure_profile" | "canonical_encoding"),
                "{id}: {variant}: {error}"
            );
        }
        let command = fa_verify::cli::run(
            &[
                "report".into(),
                "numbers.fab".into(),
                "--key".into(),
                key.iter().map(|byte| format!("{byte:02x}")).collect(),
                "--receipt".into(),
                "numbers.receipt".into(),
                "--json".into(),
            ],
            &|path| match path {
                "numbers.fab" => Ok(produced.bundle.bytes.clone()),
                "numbers.receipt" => Ok(produced.receipt.clone()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "unexpected input",
                )),
            },
        );
        assert_eq!(command.exit, 0, "{}", command.stdout);
        assert!(command.stdout.contains(id));
        assert!(
            command
                .stdout
                .contains(if id == "numbers.relative_size_factor" {
                    "rsf_bps"
                } else {
                    "split_total"
                })
        );
    }
}
