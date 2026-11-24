//! Real temporal graph reports cross the independent verifier boundary.
//! Complete authenticated original legs, not producer graph paths, must
//! reproduce citations, retained amounts, work counters and witness text.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture, id: &str) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(id, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request
}

fn export(f: &mut Fixture, certified: &CertifiedProcedure) -> crate::ProducedBundle {
    certified.certificate.check_offline_profile().unwrap();
    assert_eq!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report,
    );
    produce(f, &certified.certificate)
}

fn verify_run(
    produced: &crate::ProducedBundle,
    certified: &CertifiedProcedure,
    key: [u8; 32],
) -> fa_verify::report::VerifiedProcedure {
    let run = verify(produced, &certified.certificate, key)
        .procedure
        .unwrap();
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (
            certified.report.work.entries,
            certified.report.work.legs,
            certified.report.work.comparisons
        )
    );
    assert_eq!(run.findings.len(), certified.report.findings.len());
    run
}

pub(super) fn omit_posting(produced: &crate::ProducedBundle, digest: [u8; 32]) -> Vec<u8> {
    let bytes = &produced.bundle.bytes;
    let mut reader = Reader::new(bytes);
    reader.bytes(64, "format").unwrap();
    assert_eq!(reader.u16("major").unwrap(), 2);
    assert_eq!(reader.u16("minor").unwrap(), 0);
    for field in ["certificate", "checkpoint", "prefix"] {
        reader
            .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, field)
            .unwrap();
    }
    let count_at = reader.offset();
    let count = reader.u32("records").unwrap();
    let mut original = None;
    for _ in 0..count {
        let start = reader.offset();
        reader.u32("proposal_length").unwrap();
        let payload = reader
            .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "record")
            .unwrap();
        if fa_model::Entry::decode(payload).is_ok_and(|entry| entry.entry_digest == digest) {
            original = Some((start, reader.offset()));
        }
    }
    let (start, end) = original.expect("complete prefix includes the original posting");
    let mut omitted = Writer::new();
    omitted
        .fixed(&bytes[..count_at])
        .u32(count - 1)
        .fixed(&bytes[count_at + 4..start])
        .fixed(&bytes[end..]);
    omitted.finish().unwrap()
}

#[test]
fn circular_flows_export_original_paths_retention_and_historical_reversal_liveness() {
    let mut f = Fixture::new(234);
    let (first, _) = f.post(1, "1000", "1010", 1_000, false);
    let (second, _) = f.post(2, "1010", "1020", 950, false);
    let (closing, _) = f.post(3, "1020", "1000", 800, false);
    f.post(4, "1000", "1010", 1_000, false);
    f.post(5, "1010", "1000", 690, false);
    f.post(6, "1010", "1000", 1_000, false);
    // The first sub-threshold return prevents selecting the later large
    // return directly. The intermediate path still closes with 80% retained.
    let original = f.certify(&request(&f, "graph.circular_flows"));
    assert_eq!(original.report.findings.len(), 1);
    assert_eq!(original.report.findings[0].statistic.value, 800);
    assert_eq!(
        original.report.findings[0].cites,
        [
            Cite::Entry(first),
            Cite::Account(f.id("1000")),
            Cite::Entry(second),
            Cite::Account(f.id("1010")),
            Cite::Entry(closing),
            Cite::Account(f.id("1020")),
        ]
    );
    let historical_head = f.head();
    let undo = reverse(&mut f, first, b"portable-cycle-undo", 20);
    let corrected = f.certify(&request(&f, "graph.circular_flows"));
    assert_ne!(corrected.report.findings, original.report.findings);
    assert!(
        corrected
            .report
            .findings
            .iter()
            .all(|finding| !finding.cites.contains(&Cite::Entry(first)))
    );
    reverse(&mut f, undo, b"portable-cycle-restore", 21);
    let restored = f.certify(&request(&f, "graph.circular_flows"));
    assert_eq!(restored.report.findings, original.report.findings);
    let mut impossible = request(&f, "graph.circular_flows");
    impossible.parameters = impossible
        .parameters
        .set("min_retention_bps", 10_001)
        .unwrap();
    let empty = f.certify(&impossible);
    assert!(empty.report.findings.is_empty());
    let key = f.book.checkpoint_public_key();
    let artifacts: Vec<_> = [original, corrected, restored, empty]
        .into_iter()
        .map(|certified| {
            let produced = export(&mut f, &certified);
            (certified, produced)
        })
        .collect();
    drop(f);
    for (certified, produced) in artifacts {
        let run = verify_run(&produced, &certified, key);
        assert!(produced.checkpoint.checkpoint.body.statement.through_seq > historical_head);
        assert!(matches!(
            run.parameters,
            VerifiedProcedureParameters::GraphCircularFlows { .. }
        ));
        assert!(run.findings.iter().all(|finding| matches!(
            finding.statistic,
            VerifiedProcedureStatistic::CircularFlow { .. }
        )));
    }
}

#[test]
fn layering_exports_only_forward_chronology_with_shortcuts_and_exact_large_amounts() {
    let mut f = Fixture::new(235);
    let amount = i128::MAX / 800 * 100;
    let (first, _) = f.post(3, "1000", "1010", amount, false);
    let (earlier_terminal, _) = f.post(3, "1020", "6000", amount / 10 * 9, false);
    let (middle, _) = f.post(3, "1010", "1020", amount / 10 * 9, false);
    let earlier = f.certify(&request(&f, "graph.layering"));
    assert!(
        earlier.report.findings.is_empty(),
        "same-day backwards hops are excluded by v3"
    );
    let (terminal, _) = f.post(3, "1020", "6000", amount / 100 * 81, false);
    f.post(3, "1000", "6000", amount, false);
    let certified = f.certify(&request(&f, "graph.layering"));
    assert_eq!(certified.report.findings.len(), 1);
    assert_eq!(
        certified.report.findings[0].statistic.value,
        amount / 100 * 81
    );
    assert_eq!(
        certified.report.findings[0].cites,
        [
            Cite::Entry(first),
            Cite::Account(f.id("1000")),
            Cite::Entry(middle),
            Cite::Account(f.id("1010")),
            Cite::Entry(terminal),
            Cite::Account(f.id("1020")),
            Cite::Account(f.id("6000")),
        ]
    );
    assert!(
        !certified.report.findings[0]
            .cites
            .contains(&Cite::Entry(earlier_terminal))
    );
    let key = f.book.checkpoint_public_key();
    let earlier_bundle = export(&mut f, &earlier);
    let bundle = export(&mut f, &certified);
    let destination = f.id("6000").0;
    drop(f);
    assert!(
        verify_run(&earlier_bundle, &earlier, key)
            .findings
            .is_empty()
    );
    let run = verify_run(&bundle, &certified, key);
    assert!(matches!(
        run.parameters,
        VerifiedProcedureParameters::GraphLayering { min_hops: 3, .. }
    ));
    assert!(
        matches!(&run.findings[0].statistic, VerifiedProcedureStatistic::LayeredFlow { destination: account, mantissa, .. } if *account == destination && *mantissa == amount / 100 * 81)
    );
}

#[test]
fn circular_flows_export_allocated_split_postings_and_unit_entity_partitions() {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let mut f = Fixture::with_entities(
        236,
        vec![fa_journal::genesis::LegalEntitySpec {
            code: "ALPHA".into(),
            name: "Declared graph entity".into(),
            functional_unit: usd,
        }],
    );
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let entity = fa_model::entity_value_vid(f.book.context().book_id, "ALPHA");
    let mut split = template(&f, source, b"portable-cycle-split", 2);
    split.legs = vec![
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(usd, 1_600)),
        LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(usd, 800)),
        LegPayload::simple(Side::Debit, f.id("1020"), Amount::new(usd, 800)),
    ];
    for leg in &mut split.legs {
        leg.dimension_set
            .push((fa_model::LEGAL_ENTITY_DIMENSION, entity));
    }
    split.unit_totals = EntryPayload::fold_unit_totals(&split.legs).unwrap();
    let outgoing = post(&mut f, split);
    f.post(3, "1010", "1000", 800, false);
    f.post(3, "1020", "1000", 800, false);
    let yen = f.book.context().units.lookup("JPY").unwrap();
    for (date, from, to) in [(4, "1000", "1010"), (5, "1010", "1000")] {
        let mut proposal = template(
            &f,
            source,
            format!("portable-cycle-yen-{date}").as_bytes(),
            date,
        );
        proposal.legs = vec![
            LegPayload::simple(Side::Credit, f.id(from), Amount::new(yen, 800)),
            LegPayload::simple(Side::Debit, f.id(to), Amount::new(yen, 800)),
        ];
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        post(&mut f, proposal);
    }
    let certified = f.certify(&request(&f, "graph.circular_flows"));
    assert_eq!(certified.report.findings.len(), 3);
    let key = f.book.checkpoint_public_key();
    let produced = export(&mut f, &certified);
    drop(f);
    let run = verify_run(&produced, &certified, key);
    assert_eq!(
        run.findings
            .iter()
            .filter(|finding| matches!(
                finding.statistic,
                VerifiedProcedureStatistic::CircularFlow { scale: 0, .. }
            ))
            .count(),
        1
    );
    assert_eq!(run.findings.iter().filter(|finding| matches!(&finding.statistic, VerifiedProcedureStatistic::CircularFlow { hops, unit, entity: Some(found), mantissa: 800, .. } if *unit == usd.0 && *found == entity.0 && hops[0].0 == outgoing.0)).count(), 2);
}

#[test]
fn temporal_graph_reports_reject_resealed_paths_amounts_witnesses_and_profile_changes() {
    for (seed, id) in [(237, "graph.circular_flows"), (238, "graph.layering")] {
        let mut f = Fixture::new(seed);
        let (first, _) = f.post(1, "1000", "1010", 1_000, false);
        f.post(2, "1010", "1020", 900, false);
        f.post(
            3,
            "1020",
            if id == "graph.layering" {
                "6000"
            } else {
                "1000"
            },
            810,
            false,
        );
        let certified = f.certify(&request(&f, id));
        assert_eq!(certified.report.findings.len(), 1);
        let produced = export(&mut f, &certified);
        let key = f.book.checkpoint_public_key();
        verify_run(&produced, &certified, key);
        for variant in [
            "amount",
            "population",
            "severity",
            "chronology",
            "account",
            "omitted",
            "comparisons",
            "legs",
            "entries",
            "witness",
            "window",
        ] {
            let mut forged = certified.certificate.clone();
            let report = &mut forged.report;
            match variant {
                "amount" => report.findings[0].statistic.value += 1,
                "population" => report.findings[0].statistic.population += 1,
                "severity" => report.findings[0].severity = Severity::Medium,
                "chronology" => report.findings[0].cites.swap(0, 2),
                "account" => report.findings[0].cites[1] = Cite::Account(f.id("3000")),
                "omitted" => report.findings.clear(),
                "comparisons" => report.work.comparisons += 1,
                "legs" => report.work.legs += 1,
                "entries" => report.work.entries += 1,
                "witness" => report.findings[0].narrative.push_str(" forged"),
                "window" => {
                    report
                        .parameters
                        .iter_mut()
                        .find(|(name, _)| name == "window_days")
                        .unwrap()
                        .1 = 0
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
        for variant in ["hops", "historical_version", "cutoff", "negative_window"] {
            let mut forged = certified.certificate.clone();
            match variant {
                "hops" => {
                    forged
                        .report
                        .parameters
                        .iter_mut()
                        .find(|(name, _)| name.ends_with("hops"))
                        .unwrap()
                        .1 = 9
                }
                "historical_version" => {
                    let version = if id == "graph.layering" { 2 } else { 1 };
                    forged.report.version = version;
                    for finding in &mut forged.report.findings {
                        finding.version = version;
                    }
                }
                "cutoff" => forged.report.coordinate.effective_through = Some(day(3)),
                "negative_window" => {
                    forged
                        .report
                        .parameters
                        .iter_mut()
                        .find(|(name, _)| name == "window_days")
                        .unwrap()
                        .1 = -1
                }
                _ => unreachable!(),
            }
            assert_eq!(
                forged.check_offline_profile().unwrap_err().code,
                fa_notary::code::SCOPE_UNSUPPORTED
            );
            reseal(&mut forged);
            let changed = replace_certificate(&produced.bundle.bytes, &forged);
            assert_eq!(
                verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                    .unwrap_err()
                    .predicate,
                "procedure_profile",
                "{id}: {variant}"
            );
        }
        let digest = f
            .book
            .read_entry(&f.cx(), first)
            .unwrap()
            .unwrap()
            .0
            .entry_digest;
        let omitted = omit_posting(&produced, digest);
        assert_eq!(
            verify_report_expected(
                &omitted,
                &[key],
                None,
                None,
                Some(certified.certificate.digest())
            )
            .unwrap_err()
            .predicate,
            "record_completeness",
            "{id}: repairing record framing cannot omit a source transfer",
        );
    }
}
