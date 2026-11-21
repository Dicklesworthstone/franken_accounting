//! The ordinary graph procedure, exported by the real facade and checked by
//! the dependency-free verifier after the source book is gone.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("graph.round_trips", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request
}

fn export(f: &mut Fixture, certified: &CertifiedProcedure) -> crate::ProducedBundle {
    assert_eq!(certified.certificate.format(), PROCEDURE_CERTIFICATE_FORMAT);
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

#[test]
fn graph_round_trips_export_pairing_period_severity_units_and_historical_liveness() {
    let mut f = Fixture::new(220);
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let (first, _) = f.post(2, "1000", "1010", 800, false);
    let (second, _) = f.post(3, "1000", "1010", 800, false);
    let (back_first, _) = f.post(7, "1010", "1000", 800, false);
    let (back_second, _) = f.post(8, "1010", "1000", 800, false);
    f.post(24, "1000", "1020", 700, false);
    f.post(29, "1020", "1000", 700, false);
    f.post(9, "1000", "6000", 800, false);
    f.post(10, "6000", "1000", 800, false);
    let yen = f.book.context().units.lookup("JPY").unwrap();
    for (date, from, to) in [(5, "1000", "1010"), (6, "1010", "1000")] {
        let mut proposal = template(
            &f,
            source,
            format!("round-trip-yen-{date}").as_bytes(),
            date,
        );
        proposal.legs = vec![
            LegPayload::simple(Side::Credit, f.id(from), Amount::new(yen, 800)),
            LegPayload::simple(Side::Debit, f.id(to), Amount::new(yen, 800)),
        ];
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        post(&mut f, proposal);
    }
    let original = f.certify(&request(&f));
    assert_eq!(original.report.findings.len(), 4);
    assert!(
        original
            .report
            .findings
            .iter()
            .all(|finding| finding.statistic.population == 8)
    );
    assert_eq!(
        original
            .report
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::High)
            .count(),
        1
    );
    for pair in [(first, back_first), (second, back_second)] {
        assert!(
            original
                .report
                .findings
                .iter()
                .any(|finding| finding.cites[..2] == [Cite::Entry(pair.0), Cite::Entry(pair.1)])
        );
    }
    assert!(
        original
            .report
            .findings
            .iter()
            .any(|finding| finding.statistic.scale == 0)
    );
    let historical_head = f.head();
    let undo = reverse(&mut f, first, b"round-trip-undo", 20);
    let corrected = f.certify(&request(&f));
    assert_eq!(corrected.report.findings.len(), 3);
    reverse(&mut f, undo, b"round-trip-restore", 21);
    let restored = f.certify(&request(&f));
    assert_eq!(restored.report.findings, original.report.findings);
    let mut empty_request = request(&f);
    empty_request.parameters = empty_request.parameters.set("window_days", 0).unwrap();
    let empty = f.certify(&empty_request);
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
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > historical_head.0);
        let run = verified.procedure.unwrap();
        assert!(matches!(
            run.parameters,
            VerifiedProcedureParameters::GraphRoundTrips { .. }
        ));
        assert_eq!(
            (run.live_entries, run.live_legs, run.comparisons),
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            )
        );
        assert!(run.findings.iter().all(|finding| matches!(
            finding.statistic,
            VerifiedProcedureStatistic::RoundTrip { .. }
        )));
    }
}

#[test]
fn graph_round_trips_export_allocated_split_legs_and_original_entity_identity() {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let mut f = Fixture::with_entities(
        221,
        vec![fa_journal::genesis::LegalEntitySpec {
            code: "ALPHA".into(),
            name: "Declared entity".into(),
            functional_unit: usd,
        }],
    );
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let entity = fa_model::entity_value_vid(f.book.context().book_id, "ALPHA");
    let mut split = template(&f, source, b"round-trip-split", 20);
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
    f.post(25, "1010", "1000", 800, false);
    f.post(25, "1020", "1000", 800, false);
    let certified = f.certify(&request(&f));
    assert_eq!(certified.report.findings.len(), 2);
    let produced = export(&mut f, &certified);
    let key = f.book.checkpoint_public_key();
    drop(f);
    let run = verify(&produced, &certified.certificate, key)
        .procedure
        .unwrap();
    for finding in run.findings {
        assert!(
            matches!(finding.statistic, VerifiedProcedureStatistic::RoundTrip {
            outbound, entity: Some(found), mantissa: 800, scale: 2, ..
        } if outbound == outgoing.0 && found == entity.0)
        );
    }
}

#[test]
fn graph_round_trips_reject_resealed_outputs_and_unsupported_multihop_profiles() {
    let mut f = Fixture::new(222);
    let (outgoing, _) = f.post(24, "1000", "1010", 800, false);
    f.post(29, "1010", "1000", 800, false);
    let certified = f.certify(&request(&f));
    assert_eq!(certified.report.findings.len(), 1);
    let produced = export(&mut f, &certified);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "amount",
        "population",
        "severity",
        "entry",
        "account",
        "omitted",
        "comparisons",
        "legs",
        "entries",
        "narrative",
        "period_window",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "amount" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::Medium,
            "entry" => report.findings[0].cites.swap(0, 1),
            "account" => report.findings[0].cites[2] = Cite::Account(f.id("6000")),
            "omitted" => report.findings.clear(),
            "comparisons" => report.work.comparisons += 1,
            "legs" => report.work.legs += 1,
            "entries" => report.work.entries += 1,
            "narrative" => report.findings[0].narrative.push_str(" altered"),
            "period_window" => {
                report
                    .parameters
                    .iter_mut()
                    .find(|(name, _)| name == "period_end_days")
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
            "{variant}"
        );
    }
    for variant in ["multihop", "version", "cutoff", "zero_search", "handle"] {
        let mut forged = certified.certificate.clone();
        match variant {
            "multihop" => {
                forged
                    .report
                    .parameters
                    .iter_mut()
                    .find(|(name, _)| name == "max_hops")
                    .unwrap()
                    .1 = 3
            }
            "zero_search" => {
                forged
                    .report
                    .parameters
                    .iter_mut()
                    .find(|(name, _)| name == "max_search_steps")
                    .unwrap()
                    .1 = 0
            }
            "version" => {
                forged.report.version = 1;
                forged.report.findings[0].version = 1;
            }
            "cutoff" => forged.report.coordinate.effective_through = Some(day(31)),
            "handle" => forged.report.inputs.push(("account".into(), "1000".into())),
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
            "{variant}"
        );
    }
    // An attacker can repair transport counts as well as public output hashes.
    // The authenticated complete prefix must still require the original leg
    // payload that supplied the outward transfer.
    let outgoing_digest = f
        .book
        .read_entry(&f.cx(), outgoing)
        .unwrap()
        .unwrap()
        .0
        .entry_digest;
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
        if fa_model::Entry::decode(payload).is_ok_and(|entry| entry.entry_digest == outgoing_digest)
        {
            original = Some((start, reader.offset()));
        }
    }
    let (start, end) = original.unwrap();
    let mut omitted = Writer::new();
    omitted
        .fixed(&bytes[..count_at])
        .u32(count - 1)
        .fixed(&bytes[count_at + 4..start])
        .fixed(&bytes[end..]);
    assert_eq!(
        verify_report_expected(
            &omitted.finish().unwrap(),
            &[key],
            None,
            None,
            Some(certified.certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "record_completeness"
    );
    let mut altered = bytes.clone();
    altered[end - 1] ^= 1;
    assert_eq!(
        verify_report_expected(
            &altered,
            &[key],
            None,
            None,
            Some(certified.certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "record_derivation"
    );
    assert!(verify_report_expected(bytes, &[key], None, None, None).is_err());
    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "round-trips.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "round-trips.receipt".into(),
            "--json".into(),
        ],
        &|path| match path {
            "round-trips.fab" => Ok(produced.bundle.bytes.clone()),
            "round-trips.receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected test input",
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}", command.stdout);
    assert!(command.stdout.contains("round_trip_mantissa"));
    assert!(command.stdout.contains("\"value\":\"800\""));
    assert!(command.stdout.contains("outbound_entry"));
    assert!(command.stdout.contains("return_entry"));
}
