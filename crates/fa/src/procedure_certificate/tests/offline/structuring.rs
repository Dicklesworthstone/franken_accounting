//! Native graph results must agree byte-for-byte with independently allocated
//! original journal legs, after the source book is no longer available.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("graph.structuring", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    for (name, value) in [
        ("floor", 200),
        ("threshold", 1_000),
        ("min_count", 3),
        ("window_days", 5),
    ] {
        request.parameters = request.parameters.set(name, value).unwrap();
    }
    request
}

fn export(f: &mut Fixture, certified: &CertifiedProcedure) -> crate::ProducedBundle {
    assert_eq!(certified.certificate.format(), PROCEDURE_CERTIFICATE_FORMAT);
    assert!(certified.certificate.supplemental_inputs().is_empty());
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
fn graph_structuring_exports_original_split_legs_complete_chains_and_historical_liveness() {
    let mut f = Fixture::new(209);
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let mut first = VId(0);
    for date in [2, 7, 12, 18] {
        let (entry, _) = f.post(date, "1000", "1010", 800, false);
        if date == 2 {
            first = entry;
        }
    }
    let mut split = template(&f, source, b"structuring-split", 5);
    split.legs = vec![
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(f.unit, 2_400)),
        LegPayload::simple(Side::Debit, f.id("1020"), Amount::new(f.unit, 800)),
        LegPayload::simple(Side::Debit, f.id("1020"), Amount::new(f.unit, 800)),
        LegPayload::simple(Side::Debit, f.id("1020"), Amount::new(f.unit, 800)),
    ];
    split.unit_totals = EntryPayload::fold_unit_totals(&split.legs).unwrap();
    let split_entry = post(&mut f, split);
    let mut ties = template(&f, source, b"structuring-capacity-ties", 5);
    ties.legs = vec![
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(f.unit, 1)),
        LegPayload::simple(Side::Credit, f.id("1010"), Amount::new(f.unit, 1)),
        LegPayload::simple(Side::Debit, f.id("1020"), Amount::new(f.unit, 1)),
        LegPayload::simple(Side::Debit, f.id("6000"), Amount::new(f.unit, 1)),
    ];
    ties.unit_totals = EntryPayload::fold_unit_totals(&ties.legs).unwrap();
    post(&mut f, ties);
    let yen = f.book.context().units.lookup("JPY").unwrap();
    for date in [3, 4, 5] {
        let mut proposal = template(
            &f,
            source,
            format!("structuring-yen-{date}").as_bytes(),
            date,
        );
        proposal.legs = vec![
            LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(yen, 800)),
            LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(yen, 800)),
        ];
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        post(&mut f, proposal);
    }
    f.post(5, "1000", "1010", 199, false);
    f.post(5, "1000", "1010", 1_000, false);
    f.post(5, "1010", "1000", 800, false);
    let historical = f.certify(&request(&f));
    assert_eq!(historical.report.findings.len(), 2);
    assert!(
        historical
            .report
            .findings
            .iter()
            .all(|finding| finding.statistic.value == 2_400 && finding.statistic.population == 8)
    );
    assert!(
        historical
            .report
            .findings
            .iter()
            .any(|finding| finding.narrative.contains("within 10 day(s)"))
    );
    assert!(historical.report.findings.iter().any(|finding| finding.cites.len() == 3 && finding.cites[2] == Cite::Entry(split_entry)));
    let mut yen_request = request(&f);
    yen_request.parameters = yen_request.parameters.set("currency_iso4217", 392).unwrap();
    let yen_report = f.certify(&yen_request);
    assert_eq!(yen_report.report.findings.len(), 1);
    assert_eq!(yen_report.report.findings[0].statistic.scale, 0);
    let mut zero_request = request(&f);
    zero_request.parameters = zero_request.parameters.set("min_count", 100).unwrap();
    let zero = f.certify(&zero_request);
    assert!(zero.report.findings.is_empty());
    assert_eq!(zero.report.work.comparisons, 8);
    let original_frontier = f.head();
    let undo = reverse(&mut f, first, b"structuring-undo", 20);
    let corrected = f.certify(&request(&f));
    assert_eq!(corrected.report.findings.len(), 1);
    reverse(&mut f, undo, b"structuring-restore", 21);
    let restored = f.certify(&request(&f));
    assert_eq!(restored.report.findings, historical.report.findings);
    let key = f.book.checkpoint_public_key();
    let mut artifacts = Vec::new();
    for certified in [historical, yen_report, zero, corrected, restored] {
        let produced = export(&mut f, &certified);
        artifacts.push((certified, produced));
    }
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > original_frontier.0);
        let graph = verified.procedure.unwrap();
        assert!(matches!(
            graph.parameters,
            VerifiedProcedureParameters::GraphStructuring { .. }
        ));
        assert_eq!(graph.live_entries, certified.report.work.entries);
        assert_eq!(graph.live_legs, certified.report.work.legs);
        assert_eq!(graph.comparisons, certified.report.work.comparisons);
        assert!(graph.findings.iter().all(|finding| matches!(
            finding.statistic,
            VerifiedProcedureStatistic::StructuredTransfers { .. }
        )));
    }
}

#[test]
fn graph_structuring_offline_resolves_a_sole_explicit_entity_from_original_legs() {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let mut f = Fixture::with_entities(
        210,
        vec![fa_journal::genesis::LegalEntitySpec {
            code: "ALPHA".into(),
            name: "Declared entity".into(),
            functional_unit: usd,
        }],
    );
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let entity = fa_model::entity_value_vid(f.book.context().book_id, "ALPHA");
    for date in [2, 3, 4] {
        let mut proposal = template(
            &f,
            source,
            format!("entity-transfer-{date}").as_bytes(),
            date,
        );
        proposal.legs = vec![
            LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(usd, 800)),
            LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(usd, 800)),
        ];
        if date == 3 {
            for leg in &mut proposal.legs {
                leg.dimension_set
                    .push((fa_model::LEGAL_ENTITY_DIMENSION, entity));
            }
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        post(&mut f, proposal);
    }
    let certified = f.certify(&request(&f));
    assert_eq!(certified.report.findings.len(), 1);
    let produced = export(&mut f, &certified);
    let verified = verify(
        &produced,
        &certified.certificate,
        f.book.checkpoint_public_key(),
    );
    let graph = verified.procedure.unwrap();
    assert!(matches!(graph.findings[0].statistic,
        VerifiedProcedureStatistic::StructuredTransfers { entity: Some(value), .. } if value == entity.0));
}

#[test]
fn graph_structuring_rejects_resealed_findings_omitted_sources_and_unsupported_profiles() {
    let mut f = Fixture::new(211);
    let (first, _) = f.post(2, "1000", "1010", 800, false);
    f.post(3, "1000", "1010", 800, false);
    f.post(4, "1000", "1010", 800, false);
    let certified = f.certify(&request(&f));
    let produced = export(&mut f, &certified);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "amount",
        "population",
        "severity",
        "account",
        "entry",
        "omitted",
        "comparisons",
        "legs",
        "entries",
        "parameter",
        "narrative",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "amount" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::Info,
            "account" => report.findings[0].cites[0] = Cite::Account(f.id("6000")),
            "entry" => report.findings[0].cites[2] = Cite::Entry(VId(1)),
            "omitted" => report.findings.clear(),
            "comparisons" => report.work.comparisons += 1,
            "legs" => report.work.legs += 1,
            "entries" => report.work.entries += 1,
            "parameter" => {
                report
                    .parameters
                    .iter_mut()
                    .find(|(name, _)| name == "threshold")
                    .unwrap()
                    .1 += 1
            }
            "narrative" => report.findings[0].narrative.push_str(" altered"),
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
    for variant in ["version", "cutoff", "handle", "parameter"] {
        let mut forged = certified.certificate.clone();
        match variant {
            "version" => {
                forged.report.version = 1;
                for finding in &mut forged.report.findings {
                    finding.version = 1;
                }
            }
            "cutoff" => forged.report.coordinate.effective_through = Some(day(31)),
            "handle" => forged.report.inputs.push(("account".into(), "1000".into())),
            "parameter" => {
                forged
                    .report
                    .parameters
                    .iter_mut()
                    .find(|(name, _)| name == "min_count")
                    .unwrap()
                    .1 = 0
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
            if variant == "handle" {
                "canonical_encoding"
            } else {
                "procedure_profile"
            },
            "{variant}"
        );
    }

    let digest = f
        .book
        .read_entry(&f.cx(), first)
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
    let count_offset = reader.offset();
    let count = reader.u32("records").unwrap();
    let mut member = None;
    for _ in 0..count {
        let start = reader.offset();
        reader.u32("proposal length").unwrap();
        let payload = reader
            .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "record")
            .unwrap();
        if fa_model::Entry::decode(payload).is_ok_and(|entry| entry.entry_digest == digest) {
            member = Some((start, reader.offset()));
        }
    }
    let (start, end) = member.unwrap();
    let mut writer = Writer::new();
    writer
        .fixed(&bytes[..count_offset])
        .u32(count - 1)
        .fixed(&bytes[count_offset + 4..start])
        .fixed(&bytes[end..]);
    let omitted = writer.finish().unwrap();
    let mut altered = bytes.clone();
    altered[end - 1] ^= 1;
    for (changed, predicate) in [
        (omitted, "record_completeness"),
        (altered, "record_derivation"),
    ] {
        assert_eq!(
            verify_report_expected(
                &changed,
                &[key],
                None,
                None,
                Some(certified.certificate.digest())
            )
            .unwrap_err()
            .predicate,
            predicate
        );
    }
    assert!(verify_report_expected(bytes, &[key], None, None, None).is_err());
    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "graph.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "graph.receipt".into(),
            "--json".into(),
        ],
        &|path| match path {
            "graph.fab" => Ok(produced.bundle.bytes.clone()),
            "graph.receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}", command.stdout);
    for field in [
        "graph.structuring",
        "chain_mantissa",
        "from_account",
        "to_account",
        "transfers",
    ] {
        assert!(
            command.stdout.contains(field),
            "{field}: {}",
            command.stdout
        );
    }
}
