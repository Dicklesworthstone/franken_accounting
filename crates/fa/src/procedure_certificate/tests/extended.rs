use super::*;
use fa_model::{PartyKind, PartySpec, party_vid};
use fgdb_types::CanonicalScalar;

fn review(f: &mut Fixture) -> fa_journal::Attested {
    let cx = f.cx();
    f.runtime
        .block_on(f.book.record_review(
            &cx,
            &Capability::embedded(VId(74), &["approve"]).unwrap(),
            &f.evidence[0].document_oid,
            Vec::new(),
        ))
        .unwrap()
        .unwrap()
}

fn party(f: &mut Fixture, code: &str, bank: &str) -> VId {
    let cx = f.cx();
    let spec = PartySpec {
        code: code.into(),
        kind: PartyKind::Vendor,
        name: f.book.seal_text(&cx, code).unwrap(),
        identifiers: vec![("bank_account".into(), f.book.seal_text(&cx, bank).unwrap())],
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
    party_vid(f.book.context().book_id, code)
}

#[test]
fn layering_v3_keeps_the_actual_v2_registry_and_native_algorithm_replayable() {
    let mut f = Fixture::new(126);
    let (ab, _) = f.post(1, "1000", "1010", 100, false);
    let (cd, _) = f.post(1, "1020", "6000", 100, false);
    let (bc, _) = f.post(1, "1010", "1020", 100, false);
    let mut request = f.request("graph.layering", ab);
    request.effective_through = None;
    let current = f.certify(&request).certificate;
    assert_eq!(current.report.version, 3);
    assert!(current.report.findings.is_empty());
    request.version = Some(2);
    let legacy = f.certify(&request).certificate;
    assert_eq!(legacy.report.version, 2);
    assert_eq!(legacy.report.findings.len(), 1);
    assert_eq!(
        legacy.report.findings[0].statistic,
        Statistic {
            name: "layered_mantissa".into(),
            value: 100,
            scale: 2,
            population: 3
        }
    );
    let entries = |report: &ProcedureRun| {
        report.findings[0]
            .cites
            .iter()
            .filter_map(|cite| {
                if let Cite::Entry(vid) = cite {
                    Some(*vid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(entries(&legacy.report), vec![ab, bc, cd]);
    // Frozen from the b1afca58 native producer's actual retained v2
    // certificate, before this registry edit; never regenerated from v3.
    assert_eq!(
        legacy.registry,
        [
            0x10, 0x3d, 0xab, 0x0f, 0xd1, 0x46, 0xb9, 0x49, 0xf5, 0x27, 0x4e, 0x3e, 0x01, 0xfa,
            0xba, 0x0e, 0x5d, 0x05, 0xc7, 0xb1, 0xf3, 0x4d, 0x03, 0x60, 0x2e, 0xe8, 0x4c, 0xda,
            0xd5, 0x73, 0xef, 0x74,
        ]
    );
    let decoded = ProcedureCertificate::decode(&legacy.canonical_bytes().unwrap()).unwrap();
    let (later_cd, _) = f.post(1, "1020", "6000", 100, false);
    let after = f.head();
    let replayed = f
        .book
        .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
        .unwrap()
        .unwrap();
    assert_eq!(replayed, legacy.report);
    let mut positive = f.request("graph.layering", ab);
    positive.effective_through = None;
    let report = f.certify(&positive).certificate.report;
    assert_eq!(report.version, 3);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(entries(&report), vec![ab, bc, later_cd]);
    assert_eq!(report.findings[0].statistic.population, 4);

    // Repair the public outer digest: version/registry confusion must be
    // rejected by the declared algorithm law, not a stale checksum.
    for (mut confused, registry) in [
        (current, legacy.registry),
        (legacy, registry_digest().unwrap()),
    ] {
        confused.registry = registry;
        confused.digest = domain_digest(CERTIFICATE_DOMAIN, &[&confused.body().unwrap()]);
        let decoded = ProcedureCertificate::decode(&confused.canonical_bytes().unwrap()).unwrap();
        let refusal = f
            .book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert!(
            refusal
                .message
                .contains("does not declare this algorithm version")
        );
    }
    assert_eq!(f.head(), after);
}

#[test]
fn lookback_versions_keep_the_real_prior_registry_and_native_replay() {
    let mut f = Fixture::new(128);
    let (source, _) = f.post(31, "6000", "1000", 100_000, false);
    let before = f.head();
    let mut request = f.request("lookback.fraudulent_transfer", source);
    request.parameters = request
        .parameters
        .set("section_548_days", i128::from(u32::MAX))
        .unwrap()
        .set("uvta_days", i128::from(u32::MAX))
        .unwrap();
    let current = f.certify(&request).certificate;
    assert_eq!(current.report.version, 2);
    assert_eq!(current.report.findings.len(), 1);
    assert_eq!(current.report.findings[0].statistic.value, 100_000);
    assert_eq!(current.report.findings[0].severity, Severity::High);
    request.version = Some(1);
    let legacy = f.certify(&request).certificate;
    assert_eq!(legacy.report.version, 1);
    assert!(legacy.report.findings.is_empty());
    // Extracted from both real pre-change P3/F1 certificates, not regenerated.
    let expected = [
        0xef, 0x30, 0xc8, 0xaa, 0x8a, 0x96, 0x6b, 0x65, 0x8c, 0x60, 0x4b, 0x02, 0x37, 0x47, 0x94,
        0x8e, 0xff, 0xb8, 0x20, 0x92, 0x76, 0x69, 0x41, 0xd0, 0x9a, 0x1b, 0x09, 0x7d, 0x75, 0xa5,
        0x5a, 0x14,
    ];
    assert_eq!(legacy.registry, expected);
    assert_eq!(
        registry_versions(&expected).unwrap(),
        Some((2, 3, 3, 3, 1, 2))
    );
    assert_ne!(current.registry, expected);
    let mut mixed = fa_registry::toml::parse(PROCEDURE_REGISTRIES[0].1).unwrap();
    let historical = fa_registry::toml::parse(&legacy_lookback_registry_text().unwrap()).unwrap();
    let fraud = historical.arrays["procedure"]
        .iter()
        .find(|row| {
            row.get("id").and_then(fa_registry::toml::Value::as_str)
                == Some("lookback.fraudulent_transfer")
        })
        .unwrap()
        .clone();
    let current_fraud = mixed
        .arrays
        .get_mut("procedure")
        .unwrap()
        .iter_mut()
        .find(|row| {
            row.get("id").and_then(fa_registry::toml::Value::as_str)
                == Some("lookback.fraudulent_transfer")
        })
        .unwrap();
    *current_fraud = fraud;
    let mixed = registry_digest_with_procedures(mixed.canonical_bytes()).unwrap();
    assert_eq!(
        registry_versions(&mixed).unwrap(),
        None,
        "P4/F1 was never published"
    );
    for certificate in [&current, &legacy] {
        let decoded =
            ProcedureCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            f.book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
                .unwrap()
                .unwrap(),
            certificate.report,
        );
    }
    // A positive legacy run also needs legacy finding identities, not today's
    // registry version supplied by the common finding constructor.
    request.parameters = Params::defaults("lookback.fraudulent_transfer").unwrap();
    let positive = f.certify(&request).certificate;
    assert_eq!(positive.report.findings.len(), 1);
    assert_eq!(positive.report.findings[0].version, 1);
    assert_eq!(positive.report.findings[0].statistic.value, 100_000);
    assert_eq!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &positive)
            .unwrap()
            .unwrap(),
        positive.report,
    );
    for (mut confused, registry) in [
        (current, legacy.registry),
        (legacy, registry_digest().unwrap()),
    ] {
        confused.registry = registry;
        confused.digest = domain_digest(CERTIFICATE_DOMAIN, &[&confused.body().unwrap()]);
        let refusal = confused.request().unwrap_err();
        assert_eq!(refusal.exit, exit::VERIFICATION);
        assert!(
            refusal
                .message
                .contains("does not declare this algorithm version")
        );
    }
    assert_eq!(
        f.head(),
        before,
        "certification and all replay paths are read-only"
    );
}

#[test]
fn pre_layering_registry_keeps_unchanged_jet_versions_and_portable_documents() {
    let mut f = Fixture::new(127);
    f.assign_role("1000", "suspense");
    let (source, _) = f.post(1, "1000", "1010", 100, false);
    let before = f.head();
    for version in [1, 2] {
        let mut request = f.request("jet.round_amounts", source);
        request.version = Some(version);
        if version == 1 {
            request.effective_through = None;
        }
        let mut certificate = f.certify(&request).certificate;
        let document = layering_v2_registry_document(version == 1).unwrap();
        certificate.registry = registry_digest_with_procedures(document.clone()).unwrap();
        certificate.digest = domain_digest(CERTIFICATE_DOMAIN, &[&certificate.body().unwrap()]);
        let decoded =
            ProcedureCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            canonical_registry_document(&decoded.registry).unwrap(),
            Some(document)
        );
        decoded.check_offline_profile().unwrap();
        let replayed = f
            .book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap();
        assert_eq!(replayed, certificate.report);
        let text = fa_registry::procedures::layering_v2_registry_text(
            &legacy_lookback_registry_text().unwrap(),
        )
        .unwrap();
        let text = if version == 1 {
            retained_jet_registry_text(&text).unwrap()
        } else {
            text
        };
        certificate.registry = domain_digest(
            b"fa:procedure-registry:v1",
            &[text.as_bytes(), PROCEDURE_REGISTRIES[1].1.as_bytes()],
        );
        certificate.digest = domain_digest(CERTIFICATE_DOMAIN, &[&certificate.body().unwrap()]);
        let raw = ProcedureCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap();
        assert!(raw.check_offline_profile().is_err());
        assert_eq!(
            f.book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &raw)
                .unwrap()
                .unwrap(),
            certificate.report
        );
    }
    let mut confused = f
        .certify(&f.request("jet.suspense_aging", source))
        .certificate;
    assert_eq!(confused.report.version, 3);
    confused.registry = retained_registry_digest().unwrap();
    confused.digest = domain_digest(CERTIFICATE_DOMAIN, &[&confused.body().unwrap()]);
    let confused = ProcedureCertificate::decode(&confused.canonical_bytes().unwrap()).unwrap();
    let refusal = f
        .book
        .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &confused)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    assert!(
        refusal
            .message
            .contains("does not declare this algorithm version")
    );
    assert_eq!(f.head(), before);
}

#[test]
fn lapping_v3_retains_native_v2_outputs_and_rejects_the_unversioned_widening() {
    let mut f = Fixture::new(130);
    f.assign_role("1010", "receivable");
    party(&mut f, "LAPPING-A", "lapping-a");
    party(&mut f, "LAPPING-B", "lapping-b");
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let post = |f: &mut Fixture, date, from: &str, to: &str, investor: &str, key: &[u8]| {
        let cx = f.cx();
        let (template, _) = f.book.read_entry(&cx, source).unwrap().unwrap();
        let mut proposal = template.proposal;
        proposal.effective_date = day(date);
        proposal.idempotency_key = key.to_vec();
        proposal.description = f
            .book
            .seal_text(
                &cx,
                "Explicitly synthetic native lapping compatibility control",
            )
            .unwrap();
        proposal.legs = vec![
            LegPayload::simple(Side::Credit, f.id(from), Amount::new(f.unit, 10_000)),
            LegPayload::simple(Side::Debit, f.id(to), Amount::new(f.unit, 10_000)),
        ];
        for leg in &mut proposal.legs {
            if leg.account_ref == f.id("1010") {
                leg.dimension_set.push((
                    fa_model::PARTY_DIMENSION,
                    fa_model::party_value_vid(f.book.context().book_id, investor),
                ));
            }
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        match f
            .runtime
            .block_on(f.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(&["post"]),
                },
            ))
            .unwrap()
            .unwrap()
        {
            Posted::Committed { entry_ref, .. } => entry_ref.vid,
            other => panic!("fresh lapping posting: {other:?}"),
        }
    };
    let invoice = post(&mut f, 1, "3000", "1010", "LAPPING-A", b"lapping-invoice");
    let other = post(&mut f, 3, "1010", "1000", "LAPPING-B", b"lapping-other");
    let settled = post(
        &mut f,
        6,
        "1010",
        "1000",
        "LAPPING-A",
        b"lapping-settlement",
    );
    let before = f.head();
    let cx = f.cx();
    let mut request = f.request("recon.lapping", source);
    request.effective_through = None;
    let ordinary = f.certify(&request).certificate;
    assert_eq!(ordinary.report.version, 4);
    assert_eq!(ordinary.report.work.comparisons, 10);
    assert_eq!(ordinary.report.findings.len(), 1);
    let finding = &ordinary.report.findings[0];
    assert_eq!(finding.version, 4);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(
        finding.statistic,
        Statistic::count("settlement_delay_days", 5, 3)
    );
    assert_eq!(
        finding.cites,
        vec![
            Cite::Account(f.id("1010")),
            Cite::Entry(invoice),
            Cite::Entry(other),
            Cite::Entry(settled)
        ]
    );
    request.version = Some(2);
    let old_ordinary = f.certify(&request).certificate;
    assert_eq!(old_ordinary.report.findings.len(), 1);
    assert_eq!(old_ordinary.report.findings[0].version, 2);
    assert_eq!(old_ordinary.report.findings[0].statistic, finding.statistic);
    assert_eq!(old_ordinary.report.findings[0].cites, finding.cites);
    assert_eq!(old_ordinary.report.work.comparisons, 3);
    request.version = Some(3);
    let old_wide_ordinary = f.certify(&request).certificate;
    assert_eq!(old_wide_ordinary.report.version, 3);
    assert_eq!(old_wide_ordinary.report.work, old_ordinary.report.work);
    assert_eq!(
        old_wide_ordinary.report.findings[0].statistic,
        finding.statistic
    );
    assert_eq!(old_wide_ordinary.report.findings[0].cites, finding.cites);
    request.parameters = request
        .parameters
        .set("window_days", i128::from(u32::MAX))
        .unwrap();
    let old_wide = f.certify(&request).certificate;
    assert_eq!(old_wide.report.findings, old_wide_ordinary.report.findings);
    assert_eq!(old_wide.report.work, old_wide_ordinary.report.work);
    // Extracted from an actual retained v3 native certificate, independently
    // of this revision's inverse and producer; never regenerated for v4.
    assert_eq!(
        old_wide.registry,
        [
            0x20, 0x9f, 0x23, 0x5e, 0x5c, 0x85, 0xec, 0x54, 0xc4, 0xa5, 0x52, 0x3a, 0xc8, 0xaf,
            0x58, 0x85, 0xc3, 0xad, 0x82, 0xdd, 0xe6, 0xcd, 0x9d, 0x68, 0x93, 0x33, 0x48, 0xcd,
            0x78, 0x7f, 0xb5, 0x45,
        ]
    );
    assert_eq!(
        registry_versions(&old_wide.registry).unwrap(),
        Some((2, 3, 3, 4, 2, 3))
    );
    request.version = Some(2);
    let legacy = f.certify(&request).certificate;
    assert_eq!(legacy.report.version, 2);
    assert!(legacy.report.findings.is_empty());
    // Actual P4/F2 native certificate commitment before the lapping revision.
    assert_eq!(
        legacy.registry,
        [
            0xe7, 0x4d, 0xa5, 0x15, 0xc2, 0xc0, 0xf3, 0xf7, 0x8d, 0x08, 0x34, 0x53, 0x81, 0xf9,
            0xd9, 0xce, 0x2f, 0xbc, 0x75, 0x4d, 0xf7, 0xa1, 0xd2, 0xb0, 0x0f, 0x28, 0xd3, 0x42,
            0x83, 0xc0, 0x83, 0xa1,
        ]
    );
    assert_eq!(
        registry_versions(&legacy.registry).unwrap(),
        Some((2, 3, 3, 4, 2, 2))
    );
    request.version = None;
    let current = f.certify(&request).certificate;
    assert_eq!(current.report.version, 4);
    assert_eq!(current.report.work, ordinary.report.work);
    assert_eq!(current.report.findings, ordinary.report.findings);
    assert_ne!(current.registry, legacy.registry);
    assert_ne!(current.registry, old_wide.registry);
    assert_eq!(
        registry_versions(&current.registry).unwrap(),
        Some((2, 3, 3, 4, 2, 4))
    );
    // Extracted independently from both actual native certificates in the
    // preserved 6a1e62d3/b1afca58 control, not regenerated from this producer.
    let original_registry = [
        0x10, 0x3d, 0xab, 0x0f, 0xd1, 0x46, 0xb9, 0x49, 0xf5, 0x27, 0x4e, 0x3e, 0x01, 0xfa, 0xba,
        0x0e, 0x5d, 0x05, 0xc7, 0xb1, 0xf3, 0x4d, 0x03, 0x60, 0x2e, 0xe8, 0x4c, 0xda, 0xd5, 0x73,
        0xef, 0x74,
    ];
    let mut original = legacy.clone();
    original.registry = original_registry;
    super::offline::reseal(&mut original);
    for certificate in [
        &ordinary,
        &old_ordinary,
        &old_wide_ordinary,
        &old_wide,
        &current,
        &legacy,
        &original,
    ] {
        let decoded =
            ProcedureCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap();
        assert_eq!(decoded.supplemental_inputs().len(), 6);
        assert_eq!(
            f.book
                .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &decoded)
                .unwrap()
                .unwrap(),
            certificate.report
        );
    }
    // The intermediate widened producer emitted a false v2 identity under
    // this exact old registry. Keep that coherent counterexample rejected.
    let mut mistagged = original.clone();
    mistagged.report.findings = current.report.findings.clone();
    for finding in &mut mistagged.report.findings {
        finding.version = 2;
    }
    super::offline::reseal(&mut mistagged);
    let refusal = f
        .book
        .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &mistagged)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert!(refusal.message.contains("does not replay exactly"));
    // Findings agree across v3/v4; an enclosing checksum is not evidence
    // that their different recorded work transcripts are interchangeable.
    for (mut wrong_work, work) in [
        (old_wide.clone(), current.report.work),
        (current.clone(), old_wide.report.work),
    ] {
        wrong_work.report.work = work;
        super::offline::reseal(&mut wrong_work);
        let decoded = ProcedureCertificate::decode(&wrong_work.canonical_bytes().unwrap()).unwrap();
        let refusal = f
            .book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::VERIFICATION);
        assert!(refusal.message.contains("does not replay exactly"));
    }
    for (mut confused, registry) in [
        (current.clone(), legacy.registry),
        (legacy.clone(), current.registry),
        (old_wide.clone(), current.registry),
        (current.clone(), old_wide.registry),
        (old_wide.clone(), legacy.registry),
        (legacy.clone(), old_wide.registry),
    ] {
        confused.registry = registry;
        confused.digest = domain_digest(CERTIFICATE_DOMAIN, &[&confused.body().unwrap()]);
        let decoded = ProcedureCertificate::decode(&confused.canonical_bytes().unwrap()).unwrap();
        let refusal = decoded.request().unwrap_err();
        assert_eq!(refusal.exit, exit::VERIFICATION);
        assert!(
            refusal
                .message
                .contains("does not declare this algorithm version")
        );
    }
    assert_eq!(
        f.head(),
        before,
        "certification, replay and refusals do not write"
    );
    f.post(7, "1000", "6000", 100, false);
    let after = f.head();
    for certificate in [&original, &old_wide, &current] {
        assert_eq!(
            f.book
                .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), certificate)
                .unwrap()
                .unwrap(),
            certificate.report
        );
    }
    assert_eq!(f.head(), after);
}

#[test]
fn ponzi_motif_certifies_native_inputs_and_replays_after_backdated_subscription() {
    let mut f = Fixture::new(129);
    f.assign_role("1000", "cash");
    party(&mut f, "MOTIF-A", "motif-bank-a");
    party(&mut f, "MOTIF-B", "motif-bank-b");
    // This anonymous funding is a real posted proposal template, not an
    // investor movement. Each named movement below is admitted separately.
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let post = |f: &mut Fixture, date, from: &str, to: &str, amount, investor: &str, key: &[u8]| {
        let cx = f.cx();
        let (template, _) = f.book.read_entry(&cx, source).unwrap().unwrap();
        let mut proposal = template.proposal;
        proposal.effective_date = day(date);
        proposal.idempotency_key = key.to_vec();
        proposal.description = f
            .book
            .seal_text(&cx, "Synthetic investor movement for native replay")
            .unwrap();
        proposal.legs = vec![
            LegPayload::simple(Side::Credit, f.id(from), Amount::new(f.unit, amount)),
            LegPayload::simple(Side::Debit, f.id(to), Amount::new(f.unit, amount)),
        ];
        for leg in &mut proposal.legs {
            if leg.account_ref != f.id("1000") {
                leg.dimension_set.push((
                    fa_model::PARTY_DIMENSION,
                    fa_model::party_value_vid(f.book.context().book_id, investor),
                ));
            }
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        match f
            .runtime
            .block_on(f.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(&["post"]),
                },
            ))
            .unwrap()
            .unwrap()
        {
            Posted::Committed { entry_ref, .. } => entry_ref.vid,
            other => panic!("fresh investor posting: {other:?}"),
        }
    };
    post(&mut f, 1, "3000", "1000", 100_000, "MOTIF-A", b"motif-a-in");
    let new_money = post(&mut f, 9, "3000", "1000", 60_000, "MOTIF-B", b"motif-b-in");
    let payout = post(
        &mut f,
        10,
        "1000",
        "6000",
        50_000,
        "MOTIF-A",
        b"motif-a-paid",
    );
    let cx = f.cx();
    let before = f.head();
    let mut request = f.request("graph.ponzi_motif", source);
    request.parameters = request.parameters.set("window_days", 7).unwrap();
    let built = request.build().unwrap();
    let plain = f
        .book
        .run_procedure(
            &cx,
            built.as_ref(),
            request.known_at,
            request.effective_through,
            request.budget,
        )
        .unwrap();
    let certified = f.certify(&request);
    assert_eq!(certified.report, plain);
    assert_eq!(certified.report.version, 1);
    assert_eq!(certified.report.findings.len(), 1);
    let finding = &certified.report.findings[0];
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(
        finding.statistic,
        Statistic {
            name: "new_money_to_redemptions_bps".into(),
            value: 12_000,
            scale: 0,
            population: 3,
        }
    );
    assert_eq!(
        finding.cites,
        vec![Cite::Entry(payout), Cite::Entry(new_money)]
    );
    assert_eq!(
        certified.certificate.format(),
        EXTENDED_PROCEDURE_CERTIFICATE_FORMAT
    );
    assert_eq!(certified.certificate.supplemental_inputs().len(), 6);
    let decoded =
        ProcedureCertificate::decode(&certified.certificate.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        ReportArtifact::decode(&decoded.canonical_bytes().unwrap())
            .unwrap()
            .family(),
        ReportArtifactFamily::Procedure
    );
    assert!(matches!(
        f.book
            .procedure_certificate_status(&cx, PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap(),
        ProcedureCertificateStatus::Current { checked_at } if checked_at == before
    ));
    // The producer's body() already rejects these corruptions. Forge their
    // raw framing so a stale outer checksum cannot explain the refusal.
    let rehash = |certificate: &mut ProcedureCertificate| {
        let mut wire = Writer::new();
        wire.bytes(certificate.format())
            .bytes(&certificate.source.canonical_bytes().unwrap())
            .bytes(&certificate.approvals.canonical_bytes());
        wire.list(&certificate.extended_inputs, |w, input| {
            w.bytes(&input.canonical_bytes());
        });
        wire.fixed(&certificate.registry)
            .u128(certificate.producer.0)
            .fixed(&certificate.capability_commitment)
            .bytes(&certificate.output);
        let mut bytes = wire.finish().unwrap();
        certificate.digest = domain_digest(CERTIFICATE_DOMAIN, &[&bytes]);
        bytes.extend_from_slice(&certificate.digest);
        assert_eq!(
            ProcedureCertificate::decode(&bytes).unwrap_err().exit,
            exit::VERIFICATION
        );
    };
    for omit_party in [true, false] {
        let mut damaged = decoded.clone();
        if omit_party {
            // Removing the Party population must fail even with a fresh
            // outer checksum. The omitted population cannot be inferred.
            damaged.extended_inputs.remove(1);
        } else {
            // A different certified population from the same snapshot is
            // not a substitute for the required Party input either.
            damaged.extended_inputs[1] = damaged.extended_inputs[0].clone();
        }
        rehash(&mut damaged);
        let refusal = f
            .book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &damaged)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::VERIFICATION);
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    }
    let mut damaged = decoded.clone();
    let last = damaged.output.len() - 1;
    damaged.output[last] ^= 1;
    rehash(&mut damaged);
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &damaged)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
    let mut forged = decoded.clone();
    forged.report.findings[0].statistic.value = 12_001;
    // Every checksum and the output encoding agree; only recomputing the
    // ratio from the certified native inputs exposes this false result.
    super::offline::reseal(&mut forged);
    let refusal = f
        .book
        .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &forged)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert!(refusal.message.contains("does not replay exactly"));
    assert_eq!(
        f.book
            .certify_procedure(&cx, PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::SAFETY
    );
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["produce"]), &decoded)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::SAFETY
    );
    request.parameters = request
        .parameters
        .set("window_days", i128::from(u32::MAX))
        .unwrap();
    let wide = f.certify(&request);
    assert!(wide.report.findings.is_empty());
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &wide.certificate)
            .unwrap()
            .unwrap(),
        wide.report
    );
    assert_eq!(
        f.head(),
        before,
        "read, certification and refusals never publish"
    );

    post(
        &mut f,
        9,
        "3000",
        "1000",
        10_000,
        "MOTIF-B",
        b"motif-backdated",
    );
    let after = f.head();
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap(),
        certified.report
    );
    let status = f
        .book
        .procedure_certificate_status(&cx, PRINCIPAL, &cap(&["read"]), &decoded)
        .unwrap()
        .unwrap();
    assert!(matches!(
        status,
        ProcedureCertificateStatus::Changed { checked_at, current }
            if checked_at == after
                && current.findings.len() == 1
                && current.findings[0].statistic.value == 14_000
                && current.findings[0].statistic.population == 4
    ));
    assert_eq!(f.head(), after);
}

#[test]
fn all_additional_procedures_round_trip_with_complete_native_populations() {
    let mut f = Fixture::new(91);
    // The role-selected procedures (fa-kxc4) need their roles held.
    f.assign_procedure_roles();
    let (source, _) = f.post(1, "3000", "1000", 100, true);
    f.post(2, "1000", "1010", 80, false);
    f.post(3, "1010", "1020", 60, false);
    f.post(4, "1020", "6000", 10, false);
    let before = f.head();
    assert_eq!(EXTENDED_CERTIFIABLE_PROCEDURES.len(), 44);
    let mut saved = Vec::new();
    for &(id, version) in EXTENDED_CERTIFIABLE_PROCEDURES {
        assert!(!supported(id, version), "the legacy closure is unchanged");
        let c = f.certify(&f.request(id, source)).certificate;
        assert_eq!(c.format(), EXTENDED_PROCEDURE_CERTIFICATE_FORMAT);
        assert_eq!(c.supplemental_inputs().len(), 6);
        assert_eq!(c.report.version, version);
        let bytes = c.canonical_bytes().unwrap();
        assert_eq!(ProcedureCertificate::decode(&bytes).unwrap(), c);
        assert_eq!(
            ReportArtifact::decode(&bytes).unwrap().family(),
            ReportArtifactFamily::Procedure
        );
        assert_eq!(f.head(), before, "certification cannot publish {id}");
        saved.push(c);
    }
    f.post(1, "3000", "1000", 300, false);
    review(&mut f);
    let after = f.head();
    for c in saved {
        let replayed = f
            .book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .unwrap();
        assert_eq!(
            replayed, c.report,
            "{} is pinned before later evidence",
            c.report.procedure
        );
        assert_eq!(f.head(), after);
    }
}

// Construct framing cases over real native captures, not receipts of an old
// algorithm execution. Repair every public digest so an obsolete checksum
// cannot stand in for the registry/version and closure checks below.
fn historical_frame(
    mut captured: ProcedureCertificate,
    id: &str,
    version: u16,
) -> ProcedureCertificate {
    let report = &mut captured.report;
    assert!(report.findings.is_empty());
    report.procedure = id.into();
    report.version = version;
    let mut parameters = Writer::new();
    parameters.str(id).u16(version);
    parameters.list(&report.parameters, |w, (key, value)| {
        w.str(key).i128(*value);
    });
    parameters.list(&report.inputs, |w, (key, value)| {
        w.str(key).str(value);
    });
    report.parameters_digest = raw_digest(
        fa_lantern::PARAMETERS_DIGEST_DOMAIN,
        &parameters.finish().unwrap(),
    );
    let mut findings = Writer::new();
    findings
        .str(id)
        .u16(version)
        .fixed(&report.parameters_digest)
        .fixed(&report.inputs_digest);
    report.coordinate.encode(&mut findings);
    findings.list(&report.findings, |w, finding| finding.encode(w));
    report.findings_digest = raw_digest(
        fa_lantern::FINDINGS_DIGEST_DOMAIN,
        &findings.finish().unwrap(),
    );
    let policy = fa_policy::Steward::embedded().unwrap().policy_oid;
    report.decision_card = fa_policy::decide_lantern_threshold(
        Some(policy),
        policy,
        id,
        version,
        &report.parameters,
        report.population,
    );
    report.decision_card_digest = report.decision_card.digest().unwrap();
    captured.output = encode_run(report).unwrap();
    captured.registry = [0; 32];
    assert_ne!(captured.registry, registry_digest().unwrap());
    captured
}

#[test]
fn historical_extended_versions_keep_their_complete_native_closure() {
    let mut f = Fixture::new(117);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let prototype = f
        .certify(&f.request("recon.assertion_drift", source))
        .certificate;
    let before = f.head();
    // Historical identities from emitted catalogs, including the two removed
    // names. This is a format-compatibility inventory, not algorithm aliases.
    let histories: &[(&str, &[u16])] = &[
        ("aging.inventory", &[1, 2]),
        ("benford.first_two_digits", &[1]),
        ("benford.second_digit", &[1]),
        ("completeness.unrecorded_liabilities", &[1]),
        ("confirm.coverage", &[1]),
        ("damages.attested_baseline", &[1]),
        ("damages.but_for", &[1]),
        ("distribution.pro_rata", &[1, 2, 3]),
        ("distribution.rising_tide", &[1, 2, 3]),
        ("events.subsequent", &[1, 2]),
        ("expense.capitalization", &[1]),
        ("graph.circular_flows", &[1]),
        ("graph.communities", &[1, 2]),
        ("graph.layering", &[1]),
        ("graph.party_circular_flows", &[1]),
        ("graph.party_layering", &[1]),
        ("graph.related_party_exposure", &[1]),
        ("graph.shell_signature", &[1]),
        ("jet.intercompany_unmatched", &[1]),
        ("jet.suspense_aging", &[1, 2]),
        ("jet.unusual_accounts", &[1]),
        ("lookback.preferences", &[1, 2]),
        ("payroll.ghost", &[1]),
        ("ponzi.net_investment", &[1, 2, 3, 4]),
        ("recon.assertion_drift", &[1]),
        ("recon.attested_register_compare", &[1]),
        ("recon.book_to_book", &[1]),
        ("recon.intercompany", &[1]),
        ("recon.lapping", &[1]),
        ("reversal.patterns", &[1]),
        ("solvency.balance_sheet_test", &[1, 2]),
        ("solvency.cash_flow_test", &[1, 2, 3, 4]),
    ];
    assert_eq!(
        histories
            .iter()
            .map(|(_, versions)| versions.len())
            .sum::<usize>(),
        48
    );
    for &(id, versions) in histories {
        for &version in versions {
            assert!(!extended::supported(id, version));
            let mut saved = historical_frame(prototype.clone(), id, version);
            let body = saved
                .body()
                .unwrap_or_else(|error| panic!("{id}@{version}: {error}"));
            saved.digest = domain_digest(CERTIFICATE_DOMAIN, &[&body]);
            let bytes = saved.canonical_bytes().unwrap();
            let decoded = ProcedureCertificate::decode(&bytes).unwrap();
            assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
            assert_eq!(decoded.supplemental_inputs().len(), 6);
            assert_eq!(
                ReportArtifact::decode(&bytes).unwrap().family(),
                ReportArtifactFamily::Procedure
            );
            let unavailable = f
                .book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
                .unwrap()
                .unwrap_err();
            assert_eq!(
                unavailable.code,
                crate::certificate::code::CERTIFICATE_REGISTRY_UNAVAILABLE,
                "{id}@{version}"
            );
            assert_eq!(unavailable.exit, exit::ENVIRONMENT);

            // Even a repaired envelope naming today's registry cannot make
            // its old identity dispatch a current algorithm.
            saved.registry = registry_digest().unwrap();
            saved.digest = domain_digest(CERTIFICATE_DOMAIN, &[&saved.body().unwrap()]);
            let rebound = ProcedureCertificate::decode(&saved.canonical_bytes().unwrap()).unwrap();
            let mismatch = f
                .book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &rebound)
                .unwrap()
                .unwrap_err();
            assert_eq!(
                mismatch.exit,
                exit::VERIFICATION,
                "{id}@{version}: {mismatch}"
            );
            let mut missing = saved.clone();
            missing.extended_inputs.pop();
            assert!(
                missing.body().is_err(),
                "{id}@{version} needs every native witness"
            );
            let mut swapped = saved;
            swapped.extended_inputs.swap(0, 1);
            assert!(
                swapped.body().is_err(),
                "{id}@{version} needs the exact native populations"
            );
            assert_eq!(f.head(), before, "{id}@{version} must not publish");
        }
    }
    for (id, version) in [
        ("future.unaudited", 1),
        ("aging.inventory", 0),
        ("aging.inventory", 4),
        ("damages.but_for", 2),
        ("recon.book_to_book", 2),
        ("graph.circular_flows", 3),
        ("graph.communities", 4),
        ("graph.party_circular_flows", 3),
        ("graph.round_trips", 1),
        ("reversal.patterns", 3),
        ("jet.suspense_aging", 4),
    ] {
        assert!(
            !extended::has_retained_closure(id, version),
            "{id}@{version}"
        );
        if version != 0 {
            assert!(
                historical_frame(prototype.clone(), id, version)
                    .body()
                    .is_err()
            );
        }
    }
}

#[test]
fn original_benford_version_keeps_its_original_closure_and_cannot_replay_as_current() {
    let mut f = Fixture::new(118);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let prototype = f
        .certify(&f.request("cutoff.period_boundary", source))
        .certificate;
    let before = f.head();
    let mut saved = historical_frame(prototype, "benford.first_digit", 1);
    saved.digest = domain_digest(CERTIFICATE_DOMAIN, &[&saved.body().unwrap()]);
    let bytes = saved.canonical_bytes().unwrap();
    let decoded = ProcedureCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    assert!(decoded.supplemental_inputs().is_empty());
    let unavailable = f
        .book
        .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        unavailable.code,
        crate::certificate::code::CERTIFICATE_REGISTRY_UNAVAILABLE
    );
    saved.registry = registry_digest().unwrap();
    saved.digest = domain_digest(CERTIFICATE_DOMAIN, &[&saved.body().unwrap()]);
    let rebound = ProcedureCertificate::decode(&saved.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &rebound)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
    saved.extended_inputs = f
        .certify(&f.request("benford.second_digit", source))
        .certificate
        .extended_inputs;
    assert!(
        saved.body().is_err(),
        "an original-format procedure never acquires the extended closure"
    );
    assert_eq!(f.head(), before);
}

/// fa-kxc4: a procedure that selects its population by account role is
/// refused while no account holds the role, never certified over an empty
/// population (planted), and certifies and replays once the role is held.
#[test]
fn role_selected_procedures_refuse_without_their_role_and_certify_with_it() {
    let mut f = Fixture::new(95);
    let (source, _) = f.post(1, "3000", "1020", 100, false);
    let before = f.head();
    let selected = [
        ("jet.suspense_aging", "suspense"),
        ("jet.intercompany_unmatched", "intercompany"),
        ("recon.intercompany", "intercompany"),
        ("recon.lapping", "receivable or payable"),
        ("expense.capitalization", "fixed_asset"),
        ("aging.inventory", "inventory"),
        ("payroll.ghost", "payroll"),
        ("confirm.coverage", "cash or receivable"),
        ("solvency.cash_flow_test", "cash"),
        ("graph.ponzi_motif", "cash"),
        ("lookback.preferences", "cash"),
        ("ponzi.net_investment", "cash"),
        ("distribution.rising_tide", "cash"),
        ("distribution.pro_rata", "cash"),
    ];
    for (id, role) in selected {
        let refused = f.book.certify_procedure(
            &f.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &f.request(id, source),
        );
        assert!(
            matches!(
                &refused,
                Err(BookError::Lantern(fa_lantern::LanternError::RoleUnassigned { procedure, role: r }))
                    if procedure == id && r == role
            ),
            "{id}: {refused:?}"
        );
        if let Err(error) = &refused {
            assert_eq!(error.exit(), fa_journal::exit::REFUSAL, "{id}");
        }
    }
    assert_eq!(f.head(), before, "a refused run writes nothing");
    f.assign_procedure_roles();
    for (id, _) in selected {
        let certified = f.certify(&f.request(id, source));
        // fa-6l8g moved the party-attributing procedures to version 3;
        // full-u32 lookback arithmetic moved preferences to version 4, and
        // fa-yugf.83 the investor-population ones on to version 4. As-of
        // netting moved aging.inventory to version 3; cash-overdraft netting
        // and a shared cash/liability cutoff moved the cash-flow screen to 5.
        let version = match id {
            "graph.ponzi_motif" => 1,
            "lookback.preferences" | "recon.lapping" => 4,
            "aging.inventory" | "jet.suspense_aging" => 3,
            "solvency.cash_flow_test" => 5,
            "ponzi.net_investment" => 5,
            "distribution.rising_tide" | "distribution.pro_rata" => 4,
            _ => 2,
        };
        assert_eq!(certified.report.version, version, "{id}");
        assert_eq!(
            f.book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report,
            "{id}"
        );
    }
}

#[test]
fn ponzi_v5_certificates_refuse_the_old_cash_only_version_instead_of_reinterpreting_it() {
    let mut f = Fixture::new(96);
    f.assign_procedure_roles();
    let (source, _) = f.post(1, "3000", "1000", 100, true);
    let before = f.head();
    let certified = f.certify(&f.request("ponzi.net_investment", source));
    assert_eq!(certified.report.version, 5);
    assert_eq!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report
    );
    let mut old_method = certified.certificate;
    old_method.report.version = 4;
    let refusal = old_method.request().unwrap_err();
    assert!(
        refusal
            .message
            .contains("procedure identity, claim, evidence or full parameter set has changed")
    );
    assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
    assert_eq!(f.head(), before, "method/version refusal cannot publish");
}

#[test]
fn assertion_drift_v2_certifies_gross_periods_and_replays_before_later_changes() {
    let mut f = Fixture::new(97);
    let (source, _) = f.post(31, "3000", "1000", 5_000, false);
    let cx = f.cx();
    let january_key = fa_registers::EntityCellKey {
        account: f.id("1000"),
        unit_id: f.unit.0,
        period: "FY2026-P01".into(),
        entity: None,
    };
    let january = f
        .book
        .evaluate_register_equals(&cx, &january_key, None)
        .unwrap();
    assert_eq!(january.amount.mantissa, 5_000);
    let january_attestation = f
        .runtime
        .block_on(f.book.record_register_equals(
            &cx,
            &cap(&["reconcile"]),
            &january,
            f.evidence.iter().map(|e| e.document_oid).collect(),
        ))
        .unwrap()
        .unwrap();
    let before_reversal = f.certify(&f.request("recon.assertion_drift", source));
    assert_eq!(before_reversal.report.version, 2);
    assert!(before_reversal.report.findings.is_empty());

    f.runtime
        .block_on(f.book.transition_period(
            &cx,
            "FY2026-P02",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"open-assertion-february",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let (original, _) = f.book.read_entry(&cx, source).unwrap().unwrap();
    let target = fa_model::EntryRef {
        vid: source,
        entry_digest: original.entry_digest,
    };
    let mut reversal = original.proposal;
    reversal.class = EntryClass::REVERSAL;
    reversal.effective_date = DateDay::from_ymd(2026, 2, 1).unwrap();
    reversal.idempotency_key = b"reverse-asserted-january-posting".to_vec();
    reversal.description = f
        .book
        .seal_text(&cx, "reverse January in February")
        .unwrap();
    reversal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    f.runtime
        .block_on(f.book.post(
            &cx,
            PostRequest {
                proposal: reversal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post", "reconcile"]),
            },
        ))
        .unwrap()
        .unwrap();
    let february_key = fa_registers::EntityCellKey {
        period: "FY2026-P02".into(),
        ..january_key.clone()
    };
    let february = f
        .book
        .evaluate_register_equals(&cx, &february_key, None)
        .unwrap();
    assert_eq!(february.amount.mantissa, -5_000);
    f.runtime
        .block_on(f.book.record_register_equals(
            &cx,
            &cap(&["reconcile"]),
            &february,
            f.evidence.iter().map(|e| e.document_oid).collect(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        f.book
            .evaluate_register_equals(&cx, &january_key, None)
            .unwrap()
            .amount
            .mantissa,
        5_000,
        "the accounting register keeps the January posting"
    );
    let mut request = f.request("recon.assertion_drift", source);
    request.effective_through = None;
    let after_reversal = f.certify(&request);
    assert!(
        after_reversal.report.findings.is_empty(),
        "both native attestations agree with their own period: {:?}",
        after_reversal.report.findings
    );

    // A new backdated posting really changes January's attested activity.
    // It must be reported even though that period also has a reversed entry.
    let (backdated, _) = f.post(15, "3000", "1000", 700, false);
    request.known_at = Some(f.head());
    let drifted = f.certify(&request);
    assert_eq!(drifted.report.findings.len(), 1);
    let finding = &drifted.report.findings[0];
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.statistic.value, 700);
    assert_eq!(
        finding.cites,
        vec![
            Cite::Attestation(january_attestation.vid),
            Cite::Account(f.id("1000")),
            Cite::Period("FY2026-P01".into()),
            Cite::Entry(backdated),
        ]
    );
    let head = f.head();
    for certified in [before_reversal, after_reversal, drifted] {
        let bytes = certified.certificate.canonical_bytes().unwrap();
        let decoded = ProcedureCertificate::decode(&bytes).unwrap();
        assert_eq!(decoded.report.version, 2);
        assert_eq!(decoded.supplemental_inputs().len(), 6);
        let replayed = f
            .book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap();
        assert_eq!(replayed, certified.report);
        assert_eq!(encode_run(&replayed).unwrap(), decoded.output);
    }
    assert_eq!(f.head(), head, "certification and replay do not publish");
}

#[test]
fn assertion_drift_uses_declared_entity_cells_including_implicit_and_none() {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let mut f = Fixture::with_entities(
        99,
        vec![fa_journal::genesis::LegalEntitySpec {
            code: "ALPHA".into(),
            name: "Declared balancing entity".into(),
            functional_unit: usd,
        }],
    );
    // Both legs are untagged, which the native register assigns to ALPHA.
    let (source, _) = f.post(1, "3000", "1000", 1_000, false);
    let cx = f.cx();
    f.runtime
        .block_on(f.book.create_legal_entity(
            &cx,
            &fa_model::LegalEntityFullSpec {
                code: "INFORMATIONAL".into(),
                name: "REA relationship endpoint, not a balancing entity".into(),
                jurisdiction: "US".into(),
                functional_unit: usd,
                formed: None,
                dissolved: None,
                external_ids: Vec::new(),
            },
            PRINCIPAL,
            day(1),
            b"informational-entity",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    let mut alpha_attestation = None;
    for (entity, expected) in [(Some("ALPHA".to_string()), 1_000), (None, 0)] {
        let key = fa_registers::EntityCellKey {
            account: f.id("1000"),
            unit_id: usd.0,
            period: "FY2026-P01".into(),
            entity,
        };
        let claim = f.book.evaluate_register_equals(&cx, &key, None).unwrap();
        assert_eq!(claim.amount.mantissa, expected);
        let attested = f
            .runtime
            .block_on(f.book.record_register_equals(
                &cx,
                &cap(&["reconcile"]),
                &claim,
                f.evidence.iter().map(|e| e.document_oid).collect(),
            ))
            .unwrap()
            .unwrap();
        if key.entity.is_some() {
            alpha_attestation = Some(attested.vid);
        }
    }
    let snapshot = Snapshot::read(&f.book.db, &cx.query(), f.book.context(), None, None).unwrap();
    assert_eq!(snapshot.declared_entities.len(), 1);
    assert!(snapshot.declared_entities.contains_key("ALPHA"));
    assert_eq!(snapshot.rea.legal_entities.len(), 2);
    let certified = f.certify(&f.request("recon.assertion_drift", source));
    assert!(
        certified.report.findings.is_empty(),
        "{:?}",
        certified.report.findings
    );

    let (later, _) = f.post(2, "3000", "1000", 125, false);
    let changed = f.certify(&f.request("recon.assertion_drift", source));
    assert_eq!(changed.report.findings.len(), 1);
    assert_eq!(changed.report.findings[0].statistic.value, 125);
    assert_eq!(
        changed.report.findings[0].cites,
        vec![
            Cite::Attestation(alpha_attestation.unwrap()),
            Cite::Account(f.id("1000")),
            Cite::Period("FY2026-P01".into()),
            Cite::Entry(later),
        ]
    );
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report,
        "later implicit activity cannot change the earlier certified result"
    );
}

#[test]
fn assertion_drift_v1_decodes_but_cannot_dispatch_the_v2_fold() {
    let mut f = Fixture::new(98);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let mut saved = f
        .certify(&f.request("recon.assertion_drift", source))
        .certificate;
    assert!(saved.report.findings.is_empty());
    assert!(!extended::supported("recon.assertion_drift", 1));
    assert!(extended::has_retained_closure("recon.assertion_drift", 1));

    // Build a version-1 computation over an empty attestation population,
    // where both historical and current calculations produce no findings.
    // This is a constructed decoder/dispatch fixture, not an old run receipt.
    // Recompute every public digest so refusal cannot rely on a stale checksum.
    saved.report.version = 1;
    let report = &mut saved.report;
    let mut parameters = Writer::new();
    parameters.str(&report.procedure).u16(report.version);
    parameters.list(&report.parameters, |w, (key, value)| {
        w.str(key).i128(*value);
    });
    parameters.list(&report.inputs, |w, (key, value)| {
        w.str(key).str(value);
    });
    report.parameters_digest = raw_digest(
        fa_lantern::PARAMETERS_DIGEST_DOMAIN,
        &parameters.finish().unwrap(),
    );
    let mut findings = Writer::new();
    findings
        .str(&report.procedure)
        .u16(report.version)
        .fixed(&report.parameters_digest)
        .fixed(&report.inputs_digest);
    report.coordinate.encode(&mut findings);
    findings.list(&report.findings, |w, finding| finding.encode(w));
    report.findings_digest = raw_digest(
        fa_lantern::FINDINGS_DIGEST_DOMAIN,
        &findings.finish().unwrap(),
    );
    let policy = fa_policy::Steward::embedded().unwrap().policy_oid;
    report.decision_card = fa_policy::decide_lantern_threshold(
        Some(policy),
        policy,
        &report.procedure,
        report.version,
        &report.parameters,
        report.population,
    );
    report.decision_card_digest = report.decision_card.digest().unwrap();
    saved.output = encode_run(report).unwrap();
    saved.registry = [0; 32];
    assert_ne!(saved.registry, registry_digest().unwrap());
    saved.digest = domain_digest(CERTIFICATE_DOMAIN, &[&saved.body().unwrap()]);
    let bytes = saved.canonical_bytes().unwrap();
    let decoded = ProcedureCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        ReportArtifact::decode(&bytes).unwrap().family(),
        ReportArtifactFamily::Procedure
    );
    let head = f.head();
    let unavailable = f
        .book
        .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        unavailable.code,
        crate::certificate::code::CERTIFICATE_REGISTRY_UNAVAILABLE
    );
    assert_eq!(unavailable.exit, exit::ENVIRONMENT);

    // Even deliberately rebinding the envelope to today's registry cannot
    // cause the old version to run the corrected algorithm under a v1 label.
    saved.registry = registry_digest().unwrap();
    saved.digest = domain_digest(CERTIFICATE_DOMAIN, &[&saved.body().unwrap()]);
    let rebound = ProcedureCertificate::decode(&saved.canonical_bytes().unwrap()).unwrap();
    let mismatch = f
        .book
        .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &rebound)
        .unwrap()
        .unwrap_err();
    assert_eq!(mismatch.exit, exit::VERIFICATION);
    assert!(
        mismatch
            .message
            .contains("procedure identity, claim, evidence or full parameter set has changed")
    );
    assert_eq!(f.head(), head);

    saved.extended_inputs.pop();
    assert!(
        saved.body().is_err(),
        "legacy decoding still requires every attestation/REA witness"
    );
}

#[test]
fn signed_solvency_certifies_its_method_and_refuses_the_old_version() {
    let mut f = Fixture::new(94);
    let (source, _) = f.post(1, "1010", "6000", 20, false);
    let before = f.head();
    let certified = f.certify(&f.request("solvency.balance_sheet_test", source));
    assert_eq!(certified.report.version, 3);
    assert_eq!(certified.report.findings.len(), 1);
    assert_eq!(certified.report.findings[0].statistic.value, 20);
    let certificate =
        ProcedureCertificate::decode(&certified.certificate.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certificate)
            .unwrap()
            .unwrap(),
        certified.report
    );
    for old in [1, 2] {
        let mut old_method = certificate.clone();
        old_method.report.version = old;
        let refusal = old_method.request().unwrap_err();
        assert!(
            refusal
                .message
                .contains("procedure identity, claim, evidence or full parameter set has changed"),
            "version {old}: {}",
            refusal.message
        );
        assert_eq!(refusal.exit, exit::VERIFICATION);
    }
    assert_eq!(
        f.head(),
        before,
        "certification, replay and refusal never publish"
    );
}

#[test]
fn independent_attestations_change_results_but_not_the_saved_historical_run() {
    let mut f = Fixture::new(92);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let key = fa_registers::EntityCellKey {
        account: f.id("1000"),
        unit_id: f.unit.0,
        period: "FY2026-P01".into(),
        entity: None,
    };
    let cx = f.cx();
    let claim = f.book.evaluate_register_equals(&cx, &key, None).unwrap();
    let evidence = f.evidence.iter().map(|e| e.document_oid).collect();
    let attested = f
        .runtime
        .block_on(
            f.book
                .record_register_equals(&cx, &cap(&["reconcile"]), &claim, evidence),
        )
        .unwrap()
        .unwrap();
    let c = f
        .certify(&f.request("recon.attested_register_compare", source))
        .certificate;
    assert!(
        c.report.findings.is_empty(),
        "the original declared balance matches"
    );
    f.post(1, "3000", "1000", 70, false);
    let current = f.certify(&f.request("recon.attested_register_compare", source));
    assert!(
        current
            .report
            .findings
            .iter()
            .any(|f| f.statistic.name == "attested_register_discrepancy" && f.statistic.value == 70)
    );
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .unwrap(),
        c.report
    );
    assert!(f.book.db.vertex(attested.vid).unwrap().is_some());
    // Full v2 certificates also use existing retention and finding records.
    let bytes = current.certificate.canonical_bytes().unwrap();
    let kept = f
        .runtime
        .block_on(f.book.retain_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &bytes,
            Some(current.certificate.digest()),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(kept.recorded_at, f.head());
    let run = f
        .runtime
        .block_on(f.book.record_findings(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            current.certificate.digest(),
        ))
        .unwrap()
        .unwrap();
    assert!(!run.finding_ids.is_empty());
    assert_eq!(run.report, current.report);
}

#[test]
fn procedure_status_detects_new_attestation_without_new_postings() {
    let mut f = Fixture::new(106);
    f.assign_role("1000", "cash");
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let certified = f.certify(&f.request("confirm.coverage", source));
    assert_eq!(certified.report.findings.len(), 1);
    let reviewed = review(&mut f);
    let cx = f.cx();
    let head = f.head();
    let status = f
        .book
        .procedure_certificate_status(&cx, PRINCIPAL, &cap(&["read"]), &certified.certificate)
        .unwrap()
        .unwrap();
    let ProcedureCertificateStatus::Changed {
        checked_at,
        current,
    } = status
    else {
        panic!("the new independent review changes confirmation coverage");
    };
    assert_eq!(checked_at, head);
    assert_eq!(current.population, certified.report.population);
    assert_eq!(current.decision_card, certified.report.decision_card);
    assert!(current.findings.is_empty());
    assert!(f.book.db.vertex(reviewed.vid).unwrap().is_some());
    assert_eq!(f.head(), head, "status must not journal its recomputation");
}

#[test]
fn nonempty_party_identity_graph_survives_later_population_changes_and_reopen() {
    let mut f = Fixture::new(93);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let a = party(&mut f, "VENDOR-A", "AB-123");
    let b = party(&mut f, "VENDOR-B", "ab 123");
    let c = f
        .certify(&f.request("graph.identity_resolution", source))
        .certificate;
    assert_eq!(c.report.findings.len(), 1);
    assert!(c.report.findings[0].cites.contains(&Cite::Principal(a)));
    assert!(c.report.findings[0].cites.contains(&Cite::Principal(b)));
    assert_eq!(
        f.book
            .procedure_certificate_status(&f.cx(), PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .unwrap(),
        ProcedureCertificateStatus::Current {
            checked_at: f.head()
        }
    );
    let bytes = c.canonical_bytes().unwrap();
    party(&mut f, "VENDOR-C", "ab123");
    let new = f.certify(&f.request("graph.identity_resolution", source));
    assert_ne!(new.report.findings_digest, c.report.findings_digest);
    assert_eq!(
        f.book
            .procedure_certificate_status(&f.cx(), PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .unwrap(),
        ProcedureCertificateStatus::Changed {
            checked_at: f.head(),
            current: Box::new(new.report)
        }
    );
    let cx = f.cx();
    let vfs = f.vfs.clone();
    drop(f.book);
    let reopened = f
        .runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            Path::new("procedures"),
            BookKeys::for_development(93),
            Entropy::deterministic(999),
        ))
        .unwrap();
    let replayed =
        reopened.replay_report_artifact(&cx, PRINCIPAL, &cap(&["read"]), &bytes, Some(c.digest()));
    assert_eq!(replayed.unwrap().unwrap().output, c.output);
}

#[test]
fn missing_reordered_rebound_and_cross_snapshot_witnesses_cannot_be_rehashed_away() {
    let mut f = Fixture::new(94);
    // confirm.coverage reads the cash and receivable roles (fa-kxc4).
    f.assign_procedure_roles();
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let c = f
        .certify(&f.request("confirm.coverage", source))
        .certificate;
    let mut missing = c.clone();
    missing.extended_inputs.pop();
    assert!(missing.body().is_err());
    let mut reordered = c.clone();
    reordered.extended_inputs.swap(0, 1);
    assert!(reordered.body().is_err());
    let mut statement = c.clone();
    statement.extended_inputs[0] = c.approvals.clone();
    assert!(statement.body().is_err());
    review(&mut f);
    let later = f
        .certify(&f.request("confirm.coverage", source))
        .certificate;
    let mut mixed = c.clone();
    mixed.extended_inputs[0] = later.extended_inputs[0].clone();
    assert!(mixed.body().is_err());
    let bytes = c.canonical_bytes().unwrap();
    for end in [0, 4, 32, bytes.len() / 2, bytes.len() - 1] {
        assert!(ProcedureCertificate::decode(&bytes[..end]).is_err());
    }
    let mut too_new = bytes.clone();
    too_new[4 + EXTENDED_PROCEDURE_CERTIFICATE_FORMAT.len() - 1] = b'3';
    assert!(ProcedureCertificate::decode(&too_new).is_err());
    let mut downgrade = bytes;
    downgrade[4 + EXTENDED_PROCEDURE_CERTIFICATE_FORMAT.len() - 1] = b'1';
    assert!(ProcedureCertificate::decode(&downgrade).is_err());
}

#[test]
fn attestation_rewrites_and_restoration_refuse_replay_and_fresh_certification() {
    let mut f = Fixture::new(95);
    // confirm.coverage reads the cash and receivable roles (fa-kxc4).
    f.assign_procedure_roles();
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let reviewed = review(&mut f);
    let c = f
        .certify(&f.request("confirm.coverage", source))
        .certificate;
    let old = f.book.db.vertex(reviewed.vid).unwrap().unwrap();
    let original = fa_journal::rows::prop(&old, property::FA_DIGEST)
        .unwrap()
        .clone();
    let cx = f.cx();
    for value in [CanonicalScalar::bytes(vec![0; 32]).unwrap(), original] {
        let mut batch = fgdb::WriteBatch::new(fa_model::symbols::relation::SUPERSEDES);
        batch.set_vertex_property(reviewed.vid, property::FA_DIGEST, Some(value));
        f.runtime
            .block_on(f.book.db.write(&cx.commit(), batch))
            .unwrap();
        let r = f
            .book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .unwrap_err();
        assert_eq!(r.exit, exit::VERIFICATION);
        assert!(r.message.contains("attestation"));
        let fresh = f
            .book
            .certify_procedure(
                &cx,
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &f.request("confirm.coverage", source),
            )
            .unwrap()
            .unwrap_err();
        assert!(fresh.message.contains("attestation"));
    }
}

#[test]
fn a_discrepancy_beyond_signed_statistic_capacity_has_no_certificate_or_wrapped_finding() {
    let mut f = Fixture::new(96);
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let cx = f.cx();
    let key = fa_registers::EntityCellKey {
        account: f.id("1000"),
        unit_id: f.unit.0,
        period: "FY2026-P01".into(),
        entity: None,
    };
    let claim = f.book.evaluate_register_equals(&cx, &key, None).unwrap();
    assert_eq!(claim.amount.mantissa, 1);
    f.runtime
        .block_on(f.book.record_register_equals(
            &cx,
            &cap(&["reconcile"]),
            &claim,
            f.evidence.iter().map(|e| e.document_oid).collect(),
        ))
        .unwrap()
        .unwrap();
    f.post(1, "1000", "6000", i128::MAX, false);
    let exact = f.certify(&f.request("recon.attested_register_compare", source));
    assert_eq!(exact.report.findings[0].statistic.value, i128::MAX);
    let head = f.head();
    let legs = vec![
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(f.unit, 1)),
        LegPayload::simple(Side::Debit, f.id("3000"), Amount::new(f.unit, 1)),
    ];
    let over_cap = EntryPayload {
        schema_minor: 0,
        book_id: f.book.context().book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(1),
        document_date: None,
        description: f.book.seal_text(&cx, "Over-cap credit").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"over-cap-credit".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: f.evidence.clone(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
        extensions: Vec::new(),
    };
    let refusal = f
        .runtime
        .block_on(f.book.post(
            &cx,
            PostRequest {
                proposal: over_cap,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198", "{refusal}");
    assert_eq!(f.head(), head);
    let head = f.head();
    let rows = f.book.db.vertices().unwrap();
    // This extra balanced credit would make the cash cell's gross credits
    // MAX+1. The current publication law must stop it before an invalid
    // journal can reach certification. The unchanged Lantern arithmetic
    // tests retain direct full-width discrepancy/refusal coverage.
    let (source_entry, _) = f.book.read_entry(&cx, source).unwrap().unwrap();
    let mut over_capacity = source_entry.proposal;
    over_capacity.idempotency_key = b"over-capacity-certificate-source".to_vec();
    for leg in &mut over_capacity.legs {
        leg.side = leg.side.flipped();
    }
    over_capacity.unit_totals = EntryPayload::fold_unit_totals(&over_capacity.legs).unwrap();
    let refusal = f
        .runtime
        .block_on(f.book.post(
            &cx,
            PostRequest {
                proposal: over_capacity,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3));
    assert_eq!(f.head(), head);
    assert_eq!(f.book.db.vertices().unwrap(), rows);
    assert_eq!(
        f.certify(&f.request("recon.attested_register_compare", source))
            .report,
        exact.report
    );
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &exact.certificate)
            .unwrap()
            .unwrap(),
        exact.report
    );
    // The source-capacity refusal above must not replace the independent
    // statistic-width boundary. A wider attestation keeps the journal's
    // monetary cells representable while the discrepancy exceeds i128.
    let mut wider_claim = fa_registers::assertion::claim_of(&claim);
    wider_claim.mantissa = 2;
    let evidence: Vec<_> = f.evidence.iter().map(|e| e.document_oid).collect();
    f.runtime
        .block_on(fa_journal::attestation::commit_register_equals(
            &mut f.book.db,
            &cx,
            &f.book.context,
            &Capability::embedded(VId(74), &["reconcile"]).unwrap(),
            None,
            wider_claim,
            evidence,
        ))
        .unwrap()
        .unwrap();
    let head = f.head();
    let rows = f.book.db.vertices().unwrap();
    assert!(matches!(
        f.book.certify_procedure(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &f.request("recon.attested_register_compare", source)
        ),
        Err(crate::BookError::Lantern(
            fa_lantern::LanternError::Overflow("attested_register discrepancy magnitude")
        ))
    ));
    assert_eq!(f.head(), head);
    assert_eq!(f.book.db.vertices().unwrap(), rows);
    assert_eq!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &exact.certificate)
            .unwrap()
            .unwrap(),
        exact.report
    );
}

#[test]
fn extended_input_reads_never_inherit_attester_or_saved_producer_authority() {
    let mut f = Fixture::new(97);
    // confirm.coverage reads the cash and receivable roles (fa-kxc4).
    f.assign_procedure_roles();
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let attested = review(&mut f);
    let request = f.request("confirm.coverage", source);
    let c = f.certify(&request).certificate;
    assert_eq!(c.supplemental_inputs().len(), 6);
    let before = f.head();
    let bytes = c.canonical_bytes().unwrap();
    for reader in [
        cap(&["post"]),
        cap(&["approve"]),
        cap(&["produce"]),
        cap(&["read"]).expiring_at(before),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(),
    ] {
        let denial = f
            .book
            .replay_procedure(&f.cx(), PRINCIPAL, &reader, &c)
            .unwrap()
            .unwrap_err();
        assert_ne!(denial.code, crate::certificate::code::CERTIFICATE_INVALID);
        let denial = f
            .book
            .replay_report_artifact(&f.cx(), PRINCIPAL, &reader, b"not an artifact", None)
            .unwrap()
            .unwrap_err();
        assert_ne!(denial.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(f.head(), before);
    }
    assert!(
        f.book
            .certify_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
    let actual = f
        .book
        .replay_report_artifact(
            &f.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &bytes,
            Some(c.digest()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(actual.output, c.output);
    // An actual approver and intact native attestation do not authorize replay
    // of the whole book. Only the current requesting principal's scope does.
    assert!(
        f.book
            .replay_procedure(
                &f.cx(),
                VId(74),
                &Capability::embedded(VId(74), &["approve"]).unwrap(),
                &c
            )
            .unwrap()
            .is_err()
    );
    assert!(f.book.db.vertex(attested.vid).unwrap().is_some());
    assert_eq!(f.head(), before);
}
