use super::*;

#[test]
fn intercompany_v3_certifies_each_uncovered_leg_without_netting_and_replays_v2() {
    let mut f = Fixture::new(0xe1);
    f.assign_role("1000", "intercompany");
    let (receipt, _) = f.post(1, "3000", "1000", 5_000, false);
    f.post(20, "1000", "1010", 5_000, false);
    let before = f.head();
    let mut request = f.request("recon.intercompany", receipt);
    let current = f.certify(&request);
    assert_eq!(current.report.version, 3);
    assert_eq!(current.report.claim, Claim::Statistical);
    assert_eq!(current.report.findings.len(), 2);
    assert!(current.report.findings.iter().all(|finding| {
        finding.version == 3
            && finding.severity == Severity::Critical
            && finding.statistic.name == "intercompany_undeclared"
            && finding.statistic.value == 5_000
            && finding.statistic.scale == 2
            && finding.statistic.population == 2
            && matches!(finding.cites.as_slice(), [
                Cite::Entry(_), Cite::Leg { .. }, Cite::Account(_), Cite::Period(_),
            ])
    }));
    assert_eq!(current.certificate.format(), EXTENDED_PROCEDURE_CERTIFICATE_FORMAT);
    assert_eq!(current.certificate.supplemental_inputs().len(), extended::COUNT);
    current.certificate.check_offline_profile().unwrap();

    request.version = Some(2);
    request.effective_through = None;
    let prior = f.certify(&request);
    assert_eq!(prior.report.version, 2);
    assert!(prior.report.findings.is_empty(), "retained v2 keeps its aggregate law");
    assert_ne!(prior.certificate.registry, current.certificate.registry);
    assert_eq!(
        prior.certificate.registry,
        intercompany_v2_registry_digest().unwrap(),
    );
    assert_eq!(
        canonical_registry_document(&prior.certificate.registry).unwrap().unwrap(),
        pre_intercompany_registry_document().unwrap(),
    );
    for certified in [&prior, &current] {
        let bytes = certified.certificate.canonical_bytes().unwrap();
        let decoded = ProcedureCertificate::decode(&bytes).unwrap();
        assert_eq!(
            f.book.replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
                .unwrap().unwrap(),
            certified.report,
        );
        assert_eq!(ReportArtifact::decode(&bytes).unwrap().family(), ReportArtifactFamily::Procedure);
    }
    let mut wrong = current.certificate.clone();
    wrong.registry = prior.certificate.registry;
    assert!(wrong.request().is_err(), "v3 never borrows the v2 registry");
    wrong = prior.certificate.clone();
    wrong.registry = current.certificate.registry;
    assert!(wrong.request().is_err(), "v2 never borrows the v3 registry");

    request.version = Some(3);
    request.effective_through = Some(day(10));
    let cutoff = f.certify(&request);
    assert_eq!(cutoff.report.findings.len(), 1);
    assert_eq!(cutoff.report.findings[0].statistic.population, 1);
    assert_eq!(cutoff.report.coordinate.effective_through, Some(day(10)));
    assert_eq!(f.head(), before, "certification and replay publish nothing");

    let current_bundle = export(&mut f, &current);
    let cutoff_bundle = export(&mut f, &cutoff);
    let key = f.book.checkpoint_public_key();
    drop(f);
    independent(&current, &current_bundle, key);
    independent(&cutoff, &cutoff_bundle, key);
    reject_resealed(&current, &current_bundle, key);
    let json = fa_verify::cli::run(
        &[
            "report".into(), "intercompany.fab".into(),
            "--key".into(), key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(), "intercompany.receipt".into(), "--json".into(),
        ],
        &|path| match path {
            "intercompany.fab" => Ok(current_bundle.bundle.bytes.clone()),
            "intercompany.receipt" => Ok(current_bundle.receipt.clone()),
            _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "unexpected input")),
        },
    );
    assert_eq!(json.exit, 0, "{}", json.stdout);
    for expected in [
        "\"statistic\":\"intercompany_undeclared\"",
        "\"value\":\"5000\"",
        "\"scale\":2",
        "\"coverage_scope\":\"native declared pairs and live intercompany role legs\"",
        "\"entity_basis\":\"authenticated literal leg dimensions\"",
        "\"posting_admission\":\"not_judged\"",
    ] {
        assert!(json.stdout.contains(expected), "{expected}: {}", json.stdout);
    }
}

#[test]
fn unrelated_certificates_keep_every_published_procedure_registry_epoch() {
    let mut f = Fixture::new(0xe2);
    let (source, _) = f.post(1, "3000", "1000", 1_000, false);
    let current = f.certify(&f.request("jet.weekend", source)).certificate;
    let documents = [
        pre_intercompany_registry_document().unwrap(),
        pre_kiting_registry_document().unwrap().canonical_bytes(),
        pre_solvency_registry_document().unwrap().canonical_bytes(),
        pre_lapping_metering_registry_document().unwrap().canonical_bytes(),
        pre_lapping_registry_document().unwrap().canonical_bytes(),
        legacy_lookback_registry_document().unwrap(),
        layering_v2_registry_document(false).unwrap(),
        layering_v2_registry_document(true).unwrap(),
        retained_registry_document().unwrap(),
    ];
    for (index, document) in documents.into_iter().enumerate() {
        let mut foundations = vec![published_foundations()[0]];
        if index == 0 {
            foundations.push(PROCEDURE_REGISTRIES[1].1);
        }
        for foundation in foundations {
            let registry = canonical_procedure_closure(&document, foundation).unwrap();
            assert!(registry_versions(&registry).unwrap().is_some());
            assert!(!declares_intercompany_v3(&registry).unwrap());
            assert_eq!(canonical_registry_document(&registry).unwrap(), Some(document.clone()));
            let mut retained = current.clone();
            retained.registry = registry;
            retained.digest = domain_digest(CERTIFICATE_DOMAIN, &[&retained.body().unwrap()]);
            let replayed = f.book.replay_procedure(
                &f.cx(), PRINCIPAL, &cap(&["read"]), &retained,
            ).unwrap().unwrap();
            assert_eq!(replayed, current.report, "unrelated retained epoch {index}");
        }
    }
    for text in [
        pre_intercompany_registry_text().unwrap().to_owned(),
        pre_kiting_registry_text().unwrap().to_owned(),
        pre_solvency_registry_text().unwrap(),
        pre_lapping_metering_registry_text().unwrap(),
        pre_lapping_registry_text().unwrap(),
        legacy_lookback_registry_text().unwrap(),
        retained_legacy_registry_text().unwrap(),
    ] {
        let registry = raw_procedure_closure(&text, published_foundations()[0]);
        assert!(registry_versions(&registry).unwrap().is_some());
        assert!(!declares_intercompany_v3(&registry).unwrap());
        assert!(canonical_registry_document(&registry).unwrap().is_none());
        let mut retained = current.clone();
        retained.registry = registry;
        retained.digest = domain_digest(CERTIFICATE_DOMAIN, &[&retained.body().unwrap()]);
        assert_eq!(
            f.book.replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &retained)
                .unwrap().unwrap(),
            current.report,
        );
    }
}


/// Produce through the public facade, then verify after the live book is gone.
fn export(f: &mut Fixture, certified: &CertifiedProcedure) -> crate::ProducedBundle {
    certified.certificate.check_offline_profile().unwrap();
    let cx = f.cx();
    f.runtime
        .block_on(f.book.checkpoint(&cx, PRINCIPAL, &cap(&["witness"])))
        .unwrap()
        .unwrap();
    let before = f.head();
    let produced = f
        .runtime
        .block_on(f.book.produce_procedure_report_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            &certified.certificate,
        ))
        .unwrap()
        .unwrap()
        .expect("a checkpoint covers the complete native intercompany prefix");
    assert_eq!(f.head(), before, "export must not publish journal effects");
    produced
}

fn independent(
    certified: &CertifiedProcedure,
    produced: &crate::ProducedBundle,
    key: [u8; 32],
) {
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let result = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        Some(certified.certificate.digest()),
    )
    .expect("the independent verifier must reconstruct the native v3 result");
    assert_eq!(result.certificate_digest, *certified.certificate.digest());
    assert_eq!(result.known_at, certified.certificate.known_at().0);
    assert_eq!(result.output, certified.certificate.output());
    let procedure = result.procedure.unwrap();
    assert_eq!(
        (procedure.live_entries, procedure.live_legs, procedure.comparisons),
        (
            certified.report.work.entries,
            certified.report.work.legs,
            certified.report.work.comparisons,
        ),
    );
    assert_eq!(procedure.findings.len(), certified.report.findings.len());
    for (verified, native) in procedure.findings.iter().zip(&certified.report.findings) {
        assert_eq!(verified.population, native.statistic.population);
        assert_eq!(verified.narrative, native.narrative);
    }
}

fn reject_resealed(
    certified: &CertifiedProcedure,
    produced: &crate::ProducedBundle,
    key: [u8; 32],
) {
    assert!(!certified.report.findings.is_empty());
    for variant in ["omitted", "amount", "population", "leg", "work", "narrative"] {
        let mut forged = certified.certificate.clone();
        match variant {
            "omitted" => forged.report.findings.clear(),
            "amount" => forged.report.findings[0].statistic.value += 1,
            "population" => forged.report.findings[0].statistic.population += 1,
            "leg" => match &mut forged.report.findings[0].cites[1] {
                Cite::Leg { ordinal, .. } => *ordinal = 1 - *ordinal,
                other => panic!("expected a leg citation, got {other:?}"),
            },
            "work" => forged.report.work.comparisons += 1,
            "narrative" => forged.report.findings[0].narrative.push_str(" forged"),
            _ => unreachable!(),
        }
        // Repair every public output/parameter/card/certificate digest and give
        // the recipient the forged outer pin. Source authentication is intact;
        // recomputation must still reject an omitted or fabricated finding.
        super::offline::reseal(&mut forged);
        let mut reader = Reader::new(&produced.bundle.bytes);
        let format = reader.bytes(64, "format").unwrap();
        let major = reader.u16("major").unwrap();
        let minor = reader.u16("minor").unwrap();
        reader.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "certificate").unwrap();
        let mut writer = Writer::new();
        writer
            .bytes(format)
            .u16(major)
            .u16(minor)
            .bytes(&forged.canonical_bytes().unwrap())
            .fixed(&produced.bundle.bytes[reader.offset()..]);
        let replaced = writer.finish().unwrap();
        let refusal = fa_verify::report::verify_report_expected(
            &replaced, &[key], None, None, Some(forged.digest()),
        )
        .expect_err("resealed intercompany findings must be independently recomputed");
        assert_eq!(refusal.predicate, "procedure_recomputation", "{variant}");
    }
}

fn entity_fixture(seed: u8) -> Fixture {
    let unit = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    Fixture::with_entities(
        seed,
        ["A", "B"]
            .into_iter()
            .map(|code| fa_journal::genesis::LegalEntitySpec {
                code: code.into(),
                name: code.into(),
                functional_unit: unit,
            })
            .collect(),
    )
}

fn entity_transfer(f: &mut Fixture, date: u8, key: &[u8], pair: Option<&str>) -> VId {
    let cx = f.cx();
    let legs = [
        ("1000", Side::Debit, "A"),
        ("1010", Side::Credit, "A"),
        ("3000", Side::Credit, "B"),
        ("1020", Side::Debit, "B"),
    ]
    .into_iter()
    .map(|(account, side, entity)| {
        let mut leg = LegPayload::simple(side, f.id(account), Amount::new(f.unit, 5_000));
        leg.dimension_set = vec![(
            fa_model::LEGAL_ENTITY_DIMENSION,
            fa_model::entity_value_vid(f.book.context().book_id, entity),
        )];
        leg
    })
    .collect::<Vec<_>>();
    let mut proposal = EntryPayload {
        schema_minor: 0,
        book_id: f.book.context().book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(date),
        document_date: None,
        description: f.book.seal_text(&cx, "Native reciprocal entity transfer").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent { intent_oid: Oid([1; 32]), intent_kind: 1 },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: f.evidence.clone(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
        extensions: Vec::new(),
    };
    if let Some(pair_key) = pair {
        proposal.set_intercompany_pairs(&fa_model::IntercompanyPairs {
            pairs: vec![fa_model::IntercompanyPair {
                pair_key: pair_key.into(),
                left_leg: 1,
                right_leg: 3,
            }],
        }).unwrap();
    }
    post_payload(f, proposal)
}

fn post_payload(f: &mut Fixture, proposal: EntryPayload) -> VId {
    let cx = f.cx();
    f.runtime
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
        .entry_ref()
        .vid
}

fn reverse_native(f: &mut Fixture, source: VId, date: u8, key: &[u8]) -> VId {
    let (entry, _) = f.book.read_entry(&f.cx(), source).unwrap().unwrap();
    let target = fa_model::EntryRef { vid: source, entry_digest: entry.entry_digest };
    let mut proposal = entry.proposal;
    proposal.idempotency_key = key.to_vec();
    proposal.class = EntryClass::REVERSAL;
    proposal.effective_date = day(date);
    proposal.effective_period = None;
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut proposal.legs {
        leg.side = leg.side.flipped();
        leg.settles.clear();
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post_payload(f, proposal)
}

#[test]
fn intercompany_v3_portable_accepts_native_pairs_without_roles_across_reversals() {
    let mut f = entity_fixture(0xe3);
    let original = entity_transfer(&mut f, 5, b"paired", Some("lasting-pair"));
    let historical = f.certify(&f.request("recon.intercompany", original));
    assert!(historical.report.findings.is_empty());
    let undo = reverse_native(&mut f, original, 20, b"paired-undo");
    let canceled = f.certify(&f.request("recon.intercompany", original));
    assert!(canceled.report.findings.is_empty());
    assert_eq!(canceled.report.work.legs, 8);
    assert_eq!(
        canceled.report.work.comparisons,
        canceled.report.work.entries + 2 + 4 + 4,
        "prefix entries, two declarations, entity cells and inherited legs",
    );
    let mut request = f.request("recon.intercompany", original);
    request.effective_through = Some(day(10));
    let through_original = f.certify(&request);
    assert_eq!(
        through_original.report.work.comparisons,
        canceled.report.work.comparisons + 4,
        "cutoff selection precedes liveness and visits the original four legs",
    );
    reverse_native(&mut f, undo, 25, b"paired-restore");
    let restored = f.certify(&f.request("recon.intercompany", original));
    assert!(restored.report.findings.is_empty());
    assert_eq!(restored.report.work.legs, 12);
    assert_eq!(
        restored.report.work.comparisons,
        restored.report.work.entries + 3 + 6 + 8 + 4,
        "restoration preserves the declared pair and each metered history check",
    );
    request.known_at = Some(f.head());
    let cutoff_after_restore = f.certify(&request);
    assert!(cutoff_after_restore.report.findings.is_empty());
    let key = f.book.checkpoint_public_key();
    let artifacts: Vec<_> = [
        historical, canceled, through_original, restored, cutoff_after_restore,
    ]
    .into_iter()
    .map(|certified| {
        let produced = export(&mut f, &certified);
        (certified, produced)
    })
    .collect();
    drop(f);
    for (certified, produced) in artifacts {
        independent(&certified, &produced, key);
    }
}

#[test]
fn intercompany_v3_portable_counts_the_declared_and_role_population_once() {
    let mut f = entity_fixture(0xe4);
    f.assign_role("1010", "intercompany");
    f.assign_role("1020", "intercompany");
    let declared = entity_transfer(&mut f, 3, b"covered", Some("covered-pair"));
    let covered = f.certify(&f.request("recon.intercompany", declared));
    let uncovered = entity_transfer(&mut f, 4, b"uncovered", None);
    let certified = f.certify(&f.request("recon.intercompany", declared));
    assert_eq!(certified.report.findings.len(), 2);
    for finding in &certified.report.findings {
        assert_eq!(finding.statistic.population, 4);
        assert_eq!(finding.statistic.value, 5_000);
        assert_eq!(finding.statistic.scale, 2);
        assert!(finding.cites.contains(&Cite::Entry(uncovered)));
        assert!(!finding.cites.contains(&Cite::Entry(declared)));
    }
    let covered_bundle = export(&mut f, &covered);
    let produced = export(&mut f, &certified);
    let key = f.book.checkpoint_public_key();
    drop(f);
    independent(&covered, &covered_bundle, key);
    independent(&certified, &produced, key);
}

#[test]
fn intercompany_v3_portable_includes_activity_roles_without_native_pairs() {
    let mut f = Fixture::new(0xe5);
    f.assign_role("6000", "intercompany_activity");
    let (source, _) = f.post(1, "3000", "6000", 7_000, false);
    f.post(2, "6000", "1010", 7_000, false);
    let certified = f.certify(&f.request("recon.intercompany", source));
    assert_eq!(certified.report.findings.len(), 2);
    for finding in &certified.report.findings {
        assert_eq!(finding.statistic.population, 2);
        assert_eq!(finding.statistic.value, 7_000);
        assert!(finding.cites.contains(&Cite::Account(f.id("6000"))));
    }
    let produced = export(&mut f, &certified);
    let key = f.book.checkpoint_public_key();
    drop(f);
    independent(&certified, &produced, key);
}
