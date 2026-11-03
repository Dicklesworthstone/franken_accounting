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
fn all_additional_procedures_round_trip_with_complete_native_populations() {
    let mut f = Fixture::new(91);
    // The role-selected procedures (fa-kxc4) need their roles held.
    f.assign_procedure_roles();
    let (source, _) = f.post(1, "3000", "1000", 100, true);
    f.post(2, "1000", "1010", 80, false);
    f.post(3, "1010", "1020", 60, false);
    f.post(4, "1020", "6000", 10, false);
    let before = f.head();
    assert_eq!(EXTENDED_CERTIFIABLE_PROCEDURES.len(), 43);
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
        // fa-6l8g moved the party-attributing procedures to version 3, and
        // fa-yugf.83 the investor-population ones on to version 4. As-of
        // netting moved aging.inventory to version 3; cash-overdraft netting
        // moved the cash-flow solvency screen to version 4.
        let version = match id {
            "lookback.preferences" | "aging.inventory" => 3,
            "solvency.cash_flow_test" => 4,
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
            .contains("no complete registered native certificate closure")
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
                .contains("no complete registered native certificate closure"),
            "version {old}: {}",
            refusal.message
        );
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
    let bytes = c.canonical_bytes().unwrap();
    party(&mut f, "VENDOR-C", "ab123");
    let new = f.certify(&f.request("graph.identity_resolution", source));
    assert_ne!(new.report.findings_digest, c.report.findings_digest);
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
