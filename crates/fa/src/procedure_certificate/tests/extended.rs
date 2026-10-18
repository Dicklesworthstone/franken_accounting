use super::*;
use fa_model::{PartyKind, PartySpec, party_vid};
use fgdb_types::CanonicalScalar;

fn review(f: &mut Fixture) -> fa_journal::Attested {
    let cx = f.cx();
    f.runtime.block_on(f.book.record_review(
        &cx, &Capability::embedded(VId(74), &["approve"]).unwrap(),
        &f.evidence[0].document_oid, Vec::new(),
    )).unwrap().unwrap()
}

fn party(f: &mut Fixture, code: &str, bank: &str) -> VId {
    let cx = f.cx();
    let spec = PartySpec {
        code: code.into(), kind: PartyKind::Vendor,
        name: f.book.seal_text(&cx, code).unwrap(),
        identifiers: vec![("bank_account".into(), f.book.seal_text(&cx, bank).unwrap())],
        external_ids: Vec::new(),
    };
    f.runtime.block_on(f.book.create_party(&cx, &spec, PRINCIPAL, day(1), code.as_bytes(), &cap(&["schema_change"])))
        .unwrap().unwrap();
    party_vid(f.book.context().book_id, code)
}

#[test]
fn all_additional_procedures_round_trip_with_complete_native_populations() {
    let mut f = Fixture::new(91);
    let (source, _) = f.post(1, "3000", "1000", 100, true);
    f.post(2, "1000", "1010", 80, false);
    f.post(3, "1010", "1020", 60, false);
    f.post(4, "1020", "6000", 10, false);
    let before = f.head();
    assert_eq!(EXTENDED_CERTIFIABLE_PROCEDURES.len(), 29);
    let mut saved = Vec::new();
    for &(id, version) in EXTENDED_CERTIFIABLE_PROCEDURES {
        assert!(!supported(id, version), "the legacy closure is unchanged");
        let c = f.certify(&f.request(id, source)).certificate;
        assert_eq!(c.format(), EXTENDED_PROCEDURE_CERTIFICATE_FORMAT);
        assert_eq!(c.supplemental_inputs().len(), 6);
        assert_eq!(c.report.version, version);
        let bytes = c.canonical_bytes().unwrap();
        assert_eq!(ProcedureCertificate::decode(&bytes).unwrap(), c);
        assert_eq!(ReportArtifact::decode(&bytes).unwrap().family(), ReportArtifactFamily::Procedure);
        assert_eq!(f.head(), before, "certification cannot publish {id}");
        saved.push(c);
    }
    f.post(1, "3000", "1000", 300, false);
    review(&mut f);
    let after = f.head();
    for c in saved {
        let replayed = f.book.replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &c).unwrap().unwrap();
        assert_eq!(replayed, c.report, "{} is pinned before later evidence", c.report.procedure);
        assert_eq!(f.head(), after);
    }
}

#[test]
fn independent_attestations_change_results_but_not_the_saved_historical_run() {
    let mut f = Fixture::new(92);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let key = fa_registers::EntityCellKey {
        account: f.id("1000"), unit_id: f.unit.0, period: "FY2026-P01".into(), entity: None,
    };
    let cx = f.cx();
    let claim = f.book.evaluate_register_equals(&cx, &key, None).unwrap();
    let evidence = f.evidence.iter().map(|e| e.document_oid).collect();
    let attested = f.runtime.block_on(f.book.record_register_equals(&cx, &cap(&["reconcile"]), &claim, evidence))
        .unwrap().unwrap();
    let c = f.certify(&f.request("recon.book_to_book", source)).certificate;
    assert!(c.report.findings.is_empty(), "the original declared balance matches");
    f.post(1, "3000", "1000", 70, false);
    let current = f.certify(&f.request("recon.book_to_book", source));
    assert!(current.report.findings.iter().any(|f| f.statistic.name == "book_to_book_discrepancy" && f.statistic.value == 70));
    assert_eq!(f.book.replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &c).unwrap().unwrap(), c.report);
    assert!(f.book.db.vertex(attested.vid).unwrap().is_some());
    // Full v2 certificates also use existing retention and finding records.
    let bytes = current.certificate.canonical_bytes().unwrap();
    let kept = f.runtime.block_on(f.book.retain_report_artifact(&cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(current.certificate.digest())))
        .unwrap().unwrap();
    assert_eq!(kept.recorded_at, f.head());
    let run = f.runtime.block_on(f.book.record_findings(&cx, PRINCIPAL, &cap(&["read", "produce"]), current.certificate.digest()))
        .unwrap().unwrap();
    assert!(!run.finding_ids.is_empty());
    assert_eq!(run.report, current.report);
}

#[test]
fn nonempty_party_identity_graph_survives_later_population_changes_and_reopen() {
    let mut f = Fixture::new(93);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let a = party(&mut f, "VENDOR-A", "AB-123");
    let b = party(&mut f, "VENDOR-B", "ab 123");
    let c = f.certify(&f.request("graph.identity_resolution", source)).certificate;
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
    let reopened = f.runtime.block_on(AsyncBook::open_with_vfs(
        &cx, vfs, Path::new("procedures"), BookKeys::for_development(93), Entropy::deterministic(999),
    )).unwrap();
    let replayed = reopened.replay_report_artifact(&cx, PRINCIPAL, &cap(&["read"]), &bytes, Some(c.digest()));
    assert_eq!(replayed.unwrap().unwrap().output, c.output);
}

#[test]
fn missing_reordered_rebound_and_cross_snapshot_witnesses_cannot_be_rehashed_away() {
    let mut f = Fixture::new(94);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let c = f.certify(&f.request("confirm.coverage", source)).certificate;
    let mut missing = c.clone(); missing.extended_inputs.pop();
    assert!(missing.body().is_err());
    let mut reordered = c.clone(); reordered.extended_inputs.swap(0, 1);
    assert!(reordered.body().is_err());
    let mut statement = c.clone(); statement.extended_inputs[0] = c.approvals.clone();
    assert!(statement.body().is_err());
    review(&mut f);
    let later = f.certify(&f.request("confirm.coverage", source)).certificate;
    let mut mixed = c.clone(); mixed.extended_inputs[0] = later.extended_inputs[0].clone();
    assert!(mixed.body().is_err());
    let bytes = c.canonical_bytes().unwrap();
    for end in [0, 4, 32, bytes.len() / 2, bytes.len() - 1] {
        assert!(ProcedureCertificate::decode(&bytes[..end]).is_err());
    }
    let mut too_new = bytes.clone(); too_new[4 + EXTENDED_PROCEDURE_CERTIFICATE_FORMAT.len() - 1] = b'3';
    assert!(ProcedureCertificate::decode(&too_new).is_err());
    let mut downgrade = bytes; downgrade[4 + EXTENDED_PROCEDURE_CERTIFICATE_FORMAT.len() - 1] = b'1';
    assert!(ProcedureCertificate::decode(&downgrade).is_err());
}

#[test]
fn attestation_rewrites_and_restoration_refuse_replay_and_fresh_certification() {
    let mut f = Fixture::new(95);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let reviewed = review(&mut f);
    let c = f.certify(&f.request("confirm.coverage", source)).certificate;
    let old = f.book.db.vertex(reviewed.vid).unwrap().unwrap();
    let original = fa_journal::rows::prop(&old, property::FA_DIGEST).unwrap().clone();
    let cx = f.cx();
    for value in [CanonicalScalar::bytes(vec![0; 32]).unwrap(), original] {
        let mut batch = fgdb::WriteBatch::new(fa_model::symbols::relation::SUPERSEDES);
        batch.set_vertex_property(reviewed.vid, property::FA_DIGEST, Some(value));
        f.runtime.block_on(f.book.db.write(&cx.commit(), batch)).unwrap();
        let r = f.book.replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &c).unwrap().unwrap_err();
        assert_eq!(r.exit, exit::VERIFICATION);
        assert!(r.message.contains("attestation"));
        let fresh = f.book.certify_procedure(&cx, PRINCIPAL, &cap(&["read", "produce"]), &f.request("confirm.coverage", source))
            .unwrap().unwrap_err();
        assert!(fresh.message.contains("attestation"));
    }
}

#[test]
fn a_discrepancy_beyond_signed_statistic_capacity_has_no_certificate_or_wrapped_finding() {
    let mut f = Fixture::new(96);
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    let cx = f.cx();
    let key = fa_registers::EntityCellKey {
        account: f.id("1000"), unit_id: f.unit.0, period: "FY2026-P01".into(), entity: None,
    };
    let claim = f.book.evaluate_register_equals(&cx, &key, None).unwrap();
    assert_eq!(claim.amount.mantissa, 1);
    f.runtime.block_on(f.book.record_register_equals(&cx, &cap(&["reconcile"]), &claim, f.evidence.iter().map(|e| e.document_oid).collect()))
        .unwrap().unwrap();
    f.post(1, "1000", "6000", i128::MAX, false);
    let exact = f.certify(&f.request("recon.book_to_book", source));
    assert_eq!(exact.report.findings[0].statistic.value, i128::MAX);
    f.post(1, "1000", "3000", 1, false);
    let head = f.head();
    assert!(matches!(f.book.certify_procedure(&cx, PRINCIPAL, &cap(&["read", "produce"]), &f.request("recon.book_to_book", source)),
        Err(crate::BookError::Lantern(fa_lantern::LanternError::Overflow("book_to_book discrepancy magnitude")))));
    assert_eq!(f.head(), head);
    assert_eq!(f.book.replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &exact.certificate).unwrap().unwrap(), exact.report);
}

#[test]
fn extended_input_reads_never_inherit_attester_or_saved_producer_authority() {
    let mut f = Fixture::new(97);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let attested = review(&mut f);
    let request = f.request("confirm.coverage", source);
    let c = f.certify(&request).certificate;
    assert_eq!(c.supplemental_inputs().len(), 6);
    let before = f.head();
    let bytes = c.canonical_bytes().unwrap();
    for reader in [
        cap(&["post"]), cap(&["approve"]), cap(&["produce"]),
        cap(&["read"]).expiring_at(before),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(),
    ] {
        let denial = f.book.replay_procedure(&f.cx(), PRINCIPAL, &reader, &c).unwrap().unwrap_err();
        assert_ne!(denial.code, crate::certificate::code::CERTIFICATE_INVALID);
        let denial = f.book.replay_report_artifact(&f.cx(), PRINCIPAL, &reader, b"not an artifact", None).unwrap().unwrap_err();
        assert_ne!(denial.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(f.head(), before);
    }
    assert!(f.book.certify_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &request).unwrap().is_err());
    let actual = f.book.replay_report_artifact(&f.cx(), PRINCIPAL, &cap(&["read"]), &bytes, Some(c.digest())).unwrap().unwrap();
    assert_eq!(actual.output, c.output);
    // An actual approver and intact native attestation do not authorize replay
    // of the whole book. Only the current requesting principal's scope does.
    assert!(f.book.replay_procedure(&f.cx(), VId(74), &Capability::embedded(VId(74), &["approve"]).unwrap(), &c).unwrap().is_err());
    assert!(f.book.db.vertex(attested.vid).unwrap().is_some());
    assert_eq!(f.head(), before);
}
