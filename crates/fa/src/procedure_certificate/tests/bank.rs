//! Native bank closes, certified drift and admitted historical replay.

use super::*;
use crate::bank::{
    BankConfirmationRequest, BankFormat, BankImportRequest, BankMatchRequest,
    BankReconciliationRecorded, BankReconciliationRequest,
};
use fgdb_types::CanonicalScalar;

const CSV: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n1,CERTIFIED-BANK,USD,2026-01-15,0.00,100.00,2026-01-05,2026-01-05,CRDT,100.00,Customer,\n";

fn close(f: &mut Fixture) -> (BankReconciliationRecorded, VId) {
    let (entry, _) = f.post(5, "3000", "1000", 10_000, false);
    let cx = f.cx();
    let cash = f.id("1000");
    let capability = cap(&["read", "post", "reconcile", "privileged"]);
    let imported = f
        .runtime
        .block_on(f.book.import_bank_statement(
            &cx,
            &capability,
            BankImportRequest {
                account: cash,
                format: BankFormat::Csv,
                bytes: CSV.as_bytes().to_vec(),
                previous_manifest: None,
            },
        ))
        .unwrap()
        .unwrap();
    let matched = f
        .runtime
        .block_on(f.book.match_bank_statement(
            &cx,
            &capability,
            BankMatchRequest {
                manifest_oid: imported.manifest_oid,
                known_at: None,
                date_window_days: 3,
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(matched.proposals.len(), 1);
    assert_eq!(matched.proposals[0].matched_entry_ordinal, Some(0));
    f.runtime
        .block_on(f.book.confirm_bank_statement_match(
            &cx,
            &capability,
            BankConfirmationRequest {
                manifest_oid: imported.manifest_oid,
                line_ordinal: matched.lines[0].line_ordinal,
                proposal_digest: matched.proposals[0].oid().unwrap().0,
                source_known_at: matched.known_at,
                date_window_days: matched.date_window_days,
                proposer: matched.proposals[0].principal,
            },
        ))
        .unwrap()
        .unwrap();
    let selected = f.head();
    let recorded = f
        .runtime
        .block_on(f.book.reconcile_bank_statement(
            &cx,
            &capability,
            BankReconciliationRequest {
                manifest_oid: imported.manifest_oid,
                evaluated_known_at: selected,
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(recorded.claim.cash_balance, 10_000);
    (recorded, entry)
}

fn request(f: &Fixture) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(bank::PROCEDURE, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request.effective_through = Some(day(31));
    request
}

fn certify(f: &mut Fixture) -> CertifiedProcedure {
    let cx = f.cx();
    let request = request(f);
    f.runtime
        .block_on(f.book.certify_procedure_with_history(
            &cx,
            PRINCIPAL,
            &cap(&["read", "reconcile", "produce"]),
            &request,
        ))
        .unwrap()
        .unwrap()
}

fn late_cash(f: &mut Fixture, source: VId) -> VId {
    let row = f.book.db.vertex(source).unwrap().unwrap();
    let bytes = fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "cash Entry").unwrap();
    let mut proposal = fa_model::Entry::decode(&bytes).unwrap().proposal;
    proposal.idempotency_key = b"bank-certificate-late-cash".to_vec();
    proposal.effective_date = day(10);
    for leg in &mut proposal.legs {
        leg.amount.mantissa = 500;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let cx = f.cx();
    f.runtime
        .block_on(f.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post", "reconcile"]),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref()
        .vid
}

#[test]
fn bank_drift_v3_replays_original_cash_after_authorized_drift_and_cold_reopen() {
    let mut f = Fixture::new(101);
    let (closed, source) = close(&mut f);
    let before = f.head();
    let clean = certify(&mut f);
    assert_eq!(
        clean.certificate.format(),
        BANK_PROCEDURE_CERTIFICATE_FORMAT
    );
    assert!(clean.report.findings.is_empty());
    assert_eq!(clean.report.coordinate.known_at, before);
    assert_eq!(f.head(), before);
    let bytes = clean.certificate.canonical_bytes().unwrap();
    assert_eq!(
        ProcedureCertificate::decode(&bytes).unwrap(),
        clean.certificate
    );
    assert_eq!(
        ReportArtifact::decode(&bytes).unwrap().family(),
        ReportArtifactFamily::Procedure
    );

    let cx = f.cx();
    let request = request(&f);
    let ordinary = f
        .runtime
        .block_on(f.book.run_procedure_with_history(
            &cx,
            PRINCIPAL,
            &cap(&["read", "reconcile"]),
            &request,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        ordinary, clean.report,
        "ordinary runs do not require Produce"
    );
    let later = late_cash(&mut f, source);
    let drift = certify(&mut f);
    let finding = drift
        .report
        .findings
        .iter()
        .find(|finding| finding.statistic.name == "bank_statement_balance_drift")
        .unwrap();
    assert_eq!(finding.statistic.value, 500);
    assert!(
        finding
            .cites
            .contains(&Cite::Attestation(closed.attestation_vid))
    );
    assert!(
        finding
            .cites
            .iter()
            .any(|cite| matches!(cite, Cite::Entry(reference) if *reference == later))
    );
    assert_eq!(
        f.book
            .replay_procedure(
                &cx,
                PRINCIPAL,
                &cap(&["read", "reconcile"]),
                &clean.certificate
            )
            .unwrap()
            .unwrap(),
        clean.report,
    );

    let head = f.head();
    let vfs = f.vfs.clone();
    drop(f.book);
    let mut reopened = f
        .runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            Path::new("procedures"),
            BookKeys::for_development(101),
            Entropy::deterministic(1001),
        ))
        .unwrap();
    let replayed = f
        .runtime
        .block_on(reopened.replay_report_artifact_for_with_history(
            &cx,
            PRINCIPAL,
            &cap(&["read", "reconcile"]),
            &bytes,
            Some(clean.certificate.digest()),
            crate::ReportArtifactExpectation::AsSupplied,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(replayed.output, clean.certificate.output);
    assert_eq!(replayed.known_at, before);
    assert_eq!(
        reopened.head(&cx).unwrap(),
        head,
        "replay publishes nothing"
    );
    assert_eq!(
        f.runtime
            .block_on(reopened.replay_procedure_with_history(
                &cx,
                PRINCIPAL,
                &cap(&["read", "reconcile"]),
                &drift.certificate,
            ))
            .unwrap()
            .unwrap(),
        drift.report
    );
}

#[test]
fn bank_v3_requires_complete_population_and_relationship_witnesses() {
    let mut f = Fixture::new(102);
    close(&mut f);
    let certificate = certify(&mut f).certificate;
    assert_eq!(certificate.supplemental_inputs().len(), 15);
    for name in [
        "Attestation",
        "BankMatch",
        "BankMatchedLeg",
        "BankUnmatch",
        "BankStatementLink",
        "Document",
        "Leg",
    ] {
        assert!(
            certificate
                .supplemental_inputs()
                .iter()
                .any(|native| native.statement.contains(&format!("(n:{name})")))
        );
    }
    for relation in [
        "ATTESTS",
        "CITES",
        "IN_BOOK",
        "MATCHES",
        "SUPERSEDES",
        "DERIVED_FROM",
        "HAS_LEG",
        "POSTS_TO",
    ] {
        assert!(
            certificate
                .supplemental_inputs()
                .iter()
                .any(|native| native.statement.contains(&format!("[e:{relation}]")))
        );
    }
    for index in 0..certificate.extended_inputs.len() {
        let mut missing = certificate.clone();
        missing.extended_inputs.remove(index);
        assert!(
            missing.body().is_err(),
            "every population and relation is mandatory"
        );
    }
    let mut reordered = certificate.clone();
    reordered.extended_inputs.swap(0, 1);
    assert!(reordered.body().is_err());
    let mut rebound = certificate.clone();
    rebound.extended_inputs[0] = certificate.approvals.clone();
    assert!(rebound.body().is_err());
    f.post(6, "1010", "6000", 10, false);
    let current = certify(&mut f).certificate;
    let mut mixed = certificate.clone();
    mixed.extended_inputs[0] = current.extended_inputs[0].clone();
    assert!(mixed.body().is_err());

    let mut forged = certificate.clone();
    let native = forged
        .extended_inputs
        .iter_mut()
        .find(|input| input.statement.contains("[e:ATTESTS]"))
        .unwrap();
    native.result_digest.0[0] ^= 1;
    forged.digest = domain_digest(CERTIFICATE_DOMAIN, &[&forged.body().unwrap()]);
    let intact = ProcedureCertificate::decode(&forged.canonical_bytes().unwrap()).unwrap();
    assert!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read", "reconcile"]), &intact)
            .unwrap()
            .is_err(),
        "repairing public framing cannot certify a false native edge result"
    );
    let mut downgrade = certificate.canonical_bytes().unwrap();
    downgrade[4 + BANK_PROCEDURE_CERTIFICATE_FORMAT.len() - 1] = b'2';
    assert!(ProcedureCertificate::decode(&downgrade).is_err());
}

#[test]
fn bank_v3_scope_precedes_native_history_and_restored_damage_cannot_replay() {
    let mut f = Fixture::new(103);
    let (closed, _) = close(&mut f);
    let certificate = certify(&mut f).certificate;
    let cx = f.cx();
    let saved = f.book.db.vertex(closed.attestation_vid).unwrap().unwrap();
    let original = fa_journal::rows::prop(&saved, property::FA_DIGEST)
        .unwrap()
        .clone();
    for value in [CanonicalScalar::bytes(vec![0; 32]).unwrap(), original] {
        let mut batch = fgdb::WriteBatch::new(fa_model::symbols::relation::SUPERSEDES);
        batch.set_vertex_property(closed.attestation_vid, property::FA_DIGEST, Some(value));
        f.runtime
            .block_on(f.book.db.write(&cx.commit(), batch))
            .unwrap();
    }
    let request = request(&f);
    for denied in [
        cap(&["read", "produce"]),
        cap(&["read", "reconcile", "produce"])
            .for_accounts(&["1000"])
            .unwrap(),
        cap(&["read", "reconcile", "produce"]).expiring_at(f.head()),
        cap(&["read", "reconcile", "produce"])
            .for_books(&[Id128([255; 16])])
            .unwrap(),
    ] {
        let refusal = f
            .runtime
            .block_on(
                f.book
                    .certify_procedure_with_history(&cx, PRINCIPAL, &denied, &request),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.exit,
            exit::SAFETY,
            "scope precedes corrupted native history"
        );
    }
    let missing = f
        .book
        .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(missing.code, fa_journal::refusal::code::CAPABILITY);
    assert!(
        f.book
            .replay_procedure(&cx, PRINCIPAL, &cap(&["read", "reconcile"]), &certificate)
            .unwrap()
            .is_err(),
        "the saved prefix cannot hide later altered-then-restored immutable history"
    );
    assert!(
        f.runtime
            .block_on(f.book.certify_procedure_with_history(
                &cx,
                PRINCIPAL,
                &cap(&["read", "reconcile", "produce"]),
                &request,
            ))
            .unwrap()
            .is_err(),
        "fresh certification also refolds native integrity"
    );
}
