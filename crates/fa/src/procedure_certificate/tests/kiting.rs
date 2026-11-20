//! Native source replay, persistence and authority for temporal bank screening.

use super::*;
use crate::bank::{
    BankConfirmationRequest, BankDecisionRef, BankFormat, BankImportRequest, BankMatchRecorded,
    BankMatchRequest, BankUnmatchRequest,
};

const HEADER: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n";

fn full() -> Capability {
    cap(&["read", "reconcile", "privileged", "produce"])
}

/// Three exact cash transfers, each confirmed on both banks' original lines.
/// The receipt is available on January 5 and the outgoing debit clears on 10.
fn kite(f: &mut Fixture) -> Vec<BankMatchRecorded> {
    for account in ["1000", "1010", "1020"] {
        f.assign_role(account, "cash");
    }
    f.post(5, "1000", "1010", 10_000, false);
    f.post(5, "1010", "1020", 10_000, false);
    f.post(5, "1020", "1000", 10_000, false);
    let cx = f.cx();
    let authority = cap(&["read", "post", "reconcile", "privileged"]);
    let mut matches = Vec::new();
    for account in ["1000", "1010", "1020"] {
        let bytes = format!(
            "{HEADER}1,BANK-{account},USD,2026-01-15,0.00,0.00,2026-01-05,2026-01-05,CRDT,100.00,private counterparty,\n1,BANK-{account},USD,2026-01-15,0.00,0.00,2026-01-05,2026-01-10,DBIT,100.00,private counterparty,\n"
        );
        let account = f.id(account);
        let imported = f
            .runtime
            .block_on(f.book.import_bank_statement(
                &cx,
                &authority,
                BankImportRequest {
                    account,
                    format: BankFormat::Csv,
                    bytes: bytes.into_bytes(),
                    previous_manifest: None,
                },
            ))
            .unwrap()
            .unwrap();
        let matched = f
            .runtime
            .block_on(f.book.match_bank_statement(
                &cx,
                &authority,
                BankMatchRequest {
                    manifest_oid: imported.manifest_oid,
                    known_at: None,
                    date_window_days: 0,
                },
            ))
            .unwrap()
            .unwrap();
        assert_eq!(matched.proposals.len(), 2);
        for (line, proposal) in matched.lines.iter().zip(&matched.proposals) {
            assert!(proposal.matched_entry_ordinal.is_some());
            matches.push(
                f.runtime
                    .block_on(f.book.confirm_bank_statement_match(
                        &cx,
                        &authority,
                        BankConfirmationRequest {
                            manifest_oid: imported.manifest_oid,
                            line_ordinal: line.line_ordinal,
                            proposal_digest: proposal.oid().unwrap().0,
                            source_known_at: matched.known_at,
                            date_window_days: matched.date_window_days,
                            proposer: proposal.principal,
                        },
                    ))
                    .unwrap()
                    .unwrap(),
            );
        }
    }
    matches
}

fn request() -> ProcedureRequest {
    ProcedureRequest::new(kiting::PROCEDURE, catalog::Inputs::default()).unwrap()
}

fn certify(f: &mut Fixture, request: &ProcedureRequest) -> CertifiedProcedure {
    let cx = f.cx();
    f.runtime
        .block_on(
            f.book
                .certify_procedure_with_history(&cx, PRINCIPAL, &full(), request),
        )
        .unwrap()
        .unwrap()
}

#[test]
fn kiting_v4_replays_retains_and_records_the_complete_three_bank_cycle() {
    let mut f = Fixture::new(151);
    kite(&mut f);
    let before = f.head();
    let certified = certify(&mut f, &request());
    assert_eq!(certified.report.coordinate.known_at, before);
    assert_eq!(certified.report.findings.len(), 1);
    assert_eq!(
        certified.certificate.format(),
        KITING_PROCEDURE_CERTIFICATE_FORMAT
    );
    assert_eq!(certified.certificate.supplemental_inputs().len(), 19);
    assert_eq!(f.head(), before, "screening publishes no accounting record");
    let bytes = certified.certificate.canonical_bytes().unwrap();
    assert_eq!(
        ProcedureCertificate::decode(&bytes).unwrap(),
        certified.certificate
    );
    assert_eq!(
        ReportArtifact::decode(&bytes).unwrap().family(),
        ReportArtifactFamily::Procedure
    );
    assert!(certified.certificate.check_offline_profile().is_err());
    assert!(!String::from_utf8_lossy(&bytes).contains("private counterparty"));

    let cx = f.cx();
    let ordinary = f
        .runtime
        .block_on(f.book.run_procedure_with_history(
            &cx,
            PRINCIPAL,
            &cap(&["read", "reconcile", "privileged"]),
            &request(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        ordinary, certified.report,
        "execution needs no Produce grant"
    );
    f.runtime
        .block_on(f.book.retain_report_artifact(
            &cx,
            PRINCIPAL,
            &full(),
            &bytes,
            Some(certified.certificate.digest()),
        ))
        .unwrap()
        .unwrap();
    let recorded = f
        .runtime
        .block_on(
            f.book
                .record_findings(&cx, PRINCIPAL, &full(), certified.certificate.digest()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(recorded.finding_ids.len(), 1);
    assert_eq!(recorded.report, certified.report);
    let read = f
        .runtime
        .block_on(f.book.read_findings_with_history(
            &cx,
            PRINCIPAL,
            &full(),
            certified.certificate.digest(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(read, recorded);
    let paper = f
        .runtime
        .block_on(f.book.finding_workpaper_with_history(
            &cx,
            PRINCIPAL,
            &full(),
            certified.certificate.digest(),
        ))
        .unwrap()
        .unwrap();
    let paper_bytes = paper.canonical_bytes().unwrap();
    let replayed_paper = f
        .runtime
        .block_on(f.book.replay_finding_workpaper_with_history(
            &cx,
            PRINCIPAL,
            &full(),
            &paper_bytes,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(replayed_paper, recorded);
    let denied = f
        .runtime
        .block_on(f.book.read_findings_with_history(
            &cx,
            PRINCIPAL,
            &cap(&["read", "reconcile"]),
            certified.certificate.digest(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, fa_journal::refusal::code::CAPABILITY);

    let head = f.head();
    let vfs = f.vfs.clone();
    drop(f.book);
    let mut reopened = f
        .runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            Path::new("procedures"),
            BookKeys::for_development(151),
            Entropy::deterministic(1510),
        ))
        .unwrap();
    let replayed = f
        .runtime
        .block_on(reopened.replay_report_artifact_for_with_history(
            &cx,
            PRINCIPAL,
            &full(),
            &bytes,
            Some(certified.certificate.digest()),
            crate::ReportArtifactExpectation::AsSupplied,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(replayed.output, certified.certificate.output);
    assert_eq!(replayed.known_at, before);
    assert_eq!(reopened.head(&cx).unwrap(), head);
}

#[test]
fn kiting_unmatch_changes_current_population_without_rewriting_saved_evidence() {
    let mut f = Fixture::new(152);
    let matches = kite(&mut f);
    let certified = certify(&mut f, &request());
    let cx = f.cx();
    let status = f
        .runtime
        .block_on(f.book.procedure_certificate_status_with_history(
            &cx,
            PRINCIPAL,
            &full(),
            &certified.certificate,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        status,
        ProcedureCertificateStatus::Current {
            checked_at: f.head()
        }
    );
    let target = &matches[0];
    f.runtime
        .block_on(f.book.unmatch_bank_match(
            &cx,
            &full(),
            BankUnmatchRequest {
                target: BankDecisionRef {
                    vid: target.match_vid,
                    digest: target.match_digest,
                },
            },
        ))
        .unwrap()
        .unwrap();
    let later = certify(&mut f, &request());
    assert!(
        later.report.findings.is_empty(),
        "one unmatched endpoint breaks the bank cycle"
    );
    assert_ne!(later.report.inputs_digest, certified.report.inputs_digest);
    assert_eq!(
        f.runtime
            .block_on(f.book.replay_procedure_with_history(
                &cx,
                PRINCIPAL,
                &full(),
                &certified.certificate,
            ))
            .unwrap()
            .unwrap(),
        certified.report
    );
    let status = f
        .runtime
        .block_on(f.book.procedure_certificate_status_with_history(
            &cx,
            PRINCIPAL,
            &full(),
            &certified.certificate,
        ))
        .unwrap()
        .unwrap();
    assert!(
        matches!(status, ProcedureCertificateStatus::Changed { current, .. }
        if *current == later.report)
    );
}

#[test]
fn kiting_full_source_authority_and_native_v4_closure_cannot_be_waived() {
    let mut f = Fixture::new(153);
    kite(&mut f);
    let cx = f.cx();
    let before = f.head();
    for authority in [
        cap(&["read", "produce"]),
        cap(&["read", "reconcile", "produce"]),
        cap(&["read", "privileged", "produce"]),
    ] {
        let refusal = f
            .runtime
            .block_on(
                f.book
                    .certify_procedure_with_history(&cx, PRINCIPAL, &authority, &request()),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
        assert_eq!(f.head(), before);
    }
    assert!(
        f.book
            .certify_procedure(&cx, PRINCIPAL, &full(), &request())
            .unwrap()
            .is_err(),
        "resident metadata alone must not manufacture original statement evidence"
    );
    let certified = certify(&mut f, &request());
    let mut incomplete = certified.certificate.clone();
    incomplete.extended_inputs.pop();
    assert!(incomplete.canonical_bytes().is_err());
    let mut confused = certified.certificate.clone();
    confused.registry =
        registry_digest_with_procedures(pre_kiting_registry_document().unwrap().canonical_bytes())
            .unwrap();
    assert!(
        confused.request().is_err(),
        "a pre-kiting registry cannot attest the new algorithm"
    );
    let mut downgraded = certified.certificate.canonical_bytes().unwrap();
    downgraded[4 + KITING_PROCEDURE_CERTIFICATE_FORMAT.len() - 1] = b'3';
    assert!(ProcedureCertificate::decode(&downgraded).is_err());
    assert_eq!(f.head(), before);
}

#[test]
fn adding_kiting_preserves_the_preexisting_canonical_and_raw_registry_epochs() {
    let mut f = Fixture::new(154);
    let (source, _) = f.post(5, "3000", "1000", 10_000, false);
    let request = f.request("jet.round_amounts", source);
    let certified = f.certify(&request);
    let previous = pre_kiting_registry_text().unwrap();
    assert!(!previous.contains("id = \"graph.kiting\""));
    for registry in [
        registry_digest_with_procedures(pre_kiting_registry_document().unwrap().canonical_bytes())
            .unwrap(),
        domain_digest(
            b"fa:procedure-registry:v1",
            &[previous.as_bytes(), PROCEDURE_REGISTRIES[1].1.as_bytes()],
        ),
    ] {
        let mut retained = certified.certificate.clone();
        retained.registry = registry;
        retained.digest = domain_digest(CERTIFICATE_DOMAIN, &[&retained.body().unwrap()]);
        let bytes = retained.canonical_bytes().unwrap();
        let retained = ProcedureCertificate::decode(&bytes).unwrap();
        assert_eq!(
            f.book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &retained)
                .unwrap()
                .unwrap(),
            certified.report
        );
    }
}
