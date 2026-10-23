//! Equity certificates exercise admitted journal history and native replay.

use super::*;
use crate::{
    CertificateStatus, EquityRollForwardCertificate, ReportArtifact, ReportArtifactExpectation,
    ReportArtifactFamily,
};
use fa_model::{Writer, domain_digest};

fn request(h: &Harness) -> EquityRollForwardRequest {
    EquityRollForwardRequest {
        units: vec![h.usd.0],
        label: "Equity January 10–20".into(),
        effective_from: day(10),
        effective_through: day(20),
        known_at: Some(h.head()),
        issuance_accounts: vec![h.id("3000")],
        distribution_accounts: Vec::new(),
    }
}

fn certify(h: &Harness) -> crate::CertifiedEquityRollForward {
    h.book
        .certify_equity_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request(h))
        .unwrap()
        .unwrap()
}

fn frame(
    source: &RollForwardCertificate,
    request: &EquityRollForwardRequest,
    output: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(crate::EQUITY_CERTIFICATE_FORMAT)
        .bytes(&source.canonical_bytes().unwrap())
        .list(&request.issuance_accounts, |w, id| {
            w.u128(id.0);
        })
        .list(&request.distribution_accounts, |w, id| {
            w.u128(id.0);
        })
        .bytes(output);
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(b"fa:equity-roll-forward-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    bytes
}

#[test]
fn equity_certificate_retains_and_replays_the_full_statement_without_posting() {
    let mut h = Harness::new();
    h.post(1, b"equity-opening", h.usd, 100);
    h.post(10, b"equity-first", h.usd, 50);
    h.post(20, b"equity-last", h.usd, -20);
    let before = h.head();
    let certified = certify(&h);
    let expected = certified.certificate.request();
    let report = &certified.report;
    assert_eq!(report.statement.units[0].opening_total_equity, 100);
    assert_eq!(report.statement.units[0].issuances, 30);
    assert_eq!(report.statement.units[0].closing_total_equity, 130);
    assert_eq!(report.statement.units[0].equity_tie_out_residual, 0);
    assert!(report.accounts.iter().any(|account| account.code == "6100"));
    assert_eq!(report.movements.len(), 2);
    let bytes = certified.certificate.canonical_bytes().unwrap();
    assert_eq!(
        EquityRollForwardCertificate::decode(&bytes).unwrap(),
        certified.certificate
    );
    let artifact = ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(artifact.family(), ReportArtifactFamily::EquityRollForward);
    assert_eq!(artifact.output(), report.canonical_bytes().unwrap());
    assert_eq!(h.head(), before, "certification is read-only");
    let cx = h.cx();
    let authority = cap(&["read", "produce"]);
    let expectation = ReportArtifactExpectation::EquityRollForward(expected);
    let retained = h
        .runtime
        .block_on(h.book.retain_report_artifact_for(
            &cx,
            PRINCIPAL,
            &authority,
            &bytes,
            Some(artifact.digest()),
            expectation,
        ))
        .unwrap()
        .unwrap();
    let after_retention = h.head();
    assert_eq!(
        h.runtime
            .block_on(h.book.retain_report_artifact_for(
                &cx,
                PRINCIPAL,
                &authority,
                &bytes,
                Some(artifact.digest()),
                expectation,
            ))
            .unwrap()
            .unwrap(),
        retained
    );
    assert_eq!(h.head(), after_retention, "retry does not republish");
    assert_eq!(
        h.runtime
            .block_on(
                h.book
                    .read_report_artifact(&cx, PRINCIPAL, &authority, artifact.digest(),)
            )
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        bytes
    );
    let replayed = h
        .book
        .replay_report_artifact_for(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &bytes,
            Some(artifact.digest()),
            expectation,
        )
        .unwrap()
        .unwrap();
    assert_eq!(replayed.output, report.canonical_bytes().unwrap());
    assert_eq!(
        h.book
            .report_artifact_status(
                &cx,
                PRINCIPAL,
                &authority,
                &bytes,
                Some(artifact.digest()),
                expectation,
            )
            .unwrap()
            .unwrap(),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    h.post(21, b"equity-outside-window", h.usd, 9);
    h.post(15, b"equity-other-currency", h.jpy, 8);
    assert_eq!(
        h.book
            .report_artifact_status(&cx, PRINCIPAL, &authority, &bytes, None, expectation,)
            .unwrap()
            .unwrap(),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    h.post(1, b"equity-late-opening", h.usd, 7);
    let status = h
        .book
        .report_artifact_status(&cx, PRINCIPAL, &authority, &bytes, None, expectation)
        .unwrap()
        .unwrap();
    assert!(
        matches!(status, CertificateStatus::SupersededBy { later_entries, .. } if later_entries.len() == 1)
    );
    assert_eq!(
        h.book
            .replay_equity_roll_forward(
                &cx,
                PRINCIPAL,
                &authority,
                &certified.certificate,
                expected,
            )
            .unwrap()
            .unwrap(),
        *report,
        "historical output stays unchanged"
    );
}

#[test]
fn equity_replay_rejects_rehashed_output_omissions_and_incomplete_source_charts() {
    let mut h = Harness::new();
    h.post(10, b"equity-in", h.usd, 50);
    h.post(11, b"equity-out", h.usd, -50);
    let certified = certify(&h);
    let expected = certified.certificate.request();
    let before = h.head();
    let mut omitted = certified.report.clone();
    omitted.movements.clear(); // Same totals, but the evidence is incomplete.
    let forged = EquityRollForwardCertificate::decode(&frame(
        certified.certificate.source_certificate(),
        expected,
        &omitted.canonical_bytes().unwrap(),
    ))
    .unwrap();
    assert!(
        h.book
            .replay_equity_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged, expected)
            .unwrap()
            .is_err()
    );
    let mut wrong_amount = certified.report.clone();
    wrong_amount.statement.units[0].issuances = 1;
    let forged = EquityRollForwardCertificate::decode(&frame(
        certified.certificate.source_certificate(),
        expected,
        &wrong_amount.canonical_bytes().unwrap(),
    ))
    .unwrap();
    assert!(
        h.book
            .replay_equity_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged, expected)
            .unwrap()
            .is_err()
    );
    let mut source_request = certified.certificate.source_certificate().request().clone();
    source_request.accounts.retain(|id| *id != h.id("6100"));
    let incomplete_source = h
        .book
        .certify_roll_forward(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &source_request,
        )
        .unwrap()
        .unwrap();
    let forged = EquityRollForwardCertificate::decode(&frame(
        &incomplete_source.certificate,
        expected,
        certified.certificate.output(),
    ))
    .unwrap();
    assert!(
        h.book
            .replay_equity_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged, expected)
            .unwrap()
            .is_err(),
        "a valid source missing a zero expense leaf cannot prove the whole equity statement"
    );
    let mut corrupted = certified.certificate.canonical_bytes().unwrap();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(EquityRollForwardCertificate::decode(&corrupted).is_err());
    assert_eq!(h.head(), before);
}

#[test]
fn equity_replay_binds_roles_dates_units_label_prefix_and_current_authority() {
    let mut h = Harness::new();
    h.post(10, b"equity-replay", h.usd, 50);
    let certified = certify(&h);
    let request = certified.certificate.request();
    let mut variants = Vec::new();
    let mut changed = request.clone();
    changed.distribution_accounts = std::mem::take(&mut changed.issuance_accounts);
    variants.push(changed);
    let mut changed = request.clone();
    changed.effective_from = day(9);
    variants.push(changed);
    let mut changed = request.clone();
    changed.effective_through = day(21);
    variants.push(changed);
    let mut changed = request.clone();
    changed.label.push('!');
    variants.push(changed);
    let mut changed = request.clone();
    changed.units = vec![h.jpy.0];
    variants.push(changed);
    let mut changed = request.clone();
    changed.known_at = None;
    variants.push(changed);
    for expected in variants {
        assert!(
            h.book
                .replay_equity_roll_forward(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &certified.certificate,
                    &expected
                )
                .unwrap()
                .is_err(),
            "{expected:?}"
        );
    }
    let bytes = certified.certificate.canonical_bytes().unwrap();
    assert!(
        h.book
            .replay_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(certified.certificate.digest())
            )
            .unwrap()
            .is_err(),
        "a public digest never supplies the recipient's classification choices"
    );
    assert!(
        h.book
            .certify_equity_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), request)
            .unwrap()
            .is_err(),
        "certification requires produce"
    );
    assert!(
        h.book
            .replay_equity_roll_forward(
                &h.cx(),
                VId(99),
                &cap(&["read"]),
                &certified.certificate,
                request
            )
            .unwrap()
            .is_err(),
        "the saved producer grants no current authority"
    );
}
