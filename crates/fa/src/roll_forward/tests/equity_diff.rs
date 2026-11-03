//! Original equity certificates, independent roles and exact recorded-time changes.

use super::*;
use crate::{
    CertifiedEquityRollForward, EquityRollForwardCertificate, EquityRollForwardDiff,
    EquityRollForwardDiffCertificate, EquityRollForwardDiffRequest, ReportArtifact,
    ReportArtifactExpectation, ReportArtifactFamily,
};
use fa_model::{Writer, domain_digest};

fn question(h: &Harness) -> EquityRollForwardRequest {
    EquityRollForwardRequest {
        units: vec![h.usd.0, h.jpy.0],
        label: "Equity January 10–20".into(),
        effective_from: day(10),
        effective_through: day(20),
        known_at: Some(h.head()),
        issuance_accounts: vec![h.id("3000")],
        distribution_accounts: Vec::new(),
    }
}

fn certify(h: &Harness, request: &EquityRollForwardRequest) -> CertifiedEquityRollForward {
    h.book
        .certify_equity_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap()
}

fn change(report: &EquityRollForwardDiff, unit: u32, code: &str) -> (i128, i128, i128) {
    let line = report
        .units()
        .iter()
        .find(|row| row.unit_id == unit)
        .unwrap()
        .lines
        .iter()
        .find(|row| row.code == code)
        .unwrap();
    (line.before, line.after, line.delta)
}

fn equity_frame(
    certificate: &EquityRollForwardCertificate,
    output: &[u8],
    legacy: bool,
) -> EquityRollForwardCertificate {
    let request = certificate.request();
    let mut w = Writer::new();
    w.bytes(if legacy {
        b"fa:equity-roll-forward-certificate:v1"
    } else {
        crate::EQUITY_CERTIFICATE_FORMAT
    })
    .bytes(&certificate.source_certificate().canonical_bytes().unwrap())
    .list(&request.issuance_accounts, |w, id| {
        w.u128(id.0);
    })
    .list(&request.distribution_accounts, |w, id| {
        w.u128(id.0);
    })
    .bytes(output);
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(
        if legacy {
            b"fa:equity-roll-forward-certificate-digest:v1"
        } else {
            b"fa:equity-roll-forward-certificate-digest:v2"
        },
        &[&bytes],
    );
    bytes.extend_from_slice(&digest);
    EquityRollForwardCertificate::decode(&bytes).unwrap()
}

fn diff_frame(
    before: &EquityRollForwardCertificate,
    after: &EquityRollForwardCertificate,
    output: &[u8],
) -> Result<EquityRollForwardDiffCertificate, Refusal> {
    let mut w = Writer::new();
    w.bytes(crate::EQUITY_DIFF_CERTIFICATE_FORMAT)
        .bytes(&before.canonical_bytes().unwrap())
        .bytes(&after.canonical_bytes().unwrap())
        .u128(PRINCIPAL.0)
        .fixed(&cap(&["read", "produce"]).commitment().unwrap())
        .bytes(output);
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(
        b"fa:equity-roll-forward-diff-certificate-digest:v1",
        &[&bytes],
    );
    bytes.extend_from_slice(&digest);
    EquityRollForwardDiffCertificate::decode(&bytes)
}

#[test]
fn equity_comparison_preserves_both_originals_and_every_unit_row() {
    let mut h = Harness::new();
    h.post(1, b"equity-diff-opening", h.usd, 100);
    h.post(10, b"equity-diff-issued", h.usd, 50);
    let before = certify(&h, &question(&h));
    h.post(5, b"equity-diff-late-opening", h.usd, 7);
    h.post(15, b"equity-diff-owner-withdrawal", h.usd, -20);
    let after = certify(&h, &question(&h));
    let expected = EquityRollForwardDiffRequest {
        before: before.certificate.request().clone(),
        after: after.certificate.known_at(),
    };
    let head = h.head();
    let certified = h
        .book
        .compare_equity_roll_forward_certificates(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &before.certificate,
            &after.certificate,
            &expected,
        )
        .unwrap()
        .unwrap();
    let report = &certified.report;
    assert_eq!(report.before(), &before.report);
    assert_eq!(report.after(), &after.report);
    assert_eq!(report.units().len(), 2);
    assert!(report.units().iter().all(|unit| unit.lines.len() == 15));
    assert_eq!(
        change(report, h.usd.0, "opening_total_equity"),
        (100, 107, 7)
    );
    assert_eq!(change(report, h.usd.0, "issuances"), (50, 30, -20));
    assert_eq!(
        change(report, h.usd.0, "closing_total_equity"),
        (150, 137, -13)
    );
    assert_eq!(
        change(report, h.usd.0, "equity_tie_out_residual"),
        (0, 0, 0)
    );
    assert!(
        report
            .units()
            .iter()
            .find(|u| u.unit_id == h.jpy.0)
            .unwrap()
            .lines
            .iter()
            .all(|l| { (l.before, l.after, l.delta) == (0, 0, 0) })
    );
    assert!(!report.is_unchanged());
    let (old, new) = certified.certificate.sources();
    assert_eq!(
        old.canonical_bytes().unwrap(),
        before.certificate.canonical_bytes().unwrap()
    );
    assert_eq!(
        new.canonical_bytes().unwrap(),
        after.certificate.canonical_bytes().unwrap()
    );
    assert_eq!(
        h.book
            .diff_equity_roll_forward_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                old,
                new,
                &expected,
            )
            .unwrap()
            .unwrap(),
        *report,
    );
    assert_eq!(h.head(), head, "comparison and replay publish nothing");

    let bytes = certified.certificate.canonical_bytes().unwrap();
    let artifact = ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(
        artifact.family(),
        ReportArtifactFamily::EquityRollForwardDiff
    );
    assert_eq!(artifact.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        artifact.equity_roll_forward_diff_certificate(),
        Some(&certified.certificate)
    );
    assert!(artifact.equity_roll_forward_certificate().is_none());
    assert_eq!(certified.certificate.request().unwrap(), expected);
    let request_bytes = expected.canonical_bytes().unwrap();
    assert_eq!(
        EquityRollForwardDiffRequest::decode(&request_bytes).unwrap(),
        expected
    );
    let expectation = ReportArtifactExpectation::EquityRollForwardDiff(&expected);
    assert_eq!(
        h.book
            .replay_report_artifact_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                None,
                expectation,
            )
            .unwrap()
            .unwrap()
            .output,
        report.canonical_bytes().unwrap(),
    );
    assert!(
        h.book
            .replay_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
            )
            .unwrap()
            .is_err(),
        "the digest cannot replace independent role expectations"
    );

    h.post(21, b"equity-diff-outside-date", h.usd, 99);
    assert_eq!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                None,
                expectation,
            )
            .unwrap()
            .unwrap(),
        crate::CertificateStatus::Current {
            checked_at: h.head()
        },
    );
    h.post(2, b"equity-diff-new-opening", h.usd, 1);
    assert!(matches!(
        h.book.report_artifact_status(
            &h.cx(), PRINCIPAL, &cap(&["read"]), &bytes, None, expectation,
        ).unwrap().unwrap(),
        crate::CertificateStatus::SupersededBy { later_entries, .. } if later_entries.len() == 1
    ));
    assert_eq!(
        h.book
            .replay_equity_roll_forward_diff(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &certified.certificate,
                &expected,
            )
            .unwrap()
            .unwrap(),
        *report,
    );
}

#[test]
fn equity_comparison_refuses_role_date_unit_source_and_expected_question_drift() {
    let mut h = Harness::new();
    h.post(10, b"equity-diff-question", h.usd, 50);
    let before = certify(&h, &question(&h));
    h.post(15, b"equity-diff-question-later", h.usd, 20);
    let after = certify(&h, &question(&h));
    let expected = EquityRollForwardDiffRequest {
        before: before.certificate.request().clone(),
        after: after.certificate.known_at(),
    };
    let mut alternatives = Vec::new();
    let mut roles = question(&h);
    roles.issuance_accounts.clear();
    alternatives.push(roles);
    let mut distribution = question(&h);
    distribution.distribution_accounts = std::mem::take(&mut distribution.issuance_accounts);
    alternatives.push(distribution);
    let mut date = question(&h);
    date.effective_from = day(11);
    alternatives.push(date);
    let mut units = question(&h);
    units.units = vec![h.usd.0];
    alternatives.push(units);
    let mut label = question(&h);
    label.label.push_str(" changed");
    alternatives.push(label);
    for question in alternatives {
        let other = certify(&h, &question);
        let error = h
            .book
            .diff_equity_roll_forward_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &before.certificate,
                &other.certificate,
                &expected,
            )
            .unwrap()
            .unwrap_err();
        assert!(
            error
                .message
                .contains("same book, trunk, dates, units and roles")
        );
        let wrong_expected = EquityRollForwardDiffRequest {
            before: EquityRollForwardRequest {
                known_at: expected.before.known_at,
                ..question
            },
            after: expected.after,
        };
        let error = h
            .book
            .diff_equity_roll_forward_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &before.certificate,
                &after.certificate,
                &wrong_expected,
            )
            .unwrap()
            .unwrap_err();
        assert!(error.message.contains("independently expected"));
    }
    let mut unpinned = expected.clone();
    unpinned.before.known_at = None;
    assert!(unpinned.canonical_bytes().is_err());
    let mut reverse = expected.clone();
    reverse.after = CommitSeq(expected.before.known_at.unwrap().0 - 1);
    assert!(reverse.canonical_bytes().is_err());
    let denial = h
        .book
        .compare_equity_roll_forward_certificates(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &before.certificate,
            &after.certificate,
            &expected,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denial.exit, 7,
        "certification needs current Produce authority"
    );
    let denial = h
        .book
        .diff_equity_roll_forward_certificates(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]).for_accounts(&["3000"]).unwrap(),
            &before.certificate,
            &after.certificate,
            &expected,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denial.exit, 7,
        "selected roles cannot authorize the whole-book source closure"
    );
}

#[test]
fn equity_comparison_refuses_rehashed_output_and_omitted_movement_evidence() {
    let mut h = Harness::new();
    h.post(10, b"equity-diff-forgery-before", h.usd, 50);
    let before = certify(&h, &question(&h));
    // Offset exactly: the monetary comparison is unchanged, but the original
    // report commitments must retain both genuine new movements.
    h.post(15, b"equity-diff-forgery-positive", h.usd, 9);
    h.post(16, b"equity-diff-forgery-negative", h.usd, -9);
    let after = certify(&h, &question(&h));
    let expected = EquityRollForwardDiffRequest {
        before: before.certificate.request().clone(),
        after: after.certificate.known_at(),
    };
    let certified = h
        .book
        .compare_equity_roll_forward_certificates(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &before.certificate,
            &after.certificate,
            &expected,
        )
        .unwrap()
        .unwrap();
    assert!(certified.report.is_unchanged());
    assert_eq!(
        certified.report.after().movements.len(),
        certified.report.before().movements.len() + 2
    );
    let mut wrong_output = certified.certificate.output().to_vec();
    *wrong_output.last_mut().unwrap() ^= 1;
    let forged = diff_frame(&before.certificate, &after.certificate, &wrong_output).unwrap();
    assert!(
        h.book
            .replay_equity_roll_forward_diff(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &forged,
                &expected,
            )
            .unwrap()
            .is_err()
    );

    let mut omitted = after.report.clone();
    omitted.movements.truncate(before.report.movements.len());
    assert_eq!(omitted.statement, after.report.statement);
    let source = equity_frame(
        &after.certificate,
        &omitted.canonical_bytes().unwrap(),
        false,
    );
    let forged = diff_frame(&before.certificate, &source, certified.certificate.output()).unwrap();
    let error = h
        .book
        .replay_equity_roll_forward_diff(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged, &expected)
        .unwrap()
        .unwrap_err();
    assert!(error.message.contains("movement citations did not replay"));
    assert!(
        h.book
            .compare_equity_roll_forward_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &before.certificate,
                &source,
                &expected,
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn equity_comparison_zero_interval_preserves_identity_and_refuses_v1() {
    let mut h = Harness::new();
    h.post(10, b"equity-diff-zero", h.usd, 50);
    let source = certify(&h, &question(&h));
    let expected = EquityRollForwardDiffRequest {
        before: source.certificate.request().clone(),
        after: source.certificate.known_at(),
    };
    let identical = h
        .book
        .compare_equity_roll_forward_certificates(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &source.certificate,
            &source.certificate,
            &expected,
        )
        .unwrap()
        .unwrap();
    assert!(identical.report.is_unchanged());
    assert_eq!(
        identical.certificate.sources().0,
        identical.certificate.sources().1
    );

    let other = h
        .book
        .certify_equity_roll_forward(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce", "post"]),
            source.certificate.request(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(other.report, source.report);
    assert_eq!(
        other.certificate, source.certificate,
        "the original source format binds the accounting inputs, not the reader's extra permissions"
    );
    let other_comparison = h
        .book
        .compare_equity_roll_forward_certificates(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce", "post"]),
            &source.certificate,
            &source.certificate,
            &expected,
        )
        .unwrap()
        .unwrap();
    assert_eq!(other_comparison.report, identical.report);
    assert_eq!(
        other_comparison.certificate.sources(),
        identical.certificate.sources()
    );
    assert_ne!(
        other_comparison.certificate.capability_commitment(),
        identical.certificate.capability_commitment(),
        "the comparison retains its producer capability as original provenance"
    );

    // A canonical, rehashed frame may still omit original provenance. Keep
    // the exact same question, native source and statement amounts so the
    // equal-frontier identity guard is exercised independently of scope refusals.
    let mut omitted = source.report.clone();
    assert_eq!(omitted.movements.len(), 1);
    omitted.movements.clear();
    assert_eq!(omitted.statement, source.report.statement);
    let different = equity_frame(
        &source.certificate,
        &omitted.canonical_bytes().unwrap(),
        false,
    );
    assert_eq!(different.request(), source.certificate.request());
    assert_eq!(
        different.source_certificate(),
        source.certificate.source_certificate()
    );
    assert_ne!(different, source.certificate);
    assert!(
        h.book
            .diff_equity_roll_forward_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &source.certificate,
                &different,
                &expected,
            )
            .unwrap()
            .unwrap_err()
            .message
            .contains("identical original certificate")
    );
    assert!(
        diff_frame(
            &source.certificate,
            &different,
            identical.certificate.output()
        )
        .is_err()
    );

    let legacy = equity_frame(
        &source.certificate,
        &source.report.canonical_bytes_for(true).unwrap(),
        true,
    );
    assert!(
        h.book
            .diff_equity_roll_forward_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &legacy,
                &legacy,
                &expected,
            )
            .unwrap()
            .unwrap_err()
            .message
            .contains("original v2")
    );
    assert!(diff_frame(&legacy, &legacy, identical.certificate.output()).is_err());
    assert_eq!(
        h.book
            .replay_equity_roll_forward(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &legacy,
                &expected.before,
            )
            .unwrap()
            .unwrap(),
        source.report,
        "legacy single-report replay remains valid"
    );
}
