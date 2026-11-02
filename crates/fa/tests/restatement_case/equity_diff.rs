//! Producer-to-recipient comparison of a real approved prior-period adjustment.
//! Invoked by the full case lifecycle fixture, after its atomic Post and before
//! disclosure. These comparisons do not replace the mandatory case disclosures.

use super::*;

pub(super) fn verify_posted_adjustment_comparison(
    book: &mut Book,
    capability: &Capability,
    before: &fa::CertifiedEquityRollForward,
    after: &fa::CertifiedEquityRollForward,
    original_request: &fa::EquityRollForwardRequest,
    state: Oid,
) {
    let expected = fa::EquityRollForwardDiffRequest {
        before: original_request.clone(),
        after: after.certificate.known_at(),
    };
    let head = book.head().unwrap();
    let comparison = book
        .compare_equity_roll_forward_certificates(
            PRINCIPAL,
            capability,
            &before.certificate,
            &after.certificate,
            &expected,
        )
        .unwrap()
        .unwrap();
    let certificate = &comparison.certificate;
    assert_eq!(comparison.report.before(), &before.report);
    assert_eq!(comparison.report.after(), &after.report);
    assert_eq!(
        certificate.sources().0.canonical_bytes().unwrap(),
        before.certificate.canonical_bytes().unwrap()
    );
    assert_eq!(
        certificate.sources().1.canonical_bytes().unwrap(),
        after.certificate.canonical_bytes().unwrap()
    );
    let wanted = [
        ("opening_contributed_equity", 0),
        ("opening_unclosed_earnings", 0),
        ("opening_total_equity", 0),
        ("prior_period_adjustments", 50_000),
        ("opening_equity_as_adjusted", 50_000),
        ("net_income", 0),
        ("issuances", 0),
        ("distributions", 0),
        ("other_equity_movements", 0),
        ("closing_transfers_net", 0),
        ("net_equity_change", 50_000),
        ("closing_contributed_equity", 50_000),
        ("closing_unclosed_earnings", 0),
        ("closing_total_equity", 50_000),
        ("equity_tie_out_residual", 0),
    ];
    assert_eq!(comparison.report.units().len(), 1);
    let lines = &comparison.report.units()[0].lines;
    assert_eq!(lines.len(), wanted.len());
    for (line, (code, amount)) in lines.iter().zip(wanted) {
        assert_eq!(line.code, code);
        assert_eq!((line.before, line.after, line.delta), (0, amount, amount));
    }
    let bundle = book
        .produce_equity_roll_forward_diff_bundle(
            PRINCIPAL,
            capability,
            Some(state),
            certificate,
            &expected,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    let again = book
        .produce_equity_roll_forward_diff_bundle(
            PRINCIPAL,
            capability,
            Some(state),
            certificate,
            &expected,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(bundle.bundle.bytes, again.bundle.bytes);
    assert_eq!(bundle.receipt, again.receipt);
    assert_eq!(book.head().unwrap(), head);

    // This request was selected before Post, apart from the delivered bundle.
    // Its canonical bytes must agree across two separately implemented codecs.
    let request_bytes = expected.canonical_bytes().unwrap();
    let recipient =
        fa_verify::report::EquityRollForwardDiffRequest::decode(&request_bytes).unwrap();
    assert_eq!(recipient.canonical_bytes().unwrap(), request_bytes);
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&bundle.checkpoint.bytes, &[key]).unwrap();
    let verify = |question: &fa_verify::report::EquityRollForwardDiffRequest, pin| {
        fa_verify::report::verify_equity_roll_forward_diff_report_expected(
            &bundle.bundle.bytes,
            &[key],
            Some(&anchor.checkpoint),
            Some(&bundle.receipt),
            question,
            Some(pin),
        )
    };
    let verified = verify(&recipient, certificate.digest())
        .expect("independently recompute both original equity reports around the real case Post");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.known_at, expected.after.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.equity_roll_forward.is_none());
    let proof = verified.equity_roll_forward_diff.unwrap();
    assert!(proof.before.movements.is_empty());
    assert_eq!(proof.after.movements.len(), 1);
    let movement = &proof.after.movements[0];
    assert_eq!(movement.case_ordinal, Some(1));
    assert_eq!(movement.relates_to.as_ref().unwrap().1, "FY2025-P12");
    assert_eq!(
        movement.entry_digest,
        after.report.movements[0].entry_digest
    );
    assert_eq!(proof.units.len(), 1);
    for (line, (code, amount)) in proof.units[0].lines.iter().zip(wanted) {
        assert_eq!(line.code, code);
        assert_eq!((line.before, line.after, line.delta), (0, amount, amount));
    }
    assert_eq!(proof.units[0].lines.len(), wanted.len());
    assert!(verify(&recipient, after.certificate.digest()).is_err());
    let mut changed_roles = recipient.clone();
    changed_roles.issuance_accounts.clear();
    assert!(verify(&changed_roles, certificate.digest()).is_err());
    let mut changed_date = recipient.clone();
    changed_date.effective_from += 1;
    assert!(verify(&changed_date, certificate.digest()).is_err());
    assert!(
        fa_verify::report::verify_report_expected(
            &bundle.bundle.bytes,
            &[key],
            Some(&anchor.checkpoint),
            Some(&bundle.receipt),
            Some(certificate.digest()),
        )
        .is_err(),
        "a receipt and pin do not choose the recipient's equity question"
    );

    let bytes = certificate.canonical_bytes().unwrap();
    book.retain_report_artifact_for(
        PRINCIPAL,
        capability,
        &bytes,
        Some(certificate.digest()),
        fa::ReportArtifactExpectation::EquityRollForwardDiff(&expected),
    )
    .unwrap()
    .unwrap();
    let retained = book
        .read_report_artifact(PRINCIPAL, capability, certificate.digest())
        .unwrap()
        .unwrap();
    assert_eq!(retained.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        retained.family(),
        fa::ReportArtifactFamily::EquityRollForwardDiff
    );
    assert_eq!(
        book.replay_equity_roll_forward_diff(PRINCIPAL, capability, certificate, &expected)
            .unwrap()
            .unwrap(),
        comparison.report
    );
}
