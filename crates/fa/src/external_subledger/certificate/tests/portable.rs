//! Real reviewed detail, signed export, and a detached independent receiver.

use super::*;

fn question(certificate: &ExternalFeedCertificate) -> fa_verify::report::ExternalFeedRequest {
    let request = certificate.request().unwrap();
    fa_verify::report::ExternalFeedRequest {
        feed: request.feed,
        control_account: request.control_account.0,
        effective_through: request.effective_through.0,
        known_at: request.known_at.unwrap().0,
    }
}

fn produce(h: &mut Harness, certificate: &ExternalFeedCertificate) -> crate::ProducedBundle {
    let cx = h.cx();
    let capability = cap(&["read", "produce", "witness"]);
    let checkpoint = h
        .runtime
        .block_on(h.book.checkpoint(&cx, PRINCIPAL, &capability))
        .unwrap()
        .unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let expected = certificate.request().unwrap();
    let before = h.book.head(&cx).unwrap();
    let bundle = h
        .runtime
        .block_on(h.book.produce_external_feed_bundle(
            &cx,
            PRINCIPAL,
            &capability,
            Some(state),
            certificate,
            &expected,
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = h
        .runtime
        .block_on(h.book.produce_external_feed_bundle(
            &cx,
            PRINCIPAL,
            &capability,
            Some(state),
            certificate,
            &expected,
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        bundle, repeated,
        "fixed checkpoint and request reproduce exact bytes and receipt"
    );
    assert_eq!(
        h.book.head(&cx).unwrap(),
        before,
        "export publishes no accounting effects"
    );
    bundle
}

fn verify(
    key: [u8; 32],
    bundle: &crate::ProducedBundle,
    certificate: &ExternalFeedCertificate,
) -> fa_verify::report::VerifiedReport {
    let anchor = fa_verify::verify_checkpoint(&bundle.checkpoint.bytes, &[key]).unwrap();
    let expected = question(certificate);
    let verified = fa_verify::report::verify_report_external_feed_expected(
        &bundle.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&bundle.receipt),
        &expected,
        Some(certificate.digest()),
    )
    .expect("the independent receiver must reproduce every original external-feed output byte");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    let external = verified.external_feed.as_ref().unwrap();
    assert_eq!(external.feed, expected.feed);
    assert_eq!(external.control_account, expected.control_account);
    assert_eq!(external.known_at, expected.known_at);
    assert_eq!(external.effective_through, expected.effective_through);
    assert_eq!(
        external.source_certificate_digest,
        certificate.source_certificate().digest
    );
    assert!(
        fa_verify::report::verify_report_expected(
            &bundle.bundle.bytes,
            &[key],
            None,
            Some(&bundle.receipt),
            Some(certificate.digest()),
        )
        .is_err(),
        "a delivered artifact cannot supply the recipient's external-feed question"
    );

    let args = vec![
        "report".into(),
        "bundle".into(),
        "--key".into(),
        fa_verify::blake3::hex(&key),
        "--receipt".into(),
        "receipt".into(),
        "--expect".into(),
        fa_verify::blake3::hex(certificate.digest()),
        "--external-feed".into(),
        expected.feed,
        "--control-account".into(),
        format!("0x{:032x}", expected.control_account),
        "--through".into(),
        expected.effective_through.to_string(),
        "--known-at".into(),
        expected.known_at.to_string(),
        "--json".into(),
    ];
    let output = fa_verify::cli::run(&args, &|path| match path {
        "bundle" => Ok(bundle.bundle.bytes.clone()),
        "receipt" => Ok(bundle.receipt.clone()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            path.to_string(),
        )),
    });
    assert_eq!(output.exit, 0, "{}{}", output.stdout, output.stderr);
    for expected in [
        "\"report_mode\":\"external_feed_reconciliation\"",
        "\"review_citations\":\"authenticated_journal_at_summary_birth\"",
        "\"native_graph_mirrors\":\"not_judged\"",
        "\"source_system_completeness\":\"not_judged\"",
        "\"human_review_independence\":\"not_judged\"",
    ] {
        assert!(
            output.stdout.contains(expected),
            "{expected}: {}",
            output.stdout
        );
    }
    verified
}

#[test]
fn external_feed_bundles_recompute_gross_detail_reversals_uncovered_and_pending_effects() {
    let mut h = Harness::new();
    let first = h.batch("first", "2026-03-10", 10_000);
    h.batch("second", "2026-03-11", 2_000);
    let saved = h.certify(&h.request("2026-03-15"));
    let original = produce(&mut h, &saved.certificate);
    let reversed = h.reverse(first, "reverse-first", "2026-03-12");
    h.reverse(reversed, "reverse-reversal", "2026-03-13");
    h.post(h.proposal(
        "zero-net-uncovered",
        "2026-03-14",
        h.legs("control", "control", 100),
    ));
    let mut pending = h.proposal("hold", "2026-03-14", h.legs("control", "cash", 400));
    pending.class = EntryClass::PENDING;
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    h.post(pending);
    let current = h.certify(&h.request("2026-03-15"));
    let current_bundle = produce(&mut h, &current.certificate);
    let historical_bundle = produce(&mut h, &saved.certificate);
    let key = h.book.checkpoint_public_key();
    drop(h);

    for bundle in [&original, &historical_bundle] {
        let old = verify(key, bundle, &saved.certificate)
            .external_feed
            .unwrap();
        assert!(old.reconciled);
        assert_eq!(old.batches.len(), 2);
        assert_eq!(old.totals[0].detail_debits, 12_000);
        assert_eq!(old.totals[0].control_debits, 12_000);
        assert_eq!(old.totals[0].pending_debits, 0);
    }
    let current = verify(key, &current_bundle, &current.certificate)
        .external_feed
        .unwrap();
    assert!(!current.reconciled);
    assert_eq!(current.contributions.len(), 4);
    assert_eq!(current.totals[0].detail_debits, 22_000);
    assert_eq!(current.totals[0].detail_credits, 10_000);
    assert_eq!(current.totals[0].control_debits, 22_100);
    assert_eq!(current.totals[0].control_credits, 10_100);
    assert_eq!(current.totals[0].pending_debits, 400);
    assert_eq!(current.totals[0].register_debits_pending, 400);
    assert!(current.unattributed.iter().any(|leg| leg.pending));
}

#[test]
fn external_export_requires_authority_and_an_independently_fixed_question() {
    let mut h = Harness::new();
    h.batch("original", "2026-03-10", 10_000);
    let certified = h.certify(&h.request("2026-03-15"));
    let good = certified.certificate.request().unwrap();
    let cx = h.cx();
    let before = h.book.head(&cx).unwrap();
    let denied = cap(&["read", "produce"])
        .for_accounts(&["control"])
        .unwrap();
    let mut damaged = certified.certificate.clone();
    damaged.output[0] ^= 1;
    let mut first = None;
    for certificate in [&certified.certificate, &damaged] {
        for state in [None, Some(Oid([0xff; 32]))] {
            let refusal = h
                .runtime
                .block_on(h.book.produce_external_feed_bundle(
                    &cx,
                    PRINCIPAL,
                    &denied,
                    state,
                    certificate,
                    &good,
                ))
                .unwrap()
                .unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
            if let Some(first) = &first {
                assert_eq!(&refusal, first);
            } else {
                first = Some(refusal);
            }
        }
    }
    let mut wrong_feed = good.clone();
    wrong_feed.feed = "different-feed".into();
    let mut wrong_account = good.clone();
    wrong_account.control_account = h.id("cash");
    let mut wrong_cutoff = good.clone();
    wrong_cutoff.effective_through = day("2026-03-14");
    let mut unfixed = good;
    unfixed.known_at = None;
    for question in [wrong_feed, wrong_account, wrong_cutoff, unfixed] {
        let refusal = h
            .runtime
            .block_on(h.book.produce_external_feed_bundle(
                &cx,
                PRINCIPAL,
                &cap(&["read", "produce"]),
                None,
                &certified.certificate,
                &question,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    }
    assert_eq!(h.book.head(&cx).unwrap(), before);
}
