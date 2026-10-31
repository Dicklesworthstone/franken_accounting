//! Real signed producer artifacts cross the dependency-free verifier boundary.
//! Repaired checksums deliberately bypass integrity-only failures so missing
//! zero-account coverage must fail the independent accounting reconstruction.

use super::*;
use fa_model::{Reader, Writer};
use fa_verify::report::{
    AgingPortfolioRequest as ExpectedPortfolio, AgingPortfolioScope as ExpectedScope,
    verify_aging_portfolio_report_expected, verify_report_expected,
};

fn expectation(request: &AgingPortfolioRequest) -> ExpectedPortfolio {
    ExpectedPortfolio {
        scope: match &request.scope {
            AgingAccountScope::AllPosting => ExpectedScope::AllPosting,
            AgingAccountScope::Selected(ids) => {
                ExpectedScope::Selected(ids.iter().map(|id| id.0).collect())
            }
        },
        known_at: request.known_at.unwrap().0,
        effective_through: request.effective_through.0,
        upper_bounds: request.buckets.upper_bounds().to_vec(),
    }
}

fn produce(h: &mut Harness, certified: &CertifiedAgingPortfolio) -> crate::ProducedBundle {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.checkpoint(&cx, PRINCIPAL, &cap(&["witness"])))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(h.book.produce_aging_portfolio_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            &certified.certificate,
            certified.report.request(),
        ))
        .unwrap()
        .unwrap()
        .expect("checkpoint covers the original portfolio sources")
}

fn replace_certificate(bundle: &[u8], certificate: &AgingPortfolioCertificate) -> Vec<u8> {
    let mut r = Reader::new(bundle);
    let format = r.bytes(64, "format").unwrap();
    let major = r.u16("major").unwrap();
    let minor = r.u16("minor").unwrap();
    r.bytes(64 * 1024 * 1024, "certificate").unwrap();
    let mut w = Writer::new();
    w.bytes(format)
        .u16(major)
        .u16(minor)
        .bytes(&certificate.canonical_bytes().unwrap())
        .fixed(&bundle[r.offset()..]);
    w.finish().unwrap()
}

#[test]
fn historical_multicurrency_portfolio_exports_original_sources_and_zero_accounts() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post("euro-sale", "2026-03-02", h.eur, ("ar", "sales"), 75, None);
    h.post(
        "payment",
        "2026-03-15",
        h.usd,
        ("cash", "ar"),
        40,
        Some(invoice),
    );
    let mut pending = h.proposal(
        "pending-ar-cash",
        "2026-03-16",
        vec![
            fa_model::LegPayload::simple(
                fa_money::Side::Debit,
                h.id("ar"),
                fa_money::Amount::new(h.usd, 17),
            ),
            fa_model::LegPayload::simple(
                fa_money::Side::Credit,
                h.id("cash"),
                fa_money::Amount::new(h.usd, 17),
            ),
        ],
    );
    pending.class = fa_model::EntryClass::PENDING;
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    h.try_post(pending).unwrap();
    let saved = certify(&h, &h.request());
    let expected = expectation(saved.report.request());
    // The checkpoint may cover a later journal. It must not replace the
    // certificate's historical sources, chart partition or accounting question.
    h.post(
        "later-payment",
        "2026-03-20",
        h.usd,
        ("cash", "ar"),
        20,
        Some(invoice),
    );
    h.add_leaf("later-zero");
    let mut h = h.reopen();
    let produced = produce(&mut h, &saved);
    let key = h.book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = verify_aging_portfolio_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        &expected,
        Some(saved.certificate.digest()),
    )
    .expect("both original sources independently recompute from the signed prefix");
    assert_eq!(verified.certificate_digest, *saved.certificate.digest());
    assert_eq!(verified.output, saved.certificate.output());
    assert_eq!(verified.known_at, expected.known_at);
    let report = verified.aging_portfolio.unwrap();
    assert_eq!(report.accounts.len(), 6);
    assert!(report.is_complete_and_reconciled());
    assert!(report.has_pending_reservations());
    assert!(report.uncovered_accounts.is_empty());
    assert!(
        !report
            .accounts
            .iter()
            .any(|a| a.account.code == "summary" || a.account.code == "later-zero")
    );
    let idle = report
        .accounts
        .iter()
        .find(|a| a.account.code == "idle")
        .unwrap();
    assert!(
        idle.rows.is_empty(),
        "zero leaves are covered without invented unit rows"
    );
    let ar = report
        .accounts
        .iter()
        .find(|a| a.account.code == "ar")
        .unwrap();
    assert_eq!(
        ar.rows.len(),
        2,
        "native currencies must not be netted together"
    );
    let usd = ar.rows.iter().find(|row| row.unit_id == h.usd.0).unwrap();
    assert_eq!((usd.posted_debits, usd.posted_credits), (100, 40));
    assert_eq!((usd.pending_debits, usd.pending_credits), (17, 0));
    assert_eq!(
        (usd.open_debits, usd.open_credits, usd.open_net),
        (60, 0, 60)
    );
    let eur = ar.rows.iter().find(|row| row.unit_id == h.eur.0).unwrap();
    assert_eq!((eur.posted_net, eur.open_net, eur.difference), (75, 75, 0));
    assert_eq!(
        report.aging_certificate_digest,
        *saved.certificate.aging_source().digest()
    );
    assert_eq!(
        report.control_certificate_digest,
        saved.certificate.control_source().digest
    );
    // A native source digest cannot pin the composed question, even with a
    // valid signed receipt accompanying the exact same bundle.
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&checkpoint.checkpoint),
            Some(&produced.receipt),
            Some(&saved.certificate.aging_source().source().digest),
        )
        .is_err()
    );
}

#[test]
fn zero_portfolios_require_exact_recipient_scope_and_all_historical_chart_leaves() {
    let mut h = Harness::new();
    let selected = certify(
        &h,
        &AgingPortfolioRequest {
            scope: AgingAccountScope::Selected(vec![h.id("ar"), h.id("idle")]),
            ..h.request()
        },
    );
    let all = certify(&h, &h.request());
    let produced = produce(&mut h, &selected);
    let key = h.book.checkpoint_public_key();
    let expected = expectation(selected.report.request());
    let verify = |request: &ExpectedPortfolio| {
        verify_aging_portfolio_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            request,
            Some(selected.certificate.digest()),
        )
    };
    let good = verify(&expected).unwrap().aging_portfolio.unwrap();
    assert_eq!((good.accounts.len(), good.uncovered_accounts.len()), (2, 4));
    assert!(good.accounts.iter().all(|account| account.rows.is_empty()));
    assert!(good.is_reconciled());
    assert!(!good.is_complete_and_reconciled());
    let mut wrong = Vec::new();
    let mut request = expected.clone();
    request.scope = ExpectedScope::AllPosting;
    wrong.push(request);
    let mut request = expected.clone();
    request.scope = ExpectedScope::Selected(vec![h.id("ar").0]);
    wrong.push(request);
    let mut request = expected.clone();
    request.scope = ExpectedScope::Selected(vec![h.id("ar").0, h.id("ar").0]);
    wrong.push(request);
    let mut request = expected.clone();
    request.known_at += 1;
    wrong.push(request);
    let mut request = expected.clone();
    request.effective_through -= 1;
    wrong.push(request);
    let mut request = expected.clone();
    request.upper_bounds.clear();
    wrong.push(request);
    for request in wrong {
        assert!(
            verify(&request).is_err(),
            "zero balances cannot substitute another request"
        );
    }
    // Re-signing/re-pinning a certificate with a shortened coverage list must
    // still fail: completeness derives from authenticated chart declarations.
    for omit_selected in [false, true] {
        let mut altered = selected.report.clone();
        if omit_selected {
            altered.accounts.pop();
        } else {
            altered.uncovered.pop();
        }
        let forged = reseal(&selected.certificate, &altered);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        let error = verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
            .expect_err("missing zero account must fail independent recomputation");
        assert_eq!(error.predicate, "report_recomputation");
    }
    let produced = produce(&mut h, &all);
    let mut all_ids: Vec<_> = all
        .report
        .accounts()
        .iter()
        .map(|a| a.account().vid.0)
        .collect();
    all_ids.sort_unstable();
    let mut same_coverage = expectation(all.report.request());
    same_coverage.scope = ExpectedScope::Selected(all_ids);
    assert!(
        verify_aging_portfolio_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            &same_coverage,
            Some(all.certificate.digest()),
        )
        .is_err(),
        "all-posting is distinct from a complete hand-picked subset"
    );
    let mut shortened = all.report.clone();
    shortened.accounts.retain(|a| a.account().code != "idle");
    let forged = reseal(&all.certificate, &shortened);
    let bundle = replace_certificate(&produced.bundle.bytes, &forged);
    assert_eq!(
        verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
}

#[test]
fn repaired_outer_digests_cannot_change_comparisons_metadata_or_signed_payload_closure() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let saved = certify(
        &h,
        &AgingPortfolioRequest {
            scope: AgingAccountScope::Selected(vec![h.id("ar")]),
            ..h.request()
        },
    );
    let produced = produce(&mut h, &saved);
    let key = h.book.checkpoint_public_key();
    let mut variants = Vec::new();
    let mut altered = saved.report.clone();
    altered.accounts[0].rows[0].difference = 7;
    variants.push(altered);
    let mut altered = saved.report.clone();
    altered.accounts[0].rows[0].pending_debits = 7;
    variants.push(altered);
    let mut altered = saved.report.clone();
    altered.uncovered[0].name.push_str(" substituted");
    variants.push(altered);
    for altered in variants {
        let forged = reseal(&saved.certificate, &altered);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        assert_eq!(
            verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
                .unwrap_err()
                .predicate,
            "report_recomputation"
        );
    }
    // Remove one payload while preserving the signed checkpoint, its prefix
    // proof and the certificate. The count is repaired to avoid a mere parse
    // failure: the disclosed record set is now incomplete.
    let bytes = &produced.bundle.bytes;
    let mut r = Reader::new(bytes);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(64 * 1024 * 1024, "certificate").unwrap();
    r.bytes(64 * 1024 * 1024, "checkpoint").unwrap();
    r.bytes(64 * 1024 * 1024, "prefix").unwrap();
    let count_offset = r.offset();
    let count = r.u32("records").unwrap();
    assert!(count > 0);
    r.u32("proposal length").unwrap();
    r.bytes(64 * 1024 * 1024, "record").unwrap();
    let mut w = Writer::new();
    w.fixed(&bytes[..count_offset])
        .u32(count - 1)
        .fixed(&bytes[r.offset()..]);
    let incomplete = w.finish().unwrap();
    assert!(
        verify_report_expected(
            &incomplete,
            &[key],
            None,
            None,
            Some(saved.certificate.digest()),
        )
        .is_err()
    );
}
