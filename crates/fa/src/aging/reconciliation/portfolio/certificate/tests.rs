use super::super::test_support::*;
use super::*;

fn certify(h: &Harness, request: &AgingPortfolioRequest) -> CertifiedAgingPortfolio {
    h.book
        .certify_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap()
}
fn replay(
    h: &Harness,
    certificate: &AgingPortfolioCertificate,
    expected: &AgingPortfolioRequest,
) -> Outcome<AgingPortfolio> {
    h.book
        .replay_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read"]), certificate, expected)
}
fn reseal(
    original: &AgingPortfolioCertificate,
    report: &AgingPortfolio,
) -> AgingPortfolioCertificate {
    AgingPortfolioCertificate::seal(
        original.aging.clone(),
        original.control.clone(),
        original.scope.clone(),
        original.producer,
        original.capability_commitment,
        report.canonical_bytes().unwrap(),
    )
    .unwrap()
}

#[test]
fn one_source_pair_roundtrips_and_matches_the_uncertified_portfolio_without_writes() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post(
        "payment",
        "2026-03-15",
        h.usd,
        ("cash", "ar"),
        40,
        Some(invoice),
    );
    let at = h.head();
    let certified = certify(&h, &h.request());
    assert_eq!(certified.report, h.report(&h.request()));
    assert_eq!(
        certified.certificate.request().unwrap(),
        *certified.report.request()
    );
    assert_eq!(
        certified
            .certificate
            .aging_source()
            .request()
            .unwrap()
            .account,
        None
    );
    assert_eq!(certified.certificate.producer(), PRINCIPAL);
    assert_eq!(
        *certified.certificate.capability_commitment(),
        cap(&["read", "produce"]).commitment().unwrap()
    );
    let encoded = certified.certificate.canonical_bytes().unwrap();
    let decoded = AgingPortfolioCertificate::decode(&encoded).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(
        decoded.output(),
        certified.report.canonical_bytes().unwrap()
    );
    assert_eq!(
        replay(&h, &decoded, certified.report.request())
            .unwrap()
            .unwrap(),
        certified.report
    );
    let composed = h
        .book
        .certify_aging_portfolio_from_sources(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            decoded.aging_source(),
            decoded.control_source(),
            certified.report.request(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(composed, certified);
    assert_eq!(h.head(), at);
}

#[test]
fn later_payments_and_new_zero_accounts_do_not_replace_saved_coverage_after_reopen() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let saved = certify(&h, &h.request());
    let aging_bytes = saved.certificate.aging_source().canonical_bytes().unwrap();
    let control_bytes = saved
        .certificate
        .control_source()
        .canonical_bytes()
        .unwrap();
    h.post(
        "later",
        "2026-03-20",
        h.usd,
        ("cash", "ar"),
        30,
        Some(invoice),
    );
    h.add_leaf("later-zero");
    let h = h.reopen();
    assert_eq!(
        replay(&h, &saved.certificate, saved.report.request())
            .unwrap()
            .unwrap(),
        saved.report
    );
    let composed = h
        .book
        .certify_aging_portfolio_from_sources(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            saved.certificate.aging_source(),
            saved.certificate.control_source(),
            saved.report.request(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(composed.certificate, saved.certificate);
    assert_eq!(
        composed
            .certificate
            .aging_source()
            .canonical_bytes()
            .unwrap(),
        aging_bytes
    );
    assert_eq!(
        composed
            .certificate
            .control_source()
            .canonical_bytes()
            .unwrap(),
        control_bytes
    );
    assert_eq!(composed.report.accounts().len(), 6);
    assert_eq!(certify(&h, &h.request()).report.accounts().len(), 7);
}

#[test]
fn recipient_question_cannot_be_substituted_even_when_all_amounts_are_zero() {
    let h = Harness::new();
    let mut request = h.request();
    request.scope = AgingAccountScope::Selected(vec![h.id("ar"), h.id("cash")]);
    let saved = certify(&h, &request);
    let correct = saved.report.request().clone();
    let mut reordered = correct.clone();
    if let AgingAccountScope::Selected(ids) = &mut reordered.scope {
        ids.reverse();
    }
    assert_eq!(
        replay(&h, &saved.certificate, &reordered).unwrap().unwrap(),
        saved.report
    );
    let mut wrong = Vec::new();
    let mut r = correct.clone();
    r.scope = AgingAccountScope::AllPosting;
    wrong.push(r);
    let mut r = correct.clone();
    r.scope = AgingAccountScope::Selected(vec![h.id("idle")]);
    wrong.push(r);
    let mut r = correct.clone();
    r.scope = AgingAccountScope::Selected(vec![h.id("ar"), h.id("ar")]);
    wrong.push(r);
    let mut r = correct.clone();
    r.known_at = None;
    wrong.push(r);
    let mut r = correct.clone();
    r.known_at = Some(CommitSeq(h.head().0 + 1));
    wrong.push(r);
    let mut r = correct.clone();
    r.effective_through = day("2026-03-30");
    wrong.push(r);
    let mut r = correct;
    r.buckets = AgingBuckets::new(vec![]).unwrap();
    wrong.push(r);
    for request in wrong {
        assert!(replay(&h, &saved.certificate, &request).unwrap().is_err());
        assert!(
            h.book
                .aging_portfolio_jsonl(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    &saved.certificate,
                    &request
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn repaired_outer_checksums_cannot_drop_coverage_or_change_comparisons() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let request = AgingPortfolioRequest {
        scope: AgingAccountScope::Selected(vec![h.id("ar")]),
        ..h.request()
    };
    let good = certify(&h, &request);
    let mut variants = Vec::new();
    let mut r = good.report.clone();
    r.uncovered.clear();
    variants.push(r);
    let mut r = good.report.clone();
    r.accounts.clear();
    variants.push(r);
    let mut r = good.report.clone();
    r.accounts[0].rows[0].difference = 7;
    variants.push(r);
    let mut r = good.report.clone();
    r.accounts[0].rows[0].pending_debits = 7;
    variants.push(r);
    let mut r = good.report.clone();
    r.accounts[0].account.name.push_str(" false");
    variants.push(r);
    for altered in variants {
        let forged = reseal(&good.certificate, &altered);
        let decoded =
            AgingPortfolioCertificate::decode(&forged.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            replay(&h, &decoded, good.report.request())
                .unwrap()
                .unwrap_err()
                .exit,
            exit::VERIFICATION
        );
        assert!(
            h.book
                .aging_portfolio_jsonl(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    &decoded,
                    good.report.request()
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn different_native_prefixes_cutoffs_and_filtered_aging_sources_are_not_composable() {
    let mut h = Harness::new();
    let first = certify(&h, &h.request());
    h.add_leaf("new-zero");
    let second = certify(&h, &h.request());
    assert!(
        h.book
            .certify_aging_portfolio_from_sources(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                first.certificate.aging_source(),
                second.certificate.control_source(),
                first.report.request()
            )
            .unwrap()
            .is_err()
    );
    let filtered = h
        .book
        .certify_effective_date_aging(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &AgingRequest {
                account: Some(h.id("ar")),
                effective_through: day("2026-03-31"),
                known_at: Some(h.head()),
                buckets: AgingBuckets::thirty_day(),
            },
        )
        .unwrap()
        .unwrap();
    assert!(
        h.book
            .certify_aging_portfolio_from_sources(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &filtered.certificate,
                second.certificate.control_source(),
                second.report.request()
            )
            .unwrap()
            .is_err()
    );
    let mut earlier = h.request();
    earlier.effective_through = day("2026-03-30");
    let earlier = certify(&h, &earlier);
    assert!(
        h.book
            .certify_aging_portfolio_from_sources(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                earlier.certificate.aging_source(),
                second.certificate.control_source(),
                earlier.report.request()
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn malformed_containers_and_unbounded_or_noncanonical_scopes_are_refused() {
    let h = Harness::new();
    let request = AgingPortfolioRequest {
        scope: AgingAccountScope::Selected(vec![h.id("ar"), h.id("cash")]),
        ..h.request()
    };
    let saved = certify(&h, &request);
    let bytes = saved.certificate.canonical_bytes().unwrap();
    for end in [0, 1, 4, bytes.len() / 2, bytes.len() - 1] {
        assert!(AgingPortfolioCertificate::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(AgingPortfolioCertificate::decode(&trailing).is_err());
    let mut digest = bytes.clone();
    let last = digest.len() - 1;
    digest[last] ^= 1;
    assert!(AgingPortfolioCertificate::decode(&digest).is_err());
    let scope = 4 + FORMAT.len() + 16 + 32;
    let mut tag = bytes.clone();
    tag[scope] = 255;
    assert!(AgingPortfolioCertificate::decode(&tag).is_err());
    let mut count = bytes.clone();
    count[scope + 1..scope + 5].copy_from_slice(&4097_u32.to_le_bytes());
    assert!(AgingPortfolioCertificate::decode(&count).is_err());
    let mut duplicate = bytes.clone();
    duplicate.copy_within(scope + 5..scope + 21, scope + 21);
    assert!(AgingPortfolioCertificate::decode(&duplicate).is_err());
    let mut reversed = bytes;
    for i in 0..16 {
        reversed.swap(scope + 5 + i, scope + 21 + i);
    }
    assert!(AgingPortfolioCertificate::decode(&reversed).is_err());
}

#[test]
fn workpaper_keeps_control_only_units_exact_amounts_selected_detail_and_uncovered_leaves() {
    use crate::{FxRatePurpose, FxSettlementRequest};
    use fa_model::LegPayload;
    use fa_money::{Amount, Side};

    let mut h = Harness::new();
    let invoice = h.post("usd", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post(
        "fully-paid",
        "2026-03-15",
        h.usd,
        ("cash", "ar"),
        100,
        Some(invoice),
    );
    let exact = (1_i128 << 90) + 1;
    let spot = h.fx_rate("2026-03-01", FxRatePurpose::SpotClose, 2);
    let rate = h.fx_rate("2026-03-15", FxRatePurpose::Settlement, 3);
    let proposal = h.proposal(
        "eur",
        "2026-03-01",
        vec![
            LegPayload::simple(Side::Debit, h.id("ar"), Amount::new(h.eur, exact)),
            LegPayload::simple(Side::Credit, h.id("sales"), Amount::new(h.eur, exact)),
        ],
    );
    let valued = h.value_fx(proposal, spot);
    assert!(
        valued
            .legs
            .iter()
            .all(|leg| leg.base_amount == Some(Amount::new(h.usd, 2 * exact)))
    );
    let eur = h.try_post(valued).unwrap();
    // The existing liability leaf serves as the explicit FX clearing account;
    // its native positions must net to zero in the functional currency.
    let application = FxSettlementRequest {
        target: eur,
        target_ordinal: 0,
        amount: Amount::new(h.eur, 7),
        settlement_amount: Amount::new(h.usd, 21),
        settlement_account: h.id("cash"),
        conversion_account: h.id("ap"),
        realized_fx_account: h.id("sales"),
        rate_document: rate,
    };
    let template = h.proposal("partially-paid", "2026-03-15", Vec::new());
    let before = h.head();
    let rows = h.book.db.vertices().unwrap();
    let mut unexplained_cash = application.clone();
    unexplained_cash.settlement_amount.mantissa = 20;
    let refusal = h
        .prepare_fx(&unexplained_cash, template.clone())
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-071", 3));
    assert_eq!(h.head(), before);
    assert_eq!(h.book.db.vertices().unwrap(), rows);
    let prepared = h.prepare_fx(&application, template).unwrap();
    assert_eq!(
        prepared.carrying().original_base,
        Amount::new(h.usd, 2 * exact)
    );
    assert_eq!(prepared.base_relief(), Amount::new(h.usd, 14));
    let mut altered_relief = prepared.proposal().clone();
    for leg in &mut altered_relief.legs[..2] {
        leg.base_amount.as_mut().unwrap().mantissa += 1;
    }
    let totals = altered_relief.base_totals.as_mut().unwrap();
    totals.debits += 1;
    totals.credits += 1;
    let refusal = h.try_post(altered_relief).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-071", 3));
    assert_eq!(h.head(), before);
    assert_eq!(h.book.db.vertices().unwrap(), rows);
    h.try_post(prepared.into_proposal()).unwrap();

    let remaining = h
        .prepare_fx(
            &FxSettlementRequest {
                amount: Amount::new(h.eur, exact - 7),
                settlement_amount: Amount::new(h.usd, 3 * (exact - 7)),
                ..application
            },
            h.proposal("remaining-payment", "2026-03-15", Vec::new()),
        )
        .unwrap();
    assert_eq!(
        remaining.carrying().open_native,
        Amount::new(h.eur, exact - 7)
    );
    assert_eq!(remaining.carrying().applied_base, Amount::new(h.usd, 14));
    assert_eq!(
        remaining.carrying().open_base,
        Amount::new(h.usd, 2 * exact - 14)
    );
    assert_eq!(remaining.base_relief(), remaining.carrying().open_base);
    let cx = h.cx();
    let functional = h
        .runtime
        .block_on(
            h.book
                .functional_period_activity(&cx, &cap(&["read"]), "FY2026-P03", None),
        )
        .unwrap()
        .unwrap();
    let clearing = functional
        .cells
        .iter()
        .find(|cell| cell.key.account == h.id("ap"))
        .unwrap();
    assert_eq!((clearing.debits, clearing.credits), (14, 14));
    let ar = functional
        .cells
        .iter()
        .find(|cell| cell.key.account == h.id("ar"))
        .unwrap();
    assert_eq!(ar.net(), Some(2 * exact - 14));
    let verification = h.book.verify_fx_conversions(&cx, None).unwrap();
    assert!(verification.is_green(), "{verification:?}");
    assert_eq!(verification.checked.values().sum::<u64>(), 2);
    let request = AgingPortfolioRequest {
        scope: AgingAccountScope::Selected(vec![h.id("ar"), h.id("idle")]),
        ..h.request()
    };
    let saved = certify(&h, &request);
    let at = h.head();
    let text = h
        .book
        .aging_portfolio_jsonl(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &saved.certificate,
            saved.report.request(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        text.matches("\"event\":\"aging_portfolio_unit\"").count(),
        2
    );
    assert_eq!(
        text.matches("\"event\":\"aging_portfolio_control\"")
            .count(),
        2
    );
    assert_eq!(
        text.matches("\"event\":\"aging_portfolio_item\"").count(),
        1
    );
    assert_eq!(
        text.matches("\"event\":\"aging_portfolio_application\"")
            .count(),
        1
    );
    assert_eq!(
        text.matches("\"event\":\"aging_portfolio_account\"")
            .count(),
        6
    );
    assert!(text.contains(&format!("\"original\":\"{exact}\"")));
    assert!(text.contains(&format!("\"open\":\"{}\"", exact - 7)));
    assert!(text.contains("\"posted_debits\":\"100\",\"posted_credits\":\"100\""));
    assert!(text.contains(
        "\"complete\":false,\"selected_reconciled\":true,\"complete_and_reconciled\":false"
    ));
    assert!(
        text.contains("\"external_subledger_attestation\":false,\"period_close_authorized\":false")
    );
    assert!(!text.contains("Portfolio accounting evidence"));
    assert_eq!(
        text,
        h.book
            .aging_portfolio_jsonl(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &saved.certificate,
                saved.report.request()
            )
            .unwrap()
            .unwrap()
    );
    assert_eq!(h.head(), at);
    let cold = h.reopen();
    assert_eq!(
        replay(&cold, &saved.certificate, saved.report.request())
            .unwrap()
            .unwrap(),
        saved.report
    );
    assert_eq!(
        cold.book
            .aging_portfolio_jsonl(
                &cold.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &saved.certificate,
                saved.report.request(),
            )
            .unwrap()
            .unwrap(),
        text
    );
    assert_eq!(cold.head(), at);
}

#[test]
fn an_unvalued_foreign_application_is_refused_without_changing_the_workpaper_source() {
    use fa_model::{LegPayload, Settlement};
    use fa_money::{Amount, Side};

    let mut h = Harness::new();
    let exact = (1_i128 << 90) + 1;
    let invoice = h.post(
        "unvalued-eur",
        "2026-03-01",
        h.eur,
        ("ar", "sales"),
        exact,
        None,
    );
    let before = h.head();
    let rows = h.book.db.vertices().unwrap();
    let report = h.report(&h.request());
    let mut applying = LegPayload::simple(Side::Credit, h.id("ar"), Amount::new(h.eur, 7));
    applying.settles.push(Settlement {
        target: invoice,
        ordinal: 0,
        amount: applying.amount,
    });
    let proposal = h.proposal(
        "unvalued-payment",
        "2026-03-15",
        vec![
            LegPayload::simple(Side::Debit, h.id("cash"), Amount::new(h.eur, 7)),
            applying,
        ],
    );
    let refusal = h.try_post(proposal).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-071", 3));
    assert_eq!(h.head(), before);
    assert_eq!(h.book.db.vertices().unwrap(), rows);
    assert_eq!(h.report(&h.request()), report);
}

#[test]
fn present_authority_is_required_even_with_a_saved_producer_and_corrupt_native_data() {
    use fa_model::symbols::{property, relation};
    use fgdb::{WriteBatch, WriteMismatchPolicy};
    use fgdb_types::CanonicalScalar;
    let mut h = Harness::new();
    let entry = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let saved = certify(&h, &h.request());
    assert!(
        h.book
            .certify_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request())
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .certify_aging_portfolio_from_sources(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                saved.certificate.aging_source(),
                saved.certificate.control_source(),
                saved.report.request()
            )
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .aging_portfolio_jsonl(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &saved.certificate,
                saved.report.request()
            )
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .replay_aging_portfolio(
                &h.cx(),
                VId(99),
                &cap(&["read"]),
                &saved.certificate,
                saved.report.request()
            )
            .unwrap()
            .is_err()
    );
    let cx = h.cx();
    let row = cx
        .query()
        .with_restriction(|| h.book.db.vertex(entry.vid))
        .unwrap()
        .unwrap();
    let original = fa_journal::rows::prop(&row, property::FA_PAYLOAD)
        .cloned()
        .unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        entry.vid,
        property::FA_PAYLOAD,
        Some(original),
        CanonicalScalar::bytes(Vec::new()).unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let at = h.head();
    let refused = h
        .book
        .replay_aging_portfolio(
            &cx,
            PRINCIPAL,
            &cap(&["produce"]),
            &saved.certificate,
            saved.report.request(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::CAPABILITY);
    assert!(!matches!(
        h.book
            .reconcile_aging_portfolio(&cx, PRINCIPAL, &cap(&["read"]), &h.request()),
        Ok(Ok(_))
    ));
    assert_eq!(h.head(), at);
}
