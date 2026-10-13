use super::*;
use super::super::test_support::*;

fn certify(h: &Harness, request: &AgingPortfolioRequest) -> CertifiedAgingPortfolio {
    h.book.certify_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request).unwrap().unwrap()
}
fn replay(h: &Harness, certificate: &AgingPortfolioCertificate, expected: &AgingPortfolioRequest) -> Outcome<AgingPortfolio> {
    h.book.replay_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read"]), certificate, expected)
}
fn reseal(original: &AgingPortfolioCertificate, report: &AgingPortfolio) -> AgingPortfolioCertificate {
    AgingPortfolioCertificate::seal(original.aging.clone(), original.control.clone(), original.scope.clone(),
        original.producer, original.capability_commitment, report.canonical_bytes().unwrap()).unwrap()
}

#[test]
fn one_source_pair_roundtrips_and_matches_the_uncertified_portfolio_without_writes() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post("payment", "2026-03-15", h.usd, ("cash", "ar"), 40, Some(invoice));
    let at = h.head();
    let certified = certify(&h, &h.request());
    assert_eq!(certified.report, h.report(&h.request()));
    assert_eq!(certified.certificate.request().unwrap(), *certified.report.request());
    assert_eq!(certified.certificate.aging_source().request().unwrap().account, None);
    assert_eq!(certified.certificate.producer(), PRINCIPAL);
    assert_eq!(*certified.certificate.capability_commitment(), cap(&["read", "produce"]).commitment().unwrap());
    let encoded = certified.certificate.canonical_bytes().unwrap();
    let decoded = AgingPortfolioCertificate::decode(&encoded).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(decoded.output(), certified.report.canonical_bytes().unwrap());
    assert_eq!(replay(&h, &decoded, certified.report.request()).unwrap().unwrap(), certified.report);
    let composed = h.book.certify_aging_portfolio_from_sources(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        decoded.aging_source(), decoded.control_source(), certified.report.request()).unwrap().unwrap();
    assert_eq!(composed, certified);
    assert_eq!(h.head(), at);
}

#[test]
fn later_payments_and_new_zero_accounts_do_not_replace_saved_coverage_after_reopen() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let saved = certify(&h, &h.request());
    let aging_bytes = saved.certificate.aging_source().canonical_bytes().unwrap();
    let control_bytes = saved.certificate.control_source().canonical_bytes().unwrap();
    h.post("later", "2026-03-20", h.usd, ("cash", "ar"), 30, Some(invoice));
    h.add_leaf("later-zero");
    let h = h.reopen();
    assert_eq!(replay(&h, &saved.certificate, saved.report.request()).unwrap().unwrap(), saved.report);
    let composed = h.book.certify_aging_portfolio_from_sources(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        saved.certificate.aging_source(), saved.certificate.control_source(), saved.report.request()).unwrap().unwrap();
    assert_eq!(composed.certificate, saved.certificate);
    assert_eq!(composed.certificate.aging_source().canonical_bytes().unwrap(), aging_bytes);
    assert_eq!(composed.certificate.control_source().canonical_bytes().unwrap(), control_bytes);
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
    if let AgingAccountScope::Selected(ids) = &mut reordered.scope { ids.reverse(); }
    assert_eq!(replay(&h, &saved.certificate, &reordered).unwrap().unwrap(), saved.report);
    let mut wrong = Vec::new();
    let mut r = correct.clone(); r.scope = AgingAccountScope::AllPosting; wrong.push(r);
    let mut r = correct.clone(); r.scope = AgingAccountScope::Selected(vec![h.id("idle")]); wrong.push(r);
    let mut r = correct.clone(); r.scope = AgingAccountScope::Selected(vec![h.id("ar"), h.id("ar")]); wrong.push(r);
    let mut r = correct.clone(); r.known_at = None; wrong.push(r);
    let mut r = correct.clone(); r.known_at = Some(CommitSeq(h.head().0 + 1)); wrong.push(r);
    let mut r = correct.clone(); r.effective_through = day("2026-03-30"); wrong.push(r);
    let mut r = correct; r.buckets = AgingBuckets::new(vec![]).unwrap(); wrong.push(r);
    for request in wrong {
        assert!(replay(&h, &saved.certificate, &request).unwrap().is_err());
        assert!(h.book.aging_portfolio_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
            &saved.certificate, &request).unwrap().is_err());
    }
}

#[test]
fn repaired_outer_checksums_cannot_drop_coverage_or_change_comparisons() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let request = AgingPortfolioRequest { scope: AgingAccountScope::Selected(vec![h.id("ar")]), ..h.request() };
    let good = certify(&h, &request);
    let mut variants = Vec::new();
    let mut r = good.report.clone(); r.uncovered.clear(); variants.push(r);
    let mut r = good.report.clone(); r.accounts.clear(); variants.push(r);
    let mut r = good.report.clone(); r.accounts[0].rows[0].difference = 7; variants.push(r);
    let mut r = good.report.clone(); r.accounts[0].rows[0].pending_debits = 7; variants.push(r);
    let mut r = good.report.clone(); r.accounts[0].account.name.push_str(" false"); variants.push(r);
    for altered in variants {
        let forged = reseal(&good.certificate, &altered);
        let decoded = AgingPortfolioCertificate::decode(&forged.canonical_bytes().unwrap()).unwrap();
        assert_eq!(replay(&h, &decoded, good.report.request()).unwrap().unwrap_err().exit, exit::VERIFICATION);
        assert!(h.book.aging_portfolio_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
            &decoded, good.report.request()).unwrap().is_err());
    }
}

#[test]
fn different_native_prefixes_cutoffs_and_filtered_aging_sources_are_not_composable() {
    let mut h = Harness::new();
    let first = certify(&h, &h.request());
    h.add_leaf("new-zero");
    let second = certify(&h, &h.request());
    assert!(h.book.certify_aging_portfolio_from_sources(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        first.certificate.aging_source(), second.certificate.control_source(), first.report.request()).unwrap().is_err());
    let filtered = h.book.certify_effective_date_aging(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        &AgingRequest { account: Some(h.id("ar")), effective_through: day("2026-03-31"),
            known_at: Some(h.head()), buckets: AgingBuckets::thirty_day() }).unwrap().unwrap();
    assert!(h.book.certify_aging_portfolio_from_sources(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        &filtered.certificate, second.certificate.control_source(), second.report.request()).unwrap().is_err());
    let mut earlier = h.request(); earlier.effective_through = day("2026-03-30");
    let earlier = certify(&h, &earlier);
    assert!(h.book.certify_aging_portfolio_from_sources(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        earlier.certificate.aging_source(), second.certificate.control_source(), earlier.report.request()).unwrap().is_err());
}

#[test]
fn malformed_containers_and_unbounded_or_noncanonical_scopes_are_refused() {
    let h = Harness::new();
    let request = AgingPortfolioRequest { scope: AgingAccountScope::Selected(vec![h.id("ar"), h.id("cash")]), ..h.request() };
    let saved = certify(&h, &request);
    let bytes = saved.certificate.canonical_bytes().unwrap();
    for end in [0, 1, 4, bytes.len() / 2, bytes.len() - 1] {
        assert!(AgingPortfolioCertificate::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone(); trailing.push(0);
    assert!(AgingPortfolioCertificate::decode(&trailing).is_err());
    let mut digest = bytes.clone(); let last = digest.len() - 1; digest[last] ^= 1;
    assert!(AgingPortfolioCertificate::decode(&digest).is_err());
    let scope = 4 + FORMAT.len() + 16 + 32;
    let mut tag = bytes.clone(); tag[scope] = 255;
    assert!(AgingPortfolioCertificate::decode(&tag).is_err());
    let mut count = bytes.clone(); count[scope + 1..scope + 5].copy_from_slice(&4097_u32.to_le_bytes());
    assert!(AgingPortfolioCertificate::decode(&count).is_err());
    let mut duplicate = bytes.clone();
    duplicate.copy_within(scope + 5..scope + 21, scope + 21);
    assert!(AgingPortfolioCertificate::decode(&duplicate).is_err());
    let mut reversed = bytes;
    for i in 0..16 { reversed.swap(scope + 5 + i, scope + 21 + i); }
    assert!(AgingPortfolioCertificate::decode(&reversed).is_err());
}

#[test]
fn workpaper_keeps_control_only_units_exact_amounts_selected_detail_and_uncovered_leaves() {
    let mut h = Harness::new();
    let invoice = h.post("usd", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post("fully-paid", "2026-03-15", h.usd, ("cash", "ar"), 100, Some(invoice));
    let exact = (1_i128 << 90) + 1;
    let eur = h.post("eur", "2026-03-01", h.eur, ("ar", "sales"), exact, None);
    h.post("partially-paid", "2026-03-15", h.eur, ("cash", "ar"), 7, Some(eur));
    let request = AgingPortfolioRequest { scope: AgingAccountScope::Selected(vec![h.id("ar"), h.id("idle")]), ..h.request() };
    let saved = certify(&h, &request);
    let at = h.head();
    let text = h.book.aging_portfolio_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        &saved.certificate, saved.report.request()).unwrap().unwrap();
    assert_eq!(text.matches("\"event\":\"aging_portfolio_unit\"").count(), 2);
    assert_eq!(text.matches("\"event\":\"aging_portfolio_control\"").count(), 2);
    assert_eq!(text.matches("\"event\":\"aging_portfolio_item\"").count(), 1);
    assert_eq!(text.matches("\"event\":\"aging_portfolio_application\"").count(), 1);
    assert_eq!(text.matches("\"event\":\"aging_portfolio_account\"").count(), 6);
    assert!(text.contains(&format!("\"original\":\"{exact}\"")));
    assert!(text.contains(&format!("\"open\":\"{}\"", exact - 7)));
    assert!(text.contains("\"posted_debits\":\"100\",\"posted_credits\":\"100\""));
    assert!(text.contains("\"complete\":false,\"selected_reconciled\":true,\"complete_and_reconciled\":false"));
    assert!(text.contains("\"external_subledger_attestation\":false,\"period_close_authorized\":false"));
    assert!(!text.contains("Portfolio accounting evidence"));
    assert_eq!(text, h.book.aging_portfolio_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        &saved.certificate, saved.report.request()).unwrap().unwrap());
    assert_eq!(h.head(), at);
}

#[test]
fn present_authority_is_required_even_with_a_saved_producer_and_corrupt_native_data() {
    use fa_model::symbols::{property, relation};
    use fgdb::{WriteBatch, WriteMismatchPolicy};
    use fgdb_types::CanonicalScalar;
    let mut h = Harness::new();
    let entry = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let saved = certify(&h, &h.request());
    assert!(h.book.certify_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request()).unwrap().is_err());
    assert!(h.book.certify_aging_portfolio_from_sources(&h.cx(), PRINCIPAL, &cap(&["read"]),
        saved.certificate.aging_source(), saved.certificate.control_source(), saved.report.request()).unwrap().is_err());
    assert!(h.book.aging_portfolio_jsonl(&h.cx(), PRINCIPAL, &cap(&["read"]),
        &saved.certificate, saved.report.request()).unwrap().is_err());
    assert!(h.book.replay_aging_portfolio(&h.cx(), VId(99), &cap(&["read"]),
        &saved.certificate, saved.report.request()).unwrap().is_err());
    let cx = h.cx();
    let row = cx.query().with_restriction(|| h.book.db.vertex(entry.vid)).unwrap().unwrap();
    let original = fa_journal::rows::prop(&row, property::FA_PAYLOAD).cloned().unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(entry.vid, property::FA_PAYLOAD, Some(original),
        CanonicalScalar::bytes(Vec::new()).unwrap(), WriteMismatchPolicy::AbortWrite);
    h.runtime.block_on(h.book.db.write(&cx.commit(), damage)).unwrap();
    let at = h.head();
    let refused = h.book.replay_aging_portfolio(&cx, PRINCIPAL, &cap(&["produce"]),
        &saved.certificate, saved.report.request()).unwrap().unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::CAPABILITY);
    assert!(!matches!(h.book.reconcile_aging_portfolio(&cx, PRINCIPAL, &cap(&["read"]), &h.request()), Ok(Ok(_))));
    assert_eq!(h.head(), at);
}
