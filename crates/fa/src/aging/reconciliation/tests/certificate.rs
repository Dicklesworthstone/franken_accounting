use super::*;
use fa_model::domain_digest;

fn certified(h: &Harness, request: &AgingReconciliationRequest) -> CertifiedAgingReconciliation {
    h.book.certify_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL,
        &cap(&["read", "produce"]), request).unwrap().unwrap()
}
fn replay(h: &Harness, certificate: &AgingReconciliationCertificate,
    expected: &AgingReconciliationRequest) -> AgingReconciliation
{
    h.book.replay_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL,
        &cap(&["read"]), certificate, expected).unwrap().unwrap()
}
fn workpaper(h: &Harness, certificate: &AgingReconciliationCertificate,
    expected: &AgingReconciliationRequest) -> String
{
    h.book.effective_date_aging_reconciliation_jsonl(&h.cx(), PRINCIPAL,
        &cap(&["read", "produce"]), certificate, expected).unwrap().unwrap()
}

#[test]
fn saved_dual_sources_roundtrip_reopen_and_keep_the_original_comparison() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post("partial", "2026-03-10", h.usd, ("cash", "ar"), 40, Some(invoice));
    let good = certified(&h, &h.request("ar", "2026-03-31"));
    let expected = good.certificate.request().unwrap();
    assert_eq!(expected.known_at, Some(h.head()));
    let encoded = good.certificate.canonical_bytes().unwrap();
    let aging_bytes = good.certificate.aging_source().canonical_bytes().unwrap();
    let control_bytes = good.certificate.control_source().canonical_bytes().unwrap();
    let decoded = AgingReconciliationCertificate::decode(&encoded).unwrap();
    assert_eq!(decoded, good.certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(decoded.producer(), PRINCIPAL);
    assert_eq!(*decoded.capability_commitment(), cap(&["read", "produce"]).commitment().unwrap());
    assert_eq!(good.report, h.report(&expected));
    let text = workpaper(&h, &decoded, &expected);
    assert!(text.contains("\"posted_debits\":\"100\""));
    assert!(text.contains("\"posted_credits\":\"40\""));
    assert!(text.contains("\"open_net\":\"60\""));
    h.post("late", "2026-03-20", h.usd, ("cash", "ar"), 20, Some(invoice));
    let h = h.reopen();
    let head = h.head();
    assert_eq!(replay(&h, &decoded, &expected), good.report);
    assert_eq!(workpaper(&h, &decoded, &expected), text);
    let reused = h.book.certify_effective_date_aging_reconciliation_from_sources(&h.cx(), PRINCIPAL,
        &cap(&["read", "produce"]), decoded.aging_source(), decoded.control_source(), &expected)
        .unwrap().unwrap();
    assert_eq!(reused.certificate, decoded);
    assert_eq!(reused.certificate.aging_source().canonical_bytes().unwrap(), aging_bytes);
    assert_eq!(reused.certificate.control_source().canonical_bytes().unwrap(), control_bytes);
    assert_eq!(h.head(), head);
    assert_eq!(certified(&h, &h.request("ar", "2026-03-31")).report.rows()[0].open_net, 40);
}

#[test]
fn valid_equal_total_certificates_do_not_choose_the_recipients_question() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let good = certified(&h, &h.request("ar", "2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let other_date = certified(&h, &h.request("ar", "2026-03-30"));
    assert_eq!(other_date.report.rows(), good.report.rows());
    assert!(h.book.replay_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL, &cap(&["read"]),
        &other_date.certificate, &expected).unwrap().is_err());
    assert!(h.book.certify_effective_date_aging_reconciliation_from_sources(&h.cx(), PRINCIPAL,
        &cap(&["read", "produce"]), good.certificate.aging_source(), other_date.certificate.control_source(),
        &expected).unwrap().is_err());
    h.post("unrelated", "2026-03-10", h.usd, ("cash", "sales"), 5, None);
    let later = certified(&h, &h.request("ar", "2026-03-31"));
    assert_eq!(later.report.rows(), good.report.rows());
    assert!(h.book.certify_effective_date_aging_reconciliation_from_sources(&h.cx(), PRINCIPAL,
        &cap(&["read", "produce"]), good.certificate.aging_source(), later.certificate.control_source(),
        &expected).unwrap().is_err());
    let mut wrong_account = expected.clone(); wrong_account.account = h.id("cash");
    let mut wrong_bucket = expected.clone(); wrong_bucket.buckets = AgingBuckets::new(vec![30]).unwrap();
    let mut wrong_at = expected.clone(); wrong_at.known_at = Some(h.head());
    for wrong in [wrong_account, wrong_bucket, wrong_at] {
        assert_eq!(h.book.replay_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL, &cap(&["read"]),
            &good.certificate, &wrong).unwrap().unwrap_err().exit, exit::VERIFICATION);
    }
    let mut unresolved = expected; unresolved.known_at = None;
    assert_eq!(h.book.replay_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL, &cap(&["read"]),
        &good.certificate, &unresolved).unwrap().unwrap_err().exit, exit::USAGE);
}

#[test]
fn repaired_outer_digests_cannot_change_the_computed_verdict_or_money() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let good = certified(&h, &h.request("ar", "2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let bytes = good.certificate.canonical_bytes().unwrap();
    for offset_from_end in [33, 34, 50] {
        let mut changed = bytes.clone();
        let len = changed.len(); changed[len - offset_from_end] ^= 1;
        let digest = domain_digest(b"fa:aging-reconciliation-digest:v1", &[&changed[..len - 32]]);
        changed[len - 32..].copy_from_slice(&digest);
        // Valid content envelope, deliberately false comparison bytes.
        let forged = AgingReconciliationCertificate::decode(&changed).unwrap();
        assert_eq!(h.book.replay_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL, &cap(&["read"]),
            &forged, &expected).unwrap().unwrap_err().exit, exit::VERIFICATION);
        assert!(h.book.effective_date_aging_reconciliation_jsonl(&h.cx(), PRINCIPAL,
            &cap(&["read", "produce"]), &forged, &expected).unwrap().is_err());
    }
    for length in [0, 1, 4, bytes.len() / 2, bytes.len() - 1] {
        assert!(AgingReconciliationCertificate::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes; trailing.push(0);
    assert!(AgingReconciliationCertificate::decode(&trailing).is_err());
    assert!(AgingReconciliationCertificate::decode(&u32::MAX.to_le_bytes()).is_err());
}

#[test]
fn production_export_and_replay_require_current_authority_not_saved_provenance() {
    let h = Harness::new();
    let good = certified(&h, &h.request("ar", "2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let head = h.head();
    let mut damaged = good.certificate.control_source().clone(); damaged.output_digest[0] ^= 1;
    for denied in [cap(&["read"]), cap(&["produce"]), cap(&["post"])] {
        assert_eq!(h.book.certify_effective_date_aging_reconciliation_from_sources(&h.cx(), PRINCIPAL, &denied,
            good.certificate.aging_source(), &damaged, &expected).unwrap().unwrap_err().code,
            fa_journal::refusal::code::CAPABILITY);
        assert!(h.book.effective_date_aging_reconciliation_jsonl(&h.cx(), PRINCIPAL, &denied,
            &good.certificate, &expected).unwrap().is_err());
    }
    assert!(h.book.replay_effective_date_aging_reconciliation(&h.cx(), VId(8), &cap(&["read"]),
        &good.certificate, &expected).unwrap().is_err());
    assert!(h.book.replay_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL, &cap(&["produce"]),
        &good.certificate, &expected).unwrap().is_err());
    assert!(h.book.certify_effective_date_aging_reconciliation_from_sources(&h.cx(), PRINCIPAL,
        &cap(&["read", "produce"]), good.certificate.aging_source(), &damaged, &expected).unwrap().is_err());
    let other = Harness::in_book(Id128([0x7a; 16]));
    assert!(!matches!(other.book.replay_effective_date_aging_reconciliation(&other.cx(), PRINCIPAL,
        &cap(&["read"]), &good.certificate, &expected), Ok(Ok(_))));
    assert_eq!(h.head(), head);
}

#[test]
fn workpapers_keep_exact_units_for_fully_paid_and_large_native_balances() {
    let mut h = Harness::new();
    let invoice = h.post("paid-invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post("paid", "2026-03-10", h.usd, ("cash", "ar"), 100, Some(invoice));
    let exact = (1_i128 << 90) + 1;
    h.post("eur-invoice", "2026-03-01", h.eur, ("ar", "sales"), exact, None);
    let good = certified(&h, &h.request("ar", "2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let text = workpaper(&h, &good.certificate, &expected);
    assert_eq!(text.matches("\"event\":\"aging_control_row\"").count(), 2);
    assert_eq!(text.matches("\"event\":\"aging_control_unit\"").count(), 2);
    assert!(text.contains(&format!("\"open_net\":\"{exact}\"")));
    assert!(text.contains("\"code\":\"USD\""));
    assert!(text.contains("\"code\":\"EUR\""));
    assert!(text.lines().last().unwrap().contains("\"reconciled\":true"));
    assert!(text.lines().last().unwrap().contains("\"external_subledger_attestation\":false"));
    assert!(!text.contains("Open-item/control evidence"));
    let empty = certified(&h, &h.request("ap", "2026-03-31"));
    let text = workpaper(&h, &empty.certificate, &empty.certificate.request().unwrap());
    assert!(text.contains("\"unit_count\":\"0\""));
    assert!(text.contains("\"name\":\"ap account\""));
}

#[test]
fn rewritten_journal_history_cannot_yield_a_saved_comparison_or_workpaper() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let good = certified(&h, &h.request("ar", "2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let cx = h.cx();
    let row = cx.query().with_restriction(|| h.book.db.vertex(invoice.vid)).unwrap().unwrap();
    let original = fa_journal::rows::prop(&row, property::FA_PAYLOAD).cloned().unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(invoice.vid, property::FA_PAYLOAD, Some(original),
        CanonicalScalar::bytes(Vec::new()).unwrap(), WriteMismatchPolicy::AbortWrite);
    h.runtime.block_on(h.book.db.write(&cx.commit(), damage)).unwrap();
    assert!(!matches!(h.book.replay_effective_date_aging_reconciliation(&cx, PRINCIPAL, &cap(&["read"]),
        &good.certificate, &expected), Ok(Ok(_))));
    assert!(!matches!(h.book.effective_date_aging_reconciliation_jsonl(&cx, PRINCIPAL,
        &cap(&["read", "produce"]), &good.certificate, &expected), Ok(Ok(_))));
}
