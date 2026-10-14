//! Real native certificates: local framing success alone never proves a report.

use super::*;
use fa::indirect_cash_flow::{CertifiedIndirectCashFlow, IndirectCashFlowCertificate};

fn certify(h: &Harness, request: &IndirectCashFlowRequest) -> CertifiedIndirectCashFlow {
    h.book
        .certify_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap()
}

#[test]
fn native_certificate_roundtrip_fixes_head_and_preserves_every_large_amount_and_zero_unit() {
    let mut h = Harness::new();
    let k = (1i128 << 80) + 17;
    h.scenario(k);
    let expected = h.request();
    let mut at_head = expected.clone();
    at_head.cash.known_at = None;
    let before = h.head();
    let result = certify(&h, &at_head);
    assert_eq!(result.certificate().known_at(), before);
    assert_eq!(
        result.certificate().source_certificate().request().known_at,
        Some(before)
    );
    let bytes = result.certificate().canonical_bytes().unwrap();
    let decoded = IndirectCashFlowCertificate::decode(&bytes).unwrap();
    assert_eq!(&decoded, result.certificate());
    assert_eq!(decoded.output(), result.report().canonical_bytes().unwrap());
    let report = h
        .book
        .replay_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &decoded, &expected)
        .unwrap()
        .unwrap();
    assert_eq!(&report, result.report());
    assert_eq!(
        report
            .units()
            .iter()
            .find(|u| u.unit_id == h.usd.0)
            .unwrap()
            .operating,
        30 * k
    );
    assert_eq!(
        report
            .units()
            .iter()
            .find(|u| u.unit_id == h.jpy.0)
            .unwrap()
            .closing,
        0
    );
    assert_eq!(h.head(), before);
}

#[test]
fn retained_indirect_certificate_replays_after_backdated_cash_and_non_cash_postings() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.scenario(1);
    let expected = h.request();
    let original = certify(&h, &expected);
    let retained = original.certificate().canonical_bytes().unwrap();
    h.post(
        8,
        b"later-non-cash",
        h.usd,
        &[("6100", D, 1), ("1590", C, 1)],
    );
    h.post(9, b"later-cash", h.usd, &[("1000", D, 5), ("4000", C, 5)]);
    let before = h.head();
    let restored = IndirectCashFlowCertificate::decode(&retained).unwrap();
    let replayed = h
        .book
        .replay_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &restored, &expected)
        .unwrap()
        .unwrap();
    assert_eq!(
        replayed.canonical_bytes().unwrap(),
        original.report().canonical_bytes().unwrap()
    );
    assert_eq!(h.head(), before);
    let mut changed_cutoff = expected;
    changed_cutoff.cash.known_at = Some(before);
    assert!(
        h.book
            .replay_indirect_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &restored,
                &changed_cutoff
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn permutations_share_identity_but_equal_operating_cash_does_not_authorize_another_definition() {
    let mut h = Harness::new();
    h.scenario(1);
    let expected = h.request();
    let original = certify(&h, &expected);
    let mut permuted = expected.clone();
    permuted.cash.units.reverse();
    permuted.cash_definition.assignments.reverse();
    permuted.definition.adjustments.reverse();
    assert_eq!(certify(&h, &permuted).certificate(), original.certificate());
    assert_eq!(
        h.book
            .replay_indirect_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &permuted
            )
            .unwrap()
            .unwrap(),
        *original.report()
    );

    let mut other = expected.clone();
    other.definition.adjustments[0].reason = "different supporting judgment".into();
    // Both categories permit this exact expense leg, but their classification
    // decisions and section totals are different even though operating cash ties.
    other.definition.adjustments[0].category = AdjustmentCategory::NonOperating;
    let alternative = certify(&h, &other);
    let original_usd = original
        .report()
        .units()
        .iter()
        .find(|u| u.unit_id == h.usd.0)
        .unwrap();
    let alternative_usd = alternative
        .report()
        .units()
        .iter()
        .find(|u| u.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (original_usd.operating, alternative_usd.operating),
        (30, 30)
    );
    assert_eq!((original_usd.non_cash, alternative_usd.non_cash), (10, 0));
    assert_eq!(
        (original_usd.non_operating, alternative_usd.non_operating),
        (-20, -10)
    );
    assert_ne!(
        alternative.certificate().digest(),
        original.certificate().digest()
    );
    assert_eq!(
        alternative.certificate().source_certificate(),
        original.certificate().source_certificate()
    );
    assert!(
        h.book
            .replay_indirect_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                alternative.certificate(),
                &expected
            )
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .replay_indirect_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &other
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn replay_requires_independently_fixed_cash_scope_periods_and_all_classifications() {
    let mut h = Harness::new();
    h.scenario(1);
    let expected = h.request();
    let original = certify(&h, &expected);
    let mut head = expected.clone();
    head.cash.known_at = None;
    let mut units = expected.clone();
    units.cash.units.retain(|u| *u != h.jpy.0); // zero matters
    let mut dates = expected.clone();
    dates.cash.effective_through = day(30);
    let mut periods = expected.clone();
    periods.income_periods = vec!["FY2026-P02".into()];
    let mut cash_class = expected.clone();
    cash_class.cash_definition.assignments[0].activity = CashFlowActivity::ExchangeEffect;
    let mut name = expected.clone();
    name.definition.name = "substituted workpaper".into();
    let mut sign = expected;
    sign.definition.adjustments[0].sign = AdjustmentSign::CreditMinusDebit;
    for request in [head, units, dates, periods, cash_class, name, sign] {
        assert!(
            h.book
                .replay_indirect_cash_flow(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    original.certificate(),
                    &request
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn producer_requires_produce_while_replay_rechecks_current_read_and_holder() {
    let mut h = Harness::new();
    h.scenario(1);
    let request = h.request();
    for (principal, capability) in [
        (PRINCIPAL, cap(&["read"])),
        (PRINCIPAL, cap(&["produce"])),
        (VId(2), cap(&["read", "produce"])),
    ] {
        assert!(
            h.book
                .certify_indirect_cash_flow(&h.cx(), principal, &capability, &request)
                .unwrap()
                .is_err()
        );
    }
    let original = certify(&h, &request);
    for (principal, capability) in [
        (PRINCIPAL, cap(&["post"])),
        (PRINCIPAL, cap(&["produce"])),
        (VId(2), cap(&["read"])),
    ] {
        assert!(
            h.book
                .replay_indirect_cash_flow(
                    &h.cx(),
                    principal,
                    &capability,
                    original.certificate(),
                    &request
                )
                .unwrap()
                .is_err()
        );
    }
    h.book
        .replay_indirect_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            original.certificate(),
            &request,
        )
        .unwrap()
        .unwrap();
}

#[test]
fn forged_indirect_amount_with_recomputed_unkeyed_digest_decodes_but_never_replays() {
    let mut h = Harness::new();
    h.scenario(1);
    let request = h.request();
    let original = certify(&h, &request);
    let mut bytes = original.certificate().canonical_bytes().unwrap();
    let body_len = bytes.len() - 32;
    // Last body byte belongs to the last native unit's closing amount. All
    // nested source bytes and outer framing remain pristine and self-consistent.
    bytes[body_len - 1] ^= 1;
    let digest = fa_model::domain_digest(
        b"fa:indirect-cash-flow-certificate-digest:v1",
        &[&bytes[..body_len]],
    );
    bytes[body_len..].copy_from_slice(&digest);
    let forged = IndirectCashFlowCertificate::decode(&bytes).unwrap();
    assert_ne!(forged.output(), original.certificate().output());
    let before = h.head();
    let refusal = h
        .book
        .replay_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged, &request)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-150");
    assert_eq!(refusal.exit, 8);
    assert_eq!(h.head(), before);
}

#[test]
fn native_certificate_refuses_truncation_trailing_data_unknown_version_and_hostile_lengths() {
    let mut h = Harness::new();
    h.scenario(1);
    let bytes = certify(&h, &h.request())
        .into_certificate()
        .canonical_bytes()
        .unwrap();
    for cut in [
        0,
        1,
        3,
        4,
        16,
        39,
        bytes.len() / 2,
        bytes.len() - 33,
        bytes.len() - 1,
    ] {
        assert!(IndirectCashFlowCertificate::decode(&bytes[..cut]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(IndirectCashFlowCertificate::decode(&trailing).is_err());
    let mut digest = bytes.clone();
    let last = digest.len() - 1;
    digest[last] ^= 1;
    assert!(IndirectCashFlowCertificate::decode(&digest).is_err());
    let mut version = bytes.clone();
    let end = 4 + fa::indirect_cash_flow::INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT.len();
    version[end - 1] = b'9';
    assert!(IndirectCashFlowCertificate::decode(&version).is_err());
    let mut length = bytes;
    length[end..end + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(IndirectCashFlowCertificate::decode(&length).is_err());
}

#[test]
fn the_same_book_id_and_commit_count_do_not_make_another_history_a_valid_source() {
    let mut first = Harness::new();
    first.scenario(1);
    let expected = first.request();
    let original = certify(&first, &expected);
    let mut different = Harness::new();
    different.scenario(2);
    assert_eq!(
        first.book.context().book_id,
        different.book.context().book_id
    );
    assert_eq!(first.head(), different.head());
    assert!(!matches!(
        different.book.replay_indirect_cash_flow(
            &different.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            original.certificate(),
            &expected
        ),
        Ok(Ok(_))
    ));
}

#[test]
fn an_empty_month_certifies_with_no_adjustments_and_keeps_zero_native_cells() {
    let h = Harness::new();
    let cash = h.cash_request();
    let request = IndirectCashFlowRequest {
        cash_definition: CashFlowDefinition {
            name: "Empty cash v1".into(),
            cash_accounts: cash.accounts.iter().map(|a| a.0).collect(),
            assignments: Vec::new(),
        },
        cash,
        income_periods: vec!["FY2026-OPEN".into(), "FY2026-P01".into()],
        definition: IndirectCashFlowDefinition {
            name: "Empty indirect v1".into(),
            adjustments: Vec::new(),
        },
    };
    let before = h.head();
    let original = certify(&h, &request);
    assert!(original.report().contributions().is_empty());
    assert_eq!(original.report().units().len(), 2);
    for u in original.report().units() {
        assert_eq!((u.net_income, u.operating, u.closing), (0, 0, 0));
    }
    let restored =
        IndirectCashFlowCertificate::decode(&original.certificate().canonical_bytes().unwrap())
            .unwrap();
    assert_eq!(
        h.book
            .replay_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &restored, &request)
            .unwrap()
            .unwrap(),
        *original.report()
    );
    assert_eq!(h.head(), before);
}
