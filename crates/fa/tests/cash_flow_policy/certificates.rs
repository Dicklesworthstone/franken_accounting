use super::*;
use fa::cash_flow_policy::{
    CASH_FLOW_POLICY_CERTIFICATE_FORMAT, CashFlowPolicyCertificate, CashFlowPolicyDecision,
    CertifiedPolicyCashFlow,
};
use fa::{CASH_FLOW_CERTIFICATE_FORMAT, CashFlowCertificate};
use fa_model::{Writer, domain_digest};

fn certify(
    h: &Harness,
    request: &RollForwardRequest,
    policy: &CashFlowPolicy,
) -> CertifiedPolicyCashFlow {
    h.book
        .certify_cash_flow_with_policy(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            request,
            policy,
        )
        .unwrap()
        .unwrap()
}

// A malicious producer can recompute unkeyed digests. This helper deliberately
// does so without the native producer, proving the consumer must really replay.
fn wrap(
    source: &CashFlowCertificate,
    policy: &CashFlowPolicy,
    decisions: &[CashFlowPolicyDecision],
) -> CashFlowPolicyCertificate {
    let mut w = Writer::new();
    w.bytes(CASH_FLOW_POLICY_CERTIFICATE_FORMAT)
        .bytes(&source.canonical_bytes().unwrap())
        .bytes(&policy.canonical_bytes().unwrap())
        .list(decisions, |w, d| {
            w.fixed(&d.entry_digest)
                .u32(d.leg_index)
                .u8(d.activity as u8)
                .u8(d.basis as u8);
        });
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(b"fa:cash-flow-policy-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    CashFlowPolicyCertificate::decode(&bytes).unwrap()
}

#[test]
fn policy_certificates_roundtrip_large_values_zero_units_and_permuted_requests() {
    let mut h = Harness::new();
    h.scenario((1i128 << 80) + 17);
    let mut request = h.request();
    let mut policy = h.policy();
    let before = h.head();
    let original = certify(&h, &request, &policy);
    let bytes = original.certificate().canonical_bytes().unwrap();
    let restored = CashFlowPolicyCertificate::decode(&bytes).unwrap();
    assert_eq!(&restored, original.certificate());
    let report = h
        .book
        .replay_cash_flow_with_policy(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &restored,
            &request,
            &policy,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        report.canonical_bytes().unwrap(),
        original.report().canonical_bytes().unwrap()
    );
    assert_eq!(restored.known_at(), before);
    assert_eq!(
        report
            .report()
            .units()
            .iter()
            .find(|u| u.unit_id == h.usd.0)
            .unwrap()
            .closing,
        105 * ((1i128 << 80) + 17)
    );
    assert_eq!(
        report
            .report()
            .units()
            .iter()
            .find(|u| u.unit_id == h.jpy.0)
            .unwrap()
            .closing,
        0
    );
    request.accounts.reverse();
    request.units.reverse();
    policy.cash_accounts.reverse();
    policy.account_rules.reverse();
    assert_eq!(
        certify(&h, &request, &policy).certificate(),
        original.certificate()
    );
    assert_eq!(h.head(), before);
}

#[test]
fn head_is_fixed_once_and_old_policy_decisions_replay_after_backdated_activity() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.scenario(1);
    let mut request = h.request();
    let expected = request.clone();
    request.known_at = None;
    let policy = h.policy();
    let original = certify(&h, &request, &policy);
    assert_eq!(Some(original.certificate().known_at()), expected.known_at);
    let portable = original.certificate().canonical_bytes().unwrap();
    h.post(
        2,
        b"new-backdated-sale",
        h.usd,
        &[("1000", D, 9), ("4000", C, 9)],
    );
    let restored = CashFlowPolicyCertificate::decode(&portable).unwrap();
    let before = h.head();
    let replay = h
        .book
        .replay_cash_flow_with_policy(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &restored,
            &expected,
            &policy,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        replay.canonical_bytes().unwrap(),
        original.report().canonical_bytes().unwrap()
    );
    let newer = certify(&h, &h.request(), &policy);
    assert_eq!(
        newer.report().decisions().len(),
        original.report().decisions().len() + 1
    );
    assert_eq!(h.head(), before);
}

#[test]
fn unused_rules_are_bound_even_when_the_nested_cash_report_is_identical() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(2, b"only-sale", h.usd, &[("1000", D, 10), ("4000", C, 10)]);
    let request = h.request();
    let policy = h.policy();
    let original = certify(&h, &request, &policy);
    let mut changed = policy.clone();
    changed
        .account_rules
        .iter_mut()
        .find(|r| r.account_id == h.id("1500").0)
        .unwrap()
        .activity = CashFlowActivity::Financing;
    let alternate = certify(&h, &request, &changed);
    assert_eq!(
        original.certificate().source_certificate(),
        alternate.certificate().source_certificate()
    );
    assert_ne!(
        original.certificate().digest(),
        alternate.certificate().digest()
    );
    let refusal = h
        .book
        .replay_cash_flow_with_policy(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            original.certificate(),
            &request,
            &changed,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-150");
    assert_eq!(refusal.exit, 8);
}

#[test]
fn a_self_consistent_forged_policy_cannot_claim_the_old_native_classification() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(2, b"sale", h.usd, &[("1000", D, 10), ("4000", C, 10)]);
    let request = h.request();
    let policy = h.policy();
    let original = certify(&h, &request, &policy);
    let mut changed = policy;
    changed
        .account_rules
        .iter_mut()
        .find(|r| r.account_id == h.id("4000").0)
        .unwrap()
        .activity = CashFlowActivity::Investing;
    let forged = wrap(
        original.certificate().source_certificate(),
        &changed,
        original.certificate().decisions(),
    );
    // Even granting the forged policy as the independently expected input cannot
    // make its old Operating decisions reproduce from an Investing account rule.
    let before = h.head();
    let refusal = h
        .book
        .replay_cash_flow_with_policy(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &forged,
            &request,
            &changed,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-150");
    assert_eq!(refusal.exit, 8);
    assert_eq!(h.head(), before);
}

#[test]
fn nested_forged_cash_output_is_still_replayed_after_policy_decisions_match() {
    let mut h = Harness::new();
    h.scenario(1);
    let request = h.request();
    let policy = h.policy();
    let original = certify(&h, &request, &policy);
    let source = original.certificate().source_certificate();
    let mut output = source.output().to_vec();
    *output.last_mut().unwrap() ^= 1;
    let definition = source.definition();
    let mut w = Writer::new();
    w.bytes(CASH_FLOW_CERTIFICATE_FORMAT)
        .bytes(&source.source_certificate().canonical_bytes().unwrap())
        .str(&definition.name)
        .list(&definition.cash_accounts, |w, id| {
            w.u128(*id);
        })
        .list(&definition.assignments, |w, a| {
            w.fixed(&a.entry_digest)
                .u32(a.leg_index)
                .u8(a.activity as u8);
        })
        .bytes(&output);
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(b"fa:cash-flow-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    let bad_cash = CashFlowCertificate::decode(&bytes).unwrap();
    let forged = wrap(
        &bad_cash,
        original.certificate().policy(),
        original.certificate().decisions(),
    );
    let before = h.head();
    let refusal = h
        .book
        .replay_cash_flow_with_policy(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &forged,
            &request,
            &policy,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-150");
    assert_eq!(refusal.exit, 8);
    assert_eq!(h.head(), before);
}

#[test]
fn producer_and_recipient_need_their_current_operations_and_holder_identity() {
    let mut h = Harness::new();
    h.scenario(1);
    let request = h.request();
    let policy = h.policy();
    let before = h.head();
    let original = certify(&h, &request, &policy);
    for capability in [cap(&["read"]), cap(&["produce"]), cap(&["post"])] {
        assert!(
            h.book
                .certify_cash_flow_with_policy(&h.cx(), PRINCIPAL, &capability, &request, &policy)
                .unwrap()
                .is_err()
        );
    }
    for (principal, capability) in [(PRINCIPAL, cap(&["produce"])), (VId(99), cap(&["read"]))] {
        assert!(
            h.book
                .replay_cash_flow_with_policy(
                    &h.cx(),
                    principal,
                    &capability,
                    original.certificate(),
                    &request,
                    &policy
                )
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(h.head(), before);
}

#[test]
fn recipients_must_bind_dates_zero_units_scope_label_and_an_explicit_prefix() {
    let mut h = Harness::new();
    h.scenario(1);
    let request = h.request();
    let policy = h.policy();
    let original = certify(&h, &request, &policy);
    for bad in [
        RollForwardRequest {
            known_at: None,
            ..request.clone()
        },
        RollForwardRequest {
            effective_from: day(2),
            ..request.clone()
        },
        RollForwardRequest {
            label: "Another report".into(),
            ..request.clone()
        },
        RollForwardRequest {
            units: vec![h.usd.0],
            ..request.clone()
        },
        RollForwardRequest {
            accounts: vec![h.id("1000")],
            ..request.clone()
        },
    ] {
        let refusal = h
            .book
            .replay_cash_flow_with_policy(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &bad,
                &policy,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, "FA-REF-150");
        assert_eq!(refusal.exit, 8);
    }
}

#[test]
fn malformed_transport_and_another_history_with_the_same_book_id_are_not_accepted() {
    let mut h = Harness::new();
    h.scenario(1);
    let request = h.request();
    let policy = h.policy();
    let original = certify(&h, &request, &policy);
    let bytes = original.certificate().canonical_bytes().unwrap();
    for n in (0..80).chain([bytes.len() / 2, bytes.len() - 33, bytes.len() - 1]) {
        assert!(
            CashFlowPolicyCertificate::decode(&bytes[..n]).is_err(),
            "prefix {n}"
        );
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(CashFlowPolicyCertificate::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[4] ^= 1;
    assert!(CashFlowPolicyCertificate::decode(&bad).is_err());
    let mut bad = bytes;
    *bad.last_mut().unwrap() ^= 1;
    assert!(CashFlowPolicyCertificate::decode(&bad).is_err());
    let mut other = Harness::new();
    other.scenario(2);
    assert_eq!(other.book.context().book_id, h.book.context().book_id);
    assert_eq!(other.head(), h.head());
    assert!(
        other
            .book
            .replay_cash_flow_with_policy(
                &other.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &request,
                &policy
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn explicit_override_provenance_survives_a_portable_roundtrip() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(
        3,
        b"mixed",
        h.usd,
        &[("1000", D, 50), ("4000", C, 30), ("2300", C, 20)],
    );
    let request = h.request();
    let mut policy = h.policy();
    let ledger = h.ledger();
    let leg = &ledger.lines()[0];
    policy.overrides.push(CashFlowAssignment {
        entry_digest: leg.entry_digest,
        leg_index: leg.leg_index,
        activity: CashFlowActivity::Financing,
    });
    let restored_policy = CashFlowPolicy::decode(&policy.canonical_bytes().unwrap()).unwrap();
    let original = certify(&h, &request, &restored_policy);
    let restored =
        CashFlowPolicyCertificate::decode(&original.certificate().canonical_bytes().unwrap())
            .unwrap();
    let replay = h
        .book
        .replay_cash_flow_with_policy(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &restored,
            &request,
            &restored_policy,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        replay.decisions()[0].basis,
        CashFlowDecisionBasis::ExplicitOverride
    );
    assert_eq!(
        replay.canonical_bytes().unwrap(),
        original.report().canonical_bytes().unwrap()
    );
    policy.overrides.clear();
    assert!(
        h.book
            .replay_cash_flow_with_policy(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &restored,
                &request,
                &policy
            )
            .unwrap()
            .is_err()
    );
}
