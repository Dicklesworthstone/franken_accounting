//! Native replay and hostile-delivery tests share the real posting harness.
use super::*;
use fa::cash_flow_split::{CashFlowSplitCertificate, CertifiedSplitCashFlow};

fn certify(
    h: &Harness,
    request: &RollForwardRequest,
    definition: &CashFlowSplitDefinition,
) -> CertifiedSplitCashFlow {
    h.book
        .certify_split_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            request,
            definition,
        )
        .unwrap()
        .unwrap()
}

#[test]
fn portable_split_certificate_replays_large_exact_amounts_and_zero_units_after_reopen() {
    let mut h = Harness::new();
    let k = (1i128 << 100) + 17;
    h.loan(k);
    let request = h.request();
    let definition = h.loan_definition(k);
    let before = h.head();
    let original = certify(&h, &request, &definition);
    let bytes = original.certificate().canonical_bytes().unwrap();
    let expected = original.report().canonical_bytes().unwrap();
    let Harness {
        runtime,
        root,
        vfs,
        book,
        ..
    } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let book = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            Path::new("cash-splits"),
            BookKeys::for_development(129),
            Entropy::deterministic(130),
        ))
        .unwrap();
    let decoded = CashFlowSplitCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded, *original.certificate());
    assert_eq!(decoded.known_at(), before);
    let report = book
        .replay_split_cash_flow(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &decoded,
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert_eq!(report.canonical_bytes().unwrap(), expected);
    assert_eq!(report.source().cells().len(), 4);
    assert_eq!(report.source().lines().len(), 1);
    assert_eq!(book.head(&cx).unwrap(), before);
}

#[test]
fn head_is_fixed_once_and_backdated_new_cash_does_not_replace_the_retained_cutoff() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.loan(1);
    let mut request = h.request();
    request.known_at = None;
    let definition = h.loan_definition(1);
    let at = h.head();
    let original = certify(&h, &request, &definition);
    assert_eq!(original.certificate().known_at(), at);
    request.known_at = Some(at); // independently retained original selection
    h.post(
        12,
        b"later-backdated",
        h.usd,
        &[("1000", D, 9), ("4000", C, 9)],
    );
    let before = h.head();
    let decoded =
        CashFlowSplitCertificate::decode(&original.certificate().canonical_bytes().unwrap())
            .unwrap();
    let report = h
        .book
        .replay_split_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &decoded,
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert_eq!(report, *original.report());
    assert_eq!(h.head(), before);
    assert!(
        h.book
            .certify_split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &h.request(),
                &definition
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn canonical_scope_split_and_portion_permutations_preserve_certificate_identity() {
    let mut h = Harness::new();
    h.loan(1);
    let mut request = h.request();
    let mut definition = h.loan_definition(1);
    let original = certify(&h, &request, &definition);
    request.accounts.reverse();
    request.units.reverse();
    definition.cash_accounts.reverse();
    definition.splits.reverse();
    for split in &mut definition.splits {
        split.portions.reverse();
    }
    let permuted = certify(&h, &request, &definition);
    assert_eq!(original.certificate(), permuted.certificate());
    assert_eq!(
        h.book
            .replay_split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &request,
                &definition
            )
            .unwrap()
            .unwrap(),
        *original.report()
    );
}

#[test]
fn same_gross_totals_with_different_original_leg_portions_are_not_the_same_artifact() {
    use CashFlowActivity::{Financing as F, Operating as O};
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.loan(1);
    h.post(
        11,
        b"second-loan",
        h.usd,
        &[("1000", C, 100), ("2300", D, 92), ("6100", D, 8)],
    );
    let request = h.request();
    let mut definition = h.definition();
    definition.splits[0].portions = portions(&[(O, 7), (F, 93)]);
    definition.splits[1].portions = portions(&[(O, 8), (F, 92)]);
    let original = certify(&h, &request, &definition);
    let mut changed = definition.clone();
    changed.splits[0].portions = portions(&[(O, 8), (F, 92)]);
    changed.splits[1].portions = portions(&[(O, 7), (F, 93)]);
    let other = certify(&h, &request, &changed);
    assert_eq!(original.report().units(), other.report().units());
    assert_ne!(
        original.certificate().digest(),
        other.certificate().digest()
    );
    assert!(
        h.book
            .replay_split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                other.certificate(),
                &request,
                &definition
            )
            .unwrap()
            .is_err()
    );
    let mut reason = definition.clone();
    reason.splits[0].reason.push('!');
    assert!(
        h.book
            .replay_split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &request,
                &reason
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn replay_requires_the_independently_fixed_request_including_zero_accounts_and_units() {
    let mut h = Harness::new();
    h.loan(1);
    let request = h.request();
    let definition = h.loan_definition(1);
    let original = certify(&h, &request, &definition);
    let mut requests = Vec::new();
    let mut bad = request.clone();
    bad.known_at = None;
    requests.push(bad);
    let mut bad = request.clone();
    bad.label.push('!');
    requests.push(bad);
    let mut bad = request.clone();
    bad.effective_from = day(11);
    requests.push(bad);
    let mut bad = request.clone();
    bad.accounts.pop();
    requests.push(bad);
    let mut bad = request;
    bad.units.pop();
    requests.push(bad);
    for bad in requests {
        assert!(
            h.book
                .replay_split_cash_flow(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    original.certificate(),
                    &bad,
                    &definition
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn read_produce_and_holder_checks_are_not_granted_by_the_delivered_certificate() {
    let mut h = Harness::new();
    h.loan(1);
    let request = h.request();
    let definition = h.loan_definition(1);
    let before = h.head();
    assert!(
        h.book
            .certify_split_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &definition)
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .certify_split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["produce"]),
                &request,
                &definition
            )
            .unwrap()
            .is_err()
    );
    let original = certify(&h, &request, &definition);
    for (actor, capability) in [(PRINCIPAL, cap(&["post"])), (VId(99), cap(&["read"]))] {
        assert!(
            h.book
                .replay_split_cash_flow(
                    &h.cx(),
                    actor,
                    &capability,
                    original.certificate(),
                    &request,
                    &definition
                )
                .unwrap()
                .is_err()
        );
    }
    h.book
        .replay_split_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            original.certificate(),
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert_eq!(h.head(), before);
}

#[test]
fn an_attacker_recomputing_the_unkeyed_digest_cannot_make_changed_output_replay() {
    let mut h = Harness::new();
    h.loan(1);
    let request = h.request();
    let definition = h.loan_definition(1);
    let original = certify(&h, &request, &definition);
    let mut bytes = original.certificate().canonical_bytes().unwrap();
    let body = bytes.len() - 32;
    bytes[body - 1] ^= 1; // last original output amount, never a nested source byte
    let digest = fa_model::domain_digest(
        b"fa:cash-flow-split-certificate-digest:v1",
        &[&bytes[..body]],
    );
    bytes[body..].copy_from_slice(&digest);
    let forged = CashFlowSplitCertificate::decode(&bytes).unwrap();
    assert_ne!(forged.output(), original.certificate().output());
    let refusal = h
        .book
        .replay_split_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &forged,
            &request,
            &definition,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-150");
    assert_eq!(refusal.exit, 8);
}

#[test]
fn same_book_identity_and_sequence_count_do_not_substitute_another_native_history() {
    use Side::{Credit as C, Debit as D};
    let mut a = Harness::new();
    a.loan(1);
    let request = a.request();
    let definition = a.loan_definition(1);
    let original = certify(&a, &request, &definition);
    let mut b = Harness::new();
    b.post(1, b"opening", b.usd, &[("1000", D, 500), ("3000", C, 500)]);
    b.post(
        10,
        b"loan-payment",
        b.usd,
        &[("1000", C, 101), ("2300", D, 93), ("6100", D, 8)],
    );
    assert_eq!(a.head(), b.head());
    assert_eq!(a.book.context().book_id, b.book.context().book_id);
    a.book
        .replay_split_cash_flow(
            &a.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            original.certificate(),
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert!(!matches!(
        b.book.replay_split_cash_flow(
            &b.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            original.certificate(),
            &request,
            &definition
        ),
        Ok(Ok(_))
    ));
}

#[test]
fn truncated_changed_and_extended_transport_never_yields_a_certificate() {
    let mut h = Harness::new();
    h.loan(1);
    let original = certify(&h, &h.request(), &h.loan_definition(1));
    let bytes = original.certificate().canonical_bytes().unwrap();
    for n in [
        0,
        1,
        31,
        32,
        64,
        bytes.len() / 2,
        bytes.len() - 33,
        bytes.len() - 1,
    ] {
        assert!(CashFlowSplitCertificate::decode(&bytes[..n]).is_err());
    }
    let mut changed = bytes.clone();
    changed[40] ^= 1;
    assert!(CashFlowSplitCertificate::decode(&changed).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(CashFlowSplitCertificate::decode(&trailing).is_err());
}
