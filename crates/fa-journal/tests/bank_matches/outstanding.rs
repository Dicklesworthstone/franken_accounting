//! Outstanding deposits and checks are exact native cash-leg selections. The
//! bridge, historical replay and closing lock all use the same retained claim.

use super::*;
use fa_journal::attestation::{
    Attestation, AttestationClaim, CapabilityBinding, Subject, read_attestation, reconciled_vid,
};
use fa_journal::bank::{
    BankOutstandingItem, BankOutstandingLeg, BankReconciliationPreparation,
    BankReconciliationRecorded, BankReconciliationRequest, BankReconciliationStatus,
    bank_reconciliation_status, prepare_bank_reconciliation_with_outstanding,
    reconcile_bank_statement, reconcile_bank_statement_with_outstanding,
};
use fa_journal::post::{PostPreparation, prepare_post};
use fa_journal::refusal::{code, exit};
use fa_journal::rows::edge_id;

fn post_request(
    h: &mut Harness,
    proposal: EntryPayload,
    capability: Capability,
) -> Result<Posted, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(post(
            &mut h.db,
            &cx,
            &h.book,
            PostRequest {
                proposal,
                capability,
                approvals: Vec::new(),
                plan_certificate: None,
            },
        ))
        .unwrap()
}

fn cash(h: &mut Harness, signed: i128, reference: &str, key: &[u8]) -> EntryRef {
    let mut proposal = h.entry_payload(&[signed.abs()], reference, key);
    if signed < 0 {
        for leg in &mut proposal.legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    }
    post_request(h, proposal, cap(OWNER)).unwrap().entry_ref()
}

fn selected(entry_ref: EntryRef) -> BankOutstandingLeg {
    BankOutstandingLeg {
        entry_ref,
        leg_ordinal: 0,
    }
}

fn close_request(h: &Harness, import: BankImportWitness) -> BankReconciliationRequest {
    BankReconciliationRequest {
        import,
        predecessors: Vec::new(),
        evaluated_known_at: h.head(),
    }
}

fn close(
    h: &mut Harness,
    request: BankReconciliationRequest,
    outstanding: Vec<BankOutstandingLeg>,
) -> Result<BankReconciliationRecorded, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(reconcile_bank_statement_with_outstanding(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            None,
            request,
            outstanding,
        ))
        .unwrap()
}

fn status(
    h: &mut Harness,
    manifest: Oid,
    at: Option<CommitSeq>,
) -> Result<BankReconciliationStatus, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(bank_reconciliation_status(
            &mut h.db,
            &cx,
            &h.book,
            &metadata_cap(OWNER),
            manifest,
            at,
        ))
        .unwrap()
}

fn confirmed(h: &mut Harness) -> (BankImportWitness, BankMatchRecorded) {
    let entry = cash(h, 10_000, "WIRE", b"cleared-cash");
    let (import, line) = h.imported("WIRE", 10_000, b"cleared-statement");
    let request = h.request(import.clone(), line, entry, 0);
    let matched = h.confirm(&cap(CONFIRMER), request).unwrap();
    (import, matched)
}

fn empty_statement(h: &mut Harness, key: &[u8]) -> BankImportWitness {
    reconciliation_tests::statement(h, "", &[], day(), day(), 0, key).0
}

fn assert_bank_refusal(
    h: &mut Harness,
    import: BankImportWitness,
    outstanding: Vec<BankOutstandingLeg>,
    message: &str,
) {
    let request = close_request(h, import);
    let before = h.head();
    let failure = close(h, request, outstanding).unwrap_err();
    assert_eq!(failure.code, code::BANK_MATCH, "{}", failure.message);
    assert!(failure.message.contains(message), "{}", failure.message);
    assert_eq!(
        h.head(),
        before,
        "a refused bridge publishes no native rows"
    );
}

#[test]
fn deposits_and_checks_derive_exact_signed_amounts_and_cite_their_sources() {
    let mut h = Harness::new();
    let (import, matched) = confirmed(&mut h);
    // These amounts distinguish integer accounting from a binary64 round trip.
    let deposit_amount = 9_007_199_254_740_993_i128;
    let check_amount = 9_007_199_254_740_000_i128;
    let deposit = cash(&mut h, deposit_amount, "DEPOSIT", b"outstanding-deposit");
    let check = cash(&mut h, -check_amount, "CHECK", b"outstanding-check");
    let request = close_request(&h, import.clone());
    let evaluated = request.evaluated_known_at;
    let recorded = close(&mut h, request, vec![selected(check), selected(deposit)]).unwrap();
    let mut expected = vec![
        BankOutstandingItem {
            entry_ref: deposit,
            leg_ordinal: 0,
            signed_amount: deposit_amount,
        },
        BankOutstandingItem {
            entry_ref: check,
            leg_ordinal: 0,
            signed_amount: -check_amount,
        },
    ];
    expected.sort_by_key(|item| (item.entry_ref.vid, item.leg_ordinal));
    assert_eq!(recorded.claim.outstanding, expected);
    assert_eq!(recorded.claim.cash_balance, 10_993);
    assert_eq!(recorded.claim.outstanding_amount(), Some(993));
    assert_eq!(recorded.claim.adjusted_cash_balance(), Some(10_000));
    assert_eq!(recorded.claim.matches, vec![decision_ref(&matched)]);
    assert_eq!(recorded.recorded_at.0, evaluated.0 + 1);
    let (stored, at) = read_attestation(&h.db, recorded.attestation_vid)
        .unwrap()
        .unwrap();
    assert_eq!(stored.attestation.claim.tag(), 11);
    assert_eq!(
        stored.attestation.claim,
        AttestationClaim::Reconciled(Box::new(recorded.claim.clone()))
    );
    assert_eq!(at, recorded.recorded_at);
    for source in [deposit, check] {
        assert!(
            h.db.edge_at(
                edge_id(relation::CITES, recorded.attestation_vid, source.vid),
                at
            )
            .unwrap()
            .is_some()
        );
    }
    let current = status(&mut h, import.manifest_oid(), None).unwrap();
    assert_eq!(current.reconciled_through, Some(day()));
    assert!(!current.reconciliations[0].balance_drift);
    assert!(!current.reconciliations[0].cash_drift);
}

#[test]
fn zero_sum_selections_remain_explicit_and_retry_binds_exact_refs_not_just_the_net() {
    let mut h = Harness::new();
    let first = cash(&mut h, 500, "FIRST", b"first-deposit");
    let first_check = cash(&mut h, -500, "FIRST", b"first-check");
    let second = cash(&mut h, 500, "SECOND", b"second-deposit");
    let second_check = cash(&mut h, -500, "SECOND", b"second-check");
    let import = empty_statement(&mut h, b"zero-sum-statement");
    let request = close_request(&h, import);
    let recorded = close(
        &mut h,
        request.clone(),
        vec![selected(first), selected(first_check)],
    )
    .unwrap();
    assert_eq!(recorded.claim.outstanding.len(), 2);
    assert_eq!(recorded.claim.outstanding_amount(), Some(0));
    assert_eq!(recorded.claim.adjusted_cash_balance(), Some(0));
    let (stored, _) = read_attestation(&h.db, recorded.attestation_vid)
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.attestation.claim.tag(),
        11,
        "zero net is still a nonempty reviewed selection"
    );
    let before = h.head();
    let retry = close(
        &mut h,
        request.clone(),
        vec![selected(first_check), selected(first)],
    )
    .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.attestation_vid, recorded.attestation_vid);
    assert_eq!(retry.attestation_digest, recorded.attestation_digest);
    assert_eq!(retry.recorded_at, recorded.recorded_at);
    assert_eq!(retry.claim, recorded.claim);
    for changed in [Vec::new(), vec![selected(second), selected(second_check)]] {
        assert_eq!(
            close(&mut h, request.clone(), changed).unwrap_err().code,
            code::CONFLICT
        );
        assert_eq!(h.head(), before);
    }

    // The old entrypoint retains the original empty-selection wire profile.
    let mut h = Harness::new();
    let import = empty_statement(&mut h, b"legacy-empty-statement");
    let request = close_request(&h, import);
    let cx = h.cx();
    let legacy = h
        .runtime
        .block_on(reconcile_bank_statement(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            None,
            request,
        ))
        .unwrap()
        .unwrap();
    let (stored, _) = read_attestation(&h.db, legacy.attestation_vid)
        .unwrap()
        .unwrap();
    assert!(legacy.claim.outstanding.is_empty());
    assert_eq!(stored.attestation.claim.tag(), 3);
}

#[test]
fn outstanding_sources_must_be_unique_posted_cash_in_the_exact_account_unit_and_cutoff() {
    for attack in [
        "digest",
        "missing",
        "ordinal",
        "account",
        "future",
        "pending",
        "unit",
        "duplicate",
        "duplicate-digest",
    ] {
        let mut h = Harness::with_currency_policy(None, None, true);
        let mut proposal = h.entry_payload(&[500], "OUTSTANDING", b"selected-source");
        match attack {
            "future" => proposal.effective_date = DateDay(day().0 + 1),
            "pending" => {
                proposal.class = EntryClass::PENDING;
                proposal.pending = Some(fa_model::Pending {
                    timeout_ns: None,
                    resolution_of: None,
                    disposition: None,
                });
            }
            "unit" => {
                let eur = h.book.units.lookup("EUR").unwrap();
                for leg in &mut proposal.legs {
                    leg.amount.unit = eur;
                }
                proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
            }
            _ => {}
        }
        let entry = post_request(&mut h, proposal, cap(OWNER))
            .unwrap()
            .entry_ref();
        let import = empty_statement(&mut h, b"invalid-source-statement");
        let mut references = vec![selected(entry)];
        let message = match attack {
            "digest" => {
                references[0].entry_ref.entry_digest[0] ^= 1;
                "unchanged posted cash Entry"
            }
            "missing" => {
                references[0].entry_ref.vid = VId(0);
                "did not exist"
            }
            "ordinal" => {
                references[0].leg_ordinal = 2;
                "no such original cash-leg ordinal"
            }
            "account" => {
                references[0].leg_ordinal = 1;
                "exact cash account and currency"
            }
            "future" | "unit" => "exact cash account and currency",
            "pending" => "unchanged posted cash Entry",
            "duplicate" | "duplicate-digest" => {
                let mut duplicate = references[0];
                if attack == "duplicate-digest" {
                    duplicate.entry_ref.entry_digest[0] ^= 1;
                }
                references.push(duplicate);
                "repeats a cash Entry and leg ordinal"
            }
            _ => unreachable!(),
        };
        assert_bank_refusal(&mut h, import, references, message);
    }
}

#[test]
fn an_active_confirmation_on_any_statement_precludes_outstanding_until_explicit_release() {
    let mut h = Harness::new();
    let entry = cash(&mut h, 500, "CLEARED", b"cleared-elsewhere");
    let (other, line) = h.imported("CLEARED", 500, b"other-statement");
    let request = h.request(other, line, entry, 0);
    let matched = h.confirm(&cap(CONFIRMER), request).unwrap();
    let import = empty_statement(&mut h, b"reviewed-statement");
    assert_bank_refusal(
        &mut h,
        import.clone(),
        vec![selected(entry)],
        "already has an active native bank confirmation",
    );
    h.unmatch(&metadata_cap(OWNER), decision_ref(&matched))
        .unwrap();
    let request = close_request(&h, import);
    let recorded = close(&mut h, request, vec![selected(entry)]).unwrap();
    assert_eq!(recorded.claim.cash_balance, 500);
    assert_eq!(recorded.claim.adjusted_cash_balance(), Some(0));
}

#[test]
fn the_bridge_never_substitutes_for_statement_confirmation_or_an_unexplained_difference() {
    let mut h = Harness::new();
    let cleared = cash(&mut h, 10_000, "WIRE", b"unconfirmed-cash");
    let deposit = cash(&mut h, 700, "OUTSTANDING", b"unconfirmed-outstanding");
    let (import, line) = h.imported("WIRE", 10_000, b"unconfirmed-statement");
    assert_bank_refusal(
        &mut h,
        import.clone(),
        vec![selected(deposit)],
        "every retained statement line",
    );
    let request = h.request(import.clone(), line, cleared, 0);
    h.confirm(&cap(CONFIRMER), request).unwrap();
    assert_bank_refusal(
        &mut h,
        import.clone(),
        Vec::new(),
        "differs from statement closing",
    );
    cash(&mut h, 200, "UNEXPLAINED", b"unexplained-cash");
    assert_bank_refusal(
        &mut h,
        import,
        vec![selected(deposit)],
        "differs from statement closing",
    );
}

#[test]
fn later_clearance_preserves_the_original_claim_but_cannot_be_reused_as_current_outstanding() {
    let mut h = Harness::new();
    let (import, _) = confirmed(&mut h);
    let deposit = cash(&mut h, 500, "DEPOSIT", b"later-cleared-deposit");
    let request = close_request(&h, import.clone());
    let recorded = close(&mut h, request.clone(), vec![selected(deposit)]).unwrap();
    let original_row = h.db.vertex(recorded.attestation_vid).unwrap().unwrap();
    let (next, line) = h.imported("DEPOSIT", 500, b"later-clearance-statement");
    let confirmation = h.request(next, line, deposit, 0);
    h.confirm(&cap(CONFIRMER), confirmation).unwrap();
    let before = h.head();
    let retry = close(&mut h, request, vec![selected(deposit)]).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.attestation_vid, recorded.attestation_vid);
    assert_eq!(retry.recorded_at, recorded.recorded_at);
    assert_eq!(retry.claim, recorded.claim);
    assert_eq!(h.head(), before);
    assert_eq!(
        h.db.vertex(recorded.attestation_vid).unwrap().unwrap(),
        original_row
    );
    for at in [Some(recorded.recorded_at), None] {
        let state = status(&mut h, import.manifest_oid(), at).unwrap();
        assert_eq!(state.reconciled_through, Some(day()));
        assert_eq!(state.reconciliations.len(), 1);
        assert_eq!(state.reconciliations[0].recorded.claim, recorded.claim);
        assert!(!state.reconciliations[0].cash_drift);
        assert!(!state.reconciliations[0].match_drift);
    }
    assert_bank_refusal(
        &mut h,
        import,
        vec![selected(deposit)],
        "already has an active native bank confirmation",
    );
}

#[test]
fn adjusted_closes_and_prepared_cash_posts_conflict_in_both_orders_and_install_the_cutoff() {
    for close_first in [false, true] {
        let mut h = Harness::new();
        let (import, _) = confirmed(&mut h);
        let deposit = cash(&mut h, 500, "DEPOSIT", b"racing-outstanding");
        let request = close_request(&h, import.clone());
        let reviewed = h.head();
        let late = PostRequest {
            proposal: h.entry_payload(&[200], "LATE", b"racing-late-cash"),
            capability: Capability::embedded(OWNER, &["post"]).unwrap(),
            approvals: Vec::new(),
            plan_certificate: None,
        };
        let cx = h.cx();
        let PostPreparation::Ready(prepared_post) =
            prepare_post(&mut h.db, &cx, &h.book, late.clone())
                .unwrap()
                .unwrap()
        else {
            panic!("a fresh cash entry prepares before the close");
        };
        let BankReconciliationPreparation::Ready(prepared_close) =
            prepare_bank_reconciliation_with_outstanding(
                &mut h.db,
                &cx,
                &h.book,
                &cap(CONFIRMER),
                None,
                request,
                vec![selected(deposit)],
            )
            .unwrap()
            .unwrap()
        else {
            panic!("an explained outstanding bridge prepares");
        };
        if close_first {
            let recorded = h
                .runtime
                .block_on(prepared_close.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            let failure = h
                .runtime
                .block_on(prepared_post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err();
            assert_eq!(
                (failure.code, failure.exit),
                (code::CONFLICT, exit::CONFLICT)
            );
            assert_eq!(h.head().0, reviewed.0 + 1);
            let before = h.head();
            let failure = post_request(&mut h, late.proposal.clone(), late.capability).unwrap_err();
            assert_eq!(failure.code, code::CAPABILITY);
            assert_eq!(h.head(), before);
            let authorized = post_request(&mut h, late.proposal, cap(OWNER)).unwrap();
            assert!(
                h.db.edge_at(
                    edge_id(
                        relation::CITES,
                        authorized.entry_ref().vid,
                        recorded.attestation_vid
                    ),
                    h.head()
                )
                .unwrap()
                .is_some()
            );
            let state = status(&mut h, import.manifest_oid(), None).unwrap();
            assert!(state.reconciliations[0].cash_drift);
            assert_eq!(
                state.reconciliations[0].citing_entries,
                vec![authorized.entry_ref()]
            );
        } else {
            h.runtime
                .block_on(prepared_post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            let failure = h
                .runtime
                .block_on(prepared_close.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err();
            assert_eq!(
                (failure.code, failure.exit),
                (code::CONFLICT, exit::CONFLICT)
            );
            assert_eq!(h.head().0, reviewed.0 + 1);
            assert!(
                status(&mut h, import.manifest_oid(), None)
                    .unwrap()
                    .reconciliations
                    .is_empty()
            );
        }
    }
}

#[test]
fn clearing_a_selected_leg_invalidates_a_prepared_adjusted_close() {
    let mut h = Harness::new();
    let (import, _) = confirmed(&mut h);
    let deposit = cash(&mut h, 500, "DEPOSIT", b"racing-clearance");
    let (next, line) = h.imported("DEPOSIT", 500, b"racing-clearance-statement");
    let confirmation = h.request(next, line, deposit, 0);
    let request = close_request(&h, import.clone());
    let cx = h.cx();
    let BankReconciliationPreparation::Ready(prepared) =
        prepare_bank_reconciliation_with_outstanding(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            None,
            request,
            vec![selected(deposit)],
        )
        .unwrap()
        .unwrap()
    else {
        panic!("an uncleared deposit prepares");
    };
    h.confirm(&cap(CONFIRMER), confirmation).unwrap();
    let before = h.head();
    let failure = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.code, code::CONFLICT);
    assert_eq!(h.head(), before);
    assert!(
        status(&mut h, import.manifest_oid(), None)
            .unwrap()
            .reconciliations
            .is_empty()
    );
    assert_bank_refusal(
        &mut h,
        import,
        vec![selected(deposit)],
        "already has an active native bank confirmation",
    );
}

#[test]
fn a_self_consistent_claim_cannot_invent_amounts_or_rebind_an_outstanding_source() {
    for change_source in [false, true] {
        let mut h = Harness::new();
        let (import, _) = confirmed(&mut h);
        let deposit = cash(&mut h, 300, "DEPOSIT", b"forged-deposit");
        let check = cash(&mut h, -100, "CHECK", b"forged-check");
        let request = close_request(&h, import.clone());
        let recorded = close(&mut h, request, vec![selected(deposit), selected(check)]).unwrap();
        let mut forged = recorded.claim;
        forged.evaluated_known_at = h.head();
        if change_source {
            forged.outstanding[0].entry_ref.entry_digest[0] ^= 1;
        } else {
            // Preserve the bridge's total; only exact source derivation detects
            // the two invented, offsetting per-leg amounts.
            forged.outstanding[0].signed_amount += 1;
            forged.outstanding[1].signed_amount -= 1;
        }
        assert_eq!(forged.adjusted_cash_balance(), Some(10_000));
        let identity = reconciled_vid(
            h.book.book_id,
            import.manifest_oid(),
            forged.evaluated_known_at,
            OWNER,
        );
        let mut evidence = vec![import.manifest_oid(), import.manifest().statement_oid];
        evidence.sort();
        let attestation = Attestation {
            book_id: h.book.book_id,
            claim: AttestationClaim::Reconciled(Box::new(forged)),
            subject: Subject::Document(import.manifest_oid()),
            principal: OWNER,
            evidence_refs: evidence,
        };
        let binding = CapabilityBinding {
            profile: Profile::Human,
            capability_commitment: cap(OWNER).commitment().unwrap(),
        };
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(attestation.canonical_bytes(&binding).unwrap()).unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(attestation.signed_digest().unwrap().to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
            ),
            (
                property::CODE,
                CanonicalScalar::ucs_basic_text("Reconciled").unwrap(),
            ),
        ];
        props.sort_by_key(|(key, _)| key.0);
        let mut damage = WriteBatch::new(relation::ATTESTS);
        damage.create_vertex(identity, vec![label::ATTESTATION], props);
        h.write(damage);
        let failure = status(&mut h, import.manifest_oid(), None).unwrap_err();
        assert_eq!(failure.code, code::ATTESTATION_DRIFT);
        assert!(
            failure.message.contains(if change_source {
                "unchanged posted cash Entry"
            } else {
                "selected outstanding cash legs"
            }),
            "{}",
            failure.message
        );
    }
}

#[test]
fn outstanding_citation_damage_is_detected_even_after_exact_property_restoration() {
    for restore in [false, true] {
        let mut h = Harness::new();
        let (import, _) = confirmed(&mut h);
        let deposit = cash(&mut h, 500, "DEPOSIT", b"protected-outstanding");
        let request = close_request(&h, import.clone());
        let recorded = close(&mut h, request.clone(), vec![selected(deposit)]).unwrap();
        let eid = edge_id(relation::CITES, recorded.attestation_vid, deposit.vid);
        let mut damage = WriteBatch::new(relation::CITES);
        if restore {
            damage.set_edge_property(
                eid,
                property::FA_DIGEST,
                Some(CanonicalScalar::bytes(vec![9; 32]).unwrap()),
            );
        } else {
            damage.delete_edge(eid);
        }
        h.write(damage);
        if restore {
            let mut restoration = WriteBatch::new(relation::CITES);
            restoration.set_edge_property(eid, property::FA_DIGEST, None);
            h.write(restoration);
        }
        let before = h.head();
        assert_eq!(
            status(&mut h, import.manifest_oid(), None)
                .unwrap_err()
                .code,
            code::ATTESTATION_DRIFT
        );
        assert_eq!(
            close(&mut h, request, vec![selected(deposit)])
                .unwrap_err()
                .code,
            code::ATTESTATION_DRIFT
        );
        assert_eq!(h.head(), before);
        assert!(status(&mut h, import.manifest_oid(), Some(recorded.recorded_at)).is_ok());
    }
}
