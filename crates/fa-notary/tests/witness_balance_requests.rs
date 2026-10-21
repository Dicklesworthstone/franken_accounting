//! Actual Notary-produced nonzero balances through the recipient-bound bundle API.
//! These fixtures exercise serialization/signatures/folds, not posting admission.

use std::collections::BTreeMap;

use fa_model::{EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey};
use fa_money::{Amount, Side, UnitId};
use fa_notary::bundle::{
    BalanceRequest, BundleRequest, BundleScope, ProductionReceipt, ReceiptBody, assemble,
};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::{CheckpointSigner, Journal, ScopeIndex, SigningKey, StoredCheckpoint};
use fa_time::DateDay;
use fa_verify::checkpoint::witness::bundle::balances::verify_witnessed_bundle_balances_for;
use fa_verify::checkpoint::witness::bundle::{BundleExpectation, verify_witnessed_bundle_for};
use fa_verify::checkpoint::witness::{
    RecipientWitnessPolicy, WitnessedCheckpoint, verify_witnessed_checkpoint,
};
use fa_verify::{BalanceAmounts, BalanceExpectation, BalanceScope};
use fgdb_types::{CommitSeq, VId};

fn fixture() -> (Journal, StoredCheckpoint, WitnessedCheckpoint, SigningKey) {
    let book = Id128([0x11; 16]);
    let legs = vec![
        LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(1), 123)),
        LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(1), 123)),
        LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(2), 45)),
        LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(2), 45)),
    ];
    let proposal = EntryPayload {
        schema_minor: 1,
        book_id: book,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay(20_527),
        document_date: None,
        description: Erasable::seal(
            &"balance request".to_string(),
            None,
            &SealKey([3; 32]),
            [1; 32],
            [2; 24],
        ),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"witness-balance-request".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([4; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: None,
        evidence: vec![],
        supersession: vec![],
        pending: None,
        external_ids: vec![],
        extensions: vec![],
        tags: vec![],
    };
    let journal = Journal::from_records(
        book,
        CommitSeq(7),
        vec![(VId(100), proposal.seal(vec![], None).unwrap(), CommitSeq(7))],
    )
    .unwrap();
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let checkpoint = TransparencyCheckpoint::sign(
        CheckpointBody {
            statement: journal.statement(),
            state_oid: Oid([2; 32]),
            scope_index_root: ScopeIndex::of(&journal).root(),
            substrate_chain_commitment: [4; 32],
            witness_policy_oid: Some(Oid([0x55; 32])),
            time_evidence_oid: None,
        },
        &[&publisher, &a, &b],
    )
    .unwrap();
    let stored = StoredCheckpoint {
        oid: checkpoint.oid().unwrap(),
        vid: VId(1),
        bytes: checkpoint.canonical_bytes().unwrap(),
        checkpoint,
    };
    let policy = RecipientWitnessPolicy::new(
        book.0,
        [0; 16],
        [0x55; 32],
        publisher.public_key(),
        &[a.public_key(), b.public_key()],
        2,
    )
    .unwrap();
    let pin = verify_witnessed_checkpoint(&stored.bytes, &policy).unwrap();
    (journal, stored, pin, publisher)
}

fn expected() -> [BalanceExpectation; 2] {
    [
        BalanceExpectation {
            scope: BalanceScope {
                account: 10,
                unit: 1,
                effective_through: None,
            },
            amounts: Some(BalanceAmounts {
                debits: 123,
                credits: 0,
            }),
        },
        BalanceExpectation {
            scope: BalanceScope {
                account: 20,
                unit: 2,
                effective_through: Some(20_527),
            },
            amounts: Some(BalanceAmounts {
                debits: 0,
                credits: 45,
            }),
        },
    ]
}

fn bundle_request(balances: &[BalanceExpectation]) -> BundleRequest {
    BundleRequest {
        scope: BundleScope::Prefix,
        inline_documents: true,
        balances: balances
            .iter()
            .map(|b| BalanceRequest {
                account: VId(b.scope.account),
                unit: b.scope.unit,
                effective_through: b.scope.effective_through,
            })
            .collect(),
    }
}

fn requirement() -> BundleExpectation {
    BundleExpectation {
        scope: fa_verify::BundleScope::Prefix,
        inline_documents: true,
        publisher_receipt: false,
    }
}

#[test]
fn actual_producer_proofs_satisfy_exact_nonzero_multi_unit_cells_and_publisher_receipt() {
    let (journal, stored, pin, publisher) = fixture();
    let mut wanted = expected();
    let bundle = assemble(
        &journal,
        &stored,
        &bundle_request(&wanted),
        &BTreeMap::new(),
    )
    .unwrap()
    .unwrap();
    let receipt = ProductionReceipt::sign(
        ReceiptBody {
            bundle_digest: bundle.digest,
            producer_principal: VId(7),
            produced_at_seq: CommitSeq(8),
            capability_commitment: [0x66; 32],
            time_evidence_oid: None,
        },
        &publisher,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    wanted.reverse(); // producer order is not a selector
    let requirement = BundleExpectation {
        publisher_receipt: true,
        ..requirement()
    };
    let report = verify_witnessed_bundle_balances_for(
        &bundle.bytes,
        &pin,
        &requirement,
        &wanted,
        Some(&receipt),
    )
    .unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(report.digest, bundle.digest);
    assert_eq!(report.summary.balances.len(), 2);
    assert!(report.receipt.is_some());
}

#[test]
fn valid_productions_cannot_omit_duplicate_or_substitute_requested_stock_cells() {
    let (journal, stored, pin, _) = fixture();
    let wanted = expected();
    let mut changed_unit = wanted[1];
    changed_unit.scope.unit = 1;
    let mut changed_cutoff = wanted[1];
    changed_cutoff.scope.effective_through = Some(20_526);
    for supplied in [
        vec![],
        vec![wanted[0]],
        vec![wanted[0], wanted[0]],
        vec![wanted[0], changed_unit],
        vec![wanted[0], changed_cutoff],
    ] {
        let bundle = assemble(
            &journal,
            &stored,
            &bundle_request(&supplied),
            &BTreeMap::new(),
        )
        .unwrap()
        .unwrap();
        assert!(
            verify_witnessed_bundle_for(&bundle.bytes, &pin, &requirement(), None)
                .unwrap()
                .verified()
        );
        let report = verify_witnessed_bundle_balances_for(
            &bundle.bytes,
            &pin,
            &requirement(),
            &wanted,
            None,
        )
        .unwrap();
        assert!(!report.verified(), "{:?}", report.checks);
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.check == "requested_balance_set"
                    && matches!(c.grade, fa_verify::Grade::Fail(_)))
        );
    }
}

#[test]
fn real_nonzero_gross_amounts_are_not_replaceable_by_an_equal_net() {
    let (journal, stored, pin, _) = fixture();
    let mut wanted = expected();
    let bundle = assemble(
        &journal,
        &stored,
        &bundle_request(&wanted),
        &BTreeMap::new(),
    )
    .unwrap()
    .unwrap();
    wanted[0].amounts = Some(BalanceAmounts {
        debits: 223,
        credits: 100,
    }); // same net 123
    let report =
        verify_witnessed_bundle_balances_for(&bundle.bytes, &pin, &requirement(), &wanted, None)
            .unwrap();
    assert!(!report.verified());
    assert!(
        report.checks.iter().any(
            |c| c.check == "requested_balance_set" && matches!(c.grade, fa_verify::Grade::Pass)
        )
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.check == "requested_balance_amounts"
                && matches!(c.grade, fa_verify::Grade::Fail(_)))
    );
    wanted[0].amounts = None;
    assert!(
        verify_witnessed_bundle_balances_for(&bundle.bytes, &pin, &requirement(), &wanted, None,)
            .unwrap()
            .verified()
    );
}
