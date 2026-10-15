//! Real model codec versus the independent v3 balance verifier.
//! Detached journals test proof semantics, not kernel admission or economics.

use fa_journal::migration::{RunBody, RunMode, kind};
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128,
    LegPayload, Oid, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::{AccumulatorState, Journal};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x5a; 16]);
const KEY: SealKey = SealKey([0x33; 32]);
const CASH: VId = VId(10);
const OFFSET: VId = VId(20);

fn body(mode: RunMode, sole: bool, key: &str) -> RunBody {
    RunBody {
        book_id: BOOK,
        run_key: key.into(),
        source_system: "legacy".into(),
        mode,
        trial_balance: Oid([1; 32]),
        opening_date: DateDay(100),
        lines: Vec::new(),
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: sole,
    }
}

fn payload(class: EntryClass, legs: Vec<LegPayload>, seq: u64, day: i32) -> EntryPayload {
    EntryPayload {
        schema_minor: 1,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class,
        effective_date: DateDay(day),
        document_date: None,
        description: Erasable::seal(&"complete proof".to_string(), None, &KEY, [1; 32], [2; 24]),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: seq.to_le_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([4; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

fn control(body: &RunBody, transition: u8, seq: u64) -> (VId, Entry, CommitSeq) {
    let digest = body.digest().unwrap();
    let mut p = payload(EntryClass::MIGRATION_CONTROL, vec![], seq, 100);
    p.control = Some(ControlPayload::MigrationControl {
        run_ref: body.vid(),
        kind: transition,
        tie_out_digest: if transition == kind::OPEN {
            digest
        } else {
            [9; 32]
        },
    });
    p.origin = EntryOrigin::Control {
        control_kind: ControlKind::MIGRATION_RUN,
        spec_body_digest: digest,
    };
    (
        VId(u128::from(seq)),
        p.seal(vec![], None).unwrap(),
        CommitSeq(seq),
    )
}

fn posting(body: Option<&RunBody>, seq: u64, day: i32, unit: u32) -> (VId, Entry, CommitSeq) {
    let class = if body.is_some() {
        EntryClass::MIGRATION
    } else {
        EntryClass::ORIGINAL
    };
    let mut p = payload(
        class,
        vec![
            LegPayload::simple(Side::Debit, CASH, Amount::new(UnitId(unit), 5_000)),
            LegPayload::simple(Side::Credit, OFFSET, Amount::new(UnitId(unit), 5_000)),
        ],
        seq,
        day,
    );
    if let Some(body) = body {
        p.origin = EntryOrigin::Migration {
            run_ref: body.vid(),
            source_system: body.source_system.clone(),
            source_id: Erasable::seal(&"source entry".to_string(), None, &KEY, [3; 32], [4; 24]),
            source_recorded_at_ns: Some(42),
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: Oid([5; 32]),
        };
    }
    (
        VId(u128::from(seq)),
        p.seal(vec![], None).unwrap(),
        CommitSeq(seq),
    )
}

fn anchor(journal: &Journal) -> fa_verify::Checkpoint {
    let state = AccumulatorState::of_journal(journal, None);
    fa_verify::verify_state(&state.canonical_bytes().unwrap())
        .unwrap()
        .checkpoint
}

fn checked(
    journal: &Journal,
    bodies: &[RunBody],
    account: VId,
    unit: u32,
    day: Option<i32>,
) -> fa_verify::Balance {
    let bytes = journal
        .balance_proof_complete(account, unit, day, bodies)
        .unwrap()
        .unwrap();
    let mut reader = fa_model::Reader::new(&bytes);
    assert_eq!(
        reader.bytes(128, "format").unwrap(),
        fa_verify::migration_balance::BALANCE_FORMAT_V3
    );
    let result = fa_verify::verify_balance(&bytes, &anchor(journal)).unwrap();
    assert_eq!(result.scope, "recomputation");
    result
}

fn ordinary_prefix() -> Journal {
    let (vid, entry, seq) = posting(None, 2, 100, 1);
    let mut pending = entry.proposal;
    pending.class = EntryClass::PENDING;
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    Journal::from_records(
        BOOK,
        CommitSeq(4),
        vec![
            posting(None, 1, 100, 1),
            (vid, pending.seal(vec![], None).unwrap(), seq),
            posting(None, 3, 101, 1),
            posting(None, 4, 100, 2),
        ],
    )
    .unwrap()
}

#[test]
fn complete_proofs_bind_excluded_pending_future_and_other_unit_payloads() {
    let journal = ordinary_prefix();
    let cash = checked(&journal, &[], CASH, 1, Some(100));
    assert_eq!((cash.claim.debits, cash.claim.credits), (5_000, 0));
    assert_eq!(cash.contributing, vec![0]);
    let offset = checked(&journal, &[], OFFSET, 1, Some(100));
    assert_eq!((offset.claim.debits, offset.claim.credits), (0, 5_000));
    assert_eq!(checked(&journal, &[], CASH, 1, None).claim.debits, 10_000);
    assert_eq!(checked(&journal, &[], CASH, 2, None).claim.debits, 5_000);
    assert_eq!(checked(&journal, &[], CASH, 1, Some(99)).claim.debits, 0);
    assert_eq!(checked(&journal, &[], VId(999), 1, None).claim.debits, 0);
    let bytes = journal
        .balance_proof_complete(CASH, 1, Some(100), &[])
        .unwrap()
        .unwrap();
    for leaf in &journal.leaves {
        assert!(
            bytes
                .windows(leaf.payload.len())
                .any(|part| part == leaf.payload)
        );
    }
}

#[test]
fn all_model_migration_modes_preserve_visibility_and_minimal_body_disclosure() {
    for (mode, sole) in [
        (RunMode::OpeningOnly, false),
        (RunMode::PeriodBalances, false),
        (RunMode::FullDetail, false),
        (RunMode::FullDetail, true),
    ] {
        for terminal in [None, Some(kind::FINALIZE), Some(kind::ABANDON)] {
            for day in [90, 100] {
                let run = body(mode, sole, "selected");
                let unrelated = body(RunMode::OpeningOnly, false, "private-other-unit");
                let mut records =
                    vec![control(&run, kind::OPEN, 1), posting(Some(&run), 2, day, 1)];
                if let Some(transition) = terminal {
                    records.push(control(&run, transition, 3));
                }
                records.extend([
                    control(&unrelated, kind::OPEN, 4),
                    posting(Some(&unrelated), 5, day, 2),
                    control(&unrelated, kind::FINALIZE, 6),
                ]);
                let journal = Journal::from_records(BOOK, CommitSeq(6), records).unwrap();
                let visible = terminal == Some(kind::FINALIZE)
                    && (mode != RunMode::FullDetail || sole || day >= 100);
                let witnesses = std::slice::from_ref(&run);
                let report = checked(&journal, witnesses, CASH, 1, Some(day));
                assert_eq!(report.claim.debits, if visible { 5_000 } else { 0 });
                assert_eq!(report.contributing, if visible { vec![1] } else { vec![] });
                assert_eq!(
                    checked(&journal, &[], CASH, 1, Some(day - 1)).claim.debits,
                    0
                );
                let bytes = journal
                    .balance_proof_complete(CASH, 1, Some(day), witnesses)
                    .unwrap()
                    .unwrap();
                let secret = unrelated.canonical_bytes().unwrap();
                assert!(!bytes.windows(secret.len()).any(|part| part == secret));
            }
        }
    }
}

#[test]
fn legacy_wire_bytes_are_stable_but_do_not_overstate_their_assurance() {
    let journal = ordinary_prefix();
    let v1 = journal.balance_proof(CASH, 1, Some(100)).unwrap().unwrap();
    let v2 = journal
        .balance_proof_with_migrations(CASH, 1, Some(100), &[])
        .unwrap()
        .unwrap();
    let full = checked(&journal, &[], CASH, 1, Some(100));
    for bytes in [&v1, &v2] {
        let legacy = fa_verify::verify_balance(bytes, &anchor(&journal)).unwrap();
        assert_eq!(legacy.scope, "membership_only");
        assert_eq!(legacy.claim, full.claim);
    }
    assert_eq!(
        journal.balance_proof(CASH, 1, Some(100)).unwrap().unwrap(),
        v1
    );
    assert_eq!(
        journal
            .balance_proof_with_migrations(CASH, 1, Some(100), &[])
            .unwrap()
            .unwrap(),
        v2
    );
}

#[test]
fn producer_checks_excluded_selector_caches_instead_of_trusting_them() {
    let original =
        Journal::from_records(BOOK, CommitSeq(1), vec![posting(None, 1, 100, 1)]).unwrap();
    for field in 0..5 {
        let mut journal = original.clone();
        let leaf = &mut journal.leaves[0];
        match field {
            0 => leaf.envelope.class = EntryClass::PENDING,
            1 => leaf.envelope.account_vids.clear(),
            2 => leaf.envelope.unit_ids.clear(),
            3 => leaf.envelope.effective_day = Some(101),
            _ => leaf.envelope.effective_day = None,
        }
        leaf.envelope_bytes = leaf.envelope.canonical_bytes().unwrap();
        leaf.hash = fa_notary::tree::leaf_hash(&leaf.envelope_bytes);
        let refusal = journal
            .balance_proof_complete(CASH, 1, Some(100), &[])
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_notary::code::MIGRATION_STAGED);
    }
}

#[test]
fn complete_proof_size_limits_cover_excluded_records_before_decoding() {
    assert_eq!(
        fa_notary::migration_balance::MAX_BALANCE_PROOF_BYTES,
        fa_verify::migration_balance::MAX_BALANCE_PROOF_BYTES
    );
    let mut journal = ordinary_prefix();
    // This record is outside the requested unit, but cannot evade the bound.
    journal.leaves[3].payload = vec![0; 8 * 1024 * 1024 + 1];
    let refusal = journal
        .balance_proof_complete(CASH, 1, Some(100), &[])
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-127");
    let mut leaf = journal.leaves[0].clone();
    leaf.payload = vec![0; 8 * 1024 * 1024];
    journal.leaves = vec![leaf; 8];
    // Payload bytes alone fit 64 MiB; framing and envelopes make it too large.
    let refusal = journal
        .balance_proof_complete(CASH, 1, None, &[])
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-127");
}

#[test]
fn earlier_checkpoint_visibility_is_stable_and_cannot_borrow_later_finalization() {
    let run = body(RunMode::OpeningOnly, false, "historical");
    let records = vec![
        control(&run, kind::OPEN, 1),
        posting(Some(&run), 2, 100, 1),
        control(&run, kind::FINALIZE, 3),
    ];
    let early = Journal::from_records(BOOK, CommitSeq(2), records[..2].to_vec()).unwrap();
    let later = Journal::from_records(BOOK, CommitSeq(3), records).unwrap();
    let bodies = std::slice::from_ref(&run);
    let first = early
        .balance_proof_complete(CASH, 1, None, bodies)
        .unwrap()
        .unwrap();
    assert_eq!(checked(&early, bodies, CASH, 1, None).claim.debits, 0);
    assert_eq!(checked(&later, bodies, CASH, 1, None).claim.debits, 5_000);
    assert_eq!(
        early
            .balance_proof_complete(CASH, 1, None, bodies)
            .unwrap()
            .unwrap(),
        first
    );
    assert!(matches!(
        fa_verify::verify_balance(&first, &anchor(&later)),
        Err(fa_verify::VerifyError::NotTrusted { .. })
    ));
}

#[test]
fn missing_rebound_duplicate_and_unrelated_run_bodies_still_fail_closed() {
    let run = body(RunMode::FullDetail, false, "policy");
    let journal = Journal::from_records(
        BOOK,
        CommitSeq(3),
        vec![
            control(&run, kind::OPEN, 1),
            posting(Some(&run), 2, 90, 1),
            control(&run, kind::FINALIZE, 3),
        ],
    )
    .unwrap();
    let mut rebound = run.clone();
    rebound.sole_opening_source = true;
    for bodies in [
        vec![],
        vec![rebound],
        vec![run.clone(), run.clone()],
        vec![run.clone(), body(RunMode::OpeningOnly, false, "unrelated")],
    ] {
        let refusal = journal
            .balance_proof_complete(CASH, 1, None, &bodies)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_notary::code::MIGRATION_STAGED);
    }
}
