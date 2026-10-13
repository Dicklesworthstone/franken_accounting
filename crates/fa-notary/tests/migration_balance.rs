//! Model-encoded producer/verifier differential coverage for v2 balances.
//! These detached journals exercise the real model codec and independent
//! verifier, not kernel admission, authorization, or trial-balance tie-out.

use fa_journal::migration::{RunBody, RunMode, kind};
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload,
    Erasable, Id128, LegPayload, Oid, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::{AccumulatorState, Journal, code};
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
        description: Erasable::seal(&"migration proof".to_string(), None, &KEY, [1; 32], [2; 24]),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: seq.to_le_bytes().to_vec(),
        origin: EntryOrigin::Intent { intent_oid: Oid([4; 32]), intent_kind: 1 },
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
    let mut p = payload(EntryClass::MIGRATION_CONTROL, Vec::new(), seq, body.opening_date.0);
    p.control = Some(ControlPayload::MigrationControl {
        run_ref: body.vid(),
        kind: transition,
        tie_out_digest: if transition == kind::OPEN { digest } else { [9; 32] },
    });
    p.origin = EntryOrigin::Control {
        control_kind: ControlKind::MIGRATION_RUN,
        spec_body_digest: digest,
    };
    (VId(u128::from(seq)), p.seal(Vec::new(), None).unwrap(), CommitSeq(seq))
}

fn posting(body: Option<&RunBody>, seq: u64, day: i32, unit: u32) -> (VId, Entry, CommitSeq) {
    let class = if body.is_some() { EntryClass::MIGRATION } else { EntryClass::ORIGINAL };
    let mut p = payload(class, vec![
        LegPayload::simple(Side::Debit, CASH, Amount::new(UnitId(unit), 5_000)),
        LegPayload::simple(Side::Credit, OFFSET, Amount::new(UnitId(unit), 5_000)),
    ], seq, day);
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
    (VId(u128::from(seq)), p.seal(Vec::new(), None).unwrap(), CommitSeq(seq))
}

fn history(body: &RunBody, terminal: Option<u8>, day: i32) -> Journal {
    let mut records = vec![control(body, kind::OPEN, 1), posting(Some(body), 2, day, 1)];
    if let Some(terminal) = terminal {
        records.push(control(body, terminal, 3));
    }
    Journal::from_records(BOOK, CommitSeq(3), records).unwrap()
}

fn anchor(journal: &Journal) -> fa_verify::Checkpoint {
    let state = AccumulatorState::of_journal(journal, None);
    // The test supplies this independently known checkpoint. Merely parsing
    // a state in an untrusted package would NOT establish checkpoint trust.
    fa_verify::verify_state(&state.canonical_bytes().unwrap()).unwrap().checkpoint
}

fn checked(journal: &Journal, bodies: &[RunBody], account: VId, unit: u32, day: Option<i32>) -> fa_verify::Balance {
    let proof = journal.balance_proof_with_migrations(account, unit, day, bodies)
        .unwrap().unwrap();
    assert!(proof.windows(b"fa:acc-balance-proof:v2".len())
        .any(|bytes| bytes == b"fa:acc-balance-proof:v2"));
    fa_verify::verify_balance(&proof, &anchor(journal)).unwrap()
}

#[test]
fn model_encoded_open_abandoned_and_finalized_runs_agree_with_the_independent_verifier() {
    let body = body(RunMode::OpeningOnly, false, "run");
    for (terminal, expected) in [(None, 0), (Some(kind::ABANDON), 0), (Some(kind::FINALIZE), 5_000)] {
        let journal = history(&body, terminal, 100);
        let cash = checked(&journal, std::slice::from_ref(&body), CASH, 1, None);
        let offset = checked(&journal, std::slice::from_ref(&body), OFFSET, 1, None);
        assert_eq!((cash.claim.debits, cash.claim.credits), (expected, 0));
        assert_eq!((offset.claim.debits, offset.claim.credits), (0, expected));
        assert_eq!(cash.contributing, if expected == 0 { vec![] } else { vec![1] });
    }
}

#[test]
fn each_mode_and_effective_cutoff_uses_the_committed_policy() {
    for (mode, sole, day, expected) in [
        (RunMode::OpeningOnly, false, 100, 5_000),
        (RunMode::PeriodBalances, false, 90, 5_000),
        (RunMode::FullDetail, false, 90, 0),
        (RunMode::FullDetail, true, 90, 5_000),
        (RunMode::FullDetail, false, 100, 5_000),
    ] {
        let body = body(mode, sole, "mode");
        let journal = history(&body, Some(kind::FINALIZE), day);
        let result = checked(&journal, std::slice::from_ref(&body), CASH, 1, Some(day));
        assert_eq!(result.claim.debits, expected);
        let earlier = checked(&journal, &[], CASH, 1, Some(day - 1));
        assert_eq!(earlier.claim.debits, 0);
        assert!(earlier.contributing.is_empty());
        assert_eq!(checked(&journal, &[], CASH, 2, None).claim.debits, 0);
        assert_eq!(checked(&journal, &[], VId(999), 1, None).claim.debits, 0);
    }
}

#[test]
fn recorded_prefix_before_finalization_stays_invisible_after_a_later_prefix_activates_it() {
    let body = body(RunMode::OpeningOnly, false, "known-at");
    let records = vec![
        control(&body, kind::OPEN, 1),
        posting(Some(&body), 2, 100, 1),
        control(&body, kind::FINALIZE, 3),
    ];
    let early = Journal::from_records(BOOK, CommitSeq(2), records[..2].to_vec()).unwrap();
    let later = Journal::from_records(BOOK, CommitSeq(3), records).unwrap();
    let witnesses = std::slice::from_ref(&body);
    let first = early.balance_proof_with_migrations(CASH, 1, None, witnesses).unwrap().unwrap();
    assert_eq!(fa_verify::verify_balance(&first, &anchor(&early)).unwrap().claim.debits, 0);
    assert_eq!(checked(&later, witnesses, CASH, 1, None).claim.debits, 5_000);
    assert_eq!(early.balance_proof_with_migrations(CASH, 1, None, witnesses).unwrap().unwrap(), first);
    assert!(matches!(fa_verify::verify_balance(&first, &anchor(&later)),
        Err(fa_verify::VerifyError::NotTrusted { .. })));
}

#[test]
fn multiple_run_witnesses_are_canonical_and_unrelated_unit_bodies_are_not_disclosed() {
    let a = body(RunMode::OpeningOnly, false, "a");
    let b = body(RunMode::OpeningOnly, false, "b");
    let c = body(RunMode::OpeningOnly, false, "unrelated");
    let journal = Journal::from_records(BOOK, CommitSeq(10), vec![
        control(&a, kind::OPEN, 1), control(&b, kind::OPEN, 2), control(&c, kind::OPEN, 3),
        posting(Some(&a), 4, 100, 1), posting(Some(&b), 5, 100, 1),
        posting(Some(&c), 6, 100, 2),
        control(&a, kind::FINALIZE, 7), control(&b, kind::ABANDON, 8),
        control(&c, kind::FINALIZE, 9), posting(None, 10, 100, 1),
    ]).unwrap();
    let first = journal.balance_proof_with_migrations(CASH, 1, None, &[a.clone(), b.clone()])
        .unwrap().unwrap();
    let reversed = journal.balance_proof_with_migrations(CASH, 1, None, &[b.clone(), a.clone()])
        .unwrap().unwrap();
    assert_eq!(first, reversed);
    let report = fa_verify::verify_balance(&first, &anchor(&journal)).unwrap();
    assert_eq!(report.claim.debits, 10_000);
    assert_eq!(report.contributing, vec![3, 9]);
    let private_body = c.canonical_bytes().unwrap();
    assert!(!first.windows(private_body.len()).any(|window| window == private_body));
    assert_eq!(checked(&journal, std::slice::from_ref(&c), CASH, 2, None).claim.debits, 5_000);
    assert!(journal.balance_proof_with_migrations(CASH, 1, None, &[a, b, c]).unwrap().is_err());
}

#[test]
fn body_substitution_missing_bodies_and_duplicate_bodies_are_refused() {
    let body = body(RunMode::FullDetail, false, "policy");
    let journal = history(&body, Some(kind::FINALIZE), 90);
    let mut changed = body.clone();
    changed.sole_opening_source = true;
    let mut foreign = body.clone();
    foreign.book_id = Id128([99; 16]);
    for bodies in [vec![], vec![changed], vec![foreign], vec![body.clone(), body]] {
        let refusal = journal.balance_proof_with_migrations(CASH, 1, None, &bodies)
            .unwrap().unwrap_err();
        assert_eq!(refusal.code, code::MIGRATION_STAGED);
    }
}

#[test]
fn inconsistent_lifecycles_are_rejected_instead_of_selectively_counted() {
    let body = body(RunMode::OpeningOnly, false, "invalid");
    for records in [
        vec![control(&body, kind::FINALIZE, 1)],
        vec![control(&body, kind::OPEN, 1), control(&body, kind::OPEN, 2)],
        vec![posting(Some(&body), 1, 100, 1), control(&body, kind::OPEN, 2)],
        vec![control(&body, kind::OPEN, 1), control(&body, kind::FINALIZE, 2), posting(Some(&body), 3, 100, 1)],
        vec![control(&body, kind::OPEN, 1), control(&body, kind::ABANDON, 2), control(&body, kind::FINALIZE, 3)],
    ] {
        let has_chunk = records.iter().any(|(_, e, _)| e.proposal.class == EntryClass::MIGRATION);
        let journal = Journal::from_records(BOOK, CommitSeq(3), records).unwrap();
        let bodies = if has_chunk { std::slice::from_ref(&body) } else { &[] };
        assert!(journal.balance_proof_with_migrations(CASH, 1, None, bodies).unwrap().is_err());
    }
}

#[test]
fn empty_and_nonmigration_v2_proofs_work_without_changing_v1_bytes() {
    for records in [vec![], vec![posting(None, 1, 100, 1)]] {
        let expected = if records.is_empty() { 0 } else { 5_000 };
        let journal = Journal::from_records(BOOK, CommitSeq(1), records).unwrap();
        let before = journal.balance_proof(CASH, 1, None).unwrap().unwrap();
        assert_eq!(checked(&journal, &[], CASH, 1, None).claim.debits, expected);
        assert_eq!(journal.balance_proof(CASH, 1, None).unwrap().unwrap(), before);
        assert_eq!(fa_verify::verify_balance(&before, &anchor(&journal)).unwrap().claim.debits, expected);
    }
}
