//! Request-local reuse against the independent single-proof paths. These
//! detached journals exercise proof semantics, not posting admission or speed.

use super::*;
use fa_journal::custody::{CustodyBody, CustodyEvent};
use fa_journal::migration::SourceChunk;
use fa_model::{
    EntryPayload, Erasable, EvidenceRef, Id128, IntakeSource, LegPayload, Oid, SealKey, Writer,
    domain_digest, migration_entry_vid,
};
use fa_money::{Amount, UnitId};
use fa_time::DateDay;

const BOOK: Id128 = Id128([0x5a; 16]);
const KEY: SealKey = SealKey([0x33; 32]);
const OFFSET: VId = VId(999);
type EntryRecord = (VId, Entry, CommitSeq);

fn payload(seq: u64, day: i32, legs: Vec<LegPayload>) -> EntryPayload {
    EntryPayload {
        schema_minor: 1,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay(day),
        document_date: None,
        description: Erasable::seal(
            &"balance observation".to_string(),
            None,
            &KEY,
            [1; 32],
            [2; 24],
        ),
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

fn posting(seq: u64, day: i32, account: VId, unit: u32, amount: i128) -> EntryRecord {
    let p = payload(
        seq,
        day,
        vec![
            LegPayload::simple(Side::Debit, account, Amount::new(UnitId(unit), amount)),
            LegPayload::simple(Side::Credit, OFFSET, Amount::new(UnitId(unit), amount)),
        ],
    );
    (
        VId(u128::from(seq)),
        p.seal(vec![], None).unwrap(),
        CommitSeq(seq),
    )
}

fn run(mode: RunMode, sole: bool) -> RunBody {
    RunBody {
        book_id: BOOK,
        run_key: format!("shared-{mode:?}-{sole}"),
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

fn control(run: &RunBody, transition: u8, seq: u64) -> EntryRecord {
    let digest = run.digest().unwrap();
    let mut p = payload(seq, 100, Vec::new());
    p.class = EntryClass::MIGRATION_CONTROL;
    p.control = Some(ControlPayload::MigrationControl {
        run_ref: run.vid(),
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

fn chunk(run: &RunBody, seq: u64, day: i32, account: VId, unit: u32) -> EntryRecord {
    let (_, entry, recorded) = posting(seq, day, account, unit, 5_000);
    let mut p = entry.proposal;
    p.class = EntryClass::MIGRATION;
    p.origin = EntryOrigin::Migration {
        run_ref: run.vid(),
        source_system: run.source_system.clone(),
        source_id: Erasable::seal(&"source".to_string(), None, &KEY, [3; 32], [4; 24]),
        source_recorded_at_ns: Some(42),
        source_entered_by: None,
        source_approved_by: None,
        batch_oid: Oid([5; 32]),
    };
    (
        migration_entry_vid(BOOK, run.vid(), &p.idempotency_key),
        p.seal(vec![], None).unwrap(),
        recorded,
    )
}

fn anchor(journal: &Journal) -> fa_verify::Checkpoint {
    fa_verify::verify_state(
        &AccumulatorState::of_journal(journal, None)
            .canonical_bytes()
            .unwrap(),
    )
    .unwrap()
    .checkpoint
}

fn same_proof(
    shared: &mut BalanceProofs<'_>,
    account: VId,
    unit: u32,
    through: Option<i32>,
    inputs: &dyn MigrationSourceInputs,
    complete: bool,
) -> Vec<u8> {
    let literal = if complete {
        shared
            .journal
            .balance_proof_complete_auto(account, unit, through, inputs)
    } else {
        shared
            .journal
            .balance_proof_auto(account, unit, through, inputs)
    }
    .unwrap()
    .unwrap();
    let actual = shared
        .prove(account, unit, through, inputs, complete)
        .unwrap()
        .unwrap();
    assert_eq!(
        actual, literal,
        "account={account:?} unit={unit} through={through:?} complete={complete}"
    );
    actual
}

#[test]
fn shared_proofs_match_literal_bytes_across_cells_cutoffs_and_evidence() {
    let mut hold = posting(2, 100, VId(10), 1, 7_000);
    hold.1.proposal.class = EntryClass::PENDING;
    hold.1.proposal.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    hold.1 = hold.1.proposal.seal(vec![], None).unwrap();
    let mut records: Vec<_> = [
        posting(1, 100, VId(10), 1, 5_000),
        hold,
        posting(3, 101, VId(10), 1, 8_000),
        posting(4, 100, VId(10), 2, 9_000),
        posting(5, 100, VId(20), 1, 3_000),
    ]
    .into_iter()
    .map(|(vid, entry, seq)| (vid, crate::journal::Record::Entry(Box::new(entry)), seq))
    .collect();
    records.push((
        VId(600),
        crate::journal::Record::Custody(CustodyEvent {
            book_id: BOOK,
            document_oid: Oid([3; 32]),
            index: 0,
            prev_digest: [0; 32],
            body: CustodyBody::Receipt {
                source: IntakeSource::Email {
                    message_id: "retained-source".into(),
                },
                received_by: VId(7),
                digest_at_receipt: [4; 32],
                run_ref: None,
            },
        }),
        CommitSeq(6),
    ));
    let journal =
        Journal::from_records_with_evidence(BOOK, CommitSeq(6), Some(CommitSeq(1)), records)
            .unwrap();
    let mut shared = BalanceProofs::new(&journal);
    let empty = BTreeMap::new();
    for complete in [false, true, false, true] {
        for account in [VId(10), VId(20), OFFSET, VId(404)] {
            for unit in [1, 2] {
                for through in [Some(99), Some(100), None] {
                    let bytes = same_proof(&mut shared, account, unit, through, &empty, complete);
                    let verified = fa_verify::verify_balance(&bytes, &anchor(&journal)).unwrap();
                    if account == VId(10) && unit == 1 && through == Some(100) {
                        assert_eq!((verified.claim.debits, verified.claim.credits), (5_000, 0));
                    }
                }
            }
        }
    }
    assert_eq!(shared.indexed_leaves, journal.leaves.len());
    assert_eq!(shared.authenticated_entries, 5);
    assert_eq!(shared.authenticated_evidence, 1);
}

#[test]
fn shared_migration_proofs_keep_visibility_and_historical_frontiers() {
    for (mode, sole) in [
        (RunMode::OpeningOnly, false),
        (RunMode::PeriodBalances, false),
        (RunMode::FullDetail, false),
        (RunMode::FullDetail, true),
    ] {
        for terminal in [None, Some(kind::FINALIZE), Some(kind::ABANDON)] {
            let body = run(mode, sole);
            let mut records = vec![
                control(&body, kind::OPEN, 1),
                chunk(&body, 2, 90, VId(10), 1),
                chunk(&body, 3, 100, VId(20), 2),
            ];
            if let Some(transition) = terminal {
                records.push(control(&body, transition, 4));
            }
            let inputs = BTreeMap::from([(body.vid(), body.clone())]);
            let historical =
                Journal::from_records(BOOK, CommitSeq(3), records[..3].to_vec()).unwrap();
            let journal = Journal::from_records(BOOK, CommitSeq(4), records).unwrap();
            let mut shared = BalanceProofs::new(&journal);
            for complete in [false, true] {
                for (account, unit) in [(VId(10), 1), (VId(20), 2), (VId(30), 1)] {
                    for through in [Some(89), Some(90), Some(100), None] {
                        let bytes =
                            same_proof(&mut shared, account, unit, through, &inputs, complete);
                        let result = fa_verify::verify_balance(&bytes, &anchor(&journal)).unwrap();
                        if account == VId(10) && through == Some(90) {
                            let visible = terminal == Some(kind::FINALIZE)
                                && (mode != RunMode::FullDetail || sole);
                            assert_eq!(result.claim.debits, if visible { 5_000 } else { 0 });
                        }
                    }
                }
            }
            let mut earlier = BalanceProofs::new(&historical);
            let bytes = same_proof(&mut earlier, VId(20), 2, None, &inputs, true);
            assert_eq!(
                fa_verify::verify_balance(&bytes, &anchor(&historical))
                    .unwrap()
                    .claim
                    .debits,
                0
            );
            assert_eq!(shared.authenticated_entries, journal.leaves.len());
            assert_eq!(earlier.authenticated_entries, historical.leaves.len());
        }
    }
}

#[test]
fn shared_source_bound_proofs_preserve_the_complete_v4_upgrade() {
    let body = run(RunMode::FullDetail, false);
    let chunks = vec![
        chunk(&body, 3, 100, VId(10), 1),
        chunk(&body, 4, 101, VId(20), 2),
    ];
    let source_commit = [0x71; 32];
    let package_commit = [0x72; 32];
    let source = SourceManifest {
        book_id: BOOK,
        run_ref: body.vid(),
        run_body_digest: body.digest().unwrap(),
        source_oid: Oid(domain_digest(
            b"fa:oid:document:v1",
            &[&BOOK.0, &source_commit],
        )),
        source_commit,
        package_oid: Oid(domain_digest(
            b"fa:oid:document:v1",
            &[&BOOK.0, &package_commit],
        )),
        package_commit,
        source_rows: 4,
        chunks: chunks
            .iter()
            .map(|(vid, entry, _)| SourceChunk {
                entry_vid: *vid,
                proposal_digest: entry.proposal_digest,
            })
            .collect(),
    };
    let mut binding = control(&body, kind::BIND_SOURCE, 2);
    let mut p = binding.1.proposal;
    p.control = Some(ControlPayload::MigrationControl {
        run_ref: body.vid(),
        kind: kind::BIND_SOURCE,
        tie_out_digest: source.digest().unwrap(),
    });
    p.evidence = vec![
        EvidenceRef {
            document_oid: source.source_oid,
            doc_commit: source.source_commit,
            role: 1,
        },
        EvidenceRef {
            document_oid: source.package_oid,
            doc_commit: source.package_commit,
            role: 1,
        },
    ];
    p.evidence.sort_unstable();
    binding.1 = p.seal(vec![], None).unwrap();
    let mut list = Writer::new();
    list.list(&chunks, |w, (vid, entry, _)| {
        w.u128(vid.0).fixed(&entry.proposal_digest);
    });
    let tie_out = domain_digest(
        b"fa:migration-tie-out:v2",
        &[
            &body.digest().unwrap(),
            &source.digest().unwrap(),
            &list.finish().unwrap(),
        ],
    );
    let mut terminal = control(&body, kind::FINALIZE, 5);
    terminal.1.proposal.control = Some(ControlPayload::MigrationControl {
        run_ref: body.vid(),
        kind: kind::FINALIZE,
        tie_out_digest: tie_out,
    });
    terminal.1 = terminal.1.proposal.seal(vec![], None).unwrap();
    let mut records = vec![control(&body, kind::OPEN, 1), binding];
    records.extend(chunks);
    records.push(terminal);
    let journal = Journal::from_records(BOOK, CommitSeq(5), records).unwrap();
    let inputs = MigrationInputs {
        bodies: BTreeMap::from([(body.vid(), body)]),
        manifests: BTreeMap::from([(source.run_ref, source)]),
    };
    let mut shared = BalanceProofs::new(&journal);
    for complete in [false, true, false] {
        for (account, unit, through) in [(VId(10), 1, Some(100)), (VId(20), 2, None)] {
            let bytes = same_proof(&mut shared, account, unit, through, &inputs, complete);
            assert_eq!(
                fa_model::Reader::new(&bytes).bytes(128, "format").unwrap(),
                BALANCE_FORMAT_V4
            );
            assert_eq!(
                fa_verify::verify_balance(&bytes, &anchor(&journal))
                    .unwrap()
                    .claim
                    .debits,
                5_000
            );
        }
    }
    assert_eq!(shared.authenticated_entries, journal.leaves.len());

    // Cached entry authentication binds neither caller-supplied migration
    // bodies nor manifests. Every later proof validates its own inputs.
    let mut missing_manifest = inputs.clone();
    missing_manifest.manifests.clear();
    let mut rebound_body = inputs.clone();
    rebound_body
        .bodies
        .values_mut()
        .next()
        .unwrap()
        .sole_opening_source = true;
    for changed in [MigrationInputs::default(), missing_manifest, rebound_body] {
        let expected = journal
            .balance_proof_complete_auto(VId(10), 1, Some(100), &changed)
            .unwrap()
            .unwrap_err();
        let actual = shared
            .prove(VId(10), 1, Some(100), &changed, true)
            .unwrap()
            .unwrap_err();
        assert_eq!(actual, expected);
    }
}

#[test]
fn cached_authentication_never_caches_selection_admission() {
    let mut invalid = posting(1, 100, VId(10), 1, 5_000);
    invalid.1.proposal.origin = EntryOrigin::Control {
        control_kind: ControlKind::MIGRATION_RUN,
        spec_body_digest: [9; 32],
    };
    invalid.1 = invalid.1.proposal.seal(vec![], None).unwrap();
    let journal = Journal::from_records(
        BOOK,
        CommitSeq(2),
        vec![invalid, posting(2, 100, VId(20), 1, 2_000)],
    )
    .unwrap();
    let empty = BTreeMap::new();
    let mut shared = BalanceProofs::new(&journal);
    // The malformed posting is authenticated but not selected by this cell.
    same_proof(&mut shared, VId(20), 1, None, &empty, true);
    assert_eq!(shared.authenticated_entries, 2);
    for _ in 0..2 {
        let expected = journal
            .balance_proof_complete_auto(VId(10), 1, None, &empty)
            .unwrap()
            .unwrap_err();
        let actual = shared
            .prove(VId(10), 1, None, &empty, true)
            .unwrap()
            .unwrap_err();
        assert_eq!(actual, expected);
        assert!(actual.message.contains("control origin"));
    }
    // Eagerly validating the whole prefix would incorrectly let a later
    // undecodable payload replace the earlier selected-origin refusal.
    let mut corrupt = journal.clone();
    corrupt.leaves[1].payload = vec![0];
    let expected = corrupt
        .balance_proof_complete_auto(VId(10), 1, None, &empty)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        BalanceProofs::new(&corrupt)
            .prove(VId(10), 1, None, &empty, true)
            .unwrap()
            .unwrap_err(),
        expected
    );
}

#[test]
fn cached_selection_keeps_payload_failures_and_size_refusal_order() {
    let original = Journal::from_records(
        BOOK,
        CommitSeq(2),
        vec![
            posting(1, 100, VId(10), 1, 5),
            posting(2, 100, VId(20), 2, 7),
        ],
    )
    .unwrap();
    let empty = BTreeMap::new();
    for field in 0..7 {
        let mut journal = original.clone();
        let leaf = &mut journal.leaves[1];
        match field {
            0 => leaf.envelope.class = EntryClass::PENDING,
            1 => leaf.envelope.account_vids.clear(),
            2 => leaf.envelope.unit_ids.clear(),
            3 => leaf.envelope.effective_day = None,
            4 => leaf.proposal_len += 1,
            5 => leaf.payload = vec![0],
            _ => leaf.payload = vec![0; 8 * 1024 * 1024 + 1],
        }
        leaf.envelope_bytes = leaf.envelope.canonical_bytes().unwrap();
        let mut shared = BalanceProofs::new(&journal);
        // A partial proof has no obligation to decode an unrelated payload.
        same_proof(&mut shared, VId(10), 1, Some(100), &empty, false);
        let expected = journal.balance_proof_complete_auto(VId(10), 1, Some(100), &empty);
        let actual = shared.prove(VId(10), 1, Some(100), &empty, true);
        assert_eq!(
            format!("{actual:?}"),
            format!("{expected:?}"),
            "mutation {field}"
        );
        assert!(!matches!(actual, Ok(Ok(_))));
    }
}

#[test]
fn cached_legacy_fold_preserves_checked_gross_overflow() {
    let journal = Journal::from_records(
        BOOK,
        CommitSeq(2),
        vec![
            posting(1, 100, VId(10), 1, i128::MAX),
            posting(2, 100, VId(10), 1, 1),
        ],
    )
    .unwrap();
    let empty = BTreeMap::new();
    let mut shared = BalanceProofs::new(&journal);
    // Warm only authentication under an empty cell; no amount is selected.
    same_proof(&mut shared, VId(404), 1, None, &empty, true);
    let expected = journal
        .balance_proof_auto(VId(10), 1, None, &empty)
        .unwrap_err();
    let actual = shared.prove(VId(10), 1, None, &empty, false).unwrap_err();
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    assert!(format!("{actual:?}").contains("overflowed i128"));
}

#[test]
fn shared_selection_authenticates_once_and_uses_the_account_index() {
    const COUNT: u64 = 512;
    const CELLS: u64 = 32;
    let records = (1..=COUNT)
        .map(|seq| posting(seq, 100, VId(10 + u128::from((seq - 1) % CELLS)), 1, 5))
        .collect();
    let journal = Journal::from_records(BOOK, CommitSeq(COUNT), records).unwrap();
    let mut shared = BalanceProofs::new(&journal);
    assert!(
        shared.entries.is_empty(),
        "a no-balance bundle allocates no population cache"
    );
    for cell in 0..CELLS {
        let account = VId(10 + u128::from(cell));
        let (expected, needed) = select(&journal, account, 1, Some(100), true)
            .unwrap()
            .unwrap();
        let (actual, actual_needed) = shared.select(account, 1, Some(100), true).unwrap().unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual_needed, needed);
    }
    assert_eq!(shared.authenticated_entries, COUNT as usize);
    assert_eq!(shared.indexed_leaves, COUNT as usize);
    assert_eq!(
        shared.selection_visits,
        (COUNT + (CELLS - 1) * (COUNT / CELLS)) as usize
    );
    // These are selector/authentication counts, not total bundle work:
    // transport still measures and emits the required prefix for every proof.
    assert!(shared.selection_visits < (COUNT * CELLS) as usize);
}
