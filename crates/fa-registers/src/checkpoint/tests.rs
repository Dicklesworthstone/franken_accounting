use super::*;

const BOOK: Id128 = Id128([0x6a; 16]);
const PERIOD: &str = "FY2026-P03";

fn cell(account: u128, debits: i128, credits: i128, entries: u64) -> Cell {
    Cell {
        key: CellKey {
            account: VId(account),
            unit_id: 1,
            period: PERIOD.into(),
        },
        debits,
        credits,
        entry_count: entries,
    }
}

fn refresh(fold: &mut Fold) {
    fold.fold_digest = crate::digest_of(
        &fold.period,
        &fold.cells,
        &fold.pending,
        fold.watermark,
        fold.posted_legs_digest,
        &fold.pending_holds,
    )
    .unwrap();
}

fn sample() -> Fold {
    let mut fold = Fold {
        period: PERIOD.into(),
        cells: vec![cell(1, 70, 10, 3), cell(2, 0, 60, 3)],
        pending: vec![cell(1, 9, 0, 1), cell(3, 0, 9, 1)],
        watermark: Some(CommitSeq(7)),
        entries: 3,
        fold_digest: [0; 32],
        posted_legs_digest: [0x72; 32],
        pending_holds: BTreeMap::from([((CommitSeq(4), VId(88)), [0x34; 32])]),
    };
    refresh(&mut fold);
    fold
}

fn reseal(checkpoint: &mut Checkpoint) {
    refresh(&mut checkpoint.fold);
    checkpoint.cells_root = domain_digest(
        b"fa:register-checkpoint-cells:v1",
        &[
            &checkpoint.definition_oid,
            &columns(&checkpoint.fold).unwrap(),
        ],
    );
    checkpoint.body_digest = domain_digest(
        b"fa:register-checkpoint-body:v1",
        &[&checkpoint.body_bytes().unwrap()],
    );
}

#[test]
fn complete_checkpoint_round_trip_preserves_both_columns_and_continuation_state() {
    let previous = CheckpointRef {
        through: CommitSeq(5),
        body_digest: [0x15; 32],
    };
    let checkpoint = Checkpoint::build(BOOK, CommitSeq(9), &sample(), Some(previous)).unwrap();
    assert_eq!(checkpoint.cell_count, 3, "an overlapping key is one cell");
    assert_eq!(checkpoint.fold.pending_holds.len(), 1);
    assert_eq!(checkpoint.fold.entries, 3);
    assert_eq!(
        checkpoint.definition_oid,
        definition_oid(BOOK, PERIOD).unwrap()
    );
    assert_eq!(
        Checkpoint::decode(&checkpoint.encode().unwrap(), BOOK, PERIOD).unwrap(),
        checkpoint
    );
    assert_eq!(
        read_pointer(&pointer_bytes(checkpoint.reference()).unwrap()).unwrap(),
        checkpoint.reference()
    );
    assert_ne!(
        head_vid(BOOK, PERIOD),
        crate::maintainer::state_vid(BOOK, PERIOD)
    );
    assert_ne!(
        head_vid(BOOK, PERIOD),
        vid(BOOK, PERIOD, checkpoint.reference())
    );

    let mut swapped = sample();
    std::mem::swap(&mut swapped.cells, &mut swapped.pending);
    swapped.entries = 3;
    // Compare the exact tagged columns directly: posted and pending may never
    // hash as one unordered bag even when their numeric totals coincide.
    assert_ne!(
        columns(&swapped).unwrap(),
        columns(&checkpoint.fold).unwrap()
    );
}

#[test]
fn checkpoint_decoder_refuses_foreign_coordinates_and_resealed_malformed_state() {
    let checkpoint = Checkpoint::build(BOOK, CommitSeq(9), &sample(), None).unwrap();
    let encoded = checkpoint.encode().unwrap();
    assert!(Checkpoint::decode(&encoded, Id128([0x6b; 16]), PERIOD).is_err());
    assert!(Checkpoint::decode(&encoded, BOOK, "FY2026-P04").is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Checkpoint::decode(&trailing, BOOK, PERIOD).is_err());
    assert!(Checkpoint::decode(&encoded[..encoded.len() - 1], BOOK, PERIOD).is_err());

    for alteration in 0..7 {
        let mut malformed = checkpoint.clone();
        match alteration {
            0 => malformed.fold.cells.reverse(),
            1 => malformed.fold.cells[0].debits = -1,
            2 => malformed.fold.cells[0].entry_count = 4,
            3 => malformed.fold.watermark = Some(CommitSeq(10)),
            4 => {
                malformed
                    .fold
                    .pending_holds
                    .insert((CommitSeq(10), VId(89)), [9; 32]);
            }
            5 => malformed.cell_count = 4,
            6 => malformed.previous = Some(malformed.reference()),
            _ => unreachable!(),
        }
        // Recompute every unkeyed commitment; ordering, coordinate and shape
        // laws must still reject malformed state rather than trust its hash.
        reseal(&mut malformed);
        assert!(
            Checkpoint::decode(&malformed.encode().unwrap(), BOOK, PERIOD).is_err(),
            "resealed malformed state {alteration} was admitted"
        );
    }
    let mut duplicate = checkpoint.clone();
    duplicate.fold.cells[1] = duplicate.fold.cells[0].clone();
    reseal(&mut duplicate);
    assert!(Checkpoint::decode(&duplicate.encode().unwrap(), BOOK, PERIOD).is_err());
}

#[test]
fn checkpoint_commitments_bind_counts_holds_and_native_definition() {
    let checkpoint = Checkpoint::build(BOOK, CommitSeq(9), &sample(), None).unwrap();
    for alteration in 0..4 {
        let mut changed = checkpoint.clone();
        match alteration {
            0 => changed.cells_root[0] ^= 1,
            1 => changed.body_digest[0] ^= 1,
            2 => changed.definition_oid[0] ^= 1,
            3 => changed.fold.pending_holds.values_mut().next().unwrap()[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(Checkpoint::decode(&changed.encode().unwrap(), BOOK, PERIOD).is_err());
    }
    let mut wrong_count = checkpoint.clone();
    wrong_count.fold.entries = 4;
    reseal(&mut wrong_count);
    assert_ne!(wrong_count.body_digest, checkpoint.body_digest);
    // Integrity is deliberately not proof of the journal's value: a coherent
    // invented count still needs the independently refolded verification test.
    assert!(Checkpoint::decode(&wrong_count.encode().unwrap(), BOOK, PERIOD).is_ok());
}

#[test]
fn checkpoint_codec_bounds_counts_before_allocation_and_chunks_large_bodies() {
    for count in [
        u32::try_from(MAX_REGISTER_CHECKPOINT_CELLS).unwrap(),
        u32::try_from(MAX_REGISTER_CHECKPOINT_CELLS).unwrap() + 1,
    ] {
        let bytes = count.to_le_bytes();
        assert!(read_cells(&mut Reader::new(&bytes), PERIOD).is_err());
    }
    let too_large = vec![0; MAX_REGISTER_CHECKPOINT_BYTES + 1];
    assert!(Checkpoint::decode(&too_large, BOOK, PERIOD).is_err());

    let mut fold = sample();
    fold.cells = (1..=100).map(|account| cell(account, 7, 3, 1)).collect();
    fold.pending.clear();
    fold.pending_holds.clear();
    fold.entries = 1;
    refresh(&mut fold);
    let checkpoint = Checkpoint::build(BOOK, CommitSeq(9), &fold, None).unwrap();
    let bytes = checkpoint.encode().unwrap();
    assert!(bytes.len() > object::CHUNK_BYTES);
    let stored = object::payload(ObjectKind::RegisterCheckpoint, &bytes).unwrap();
    assert!(stored.len() < object::CHUNK_BYTES);
    assert_ne!(stored, bytes);
    assert_eq!(Checkpoint::decode(&bytes, BOOK, PERIOD).unwrap().fold, fold);

    fold.pending = fold.cells.clone();
    fold.pending_holds = (0..=MAX_BATCH_ENTRIES)
        .map(|index| ((CommitSeq(4), VId(index as u128)), [1; 32]))
        .collect();
    refresh(&mut fold);
    assert!(Checkpoint::build(BOOK, CommitSeq(9), &fold, None).is_err());
}

#[test]
fn empty_and_fully_released_checkpoints_keep_their_distinct_frontiers() {
    let mut fold = Fold {
        period: PERIOD.into(),
        cells: Vec::new(),
        pending: Vec::new(),
        watermark: None,
        entries: 0,
        fold_digest: [0; 32],
        posted_legs_digest: [0; 32],
        pending_holds: BTreeMap::new(),
    };
    refresh(&mut fold);
    let empty = Checkpoint::build(BOOK, CommitSeq(2), &fold, None).unwrap();
    assert_eq!(empty.cell_count, 0);
    fold.watermark = Some(CommitSeq(7));
    refresh(&mut fold);
    let released = Checkpoint::build(BOOK, CommitSeq(9), &fold, Some(empty.reference())).unwrap();
    assert_eq!(released.cell_count, 0);
    assert_ne!(released.fold.fold_digest, empty.fold.fold_digest);
    assert_eq!(
        Checkpoint::decode(&released.encode().unwrap(), BOOK, PERIOD).unwrap(),
        released
    );
}
