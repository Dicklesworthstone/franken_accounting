use super::*;

const BOOK: Id128 = Id128([0x4f; 16]);
const PERIOD: &str = "FY2026-P01";

fn cell(account: u128, debits: i128, credits: i128, entries: u64) -> FunctionalCell {
    FunctionalCell {
        key: FunctionalCellKey {
            account: VId(account),
            unit_id: 1,
            period: PERIOD.into(),
            entity: Some("ALPHA".into()),
        },
        debits,
        credits,
        entry_count: entries,
    }
}

fn sample() -> Snapshot {
    let mut state = FunctionalState {
        fold: FunctionalFold {
            period: PERIOD.into(),
            base_unit: UnitId(1),
            known_at: CommitSeq(9),
            cells: vec![cell(1, 70, 10, 3), cell(2, 0, 60, 3)],
            pending: vec![cell(1, 9, 0, 1), cell(3, 0, 9, 1)],
            watermark: Some(CommitSeq(7)),
            entries: 3,
            fold_digest: [0; 32],
        },
        posted_legs_digest: [0x72; 32],
        pending_holds: BTreeMap::from([((CommitSeq(4), VId(88)), [0x34; 32])]),
    };
    refresh(&mut state).unwrap();
    Snapshot {
        book: BOOK,
        through: CommitSeq(9),
        spec_digest: [0x19; 32],
        previous: Some(CheckpointRef {
            through: CommitSeq(5),
            body_digest: [0x15; 32],
        }),
        state,
    }
}

#[test]
fn complete_functional_state_round_trips_entities_columns_and_continuation() {
    let snapshot = sample();
    let bytes = snapshot.encode().unwrap();
    assert_eq!(Snapshot::decode(&bytes, BOOK, PERIOD).unwrap(), snapshot);
    let reference = CheckpointRef {
        through: snapshot.through,
        body_digest: body_digest(&bytes),
    };
    assert_eq!(
        read_pointer(&pointer_bytes(reference).unwrap()).unwrap(),
        reference
    );
    assert_ne!(
        head_vid(BOOK, PERIOD),
        crate::maintainer::state_vid(BOOK, PERIOD)
    );
    assert_ne!(
        head_vid(BOOK, PERIOD),
        crate::checkpoint::head_vid(BOOK, PERIOD)
    );
    assert_ne!(
        checkpoint_vid(BOOK, PERIOD, reference),
        crate::checkpoint::vid(
            BOOK,
            PERIOD,
            crate::checkpoint::CheckpointRef {
                through: reference.through,
                body_digest: reference.body_digest,
            },
        )
    );
    let mut other_entity = snapshot.clone();
    other_entity.state.fold.cells[0].key.entity = Some("BETA".into());
    refresh(&mut other_entity.state).unwrap();
    assert_ne!(
        other_entity.state.fold.fold_digest,
        snapshot.state.fold.fold_digest
    );
    assert_ne!(
        body_digest(&other_entity.encode().unwrap()),
        reference.body_digest
    );
    let mut other_book_definition = snapshot.clone();
    other_book_definition.spec_digest[0] ^= 1;
    assert_ne!(
        body_digest(&other_book_definition.encode().unwrap()),
        reference.body_digest
    );
}

#[test]
fn codec_refuses_wrong_coordinates_and_resealed_invalid_continuation() {
    let snapshot = sample();
    let bytes = snapshot.encode().unwrap();
    assert!(Snapshot::decode(&bytes, Id128([0x50; 16]), PERIOD).is_err());
    assert!(Snapshot::decode(&bytes, BOOK, "FY2026-P02").is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Snapshot::decode(&trailing, BOOK, PERIOD).is_err());
    assert!(Snapshot::decode(&bytes[..bytes.len() - 1], BOOK, PERIOD).is_err());
    for alteration in 0..10 {
        let mut malformed = snapshot.clone();
        match alteration {
            0 => malformed.state.fold.cells.reverse(),
            1 => malformed.state.fold.cells[0].debits = -1,
            2 => malformed.state.fold.cells[0].entry_count = 4,
            3 => malformed.state.fold.cells[0].key.unit_id = 2,
            4 => malformed.state.fold.cells[0].key.entity = Some("E".repeat(33)),
            5 => malformed.state.fold.known_at = CommitSeq(10),
            6 => malformed.state.fold.watermark = Some(CommitSeq(10)),
            7 => malformed.state.pending_holds.clear(),
            8 => malformed.previous.as_mut().unwrap().through = CommitSeq(9),
            9 => malformed.state.fold.cells[1] = malformed.state.fold.cells[0].clone(),
            _ => unreachable!(),
        }
        refresh(&mut malformed.state).unwrap();
        assert!(
            malformed.encode().is_err(),
            "invalid state {alteration} was accepted"
        );
    }
    let mut wrong_digest = snapshot;
    wrong_digest.state.posted_legs_digest[0] ^= 1;
    assert!(wrong_digest.encode().is_err());
}

#[test]
fn functional_snapshot_bounds_precede_allocation_and_large_bodies_use_objects() {
    for count in [
        MAX_REGISTER_CHECKPOINT_CELLS,
        MAX_REGISTER_CHECKPOINT_CELLS + 1,
    ] {
        let bytes = u32::try_from(count).unwrap().to_le_bytes();
        assert!(read_cells(&mut Reader::new(&bytes), PERIOD, UnitId(1)).is_err());
    }
    assert!(Snapshot::decode(&vec![0; MAX_REGISTER_CHECKPOINT_BYTES + 1], BOOK, PERIOD).is_err());
    let mut snapshot = sample();
    snapshot.state.fold.cells = (1..=200).map(|account| cell(account, 1, 0, 1)).collect();
    snapshot.state.fold.entries = 1;
    snapshot.state.fold.pending.clear();
    snapshot.state.pending_holds.clear();
    refresh(&mut snapshot.state).unwrap();
    let bytes = snapshot.encode().unwrap();
    assert!(bytes.len() > object::CHUNK_BYTES);
    let stored = object::payload(ObjectKind::RegisterCheckpoint, &bytes).unwrap();
    assert!(stored.len() < object::CHUNK_BYTES);
    assert_eq!(Snapshot::decode(&bytes, BOOK, PERIOD).unwrap(), snapshot);
    snapshot.state.pending_holds = (0..=MAX_BATCH_ENTRIES)
        .map(|index| ((CommitSeq(4), VId(index as u128)), [1; 32]))
        .collect();
    refresh(&mut snapshot.state).unwrap();
    assert!(snapshot.encode().is_err());
}
