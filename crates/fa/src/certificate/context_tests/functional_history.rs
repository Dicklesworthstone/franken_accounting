//! Ordinary public reads carry native integrity without trusting report caches.

use super::*;
use fa_journal::entry_history::EntryHistoryWork;

fn read(
    h: &mut Harness,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> crate::Outcome<FunctionalTrialBalance> {
    let cx = h.cx();
    h.runtime.block_on(
        h.book
            .functional_trial_balance(&cx, capability, activity(), known_at),
    )
}

fn allowed(h: &mut Harness, known_at: Option<CommitSeq>) -> FunctionalTrialBalance {
    read(h, &cap(&["read"]), known_at).unwrap().unwrap()
}

fn assert_warm(work: EntryHistoryWork) {
    assert!(!work.rebuilt, "{work:?}");
    assert_eq!(work.snapshot_scans, 0, "{work:?}");
    assert_eq!(work.snapshot_rows, 0, "{work:?}");
    assert_eq!(work.delta_rows, 0, "{work:?}");
    assert_eq!(work.entries_decoded, 0, "{work:?}");
}

#[test]
fn public_functional_reads_authenticate_only_the_new_entry_history_after_warming() {
    let (mut h, _) = fixture();
    advance(&mut h);
    let first_at = h.head();
    let entry_count = h
        .book
        .db
        .vertices_at(first_at)
        .unwrap()
        .iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .count();
    let first = allowed(&mut h, None);
    assert_eq!(first.total_debits().unwrap(), 25_050);
    let cold = h.book.functional_history_read_work();
    assert!(cold.rebuilt && cold.snapshot_scans > 0, "{cold:?}");
    assert_eq!(cold.entries_decoded, entry_count, "{cold:?}");

    assert_eq!(allowed(&mut h, None), first);
    assert_warm(h.book.functional_history_read_work());
    let independent = certify(&mut h, activity());
    assert_eq!(
        first.canonical_bytes().unwrap(),
        independent.certificate.output
    );
    assert_warm(h.book.functional_history_read_work());
    assert_eq!(h.head(), first_at, "reads and certification do not publish");

    let extra = proposal(&h, b"functional-history-tail", 700);
    post(&mut h, extra);
    let tail_at = h.head();
    let tail = allowed(&mut h, None);
    assert_eq!(tail.total_debits().unwrap(), 25_750);
    let work = h.book.functional_history_read_work();
    assert!(!work.rebuilt && work.delta_rows > 0, "{work:?}");
    assert_eq!(
        (work.snapshot_scans, work.entries_decoded),
        (0, 1),
        "{work:?}"
    );
    assert_eq!(
        tail.canonical_bytes().unwrap(),
        certify(&mut h, activity()).certificate.output,
    );
    assert_eq!(h.book.functional_history_read_work(), work);
    assert_eq!(h.head(), tail_at);

    // Older selections must not evict the newer verified prefix.
    assert_eq!(allowed(&mut h, Some(first_at)), first);
    assert!(h.book.functional_history_read_work().rebuilt);
    assert_eq!(allowed(&mut h, None), tail);
    assert_warm(h.book.functional_history_read_work());

    let advanced = advance(&mut h);
    assert!(advanced.wrote);
    let maintained = allowed(&mut h, None);
    let work = h.book.functional_history_read_work();
    assert!(!work.rebuilt && work.delta_rows > 0, "{work:?}");
    assert_eq!(
        (work.snapshot_scans, work.entries_decoded),
        (0, 0),
        "{work:?}"
    );
    assert_eq!(
        maintained.total_debits().unwrap(),
        tail.total_debits().unwrap()
    );
    assert_eq!(
        maintained.canonical_bytes().unwrap(),
        certify(&mut h, activity()).certificate.output,
    );
}

#[test]
fn reopened_functional_reads_reauthenticate_only_after_current_whole_book_admission() {
    for compact in [false, true] {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let directory = Path::new("functional-history-read-book");
        let book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                directory,
                BookKeys::for_development(SEED),
                spec(),
                Entropy::deterministic(u64::from(SEED)),
            ))
            .unwrap();
        let mut h = Harness {
            runtime,
            root,
            book,
        };
        h.populate();
        advance(&mut h);
        let expected = allowed(&mut h, None);
        if compact {
            h.runtime.block_on(h.book.compact_storage(&cx)).unwrap();
        }
        let Harness {
            runtime,
            root,
            book,
        } = h;
        drop(book);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs,
                directory,
                BookKeys::for_development(SEED),
                Entropy::deterministic(u64::from(SEED) + 1),
            ))
            .unwrap();
        let mut h = Harness {
            runtime,
            root,
            book,
        };
        let at = h.head();
        assert_eq!(
            h.book.functional_history_read_work(),
            EntryHistoryWork::default()
        );
        assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
        for capability in [
            cap(&["verify"]),
            cap(&["read"]).for_books(&[Id128([0xf1; 16])]).unwrap(),
            cap(&["read"]).for_accounts(&["1000"]).unwrap(),
            cap(&["read"]).known_at_most(CommitSeq(at.0 - 1)),
            cap(&["read"]).expiring_at(at),
        ] {
            assert!(read(&mut h, &capability, None).unwrap().is_err());
            assert_eq!(
                h.book.functional_history_read_work(),
                EntryHistoryWork::default()
            );
            assert!(
                h.book.db.delta_since(CommitSeq(0)).is_err(),
                "refused authority must not hydrate retained history"
            );
            assert_eq!(h.head(), at);
        }
        assert!(
            read(&mut h, &cap(&["read"]), Some(CommitSeq(at.0 + 1)))
                .unwrap()
                .is_err()
        );
        assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
        if compact {
            // Storage compaction retires the native creation history.
            // Derived cells cannot replace that missing integrity evidence.
            let refusal = read(&mut h, &cap(&["read"]), None)
                .unwrap()
                .unwrap_err();
            assert_eq!(
                refusal.code,
                fa_journal::refusal::code::REPLAY_UNSUPPORTED
            );
            assert_eq!(
                h.book.functional_history_read_work(),
                EntryHistoryWork::default()
            );
            assert_eq!(h.head(), at);
            continue;
        }
        assert_eq!(allowed(&mut h, None), expected);
        let cold = h.book.functional_history_read_work();
        assert!(cold.rebuilt && cold.snapshot_scans == 1 && cold.entries_decoded > 0);
        assert_eq!(allowed(&mut h, None), expected);
        assert_warm(h.book.functional_history_read_work());
        assert_eq!(h.head(), at);
    }
}

#[test]
fn a_warm_functional_read_refuses_rewritten_and_restored_entry_history() {
    let (mut h, _) = fixture();
    advance(&mut h);
    let intact = h.head();
    let expected = allowed(&mut h, None);
    assert_eq!(allowed(&mut h, None), expected);
    let work = h.book.functional_history_read_work();
    assert_warm(work);
    let source = h
        .book
        .db
        .vertices_at(intact)
        .unwrap()
        .into_iter()
        .find(|row| {
            row.labels.contains(&label::ENTRY)
                && Entry::decode(&bytes(row, property::FA_PAYLOAD, "source").unwrap())
                    .unwrap()
                    .proposal
                    .idempotency_key
                    == b"symbol-post"
        })
        .unwrap();
    let cx = h.cx();
    let mut damage = WriteBatch::new(relation::HAS_LEG);
    damage.set_vertex_property(
        source.vid,
        property::FA_DIGEST,
        Some(scalar_bytes("corrupt journal source", vec![0; 32]).unwrap()),
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    assert!(read(&mut h, &cap(&["read"]), None).is_err());
    assert_eq!(h.book.functional_history_read_work(), work);
    let mut restore = WriteBatch::new(relation::HAS_LEG);
    for (key, value) in source.props {
        restore.set_vertex_property(source.vid, key, Some(value));
    }
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), restore))
        .unwrap();
    assert!(
        read(&mut h, &cap(&["read"]), None).is_err(),
        "restoration cannot erase a journal rewrite"
    );
    assert_eq!(h.book.functional_history_read_work(), work);
    let head = h.head();
    assert_eq!(allowed(&mut h, Some(intact)), expected);
    assert_eq!(h.head(), head);
}

#[test]
fn cancelled_functional_read_cannot_reuse_a_warm_history_verdict() {
    let (mut h, _) = fixture();
    allowed(&mut h, None);
    let work = h.book.functional_history_read_work();
    h.root.cancel_with(
        asupersync::CancelKind::User,
        Some("cancelled functional observation"),
    );
    assert!(read(&mut h, &cap(&["read"]), None).is_err());
    assert_eq!(h.book.functional_history_read_work(), work);
}
