//! A backlog of real pending entries must not exceed the native scalar row
//! limit before the complete checkpoint format reaches its registered bounds.

use super::*;

use fa_model::symbols::{label, property, relation};
use fa_registers::{checkpoint, maintainer};

fn post_matching(
    kernel: &mut Kernel,
    oracle: &mut Oracle,
    refs: &mut Vec<EntryRef>,
    intent: &Intent,
) {
    let usd = kernel.book.units.lookup("USD").unwrap();
    let posted = kernel_post(kernel, intent, usd, refs).expect("kernel admits the fixture entry");
    assert!(matches!(
        oracle.post(intent),
        Verdict::Posted { index, .. } if index == refs.len()
    ));
    refs.push(posted.entry_ref());
}

fn add_holds(kernel: &mut Kernel, oracle: &mut Oracle, refs: &mut Vec<EntryRef>, count: usize) {
    for _ in 0..count {
        let hold = maintenance_intent(
            "Pending",
            DateDay::from_ymd(2026, 3, 10).unwrap(),
            10,
            &format!("large-state-hold-{}", refs.len()),
        );
        post_matching(kernel, oracle, refs, &hold);
    }
}

fn state_payload(kernel: &Kernel, period: &str) -> Vec<u8> {
    let state = kernel
        .db
        .vertex(maintainer::state_vid(kernel.book.book_id, period))
        .unwrap()
        .unwrap();
    rows::bytes(&state, property::FA_PAYLOAD, "maintenance state").unwrap()
}

fn state_version(kernel: &Kernel, period: &str) -> u16 {
    let bytes = state_payload(kernel, period);
    assert_eq!(&bytes[..4], b"FARS");
    assert!(bytes.len() <= fa_journal::object::CHUNK_BYTES);
    u16::from_le_bytes(bytes[4..6].try_into().unwrap())
}

fn assert_contextually_verified(kernel: &Kernel, period: &str) {
    let verified = fa_registers::verify_period_with_context(
        &kernel.db,
        &kernel.ctx().query(),
        &kernel.book,
        period,
    )
    .unwrap();
    assert!(verified.is_green(), "{verified:?}");
}

#[test]
fn hundreds_of_live_holds_advance_release_and_retain_exact_historical_answers() {
    let (mut kernel, mut oracle, periods) = setup();
    let (march, april) = (&periods[2], &periods[3]);
    open_period(&mut kernel, &mut oracle, march, 1);
    open_period(&mut kernel, &mut oracle, april, 2);
    let mut refs = Vec::new();
    add_holds(&mut kernel, &mut oracle, &mut refs, 1);
    let small = maintain(&mut kernel, march);
    assert_eq!(
        state_version(&kernel, march),
        2,
        "old inline format remains readable"
    );

    add_holds(&mut kernel, &mut oracle, &mut refs, 319);
    let ctx = kernel.ctx();
    let frontier = kernel.db.frontier().unwrap();
    let before = state_payload(&kernel, march);
    let abandoned = kernel
        .runtime
        .block_on(fa_registers::prepare_advance(
            &mut kernel.db,
            &ctx,
            &kernel.book,
            march,
        ))
        .unwrap();
    assert_eq!(abandoned.result().fold.pending_holds().len(), 320);
    drop(abandoned);
    assert_eq!(kernel.db.frontier().unwrap(), frontier);
    assert_eq!(
        state_payload(&kernel, march),
        before,
        "preparing a large body publishes nothing"
    );

    let large = maintain(&mut kernel, march);
    assert!(!large.rebuilt);
    assert_eq!(large.entries_decoded, 319);
    assert_eq!(large.fold.pending_holds().len(), 320);
    assert_eq!(state_version(&kernel, march), 3);
    maintained_matches_oracle(&large, &oracle, kernel.book.book_id);
    let reference = large
        .checkpoint
        .expect("large state forces a complete checkpoint");
    let root = kernel
        .db
        .vertex(checkpoint::vid(kernel.book.book_id, march, reference))
        .unwrap()
        .unwrap();
    assert!(
        rows::bytes(&root, property::FA_PAYLOAD, "checkpoint manifest")
            .unwrap()
            .starts_with(b"fa:object:v1"),
        "320 holds exceed 16 KiB and require native object fragments"
    );
    assert_eq!(
        checkpoint::load(
            &kernel.db,
            &ctx.query(),
            &kernel.book,
            march,
            reference,
            large.published_at
        )
        .unwrap()
        .fold,
        large.fold
    );
    assert_contextually_verified(&kernel, march);
    let unchanged_frontier = kernel.db.frontier().unwrap();
    let unchanged = maintain(&mut kernel, march);
    assert!(
        !unchanged.wrote,
        "a large state does not manufacture empty checkpoint commits"
    );
    assert_eq!(kernel.db.frontier().unwrap(), unchanged_frontier);

    let accounts = fa_journal::genesis::list_accounts(&kernel.db).unwrap();
    assert!(
        maintainer::head_fold(&kernel.db, &kernel.book, march, &accounts)
            .unwrap()
            .is_none()
    );
    let tail = maintenance_intent(
        "Original",
        DateDay::from_ymd(2026, 3, 11).unwrap(),
        17,
        "large-state-posted-tail",
    );
    post_matching(&mut kernel, &mut oracle, &mut refs, &tail);
    let served = maintainer::fold_at_with_context(
        &kernel.db,
        &ctx.query(),
        &kernel.book,
        march,
        &accounts,
        kernel.db.frontier().unwrap(),
    )
    .unwrap()
    .expect("large state plus its retained tail serves a typed read");
    assert_eq!(served.checkpoint, Some(reference));
    assert_eq!(served.tail_entries, 1);
    assert_eq!(
        served.fold,
        fold_period(&kernel.db, &kernel.book, march).unwrap()
    );
    let advanced = maintain(&mut kernel, march);
    assert_eq!(advanced.entries_decoded, 1);
    assert_eq!(advanced.from, large.through);
    assert!(
        advanced.checkpoint.is_some(),
        "every changed large state owns an exact body"
    );
    maintained_matches_oracle(&advanced, &oracle, kernel.book.book_id);

    // Posting four of the first ten-unit hold releases all ten in March;
    // the selected four-unit posted vector belongs to April only.
    let mut partial = maintenance_intent(
        "Resolution",
        DateDay::from_ymd(2026, 4, 10).unwrap(),
        4,
        "large-state-partial-resolution",
    );
    partial.resolves = Some(Resolve {
        target: 0,
        posts: Some(vec![0, 1]),
    });
    post_matching(&mut kernel, &mut oracle, &mut refs, &partial);
    let released = maintain(&mut kernel, march);
    assert_eq!(released.fold.pending_holds().len(), 319);
    assert_eq!(
        released
            .fold
            .pending
            .iter()
            .map(|cell| cell.debits)
            .sum::<i128>(),
        3_190
    );
    maintained_matches_oracle(&released, &oracle, kernel.book.book_id);
    let posted = maintain(&mut kernel, april);
    assert_eq!(
        posted
            .fold
            .cells
            .iter()
            .map(|cell| cell.debits)
            .sum::<i128>(),
        4
    );
    assert!(posted.fold.pending.is_empty());
    maintained_matches_oracle(&posted, &oracle, kernel.book.book_id);

    for target in 1..320 {
        let mut void = maintenance_intent(
            "Resolution",
            DateDay::from_ymd(2026, 4, 11).unwrap(),
            0,
            &format!("large-state-void-{target}"),
        );
        void.resolves = Some(Resolve {
            target,
            posts: None,
        });
        post_matching(&mut kernel, &mut oracle, &mut refs, &void);
    }
    let cleared = maintain(&mut kernel, march);
    assert!(cleared.fold.pending.is_empty());
    assert!(cleared.fold.pending_holds().is_empty());
    assert_eq!(
        state_version(&kernel, march),
        2,
        "small state returns to the compatible inline format"
    );
    maintained_matches_oracle(&cleared, &oracle, kernel.book.book_id);
    let final_april = maintain(&mut kernel, april);
    maintained_matches_oracle(&final_april, &oracle, kernel.book.book_id);
    for period in [march, april] {
        assert_contextually_verified(&kernel, period);
    }

    // Both formats are observed at their own original snapshot. Later
    // resolutions, rewritten headers and newer checkpoint pointers are absent.
    let final_frontier = kernel.db.frontier().unwrap();
    for (snapshot, expected_checkpoint) in [(&small, None), (&large, Some(reference))] {
        let historical = maintainer::fold_at_with_context(
            &kernel.db,
            &ctx.query(),
            &kernel.book,
            march,
            &accounts,
            snapshot.published_at,
        )
        .unwrap()
        .unwrap();
        assert_eq!(historical.fold, snapshot.fold);
        assert_eq!(historical.checkpoint, expected_checkpoint);
        assert_eq!(historical.tail_entries, 0);
        assert_eq!(
            historical.fold,
            fa_registers::fold_period_at(
                &kernel.db,
                &kernel.book,
                march,
                Some(snapshot.published_at)
            )
            .unwrap()
        );
    }
    assert_eq!(
        kernel.db.frontier().unwrap(),
        final_frontier,
        "reads never repair"
    );
}

fn write_header(kernel: &mut Kernel, period: &str, payload: Vec<u8>) {
    let mut digest = fgdb_crypto::Hasher::new();
    digest.update(b"fa:register-state-payload:v1");
    digest.update(&kernel.book.book_id.0);
    digest.update(&(period.len() as u64).to_le_bytes());
    digest.update(period.as_bytes());
    digest.update(&payload);
    let state = maintainer::state_vid(kernel.book.book_id, period);
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    batch.set_vertex_property(
        state,
        property::FA_PAYLOAD,
        Some(rows::scalar_bytes("header", payload).unwrap()),
    );
    batch.set_vertex_property(
        state,
        property::FA_DIGEST,
        Some(rows::scalar_bytes("checksum", digest.finalize().0.to_vec()).unwrap()),
    );
    let ctx = kernel.ctx();
    kernel
        .runtime
        .block_on(kernel.db.write(&ctx.commit(), batch))
        .unwrap();
}

fn assert_large_state_refused(kernel: &mut Kernel, period: &str) {
    let ctx = kernel.ctx();
    let frontier = kernel.db.frontier().unwrap();
    assert!(matches!(
        kernel.runtime.block_on(fa_registers::prepare_advance(
            &mut kernel.db,
            &ctx,
            &kernel.book,
            period
        )),
        Err(fa_registers::RegisterError::ProjectionDrift(_))
    ));
    assert_eq!(kernel.db.frontier().unwrap(), frontier);
    let verified =
        fa_registers::verify_period_with_context(&kernel.db, &ctx.query(), &kernel.book, period)
            .unwrap();
    assert!(!verified.is_green(), "{verified:?}");
    assert_eq!(verified.cache_status, fa_registers::CacheStatus::Corrupt);
}

#[test]
fn checkpoint_backed_state_refuses_resealed_reference_and_fragment_corruption() {
    let (mut kernel, mut oracle, periods) = setup();
    let march = &periods[2];
    open_period(&mut kernel, &mut oracle, march, 1);
    add_holds(&mut kernel, &mut oracle, &mut Vec::new(), 72);
    let original = maintain(&mut kernel, march);
    assert_eq!(state_version(&kernel, march), 3);
    let reference = original.checkpoint.unwrap();
    let valid_header = state_payload(&kernel, march);
    let mut wrong_reference = valid_header.clone();
    *wrong_reference.last_mut().unwrap() ^= 1;
    write_header(&mut kernel, march, wrong_reference);
    assert_large_state_refused(&mut kernel, march);
    assert!(
        fa_registers::verify_period(&kernel.db, &kernel.book, march)
            .unwrap()
            .is_green(),
        "the legacy verifier checks mutable accounting claims, not archive storage"
    );
    write_header(&mut kernel, march, valid_header);
    assert_contextually_verified(&kernel, march);

    let root = checkpoint::vid(kernel.book.book_id, march, reference);
    let root_birth = kernel.db.vertex(root).unwrap().unwrap().created_at;
    let fragment = kernel
        .db
        .vertices()
        .unwrap()
        .into_iter()
        .find(|row| {
            row.vid != root
                && row.labels == vec![label::REGISTER_CHECKPOINT]
                && row.created_at == root_birth
        })
        .expect("large checkpoint has a fragment born with its root");
    let mut bytes = rows::bytes(&fragment, property::FA_PAYLOAD, "fragment").unwrap();
    bytes[0] ^= 1;
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    batch.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(rows::scalar_bytes("damaged fragment", bytes).unwrap()),
    );
    let ctx = kernel.ctx();
    kernel
        .runtime
        .block_on(kernel.db.write(&ctx.commit(), batch))
        .unwrap();
    assert_large_state_refused(&mut kernel, march);
    let accounts = fa_journal::genesis::list_accounts(&kernel.db).unwrap();
    assert!(
        maintainer::fold_at_with_context(
            &kernel.db,
            &ctx.query(),
            &kernel.book,
            march,
            &accounts,
            kernel.db.frontier().unwrap()
        )
        .unwrap()
        .is_none()
    );
    let historical = maintainer::fold_at_with_context(
        &kernel.db,
        &ctx.query(),
        &kernel.book,
        march,
        &accounts,
        original.published_at,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        historical.fold, original.fold,
        "later fragment corruption does not enter earlier visibility"
    );
    let (report, served) = fa_registers::trial_balance_served_at_with_context(
        &kernel.db,
        &ctx.query(),
        &kernel.book,
        &[march.clone()],
        None,
    )
    .unwrap();
    assert!(matches!(served, fa_registers::Served::Literal(_)));
    assert_eq!(
        report,
        trial_balance_at(&kernel.db, &kernel.book, &[march.clone()], None).unwrap()
    );
}

#[test]
fn interrupted_large_publication_exposes_neither_cursor_nor_checkpoint_fragments() {
    let chart: Vec<ChartRow> = ACCOUNTS
        .iter()
        .map(|(code, ty, leaf)| (*code, *ty, *leaf, 0, None))
        .collect();
    let (mut kernel, mut oracle, periods, vfs) = setup_store(&chart);
    let march = &periods[2];
    open_period(&mut kernel, &mut oracle, march, 1);
    add_holds(&mut kernel, &mut oracle, &mut Vec::new(), 72);
    let ctx = kernel.ctx();
    let before = kernel.db.frontier().unwrap();
    let expected = fold_period(&kernel.db, &kernel.book, march).unwrap();
    let prepared = kernel
        .runtime
        .block_on(fa_registers::prepare_advance(
            &mut kernel.db,
            &ctx,
            &kernel.book,
            march,
        ))
        .unwrap();
    assert!(
        kernel
            .runtime
            .block_on(maintainer::publish_advance_with_crash(
                &mut kernel.db,
                &ctx,
                &kernel.book,
                prepared,
                Some(fgdb::CrashPoint::BeforeCapsule)
            ))
            .is_err()
    );
    let Kernel {
        runtime,
        root,
        db,
        book,
        evidence,
        agent_evidence,
    } = kernel;
    drop(db);
    let db = runtime
        .block_on(Database::open_with_vfs(
            &ctx.commit(),
            vfs.clone(),
            vfs.database_dir(),
            db_keys(),
        ))
        .unwrap();
    let mut kernel = Kernel {
        runtime,
        root,
        db,
        book,
        evidence,
        agent_evidence,
    };
    assert_eq!(kernel.db.frontier().unwrap(), before);
    assert!(
        kernel
            .db
            .vertex(maintainer::state_vid(kernel.book.book_id, march))
            .unwrap()
            .is_none()
    );
    assert!(
        kernel
            .db
            .vertices()
            .unwrap()
            .iter()
            .all(|row| !row.labels.contains(&label::REGISTER_CHECKPOINT))
    );
    assert_eq!(
        fold_period(&kernel.db, &kernel.book, march).unwrap(),
        expected
    );
    let recovered = maintain(&mut kernel, march);
    assert_eq!(recovered.fold, expected);
    assert_eq!(state_version(&kernel, march), 3);
    assert_contextually_verified(&kernel, march);
}
