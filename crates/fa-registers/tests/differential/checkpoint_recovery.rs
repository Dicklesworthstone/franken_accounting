//! Durable snapshots are independently useful after mutable maintenance loss,
//! and their authenticated bytes are still checked against journal truth.

use super::*;

use fa_model::symbols::{property, relation};
use fa_registers::checkpoint;

fn post_both(kernel: &mut Kernel, oracle: &mut Oracle, period: &str, amount: i128, key: &str) {
    let intent = maintenance_intent(
        "Original",
        DateDay::from_ymd(2026, 3, 10).unwrap(),
        amount,
        key,
    );
    let usd = kernel.book.units.lookup("USD").unwrap();
    kernel_post(kernel, &intent, usd, &[]).unwrap();
    match oracle.post(&intent) {
        Verdict::Posted { period: actual, .. } => assert_eq!(actual, period),
        other => panic!("oracle refused the kernel's posting: {other:?}"),
    }
}

#[test]
fn an_archive_and_exact_tail_answer_after_mutable_cell_corruption() {
    let (mut kernel, mut oracle, periods) = setup();
    let period = &periods[2];
    open_period(&mut kernel, &mut oracle, period, 1);
    post_both(&mut kernel, &mut oracle, period, 100, "archive-base");
    let first = maintain(&mut kernel, period);
    maintained_matches_oracle(&first, &oracle, kernel.book.book_id);
    let original = first.checkpoint.expect("first advance retains a snapshot");

    post_both(&mut kernel, &mut oracle, period, 25, "archive-tail");
    let usd = kernel.book.units.lookup("USD").unwrap();
    let cell = fa_registers::register_vid(
        kernel.book.book_id,
        &fa_registers::CellKey {
            account: account_vid(kernel.book.book_id, "6000"),
            unit_id: usd.0,
            period: period.clone(),
        },
    );
    let mut damage = WriteBatch::new(relation::IN_PERIOD);
    damage.set_vertex_property(
        cell,
        property::DEBITS_POSTED,
        Some(rows::scalar_bytes("debits", 999i128.to_le_bytes().to_vec()).unwrap()),
    );
    let ctx = kernel.ctx();
    kernel
        .runtime
        .block_on(kernel.db.write(&ctx.commit(), damage))
        .unwrap();
    let at = kernel.db.frontier().unwrap();
    let accounts = fa_journal::genesis::list_accounts(&kernel.db).unwrap();
    let served = fa_registers::maintainer::fold_at_with_context(
        &kernel.db,
        &ctx.query(),
        &kernel.book,
        period,
        &accounts,
        at,
    )
    .unwrap()
    .expect("the immutable snapshot survives mutable cell corruption");
    assert_eq!(served.checkpoint, Some(original));
    assert_eq!(served.served_at, original.through);
    assert_eq!(served.tail_entries, 1);
    assert_eq!(
        served.fold,
        fold_period(&kernel.db, &kernel.book, period).unwrap()
    );

    let selection = vec![period.clone()];
    let (report, how) = fa_registers::trial_balance_served_at_with_context(
        &kernel.db,
        &ctx.query(),
        &kernel.book,
        &selection,
        Some(at),
    )
    .unwrap();
    assert!(
        matches!(how, fa_registers::Served::Maintained(_)),
        "{how:?}"
    );
    assert_eq!(
        report,
        trial_balance_at(&kernel.db, &kernel.book, &selection, Some(at)).unwrap()
    );
    for ((code, unit), expected) in oracle.fold(period) {
        let row = report
            .rows
            .iter()
            .find(|row| row.code == code && row.unit_id == unit)
            .expect("oracle account appears in the report");
        assert_eq!(row.debits, expected.debits.to_i128().unwrap());
        assert_eq!(row.credits, expected.credits.to_i128().unwrap());
    }
    assert_eq!(kernel.db.frontier().unwrap(), at, "serving never repairs");
    assert!(
        !fa_registers::verify_period_with_context(&kernel.db, &ctx.query(), &kernel.book, period)
            .unwrap()
            .is_green(),
        "successful archive reads do not conceal drift in mutable cells"
    );
}

#[test]
fn a_deleted_primary_header_recovers_without_resurrecting_its_spent_identity() {
    let (mut kernel, mut oracle, periods) = setup();
    let period = &periods[2];
    open_period(&mut kernel, &mut oracle, period, 1);
    post_both(&mut kernel, &mut oracle, period, 100, "recovery-base");
    let first = maintain(&mut kernel, period);
    let original = first.checkpoint.expect("first advance retains a snapshot");
    let original_root = checkpoint::vid(kernel.book.book_id, period, original);
    let original_row = kernel.db.vertex(original_root).unwrap().unwrap();
    post_both(&mut kernel, &mut oracle, period, 25, "recovery-tail");

    let primary = fa_registers::maintainer::state_vid(kernel.book.book_id, period);
    let head = checkpoint::head_vid(kernel.book.book_id, period);
    let ctx = kernel.ctx();
    let mut damage = WriteBatch::new(relation::IN_PERIOD);
    damage.delete_vertex(primary);
    kernel
        .runtime
        .block_on(kernel.db.write(&ctx.commit(), damage))
        .unwrap();
    let recovered = maintain(&mut kernel, period);
    assert_eq!(recovered.recovered_from, Some(original.through));
    assert_eq!(recovered.from, original.through);
    assert_eq!(recovered.entries_decoded, 1);
    assert!(
        !recovered.rebuilt,
        "the retained suffix needs no full refold"
    );
    assert!(recovered.wrote);
    maintained_matches_oracle(&recovered, &oracle, kernel.book.book_id);
    assert!(kernel.db.vertex(primary).unwrap().is_none());
    let head_row = kernel.db.vertex(head).unwrap().unwrap();
    assert!(rows::prop(&head_row, property::FA_PAYLOAD).is_some());
    assert!(rows::prop(&head_row, property::TARGET_REF).is_some());
    assert_eq!(kernel.db.vertex(original_root).unwrap(), Some(original_row));

    post_both(&mut kernel, &mut oracle, period, 7, "recovery-next");
    let next = maintain(&mut kernel, period);
    assert_eq!(next.from, recovered.through);
    assert_eq!(
        next.recovered_from, None,
        "the recovered header is reusable"
    );
    assert_eq!(next.entries_decoded, 1);
    assert!(!next.rebuilt);
    maintained_matches_oracle(&next, &oracle, kernel.book.book_id);
    assert!(
        kernel.db.vertex(primary).unwrap().is_none(),
        "neither recovery nor subsequent maintenance resurrects a spent VID"
    );
    let verified =
        fa_registers::verify_period_with_context(&kernel.db, &ctx.query(), &kernel.book, period)
            .unwrap();
    assert!(verified.is_green(), "{verified:?}");
}

#[test]
fn a_coherently_forged_checkpoint_is_rejected_by_independent_journal_refolding() {
    let (mut kernel, mut oracle, periods) = setup();
    let period = &periods[2];
    open_period(&mut kernel, &mut oracle, period, 1);
    post_both(&mut kernel, &mut oracle, period, 100, "forgery-base");
    let old = maintain(&mut kernel, period);
    post_both(&mut kernel, &mut oracle, period, 25, "forgery-new-truth");
    let current = maintain(&mut kernel, period);
    maintained_matches_oracle(&current, &oracle, kernel.book.book_id);
    assert_ne!(old.fold, current.fold);
    let ctx = kernel.ctx();
    let through = kernel.db.frontier().unwrap();

    // Stage a complete, self-consistent old fold under a newer source prefix.
    // Every chunk, digest and cell root is valid; only the accounting claim is
    // false. Independent verification must detect that semantic mismatch.
    let mut forged_batch = WriteBatch::new(relation::IN_PERIOD);
    let forged = checkpoint::stage(
        &kernel.db,
        &ctx.query(),
        &kernel.book,
        &mut forged_batch,
        through,
        &old.fold,
        false,
    )
    .unwrap();
    let published_at = kernel
        .runtime
        .block_on(kernel.db.write(&ctx.commit(), forged_batch))
        .unwrap();
    let loaded =
        checkpoint::load_latest(&kernel.db, &ctx.query(), &kernel.book, period, published_at)
            .unwrap()
            .expect("the forged archive is structurally valid");
    assert_eq!(loaded, forged);
    assert_eq!(loaded.fold, old.fold);
    assert_eq!(loaded.through, through);
    assert_eq!(
        fold_period(&kernel.db, &kernel.book, period).unwrap(),
        current.fold
    );
    assert!(
        fa_registers::verify_period(&kernel.db, &kernel.book, period)
            .unwrap()
            .is_green(),
        "the mutable cells themselves still match journal truth"
    );
    let verified =
        fa_registers::verify_period_with_context(&kernel.db, &ctx.query(), &kernel.book, period)
            .unwrap();
    assert!(!verified.is_green());
    assert!(
        verified
            .projection_errors
            .iter()
            .any(|error| error.contains("independently refolded journal prefix"))
    );
    assert_eq!(verified.cache_status, fa_registers::CacheStatus::Corrupt);
    assert_eq!(verified.verified_through, None);
}
