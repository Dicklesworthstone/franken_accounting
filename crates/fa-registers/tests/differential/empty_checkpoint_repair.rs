//! Empty materialization must repair existing maintenance state, even when
//! only the independent checkpoint head survives the primary header's loss.

use super::*;

use fa_model::symbols::{label, property, relation};
use fa_registers::checkpoint;

#[test]
fn empty_materialization_repairs_a_checkpoint_head_after_primary_state_loss() {
    let (mut kernel, mut oracle, periods) = setup();
    let period = &periods[2];
    open_period(&mut kernel, &mut oracle, period, 1);
    assert!(oracle.fold(period).is_empty());
    assert!(oracle.pending_fold(period).is_empty());

    let first = maintain(&mut kernel, period);
    assert!(first.fold.cells.is_empty());
    assert!(first.fold.pending.is_empty());
    let original = first
        .checkpoint
        .expect("advance retains the empty snapshot");
    let original_root = checkpoint::vid(kernel.book.book_id, period, original);
    let original_row = kernel.db.vertex(original_root).unwrap().unwrap();
    let primary = fa_registers::maintainer::state_vid(kernel.book.book_id, period);
    let head = checkpoint::head_vid(kernel.book.book_id, period);
    let journal_before: BTreeMap<_, _> = kernel
        .db
        .vertices()
        .unwrap()
        .into_iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .map(|row| (row.vid, row))
        .collect();
    let ctx = kernel.ctx();

    // A deleted native identity is spent. Repair must use the surviving head,
    // and a damaged archive pointer must not defeat an explicit literal fold.
    let mut damage = WriteBatch::new(relation::IN_PERIOD);
    damage.delete_vertex(primary);
    damage.set_vertex_property(
        head,
        property::TARGET_REF,
        Some(fa_journal::rows::scalar_bytes("damaged checkpoint pointer", vec![0xff]).unwrap()),
    );
    let damaged_at = kernel
        .runtime
        .block_on(kernel.db.write(&ctx.commit(), damage))
        .unwrap();
    assert!(kernel.db.vertex(primary).unwrap().is_none());
    assert!(matches!(
        checkpoint::load_latest(&kernel.db, &ctx.query(), &kernel.book, period, damaged_at),
        Err(fa_registers::RegisterError::ProjectionDrift(_))
    ));
    assert!(
        !fa_registers::verify_period_with_context(&kernel.db, &ctx.query(), &kernel.book, period,)
            .unwrap()
            .is_green()
    );

    let literal = fold_period(&kernel.db, &kernel.book, period).unwrap();
    assert_eq!(literal, first.fold);
    let repaired_at = kernel
        .runtime
        .block_on(fa_registers::materialize(
            &mut kernel.db,
            &ctx,
            &kernel.book,
            &literal,
        ))
        .expect("empty materialization repairs the surviving checkpoint head");
    assert!(
        repaired_at > damaged_at,
        "an existing empty cache must not take the uninitialized-period no-op"
    );
    assert!(
        kernel.db.vertex(primary).unwrap().is_none(),
        "repair never resurrects a spent maintenance identity"
    );
    let restored =
        checkpoint::load_latest(&kernel.db, &ctx.query(), &kernel.book, period, repaired_at)
            .unwrap()
            .expect("repair publishes a complete replacement checkpoint");
    assert_eq!(restored.through, damaged_at);
    assert_eq!(restored.fold, literal);
    assert_eq!(restored.cell_count, 0);
    assert_eq!(restored.previous, None);
    assert_ne!(restored.reference(), original);
    assert_eq!(kernel.db.vertex(original_root).unwrap(), Some(original_row));
    let verified =
        fa_registers::verify_period_with_context(&kernel.db, &ctx.query(), &kernel.book, period)
            .unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert_eq!(verified.verified_through, Some(damaged_at));

    // A subsequent ordinary advance reads the replacement FARS header on the
    // head; it has no new journal work and must not manufacture another write.
    assert!(!maintain(&mut kernel, period).wrote);
    assert_eq!(kernel.db.frontier().unwrap(), repaired_at);
    let journal_after: BTreeMap<_, _> = kernel
        .db
        .vertices()
        .unwrap()
        .into_iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .map(|row| (row.vid, row))
        .collect();
    assert_eq!(journal_after, journal_before);
}
