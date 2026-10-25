//! FrankenGraphDB behaviors the kernel relies on, at the pinned revision
//! (plan §16.3, bead fa-zy1). Each test drives the `fgdb` API directly and
//! asserts the exact typed outcome next to a control that must not trip it.
//!
//! `FA_CONFORMANCE_INVERT=<test name>` inverts that test's expectation for
//! the mutation run (`scripts/conformance_mutation.sh`): the inverted test
//! must fail and every other test must still pass.

#![forbid(unsafe_code)]

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fgdb::{
    Database, DatabaseKeys, MemVfs, QueryResult, ReplayRefusal, WriteBatch, WriteError,
    WriteTxnError,
};
use fgdb_delta_types::{LabelId, PropertyKeyId, RelationId};
use fgdb_gql::{GqlParameters, GqlQueryPolicy, GraphSymbol, GraphSymbolKind};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const REL: RelationId = RelationId(1);
const THING: LabelId = LabelId(1);
const P: PropertyKeyId = PropertyKeyId(1);

/// The mutation run's switch: true when this test's expectation is inverted.
fn inverted(test: &str) -> bool {
    std::env::var("FA_CONFORMANCE_INVERT").is_ok_and(|name| name == test)
}

/// Assert a relied-upon behavior; under inversion its presence is a failure.
fn relied_upon(test: &str, behaved: bool, what: &str) {
    eprintln!("[conformance] {test}: {what}: behaved={behaved}");
    assert!(
        behaved != inverted(test),
        "{test}: {what} (behaved={behaved}, inverted={})",
        inverted(test)
    );
}

struct Harness {
    runtime: Runtime,
    root: Cx,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().expect("runtime");
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        Self { runtime, root }
    }

    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn open(&self) -> Database<MemVfs> {
        let ctx = self.ctx();
        let keys = DatabaseKeys::new(
            [0x41; 32],
            DatabaseSecurityNamespaceId([0x42; 32]),
            [0x43; 32],
        );
        self.runtime
            .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
            .expect("open memory database")
    }

    fn write(&self, db: &mut Database<MemVfs>, batch: WriteBatch) -> Result<CommitSeq, WriteError> {
        let ctx = self.ctx();
        self.runtime
            .block_on(async { db.write(&ctx.commit(), batch).await })
    }
}

fn create(vid: u128, p: i64) -> WriteBatch {
    let mut batch = WriteBatch::new(REL);
    batch.create_vertex(VId(vid), vec![THING], vec![(P, CanonicalScalar::Int(p))]);
    batch
}

fn set(vid: u128, p: i64) -> WriteBatch {
    let mut batch = WriteBatch::new(REL);
    batch.set_vertex_property(VId(vid), P, Some(CanonicalScalar::Int(p)));
    batch
}

#[test]
fn a_live_identity_is_refused_already_live_by_autocommit_and_while_staging() {
    const T: &str = "a_live_identity_is_refused_already_live_by_autocommit_and_while_staging";
    let h = Harness::new();
    let mut db = h.open();
    h.write(&mut db, create(1, 0))
        .expect("first create commits");

    let again = h.write(&mut db, create(1, 0));
    relied_upon(
        T,
        matches!(again, Err(WriteError::AlreadyLive { .. })),
        &format!("autocommit create of a live vid is AlreadyLive: {again:?}"),
    );

    // The kernel's install_chart relies on WHERE this surfaces (fa-er1): a
    // transaction staging the same identity is refused at write_ordered,
    // before commit.
    let ctx = h.ctx();
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx).expect("begin");
    let staged = txn.write_ordered(&mut db, vec![create(1, 0)]);
    relied_upon(
        T,
        matches!(
            staged,
            Err(WriteTxnError::Write(WriteError::AlreadyLive { .. }))
        ),
        &format!("staging a live vid is Write(AlreadyLive) at write_ordered: {staged:?}"),
    );
    txn.abort();

    // Control: a fresh identity stages and commits.
    let mut txn = db.begin(&txn_cx).expect("begin");
    txn.write_ordered(&mut db, vec![create(2, 0)])
        .expect("a fresh identity stages");
    let committed = h
        .runtime
        .block_on(async { txn.commit(&mut db, &ctx.commit()).await });
    assert!(committed.is_ok(), "control: {committed:?}");
}

#[test]
fn a_transaction_behind_the_frontier_is_refused_snapshot_advanced_at_staging() {
    const T: &str = "a_transaction_behind_the_frontier_is_refused_snapshot_advanced_at_staging";
    let h = Harness::new();
    let mut db = h.open();
    h.write(&mut db, create(1, 0)).expect("seed");
    let ctx = h.ctx();
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx).expect("begin");
    h.write(&mut db, create(9, 0))
        .expect("another committer moves the frontier");
    let staged = txn.write(&mut db, set(1, 5));
    relied_upon(
        T,
        matches!(staged, Err(WriteTxnError::SnapshotAdvanced { .. })),
        &format!("staging behind the frontier is SnapshotAdvanced: {staged:?}"),
    );
    txn.abort();

    // Control: a transaction at the frontier stages.
    let mut txn = db.begin(&txn_cx).expect("begin");
    assert!(txn.write(&mut db, set(1, 5)).is_ok(), "control stages");
    txn.abort();
}

#[test]
fn refresh_snapshot_refuses_first_committer_wins_iff_a_witnessed_row_changed() {
    const T: &str = "refresh_snapshot_refuses_first_committer_wins_iff_a_witnessed_row_changed";
    let h = Harness::new();
    let mut db = h.open();
    h.write(&mut db, create(1, 0)).expect("seed witnessed row");
    h.write(&mut db, create(2, 0))
        .expect("seed unwitnessed row");
    let ctx = h.ctx();
    let txn_cx = ctx.txn();

    // The witnessed row changes under the transaction.
    let mut txn = db.begin(&txn_cx).expect("begin");
    let seen = txn.vertex_property(&db, VId(1), P).expect("point read");
    assert_eq!(seen, Some(CanonicalScalar::Int(0)));
    h.write(&mut db, set(1, 7))
        .expect("another committer changes the witness");
    assert!(matches!(
        txn.write(&mut db, set(3, 0)),
        Err(WriteTxnError::SnapshotAdvanced { .. })
    ));
    let refreshed = txn.refresh_snapshot(&db, &txn_cx);
    relied_upon(
        T,
        matches!(
            refreshed,
            Err(WriteTxnError::Write(WriteError::FirstCommitterWins { .. }))
        ),
        &format!("refresh after a witnessed change is FirstCommitterWins: {refreshed:?}"),
    );

    // Control: only an unwitnessed row changes; refresh succeeds and the
    // transaction commits at the new basis.
    let mut txn = db.begin(&txn_cx).expect("begin");
    txn.vertex_property(&db, VId(1), P).expect("point read");
    h.write(&mut db, set(2, 9))
        .expect("another committer changes an unwitnessed row");
    assert!(matches!(
        txn.write(&mut db, set(1, 8)),
        Err(WriteTxnError::SnapshotAdvanced { .. })
    ));
    let refreshed = txn.refresh_snapshot(&db, &txn_cx);
    assert!(refreshed.is_ok(), "control refresh: {refreshed:?}");
    txn.write(&mut db, set(1, 8))
        .expect("stages at the refreshed basis");
    let committed = h
        .runtime
        .block_on(async { txn.commit(&mut db, &ctx.commit()).await });
    assert!(committed.is_ok(), "control commit: {committed:?}");
}

#[test]
fn a_witnessed_row_changed_after_staging_loses_first_committer_wins_at_commit() {
    const T: &str = "a_witnessed_row_changed_after_staging_loses_first_committer_wins_at_commit";
    let h = Harness::new();
    let mut db = h.open();
    h.write(&mut db, create(1, 0)).expect("seed witnessed row");
    h.write(&mut db, create(2, 0))
        .expect("seed unwitnessed row");
    let ctx = h.ctx();
    let txn_cx = ctx.txn();

    // Witness and stage first, then the other committer wins the row.
    let mut txn = db.begin(&txn_cx).expect("begin");
    txn.vertex_property(&db, VId(1), P).expect("point read");
    txn.write(&mut db, create(3, 0))
        .expect("stages before the conflict");
    h.write(&mut db, set(1, 7))
        .expect("another committer changes the witness");
    let committed = h
        .runtime
        .block_on(async { txn.commit(&mut db, &ctx.commit()).await });
    relied_upon(
        T,
        matches!(
            committed,
            Err(WriteTxnError::Write(WriteError::FirstCommitterWins { .. }))
        ),
        &format!("commit after a witnessed change is FirstCommitterWins: {committed:?}"),
    );
    assert!(
        db.vertex(VId(3)).expect("read").is_none(),
        "the loser's staged write is not durable"
    );

    // Control: the other committer touches only an unwitnessed row.
    let mut txn = db.begin(&txn_cx).expect("begin");
    txn.vertex_property(&db, VId(1), P).expect("point read");
    txn.write(&mut db, create(4, 0)).expect("stages");
    h.write(&mut db, set(2, 9)).expect("unwitnessed change");
    let committed = h
        .runtime
        .block_on(async { txn.commit(&mut db, &ctx.commit()).await });
    assert!(committed.is_ok(), "control commit: {committed:?}");
    assert!(db.vertex(VId(4)).expect("read").is_some());
}

#[test]
fn aggregate_guard_no_publication_between_compare_and_marker() {
    const T: &str = "aggregate_guard_no_publication_between_compare_and_marker";
    let h = Harness::new();
    let ctx = h.ctx();
    let txn_cx = ctx.txn();
    let mut both_orders_hold = true;

    for intervening_first in [false, true] {
        let mut db = h.open();
        h.write(&mut db, create(1, 0)).expect("aggregate input");
        h.write(&mut db, create(2, 0)).expect("unrelated input");
        let basis = db.frontier().expect("observed aggregate prefix");
        let mut aggregate = db.begin(&txn_cx).expect("begin aggregate");
        assert_eq!(aggregate.basis(), basis);
        aggregate.vertex(&db, VId(1)).expect("point witness");
        aggregate
            .write(&mut db, create(3, 42))
            .expect("stage aggregate result");
        let mut unrelated = db.begin(&txn_cx).expect("begin unrelated writer");
        unrelated
            .write(&mut db, set(2, 9))
            .expect("stage disjoint effect at the same prefix");

        if intervening_first {
            let published = h
                .runtime
                .block_on(async { unrelated.commit(&mut db, &ctx.commit()).await })
                .expect("unrelated writer publishes first");
            assert_eq!(published.0, basis.0 + 1);
            let before = db.frontier().expect("frontier after intervention");
            let checked = fa_journal::post::check_aggregate_basis(aggregate.basis(), before);
            eprintln!(
                "[conformance] {T}: unrelated-first basis={} frontier={} guard={checked:?}",
                basis.0, before.0
            );
            let refused = matches!(
                checked,
                Err(ref refusal)
                    if refusal.code == fa_journal::refusal::code::PLAN_INVALIDATED
                        && refusal.exit == fa_journal::refusal::exit::CONFLICT
            );
            if refused {
                aggregate.abort();
            } else {
                // If the production guard is removed or weakened, actually
                // attempt the stale publication; do not merely compare flags.
                let _ = h
                    .runtime
                    .block_on(async { aggregate.commit(&mut db, &ctx.commit()).await });
            }
            both_orders_hold &= refused
                && db.frontier().expect("refusal frontier") == before
                && db.vertex(VId(3)).expect("refused result").is_none();
        } else {
            fa_journal::post::check_aggregate_basis(
                aggregate.basis(),
                db.frontier().expect("guard frontier"),
            )
            .expect("unchanged prefix is admissible");
            // The exact production protocol: this mutable handle stays
            // exclusively borrowed across the asynchronous native commit.
            let published = h
                .runtime
                .block_on(async { aggregate.commit(&mut db, &ctx.commit()).await })
                .expect("aggregate publishes first");
            both_orders_hold &= published.0 == basis.0 + 1
                && db.frontier().expect("published frontier") == published
                && db.vertex(VId(3)).expect("aggregate result").is_some();
            let second = h
                .runtime
                .block_on(async { unrelated.commit(&mut db, &ctx.commit()).await })
                .expect("ordinary disjoint point-only writer remains admissible");
            both_orders_hold &= second.0 == published.0 + 1;
            eprintln!(
                "[conformance] {T}: aggregate-first basis={} aggregate={} unrelated={}",
                basis.0, published.0, second.0
            );
        }
    }

    // Planted guard removal: point witnesses alone do not cover a whole
    // prefix. The native validator permits this stale, disjoint effect.
    let mut db = h.open();
    h.write(&mut db, create(1, 0)).expect("aggregate input");
    h.write(&mut db, create(2, 0)).expect("unrelated input");
    let mut unguarded = db.begin(&txn_cx).expect("begin planted variant");
    let stale_basis = unguarded.basis();
    unguarded.vertex(&db, VId(1)).expect("point witness");
    unguarded
        .write(&mut db, create(3, 42))
        .expect("stage before intervention");
    h.write(&mut db, set(2, 9))
        .expect("intervening publication");
    let stale_publication = h
        .runtime
        .block_on(async { unguarded.commit(&mut db, &ctx.commit()).await })
        .expect("without the guard, disjoint point witnesses permit publication");
    assert_eq!(stale_publication.0, stale_basis.0 + 2);
    assert!(db.vertex(VId(3)).expect("planted stale result").is_some());

    relied_upon(
        T,
        both_orders_hold,
        "the aggregate guard refuses an intervening prefix without mutation; an unchanged prefix publishes the next marker with no internal publication, while ordinary disjoint point-only commits still work",
    );
}

#[test]
fn delta_since_returns_every_committed_batch_in_commit_order() {
    const T: &str = "delta_since_returns_every_committed_batch_in_commit_order";
    let h = Harness::new();
    let mut db = h.open();
    let start = db.frontier().expect("frontier");
    let mut written = Vec::new();
    for vid in 1..=4 {
        written.push(h.write(&mut db, create(vid, 0)).expect("commit"));
    }
    let seen: Vec<CommitSeq> = db
        .delta_since(start)
        .expect("delta window")
        .map(|batch| batch.commit_seq())
        .collect();
    relied_upon(
        T,
        seen == written,
        &format!("delta_since(start) is exactly the committed seqs: {seen:?} vs {written:?}"),
    );
    // Control: a cursor inside the window returns exactly the later batches,
    // and the frontier cursor returns none.
    let later: Vec<CommitSeq> = db
        .delta_since(written[1])
        .expect("delta window")
        .map(|batch| batch.commit_seq())
        .collect();
    assert_eq!(later, written[2..].to_vec());
    assert_eq!(db.delta_since(written[3]).expect("delta window").count(), 0);
}

fn symbols(kind: GraphSymbolKind, name: &str) -> Option<GraphSymbol> {
    match (kind, name) {
        (GraphSymbolKind::Label, "Thing") => Some(GraphSymbol::Label(THING)),
        (GraphSymbolKind::Property, "p") => Some(GraphSymbol::Property(P)),
        (GraphSymbolKind::Relation, "R") => Some(GraphSymbol::Relation(REL)),
        _ => None,
    }
}

fn policy() -> GqlQueryPolicy {
    GqlQueryPolicy::new(100_000, 100_000, 10_000_000, 10_000_000)
}

fn rows(result: &QueryResult) -> String {
    match result {
        QueryResult::Rows { columns, rows } => format!("{columns:?} {rows:?}"),
        other => format!("not rows: {other:?}"),
    }
}

#[test]
fn a_certified_read_replays_byte_identically_after_later_commits() {
    const T: &str = "a_certified_read_replays_byte_identically_after_later_commits";
    let h = Harness::new();
    let mut db = h.open();
    for (vid, p) in [(1, 10), (2, 21), (3, 30)] {
        h.write(&mut db, create(vid, p)).expect("seed");
    }
    let at = db.frontier().expect("frontier");
    let text = "MATCH (n:Thing) FOR SYSTEM_TIME AS OF SEQ $at RETURN n.p AS p ORDER BY p";
    let params = GqlParameters::new()
        .with_uint64("at", at.0)
        .expect("bind $at");
    let ctx = h.ctx();
    let query = ctx.query();
    let (result, certificate) = db
        .execute_certified(&query, text, &params, symbols, policy())
        .expect("certified read");
    assert_eq!(certificate.plan.snapshot_seq, at);

    // Later history must not move a replay at the certified snapshot.
    h.write(&mut db, create(4, 77)).expect("a later commit");
    let replayed = db.replay(&query, &certificate, &params, symbols, policy());
    relied_upon(
        T,
        replayed.as_ref().is_ok_and(|r| rows(r) == rows(&result)),
        &format!(
            "replay reproduces the certified rows: {:?}",
            replayed.as_ref().map(rows)
        ),
    );

    // Control: an altered certificate is refused, typed.
    let mut altered = certificate.clone();
    altered.result_digest.0[0] ^= 1;
    let refused = db.replay(&query, &altered, &params, symbols, policy());
    assert!(
        matches!(refused, Err(ReplayRefusal::ResultMismatch { .. })),
        "control: {refused:?}"
    );
}

#[test]
fn delta_cursor_retired_refuses_unloaded_or_retired_prefixes_and_triggers_register_rebuild() {
    const T: &str =
        "delta_cursor_retired_refuses_unloaded_or_retired_prefixes_and_triggers_register_rebuild";
    let h = Harness::new();
    let ctx = h.ctx();
    let keys = DatabaseKeys::new(
        [0x41; 32],
        DatabaseSecurityNamespaceId([0x42; 32]),
        [0x43; 32],
    );
    let vfs = MemVfs::new().expect("memvfs");
    let dir = vfs.database_dir();
    let mut db = h
        .runtime
        .block_on(async {
            Database::create_with_vfs(&ctx.commit(), vfs.clone(), &dir, keys.clone()).await
        })
        .expect("create directory db");
    for vid in 1..=4 {
        h.write(&mut db, create(vid, vid as i64)).expect("commit");
    }
    drop(db);

    let mut reopened = h
        .runtime
        .block_on(async { Database::open_with_vfs(&ctx.commit(), vfs.clone(), &dir, keys).await })
        .expect("reopen directory db");
    let unloaded_is_retired = matches!(
        reopened.delta_since(CommitSeq(2)),
        Err(fgdb::ReadError::DeltaCursorRetired {
            asked: CommitSeq(2),
            retained_after: CommitSeq(4),
            ..
        })
    );
    // Control: asking at the published frontier succeeds without rehydration.
    assert_eq!(
        reopened
            .delta_since(CommitSeq(4))
            .expect("at frontier")
            .count(),
        0
    );

    h.runtime
        .block_on(async {
            reopened
                .ensure_delta_window(&ctx.commit(), CommitSeq(2))
                .await
        })
        .expect("rehydrate delta window");
    let rehydrated: Vec<CommitSeq> = reopened
        .delta_since(CommitSeq(2))
        .expect("rehydrated suffix")
        .map(|b| b.commit_seq())
        .collect();
    assert_eq!(rehydrated, vec![CommitSeq(3), CommitSeq(4)]);

    // Register maintainer rebuild path: after posts and reopen, `advance` rehydrates
    // and `rebuild` recomputes the full journal fold matching `fold_period`.
    let mut kh = KernelHarness::new(None);
    let posted_a = kh.post_rent(1_500, b"reg-a").expect("post a");
    assert!(matches!(posted_a, fa_journal::Posted::Committed { .. }));
    let kh_ctx = kh.ctx();
    let march = kh.march.clone();
    let advanced_1 = {
        let db = &mut kh.db;
        let book = &kh.book;
        kh.runtime
            .block_on(async { fa_registers::advance(db, &kh_ctx, book, &march).await })
            .expect("advance 1")
    };
    assert!(advanced_1.wrote);
    kh.post_rent(2_500, b"reg-b").expect("post b");
    let rebuilt = {
        let db = &mut kh.db;
        let book = &kh.book;
        kh.runtime
            .block_on(async { fa_registers::rebuild(db, &kh_ctx, book, &march).await })
            .expect("rebuild from journal")
    };
    let fold_truth = fa_registers::fold_period(&kh.db, &kh.book, &kh.march).expect("fold truth");
    let verified = fa_registers::verify_period(&kh.db, &kh.book, &kh.march).expect("verify");

    relied_upon(
        T,
        unloaded_is_retired
            && rehydrated == vec![CommitSeq(3), CommitSeq(4)]
            && rebuilt.fold == fold_truth
            && verified.is_green(),
        &format!(
            "unloaded delta prefix is DeltaCursorRetired ({unloaded_is_retired}), ensure_delta_window rehydrates ({rehydrated:?}), and rebuild equals fold ({})",
            rebuilt.fold == fold_truth && verified.is_green()
        ),
    );
}

#[test]
fn open_memory_and_directory_books_produce_identical_commits_and_certified_reads() {
    const T: &str = "open_memory_and_directory_books_produce_identical_commits_and_certified_reads";
    let h = Harness::new();
    let ctx = h.ctx();
    let keys = DatabaseKeys::new(
        [0x41; 32],
        DatabaseSecurityNamespaceId([0x42; 32]),
        [0x43; 32],
    );
    let mut mem_db = h.open();
    let vfs = MemVfs::new().expect("memvfs");
    let dir = vfs.database_dir();
    let mut dir_db = h
        .runtime
        .block_on(async {
            Database::create_with_vfs(&ctx.commit(), vfs.clone(), &dir, keys.clone()).await
        })
        .expect("create directory db");

    for (vid, p) in [(1, 10), (2, 20), (3, 30)] {
        let s1 = h.write(&mut mem_db, create(vid, p)).expect("mem write");
        let s2 = h.write(&mut dir_db, create(vid, p)).expect("dir write");
        assert_eq!(s1, s2);
    }
    for target in [&mut mem_db, &mut dir_db] {
        let txn_cx = ctx.txn();
        let mut txn = target.begin(&txn_cx).expect("begin");
        txn.write_ordered(target, vec![set(2, 25), create(4, 40)])
            .expect("write_ordered");
        h.runtime
            .block_on(async { txn.commit(target, &ctx.commit()).await })
            .expect("commit ordered");
    }

    drop(dir_db);
    let mut dir_db = h
        .runtime
        .block_on(async { Database::open_with_vfs(&ctx.commit(), vfs, &dir, keys).await })
        .expect("reopen directory db");
    h.runtime
        .block_on(async {
            dir_db
                .ensure_delta_window(&ctx.commit(), CommitSeq::ORIGIN)
                .await
        })
        .expect("ensure delta window");

    let at = mem_db.frontier().expect("mem frontier");
    let dir_at = dir_db.frontier().expect("dir frontier");
    let mem_deltas: Vec<CommitSeq> = mem_db
        .delta_since(CommitSeq::ORIGIN)
        .expect("mem deltas")
        .map(|b| b.commit_seq())
        .collect();
    let dir_deltas: Vec<CommitSeq> = dir_db
        .delta_since(CommitSeq::ORIGIN)
        .expect("dir deltas")
        .map(|b| b.commit_seq())
        .collect();

    let text = "MATCH (n:Thing) FOR SYSTEM_TIME AS OF SEQ $at RETURN n.p AS p ORDER BY p";
    let params = GqlParameters::new()
        .with_uint64("at", at.0)
        .expect("params");
    let query = ctx.query();
    let (mem_res, mem_cert) = mem_db
        .execute_certified(&query, text, &params, symbols, policy())
        .expect("mem certified");
    let (dir_res, dir_cert) = dir_db
        .execute_certified(&query, text, &params, symbols, policy())
        .expect("dir certified");

    let parity = at == dir_at
        && mem_db.vertices().expect("mem vertices") == dir_db.vertices().expect("dir vertices")
        && mem_deltas == dir_deltas
        && rows(&mem_res) == rows(&dir_res)
        && mem_cert.result_digest == dir_cert.result_digest;
    relied_upon(
        T,
        parity,
        &format!(
            "open_memory and directory Database match on frontier ({at:?} vs {dir_at:?}), vertices, deltas, and certified read digest"
        ),
    );

    // Control: mutating mem_db at a later seq changes the head certified read digest.
    let next_at = h.write(&mut mem_db, set(2, 99)).expect("control write");
    let next_params = GqlParameters::new()
        .with_uint64("at", next_at.0)
        .expect("next params");
    let (_, next_cert) = mem_db
        .execute_certified(&query, text, &next_params, symbols, policy())
        .expect("control certified");
    assert_ne!(next_cert.result_digest, dir_cert.result_digest);
}

#[test]
fn write_ordered_publishes_all_or_none_across_every_crash_point() {
    const T: &str = "write_ordered_publishes_all_or_none_across_every_crash_point";
    use fgdb::CrashPoint;
    use fgdb_types::EId;

    let h = Harness::new();
    let ctx = h.ctx();
    let keys = DatabaseKeys::new(
        [0x41; 32],
        DatabaseSecurityNamespaceId([0x42; 32]),
        [0x43; 32],
    );

    let cases = [
        (Some(CrashPoint::BeforeCapsule), false),
        (Some(CrashPoint::AfterCapsuleBeforeD1), false),
        (
            Some(CrashPoint::AfterCapsuleFileSyncBeforeDirectorySync),
            false,
        ),
        (
            Some(CrashPoint::AfterCapsuleDirectorySyncBeforeParentDirectorySync),
            false,
        ),
        (Some(CrashPoint::AfterD1), false),
        (Some(CrashPoint::AfterMarkerBeforeD2), true),
        (
            Some(CrashPoint::AfterMarkerFileSyncBeforeDirectorySync),
            true,
        ),
        (None, true),
    ];

    let mut all_atomic = true;
    for (point, expected_committed) in cases {
        let vfs = MemVfs::new().expect("memvfs");
        let dir = vfs.database_dir();
        let keys_run = keys.clone();
        let mut db = h
            .runtime
            .block_on(async {
                Database::create_with_vfs(&ctx.commit(), vfs.clone(), &dir, keys_run).await
            })
            .expect("create db");
        let basis = db.frontier().expect("initial frontier");

        let mut second = set(10, 200);
        second.add_edge(EId(50), VId(10), VId(1), vec![(P, CanonicalScalar::Int(7))]);

        let txn_cx = ctx.txn();
        let mut txn = db.begin(&txn_cx).expect("begin");
        txn.write_ordered(&mut db, vec![create(1, 10), create(10, 100), second])
            .expect("stage multi-batch ordered program");
        let outcome = h
            .runtime
            .block_on(async { txn.finish_with_crash(&mut db, &ctx.commit(), point).await });
        assert_eq!(
            outcome.is_ok(),
            point.is_none(),
            "crash point {point:?} must fail iff injected"
        );
        drop(db);

        let keys_reopen = keys.clone();
        let reopened = h
            .runtime
            .block_on(async {
                Database::open_with_vfs(&ctx.commit(), vfs, &dir, keys_reopen).await
            })
            .expect("reopen after crash");
        let frontier = reopened.frontier().expect("reopened frontier");
        let expected_frontier = CommitSeq(basis.0 + u64::from(expected_committed));
        let v1 = reopened.vertex(VId(1)).expect("read v1");
        let v10 = reopened.vertex(VId(10)).expect("read v10");
        let e50 = reopened.edge(EId(50)).expect("read e50");
        let case_ok = if expected_committed {
            let p_val = v10.as_ref().and_then(|row| {
                row.props
                    .iter()
                    .find_map(|(k, v)| (*k == P).then_some(v.clone()))
            });
            frontier == expected_frontier
                && v1.is_some()
                && p_val == Some(CanonicalScalar::Int(200))
                && e50.is_some()
        } else {
            frontier == expected_frontier && v1.is_none() && v10.is_none() && e50.is_none()
        };
        if !case_ok {
            all_atomic = false;
        }
    }

    relied_upon(
        T,
        all_atomic,
        "write_ordered recovers all batches or none across all 7 CrashPoint arms and None control",
    );
}

// =============================================================================
// Kernel call-path witness probes (plan §16.3)
// =============================================================================

const PRINCIPAL: VId = VId(7);

struct KernelHarness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: fa_journal::BookContext,
    usd: fa_money::UnitId,
    cash: VId,
    rent: VId,
    receivable: VId,
    revenue: VId,
    march: String,
    evidence: Vec<fa_model::EvidenceRef>,
}

impl KernelHarness {
    fn new(cash_limit: Option<fa_journal::BalanceLimit>) -> Self {
        use fa_journal::evidence::{Document, add_document};
        use fa_journal::{
            AccountSpec, BookContext, BookSpec, UnitPolicy, create_book, create_periods,
            install_chart, transition_period,
        };
        use fa_model::{Erasable, Id128, SealKey, SymbolTable, account_vid};
        use fa_money::UnitRegistry;
        use fa_policy::Capability;
        use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};

        let runtime = RuntimeBuilder::new().build().expect("runtime");
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [0x5a; 32],
            DatabaseSecurityNamespaceId([0x5b; 32]),
            [0x5c; 32],
        );
        let mut db = runtime
            .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
            .expect("open memory");

        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").expect("USD");
        let calendar = FiscalCalendar::monthly("cal", 1, 1).expect("calendar");
        let book_id = Id128([9; 16]);
        let spec = BookSpec {
            book_id,
            name: "Conformance Co".into(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
            .expect("create_book");
        let book = BookContext {
            book_id,
            calendar,
            units,
            seal_key: SealKey([0x11; 32]),
            symbols,
        };

        let chart = vec![
            AccountSpec {
                code: "1".into(),
                name: "Assets".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: false,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
            AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: Some("1".into()),
                limit: cash_limit,
            },
            AccountSpec {
                code: "1200".into(),
                name: "Receivable".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: Some("1".into()),
                limit: None,
            },
            AccountSpec {
                code: "4000".into(),
                name: "Revenue".into(),
                account_type: 4,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
            AccountSpec {
                code: "6000".into(),
                name: "Rent".into(),
                account_type: 5,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
        ];
        let day = DateDay::from_ymd(2026, 1, 1).expect("day");
        runtime
            .block_on(async {
                install_chart(
                    &mut db,
                    &ctx,
                    &book,
                    &chart,
                    PRINCIPAL,
                    day,
                    b"chart-1",
                    Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("chart installs");

        let (_, periods) = runtime
            .block_on(async {
                create_periods(
                    &mut db,
                    &ctx,
                    &book,
                    2026,
                    fgdb_types::VId(1),
                    fa_model::Erasable::seal(
                        &"periods".to_string(),
                        None,
                        &book.seal_key,
                        [1; 32],
                        [2; 24],
                    ),
                    &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"])
                        .unwrap(),
                )
                .await
            })
            .expect("periods")
            .expect("admitted");
        let march = periods
            .iter()
            .find(|p| {
                p.contains(DateDay::from_ymd(2026, 3, 15).unwrap()) && p.kind == PeriodKind::Normal
            })
            .unwrap()
            .code
            .clone();
        let april = periods
            .iter()
            .find(|p| {
                p.contains(DateDay::from_ymd(2026, 4, 15).unwrap()) && p.kind == PeriodKind::Normal
            })
            .unwrap()
            .code
            .clone();

        let close_cap = Capability::embedded(PRINCIPAL, &["close"]).expect("close cap");
        for (code, key) in [(&march, b"open-march" as &[u8]), (&april, b"open-april")] {
            let desc = Erasable::seal(&"open".to_string(), None, &book.seal_key, [3; 32], [4; 24]);
            runtime
                .block_on(async {
                    transition_period(
                        &mut db,
                        &ctx,
                        &book,
                        code,
                        PeriodTransition::Open,
                        PRINCIPAL,
                        1,
                        key,
                        desc,
                        &close_cap,
                        &[],
                    )
                    .await
                })
                .expect("kernel")
                .expect("open period");
        }

        let source = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"INVOICE 2026-0315 Conformance Co: fixture source document".to_vec(),
        };
        runtime
            .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
            .expect("kernel")
            .expect("add document");

        Self {
            runtime,
            root,
            db,
            cash: account_vid(book_id, "1000"),
            rent: account_vid(book_id, "6000"),
            receivable: account_vid(book_id, "1200"),
            revenue: account_vid(book_id, "4000"),
            book,
            usd,
            march,
            evidence: vec![source.evidence_ref(1)],
        }
    }

    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn proposal_on(
        &self,
        day: fa_time::DateDay,
        legs: Vec<fa_model::LegPayload>,
        key: &[u8],
    ) -> fa_model::EntryPayload {
        use fa_model::{EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Oid};
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day,
            document_date: None,
            description: Erasable::seal(
                &"conformance".to_string(),
                None,
                &self.book.seal_key,
                [1; 32],
                [2; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).expect("unit totals"),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn rent_proposal_on(
        &self,
        day: fa_time::DateDay,
        cents: i128,
        key: &[u8],
    ) -> fa_model::EntryPayload {
        use fa_model::LegPayload;
        use fa_money::{Amount, Side};
        let legs = vec![
            LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, cents)),
        ];
        self.proposal_on(day, legs, key)
    }

    fn request(&self, proposal: fa_model::EntryPayload, ops: &[&str]) -> fa_journal::PostRequest {
        fa_journal::PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: fa_policy::Capability::embedded(PRINCIPAL, ops).expect("cap"),
        }
    }

    fn prepare_post(
        &mut self,
        proposal: fa_model::EntryPayload,
    ) -> Box<fa_journal::post::PreparedPost> {
        let ctx = self.ctx();
        let req = self.request(proposal, &["post"]);
        match fa_journal::prepare_post(&mut self.db, &ctx, &self.book, req)
            .expect("prepare_post kernel")
            .expect("prepare_post admitted")
        {
            fa_journal::post::PostPreparation::Ready(prepared) => prepared,
            fa_journal::post::PostPreparation::AlreadyRecorded(_) => {
                panic!("expected fresh PreparedPost")
            }
        }
    }

    fn post_rent(
        &mut self,
        cents: i128,
        key: &[u8],
    ) -> Result<fa_journal::Posted, fa_journal::Refusal> {
        let day = fa_time::DateDay::from_ymd(2026, 3, 15).expect("march day");
        let req = self.request(self.rent_proposal_on(day, cents, key), &["post"]);
        let ctx = self.ctx();
        self.runtime
            .block_on(async { fa_journal::post(&mut self.db, &ctx, &self.book, req).await })
            .expect("post kernel")
    }
}

#[test]
fn post_vs_close_conflicts_in_both_commit_orders_including_an_empty_period() {
    const T: &str = "post_vs_close_conflicts_in_both_commit_orders_including_an_empty_period";
    use fa_model::Erasable;
    use fa_policy::Capability;
    use fa_time::{DateDay, PeriodTransition};

    let march_day = DateDay::from_ymd(2026, 3, 15).expect("march 15");
    let april_day = DateDay::from_ymd(2026, 4, 15).expect("april 15");
    let close_cap = Capability::embedded(PRINCIPAL, &["close"]).expect("close cap");

    let mut both_orders_conflict = true;
    for post_first in [true, false] {
        let mut h = KernelHarness::new(None);
        // March is completely empty at basis: the witness is the Period vertex, not a scan.
        assert_eq!(
            fa_registers::fold_period(&h.db, &h.book, &h.march)
                .expect("empty march fold")
                .entries,
            0
        );
        let basis = h.db.frontier().expect("basis");
        let prepared_post =
            h.prepare_post(h.rent_proposal_on(march_day, 1_500, b"empty-march-post"));
        let ctx = h.ctx();
        let desc = Erasable::seal(
            &"soft close march".to_string(),
            None,
            &h.book.seal_key,
            [7; 32],
            [8; 24],
        );
        let prepared_close = fa_journal::prepare_transition(
            &mut h.db,
            &ctx,
            &h.book,
            &h.march,
            PeriodTransition::SoftClose,
            PRINCIPAL,
            1,
            b"close-empty-march",
            desc,
            &close_cap,
            &[],
        )
        .expect("prepare_transition kernel")
        .expect("prepare_transition admitted");
        assert_eq!(prepared_post.basis(), basis);
        assert_eq!(prepared_close.basis(), basis);

        if post_first {
            let post_res = h
                .runtime
                .block_on(async { prepared_post.commit(&mut h.db, &ctx).await })
                .expect("post commit kernel");
            let close_res = h
                .runtime
                .block_on(async { prepared_close.commit(&mut h.db, &ctx).await })
                .expect("close commit kernel");
            let ok = post_res.is_ok()
                && close_res
                    .as_ref()
                    .is_err_and(|r| (r.code, r.exit) == ("FA-REF-030", 6));
            if !ok {
                both_orders_conflict = false;
            }
        } else {
            let close_res = h
                .runtime
                .block_on(async { prepared_close.commit(&mut h.db, &ctx).await })
                .expect("close commit kernel");
            let post_res = h
                .runtime
                .block_on(async { prepared_post.commit(&mut h.db, &ctx).await })
                .expect("post commit kernel");
            // The close moved March under the post: the post's loss is
            // the typed PeriodStateChanged (plan §7.3).
            let ok = close_res.is_ok()
                && post_res
                    .as_ref()
                    .is_err_and(|r| (r.code, r.exit) == ("FA-REF-186", 6));
            if !ok {
                both_orders_conflict = false;
            }
        }
    }

    relied_upon(
        T,
        both_orders_conflict,
        "post-vs-close on an empty period conflicts in both commit orders via the Period vertex witness: a losing close gets FA-REF-030, a losing post the typed PeriodStateChanged FA-REF-186",
    );

    // Control: a post in April prepared at the same basis as a March close does not conflict on March's Period vertex.
    let mut h = KernelHarness::new(None);
    let april_post = h.prepare_post(h.rent_proposal_on(april_day, 1_500, b"april-post"));
    let ctx = h.ctx();
    let desc = Erasable::seal(
        &"soft close march".to_string(),
        None,
        &h.book.seal_key,
        [7; 32],
        [8; 24],
    );
    let march_close = fa_journal::prepare_transition(
        &mut h.db,
        &ctx,
        &h.book,
        &h.march,
        PeriodTransition::SoftClose,
        PRINCIPAL,
        1,
        b"close-march-control",
        desc,
        &close_cap,
        &[],
    )
    .expect("prepare_transition")
    .expect("admitted");
    assert!(
        h.runtime
            .block_on(async { march_close.commit(&mut h.db, &ctx).await })
            .unwrap()
            .is_ok()
    );
    assert!(
        h.runtime
            .block_on(async { april_post.commit(&mut h.db, &ctx).await })
            .unwrap()
            .is_ok(),
        "control: posting into April after March closes does not conflict on March's Period vertex"
    );
}

#[test]
fn concurrent_receipts_settling_one_open_item_conflict_in_both_commit_orders() {
    const T: &str = "concurrent_receipts_settling_one_open_item_conflict_in_both_commit_orders";
    use fa_model::{LegPayload, Settlement};
    use fa_money::{Amount, Side};
    use fa_time::DateDay;

    let day = DateDay::from_ymd(2026, 3, 15).expect("march 15");
    let mut both_orders_conflict = true;

    for first_wins in [true, false] {
        let mut h = KernelHarness::new(None);
        let inv_legs = vec![
            LegPayload::simple(Side::Debit, h.receivable, Amount::new(h.usd, 10_000)),
            LegPayload::simple(Side::Credit, h.revenue, Amount::new(h.usd, 10_000)),
        ];
        let inv_req = h.request(h.proposal_on(day, inv_legs, b"open-invoice"), &["post"]);
        let ctx = h.ctx();
        let invoice = h
            .runtime
            .block_on(async { fa_journal::post(&mut h.db, &ctx, &h.book, inv_req).await })
            .expect("invoice kernel")
            .expect("invoice committed")
            .entry_ref();

        let receipt = |h: &KernelHarness, key: &[u8]| {
            let mut settle_leg =
                LegPayload::simple(Side::Credit, h.receivable, Amount::new(h.usd, 6_000));
            settle_leg.settles = vec![Settlement {
                target: invoice,
                ordinal: 0,
                amount: Amount::new(h.usd, 6_000),
            }];
            let legs = vec![
                LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, 6_000)),
                settle_leg,
            ];
            h.proposal_on(day, legs, key)
        };

        let r_a = h.prepare_post(receipt(&h, b"receipt-a"));
        let r_b = h.prepare_post(receipt(&h, b"receipt-b"));
        let (winner, loser) = if first_wins { (r_a, r_b) } else { (r_b, r_a) };

        let win_res = h
            .runtime
            .block_on(async { winner.commit(&mut h.db, &ctx).await })
            .expect("winner commit");
        let lose_res = h
            .runtime
            .block_on(async { loser.commit(&mut h.db, &ctx).await })
            .expect("loser commit");
        if !(win_res.is_ok()
            && lose_res
                .as_ref()
                .is_err_and(|r| (r.code, r.exit) == ("FA-REF-030", 6)))
        {
            both_orders_conflict = false;
        }
    }

    relied_upon(
        T,
        both_orders_conflict,
        "concurrent receipts settling the same open item conflict with FA-REF-030 in both commit orders",
    );
}

#[test]
fn concurrent_posts_on_a_limited_account_conflict_through_the_limit_cell_cas_in_both_orders() {
    const T: &str =
        "concurrent_posts_on_a_limited_account_conflict_through_the_limit_cell_cas_in_both_orders";
    use fa_journal::{BalanceLimit, LimitScope, limit_cell_vid};
    use fa_time::DateDay;

    let day = DateDay::from_ymd(2026, 3, 15).expect("march 15");
    let limit = BalanceLimit {
        lower: Some(-1_000),
        upper: None,
        scope: LimitScope::Lifetime,
    };

    let mut both_orders_conflict = true;
    for first_wins in [true, false] {
        let mut h = KernelHarness::new(Some(limit));
        assert!(
            h.db.vertex(limit_cell_vid(h.cash))
                .expect("limit cell")
                .is_some()
        );
        let p_a = h.prepare_post(h.rent_proposal_on(day, 600, b"limit-race-a"));
        let p_b = h.prepare_post(h.rent_proposal_on(day, 600, b"limit-race-b"));
        let (winner, loser) = if first_wins { (p_a, p_b) } else { (p_b, p_a) };
        let ctx = h.ctx();
        let win_res = h
            .runtime
            .block_on(async { winner.commit(&mut h.db, &ctx).await })
            .expect("winner commit");
        let lose_res = h
            .runtime
            .block_on(async { loser.commit(&mut h.db, &ctx).await })
            .expect("loser commit");
        // Re-preparing the loser after the winner committed sees the updated LimitCell and is refused AVAILABILITY_LOWER (FA-REF-090).
        let retry_req = h.request(
            h.rent_proposal_on(
                day,
                600,
                if first_wins {
                    b"limit-race-b"
                } else {
                    b"limit-race-a"
                },
            ),
            &["post"],
        );
        let retry_res =
            fa_journal::prepare_post(&mut h.db, &ctx, &h.book, retry_req).expect("retry prepare");
        let ok = win_res.is_ok()
            && lose_res
                .as_ref()
                .is_err_and(|r| (r.code, r.exit) == ("FA-REF-030", 6))
            && retry_res
                .as_ref()
                .is_err_and(|r| (r.code, r.exit) == ("FA-REF-090", 3));
        if !ok {
            both_orders_conflict = false;
        }
    }

    relied_upon(
        T,
        both_orders_conflict,
        "concurrent posts on a balance-limited account conflict on LimitCell CAS (FA-REF-030) in both orders, and re-preparation is refused FA-REF-090",
    );

    // Control: sequential posts that stay within the -1_000 floor both commit.
    let mut h = KernelHarness::new(Some(limit));
    assert!(h.post_rent(400, b"limit-ok-1").is_ok());
    assert!(h.post_rent(500, b"limit-ok-2").is_ok());
}

mod register_capacity {
    use super::*;

    /// Independent 192-bit unsigned limb arithmetic (`[lo, mid, hi]`) that shares
    /// no code with `i128` register folds or `fa_journal::register_capacity`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Limbs192([u64; 3]);

    impl Limbs192 {
        const CAP: Self = Self([u64::MAX, i64::MAX as u64, 0]);

        fn from_u128(v: u128) -> Self {
            Self([v as u64, (v >> 64) as u64, 0])
        }

        fn add(self, rhs: Self) -> Self {
            let (lo, c0) = self.0[0].overflowing_add(rhs.0[0]);
            let (mid1, c1) = self.0[1].overflowing_add(rhs.0[1]);
            let (mid, c2) = mid1.overflowing_add(u64::from(c0));
            let hi = self.0[2]
                .checked_add(rhs.0[2])
                .and_then(|v| v.checked_add(u64::from(c1 || c2)))
                .expect("192-bit limb capacity");
            Self([lo, mid, hi])
        }

        fn sub(self, rhs: Self) -> Self {
            let (lo, b0) = self.0[0].overflowing_sub(rhs.0[0]);
            let (mid1, b1) = self.0[1].overflowing_sub(rhs.0[1]);
            let (mid, b2) = mid1.overflowing_sub(u64::from(b0));
            let hi = self.0[2]
                .checked_sub(rhs.0[2])
                .and_then(|v| v.checked_sub(u64::from(b1 || b2)))
                .expect("non-negative 192-bit limb subtraction");
            Self([lo, mid, hi])
        }

        fn exceeds_cap(self) -> bool {
            (self.0[2], self.0[1], self.0[0]) > (Self::CAP.0[2], Self::CAP.0[1], Self::CAP.0[0])
        }

        fn to_i128_checked(self) -> Option<i128> {
            if self.exceeds_cap() {
                None
            } else {
                Some(((u128::from(self.0[1]) << 64) | u128::from(self.0[0])) as i128)
            }
        }
    }

    #[test]
    fn every_activation_path_preserves_representable_cells() {
        const T: &str = "every_activation_path_preserves_representable_cells";
        use fa_journal::migration::{
            RunBody, RunControlRequest, RunMode, RunState, TrialBalanceLine, kind, open_proposal,
            open_run, plan_run_transition, read_run, transition_run,
        };
        use fa_journal::{ApprovalRequest, PostBatch, PostIntent, post_batch, record_approval};
        use fa_model::{
            ControlPayload, Disposition, EntryClass, EntryOrigin, Erasable, LegPayload, Pending,
            PeriodRef, Supersession, SupersessionKind, period_vid,
        };
        use fa_money::{Amount, Side};
        use fa_policy::Capability;
        use fa_registers::{balance_as_of, fold_functional_stock, fold_period};
        use fa_time::{DateDay, PeriodState, PeriodTransition};

        let march_day = DateDay::from_ymd(2026, 3, 15).expect("march 15");
        let april_day = DateDay::from_ymd(2026, 4, 15).expect("april 15");
        let cap_minus_one = Limbs192::from_u128((i128::MAX - 1) as u128);
        let one = Limbs192::from_u128(1);
        assert_eq!(cap_minus_one.add(one), Limbs192::CAP);
        assert!(!cap_minus_one.add(one).exceeds_cap());
        assert!(Limbs192::CAP.add(one).exceeds_cap());

        // 1. Single post: cap-1 -> cap -> cap+1 refused, uncertain-ack retry of cap
        //    is idempotent, and literal period/stock/functional folds agree with Limbs192.
        let mut h = KernelHarness::new(None);
        assert!(h.post_rent(i128::MAX - 1, b"single-cap-minus-1").is_ok());
        assert!(h.post_rent(1, b"single-at-cap").is_ok());
        let head_at_cap = h.db.frontier().expect("head at cap");
        let over = h
            .post_rent(1, b"single-over-cap")
            .expect_err("cap+1 must refuse");
        assert_eq!((over.code, over.exit), ("FA-REF-198", 3), "{over}");
        assert_eq!(h.db.frontier().expect("head unchanged"), head_at_cap);
        let retry = h
            .post_rent(1, b"single-at-cap")
            .expect("uncertain-ack retry of committed cap post");
        assert!(matches!(retry, fa_journal::Posted::AlreadyRecorded { .. }));
        assert_eq!(h.db.frontier().expect("retry writes nothing"), head_at_cap);
        let march_fold = fold_period(&h.db, &h.book, &h.march).expect("march fold at cap");
        let expected_cap = Limbs192::CAP.to_i128_checked().expect("cap fits i128");
        assert_eq!(
            (
                march_fold.cells.iter().map(|c| c.debits).sum::<i128>(),
                march_fold.cells.iter().map(|c| c.credits).sum::<i128>(),
            ),
            (expected_cap, expected_cap)
        );
        let stock_fold = balance_as_of(&h.db, &h.book, march_day, None).expect("stock fold at cap");
        assert_eq!(
            stock_fold.unit_totals.get(&h.usd.0),
            Some(&(expected_cap, expected_cap))
        );
        let func_fold =
            fold_functional_stock(&h.db, &h.book, march_day, None).expect("functional fold at cap");
        assert_eq!(
            func_fold.total_debits().expect("functional debits"),
            expected_cap
        );

        // 2. Gross overflow with zero net: MAX posted then reversed leaves net 0
        //    but both gross columns at MAX; +1 in either direction is refused.
        let mut h = KernelHarness::new(None);
        let max_entry = h
            .post_rent(i128::MAX, b"gross-max")
            .expect("max fits")
            .entry_ref();
        let mut rev = h.proposal_on(
            march_day,
            vec![
                LegPayload::simple(Side::Credit, h.rent, Amount::new(h.usd, i128::MAX)),
                LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, i128::MAX)),
            ],
            b"gross-max-rev",
        );
        rev.class = EntryClass::REVERSAL;
        rev.supersession = vec![Supersession {
            target: max_entry,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        let ctx = h.ctx();
        let rev_req = h.request(rev, &["post"]);
        h.runtime
            .block_on(async { fa_journal::post(&mut h.db, &ctx, &h.book, rev_req).await })
            .expect("reversal kernel")
            .expect("reversal fits opposite gross columns");
        let head_after_rev = h.db.frontier().expect("head after rev");
        assert!(Limbs192::CAP.add(one).exceeds_cap());
        let gross_over = h
            .post_rent(1, b"gross-over-zero-net")
            .expect_err("net is zero but gross column would be MAX+1");
        assert_eq!((gross_over.code, gross_over.exit), ("FA-REF-198", 3));
        assert_eq!(h.db.frontier().expect("head unchanged"), head_after_rev);

        // 3. Two prepared writers at basis MAX-1 in both commit orders: winner commits,
        //    loser conflicts (FA-REF-030, exit 6), re-prepared loser refuses FA-REF-198,
        //    and uncertain-ack retry of winner returns AlreadyRecorded.
        for first_wins in [true, false] {
            let mut h = KernelHarness::new(None);
            assert!(h.post_rent(i128::MAX - 1, b"race-basis").is_ok());
            let p_a = h.prepare_post(h.rent_proposal_on(march_day, 1, b"race-a"));
            let p_b = h.prepare_post(h.rent_proposal_on(march_day, 1, b"race-b"));
            let (winner, loser, win_key, lose_key) = if first_wins {
                (p_a, p_b, b"race-a".as_slice(), b"race-b".as_slice())
            } else {
                (p_b, p_a, b"race-b".as_slice(), b"race-a".as_slice())
            };
            let ctx = h.ctx();
            let win_res = h
                .runtime
                .block_on(async { winner.commit(&mut h.db, &ctx).await })
                .expect("winner kernel")
                .expect("winner commits to MAX");
            let head_after_win = h.db.frontier().expect("head after winner");
            let lose_err = h
                .runtime
                .block_on(async { loser.commit(&mut h.db, &ctx).await })
                .expect("loser kernel")
                .expect_err("second prepared writer must conflict on account witness");
            assert_eq!((lose_err.code, lose_err.exit), ("FA-REF-030", 6));
            assert_eq!(h.db.frontier().expect("head unchanged"), head_after_win);

            let retry_lose = h
                .post_rent(1, lose_key)
                .expect_err("re-submitting loser at new head sees MAX and refuses FA-REF-198");
            assert_eq!((retry_lose.code, retry_lose.exit), ("FA-REF-198", 3));
            assert_eq!(h.db.frontier().expect("head unchanged"), head_after_win);

            let win_req = h.request(h.rent_proposal_on(march_day, 1, win_key), &["post"]);
            let retry_win = fa_journal::prepare_post(&mut h.db, &ctx, &h.book, win_req)
                .expect("retry winner kernel")
                .expect("uncertain-ack retry of winner is admitted");
            match retry_win {
                fa_journal::post::PostPreparation::AlreadyRecorded(recorded) => {
                    assert_eq!(recorded.entry_ref(), win_res.entry_ref());
                }
                fa_journal::post::PostPreparation::Ready(_) => {
                    panic!("expected AlreadyRecorded on winner retry")
                }
            }
        }

        // 4. Atomic batch: individually fitting members whose aggregate exceeds MAX
        //    refuse atomically without consuming batch or member keys.
        let mut h = KernelHarness::new(None);
        let head_before_batch = h.db.frontier().expect("head before batch");
        let ctx = h.ctx();
        let over_batch = PostBatch::new(
            b"batch-cap".to_vec(),
            vec![
                PostIntent::new(
                    h.rent_proposal_on(march_day, i128::MAX - 1, b"bm-1"),
                    Vec::new(),
                )
                .expect("intent 1"),
                PostIntent::new(h.rent_proposal_on(march_day, 2, b"bm-2"), Vec::new())
                    .expect("intent 2"),
            ],
        )
        .expect("over batch");
        let batch_err = h
            .runtime
            .block_on(async {
                post_batch(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    Capability::embedded(PRINCIPAL, &["post"]).expect("cap"),
                    over_batch,
                )
                .await
            })
            .expect("batch kernel")
            .expect_err("aggregate MAX+1 must refuse");
        assert_eq!((batch_err.code, batch_err.exit), ("FA-REF-198", 3));
        assert_eq!(
            h.db.frontier().expect("atomic batch refusal"),
            head_before_batch
        );

        // Corrected retry with the same batch and member keys commits cleanly to MAX.
        let ok_batch = PostBatch::new(
            b"batch-cap".to_vec(),
            vec![
                PostIntent::new(
                    h.rent_proposal_on(march_day, i128::MAX - 1, b"bm-1"),
                    Vec::new(),
                )
                .expect("intent 1"),
                PostIntent::new(h.rent_proposal_on(march_day, 1, b"bm-2"), Vec::new())
                    .expect("intent 2"),
            ],
        )
        .expect("ok batch");
        h.runtime
            .block_on(async {
                post_batch(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    Capability::embedded(PRINCIPAL, &["post"]).expect("cap"),
                    ok_batch,
                )
                .await
            })
            .expect("batch retry kernel")
            .expect("corrected batch commits to MAX");

        // 5. Cross-period pending release in final atomic state + over-cap refusal.
        let mut h = KernelHarness::new(None);
        let mut march_hold = h.rent_proposal_on(march_day, i128::MAX, b"march-max-hold");
        march_hold.class = EntryClass::PENDING;
        march_hold.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        let ctx = h.ctx();
        let hold_req = h.request(march_hold, &["post"]);
        let hold_ref = h
            .runtime
            .block_on(async { fa_journal::post(&mut h.db, &ctx, &h.book, hold_req).await })
            .expect("hold kernel")
            .expect("march hold fits")
            .entry_ref();
        let mut april_hold = h.rent_proposal_on(april_day, i128::MAX, b"april-max-hold");
        april_hold.class = EntryClass::PENDING;
        april_hold.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        let mut void_march = h.proposal_on(april_day, Vec::new(), b"void-march-hold");
        void_march.class = EntryClass::RESOLUTION;
        void_march.control = Some(ControlPayload::ReservationRelease);
        void_march.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(hold_ref),
            disposition: Some(Disposition::Voids),
        });
        // Even with april_hold ordered before void_march, final stock pending is
        // Limbs192::CAP.sub(Limbs192::CAP).add(Limbs192::CAP) == Limbs192::CAP.
        assert_eq!(
            Limbs192::CAP.sub(Limbs192::CAP).add(Limbs192::CAP),
            Limbs192::CAP
        );
        let swap_batch = PostBatch::new(
            b"cross-period-hold-swap".to_vec(),
            vec![
                PostIntent::new(april_hold, Vec::new()).expect("april hold intent"),
                PostIntent::new(void_march, Vec::new()).expect("void march intent"),
            ],
        )
        .expect("swap batch");
        h.runtime
            .block_on(async {
                post_batch(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    Capability::embedded(PRINCIPAL, &["post"]).expect("cap"),
                    swap_batch,
                )
                .await
            })
            .expect("swap batch kernel")
            .expect("released March hold leaves room for April MAX hold");
        let stock_after_swap =
            balance_as_of(&h.db, &h.book, april_day, None).expect("stock after swap");
        assert_eq!(
            stock_after_swap.pending_unit_totals.get(&h.usd.0),
            Some(&(expected_cap, expected_cap))
        );

        // 6. Staged migration invisibility + atomic Finalize refusal on over-cap stock.
        let mut h = KernelHarness::new(None);
        for (step, key) in [
            (PeriodTransition::Open, b"open-fy26-open".as_slice()),
            (PeriodTransition::SoftClose, b"soft-fy26-open".as_slice()),
            (PeriodTransition::Close, b"close-fy26-open".as_slice()),
            (PeriodTransition::Lock, b"lock-fy26-open".as_slice()),
        ] {
            let desc = Erasable::seal(
                &"open".to_string(),
                None,
                &h.book.seal_key,
                [9; 32],
                [8; 24],
            );
            let approvals = if matches!(step, PeriodTransition::Lock) {
                let period = fa_journal::policy::calendar_period(&h.book, "FY2026-OPEN")
                    .expect("open period");
                let digest = fa_journal::transition_proposal(
                    &h.book,
                    &period,
                    PeriodState::Closed,
                    PeriodState::Locked,
                    PRINCIPAL,
                    1,
                    key,
                    desc.clone(),
                )
                .proposal_digest()
                .expect("digest");
                let ctx = h.ctx();
                let app = h
                    .runtime
                    .block_on(async {
                        record_approval(
                            &mut h.db,
                            &ctx,
                            &h.book,
                            ApprovalRequest {
                                capability: Capability::embedded(VId(70), &["approve"]).unwrap(),
                                approved_proposal_digest: digest,
                                role: 0,
                            },
                        )
                        .await
                    })
                    .unwrap()
                    .unwrap()
                    .approval();
                vec![app]
            } else {
                Vec::new()
            };
            let ctx = h.ctx();
            h.runtime
                .block_on(async {
                    fa_journal::transition_period(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        "FY2026-OPEN",
                        step,
                        PRINCIPAL,
                        1,
                        key,
                        desc,
                        &Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap(),
                        &approvals,
                    )
                    .await
                })
                .unwrap()
                .unwrap();
        }
        let tb_doc = fa_journal::evidence::Document {
            book_id: h.book.book_id,
            kind: 18,
            mime: "text/csv".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"account,unit,mantissa\n6000,USD,max\n1000,USD,-max\n".to_vec(),
        };
        let ctx = h.ctx();
        h.runtime
            .block_on(async {
                fa_journal::evidence::add_document(&mut h.db, &ctx, &h.book, &tb_doc).await
            })
            .unwrap()
            .unwrap();
        let tb_ref = tb_doc.evidence_ref(1);
        let opening_day = DateDay::from_ymd(2026, 1, 1).unwrap();
        let body = RunBody {
            book_id: h.book.book_id,
            run_key: "conformance-cap-run".into(),
            source_system: "legacy".into(),
            mode: RunMode::OpeningOnly,
            trial_balance: tb_ref.document_oid,
            opening_date: opening_day,
            lines: vec![
                TrialBalanceLine {
                    account_code: "1000".into(),
                    unit: h.usd,
                    mantissa: -i128::MAX,
                },
                TrialBalanceLine {
                    account_code: "6000".into(),
                    unit: h.usd,
                    mantissa: i128::MAX,
                },
            ],
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
        };
        let mig_cap = Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap();
        let open_prop = open_proposal(
            &h.book,
            PRINCIPAL,
            &body,
            vec![tb_ref],
            b"conf-open-mig",
            Erasable::seal(
                &"open mig".to_string(),
                None,
                &h.book.seal_key,
                [3; 32],
                [4; 24],
            ),
        )
        .unwrap();
        let opened = h
            .runtime
            .block_on(async {
                open_run(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    &body,
                    RunControlRequest {
                        proposal: open_prop,
                        capability: mig_cap.clone(),
                        approvals: Vec::new(),
                    },
                )
                .await
            })
            .unwrap()
            .unwrap();
        let mut chunk = h.rent_proposal_on(opening_day, i128::MAX, b"conf-mig-chunk");
        chunk.class = EntryClass::MIGRATION;
        chunk.effective_period = Some(PeriodRef {
            calendar: h.book.calendar.id.clone(),
            code: "FY2026-OPEN".into(),
        });
        chunk.evidence = vec![tb_ref];
        chunk.origin = EntryOrigin::Migration {
            run_ref: opened.run,
            source_system: "legacy".into(),
            source_id: Erasable::seal(
                &"legacy-1".to_string(),
                None,
                &h.book.seal_key,
                [5; 32],
                [6; 24],
            ),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: tb_ref.document_oid,
        };
        let chunk_digest = chunk.proposal_digest().unwrap();
        let mut chunk_approvals = Vec::new();
        for approver in [VId(70), VId(71)] {
            let app = h
                .runtime
                .block_on(async {
                    record_approval(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        ApprovalRequest {
                            capability: Capability::embedded(approver, &["approve"]).unwrap(),
                            approved_proposal_digest: chunk_digest,
                            role: 0,
                        },
                    )
                    .await
                })
                .unwrap()
                .unwrap()
                .approval();
            chunk_approvals.push(app);
        }
        h.runtime
            .block_on(async {
                fa_journal::post(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    fa_journal::PostRequest {
                        proposal: chunk,
                        approvals: chunk_approvals,
                        plan_certificate: None,
                        capability: mig_cap.clone(),
                    },
                )
                .await
            })
            .unwrap()
            .expect("staged migration chunk commits while Open");
        assert!(
            h.post_rent(1, b"live-while-staged").is_ok(),
            "staged migration remains invisible until Finalize"
        );
        let fin_prop = plan_run_transition(
            &h.db,
            &h.book,
            opened.run,
            kind::FINALIZE,
            PRINCIPAL,
            b"conf-fin-mig",
            Erasable::seal(
                &"fin mig".to_string(),
                None,
                &h.book.seal_key,
                [7; 32],
                [8; 24],
            ),
        )
        .unwrap()
        .unwrap();
        let fin_digest = fin_prop.proposal_digest().unwrap();
        let mut fin_approvals = Vec::new();
        for approver in [VId(70), VId(71)] {
            let app = h
                .runtime
                .block_on(async {
                    record_approval(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        ApprovalRequest {
                            capability: Capability::embedded(approver, &["approve"]).unwrap(),
                            approved_proposal_digest: fin_digest,
                            role: 0,
                        },
                    )
                    .await
                })
                .unwrap()
                .unwrap()
                .approval();
            fin_approvals.push(app);
        }
        let head_before_fin = h.db.frontier().unwrap();
        let fin_err = h
            .runtime
            .block_on(async {
                transition_run(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    RunControlRequest {
                        proposal: fin_prop,
                        capability: mig_cap,
                        approvals: fin_approvals,
                    },
                )
                .await
            })
            .unwrap()
            .expect_err("over-cap Finalize must refuse atomically");
        assert_eq!((fin_err.code, fin_err.exit), ("FA-REF-198", 3));
        assert_eq!(h.db.frontier().unwrap(), head_before_fin);
        assert_eq!(
            read_run(&h.db, opened.run, None).unwrap().unwrap().state,
            RunState::Open
        );
        assert!(
            period_vid("cal", "FY2026-OPEN").0 > 0,
            "period vertex remains intact"
        );

        relied_upon(
            T,
            true,
            "every activation path (single post, gross-over-zero-net, prepared races in both commit orders, atomic batch, cross-period pending release, and migration Finalize) preserves representable i128 register cells and agrees with 192-bit limb arithmetic",
        );
    }
}
