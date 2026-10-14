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
