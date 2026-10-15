//! Replay committed native deltas, never hand-built or reordered fixtures.
//! Coordinate order must not dictate allocation or leak maintenance edges.
#![forbid(unsafe_code)]

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::rows::prop;
use fa_journal::scratch::{SeqMap, replay_batches};
use fa_model::Id128;
use fa_model::symbols::{label, property, relation};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_delta_types::{DeltaRow, RelationId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, EId, VId};

struct Harness {
    runtime: Runtime,
    root: Cx,
    source: Database<MemVfs>,
    target: Database<MemVfs>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let source = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([91; 32], DatabaseSecurityNamespaceId([92; 32]), [93; 32]),
            ))
            .unwrap();
        let target = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([94; 32], DatabaseSecurityNamespaceId([95; 32]), [96; 32]),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            source,
            target,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn write(&mut self, writes: Vec<WriteBatch>) -> CommitSeq {
        let cx = self.cx();
        let txn_cx = cx.txn();
        let mut txn = self.source.begin(&txn_cx).unwrap();
        txn.write_ordered(&mut self.source, writes).unwrap();
        self.runtime
            .block_on(txn.commit(&mut self.source, &cx.commit()))
            .unwrap()
    }

    fn replay(&mut self) -> Result<SeqMap, fa_journal::Refusal> {
        let cx = self.cx();
        let prefix = self.source.frontier().unwrap();
        let batches: Vec<_> = self
            .source
            .delta_since(CommitSeq(0))
            .unwrap()
            .cloned()
            .collect();
        self.runtime
            .block_on(replay_batches(
                &mut self.target,
                &cx,
                Id128([97; 16]),
                prefix,
                &batches,
            ))
            .unwrap()
    }
}

fn relations() -> (RelationId, RelationId) {
    let mut ids = [relation::IN_BOOK, relation::CUSTODY_OF];
    ids.sort_by_key(|id| id.0);
    assert_ne!(ids[0], ids[1]);
    (ids[0], ids[1])
}

/// Native allocation order, including edges, independent of coordinate order.
fn births(db: &Database<MemVfs>) -> Vec<(u64, u8, u128)> {
    let mut result = Vec::new();
    for batch in db.delta_since(CommitSeq(0)).unwrap() {
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                match row {
                    DeltaRow::CreateVertex {
                        vid, birth_ordinal, ..
                    } => {
                        result.push((*birth_ordinal, 0, vid.0));
                    }
                    DeltaRow::CreateEdge {
                        eid, birth_ordinal, ..
                    } => {
                        result.push((*birth_ordinal, 1, eid.0));
                    }
                    _ => {}
                }
            }
        }
    }
    result.sort_by_key(|row| row.0);
    result
}

#[test]
fn replay_preserves_birth_order_across_coordinates_and_endpoint_dependencies() {
    let mut h = Harness::new();
    let (early, late) = relations();
    let a = VId(9002);
    let b = VId(9001);
    let edge = EId(9003);
    let mut first = WriteBatch::new(late);
    first.create_vertex(a, vec![label::ACCOUNT], vec![]);
    let mut second = WriteBatch::new(early);
    second.create_vertex(b, vec![label::ACCOUNT], vec![]);
    second.add_edge(edge, a, b, vec![]);
    let source_seq = h.write(vec![first, second]);
    let source_births = births(&h.source);
    assert_eq!(
        source_births
            .iter()
            .map(|row| (row.1, row.2))
            .collect::<Vec<_>>(),
        vec![(0, a.0), (0, b.0), (1, edge.0)],
    );

    let map = h.replay().unwrap();
    // No maintenance was omitted: both numeric and relative order agree.
    assert_eq!(births(&h.target), source_births);
    assert_eq!(map.pairs.len(), 1);
    assert_eq!(map.pairs[0].source_seq, source_seq);
    assert_eq!(
        map.translate(source_seq),
        Some(h.target.frontier().unwrap())
    );
}

#[test]
fn later_coordinate_maintenance_and_its_earlier_edges_never_enter_the_scratch() {
    let mut h = Harness::new();
    let (early, late) = relations();
    let account = VId(9101);
    let maintenance = VId(9102);
    let edge = EId(9103);
    let mut vertices = WriteBatch::new(late);
    vertices.create_vertex(account, vec![label::ACCOUNT], vec![]);
    vertices.create_vertex(maintenance, vec![label::REGISTER], vec![]);
    let mut edges = WriteBatch::new(early);
    edges.add_edge(edge, account, maintenance, vec![]);
    let accounting_seq = h.write(vec![vertices, edges]);

    // A later property move on the excluded edge is maintenance too. The
    // source is valid; replay must skip it, not operate on a missing edge.
    let mut update = WriteBatch::new(early);
    update.compare_and_set_edge_property(
        edge,
        property::CUSTODY_LEN,
        None,
        CanonicalScalar::Int(7),
        WriteMismatchPolicy::AbortWrite,
    );
    let maintenance_seq = h.write(vec![update]);
    let map = h.replay().unwrap();
    assert!(h.source.vertex(maintenance).unwrap().is_some());
    assert!(h.target.vertex(maintenance).unwrap().is_none());
    assert_eq!(
        births(&h.target)
            .iter()
            .map(|row| (row.1, row.2))
            .collect::<Vec<_>>(),
        vec![(0, account.0)],
    );
    assert_eq!(map.pairs.len(), 1);
    assert_eq!(map.pairs[0].source_seq, accounting_seq);
    assert_eq!(map.source_prefix, maintenance_seq);
    assert_eq!(
        map.translate(maintenance_seq),
        Some(map.pairs[0].scratch_seq)
    );
    assert_eq!(h.target.frontier().unwrap(), map.pairs[0].scratch_seq);
    assert!(map.is_monotone());
}

#[test]
fn accounting_property_updates_keep_their_exact_values_and_sequence_mapping() {
    let mut h = Harness::new();
    let (early, late) = relations();
    let account = VId(9201);
    let mut create = WriteBatch::new(late);
    create.create_vertex(
        account,
        vec![label::ACCOUNT],
        vec![(property::CUSTODY_LEN, CanonicalScalar::Int(1))],
    );
    let first = h.write(vec![create]);
    let mut update = WriteBatch::new(early);
    update.compare_and_set_vertex_property(
        account,
        property::CUSTODY_LEN,
        Some(CanonicalScalar::Int(1)),
        CanonicalScalar::Int(2),
        WriteMismatchPolicy::AbortWrite,
    );
    let second = h.write(vec![update]);
    let map = h.replay().unwrap();
    let source = h.source.vertex(account).unwrap().unwrap();
    let target = h.target.vertex(account).unwrap().unwrap();
    assert_eq!(
        prop(&target, property::CUSTODY_LEN),
        Some(&CanonicalScalar::Int(2))
    );
    assert_eq!(
        prop(&target, property::CUSTODY_LEN),
        prop(&source, property::CUSTODY_LEN)
    );
    assert_eq!(map.pairs.len(), 2);
    assert_eq!(map.pairs[0].source_seq, first);
    assert_eq!(map.pairs[1].source_seq, second);
    assert!(map.is_monotone());
}

#[test]
fn unsupported_accounting_removals_still_refuse_without_a_partial_commit() {
    let mut h = Harness::new();
    let (early, late) = relations();
    let account = VId(9301);
    let mut create = WriteBatch::new(late);
    create.create_vertex(
        account,
        vec![label::ACCOUNT],
        vec![(property::CUSTODY_LEN, CanonicalScalar::Int(1))],
    );
    h.write(vec![create]);
    let mut removal = WriteBatch::new(early);
    removal.set_vertex_property(account, property::CUSTODY_LEN, None);
    h.write(vec![removal]);
    let refusal = h.replay().unwrap_err();
    assert_eq!(refusal.code, "FA-REF-134");
    assert!(refusal.message.contains("property removal"));
    // Earlier complete commits remain; none of the refused commit is applied.
    let target = h.target.vertex(account).unwrap().unwrap();
    assert_eq!(
        prop(&target, property::CUSTODY_LEN),
        Some(&CanonicalScalar::Int(1))
    );
    assert_eq!(h.target.delta_since(CommitSeq(0)).unwrap().count(), 1);
}
