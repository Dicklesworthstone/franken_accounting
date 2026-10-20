//! A scratch replay must preserve native closing coordinates and must never
//! turn corrupted source accounting history into clean maintenance-free facts.

use super::*;
use fa_journal::bank::{
    BankReconciliationRecorded, BankReconciliationRequest, read_bank_reconciliation_states,
    reconcile_bank_statement,
};
use fa_journal::evidence::document_vid;
use fa_journal::scratch::{SeqMap, replay_into};

const MAINTENANCE_VERTEX: VId = VId(0x7265_706c_6179_6d61_696e_7465_6e61_6e63);

struct ClosedSource {
    cash: EntryRef,
    matched: BankMatchRecorded,
    closed: BankReconciliationRecorded,
    before_close: CommitSeq,
    maintenance: CommitSeq,
}

fn closed_source(h: &mut Harness) -> ClosedSource {
    // A real native maintenance publication separates the source cash and
    // import coordinates from those produced by the old compressed replay.
    let mut maintenance = WriteBatch::new(relation::IN_BOOK);
    maintenance.create_vertex(MAINTENANCE_VERTEX, vec![label::REGISTER], vec![]);
    h.write(maintenance);
    let maintenance = h.head();
    let cash = h.entry(&[10_000], "WIRE", b"replayed-cash");
    let (import, line) = h.imported("WIRE", 10_000, b"replayed-statement");
    let request = h.request(import.clone(), line, cash, 0);
    let matched = h.confirm(&cap(CONFIRMER), request).unwrap();
    let before_close = h.head();
    let request = BankReconciliationRequest {
        import,
        predecessors: Vec::new(),
        evaluated_known_at: before_close,
    };
    let cx = h.cx();
    let closed = h
        .runtime
        .block_on(reconcile_bank_statement(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            request,
        ))
        .unwrap()
        .unwrap();
    ClosedSource {
        cash,
        matched,
        closed,
        before_close,
        maintenance,
    }
}

fn empty_target(h: &Harness) -> Database<MemVfs> {
    let cx = h.cx();
    h.runtime
        .block_on(Database::open_memory(
            &cx.commit(),
            DatabaseKeys::new([151; 32], DatabaseSecurityNamespaceId([152; 32]), [153; 32]),
        ))
        .unwrap()
}

fn replay(
    h: &mut Harness,
    target: &mut Database<MemVfs>,
    prefix: Option<CommitSeq>,
) -> Result<SeqMap, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(replay_into(&mut h.db, target, &cx, &h.book, prefix))
        .unwrap()
}

fn assert_source_refused_before_copy(h: &mut Harness, source: &ClosedSource, expected_code: &str) {
    let head = h.head();
    let mut target = empty_target(h);
    let refusal = replay(h, &mut target, None).unwrap_err();
    assert_eq!(refusal.code, expected_code);
    assert_eq!(refusal.exit, refusal::exit::VERIFICATION);
    assert_eq!(h.head(), head, "source verification never changes trunk");
    assert_eq!(
        target.frontier().unwrap(),
        CommitSeq(0),
        "corrupted original history is refused before any scratch publication"
    );
    assert!(target.vertices_at(CommitSeq(0)).unwrap().is_empty());

    // Later corruption cannot rewrite the intact source prefix. The same
    // original close remains readable when that exact prefix is replayed.
    let map = replay(h, &mut target, Some(source.closed.recorded_at)).unwrap();
    assert_eq!(map.source_prefix, source.closed.recorded_at);
    assert_eq!(target.frontier().unwrap(), source.closed.recorded_at);
    let states =
        read_bank_reconciliation_states(&target, &h.cx(), &h.book, &metadata_cap(OWNER), None)
            .unwrap()
            .unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].recorded, source.closed);
    assert!(!states[0].balance_drift && !states[0].cash_drift && !states[0].match_drift);
    assert_eq!(h.head(), head);
}

#[test]
fn reconciled_scratch_preserves_native_sequences_without_copying_maintenance_objects() {
    let mut h = Harness::new();
    let source = closed_source(&mut h);
    let mut maintenance = WriteBatch::new(relation::IN_BOOK);
    maintenance.set_vertex_property(
        MAINTENANCE_VERTEX,
        property::CODE,
        Some(CanonicalScalar::ucs_basic_text("later checkpoint").unwrap()),
    );
    h.write(maintenance);
    let head = h.head();
    let mut target = empty_target(&h);
    let map = replay(&mut h, &mut target, None).unwrap();
    assert_eq!(target.frontier().unwrap(), head);
    assert!(target.vertex(MAINTENANCE_VERTEX).unwrap().is_none());
    assert!(
        map.pairs
            .iter()
            .all(|pair| pair.source_seq == pair.scratch_seq)
    );
    assert!(
        map.pairs
            .iter()
            .all(|pair| { pair.source_seq != source.maintenance && pair.source_seq != head })
    );
    assert_eq!(
        map.translate(head),
        Some(source.closed.recorded_at),
        "the accounting-only map still floors trailing maintenance"
    );
    let states =
        read_bank_reconciliation_states(&target, &h.cx(), &h.book, &metadata_cap(OWNER), None)
            .unwrap()
            .unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].recorded, source.closed);
    assert!(!states[0].balance_drift && !states[0].cash_drift && !states[0].match_drift);

    let mut old_target = empty_target(&h);
    let old_map = replay(&mut h, &mut old_target, Some(source.before_close)).unwrap();
    assert_eq!(old_map.source_prefix, source.before_close);
    assert!(old_target.frontier().unwrap() < source.before_close);
    assert!(
        old_map
            .pairs
            .iter()
            .any(|pair| pair.scratch_seq < pair.source_seq)
    );
    assert_eq!(
        old_map.translate(source.before_close),
        Some(old_target.frontier().unwrap()),
        "a fork before the first close retains its original compressed mapping"
    );
    assert_eq!(h.head(), head);
}

#[test]
fn scratch_refuses_close_relabel_and_rewrite_even_after_exact_restoration() {
    for restore in [false, true] {
        let mut h = Harness::new();
        let source = closed_source(&mut h);
        let vid = source.closed.attestation_vid;
        let original = h.db.vertex(vid).unwrap().unwrap();
        let mut damage = WriteBatch::new(relation::ATTESTS);
        damage.set_vertex_label(vid, label::REGISTER, true);
        damage.set_vertex_property(
            vid,
            property::CODE,
            Some(CanonicalScalar::ucs_basic_text("rewritten close").unwrap()),
        );
        h.write(damage);
        if restore {
            let mut repair = WriteBatch::new(relation::ATTESTS);
            repair.set_vertex_label(vid, label::REGISTER, false);
            for (key, value) in &original.props {
                repair.set_vertex_property(vid, *key, Some(value.clone()));
            }
            h.write(repair);
            let current = h.db.vertex(vid).unwrap().unwrap();
            assert_eq!(current.labels, original.labels);
            assert_eq!(current.props, original.props);
        }
        assert_source_refused_before_copy(&mut h, &source, refusal::code::ATTESTATION_DRIFT);
    }
}

#[test]
fn scratch_refuses_cash_match_and_import_sources_hidden_as_deleted_maintenance() {
    for kind in ["cash", "confirmation", "import", "statement"] {
        let mut h = Harness::new();
        let source = closed_source(&mut h);
        let (vid, expected_code) = match kind {
            "cash" => (source.cash.vid, refusal::code::ATTESTATION_DRIFT),
            "confirmation" => (source.matched.match_vid, refusal::code::BANK_MATCH_DRIFT),
            "import" => (
                source.closed.claim.import_run,
                refusal::code::ATTESTATION_DRIFT,
            ),
            "statement" => (
                document_vid(&source.closed.claim.manifest.statement_oid),
                refusal::code::BANK_MATCH_DRIFT,
            ),
            _ => unreachable!(),
        };
        let mut relabel = WriteBatch::new(relation::IN_BOOK);
        relabel.set_vertex_label(vid, label::REGISTER, true);
        h.write(relabel);
        let mut remove = WriteBatch::new(relation::IN_BOOK);
        remove.delete_vertex(vid);
        h.write(remove);
        assert!(h.db.vertex(vid).unwrap().is_none());
        assert_source_refused_before_copy(&mut h, &source, expected_code);
    }
}

#[test]
fn scratch_refuses_a_reconciled_claim_manufactured_from_a_maintenance_birth() {
    let mut original = Harness::new();
    let source = closed_source(&mut original);
    let attestation = original
        .db
        .vertex(source.closed.attestation_vid)
        .unwrap()
        .unwrap();

    // This book has no genuine native close. Merely adding the Attestation
    // label to a maintenance birth cannot manufacture one or hide the attempt
    // from the source validation that precedes scratch filtering.
    let mut h = Harness::new();
    let intact_prefix = h.head();
    let mut create = WriteBatch::new(relation::IN_BOOK);
    create.create_vertex(attestation.vid, vec![label::REGISTER], attestation.props);
    h.write(create);
    let mut relabel = WriteBatch::new(relation::ATTESTS);
    relabel.set_vertex_label(attestation.vid, label::ATTESTATION, true);
    h.write(relabel);
    let head = h.head();
    let mut target = empty_target(&h);
    let refusal = replay(&mut h, &mut target, None).unwrap_err();
    assert_eq!(refusal.code, refusal::code::ATTESTATION_DRIFT);
    assert_eq!(target.frontier().unwrap(), CommitSeq(0));
    assert_eq!(h.head(), head);
    let map = replay(&mut h, &mut target, Some(intact_prefix)).unwrap();
    assert_eq!(map.source_prefix, intact_prefix);
    assert!(target.vertex(attestation.vid).unwrap().is_none());
}
