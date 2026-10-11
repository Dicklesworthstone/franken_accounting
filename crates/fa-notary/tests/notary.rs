//! The notary against the real in-memory substrate, with the independent
//! verifier as the oracle: every committed entry proves inclusion against a
//! journaled state that `fa-verify` accepts from the state's bytes alone; a
//! later state proves it extends an earlier one; the complete prefix is
//! verifiable and an omitted leaf is detected; an entry recorded after a
//! state cannot be proved against it; a forged state is found by
//! recomputation and blocks further checkpoints; and every byte of a proof
//! is bound.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::rows::book_root;
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload, Oid, Pending,
    SealKey, SymbolTable, Writer, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_notary::{
    AccumulatorState, Journal, StoredState, chain, checkpoint, code, latest, prove_balance,
    prove_consistency, prove_inclusion, prove_prefix, state_oid, state_vid, verify_accumulator,
};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fa_verify::{RecordCheck, VerifyError};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const PRINCIPAL: VId = VId(7);

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    rent: VId,
    utilities: VId,
    /// A real source document recorded at setup; every posting cites it
    /// (the evidence minimum). Documents are not entries, so not leaves.
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn post(&mut self, expense: VId, cents: i128, key: &[u8]) -> VId {
        self.post_on(expense, cents, key, 15, EntryClass::ORIGINAL)
    }

    /// Post `Dr expense / Cr cash` effective March `day`; the `Pending`
    /// class posts a hold, which reserves and never posts.
    fn post_on(
        &mut self,
        expense: VId,
        cents: i128,
        key: &[u8],
        day: u8,
        class: EntryClass,
    ) -> VId {
        let legs = vec![
            LegPayload::simple(Side::Debit, expense, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, cents)),
        ];
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: DateDay::from_ymd(2026, 3, day).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"expense".to_string(),
                None,
                &self.book.seal_key,
                [1; 32],
                [2; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
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
            pending: (class == EntryClass::PENDING).then_some(Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            }),
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).expect("post"),
        };
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("admitted")
            .entry_ref()
            .vid
    }

    fn checkpoint(&mut self) -> StoredState {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { checkpoint(db, &ctx, book).await })
            .expect("kernel")
            .expect("checkpoint admitted")
            .stored
    }

    fn checkpoint_refusal(&mut self) -> Refusal {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { checkpoint(db, &ctx, book).await })
            .expect("kernel")
            .expect_err("checkpoint refused")
    }

    /// Write `state` as a vertex and move the head pointer to it from
    /// `head` with the notary's own CAS — what an insider with raw store
    /// access could do. Returns its oid and the planting commit.
    fn plant_state(&mut self, state: &AccumulatorState, head: Option<Oid>) -> (Oid, CommitSeq) {
        let bytes = state.canonical_bytes().unwrap();
        let oid = state_oid(&bytes);
        let scalar = |b: Vec<u8>| CanonicalScalar::bytes(b).unwrap();
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        batch.create_vertex(
            state_vid(&oid),
            vec![label::ACCUMULATOR_STATE],
            vec![
                (property::FA_PAYLOAD, scalar(bytes)),
                (property::FA_DIGEST, scalar(oid.0.to_vec())),
            ],
        );
        batch.compare_and_set_vertex_property(
            book_root(),
            property::ACCUMULATOR_HEAD,
            head.map(|o| scalar(o.0.to_vec())),
            scalar(oid.0.to_vec()),
            WriteMismatchPolicy::AbortWrite,
        );
        self.write_raw(batch);
        (oid, self.db.frontier().unwrap())
    }

    fn write_raw(&mut self, batch: WriteBatch) {
        let ctx = self.ctx();
        self.runtime
            .block_on(async { self.db.write(&ctx.commit(), batch).await })
            .expect("plant a raw write in the real substrate");
    }
}

fn harness() -> Harness {
    harness_with(None)
}

/// The fixture book, optionally with an opening date (plan §7.2): periods
/// created before it are born Historical.
fn harness_with(opening_date: Option<DateDay>) -> Harness {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x6a; 32],
        DatabaseSecurityNamespaceId([0x6b; 32]),
        [0x6c; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([8; 16]);
    let spec = BookSpec {
        book_id,
        name: "Notary Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date,
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
    let account = |code: &str, name: &str, account_type: u8| AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    };
    let chart = vec![
        account("1000", "Cash", 1),
        account("6000", "Rent", 5),
        account("7000", "Utilities", 5),
    ];
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PRINCIPAL,
                day,
                b"chart",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
    let (_, periods) = runtime
        .block_on(async { create_periods(&mut db, &ctx, &book, 2026).await })
        .expect("periods");
    let march = periods
        .iter()
        .find(|p| {
            p.contains(DateDay::from_ymd(2026, 3, 15).unwrap()) && p.kind == PeriodKind::Normal
        })
        .unwrap()
        .code
        .clone();
    runtime
        .block_on(async {
            transition_period(
                &mut db,
                &ctx,
                &book,
                &march,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day,
                b"open",
                Erasable::seal(&"open".to_string(), None, &book.seal_key, [3; 32], [4; 24]),
                &Capability::embedded(PRINCIPAL, &["close"]).expect("close"),
                &[],
            )
            .await
        })
        .expect("kernel")
        .expect("opens");
    let source = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"INVOICE (notary fixture source document)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
        .expect("kernel")
        .expect("the fixture document is admitted");
    Harness {
        evidence: vec![source.evidence_ref(1)],
        runtime,
        root,
        db,
        cash: account_vid(book_id, "1000"),
        rent: account_vid(book_id, "6000"),
        utilities: account_vid(book_id, "7000"),
        book,
        usd,
    }
}

/// What an outsider does with a state's bytes: verify them on their own and
/// take the checkpoint they commit.
fn outsider_checkpoint(stored: &StoredState) -> fa_verify::Checkpoint {
    let state = fa_verify::verify_state(&stored.bytes).expect("the state verifies on its own");
    assert_eq!(state.oid, stored.oid.0, "the outsider derives the same oid");
    assert_eq!(state.signatures, fa_verify::Signatures::Unsigned);
    assert_eq!(
        state.prev_state_oid,
        stored.state.prev_state_oid.map(|o| o.0)
    );
    state.checkpoint
}

fn statement_bytes(s: &AccumulatorState) -> Vec<u8> {
    let mut w = Writer::new();
    s.statement().encode(&mut w);
    w.finish().unwrap()
}

#[test]
fn every_entry_proves_inclusion_against_a_journaled_state() {
    let mut h = harness();
    let posted: Vec<VId> = (0..5u8)
        .map(|i| {
            let account = if i % 2 == 0 { h.rent } else { h.utilities };
            h.post(account, 1_000 + i128::from(i), &[b'p', i])
        })
        .collect();
    let stored = h.checkpoint();
    let trusted = outsider_checkpoint(&stored);
    assert_eq!(trusted.book_id, h.book.book_id.0);
    assert_eq!(trusted.through_seq, stored.state.through_seq.0);
    assert!(stored.recorded_at > stored.state.through_seq);
    assert_eq!(stored.state.prev_state_oid, None);

    // The chart install, the March opening, and the five postings.
    let journal = Journal::read(&h.db, &h.book, Some(stored.state.through_seq))
        .unwrap()
        .unwrap();
    assert_eq!(journal.len(), 7);
    assert_eq!(trusted.leaf_count, 7);
    assert_eq!(journal.leaves[0].envelope.class, EntryClass::SCHEMA_CONTROL);
    assert_eq!(journal.leaves[0].envelope.effective_day, None);
    assert_eq!(journal.leaves[1].envelope.class, EntryClass::PERIOD_CONTROL);
    assert!(journal.leaves[1].envelope.effective_day.is_some());
    assert!(
        journal
            .leaves
            .windows(2)
            .all(|w| w[0].envelope.commit_seq < w[1].envelope.commit_seq)
    );

    for leaf in &journal.leaves {
        let proof = prove_inclusion(&h.db, &h.book, &stored.state, leaf.vid, true)
            .unwrap()
            .unwrap();
        let report = fa_verify::verify_inclusion(&proof, &trusted).expect("inclusion verifies");
        assert_eq!(report.scope, "inclusion");
        assert_eq!(report.record, RecordCheck::Recomputed);
        assert_eq!(report.envelope.encode(), leaf.envelope_bytes);
        assert_eq!(report.envelope.commit_seq, leaf.envelope.commit_seq.0);

        let bare = prove_inclusion(&h.db, &h.book, &stored.state, leaf.vid, false)
            .unwrap()
            .unwrap();
        let report = fa_verify::verify_inclusion(&bare, &trusted).unwrap();
        assert_eq!(report.record, RecordCheck::NotSupplied);
    }
    for (i, vid) in posted.iter().enumerate() {
        let leaf = &journal.leaves[journal.leaf_index(*vid).unwrap()];
        let expense = if i % 2 == 0 { h.rent } else { h.utilities };
        let mut accounts = vec![h.cash, expense];
        accounts.sort_by_key(|v| v.0);
        assert_eq!(leaf.envelope.account_vids, accounts);
        assert_eq!(leaf.envelope.unit_ids, vec![h.usd.0]);
        assert_eq!(leaf.envelope.class, EntryClass::ORIGINAL);
    }
}

/// The producer's accumulator and the verifier's are two implementations
/// that must agree on every leaf, every envelope, and the root.
#[test]
fn the_producer_and_the_independent_verifier_agree_on_every_leaf_and_the_root() {
    let mut h = harness();
    for i in 0..9u8 {
        h.post(h.rent, 100 + i128::from(i), &[b'd', i]);
    }
    let journal = Journal::read(&h.db, &h.book, None).unwrap().unwrap();
    let mut hashes = Vec::new();
    for leaf in &journal.leaves {
        assert_eq!(fa_verify::tree::leaf_hash(&leaf.envelope_bytes), leaf.hash);
        let decoded = fa_verify::LeafEnvelope::decode(&leaf.envelope_bytes).unwrap();
        assert_eq!(decoded.encode(), leaf.envelope_bytes);
        // The verifier rebuilds the envelope from the payload bytes alone.
        let rebuilt = fa_verify::envelope::envelope_of_entry(
            &leaf.payload,
            leaf.proposal_len,
            decoded.commit_seq,
            decoded.within_commit_ordinal,
        )
        .unwrap();
        assert_eq!(rebuilt, decoded);
        hashes.push(leaf.hash);
    }
    assert_eq!(fa_verify::tree::root_of(&hashes), journal.root());
    assert_eq!(fa_verify::tree::bag_peaks(&journal.peaks()), journal.root());
}

#[test]
fn a_later_state_extends_the_earlier_and_consistency_verifies() {
    let mut h = harness();
    h.post(h.rent, 500, b"a1");
    let a = h.checkpoint();
    for i in 0..3u8 {
        h.post(h.utilities, 70 + i128::from(i), &[b'b', i]);
    }
    let b = h.checkpoint();
    assert_eq!(b.state.prev_state_oid, Some(a.oid));
    assert_eq!(b.state.leaf_count, a.state.leaf_count + 3);
    assert!(b.state.through_seq >= a.recorded_at);
    let c = h.checkpoint();
    assert_eq!(c.state.prev_state_oid, Some(b.oid));
    assert_eq!(
        c.state.leaf_count, b.state.leaf_count,
        "a state is not a leaf"
    );

    let ta = outsider_checkpoint(&a);
    let tb = outsider_checkpoint(&b);
    let tc = outsider_checkpoint(&c);
    let ab = prove_consistency(&h.db, &h.book, &a.state, &b.state)
        .unwrap()
        .unwrap();
    let report = fa_verify::verify_consistency(&ab, &ta, &tb).expect("b extends a");
    assert_eq!(report.extended, tb);
    let bc = prove_consistency(&h.db, &h.book, &b.state, &c.state)
        .unwrap()
        .unwrap();
    assert_eq!(
        fa_verify::verify_consistency(&bc, &tb, &tc)
            .unwrap()
            .extended,
        tc
    );
    let ac = prove_consistency(&h.db, &h.book, &a.state, &c.state)
        .unwrap()
        .unwrap();
    assert_eq!(
        fa_verify::verify_consistency(&ac, &ta, &tc)
            .unwrap()
            .extended,
        tc
    );

    // Backwards is refused by the producer, and a proof against a state the
    // caller does not trust is refused by the verifier.
    let back = prove_consistency(&h.db, &h.book, &b.state, &a.state)
        .unwrap()
        .unwrap_err();
    assert_eq!(back.code, code::NOT_EXTENDED);
    assert!(matches!(
        fa_verify::verify_consistency(&ab, &tb, &tc),
        Err(VerifyError::NotTrusted { .. })
    ));
    // A proof to b offered as evidence for c names the wrong claim.
    assert!(matches!(
        fa_verify::verify_consistency(&ab, &ta, &tc),
        Err(VerifyError::NotClaimed { .. })
    ));
    // A claimed root that is not the extension (one flipped bit) is caught
    // even when the proof is rewritten to name it.
    let mut forged = ab.clone();
    let new_root_at = 4 + b"fa:acc-consistency-proof:v1".len() + 80 + 48;
    forged[new_root_at] ^= 1;
    let mut forged_claim = tb;
    forged_claim.root[0] ^= 1;
    assert_eq!(
        fa_verify::verify_consistency(&forged, &ta, &forged_claim),
        Err(VerifyError::Consistency)
    );

    let states = chain(&h.db).unwrap();
    assert_eq!(
        states.iter().map(|s| s.oid).collect::<Vec<_>>(),
        vec![c.oid, b.oid, a.oid]
    );
    assert_eq!(
        latest(&h.db, Some(b.recorded_at)).unwrap().unwrap().oid,
        b.oid
    );
    assert_eq!(latest(&h.db, Some(a.state.through_seq)).unwrap(), None);
}

#[test]
fn an_entry_recorded_after_the_state_is_refused_and_a_forged_proof_fails() {
    let mut h = harness();
    h.post(h.rent, 10, b"before");
    let a = h.checkpoint();
    let late = h.post(h.rent, 20, b"after");

    let refused = prove_inclusion(&h.db, &h.book, &a.state, late, true)
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::NOT_IN_PREFIX);
    assert_eq!(refused.exit, exit::REFUSAL);

    // Forge: prove the late entry against the head journal, then splice the
    // trusted state's statement over the head's. The verifier refuses on
    // the recorded sequence before it even walks the path.
    let head = Journal::read(&h.db, &h.book, None).unwrap().unwrap();
    let mut forged = head.inclusion_proof(late, true).unwrap().unwrap();
    let at = 4 + b"fa:acc-inclusion-proof:v1".len();
    forged[at..at + 80].copy_from_slice(&statement_bytes(&a.state));
    let trusted = outsider_checkpoint(&a);
    let err = fa_verify::verify_inclusion(&forged, &trusted).unwrap_err();
    assert_eq!(
        err,
        VerifyError::AfterCheckpoint {
            commit_seq: head.leaves[head.leaf_index(late).unwrap()]
                .envelope
                .commit_seq
                .0,
            through_seq: a.state.through_seq.0,
        }
    );
}

#[test]
fn the_complete_prefix_verifies_and_an_omitted_leaf_is_detected() {
    let mut h = harness();
    for i in 0..6u8 {
        let account = if i < 4 { h.rent } else { h.utilities };
        h.post(account, 300 + i128::from(i), &[b's', i]);
    }
    let a = h.checkpoint();
    let trusted = outsider_checkpoint(&a);
    let proof = prove_prefix(&h.db, &h.book, &a.state).unwrap().unwrap();
    let prefix = fa_verify::verify_prefix(&proof, &trusted).expect("complete prefix");
    assert_eq!(prefix.scope, "seq_range_complete");
    // A scope predicate over the authenticated prefix is complete: exactly
    // the four rent postings.
    let rent: Vec<_> = prefix
        .envelopes
        .iter()
        .filter(|e| e.account_vids.contains(&h.rent.0))
        .collect();
    assert_eq!(rent.len(), 4);

    let journal = Journal::read(&h.db, &h.book, Some(a.state.through_seq))
        .unwrap()
        .unwrap();
    let envelopes: Vec<Vec<u8>> = journal
        .leaves
        .iter()
        .map(|l| l.envelope_bytes.clone())
        .collect();
    let encode = |list: &[Vec<u8>]| {
        let mut w = Writer::new();
        w.bytes(b"fa:acc-prefix-proof:v1");
        a.state.statement().encode(&mut w);
        w.list(list, |w, e| {
            w.bytes(e);
        });
        w.finish().unwrap()
    };
    assert_eq!(
        encode(&envelopes),
        proof,
        "the producer's prefix proof is this list"
    );

    // Omit one in-scope leaf.
    let rent_index = journal
        .leaves
        .iter()
        .position(|l| l.envelope.account_vids.contains(&h.rent))
        .unwrap();
    let mut omitted = envelopes.clone();
    omitted.remove(rent_index);
    assert!(matches!(
        fa_verify::verify_prefix(&encode(&omitted), &trusted),
        Err(VerifyError::LeafCount { .. })
    ));
    // Omit it and pad with a duplicate to keep the count.
    let mut padded = omitted.clone();
    padded.push(envelopes[envelopes.len() - 1].clone());
    assert!(matches!(
        fa_verify::verify_prefix(&encode(&padded), &trusted),
        Err(VerifyError::Order { .. })
    ));
    // Reorder two leaves.
    let mut swapped = envelopes.clone();
    swapped.swap(2, 3);
    assert!(matches!(
        fa_verify::verify_prefix(&encode(&swapped), &trusted),
        Err(VerifyError::Order { .. })
    ));
    // Re-point an in-scope leaf at another account: the root catches it.
    let mut altered = envelopes.clone();
    let mut env = fa_verify::LeafEnvelope::decode(&altered[rent_index]).unwrap();
    env.account_vids = vec![h.cash.0.min(h.utilities.0), h.cash.0.max(h.utilities.0)];
    altered[rent_index] = env.encode();
    assert_eq!(
        fa_verify::verify_prefix(&encode(&altered), &trusted),
        Err(VerifyError::Root)
    );
}

#[test]
fn recomputation_finds_a_forged_state_and_blocks_checkpoints_over_it() {
    let mut h = harness();
    h.post(h.rent, 40, b"x1");
    let a = h.checkpoint();
    h.post(h.rent, 41, b"x2");
    let b = h.checkpoint();
    let green = verify_accumulator(&h.db, &h.book).unwrap();
    assert!(green.is_green(), "{green:?}");
    assert_eq!(green.states.len(), 2);

    // Plant a state whose root is not the journal's, chained from b and
    // installed as the head — what an insider rewriting history would do.
    let head = Journal::read(&h.db, &h.book, None).unwrap().unwrap();
    let mut forged = AccumulatorState::of_journal(&head, Some(b.oid));
    forged.root[0] ^= 1;
    let bytes = forged.canonical_bytes().unwrap();
    let oid = state_oid(&bytes);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(
        state_vid(&oid),
        vec![label::ACCUMULATOR_STATE],
        vec![
            (property::FA_PAYLOAD, CanonicalScalar::bytes(bytes).unwrap()),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(oid.0.to_vec()).unwrap(),
            ),
        ],
    );
    batch.compare_and_set_vertex_property(
        book_root(),
        property::ACCUMULATOR_HEAD,
        Some(CanonicalScalar::bytes(b.oid.0.to_vec()).unwrap()),
        CanonicalScalar::bytes(oid.0.to_vec()).unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.write_raw(batch);

    let found = verify_accumulator(&h.db, &h.book).unwrap();
    assert!(!found.is_green());
    assert!(found.states[0].finding.is_some(), "{found:?}");
    assert!(found.states[1..].iter().all(|s| s.finding.is_none()));

    let refused = h.checkpoint_refusal();
    assert_eq!(refused.code, code::ACCUMULATOR_DRIFT);
    assert_eq!(refused.exit, exit::VERIFICATION);
    let no_proof = prove_inclusion(&h.db, &h.book, &forged, head.leaves[0].vid, false)
        .unwrap()
        .unwrap_err();
    assert_eq!(no_proof.code, code::ACCUMULATOR_DRIFT);
    // The honest earlier states still prove.
    assert!(
        prove_inclusion(&h.db, &h.book, &a.state, head.leaves[0].vid, false)
            .unwrap()
            .is_ok()
    );

    // A state vertex the chain never reaches is reported too.
    let orphan = AccumulatorState::of_journal(&head, None);
    let obytes = orphan.canonical_bytes().unwrap();
    let ooid = state_oid(&obytes);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(
        state_vid(&ooid),
        vec![label::ACCUMULATOR_STATE],
        vec![(
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(obytes).unwrap(),
        )],
    );
    h.write_raw(batch);
    let found = verify_accumulator(&h.db, &h.book).unwrap();
    assert_eq!(found.unchained, vec![state_vid(&ooid)]);
}

#[test]
fn every_byte_of_an_inclusion_proof_is_bound() {
    let mut h = harness();
    for i in 0..4u8 {
        h.post(h.utilities, 900 + i128::from(i), &[b't', i]);
    }
    let a = h.checkpoint();
    let trusted = outsider_checkpoint(&a);
    let journal = Journal::read(&h.db, &h.book, Some(a.state.through_seq))
        .unwrap()
        .unwrap();
    let target = journal.leaves[3].vid;
    let proof = prove_inclusion(&h.db, &h.book, &a.state, target, true)
        .unwrap()
        .unwrap();
    fa_verify::verify_inclusion(&proof, &trusted).unwrap();
    for i in 0..proof.len() {
        for bit in [0x01u8, 0x80] {
            let mut t = proof.clone();
            t[i] ^= bit;
            assert!(
                fa_verify::verify_inclusion(&t, &trusted).is_err(),
                "byte {i} bit {bit:#x} flipped and the proof still verified"
            );
        }
    }
    let mut long = proof.clone();
    long.push(0);
    assert!(fa_verify::verify_inclusion(&long, &trusted).is_err());
    assert!(fa_verify::verify_inclusion(&proof[..proof.len() - 1], &trusted).is_err());
}

/// Tampering that breaks the chain itself — a state's bytes rewritten in
/// place, a head pointer naming nothing — is a verification finding (and a
/// checkpoint refusal with exit 8), never a read error.
#[test]
fn a_rewritten_state_or_dangling_head_is_a_finding_and_blocks_checkpoints() {
    let mut h = harness();
    h.post(h.rent, 5, b"w1");
    let a = h.checkpoint();
    h.post(h.rent, 6, b"w2");
    let b = h.checkpoint();

    // Rewrite a's payload in place: b still loads, but its predecessor is no
    // longer the object b's prev_state_oid names.
    let mut rewritten = a.state.clone();
    rewritten.leaf_count += 1;
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.set_vertex_property(
        a.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(rewritten.canonical_bytes().unwrap()).unwrap()),
    );
    h.write_raw(batch);
    let found = verify_accumulator(&h.db, &h.book).expect("a finding, not an error");
    assert!(!found.is_green());
    assert!(
        found
            .broken
            .as_deref()
            .is_some_and(|why| why.contains("does not hash to its oid")),
        "{found:?}"
    );
    assert_eq!(found.states.len(), 1);
    assert_eq!(found.states[0].oid, b.oid);
    assert!(found.states[0].finding.is_none());
    assert!(
        chain(&h.db).is_err(),
        "the strict listing refuses a broken chain"
    );

    // Point the head at nothing.
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.set_vertex_property(
        book_root(),
        property::ACCUMULATOR_HEAD,
        Some(CanonicalScalar::bytes(vec![0xee; 32]).unwrap()),
    );
    h.write_raw(batch);
    let found = verify_accumulator(&h.db, &h.book).unwrap();
    assert!(
        found
            .broken
            .as_deref()
            .is_some_and(|why| why.contains("named but absent")),
        "{found:?}"
    );
    assert!(found.states.is_empty());
    assert_eq!(
        found.unchained.len(),
        2,
        "both real states are now unreachable"
    );
    let refused = h.checkpoint_refusal();
    assert_eq!(refused.code, code::ACCUMULATOR_DRIFT);
    assert_eq!(refused.exit, exit::VERIFICATION);
}

/// WhiteCreek's predecessor review (fa-l3c): a well-hashed predecessor whose
/// root and peaks are a true prefix but whose `through_seq` is falsely
/// advanced is refused — `checkpoint()` used to publish over it although
/// verification rejects it.
#[test]
fn checkpoint_refuses_a_predecessor_with_a_falsely_advanced_sequence() {
    let mut h = harness();
    h.post(h.rent, 1, b"f1");
    let a = h.checkpoint();
    h.post(h.rent, 2, b"f2");
    h.post(h.rent, 3, b"f3");
    let mut advanced = a.state.clone();
    advanced.through_seq = h.db.frontier().unwrap();
    advanced.prev_state_oid = Some(a.oid);
    h.plant_state(&advanced, Some(a.oid));

    let found = verify_accumulator(&h.db, &h.book).unwrap();
    assert!(found.states[0].finding.is_some(), "{found:?}");
    let refused = h.checkpoint_refusal();
    assert_eq!(refused.code, code::ACCUMULATOR_DRIFT);
    assert_eq!(refused.exit, exit::VERIFICATION);
    assert!(
        refused.message.contains("not what the journal reproduces"),
        "{refused:?}"
    );
}

/// The timing half of the same review: a predecessor claiming the prefix
/// through the very commit that records it has the right counts (that
/// commit adds no entry) and is still refused, by its sequence.
#[test]
fn checkpoint_refuses_a_predecessor_that_claims_its_own_recording_commit() {
    let mut h = harness();
    h.post(h.rent, 1, b"g1");
    let a = h.checkpoint();
    let next = CommitSeq(h.db.frontier().unwrap().0 + 1);
    let journal = Journal::read(&h.db, &h.book, None).unwrap().unwrap();
    let mut early = AccumulatorState::of_journal(&journal, Some(a.oid));
    early.through_seq = next;
    let (_, recorded_at) = h.plant_state(&early, Some(a.oid));
    assert_eq!(
        recorded_at, next,
        "the plant commits at the claimed sequence"
    );
    h.post(h.rent, 2, b"g2");

    let found = verify_accumulator(&h.db, &h.book).unwrap();
    assert!(
        found.states[0]
            .finding
            .as_deref()
            .is_some_and(|f| f.contains("claims a prefix through")),
        "{found:?}"
    );
    let refused = h.checkpoint_refusal();
    assert_eq!(refused.code, code::ACCUMULATOR_DRIFT);
    assert!(
        refused.message.contains("claims a prefix through"),
        "{refused:?}"
    );
}

/// Re-encode a balance proof from its parts, so a test can plant one fault.
#[allow(clippy::too_many_arguments)]
fn balance_bytes(
    statement: &fa_notary::Statement,
    account: VId,
    unit: u32,
    through: Option<i32>,
    debits: i128,
    credits: i128,
    envelopes: &[Vec<u8>],
    records: &[(u64, u32, Vec<u8>)],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"fa:acc-balance-proof:v1");
    statement.encode(&mut w);
    w.u128(account.0)
        .u32(unit)
        .opt(through.as_ref(), |w, d| {
            w.i32(*d);
        })
        .i128(debits)
        .i128(credits)
        .list(envelopes, |w, e| {
            w.bytes(e);
        })
        .list(records, |w, (i, len, payload)| {
            w.u64(*i).u32(*len).bytes(payload);
        });
    w.finish().unwrap()
}

/// The balance-recomputation proof (§13.3): for every (account, unit) the
/// outsider's refold from exactly the authenticated in-scope entries equals
/// the register fold at the same known-at and cutoff — holds excluded — and
/// an omitted, extra, or altered record or a wrong claim is refused.
#[test]
fn balance_proofs_refold_exactly_the_register_balances_and_refuse_tampering() {
    let mut h = harness();
    h.post_on(h.rent, 1_000, b"m10", 10, EntryClass::ORIGINAL);
    h.post_on(h.utilities, 250, b"m12", 12, EntryClass::ORIGINAL);
    h.post_on(h.rent, 333, b"m20", 20, EntryClass::ORIGINAL);
    h.post_on(h.utilities, 7_000, b"hold", 11, EntryClass::PENDING);
    let a = h.checkpoint();
    let trusted = outsider_checkpoint(&a);
    let mid = DateDay::from_ymd(2026, 3, 15).unwrap();
    let late = DateDay::from_ymd(2026, 3, 31).unwrap();

    for cutoff in [mid, late] {
        let tb = fa_registers::balance_as_of(&h.db, &h.book, cutoff, Some(a.state.through_seq))
            .expect("register fold");
        for account in [h.cash, h.rent, h.utilities] {
            let proof = prove_balance(&h.db, &h.book, &a.state, account, h.usd.0, Some(cutoff.0))
                .unwrap()
                .unwrap();
            let report = fa_verify::verify_balance(&proof, &trusted).expect("refold matches");
            let expected = tb
                .rows
                .iter()
                .find(|r| r.account == account && r.unit_id == h.usd.0)
                .map_or((0, 0), |r| (r.debits, r.credits));
            assert_eq!((report.claim.debits, report.claim.credits), expected);
            assert_eq!(report.scope, "recomputation");
        }
    }
    // The hold reserved 7,000 against cash and utilities but posted nothing.
    let cash_all = fa_verify::verify_balance(
        &prove_balance(&h.db, &h.book, &a.state, h.cash, h.usd.0, None)
            .unwrap()
            .unwrap(),
        &trusted,
    )
    .unwrap();
    assert_eq!((cash_all.claim.debits, cash_all.claim.credits), (0, 1_583));
    assert_eq!(cash_all.contributing.len(), 3);

    // Plant one fault at a time into the honest parts.
    let journal = Journal::read(&h.db, &h.book, Some(a.state.through_seq))
        .unwrap()
        .unwrap();
    let statement = a.state.statement();
    let envelopes: Vec<Vec<u8>> = journal
        .leaves
        .iter()
        .map(|l| l.envelope_bytes.clone())
        .collect();
    let record = |i: usize| {
        let l = &journal.leaves[i];
        (
            i as u64,
            u32::try_from(l.proposal_len).unwrap(),
            l.payload.clone(),
        )
    };
    let rent = |l: &fa_notary::Leaf| {
        l.envelope.class == EntryClass::ORIGINAL && l.envelope.account_vids.contains(&h.rent)
    };
    let in_scope: Vec<usize> = (0..journal.leaves.len())
        .filter(|i| rent(&journal.leaves[*i]))
        .collect();
    assert_eq!(in_scope.len(), 2);
    let honest: Vec<_> = in_scope.iter().map(|i| record(*i)).collect();
    let make = |debits, credits, records: &[(u64, u32, Vec<u8>)]| {
        balance_bytes(
            &statement, h.rent, h.usd.0, None, debits, credits, &envelopes, records,
        )
    };
    assert_eq!(
        make(1_333, 0, &honest),
        prove_balance(&h.db, &h.book, &a.state, h.rent, h.usd.0, None)
            .unwrap()
            .unwrap(),
        "the test encoder is the producer's format"
    );
    assert!(fa_verify::verify_balance(&make(1_333, 0, &honest), &trusted).is_ok());
    assert_eq!(
        fa_verify::verify_balance(&make(1_000, 0, &honest[..1]), &trusted),
        Err(VerifyError::RecordSet {
            index: in_scope[1] as u64
        }),
        "an omitted in-scope record"
    );
    let hold_index = journal
        .leaves
        .iter()
        .position(|l| l.envelope.class == EntryClass::PENDING)
        .unwrap();
    let mut with_hold = honest.clone();
    with_hold.push(record(hold_index));
    with_hold.sort_by_key(|r| r.0);
    assert!(
        matches!(
            fa_verify::verify_balance(&make(1_333, 0, &with_hold), &trusted),
            Err(VerifyError::RecordSet { .. })
        ),
        "an extra record (a hold) is not admitted"
    );
    assert_eq!(
        fa_verify::verify_balance(&make(1_334, 0, &honest), &trusted),
        Err(VerifyError::Claim {
            debits: 1_333,
            credits: 0
        }),
        "a wrong claim is refused with the refold"
    );
    let mut altered = honest.clone();
    let n = altered[0].2.len();
    altered[0].2[n / 3] ^= 1;
    assert!(
        matches!(
            fa_verify::verify_balance(&make(1_333, 0, &altered), &trusted),
            Err(VerifyError::Record(_))
        ),
        "an altered record"
    );
    let mut swapped = honest.clone();
    swapped[0].2 = record(hold_index).2;
    swapped[0].1 = record(hold_index).1;
    assert!(
        matches!(
            fa_verify::verify_balance(&make(1_333, 0, &swapped), &trusted),
            Err(VerifyError::Record(_))
        ),
        "another entry's record under an in-scope index"
    );
}

fn approve_two(h: &mut Harness, digest: [u8; 32]) -> Vec<fa_model::ApprovalRef> {
    [VId(8), VId(9)]
        .into_iter()
        .map(|who| {
            let ctx = h.ctx();
            let db = &mut h.db;
            let book = &h.book;
            let req = ApprovalRequest {
                capability: Capability::embedded(who, &["approve"]).unwrap(),
                approved_proposal_digest: digest,
                role: 0,
            };
            h.runtime
                .block_on(async move { record_approval(db, &ctx, book, req).await })
                .expect("kernel")
                .expect("approved")
                .approval()
        })
        .collect()
}

/// fa-xo0 interim (ruling 3243): the accumulator keeps a staged migration
/// chunk (it is journaled), but a balance proof never counts it — the
/// register fold does not, and `fa-verify` cannot yet see the run — so a
/// proof touching a staged chunk's account refuses FA-REF-133 while every
/// other account proves; once the run's Finalize is in the prefix, the same
/// account proves and verifies, and the earlier prefix still refuses.
#[test]
fn a_staged_migration_chunk_blocks_its_balance_proof_until_the_run_finalizes() {
    let mut h = harness();
    let opening = DateDay::from_ymd(2026, 1, 1).unwrap();
    let sealed = |h: &Harness, text: &str| {
        Erasable::seal(&text.to_string(), None, &h.book.seal_key, [5; 32], [6; 24])
    };
    for (i, t) in [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
        PeriodTransition::Lock,
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("opening-{i}");
        let desc = |h: &Harness| {
            Erasable::seal(
                &"opening".to_string(),
                None,
                &h.book.seal_key,
                [3; 32],
                [4; 24],
            )
        };
        // Lock is dual-controlled (sod_policy.toml): the approvers approve
        // exactly the proposal this transition commits (Lock is legal only
        // from Closed).
        let approvals = if matches!(t, PeriodTransition::Lock) {
            let digest = transition_proposal(
                &h.book,
                "FY2026-OPEN",
                PeriodState::Closed,
                PeriodState::Locked,
                PRINCIPAL,
                1,
                opening,
                key.as_bytes(),
                desc(&h),
            )
            .proposal_digest()
            .unwrap();
            approve_two(&mut h, digest)
        } else {
            Vec::new()
        };
        let desc = desc(&h);
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move {
                transition_period(
                    db,
                    &ctx,
                    book,
                    "FY2026-OPEN",
                    t,
                    PRINCIPAL,
                    1,
                    opening,
                    key.as_bytes(),
                    desc,
                    &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
                    &approvals,
                )
                .await
            })
            .expect("kernel")
            .expect("transition");
    }
    let preparer = Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap();

    // Open a run over cash and rent: Dr cash 5,000 / Cr rent 5,000.
    let body = RunBody {
        book_id: h.book.book_id,
        run_key: "go-live".into(),
        source_system: "legacy-gl".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: h.evidence[0].document_oid,
        opening_date: opening,
        lines: vec![
            TrialBalanceLine {
                account_code: "1000".into(),
                unit: h.usd,
                mantissa: 5_000,
            },
            TrialBalanceLine {
                account_code: "6000".into(),
                unit: h.usd,
                mantissa: -5_000,
            },
        ],
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let proposal = open_proposal(
        &h.book,
        PRINCIPAL,
        &body,
        vec![h.evidence[0]],
        b"open-run",
        sealed(&h, "open"),
    )
    .unwrap();
    let req = RunControlRequest {
        proposal,
        capability: preparer.clone(),
        approvals: Vec::new(),
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    let run = h
        .runtime
        .block_on(async move { open_run(db, &ctx, book, &body, req).await })
        .expect("kernel")
        .expect("opened")
        .run;

    // The chunk: staged, invisible.
    let legs = vec![
        LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, 5_000)),
        LegPayload::simple(Side::Credit, h.rent, Amount::new(h.usd, 5_000)),
    ];
    let chunk = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: h.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::MIGRATION,
        effective_date: opening,
        document_date: None,
        description: sealed(&h, "opening balances"),
        effective_period: Some(fa_model::PeriodRef {
            calendar: h.book.calendar.id.clone(),
            code: "FY2026-OPEN".into(),
        }),
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"chunk-0".to_vec(),
        origin: EntryOrigin::Migration {
            run_ref: run,
            source_system: "legacy-gl".into(),
            source_id: sealed(&h, "JE-1"),
            source_recorded_at_ns: Some(-1_000_000_000_000_000_000),
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: Oid([5; 32]),
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: h.evidence.clone(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let approvals = approve_two(&mut h, chunk.proposal_digest().unwrap());
    let req = PostRequest {
        proposal: chunk,
        approvals,
        plan_certificate: None,
        capability: preparer.clone(),
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("the chunk stages");
    h.post(h.utilities, 250, b"after-chunk");

    let staged = h.checkpoint();
    let staged_trusted = outsider_checkpoint(&staged);
    let journal = Journal::read(&h.db, &h.book, Some(staged.state.through_seq))
        .unwrap()
        .unwrap();
    assert!(
        journal
            .leaves
            .iter()
            .any(|l| l.envelope.class == EntryClass::MIGRATION),
        "the accumulator keeps the staged chunk"
    );
    for account in [h.cash, h.rent] {
        let r = prove_balance(&h.db, &h.book, &staged.state, account, h.usd.0, None)
            .unwrap()
            .expect_err("a staged chunk's account does not prove");
        assert_eq!(
            (r.code, r.exit),
            (code::MIGRATION_STAGED, exit::REFUSAL),
            "{r}"
        );
    }
    // An account the chunk does not touch proves as before.
    let utilities = prove_balance(&h.db, &h.book, &staged.state, h.utilities, h.usd.0, None)
        .unwrap()
        .expect("unaffected account proves");
    assert!(fa_verify::verify_balance(&utilities, &staged_trusted).is_ok());

    // Finalize (two approvals over the planned proposal).
    let fin = plan_run_transition(
        &h.db,
        &h.book,
        run,
        fa_journal::migration::kind::FINALIZE,
        PRINCIPAL,
        b"finalize",
        sealed(&h, "finalize"),
    )
    .unwrap()
    .expect("ties out");
    let approvals = approve_two(&mut h, fin.proposal_digest().unwrap());
    let req = RunControlRequest {
        proposal: fin,
        capability: preparer,
        approvals,
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async move { transition_run(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("finalized");

    let active = h.checkpoint();
    let trusted = outsider_checkpoint(&active);
    let register = fa_registers::balance_as_of(
        &h.db,
        &h.book,
        DateDay::from_ymd(2026, 12, 31).unwrap(),
        Some(active.state.through_seq),
    )
    .expect("register fold");
    for account in [h.cash, h.rent] {
        let proof = prove_balance(&h.db, &h.book, &active.state, account, h.usd.0, None)
            .unwrap()
            .expect("a finalized run's account proves");
        let report = fa_verify::verify_balance(&proof, &trusted).expect("refold matches");
        let expected = register
            .rows
            .iter()
            .find(|r| r.account == account && r.unit_id == h.usd.0)
            .map_or((0, 0), |r| (r.debits, r.credits));
        assert_eq!((report.claim.debits, report.claim.credits), expected);
    }
    // The earlier prefix holds no Finalize leaf: it still refuses.
    let r = prove_balance(&h.db, &h.book, &staged.state, h.cash, h.usd.0, None)
        .unwrap()
        .expect_err("the staged prefix never proves the chunk");
    assert_eq!(r.code, code::MIGRATION_STAGED);
}

fn seal_text(h: &Harness, text: &str) -> Erasable<String> {
    Erasable::seal(&text.to_string(), None, &h.book.seal_key, [5; 32], [6; 24])
}

/// Walk FY2026's Opening period to Locked, where migration chunks land
/// (Lock is dual-controlled and legal only from Closed).
fn lock_opening(h: &mut Harness, opening: DateDay) {
    for (i, t) in [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
        PeriodTransition::Lock,
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("opening-{i}");
        let approvals = if matches!(t, PeriodTransition::Lock) {
            let digest = transition_proposal(
                &h.book,
                "FY2026-OPEN",
                PeriodState::Closed,
                PeriodState::Locked,
                PRINCIPAL,
                1,
                opening,
                key.as_bytes(),
                seal_text(h, "period"),
            )
            .proposal_digest()
            .unwrap();
            approve_two(h, digest)
        } else {
            Vec::new()
        };
        let desc = seal_text(h, "period");
        let ctx = h.ctx();
        let (db, book) = (&mut h.db, &h.book);
        h.runtime
            .block_on(async move {
                transition_period(
                    db,
                    &ctx,
                    book,
                    "FY2026-OPEN",
                    t,
                    PRINCIPAL,
                    1,
                    opening,
                    key.as_bytes(),
                    desc,
                    &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
                    &approvals,
                )
                .await
            })
            .expect("kernel")
            .expect("transition");
    }
}

/// Stage `Dr rent / Cr cash` of `cents` into `run` as a migration chunk in
/// `period`, dated `date`, with its two approvals.
fn stage_rent_chunk(
    h: &mut Harness,
    run: VId,
    key: &[u8],
    (period, date): (&str, DateDay),
    cents: i128,
) {
    let legs = vec![
        LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, cents)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, cents)),
    ];
    let chunk = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: h.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::MIGRATION,
        effective_date: date,
        document_date: None,
        description: seal_text(h, "legacy rent"),
        effective_period: Some(fa_model::PeriodRef {
            calendar: h.book.calendar.id.clone(),
            code: period.into(),
        }),
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Migration {
            run_ref: run,
            source_system: "legacy-gl".into(),
            source_id: seal_text(h, "JE-legacy"),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: Oid([5; 32]),
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: h.evidence.clone(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let approvals = approve_two(h, chunk.proposal_digest().unwrap());
    let req = PostRequest {
        proposal: chunk,
        approvals,
        plan_certificate: None,
        capability: Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap(),
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("the chunk stages");
}

/// fa-e00 interim under ruling 3675 F3 (WhiteCreek 3897): a finalized,
/// non-sole FullDetail run's detail dated before its opening date is
/// summarized by the Opening chunk, so no fold counts it — and no balance
/// proof may either, since `fa-verify` cannot tell it from a counting
/// chunk. A book going live 2026-01-01 imports a June 2025 rent payment as
/// detail and the same balances as its Opening chunk. A planted state
/// projection (Finalized, with no Finalize record) authorizes no proof:
/// only the journal's leaves decide (WhiteCreek 3905). After Finalize the
/// accumulator holds both chunks and the register counts the Opening chunk
/// only; cash and rent refuse FA-REF-133 (the detail is dated before its
/// run's Open record), while utilities proves and verifies.
#[test]
fn finalized_full_detail_history_before_the_opening_date_never_proves() {
    let opening = DateDay::from_ymd(2026, 1, 1).unwrap();
    let mut h = harness_with(Some(opening));
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async move { create_periods(db, &ctx, book, 2025).await })
        .expect("FY2025 periods, born Historical");
    lock_opening(&mut h, opening);
    h.post(h.utilities, 250, b"utilities");

    let line = |code: &str, mantissa: i128| TrialBalanceLine {
        account_code: code.into(),
        unit: h.usd,
        mantissa,
    };
    let paid = vec![line("1000", -300), line("6000", 300)];
    let body = RunBody {
        book_id: h.book.book_id,
        run_key: "full-detail".into(),
        source_system: "legacy-gl".into(),
        mode: RunMode::FullDetail,
        trial_balance: h.evidence[0].document_oid,
        opening_date: opening,
        lines: paid.clone(),
        periods: (1..=12u8)
            .map(|m| PeriodBalance {
                period_code: format!("FY2025-P{m:02}"),
                trial_balance: h.evidence[0].document_oid,
                lines: if m < 6 { Vec::new() } else { paid.clone() },
            })
            .collect(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let proposal = open_proposal(
        &h.book,
        PRINCIPAL,
        &body,
        vec![h.evidence[0]],
        b"open-full-detail",
        seal_text(&h, "open"),
    )
    .unwrap();
    let req = RunControlRequest {
        proposal,
        capability: Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap(),
        approvals: Vec::new(),
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    let run = h
        .runtime
        .block_on(async move { open_run(db, &ctx, book, &body, req).await })
        .expect("kernel")
        .expect("opened")
        .run;
    stage_rent_chunk(&mut h, run, b"opening", ("FY2026-OPEN", opening), 300);

    // Planted drift (WhiteCreek 3905), while only the Opening chunk is
    // staged so the missing Finalize record is the sole reason to refuse
    // (MaroonSquirrel 3917): the run's state projection says Finalized with
    // no Finalize record in the journal. Only the journal's leaves decide,
    // so the proof still refuses; then the projection is restored, the June
    // detail is staged, and the run finalizes for real.
    let run_state = |from: i64, to: i64| {
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        batch.compare_and_set_vertex_property(
            run,
            property::STATE,
            Some(CanonicalScalar::Int(from)),
            CanonicalScalar::Int(to),
            WriteMismatchPolicy::AbortWrite,
        );
        batch
    };
    h.write_raw(run_state(0, 1));
    let drifted = h.checkpoint();
    for account in [h.cash, h.rent] {
        let r = prove_balance(&h.db, &h.book, &drifted.state, account, h.usd.0, None)
            .unwrap()
            .expect_err("a state projection authorizes no proof");
        assert_eq!(r.code, code::MIGRATION_STAGED, "{r}");
        assert!(r.message.contains("no Finalize record"), "{r}");
    }
    h.write_raw(run_state(1, 0));
    let june = DateDay::from_ymd(2025, 6, 10).unwrap();
    stage_rent_chunk(&mut h, run, b"detail", ("FY2025-P06", june), 300);

    let fin = plan_run_transition(
        &h.db,
        &h.book,
        run,
        fa_journal::migration::kind::FINALIZE,
        PRINCIPAL,
        b"finalize",
        seal_text(&h, "finalize"),
    )
    .unwrap()
    .expect("the chain ties out");
    let approvals = approve_two(&mut h, fin.proposal_digest().unwrap());
    let req = RunControlRequest {
        proposal: fin,
        capability: Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap(),
        approvals,
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async move { transition_run(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("finalized");

    let active = h.checkpoint();
    let trusted = outsider_checkpoint(&active);
    let journal = Journal::read(&h.db, &h.book, Some(active.state.through_seq))
        .unwrap()
        .unwrap();
    assert_eq!(
        journal
            .leaves
            .iter()
            .filter(|l| l.envelope.class == EntryClass::MIGRATION)
            .count(),
        2,
        "the accumulator keeps both chunks"
    );
    let register = fa_registers::balance_as_of(
        &h.db,
        &h.book,
        DateDay::from_ymd(2026, 12, 31).unwrap(),
        Some(active.state.through_seq),
    )
    .expect("register fold");
    let rent = register
        .rows
        .iter()
        .find(|r| r.account == h.rent && r.unit_id == h.usd.0)
        .map(|r| (r.debits, r.credits));
    assert_eq!(
        rent,
        Some((300, 0)),
        "the register counts the Opening chunk only"
    );
    for account in [h.cash, h.rent] {
        let r = prove_balance(&h.db, &h.book, &active.state, account, h.usd.0, None)
            .unwrap()
            .expect_err("summarized history never proves");
        assert_eq!(
            (r.code, r.exit),
            (code::MIGRATION_STAGED, exit::REFUSAL),
            "{r}"
        );
        assert!(r.message.contains("before its run's opening date"), "{r}");
    }
    let utilities = prove_balance(&h.db, &h.book, &active.state, h.utilities, h.usd.0, None)
        .unwrap()
        .expect("an account no chunk touches proves");
    assert!(fa_verify::verify_balance(&utilities, &trusted).is_ok());
}

/// fa-e00 supplemental controls. A finalized sole-source run counts its
/// prior-year detail in registers, but v1 leaves cannot authenticate that
/// mode: the producer conservatively refuses. Detail on/after OPEN still
/// proves, and raw inclusion never depends on balance visibility.
#[test]
fn full_detail_proof_boundary_preserves_inclusion_and_supported_balances() {
    let opening = DateDay::from_ymd(2026, 1, 1).unwrap();
    for (detail_year, sole_source) in [(2025, true), (2026, false), (2026, true)] {
        let prior_year = detail_year < 2026;
        // February's go-live makes January Historical and its Opening
        // born Locked, while March remains Normal for the shared harness.
        let go_live = if prior_year {
            opening
        } else {
            DateDay::from_ymd(2026, 2, 1).unwrap()
        };
        let mut h = harness_with(Some(go_live));
        if prior_year {
            let ctx = h.ctx();
            let (db, book) = (&mut h.db, &h.book);
            h.runtime
                .block_on(async move { create_periods(db, &ctx, book, 2025).await })
                .expect("FY2025 periods, born Historical");
        }
        let line = |code: &str, mantissa| TrialBalanceLine {
            account_code: code.into(),
            unit: h.usd,
            mantissa,
        };
        let opening_lines = vec![line("1000", -300), line("6000", 300)];
        let counted = if sole_source { 300 } else { 500 };
        let paid = vec![line("1000", -counted), line("6000", counted)];
        let body = RunBody {
            book_id: h.book.book_id,
            run_key: "supplement-full-detail".into(),
            source_system: "legacy-gl".into(),
            mode: RunMode::FullDetail,
            trial_balance: h.evidence[0].document_oid,
            opening_date: opening,
            lines: if sole_source {
                Vec::new()
            } else {
                opening_lines.clone()
            },
            periods: (1..=if prior_year { 12 } else { 1 })
                .map(|m| PeriodBalance {
                    period_code: format!("FY{detail_year}-P{m:02}"),
                    trial_balance: h.evidence[0].document_oid,
                    lines: paid.clone(),
                })
                .collect(),
            detail_base: if sole_source {
                Vec::new()
            } else {
                opening_lines
            },
            sole_opening_source: sole_source,
        };
        let proposal = open_proposal(
            &h.book,
            PRINCIPAL,
            &body,
            h.evidence.clone(),
            b"open-supplement",
            seal_text(&h, "open"),
        )
        .unwrap();
        let req = RunControlRequest {
            proposal,
            capability: Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap(),
            approvals: Vec::new(),
        };
        let ctx = h.ctx();
        let (db, book) = (&mut h.db, &h.book);
        let run = h
            .runtime
            .block_on(async move { open_run(db, &ctx, book, &body, req).await })
            .expect("kernel")
            .expect("opens real run")
            .run;
        if !sole_source {
            // Opening ends before February go-live; no Planned-period
            // shortcut or raw state edit substitutes for its birth law.
            stage_rent_chunk(&mut h, run, b"opening", ("FY2026-OPEN", opening), 300);
        }
        let detail_day = DateDay::from_ymd(detail_year, 1, 15).unwrap();
        let period = format!("FY{detail_year}-P01");
        stage_rent_chunk(
            &mut h,
            run,
            b"detail",
            (&period, detail_day),
            if sole_source { 300 } else { 200 },
        );
        let fin = plan_run_transition(
            &h.db,
            &h.book,
            run,
            fa_journal::migration::kind::FINALIZE,
            PRINCIPAL,
            b"finalize-supplement",
            seal_text(&h, "finalize"),
        )
        .unwrap()
        .expect("real chain ties out");
        let approvals = approve_two(&mut h, fin.proposal_digest().unwrap());
        let req = RunControlRequest {
            proposal: fin,
            capability: Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap(),
            approvals,
        };
        let ctx = h.ctx();
        let (db, book) = (&mut h.db, &h.book);
        h.runtime
            .block_on(async move { transition_run(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("finalizes");
        let active = h.checkpoint();
        let trusted = outsider_checkpoint(&active);
        let journal = Journal::read(&h.db, &h.book, Some(active.state.through_seq))
            .unwrap()
            .unwrap();
        let chunks: Vec<_> = journal
            .leaves
            .iter()
            .filter(|l| l.envelope.class == EntryClass::MIGRATION)
            .collect();
        assert_eq!(chunks.len(), if sole_source { 1 } else { 2 });
        for leaf in chunks {
            let proof = prove_inclusion(&h.db, &h.book, &active.state, leaf.vid, true)
                .unwrap()
                .expect("raw historical record still proves");
            let report = fa_verify::verify_inclusion(&proof, &trusted).expect("inclusion verifies");
            assert_eq!(report.record, RecordCheck::Recomputed);
            assert_eq!(report.envelope.encode(), leaf.envelope_bytes);
        }
        for cutoff in [None, Some(DateDay::from_ymd(detail_year, 1, 31).unwrap().0)] {
            let register = fa_registers::balance_as_of(
                &h.db,
                &h.book,
                cutoff.map_or(DateDay::from_ymd(2026, 12, 31).unwrap(), DateDay),
                Some(active.state.through_seq),
            )
            .expect("register fold");
            let rent = register
                .rows
                .iter()
                .find(|r| r.account == h.rent && r.unit_id == h.usd.0)
                .expect("the finalized detail counts in the register");
            assert_eq!((rent.debits, rent.credits), (counted, 0));
            if prior_year {
                let r = journal
                    .posted_balance(h.rent, h.usd.0, cutoff)
                    .unwrap()
                    .expect_err("v1 cannot authenticate sole-source mode");
                assert_eq!((r.code, r.exit), (code::MIGRATION_STAGED, exit::REFUSAL));
                assert!(r.message.contains("before its run's opening date"));
                let r = journal
                    .balance_proof(h.rent, h.usd.0, cutoff)
                    .unwrap()
                    .expect_err("v1 producer remains conservative");
                assert_eq!((r.code, r.exit), (code::MIGRATION_STAGED, exit::REFUSAL));
                assert!(r.message.contains("before its run's opening date"));
                let r = prove_balance(&h.db, &h.book, &active.state, h.rent, h.usd.0, cutoff)
                    .unwrap()
                    .expect_err("checkpoint proof also refuses");
                assert_eq!((r.code, r.exit), (code::MIGRATION_STAGED, exit::REFUSAL));
                assert!(r.message.contains("before its run's opening date"));
            } else {
                assert_eq!(
                    journal
                        .posted_balance(h.rent, h.usd.0, cutoff)
                        .unwrap()
                        .unwrap(),
                    (counted, 0)
                );
                let proof = prove_balance(&h.db, &h.book, &active.state, h.rent, h.usd.0, cutoff)
                    .unwrap()
                    .expect("on/after-opening finalized detail proves");
                let report =
                    fa_verify::verify_balance(&proof, &trusted).expect("independent refold");
                assert_eq!((report.claim.debits, report.claim.credits), (counted, 0));
            }
        }
        // No detail selected: the prior-year sole source proves zero;
        // the mid-year nonsole run proves its Opening chunk alone, dated
        // exactly on OPEN. The sole-source same-year run also proves zero.
        let cutoff = Some(DateDay::from_ymd(detail_year, 1, 1).unwrap().0);
        let expected = if sole_source { (0, 0) } else { (300, 0) };
        assert_eq!(
            journal
                .posted_balance(h.rent, h.usd.0, cutoff)
                .unwrap()
                .unwrap(),
            expected
        );
        let proof = prove_balance(&h.db, &h.book, &active.state, h.rent, h.usd.0, cutoff)
            .unwrap()
            .expect("cutoff selects no excluded history");
        let report = fa_verify::verify_balance(&proof, &trusted).expect("cutoff balance verifies");
        assert_eq!((report.claim.debits, report.claim.credits), expected);
    }
}

/// fa-kjl acceptance example: a scratch replay with intervening system
/// records (plan §15.2). The notary's checkpoints are maintenance: the
/// `AccumulatorState` vertex and the head pointer its commit moves on the
/// book root. A book whose posts are interleaved with two checkpoints
/// replays into a scratch book that holds every entry, no checkpoint and no
/// head pointer; neither checkpoint commit is paired, the map verifies, and
/// the scratch book's March fold is the source's.
#[test]
fn a_scratch_replay_carries_no_notary_checkpoint_and_verifies() {
    let mut h = harness();
    h.post(h.rent, 1_000, b"r1");
    let first = h.checkpoint();
    h.post(h.utilities, 250, b"u1");
    let second = h.checkpoint();
    h.post(h.rent, 500, b"r2");
    let head = h.db.frontier().unwrap();
    // Positive controls: the source holds both checkpoints and its head
    // pointer, so the scratch negatives below cannot pass vacuously.
    assert_eq!(
        h.db.vertices_at(head)
            .unwrap()
            .iter()
            .filter(|v| v.labels.contains(&label::ACCUMULATOR_STATE))
            .count(),
        2,
        "the source holds both checkpoints"
    );
    assert!(
        fa_journal::rows::prop(
            &h.db.vertex(book_root()).unwrap().expect("root"),
            property::ACCUMULATOR_HEAD
        )
        .is_some(),
        "the source's root points at its latest checkpoint"
    );
    let ctx = h.ctx();
    let keys = DatabaseKeys::new(
        [0x7a; 32],
        DatabaseSecurityNamespaceId([0x7b; 32]),
        [0x7c; 32],
    );
    let mut scratch = h
        .runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("a fresh scratch database");
    let id = h.book.book_id;
    let (db, runtime) = (&mut h.db, &h.runtime);
    let map = runtime
        .block_on(async { replay_into(db, &mut scratch, &ctx, id, Some(head)).await })
        .expect("kernel")
        .expect("replays");
    for checkpoint in [first.recorded_at, second.recorded_at] {
        assert!(
            map.pairs.iter().all(|p| p.source_seq != checkpoint),
            "a checkpoint commit is never paired"
        );
    }
    let verified = fa_registers::replay::verify_replay(&h.db, &scratch, &h.book, &map)
        .expect("kernel")
        .expect("the map verifies");
    assert_eq!(verified.pairs_checked, map.pairs.len());
    let at = scratch.frontier().unwrap();
    assert!(
        scratch
            .vertices_at(at)
            .unwrap()
            .iter()
            .all(|v| !v.labels.contains(&label::ACCUMULATOR_STATE)),
        "no checkpoint reaches the scratch book"
    );
    assert!(
        fa_journal::rows::prop(
            &scratch.vertex(book_root()).unwrap().expect("root"),
            property::ACCUMULATOR_HEAD
        )
        .is_none(),
        "nor a head pointer to one"
    );
    let fold = |db: &Database<MemVfs>| {
        fa_registers::fold_period(db, &h.book, "FY2026-P03")
            .expect("fold")
            .cells
    };
    assert!(!fold(&h.db).is_empty(), "the source's March fold has cells");
    assert_eq!(fold(&scratch), fold(&h.db));
}
