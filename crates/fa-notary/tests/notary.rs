//! The notary against the real in-memory substrate, with the independent
//! verifier as the oracle: every committed entry proves inclusion against a
//! journaled state that `fa-verify` accepts from the state's bytes alone; a
//! later state proves it extends an earlier one; the complete prefix is
//! verifiable and an omitted leaf is detected; an entry recorded after a
//! state cannot be proved against it; a forged state is found by
//! recomputation and blocks further checkpoints; every byte of a proof is
//! bound; and an evidence bundle of each scope verifies predicate by
//! predicate, reproduces byte for byte, and fails exactly the predicate a
//! planted defect breaks.

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
use fa_notary::checkpoint::checkpoint_vid;
use fa_notary::{
    AccumulatorState, BalanceRequest, BundleRequest, BundleScope, Journal, ProductionReceipt,
    ReceiptBody, ScopeRequest, SigningKey, StoredState, bundle_basis, chain, checkpoint, code,
    latest, prove_balance, prove_consistency, prove_inclusion, prove_prefix, state_oid, state_vid,
    verify_accumulator,
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
    /// The book's checkpoint signer.
    signer: SigningKey,
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
        self.checkpointed().stored
    }

    fn checkpointed(&mut self) -> fa_notary::Checkpointed {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let signer = &self.signer;
        self.runtime
            .block_on(async move { checkpoint(db, &ctx, book, signer).await })
            .expect("kernel")
            .expect("checkpoint admitted")
    }

    fn checkpoint_refusal(&mut self) -> Refusal {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let signer = &self.signer;
        self.runtime
            .block_on(async move { checkpoint(db, &ctx, book, signer).await })
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
        signer: SigningKey::from_seed(&[0x5a; 32]),
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
    let green = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
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

    let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
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
    let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
    assert_eq!(found.unchained, vec![state_vid(&ooid)]);
}

/// An attacker can write a later version whose own entry digests are
/// perfectly valid. The checkpoint's historical snapshot is unchanged,
/// while head reports would read different accounting facts. Verification
/// and every new proof must detect that disagreement.
#[test]
fn checkpointed_entries_must_remain_unchanged_before_verification_or_production() {
    for change in [
        "resealed payload",
        "retirement",
        "removed label",
        "missing digest",
        "changed digest",
        "malformed payload",
    ] {
        let mut h = harness();
        let target = h.post(h.rent, 125, b"protected-prefix");
        let a = h.checkpoint();
        let saved_proof = prove_inclusion(&h.db, &h.book, &a.state, target, true)
            .unwrap()
            .unwrap();
        let bundle_request = BundleRequest {
            scope: BundleScope::Prefix,
            balances: Vec::new(),
            inline_documents: true,
        };
        let saved_bundle = h.bundle(&a, &bundle_request).unwrap();
        let saved_receipt = h.receipt(&saved_bundle, h.db.frontier().unwrap());
        let saved_bundle_report = fa_verify::verify_bundle(
            &saved_bundle.bytes,
            &[h.signer.public_key()],
            Some(&saved_receipt),
        )
        .unwrap();
        assert!(saved_bundle_report.verified(), "{saved_bundle_report:?}");
        let trusted = outsider_checkpoint(&a);
        let before = Journal::read(&h.db, &h.book, Some(a.state.through_seq))
            .unwrap()
            .unwrap();
        h.post(h.utilities, 75, b"later-prefix");
        let b = h.checkpoint();

        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        match change {
            "resealed payload" => {
                let row = h.db.vertex(target).unwrap().unwrap();
                let original = fa_model::Entry::decode(
                    &fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "entry.payload").unwrap(),
                )
                .unwrap();
                let mut proposal = original.proposal;
                for leg in &mut proposal.legs {
                    leg.amount.mantissa = leg.amount.mantissa.checked_add(1).unwrap();
                }
                proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
                let rewritten = proposal
                    .seal(original.approvals, original.plan_certificate)
                    .unwrap();
                let payload = rewritten.encode().unwrap();
                assert_eq!(
                    fa_model::Entry::decode(&payload).unwrap(),
                    rewritten,
                    "the attack has valid recalculated digests, not a malformed entry"
                );
                batch.set_vertex_property(
                    target,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(payload).unwrap()),
                );
                batch.set_vertex_property(
                    target,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(rewritten.entry_digest.to_vec()).unwrap()),
                );
            }
            "retirement" => {
                batch.delete_vertex(target);
            }
            "removed label" => {
                batch.set_vertex_label(target, label::ENTRY, false);
            }
            "missing digest" => {
                batch.set_vertex_property(target, property::FA_DIGEST, None);
            }
            "changed digest" => {
                batch.set_vertex_property(
                    target,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0xed; 32]).unwrap()),
                );
            }
            other => {
                assert_eq!(other, "malformed payload", "the cases above are exhaustive");
                batch.set_vertex_property(
                    target,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(b"invalid entry bytes".to_vec()).unwrap()),
                );
            }
        }
        h.write_raw(batch);
        let attacked_head = h.db.frontier().unwrap();

        assert_eq!(
            Journal::read(&h.db, &h.book, Some(a.state.through_seq))
                .unwrap()
                .unwrap(),
            before,
            "{change}: the historical view alone cannot expose this attack"
        );
        let verified = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
        assert!(!verified.is_green(), "{change}: {verified:?}");
        assert_eq!(verified.states.len(), 2);
        for state in &verified.states {
            assert!(
                state.finding.as_deref().is_some_and(|finding| {
                    finding.contains(&format!("{:032x}", target.0))
                        && finding.contains(&attacked_head.0.to_string())
                }),
                "{change}: {state:?}"
            );
        }
        for produced in [
            prove_inclusion(&h.db, &h.book, &a.state, target, true),
            prove_inclusion(&h.db, &h.book, &a.state, target, false),
            prove_prefix(&h.db, &h.book, &a.state),
            prove_balance(&h.db, &h.book, &a.state, h.rent, h.usd.0, None),
            prove_consistency(&h.db, &h.book, &a.state, &b.state),
        ] {
            let refused = produced.unwrap().unwrap_err();
            assert_eq!(refused.code, code::ACCUMULATOR_DRIFT, "{change}");
            assert_eq!(refused.exit, exit::VERIFICATION, "{change}");
            assert!(refused.message.contains(&format!("{:032x}", target.0)));
        }
        let refused = h
            .bundle(&a, &bundle_request)
            .expect_err("a rewritten checkpoint prefix cannot issue a new bundle");
        assert_eq!(refused.code, code::ACCUMULATOR_DRIFT, "{change}");
        assert_eq!(refused.exit, exit::VERIFICATION, "{change}");
        assert!(refused.message.contains(&format!("{:032x}", target.0)));
        let refused = h.checkpoint_refusal();
        assert_eq!(refused.code, code::ACCUMULATOR_DRIFT, "{change}");
        assert_eq!(refused.exit, exit::VERIFICATION, "{change}");
        assert_eq!(
            h.db.frontier().unwrap(),
            attacked_head,
            "{change}: failed verification, proof production and checkpointing never write"
        );
        // Already-produced historical evidence keeps its exact claim. The
        // refusal concerns issuing a new proof from a now-inconsistent book.
        fa_verify::verify_inclusion(&saved_proof, &trusted).unwrap();
        let saved_bundle_report = fa_verify::verify_bundle(
            &saved_bundle.bytes,
            &[h.signer.public_key()],
            Some(&saved_receipt),
        )
        .unwrap();
        assert!(saved_bundle_report.verified(), "{saved_bundle_report:?}");
    }
}

#[test]
fn an_unchanged_checkpoint_prefix_still_proves_after_later_postings() {
    let mut h = harness();
    let target = h.post(h.rent, 300, b"original-prefix");
    let a = h.checkpoint();
    let trusted = outsider_checkpoint(&a);
    let saved = prove_inclusion(&h.db, &h.book, &a.state, target, true)
        .unwrap()
        .unwrap();
    let bundle_request = BundleRequest {
        scope: BundleScope::Prefix,
        balances: Vec::new(),
        inline_documents: true,
    };
    let saved_bundle = h.bundle(&a, &bundle_request).unwrap();
    let prefix = Journal::read(&h.db, &h.book, Some(a.state.through_seq))
        .unwrap()
        .unwrap();

    h.post(h.utilities, 250, b"later-ordinary-posting");
    let b = h.checkpoint();
    let observed_at = h.db.frontier().unwrap();
    prefix
        .verify_unchanged_at(&h.db, observed_at)
        .unwrap()
        .unwrap();
    assert!(
        verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer)
            .unwrap()
            .is_green()
    );
    let proof = prove_inclusion(&h.db, &h.book, &a.state, target, true)
        .unwrap()
        .unwrap();
    assert_eq!(proof, saved);
    assert_eq!(h.bundle(&a, &bundle_request).unwrap(), saved_bundle);
    fa_verify::verify_inclusion(&proof, &trusted).unwrap();
    let prefix_proof = prove_prefix(&h.db, &h.book, &a.state).unwrap().unwrap();
    fa_verify::verify_prefix(&prefix_proof, &trusted).unwrap();
    let balance = prove_balance(&h.db, &h.book, &a.state, h.rent, h.usd.0, None)
        .unwrap()
        .unwrap();
    let folded = fa_verify::verify_balance(&balance, &trusted).unwrap();
    assert_eq!((folded.claim.debits, folded.claim.credits), (300, 0));
    let extension = prove_consistency(&h.db, &h.book, &a.state, &b.state)
        .unwrap()
        .unwrap();
    let extended = outsider_checkpoint(&b);
    assert_eq!(
        fa_verify::verify_consistency(&extension, &trusted, &extended)
            .unwrap()
            .extended,
        extended
    );
    assert_eq!(h.db.frontier().unwrap(), observed_at);
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
    let found =
        verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).expect("a finding, not an error");
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
    let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
    assert!(
        found
            .broken
            .as_deref()
            .is_some_and(|why| why.contains("named but absent")),
        "{found:?}"
    );
    assert!(found.states.is_empty());
    let mut unchained = found.unchained.clone();
    unchained.sort_by_key(|v| v.0);
    let mut expected = vec![a.vid, b.vid, checkpoint_vid(&a.oid), checkpoint_vid(&b.oid)];
    expected.sort_by_key(|v| v.0);
    assert_eq!(
        unchained, expected,
        "both real states and their checkpoints are now unreachable"
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

    let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
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

    let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
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

/// fa-e00: the accumulator keeps a staged migration chunk (it is
/// journaled), but a balance never counts it before the run finalizes. A
/// proof touching a staged chunk's account is the migration-aware v2 format,
/// which authenticates the run's state, so it proves exactly the register
/// fold (the chunk excluded) and a v1-only verifier cannot read it; this
/// replaces the interim FA-REF-133 refusal (fa-xo0, ruling 3243). Once the
/// run's Finalize is in the prefix, the same account proves the chunk, and
/// the earlier prefix still proves it excluded.
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
    let bundle_request = |account, unit| BundleRequest {
        scope: BundleScope::Prefix,
        balances: vec![balance(account, unit, None)],
        inline_documents: true,
    };
    let before_refusal = h.db.frontier().unwrap();
    let staged_register = fa_registers::balance_as_of(
        &h.db,
        &h.book,
        DateDay::from_ymd(2026, 12, 31).unwrap(),
        Some(staged.state.through_seq),
    )
    .expect("register fold");
    let usd = h.usd.0;
    let staged_expected = |account: VId| {
        staged_register
            .rows
            .iter()
            .find(|r| r.account == account && r.unit_id == usd)
            .map_or((0, 0), |r| (r.debits, r.credits))
    };
    for account in [h.cash, h.rent] {
        let proof = prove_balance(&h.db, &h.book, &staged.state, account, h.usd.0, None)
            .unwrap()
            .expect("a staged chunk's account proves in v2");
        assert!(
            fa_verify::balance::verify_balance(&proof, &staged_trusted).is_err(),
            "a v1-only verifier cannot read the migration-aware proof"
        );
        let report = fa_verify::verify_balance(&proof, &staged_trusted).expect("v2 refold");
        assert_eq!(
            (report.claim.debits, report.claim.credits),
            staged_expected(account),
            "the staged chunk is excluded exactly as the register excludes it"
        );
        let bundle = h
            .bundle(&staged, &bundle_request(account, h.usd))
            .expect("the staged balance bundles in v2");
        let receipt = h.receipt(&bundle, before_refusal);
        let report =
            fa_verify::verify_bundle(&bundle.bytes, &[h.signer.public_key()], Some(&receipt))
                .expect("readable bundle");
        assert!(report.verified(), "{:#?}", not_passed(&report));
    }
    assert_eq!(h.db.frontier().unwrap(), before_refusal);
    // An account the chunk does not touch proves as before.
    let utilities = prove_balance(&h.db, &h.book, &staged.state, h.utilities, h.usd.0, None)
        .unwrap()
        .expect("unaffected account proves");
    assert!(fa_verify::verify_balance(&utilities, &staged_trusted).is_ok());
    let bundle = h
        .bundle(&staged, &bundle_request(h.utilities, h.usd))
        .expect("a bundle can still prove an unaffected account");
    let receipt = h.receipt(&bundle, before_refusal);
    let report = fa_verify::verify_bundle(&bundle.bytes, &[h.signer.public_key()], Some(&receipt))
        .expect("readable bundle");
    assert!(report.verified(), "{:#?}", not_passed(&report));

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
        let bundle = h
            .bundle(&active, &bundle_request(account, h.usd))
            .expect("the finalized balance can be bundled");
        let receipt = h.receipt(&bundle, h.db.frontier().unwrap());
        let report =
            fa_verify::verify_bundle(&bundle.bytes, &[h.signer.public_key()], Some(&receipt))
                .expect("readable bundle");
        assert!(report.verified(), "{:#?}", not_passed(&report));
    }
    // The earlier prefix holds no Finalize leaf: it still proves the chunk
    // excluded.
    let proof = prove_balance(&h.db, &h.book, &staged.state, h.cash, h.usd.0, None)
        .unwrap()
        .expect("the staged prefix proves");
    let report = fa_verify::verify_balance(&proof, &staged_trusted).expect("v2 refold");
    assert_eq!(
        (report.claim.debits, report.claim.credits),
        staged_expected(h.cash)
    );
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

/// fa-e00 (ruling 3675 F3, WhiteCreek 3897; the v2 resolution): a finalized,
/// non-sole FullDetail run's detail dated before its opening date is
/// summarized by the Opening chunk, so no fold counts it. A book going live
/// 2026-01-01 imports a June 2025 rent payment as detail and the same
/// balances as its Opening chunk. A planted state projection (Finalized,
/// with no Finalize record) authorizes nothing: the v2 proof reads the run
/// lifecycle from the journal's leaves alone (WhiteCreek 3905) and proves
/// the staged chunk excluded. After Finalize the accumulator holds both
/// chunks and the register counts the Opening chunk only; the v2 proofs of
/// cash and rent equal that register (the June detail is never counted),
/// the v1 producer still refuses FA-REF-133, and utilities proves too.
#[test]
fn finalized_full_detail_history_before_the_opening_date_never_counts() {
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
    // The honest fold is the register before the planted projection: the
    // same entries (only the raw write and the checkpoint follow), with the
    // run still Open. The register reads the projection, so after the plant
    // it would count the staged chunk; the proof must not.
    let honest = h.db.frontier().unwrap();
    h.write_raw(run_state(0, 1));
    let drifted = h.checkpoint();
    let drifted_trusted = outsider_checkpoint(&drifted);
    let honest_register = fa_registers::balance_as_of(
        &h.db,
        &h.book,
        DateDay::from_ymd(2026, 12, 31).unwrap(),
        Some(honest),
    )
    .expect("register fold");
    for account in [h.cash, h.rent] {
        // fa-e00: the proof is v2, whose run lifecycle comes from the
        // journal's leaves alone; the planted projection counts nothing.
        let proof = prove_balance(&h.db, &h.book, &drifted.state, account, h.usd.0, None)
            .unwrap()
            .expect("the staged chunk's account proves in v2");
        let report = fa_verify::verify_balance(&proof, &drifted_trusted).expect("v2 refold");
        let expected = honest_register
            .rows
            .iter()
            .find(|r| r.account == account && r.unit_id == h.usd.0)
            .map_or((0, 0), |r| (r.debits, r.credits));
        assert_eq!(
            (report.claim.debits, report.claim.credits),
            expected,
            "a state projection authorizes nothing: the chunk stays excluded"
        );
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
        // fa-e00: summarized history is excluded by the v2 proof exactly as
        // the register excludes it (the Opening chunk counts, June does not);
        // the v1 journal fold still refuses it.
        let proof = prove_balance(&h.db, &h.book, &active.state, account, h.usd.0, None)
            .unwrap()
            .expect("summarized history proves excluded in v2");
        let report = fa_verify::verify_balance(&proof, &trusted).expect("v2 refold");
        let expected = register
            .rows
            .iter()
            .find(|r| r.account == account && r.unit_id == h.usd.0)
            .map_or((0, 0), |r| (r.debits, r.credits));
        assert_eq!((report.claim.debits, report.claim.credits), expected);
        let r = journal
            .balance_proof(account, h.usd.0, None)
            .unwrap()
            .expect_err("the v1 producer stays conservative");
        assert_eq!(
            (r.code, r.exit),
            (code::MIGRATION_STAGED, exit::REFUSAL),
            "{r}"
        );
    }
    let utilities = prove_balance(&h.db, &h.book, &active.state, h.utilities, h.usd.0, None)
        .unwrap()
        .expect("an account no chunk touches proves");
    assert!(fa_verify::verify_balance(&utilities, &trusted).is_ok());
}

/// fa-e00 supplemental controls. A finalized sole-source run counts its
/// prior-year detail in registers, but v1 leaves cannot authenticate that
/// mode: the v1 journal fold and v1 producer conservatively refuse, while
/// the auto-versioned checkpoint proof is v2, which authenticates the mode
/// and proves the register value. Detail on/after OPEN proves too, and raw
/// inclusion never depends on balance visibility.
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
                let proof = prove_balance(&h.db, &h.book, &active.state, h.rent, h.usd.0, cutoff)
                    .unwrap()
                    .expect("the checkpoint proof is v2, which authenticates the mode");
                assert!(fa_verify::balance::verify_balance(&proof, &trusted).is_err());
                let report = fa_verify::verify_balance(&proof, &trusted).expect("v2 refold");
                assert_eq!((report.claim.debits, report.claim.credits), (counted, 0));
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
/// `AccumulatorState` vertex, the signed `TransparencyCheckpoint` beside it
/// (it signs the source's prefix by sequence numbers a scratch book does
/// not share), and the head pointer their commit moves on the book root. A
/// book whose posts are interleaved with two checkpoints replays into a
/// scratch book that holds every entry, no checkpoint and no head pointer;
/// neither checkpoint commit is paired, the map verifies, and the scratch
/// book's March fold is the source's.
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
    for checkpoint_label in [label::ACCUMULATOR_STATE, label::TRANSPARENCY_CHECKPOINT] {
        assert_eq!(
            h.db.vertices_at(head)
                .unwrap()
                .iter()
                .filter(|v| v.labels.contains(&checkpoint_label))
                .count(),
            2,
            "the source holds both checkpoints"
        );
    }
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
            .all(|v| !v.labels.contains(&label::ACCUMULATOR_STATE)
                && !v.labels.contains(&label::TRANSPARENCY_CHECKPOINT)),
        "no checkpoint, signed or not, reaches the scratch book"
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

// ---- signed checkpoints and ScopeIndexComplete (fa-l3c slice 3) ------------

/// What an outsider does with a checkpoint's bytes and the book's public
/// key.
fn signed_checkpoint(h: &Harness, c: &fa_notary::Checkpointed) -> fa_verify::SignedCheckpoint {
    fa_verify::verify_checkpoint(&c.checkpoint.bytes, &[h.signer.public_key()])
        .expect("the book's key signed the checkpoint")
}

fn day(d: u8) -> i32 {
    DateDay::from_ymd(2026, 3, d).unwrap().0
}

/// The checkpoint beside each state is signed by the book's key, binds the
/// state, the prefix's scope-index root and the substrate's chain
/// commitment, and every forgery an outsider could be handed is refused:
/// another key, a flipped bit, a signature over another body, and a body
/// altered under its original signature.
#[test]
fn checkpoints_are_signed_by_the_book_key_and_forgeries_are_refused() {
    use fa_notary::checkpoint::signer_key_id;
    use fa_verify::{CheckpointError, verify_checkpoint};

    let mut h = harness();
    h.post(h.rent, 5, b"k1");
    h.post(h.utilities, 7, b"k2");
    let c = h.checkpointed();
    let signed = signed_checkpoint(&h, &c);
    assert_eq!(signed.checkpoint, outsider_checkpoint(&c.stored));
    assert_eq!(signed.state_oid, c.stored.oid.0);
    assert_eq!(signed.oid, c.checkpoint.oid.0);
    assert_eq!(
        signed.signed_by,
        vec![signer_key_id(&h.signer.public_key())]
    );
    assert!(signed.not_judged.is_empty());
    assert_eq!(signed.witness_policy_oid, None);
    assert_eq!(signed.time_evidence_oid, None);
    let journal = Journal::read(&h.db, &h.book, Some(c.stored.state.through_seq))
        .unwrap()
        .unwrap();
    assert_eq!(
        signed.scope_index_root,
        fa_notary::ScopeIndex::of(&journal).root()
    );
    // The chain commitment is the substrate's at the state's sequence: a
    // later checkpoint commits another.
    h.post(h.rent, 9, b"k3");
    let next = h.checkpointed();
    let later = signed_checkpoint(&h, &next);
    assert_ne!(
        later.substrate_chain_commitment,
        signed.substrate_chain_commitment
    );

    let cp = &c.checkpoint.checkpoint;
    let trusted = [h.signer.public_key()];
    let other = SigningKey::from_seed(&[0x33; 32]);
    let message = cp.body.signed_message().unwrap();
    let refused = |forged: &fa_notary::TransparencyCheckpoint, what: &str| {
        let result = verify_checkpoint(&forged.canonical_bytes().unwrap(), &trusted);
        assert!(
            matches!(
                result,
                Err(VerifyError::Checkpoint(CheckpointError::Signature { .. }))
            ),
            "{what}: {result:?}"
        );
    };
    // 1. Not signed by a trusted key at all.
    assert_eq!(
        verify_checkpoint(&c.checkpoint.bytes, &[other.public_key()]),
        Err(VerifyError::Checkpoint(CheckpointError::NoTrustedSignature))
    );
    // 2. Another key's signature under the book key's id.
    let mut swapped = cp.clone();
    swapped.signatures[0].bytes = other.sign(&message).to_vec();
    refused(&swapped, "another key");
    // 3. One flipped bit, in R and in S.
    for at in [3, 40] {
        let mut flipped = cp.clone();
        flipped.signatures[0].bytes[at] ^= 0x10;
        refused(&flipped, "a flipped bit");
    }
    // 4. The book key's signature over another body.
    let mut other_body = cp.body.clone();
    other_body.scope_index_root[0] ^= 1;
    let mut spliced = cp.clone();
    spliced.signatures[0].bytes = h
        .signer
        .sign(&other_body.signed_message().unwrap())
        .to_vec();
    refused(&spliced, "a signature over another body");
    // 5. The body altered under its original signature, field by field.
    let mut altered = cp.clone();
    altered.body.scope_index_root[31] ^= 1;
    refused(&altered, "scope_index_root altered");
    let mut altered = cp.clone();
    altered.body.substrate_chain_commitment[0] ^= 1;
    refused(&altered, "chain commitment altered");
    let mut altered = cp.clone();
    altered.body.statement.leaf_count += 1;
    refused(&altered, "leaf count altered");
}

/// A checkpoint rewritten in the store — re-signed by someone without the
/// book's key — is a finding, blocks further checkpoints with FA-REF-127,
/// and is never handed out.
#[test]
fn a_tampered_stored_checkpoint_is_a_finding_and_refused() {
    use fa_notary::checkpoint::{checkpoint_oid, checkpoint_vid};

    let mut h = harness();
    h.post(h.rent, 5, b"t1");
    let c = h.checkpointed();
    let mut forged_body = c.checkpoint.checkpoint.body.clone();
    forged_body.scope_index_root = [0x77; 32];
    let insider = SigningKey::from_seed(&[0x44; 32]);
    let forged = fa_notary::TransparencyCheckpoint::sign(forged_body, &[&insider]).unwrap();
    let bytes = forged.canonical_bytes().unwrap();
    let scalar = |b: Vec<u8>| CanonicalScalar::bytes(b).unwrap();
    let mut batch = WriteBatch::new(relation::CHECKPOINTS);
    batch.set_vertex_property(
        checkpoint_vid(&c.stored.oid),
        property::FA_PAYLOAD,
        Some(scalar(bytes.clone())),
    );
    batch.set_vertex_property(
        checkpoint_vid(&c.stored.oid),
        property::FA_DIGEST,
        Some(scalar(checkpoint_oid(&bytes).0.to_vec())),
    );
    h.write_raw(batch);

    let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
    assert!(!found.is_green());
    assert!(
        found.states[0]
            .finding
            .as_deref()
            .is_some_and(|f| f.contains("checkpoint is not what")),
        "{found:?}"
    );
    let refusal = fa_notary::stored_checkpoint(&h.db, &h.ctx(), &h.book, &c.stored, &h.signer)
        .unwrap()
        .expect_err("a tampered checkpoint is never handed out");
    assert_eq!(refusal.code, code::CHECKPOINT_INVALID);
    assert_eq!(refusal.exit, exit::VERIFICATION);
    h.post(h.rent, 6, b"t2");
    let refused = h.checkpoint_refusal();
    assert_eq!(refused.code, code::CHECKPOINT_INVALID);
    assert_eq!(refused.exit, exit::VERIFICATION);
}

/// A history over three accounts and many days: every exact-account
/// interval — empty, first day, last day, one day, the whole range, and an
/// account with no entries — proves complete against the signed root, and
/// the listed leaves are exactly a brute-force filter of the verified
/// complete prefix. With the prefix, the index is recomputed and the
/// premise is `Recomputed`; without it, the premise names the signer.
#[test]
fn scope_proofs_list_exactly_the_brute_force_filter() {
    use fa_verify::{IndexDerivation, ScopeClaim, verify_scope};

    let mut h = harness();
    let mut n = 0u8;
    for d in [2u8, 2, 5, 9, 9, 9, 14, 20, 27, 31] {
        for (i, account) in [h.rent, h.utilities].into_iter().enumerate() {
            if (d as usize + i).is_multiple_of(3) {
                continue;
            }
            n += 1;
            let class = if n.is_multiple_of(5) {
                EntryClass::PENDING
            } else {
                EntryClass::ORIGINAL
            };
            h.post_on(account, 100 + i128::from(n), &[b'p', n], d, class);
        }
    }
    let c = h.checkpointed();
    let signed = signed_checkpoint(&h, &c);
    let prefix_proof = prove_prefix(&h.db, &h.book, &c.stored.state)
        .unwrap()
        .unwrap();
    let prefix = fa_verify::verify_prefix(&prefix_proof, &signed.checkpoint).unwrap();
    let unused = VId(0xdead_beef);
    let intervals = [
        (day(1), day(31)),
        (day(2), day(2)),
        (day(31), day(31)),
        (day(9), day(14)),
        (day(15), day(19)),
        (day(3), day(4)),
        (i32::MIN, i32::MAX),
        (day(28), day(30)),
    ];
    let mut proved = 0;
    for account in [h.rent, h.utilities, h.cash, unused] {
        for (from, to) in intervals {
            let expected: Vec<u64> = prefix
                .envelopes
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    e.effective_day.is_some_and(|d| from <= d && d <= to)
                        && e.account_vids.binary_search(&account.0).is_ok()
                })
                .map(|(i, _)| i as u64)
                .collect();
            let proof = fa_notary::prove_scope(
                &h.db,
                &h.book,
                &c.stored.state,
                &ScopeRequest::Account { account, from, to },
            )
            .unwrap()
            .unwrap();
            let claim = ScopeClaim {
                account: account.0,
                from,
                to,
            };
            let report = verify_scope(&proof, &signed, &claim, None).expect("scope verifies");
            let listed: Vec<u64> = report.leaves.iter().map(|(i, _)| *i).collect();
            let mut sorted = expected.clone();
            sorted.sort_by_key(|i| prefix.envelopes[*i as usize].effective_day);
            assert_eq!(listed, sorted, "{account:?} [{from}, {to}]");
            assert_eq!(report.scope, "scope_index_complete");
            assert_eq!(
                report.index_derivation,
                IndexDerivation::Signed {
                    by: signed.signed_by.clone()
                }
            );
            let recomputed = verify_scope(&proof, &signed, &claim, Some(&prefix_proof)).unwrap();
            assert_eq!(recomputed.index_derivation, IndexDerivation::Recomputed);
            proved += 1;
        }
    }
    assert_eq!(proved, 32);
}

/// A scope proof parsed into its fields so a test can plant a defect and
/// re-encode it, exactly as a dishonest producer could.
#[derive(Clone)]
struct ScopeProof {
    statement: [u8; 80],
    count: u64,
    account: u128,
    from: i32,
    to: i32,
    lo: u64,
    items: Vec<ScopeItem>,
    left: Option<Neighbour>,
    right: Option<Neighbour>,
}

type Path = Vec<[u8; 32]>;
/// day, leaf index, scope path, envelope bytes, accumulator path.
type ScopeItem = (i32, u64, Path, Vec<u8>, Path);
/// account, day, leaf index, scope path.
type Neighbour = (u128, i32, u64, Path);

impl ScopeProof {
    fn parse(bytes: &[u8]) -> Self {
        let mut r = fa_model::Reader::new(bytes);
        assert_eq!(r.bytes(64, "format").unwrap(), b"fa:scope-proof:v1");
        let path = |r: &mut fa_model::Reader<'_>| r.list(64, "path", |r| r.fixed("node")).unwrap();
        let statement = r.fixed("statement").unwrap();
        let count = r.u64("count").unwrap();
        let account = r.u128("account").unwrap();
        let from = r.i32("from").unwrap();
        let to = r.i32("to").unwrap();
        let lo = r.u64("lo").unwrap();
        let n = r.count(1 << 20, "items").unwrap();
        let mut items = Vec::new();
        for _ in 0..n {
            let d = r.i32("day").unwrap();
            let i = r.u64("leaf").unwrap();
            let p = path(&mut r);
            let e = r.bytes(1 << 20, "envelope").unwrap().to_vec();
            let a = path(&mut r);
            items.push((d, i, p, e, a));
        }
        let side = |r: &mut fa_model::Reader<'_>| {
            r.opt("side", |r| {
                Ok((
                    r.u128("a")?,
                    r.i32("d")?,
                    r.u64("i")?,
                    r.list(64, "path", |r| r.fixed("node"))?,
                ))
            })
            .unwrap()
        };
        let left = side(&mut r);
        let right = side(&mut r);
        r.finish().unwrap();
        Self {
            statement,
            count,
            account,
            from,
            to,
            lo,
            items,
            left,
            right,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let path = |w: &mut Writer, p: &Vec<[u8; 32]>| {
            w.list(p, |w, d| {
                w.fixed(d);
            });
        };
        w.bytes(b"fa:scope-proof:v1")
            .fixed(&self.statement)
            .u64(self.count)
            .u128(self.account)
            .i32(self.from)
            .i32(self.to)
            .u64(self.lo);
        w.list(&self.items, |w, (d, i, p, e, a)| {
            w.i32(*d).u64(*i);
            path(w, p);
            w.bytes(e);
            path(w, a);
        });
        for side in [&self.left, &self.right] {
            w.opt(side.as_ref(), |w, (a, d, i, p)| {
                w.u128(*a).i32(*d).u64(*i);
                path(w, p);
            });
        }
        w.finish().unwrap()
    }
}

/// Planted defects a dishonest producer could try, each refused: a dropped
/// in-scope tuple, a run claimed empty, an interval widened over its left
/// neighbour, two envelopes swapped, a proof against another checkpoint, an
/// index root the book key signed but that the journal does not derive, and
/// a scope the index cannot prove (FA-REF-126).
#[test]
fn planted_scope_defects_are_refused() {
    use fa_verify::{ScopeClaim, verify_scope};

    let mut h = harness();
    for (i, d) in [3u8, 7, 7, 8, 12, 12, 19].into_iter().enumerate() {
        h.post_on(
            h.rent,
            50 + i as i128,
            &[b'd', i as u8],
            d,
            EntryClass::ORIGINAL,
        );
        h.post_on(
            h.utilities,
            60 + i as i128,
            &[b'u', i as u8],
            d,
            EntryClass::ORIGINAL,
        );
    }
    let c = h.checkpointed();
    let signed = signed_checkpoint(&h, &c);
    let prove = |h: &Harness, state: &AccumulatorState, from: i32, to: i32| {
        fa_notary::prove_scope(
            &h.db,
            &h.book,
            state,
            &ScopeRequest::Account {
                account: h.rent,
                from,
                to,
            },
        )
        .unwrap()
        .unwrap()
    };
    let honest = prove(&h, &c.stored.state, day(7), day(12));
    let asked = ScopeClaim {
        account: h.rent.0,
        from: day(7),
        to: day(12),
    };
    let parsed = ScopeProof::parse(&honest);
    assert_eq!(parsed.items.len(), 5, "rent on days 7, 7, 8, 12, 12");
    assert!(
        verify_scope(&parsed.encode(), &signed, &asked, None).is_ok(),
        "re-encoding is faithful"
    );
    // Each planted proof is checked as the scope it claims, so the
    // defect itself, not a mismatch with the question, is what is refused.
    let refused = |p: &ScopeProof, what: &str| {
        let claim = ScopeClaim {
            account: p.account,
            from: p.from,
            to: p.to,
        };
        let result = verify_scope(&p.encode(), &signed, &claim, None);
        assert!(result.is_err(), "{what} was accepted");
        result.unwrap_err()
    };

    // 1. A dropped in-scope tuple, from the middle and from each end.
    for at in [2, 0, 4] {
        let mut p = parsed.clone();
        p.items.remove(at);
        if at == 0 {
            p.lo += 1;
        }
        let e = refused(&p, "a dropped tuple");
        assert!(
            matches!(e, VerifyError::ScopeRoot | VerifyError::ScopeRun),
            "{e}"
        );
    }
    // 2. The whole run claimed empty, neighbours kept.
    let mut p = parsed.clone();
    p.items.clear();
    let e = refused(&p, "a run claimed empty");
    assert!(
        matches!(e, VerifyError::ScopeRoot | VerifyError::ScopeRun),
        "{e}"
    );
    // 3. The interval widened so its left neighbour (rent, day 3) falls in.
    let mut p = parsed.clone();
    assert_eq!(
        p.left.as_ref().map(|l| (l.0, l.1)),
        Some((h.rent.0, day(3)))
    );
    p.from = day(3);
    assert_eq!(refused(&p, "a widened interval"), VerifyError::ScopeRun);
    // ... and on the right (rent, day 19).
    let mut p = parsed.clone();
    p.to = day(19);
    assert_eq!(refused(&p, "a widened interval"), VerifyError::ScopeRun);
    // 4. Two envelopes swapped between tuples of different days.
    let mut p = parsed.clone();
    let (first, last) = (p.items[0].3.clone(), p.items[4].3.clone());
    p.items[0].3 = last;
    p.items[4].3 = first;
    let e = refused(&p, "swapped envelopes");
    assert!(
        matches!(e, VerifyError::ScopeTuple { .. } | VerifyError::Inclusion),
        "{e}"
    );
    // 5. A proof against another checkpoint: a later prefix's proof does
    //    not verify against the earlier signed checkpoint.
    h.post_on(h.rent, 99, b"late", 8, EntryClass::ORIGINAL);
    let later = h.checkpointed();
    let late_proof = prove(&h, &later.stored.state, day(7), day(12));
    assert!(matches!(
        verify_scope(&late_proof, &signed, &asked, None),
        Err(VerifyError::NotTrusted { .. })
    ));
    // The earlier proof claims nothing past its prefix: the late entry is
    // not listed, and the report names the earlier checkpoint.
    let report = verify_scope(&honest, &signed, &asked, None).unwrap();
    assert_eq!(report.checkpoint.through_seq, c.stored.state.through_seq.0);
    assert_eq!(report.leaves.len(), 5);
    // A proof answers only the scope it was asked for: under another
    // question, even one with the same answer, it is refused.
    let mut other_question = asked;
    other_question.to = day(13);
    assert_eq!(
        verify_scope(&honest, &signed, &other_question, None),
        Err(VerifyError::ScopeClaim)
    );
    // 6. An index root the book's own key signed but the journal does not
    //    derive: the signature verifies, the scope paths do not open it,
    //    and recomputation from the complete prefix names the mismatch.
    let mut lying = c.checkpoint.checkpoint.body.clone();
    lying.scope_index_root = [0x5c; 32];
    let lying = fa_notary::TransparencyCheckpoint::sign(lying, &[&h.signer]).unwrap();
    let lying =
        fa_verify::verify_checkpoint(&lying.canonical_bytes().unwrap(), &[h.signer.public_key()])
            .expect("the book key did sign it");
    assert_eq!(
        verify_scope(&honest, &lying, &asked, None),
        Err(VerifyError::ScopeRoot)
    );
    let prefix_proof = prove_prefix(&h.db, &h.book, &c.stored.state)
        .unwrap()
        .unwrap();
    assert_eq!(
        fa_verify::recompute_index(&prefix_proof, &lying),
        Err(VerifyError::ScopeIndexDerivation)
    );
    assert_eq!(fa_verify::recompute_index(&prefix_proof, &signed), Ok(()));
    // 7. Scopes the index cannot prove are refused, naming the prefix.
    for request in [
        ScopeRequest::Book {
            from: day(1),
            to: day(31),
        },
        ScopeRequest::Accounts {
            accounts: vec![h.rent, h.utilities],
            from: day(1),
            to: day(31),
        },
        ScopeRequest::Account {
            account: h.rent,
            from: day(12),
            to: day(7),
        },
    ] {
        let refusal = fa_notary::prove_scope(&h.db, &h.book, &c.stored.state, &request)
            .unwrap()
            .expect_err("unsupported scope");
        assert_eq!(refusal.code, code::SCOPE_UNSUPPORTED);
        assert_eq!(refusal.exit, exit::REFUSAL);
        assert!(refusal.fix.contains("prove_prefix"), "{}", refusal.fix);
    }
}

// ---- evidence bundles and production receipts (fa-l3c slice 5) -------------

impl Harness {
    /// Record another source document; its citation in `role`.
    fn document(&mut self, bytes: &[u8], role: u8) -> EvidenceRef {
        let doc = Document {
            book_id: self.book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: bytes.to_vec(),
        };
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async { add_document(db, &ctx, book, &doc).await })
            .expect("kernel")
            .expect("the document is admitted");
        doc.evidence_ref(role)
    }

    fn bundle(
        &self,
        state: &StoredState,
        request: &BundleRequest,
    ) -> Result<fa_notary::Bundle, Refusal> {
        let (journal, checkpoint) =
            bundle_basis(&self.db, &self.ctx(), &self.book, state, &self.signer)
                .expect("kernel")?;
        // The facade reads each cited document as its capability may see it
        // (`read_document_for`, fa crate tests); these fixtures' documents
        // are inline and ungoverned, so the format tests read them whole.
        let mut documents = std::collections::BTreeMap::new();
        for oid in fa_notary::bundle::cited_documents(&journal, request).expect("kernel")? {
            let doc = read_document(&self.db, &oid)
                .expect("kernel")?
                .expect("a cited document is held");
            documents.insert(oid, DocumentRead::Full(doc));
        }
        let runs = fa_notary::migration_balance::bundle_run_bodies(&self.db, &journal, request)
            .expect("kernel")?;
        fa_notary::bundle::assemble_with_runs(&journal, &checkpoint, request, &documents, &runs)
            .expect("kernel")
    }

    fn receipt(&self, bundle: &fa_notary::Bundle, at: CommitSeq) -> Vec<u8> {
        ProductionReceipt::sign(
            ReceiptBody {
                bundle_digest: bundle.digest,
                producer_principal: PRINCIPAL,
                produced_at_seq: at,
                capability_commitment: [0xcc; 32],
                time_evidence_oid: None,
            },
            &self.signer,
        )
        .unwrap()
        .canonical_bytes()
        .unwrap()
    }
}

/// Postings citing one document, then two (a second document joins the
/// citation list), a hold, and a later rent, published as one state:
/// `[rent on the 3rd, utilities on the 9th, hold on the 12th, rent on the 20th]`.
fn bundle_book() -> (Harness, fa_notary::Checkpointed, [VId; 4]) {
    let mut h = harness();
    let rent_3 = h.post_on(h.rent, 120_000, b"b-rent-3", 3, EntryClass::ORIGINAL);
    let lease = h.document(b"LEASE (a second source document)", 2);
    h.evidence.push(lease);
    h.evidence.sort();
    let utilities = h.post_on(h.utilities, 4_500, b"b-util", 9, EntryClass::ORIGINAL);
    let hold = h.post_on(h.utilities, 700, b"b-hold", 12, EntryClass::PENDING);
    let rent_20 = h.post_on(h.rent, 60_000, b"b-rent-20", 20, EntryClass::ORIGINAL);
    let c = h.checkpointed();
    (h, c, [rent_3, utilities, hold, rent_20])
}

fn balance(account: VId, unit: UnitId, through: Option<i32>) -> BalanceRequest {
    BalanceRequest {
        account,
        unit: unit.0,
        effective_through: through,
    }
}

/// `(check, subject, reason)` of every check that did not pass, with
/// `unrun:` marking the ones that did not run.
fn not_passed(report: &fa_verify::BundleReport) -> Vec<(&'static str, String, String)> {
    report
        .checks
        .iter()
        .filter_map(|c| match &c.grade {
            fa_verify::Grade::Pass => None,
            fa_verify::Grade::Fail(why) => Some((c.check, c.subject.clone(), why.clone())),
            fa_verify::Grade::Unrun(why) => {
                Some((c.check, c.subject.clone(), format!("unrun: {why}")))
            }
        })
        .collect()
}

fn names(failed: &[(&'static str, String, String)]) -> Vec<&'static str> {
    failed.iter().map(|f| f.0).collect()
}

/// A bundle of each scope verifies predicate by predicate with nothing but
/// fa-verify and the book's key, with its production receipt; the same
/// request against the same checkpoint is the same bytes; each scope is
/// reported under its own completeness label (named entries as
/// `membership_only`, never complete); and fa-verify's evidence decoder
/// agrees with the model's on every leaf of the prefix, control entries
/// included.
#[test]
fn bundles_of_every_scope_verify_predicate_by_predicate_and_reproduce_byte_for_byte() {
    let (h, c, [rent_3, utilities, _hold, rent_20]) = bundle_book();
    let pk = h.signer.public_key();
    let at = h.db.frontier().unwrap();
    let account = |account: VId, from: u8, to: u8| {
        BundleScope::Index(ScopeRequest::Account {
            account,
            from: day(from),
            to: day(to),
        })
    };
    let cases = [
        (
            BundleRequest {
                scope: BundleScope::Prefix,
                balances: vec![
                    balance(h.cash, h.usd, None),
                    balance(h.rent, h.usd, Some(day(10))),
                ],
                inline_documents: true,
            },
            "seq_range_complete",
        ),
        (
            BundleRequest {
                scope: account(h.rent, 1, 31),
                balances: vec![balance(h.rent, h.usd, None)],
                inline_documents: false,
            },
            "scope_index_complete",
        ),
        (
            BundleRequest {
                scope: account(h.rent, 4, 19),
                balances: Vec::new(),
                inline_documents: true,
            },
            "scope_index_complete",
        ),
        (
            BundleRequest {
                scope: BundleScope::Entries(vec![rent_20, utilities, rent_3, utilities]),
                balances: Vec::new(),
                inline_documents: true,
            },
            "membership_only",
        ),
    ];
    let mut entries = Vec::new();
    for (request, label) in &cases {
        let bundle = h.bundle(&c.stored, request).expect("produced");
        assert_eq!(h.bundle(&c.stored, request).unwrap(), bundle, "{label}");
        let receipt = h.receipt(&bundle, at);
        assert_eq!(h.receipt(&bundle, at), receipt, "Ed25519 is deterministic");
        let report =
            fa_verify::verify_bundle(&bundle.bytes, &[pk], Some(&receipt)).expect("readable");
        assert!(report.verified(), "{label}: {:#?}", not_passed(&report));
        assert_eq!(report.digest, bundle.digest);
        assert_eq!(report.manifest.checkpoint_oid, c.checkpoint.oid.0);
        let completeness = report
            .checks
            .iter()
            .find(|k| matches!(k.check, "completeness"))
            .unwrap();
        assert_eq!(completeness.scope, *label);
        assert_eq!(
            completeness
                .subject
                .contains("premise: the scope index as signed by"),
            *label == "scope_index_complete",
            "{}",
            completeness.subject
        );
        let facts = report.receipt.clone().expect("the receipt verified");
        assert_eq!(
            (facts.producer_principal, facts.produced_at_seq),
            (PRINCIPAL.0, at.0)
        );
        assert_eq!(facts.capability_commitment, [0xcc; 32]);
        assert_eq!(facts.time_evidence_oid, None);
        let count = |name: &str| report.checks.iter().filter(|k| k.check == name).count() as u64;
        assert_eq!(count("record"), report.summary.entries);
        assert_eq!(count("closure"), report.summary.entries);
        assert_eq!(count("public_commitment"), report.summary.documents);
        assert_eq!(count("recomputation"), request.balances.len() as u64);
        let inline = if request.inline_documents {
            report.summary.documents
        } else {
            0
        };
        assert_eq!(report.summary.inline, inline);
        entries.push(report.summary.entries);
    }
    // Every leaf; rent's two; none of rent's between the 4th and the 19th;
    // three distinct named entries.
    assert_eq!(entries[0], c.stored.state.leaf_count);
    assert_eq!(entries[1..], [2, 0, 3]);

    let journal = Journal::read(&h.db, &h.book, Some(c.stored.state.through_seq))
        .unwrap()
        .unwrap();
    let mut controls = 0;
    let mut two_documents = 0;
    for leaf in &journal.leaves {
        let entry = fa_model::Entry::decode(&leaf.payload).unwrap();
        controls += usize::from(entry.proposal.control.is_some());
        let mut model: Vec<[u8; 32]> = entry
            .proposal
            .evidence
            .iter()
            .map(|e| e.doc_commit)
            .collect();
        model.sort_unstable();
        model.dedup();
        two_documents += usize::from(model.len() == 2);
        assert_eq!(
            fa_verify::envelope::cited_documents(&leaf.payload[..leaf.proposal_len]).unwrap(),
            model
        );
    }
    assert!(controls >= 2, "the chart install and the period opening");
    assert_eq!(two_documents, 3, "utilities, the hold, and the later rent");
}

/// An import run's control record (fa-txf part A, control tag 13) decodes
/// in fa-verify exactly: the decoder differential holds on its leaf (it
/// cites no document), and a prefix bundle over a book holding one
/// verifies predicate by predicate.
#[test]
fn an_import_run_control_record_decodes_in_fa_verify() {
    let mut h = harness();
    h.post(h.rent, 1_000, b"r1");
    let req = ImportRequest {
        principal: PRINCIPAL,
        source: fa_model::IntakeSource::Connector {
            name: "fa-import".into(),
            version: "1".into(),
        },
        idempotency_key: b"import".to_vec(),
        effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
        description: seal_text(&h, "import"),
        documents: vec![Document {
            book_id: h.book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"INVOICE (imported)".to_vec(),
        }],
    };
    let ctx = h.ctx();
    let cap = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let (db, book) = (&mut h.db, &h.book);
    let recorded = h
        .runtime
        .block_on(async move { import_run(db, &ctx, book, &cap, req).await })
        .expect("kernel")
        .expect("imported");
    let stored = h.checkpoint();
    let journal = Journal::read(&h.db, &h.book, Some(stored.state.through_seq))
        .unwrap()
        .unwrap();
    let leaf = journal
        .leaves
        .iter()
        .find(|l| l.vid == recorded.receipt.run)
        .expect("the run's control entry is a leaf");
    assert_eq!(leaf.envelope.class, EntryClass::IMPORT_CONTROL);
    assert_eq!(
        fa_verify::envelope::cited_documents(&leaf.payload[..leaf.proposal_len]).unwrap(),
        Vec::<[u8; 32]>::new()
    );
    let bundle = h
        .bundle(
            &stored,
            &BundleRequest {
                scope: BundleScope::Prefix,
                balances: Vec::new(),
                inline_documents: true,
            },
        )
        .expect("produced");
    let report = fa_verify::verify_bundle(&bundle.bytes, &[h.signer.public_key()], None).unwrap();
    assert!(report.verified(), "{:#?}", report.checks);
}

/// A bundle cut at its list boundaries (the layout in fa-verify's `bundle`
/// module), so a test can plant one defect and re-encode the rest exactly.
#[derive(Clone)]
struct Cut {
    head: Vec<u8>,
    /// Where the manifest's completeness tag sits in `head`.
    completeness_at: usize,
    entries: Vec<CutEntry>,
    balances: Vec<(Vec<u8>, u16, Vec<u8>)>,
    md: Vec<u8>,
}

type CutStub = ([u8; 32], u8, u64, [u8; 32], Option<Vec<u8>>);

#[derive(Clone)]
struct CutEntry {
    leaf_index: u64,
    proposal_len: u32,
    record: Vec<u8>,
    stubs: Vec<CutStub>,
}

impl Cut {
    fn of(bytes: &[u8]) -> Self {
        const ANY: usize = usize::MAX;
        let mut r = fa_model::Reader::new(bytes);
        r.bytes(64, "format").unwrap();
        r.u16("major").unwrap();
        r.u16("minor").unwrap();
        r.fixed::<16>("book").unwrap();
        r.fixed::<16>("branch").unwrap();
        r.u64("through").unwrap();
        r.u64("leaves").unwrap();
        r.fixed::<32>("checkpoint_oid").unwrap();
        let scope = r.u8("scope").unwrap();
        if scope == 2 {
            r.u128("account").unwrap();
            r.i32("from").unwrap();
            r.i32("to").unwrap();
        } else if scope == 3 {
            let n = r.count(ANY, "named").unwrap();
            for _ in 0..n {
                r.u64("leaf").unwrap();
            }
        }
        let completeness_at = r.offset();
        if r.u8("completeness").unwrap() == 1 {
            r.u64("from").unwrap();
            r.u64("to").unwrap();
        }
        r.bytes(ANY, "checkpoint").unwrap();
        if scope == 3 {
            let n = r.count(ANY, "members").unwrap();
            for _ in 0..n {
                r.bytes(ANY, "envelope").unwrap();
                let p = r.count(ANY, "path").unwrap();
                for _ in 0..p {
                    r.fixed::<32>("node").unwrap();
                }
            }
        } else {
            r.bytes(ANY, "proof").unwrap();
        }
        let head = bytes[..r.offset()].to_vec();
        let entries = r
            .list(ANY, "entries", |r| {
                Ok(CutEntry {
                    leaf_index: r.u64("leaf_index")?,
                    proposal_len: r.u32("proposal_len")?,
                    record: r.bytes(ANY, "record")?.to_vec(),
                    stubs: r.list(ANY, "stubs", |r| {
                        Ok((
                            r.fixed("doc_commit")?,
                            r.u8("kind")?,
                            r.u64("length")?,
                            r.fixed("chunk_root")?,
                            r.opt("document", |r| Ok(r.bytes(ANY, "document")?.to_vec()))?,
                        ))
                    })?,
                })
            })
            .unwrap();
        let balances = r
            .list(ANY, "balances", |r| {
                Ok((
                    r.bytes(64, "domain")?.to_vec(),
                    r.u16("version")?,
                    r.bytes(ANY, "proof")?.to_vec(),
                ))
            })
            .unwrap();
        let md = r.bytes(ANY, "manifest_md").unwrap().to_vec();
        r.finish().unwrap();
        Self {
            head,
            completeness_at,
            entries,
            balances,
            md,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.head)
            .list(&self.entries, |w, e| {
                w.u64(e.leaf_index)
                    .u32(e.proposal_len)
                    .bytes(&e.record)
                    .list(&e.stubs, |w, (commit, kind, length, root, inline)| {
                        w.fixed(commit).u8(*kind).u64(*length).fixed(root).opt(
                            inline.as_ref(),
                            |w, b| {
                                w.bytes(b);
                            },
                        );
                    });
            })
            .list(&self.balances, |w, (domain, version, proof)| {
                w.bytes(domain).u16(*version).bytes(proof);
            })
            .bytes(&self.md);
        w.finish().unwrap()
    }

    /// Regenerate `manifest_md` for the planted body with fa-verify's own
    /// generator, so the planted defect is the only one.
    fn with_md(mut self, manifest: &fa_verify::Manifest) -> Self {
        let summary = fa_verify::Summary {
            format: (1, 0),
            entries: self.entries.len() as u64,
            documents: self.entries.iter().map(|e| e.stubs.len() as u64).sum(),
            inline: self
                .entries
                .iter()
                .flat_map(|e| &e.stubs)
                .filter(|s| s.4.is_some())
                .count() as u64,
            balances: self
                .balances
                .iter()
                .map(|(d, v, _)| (d.clone(), *v))
                .collect(),
        };
        self.md = fa_verify::bundle::manifest_md(manifest, &summary).into_bytes();
        self
    }

    fn position(&self, leaf: u64) -> usize {
        self.entries
            .iter()
            .position(|e| e.leaf_index == leaf)
            .unwrap()
    }
}

/// Every planted defect fails the predicate it breaks — and, where the
/// grading says so, leaves the predicates resting on it unrun — while the
/// untouched predicates still pass: an omitted entry, a padded entry, a
/// payload swapped under its envelope, a document whose bytes or stub do
/// not match, a stub the entry does not cite, a citation without a stub, a
/// reordered body, a receipt over another bundle or by another key, an
/// untrusted key, an edited manifest text, a completeness claim the scope
/// does not admit, a fold law the verifier does not implement, and a
/// format version it does not implement.
#[test]
fn planted_bundle_defects_fail_the_predicate_they_break() {
    use fa_verify::{BundleError, verify_bundle};

    let (h, c, [rent_3, utilities, _hold, rent_20]) = bundle_book();
    let pk = h.signer.public_key();
    let at = h.db.frontier().unwrap();
    let journal = Journal::read(&h.db, &h.book, Some(c.stored.state.through_seq))
        .unwrap()
        .unwrap();
    let leaf = |vid: VId| journal.leaf_index(vid).unwrap() as u64;
    let (rent_3, utilities, rent_20) = (leaf(rent_3), leaf(utilities), leaf(rent_20));

    let prefix = h
        .bundle(
            &c.stored,
            &BundleRequest {
                scope: BundleScope::Prefix,
                balances: vec![balance(h.cash, h.usd, None)],
                inline_documents: true,
            },
        )
        .unwrap();
    let base = verify_bundle(&prefix.bytes, &[pk], None).unwrap();
    assert!(base.verified(), "{:#?}", not_passed(&base));
    let cut = Cut::of(&prefix.bytes);
    assert_eq!(cut.bytes(), prefix.bytes, "the cut re-encodes exactly");
    let check = |planted: Cut, manifest: &fa_verify::Manifest| {
        not_passed(&verify_bundle(&planted.with_md(manifest).bytes(), &[pk], None).unwrap())
    };
    let m = &base.manifest;

    // 1. An omitted entry.
    let mut omitted = cut.clone();
    omitted.entries.remove(omitted.position(rent_20));
    let failed = check(omitted, m);
    assert_eq!(names(&failed), ["entries"], "{failed:#?}");
    assert!(
        failed[0]
            .2
            .contains(&format!("in-scope leaf {rent_20} has no entry"))
    );

    // 2. A padded entry: the utilities entry inside rent's account scope.
    let rent_scope = h
        .bundle(
            &c.stored,
            &BundleRequest {
                scope: BundleScope::Index(ScopeRequest::Account {
                    account: h.rent,
                    from: day(1),
                    to: day(31),
                }),
                balances: Vec::new(),
                inline_documents: true,
            },
        )
        .unwrap();
    let rent_report = verify_bundle(&rent_scope.bytes, &[pk], None).unwrap();
    assert!(rent_report.verified(), "{:#?}", not_passed(&rent_report));
    let mut padded = Cut::of(&rent_scope.bytes);
    padded
        .entries
        .push(cut.entries[cut.position(utilities)].clone());
    padded.entries.sort_by_key(|e| e.leaf_index);
    let failed = check(padded, &rent_report.manifest);
    assert_eq!(
        names(&failed),
        ["entries", "record", "closure"],
        "{failed:#?}"
    );
    assert!(failed[0].2.contains("padded"), "{}", failed[0].2);
    assert!(failed[1].2.starts_with("unrun:") && failed[2].2.starts_with("unrun:"));

    // 3. Two payloads swapped under their envelopes.
    let mut swapped = cut.clone();
    let (a, b) = (swapped.position(rent_3), swapped.position(rent_20));
    let (ra, rb) = (swapped.entries[a].clone(), swapped.entries[b].clone());
    (swapped.entries[a].record, swapped.entries[a].proposal_len) = (rb.record, rb.proposal_len);
    (swapped.entries[b].record, swapped.entries[b].proposal_len) = (ra.record, ra.proposal_len);
    let failed = check(swapped, m);
    assert_eq!(
        names(&failed),
        ["record", "closure", "record", "closure"],
        "{failed:#?}"
    );
    assert!(failed[1].2.starts_with("unrun:"));

    // 4a. An included document whose bytes are not the committed document.
    let mut altered = cut.clone();
    let u = altered.position(utilities);
    if let Some(bytes) = altered.entries[u].stubs[0].4.as_mut() {
        bytes[0] ^= 1;
    }
    let failed = check(altered, m);
    assert_eq!(names(&failed), ["public_commitment"], "{failed:#?}");
    assert!(
        failed[0].2.contains("chunk root differs"),
        "{}",
        failed[0].2
    );
    // 4b. A stub's length that its commitment does not commit.
    let mut lying = cut.clone();
    lying.entries[u].stubs[1].2 += 1;
    let failed = check(lying, m);
    assert_eq!(names(&failed), ["public_commitment"], "{failed:#?}");
    // 4c. A cited document without a stub.
    let mut missing = cut.clone();
    let dropped = missing.entries[u].stubs.remove(1);
    let failed = check(missing, m);
    assert_eq!(names(&failed), ["closure"], "{failed:#?}");
    assert!(failed[0].2.contains("has no stub"), "{}", failed[0].2);
    // 4d. A stub the entry does not cite (rent on the 3rd cites one document).
    let mut extra = cut.clone();
    let r = extra.position(rent_3);
    extra.entries[r].stubs.push(dropped);
    extra.entries[r].stubs.sort_by_key(|s| s.0);
    let failed = check(extra, m);
    assert_eq!(names(&failed), ["closure"], "{failed:#?}");
    assert!(failed[0].2.contains("not cited"), "{}", failed[0].2);

    // 5. A reordered body is refused whole, and is another digest.
    let mut reordered = cut.clone();
    reordered.entries.swap(a, b);
    let bytes = reordered.bytes();
    assert!(matches!(
        verify_bundle(&bytes, &[pk], None),
        Err(BundleError::Decode(e)) if e.reason == fa_verify::codec::Reason::Unsorted
    ));
    assert_ne!(fa_verify::bundle::bundle_digest(&bytes), prefix.digest);

    // 6. Receipts: over another bundle, by another key, with a flipped bit.
    let receipt = h.receipt(&prefix, at);
    let r = not_passed(&verify_bundle(&rent_scope.bytes, &[pk], Some(&receipt)).unwrap());
    assert_eq!(names(&r), ["production_receipt"]);
    assert!(r[0].2.contains("not this one"), "{}", r[0].2);
    let other = SigningKey::from_seed(&[0x01; 32]);
    let foreign =
        ProductionReceipt::sign(ProductionReceipt::decode(&receipt).unwrap().body, &other)
            .unwrap()
            .canonical_bytes()
            .unwrap();
    let r = not_passed(&verify_bundle(&prefix.bytes, &[pk], Some(&foreign)).unwrap());
    assert_eq!(names(&r), ["production_receipt"]);
    assert!(r[0].2.contains("did not name as trusted"), "{}", r[0].2);
    let mut flipped = receipt.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x10;
    let r = not_passed(&verify_bundle(&prefix.bytes, &[pk], Some(&flipped)).unwrap());
    assert_eq!(names(&r), ["production_receipt"]);
    assert!(r[0].2.contains("does not verify"), "{}", r[0].2);

    // 7. An untrusted key: the checkpoint fails, everything resting on it
    // is unrun, and the stubs — checked against their own commitments —
    // still pass; the receipt is by a key the caller did not name.
    let report = verify_bundle(&prefix.bytes, &[other.public_key()], Some(&receipt)).unwrap();
    for k in &report.checks {
        let expected = match k.check {
            "checkpoint" | "production_receipt" => "fail",
            "public_commitment" => "pass",
            _ => "unrun",
        };
        let got = match k.grade {
            fa_verify::Grade::Pass => "pass",
            fa_verify::Grade::Fail(_) => "fail",
            fa_verify::Grade::Unrun(_) => "unrun",
        };
        assert_eq!((k.check, got), (k.check, expected), "{}", k.subject);
    }

    // 8. A manifest text that says something else.
    let mut text = cut.clone().with_md(m);
    text.md[2] ^= 0x20;
    let failed = not_passed(&verify_bundle(&text.bytes(), &[pk], None).unwrap());
    assert_eq!(names(&failed), ["manifest"], "{failed:#?}");

    // 9. Named entries claiming completeness: refused as the manifest's
    // claim, while membership itself still verifies.
    let named = h
        .bundle(
            &c.stored,
            &BundleRequest {
                scope: BundleScope::Entries(vec![journal.leaves[rent_3 as usize].vid]),
                balances: Vec::new(),
                inline_documents: false,
            },
        )
        .unwrap();
    let named_report = verify_bundle(&named.bytes, &[pk], None).unwrap();
    assert!(named_report.verified(), "{:#?}", not_passed(&named_report));
    let mut inflated = Cut::of(&named.bytes);
    let mut claim = vec![1u8];
    claim.extend_from_slice(&0u64.to_le_bytes());
    claim.extend_from_slice(&c.stored.state.leaf_count.to_le_bytes());
    let at_tag = inflated.completeness_at;
    let replaced: Vec<u8> = inflated.head.splice(at_tag..=at_tag, claim).collect();
    assert_eq!(replaced, [3], "FilterAttested");
    let mut claimed = named_report.manifest.clone();
    claimed.completeness = fa_verify::Completeness::SeqRangeComplete {
        from: 0,
        to: c.stored.state.leaf_count,
    };
    let report = verify_bundle(&inflated.with_md(&claimed).bytes(), &[pk], None).unwrap();
    let failed = not_passed(&report);
    assert_eq!(names(&failed), ["manifest"], "{failed:#?}");
    assert!(
        failed[0]
            .2
            .contains("only admissible claim is membership_only")
    );
    let completeness = report
        .checks
        .iter()
        .find(|k| matches!(k.check, "completeness"))
        .unwrap();
    assert_eq!(completeness.scope, "membership_only");

    // 10. A balance under a fold law this verifier does not implement.
    let mut v3 = cut.clone();
    v3.balances[0].0 = b"fa:register-fold:v3".to_vec();
    v3.balances[0].1 = 3;
    let failed = check(v3, m);
    assert_eq!(names(&failed), ["recomputation"], "{failed:#?}");
    assert!(
        failed[0].2.contains("`fa:register-fold:v3` version 3"),
        "{}",
        failed[0].2
    );

    // 11. A bundle targeting another fa-verify format.
    let mut v2 = prefix.bytes.clone();
    let major_at = 4 + fa_notary::bundle::BUNDLE_FORMAT.len();
    v2[major_at] = 2;
    assert_eq!(
        verify_bundle(&v2, &[pk], None).unwrap_err(),
        BundleError::Version { major: 2, minor: 0 }
    );
}

/// The index proves one account's interval and nothing wider (FA-REF-126,
/// naming the prefix); named entries must be inside the checkpoint's
/// prefix (FA-REF-120).
#[test]
fn bundles_refuse_scopes_the_index_cannot_prove_and_entries_beyond_the_prefix() {
    let (mut h, c, _) = bundle_book();
    for request in [
        ScopeRequest::Book {
            from: day(1),
            to: day(31),
        },
        ScopeRequest::Accounts {
            accounts: vec![h.rent, h.utilities],
            from: day(1),
            to: day(31),
        },
    ] {
        let refusal = h
            .bundle(
                &c.stored,
                &BundleRequest {
                    scope: BundleScope::Index(request),
                    balances: Vec::new(),
                    inline_documents: false,
                },
            )
            .unwrap_err();
        assert_eq!(refusal.code, code::SCOPE_UNSUPPORTED);
        assert!(refusal.fix.contains("prove_prefix"), "{}", refusal.fix);
    }
    let later = h.post(h.rent, 1, b"after the checkpoint");
    let refusal = h
        .bundle(
            &c.stored,
            &BundleRequest {
                scope: BundleScope::Entries(vec![later]),
                balances: Vec::new(),
                inline_documents: false,
            },
        )
        .unwrap_err();
    assert_eq!(refusal.code, code::NOT_IN_PREFIX);
}

/// A bundle's balance claim is defined under the register fold law it
/// names: the producer's law, the verifier's implemented law and the
/// book's register fold digest domain are one law, so changing the
/// register fold (fa-l3c slice 4b) fails here until a new law is named.
#[test]
fn the_bundle_balance_law_is_the_register_fold_law() {
    use fa_notary::bundle::{BALANCE_FOLD_DOMAIN, BALANCE_FOLD_VERSION};
    assert_eq!(BALANCE_FOLD_DOMAIN, fa_registers::FOLD_DIGEST_DOMAIN);
    assert_eq!(
        fa_verify::bundle::FOLD_DOMAIN,
        fa_registers::FOLD_DIGEST_DOMAIN
    );
    assert_eq!(fa_verify::bundle::FOLD_VERSION, BALANCE_FOLD_VERSION);
    assert!(
        fa_registers::FOLD_DIGEST_DOMAIN.ends_with(format!(":v{BALANCE_FOLD_VERSION}").as_bytes())
    );
}

#[test]
fn bundle_limits_refuse_too_many_balances_and_oversized_inline_documents_while_admitting_stubs() {
    let (h, c, _) = bundle_book();
    let (journal, checkpoint) = bundle_basis(&h.db, &h.ctx(), &h.book, &c.stored, &h.signer)
        .unwrap()
        .unwrap();

    // 1. More than MAX_BUNDLE_BALANCES (4096) balance claims are refused
    // cleanly with FA-REF-129 in both cited_documents and assemble.
    let too_many_balances = BundleRequest {
        scope: BundleScope::Prefix,
        balances: vec![balance(h.cash, h.usd, None); fa_notary::MAX_BUNDLE_BALANCES + 1],
        inline_documents: false,
    };
    let cited_err = fa_notary::bundle::cited_documents(&journal, &too_many_balances)
        .unwrap()
        .unwrap_err();
    assert_eq!(cited_err.code, code::BUNDLE_LIMIT);
    assert_eq!(cited_err.exit, exit::REFUSAL);
    let assemble_err = fa_notary::bundle::assemble(
        &journal,
        &checkpoint,
        &too_many_balances,
        &std::collections::BTreeMap::new(),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(assemble_err.code, code::BUNDLE_LIMIT);
    assert_eq!(assemble_err.exit, exit::REFUSAL);

    // 2. An entry citing a document over MAX_INLINE_DOCUMENT_BYTES (16 MiB)
    // is refused with FA-REF-129 when inline_documents is true, and succeeds
    // as a stub-only .fab bundle when inline_documents is false.
    let oversized_doc = Document {
        book_id: h.book.book_id,
        kind: 1,
        mime: "application/octet-stream".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: vec![0xab; fa_notary::MAX_INLINE_DOCUMENT_BYTES + 1],
    };
    let doc_oid = oversized_doc.oid();
    let legs = vec![
        LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 500)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 500)),
    ];
    let proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: h.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay::from_ymd(2026, 3, 21).unwrap(),
        document_date: None,
        description: Erasable::seal(
            &"oversized evidence".to_string(),
            None,
            &h.book.seal_key,
            [1; 32],
            [2; 24],
        ),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"oversized-doc".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![oversized_doc.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let synthetic = Journal::from_records(
        h.book.book_id,
        CommitSeq(10),
        vec![(VId(999), entry, CommitSeq(5))],
    )
    .unwrap();
    let state = AccumulatorState::of_journal(&synthetic, None);
    let state_oid = state_oid(&state.canonical_bytes().unwrap());
    let body = fa_notary::checkpoint::CheckpointBody {
        statement: synthetic.statement(),
        state_oid,
        scope_index_root: [0; 32],
        substrate_chain_commitment: [0; 32],
        witness_policy_oid: None,
        time_evidence_oid: None,
    };
    let signed = fa_notary::TransparencyCheckpoint::sign(body, &[&h.signer]).unwrap();
    let signed_bytes = signed.canonical_bytes().unwrap();
    let stored_cp = fa_notary::StoredCheckpoint {
        oid: fa_notary::checkpoint::checkpoint_oid(&signed_bytes),
        vid: checkpoint_vid(&state_oid),
        checkpoint: signed,
        bytes: signed_bytes,
    };
    let mut docs = std::collections::BTreeMap::new();
    docs.insert(doc_oid, DocumentRead::Full(oversized_doc));

    let inline_err = fa_notary::bundle::assemble(
        &synthetic,
        &stored_cp,
        &BundleRequest {
            scope: BundleScope::Prefix,
            balances: Vec::new(),
            inline_documents: true,
        },
        &docs,
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(inline_err.code, code::BUNDLE_LIMIT);
    assert_eq!(inline_err.exit, exit::REFUSAL);

    let stub_only = fa_notary::bundle::assemble(
        &synthetic,
        &stored_cp,
        &BundleRequest {
            scope: BundleScope::Prefix,
            balances: Vec::new(),
            inline_documents: false,
        },
        &docs,
    )
    .unwrap()
    .expect("stub-only bundle succeeds on >16 MiB document");
    let report =
        fa_verify::verify_bundle(&stub_only.bytes, &[h.signer.public_key()], None).unwrap();
    assert!(report.verified(), "{:#?}", not_passed(&report));
    assert_eq!(report.summary.documents, 1);
    assert_eq!(report.summary.inline, 0);
}
