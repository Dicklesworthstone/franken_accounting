//! Balance assertions recorded as attestations (fa-g21 part 2; plan §9.4),
//! against the real in-memory substrate.
//!
//! A `RegisterEquals` claim is recorded only when it is exactly what the
//! book evaluates for its cell at its own sequence; it stays true forever
//! (a later entry is drift at head, not falsity); every recording refusal
//! is planted; a claim written outside the recorder is caught where it is
//! relied on. The seeded test compares every recorded claim's value with a
//! literal model: the running debit-minus-credit sum of the legs the test
//! itself committed to the cell, snapshotted at each commit sequence. Each
//! step logs what the kernel decided (`cargo test -- --nocapture`).
//!
//! No-claim boundary: a recorded assertion proves the book's fold at that
//! sequence equals the stated value; it says nothing about whether the bank
//! statement it cites is genuine.

use std::collections::BTreeMap;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::attestation::{
    Attestation, AttestationClaim, CapabilityBinding, Subject, read_attestation,
};
use fa_journal::evidence::{Document, add_document};
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload, Oid, SealKey,
    SymbolTable,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_registers::assertion::{assertion_holds, claim_of, record_register_equals};
use fa_registers::entity::{EntityCellKey, RegisterEquals, register_equals};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const PREPARER: VId = VId(7);
const CONTROLLER: VId = VId(8);
const SECOND_CONTROLLER: VId = VId(9);

struct Book {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    revenue: VId,
    march: String,
    statement: EvidenceRef,
}

impl Book {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn head(&self) -> CommitSeq {
        self.db.frontier().expect("frontier")
    }

    /// Post `cents` debit to cash, credit to revenue, citing the statement.
    fn post(&mut self, key: &[u8], cents: i128) -> Posted {
        let legs = vec![
            LegPayload::simple(Side::Debit, self.cash, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.revenue, Amount::new(self.usd, cents)),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"receipt".to_string(),
                None,
                &self.book.seal_key,
                [3; 32],
                [3; 24],
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
            principal_ref: PREPARER,
            session_ref: None,
            evidence: vec![self.statement],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PREPARER, &["post"]).expect("post"),
        };
        let ctx = self.ctx();
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("a balanced Original in an Open period posts")
    }

    fn cash_cell(&self) -> EntityCellKey {
        EntityCellKey {
            account: self.cash,
            unit_id: self.usd.0,
            period: self.march.clone(),
            entity: None,
        }
    }

    fn evaluate(&self, known_at: Option<CommitSeq>) -> RegisterEquals {
        register_equals(&self.db, &self.book, &self.cash_cell(), known_at).expect("evaluates")
    }

    fn record(
        &mut self,
        cap: &Capability,
        claim: &RegisterEquals,
        evidence: Vec<Oid>,
    ) -> Result<Attested, Refusal> {
        let ctx = self.ctx();
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(
                async move { record_register_equals(db, &ctx, book, cap, claim, evidence).await },
            )
            .expect("no foundation failure")
    }

    fn holds(&self, vid: VId) -> Option<bool> {
        assertion_holds(&self.db, &self.book, vid).expect("evaluates")
    }
}

fn controller(holder: VId) -> Capability {
    Capability::embedded(holder, &["reconcile"]).expect("reconcile")
}

fn book() -> Book {
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
    let book_id = Id128([0x6e; 16]);
    let spec = BookSpec {
        book_id,
        name: "Assertion Co".into(),
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
    let leaf = |code: &str, account_type: u8, normal_balance: u8| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type,
        normal_balance,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    };
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &[leaf("1000", 1, 0), leaf("4000", 4, 1)],
                PREPARER,
                day,
                b"chart",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
                &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
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
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
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
    runtime
        .block_on(async {
            transition_period(
                &mut db,
                &ctx,
                &book,
                &march,
                PeriodTransition::Open,
                PREPARER,
                1,
                b"open",
                Erasable::seal(&"open".to_string(), None, &book.seal_key, [3; 32], [4; 24]),
                &Capability::embedded(PREPARER, &["close"]).expect("close"),
                &[],
            )
            .await
        })
        .expect("kernel")
        .expect("opens");
    let statement = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: CONTROLLER,
        bytes: b"BANK STATEMENT March 2026 (assertion fixture)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &statement).await })
        .expect("kernel")
        .expect("admitted");
    Book {
        runtime,
        root,
        db,
        cash: fa_model::account_vid(book_id, "1000"),
        revenue: fa_model::account_vid(book_id, "4000"),
        book,
        usd,
        march,
        statement: statement.evidence_ref(1),
    }
}

#[test]
fn a_true_claim_is_recorded_once_per_attester_and_stays_true_after_a_later_entry() {
    let mut b = book();
    b.post(b"r-1", 120_000);
    b.post(b"r-2", 30_000);
    let claim = b.evaluate(None);
    eprintln!(
        "g21p2: cash cell at {} folds to {} (digest {})",
        claim.evaluated_known_at.0,
        claim.amount.mantissa,
        fa_journal::evidence::hex(&claim.fold_digest)
    );
    assert_eq!(claim.amount.mantissa, 150_000);
    let statement = vec![b.statement.document_oid];

    let recorded = b
        .record(&controller(CONTROLLER), &claim, statement.clone())
        .expect("recorded");
    eprintln!(
        "g21p2: recorded {:032x} at {:?}",
        recorded.vid.0, recorded.recorded_at
    );
    assert!(!recorded.already_recorded);
    let (stored, _) = read_attestation(&b.db, recorded.vid)
        .unwrap()
        .expect("readable");
    assert_eq!(
        stored.attestation.claim,
        AttestationClaim::RegisterEquals(claim_of(&claim))
    );
    assert_eq!(stored.attestation.evidence_refs, statement);
    assert_eq!(stored.attestation.principal, CONTROLLER);
    assert_eq!(b.holds(recorded.vid), Some(true));

    // The same claim again is its recorded outcome; a second controller's is
    // its own attestation.
    let again = b
        .record(&controller(CONTROLLER), &claim, statement.clone())
        .expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(again.vid, recorded.vid);
    let second = b
        .record(&controller(SECOND_CONTROLLER), &claim, statement.clone())
        .expect("recorded");
    assert_ne!(second.vid, recorded.vid);

    // A later entry into the attested period: the claim names its sequence
    // and stays true; the cell at head has drifted.
    b.post(b"r-3", 5_000);
    assert_eq!(b.holds(recorded.vid), Some(true));
    let head = b.evaluate(None);
    eprintln!(
        "g21p2: after a later entry the claim still holds; head folds to {} (drift {})",
        head.amount.mantissa,
        head.amount.mantissa - claim.amount.mantissa
    );
    assert_eq!(head.amount.mantissa, 155_000);
    // The claim at the earlier sequence is still recordable, and true.
    let earlier = b.evaluate(Some(claim.evaluated_known_at));
    assert_eq!(earlier, claim);
}

#[test]
fn every_recording_law_refuses_its_planted_negative() {
    let mut b = book();
    b.post(b"n-1", 70_000);
    let claim = b.evaluate(None);
    let statement = vec![b.statement.document_oid];
    let cap = controller(CONTROLLER);
    let mut wrong_amount = claim.clone();
    wrong_amount.amount.mantissa += 1;
    let mut wrong_digest = claim.clone();
    wrong_digest.fold_digest[0] ^= 1;
    let mut wrong_day = claim.clone();
    wrong_day.as_of_effective.0 -= 1;
    let mut wrong_unit = claim.clone();
    wrong_unit.amount.unit = UnitId(claim.amount.unit.0 + 1);
    let mut future = claim.clone();
    future.evaluated_known_at = CommitSeq(b.head().0 + 1_000);
    let ghost = Document {
        book_id: b.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: CONTROLLER,
        bytes: b"a statement never recorded".to_vec(),
    }
    .oid();
    let mut unsorted = vec![statement[0], ghost];
    unsorted.sort();
    unsorted.reverse();
    let agent = fa_journal::Capability::new(
        CONTROLLER,
        fa_journal::Profile::Agent,
        &[fa_journal::Op::Post],
        CONTROLLER,
    )
    .unwrap();
    let cases: Vec<(&str, Capability, RegisterEquals, Vec<Oid>, &str)> = vec![
        (
            "a wrong amount",
            cap.clone(),
            wrong_amount,
            statement.clone(),
            "FA-REF-140",
        ),
        (
            "a wrong fold digest",
            cap.clone(),
            wrong_digest,
            statement.clone(),
            "FA-REF-140",
        ),
        (
            "a wrong as-of day",
            cap.clone(),
            wrong_day,
            statement.clone(),
            "FA-REF-140",
        ),
        (
            "a wrong unit",
            cap.clone(),
            wrong_unit,
            statement.clone(),
            "FA-REF-140",
        ),
        (
            "a sequence after head",
            cap.clone(),
            future,
            statement.clone(),
            "FA-REF-140",
        ),
        (
            "an unheld statement",
            cap.clone(),
            claim.clone(),
            vec![ghost],
            "FA-REF-110",
        ),
        (
            "unsorted evidence",
            cap.clone(),
            claim.clone(),
            unsorted,
            "FA-REF-100",
        ),
        (
            "no reconcile op",
            Capability::embedded(CONTROLLER, &["post"]).unwrap(),
            claim.clone(),
            statement.clone(),
            "FA-REF-011",
        ),
        (
            "an agent",
            agent,
            claim.clone(),
            statement.clone(),
            "FA-REF-013",
        ),
    ];
    let before = b.head();
    for (what, cap, c, evidence, code) in cases {
        let r = b.record(&cap, &c, evidence).unwrap_err();
        eprintln!("g21p2: {what} -> {} {}", r.code, r.message);
        assert_eq!(r.code, code, "{what}: {r}");
        assert_eq!(b.head(), before, "{what}: nothing written");
    }
    // The true claim is still recordable after all of them.
    assert!(b.record(&cap, &claim, statement).is_ok());
}

#[test]
fn a_false_claim_written_outside_the_recorder_does_not_hold() {
    let mut b = book();
    b.post(b"f-1", 40_000);
    let claim = b.evaluate(None);
    let mut forged = claim_of(&claim);
    forged.mantissa += 1_000;
    let a = Attestation {
        book_id: b.book.book_id,
        subject: Subject::Cell(forged.cell_digest()),
        claim: AttestationClaim::RegisterEquals(forged),
        principal: CONTROLLER,
        evidence_refs: Vec::new(),
    };
    let vid = a.vid().expect("an identity");
    let binding = CapabilityBinding {
        profile: fa_journal::Profile::Human,
        capability_commitment: [0xf0; 32],
    };
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(a.canonical_bytes(&binding).unwrap()).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(a.signed_digest().unwrap().to_vec()).unwrap(),
        ),
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(a.book_id.0.to_vec()).unwrap(),
        ),
        (
            property::CODE,
            CanonicalScalar::ucs_basic_text(a.claim.name()).unwrap(),
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut batch = WriteBatch::new(relation::ATTESTS);
    batch.create_vertex(vid, vec![label::ATTESTATION], props);
    let ctx = b.ctx();
    let db = &mut b.db;
    b.runtime
        .block_on(async move { db.write(&ctx.commit(), batch).await })
        .expect("raw write");
    eprintln!("g21p2: a forged claim (+1000) holds? {:?}", b.holds(vid));
    assert_eq!(b.holds(vid), Some(false));
    // A vertex that is no RegisterEquals is not an assertion.
    assert_eq!(b.holds(VId(12_345)), None);
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn recorded_claims_agree_with_a_literal_running_sum_at_every_sequence() {
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for seed in [0x51ed_2701_8b3c_4d19_u64, 0x9e37_79b9_7f4a_7c15] {
        let mut rng = Rng(seed);
        let mut b = book();
        let statement = vec![b.statement.document_oid];
        // The literal model: the cash cell's net after each post, keyed by
        // the commit sequence that recorded it.
        let mut net: i128 = 0;
        let mut model: Vec<(CommitSeq, i128)> = Vec::new();
        let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
        for step in 0..60u64 {
            if rng.below(3) != 0 || model.is_empty() {
                let cents = i128::from(1 + rng.below(50_000));
                let posted = b.post(format!("s-{seed:x}-{step}").as_bytes(), cents);
                net += cents;
                model.push((posted.recorded_at(), net));
                *seen.entry("posted").or_default() += 1;
                continue;
            }
            // A claim at a random committed sequence, true or tampered.
            let i = usize::try_from(rng.below(u64::try_from(model.len()).unwrap())).unwrap();
            let (seq, expected) = model[i];
            let mut claim = b.evaluate(Some(seq));
            assert_eq!(
                claim.amount.mantissa, expected,
                "seed {seed:x} step {step}: the fold at {} is not the literal sum",
                seq.0
            );
            let tampered = rng.below(2) == 0;
            if tampered {
                claim.amount.mantissa += i128::from(1 + rng.below(9));
            }
            let holder = if rng.below(2) == 0 {
                CONTROLLER
            } else {
                SECOND_CONTROLLER
            };
            let got = b.record(&controller(holder), &claim, statement.clone());
            assert_eq!(
                got.is_err(),
                tampered,
                "seed {seed:x} step {step}: tampered={tampered}, recorder returned {got:?}"
            );
            match got {
                Ok(a) => {
                    assert_eq!(b.holds(a.vid), Some(true));
                    *seen
                        .entry(if a.already_recorded {
                            "re-recorded"
                        } else {
                            "recorded"
                        })
                        .or_default() += 1;
                }
                Err(r) => {
                    assert_eq!(r.code, "FA-REF-140", "seed {seed:x} step {step}: {r}");
                    *seen.entry("FA-REF-140").or_default() += 1;
                }
            }
        }
        eprintln!("g21p2 seed {seed:x}: {seen:?}");
        for key in ["posted", "recorded", "FA-REF-140"] {
            assert!(
                seen.get(key).copied().unwrap_or(0) >= 3,
                "seed {seed:x}: {key} reached {:?}: {seen:?}",
                seen.get(key)
            );
            *totals.entry(key).or_default() += seen[key];
        }
    }
    eprintln!("g21p2 totals: {totals:?}");
}
