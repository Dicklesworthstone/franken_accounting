//! Erasure never changes an amount (fa-lp6; plan §8.5; the consistency
//! oracle "erasure leaves amounts intact"), against the real in-memory
//! substrate.
//!
//! `ErasureCut` itself is a registered absence in this build (Appendix H
//! R-ERASE; `fa_journal::evidence::erasure_cut` refuses with FA-REF-088), and
//! per-Party subject keys are bead fa-v74. What this file proves is the
//! invariant any erasure mechanism must keep: once the key that seals an
//! entry's erasable fields is unavailable — the state an erasure produces —
//! the registers, the trial balance, and every entry's verified digests are
//! exactly what they were; equivalence over a field nobody can open is
//! refused (FA-REF-033), never guessed. The planted negative: an amount
//! rewritten inside a stored payload is detected, never folded.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{Document, add_document, erasure_cut};
use fa_journal::post::read_entry;
use fa_journal::*;
use fa_model::symbols::property;
use fa_model::{
    Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload, Oid,
    SealKey, SymbolTable,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_registers::{fold_period, trial_balance};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, VId};

const PRINCIPAL: VId = VId(7);
const CUSTOMER: VId = VId(42);

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    rent: VId,
    revenue: VId,
    march: String,
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    /// An entry whose description (and one leg memo) is erasable data:
    /// sealed under `key`, the memo naming a subject.
    fn proposal(
        &self,
        key: &SealKey,
        debit: VId,
        credit: VId,
        cents: i128,
        idem: &[u8],
        nonce: u8,
    ) -> EntryPayload {
        let mut legs = vec![
            LegPayload::simple(Side::Debit, debit, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, credit, Amount::new(self.usd, cents)),
        ];
        legs[0].memo = Some(Erasable::seal(
            &"customer: Jane Q. Example".to_string(),
            Some(CUSTOMER),
            key,
            [nonce; 32],
            [nonce; 24],
        ));
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"services for Jane Q. Example".to_string(),
                None,
                key,
                [nonce.wrapping_add(1); 32],
                [nonce.wrapping_add(1); 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: idem.to_vec(),
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

    fn post_under(
        &mut self,
        book: &BookContext,
        proposal: EntryPayload,
    ) -> Result<Posted, Refusal> {
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).expect("post"),
        };
        let ctx = self.ctx();
        let db = &mut self.db;
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
    }

    fn write_raw(&mut self, batch: WriteBatch) {
        let ctx = self.ctx();
        let db = &mut self.db;
        self.runtime
            .block_on(async move { db.write(&ctx.commit(), batch).await })
            .expect("raw write");
    }
}

fn harness() -> Harness {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x7a; 32],
        DatabaseSecurityNamespaceId([0x7b; 32]),
        [0x7c; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([0x4e; 16]);
    let spec = BookSpec {
        book_id,
        name: "Erasure Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
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
    let leaf = |code: &str, name: &str, account_type: u8, normal_balance: u8| AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type,
        normal_balance,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    };
    let chart = vec![
        leaf("1000", "Cash", 1, 0),
        leaf("4000", "Revenue", 4, 1),
        leaf("6000", "Rent", 5, 0),
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
                Erasable::seal(
                    &"period".to_string(),
                    None,
                    &book.seal_key,
                    [3; 32],
                    [4; 24],
                ),
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
        bytes: b"INVOICE 77 to Jane Q. Example (erasure fixture)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
        .expect("kernel")
        .expect("the fixture document is admitted");
    Harness {
        runtime,
        root,
        db,
        cash: account_vid_of(book_id, "1000"),
        revenue: account_vid_of(book_id, "4000"),
        rent: account_vid_of(book_id, "6000"),
        book,
        usd,
        march,
        evidence: vec![source.evidence_ref(1)],
    }
}

fn account_vid_of(book: Id128, code: &str) -> VId {
    fa_model::account_vid(book, code)
}

#[test]
fn key_loss_never_changes_an_amount_and_equivalence_is_never_guessed() {
    let mut h = harness();
    let key = h.book.seal_key.clone();
    let book = h.book.clone();
    let (cash, revenue, rent) = (h.cash, h.revenue, h.rent);
    let sale = h.proposal(&key, cash, revenue, 120_000, b"sale-1", 10);
    let mut vids = Vec::new();
    for p in [
        sale.clone(),
        h.proposal(&key, rent, cash, 45_000, b"rent-1", 20),
        h.proposal(&key, cash, revenue, 7_525, b"sale-2", 30),
    ] {
        vids.push(h.post_under(&book, p).expect("admitted").entry_ref().vid);
    }
    let fold = fold_period(&h.db, &book, &h.march).expect("fold");
    let tb = trial_balance(&h.db, &book, &[h.march.clone()]).expect("trial balance");
    let entries: Vec<Entry> = vids
        .iter()
        .map(|v| read_entry(&h.db, *v).unwrap().expect("entry row").0)
        .collect();
    assert_eq!(fold.entries, 3);

    // The key that sealed the descriptions and memos is gone: the state an
    // erasure produces. Nothing the book says about amounts changes.
    let mut erased = book.clone();
    erased.seal_key = SealKey([0xee; 32]);
    assert_eq!(fold_period(&h.db, &erased, &h.march).expect("fold"), fold);
    assert_eq!(
        trial_balance(&h.db, &erased, &[h.march.clone()]).expect("trial balance"),
        tb
    );
    for (vid, entry) in vids.iter().zip(&entries) {
        let (back, _) = read_entry(&h.db, *vid).unwrap().expect("entry row");
        assert_eq!(&back, entry, "digests verify without any key");
    }
    // The erased fields are unopenable, and their digests survive.
    let e = &entries[0];
    assert!(e.proposal.description.open(&erased.seal_key, 1024).is_err());
    assert!(
        e.proposal.description.open(&key, 1024).is_ok(),
        "control: the key opens it"
    );
    let memo = e.proposal.legs[0].memo.as_ref().expect("memo");
    assert_eq!(memo.subject_ref(), Some(CUSTOMER));
    assert!(memo.open(&erased.seal_key, 1024).is_err());
    assert_eq!(
        memo.field_digest(),
        sale.legs[0].memo.as_ref().unwrap().field_digest()
    );

    // Retry under the erased key: identical prepared bytes are the recorded
    // outcome; a re-sealed retry cannot be compared, so it is refused.
    let same = h.post_under(&erased, sale.clone()).expect("recorded");
    assert!(matches!(same, Posted::AlreadyRecorded { .. }), "{same:?}");
    let resealed = h.proposal(&erased.seal_key, cash, revenue, 120_000, b"sale-1", 99);
    let r = h.post_under(&erased, resealed).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-033", exit::CONFLICT), "{r}");

    // ErasureCut is a registered absence: refused, nothing written.
    let head = h.db.frontier().unwrap();
    let refused = erasure_cut(CUSTOMER);
    assert_eq!((refused.code, refused.exit), ("FA-REF-088", exit::REFUSAL));
    assert!(
        refused.cite.contains("R-ERASE") && refused.cite.contains("fa-v74"),
        "{}",
        refused.cite
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(fold_period(&h.db, &book, &h.march).expect("fold"), fold);
}

/// The planted negative: an amount rewritten inside a stored payload, its
/// digests left as they were, is detected — by the entry read and by the
/// fold — never folded as the new amount.
#[test]
fn an_amount_rewritten_in_a_stored_payload_is_detected_never_folded() {
    let mut h = harness();
    let key = h.book.seal_key.clone();
    let book = h.book.clone();
    let (cash, revenue) = (h.cash, h.revenue);
    let vid = h
        .post_under(
            &book,
            h.proposal(&key, cash, revenue, 120_000, b"sale-1", 10),
        )
        .expect("admitted")
        .entry_ref()
        .vid;
    let before = fold_period(&h.db, &book, &h.march).expect("fold");
    let (mut entry, _) = read_entry(&h.db, vid).unwrap().expect("entry row");
    // Balanced, so only the digests can tell: 1,200.00 becomes 0.01.
    for leg in &mut entry.proposal.legs {
        leg.amount.mantissa = 1;
    }
    entry.proposal.unit_totals = EntryPayload::fold_unit_totals(&entry.proposal.legs).unwrap();
    let tampered = entry.encode().expect("encodes with the stale digests");
    let mut batch = WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
    batch.set_vertex_property(
        vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(tampered).unwrap()),
    );
    h.write_raw(batch);

    assert!(read_entry(&h.db, vid).is_err(), "the entry read detects it");
    assert!(
        fold_period(&h.db, &book, &h.march).is_err(),
        "the fold refuses a payload whose digests do not verify (it was {before:?})"
    );
    assert!(trial_balance(&h.db, &book, &[h.march.clone()]).is_err());
}
