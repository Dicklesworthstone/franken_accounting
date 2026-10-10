//! Registers against the real in-memory substrate: the fold equals the posted
//! legs with the last commit as watermark; materialize-then-verify is green;
//! a tampered Register vertex is reported as drift (the journal wins); the
//! trial balance nets to zero per unit; control records contribute nothing.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::*;
use fa_model::symbols::property;
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey, SymbolTable,
    account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_registers::{fold_period, materialize, register_vid, trial_balance, verify_period};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, VId};

const PRINCIPAL: VId = VId(7);

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    rent: VId,
    march: String,
}

impl Harness {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn post_rent(&mut self, cents: i128, key: &[u8]) -> Posted {
        let legs = vec![
            LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, cents)),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"rent".to_string(),
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
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
        };
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::with_ops(&["post"]),
        };
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("admitted")
    }
}

fn harness() -> Harness {
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
        name: "Reg Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
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
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
        },
        AccountSpec {
            code: "6000".into(),
            name: "Rent".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
        },
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
    Harness {
        runtime,
        root,
        db,
        cash: account_vid(book_id, "1000"),
        rent: account_vid(book_id, "6000"),
        book,
        usd,
        march,
    }
}

#[test]
fn fold_equals_the_posted_legs_with_the_last_commit_as_watermark() {
    let mut h = harness();
    let empty = fold_period(&h.db, &h.book, &h.march).unwrap();
    assert!(
        empty.cells.is_empty() && empty.watermark.is_none() && empty.entries == 0,
        "the opening control record contributes nothing"
    );
    h.post_rent(1_000, b"r1");
    let p2 = h.post_rent(2_500, b"r2");
    let fold = fold_period(&h.db, &h.book, &h.march).unwrap();
    assert_eq!(fold.entries, 2);
    assert_eq!(fold.watermark, Some(p2.recorded_at()));
    assert_eq!(fold.cells.len(), 2);
    let cash = fold.cells.iter().find(|c| c.key.account == h.cash).unwrap();
    let rent = fold.cells.iter().find(|c| c.key.account == h.rent).unwrap();
    assert_eq!((cash.debits, cash.credits, cash.entry_count), (0, 3_500, 2));
    assert_eq!((rent.debits, rent.credits, rent.entry_count), (3_500, 0, 2));
    // Deterministic: the same journal folds to the same digest; a new post changes it.
    assert_eq!(
        fold.fold_digest,
        fold_period(&h.db, &h.book, &h.march).unwrap().fold_digest
    );
    h.post_rent(1, b"r3");
    assert_ne!(
        fold.fold_digest,
        fold_period(&h.db, &h.book, &h.march).unwrap().fold_digest
    );
}

#[test]
fn materialize_then_verify_is_green_and_a_tampered_register_is_drift() {
    let mut h = harness();
    h.post_rent(1_000, b"r1");
    let fold = fold_period(&h.db, &h.book, &h.march).unwrap();
    let ctx = h.ctx();
    h.runtime
        .block_on(async { materialize(&mut h.db, &ctx, &h.book, &fold).await })
        .expect("materialize");
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(v.is_green(), "{v:?}");
    assert_eq!(v.cells_checked, 2);

    // A later post makes the stored registers stale: verify says so, the
    // journal is untouched, and re-materializing restores green.
    h.post_rent(5, b"r2");
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(!v.is_green() && v.drift.len() == 2, "{v:?}");
    let fold = fold_period(&h.db, &h.book, &h.march).unwrap();
    h.runtime
        .block_on(async { materialize(&mut h.db, &ctx, &h.book, &fold).await })
        .expect("re-materialize");
    assert!(verify_period(&h.db, &h.book, &h.march).unwrap().is_green());

    // Tamper with a stored register directly: drift names the cell with both values.
    let cash_key = fold
        .cells
        .iter()
        .find(|c| c.key.account == h.cash)
        .unwrap()
        .key
        .clone();
    let rvid = register_vid(h.book.book_id, &cash_key);
    let mut batch = WriteBatch::new(fa_model::symbols::relation::IN_PERIOD);
    batch.set_vertex_property(
        rvid,
        property::CREDITS_POSTED,
        Some(CanonicalScalar::bytes(999i128.to_le_bytes().to_vec()).unwrap()),
    );
    h.runtime
        .block_on(async { h.db.write(&ctx.commit(), batch).await })
        .expect("tamper write");
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(!v.is_green());
    assert_eq!(v.drift.len(), 1);
    assert_eq!(v.drift[0].key, cash_key);
    assert_eq!(v.drift[0].stored, Some((0, 999, 2)));
    assert_eq!(v.drift[0].refolded, (0, 1_005, 2));
}

#[test]
fn trial_balance_nets_to_zero_per_unit_and_names_accounts() {
    let mut h = harness();
    h.post_rent(1_000, b"r1");
    h.post_rent(250, b"r2");
    let tb = trial_balance(&h.db, &h.book, &[h.march.clone()]).unwrap();
    assert!(tb.is_balanced());
    assert_eq!(tb.unit_totals.get(&h.usd.0), Some(&(1_250, 1_250)));
    assert_eq!(tb.rows.len(), 2);
    assert_eq!(
        (
            tb.rows[0].code.as_str(),
            tb.rows[0].debits,
            tb.rows[0].credits
        ),
        ("1000", 0, 1_250)
    );
    assert_eq!(
        (
            tb.rows[1].code.as_str(),
            tb.rows[1].debits,
            tb.rows[1].credits
        ),
        ("6000", 1_250, 0)
    );
    assert!(tb.rows[0].account_type.is_stock() && tb.rows[1].account_type.is_flow());
}
