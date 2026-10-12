//! Registers against the real in-memory substrate: the fold equals the posted
//! legs with the last commit as watermark; materialize-then-verify is green;
//! a tampered Register vertex is reported as drift (the journal wins); the
//! trial balance nets to zero per unit; control records contribute nothing.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{Document, add_document};
use fa_journal::rows::edge_id;
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef,
    Id128, LegPayload, Oid, Pending, SealKey, Supersession, SupersessionKind, SymbolTable,
    account_vid, period_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_registers::{
    CacheStatus, Cell, CellKey, Fold, RegisterError, balance_as_of, fold_period, fold_period_at,
    materialize, period_activity, period_activity_excluding_classes, register_vid, trial_balance,
    trial_balance_at, verify_period,
};
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
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn materialize_march(&mut self) -> Fold {
        self.materialize_period(&self.march.clone())
    }

    fn materialize_period(&mut self, period: &str) -> Fold {
        let fold = fold_period(&self.db, &self.book, period).expect("journal fold");
        let ctx = self.ctx();
        self.runtime
            .block_on(async { materialize(&mut self.db, &ctx, &self.book, &fold).await })
            .expect("materialize current journal fold");
        let verified = verify_period(&self.db, &self.book, period).expect("verify repaired cells");
        assert!(verified.is_green(), "{verified:?}");
        assert_eq!(verified.refold_digest, fold.fold_digest);
        assert_eq!(fold_period(&self.db, &self.book, period).unwrap(), fold);
        fold
    }

    fn write_derived(&mut self, batch: WriteBatch) {
        let ctx = self.ctx();
        self.runtime
            .block_on(async { self.db.write(&ctx.commit(), batch).await })
            .expect("plant derived-register corruption in the real substrate");
    }

    fn assert_not_green(&self, fault: &str) {
        match verify_period(&self.db, &self.book, &self.march) {
            Ok(v) => assert!(!v.is_green(), "{fault} was accepted: {v:?}"),
            Err(RegisterError::Kernel(KernelError::Corrupt(_))) => {}
            Err(e) => panic!("{fault}: unexpected failure rather than detected corruption: {e}"),
        }
    }

    fn plant_zero_phantom(&mut self, fold: &Fold, linked: bool) -> VId {
        // This account exists in the chart but has no journal contribution.
        let key = CellKey {
            account: account_vid(self.book.book_id, "7000"),
            unit_id: self.usd.0,
            period: self.march.clone(),
        };
        let rvid = register_vid(self.book.book_id, &key);
        let mut batch = WriteBatch::new(relation::IN_PERIOD);
        batch.create_vertex(
            rvid,
            vec![label::REGISTER],
            vec![
                (
                    property::BOOK_ID,
                    scalar_bytes(self.book.book_id.0.to_vec()),
                ),
                (
                    property::ACCOUNT_REF,
                    scalar_bytes(key.account.0.to_le_bytes().to_vec()),
                ),
                (
                    property::UNIT_ID,
                    CanonicalScalar::Int(i64::from(key.unit_id)),
                ),
                (
                    property::EFFECTIVE_PERIOD,
                    CanonicalScalar::ucs_basic_text(&self.march).unwrap(),
                ),
                (
                    property::DEBITS_POSTED,
                    scalar_bytes(0i128.to_le_bytes().to_vec()),
                ),
                (
                    property::CREDITS_POSTED,
                    scalar_bytes(0i128.to_le_bytes().to_vec()),
                ),
                (property::ENTRY_COUNT, CanonicalScalar::Int(0)),
                (
                    property::DEBITS_PENDING,
                    scalar_bytes(0i128.to_le_bytes().to_vec()),
                ),
                (
                    property::CREDITS_PENDING,
                    scalar_bytes(0i128.to_le_bytes().to_vec()),
                ),
                (property::PENDING_COUNT, CanonicalScalar::Int(0)),
                (
                    property::WATERMARK,
                    CanonicalScalar::Int(i64::try_from(fold.watermark.map_or(0, |w| w.0)).unwrap()),
                ),
                // Copy the true digest: comparing only this claim is insufficient.
                (
                    property::FA_FOLD_DIGEST,
                    scalar_bytes(fold.fold_digest.to_vec()),
                ),
            ],
        );
        if linked {
            let pvid = period_vid(&self.book.calendar.id, &self.march);
            batch.add_edge(edge_id(relation::IN_PERIOD, rvid, pvid), rvid, pvid, vec![]);
        }
        self.write_derived(batch);
        rvid
    }

    fn post_rent(&mut self, cents: i128, key: &[u8]) -> Posted {
        self.post_expense(self.rent, cents, key)
    }

    fn post_expense(&mut self, expense: VId, cents: i128, key: &[u8]) -> Posted {
        let legs = vec![
            LegPayload::simple(Side::Debit, expense, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, cents)),
        ];
        self.commit(self.proposal(legs, key, EntryClass::ORIGINAL))
    }

    fn proposal(&self, legs: Vec<LegPayload>, key: &[u8], class: EntryClass) -> EntryPayload {
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
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
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn commit(&mut self, proposal: EntryPayload) -> Posted {
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
    }

    fn hold(&mut self, legs: Vec<LegPayload>, key: &[u8]) -> Posted {
        let mut proposal = self.proposal(legs, key, EntryClass::PENDING);
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        self.commit(proposal)
    }

    fn expense_legs(&self, cents: i128) -> Vec<LegPayload> {
        vec![
            LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, cents)),
        ]
    }

    fn open_april(&mut self) -> String {
        let date = DateDay::from_ymd(2026, 4, 15).unwrap();
        let april = self
            .book
            .calendar
            .periods_for_year(2026)
            .unwrap()
            .into_iter()
            .find(|p| p.contains(date) && p.kind == PeriodKind::Normal)
            .unwrap()
            .code;
        let ctx = self.ctx();
        self.runtime
            .block_on(async {
                transition_period(
                    &mut self.db,
                    &ctx,
                    &self.book,
                    &april,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    date,
                    b"open-april",
                    Erasable::seal(
                        &"April".to_string(),
                        None,
                        &self.book.seal_key,
                        [7; 32],
                        [8; 24],
                    ),
                    &Capability::embedded(PRINCIPAL, &["close"]).expect("close"),
                    &[],
                )
                .await
            })
            .expect("kernel")
            .expect("opens April");
        april
    }
}

fn scalar_bytes(bytes: Vec<u8>) -> CanonicalScalar {
    CanonicalScalar::bytes(bytes).unwrap()
}

fn assert_cell(cells: &[Cell], account: VId, expected: (i128, i128, u64)) {
    let cell = cells.iter().find(|c| c.key.account == account).unwrap();
    assert_eq!((cell.debits, cell.credits, cell.entry_count), expected);
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
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
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
        AccountSpec {
            code: "7000".into(),
            name: "Utilities".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
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
        bytes: b"INVOICE (registers fixture source document)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
        .expect("kernel")
        .expect("the fixture document is admitted");
    Harness {
        runtime,
        root,
        db,
        cash: account_vid(book_id, "1000"),
        rent: account_vid(book_id, "6000"),
        book,
        usd,
        march,
        evidence: vec![source.evidence_ref(1)],
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
    assert_eq!(v.cache_status, CacheStatus::Verified);
    let basis = v.verified_through.expect("materialized prefix");
    assert!(
        basis < h.db.frontier().unwrap(),
        "publication is not an entry"
    );
    assert!(!v.stale);
    assert_eq!(v.lag_entries, 0);

    // A later post makes the cache stale without invalidating its checked prefix.
    h.post_rent(5, b"r2");
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(v.is_green() && v.stale, "{v:?}");
    assert_eq!(v.verified_through, Some(basis));
    assert_eq!(v.lag_entries, 1);
    assert!(v.drift.is_empty());
    assert_eq!(v.refold_digest, fold.fold_digest);
    let fold = fold_period(&h.db, &h.book, &h.march).unwrap();
    h.runtime
        .block_on(async { materialize(&mut h.db, &ctx, &h.book, &fold).await })
        .expect("re-materialize");
    let current = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(current.is_green() && !current.stale, "{current:?}");
    assert_eq!(current.lag_entries, 0);

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
    assert_eq!(v.cache_status, CacheStatus::Corrupt);
    assert_eq!(v.verified_through, None);
    assert_eq!(v.drift.len(), 1);
    assert_eq!(v.drift[0].key, cash_key);
    assert_eq!(v.drift[0].stored, Some((0, 999, 2)));
    assert_eq!(v.drift[0].refolded, (0, 1_005, 2));
}

#[test]
fn class_filtered_activity_uses_payload_lineage_and_ignores_damaged_registers() {
    let mut h = harness();
    h.post_rent(100, b"ordinary-activity");
    let adjustment = h.commit(h.proposal(
        h.expense_legs(20),
        b"adjustment-activity",
        EntryClass::ADJUSTING,
    ));
    let before_reversal = h.db.frontier().unwrap();
    let mut target = adjustment.entry_ref();
    for key in [
        b"undo-adjustment".as_slice(),
        b"restore-adjustment".as_slice(),
    ] {
        let (original, _) = read_entry(&h.db, target.vid).unwrap().unwrap();
        let legs = original
            .proposal
            .legs
            .iter()
            .map(|leg| {
                LegPayload::simple(
                    if leg.side == Side::Debit {
                        Side::Credit
                    } else {
                        Side::Debit
                    },
                    leg.account_ref,
                    leg.amount,
                )
            })
            .collect();
        let mut reversal = h.proposal(legs, key, EntryClass::REVERSAL);
        reversal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        target = h.commit(reversal).entry_ref();
    }
    h.hold(h.expense_legs(500), b"reservation-is-separate");
    let periods = [h.march.clone()];
    let ordinary = period_activity(&h.db, &h.book, &periods, None).unwrap();
    let unfiltered =
        period_activity_excluding_classes(&h.db, &h.book, &periods, None, &[]).unwrap();
    assert_eq!(
        ordinary, unfiltered,
        "ordinary activity has unchanged semantics"
    );
    let filtered =
        period_activity_excluding_classes(&h.db, &h.book, &periods, None, &[EntryClass::ADJUSTING])
            .unwrap();
    let expense = filtered
        .rows
        .iter()
        .find(|row| row.account == h.rent)
        .unwrap();
    assert_eq!((expense.debits, expense.credits), (100, 0));
    assert_eq!((expense.debits_pending, expense.credits_pending), (500, 0));
    assert_eq!(filtered.unit_totals[&h.usd.0], (100, 100));
    let historical = period_activity_excluding_classes(
        &h.db,
        &h.book,
        &periods,
        Some(before_reversal),
        &[EntryClass::ADJUSTING],
    )
    .unwrap();
    assert_eq!(historical.unit_totals[&h.usd.0], (100, 100));
    assert!(
        historical
            .pending_unit_totals
            .values()
            .all(|totals| *totals == (0, 0))
    );

    let fold = h.materialize_march();
    let cell = fold
        .cells
        .iter()
        .find(|cell| cell.key.account == h.rent)
        .unwrap();
    let mut corrupt = WriteBatch::new(relation::IN_PERIOD);
    corrupt.set_vertex_property(
        register_vid(h.book.book_id, &cell.key),
        property::DEBITS_POSTED,
        Some(scalar_bytes(9_999i128.to_le_bytes().to_vec())),
    );
    h.write_derived(corrupt);
    h.assert_not_green("the planted register amount is detected");
    let after =
        period_activity_excluding_classes(&h.db, &h.book, &periods, None, &[EntryClass::ADJUSTING])
            .unwrap();
    assert_eq!(after.rows, filtered.rows);
    assert_eq!(after.unit_totals, filtered.unit_totals);
    assert_eq!(after.pending_unit_totals, filtered.pending_unit_totals);
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

#[test]
fn empty_period_verifies_and_rebuild_does_not_invent_cells_or_postings() {
    let mut h = harness();
    let before = h.db.frontier().unwrap();
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(
        v.is_green(),
        "empty journal and empty stored set must agree: {v:?}"
    );
    assert_eq!(v.cells_checked, 0);
    assert_eq!(v.cache_status, CacheStatus::Uninitialized);
    assert_eq!(v.verified_through, None);
    let fold = h.materialize_march();
    assert!(fold.cells.is_empty());
    assert_eq!(fold.entries, 0);
    assert_eq!(fold.watermark, None);
    assert_eq!(h.db.frontier().unwrap(), before, "no empty rebuild write");
    let ctx = h.ctx();
    let advanced = h
        .runtime
        .block_on(fa_registers::advance(&mut h.db, &ctx, &h.book, &h.march))
        .unwrap();
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(v.is_green() && !v.stale, "{v:?}");
    assert_eq!(v.cache_status, CacheStatus::Verified);
    assert_eq!(v.verified_through, Some(advanced.through));
    assert_eq!(v.lag_entries, 0);
    assert_eq!(advanced.fold.watermark, None);
    assert!(advanced.published_at > advanced.through);
    // The twin: a real Entry after publication creates lag, even though
    // the verified empty prefix still has no monetary watermark.
    h.post_rent(7, b"after-empty-advance");
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(v.is_green() && v.stale, "{v:?}");
    assert_eq!(v.verified_through, Some(advanced.through));
    assert_eq!(v.lag_entries, 1);
}

#[test]
fn prefix_verification_refuses_rewritten_or_retired_journal_entries() {
    for retire in [false, true] {
        let mut h = harness();
        let posted = h.post_rent(13, b"immutable-prefix");
        h.materialize_march();
        let before = verify_period(&h.db, &h.book, &h.march).unwrap();
        assert!(before.is_green() && !before.stale);
        let mut write = WriteBatch::new(relation::IN_PERIOD);
        if retire {
            write.set_vertex_label(posted.entry_ref().vid, label::ENTRY, false);
        } else {
            write.set_vertex_property(
                posted.entry_ref().vid,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(vec![0xff]).unwrap()),
            );
        }
        h.write_derived(write);
        let v = verify_period(&h.db, &h.book, &h.march).unwrap();
        assert!(!v.is_green(), "retire={retire}: {v:?}");
        assert_eq!(v.cache_status, CacheStatus::Corrupt);
        assert_eq!(v.verified_through, None);
        assert!(
            v.projection_errors
                .iter()
                .any(|error| error.contains("changed or disappeared"))
        );
    }
}

#[test]
fn a_missing_cache_header_cannot_certify_surviving_cells() {
    let mut h = harness();
    h.post_rent(17, b"missing-header");
    h.materialize_march();
    assert!(verify_period(&h.db, &h.book, &h.march).unwrap().is_green());
    let mut write = WriteBatch::new(relation::IN_PERIOD);
    write.delete_vertex(fa_registers::maintainer::state_vid(
        h.book.book_id,
        &h.march,
    ));
    h.write_derived(write);
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(!v.is_green());
    assert_eq!(v.cache_status, CacheStatus::Corrupt);
    assert_eq!(v.verified_through, None);
    assert!(
        v.projection_errors
            .iter()
            .any(|error| error.contains("maintenance header"))
    );
}

#[test]
fn a_checksummed_cursor_before_period_creation_is_corruption() {
    let mut h = harness();
    let ctx = h.ctx();
    let initialized = h
        .runtime
        .block_on(fa_registers::advance(&mut h.db, &ctx, &h.book, &h.march))
        .unwrap();
    assert!(initialized.through.0 > 0);
    assert!(verify_period(&h.db, &h.book, &h.march).unwrap().is_green());
    let state = fa_registers::maintainer::state_vid(h.book.book_id, &h.march);
    let row = h.db.vertex(state).unwrap().unwrap();
    let mut payload = fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "state").unwrap();
    assert_eq!(&payload[..4], b"FARS");
    assert_eq!(&payload[6..14], &initialized.through.0.to_le_bytes());
    payload[6..14].copy_from_slice(&0u64.to_le_bytes());
    let mut digest = fgdb_crypto::Hasher::new();
    digest.update(b"fa:register-state-payload:v1");
    digest.update(&h.book.book_id.0);
    digest.update(&(h.march.len() as u64).to_le_bytes());
    digest.update(h.march.as_bytes());
    digest.update(&payload);
    let mut write = WriteBatch::new(relation::IN_PERIOD);
    write.set_vertex_property(
        state,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(payload).unwrap()),
    );
    write.set_vertex_property(
        state,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(digest.finalize().0.to_vec()).unwrap()),
    );
    h.write_derived(write);
    let before = h.db.frontier().unwrap();
    let v = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(!v.is_green());
    assert_eq!(v.cache_status, CacheStatus::Corrupt);
    assert_eq!(v.verified_through, None);
    assert!(
        v.projection_errors
            .iter()
            .any(|e| e.contains("cursor predates its period"))
    );
    assert!(matches!(
        h.runtime
            .block_on(fa_registers::advance(&mut h.db, &ctx, &h.book, &h.march)),
        Err(RegisterError::ProjectionDrift(_))
    ));
    assert_eq!(h.db.frontier().unwrap(), before);
    h.runtime
        .block_on(fa_registers::rebuild(&mut h.db, &ctx, &h.book, &h.march))
        .unwrap();
    let repaired = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(repaired.is_green() && !repaired.stale);
}

#[test]
fn zero_phantom_cells_are_detected_and_rebuild_removes_them() {
    for (with_post, linked) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut h = harness();
        if with_post {
            h.post_rent(1_000, b"real-rent");
        }
        let before = h.materialize_march();
        let phantom = h.plant_zero_phantom(&before, linked);
        assert!(h.db.vertex(phantom).unwrap().is_some());
        h.assert_not_green("zero-valued phantom with copied genuine fold digest");
        assert_eq!(fold_period(&h.db, &h.book, &h.march).unwrap(), before);
        assert_eq!(
            h.materialize_march(),
            before,
            "recovery preserves journal truth"
        );
        let pvid = period_vid(&h.book.calendar.id, &h.march);
        assert!(
            !h.db
                .in_neighbours(pvid, relation::IN_PERIOD)
                .unwrap()
                .contains(&phantom)
        );
        if let Some(row) = h.db.vertex(phantom).unwrap() {
            assert!(
                !row.labels.contains(&label::REGISTER),
                "phantom still a Register after rebuild"
            );
            assert!(
                fa_journal::rows::prop(&row, property::EFFECTIVE_PERIOD).is_none(),
                "phantom still attributed to a period"
            );
        }
        // A phantom cannot permanently spend a deterministic cell identity:
        // a later real posting must be able to materialize this exact key.
        let utility = account_vid(h.book.book_id, "7000");
        h.post_expense(utility, 42, b"first-real-utility");
        let recovered = h.materialize_march();
        let cell = recovered
            .cells
            .iter()
            .find(|c| c.key.account == utility)
            .unwrap();
        assert_eq!((cell.debits, cell.credits, cell.entry_count), (42, 0, 1));
        assert_eq!(register_vid(h.book.book_id, &cell.key), phantom);
        let stored = h.db.vertex(phantom).unwrap().unwrap();
        assert!(stored.labels.contains(&label::REGISTER));
        assert_eq!(
            fa_journal::rows::prop(&stored, property::DEBITS_POSTED),
            Some(&scalar_bytes(42i128.to_le_bytes().to_vec()))
        );
        assert_eq!(
            fa_journal::rows::prop(&stored, property::CREDITS_POSTED),
            Some(&scalar_bytes(0i128.to_le_bytes().to_vec()))
        );
        assert_eq!(
            fa_journal::rows::prop(&stored, property::ENTRY_COUNT),
            Some(&CanonicalScalar::Int(1))
        );
    }
}

#[test]
fn register_metadata_and_watermark_corruption_cannot_verify() {
    let mut h = harness();
    let first = h.post_rent(1_000, b"r1");
    h.post_rent(5, b"r2");
    let fold = h.materialize_march();
    let rvid = register_vid(h.book.book_id, &fold.cells[0].key);
    let cases = [
        (
            "wrong book",
            property::BOOK_ID,
            Some(scalar_bytes(vec![99; 16])),
        ),
        (
            "wrong account",
            property::ACCOUNT_REF,
            Some(scalar_bytes(
                account_vid(h.book.book_id, "7000").0.to_le_bytes().to_vec(),
            )),
        ),
        (
            "wrong unit",
            property::UNIT_ID,
            Some(CanonicalScalar::Int(i64::from(h.usd.0) + 1)),
        ),
        (
            "wrong period",
            property::EFFECTIVE_PERIOD,
            Some(CanonicalScalar::ucs_basic_text("FY2026-P99").unwrap()),
        ),
        (
            "stale watermark",
            property::WATERMARK,
            Some(CanonicalScalar::Int(
                i64::try_from(first.recorded_at().0).unwrap(),
            )),
        ),
        ("missing watermark", property::WATERMARK, None),
        (
            "malformed account",
            property::ACCOUNT_REF,
            Some(scalar_bytes(vec![1])),
        ),
        ("missing account", property::ACCOUNT_REF, None),
        ("missing digest", property::FA_FOLD_DIGEST, None),
        (
            "wrong digest",
            property::FA_FOLD_DIGEST,
            Some(scalar_bytes(vec![99; 32])),
        ),
    ];
    for (fault, property, value) in cases {
        let mut batch = WriteBatch::new(relation::IN_PERIOD);
        batch.set_vertex_property(rvid, property, value);
        h.write_derived(batch);
        h.assert_not_green(fault);
        assert_eq!(
            fold_period(&h.db, &h.book, &h.march).unwrap(),
            fold,
            "{fault} changed the journal"
        );
        assert_eq!(
            h.materialize_march(),
            fold,
            "{fault} rebuild changed the fold"
        );
    }
}

#[test]
fn missing_register_membership_is_detected_and_repaired() {
    for remove_label in [false, true] {
        let mut h = harness();
        h.post_rent(123, b"rent");
        // Nonempty journal without its materialization cannot verify green.
        h.assert_not_green("unmaterialized journal cells");
        let fold = h.materialize_march();
        let rvid = register_vid(h.book.book_id, &fold.cells[0].key);
        let pvid = period_vid(&h.book.calendar.id, &h.march);
        let mut batch = WriteBatch::new(relation::IN_PERIOD);
        if remove_label {
            batch.set_vertex_label(rvid, label::REGISTER, false);
        } else {
            let edge =
                h.db.edges()
                    .unwrap()
                    .into_iter()
                    .find(|e| {
                        e.entry.src == rvid
                            && e.entry.dst == pvid
                            && e.entry.relation == relation::IN_PERIOD
                    })
                    .expect("materialized cell has its period membership");
            batch.delete_edge(edge.entry.eid);
        }
        h.write_derived(batch);
        h.assert_not_green("missing register label or period edge");
        assert_eq!(h.materialize_march(), fold);
        assert!(
            h.db.vertex(rvid)
                .unwrap()
                .unwrap()
                .labels
                .contains(&label::REGISTER)
        );
        assert!(
            h.db.in_neighbours(pvid, relation::IN_PERIOD)
                .unwrap()
                .contains(&rvid)
        );
    }
}

#[test]
fn materialize_refuses_stale_or_modified_folds_without_writing() {
    let mut h = harness();
    h.post_rent(1_000, b"r1");
    let stale = h.materialize_march();
    h.post_rent(25, b"r2");
    let current = fold_period(&h.db, &h.book, &h.march).unwrap();
    let mut modified = current.clone();
    modified.cells[0].entry_count += 1;
    let ctx = h.ctx();
    for (fault, supplied) in [("stale", stale), ("modified", modified)] {
        let before = h.db.frontier().unwrap();
        let result = h
            .runtime
            .block_on(async { materialize(&mut h.db, &ctx, &h.book, &supplied).await });
        assert!(
            result.is_err(),
            "{fault} caller-supplied Fold was persisted"
        );
        assert_eq!(
            h.db.frontier().unwrap(),
            before,
            "{fault} rejection wrote state"
        );
        assert_eq!(fold_period(&h.db, &h.book, &h.march).unwrap(), current);
    }
    assert_eq!(h.materialize_march(), current);
}

#[test]
fn recovery_refuses_to_rewrite_an_account_forged_as_a_register() {
    let mut h = harness();
    h.post_rent(250, b"rent");
    let fold = h.materialize_march();
    let rvid = h.cash;
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    batch.set_vertex_label(rvid, label::REGISTER, true);
    batch.set_vertex_property(
        rvid,
        property::EFFECTIVE_PERIOD,
        Some(CanonicalScalar::ucs_basic_text(&h.march).unwrap()),
    );
    h.write_derived(batch);
    h.assert_not_green("immutable Account forged as a Register");
    let before = h.db.frontier().unwrap();
    let row_before = h.db.vertex(rvid).unwrap().unwrap();
    let ctx = h.ctx();
    let result = h
        .runtime
        .block_on(async { materialize(&mut h.db, &ctx, &h.book, &fold).await });
    assert!(
        matches!(result, Err(RegisterError::Kernel(KernelError::Corrupt(_)))),
        "recovery must refuse ambiguous ownership: {result:?}"
    );
    assert_eq!(h.db.frontier().unwrap(), before, "refusal changed storage");
    let row_after = h.db.vertex(rvid).unwrap().unwrap();
    assert_eq!(row_after.labels, row_before.labels);
    assert_eq!(row_after.props, row_before.props);
    assert_eq!(fold_period(&h.db, &h.book, &h.march).unwrap(), fold);
}

#[test]
fn missing_entry_period_projection_does_not_hide_journal_contributions() {
    let mut h = harness();
    let posted = h.post_rent(12_345, b"rent");
    let fold = h.materialize_march();
    let evid = posted.entry_ref().vid;
    let row_before = h.db.vertex(evid).unwrap().unwrap();
    let pvid = period_vid(&h.book.calendar.id, &h.march);
    let edge = h
        .db
        .edges()
        .unwrap()
        .into_iter()
        .find(|e| {
            e.entry.src == evid && e.entry.dst == pvid && e.entry.relation == relation::IN_PERIOD
        })
        .expect("posted entry has a period projection");
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    batch.delete_edge(edge.entry.eid);
    h.write_derived(batch);
    assert!(
        !h.db
            .in_neighbours(pvid, relation::IN_PERIOD)
            .unwrap()
            .contains(&evid)
    );
    assert_eq!(h.db.vertex(evid).unwrap().unwrap().props, row_before.props);
    assert_eq!(fold_period(&h.db, &h.book, &h.march).unwrap(), fold);
    let verification = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(
        verification.is_green(),
        "intact materialized cells still match the payload: {verification:?}"
    );
    assert_eq!(h.materialize_march(), fold);
}

#[test]
fn partial_post_releases_all_march_reservations_and_posts_only_in_april() {
    let mut h = harness();
    let april = h.open_april();
    let utilities = account_vid(h.book.book_id, "7000");
    let hold = h.hold(
        vec![
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 6_000)),
            LegPayload::simple(Side::Debit, utilities, Amount::new(h.usd, 4_000)),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 10_000)),
        ],
        b"three-leg-hold",
    );
    let held = h.materialize_march();
    assert!(held.cells.is_empty(), "a hold posts nothing");
    assert_eq!(held.entries, 0);
    assert_eq!(held.watermark, Some(hold.recorded_at()));
    assert_eq!(held.pending.len(), 3);
    assert_cell(&held.pending, h.rent, (6_000, 0, 1));
    assert_cell(&held.pending, utilities, (4_000, 0, 1));
    assert_cell(&held.pending, h.cash, (0, 10_000, 1));
    let reserved_report = trial_balance(&h.db, &h.book, &[h.march.clone()]).unwrap();
    assert!(reserved_report.is_balanced());
    assert_eq!(reserved_report.unit_totals.get(&h.usd.0), Some(&(0, 0)));
    assert_eq!(
        reserved_report.pending_unit_totals.get(&h.usd.0),
        Some(&(10_000, 10_000))
    );
    for cell in &held.pending {
        let stored =
            h.db.vertex(register_vid(h.book.book_id, &cell.key))
                .unwrap()
                .unwrap();
        for (property, value) in [
            (property::DEBITS_POSTED, 0),
            (property::CREDITS_POSTED, 0),
            (property::DEBITS_PENDING, cell.debits),
            (property::CREDITS_PENDING, cell.credits),
        ] {
            assert_eq!(
                fa_journal::rows::prop(&stored, property),
                Some(&scalar_bytes(value.to_le_bytes().to_vec()))
            );
        }
        assert_eq!(
            fa_journal::rows::prop(&stored, property::PENDING_COUNT),
            Some(&CanonicalScalar::Int(1))
        );
        assert_eq!(
            fa_journal::rows::prop(&stored, property::ENTRY_COUNT),
            Some(&CanonicalScalar::Int(0))
        );
    }
    let original = h.db.vertex(hold.entry_ref().vid).unwrap().unwrap();
    // Select the Rent leg and Cash leg explicitly; the unposted Utilities
    // reservation must be released too, not left behind as a 4,000 hold.
    let mut proposal = h.proposal(
        h.expense_legs(6_000),
        b"partial-post-in-april",
        EntryClass::RESOLUTION,
    );
    proposal.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
    proposal.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(hold.entry_ref()),
        disposition: Some(Disposition::Posts {
            source_ordinals: vec![0, 2],
        }),
    });
    let basis = verify_period(&h.db, &h.book, &h.march)
        .unwrap()
        .verified_through;
    let posted = h.commit(proposal);
    let stale = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(stale.is_green() && stale.stale, "{stale:?}");
    assert_eq!(stale.verified_through, basis);
    assert_eq!(stale.lag_entries, 1);
    let released = h.materialize_march();
    let fresh = verify_period(&h.db, &h.book, &h.march).unwrap();
    assert!(fresh.is_green() && !fresh.stale, "{fresh:?}");
    assert!(released.pending.is_empty());
    assert!(released.cells.is_empty());
    assert_eq!(released.entries, 0);
    assert_eq!(released.watermark, Some(posted.recorded_at()));
    assert_ne!(released.fold_digest, held.fold_digest);
    let april_fold = h.materialize_period(&april);
    assert!(april_fold.pending.is_empty());
    assert_eq!(april_fold.entries, 1);
    assert_eq!(april_fold.cells.len(), 2);
    assert_eq!(april_fold.watermark, Some(posted.recorded_at()));
    assert_cell(&april_fold.cells, h.rent, (6_000, 0, 1));
    assert_cell(&april_fold.cells, h.cash, (0, 6_000, 1));
    assert_eq!(
        fold_period_at(&h.db, &h.book, &h.march, Some(hold.recorded_at())).unwrap(),
        held,
        "historical reservation survives a later resolution and rebuild"
    );
    let historical =
        trial_balance_at(&h.db, &h.book, &[h.march.clone()], Some(hold.recorded_at())).unwrap();
    assert_eq!(historical.rows, reserved_report.rows);
    assert_eq!(historical.known_at, hold.recorded_at());
    let posted_report = trial_balance(&h.db, &h.book, std::slice::from_ref(&april)).unwrap();
    assert!(posted_report.is_balanced());
    assert_eq!(
        posted_report.unit_totals.get(&h.usd.0),
        Some(&(6_000, 6_000))
    );
    assert!(
        posted_report
            .pending_unit_totals
            .values()
            .all(|amounts| *amounts == (0, 0)),
        "partial posting releases the whole original reservation"
    );
    let march_cutoff = balance_as_of(
        &h.db,
        &h.book,
        DateDay::from_ymd(2026, 3, 31).unwrap(),
        Some(posted.recorded_at()),
    )
    .unwrap();
    assert_eq!(march_cutoff.known_at, posted.recorded_at());
    assert!(
        march_cutoff.rows.is_empty(),
        "later-known release clears March's hold, but April's posting is after the cutoff"
    );
    assert!(march_cutoff.unit_totals.is_empty());
    assert!(march_cutoff.pending_unit_totals.is_empty());

    // A missing derived edge cannot turn an immutable resolution into an
    // outstanding hold again. Read HEAD after the actual edge removal.
    let resolution_edge =
        h.db.edges()
            .unwrap()
            .into_iter()
            .find(|edge| {
                edge.entry.src == posted.entry_ref().vid
                    && edge.entry.dst == hold.entry_ref().vid
                    && edge.entry.relation == relation::RESOLVES
            })
            .expect("resolution has a derived target edge");
    let mut batch = WriteBatch::new(relation::RESOLVES);
    batch.delete_edge(resolution_edge.entry.eid);
    h.write_derived(batch);
    assert!(
        !h.db
            .edges()
            .unwrap()
            .iter()
            .any(|edge| { edge.entry.eid == resolution_edge.entry.eid })
    );
    assert_eq!(fold_period(&h.db, &h.book, &h.march).unwrap(), released);
    assert_eq!(fold_period(&h.db, &h.book, &april).unwrap(), april_fold);
    let after_edge_loss = trial_balance(&h.db, &h.book, std::slice::from_ref(&april)).unwrap();
    assert_eq!(after_edge_loss.known_at, h.db.frontier().unwrap());
    assert_eq!(after_edge_loss.rows, posted_report.rows);
    assert_eq!(after_edge_loss.unit_totals, posted_report.unit_totals);
    assert_eq!(
        after_edge_loss.pending_unit_totals,
        posted_report.pending_unit_totals
    );
    assert!(verify_period(&h.db, &h.book, &h.march).unwrap().is_green());
    assert!(verify_period(&h.db, &h.book, &april).unwrap().is_green());
    assert_eq!(
        h.db.vertex(hold.entry_ref().vid).unwrap().unwrap().props,
        original.props,
        "resolving and rebuilding cannot mutate the pending entry"
    );
}

#[test]
fn april_void_releases_only_its_march_hold_and_never_posts() {
    let mut h = harness();
    let april = h.open_april();
    let first = h.hold(h.expense_legs(700), b"hold-to-void");
    let second = h.hold(h.expense_legs(900), b"hold-to-retain");
    let held = h.materialize_march();
    assert!(held.cells.is_empty());
    assert_eq!(held.entries, 0);
    assert_cell(&held.pending, h.rent, (1_600, 0, 2));
    assert_cell(&held.pending, h.cash, (0, 1_600, 2));

    for (target, key, remaining) in [
        (first.entry_ref(), b"void-first".as_slice(), 900),
        (second.entry_ref(), b"void-second".as_slice(), 0),
    ] {
        let mut proposal = h.proposal(Vec::new(), key, EntryClass::RESOLUTION);
        proposal.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
        proposal.control = Some(ControlPayload::ReservationRelease);
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Voids),
        });
        let basis = verify_period(&h.db, &h.book, &h.march)
            .unwrap()
            .verified_through;
        let resolution = h.commit(proposal);
        let stale = verify_period(&h.db, &h.book, &h.march).unwrap();
        assert!(stale.is_green() && stale.stale, "{stale:?}");
        assert_eq!(stale.verified_through, basis);
        assert_eq!(stale.lag_entries, 1);
        let march = h.materialize_march();
        let fresh = verify_period(&h.db, &h.book, &h.march).unwrap();
        assert!(fresh.is_green() && !fresh.stale, "{fresh:?}");
        assert!(march.cells.is_empty());
        assert_eq!(march.entries, 0);
        assert_eq!(march.watermark, Some(resolution.recorded_at()));
        if remaining == 0 {
            assert!(march.pending.is_empty());
        } else {
            assert_eq!(march.pending.len(), 2);
            assert_cell(&march.pending, h.rent, (remaining, 0, 1));
            assert_cell(&march.pending, h.cash, (0, remaining, 1));
        }
        let april_fold = h.materialize_period(&april);
        assert!(april_fold.cells.is_empty());
        assert!(april_fold.pending.is_empty());
        assert_eq!(april_fold.entries, 0, "a void is never a posting");
        assert_eq!(
            fold_period_at(&h.db, &h.book, &h.march, Some(second.recorded_at())).unwrap(),
            held,
            "known-at before the void retains both original holds"
        );
    }
}

#[test]
fn pending_column_corruption_is_detected_and_rebuilt_from_the_journal() {
    let mut h = harness();
    h.post_rent(123, b"posted-rent");
    h.hold(h.expense_legs(700), b"rent-hold");
    let held = h.materialize_march();
    assert_cell(&held.cells, h.cash, (0, 123, 1));
    assert_cell(&held.pending, h.cash, (0, 700, 1));
    let key = held
        .pending
        .iter()
        .find(|cell| cell.key.account == h.cash)
        .unwrap()
        .key
        .clone();
    let rvid = register_vid(h.book.book_id, &key);
    for (property, forged) in [
        (
            property::DEBITS_PENDING,
            Some(scalar_bytes(1i128.to_le_bytes().to_vec())),
        ),
        (
            property::CREDITS_PENDING,
            Some(scalar_bytes(699i128.to_le_bytes().to_vec())),
        ),
        (property::PENDING_COUNT, Some(CanonicalScalar::Int(2))),
        (property::CREDITS_PENDING, None),
    ] {
        let mut batch = WriteBatch::new(relation::IN_PERIOD);
        batch.set_vertex_property(rvid, property, forged);
        h.write_derived(batch);
        h.assert_not_green("stored pending column diverges from immutable hold");
        assert_eq!(fold_period(&h.db, &h.book, &h.march).unwrap(), held);
        assert_eq!(h.materialize_march(), held);
        let stored = h.db.vertex(rvid).unwrap().unwrap();
        assert_eq!(
            fa_journal::rows::prop(&stored, property::DEBITS_PENDING),
            Some(&scalar_bytes(0i128.to_le_bytes().to_vec()))
        );
        assert_eq!(
            fa_journal::rows::prop(&stored, property::CREDITS_PENDING),
            Some(&scalar_bytes(700i128.to_le_bytes().to_vec()))
        );
        assert_eq!(
            fa_journal::rows::prop(&stored, property::PENDING_COUNT),
            Some(&CanonicalScalar::Int(1))
        );
        assert_eq!(
            fa_journal::rows::prop(&stored, property::CREDITS_POSTED),
            Some(&scalar_bytes(123i128.to_le_bytes().to_vec()))
        );
    }
}

/// Plan §5.4–5.5 at the kernel boundary: a limit is structural (one unit, a
/// leaf, lower ≤ upper, at least one bound), a limited account is born with
/// a zero LimitCell, and a breach names the bound, the net, the
/// reservations, and the exact amount that would be admissible.
#[test]
fn chart_limits_are_structural_and_breaches_name_the_admissible_amount() {
    let mut h = harness();
    let usd = h.usd;
    let install = |h: &mut Harness, spec: AccountSpec, key: &[u8]| {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let day = DateDay::from_ymd(2026, 1, 1).unwrap();
        let description =
            Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]);
        h.runtime
            .block_on(async move {
                install_chart(db, &ctx, book, &[spec], PRINCIPAL, day, key, description).await
            })
            .expect("kernel")
    };
    let petty = |limit: Option<BalanceLimit>, policy: UnitPolicy, leaf: bool| AccountSpec {
        code: "1100".into(),
        name: "Petty cash".into(),
        account_type: 1,
        normal_balance: 0,
        is_leaf: leaf,
        unit_policy: policy,
        parent_code: None,
        limit,
    };
    let floor = |lower: Option<i128>, upper: Option<i128>| {
        Some(BalanceLimit {
            lower,
            upper,
            scope: LimitScope::Lifetime,
        })
    };
    for (n, bad) in [
        petty(floor(None, None), UnitPolicy::Single(usd), true),
        petty(floor(Some(10), Some(5)), UnitPolicy::Single(usd), true),
        petty(floor(Some(0), None), UnitPolicy::AnyUnit, true),
        petty(floor(Some(0), None), UnitPolicy::Single(usd), false),
    ]
    .into_iter()
    .enumerate()
    {
        let refused = install(&mut h, bad, format!("bad-{n}").as_bytes()).expect_err("structural");
        assert_eq!(
            (refused.code, refused.exit),
            ("FA-REF-100", exit::USAGE),
            "{refused}"
        );
    }
    let petty_vid = account_vid(h.book.book_id, "1100");
    assert!(
        h.db.vertex(petty_vid).unwrap().is_none(),
        "a refused chart writes nothing"
    );
    install(
        &mut h,
        petty(floor(Some(0), Some(50_000)), UnitPolicy::Single(usd), true),
        b"petty",
    )
    .expect("a well-formed limit installs");
    let row = h.db.vertex(petty_vid).unwrap().expect("account");
    assert_eq!(
        rows::AccountRow::decode(&row).unwrap().limit,
        Some(BalanceLimit {
            lower: Some(0),
            upper: Some(50_000),
            scope: LimitScope::Lifetime,
        })
    );
    let cell =
        h.db.vertex(limit_cell_vid(petty_vid))
            .unwrap()
            .expect("born with its cell");
    assert!(cell.labels.contains(&label::LIMIT_CELL));
    assert_eq!(LimitCell::decode(&cell).unwrap(), LimitCell::default());

    let mv = |h: &Harness, dr: VId, cr: VId, cents: i128| {
        vec![
            LegPayload::simple(Side::Debit, dr, Amount::new(h.usd, cents)),
            LegPayload::simple(Side::Credit, cr, Amount::new(h.usd, cents)),
        ]
    };
    let try_commit = |h: &mut Harness, proposal: EntryPayload| {
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).expect("post"),
        };
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
    };
    // Fund 100 from cash (unlimited), then try to spend 101.
    let fund = h.proposal(
        mv(&h, petty_vid, h.cash, 100),
        b"fund",
        EntryClass::ORIGINAL,
    );
    assert!(matches!(
        try_commit(&mut h, fund),
        Ok(Posted::Committed { .. })
    ));
    let over = h.proposal(
        mv(&h, h.rent, petty_vid, 101),
        b"over",
        EntryClass::ORIGINAL,
    );
    let refused = try_commit(&mut h, over).expect_err("an overdraw is refused");
    assert_eq!((refused.code, refused.exit), ("FA-REF-090", exit::REFUSAL));
    assert!(
        refused.message.contains("`1100`") && refused.message.contains("net 1.00 USD"),
        "{refused}"
    );
    assert!(
        refused.message.contains("lower bound 0.00 USD"),
        "{refused}"
    );
    assert!(refused.fix.contains("at most 1.00 USD"), "{refused}");
    // A hold of 80 reserves: a posted 30 now has only 20 available.
    h.hold(mv(&h, h.rent, petty_vid, 80), b"hold");
    let thirty = h.proposal(
        mv(&h, h.rent, petty_vid, 30),
        b"thirty",
        EntryClass::ORIGINAL,
    );
    let refused = try_commit(&mut h, thirty).expect_err("the hold reserves");
    assert!(
        refused.message.contains("reserved outflows 0.80 USD"),
        "{refused}"
    );
    assert!(refused.fix.contains("at most 0.20 USD"), "{refused}");
    // The cap: 100 posted in; 49_901 more would exceed 50_000.
    let cap = h.proposal(
        mv(&h, petty_vid, h.cash, 49_901),
        b"cap",
        EntryClass::ORIGINAL,
    );
    let refused = try_commit(&mut h, cap).expect_err("over the cap");
    assert_eq!(refused.code, "FA-REF-091");
    assert!(refused.fix.contains("at most 499.00 USD"), "{refused}");
    let stored =
        LimitCell::decode(&h.db.vertex(limit_cell_vid(petty_vid)).unwrap().unwrap()).unwrap();
    assert_eq!(
        stored,
        LimitCell {
            debits_posted: 100,
            credits_posted: 0,
            debits_pending: 0,
            credits_pending: 80,
            generation: 2
        }
    );
    let verified = fa_registers::verify_availability(&h.db, &h.book, None).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert_eq!(verified.accounts_checked, 1);
    assert_eq!(
        (verified.accounts[0].net, verified.accounts[0].pending_out),
        (100, 80)
    );
}

/// Review 3063: a LimitCell's `account_ref` is part of the witness. Two
/// limited accounts post and verify green (positive control); rebinding only
/// one cell's `account_ref` to the other account makes the verifier name both
/// accounts and the kernel refuse every post on the rebound account (fail
/// closed, as for the `applied` mirror), while the other limited account and
/// unlimited accounts keep posting. An absent `account_ref` is the same.
#[test]
fn a_limit_cell_rebound_to_another_account_fails_closed_and_verify_names_both() {
    let mut h = harness();
    let usd = h.usd;
    let floor = Some(BalanceLimit {
        lower: Some(0),
        upper: None,
        scope: LimitScope::Lifetime,
    });
    let spec = |code: &str| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: 1,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: floor,
    };
    let chart = [spec("1100"), spec("1110")];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let day = DateDay::from_ymd(2026, 1, 1).unwrap();
        let description =
            Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]);
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &chart,
                    PRINCIPAL,
                    day,
                    b"two-limited",
                    description,
                )
                .await
            })
            .expect("kernel")
            .expect("installs");
    }
    let a = account_vid(h.book.book_id, "1100");
    let b = account_vid(h.book.book_id, "1110");
    let cash = h.cash;
    let post_raw = |h: &mut Harness, dr: VId, cr: VId, cents: i128, key: &[u8]| {
        let legs = vec![
            LegPayload::simple(Side::Debit, dr, Amount::new(h.usd, cents)),
            LegPayload::simple(Side::Credit, cr, Amount::new(h.usd, cents)),
        ];
        let req = PostRequest {
            proposal: h.proposal(legs, key, EntryClass::ORIGINAL),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).expect("post"),
        };
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
    };
    // Positive control: both cells intact and bound; both accounts post.
    for (account, key) in [(a, b"fund-a" as &[u8]), (b, b"fund-b")] {
        assert!(matches!(
            post_raw(&mut h, account, cash, 100, key),
            Ok(Ok(Posted::Committed { .. }))
        ));
    }
    let intact = fa_registers::verify_availability(&h.db, &h.book, None).unwrap();
    assert!(intact.is_green(), "{intact:?}");
    assert_eq!(intact.accounts_checked, 2);

    // Rebind only 1100's cell to 1110: the sums stay exactly right.
    let cell_a = limit_cell_vid(a);
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        cell_a,
        property::ACCOUNT_REF,
        Some(scalar_bytes(b.0.to_le_bytes().to_vec())),
    );
    h.write_derived(batch);
    let rebound = fa_registers::verify_availability(&h.db, &h.book, None).unwrap();
    assert!(!rebound.is_green());
    assert_eq!(rebound.drift.len(), 1, "{rebound:?}");
    let d = &rebound.drift[0];
    assert_eq!((d.account, d.code.as_str()), (a, "1100"));
    assert_eq!(d.stored_account, Some(b));
    assert_eq!(d.stored_account_code.as_deref(), Some("1110"));
    assert_eq!(d.stored, Some(d.refolded), "only the binding was changed");
    let refused = post_raw(&mut h, a, cash, 1, b"fund-a-again");
    let other_hex = format!("{:032x}", b.0);
    assert!(
        matches!(&refused, Err(KernelError::Corrupt(m))
            if m.contains(&other_hex) && m.contains("fa verify availability")),
        "a rebound cell must fail closed: {refused:?}"
    );
    assert!(matches!(
        post_raw(&mut h, b, cash, 1, b"fund-b-again"),
        Ok(Ok(Posted::Committed { .. }))
    ));
    h.post_rent(5, b"unlimited-still-posts");

    // An absent binding is the same failure.
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(cell_a, property::ACCOUNT_REF, None);
    h.write_derived(batch);
    let unbound = fa_registers::verify_availability(&h.db, &h.book, None).unwrap();
    assert!(
        unbound
            .drift
            .iter()
            .any(|d| d.account == a && d.stored_account.is_none() && d.stored.is_some()),
        "{unbound:?}"
    );
    assert!(matches!(
        post_raw(&mut h, a, cash, 1, b"fund-a-unbound"),
        Err(KernelError::Corrupt(_))
    ));
}
