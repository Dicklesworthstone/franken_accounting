//! Registers against the real in-memory substrate: the fold equals the posted
//! legs with the last commit as watermark; materialize-then-verify is green;
//! a tampered Register vertex is reported as drift (the journal wins); the
//! trial balance nets to zero per unit; control records contribute nothing.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{Document, add_document};
use fa_journal::fx::FxRateTerms;
use fa_journal::rows::edge_id;
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, Erasable,
    EvidenceRef, Id128, LegPayload, Oid, Pending, SealKey, Supersession, SupersessionKind,
    SymbolTable, account_vid, period_vid,
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
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
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
                PRINCIPAL,
                1,
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
        let (original, _) = fa_journal::post::read_entry(&h.db, target.vid)
            .unwrap()
            .unwrap();
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
    for mode in ["payload", "digest", "retire"] {
        let mut h = harness();
        let posted = h.post_rent(13, b"immutable-prefix");
        h.materialize_march();
        let before = verify_period(&h.db, &h.book, &h.march).unwrap();
        assert!(before.is_green() && !before.stale);
        let mut write = WriteBatch::new(relation::IN_PERIOD);
        match mode {
            "retire" => {
                write.set_vertex_label(posted.entry_ref().vid, label::ENTRY, false);
            }
            "digest" => {
                write.set_vertex_property(
                    posted.entry_ref().vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0xaa; 32]).unwrap()),
                );
            }
            _ => {
                write.set_vertex_property(
                    posted.entry_ref().vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(vec![0xff]).unwrap()),
                );
            }
        }
        h.write_derived(write);
        let v = verify_period(&h.db, &h.book, &h.march).unwrap();
        assert!(!v.is_green(), "mode={mode}: {v:?}");
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
                install_chart(
                    db,
                    &ctx,
                    book,
                    &[spec],
                    PRINCIPAL,
                    day,
                    key,
                    description,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
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
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
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

#[test]
fn equal_sum_histories_with_different_leg_orders_have_distinct_fold_digests() {
    let mut a = harness();
    let mut b = harness();

    // Book A posts 100 then 50; Book B posts 50 then 100 under identical keys.
    let ctx_a = a.ctx();
    let ctx_b = b.ctx();
    a.post_rent(100, b"entry-1");
    a.runtime
        .block_on(fa_registers::advance(&mut a.db, &ctx_a, &a.book, &a.march))
        .expect("advance a step 1");
    a.post_rent(50, b"entry-2");
    let adv_a = a
        .runtime
        .block_on(fa_registers::advance(&mut a.db, &ctx_a, &a.book, &a.march))
        .expect("advance a step 2");

    b.post_rent(50, b"entry-1");
    b.runtime
        .block_on(fa_registers::advance(&mut b.db, &ctx_b, &b.book, &b.march))
        .expect("advance b step 1");
    b.post_rent(100, b"entry-2");
    let adv_b = b
        .runtime
        .block_on(fa_registers::advance(&mut b.db, &ctx_b, &b.book, &b.march))
        .expect("advance b step 2");

    let fold_a = fold_period(&a.db, &a.book, &a.march).unwrap();
    let fold_b = fold_period(&b.db, &b.book, &b.march).unwrap();
    assert_eq!(adv_a.fold, fold_a);
    assert_eq!(adv_b.fold, fold_b);
    assert_eq!(fold_a.cells, fold_b.cells, "both books sum to 150");
    assert_eq!(
        fold_a.watermark, fold_b.watermark,
        "same commit sequence watermark"
    );
    assert_eq!(fold_a.entries, fold_b.entries);
    assert_ne!(
        fold_a.fold_digest, fold_b.fold_digest,
        "100@seq1 + 50@seq2 vs 50@seq1 + 100@seq2 must have distinct fold digests"
    );

    let ent_a = fa_registers::fold_period_by_entity(&a.db, &a.book, &a.march, None).unwrap();
    let ent_b = fa_registers::fold_period_by_entity(&b.db, &b.book, &b.march, None).unwrap();
    assert_eq!(ent_a.cells, ent_b.cells);
    assert_eq!(ent_a.watermark, ent_b.watermark);
    assert_ne!(ent_a.fold_digest, ent_b.fold_digest);

    // Within a single entry, reordering leg ordinals also changes fold_digest
    // even though the summed cells and watermark are identical.
    let mut c = harness();
    let mut d = harness();
    let utilities = account_vid(c.book.book_id, "7000");
    c.commit(c.proposal(
        vec![
            LegPayload::simple(Side::Debit, c.rent, Amount::new(c.usd, 60)),
            LegPayload::simple(Side::Debit, utilities, Amount::new(c.usd, 40)),
            LegPayload::simple(Side::Credit, c.cash, Amount::new(c.usd, 100)),
        ],
        b"split-entry",
        EntryClass::ORIGINAL,
    ));
    d.commit(d.proposal(
        vec![
            LegPayload::simple(Side::Debit, utilities, Amount::new(d.usd, 40)),
            LegPayload::simple(Side::Debit, d.rent, Amount::new(d.usd, 60)),
            LegPayload::simple(Side::Credit, d.cash, Amount::new(d.usd, 100)),
        ],
        b"split-entry",
        EntryClass::ORIGINAL,
    ));
    let fold_c = fold_period(&c.db, &c.book, &c.march).unwrap();
    let fold_d = fold_period(&d.db, &d.book, &d.march).unwrap();
    assert_eq!(fold_c.cells, fold_d.cells);
    assert_eq!(fold_c.watermark, fold_d.watermark);
    assert_ne!(
        fold_c.fold_digest, fold_d.fold_digest,
        "leg ordinal order within an entry must be bound by fold_digest"
    );
}

#[test]
fn as_of_and_activity_semantics_across_all_account_types_and_memo_footing() {
    use std::collections::BTreeMap;

    let mut h = harness();
    let usd = h.usd;
    let dec_2025 = DateDay::from_ymd(2025, 12, 15).unwrap();
    let mar_2026 = DateDay::from_ymd(2026, 3, 15).unwrap();
    let end_mar_2026 = DateDay::from_ymd(2026, 3, 31).unwrap();

    // Create FY2025 periods and open FY2025-P12.
    let (_, fy2025) = {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move {
                create_periods(
                    db,
                    &ctx,
                    book,
                    2025,
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
            .expect("fy2025 created")
            .expect("admitted")
    };
    let p12_2025 = fy2025
        .iter()
        .find(|p| p.contains(dec_2025) && p.kind == PeriodKind::Normal)
        .unwrap()
        .code
        .clone();
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"open-p12".to_string(),
            None,
            &book.seal_key,
            [11; 32],
            [12; 24],
        );
        let cap = Capability::embedded(PRINCIPAL, &["close"]).expect("close");
        let p12 = p12_2025.as_str();
        h.runtime
            .block_on(async move {
                transition_period(
                    db,
                    &ctx,
                    book,
                    p12,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    b"open-2025-p12",
                    desc,
                    &cap,
                    &[],
                )
                .await
            })
            .expect("kernel")
            .expect("opened 2025-p12");
    }

    // Install one leaf account per registered AccountType (1..=8) plus counter-accounts.
    let type_accounts: &[(&str, &str, u8, u8)] = &[
        ("1010", "AssetSample", 1, 0),
        ("2010", "LiabilitySample", 2, 1),
        ("3010", "EquitySample", 3, 1),
        ("4010", "RevenueSample", 4, 1),
        ("5010", "ExpenseSample", 5, 0),
        ("8010", "MemoGuarantee", 6, 0),
        ("8020", "MemoCounter", 6, 1),
        ("8510", "OffBalanceCommitment", 8, 0),
        ("8520", "OffBalanceCounter", 8, 1),
        ("9010", "StatHeadcount", 7, 0),
        ("9020", "StatCounter", 7, 1),
    ];
    let specs: Vec<AccountSpec> = type_accounts
        .iter()
        .map(|(code, name, tag, nb)| AccountSpec {
            code: (*code).into(),
            name: (*name).into(),
            account_type: *tag,
            normal_balance: *nb,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        })
        .collect();
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"all-types".to_string(),
            None,
            &book.seal_key,
            [13; 32],
            [14; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &specs,
                    PRINCIPAL,
                    dec_2025,
                    b"install-all-types",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("installed");
    }

    let mut oracle = fa_reference::Oracle::new(h.book.calendar.clone());
    oracle.create_periods(2025);
    oracle.create_periods(2026);
    oracle
        .transition(&p12_2025, PeriodTransition::Open)
        .expect("oracle open 2025-p12");
    oracle
        .transition(&h.march, PeriodTransition::Open)
        .expect("oracle open 2026-p03");
    for (code, _, tag, _) in type_accounts {
        oracle.add_account(fa_reference::Account {
            code: (*code).into(),
            is_leaf: true,
            unit: Some(usd.0),
        });
        oracle.set_account_type(code, *tag);
    }

    let book_id = h.book.book_id;
    let vid = move |code: &str| account_vid(book_id, code);
    let post_dated = |h: &mut Harness,
                      oracle: &mut fa_reference::Oracle,
                      date: DateDay,
                      key: &[u8],
                      legs: &[(&str, Side, i128)]|
     -> (Result<Posted, Refusal>, fa_reference::Verdict) {
        let k_legs: Vec<LegPayload> = legs
            .iter()
            .map(|(c, side, m)| LegPayload::simple(*side, vid(c), Amount::new(usd, *m)))
            .collect();
        let mut proposal = h.proposal(k_legs, key, EntryClass::ORIGINAL);
        proposal.effective_date = date;
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).expect("post"),
        };
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let k_res = h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel");
        let o_legs: Vec<fa_reference::Leg> = legs
            .iter()
            .map(|(c, side, m)| fa_reference::Leg {
                side: match side {
                    Side::Debit => fa_reference::Side::Debit,
                    Side::Credit => fa_reference::Side::Credit,
                },
                account: (*c).into(),
                unit: usd.0,
                entity: None,
                mantissa: *m,
            })
            .collect();
        let o_intent = fa_reference::Intent {
            class: "Original".into(),
            date,
            discriminator: None,
            legs: o_legs,
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 0,
            resolves: None,
            settles: Vec::new(),
            key: key.to_vec(),
        };
        let o_res = oracle.post(&o_intent);
        (k_res, o_res)
    };

    // Planted negatives: mixing a monetary leg with a Memo, OffBalance, or
    // Statistical leg in the same unit is refused FA-REF-001 by both kernel and oracle.
    let head_before = h.db.frontier().unwrap();
    for (bad_key, bad_legs) in [
        (
            b"mix-asset-memo" as &[u8],
            &[("1010", Side::Debit, 500), ("8020", Side::Credit, 500)][..],
        ),
        (
            b"mix-asset-offbal",
            &[("1010", Side::Debit, 500), ("8520", Side::Credit, 500)][..],
        ),
        (
            b"mix-rev-stat",
            &[("9010", Side::Debit, 300), ("4010", Side::Credit, 300)][..],
        ),
        (
            b"mix-offbal-stat",
            &[("8510", Side::Debit, 300), ("9020", Side::Credit, 300)][..],
        ),
    ] {
        let (k_res, o_res) = post_dated(&mut h, &mut oracle, mar_2026, bad_key, bad_legs);
        let err = k_res.expect_err("memo/off-balance/statistical leg must not cross-balance");
        assert_eq!((err.code, err.exit), ("FA-REF-001", exit::REFUSAL));
        assert_eq!(o_res, fa_reference::Verdict::Refused { code: "FA-REF-001" });
    }
    assert_eq!(h.db.frontier().unwrap(), head_before);

    // Post FY2025 activity across all 8 account types (unclosed prior year).
    for (key, legs) in [
        (
            b"fy25-stock" as &[u8],
            &[
                ("1010", Side::Debit, 1_000),
                ("2010", Side::Credit, 400),
                ("3010", Side::Credit, 600),
            ][..],
        ),
        (
            b"fy25-flow",
            &[
                ("1010", Side::Debit, 200),
                ("5010", Side::Debit, 300),
                ("4010", Side::Credit, 500),
            ][..],
        ),
        (
            b"fy25-memo",
            &[("8010", Side::Debit, 700), ("8020", Side::Credit, 700)][..],
        ),
        (
            b"fy25-offbal",
            &[("8510", Side::Debit, 950), ("8520", Side::Credit, 950)][..],
        ),
        (
            b"fy25-stat",
            &[("9010", Side::Debit, 42), ("9020", Side::Credit, 42)][..],
        ),
    ] {
        let (k_res, o_res) = post_dated(&mut h, &mut oracle, dec_2025, key, legs);
        assert!(matches!(k_res, Ok(Posted::Committed { .. })));
        assert!(matches!(o_res, fa_reference::Verdict::Posted { .. }));
    }

    // Post FY2026 activity across all 8 account types.
    for (key, legs) in [
        (
            b"fy26-stock" as &[u8],
            &[
                ("1010", Side::Debit, 250),
                ("2010", Side::Credit, 100),
                ("3010", Side::Credit, 150),
            ][..],
        ),
        (
            b"fy26-flow",
            &[
                ("1010", Side::Debit, 120),
                ("5010", Side::Debit, 80),
                ("4010", Side::Credit, 200),
            ][..],
        ),
        (
            b"fy26-memo",
            &[("8010", Side::Debit, 150), ("8020", Side::Credit, 150)][..],
        ),
        (
            b"fy26-offbal",
            &[("8510", Side::Debit, 225), ("8520", Side::Credit, 225)][..],
        ),
        (
            b"fy26-stat",
            &[("9010", Side::Debit, 8), ("9020", Side::Credit, 8)][..],
        ),
    ] {
        let (k_res, o_res) = post_dated(&mut h, &mut oracle, mar_2026, key, legs);
        assert!(matches!(k_res, Ok(Posted::Committed { .. })));
        assert!(matches!(o_res, fa_reference::Verdict::Posted { .. }));
    }

    // Also place one pending hold on monetary accounts and one on memo accounts in FY2026.
    h.hold(
        vec![
            LegPayload::simple(Side::Debit, vid("5010"), Amount::new(usd, 55)),
            LegPayload::simple(Side::Credit, vid("1010"), Amount::new(usd, 55)),
        ],
        b"hold-monetary",
    );
    h.hold(
        vec![
            LegPayload::simple(Side::Debit, vid("8010"), Amount::new(usd, 99)),
            LegPayload::simple(Side::Credit, vid("8020"), Amount::new(usd, 99)),
        ],
        b"hold-memo",
    );

    let as_of_tb = balance_as_of(&h.db, &h.book, end_mar_2026, None).expect("balance_as_of");
    let periods_tb =
        trial_balance_at(&h.db, &h.book, &[h.march.clone()], None).expect("trial_balance_at");
    assert_eq!(as_of_tb.rows, periods_tb.rows);
    assert_eq!(as_of_tb.unit_totals, periods_tb.unit_totals);
    assert_eq!(as_of_tb.pending_unit_totals, periods_tb.pending_unit_totals);
    assert!(as_of_tb.is_balanced());

    let oracle_stock = oracle.stock_known(end_mar_2026, oracle.known());
    let got_stock: BTreeMap<(String, u32), (i128, i128)> = as_of_tb
        .rows
        .iter()
        .map(|r| ((r.code.clone(), r.unit_id), (r.debits, r.credits)))
        .collect();
    let want_stock: BTreeMap<(String, u32), (i128, i128)> = oracle_stock
        .iter()
        .map(|(k, c)| {
            (
                k.clone(),
                (c.debits.to_i128().unwrap(), c.credits.to_i128().unwrap()),
            )
        })
        .collect();
    assert_eq!(
        got_stock, want_stock,
        "as-of TB rows match oracle ITD fold across all 8 account types"
    );
    assert_eq!(
        as_of_tb.unit_totals,
        oracle.trial_balance_totals(&oracle_stock),
        "monetary unit_totals exclude Memo (6), Statistical (7), and OffBalance (8) rows"
    );
    assert_eq!(
        as_of_tb.pending_unit_totals.get(&usd.0).copied(),
        Some((55, 55)),
        "pending_unit_totals include monetary holds (55) and exclude memo holds (99)"
    );

    let act_tb =
        period_activity(&h.db, &h.book, &[h.march.clone()], None).expect("period_activity");
    let oracle_act = oracle.activity_known(&[h.march.as_str()], oracle.known());
    let got_act: BTreeMap<(String, u32), (i128, i128)> = act_tb
        .rows
        .iter()
        .map(|r| ((r.code.clone(), r.unit_id), (r.debits, r.credits)))
        .collect();
    let want_act: BTreeMap<(String, u32), (i128, i128)> = oracle_act
        .iter()
        .map(|(k, c)| {
            (
                k.clone(),
                (c.debits.to_i128().unwrap(), c.credits.to_i128().unwrap()),
            )
        })
        .collect();
    assert_eq!(got_act, want_act);
    assert_eq!(act_tb.unit_totals, oracle.trial_balance_totals(&oracle_act));

    for (code, _, tag, _) in type_accounts {
        let stock_row = as_of_tb
            .rows
            .iter()
            .find(|r| r.code == *code)
            .expect("present in as_of_tb");
        let act_row = act_tb
            .rows
            .iter()
            .find(|r| r.code == *code)
            .expect("present in act_tb");
        assert_eq!(stock_row.account_type.0, *tag);
        assert!(
            stock_row.debits > act_row.debits || stock_row.credits > act_row.credits,
            "as-of folds inception-to-date (FY2025 + FY2026) for account {code} (type {tag})"
        );
        eprintln!(
            "fa-a57x account_type={}({}) is_memo={} selector=as-of:{} result=({},{}) selector=activity:{} result=({},{})",
            stock_row.account_type.name().unwrap_or("?"),
            tag,
            stock_row.account_type.is_memo(),
            end_mar_2026,
            stock_row.debits,
            stock_row.credits,
            h.march,
            act_row.debits,
            act_row.credits,
        );
    }
}

#[test]
fn memo_off_balance_and_single_sided_statistical_legs_obey_partition_and_footing_law() {
    use fa_model::AccountType;
    use fa_registers::verify_entities;

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let each = h.book.units.lookup("EACH").unwrap();
    let hour = h.book.units.lookup("HOUR").unwrap();
    let mar_2026 = DateDay::from_ymd(2026, 3, 15).unwrap();
    let end_mar_2026 = DateDay::from_ymd(2026, 3, 31).unwrap();

    let extra_accounts = [
        AccountSpec {
            code: "8100".into(),
            name: "MemoAsset".into(),
            account_type: AccountType::MEMO.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "8200".into(),
            name: "MemoCounter".into(),
            account_type: AccountType::MEMO.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "8510".into(),
            name: "LeaseCommitment".into(),
            account_type: AccountType::OFF_BALANCE.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "8520".into(),
            name: "LeaseCommitmentCounter".into(),
            account_type: AccountType::OFF_BALANCE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "9100".into(),
            name: "Headcount".into(),
            account_type: AccountType::STATISTICAL.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(each),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "9200".into(),
            name: "BillableHours".into(),
            account_type: AccountType::STATISTICAL.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(hour),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "1990".into(),
            name: "InventoryUnitsAsset".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"memo-offbal-stat".to_string(),
            None,
            &book.seal_key,
            [21; 32],
            [22; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &extra_accounts,
                    PRINCIPAL,
                    mar_2026,
                    b"install-memo-offbal-stat",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("installed");
    }

    let mut oracle = fa_reference::Oracle::new(h.book.calendar.clone());
    oracle.create_periods(2026);
    oracle
        .transition(&h.march, PeriodTransition::Open)
        .expect("oracle open 2026-p03");
    for (code, tag, unit_opt) in [
        ("1000", AccountType::ASSET.0, Some(usd.0)),
        ("6000", AccountType::EXPENSE.0, Some(usd.0)),
        ("8100", AccountType::MEMO.0, None),
        ("8200", AccountType::MEMO.0, None),
        ("8510", AccountType::OFF_BALANCE.0, None),
        ("8520", AccountType::OFF_BALANCE.0, None),
        ("9100", AccountType::STATISTICAL.0, Some(each.0)),
        ("9200", AccountType::STATISTICAL.0, Some(hour.0)),
        ("1990", AccountType::ASSET.0, None),
    ] {
        oracle.add_account(fa_reference::Account {
            code: code.into(),
            is_leaf: true,
            unit: unit_opt,
        });
        oracle.set_account_type(code, tag);
    }

    let book_id = h.book.book_id;
    let vid = move |code: &str| account_vid(book_id, code);
    let post_both = |h: &mut Harness,
                     oracle: &mut fa_reference::Oracle,
                     key: &[u8],
                     legs: &[(&str, Side, fa_money::UnitId, i128)]|
     -> (Result<Posted, Refusal>, fa_reference::Verdict) {
        let k_legs: Vec<LegPayload> = legs
            .iter()
            .map(|(c, side, u, m)| LegPayload::simple(*side, vid(c), Amount::new(*u, *m)))
            .collect();
        let mut proposal = h.proposal(k_legs, key, EntryClass::ORIGINAL);
        proposal.effective_date = mar_2026;
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).expect("post"),
        };
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let k_res = h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel");
        let o_legs: Vec<fa_reference::Leg> = legs
            .iter()
            .map(|(c, side, u, m)| fa_reference::Leg {
                side: match side {
                    Side::Debit => fa_reference::Side::Debit,
                    Side::Credit => fa_reference::Side::Credit,
                },
                account: (*c).into(),
                unit: u.0,
                entity: None,
                mantissa: *m,
            })
            .collect();
        let o_intent = fa_reference::Intent {
            class: "Original".into(),
            date: mar_2026,
            discriminator: None,
            legs: o_legs,
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 0,
            resolves: None,
            settles: Vec::new(),
            key: key.to_vec(),
        };
        let o_res = oracle.post(&o_intent);
        (k_res, o_res)
    };

    // 1. Single-sided statistical postings in EACH or HOUR on Statistical accounts succeed;
    //    single-sided postings in USD fail FA-REF-100; single-sided postings in EACH on
    //    Asset, Memo, or OffBalance fail FA-REF-001.
    for (bad_key, bad_legs, want_code, want_exit) in [
        (
            b"1leg-usd-stat" as &[u8],
            &[("9100", Side::Debit, usd, 10)][..],
            "FA-REF-100",
            exit::USAGE,
        ),
        (
            b"1leg-each-asset",
            &[("1990", Side::Debit, each, 10)][..],
            "FA-REF-001",
            exit::REFUSAL,
        ),
        (
            b"1leg-each-memo",
            &[("8100", Side::Debit, each, 10)][..],
            "FA-REF-001",
            exit::REFUSAL,
        ),
        (
            b"1leg-each-offbal",
            &[("8510", Side::Debit, each, 10)][..],
            "FA-REF-001",
            exit::REFUSAL,
        ),
        (
            b"2leg-each-asset-stat",
            &[
                ("1990", Side::Debit, each, 10),
                ("9100", Side::Credit, each, 10),
            ][..],
            "FA-REF-001",
            exit::REFUSAL,
        ),
    ] {
        let (k_res, o_res) = post_both(&mut h, &mut oracle, bad_key, bad_legs);
        let err = k_res.expect_err("expected refusal");
        assert_eq!((err.code, err.exit), (want_code, want_exit), "{err}");
        assert_eq!(
            o_res,
            fa_reference::Verdict::Refused { code: want_code },
            "key {:?}",
            std::str::from_utf8(bad_key)
        );
    }

    // 2. Post valid single-sided statistical entries (headcount in EACH, hours in HOUR),
    //    balanced OffBalance commitment in USD, and composite entry with monetary + OffBalance + Statistical.
    for (ok_key, ok_legs) in [
        (
            b"stat-headcount-1leg" as &[u8],
            &[("9100", Side::Debit, each, 42)][..],
        ),
        (
            b"stat-hours-1leg",
            &[("9200", Side::Debit, hour, 16_000)][..],
        ),
        (
            b"offbal-commitment",
            &[
                ("8510", Side::Debit, usd, 250_000),
                ("8520", Side::Credit, usd, 250_000),
            ][..],
        ),
        (
            b"composite-monetary-offbal-stat",
            &[
                ("6000", Side::Debit, usd, 100_000),
                ("1000", Side::Credit, usd, 100_000),
                ("8100", Side::Debit, usd, 50_000),
                ("8520", Side::Credit, usd, 50_000),
                ("9100", Side::Debit, each, 3),
            ][..],
        ),
    ] {
        let (k_res, o_res) = post_both(&mut h, &mut oracle, ok_key, ok_legs);
        assert!(matches!(k_res, Ok(Posted::Committed { .. })), "{k_res:?}");
        assert!(
            matches!(o_res, fa_reference::Verdict::Posted { .. }),
            "{o_res:?}"
        );
    }

    let tb = balance_as_of(&h.db, &h.book, end_mar_2026, None).expect("balance_as_of");
    assert!(
        tb.is_balanced(),
        "monetary trial balance must remain balanced"
    );
    assert_eq!(
        tb.unit_totals.get(&usd.0).copied(),
        Some((100_000, 100_000)),
        "monetary unit_totals include only 1000/6000 (100_000) and exclude Memo/OffBalance (300_000)"
    );
    assert_eq!(
        tb.unit_totals.get(&each.0),
        None,
        "statistical EACH rows do not enter monetary unit_totals"
    );
    let headcount_row = tb
        .rows
        .iter()
        .find(|r| r.code == "9100")
        .expect("9100 row present");
    assert_eq!(
        (
            headcount_row.debits,
            headcount_row.credits,
            headcount_row.unit_id
        ),
        (45, 0, each.0)
    );
    let hours_row = tb
        .rows
        .iter()
        .find(|r| r.code == "9200")
        .expect("9200 row present");
    assert_eq!(
        (hours_row.debits, hours_row.credits, hours_row.unit_id),
        (16_000, 0, hour.0)
    );
    let offbal_row = tb
        .rows
        .iter()
        .find(|r| r.code == "8510")
        .expect("8510 row present");
    assert_eq!(
        (
            offbal_row.debits,
            offbal_row.credits,
            offbal_row.account_type
        ),
        (250_000, 0, AccountType::OFF_BALANCE)
    );

    let entity_v = verify_entities(&h.db, &h.book, &h.march, None).expect("verify_entities");
    assert!(entity_v.is_green(), "findings: {:?}", entity_v.findings);
}

#[test]
fn lots_fifo_lifo_wac_specific_id_reversal_and_reference_differential() {
    use fa_model::{AccountType, EntryRef};
    use fa_money::{
        AccountingRegime, ConversionError, LotError, LotLaw, RoundingLaw, convert_with_law,
    };
    use fa_reference::lots::{RefLot, RefRounding, convert_oracle, relieve_lots_oracle};
    use fa_registers::{LotDisposalRequest, lots, verify_open_items};

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let share = h.book.units.lookup("SHARE").unwrap();
    let mar_10 = DateDay::from_ymd(2026, 3, 10).unwrap();
    let mar_12 = DateDay::from_ymd(2026, 3, 12).unwrap();
    let mar_15 = DateDay::from_ymd(2026, 3, 15).unwrap();
    let mar_20 = DateDay::from_ymd(2026, 3, 20).unwrap();

    // Install AnyUnit inventory account 1400, share clearing 1499, and COGS 5000.
    let lot_accounts = [
        AccountSpec {
            code: "1400".into(),
            name: "InventoryLots".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "1499".into(),
            name: "InventoryQuantityClearing".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(share),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "5000".into(),
            name: "CostOfGoodsSold".into(),
            account_type: AccountType::EXPENSE.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"install-lot-accounts".to_string(),
            None,
            &book.seal_key,
            [31; 32],
            [32; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &lot_accounts,
                    PRINCIPAL,
                    mar_10,
                    b"install-lot-accounts",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("installed");
    }

    let inv = account_vid(h.book.book_id, "1400");
    let qty_clear = account_vid(h.book.book_id, "1499");
    let cogs = account_vid(h.book.book_id, "5000");
    let cash = h.cash;

    // Acquire Lot 1 on 2026-03-10: buy 10 SHARE (scale 4 -> 100_000) @ 100 USD (scale 2 -> 100_000 cents = $1,000.00).
    let lot1_legs = vec![
        LegPayload::simple(Side::Debit, inv, Amount::new(share, 100_000)),
        LegPayload::simple(Side::Credit, qty_clear, Amount::new(share, 100_000)),
        LegPayload::simple(Side::Debit, inv, Amount::new(usd, 100_000)),
        LegPayload::simple(Side::Credit, cash, Amount::new(usd, 100_000)),
    ];
    let mut prop1 = h.proposal(lot1_legs, b"buy-lot-1", EntryClass::ORIGINAL);
    prop1.effective_date = mar_10;
    let lot1_vid = {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: prop1,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        match h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap()
        {
            Posted::Committed { entry_ref, .. } => entry_ref.vid,
            other => panic!("unexpected: {other:?}"),
        }
    };

    // Acquire Lot 2 on 2026-03-12: buy 10 SHARE (100_000) @ 120 USD (120_000 cents = $1,200.00).
    let lot2_legs = vec![
        LegPayload::simple(Side::Debit, inv, Amount::new(share, 100_000)),
        LegPayload::simple(Side::Credit, qty_clear, Amount::new(share, 100_000)),
        LegPayload::simple(Side::Debit, inv, Amount::new(usd, 120_000)),
        LegPayload::simple(Side::Credit, cash, Amount::new(usd, 120_000)),
    ];
    let mut prop2 = h.proposal(lot2_legs, b"buy-lot-2", EntryClass::ORIGINAL);
    prop2.effective_date = mar_12;
    let lot2_vid = {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: prop2,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        match h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap()
        {
            Posted::Committed { entry_ref, .. } => entry_ref.vid,
            other => panic!("unexpected: {other:?}"),
        }
    };

    let report = lots(&h.db, &h.book, inv, None, None).expect("lots report");
    assert_eq!(report.lots.len(), 2);
    assert_eq!(report.lots[0].entry, lot1_vid);
    assert_eq!(report.lots[0].open_quantity.mantissa, 100_000);
    assert_eq!(report.lots[0].open_cost.mantissa, 100_000);
    assert_eq!(report.lots[1].entry, lot2_vid);
    assert_eq!(report.lots[1].open_quantity.mantissa, 100_000);
    assert_eq!(report.lots[1].open_cost.mantissa, 120_000);

    let ref_lots: Vec<RefLot> = report
        .lots
        .iter()
        .map(|l| RefLot {
            entry_id: l.entry.0,
            ordinal: l.qty_ordinal,
            effective_day: l.effective_date.0,
            recorded_seq: l.recorded_at.0,
            quantity_unit: l.open_quantity.unit.0,
            open_quantity: l.open_quantity.mantissa,
            cost_unit: l.open_cost.unit.0,
            open_cost: l.open_cost.mantissa,
        })
        .collect();

    // Plan sell 15 SHARE (150_000) under FIFO, LIFO, WeightedAverage, SpecificId and verify against fa-reference!
    for (law, law_str, targets, expected_cost) in [
        (LotLaw::Fifo, "FIFO", vec![], 160_000i128),
        (LotLaw::Lifo, "LIFO", vec![], 170_000i128),
        (
            LotLaw::WeightedAverage,
            "WeightedAverage",
            vec![],
            165_000i128,
        ),
        (
            LotLaw::SpecificId,
            "SpecificId",
            vec![(lot2_vid, 0), (lot1_vid, 0)],
            170_000i128,
        ),
    ] {
        let plan = report
            .plan_disposal(&LotDisposalRequest {
                quantity: Amount::new(share, 150_000),
                law,
                regime: AccountingRegime::UsGaap,
                rounding_law: RoundingLaw::HalfEven,
                targets: targets.clone(),
            })
            .expect("plan disposal");
        assert_eq!(plan.total_cost.mantissa, expected_cost, "law {law:?}");

        let ref_targets: Vec<(u128, u16)> = targets.iter().map(|(v, o)| (v.0, *o)).collect();
        let oracle_out = relieve_lots_oracle(
            &ref_lots,
            share.0,
            150_000,
            law_str,
            Some("US-GAAP"),
            RefRounding::HalfEven,
            &ref_targets,
        )
        .expect("oracle disposal");
        assert_eq!(oracle_out.total_cost, plan.total_cost.mantissa);
        assert_eq!(oracle_out.slices.len(), plan.slices.len());
        for (s_engine, s_oracle) in plan.slices.iter().zip(oracle_out.slices.iter()) {
            assert_eq!(s_engine.entry.0, s_oracle.entry_id);
            assert_eq!(s_engine.qty_ordinal, s_oracle.ordinal);
            assert_eq!(
                s_engine.quantity_relieved.mantissa,
                s_oracle.quantity_relieved
            );
            assert_eq!(s_engine.cost_relieved.mantissa, s_oracle.cost_relieved);
            assert_eq!(
                s_engine.open_quantity_after.mantissa,
                s_oracle.open_quantity_after
            );
            assert_eq!(s_engine.open_cost_after.mantissa, s_oracle.open_cost_after);
        }
    }

    // Planted negatives:
    // 1. LIFO under IFRS refused citing IAS 2.25 (both engine and oracle).
    let ifrs_err = report
        .plan_disposal(&LotDisposalRequest {
            quantity: Amount::new(share, 50_000),
            law: LotLaw::Lifo,
            regime: AccountingRegime::Ifrs,
            rounding_law: RoundingLaw::HalfEven,
            targets: vec![],
        })
        .expect_err("LIFO refused under IFRS");
    assert!(matches!(
        ifrs_err,
        LotError::RegimeRefused {
            law: LotLaw::Lifo,
            regime: AccountingRegime::Ifrs,
            ref citation,
        } if citation.contains("IAS 2.25")
    ));
    assert!(
        relieve_lots_oracle(
            &ref_lots,
            share.0,
            50_000,
            "LIFO",
            Some("IFRS"),
            RefRounding::HalfEven,
            &[]
        )
        .unwrap_err()
        .contains("IAS 2.25")
    );

    // 2. Over-relief refused (both engine and oracle).
    let over_err = report
        .plan_disposal(&LotDisposalRequest {
            quantity: Amount::new(share, 250_000),
            law: LotLaw::Fifo,
            regime: AccountingRegime::UsGaap,
            rounding_law: RoundingLaw::HalfEven,
            targets: vec![],
        })
        .expect_err("over-relief refused");
    assert!(matches!(over_err, LotError::OverRelief { .. }));
    assert!(
        relieve_lots_oracle(
            &ref_lots,
            share.0,
            250_000,
            "FIFO",
            None,
            RefRounding::HalfEven,
            &[]
        )
        .is_err()
    );

    // 3. Implicit unit conversion refused, explicit conversion matches oracle.
    let mut conv_reg = h.book.units.clone();
    let hour = conv_reg.lookup("HOUR").unwrap();
    let day = conv_reg
        .register(fa_money::Unit {
            code: "DAY".into(),
            scale: 4,
            version: 0,
            kind: fa_money::UnitKind::Time,
            rounding_default: RoundingLaw::HalfEven,
        })
        .unwrap();
    let conv_laws = fa_registry::ConversionLaws::embedded().unwrap();
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = fa_money::ArithmeticBudget::new(
        &cx,
        fa_money::BudgetLimits::uniform(1_000_000_000, 0),
        8192,
    );
    let imp_err = convert_with_law(
        Amount::new(hour, 2000),
        day,
        None,
        &conv_laws,
        &conv_reg,
        &mut budget,
    )
    .expect_err("implicit conversion refused");
    assert!(matches!(
        imp_err,
        ConversionError::ImplicitConversionRefused {
            ref matching_laws,
            ..
        } if matching_laws.iter().any(|s| s == "HoursToDays8h")
    ));
    let conv = convert_with_law(
        Amount::new(hour, 2000),
        day,
        Some("HoursToDays8h"),
        &conv_laws,
        &conv_reg,
        &mut budget,
    )
    .expect("explicit conversion");
    let oracle_conv = convert_oracle(
        2000,
        "HOUR",
        2,
        "DAY",
        4,
        Some("HoursToDays8h"),
        RefRounding::HalfEven,
    )
    .expect("oracle conversion");
    assert_eq!(conv.mantissa, oracle_conv);
    assert_eq!(conv.mantissa, 25_000);

    // Commit the FIFO disposal of 15 SHARE on 2026-03-15 using the plan's quantity and cost settlements!
    let fifo_plan = report
        .plan_disposal(&LotDisposalRequest {
            quantity: Amount::new(share, 150_000),
            law: LotLaw::Fifo,
            regime: AccountingRegime::UsGaap,
            rounding_law: RoundingLaw::HalfEven,
            targets: vec![],
        })
        .unwrap();
    let mut disp_qty_leg = LegPayload::simple(Side::Credit, inv, fifo_plan.total_quantity);
    disp_qty_leg.settles = fifo_plan.quantity_settlements();
    let mut disp_cost_leg = LegPayload::simple(Side::Credit, inv, fifo_plan.total_cost);
    disp_cost_leg.settles = fifo_plan.cost_settlements();
    let disp_legs = vec![
        LegPayload::simple(Side::Debit, qty_clear, fifo_plan.total_quantity),
        disp_qty_leg,
        LegPayload::simple(Side::Debit, cogs, fifo_plan.total_cost),
        disp_cost_leg,
    ];
    let mut disp_prop = h.proposal(disp_legs, b"sell-15-fifo", EntryClass::ORIGINAL);
    disp_prop.effective_date = mar_15;
    let (disp_vid, disp_digest) = {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: disp_prop,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        match h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap()
        {
            Posted::Committed { entry_ref, .. } => (entry_ref.vid, entry_ref.entry_digest),
            other => panic!("unexpected: {other:?}"),
        }
    };

    // Verify open-item mirrors and check post-disposal lot report:
    // Lot 1 is fully relieved (open 0 SHARE, 0 USD), Lot 2 has 5 SHARE (50_000) and $600 (60_000) open!
    assert!(verify_open_items(&h.db, &h.book, None).unwrap().is_green());
    let after_disp = lots(&h.db, &h.book, inv, None, None).unwrap();
    assert_eq!(after_disp.lots[0].open_quantity.mantissa, 0);
    assert_eq!(after_disp.lots[0].open_cost.mantissa, 0);
    assert_eq!(after_disp.lots[0].relieves.len(), 1);
    assert!(after_disp.lots[0].relieves[0].live);
    assert_eq!(after_disp.lots[0].relieves[0].quantity.mantissa, 100_000);
    assert_eq!(after_disp.lots[0].relieves[0].cost.mantissa, 100_000);
    assert_eq!(after_disp.lots[1].open_quantity.mantissa, 50_000);
    assert_eq!(after_disp.lots[1].open_cost.mantissa, 60_000);
    assert_eq!(after_disp.lots[1].relieves.len(), 1);
    assert!(after_disp.lots[1].relieves[0].live);
    assert_eq!(after_disp.lots[1].relieves[0].quantity.mantissa, 50_000);
    assert_eq!(after_disp.lots[1].relieves[0].cost.mantissa, 60_000);

    // Reverse the disposal entry on 2026-03-20: UNSETTLES restores both Lot 1 and Lot 2!
    let rev_legs = vec![
        LegPayload::simple(Side::Credit, qty_clear, fifo_plan.total_quantity),
        LegPayload::simple(Side::Debit, inv, fifo_plan.total_quantity),
        LegPayload::simple(Side::Credit, cogs, fifo_plan.total_cost),
        LegPayload::simple(Side::Debit, inv, fifo_plan.total_cost),
    ];
    let mut rev_prop = h.proposal(rev_legs, b"rev-sell-15-fifo", EntryClass::REVERSAL);
    rev_prop.effective_date = mar_20;
    rev_prop.supersession = vec![Supersession {
        kind: SupersessionKind::Reverses,
        target: EntryRef {
            vid: disp_vid,
            entry_digest: disp_digest,
        },
        reason_code: 1,
    }];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: rev_prop,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }

    assert!(verify_open_items(&h.db, &h.book, None).unwrap().is_green());
    let after_rev = lots(&h.db, &h.book, inv, None, None).unwrap();
    assert_eq!(after_rev.lots[0].open_quantity.mantissa, 100_000);
    assert_eq!(after_rev.lots[0].open_cost.mantissa, 100_000);
    assert!(!after_rev.lots[0].relieves[0].live);
    assert_eq!(after_rev.lots[1].open_quantity.mantissa, 100_000);
    assert_eq!(after_rev.lots[1].open_cost.mantissa, 120_000);
    assert!(!after_rev.lots[1].relieves[0].live);
}

#[test]
fn fx_valuation_residual_revaluation_and_realized_fx_match_oracle_and_fold_functionally() {
    use fa_journal::{
        FxLawId, FxRateDocument, FxRatePurpose, add_document, plan_realized_fx_settlement,
        plan_revaluation, value_proposal,
    };
    use fa_money::RoundingLaw;
    use fa_money_rate::*;
    use fa_reference::fx::{
        OracleFunctionalEntry, OracleFxLeg, OracleRateQuote, OracleRealizedLeg,
        fold_functional_period, value_entity_legs, verify_realized_fx,
    };
    use fa_registers::{FunctionalCellKey, fold_period_functional, verify_functional_fold};

    mod fa_money_rate {
        pub use asupersync::Cx;
        pub use fa_money::rate::{ArithmeticBudget, BudgetLimits};
    }

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let mar_05 = DateDay::from_ymd(2026, 3, 5).unwrap();
    let mar_10 = DateDay::from_ymd(2026, 3, 10).unwrap();
    let mar_25 = DateDay::from_ymd(2026, 3, 25).unwrap();
    let mar_28 = DateDay::from_ymd(2026, 3, 28).unwrap();

    let fx_accounts = vec![
        AccountSpec {
            code: "1210".into(),
            name: "AccountsReceivableEur".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "4110".into(),
            name: "RevenueEur".into(),
            account_type: AccountType::REVENUE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "2910".into(),
            name: "FxConversionClearing".into(),
            account_type: AccountType::LIABILITY.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "7110".into(),
            name: "RealizedFxGainLoss".into(),
            account_type: AccountType::REVENUE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "7120".into(),
            name: "UnrealizedFxGainLoss".into(),
            account_type: AccountType::REVENUE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"install-fx-chart".to_string(),
            None,
            &book.seal_key,
            [61; 32],
            [62; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &fx_accounts,
                    PRINCIPAL,
                    mar_05,
                    b"install-fx-chart",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .unwrap()
            .unwrap();
    }

    let ar_eur = account_vid(h.book.book_id, "1210");
    let rev_eur = account_vid(h.book.book_id, "4110");
    let fx_conv = account_vid(h.book.book_id, "2910");
    let fx_realized = account_vid(h.book.book_id, "7110");
    let fx_unrealized = account_vid(h.book.book_id, "7120");
    let spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();

    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    // 1. SpotClose with rounding residual (Dr 0.01 EUR, Dr 0.01 EUR / Cr 0.02 EUR at 1/2 USD/EUR under HalfUp).
    let rate_half = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 1,
            rate_den: 2,
            rounding: RoundingLaw::HalfUp,
        },
        mar_05,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_half.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }

    let mut raw_res = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Credit, rev_eur, Amount::new(eur, 2)),
        ],
        b"fx-spot-residual",
        EntryClass::ORIGINAL,
    );
    raw_res.effective_date = mar_05;
    let valued_res = value_proposal(
        &mut budget,
        raw_res,
        &spec,
        &h.book.units,
        FxLawId::SpotClose,
        std::slice::from_ref(&rate_half),
    )
    .unwrap();

    // Cross-check against independent reference oracle (`fa_reference::fx::value_entity_legs`).
    let mut oracle_rates = std::collections::BTreeMap::new();
    oracle_rates.insert(
        eur.0,
        OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 1,
            rate_den: 2,
            rounding_law: "HalfUp".into(),
        },
    );
    let oracle_val = value_entity_legs(
        &[
            OracleFxLeg {
                side: fa_reference::Side::Debit,
                account: ar_eur.0,
                unit: eur.0,
                mantissa: 1,
                entity: None,
            },
            OracleFxLeg {
                side: fa_reference::Side::Debit,
                account: ar_eur.0,
                unit: eur.0,
                mantissa: 1,
                entity: None,
            },
            OracleFxLeg {
                side: fa_reference::Side::Credit,
                account: rev_eur.0,
                unit: eur.0,
                mantissa: 2,
                entity: None,
            },
        ],
        usd.0,
        2,
        &oracle_rates,
    )
    .unwrap();
    let bt_res = valued_res.base_totals.as_ref().unwrap();
    assert_eq!(bt_res.debits, oracle_val.base_debits);
    assert_eq!(bt_res.credits, oracle_val.base_credits);
    assert_eq!(
        bt_res.residual.map(|r| (r.leg_ordinal, r.amount.mantissa)),
        oracle_val.residual
    );
    assert_eq!(oracle_val.residual, Some((2, 1)));

    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: valued_res.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }

    // 2. SpotClose invoice of 100.00 EUR at 1.10 USD/EUR (110.00 USD) on 2026-03-10.
    let rate_spot = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 110,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        mar_10,
        1_700_100_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_spot.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }
    let mut raw_inv = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 10_000)),
            LegPayload::simple(Side::Credit, rev_eur, Amount::new(eur, 10_000)),
        ],
        b"fx-spot-100-eur",
        EntryClass::ORIGINAL,
    );
    raw_inv.effective_date = mar_10;
    let valued_inv = value_proposal(
        &mut budget,
        raw_inv,
        &spec,
        &h.book.units,
        FxLawId::SpotClose,
        std::slice::from_ref(&rate_spot),
    )
    .unwrap();
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: valued_inv.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }

    // 3. PeriodEndRevaluation of the 100.00 EUR receivable at period-close rate 1.15 USD/EUR (+5.00 USD).
    let rate_close = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 115,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        mar_25,
        1_700_200_000_000_000_000,
        FxRatePurpose::PeriodClose,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_close.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }
    let mut reval_tpl = h.proposal(Vec::new(), b"fx-reval-mar25", EntryClass::REVALUATION);
    reval_tpl.effective_date = mar_25;
    reval_tpl.evidence.clear();
    let reval_prop = plan_revaluation(
        &mut budget,
        reval_tpl,
        ar_eur,
        Side::Debit,
        Amount::new(eur, 10_000),
        Amount::new(usd, 11_000),
        fx_unrealized,
        &rate_close,
        Vec::new(),
        &h.book.units,
    )
    .unwrap();
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: reval_prop.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }

    // 4. Realized FX settlement of the 100.00 EUR receivable (now carried at 115.00 USD)
    //    into USD cash at settlement rate 1.18 USD/EUR (118.00 USD; +3.00 USD realized gain).
    let rate_settle = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 118,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        mar_28,
        1_700_300_000_000_000_000,
        FxRatePurpose::Settlement,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_settle.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }
    let mut settle_tpl = h.proposal(Vec::new(), b"fx-settle-mar28", EntryClass::ORIGINAL);
    settle_tpl.effective_date = mar_28;
    let settle_prop = plan_realized_fx_settlement(
        &mut budget,
        settle_tpl,
        ar_eur,
        Side::Credit,
        Amount::new(eur, 10_000),
        Amount::new(usd, 11_500),
        h.cash,
        fx_conv,
        fx_realized,
        &rate_settle,
        Vec::new(),
        &h.book.units,
    )
    .unwrap();

    // Verify realized FX entry against independent reference oracle (`FA-INV-01.realized-fx`).
    let to_oracle_legs = |p: &EntryPayload| -> Vec<OracleRealizedLeg> {
        p.legs
            .iter()
            .map(|l| OracleRealizedLeg {
                side: match l.side {
                    Side::Debit => fa_reference::Side::Debit,
                    Side::Credit => fa_reference::Side::Credit,
                },
                account: l.account_ref.0,
                unit: l.amount.unit.0,
                mantissa: l.amount.mantissa,
                base_unit: l.base_amount.unwrap().unit.0,
                base_mantissa: l.base_amount.unwrap().mantissa,
                entity: None,
            })
            .collect()
    };
    verify_realized_fx(
        &to_oracle_legs(&settle_prop),
        usd.0,
        2,
        eur.0,
        2,
        118,
        100,
        "HalfEven",
    )
    .expect("reference oracle verifies paired conversion realized FX entry");

    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: settle_prop.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }

    // 5. Functional-value register fold (`FA-INV-04.functional-fold`) and reference differential.
    let f_fold = fold_period_functional(&h.db, &h.book, &h.march, None).unwrap();
    verify_functional_fold(&h.db, &h.book, &h.march, &f_fold).unwrap();
    assert_eq!(
        f_fold.total_debits().unwrap(),
        f_fold.total_credits().unwrap()
    );

    // Paired conversion clearing account nets to 0 in functional currency!
    let conv_cell = f_fold
        .cell(&FunctionalCellKey {
            account: fx_conv,
            unit_id: usd.0,
            period: h.march.clone(),
            entity: None,
        })
        .unwrap();
    assert_eq!(conv_cell.debits, 11_500);
    assert_eq!(conv_cell.credits, 11_500);
    assert_eq!(conv_cell.net(), Some(0));

    let oracle_entries = vec![
        OracleFunctionalEntry {
            period: h.march.clone(),
            is_pending: false,
            is_resolved: false,
            legs: to_oracle_legs(&valued_res),
        },
        OracleFunctionalEntry {
            period: h.march.clone(),
            is_pending: false,
            is_resolved: false,
            legs: to_oracle_legs(&valued_inv),
        },
        OracleFunctionalEntry {
            period: h.march.clone(),
            is_pending: false,
            is_resolved: false,
            legs: to_oracle_legs(&reval_prop),
        },
        OracleFunctionalEntry {
            period: h.march.clone(),
            is_pending: false,
            is_resolved: false,
            legs: to_oracle_legs(&settle_prop),
        },
    ];
    let oracle_fold = fold_functional_period(&oracle_entries, usd.0, &h.march).unwrap();
    assert_eq!(f_fold.cells.len(), oracle_fold.len());
    for cell in &f_fold.cells {
        let key = (
            cell.key.account.0,
            cell.key.unit_id,
            cell.key.period.clone(),
            cell.key.entity.clone(),
        );
        assert_eq!(
            oracle_fold.get(&key).copied(),
            Some((cell.debits, cell.credits, cell.entry_count))
        );
    }
}

#[test]
fn fx_unbalanced_base_amounts_are_refused_without_mutating_book() {
    use asupersync::Cx;
    use fa_journal::{FxLawId, FxRateDocument, FxRatePurpose, add_document, exit, value_proposal};
    use fa_money::RoundingLaw;
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let mar_05 = DateDay::from_ymd(2026, 3, 5).unwrap();
    let fx_accounts = vec![
        AccountSpec {
            code: "1210".into(),
            name: "AccountsReceivableEur".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "4110".into(),
            name: "RevenueEur".into(),
            account_type: AccountType::REVENUE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"install-fx-neg-base".to_string(),
            None,
            &book.seal_key,
            [71; 32],
            [72; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &fx_accounts,
                    PRINCIPAL,
                    mar_05,
                    b"install-fx-neg-base",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .unwrap()
            .unwrap();
    }
    let ar_eur = account_vid(h.book.book_id, "1210");
    let rev_eur = account_vid(h.book.book_id, "4110");
    let spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    let rate_half = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 1,
            rate_den: 2,
            rounding: RoundingLaw::HalfUp,
        },
        mar_05,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_half.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }

    let mut raw_res = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Credit, rev_eur, Amount::new(eur, 2)),
        ],
        b"fx-neg-base",
        EntryClass::ORIGINAL,
    );
    raw_res.effective_date = mar_05;
    let mut unbalanced_base = value_proposal(
        &mut budget,
        raw_res,
        &spec,
        &h.book.units,
        FxLawId::SpotClose,
        std::slice::from_ref(&rate_half),
    )
    .unwrap();

    let before = h.db.frontier().unwrap();
    unbalanced_base.legs[2].base_amount = Some(Amount::new(usd, 1));
    unbalanced_base.base_totals.as_mut().unwrap().credits = 1;
    unbalanced_base.base_totals.as_mut().unwrap().residual = None;
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: unbalanced_base,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        let err = h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap_err();
        assert_eq!((err.code, err.exit), ("FA-REF-001", exit::REFUSAL));
    }
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn fx_wrong_or_excessive_base_residual_is_refused_without_mutating_book() {
    use asupersync::Cx;
    use fa_journal::{FxLawId, FxRateDocument, FxRatePurpose, add_document, exit, value_proposal};
    use fa_model::Residual;
    use fa_money::RoundingLaw;
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let mar_05 = DateDay::from_ymd(2026, 3, 5).unwrap();
    let fx_accounts = vec![
        AccountSpec {
            code: "1210".into(),
            name: "AccountsReceivableEur".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "4110".into(),
            name: "RevenueEur".into(),
            account_type: AccountType::REVENUE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"install-fx-neg-res".to_string(),
            None,
            &book.seal_key,
            [73; 32],
            [74; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &fx_accounts,
                    PRINCIPAL,
                    mar_05,
                    b"install-fx-neg-res",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .unwrap()
            .unwrap();
    }
    let ar_eur = account_vid(h.book.book_id, "1210");
    let rev_eur = account_vid(h.book.book_id, "4110");
    let spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    let rate_half = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 1,
            rate_den: 2,
            rounding: RoundingLaw::HalfUp,
        },
        mar_05,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_half.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }

    let mut raw_res = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Credit, rev_eur, Amount::new(eur, 2)),
        ],
        b"fx-neg-res",
        EntryClass::ORIGINAL,
    );
    raw_res.effective_date = mar_05;
    let mut wrong_residual = value_proposal(
        &mut budget,
        raw_res,
        &spec,
        &h.book.units,
        FxLawId::SpotClose,
        std::slice::from_ref(&rate_half),
    )
    .unwrap();

    let before = h.db.frontier().unwrap();
    wrong_residual.base_totals.as_mut().unwrap().residual = Some(Residual {
        leg_ordinal: 0,
        amount: Amount::new(usd, 5),
    });
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: wrong_residual,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        let err = h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap_err();
        assert_eq!((err.code, err.exit), ("FA-REF-001", exit::REFUSAL));
    }
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn fx_unpaired_realized_fx_settlement_is_refused_without_mutating_book() {
    use asupersync::Cx;
    use fa_journal::{
        FxRateDocument, FxRatePurpose, add_document, exit, plan_realized_fx_settlement,
    };
    use fa_money::RoundingLaw;
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};
    use fa_reference::fx::{OracleRealizedLeg, verify_realized_fx};

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let mar_05 = DateDay::from_ymd(2026, 3, 5).unwrap();
    let fx_accounts = vec![
        AccountSpec {
            code: "1210".into(),
            name: "AccountsReceivableEur".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "2910".into(),
            name: "FxConversionClearing".into(),
            account_type: AccountType::LIABILITY.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "7110".into(),
            name: "RealizedFxGainLoss".into(),
            account_type: AccountType::REVENUE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"install-fx-neg-settle".to_string(),
            None,
            &book.seal_key,
            [75; 32],
            [76; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &fx_accounts,
                    PRINCIPAL,
                    mar_05,
                    b"install-fx-neg-settle",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .unwrap()
            .unwrap();
    }
    let ar_eur = account_vid(h.book.book_id, "1210");
    let fx_conv = account_vid(h.book.book_id, "2910");
    let fx_realized = account_vid(h.book.book_id, "7110");
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    let rate_settle = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 118,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        mar_05,
        1_700_000_000_000_000_000,
        FxRatePurpose::Settlement,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_settle.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }

    let before = h.db.frontier().unwrap();
    let mut settle_tpl = h.proposal(Vec::new(), b"fx-neg-settle", EntryClass::ORIGINAL);
    settle_tpl.effective_date = mar_05;
    let mut unpaired_settle = plan_realized_fx_settlement(
        &mut budget,
        settle_tpl,
        ar_eur,
        Side::Credit,
        Amount::new(eur, 10_000),
        Amount::new(usd, 11_000),
        h.cash,
        fx_conv,
        fx_realized,
        &rate_settle,
        Vec::new(),
        &h.book.units,
    )
    .unwrap();
    unpaired_settle.legs[1].account_ref = ar_eur;
    assert!(
        verify_realized_fx(
            &unpaired_settle
                .legs
                .iter()
                .map(|l| OracleRealizedLeg {
                    side: match l.side {
                        Side::Debit => fa_reference::Side::Debit,
                        Side::Credit => fa_reference::Side::Credit,
                    },
                    account: l.account_ref.0,
                    unit: l.amount.unit.0,
                    mantissa: l.amount.mantissa,
                    base_unit: l.base_amount.unwrap().unit.0,
                    base_mantissa: l.base_amount.unwrap().mantissa,
                    entity: None,
                })
                .collect::<Vec<_>>(),
            usd.0,
            2,
            eur.0,
            2,
            118,
            100,
            "HalfEven",
        )
        .is_err()
    );
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: unpaired_settle,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        let err = h
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap_err();
        assert_eq!((err.code, err.exit), ("FA-REF-001", exit::REFUSAL));
    }
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn fx_tampered_functional_fold_is_detected_by_verify_functional_fold() {
    use asupersync::Cx;
    use fa_journal::{FxLawId, FxRateDocument, FxRatePurpose, add_document, value_proposal};
    use fa_money::RoundingLaw;
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};
    use fa_registers::{fold_period_functional, verify_functional_fold};

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let mar_05 = DateDay::from_ymd(2026, 3, 5).unwrap();
    let fx_accounts = vec![
        AccountSpec {
            code: "1210".into(),
            name: "AccountsReceivableEur".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "4110".into(),
            name: "RevenueEur".into(),
            account_type: AccountType::REVENUE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let desc = Erasable::seal(
            &"install-fx-neg-fold".to_string(),
            None,
            &book.seal_key,
            [77; 32],
            [78; 24],
        );
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &fx_accounts,
                    PRINCIPAL,
                    mar_05,
                    b"install-fx-neg-fold",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .unwrap()
            .unwrap();
    }
    let ar_eur = account_vid(h.book.book_id, "1210");
    let rev_eur = account_vid(h.book.book_id, "4110");
    let spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    let rate_half = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 1,
            rate_den: 2,
            rounding: RoundingLaw::HalfUp,
        },
        mar_05,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    {
        let doc = rate_half.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }

    let mut raw_res = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Debit, ar_eur, Amount::new(eur, 1)),
            LegPayload::simple(Side::Credit, rev_eur, Amount::new(eur, 2)),
        ],
        b"fx-neg-fold",
        EntryClass::ORIGINAL,
    );
    raw_res.effective_date = mar_05;
    let valid_res = value_proposal(
        &mut budget,
        raw_res,
        &spec,
        &h.book.units,
        FxLawId::SpotClose,
        std::slice::from_ref(&rate_half),
    )
    .unwrap();
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: valid_res,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }
    let mut f_fold = fold_period_functional(&h.db, &h.book, &h.march, None).unwrap();
    f_fold.cells[0].debits += 1;
    assert!(verify_functional_fold(&h.db, &h.book, &h.march, &f_fold).is_err());
}

#[test]
fn fx_current_rate_translation_two_period_cta_roll_forward_and_recycling_match_oracle() {
    use fa_journal::refusal::code;
    use fa_journal::{FxRateDocument, FxRatePurpose, add_document};
    use fa_money::RoundingLaw;
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};
    use fa_reference::Side as RefSide;
    use fa_reference::fx::{
        OracleRateQuote, OracleTranslationKind, OracleTranslationLine,
        translate_current_rate_oracle,
    };
    use fa_registers::{
        TranslationInputLine, TranslationItemKind, plan_cta_deconsolidation_recycling,
        translate_current_rate, verify_translation_certificate,
    };

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let acct_cash = h.cash;
    let acct_ap = VId(990_002);
    let acct_equity = h.cash;
    let acct_rev = h.rent;
    let acct_exp = VId(990_003);
    let acct_div = VId(990_001);

    let jan_01 = DateDay::from_ymd(2026, 1, 1).unwrap();
    let jan_20 = DateDay::from_ymd(2026, 1, 20).unwrap();
    let jan_31 = DateDay::from_ymd(2026, 1, 31).unwrap();
    let feb_28 = DateDay::from_ymd(2026, 2, 28).unwrap();
    let mar_31 = DateDay::from_ymd(2026, 3, 31).unwrap();

    // Rate documents (reporting USD per 1 EUR):
    // - SpotClose 2026-01-01: 1.08 (108 / 100)
    // - SpotClose 2026-01-20: 1.11 (111 / 100)
    // - PeriodAverage 2026-01-31: 1.10 (110 / 100)
    // - PeriodClose 2026-01-31: 1.12 (112 / 100)
    // - PeriodAverage 2026-02-28: 1.13 (113 / 100)
    // - PeriodClose 2026-02-28: 1.15 (115 / 100)
    // - PeriodClose 2026-03-31: 1.15 (115 / 100) for posting recycling in h.march
    let doc_spot_jan01 = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 108,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        jan_01,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    let doc_spot_jan20 = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 111,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        jan_20,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    let doc_avg_jan = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 110,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        jan_31,
        1_700_000_000_000_000_000,
        FxRatePurpose::PeriodAverage,
        "ECB",
    )
    .unwrap();
    let doc_close_jan = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 112,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        jan_31,
        1_700_000_000_000_000_000,
        FxRatePurpose::PeriodClose,
        "ECB",
    )
    .unwrap();
    let doc_avg_feb = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 113,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        feb_28,
        1_700_000_000_000_000_000,
        FxRatePurpose::PeriodAverage,
        "ECB",
    )
    .unwrap();
    let doc_close_feb = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 115,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        feb_28,
        1_700_000_000_000_000_000,
        FxRatePurpose::PeriodClose,
        "ECB",
    )
    .unwrap();
    let doc_close_mar = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 115,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        mar_31,
        1_700_000_000_000_000_000,
        FxRatePurpose::PeriodClose,
        "ECB",
    )
    .unwrap();

    let stripped = asupersync::Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    // Period 1 (2026-01):
    // Cash: Dr EUR 1,500.00 (150_000)
    // AP: Cr EUR 300.00 (30_000)
    // Share Capital (issued 2026-01-01): Cr EUR 1,000.00 (100_000)
    // Revenue: Cr EUR 500.00 (50_000)
    // Expense: Dr EUR 200.00 (20_000)
    // Dividend (declared 2026-01-20): Dr EUR 100.00 (10_000)
    // Total Dr = 180_000, Total Cr = 180_000 (prior RE = 0)
    let p1_lines = vec![
        TranslationInputLine {
            account: acct_cash,
            kind: TranslationItemKind::Asset,
            side: Side::Debit,
            functional_amount: Amount::new(eur, 150_000),
            is_current_period_activity: true,
        },
        TranslationInputLine {
            account: acct_ap,
            kind: TranslationItemKind::Liability,
            side: Side::Credit,
            functional_amount: Amount::new(eur, 30_000),
            is_current_period_activity: true,
        },
        TranslationInputLine {
            account: acct_equity,
            kind: TranslationItemKind::ContributedEquity {
                originating_date: jan_01,
            },
            side: Side::Credit,
            functional_amount: Amount::new(eur, 100_000),
            is_current_period_activity: true,
        },
        TranslationInputLine {
            account: acct_rev,
            kind: TranslationItemKind::Revenue,
            side: Side::Credit,
            functional_amount: Amount::new(eur, 50_000),
            is_current_period_activity: true,
        },
        TranslationInputLine {
            account: acct_exp,
            kind: TranslationItemKind::Expense,
            side: Side::Debit,
            functional_amount: Amount::new(eur, 20_000),
            is_current_period_activity: true,
        },
        TranslationInputLine {
            account: acct_div,
            kind: TranslationItemKind::Dividend {
                declaration_date: jan_20,
            },
            side: Side::Debit,
            functional_amount: Amount::new(eur, 10_000),
            is_current_period_activity: true,
        },
    ];
    let hist_docs = vec![doc_spot_jan01.clone(), doc_spot_jan20.clone()];

    let stmt_p1 = translate_current_rate(
        &mut budget,
        "2026-01",
        jan_31,
        eur,
        usd,
        &p1_lines,
        &doc_close_jan,
        &doc_avg_jan,
        &hist_docs,
        0,
        0,
        0,
        &h.book.units,
    )
    .unwrap();

    // Check translated USD amounts:
    // Assets: 150_000 * 1.12 = 168_000
    // Liabilities: 30_000 * 1.12 = 33_600
    // Net Assets: 134_400
    // Equity: 100_000 * 1.08 = 108_000
    // Revenue: 50_000 * 1.10 = 55_000
    // Expense: 20_000 * 1.10 = 22_000
    // Translated NI: 33_000
    // Dividends: 10_000 * 1.11 = 11_100
    // Ending RE: 0 + 33_000 - 11_100 = 21_900
    // Ending CTA: 134_400 - (108_000 + 21_900) = 4_500
    assert_eq!(stmt_p1.total_assets_reporting, 168_000);
    assert_eq!(stmt_p1.total_liabilities_reporting, 33_600);
    assert_eq!(stmt_p1.total_contributed_equity_reporting, 108_000);
    assert_eq!(stmt_p1.translated_net_income_reporting, 33_000);
    assert_eq!(stmt_p1.total_dividends_reporting, 11_100);
    assert_eq!(stmt_p1.ending_retained_earnings_reporting, 21_900);
    assert_eq!(stmt_p1.cta_schedule.ending_cumulative_cta_credit, 4_500);
    assert_eq!(stmt_p1.cta_schedule.delta_cta_credit, 4_500);
    // CTA roll-forward decomposition tie-out:
    assert_eq!(
        stmt_p1.cta_schedule.opening_net_assets_retranslation
            + stmt_p1.cta_schedule.period_net_income_spread
            + stmt_p1.cta_schedule.equity_and_dividend_spread,
        stmt_p1.cta_schedule.delta_cta_credit
    );
    verify_translation_certificate(
        &mut budget,
        &stmt_p1,
        &p1_lines,
        &doc_close_jan,
        &doc_avg_jan,
        &hist_docs,
        0,
        &h.book.units,
    )
    .unwrap();

    // Compare against independent limb-arithmetic oracle:
    let mut oracle_hist = std::collections::BTreeMap::new();
    oracle_hist.insert(
        jan_01.0,
        OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 108,
            rate_den: 100,
            rounding_law: "HalfEven".into(),
        },
    );
    oracle_hist.insert(
        jan_20.0,
        OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 111,
            rate_den: 100,
            rounding_law: "HalfEven".into(),
        },
    );
    let oracle_p1 = translate_current_rate_oracle(
        &[
            OracleTranslationLine {
                account: acct_cash.0,
                kind: OracleTranslationKind::Asset,
                side: RefSide::Debit,
                functional_mantissa: 150_000,
            },
            OracleTranslationLine {
                account: acct_ap.0,
                kind: OracleTranslationKind::Liability,
                side: RefSide::Credit,
                functional_mantissa: 30_000,
            },
            OracleTranslationLine {
                account: acct_equity.0,
                kind: OracleTranslationKind::ContributedEquity {
                    originating_date: jan_01.0,
                },
                side: RefSide::Credit,
                functional_mantissa: 100_000,
            },
            OracleTranslationLine {
                account: acct_rev.0,
                kind: OracleTranslationKind::Revenue,
                side: RefSide::Credit,
                functional_mantissa: 50_000,
            },
            OracleTranslationLine {
                account: acct_exp.0,
                kind: OracleTranslationKind::Expense,
                side: RefSide::Debit,
                functional_mantissa: 20_000,
            },
            OracleTranslationLine {
                account: acct_div.0,
                kind: OracleTranslationKind::Dividend {
                    declaration_date: jan_20.0,
                },
                side: RefSide::Debit,
                functional_mantissa: 10_000,
            },
        ],
        2,
        2,
        &OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 112,
            rate_den: 100,
            rounding_law: "HalfEven".into(),
        },
        &OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 110,
            rate_den: 100,
            rounding_law: "HalfEven".into(),
        },
        &oracle_hist,
        0,
        0,
        0,
    )
    .unwrap();
    assert_eq!(
        stmt_p1.ending_retained_earnings_reporting,
        oracle_p1.ending_retained_earnings_reporting
    );
    assert_eq!(
        stmt_p1.cta_schedule.ending_cumulative_cta_credit,
        oracle_p1.ending_cumulative_cta_credit
    );
    assert_eq!(
        stmt_p1.cta_schedule.delta_cta_credit,
        oracle_p1.delta_cta_credit
    );

    // Period 2 (2026-02):
    // Opening functional RE = 50_000 - 20_000 - 10_000 = 20_000
    // Cash grows to EUR 1,900.00 (190_000), AP stays EUR 300.00 (30_000),
    // Share Capital stays EUR 1,000.00 (100_000, prior-period layer),
    // P2 Revenue: Cr EUR 600.00 (60_000), P2 Expense: Dr EUR 200.00 (20_000).
    // Total Dr = 210_000, Total Cr = 190_000 + prior_re_func (20_000) = 210_000.
    let p2_lines = vec![
        TranslationInputLine {
            account: acct_cash,
            kind: TranslationItemKind::Asset,
            side: Side::Debit,
            functional_amount: Amount::new(eur, 190_000),
            is_current_period_activity: false,
        },
        TranslationInputLine {
            account: acct_ap,
            kind: TranslationItemKind::Liability,
            side: Side::Credit,
            functional_amount: Amount::new(eur, 30_000),
            is_current_period_activity: false,
        },
        TranslationInputLine {
            account: acct_equity,
            kind: TranslationItemKind::ContributedEquity {
                originating_date: jan_01,
            },
            side: Side::Credit,
            functional_amount: Amount::new(eur, 100_000),
            is_current_period_activity: false,
        },
        TranslationInputLine {
            account: acct_rev,
            kind: TranslationItemKind::Revenue,
            side: Side::Credit,
            functional_amount: Amount::new(eur, 60_000),
            is_current_period_activity: true,
        },
        TranslationInputLine {
            account: acct_exp,
            kind: TranslationItemKind::Expense,
            side: Side::Debit,
            functional_amount: Amount::new(eur, 20_000),
            is_current_period_activity: true,
        },
    ];

    let stmt_p2 = translate_current_rate(
        &mut budget,
        "2026-02",
        feb_28,
        eur,
        usd,
        &p2_lines,
        &doc_close_feb,
        &doc_avg_feb,
        &hist_docs,
        20_000,
        stmt_p1.ending_retained_earnings_reporting,
        stmt_p1.cta_schedule.ending_cumulative_cta_credit,
        &h.book.units,
    )
    .unwrap();

    // Check P2 math:
    // Assets: 190_000 * 1.15 = 218_500
    // Liabilities: 30_000 * 1.15 = 34_500
    // Net Assets: 184_000
    // Equity: 108_000
    // P2 NI at avg (1.13): (60_000 - 20_000) * 1.13 = 45_200
    // Ending RE: 21_900 + 45_200 = 67_100
    // Ending cumulative CTA: 184_000 - (108_000 + 67_100) = 8_900
    // Delta CTA: 8_900 - 4_500 = 4_400
    // Decomposition:
    // - Opening net assets (EUR 1,200.00 = 120_000) retranslated from 1.12 to 1.15: 120_000 * 0.03 = 3_600
    // - P2 NI (EUR 400.00 = 40_000) spread between close (1.15) and avg (1.13): 40_000 * 0.02 = 800
    // - Total delta CTA = 3_600 + 800 = 4_400!
    assert_eq!(stmt_p2.ending_retained_earnings_reporting, 67_100);
    assert_eq!(stmt_p2.cta_schedule.ending_cumulative_cta_credit, 8_900);
    assert_eq!(stmt_p2.cta_schedule.delta_cta_credit, 4_400);
    assert_eq!(stmt_p2.cta_schedule.opening_net_assets_retranslation, 3_600);
    assert_eq!(stmt_p2.cta_schedule.period_net_income_spread, 800);
    assert_eq!(stmt_p2.cta_schedule.equity_and_dividend_spread, 0);

    verify_translation_certificate(
        &mut budget,
        &stmt_p2,
        &p2_lines,
        &doc_close_feb,
        &doc_avg_feb,
        &hist_docs,
        20_000,
        &h.book.units,
    )
    .unwrap();

    // Missing historical rate document refuses with EVIDENCE_UNKNOWN:
    let err = translate_current_rate(
        &mut budget,
        "2026-02",
        feb_28,
        eur,
        usd,
        &p2_lines,
        &doc_close_feb,
        &doc_avg_feb,
        &[],
        20_000,
        stmt_p1.ending_retained_earnings_reporting,
        stmt_p1.cta_schedule.ending_cumulative_cta_credit,
        &h.book.units,
    )
    .expect_err("missing historical SpotClose rate must refuse");
    assert_eq!(err.code, code::EVIDENCE_UNKNOWN);

    // Post CTA recycling on deconsolidation in h.march:
    {
        let doc = doc_close_mar
            .document(h.book.book_id, PRINCIPAL, 3)
            .unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }
    let mut recycle_tpl = h.proposal(Vec::new(), b"fx-cta-recycle", EntryClass::REVALUATION);
    recycle_tpl.effective_date = mar_31;
    let recycle_entry = plan_cta_deconsolidation_recycling(
        recycle_tpl,
        &stmt_p2,
        acct_equity,
        acct_rev,
        &doc_close_mar,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(recycle_entry.legs.len(), 2);
    assert_eq!(recycle_entry.legs[0].side, Side::Debit);
    assert_eq!(recycle_entry.legs[0].amount, Amount::new(usd, 8_900));
    assert_eq!(recycle_entry.legs[1].side, Side::Credit);
    assert_eq!(recycle_entry.legs[1].amount, Amount::new(usd, 8_900));
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: recycle_entry,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }
}

#[test]
fn fx_temporal_remeasurement_two_period_monetary_vs_non_monetary_matches_oracle() {
    use fa_journal::{FxRateDocument, FxRatePurpose, add_document};
    use fa_model::AccountType;
    use fa_money::RoundingLaw;
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};
    use fa_reference::Side as RefSide;
    use fa_reference::fx::{
        OracleRateQuote, OracleRemeasurementBasis, OracleRemeasurementLine,
        remeasure_temporal_oracle,
    };
    use fa_registers::{
        RemeasurementBasis, RemeasurementInputLine, plan_remeasurement_entry, remeasure_temporal,
        verify_remeasurement_certificate,
    };

    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();

    let jan_01 = DateDay::from_ymd(2026, 1, 1).unwrap();
    let mar_31 = DateDay::from_ymd(2026, 3, 31).unwrap();

    let doc_spot_jan01 = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 105,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        jan_01,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "ECB",
    )
    .unwrap();
    let doc_avg_mar = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 110,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        mar_31,
        1_700_000_000_000_000_000,
        FxRatePurpose::PeriodAverage,
        "ECB",
    )
    .unwrap();
    let doc_close_mar = FxRateDocument::new(
        FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: 115,
            rate_den: 100,
            rounding: RoundingLaw::HalfEven,
        },
        mar_31,
        1_700_000_000_000_000_000,
        FxRatePurpose::PeriodClose,
        "ECB",
    )
    .unwrap();

    for d in [&doc_spot_jan01, &doc_avg_mar, &doc_close_mar] {
        let doc = d.document(h.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &doc).await })
            .unwrap()
            .unwrap();
    }

    let stripped = asupersync::Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    // EUR currency-of-record subsidiary with USD functional currency:
    // - Cash (Monetary Asset): Dr EUR 900.00 (90_000) -> Closing 1.15 = 103_500
    // - Inventory (Non-Monetary Asset, acquired 2026-01-01): Dr EUR 400.00 (40_000) -> Historical 1.05 = 42_000
    // - AP (Monetary Liability): Cr EUR 200.00 (20_000) -> Closing 1.15 = 23_000
    // - Share Capital (Equity, issued 2026-01-01): Cr EUR 1,000.00 (100_000) -> Historical 1.05 = 105_000
    // - Revenue (Flow): Cr EUR 500.00 (50_000) -> Average 1.10 = 55_000
    // - COGS (Historical Cost Allocation from 2026-01-01 inventory): Dr EUR 300.00 (30_000) -> Historical 1.05 = 31_500
    // - Operating Expense (Flow): Dr EUR 100.00 (10_000) -> Average 1.10 = 11_000
    // Record Dr = 170_000, Record Cr = 170_000.
    // BS Dr - Cr in USD = (103_500 + 42_000) - (23_000 + 105_000) = 17_500.
    // Pre-FX P&L in USD = 55_000 - 31_500 - 11_000 = 12_500.
    // Remeasurement gain in P&L = 17_500 - 12_500 = +5_000 ($50.00)!
    // Remeasured Net Income = 12_500 + 5_000 = 17_500!
    let acct_inv = VId(991_000);
    let acct_ap = VId(991_003);
    let acct_eq = VId(991_001);
    let acct_rev = h.rent;
    let acct_cogs = VId(991_004);
    let acct_opex = VId(991_002);
    let lines = vec![
        RemeasurementInputLine {
            account: h.cash,
            account_type: AccountType::ASSET,
            basis: RemeasurementBasis::MonetaryClosing,
            side: Side::Debit,
            record_amount: Amount::new(eur, 90_000),
        },
        RemeasurementInputLine {
            account: acct_inv,
            account_type: AccountType::ASSET,
            basis: RemeasurementBasis::NonMonetaryHistorical {
                acquisition_date: jan_01,
            },
            side: Side::Debit,
            record_amount: Amount::new(eur, 40_000),
        },
        RemeasurementInputLine {
            account: acct_ap,
            account_type: AccountType::LIABILITY,
            basis: RemeasurementBasis::MonetaryClosing,
            side: Side::Credit,
            record_amount: Amount::new(eur, 20_000),
        },
        RemeasurementInputLine {
            account: acct_eq,
            account_type: AccountType::EQUITY,
            basis: RemeasurementBasis::NonMonetaryHistorical {
                acquisition_date: jan_01,
            },
            side: Side::Credit,
            record_amount: Amount::new(eur, 100_000),
        },
        RemeasurementInputLine {
            account: acct_rev,
            account_type: AccountType::REVENUE,
            basis: RemeasurementBasis::FlowAverage,
            side: Side::Credit,
            record_amount: Amount::new(eur, 50_000),
        },
        RemeasurementInputLine {
            account: acct_cogs,
            account_type: AccountType::EXPENSE,
            basis: RemeasurementBasis::HistoricalCostAllocation {
                acquisition_date: jan_01,
            },
            side: Side::Debit,
            record_amount: Amount::new(eur, 30_000),
        },
        RemeasurementInputLine {
            account: acct_opex,
            account_type: AccountType::EXPENSE,
            basis: RemeasurementBasis::FlowAverage,
            side: Side::Debit,
            record_amount: Amount::new(eur, 10_000),
        },
    ];
    let hist_docs = vec![doc_spot_jan01.clone()];

    let run = remeasure_temporal(
        &mut budget,
        &h.march,
        mar_31,
        eur,
        usd,
        &lines,
        &doc_close_mar,
        &doc_avg_mar,
        &hist_docs,
        0,
        0,
        0,
        &h.book.units,
    )
    .unwrap();

    assert_eq!(run.pre_fx_net_income_functional, 12_500);
    assert_eq!(run.delta_remeasurement_gain_credit, 5_000);
    assert_eq!(run.cumulative_remeasurement_gain_credit, 5_000);
    assert_eq!(run.remeasured_net_income_functional, 17_500);
    assert_eq!(run.ending_retained_earnings_functional, 17_500);

    verify_remeasurement_certificate(
        &mut budget,
        &run,
        &lines,
        &doc_close_mar,
        &doc_avg_mar,
        &hist_docs,
        0,
        &h.book.units,
    )
    .unwrap();

    // Compare against independent limb-arithmetic oracle:
    let mut oracle_hist = std::collections::BTreeMap::new();
    oracle_hist.insert(
        jan_01.0,
        OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 105,
            rate_den: 100,
            rounding_law: "HalfEven".into(),
        },
    );
    let oracle_out = remeasure_temporal_oracle(
        &[
            OracleRemeasurementLine {
                account: h.cash.0,
                is_income_statement: false,
                basis: OracleRemeasurementBasis::MonetaryClosing,
                side: RefSide::Debit,
                record_mantissa: 90_000,
            },
            OracleRemeasurementLine {
                account: acct_inv.0,
                is_income_statement: false,
                basis: OracleRemeasurementBasis::NonMonetaryHistorical {
                    acquisition_date: jan_01.0,
                },
                side: RefSide::Debit,
                record_mantissa: 40_000,
            },
            OracleRemeasurementLine {
                account: acct_ap.0,
                is_income_statement: false,
                basis: OracleRemeasurementBasis::MonetaryClosing,
                side: RefSide::Credit,
                record_mantissa: 20_000,
            },
            OracleRemeasurementLine {
                account: acct_eq.0,
                is_income_statement: false,
                basis: OracleRemeasurementBasis::NonMonetaryHistorical {
                    acquisition_date: jan_01.0,
                },
                side: RefSide::Credit,
                record_mantissa: 100_000,
            },
            OracleRemeasurementLine {
                account: acct_rev.0,
                is_income_statement: true,
                basis: OracleRemeasurementBasis::FlowAverage,
                side: RefSide::Credit,
                record_mantissa: 50_000,
            },
            OracleRemeasurementLine {
                account: acct_cogs.0,
                is_income_statement: true,
                basis: OracleRemeasurementBasis::HistoricalCostAllocation {
                    acquisition_date: jan_01.0,
                },
                side: RefSide::Debit,
                record_mantissa: 30_000,
            },
            OracleRemeasurementLine {
                account: acct_opex.0,
                is_income_statement: true,
                basis: OracleRemeasurementBasis::FlowAverage,
                side: RefSide::Debit,
                record_mantissa: 10_000,
            },
        ],
        2,
        2,
        &OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 115,
            rate_den: 100,
            rounding_law: "HalfEven".into(),
        },
        &OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: 2,
            rate_num: 110,
            rate_den: 100,
            rounding_law: "HalfEven".into(),
        },
        &oracle_hist,
        0,
        0,
        0,
    )
    .unwrap();
    assert_eq!(
        run.delta_remeasurement_gain_credit,
        oracle_out.delta_remeasurement_gain_credit
    );
    assert_eq!(
        run.remeasured_net_income_functional,
        oracle_out.remeasured_net_income_functional
    );
    assert_eq!(
        run.ending_retained_earnings_functional,
        oracle_out.ending_retained_earnings_functional
    );

    // Plan and post the delta-cumulative remeasurement entry into the book:
    let mut remeas_tpl = h.proposal(Vec::new(), b"fx-remeas-p1", EntryClass::REVALUATION);
    remeas_tpl.effective_date = mar_31;
    let remeas_entry = plan_remeasurement_entry(
        remeas_tpl,
        &run,
        h.cash,
        h.rent,
        &doc_close_mar,
        &doc_avg_mar,
        &hist_docs,
        Vec::new(),
    )
    .unwrap();
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        let req = PostRequest {
            proposal: remeas_entry,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        h.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .unwrap()
            .unwrap();
    }
}
