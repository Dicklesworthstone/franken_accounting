//! Cumulative functional stock from real native postings, holds and migrations.
//! Literal amounts are independent of the fold; no register cells are inputs.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{Document, add_document};
use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms, value_proposal};
use fa_journal::migration::{
    RunBody, RunControlRequest, RunMode, RunState, TrialBalanceLine, kind, open_proposal, open_run,
    plan_run_transition, transition_run,
};
use fa_journal::{
    AccountSpec, ApprovalRequest, BookContext, BookSpec, Capability, PostRequest, Posted,
    UnitPolicy, create_book, create_periods, install_chart, post, record_approval,
    transition_period,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ApprovalRef, ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload,
    Erasable, EvidenceRef, Id128, LegPayload, Pending, PeriodRef, SealKey, SymbolTable,
    account_vid,
};
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_registers::{
    FunctionalStockCell, FunctionalStockCellKey, FunctionalStockFold, RegisterError, balance_as_of,
    fold_functional_stock, fold_period_functional, verify_functional_stock,
};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const PRINCIPAL: VId = VId(7);

fn day(year: i32, month: u8, date: u8) -> DateDay {
    DateDay::from_ymd(year, month, date).unwrap()
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Fixture {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    eur: UnitId,
    evidence: EvidenceRef,
}

impl Fixture {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [0x31; 32],
            DatabaseSecurityNamespaceId([0x32; 32]),
            [0x33; 32],
        );
        let mut db = runtime
            .block_on(Database::open_memory(&ctx.commit(), keys))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let calendar = FiscalCalendar::monthly("fx-stock", 1, 1).unwrap();
        let spec = BookSpec {
            book_id: Id128([0x34; 16]),
            name: "Functional stock".into(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            // The 2025 Opening period is genuinely born Locked for the
            // migration test, while the selected later normal periods open.
            opening_date: Some(day(2025, 1, 2)),
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(create_book(&mut db, &ctx, &spec, &units, &symbols))
            .unwrap();
        let book = BookContext {
            book_id: spec.book_id,
            calendar,
            units,
            seal_key: SealKey([0x35; 32]),
            symbols,
        };
        let accounts: Vec<_> = [("1200", AccountType::ASSET), ("4000", AccountType::REVENUE)]
            .into_iter()
            .map(|(code, kind)| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: kind.0,
                normal_balance: u8::from(kind == AccountType::REVENUE),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect();
        let text = |value: &str| {
            Erasable::seal(&value.to_string(), None, &book.seal_key, [1; 32], [2; 24])
        };
        runtime
            .block_on(install_chart(
                &mut db,
                &ctx,
                &book,
                &accounts,
                PRINCIPAL,
                day(2025, 1, 1),
                b"fx-stock-chart",
                text("chart"),
                &cap(&["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        for year in [2025, 2026] {
            runtime
                .block_on(create_periods(
                    &mut db,
                    &ctx,
                    &book,
                    year,
                    PRINCIPAL,
                    text("periods"),
                    &cap(&["schema_change"]),
                ))
                .unwrap()
                .unwrap();
        }
        for code in ["FY2025-P12", "FY2026-P01", "FY2026-P03", "FY2026-P04"] {
            runtime
                .block_on(transition_period(
                    &mut db,
                    &ctx,
                    &book,
                    code,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    format!("open-{code}").as_bytes(),
                    text("open"),
                    &cap(&["close"]),
                    &[],
                ))
                .unwrap()
                .unwrap();
        }
        let document = Document {
            book_id: book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Retained stock fixture invoice".to_vec(),
        };
        runtime
            .block_on(add_document(&mut db, &ctx, &book, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            db,
            book,
            usd,
            eur,
            evidence: document.evidence_ref(1),
        }
    }

    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn sealed(&self, text: &str) -> Erasable<String> {
        Erasable::seal(
            &text.to_string(),
            None,
            &self.book.seal_key,
            [3; 32],
            [4; 24],
        )
    }

    fn legs(&self, unit: UnitId, amount: i128) -> Vec<LegPayload> {
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(self.book.book_id, "1200"),
                Amount::new(unit, amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(self.book.book_id, "4000"),
                Amount::new(unit, amount),
            ),
        ]
    }

    fn proposal(&self, key: &str, date: DateDay, unit: UnitId, amount: i128) -> EntryPayload {
        let legs = self.legs(unit, amount);
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: date,
            document_date: None,
            description: self.sealed("stock posting"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: self.evidence.document_oid,
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn post(&mut self, proposal: EntryPayload) -> Posted {
        let ctx = self.ctx();
        self.runtime
            .block_on(post(
                &mut self.db,
                &ctx,
                &self.book,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(&["post", "migrate"]),
                },
            ))
            .unwrap()
            .unwrap()
    }

    fn approvals(&mut self, digest: [u8; 32]) -> Vec<ApprovalRef> {
        let ctx = self.ctx();
        [VId(8), VId(9)]
            .into_iter()
            .map(|who| {
                self.runtime
                    .block_on(record_approval(
                        &mut self.db,
                        &ctx,
                        &self.book,
                        ApprovalRequest {
                            capability: Capability::embedded(who, &["approve"]).unwrap(),
                            approved_proposal_digest: digest,
                            role: 0,
                        },
                    ))
                    .unwrap()
                    .unwrap()
                    .approval()
            })
            .collect()
    }

    fn rate(&mut self, date: DateDay, numerator: u128, source: &str) -> FxRateDocument {
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: numerator,
                rate_den: 10,
                rounding: RoundingLaw::HalfEven,
            },
            date,
            1_700_000_000_000_000_000,
            FxRatePurpose::SpotClose,
            source,
        )
        .unwrap();
        let document = rate.document(self.book.book_id, PRINCIPAL, 3).unwrap();
        let ctx = self.ctx();
        self.runtime
            .block_on(add_document(&mut self.db, &ctx, &self.book, &document))
            .unwrap()
            .unwrap();
        rate
    }

    fn valued(&self, proposal: EntryPayload, rate: &FxRateDocument) -> EntryPayload {
        let arithmetic = self.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        let spec = fa_journal::genesis::read_book_spec(&self.db)
            .unwrap()
            .unwrap();
        value_proposal(
            &mut budget,
            proposal,
            &spec,
            &self.book.units,
            FxLawId::SpotClose,
            std::slice::from_ref(rate),
        )
        .unwrap()
    }

    fn stock(&self, through: DateDay, known_at: Option<CommitSeq>) -> FunctionalStockFold {
        let before = self.db.frontier().unwrap();
        let fold = fold_functional_stock(&self.db, &self.book, through, known_at).unwrap();
        verify_functional_stock(&self.db, &self.book, &fold).unwrap();
        assert_eq!(
            self.db.frontier().unwrap(),
            before,
            "stock reads never publish"
        );
        fold
    }

    fn cell<'a>(&self, fold: &'a FunctionalStockFold, code: &str) -> &'a FunctionalStockCell {
        fold.cell(&FunctionalStockCellKey {
            account: account_vid(self.book.book_id, code),
            unit_id: self.usd.0,
            entity: None,
        })
        .unwrap()
    }
}

#[test]
fn stock_carries_earlier_periods_and_years_at_committed_values_without_new_rate_conversion() {
    let mut f = Fixture::new();
    let december = day(2025, 12, 5);
    let january = day(2026, 1, 5);
    let rate = f.rate(december, 11, "Retained December rate");
    let proposal = f.valued(f.proposal("december", december, f.eur, 10_000), &rate);
    f.post(proposal);
    let original_prefix = f.db.frontier().unwrap();
    let original = f.stock(day(2026, 4, 30), Some(original_prefix));
    assert_eq!(
        (
            original.total_debits().unwrap(),
            original.total_credits().unwrap()
        ),
        (11_000, 11_000)
    );
    let rate = f.rate(january, 12, "Retained January rate");
    let proposal = f.valued(f.proposal("january", january, f.eur, 5_000), &rate);
    f.post(proposal);

    let current = f.stock(day(2026, 4, 30), None);
    assert_eq!(current.entries, 2);
    assert_eq!(
        (
            current.total_debits().unwrap(),
            current.total_credits().unwrap()
        ),
        (17_000, 17_000)
    );
    let asset = f.cell(&current, "1200");
    assert_eq!(
        (asset.debits, asset.credits, asset.entry_count, asset.net()),
        (17_000, 0, 2, Some(17_000))
    );
    assert_eq!(
        f.stock(day(2025, 12, 31), None).total_debits().unwrap(),
        11_000
    );
    assert_eq!(
        f.stock(day(2026, 1, 4), None).total_debits().unwrap(),
        11_000
    );
    assert_eq!(
        f.stock(day(2026, 1, 5), None).total_debits().unwrap(),
        17_000
    );
    let april = fold_period_functional(&f.db, &f.book, "FY2026-P04", None).unwrap();
    assert!(april.cells.is_empty());
    let native = balance_as_of(&f.db, &f.book, day(2026, 4, 30), None).unwrap();
    assert_eq!(native.unit_totals.get(&f.eur.0), Some(&(15_000, 15_000)));

    f.rate(january, 90, "Later quote never rewrites the carrying value");
    let later = f.stock(day(2026, 4, 30), None);
    assert_eq!(later.cells, current.cells);
    assert_eq!(later.fold_digest, current.fold_digest);
    assert_eq!(later.watermark, current.watermark);
    assert_eq!(f.stock(day(2026, 4, 30), Some(original_prefix)), original);
    let before = f.stock(day(2025, 12, 4), None);
    assert!(before.cells.is_empty() && before.pending.is_empty());
    assert_eq!((before.entries, before.watermark), (0, None));
}

#[test]
fn holds_release_at_known_at_while_posted_subvectors_obey_the_effective_cutoff() {
    let mut f = Fixture::new();
    let march = day(2026, 3, 5);
    let rate = f.rate(march, 11, "Pending foreign rate");
    let mut foreign = f.proposal("foreign-hold", march, f.eur, 10_000);
    foreign.class = EntryClass::PENDING;
    foreign.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let foreign = f.post(f.valued(foreign, &rate));
    let mut base = f.proposal("base-hold", day(2026, 3, 10), f.usd, 10_000);
    base.class = EntryClass::PENDING;
    base.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let base = f.post(base);
    let held_at = f.db.frontier().unwrap();
    let held = f.stock(day(2026, 3, 31), Some(held_at));
    assert_eq!(held.entries, 0);
    assert!(held.cells.is_empty());
    assert_eq!(
        held.pending.iter().map(|cell| cell.debits).sum::<i128>(),
        21_000
    );

    let mut future = f.proposal("future-hold", day(2026, 4, 20), f.usd, 3_000);
    future.class = EntryClass::PENDING;
    future.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    f.post(future);
    assert_eq!(
        f.stock(day(2026, 3, 31), None).fold_digest,
        held.fold_digest
    );

    let mut partial = f.proposal("april-partial", day(2026, 4, 10), f.usd, 6_000);
    partial.class = EntryClass::RESOLUTION;
    partial.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(base.entry_ref()),
        disposition: Some(Disposition::Posts {
            source_ordinals: vec![0, 1],
        }),
    });
    let partial = f.post(partial);
    let march_after = f.stock(day(2026, 3, 31), None);
    assert_eq!(march_after.entries, 0);
    assert!(march_after.cells.is_empty());
    assert_eq!(
        march_after
            .pending
            .iter()
            .map(|cell| cell.debits)
            .sum::<i128>(),
        11_000
    );
    assert_eq!(march_after.watermark, Some(partial.recorded_at()));
    assert_eq!(f.stock(day(2026, 3, 31), Some(held_at)), held);

    let mut void = f.proposal("april-void", day(2026, 4, 11), f.usd, 1);
    void.class = EntryClass::RESOLUTION;
    void.legs.clear();
    void.unit_totals.clear();
    void.control = Some(ControlPayload::ReservationRelease);
    void.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(foreign.entry_ref()),
        disposition: Some(Disposition::Voids),
    });
    let void = f.post(void);
    let released = f.stock(day(2026, 3, 31), None);
    assert!(released.cells.is_empty() && released.pending.is_empty());
    assert_eq!(released.watermark, Some(void.recorded_at()));
    let april = f.stock(day(2026, 4, 15), None);
    assert_eq!((april.entries, april.total_debits().unwrap()), (1, 6_000));
    assert!(april.pending.is_empty());
    let april_end = f.stock(day(2026, 4, 30), None);
    assert_eq!(
        april_end
            .pending
            .iter()
            .map(|cell| cell.debits)
            .sum::<i128>(),
        3_000
    );
    let native = balance_as_of(&f.db, &f.book, day(2026, 4, 30), None).unwrap();
    assert_eq!(native.unit_totals.get(&f.usd.0), Some(&(6_000, 6_000)));
    assert_eq!(
        native.pending_unit_totals.get(&f.usd.0),
        Some(&(3_000, 3_000))
    );
}

#[test]
fn unvalued_foreign_legs_refuse_only_when_selected_and_stock_sums_are_checked() {
    let mut f = Fixture::new();
    f.post(f.proposal("base", day(2026, 1, 5), f.usd, 100));
    let original = f.stock(day(2026, 4, 30), None);
    f.post(f.proposal("unvalued", day(2026, 3, 5), f.eur, 100));
    let head = f.db.frontier().unwrap();
    assert_eq!(f.stock(day(2026, 1, 31), None).total_debits().unwrap(), 100);
    assert_eq!(f.stock(day(2026, 4, 30), Some(original.known_at)), original);
    assert!(matches!(
        fold_functional_stock(&f.db, &f.book, day(2026, 3, 5), None),
        Err(RegisterError::ProjectionDrift(_))
    ));
    assert_eq!(f.db.frontier().unwrap(), head);

    let mut large = Fixture::new();
    let amount = i128::MAX / 2 + 1;
    large.post(large.proposal("large-a", day(2025, 12, 5), large.usd, amount));
    let head = large.db.frontier().unwrap();
    let proposal = large.proposal("large-b", day(2026, 1, 5), large.usd, amount);
    let ctx = large.ctx();
    let refusal = large
        .runtime
        .block_on(post(
            &mut large.db,
            &ctx,
            &large.book,
            PostRequest {
                proposal,
                approvals: vec![],
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3), "{refusal}");
    assert_eq!(large.db.frontier().unwrap(), head);
    assert_eq!(
        large.stock(day(2025, 12, 31), None).total_debits().unwrap(),
        amount
    );
    assert_eq!(
        fold_functional_stock(&large.db, &large.book, day(2026, 1, 31), None)
            .unwrap()
            .total_debits()
            .unwrap(),
        amount
    );
    assert!(
        verify_functional_stock(&large.db, &large.book, &large.stock(day(2026, 1, 31), None))
            .is_ok()
    );
    assert_eq!(large.db.frontier().unwrap(), head);
}

#[test]
fn equal_amounts_with_different_rate_provenance_have_different_source_digests() {
    fn one(source: &str) -> FunctionalStockFold {
        let mut f = Fixture::new();
        let date = day(2026, 1, 5);
        let rate = f.rate(date, 11, source);
        f.post(f.valued(f.proposal("same-identity", date, f.eur, 10_000), &rate));
        f.stock(day(2026, 1, 31), None)
    }
    let a = one("Independently retained source A");
    let b = one("Independently retained source B");
    assert_eq!(a.cells, b.cells);
    assert_eq!(a.entries, b.entries);
    assert_eq!(a.watermark, b.watermark);
    assert_ne!(a.fold_digest, b.fold_digest);
}

#[test]
fn historical_book_spec_and_claim_verification_preserve_the_selected_coordinate() {
    let mut f = Fixture::new();
    f.post(f.proposal("before-damage", day(2026, 1, 5), f.usd, 12_345));
    let original = f.stock(day(2026, 1, 31), None);
    let mut wrong = original.clone();
    wrong.cells[0].debits += 1;
    assert!(matches!(
        verify_functional_stock(&f.db, &f.book, &wrong),
        Err(RegisterError::ProjectionDrift(_))
    ));
    let mut wrong_cutoff = original.clone();
    wrong_cutoff.effective_through = day(2026, 1, 4);
    assert!(matches!(
        verify_functional_stock(&f.db, &f.book, &wrong_cutoff),
        Err(RegisterError::ProjectionDrift(_))
    ));
    assert!(matches!(
        fold_functional_stock(
            &f.db,
            &f.book,
            day(2026, 1, 31),
            Some(CommitSeq(original.known_at.0 + 1))
        ),
        Err(RegisterError::InvalidSelection(_))
    ));

    let mut damaged = fa_journal::genesis::read_book_spec(&f.db).unwrap().unwrap();
    damaged.base_unit = f.eur;
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    batch.set_vertex_property(
        fa_journal::rows::book_root(),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(damaged.canonical_bytes().unwrap()).unwrap()),
    );
    let ctx = f.ctx();
    f.runtime
        .block_on(f.db.write(&ctx.commit(), batch))
        .unwrap();
    assert!(matches!(
        fold_functional_stock(&f.db, &f.book, day(2026, 1, 31), None),
        Err(RegisterError::ProjectionDrift(_))
    ));
    assert_eq!(f.stock(day(2026, 1, 31), Some(original.known_at)), original);
}

#[test]
fn migration_stock_appears_only_at_finalization_and_uses_its_activation_watermark() {
    for damage_kind in 0..4 {
        let mut f = Fixture::new();
        let document = Document {
            book_id: f.book.book_id,
            kind: 18,
            mime: "text/csv".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"account,unit,net\n1200,USD,500.00\n4000,USD,-500.00\n".to_vec(),
        };
        let ctx = f.ctx();
        f.runtime
            .block_on(add_document(&mut f.db, &ctx, &f.book, &document))
            .unwrap()
            .unwrap();
        let evidence = document.evidence_ref(1);
        let body = RunBody {
            book_id: f.book.book_id,
            run_key: "stock-opening".into(),
            source_system: "legacy".into(),
            mode: RunMode::OpeningOnly,
            trial_balance: evidence.document_oid,
            opening_date: day(2025, 1, 1),
            lines: vec![
                TrialBalanceLine {
                    account_code: "1200".into(),
                    unit: f.usd,
                    mantissa: 50_000,
                },
                TrialBalanceLine {
                    account_code: "4000".into(),
                    unit: f.usd,
                    mantissa: -50_000,
                },
            ],
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
        };
        let proposal = open_proposal(
            &f.book,
            PRINCIPAL,
            &body,
            vec![evidence],
            b"open-stock-run",
            f.sealed("open migration"),
        )
        .unwrap();
        let opened = f
            .runtime
            .block_on(open_run(
                &mut f.db,
                &ctx,
                &f.book,
                &body,
                RunControlRequest {
                    proposal,
                    capability: cap(&["post", "migrate"]),
                    approvals: Vec::new(),
                },
            ))
            .unwrap()
            .unwrap();
        let mut chunk = f.proposal("opening-chunk", day(2025, 1, 1), f.usd, 50_000);
        chunk.class = EntryClass::MIGRATION;
        chunk.effective_period = Some(PeriodRef {
            calendar: f.book.calendar.id.clone(),
            code: "FY2025-OPEN".into(),
        });
        chunk.evidence = vec![evidence];
        chunk.origin = EntryOrigin::Migration {
            run_ref: opened.run,
            source_system: "legacy".into(),
            source_id: f.sealed("legacy-entry-1"),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: evidence.document_oid,
        };
        let approvals = f.approvals(chunk.proposal_digest().unwrap());
        let chunk = f
            .runtime
            .block_on(post(
                &mut f.db,
                &ctx,
                &f.book,
                PostRequest {
                    proposal: chunk,
                    approvals,
                    plan_certificate: None,
                    capability: cap(&["post", "migrate"]),
                },
            ))
            .unwrap()
            .unwrap();
        let staged_at = f.db.frontier().unwrap();
        let staged = f.stock(day(2026, 1, 31), None);
        assert!(staged.cells.is_empty() && staged.pending.is_empty());
        assert_eq!((staged.entries, staged.watermark), (0, None));

        let proposal = plan_run_transition(
            &f.db,
            &f.book,
            opened.run,
            kind::FINALIZE,
            PRINCIPAL,
            b"finalize-stock-run",
            f.sealed("finalize migration"),
        )
        .unwrap()
        .unwrap();
        let approvals = f.approvals(proposal.proposal_digest().unwrap());
        let before_finalize = f.db.frontier().unwrap();
        let finalized = f
            .runtime
            .block_on(transition_run(
                &mut f.db,
                &ctx,
                &f.book,
                RunControlRequest {
                    proposal,
                    capability: cap(&["post", "migrate"]),
                    approvals,
                },
            ))
            .unwrap()
            .unwrap();
        assert!(finalized.recorded_at > chunk.recorded_at());
        let visible = f.stock(day(2026, 1, 31), None);
        assert_eq!(
            (
                visible.entries,
                visible.total_debits().unwrap(),
                visible.total_credits().unwrap()
            ),
            (1, 50_000, 50_000)
        );
        assert_eq!(visible.watermark, Some(finalized.recorded_at));
        assert_eq!(f.stock(day(2026, 1, 31), Some(staged_at)), staged);
        assert!(
            f.stock(day(2026, 1, 31), Some(before_finalize))
                .cells
                .is_empty()
        );
        assert!(f.stock(day(2024, 12, 31), None).cells.is_empty());
        let native = balance_as_of(&f.db, &f.book, day(2026, 1, 31), None).unwrap();
        assert_eq!(native.unit_totals.get(&f.usd.0), Some(&(50_000, 50_000)));

        let valid_at = f.db.frontier().unwrap();
        let mut damage = WriteBatch::new(relation::IN_MIGRATION_RUN);
        match damage_kind {
            0 => {
                damage.set_vertex_property(
                    body.vid(),
                    property::STATE,
                    Some(RunState::Open.scalar()),
                );
            }
            1 => {
                // Self-consistent payload/checksum corruption would make the
                // ordinary FullDetail visibility predicate hide this opening.
                let mut hidden = body.clone();
                hidden.mode = RunMode::FullDetail;
                hidden.opening_date = day(2027, 1, 1);
                damage.set_vertex_property(
                    body.vid(),
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(hidden.canonical_bytes().unwrap()).unwrap()),
                );
                damage.set_vertex_property(
                    body.vid(),
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(hidden.digest().unwrap().to_vec()).unwrap()),
                );
            }
            2 => {
                damage.set_vertex_label(body.vid(), label::MIGRATION_RUN, false);
                damage.set_vertex_label(body.vid(), label::DOCUMENT, true);
            }
            3 => {
                damage.delete_vertex(body.vid());
            }
            _ => unreachable!(),
        }
        f.runtime
            .block_on(f.db.write(&ctx.commit(), damage))
            .unwrap();
        let damaged_at = f.db.frontier().unwrap();
        assert!(
            matches!(
                fold_functional_stock(&f.db, &f.book, day(2026, 1, 31), None),
                Err(RegisterError::Kernel(fa_journal::KernelError::Corrupt(_)))
            ),
            "migration damage {damage_kind} cannot remove its carrying amount"
        );
        assert_eq!(f.stock(day(2026, 1, 31), Some(valid_at)), visible);
        assert_eq!(f.db.frontier().unwrap(), damaged_at);
        if damage_kind < 3 {
            let mut restore = WriteBatch::new(relation::IN_MIGRATION_RUN);
            match damage_kind {
                0 => {
                    restore.set_vertex_property(
                        body.vid(),
                        property::STATE,
                        Some(RunState::Finalized.scalar()),
                    );
                }
                1 => {
                    restore.set_vertex_property(
                        body.vid(),
                        property::FA_PAYLOAD,
                        Some(CanonicalScalar::bytes(body.canonical_bytes().unwrap()).unwrap()),
                    );
                    restore.set_vertex_property(
                        body.vid(),
                        property::FA_DIGEST,
                        Some(CanonicalScalar::bytes(body.digest().unwrap().to_vec()).unwrap()),
                    );
                }
                2 => {
                    restore.set_vertex_label(body.vid(), label::DOCUMENT, false);
                    restore.set_vertex_label(body.vid(), label::MIGRATION_RUN, true);
                }
                _ => unreachable!(),
            }
            f.runtime
                .block_on(f.db.write(&ctx.commit(), restore))
                .unwrap();
            let restored_at = f.db.frontier().unwrap();
            assert!(
                matches!(
                    fold_functional_stock(&f.db, &f.book, day(2026, 1, 31), None),
                    Err(RegisterError::Kernel(fa_journal::KernelError::Corrupt(_)))
                ),
                "exact restoration cannot erase migration mutation {damage_kind}"
            );
            assert_eq!(f.stock(day(2026, 1, 31), Some(valid_at)), visible);
            assert_eq!(f.db.frontier().unwrap(), restored_at);
        }
    }
}
