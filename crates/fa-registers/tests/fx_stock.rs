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
        Self::with_entity(false)
    }

    fn with_entity(declared: bool) -> Self {
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
            entities: if declared {
                vec![fa_journal::genesis::LegalEntitySpec {
                    code: "Estate".into(),
                    name: "Estate".into(),
                    functional_unit: usd,
                }]
            } else {
                Vec::new()
            },
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

    /// Fault-inject a canonical retained payload through the substrate. This
    /// does not bypass the production writer through a public accounting API,
    /// fabricate a recorded timestamp, or claim genuine old-producer proof.
    fn append_retained_fault(&mut self, proposal: EntryPayload) -> (fa_model::EntryRef, CommitSeq) {
        let vid = fa_model::entry_vid(
            proposal.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        );
        let entry = proposal.seal(Vec::new(), None).unwrap();
        let mut batch = WriteBatch::new(relation::HAS_LEG);
        batch.create_vertex(
            vid,
            vec![label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        let ctx = self.ctx();
        self.runtime
            .block_on(self.db.write(&ctx.commit(), batch))
            .unwrap();
        let source = fa_journal::post::read_entry(&self.db, vid)
            .unwrap()
            .unwrap();
        assert_eq!(source.0, entry);
        (entry.entry_ref(vid), source.1)
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
    assert_eq!(
        large.stock(day(2026, 1, 31), None).total_credits().unwrap(),
        amount
    );
    assert_eq!(large.db.frontier().unwrap(), head);
}

#[test]
fn native_entity_capacity_diagnosis_preserves_exact_scope_source_and_history() {
    for declared in [false, true] {
        for pending in [false, true] {
            let mut f = Fixture::with_entity(declared);
            let date = day(2026, 1, 5);
            let through = day(2026, 1, 31);
            let periods = vec!["FY2026-P01".to_string()];
            let as_pending = |mut proposal: EntryPayload| {
                if pending {
                    proposal.class = EntryClass::PENDING;
                    proposal.pending = Some(Pending {
                        timeout_ns: None,
                        resolution_of: None,
                        disposition: None,
                    });
                }
                proposal
            };
            f.post(as_pending(f.proposal(
                "entity-maximum",
                date,
                f.usd,
                i128::MAX,
            )));
            let safe = f.db.frontier().unwrap();
            let original = fa_registers::entity::fold_period_by_entity(
                &f.db,
                &f.book,
                &periods[0],
                Some(safe),
            )
            .unwrap();
            let one = as_pending(f.proposal("retained-entity-one", date, f.usd, 1));
            let (source, recorded_at) = f.append_retained_fault(one);
            let head = f.db.frontier().unwrap();
            let rows = f.db.vertices().unwrap();
            let period_error =
                fa_registers::entity::fold_period_by_entity(&f.db, &f.book, &periods[0], None)
                    .unwrap_err();
            let mut errors = vec![(period_error, periods.clone(), None)];
            if pending {
                // These two reports select posted activity, not reservations.
                assert!(
                    fa_registers::entity::stock_by_entity(&f.db, &f.book, through, None)
                        .unwrap()
                        .cells
                        .is_empty()
                );
                assert!(
                    fa_registers::entity::period_activity_by_entity(
                        &f.db,
                        &f.book,
                        &periods,
                        None,
                        &[]
                    )
                    .unwrap()
                    .cells
                    .is_empty()
                );
            } else {
                errors.push((
                    fa_registers::entity::stock_by_entity(&f.db, &f.book, through, None)
                        .unwrap_err(),
                    Vec::new(),
                    Some(through),
                ));
                errors.push((
                    fa_registers::entity::period_activity_by_entity(
                        &f.db,
                        &f.book,
                        &periods,
                        None,
                        &[],
                    )
                    .unwrap_err(),
                    periods.clone(),
                    None,
                ));
                // Selection precedes arithmetic: the same source remains a
                // valid empty report before its effective day or in March.
                assert!(
                    fa_registers::entity::stock_by_entity(&f.db, &f.book, day(2026, 1, 4), None)
                        .unwrap()
                        .cells
                        .is_empty()
                );
                assert!(
                    fa_registers::entity::period_activity_by_entity(
                        &f.db,
                        &f.book,
                        &["FY2026-P03".into()],
                        None,
                        &[]
                    )
                    .unwrap()
                    .cells
                    .is_empty()
                );
            }
            for (error, selected_periods, effective_through) in errors {
                let RegisterError::Capacity(diagnosis) = error else {
                    panic!("typed native entity diagnosis required: {error:?}")
                };
                assert_eq!(diagnosis.source, source);
                assert_eq!(
                    (diagnosis.recorded_at, diagnosis.known_at),
                    (recorded_at, head)
                );
                assert!(!diagnosis.functional);
                assert!(diagnosis.by_entity);
                assert_eq!(diagnosis.pending, pending);
                assert_eq!(diagnosis.entity.as_deref(), declared.then_some("Estate"));
                assert_eq!(
                    (diagnosis.periods.clone(), diagnosis.effective_through),
                    (selected_periods, effective_through)
                );
                assert_eq!(diagnosis.account, account_vid(f.book.book_id, "1200"));
                assert_eq!((diagnosis.unit_id, diagnosis.side), (f.usd.0, Side::Debit));
                assert_eq!((diagnosis.accumulated, diagnosis.incoming), (i128::MAX, 1));
                let refusal = diagnosis.refusal();
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3));
                let entity = if declared { "Estate" } else { "<default>" };
                assert!(
                    refusal.message.contains(&format!("entity {entity};")),
                    "{refusal}"
                );
            }
            assert_eq!(
                fa_registers::entity::fold_period_by_entity(
                    &f.db,
                    &f.book,
                    &periods[0],
                    Some(safe)
                )
                .unwrap(),
                original
            );
            assert_eq!(f.db.frontier().unwrap(), head);
            assert_eq!(f.db.vertices().unwrap(), rows);
        }
    }
}

#[test]
fn retained_cell_capacity_diagnoses_native_functional_and_pending_without_mutation() {
    for (functional, pending) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut f = Fixture::new();
        let date = day(2026, 1, 5);
        let mut first = if functional {
            let rate = f.rate(date, i128::MAX as u128, "retained maximum");
            f.valued(f.proposal("maximum", date, f.eur, 10), &rate)
        } else {
            f.proposal("maximum", date, f.usd, i128::MAX)
        };
        if pending {
            first.class = EntryClass::PENDING;
            first.pending = Some(Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            });
        }
        let first_posted = f.post(first).entry_ref();
        if !functional {
            let ctx = f.ctx();
            f.runtime
                .block_on(fa_registers::advance(
                    &mut f.db,
                    &ctx,
                    &f.book,
                    "FY2026-P01",
                ))
                .unwrap();
        }
        let safe = f.db.frontier().unwrap();
        let original =
            fa_registers::fold_period_at(&f.db, &f.book, "FY2026-P01", Some(safe)).unwrap();
        let mut next = if functional {
            let rate = f.rate(date, 10, "retained one-to-one");
            f.valued(f.proposal("retained-one", date, f.eur, 1), &rate)
        } else {
            f.proposal("retained-one", date, f.usd, 1)
        };
        if pending {
            next.class = EntryClass::PENDING;
            next.pending = Some(Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            });
        }
        let (source, recorded_at) = f.append_retained_fault(next);
        let head = f.db.frontier().unwrap();
        let rows = f.db.vertices().unwrap();
        if !functional {
            let ctx = f.ctx();
            let error = f
                .runtime
                .block_on(fa_registers::advance(
                    &mut f.db,
                    &ctx,
                    &f.book,
                    "FY2026-P01",
                ))
                .unwrap_err();
            assert!(matches!(error, RegisterError::Capacity(_)), "{error:?}");
        }
        let period_error = if functional {
            fold_period_functional(&f.db, &f.book, "FY2026-P01", None).unwrap_err()
        } else {
            fa_registers::fold_period(&f.db, &f.book, "FY2026-P01").unwrap_err()
        };
        let stock_error = if functional {
            fold_functional_stock(&f.db, &f.book, day(2026, 1, 31), None).unwrap_err()
        } else {
            balance_as_of(&f.db, &f.book, day(2026, 1, 31), None).unwrap_err()
        };
        for (error, periods, through) in [
            (period_error, vec!["FY2026-P01".to_string()], None),
            (stock_error, Vec::new(), Some(day(2026, 1, 31))),
        ] {
            let RegisterError::Capacity(diagnosis) = error else {
                panic!("typed cell diagnosis required: {error:?}")
            };
            assert_eq!(diagnosis.source, source);
            assert_eq!(
                (diagnosis.recorded_at, diagnosis.known_at),
                (recorded_at, head)
            );
            assert_eq!(
                (diagnosis.functional, diagnosis.pending),
                (functional, pending)
            );
            assert_eq!(diagnosis.by_entity, functional);
            assert_eq!((diagnosis.accumulated, diagnosis.incoming), (i128::MAX, 1));
            assert_eq!(diagnosis.unit_id, f.usd.0);
            assert_eq!(diagnosis.account, account_vid(f.book.book_id, "1200"));
            assert_eq!(diagnosis.side, Side::Debit);
            assert_eq!(
                (diagnosis.periods.clone(), diagnosis.effective_through),
                (periods, through)
            );
            let refusal = diagnosis.refusal();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3));
            assert!(refusal.fix.contains("preserve"));
            assert!(refusal.fix.contains("reversal adds gross"));
        }
        assert_eq!(
            fa_registers::fold_period_at(&f.db, &f.book, "FY2026-P01", Some(safe)).unwrap(),
            original,
        );
        assert!(
            fa_journal::post::read_entry(&f.db, source.vid)
                .unwrap()
                .is_some()
        );
        assert_eq!(f.db.frontier().unwrap(), head);
        assert_eq!(f.db.vertices().unwrap(), rows);
        if pending {
            // Explicitly resolving a reservation changes the current state,
            // while the over-cap historical coordinate stays invalid.
            let mut release = f.proposal("release-large", date, f.usd, 1);
            release.class = EntryClass::RESOLUTION;
            release.legs.clear();
            release.unit_totals.clear();
            release.control = Some(ControlPayload::ReservationRelease);
            release.pending = Some(Pending {
                timeout_ns: None,
                resolution_of: Some(first_posted),
                disposition: Some(Disposition::Voids),
            });
            f.post(release);
            let ctx = f.ctx();
            let recovered = f
                .runtime
                .block_on(fa_registers::advance(
                    &mut f.db,
                    &ctx,
                    &f.book,
                    "FY2026-P01",
                ))
                .unwrap();
            if !functional {
                assert!(
                    recovered.rebuilt,
                    "overflowing pending tail must refold its final state"
                );
            }
            assert_eq!(recovered.fold.pending.len(), 2);
            assert!(
                recovered
                    .fold
                    .pending
                    .iter()
                    .all(|cell| cell.debits.checked_add(cell.credits) == Some(1))
            );
            if functional {
                let native =
                    fa_registers::fold_period_at(&f.db, &f.book, "FY2026-P01", Some(head)).unwrap();
                assert!(
                    native
                        .pending
                        .iter()
                        .all(|cell| cell.debits.checked_add(cell.credits) == Some(11))
                );
                assert!(matches!(
                    fold_period_functional(&f.db, &f.book, "FY2026-P01", Some(head)),
                    Err(RegisterError::Capacity(_))
                ));
            } else {
                assert!(
                    matches!(
                        fa_registers::fold_period_at(&f.db, &f.book, "FY2026-P01", Some(head)),
                        Err(RegisterError::Capacity(_))
                    ),
                    "the historical native prefix remains over-cap"
                );
            }
            let current = fold_period_functional(&f.db, &f.book, "FY2026-P01", None).unwrap();
            assert_eq!(current.pending.len(), 2);
            assert!(
                current
                    .pending
                    .iter()
                    .all(|cell| cell.debits.checked_add(cell.credits) == Some(1))
            );
        }
    }
}

#[test]
fn cross_account_report_overflow_is_distinct_from_a_retained_cell_violation() {
    let mut f = Fixture::new();
    let accounts = [("1280", AccountType::ASSET), ("4080", AccountType::REVENUE)]
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
        .collect::<Vec<_>>();
    let ctx = f.ctx();
    let description = f.sealed("independent columns");
    f.runtime
        .block_on(install_chart(
            &mut f.db,
            &ctx,
            &f.book,
            &accounts,
            PRINCIPAL,
            day(2026, 1, 1),
            b"independent-columns",
            description,
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    f.post(f.proposal("column-a", day(2026, 1, 5), f.usd, i128::MAX));
    let mut second = f.proposal("column-b", day(2026, 1, 5), f.usd, i128::MAX);
    second.legs[0].account_ref = account_vid(f.book.book_id, "1280");
    second.legs[1].account_ref = account_vid(f.book.book_id, "4080");
    f.post(second);
    let head = f.db.frontier().unwrap();
    let fold = fa_registers::fold_period(&f.db, &f.book, "FY2026-P01").unwrap();
    assert_eq!(fold.cells.len(), 4);
    assert!(matches!(
        balance_as_of(&f.db, &f.book, day(2026, 1, 31), None),
        Err(RegisterError::Overflow),
    ));
    assert_eq!(f.db.frontier().unwrap(), head);
}

#[test]
fn maintained_cross_period_overflow_refolds_to_identify_the_retained_source() {
    let mut f = Fixture::new();
    f.post(f.proposal("december-maximum", day(2025, 12, 5), f.usd, i128::MAX));
    let ctx = f.ctx();
    f.runtime
        .block_on(fa_registers::advance(
            &mut f.db,
            &ctx,
            &f.book,
            "FY2025-P12",
        ))
        .unwrap();
    let next = f.proposal("january-one", day(2026, 1, 5), f.usd, 1);
    let (source, recorded_at) = f.append_retained_fault(next);
    let ctx = f.ctx();
    f.runtime
        .block_on(fa_registers::advance(
            &mut f.db,
            &ctx,
            &f.book,
            "FY2026-P01",
        ))
        .unwrap();
    let head = f.db.frontier().unwrap();
    let before = f.db.vertices().unwrap();
    let error =
        fa_registers::trial_balance_served(&f.db, &f.book, &["FY2026-P01".into()]).unwrap_err();
    let RegisterError::Capacity(diagnosis) = error else {
        panic!("exact source diagnosis required: {error:?}")
    };
    assert_eq!(diagnosis.source, source);
    assert_eq!(
        (diagnosis.recorded_at, diagnosis.known_at),
        (recorded_at, head)
    );
    assert_eq!((diagnosis.accumulated, diagnosis.incoming), (i128::MAX, 1));
    assert_eq!(diagnosis.effective_through, Some(day(2026, 1, 31)));
    assert!(diagnosis.periods.is_empty());
    assert_eq!(f.db.frontier().unwrap(), head);
    assert_eq!(f.db.vertices().unwrap(), before);
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
fn functional_migration_activation_agrees_with_independent_capacity_and_rate_oracles() {
    use fa_reference::fx::{
        OracleCapacityError, OracleFunctionalEntry, OracleFxLeg, OracleRateQuote,
        OracleRealizedLeg, admit_register_capacity, value_entity_legs,
    };

    for base in [i128::MAX, i128::MAX - 1] {
        let mut f = Fixture::new();
        let opening = day(2025, 1, 1);
        let through = day(2026, 1, 31);
        // Expectations start with the unvalued source, not the kernel's
        // valued legs, visibility predicate or observed publication result.
        let foreign: Vec<_> = [
            ("1200", fa_reference::Side::Debit),
            ("4000", fa_reference::Side::Credit),
        ]
        .into_iter()
        .map(|(code, side)| OracleFxLeg {
            side,
            account: account_vid(f.book.book_id, code).0,
            unit: f.eur.0,
            mantissa: 10,
            entity: None,
        })
        .collect();
        let rates = std::collections::BTreeMap::from([(
            f.eur.0,
            OracleRateQuote {
                quote_unit: f.eur.0,
                quote_scale: f.book.units.get(f.eur).unwrap().scale,
                rate_num: base as u128,
                rate_den: 10,
                rounding_law: "HalfEven".into(),
            },
        )]);
        let valuation = value_entity_legs(
            &foreign,
            f.usd.0,
            f.book.units.get(f.usd).unwrap().scale,
            &rates,
        )
        .unwrap();
        assert_eq!(valuation.base_mantissas, vec![base, base]);
        let migrated = OracleFunctionalEntry {
            period: "FY2025-OPEN".into(),
            is_pending: false,
            is_resolved: false,
            legs: foreign
                .iter()
                .zip(&valuation.base_mantissas)
                .map(|(leg, &base_mantissa)| OracleRealizedLeg {
                    side: leg.side,
                    account: leg.account,
                    unit: leg.unit,
                    mantissa: leg.mantissa,
                    base_unit: f.usd.0,
                    base_mantissa,
                    entity: None,
                })
                .collect(),
        };
        let live = OracleFunctionalEntry {
            period: "FY2026-P01".into(),
            is_pending: false,
            is_resolved: false,
            legs: foreign
                .iter()
                .map(|leg| OracleRealizedLeg {
                    side: leg.side,
                    account: leg.account,
                    unit: f.usd.0,
                    mantissa: 1,
                    base_unit: f.usd.0,
                    base_mantissa: 1,
                    entity: None,
                })
                .collect(),
        };
        assert_eq!(
            admit_register_capacity(&[migrated.clone()], f.usd.0),
            Ok(())
        );
        assert_eq!(admit_register_capacity(&[live.clone()], f.usd.0), Ok(()));
        let verdict = admit_register_capacity(&[live, migrated], f.usd.0);
        assert_eq!(verdict.is_ok(), base == i128::MAX - 1);

        let rate = f.rate(opening, base as u128, "Retained migration capacity rate");
        let document = Document {
            book_id: f.book.book_id,
            kind: 18,
            mime: "text/csv".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"account,unit,net\n1200,EUR,0.10\n4000,EUR,-0.10\n".to_vec(),
        };
        let ctx = f.ctx();
        f.runtime
            .block_on(add_document(&mut f.db, &ctx, &f.book, &document))
            .unwrap()
            .unwrap();
        let evidence = document.evidence_ref(1);
        let body = RunBody {
            book_id: f.book.book_id,
            run_key: "functional-capacity-opening".into(),
            source_system: "legacy".into(),
            mode: RunMode::OpeningOnly,
            trial_balance: evidence.document_oid,
            opening_date: opening,
            lines: vec![
                TrialBalanceLine {
                    account_code: "1200".into(),
                    unit: f.eur,
                    mantissa: 10,
                },
                TrialBalanceLine {
                    account_code: "4000".into(),
                    unit: f.eur,
                    mantissa: -10,
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
            b"open-functional-capacity",
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
        let mut chunk = f.proposal("functional-capacity-chunk", opening, f.eur, 10);
        chunk.class = EntryClass::MIGRATION;
        chunk.effective_period = Some(PeriodRef {
            calendar: f.book.calendar.id.clone(),
            code: "FY2025-OPEN".into(),
        });
        chunk.evidence = vec![evidence];
        chunk.origin = EntryOrigin::Migration {
            run_ref: opened.run,
            source_system: "legacy".into(),
            source_id: f.sealed("functional-opening-entry"),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: evidence.document_oid,
        };
        let chunk = f.valued(chunk, &rate);
        assert_eq!(
            chunk
                .legs
                .iter()
                .map(|leg| leg.base_amount.unwrap().mantissa)
                .collect::<Vec<_>>(),
            valuation.base_mantissas
        );
        let approvals = f.approvals(chunk.proposal_digest().unwrap());
        let staged = f
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
        let invisible = f.stock(through, Some(staged_at));
        assert!(invisible.cells.is_empty());
        assert_eq!((invisible.entries, invisible.watermark), (0, None));

        // The real live posting must succeed despite the staged foreign
        // value. Both native cells fit; only their functional sum can fail.
        f.post(f.proposal("live-native-unit", day(2026, 1, 5), f.usd, 1));
        let live_at = f.db.frontier().unwrap();
        let live_stock = f.stock(through, Some(live_at));
        assert_eq!(
            (
                live_stock.entries,
                live_stock.total_debits().unwrap(),
                live_stock.total_credits().unwrap()
            ),
            (1, 1, 1)
        );

        let proposal = plan_run_transition(
            &f.db,
            &f.book,
            opened.run,
            kind::FINALIZE,
            PRINCIPAL,
            b"finalize-functional-capacity",
            f.sealed("finalize migration"),
        )
        .unwrap()
        .unwrap();
        let approvals = f.approvals(proposal.proposal_digest().unwrap());
        let before = f.db.frontier().unwrap();
        let rows = f.db.vertices().unwrap();
        let result = f
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
            .unwrap();
        match verdict {
            Err(OracleCapacityError::Exceeded {
                functional: true,
                pending: false,
                ..
            }) => {
                let refusal = result.unwrap_err();
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3), "{refusal}");
                assert!(refusal.message.contains("functional"), "{refusal}");
                assert_eq!(f.db.frontier().unwrap(), before);
                assert_eq!(f.db.vertices().unwrap(), rows);
                assert_eq!(
                    fa_journal::migration::read_run(&f.db, opened.run, None)
                        .unwrap()
                        .unwrap()
                        .state,
                    RunState::Open
                );
                assert_eq!(f.stock(through, None).total_debits().unwrap(), 1);
            }
            Ok(()) => {
                let finalized = result.unwrap();
                assert!(finalized.recorded_at > staged.recorded_at());
                assert_eq!(
                    fa_journal::migration::read_run(&f.db, opened.run, None)
                        .unwrap()
                        .unwrap()
                        .state,
                    RunState::Finalized
                );
                let stock = f.stock(through, None);
                assert_eq!(
                    (
                        stock.entries,
                        stock.total_debits().unwrap(),
                        stock.total_credits().unwrap()
                    ),
                    (2, i128::MAX, i128::MAX)
                );
                assert_eq!(stock.watermark, Some(finalized.recorded_at));
                let period = fold_period_functional(&f.db, &f.book, "FY2025-OPEN", None).unwrap();
                assert_eq!(period.total_debits().unwrap(), base);
                assert_eq!(period.total_credits().unwrap(), base);
                let native = balance_as_of(&f.db, &f.book, through, None).unwrap();
                assert_eq!(native.unit_totals.get(&f.eur.0), Some(&(10, 10)));
                assert_eq!(native.unit_totals.get(&f.usd.0), Some(&(1, 1)));
            }
            other => panic!("unexpected independent capacity verdict: {other:?}"),
        }
        assert_eq!(f.stock(through, Some(staged_at)), invisible);
        assert_eq!(f.stock(through, Some(live_at)), live_stock);
    }
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
