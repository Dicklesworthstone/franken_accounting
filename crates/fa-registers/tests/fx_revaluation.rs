//! Source-bound revaluation against real native entries and retained rates.
//! Literal exposure/carrying expectations are independent of the planner;
//! the functional stock fold verifies the actually published accounting effect.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::chart::{
    FxRevaluationRoute, FxRevaluationRoutesRequest, set_fx_revaluation_routes,
};
use fa_journal::evidence::{Document, add_document, document_vid, evidenced_by};
use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms, value_proposal};
use fa_journal::post::{PostPreparation, prepare_post, read_entry};
use fa_journal::refusal::{Outcome, code};
use fa_journal::rows::{edge_id, leg_vid, mantissa_scalar};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, Capability, FxRevaluationRequest, KernelError, PostRequest,
    Posted, PreparedFxRevaluation, UnitPolicy, create_book, create_periods, install_chart, post,
    prepare_fx_revaluation, transition_period,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, EvidenceRef, Id128,
    LegPayload, Oid, PeriodRef, SealKey, Supersession, SupersessionKind, SymbolTable, account_vid,
    entry_mirrors, entry_vid, leg_mirrors, period_vid, unit_vid,
};
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_registers::{FunctionalStockCellKey, balance_as_of, fold_functional_stock};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const PRINCIPAL: VId = VId(7);

fn day(month: u8, day: u8) -> DateDay {
    DateDay::from_ymd(2026, month, day).unwrap()
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn request(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: cap(&["read", "post"]),
    }
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
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new(
                    [0xa1; 32],
                    DatabaseSecurityNamespaceId([0xa2; 32]),
                    [0xa3; 32],
                ),
            ))
            .unwrap();
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let book = BookContext {
            book_id: Id128([0xa4; 16]),
            calendar: FiscalCalendar::monthly("revaluation", 1, 1).unwrap(),
            units,
            seal_key: SealKey([0xa5; 32]),
            symbols: SymbolTable::compiled(),
        };
        runtime
            .block_on(create_book(
                &mut db,
                &cx,
                &BookSpec {
                    book_id: book.book_id,
                    name: "Source-bound revaluation".into(),
                    base_unit: usd,
                    calendar: book.calendar.clone(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                &book.units,
                &book.symbols,
            ))
            .unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET, usd),
            ("1200", AccountType::ASSET, eur),
            ("1290", AccountType::ASSET, usd),
            ("2200", AccountType::LIABILITY, eur),
            ("2290", AccountType::LIABILITY, usd),
            ("4000", AccountType::REVENUE, eur),
            ("4100", AccountType::REVENUE, usd),
            ("7100", AccountType::REVENUE, usd),
        ]
        .into_iter()
        .map(|(code, kind, unit)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(matches!(
                kind,
                AccountType::LIABILITY | AccountType::REVENUE
            )),
            is_leaf: true,
            unit_policy: UnitPolicy::Single(unit),
            parent_code: None,
            limit: None,
        })
        .collect();
        let seal =
            |text: &str| Erasable::seal(&text.to_string(), None, &book.seal_key, [1; 32], [2; 24]);
        runtime
            .block_on(install_chart(
                &mut db,
                &cx,
                &book,
                &accounts,
                PRINCIPAL,
                day(1, 1),
                b"revaluation-chart",
                seal("Monetary exposure and dedicated valuation leaves"),
                &cap(&["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(create_periods(
                &mut db,
                &cx,
                &book,
                2026,
                PRINCIPAL,
                seal("Calendar"),
                &cap(&["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        for period in ["FY2026-P01", "FY2026-P02", "FY2026-P03"] {
            runtime
                .block_on(transition_period(
                    &mut db,
                    &cx,
                    &book,
                    period,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    period.as_bytes(),
                    seal("Open period"),
                    &cap(&["close"]),
                    &[],
                ))
                .unwrap()
                .unwrap();
        }
        let routes: BTreeMap<_, _> = [("1200", "1290"), ("2200", "2290")]
            .into_iter()
            .map(|(source, valuation)| {
                (
                    account_vid(book.book_id, source),
                    FxRevaluationRoute {
                        valuation_account: account_vid(book.book_id, valuation),
                        unrealized_account: account_vid(book.book_id, "7100"),
                    },
                )
            })
            .collect();
        runtime
            .block_on(set_fx_revaluation_routes(
                &mut db,
                &cx,
                &book,
                &cap(&["read", "schema_change"]),
                FxRevaluationRoutesRequest {
                    principal: PRINCIPAL,
                    effective_from: day(1, 1),
                    routes,
                    idempotency_key: b"reviewed-routes".to_vec(),
                    description: seal("Reviewed routes"),
                },
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id: book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Retained foreign transaction evidence".to_vec(),
        };
        runtime
            .block_on(add_document(&mut db, &cx, &book, &document))
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

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn head(&self) -> CommitSeq {
        self.db.frontier().unwrap()
    }

    fn account(&self, code: &str) -> VId {
        account_vid(self.book.book_id, code)
    }

    fn proposal(&self, key: &str, date: DateDay, legs: Vec<LegPayload>) -> EntryPayload {
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: date,
            document_date: None,
            description: Erasable::seal(
                &key.to_string(),
                None,
                &self.book.seal_key,
                [3; 32],
                [4; 24],
            ),
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

    fn template(&self, plan: &PreparedFxRevaluation, key: &str) -> EntryPayload {
        let mut template = self.proposal(key, plan.closing_date(), Vec::new());
        template.class = EntryClass::REVALUATION;
        template.effective_period = Some(PeriodRef {
            calendar: self.book.calendar.id.clone(),
            code: plan.request().period.clone(),
        });
        template
    }

    fn try_post(&mut self, proposal: EntryPayload) -> Outcome<Posted> {
        let cx = self.cx();
        self.runtime
            .block_on(post(&mut self.db, &cx, &self.book, request(proposal)))
    }

    fn post(&mut self, proposal: EntryPayload) -> Posted {
        self.try_post(proposal).unwrap().unwrap()
    }

    fn reversal(
        &self,
        target: EntryRef,
        original: &EntryPayload,
        date: DateDay,
        period: &str,
        key: &str,
    ) -> EntryPayload {
        let mut reversal = original.clone();
        reversal.class = EntryClass::REVERSAL;
        reversal.effective_date = date;
        reversal.effective_period = Some(PeriodRef {
            calendar: self.book.calendar.id.clone(),
            code: period.into(),
        });
        reversal.idempotency_key = key.as_bytes().to_vec();
        reversal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        for leg in &mut reversal.legs {
            leg.side = if leg.side == Side::Debit {
                Side::Credit
            } else {
                Side::Debit
            };
        }
        reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
        reversal
    }

    fn rate(
        &mut self,
        date: DateDay,
        numerator: u128,
        purpose: FxRatePurpose,
        rounding: RoundingLaw,
        source: &str,
    ) -> FxRateDocument {
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: numerator,
                rate_den: 10,
                rounding,
            },
            date,
            1_767_571_200_000_000_000,
            purpose,
            source,
        )
        .unwrap();
        let document = rate.document(self.book.book_id, PRINCIPAL, 3).unwrap();
        let cx = self.cx();
        self.runtime
            .block_on(add_document(&mut self.db, &cx, &self.book, &document))
            .unwrap()
            .unwrap();
        rate
    }

    fn foreign(
        &mut self,
        key: &str,
        date: DateDay,
        source: &str,
        side: Side,
        cents: i128,
        numerator: u128,
    ) -> Posted {
        let rate = self.rate(
            date,
            numerator,
            FxRatePurpose::SpotClose,
            RoundingLaw::HalfEven,
            key,
        );
        let opposite = if side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        let raw = self.proposal(
            key,
            date,
            vec![
                LegPayload::simple(side, self.account(source), Amount::new(self.eur, cents)),
                LegPayload::simple(opposite, self.account("4000"), Amount::new(self.eur, cents)),
            ],
        );
        let arithmetic = self.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        let spec = fa_journal::genesis::read_book_spec(&self.db)
            .unwrap()
            .unwrap();
        let valued = value_proposal(
            &mut budget,
            raw,
            &spec,
            &self.book.units,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap();
        self.post(valued)
    }

    fn selection(&self, period: &str, source: &str, rate: &FxRateDocument) -> FxRevaluationRequest {
        FxRevaluationRequest {
            period: period.into(),
            source_account: self.account(source),
            rate_document: rate.oid(self.book.book_id).unwrap(),
            entity: None,
        }
    }

    fn prepare(
        &self,
        capability: &Capability,
        selection: &FxRevaluationRequest,
    ) -> Outcome<PreparedFxRevaluation> {
        let arithmetic = self.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        prepare_fx_revaluation(
            &self.db,
            &self.cx(),
            &self.book,
            capability,
            selection,
            &mut budget,
        )
    }

    fn plan(&self, selection: &FxRevaluationRequest) -> PreparedFxRevaluation {
        let before = self.head();
        let plan = self
            .prepare(&cap(&["read", "post"]), selection)
            .unwrap()
            .unwrap();
        assert_eq!(
            self.head(),
            before,
            "preparing a revaluation never publishes"
        );
        plan
    }

    fn net(&self, account: &str, through: DateDay, known_at: Option<CommitSeq>) -> i128 {
        fold_functional_stock(&self.db, &self.book, through, known_at)
            .unwrap()
            .cell(&FunctionalStockCellKey {
                account: self.account(account),
                unit_id: self.usd.0,
                entity: None,
            })
            .map_or(0, |cell| cell.net().unwrap())
    }

    /// Deliberately bypass economic admission while retaining a canonical
    /// native birth, every scalar mirror, and the complete monetary topology.
    /// This distinguishes a forged calculation from damaged projections.
    fn append_unchecked(&mut self, proposal: EntryPayload) {
        let entry = proposal.seal(Vec::new(), None).unwrap();
        let evid = entry_vid(
            self.book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            &entry.proposal.idempotency_key,
        );
        let period = entry.proposal.effective_period.as_ref().unwrap();
        let pvid = period_vid(&period.calendar, &period.code);
        let mut has_leg = WriteBatch::new(relation::HAS_LEG);
        let mut in_period = WriteBatch::new(relation::IN_PERIOD);
        let mut posts_to = WriteBatch::new(relation::POSTS_TO);
        let mut in_unit = WriteBatch::new(relation::IN_UNIT);
        has_leg.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry).unwrap());
        in_period.add_edge(edge_id(relation::IN_PERIOD, evid, pvid), evid, pvid, vec![]);
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            assert!(leg.dimension_set.is_empty());
            let ordinal = u16::try_from(ordinal).unwrap();
            let lvid = leg_vid(evid, ordinal);
            let mut mirrors = leg_mirrors(
                leg,
                ordinal,
                entry.proposal.effective_date,
                &self.book.units,
            )
            .unwrap();
            mirrors.push((property::APPLIED, mantissa_scalar("applied", 0).unwrap()));
            has_leg.create_vertex(lvid, vec![label::LEG], mirrors);
            has_leg.add_edge(
                edge_id(relation::HAS_LEG, evid, lvid),
                evid,
                lvid,
                vec![(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
            );
            posts_to.add_edge(
                edge_id(relation::POSTS_TO, lvid, leg.account_ref),
                lvid,
                leg.account_ref,
                vec![],
            );
            let unit = self.book.units.get(leg.amount.unit).unwrap();
            let uvid = unit_vid(
                self.book.book_id,
                &format!("{}@v{}", unit.code, unit.version),
            );
            in_unit.add_edge(edge_id(relation::IN_UNIT, lvid, uvid), lvid, uvid, vec![]);
        }
        let mut batches = vec![has_leg, in_period, posts_to, in_unit];
        let documents: Vec<_> = entry
            .proposal
            .evidence
            .iter()
            .map(|evidence| document_vid(&evidence.document_oid))
            .collect();
        batches.extend(evidenced_by(evid, &documents));
        let cx = self.cx();
        let txn_cx = cx.txn();
        let mut txn = self.db.begin(&txn_cx).unwrap();
        txn.write_ordered(&mut self.db, batches).unwrap();
        self.runtime
            .block_on(txn.commit(&mut self.db, &cx.commit()))
            .unwrap();
    }
}

#[test]
fn closing_rates_change_carrying_adjustments_without_changing_native_exposure() {
    let mut f = Fixture::new();
    let source = f.foreign(
        "january-invoice",
        day(1, 5),
        "1200",
        Side::Debit,
        10_000,
        11,
    );
    let original = read_entry(&f.db, source.entry_ref().vid).unwrap().unwrap();
    let close = f.rate(
        day(1, 31),
        12,
        FxRatePurpose::PeriodClose,
        RoundingLaw::HalfEven,
        "January close",
    );
    let selection = f.selection("FY2026-P01", "1200", &close);
    let plan = f.plan(&selection);
    assert_eq!(
        (
            plan.source_native_net().mantissa,
            plan.source_base_net().mantissa,
            plan.prior_adjustment_net().mantissa,
            plan.current_carrying_net().mantissa,
            plan.target_base_net().mantissa,
            plan.delta().mantissa
        ),
        (10_000, 11_000, 0, 11_000, 12_000, 1_000)
    );
    assert_eq!(plan.legs()[0].account_ref, f.account("1290"));
    assert_eq!(plan.legs()[0].side, Side::Debit);
    assert!(
        plan.legs()
            .iter()
            .all(|leg| leg.amount.unit == f.usd && leg.base_amount == Some(leg.amount))
    );
    let proposal = plan
        .proposal(f.template(&plan, "january-revaluation"))
        .unwrap();
    let posted = f.post(proposal.clone());
    let january_at = f.head();
    assert_eq!(f.net("1200", day(1, 31), None), 11_000);
    assert_eq!(f.net("1290", day(1, 31), None), 1_000);
    assert_eq!(f.net("7100", day(1, 31), None), -1_000);
    let native = balance_as_of(&f.db, &f.book, day(1, 31), None).unwrap();
    assert_eq!(native.unit_totals.get(&f.eur.0), Some(&(10_000, 10_000)));
    assert_eq!(
        read_entry(&f.db, source.entry_ref().vid).unwrap().unwrap(),
        original
    );
    let noop = f.plan(&selection);
    assert!(noop.is_noop() && noop.legs().is_empty());
    assert_eq!(
        (noop.current_carrying_net().mantissa, noop.delta().mantissa),
        (12_000, 0)
    );
    assert!(
        noop.proposal(f.template(&noop, "unneeded-adjustment"))
            .is_err()
    );
    assert_eq!(f.head(), january_at);

    let february = f.rate(
        day(2, 28),
        13,
        FxRatePurpose::PeriodClose,
        RoundingLaw::HalfEven,
        "February close",
    );
    let second = f.plan(&f.selection("FY2026-P02", "1200", &february));
    assert_eq!(
        (
            second.source_native_net().mantissa,
            second.source_base_net().mantissa,
            second.prior_adjustment_net().mantissa,
            second.current_carrying_net().mantissa,
            second.target_base_net().mantissa,
            second.delta().mantissa
        ),
        (10_000, 11_000, 1_000, 12_000, 13_000, 1_000)
    );
    f.post(
        second
            .proposal(f.template(&second, "february-revaluation"))
            .unwrap(),
    );
    assert_eq!(
        f.net("1200", day(2, 28), None) + f.net("1290", day(2, 28), None),
        13_000
    );
    assert_eq!(f.net("1290", day(1, 31), None), 1_000);
    assert_eq!(f.net("1290", day(2, 28), Some(january_at)), 1_000);
    let head = f.head();
    assert_eq!(f.post(proposal).entry_ref(), posted.entry_ref());
    assert_eq!(
        f.head(),
        head,
        "an exact historical retry does not revalue again"
    );
}

#[test]
fn saved_proposals_bind_population_amounts_and_publication_frontier() {
    let mut f = Fixture::new();
    f.foreign("invoice", day(1, 5), "1200", Side::Debit, 10_000, 11);
    let close = f.rate(
        day(1, 31),
        12,
        FxRatePurpose::PeriodClose,
        RoundingLaw::HalfEven,
        "Close",
    );
    let selection = f.selection("FY2026-P01", "1200", &close);
    let old = f.plan(&selection);
    let saved = old.proposal(f.template(&old, "stale-revaluation")).unwrap();
    f.foreign("late-invoice", day(1, 20), "1200", Side::Debit, 2_000, 13);
    let before = f.head();
    assert_eq!(
        f.try_post(saved).unwrap().unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(f.head(), before);
    let current = f.plan(&selection);
    assert_ne!(current.source_digest(), old.source_digest());
    assert_eq!(
        (
            current.source_native_net().mantissa,
            current.source_base_net().mantissa,
            current.target_base_net().mantissa,
            current.delta().mantissa
        ),
        (12_000, 13_600, 14_400, 800)
    );
    let proposal = current
        .proposal(f.template(&current, "current-revaluation"))
        .unwrap();

    let mut forged = proposal.clone();
    forged.idempotency_key = b"forged-balanced-amount".to_vec();
    for leg in &mut forged.legs {
        leg.amount.mantissa += 1;
        leg.base_amount = Some(leg.amount);
    }
    forged.unit_totals = EntryPayload::fold_unit_totals(&forged.legs).unwrap();
    let totals = forged.base_totals.as_mut().unwrap();
    totals.debits += 1;
    totals.credits += 1;
    forged.validate().unwrap();
    assert_eq!(
        f.try_post(forged).unwrap().unwrap_err().code,
        code::PLAN_INVALIDATED
    );

    let mut forged = proposal.clone();
    forged.idempotency_key = b"forged-source-digest".to_vec();
    let mut basis = current.basis().clone();
    basis.source_digest[0] ^= 1;
    forged.extensions[0].1 = basis.canonical_bytes().unwrap();
    forged.validate().unwrap();
    assert_eq!(
        f.try_post(forged).unwrap().unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    let mut unbound = proposal.clone();
    unbound.idempotency_key = b"unbound-caller-amounts".to_vec();
    unbound.extensions.clear();
    assert_eq!(
        f.try_post(unbound).unwrap().unwrap_err().code,
        code::CLASS_NOT_IMPLEMENTED
    );
    let mut naked = proposal.clone();
    naked.idempotency_key = b"naked-revaluation".to_vec();
    naked.extensions.clear();
    naked.base_totals = None;
    for leg in &mut naked.legs {
        leg.base_amount = None;
    }
    assert_eq!(
        f.try_post(naked).unwrap().unwrap_err().code,
        code::CLASS_NOT_IMPLEMENTED
    );
    assert_eq!(f.head(), before);

    let cx = f.cx();
    let PostPreparation::Ready(prepared) =
        prepare_post(&mut f.db, &cx, &f.book, request(proposal.clone()))
            .unwrap()
            .unwrap()
    else {
        panic!("the reviewed adjustment is fresh");
    };
    let unrelated = f.proposal(
        "unrelated-usd",
        day(1, 10),
        vec![
            LegPayload::simple(Side::Debit, f.account("1000"), Amount::new(f.usd, 100)),
            LegPayload::simple(Side::Credit, f.account("4100"), Amount::new(f.usd, 100)),
        ],
    );
    f.post(unrelated);
    let moved = f.head();
    let refused = f
        .runtime
        .block_on(prepared.commit(&mut f.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED);
    assert_eq!(refused.exit, 6);
    assert_eq!(f.head(), moved);
    // A new native preparation can revalidate the saved economic basis after
    // an unrelated commit; the abandoned transaction itself cannot publish.
    f.post(proposal);
    assert_eq!(
        f.net("1200", day(1, 31), None) + f.net("1290", day(1, 31), None),
        14_400
    );
}

#[test]
fn credit_exposure_and_zero_native_exposure_keep_signed_carrying_math_exact() {
    let mut f = Fixture::new();
    f.foreign(
        "foreign-liability",
        day(1, 5),
        "2200",
        Side::Credit,
        10_000,
        11,
    );
    let close = f.rate(
        day(1, 31),
        12,
        FxRatePurpose::PeriodClose,
        RoundingLaw::HalfEven,
        "Signed close",
    );
    let liability = f.plan(&f.selection("FY2026-P01", "2200", &close));
    assert_eq!(
        (
            liability.source_native_net().mantissa,
            liability.source_base_net().mantissa,
            liability.target_base_net().mantissa,
            liability.delta().mantissa
        ),
        (-10_000, -11_000, -12_000, -1_000)
    );
    assert_eq!(liability.legs()[0].side, Side::Credit);
    assert_eq!(liability.legs()[1].side, Side::Debit);
    let posted = f.post(
        liability
            .proposal(f.template(&liability, "liability-revaluation"))
            .unwrap(),
    );
    assert_eq!(
        f.net("2200", day(1, 31), None) + f.net("2290", day(1, 31), None),
        -12_000
    );

    f.foreign("debit-exposure", day(1, 8), "1200", Side::Debit, 10_000, 11);
    f.foreign(
        "credit-exposure",
        day(1, 9),
        "1200",
        Side::Credit,
        10_000,
        12,
    );
    let cleared_native = f.plan(&f.selection("FY2026-P01", "1200", &close));
    assert_eq!(
        (
            cleared_native.source_native_net().mantissa,
            cleared_native.source_base_net().mantissa,
            cleared_native.target_base_net().mantissa,
            cleared_native.delta().mantissa
        ),
        (0, -1_000, 0, 1_000)
    );
    assert!(
        !cleared_native.is_noop(),
        "zero foreign units can still leave a functional carrying difference"
    );
    f.post(
        cleared_native
            .proposal(f.template(&cleared_native, "clear-functional-remainder"))
            .unwrap(),
    );
    assert_eq!(
        f.net("1200", day(1, 31), None) + f.net("1290", day(1, 31), None),
        0
    );
    assert!(f.plan(&f.selection("FY2026-P01", "1200", &close)).is_noop());

    let original = read_entry(&f.db, posted.entry_ref().vid)
        .unwrap()
        .unwrap()
        .0;
    let mut reversal = original.proposal;
    reversal.class = EntryClass::REVERSAL;
    reversal.idempotency_key = b"unsupported-revaluation-reversal".to_vec();
    reversal.extensions.clear();
    reversal.supersession = vec![Supersession {
        target: posted.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversal.legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    let before = f.head();
    assert!(
        f.try_post(reversal).unwrap().is_err(),
        "v1 cannot silently reverse its source-bound valuation lineage"
    );
    assert_eq!(f.head(), before);
}

#[test]
fn retained_closing_source_and_current_whole_book_authority_are_mandatory() {
    let mut f = Fixture::new();
    f.foreign("valued-source", day(1, 5), "1200", Side::Debit, 10_000, 11);
    for (date, purpose, rounding, source) in [
        (
            day(1, 30),
            FxRatePurpose::PeriodClose,
            RoundingLaw::HalfEven,
            "Wrong closing date",
        ),
        (
            day(1, 31),
            FxRatePurpose::SpotClose,
            RoundingLaw::HalfEven,
            "Wrong purpose",
        ),
        (
            day(1, 31),
            FxRatePurpose::PeriodClose,
            RoundingLaw::HalfUp,
            "Wrong rounding",
        ),
    ] {
        let rate = f.rate(date, 12, purpose, rounding, source);
        let selection = f.selection("FY2026-P01", "1200", &rate);
        let before = f.head();
        assert_eq!(
            f.prepare(&cap(&["read", "post"]), &selection)
                .unwrap()
                .unwrap_err()
                .code,
            code::STRUCTURE
        );
        assert_eq!(f.head(), before);
    }
    let close = f.rate(
        day(1, 31),
        12,
        FxRatePurpose::PeriodClose,
        RoundingLaw::HalfEven,
        "Valid close",
    );
    let selection = f.selection("FY2026-P01", "1200", &close);
    let mut unknown = selection.clone();
    unknown.rate_document = Oid([0xff; 32]);
    let head = f.head();
    for denied in [
        cap(&["post"]),
        cap(&["read"]),
        cap(&["read", "post"]).for_accounts(&["1200"]).unwrap(),
        cap(&["read", "post"]).expiring_at(head),
    ] {
        let refusal = f.prepare(&denied, &unknown).unwrap().unwrap_err();
        assert_eq!(
            refusal.exit, 7,
            "authority must win before unknown source observation"
        );
        assert_eq!(f.head(), head);
    }
    assert_eq!(
        f.prepare(&cap(&["read", "post"]), &unknown)
            .unwrap()
            .unwrap_err()
            .code,
        code::EVIDENCE_UNKNOWN
    );
    let unvalued = f.proposal(
        "unvalued-source",
        day(1, 20),
        vec![
            LegPayload::simple(Side::Debit, f.account("1200"), Amount::new(f.eur, 100)),
            LegPayload::simple(Side::Credit, f.account("4000"), Amount::new(f.eur, 100)),
        ],
    );
    f.post(unvalued);
    let head = f.head();
    let refusal = f
        .prepare(&cap(&["read", "post"]), &selection)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::CLASS_NOT_IMPLEMENTED);
    assert!(refusal.message.contains("no retained functional valuation"));
    assert_eq!(f.head(), head);
}

#[test]
fn canonical_forged_adjustment_cannot_become_trusted_carrying_history() {
    let mut f = Fixture::new();
    f.foreign("forgery-source", day(1, 5), "1200", Side::Debit, 10_000, 11);
    let close = f.rate(
        day(1, 31),
        12,
        FxRatePurpose::PeriodClose,
        RoundingLaw::HalfEven,
        "Closing source for historical proof",
    );
    let selection = f.selection("FY2026-P01", "1200", &close);
    let prepared = f.plan(&selection);
    assert_eq!(prepared.delta().mantissa, 1_000);
    let mut forged = prepared
        .proposal(f.template(&prepared, "balanced-but-forged-history"))
        .unwrap();
    for leg in &mut forged.legs {
        leg.amount.mantissa += 1;
        leg.base_amount = Some(leg.amount);
    }
    forged.unit_totals = EntryPayload::fold_unit_totals(&forged.legs).unwrap();
    let totals = forged.base_totals.as_mut().unwrap();
    totals.debits += 1;
    totals.credits += 1;
    forged.validate().unwrap();
    f.append_unchecked(forged);
    let before = f.head();

    fa_journal::entry_history::verify_entry_history(&f.db, &f.cx(), &f.book, None).unwrap();
    fa_journal::migration::verify_run_visibility_at(&f.db, &f.book, before).unwrap();
    assert!(
        fa_journal::projections::verify_projections(&f.db, &f.book, None)
            .unwrap()
            .is_green()
    );
    assert!(
        fa_journal::period::verify_periods(&f.db, &f.book, None)
            .unwrap()
            .is_green()
    );
    assert_eq!(f.net("1290", day(1, 31), None), 1_001);
    let error = f.prepare(&cap(&["read", "post"]), &selection).unwrap_err();
    assert!(matches!(error, KernelError::Corrupt(message)
        if message.contains("does not reproduce its original observation and publication basis")));
    assert_eq!(
        f.head(),
        before,
        "economic replay refuses without publication"
    );
}

#[test]
fn manual_valuation_postings_remain_unbound_even_after_their_net_is_zero() {
    let mut f = Fixture::new();
    f.foreign(
        "dedicated-source",
        day(1, 5),
        "1200",
        Side::Debit,
        10_000,
        11,
    );
    let close = f.rate(
        day(1, 31),
        12,
        FxRatePurpose::PeriodClose,
        RoundingLaw::HalfEven,
        "Closing source for dedicated leaf",
    );
    let selection = f.selection("FY2026-P01", "1200", &close);
    assert_eq!(f.plan(&selection).delta().mantissa, 1_000);
    for (key, side, opposite, net) in [
        ("unbound-manual-adjustment", Side::Debit, Side::Credit, 100),
        ("unbound-manual-offset", Side::Credit, Side::Debit, 0),
    ] {
        let proposal = f.proposal(
            key,
            day(1, 31),
            vec![
                LegPayload::simple(side, f.account("1290"), Amount::new(f.usd, 100)),
                LegPayload::simple(opposite, f.account("4100"), Amount::new(f.usd, 100)),
            ],
        );
        f.post(proposal);
        assert_eq!(f.net("1290", day(1, 31), None), net);
        assert_eq!(f.net("1200", day(1, 31), None), 11_000);
        let before = f.head();
        let refusal = f
            .prepare(&cap(&["read", "post"]), &selection)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CLASS_NOT_IMPLEMENTED);
        assert!(
            refusal
                .message
                .contains("unrelated or legacy unbound posting")
        );
        assert_eq!(f.head(), before);
    }
}

#[test]
fn foreign_reversal_preserves_committed_valuation_provenance_and_rounding() {
    fn value(f: &Fixture, mut proposal: EntryPayload, rate: &FxRateDocument) -> EntryPayload {
        proposal.base_totals = None;
        for leg in &mut proposal.legs {
            leg.base_amount = None;
        }
        proposal
            .evidence
            .retain(|evidence| evidence.role != fa_journal::fx::RATE_EVIDENCE_ROLE);
        let arithmetic = f.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        value_proposal(
            &mut budget,
            proposal,
            &fa_journal::genesis::read_book_spec(&f.db).unwrap().unwrap(),
            &f.book.units,
            FxLawId::SpotClose,
            std::slice::from_ref(rate),
        )
        .unwrap()
    }

    for with_residual in [false, true] {
        let mut f = Fixture::new();
        let numerator = if with_residual { 5 } else { 11 };
        let rate = f.rate(
            day(1, 5),
            numerator,
            FxRatePurpose::SpotClose,
            RoundingLaw::HalfEven,
            "Original retained valuation source",
        );
        let legs = if with_residual {
            vec![
                LegPayload::simple(Side::Debit, f.account("1200"), Amount::new(f.eur, 3)),
                LegPayload::simple(Side::Debit, f.account("2200"), Amount::new(f.eur, 3)),
                LegPayload::simple(Side::Credit, f.account("4000"), Amount::new(f.eur, 6)),
            ]
        } else {
            vec![
                LegPayload::simple(Side::Debit, f.account("1200"), Amount::new(f.eur, 10_000)),
                LegPayload::simple(Side::Credit, f.account("4000"), Amount::new(f.eur, 10_000)),
            ]
        };
        let original = value(&f, f.proposal("valued-original", day(1, 5), legs), &rate);
        assert_eq!(
            original.base_totals.as_ref().unwrap().residual.is_some(),
            with_residual
        );
        let posted = f.post(original.clone());
        let mut exact = original.clone();
        exact.class = EntryClass::REVERSAL;
        exact.idempotency_key = b"exact-valued-reversal".to_vec();
        exact.supersession = vec![Supersession {
            target: posted.entry_ref(),
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        for leg in &mut exact.legs {
            leg.side = if leg.side == Side::Debit {
                Side::Credit
            } else {
                Side::Debit
            };
        }
        exact.unit_totals = EntryPayload::fold_unit_totals(&exact.legs).unwrap();

        for (quoted_numerator, source) in [
            (numerator, "Distinct source with the same rate"),
            (12, "Different same-day rate"),
        ] {
            let alternate = f.rate(
                day(1, 5),
                quoted_numerator,
                FxRatePurpose::SpotClose,
                RoundingLaw::HalfEven,
                source,
            );
            let forged = value(&f, exact.clone(), &alternate);
            assert_eq!(
                forged.legs.iter().map(|leg| leg.amount).collect::<Vec<_>>(),
                original
                    .legs
                    .iter()
                    .map(|leg| leg.amount)
                    .collect::<Vec<_>>()
            );
            assert_ne!(forged.base_totals, original.base_totals);
            let before = f.head();
            let refused = f.try_post(forged).unwrap().unwrap_err();
            assert_eq!(refused.code, code::REVERSAL_SHAPE);
            assert_eq!(f.head(), before);
        }
        let mut erased = exact.clone();
        erased.base_totals = None;
        for leg in &mut erased.legs {
            leg.base_amount = None;
        }
        let before = f.head();
        assert_eq!(
            f.try_post(erased).unwrap().unwrap_err().code,
            code::REVERSAL_SHAPE
        );
        assert_eq!(f.head(), before);

        let reversal = f.post(exact.clone());
        let retained = read_entry(&f.db, reversal.entry_ref().vid)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(retained.proposal.base_totals, original.base_totals);
        assert_eq!(retained.proposal.evidence, original.evidence);
        for (old, undo) in original.legs.iter().zip(&retained.proposal.legs) {
            assert_eq!(old.amount, undo.amount);
            assert_eq!(old.base_amount, undo.base_amount);
            assert_ne!(old.side, undo.side);
        }
        let functional = fold_functional_stock(&f.db, &f.book, day(1, 31), None).unwrap();
        assert!(functional.cells.iter().all(|cell| cell.net().unwrap() == 0));
        let close = f.rate(
            day(1, 31),
            12,
            FxRatePurpose::PeriodClose,
            RoundingLaw::HalfEven,
            "Close after the exact reversal",
        );
        let no_exposure = f.plan(&f.selection("FY2026-P01", "1200", &close));
        assert_eq!(no_exposure.source_native_net().mantissa, 0);
        assert_eq!(no_exposure.source_base_net().mantissa, 0);
        assert!(no_exposure.is_noop());
        let before = f.head();
        let retry = f.post(exact);
        assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
        assert_eq!(retry.entry_ref(), reversal.entry_ref());
        assert_eq!(f.head(), before);
    }
}

#[test]
fn later_foreign_reversals_retain_the_original_valuation_day_and_period_through_ancestry() {
    fn value(
        f: &Fixture,
        mut proposal: EntryPayload,
        law: FxLawId,
        rate: &FxRateDocument,
    ) -> EntryPayload {
        proposal.base_totals = None;
        for leg in &mut proposal.legs {
            leg.base_amount = None;
        }
        proposal
            .evidence
            .retain(|evidence| evidence.role != fa_journal::fx::RATE_EVIDENCE_ROLE);
        let arithmetic = f.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        value_proposal(
            &mut budget,
            proposal,
            &fa_journal::genesis::read_book_spec(&f.db).unwrap().unwrap(),
            &f.book.units,
            law,
            std::slice::from_ref(rate),
        )
        .unwrap()
    }

    for (law, reversal_month, with_residual) in [
        (FxLawId::SpotClose, 1, false),
        (FxLawId::SpotClose, 2, true),
        (FxLawId::PeriodAverage, 2, false),
        (FxLawId::PeriodAverage, 2, true),
    ] {
        let mut f = Fixture::new();
        let original_quote_day = if law == FxLawId::SpotClose {
            day(1, 5)
        } else {
            day(1, 31)
        };
        let numerator = if with_residual { 5 } else { 11 };
        let original_rate = f.rate(
            original_quote_day,
            numerator,
            law.required_purpose().expect("quoted valuation law"),
            RoundingLaw::HalfEven,
            "Retained original-period quote",
        );
        let legs = if with_residual {
            vec![
                LegPayload::simple(Side::Debit, f.account("1200"), Amount::new(f.eur, 3)),
                LegPayload::simple(Side::Debit, f.account("2200"), Amount::new(f.eur, 3)),
                LegPayload::simple(Side::Credit, f.account("4000"), Amount::new(f.eur, 6)),
            ]
        } else {
            vec![
                LegPayload::simple(Side::Debit, f.account("1200"), Amount::new(f.eur, 10_000)),
                LegPayload::simple(Side::Credit, f.account("4000"), Amount::new(f.eur, 10_000)),
            ]
        };
        let original = value(
            &f,
            f.proposal("original-period-valuation", day(1, 5), legs),
            law,
            &original_rate,
        );
        assert_eq!(
            original.base_totals.as_ref().unwrap().residual.is_some(),
            with_residual
        );
        let source = f.post(original.clone());
        let retained_source = read_entry(&f.db, source.entry_ref().vid).unwrap().unwrap();
        let source_net = original.legs[0].base_amount.unwrap().mantissa;
        let reversal_period = format!("FY2026-P{reversal_month:02}");
        let reversal_date = day(reversal_month, 20);
        let close_date = day(reversal_month, if reversal_month == 1 { 31 } else { 28 });
        let exact = f.reversal(
            source.entry_ref(),
            &original,
            reversal_date,
            &reversal_period,
            "later-period-reversal",
        );

        // A newly valued Original still needs its own date/period's quote;
        // only a verified reversal inherits its ancestor's valuation context.
        let mut wrong_context = original.clone();
        wrong_context.effective_date = day(2, 20);
        wrong_context.effective_period = Some(PeriodRef {
            calendar: f.book.calendar.id.clone(),
            code: "FY2026-P02".into(),
        });
        wrong_context.idempotency_key = b"fresh-post-cannot-inherit-date".to_vec();
        let before = f.head();
        assert_eq!(
            f.try_post(wrong_context).unwrap().unwrap_err().code,
            code::STRUCTURE
        );
        assert_eq!(f.head(), before);

        // These are valid fresh valuations for the reversal date. Neither
        // equal numeric carrying under new provenance nor changed carrying
        // may replace the exact original quote and amounts on a reversal.
        for quoted_numerator in [numerator, 12] {
            let alternate = f.rate(
                if law == FxLawId::SpotClose {
                    reversal_date
                } else {
                    close_date
                },
                quoted_numerator,
                law.required_purpose().expect("quoted valuation law"),
                RoundingLaw::HalfEven,
                "New reversal-period quote must not replace retained valuation",
            );
            let forged = value(&f, exact.clone(), law, &alternate);
            assert_ne!(forged.base_totals, original.base_totals);
            let before = f.head();
            assert_eq!(
                f.try_post(forged).unwrap().unwrap_err().code,
                code::REVERSAL_SHAPE
            );
            assert_eq!(f.head(), before);
        }
        if with_residual {
            let mut changed_residual = exact.clone();
            changed_residual
                .base_totals
                .as_mut()
                .unwrap()
                .residual
                .as_mut()
                .unwrap()
                .amount
                .mantissa += 1;
            changed_residual.validate().unwrap();
            let before = f.head();
            assert_eq!(
                f.try_post(changed_residual).unwrap().unwrap_err().code,
                code::REVERSAL_SHAPE
            );
            assert_eq!(f.head(), before);
        }

        let reversed = f.post(exact.clone());
        let reversal_entry = read_entry(&f.db, reversed.entry_ref().vid)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(reversal_entry.proposal.effective_date, reversal_date);
        assert_eq!(reversal_entry.proposal.base_totals, original.base_totals);
        assert_eq!(reversal_entry.proposal.evidence, original.evidence);
        assert_eq!(f.net("1200", close_date, None), 0);
        assert_eq!(f.net("1200", day(1, 5), None), source_net);
        let close = f.rate(
            close_date,
            12,
            FxRatePurpose::PeriodClose,
            RoundingLaw::HalfEven,
            "Closing quote after the exact later reversal",
        );
        let no_exposure = f.plan(&f.selection(&reversal_period, "1200", &close));
        assert_eq!(no_exposure.source_native_net().mantissa, 0);
        assert_eq!(no_exposure.source_base_net().mantissa, 0);
        assert!(no_exposure.is_noop());

        let restore = f.reversal(
            reversed.entry_ref(),
            &reversal_entry.proposal,
            day(3, 20),
            "FY2026-P03",
            "march-reversal-of-reversal",
        );
        if reversal_month == 2 {
            let mut earlier = restore.clone();
            earlier.effective_date = day(1, 20);
            earlier.effective_period.as_mut().unwrap().code = "FY2026-P01".into();
            let before = f.head();
            assert_eq!(
                f.try_post(earlier).unwrap().unwrap_err().code,
                code::REVERSAL_PERIOD
            );
            assert_eq!(f.head(), before);
        }
        let restored = f.post(restore.clone());
        let restored_entry = read_entry(&f.db, restored.entry_ref().vid)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(restored_entry.proposal.effective_date, day(3, 20));
        assert_eq!(restored_entry.proposal.base_totals, original.base_totals);
        assert_eq!(restored_entry.proposal.evidence, original.evidence);
        assert_eq!(restored_entry.proposal.legs, original.legs);
        assert_eq!(f.net("1200", day(3, 31), None), source_net);
        assert_eq!(f.net("1200", close_date, None), 0);
        assert_eq!(f.net("1200", day(3, 31), Some(reversed.recorded_at())), 0);
        assert_eq!(
            read_entry(&f.db, source.entry_ref().vid).unwrap().unwrap(),
            retained_source
        );
        let before = f.head();
        for (proposal, prior) in [(exact, reversed), (restore, restored)] {
            let retry = f.post(proposal);
            assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
            assert_eq!(retry.entry_ref(), prior.entry_ref());
            assert_eq!(retry.recorded_at(), prior.recorded_at());
            assert_eq!(f.head(), before);
        }
    }
}

#[test]
fn prepared_later_reversal_witnesses_the_original_valuation_ancestor() {
    let mut f = Fixture::new();
    let source = f.foreign(
        "ancestor-source",
        day(1, 5),
        "1200",
        Side::Debit,
        10_000,
        11,
    );
    let original = read_entry(&f.db, source.entry_ref().vid)
        .unwrap()
        .unwrap()
        .0;
    let first = f.reversal(
        source.entry_ref(),
        &original.proposal,
        day(2, 20),
        "FY2026-P02",
        "february-reversal",
    );
    let reversed = f.post(first);
    let first = read_entry(&f.db, reversed.entry_ref().vid)
        .unwrap()
        .unwrap()
        .0;
    let second = f.reversal(
        reversed.entry_ref(),
        &first.proposal,
        day(3, 20),
        "FY2026-P03",
        "march-restoration",
    );
    let cx = f.cx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut f.db, &cx, &f.book, request(second))
        .unwrap()
        .unwrap()
    else {
        panic!("the reversal-of-reversal is fresh");
    };
    // Change the original ancestor, not the immediate reversal target. A
    // prepared post must retain the original valuation as a native witness.
    let mut damage = WriteBatch::new(relation::HAS_LEG);
    damage.set_vertex_property(
        source.entry_ref().vid,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(vec![0xff; 32]).unwrap()),
    );
    f.runtime
        .block_on(f.db.write(&cx.commit(), damage))
        .unwrap();
    let before = f.head();
    let refused = f
        .runtime
        .block_on(prepared.commit(&mut f.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CONFLICT);
    assert_eq!(f.head(), before);
    assert!(
        read_entry(
            &f.db,
            fa_journal::rows::reversal_vid(reversed.entry_ref().vid)
        )
        .unwrap()
        .is_none()
    );
}
