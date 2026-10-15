//! Mixed original postings, not synthetic split legs, exercise the native path.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::cash_flow_split::{
    CashFlowLegSplit, CashFlowPortion, CashFlowSplitDefinition, SplitCashFlow,
};
use fa::general_ledger::{CashFlowActivity, CashFlowAssignment, CashFlowDefinition};
use fa::{AsyncBook, BookKeys, Capability, Entropy, GeneralLedger, RollForwardRequest};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::{CommitSeq, VId, context::PurposeContexts};
use std::path::Path;

const PRINCIPAL: VId = VId(1);
fn day(d: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, d).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn portions(parts: &[(CashFlowActivity, i128)]) -> Vec<CashFlowPortion> {
    parts
        .iter()
        .map(|(activity, amount)| CashFlowPortion {
            activity: *activity,
            amount: *amount,
        })
        .collect()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    jpy: UnitId,
    evidence: Vec<EvidenceRef>,
}
impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let jpy = units.lookup("JPY").unwrap();
        let book_id = Id128([129; 16]);
        let spec = BookSpec {
            book_id,
            name: "Mixed cash splits".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("cash-splits", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("cash-splits"),
                BookKeys::for_development(129),
                spec,
                Entropy::deterministic(129),
            ))
            .unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET),
            ("1010", AccountType::ASSET),
            ("2300", AccountType::LIABILITY),
            ("3000", AccountType::EQUITY),
            ("4000", AccountType::REVENUE),
            ("6100", AccountType::EXPENSE),
        ]
        .into_iter()
        .map(|(code, kind)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from([2, 3, 4].contains(&kind.0)),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
        runtime
            .block_on(book.install_chart(&cx, &accounts, PRINCIPAL, day(1), b"split-chart"))
            .unwrap()
            .unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P01",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day(1),
                b"split-open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let doc = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Private mixed transaction evidence".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            jpy,
            evidence: vec![doc.evidence_ref(1)],
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn request(&self) -> RollForwardRequest {
        RollForwardRequest {
            accounts: vec![self.id("1000"), self.id("1010")],
            units: vec![self.usd.0, self.jpy.0],
            label: "Cash portions €".into(),
            effective_from: day(10),
            effective_through: day(20),
            known_at: Some(self.head()),
        }
    }
    fn post(&mut self, date: u8, key: &[u8], unit: UnitId, rows: &[(&str, Side, i128)]) {
        let legs = rows
            .iter()
            .map(|(code, side, amount)| {
                LegPayload::simple(*side, self.id(code), Amount::new(unit, *amount))
            })
            .collect();
        self.post_legs(date, key, legs);
    }
    fn post_legs(&mut self, date: u8, key: &[u8], legs: Vec<LegPayload>) {
        let cx = self.cx();
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&cx, "Private split posting").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([57; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        };
        self.runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(&["post"]),
                },
            ))
            .unwrap()
            .unwrap();
    }
    fn ledger(&self) -> GeneralLedger {
        self.book
            .general_ledger(&self.cx(), PRINCIPAL, &cap(&["read"]), &self.request())
            .unwrap()
            .unwrap()
    }
    fn definition(&self) -> CashFlowSplitDefinition {
        let ledger = self.ledger();
        CashFlowSplitDefinition {
            name: "Explicit split instruction v1".into(),
            cash_accounts: self.request().accounts.iter().map(|a| a.0).collect(),
            splits: ledger
                .lines()
                .iter()
                .map(|l| CashFlowLegSplit {
                    entry_digest: l.entry_digest,
                    leg_index: l.leg_index,
                    reason: "Explicit classification".into(),
                    portions: portions(&[(CashFlowActivity::Operating, l.debits.max(l.credits))]),
                })
                .collect(),
        }
    }
    fn read(&self, definition: &CashFlowSplitDefinition) -> SplitCashFlow {
        self.book
            .split_cash_flow(
                &self.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &self.request(),
                definition,
            )
            .unwrap()
            .unwrap()
    }
    fn loan(&mut self, k: i128) {
        use Side::{Credit as C, Debit as D};
        self.post(
            1,
            b"opening",
            self.usd,
            &[("1000", D, 500 * k), ("3000", C, 500 * k)],
        );
        self.post(
            10,
            b"loan-payment",
            self.usd,
            &[
                ("1000", C, 100 * k),
                ("2300", D, 93 * k),
                ("6100", D, 7 * k),
            ],
        );
    }
    fn loan_definition(&self, k: i128) -> CashFlowSplitDefinition {
        let mut definition = self.definition();
        definition.splits[0].reason = "Interest and principal per source loan payment".into();
        definition.splits[0].portions = portions(&[
            (CashFlowActivity::Financing, 93 * k),
            (CashFlowActivity::Operating, 7 * k),
        ]);
        definition
    }
}

#[test]
fn one_original_loan_payment_is_split_without_inventing_or_rewriting_journal_legs() {
    let mut h = Harness::new();
    h.loan(1);
    let before = h.head();
    let ledger = h.ledger().canonical_bytes().unwrap();
    let report = h.read(&h.loan_definition(1));
    let usd = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (
            usd.opening,
            usd.operating.outflows,
            usd.financing.outflows,
            usd.net_change,
            usd.closing
        ),
        (500, 7, 93, -100, 400)
    );
    assert_eq!((usd.operating.inflows, usd.financing.inflows), (0, 0));
    assert_eq!(report.source().lines().len(), 1);
    assert_eq!(report.source().canonical_bytes().unwrap(), ledger);
    assert_eq!(report.definition().splits[0].portions.len(), 2);
    assert_eq!(h.head(), before);
}

#[test]
fn partial_internal_transfer_preserves_external_cash_and_zero_cells() {
    use CashFlowActivity::{Financing as F, InternalTransfer as T, Operating as O};
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(
        10,
        b"compound",
        h.usd,
        &[
            ("1000", D, 150),
            ("1010", C, 50),
            ("4000", C, 60),
            ("2300", C, 40),
        ],
    );
    let ledger = h.ledger();
    let mut definition = h.definition();
    for (line, split) in ledger.lines().iter().zip(&mut definition.splits) {
        split.portions = if line.debits > 0 {
            portions(&[(T, 50), (O, 60), (F, 40)])
        } else {
            portions(&[(T, 50)])
        };
    }
    let report = h.read(&definition);
    let usd = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (
            usd.operating.inflows,
            usd.financing.inflows,
            usd.net_change,
            usd.closing
        ),
        (60, 40, 100, 100)
    );
    assert_eq!(report.source().lines().len(), 2);
    assert_eq!(report.source().cells().len(), 4);
    let zero = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.jpy.0)
        .unwrap();
    assert_eq!((zero.opening, zero.net_change, zero.closing), (0, 0, 0));
}

#[test]
fn under_over_and_overflowing_partitions_refuse_without_any_book_change() {
    use CashFlowActivity::{Financing as F, Operating as O};
    let mut h = Harness::new();
    h.loan(1);
    let before = h.head();
    for parts in [
        vec![(O, 7), (F, 92)],
        vec![(O, 8), (F, 93)],
        vec![(O, i128::MAX), (F, 1)],
    ] {
        let mut bad = h.loan_definition(1);
        bad.splits[0].portions = portions(&parts);
        let refusal = h
            .book
            .split_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request(), &bad)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, 2);
        assert_eq!(h.head(), before);
    }
}

#[test]
fn missing_even_cancelling_legs_foreign_citations_and_duplicate_splits_refuse() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(
        10,
        b"cancelling",
        h.usd,
        &[("1000", D, 50), ("1010", C, 50)],
    );
    let original = h.definition();
    let mut missing = original.clone();
    missing.splits.clear();
    let mut foreign = original.clone();
    foreign.splits[0].entry_digest = [255; 32];
    let mut duplicate = original;
    duplicate.splits[1] = duplicate.splits[0].clone();
    for bad in [missing, foreign, duplicate] {
        assert!(
            h.book
                .split_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request(), &bad)
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn internal_portions_cannot_net_across_entries_units_or_one_account() {
    use Side::{Credit as C, Debit as D};
    for (other_entry, other_unit) in [(false, false), (true, false), (true, true)] {
        let mut h = Harness::new();
        if !other_entry {
            h.post(
                10,
                b"same-account",
                h.usd,
                &[("1000", D, 50), ("1000", C, 50)],
            );
        } else {
            h.post(10, b"incoming", h.usd, &[("1000", D, 50), ("3000", C, 50)]);
            h.post(
                11,
                b"outgoing",
                if other_unit { h.jpy } else { h.usd },
                &[("1010", C, 50), ("3000", D, 50)],
            );
        }
        let mut definition = h.definition();
        for split in &mut definition.splits {
            split.portions[0].activity = CashFlowActivity::InternalTransfer;
        }
        assert!(
            h.book
                .split_cash_flow(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &h.request(),
                    &definition
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn partial_transfer_imbalance_cannot_be_hidden_by_other_cash_sections() {
    use CashFlowActivity::{InternalTransfer as T, Operating as O};
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(
        10,
        b"transfer",
        h.usd,
        &[("1000", D, 100), ("1010", C, 100)],
    );
    let mut definition = h.definition();
    definition.splits[0].portions = portions(&[(T, 70), (O, 30)]);
    definition.splits[1].portions = portions(&[(T, 60), (O, 40)]);
    assert!(
        h.book
            .split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &h.request(),
                &definition
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn refunds_and_large_exact_amounts_keep_gross_directions_and_currency_isolation() {
    use CashFlowActivity::{Financing as F, Operating as O};
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    let k = (1i128 << 100) + 17;
    h.loan(k);
    h.post(
        11,
        b"refund",
        h.usd,
        &[
            ("1000", D, 100 * k),
            ("2300", C, 93 * k),
            ("6100", C, 7 * k),
        ],
    );
    h.post(
        12,
        b"yen-payment",
        h.jpy,
        &[("1000", C, 100), ("2300", D, 80), ("6100", D, 20)],
    );
    let ledger = h.ledger();
    let mut definition = h.definition();
    for (line, split) in ledger.lines().iter().zip(&mut definition.splits) {
        split.portions = if ledger.cells()[line.cell_index as usize].unit_id == h.usd.0 {
            portions(&[(O, 7 * k), (F, 93 * k)])
        } else {
            portions(&[(O, 20), (F, 80)])
        };
    }
    let report = h.read(&definition);
    let usd = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (
            usd.operating.inflows,
            usd.operating.outflows,
            usd.operating.net
        ),
        (7 * k, 7 * k, 0)
    );
    assert_eq!(
        (
            usd.financing.inflows,
            usd.financing.outflows,
            usd.net_change
        ),
        (93 * k, 93 * k, 0)
    );
    let yen = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.jpy.0)
        .unwrap();
    assert_eq!(
        (yen.operating.outflows, yen.financing.outflows, yen.closing),
        (20, 80, -100)
    );
}

#[test]
fn whole_leg_splits_agree_with_the_existing_cash_engine() {
    let mut h = Harness::new();
    h.loan(1);
    let definition = h.definition();
    let old = CashFlowDefinition {
        name: definition.name.clone(),
        cash_accounts: definition.cash_accounts.clone(),
        assignments: definition
            .splits
            .iter()
            .map(|s| CashFlowAssignment {
                entry_digest: s.entry_digest,
                leg_index: s.leg_index,
                activity: s.portions[0].activity,
            })
            .collect(),
    };
    let report = h.read(&definition);
    let prior = h
        .book
        .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request(), &old)
        .unwrap()
        .unwrap();
    assert_eq!(report.units(), prior.units());
    assert_eq!(report.source(), prior.source());
}

#[test]
fn permutations_normalize_but_changed_portions_and_reasons_change_the_output() {
    let mut h = Harness::new();
    h.loan(1);
    let mut definition = h.loan_definition(1);
    let original = h.read(&definition).canonical_bytes().unwrap();
    definition.cash_accounts.reverse();
    definition.splits.reverse();
    definition.splits[0].portions.reverse();
    assert_eq!(h.read(&definition).canonical_bytes().unwrap(), original);
    definition.splits[0].reason.push('!');
    assert_ne!(h.read(&definition).canonical_bytes().unwrap(), original);
    definition.splits[0].portions = portions(&[
        (CashFlowActivity::Operating, 8),
        (CashFlowActivity::Financing, 92),
    ]);
    let changed = h.read(&definition);
    assert_ne!(changed.canonical_bytes().unwrap(), original);
    assert_eq!(
        changed
            .units()
            .iter()
            .find(|u| u.unit_id == h.usd.0)
            .unwrap()
            .net_change,
        -100
    );
}

#[test]
fn historical_cutoffs_are_fixed_and_new_activity_requires_new_splits() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.loan(1);
    let request = h.request();
    let definition = h.loan_definition(1);
    let original = h.read(&definition);
    h.post(12, b"backdated", h.usd, &[("1000", D, 5), ("4000", C, 5)]);
    let replay = h
        .book
        .split_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &definition)
        .unwrap()
        .unwrap();
    assert_eq!(replay, original);
    assert!(
        h.book
            .split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &h.request(),
                &definition
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn empty_interval_preserves_opening_stock_and_requires_current_read_authority() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(1, b"opening", h.usd, &[("1000", D, 100), ("3000", C, 100)]);
    let definition = h.definition();
    let report = h.read(&definition);
    assert!(report.source().lines().is_empty());
    let usd = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.usd.0)
        .unwrap();
    assert_eq!((usd.opening, usd.closing), (100, 100));
    for (actor, capability) in [(PRINCIPAL, cap(&["post"])), (VId(99), cap(&["read"]))] {
        assert!(
            h.book
                .split_cash_flow(&h.cx(), actor, &capability, &h.request(), &definition)
                .unwrap()
                .is_err()
        );
    }
    let mut wrong = definition;
    wrong.cash_accounts.pop();
    assert!(
        h.book
            .split_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request(), &wrong)
            .unwrap()
            .is_err()
    );
}

#[test]
fn transfers_cannot_cancel_between_currencies_even_inside_the_same_original_entry() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    let legs = [
        ("1000", D, h.usd),
        ("3000", C, h.usd),
        ("1010", C, h.jpy),
        ("3000", D, h.jpy),
    ]
    .into_iter()
    .map(|(code, side, unit)| LegPayload::simple(side, h.id(code), Amount::new(unit, 50)))
    .collect();
    h.post_legs(10, b"two-currencies", legs);
    let mut definition = h.definition();
    assert_eq!(definition.splits.len(), 2);
    assert_eq!(
        definition.splits[0].entry_digest,
        definition.splits[1].entry_digest
    );
    for split in &mut definition.splits {
        split.portions[0].activity = CashFlowActivity::InternalTransfer;
    }
    assert!(
        h.book
            .split_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &h.request(),
                &definition
            )
            .unwrap()
            .is_err()
    );
}

#[path = "cash_flow_split/certificates.rs"]
mod certificates;
