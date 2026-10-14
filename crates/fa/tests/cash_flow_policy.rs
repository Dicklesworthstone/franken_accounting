//! Real postings exercise policy selection; arithmetic expectations are literal.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::cash_flow_policy::{
    CashFlowAccountRule, CashFlowDecisionBasis, CashFlowPolicy, PolicyCashFlow,
};
use fa::general_ledger::{CashFlowActivity, CashFlowAssignment};
use fa::{AsyncBook, BookKeys, Capability, Entropy, GeneralLedger, RollForwardRequest};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::{CommitSeq, VId, context::PurposeContexts};

const PRINCIPAL: VId = VId(1);
fn day(d: u8) -> DateDay { DateDay::from_ymd(2026, 1, d).unwrap() }
fn cap(ops: &[&str]) -> Capability { Capability::embedded(PRINCIPAL, ops).unwrap() }

struct Harness {
    runtime: Runtime,
    root: Cx,
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
        let book_id = Id128([127; 16]);
        let spec = BookSpec { book_id, name: "Cash policy native tests".into(), base_unit: usd,
            calendar: FiscalCalendar::monthly("cash-policy", 1, 1).unwrap(),
            time_zone_policy: None, entities: Vec::new(), opening_date: None };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime.block_on(AsyncBook::create_with_vfs(&cx, vfs,
            Path::new("cash-policy-book"), BookKeys::for_development(127), spec,
            Entropy::deterministic(127))).unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET), ("1010", AccountType::ASSET), ("1200", AccountType::ASSET),
            ("1500", AccountType::ASSET), ("2000", AccountType::LIABILITY),
            ("2300", AccountType::LIABILITY), ("3000", AccountType::EQUITY),
            ("4000", AccountType::REVENUE), ("6100", AccountType::EXPENSE),
        ].into_iter().map(|(code, kind)| AccountSpec { code: code.into(), name: code.into(),
            account_type: kind.0, normal_balance: u8::from([2, 3, 4].contains(&kind.0)), is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency, parent_code: None, limit: None }).collect();
        runtime.block_on(book.install_chart(&cx, &accounts, PRINCIPAL, day(1), b"policy-chart")).unwrap().unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
        runtime.block_on(book.transition_period(&cx, "FY2026-P01", PeriodTransition::Open,
            PRINCIPAL, 1, day(1), b"policy-open", &cap(&["close"]))).unwrap().unwrap();
        let doc = Document { book_id, kind: 1, mime: "text/plain".into(), grade: 3,
            retrieved_by: PRINCIPAL, bytes: b"Confidential policy test evidence".to_vec() };
        runtime.block_on(book.add_document(&cx, &doc)).unwrap().unwrap();
        Self { runtime, root, book, usd, jpy, evidence: vec![doc.evidence_ref(1)] }
    }
    fn cx(&self) -> PurposeContexts { PurposeContexts::narrow_runtime_root(&self.root) }
    fn id(&self, code: &str) -> VId { account_vid(self.book.context().book_id, code) }
    fn head(&self) -> CommitSeq { self.book.head(&self.cx()).unwrap() }
    fn request(&self) -> RollForwardRequest {
        RollForwardRequest { accounts: vec![self.id("1000"), self.id("1010")],
            units: vec![self.usd.0, self.jpy.0], label: "January cash policy".into(),
            effective_from: day(1), effective_through: day(31), known_at: Some(self.head()) }
    }
    fn policy(&self) -> CashFlowPolicy {
        use CashFlowActivity::{Operating, Investing, Financing};
        CashFlowPolicy { name: "Explicit account policy v1".into(),
            cash_accounts: vec![self.id("1010").0, self.id("1000").0],
            account_rules: [("1200", Operating), ("1500", Investing), ("2000", Operating),
                ("2300", Financing), ("3000", Financing), ("4000", Operating), ("6100", Operating)]
                .into_iter().map(|(code, activity)| CashFlowAccountRule { account_id: self.id(code).0, activity }).collect(),
            overrides: Vec::new() }
    }
    fn post(&mut self, date: u8, key: &[u8], unit: UnitId, rows: &[(&str, Side, i128)]) {
        let legs = rows.iter().map(|(code, side, amount)| LegPayload::simple(*side, self.id(code), Amount::new(unit, *amount))).collect();
        self.post_legs(date, key, legs);
    }
    fn post_legs(&mut self, date: u8, key: &[u8], legs: Vec<LegPayload>) {
        let cx = self.cx();
        let proposal = EntryPayload {
            schema_minor: 0, book_id: self.book.context().book_id, branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL, effective_date: day(date), document_date: None,
            description: self.book.seal_text(&cx, "Private cash policy posting").unwrap(),
            effective_period: None, unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs, control: None, base_totals: None, idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent { intent_oid: Oid([57; 32]), intent_kind: 1 },
            principal_ref: PRINCIPAL, session_ref: None, evidence: self.evidence.clone(),
            supersession: Vec::new(), pending: None, external_ids: Vec::new(), tags: Vec::new(), extensions: Vec::new(),
        };
        self.runtime.block_on(self.book.post(&cx, PostRequest { proposal, approvals: Vec::new(),
            plan_certificate: None, capability: cap(&["post"]) })).unwrap().unwrap();
    }
    fn ledger(&self) -> GeneralLedger {
        self.book.general_ledger(&self.cx(), PRINCIPAL, &cap(&["read"]), &self.request()).unwrap().unwrap()
    }
    fn read(&self) -> PolicyCashFlow {
        self.book.cash_flow_with_policy(&self.cx(), PRINCIPAL, &cap(&["read"]), &self.request(), &self.policy()).unwrap().unwrap()
    }
    fn scenario(&mut self, k: i128) {
        use Side::{Credit as C, Debit as D};
        self.post(1, b"funding", self.usd, &[("1000", D, 100*k), ("3000", C, 100*k)]);
        self.post(5, b"sale", self.usd, &[("1000", D, 40*k), ("4000", C, 40*k)]);
        self.post(7, b"payroll", self.usd, &[("6100", D, 15*k), ("1000", C, 15*k)]);
        self.post(10, b"asset", self.usd, &[("1500", D, 20*k), ("1000", C, 20*k)]);
        self.post(15, b"internal", self.usd, &[("1010", D, 10*k), ("1000", C, 10*k)]);
    }
}

#[test]
fn real_cash_entries_follow_explicit_rules_and_internal_transfers_without_manual_assignments() {
    let mut h = Harness::new(); h.scenario(1);
    let before = h.head(); let report = h.read();
    let usd = report.report().units().iter().find(|u| u.unit_id == h.usd.0).unwrap();
    assert_eq!((usd.operating.inflows, usd.operating.outflows, usd.operating.net), (40, 15, 25));
    assert_eq!((usd.investing.net, usd.financing.net, usd.net_change, usd.closing), (-20, 100, 105, 105));
    assert_eq!(report.decisions().len(), 6);
    assert_eq!(report.decisions().iter().filter(|d| d.basis == CashFlowDecisionBasis::InternalTransfer).count(), 2);
    assert_eq!(report.decisions().iter().filter(|d| d.basis == CashFlowDecisionBasis::AccountRules).count(), 4);
    assert!(report.report().source().cells().iter().filter(|c| c.unit_id == h.jpy.0).all(|c| c.closing == 0));
    assert_eq!(h.head(), before);
}

#[test]
fn mixed_counterparts_refuse_until_an_explicit_whole_cash_leg_decision_is_supplied() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(10, b"mixed", h.usd, &[("1000", D, 50), ("4000", C, 30), ("2300", C, 20)]);
    let request = h.request(); let mut policy = h.policy();
    assert!(h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &policy).unwrap().is_err());
    let ledger = h.ledger(); let cash = &ledger.lines()[0];
    policy.overrides.push(CashFlowAssignment { entry_digest: cash.entry_digest, leg_index: cash.leg_index, activity: CashFlowActivity::Financing });
    let report = h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &policy).unwrap().unwrap();
    assert_eq!(report.decisions()[0].basis, CashFlowDecisionBasis::ExplicitOverride);
    assert_eq!(report.report().units().iter().find(|u| u.unit_id == h.usd.0).unwrap().financing.inflows, 50);
    // The explicit choice is recorded, not an inferred 30/20 allocation.
    assert_eq!(report.report().definition().assignments.len(), 1);
}

#[test]
fn every_counterpart_must_be_mapped_even_when_the_others_agree() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(2, b"two-operating", h.usd, &[("1000", D, 50), ("4000", C, 30), ("2000", C, 20)]);
    assert_eq!(h.read().report().units().iter().find(|u| u.unit_id == h.usd.0).unwrap().operating.net, 50);
    let mut policy = h.policy(); policy.account_rules.retain(|r| r.account_id != h.id("2000").0);
    assert!(h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request(), &policy).unwrap().is_err());
}

#[test]
fn same_cash_account_roundtrip_is_not_inferred_to_be_an_internal_transfer() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new(); h.post(4, b"same-cash", h.usd, &[("1000", D, 7), ("1000", C, 7)]);
    let mut policy = h.policy(); let request = h.request();
    assert!(h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &policy).unwrap().is_err());
    policy.overrides = h.ledger().lines().iter().map(|l| CashFlowAssignment {
        entry_digest: l.entry_digest, leg_index: l.leg_index, activity: CashFlowActivity::Operating }).collect();
    let report = h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &policy).unwrap().unwrap();
    let usd = report.report().units().iter().find(|u| u.unit_id == h.usd.0).unwrap();
    assert_eq!((usd.operating.inflows, usd.operating.outflows, usd.operating.net), (7, 7, 0));
    assert_eq!(report.decisions().len(), 2);
}

#[test]
fn counterpart_classes_are_isolated_per_native_unit_inside_one_entry() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    let legs = [("1000", D, h.usd, 30), ("4000", C, h.usd, 30),
        ("1010", D, h.jpy, 70), ("2300", C, h.jpy, 70)].into_iter()
        .map(|(code, side, unit, n)| LegPayload::simple(side, h.id(code), Amount::new(unit, n))).collect();
    h.post_legs(8, b"two-units", legs);
    let report = h.read();
    let usd = report.report().units().iter().find(|u| u.unit_id == h.usd.0).unwrap();
    let jpy = report.report().units().iter().find(|u| u.unit_id == h.jpy.0).unwrap();
    assert_eq!((usd.operating.net, usd.financing.net), (30, 0));
    assert_eq!((jpy.operating.net, jpy.financing.net), (0, 70));
}

#[test]
fn policies_reuse_rules_for_new_activity_without_rewriting_historical_results() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new(); h.scenario((1i128 << 80) + 17);
    let request = h.request(); let mut policy = h.policy();
    let original = h.read().canonical_bytes().unwrap();
    policy.account_rules.reverse(); policy.cash_accounts.reverse();
    h.post(3, b"late-sale", h.usd, &[("1000", D, 11), ("4000", C, 11)]);
    let old = h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &policy).unwrap().unwrap();
    assert_eq!(old.canonical_bytes().unwrap(), original);
    let current = h.read();
    assert_eq!(current.decisions().len(), old.decisions().len() + 1);
    assert_eq!(current.report().units().iter().find(|u| u.unit_id == h.usd.0).unwrap().closing,
        105 * ((1i128 << 80) + 17) + 11);
}

#[test]
fn unused_unknown_rules_foreign_overrides_and_mismatched_cash_scope_are_refused() {
    let h = Harness::new(); let request = h.request(); let original = h.policy();
    assert!(h.read().decisions().is_empty());
    let mut bad = original.clone(); bad.account_rules.push(CashFlowAccountRule { account_id: u128::MAX, activity: CashFlowActivity::Operating });
    assert!(h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &bad).unwrap().is_err());
    let mut bad = original.clone(); bad.overrides.push(CashFlowAssignment { entry_digest: [9; 32], leg_index: 0, activity: CashFlowActivity::Operating });
    assert!(h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &bad).unwrap().is_err());
    let mut bad = original; bad.cash_accounts.pop();
    assert!(h.book.cash_flow_with_policy(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &bad).unwrap().is_err());
}

#[test]
fn current_read_authority_is_required_and_mixed_cash_movements_are_not_netted_to_transfers() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new(); h.post(3, b"cash-and-revenue", h.usd, &[("1010", D, 100), ("1000", C, 80), ("4000", C, 20)]);
    let request = h.request(); let policy = h.policy(); let before = h.head();
    for (principal, capability) in [(PRINCIPAL, cap(&["post"])), (VId(99), cap(&["read"]))] {
        assert!(h.book.cash_flow_with_policy(&h.cx(), principal, &capability, &request, &policy).unwrap().is_err());
    }
    let report = h.read();
    assert!(report.decisions().iter().all(|d| d.basis == CashFlowDecisionBasis::AccountRules));
    let usd = report.report().units().iter().find(|u| u.unit_id == h.usd.0).unwrap();
    assert_eq!((usd.operating.inflows, usd.operating.outflows, usd.operating.net), (100, 80, 20));
    assert_eq!(h.head(), before);
}
