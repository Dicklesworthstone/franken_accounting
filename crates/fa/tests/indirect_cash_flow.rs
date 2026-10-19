//! Literal native journal scenarios for the earnings-to-cash bridge.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::general_ledger::{CashFlowActivity, CashFlowAssignment, CashFlowDefinition};
use fa::indirect_cash_flow::{
    AdjustmentCategory, AdjustmentSign, IndirectCashFlowAdjustment, IndirectCashFlowDefinition,
    IndirectCashFlowRequest,
};
use fa::{AsyncBook, BookKeys, Capability, Entropy, RollForwardRequest};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};
use std::path::Path;

const PRINCIPAL: VId = VId(1);
fn day(n: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, n).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
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
        let book_id = Id128([124; 16]);
        let spec = BookSpec {
            book_id,
            name: "Indirect cash source".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("indirect-cash", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                Path::new("indirect-cash-book"),
                BookKeys::for_development(124),
                spec,
                Entropy::deterministic(124),
            ))
            .unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET),
            ("1200", AccountType::ASSET),
            ("1500", AccountType::ASSET),
            ("1590", AccountType::ASSET),
            ("2000", AccountType::LIABILITY),
            ("3000", AccountType::EQUITY),
            ("4000", AccountType::REVENUE),
            ("4100", AccountType::REVENUE),
            ("6000", AccountType::EXPENSE),
            ("6100", AccountType::EXPENSE),
        ]
        .into_iter()
        .map(|(code, kind)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(
                [
                    AccountType::LIABILITY,
                    AccountType::EQUITY,
                    AccountType::REVENUE,
                ]
                .contains(&kind),
            ),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
        runtime
            .block_on(book.install_chart(
                &cx,
                &accounts,
                PRINCIPAL,
                day(1),
                b"indirect-chart",
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.create_periods(
                &cx,
                2026,
                fgdb_types::VId(1),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P01",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day(1),
                b"indirect-open",
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
            bytes: b"Private source documents for indirect cash".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
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
    fn post(&mut self, date: u8, key: &[u8], unit: UnitId, parts: &[(&str, Side, i128)]) {
        let cx = self.cx();
        let legs: Vec<_> = parts
            .iter()
            .map(|(code, side, amount)| {
                LegPayload::simple(*side, self.id(code), Amount::new(unit, *amount))
            })
            .collect();
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self
                .book
                .seal_text(&cx, "Private indirect-cash narrative")
                .unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([58; 32]),
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
    fn scenario(&mut self, k: i128) {
        use Side::{Credit as C, Debit as D};
        self.post(
            1,
            b"capital",
            self.usd,
            &[("1000", D, 100 * k), ("3000", C, 100 * k)],
        );
        self.post(
            2,
            b"equipment",
            self.usd,
            &[("1500", D, 60 * k), ("1000", C, 60 * k)],
        );
        self.post(
            3,
            b"credit-sale",
            self.usd,
            &[("1200", D, 80 * k), ("4000", C, 80 * k)],
        );
        self.post(
            4,
            b"receipt",
            self.usd,
            &[("1000", D, 50 * k), ("1200", C, 50 * k)],
        );
        self.post(
            5,
            b"payroll",
            self.usd,
            &[("6000", D, 20 * k), ("1000", C, 20 * k)],
        );
        self.post(
            6,
            b"depreciation",
            self.usd,
            &[("6100", D, 10 * k), ("1590", C, 10 * k)],
        );
        self.post(
            7,
            b"asset-disposal",
            self.usd,
            &[
                ("1000", D, 70 * k),
                ("1590", D, 10 * k),
                ("1500", C, 60 * k),
                ("4100", C, 20 * k),
            ],
        );
    }
    fn cash_request(&self) -> RollForwardRequest {
        RollForwardRequest {
            accounts: vec![self.id("1000")],
            units: vec![self.usd.0, self.jpy.0],
            label: "January earnings-to-cash".into(),
            effective_from: day(1),
            effective_through: day(31),
            known_at: Some(self.head()),
        }
    }
    fn adjustment(
        &self,
        date: u8,
        code: &str,
        category: AdjustmentCategory,
        sign: AdjustmentSign,
    ) -> IndirectCashFlowAdjustment {
        let request = RollForwardRequest {
            accounts: vec![self.id(code)],
            ..self.cash_request()
        };
        let detail = self
            .book
            .general_ledger(&self.cx(), PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .unwrap();
        let line = detail
            .lines()
            .iter()
            .find(|l| l.effective_day == day(date))
            .unwrap();
        IndirectCashFlowAdjustment {
            entry_digest: line.entry_digest,
            leg_index: line.leg_index,
            category,
            sign,
            reason: format!("explicit-{code}-{date}"),
        }
    }
    fn request(&self) -> IndirectCashFlowRequest {
        let cash = self.cash_request();
        let ledger = self
            .book
            .general_ledger(&self.cx(), PRINCIPAL, &cap(&["read"]), &cash)
            .unwrap()
            .unwrap();
        let cash_definition = CashFlowDefinition {
            name: "Cash classification v1".into(),
            cash_accounts: cash.accounts.iter().map(|a| a.0).collect(),
            assignments: ledger
                .lines()
                .iter()
                .map(|line| CashFlowAssignment {
                    entry_digest: line.entry_digest,
                    leg_index: line.leg_index,
                    activity: if line.effective_day == day(1) {
                        CashFlowActivity::Financing
                    } else if [day(2), day(7)].contains(&line.effective_day) {
                        CashFlowActivity::Investing
                    } else {
                        CashFlowActivity::Operating
                    },
                })
                .collect(),
        };
        let definition = IndirectCashFlowDefinition {
            name: "Indirect policy v1".into(),
            adjustments: vec![
                self.adjustment(
                    6,
                    "6100",
                    AdjustmentCategory::NonCash,
                    AdjustmentSign::DebitMinusCredit,
                ),
                self.adjustment(
                    3,
                    "1200",
                    AdjustmentCategory::WorkingCapital,
                    AdjustmentSign::CreditMinusDebit,
                ),
                self.adjustment(
                    4,
                    "1200",
                    AdjustmentCategory::WorkingCapital,
                    AdjustmentSign::CreditMinusDebit,
                ),
                self.adjustment(
                    7,
                    "4100",
                    AdjustmentCategory::NonOperating,
                    AdjustmentSign::DebitMinusCredit,
                ),
            ],
        };
        IndirectCashFlowRequest {
            cash,
            cash_definition,
            income_periods: vec!["FY2026-OPEN".into(), "FY2026-P01".into()],
            definition,
        }
    }
}

#[test]
fn earnings_depreciation_receivables_and_disposal_gain_reconcile_to_direct_cash() {
    let mut h = Harness::new();
    h.scenario(1);
    let before = h.head();
    let report = h
        .book
        .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &h.request())
        .unwrap()
        .unwrap();
    let usd = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (
            usd.net_income,
            usd.non_cash,
            usd.working_capital,
            usd.non_operating
        ),
        (70, 10, -30, -20)
    );
    assert_eq!(
        (usd.operating, usd.direct_operating, usd.operating_residual),
        (30, 30, 0)
    );
    assert_eq!(
        (
            usd.opening,
            usd.investing,
            usd.financing,
            usd.net_change,
            usd.closing
        ),
        (0, 10, 100, 140, 140)
    );
    assert_eq!(report.contributions().len(), 4);
    let jpy = report
        .units()
        .iter()
        .find(|u| u.unit_id == h.jpy.0)
        .unwrap();
    assert_eq!((jpy.net_income, jpy.operating, jpy.closing), (0, 0, 0));
    assert!(
        report
            .non_cash_source()
            .unwrap()
            .accounts()
            .iter()
            .all(|a| a.id != h.id("1000").0)
    );
    assert_eq!(h.head(), before);
}

#[test]
fn large_integer_amounts_and_permutations_preserve_exact_canonical_bytes() {
    let mut h = Harness::new();
    let k = (1i128 << 80) + 17;
    h.scenario(k);
    let mut request = h.request();
    let original = h
        .book
        .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
        .unwrap()
        .unwrap();
    assert_eq!(
        original
            .units()
            .iter()
            .find(|u| u.unit_id == h.usd.0)
            .unwrap()
            .operating,
        30 * k
    );
    request.cash.units.reverse();
    request.cash_definition.assignments.reverse();
    request.definition.adjustments.reverse();
    let permuted = h
        .book
        .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
        .unwrap()
        .unwrap();
    assert_eq!(
        original.canonical_bytes().unwrap(),
        permuted.canonical_bytes().unwrap()
    );
}

#[test]
fn wrong_sign_missing_adjustment_invented_leg_and_cash_leg_all_refuse() {
    let mut h = Harness::new();
    h.scenario(1);
    let original = h.request();
    let mut wrong = original.clone();
    wrong.definition.adjustments[0].sign = AdjustmentSign::CreditMinusDebit;
    let mut missing = original.clone();
    missing.definition.adjustments.pop();
    let mut invented = original.clone();
    invented.definition.adjustments[0].entry_digest = [0; 32];
    let mut cash = original.clone();
    cash.definition.adjustments[0].entry_digest = cash.cash_definition.assignments[0].entry_digest;
    cash.definition.adjustments[0].leg_index = cash.cash_definition.assignments[0].leg_index;
    let mut duplicate = original.clone();
    duplicate
        .definition
        .adjustments
        .push(duplicate.definition.adjustments[0].clone());
    let mut wrong_type = original;
    wrong_type.definition.adjustments[0].category = AdjustmentCategory::WorkingCapital;
    for request in [wrong, missing, invented, cash, duplicate, wrong_type] {
        assert!(
            h.book
                .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn native_period_coverage_refuses_partial_extra_missing_and_repeated_periods() {
    let mut h = Harness::new();
    h.scenario(1);
    let original = h.request();
    let mut partial = original.clone();
    partial.cash.effective_through = day(30);
    let mut extra = original.clone();
    extra.income_periods.push("FY2026-P02".into());
    let mut missing = original.clone();
    missing.income_periods.clear();
    let mut repeated = original;
    repeated.income_periods.push("FY2026-P01".into());
    for request in [partial, extra, missing, repeated] {
        assert!(
            h.book
                .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn backdated_non_cash_activity_cannot_silently_refresh_the_old_bridge() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.scenario(1);
    let pinned = h.request();
    let original = h
        .book
        .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &pinned)
        .unwrap()
        .unwrap();
    h.post(
        8,
        b"extra-depreciation",
        h.usd,
        &[("6100", D, 1), ("1590", C, 1)],
    );
    let old = h
        .book
        .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &pinned)
        .unwrap()
        .unwrap();
    assert_eq!(
        old.canonical_bytes().unwrap(),
        original.canonical_bytes().unwrap()
    );
    let mut current = pinned;
    current.cash.known_at = None;
    assert!(
        h.book
            .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &current)
            .unwrap()
            .is_err()
    );
}

#[test]
fn opposing_currency_residuals_do_not_cancel_and_current_authority_is_required() {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.scenario(1);
    let mut request = h.request();
    for (principal, capability) in [(VId(2), cap(&["read"])), (PRINCIPAL, cap(&["post"]))] {
        assert!(
            h.book
                .indirect_cash_flow(&h.cx(), principal, &capability, &request)
                .unwrap()
                .is_err()
        );
    }
    h.post(
        8,
        b"usd-expense",
        h.usd,
        &[("6100", D, 10), ("1590", C, 10)],
    );
    h.post(
        9,
        b"jpy-accrual",
        h.jpy,
        &[("1200", D, 10), ("4000", C, 10)],
    );
    request.cash.known_at = None;
    assert!(
        h.book
            .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
}

#[path = "indirect_cash_flow/certificates.rs"]
mod certificates;
