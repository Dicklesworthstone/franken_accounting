//! Real-book tests: a group is one production-kernel entry, not N payments.

use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{EntryRef, EvidenceRef, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;

use crate::{BookKeys, Entropy};

const BOOK: Id128 = Id128([0x76; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "settlement-group";
fn day(text: &str) -> DateDay { DateDay::parse(text).unwrap() }
fn account(code: &str) -> VId { account_vid(BOOK, code) }
fn cap() -> Capability { Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap() }
fn leg(side: Side, code: &str, unit: UnitId, amount: i128) -> LegPayload {
    LegPayload::simple(side, account(code), Amount::new(unit, amount))
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    evidence: EvidenceRef,
    usd: UnitId,
    eur: UnitId,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let vfs = MemVfs::new().unwrap();
        let mut book = runtime.block_on(AsyncBook::create_with_vfs(
            &cx, vfs.clone(), Path::new(PATH), BookKeys::for_development(118),
            BookSpec {
                book_id: BOOK, name: "Atomic settlement group fixture".into(), base_unit: usd,
                calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                time_zone_policy: None, entities: Vec::new(), opening_date: None,
            }, Entropy::deterministic(118),
        )).unwrap();
        let chart = ["cash", "receivable", "payable", "capital"].into_iter().map(|code| AccountSpec {
            code: code.into(), name: code.into(),
            account_type: match code { "payable" => 2, "capital" => 3, _ => 1 },
            normal_balance: u8::from(matches!(code, "payable" | "capital")), is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency, parent_code: None, limit: None,
        }).collect::<Vec<_>>();
        runtime.block_on(book.install_chart(&cx, &chart, PRINCIPAL, day("2026-03-01"), b"chart"))
            .unwrap().unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
        runtime.block_on(book.transition_period(
            &cx, "FY2026-P03", PeriodTransition::Open, PRINCIPAL, 1, day("2026-03-01"),
            b"open", &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        )).unwrap().unwrap();
        let document = Document {
            book_id: BOOK, kind: 1, mime: "text/plain".into(), grade: 3,
            retrieved_by: PRINCIPAL, bytes: b"evidence for atomic settlement groups".to_vec(),
        };
        runtime.block_on(book.add_document(&cx, &document)).unwrap().unwrap();
        Self { runtime, root, book, vfs, evidence: document.evidence_ref(1), usd, eur }
    }

    fn cx(&self) -> PurposeContexts { PurposeContexts::narrow_runtime_root(&self.root) }
    fn head(&self) -> CommitSeq { self.book.head(&self.cx()).unwrap() }

    fn proposal(&self, key: &str, legs: Vec<LegPayload>) -> EntryPayload {
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR, book_id: BOOK,
            branch_id: Id128::TRUNK, class: EntryClass::ORIGINAL,
            effective_date: day("2026-03-20"), document_date: None,
            description: self.book.seal_text(&self.cx(), key).unwrap(), effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(), legs,
            control: None, base_totals: None, idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent { intent_oid: Oid([1; 32]), intent_kind: 1 },
            principal_ref: PRINCIPAL, session_ref: None, evidence: vec![self.evidence],
            supersession: Vec::new(), pending: None, external_ids: Vec::new(),
            extensions: Vec::new(), tags: Vec::new(),
        }
    }

    fn post(&mut self, proposal: EntryPayload) -> EntryRef {
        let cx = self.cx();
        self.runtime.block_on(self.book.post(&cx, PostRequest {
            proposal, approvals: Vec::new(), plan_certificate: None, capability: cap(),
        })).unwrap().unwrap().entry_ref()
    }

    fn invoice(&mut self, key: &str, amount: i128) -> EntryRef {
        self.post(self.proposal(key, vec![
            leg(Side::Debit, "receivable", self.usd, amount),
            leg(Side::Credit, "capital", self.usd, amount),
        ]))
    }

    fn prepare(&self, request: SettlementGroupRequest) -> PreparedSettlementGroup {
        self.book.prepare_settlement_group(&self.cx(), request, &cap()).unwrap().unwrap()
    }

    fn plan(&mut self, request: SettlementGroupRequest) -> SettlementGroupPostPlan {
        let cx = self.cx();
        self.book.plan_settlement_group(&cx, request, Vec::new(), &cap()).unwrap().unwrap()
    }

    fn commit(&mut self, plan: SettlementGroupPostPlan) -> Posted {
        let cx = self.cx();
        self.runtime.block_on(self.book.commit_settlement_group_plan(&cx, plan, &cap()))
            .unwrap().unwrap()
    }

    fn open(&self, entry: EntryRef, ordinal: u16) -> i128 {
        self.book.open_items(&self.cx(), None, None).unwrap().into_iter()
            .find(|item| item.entry == entry.vid && item.ordinal == ordinal).unwrap().open
    }

    fn consume(&mut self, invoice: EntryRef, amount: i128) {
        let request = SettlementPostRequest {
            proposal: self.proposal("competing-receipt", vec![
                leg(Side::Debit, "cash", self.usd, amount),
                leg(Side::Credit, "receivable", self.usd, amount),
            ]), payment_leg: 1, targets: vec![(invoice.vid, 0)],
        };
        let cx = self.cx();
        let plan = self.book.plan_settlement(&cx, request, Vec::new(), &cap()).unwrap().unwrap();
        self.runtime.block_on(self.book.commit_settlement_plan(&cx, plan, &cap())).unwrap().unwrap();
    }

    fn reopen(self) -> Self {
        let Self { runtime, root, book, vfs, evidence, usd, eur } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime.block_on(AsyncBook::open_with_vfs(
            &cx, vfs.clone(), Path::new(PATH), BookKeys::for_development(118),
            Entropy::deterministic(119),
        )).unwrap();
        Self { runtime, root, book, vfs, evidence, usd, eur }
    }
}

fn fixture() -> (Harness, EntryRef, EntryRef, SettlementGroupRequest) {
    let mut h = Harness::new();
    let invoice = h.invoice("usd-invoice", 100);
    let bill = h.post(h.proposal("eur-bill", vec![
        leg(Side::Debit, "cash", h.eur, 70), leg(Side::Credit, "payable", h.eur, 70),
    ]));
    let request = SettlementGroupRequest {
        proposal: h.proposal("group-payment", vec![
            leg(Side::Debit, "cash", h.usd, 125), leg(Side::Credit, "receivable", h.usd, 125),
            leg(Side::Debit, "payable", h.eur, 60), leg(Side::Credit, "cash", h.eur, 60),
        ]),
        payments: vec![
            SettlementLegSelection { payment_leg: 2, targets: vec![(bill.vid, 1)] },
            SettlementLegSelection { payment_leg: 1, targets: vec![(invoice.vid, 0)] },
        ],
    };
    (h, invoice, bill, request)
}

#[test]
fn mixed_native_units_and_debit_credit_applications_publish_as_one_entry() {
    let (mut h, invoice, bill, request) = fixture();
    let at = h.head();
    let prepared = h.prepare(request.clone());
    let mut expected = request.proposal.clone();
    expected.legs[1].settles = vec![fa_model::Settlement {
        target: invoice, ordinal: 0, amount: Amount::new(h.usd, 100),
    }];
    expected.legs[2].settles = vec![fa_model::Settlement {
        target: bill, ordinal: 1, amount: Amount::new(h.eur, 60),
    }];
    assert_eq!(prepared.proposal(), &expected, "only the selected settles lists change");
    assert_eq!(prepared.known_at(), at);
    assert_eq!(prepared.allocations().iter().map(|a| a.payment_leg).collect::<Vec<_>>(), [1, 2]);
    assert!(prepared.allocations().iter().all(|a| a.allocation.known_at == at));
    assert_eq!(prepared.allocations()[0].allocation.unapplied, 25);
    assert_eq!(prepared.allocations()[1].allocation.unapplied, 0);
    let mut reordered = request.clone(); reordered.payments.reverse();
    assert_eq!(h.prepare(reordered), prepared, "selection order is not accounting order");
    let cx = h.cx();
    let plan = h.book.plan_prepared_settlement_group(&cx, prepared, Vec::new(), &cap()).unwrap().unwrap();
    assert_eq!(plan.post_plan().intent().proposal(), &expected);
    assert_eq!(h.head(), at, "preparation and rehearsal publish nothing");
    let posted = h.commit(plan);
    assert_eq!(posted.recorded_at(), CommitSeq(at.0 + 1));
    assert_eq!(h.open(invoice, 0), 0);
    assert_eq!(h.open(bill, 1), 10);
    assert_eq!(h.open(posted.entry_ref(), 1), 25);
    assert_eq!(h.open(posted.entry_ref(), 2), 0);
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

#[test]
fn portable_group_plan_retries_after_reopen_without_spending_again() {
    let (mut h, invoice, bill, request) = fixture();
    let plan = h.plan(request);
    let bytes = plan.post_plan().canonical_bytes().unwrap();
    let posted = h.commit(plan.clone());
    assert!(matches!(h.commit(plan), Posted::AlreadyRecorded { .. }));
    h.invoice("later", 9);
    let head = h.head();
    let mut h = h.reopen();
    let cx = h.cx();
    let retry = h.runtime.block_on(h.book.commit_plan(&cx, PostPlan::decode(&bytes).unwrap(), &cap()))
        .unwrap().unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.head(), head);
    assert_eq!(h.open(invoice, 0), 0);
    assert_eq!(h.open(bill, 1), 10);
}

#[test]
fn duplicate_applying_legs_and_overlapping_even_unused_targets_are_refused() {
    let (h, invoice, bill, base) = fixture();
    let mut cases = Vec::new();
    let mut duplicate = base.clone(); duplicate.payments.push(duplicate.payments[0].clone());
    cases.push(duplicate);
    let mut duplicate = base.clone(); duplicate.payments[0].targets.push((invoice.vid, 0));
    cases.push(duplicate);
    let mut duplicate = base.clone(); duplicate.payments[0].targets.push((bill.vid, 1));
    cases.push(duplicate);
    let mut empty = base.clone(); empty.payments.clear(); cases.push(empty);
    let mut too_many = base.clone();
    too_many.payments = vec![too_many.payments[0].clone(); MAX_SETTLEMENT_GROUP_LEGS + 1];
    cases.push(too_many);
    let mut too_many = base.clone();
    too_many.payments = (0..5).map(|_| SettlementLegSelection {
        payment_leg: 1, targets: vec![(invoice.vid, 0); MAX_SETTLES_PER_LEG],
    }).collect();
    cases.push(too_many);
    let mut bad_ordinal = base; bad_ordinal.payments[0].payment_leg = u16::MAX; cases.push(bad_ordinal);
    let at = h.head();
    for request in cases {
        let refusal = h.book.prepare_settlement_group(&h.cx(), request, &cap()).unwrap().unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE);
        assert_eq!(h.head(), at);
    }
    assert_eq!(h.open(invoice, 0), 100);
    assert_eq!(h.open(bill, 1), 70);
}

#[test]
fn invalid_later_selection_returns_no_partial_payment() {
    let (h, invoice, bill, base) = fixture();
    let at = h.head();
    // Canonical order prepares the invoice first, then encounters the bad bill.
    let mut missing = base.clone(); missing.payments[0].targets.push((VId(u128::MAX), 0));
    let mut dimensions = base.clone(); dimensions.proposal.legs[2].dimension_set = vec![(1, VId(99))];
    let mut overwritten = base;
    overwritten.proposal.legs[0].settles = vec![fa_model::Settlement {
        target: invoice, ordinal: 0, amount: Amount::new(h.usd, 1),
    }];
    for request in [missing, dimensions, overwritten] {
        assert!(h.book.prepare_settlement_group(&h.cx(), request, &cap()).unwrap().is_err());
        assert_eq!(h.head(), at);
        assert_eq!(h.open(invoice, 0), 100);
        assert_eq!(h.open(bill, 1), 70);
    }
}

#[test]
fn complete_entry_balance_and_evidence_laws_remain_kernel_enforced() {
    let (mut h, invoice, bill, base) = fixture();
    let mut balance = base.clone();
    balance.proposal.legs[3].amount.mantissa = 59;
    balance.proposal.unit_totals = EntryPayload::fold_unit_totals(&balance.proposal.legs).unwrap();
    let mut evidence = base; evidence.proposal.evidence.clear();
    let at = h.head(); let cx = h.cx();
    for (request, code) in [
        (balance, fa_journal::refusal::code::UNBALANCED),
        (evidence, fa_journal::refusal::code::EVIDENCE_MINIMUM),
    ] {
        let prepared = h.prepare(request);
        let refusal = h.book.plan_prepared_settlement_group(&cx, prepared, Vec::new(), &cap())
            .unwrap().unwrap_err();
        assert_eq!(refusal.code, code);
        assert_eq!(h.head(), at);
        assert_eq!(h.open(invoice, 0), 100);
        assert_eq!(h.open(bill, 1), 70);
    }
}

#[test]
fn authority_covers_the_whole_payment_and_is_rechecked_at_rehearsal() {
    let (mut h, _, _, base) = fixture();
    let prepared = h.prepare(base.clone());
    let at = h.head(); let cx = h.cx();
    let capabilities = [
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        cap().for_books(&[Id128([0x77; 16])]).unwrap(),
        cap().expiring_at(at),
        cap().with_ceiling(h.usd, 100).unwrap().with_ceiling(h.eur, 100).unwrap(),
    ];
    for capability in capabilities {
        assert!(h.book.prepare_settlement_group(&cx, base.clone(), &capability).unwrap().is_err());
        assert!(h.book.plan_prepared_settlement_group(&cx, prepared.clone(), Vec::new(), &capability)
            .unwrap().is_err());
        assert_eq!(h.head(), at);
    }
    let mut bad = base; bad.payments.clear();
    let denial = h.book.prepare_settlement_group(&cx, bad,
        &Capability::embedded(PRINCIPAL, &["post"]).unwrap()).unwrap().unwrap_err();
    assert_eq!(denial.code, "FA-REF-011", "read admission precedes even group shape inspection");
}

#[test]
fn competing_consumption_invalidates_the_whole_group_not_only_one_leg() {
    let (mut h, invoice, bill, request) = fixture();
    let plan = h.plan(request);
    h.consume(invoice, 30);
    let at = h.head(); let cx = h.cx();
    let result = h.runtime.block_on(h.book.commit_settlement_group_plan(&cx, plan, &cap())).unwrap();
    assert!(result.is_err());
    assert_eq!(h.head(), at);
    assert_eq!(h.open(invoice, 0), 70);
    assert_eq!(h.open(bill, 1), 70, "the other selection must not commit alone");
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}
