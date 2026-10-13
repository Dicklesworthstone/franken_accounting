//! Real-kernel settlement preparation, publication and exact-plan retries.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{AsyncBook, BookKeys, Capability, Entropy, SettlementPostPlan, SettlementPostRequest};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x52; 16]);
const PRINCIPAL: VId = VId(7);

fn day(text: &str) -> DateDay { DateDay::parse(text).unwrap() }
fn account(code: &str) -> VId { account_vid(BOOK, code) }
fn capability() -> Capability { Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap() }

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    evidence: EvidenceRef,
    usd: UnitId,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let vfs = MemVfs::new().unwrap();
        let mut book = runtime.block_on(AsyncBook::create_with_vfs(
            &cx, vfs.clone(), Path::new("settlement-book"), BookKeys::for_development(82),
            BookSpec {
                book_id: BOOK, name: "Settlement fixture".into(), base_unit: usd,
                calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                time_zone_policy: None, entities: Vec::new(), opening_date: None,
            }, Entropy::deterministic(82),
        )).unwrap();
        let chart = ["cash", "receivable", "payable", "capital"].into_iter().map(|code| {
            let credit = matches!(code, "payable" | "capital");
            AccountSpec {
                code: code.into(), name: code.into(),
                account_type: match code { "payable" => 2, "capital" => 3, _ => 1 },
                normal_balance: u8::from(credit), is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency, parent_code: None, limit: None,
            }
        }).collect::<Vec<_>>();
        runtime.block_on(book.install_chart(&cx, &chart, PRINCIPAL, day("2026-03-01"), b"chart"))
            .unwrap().unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
        runtime.block_on(book.transition_period(
            &cx, "FY2026-P03", PeriodTransition::Open, PRINCIPAL, 1, day("2026-03-01"),
            b"open-march", &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        )).unwrap().unwrap();
        let doc = Document {
            book_id: BOOK, kind: 1, mime: "text/plain".into(), grade: 3,
            retrieved_by: PRINCIPAL, bytes: b"settlement fixture evidence".to_vec(),
        };
        runtime.block_on(book.add_document(&cx, &doc)).unwrap().unwrap();
        Self { runtime, root, book, vfs, evidence: doc.evidence_ref(1), usd }
    }

    fn cx(&self) -> PurposeContexts { PurposeContexts::narrow_runtime_root(&self.root) }
    fn head(&self) -> CommitSeq { self.book.head(&self.cx()).unwrap() }

    fn proposal(&self, key: &str, date: &str, debit: &str, credit: &str, amount: i128) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Debit, account(debit), Amount::new(self.usd, amount)),
            LegPayload::simple(Side::Credit, account(credit), Amount::new(self.usd, amount)),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR, book_id: BOOK,
            branch_id: Id128::TRUNK, class: EntryClass::ORIGINAL,
            effective_date: day(date), document_date: None,
            description: self.book.seal_text(&self.cx(), key).unwrap(), effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(), legs,
            control: None, base_totals: None, idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent { intent_oid: Oid([1; 32]), intent_kind: 1 },
            principal_ref: PRINCIPAL, session_ref: None, evidence: vec![self.evidence],
            supersession: Vec::new(), pending: None, external_ids: Vec::new(),
            extensions: Vec::new(), tags: Vec::new(),
        }
    }

    fn post(&mut self, proposal: EntryPayload) -> Posted {
        let cx = self.cx();
        self.runtime.block_on(self.book.post(&cx, PostRequest {
            proposal, approvals: Vec::new(), plan_certificate: None, capability: capability(),
        })).unwrap().unwrap()
    }

    fn invoice(&mut self, key: &str, date: &str, amount: i128) -> EntryRef {
        let proposal = self.proposal(key, date, "receivable", "capital", amount);
        self.post(proposal).entry_ref()
    }

    fn receipt(&self, key: &str, amount: i128, invoices: &[EntryRef]) -> SettlementPostRequest {
        SettlementPostRequest {
            proposal: self.proposal(key, "2026-03-20", "cash", "receivable", amount),
            payment_leg: 1, targets: invoices.iter().map(|entry| (entry.vid, 0)).collect(),
        }
    }

    fn plan(&mut self, request: SettlementPostRequest) -> SettlementPostPlan {
        let cx = self.cx();
        self.book.plan_settlement(&cx, request, Vec::new(), &capability()).unwrap().unwrap()
    }

    fn commit(&mut self, plan: SettlementPostPlan) -> Posted {
        let cx = self.cx();
        self.runtime.block_on(self.book.commit_settlement_plan(&cx, plan, &capability()))
            .unwrap().unwrap()
    }

    fn open(&self, entry: EntryRef, ordinal: u16) -> i128 {
        self.book.open_items(&self.cx(), None, None).unwrap().into_iter()
            .find(|item| item.entry == entry.vid && item.ordinal == ordinal).unwrap().open
    }
}

#[test]
fn fifo_preparation_binds_full_digests_and_changes_only_the_selected_settles_list() {
    let mut h = Harness::new();
    let newer = h.invoice("newer", "2026-03-12", 70);
    let older = h.invoice("older", "2026-03-10", 100);
    let request = h.receipt("receipt", 130, &[newer, older]);
    let at = h.head();
    let prepared = h.book.prepare_settlement(&h.cx(), request.clone(), &capability()).unwrap().unwrap();
    assert_eq!(prepared.allocation().known_at, at);
    assert_eq!(prepared.allocation().unapplied, 0);
    let mut expected = request.proposal.clone();
    expected.legs[1].settles = vec![
        fa_model::Settlement { target: older, ordinal: 0, amount: Amount::new(h.usd, 100) },
        fa_model::Settlement { target: newer, ordinal: 0, amount: Amount::new(h.usd, 30) },
    ];
    assert_eq!(prepared.proposal(), &expected);
    assert_eq!(h.head(), at, "preparation must not publish anything");
    let plan = h.plan(request);
    assert_eq!(plan.post_plan().proposal().legs, expected.legs);
    assert_eq!(plan.post_plan().certificate().snapshot_seq, at);
    assert_eq!(h.head(), at, "kernel rehearsal must abort its writes");
    let posted = h.commit(plan.clone());
    assert_eq!(h.open(older, 0), 0);
    assert_eq!(h.open(newer, 0), 40);
    assert_eq!(h.open(posted.entry_ref(), 1), 0);
    assert!(h.book.verify_open_items(&h.cx()).unwrap().is_green());
    let committed_at = h.head();
    let retry = h.commit(plan);
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.head(), committed_at, "exact retry must not publish a second payment");
}

#[test]
fn overpayment_is_an_explicit_unapplied_credit_not_a_writeoff_or_balancing_plug() {
    let mut h = Harness::new();
    let invoice = h.invoice("invoice", "2026-03-10", 100);
    let plan = h.plan(h.receipt("overpayment", 125, &[invoice]));
    assert_eq!(plan.allocation().allocations[0].amount, 100);
    assert_eq!(plan.allocation().unapplied, 25);
    assert_eq!(plan.post_plan().proposal().legs.len(), 2);
    assert!(plan.post_plan().proposal().legs.iter().all(|leg| leg.amount.mantissa == 125));
    let posted = h.commit(plan);
    assert_eq!(h.open(invoice, 0), 0);
    assert_eq!(h.open(posted.entry_ref(), 1), 25);
    assert!(h.book.verify_open_items(&h.cx()).unwrap().is_green());
}

#[test]
fn payable_payment_uses_debit_applications_with_no_receivables_assumption() {
    let mut h = Harness::new();
    let bill = h.proposal("bill", "2026-03-10", "cash", "payable", 100);
    let bill = h.post(bill).entry_ref();
    let request = SettlementPostRequest {
        proposal: h.proposal("vendor-payment", "2026-03-20", "payable", "cash", 60),
        payment_leg: 0, targets: vec![(bill.vid, 1)],
    };
    let plan = h.plan(request);
    assert_eq!(plan.allocation().request.side, Side::Debit);
    assert_eq!(plan.post_plan().proposal().legs[0].settles[0].target, bill);
    let posted = h.commit(plan);
    assert_eq!(h.open(bill, 1), 40);
    assert_eq!(h.open(posted.entry_ref(), 0), 0);
    assert!(h.book.verify_open_items(&h.cx()).unwrap().is_green());
}

#[test]
fn portable_plan_retry_after_reopen_and_later_publications_returns_the_original_receipt() {
    let mut h = Harness::new();
    let invoice = h.invoice("invoice", "2026-03-10", 100);
    let plan = h.plan(h.receipt("receipt", 60, &[invoice]));
    let portable = plan.post_plan().canonical_bytes().unwrap();
    let posted = h.commit(plan);
    let _ = h.invoice("later-invoice", "2026-03-21", 7);
    let head = h.head();
    let Harness { runtime, root, book, vfs, .. } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut reopened = runtime.block_on(AsyncBook::open_with_vfs(
        &cx, vfs, Path::new("settlement-book"), BookKeys::for_development(82),
        Entropy::deterministic(83),
    )).unwrap();
    let plan = fa::PostPlan::decode(&portable).unwrap();
    let retry = runtime.block_on(reopened.commit_plan(&cx, plan, &capability())).unwrap().unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(reopened.head(&cx).unwrap(), head);
    let items = reopened.open_items(&cx, Some(account("receivable")), None).unwrap();
    assert_eq!(items.iter().find(|item| item.entry == invoice.vid && item.ordinal == 0).unwrap().open, 40);
    assert!(reopened.verify_open_items(&cx).unwrap().is_green());
}
