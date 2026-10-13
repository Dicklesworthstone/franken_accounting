//! Real-kernel fixtures for portable group transport and restart/revalidation.

use super::*;
use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{EntryRef, EvidenceRef, Id128, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, BookKeys, Entropy, PostPlan, SettlementPostRequest};

const BOOK: Id128 = Id128([0x79; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "portable-settlement-group";
fn day(s: &str) -> DateDay { DateDay::parse(s).unwrap() }
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
            &cx, vfs.clone(), Path::new(PATH), BookKeys::for_development(121),
            BookSpec {
                book_id: BOOK, name: "Portable group review fixture".into(), base_unit: usd,
                calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                time_zone_policy: None, entities: Vec::new(), opening_date: None,
            }, Entropy::deterministic(121),
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
            retrieved_by: PRINCIPAL, bytes: b"portable group evidence".to_vec(),
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
        self.post(self.proposal(key, vec![leg(Side::Debit, "receivable", self.usd, amount),
            leg(Side::Credit, "capital", self.usd, amount)]))
    }
    fn consume(&mut self, invoice: EntryRef, amount: i128) {
        let request = SettlementPostRequest {
            proposal: self.proposal("competing", vec![leg(Side::Debit, "cash", self.usd, amount),
                leg(Side::Credit, "receivable", self.usd, amount)]),
            payment_leg: 1, targets: vec![(invoice.vid, 0)],
        };
        let cx = self.cx();
        let plan = self.book.plan_settlement(&cx, request, Vec::new(), &cap()).unwrap().unwrap();
        self.runtime.block_on(self.book.commit_settlement_plan(&cx, plan, &cap())).unwrap().unwrap();
    }
    fn open(&self, entry: EntryRef, ordinal: u16) -> i128 {
        self.book.open_items(&self.cx(), None, None).unwrap().into_iter()
            .find(|item| item.entry == entry.vid && item.ordinal == ordinal).unwrap().open
    }
    fn reopen(self) -> Self {
        let Self { runtime, root, book, vfs, evidence, usd, eur } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime.block_on(AsyncBook::open_with_vfs(
            &cx, vfs.clone(), Path::new(PATH), BookKeys::for_development(121),
            Entropy::deterministic(122),
        )).unwrap();
        Self { runtime, root, book, vfs, evidence, usd, eur }
    }
}

struct Fixture {
    h: Harness,
    invoice: EntryRef,
    bill: EntryRef,
    unused: EntryRef,
    review: SettlementGroupReview,
}
fn fixture() -> Fixture {
    let mut h = Harness::new();
    let invoice = h.invoice("invoice", 100);
    let bill = h.post(h.proposal("bill", vec![leg(Side::Debit, "cash", h.eur, 70),
        leg(Side::Credit, "payable", h.eur, 70)]));
    let unused = h.invoice("unused", 90);
    let request = SettlementGroupRequest {
        proposal: h.proposal("group", vec![leg(Side::Debit, "cash", h.usd, 60),
            leg(Side::Credit, "receivable", h.usd, 60), leg(Side::Debit, "payable", h.eur, 80),
            leg(Side::Credit, "cash", h.eur, 80)]),
        payments: vec![
            SettlementLegSelection { payment_leg: 2, targets: vec![(bill.vid, 1)] },
            SettlementLegSelection { payment_leg: 1, targets: vec![(unused.vid, 0), (invoice.vid, 0)] },
        ],
    };
    let prepared = h.book.prepare_settlement_group(&h.cx(), request, &cap()).unwrap().unwrap();
    let review = prepared.export_review().unwrap();
    Fixture { h, invoice, bill, unused, review }
}

#[test]
fn portable_bytes_keep_one_combined_proposal_and_all_unused_targets() {
    let f = fixture(); let review = &f.review; let head = f.h.head();
    let bytes = review.canonical_bytes().unwrap();
    assert_eq!(SettlementGroupReview::decode(&bytes).unwrap(), *review);
    assert_eq!(review.allocations()[0].allocation.request.targets.len(), 2);
    assert_eq!(review.allocations()[0].allocation.allocations.len(), 1);
    assert_eq!(review.allocations()[1].allocation.unapplied, 10);
    // Independent framing oracle, not a Writer/Reader round trip.
    let intent = review.intent.canonical_bytes().unwrap();
    let mut expected = b"FA-SETTLEMENT-GROUP-REVIEW\0".to_vec();
    expected.extend_from_slice(&[1, 0, 0, 0]);
    expected.extend_from_slice(&head.0.to_le_bytes());
    expected.extend_from_slice(&u32::try_from(intent.len()).unwrap().to_le_bytes());
    expected.extend_from_slice(&intent);
    expected.extend_from_slice(&2_u32.to_le_bytes());
    for part in review.allocations() {
        expected.extend_from_slice(&part.payment_leg.to_le_bytes());
        expected.extend_from_slice(&u32::try_from(part.allocation.request.targets.len()).unwrap().to_le_bytes());
        for (entry, ordinal) in &part.allocation.request.targets {
            expected.extend_from_slice(&entry.0.to_le_bytes()); expected.extend_from_slice(&ordinal.to_le_bytes());
        }
        expected.extend_from_slice(&u32::try_from(part.allocation.allocations.len()).unwrap().to_le_bytes());
        for a in &part.allocation.allocations {
            expected.extend_from_slice(&a.entry.0.to_le_bytes()); expected.extend_from_slice(&a.ordinal.to_le_bytes());
            for n in [a.amount, a.open_before, a.open_after] { expected.extend_from_slice(&n.to_le_bytes()); }
        }
        expected.extend_from_slice(&part.allocation.unapplied.to_le_bytes());
    }
    assert_eq!(bytes, expected);
    let fresh = f.h.book.refresh_settlement_group_review(&f.h.cx(), review, &cap()).unwrap().unwrap();
    assert_eq!(fresh.export_review().unwrap(), *review);
    assert_eq!(fresh.request(), &review.request().unwrap());
    assert_eq!(f.h.head(), head);
}

#[test]
fn hostile_framing_counts_ordinals_trailing_bytes_and_all_prefixes_fail_closed() {
    let f = fixture(); let bytes = f.review.canonical_bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(SettlementGroupReview::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    for offset in [0, 27, 29] {
        let mut bad = bytes.clone(); bad[offset] = 255;
        assert!(SettlementGroupReview::decode(&bad).is_err());
    }
    let groups = 43 + f.review.intent.canonical_bytes().unwrap().len();
    let first_targets = groups + 6;
    let first_allocations = first_targets + 4 + 18 * f.review.allocations()[0].allocation.request.targets.len();
    for offset in [39, groups, first_targets, first_allocations] {
        let mut bad = bytes.clone(); bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(SettlementGroupReview::decode(&bad).is_err(), "count {offset}");
    }
    let mut bad = bytes.clone(); bad[groups + 4..groups + 6].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(SettlementGroupReview::decode(&bad).is_err());
    let mut bad = bytes; bad.push(0);
    assert!(SettlementGroupReview::decode(&bad).is_err());
    assert!(matches!(SettlementGroupReview::decode(&vec![0; MAX_SETTLEMENT_GROUP_REVIEW_BYTES + 1]),
        Err(SettlementReviewError::TooLarge { .. })));
}

#[test]
fn inconsistent_witnesses_noncanonical_order_hidden_legs_and_overlap_are_rejected() {
    let f = fixture(); let base = f.review;
    let mut cases = Vec::new();
    let mut bad = base.clone(); bad.allocations.reverse(); cases.push(bad);
    let mut bad = base.clone(); bad.allocations.push(bad.allocations[0].clone()); cases.push(bad);
    let mut bad = base.clone(); bad.allocations[0].allocation.request.targets.reverse(); cases.push(bad);
    let mut bad = base.clone(); bad.allocations[0].allocation.known_at = CommitSeq(0); cases.push(bad);
    let mut bad = base.clone(); bad.allocations[0].allocation.allocations[0].open_after += 1; cases.push(bad);
    let mut bad = base.clone(); bad.allocations[1].allocation.unapplied = -1; cases.push(bad);
    let mut bad = base.clone(); bad.allocations[0].allocation.request.amount = i128::MAX; cases.push(bad);
    let mut bad = base.clone();
    bad.allocations[1].allocation.request.targets.push((f.unused.vid, 0));
    bad.allocations[1].allocation.request.targets.sort_unstable(); cases.push(bad);
    let mut bad = base.clone();
    let mut proposal = bad.proposal().clone(); proposal.legs[0].settles = proposal.legs[1].settles.clone();
    bad.intent = PostIntent::new(proposal, Vec::new()).unwrap(); cases.push(bad);
    let mut bad = base; bad.allocations = vec![bad.allocations[0].clone(); MAX_SETTLEMENT_GROUP_LEGS + 1]; cases.push(bad);
    for (i, bad) in cases.into_iter().enumerate() { assert!(bad.canonical_bytes().is_err(), "case {i}"); }
}

#[test]
fn reopened_review_accepts_approval_publications_then_one_commit_and_exact_plan_retry() {
    let Fixture { mut h, invoice, bill, unused, review } = fixture();
    let bytes = review.canonical_bytes().unwrap(); let digest = review.digest().unwrap();
    let cx = h.cx();
    let approved = h.runtime.block_on(h.book.approve(&cx,
        Capability::embedded(VId(8), &["approve"]).unwrap(),
        review.proposal().proposal_digest().unwrap(),
    )).unwrap().unwrap().approval();
    let mut h = h.reopen();
    let decoded = SettlementGroupReview::decode(&bytes).unwrap();
    assert_eq!(decoded.digest().unwrap(), digest);
    let head = h.head(); let cx = h.cx();
    let plan = h.book.plan_settlement_group_review(&cx, &decoded, vec![approved], &cap()).unwrap().unwrap();
    assert_eq!(plan.post_plan().intent().proposal(), decoded.proposal());
    assert_eq!(plan.post_plan().certificate().snapshot_seq, head);
    assert_eq!(h.head(), head, "review resume and kernel rehearsal publish nothing");
    let saved = plan.post_plan().canonical_bytes().unwrap();
    let posted = h.runtime.block_on(h.book.commit_settlement_group_plan(&cx, plan, &cap())).unwrap().unwrap();
    assert_eq!(posted.recorded_at(), CommitSeq(head.0 + 1));
    assert_eq!((h.open(invoice, 0), h.open(bill, 1), h.open(unused, 0)), (40, 0, 90));
    assert_eq!(h.open(posted.entry_ref(), 2), 10);
    h.invoice("later", 7); let mut h = h.reopen(); let head = h.head(); let cx = h.cx();
    let retried = h.runtime.block_on(h.book.commit_plan(&cx, PostPlan::decode(&saved).unwrap(), &cap()))
        .unwrap().unwrap();
    assert!(matches!(retried, Posted::AlreadyRecorded { .. }));
    assert_eq!(retried.entry_ref(), posted.entry_ref());
    assert_eq!(retried.recorded_at(), posted.recorded_at());
    assert_eq!(h.head(), head);
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

#[test]
fn competing_consumption_requires_new_review_even_when_all_payment_effects_still_fit() {
    let Fixture { mut h, invoice, bill, review, .. } = fixture();
    let original = review.proposal().proposal_digest().unwrap();
    h.consume(invoice, 10); let head = h.head(); let cx = h.cx();
    let fresh = h.book.prepare_settlement_group(&cx, review.request().unwrap(), &cap()).unwrap().unwrap();
    assert_eq!(fresh.proposal().proposal_digest().unwrap(), original);
    let denial = h.book.plan_settlement_group_review(&cx, &review, Vec::new(), &cap()).unwrap().unwrap_err();
    assert_eq!(denial.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!((h.open(invoice, 0), h.open(bill, 1)), (90, 70));
    assert_eq!(h.head(), head, "neither application may be partially published");
}

#[test]
fn internally_consistent_false_witnesses_and_full_target_substitution_fail_live_revalidation() {
    let f = fixture(); let head = f.h.head(); let cx = f.h.cx();
    let mut false_amounts = f.review.clone();
    false_amounts.allocations[0].allocation.allocations[0].open_before += 1;
    false_amounts.allocations[0].allocation.allocations[0].open_after += 1;
    let mut false_basis = f.review.clone(); false_basis.known_at = CommitSeq(head.0 + 100);
    for part in &mut false_basis.allocations { part.allocation.known_at = false_basis.known_at; }
    let mut false_digest = f.review.clone(); let mut proposal = false_digest.proposal().clone();
    let mut wrong = f.unused; wrong.vid = f.invoice.vid;
    proposal.legs[1].settles[0].target = wrong;
    false_digest.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    for changed in [false_amounts, false_basis, false_digest] {
        let decoded = SettlementGroupReview::decode(&changed.canonical_bytes().unwrap()).unwrap();
        assert_ne!(decoded.digest().unwrap(), f.review.digest().unwrap());
        let denial = f.h.book.refresh_settlement_group_review(&cx, &decoded, &cap()).unwrap().unwrap_err();
        assert_eq!(denial.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    }
    assert_eq!(f.h.head(), head);
}

#[test]
fn current_read_and_post_authority_are_required_even_for_an_unchanged_saved_review() {
    let f = fixture(); let head = f.h.head();
    for denied in [Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap()] {
        assert!(f.h.book.refresh_settlement_group_review(&f.h.cx(), &f.review, &denied).unwrap().is_err());
        assert_eq!(f.h.head(), head);
    }
}

#[test]
fn approvals_cannot_be_smuggled_in_the_unsigned_review_intent() {
    let Fixture { mut h, review, .. } = fixture(); let cx = h.cx();
    let approval = h.runtime.block_on(h.book.approve(&cx,
        Capability::embedded(VId(8), &["approve"]).unwrap(), review.proposal().proposal_digest().unwrap(),
    )).unwrap().unwrap().approval();
    let intent = PostIntent::new(review.proposal().clone(), vec![approval]).unwrap().canonical_bytes().unwrap();
    let old = review.canonical_bytes().unwrap();
    let mut hostile = old[..39].to_vec();
    hostile.extend_from_slice(&u32::try_from(intent.len()).unwrap().to_le_bytes());
    hostile.extend_from_slice(&intent);
    hostile.extend_from_slice(&old[43 + review.intent.canonical_bytes().unwrap().len()..]);
    assert!(SettlementGroupReview::decode(&hostile).is_err());
}

#[test]
fn aggregate_target_budget_is_enforced_across_lists_during_decode() {
    let f = fixture(); let intent = f.review.intent.canonical_bytes().unwrap();
    let mut w = Writer::new();
    w.fixed(MAGIC).u16(MAJOR).u16(MINOR).u64(f.h.head().0).bytes(&intent).u32(5);
    for group in 0..5_u16 {
        w.u16(group).u32(1024);
        for item in 0..1024_u128 { w.u128(u128::from(group) * 1024 + item).u16(0); }
        w.u32(0).i128(0);
    }
    // No fifth 1024-target allocation may be accepted even though the complete
    // byte envelope fits its byte budget and every individual list fits 1024.
    assert!(SettlementGroupReview::decode(&w.finish().unwrap()).is_err());
}

#[test]
fn large_native_amounts_remain_exact_across_transport_and_resume() {
    let mut h = Harness::new(); let amount = 9_007_199_254_740_993_i128;
    let invoice = h.invoice("large-invoice", amount + 2);
    let request = SettlementGroupRequest {
        proposal: h.proposal("large-payment", vec![leg(Side::Debit, "cash", h.usd, amount),
            leg(Side::Credit, "receivable", h.usd, amount)]),
        payments: vec![SettlementLegSelection { payment_leg: 1, targets: vec![(invoice.vid, 0)] }],
    };
    let cx = h.cx();
    let review = h.book.prepare_settlement_group(&cx, request, &cap()).unwrap().unwrap().export_review().unwrap();
    let decoded = SettlementGroupReview::decode(&review.canonical_bytes().unwrap()).unwrap();
    assert_eq!(decoded.allocations()[0].allocation.allocations[0].amount, amount);
    assert_eq!(decoded.allocations()[0].allocation.allocations[0].open_after, 2);
    let plan = h.book.plan_settlement_group_review(&cx, &decoded, Vec::new(), &cap()).unwrap().unwrap();
    h.runtime.block_on(h.book.commit_settlement_group_plan(&cx, plan, &cap())).unwrap().unwrap();
    assert_eq!(h.open(invoice, 0), 2);
}

mod approval;
