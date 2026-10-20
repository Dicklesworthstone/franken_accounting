//! Real kernel-backed review/approval/resume tests plus hostile codec inputs.

use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{EntryOrigin, EntryRef, EvidenceRef, Id128, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;

use crate::{BookKeys, Entropy, PostPlan};

const BOOK: Id128 = Id128([0x65; 16]);
const PRINCIPAL: VId = VId(7);
fn day(value: &str) -> DateDay {
    DateDay::parse(value).unwrap()
}
fn account(code: &str) -> VId {
    account_vid(BOOK, code)
}
fn cap() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}

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
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("settlement-review"),
                BookKeys::for_development(101),
                BookSpec {
                    book_id: BOOK,
                    name: "Settlement review fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(101),
            ))
            .unwrap();
        let chart = ["cash", "receivable", "capital"]
            .into_iter()
            .map(|code| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: if code == "capital" { 3 } else { 1 },
                normal_balance: u8::from(code == "capital"),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect::<Vec<_>>();
        runtime
            .block_on(book.install_chart(
                &cx,
                &chart,
                PRINCIPAL,
                day("2026-03-01"),
                b"chart",
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
                "FY2026-P03",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                b"open",
                &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        let doc = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"portable settlement review evidence".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            evidence: doc.evidence_ref(1),
            usd,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn proposal(
        &self,
        key: &str,
        date: &str,
        debit: &str,
        credit: &str,
        amount: i128,
    ) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Debit, account(debit), Amount::new(self.usd, amount)),
            LegPayload::simple(Side::Credit, account(credit), Amount::new(self.usd, amount)),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&self.cx(), key).unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
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

    fn invoice(&mut self, key: &str, date: &str, amount: i128) -> EntryRef {
        let proposal = self.proposal(key, date, "receivable", "capital", amount);
        let cx = self.cx();
        self.runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    capability: cap(),
                    plan_certificate: None,
                },
            ))
            .unwrap()
            .unwrap()
            .entry_ref()
    }

    fn prepare(&mut self, key: &str, amount: i128, targets: &[EntryRef]) -> PreparedSettlement {
        let cx = self.cx();
        let request = SettlementPostRequest {
            proposal: self.proposal(key, "2026-03-20", "cash", "receivable", amount),
            payment_leg: 1,
            targets: targets.iter().map(|e| (e.vid, 0)).collect(),
        };
        self.runtime
            .block_on(self.book.prepare_settlement(&cx, request, &cap()))
            .unwrap()
            .unwrap()
    }

    fn approve(&mut self, digest: [u8; 32]) -> ApprovalRef {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.approve(
                &cx,
                Capability::embedded(VId(8), &["approve"]).unwrap(),
                digest,
            ))
            .unwrap()
            .unwrap()
            .approval()
    }

    fn open(&self, entry: EntryRef) -> i128 {
        self.book
            .open_items(&self.cx(), Some(account("receivable")), None)
            .unwrap()
            .into_iter()
            .find(|item| item.entry == entry.vid && item.ordinal == 0)
            .unwrap()
            .open
    }
}

fn fixture() -> (Harness, SettlementReview) {
    let mut h = Harness::new();
    let newer = h.invoice("newer", "2026-03-12", 70);
    let older = h.invoice("older", "2026-03-10", 100);
    let unused = h.invoice("unused", "2026-03-15", 90);
    let review = h
        .prepare("payment", 130, &[unused, newer, older])
        .export_review()
        .unwrap();
    (h, review)
}

#[test]
fn portable_review_retains_sealed_proposal_full_handles_fifo_and_unused_targets() {
    let (mut h, review) = fixture();
    let at = h.head();
    assert_eq!(review.allocation().request.targets.len(), 3);
    assert_eq!(
        review
            .allocation()
            .allocations
            .iter()
            .map(|a| a.amount)
            .collect::<Vec<_>>(),
        [100, 30]
    );
    let bytes = review.canonical_bytes().unwrap();
    let decoded = SettlementReview::decode(&bytes).unwrap();
    assert_eq!(decoded, review);
    assert_eq!(decoded.digest().unwrap(), review.digest().unwrap());
    assert_eq!(
        decoded.proposal().description,
        review.proposal().description
    );
    assert_eq!(
        decoded.proposal().proposal_digest().unwrap(),
        review.proposal().proposal_digest().unwrap()
    );
    assert_eq!(decoded.payment_leg(), 1);
    let cx = h.cx();
    let refreshed = h
        .runtime
        .block_on(h.book.refresh_settlement_review(&cx, &decoded, &cap()))
        .unwrap()
        .unwrap();
    assert_eq!(refreshed.proposal(), review.proposal());
    assert_eq!(refreshed.allocation(), review.allocation());
    assert_eq!(h.head(), at, "export, decode and refresh publish nothing");

    // Independent envelope construction, not a Writer/Reader round trip.
    let mut expected = b"FA-SETTLEMENT-REVIEW\0".to_vec();
    expected.extend_from_slice(&[1, 0, 0, 0]);
    expected.extend_from_slice(&at.0.to_le_bytes());
    expected.extend_from_slice(&1_u16.to_le_bytes());
    let intent = review.intent.canonical_bytes().unwrap();
    expected.extend_from_slice(&u32::try_from(intent.len()).unwrap().to_le_bytes());
    expected.extend_from_slice(&intent);
    expected.extend_from_slice(&3_u32.to_le_bytes());
    for (entry, ordinal) in &review.allocation.request.targets {
        expected.extend_from_slice(&entry.0.to_le_bytes());
        expected.extend_from_slice(&ordinal.to_le_bytes());
    }
    expected.extend_from_slice(&2_u32.to_le_bytes());
    for part in &review.allocation.allocations {
        expected.extend_from_slice(&part.entry.0.to_le_bytes());
        expected.extend_from_slice(&part.ordinal.to_le_bytes());
        for amount in [part.amount, part.open_before, part.open_after] {
            expected.extend_from_slice(&amount.to_le_bytes());
        }
    }
    expected.extend_from_slice(&0_i128.to_le_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn hostile_framing_versions_counts_trailing_bytes_and_every_truncation_are_rejected() {
    let (_, review) = fixture();
    let bytes = review.canonical_bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(
            SettlementReview::decode(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    for offset in [0, 21, 23] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(SettlementReview::decode(&bad).is_err(), "header {offset}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SettlementReview::decode(&trailing).is_err());
    let targets_offset = 39 + review.intent.canonical_bytes().unwrap().len();
    let allocations_offset = targets_offset + 4 + 18 * review.allocation.request.targets.len();
    for offset in [35, targets_offset, allocations_offset] {
        let mut bad = bytes.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            SettlementReview::decode(&bad).is_err(),
            "hostile length at {offset}"
        );
    }
    assert!(matches!(
        SettlementReview::decode(&vec![0; MAX_SETTLEMENT_REVIEW_BYTES + 1]),
        Err(SettlementReviewError::TooLarge { .. }),
    ));
}

#[test]
fn internally_inconsistent_reviews_cannot_be_encoded() {
    let (_, review) = fixture();
    let mut cases = Vec::new();
    let mut changed = review.clone();
    changed.payment_leg = u16::MAX;
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.request.targets.reverse();
    cases.push(changed);
    let mut changed = review.clone();
    changed
        .allocation
        .request
        .targets
        .push(changed.allocation.request.targets[0]);
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.allocations[0].amount = 0;
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.allocations[0].open_after = -1;
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.allocations[0].open_before = 1;
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.unapplied = 1;
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.allocations.swap(0, 1);
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.request.unit_id = u32::MAX;
    cases.push(changed);
    let mut changed = review.clone();
    changed.intent = PostIntent::new(
        review.proposal().clone(),
        vec![ApprovalRef {
            approval_vid: VId(9),
            approved_digest: review.proposal().proposal_digest().unwrap(),
        }],
    )
    .unwrap();
    cases.push(changed);
    for (i, changed) in cases.into_iter().enumerate() {
        assert!(changed.canonical_bytes().is_err(), "malformed review {i}");
    }
}

#[test]
fn approval_publication_reopen_and_resume_preserve_the_exact_payment_and_retry_receipt() {
    let mut h = Harness::new();
    let invoice = h.invoice("invoice", "2026-03-10", 100);
    let prepared = h.prepare("approved-payment", 60, &[invoice]);
    let review = prepared.export_review().unwrap();
    let reviewed_at = h.head();
    let bytes = review.canonical_bytes().unwrap();
    let approval = h.approve(review.proposal().proposal_digest().unwrap());
    let after_approval = h.head();
    assert!(after_approval > reviewed_at);
    let cx = h.cx();
    // The existing strict API is intentionally not loosened.
    assert!(
        h.runtime
            .block_on(
                h.book
                    .plan_prepared_settlement(&cx, prepared, vec![approval], &cap())
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), after_approval);

    let Harness {
        runtime,
        root,
        book,
        vfs,
        ..
    } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut reopened = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            Path::new("settlement-review"),
            BookKeys::for_development(101),
            Entropy::deterministic(102),
        ))
        .unwrap();
    let decoded = SettlementReview::decode(&bytes).unwrap();
    let plan = runtime
        .block_on(reopened.plan_settlement_review(&cx, &decoded, vec![approval], &cap()))
        .unwrap()
        .unwrap();
    assert_eq!(plan.post_plan().proposal(), review.proposal());
    assert_eq!(plan.post_plan().approvals(), &[approval]);
    assert_eq!(plan.allocation().known_at, after_approval);
    assert_eq!(
        decoded.allocation().known_at,
        reviewed_at,
        "the old review is immutable"
    );
    assert_eq!(
        reopened.head(&cx).unwrap(),
        after_approval,
        "planning writes nothing"
    );
    let portable = plan.post_plan().canonical_bytes().unwrap();
    let posted = runtime
        .block_on(reopened.commit_settlement_plan(&cx, plan, &cap()))
        .unwrap()
        .unwrap();
    let at = reopened.head(&cx).unwrap();
    let retry = runtime
        .block_on(reopened.commit_plan(&cx, PostPlan::decode(&portable).unwrap(), &cap()))
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(posted.entry_ref(), retry.entry_ref());
    assert_eq!(posted.recorded_at(), retry.recorded_at());
    assert_eq!(reopened.head(&cx).unwrap(), at);
    assert!(reopened.verify_open_items(&cx).unwrap().is_green());
    let items = reopened
        .open_items(&cx, Some(account("receivable")), None)
        .unwrap();
    assert_eq!(
        items
            .iter()
            .find(|i| i.entry == invoice.vid && i.ordinal == 0)
            .unwrap()
            .open,
        40
    );
}

#[test]
fn a_competing_payment_requires_new_review_even_when_the_old_allocation_still_fits() {
    let mut h = Harness::new();
    let invoice = h.invoice("invoice", "2026-03-10", 1000);
    let review = h
        .prepare("reviewed-payment", 60, &[invoice])
        .export_review()
        .unwrap();
    let other = h.prepare("competing-payment", 10, &[invoice]);
    let cx = h.cx();
    let plan = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement(&cx, other, Vec::new(), &cap()),
        )
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(h.book.commit_settlement_plan(&cx, plan, &cap()))
        .unwrap()
        .unwrap();
    let at = h.head();
    // Same final application amount is insufficient: the reviewed before/after
    // exposure changed even though 990 still covers this payment of 60.
    let refusal = h
        .runtime
        .block_on(h.book.refresh_settlement_review(&cx, &review, &cap()))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(h.head(), at);
    assert_eq!(h.open(invoice), 990);
    assert!(
        h.runtime
            .block_on(
                h.book
                    .plan_settlement_review(&cx, &review, Vec::new(), &cap())
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
}

#[test]
fn decoded_claims_need_current_revalidation_even_when_their_internal_arithmetic_is_valid() {
    let (mut h, review) = fixture();
    let cx = h.cx();
    let at = h.head();
    let mut cases = Vec::new();
    let mut changed = review.clone();
    changed.allocation.allocations[0].open_before = changed.allocation.allocations[0]
        .open_before
        .checked_add(9)
        .unwrap();
    changed.allocation.allocations[0].open_after = changed.allocation.allocations[0]
        .open_after
        .checked_add(9)
        .unwrap();
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocation.known_at = CommitSeq(at.0.checked_add(100).unwrap());
    cases.push(changed);
    let mut changed = review.clone();
    let mut proposal = review.proposal().clone();
    proposal.legs[1].settles[0].target.entry_digest[0] ^= 1;
    changed.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    cases.push(changed);
    for changed in cases {
        let decoded = SettlementReview::decode(&changed.canonical_bytes().unwrap()).unwrap();
        assert_ne!(decoded.digest().unwrap(), review.digest().unwrap());
        let refusal = h
            .runtime
            .block_on(h.book.refresh_settlement_review(&cx, &decoded, &cap()))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
        assert_eq!(h.head(), at);
    }
}

#[test]
fn approval_refs_are_external_and_must_bind_the_proposal_not_the_review_container() {
    let (mut h, review) = fixture();
    let wrong = h.approve(review.digest().unwrap());
    let at = h.head();
    let cx = h.cx();
    assert!(
        h.runtime
            .block_on(
                h.book
                    .plan_settlement_review(&cx, &review, vec![wrong], &cap())
            )
            .unwrap()
            .is_err()
    );
    let forged = ApprovalRef {
        approval_vid: VId(u128::MAX),
        approved_digest: review.proposal().proposal_digest().unwrap(),
    };
    assert!(
        h.runtime
            .block_on(
                h.book
                    .plan_settlement_review(&cx, &review, vec![forged], &cap())
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    let right = h.approve(review.proposal().proposal_digest().unwrap());
    let at = h.head();
    assert!(
        h.runtime
            .block_on(
                h.book
                    .plan_settlement_review(&cx, &review, vec![right], &cap())
            )
            .unwrap()
            .is_ok()
    );
    assert_eq!(h.head(), at);
}

#[test]
fn a_review_grants_no_read_post_principal_scope_or_expiry_authority() {
    let (mut h, review) = fixture();
    let at = h.head();
    let denied = [
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        cap().expiring_at(at),
        cap().for_books(&[Id128([0x99; 16])]).unwrap(),
        cap().with_ceiling(h.usd, 129).unwrap(),
    ];
    let cx = h.cx();
    for capability in &denied {
        assert!(
            h.runtime
                .block_on(h.book.refresh_settlement_review(&cx, &review, capability))
                .unwrap()
                .is_err()
        );
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .plan_settlement_review(&cx, &review, Vec::new(), capability)
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

mod approval;
