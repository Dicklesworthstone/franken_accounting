//! Public allocation reviews compose with real evidence, native plans and retries.
use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{AllocationPosting, AllocationReview, AsyncBook, BookKeys, Capability, Entropy, PostPlan};
use fa_journal::refusal::code;
use fa_journal::{AccountSpec, BookSpec, Document, Posted, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, Id128, Oid, account_vid};
use fa_money::allocation::{AllocationMethod, AllocationRequest, AllocationTarget};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0xB4; 16]);
const AUTHOR: VId = VId(7);
fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn account(code: &str) -> VId {
    account_vid(BOOK, code)
}
fn author() -> Capability {
    Capability::embedded(AUTHOR, &["post"]).unwrap()
}
fn approver() -> Capability {
    Capability::embedded(VId(8), &["approve"]).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
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
                Path::new("allocation-review-book"),
                BookKeys::for_development(180),
                BookSpec {
                    book_id: BOOK,
                    name: "Allocation review fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(180),
            ))
            .unwrap();
        let chart = ["source", "a", "b", "c"]
            .into_iter()
            .map(|name| AccountSpec {
                code: name.into(),
                name: name.into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            })
            .collect::<Vec<_>>();
        runtime
            .block_on(book.install_chart(
                &cx,
                &chart,
                AUTHOR,
                day("2026-03-01"),
                b"chart",
                &fa_journal::Capability::embedded(AUTHOR, &["schema_change"]).unwrap(),
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
                AUTHOR,
                1,
                day("2026-03-01"),
                b"open-march",
                &Capability::embedded(AUTHOR, &["close"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            usd,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn basis(&self, weights: &[(&str, u128)]) -> AllocationPosting {
        AllocationPosting {
            source: account("source"),
            source_side: Side::Credit,
            dimensions: Vec::new(),
            request: AllocationRequest {
                total: Amount::new(self.usd, 10_000),
                method: AllocationMethod::LargestRemainder,
                targets: weights
                    .iter()
                    .map(|(name, basis)| AllocationTarget {
                        id: account(name).0,
                        basis: *basis,
                    })
                    .collect(),
            },
        }
    }

    fn template(&self, basis: &AllocationPosting, key: &str) -> EntryPayload {
        EntryPayload {
            schema_minor: 1,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ALLOCATION,
            effective_date: day("2026-03-15"),
            document_date: None,
            description: self.book.seal_text(&self.cx(), key).unwrap(),
            effective_period: None,
            unit_totals: Vec::new(),
            legs: Vec::new(),
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: AUTHOR,
            session_ref: None,
            evidence: vec![basis.driver_evidence(BOOK).unwrap()],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn import(&mut self, bytes: Vec<u8>) {
        let cx = self.cx();
        let doc = Document {
            book_id: BOOK,
            kind: 21,
            mime: "application/octet-stream".into(),
            grade: 3,
            retrieved_by: AUTHOR,
            bytes,
        };
        self.runtime
            .block_on(self.book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
    }

    fn review(&mut self, key: &str) -> AllocationReview {
        let basis = self.basis(&[("a", 1), ("b", 1), ("c", 1)]);
        self.import(basis.basis_bytes().unwrap());
        let template = self.template(&basis, key);
        AllocationReview::new(basis, template).unwrap()
    }

    fn plan(&mut self, review: &AllocationReview) -> PostPlan {
        let cx = self.cx();
        self.book
            .plan_allocation_review(&cx, review, review.digest().unwrap(), Vec::new(), &author())
            .unwrap()
            .unwrap()
    }
}

#[test]
fn approval_publications_do_not_change_the_reviewed_proposal_or_create_a_stale_rehearsal() {
    let mut h = Harness::new();
    let review = h.review("reviewed-allocation");
    let saved = review.canonical_bytes().unwrap();
    let digest = review.digest().unwrap();
    let cx = h.cx();
    let before = h.head();
    let approval = h
        .runtime
        .block_on(
            h.book
                .approve(&cx, approver(), review.proposal_digest().unwrap()),
        )
        .unwrap()
        .unwrap();
    assert!(h.head() > before);
    let review = AllocationReview::decode(&saved).unwrap();
    let at = h.head();
    let plan = h
        .book
        .plan_allocation_review(&cx, &review, digest, vec![approval.approval()], &author())
        .unwrap()
        .unwrap();
    assert_eq!(plan.proposal(), review.proposal());
    assert_eq!(plan.certificate().snapshot_seq, at);
    assert_eq!(h.head(), at, "rehearsal publishes nothing");
    assert_eq!(plan.approvals(), &[approval.approval()]);
    let portable = plan.canonical_bytes().unwrap();
    let posted = h
        .runtime
        .block_on(h.book.commit_plan(&cx, plan, &author()))
        .unwrap()
        .unwrap();
    let (entry, _) = h
        .book
        .read_entry(&cx, posted.entry_ref().vid)
        .unwrap()
        .unwrap();
    assert_eq!(&entry.proposal, review.proposal());
    assert_eq!(entry.approvals, vec![approval.approval()]);
    let fold = h.book.fold_period(&cx, "FY2026-P03").unwrap();
    assert_eq!(fold.entries, 1);
    for (name, net) in [("source", -10_000), ("a", 3334), ("b", 3333), ("c", 3333)] {
        assert_eq!(
            fold.cells
                .iter()
                .find(|cell| cell.key.account == account(name))
                .unwrap()
                .net(),
            Some(net)
        );
    }
    let at = h.head();
    let retry = h
        .runtime
        .block_on(
            h.book
                .commit_plan(&cx, PostPlan::decode(&portable).unwrap(), &author()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.head(), at);
}

#[test]
fn planning_refuses_substituted_review_and_inadequate_current_authority_without_writes() {
    let mut h = Harness::new();
    let review = h.review("guarded");
    let digest = review.digest().unwrap();
    let cx = h.cx();
    let at = h.head();
    let mut wrong = digest;
    wrong[0] ^= 1;
    let refusal = h
        .book
        .plan_allocation_review(&cx, &review, wrong, Vec::new(), &author())
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    for denied in [
        Capability::embedded(AUTHOR, &["read"]).unwrap(),
        Capability::embedded(VId(8), &["post"]).unwrap(),
        author().with_ceiling(h.usd, 9999).unwrap(),
        author().expiring_at(at),
        author().for_books(&[Id128([9; 16])]).unwrap(),
    ] {
        assert!(
            h.book
                .plan_allocation_review(&cx, &review, digest, Vec::new(), &denied)
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
}

#[test]
fn decoding_a_review_does_not_create_driver_evidence_or_approve_zero_share_accounts() {
    let mut h = Harness::new();
    let basis = h.basis(&[("a", 1), ("missing", 0)]);
    let template = h.template(&basis, "missing-driver");
    let review = AllocationReview::new(basis.clone(), template).unwrap();
    let review = AllocationReview::decode(&review.canonical_bytes().unwrap()).unwrap();
    let cx = h.cx();
    let before = h.head();
    let result = h
        .book
        .plan_allocation_review(
            &cx,
            &review,
            review.digest().unwrap(),
            Vec::new(),
            &author(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(result.code, code::EVIDENCE_UNKNOWN);
    assert_eq!(h.head(), before);
    h.import(basis.basis_bytes().unwrap());
    let before = h.head();
    let result = h
        .book
        .plan_allocation_review(
            &cx,
            &review,
            review.digest().unwrap(),
            Vec::new(),
            &author(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(result.code, code::UNKNOWN_ACCOUNT);
    assert_eq!(h.head(), before);
}

#[test]
fn saved_review_is_not_a_way_to_refresh_an_invalidated_native_plan() {
    let mut h = Harness::new();
    let review = h.review("stale-plan");
    let old = h.plan(&review);
    h.import(b"a later unrelated document".to_vec());
    let before = h.head();
    let cx = h.cx();
    let refused = h
        .runtime
        .block_on(h.book.commit_plan(&cx, old, &author()))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED);
    assert_eq!(h.head(), before);
    // Explicit fresh rehearsal is allowed before a successful publication;
    // it must keep the reviewed proposal byte-for-byte, not repair the old plan.
    let fresh = h.plan(&review);
    assert_eq!(fresh.proposal(), review.proposal());
    assert_eq!(fresh.certificate().snapshot_seq, before);
    assert_eq!(h.head(), before);
}

#[test]
fn portable_review_can_be_planned_after_reopen_without_resealing_the_description() {
    let mut h = Harness::new();
    let review = h.review("reopen");
    let bytes = review.canonical_bytes().unwrap();
    let digest = review.digest().unwrap();
    let at = h.head();
    let Harness {
        runtime,
        root,
        book,
        vfs,
        ..
    } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut book = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            Path::new("allocation-review-book"),
            BookKeys::for_development(180),
            Entropy::deterministic(181),
        ))
        .unwrap();
    let decoded = AllocationReview::decode(&bytes).unwrap();
    let plan = book
        .plan_allocation_review(&cx, &decoded, digest, Vec::new(), &author())
        .unwrap()
        .unwrap();
    assert_eq!(plan.proposal(), review.proposal());
    assert_eq!(book.head(&cx).unwrap(), at);
    runtime
        .block_on(book.commit_plan(&cx, plan, &author()))
        .unwrap()
        .unwrap();
    assert!(book.verify_projections(&cx, None).unwrap().is_green());
}

#[path = "allocation_review/approval.rs"]
mod approval;
