//! The portable source review crosses real book reopens, approval publications
//! and native plan/commit/retry. No deserialized object is trusted as a fold.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{
    AllocationReview, AsyncBook, BalanceAllocationRequest, BalanceAllocationReview, BookKeys,
    Capability, Entropy, PostPlan, PreparedBalanceAllocation,
};
use fa_journal::allocation::ALLOCATION_DOCUMENT_KIND;
use fa_journal::refusal::code;
use fa_journal::{
    AccountSpec, Approved, BookSpec, Document, PostRequest, Posted, Refusal, UnitPolicy,
};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::allocation::{AllocationMethod, AllocationTarget};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0xBC; 16]);
const PRINCIPAL: VId = VId(7);
fn account(code: &str) -> VId {
    account_vid(BOOK, code)
}
fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn post_cap() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}
fn approve_cap() -> Capability {
    Capability::embedded(VId(8), &["read", "approve"]).unwrap()
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
        let vfs = MemVfs::new().unwrap();
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("portable-source"),
                BookKeys::for_development(188),
                BookSpec {
                    book_id: BOOK,
                    name: "Portable source allocation".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(188),
            ))
            .unwrap();
        let chart = ["source", "offset", "a", "b", "c"]
            .into_iter()
            .map(|code| AccountSpec {
                code: code.into(),
                name: code.into(),
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
        for period in ["FY2026-P03", "FY2026-P04"] {
            runtime
                .block_on(book.transition_period(
                    &cx,
                    period,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    period.as_bytes(),
                    &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
                ))
                .unwrap()
                .unwrap();
        }
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
    fn request(&self) -> BalanceAllocationRequest {
        BalanceAllocationRequest {
            target_cells: Vec::new(),
            source: account("source"),
            period: "FY2026-P03".into(),
            unit: self.usd,
            dimensions: Vec::new(),
            method: AllocationMethod::LargestRemainder,
            targets: ["a", "b", "c"]
                .into_iter()
                .map(|name| AllocationTarget {
                    id: account(name).0,
                    basis: 1,
                })
                .collect(),
        }
    }
    fn prepare(&mut self, request: &BalanceAllocationRequest) -> PreparedBalanceAllocation {
        let cx = self.cx();
        self.runtime
            .block_on(
                self.book
                    .prepare_balance_allocation(&cx, request, &post_cap()),
            )
            .unwrap()
            .unwrap()
    }
    fn document(&mut self, bytes: Vec<u8>) -> EvidenceRef {
        let document = Document {
            book_id: BOOK,
            kind: ALLOCATION_DOCUMENT_KIND,
            mime: "application/octet-stream".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes,
        };
        let cx = self.cx();
        self.runtime
            .block_on(self.book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        document.evidence_ref(1)
    }
    fn template(&self, key: &str, evidence: EvidenceRef) -> EntryPayload {
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
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
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }
    fn movement(&mut self, key: &str, debit: &str, credit: &str, amount: i128, date: &str) {
        let evidence = self.document(key.as_bytes().to_vec());
        let mut proposal = self.template(key, evidence);
        proposal.class = EntryClass::ORIGINAL;
        proposal.effective_date = day(date);
        proposal.legs = vec![
            LegPayload::simple(Side::Debit, account(debit), Amount::new(self.usd, amount)),
            LegPayload::simple(Side::Credit, account(credit), Amount::new(self.usd, amount)),
        ];
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        let cx = self.cx();
        self.runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap(),
                },
            ))
            .unwrap()
            .unwrap();
    }
    fn packet(&mut self, request: &BalanceAllocationRequest, key: &str) -> BalanceAllocationReview {
        let prepared = self.prepare(request);
        let evidence = self.document(prepared.posting().basis_bytes().unwrap());
        prepared
            .portable_review(self.template(key, evidence))
            .unwrap()
    }
    fn plan(
        &mut self,
        review: &BalanceAllocationReview,
        digest: [u8; 32],
        approvals: Vec<ApprovalRef>,
    ) -> Result<PostPlan, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.plan_balance_allocation(
                &cx,
                review,
                digest,
                approvals,
                &post_cap(),
            ))
            .unwrap()
    }
    fn approve(
        &mut self,
        review: &BalanceAllocationReview,
        digest: [u8; 32],
    ) -> Result<Approved, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(
                self.book
                    .approve_balance_allocation(&cx, review, digest, &approve_cap()),
            )
            .unwrap()
    }
    fn commit(&mut self, plan: PostPlan) -> Result<Posted, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.commit_plan(&cx, plan, &post_cap()))
            .unwrap()
    }
    fn net(&self, name: &str) -> i128 {
        self.book
            .fold_period(&self.cx(), "FY2026-P03")
            .unwrap()
            .cells
            .iter()
            .find(|cell| cell.key.account == account(name) && cell.key.unit_id == self.usd.0)
            .map_or(0, |cell| cell.debits.checked_sub(cell.credits).unwrap())
    }
    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            book,
            vfs,
            usd,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("portable-source"),
                BookKeys::for_development(188),
                Entropy::deterministic(189),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            usd,
        }
    }
}

#[test]
fn only_saved_bytes_and_one_digest_survive_the_entire_approval_posting_lifecycle() {
    let mut h = Harness::new();
    h.movement("pool", "source", "offset", 10_000, "2026-03-10");
    let (bytes, digest) = {
        let review = h.packet(&h.request(), "allocate");
        (review.canonical_bytes().unwrap(), review.digest().unwrap())
    }; // Both preparation and sealed review are gone; only the handoff remains.
    h = h.reopen();
    let review = BalanceAllocationReview::decode(&bytes).unwrap();
    let old_plan = h.plan(&review, digest, Vec::new()).unwrap();
    let approval = h.approve(&review, digest).unwrap();
    let at = h.head();
    let duplicate = h.approve(&review, digest).unwrap();
    assert!(matches!(duplicate, Approved::AlreadyRecorded { .. }));
    assert_eq!(duplicate.approval(), approval.approval());
    assert_eq!(h.head(), at);
    assert_eq!(h.commit(old_plan).unwrap_err().code, code::PLAN_INVALIDATED);
    assert_eq!(h.head(), at);
    drop(review);
    h = h.reopen();
    let review = BalanceAllocationReview::decode(&bytes).unwrap();
    let plan = h.plan(&review, digest, vec![approval.approval()]).unwrap();
    assert_eq!(
        plan.proposal(),
        review.review().proposal(),
        "do not reseal after approval"
    );
    assert_eq!(h.head(), at, "rehearsal is read-only");
    let plan_bytes = plan.canonical_bytes().unwrap();
    let posted = h.commit(plan).unwrap();
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (0, 3334, 3333, 3333)
    );
    h = h.reopen();
    let at = h.head();
    let retry = h.commit(PostPlan::decode(&plan_bytes).unwrap()).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.head(), at);
    assert_eq!(
        h.plan(&review, digest, Vec::new()).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(
        h.approve(&review, digest).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(
        h.head(),
        at,
        "a depleted source is not automatically refreshed"
    );
}

#[test]
fn same_net_history_changes_after_approval_refuse_without_publication() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", 100, "2026-03-10");
    let review = h.packet(&h.request(), "allocate");
    let digest = review.digest().unwrap();
    let approval = h.approve(&review, digest).unwrap();
    h.movement("increase", "source", "offset", 20, "2026-03-11");
    h.movement("decrease", "offset", "source", 20, "2026-03-12");
    let current = h.prepare(&review.request());
    assert_eq!(current.posting(), review.review().posting());
    assert_ne!(current.source_digest(), review.source_digest());
    let at = h.head();
    review.verify_for(&digest).unwrap();
    assert_eq!(
        h.plan(&review, digest, vec![approval.approval()])
            .unwrap_err()
            .code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(
        h.approve(&review, digest).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(h.head(), at);
}

#[test]
fn source_claim_substitution_needs_both_recipient_identity_and_live_history() {
    let mut h = Harness::new();
    h.movement("march", "source", "offset", 100, "2026-03-10");
    h.movement("april", "source", "offset", 100, "2026-04-10");
    let original = h.packet(&h.request(), "allocate");
    let digest = original.digest().unwrap();
    let bytes = original.canonical_bytes().unwrap();
    // Independent v1 layout: magic[14], versions[4], period length[4].
    let period_at = 22;
    let source_at = period_at + original.source_period().len();
    for field in 0..2 {
        let mut changed = bytes.clone();
        match field {
            0 => changed[period_at + original.source_period().len() - 1] = b'4',
            _ => changed[source_at] ^= 1,
        }
        let changed = BalanceAllocationReview::decode(&changed).unwrap();
        assert_eq!(changed.review(), original.review());
        let at = h.head();
        for expected in [digest, changed.digest().unwrap()] {
            assert_eq!(
                h.plan(&changed, expected, Vec::new()).unwrap_err().code,
                code::PLAN_INVALIDATED
            );
            assert_eq!(
                h.approve(&changed, expected).unwrap_err().code,
                code::PLAN_INVALIDATED
            );
            assert_eq!(h.head(), at);
        }
    }
    let at = h.head();
    for wrong in [
        original.source_digest(),
        original.review().digest().unwrap(),
        original.review().proposal_digest().unwrap(),
    ] {
        assert_eq!(
            h.plan(&original, wrong, Vec::new()).unwrap_err().code,
            code::PLAN_INVALIDATED
        );
        assert_eq!(
            h.approve(&original, wrong).unwrap_err().code,
            code::PLAN_INVALIDATED
        );
        assert_eq!(h.head(), at);
    }
}

#[test]
fn restored_handoff_keeps_scope_holder_expiry_operations_and_amount_ceilings() {
    let mut h = Harness::new();
    h.movement("pool", "source", "offset", 100, "2026-03-10");
    let review = h.packet(&h.request(), "allocate");
    let review = BalanceAllocationReview::decode(&review.canonical_bytes().unwrap()).unwrap();
    let digest = review.digest().unwrap();
    let at = h.head();
    let cx = h.cx();
    for denied in [
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        post_cap().for_books(&[Id128([0xff; 16])]).unwrap(),
        post_cap().expiring_at(at),
        post_cap().with_ceiling(h.usd, 99).unwrap(),
    ] {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .plan_balance_allocation(&cx, &review, digest, Vec::new(), &denied)
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
    for denied in [
        Capability::embedded(PRINCIPAL, &["read", "approve"]).unwrap(),
        Capability::embedded(VId(8), &["approve"]).unwrap(),
        Capability::embedded(VId(8), &["read"]).unwrap(),
        approve_cap().for_books(&[Id128([0xff; 16])]).unwrap(),
        approve_cap().expiring_at(at),
        approve_cap().with_ceiling(h.usd, 99).unwrap(),
    ] {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .approve_balance_allocation(&cx, &review, digest, &denied)
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
    // The approver has no Post grant and still can approve the selected source.
    h.approve(&review, digest).unwrap();
}

#[test]
fn closed_period_still_needs_both_permission_and_real_separate_approval() {
    let mut h = Harness::new();
    h.movement("pool", "source", "offset", 100, "2026-03-10");
    let review = h.packet(&h.request(), "allocate");
    let digest = review.digest().unwrap();
    let cx = h.cx();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P03",
            PeriodTransition::Close,
            PRINCIPAL,
            1,
            b"close",
            &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let approval = h.approve(&review, digest).unwrap();
    let at = h.head();
    assert!(h.plan(&review, digest, vec![approval.approval()]).is_err());
    let closed = Capability::embedded(PRINCIPAL, &["read", "post", "post_closed"]).unwrap();
    assert!(
        h.runtime
            .block_on(
                h.book
                    .plan_balance_allocation(&cx, &review, digest, Vec::new(), &closed)
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    let plan = h
        .runtime
        .block_on(h.book.plan_balance_allocation(
            &cx,
            &review,
            digest,
            vec![approval.approval()],
            &closed,
        ))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(h.book.commit_plan(&cx, plan, &closed))
        .unwrap()
        .unwrap();
    assert_eq!(h.net("source"), 0);
}

#[test]
fn transport_and_approval_do_not_invent_driver_evidence_or_target_accounts() {
    let mut h = Harness::new();
    h.movement("pool", "source", "offset", 1, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let missing = prepared.posting().driver_evidence(BOOK).unwrap();
    let review = prepared
        .portable_review(h.template("missing-driver", missing))
        .unwrap();
    let digest = review.digest().unwrap();
    let at = h.head();
    assert!(h.plan(&review, digest, Vec::new()).is_err());
    assert_eq!(h.head(), at);
    let mut request = h.request();
    request.targets = vec![
        AllocationTarget {
            id: account("a").0,
            basis: 1,
        },
        AllocationTarget {
            id: account("never-created").0,
            basis: 0,
        },
    ];
    let review = h.packet(&request, "zero-target");
    let digest = review.digest().unwrap();
    let approval = h.approve(&review, digest).unwrap();
    let at = h.head();
    assert_eq!(
        h.plan(&review, digest, vec![approval.approval()])
            .unwrap_err()
            .code,
        code::UNKNOWN_ACCOUNT
    );
    assert_eq!(
        h.head(),
        at,
        "zero-valued declarations still pass native account admission"
    );
}

#[test]
fn prepared_adoption_checks_the_exact_driver_not_only_the_outcome() {
    let mut h = Harness::new();
    h.movement("pool", "source", "offset", 9, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let evidence = h.document(prepared.posting().basis_bytes().unwrap());
    let template = h.template("allocate", evidence);
    let ordinary = prepared.review(template.clone()).unwrap();
    let adopted = BalanceAllocationReview::from_review(&prepared, ordinary.clone()).unwrap();
    let built = prepared.portable_review(template).unwrap();
    assert_eq!(adopted, built);
    assert_eq!(adopted.request(), *prepared.request());
    assert_eq!(adopted.review().proposal(), ordinary.proposal());
    let mut changed = prepared.posting().clone();
    for target in &mut changed.request.targets {
        target.basis *= 2;
    }
    assert_eq!(
        changed.request.execute().unwrap().shares(),
        ordinary.outcome().unwrap().shares()
    );
    let template = h.template("other-driver", changed.driver_evidence(BOOK).unwrap());
    let different = AllocationReview::new(changed, template).unwrap();
    assert!(BalanceAllocationReview::from_review(&prepared, different).is_err());
}

#[test]
fn credit_source_with_signed_rounding_residual_survives_reopen() {
    let mut h = Harness::new();
    h.movement("credit-pool", "offset", "source", 1, "2026-03-10");
    let mut request = h.request();
    request.method = AllocationMethod::ProRataResidualToNamed {
        rounding: RoundingLaw::Ceiling,
        recipient: account("a").0,
    };
    let review = h.packet(&request, "allocate-credit");
    assert_eq!(review.review().posting().source_side, Side::Debit);
    assert_eq!(review.review().outcome().unwrap().shares()[0].mantissa, -1);
    let digest = review.digest().unwrap();
    let bytes = review.canonical_bytes().unwrap();
    drop(review);
    h = h.reopen();
    let restored = BalanceAllocationReview::decode(&bytes).unwrap();
    let approval = h.approve(&restored, digest).unwrap();
    let plan = h
        .plan(&restored, digest, vec![approval.approval()])
        .unwrap();
    h.commit(plan).unwrap();
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (0, 1, -1, -1)
    );
}

#[test]
fn a_validly_encoded_review_for_another_book_is_never_approved_or_planned_here() {
    let mut h = Harness::new();
    h.movement("pool", "source", "offset", 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let other = Id128([0xfe; 16]);
    let evidence = prepared.posting().driver_evidence(other).unwrap();
    let mut template = h.template("wrong-book", evidence);
    template.book_id = other;
    let review = prepared.portable_review(template).unwrap();
    let review = BalanceAllocationReview::decode(&review.canonical_bytes().unwrap()).unwrap();
    let digest = review.digest().unwrap();
    let at = h.head();
    assert_eq!(
        h.plan(&review, digest, Vec::new()).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(
        h.approve(&review, digest).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(h.head(), at);
}
