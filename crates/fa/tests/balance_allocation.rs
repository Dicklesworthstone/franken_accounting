//! Real journal -> selected posted balance -> reviewed allocation -> native
//! plan/commit/retry. No arithmetic-only mock stands in for kernel admission.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{
    AllocationReview, AsyncBook, BalanceAllocationRequest, BookKeys, Capability, Entropy, PostPlan,
    PreparedBalanceAllocation,
};
use fa_journal::allocation::ALLOCATION_DOCUMENT_KIND;
use fa_journal::refusal::code;
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, Refusal, UnitPolicy};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid, account_vid,
};
use fa_money::allocation::{AllocationMethod, AllocationTarget};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0xBA; 16]);
const PRINCIPAL: VId = VId(7);
fn account(code: &str) -> VId {
    account_vid(BOOK, code)
}
fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn cap() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    usd: UnitId,
    eur: UnitId,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = MemVfs::new().unwrap();
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("balance-allocation"),
                BookKeys::for_development(186),
                BookSpec {
                    book_id: BOOK,
                    name: "Journal-derived allocation fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(186),
            ))
            .unwrap();
        let chart = ["source", "offset", "a", "b", "c", "summary", "eur-only"]
            .into_iter()
            .map(|code| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: code != "summary",
                unit_policy: if code == "eur-only" {
                    UnitPolicy::Single(eur)
                } else {
                    UnitPolicy::AnyUnit
                },
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
        for (period, date) in [("FY2026-P03", "2026-03-01"), ("FY2026-P04", "2026-04-01")] {
            runtime
                .block_on(book.transition_period(
                    &cx,
                    period,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    day(date),
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
            eur,
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

    #[allow(clippy::too_many_arguments)]
    fn movement(
        &mut self,
        key: &str,
        debit: &str,
        credit: &str,
        unit: UnitId,
        amount: i128,
        date: &str,
    ) {
        let evidence = self.document(key.as_bytes().to_vec());
        let mut proposal = self.template(key, evidence);
        proposal.class = EntryClass::ORIGINAL;
        proposal.effective_date = day(date);
        proposal.legs = vec![
            LegPayload::simple(Side::Debit, account(debit), Amount::new(unit, amount)),
            LegPayload::simple(Side::Credit, account(credit), Amount::new(unit, amount)),
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
                    capability: cap(),
                },
            ))
            .unwrap()
            .unwrap();
    }

    fn prepare(&self, request: &BalanceAllocationRequest) -> PreparedBalanceAllocation {
        self.book
            .prepare_balance_allocation(&self.cx(), request, &cap())
            .unwrap()
            .unwrap()
    }

    fn review(&mut self, prepared: &PreparedBalanceAllocation, key: &str) -> AllocationReview {
        let evidence = self.document(prepared.posting().basis_bytes().unwrap());
        prepared.review(self.template(key, evidence)).unwrap()
    }

    fn plan(
        &mut self,
        prepared: &PreparedBalanceAllocation,
        review: &AllocationReview,
    ) -> Result<PostPlan, Refusal> {
        let cx = self.cx();
        self.book
            .plan_balance_allocation_review(
                &cx,
                prepared.request(),
                prepared.source_digest(),
                review,
                review.digest().unwrap(),
                Vec::new(),
                &cap(),
            )
            .unwrap()
    }

    fn commit(&mut self, plan: PostPlan) -> Result<Posted, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.commit_plan(&cx, plan, &cap()))
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
}

#[test]
fn journal_balance_to_review_native_plan_commit_and_exact_retry() {
    let mut h = Harness::new();
    h.movement("pool", "source", "offset", h.usd, 10_000, "2026-03-10");
    let at = h.head();
    let prepared = h.prepare(&h.request());
    assert_eq!(h.head(), at, "preparation must not publish");
    assert_eq!(prepared.known_at(), at);
    assert_eq!(
        (
            prepared.debits(),
            prepared.credits(),
            prepared.contributions()
        ),
        (10_000, 0, 1)
    );
    assert_eq!(prepared.posting().source_side, Side::Credit);
    let review = h.review(&prepared, "allocate-pool");
    let head = h.head();
    let plan = h.plan(&prepared, &review).unwrap();
    assert_eq!(h.head(), head, "planning must not publish");
    let bytes = plan.canonical_bytes().unwrap();
    let posted = h.commit(plan).unwrap();
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (0, 3334, 3333, 3333)
    );
    let head = h.head();
    let retry = h.commit(PostPlan::decode(&bytes).unwrap()).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.head(), head);
}

#[test]
fn credit_balance_is_redistributed_with_the_opposite_source_side() {
    let mut h = Harness::new();
    h.movement("credit-pool", "offset", "source", h.usd, 7, "2026-03-10");
    let prepared = h.prepare(&h.request());
    assert_eq!((prepared.debits(), prepared.credits()), (0, 7));
    assert_eq!(prepared.posting().source_side, Side::Debit);
    assert_eq!(prepared.posting().request.total.mantissa, 7);
    let review = h.review(&prepared, "allocate-credit");
    let plan = h.plan(&prepared, &review).unwrap();
    h.commit(plan).unwrap();
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (0, -3, -2, -2)
    );
}

#[test]
fn source_changes_refuse_even_when_net_amount_is_identical() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    h.movement("increase", "source", "offset", h.usd, 20, "2026-03-11");
    h.movement("decrease", "offset", "source", h.usd, 20, "2026-03-12");
    let current = h.prepare(&h.request());
    assert_eq!(prepared.posting(), current.posting());
    assert_ne!(prepared.source_digest(), current.source_digest());
    let head = h.head();
    assert_eq!(
        h.plan(&prepared, &review).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(h.head(), head);
}

#[test]
fn unrelated_changes_other_units_and_other_periods_do_not_replace_the_source() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    h.movement("other-accounts", "a", "b", h.usd, 9, "2026-03-11");
    h.movement("other-unit", "source", "offset", h.eur, 900, "2026-03-11");
    h.movement("other-period", "source", "offset", h.usd, 800, "2026-04-11");
    let current = h.prepare(&h.request());
    assert!(current.known_at() > prepared.known_at());
    assert_eq!(current.source_digest(), prepared.source_digest());
    assert_eq!(current.posting(), prepared.posting());
    h.plan(&prepared, &review).unwrap();
}

#[test]
fn zero_sources_and_nonmatching_dimensions_never_create_an_allocation() {
    let mut h = Harness::new();
    let request = h.request();
    assert!(
        h.book
            .prepare_balance_allocation(&h.cx(), &request, &cap())
            .unwrap()
            .is_err()
    );
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let mut dimensioned = request.clone();
    dimensioned.dimensions = vec![(1, VId(99))];
    let at = h.head();
    assert!(
        h.book
            .prepare_balance_allocation(&h.cx(), &dimensioned, &cap())
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    assert_eq!(h.prepare(&request).posting().request.total.mantissa, 100);
}

#[test]
fn read_post_scope_expiry_and_derived_leg_ceilings_are_required() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let request = h.request();
    let at = h.head();
    let denied = [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        cap().expiring_at(at),
        cap().for_books(&[Id128([0xFF; 16])]).unwrap(),
        cap().with_ceiling(h.usd, 99).unwrap(),
    ];
    for authority in denied {
        assert!(
            h.book
                .prepare_balance_allocation(&h.cx(), &request, &authority)
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
    let exact = cap().with_ceiling(h.usd, 100).unwrap();
    assert!(
        h.book
            .prepare_balance_allocation(&h.cx(), &request, &exact)
            .unwrap()
            .is_ok()
    );
    let mut hidden = request;
    hidden.source = VId(u128::MAX);
    hidden.period = "does-not-exist".into();
    // Missing authority refuses before even trying to resolve the hidden input.
    assert!(
        h.book
            .prepare_balance_allocation(
                &h.cx(),
                &hidden,
                &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn source_and_review_digest_substitutions_refuse_without_publication() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let at = h.head();
    let cx = h.cx();
    let mut wrong_source = prepared.source_digest();
    wrong_source[0] ^= 1;
    let mut wrong_review = review.digest().unwrap();
    wrong_review[0] ^= 1;
    for (source, digest) in [
        (wrong_source, review.digest().unwrap()),
        (prepared.source_digest(), wrong_review),
    ] {
        let refusal = h
            .book
            .plan_balance_allocation_review(
                &cx,
                prepared.request(),
                source,
                &review,
                digest,
                Vec::new(),
                &cap(),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::PLAN_INVALIDATED);
        assert_eq!(h.head(), at);
    }
}

#[test]
fn a_claimed_driver_does_not_bypass_native_evidence_admission() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let evidence = prepared.posting().driver_evidence(BOOK).unwrap();
    let review = prepared
        .review(h.template("missing-driver", evidence))
        .unwrap();
    let at = h.head();
    assert!(h.plan(&prepared, &review).is_err());
    assert_eq!(h.head(), at);
}

#[test]
fn zero_share_targets_still_pass_through_native_account_validation() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 1, "2026-03-10");
    let mut request = h.request();
    request.method = AllocationMethod::Waterfall;
    request.targets = vec![
        AllocationTarget {
            id: account("a").0,
            basis: 1,
        },
        AllocationTarget {
            id: account("summary").0,
            basis: 0,
        },
    ];
    let prepared = h.prepare(&request);
    let review = h.review(&prepared, "zero-summary");
    let at = h.head();
    assert_eq!(
        h.plan(&prepared, &review).unwrap_err().code,
        code::NOT_A_LEAF
    );
    assert_eq!(h.head(), at);
}

#[test]
fn native_plan_cannot_be_reused_after_an_intervening_publication() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let plan = h.plan(&prepared, &review).unwrap();
    h.movement("intervening", "a", "b", h.usd, 1, "2026-03-11");
    let at = h.head();
    assert_eq!(h.commit(plan).unwrap_err().code, code::PLAN_INVALIDATED);
    assert_eq!(h.head(), at);
    assert_eq!(h.net("source"), 100);
}

#[test]
fn independently_saved_source_and_review_can_be_revalidated_after_reopen() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let review_digest = review.digest().unwrap();
    let review_bytes = review.canonical_bytes().unwrap();
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
            Path::new("balance-allocation"),
            BookKeys::for_development(186),
            Entropy::deterministic(187),
        ))
        .unwrap();
    let plan = book
        .plan_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &AllocationReview::decode(&review_bytes).unwrap(),
            review_digest,
            Vec::new(),
            &cap(),
        )
        .unwrap()
        .unwrap();
    let plan_bytes = plan.canonical_bytes().unwrap();
    let posted = runtime
        .block_on(book.commit_plan(&cx, plan, &cap()))
        .unwrap()
        .unwrap();
    let head = book.head(&cx).unwrap();
    let retry = runtime
        .block_on(book.commit_plan(&cx, PostPlan::decode(&plan_bytes).unwrap(), &cap()))
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(book.head(&cx).unwrap(), head);
}

fn approver() -> Capability {
    Capability::embedded(VId(8), &["read", "approve"]).unwrap()
}

#[test]
fn source_revalidating_approver_needs_no_post_and_can_complete_the_workflow() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let cx = h.cx();
    let digest = review.digest().unwrap();
    let approved = h
        .runtime
        .block_on(h.book.approve_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            digest,
            &approver(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        approved.approval().approved_digest,
        review.proposal_digest().unwrap()
    );
    assert_ne!(approved.approval().approved_digest, digest);
    assert_ne!(
        approved.approval().approved_digest,
        prepared.source_digest()
    );
    let at = h.head();
    let retry = h
        .runtime
        .block_on(h.book.approve_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            digest,
            &approver(),
        ))
        .unwrap()
        .unwrap();
    assert!(matches!(
        retry,
        fa_journal::Approved::AlreadyRecorded { .. }
    ));
    assert_eq!(retry.approval(), approved.approval());
    assert_eq!(h.head(), at);
    let plan = h
        .book
        .plan_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            digest,
            vec![approved.approval()],
            &cap(),
        )
        .unwrap()
        .unwrap();
    h.commit(plan).unwrap();
    assert_eq!(h.net("source"), 0);
}

#[test]
fn changed_source_cannot_receive_a_source_bound_approval_even_with_the_same_total() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    h.movement("plus", "source", "offset", h.usd, 10, "2026-03-11");
    h.movement("minus", "offset", "source", h.usd, 10, "2026-03-12");
    assert_eq!(h.prepare(&h.request()).posting(), prepared.posting());
    let cx = h.cx();
    let at = h.head();
    let refusal = h
        .runtime
        .block_on(h.book.approve_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            review.digest().unwrap(),
            &approver(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert_eq!(h.head(), at);
}

#[test]
fn source_approval_enforces_read_approve_separation_expiry_scope_and_ceilings() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let at = h.head();
    let cx = h.cx();
    let denied = [
        Capability::embedded(PRINCIPAL, &["read", "approve"]).unwrap(),
        Capability::embedded(VId(8), &["approve"]).unwrap(),
        Capability::embedded(VId(8), &["read"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        approver().expiring_at(at),
        approver().for_books(&[Id128([0xFF; 16])]).unwrap(),
        approver().with_ceiling(h.usd, 99).unwrap(),
    ];
    for authority in denied {
        assert!(
            h.runtime
                .block_on(h.book.approve_balance_allocation_review(
                    &cx,
                    prepared.request(),
                    prepared.source_digest(),
                    &review,
                    review.digest().unwrap(),
                    &authority,
                ))
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
}

#[test]
fn source_approval_requires_both_independently_retained_digests() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let cx = h.cx();
    let at = h.head();
    let mut wrong_source = prepared.source_digest();
    wrong_source[0] ^= 1;
    let mut wrong_review = review.digest().unwrap();
    wrong_review[0] ^= 1;
    for (source, digest) in [
        (wrong_source, review.digest().unwrap()),
        (prepared.source_digest(), wrong_review),
    ] {
        let refusal = h
            .runtime
            .block_on(h.book.approve_balance_allocation_review(
                &cx,
                prepared.request(),
                source,
                &review,
                digest,
                &approver(),
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::PLAN_INVALIDATED);
        assert_eq!(h.head(), at);
    }
}

#[test]
fn source_approval_does_not_grant_closed_period_posting_authority() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let cx = h.cx();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P03",
            PeriodTransition::Close,
            PRINCIPAL,
            1,
            day("2026-03-31"),
            b"close-march",
            &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let approval = h
        .runtime
        .block_on(h.book.approve_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            review.digest().unwrap(),
            &approver(),
        ))
        .unwrap()
        .unwrap();
    let at = h.head();
    assert!(
        h.book
            .plan_balance_allocation_review(
                &cx,
                prepared.request(),
                prepared.source_digest(),
                &review,
                review.digest().unwrap(),
                vec![approval.approval()],
                &cap(),
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    let closed = Capability::embedded(PRINCIPAL, &["read", "post", "post_closed"]).unwrap();
    assert!(
        h.book
            .plan_balance_allocation_review(
                &cx,
                prepared.request(),
                prepared.source_digest(),
                &review,
                review.digest().unwrap(),
                Vec::new(),
                &closed,
            )
            .unwrap()
            .is_err(),
        "period permission alone must not substitute for the approval"
    );
    assert_eq!(h.head(), at);
    let plan = h
        .book
        .plan_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            review.digest().unwrap(),
            vec![approval.approval()],
            &closed,
        )
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(h.book.commit_plan(&cx, plan, &closed))
        .unwrap()
        .unwrap();
    assert_eq!(h.net("source"), 0);
}

#[test]
fn source_approval_survives_reopen_and_retries_without_a_second_publication() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    let cx = h.cx();
    let digest = review.digest().unwrap();
    let approval = h
        .runtime
        .block_on(h.book.approve_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            digest,
            &approver(),
        ))
        .unwrap()
        .unwrap();
    let at = h.head();
    let bytes = review.canonical_bytes().unwrap();
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
            Path::new("balance-allocation"),
            BookKeys::for_development(186),
            Entropy::deterministic(187),
        ))
        .unwrap();
    let retry = runtime
        .block_on(book.approve_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &AllocationReview::decode(&bytes).unwrap(),
            digest,
            &approver(),
        ))
        .unwrap()
        .unwrap();
    assert!(matches!(
        retry,
        fa_journal::Approved::AlreadyRecorded { .. }
    ));
    assert_eq!(retry.approval(), approval.approval());
    assert_eq!(retry.recorded_at(), approval.recorded_at());
    assert_eq!(book.head(&cx).unwrap(), at);
}

#[test]
fn a_depleted_reviewed_source_is_a_conflict_for_both_planning_and_approval() {
    let mut h = Harness::new();
    h.movement("initial", "source", "offset", h.usd, 100, "2026-03-10");
    let prepared = h.prepare(&h.request());
    let review = h.review(&prepared, "reviewed");
    h.movement("depleted", "offset", "source", h.usd, 100, "2026-03-11");
    assert_eq!(h.net("source"), 0);
    let at = h.head();
    assert_eq!(
        h.plan(&prepared, &review).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    let cx = h.cx();
    let refusal = h
        .runtime
        .block_on(h.book.approve_balance_allocation_review(
            &cx,
            prepared.request(),
            prepared.source_digest(),
            &review,
            review.digest().unwrap(),
            &approver(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert_eq!(h.head(), at);
}
