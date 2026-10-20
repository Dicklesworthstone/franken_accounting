//! Allocation uses the real journal, evidence admission, native plans and folds.
//! No test substitutes the arithmetic receipt for a successful kernel commit.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{AllocationPosting, AsyncBook, BookKeys, Capability, Entropy, PostIntent, PostPlan};
use fa_journal::allocation::{ALLOCATION_DOCUMENT_KIND, ALLOCATION_EXTENSION};
use fa_journal::refusal::code;
use fa_journal::{
    AccountSpec, BalanceLimit, BookSpec, Document, LimitScope, PostRequest, Posted, Refusal,
    UnitPolicy,
};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::allocation::{AllocationMethod, AllocationRequest, AllocationTarget};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0xA7; 16]);
const PRINCIPAL: VId = VId(7);
fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn account(code: &str) -> VId {
    account_vid(BOOK, code)
}
fn capability() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    usd: UnitId,
}

impl Harness {
    fn new(limited_source: bool) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let vfs = MemVfs::new().unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("allocation-book"),
                BookKeys::for_development(167),
                BookSpec {
                    book_id: BOOK,
                    name: "Native allocation fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(167),
            ))
            .unwrap();
        let chart = ["source", "a", "b", "c", "summary", "eur-only"]
            .into_iter()
            .map(|code| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: code != "summary",
                unit_policy: UnitPolicy::Single(if code == "eur-only" { eur } else { usd }),
                parent_code: matches!(code, "a" | "b" | "c").then(|| "summary".into()),
                limit: (limited_source && code == "source").then_some(BalanceLimit {
                    lower: Some(0),
                    upper: None,
                    scope: LimitScope::Lifetime,
                }),
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
                b"open-march",
                &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
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
    fn basis(
        &self,
        total: i128,
        method: AllocationMethod,
        weights: &[(&str, u128)],
    ) -> AllocationPosting {
        AllocationPosting {
            source: account("source"),
            source_side: Side::Credit,
            dimensions: Vec::new(),
            request: AllocationRequest {
                total: Amount::new(self.usd, total),
                method,
                targets: weights
                    .iter()
                    .map(|(code, basis)| AllocationTarget {
                        id: account(code).0,
                        basis: *basis,
                    })
                    .collect(),
            },
        }
    }

    fn import_driver(&mut self, basis: &AllocationPosting, grade: u8) -> EvidenceRef {
        let doc = Document {
            book_id: BOOK,
            kind: ALLOCATION_DOCUMENT_KIND,
            mime: "application/octet-stream".into(),
            grade,
            retrieved_by: PRINCIPAL,
            bytes: basis.basis_bytes().unwrap(),
        };
        let cx = self.cx();
        self.runtime
            .block_on(self.book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
        assert_eq!(doc.evidence_ref(1), basis.driver_evidence(BOOK).unwrap());
        doc.evidence_ref(1)
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

    fn proposal(&mut self, key: &str, basis: &AllocationPosting) -> EntryPayload {
        let evidence = self.import_driver(basis, 3);
        basis.proposal(self.template(key, evidence)).unwrap()
    }

    fn post(&mut self, proposal: EntryPayload, cap: Capability) -> Result<Posted, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap,
                },
            ))
            .unwrap()
    }

    fn plan(&mut self, proposal: EntryPayload) -> PostPlan {
        let cx = self.cx();
        self.book
            .plan(
                &cx,
                PostIntent::new(proposal, Vec::new()).unwrap(),
                &capability(),
            )
            .unwrap()
            .unwrap()
    }

    fn commit(&mut self, plan: PostPlan) -> Result<Posted, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.commit_plan(&cx, plan, &capability()))
            .unwrap()
    }

    fn net(&self, code: &str) -> i128 {
        self.book
            .fold_period(&self.cx(), "FY2026-P03")
            .unwrap()
            .cells
            .iter()
            .find(|cell| cell.key.account == account(code) && cell.key.unit_id == self.usd.0)
            .map_or(0, |cell| cell.debits.checked_sub(cell.credits).unwrap())
    }

    fn reversal(&self, key: &str, target: EntryRef) -> EntryPayload {
        let (original, _) = self
            .book
            .read_entry(&self.cx(), target.vid)
            .unwrap()
            .unwrap();
        let mut proposal = self.template(key, original.proposal.evidence[0]);
        proposal.class = EntryClass::REVERSAL;
        proposal.legs = original
            .proposal
            .legs
            .into_iter()
            .map(|mut leg| {
                leg.side = match leg.side {
                    Side::Debit => Side::Credit,
                    Side::Credit => Side::Debit,
                };
                leg
            })
            .collect();
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        proposal.supersession = vec![fa_model::entry::Supersession {
            target,
            kind: fa_model::SupersessionKind::Reverses,
            reason_code: 1,
        }];
        proposal
    }

    fn assert_refusal(&mut self, proposal: EntryPayload, expected: &str) {
        let head = self.head();
        let refusal = self.post(proposal, capability()).unwrap_err();
        assert_eq!(refusal.code, expected, "{refusal}");
        assert_eq!(self.head(), head, "a refusal must not publish anything");
    }
}

#[test]
fn allocation_driver_to_native_plan_to_journal_and_register_fold() {
    let mut h = Harness::new(false);
    let basis = h.basis(
        10_000,
        AllocationMethod::LargestRemainder,
        &[("a", 1), ("b", 1), ("c", 1)],
    );
    let proposal = h.proposal("allocate", &basis);
    let head = h.head();
    let plan = h.plan(proposal.clone());
    assert_eq!(h.head(), head, "rehearsal publishes no entry");
    assert_eq!(plan.proposal(), &proposal);
    let portable = plan.canonical_bytes().unwrap();
    let posted = h.commit(PostPlan::decode(&portable).unwrap()).unwrap();
    let (stored, at) = h
        .book
        .read_entry(&h.cx(), posted.entry_ref().vid)
        .unwrap()
        .unwrap();
    assert_eq!(stored.proposal, proposal);
    assert_eq!(at, posted.recorded_at());
    assert_eq!(stored.proposal.class, EntryClass::ALLOCATION);
    assert_eq!(stored.proposal.extensions[0].0, ALLOCATION_EXTENSION);
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (-10_000, 3334, 3333, 3333)
    );
    assert!(
        h.book
            .fold_period(&h.cx(), "FY2026-P03")
            .unwrap()
            .pending
            .is_empty()
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.book.materialize_registers(&cx, "FY2026-P03"))
        .unwrap();
    assert!(
        h.book
            .verify_registers(&cx, "FY2026-P03")
            .unwrap()
            .is_green()
    );
    assert!(h.book.verify_projections(&cx, None).unwrap().is_green());
    let head = h.head();
    let retry = h.commit(PostPlan::decode(&portable).unwrap()).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.head(), head);
}

#[test]
fn transported_allocation_plan_survives_reopen_and_exact_retry() {
    let mut h = Harness::new(false);
    let basis = h.basis(
        7,
        AllocationMethod::Waterfall,
        &[("a", 2), ("b", 0), ("c", 9)],
    );
    let proposal = h.proposal("waterfall", &basis);
    let plan = h.plan(proposal);
    let bytes = plan.canonical_bytes().unwrap();
    let posted = h.commit(plan).unwrap();
    let head = h.head();
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
            Path::new("allocation-book"),
            BookKeys::for_development(167),
            Entropy::deterministic(168),
        ))
        .unwrap();
    let retry = runtime
        .block_on(reopened.commit_plan(&cx, PostPlan::decode(&bytes).unwrap(), &capability()))
        .unwrap()
        .unwrap();
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(reopened.head(&cx).unwrap(), head);
    assert_eq!(reopened.fold_period(&cx, "FY2026-P03").unwrap().entries, 1);
}

#[test]
fn balanced_wrong_shares_and_transplanted_provenance_are_rejected() {
    let mut h = Harness::new(false);
    let basis = h.basis(
        10_000,
        AllocationMethod::LargestRemainder,
        &[("a", 1), ("b", 1), ("c", 1)],
    );
    let original = h.proposal("tamper", &basis);
    let mut wrong = original.clone();
    wrong.legs[1].amount.mantissa -= 1;
    wrong.legs[2].amount.mantissa += 1;
    assert_eq!(
        EntryPayload::fold_unit_totals(&wrong.legs).unwrap(),
        original.unit_totals
    );
    wrong.validate().unwrap();
    h.assert_refusal(wrong, code::STRUCTURE);
    let mut wrong_class = original.clone();
    wrong_class.class = EntryClass::ORIGINAL;
    h.assert_refusal(wrong_class, code::STRUCTURE);
    let mut missing = original;
    missing.extensions.clear();
    h.assert_refusal(missing, code::CLASS_NOT_IMPLEMENTED);
}

#[test]
fn rehashed_basis_requires_its_own_driver_document_not_the_old_citation() {
    let mut h = Harness::new(false);
    let basis = h.basis(7, AllocationMethod::LargestRemainder, &[("a", 1), ("b", 1)]);
    let original = h.proposal("changed-basis", &basis);
    let mut changed = basis.clone();
    changed.request.targets[0].basis = 3;
    // Construction independently recomputes both inner hashes and exact legs.
    let mut proposal = changed
        .proposal(h.template("changed-basis", changed.driver_evidence(BOOK).unwrap()))
        .unwrap();
    proposal.evidence = original.evidence;
    proposal.validate().unwrap();
    h.assert_refusal(proposal, code::EVIDENCE_COMMIT);
    // Merely presenting the matching reference does not create its document.
    let proposal = changed
        .proposal(h.template("absent-driver", changed.driver_evidence(BOOK).unwrap()))
        .unwrap();
    h.assert_refusal(proposal, code::EVIDENCE_UNKNOWN);
}

#[test]
fn zero_share_targets_still_require_existing_compatible_leaf_accounts() {
    let mut h = Harness::new(false);
    for (target, expected) in [
        ("missing", code::UNKNOWN_ACCOUNT),
        ("summary", code::NOT_A_LEAF),
        ("eur-only", code::UNIT_POLICY),
    ] {
        let basis = h.basis(
            1,
            AllocationMethod::EqualSplitResidualFirst,
            &[("a", 1), (target, 1)],
        );
        let proposal = h.proposal(target, &basis);
        assert_eq!(proposal.legs.len(), 2, "zero target has no journal leg");
        h.assert_refusal(proposal, expected);
    }
    let valid = h.basis(
        1,
        AllocationMethod::EqualSplitResidualFirst,
        &[("a", 1), ("b", 1), ("c", 1)],
    );
    let proposal = h.proposal("valid-zero-shares", &valid);
    h.post(proposal, capability()).unwrap();
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (-1, 1, 0, 0)
    );
}

#[test]
fn named_negative_residual_is_an_explicit_opposite_side_leg() {
    let mut h = Harness::new(false);
    let basis = h.basis(
        1,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: account("a").0,
        },
        &[("a", 1), ("b", 1), ("c", 1)],
    );
    let proposal = h.proposal("rounding-correction", &basis);
    assert_eq!(
        proposal
            .legs
            .iter()
            .map(|leg| (leg.side, leg.amount.mantissa))
            .collect::<Vec<_>>(),
        [
            (Side::Credit, 1),
            (Side::Credit, 1),
            (Side::Debit, 1),
            (Side::Debit, 1)
        ]
    );
    h.post(proposal, capability()).unwrap();
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (-1, -1, 1, 1)
    );
}

#[test]
fn allocation_does_not_bypass_authority_periods_or_availability() {
    let mut h = Harness::new(false);
    let basis = h.basis(7, AllocationMethod::LargestRemainder, &[("a", 1)]);
    let mut proposal = basis
        .proposal(h.template("unauthorized", basis.driver_evidence(BOOK).unwrap()))
        .unwrap();
    let head = h.head();
    let refusal = h
        .post(
            proposal.clone(),
            Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        refusal.exit, 7,
        "authority precedes missing document observation"
    );
    assert_ne!(refusal.code, code::EVIDENCE_UNKNOWN);
    assert_eq!(h.head(), head);
    h.import_driver(&basis, 3);
    proposal.effective_date = day("2026-04-01"); // April is still Future.
    h.assert_refusal(proposal, code::PERIOD_LAW);

    let mut limited = Harness::new(true);
    let basis = limited.basis(7, AllocationMethod::LargestRemainder, &[("a", 1)]);
    let proposal = limited.proposal("overdraft", &basis);
    limited.assert_refusal(proposal, code::AVAILABILITY_LOWER);
    assert_eq!(limited.net("source"), 0);
}

#[test]
fn unreviewed_agent_driver_cannot_be_promoted_by_a_human_post() {
    let mut h = Harness::new(false);
    let basis = h.basis(7, AllocationMethod::LargestRemainder, &[("a", 1)]);
    let evidence = h.import_driver(&basis, 4); // AgentUpload; no independent review.
    let proposal = basis
        .proposal(h.template("self-sourced", evidence))
        .unwrap();
    h.assert_refusal(proposal, code::SELF_SOURCED);
}

#[test]
fn later_publication_invalidates_an_uncommitted_allocation_plan() {
    let mut h = Harness::new(false);
    let basis = h.basis(7, AllocationMethod::LargestRemainder, &[("a", 1)]);
    let proposal = h.proposal("stale", &basis);
    let plan = h.plan(proposal.clone());
    let changed_basis = h.basis(8, AllocationMethod::LargestRemainder, &[("a", 1)]);
    h.import_driver(&changed_basis, 3);
    let head = h.head();
    let refusal = h.commit(plan).unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert_eq!(h.head(), head);
    assert_eq!(h.net("source"), 0);
    let refreshed = h.plan(proposal);
    h.commit(refreshed).unwrap();
    assert_eq!(h.net("a"), 7);
}

#[test]
fn existing_effects_are_not_discarded_by_the_typed_constructor() {
    let h = Harness::new(false);
    let basis = h.basis(7, AllocationMethod::LargestRemainder, &[("a", 1)]);
    let mut template = h.template("occupied", basis.driver_evidence(BOOK).unwrap());
    template.legs.push(LegPayload::simple(
        Side::Debit,
        account("b"),
        Amount::new(h.usd, 7),
    ));
    assert_eq!(basis.proposal(template).unwrap_err().code, code::STRUCTURE);
}

#[test]
fn allocation_reversal_and_reversal_of_reversal_preserve_exact_lineage() {
    let mut h = Harness::new(false);
    let basis = h.basis(
        10_000,
        AllocationMethod::LargestRemainder,
        &[("a", 1), ("b", 1), ("c", 1)],
    );
    let proposal = h.proposal("original-allocation", &basis);
    let original = h.post(proposal.clone(), capability()).unwrap().entry_ref();
    let reversal = h.reversal("reverse-allocation", original);
    assert!(
        reversal.extensions.is_empty(),
        "correction cites the original instead of impersonating its allocation"
    );
    let reversal = h.post(reversal, capability()).unwrap().entry_ref();
    for code in ["source", "a", "b", "c"] {
        assert_eq!(h.net(code), 0);
    }
    let duplicate = h.reversal("duplicate-reversal", original);
    h.assert_refusal(duplicate, code::ALREADY_REVERSED);
    let restoration = h.reversal("restore-allocation", reversal);
    h.post(restoration, capability()).unwrap();
    assert_eq!(
        (h.net("source"), h.net("a"), h.net("b"), h.net("c")),
        (-10_000, 3334, 3333, 3333)
    );
    let (stored, _) = h.book.read_entry(&h.cx(), original.vid).unwrap().unwrap();
    assert_eq!(
        stored.proposal, proposal,
        "correction never rewrites the original driver or amounts"
    );
    assert_eq!(
        h.book.fold_period(&h.cx(), "FY2026-P03").unwrap().entries,
        3
    );
}
