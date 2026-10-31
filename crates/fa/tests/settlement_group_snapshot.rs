//! Shared-snapshot preparation must reproduce the established single-leg
//! semantics and still publish only through the ordinary atomic kernel plan.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{
    AsyncBook, BookKeys, Entropy, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms,
    MAX_SETTLEMENT_GROUP_LEGS, PostPlan, SettlementGroupRequest, SettlementLegSelection,
    SettlementPostRequest,
};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x79; 16]);
const PRINCIPAL: VId = VId(7);

fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn cap() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}
fn leg(side: Side, code: &str, unit: UnitId, amount: i128) -> LegPayload {
    LegPayload::simple(side, account_vid(BOOK, code), Amount::new(unit, amount))
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
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
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                MemVfs::new().unwrap(),
                Path::new("shared-settlement-snapshot"),
                BookKeys::for_development(121),
                BookSpec {
                    book_id: BOOK,
                    name: "Shared settlement snapshot".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(121),
            ))
            .unwrap();
        let chart = ["cash", "receivable", "payable", "capital"]
            .into_iter()
            .map(|code| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: match code {
                    "payable" => 2,
                    "capital" => 3,
                    _ => 1,
                },
                normal_balance: u8::from(matches!(code, "payable" | "capital")),
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
        let document = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"shared snapshot settlement evidence".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            evidence: document.evidence_ref(1),
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

    fn proposal(&self, key: &str, legs: Vec<LegPayload>) -> EntryPayload {
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day("2026-03-20"),
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

    fn post(&mut self, proposal: EntryPayload) -> EntryRef {
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
            .unwrap()
            .entry_ref()
    }
    fn value(&mut self, proposal: EntryPayload, law: FxLawId) -> EntryPayload {
        let cx = self.cx();
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: 1,
                rate_den: 1,
                rounding: RoundingLaw::HalfEven,
            },
            proposal.effective_date,
            1_767_571_200_000_000_000,
            if law == FxLawId::SpotClose {
                FxRatePurpose::SpotClose
            } else {
                FxRatePurpose::Settlement
            },
            "explicit retained EUR shared snapshot quote",
        )
        .unwrap();
        let oid = self
            .runtime
            .block_on(self.book.upload_fx_rate(&cx, &cap(), &rate))
            .unwrap()
            .unwrap()
            .oid;
        let stripped = self.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        self.runtime
            .block_on(
                self.book
                    .value_fx_proposal(&cx, &cap(), proposal, law, &[oid], &mut budget),
            )
            .unwrap()
            .unwrap()
    }
}

// Distinct accounts, currencies and sides deliberately share ONE source entry.
fn fixture(amount: i128) -> (Harness, EntryRef, SettlementGroupRequest) {
    let mut h = Harness::new();
    let source = h.proposal(
        "source",
        vec![
            leg(Side::Debit, "receivable", h.usd, amount),
            leg(Side::Credit, "capital", h.usd, amount),
            leg(Side::Debit, "cash", h.eur, 70),
            leg(Side::Credit, "payable", h.eur, 70),
        ],
    );
    let source = h.value(source, FxLawId::SpotClose);
    let source = h.post(source);
    let proposal = h.proposal(
        "payment",
        vec![
            leg(Side::Debit, "cash", h.usd, amount + 25),
            leg(Side::Credit, "receivable", h.usd, amount + 25),
            leg(Side::Debit, "payable", h.eur, 60),
            leg(Side::Credit, "cash", h.eur, 60),
        ],
    );
    let proposal = h.value(proposal, FxLawId::SettlementSpotCarrying);
    let request = SettlementGroupRequest {
        proposal,
        payments: vec![
            SettlementLegSelection {
                payment_leg: 2,
                targets: vec![(source.vid, 3)],
            },
            SettlementLegSelection {
                payment_leg: 1,
                targets: vec![(source.vid, 0)],
            },
        ],
    };
    (h, source, request)
}

#[test]
fn shared_snapshot_matches_each_single_leg_and_preserves_full_source_digests() {
    let (mut h, source, request) = fixture((1_i128 << 100) + 1);
    let at = h.head();
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_settlement_group(&cx, request.clone(), &cap()),
        )
        .unwrap()
        .unwrap();
    let mut expected = request.proposal.clone();
    for selection in &request.payments {
        let single = h
            .runtime
            .block_on(h.book.prepare_settlement(
                &cx,
                SettlementPostRequest {
                    proposal: request.proposal.clone(),
                    payment_leg: selection.payment_leg,
                    targets: selection.targets.clone(),
                },
                &cap(),
            ))
            .unwrap()
            .unwrap();
        let group = prepared
            .allocations()
            .iter()
            .find(|part| part.payment_leg == selection.payment_leg)
            .unwrap();
        assert_eq!(&group.allocation, single.allocation());
        assert_eq!(group.allocation.known_at, at);
        let ordinal = usize::from(selection.payment_leg);
        expected.legs[ordinal].settles = single.proposal().legs[ordinal].settles.clone();
        assert_eq!(expected.legs[ordinal].settles[0].target, source);
    }
    assert_eq!(prepared.proposal(), &expected);
    assert_eq!(prepared.known_at(), at);
    assert_eq!(prepared.allocations()[0].allocation.unapplied, 25);
    assert_eq!(
        h.head(),
        at,
        "preparation must not publish or reserve capacity"
    );
}

#[test]
fn invalid_unused_target_in_later_selection_returns_no_partial_group() {
    let (mut h, source, mut request) = fixture(100);
    // The valid payable target already covers the entire payment; an extra
    // capital/USD target is nevertheless ineligible and must be checked.
    request.payments[0].targets.push((source.vid, 1));
    let at = h.head();
    let cx = h.cx();
    assert!(
        h.runtime
            .block_on(h.book.prepare_settlement_group(&cx, request, &cap()))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
}

#[test]
fn full_entry_read_and_post_admission_are_required_before_preparation() {
    let (mut h, _, request) = fixture(100);
    let at = h.head();
    let cx = h.cx();
    for operations in [vec!["read"], vec!["post"]] {
        let capability = Capability::embedded(PRINCIPAL, &operations).unwrap();
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .prepare_settlement_group(&cx, request.clone(), &capability)
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
}

#[test]
fn prepared_shared_snapshot_still_commits_atomically_and_retries_the_same_plan() {
    let (mut h, source, request) = fixture(100);
    let cx = h.cx();
    let at = h.head();
    let prepared = h
        .runtime
        .block_on(h.book.prepare_settlement_group(&cx, request, &cap()))
        .unwrap()
        .unwrap();
    let plan = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement_group(&cx, prepared, Vec::new(), &cap()),
        )
        .unwrap()
        .unwrap();
    let saved = plan.post_plan().canonical_bytes().unwrap();
    let posted = h
        .runtime
        .block_on(h.book.commit_settlement_group_plan(&cx, plan, &cap()))
        .unwrap()
        .unwrap();
    assert_eq!(posted.recorded_at(), CommitSeq(at.0 + 1));
    let head = h.head();
    let retry = h
        .runtime
        .block_on(
            h.book
                .commit_plan(&cx, PostPlan::decode(&saved).unwrap(), &cap()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.head(), head);
    let items = h.book.open_items(&cx, None, None).unwrap();
    assert_eq!(
        items
            .iter()
            .find(|item| item.entry == source.vid && item.ordinal == 0)
            .unwrap()
            .open,
        0
    );
    assert_eq!(
        items
            .iter()
            .find(|item| item.entry == source.vid && item.ordinal == 3)
            .unwrap()
            .open,
        10
    );
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

#[test]
fn maximum_supported_selections_share_one_basis_and_one_source_entry() {
    let mut h = Harness::new();
    let count = MAX_SETTLEMENT_GROUP_LEGS.min(fa_model::limits::MAX_LEGS_PER_ENTRY / 2);
    assert!(count > 1);
    let mut source_legs = Vec::new();
    let mut payment_legs = Vec::new();
    for _ in 0..count {
        source_legs.extend([
            leg(Side::Debit, "receivable", h.usd, 100),
            leg(Side::Credit, "capital", h.usd, 100),
        ]);
        payment_legs.extend([
            leg(Side::Debit, "cash", h.usd, 60),
            leg(Side::Credit, "receivable", h.usd, 60),
        ]);
    }
    let source = h.post(h.proposal("many-targets", source_legs));
    let request = SettlementGroupRequest {
        proposal: h.proposal("many-payments", payment_legs),
        payments: (0..count)
            .rev()
            .map(|index| SettlementLegSelection {
                payment_leg: u16::try_from(index * 2 + 1).unwrap(),
                targets: vec![(source.vid, u16::try_from(index * 2).unwrap())],
            })
            .collect(),
    };
    let at = h.head();
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(h.book.prepare_settlement_group(&cx, request, &cap()))
        .unwrap()
        .unwrap();
    assert_eq!(prepared.allocations().len(), count);
    for part in prepared.allocations() {
        assert_eq!(part.allocation.known_at, at);
        assert_eq!(part.allocation.allocations.len(), 1);
        let applied = &part.allocation.allocations[0];
        assert_eq!(
            (applied.open_before, applied.amount, applied.open_after),
            (100, 60, 40)
        );
        let settles = &prepared.proposal().legs[usize::from(part.payment_leg)].settles;
        assert_eq!(settles[0].target, source);
    }
    assert_eq!(h.head(), at);
}
