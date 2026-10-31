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

use crate::{BookKeys, Entropy, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms};
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};

const BOOK: Id128 = Id128([0x76; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "settlement-group";
fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn account(code: &str) -> VId {
    account_vid(BOOK, code)
}
fn cap() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}
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
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                BookKeys::for_development(118),
                BookSpec {
                    book_id: BOOK,
                    name: "Atomic settlement group fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(118),
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
            bytes: b"evidence for atomic settlement groups".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
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

    fn value(
        &mut self,
        proposal: EntryPayload,
        law: FxLawId,
        numerator: u128,
        denominator: u128,
    ) -> EntryPayload {
        let cx = self.cx();
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: numerator,
                rate_den: denominator,
                rounding: RoundingLaw::HalfEven,
            },
            proposal.effective_date,
            1_767_571_200_000_000_000,
            if law == FxLawId::SpotClose {
                FxRatePurpose::SpotClose
            } else {
                FxRatePurpose::Settlement
            },
            "explicit retained EUR fixture quote",
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

    fn invoice(&mut self, key: &str, amount: i128) -> EntryRef {
        self.post(self.proposal(
            key,
            vec![
                leg(Side::Debit, "receivable", self.usd, amount),
                leg(Side::Credit, "capital", self.usd, amount),
            ],
        ))
    }

    fn prepare(&mut self, request: SettlementGroupRequest) -> PreparedSettlementGroup {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.prepare_settlement_group(&cx, request, &cap()))
            .unwrap()
            .unwrap()
    }

    fn plan(&mut self, request: SettlementGroupRequest) -> SettlementGroupPostPlan {
        let cx = self.cx();
        self.runtime
            .block_on(
                self.book
                    .plan_settlement_group(&cx, request, Vec::new(), &cap()),
            )
            .unwrap()
            .unwrap()
    }

    fn commit(&mut self, plan: SettlementGroupPostPlan) -> Posted {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.commit_settlement_group_plan(&cx, plan, &cap()))
            .unwrap()
            .unwrap()
    }

    fn open(&self, entry: EntryRef, ordinal: u16) -> i128 {
        self.book
            .open_items(&self.cx(), None, None)
            .unwrap()
            .into_iter()
            .find(|item| item.entry == entry.vid && item.ordinal == ordinal)
            .unwrap()
            .open
    }

    fn consume(&mut self, invoice: EntryRef, amount: i128) {
        let request = SettlementPostRequest {
            proposal: self.proposal(
                "competing-receipt",
                vec![
                    leg(Side::Debit, "cash", self.usd, amount),
                    leg(Side::Credit, "receivable", self.usd, amount),
                ],
            ),
            payment_leg: 1,
            targets: vec![(invoice.vid, 0)],
        };
        let cx = self.cx();
        let plan = self
            .runtime
            .block_on(self.book.plan_settlement(&cx, request, Vec::new(), &cap()))
            .unwrap()
            .unwrap();
        self.runtime
            .block_on(self.book.commit_settlement_plan(&cx, plan, &cap()))
            .unwrap()
            .unwrap();
    }

    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            book,
            vfs,
            evidence,
            usd,
            eur,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                BookKeys::for_development(118),
                Entropy::deterministic(119),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            evidence,
            usd,
            eur,
        }
    }
}

fn fixture() -> (Harness, EntryRef, EntryRef, SettlementGroupRequest) {
    let mut h = Harness::new();
    let invoice = h.invoice("usd-invoice", 100);
    let bill = h.proposal(
        "eur-bill",
        vec![
            leg(Side::Debit, "cash", h.eur, 70),
            leg(Side::Credit, "payable", h.eur, 70),
        ],
    );
    let bill = h.value(bill, FxLawId::SpotClose, 1, 1);
    let bill = h.post(bill);
    let proposal = h.proposal(
        "group-payment",
        vec![
            leg(Side::Debit, "cash", h.usd, 125),
            leg(Side::Credit, "receivable", h.usd, 125),
            leg(Side::Debit, "payable", h.eur, 60),
            leg(Side::Credit, "cash", h.eur, 60),
        ],
    );
    let proposal = h.value(proposal, FxLawId::SettlementSpotCarrying, 1, 1);
    let request = SettlementGroupRequest {
        proposal,
        payments: vec![
            SettlementLegSelection {
                payment_leg: 2,
                targets: vec![(bill.vid, 1)],
            },
            SettlementLegSelection {
                payment_leg: 1,
                targets: vec![(invoice.vid, 0)],
            },
        ],
    };
    (h, invoice, bill, request)
}

/// The capability gap these original EUR fixtures expose (fa-pvt7): since 7df9b1ac3
/// a foreign-currency applying leg must carry its source-bound
/// RemainingCarryingValue basis. A raw group applying a EUR bill without
/// retained valuation evidence must still refuse FA-REF-071 and publish nothing.
#[test]
fn foreign_currency_application_in_a_group_is_refused_without_its_carrying_basis() {
    let mut h = Harness::new();
    let eur = UnitRegistry::embedded().unwrap().lookup("EUR").unwrap();
    let bill = h.post(h.proposal(
        "eur-bill",
        vec![
            leg(Side::Debit, "cash", eur, 70),
            leg(Side::Credit, "payable", eur, 70),
        ],
    ));
    let request = SettlementGroupRequest {
        proposal: h.proposal(
            "eur-group",
            vec![
                leg(Side::Debit, "payable", eur, 60),
                leg(Side::Credit, "cash", eur, 60),
            ],
        ),
        payments: vec![SettlementLegSelection {
            payment_leg: 0,
            targets: vec![(bill.vid, 1)],
        }],
    };
    let at = h.head();
    let cx = h.cx();
    let refused = h
        .runtime
        .block_on(
            h.book
                .plan_settlement_group(&cx, request, Vec::new(), &cap()),
        )
        .unwrap()
        .expect_err("a foreign application without its carrying basis");
    assert_eq!(refused.code, "FA-REF-071", "{refused:?}");
    assert!(
        refused.message.contains("RemainingCarryingValue"),
        "{refused:?}"
    );
    assert_eq!(h.head(), at, "nothing is published");
    assert_eq!(h.open(bill, 1), 70, "the bill stays open");
}

#[test]
fn mixed_native_units_and_debit_credit_applications_publish_as_one_entry() {
    let (mut h, invoice, bill, request) = fixture();
    let at = h.head();
    let prepared = h.prepare(request.clone());
    let mut expected = request.proposal.clone();
    expected.legs[1].settles = vec![fa_model::Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(h.usd, 100),
    }];
    expected.legs[2].settles = vec![fa_model::Settlement {
        target: bill,
        ordinal: 1,
        amount: Amount::new(h.eur, 60),
    }];
    assert_eq!(
        prepared.proposal(),
        &expected,
        "only the selected settles lists change"
    );
    assert_eq!(prepared.known_at(), at);
    assert_eq!(
        prepared
            .allocations()
            .iter()
            .map(|a| a.payment_leg)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(
        prepared
            .allocations()
            .iter()
            .all(|a| a.allocation.known_at == at)
    );
    assert_eq!(prepared.allocations()[0].allocation.unapplied, 25);
    assert_eq!(prepared.allocations()[1].allocation.unapplied, 0);
    let mut reordered = request.clone();
    reordered.payments.reverse();
    assert_eq!(
        h.prepare(reordered),
        prepared,
        "selection order is not accounting order"
    );
    let cx = h.cx();
    let plan = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement_group(&cx, prepared, Vec::new(), &cap()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(plan.post_plan().intent().proposal(), &expected);
    assert_eq!(h.head(), at, "preparation and rehearsal publish nothing");
    let posted = h.commit(plan);
    assert_eq!(posted.recorded_at(), CommitSeq(at.0 + 1));
    assert_eq!(h.open(invoice, 0), 0);
    assert_eq!(h.open(bill, 1), 10);
    assert_eq!(h.open(posted.entry_ref(), 1), 25);
    assert_eq!(h.open(posted.entry_ref(), 2), 0);
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
    assert!(h.book.verify_fx_conversions(&cx, None).unwrap().is_green());
}

#[test]
fn foreign_spot_group_refuses_changed_quote_without_publishing_native_half() {
    let (mut h, invoice, bill, mut request) = fixture();
    request.proposal.base_totals = None;
    for leg in &mut request.proposal.legs {
        leg.base_amount = None;
    }
    // Drop only the former Rate citation; the business evidence is retained.
    request
        .proposal
        .evidence
        .retain(|evidence| evidence.role != 3);
    request.proposal = h.value(request.proposal, FxLawId::SettlementSpotCarrying, 2, 1);
    let at = h.head();
    let cx = h.cx();
    let refused = h
        .runtime
        .block_on(
            h.book
                .plan_settlement_group(&cx, request, Vec::new(), &cap()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-071");
    assert!(refused.message.contains("RemainingCarryingValue"));
    assert_eq!(h.head(), at);
    assert_eq!(h.open(invoice, 0), 100);
    assert_eq!(h.open(bill, 1), 70);
}

#[test]
fn foreign_spot_group_records_partial_relief_separately_from_complete_payment_leg() {
    let (mut h, invoice, bill, mut request) = fixture();
    let proposal = h.proposal(
        "overpayment-group",
        vec![
            leg(Side::Debit, "cash", h.usd, 125),
            leg(Side::Credit, "receivable", h.usd, 125),
            leg(Side::Debit, "payable", h.eur, 80),
            leg(Side::Credit, "cash", h.eur, 80),
        ],
    );
    request.proposal = h.value(proposal, FxLawId::SettlementSpotCarrying, 1, 1);
    let plan = h.plan(request);
    let posted = h.commit(plan);
    assert_eq!(h.open(invoice, 0), 0);
    assert_eq!(h.open(bill, 1), 0);
    assert_eq!(h.open(posted.entry_ref(), 2), 10);
    let cx = h.cx();
    let item = h
        .book
        .query(&cx, |db, book| {
            Ok(fa_journal::carrying::open_item_carrying_at(
                db,
                &cx,
                book,
                bill,
                1,
                h.head(),
            )?)
        })
        .unwrap()
        .unwrap();
    assert_eq!(item.applied_native, Amount::new(h.eur, 70));
    assert_eq!(item.applied_base, Amount::new(h.usd, 70));
    assert_eq!(item.open_base, Amount::new(h.usd, 0));
    assert!(h.book.verify_fx_conversions(&cx, None).unwrap().is_green());
    let h = h.reopen();
    assert_eq!(h.open(posted.entry_ref(), 2), 10);
    assert!(
        h.book
            .verify_fx_conversions(&h.cx(), None)
            .unwrap()
            .is_green()
    );
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
    let retry = h
        .runtime
        .block_on(
            h.book
                .commit_plan(&cx, PostPlan::decode(&bytes).unwrap(), &cap()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.head(), head);
    assert_eq!(h.open(invoice, 0), 0);
    assert_eq!(h.open(bill, 1), 10);
}

#[test]
fn foreign_spot_group_final_rounding_and_later_reversal_restore_recorded_relief() {
    let mut h = Harness::new();
    let source = h.proposal(
        "rounding-source",
        vec![
            leg(Side::Debit, "cash", h.eur, 3),
            leg(Side::Credit, "payable", h.eur, 3),
        ],
    );
    let source = h.value(source, FxLawId::SpotClose, 2, 3);
    let source = h.post(source);
    let request = |h: &mut Harness, key: &str, amount| {
        let proposal = h.proposal(
            key,
            vec![
                leg(Side::Debit, "payable", h.eur, amount),
                leg(Side::Credit, "cash", h.eur, amount),
            ],
        );
        SettlementGroupRequest {
            proposal: h.value(proposal, FxLawId::SettlementSpotCarrying, 2, 3),
            payments: vec![SettlementLegSelection {
                payment_leg: 0,
                targets: vec![(source.vid, 1)],
            }],
        }
    };
    let first = request(&mut h, "first-rounded", 1);
    let plan = h.plan(first);
    h.commit(plan);
    assert_eq!(h.open(source, 1), 2);
    // A one-cent partial relief now rounds to zero from the remaining
    // pool, while the immutable quote rounds it to one. Refuse the mismatch.
    let second = request(&mut h, "wrong-rounded", 1);
    let at = h.head();
    let cx = h.cx();
    let refusal = h
        .runtime
        .block_on(
            h.book
                .plan_settlement_group(&cx, second, Vec::new(), &cap()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-071");
    assert_eq!(h.head(), at);
    let final_payment = request(&mut h, "final-rounded", 2);
    let plan = h.plan(final_payment);
    let posted = h.commit(plan).entry_ref();
    assert_eq!(h.open(source, 1), 0);
    let mut undo = h
        .book
        .read_entry(&cx, posted.vid)
        .unwrap()
        .unwrap()
        .0
        .proposal;
    undo.class = EntryClass::REVERSAL;
    undo.effective_date = day("2026-03-21");
    undo.effective_period = None;
    undo.idempotency_key = b"undo-final-rounded".to_vec();
    for leg in &mut undo.legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        leg.settles.clear();
    }
    undo.unit_totals = EntryPayload::fold_unit_totals(&undo.legs).unwrap();
    undo.supersession = vec![fa_model::Supersession {
        target: posted,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    h.post(undo);
    assert_eq!(h.open(source, 1), 2);
    let item = h
        .book
        .query(&cx, |db, book| {
            Ok(fa_journal::carrying::open_item_carrying_at(
                db,
                &cx,
                book,
                source,
                1,
                h.head(),
            )?)
        })
        .unwrap()
        .unwrap();
    assert_eq!(item.open_base, Amount::new(h.usd, 1));
    assert!(h.book.verify_fx_conversions(&cx, None).unwrap().is_green());
}

#[test]
fn duplicate_applying_legs_and_overlapping_even_unused_targets_are_refused() {
    let (mut h, invoice, bill, base) = fixture();
    let mut cases = Vec::new();
    let mut duplicate = base.clone();
    duplicate.payments.push(duplicate.payments[0].clone());
    cases.push(duplicate);
    let mut duplicate = base.clone();
    duplicate.payments[0].targets.push((invoice.vid, 0));
    cases.push(duplicate);
    let mut duplicate = base.clone();
    duplicate.payments[0].targets.push((bill.vid, 1));
    cases.push(duplicate);
    let mut empty = base.clone();
    empty.payments.clear();
    cases.push(empty);
    let mut too_many = base.clone();
    too_many.payments = vec![too_many.payments[0].clone(); MAX_SETTLEMENT_GROUP_LEGS + 1];
    cases.push(too_many);
    let mut too_many = base.clone();
    too_many.payments = (0..5)
        .map(|_| SettlementLegSelection {
            payment_leg: 1,
            targets: vec![(invoice.vid, 0); MAX_SETTLES_PER_LEG],
        })
        .collect();
    cases.push(too_many);
    let mut bad_ordinal = base;
    bad_ordinal.payments[0].payment_leg = u16::MAX;
    cases.push(bad_ordinal);
    let at = h.head();
    let cx = h.cx();
    for request in cases {
        let refusal = h
            .runtime
            .block_on(h.book.prepare_settlement_group(&cx, request, &cap()))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE);
        assert_eq!(h.head(), at);
    }
    assert_eq!(h.open(invoice, 0), 100);
    assert_eq!(h.open(bill, 1), 70);
}

#[test]
fn invalid_later_selection_returns_no_partial_payment() {
    let (mut h, invoice, bill, base) = fixture();
    let at = h.head();
    let cx = h.cx();
    // Canonical order prepares the invoice first, then encounters the bad bill.
    let mut missing = base.clone();
    missing.payments[0].targets.push((VId(u128::MAX), 0));
    let mut dimensions = base.clone();
    dimensions.proposal.legs[2].dimension_set = vec![(1, VId(99))];
    let mut overwritten = base;
    overwritten.proposal.legs[0].settles = vec![fa_model::Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(h.usd, 1),
    }];
    for request in [missing, dimensions, overwritten] {
        assert!(
            h.runtime
                .block_on(h.book.prepare_settlement_group(&cx, request, &cap()))
                .unwrap()
                .is_err()
        );
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
    let mut evidence = base;
    evidence.proposal.evidence.clear();
    // A valued EUR entry without its Rate citation is refused by the
    // earlier commitment check. Retain the generic empty-evidence control
    // independently, without weakening either precise refusal.
    let mut minimum = SettlementGroupRequest {
        proposal: h.proposal(
            "no-business-evidence",
            vec![
                leg(Side::Debit, "cash", h.usd, 60),
                leg(Side::Credit, "receivable", h.usd, 60),
            ],
        ),
        payments: vec![SettlementLegSelection {
            payment_leg: 1,
            targets: vec![(invoice.vid, 0)],
        }],
    };
    minimum.proposal.evidence.clear();
    let at = h.head();
    let cx = h.cx();
    for (request, code) in [
        (balance, fa_journal::refusal::code::UNBALANCED),
        (evidence, fa_journal::refusal::code::EVIDENCE_COMMIT),
        (minimum, fa_journal::refusal::code::EVIDENCE_MINIMUM),
    ] {
        let prepared = h.prepare(request);
        let refusal = h
            .runtime
            .block_on(
                h.book
                    .plan_prepared_settlement_group(&cx, prepared, Vec::new(), &cap()),
            )
            .unwrap()
            .unwrap_err();
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
    let at = h.head();
    let cx = h.cx();
    let capabilities = [
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        cap().for_books(&[Id128([0x77; 16])]).unwrap(),
        cap().expiring_at(at),
        cap()
            .with_ceiling(h.usd, 100)
            .unwrap()
            .with_ceiling(h.eur, 100)
            .unwrap(),
    ];
    for capability in capabilities {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .prepare_settlement_group(&cx, base.clone(), &capability)
                )
                .unwrap()
                .is_err()
        );
        assert!(
            h.runtime
                .block_on(h.book.plan_prepared_settlement_group(
                    &cx,
                    prepared.clone(),
                    Vec::new(),
                    &capability
                ))
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
    let mut bad = base;
    bad.payments.clear();
    let denial = h
        .runtime
        .block_on(h.book.prepare_settlement_group(
            &cx,
            bad,
            &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denial.code, "FA-REF-011",
        "read admission precedes even group shape inspection"
    );
}

#[test]
fn competing_consumption_invalidates_the_whole_group_not_only_one_leg() {
    let (mut h, invoice, bill, request) = fixture();
    let plan = h.plan(request);
    h.consume(invoice, 30);
    let at = h.head();
    let cx = h.cx();
    let result = h
        .runtime
        .block_on(h.book.commit_settlement_group_plan(&cx, plan, &cap()))
        .unwrap();
    assert!(result.is_err());
    assert_eq!(h.head(), at);
    assert_eq!(h.open(invoice, 0), 70);
    assert_eq!(
        h.open(bill, 1),
        70,
        "the other selection must not commit alone"
    );
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

mod review;
