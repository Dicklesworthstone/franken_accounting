//! Real-kernel settlement preparation, publication and exact-plan retries.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{AsyncBook, BookKeys, Capability, Entropy, SettlementPostPlan, SettlementPostRequest};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x52; 16]);
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
                Path::new("settlement-book"),
                BookKeys::for_development(82),
                BookSpec {
                    book_id: BOOK,
                    name: "Settlement fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(82),
            ))
            .unwrap();
        let chart = ["cash", "receivable", "payable", "capital"]
            .into_iter()
            .map(|code| {
                let credit = matches!(code, "payable" | "capital");
                AccountSpec {
                    code: code.into(),
                    name: code.into(),
                    account_type: match code {
                        "payable" => 2,
                        "capital" => 3,
                        _ => 1,
                    },
                    normal_balance: u8::from(credit),
                    is_leaf: true,
                    unit_policy: UnitPolicy::AnyCurrency,
                    parent_code: None,
                    limit: None,
                }
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
        let doc = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"settlement fixture evidence".to_vec(),
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

    fn post(&mut self, proposal: EntryPayload) -> Posted {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: capability(),
                },
            ))
            .unwrap()
            .unwrap()
    }

    fn invoice(&mut self, key: &str, date: &str, amount: i128) -> EntryRef {
        let proposal = self.proposal(key, date, "receivable", "capital", amount);
        self.post(proposal).entry_ref()
    }

    fn receipt(&self, key: &str, amount: i128, invoices: &[EntryRef]) -> SettlementPostRequest {
        SettlementPostRequest {
            proposal: self.proposal(key, "2026-03-20", "cash", "receivable", amount),
            payment_leg: 1,
            targets: invoices.iter().map(|entry| (entry.vid, 0)).collect(),
        }
    }

    fn plan(&mut self, request: SettlementPostRequest) -> SettlementPostPlan {
        let cx = self.cx();
        self.runtime
            .block_on(
                self.book
                    .plan_settlement(&cx, request, Vec::new(), &capability()),
            )
            .unwrap()
            .unwrap()
    }

    fn commit(&mut self, plan: SettlementPostPlan) -> Posted {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.commit_settlement_plan(&cx, plan, &capability()))
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
}

#[test]
fn fifo_preparation_binds_full_digests_and_changes_only_the_selected_settles_list() {
    let mut h = Harness::new();
    let newer = h.invoice("newer", "2026-03-12", 70);
    let older = h.invoice("older", "2026-03-10", 100);
    let request = h.receipt("receipt", 130, &[newer, older]);
    let at = h.head();
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_settlement(&cx, request.clone(), &capability()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(prepared.allocation().known_at, at);
    assert_eq!(prepared.allocation().unapplied, 0);
    let mut expected = request.proposal.clone();
    expected.legs[1].settles = vec![
        fa_model::Settlement {
            target: older,
            ordinal: 0,
            amount: Amount::new(h.usd, 100),
        },
        fa_model::Settlement {
            target: newer,
            ordinal: 0,
            amount: Amount::new(h.usd, 30),
        },
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
    assert_eq!(
        h.head(),
        committed_at,
        "exact retry must not publish a second payment"
    );
}

#[test]
fn overpayment_is_an_explicit_unapplied_credit_not_a_writeoff_or_balancing_plug() {
    let mut h = Harness::new();
    let invoice = h.invoice("invoice", "2026-03-10", 100);
    let plan = h.plan(h.receipt("overpayment", 125, &[invoice]));
    assert_eq!(plan.allocation().allocations[0].amount, 100);
    assert_eq!(plan.allocation().unapplied, 25);
    assert_eq!(plan.post_plan().proposal().legs.len(), 2);
    assert!(
        plan.post_plan()
            .proposal()
            .legs
            .iter()
            .all(|leg| leg.amount.mantissa == 125)
    );
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
        payment_leg: 0,
        targets: vec![(bill.vid, 1)],
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
            Path::new("settlement-book"),
            BookKeys::for_development(82),
            Entropy::deterministic(83),
        ))
        .unwrap();
    let plan = fa::PostPlan::decode(&portable).unwrap();
    let retry = runtime
        .block_on(reopened.commit_plan(&cx, plan, &capability()))
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(reopened.head(&cx).unwrap(), head);
    let items = reopened
        .open_items(&cx, Some(account("receivable")), None)
        .unwrap();
    assert_eq!(
        items
            .iter()
            .find(|item| item.entry == invoice.vid && item.ordinal == 0)
            .unwrap()
            .open,
        40
    );
    assert!(reopened.verify_open_items(&cx).unwrap().is_green());
}

#[test]
fn reviewed_preparation_is_exact_and_an_unrelated_commit_requires_explicit_refresh() {
    let mut h = Harness::new();
    let invoice = h.invoice("review-invoice", "2026-03-10", 100);
    let request = h.receipt("review-payment", 60, &[invoice]);
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_settlement(&cx, request.clone(), &capability()),
        )
        .unwrap()
        .unwrap();
    let at = h.head();
    let plan = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement(&cx, prepared.clone(), Vec::new(), &capability()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(plan.allocation(), prepared.allocation());
    assert_eq!(plan.post_plan().intent().proposal(), prepared.proposal());
    assert_eq!(h.head(), at);

    let _ = h.invoice("unrelated-review-publication", "2026-03-11", 5);
    let advanced = h.head();
    let refusal = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement(&cx, prepared.clone(), Vec::new(), &capability()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(refusal.exit, fa_journal::exit::CONFLICT);
    assert_eq!(prepared.allocation().known_at, at);
    assert_eq!(
        h.head(),
        advanced,
        "refusal must not publish the reviewed payment"
    );
    assert_eq!(h.open(invoice, 0), 100);

    // Refresh is a separate, explicit operation that produces a newly reviewed
    // basis even when the actual allocations happen to be numerically equal.
    let fresh = h.plan(request);
    assert_eq!(fresh.allocation().known_at, advanced);
    assert_eq!(
        fresh.allocation().allocations,
        prepared.allocation().allocations
    );
    assert_eq!(h.head(), advanced);
}

#[test]
fn reviewed_payment_is_never_silently_reallocated_after_a_competing_application() {
    let mut h = Harness::new();
    let invoice = h.invoice("competing-invoice", "2026-03-10", 100);
    let request = h.receipt("reviewed-eightytotal", 80, &[invoice]);
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_settlement(&cx, request.clone(), &capability()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(prepared.allocation().allocations[0].amount, 80);
    assert_eq!(prepared.allocation().unapplied, 0);
    let other = h.plan(h.receipt("other-payment", 60, &[invoice]));
    h.commit(other);
    let head = h.head();
    let refusal = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement(&cx, prepared, Vec::new(), &capability()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::OVER_APPLICATION);
    assert_eq!(h.head(), head);
    assert_eq!(h.open(invoice, 0), 40);
    let fresh = h.plan(request);
    assert_eq!(fresh.allocation().allocations[0].amount, 40);
    assert_eq!(
        fresh.allocation().unapplied,
        40,
        "a changed allocation must require new review"
    );
    assert_eq!(h.head(), head);
}

#[test]
fn independently_planned_payments_cannot_both_spend_the_same_open_amount() {
    let mut h = Harness::new();
    let invoice = h.invoice("shared-invoice", "2026-03-10", 100);
    let first = h.plan(h.receipt("first-spender", 60, &[invoice]));
    let second = h.plan(h.receipt("second-spender", 60, &[invoice]));
    assert_eq!(first.allocation().known_at, second.allocation().known_at);
    let receipt = h.commit(first.clone());
    let head = h.head();
    let cx = h.cx();
    let refusal = h
        .runtime
        .block_on(h.book.commit_settlement_plan(&cx, second, &capability()))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(h.head(), head);
    assert_eq!(h.open(invoice, 0), 40);
    assert_eq!(h.commit(first).entry_ref(), receipt.entry_ref());
    assert_eq!(h.head(), head);
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

#[test]
fn authority_is_required_before_target_observation_and_again_before_planning_or_commit() {
    let mut h = Harness::new();
    let invoice = h.invoice("authority-invoice", "2026-03-10", 100);
    let request = h.receipt("authority-payment", 60, &[invoice]);
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_settlement(&cx, request.clone(), &capability()),
        )
        .unwrap()
        .unwrap();
    let plan = h.plan(request.clone());
    let head = h.head();
    let denied = [
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
    ];
    for cap in &denied {
        let known = h
            .runtime
            .block_on(h.book.prepare_settlement(&cx, request.clone(), cap))
            .unwrap()
            .unwrap_err();
        let mut missing = request.clone();
        missing.targets = vec![(VId(u128::MAX), 0)];
        let unknown = h
            .runtime
            .block_on(h.book.prepare_settlement(&cx, missing, cap))
            .unwrap()
            .unwrap_err();
        assert_eq!(
            known, unknown,
            "unauthorized callers must not learn target existence"
        );
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .plan_prepared_settlement(&cx, prepared.clone(), Vec::new(), cap)
                )
                .unwrap()
                .is_err()
        );
        assert!(
            h.runtime
                .block_on(h.book.commit_settlement_plan(&cx, plan.clone(), cap))
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), head);
        assert_eq!(h.open(invoice, 0), 100);
    }
    h.commit(plan);
    assert_eq!(h.open(invoice, 0), 40);
}

#[test]
fn every_selected_target_and_request_boundary_is_checked_without_a_partial_payment() {
    let mut h = Harness::new();
    let invoice = h.invoice("boundary-invoice", "2026-03-10", 100);
    let base = h.receipt("boundary-payment", 60, &[invoice]);
    let mut cases = Vec::<(&str, SettlementPostRequest)>::new();
    let mut changed = base.clone();
    changed.targets.push((VId(u128::MAX), 0));
    cases.push(("missing target after payment would be exhausted", changed));
    let mut changed = base.clone();
    changed.targets.push(changed.targets[0]);
    cases.push(("duplicate target", changed));
    let mut changed = base.clone();
    changed.targets[0].1 = u16::MAX;
    cases.push(("unknown target ordinal", changed));
    let mut changed = base.clone();
    changed.targets[0].1 = 1;
    cases.push(("cross-account target", changed));
    let mut changed = base.clone();
    changed.targets.clear();
    cases.push(("empty target selection", changed));
    let mut changed = base.clone();
    changed.targets = vec![(invoice.vid, 0); fa_model::limits::MAX_SETTLES_PER_LEG + 1];
    cases.push(("oversized target selection", changed));
    let mut changed = base.clone();
    changed.payment_leg = u16::MAX;
    cases.push(("missing applying leg", changed));
    let mut changed = base.clone();
    changed.proposal.legs[1].account_ref = VId(u128::MAX);
    cases.push(("unknown applying account is a typed refusal", changed));
    let mut changed = base.clone();
    let eur = UnitRegistry::embedded().unwrap().lookup("EUR").unwrap();
    for leg in &mut changed.proposal.legs {
        leg.amount.unit = eur;
    }
    changed.proposal.unit_totals = EntryPayload::fold_unit_totals(&changed.proposal.legs).unwrap();
    cases.push(("wrong target unit", changed));
    let mut changed = base.clone();
    changed.proposal.legs[0].side = Side::Credit;
    changed.proposal.legs[1].side = Side::Debit;
    changed.proposal.unit_totals = EntryPayload::fold_unit_totals(&changed.proposal.legs).unwrap();
    cases.push(("target and applying leg have the same side", changed));
    let mut changed = base.clone();
    changed.proposal.effective_date = day("2026-03-05");
    cases.push(("target is effective after the payment", changed));
    let mut changed = base.clone();
    changed.proposal.legs[1].dimension_set = vec![(1, VId(99))];
    cases.push(("different party or entity dimensions", changed));
    let mut changed = base.clone();
    changed.proposal.legs[0].settles.push(fa_model::Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(h.usd, 1),
    });
    cases.push(("preexisting application on an unselected leg", changed));
    let mut changed = base.clone();
    changed.proposal.legs[1].amount.mantissa = 0;
    cases.push(("zero applying amount", changed));
    let mut changed = base.clone();
    changed.proposal.class = EntryClass::PENDING;
    cases.push(("unsupported payment class", changed));
    let mut changed = base.clone();
    changed.proposal.origin = EntryOrigin::Rule {
        rule_version_oid: Oid([2; 32]),
        event_ref: VId(9),
        inputs_digest: [3; 32],
    };
    cases.push(("unverified rule provenance", changed));
    let mut changed = base.clone();
    changed.proposal.book_id = Id128([0x53; 16]);
    cases.push(("foreign book", changed));
    let mut changed = base.clone();
    changed.proposal.branch_id = Id128([0x53; 16]);
    cases.push(("foreign branch", changed));
    let mut changed = base;
    changed.proposal.unit_totals[0].debits = 999;
    cases.push(("malformed redundant unit totals", changed));
    let head = h.head();
    let cx = h.cx();
    for (name, request) in cases {
        let refusal = h
            .runtime
            .block_on(h.book.prepare_settlement(&cx, request, &capability()))
            .unwrap()
            .expect_err(name);
        assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE, "{name}");
        assert_eq!(h.head(), head, "{name}");
        assert_eq!(h.open(invoice, 0), 100, "{name}");
    }
}

#[test]
fn all_closed_targets_do_not_turn_a_new_payment_into_unrelated_unapplied_cash() {
    let mut h = Harness::new();
    let invoice = h.invoice("closed-invoice", "2026-03-10", 100);
    let paid = h.plan(h.receipt("pay-in-full", 100, &[invoice]));
    h.commit(paid);
    let head = h.head();
    let request = h.receipt("another-payment", 100, &[invoice]);
    let cx = h.cx();
    let refusal = h
        .runtime
        .block_on(h.book.prepare_settlement(&cx, request, &capability()))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE);
    assert!(
        refusal
            .message
            .contains("no selected item has an open amount")
    );
    assert_eq!(h.head(), head);
    assert_eq!(h.open(invoice, 0), 0);
}

#[test]
fn production_balance_and_evidence_laws_cannot_be_bypassed_by_preparation() {
    let mut h = Harness::new();
    let invoice = h.invoice("kernel-laws-invoice", "2026-03-10", 100);
    let base = h.receipt("kernel-laws-payment", 60, &[invoice]);
    let head = h.head();
    let cx = h.cx();
    let mut unbalanced = base.clone();
    unbalanced.proposal.legs[0].amount.mantissa = 59;
    unbalanced.proposal.unit_totals =
        EntryPayload::fold_unit_totals(&unbalanced.proposal.legs).unwrap();
    let prepared = h
        .runtime
        .block_on(h.book.prepare_settlement(&cx, unbalanced, &capability()))
        .unwrap()
        .unwrap();
    assert_eq!(
        prepared.proposal().legs.len(),
        2,
        "no balancing plug is invented"
    );
    assert_eq!(prepared.proposal().legs[0].amount.mantissa, 59);
    let refusal = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement(&cx, prepared, Vec::new(), &capability()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::UNBALANCED);

    let mut missing_evidence = base;
    missing_evidence.proposal.evidence.clear();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_settlement(&cx, missing_evidence, &capability()),
        )
        .unwrap()
        .unwrap();
    let refusal = h
        .runtime
        .block_on(
            h.book
                .plan_prepared_settlement(&cx, prepared, Vec::new(), &capability()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::EVIDENCE_MINIMUM);
    assert_eq!(h.head(), head);
    assert_eq!(h.open(invoice, 0), 100);
}

#[test]
fn large_mantissas_remain_exact_through_allocation_posting_and_refolding() {
    let mut h = Harness::new();
    let invoice = h.invoice("large-invoice", "2026-03-10", 9_007_199_254_740_995);
    let plan = h.plan(h.receipt("large-payment", 9_007_199_254_740_993, &[invoice]));
    assert_eq!(
        plan.allocation().allocations[0].amount,
        9_007_199_254_740_993
    );
    assert_eq!(plan.allocation().allocations[0].open_after, 2);
    let posted = h.commit(plan);
    assert_eq!(h.open(invoice, 0), 2);
    assert_eq!(h.open(posted.entry_ref(), 1), 0);
    assert!(h.book.verify_open_items(&h.cx()).unwrap().is_green());
}
