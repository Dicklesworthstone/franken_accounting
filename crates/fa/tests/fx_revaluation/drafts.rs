//! A source-bound FX review survives draft controls, never a changed source.
//! Each publication is one intrinsic adjustment and its inert Promote control.

use super::*;
use fa_journal::DraftState;
use fa_policy::{Op, Profile, possession_digest};

const PLANNER: VId = VId(231);
const REVIEWER: VId = VId(232);
const DRAFT: &str = "reviewed-january-fx";

fn planner() -> Capability {
    Capability::new(PLANNER, Profile::Agent, &[Op::Read, Op::Post], PRINCIPAL).unwrap()
}

fn reviewer(ops: &[&str]) -> Capability {
    Capability::embedded(REVIEWER, ops).unwrap()
}

fn open(f: &mut Fixture, capability: &Capability, name: &str) {
    f.book
        .open_draft(
            capability.clone(),
            name,
            day(31),
            "Retained closing FX review",
        )
        .unwrap()
        .unwrap();
}

fn review(
    f: &mut Fixture,
    capability: &Capability,
    source: &str,
    rate: Oid,
    key: &[u8],
) -> PostIntent {
    review_mode(f, capability, source, rate, key, false)
}

fn review_mode(
    f: &mut Fixture,
    capability: &Capability,
    source: &str,
    rate: Oid,
    key: &[u8],
    item_allocation: bool,
) -> PostIntent {
    let mut request = f.request(source, rate);
    request.item_allocation = item_allocation;
    let prepared = f
        .book
        .prepare_fx_revaluation(&request, capability)
        .unwrap()
        .unwrap();
    let mut proposal = f.proposal(&prepared, key);
    proposal.principal_ref = capability.holder();
    let intent = PostIntent::new(proposal, Vec::new()).unwrap();
    PostIntent::decode(&intent.canonical_bytes().unwrap()).unwrap()
}

fn append(
    f: &mut Fixture,
    capability: &Capability,
    intent: PostIntent,
) -> fa_journal::DraftPlanned {
    f.book
        .plan_into_draft(capability.clone(), DRAFT, intent)
        .unwrap()
        .unwrap()
}

fn promote(f: &mut Fixture) -> Result<fa_journal::DraftPromoted, fa_journal::Refusal> {
    f.book
        .promote_draft(
            reviewer(&["read", "approve"]),
            DRAFT,
            day(31),
            "Independent approval of the exact retained FX adjustment",
        )
        .unwrap()
}

fn ordinary(f: &Fixture, key: &[u8]) -> PostIntent {
    let mut proposal = f.template(key, EntryClass::ORIGINAL, day(10));
    proposal.principal_ref = PLANNER;
    proposal.evidence = vec![f.invoice];
    proposal.legs = vec![
        LegPayload::simple(Side::Debit, f.account("6700"), Amount::new(f.usd, 100)),
        LegPayload::simple(Side::Credit, f.account("4700"), Amount::new(f.usd, 100)),
    ];
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    PostIntent::new(proposal, Vec::new()).unwrap()
}

fn assert_open_unchanged(f: &Fixture, before: CommitSeq, original: &fa_journal::DraftView) {
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(&f.book.draft(DRAFT).unwrap().unwrap(), original);
    assert_eq!(original.state, DraftState::Open);
}

#[test]
fn source_bound_fx_draft_rehearses_and_promotes_the_original_signed_delta_once() {
    for (liability, source, valuation, expected_delta, item_allocation) in [
        (false, "1200", "1290", 1_000, false),
        (true, "2200", "2290", -1_000, false),
        (false, "1200", "1290", 1_000, true),
        (true, "2200", "2290", -1_000, true),
    ] {
        let mut f = Fixture::new();
        let source_entry = f.post_source(b"draft-source-invoice", liability, 10_000);
        let source_before = f.book.read_entry(source_entry.vid).unwrap().unwrap();
        let rate = f.closing_rate(12);
        // Checkpoint maintenance must not move the original source coordinates
        // when the same journal is replayed into the separate rehearsal book.
        f.book
            .checkpoint(PRINCIPAL, &cap(&["read", "produce", "witness"]))
            .unwrap()
            .unwrap();
        let agent = planner();
        open(&mut f, &agent, DRAFT);
        let intent = review_mode(
            &mut f,
            &agent,
            source,
            rate.oid,
            b"draft-revaluation",
            item_allocation,
        );
        let proposal = intent.proposal().clone();
        let before = f.book.head().unwrap();
        assert_eq!(
            f.book
                .post(PostRequest {
                    proposal: proposal.clone(),
                    approvals: Vec::new(),
                    capability: agent.clone(),
                    plan_certificate: None,
                })
                .unwrap()
                .unwrap_err()
                .exit,
            7,
        );
        assert_eq!(f.book.head().unwrap(), before);
        let planned = append(&mut f, &agent, intent.clone());
        let reviewed_digest = planned.plan.unwrap().members()[0].entry.entry_digest;
        let retained = f.book.draft(DRAFT).unwrap().unwrap();
        assert_eq!(retained.intents[0].intent, intent);
        assert_eq!(retained.intents[0].capability, agent);

        // Retaining a later quote never silently reprices a saved proposal.
        let later_rate = f.closing_rate(13);
        assert_ne!(later_rate.oid, rate.oid);
        let before = f.book.head().unwrap();
        let certified = f
            .book
            .certify_draft_diff(REVIEWER, &reviewer(&["read", "produce"]), DRAFT, PERIOD)
            .unwrap()
            .unwrap();
        assert_eq!(certified.report.plans, 1);
        let row = certified
            .report
            .rows
            .iter()
            .find(|row| row.code == valuation)
            .unwrap();
        assert_eq!(row.delta, expected_delta);
        let (mut scratch, rehearsal) = f
            .book
            .rehearse_draft_at(REVIEWER, &reviewer(&["read"]), DRAFT, before)
            .unwrap()
            .unwrap();
        assert_eq!(rehearsal.batch.entries, certified.report.entries);
        assert_eq!(rehearsal.batch.entries[0].entry_digest, reviewed_digest);
        assert!(
            rehearsal
                .seq_map
                .pairs
                .iter()
                .all(|pair| pair.source_seq == pair.scratch_seq)
        );
        let mut scratch_request = f.request(source, rate.oid);
        scratch_request.item_allocation = item_allocation;
        assert!(
            scratch
                .prepare_fx_revaluation(&scratch_request, &author())
                .unwrap()
                .unwrap()
                .is_noop(),
            "the hypothetical signed adjustment exactly reaches the retained closing rate",
        );
        assert_open_unchanged(&f, before, &retained);
        assert_eq!(
            f.book.read_entry(source_entry.vid).unwrap().unwrap(),
            source_before
        );
        assert!(
            f.book
                .read_entry(rehearsal.batch.entries[0].vid)
                .unwrap()
                .is_none()
        );

        let self_approval = Capability::embedded(PLANNER, &["read", "approve"]).unwrap();
        assert_eq!(
            f.book
                .promote_draft(self_approval, DRAFT, day(31), "not independent")
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-008",
        );
        assert_open_unchanged(&f, before, &retained);
        let promoted = promote(&mut f).unwrap();
        assert_eq!(promoted.entries, rehearsal.batch.entries);
        assert_eq!(promoted.recorded_at, CommitSeq(before.0 + 1));
        let (entry, recorded_at) = f.book.read_entry(promoted.entries[0].vid).unwrap().unwrap();
        assert_eq!(entry.proposal, proposal);
        assert_eq!(recorded_at, promoted.recorded_at);
        assert_eq!(
            f.book.draft(DRAFT).unwrap().unwrap().state,
            DraftState::Promoted
        );
        let repeated = promote(&mut f).unwrap();
        assert!(repeated.already_recorded);
        assert_eq!(repeated.entries, promoted.entries);
        assert_eq!(repeated.recorded_at, promoted.recorded_at);
        assert_eq!(f.book.head().unwrap(), promoted.recorded_at);
        assert_eq!(
            f.book
                .replay_draft_diff(REVIEWER, &reviewer(&["read"]), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report,
        );

        let mut next_request = f.request(source, later_rate.oid);
        next_request.item_allocation = item_allocation;
        let next = f
            .book
            .prepare_fx_revaluation(&next_request, &author())
            .unwrap()
            .unwrap();
        assert_eq!(next.basis().item_allocation.is_some(), item_allocation);
        assert_eq!(next.delta().mantissa, expected_delta);
        assert_eq!(next.prior_adjustment_net().mantissa, expected_delta);
        // The standalone verifier's retained FX profile is aggregate v1.
        // The item-allocated v2 cases above exercise the native draft and
        // source replay only; they make no portable verification claim.
        if item_allocation {
            continue;
        }
        let producer = cap(&["read", "produce"]);
        let certificate = f
            .book
            .certify_functional_trial_balance(
                &producer,
                fa::TrialBalanceSelection::AsOf(day(31)),
                None,
            )
            .unwrap()
            .unwrap()
            .certificate;
        let state = f
            .book
            .checkpoint(PRINCIPAL, &cap(&["read", "produce", "witness"]))
            .unwrap()
            .unwrap()
            .checkpoint
            .checkpoint
            .body
            .state_oid;
        let produced = f
            .book
            .produce_report_bundle(PRINCIPAL, &producer, Some(state), &certificate)
            .unwrap()
            .unwrap()
            .unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[f.book.checkpoint_public_key()],
            None,
            Some(&produced.receipt),
            Some(&certificate.digest),
        )
        .unwrap();
        assert_eq!(verified.output, certificate.output);
        let cell = verified
            .functional_trial_balance
            .unwrap()
            .cells
            .into_iter()
            .find(|cell| cell.account == f.account(valuation).0)
            .unwrap();
        assert_eq!(
            cell.debits.checked_sub(cell.credits).unwrap(),
            expected_delta
        );
    }
}

#[test]
fn fx_draft_refuses_mixed_multiple_and_ordinary_batch_publication_without_partial_records() {
    for mode in ["fx-first", "ordinary-first", "two-fx"] {
        let mut f = Fixture::new();
        f.post_source(b"singleton-exposure", false, 10_000);
        let rate = f.closing_rate(12);
        let agent = planner();
        open(&mut f, &agent, DRAFT);
        let fx = review(&mut f, &agent, "1200", rate.oid, b"singleton-fx");
        let other = if mode == "two-fx" {
            review(&mut f, &agent, "1200", rate.oid, b"duplicate-fx-source")
        } else {
            ordinary(&f, b"ordinary-draft-member")
        };
        let (first, second) = if mode == "ordinary-first" {
            (other, fx)
        } else {
            (fx, other)
        };
        append(&mut f, &agent, first);
        let before = f.book.head().unwrap();
        let retained = f.book.draft(DRAFT).unwrap().unwrap();
        let refusal = f
            .book
            .plan_into_draft(agent, DRAFT, second)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.code,
            code::CLASS_NOT_IMPLEMENTED,
            "{mode}: {refusal}"
        );
        assert_open_unchanged(&f, before, &retained);
    }
    let mut f = Fixture::new();
    f.post_source(b"native-batch-exposure", false, 10_000);
    let rate = f.closing_rate(12);
    let intent = review(&mut f, &author(), "1200", rate.oid, b"native-batch-fx");
    let batch = fa_intents::PostBatch::new(b"not-a-draft".to_vec(), vec![intent]).unwrap();
    let before = f.book.head().unwrap();
    assert!(
        f.book
            .plan_batch(batch.clone(), &author())
            .unwrap()
            .is_err()
    );
    assert!(f.book.post_batch(batch, &author()).unwrap().is_err());
    assert_eq!(f.book.head().unwrap(), before);
}

#[test]
fn fx_draft_rechecks_sources_routes_and_period_before_append_or_promotion() {
    for appended in [false, true] {
        for change in ["source", "routes", "period"] {
            let mut f = Fixture::new();
            f.post_source(b"original-exposure", false, 10_000);
            let rate = f.closing_rate(12);
            let agent = planner();
            open(&mut f, &agent, DRAFT);
            let intent = review(&mut f, &agent, "1200", rate.oid, b"unchanged-review");
            if appended {
                append(&mut f, &agent, intent.clone());
            }
            match change {
                "source" => {
                    f.post_source(b"late-backdated-exposure", false, 100);
                }
                "routes" => {
                    let current = f
                        .book
                        .fx_revaluation_routes_at(day(31), None, &cap(&["read"]))
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    let description = f
                        .book
                        .seal_text("New route control with identical destinations")
                        .unwrap();
                    f.book
                        .set_fx_revaluation_routes(
                            FxRevaluationRoutesRequest {
                                principal: PRINCIPAL,
                                effective_from: day(1),
                                routes: current.routes,
                                idempotency_key: b"later-route-control".to_vec(),
                                description,
                            },
                            &cap(&["read", "schema_change"]),
                        )
                        .unwrap()
                        .unwrap();
                }
                "period" => {
                    f.book
                        .transition_period(
                            PERIOD,
                            PeriodTransition::SoftClose,
                            PRINCIPAL,
                            1,
                            b"period-after-review",
                            &cap(&["close"]),
                        )
                        .unwrap()
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let before = f.book.head().unwrap();
            let retained = f.book.draft(DRAFT).unwrap().unwrap();
            let refusal = if appended {
                promote(&mut f).unwrap_err()
            } else {
                f.book
                    .plan_into_draft(agent, DRAFT, intent)
                    .unwrap()
                    .unwrap_err()
            };
            assert_eq!(
                refusal.code,
                code::PLAN_INVALIDATED,
                "{change}/{appended}: {refusal}"
            );
            assert_open_unchanged(&f, before, &retained);
        }
    }
}

#[test]
fn fx_draft_observes_current_authority_before_unknown_sources_or_drafts() {
    let mut f = Fixture::new();
    f.post_source(b"authority-exposure", false, 10_000);
    let rate = f.closing_rate(12);
    let agent = planner();
    let intent = review(&mut f, &agent, "1200", rate.oid, b"authority-review");
    let head = f.book.head().unwrap();
    for denied in [
        Capability::new(PLANNER, Profile::Agent, &[Op::Post], PRINCIPAL).unwrap(),
        agent
            .clone()
            .for_accounts(&["1200", "1290", "4700"])
            .unwrap(),
        agent.clone().for_periods(&[PERIOD]).unwrap(),
        agent.clone().for_books(&[Id128([0xff; 16])]).unwrap(),
        agent.clone().known_at_most(head),
        agent.expiring_at(head),
    ] {
        let refusal = f
            .book
            .plan_into_draft(denied, "nonexistent-draft", intent.clone())
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.exit, 7,
            "authority precedes draft discovery: {refusal}"
        );
        assert_eq!(f.book.head().unwrap(), head);
    }
    for denied in [reviewer(&[]), reviewer(&["read"]).expiring_at(head)] {
        let refusal = match f
            .book
            .rehearse_draft_at(REVIEWER, &denied, "nonexistent-draft", head)
            .unwrap()
        {
            Err(refusal) => refusal,
            Ok(_) => panic!("a denied reader must not discover or rehearse a draft"),
        };
        assert_eq!(
            refusal.exit, 7,
            "authority precedes rehearsal discovery: {refusal}"
        );
        assert_eq!(f.book.head().unwrap(), head);
    }
}

#[test]
fn fx_draft_rechecks_both_principals_and_holder_bound_expiry_at_promotion() {
    for revoked in ["planner", "promoter"] {
        let mut f = Fixture::new();
        f.post_source(b"revoked-source", false, 10_000);
        let rate = f.closing_rate(12);
        let agent = planner();
        open(&mut f, &agent, DRAFT);
        let intent = review(&mut f, &agent, "1200", rate.oid, b"revoked-review");
        append(&mut f, &agent, intent);
        let token = if revoked == "planner" {
            agent
        } else {
            reviewer(&["read", "approve"])
        };
        f.book
            .revoke_capability(
                cap(&["issue_capability"]),
                token.commitment().unwrap(),
                day(31),
                b"revoke-draft-authority",
                "Current authority withdrawn",
            )
            .unwrap()
            .unwrap();
        let before = f.book.head().unwrap();
        let retained = f.book.draft(DRAFT).unwrap().unwrap();
        let refusal = promote(&mut f).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-023", "{revoked}: {refusal}");
        assert_open_unchanged(&f, before, &retained);
    }

    let mut f = Fixture::new();
    f.post_source(b"issued-source", false, 10_000);
    let rate = f.closing_rate(12);
    let expires = CommitSeq(f.book.head().unwrap().0 + 4);
    let issued = planner()
        .holder_bound(possession_digest(&[231; 32]))
        .expiring_at(expires);
    f.book
        .issue_capability(
            cap(&["read", "post", "issue_capability"]),
            issued.clone(),
            day(31),
            b"issue-fx-planner",
            "Holder-bound expiring planner",
        )
        .unwrap()
        .unwrap();
    open(&mut f, &issued, DRAFT);
    let intent = review(&mut f, &issued, "1200", rate.oid, b"issued-review");
    append(&mut f, &issued, intent);
    assert_eq!(f.book.head().unwrap(), CommitSeq(expires.0 - 1));
    open(&mut f, &author(), "advance-past-authority");
    let before = f.book.head().unwrap();
    assert_eq!(before, expires);
    let retained = f.book.draft(DRAFT).unwrap().unwrap();
    let refusal = promote(&mut f).unwrap_err();
    assert_eq!(
        refusal.exit, 7,
        "the promoter cannot renew the planner: {refusal}"
    );
    assert_open_unchanged(&f, before, &retained);
}
