//! Automatic accrual reversals obey native posting laws at execution.
use super::*;
use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms, value_proposal};
use fa_journal::refusal::code;
use fa_journal::schedule::{ReversalBatch, ReversalStatus};
use fa_journal::usage::{UsageCell, UsageKey, verify_usage};
use fa_model::symbols::label;
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fgdb_types::CommitSeq;

fn april() -> DateDay {
    DateDay::from_ymd(2026, 4, 1).unwrap()
}

fn fixture() -> Harness {
    harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None)
}

fn accrue(h: &mut Harness, amount: i128, key: &[u8]) -> EntryRef {
    let proposal = with_auto_reverse(
        h.proposal(h.rent_legs(amount), key, EntryClass::ADJUSTING),
        april(),
    );
    h.post(h.request(proposal, &["post"])).unwrap().entry_ref()
}

fn zero_rent(h: &mut Harness, target: EntryRef) {
    // A separate original, not a cancellation: the schedule remains live.
    let mut offset = h.reversal_of_entry(target, b"offset-before-retirement");
    offset.class = EntryClass::ORIGINAL;
    offset.supersession.clear();
    h.post(h.request(offset, &["post"])).unwrap();
}

fn close_rent(h: &mut Harness, closed_on: DateDay) {
    let ctx = h.ctx();
    let description = h.statement("retire zero-balance rent", 115);
    let day = h.day();
    h.runtime
        .block_on(close_account(
            &mut h.db,
            &ctx,
            &h.book,
            "6000",
            closed_on,
            PRINCIPAL,
            day,
            b"retire-rent-before-reversal",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
}

fn tick(h: &mut Harness, day: DateDay, nonce: u8) {
    let ns = u64::try_from(day.0).unwrap() * 86_400_000_000_000 + u64::from(nonce);
    h.tick(ns, &[b'a', nonce], nonce);
}

fn executor(h: &Harness) -> Capability {
    let system = fa_journal::rows::system_principal(h.book.book_id);
    Capability::new(system, Profile::System, &[Op::Post], PRINCIPAL).unwrap()
}

fn sweep(h: &mut Harness, capability: Capability) -> Result<Option<ReversalBatch>, Refusal> {
    let ctx = h.ctx();
    let req = SweepRequest {
        principal_ref: capability.holder(),
        capability,
        max_batch: 16,
    };
    let book = &h.book;
    let mut describe = |text: &str| {
        Ok(Erasable::seal(
            &text.to_string(),
            None,
            &book.seal_key,
            [117; 32],
            [118; 24],
        ))
    };
    h.runtime
        .block_on(fa_journal::schedule::sweep_reversals_batch(
            &mut h.db,
            &ctx,
            book,
            &req,
            &mut describe,
        ))
        .unwrap()
}

fn open(h: &mut Harness, capability: &Capability, key: &[u8]) -> Result<Transitioned, Refusal> {
    let ctx = h.ctx();
    let description = h.statement("open with governed reversals", 119);
    h.runtime
        .block_on(transition_period(
            &mut h.db,
            &ctx,
            &h.book,
            &h.april,
            PeriodTransition::Open,
            capability.holder(),
            1,
            key,
            description,
            capability,
            &[],
        ))
        .unwrap()
}

fn closer() -> Capability {
    Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap()
}

fn reviewing_closer() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "close", "post"]).unwrap()
}

fn valued_accrual(h: &mut Harness, law: FxLawId) -> (EntryRef, Oid) {
    let foreign = h.book.units.lookup("EUR").unwrap();
    let accounts = [("6100", 5, 0), ("2100", 2, 1)]
        .into_iter()
        .map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(foreign),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
    let ctx = h.ctx();
    let day = h.day();
    let description = h.statement("foreign accrual chart", 151);
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"foreign-accrual-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let (as_of, purpose) = match law {
        FxLawId::SpotClose => (day, FxRatePurpose::SpotClose),
        FxLawId::PeriodAverage => (
            DateDay::from_ymd(2026, 3, 31).unwrap(),
            FxRatePurpose::PeriodAverage,
        ),
        _ => panic!("fixture requires a quote-based accrual law"),
    };
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: foreign,
            rate_num: 1,
            rate_den: 3,
            rounding: RoundingLaw::HalfEven,
        },
        as_of,
        1,
        purpose,
        "Original March quote with a split-credit residual",
    )
    .unwrap();
    let document = rate
        .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
        .unwrap();
    h.add_document(&document).unwrap();
    let proposal = with_auto_reverse(
        h.proposal(
            vec![
                LegPayload::simple(
                    Side::Debit,
                    account_vid(h.book.book_id, "6100"),
                    Amount::new(foreign, 8),
                ),
                LegPayload::simple(
                    Side::Credit,
                    account_vid(h.book.book_id, "2100"),
                    Amount::new(foreign, 4),
                ),
                LegPayload::simple(
                    Side::Credit,
                    account_vid(h.book.book_id, "2100"),
                    Amount::new(foreign, 4),
                ),
            ],
            b"foreign-auto-reversing-accrual",
            EntryClass::ADJUSTING,
        ),
        april(),
    );
    let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(100_000, 0), 4096);
    let proposal = value_proposal(
        &mut budget,
        proposal,
        &fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap(),
        &h.book.units,
        law,
        &[rate],
    )
    .unwrap();
    assert_eq!(
        proposal
            .legs
            .iter()
            .map(|leg| leg.base_amount.unwrap().mantissa)
            .collect::<Vec<_>>(),
        [3, 2, 1],
    );
    assert_eq!(
        proposal.base_totals.as_ref().unwrap().residual,
        Some(fa_model::Residual {
            leg_ordinal: 1,
            amount: Amount::new(h.usd, 1),
        })
    );
    let target = h.post(h.request(proposal, &["post"])).unwrap().entry_ref();
    (target, document.oid())
}

#[test]
fn scheduled_foreign_accruals_keep_original_rates_and_residuals_on_both_execution_paths() {
    for law in [FxLawId::SpotClose, FxLawId::PeriodAverage] {
        for via_open in [false, true] {
            let mut h = fixture();
            let (target, rate) = valued_accrual(&mut h, law);
            let (original, _) = read_entry(&h.db, target.vid).unwrap().unwrap();
            let march = h.march.clone();
            h.transition(&march, PeriodTransition::SoftClose, b"close-source-soft")
                .unwrap();
            h.transition(&march, PeriodTransition::Close, b"close-source")
                .unwrap();
            if !via_open {
                open(&mut h, &closer(), b"foreign-open-before-due").unwrap();
            }
            tick(&mut h, april(), 152);
            let minted = if via_open {
                let result = open(&mut h, &closer(), b"foreign-open-with-due").unwrap();
                assert!(result.blocked.is_empty(), "{result:?}");
                result.minted
            } else {
                let capability = executor(&h);
                let result = sweep(&mut h, capability).unwrap().unwrap();
                assert!(result.blocked.is_empty(), "{result:?}");
                result.minted
            };
            assert_eq!(minted.len(), 1, "{law:?}, open={via_open}");
            assert_eq!(minted[0].0, target);
            let (reversal, at) = read_entry(&h.db, minted[0].1.vid).unwrap().unwrap();
            assert_eq!(reversal.proposal.effective_date, april());
            assert_eq!(reversal.proposal.base_totals, original.proposal.base_totals);
            for (before, after) in original.proposal.legs.iter().zip(&reversal.proposal.legs) {
                assert_eq!(before.amount, after.amount);
                assert_eq!(before.base_amount, after.base_amount);
                assert_ne!(before.side, after.side);
            }
            assert_eq!(
                reversal.proposal.evidence,
                original
                    .proposal
                    .evidence
                    .iter()
                    .filter(|evidence| evidence.role == fa_journal::fx::RATE_EVIDENCE_ROLE)
                    .copied()
                    .collect::<Vec<_>>()
            );
            assert!(
                h.db.edges().unwrap().iter().any(|edge| {
                    edge.entry.relation == relation::EVIDENCED_BY
                        && edge.entry.src == minted[0].1.vid
                        && edge.entry.dst == document_vid(&rate)
                }),
                "the retained quote is in the reversal's evidence graph"
            );
            assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());
            let ctx = h.ctx();
            assert!(
                ctx.query()
                    .with_restriction(|| {
                        fa_journal::fx::verify_fx_conversions(&h.db, &ctx, &h.book, at)
                    })
                    .unwrap()
                    .is_green(),
                "{law:?}, open={via_open}"
            );
            let capability = executor(&h);
            assert!(
                sweep(&mut h, capability).unwrap().is_none(),
                "resolved exactly once"
            );
        }
    }
}

#[test]
fn scheduled_foreign_accrual_refuses_damaged_rate_evidence_at_execution() {
    for via_open in [false, true] {
        let mut h = fixture();
        let (target, rate) = valued_accrual(&mut h, FxLawId::SpotClose);
        if !via_open {
            open(&mut h, &closer(), b"damaged-rate-open-before-due").unwrap();
        }
        tick(&mut h, april(), 153);
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            document_vid(&rate),
            property::FA_DIGEST,
            Some(CanonicalScalar::bytes(vec![0x99; 32]).unwrap()),
        );
        h.write_raw(damage);
        if via_open {
            let head = h.db.frontier().unwrap();
            let refusal = open(&mut h, &closer(), b"damaged-rate-open-with-due").unwrap_err();
            assert_eq!(refusal.code, code::EVIDENCE_COMMIT);
            assert_eq!(h.period_state(&h.april), PeriodState::Future);
            assert_eq!(h.db.frontier().unwrap(), head);
        } else {
            let capability = executor(&h);
            let result = sweep(&mut h, capability).unwrap().unwrap();
            assert!(result.minted.is_empty());
            assert_eq!(result.blocked.len(), 1);
            assert_eq!(result.blocked[0].0, target);
            assert!(result.blocked[0].1.contains(code::EVIDENCE_COMMIT));
        }
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
}

#[test]
fn schedule_verification_rejects_repriced_functional_effects_even_when_native_legs_match() {
    let mut h = fixture();
    let (target, _) = valued_accrual(&mut h, FxLawId::SpotClose);
    tick(&mut h, april(), 154);
    let result = open(&mut h, &closer(), b"foreign-repricing-control").unwrap();
    let reversed = result.minted[0].1;
    let (entry, _) = read_entry(&h.db, reversed.vid).unwrap().unwrap();
    let mut changed = entry.proposal;
    // Keep the native side swap and the functional double-entry equality,
    // but make the reversal carry 4 instead of the original 3 USD cents.
    changed.legs[0].base_amount.as_mut().unwrap().mantissa = 4;
    changed.legs[1].base_amount.as_mut().unwrap().mantissa = 3;
    let totals = changed.base_totals.as_mut().unwrap();
    totals.debits = 4;
    totals.credits = 4;
    let changed = changed
        .seal(entry.approvals, entry.plan_certificate)
        .unwrap();
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        reversed.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(changed.encode().unwrap()).unwrap()),
    );
    damage.set_vertex_property(
        reversed.vid,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(changed.entry_digest.to_vec()).unwrap()),
    );
    h.write_raw(damage);
    let verified = verify_schedules(&h.db, &h.book).unwrap();
    assert!(!verified.is_green());
    assert!(
        verified.drift.iter().any(|problem| {
            problem.contains(&format!("{:032x}", target.vid.0))
                && problem.contains("not the bound effect")
        }),
        "{verified:?}"
    );
}

#[test]
fn automatic_accruals_still_refuse_application_effects_without_an_undo_law() {
    let mut h = fixture();
    let invoice = h
        .post(h.request(h.invoice(10, b"application-accrual-invoice"), &["post"]))
        .unwrap()
        .entry_ref();
    let mut applying = h.receipt(
        10,
        vec![Settlement {
            target: invoice,
            ordinal: 0,
            amount: Amount::new(h.usd, 10),
        }],
        b"application-accrual",
    );
    applying.class = EntryClass::ADJUSTING;
    let applying = with_auto_reverse(applying, april());
    let head = h.db.frontier().unwrap();
    let refusal = h.post(h.request(applying, &["post"])).unwrap_err();
    assert_eq!(refusal.code, code::STRUCTURE);
    assert!(refusal.message.contains("no applications"));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.applied_to(invoice.vid, 0), 0);
}

fn opening_plan(
    h: &mut Harness,
    capability: &Capability,
    key: &[u8],
) -> Result<TransitionPlan, Refusal> {
    let ctx = h.ctx();
    let description = h.statement("review exact scheduled opening effects", 141);
    h.runtime
        .block_on(fa_journal::period::plan_open_transition(
            &mut h.db,
            &ctx,
            &h.book,
            &h.april,
            capability.holder(),
            1,
            key,
            description,
            capability,
        ))
        .expect("opening rehearsal kernel")
}

fn commit_opening_plan(
    h: &mut Harness,
    plan: &TransitionPlan,
    capability: &Capability,
) -> Result<Transitioned, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(transition_planned(
            &mut h.db,
            &ctx,
            &h.book,
            plan,
            PeriodTransition::Open,
            capability,
            &[],
        ))
        .expect("opening plan publication kernel")
}

#[test]
fn opening_plan_rehearses_exact_reversals_without_writes_and_retries_its_original_effects() {
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"reviewed-opening-accrual");
    tick(&mut h, april(), 142);
    let capability = reviewing_closer();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let plan = opening_plan(&mut h, &capability, b"reviewed-opening").unwrap();
    let effects = plan.opening_effects.as_ref().expect("full opening preview");
    assert_eq!(
        effects.capability_commitment,
        capability.commitment().unwrap()
    );
    assert!(effects.tick.is_some());
    assert_eq!(effects.minted.len(), 1);
    assert_eq!(effects.minted[0].0, target);
    assert_eq!(effects.minted[0].1.vid, reversal_vid(target.vid));
    assert!(effects.blocked.is_empty());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(
        h.db.vertices().unwrap(),
        vertices,
        "a dry run published state"
    );
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    let wire = plan.encode().unwrap();
    assert_eq!(TransitionPlan::decode(&wire).unwrap(), plan);
    assert_eq!(
        opening_plan(&mut h, &capability, b"reviewed-opening")
            .unwrap()
            .encode()
            .unwrap(),
        wire,
        "the same prefix and reviewed request produce the same artifact"
    );

    // An independent approval adds history without changing the scheduled
    // accounting effects. A blanket head-equality check would reject this.
    h.approve_transition(plan.proposal_digest(&h.book).unwrap().unwrap());
    let done = commit_opening_plan(&mut h, &plan, &capability).unwrap();
    assert!(!done.already_recorded);
    assert_eq!(done.minted, effects.minted);
    assert_eq!(done.blocked, effects.blocked);
    assert_eq!(h.period_state(&h.april), PeriodState::Open);
    let (reversal, recorded_at) = read_entry(&h.db, done.minted[0].1.vid).unwrap().unwrap();
    assert_eq!(reversal.entry_digest, effects.minted[0].1.entry_digest);
    assert_eq!(recorded_at, done.recorded_at);
    assert_eq!(reversal.proposal.class, EntryClass::REVERSAL);
    assert_eq!(reversal.proposal.supersession[0].target, target);
    assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());
    assert_leg_projections(&h);

    tick(&mut h, DateDay(april().0 + 1), 143);
    let head = h.db.frontier().unwrap();
    let retry = commit_opening_plan(&mut h, &plan, &capability).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, done.control_entry);
    assert_eq!(retry.recorded_at, done.recorded_at);
    assert_eq!(retry.minted, effects.minted);
    assert_eq!(retry.blocked, effects.blocked);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn opening_plan_refuses_newly_due_or_newly_recorded_reversals_before_opening() {
    for tick_after_plan in [false, true] {
        let mut h = fixture();
        let capability = reviewing_closer();
        let existing = if tick_after_plan {
            Some(accrue(&mut h, 100, b"waiting-for-reviewed-tick"))
        } else {
            tick(&mut h, april(), 144);
            None
        };
        let plan = opening_plan(&mut h, &capability, b"empty-reviewed-opening").unwrap();
        let effects = plan.opening_effects.as_ref().unwrap();
        assert!(effects.minted.is_empty());
        assert!(effects.blocked.is_empty());
        assert_eq!(effects.tick.is_none(), tick_after_plan);
        let target = if let Some(target) = existing {
            tick(&mut h, april(), 145);
            target
        } else {
            accrue(&mut h, 100, b"scheduled-after-opening-review")
        };
        let head = h.db.frontier().unwrap();
        let refusal = commit_opening_plan(&mut h, &plan, &capability).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::PLAN_INVALIDATED, exit::CONFLICT)
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.period_state(&h.april), PeriodState::Future);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        let fresh = opening_plan(&mut h, &capability, b"empty-reviewed-opening").unwrap();
        assert_eq!(fresh.opening_effects.as_ref().unwrap().minted[0].0, target);
        let done = commit_opening_plan(&mut h, &fresh, &capability).unwrap();
        assert_eq!(done.minted, fresh.opening_effects.unwrap().minted);
    }
}

#[test]
fn opening_plan_refuses_changed_availability_and_retains_the_reviewed_block_on_retry() {
    let mut h = harness_configured(
        Vec::new(),
        Some(TimeZonePolicy::Utc),
        Some(BalanceLimit {
            lower: None,
            upper: Some(0),
            scope: LimitScope::Lifetime,
        }),
    );
    let target = accrue(&mut h, 100, b"limited-reviewed-accrual");
    tick(&mut h, april(), 146);
    let capability = reviewing_closer();
    let plan = opening_plan(&mut h, &capability, b"review-limited-opening").unwrap();
    assert_eq!(plan.opening_effects.as_ref().unwrap().minted[0].0, target);
    // Cash was -100, so the reviewed reversal could restore it to zero.
    // An independent receipt consumes that space without cancelling the
    // accrual schedule: the same reversal is now blocked by the upper limit.
    zero_rent(&mut h, target);
    let head = h.db.frontier().unwrap();
    let cell = h.db.vertex(limit_cell_vid(h.cash)).unwrap().unwrap();
    let refusal = commit_opening_plan(&mut h, &plan, &capability).unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::PLAN_INVALIDATED, exit::CONFLICT)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertex(limit_cell_vid(h.cash)).unwrap().unwrap(), cell);
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());

    let blocked = opening_plan(&mut h, &capability, b"review-limited-opening").unwrap();
    let effects = blocked.opening_effects.as_ref().unwrap();
    assert!(effects.minted.is_empty());
    assert_eq!(effects.blocked.len(), 1);
    assert_eq!(effects.blocked[0].0, target);
    assert!(effects.blocked[0].1.contains(code::AVAILABILITY_UPPER));
    let done = commit_opening_plan(&mut h, &blocked, &capability).unwrap();
    assert_eq!(done.blocked, effects.blocked);
    assert!(done.minted.is_empty());
    // Restore availability after the opening. Replaying this acknowledged
    // outcome must retain the reviewed block, not silently mint the reversal.
    let spend = h.proposal(
        h.rent_legs(100),
        b"spend-after-blocked-open",
        EntryClass::ORIGINAL,
    );
    h.post(h.request(spend, &["post"])).unwrap();
    tick(&mut h, DateDay(april().0 + 1), 147);
    let head = h.db.frontier().unwrap();
    let retry = commit_opening_plan(&mut h, &blocked, &capability).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.recorded_at, done.recorded_at);
    assert_eq!(retry.minted, done.minted);
    assert_eq!(retry.blocked, effects.blocked);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());
}

#[test]
fn opening_plan_authenticates_effects_and_cannot_be_replaced_by_a_proposal_only_plan() {
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"opening-authentication-accrual");
    tick(&mut h, april(), 148);
    let capability = reviewing_closer();
    let plan = opening_plan(&mut h, &capability, b"authenticate-opening-manifest").unwrap();
    let head = h.db.frontier().unwrap();
    for mutation in 0..7 {
        let mut changed = plan.clone();
        if mutation == 0 {
            changed.opening_effects = None;
        } else {
            let effects = changed.opening_effects.as_mut().unwrap();
            match mutation {
                1 => effects.capability_commitment[0] ^= 1,
                2 => effects.tick = None,
                3 => effects.minted[0].0.entry_digest[0] ^= 1,
                4 => effects.minted[0].1.entry_digest[0] ^= 1,
                5 => effects.minted.clear(),
                6 => effects
                    .blocked
                    .push((target, "claimed reviewed block".into())),
                _ => unreachable!(),
            }
        }
        let changed = TransitionPlan::decode(&changed.encode().unwrap()).unwrap();
        let refusal = commit_opening_plan(&mut h, &changed, &capability).unwrap_err();
        assert_eq!(
            refusal.code,
            code::PLAN_INVALIDATED,
            "mutation {mutation}: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.period_state(&h.april), PeriodState::Future);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    let proposal_only = plan_transition(
        &h.db,
        &h.book,
        &h.april,
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"proposal-only-opening",
        h.statement("unreviewed automatic effects", 149),
    )
    .unwrap()
    .unwrap();
    assert!(proposal_only.opening_effects.is_none());
    let refusal = commit_opening_plan(&mut h, &proposal_only, &capability).unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    let altered_authority = capability.clone().with_ceiling(h.usd, 100).unwrap();
    let refusal = commit_opening_plan(&mut h, &plan, &altered_authority).unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert_eq!(h.db.frontier().unwrap(), head);
    commit_opening_plan(&mut h, &plan, &capability).unwrap();
}

#[test]
fn opening_rehearsal_requires_current_whole_book_read_and_execution_authority() {
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"opening-authority-accrual");
    tick(&mut h, april(), 150);
    let head = h.db.frontier().unwrap();
    for capability in [
        Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read", "close"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
        reviewing_closer().for_accounts(&["6000"]).unwrap(),
    ] {
        let refusal = opening_plan(&mut h, &capability, b"opening-authority").unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY, "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.period_state(&h.april), PeriodState::Future);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    let capability = reviewing_closer();
    let plan = opening_plan(&mut h, &capability, b"opening-authority").unwrap();
    h.revoke(&capability, 151);
    let head = h.db.frontier().unwrap();
    assert!(opening_plan(&mut h, &capability, b"opening-authority-after-revocation").is_err());
    assert!(commit_opening_plan(&mut h, &plan, &capability).is_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
}

#[test]
fn register_capacity_governs_scheduled_sweep_and_atomic_period_open() {
    for via_open in [false, true] {
        let mut h = fixture();
        let target = accrue(&mut h, 1, b"capacity-accrual");
        if !via_open {
            open(&mut h, &closer(), b"capacity-open-before-due").unwrap();
        }
        let mut opposite = h.proposal(
            h.rent_legs(i128::MAX),
            b"opposite-gross-cap",
            EntryClass::ORIGINAL,
        );
        for leg in &mut opposite.legs {
            leg.side = leg.side.flipped();
        }
        opposite.unit_totals = EntryPayload::fold_unit_totals(&opposite.legs).unwrap();
        h.post(h.request(opposite, &["post"])).unwrap();
        tick(&mut h, april(), 125);
        let head = h.db.frontier().unwrap();
        if via_open {
            let refusal = open(&mut h, &closer(), b"capacity-open-at-due").unwrap_err();
            assert_eq!(refusal.code, "FA-REF-198", "{refusal}");
            assert_eq!(
                h.db.frontier().unwrap(),
                head,
                "period and reversal are both absent"
            );
            let row = h.db.vertex(period_vid("cal", &h.april)).unwrap().unwrap();
            assert_eq!(PeriodRow::decode(&row).unwrap().state, PeriodState::Future);
        } else {
            let capability = executor(&h);
            let result = sweep(&mut h, capability).unwrap().unwrap();
            assert!(result.minted.is_empty());
            assert_eq!(result.blocked.len(), 1);
            assert!(result.blocked[0].1.contains("FA-REF-198"));
        }
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        assert_leg_projections(&h);
    }
}

fn issue_quota(h: &mut Harness, capability: Capability, limit: i128) -> Capability {
    let capability = capability
        .holder_bound(fa_policy::possession_digest(&[120; 32]))
        .with_daily_total(h.usd, limit)
        .unwrap();
    let ctx = h.ctx();
    let request = fa_journal::policy::IssuanceRequest {
        capability: Capability::embedded(PRINCIPAL, &["issue_capability", "post", "close"])
            .unwrap(),
        issued: capability.clone(),
        effective_date: h.day(),
        idempotency_key: format!("schedule-quota-{limit}-{:032x}", capability.holder().0)
            .into_bytes(),
        description: h.statement("issue scheduled execution quota", 120),
    };
    h.runtime
        .block_on(fa_journal::policy::issue_capability(
            &mut h.db, &ctx, &h.book, request,
        ))
        .unwrap()
        .unwrap();
    capability
}

fn usage_key(h: &Harness, capability: &Capability, day: DateDay) -> UsageKey {
    UsageKey {
        book_id: h.book.book_id,
        root_issuance: capability.commitment().unwrap(),
        day,
        unit: h.usd,
    }
}

#[test]
fn retired_account_blocks_both_execution_paths_and_open_retry_preserves_its_reason() {
    for via_open in [false, true] {
        let mut h = fixture();
        let target = accrue(&mut h, 100, b"retiring-accrual");
        zero_rent(&mut h, target);
        if !via_open {
            open(&mut h, &closer(), b"open-before-due").unwrap();
        }
        close_rent(&mut h, april());
        tick(&mut h, april(), 121);
        let reason = if via_open {
            let result = open(&mut h, &closer(), b"open-retired").unwrap();
            assert!(result.minted.is_empty());
            assert_eq!(result.blocked.len(), 1);
            assert_eq!(result.blocked[0].0, target);
            // Advance history. A retry must retain the original block even
            // after its tick and the surrounding history have moved.
            tick(&mut h, DateDay(april().0 + 1), 122);
            let head = h.db.frontier().unwrap();
            let retry = open(
                &mut h,
                &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
                b"open-retired",
            )
            .unwrap();
            assert!(retry.already_recorded);
            assert_eq!(retry.blocked, result.blocked);
            assert_eq!(retry.minted, result.minted);
            assert_eq!(h.db.frontier().unwrap(), head);
            result.blocked[0].1.clone()
        } else {
            let due = due_reversals(&h.db, &h.book).unwrap();
            assert!(matches!(&due[0].status, ReversalStatus::Blocked { row, .. }
                if row.contains("outside its effective interval")));
            let cap = executor(&h);
            let result = sweep(&mut h, cap).unwrap().unwrap();
            assert!(result.minted.is_empty());
            assert_eq!(result.blocked.len(), 1);
            result.blocked[0].1.clone()
        };
        assert!(reason.contains(code::NOT_A_LEAF), "{reason}");
        assert!(
            reason.contains("outside its effective interval"),
            "{reason}"
        );
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());
    }
}

#[test]
fn account_effectivity_is_judged_at_reversal_date_and_close_races_conflict() {
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"pre-close-reversal");
    zero_rent(&mut h, target);
    close_rent(&mut h, DateDay(april().0 + 1));
    tick(&mut h, april(), 123);
    let result = open(&mut h, &closer(), b"open-valid-historical-account").unwrap();
    assert_eq!(result.minted.len(), 1);
    assert_eq!(result.minted[0].0, target);
    assert!(result.blocked.is_empty());
    assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());

    let mut h = fixture();
    let target = accrue(&mut h, 100, b"racing-account-close");
    zero_rent(&mut h, target);
    tick(&mut h, april(), 124);
    let ctx = h.ctx();
    let description = h.statement("prepared Open", 125);
    let prepared = fa_journal::period::prepare_transition(
        &mut h.db,
        &ctx,
        &h.book,
        &h.april,
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"race-open",
        description,
        &closer(),
        &[],
    )
    .unwrap()
    .unwrap();
    close_rent(&mut h, april());
    let head = h.db.frontier().unwrap();
    let refusal = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &ctx))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::CONFLICT, exit::CONFLICT)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
}

#[test]
fn automatic_effects_enforce_post_ceiling_class_scope_dry_run_and_revocation() {
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"governed-accrual");
    tick(&mut h, april(), 126);
    let head = h.db.frontier().unwrap();
    let denied = [
        Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        closer().with_ceiling(h.usd, 99).unwrap(),
        closer().for_classes(&[EntryClass::ORIGINAL]).unwrap(),
        closer().for_accounts(&["6000"]).unwrap(),
        closer().for_periods(&[h.april.as_str()]).unwrap(),
        closer().effective_through(DateDay(april().0 - 1)),
        closer().with_requires_dry_run(),
    ];
    for (n, cap) in denied.iter().enumerate() {
        assert!(open(&mut h, cap, format!("denied-open-{n}").as_bytes()).is_err());
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.period_state(&h.april), PeriodState::Future);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    // No due effects are hidden by moving the period first: use a separate
    // fixture whose period was opened before the committed tick.
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"bounded-sweep-accrual");
    open(&mut h, &closer(), b"sweep-period").unwrap();
    for (nonce, cap) in [
        (127, executor(&h).with_ceiling(h.usd, 99).unwrap()),
        (
            128,
            executor(&h).for_classes(&[EntryClass::ORIGINAL]).unwrap(),
        ),
        (129, executor(&h).with_requires_dry_run()),
    ] {
        tick(&mut h, april(), nonce);
        let result = sweep(&mut h, cap).unwrap().unwrap();
        assert!(result.minted.is_empty());
        assert_eq!(result.blocked.len(), 1);
        assert_eq!(result.blocked[0].0, target);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    let cap = executor(&h);
    h.revoke(&cap, 130);
    tick(&mut h, april(), 131);
    let head = h.db.frontier().unwrap();
    assert!(sweep(&mut h, cap).is_err());
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn one_sweep_shares_daily_budget_across_reversals_and_keeps_processing_after_a_block() {
    let mut h = fixture();
    let first = accrue(&mut h, 60, b"quota-first");
    let second = accrue(&mut h, 60, b"quota-second");
    let third = accrue(&mut h, 30, b"quota-third");
    open(&mut h, &closer(), b"open-before-budget-tick").unwrap();
    let cap = executor(&h);
    let cap = issue_quota(&mut h, cap, 100);
    tick(&mut h, april(), 132);
    let result = sweep(&mut h, cap.clone()).unwrap().unwrap();
    assert_eq!(
        result.minted.iter().map(|p| p.0).collect::<Vec<_>>(),
        [first, third]
    );
    assert_eq!(result.blocked.len(), 1);
    assert_eq!(result.blocked[0].0, second);
    assert!(result.blocked[0].1.contains(code::DAILY_CEILING));
    let key = usage_key(&h, &cap, april());
    let cell = UsageCell::from_row(&h.db.vertex(key.cell_vid()).unwrap().unwrap(), key).unwrap();
    assert_eq!((cell.gross_debits, cell.generation), (90, 2));
    let head = h.db.frontier().unwrap();
    assert_eq!(sweep(&mut h, cap.clone()).unwrap(), None);
    assert_eq!(h.db.frontier().unwrap(), head);
    // A newly committed day permits the outstanding exact reversal without
    // refunding or rewriting any previous usage.
    tick(&mut h, DateDay(april().0 + 1), 133);
    let next = sweep(&mut h, cap.clone()).unwrap().unwrap();
    assert_eq!(next.minted.len(), 1);
    assert_eq!(next.minted[0].0, second);
    assert!(next.blocked.is_empty());
    let report = verify_usage(&h.db, &h.ctx(), &h.book, None).unwrap();
    assert!(report.is_green(), "{:?}", report.drift);
    assert_eq!((report.charges_checked, report.cells_checked), (3, 2));
}

#[test]
fn opening_with_insufficient_daily_budget_rolls_back_all_effects_and_usage() {
    let mut h = fixture();
    let first = accrue(&mut h, 60, b"open-quota-first");
    let second = accrue(&mut h, 60, b"open-quota-second");
    let too_small = issue_quota(&mut h, closer(), 100);
    tick(&mut h, april(), 134);
    let head = h.db.frontier().unwrap();
    let refusal = open(&mut h, &too_small, b"open-budget-atomic").unwrap_err();
    assert_eq!(refusal.code, code::DAILY_CEILING);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    assert!(
        h.db.vertex(usage_key(&h, &too_small, april()).cell_vid())
            .unwrap()
            .is_none()
    );
    for target in [first, second] {
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    assert!(
        !h.db
            .vertices()
            .unwrap()
            .iter()
            .any(|r| r.labels.contains(&label::USAGE_DEBIT))
    );
    // The explicitly issued larger authorization makes the same requested
    // atomic Open possible; its System entries charge the real Human actor.
    let cap = issue_quota(&mut h, closer(), 150);
    let result = open(&mut h, &cap, b"open-budget-atomic").unwrap();
    assert_eq!(result.minted.len(), 2);
    assert!(result.blocked.is_empty());
    let key = usage_key(&h, &cap, april());
    let cell = UsageCell::from_row(&h.db.vertex(key.cell_vid()).unwrap().unwrap(), key).unwrap();
    assert_eq!((cell.gross_debits, cell.generation), (120, 2));
    let report = verify_usage(&h.db, &h.ctx(), &h.book, None).unwrap();
    assert!(report.is_green(), "{:?}", report.drift);
    assert_eq!(report.charges_checked, 2);
    let head = h.db.frontier().unwrap();
    let retry = open(
        &mut h,
        &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        b"open-budget-atomic",
    )
    .unwrap();
    assert_eq!(retry.minted, result.minted);
    assert!(retry.already_recorded);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(
        verify_usage(&h.db, &h.ctx(), &h.book, Some(CommitSeq(head.0)))
            .unwrap()
            .charges_checked,
        2
    );
}
