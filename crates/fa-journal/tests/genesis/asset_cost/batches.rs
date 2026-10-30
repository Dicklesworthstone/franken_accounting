//! Governed recurring charges compose only across independent acquisitions.

use super::*;
use fa_journal::refusal::code;
use fgdb_types::CommitSeq;

impl Fixture {
    fn add_schedule(
        &mut self,
        acquisition: EntryRef,
        ordinal: u16,
        name: &str,
        kind: AssetCostKind,
    ) -> AssetScheduleRecorded {
        let mut spec = self.schedule.spec.clone();
        spec.name = name.into();
        spec.kind = kind;
        spec.acquisition = acquisition;
        spec.acquisition_ordinal = ordinal;
        let request = AssetScheduleRequest {
            principal: PRINCIPAL,
            spec,
            effective_date: self.h.day(),
            idempotency_key: format!("schedule-{name}").into_bytes(),
            description: self.source.description.clone(),
            approvals: Vec::new(),
        };
        let cx = self.h.ctx();
        self.h
            .runtime
            .block_on(create_asset_schedule(
                &mut self.h.db,
                &cx,
                &self.h.book,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
                request,
            ))
            .unwrap()
            .unwrap()
    }

    fn second_schedule(&mut self) -> AssetScheduleRecorded {
        let mut source = self.source.clone();
        source.idempotency_key = b"intangible-acquisition".to_vec();
        let acquisition = self.h.post(posting(source)).unwrap().entry_ref();
        self.add_schedule(acquisition, 0, "license", AssetCostKind::Amortization)
    }

    fn charge_for(
        &self,
        schedule: &AssetScheduleRecorded,
        capability: &Capability,
        key: &[u8],
    ) -> EntryPayload {
        let mut template = self.template(3, key);
        template.principal_ref = capability.holder();
        prepare_asset_charge(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            capability,
            &AssetChargeRequest {
                schedule: schedule.entry,
                through_period: template.effective_period.clone().unwrap(),
                kind: schedule.spec.kind,
            },
            &template,
        )
        .unwrap()
        .unwrap()
        .proposal(template)
        .unwrap()
    }

    fn post_charges(
        &mut self,
        batch: fa_intents::PostBatch,
        capability: &Capability,
    ) -> Result<BatchPosted, Refusal> {
        let cx = self.h.ctx();
        self.h
            .runtime
            .block_on(post_batch(
                &mut self.h.db,
                &cx,
                &self.h.book,
                capability.clone(),
                batch,
            ))
            .expect("asset batch kernel")
    }

    fn charge_pair(&self, other: &AssetScheduleRecorded, key: &str) -> fa_intents::PostBatch {
        self.h.batch(
            key.as_bytes(),
            vec![
                self.charge_for(&self.schedule, &cap(), format!("{key}-first").as_bytes()),
                self.charge_for(other, &cap(), format!("{key}-second").as_bytes()),
            ],
        )
    }
}

fn recognized(db: &Database<MemVfs>, h: &Harness) -> Vec<i128> {
    asset_register(db, &h.ctx(), &h.book, &cap(), db.frontier().unwrap())
        .unwrap()
        .unwrap()
        .rows
        .iter()
        .map(|row| row.recognized.mantissa)
        .collect()
}

#[test]
fn independent_depreciation_and_amortization_share_one_atomic_publication() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 10_007, 7, 3);
    let other = f.second_schedule();
    let batch = f.charge_pair(&other, "atomic-assets");
    let before = f.h.db.frontier().unwrap();
    assert_eq!(recognized(&f.h.db, &f.h), [0, 0]);
    let posted = f.post_charges(batch.clone(), &cap()).unwrap();
    assert_eq!(posted.recorded_at, CommitSeq(before.0 + 1));
    assert_eq!(posted.entries.len(), 2);
    assert_eq!(recognized(&f.h.db, &f.h), [3333, 3333]);
    for reference in &posted.entries {
        let (entry, at) = read_entry(&f.h.db, reference.vid).unwrap().unwrap();
        assert_eq!(at, posted.recorded_at);
        assert_eq!(entry.proposal.legs[0].amount.mantissa, 3333);
        assert_eq!(entry.proposal.legs[1].amount.mantissa, 3333);
    }
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
    let rows = f.h.db.vertices().unwrap();
    let retry = f.post_charges(batch, &cap()).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
}

#[test]
fn asset_batch_refuses_duplicate_schedules_shared_acquisitions_and_mixed_effects() {
    for variant in [
        "same-schedule",
        "forged-digest",
        "shared-acquisition",
        "ordinary",
        "reversal",
    ] {
        for reversed_order in [false, true] {
            let mut f = Fixture::new(AssetCostKind::Depreciation, 10_007, 7, 3);
            let (first_schedule, second_schedule) = if variant == "shared-acquisition" {
                let source = f.h.proposal(
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(f.h.book.book_id, "1500"),
                            Amount::new(f.h.usd, 10_007),
                        ),
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(f.h.book.book_id, "1500"),
                            Amount::new(f.h.usd, 10_007),
                        ),
                        LegPayload::simple(Side::Credit, f.h.cash, Amount::new(f.h.usd, 20_014)),
                    ],
                    b"two-assets-one-invoice",
                    EntryClass::ORIGINAL,
                );
                let acquisition = f.h.post(posting(source)).unwrap().entry_ref();
                (
                    f.add_schedule(acquisition, 0, "first-shared", AssetCostKind::Depreciation),
                    f.add_schedule(acquisition, 1, "second-shared", AssetCostKind::Depreciation),
                )
            } else {
                (f.schedule.clone(), f.schedule.clone())
            };
            let first = f.charge_for(&first_schedule, &cap(), b"unsafe-first");
            let mut second = f.charge_for(&second_schedule, &cap(), b"unsafe-second");
            match variant {
                "forged-digest" => {
                    let mut basis = second.asset_charge_basis().unwrap().unwrap();
                    basis.schedule.entry_digest[0] ^= 1;
                    second.set_asset_charge_basis(&basis).unwrap();
                }
                "ordinary" => {
                    second =
                        f.h.proposal(f.h.rent_legs(1), b"ordinary", EntryClass::ORIGINAL)
                }
                "reversal" => second = undo(&f.source, f.acquisition, b"mixed-source-undo"),
                _ => {}
            }
            let mut members = vec![first, second];
            if reversed_order {
                members.reverse();
            }
            let batch = f.h.batch(b"unsafe-assets", members);
            let before = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let refusal = f.post_charges(batch, &cap()).unwrap_err();
            assert_eq!(refusal.code, code::STRUCTURE, "{variant}: {refusal}");
            assert_eq!(f.h.db.frontier().unwrap(), before);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
            assert!(recognized(&f.h.db, &f.h).iter().all(|amount| *amount == 0));
        }
    }
}

#[test]
fn false_later_charge_rolls_back_prior_effects_and_source_guards() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 10_007, 7, 3);
    let other = f.second_schedule();
    let first = f.charge_for(&f.schedule, &cap(), b"rollback-first");
    let mut second = f.charge_for(&other, &cap(), b"rollback-second");
    // This is still balanced. Only an independent source derivation rejects it.
    for leg in &mut second.legs {
        leg.amount.mantissa += 1;
    }
    second.unit_totals = EntryPayload::fold_unit_totals(&second.legs).unwrap();
    let batch = f.h.batch(b"rollback-assets", vec![first, second]);
    let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.post_charges(batch, &cap()).unwrap_err();
    assert!(refusal.message.contains("member 1"), "{refusal}");
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert!(f.h.db.vertex(outcome).unwrap().is_none());
    assert_eq!(recognized(&f.h.db, &f.h), [0, 0]);
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn asset_batch_plans_guard_the_complete_prefix_and_exact_retry() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 10_007, 7, 3);
    let other = f.second_schedule();
    let capability = cap().with_requires_dry_run();
    let batch = f.charge_pair(&other, "planned-assets");
    let before = f.h.db.frontier().unwrap();
    assert!(f.post_charges(batch.clone(), &capability).is_err());
    let plan = f.h.planned_batch(batch, &capability).unwrap();
    assert_eq!(f.h.db.frontier().unwrap(), before);
    f.h.open_draft(f.h.agent_capability(), "between-plan-and-commit")
        .unwrap();
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.publish_batch_plan(plan, &capability).unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    let fresh = f.charge_pair(&other, "planned-assets");
    let plan = f.h.planned_batch(fresh, &capability).unwrap();
    let posted = f.h.publish_batch_plan(plan.clone(), &capability).unwrap();
    assert_eq!(posted.recorded_at, CommitSeq(before.0 + 1));
    assert_eq!(recognized(&f.h.db, &f.h), [3333, 3333]);
    let retry = f.h.publish_batch_plan(plan, &capability).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at);
}

#[test]
fn asset_draft_rehearsal_and_promotion_preserve_sources_and_reviewed_effects() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 10_007, 7, 3);
    let other = f.second_schedule();
    let agent = f.h.agent_capability();
    let name = "month-end-assets";
    f.h.open_draft(agent.clone(), name).unwrap();
    let first = f.charge_for(&f.schedule, &agent, b"draft-first");
    let first_basis = first.asset_charge_basis().unwrap().unwrap().known_at;
    f.h.plan_draft(agent.clone(), name, first).unwrap();
    let second = f.charge_for(&other, &agent, b"draft-second");
    assert!(second.asset_charge_basis().unwrap().unwrap().known_at > first_basis);
    let planned = f.h.plan_draft(agent.clone(), name, second).unwrap();
    let entries = planned
        .plan
        .unwrap()
        .members()
        .iter()
        .map(|member| {
            member.entry.entry_ref(entry_vid(
                f.h.book.book_id,
                &AGENT.0.to_le_bytes(),
                &member.entry.proposal.idempotency_key,
            ))
        })
        .collect::<Vec<_>>();
    f.h.post(posting(f.h.proposal(
        f.h.rent_legs(1),
        b"unrelated-rent",
        EntryClass::ORIGINAL,
    )))
    .unwrap();
    assert_eq!(recognized(&f.h.db, &f.h), [0, 0]);
    let view = f.h.draft(name);
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let direct = PostRequest {
        proposal: view.intents[0].intent.proposal().clone(),
        approvals: Vec::new(),
        plan_certificate: None,
        capability: agent,
    };
    assert_eq!(f.h.post(direct).unwrap_err().exit, 7);
    let self_approver = Capability::embedded(AGENT, &["read", "approve"]).unwrap();
    assert_eq!(
        f.h.promote(self_approver, name).unwrap_err().code,
        "FA-REF-008"
    );
    let cx = f.h.ctx();
    let target =
        f.h.runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([229; 32], DatabaseSecurityNamespaceId([230; 32]), [231; 32]),
            ))
            .unwrap();
    let (scratch, rehearsal) =
        f.h.runtime
            .block_on(rehearse_draft_into(
                &mut f.h.db,
                target,
                &cx,
                &f.h.book,
                &Capability::embedded(APPROVER, &["read"]).unwrap(),
                DraftRehearsalRequest {
                    name: name.into(),
                    known_at: before,
                },
            ))
            .unwrap()
            .unwrap();
    assert_eq!(rehearsal.batch.entries, entries);
    assert_eq!(recognized(&scratch, &f.h), [3333, 3333]);
    assert!(
        verify_asset_schedules(&scratch, &cx, &f.h.book)
            .unwrap()
            .is_green()
    );
    for acquisition in [f.acquisition, other.spec.acquisition] {
        assert_eq!(
            fa_journal::post::read_entry_at(&scratch, acquisition.vid, before).unwrap(),
            read_entry(&f.h.db, acquisition.vid).unwrap(),
        );
    }
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_eq!(f.h.draft(name), view);
    let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
    assert_eq!(promoted.recorded_at, CommitSeq(before.0 + 1));
    assert_eq!(promoted.entries, entries);
    for (reference, retained) in entries.iter().zip(&view.intents) {
        let (entry, at) = read_entry(&f.h.db, reference.vid).unwrap().unwrap();
        assert_eq!(entry.proposal, *retained.intent.proposal());
        assert_eq!(entry.entry_digest, reference.entry_digest);
        assert_eq!(at, promoted.recorded_at);
    }
    assert_eq!(recognized(&f.h.db, &f.h), [3333, 3333]);
    assert!(
        verify_asset_schedules(&f.h.db, &cx, &f.h.book)
            .unwrap()
            .is_green()
    );
    let retry = f.h.promote(f.h.approver_capability(), name).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, entries);
    assert_eq!(f.h.db.frontier().unwrap(), promoted.recorded_at);
}

#[test]
fn asset_drafts_refuse_source_drift_period_changes_and_revoked_planners_atomically() {
    for change in [
        "charge",
        "charge-and-undo",
        "acquisition-undo",
        "period",
        "revoked",
    ] {
        let mut f = Fixture::new(AssetCostKind::Depreciation, 10_007, 7, 3);
        let other = f.second_schedule();
        let agent = f.h.agent_capability();
        let name = "stale-assets";
        f.h.open_draft(agent.clone(), name).unwrap();
        for (schedule, key) in [
            (&f.schedule, b"stale-first".as_slice()),
            (&other, b"stale-second".as_slice()),
        ] {
            let proposal = f.charge_for(schedule, &agent, key);
            f.h.plan_draft(agent.clone(), name, proposal).unwrap();
        }
        match change {
            "charge" | "charge-and-undo" => {
                let charge = f.charge_for(&other, &cap(), b"intervening-charge");
                let reference = f.h.post(posting(charge.clone())).unwrap().entry_ref();
                if change == "charge-and-undo" {
                    f.h.post(posting(undo(
                        &charge,
                        reference,
                        b"undo-intervening-charge",
                    )))
                    .unwrap();
                    assert_eq!(recognized(&f.h.db, &f.h), [0, 0]);
                }
            }
            "acquisition-undo" => {
                let source = read_entry(&f.h.db, other.spec.acquisition.vid)
                    .unwrap()
                    .unwrap()
                    .0
                    .proposal;
                f.h.post(posting(undo(
                    &source,
                    other.spec.acquisition,
                    b"undo-source",
                )))
                .unwrap();
            }
            "period" => {
                let march = f.h.march.clone();
                f.h.transition(&march, PeriodTransition::SoftClose, b"assets-softclose")
                    .unwrap();
                f.h.transition(&march, PeriodTransition::Close, b"assets-close")
                    .unwrap();
            }
            "revoked" => f.h.revoke(&agent, 232),
            _ => unreachable!(),
        }
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let view = f.h.draft(name);
        let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
        assert!(matches!(refusal.exit, 6 | 7), "{change}: {refusal}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(name), view);
        for retained in &view.intents {
            assert!(
                read_entry(
                    &f.h.db,
                    entry_vid(
                        f.h.book.book_id,
                        &AGENT.0.to_le_bytes(),
                        &retained.intent.proposal().idempotency_key,
                    )
                )
                .unwrap()
                .is_none()
            );
        }
    }
}

#[test]
fn asset_source_authority_precedes_batch_and_missing_draft_observation() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 10_007, 7, 3);
    let other = f.second_schedule();
    let batch = f.charge_pair(&other, "authority-assets");
    let agent = f.h.agent_capability();
    let mut proposal = f.charge_for(&f.schedule, &agent, b"unreadable-asset-review");
    let mut basis = proposal.asset_charge_basis().unwrap().unwrap();
    basis.schedule.vid = VId(999_555);
    proposal.set_asset_charge_basis(&basis).unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        cap()
            .for_accounts(&["1000", "1500", "1590", "6000"])
            .unwrap(),
    ] {
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        assert_eq!(f.post_charges(batch.clone(), &denied).unwrap_err().exit, 7);
        assert_eq!(
            f.h.planned_batch(batch.clone(), &denied).unwrap_err().exit,
            7
        );
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
    for denied in [
        Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Post],
            PRINCIPAL,
        )
        .unwrap(),
        agent.for_accounts(&["1500", "1590", "6000"]).unwrap(),
    ] {
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal =
            f.h.plan_draft(denied, "absent-draft", proposal.clone())
                .unwrap_err();
        assert_eq!(refusal.exit, 7, "{refusal}");
        assert_ne!(refusal.code, code::DRAFT_UNKNOWN);
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
}
