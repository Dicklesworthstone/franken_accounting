//! A draft review uses the real ordered batch and retained planner authority in
//! an isolated scratch book. Source history is admitted before it is copied.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::post::read_entry;
use fa_journal::refusal::{Outcome, code};
use fa_journal::rows::{edge_id, prop, reversal_vid};
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, EvidenceRef, Id128,
    LegPayload, Oid, SealKey, Supersession, SupersessionKind, SymbolTable, account_vid, entry_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Op, Profile};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

#[path = "draft_rehearsal/fixture.rs"]
mod fixture;
use fixture::*;

#[test]
fn agent_rehearsal_matches_atomic_promotion_without_touching_trunk() {
    let mut h = Harness::new(None);
    let planner = agent().with_ceiling(h.usd, 20_000).unwrap();
    let opened = h.open("close-march", planner.clone());
    let first = h.proposal(12_345, b"rent", EntryClass::ORIGINAL, AGENT);
    let second = h.proposal(500, b"fees", EntryClass::ORIGINAL, AGENT);
    let approvals = [h.approve(&first, APPROVER), h.approve(&second, APPROVER)];
    let first_intent = PostIntent::new(first.clone(), vec![approvals[0]]).unwrap();
    let second_intent = PostIntent::new(second.clone(), vec![approvals[1]]).unwrap();
    let first_plan = h.plan("close-march", planner.clone(), first_intent.clone());
    let second_plan = h.plan("close-march", planner.clone(), second_intent.clone());
    h.maintenance(1);
    let basis = h.head();
    let before_rows = h.db.vertices().unwrap();
    let before_edges = h.db.edges_at(basis).unwrap();
    let before_view = h.draft("close-march");
    let before_cash = cash_balance(&h.db, h.cash);
    let expected = vec![member_ref(&first_intent), member_ref(&second_intent)];
    let (target, _) = h.target();
    let (scratch, review) = h
        .rehearse(target, &reader(), "close-march", basis)
        .unwrap()
        .unwrap();

    assert_eq!(review.source.known_at, basis);
    assert_eq!(review.source.body, before_view.body);
    assert_eq!(
        review.source.open.entry_ref,
        recorded_ref(&h.db, opened.control_entry)
    );
    assert_eq!(review.source.open.recorded_at, opened.recorded_at);
    assert_eq!(
        review
            .source
            .plans
            .iter()
            .map(|p| p.entry_ref)
            .collect::<Vec<_>>(),
        vec![
            recorded_ref(&h.db, first_plan.recorded.control_entry),
            recorded_ref(&h.db, second_plan.recorded.control_entry),
        ]
    );
    assert_eq!(
        review
            .source
            .plans
            .iter()
            .map(|p| p.recorded_at)
            .collect::<Vec<_>>(),
        vec![
            first_plan.recorded.recorded_at,
            second_plan.recorded.recorded_at
        ]
    );
    let source_bytes = review.source.canonical_bytes().unwrap();
    assert_eq!(
        DraftRehearsalSource::decode(&source_bytes).unwrap(),
        review.source
    );
    assert_eq!(review.view, before_view);
    assert!(review.view.intents.iter().all(|p| p.capability == planner));
    assert_eq!(review.view.intents[0].intent, first_intent);
    assert_eq!(review.view.intents[1].intent, second_intent);
    assert_eq!(review.seq_map.source_prefix, basis);
    assert!(
        review
            .seq_map
            .pairs
            .iter()
            .all(|p| p.source_seq == p.scratch_seq)
    );
    assert_eq!(review.batch.entries, expected);
    assert_eq!(review.batch.recorded_at, CommitSeq(basis.0 + 1));
    assert_eq!(scratch.frontier().unwrap(), review.batch.recorded_at);
    assert!(!review.batch.already_recorded);
    assert_eq!(
        review.batch.periods,
        vec![h.period.clone(), h.period.clone()]
    );
    assert_eq!(cash_balance(&scratch, h.cash), before_cash - 12_845);
    assert!(scratch.vertex(maintenance_vid(1)).unwrap().is_none());
    assert_eq!(
        read_draft(&scratch, &h.ctx().query(), &h.book, "close-march")
            .unwrap()
            .unwrap(),
        before_view
    );
    for (member, approval) in review.batch.entries.iter().zip(approvals) {
        let (entry, recorded_at) = read_entry(&scratch, member.vid).unwrap().unwrap();
        assert_eq!(recorded_at, review.batch.recorded_at);
        assert_eq!(entry.proposal.principal_ref, AGENT);
        assert_eq!(entry.approvals, vec![approval]);
        assert_eq!(entry.entry_digest, member.entry_digest);
        assert!(read_entry(&h.db, member.vid).unwrap().is_none());
    }
    assert_eq!(h.head(), basis);
    assert_eq!(h.db.vertices().unwrap(), before_rows);
    assert_eq!(h.db.edges_at(basis).unwrap(), before_edges);
    assert_eq!(h.draft("close-march"), before_view);
    assert_eq!(cash_balance(&h.db, h.cash), before_cash);

    let promoted = h.promote("close-march");
    assert_eq!(promoted.entries, review.batch.entries);
    assert_eq!(promoted.recorded_at, review.batch.recorded_at);
    assert_eq!(promoted.outcome, review.batch.outcome);
    for member in &promoted.entries {
        assert_eq!(
            read_entry(&h.db, member.vid).unwrap(),
            read_entry(&scratch, member.vid).unwrap()
        );
    }
    assert_eq!(cash_balance(&h.db, h.cash), cash_balance(&scratch, h.cash));
    assert_eq!(h.draft("close-march").state, DraftState::Promoted);

    // A subsequent live promotion does not reinterpret the captured review.
    let promoted_at = h.head();
    let (target, _) = h.target();
    let (historical, replay) = h
        .rehearse(target, &reader(), "close-march", basis)
        .unwrap()
        .unwrap();
    assert_eq!(
        replay.source.canonical_bytes().unwrap(),
        review.source.canonical_bytes().unwrap()
    );
    assert_eq!(
        replay.source.digest().unwrap(),
        review.source.digest().unwrap()
    );
    assert_eq!(replay.seq_map, review.seq_map);
    assert_eq!(replay.batch.entries, review.batch.entries);
    assert_eq!(historical.frontier().unwrap(), scratch.frontier().unwrap());
    assert_eq!(
        cash_balance(&historical, h.cash),
        cash_balance(&scratch, h.cash)
    );
    assert_eq!(h.head(), promoted_at);
}

#[test]
fn individually_valid_plans_share_one_limit_and_cannot_publish_a_partial_batch() {
    let mut h = Harness::new(Some(BalanceLimit {
        lower: Some(-1_000),
        upper: None,
        scope: LimitScope::Lifetime,
    }));
    let planner = agent();
    h.open("overdraft", planner.clone());
    let mut members = Vec::new();
    for key in [b"first".as_slice(), b"second".as_slice()] {
        let proposal = h.proposal(600, key, EntryClass::ORIGINAL, AGENT);
        let intent = PostIntent::new(proposal, Vec::new()).unwrap();
        members.push(member_ref(&intent));
        let planned = h.plan("overdraft", planner.clone(), intent);
        assert!(
            planned.plan.is_some(),
            "each intent passes against unchanged trunk"
        );
    }
    let basis = h.head();
    let before = h.db.vertices().unwrap();
    let (target, storage) = h.target();
    let refusal = lawful_refusal(h.rehearse(target, &reader(), "overdraft", basis));
    assert!(refusal.message.starts_with("batch member 1:"), "{refusal}");
    assert_eq!(
        refusal.code,
        code::AVAILABILITY_LOWER,
        "the second member sees the first cash outflow"
    );
    assert_eq!(h.head(), basis);
    assert_eq!(h.db.vertices().unwrap(), before);
    assert_eq!(h.draft("overdraft").state, DraftState::Open);
    assert_eq!(cash_balance(&h.db, h.cash), 0);

    let scratch = h.reopen(&storage);
    assert_eq!(
        scratch.frontier().unwrap(),
        basis,
        "only the source prefix was copied"
    );
    assert_eq!(cash_balance(&scratch, h.cash), 0);
    for member in members {
        assert!(read_entry(&scratch, member.vid).unwrap().is_none());
        assert!(read_entry(&h.db, member.vid).unwrap().is_none());
    }
    assert!(
        scratch
            .vertices()
            .unwrap()
            .iter()
            .all(|row| !row.labels.contains(&label::INTENT_OUTCOME))
    );
}

#[test]
fn scratch_admission_cannot_be_reused_on_an_existing_database() {
    let mut h = Harness::new(None);
    h.open("isolated", agent());
    let intent = PostIntent::new(
        h.proposal(100, b"isolated", EntryClass::ORIGINAL, AGENT),
        Vec::new(),
    )
    .unwrap();
    h.plan("isolated", agent(), intent);
    let basis = h.head();
    let (target, storage) = h.target();
    let (scratch, review) = h
        .rehearse(target, &reader(), "isolated", basis)
        .unwrap()
        .unwrap();
    let rows = scratch.vertices().unwrap();
    let refusal = lawful_refusal(h.rehearse(scratch, &reader(), "isolated", basis));
    assert_eq!(refusal.code, code::STRUCTURE, "{refusal}");
    let reopened = h.reopen(&storage);
    assert_eq!(reopened.frontier().unwrap(), review.batch.recorded_at);
    assert_eq!(reopened.vertices().unwrap(), rows);
    assert_eq!(h.head(), basis);
    assert_eq!(h.draft("isolated").state, DraftState::Open);
}

#[test]
fn maintenance_coordinates_cannot_revive_expired_planner_authority() {
    let mut h = Harness::new(None);
    h.open("expiry", agent());
    h.maintenance(1);
    h.maintenance(2);
    let expiry = CommitSeq(h.head().0 + 2);
    let planner = agent().expiring_at(expiry);
    let intent = PostIntent::new(
        h.proposal(100, b"expires", EntryClass::ORIGINAL, AGENT),
        Vec::new(),
    )
    .unwrap();
    let expected = member_ref(&intent);
    h.plan("expiry", planner.clone(), intent);
    let captured = h.head();
    assert_eq!(captured.0 + 1, expiry.0);
    h.maintenance(3);
    assert_eq!(h.head(), expiry);

    let (target, storage) = h.target();
    let refusal = lawful_refusal(h.rehearse(target, &reader(), "expiry", expiry));
    assert!(refusal.message.contains("expired"), "{refusal}");
    let scratch = h.reopen(&storage);
    assert_eq!(scratch.frontier().unwrap(), expiry);
    assert!(read_entry(&scratch, expected.vid).unwrap().is_none());
    assert_eq!(h.head(), expiry);

    // The original prefix remains a valid historical rehearsal. Keeping all
    // source sequences also keeps its stored planner's expiry unchanged.
    let (target, _) = h.target();
    let (scratch, review) = h
        .rehearse(target, &reader(), "expiry", captured)
        .unwrap()
        .unwrap();
    assert_eq!(review.view.intents[0].capability, planner);
    assert_eq!(review.batch.entries, vec![expected]);
    assert_eq!(review.batch.recorded_at, expiry);
    assert_eq!(scratch.frontier().unwrap(), expiry);
    assert_eq!(review.seq_map.source_prefix, captured);
    assert!(
        review
            .seq_map
            .pairs
            .iter()
            .all(|pair| pair.source_seq == pair.scratch_seq)
    );
    for ordinal in [1, 2, 3] {
        assert!(scratch.vertex(maintenance_vid(ordinal)).unwrap().is_none());
    }
    assert_eq!(h.head(), expiry);
}

#[test]
fn revoked_planner_is_rejected_at_head_and_historical_review_keeps_its_old_basis() {
    let mut h = Harness::new(None);
    let planner = agent();
    h.open("revocation", planner.clone());
    let intent = PostIntent::new(
        h.proposal(100, b"revoked", EntryClass::ORIGINAL, AGENT),
        Vec::new(),
    )
    .unwrap();
    let expected = member_ref(&intent);
    h.plan("revocation", planner.clone(), intent);
    let captured = h.head();
    h.revoke(&planner, b"revoke-planner");
    let revoked_at = h.head();
    let (target, storage) = h.target();
    let refusal = lawful_refusal(h.rehearse(target, &reader(), "revocation", revoked_at));
    assert_eq!(refusal.code, "FA-REF-023", "{refusal}");
    assert!(
        read_entry(&h.reopen(&storage), expected.vid)
            .unwrap()
            .is_none()
    );
    assert_eq!(h.head(), revoked_at);
    let (target, _) = h.target();
    let (_, historical) = h
        .rehearse(target, &reader(), "revocation", captured)
        .unwrap()
        .unwrap();
    assert_eq!(historical.source.known_at, captured);
    assert_eq!(historical.batch.entries, vec![expected]);
    assert_eq!(h.head(), revoked_at);
}

#[test]
fn current_whole_book_read_is_required_before_draft_existence_or_copying() {
    let mut h = Harness::new(None);
    h.open("private", agent());
    let intent = PostIntent::new(
        h.proposal(100, b"private", EntryClass::ORIGINAL, AGENT),
        Vec::new(),
    )
    .unwrap();
    h.plan("private", agent(), intent);
    let captured = h.head();
    let revoked = Capability::embedded(VId(94), &["read"]).unwrap();
    h.revoke(&revoked, b"revoke-reviewer");
    let head = h.head();
    let readers = [
        Capability::embedded(REVIEWER, &["post"]).unwrap(),
        reader().for_books(&[Id128([99; 16])]).unwrap(),
        reader().for_accounts(&["1000"]).unwrap(),
        reader().expiring_at(head),
        revoked,
    ];
    for capability in readers {
        let mut refused_code = None;
        for name in ["private", "does-not-exist"] {
            let (target, storage) = h.target();
            let refusal = lawful_refusal(h.rehearse(target, &capability, name, captured));
            assert_eq!(refusal.exit, exit::SAFETY, "{refusal}");
            assert_ne!(refusal.code, code::DRAFT_UNKNOWN);
            if let Some(previous) = refused_code {
                assert_eq!(refusal.code, previous, "existence cannot change admission");
            }
            refused_code = Some(refusal.code);
            let scratch = h.reopen(&storage);
            assert_eq!(scratch.frontier().unwrap(), CommitSeq(0));
            assert!(scratch.vertices().unwrap().is_empty());
            assert_eq!(h.head(), head);
        }
    }
}

#[test]
fn period_close_rechecks_the_original_agent_and_independent_human_approval() {
    for approved in [false, true] {
        let mut h = Harness::new(None);
        let original = h.proposal(1_000, b"original", EntryClass::ORIGINAL, OWNER);
        let original = h.post(original);
        let planner = Capability::new(
            AGENT,
            Profile::Agent,
            &[Op::Read, Op::Post, Op::PostClosed],
            OWNER,
        )
        .unwrap();
        h.open("closed-reversal", planner.clone());
        let mut reversal = h.proposal(1_000, b"undo", EntryClass::REVERSAL, AGENT);
        for leg in &mut reversal.legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
        }
        reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
        reversal.supersession = vec![Supersession {
            target: original,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        let approvals = if approved {
            vec![h.approve(&reversal, APPROVER)]
        } else {
            Vec::new()
        };
        let intent = PostIntent::new(reversal, approvals.clone()).unwrap();
        h.plan("closed-reversal", planner.clone(), intent);
        h.transition(PeriodTransition::SoftClose, b"soft-close");
        h.transition(PeriodTransition::Close, b"close");
        let basis = h.head();
        let (target, storage) = h.target();
        let result = h.rehearse(target, &reader(), "closed-reversal", basis);
        if approved {
            let (scratch, review) = result.unwrap().unwrap();
            assert_eq!(review.view.intents[0].capability, planner);
            assert_eq!(review.batch.entries.len(), 1);
            assert_eq!(review.batch.entries[0].vid, reversal_vid(original.vid));
            let (entry, _) = read_entry(&scratch, review.batch.entries[0].vid)
                .unwrap()
                .unwrap();
            assert_eq!(entry.approvals, approvals);
            assert_eq!(entry.proposal.principal_ref, AGENT);
            assert_eq!(cash_balance(&scratch, h.cash), 0);
        } else {
            let refusal = lawful_refusal(result);
            assert_eq!(refusal.exit, exit::SAFETY, "{refusal}");
            assert!(
                refusal.message.contains("Human") || refusal.message.contains("human"),
                "{refusal}"
            );
            let scratch = h.reopen(&storage);
            assert_eq!(scratch.frontier().unwrap(), basis);
            assert!(
                read_entry(&scratch, reversal_vid(original.vid))
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(h.head(), basis);
        assert_eq!(cash_balance(&h.db, h.cash), -1_000);
        assert_eq!(h.draft("closed-reversal").state, DraftState::Open);
    }
}

#[test]
fn original_plan_cannot_rehearse_after_its_period_closes() {
    let mut h = Harness::new(None);
    h.open("closed-original", agent());
    let intent = PostIntent::new(
        h.proposal(100, b"closed-original", EntryClass::ORIGINAL, AGENT),
        Vec::new(),
    )
    .unwrap();
    let member = member_ref(&intent);
    h.plan("closed-original", agent(), intent);
    h.transition(PeriodTransition::SoftClose, b"soft-close");
    h.transition(PeriodTransition::Close, b"close");
    let basis = h.head();
    let (target, storage) = h.target();
    let refusal = lawful_refusal(h.rehearse(target, &reader(), "closed-original", basis));
    assert_eq!(refusal.code, code::PERIOD_LAW, "{refusal}");
    assert_eq!(h.head(), basis);
    let scratch = h.reopen(&storage);
    assert_eq!(scratch.frontier().unwrap(), basis);
    assert!(read_entry(&scratch, member.vid).unwrap().is_none());
}

#[test]
fn incomplete_extra_or_rewritten_draft_sources_fail_before_any_scratch_publication() {
    for attack in [
        "missing-membership",
        "foreign-plan-membership",
        "plan-rewrite-restored",
        "body-rewrite-restored",
        "plan-maintenance-relabel",
    ] {
        let mut h = Harness::new(None);
        h.open("reviewed", agent());
        let intent = PostIntent::new(
            h.proposal(100, b"reviewed", EntryClass::ORIGINAL, AGENT),
            Vec::new(),
        )
        .unwrap();
        let planned = h.plan("reviewed", agent(), intent);
        let draft = h.draft("reviewed").vid;
        let plan = planned.recorded.control_entry;
        match attack {
            "missing-membership" => {
                let mut change = WriteBatch::new(relation::IN_CASE);
                change.delete_edge(edge_id(relation::IN_CASE, plan, draft));
                h.write(change);
            }
            "foreign-plan-membership" => {
                h.open("another", agent());
                let other = PostIntent::new(
                    h.proposal(1, b"another", EntryClass::ORIGINAL, AGENT),
                    Vec::new(),
                )
                .unwrap();
                let other = h.plan("another", agent(), other).recorded.control_entry;
                let mut change = WriteBatch::new(relation::IN_CASE);
                change.add_edge(
                    edge_id(relation::IN_CASE, other, draft),
                    other,
                    draft,
                    vec![],
                );
                h.write(change);
            }
            "plan-rewrite-restored" | "body-rewrite-restored" => {
                let vid = if attack == "plan-rewrite-restored" {
                    plan
                } else {
                    draft
                };
                let original = h.db.vertex(vid).unwrap().unwrap();
                let payload = prop(&original, property::FA_PAYLOAD).unwrap().clone();
                let mut change = WriteBatch::new(relation::IN_CASE);
                change.set_vertex_property(
                    vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(vec![0]).unwrap()),
                );
                h.write(change);
                let mut restore = WriteBatch::new(relation::IN_CASE);
                restore.set_vertex_property(vid, property::FA_PAYLOAD, Some(payload));
                h.write(restore);
                let restored = h.db.vertex(vid).unwrap().unwrap();
                assert_eq!(restored.props, original.props);
                assert_eq!(restored.labels, original.labels);
            }
            "plan-maintenance-relabel" => {
                let mut change = WriteBatch::new(relation::IN_CASE);
                change.set_vertex_label(plan, label::REGISTER, true);
                h.write(change);
            }
            _ => unreachable!(),
        }
        let basis = h.head();
        let before = h.db.vertices().unwrap();
        let (target, storage) = h.target();
        match h.rehearse(target, &reader(), "reviewed", basis) {
            Err(KernelError::Corrupt(_)) => {}
            Err(error) => panic!("{attack}: unexpected foundation failure: {error}"),
            Ok(Err(refusal)) => {
                panic!("{attack}: native history damage must be corruption: {refusal}")
            }
            Ok(Ok(_)) => panic!("{attack}: damaged draft was rehearsed"),
        }
        let scratch = h.reopen(&storage);
        assert_eq!(scratch.frontier().unwrap(), CommitSeq(0), "{attack}");
        assert!(scratch.vertices().unwrap().is_empty(), "{attack}");
        assert_eq!(h.head(), basis, "{attack}");
        assert_eq!(h.db.vertices().unwrap(), before, "{attack}");
    }
}
