//! Reapplication retains the original foreign relief; a later carrying
//! position may admit that exact effect or refuse it, never reprice it.

use super::*;
use fa_model::Entry;

fn position(f: &Fixture) -> (i128, i128) {
    let item = f.carrying();
    (item.open_native.mantissa, item.open_base.mantissa)
}

fn undone(f: &mut Fixture) -> (EntryPayload, EntryRef, EntryPayload, EntryRef) {
    let original = f.prepare(1, b"reapplication-original").into_proposal();
    let applied = f.h.post(request(original.clone())).unwrap().entry_ref();
    let reversal = undo(&original, applied, b"reapplication-undo");
    let reversed = f.h.post(request(reversal.clone())).unwrap().entry_ref();
    (original, applied, reversal, reversed)
}

pub(super) fn plan_reversal_draft(
    f: &mut Fixture,
    name: &str,
    mut proposal: EntryPayload,
) -> (Capability, Entry) {
    let planner = Capability::new(
        AGENT,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap()
    .on_branch(fa_model::draft_branch(f.h.book.book_id, name))
    .unwrap();
    assert!(fa_policy::admit_read(&planner, AGENT, f.h.book.book_id).is_err());
    proposal.principal_ref = AGENT;
    f.h.open_draft(planner.clone(), name).unwrap();
    let planned = f.h.plan_draft(planner.clone(), name, proposal).unwrap();
    let preview = planned.plan.unwrap();
    assert_eq!(preview.members().len(), 1);
    let entry = preview.members()[0].entry.clone();
    let vid = reversal_vid(entry.proposal.supersession[0].target.vid);
    assert!(read_entry(&f.h.db, vid).unwrap().is_none());
    assert_eq!(f.h.draft(name).state, DraftState::Open);
    (planner, entry)
}

pub(super) fn promote_reversal_draft(f: &mut Fixture, name: &str, reviewed: &Entry) -> EntryRef {
    let expected = reviewed.entry_ref(reversal_vid(reviewed.proposal.supersession[0].target.vid));
    let before = f.h.db.frontier().unwrap();
    let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
    assert_eq!(promoted.recorded_at.0, before.0 + 1);
    assert_eq!(promoted.entries, vec![expected]);
    assert!(!promoted.already_recorded);
    let (recorded, at) = read_entry(&f.h.db, expected.vid).unwrap().unwrap();
    assert_eq!(&recorded, reviewed);
    assert_eq!(at, promoted.recorded_at);
    assert_eq!(recorded.proposal.principal_ref, AGENT);
    assert_eq!(f.h.draft(name).state, DraftState::Promoted);
    let rows = f.h.db.vertices().unwrap();
    let retry = f.h.promote(f.h.approver_capability(), name).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, promoted.entries);
    assert_eq!(retry.recorded_at, promoted.recorded_at);
    assert_eq!(f.h.db.frontier().unwrap(), promoted.recorded_at);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    expected
}

#[test]
fn dedicated_foreign_reversal_drafts_restore_exact_relief_without_repricing() {
    let mut f = fixture(3, 10);
    let original = f.prepare(1, b"draft-chain-original").into_proposal();
    let applied = f.h.post(request(original.clone())).unwrap().entry_ref();
    let reversal = undo(&original, applied, b"draft-chain-undo");
    let (planner, reviewed) = plan_reversal_draft(&mut f, "foreign-undo", reversal);
    assert_eq!(position(&f), (2, 7), "planning must not restore capacity");
    let before = f.h.db.frontier().unwrap();
    let mut direct = request(reviewed.proposal.clone());
    direct.capability = planner;
    assert_eq!(f.h.post(direct).unwrap_err().exit, exit::SAFETY);
    let owner = Capability::embedded(AGENT, &["read", "approve"]).unwrap();
    assert_eq!(
        f.h.promote(owner, "foreign-undo").unwrap_err().exit,
        exit::SAFETY
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let reversed = promote_reversal_draft(&mut f, "foreign-undo", &reviewed);
    assert_eq!(position(&f), (3, 10));

    let restore = undo(&reviewed.proposal, reversed, b"draft-chain-redo");
    let (_, reviewed) = plan_reversal_draft(&mut f, "foreign-redo", restore);
    let competing = f.prepare(1, b"draft-chain-intervening").into_proposal();
    f.h.post(request(competing)).unwrap();
    assert_eq!(position(&f), (2, 7));
    assert_eq!(
        f.prepare(1, b"draft-chain-fresh-relief")
            .base_relief()
            .mantissa,
        4
    );
    let cx = f.h.ctx();
    let scratch =
        f.h.runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([131; 32], DatabaseSecurityNamespaceId([132; 32]), [133; 32]),
            ))
            .unwrap();
    let basis = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let (scratch, replay) =
        f.h.runtime
            .block_on(rehearse_draft_into(
                &mut f.h.db,
                scratch,
                &cx,
                &f.h.book,
                &Capability::embedded(APPROVER, &["read"]).unwrap(),
                DraftRehearsalRequest {
                    name: "foreign-redo".into(),
                    known_at: basis,
                },
            ))
            .unwrap()
            .unwrap();
    assert_eq!(
        replay.batch.entries,
        vec![reviewed.entry_ref(reversal_vid(reversed.vid))]
    );
    let scratch_position = open_item_carrying_at(
        &scratch,
        &cx,
        &f.h.book,
        f.target,
        0,
        scratch.frontier().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        (
            scratch_position.open_native.mantissa,
            scratch_position.open_base.mantissa
        ),
        (1, 4)
    );
    assert_eq!(f.h.db.frontier().unwrap(), basis);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_eq!(
        position(&f),
        (2, 7),
        "scratch rehearsal must leave trunk unchanged"
    );
    let restored = promote_reversal_draft(&mut f, "foreign-redo", &reviewed);
    assert_eq!(
        position(&f),
        (1, 4),
        "restore the recorded three, not a newly valued four"
    );

    let second_undo = undo(&reviewed.proposal, restored, b"draft-chain-second-undo");
    let (_, reviewed) = plan_reversal_draft(&mut f, "foreign-second-undo", second_undo);
    assert_eq!(position(&f), (1, 4));
    let second_reversed = promote_reversal_draft(&mut f, "foreign-second-undo", &reviewed);
    assert_eq!(position(&f), (2, 7));
    let second_redo = undo(
        &reviewed.proposal,
        second_reversed,
        b"draft-chain-second-redo",
    );
    let (_, reviewed) = plan_reversal_draft(&mut f, "foreign-second-redo", second_redo);
    promote_reversal_draft(&mut f, "foreign-second-redo", &reviewed);
    assert_eq!(position(&f), (1, 4));
    let final_payment = f.prepare(1, b"draft-chain-final").into_proposal();
    f.h.post(request(final_payment)).unwrap();
    assert_eq!(position(&f), (0, 0));
    assert_leg_projections(&f.h);
    f.verify();
}

#[test]
fn dedicated_foreign_reversal_promotion_rechecks_capacity_and_lineage_atomically() {
    for conflict in [
        "native",
        "negative base",
        "stranded base",
        "source",
        "lineage",
        "revoked",
    ] {
        let mut f = match conflict {
            "negative base" => fixture(2, 3),
            "stranded base" => fixture(2, 1),
            _ => fixture(3, 10),
        };
        let (_, _, reversal, reversed) = undone(&mut f);
        let restore = undo(&reversal, reversed, b"draft-conflicting-redo");
        let name = "conflicting-foreign-redo";
        let (planner, reviewed) = plan_reversal_draft(&mut f, name, restore);
        let expected = match conflict {
            "native" | "negative base" | "stranded base" => {
                let native = if conflict == "native" { 3 } else { 1 };
                let competing = f
                    .prepare(native, b"draft-capacity-competitor")
                    .into_proposal();
                f.h.post(request(competing)).unwrap();
                if conflict == "native" {
                    fa_journal::refusal::code::OVER_APPLICATION
                } else {
                    fa_journal::refusal::code::SETTLE_SHAPE
                }
            }
            "source" => {
                let (source, _) = read_entry(&f.h.db, f.target.vid).unwrap().unwrap();
                let source_undo = undo(&source.proposal, f.target, b"draft-source-undo");
                f.h.post(request(source_undo)).unwrap();
                fa_journal::refusal::code::SETTLE_TARGET
            }
            "lineage" => {
                let competing = undo(&reversal, reversed, b"draft-lineage-competitor");
                f.h.post(request(competing)).unwrap();
                fa_journal::refusal::code::ALREADY_REVERSED
            }
            "revoked" => {
                f.h.revoke(&planner, 191);
                "FA-REF-023"
            }
            _ => unreachable!(),
        };
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused = f.h.promote(f.h.approver_capability(), name).unwrap_err();
        assert_eq!(refused.code, expected, "{conflict}: {refused}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(name).state, DraftState::Open);
        let vid = reversal_vid(reviewed.proposal.supersession[0].target.vid);
        if conflict != "lineage" {
            assert!(read_entry(&f.h.db, vid).unwrap().is_none());
        }
        assert_leg_projections(&f.h);
        f.verify();
    }
}

#[test]
fn foreign_reversal_draft_promotion_rechecks_planner_before_source_history_decode() {
    for revoked in [false, true] {
        let mut f = fixture(3, 10);
        let (_, _, reversal, reversed) = undone(&mut f);
        let restore = undo(&reversal, reversed, b"draft-poisoned-redo");
        let name = "poisoned-foreign-redo";
        let (planner, _) = plan_reversal_draft(&mut f, name, restore);
        if revoked {
            f.h.revoke(&planner, 192);
        }
        let mut poison = fgdb::WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
        poison.set_vertex_property(
            f.target.vid,
            fa_model::symbols::property::FA_PAYLOAD,
            Some(fa_journal::rows::scalar_bytes("payload", vec![0xff]).unwrap()),
        );
        f.h.write_raw(poison);
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let cx = f.h.ctx();
        let request = f.h.draft_request(f.h.approver_capability());
        let result =
            f.h.runtime
                .block_on(promote_draft(&mut f.h.db, &cx, &f.h.book, name, request));
        if revoked {
            let refused = result.unwrap().unwrap_err();
            assert_eq!((refused.code, refused.exit), ("FA-REF-023", exit::SAFETY));
        } else {
            assert!(
                result.is_err(),
                "an admitted planner reaches the poisoned source trap"
            );
        }
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(name).state, DraftState::Open);
    }
}

#[test]
fn foreign_reapplication_drafts_refuse_companions_in_either_order() {
    for reversal_first in [false, true] {
        let mut f = fixture(3, 10);
        let (_, _, reversal, reversed) = undone(&mut f);
        let mut restore = undo(&reversal, reversed, b"draft-mixed-redo");
        restore.principal_ref = AGENT;
        let ordinary = f.h.agent_rent(1, b"draft-mixed-rent");
        let name = "mixed-foreign-redo";
        let planner = f.h.agent_capability();
        f.h.open_draft(planner.clone(), name).unwrap();
        let (first, second) = if reversal_first {
            (restore, ordinary)
        } else {
            (ordinary, restore)
        };
        f.h.plan_draft(planner.clone(), name, first).unwrap();
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused = f.h.plan_draft(planner, name, second).unwrap_err();
        assert_eq!(
            refused.code,
            fa_journal::refusal::code::CLASS_NOT_IMPLEMENTED
        );
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(name).intents.len(), 1);
        assert_eq!(f.h.draft(name).state, DraftState::Open);
        assert_eq!(position(&f), (3, 10));
        f.verify();
    }
}

#[test]
fn foreign_reversal_drafts_keep_branch_and_complete_ancestor_source_scope() {
    for confined in [false, true] {
        let mut f = fixture(3, 10);
        let (_, _, reversal, reversed) = undone(&mut f);
        let mut restore = undo(&reversal, reversed, b"draft-scoped-redo");
        restore.principal_ref = AGENT;
        let name = "scoped-foreign-redo";
        let mut planner = Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Post],
            PRINCIPAL,
        )
        .unwrap();
        if confined {
            planner = planner
                .on_branch(fa_model::draft_branch(f.h.book.book_id, name))
                .unwrap()
                .for_accounts(&["1000", "1211", "2991", "7091"])
                .unwrap();
        }
        f.h.open_draft(planner.clone(), name).unwrap();
        // The applying entry and its reversal fit the proposal scope, but
        // the original receivable's complete footprint also includes 4011.
        // Its poisoned payload must remain unobserved when scope denies it.
        let mut poison = fgdb::WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
        poison.set_vertex_property(
            f.target.vid,
            fa_model::symbols::property::FA_PAYLOAD,
            Some(fa_journal::rows::scalar_bytes("payload", vec![0xff]).unwrap()),
        );
        f.h.write_raw(poison);
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused = f.h.plan_draft(planner, name, restore).unwrap_err();
        let expected = if confined {
            fa_journal::refusal::code::REVERSAL_TARGET
        } else {
            fa_journal::refusal::code::CAPABILITY
        };
        assert_eq!(refused.code, expected, "{refused}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert!(f.h.draft(name).intents.is_empty());
    }
}

#[test]
fn foreign_reapplication_preserves_recorded_relief_through_repeated_lineage_and_history() {
    let mut f = fixture(3, 10);
    let (original, _, reversal, reversed) = undone(&mut f);
    let at_undo = f.h.db.frontier().unwrap();
    assert_eq!(position(&f), (3, 10));
    let competing = f.prepare(1, b"reapplication-intervening").into_proposal();
    f.h.post(request(competing)).unwrap();
    assert_eq!(position(&f), (2, 7));
    assert_eq!(
        f.prepare(1, b"fresh-relief-would-differ")
            .base_relief()
            .mantissa,
        4,
    );

    let restored = undo(&reversal, reversed, b"reapplication-restore");
    let restored_ref = f.h.post(request(restored.clone())).unwrap().entry_ref();
    assert_eq!(
        position(&f),
        (1, 4),
        "the original relief is three, not the newly computed four"
    );
    let at_restore = f.h.db.frontier().unwrap();
    let second_undo = undo(&restored, restored_ref, b"reapplication-second-undo");
    let second_undo_ref = f.h.post(request(second_undo.clone())).unwrap().entry_ref();
    assert_eq!(position(&f), (2, 7));
    let second_restore = undo(
        &second_undo,
        second_undo_ref,
        b"reapplication-second-restore",
    );
    f.h.post(request(second_restore)).unwrap();
    assert_eq!(position(&f), (1, 4));
    let final_payment = f.prepare(1, b"reapplication-final");
    assert_eq!(final_payment.base_relief().mantissa, 4);
    f.h.post(request(final_payment.into_proposal())).unwrap();
    assert_eq!(position(&f), (0, 0));

    let head = f.h.db.frontier().unwrap();
    for recorded in [original, reversal, restored] {
        assert!(matches!(
            f.h.post(request(recorded)).unwrap(),
            Posted::AlreadyRecorded { .. }
        ));
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(position(&f), (0, 0));
    }
    for (at, expected) in [(at_undo, (3, 10)), (at_restore, (1, 4))] {
        let item = open_item_carrying_at(&f.h.db, &f.h.ctx(), &f.h.book, f.target, 0, at)
            .unwrap()
            .unwrap();
        assert_eq!(
            (item.open_native.mantissa, item.open_base.mantissa),
            expected
        );
    }
    assert_leg_projections(&f.h);
    f.verify();
}

#[test]
fn foreign_reapplication_refuses_negative_and_stranded_base_without_repricing_or_publication() {
    for base in [1, 3] {
        let mut f = fixture(2, base);
        let (_, _, reversal, reversed) = undone(&mut f);
        let competing = f
            .prepare(1, b"reapplication-rounded-competitor")
            .into_proposal();
        let competitor = f.h.post(request(competing.clone())).unwrap().entry_ref();
        assert_eq!(position(&f), (1, 1));
        let restore = undo(&reversal, reversed, b"reapplication-rounded-restore");
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused = f.h.post(request(restore.clone())).unwrap_err();
        assert_eq!(refused.code, fa_journal::refusal::code::SETTLE_SHAPE);
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(position(&f), (1, 1));
        assert_leg_projections(&f.h);
        f.verify();

        let undo_competitor = undo(
            &competing,
            competitor,
            b"reapplication-rounded-competitor-undo",
        );
        f.h.post(request(undo_competitor)).unwrap();
        f.h.post(request(restore)).unwrap();
        assert_eq!(position(&f), (1, 1));
        assert_leg_projections(&f.h);
        f.verify();
    }
}

#[test]
fn foreign_reapplication_preserves_native_target_liveness_and_capacity_refusals() {
    for consume_capacity in [false, true] {
        let mut f = fixture(3, 10);
        let (_, _, reversal, reversed) = undone(&mut f);
        let restore = undo(&reversal, reversed, b"reapplication-target-restore");
        let expected = if consume_capacity {
            let competing = f
                .prepare(3, b"reapplication-target-consumed")
                .into_proposal();
            f.h.post(request(competing)).unwrap();
            fa_journal::refusal::code::OVER_APPLICATION
        } else {
            let (source, _) = read_entry(&f.h.db, f.target.vid).unwrap().unwrap();
            let reversed_source =
                undo(&source.proposal, f.target, b"reapplication-target-reversed");
            f.h.post(request(reversed_source)).unwrap();
            fa_journal::refusal::code::SETTLE_TARGET
        };
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused = f.h.post(request(restore)).unwrap_err();
        assert_eq!(refused.code, expected, "{refused}");
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_leg_projections(&f.h);
    }
}

#[test]
fn foreign_reapplication_cannot_precede_the_latest_recorded_item_effect() {
    let mut f = fixture(3, 10);
    let original = f
        .prepare(1, b"reapplication-dated-original")
        .into_proposal();
    let applied = f.h.post(request(original.clone())).unwrap().entry_ref();
    let mut reversal = undo(&original, applied, b"reapplication-dated-undo");
    reversal.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
    let reversed = f.h.post(request(reversal.clone())).unwrap().entry_ref();
    let mut restore = undo(&reversal, reversed, b"reapplication-dated-restore");
    restore.effective_date = f.h.day();
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refused = f.h.post(request(restore.clone())).unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    restore.effective_date = reversal.effective_date;
    f.h.post(request(restore)).unwrap();
    assert_eq!(position(&f), (2, 7));
    f.verify();
}

#[test]
fn foreign_reapplication_requires_read_before_observing_complete_carrying_history() {
    for poison_history in [false, true] {
        let mut f = fixture(3, 10);
        let original = f
            .prepare(1, b"reapplication-authority-original")
            .into_proposal();
        let applied = f.h.post(request(original.clone())).unwrap().entry_ref();
        let reversal = undo(&original, applied, b"reapplication-authority-undo");
        let mut first_undo = request(reversal.clone());
        first_undo.capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
        let reversed = f.h.post(first_undo).unwrap().entry_ref();
        let restore = undo(&reversal, reversed, b"reapplication-authority-restore");
        if poison_history {
            let unrelated = f.h.proposal(
                f.h.rent_legs(1),
                b"reapplication-authority-unrelated",
                EntryClass::ORIGINAL,
            );
            let unrelated = f.h.post(request(unrelated)).unwrap().entry_ref();
            let mut poison = fgdb::WriteBatch::new(fa_model::symbols::relation::CUSTODY_OF);
            poison.set_vertex_property(
                unrelated.vid,
                fa_model::symbols::property::FA_PAYLOAD,
                Some(fa_journal::rows::scalar_bytes("payload", vec![0xff]).unwrap()),
            );
            f.h.write_raw(poison);
        }
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let mut without_read = request(restore.clone());
        without_read.capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
        let refused = f.h.post(without_read).unwrap_err();
        assert_eq!(
            refused.code,
            fa_journal::refusal::code::CAPABILITY,
            "{refused}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        if poison_history {
            assert!(
                open_item_carrying_at(&f.h.db, &f.h.ctx(), &f.h.book, f.target, 0, head,).is_err(),
                "the complete-history reader reaches the planted payload trap"
            );
        } else {
            f.h.post(request(restore)).unwrap();
            assert_eq!(position(&f), (2, 7));
            f.verify();
        }
    }
}

#[test]
fn prepared_foreign_reapplication_keeps_its_complete_prefix_dependency() {
    for consume_capacity in [false, true] {
        let mut f = fixture(3, 10);
        let (_, _, reversal, reversed) = undone(&mut f);
        let restore = undo(&reversal, reversed, b"reapplication-prepared-restore");
        let cx = f.h.ctx();
        let staged = prepare_post(&mut f.h.db, &cx, &f.h.book, request(restore.clone()))
            .unwrap()
            .unwrap();
        let PostPreparation::Ready(prepared) = staged else {
            panic!("a new reapplication is prepared");
        };
        if consume_capacity {
            let competing = f
                .prepare(1, b"reapplication-prepared-competitor")
                .into_proposal();
            f.h.post(request(competing)).unwrap();
        } else {
            let document = f.h.document(
                INVOICE,
                HUMAN_UPLOAD,
                b"unrelated evidence after reapplication preparation",
            );
            f.h.add_document(&document).unwrap();
        }
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused =
            f.h.runtime
                .block_on(prepared.commit(&mut f.h.db, &cx))
                .unwrap()
                .unwrap_err();
        assert_eq!(refused.code, fa_journal::refusal::code::PLAN_INVALIDATED);
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        f.h.post(request(restore)).unwrap();
        assert_eq!(position(&f), if consume_capacity { (1, 4) } else { (2, 7) });
        f.verify();
    }
}

#[test]
fn foreign_reapplication_refuses_compound_publication_even_as_the_first_member() {
    for member_position in 0..3 {
        let mut f = fixture(3, 10);
        let (_, _, reversal, reversed) = undone(&mut f);
        let restore = undo(&reversal, reversed, b"reapplication-batch-restore");
        let ordinary = f.h.proposal(
            f.h.rent_legs(1),
            b"reapplication-batch-companion",
            EntryClass::ORIGINAL,
        );
        let members = match member_position {
            0 => vec![restore.clone(), ordinary],
            1 => vec![ordinary, restore.clone()],
            _ => vec![restore.clone()],
        };
        let batch = f.h.batch(b"reapplication-batch", members);
        let capability = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let direct = f.post_fx_batch(batch.clone()).unwrap_err();
        assert_eq!(
            direct.code,
            fa_journal::refusal::code::CLASS_NOT_IMPLEMENTED
        );
        let planned = f.h.planned_batch(batch, &capability).unwrap_err();
        assert_eq!(
            planned.code,
            fa_journal::refusal::code::CLASS_NOT_IMPLEMENTED
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(position(&f), (3, 10));
        f.h.post(request(restore)).unwrap();
        assert_eq!(position(&f), (2, 7));
        assert_leg_projections(&f.h);
        f.verify();
    }
}

#[test]
fn partial_spot_reapplication_uses_the_applied_quote_amount_not_the_complete_leg() {
    let mut f = fixture(3, 6);
    let cash = account_vid(f.h.book.book_id, "1011");
    let cx = f.h.ctx();
    let day = f.h.day();
    let description =
        f.h.proposal(vec![], b"spot-cash-description", EntryClass::ORIGINAL)
            .description;
    f.h.runtime
        .block_on(install_chart(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &[AccountSpec {
                code: "1011".into(),
                name: "EUR cash".into(),
                account_type: fa_model::AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(f.foreign),
                parent_code: None,
                limit: None,
            }],
            PRINCIPAL,
            day,
            b"spot-eur-cash-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let (source, _) = read_entry(&f.h.db, f.target.vid).unwrap().unwrap();
    let mut proposal = f.h.proposal(
        vec![
            LegPayload::simple(Side::Debit, cash, Amount::new(f.foreign, 3)),
            LegPayload::simple(
                Side::Credit,
                source.proposal.legs[0].account_ref,
                Amount::new(f.foreign, 3),
            ),
        ],
        b"reapplication-partial-spot",
        EntryClass::ORIGINAL,
    );
    proposal.legs[1].settles = vec![Settlement {
        target: f.target,
        ordinal: 0,
        amount: Amount::new(f.foreign, 1),
    }];
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: f.h.usd,
            quote_unit: f.foreign,
            rate_num: 2,
            rate_den: 1,
            rounding: RoundingLaw::HalfEven,
        },
        f.h.day(),
        1_700_000_000_000_000_001,
        FxRatePurpose::Settlement,
        "explicit settlement rate",
    )
    .unwrap();
    assert_eq!(
        rate.evidence_ref(f.h.book.book_id).unwrap().document_oid,
        f.rate
    );
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let spec = fa_journal::genesis::read_book_spec(&f.h.db)
        .unwrap()
        .unwrap();
    let proposal = value_proposal(
        &mut budget,
        proposal,
        &spec,
        &f.h.book.units,
        FxLawId::SettlementSpotCarrying,
        &[rate],
    )
    .unwrap();
    assert_eq!(proposal.legs[1].base_amount.unwrap().mantissa, 6);
    let applied = f.h.post(request(proposal.clone())).unwrap().entry_ref();
    assert_eq!(position(&f), (2, 4));
    let reversal = undo(&proposal, applied, b"reapplication-partial-spot-undo");
    let reversed = f.h.post(request(reversal.clone())).unwrap().entry_ref();
    assert_eq!(position(&f), (3, 6));
    let restore = undo(&reversal, reversed, b"reapplication-partial-spot-restore");
    let restored = f.h.post(request(restore.clone())).unwrap().entry_ref();
    assert_eq!(position(&f), (2, 4));
    let draft_undo = undo(&restore, restored, b"draft-partial-spot-undo");
    let (_, reviewed) = plan_reversal_draft(&mut f, "partial-spot-undo", draft_undo);
    let reversed = promote_reversal_draft(&mut f, "partial-spot-undo", &reviewed);
    assert_eq!(position(&f), (3, 6));
    let draft_restore = undo(&reviewed.proposal, reversed, b"draft-partial-spot-redo");
    let (_, reviewed) = plan_reversal_draft(&mut f, "partial-spot-redo", draft_restore);
    promote_reversal_draft(&mut f, "partial-spot-redo", &reviewed);
    assert_eq!(position(&f), (2, 4));
    assert_leg_projections(&f.h);
    f.verify();
}
