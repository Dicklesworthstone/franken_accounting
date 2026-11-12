//! Reapplication retains the original foreign relief; a later carrying
//! position may admit that exact effect or refuse it, never reprice it.

use super::*;

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
    f.h.post(request(restore)).unwrap();
    assert_eq!(position(&f), (2, 4));
    assert_leg_projections(&f.h);
    f.verify();
}
