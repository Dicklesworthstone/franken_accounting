use super::*;

fn retained_entries(f: &RevaluedFixture, at: CommitSeq) -> usize {
    f.f.h
        .db
        .vertices_at(at)
        .unwrap()
        .into_iter()
        .filter(|row| row.labels.contains(&fa_model::symbols::label::ENTRY))
        .count()
}

#[test]
fn allocated_population_decodes_one_history_as_the_item_count_grows() {
    for count in [16, 64, 256] {
        let input = vec![(3, 10); count];
        let mut f = RevaluedFixture::new(Side::Debit, &input);
        let prepared = f.revaluation(13, 3, 3, true).unwrap();
        let work = prepared.population_work();
        let entries = retained_entries(&f, prepared.known_at());
        assert_eq!(work.history_scans, 1, "items={count}");
        assert_eq!(work.entries_decoded, entries, "items={count}");
        assert_eq!(work.source_guard_entries, entries, "items={count}");
        assert_eq!(
            work.item_effect_entries, 0,
            "unrelated entries are not item effects"
        );
        assert_eq!(work.applications_indexed, 0);
        assert_eq!(work.settlement_legs_examined, 0);

        // The independently implemented unbounded-integer oracle owns the
        // allocation expectation, including the immutable item tie order.
        let expected = allocate_revalued_carrying(13 * count as i128, &input).unwrap();
        let allocation = prepared.basis().item_allocation.as_ref().unwrap();
        assert_eq!(allocation.items.len(), count);
        let mut targets = f.targets.clone();
        targets.sort_by_key(|target| target.vid);
        for ((item, expected), target) in allocation.items.iter().zip(expected).zip(targets) {
            assert_eq!(item.target, target);
            assert_eq!(item.ordinal, 0);
            assert_eq!(item.open_native.mantissa, expected.native);
            assert_eq!(item.historical_base.mantissa, expected.historical_base);
            assert_eq!(item.prior_valuation.mantissa, 0);
            assert_eq!(item.target_base.mantissa, expected.carrying_base);
        }
    }
}

#[test]
fn a_thousand_items_in_one_entry_do_not_redecode_that_entry_per_ordinal() {
    let count = 1_024_u16;
    let mut f = RevaluedFixture::new(Side::Debit, &[]);
    let rate = f.rate(10, 3, day(3, 15), FxRatePurpose::SpotClose);
    let mut legs = vec![
        LegPayload::simple(Side::Debit, f.source, Amount::new(f.f.foreign, 3));
        usize::from(count)
    ];
    legs.push(LegPayload::simple(
        Side::Credit,
        account_vid(f.f.h.book.book_id, "4011"),
        Amount::new(f.f.foreign, i128::from(count) * 3),
    ));
    let proposal =
        f.f.h
            .proposal(legs, b"many-foreign-items", EntryClass::ORIGINAL);
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let spec = fa_journal::genesis::read_book_spec(&f.f.h.db)
        .unwrap()
        .unwrap();
    let proposal = value_proposal(
        &mut budget,
        proposal,
        &spec,
        &f.f.h.book.units,
        FxLawId::SpotClose,
        &[rate],
    )
    .unwrap();
    let target = f.f.h.post(request(proposal)).unwrap().entry_ref();
    let prepared = f.revaluation(13, 3, 3, true).unwrap();
    let work = prepared.population_work();
    assert_eq!(work.history_scans, 1);
    assert_eq!(
        work.entries_decoded,
        retained_entries(&f, prepared.known_at())
    );
    assert_eq!(work.source_guard_entries, work.entries_decoded);
    assert_eq!(work.item_effect_entries, 0);
    let input = vec![(3, 10); usize::from(count)];
    let expected = allocate_revalued_carrying(13 * i128::from(count), &input).unwrap();
    let allocation = prepared.basis().item_allocation.as_ref().unwrap();
    assert_eq!(allocation.items.len(), usize::from(count));
    for (ordinal, (item, expected)) in allocation.items.iter().zip(expected).enumerate() {
        assert_eq!(item.target, target);
        assert_eq!(usize::from(item.ordinal), ordinal);
        assert_eq!(item.open_native.mantissa, expected.native);
        assert_eq!(item.historical_base.mantissa, expected.historical_base);
        assert_eq!(item.target_base.mantissa, expected.carrying_base);
    }
}

#[test]
fn grouped_release_validation_visits_group_legs_linearly_and_undo_is_exact() {
    for count in [8, 64] {
        let mut f = RevaluedFixture::new(Side::Debit, &vec![(3, 10); count]);
        let first = f.revaluation(13, 3, 3, true).unwrap();
        f.post_revaluation(first, b"indexed-group-first-valuation");
        let requests = f
            .targets
            .iter()
            .map(|target| f.f.fx_request(*target, 1))
            .collect::<Vec<_>>();
        let mut template =
            f.f.h
                .proposal(vec![], b"indexed-group-release", EntryClass::ORIGINAL);
        template.effective_date = day(4, 15);
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let group = prepare_fx_settlement_group(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &requests,
            template,
            &mut budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(group.audit_work().source_history_audits, 1);
        assert_eq!(group.audit_work().successful_reuses, count - 1);
        let group = group.into_proposal();
        let legs = group.legs.len();
        let posted = f.f.h.post(request(group.clone())).unwrap();
        let prepared = f.revaluation(5, 1, 4, true).unwrap();
        let work = prepared.population_work();
        assert_eq!(work.history_scans, 1);
        assert_eq!(
            work.entries_decoded,
            retained_entries(&f, prepared.known_at())
        );
        assert_eq!(work.applications_indexed, count);
        assert_eq!(
            work.item_effect_entries,
            count * 2,
            "one allocation and application per item"
        );
        assert_eq!(
            work.settlement_legs_examined, legs,
            "the immutable group shape is checked once"
        );
        assert!(work.release_items_examined <= count * 8, "{work:?}");
        assert!(work.release_legs_examined <= legs * 4, "{work:?}");

        let initial = OracleRevaluedCarrying {
            native: 3,
            historical_base: 10,
            carrying_base: 13,
        };
        let released = remaining_revalued_carrying_relief(initial, 1).unwrap();
        let after = OracleRevaluedCarrying {
            native: initial.native - released.native,
            historical_base: initial.historical_base - released.historical_base,
            carrying_base: initial.carrying_base - released.carrying_base,
        };
        let inputs = vec![(after.native, after.historical_base); count];
        let expected =
            allocate_revalued_carrying(5 * after.native * count as i128, &inputs).unwrap();
        let allocation = prepared.basis().item_allocation.as_ref().unwrap();
        for (item, expected) in allocation.items.iter().zip(expected) {
            assert_eq!(item.open_native.mantissa, expected.native);
            assert_eq!(item.historical_base.mantissa, expected.historical_base);
            assert_eq!(
                item.prior_valuation.mantissa,
                after.carrying_base - after.historical_base
            );
            assert_eq!(item.target_base.mantissa, expected.carrying_base);
        }
        // The unchanged literal single-item reader independently selects its
        // full prefix. These probes also verify the cached release's exact
        // source commitment against the recorded group.
        for index in [0, count / 2, count - 1] {
            assert_eq!(f.position(f.targets[index], None), after);
        }

        f.f.h
            .post(request(undo(
                &group,
                posted.entry_ref(),
                b"indexed-group-undo",
            )))
            .unwrap();
        let restored = f.revaluation(5, 1, 4, true).unwrap();
        let work = restored.population_work();
        assert_eq!(
            work.item_effect_entries,
            count * 3,
            "allocation, application and exact undo"
        );
        assert!(work.settlement_legs_examined <= legs * 2, "{work:?}");
        assert!(work.release_items_examined <= count * 8, "{work:?}");
        for item in &restored.basis().item_allocation.as_ref().unwrap().items {
            assert_eq!(item.open_native.mantissa, initial.native);
            assert_eq!(item.historical_base.mantissa, initial.historical_base);
            assert_eq!(
                item.prior_valuation.mantissa,
                initial.carrying_base - initial.historical_base
            );
        }
        for index in [0, count / 2, count - 1] {
            assert_eq!(f.position(f.targets[index], None), initial);
        }
    }
}

#[test]
fn shared_population_keeps_later_effective_applications_in_its_native_prefix() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10), (3, 10)]);
    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"future-effect-first-valuation");
    let target = f.targets[0];
    let before = f.f.h.db.frontier().unwrap();
    let future = f
        .prepare(target, 1, day(5, 15), b"future-effective-application")
        .unwrap();
    f.f.h.post(request(future.into_proposal())).unwrap();
    let literal = open_item_carrying_at(
        &f.f.h.db,
        &f.f.h.ctx(),
        &f.f.h.book,
        target,
        0,
        f.f.h.db.frontier().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(literal.latest_effective_date, day(5, 15));
    assert_eq!(f.position(target, Some(before)).native, 3);
    let refusal = f.revaluation(5, 1, 4, true).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-102", "{refusal}");
    assert!(
        refusal
            .message
            .contains("would precede an already recorded application"),
        "{refusal}"
    );
}

#[test]
fn allocated_release_recognition_reads_each_reversal_edge_once() {
    for count in [32, 256] {
        let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
        let allocation = f.revaluation(13, 3, 3, true).unwrap();
        f.post_revaluation(allocation, b"lineage-initial-allocation");
        let proposal = f
            .prepare(f.targets[0], 1, day(4, 15), b"lineage-release")
            .unwrap()
            .into_proposal();
        let posted = f.f.h.post(request(proposal.clone())).unwrap();
        let mut parent = posted.entry_ref();
        let mut previous = proposal;
        let mut births = fgdb::WriteBatch::new(relation::IN_BOOK);
        // Exercise the retained-prefix reader directly with canonically
        // sealed exact reversal records. This is not a claim that the current
        // posting API admits re-applying an allocated settlement by reversal
        // of its undo; source verification must still bound its native reads.
        for ordinal in 0..count {
            let key = format!("retained-release-reversal-{ordinal}");
            let reversal = undo(&previous, parent, key.as_bytes());
            let entry = reversal.seal(vec![], None).unwrap();
            let vid = reversal_vid(parent.vid);
            births.create_vertex(
                vid,
                vec![fa_model::symbols::label::ENTRY],
                fa_model::entry_mirrors(&entry).unwrap(),
            );
            parent = entry.entry_ref(vid);
            previous = entry.proposal;
        }
        f.f.h.write_raw(births);
        let prepared = f.revaluation(5, 1, 4, false).unwrap();
        assert_eq!(
            prepared.population_work().release_lineage_entries_read,
            count
        );
        // An even exact reversal chain leaves the original application in
        // force. The independent oracle supplies its remaining components.
        let initial = OracleRevaluedCarrying {
            native: 3,
            historical_base: 10,
            carrying_base: 13,
        };
        let released = remaining_revalued_carrying_relief(initial, 1).unwrap();
        assert_eq!(
            prepared.source_native_net().mantissa,
            initial.native - released.native
        );
        assert_eq!(
            prepared.source_base_net().mantissa,
            initial.historical_base - released.historical_base
        );
        assert_eq!(
            prepared.current_carrying_net().mantissa,
            initial.carrying_base - released.carrying_base
        );

        // A newly encountered child never inherits authority to change its
        // immediate parent's digest, even when that parent has a valid suffix.
        let mut bad = undo(&previous, parent, b"retained-bad-child");
        bad.supersession[0].target.entry_digest[0] ^= 1;
        let bad = bad.seal(vec![], None).unwrap();
        let mut birth = fgdb::WriteBatch::new(relation::IN_BOOK);
        birth.create_vertex(
            reversal_vid(parent.vid),
            vec![fa_model::symbols::label::ENTRY],
            fa_model::entry_mirrors(&bad).unwrap(),
        );
        f.f.h.write_raw(birth);
        let refusal = f.revaluation(5, 1, 4, false).unwrap_err();
        assert!(
            refusal
                .message
                .contains("reversal differs from its recorded target"),
            "{refusal}"
        );
    }
}
