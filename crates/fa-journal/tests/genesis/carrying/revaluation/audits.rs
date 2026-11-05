use super::*;

fn prepare_group_at(
    f: &RevaluedFixture,
    inputs: &[FxSettlementRequest],
    date: DateDay,
    key: &[u8],
) -> Result<PreparedFxSettlementGroup, Refusal> {
    prepare_group_outcome(f, inputs, date, key).unwrap()
}

fn prepare_group_outcome(
    f: &RevaluedFixture,
    inputs: &[FxSettlementRequest],
    date: DateDay,
    key: &[u8],
) -> fa_journal::refusal::Outcome<PreparedFxSettlementGroup> {
    let mut template = f.f.h.proposal(vec![], key, EntryClass::ORIGINAL);
    template.effective_date = date;
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    prepare_fx_settlement_group(
        &f.f.h.db,
        &f.f.h.ctx(),
        &f.f.h.book,
        &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
        inputs,
        template,
        &mut budget,
    )
}

fn assert_literal_items(f: &RevaluedFixture, group: &PreparedFxSettlementGroup) {
    for item in group.items() {
        let literal = open_item_carrying_at(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            item.carrying.target,
            item.carrying.ordinal,
            item.carrying.known_at,
        )
        .unwrap()
        .unwrap();
        assert_eq!(item.carrying, literal);
    }
}

#[test]
fn grouped_audits_preserve_literal_results_and_actual_retry_prefix() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10); 4]);
    let inputs = f
        .targets
        .iter()
        .map(|target| f.f.fx_request(*target, 1))
        .collect::<Vec<_>>();
    let unallocated = prepare_group_at(&f, &inputs, day(4, 15), b"before-allocation").unwrap();
    assert_eq!(
        unallocated.audit_work(),
        fa_journal::carrying::CarryingAuditWork::default()
    );
    let work = unallocated.population_work();
    assert_eq!(work.history_scans, 1);
    assert_eq!(work.source_guard_entries + 1, work.entries_decoded);
    assert_eq!(work.item_effect_entries, 0);
    assert_literal_items(&f, &unallocated);

    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"audit-first-allocation");
    let before = f.f.h.db.frontier().unwrap();
    let prepared = prepare_group_at(&f, &inputs, day(4, 15), b"audited-group").unwrap();
    assert_eq!(prepared.audit_work().source_history_audits, 1);
    assert_eq!(prepared.audit_work().successful_reuses, inputs.len() - 1);
    let work = prepared.population_work();
    assert_eq!(work.history_scans, 1);
    assert_eq!(work.source_guard_entries + 1, work.entries_decoded);
    assert_eq!(work.item_effect_entries, inputs.len());
    assert_literal_items(&f, &prepared);
    for (input, item) in inputs.iter().zip(prepared.items()) {
        let single = f
            .prepare(input.target, 1, day(4, 15), b"audited-group")
            .unwrap();
        assert_eq!(single.carrying(), &item.carrying);
        assert_eq!(single.base_relief(), item.base_relief);
        assert_eq!(
            single.proposal().legs,
            prepared.proposal().legs[item.leg_range.clone()]
        );
    }
    let proposal = prepared.proposal().clone();
    let posted = f.f.h.post(request(proposal.clone())).unwrap();
    assert_eq!(posted.recorded_at().0, before.0 + 1);
    let later = f.revaluation(5, 1, 4, true).unwrap();
    f.post_revaluation(later, b"audit-later-allocation");
    let head = f.f.h.db.frontier().unwrap();
    assert!(head > posted.recorded_at());

    // A group retry must audit the old source prefix even though new source
    // effects now exist at head. It reconstructs exactly the published bytes.
    let retry = prepare_group_at(&f, &inputs, day(4, 15), b"audited-group").unwrap();
    assert_eq!(retry, prepared);
    assert!(
        retry
            .items()
            .iter()
            .all(|item| item.carrying.known_at == before)
    );
    assert_literal_items(&f, &retry);

    // A new operation at head cannot reuse that historical success. The
    // actual verifier runs again and the new carrying components are visible.
    let fresh = prepare_group_at(&f, &inputs, day(5, 2), b"fresh-audited-group").unwrap();
    assert_eq!(fresh.audit_work().source_history_audits, 1);
    assert_eq!(fresh.audit_work().successful_reuses, inputs.len() - 1);
    let work = fresh.population_work();
    assert_eq!(work.history_scans, 1);
    assert_eq!(work.source_guard_entries + 1, work.entries_decoded);
    assert_eq!(work.applications_indexed, inputs.len());
    assert_eq!(work.item_effect_entries, inputs.len() * 3);
    assert!(
        fresh
            .items()
            .iter()
            .all(|item| item.carrying.known_at == head)
    );
    assert_literal_items(&f, &fresh);
    for (old, new) in prepared.items().iter().zip(fresh.items()) {
        assert_eq!(old.carrying.open_native.mantissa, 3);
        assert_eq!(new.carrying.open_native.mantissa, 2);
        assert_ne!(
            old.carrying.carrying_source_digest,
            new.carrying.carrying_source_digest
        );
    }
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
}

#[test]
fn successful_first_source_audit_does_not_skip_a_later_targets_checks() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10); 2]);
    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"audit-refusal-allocation");
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    let inputs = f
        .targets
        .iter()
        .map(|target| f.f.fx_request(*target, 1))
        .collect::<Vec<_>>();
    for bad_ordinal in [false, true] {
        let mut invalid = inputs.clone();
        if bad_ordinal {
            invalid[1].target_ordinal = u16::MAX;
        } else {
            invalid[1].target.entry_digest[0] ^= 1;
        }
        let literal = open_item_carrying_at(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            invalid[1].target,
            invalid[1].target_ordinal,
            head,
        )
        .unwrap()
        .unwrap_err();
        for _ in 0..2 {
            let refusal =
                prepare_group_at(&f, &invalid, day(4, 15), b"invalid-audited-group").unwrap_err();
            assert_eq!(refusal, literal);
            assert_eq!(f.f.h.db.frontier().unwrap(), head);
            assert_eq!(f.f.h.db.vertices().unwrap(), rows);
        }
    }
    let valid = prepare_group_at(&f, &inputs, day(4, 15), b"invalid-audited-group").unwrap();
    assert_eq!(valid.audit_work().source_history_audits, 1);
    assert_eq!(valid.audit_work().successful_reuses, 1);
    assert_literal_items(&f, &valid);
}

#[test]
fn compound_carrying_preserves_target_refusals_before_unrelated_history_errors() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10); 2]);
    let inputs = f
        .targets
        .iter()
        .map(|target| f.f.fx_request(*target, 1))
        .collect::<Vec<_>>();
    let (original, _) = read_entry(&f.f.h.db, f.f.target.vid).unwrap().unwrap();
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    // The literal native scan encounters the duplicate reversals before the
    // malformed high-id payload. An index that decodes the complete population
    // before indexing reversals discovers the payload error first instead.
    for ordinal in 1..=2_u128 {
        let vid = VId(ordinal);
        assert!(f.f.h.db.vertex(vid).unwrap().is_none());
        let reversed = undo(
            &original.proposal,
            f.f.target,
            format!("duplicate-reversal-{ordinal}").as_bytes(),
        )
        .seal(vec![], None)
        .unwrap();
        damage.create_vertex(
            vid,
            vec![fa_model::symbols::label::ENTRY],
            fa_model::entry_mirrors(&reversed).unwrap(),
        );
    }
    let corrupt = VId(u128::MAX);
    assert!(f.f.h.db.vertex(corrupt).unwrap().is_none());
    let mut mirrors = fa_model::entry_mirrors(&original).unwrap();
    mirrors
        .iter_mut()
        .find(|(key, _)| *key == property::FA_PAYLOAD)
        .unwrap()
        .1 = CanonicalScalar::bytes(Vec::new()).unwrap();
    damage.create_vertex(corrupt, vec![fa_model::symbols::label::ENTRY], mirrors);
    f.f.h.write_raw(damage);
    let at = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();

    for bad_ordinal in [false, true] {
        let mut invalid = inputs.clone();
        if bad_ordinal {
            invalid[0].target_ordinal = u16::MAX;
        } else {
            invalid[0].target.entry_digest[0] ^= 1;
        }
        let literal = open_item_carrying_at(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            invalid[0].target,
            invalid[0].target_ordinal,
            at,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(
            prepare_group_outcome(&f, &invalid, day(4, 15), b"early-target-refusal")
                .unwrap()
                .unwrap_err(),
            literal
        );
    }
    let literal = open_item_carrying_at(
        &f.f.h.db,
        &f.f.h.ctx(),
        &f.f.h.book,
        inputs[0].target,
        inputs[0].target_ordinal,
        at,
    )
    .unwrap_err();
    assert!(
        literal
            .to_string()
            .contains("duplicate reversal successors"),
        "{literal}"
    );
    let grouped =
        prepare_group_outcome(&f, &inputs, day(4, 15), b"native-first-error").unwrap_err();
    assert_eq!(format!("{grouped:?}"), format!("{literal:?}"));
    assert_eq!(f.f.h.db.frontier().unwrap(), at);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);
}

#[test]
fn compound_carrying_does_not_treat_another_books_target_as_absent() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10); 2]);
    let (original, _) = read_entry(&f.f.h.db, f.targets[1].vid).unwrap().unwrap();
    let mut foreign = original.proposal;
    foreign.book_id = Id128([0x89; 16]);
    let foreign = foreign.seal(vec![], None).unwrap();
    let foreign_vid = VId(13);
    assert!(f.f.h.db.vertex(foreign_vid).unwrap().is_none());
    let mut birth = fgdb::WriteBatch::new(relation::IN_BOOK);
    birth.create_vertex(
        foreign_vid,
        vec![fa_model::symbols::label::ENTRY],
        fa_model::entry_mirrors(&foreign).unwrap(),
    );
    f.f.h.write_raw(birth);
    let at = f.f.h.db.frontier().unwrap();
    let inputs = [
        f.f.fx_request(f.targets[0], 1),
        f.f.fx_request(foreign.entry_ref(foreign_vid), 1),
    ];
    let literal = open_item_carrying_at(
        &f.f.h.db,
        &f.f.h.ctx(),
        &f.f.h.book,
        inputs[1].target,
        inputs[1].target_ordinal,
        at,
    )
    .unwrap()
    .unwrap_err();
    assert!(literal.message.contains("retained posted item"));
    assert_eq!(
        prepare_group_at(&f, &inputs, day(4, 15), b"foreign-item-handle").unwrap_err(),
        literal
    );
    assert_eq!(f.f.h.db.frontier().unwrap(), at);
}

#[test]
fn singleton_and_grouped_preparation_keep_request_refusals_before_integrity_errors() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let input = f.f.fx_request(f.targets[0], 1);
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.delete_vertex(f.f.target.vid);
    f.f.h.write_raw(damage);
    let at = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    let key = b"singleton-group-refusal-order";
    let prepare_single = |request: &FxSettlementRequest, date: DateDay| {
        let mut template = f.f.h.proposal(vec![], key, EntryClass::ORIGINAL);
        template.effective_date = date;
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        prepare_fx_settlement(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            request,
            template,
            &mut budget,
        )
    };
    for mode in ["account", "amount", "date", "rate"] {
        let mut request = input.clone();
        let mut date = day(4, 15);
        match mode {
            "account" => request.settlement_account = f.source,
            "amount" => request.amount.mantissa = 0,
            "date" => date = day(3, 1),
            "rate" => request.rate_document = Oid([0xff; 32]),
            _ => unreachable!(),
        }
        let single = prepare_single(&request, date).expect(mode).unwrap_err();
        let grouped = prepare_group_outcome(&f, &[request], date, key)
            .expect(mode)
            .unwrap_err();
        assert_eq!(single, grouped, "{mode}");
    }
    let single = prepare_single(&input, day(4, 15))
        .expect_err("a valid request cannot conceal a retired Entry");
    let grouped = prepare_group_outcome(&f, &[input], day(4, 15), key)
        .expect_err("a valid group cannot conceal a retired Entry");
    assert_eq!(format!("{single:?}"), format!("{grouped:?}"));
    assert_eq!(f.f.h.db.frontier().unwrap(), at);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);
}

#[test]
fn compound_carrying_keeps_full_history_tamper_refusals() {
    for (allocated, victim_kind, mode) in [
        (false, "unrelated"),
        (true, "unrelated"),
        (true, "allocation"),
    ]
    .into_iter()
    .flat_map(|(allocated, victim_kind)| {
        ["delete", "relabel", "rewrite", "restore"]
            .into_iter()
            .map(move |mode| (allocated, victim_kind, mode))
    }) {
        let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10); 2]);
        let allocation = allocated.then(|| {
            let prepared = f.revaluation(13, 3, 3, true).unwrap();
            f.post_revaluation(prepared, b"compound-tamper-allocation")
                .entry_ref()
        });
        let inputs = f
            .targets
            .iter()
            .map(|target| f.f.fx_request(*target, 1))
            .collect::<Vec<_>>();
        let before = f.f.h.db.frontier().unwrap();
        let original = prepare_group_at(&f, &inputs, day(4, 15), b"compound-tamper-group").unwrap();
        assert_eq!(
            original.items()[0].carrying.valuation_route.is_some(),
            allocated
        );

        // Unrelated Entry damage cannot be found by target/source-only scans.
        // Deleting the allocation also removes the apparent valuation route,
        // so integrity cannot depend on that route remaining visible.
        let victim = match victim_kind {
            "allocation" => allocation.unwrap(),
            _ => f.f.target,
        };
        let case = format!("allocated={allocated}, victim={victim_kind}, mode={mode}");
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        match mode {
            "delete" => {
                damage.delete_vertex(victim.vid);
            }
            "relabel" => {
                damage.set_vertex_label(victim.vid, fa_model::symbols::label::ENTRY, false);
            }
            _ => {
                damage.set_vertex_property(
                    victim.vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
                );
            }
        }
        f.f.h.write_raw(damage);
        if mode == "restore" {
            let mut restoration = fgdb::WriteBatch::new(relation::IN_BOOK);
            restoration.set_vertex_property(
                victim.vid,
                property::FA_DIGEST,
                Some(CanonicalScalar::bytes(victim.entry_digest.to_vec()).unwrap()),
            );
            f.f.h.write_raw(restoration);
        }
        let at = f.f.h.db.frontier().unwrap();
        let rows = f.f.h.db.vertices().unwrap();
        let literal = open_item_carrying_at(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            inputs[0].target,
            inputs[0].target_ordinal,
            at,
        )
        .map(|outcome| outcome.map(|_| ()));
        if victim_kind == "unrelated" {
            assert!(literal.is_err(), "{case}: {literal:?}");
        } else {
            // A damaged allocation can fail its existing source-reproduction
            // law before the additional prefix proof runs. Preserve that
            // refusal; neither failure form may return a carrying result.
            match &literal {
                Err(_) => {}
                Ok(Err(refusal)) => {
                    assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE, "{case}");
                    assert!(
                        refusal.message.contains(
                            "retained item allocation does not reproduce its complete original and publication source populations"
                        ),
                        "{case}: {refusal}"
                    );
                }
                Ok(Ok(())) => panic!("{case}: damaged allocation returned a carrying result"),
            }
        }
        for _ in 0..2 {
            let compound = prepare_group_outcome(&f, &inputs, day(4, 15), b"compound-tamper-group")
                .map(|outcome| outcome.map(|_| ()));
            assert!(!matches!(&compound, Ok(Ok(()))), "{case}: {compound:?}");
            assert_eq!(format!("{compound:?}"), format!("{literal:?}"), "{case}");
        }
        // A later raw-store alteration cannot corrupt the intact historical
        // coordinate, nor can a cached head failure contaminate that read.
        let historical = open_item_carrying_at(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            inputs[0].target,
            inputs[0].target_ordinal,
            before,
        )
        .unwrap()
        .unwrap();
        assert_eq!(historical, original.items()[0].carrying, "{case}");
        assert_eq!(f.f.h.db.frontier().unwrap(), at);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn grouped_audits_verify_each_distinct_source_account() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10); 2]);
    let accounts = [
        ("1213", fa_model::AccountType::ASSET, f.f.foreign),
        ("1293", fa_model::AccountType::ASSET, f.f.h.usd),
        ("7093", fa_model::AccountType::REVENUE, f.f.h.usd),
    ]
    .into_iter()
    .map(|(code, kind, unit)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: u8::from(kind == fa_model::AccountType::REVENUE),
        is_leaf: true,
        unit_policy: UnitPolicy::Single(unit),
        parent_code: None,
        limit: None,
    })
    .collect::<Vec<_>>();
    let cx = f.f.h.ctx();
    let description =
        f.f.h
            .proposal(vec![], b"audit-other-chart", EntryClass::ORIGINAL)
            .description;
    f.f.h
        .runtime
        .block_on(install_chart(
            &mut f.f.h.db,
            &cx,
            &f.f.h.book,
            &accounts,
            PRINCIPAL,
            day(3, 1),
            b"audit-other-chart",
            description.clone(),
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let second_source = account_vid(f.f.h.book.book_id, "1213");
    let second_route = FxRevaluationRoute {
        valuation_account: account_vid(f.f.h.book.book_id, "1293"),
        unrealized_account: account_vid(f.f.h.book.book_id, "7093"),
    };
    f.f.h
        .runtime
        .block_on(set_fx_revaluation_routes(
            &mut f.f.h.db,
            &cx,
            &f.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            FxRevaluationRoutesRequest {
                principal: PRINCIPAL,
                effective_from: day(4, 1),
                routes: [
                    (
                        f.source,
                        FxRevaluationRoute {
                            valuation_account: f.valuation,
                            unrealized_account: f.unrealized,
                        },
                    ),
                    (second_source, second_route),
                ]
                .into(),
                idempotency_key: b"audit-two-source-routes".to_vec(),
                description,
            },
        ))
        .unwrap()
        .unwrap();
    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"audit-source-one");
    f.source = second_source;
    for key in [b"audit-other-invoice-one", b"audit-other-invoice-two"] {
        let target = f.invoice(3, 10, Side::Debit, key);
        f.targets.push(target);
    }
    let second = f.revaluation(5, 1, 4, true).unwrap();
    f.post_revaluation(second, b"audit-source-two");
    let inputs = f
        .targets
        .iter()
        .map(|target| f.f.fx_request(*target, 1))
        .collect::<Vec<_>>();
    let prepared = prepare_group_at(&f, &inputs, day(5, 2), b"audited-two-source-group").unwrap();
    assert_eq!(prepared.audit_work().source_history_audits, 2);
    assert_eq!(prepared.audit_work().successful_reuses, 2);
    let work = prepared.population_work();
    assert_eq!(work.history_scans, 1);
    assert_eq!(work.source_guard_entries, (work.entries_decoded - 1) * 2);
    assert_literal_items(&f, &prepared);
    let proposal = prepared.into_proposal();
    let posted = f.f.h.post(request(proposal.clone())).unwrap();
    f.f.h
        .post(request(undo(
            &proposal,
            posted.entry_ref(),
            b"audited-two-source-undo",
        )))
        .unwrap();
    for target in &f.targets {
        assert_eq!(f.position(*target, None).native, 3);
    }
}
