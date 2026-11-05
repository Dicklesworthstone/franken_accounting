use super::*;

fn prepare_group_at(
    f: &RevaluedFixture,
    inputs: &[FxSettlementRequest],
    date: DateDay,
    key: &[u8],
) -> Result<PreparedFxSettlementGroup, Refusal> {
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
    .unwrap()
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
    assert_literal_items(&f, &unallocated);

    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"audit-first-allocation");
    let before = f.f.h.db.frontier().unwrap();
    let prepared = prepare_group_at(&f, &inputs, day(4, 15), b"audited-group").unwrap();
    assert_eq!(prepared.audit_work().source_history_audits, 1);
    assert_eq!(prepared.audit_work().successful_reuses, inputs.len() - 1);
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
