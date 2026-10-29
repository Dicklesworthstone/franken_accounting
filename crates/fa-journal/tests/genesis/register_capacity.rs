use super::*;

#[test]
fn functional_capacity_refuses_while_native_cells_still_fit() {
    use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms, value_proposal};
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};
    use fa_reference::fx::{
        OracleCapacityError, OracleFunctionalEntry, OracleFxLeg, OracleRateQuote,
        OracleRealizedLeg, admit_register_capacity, value_entity_legs,
    };
    let mut h = harness();
    let eur = h.book.units.lookup("EUR").unwrap();
    let accounts: Vec<_> = [("1288", 1, 0), ("4088", 4, 1)]
        .into_iter()
        .map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        })
        .collect();
    let ctx = h.ctx();
    let description = h
        .proposal(vec![], b"foreign-chart", EntryClass::ORIGINAL)
        .description;
    let day = h.day();
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"foreign-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: eur,
            rate_num: i128::MAX as u128,
            rate_den: 1,
            rounding: fa_money::RoundingLaw::HalfEven,
        },
        day,
        1,
        FxRatePurpose::SpotClose,
        "Capacity boundary retained rate",
    )
    .unwrap();
    h.add_document(
        &rate
            .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    let reference_rates = std::collections::BTreeMap::from([(
        eur.0,
        OracleRateQuote {
            quote_unit: eur.0,
            quote_scale: h.book.units.get(eur).unwrap().scale,
            rate_num: i128::MAX as u128,
            rate_den: 1,
            rounding_law: "HalfEven".into(),
        },
    )]);
    let mut reference = Vec::new();
    for (index, (key, flipped)) in [
        (b"functional-at-cap".as_slice(), false),
        (b"functional-over-cap".as_slice(), false),
        (b"functional-over-cap".as_slice(), true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(h.book.book_id, "1288"),
                Amount::new(eur, 1),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(h.book.book_id, "4088"),
                Amount::new(eur, 1),
            ),
        ];
        if flipped {
            for leg in &mut legs {
                leg.side = leg.side.flipped();
            }
        }
        let oracle_legs: Vec<_> = legs
            .iter()
            .map(|leg| OracleFxLeg {
                side: match leg.side {
                    Side::Debit => fa_reference::Side::Debit,
                    Side::Credit => fa_reference::Side::Credit,
                },
                account: leg.account_ref.0,
                unit: leg.amount.unit.0,
                mantissa: leg.amount.mantissa,
                entity: None,
            })
            .collect();
        // Compute expectations from the unvalued intent and independent rate
        // arithmetic, before production valuation or posting has run.
        let expected = value_entity_legs(
            &oracle_legs,
            h.usd.0,
            h.book.units.get(h.usd).unwrap().scale,
            &reference_rates,
        )
        .unwrap();
        let next = OracleFunctionalEntry {
            period: h.march.clone(),
            is_pending: false,
            is_resolved: false,
            legs: oracle_legs
                .iter()
                .zip(&expected.base_mantissas)
                .map(|(leg, &base_mantissa)| OracleRealizedLeg {
                    side: leg.side,
                    account: leg.account,
                    unit: leg.unit,
                    mantissa: leg.mantissa,
                    base_unit: h.usd.0,
                    base_mantissa,
                    entity: leg.entity.clone(),
                })
                .collect(),
        };
        let mut candidate = reference.clone();
        candidate.push(next.clone());
        let capacity = admit_register_capacity(&candidate, h.usd.0);
        assert_eq!(capacity.is_ok(), index != 1, "{capacity:?}");
        let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(100_000, 0), 4096);
        let proposal = value_proposal(
            &mut budget,
            h.proposal(legs, key, EntryClass::ORIGINAL),
            &fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap(),
            &h.book.units,
            FxLawId::SpotClose,
            std::slice::from_ref(&rate),
        )
        .unwrap();
        assert_eq!(
            proposal
                .legs
                .iter()
                .map(|leg| leg.base_amount.unwrap().mantissa)
                .collect::<Vec<_>>(),
            expected.base_mantissas
        );
        assert_eq!(proposal.legs[0].base_amount.unwrap().mantissa, i128::MAX);
        let head = h.db.frontier().unwrap();
        let result = h.post(h.request(proposal, &["post"]));
        if capacity.is_ok() {
            result.expect("independent native/functional capacity admits");
            reference.push(next);
        } else {
            assert!(matches!(
                capacity,
                Err(OracleCapacityError::Exceeded {
                    functional: true,
                    pending: false,
                    ..
                })
            ));
            let refusal = result.unwrap_err();
            assert_eq!(refusal.code, "FA-REF-198", "{refusal}");
            assert!(refusal.message.contains("functional"), "{refusal}");
            assert_eq!(h.db.frontier().unwrap(), head);
        }
    }
    assert_leg_projections(&h);
}

fn oracle(h: &Harness) -> fa_reference::Oracle {
    let mut oracle = fa_reference::Oracle::new(h.book.calendar.clone());
    oracle.create_periods(2026);
    oracle.transition(&h.march, PeriodTransition::Open).unwrap();
    for code in ["1000", "6000"] {
        oracle.add_account(fa_reference::Account {
            code: code.into(),
            is_leaf: true,
            unit: Some(h.usd.0),
        });
    }
    oracle
}

fn intent(h: &Harness, amount: i128, key: &[u8]) -> fa_reference::Intent {
    fa_reference::Intent {
        class: "Original".into(),
        date: h.day(),
        discriminator: None,
        legs: vec![
            fa_reference::Leg {
                side: fa_reference::Side::Debit,
                account: "6000".into(),
                unit: h.usd.0,
                entity: None,
                mantissa: amount,
            },
            fa_reference::Leg {
                side: fa_reference::Side::Credit,
                account: "1000".into(),
                unit: h.usd.0,
                entity: None,
                mantissa: amount,
            },
        ],
        key: key.to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 0,
        resolves: None,
        settles: vec![],
    }
}

#[test]
fn cumulative_gross_capacity_is_admitted_before_publication() {
    let mut h = harness();
    let mut reference = oracle(&h);
    for (amount, key) in [
        (i128::MAX - 1, b"cap-minus-one".as_slice()),
        (1, b"at-cap".as_slice()),
    ] {
        h.post(h.request(
            h.proposal(h.rent_legs(amount), key, EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("representable gross cell");
        assert!(matches!(
            reference.post(&intent(&h, amount, key)),
            fa_reference::Verdict::Posted { .. }
        ));
    }
    let head = h.db.frontier().unwrap();
    let proposal = h.proposal(h.rent_legs(1), b"correctable", EntryClass::ORIGINAL);
    let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3), "{refusal}");
    assert!(refusal.message.contains("posted"), "{refusal}");
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "no entry or outcome was published"
    );
    let invalid_plan = h.proposal(
        h.rent_legs(1),
        b"invalid-capacity-plan",
        EntryClass::ORIGINAL,
    );
    let refusal = h.post_plan(h.request(invalid_plan, &["post"])).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "planning cannot approve over-cap effects"
    );
    assert_eq!(
        reference.post(&intent(&h, 1, b"correctable")),
        fa_reference::Verdict::Refused { code: "FA-REF-198" }
    );
    assert_leg_projections(&h);

    // A refused key remains free. Opposite gross columns still have room.
    let mut corrected = h.proposal(h.rent_legs(1), b"correctable", EntryClass::ORIGINAL);
    for leg in &mut corrected.legs {
        leg.side = leg.side.flipped();
    }
    corrected.unit_totals = EntryPayload::fold_unit_totals(&corrected.legs).unwrap();
    h.post(h.request(corrected, &["post"]))
        .expect("same key with corrected admissible effects");
    assert_leg_projections(&h);
}

#[test]
fn prepared_writers_cannot_jointly_exceed_capacity() {
    for first in [0, 1] {
        let mut h = harness();
        h.post(h.request(
            h.proposal(h.rent_legs(i128::MAX - 1), b"basis", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
        let mut prepared = Vec::new();
        for key in [b"writer-a".as_slice(), b"writer-b".as_slice()] {
            let request = h.request(
                h.proposal(h.rent_legs(1), key, EntryClass::ORIGINAL),
                &["post"],
            );
            let ctx = h.ctx();
            let PostPreparation::Ready(p) = prepare_post(&mut h.db, &ctx, &h.book, request)
                .unwrap()
                .unwrap()
            else {
                panic!("fresh writer");
            };
            prepared.push(Some(p));
        }
        let ctx = h.ctx();
        let winner = prepared[first].take().unwrap();
        h.runtime
            .block_on(winner.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap();
        let head = h.db.frontier().unwrap();
        let loser = prepared[1 - first].take().unwrap();
        let refusal = h
            .runtime
            .block_on(loser.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.exit, 6,
            "native prefix witness must conflict: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_leg_projections(&h);
    }
}

#[test]
fn fitting_net_does_not_authorize_overflowing_gross_columns() {
    let mut h = harness();
    let posted = h
        .post(h.request(
            h.proposal(h.rent_legs(i128::MAX), b"maximum", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
    let target = committed(&posted).unwrap().0;
    h.post(h.request(h.reversal_of(target, i128::MAX, b"reverse"), &["post"]))
        .unwrap();
    let head = h.db.frontier().unwrap();
    let refusal = h
        .post(h.request(
            h.proposal(h.rent_legs(1), b"net-fits", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_leg_projections(&h);
}

#[test]
fn pending_release_is_judged_in_the_final_atomic_state_across_periods() {
    let mut h = harness();
    let mut reference = oracle(&h);
    let mut old = intent(&h, i128::MAX, b"old-hold");
    old.class = "Pending".into();
    let fa_reference::Verdict::Posted {
        index: old_index, ..
    } = reference.post(&old)
    else {
        panic!("oracle hold fits");
    };
    let hold = h
        .post(h.request(h.pending(h.rent_legs(i128::MAX), b"old-hold"), &["post"]))
        .unwrap();
    let target = committed(&hold).unwrap().0;
    h.transition(
        &h.april.clone(),
        PeriodTransition::Open,
        b"open-april-capacity",
    )
    .unwrap();
    let mut next = h.pending(h.rent_legs(1), b"next-hold");
    next.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let mut release = h.resolution_voids(target, b"release-old");
    release.effective_date = next.effective_date;
    let batch = h.batch(b"replace-hold", vec![next, release]);
    h.post_batch(batch)
        .expect("released old hold is absent from final pending sum");
    reference
        .transition(&h.april, PeriodTransition::Open)
        .unwrap();
    let mut next = intent(&h, 1, b"next-hold");
    next.class = "Pending".into();
    next.date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let mut release = next.clone();
    release.class = "Resolution".into();
    release.key = b"release-old".to_vec();
    release.legs.clear();
    release.resolves = Some(fa_reference::Resolve {
        target: old_index,
        posts: None,
    });
    assert!(matches!(
        reference.post_batch(b"replace-hold", &[next, release]),
        fa_reference::BatchVerdict::Posted { .. }
    ));
    assert_leg_projections(&h);
    let head = h.db.frontier().unwrap();
    let mut too_large = h.pending(h.rent_legs(i128::MAX), b"pending-over-cap");
    too_large.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let refusal = h.post(h.request(too_large, &["post"])).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn pending_release_uses_final_state_without_intermediate_false_refusal() {
    for release_first in [false, true] {
        let mut h = harness();
        let mut reference = oracle(&h);
        let mut old = intent(&h, i128::MAX, b"full-cap-hold");
        old.class = "Pending".into();
        let fa_reference::Verdict::Posted {
            index: old_index, ..
        } = reference.post(&old)
        else {
            panic!("oracle hold fits");
        };
        let hold = h
            .post(h.request(
                h.pending(h.rent_legs(i128::MAX), b"full-cap-hold"),
                &["post"],
            ))
            .unwrap();
        let target = committed(&hold).unwrap().0;
        h.transition(
            &h.april.clone(),
            PeriodTransition::Open,
            b"open-april-final-state",
        )
        .unwrap();
        reference
            .transition(&h.april, PeriodTransition::Open)
            .unwrap();

        let mut next = h.pending(h.rent_legs(i128::MAX), b"replacement-max-hold");
        next.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
        let mut release = h.resolution_voids(target, b"release-full-cap-hold");
        release.effective_date = next.effective_date;
        let members = if release_first {
            vec![release, next]
        } else {
            // Even when the new MAX hold precedes the release in the batch,
            // admission judges the final atomic state (0 in March, MAX in April,
            // MAX in cumulative stock) without a false intermediate refusal.
            vec![next, release]
        };
        h.post_batch(h.batch(b"swap-max-hold", members))
            .expect("final atomic pending state is representable in both member orders");

        let mut ref_next = intent(&h, i128::MAX, b"replacement-max-hold");
        ref_next.class = "Pending".into();
        ref_next.date = DateDay::from_ymd(2026, 4, 1).unwrap();
        let mut ref_release = ref_next.clone();
        ref_release.class = "Resolution".into();
        ref_release.key = b"release-full-cap-hold".to_vec();
        ref_release.legs.clear();
        ref_release.resolves = Some(fa_reference::Resolve {
            target: old_index,
            posts: None,
        });
        let ref_members = if release_first {
            vec![ref_release, ref_next]
        } else {
            vec![ref_next, ref_release]
        };
        assert!(matches!(
            reference.post_batch(b"swap-max-hold", &ref_members),
            fa_reference::BatchVerdict::Posted { .. }
        ));
        assert_leg_projections(&h);

        // Adding 1 more pending unit on top of the active April MAX hold is
        // refused atomically with FA-REF-198.
        let head = h.db.frontier().unwrap();
        let mut over = h.pending(h.rent_legs(1), b"over-after-swap");
        over.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
        let refusal = h.post(h.request(over, &["post"])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3), "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn migration_finalize_capacity_failure_is_atomic() {
    use fa_journal::migration::{
        RunBody, RunControlRequest, RunMode, RunState, TrialBalanceLine, kind, open_proposal,
        open_run, plan_run_transition, read_run, transition_run,
    };

    for (staged_amount, live_amount, expect_ok) in
        [(i128::MAX, 1_i128, false), (i128::MAX - 1, 1_i128, true)]
    {
        let mut h = harness();
        for (step, key) in [
            (PeriodTransition::Open, b"open-fy26-open".as_slice()),
            (PeriodTransition::SoftClose, b"soft-fy26-open".as_slice()),
            (PeriodTransition::Close, b"close-fy26-open".as_slice()),
            (PeriodTransition::Lock, b"lock-fy26-open".as_slice()),
        ] {
            h.transition("FY2026-OPEN", step, key).unwrap();
        }
        let opening_day = DateDay::from_ymd(2026, 1, 1).unwrap();
        let tb_doc = h.document(
            18,
            HUMAN_UPLOAD,
            b"account,unit,mantissa\n6000,USD,max\n1000,USD,-max\n",
        );
        h.add_document(&tb_doc).unwrap();
        let tb_ref = tb_doc.evidence_ref(1);
        let body = RunBody {
            book_id: h.book.book_id,
            run_key: "capacity-atomic-opening".into(),
            source_system: "legacy-gl".into(),
            mode: RunMode::OpeningOnly,
            trial_balance: tb_ref.document_oid,
            opening_date: opening_day,
            lines: vec![
                TrialBalanceLine {
                    account_code: "1000".into(),
                    unit: h.usd,
                    mantissa: -staged_amount,
                },
                TrialBalanceLine {
                    account_code: "6000".into(),
                    unit: h.usd,
                    mantissa: staged_amount,
                },
            ],
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
        };
        let cap = Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap();
        let open_prop = open_proposal(
            &h.book,
            PRINCIPAL,
            &body,
            vec![tb_ref],
            b"open-capacity-migration",
            h.proposal(vec![], b"open-desc", EntryClass::ORIGINAL)
                .description,
        )
        .unwrap();
        let ctx = h.ctx();
        let opened = h
            .runtime
            .block_on(open_run(
                &mut h.db,
                &ctx,
                &h.book,
                &body,
                RunControlRequest {
                    proposal: open_prop,
                    capability: cap.clone(),
                    approvals: Vec::new(),
                },
            ))
            .unwrap()
            .unwrap();

        let mut chunk = h.proposal(
            h.rent_legs(staged_amount),
            b"staged-capacity-chunk",
            EntryClass::MIGRATION,
        );
        chunk.effective_date = opening_day;
        chunk.effective_period = Some(fa_model::PeriodRef {
            calendar: h.book.calendar.id.clone(),
            code: "FY2026-OPEN".into(),
        });
        chunk.evidence = vec![tb_ref];
        chunk.origin = EntryOrigin::Migration {
            run_ref: opened.run,
            source_system: "legacy-gl".into(),
            source_id: h
                .proposal(vec![], b"src-id", EntryClass::ORIGINAL)
                .description,
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: tb_ref.document_oid,
        };
        let chunk_digest = chunk.proposal_digest().unwrap();
        let chunk_approvals = vec![h.approve_transition(chunk_digest), {
            let ctx = h.ctx();
            let req = ApprovalRequest {
                capability: Capability::embedded(VId(71), &["approve"]).unwrap(),
                approved_proposal_digest: chunk_digest,
                role: 0,
            };
            h.runtime
                .block_on(record_approval(&mut h.db, &ctx, &h.book, req))
                .unwrap()
                .unwrap()
                .approval()
        }];
        h.post(PostRequest {
            proposal: chunk,
            approvals: chunk_approvals,
            plan_certificate: None,
            capability: cap.clone(),
        })
        .expect("staged migration chunk commits while invisible to live registers");

        // While the migration run is Open, its staged chunk is invisible, so a
        // live posting in March is admitted against the live register only.
        h.post(h.request(
            h.proposal(
                h.rent_legs(live_amount),
                b"live-march",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .expect("live post succeeds while migration is staged");

        let fin_prop = plan_run_transition(
            &h.db,
            &h.book,
            opened.run,
            kind::FINALIZE,
            PRINCIPAL,
            b"finalize-capacity-migration",
            h.proposal(vec![], b"fin-desc", EntryClass::ORIGINAL)
                .description,
        )
        .unwrap()
        .unwrap();
        let fin_digest = fin_prop.proposal_digest().unwrap();
        let fin_approvals = vec![h.approve_transition(fin_digest), {
            let ctx = h.ctx();
            let req = ApprovalRequest {
                capability: Capability::embedded(VId(71), &["approve"]).unwrap(),
                approved_proposal_digest: fin_digest,
                role: 0,
            };
            h.runtime
                .block_on(record_approval(&mut h.db, &ctx, &h.book, req))
                .unwrap()
                .unwrap()
                .approval()
        }];
        let head_before = h.db.frontier().unwrap();
        let ctx = h.ctx();
        let res = h
            .runtime
            .block_on(transition_run(
                &mut h.db,
                &ctx,
                &h.book,
                RunControlRequest {
                    proposal: fin_prop,
                    capability: cap,
                    approvals: fin_approvals,
                },
            ))
            .unwrap();
        if expect_ok {
            res.expect("fitting staged + live stock activates at Finalize");
            assert_eq!(
                read_run(&h.db, opened.run, None).unwrap().unwrap().state,
                RunState::Finalized
            );
        } else {
            let refusal = res.expect_err("over-cap Finalize must refuse atomically");
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3), "{refusal}");
            assert_eq!(
                h.db.frontier().unwrap(),
                head_before,
                "failed Finalize must not advance the commit frontier"
            );
            assert_eq!(
                read_run(&h.db, opened.run, None).unwrap().unwrap().state,
                RunState::Open,
                "failed Finalize must leave the migration run Open"
            );
        }
        assert_leg_projections(&h);
    }
}

#[test]
fn atomic_batch_capacity_refusal_publishes_neither_members_nor_outcome() {
    let mut h = harness();
    let before = h.db.frontier().unwrap();
    let batch = h.batch(
        b"capacity-batch",
        vec![
            h.proposal(h.rent_legs(i128::MAX), b"batch-max", EntryClass::ORIGINAL),
            h.proposal(h.rent_legs(1), b"batch-one", EntryClass::ORIGINAL),
        ],
    );
    let refusal = h.post_batch(batch).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), before);
    let corrected = h.batch(
        b"capacity-batch",
        vec![
            h.proposal(h.rent_legs(1), b"batch-max", EntryClass::ORIGINAL),
            h.proposal(h.rent_legs(1), b"batch-one", EntryClass::ORIGINAL),
        ],
    );
    h.post_batch(corrected)
        .expect("refused batch and member keys stay free");
    assert_leg_projections(&h);
}

#[test]
fn replacement_capacity_refusal_keeps_the_entire_pair_unpublished() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(
                h.rent_legs(i128::MAX - 1),
                b"pair-basis",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap();
    let target = original.entry_ref();
    let reversal = h.reversal_of(target, i128::MAX - 1, b"capacity-pair-reversal");
    let mut replacement = h.proposal(
        h.rent_legs(2),
        b"capacity-pair-replacement",
        EntryClass::REPLACEMENT,
    );
    replacement.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Replaces,
        reason_code: 1,
    }];
    let before = h.db.frontier().unwrap();
    let refusal = h
        .post_pair(
            h.request(reversal, &["post"]),
            h.request(replacement, &["post"]),
        )
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198", "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    assert_leg_projections(&h);
}

fn post_carried(
    h: &mut Harness,
    req: PostRequest,
    carried: &mut fa_journal::CarriedHistory,
) -> Result<Posted, Refusal> {
    let ctx = h.ctx();
    let db = &mut h.db;
    let book = &h.book;
    h.runtime
        .block_on(async move { fa_journal::post_carrying(db, &ctx, book, req, carried).await })
        .expect("kernel")
}

fn post_batch_carried(
    h: &mut Harness,
    batch: fa_intents::PostBatch,
    carried: &mut fa_journal::CarriedHistory,
) -> Result<fa_journal::BatchPosted, Refusal> {
    let ctx = h.ctx();
    let db = &mut h.db;
    let book = &h.book;
    let cap = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    h.runtime
        .block_on(async move {
            fa_journal::post_batch_carrying(db, &ctx, book, cap, batch, carried).await
        })
        .expect("kernel")
}

#[test]
fn carried_capacity_admits_and_refuses_as_the_scan_does() {
    let mut h = harness();
    let mut carried = fa_journal::CarriedHistory::default();
    for (amount, key) in [
        (i128::MAX - 1, b"carried-cap-minus-one".as_slice()),
        (1, b"carried-at-cap".as_slice()),
    ] {
        let req = h.request(
            h.proposal(h.rent_legs(amount), key, EntryClass::ORIGINAL),
            &["post"],
        );
        post_carried(&mut h, req, &mut carried).expect("representable gross cell");
        assert!(
            carried.capacity().is_some_and(|s| s.summarized()),
            "an ordinary book stays summarized"
        );
    }
    // One more cent overflows the posted debit column: the carried path
    // refuses with exactly the scan's refusal, and publishes nothing.
    let head = h.db.frontier().unwrap();
    let over = h.proposal(h.rent_legs(1), b"carried-over", EntryClass::ORIGINAL);
    let scanned = h.post(h.request(over.clone(), &["post"])).unwrap_err();
    let req = h.request(over.clone(), &["post"]);
    let refusal = post_carried(&mut h, req, &mut carried).unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit, &refusal.message),
        (scanned.code, scanned.exit, &scanned.message),
        "{refusal}"
    );
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), head, "nothing was published");
    // The opposite gross columns still have room, answered by the summary.
    let mut corrected = over;
    for leg in &mut corrected.legs {
        leg.side = leg.side.flipped();
    }
    corrected.unit_totals = EntryPayload::fold_unit_totals(&corrected.legs).unwrap();
    let req = h.request(corrected, &["post"]);
    post_carried(&mut h, req, &mut carried).expect("opposite gross columns fit");
    assert!(carried.capacity().is_some_and(|s| s.summarized()));
    assert_leg_projections(&h);
}

#[test]
fn carried_capacity_follows_a_released_hold() {
    let mut h = harness();
    let mut carried = fa_journal::CarriedHistory::default();
    let req = h.request(
        h.pending(h.rent_legs(i128::MAX), b"carried-hold"),
        &["post"],
    );
    let hold = post_carried(&mut h, req, &mut carried).unwrap();
    let target = committed(&hold).unwrap().0;
    h.transition(
        &h.april.clone(),
        PeriodTransition::Open,
        b"open-april-carried",
    )
    .unwrap();
    let mut next = h.pending(h.rent_legs(1), b"carried-next");
    next.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let mut release = h.resolution_voids(target, b"carried-release");
    release.effective_date = next.effective_date;
    let batch = h.batch(b"carried-replace", vec![next, release]);
    post_batch_carried(&mut h, batch, &mut carried)
        .expect("the released hold is absent from the final pending sum");

    // A full hold again overflows the pending column (1 + MAX). Carried over
    // the release, the summary still stands for the book: the release is
    // folded before the new hold, so no column passes MAX on the way.
    let head = h.db.frontier().unwrap();
    let mut too_large = h.pending(h.rent_legs(i128::MAX), b"carried-too-large");
    too_large.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let scanned = h.post(h.request(too_large.clone(), &["post"])).unwrap_err();
    let req = h.request(too_large, &["post"]);
    let refusal = post_carried(&mut h, req, &mut carried).unwrap_err();
    assert_eq!(
        (refusal.code, &refusal.message),
        (scanned.code, &scanned.message),
        "{refusal}"
    );
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        carried.capacity().is_some_and(|s| s.summarized()),
        "the summary carried over the release"
    );
}

#[test]
fn carried_resolution_capacity_releases_before_mixed_batch_additions() {
    for release_first in [false, true] {
        let mut h = harness();
        let mut carried = fa_journal::CarriedHistory::default();
        let req = h.request(
            h.pending(h.rent_legs(i128::MAX), b"summary-full-hold"),
            &["post"],
        );
        let target = post_carried(&mut h, req, &mut carried).unwrap().entry_ref();
        h.transition(&h.april.clone(), PeriodTransition::Open, b"summary-april")
            .unwrap();
        let date = DateDay::from_ymd(2026, 4, 1).unwrap();
        let mut release =
            h.resolution_posts(target, h.rent_legs(1), vec![0, 1], b"summary-partial-post");
        release.effective_date = date;
        let mut next = h.pending(h.rent_legs(i128::MAX), b"summary-replacement-hold");
        next.effective_date = date;
        let mut ordinary = h.invoice(3, b"summary-unrelated-post");
        ordinary.effective_date = date;
        let members = if release_first {
            vec![release, next, ordinary]
        } else {
            vec![next, ordinary, release]
        };
        let batch = h.batch(b"summary-swap-full-hold", members);
        post_batch_carried(&mut h, batch, &mut carried)
            .expect("full original vector releases before the new MAX hold is added");
        let history = carried.capacity().unwrap();
        assert!(history.admitted_from_summary(), "no literal admission scan");
        assert_eq!(history.resolution_targets_read(), 1);

        // Only one cent posted; all of the former MAX reservation was
        // released. The new MAX hold is now the sole pending contribution.
        let head = h.db.frontier().unwrap();
        let mut over = h.pending(h.rent_legs(1), b"summary-one-too-many");
        over.effective_date = date;
        let scanned = h.post(h.request(over.clone(), &["post"])).unwrap_err();
        let req = h.request(over, &["post"]);
        let cached = post_carried(&mut h, req, &mut carried).unwrap_err();
        assert_eq!(cached, scanned, "literal first refusal is preserved");
        assert_eq!(cached.code, "FA-REF-198");
        assert!(!carried.capacity().unwrap().admitted_from_summary());
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_leg_projections(&h);
    }
}

#[test]
fn carried_resolution_capacity_handles_holds_born_and_resolved_in_one_batch() {
    for posts in [false, true] {
        let mut h = harness();
        let mut carried = fa_journal::CarriedHistory::default();
        // An unrelated committed MAX hold uses the same cells. Removing a
        // newly born hold from that summary would corrupt this reservation.
        let req = h.request(
            h.pending(h.rent_legs(i128::MAX), b"summary-existing-max"),
            &["post"],
        );
        post_carried(&mut h, req, &mut carried).unwrap();
        let held = h.pending(h.rent_legs(i128::MAX), b"summary-transient-max");
        let target = h.member_ref(&held);
        let release = if posts {
            h.resolution_posts(
                target,
                h.rent_legs(1),
                vec![0, 1],
                b"summary-transient-release",
            )
        } else {
            h.resolution_voids(target, b"summary-transient-release")
        };
        let batch = h.batch(b"summary-transient-batch", vec![held, release]);
        post_batch_carried(&mut h, batch, &mut carried)
            .expect("transient hold is absent from the final pending columns");
        let history = carried.capacity().unwrap();
        assert!(history.admitted_from_summary());
        assert_eq!(history.resolution_targets_read(), 1);
        let over = h.pending(h.rent_legs(1), b"summary-original-still-reserved");
        let head = h.db.frontier().unwrap();
        let scanned = h.post(h.request(over.clone(), &["post"])).unwrap_err();
        let req = h.request(over, &["post"]);
        let cached = post_carried(&mut h, req, &mut carried).unwrap_err();
        assert_eq!(cached, scanned);
        assert_eq!(cached.code, "FA-REF-198");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_leg_projections(&h);
    }
}

#[test]
fn carried_resolution_capacity_keeps_posted_overflow_and_target_refusals() {
    let mut h = harness();
    let mut carried = fa_journal::CarriedHistory::default();
    for proposal in [
        h.proposal(
            h.rent_legs(i128::MAX - 1),
            b"summary-posted-near-cap",
            EntryClass::ORIGINAL,
        ),
        h.pending(h.rent_legs(10), b"summary-posted-held"),
    ] {
        let req = h.request(proposal, &["post"]);
        post_carried(&mut h, req, &mut carried).unwrap();
    }
    let hold_vid = entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        b"summary-posted-held",
    );
    let (held, _) = read_entry(&h.db, hold_vid).unwrap().unwrap();
    let target = EntryRef {
        vid: hold_vid,
        entry_digest: held.entry_digest,
    };
    let head = h.db.frontier().unwrap();
    for (target, amount) in [
        (
            EntryRef {
                entry_digest: [0; 32],
                ..target
            },
            1,
        ),
        (target, 0),
        (target, 2),
    ] {
        let proposal = h.resolution_posts(
            target,
            h.rent_legs(amount),
            vec![0, 1],
            b"summary-refused-post",
        );
        let scanned = h.post(h.request(proposal.clone(), &["post"])).unwrap_err();
        let req = h.request(proposal, &["post"]);
        let cached = post_carried(&mut h, req, &mut carried).unwrap_err();
        assert_eq!(cached, scanned, "target/shape/capacity precedence");
        if amount == 2 {
            assert_eq!(cached.code, "FA-REF-198");
            assert!(!carried.capacity().unwrap().admitted_from_summary());
        }
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    let req = h.request(
        h.resolution_posts(target, h.rent_legs(1), vec![0, 1], b"summary-refused-post"),
        &["post"],
    );
    post_carried(&mut h, req, &mut carried).expect("corrected request uses the unspent identity");
    assert!(carried.capacity().unwrap().admitted_from_summary());
    let repeat = h.resolution_voids(target, b"summary-second-release");
    let scanned = h.post(h.request(repeat.clone(), &["post"])).unwrap_err();
    let req = h.request(repeat, &["post"]);
    assert_eq!(
        post_carried(&mut h, req, &mut carried).unwrap_err(),
        scanned
    );
    assert_leg_projections(&h);
}

#[test]
fn carried_resolution_capacity_reads_targets_not_unrelated_history() {
    let mut h = harness();
    let mut carried = fa_journal::CarriedHistory::default();
    let mut filler_count = 0;
    let mut work = Vec::new();
    for size in [2, 4, 8, 16, 32] {
        while filler_count < size {
            let proposal = h.invoice(
                1,
                format!("resolution-unrelated-{filler_count:02}").as_bytes(),
            );
            let req = h.request(proposal, &["post"]);
            post_carried(&mut h, req, &mut carried).unwrap();
            filler_count += 1;
        }
        let proposal = h.pending(
            h.rent_legs(100),
            format!("resolution-counted-hold-{size:02}").as_bytes(),
        );
        let req = h.request(proposal, &["post"]);
        let target = post_carried(&mut h, req, &mut carried).unwrap().entry_ref();
        let proposal = h.resolution_posts(
            target,
            h.rent_legs(1),
            vec![0, 1],
            format!("resolution-counted-post-{size:02}").as_bytes(),
        );
        let req = h.request(proposal, &["post"]);
        post_carried(&mut h, req, &mut carried).unwrap();
        let history = carried.capacity().unwrap();
        assert!(history.admitted_from_summary(), "size={size}");
        assert_eq!(history.resolution_targets_read(), 1, "size={size}");
        work.push(history.carried_rows().expect("only the new hold's suffix"));
    }
    assert!(work[0] > 0);
    assert!(work.iter().all(|rows| *rows == work[0]), "{work:?}");
    assert_leg_projections(&h);
}

#[test]
fn carried_resolution_capacity_preserves_mixed_native_and_functional_columns() {
    use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms, value_proposal};
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};

    // One vector has both EUR and USD on each account. The first rate exercises
    // HalfEven rounding with positive initial and resolved valuations; SpotClose
    // does not admit zero initial base amounts. The second makes the full
    // functional hold exactly MAX while every native amount remains small.
    for (rate_num, rate_den) in [(3, 4), ((i128::MAX as u128 - 1) / 2, 1)] {
        let mut h = harness();
        let eur = h.book.units.lookup("EUR").unwrap();
        let specs: Vec<_> = [("1289", 1, 0), ("4089", 4, 1)]
            .into_iter()
            .map(|(code, account_type, normal_balance)| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type,
                normal_balance,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect();
        let ctx = h.ctx();
        let description = h
            .proposal(vec![], b"resolution-fx-chart", EntryClass::ORIGINAL)
            .description;
        let date = h.day();
        h.runtime
            .block_on(install_chart(
                &mut h.db,
                &ctx,
                &h.book,
                &specs,
                PRINCIPAL,
                date,
                b"resolution-fx-chart",
                description,
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: h.usd,
                quote_unit: eur,
                rate_num,
                rate_den,
                rounding: fa_money::RoundingLaw::HalfEven,
            },
            date,
            1,
            FxRatePurpose::SpotClose,
            "Mixed reservation capacity rate",
        )
        .unwrap();
        h.add_document(
            &rate
                .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
                .unwrap(),
        )
        .unwrap();
        let debit = account_vid(h.book.book_id, "1289");
        let credit = account_vid(h.book.book_id, "4089");
        let usd = h.usd;
        let legs = |foreign| {
            vec![
                LegPayload::simple(Side::Debit, debit, Amount::new(eur, foreign)),
                LegPayload::simple(Side::Credit, credit, Amount::new(eur, foreign)),
                LegPayload::simple(Side::Debit, debit, Amount::new(usd, 1)),
                LegPayload::simple(Side::Credit, credit, Amount::new(usd, 1)),
            ]
        };
        let value = |h: &Harness, proposal| {
            let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
            let mut budget =
                ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(100_000, 0), 4096);
            value_proposal(
                &mut budget,
                proposal,
                &fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap(),
                &h.book.units,
                FxLawId::SpotClose,
                std::slice::from_ref(&rate),
            )
            .unwrap()
        };
        let held = value(&h, h.pending(legs(2), b"resolution-fx-hold"));
        assert_eq!(
            held.base_totals.as_ref().unwrap().debits,
            if rate_den == 4 { 3 } else { i128::MAX }
        );
        let mut carried = fa_journal::CarriedHistory::default();
        let req = h.request(held, &["post"]);
        let target = post_carried(&mut h, req, &mut carried).unwrap().entry_ref();
        let next = value(&h, h.pending(legs(2), b"resolution-fx-new-hold"));
        let release = value(
            &h,
            h.resolution_posts(target, legs(1), vec![0, 1, 2, 3], b"resolution-fx-partial"),
        );
        let batch = h.batch(b"resolution-fx-swap", vec![next, release]);
        post_batch_carried(&mut h, batch, &mut carried)
            .expect("native and functional pending columns both release in full");
        assert!(carried.capacity().unwrap().admitted_from_summary());
        assert_eq!(carried.capacity().unwrap().resolution_targets_read(), 1);
        if rate_den == 1 {
            let more = value(&h, h.pending(legs(1), b"resolution-fx-over"));
            let head = h.db.frontier().unwrap();
            let scanned = h.post(h.request(more.clone(), &["post"])).unwrap_err();
            let req = h.request(more, &["post"]);
            let cached = post_carried(&mut h, req, &mut carried).unwrap_err();
            assert_eq!(cached, scanned);
            assert_eq!(cached.code, "FA-REF-198");
            assert!(cached.message.contains("functional"), "{cached}");
            assert!(!carried.capacity().unwrap().admitted_from_summary());
            assert_eq!(h.db.frontier().unwrap(), head);
        }
        assert_leg_projections(&h);
    }
}

#[test]
fn a_carried_capacity_summary_never_crosses_to_another_database() {
    // Two books that diverge at one commit and stand at one frontier: `full`
    // is near the posted-debit cap, `open` holds two cents.
    let mut full = harness();
    for (amount, key) in [
        (i128::MAX - 5, b"cross-near-cap".as_slice()),
        (1, b"cross-one".as_slice()),
    ] {
        full.post(full.request(
            full.proposal(full.rent_legs(amount), key, EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
    }
    let mut open = harness();
    let mut carried = fa_journal::CarriedHistory::default();
    for key in [b"cross-pad-a".as_slice(), b"cross-pad-b".as_slice()] {
        let req = open.request(
            open.proposal(open.rent_legs(1), key, EntryClass::ORIGINAL),
            &["post"],
        );
        post_carried(&mut open, req, &mut carried).unwrap();
    }
    assert_eq!(open.db.frontier().unwrap(), full.db.frontier().unwrap());
    // `open`'s summary handed to `full`: five more cents overflow `full`'s
    // column, so the post must still be refused.
    let over = full.proposal(full.rent_legs(5), b"cross-over", EntryClass::ORIGINAL);
    let req = full.request(over, &["post"]);
    let refusal = post_carried(&mut full, req, &mut carried).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198", "{refusal}");
}

#[test]
fn a_rewritten_committed_entry_ends_the_capacity_summary() {
    let mut h = harness();
    let mut carried = fa_journal::CarriedHistory::default();
    let req = h.request(
        h.proposal(
            h.rent_legs(i128::MAX - 10),
            b"tamper-base",
            EntryClass::ORIGINAL,
        ),
        &["post"],
    );
    let base = post_carried(&mut h, req, &mut carried).unwrap();
    let req = h.request(
        h.proposal(h.rent_legs(1), b"tamper-next", EntryClass::ORIGINAL),
        &["post"],
    );
    post_carried(&mut h, req, &mut carried).unwrap();
    assert!(carried.capacity().is_some_and(|s| s.summarized()));

    // Behind the summary's back, the first entry's legs grow to MAX - 2.
    let vid = base.entry_ref().vid;
    let row = h.db.vertex(vid).unwrap().unwrap();
    let stored = fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "entry").unwrap();
    let mut entry = fa_model::Entry::decode(&stored).unwrap();
    assert_eq!(entry.encode().unwrap(), stored, "the payload round-trips");
    for leg in &mut entry.proposal.legs {
        leg.amount = Amount::new(h.usd, i128::MAX - 2);
    }
    entry.proposal.unit_totals = EntryPayload::fold_unit_totals(&entry.proposal.legs).unwrap();
    // A well-formed entry, its digests recomputed: only its amounts lie.
    let entry = entry
        .proposal
        .clone()
        .seal(entry.approvals.clone(), entry.plan_certificate)
        .unwrap();
    let mut damage = fgdb::WriteBatch::new(relation::IN_PERIOD);
    damage.set_vertex_property(
        vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(entry.encode().unwrap()).unwrap()),
    );
    let ctx = h.ctx();
    h.runtime
        .block_on(h.db.write(&ctx.commit(), damage))
        .unwrap();

    // The scan reads the rewritten legs: MAX - 2 + 1 + 5 overflows. The
    // summary no longer stands for the book, so the carried path refuses
    // exactly as the scan does instead of answering from stale columns.
    let over = h.proposal(h.rent_legs(5), b"tamper-over", EntryClass::ORIGINAL);
    let scanned = h.post(h.request(over.clone(), &["post"])).unwrap_err();
    let req = h.request(over, &["post"]);
    let refusal = post_carried(&mut h, req, &mut carried).unwrap_err();
    assert_eq!(
        (refusal.code, &refusal.message),
        (scanned.code, &scanned.message),
        "{refusal}"
    );
    assert_eq!(refusal.code, "FA-REF-198");
    assert!(
        carried.capacity().is_some_and(|s| !s.summarized()),
        "a changed committed entry ends the summary"
    );
}

#[test]
fn a_post_visits_only_the_new_suffix_for_its_reconciliation_witness() {
    // fa-rcw1's counted work witness: each carried post examines only the
    // delta rows of the commit since the last post, the same count whether
    // the book holds three entries or forty.
    let mut h = harness();
    let mut carried = fa_journal::CarriedHistory::default();
    let mut counts = Vec::new();
    for i in 0..40u32 {
        let req = h.request(
            h.proposal(
                h.rent_legs(100),
                format!("suffix-{i:02}").as_bytes(),
                EntryClass::ORIGINAL,
            ),
            &["post"],
        );
        post_carried(&mut h, req, &mut carried).unwrap();
        counts.push((
            carried.reconciliation().and_then(|r| r.carried_rows()),
            carried.capacity().and_then(|c| c.carried_rows()),
        ));
    }
    assert_eq!(counts[0], (None, None), "the first post verifies in full");
    let later = &counts[2..];
    assert!(
        later
            .iter()
            .all(|c| c.0.is_some_and(|n| n > 0) && c.1.is_some_and(|n| n > 0)),
        "every later post carries both: {counts:?}"
    );
    assert!(
        later.iter().all(|c| *c == later[0]),
        "the same rows per post as the book grows: {counts:?}"
    );
    assert!(carried.capacity().is_some_and(|c| c.summarized()));
}

#[test]
fn account_scope_precedes_capacity_across_legal_entities_and_keeps_refused_keys_free() {
    let mut h = harness_with_entities(
        ["A", "B"]
            .into_iter()
            .map(|code| LegalEntitySpec {
                code: code.into(),
                name: code.into(),
                functional_unit: UnitId(0),
            })
            .collect(),
    );
    let with_entity = |mut proposal: EntryPayload, code: &str| {
        for leg in &mut proposal.legs {
            leg.dimension_set = vec![(
                fa_model::LEGAL_ENTITY_DIMENSION,
                fa_model::entity_value_vid(h.book.book_id, code),
            )];
        }
        proposal
    };
    let maximum = with_entity(
        h.proposal(
            h.rent_legs(i128::MAX),
            b"entity-A-max",
            EntryClass::ORIGINAL,
        ),
        "A",
    );
    let over = with_entity(
        h.proposal(h.rent_legs(1), b"entity-B-retry", EntryClass::ORIGINAL),
        "B",
    );
    h.post(h.request(maximum, &["post"])).unwrap();
    let head = h.db.frontier().unwrap();
    let mut request = h.request(over.clone(), &["post"]);
    request.capability = request.capability.for_accounts(&["6000"]).unwrap();
    let refusal = h.post(request).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
    assert!(refusal.message.contains("accounts"), "{refusal}");
    assert!(!refusal.message.contains("stock"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);

    // The same authorized accounts include their other entity's stock;
    // disjoint entity dimensions do not authorize an overflowing column.
    let scoped = Capability::embedded(PRINCIPAL, &["post"])
        .unwrap()
        .for_accounts(&["1000", "6000"])
        .unwrap();
    let mut request = h.request(over.clone(), &["post"]);
    request.capability = scoped.clone();
    let refusal = h.post(request).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3));
    assert_eq!(h.db.frontier().unwrap(), head);

    let mut corrected = over;
    for leg in &mut corrected.legs {
        leg.side = leg.side.flipped();
    }
    corrected.unit_totals = EntryPayload::fold_unit_totals(&corrected.legs).unwrap();
    let mut request = h.request(corrected, &["post"]);
    request.capability = scoped;
    h.post(request)
        .expect("both refusals leave the corrected scoped key free");
    assert_leg_projections(&h);
}

#[test]
fn rejected_account_scope_never_decodes_a_planted_capacity_prefix_canary() {
    let mut h = harness();
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.create_vertex(
        VId(0xcafa),
        vec![fa_model::symbols::label::ENTRY],
        vec![(
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(vec![0xff; 8]).unwrap(),
        )],
    );
    h.write_raw(damage);
    let head = h.db.frontier().unwrap();
    let before = h.db.vertices().unwrap();
    let proposal = h.proposal(h.rent_legs(1), b"scope-canary", EntryClass::ORIGINAL);
    let mut request = h.request(proposal.clone(), &["post"]);
    request.capability = request.capability.for_accounts(&["6000"]).unwrap();
    let refusal = h.post(request).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
    assert!(refusal.message.contains("accounts"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), before);

    // The canary is active: whole-book authority reaches the malformed
    // retained prefix and errors instead of producing financial success.
    let ctx = h.ctx();
    let request = h.request(proposal, &["post"]);
    let observed = h.runtime.block_on(post(&mut h.db, &ctx, &h.book, request));
    assert!(
        matches!(&observed, Err(fa_journal::refusal::KernelError::Model(_))),
        "malformed prefix must be observed: {observed:?}"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), before);
}
