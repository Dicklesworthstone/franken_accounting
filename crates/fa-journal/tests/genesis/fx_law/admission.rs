//! A registered FX law cannot replace a native source-bound derivation.

use super::*;
use fa_journal::chart::{
    FxRevaluationRoute, FxRevaluationRoutesRequest, set_fx_revaluation_routes,
};
use fa_journal::refusal::code;
use fa_journal::revaluation::{
    FxRevaluationRequest, PreparedFxRevaluation, prepare_fx_revaluation,
};
use fa_model::{BaseTotals, PeriodRef};

const UNSUPPORTED: [FxLawId; 2] = [
    FxLawId::TranslationCurrentRate,
    FxLawId::RemeasurementTemporal,
];

fn closing_rate(h: &mut Harness, date: DateDay) -> FxRateDocument {
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: h.book.units.lookup("EUR").unwrap(),
            rate_num: 6,
            rate_den: 5,
            rounding: RoundingLaw::HalfEven,
        },
        date,
        1_700_000_000_000_000_200,
        FxRatePurpose::PeriodClose,
        "Retained closing quote, not a source balance",
    )
    .unwrap();
    h.add_document(
        &rate
            .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    rate
}

/// This shape has real retained Rate evidence, balanced native and base
/// amounts, and existing posting leaves. Before the fresh-claim guard,
/// Revaluation and Adjusting could publish it without deriving any source.
fn typed_claim(
    h: &Harness,
    rate: &FxRateDocument,
    law: FxLawId,
    class: EntryClass,
    amount: i128,
    key: &[u8],
) -> EntryPayload {
    let mut proposal = h.proposal(h.rent_legs(amount), key, class);
    proposal.effective_date = rate.as_of;
    for leg in &mut proposal.legs {
        leg.base_amount = Some(leg.amount);
    }
    let evidence = rate.evidence_ref(h.book.book_id).unwrap();
    proposal.evidence.push(evidence);
    proposal.evidence.sort();
    proposal.evidence.dedup();
    proposal.base_totals = Some(BaseTotals {
        unit_id: h.usd.0,
        debits: amount,
        credits: amount,
        fx_law_oid: law.oid(),
        rate_doc_oids: vec![evidence.document_oid],
        residual: None,
    });
    proposal.validate().unwrap();
    proposal
}

#[test]
fn fresh_translation_and_remeasurement_claims_cannot_post_arbitrary_balanced_amounts() {
    let mut h = harness();
    let date = h.day();
    let rate = closing_rate(&mut h, date);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let edges = h.db.edges().unwrap();
    for law in UNSUPPORTED {
        // Changing the caller-typed class cannot turn this calculation into
        // an admitted native law. The registered Adjusting path was also
        // open; an Original spelling must not become a way around the gate.
        for class in [
            EntryClass::REVALUATION,
            EntryClass::ADJUSTING,
            EntryClass::ORIGINAL,
        ] {
            for amount in [1, 987_654] {
                let key = format!("unbound-{}-{}-{amount}", law.name(), class.0);
                let proposal = typed_claim(&h, &rate, law, class, amount, key.as_bytes());
                let refused = h.post(h.request(proposal, &["read", "post"])).unwrap_err();
                assert_eq!(refused.code, code::CLASS_NOT_IMPLEMENTED, "{refused:?}");
                assert_eq!(refused.exit, 3);
                assert!(refused.message.contains(law.name()), "{refused:?}");
                assert_eq!(h.db.frontier().unwrap(), head);
                assert_eq!(h.db.vertices().unwrap(), rows);
                assert_eq!(h.db.edges().unwrap(), edges);
            }
        }
    }
}

#[test]
fn a_period_end_basis_cannot_launder_an_unsupported_law_and_native_revaluation_still_posts() {
    let (mut h, _, _) = valued_source();
    let accounts = [("1298", 1, 0), ("4788", 4, 1)]
        .into_iter()
        .map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(h.usd),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
    let cx = h.ctx();
    let date = h.day();
    let description = h
        .proposal(vec![], b"native-fx-route-chart", EntryClass::ORIGINAL)
        .description;
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            &accounts,
            PRINCIPAL,
            date,
            b"native-fx-route-chart",
            description.clone(),
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let source = account_vid(h.book.book_id, "1288");
    h.runtime
        .block_on(set_fx_revaluation_routes(
            &mut h.db,
            &cx,
            &h.book,
            &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            FxRevaluationRoutesRequest {
                principal: PRINCIPAL,
                effective_from: date,
                routes: [(
                    source,
                    FxRevaluationRoute {
                        valuation_account: account_vid(h.book.book_id, "1298"),
                        unrealized_account: account_vid(h.book.book_id, "4788"),
                    },
                )]
                .into(),
                idempotency_key: b"native-fx-routes".to_vec(),
                description,
            },
        ))
        .unwrap()
        .unwrap();
    let date = DateDay::from_ymd(2026, 3, 31).unwrap();
    let rate = closing_rate(&mut h, date);
    let request = FxRevaluationRequest {
        period: h.march.clone(),
        source_account: source,
        rate_document: rate.evidence_ref(h.book.book_id).unwrap().document_oid,
        entity: None,
        item_allocation: false,
    };
    let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(100_000, 0), 4096);
    let prepared = prepare_fx_revaluation(
        &h.db,
        &cx,
        &h.book,
        &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
        &request,
        &mut budget,
    )
    .unwrap()
    .unwrap();
    // The source is 100 EUR minor units at 11/10; the retained 6/5 quote
    // derives 120 USD minor units, less original carrying of 110 = 10.
    assert_eq!(prepared.delta(), Amount::new(h.usd, 10));
    let mut template = h.proposal(vec![], b"native-fx-close", EntryClass::REVALUATION);
    template.effective_date = date;
    template.effective_period = Some(PeriodRef {
        calendar: h.book.calendar.id.clone(),
        code: h.march.clone(),
    });
    let original = prepared.proposal(template).unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    for law in UNSUPPORTED {
        let mut forged = original.clone();
        forged.idempotency_key = format!("laundered-{}", law.name()).into_bytes();
        forged.base_totals.as_mut().unwrap().fx_law_oid = law.oid();
        assert!(
            forged
                .extensions
                .iter()
                .any(|(tag, _)| { *tag == fa_model::entry::FX_REVALUATION_EXTENSION })
        );
        let refused = h.post(h.request(forged, &["read", "post"])).unwrap_err();
        assert_eq!(refused.code, code::CLASS_NOT_IMPLEMENTED, "{refused:?}");
        assert!(refused.message.contains(law.name()));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
    let posted = h
        .post(h.request(original.clone(), &["read", "post"]))
        .unwrap();
    assert!(matches!(posted, Posted::Committed { .. }));
    assert!(verify(&h, h.db.frontier().unwrap()).is_green());
    let head = h.db.frontier().unwrap();
    let repeated = h.post(h.request(original, &["read", "post"])).unwrap();
    assert!(matches!(repeated, Posted::AlreadyRecorded { .. }));
    assert_eq!(repeated.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), head);
}

struct RevaluationBatchFixture {
    h: Harness,
    sources: [VId; 2],
    spot: FxRateDocument,
    closing: FxRateDocument,
}

impl RevaluationBatchFixture {
    fn new() -> Self {
        let (mut h, source_rate, _) = valued_source();
        let foreign = h.book.units.lookup("EUR").unwrap();
        let accounts = [
            ("1388", 1, 0, foreign),
            ("1298", 1, 0, h.usd),
            ("1398", 1, 0, h.usd),
            ("4788", 4, 1, h.usd),
        ]
        .into_iter()
        .map(|(code, account_type, normal_balance, unit)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(unit),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
        let cx = h.ctx();
        let date = h.day();
        let description = h
            .proposal(vec![], b"batch-fx-chart", EntryClass::ORIGINAL)
            .description;
        h.runtime
            .block_on(install_chart(
                &mut h.db,
                &cx,
                &h.book,
                &accounts,
                PRINCIPAL,
                date,
                b"batch-fx-chart",
                description.clone(),
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        let sources = ["1288", "1388"].map(|code| account_vid(h.book.book_id, code));
        let routes = sources
            .into_iter()
            .zip(["1298", "1398"])
            .map(|(source, valuation)| {
                (
                    source,
                    FxRevaluationRoute {
                        valuation_account: account_vid(h.book.book_id, valuation),
                        // Shared gain offsets are outside both protected populations.
                        unrealized_account: account_vid(h.book.book_id, "4788"),
                    },
                )
            })
            .collect();
        h.runtime
            .block_on(set_fx_revaluation_routes(
                &mut h.db,
                &cx,
                &h.book,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
                FxRevaluationRoutesRequest {
                    principal: PRINCIPAL,
                    effective_from: date,
                    routes,
                    idempotency_key: b"batch-fx-routes".to_vec(),
                    description,
                },
            ))
            .unwrap()
            .unwrap();
        let closing = closing_rate(&mut h, DateDay::from_ymd(2026, 3, 31).unwrap());
        let mut fixture = Self {
            h,
            sources,
            spot: FxRateDocument::decode(&source_rate.bytes).unwrap(),
            closing,
        };
        fixture.post_source(1, 200, b"batch-fx-second-source");
        fixture
    }

    fn capability() -> Capability {
        Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
    }

    fn source_proposal(&self, index: usize, amount: i128, key: &[u8]) -> EntryPayload {
        let h = &self.h;
        let foreign = h.book.units.lookup("EUR").unwrap();
        let proposal = h.proposal(
            vec![
                LegPayload::simple(
                    Side::Debit,
                    self.sources[index],
                    Amount::new(foreign, amount),
                ),
                LegPayload::simple(
                    Side::Credit,
                    account_vid(h.book.book_id, "4088"),
                    Amount::new(foreign, amount),
                ),
            ],
            key,
            EntryClass::ORIGINAL,
        );
        let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(100_000, 0), 4096);
        value_proposal(
            &mut budget,
            proposal,
            &fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap(),
            &h.book.units,
            FxLawId::SpotClose,
            std::slice::from_ref(&self.spot),
        )
        .unwrap()
    }

    fn post_source(&mut self, index: usize, amount: i128, key: &[u8]) {
        let proposal = self.source_proposal(index, amount, key);
        self.h.post(self.h.request(proposal, &["post"])).unwrap();
    }

    fn observe(&self, index: usize, allocated: bool) -> PreparedFxRevaluation {
        let arithmetic = self.h.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        prepare_fx_revaluation(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            &Self::capability(),
            &FxRevaluationRequest {
                period: self.h.march.clone(),
                source_account: self.sources[index],
                rate_document: self
                    .closing
                    .evidence_ref(self.h.book.book_id)
                    .unwrap()
                    .document_oid,
                entity: None,
                item_allocation: allocated,
            },
            &mut budget,
        )
        .unwrap()
        .unwrap()
    }

    fn proposal(&self, index: usize, allocated: bool, key: &[u8]) -> EntryPayload {
        let prepared = self.observe(index, allocated);
        let mut template = self.h.proposal(vec![], key, EntryClass::REVALUATION);
        template.effective_date = prepared.closing_date();
        template.effective_period = Some(PeriodRef {
            calendar: self.h.book.calendar.id.clone(),
            code: self.h.march.clone(),
        });
        prepared.proposal(template).unwrap()
    }

    fn post_batch(&mut self, batch: fa_intents::PostBatch) -> Result<BatchPosted, Refusal> {
        let cx = self.h.ctx();
        self.h
            .runtime
            .block_on(fa_journal::post_batch(
                &mut self.h.db,
                &cx,
                &self.h.book,
                Self::capability(),
                batch,
            ))
            .unwrap()
    }
}

#[test]
fn independent_revaluations_publish_atomically_and_replay_each_source_at_later_cutoffs() {
    for allocated in [false, true] {
        for planned in [false, true] {
            let mut f = RevaluationBatchFixture::new();
            let batch = f.h.batch(
                b"independent-revaluations",
                vec![
                    f.proposal(0, allocated, b"first-revaluation"),
                    f.proposal(1, allocated, b"second-revaluation"),
                ],
            );
            let before = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let plan = planned.then(|| {
                let plan =
                    f.h.planned_batch(batch.clone(), &RevaluationBatchFixture::capability())
                        .unwrap();
                assert_eq!(plan.prepared_entries().len(), 2);
                assert_eq!(f.h.db.frontier().unwrap(), before);
                assert_eq!(f.h.db.vertices().unwrap(), rows);
                fa_intents::BatchPlan::decode(&plan.canonical_bytes().unwrap()).unwrap()
            });
            let posted = match &plan {
                Some(plan) => {
                    f.h.publish_batch_plan(plan.clone(), &RevaluationBatchFixture::capability())
                        .unwrap()
                }
                None => f.post_batch(batch.clone()).unwrap(),
            };
            assert!(!posted.already_recorded);
            assert_eq!(posted.entries.len(), 2);
            assert_eq!(posted.recorded_at.0, before.0 + 1);
            for (reference, member) in posted.entries.iter().zip(batch.members()) {
                let (entry, recorded) = read_entry(&f.h.db, reference.vid).unwrap().unwrap();
                assert_eq!(entry.proposal, *member.proposal());
                assert_eq!(recorded, posted.recorded_at);
            }
            assert!(verify(&f.h, posted.recorded_at).is_green());
            // Each source audits the retained same-sequence publication, then
            // folds only its own dedicated valuation leaf. The shared gain
            // account must not make either audit see a duplicate adjustment.
            for (index, (native, adjustment, carrying)) in
                [(100, 10, 120), (200, 20, 240)].into_iter().enumerate()
            {
                let observed = f.observe(index, allocated);
                assert!(observed.is_noop());
                assert_eq!(observed.source_native_net().mantissa, native);
                assert_eq!(observed.prior_adjustment_net().mantissa, adjustment);
                assert_eq!(observed.current_carrying_net().mantissa, carrying);
            }
            let unrelated = f.h.proposal(
                f.h.rent_legs(7),
                b"after-revaluations",
                EntryClass::ORIGINAL,
            );
            f.h.post(f.h.request(unrelated, &["post"])).unwrap();
            let after = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let retry = match plan {
                Some(plan) => {
                    f.h.publish_batch_plan(plan, &RevaluationBatchFixture::capability())
                        .unwrap()
                }
                None => f.post_batch(batch).unwrap(),
            };
            assert!(retry.already_recorded);
            assert_eq!(retry.entries, posted.entries);
            assert_eq!(retry.recorded_at, posted.recorded_at);
            assert_eq!(f.h.db.frontier().unwrap(), after);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
            assert!(f.observe(0, allocated).is_noop());
            assert!(f.observe(1, allocated).is_noop());
        }
    }
}

#[test]
fn independent_revaluations_and_ordinary_companions_share_one_reviewed_publication() {
    for allocated in [false, true] {
        for class in [EntryClass::ORIGINAL, EntryClass::ADJUSTING] {
            for reverse in [false, true] {
                let mut f = RevaluationBatchFixture::new();
                // Sharing the unrealized offset is safe: it is not a source
                // or a dedicated valuation leaf. The literal replay must
                // still reproduce each revaluation's exact 10/20 USD delta.
                let companion = f.h.proposal(
                    vec![
                        LegPayload::simple(Side::Debit, f.h.rent, Amount::new(f.h.usd, 7)),
                        LegPayload::simple(
                            Side::Credit,
                            account_vid(f.h.book.book_id, "4788"),
                            Amount::new(f.h.usd, 7),
                        ),
                    ],
                    b"independent-close-companion",
                    class,
                );
                let mut members = vec![
                    companion,
                    f.proposal(0, allocated, b"mixed-first-revaluation"),
                    f.proposal(1, allocated, b"mixed-second-revaluation"),
                ];
                if reverse {
                    members.reverse();
                }
                let batch = f.h.batch(b"independent-close-batch", members);
                let before = f.h.db.frontier().unwrap();
                let rows = f.h.db.vertices().unwrap();
                let capability = RevaluationBatchFixture::capability();
                let plan = f.h.planned_batch(batch.clone(), &capability).unwrap();
                assert_eq!(plan.prepared_entries().len(), 3);
                assert_eq!(f.h.db.frontier().unwrap(), before);
                assert_eq!(f.h.db.vertices().unwrap(), rows);
                let plan = fa_intents::BatchPlan::decode(&plan.canonical_bytes().unwrap()).unwrap();
                let posted = if allocated {
                    f.h.publish_batch_plan(plan.clone(), &capability).unwrap()
                } else {
                    f.post_batch(batch.clone()).unwrap()
                };
                assert!(!posted.already_recorded);
                assert_eq!(posted.entries.len(), 3);
                assert_eq!(posted.recorded_at.0, before.0 + 1);
                for (reference, member) in posted.entries.iter().zip(batch.members()) {
                    let (entry, at) = read_entry(&f.h.db, reference.vid).unwrap().unwrap();
                    assert_eq!(entry.proposal, *member.proposal());
                    assert_eq!(at, posted.recorded_at);
                }
                assert!(verify(&f.h, posted.recorded_at).is_green());
                for (index, (native, adjustment, carrying)) in
                    [(100, 10, 120), (200, 20, 240)].into_iter().enumerate()
                {
                    let observed = f.observe(index, allocated);
                    assert!(observed.is_noop());
                    assert_eq!(observed.source_native_net().mantissa, native);
                    assert_eq!(observed.prior_adjustment_net().mantissa, adjustment);
                    assert_eq!(observed.current_carrying_net().mantissa, carrying);
                }
                let later = f.h.proposal(
                    f.h.rent_legs(9),
                    b"later-independent-close-activity",
                    EntryClass::ORIGINAL,
                );
                f.h.post(f.h.request(later, &["post"])).unwrap();
                let after = f.h.db.frontier().unwrap();
                let rows = f.h.db.vertices().unwrap();
                let retry = if allocated {
                    f.h.publish_batch_plan(plan, &capability).unwrap()
                } else {
                    f.post_batch(batch).unwrap()
                };
                assert!(retry.already_recorded);
                assert_eq!(retry.entries, posted.entries);
                assert_eq!(retry.recorded_at, posted.recorded_at);
                assert_eq!(f.h.db.frontier().unwrap(), after);
                assert_eq!(f.h.db.vertices().unwrap(), rows);
                assert!(verify(&f.h, after).is_green());
            }
        }
    }
}

#[test]
fn revaluation_companions_cannot_touch_any_source_or_valuation_account_in_either_order() {
    for source in [false, true] {
        for reverse in [false, true] {
            let mut f = RevaluationBatchFixture::new();
            let revaluation = f.proposal(0, true, b"protected-revaluation");
            let companion = if source {
                f.source_proposal(0, 10, b"source-changing-companion")
            } else {
                f.h.proposal(
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(f.h.book.book_id, "1298"),
                            Amount::new(f.h.usd, 10),
                        ),
                        LegPayload::simple(Side::Credit, f.h.cash, Amount::new(f.h.usd, 10)),
                    ],
                    b"valuation-changing-companion",
                    EntryClass::ADJUSTING,
                )
            };
            let mut members = vec![revaluation, companion];
            if reverse {
                members.reverse();
            }
            let batch = f.h.batch(b"protected-revaluation-batch", members);
            let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
            let before = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let edges = f.h.db.edges().unwrap();
            let capability = RevaluationBatchFixture::capability();
            for refused in [
                f.h.planned_batch(batch.clone(), &capability).unwrap_err(),
                f.post_batch(batch).unwrap_err(),
            ] {
                assert_eq!(refused.code, code::CLASS_NOT_IMPLEMENTED, "{refused}");
                assert!(
                    refused.message.contains("source and valuation"),
                    "{refused}"
                );
            }
            assert_eq!(f.h.db.frontier().unwrap(), before);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
            assert_eq!(f.h.db.edges().unwrap(), edges);
            assert!(f.h.db.vertex(outcome).unwrap().is_none());
            assert_eq!(f.observe(0, true).delta().mantissa, 10);
        }
    }
}

#[test]
fn revaluation_batches_refuse_other_application_protocols_without_consuming_the_item() {
    for reverse in [false, true] {
        let mut f = RevaluationBatchFixture::new();
        let invoice = f.h.invoice(30, b"unrelated-companion-invoice");
        let target =
            f.h.post(f.h.request(invoice, &["post"]))
                .unwrap()
                .entry_ref();
        let receipt = f.h.receipt(
            10,
            vec![settle(target, 0, f.h.usd, 10)],
            b"unrelated-application-companion",
        );
        let mut members = vec![
            f.proposal(0, false, b"application-mixed-revaluation"),
            receipt.clone(),
        ];
        if reverse {
            members.reverse();
        }
        let batch = f.h.batch(b"application-mixed-close", members);
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused = f.post_batch(batch).unwrap_err();
        assert_eq!(refused.code, code::CLASS_NOT_IMPLEMENTED, "{refused}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.applied_to(target.vid, 0), 0);
        // The companion itself is a valid application. It needs its ordinary
        // publication protocol, not admission as an independent close effect.
        f.h.post(f.h.request(receipt, &["post"])).unwrap();
        assert_eq!(f.h.applied_to(target.vid, 0), 10);
    }
}

#[test]
fn mixed_revaluation_plans_keep_the_complete_publication_frontier_guard() {
    let mut f = RevaluationBatchFixture::new();
    let companion = f.h.proposal(
        f.h.rent_legs(7),
        b"guarded-revaluation-companion",
        EntryClass::ADJUSTING,
    );
    let batch = f.h.batch(
        b"guarded-mixed-close",
        vec![companion, f.proposal(0, false, b"guarded-revaluation")],
    );
    let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
    let capability = RevaluationBatchFixture::capability();
    let plan = f.h.planned_batch(batch, &capability).unwrap();
    // Even an unrelated intervening commit cannot silently refresh a
    // previously reviewed aggregate transaction's publication frontier.
    let later = f.h.proposal(
        f.h.rent_legs(1),
        b"after-reviewed-mixed-close",
        EntryClass::ORIGINAL,
    );
    f.h.post(f.h.request(later, &["post"])).unwrap();
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refused = f.h.publish_batch_plan(plan, &capability).unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED, "{refused}");
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert!(f.h.db.vertex(outcome).unwrap().is_none());
    assert_eq!(f.observe(0, false).delta().mantissa, 10);
}

#[test]
fn mixed_revaluation_batches_require_source_read_authority_before_source_observation() {
    for reverse in [false, true] {
        let mut f = RevaluationBatchFixture::new();
        let companion = f.h.proposal(
            f.h.rent_legs(7),
            b"unprivileged-close-companion",
            EntryClass::ORIGINAL,
        );
        let mut members = vec![companion, f.proposal(0, false, b"unprivileged-revaluation")];
        if reverse {
            members.reverse();
        }
        let batch = f.h.batch(b"unprivileged-mixed-close", members);
        // Any attempted source reconstruction would now report corruption.
        // Posting authority on the ordinary member must not bypass the
        // revaluation member's independent Read requirement in either order.
        let rate = f.closing.evidence_ref(f.h.book.book_id).unwrap();
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            document_vid(&rate.document_oid),
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(vec![0]).unwrap()),
        );
        f.h.write_raw(damage);
        let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let planned = f.h.planned_batch(batch.clone(), &capability).unwrap_err();
        assert_eq!(planned.code, code::CAPABILITY, "{planned}");
        let cx = f.h.ctx();
        let refused =
            f.h.runtime
                .block_on(fa_journal::post_batch(
                    &mut f.h.db,
                    &cx,
                    &f.h.book,
                    capability,
                    batch,
                ))
                .unwrap()
                .unwrap_err();
        assert_eq!(refused.code, code::CAPABILITY, "{refused}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn mixed_revaluation_drafts_keep_each_planners_authority_and_refuse_changed_sources() {
    for reverse in [false, true] {
        for changed in [false, true] {
            let mut f = RevaluationBatchFixture::new();
            let name = "reviewed-revaluation-with-accrual";
            let agent = f.h.agent_capability();
            let write_only = Capability::new(
                AGENT,
                fa_policy::Profile::Agent,
                &[fa_policy::Op::Post],
                PRINCIPAL,
            )
            .unwrap();
            f.h.open_draft(agent.clone(), name).unwrap();
            let mut revaluation = f.proposal(0, true, b"drafted-mixed-revaluation");
            revaluation.principal_ref = AGENT;
            let mut companion = f.h.agent_rent(7, b"drafted-close-accrual");
            companion.class = EntryClass::ADJUSTING;
            let mut members = vec![
                (write_only.clone(), companion),
                (agent.clone(), revaluation),
            ];
            if reverse {
                members.reverse();
            }
            let mut preview = None;
            for (capability, proposal) in &members {
                preview =
                    f.h.plan_draft(capability.clone(), name, proposal.clone())
                        .unwrap()
                        .plan;
            }
            let preview = preview.unwrap();
            let expected: Vec<_> = preview
                .members()
                .iter()
                .map(|member| {
                    member.entry.entry_ref(entry_vid(
                        f.h.book.book_id,
                        &AGENT.0.to_le_bytes(),
                        &member.entry.proposal.idempotency_key,
                    ))
                })
                .collect();
            let retained = f.h.draft(name);
            assert_eq!(retained.intents.len(), 2);
            for (saved, (capability, proposal)) in retained.intents.iter().zip(&members) {
                assert_eq!(&saved.capability, capability);
                assert_eq!(saved.intent.proposal(), proposal);
            }
            assert!(fa_policy::admit_read(&write_only, AGENT, f.h.book.book_id).is_err());
            for reference in &expected {
                assert!(read_entry(&f.h.db, reference.vid).unwrap().is_none());
            }
            if changed {
                f.post_source(0, 100, b"source-changed-after-close-draft");
            }
            let before = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let promoted = f.h.promote(f.h.approver_capability(), name);
            if changed {
                let refused = promoted.unwrap_err();
                assert_eq!(refused.code, code::PLAN_INVALIDATED, "{refused}");
                assert_eq!(f.h.db.frontier().unwrap(), before);
                assert_eq!(f.h.db.vertices().unwrap(), rows);
                assert_eq!(f.h.draft(name).state, DraftState::Open);
                for reference in &expected {
                    assert!(read_entry(&f.h.db, reference.vid).unwrap().is_none());
                }
                continue;
            }
            let promoted = promoted.unwrap();
            assert_eq!(promoted.entries, expected);
            assert_eq!(promoted.recorded_at.0, before.0 + 1);
            for (reference, (_, proposal)) in expected.iter().zip(&members) {
                let (entry, at) = read_entry(&f.h.db, reference.vid).unwrap().unwrap();
                assert_eq!(&entry.proposal, proposal);
                assert_eq!(at, promoted.recorded_at);
            }
            assert!(verify(&f.h, promoted.recorded_at).is_green());
            assert!(f.observe(0, true).is_noop());
            let rows = f.h.db.vertices().unwrap();
            let retry = f.h.promote(f.h.approver_capability(), name).unwrap();
            assert!(retry.already_recorded);
            assert_eq!(retry.entries, expected);
            assert_eq!(retry.recorded_at, promoted.recorded_at);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
        }
    }
}

#[test]
fn revaluation_batches_refuse_shared_sources_and_mixed_members_without_publication() {
    for mixed in [false, true] {
        for reverse in [false, true] {
            let mut f = RevaluationBatchFixture::new();
            let first = f.proposal(0, false, b"isolated-first");
            let second = if mixed {
                // Ordinary isolated postings now compose; reservation and
                // lifecycle effects still require a separate source law.
                f.h.pending(f.h.rent_legs(10), b"reservation-companion")
            } else {
                f.proposal(0, false, b"same-source-second")
            };
            let mut members = vec![first, second];
            if reverse {
                members.reverse();
            }
            let batch = f.h.batch(b"non-independent-revaluations", members);
            let before = f.h.db.frontier().unwrap();
            let vertices = f.h.db.vertices().unwrap();
            let edges = f.h.db.edges().unwrap();
            let refused = f.post_batch(batch).unwrap_err();
            assert_eq!(refused.code, code::CLASS_NOT_IMPLEMENTED, "{refused}");
            assert_eq!(f.h.db.frontier().unwrap(), before);
            assert_eq!(f.h.db.vertices().unwrap(), vertices);
            assert_eq!(f.h.db.edges().unwrap(), edges);
        }
    }
}

#[test]
fn a_changed_later_revaluation_basis_or_effect_refuses_the_whole_atomic_batch() {
    for mutation in ["source", "rate", "valuation"] {
        let mut f = RevaluationBatchFixture::new();
        let first = f.proposal(0, false, b"rollback-first-revaluation");
        let mut second = f.proposal(1, false, b"rollback-second-revaluation");
        match mutation {
            "source" => f.post_source(1, 100, b"later-second-exposure"),
            "rate" => {
                let (_, raw) = second
                    .extensions
                    .iter_mut()
                    .find(|(tag, _)| *tag == fa_model::entry::FX_REVALUATION_EXTENSION)
                    .unwrap();
                let mut basis = fa_model::FxRevaluationBasis::decode(raw).unwrap();
                basis.rate_commit[0] ^= 1;
                *raw = basis.canonical_bytes().unwrap();
            }
            "valuation" => {
                // Still balanced and base-valued, but it poisons the sibling's
                // protected history instead of the prepared dedicated leaf.
                second.legs[0].account_ref = account_vid(f.h.book.book_id, "1298");
            }
            _ => unreachable!(),
        }
        let companion = f.h.proposal(
            f.h.rent_legs(7),
            b"rollback-ordinary-companion",
            EntryClass::ADJUSTING,
        );
        let batch =
            f.h.batch(b"rollback-revaluations", vec![companion, first, second]);
        let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
        let before = f.h.db.frontier().unwrap();
        let vertices = f.h.db.vertices().unwrap();
        let edges = f.h.db.edges().unwrap();
        let refused = f.post_batch(batch).unwrap_err();
        assert_eq!(
            refused.code,
            code::PLAN_INVALIDATED,
            "{mutation}: {refused}"
        );
        assert!(refused.message.contains("member 2"), "{refused}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), vertices);
        assert_eq!(f.h.db.edges().unwrap(), edges);
        assert!(f.h.db.vertex(outcome).unwrap().is_none());
        assert_eq!(f.observe(0, false).delta().mantissa, 10);
    }
}

#[test]
fn retained_translation_claims_still_read_and_return_their_exact_recorded_outcome() {
    for law in UNSUPPORTED {
        // Construct an original pre-protocol book and its original Entry
        // births. No modern coverage marker or outcome is removed or edited.
        let mut h = harness_legacy();
        let date = h.day();
        let rate = closing_rate(&mut h, date);
        let original = typed_claim(
            &h,
            &rate,
            law,
            EntryClass::REVALUATION,
            25,
            b"retained-translation",
        );
        let entry = outcome_recovery_tests::write_legacy(&mut h, original.clone());
        let head = h.db.frontier().unwrap();
        assert_eq!(
            read_entry(&h.db, entry.vid).unwrap().unwrap().0.proposal,
            original
        );
        let historical = verify(&h, head);
        assert!(historical.is_green());
        assert_eq!(historical.checked.get(law.name()), Some(&1));
        let repeated = h
            .post(h.request(original.clone(), &["read", "post"]))
            .unwrap();
        assert!(matches!(repeated, Posted::AlreadyRecorded { .. }));
        assert_eq!(repeated.entry_ref(), entry);
        let changed = typed_claim(
            &h,
            &rate,
            law,
            EntryClass::REVALUATION,
            26,
            &original.idempotency_key,
        );
        assert_eq!(
            h.post(h.request(changed, &["read", "post"]))
                .unwrap_err()
                .code,
            code::IDEMPOTENCY_CONFLICT,
        );
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn a_retained_adjustment_can_reverse_later_using_its_original_translation_quote() {
    for law in UNSUPPORTED {
        let mut h = harness_legacy();
        let date = h.day();
        let rate = closing_rate(&mut h, date);
        let original = typed_claim(
            &h,
            &rate,
            law,
            EntryClass::ADJUSTING,
            25,
            b"retained-adjustment",
        );
        let target = outcome_recovery_tests::write_legacy(&mut h, original.clone());
        let cx = h.ctx();
        let coverage = h
            .runtime
            .block_on(prepare_outcome_rebuild(
                &mut h.db,
                &cx,
                &h.book,
                Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        h.runtime
            .block_on(publish_outcome_rebuild(&mut h.db, &cx, &h.book, coverage))
            .unwrap()
            .unwrap();
        let mut reversal = original.clone();
        reversal.class = EntryClass::REVERSAL;
        reversal.idempotency_key = b"undo-retained-adjustment".to_vec();
        reversal.effective_date = DateDay::from_ymd(2026, 3, 20).unwrap();
        reversal.supersession = vec![Supersession {
            kind: SupersessionKind::Reverses,
            target,
            reason_code: 1,
        }];
        for leg in &mut reversal.legs {
            leg.side = leg.side.flipped();
        }
        reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
        let head = h.db.frontier().unwrap();
        let mut repriced = reversal.clone();
        for leg in &mut repriced.legs {
            leg.amount.mantissa = 26;
            leg.base_amount = Some(leg.amount);
        }
        repriced.unit_totals = EntryPayload::fold_unit_totals(&repriced.legs).unwrap();
        repriced.base_totals.as_mut().unwrap().debits = 26;
        repriced.base_totals.as_mut().unwrap().credits = 26;
        assert_eq!(
            h.post(h.request(repriced, &["read", "post"]))
                .unwrap_err()
                .code,
            code::REVERSAL_SHAPE,
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        let posted = h
            .post(h.request(reversal.clone(), &["read", "post"]))
            .unwrap();
        assert!(matches!(posted, Posted::Committed { .. }));
        let (recorded, _) = read_entry(&h.db, posted.entry_ref().vid).unwrap().unwrap();
        assert_eq!(recorded.proposal.base_totals, original.base_totals);
        assert_eq!(recorded.proposal.evidence, original.evidence);
        assert!(verify(&h, h.db.frontier().unwrap()).is_green());
        let head = h.db.frontier().unwrap();
        let repeated = h.post(h.request(reversal, &["read", "post"])).unwrap();
        assert!(matches!(repeated, Posted::AlreadyRecorded { .. }));
        assert_eq!(repeated.entry_ref(), posted.entry_ref());
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

fn install_foreign_reclassification_accounts(h: &mut Harness, accounts: &[(&str, u8, u8)]) {
    let foreign = h.book.units.lookup("EUR").unwrap();
    let accounts = accounts
        .iter()
        .map(|&(code, account_type, normal_balance)| AccountSpec {
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
    let cx = h.ctx();
    let date = h.day();
    let description = h
        .proposal(vec![], b"reclass-chart", EntryClass::ORIGINAL)
        .description;
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            &accounts,
            PRINCIPAL,
            date,
            b"foreign-reclassification-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
}

fn native_foreign_reclassification(h: &Harness, target: EntryRef, key: &[u8]) -> EntryPayload {
    let amount = Amount::new(h.book.units.lookup("EUR").unwrap(), 50);
    let mut proposal = h.proposal(
        vec![
            LegPayload::simple(Side::Credit, account_vid(h.book.book_id, "1288"), amount),
            LegPayload::simple(Side::Debit, account_vid(h.book.book_id, "1388"), amount),
        ],
        key,
        EntryClass::RECLASSIFICATION,
    );
    proposal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reclassifies,
        reason_code: 1,
    }];
    proposal
}

#[test]
fn a_foreign_reclassification_cannot_omit_its_functional_carrying_value() {
    // No registered FX law supplies a reclassification's carrying-value
    // transfer. An absent valuation cannot make that unsupported law vanish.
    let classes = fa_registry::EntryClasses::embedded().unwrap();
    let laws = fa_registry::FxLaws::embedded(&classes).unwrap();
    assert!(laws.laws.iter().all(|law| {
        !law.admitted_classes
            .iter()
            .any(|class| class == "Reclassification")
    }));
    for valued in [true, false] {
        let (mut h, _, mut target) = valued_source();
        install_foreign_reclassification_accounts(&mut h, &[("1388", 1, 0)]);
        let (source, _) = read_entry(&h.db, target.vid).unwrap().unwrap();
        assert_eq!(source.proposal.legs[0].amount.mantissa, 100);
        assert_eq!(
            source.proposal.legs[0].base_amount,
            Some(Amount::new(h.usd, 110))
        );
        if !valued {
            // The historical native-only posting subset still exists; it
            // does not authorize an unregistered foreign reclassification.
            let mut unvalued = source.proposal.clone();
            unvalued.idempotency_key = b"native-only-source".to_vec();
            unvalued.base_totals = None;
            for leg in &mut unvalued.legs {
                leg.base_amount = None;
            }
            target = h.post(h.request(unvalued, &["post"])).unwrap().entry_ref();
        }
        let proposal = native_foreign_reclassification(&h, target, b"unvalued-reclass");
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges().unwrap();
        let refusal = h
            .post(h.request(proposal.clone(), &["post"]))
            .expect_err("a native move must not leave its functional value on the source");
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::CLASS_NOT_IMPLEMENTED, 3)
        );
        assert!(refusal.message.contains("Reclassification"), "{refusal}");
        assert!(refusal.message.contains("carrying"), "{refusal}");
        assert!(refusal.fix.contains("fa explain lineage"), "{refusal}");
        let planned = h
            .post_plan(h.request(proposal, &["read", "post"]))
            .unwrap_err();
        assert_eq!(planned.code, code::CLASS_NOT_IMPLEMENTED, "{planned}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges().unwrap(), edges);
    }
}

#[test]
fn base_currency_reclassification_and_retained_foreign_outcomes_keep_their_semantics() {
    let mut h = harness();
    let target = h
        .post(h.request(
            h.proposal(h.rent_legs(100), b"base-source", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let mut proposal = h.proposal(
        vec![
            LegPayload::simple(Side::Credit, h.rent, Amount::new(h.usd, 50)),
            LegPayload::simple(Side::Debit, h.receivable, Amount::new(h.usd, 50)),
        ],
        b"base-reclass",
        EntryClass::RECLASSIFICATION,
    );
    proposal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reclassifies,
        reason_code: 1,
    }];
    assert!(matches!(
        h.post(h.request(proposal, &["post"])).unwrap(),
        Posted::Committed { .. }
    ));

    // Retain the actual earlier native writer's entries, rather than
    // weakening fresh admission or editing an immutable modern outcome.
    let mut h = harness_legacy();
    install_foreign_reclassification_accounts(
        &mut h,
        &[("1288", 1, 0), ("1388", 1, 0), ("4088", 4, 1)],
    );
    let amount = Amount::new(h.book.units.lookup("EUR").unwrap(), 100);
    let original = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, account_vid(h.book.book_id, "1288"), amount),
            LegPayload::simple(Side::Credit, account_vid(h.book.book_id, "4088"), amount),
        ],
        b"legacy-foreign-source",
        EntryClass::ORIGINAL,
    );
    let target = outcome_recovery_tests::write_legacy(&mut h, original);
    let proposal = native_foreign_reclassification(&h, target, b"legacy-foreign-reclass");
    let entry = outcome_recovery_tests::write_legacy(&mut h, proposal.clone());
    let head = h.db.frontier().unwrap();
    assert_eq!(
        read_entry(&h.db, entry.vid).unwrap().unwrap().0.proposal,
        proposal
    );
    assert!(verify(&h, head).is_green());
    let repeated = h.post(h.request(proposal, &["post"])).unwrap();
    assert!(matches!(repeated, Posted::AlreadyRecorded { .. }));
    assert_eq!(repeated.entry_ref(), entry);
    assert_eq!(h.db.frontier().unwrap(), head);
}
