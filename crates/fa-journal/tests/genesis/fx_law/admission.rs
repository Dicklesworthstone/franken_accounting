//! A registered FX law cannot replace a native source-bound derivation.

use super::*;
use fa_journal::chart::{
    FxRevaluationRoute, FxRevaluationRoutesRequest, set_fx_revaluation_routes,
};
use fa_journal::refusal::code;
use fa_journal::revaluation::{FxRevaluationRequest, prepare_fx_revaluation};
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
