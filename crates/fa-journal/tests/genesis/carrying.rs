use super::*;
use fa_journal::carrying::{FxSettlementRequest, open_item_carrying_at, prepare_fx_settlement};
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};

struct Fixture {
    h: Harness,
    target: EntryRef,
    foreign: UnitId,
    conversion: VId,
    realized: VId,
    rate: Oid,
}

fn request(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: vec![],
        plan_certificate: None,
        capability: Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
    }
}

fn fixture(native: i128, base: i128) -> Fixture {
    let mut h = harness();
    let foreign = h.book.units.lookup("EUR").unwrap();
    let accounts = [
        (
            "1211",
            "Foreign receivables",
            fa_model::AccountType::ASSET,
            0,
        ),
        ("4011", "Foreign revenue", fa_model::AccountType::REVENUE, 1),
        ("2991", "FX conversion", fa_model::AccountType::LIABILITY, 1),
        ("7091", "Realized FX", fa_model::AccountType::REVENUE, 1),
    ]
    .into_iter()
    .map(|(code, name, kind, normal)| AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type: kind.0,
        normal_balance: normal,
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    })
    .collect::<Vec<_>>();
    let cx = h.ctx();
    let day = h.day();
    let description = h
        .proposal(vec![], b"chart", EntryClass::ORIGINAL)
        .description;
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"carrying-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let spot = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: foreign,
            rate_num: u128::try_from(base).unwrap(),
            rate_den: u128::try_from(native).unwrap(),
            rounding: RoundingLaw::HalfEven,
        },
        day,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "explicit fixture rate",
    )
    .unwrap();
    h.add_document(
        &spot
            .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    let settle = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: foreign,
            rate_num: 2,
            rate_den: 1,
            rounding: RoundingLaw::HalfEven,
        },
        day,
        1_700_000_000_000_000_001,
        FxRatePurpose::Settlement,
        "explicit settlement rate",
    )
    .unwrap();
    h.add_document(
        &settle
            .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    let receivable = account_vid(h.book.book_id, "1211");
    let revenue = account_vid(h.book.book_id, "4011");
    let invoice = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, receivable, Amount::new(foreign, native)),
            LegPayload::simple(Side::Credit, revenue, Amount::new(foreign, native)),
        ],
        b"foreign-invoice",
        EntryClass::ORIGINAL,
    );
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    let invoice = value_proposal(
        &mut budget,
        invoice,
        &spec,
        &h.book.units,
        FxLawId::SpotClose,
        &[spot],
    )
    .unwrap();
    let target = h.post(request(invoice)).unwrap().entry_ref();
    let conversion = account_vid(h.book.book_id, "2991");
    let realized = account_vid(h.book.book_id, "7091");
    let rate = settle.evidence_ref(h.book.book_id).unwrap().document_oid;
    Fixture {
        h,
        target,
        foreign,
        conversion,
        realized,
        rate,
    }
}

impl Fixture {
    fn prepare(&self, amount: i128, key: &[u8]) -> PreparedFxSettlement {
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let req = FxSettlementRequest {
            target: self.target,
            target_ordinal: 0,
            amount: Amount::new(self.foreign, amount),
            settlement_amount: Amount::new(self.h.usd, amount.checked_mul(2).unwrap()),
            settlement_account: self.h.cash,
            conversion_account: self.conversion,
            realized_fx_account: self.realized,
            rate_document: self.rate,
        };
        prepare_fx_settlement(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &req,
            self.h.proposal(vec![], key, EntryClass::ORIGINAL),
            &mut budget,
        )
        .unwrap()
        .unwrap()
    }

    fn carrying(&self) -> CarryingOpenItem {
        open_item_carrying_at(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            self.target,
            0,
            self.h.db.frontier().unwrap(),
        )
        .unwrap()
        .unwrap()
    }

    fn verify(&self) {
        let cx = self.h.ctx();
        let verification = cx
            .query()
            .with_restriction(|| {
                verify_fx_conversions(&self.h.db, &cx, &self.h.book, self.h.db.frontier().unwrap())
            })
            .unwrap();
        assert!(verification.is_green(), "{:?}", verification.drift);
    }
}

fn undo(proposal: &EntryPayload, target: EntryRef, key: &[u8]) -> EntryPayload {
    let mut reversed = proposal.clone();
    reversed.class = EntryClass::REVERSAL;
    reversed.idempotency_key = key.to_vec();
    reversed.supersession = vec![Supersession {
        kind: SupersessionKind::Reverses,
        target,
        reason_code: 1,
    }];
    for leg in &mut reversed.legs {
        leg.side = leg.side.flipped();
        leg.settles.clear();
    }
    reversed.unit_totals = EntryPayload::fold_unit_totals(&reversed.legs).unwrap();
    reversed
}

#[test]
fn historical_fx_and_carrying_ignore_later_book_spec_damage() {
    let mut f = fixture(3, 10);
    let settlement = f.prepare(1, b"historical-settlement").into_proposal();
    f.h.post(request(settlement)).unwrap();
    let at = f.h.db.frontier().unwrap();
    let expected_carrying = f.carrying();
    let cx = f.h.ctx();
    let expected_verification = cx
        .query()
        .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, at))
        .unwrap();
    assert!(expected_verification.is_green());
    assert_eq!(
        expected_verification.checked.get("SettlementCarryingBasis"),
        Some(&1),
    );

    // Corrupt only a later root. Both the outer FX fold and its nested
    // source-bound carrying check must retain their selected BookSpec.
    let mut spec = fa_journal::genesis::read_book_spec(&f.h.db)
        .unwrap()
        .unwrap();
    spec.base_unit = f.foreign;
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        book_root(),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(spec.canonical_bytes().unwrap()).unwrap()),
    );
    f.h.write_raw(damage);

    assert_eq!(
        open_item_carrying_at(&f.h.db, &cx, &f.h.book, f.target, 0, at)
            .unwrap()
            .unwrap(),
        expected_carrying,
    );
    assert_eq!(
        cx.query()
            .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, at))
            .unwrap(),
        expected_verification,
    );
    let head = f.h.db.frontier().unwrap();
    assert!(
        open_item_carrying_at(&f.h.db, &cx, &f.h.book, f.target, 0, head)
            .unwrap()
            .is_err(),
    );
    assert!(
        !cx.query()
            .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, head))
            .unwrap()
            .is_green(),
    );
}

#[test]
fn historical_fx_and_carrying_reject_selected_book_context_mismatches() {
    let mut f = fixture(3, 10);
    let original = fa_journal::genesis::read_book_spec(&f.h.db)
        .unwrap()
        .unwrap();
    for mismatch in ["book", "calendar"] {
        let mut changed = original.clone();
        match mismatch {
            "book" => changed.book_id = Id128([0xbb; 16]),
            "calendar" => changed.calendar.id.push_str("-changed"),
            _ => unreachable!(),
        }
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            book_root(),
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(changed.canonical_bytes().unwrap()).unwrap()),
        );
        f.h.write_raw(damage);
        let at = f.h.db.frontier().unwrap();
        let mut restore = fgdb::WriteBatch::new(relation::IN_BOOK);
        restore.set_vertex_property(
            book_root(),
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(original.canonical_bytes().unwrap()).unwrap()),
        );
        f.h.write_raw(restore);

        let cx = f.h.ctx();
        let carrying = open_item_carrying_at(&f.h.db, &cx, &f.h.book, f.target, 0, at).unwrap_err();
        assert!(
            matches!(carrying, KernelError::Corrupt(ref reason) if reason.contains("selected root")),
            "{mismatch}: {carrying}",
        );
        let verification = cx
            .query()
            .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, at))
            .unwrap_err();
        assert!(
            matches!(verification, KernelError::Corrupt(ref reason) if reason.contains("selected root")),
            "{mismatch}: {verification}",
        );
        f.verify();
        assert_eq!(f.carrying().open_base.mantissa, 10);
    }
}

#[test]
fn foreign_partial_final_and_reversed_applications_restore_recorded_base() {
    let mut f = fixture(3, 10);
    let first = f.prepare(1, b"first");
    assert_eq!(first.base_relief().mantissa, 3);
    let proposal = first.into_proposal();
    let posted = f.h.post(request(proposal.clone())).unwrap();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (2, 7)
    );
    // The same typed request reconstructs its original prefix, even though
    // the target is now partly closed. No new amount is computed on retry.
    let retry = f.prepare(1, b"first").into_proposal();
    assert_eq!(retry, proposal);
    let before = f.h.db.frontier().unwrap();
    assert_eq!(
        f.h.post(request(retry)).unwrap().entry_ref(),
        posted.entry_ref()
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);

    let mut reverse = proposal;
    reverse.class = EntryClass::REVERSAL;
    reverse.idempotency_key = b"undo-first".to_vec();
    reverse.supersession = vec![Supersession {
        kind: SupersessionKind::Reverses,
        target: posted.entry_ref(),
        reason_code: 1,
    }];
    for leg in &mut reverse.legs {
        leg.side = leg.side.flipped();
        leg.settles.clear();
    }
    reverse.unit_totals = EntryPayload::fold_unit_totals(&reverse.legs).unwrap();
    f.h.post(request(reverse)).unwrap();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (3, 10)
    );

    for (key, expected) in [
        (b"again".as_slice(), 3),
        (b"second".as_slice(), 4),
        (b"final".as_slice(), 3),
    ] {
        let plan = f.prepare(1, key);
        assert_eq!(plan.base_relief().mantissa, expected);
        f.h.post(request(plan.into_proposal())).unwrap();
    }
    let closed = f.carrying();
    assert_eq!(
        (closed.open_native.mantissa, closed.open_base.mantissa),
        (0, 0)
    );
    assert_eq!(
        (closed.applied_native.mantissa, closed.applied_base.mantissa),
        (3, 10)
    );
    f.verify();
}

#[test]
fn zero_rounded_relief_and_final_base_remainder_post_without_a_plug() {
    let mut f = fixture(2, 1);
    let first = f.prepare(1, b"zero-relief");
    assert_eq!(first.base_relief().mantissa, 0);
    let proposal = first.into_proposal();
    assert_eq!(proposal.legs.len(), 4);
    assert!(proposal.legs.iter().all(|leg| leg.amount.mantissa > 0));
    let posted = f.h.post(request(proposal.clone())).unwrap();
    f.verify();
    f.h.post(request(undo(&proposal, posted.entry_ref(), b"undo-zero")))
        .unwrap();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (2, 1),
    );
    f.verify();
    let repeated = f.prepare(1, b"zero-again").into_proposal();
    f.h.post(request(repeated)).unwrap();
    let last = f.prepare(1, b"remainder");
    assert_eq!(last.base_relief().mantissa, 1);
    f.h.post(request(last.into_proposal())).unwrap();
    assert_eq!(f.carrying().open_base.mantissa, 0);
    f.verify();
}

#[test]
fn a_batch_of_exact_undos_restores_both_recorded_reliefs_at_one_prefix() {
    let mut f = fixture(3, 10);
    let first = f.prepare(1, b"batch-first").into_proposal();
    let first_ref = f.h.post(request(first.clone())).unwrap().entry_ref();
    let second = f.prepare(1, b"batch-second").into_proposal();
    let second_ref = f.h.post(request(second.clone())).unwrap().entry_ref();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (1, 3)
    );
    let before = f.h.db.frontier().unwrap();
    let batch = f.h.batch(
        b"undo-both",
        vec![
            undo(&second, second_ref, b"undo-batch-second"),
            undo(&first, first_ref, b"undo-batch-first"),
        ],
    );
    f.h.post_batch(batch).unwrap();
    assert_eq!(f.h.db.frontier().unwrap().0, before.0 + 1);
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (3, 10)
    );
    assert_eq!(f.prepare(1, b"after-both-undos").base_relief().mantissa, 3);
    f.verify();
}

#[test]
fn unvalued_foreign_application_cannot_bypass_the_carrying_law() {
    let mut f = fixture(3, 10);
    let amount = Amount::new(f.foreign, 1);
    let mut applying =
        LegPayload::simple(Side::Credit, account_vid(f.h.book.book_id, "1211"), amount);
    applying.settles = vec![fa_model::Settlement {
        target: f.target,
        ordinal: 0,
        amount,
    }];
    let proposal = f.h.proposal(
        vec![
            LegPayload::simple(Side::Debit, account_vid(f.h.book.book_id, "4011"), amount),
            applying,
        ],
        b"unvalued-foreign-application",
        EntryClass::ORIGINAL,
    );
    let before = f.h.db.frontier().unwrap();
    let refusal = f.h.post(request(proposal)).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert!(refusal.message.contains("RemainingCarryingValue"));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let item = f.carrying();
    assert_eq!(
        (item.open_native.mantissa, item.open_base.mantissa),
        (3, 10)
    );
}

#[test]
fn malformed_conversion_or_extra_foreign_effects_are_refused_atomically() {
    let mut f = fixture(3, 10);
    let valid = f.prepare(1, b"malformed-conversion").into_proposal();
    let mut malformed = valid.clone();
    malformed.legs[1].account_ref = malformed.legs[0].account_ref;
    let before = f.h.db.frontier().unwrap();
    let refusal = f.h.post(request(malformed)).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    let mut extra = valid;
    let mut foreign = extra.legs[0].clone();
    foreign.settles.clear();
    extra.legs.push(foreign.clone());
    foreign.side = foreign.side.flipped();
    extra.legs.push(foreign);
    extra.unit_totals = EntryPayload::fold_unit_totals(&extra.legs).unwrap();
    let totals = extra.base_totals.as_mut().unwrap();
    totals.debits += 3;
    totals.credits += 3;
    let refusal = f.h.post(request(extra)).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert_eq!(f.h.db.frontier().unwrap(), before);
}

#[test]
fn caller_supplied_balanced_false_carrying_basis_is_refused_atomically() {
    let mut f = fixture(3, 10);
    let mut proposal = f.prepare(1, b"false-basis").into_proposal();
    // Rebuild a fully balanced FX proposal using the old low-level helper,
    // with a fabricated historical basis. Shape and rate checks alone pass.
    let raw = f.h.db.vertex(document_vid(&f.rate)).unwrap().unwrap();
    let record = fa_journal::evidence::DocumentRecord::decode(
        &fa_journal::rows::bytes(&raw, property::FA_PAYLOAD, "rate").unwrap(),
    )
    .unwrap();
    let Storage::Inline(bytes) = record.storage else {
        panic!("fixture rate must be inline")
    };
    let rate = FxRateDocument::decode(&bytes).unwrap();
    let template = f.h.proposal(vec![], b"false-basis", EntryClass::ORIGINAL);
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let applications = proposal.legs[0].settles.clone();
    proposal = plan_realized_fx_settlement(
        &mut budget,
        template,
        proposal.legs[0].account_ref,
        Side::Credit,
        Amount::new(f.foreign, 1),
        Amount::new(f.h.usd, 9),
        f.h.cash,
        f.conversion,
        f.realized,
        &rate,
        vec![],
        &f.h.book.units,
    )
    .unwrap();
    proposal.legs[0].settles = applications;
    let before = f.h.db.frontier().unwrap();
    let refused = f.h.post(request(proposal)).unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert!(refused.message.contains("journal-derived"));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.carrying().open_base.mantissa, 10);
}

#[test]
fn an_intervening_post_invalidates_the_foreign_settlement_aggregate() {
    let mut f = fixture(3, 10);
    let proposal = f.prepare(1, b"racing-settlement").into_proposal();
    let ctx = f.h.ctx();
    let staged = prepare_post(&mut f.h.db, &ctx, &f.h.book, request(proposal))
        .unwrap()
        .unwrap();
    let PostPreparation::Ready(prepared) = staged else {
        panic!("new plan")
    };
    let unrelated =
        f.h.proposal(f.h.rent_legs(1), b"unrelated", EntryClass::ORIGINAL);
    f.h.post(request(unrelated)).unwrap();
    let before = f.h.db.frontier().unwrap();
    let refusal =
        f.h.runtime
            .block_on(prepared.commit(&mut f.h.db, &ctx))
            .unwrap()
            .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.carrying().open_base.mantissa, 10);
}
