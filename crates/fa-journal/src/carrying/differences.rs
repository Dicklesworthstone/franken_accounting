//! The explicit version-2 cash/difference profile of the carrying laws.
//! Retained source relief and the Settlement quote remain independent inputs;
//! a fee or discount never becomes a caller-authored realized-FX plug.

use super::*;
use fa_model::{
    ApplicationDifference, ApplicationDifferenceKind, FxSettlementComponent, FxSettlementTerms,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementDifference {
    pub kind: ApplicationDifferenceKind,
    pub account: VId,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementWithDifferencesRequest {
    /// `settlement_amount` is the actual cash received or paid, in base units.
    pub settlement: FxSettlementRequest,
    pub differences: Vec<FxSettlementDifference>,
}

pub(super) fn validate_request_differences(
    request: &FxSettlementRequest,
    differences: &[FxSettlementDifference],
) -> Result<(), Refusal> {
    if differences.len() > fa_model::application::MAX_APPLICATION_DIFFERENCES {
        return Err(invalid(
            "at most 128 explicit FX difference pairs per entry",
        ));
    }
    if differences.is_empty() {
        return Ok(());
    }
    if request.amount.mantissa <= 0 || request.settlement_amount.mantissa <= 0 {
        return Err(invalid(
            "FX settlement requires positive applied and actual cash amounts",
        ));
    }
    for difference in differences {
        if difference.amount.unit != request.settlement_amount.unit
            || difference.amount.mantissa <= 0
            || [
                request.settlement_account,
                request.conversion_account,
                request.realized_fx_account,
            ]
            .contains(&difference.account)
        {
            return Err(invalid(
                "FX differences require positive base-unit amounts on accounts distinct from cash, conversion and realized FX",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_group_differences(
    requests: &[FxSettlementRequest],
    differences: &[Vec<FxSettlementDifference>],
) -> Result<(), Refusal> {
    if !differences.is_empty() && differences.len() != requests.len() {
        return Err(invalid(
            "every requested FX component must have its own explicit difference list",
        ));
    }
    let mut total = 0usize;
    for (request, differences) in requests.iter().zip(differences) {
        validate_request_differences(request, differences)?;
        total = total
            .checked_add(differences.len())
            .ok_or_else(|| invalid("FX difference count overflow"))?;
        if total > fa_model::application::MAX_APPLICATION_DIFFERENCES {
            return Err(invalid(
                "at most 128 explicit FX difference pairs per entry",
            ));
        }
    }
    Ok(())
}

fn split_requests(
    requests: &[FxSettlementWithDifferencesRequest],
) -> Result<(Vec<FxSettlementRequest>, Vec<Vec<FxSettlementDifference>>), Refusal> {
    if requests.is_empty() || requests.len() > MAX_FX_SETTLEMENT_ITEMS {
        return Err(invalid(
            "FX settlement group requires a bounded nonempty list of items",
        ));
    }
    let mut total = 0usize;
    for request in requests {
        validate_request_differences(&request.settlement, &request.differences)?;
        total = total
            .checked_add(request.differences.len())
            .ok_or_else(|| invalid("FX difference count overflow"))?;
        if total > fa_model::application::MAX_APPLICATION_DIFFERENCES {
            return Err(invalid(
                "at most 128 explicit FX difference pairs per entry",
            ));
        }
    }
    Ok((
        requests
            .iter()
            .map(|request| request.settlement.clone())
            .collect(),
        requests
            .iter()
            .map(|request| request.differences.clone())
            .collect(),
    ))
}

pub fn prepare_fx_settlement_with_differences<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: &FxSettlementWithDifferencesRequest,
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxSettlement> {
    if request.differences.is_empty() {
        return prepare_fx_settlement(
            db,
            cx,
            book,
            capability,
            &request.settlement,
            template,
            budget,
        );
    }
    cx.query().with_restriction(|| {
        let mut audits = SuccessfulHistoryAudits::default();
        let prepared = match prepare_fx_settlement_inner(
            db,
            cx,
            book,
            capability,
            None,
            &request.settlement,
            &request.differences,
            template,
            budget,
            Some(&mut audits),
        )? {
            Ok(value) => value,
            Err(refusal) => return Ok(Err(refusal)),
        };
        audits.verify_entry_prefix(db, cx, book, prepared.carrying.known_at)?;
        Ok(Ok(prepared))
    })
}

pub fn prepare_fx_settlement_group_with_differences<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    requests: &[FxSettlementWithDifferencesRequest],
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxSettlementGroup> {
    let (requests, differences) = match split_requests(requests) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    prepare_fx_settlement_group_with_admission(
        db,
        cx,
        book,
        capability,
        None,
        &requests,
        &differences,
        template,
        budget,
    )
}

pub fn admit_draft_settlement_requests_with_differences<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    requests: &[FxSettlementWithDifferencesRequest],
    template: &EntryPayload,
) -> Outcome<()> {
    let (requests, differences) = match split_requests(requests) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    admit_draft_settlement_requests_inner(
        db,
        cx,
        book,
        admission,
        &requests,
        &differences,
        template,
    )
}

pub fn prepare_fx_settlement_with_differences_in_draft<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    request: &FxSettlementWithDifferencesRequest,
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<EntryPayload> {
    prepare_fx_settlement_group_with_differences_in_draft(
        db,
        cx,
        book,
        admission,
        std::slice::from_ref(request),
        template,
        budget,
    )
}

pub fn prepare_fx_settlement_group_with_differences_in_draft<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    requests: &[FxSettlementWithDifferencesRequest],
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<EntryPayload> {
    let (requests, differences) = match split_requests(requests) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = admit_draft_settlement_requests_inner(
        db,
        cx,
        book,
        admission,
        &requests,
        &differences,
        &template,
    )? {
        return Ok(Err(refusal));
    }
    let prepared = match prepare_fx_settlement_group_with_admission(
        db,
        cx,
        book,
        admission.capability(),
        Some(admission),
        &requests,
        &differences,
        template,
        budget,
    )? {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let proposal = prepared.into_proposal();
    Ok(admission
        .admit_derived_proposal(db, book, &proposal)?
        .map(|()| proposal))
}

fn difference_side(applying_side: Side, kind: ApplicationDifferenceKind) -> Side {
    if applying_side == Side::Debit && kind != ApplicationDifferenceKind::BankCharge {
        Side::Credit
    } else {
        Side::Debit
    }
}

fn quote(
    cash: Amount,
    applying_side: Side,
    differences: impl Iterator<Item = (ApplicationDifferenceKind, Amount)>,
) -> Result<Amount, Refusal> {
    let mut reductions = Amount::new(cash.unit, 0);
    let mut charges = Amount::new(cash.unit, 0);
    for (kind, amount) in differences {
        if amount.unit != cash.unit || amount.mantissa <= 0 {
            return Err(invalid(
                "every FX difference must be positive and in the functional base unit",
            ));
        }
        let total = if kind == ApplicationDifferenceKind::BankCharge {
            &mut charges
        } else {
            &mut reductions
        };
        *total = total.checked_add(amount).map_err(invalid)?;
    }
    let before_charges = cash.checked_add(reductions).map_err(invalid)?;
    let quote = if applying_side == Side::Credit {
        before_charges.checked_add(charges)
    } else {
        before_charges.checked_sub(charges)
    }
    .map_err(invalid)?;
    if cash.mantissa <= 0 || quote.mantissa <= 0 {
        return Err(invalid(
            "actual cash and gross Settlement consideration must both be positive",
        ));
    }
    Ok(quote)
}

fn base_leg(source: &LegPayload, side: Side, account: VId, amount: Amount) -> LegPayload {
    let mut leg = LegPayload::simple(side, account, amount);
    leg.base_amount = Some(amount);
    leg.dimension_set = source.dimension_set.clone();
    leg
}

pub(super) fn apply(
    proposal: &mut EntryPayload,
    request: &FxSettlementRequest,
    differences: &[FxSettlementDifference],
    historical: Amount,
    quoted: Amount,
) -> Result<(), Refusal> {
    if differences.is_empty() {
        return Ok(());
    }
    validate_request_differences(request, differences)?;
    let source = proposal
        .legs
        .first()
        .cloned()
        .ok_or_else(|| invalid("settlement source is absent"))?;
    if request.settlement_amount.unit != historical.unit
        || quote(
            request.settlement_amount,
            source.side,
            differences
                .iter()
                .map(|difference| (difference.kind, difference.amount)),
        )? != quoted
    {
        return Err(invalid(
            "actual cash and every explicit difference must reproduce the retained gross Settlement quote exactly",
        ));
    }
    if differences
        .iter()
        .any(|difference| difference.account == source.account_ref)
    {
        return Err(invalid(
            "FX differences cannot post to their source open-item account",
        ));
    }
    let conversion = proposal
        .legs
        .get(1)
        .cloned()
        .ok_or_else(|| invalid("foreign conversion is absent"))?;
    let mut legs = vec![source.clone(), conversion];
    let mut push_pair = |side, account, amount| {
        legs.push(base_leg(&source, side, account, amount));
        legs.push(base_leg(
            &source,
            side.flipped(),
            request.conversion_account,
            amount,
        ));
    };
    push_pair(
        source.side.flipped(),
        request.settlement_account,
        request.settlement_amount,
    );
    let delta = quoted
        .mantissa
        .checked_sub(historical.mantissa)
        .ok_or_else(|| invalid("realized FX difference overflow"))?;
    if delta != 0 {
        let side = if delta > 0 {
            source.side
        } else {
            source.side.flipped()
        };
        push_pair(
            side,
            request.realized_fx_account,
            Amount::new(
                historical.unit,
                delta
                    .checked_abs()
                    .ok_or_else(|| invalid("realized FX magnitude overflow"))?,
            ),
        );
    }
    let mut bindings = Vec::with_capacity(differences.len());
    for difference in differences {
        let ordinal =
            u16::try_from(legs.len()).map_err(|_| invalid("FX difference ordinal overflow"))?;
        bindings.push(ApplicationDifference {
            leg_ordinal: ordinal,
            kind: difference.kind,
        });
        let side = difference_side(source.side, difference.kind);
        legs.push(base_leg(
            &source,
            side,
            difference.account,
            difference.amount,
        ));
        legs.push(base_leg(
            &source,
            side.flipped(),
            request.conversion_account,
            difference.amount,
        ));
    }
    proposal.legs = legs;
    proposal
        .set_fx_settlement_terms(&FxSettlementTerms {
            components: vec![FxSettlementComponent {
                applying_ordinal: 0,
                differences: bindings,
            }],
        })
        .map_err(invalid)?;
    recompute_totals(proposal)?;
    proposal.validate().map_err(invalid)
}

pub(super) fn recompute_totals(proposal: &mut EntryPayload) -> Result<(), Refusal> {
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).map_err(invalid)?;
    let totals = proposal
        .base_totals
        .as_mut()
        .ok_or_else(|| invalid("FX settlement has no functional totals"))?;
    totals.debits = 0;
    totals.credits = 0;
    for leg in &proposal.legs {
        let amount = leg
            .base_amount
            .ok_or_else(|| invalid("FX settlement has an unvalued leg"))?;
        let total = if leg.side == Side::Debit {
            &mut totals.debits
        } else {
            &mut totals.credits
        };
        *total = total
            .checked_add(amount.mantissa)
            .ok_or_else(|| invalid("FX settlement total overflow"))?;
    }
    Ok(())
}

pub(crate) fn bound_terms(
    proposal: &EntryPayload,
    ranges: &[core::ops::Range<usize>],
) -> Result<Option<FxSettlementTerms>, Refusal> {
    let terms = proposal.fx_settlement_terms().map_err(invalid)?;
    if let Some(terms) = &terms {
        terms.validate_shape(proposal.legs.len()).map_err(invalid)?;
        for component in &terms.components {
            let start = usize::from(component.applying_ordinal);
            let Ok(index) = ranges.binary_search_by_key(&start, |range| range.start) else {
                return Err(invalid(
                    "FX difference marker does not identify a real applied source component",
                ));
            };
            let range = &ranges[index];
            if component
                .differences
                .iter()
                .any(|difference| usize::from(difference.leg_ordinal) + 1 >= range.end)
            {
                return Err(invalid(
                    "FX difference pair lies outside its applied source component",
                ));
            }
        }
    }
    Ok(terms)
}

pub(super) fn quoted_effects(
    legs: &[LegPayload],
    component: &FxSettlementComponent,
) -> Result<Amount, Refusal> {
    let start = usize::from(component.applying_ordinal);
    let source = legs
        .first()
        .ok_or_else(|| invalid("FX settlement source is absent"))?;
    let cash = legs
        .get(2)
        .ok_or_else(|| invalid("FX settlement cash is absent"))?;
    let mut values = Vec::with_capacity(component.differences.len());
    for difference in &component.differences {
        let ordinal = usize::from(difference.leg_ordinal)
            .checked_sub(start)
            .ok_or_else(|| invalid("FX difference ordinal precedes its source"))?;
        let leg = legs
            .get(ordinal)
            .ok_or_else(|| invalid("FX difference leg is absent"))?;
        values.push((difference.kind, leg.amount));
    }
    quote(cash.amount, source.side, values.into_iter())
}

/// Check every leg against independently derived historical relief and gross
/// quote. No search for a plausible conversion subset can hide extra effects.
pub(crate) fn check_component(
    legs: &[LegPayload],
    component: &FxSettlementComponent,
    historical: Amount,
    quoted: Amount,
) -> Result<(), Refusal> {
    if legs.len() < 6 || component.differences.is_empty() {
        return Err(invalid(
            "explicit FX differences require their complete paired component",
        ));
    }
    let source = &legs[0];
    let foreign_conversion = &legs[1];
    let cash = &legs[2];
    if historical.mantissa < 0
        || quoted.unit != historical.unit
        || quoted.mantissa <= 0
        || source.amount.unit == historical.unit
        || source.amount.mantissa <= 0
        || source.base_amount != Some(historical)
        || source.settles.len() != 1
        || source.settles[0].amount != source.amount
        || foreign_conversion.side != source.side.flipped()
        || foreign_conversion.amount != source.amount
        || foreign_conversion.base_amount != Some(historical)
        || cash.side != source.side.flipped()
        || cash.amount.unit != historical.unit
        || cash.amount.mantissa <= 0
        || BTreeSet::from([
            source.account_ref,
            foreign_conversion.account_ref,
            cash.account_ref,
        ])
        .len()
            != 3
        || legs
            .iter()
            .any(|leg| leg.dimension_set != source.dimension_set)
        || legs.iter().skip(1).any(|leg| !leg.settles.is_empty())
    {
        return Err(invalid(
            "FX net-cash core does not reproduce its applied source, historical relief, exact dimensions and distinct routes",
        ));
    }
    let conversion_account = foreign_conversion.account_ref;
    let pair = |ordinal: usize, side: Side, amount: Amount| -> Result<(), Refusal> {
        let economic = legs
            .get(ordinal)
            .ok_or_else(|| invalid("FX economic leg is absent"))?;
        let conversion = legs
            .get(ordinal + 1)
            .ok_or_else(|| invalid("FX conversion pair is absent"))?;
        if amount.unit != historical.unit
            || amount.mantissa <= 0
            || economic.side != side
            || economic.amount != amount
            || economic.base_amount != Some(amount)
            || conversion.account_ref != conversion_account
            || conversion.side != side.flipped()
            || conversion.amount != amount
            || conversion.base_amount != Some(amount)
        {
            return Err(invalid(
                "FX effect differs from its exact positive at-par conversion pair",
            ));
        }
        Ok(())
    };
    pair(2, source.side.flipped(), cash.amount)?;
    let delta = quoted
        .mantissa
        .checked_sub(historical.mantissa)
        .ok_or_else(|| invalid("realized FX difference overflow"))?;
    let mut cursor = 4usize;
    let mut protected = BTreeSet::from([source.account_ref, conversion_account, cash.account_ref]);
    if delta != 0 {
        let realized = legs
            .get(cursor)
            .ok_or_else(|| invalid("derived realized FX pair is absent"))?;
        if !protected.insert(realized.account_ref) {
            return Err(invalid("derived realized FX requires its own account"));
        }
        pair(
            cursor,
            if delta > 0 {
                source.side
            } else {
                source.side.flipped()
            },
            Amount::new(
                historical.unit,
                delta
                    .checked_abs()
                    .ok_or_else(|| invalid("realized FX magnitude overflow"))?,
            ),
        )?;
        cursor += 2;
    }
    for difference in &component.differences {
        if usize::from(difference.leg_ordinal) != usize::from(component.applying_ordinal) + cursor {
            return Err(invalid(
                "FX differences must identify every remaining economic pair in exact order",
            ));
        }
        let economic = legs
            .get(cursor)
            .ok_or_else(|| invalid("explicit FX difference is absent"))?;
        if protected.contains(&economic.account_ref) {
            return Err(invalid(
                "explicit FX differences require accounts distinct from source, cash, conversion and realized FX",
            ));
        }
        pair(
            cursor,
            difference_side(source.side, difference.kind),
            economic.amount,
        )?;
        cursor += 2;
    }
    if cursor != legs.len() || quoted_effects(legs, component)? != quoted {
        return Err(invalid(
            "actual cash and every typed difference must exactly reproduce gross quote; no undeclared effect remains",
        ));
    }
    Ok(())
}

pub(super) fn rebase(
    component: &mut FxSettlementComponent,
    old_start: usize,
    new_start: usize,
) -> Result<(), Refusal> {
    let ordinal = |value: u16| -> Result<u16, Refusal> {
        usize::from(value)
            .checked_sub(old_start)
            .and_then(|offset| new_start.checked_add(offset))
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid("FX component ordinal overflow"))
    };
    component.applying_ordinal = ordinal(component.applying_ordinal)?;
    for difference in &mut component.differences {
        difference.leg_ordinal = ordinal(difference.leg_ordinal)?;
    }
    Ok(())
}
