//! Admission of explicit base-unit receipt/payment differences.
//!
//! This law uses only the complete proposed effects and immutable base unit.
//! The ordinary posting transaction still witnesses target identity, liveness,
//! dimensions and remaining capacity. Consequently batch, plan and draft
//! execution share the same law without an aggregate scan or a second write.

use fa_model::{ApplicationDifferenceKind, ApplicationDirection, EntryClass, EntryPayload};
use fa_money::{Amount, Side, UnitId};

use crate::refusal::{Refusal, code, exit};

fn refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::SETTLE_SHAPE,
        exit::REFUSAL,
        message,
        "plan §5.7 / Appendix B (every payment difference is explicit and reason-typed)",
        "name the actual cash, the exact amounts applied and each Discount, Writeoff or BankCharge leg in the book's base unit; a partial payment leaves the residual open, and foreign settlement uses its source-bound FX law",
    )
}

pub(crate) fn admit(proposal: &EntryPayload, base_unit: UnitId) -> Result<(), Refusal> {
    let Some(terms) = proposal
        .application_terms()
        .map_err(|error| refusal(error.to_string()))?
    else {
        return Ok(());
    };
    terms
        .validate_shape(proposal.legs.len())
        .map_err(|error| refusal(error.to_string()))?;
    // Direction describes the original payment, not the parity of a later
    // undo. exact_side_swap checks the unchanged marker and exact negation of
    // the transaction-witnessed target, including a reversal of a reversal.
    if proposal.class == EntryClass::REVERSAL {
        return Ok(());
    }
    if !matches!(proposal.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING) {
        return Err(refusal(
            "typed application differences require an Original or Adjusting posting",
        ));
    }
    if proposal.base_totals.is_some()
        || proposal
            .legs
            .iter()
            .any(|leg| leg.amount.unit != base_unit || leg.base_amount.is_some())
    {
        return Err(refusal(
            "typed application differences v1 require only the book's base unit, without FX valuations",
        ));
    }
    let cash = &proposal.legs[usize::from(terms.cash_ordinal)];
    let applying = &proposal.legs[usize::from(terms.applying_ordinal)];
    let cash_side = match terms.direction {
        ApplicationDirection::Receipt => Side::Debit,
        ApplicationDirection::Payment => Side::Credit,
    };
    if cash.side != cash_side
        || applying.side != cash_side.flipped()
        || cash.account_ref == applying.account_ref
        || !cash.settles.is_empty()
        || cash.amount.mantissa <= 0
        || applying.amount.mantissa <= 0
    {
        return Err(refusal(
            "cash and applying legs require distinct accounts, the declared receipt/payment sides and positive amounts; the cash leg carries no applications",
        ));
    }

    let mut applied = Amount::new(base_unit, 0);
    for settlement in &applying.settles {
        if settlement.amount.unit != base_unit || settlement.amount.mantissa <= 0 {
            return Err(refusal(
                "every declared application must be positive in the book's base unit",
            )
            .at("leg", usize::from(terms.applying_ordinal)));
        }
        applied = applied
            .checked_add(settlement.amount)
            .map_err(|error| refusal(format!("declared application sum: {error}")))?;
    }
    if applied != applying.amount {
        return Err(refusal(format!(
            "typed applying leg carries {} but explicitly applies {}; every unit of that leg must name its open-item target",
            applying.amount.mantissa, applied.mantissa,
        ))
        .at("leg", usize::from(terms.applying_ordinal)));
    }

    let mut reductions = Amount::new(base_unit, 0);
    let mut charges = Amount::new(base_unit, 0);
    for difference in &terms.differences {
        let ordinal = usize::from(difference.leg_ordinal);
        let leg = &proposal.legs[ordinal];
        let expected_side = match (terms.direction, difference.kind) {
            (
                ApplicationDirection::Payment,
                ApplicationDifferenceKind::Discount | ApplicationDifferenceKind::Writeoff,
            ) => Side::Credit,
            _ => Side::Debit,
        };
        if leg.side != expected_side
            || leg.account_ref == cash.account_ref
            || leg.account_ref == applying.account_ref
            || !leg.settles.is_empty()
            || leg.amount.mantissa <= 0
        {
            return Err(refusal(format!(
                "{} leg {ordinal} has the wrong side/account or carries applications: a {} needs explicit positive difference legs on their own accounts",
                difference.kind.name(), terms.direction.name(),
            ))
            .at("leg", ordinal)
            .at("kind", difference.kind.name()));
        }
        let total = if difference.kind == ApplicationDifferenceKind::BankCharge {
            &mut charges
        } else {
            &mut reductions
        };
        *total = total
            .checked_add(leg.amount)
            .map_err(|error| refusal(format!("typed difference sum: {error}")))?;
    }
    let before_charges = cash
        .amount
        .checked_add(reductions)
        .map_err(|error| refusal(format!("cash plus declared reductions: {error}")))?;
    let expected = match terms.direction {
        ApplicationDirection::Receipt => before_charges.checked_add(charges),
        ApplicationDirection::Payment => before_charges.checked_sub(charges),
    }
    .map_err(|error| refusal(format!("cash/difference equation: {error}")))?;
    if expected.mantissa <= 0 || expected != applying.amount {
        return Err(refusal(format!(
            "{} cash {} with declared reductions {} and bank charges {} requires an applied amount of {}, not {}; no unexplained difference may close the open items",
            terms.direction.name(), cash.amount.mantissa, reductions.mantissa,
            charges.mantissa, expected.mantissa, applying.amount.mantissa,
        ))
        .at("leg", usize::from(terms.applying_ordinal)));
    }
    Ok(())
}
