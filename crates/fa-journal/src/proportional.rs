//! A named, replayed native proportional sub-vector of an authenticated hold.
//!
//! The factory prepares ordinary Resolution(Posts) legs. It is not an
//! admission token: the posting kernel independently derives the same
//! vector after verifying the pending EntryRef inside its transaction.
//! Existing valuation, dimensions, periods, expiry and reservation-release
//! checks continue to judge the result through the ordinary posting path.

use fa_model::{
    Disposition, EntryClass, EntryPayload, LegPayload, ProportionalPostBasis, entity_value_vid,
};
use fa_money::proportional_post::{
    HeldLeg, MAX_PROPORTIONAL_POST_RATE_BYTES, ProportionalPostLaw, ProportionalPostOutcome,
    ProportionalPostRequest,
};
use fa_money::{ArithmeticBudget, Rate, UnitRegistry};

use crate::entity::{LegEntityError, leg_entities};
use crate::genesis::BookSpec;
use crate::refusal::{Refusal, code, exit};

pub use fa_model::entry::{PROPORTIONAL_POST_EXTENSION, PROPORTIONAL_POST_SCHEMA_MINOR};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedProportionalPost {
    pub legs: Vec<LegPayload>,
    pub source_ordinals: Vec<u16>,
    pub extension_bytes: Vec<u8>,
    /// Every original leg's posted/released amounts, including omitted zeros.
    pub outcome: ProportionalPostOutcome,
}

/// Derive from a caller-selected pending payload without storage reads.
/// The kernel later authenticates that exact payload via `resolution_of`.
/// This also supports a hold staged earlier in the same atomic batch.
pub fn prepare_proportional_post(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    spec: &BookSpec,
    units: &UnitRegistry,
    hold: &EntryPayload,
    law: ProportionalPostLaw,
    rate: &Rate,
) -> Result<PreparedProportionalPost, Refusal> {
    let rate_size = usize::try_from(rate.numerator().bits().div_ceil(8))
        .ok()
        .zip(usize::try_from(rate.denominator().bits().div_ceil(8)).ok())
        .and_then(|(numerator, denominator)| numerator.checked_add(denominator))
        .and_then(|length| length.checked_add(12));
    if rate_size.is_none_or(|length| length > MAX_PROPORTIONAL_POST_RATE_BYTES) {
        return Err(refusal(
            "the exact rate exceeds the proportional-post byte bound",
        ));
    }
    let rate_bytes = rate.encode(budget).map_err(refusal)?;
    hold.validate().map_err(refusal)?;
    if hold.class != EntryClass::PENDING || hold.book_id != spec.book_id {
        return Err(refusal(
            "the proportional source must be a Pending entry in this book",
        ));
    }
    if hold.base_totals.is_some() || hold.legs.iter().any(|leg| leg.base_amount.is_some()) {
        return Err(refusal(
            "a base-valued hold requires an explicit valued resolution; the native proportional law cannot invent or copy a new FX valuation",
        ));
    }
    if hold.legs.iter().any(|leg| {
        units
            .get(leg.amount.unit)
            .is_none_or(|unit| unit.allows_single_sided())
    }) {
        return Err(refusal(
            "proportional holds require registered balanced units, not single-sided statistical quantities",
        ));
    }
    let entities = leg_entities(spec, &hold.legs).map_err(|error| match error {
        LegEntityError::Refused(error) => error,
        LegEntityError::OtherDimension => refusal("the pending entry has an unsupported dimension"),
    })?;
    let legs = hold
        .legs
        .iter()
        .zip(entities)
        .enumerate()
        .map(|(index, (leg, entity))| {
            Ok(HeldLeg {
                source_ordinal: u16::try_from(index).map_err(refusal)?,
                amount: leg.amount,
                side: leg.side,
                legal_entity: entity.map(|code| entity_value_vid(spec.book_id, &code).0),
            })
        })
        .collect::<Result<Vec<_>, Refusal>>()?;
    let outcome = ProportionalPostRequest {
        law,
        rate: rate.clone(),
        legs,
    }
    .execute(budget)
    .map_err(refusal)?;
    let mut source_ordinals = Vec::new();
    let mut posted = Vec::new();
    for row in outcome.posted_legs() {
        let source = &hold.legs[usize::from(row.source_ordinal)];
        let mut leg = LegPayload::simple(source.side, source.account_ref, row.posted);
        leg.dimension_set = source.dimension_set.clone();
        leg.memo = source.memo.clone();
        source_ordinals.push(row.source_ordinal);
        posted.push(leg);
    }
    let basis = ProportionalPostBasis { law, rate_bytes };
    Ok(PreparedProportionalPost {
        legs: posted,
        source_ordinals,
        extension_bytes: basis.encode().map_err(refusal)?,
        outcome,
    })
}

/// A valid outer entry digest and balanced totals are insufficient. The
/// witness must reproduce every selected source ordinal and native amount.
pub(crate) fn verify_proportional_post(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    spec: &BookSpec,
    units: &UnitRegistry,
    hold: &EntryPayload,
    proposal: &EntryPayload,
) -> Result<(), Refusal> {
    let Some((_, bytes)) = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == PROPORTIONAL_POST_EXTENSION)
    else {
        return Ok(());
    };
    let basis = ProportionalPostBasis::decode(bytes).map_err(refusal)?;
    let rate = Rate::decode(budget, &basis.rate_bytes).map_err(refusal)?;
    let expected = prepare_proportional_post(budget, spec, units, hold, basis.law, &rate)?;
    let Some(Disposition::Posts { source_ordinals }) = proposal
        .pending
        .as_ref()
        .and_then(|pending| pending.disposition.as_ref())
    else {
        return Err(refusal(
            "the proportional basis belongs only to Resolution(Posts)",
        ));
    };
    if *source_ordinals != expected.source_ordinals
        || proposal.legs.len() != expected.legs.len()
        || proposal
            .legs
            .iter()
            .zip(&expected.legs)
            .any(|(actual, expected)| {
                actual.account_ref != expected.account_ref
                    || actual.side != expected.side
                    || actual.amount != expected.amount
                    || actual.dimension_set != expected.dimension_set
            })
        || *bytes != expected.extension_bytes
    {
        return Err(refusal(
            "the posted sub-vector or source ordinals do not reproduce the registered proportional law and exact rate on the authenticated pending entry",
        ));
    }
    Ok(())
}

pub fn refusal(error: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::RESOLUTION_SHAPE,
        exit::REFUSAL,
        format!("proportional hold posting: {error}"),
        "plan §5.4 (named balanced proportional sub-vector with explicit release)",
        "derive the vector from the original hold under BalancedLargestRemainder and an exact rate in [0,1]; use VoidReserve for an empty result, or an explicit valued resolution for a base-valued hold",
    )
}
