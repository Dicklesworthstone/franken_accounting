//! Complete item-population proof for the explicit allocated revaluation law.
//! The original source account still carries historical cost. Allocation acts
//! on the closing target, then records each difference on its dedicated contra.

use super::*;
use fa_model::{EntryRef, FxItemRevaluationBasis, FxRevaluationItem, SupersessionKind};
use std::collections::BTreeSet;

// These are the exact source coordinates and checked totals already computed
// by observe; passing them explicitly avoids a second, potentially different fold.
#[allow(clippy::too_many_arguments)]
pub(super) fn population<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &FxRevaluationRequest,
    spec: &BookSpec,
    route: &FxRevaluationRoute,
    at: CommitSeq,
    date: DateDay,
    entity: Option<VId>,
    entries: &[(CommitSeq, VId, Entry)],
    native: i128,
    historical: i128,
    valuation: i128,
    target: i128,
) -> Outcome<(
    Option<FxItemRevaluationBasis>,
    Vec<LegPayload>,
    Option<BaseTotals>,
)> {
    let mut reversals = BTreeMap::new();
    let by_id: BTreeMap<_, _> = entries
        .iter()
        .map(|(_, vid, entry)| (*vid, entry))
        .collect();
    for (_, vid, entry) in entries {
        if entry.proposal.class == EntryClass::REVERSAL {
            let [link] = entry.proposal.supersession.as_slice() else {
                return Ok(Err(invalid("item population has an ambiguous reversal")));
            };
            let Some(original) = by_id.get(&link.target.vid) else {
                return Ok(Err(invalid(
                    "item reversal target is outside its effective source population",
                )));
            };
            if link.kind != SupersessionKind::Reverses
                || original.entry_digest != link.target.entry_digest
                || !crate::post::exact_side_swap(&original.proposal, &entry.proposal)
                || reversals.insert(link.target.vid, *vid).is_some()
            {
                return Ok(Err(invalid(
                    "item population contains an invalid exact reversal",
                )));
            }
        }
    }
    let mut sources = BTreeMap::new();
    for (_, vid, entry) in entries {
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            if leg.account_ref != request.source_account
                || item_entity(spec, leg).map_err(|error| KernelError::Corrupt(error.message))?
                    != entity
            {
                continue;
            }
            if entry.proposal.class == EntryClass::REVERSAL {
                continue;
            }
            if !leg.settles.is_empty() {
                if !crate::carrying::is_source_bound(&entry.proposal) {
                    return Ok(Err(unsupported(
                        "the source contains an application without a recorded carrying law",
                    )));
                }
                continue;
            }
            if !entry.proposal.class.carries_open_items()
                || entry.proposal.base_totals.as_ref().is_none_or(|total| {
                    !matches!(
                        FxLawId::from_oid(&total.fx_law_oid),
                        Some(FxLawId::SpotClose | FxLawId::PeriodAverage)
                    )
                })
            {
                return Ok(Err(unsupported(
                    "the complete source population is not composed of valued original open items and their authenticated applications/undos",
                )));
            }
            if crate::carrying::live(*vid, &reversals)? {
                sources.insert(
                    (*vid, ordinal as u16),
                    EntryRef {
                        vid: *vid,
                        entry_digest: entry.entry_digest,
                    },
                );
            }
        }
    }
    let mut carrying = Vec::new();
    let mut sides = BTreeSet::new();
    let mut native_sum = 0;
    let mut historical_sum = 0;
    let mut valuation_sum = 0;
    for ((_, ordinal), reference) in sources {
        let item = match crate::carrying::open_item_carrying_inner(
            db, cx, book, reference, ordinal, at,
        )? {
            Ok(item) => item,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if item.latest_effective_date > date {
            return Ok(Err(unsupported(
                "item revaluation would precede an already recorded application, undo, or allocation; use a period ending no earlier than those effects",
            )));
        }
        if item.valuation_route.is_some_and(|prior| prior != *route) {
            return Ok(Err(unsupported(
                "the source's allocated valuation route has changed",
            )));
        }
        if item.open_native.mantissa == 0 {
            if item.historical_open_base.mantissa != 0 || item.valuation_open_base.mantissa != 0 {
                return Ok(Err(invalid(
                    "a closed item retains an unexplained historical or valuation balance",
                )));
            }
            continue;
        }
        sides.insert(item.side == Side::Debit);
        for (sum, amount) in [
            (&mut native_sum, item.open_native.mantissa),
            (&mut historical_sum, item.historical_open_base.mantissa),
            (&mut valuation_sum, item.valuation_open_base.mantissa),
        ] {
            if let Err(refusal) = add_component(sum, item.side, amount) {
                return Ok(Err(refusal));
            }
        }
        carrying.push(item);
    }
    if sides.len() > 1
        || (native_sum, historical_sum, valuation_sum) != (native, historical, valuation)
    {
        return Ok(Err(unsupported(
            "allocated revaluation requires a complete same-sided item population exactly reproducing the source and valuation accounts",
        )));
    }
    if carrying.len() > fa_model::limits::MAX_LEGS_PER_ENTRY / 2 {
        return Ok(Err(unsupported(
            "complete item population exceeds the registered per-entry leg bound",
        )));
    }
    if carrying.is_empty() {
        return Ok(Ok((None, Vec::new(), None)));
    }
    let magnitude = match target.checked_abs() {
        Some(value) => value,
        None => return Ok(Err(invalid("allocated closing target magnitude overflow"))),
    };
    let weights: Vec<_> = carrying
        .iter()
        .map(|item| item.open_native.mantissa as u128)
        .collect();
    let shares = match fa_money::allocation::largest_remainder(
        Amount::new(spec.base_unit, magnitude),
        &weights,
    ) {
        Ok(shares) => shares,
        Err(error) => return Ok(Err(invalid(error))),
    };
    let mut items = Vec::new();
    let mut legs = Vec::new();
    let mut gross = 0i128;
    for (item, target_base) in carrying.into_iter().zip(shares) {
        let delta = target_base
            .checked_sub(item.open_base)
            .map_err(|error| KernelError::Corrupt(error.to_string()))?;
        if delta.mantissa != 0 {
            let magnitude = delta
                .mantissa
                .checked_abs()
                .ok_or_else(|| KernelError::Corrupt("item adjustment magnitude overflow".into()))?;
            let Some(next_gross) = gross.checked_add(magnitude) else {
                return Ok(Err(invalid("item revaluation gross total overflow")));
            };
            gross = next_gross;
            let side = if delta.mantissa > 0 {
                item.side
            } else {
                item.side.flipped()
            };
            let amount = Amount::new(spec.base_unit, magnitude);
            for (account, side) in [
                (route.valuation_account, side),
                (route.unrealized_account, side.flipped()),
            ] {
                let mut leg = LegPayload::simple(side, account, amount);
                leg.base_amount = Some(amount);
                leg.dimension_set = item.dimensions.clone();
                legs.push(leg);
            }
        }
        items.push(FxRevaluationItem {
            target: item.target,
            ordinal: item.ordinal,
            open_native: item.open_native,
            historical_base: item.historical_open_base,
            prior_valuation: item.valuation_open_base,
            target_base,
        });
    }
    let totals = (!legs.is_empty()).then_some(BaseTotals {
        unit_id: spec.base_unit.0,
        debits: gross,
        credits: gross,
        fx_law_oid: FxLawId::PeriodEndItemRevaluation.oid(),
        rate_doc_oids: vec![request.rate_document],
        residual: None,
    });
    Ok(Ok((
        Some(FxItemRevaluationBasis {
            allocation_law: 1,
            allocation_version: 1,
            items,
        }),
        legs,
        totals,
    )))
}

pub(super) fn recognized_release<V: Vfs + Clone>(
    db: &Database<V>,
    at: CommitSeq,
    entry: &Entry,
    source: VId,
    route: &FxRevaluationRoute,
) -> Outcome<()> {
    let mut original = entry.clone();
    let mut seen = BTreeSet::new();
    while original.proposal.class == EntryClass::REVERSAL {
        let [link] = original.proposal.supersession.as_slice() else {
            return Ok(Err(invalid(
                "valuation release reversal has an ambiguous target",
            )));
        };
        if link.kind != SupersessionKind::Reverses || !seen.insert(link.target.vid) {
            return Ok(Err(invalid("valuation release reversal lineage cycles")));
        }
        let Some((parent, _)) = crate::post::read_entry_at(db, link.target.vid, at)? else {
            return Ok(Err(invalid("valuation release reversal target is missing")));
        };
        if parent.entry_digest != link.target.entry_digest
            || !crate::post::exact_side_swap(&parent.proposal, &original.proposal)
        {
            return Ok(Err(invalid(
                "valuation release reversal differs from its recorded target",
            )));
        }
        original = parent;
    }
    let basis = match crate::carrying::allocated_basis(&original.proposal) {
        Ok(basis) => basis,
        Err(refusal) => return Ok(Err(refusal)),
    };
    for release in &basis.items {
        let Some(applying) = original
            .proposal
            .legs
            .get(usize::from(release.applying_ordinal))
        else {
            return Ok(Err(invalid(
                "valuation release applying ordinal is missing",
            )));
        };
        if release.valuation_account == route.valuation_account {
            if applying.account_ref != source
                || release.unrealized_account != route.unrealized_account
            {
                return Ok(Err(invalid(
                    "valuation release differs from the source's dedicated route",
                )));
            }
            if let Err(refusal) =
                crate::carrying::check_allocated_release(&original.proposal, release)
            {
                return Ok(Err(refusal));
            }
        }
    }
    if let Err(refusal) =
        crate::carrying::covers_valuation_account(&original.proposal, source, route)
    {
        return Ok(Err(refusal));
    }
    Ok(Ok(()))
}
