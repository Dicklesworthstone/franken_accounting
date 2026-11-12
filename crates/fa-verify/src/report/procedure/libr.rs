//! Lowest intermediate balance tracing, independently over authenticated facts.
//!
//! This reproduces the registered one-account v2 calculation, including its
//! source-selected native unit/entity, signed overdrafts, declared intraday
//! ordering and evidence-linked replenishment. It establishes neither legal
//! entitlement nor the economic truth of a cited document.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_CITES, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};

pub(super) const DEFAULTS: [(&str, u32); 2] = [("intraday_order", 0), ("replenishment", 0)];
pub(super) const INPUTS: [(&str, &str); 2] = [("account", "account"), ("source", "entry")];

fn profile(message: &str) -> ReportError {
    failed("procedure_profile", message)
}

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "LIBR movement or balance exceeds exact i128 arithmetic",
    )
}

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(2, 20, "procedure.parameters")? != 2 {
        return Err(profile("LIBR requires both explicit tracing parameters"));
    }
    let mut parameters = [0u32; 2];
    for (index, (name, _)) in DEFAULTS.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(profile(
                "LIBR parameters must be unique and lexically ordered",
            ));
        }
        parameters[index] = u32::try_from(reader.i128("procedure.parameter_value")?)
            .map_err(|_| profile("LIBR parameter is outside its unsigned range"))?;
    }
    if !matches!(parameters[0], 0 | 2 | 3) || parameters[1] > 1 {
        return Err(profile(
            "LIBR supports intraday_order 0, 2 or 3 and replenishment 0 or 1",
        ));
    }
    if reader.count(2, 8, "procedure.inputs")? != 2 {
        return Err(profile(
            "LIBR requires its account and source entry handles",
        ));
    }
    let mut handles = [0u128; 2];
    for (index, (name, _)) in INPUTS.iter().enumerate() {
        if text(reader, 64, "procedure.input_name")? != *name {
            return Err(profile("LIBR handles must be unique and lexically ordered"));
        }
        let value = text(reader, 32, "procedure.input_handle")?;
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(profile(
                "LIBR handles require exactly 32 lowercase hex digits",
            ));
        }
        handles[index] = u128::from_str_radix(value, 16)
            .map_err(|_| profile("LIBR handle exceeds its identity bound"))?;
    }
    Ok(VerifiedProcedureParameters::TraceLibr {
        intraday_order: parameters[0],
        replenishment: parameters[1],
        account: handles[0],
        source: handles[1],
    })
}

struct Movement {
    identity: u128,
    day: i32,
    recorded_at: u64,
    inflow: bool,
    magnitude: i128,
    replenishes: bool,
}

pub(super) fn replay(
    selection: VerifiedProcedureParameters,
    claim: Option<i32>,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(VerifiedProcedureFinding, u64, u64), ReportError> {
    let VerifiedProcedureParameters::TraceLibr {
        intraday_order,
        replenishment,
        account,
        source,
    } = selection
    else {
        return Err(profile("expected the LIBR tracing profile"));
    };
    if !matches!(intraday_order, 0 | 2 | 3) || replenishment > 1 {
        return Err(profile("unsupported LIBR ordering or replenishment law"));
    }
    let claim = claim.ok_or_else(|| profile("LIBR requires an effective claim date"))?;
    let context = registry.trace.as_ref().ok_or_else(|| {
        failed(
            "procedure_source",
            "authenticated tracing metadata is absent",
        )
    })?;
    let normal = context
        .account_normal_balances
        .get(&account)
        .ok_or_else(|| {
            failed(
                "procedure_source",
                "traced account is absent from the historical chart",
            )
        })?;
    if *normal > 1 {
        return Err(failed(
            "procedure_source",
            "invalid historical normal balance",
        ));
    }
    let inflow_debit = *normal == 0;

    // Infer the native v2 normalization scope from ALL live in-window legs,
    // before selecting this account. A lone named entity absorbs implicit
    // mentions; multiple named entities never share an implicit selected leg.
    let mut named = BTreeSet::new();
    let mut entities = BTreeMap::new();
    for entry in live {
        let facts = context.entries.get(&entry.identity).ok_or_else(|| {
            failed(
                "procedure_source",
                "a live posting has no authenticated tracing facts",
            )
        })?;
        if entry.legs.len() != entry.leg_accounts.len() || facts.entities.len() != entry.legs.len()
        {
            return Err(failed(
                "procedure_source",
                "tracing leg identities are incomplete",
            ));
        }
        let mut selected = Vec::with_capacity(facts.entities.len());
        for values in &facts.entities {
            let value = match values.as_slice() {
                [] => None,
                [value] => {
                    named.insert(*value);
                    Some(*value)
                }
                _ => {
                    return Err(failed(
                        "procedure_entities",
                        "a leg names multiple legal entities",
                    ));
                }
            };
            selected.push(value);
        }
        entities.insert(entry.identity, selected);
    }
    let normalize = |entity| match (entity, named.len()) {
        (Some(value), _) => Ok(Some(value)),
        (None, 0) => Ok(None),
        (None, 1) => Ok(named.first().copied()),
        (None, _) => Err(failed(
            "procedure_entities",
            "a selected tracing leg has no unambiguous legal entity",
        )),
    };
    let source_entry = live
        .iter()
        .copied()
        .find(|entry| entry.identity == source)
        .ok_or_else(|| {
            failed(
                "procedure_source",
                "the source has no live posting at the claim date",
            )
        })?;
    let mut selected_scope = None;
    for ((&(unit, _), &(leg_account, debit)), &entity) in source_entry
        .legs
        .iter()
        .zip(&source_entry.leg_accounts)
        .zip(&entities[&source])
    {
        if leg_account != account || debit != inflow_debit {
            continue;
        }
        let coordinate = (unit, normalize(entity)?);
        if selected_scope.is_some_and(|previous| previous != coordinate) {
            return Err(failed(
                "procedure_source",
                "the source inflow spans units or legal entities",
            ));
        }
        selected_scope = Some(coordinate);
    }
    let (unit, entity) = selected_scope.ok_or_else(|| {
        failed(
            "procedure_source",
            "the source has no inflow-side leg on the traced account",
        )
    })?;
    let source_evidence = &context.entries[&source].evidence;
    let mut movements = Vec::new();
    for entry in live {
        let mut net = 0i128;
        for ((&(leg_unit, amount), &(leg_account, debit)), &leg_entity) in entry
            .legs
            .iter()
            .zip(&entry.leg_accounts)
            .zip(&entities[&entry.identity])
        {
            if leg_account != account || leg_unit != unit || normalize(leg_entity)? != entity {
                continue;
            }
            let magnitude = amount.checked_abs().ok_or_else(arithmetic)?;
            let signed = if debit == inflow_debit {
                magnitude
            } else {
                magnitude.checked_neg().ok_or_else(arithmetic)?
            };
            net = net.checked_add(signed).ok_or_else(arithmetic)?;
        }
        if net == 0 {
            continue;
        }
        let day = entry.effective.ok_or_else(|| {
            failed(
                "procedure_source",
                "a traced movement has no effective date",
            )
        })?;
        if day > claim {
            return Err(failed(
                "procedure_source",
                "a traced movement is after the claim date",
            ));
        }
        let facts = &context.entries[&entry.identity];
        let replenishes = entry.identity != source
            && (facts
                .evidence
                .iter()
                .any(|oid| source_evidence.contains(oid))
                || entry
                    .supersession
                    .iter()
                    .any(|(target, _, _)| *target == source));
        movements.push(Movement {
            identity: entry.identity,
            day,
            recorded_at: entry.recorded_at,
            inflow: net > 0,
            magnitude: net.checked_abs().ok_or_else(arithmetic)?,
            replenishes,
        });
    }
    let rank = |movement: &Movement| match intraday_order {
        2 => u8::from(movement.inflow),
        3 => u8::from(!movement.inflow),
        _ => 0,
    };
    movements.sort_unstable_by_key(|movement| {
        (
            movement.day,
            rank(movement),
            movement.recorded_at,
            movement.identity,
            movement.inflow,
        )
    });
    let source_at = movements
        .iter()
        .position(|movement| movement.identity == source && movement.inflow)
        .ok_or_else(|| {
            failed(
                "procedure_source",
                "the source does not net to a positive deposit",
            )
        })?;
    let count = movements.len() as u64;
    let comparisons = count.saturating_mul(u64::from(count.max(1).ilog2()));
    let mut balance = 0i128;
    for movement in &movements[..source_at] {
        balance = if movement.inflow {
            balance.checked_add(movement.magnitude)
        } else {
            balance.checked_sub(movement.magnitude)
        }
        .ok_or_else(arithmetic)?;
    }
    let deposit = movements[source_at].magnitude;
    balance = balance.checked_add(deposit).ok_or_else(arithmetic)?;
    let original_held = deposit.min(balance.max(0));
    let mut traced = original_held;
    let mut lowest = balance;
    let mut lowest_entry = None;
    let mut replenishing_entries = BTreeSet::new();
    for movement in &movements[source_at + 1..] {
        if movement.inflow {
            let before = balance.max(0);
            balance = balance
                .checked_add(movement.magnitude)
                .ok_or_else(arithmetic)?;
            let held = balance.max(0).checked_sub(before).ok_or_else(arithmetic)?;
            if replenishment == 1 && movement.replenishes && held > 0 && traced < original_held {
                let deficit = original_held.checked_sub(traced).ok_or_else(arithmetic)?;
                let available = balance
                    .max(0)
                    .checked_sub(traced)
                    .ok_or_else(arithmetic)?
                    .max(0);
                let restored = held.min(deficit).min(available);
                if restored > 0 {
                    traced = traced.checked_add(restored).ok_or_else(arithmetic)?;
                    replenishing_entries.insert(movement.identity);
                }
            }
        } else {
            balance = balance
                .checked_sub(movement.magnitude)
                .ok_or_else(arithmetic)?;
            if balance < lowest {
                lowest = balance;
                lowest_entry = Some(movement.identity);
            }
            traced = traced.min(balance.max(0));
        }
    }
    if let Some(identity) = lowest_entry {
        replenishing_entries.insert(identity);
    }
    let mut citations = vec![source];
    citations.extend(
        replenishing_entries
            .into_iter()
            .filter(|id| *id != source)
            .take(MAX_CITES - 2),
    );
    let scale = registry
        .unit_scales
        .get(&unit)
        .copied()
        .ok_or_else(|| failed("procedure_units", "the traced source unit is unregistered"))?;
    let source_date = crate::bundle::civil(movements[source_at].day);
    let claim_date = crate::bundle::civil(claim);
    let entity_text = entity.map_or_else(
        || "implicit book entity".to_string(),
        |entity| format!("entity {entity:032x}"),
    );
    // LIBR reports the lowest-balance and replenishing entries. It does not
    // allocate tainted withdrawals into the FIFO/pro-rata carrier schedule.
    let finding = VerifiedProcedureFinding {
        entry: None,
        severity: 0,
        statistic: VerifiedProcedureStatistic::TracedAmount {
            account,
            unit,
            mantissa: traced,
            scale,
            entries: citations,
        },
        population: count,
        narrative: format!(
            "LIBR: {deposit} (mantissa) deposited {source_date}; {} later movement(s) through {claim_date}; lowest balance after the deposit {lowest}; 0 withdrawal(s) carried 0 tainted; traced {traced}; {entity_text}",
            count - source_at as u64 - 1,
        ),
    };
    Ok((finding, count - 1, comparisons))
}

#[cfg(test)]
mod tests;
