//! Independent explicit FX settlement differences (extension 42, profile v2).
//!
//! The declaration selects complete ordered pairs; it never supplies a quote
//! or carrying balance. Those values come from authenticated Rate documents
//! and the preceding open-item history, independently of the producer.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct Difference {
    ordinal: usize,
    kind: u8,
}

pub(super) type Components = BTreeMap<usize, Vec<Difference>>;

fn read(raw: &[u8]) -> Result<Components, ReportError> {
    if raw.len() > 18 + 6 * 1024 + 3 * 128 {
        return Err(failed(
            "bounded_input",
            "FX settlement terms exceed the registered bounded extension frame",
        ));
    }
    let mut r = Reader::new(raw);
    if r.fixed::<12>("fx_terms.magic")? != *b"FA-FX-TERMS\0"
        || r.u16("fx_terms.version")? != 2
    {
        return Err(invalid("unsupported explicit FX settlement terms format"));
    }
    let count = r.count(1024, 9, "fx_terms.components")?;
    if count == 0 {
        return Err(invalid("FX settlement terms require an affected component"));
    }
    let mut result = BTreeMap::new();
    let mut previous = None;
    let mut total = 0usize;
    for _ in 0..count {
        let ordinal = usize::from(r.u16("fx_terms.applying_ordinal")?);
        if ordinal >= 4096 || previous.is_some_and(|last| last >= ordinal) {
            return Err(invalid(
                "FX settlement applying ordinals must be bounded and strictly ordered",
            ));
        }
        previous = Some(ordinal);
        let differences = r.count(128, 3, "fx_terms.differences")?;
        total = total
            .checked_add(differences)
            .ok_or_else(|| invalid("FX difference count overflow"))?;
        if differences == 0 || total > 128 {
            return Err(invalid(
                "FX terms require nonempty components and at most 128 differences",
            ));
        }
        let mut rows = Vec::with_capacity(differences);
        let mut previous_difference = None;
        for _ in 0..differences {
            let economic = usize::from(r.u16("fx_terms.economic_ordinal")?);
            let kind = r.u8("fx_terms.kind")?;
            if economic >= 4095
                || previous_difference.is_some_and(|last| last >= economic)
                || !matches!(kind, 1 | 3 | 4)
            {
                return Err(invalid(
                    "FX differences require ordered paired ordinals and Discount, Writeoff or BankCharge",
                ));
            }
            previous_difference = Some(economic);
            rows.push(Difference {
                ordinal: economic,
                kind,
            });
        }
        result.insert(ordinal, rows);
    }
    r.finish("FX settlement terms")?;
    Ok(result)
}

pub(super) fn read_history(
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
) -> Result<BTreeMap<usize, Components>, ReportError> {
    infos
        .iter()
        .filter_map(|(&index, info)| info.fx_settlement_terms.map(|raw| (index, raw)))
        .map(|(index, raw)| Ok((index, read(raw)?)))
        .collect()
}

pub(super) fn check_ranges(
    declarations: &Components,
    ranges: &[std::ops::Range<usize>],
) -> Result<(), ReportError> {
    if declarations
        .keys()
        .any(|ordinal| !ranges.iter().any(|range| range.start == *ordinal))
    {
        return Err(invalid(
            "FX terms name a component without its exact applying leg",
        ));
    }
    Ok(())
}

pub(super) fn component(
    history: &History<'_>,
    index: usize,
    range: std::ops::Range<usize>,
    target: Target,
    relief: i128,
    differences: &[Difference],
) -> Result<Effect, ReportError> {
    let entry = &history.parsed[&index];
    let claim = entry.base.as_ref().expect("settlement claim checked");
    let rate = &history.rates[&claim.rates[0]];
    let legs = &history.legs[index][range.clone()];
    let amounts = &entry.amounts[range.clone()];
    let details = &entry.details[range.clone()];
    let settled = &legs[0];
    let quote = super::super::super::arithmetic::convert(
        settled.mantissa,
        history.registry.units[&rate.quote].scale,
        history.registry.units[&history.spec.base].scale,
        rate.numerator,
        rate.denominator,
    )?;
    let realized = sub(quote, relief)?;
    let core = 4 + usize::from(realized != 0) * 2;
    if quote <= 0 || legs.len() != core + differences.len() * 2 || amounts[0] != relief {
        return Err(invalid(
            "explicit FX settlement omits or adds a cash, realized or declared difference pair",
        ));
    }
    let conversion = &legs[1];
    let cash = &legs[2];
    let base_conversion = &legs[3];
    let mut reserved = BTreeSet::from([settled.account, conversion.account, cash.account]);
    if reserved.len() != 3
        || conversion.unit != settled.unit
        || conversion.mantissa != settled.mantissa
        || conversion.debit == settled.debit
        || amounts[1] != relief
        || cash.unit != history.spec.base
        || cash.debit == settled.debit
        || cash.mantissa <= 0
        || amounts[2] != cash.mantissa
        || base_conversion.account != conversion.account
        || base_conversion.unit != history.spec.base
        || base_conversion.debit != settled.debit
        || base_conversion.mantissa != cash.mantissa
        || amounts[3] != cash.mantissa
        || details
            .iter()
            .any(|detail| detail.dimensions != details[0].dimensions)
    {
        return Err(invalid(
            "explicit FX cash, conversion or dimensions differ from the complete component",
        ));
    }
    let paired = |ordinal: usize, account: u128, debit: bool, amount: i128| {
        let economic = &legs[ordinal];
        let opposite = &legs[ordinal + 1];
        economic.account == account
            && economic.unit == history.spec.base
            && economic.debit == debit
            && economic.mantissa == amount
            && amount > 0
            && amounts[ordinal] == amount
            && opposite.account == conversion.account
            && opposite.unit == history.spec.base
            && opposite.debit != debit
            && opposite.mantissa == amount
            && amounts[ordinal + 1] == amount
    };
    if realized != 0 {
        let economic = &legs[4];
        let magnitude = realized
            .checked_abs()
            .ok_or_else(|| invalid("realized FX magnitude overflow"))?;
        if !reserved.insert(economic.account)
            || !paired(
                4,
                economic.account,
                if realized > 0 {
                    settled.debit
                } else {
                    !settled.debit
                },
                magnitude,
            )
        {
            return Err(invalid(
                "realized FX pair differs from retained quote minus historical carrying relief",
            ));
        }
    }
    let mut gross = cash.mantissa;
    for (position, difference) in differences.iter().enumerate() {
        let ordinal = core + position * 2;
        let economic = &legs[ordinal];
        // An application debit pays a credit-side source; bank charges add
        // to its cash outflow. All other explicit rows reduce net cash.
        let debit = if difference.kind == 4 {
            true
        } else {
            !settled.debit
        };
        if difference.ordinal != range.start + ordinal
            || reserved.contains(&economic.account)
            || !paired(ordinal, economic.account, debit, economic.mantissa)
        {
            return Err(invalid(
                "explicit difference does not name its complete classified base-currency pair",
            ));
        }
        gross = if settled.debit && difference.kind == 4 {
            sub(gross, economic.mantissa)?
        } else {
            gross
                .checked_add(economic.mantissa)
                .ok_or_else(|| invalid("explicit settlement difference sum overflow"))?
        };
    }
    if gross != quote {
        return Err(invalid(
            "actual cash and declared differences do not reproduce the retained Settlement Rate quote",
        ));
    }
    Ok(Effect {
        target,
        native: settled.mantissa,
        base: relief,
        valuation: 0,
    })
}
