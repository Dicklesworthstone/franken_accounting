//! Explicit base-currency adjustments to source-derived foreign settlements.

use fa::Book;
use fa_model::EntryPayload;
use fa_model::application::MAX_APPLICATION_DIFFERENCES;
use fa_money::{Amount, UnitId};

use crate::cli::{Fail, usage};
use crate::json::{Json, obj, s};

const USAGE: &str = r#"fx.differences:[{"item":0,"kind":"BankCharge","account":"6100","amount":"1.00 USD"}]; item is the zero-based cash/application pair. Amounts are explicit positive base-currency amounts. Receipt: quote = cash + Discount + Writeoff + BankCharge; payment: quote = cash + Discount + Writeoff - BankCharge. The rate and carrying history independently determine RealizedFx."#;

pub(super) fn parse(
    fx: &Json,
    item_count: usize,
    book: &Book,
    base_unit: UnitId,
) -> Result<Vec<Vec<fa::FxSettlementDifference>>, Fail> {
    let mut result = vec![Vec::new(); item_count];
    let Some(value) = fx.get("differences") else {
        return Ok(result);
    };
    let values = value
        .as_arr()
        .ok_or_else(|| usage("intent.fx.differences must be an array", USAGE))?;
    if values.is_empty() || values.len() > MAX_APPLICATION_DIFFERENCES {
        return Err(usage(
            "intent.fx.differences requires between 1 and 128 explicit adjustments",
            USAGE,
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let what = format!("intent.fx.differences[{index}]");
        super::strict_object(value, &["item", "kind", "account", "amount"], &what, USAGE)?;
        let item = match value.get("item") {
            Some(Json::Int(item)) => usize::try_from(*item).ok(),
            _ => None,
        }
        .filter(|item| *item < item_count)
        .ok_or_else(|| usage(format!("{what}.item must name a cash/application pair"), USAGE))?;
        let kind = crate::application::difference_kind(super::required_string(
            value, "kind", &what, USAGE,
        )?)?;
        let account = super::required_string(value, "account", &what, USAGE)?;
        let amount = Amount::parse(
            super::required_string(value, "amount", &what, USAGE)?,
            &book.context().units,
        )
        .map_err(|error| usage(format!("{what}.amount: {error}"), USAGE))?;
        if amount.unit != base_unit || amount.mantissa <= 0 {
            return Err(usage(
                format!("{what}.amount must be positive and in the book's base currency"),
                USAGE,
            ));
        }
        result[item].push(fa::FxSettlementDifference {
            kind,
            account: fa_model::account_vid(book.context().book_id, account),
            amount,
        });
    }
    Ok(result)
}

/// Classification comes from the retained marker. Actual amounts, accounts,
/// dimensions and opposite conversion legs remain in the reviewed leg list.
pub(crate) fn review(proposal: &EntryPayload) -> Result<(Json, Vec<String>), Fail> {
    let Some(terms) = proposal
        .fx_settlement_terms()
        .map_err(|error| Fail::Internal(format!("admitted FX settlement terms: {error}")))?
    else {
        return Ok((Json::Null, Vec::new()));
    };
    let lines = terms
        .components
        .iter()
        .flat_map(|component| {
            component.differences.iter().map(move |difference| {
                format!(
                    "FX application leg {}: {} on leg {}; cash is actual net cash and realized FX is independently derived",
                    component.applying_ordinal,
                    difference.kind.name(),
                    difference.leg_ordinal,
                )
            })
        })
        .collect();
    Ok((Json::Arr(
        terms
            .components
            .iter()
            .map(|component| {
                obj(vec![
                    (
                        "applying_ordinal",
                        Json::Int(i128::from(component.applying_ordinal)),
                    ),
                    (
                        "differences",
                        Json::Arr(
                            component
                                .differences
                                .iter()
                                .map(|difference| {
                                    obj(vec![
                                        (
                                            "leg_ordinal",
                                            Json::Int(i128::from(difference.leg_ordinal)),
                                        ),
                                        ("kind", s(difference.kind.name())),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    ), lines))
}
