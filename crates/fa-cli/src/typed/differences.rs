//! Explicit cash-versus-application differences for the typed settlement verbs.
//! Foreign applications retain base-unit differences in their source-derived
//! FX profile; only the kernel may check them against the retained rate.

use fa_model::application::ApplicationDifferenceKind;

use crate::application::{USAGE, difference_kind};
use crate::args::Args;
use crate::cli::{Fail, usage};
use crate::json::{Json, obj, s};

use super::{Settle, exact, is_zero, leg_json, line_words, render, sum};

struct Difference {
    kind: ApplicationDifferenceKind,
    account: String,
    amount: String,
}

pub(super) struct PreparedDifferences {
    pub control_amount: String,
    pub legs: Vec<Json>,
    pub declaration: Json,
}

/// The cash is the actual amount moved. Each declared reduction increases
/// the principal applied; an outgoing bank fee consumes cash without paying
/// principal, while an incoming fee reduces the cash received. All arithmetic
/// is checked and exact before registered unit-scale validation in the kernel.
fn control_amount(cash: &str, rows: &[Difference], kind: Settle) -> Result<String, String> {
    let mut additions = vec![cash.to_string()];
    let mut outgoing_fees = Vec::new();
    for row in rows {
        if matches!(kind, Settle::Payment) && row.kind == ApplicationDifferenceKind::BankCharge {
            outgoing_fees.push(row.amount.clone());
        } else {
            additions.push(row.amount.clone());
        }
    }
    let positive = sum(&additions)?;
    if outgoing_fees.is_empty() {
        return Ok(positive);
    }
    let fees = sum(&outgoing_fees)?;
    let positive = exact(&positive, "cash plus reductions")?;
    let fees = exact(&fees, "bank charges")?;
    if positive.unit != fees.unit {
        return Err("cash, applications and every difference must name the same unit".into());
    }
    let scale = positive.scale.max(fees.scale);
    let align = |digits: i128, places: usize| {
        u32::try_from(places)
            .ok()
            .and_then(|places| 10_i128.checked_pow(places))
            .and_then(|factor| digits.checked_mul(factor))
            .ok_or_else(|| "settlement amount is out of range".to_string())
    };
    let principal = align(positive.digits, scale - positive.scale)?
        .checked_sub(align(fees.digits, scale - fees.scale)?)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| "bank charges leave no positive principal to apply".to_string())?;
    Ok(render(principal, scale, positive.unit))
}

pub(super) fn prepare(
    args: &Args,
    kind: Settle,
    cash: &str,
    cash_account: &str,
    control_account: &str,
    entity: Option<&str>,
    uses_fx: bool,
) -> Result<Option<PreparedDifferences>, Fail> {
    let raw = args.flag_all("--difference");
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > 128 {
        return Err(usage(
            "at most 128 --difference declarations are permitted",
            USAGE,
        ));
    }
    let applications = args.flag_all("--applies");
    if applications.is_empty() || applications.iter().any(|item| !item.contains('=')) {
        return Err(usage(
            "settlement differences require explicit amounts for every --applies target",
            "--applies <entry>:<leg>=\"100.00 USD\"; their total must equal the declared principal relief",
        ));
    }
    let cash_unit = exact(cash, "cash")
        .map_err(|error| usage(error, USAGE))?
        .unit;
    let mut rows = Vec::with_capacity(raw.len());
    for (index, raw) in raw.iter().enumerate() {
        let what = format!("--difference {}", index + 1);
        let fields = line_words(raw).map_err(|error| usage(format!("{what}: {error}"), USAGE))?;
        if let Some((key, _)) = fields
            .iter()
            .find(|(key, _)| !matches!(key.as_str(), "kind" | "account" | "amount"))
        {
            return Err(usage(format!("{what}: unknown field `{key}`"), USAGE));
        }
        let field = |key: &str| {
            fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
                .ok_or_else(|| usage(format!("{what}: {key} is required"), USAGE))
        };
        let kind = difference_kind(field("kind")?)?;
        let account = field("account")?;
        if account == cash_account || account == control_account {
            return Err(usage(
                format!(
                    "{what}: a difference needs its own account, distinct from cash and the control account"
                ),
                USAGE,
            ));
        }
        let amount = sum(&[field("amount")?.to_string()])
            .map_err(|error| usage(format!("{what}: {error}"), USAGE))?;
        if is_zero(&amount) {
            return Err(usage(
                format!("{what}: a difference amount must be positive"),
                USAGE,
            ));
        }
        if exact(&amount, "difference")
            .map_err(|error| usage(error, USAGE))?
            .unit
            != cash_unit
        {
            return Err(usage(
                format!("{what}: difference and cash must name the same unit"),
                USAGE,
            ));
        }
        rows.push(Difference {
            kind,
            account: account.to_string(),
            amount,
        });
    }
    if uses_fx {
        // The foreign principal and actual base cash use different units.
        // Never add them, or infer a rate from their difference. The source
        // preparer checks the exact gross/net equation and derives every pair.
        let declaration = Json::Arr(
            rows.iter()
                .map(|row| {
                    obj(vec![
                        ("item", Json::Int(0)),
                        ("kind", s(row.kind.name())),
                        ("account", s(&row.account)),
                        ("amount", s(&row.amount)),
                    ])
                })
                .collect(),
        );
        return Ok(Some(PreparedDifferences {
            // Only the native branch consumes this value. The FX branch uses
            // the explicitly supplied foreign application amount instead.
            control_amount: cash.to_string(),
            legs: Vec::new(),
            declaration,
        }));
    }
    let control_amount = control_amount(cash, &rows, kind).map_err(|error| usage(error, USAGE))?;
    let applied_amounts: Vec<_> = applications
        .iter()
        .map(|item| {
            item.split_once('=')
                .expect("explicit applications checked above")
                .1
                .to_string()
        })
        .collect();
    let applied =
        sum(&applied_amounts).map_err(|error| usage(format!("--applies: {error}"), USAGE))?;
    if applied != control_amount {
        return Err(usage(
            format!(
                "explicit applications total {applied}, but cash and declared differences require {control_amount}"
            ),
            "correct the cash, application amounts or explicit differences; no balancing amount is inferred",
        ));
    }
    let legs = rows
        .iter()
        .map(|row| {
            let side = if matches!(kind, Settle::Payment)
                && row.kind == ApplicationDifferenceKind::BankCharge
            {
                "debit"
            } else {
                kind.cash_side()
            };
            leg_json(side, &row.account, &row.amount, None, entity, None, None)
        })
        .collect();
    let declaration = obj(vec![
        (
            "direction",
            s(match kind {
                Settle::Receipt => "Receipt",
                Settle::Payment => "Payment",
            }),
        ),
        ("cash_ordinal", Json::Int(0)),
        ("applying_ordinal", Json::Int(1)),
        (
            "differences",
            Json::Arr(
                rows.iter()
                    .enumerate()
                    .map(|(index, row)| {
                        obj(vec![
                            ("leg_ordinal", Json::Int((index + 2) as i128)),
                            ("kind", s(row.kind.name())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    Ok(Some(PreparedDifferences {
        control_amount,
        legs,
        declaration,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: ApplicationDifferenceKind, amount: &str) -> Difference {
        Difference {
            kind,
            account: "6000".into(),
            amount: amount.into(),
        }
    }

    #[test]
    fn cash_and_each_declared_difference_determine_principal_without_rounding() {
        let rows = [
            row(ApplicationDifferenceKind::Discount, "2.00 USD"),
            row(ApplicationDifferenceKind::BankCharge, "1 USD"),
        ];
        assert_eq!(
            control_amount("97 USD", &rows, Settle::Receipt).unwrap(),
            "100 USD"
        );
        assert_eq!(
            control_amount("99 USD", &rows, Settle::Payment).unwrap(),
            "100 USD"
        );
        assert_eq!(
            control_amount("97.001 USD", &rows, Settle::Receipt).unwrap(),
            "100.001 USD"
        );
        let writeoff = [row(ApplicationDifferenceKind::Writeoff, "0.05 USD")];
        assert_eq!(
            control_amount("99.95 USD", &writeoff, Settle::Receipt).unwrap(),
            "100 USD"
        );
    }

    #[test]
    fn impossible_or_mixed_unit_principal_is_refused() {
        let fee = [row(ApplicationDifferenceKind::BankCharge, "1.01 USD")];
        assert!(control_amount("1 USD", &fee, Settle::Payment).is_err());
        let equal = [row(ApplicationDifferenceKind::BankCharge, "1 USD")];
        assert!(control_amount("1 USD", &equal, Settle::Payment).is_err());
        assert!(control_amount("1 EUR", &equal, Settle::Payment).is_err());
        let overflow = [row(ApplicationDifferenceKind::Discount, "1 USD")];
        assert!(control_amount(&format!("{} USD", i128::MAX), &overflow, Settle::Receipt).is_err());
    }
}
