//! Explicit native settlement classifications, retained in extension 41.

use fa_model::EntryPayload;
use fa_model::application::{
    ApplicationDifference, ApplicationDifferenceKind, ApplicationDirection, ApplicationTerms,
};

use crate::cli::{Fail, usage};
use crate::fx::strict_object;
use crate::json::{Json, obj, s};

pub(crate) const USAGE: &str = r#""application":{"direction":"Receipt","cash_ordinal":0,"applying_ordinal":1,"differences":[{"leg_ordinal":2,"kind":"Discount"}]} binds explicit base-unit cash, fully applied control and difference legs. Kinds: Discount, Writeoff, BankCharge. Every leg must be bound exactly once; each difference has an explicit account and positive amount in legs. ShortPay remains a partial application; RealizedFx uses the source-derived FX settlement route."#;

pub(crate) fn difference_kind(name: &str) -> Result<ApplicationDifferenceKind, Fail> {
    match name {
        "Discount" => Ok(ApplicationDifferenceKind::Discount),
        "Writeoff" => Ok(ApplicationDifferenceKind::Writeoff),
        "BankCharge" => Ok(ApplicationDifferenceKind::BankCharge),
        "ShortPay" => Err(usage(
            "ShortPay does not authorize forgiving or reclassifying the unpaid balance",
            "apply the actual partial amount and leave the remainder open; an authorized write-off must explicitly name kind=Writeoff",
        )),
        "RealizedFx" => Err(usage(
            "RealizedFx must be derived from the open item's carrying basis",
            "use --fx-rate, --conversion and --realized-fx with an explicit foreign application",
        )),
        _ => Err(usage(
            format!("unknown application difference kind `{name}`"),
            "kind=Discount, kind=Writeoff or kind=BankCharge; name the account and exact amount",
        )),
    }
}

fn ordinal(object: &Json, field: &str, what: &str) -> Result<u16, Fail> {
    match object.get(field) {
        Some(Json::Int(value)) => u16::try_from(*value).map_err(|_| {
            usage(
                format!("{what}.{field} is outside the leg ordinal range"),
                USAGE,
            )
        }),
        _ => Err(usage(
            format!("{what}.{field} must be an integer leg ordinal"),
            USAGE,
        )),
    }
}

pub(crate) fn declare_terms(doc: &Json, mut proposal: EntryPayload) -> Result<EntryPayload, Fail> {
    let Some(value) = doc.get("application") else {
        return Ok(proposal);
    };
    if doc.get("reverses").is_some() {
        return Err(usage(
            "a Reversal inherits its application classification from its authenticated target",
            "omit application; the target's marker and exact reversed legs are retained",
        ));
    }
    strict_object(
        value,
        &[
            "direction",
            "cash_ordinal",
            "applying_ordinal",
            "differences",
        ],
        "application",
        USAGE,
    )?;
    let direction = match value.get("direction").and_then(Json::as_str) {
        Some("Receipt") => ApplicationDirection::Receipt,
        Some("Payment") => ApplicationDirection::Payment,
        _ => {
            return Err(usage(
                "application.direction must be Receipt or Payment",
                USAGE,
            ));
        }
    };
    let items = value
        .get("differences")
        .and_then(Json::as_arr)
        .ok_or_else(|| usage("application.differences must be an array", USAGE))?;
    if items.is_empty() || items.len() > 128 {
        return Err(usage(
            "application.differences requires between 1 and 128 classified legs",
            USAGE,
        ));
    }
    let mut differences = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let what = format!("application.differences[{index}]");
        strict_object(item, &["leg_ordinal", "kind"], &what, USAGE)?;
        let kind = item
            .get("kind")
            .and_then(Json::as_str)
            .ok_or_else(|| usage(format!("{what}.kind must name the difference kind"), USAGE))?;
        differences.push(ApplicationDifference {
            leg_ordinal: ordinal(item, "leg_ordinal", &what)?,
            kind: difference_kind(kind)?,
        });
    }
    proposal
        .set_application_terms(&ApplicationTerms {
            direction,
            cash_ordinal: ordinal(value, "cash_ordinal", "application")?,
            applying_ordinal: ordinal(value, "applying_ordinal", "application")?,
            differences,
        })
        .map_err(|error| usage(format!("application: {error}"), USAGE))?;
    Ok(proposal)
}

/// Display the exact retained classification alongside the already rendered
/// accounts, amounts and application effects. No classification is inferred.
pub(crate) fn review(proposal: &EntryPayload) -> Result<(Json, Vec<String>), Fail> {
    let Some(terms) = proposal
        .application_terms()
        .map_err(|error| Fail::Internal(format!("admitted application terms: {error}")))?
    else {
        return Ok((Json::Null, Vec::new()));
    };
    let mut human = vec![format!(
        "Application: {}; cash leg {}, applying leg {}",
        terms.direction.name(),
        terms.cash_ordinal,
        terms.applying_ordinal,
    )];
    for difference in &terms.differences {
        human.push(format!(
            "  leg {}: {}",
            difference.leg_ordinal,
            difference.kind.name(),
        ));
    }
    Ok((
        obj(vec![
            ("direction", s(terms.direction.name())),
            ("cash_ordinal", Json::Int(i128::from(terms.cash_ordinal))),
            (
                "applying_ordinal",
                Json::Int(i128::from(terms.applying_ordinal)),
            ),
            (
                "differences",
                Json::Arr(
                    terms
                        .differences
                        .iter()
                        .map(|difference| {
                            obj(vec![
                                ("leg_ordinal", Json::Int(i128::from(difference.leg_ordinal))),
                                ("kind", s(difference.kind.name())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        human,
    ))
}
