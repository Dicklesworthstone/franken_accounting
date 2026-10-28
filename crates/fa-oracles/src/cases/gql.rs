//! The second read path (docs/FORENSIC_CASE_STUDIES_PLAN.md §12.7; bead
//! fa-yugf.28, A12 step 7): every T and R value is also read with `fa query`
//! under the FA GQL profile, as an aggregate of an account's legs grouped
//! by unit and side, and netted here. It must equal the fold path's value.
//!
//! This is an R-class cross-check of two FA read paths, never independent
//! evidence. A per-account read only: a stock account (Asset, Liability,
//! Equity) reads every leg effective from the book's opening through the
//! read's period end, a flow account (Revenue, Expense) the legs of the
//! read's own periods; both at the sequence the fold path's read resolved,
//! certified (`AS KNOWN AT`).

use crate::json::Json;

use super::amount::parse_amount;

/// What one account read selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Every leg effective from `opening` through `end` (dates).
    Stock { opening: String, end: String },
    /// The legs of the periods `from` through `through` (period codes).
    Flow { from: String, through: String },
}

/// The profile statement reading `account`'s legs by unit and side at
/// `known_at`.
///
/// # Errors
/// An account code or selector that would need quoting.
pub fn statement(account: &str, selection: &Selection, known_at: i128) -> Result<String, String> {
    let quoted = |s: &str| {
        if s.is_empty() || s.contains(['\'', '\\']) {
            Err(format!("`{s}` cannot be quoted in a profile statement"))
        } else {
            Ok(format!("'{s}'"))
        }
    };
    let selector = match selection {
        Selection::Stock { opening, end } => format!(
            "EFFECTIVE BETWEEN {} AND {}",
            quoted(opening)?,
            quoted(end)?
        ),
        Selection::Flow { from, through } if from == through => {
            format!("FOR PERIOD {}", quoted(from)?)
        }
        Selection::Flow { from, through } => {
            format!("FOR PERIOD {}..{}", quoted(from)?, quoted(through)?)
        }
    };
    Ok(format!(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account {{code: {}}}), (l)-[:IN_UNIT]->(u:Unit) RETURN u.code AS unit, l.side AS side, SUM(l.amount) AS total ORDER BY unit, side {selector} AS KNOWN AT {known_at}",
        quoted(account)?
    ))
}

/// The net (debits minus credits) in `unit`'s minor units of the statement's
/// `[unit, side, total]` rows: side 0 is debit, 1 credit; a total is exact
/// decimal text without trailing zeros. No row in the unit nets to zero.
///
/// # Errors
/// A malformed row, a total finer than the unit's scale, or an overflow.
pub fn net(rows: &[Json], unit: &str, scale: u8) -> Result<i128, String> {
    let mut net = 0_i128;
    for row in rows {
        let [u, side, total] = row.as_array().unwrap_or_default() else {
            return Err(format!("expected a [unit, side, total] row observed {row}"));
        };
        if u.as_str() != Some(unit) {
            continue;
        }
        let text = total
            .as_str()
            .ok_or_else(|| format!("expected a decimal total observed {total}"))?;
        let minor = minor_units(text, scale)?;
        net = match side.as_int() {
            Some(0) => net.checked_add(minor),
            Some(1) => net.checked_sub(minor),
            _ => return Err(format!("expected side 0 or 1 observed {side}")),
        }
        .ok_or("the net overflows")?;
    }
    Ok(net)
}

/// Exact decimal text without trailing zeros (`500`, `0.5`) at `scale`.
fn minor_units(text: &str, scale: u8) -> Result<i128, String> {
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if frac.len() > usize::from(scale) {
        return Err(format!("`{text}` is finer than the unit's scale {scale}"));
    }
    let padded = format!("{whole}.{frac:0<width$}", width = usize::from(scale));
    let padded = if scale == 0 {
        whole.to_string()
    } else {
        padded
    };
    parse_amount(&padded, scale).map_err(|e| format!("`{text}`: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn rows(text: &str) -> Vec<Json> {
        json::parse(text)
            .expect("rows")
            .as_array()
            .expect("an array")
            .to_vec()
    }

    #[test]
    fn statement_reads_stock_and_flow_at_the_resolved_sequence() {
        let stock = Selection::Stock {
            opening: "2026-01-01".into(),
            end: "2026-03-31".into(),
        };
        assert_eq!(
            statement("1100", &stock, 42).as_deref(),
            Ok(
                "MATCH (l:Leg)-[:POSTS_TO]->(a:Account {code: '1100'}), (l)-[:IN_UNIT]->(u:Unit) RETURN u.code AS unit, l.side AS side, SUM(l.amount) AS total ORDER BY unit, side EFFECTIVE BETWEEN '2026-01-01' AND '2026-03-31' AS KNOWN AT 42"
            )
        );
        let quarter = Selection::Flow {
            from: "FY2026-P01".into(),
            through: "FY2026-P01".into(),
        };
        assert!(
            statement("4000", &quarter, 7)
                .is_ok_and(|s| s.ends_with(" FOR PERIOD 'FY2026-P01' AS KNOWN AT 7"))
        );
        let year = Selection::Flow {
            from: "FY2026-P01".into(),
            through: "FY2026-P04".into(),
        };
        assert!(
            statement("4000", &year, 7)
                .is_ok_and(|s| s.ends_with(" FOR PERIOD 'FY2026-P01'..'FY2026-P04' AS KNOWN AT 7"))
        );
        assert!(statement("11'00", &stock, 1).is_err());
    }

    /// Debits add and credits subtract in the read's unit; another unit's
    /// rows are not the read's; totals carry no trailing zeros.
    #[test]
    fn net_is_debits_minus_credits_in_the_unit() {
        let r = rows(r#"[["EUR",0,"7"],["USD",0,"1000"],["USD",1,"100.5"]]"#);
        assert_eq!(net(&r, "USD", 2), Ok(89_950));
        assert_eq!(net(&r, "EUR", 2), Ok(700));
        assert_eq!(net(&r, "GBP", 2), Ok(0));
        assert!(net(&rows(r#"[["USD",0,"1.005"]]"#), "USD", 2).is_err());
        assert!(net(&rows(r#"[["USD",2,"1"]]"#), "USD", 2).is_err());
        assert!(net(&rows(r#"[["USD",0]]"#), "USD", 2).is_err());
    }

    /// A netting that flips a side (a test-only bug) no longer equals the
    /// fold path's value, so the cross-check catches it.
    #[test]
    fn gql_read_differing_from_the_fold_fails() {
        let fold = 90_000;
        let r = rows(r#"[["USD",0,"1000"],["USD",1,"100"]]"#);
        assert_eq!(net(&r, "USD", 2), Ok(fold));
        let flipped = rows(r#"[["USD",1,"1000"],["USD",1,"100"]]"#);
        assert_ne!(net(&flipped, "USD", 2), Ok(fold));
    }
}
