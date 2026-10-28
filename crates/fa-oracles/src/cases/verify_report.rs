//! fa-verify's `report --json` output, read by the harness
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §12.1; bead fa-yugf.28, A12).
//!
//! fa-verify recomputes a bundled report offline. The harness compares the
//! recomputed line, row or cells with B itself, never through fa-verify's
//! `--expect`, so the comparison stays independent of the tool under test.
//! Amounts are minor units, debits positive; a statement line is as the
//! statement presents it.

use super::outsider_kind::Recomputed;
use crate::json::{self, Json};

/// What one verified report recomputed for a read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recomputation {
    /// The read's value in its unit's minor units.
    pub value: i128,
    /// The independently reconstructed canonical report's output digest.
    pub output_digest: String,
}

/// The recomputation of `target` (an account or line code) in `unit` (the
/// registered unit id) from fa-verify's `report --json` stdout. A balance
/// explanation sums its posted cells in the unit (none: zero).
///
/// # Errors
/// The report is not JSON or not verified, or names no such value.
pub fn recomputed(
    stdout: &str,
    what: Recomputed,
    target: &str,
    unit: u32,
) -> Result<Recomputation, String> {
    let report = json::parse(stdout.trim())
        .map_err(|error| format!("fa-verify report is not JSON: {error:?}"))?;
    let verdict = report.get("verdict").and_then(Json::as_str);
    if verdict != Some("verified") {
        return Err(format!(
            "expected fa-verify report verified observed {}",
            verdict.unwrap_or("no verdict")
        ));
    }
    let checks = report
        .get("checks")
        .and_then(Json::as_array)
        .unwrap_or_default();
    let named = |name: &'static str| {
        checks
            .iter()
            .filter(move |c| c.get("check").and_then(Json::as_str) == Some(name))
    };
    let detail = |c: &Json, key: &str| c.get("detail").and_then(|d| d.get(key)).cloned();
    let text = |c: &Json, key: &str| detail(c, key).and_then(|v| v.as_str().map(str::to_string));
    let in_unit = |c: &Json| detail(c, "unit").and_then(|u| u.as_int()) == Some(i128::from(unit));
    let minor = |c: &Json, key: &str| -> Result<i128, String> {
        let raw =
            text(c, key).ok_or_else(|| format!("expected a recomputed {key} observed none"))?;
        raw.parse::<i128>()
            .map_err(|_| format!("expected a recomputed {key} in minor units observed `{raw}`"))
    };
    let net = |c: &Json| -> Result<i128, String> {
        minor(c, "debits")?
            .checked_sub(minor(c, "credits")?)
            .ok_or_else(|| "the recomputed net overflows".to_string())
    };
    let value = match what {
        Recomputed::Explanation => {
            if named("balance_explanation").next().is_none() {
                return Err("expected a recomputed balance explanation observed none".into());
            }
            named("balance_explanation_cell")
                .filter(|c| text(c, "column").as_deref() == Some("posted") && in_unit(c))
                .try_fold(0_i128, |sum, c| {
                    sum.checked_add(net(c)?)
                        .ok_or_else(|| "the recomputed cells overflow".to_string())
                })?
        }
        Recomputed::TrialBalanceRow => {
            let row = named("trial_balance_row")
                .find(|c| text(c, "code").as_deref() == Some(target) && in_unit(c))
                .ok_or_else(|| {
                    format!("expected a recomputed trial-balance row {target} observed none")
                })?;
            net(row)?
        }
        Recomputed::StatementLine => {
            let line = named("statement_line")
                .find(|c| text(c, "code").as_deref() == Some(target) && in_unit(c))
                .ok_or_else(|| {
                    format!("expected a recomputed statement line {target} observed none")
                })?;
            let amount = detail(line, "amounts")
                .and_then(|a| a.as_array().and_then(<[Json]>::first).cloned())
                .and_then(|a| a.as_str().map(str::to_string))
                .ok_or_else(|| {
                    format!("expected the recomputed amounts of line {target} observed none")
                })?;
            amount.parse::<i128>().map_err(|_| {
                format!(
                    "expected line {target}'s recomputed amount in minor units observed `{amount}`"
                )
            })?
        }
    };
    let output_digest = named("canonical_report")
        .find_map(|c| text(c, "output_digest"))
        .ok_or("expected the canonical report's output digest observed none")?;
    Ok(Recomputation {
        value,
        output_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(verdict: &str, checks: &str) -> String {
        format!(
            r#"{{"v":1,"tool":"fa-verify","command":"report","verdict":"{verdict}","checks":[{checks}],"error":null}}"#
        )
    }

    fn check(name: &str, detail: &str) -> String {
        format!(
            r#"{{"check":"{name}","scope":"recomputation","result":"pass","detail":{{{detail}}},"reason":null}}"#
        )
    }

    const CANONICAL: &str = r#"{"check":"canonical_report","scope":"balance_explanation","result":"pass","detail":{"output_digest":"ab12"},"reason":null}"#;

    /// A balance explanation sums its posted cells in the read's unit; a
    /// pending cell and another unit's cell are not the read's.
    #[test]
    fn explanation_recomputation_sums_the_posted_cells_in_the_unit() {
        let checks = [
            check("balance_explanation", r#""period":"FY2026-P01""#),
            check(
                "balance_explanation_cell",
                r#""column":"posted","unit":1,"debits":"100000","credits":"10000""#,
            ),
            check(
                "balance_explanation_cell",
                r#""column":"pending","unit":1,"debits":"500","credits":"0""#,
            ),
            check(
                "balance_explanation_cell",
                r#""column":"posted","unit":2,"debits":"700","credits":"0""#,
            ),
            CANONICAL.to_string(),
        ]
        .join(",");
        assert_eq!(
            recomputed(
                &report("verified", &checks),
                Recomputed::Explanation,
                "1100",
                1
            ),
            Ok(Recomputation {
                value: 90_000,
                output_digest: "ab12".into()
            })
        );
    }

    /// A trial-balance row and a statement line are found by code and unit;
    /// a report that names neither, or did not verify, recomputes nothing.
    #[test]
    fn row_and_line_recomputations_are_found_by_code_and_unit() {
        let checks = [
            check(
                "trial_balance_row",
                r#""code":"1100","unit":1,"debits":"125000","credits":"0""#,
            ),
            check(
                "statement_line",
                r#""code":"assets","unit":1,"amounts":["125000","0"]"#,
            ),
            CANONICAL.to_string(),
        ]
        .join(",");
        let verified = report("verified", &checks);
        let value = |what, target: &str| recomputed(&verified, what, target, 1).map(|r| r.value);
        assert_eq!(value(Recomputed::TrialBalanceRow, "1100"), Ok(125_000));
        assert_eq!(value(Recomputed::StatementLine, "assets"), Ok(125_000));
        assert_eq!(
            value(Recomputed::StatementLine, "revenue"),
            Err("expected a recomputed statement line revenue observed none".into())
        );
        assert_eq!(
            value(Recomputed::Explanation, "1100"),
            Err("expected a recomputed balance explanation observed none".into())
        );
        assert_eq!(
            recomputed(
                &report("failed", &checks),
                Recomputed::TrialBalanceRow,
                "1100",
                1
            ),
            Err("expected fa-verify report verified observed failed".into())
        );
    }
}
