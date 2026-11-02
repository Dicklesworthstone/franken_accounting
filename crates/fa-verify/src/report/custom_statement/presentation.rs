//! Exact presentation units and explicitly emitted formula residuals.

use super::super::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, statement, text};
use crate::codec::{Reader, Writer};
use statement::definition::{Definition, Source};
use std::collections::BTreeMap;

const SPEC_FORMAT: &[u8] = b"fa:presentation-rounding-spec:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:presented-statement:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PresentationSpec {
    pub rounding_law: u16,
    pub scale_reduction_digits: u8,
    pub residual_line_code: String,
    pub residual_line_label: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedStatementLine {
    pub code: String,
    pub label: String,
    pub unit: u32,
    pub exact_amounts: Vec<i128>,
    pub presented_amounts: Vec<i128>,
    pub rounding_errors: Vec<i128>,
    pub is_residual_line: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPresentedStatement {
    pub rounding_law: u16,
    pub scale_reduction_digits: u8,
    pub divisor: i128,
    pub lines: Vec<PresentedStatementLine>,
}

impl PresentationSpec {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ReportError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<{ SPEC_FORMAT.len() }>("custom.presentation.format")? != SPEC_FORMAT {
            return Err(failed(
                "presentation_rounding",
                "unknown presentation specification format",
            ));
        }
        let rounding_law = r.u16("custom.presentation.law")?;
        let scale_reduction_digits = r.u8("custom.presentation.digits")?;
        let residual_line_code = text(&mut r, 64, "custom.presentation.residual_code")?.to_string();
        let residual_line_label =
            text(&mut r, 256, "custom.presentation.residual_label")?.to_string();
        r.finish("custom presentation specification")?;
        if !(1..=9).contains(&rounding_law)
            || scale_reduction_digits > 38
            || residual_line_code.is_empty()
            || !residual_line_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || residual_line_label.trim().is_empty()
        {
            return Err(failed(
                "presentation_rounding",
                "unregistered law, invalid decimal scale or residual label",
            ));
        }
        Ok(Self {
            rounding_law,
            scale_reduction_digits,
            residual_line_code,
            residual_line_label,
        })
    }
}

fn overflow() -> ReportError {
    failed(
        "exact_arithmetic",
        "custom presentation rounding exceeds the exact mantissa range",
    )
}

fn signed(magnitude: u128, negative: bool) -> Option<i128> {
    if negative && magnitude == i128::MIN.unsigned_abs() {
        Some(i128::MIN)
    } else {
        let value = i128::try_from(magnitude).ok()?;
        if negative {
            value.checked_neg()
        } else {
            Some(value)
        }
    }
}

fn rounded(exact: i128, divisor: u128, law: u16) -> Option<(i128, i128)> {
    if divisor == 0 || !(1..=9).contains(&law) {
        return None;
    }
    let negative = exact < 0;
    let q = exact.unsigned_abs() / divisor;
    let r = exact.unsigned_abs() % divisor;
    let twice_remainder = r.cmp(&(divisor - r));
    let increment = r != 0
        && match law {
            1 => twice_remainder.is_gt() || twice_remainder.is_eq() && !negative,
            2 => twice_remainder.is_gt() || twice_remainder.is_eq() && negative,
            3 => twice_remainder.is_gt() || twice_remainder.is_eq() && q % 2 == 1,
            4 => !twice_remainder.is_lt(),
            5 => twice_remainder.is_gt(),
            6 => !negative,
            7 => negative,
            8 => false,
            9 => true,
            _ => return None,
        };
    let magnitude = q.checked_add(u128::from(increment))?;
    let presented = signed(magnitude, negative)?;
    // Scale-back must also fit the producer's exact signed representation.
    // Checked multiplication is sufficient: larger u128 results could not
    // narrow to that representation either.
    let scaled_back = signed(magnitude.checked_mul(divisor)?, negative)?;
    let error = scaled_back.checked_sub(exact)?;
    if law <= 5 {
        if error.unsigned_abs().checked_mul(2)? > divisor {
            return None;
        }
    } else if error.unsigned_abs() >= divisor {
        return None;
    }
    Some((presented, error))
}

struct OutputBudget(usize);
impl OutputBudget {
    fn add(&mut self, size: usize) -> Result<(), ReportError> {
        self.0 = self
            .0
            .checked_add(size)
            .ok_or_else(|| failed("bounded_input", "presentation output size overflow"))?;
        if self.0 > MAX_REPORT_BUNDLE_BYTES {
            return Err(failed(
                "bounded_input",
                "combined exact and presented custom output exceeds 64 MiB",
            ));
        }
        Ok(())
    }
    fn row(&mut self, code: &str, label: &str, columns: usize) -> Result<(), ReportError> {
        self.add(25 + code.len() + label.len() + 48 * columns)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    spec: &PresentationSpec,
    definition: &Definition,
    statement: &statement::VerifiedStatement,
    book: &[u8; 16],
    branch: &[u8; 16],
    known_at: u64,
    containing_bytes: usize,
) -> Result<(VerifiedPresentedStatement, Vec<u8>), ReportError> {
    let divisor = 10u128.pow(u32::from(spec.scale_reduction_digits));
    let divisor_signed = i128::try_from(divisor).map_err(|_| overflow())?;
    let mut w = Writer::default();
    w.fixed(OUTPUT_FORMAT)
        .fixed(book)
        .fixed(branch)
        .u64(known_at)
        .bytes(statement.definition_name.as_bytes())
        .u32(statement.definition_version)
        .fixed(&statement.definition_digest)
        .u16(spec.rounding_law)
        .u8(spec.scale_reduction_digits)
        .i128(divisor_signed)
        .count(statement.columns.len());
    for column in &statement.columns {
        w.bytes(column.label.as_bytes()).count(column.periods.len());
        for period in &column.periods {
            w.bytes(period.as_bytes());
        }
        w.u8(u8::from(column.effective_from.is_some()));
        if let Some(day) = column.effective_from {
            w.i32(day);
        }
        w.i32(column.effective_through);
    }
    let mut budget = OutputBudget(containing_bytes);
    budget.add(w.buf.len() + 4)?;
    let mut lines = Vec::new();
    let columns = statement.columns.len();
    for (unit_index, &unit) in statement.units.iter().enumerate() {
        let mut earlier = BTreeMap::<&str, Vec<i128>>::new();
        for (line_index, line) in definition.lines.iter().enumerate() {
            // Exact statement rows have line-major, then unit-major order.
            let exact = &statement.lines[line_index * statement.units.len() + unit_index];
            if exact.code != line.code || exact.unit != unit || exact.amounts.len() != columns {
                return Err(failed(
                    "presentation_rounding",
                    "exact statement and definition rows disagree",
                ));
            }
            let mut amounts = Vec::with_capacity(columns);
            let mut errors = Vec::with_capacity(columns);
            for &amount in &exact.amounts {
                let (shown, error) =
                    rounded(amount, divisor, spec.rounding_law).ok_or_else(overflow)?;
                amounts.push(shown);
                errors.push(error);
            }
            if let Source::Formula { add, subtract } = &line.source {
                let mut residuals = Vec::with_capacity(columns);
                for (column, shown) in amounts.iter().enumerate() {
                    let mut total = statement::Sum::default();
                    for (operands, subtracting) in [(add, false), (subtract, true)] {
                        for operand in operands {
                            total
                                .add(earlier[operand.as_str()][column], subtracting)
                                .ok_or_else(overflow)?;
                        }
                    }
                    residuals.push(
                        shown
                            .checked_sub(total.value().ok_or_else(overflow)?)
                            .ok_or_else(overflow)?,
                    );
                }
                if residuals.iter().any(|residual| *residual != 0) {
                    let code = format!("{}_{}", line.code, spec.residual_line_code);
                    let label = format!("{} ({})", spec.residual_line_label, line.label);
                    budget.row(&code, &label, columns)?;
                    let rounding_errors = residuals
                        .iter()
                        .map(|amount| amount.checked_mul(divisor_signed).ok_or_else(overflow))
                        .collect::<Result<Vec<_>, _>>()?;
                    lines.push(PresentedStatementLine {
                        code,
                        label,
                        unit,
                        exact_amounts: vec![0; columns],
                        presented_amounts: residuals,
                        rounding_errors,
                        is_residual_line: true,
                    });
                }
            }
            budget.row(&line.code, &line.label, columns)?;
            earlier.insert(line.code.as_str(), amounts.clone());
            lines.push(PresentedStatementLine {
                code: line.code.clone(),
                label: line.label.clone(),
                unit,
                exact_amounts: exact.amounts.clone(),
                presented_amounts: amounts,
                rounding_errors: errors,
                is_residual_line: false,
            });
        }
    }
    w.count(lines.len());
    for line in &lines {
        w.bytes(line.code.as_bytes())
            .bytes(line.label.as_bytes())
            .u32(line.unit);
        for amounts in [
            &line.exact_amounts,
            &line.presented_amounts,
            &line.rounding_errors,
        ] {
            w.count(amounts.len());
            for amount in amounts {
                w.i128(*amount);
            }
        }
        w.u8(u8::from(line.is_residual_line));
    }
    Ok((
        VerifiedPresentedStatement {
            rounding_law: spec.rounding_law,
            scale_reduction_digits: spec.scale_reduction_digits,
            divisor: divisor_signed,
            lines,
        },
        w.buf,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_registered_tie_directions_and_even_parity_are_signed_exactly() {
        let positive = [3, 2, 2, 3, 2, 3, 2, 2, 3];
        let negative = [-2, -3, -2, -3, -2, -2, -3, -2, -3];
        for law in 1..=9 {
            assert_eq!(
                rounded(25, 10, law),
                Some((
                    positive[usize::from(law - 1)],
                    positive[usize::from(law - 1)] * 10 - 25
                ))
            );
            assert_eq!(
                rounded(-25, 10, law),
                Some((
                    negative[usize::from(law - 1)],
                    negative[usize::from(law - 1)] * 10 + 25
                ))
            );
        }
        assert_eq!(rounded(35, 10, 3), Some((4, 5)));
        assert_eq!(rounded(-35, 10, 3), Some((-4, -5)));
        assert_eq!(rounded(24, 10, 1), Some((2, -4)));
        assert_eq!(rounded(-26, 10, 2), Some((-3, -4)));
    }

    #[test]
    fn exact_minimum_and_scale_back_overflow_follow_native_bounds() {
        for law in 1..=9 {
            assert_eq!(rounded(i128::MIN, 1, law), Some((i128::MIN, 0)));
            assert_eq!(rounded(i128::MAX, 1, law), Some((i128::MAX, 0)));
        }
        assert!(rounded(i128::MAX, 10, 9).is_none());
        assert!(rounded(i128::MIN, 10, 9).is_none());
        assert_eq!(rounded(i128::MIN, 10, 8), Some((i128::MIN / 10, 8)));
        assert_eq!(rounded(1, 10u128.pow(38), 3), Some((0, -1)));
    }
}
