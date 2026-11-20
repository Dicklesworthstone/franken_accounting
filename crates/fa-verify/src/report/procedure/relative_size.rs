//! Additional RSF regression controls and a decimal long-division oracle.
//!
//! Production uses the shared number-analytics implementation and its binary
//! long division. This test-only module preserves an independent decimal
//! construction and hostile-claim tests without a second production profile.

use std::collections::BTreeMap;

use super::{
    Entry, Reader, Registry, ReportError, VerifiedProcedureFinding, VerifiedProcedureParameters,
    VerifiedProcedureStatistic, failed,
};

const DEFAULTS: [(&str, u32); 2] = super::RSF_DEFAULTS;

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "relative-size factor exceeds exact arithmetic",
    )
}

fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    super::decode(reader, false)
}

fn basis_points(largest: i128, second: i128) -> Result<i128, ReportError> {
    if largest <= 0 || second <= 0 {
        return Err(arithmetic());
    }
    let whole = (largest / second)
        .checked_mul(10_000)
        .ok_or_else(arithmetic)?;
    let mut remainder = largest % second;
    let mut fraction = 0;
    for _ in 0..4 {
        // Compute one decimal digit and the next remainder by modular
        // addition. Both operands stay below second; subtraction across the
        // boundary avoids the otherwise overflowing remainder * 10 product.
        let mut next_remainder = 0;
        let mut digit = 0;
        for _ in 0..10 {
            let distance = second - remainder;
            if next_remainder >= distance {
                next_remainder -= distance;
                digit += 1;
            } else {
                next_remainder += remainder;
            }
        }
        fraction = fraction * 10 + digit;
        remainder = next_remainder;
    }
    whole.checked_add(fraction).ok_or_else(arithmetic)
}

#[path = "relative_size/tests.rs"]
mod tests;
