//! Optional exact stock-cell requests; parse completely before any artifact I/O.

use std::ffi::OsString;

use fa_verify::checkpoint::witness::bundle::balances::{
    MAX_REQUESTED_BUNDLE_BALANCES, validate_balance_expectations,
};
use fa_verify::{BalanceAmounts, BalanceExpectation, BalanceScope};

use crate::{Failure, array, object, quote};

#[derive(Default)]
pub(super) struct BalanceArgs {
    cells: Vec<BalanceExpectation>,
    empty: bool,
}

impl BalanceArgs {
    /// Number of consumed arguments, or None when the parent owns this flag.
    pub(super) fn consume(
        &mut self,
        args: &[OsString],
        index: usize,
    ) -> Result<Option<usize>, Failure> {
        match args.get(index).and_then(|arg| arg.to_str()) {
            Some("--expect-no-balances") => {
                if self.empty {
                    return Err(Failure::usage("--expect-no-balances may be supplied only once"));
                }
                self.empty = true;
                Ok(Some(1))
            }
            Some("--expect-balance") => {
                if self.cells.len() == MAX_REQUESTED_BUNDLE_BALANCES {
                    return Err(Failure::usage("at most 4096 --expect-balance options are permitted"));
                }
                let value = args.get(index + 1).and_then(|arg| arg.to_str())
                    .ok_or_else(|| Failure::usage("--expect-balance requires an ASCII cell request"))?;
                self.cells.push(parse_cell(value)?);
                Ok(Some(2))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn finish(self) -> Result<Option<Vec<BalanceExpectation>>, Failure> {
        if self.empty && !self.cells.is_empty() {
            return Err(Failure::usage(
                "--expect-no-balances cannot be combined with --expect-balance",
            ));
        }
        validate_balance_expectations(&self.cells)
            .map_err(|error| Failure::usage(error.to_string()))?;
        Ok(if self.empty || !self.cells.is_empty() {
            Some(self.cells)
        } else {
            None
        })
    }
}

fn unsigned(text: &str, maximum_digits: usize) -> bool {
    !text.is_empty() && text.len() <= maximum_digits
        && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn gross(text: &str) -> Result<i128, Failure> {
    if !unsigned(text, 39) {
        return Err(Failure::usage("gross amounts must be nonnegative decimal i128 mantissas"));
    }
    text.parse().map_err(|_| Failure::usage("gross amount exceeds i128"))
}

fn parse_cell(text: &str) -> Result<BalanceExpectation, Failure> {
    // Bound before allocating split fields: HEX32:u32:i32:i128:i128 at maxima.
    if text.len() > 135 || !text.is_ascii() {
        return Err(Failure::usage("--expect-balance is too long or is not ASCII"));
    }
    let fields: Vec<_> = text.split(':').collect();
    if fields.len() != 3 && fields.len() != 5 {
        return Err(Failure::usage(
            "--expect-balance requires ACCOUNT32:UNIT:DAY|none[:DEBITS:CREDITS]",
        ));
    }
    let account = fields[0];
    if account.len() != 32 || !account.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage("balance account requires exactly 32 ASCII hex digits"));
    }
    let account = u128::from_str_radix(account, 16)
        .map_err(|_| Failure::usage("invalid balance account"))?;
    if !unsigned(fields[1], 10) {
        return Err(Failure::usage("balance unit requires a decimal u32"));
    }
    let unit = fields[1].parse::<u32>()
        .map_err(|_| Failure::usage("balance unit exceeds u32"))?;
    let effective_through = match fields[2] {
        "none" => None,
        day => Some(super::day(day)?),
    };
    let amounts = if fields.len() == 5 {
        Some(BalanceAmounts { debits: gross(fields[3])?, credits: gross(fields[4])? })
    } else {
        None
    };
    Ok(BalanceExpectation {
        scope: BalanceScope { account, unit, effective_through },
        amounts,
    })
}

/// Render recipient expectations, never unchecked proof claims. Decimal strings
/// preserve exact integers for consumers whose JSON numbers are IEEE doubles.
pub(super) fn json(cells: Option<&[BalanceExpectation]>) -> String {
    let Some(cells) = cells else {
        return object([("mode", quote("not_requested"))]);
    };
    object([
        ("mode", quote("exact")),
        ("cells", array(cells.iter().map(|cell| object([
            ("account", quote(&format!("{:032x}", cell.scope.account))),
            ("unit", quote(&cell.scope.unit.to_string())),
            ("effective_through_day", cell.scope.effective_through
                .map_or_else(|| "null".into(), |day| quote(&day.to_string()))),
            ("amounts", cell.amounts.map_or_else(|| "null".into(), |amounts| object([
                ("debits_mantissa", quote(&amounts.debits.to_string())),
                ("credits_mantissa", quote(&amounts.credits.to_string())),
            ]))),
        ])))),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish(extra: &[&str]) -> Result<Option<Vec<BalanceExpectation>>, Failure> {
        let args: Vec<_> = extra.iter().map(OsString::from).collect();
        let mut parsed = BalanceArgs::default();
        let mut index = 0;
        while index < args.len() {
            let count = parsed.consume(&args, index)?.expect("known test option");
            index += count;
        }
        parsed.finish()
    }

    #[test]
    fn exact_unsigned_and_signed_boundaries_are_not_rounded_or_relabelled() {
        let text = format!("{:032X}:{}:{}:{}:{}", u128::MAX, u32::MAX, i32::MIN, i128::MAX, 0);
        let parsed = parse_cell(&text).map_err(|error| error.message).unwrap();
        assert_eq!(parsed.scope.account, u128::MAX);
        assert_eq!(parsed.scope.unit, u32::MAX);
        assert_eq!(parsed.scope.effective_through, Some(i32::MIN));
        assert_eq!(parsed.amounts, Some(BalanceAmounts { debits: i128::MAX, credits: 0 }));
        let rendered = json(Some(&[parsed]));
        assert!(rendered.contains("\"effective_through_day\":\"-2147483648\""));
        assert!(rendered.contains(&format!("\"debits_mantissa\":\"{}\"", i128::MAX)));
        assert!(rendered.contains("\"unit\":\"4294967295\""));
        let learn = parse_cell(&format!("{:032x}:1:none", 10)).map_err(|e| e.message).unwrap();
        assert_eq!(learn.scope.effective_through, None);
        assert_eq!(learn.amounts, None);
    }

    #[test]
    fn malformed_scalars_partial_amount_pairs_and_floats_refuse() {
        let account = format!("{:032x}", 10);
        for suffix in [
            "1", "1:none:0", "1:none:0:0:0", "1:any", "1:2147483648",
            "1:-2147483649", "4294967296:none", "+1:none", "-1:none",
            "1:none:-1:0", "1:none:+1:0", "1:none:1.0:0", "1:none: 1:0",
            "1:none:170141183460469231731687303715884105728:0",
            "1:none:0:", "1:none::0", "1:none:０:0",
        ] {
            assert!(parse_cell(&format!("{account}:{suffix}")).is_err(), "{suffix}");
        }
        for account in ["a".repeat(31), "a".repeat(33), "g".repeat(32)] {
            assert!(parse_cell(&format!("{account}:1:none")).is_err());
        }
        assert!(parse_cell(&"a".repeat(136)).is_err());
    }

    #[test]
    fn empty_exact_unspecified_duplicates_and_conflicting_modes_remain_distinct() {
        assert!(finish(&[]).map_err(|e| e.message).unwrap().is_none());
        assert_eq!(finish(&["--expect-no-balances"]).map_err(|e| e.message).unwrap(), Some(vec![]));
        let a = format!("{:032x}:1:none", 10);
        let a_amounts = format!("{a}:0:0");
        assert!(finish(&["--expect-balance", &a, "--expect-balance", &a_amounts]).is_err());
        assert!(finish(&["--expect-no-balances", "--expect-balance", &a]).is_err());
        assert!(finish(&["--expect-no-balances", "--expect-no-balances"]).is_err());
        assert!(finish(&["--expect-balance"]).is_err());
        let b = format!("{:032x}:1:2147483647", 10);
        assert_eq!(finish(&["--expect-balance", &b, "--expect-balance", &a])
            .map_err(|e| e.message).unwrap().unwrap().len(), 2);
        assert_eq!(json(None), "{\"mode\":\"not_requested\"}");
        assert_eq!(json(Some(&[])), "{\"mode\":\"exact\",\"cells\":[]}");
    }

    #[test]
    fn request_limit_is_enforced_before_adding_an_extra_cell() {
        let mut parser = BalanceArgs::default();
        for index in 0..MAX_REQUESTED_BUNDLE_BALANCES {
            let args = [OsString::from("--expect-balance"),
                OsString::from(format!("{index:032x}:1:none"))];
            assert_eq!(parser.consume(&args, 0).map_err(|e| e.message).unwrap(), Some(2));
        }
        let args = ["--expect-balance".into(), format!("{:032x}:1:none", u128::MAX).into()];
        assert!(parser.consume(&args, 0).is_err());
        assert_eq!(parser.finish().map_err(|e| e.message).unwrap().unwrap().len(),
            MAX_REQUESTED_BUNDLE_BALANCES);
    }
}
