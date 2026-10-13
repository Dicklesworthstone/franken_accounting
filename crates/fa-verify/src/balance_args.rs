//! Recipient-owned CLI expectations, parsed before any proof or anchor I/O.
//! The scope is all-or-nothing: omitted cutoff must never become a wildcard.

use std::ffi::OsString;
use std::str::FromStr;

use fa_verify::{BalanceAmounts, BalanceExpectation, BalanceScope};

use super::Failure;

#[derive(Default)]
pub(super) struct BalanceArgs {
    account: Option<u128>,
    unit: Option<u32>,
    through: Option<Option<i32>>,
    debits: Option<i128>,
    credits: Option<i128>,
}

impl BalanceArgs {
    /// Consume only a recognized two-argument expectation option. Other
    /// options remain with the main parser; no path is converted to UTF-8.
    pub(super) fn consume(&mut self, args: &[OsString], index: usize) -> Result<bool, Failure> {
        let Some(name) = args.get(index).and_then(|arg| arg.to_str()) else {
            return Ok(false);
        };
        if !matches!(
            name,
            "--expect-account"
                | "--expect-unit"
                | "--expect-through"
                | "--expect-debits"
                | "--expect-credits"
        ) {
            return Ok(false);
        }
        let value = args
            .get(index + 1)
            .and_then(|arg| arg.to_str())
            .ok_or_else(|| {
                Failure::usage(format!(
                    "{name} requires a UTF-8 value; run fa-verify --help"
                ))
            })?;
        match name {
            "--expect-account" => {
                if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(Failure::usage(
                        "--expect-account requires exactly 32 hexadecimal digits",
                    ));
                }
                let account = u128::from_str_radix(value, 16).map_err(|_| {
                    Failure::usage("--expect-account is outside the account identifier range")
                })?;
                set(&mut self.account, account, name)?;
            }
            "--expect-unit" => set(&mut self.unit, decimal(value, name, false)?, name)?,
            "--expect-through" => {
                let through = if value == "none" {
                    None
                } else {
                    Some(decimal(value, name, true)?)
                };
                set(&mut self.through, through, name)?;
            }
            "--expect-debits" => set(&mut self.debits, decimal(value, name, false)?, name)?,
            "--expect-credits" => set(&mut self.credits, decimal(value, name, false)?, name)?,
            _ => unreachable!("recognized expectation option"),
        }
        Ok(true)
    }

    pub(super) fn finish(self, is_balance: bool) -> Result<Option<BalanceExpectation>, Failure> {
        if self.account.is_none()
            && self.unit.is_none()
            && self.through.is_none()
            && self.debits.is_none()
            && self.credits.is_none()
        {
            return Ok(None);
        }
        if !is_balance {
            return Err(Failure::usage(
                "--expect-* options are admitted only for balance",
            ));
        }
        let (Some(account), Some(unit), Some(effective_through)) =
            (self.account, self.unit, self.through)
        else {
            return Err(Failure::usage(
                "balance expectations require --expect-account, --expect-unit and --expect-through together; use none for an unbounded cutoff",
            ));
        };
        let amounts = match (self.debits, self.credits) {
            (None, None) => None,
            (Some(debits), Some(credits)) => Some(BalanceAmounts { debits, credits }),
            _ => {
                return Err(Failure::usage(
                    "--expect-debits and --expect-credits must be supplied together",
                ));
            }
        };
        Ok(Some(BalanceExpectation {
            scope: BalanceScope {
                account,
                unit,
                effective_through,
            },
            amounts,
        }))
    }
}

fn set<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), Failure> {
    if slot.is_some() {
        return Err(Failure::usage(format!("{name} may be supplied only once")));
    }
    *slot = Some(value);
    Ok(())
}

fn decimal<T: FromStr>(value: &str, name: &str, signed: bool) -> Result<T, Failure> {
    let digits = if signed {
        value.strip_prefix('-').unwrap_or(value)
    } else {
        value
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage(format!(
            "{name} requires an exact decimal integer, without rounding or separators"
        )));
    }
    value
        .parse()
        .map_err(|_| Failure::usage(format!("{name} is outside its integer range")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAGS: [(&str, &str); 5] = [
        ("--expect-account", "00000000000000000000000000000030"),
        ("--expect-unit", "1"),
        ("--expect-through", "none"),
        ("--expect-debits", "0"),
        ("--expect-credits", "120550"),
    ];

    fn parse(pairs: &[(&str, &str)], balance: bool) -> Result<Option<BalanceExpectation>, Failure> {
        let mut parsed = BalanceArgs::default();
        for (name, value) in pairs {
            assert!(parsed.consume(&[(*name).into(), (*value).into()], 0)?);
        }
        parsed.finish(balance)
    }

    #[test]
    fn only_complete_scopes_and_complete_amount_pairs_are_admitted() {
        for mask in 0..32 {
            let pairs: Vec<_> = FLAGS
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1u32 << *index) != 0)
                .map(|(_, pair)| *pair)
                .collect();
            let result = parse(&pairs, true);
            assert_eq!(result.is_ok(), matches!(mask, 0 | 7 | 31), "mask {mask}");
            if let Err(failure) = result {
                assert_eq!(failure.exit, 2);
            }
        }
    }

    #[test]
    fn boundaries_are_exact_and_none_is_an_explicit_value() {
        let parsed = parse(&FLAGS, true)
            .unwrap_or_else(|failure| panic!("{}", failure.message))
            .unwrap();
        assert_eq!(parsed.scope.account, 0x30);
        assert_eq!(parsed.scope.effective_through, None);
        assert_eq!(parsed.amounts.unwrap().credits, 120550);
        let maximum = i128::MAX.to_string();
        let pairs = [
            ("--expect-account", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            ("--expect-unit", "4294967295"),
            ("--expect-through", "-2147483648"),
            ("--expect-debits", maximum.as_str()),
            ("--expect-credits", "0"),
        ];
        let parsed = parse(&pairs, true)
            .unwrap_or_else(|failure| panic!("{}", failure.message))
            .unwrap();
        assert_eq!(parsed.scope.account, u128::MAX);
        assert_eq!(parsed.scope.unit, u32::MAX);
        assert_eq!(parsed.scope.effective_through, Some(i32::MIN));
        assert_eq!(parsed.amounts.unwrap().debits, i128::MAX);
    }

    #[test]
    fn duplicate_options_including_unbounded_cutoff_are_usage_errors() {
        for pair in FLAGS {
            let failure = parse(&[pair, pair], true).err().expect("duplicate refused");
            assert!(failure.message.contains("only once"));
        }
    }

    #[test]
    fn malformed_or_overflowing_numbers_are_never_rounded_or_coerced() {
        for (name, values) in [
            (
                "--expect-account",
                vec![
                    "30",
                    "0000000000000000000000000000000g",
                    "0x000000000000000000000000000030",
                ],
            ),
            ("--expect-unit", vec!["-1", "4294967296", "1.0", "+1", "１"]),
            (
                "--expect-through",
                vec![
                    "2147483648",
                    "-2147483649",
                    "all",
                    "null",
                    "2026-10-13",
                    "--json",
                ],
            ),
            (
                "--expect-debits",
                vec![
                    "-1",
                    "170141183460469231731687303715884105728",
                    "1e6",
                    "1,000",
                    " 1",
                ],
            ),
            ("--expect-credits", vec!["-1", "0.0", "+0", "NaN", ""]),
        ] {
            for value in values {
                let mut parsed = BalanceArgs::default();
                let result = parsed.consume(&[name.into(), value.into()], 0);
                assert!(result.is_err(), "{name} {value}");
            }
        }
    }

    #[test]
    fn missing_values_and_other_commands_cannot_silently_skip_expectations() {
        for (name, _) in FLAGS {
            let mut parsed = BalanceArgs::default();
            assert!(parsed.consume(&[name.into()], 0).is_err());
        }
        assert!(parse(&FLAGS, false).is_err());
        assert!(
            parse(&[], false)
                .unwrap_or_else(|failure| panic!("{}", failure.message))
                .is_none()
        );
        let mut parsed = BalanceArgs::default();
        assert!(
            !parsed
                .consume(&["--proof".into(), "file".into()], 0)
                .unwrap_or_else(|failure| panic!("{}", failure.message))
        );
        assert!(
            !parsed
                .consume(&["--expect-unknown".into()], 0)
                .unwrap_or_else(|failure| panic!("{}", failure.message))
        );
    }
}
