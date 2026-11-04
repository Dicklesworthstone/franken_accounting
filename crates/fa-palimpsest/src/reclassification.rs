//! Exact movement of a target's remaining legs to new accounts or dimensions.
//! Structural validation and target identity belong to the caller; this pure
//! law consumes the original account, unit, side, dimension key and mantissa.

use std::collections::{BTreeMap, BTreeSet};

/// A borrowed leg's accounting coordinates. `dimensions` is ordered by its
/// canonical value, never by address, so distinct equal keys remain one cell.
pub(crate) struct Leg<'a, D: ?Sized> {
    pub account: u128,
    pub unit: u32,
    pub debit: bool,
    pub dimensions: &'a D,
    pub amount: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Overflow,
    ExceedsSource {
        account: u128,
        unit: u32,
        amount: i128,
        available: i128,
    },
    ReturnsToSource {
        account: u128,
        unit: u32,
    },
    NoSource,
    NoDestination,
    NotConserved {
        unit: u32,
        debit: bool,
        released: i128,
        received: i128,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => {
                formatter.write_str("reclassification amount accumulation overflowed")
            }
            Self::ExceedsSource {
                account,
                unit,
                amount,
                available,
            } => write!(
                formatter,
                "reclassification out of account {account:032x} ({unit}) exceeds target amount ({amount} > {available})"
            ),
            Self::ReturnsToSource { account, unit } => write!(
                formatter,
                "reclassification moves amount back into account {account:032x} ({unit}) with the dimensions it moves out of"
            ),
            Self::NoSource => {
                formatter.write_str("reclassification does not reduce any leg of the target entry")
            }
            Self::NoDestination => formatter.write_str(
                "reclassification must move amount to at least one new account or dimension",
            ),
            Self::NotConserved {
                unit,
                debit,
                released,
                received,
            } => write!(
                formatter,
                "reclassification destinations for unit {unit} on the {} side receive {received}, but the target releases {released}",
                if *debit { "debit" } else { "credit" },
            ),
        }
    }
}

/// Judge a structurally valid reclassification against the target amounts
/// remaining after earlier live reclassifications. A leg releases a source
/// exactly when its opposite side names a target bucket at the same account,
/// unit and dimensions; every other leg is a destination. For each unit and
/// original target side, destinations receive exactly the released amount.
pub(crate) fn validate<'a, D: Ord + ?Sized + 'a>(
    target: impl IntoIterator<Item = Leg<'a, D>>,
    reclassification: impl IntoIterator<Item = Leg<'a, D>>,
) -> Result<(), Error> {
    let mut target_buckets = BTreeMap::<(u128, u32, bool, &D), i128>::new();
    for leg in target {
        let key = (leg.account, leg.unit, leg.debit, leg.dimensions);
        let slot = target_buckets.entry(key).or_default();
        *slot = slot.checked_add(leg.amount).ok_or(Error::Overflow)?;
    }

    let mut reduced_buckets = BTreeMap::<(u128, u32, bool, &D), i128>::new();
    // (unit, original side) -> (released from target, received at destination).
    // Source legs have the opposite side to the position they release.
    let mut transfers = BTreeMap::<(u32, bool), (i128, i128)>::new();
    let mut sources = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    for leg in reclassification {
        let target_key = (leg.account, leg.unit, !leg.debit, leg.dimensions);
        let place = (leg.account, leg.unit, leg.dimensions);
        if let Some(&available) = target_buckets.get(&target_key) {
            sources.insert(place);
            let slot = reduced_buckets.entry(target_key).or_default();
            *slot = slot.checked_add(leg.amount).ok_or(Error::Overflow)?;
            if *slot > available {
                return Err(Error::ExceedsSource {
                    account: leg.account,
                    unit: leg.unit,
                    amount: *slot,
                    available,
                });
            }
            let released = &mut transfers.entry((leg.unit, !leg.debit)).or_default().0;
            *released = released.checked_add(leg.amount).ok_or(Error::Overflow)?;
        } else {
            destinations.insert(place);
            let received = &mut transfers.entry((leg.unit, leg.debit)).or_default().1;
            *received = received.checked_add(leg.amount).ok_or(Error::Overflow)?;
        }
    }

    if let Some(&(account, unit, _)) = destinations.intersection(&sources).next() {
        return Err(Error::ReturnsToSource { account, unit });
    }
    if reduced_buckets.is_empty() {
        return Err(Error::NoSource);
    }
    if destinations.is_empty() {
        return Err(Error::NoDestination);
    }
    for ((unit, debit), (released, received)) in transfers {
        if released != received {
            return Err(Error::NotConserved {
                unit,
                debit,
                released,
                received,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leg(account: u128, unit: u32, debit: bool, amount: i128) -> Leg<'static, [u32]> {
        Leg {
            account,
            unit,
            debit,
            dimensions: &[],
            amount,
        }
    }

    fn target() -> [Leg<'static, [u32]>; 2] {
        [leg(6000, 0, true, 100), leg(1000, 0, false, 100)]
    }

    #[test]
    fn a_reclassification_cannot_attach_an_unrelated_balanced_pair() {
        let result = validate(
            target(),
            [
                leg(6000, 0, false, 1),
                leg(6100, 0, true, 1),
                leg(6200, 0, true, 50_000),
                leg(1000, 0, false, 50_000),
            ],
        );
        assert!(
            matches!(result, Err(Error::NotConserved { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn balanced_foreign_unit_destinations_cannot_replace_the_source_unit() {
        let result = validate(
            target(),
            [
                leg(6000, 0, false, 40),
                leg(1000, 0, true, 40),
                leg(6100, 1, true, 40),
                leg(1100, 1, false, 40),
            ],
        );
        assert!(
            matches!(result, Err(Error::NotConserved { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn source_side_means_the_target_side_before_negation() {
        // This isolates the shape law: the monetary kernel also rejects this
        // side exchange earlier because it does not balance debits/credits.
        let result = validate(
            target(),
            [
                leg(6000, 0, false, 70),
                leg(1000, 0, true, 30),
                leg(6100, 0, true, 30),
                leg(1100, 0, false, 70),
            ],
        );
        assert!(
            matches!(result, Err(Error::NotConserved { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn split_sources_and_destinations_preserve_each_unit_and_both_sides() {
        assert_eq!(
            validate(
                [
                    leg(6000, 0, true, 20),
                    leg(6000, 0, true, 80),
                    leg(1000, 0, false, 100),
                    leg(7000, 1, true, 90),
                    leg(2000, 1, false, 90),
                ],
                [
                    leg(6000, 0, false, 10),
                    leg(6000, 0, false, 60),
                    leg(6100, 0, true, 20),
                    leg(6200, 0, true, 50),
                    leg(1000, 0, true, 30),
                    leg(1100, 0, false, 30),
                    leg(7000, 1, false, 9),
                    leg(7100, 1, true, 9),
                ],
            ),
            Ok(())
        );
    }

    #[test]
    fn dimension_only_moves_and_leg_order_do_not_change_the_law() {
        let old = [1];
        let new = [2];
        let original = || {
            [
                Leg {
                    dimensions: old.as_slice(),
                    ..leg(6000, 0, true, 100)
                },
                Leg {
                    dimensions: old.as_slice(),
                    ..leg(1000, 0, false, 100)
                },
            ]
        };
        let movements = || {
            [
                Leg {
                    dimensions: old.as_slice(),
                    ..leg(6000, 0, false, 37)
                },
                Leg {
                    dimensions: new.as_slice(),
                    ..leg(6000, 0, true, 37)
                },
                Leg {
                    dimensions: old.as_slice(),
                    ..leg(1000, 0, true, 37)
                },
                Leg {
                    dimensions: new.as_slice(),
                    ..leg(1000, 0, false, 37)
                },
            ]
        };
        assert_eq!(validate(original(), movements()), Ok(()));
        assert_eq!(validate(original(), movements().into_iter().rev()), Ok(()));
    }

    #[test]
    fn source_limits_no_op_refusal_and_checked_arithmetic_remain_enforced() {
        assert!(matches!(
            validate(
                target(),
                [leg(6000, 0, false, 101), leg(6100, 0, true, 101)],
            ),
            Err(Error::ExceedsSource { .. })
        ));
        assert!(matches!(
            validate(target(), [leg(6000, 0, false, 1), leg(6000, 0, true, 1)],),
            Err(Error::ReturnsToSource { .. })
        ));
        assert_eq!(
            validate(target(), [leg(6100, 0, true, 1), leg(1100, 0, false, 1)],),
            Err(Error::NoSource)
        );
        assert_eq!(
            validate(target(), [leg(6000, 0, false, 1), leg(1000, 0, true, 1)],),
            Err(Error::NoDestination)
        );
        assert_eq!(
            validate(
                [leg(6000, 0, true, i128::MAX), leg(6000, 0, true, 1)],
                [leg(6000, 0, false, 1), leg(6100, 0, true, 1)],
            ),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn maximum_representable_moves_keep_exact_amounts_and_never_wrap() {
        assert_eq!(
            validate(
                [leg(6000, 0, true, i128::MAX)],
                [
                    leg(6000, 0, false, i128::MAX),
                    leg(6100, 0, true, i128::MAX - 1),
                    leg(6200, 0, true, 1),
                ],
            ),
            Ok(())
        );
        assert_eq!(
            validate(
                [leg(6000, 0, true, i128::MAX), leg(6001, 0, true, 1)],
                [
                    leg(6000, 0, false, i128::MAX),
                    leg(6001, 0, false, 1),
                    leg(6100, 0, true, i128::MAX),
                    leg(6101, 0, true, 1),
                ],
            ),
            Err(Error::Overflow)
        );
    }
}
