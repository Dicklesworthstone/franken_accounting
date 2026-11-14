//! Checked projection of an immutable application's exact historical relief.
//!
//! A reversal changes the sign of a recorded effect; it never prices a new
//! application from today's ratio. Valuation remains a separate component.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Components {
    pub(crate) native: i128,
    pub(crate) historical: i128,
    pub(crate) valuation: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectionError {
    InvalidRelief,
    Overflow,
    Capacity,
    Stranded,
}

/// Apply or undo one retained nonallocated application. Original capacities
/// bound the native and historical components; valuation may be signed.
pub(crate) fn project(
    current: Components,
    original_native: i128,
    original_historical: i128,
    native_relief: i128,
    historical_relief: i128,
    undo: bool,
) -> Result<Components, ProjectionError> {
    project_recorded(
        current,
        original_native,
        original_historical,
        Components {
            native: native_relief,
            historical: historical_relief,
            valuation: 0,
        },
        undo,
    )
}

/// Apply the exact historical-cost and signed valuation components of an
/// authenticated application. A later closing rate never reprices this effect.
pub(crate) fn project_recorded(
    current: Components,
    original_native: i128,
    original_historical: i128,
    relief: Components,
    undo: bool,
) -> Result<Components, ProjectionError> {
    let total_relief = relief
        .historical
        .checked_add(relief.valuation)
        .ok_or(ProjectionError::Overflow)?;
    if relief.native <= 0 || relief.historical < 0 || total_relief < 0 {
        return Err(ProjectionError::InvalidRelief);
    }
    let change = |value: i128, relief: i128| {
        if undo {
            value.checked_add(relief)
        } else {
            value.checked_sub(relief)
        }
        .ok_or(ProjectionError::Overflow)
    };
    let next = Components {
        native: change(current.native, relief.native)?,
        historical: change(current.historical, relief.historical)?,
        valuation: change(current.valuation, relief.valuation)?,
    };
    let total = next
        .historical
        .checked_add(next.valuation)
        .ok_or(ProjectionError::Overflow)?;
    if next.native < 0
        || next.native > original_native
        || next.historical < 0
        || next.historical > original_historical
        || total < 0
    {
        return Err(ProjectionError::Capacity);
    }
    // Both components must close independently. Equal and opposite residual
    // components would strand a valuation even though their sum is zero.
    if next.native == 0 && (next.historical != 0 || next.valuation != 0) {
        return Err(ProjectionError::Stranded);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(native: i128, historical: i128, valuation: i128) -> Components {
        Components {
            native,
            historical,
            valuation,
        }
    }

    #[test]
    fn recorded_relief_alternates_without_repricing() {
        let original = state(3, 10, 0);
        let applied = project(original, 3, 10, 1, 3, false).unwrap();
        assert_eq!(applied, state(2, 7, 0));
        let undone = project(applied, 3, 10, 1, 3, true).unwrap();
        assert_eq!(undone, original);
        assert_eq!(project(undone, 3, 10, 1, 3, false).unwrap(), applied);
        // A different current ratio does not alter the recorded relief.
        assert_eq!(
            project(state(2, 6, 0), 3, 10, 1, 4, false).unwrap(),
            state(1, 2, 0)
        );
    }

    #[test]
    fn native_capacity_does_not_imply_historical_capacity() {
        assert_eq!(
            project(state(1, 1, 0), 2, 3, 1, 2, false),
            Err(ProjectionError::Capacity)
        );
        assert_eq!(
            project(state(1, 3, 0), 3, 10, 1, 4, false),
            Err(ProjectionError::Capacity)
        );
    }

    #[test]
    fn zero_relief_cannot_strand_base_or_cancel_opposite_components() {
        assert_eq!(
            project(state(1, 1, 0), 2, 1, 1, 0, false),
            Err(ProjectionError::Stranded)
        );
        assert_eq!(
            project(state(1, 3, -2), 3, 10, 1, 1, false),
            Err(ProjectionError::Stranded)
        );
        assert_eq!(
            project(state(2, 0, 0), 2, 1, 1, 0, false).unwrap(),
            state(1, 0, 0)
        );
    }

    #[test]
    fn signed_valuation_remains_separate_and_total_cannot_go_negative() {
        assert_eq!(
            project(state(2, 7, -2), 3, 10, 1, 3, false).unwrap(),
            state(1, 4, -2)
        );
        assert_eq!(
            project(state(2, 3, -2), 3, 10, 1, 2, false),
            Err(ProjectionError::Capacity)
        );
        assert_eq!(
            project(state(1, 0, 3), 3, 10, 1, 3, true).unwrap(),
            state(2, 3, 3)
        );
    }

    #[test]
    fn undo_respects_original_native_and_historical_capacities() {
        for current in [state(2, 2, 0), state(1, 3, 0)] {
            assert_eq!(
                project(current, 2, 3, 1, 1, true),
                Err(ProjectionError::Capacity)
            );
        }
        assert_eq!(
            project(state(0, 0, 0), 2, 3, 2, 3, true).unwrap(),
            state(2, 3, 0)
        );
    }

    #[test]
    fn allocated_relief_changes_both_recorded_components_without_repricing() {
        for (before, relief, expected) in [
            (state(3, 10, 0), state(1, 3, 1), state(2, 7, -1)),
            (state(3, 10, -2), state(1, 3, -1), state(2, 7, -1)),
            (state(1, 3, -2), state(1, 3, -2), state(0, 0, 0)),
        ] {
            let after = project_recorded(before, 3, 10, relief, false).unwrap();
            assert_eq!(after, expected);
            assert_eq!(project_recorded(after, 3, 10, relief, true).unwrap(), before);
        }
    }

    #[test]
    fn allocated_relief_cannot_strand_opposite_components_or_spend_unavailable_value() {
        assert_eq!(
            project_recorded(state(1, 3, -2), 3, 10, state(1, 1, 0), false),
            Err(ProjectionError::Stranded)
        );
        assert_eq!(
            project_recorded(state(2, 7, -6), 3, 10, state(1, 3, 1), false),
            Err(ProjectionError::Capacity)
        );
        assert_eq!(
            project_recorded(state(2, 7, -1), 3, 10, state(1, 3, -4), false),
            Err(ProjectionError::InvalidRelief)
        );
        assert_eq!(
            project_recorded(state(1, 0, i128::MAX), 2, 1, state(1, 0, 1), true),
            Err(ProjectionError::Overflow)
        );
        assert_eq!(
            project_recorded(
                state(2, i128::MAX, 0),
                3,
                i128::MAX,
                state(1, i128::MAX, 1),
                false
            ),
            Err(ProjectionError::Overflow)
        );
    }

    #[test]
    fn full_i128_values_are_checked_without_unsigned_or_negation_shortcuts() {
        assert_eq!(
            project(
                state(i128::MAX, i128::MAX, 0),
                i128::MAX,
                i128::MAX,
                i128::MAX,
                i128::MAX,
                false
            )
            .unwrap(),
            state(0, 0, 0)
        );
        assert_eq!(
            project(state(i128::MAX, 0, 0), i128::MAX, 1, 1, 0, true),
            Err(ProjectionError::Overflow)
        );
        assert_eq!(
            project(state(1, i128::MAX, 1), 2, i128::MAX, 1, 0, true),
            Err(ProjectionError::Overflow)
        );
        for (native, historical) in [(0, 1), (-1, 1), (1, -1), (i128::MIN, 0)] {
            assert_eq!(
                project(state(1, 1, 0), 2, 3, native, historical, false),
                Err(ProjectionError::InvalidRelief)
            );
        }
    }
}
