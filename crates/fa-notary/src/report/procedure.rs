//! Shared producer eligibility for the independent procedure transport.
//!
//! The facade and the byte-level assembler must admit the same bounded profile.
//! This inventory is routing only: the independent verifier keeps its own
//! algorithm, parameter, registry and complete-source checks.

const ROUND: &[(&str, i128, i128)] = &[("round_power", 0, 30)];
const WINDOW: &[(&str, i128, i128)] = &[("window_days", 0, u32::MAX as i128)];
const DENSITY: &[(&str, i128, i128)] = &[
    ("min_legs", 0, u32::MAX as i128),
    ("round_power", 0, 30),
    ("z_squared", 1, u32::MAX as i128),
];
const BENFORD: &[(&str, i128, i128)] = &[
    ("account_type", 0, 8),
    ("currency_iso4217", 1, 999),
    ("mad_acceptable", 0, u32::MAX as i128),
    ("mad_close", 0, u32::MAX as i128),
    ("mad_marginal", 0, u32::MAX as i128),
    ("min_population", 0, u32::MAX as i128),
    ("side", 0, 1),
];

/// Return the exact evidence identity for an exportable procedure selection.
///
/// Both native facade admission and transport framing use this inventory.
/// Parameters must be explicit, unique and lexically ordered; only JET
/// round-amount/period-end v2 accepts an effective cutoff, and no current
/// portable profile accepts input handles. This is neither source verification
/// nor a claim that the delivered result agrees with the selected algorithm.
#[must_use]
pub fn profile(
    id: &str,
    version: u16,
    effective_through: Option<i32>,
    parameters: &[(&str, i128)],
    input_count: usize,
) -> Option<&'static str> {
    let (evidence, bounds) = match (id, version) {
        ("jet.round_amounts", 1 | 2) => ("FA-EVID-L01", ROUND),
        ("jet.period_end_timing", 1 | 2) => ("FA-EVID-L02", WINDOW),
        ("jet.post_closing", 1) => ("FA-EVID-L03", &[][..]),
        ("duplicates.same_same_same", 1) => ("FA-EVID-L07", &[][..]),
        ("duplicates.same_same_different", 1) => ("FA-EVID-L08", WINDOW),
        ("numbers.round_amount_density", 1) => ("FA-EVID-L64", DENSITY),
        ("benford.first_digit", 2) => ("FA-EVID-L10", BENFORD),
        _ => return None,
    };
    if input_count != 0
        || (effective_through.is_some()
            && !(version == 2 && matches!(id, "jet.round_amounts" | "jet.period_end_timing")))
        || parameters.len() != bounds.len()
        || !parameters
            .iter()
            .zip(bounds)
            .all(|(&(name, value), &(expected, low, high))| {
                name == expected && (low..=high).contains(&value)
            })
    {
        return None;
    }
    Some(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    type ProfileCase<'a> = (&'a str, u16, &'a [(&'a str, i128)], &'a str);

    #[test]
    fn portable_procedure_profiles_keep_their_exact_versions_and_evidence_ids() {
        let benford = [
            ("account_type", 0),
            ("currency_iso4217", 840),
            ("mad_acceptable", 12_000_000),
            ("mad_close", 6_000_000),
            ("mad_marginal", 15_000_000),
            ("min_population", 100),
            ("side", 0),
        ];
        let cases: &[ProfileCase<'_>] = &[
            ("jet.round_amounts", 1, &[("round_power", 3)], "FA-EVID-L01"),
            (
                "jet.round_amounts",
                2,
                &[("round_power", 30)],
                "FA-EVID-L01",
            ),
            (
                "jet.period_end_timing",
                1,
                &[("window_days", 0)],
                "FA-EVID-L02",
            ),
            (
                "jet.period_end_timing",
                2,
                &[("window_days", i128::from(u32::MAX))],
                "FA-EVID-L02",
            ),
            ("jet.post_closing", 1, &[], "FA-EVID-L03"),
            ("duplicates.same_same_same", 1, &[], "FA-EVID-L07"),
            (
                "duplicates.same_same_different",
                1,
                &[("window_days", 30)],
                "FA-EVID-L08",
            ),
            (
                "numbers.round_amount_density",
                1,
                &[("min_legs", 20), ("round_power", 2), ("z_squared", 9)],
                "FA-EVID-L64",
            ),
            ("benford.first_digit", 2, &benford, "FA-EVID-L10"),
        ];
        for &(id, version, parameters, evidence) in cases {
            assert_eq!(profile(id, version, None, parameters, 0), Some(evidence));
            assert_eq!(profile(id, 0, None, parameters, 0), None);
            assert_eq!(profile(id, 3, None, parameters, 0), None);
            assert_eq!(profile(id, version, None, parameters, 1), None);
            let accepts_cutoff =
                version == 2 && matches!(id, "jet.round_amounts" | "jet.period_end_timing");
            assert_eq!(
                profile(id, version, Some(i32::MIN), parameters, 0),
                accepts_cutoff.then_some(evidence)
            );
        }
        assert_eq!(profile("jet.weekend", 1, None, &[], 0), None);
        assert_eq!(profile("trace.libr", 2, Some(1), &[], 2), None);
        assert_eq!(profile("duplicates.same_same_same", 2, None, &[], 0), None);
        assert_eq!(profile("benford.first_digit", 1, None, &benford, 0), None);
    }

    #[test]
    fn new_portable_profiles_reject_unsupported_versions_and_parameter_inventories() {
        let duplicates = "duplicates.same_same_different";
        for window in [0, 30, i128::from(u32::MAX)] {
            assert_eq!(
                profile(duplicates, 1, None, &[("window_days", window)], 0),
                Some("FA-EVID-L08")
            );
        }
        for parameters in [
            vec![],
            vec![("window_days", -1)],
            vec![("window_days", i128::from(u32::MAX) + 1)],
            vec![("round_power", 30)],
            vec![("window_days", 30), ("window_days", 30)],
        ] {
            assert_eq!(profile(duplicates, 1, None, &parameters, 0), None);
        }
        assert_eq!(
            profile(duplicates, 2, None, &[("window_days", 30)], 0),
            None
        );
        let density = "numbers.round_amount_density";
        let defaults = [("min_legs", 20), ("round_power", 2), ("z_squared", 9)];
        assert_eq!(
            profile(
                density,
                1,
                None,
                &[
                    ("min_legs", i128::from(u32::MAX)),
                    ("round_power", 30),
                    ("z_squared", i128::from(u32::MAX)),
                ],
                0,
            ),
            Some("FA-EVID-L64")
        );
        for (index, invalid) in [
            (0, -1),
            (0, i128::from(u32::MAX) + 1),
            (1, -1),
            (1, 31),
            (2, 0),
            (2, i128::from(u32::MAX) + 1),
        ] {
            let mut parameters = defaults;
            parameters[index].1 = invalid;
            assert_eq!(profile(density, 1, None, &parameters, 0), None);
        }
        for parameters in [
            defaults[..2].to_vec(),
            vec![("round_power", 2), ("min_legs", 20), ("z_squared", 9)],
            vec![("min_legs", 20), ("round_power", 2), ("round_power", 9)],
            [defaults.as_slice(), &[("window_days", 30)]].concat(),
        ] {
            assert_eq!(profile(density, 1, None, &parameters, 0), None);
        }
        assert_eq!(profile(density, 2, None, &defaults, 0), None);
    }
}
