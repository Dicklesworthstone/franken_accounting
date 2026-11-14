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
const LIBR: &[(&str, i128, i128)] = &[("intraday_order", 0, 3), ("replenishment", 0, 1)];
const ORDERED_TRACE: &[(&str, i128, i128)] = &[("intraday_order", 0, 3)];
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
/// Parameters must be explicit, unique and lexically ordered. JET
/// round-amount/period-end v2 accepts an optional effective cutoff; tracing v2
/// requires a claim date and canonical account/source handles. This is neither source verification
/// nor a claim that the delivered result agrees with the selected algorithm.
#[must_use]
pub fn profile(
    id: &str,
    version: u16,
    effective_through: Option<i32>,
    parameters: &[(&str, i128)],
    inputs: &[(&str, &str)],
) -> Option<&'static str> {
    let (evidence, bounds) = match (id, version) {
        ("jet.round_amounts", 1 | 2) => ("FA-EVID-L01", ROUND),
        ("jet.period_end_timing", 1 | 2) => ("FA-EVID-L02", WINDOW),
        ("jet.post_closing", 1) => ("FA-EVID-L03", &[][..]),
        ("duplicates.same_same_same", 1) => ("FA-EVID-L07", &[][..]),
        ("duplicates.same_same_different", 1) => ("FA-EVID-L08", WINDOW),
        ("numbers.round_amount_density", 1) => ("FA-EVID-L64", DENSITY),
        ("benford.first_digit", 2) => ("FA-EVID-L10", BENFORD),
        ("trace.libr", 2) => ("FA-EVID-L15", LIBR),
        ("trace.fifo", 2) => ("FA-EVID-L16", ORDERED_TRACE),
        ("trace.lifo", 2) => ("FA-EVID-L17", ORDERED_TRACE),
        _ => return None,
    };
    let tracing = matches!(id, "trace.libr" | "trace.fifo" | "trace.lifo");
    if (tracing && effective_through.is_none())
        || (!tracing
            && effective_through.is_some()
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
    if tracing {
        if parameters[0].1 == 1
            || inputs.len() != 2
            || !inputs
                .iter()
                .zip(["account", "source"])
                .all(|(&(name, value), expected)| {
                    name == expected
                        && value.len() == 32
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        {
            return None;
        }
    } else if !inputs.is_empty() {
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
            assert_eq!(profile(id, version, None, parameters, &[]), Some(evidence));
            assert_eq!(profile(id, 0, None, parameters, &[]), None);
            assert_eq!(profile(id, 3, None, parameters, &[]), None);
            assert_eq!(
                profile(
                    id,
                    version,
                    None,
                    parameters,
                    &[("account", "00000000000000000000000000000001")]
                ),
                None
            );
            let accepts_cutoff =
                version == 2 && matches!(id, "jet.round_amounts" | "jet.period_end_timing");
            assert_eq!(
                profile(id, version, Some(i32::MIN), parameters, &[]),
                accepts_cutoff.then_some(evidence)
            );
        }
        assert_eq!(profile("jet.weekend", 1, None, &[], &[]), None);
        assert_eq!(profile("trace.fifo", 2, Some(1), &[], &[]), None);
        assert_eq!(
            profile("duplicates.same_same_same", 2, None, &[], &[]),
            None
        );
        assert_eq!(profile("benford.first_digit", 1, None, &benford, &[]), None);
    }

    #[test]
    fn new_portable_profiles_reject_unsupported_versions_and_parameter_inventories() {
        let duplicates = "duplicates.same_same_different";
        for window in [0, 30, i128::from(u32::MAX)] {
            assert_eq!(
                profile(duplicates, 1, None, &[("window_days", window)], &[]),
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
            assert_eq!(profile(duplicates, 1, None, &parameters, &[]), None);
        }
        assert_eq!(
            profile(duplicates, 2, None, &[("window_days", 30)], &[]),
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
                &[],
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
            assert_eq!(profile(density, 1, None, &parameters, &[]), None);
        }
        for parameters in [
            defaults[..2].to_vec(),
            vec![("round_power", 2), ("min_legs", 20), ("z_squared", 9)],
            vec![("min_legs", 20), ("round_power", 2), ("round_power", 9)],
            [defaults.as_slice(), &[("window_days", 30)]].concat(),
        ] {
            assert_eq!(profile(density, 1, None, &parameters, &[]), None);
        }
        assert_eq!(profile(density, 2, None, &defaults, &[]), None);
    }

    #[test]
    fn libr_profile_requires_its_exact_claim_date_laws_and_canonical_handles() {
        let account = "000000000000000000000000000000ab";
        let source = "fedcba98765432100000000000000001";
        let inputs = [("account", account), ("source", source)];
        let parameters = [("intraday_order", 0), ("replenishment", 0)];
        for intraday_order in [0, 2, 3] {
            for replenishment in [0, 1] {
                let parameters = [
                    ("intraday_order", intraday_order),
                    ("replenishment", replenishment),
                ];
                assert_eq!(
                    profile("trace.libr", 2, Some(i32::MAX), &parameters, &inputs),
                    Some("FA-EVID-L15")
                );
            }
        }
        for version in [0, 1, 3] {
            assert_eq!(
                profile("trace.libr", version, Some(0), &parameters, &inputs),
                None
            );
        }
        assert_eq!(profile("trace.libr", 2, None, &parameters, &inputs), None);
        for parameters in [
            vec![("intraday_order", 1), ("replenishment", 0)],
            vec![("intraday_order", 4), ("replenishment", 0)],
            vec![("intraday_order", -1), ("replenishment", 0)],
            vec![("intraday_order", 0), ("replenishment", -1)],
            vec![("intraday_order", 0), ("replenishment", 2)],
            vec![("replenishment", 0), ("intraday_order", 0)],
            vec![("intraday_order", 0)],
        ] {
            assert_eq!(
                profile("trace.libr", 2, Some(0), &parameters, &inputs),
                None
            );
        }
        for inputs in [
            vec![],
            vec![("account", account)],
            vec![("source", source), ("account", account)],
            vec![("account", account), ("account", source)],
            vec![("account", "ab"), ("source", source)],
            vec![
                ("account", "000000000000000000000000000000AB"),
                ("source", source),
            ],
            vec![
                ("account", account),
                ("source", "g0000000000000000000000000000001"),
            ],
            vec![("account", account), ("source", source), ("source", source)],
        ] {
            assert_eq!(
                profile("trace.libr", 2, Some(0), &parameters, &inputs),
                None
            );
        }
    }

    #[test]
    fn ordered_tracing_profiles_bind_the_law_claim_date_and_exact_input_inventory() {
        let account = "000000000000000000000000000000ab";
        let source = "fedcba98765432100000000000000001";
        let inputs = [("account", account), ("source", source)];
        for (id, evidence) in [("trace.fifo", "FA-EVID-L16"), ("trace.lifo", "FA-EVID-L17")] {
            for order in [0, 2, 3] {
                assert_eq!(
                    profile(id, 2, Some(i32::MAX), &[("intraday_order", order)], &inputs),
                    Some(evidence)
                );
            }
            let parameters = [("intraday_order", 0)];
            for version in [0, 1, 3] {
                assert_eq!(profile(id, version, Some(0), &parameters, &inputs), None);
            }
            assert_eq!(profile(id, 2, None, &parameters, &inputs), None);
            for parameters in [
                vec![],
                vec![("intraday_order", -1)],
                vec![("intraday_order", 1)],
                vec![("intraday_order", 4)],
                vec![("replenishment", 0)],
                vec![("intraday_order", 0), ("intraday_order", 0)],
                vec![("intraday_order", 0), ("replenishment", 0)],
            ] {
                assert_eq!(profile(id, 2, Some(0), &parameters, &inputs), None);
            }
            for inputs in [
                vec![],
                vec![("account", account)],
                vec![("source", source), ("account", account)],
                vec![("account", account), ("account", source)],
                vec![("account", "ab"), ("source", source)],
                vec![
                    ("account", account),
                    ("source", "FEDCBA98765432100000000000000001"),
                ],
                vec![("account", account), ("source", source), ("unused", source)],
            ] {
                assert_eq!(profile(id, 2, Some(0), &parameters, &inputs), None);
            }
        }
    }
}
