//! Independent signed balance-sheet and inventory-role screens.
//!
//! Each native unit remains separate. Haircuts preserve signed contra-account
//! effects, and inventory relief dates come from the selected live journal.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_CITES, MAX_FINDINGS, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed,
};

type Replay = (Vec<VerifiedProcedureFinding>, u64, u64, u64);
type SolvencyInputs = (BTreeSet<u128>, u64);
type SolvencyRow = (i128, i128, BTreeSet<u128>);

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "balance screen exceeds its exact amount or work-count bounds",
    )
}

fn count(value: usize) -> Result<u64, ReportError> {
    u64::try_from(value).map_err(|_| arithmetic())
}

fn scale(registry: &Registry, unit: u32) -> Result<u8, ReportError> {
    registry.unit_scales.get(&unit).copied().ok_or_else(|| {
        failed(
            "procedure_units",
            "balance screen requires the authenticated native unit scale",
        )
    })
}

fn validate_legs(entry: &Entry) -> Result<(), ReportError> {
    if entry.legs.len() != entry.leg_accounts.len() {
        return Err(failed(
            "procedure_inputs",
            "balance screen requires every original leg's account and side",
        ));
    }
    Ok(())
}

fn push(
    findings: &mut Vec<VerifiedProcedureFinding>,
    finding: VerifiedProcedureFinding,
) -> Result<(), ReportError> {
    if findings.len() == MAX_FINDINGS {
        return Err(failed(
            "bounded_input",
            "balance screen findings exceed the certificate bound",
        ));
    }
    findings.push(finding);
    Ok(())
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    live: &[&Entry],
    effective_through: Option<i32>,
    registry: &Registry,
) -> Result<Replay, ReportError> {
    match profile {
        VerifiedProcedureParameters::BalanceSheetSolvency {
            fair_value_haircut_bps,
        } => solvency(live, fair_value_haircut_bps, registry),
        VerifiedProcedureParameters::InventoryAging { stale_days } => {
            inventory(live, effective_through, stale_days, registry)
        }
        _ => Err(failed(
            "procedure_profile",
            "expected an inventory or signed balance-sheet screen",
        )),
    }
}

/// Compute floor(positive_amount * retained_bps / 10000) without a wide
/// multiplication or the producer's arithmetic implementation. The quotient
/// term cannot exceed amount, and the remainder product is below 100 million.
fn retained_assets(amount: i128, haircut_bps: u32) -> Result<i128, ReportError> {
    if haircut_bps > 10_000 {
        return Err(failed(
            "procedure_parameters",
            "fair_value_haircut_bps must be in 0..=10000",
        ));
    }
    if amount <= 0 {
        return Ok(amount);
    }
    let retained = i128::from(10_000 - haircut_bps);
    let whole = (amount / 10_000)
        .checked_mul(retained)
        .ok_or_else(arithmetic)?;
    let remainder = (amount % 10_000)
        .checked_mul(retained)
        .ok_or_else(arithmetic)?
        / 10_000;
    whole.checked_add(remainder).ok_or_else(arithmetic)
}

fn solvency(live: &[&Entry], haircut_bps: u32, registry: &Registry) -> Result<Replay, ReportError> {
    // Invalid parameters refuse even an empty population.
    retained_assets(0, haircut_bps)?;
    let mut ordered = live.to_vec();
    ordered.sort_unstable_by_key(|entry| entry.identity);
    let mut account_net = BTreeMap::<(u128, u32), i128>::new();
    let mut inputs = BTreeMap::<u32, SolvencyInputs>::new();
    let mut leg_work = 0u64;
    for entry in ordered {
        validate_legs(entry)?;
        for (&(unit, amount), &(account, debit)) in entry.legs.iter().zip(&entry.leg_accounts) {
            leg_work = leg_work.checked_add(1).ok_or_else(arithmetic)?;
            let account_type = registry.account_types.get(&account).ok_or_else(|| {
                failed(
                    "procedure_accounts",
                    "solvency leg lacks an authenticated historical account",
                )
            })?;
            if !matches!(*account_type, 1 | 2) {
                continue;
            }
            let magnitude = amount.checked_abs().ok_or_else(arithmetic)?;
            let signed = if debit {
                magnitude
            } else {
                magnitude.checked_neg().ok_or_else(arithmetic)?
            };
            let cell = account_net.entry((account, unit)).or_default();
            *cell = cell.checked_add(signed).ok_or_else(arithmetic)?;
            let input = inputs.entry(unit).or_default();
            input.0.insert(entry.identity);
            input.1 = input.1.checked_add(1).ok_or_else(arithmetic)?;
        }
    }
    let comparisons = count(account_net.len())?;
    let mut by_unit = BTreeMap::<u32, SolvencyRow>::new();
    for ((account, unit), net) in account_net {
        let row = by_unit.entry(unit).or_default();
        match registry.account_types.get(&account) {
            Some(1) => row.0 = row.0.checked_add(net).ok_or_else(arithmetic)?,
            Some(2) => row.1 = row.1.checked_sub(net).ok_or_else(arithmetic)?,
            _ => {
                return Err(failed(
                    "procedure_accounts",
                    "solvency basis is not an authenticated asset or liability",
                ));
            }
        }
        row.2.insert(account);
    }
    let mut findings = Vec::new();
    for (unit, (assets, liabilities, accounts)) in by_unit {
        let adjusted = retained_assets(assets, haircut_bps)?;
        if liabilities <= adjusted {
            continue;
        }
        let deficit = liabilities.checked_sub(adjusted).ok_or_else(arithmetic)?;
        let (entries, population) = inputs.remove(&unit).unwrap_or_default();
        if accounts.len() > MAX_CITES || entries.len() > MAX_CITES - accounts.len() {
            return Err(failed(
                "bounded_input",
                "the complete signed solvency basis exceeds the citation bound",
            ));
        }
        push(
            &mut findings,
            VerifiedProcedureFinding {
                entry: None,
                severity: 4,
                statistic: VerifiedProcedureStatistic::InsolvencyDeficit {
                    unit,
                    amount: deficit,
                    scale: scale(registry, unit)?,
                    accounts: accounts.into_iter().collect(),
                    entries: entries.into_iter().collect(),
                },
                population: population.max(1),
                narrative: format!(
                    "unit {unit} signed balance-sheet deficit: asset_basis={assets}, adjusted_assets={adjusted}, total_liabilities={liabilities}, insolvency_deficit={deficit} (haircut_bps={haircut_bps}; declared book-basis screen, not a fair-value or legal conclusion)"
                ),
            },
        )?;
    }
    Ok((findings, count(live.len())?, leg_work, comparisons))
}

#[derive(Default)]
struct InventoryPosition {
    balance: i128,
    earliest_debit: Option<i32>,
    latest_credit: Option<i32>,
    debit_legs: Vec<(u128, u16)>,
}

fn inventory(
    live: &[&Entry],
    effective_through: Option<i32>,
    stale_days: u32,
    registry: &Registry,
) -> Result<Replay, ReportError> {
    if stale_days == 0 {
        return Err(failed(
            "procedure_parameters",
            "stale_days must be at least one",
        ));
    }
    let mut accounts = BTreeSet::new();
    for (account, roles) in &registry.account_roles {
        if roles.contains("inventory") {
            if !registry.account_types.contains_key(account) {
                return Err(failed(
                    "procedure_roles",
                    "inventory role has no authenticated historical account declaration",
                ));
            }
            accounts.insert(*account);
        }
    }
    if accounts.is_empty() {
        return Err(failed(
            "procedure_roles",
            "the required inventory role is unassigned at the selected frontier",
        ));
    }
    let as_of = effective_through.or_else(|| live.iter().filter_map(|e| e.effective).max());
    let Some(as_of) = as_of else {
        if !live.is_empty() {
            return Err(failed(
                "procedure_inputs",
                "inventory posting has no effective date",
            ));
        }
        return Ok((Vec::new(), 0, 0, 0));
    };
    let mut ordered = live.to_vec();
    ordered.sort_unstable_by_key(|entry| (entry.effective, entry.identity));
    let mut positions = BTreeMap::<(u128, u32), InventoryPosition>::new();
    let mut population = 0u64;
    let mut leg_work = 0u64;
    for entry in ordered {
        validate_legs(entry)?;
        let effective = entry.effective.ok_or_else(|| {
            failed(
                "procedure_inputs",
                "inventory posting has no effective date",
            )
        })?;
        if effective > as_of {
            continue;
        }
        for (ordinal, (&(unit, amount), &(account, debit))) in
            entry.legs.iter().zip(&entry.leg_accounts).enumerate()
        {
            leg_work = leg_work.checked_add(1).ok_or_else(arithmetic)?;
            if !accounts.contains(&account) {
                continue;
            }
            population = population.checked_add(1).ok_or_else(arithmetic)?;
            let position = positions.entry((account, unit)).or_default();
            let magnitude = amount.checked_abs().ok_or_else(arithmetic)?;
            if debit {
                position.balance = position
                    .balance
                    .checked_add(magnitude)
                    .ok_or_else(arithmetic)?;
                position.earliest_debit = Some(
                    position
                        .earliest_debit
                        .map_or(effective, |day| day.min(effective)),
                );
                if position.debit_legs.len() < MAX_CITES - 1 {
                    position.debit_legs.push((
                        entry.identity,
                        u16::try_from(ordinal).map_err(|_| arithmetic())?,
                    ));
                }
            } else {
                position.balance = position
                    .balance
                    .checked_sub(magnitude)
                    .ok_or_else(arithmetic)?;
                position.latest_credit = Some(
                    position
                        .latest_credit
                        .map_or(effective, |day| day.max(effective)),
                );
            }
        }
    }
    let comparisons = count(positions.len())?;
    let mut findings = Vec::new();
    for ((account, unit), mut position) in positions {
        if position.balance <= 0 {
            continue;
        }
        let Some(reference) = position.latest_credit.or(position.earliest_debit) else {
            continue;
        };
        let days = (i64::from(as_of) - i64::from(reference)).max(0);
        let threshold = i64::from(stale_days);
        if days <= threshold {
            continue;
        }
        position.debit_legs.sort_unstable();
        let code = registry
            .account_codes
            .get(&account)
            .map_or("?", String::as_str);
        let balance = position.balance;
        push(
            &mut findings,
            VerifiedProcedureFinding {
                entry: None,
                severity: if days >= threshold * 2 { 3 } else { 2 },
                statistic: VerifiedProcedureStatistic::StaleInventory {
                    account,
                    unit,
                    amount: balance,
                    scale: scale(registry, unit)?,
                    legs: position.debit_legs,
                },
                population,
                narrative: format!(
                    "inventory account {code} carries net debit {balance} in unit {unit} with {days} day(s) since last relief movement (threshold {stale_days})"
                ),
            },
        )?;
    }
    Ok((findings, count(live.len())?, leg_work, comparisons))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry {
            unit_scales: BTreeMap::from([(1, 2), (2, 0), (3, 4)]),
            unit_currencies: BTreeMap::from([(1, 840), (2, 392), (3, 978)]),
            account_types: BTreeMap::from([(10, 1), (11, 1), (20, 2), (21, 2), (30, 3), (50, 5)]),
            account_codes: BTreeMap::from([
                (10, "A-stock".into()),
                (11, "A-inventory-named-but-unassigned".into()),
                (20, "L-payable".into()),
            ]),
            account_roles: BTreeMap::from([(10, BTreeSet::from(["inventory".into()]))]),
            leg_parties: BTreeMap::new(),
            entry_facts: BTreeMap::new(),
            trace: None,
            open_items: None,
            policy_oid: [7; 32],
        }
    }

    fn posting(identity: u128, day: i32, legs: &[(u128, bool, u32, i128)]) -> Entry {
        Entry {
            identity,
            digest: [1; 32],
            recorded_at: 1,
            effective: Some(day),
            class: 1,
            legs: legs
                .iter()
                .map(|&(_, _, unit, amount)| (unit, amount))
                .collect(),
            leg_accounts: legs
                .iter()
                .map(|&(account, debit, _, _)| (account, debit))
                .collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        }
    }

    fn run(
        profile: VerifiedProcedureParameters,
        entries: &[Entry],
        through: Option<i32>,
        registry: &Registry,
    ) -> Result<Replay, ReportError> {
        replay(
            profile,
            &entries.iter().collect::<Vec<_>>(),
            through,
            registry,
        )
    }

    fn solvency_profile(haircut: u32) -> VerifiedProcedureParameters {
        VerifiedProcedureParameters::BalanceSheetSolvency {
            fair_value_haircut_bps: haircut,
        }
    }

    fn inventory_profile(stale_days: u32) -> VerifiedProcedureParameters {
        VerifiedProcedureParameters::InventoryAging { stale_days }
    }

    #[test]
    fn solvency_nets_both_contra_types_before_haircut_and_cites_the_complete_basis() {
        let mut entries = vec![
            posting(
                20,
                0,
                &[
                    (10, true, 1, 10_000),
                    (20, false, 1, 8_000),
                    (30, false, 1, 2_000),
                ],
            ),
            posting(
                10,
                1,
                &[
                    (11, false, 1, 3_000),
                    (21, true, 1, 2_000),
                    (30, true, 1, 1_000),
                ],
            ),
        ];
        let registry = registry();
        assert!(
            run(solvency_profile(0), &entries, None, &registry)
                .unwrap()
                .0
                .is_empty()
        );
        let result = run(solvency_profile(2_500), &entries, None, &registry).unwrap();
        let (findings, entry_work, leg_work, comparisons) = &result;
        assert_eq!((*entry_work, *leg_work, *comparisons), (2, 6, 4));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entry, None);
        assert_eq!(findings[0].severity, 4);
        assert_eq!(findings[0].population, 4);
        assert_eq!(
            findings[0].statistic,
            VerifiedProcedureStatistic::InsolvencyDeficit {
                unit: 1,
                amount: 750,
                scale: 2,
                accounts: vec![10, 11, 20, 21],
                entries: vec![10, 20],
            }
        );
        assert_eq!(
            findings[0].narrative,
            "unit 1 signed balance-sheet deficit: asset_basis=7000, adjusted_assets=5250, total_liabilities=6000, insolvency_deficit=750 (haircut_bps=2500; declared book-basis screen, not a fair-value or legal conclusion)"
        );
        entries.reverse();
        assert_eq!(
            run(solvency_profile(2_500), &entries, None, &registry).unwrap(),
            result
        );
    }

    #[test]
    fn solvency_haircut_is_applied_once_per_unit_and_never_improves_negative_assets() {
        let registry = registry();
        let rounding = [posting(
            1,
            0,
            &[
                (10, true, 1, 1),
                (11, true, 1, 1),
                (20, false, 1, 1),
                (30, false, 1, 1),
            ],
        )];
        assert!(
            run(solvency_profile(5_000), &rounding, None, &registry)
                .unwrap()
                .0
                .is_empty(),
            "two minor units retain one; rounding each account would erase both"
        );
        let negative = [posting(
            1,
            0,
            &[
                (10, true, 1, 1_000),
                (11, false, 1, 4_000),
                (20, false, 1, 5_000),
                (21, true, 1, 1_000),
                (50, true, 1, 7_000),
            ],
        )];
        for haircut in [0, 1, 5_000, 10_000] {
            let findings = run(solvency_profile(haircut), &negative, None, &registry)
                .unwrap()
                .0;
            assert_eq!(findings.len(), 1);
            assert!(matches!(
                findings[0].statistic,
                VerifiedProcedureStatistic::InsolvencyDeficit { amount: 7_000, .. }
            ));
            assert!(
                findings[0]
                    .narrative
                    .contains("asset_basis=-3000, adjusted_assets=-3000")
            );
        }
    }

    #[test]
    fn solvency_never_offsets_one_native_unit_with_another() {
        let entries = [posting(
            7,
            0,
            &[
                (10, true, 1, 10_000),
                (20, false, 1, 1_000),
                (30, false, 1, 9_000),
                (10, true, 2, 50),
                (20, false, 2, 120),
                (30, true, 2, 70),
                (20, false, 3, 300),
                (30, true, 3, 300),
            ],
        )];
        let (findings, entry_work, leg_work, comparisons) =
            run(solvency_profile(0), &entries, None, &registry()).unwrap();
        assert_eq!((entry_work, leg_work, comparisons), (1, 8, 5));
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings[0].statistic,
            VerifiedProcedureStatistic::InsolvencyDeficit {
                unit: 2,
                amount: 70,
                scale: 0,
                accounts: vec![10, 20],
                entries: vec![7],
            }
        );
        assert_eq!(
            findings[1].statistic,
            VerifiedProcedureStatistic::InsolvencyDeficit {
                unit: 3,
                amount: 300,
                scale: 4,
                accounts: vec![20],
                entries: vec![7],
            }
        );
        assert_eq!((findings[0].population, findings[1].population), (2, 1));
    }

    #[test]
    fn haircut_remains_exact_when_the_naive_intermediate_exceeds_i128() {
        // These literal quotients were computed with unbounded integer arithmetic,
        // independently of both the native U256 path and this quotient split.
        for (haircut, expected) in [
            (0, i128::MAX),
            (1, 170_124_169_342_123_184_808_514_134_985_512_517_316),
            (1_234, 149_145_761_421_447_328_535_997_090_437_344_007_080),
            (5_000, 85_070_591_730_234_615_865_843_651_857_942_052_863),
            (9_999, 17_014_118_346_046_923_173_168_730_371_588_410),
            (10_000, 0),
        ] {
            assert_eq!(retained_assets(i128::MAX, haircut).unwrap(), expected);
            assert_eq!(retained_assets(i128::MIN, haircut).unwrap(), i128::MIN);
        }
        for amount in [1, 2, 9_999, 10_000, 10_001, 19_999, 999_999] {
            for haircut in [0, 1, 123, 5_000, 9_999, 10_000] {
                assert_eq!(
                    retained_assets(amount, haircut).unwrap(),
                    amount * i128::from(10_000 - haircut) / 10_000
                );
            }
        }
        let entries = [posting(
            1,
            0,
            &[(10, true, 1, i128::MAX), (20, false, 1, i128::MAX)],
        )];
        let findings = run(solvency_profile(1), &entries, None, &registry())
            .unwrap()
            .0;
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].statistic,
            VerifiedProcedureStatistic::InsolvencyDeficit {
                amount: 17_014_118_346_046_923_173_168_730_371_588_411,
                ..
            }
        ));
    }

    #[test]
    fn solvency_refuses_to_truncate_the_citations_supporting_a_deficit() {
        let mut entries: Vec<_> = (1..MAX_CITES)
            .map(|id| posting(id as u128, 0, &[(20, false, 1, 1), (30, true, 1, 1)]))
            .collect();
        let registry = registry();
        let findings = run(solvency_profile(0), &entries, None, &registry)
            .unwrap()
            .0;
        let VerifiedProcedureStatistic::InsolvencyDeficit {
            accounts,
            entries: cites,
            ..
        } = &findings[0].statistic
        else {
            panic!("expected a deficit")
        };
        assert_eq!(accounts, &[20]);
        assert_eq!(cites.len(), MAX_CITES - 1);
        assert_eq!(cites.first(), Some(&1));
        assert_eq!(cites.last(), Some(&((MAX_CITES - 1) as u128)));
        entries.push(posting(
            MAX_CITES as u128,
            0,
            &[(20, false, 1, 1), (30, true, 1, 1)],
        ));
        assert_eq!(
            run(solvency_profile(0), &entries, None, &registry)
                .unwrap_err()
                .predicate,
            "bounded_input"
        );
    }

    #[test]
    fn inventory_uses_declared_roles_and_keeps_native_units_separate() {
        let entries = [posting(
            5,
            0,
            &[
                (10, true, 1, 100),
                (30, false, 1, 100),
                (10, false, 2, 50),
                (30, true, 2, 50),
                (10, true, 3, 25),
                (30, false, 3, 25),
                (11, true, 1, 9_000),
                (30, false, 1, 9_000),
            ],
        )];
        let (findings, entry_work, leg_work, comparisons) =
            run(inventory_profile(10), &entries, Some(20), &registry()).unwrap();
        assert_eq!((entry_work, leg_work, comparisons), (1, 8, 3));
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings[0].statistic,
            VerifiedProcedureStatistic::StaleInventory {
                account: 10,
                unit: 1,
                amount: 100,
                scale: 2,
                legs: vec![(5, 0)],
            }
        );
        assert_eq!(
            findings[1].statistic,
            VerifiedProcedureStatistic::StaleInventory {
                account: 10,
                unit: 3,
                amount: 25,
                scale: 4,
                legs: vec![(5, 4)],
            }
        );
        assert!(
            findings
                .iter()
                .all(|f| f.severity == 3 && f.population == 3)
        );
        assert_eq!(
            findings[0].narrative,
            "inventory account A-stock carries net debit 100 in unit 1 with 20 day(s) since last relief movement (threshold 10)"
        );
    }

    #[test]
    fn inventory_age_threshold_is_strict_and_high_severity_boundary_is_inclusive() {
        let entries = [posting(1, 0, &[(10, true, 1, 100), (30, false, 1, 100)])];
        let registry = registry();
        for (as_of, severity) in [
            (0, None),
            (10, None),
            (11, Some(2)),
            (19, Some(2)),
            (20, Some(3)),
        ] {
            let findings = run(inventory_profile(10), &entries, Some(as_of), &registry)
                .unwrap()
                .0;
            assert_eq!(
                findings.first().map(|f| f.severity),
                severity,
                "as_of={as_of}"
            );
        }
        let oldest = [posting(1, i32::MIN, &[(10, true, 1, 1), (30, false, 1, 1)])];
        assert!(
            run(
                inventory_profile(u32::MAX),
                &oldest,
                Some(i32::MAX),
                &registry
            )
            .unwrap()
            .0
            .is_empty()
        );
        let findings = run(
            inventory_profile(u32::MAX - 1),
            &oldest,
            Some(i32::MAX),
            &registry,
        )
        .unwrap()
        .0;
        assert_eq!(findings[0].severity, 2);
        assert!(findings[0].narrative.contains("4294967295 day(s)"));
        let findings = run(
            inventory_profile(u32::MAX / 2),
            &oldest,
            Some(i32::MAX),
            &registry,
        )
        .unwrap()
        .0;
        assert_eq!(findings[0].severity, 3);
    }

    #[test]
    fn inventory_uses_latest_relief_and_does_not_reset_age_on_a_new_debit() {
        let entries = [
            posting(3, 0, &[(10, true, 1, 100), (30, false, 1, 100)]),
            posting(2, 5, &[(10, false, 1, 10), (30, true, 1, 10)]),
            posting(1, 9, &[(10, true, 1, 25), (30, false, 1, 25)]),
        ];
        let registry = registry();
        assert!(
            run(inventory_profile(10), &entries, Some(15), &registry)
                .unwrap()
                .0
                .is_empty()
        );
        let (findings, entry_work, leg_work, comparisons) =
            run(inventory_profile(10), &entries, Some(16), &registry).unwrap();
        assert_eq!((entry_work, leg_work, comparisons), (3, 6, 1));
        assert_eq!(findings[0].population, 3);
        assert_eq!(
            findings[0].statistic,
            VerifiedProcedureStatistic::StaleInventory {
                account: 10,
                unit: 1,
                amount: 115,
                scale: 2,
                legs: vec![(1, 0), (3, 0)],
            }
        );
        assert!(
            findings[0]
                .narrative
                .contains("11 day(s) since last relief movement")
        );
        let no_relief = [entries[0].clone(), entries[2].clone()];
        let findings = run(inventory_profile(10), &no_relief, Some(16), &registry)
            .unwrap()
            .0;
        assert!(
            findings[0]
                .narrative
                .contains("16 day(s) since last relief movement")
        );
    }

    #[test]
    fn inventory_ignores_relief_after_the_cutoff_and_infers_as_of_from_selected_postings() {
        let entries = [
            posting(1, 0, &[(10, true, 1, 100), (30, false, 1, 100)]),
            posting(2, 30, &[(50, true, 1, 1), (30, false, 1, 1)]),
            posting(3, 40, &[(10, false, 1, 100), (30, true, 1, 100)]),
        ];
        let registry = registry();
        let historical = run(inventory_profile(10), &entries, Some(30), &registry).unwrap();
        assert_eq!((historical.1, historical.2, historical.3), (3, 4, 1));
        assert!(matches!(
            historical.0[0].statistic,
            VerifiedProcedureStatistic::StaleInventory { amount: 100, .. }
        ));
        assert!(
            run(inventory_profile(10), &entries, None, &registry)
                .unwrap()
                .0
                .is_empty()
        );
        let inferred = run(inventory_profile(10), &entries[..2], None, &registry).unwrap();
        assert_eq!(inferred.0, historical.0);
        assert_eq!((inferred.1, inferred.2, inferred.3), (2, 4, 1));
    }

    #[test]
    fn inventory_citation_cap_retains_earliest_movements_then_canonicalizes_ids() {
        let count = MAX_CITES + 5;
        let mut entries: Vec<_> = (0..count)
            .map(|day| {
                posting(
                    (count - day) as u128,
                    i32::try_from(day).unwrap(),
                    &[(10, true, 1, 1), (30, false, 1, 1)],
                )
            })
            .collect();
        entries.reverse();
        let (findings, entry_work, leg_work, comparisons) = run(
            inventory_profile(10),
            &entries,
            Some(i32::try_from(count + 100).unwrap()),
            &registry(),
        )
        .unwrap();
        assert_eq!(
            (entry_work, leg_work, comparisons),
            (count as u64, (2 * count) as u64, 1)
        );
        assert_eq!(findings[0].population, count as u64);
        let VerifiedProcedureStatistic::StaleInventory { amount, legs, .. } =
            &findings[0].statistic
        else {
            panic!("expected stale inventory")
        };
        assert_eq!(*amount, count as i128);
        assert_eq!(legs.len(), MAX_CITES - 1);
        assert_eq!(legs.first(), Some(&(7, 0)));
        assert_eq!(legs.last(), Some(&(count as u128, 0)));
        assert_eq!(
            legs,
            &(7..=count as u128).map(|id| (id, 0)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn roles_and_parameters_are_required_even_for_an_empty_selected_population() {
        let mut registry = registry();
        assert_eq!(
            run(inventory_profile(1), &[], None, &registry).unwrap(),
            (Vec::new(), 0, 0, 0)
        );
        assert_eq!(
            run(solvency_profile(0), &[], None, &registry).unwrap(),
            (Vec::new(), 0, 0, 0)
        );
        assert_eq!(
            run(inventory_profile(0), &[], None, &registry)
                .unwrap_err()
                .predicate,
            "procedure_parameters"
        );
        for haircut in [10_001, u32::MAX] {
            assert_eq!(
                run(solvency_profile(haircut), &[], None, &registry)
                    .unwrap_err()
                    .predicate,
                "procedure_parameters"
            );
        }
        registry.account_roles.clear();
        assert_eq!(
            run(inventory_profile(1), &[], None, &registry)
                .unwrap_err()
                .predicate,
            "procedure_roles"
        );
        registry
            .account_roles
            .insert(999, BTreeSet::from(["inventory".into()]));
        assert_eq!(
            run(inventory_profile(1), &[], None, &registry)
                .unwrap_err()
                .predicate,
            "procedure_roles"
        );
    }

    #[test]
    fn malformed_leg_metadata_missing_dates_and_missing_native_scales_refuse() {
        let mut registry = registry();
        let mut entry = posting(1, 0, &[(10, true, 1, 100), (20, false, 1, 100)]);
        entry.leg_accounts.pop();
        for profile in [solvency_profile(1), inventory_profile(1)] {
            assert_eq!(
                run(profile, &[entry.clone()], Some(10), &registry)
                    .unwrap_err()
                    .predicate,
                "procedure_inputs"
            );
        }
        entry = posting(1, 0, &[(10, true, 1, 100), (20, false, 1, 100)]);
        entry.effective = None;
        for through in [None, Some(10)] {
            assert_eq!(
                run(inventory_profile(1), &[entry.clone()], through, &registry)
                    .unwrap_err()
                    .predicate,
                "procedure_inputs"
            );
        }
        entry.effective = Some(0);
        registry.unit_scales.clear();
        for profile in [solvency_profile(1), inventory_profile(1)] {
            assert_eq!(
                run(profile, &[entry.clone()], Some(10), &registry)
                    .unwrap_err()
                    .predicate,
                "procedure_units"
            );
        }
        registry.account_types.remove(&10);
        assert_eq!(
            run(solvency_profile(0), &[entry], None, &registry)
                .unwrap_err()
                .predicate,
            "procedure_accounts"
        );
    }

    #[test]
    fn every_solvency_accumulator_and_deficit_refuses_checked_overflow() {
        // Same-account sum, cross-account asset sum, liability sum/negation,
        // and the final deficit each have a distinct representability boundary.
        let cases = [
            vec![(10, true, 1, i128::MAX), (10, true, 1, 1)],
            vec![(10, true, 1, i128::MAX), (11, true, 1, 1)],
            vec![(20, false, 1, i128::MAX), (21, false, 1, 1)],
            vec![(20, false, 1, i128::MAX), (20, false, 1, 1)],
            vec![(10, false, 1, i128::MAX), (20, false, 1, i128::MAX)],
            vec![(10, true, 1, i128::MIN)],
        ];
        for (index, legs) in cases.iter().enumerate() {
            assert_eq!(
                run(
                    solvency_profile(0),
                    &[posting(1, 0, legs)],
                    None,
                    &registry()
                )
                .unwrap_err()
                .predicate,
                "procedure_arithmetic",
                "case {index}"
            );
        }
    }

    #[test]
    fn inventory_refuses_overflow_and_does_not_report_zero_or_credit_balances() {
        let cases = [
            vec![(10, true, 1, i128::MAX), (10, true, 1, 1)],
            vec![(10, false, 1, i128::MAX), (10, false, 1, 2)],
            vec![(10, true, 1, i128::MIN)],
        ];
        for legs in cases {
            assert_eq!(
                run(
                    inventory_profile(1),
                    &[posting(1, 0, &legs)],
                    Some(10),
                    &registry()
                )
                .unwrap_err()
                .predicate,
                "procedure_arithmetic"
            );
        }
        for credit in [100, 101] {
            let entries = [posting(1, 0, &[(10, true, 1, 100), (10, false, 1, credit)])];
            let (findings, entry_work, leg_work, comparisons) =
                run(inventory_profile(1), &entries, Some(10), &registry()).unwrap();
            assert!(findings.is_empty());
            assert_eq!((entry_work, leg_work, comparisons), (1, 2, 1));
        }
    }
}
