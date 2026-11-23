use super::*;
use crate::report::open_items::VerifiedOpenItem;

fn registry(items: Vec<VerifiedOpenItem>) -> Registry {
    Registry {
        unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
        unit_currencies: BTreeMap::from([(1, 840), (2, 392)]),
        account_types: BTreeMap::from([(10, 1), (20, 3), (30, 1), (40, 2), (50, 5)]),
        account_codes: BTreeMap::from([
            (10, "A-first".into()),
            (20, "E-capital".into()),
            (30, "A-later".into()),
            (40, "L-accrued".into()),
            (50, "X-expense".into()),
        ]),
        account_roles: BTreeMap::from([
            (
                10,
                BTreeSet::from(["suspense".into(), "fixed_asset".into()]),
            ),
            (30, BTreeSet::from(["fixed_asset".into()])),
            (40, BTreeSet::from(["accrued_expense".into()])),
        ]),
        leg_parties: BTreeMap::new(),
        entry_facts: BTreeMap::new(),
        trace: None,
        open_items: Some(items),
        policy_oid: [7; 32],
    }
}

fn item(entry: u128, day: i32, amount: i128, debit: bool) -> VerifiedOpenItem {
    VerifiedOpenItem {
        entry,
        ordinal: 0,
        account: 10,
        unit_id: 1,
        debit,
        effective_date: day,
        recorded_at: 1,
        original: amount,
        applied: 0,
        applied_out: 0,
        open: amount,
        applications: Vec::new(),
    }
}

fn entry(identity: u128, day: i32) -> Entry {
    Entry {
        identity,
        digest: [1; 32],
        recorded_at: 1,
        effective: Some(day),
        class: 1,
        legs: vec![(1, 100), (1, 100)],
        leg_accounts: vec![(10, true), (20, false)],
        supersession: Vec::new(),
        settlements: Vec::new(),
        period: None,
        transition: None,
    }
}

#[test]
fn suspense_uses_uncleared_residual_age_even_when_opposing_items_net_to_zero() {
    let mut paid = item(1, 0, 100, true);
    paid.applied = 100;
    paid.open = 0;
    let items = vec![paid, item(2, 15, 60, true), item(3, 20, 60, false)];
    let mut entries = vec![entry(1, 0), entry(2, 15), entry(3, 20)];
    entries[2].settlements.push((1, [1; 32]));
    let live = entries.iter().collect::<Vec<_>>();
    let (findings, entry_work, leg_work, comparisons) = replay(
        VerifiedProcedureParameters::SuspenseAging { max_age_days: 7 },
        &entries,
        &live,
        Some(30),
        &registry(items.clone()),
    )
    .unwrap();
    assert_eq!((entry_work, leg_work, comparisons), (3, 9, 322));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, 3);
    assert_eq!(findings[0].population, 3);
    assert_eq!(
        findings[0].statistic,
        VerifiedProcedureStatistic::SuspenseAge {
            account: 10,
            age: 15,
            entries: vec![2, 3],
        }
    );
    assert!(findings[0].narrative.contains("net balance 0 in unit 1"));
    assert!(
        replay(
            VerifiedProcedureParameters::SuspenseAging { max_age_days: 15 },
            &entries,
            &live,
            Some(30),
            &registry(items),
        )
        .unwrap()
        .0
        .is_empty(),
        "the registered age comparison is strictly greater than the threshold"
    );
}

#[test]
fn suspense_without_cutoff_uses_latest_live_posting_and_full_width_civil_days() {
    let mut entries = vec![entry(1, i32::MIN), entry(2, i32::MAX)];
    let items = vec![item(1, i32::MIN, 1, true)];
    let profile = VerifiedProcedureParameters::SuspenseAging {
        max_age_days: u32::MAX / 2,
    };
    let live = entries.iter().collect::<Vec<_>>();
    let findings = replay(profile, &entries, &live, None, &registry(items.clone()))
        .unwrap()
        .0;
    assert_eq!(findings[0].statistic.value(), i128::from(u32::MAX));
    assert_eq!(findings[0].severity, 3);
    assert!(
        replay(
            VerifiedProcedureParameters::SuspenseAging {
                max_age_days: u32::MAX,
            },
            &entries,
            &live,
            None,
            &registry(items.clone()),
        )
        .unwrap()
        .0
        .is_empty()
    );
    entries.reverse();
    assert_eq!(
        replay(
            profile,
            &entries,
            &entries.iter().collect::<Vec<_>>(),
            None,
            &registry(items),
        )
        .unwrap()
        .0,
        findings
    );
}

#[test]
fn suspense_caps_citations_by_age_without_losing_uncleared_population_or_oldest_item() {
    let mut items = (0..MAX_CITES + 4)
        .map(|index| item(index as u128 + 1, index as i32, 1, true))
        .collect::<Vec<_>>();
    items[0].entry = u128::MAX;
    let entries = vec![entry(1, 20_000)];
    let (findings, _, leg_work, _) = replay(
        VerifiedProcedureParameters::SuspenseAging { max_age_days: 7 },
        &entries,
        &entries.iter().collect::<Vec<_>>(),
        Some(20_000),
        &registry(items),
    )
    .unwrap();
    assert_eq!(leg_work, (MAX_CITES + 6) as u64);
    assert!(findings[0].narrative.contains("net balance 4100"));
    let VerifiedProcedureStatistic::SuspenseAge { entries, age, .. } = &findings[0].statistic
    else {
        panic!("suspense statistic");
    };
    assert_eq!(*age, 20_000);
    assert_eq!(entries.len(), MAX_CITES - 1);
    assert_eq!(entries.last(), Some(&u128::MAX));
    assert!(!entries.contains(&((MAX_CITES + 4) as u128)));
}

#[test]
fn suspense_refuses_missing_roles_invalid_residuals_and_exact_sum_overflow() {
    let profile = VerifiedProcedureParameters::SuspenseAging { max_age_days: 7 };
    let entries = vec![entry(1, 0)];
    let live = entries.iter().collect::<Vec<_>>();
    let empty = registry(Vec::new());
    assert_eq!(
        replay(profile, &[], &[], None, &empty).unwrap(),
        (Vec::new(), 0, 0, 0)
    );
    let mut missing = registry(Vec::new());
    missing.account_roles.clear();
    assert!(replay(profile, &[], &[], None, &missing).is_err());
    let mut missing_fold = registry(Vec::new());
    missing_fold.open_items = None;
    assert!(replay(profile, &entries, &live, Some(30), &missing_fold).is_err());
    let mut invalid = item(1, 0, 100, true);
    invalid.applied = 60;
    assert!(replay(profile, &entries, &live, Some(30), &registry(vec![invalid])).is_err());
    assert!(
        replay(
            profile,
            &entries,
            &live,
            Some(30),
            &registry(vec![item(1, 0, i128::MAX, true), item(2, 0, 1, true)]),
        )
        .is_err()
    );
    assert!(
        replay(
            profile,
            &entries,
            &live,
            Some(30),
            &registry(vec![item(1, 31, 1, true)]),
        )
        .is_err()
    );
}

#[test]
fn capitalization_uses_declared_roles_original_sides_and_registered_tie_break() {
    let mut selected = entry(1, 10);
    selected.legs = vec![(1, 900), (2, 7), (1, 900), (2, 7)];
    selected.leg_accounts = vec![(30, true), (10, true), (40, false), (50, false)];
    let mut ordinary_cash_purchase = entry(2, 10);
    ordinary_cash_purchase.leg_accounts = vec![(30, true), (20, false)];
    let entries = vec![selected, ordinary_cash_purchase];
    let (findings, entry_work, leg_work, compared) = replay(
        VerifiedProcedureParameters::ExpenseCapitalization,
        &entries,
        &entries.iter().collect::<Vec<_>>(),
        None,
        &registry(Vec::new()),
    )
    .unwrap();
    assert_eq!((entry_work, leg_work, compared), (2, 6, 0));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].entry, Some(1));
    assert_eq!(findings[0].population, 2);
    assert_eq!(
        findings[0].statistic,
        VerifiedProcedureStatistic::CapitalizedExpense {
            capital_asset: 10,
            cost_accounts: vec![40, 50],
            unit: 2,
            amount: 7,
            scale: 0,
        }
    );
    assert_eq!(
        findings[0].narrative,
        "entry capitalizes 7 in unit 2 by debiting capital asset A-first and crediting operating cost L-accrued"
    );
    let mut roles = registry(Vec::new());
    roles.account_roles.get_mut(&40).unwrap().clear();
    let changed = replay(
        VerifiedProcedureParameters::ExpenseCapitalization,
        &entries,
        &entries.iter().collect::<Vec<_>>(),
        None,
        &roles,
    )
    .unwrap()
    .0;
    let VerifiedProcedureStatistic::CapitalizedExpense { cost_accounts, .. } =
        &changed[0].statistic
    else {
        panic!("capitalized expense");
    };
    assert_eq!(
        cost_accounts,
        &[50],
        "unassigned accrued roles do not survive"
    );
}

#[test]
fn capitalization_refuses_missing_historical_roles_and_metadata_even_without_hits() {
    let profile = VerifiedProcedureParameters::ExpenseCapitalization;
    let valid = registry(Vec::new());
    assert_eq!(
        replay(profile, &[], &[], None, &valid).unwrap(),
        (Vec::new(), 0, 0, 0)
    );
    let mut missing = registry(Vec::new());
    missing.account_roles.clear();
    assert!(replay(profile, &[], &[], None, &missing).is_err());
    assert!(replay(profile, &[], &[], Some(0), &valid).is_err());
    let entries = vec![entry(1, 0)];
    let live = entries.iter().collect::<Vec<_>>();
    missing = registry(Vec::new());
    missing.account_types.remove(&10);
    assert!(replay(profile, &entries, &live, None, &missing).is_err());
}
