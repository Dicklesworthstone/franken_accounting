use super::*;
use fa_statements::{Account, AccountBalance, ColumnInput, StatementInput};
use fa_time::DateDay;

fn account(id: u128, code: &str, account_type: u8) -> Account {
    Account {
        id,
        code: code.into(),
        name: format!("{code} name"),
        account_type,
        is_leaf: true,
    }
}

fn input(seq: u64, revenue: i128, expense: i128) -> StatementInput {
    let balances = |r: i128, e: i128, unit_id: u32| {
        vec![
            AccountBalance {
                account_id: 1,
                unit_id,
                debits: 100 + r - e,
                credits: 0,
            },
            AccountBalance {
                account_id: 2,
                unit_id,
                debits: 0,
                credits: 100,
            },
            AccountBalance {
                account_id: 3,
                unit_id,
                debits: 0,
                credits: r,
            },
            AccountBalance {
                account_id: 4,
                unit_id,
                debits: e,
                credits: 0,
            },
        ]
    };
    let mut current = balances(revenue, expense, 1);
    current.extend(balances(0, 10, 2));
    let mut prior = balances(0, 0, 1);
    prior.extend(balances(0, 0, 2));
    StatementInput {
        book_id: Id128([1; 16]),
        branch_id: Id128::TRUNK,
        known_at: seq,
        accounts: vec![
            account(1, "cash", 1),
            account(2, "capital", 3),
            account(3, "sales", 4),
            account(4, "expense", 5),
        ],
        units: vec![1, 2],
        columns: vec![
            ColumnInput {
                label: "current".into(),
                periods: vec!["FY2026-P03".into()],
                effective_from: None,
                effective_through: DateDay(100),
                balances: current,
            },
            ColumnInput {
                label: "comparative".into(),
                periods: vec!["FY2025-P03".into()],
                effective_from: None,
                effective_through: DateDay(-265),
                balances: prior,
            },
        ],
    }
}

fn report(input: &StatementInput) -> Statement {
    fa_statements::evaluate(
        &StatementDefinition::embedded("balance-sheet").unwrap(),
        input,
    )
    .unwrap()
}

fn row<'a>(diff: &'a StatementDiff, code: &str, unit: u32) -> &'a StatementLineChange {
    diff.lines()
        .iter()
        .find(|l| l.code == code && l.unit_id == unit)
        .unwrap()
}

fn custom_definition() -> CustomStatementDefinition {
    let mut definition = CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded("balance-sheet").unwrap(),
    );
    definition.name = "company-balance-sheet".into();
    definition.version = 7;
    let fa_statements::custom::CustomLineSource::AccountSet { expr, .. } =
        &mut definition.lines[0].source
    else {
        panic!("the first balance-sheet line maps assets");
    };
    *expr = fa_statements::custom::AccountSetExpr::AccountCodes(vec!["cash".into()]);
    definition
}

#[test]
fn custom_bridges_preserve_exact_rows_zero_account_changes_and_separate_basis_domains() {
    let definition = custom_definition();
    let old_input = input(10, 90, 30);
    let mut new_input = input(20, 110, 35);
    new_input.accounts.push(account(99, "zero-sales", 4));
    let before = fa_statements::custom::evaluate_custom(&definition, &old_input).unwrap();
    let after = fa_statements::custom::evaluate_custom(&definition, &new_input).unwrap();
    let native = StatementDiff::between(before, after).unwrap();
    assert!(native.is_custom());
    assert_eq!(native.output_format(), CUSTOM_OUTPUT_FORMAT);
    assert_eq!(row(&native, "assets", 1).delta, [15, 0]);
    assert_eq!(row(&native, "assets", 2).delta, [0, 0]);
    assert_eq!(native.mapping_changes().len(), 1);
    assert_eq!(native.mapping_changes()[0].account_id, 99);
    assert!(native.mapping_changes()[0].before.is_none());

    let single_unit = |mut input: StatementInput| {
        input.units = vec![1];
        for column in &mut input.columns {
            column.balances.retain(|balance| balance.unit_id == 1);
        }
        fa_statements::custom::evaluate_custom(&definition, &input).unwrap()
    };
    let before = single_unit(old_input);
    let after = single_unit(new_input);
    let functional = StatementDiff::between_functional(before.clone(), after.clone()).unwrap();
    let native = StatementDiff::between(before, after).unwrap();
    assert!(functional.is_custom());
    assert_eq!(functional.functional_unit(), Some(UnitId(1)));
    assert_eq!(functional.output_format(), FUNCTIONAL_CUSTOM_OUTPUT_FORMAT);
    assert_eq!(functional.lines(), native.lines());
    assert_ne!(functional.before_digest, native.before_digest);
    assert_ne!(functional.after_digest, native.after_digest);
    assert_ne!(
        functional.canonical_bytes().unwrap(),
        native.canonical_bytes().unwrap()
    );
}

#[test]
fn custom_bridges_accept_the_complete_layout_and_refuse_changed_layouts_or_mapping_forgery() {
    use fa_statements::custom::{CustomLineDefinition, CustomLineSource, evaluate_custom};

    let mut definition = custom_definition();
    while definition.lines.len() < 128 {
        let suffix = definition.lines.len();
        definition.lines.push(CustomLineDefinition {
            code: format!("asset_detail_{suffix}"),
            label: format!("Asset detail {suffix}"),
            source: CustomLineSource::Formula {
                add: vec!["assets".into()],
                subtract: Vec::new(),
            },
        });
    }
    let before = evaluate_custom(&definition, &input(10, 90, 30)).unwrap();
    let after = evaluate_custom(&definition, &input(20, 110, 35)).unwrap();
    let diff = StatementDiff::between(before.clone(), after.clone()).unwrap();
    assert_eq!(diff.lines().len(), 256);
    assert_eq!(diff.lines().last().unwrap().delta, [0, 0]);
    let mut relabeled = definition;
    relabeled.lines[0].label = "Different asset meaning".into();
    let changed = evaluate_custom(&relabeled, &input(20, 110, 35)).unwrap();
    assert!(StatementDiff::between(before.clone(), changed).is_err());
    let mut forged = after.clone();
    forged.mappings[0].line_code = "unclosed_revenue".into();
    assert!(StatementDiff::between(before.clone(), forged).is_err());
    let mut incomplete = after;
    incomplete.lines.pop();
    assert!(StatementDiff::between(before, incomplete).is_err());
}

#[test]
fn exact_bridge_keeps_units_columns_and_subtotals_distinct() {
    let before = report(&input(10, 90, 30));
    let after = report(&input(20, 110, 35));
    let diff = StatementDiff::between(before.clone(), after.clone()).unwrap();
    assert_eq!(diff.before(), &before);
    assert_eq!(diff.after(), &after);
    assert_eq!(row(&diff, "assets", 1).before, vec![160, 100]);
    assert_eq!(row(&diff, "assets", 1).after, vec![175, 100]);
    assert_eq!(row(&diff, "assets", 1).delta, vec![15, 0]);
    assert_eq!(row(&diff, "unclosed_revenue", 1).delta, vec![20, 0]);
    assert_eq!(row(&diff, "unclosed_expense", 1).delta, vec![5, 0]);
    assert_eq!(row(&diff, "unclosed_earnings", 1).delta, vec![15, 0]);
    assert_eq!(row(&diff, "balance_check", 1).delta, vec![0, 0]);
    assert_eq!(row(&diff, "assets", 2).delta, vec![0, 0]);
    assert!(diff.amounts_changed());
    assert!(!diff.is_unchanged());
    assert!(diff.mapping_changes().is_empty());
    assert_eq!(diff.lines().len(), before.lines.len());
    assert_eq!(
        diff.canonical_bytes().unwrap(),
        diff.clone().canonical_bytes().unwrap()
    );
}

#[test]
fn zero_balance_account_additions_and_metadata_changes_are_not_lost() {
    let original = input(10, 90, 30);
    let mut changed = original.clone();
    changed.known_at = 20;
    changed.accounts.push(account(99, "zero-sales", 4));
    changed.accounts[0].name = "Cash renamed".into();
    let diff = StatementDiff::between(report(&original), report(&changed)).unwrap();
    assert!(!diff.amounts_changed());
    assert!(!diff.is_unchanged());
    assert_eq!(diff.mapping_changes().len(), 2);
    assert_eq!(diff.mapping_changes()[0].account_id, 1);
    assert!(diff.mapping_changes()[0].before.is_some());
    assert!(diff.mapping_changes()[0].after.is_some());
    assert_eq!(diff.mapping_changes()[1].account_id, 99);
    assert!(diff.mapping_changes()[1].before.is_none());
    assert_eq!(
        diff.mapping_changes()[1].after.as_ref().unwrap().line_code,
        "unclosed_revenue"
    );
    let mut removal = original;
    removal.known_at = 30;
    let removed = StatementDiff::between(report(&changed), report(&removal)).unwrap();
    assert!(removed.mapping_changes()[1].before.is_some());
    assert!(removed.mapping_changes()[1].after.is_none());
}

#[test]
fn unchanged_history_has_zero_deltas_but_binds_both_recorded_frontiers() {
    let before = report(&input(10, 90, 30));
    let later = report(&input(20, 90, 30));
    let same = StatementDiff::between(before.clone(), before.clone()).unwrap();
    let moved = StatementDiff::between(before, later).unwrap();
    assert!(same.is_unchanged());
    assert!(moved.is_unchanged());
    assert_ne!(
        same.canonical_bytes().unwrap(),
        moved.canonical_bytes().unwrap()
    );
}

#[test]
fn different_books_branches_period_identities_or_definitions_are_not_restatements() {
    let old = report(&input(10, 90, 30));
    let new = report(&input(20, 90, 30));
    let mut foreign = new.clone();
    foreign.book_id = Id128([2; 16]);
    let mut branch = new.clone();
    branch.branch_id = Id128([3; 16]);
    let mut period = new.clone();
    period.columns[0].periods = vec!["FY2026-ADJ".into()];
    let mut cutoff = new.clone();
    cutoff.columns[0].effective_through = DateDay(101);
    let mut definition = new.clone();
    definition.definition_version += 1;
    let mut bytes = new.clone();
    bytes.definition_bytes[0] ^= 1;
    let mut reversed = new.clone();
    reversed.known_at = 9;
    let mut coincident = new.clone();
    coincident.known_at = 10;
    coincident.lines[0].amounts[0] += 1;
    for changed in [
        foreign, branch, period, cutoff, definition, bytes, reversed, coincident,
    ] {
        assert!(StatementDiff::between(old.clone(), changed).is_err());
    }
}

#[test]
fn malformed_line_products_and_missing_zero_rows_are_refused() {
    let old = report(&input(10, 90, 30));
    let new = report(&input(20, 90, 30));
    let mut missing = new.clone();
    missing.lines.pop();
    let mut duplicate = new.clone();
    duplicate.lines[1] = duplicate.lines[0].clone();
    let mut missing_column = new.clone();
    missing_column.lines[0].amounts.pop();
    let mut label = new.clone();
    label.lines[0].label = "another meaning".into();
    let mut order = new.clone();
    order.lines.swap(0, 2);
    let mut mapping = new.clone();
    mapping.mappings[0].line_code = "assets".into();
    let mut duplicate_mapping = new.clone();
    duplicate_mapping
        .mappings
        .push(duplicate_mapping.mappings[0].clone());
    let mut unit = new;
    for line in &mut unit.lines {
        if line.unit_id == 2 {
            line.unit_id = 3;
        }
    }
    for changed in [
        missing,
        duplicate,
        missing_column,
        label,
        order,
        mapping,
        duplicate_mapping,
        unit,
    ] {
        assert!(StatementDiff::between(old.clone(), changed).is_err());
    }
}

fn signed_stock(seq: u64, value: i128) -> Statement {
    let magnitude = if value < 0 { -value } else { value };
    let mut input = input(seq, 0, 0);
    input.units = vec![1];
    input.columns.truncate(1);
    input.columns[0].balances = vec![
        AccountBalance {
            account_id: 1,
            unit_id: 1,
            debits: if value >= 0 { magnitude } else { 0 },
            credits: if value < 0 { magnitude } else { 0 },
        },
        AccountBalance {
            account_id: 2,
            unit_id: 1,
            debits: if value < 0 { magnitude } else { 0 },
            credits: if value >= 0 { magnitude } else { 0 },
        },
    ];
    report(&input)
}

#[test]
fn deltas_check_final_i128_representability_without_rounding_or_netting() {
    let old = signed_stock(10, -1);
    let new = signed_stock(20, i128::MAX);
    let refusal = StatementDiff::between(old, new).unwrap_err();
    assert!(refusal.message.contains("exceeds i128"));
    let edge = StatementDiff::between(signed_stock(10, 1), signed_stock(20, -i128::MAX)).unwrap();
    assert_eq!(row(&edge, "assets", 1).delta, vec![i128::MIN]);
}

#[test]
fn evaluation_order_of_source_accounts_does_not_change_the_bridge() {
    let a = input(10, 90, 30);
    let b = input(20, 110, 35);
    let expected = StatementDiff::between(report(&a), report(&b)).unwrap();
    let mut reordered = b;
    reordered.accounts.reverse();
    for column in &mut reordered.columns {
        column.balances.reverse();
    }
    assert_eq!(
        StatementDiff::between(report(&a), report(&reordered)).unwrap(),
        expected
    );
}

#[test]
fn functional_bridge_commits_one_base_unit_and_a_distinct_valuation_basis() {
    let before = signed_stock(10, 11_000);
    let after = signed_stock(20, 12_200);
    let native = StatementDiff::between(before.clone(), after.clone()).unwrap();
    let functional = StatementDiff::between_functional(before, after).unwrap();
    assert_eq!(functional.functional_unit(), Some(UnitId(1)));
    assert_eq!(row(&functional, "assets", 1).delta, vec![1_200]);
    assert_eq!(functional.lines(), native.lines());
    assert_ne!(functional.before_digest, native.before_digest);
    assert_ne!(functional.after_digest, native.after_digest);
    assert_ne!(
        functional.canonical_bytes().unwrap(),
        native.canonical_bytes().unwrap()
    );
    let bytes = functional.canonical_bytes().unwrap();
    let mut reader = fa_model::Reader::new(&bytes);
    assert_eq!(
        reader.bytes(64, "output format").unwrap(),
        FUNCTIONAL_OUTPUT_FORMAT
    );
    assert_eq!(reader.u32("base unit").unwrap(), 1);
    assert_eq!(
        reader.str(64, "valuation basis").unwrap(),
        "retained-base-amounts"
    );
    assert!(native.functional_unit().is_none());
    assert_eq!(native.output_format(), OUTPUT_FORMAT);

    assert!(
        StatementDiff::between_functional(report(&input(10, 1, 0)), report(&input(20, 2, 0)))
            .is_err(),
        "a native multi-unit report cannot masquerade as a functional statement"
    );
    let mut other_unit = signed_stock(20, 12_200);
    for line in &mut other_unit.lines {
        line.unit_id = 2;
    }
    assert!(StatementDiff::between_functional(signed_stock(10, 11_000), other_unit).is_err());
}
