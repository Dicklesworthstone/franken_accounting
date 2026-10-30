//! Exact consolidation arithmetic over independently folded entity balances.
//! The source is indexed once by unit and by (entity, unit); ownership and
//! intercompany calculations never scan unrelated units for every group link.

use super::{
    Balances, ConsolidationElimination, ConsolidationEquity, ConsolidationLeg, Entity, Ownership,
    ReportError, Totals, add, entity_hex, invalid, metadata, negate, subtract,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Calculation {
    pub stock: Totals,
    pub activity: Totals,
    pub eliminations: Vec<ConsolidationElimination>,
    pub income_eliminations: Vec<ConsolidationElimination>,
    pub equity: Vec<ConsolidationEquity>,
}

struct Nets {
    cells: BTreeMap<(Entity, u128, u32), i128>,
    units: BTreeMap<u32, Vec<(Entity, u128, i128)>>,
    entities: BTreeMap<(Entity, u32), Vec<(u128, i128)>>,
}
impl Nets {
    fn new(source: &Balances) -> Result<Self, ReportError> {
        let mut out = Self {
            cells: BTreeMap::new(),
            units: BTreeMap::new(),
            entities: BTreeMap::new(),
        };
        for (&(entity, account, unit), &(debits, credits)) in source {
            if debits < 0 || credits < 0 {
                return Err(invalid("negative entity balance"));
            }
            let net = subtract(debits, credits)?;
            out.cells.insert((entity, account, unit), net);
            out.units
                .entry(unit)
                .or_default()
                .push((entity, account, net));
            out.entities
                .entry((entity, unit))
                .or_default()
                .push((account, net));
        }
        Ok(out)
    }
    fn cell(&self, entity: Entity, account: u128, unit: u32) -> i128 {
        self.cells
            .get(&(entity, account, unit))
            .copied()
            .unwrap_or(0)
    }
    fn entity(&self, entity: Entity, unit: u32) -> &[(u128, i128)] {
        self.entities
            .get(&(entity, unit))
            .map_or(&[], Vec::as_slice)
    }
    fn credit(
        &self,
        schema: &metadata::Schema,
        entity: Entity,
        unit: u32,
        types: &[u8],
    ) -> Result<i128, ReportError> {
        self.entity(entity, unit)
            .iter()
            .try_fold(0, |sum, (account, net)| {
                if types.contains(&schema.accounts[account].account_type) {
                    add(sum, negate(*net)?)
                } else {
                    Ok(sum)
                }
            })
    }
}

/// Compute signed HalfEven(amount * bps / 10000) without ever forming the
/// overflowing product. The quotient part is at most the original magnitude;
/// the remainder product is below 100 million. This also supports i128::MIN.
fn controlling_share(amount: i128, bps: u16) -> Result<i128, ReportError> {
    if !(1..=10_000).contains(&bps) {
        return Err(invalid("invalid ownership basis points"));
    }
    let magnitude = amount.unsigned_abs();
    let bps = u128::from(bps);
    let whole = (magnitude / 10_000)
        .checked_mul(bps)
        .ok_or_else(|| invalid("controlling share overflow"))?;
    let tail = (magnitude % 10_000) * bps;
    let mut rounded = whole
        .checked_add(tail / 10_000)
        .ok_or_else(|| invalid("controlling share overflow"))?;
    let remainder = tail % 10_000;
    if remainder > 5_000 || remainder == 5_000 && rounded % 2 != 0 {
        rounded = rounded
            .checked_add(1)
            .ok_or_else(|| invalid("controlling share overflow"))?;
    }
    if amount < 0 && rounded == i128::MIN.unsigned_abs() {
        return Ok(i128::MIN);
    }
    let rounded = i128::try_from(rounded).map_err(|_| invalid("controlling share overflow"))?;
    if amount < 0 {
        negate(rounded)
    } else {
        Ok(rounded)
    }
}

fn minority_share(amount: i128, bps: u16) -> Result<i128, ReportError> {
    subtract(amount, controlling_share(amount, bps)?)
}

/// Reverse a signed debit-normal net; zero has no monetary leg.
fn reversing(
    legs: &mut Vec<ConsolidationLeg>,
    entity: Entity,
    account: u128,
    unit: u32,
    net: i128,
) -> Result<(), ReportError> {
    if net == 0 {
        return Ok(());
    }
    let (debits, credits) = if net > 0 { (0, net) } else { (negate(net)?, 0) };
    legs.push(ConsolidationLeg {
        entity_id: entity,
        account_id: account,
        unit_id: unit,
        debits,
        credits,
    });
    Ok(())
}

fn balanced(entry: ConsolidationElimination) -> Result<ConsolidationElimination, ReportError> {
    let (mut debits, mut credits) = (0, 0);
    for leg in &entry.legs {
        if leg.unit_id != entry.unit_id
            || leg.debits < 0
            || leg.credits < 0
            || (leg.debits == 0) == (leg.credits == 0)
        {
            return Err(invalid("derived elimination leg is not canonical"));
        }
        debits = add(debits, leg.debits)?;
        credits = add(credits, leg.credits)?;
    }
    if debits != credits {
        return Err(invalid("derived elimination does not balance"));
    }
    Ok(entry)
}

fn group_elimination(
    source: &Nets,
    schema: &metadata::Schema,
    accounts: &BTreeSet<u128>,
    unit: u32,
    activity: bool,
) -> Result<Option<ConsolidationElimination>, ReportError> {
    let mut legs = Vec::new();
    // Separate balance-sheet and earnings categories prevent a one-sided
    // intercompany sale's receivable and revenue from cancelling each other.
    let categories: &[bool] = if activity { &[false] } else { &[true, false] };
    for &balance_sheet in categories {
        let mut residual = 0;
        for &(entity, account, net) in source.units.get(&unit).map_or(&[][..], Vec::as_slice) {
            if net == 0
                || !accounts.contains(&account)
                || matches!(schema.accounts[&account].account_type, 1 | 2) != balance_sheet
            {
                continue;
            }
            residual = add(residual, net)?;
            reversing(&mut legs, entity, account, unit, net)?;
        }
        if residual != 0 {
            return Err(invalid(
                "intercompany balances or transactions do not match by category and unit",
            ));
        }
    }
    if legs.is_empty() {
        return Ok(None);
    }
    balanced(ConsolidationElimination {
        code: format!("ELIM-IC-GROUP-U{unit}"),
        description: format!(
            "Eliminate the group's intercompany balances and transactions in unit {unit}"
        ),
        unit_id: unit,
        legs,
    })
    .map(Some)
}

fn earnings_allocation(
    link: &Ownership,
    unit: u32,
    share: i128,
    what: &str,
) -> Result<ConsolidationElimination, ReportError> {
    let (Some(nci), Some(income)) = (link.nci, link.nci_income) else {
        return Err(invalid(
            "a nonzero earnings allocation requires both NCI roles",
        ));
    };
    let sub = entity_hex(&link.subsidiary);
    let mut legs = Vec::with_capacity(2);
    reversing(&mut legs, link.subsidiary, income, unit, negate(share)?)?;
    reversing(&mut legs, link.subsidiary, nci, unit, share)?;
    balanced(ConsolidationElimination {
        code: format!("ELIM-NCI-{sub}-U{unit}"),
        description: format!(
            "Allocate the noncontrolling interest's share of subsidiary {sub}'s {what} ({} bps owned)",
            link.bps
        ),
        unit_id: unit,
        legs,
    })
}

fn reserves_allocation(
    source: &Nets,
    schema: &metadata::Schema,
    link: &Ownership,
    unit: u32,
) -> Result<Option<(ConsolidationElimination, i128)>, ReportError> {
    let mut legs = Vec::new();
    let mut total = 0;
    for &(account, net) in source.entity(link.subsidiary, unit) {
        if net == 0
            || schema.accounts[&account].account_type != 3
            || link.capital.contains(&account)
            || link.nci == Some(account)
        {
            continue;
        }
        let share = minority_share(negate(net)?, link.bps)?;
        if share == 0 {
            continue;
        }
        reversing(&mut legs, link.subsidiary, account, unit, negate(share)?)?;
        total = add(total, share)?;
    }
    if legs.is_empty() {
        return Ok(None);
    }
    let nci = link
        .nci
        .ok_or_else(|| invalid("reserve allocations require an NCI equity account"))?;
    reversing(&mut legs, link.subsidiary, nci, unit, total)?;
    let sub = entity_hex(&link.subsidiary);
    let entry = balanced(ConsolidationElimination {
        code: format!("ELIM-NCI-RES-{sub}-U{unit}"),
        description: format!(
            "Reclassify the noncontrolling interest's share of subsidiary {sub}'s reserves ({} bps owned)",
            link.bps
        ),
        unit_id: unit,
        legs,
    })?;
    Ok(Some((entry, total)))
}

fn with_eliminations(
    source: &Balances,
    eliminations: &[ConsolidationElimination],
) -> Result<Totals, ReportError> {
    let mut totals = Totals::new();
    for (&(_, account, unit), &(debits, credits)) in source {
        let value = totals.entry((account, unit)).or_default();
        value.0 = add(value.0, debits)?;
        value.1 = add(value.1, credits)?;
    }
    for entry in eliminations {
        for leg in &entry.legs {
            let value = totals.entry((leg.account_id, leg.unit_id)).or_default();
            value.0 = add(value.0, leg.debits)?;
            value.1 = add(value.1, leg.credits)?;
        }
    }
    Ok(totals)
}

fn eliminated(
    totals: &Totals,
    schema: &metadata::Schema,
    intercompany: &BTreeSet<u128>,
    units: &[u32],
    activity: bool,
) -> Result<(), ReportError> {
    for &account in intercompany {
        if activity && !matches!(schema.accounts[&account].account_type, 4 | 5) {
            continue;
        }
        for &unit in units {
            if totals
                .get(&(account, unit))
                .is_some_and(|(debits, credits)| debits != credits)
            {
                return Err(invalid("an intercompany account remains after elimination"));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn derive(
    schema: &metadata::Schema,
    units: &[u32],
    members: &BTreeMap<String, Entity>,
    ownership: &[Ownership],
    intercompany: &BTreeSet<u128>,
    stock: &Balances,
    activity: &Balances,
) -> Result<Calculation, ReportError> {
    let stock_nets = Nets::new(stock)?;
    let activity_nets = Nets::new(activity)?;
    let mut eliminations = Vec::new();
    for &unit in units {
        if let Some(entry) = group_elimination(&stock_nets, schema, intercompany, unit, false)? {
            eliminations.push(entry);
        }
    }
    let mut expected_investments: BTreeMap<(Entity, u128, u32), i128> = BTreeMap::new();
    let mut recognized = BTreeMap::<u32, i128>::new();
    let mut allocated = BTreeMap::<u32, i128>::new();
    let mut eliminated_capital = BTreeMap::<u32, i128>::new();
    for link in ownership {
        for &unit in units {
            expected_investments
                .entry((link.parent, link.investment, unit))
                .or_default();
            let mut capital = 0;
            let mut legs = Vec::new();
            for &account in &link.capital {
                let net = stock_nets.cell(link.subsidiary, account, unit);
                capital = add(capital, negate(net)?)?;
                reversing(&mut legs, link.subsidiary, account, unit, net)?;
            }
            let mut allocations = Vec::new();
            if link.bps < 10_000 {
                if let Some((entry, share)) = reserves_allocation(&stock_nets, schema, link, unit)?
                {
                    let nci = recognized.entry(unit).or_default();
                    *nci = add(*nci, share)?;
                    let debit = allocated.entry(unit).or_default();
                    *debit = subtract(*debit, share)?;
                    allocations.push(entry);
                }
                let earnings = stock_nets.credit(schema, link.subsidiary, unit, &[4, 5])?;
                let share = minority_share(earnings, link.bps)?;
                if share != 0 {
                    allocations.push(earnings_allocation(link, unit, share, "unclosed earnings")?);
                    let nci = recognized.entry(unit).or_default();
                    *nci = add(*nci, share)?;
                    let debit = allocated.entry(unit).or_default();
                    *debit = subtract(*debit, share)?;
                }
            }
            if capital == 0 {
                eliminations.extend(allocations);
                continue;
            }
            let controlling = controlling_share(capital, link.bps)?;
            let minority = subtract(capital, controlling)?;
            let expected = expected_investments
                .get_mut(&(link.parent, link.investment, unit))
                .ok_or_else(|| invalid("investment expectation is absent"))?;
            *expected = add(*expected, controlling)?;
            reversing(&mut legs, link.parent, link.investment, unit, controlling)?;
            if minority != 0 {
                let nci = link
                    .nci
                    .ok_or_else(|| invalid("capital allocation requires an NCI equity account"))?;
                reversing(&mut legs, link.subsidiary, nci, unit, minority)?;
                let recognized = recognized.entry(unit).or_default();
                *recognized = add(*recognized, minority)?;
            }
            let eliminated = eliminated_capital.entry(unit).or_default();
            *eliminated = subtract(*eliminated, capital)?;
            let sub = entity_hex(&link.subsidiary);
            eliminations.push(balanced(ConsolidationElimination {
                code: format!("ELIM-EQ-{sub}-U{unit}"),
                description: format!(
                    "Eliminate investment in subsidiary {sub} ({} bps) against subsidiary equity",
                    link.bps
                ),
                unit_id: unit,
                legs,
            })?);
            eliminations.extend(allocations);
        }
    }
    for ((parent, account, unit), expected) in expected_investments {
        if stock_nets.cell(parent, account, unit) != expected {
            return Err(invalid(
                "parent investment differs from the controlling shares of contributed capital",
            ));
        }
    }
    let consolidated_stock = with_eliminations(stock, &eliminations)?;
    eliminated(&consolidated_stock, schema, intercompany, units, false)?;
    let mut income_eliminations = Vec::new();
    for &unit in units {
        if let Some(entry) = group_elimination(&activity_nets, schema, intercompany, unit, true)? {
            income_eliminations.push(entry);
        }
    }
    for link in ownership.iter().filter(|link| link.bps < 10_000) {
        for &unit in units {
            let earnings = activity_nets.credit(schema, link.subsidiary, unit, &[4, 5])?;
            let share = minority_share(earnings, link.bps)?;
            if share != 0 {
                income_eliminations.push(earnings_allocation(
                    link,
                    unit,
                    share,
                    "earnings for the period",
                )?);
            }
        }
    }
    let consolidated_activity = with_eliminations(activity, &income_eliminations)?;
    eliminated(&consolidated_activity, schema, intercompany, units, true)?;
    let subsidiaries: BTreeSet<_> = ownership.iter().map(|link| link.subsidiary).collect();
    let mut equity = Vec::with_capacity(units.len());
    for &unit in units {
        let mut parent_total = super::statement::Sum::default();
        let mut subsidiary_total = super::statement::Sum::default();
        for &entity in members.values() {
            let total = stock_nets.credit(schema, entity, unit, &[3, 4, 5])?;
            let sum = if subsidiaries.contains(&entity) {
                &mut subsidiary_total
            } else {
                &mut parent_total
            };
            sum.add(total, false)
                .ok_or_else(|| invalid("member equity total overflow"))?;
        }
        let parent_total = parent_total
            .value()
            .ok_or_else(|| invalid("parent equity total overflow"))?;
        let subsidiary_total = subsidiary_total
            .value()
            .ok_or_else(|| invalid("subsidiary equity total overflow"))?;
        let mut intercompany_effect = 0;
        for entry in eliminations
            .iter()
            .filter(|entry| entry.unit_id == unit && entry.code.starts_with("ELIM-IC-"))
        {
            for leg in &entry.legs {
                if matches!(schema.accounts[&leg.account_id].account_type, 3..=5) {
                    intercompany_effect =
                        add(intercompany_effect, subtract(leg.credits, leg.debits)?)?;
                }
            }
        }
        let nci = recognized.get(&unit).copied().unwrap_or(0);
        let elimination = add(
            add(
                eliminated_capital.get(&unit).copied().unwrap_or(0),
                intercompany_effect,
            )?,
            allocated.get(&unit).copied().unwrap_or(0),
        )?;
        let consolidated = add(add(add(parent_total, subsidiary_total)?, elimination)?, nci)?;
        equity.push(ConsolidationEquity {
            unit_id: unit,
            parent_total_equity: parent_total,
            subsidiaries_total_equity: subsidiary_total,
            equity_eliminations: elimination,
            non_controlling_interest_equity: nci,
            controlling_interest_equity: subtract(consolidated, nci)?,
            consolidated_total_equity: consolidated,
        });
    }
    Ok(Calculation {
        stock: consolidated_stock,
        activity: consolidated_activity,
        eliminations,
        income_eliminations,
        equity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_nci_rounding_has_exact_ties_and_full_width_intermediates() {
        for (amount, bps, expected) in [
            (5, 5_000, 2),
            (7, 5_000, 4),
            (-5, 5_000, -2),
            (-7, 5_000, -4),
            (101, 8_000, 81),
            (-101, 8_000, -81),
            (i128::MAX, 10_000, i128::MAX),
            (i128::MIN, 10_000, i128::MIN),
            (i128::MIN, 5_000, i128::MIN / 2),
        ] {
            assert_eq!(controlling_share(amount, bps).unwrap(), expected);
            assert_eq!(
                add(expected, minority_share(amount, bps).unwrap()).unwrap(),
                amount
            );
        }
        for amount in -257i128..=257 {
            for bps in [1u16, 2_500, 3_333, 5_000, 8_000, 9_999, 10_000] {
                let product = amount.abs() * i128::from(bps);
                let quotient = product / 10_000;
                let remainder = product % 10_000;
                let expected = (quotient
                    + i128::from(remainder > 5_000 || remainder == 5_000 && quotient % 2 != 0))
                    * amount.signum();
                assert_eq!(controlling_share(amount, bps).unwrap(), expected);
            }
        }
    }

    fn schema() -> metadata::Schema {
        let mut schema = metadata::Schema::default();
        for (id, code, kind) in [
            (1, "cash", 1),
            (2, "investment", 1),
            (3, "capital", 3),
            (4, "reserve", 3),
            (5, "revenue", 4),
            (6, "expense", 5),
            (7, "nci", 3),
            (8, "nci_income", 5),
        ] {
            schema.accounts.insert(
                id,
                metadata::Account {
                    code: code.into(),
                    name: code.into(),
                    account_type: kind,
                    normal_balance: u8::from(matches!(kind, 2..=4)),
                    is_leaf: true,
                    unit_policy: -1,
                    limit: None,
                    created_at: 1,
                },
            );
        }
        schema
    }

    #[test]
    fn shared_investment_is_proved_against_all_subsidiaries_together() {
        let (parent, first, second) = ([1; 16], [2; 16], [3; 16]);
        let members = BTreeMap::from([
            ("P".into(), parent),
            ("S".into(), first),
            ("T".into(), second),
        ]);
        let stock = BTreeMap::from([
            ((parent, 1, 0), (850, 0)),
            ((parent, 2, 0), (150, 0)),
            ((parent, 3, 0), (0, 1_000)),
            ((first, 1, 0), (100, 0)),
            ((first, 3, 0), (0, 100)),
            ((second, 1, 0), (50, 0)),
            ((second, 3, 0), (0, 50)),
        ]);
        let links: Vec<_> = [first, second]
            .into_iter()
            .map(|subsidiary| Ownership {
                parent,
                subsidiary,
                bps: 10_000,
                investment: 2,
                capital: vec![3],
                nci: None,
                nci_income: None,
            })
            .collect();
        let result = derive(
            &schema(),
            &[0],
            &members,
            &links,
            &BTreeSet::new(),
            &stock,
            &Balances::new(),
        )
        .unwrap();
        assert_eq!(result.eliminations.len(), 2);
        assert_eq!(result.stock[&(2, 0)], (150, 150));
        assert_eq!(result.equity[0].consolidated_total_equity, 1_000);
        let mut false_basis = stock;
        false_basis.insert((parent, 2, 0), (149, 0));
        false_basis.insert((parent, 1, 0), (851, 0));
        let error = derive(
            &schema(),
            &[0],
            &members,
            &links,
            &BTreeSet::new(),
            &false_basis,
            &Balances::new(),
        )
        .err()
        .unwrap();
        assert!(error.detail.contains("parent investment"));
    }

    #[test]
    fn reserves_and_signed_losses_keep_stock_nci_separate_from_period_income() {
        let (parent, sub) = ([1; 16], [2; 16]);
        let members = BTreeMap::from([("P".into(), parent), ("S".into(), sub)]);
        let stock = BTreeMap::from([
            ((parent, 1, 0), (920, 0)),
            ((parent, 2, 0), (80, 0)),
            ((parent, 3, 0), (0, 1_000)),
            ((sub, 1, 0), (135, 15)),
            ((sub, 3, 0), (0, 100)),
            ((sub, 4, 0), (0, 30)),
            ((sub, 5, 0), (0, 5)),
            ((sub, 6, 0), (15, 0)),
        ]);
        let activity = BTreeMap::from([((sub, 1, 0), (0, 15)), ((sub, 6, 0), (15, 0))]);
        let links = [Ownership {
            parent,
            subsidiary: sub,
            bps: 8_000,
            investment: 2,
            capital: vec![3],
            nci: Some(7),
            nci_income: Some(8),
        }];
        let result = derive(
            &schema(),
            &[0],
            &members,
            &links,
            &BTreeSet::new(),
            &stock,
            &activity,
        )
        .unwrap();
        assert_eq!(result.eliminations.len(), 3);
        assert_eq!(
            result.eliminations[1]
                .legs
                .iter()
                .map(|leg| (leg.account_id, leg.debits, leg.credits))
                .collect::<Vec<_>>(),
            [(4, 6, 0), (7, 0, 6)]
        );
        assert_eq!(
            result.eliminations[2]
                .legs
                .iter()
                .map(|leg| (leg.account_id, leg.debits, leg.credits))
                .collect::<Vec<_>>(),
            [(8, 0, 2), (7, 2, 0)]
        );
        assert_eq!(result.income_eliminations.len(), 1);
        assert_eq!(
            result.income_eliminations[0]
                .legs
                .iter()
                .map(|leg| (leg.account_id, leg.debits, leg.credits))
                .collect::<Vec<_>>(),
            [(8, 0, 3), (7, 3, 0)]
        );
        let equity = &result.equity[0];
        assert_eq!(equity.non_controlling_interest_equity, 24);
        assert_eq!(equity.equity_eliminations, -104);
        assert_eq!(equity.consolidated_total_equity, 1_040);
        assert_eq!(equity.controlling_interest_equity, 1_016);
    }
}
