//! The fixed v1 BalanceSheet and IncomeStatement definitions used by this
//! consolidation method. Their canonical bytes are constructed from the
//! method's closed line vocabulary, never from a producer-selected definition.

use super::{Certificate, ReportError, Totals, framed_hash, invalid, metadata, statement};
use crate::codec::Writer;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
enum Source {
    Account {
        kind: u8,
        credit: bool,
    },
    Formula {
        add: &'static [usize],
        subtract: &'static [usize],
    },
}
#[derive(Clone, Copy)]
struct Line {
    code: &'static str,
    label: &'static str,
    source: Source,
}
const BALANCE: &[Line] = &[
    Line {
        code: "assets",
        label: "Assets",
        source: Source::Account {
            kind: 1,
            credit: false,
        },
    },
    Line {
        code: "liabilities",
        label: "Liabilities",
        source: Source::Account {
            kind: 2,
            credit: true,
        },
    },
    Line {
        code: "equity",
        label: "Posted equity",
        source: Source::Account {
            kind: 3,
            credit: true,
        },
    },
    Line {
        code: "unclosed_revenue",
        label: "Unclosed revenue, all years",
        source: Source::Account {
            kind: 4,
            credit: true,
        },
    },
    Line {
        code: "unclosed_expense",
        label: "Unclosed expenses, all years",
        source: Source::Account {
            kind: 5,
            credit: false,
        },
    },
    Line {
        code: "unclosed_earnings",
        label: "Unclosed earnings, all years",
        source: Source::Formula {
            add: &[3],
            subtract: &[4],
        },
    },
    Line {
        code: "total_equity",
        label: "Equity including unclosed earnings",
        source: Source::Formula {
            add: &[2, 5],
            subtract: &[],
        },
    },
    Line {
        code: "liabilities_and_equity",
        label: "Liabilities and equity including unclosed earnings",
        source: Source::Formula {
            add: &[1, 6],
            subtract: &[],
        },
    },
    Line {
        code: "balance_check",
        label: "Assets less liabilities and equity (must equal zero)",
        source: Source::Formula {
            add: &[0],
            subtract: &[7],
        },
    },
];
const INCOME: &[Line] = &[
    Line {
        code: "revenue",
        label: "Revenue",
        source: Source::Account {
            kind: 4,
            credit: true,
        },
    },
    Line {
        code: "expense",
        label: "Expenses",
        source: Source::Account {
            kind: 5,
            credit: false,
        },
    },
    Line {
        code: "net_income",
        label: "Net income",
        source: Source::Formula {
            add: &[0],
            subtract: &[1],
        },
    },
];

fn definition(activity: bool) -> Vec<u8> {
    let lines = if activity { INCOME } else { BALANCE };
    let (name, title) = if activity {
        ("income-statement", "Income statement")
    } else {
        ("balance-sheet", "Balance sheet")
    };
    let mut w = Writer::default();
    w.fixed(b"FA-STATEMENT-DEF\0")
        .u16(1)
        .u16(0)
        .bytes(name.as_bytes())
        .bytes(title.as_bytes())
        .u32(1)
        .u8(u8::from(activity))
        .count(lines.len());
    for line in lines {
        w.bytes(line.code.as_bytes()).bytes(line.label.as_bytes());
        match line.source {
            Source::Account { kind, credit } => {
                w.u8(0).count(1).u8(kind).u8(u8::from(credit));
            }
            Source::Formula { add, subtract } => {
                w.u8(1);
                for operands in [add, subtract] {
                    w.count(operands.len());
                    for &operand in operands {
                        w.bytes(lines[operand].code.as_bytes());
                    }
                }
            }
        }
    }
    w.count(usize::from(!activity));
    if !activity {
        w.bytes(b"balance_check");
    }
    w.buf
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build(
    activity: bool,
    cert: &Certificate<'_>,
    period: &str,
    from: i32,
    through: i32,
    units: &[u32],
    schema: &metadata::Schema,
    balances: &Totals,
) -> Result<(statement::VerifiedStatement, Vec<u8>), ReportError> {
    let definition = definition(activity);
    let definition_lines = if activity { INCOME } else { BALANCE };
    let mut account_lines = BTreeMap::new();
    let mut mappings = Vec::new();
    for (&identity, account) in &schema.accounts {
        if !account.is_leaf {
            continue;
        }
        let Some(index) = definition_lines.iter().position(|line| {
            matches!(line.source, Source::Account { kind, .. } if kind == account.account_type)
        }) else { continue; };
        account_lines.insert(identity, index);
        mappings.push(statement::StatementMapping {
            account: identity,
            code: account.code.clone(),
            name: account.name.clone(),
            account_type: account.account_type,
            is_leaf: true,
            line_code: definition_lines[index].code.into(),
        });
    }
    mappings.sort_by(|a, b| a.code.cmp(&b.code).then(a.account.cmp(&b.account)));
    let mut sums: BTreeMap<_, _> = units
        .iter()
        .map(|unit| {
            (
                *unit,
                vec![statement::Sum::default(); definition_lines.len()],
            )
        })
        .collect();
    let mut footing: BTreeMap<u32, statement::Sum> = BTreeMap::new();
    for (&(account, unit), &(debits, credits)) in balances {
        let metadata = schema
            .accounts
            .get(&account)
            .ok_or_else(|| invalid("consolidated statement names an unknown account"))?;
        let values = sums
            .get_mut(&unit)
            .ok_or_else(|| invalid("consolidated statement uses an unknown unit"))?;
        if !metadata.is_leaf || debits < 0 || credits < 0 {
            return Err(invalid(
                "consolidated statement has an invalid source balance",
            ));
        }
        if metadata.account_type <= 5 {
            footing
                .entry(unit)
                .or_default()
                .add(debits, false)
                .and_then(|()| footing.get_mut(&unit)?.add(credits, true))
                .ok_or_else(|| invalid("consolidated monetary footing overflow"))?;
        }
        let Some(&index) = account_lines.get(&account) else {
            continue;
        };
        let Source::Account { credit, .. } = definition_lines[index].source else {
            return Err(invalid(
                "consolidated statement mapping points to a formula",
            ));
        };
        values[index]
            .add(debits, credit)
            .and_then(|()| values[index].add(credits, !credit))
            .ok_or_else(|| invalid("consolidated statement accumulation overflow"))?;
    }
    if footing.values().any(|sum| sum.value() != Some(0)) {
        return Err(invalid(
            "consolidated statement source fails monetary footing",
        ));
    }
    let mut values = BTreeMap::new();
    for (unit, mut sums) in sums {
        let mut amounts = Vec::with_capacity(definition_lines.len());
        for (index, line) in definition_lines.iter().enumerate() {
            if let Source::Formula { add, subtract } = line.source {
                for (operands, negative) in [(add, false), (subtract, true)] {
                    for &operand in operands {
                        sums[index]
                            .add(amounts[operand], negative)
                            .ok_or_else(|| invalid("consolidated formula overflow"))?;
                    }
                }
            }
            let value = sums[index]
                .value()
                .ok_or_else(|| invalid("consolidated statement line exceeds i128"))?;
            if line.code == "balance_check" && value != 0 {
                return Err(invalid(
                    "consolidated balance sheet fails its accounting identity",
                ));
            }
            amounts.push(value);
        }
        values.insert(unit, amounts);
    }
    let mut lines = Vec::with_capacity(definition_lines.len() * units.len());
    for (index, line) in definition_lines.iter().enumerate() {
        for unit in units {
            lines.push(statement::StatementLine {
                code: line.code.into(),
                label: line.label.into(),
                unit: *unit,
                amounts: vec![values[unit][index]],
            });
        }
    }
    let result = statement::VerifiedStatement {
        definition_name: if activity {
            "income-statement"
        } else {
            "balance-sheet"
        }
        .into(),
        definition_version: 1,
        definition_digest: framed_hash(b"fa:statement-definition:v1", &[&definition]),
        kind: if activity {
            "IncomeStatement"
        } else {
            "BalanceSheet"
        },
        units: units.to_vec(),
        columns: vec![statement::StatementColumn {
            label: period.into(),
            periods: vec![period.into()],
            effective_from: activity.then_some(from),
            effective_through: through,
        }],
        lines,
        mappings,
    };
    let bytes = statement::encode(
        &result,
        &definition,
        &cert.book,
        &cert.branch,
        cert.known_at,
    )?;
    Ok((result, bytes))
}
