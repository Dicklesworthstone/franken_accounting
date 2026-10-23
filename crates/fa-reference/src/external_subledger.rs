//! Literal external-detail fold (plan §5.6). This oracle uses its own limb
//! arithmetic and linear column discovery, with no production model or kernel.

use crate::Int;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detail {
    pub source: [u8; 32],
    pub account: u128,
    pub unit: u32,
    pub credit: bool,
    pub amount: i128,
    pub dimensions: Vec<(u32, u128)>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Column {
    pub account: u128,
    pub unit: u32,
    pub dimensions: Vec<(u32, u128)>,
    pub credit: bool,
    pub amount: i128,
}

/// Every gross source amount contributes once to exactly one side/coordinate.
/// Opposing sides never cancel; intermediate representability is explicit.
pub fn summarize(rows: &[Detail]) -> Result<Vec<Column>, &'static str> {
    if rows.is_empty() || rows.len() > 128 {
        return Err("source row bound");
    }
    let mut columns: Vec<(Column, Int)> = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if row.source == [0; 32]
            || (index > 0 && rows[index - 1].source >= row.source)
            || row.amount <= 0
            || row.dimensions.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err("noncanonical source row");
        }
        let position = columns.iter().position(|(column, _)| {
            column.account == row.account
                && column.unit == row.unit
                && column.credit == row.credit
                && column.dimensions == row.dimensions
        });
        if let Some(position) = position {
            let (column, value) = &mut columns[position];
            *value = value.add(&Int::from_i128(row.amount));
            column.amount = value.to_i128().ok_or("gross amount overflow")?;
        } else {
            columns.push((
                Column {
                    account: row.account,
                    unit: row.unit,
                    dimensions: row.dimensions.clone(),
                    credit: row.credit,
                    amount: row.amount,
                },
                Int::from_i128(row.amount),
            ));
        }
    }
    if columns.len() < 2 || columns.len() > 32 {
        return Err("summary leg bound");
    }
    let mut result: Vec<_> = columns.into_iter().map(|(column, _)| column).collect();
    result.sort();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gross_columns_keep_zero_net_activity_and_reject_unrepresentable_side_totals() {
        let mut rows = vec![
            Detail {
                source: [1; 32],
                account: 1,
                unit: 1,
                credit: false,
                amount: 40,
                dimensions: vec![],
            },
            Detail {
                source: [2; 32],
                account: 1,
                unit: 1,
                credit: true,
                amount: 40,
                dimensions: vec![],
            },
            Detail {
                source: [3; 32],
                account: 1,
                unit: 1,
                credit: false,
                amount: 60,
                dimensions: vec![],
            },
        ];
        let columns = summarize(&rows).unwrap();
        assert_eq!(
            columns
                .iter()
                .map(|column| (column.credit, column.amount))
                .collect::<Vec<_>>(),
            vec![(false, 100), (true, 40)]
        );
        rows[0].amount = i128::MAX;
        assert_eq!(summarize(&rows), Err("gross amount overflow"));
        rows[0].amount = 1;
        rows[2].source = rows[1].source;
        assert_eq!(summarize(&rows), Err("noncanonical source row"));
    }
}
