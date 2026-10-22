//! Exact bank CSV parsing under an explicit, retained interpretation.

use fa_model::bank_csv::{BankCsvAmounts, BankCsvDateFormat, BankCsvLayout};
use fa_money::{Amount, Side};
use fa_time::DateDay;

use super::{
    BankStatementExtract, ParsedBankLine, bank_csv_records_with, compute_bank_line_digest,
};
use crate::{FormatError, UnitCatalog, parse_exact_decimal};

const FMT: &str = "bank_csv_layout_v1";

fn invalid(detail: impl Into<String>) -> FormatError {
    FormatError::Parse {
        format: FMT,
        detail: detail.into(),
    }
}

fn date(value: &str, format: BankCsvDateFormat) -> Result<DateDay, FormatError> {
    let value = value.trim();
    let iso = match format {
        BankCsvDateFormat::Iso => value.to_owned(),
        BankCsvDateFormat::MonthDayYear | BankCsvDateFormat::DayMonthYear => {
            let b = value.as_bytes();
            if b.len() != 10
                || b[2] != b'/'
                || b[5] != b'/'
                || b.iter()
                    .enumerate()
                    .any(|(i, b)| i != 2 && i != 5 && !b.is_ascii_digit())
            {
                return Err(invalid(format!(
                    "date {value:?} does not match the declared MM/DD/YYYY or DD/MM/YYYY layout"
                )));
            }
            let (month, day) = if format == BankCsvDateFormat::MonthDayYear {
                (&value[..2], &value[3..5])
            } else {
                (&value[3..5], &value[..2])
            };
            format!("{}-{month}-{day}", &value[6..])
        }
    };
    DateDay::parse(&iso).map_err(|_| {
        invalid(format!(
            "invalid civil date {value:?} in the declared layout"
        ))
    })
}

fn decimal(value: &str, separator: u8, scale: u8) -> Result<i128, FormatError> {
    let value = value.trim();
    let opposite = if separator == b',' { '.' } else { ',' };
    if value.contains(opposite) {
        return Err(invalid(
            "amount uses an undeclared decimal separator or grouping",
        ));
    }
    let canonical = if separator == b',' {
        value.replace(',', ".")
    } else {
        value.to_owned()
    };
    parse_exact_decimal(FMT, &canonical, scale)
}

/// Parse the exact declared header, with no date, currency, sign or header
/// inference. The complete layout is retained by the bank import manifest.
/// Empty statements are valid iff the explicit opening and closing agree.
pub fn parse_bank_csv_with_layout(
    csv: &str,
    units: &UnitCatalog,
    layout: &BankCsvLayout,
) -> Result<BankStatementExtract, FormatError> {
    layout.validate().map_err(invalid)?;
    let (unit, scale) =
        units
            .lookup_code(&layout.currency)
            .ok_or_else(|| FormatError::UnknownUnit {
                format: FMT,
                unit: layout.currency.clone(),
            })?;
    let records = bank_csv_records_with(
        csv,
        char::from(layout.delimiter),
        layout.headers.len(),
        fa_model::limits::MAX_IMPORT_DOCUMENTS - 1,
        FMT,
    )?;
    let mut records = records.into_iter();
    let header = records
        .next()
        .ok_or_else(|| invalid("empty CSV bank statement"))?;
    if header != layout.headers {
        return Err(invalid(format!(
            "CSV header does not exactly match layout {}: expected ordered columns {:?}",
            layout.name, layout.headers
        )));
    }
    let index = |name: &str| {
        layout
            .headers
            .iter()
            .position(|header| header == name)
            .ok_or_else(|| invalid(format!("mapped column {name:?} is not declared")))
    };
    let booking = index(&layout.booking_date)?;
    let value = layout.value_date.as_deref().map(index).transpose()?;
    let counterparty = layout.counterparty.as_deref().map(index).transpose()?;
    let reference = layout.reference.as_deref().map(index).transpose()?;
    let (first_amount, second_amount) = match &layout.amounts {
        BankCsvAmounts::Signed { column, .. } => (index(column)?, None),
        BankCsvAmounts::DebitCredit { debit, credit } => (index(debit)?, Some(index(credit)?)),
    };
    let opening_balance = decimal(&layout.opening_balance, layout.decimal_separator, scale)?;
    let closing_balance = decimal(&layout.closing_balance, layout.decimal_separator, scale)?;
    let mut lines = Vec::new();
    for record in records {
        let ordinal = u32::try_from(lines.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| invalid("bank CSV line ordinal overflows"))?;
        if record.len() != layout.headers.len() {
            return Err(invalid(format!(
                "CSV row {ordinal} has {} fields, expected {}",
                record.len(),
                layout.headers.len()
            )));
        }
        let booking_date = date(&record[booking], layout.date_format)?;
        let value_date = value
            .map(|i| date(&record[i], layout.date_format))
            .transpose()?
            .unwrap_or(booking_date);
        if booking_date > layout.statement_date {
            return Err(invalid(format!(
                "CSV row {ordinal} books after the statement closing date"
            )));
        }
        let (side, magnitude) = match &layout.amounts {
            BankCsvAmounts::Signed {
                positive_is_credit, ..
            } => {
                let signed = decimal(&record[first_amount], layout.decimal_separator, scale)?;
                if signed == 0 {
                    return Err(invalid(format!("CSV row {ordinal} has a zero movement")));
                }
                let credit = (signed > 0) == *positive_is_credit;
                let magnitude = signed
                    .checked_abs()
                    .ok_or_else(|| invalid("CSV magnitude exceeds the exact integer range"))?;
                (if credit { Side::Credit } else { Side::Debit }, magnitude)
            }
            BankCsvAmounts::DebitCredit { .. } => {
                let field = |i: usize| {
                    if record[i].trim().is_empty() {
                        Ok(0)
                    } else {
                        decimal(&record[i], layout.decimal_separator, scale)
                    }
                };
                let debit = field(first_amount)?;
                let credit = field(second_amount.ok_or_else(|| invalid("missing credit column"))?)?;
                match (debit, credit) {
                    (debit, 0) if debit > 0 => (Side::Debit, debit),
                    (0, credit) if credit > 0 => (Side::Credit, credit),
                    _ => {
                        return Err(invalid(format!(
                            "CSV row {ordinal} must have exactly one positive debit or credit; no negative or simultaneous amounts"
                        )));
                    }
                }
            }
        };
        let counterparty = counterparty.map(|i| record[i].clone()).unwrap_or_default();
        let reference = reference.map(|i| record[i].clone()).unwrap_or_default();
        if counterparty.len() > fa_model::limits::MAX_MEMO_BYTES
            || reference.len() > fa_model::limits::MAX_MEMO_BYTES
        {
            return Err(invalid(
                "CSV counterparty or reference exceeds the registered memo limit",
            ));
        }
        let amount = Amount::new(unit, magnitude);
        let line_digest = compute_bank_line_digest(
            &layout.instrument_id,
            layout.sequence_number,
            ordinal,
            booking_date,
            side,
            amount,
            &reference,
        );
        lines.push(ParsedBankLine {
            line_ordinal: ordinal,
            booking_date,
            value_date,
            side,
            amount,
            counterparty,
            reference,
            line_digest,
        });
    }
    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: layout.instrument_id.clone(),
        sequence_number: layout.sequence_number,
        currency: layout.currency.clone(),
        statement_date: layout.statement_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> BankCsvLayout {
        BankCsvLayout {
            name: "bank-download-v1".into(),
            headers: ["Date", "Value", "Name", "Reference", "Movement"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            delimiter: b';',
            decimal_separator: b',',
            date_format: BankCsvDateFormat::DayMonthYear,
            booking_date: "Date".into(),
            value_date: Some("Value".into()),
            counterparty: Some("Name".into()),
            reference: Some("Reference".into()),
            amounts: BankCsvAmounts::Signed {
                column: "Movement".into(),
                positive_is_credit: true,
            },
            instrument_id: "BANK-OPER-01".into(),
            sequence_number: 1,
            currency: "USD".into(),
            statement_date: DateDay::parse("2026-03-31").unwrap(),
            opening_balance: "1000,00".into(),
            closing_balance: "1450,00".into(),
        }
    }

    const SOURCE: &str = "Date;Value;Name;Reference;Movement\r\n05/03/2026;06/03/2026;\"Acme; Inc\";WIRE-IN-1;600,00\r\n10/03/2026;10/03/2026;Cloud Vendor;ACH-OUT-1;-150,00\r\n";

    #[test]
    fn declared_csv_layout_applies_without_inference() {
        let units = UnitCatalog::embedded().unwrap();
        let layout = layout();
        let statement = parse_bank_csv_with_layout(SOURCE, &units, &layout).unwrap();
        assert_eq!(statement.opening_balance, 100_000);
        assert_eq!(statement.closing_balance, 145_000);
        assert_eq!(statement.lines.len(), 2);
        assert_eq!(statement.lines[0].side, Side::Credit);
        assert_eq!(statement.lines[1].side, Side::Debit);
        assert_eq!(statement.lines[0].counterparty, "Acme; Inc");
        assert_eq!(
            statement.lines[0].booking_date,
            DateDay::parse("2026-03-05").unwrap()
        );
        assert_eq!(
            statement.lines[0].value_date,
            DateDay::parse("2026-03-06").unwrap()
        );
        let bytes = layout.canonical_bytes().unwrap();
        assert_eq!(BankCsvLayout::decode(&bytes).unwrap(), layout);
        for n in 0..bytes.len() {
            assert!(BankCsvLayout::decode(&bytes[..n]).is_err());
        }
        let restored = BankCsvLayout::decode(&bytes).unwrap();
        assert_eq!(
            parse_bank_csv_with_layout(SOURCE, &units, &restored).unwrap(),
            statement
        );
    }

    #[test]
    fn declared_csv_layout_rejects_ambiguous_or_inexact_input() {
        let units = UnitCatalog::embedded().unwrap();
        for source in [
            SOURCE.replacen("Date;Value", "Value;Date", 1),
            SOURCE.replace("600,00", "600.00"),
            SOURCE.replace("600,00", "600,001"),
            SOURCE.replace("600,00", "6e2"),
            SOURCE.replace("05/03/2026", "03/05/2026"),
            SOURCE.replace("10/03/2026", "31/02/2026"),
            SOURCE.replace("-150,00", "150,00"),
            SOURCE.replace("600,00", "600,00;extra"),
        ] {
            assert!(
                parse_bank_csv_with_layout(&source, &units, &layout()).is_err(),
                "{source}"
            );
        }
        let mut duplicate = layout();
        duplicate.headers[1] = duplicate.headers[0].clone();
        assert!(parse_bank_csv_with_layout(SOURCE, &units, &duplicate).is_err());
        let mut changed = layout();
        changed.amounts = BankCsvAmounts::Signed {
            column: "Movement".into(),
            positive_is_credit: false,
        };
        assert_ne!(changed.digest().unwrap(), layout().digest().unwrap());
        assert!(parse_bank_csv_with_layout(SOURCE, &units, &changed).is_err());
    }

    #[test]
    fn separate_debit_credit_and_empty_statements_are_exact() {
        let units = UnitCatalog::embedded().unwrap();
        let mut layout = layout();
        layout.headers = ["Date", "Debit", "Credit"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        layout.value_date = None;
        layout.counterparty = None;
        layout.reference = None;
        layout.amounts = BankCsvAmounts::DebitCredit {
            debit: "Debit".into(),
            credit: "Credit".into(),
        };
        let source = "Date;Debit;Credit\n05/03/2026;;600,00\n10/03/2026;150,00;0\n";
        let statement = parse_bank_csv_with_layout(source, &units, &layout).unwrap();
        assert_eq!(statement.closing_balance, 145_000);
        for row in [
            "10/03/2026;150,00;150,00",
            "10/03/2026;-150,00;0",
            "10/03/2026;;",
            "10/03/2026;0;0",
        ] {
            let source = format!("Date;Debit;Credit\n{row}\n");
            assert!(parse_bank_csv_with_layout(&source, &units, &layout).is_err());
        }
        layout.closing_balance = layout.opening_balance.clone();
        assert!(
            parse_bank_csv_with_layout("Date;Debit;Credit\n", &units, &layout)
                .unwrap()
                .lines
                .is_empty()
        );
        layout.closing_balance = "1000,01".into();
        assert!(parse_bank_csv_with_layout("Date;Debit;Credit\n", &units, &layout).is_err());
    }

    #[test]
    fn declared_sign_convention_and_unit_scale_are_not_guessed() {
        let units = UnitCatalog::embedded().unwrap();
        let mut layout = layout();
        layout.amounts = BankCsvAmounts::Signed {
            column: "Movement".into(),
            positive_is_credit: false,
        };
        let source = SOURCE
            .replace(";600,00", ";-600,00")
            .replace(";-150,00", ";150,00");
        let statement = parse_bank_csv_with_layout(&source, &units, &layout).unwrap();
        assert_eq!(statement.closing_balance, 145_000);
        assert_eq!(statement.lines[0].side, Side::Credit);
        layout.currency = "UNREGISTERED".into();
        assert!(matches!(
            parse_bank_csv_with_layout(&source, &units, &layout),
            Err(FormatError::UnknownUnit { .. })
        ));
    }
}
