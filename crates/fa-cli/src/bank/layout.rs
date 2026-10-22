//! Explicit, bounded JSON declarations for bank CSV input.
use fa::bank::{BankCsvAmounts, BankCsvDateFormat, BankCsvLayout};
use fa_time::DateDay;

use crate::cli::{Fail, usage};
use crate::json::Json;

const EXAMPLE: &str = "fa bank import statement.csv --bank-format csv --account 1000 --layout layout.json --json; declare the exact headers, date/sign/decimal rules, currency and statement balances";

fn invalid(detail: impl Into<String>) -> Fail {
    usage(format!("bank CSV layout: {}", detail.into()), EXAMPLE)
}

fn fields(value: &Json, allowed: &[&str], name: &str) -> Result<(), Fail> {
    let Json::Obj(entries) = value else {
        return Err(invalid(format!("{name} must be an object")));
    };
    if let Some((key, _)) = entries
        .iter()
        .find(|(key, _)| !allowed.contains(&key.as_str()))
    {
        return Err(invalid(format!("unknown {name} field '{key}'")));
    }
    Ok(())
}

fn string<'a>(value: &'a Json, key: &str) -> Result<&'a str, Fail> {
    value
        .get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| invalid(format!("'{key}' must be a string")))
}

fn optional_string(value: &Json, key: &str) -> Result<Option<String>, Fail> {
    match value.get(key) {
        None => Ok(None),
        Some(Json::Str(text)) => Ok(Some(text.clone())),
        _ => Err(invalid(format!("'{key}' must be a string when supplied"))),
    }
}

pub(super) fn parse(text: &str) -> Result<BankCsvLayout, Fail> {
    if text.len() > fa_model::bank_csv::MAX_LAYOUT_BYTES {
        return Err(invalid("the JSON declaration exceeds 16384 bytes"));
    }
    let json = crate::json::parse(text).map_err(|error| invalid(error.to_string()))?;
    fields(
        &json,
        &[
            "version",
            "name",
            "headers",
            "delimiter",
            "decimal_separator",
            "date_format",
            "booking_date",
            "value_date",
            "counterparty",
            "reference",
            "amount",
            "statement",
        ],
        "layout",
    )?;
    if json.get("version") != Some(&Json::Int(1)) {
        return Err(invalid("'version' must be the integer 1"));
    }
    let headers = json
        .get("headers")
        .and_then(Json::as_arr)
        .ok_or_else(|| invalid("'headers' must be an array of exact column names"))?;
    if headers.len() > fa_model::bank_csv::MAX_COLUMNS {
        return Err(invalid("'headers' exceeds 32 columns"));
    }
    let headers = headers
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("every header must be a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let delimiter = match optional_string(&json, "delimiter")?
        .as_deref()
        .unwrap_or(",")
    {
        "," => b',',
        ";" => b';',
        "\t" => b'\t',
        _ => return Err(invalid("'delimiter' must be comma, semicolon or a tab")),
    };
    let decimal_separator = match optional_string(&json, "decimal_separator")?
        .as_deref()
        .unwrap_or(".")
    {
        "." => b'.',
        "," => b',',
        _ => return Err(invalid("'decimal_separator' must be '.' or ','")),
    };
    let date_format = match optional_string(&json, "date_format")?
        .as_deref()
        .unwrap_or("YYYY-MM-DD")
    {
        "YYYY-MM-DD" => BankCsvDateFormat::Iso,
        "MM/DD/YYYY" => BankCsvDateFormat::MonthDayYear,
        "DD/MM/YYYY" => BankCsvDateFormat::DayMonthYear,
        _ => {
            return Err(invalid(
                "'date_format' must be YYYY-MM-DD, MM/DD/YYYY or DD/MM/YYYY",
            ));
        }
    };
    let amount = json
        .get("amount")
        .ok_or_else(|| invalid("'amount' is required"))?;
    let amounts = if amount.get("column").is_some() {
        fields(amount, &["column", "positive"], "amount")?;
        let positive_is_credit = match string(amount, "positive")? {
            "credit" => true,
            "debit" => false,
            _ => return Err(invalid("'positive' must explicitly be 'credit' or 'debit'")),
        };
        BankCsvAmounts::Signed {
            column: string(amount, "column")?.to_owned(),
            positive_is_credit,
        }
    } else {
        fields(amount, &["debit", "credit"], "amount")?;
        BankCsvAmounts::DebitCredit {
            debit: string(amount, "debit")?.to_owned(),
            credit: string(amount, "credit")?.to_owned(),
        }
    };
    let statement = json
        .get("statement")
        .ok_or_else(|| invalid("'statement' is required"))?;
    fields(
        statement,
        &[
            "instrument_id",
            "sequence_number",
            "currency",
            "statement_date",
            "opening_balance",
            "closing_balance",
        ],
        "statement",
    )?;
    let sequence_number = match statement.get("sequence_number") {
        Some(Json::Int(value)) => u64::try_from(*value)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid("'sequence_number' must be an integer in 1..=u64::MAX"))?,
        _ => return Err(invalid("'sequence_number' must be a positive integer")),
    };
    let statement_date = DateDay::parse(string(statement, "statement_date")?)
        .map_err(|error| invalid(format!("'statement_date' must be YYYY-MM-DD: {error}")))?;
    let layout = BankCsvLayout {
        name: string(&json, "name")?.to_owned(),
        headers,
        delimiter,
        decimal_separator,
        date_format,
        booking_date: string(&json, "booking_date")?.to_owned(),
        value_date: optional_string(&json, "value_date")?,
        counterparty: optional_string(&json, "counterparty")?,
        reference: optional_string(&json, "reference")?,
        amounts,
        instrument_id: string(statement, "instrument_id")?.to_owned(),
        sequence_number,
        currency: string(statement, "currency")?.to_owned(),
        statement_date,
        opening_balance: string(statement, "opening_balance")?.to_owned(),
        closing_balance: string(statement, "closing_balance")?.to_owned(),
    };
    layout.validate().map_err(invalid)?;
    let bytes = layout
        .canonical_bytes()
        .map_err(|error| invalid(error.to_string()))?;
    if bytes.len() > fa_model::bank_csv::MAX_LAYOUT_BYTES {
        return Err(invalid("the canonical declaration exceeds 16384 bytes"));
    }
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYOUT: &str = r#"{"version":1,"name":"download","headers":["Date","Amount"],"booking_date":"Date","amount":{"column":"Amount","positive":"credit"},"statement":{"instrument_id":"OPERATING","sequence_number":1,"currency":"USD","statement_date":"2026-03-31","opening_balance":"0.00","closing_balance":"12.34"}}"#;

    #[test]
    fn exact_layout_json_rejects_unknown_duplicate_and_coercible_fields() {
        let layout = parse(LAYOUT).unwrap();
        assert_eq!(layout.delimiter, b',');
        assert_eq!(layout.date_format, BankCsvDateFormat::Iso);
        assert_eq!(layout.currency, "USD");
        assert_eq!(
            BankCsvLayout::decode(&layout.canonical_bytes().unwrap()).unwrap(),
            layout
        );
        for invalid in [
            LAYOUT.replace("\"version\":1", "\"version\":2"),
            LAYOUT.replace("\"version\":1", "\"version\":1,\"version\":1"),
            LAYOUT.replace("\"version\":1", "\"version\":1,\"guess\":true"),
            LAYOUT.replace("\"positive\":\"credit\"", "\"positive\":\"automatic\""),
            LAYOUT.replace(
                "\"positive\":\"credit\"",
                "\"positive\":\"credit\",\"debit\":\"Amount\"",
            ),
            LAYOUT.replace("\"opening_balance\":\"0.00\"", "\"opening_balance\":0"),
            LAYOUT.replace("\"currency\":\"USD\"", "\"currency\":\"USD\",\"scale\":2"),
            LAYOUT.replace("\"sequence_number\":1", "\"sequence_number\":0"),
            LAYOUT.replace("\"Date\",\"Amount\"", "\"Date\",\"Date\""),
            LAYOUT.replace("\"booking_date\":\"Date\"", "\"booking_date\":\"Missing\""),
            LAYOUT.replace("\"2026-03-31\"", "\"03/31/2026\""),
            LAYOUT.replace(
                "\"booking_date\":\"Date\"",
                "\"booking_date\":\"Date\",\"value_date\":null",
            ),
        ] {
            assert!(parse(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn layout_json_uses_exact_separate_amount_columns() {
        let text = LAYOUT
            .replace("[\"Date\",\"Amount\"]", "[\"Date\",\"Debit\",\"Credit\"]")
            .replace(
                "{\"column\":\"Amount\",\"positive\":\"credit\"}",
                "{\"debit\":\"Debit\",\"credit\":\"Credit\"}",
            );
        assert_eq!(
            parse(&text).unwrap().amounts,
            BankCsvAmounts::DebitCredit {
                debit: "Debit".into(),
                credit: "Credit".into(),
            }
        );
    }
}
