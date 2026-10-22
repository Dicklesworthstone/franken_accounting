//! A declared CSV interpretation retained beside the original bank statement.
//! Headers, date/number conventions and statement metadata are explicit inputs.
//! The bank parser validates amounts against the selected registered currency.

use std::collections::BTreeSet;

use fa_time::DateDay;

use crate::{DecodeError, EncodeError, Oid, Reader, Writer, domain_digest};

pub const LAYOUT_FORMAT: &[u8] = b"fa:bank-csv-layout:v1";
pub const MAX_LAYOUT_BYTES: usize = 16 * 1024;
pub const MAX_COLUMNS: usize = 32;
const MAX_NAME: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BankCsvDateFormat {
    Iso,
    MonthDayYear,
    DayMonthYear,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BankCsvAmounts {
    /// Signed movement: a positive value is an inflow iff positive_is_credit.
    Signed {
        column: String,
        positive_is_credit: bool,
    },
    /// Exactly one column must contain a positive amount. Empty means zero.
    DebitCredit { debit: String, credit: String },
}

/// Every string field is bounded; header names are unique and ordered.
/// Layout metadata is an importer's explicit declaration, not an independently
/// authenticated assertion made by the bank.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankCsvLayout {
    pub name: String,
    pub headers: Vec<String>,
    pub delimiter: u8,
    pub decimal_separator: u8,
    pub date_format: BankCsvDateFormat,
    pub booking_date: String,
    pub value_date: Option<String>,
    pub counterparty: Option<String>,
    pub reference: Option<String>,
    pub amounts: BankCsvAmounts,
    pub instrument_id: String,
    pub sequence_number: u64,
    pub currency: String,
    pub statement_date: DateDay,
    pub opening_balance: String,
    pub closing_balance: String,
}

impl BankCsvLayout {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("layout name must be a bounded ASCII identifier");
        }
        if self.headers.is_empty() || self.headers.len() > MAX_COLUMNS {
            return Err("layout needs 1..=32 declared header columns");
        }
        let mut headers = BTreeSet::new();
        for header in &self.headers {
            if header.is_empty()
                || header.len() > MAX_NAME
                || header.chars().any(char::is_control)
                || !headers.insert(header.as_str())
            {
                return Err(
                    "layout headers must be nonempty, bounded, unique names without controls",
                );
            }
        }
        if !matches!(self.delimiter, b',' | b';' | b'\t')
            || !matches!(self.decimal_separator, b'.' | b',')
        {
            return Err(
                "layout delimiter must be comma, semicolon or tab; decimal separator must be dot or comma",
            );
        }
        let selected = |column: &str| headers.contains(column);
        if !selected(&self.booking_date)
            || [&self.value_date, &self.counterparty, &self.reference]
                .into_iter()
                .flatten()
                .any(|column| !selected(column))
        {
            return Err("every mapped column must name a declared header");
        }
        match &self.amounts {
            BankCsvAmounts::Signed { column, .. } if selected(column) => {}
            BankCsvAmounts::DebitCredit { debit, credit }
                if debit != credit && selected(debit) && selected(credit) => {}
            _ => return Err("amount columns must name distinct declared headers"),
        }
        if self.instrument_id.trim().is_empty()
            || self.instrument_id.len() > 256
            || self.instrument_id.chars().any(char::is_control)
            || self.sequence_number == 0
        {
            return Err(
                "statement needs a bounded instrument identity and positive sequence number",
            );
        }
        if self.currency.is_empty()
            || self.currency.len() > 32
            || !self
                .currency
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || !(1..=9999).contains(&self.statement_date.year())
        {
            return Err(
                "statement needs a registered currency code and a modern civil closing date",
            );
        }
        for value in [&self.opening_balance, &self.closing_balance] {
            if value.is_empty() || value.len() > 128 || value.trim() != value {
                return Err("statement balances must be bounded exact decimal strings");
            }
            let magnitude = value
                .strip_prefix('-')
                .or_else(|| value.strip_prefix('+'))
                .unwrap_or(value);
            let mut parts = magnitude.split(char::from(self.decimal_separator));
            let whole = parts.next().unwrap_or("");
            let fraction = parts.next();
            if whole.is_empty()
                || !whole.bytes().all(|b| b.is_ascii_digit())
                || fraction.is_some_and(|part| {
                    part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit())
                })
                || parts.next().is_some()
            {
                return Err(
                    "statement balances must use the declared decimal separator without grouping",
                );
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(LAYOUT_FORMAT)
            .str(&self.name)
            .list(&self.headers, |w, header| {
                w.str(header);
            });
        w.u8(self.delimiter)
            .u8(self.decimal_separator)
            .u8(match self.date_format {
                BankCsvDateFormat::Iso => 0,
                BankCsvDateFormat::MonthDayYear => 1,
                BankCsvDateFormat::DayMonthYear => 2,
            })
            .str(&self.booking_date);
        for value in [&self.value_date, &self.counterparty, &self.reference] {
            w.bool(value.is_some());
            if let Some(value) = value {
                w.str(value);
            }
        }
        match &self.amounts {
            BankCsvAmounts::Signed {
                column,
                positive_is_credit,
            } => {
                w.u8(0).str(column).bool(*positive_is_credit);
            }
            BankCsvAmounts::DebitCredit { debit, credit } => {
                w.u8(1).str(debit).str(credit);
            }
        }
        w.str(&self.instrument_id)
            .u64(self.sequence_number)
            .str(&self.currency)
            .i32(self.statement_date.0)
            .str(&self.opening_balance)
            .str(&self.closing_balance);
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            LAYOUT_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if bytes.len() > MAX_LAYOUT_BYTES
            || r.fixed::<{ LAYOUT_FORMAT.len() }>("bank_csv_layout.format")?
                .as_slice()
                != LAYOUT_FORMAT
        {
            return Err(r.invalid("bank_csv_layout.format"));
        }
        let name = r.str(64, "bank_csv_layout.name")?.to_owned();
        let headers = r.list(MAX_COLUMNS, "bank_csv_layout.headers", |r| {
            Ok(r.str(MAX_NAME, "bank_csv_layout.header")?.to_owned())
        })?;
        let delimiter = r.u8("bank_csv_layout.delimiter")?;
        let decimal_separator = r.u8("bank_csv_layout.decimal_separator")?;
        let date_format = match r.u8("bank_csv_layout.date_format")? {
            0 => BankCsvDateFormat::Iso,
            1 => BankCsvDateFormat::MonthDayYear,
            2 => BankCsvDateFormat::DayMonthYear,
            tag => return Err(r.bad_tag("bank_csv_layout.date_format", tag)),
        };
        let booking_date = r.str(MAX_NAME, "bank_csv_layout.booking_date")?.to_owned();
        fn optional(r: &mut Reader<'_>) -> Result<Option<String>, DecodeError> {
            if r.bool("bank_csv_layout.column")? {
                Ok(Some(r.str(MAX_NAME, "bank_csv_layout.column")?.to_owned()))
            } else {
                Ok(None)
            }
        }
        let value_date = optional(&mut r)?;
        let counterparty = optional(&mut r)?;
        let reference = optional(&mut r)?;
        let amounts = match r.u8("bank_csv_layout.amounts")? {
            0 => BankCsvAmounts::Signed {
                column: r.str(MAX_NAME, "bank_csv_layout.amount")?.to_owned(),
                positive_is_credit: r.bool("bank_csv_layout.positive_is_credit")?,
            },
            1 => BankCsvAmounts::DebitCredit {
                debit: r.str(MAX_NAME, "bank_csv_layout.debit")?.to_owned(),
                credit: r.str(MAX_NAME, "bank_csv_layout.credit")?.to_owned(),
            },
            tag => return Err(r.bad_tag("bank_csv_layout.amounts", tag)),
        };
        let result = Self {
            name,
            headers,
            delimiter,
            decimal_separator,
            date_format,
            booking_date,
            value_date,
            counterparty,
            reference,
            amounts,
            instrument_id: r.str(256, "bank_csv_layout.instrument")?.to_owned(),
            sequence_number: r.u64("bank_csv_layout.sequence")?,
            currency: r.str(32, "bank_csv_layout.currency")?.to_owned(),
            statement_date: DateDay(r.i32("bank_csv_layout.statement_date")?),
            opening_balance: r.str(128, "bank_csv_layout.opening")?.to_owned(),
            closing_balance: r.str(128, "bank_csv_layout.closing")?.to_owned(),
        };
        if result.validate().is_err() {
            return Err(r.invalid("bank_csv_layout"));
        }
        r.finish()?;
        Ok(result)
    }
}
