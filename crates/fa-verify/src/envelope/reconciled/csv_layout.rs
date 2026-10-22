//! Independent decoder for the v1 declared CSV layout inside bank manifest v3.
//! This authenticates interpretation and bounded canonical shape, not the CSV's
//! factual accuracy. Source reparsing remains the bank importer's responsibility.
use std::collections::BTreeSet;

use crate::codec::{DecodeError, Reader, Reason};

fn string<'a>(r: &mut Reader<'a>, max: usize) -> Result<&'a str, DecodeError> {
    let bytes = r.bytes(max, "bank_csv_layout.string")?;
    core::str::from_utf8(bytes).map_err(|_| r.error("bank_csv_layout.utf8", Reason::BadTag(0)))
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decimal(value: &str, separator: u8) -> bool {
    let magnitude = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    let mut parts = magnitude.split(char::from(separator));
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next();
    !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction
            .is_none_or(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next().is_none()
}

pub(super) fn validate(bytes: &[u8], sequence: u64, date: i32) -> Result<(), DecodeError> {
    let mut r = Reader::new(bytes);
    if r.fixed::<21>("bank_csv_layout.format")? != *b"fa:bank-csv-layout:v1" {
        return Err(r.error("bank_csv_layout.format", Reason::BadTag(0)));
    }
    let name = string(&mut r, 64)?;
    if !identifier(name, 64) {
        return Err(r.error("bank_csv_layout.name", Reason::BadTag(0)));
    }
    let count = r.count(32, 4, "bank_csv_layout.headers")?;
    let mut headers = BTreeSet::new();
    for _ in 0..count {
        let header = string(&mut r, 128)?;
        if header.is_empty() || header.chars().any(char::is_control) || !headers.insert(header) {
            return Err(r.error("bank_csv_layout.headers", Reason::BadTag(0)));
        }
    }
    if count == 0 || !matches!(r.u8("bank_csv_layout.delimiter")?, b',' | b';' | b'\t') {
        return Err(r.error("bank_csv_layout.delimiter", Reason::BadTag(0)));
    }
    let separator = r.u8("bank_csv_layout.decimal_separator")?;
    if !matches!(separator, b'.' | b',') || r.u8("bank_csv_layout.date_format")? > 2 {
        return Err(r.error("bank_csv_layout.conventions", Reason::BadTag(0)));
    }
    if !headers.contains(string(&mut r, 128)?) {
        return Err(r.error("bank_csv_layout.booking_date", Reason::BadTag(0)));
    }
    for _ in 0..3 {
        if r.present("bank_csv_layout.column")? && !headers.contains(string(&mut r, 128)?) {
            return Err(r.error("bank_csv_layout.column", Reason::BadTag(0)));
        }
    }
    match r.u8("bank_csv_layout.amounts")? {
        0 => {
            if !headers.contains(string(&mut r, 128)?) {
                return Err(r.error("bank_csv_layout.amount", Reason::BadTag(0)));
            }
            r.present("bank_csv_layout.positive_is_credit")?;
        }
        1 => {
            let debit = string(&mut r, 128)?;
            let credit = string(&mut r, 128)?;
            if debit == credit || !headers.contains(debit) || !headers.contains(credit) {
                return Err(r.error("bank_csv_layout.amount", Reason::BadTag(0)));
            }
        }
        tag => return Err(r.error("bank_csv_layout.amounts", Reason::BadTag(tag))),
    }
    let instrument = string(&mut r, 256)?;
    if instrument.trim().is_empty() || instrument.chars().any(char::is_control) {
        return Err(r.error("bank_csv_layout.instrument", Reason::BadTag(0)));
    }
    let declared_sequence = r.u64("bank_csv_layout.sequence")?;
    let currency = string(&mut r, 32)?;
    let declared_date = r.i32("bank_csv_layout.statement_date")?;
    // DateDay's public epoch is 1970-01-01. These bounds are civil years 1..9999.
    if declared_sequence == 0
        || declared_sequence != sequence
        || declared_date != date
        || !(-719_162..=2_932_896).contains(&declared_date)
        || !identifier(currency, 32)
    {
        return Err(r.error("bank_csv_layout.metadata", Reason::BadTag(0)));
    }
    for _ in 0..2 {
        if !decimal(string(&mut r, 128)?, separator) {
            return Err(r.error("bank_csv_layout.balance", Reason::BadTag(0)));
        }
    }
    r.finish("bank_csv_layout")
}
