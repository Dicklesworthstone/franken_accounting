//! Select fields from one bank response and project its source-local civil dates.

use super::{CamtBlock, FormatError, camt_blocks, camt_error, camt_one, camt_optional};
use crate::parse_date_iso;
use fa_time::DateDay;

const FMT: &str = "ofx_qbo_v2";

pub(super) struct Statement<'a> {
    pub sequence: Option<CamtBlock<'a>>,
    pub currency: CamtBlock<'a>,
    pub account: CamtBlock<'a>,
    pub opening: CamtBlock<'a>,
    pub ledger: CamtBlock<'a>,
    pub transactions: Vec<CamtBlock<'a>>,
}

impl<'a> Statement<'a> {
    /// Frozen selection law for matching and retrying previously published evidence.
    pub fn revision_one(text: &'a str) -> Result<Self, FormatError> {
        let one = |tag| {
            let blocks = camt_blocks(FMT, text, tag, true)?;
            match blocks.as_slice() {
                [block] => Ok(*block),
                _ => Err(camt_error(FMT, format!("revision 1 requires one {tag}"))),
            }
        };
        if camt_blocks(FMT, text, "STMTRS", true)?.len() > 1 {
            return Err(camt_error(FMT, "multiple OFX statements"));
        }
        let sequence = match camt_blocks(FMT, text, "TRNUID", true)?.as_slice() {
            [] => None,
            [sequence] => Some(*sequence),
            _ => return Err(camt_error(FMT, "multiple OFX sequences")),
        };
        let transactions = camt_blocks(FMT, text, "STMTTRN", true)?;
        for block in &transactions {
            if !camt_blocks(FMT, block.body, "STMTTRN", true)?.is_empty() {
                return Err(camt_error(
                    FMT,
                    "nested OFX transaction envelopes are invalid",
                ));
            }
        }
        Ok(Self {
            sequence,
            currency: one("CURDEF")?,
            account: one("ACCTID")?,
            opening: one("OPENBAL")?,
            ledger: one("LEDGERBAL")?,
            transactions,
        })
    }

    pub fn parse(text: &'a str) -> Result<Self, FormatError> {
        if camt_blocks(FMT, text, "*", false)?.len() != 1 {
            return Err(camt_error(FMT, "expected one OFX document root"));
        }
        let root = camt_one(FMT, text, "OFX")?.body;
        let bank = camt_optional(FMT, root, "BANKMSGSRSV1")?;
        let card = camt_optional(FMT, root, "CREDITCARDMSGSRSV1")?;
        let direct_statement = camt_optional(FMT, root, "STMTRS")?;
        let envelope = match (bank, card) {
            (Some(bank), None) => Some((bank.body, "STMTTRNRS", "STMTRS", "BANKACCTFROM")),
            (None, Some(card)) => Some((card.body, "CCSTMTTRNRS", "CCSTMTRS", "CCACCTFROM")),
            (None, None) => None,
            _ => return Err(camt_error(FMT, "select one OFX account response")),
        };
        if envelope.is_some() && direct_statement.is_some() {
            return Err(camt_error(FMT, "ambiguous OFX statement envelopes"));
        }
        let (response, statement, account, list) =
            if let Some((messages, response_tag, statement_tag, account_tag)) = envelope {
                let response = camt_one(FMT, messages, response_tag)?.body;
                let statement = camt_one(FMT, response, statement_tag)?.body;
                let account = camt_one(FMT, statement, account_tag)?.body;
                let list = camt_optional(FMT, statement, "BANKTRANLIST")?.map_or("", |b| b.body);
                (response, statement, account, list)
            } else {
                // Compact documents can put the statement fields directly in OFX
                // or wrap them in one STMTRS, with or without the account/list aggregates.
                let statement = direct_statement.map_or(root, |b| b.body);
                let account =
                    camt_optional(FMT, statement, "BANKACCTFROM")?.map_or(statement, |b| b.body);
                let list =
                    camt_optional(FMT, statement, "BANKTRANLIST")?.map_or(statement, |b| b.body);
                let response = if direct_statement.is_some()
                    && camt_optional(FMT, statement, "TRNUID")?.is_some()
                {
                    if camt_optional(FMT, root, "TRNUID")?.is_some() {
                        return Err(camt_error(FMT, "ambiguous OFX transaction sequence"));
                    }
                    statement
                } else {
                    root
                };
                (response, statement, account, list)
            };
        let transactions = camt_blocks(FMT, list, "STMTTRN", false)?;
        // Refuse partial or mixed envelopes, including a second empty
        // statement. A transaction hidden under a sibling must not balance
        // (or disappear from) the statement that is being imported.
        if camt_blocks(FMT, root, "STMTRS", true)?.len()
            != usize::from(bank.is_some() || direct_statement.is_some())
            || camt_blocks(FMT, root, "STMTTRN", true)?.len() != transactions.len()
            || camt_blocks(FMT, root, "CCSTMTRS", true)?.len() != usize::from(card.is_some())
            || !camt_blocks(FMT, root, "INVSTMTRS", true)?.is_empty()
        {
            return Err(camt_error(FMT, "select one complete OFX bank statement"));
        }
        Ok(Self {
            sequence: camt_optional(FMT, response, "TRNUID")?,
            currency: camt_one(FMT, statement, "CURDEF")?,
            account: camt_one(FMT, account, "ACCTID")?,
            opening: camt_one(FMT, statement, "OPENBAL")?,
            ledger: camt_one(FMT, statement, "LEDGERBAL")?,
            transactions,
        })
    }
}

/// OFX Banking 2.3 §3.2.8.2. Booking and as-of fields describe the
/// bank's civil day. Converting them to UTC can shift that day.
pub(super) fn civil_date(value: &str) -> Result<DateDay, FormatError> {
    let value = value.trim();
    if value.as_bytes().get(4) == Some(&b'-') {
        return parse_date_iso(FMT, value);
    }
    let invalid = || camt_error(FMT, format!("invalid OFX date or timestamp {value:?}"));
    let (clock, zone) = match value.split_once('[') {
        Some((clock, suffix)) => (clock, Some(suffix.strip_suffix(']').ok_or_else(invalid)?)),
        None => (value, None),
    };
    let (digits, millis) = match clock.split_once('.') {
        Some((digits, millis)) => (digits, Some(millis)),
        None => (clock, None),
    };
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    match digits.len() {
        8 if zone.is_none() && millis.is_none() => {}
        14 if &digits[8..10] <= "23" && &digits[10..12] <= "59" && &digits[12..14] <= "60" => {}
        _ => return Err(invalid()),
    }
    if millis.is_some_and(|ms| ms.len() != 3 || !ms.bytes().all(|byte| byte.is_ascii_digit()))
        || zone.is_some_and(|zone| !valid_zone(zone))
    {
        return Err(invalid());
    }
    parse_date_iso(
        FMT,
        &format!("{}-{}-{}", &digits[..4], &digits[4..6], &digits[6..8]),
    )
}

fn valid_zone(zone: &str) -> bool {
    let (offset, name) = zone
        .split_once(':')
        .map_or((zone, None), |(offset, name)| (offset, Some(name)));
    if name.is_some_and(|name| {
        name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+'))
    }) {
        return false;
    }
    let magnitude = offset.strip_prefix(['+', '-']).unwrap_or(offset);
    let (hours, fraction) = magnitude
        .split_once('.')
        .map_or((magnitude, None), |(h, f)| (h, Some(f)));
    if let Some(fraction) = fraction
        && (!(1..=2).contains(&fraction.len()) || !fraction.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    if hours.is_empty() || hours.len() > 2 || !hours.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    match hours.parse::<u8>() {
        Ok(0..=11) => true,
        Ok(12) => fraction.is_none_or(|f| f.bytes().all(|b| b == b'0')),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::civil_date;
    use crate::{UnitCatalog, bank::parse_ofx_qbo};

    const TX: &str = "<STMTTRN><DTPOSTED>20240229235500.250[-5:EST]</DTPOSTED><TRNAMT>-1.25</TRNAMT><FITID>CHECK1</FITID><BANKACCTTO><ACCTID>recipient</ACCTID></BANKACCTTO></STMTTRN>";

    fn statement() -> String {
        format!(
            "<OFX><BANKMSGSRSV1><STMTTRNRS><TRNUID>42</TRNUID><STMTRS><CURDEF>USD</CURDEF><OPENBAL>3.00</OPENBAL><BANKACCTFROM><ACCTID>source</ACCTID></BANKACCTFROM><BANKTRANLIST>{TX}</BANKTRANLIST><LEDGERBAL><BALAMT>1.75</BALAMT><DTASOF>20240301</DTASOF></LEDGERBAL></STMTRS></STMTTRNRS></BANKMSGSRSV1></OFX>"
        )
    }

    #[test]
    fn bank_and_card_statements_select_source_account_and_local_day() {
        let units = UnitCatalog::embedded().unwrap();
        let bank = statement();
        let card = bank
            .replace("BANKMSGSRSV1", "CREDITCARDMSGSRSV1")
            .replace("STMTTRNRS", "CCSTMTTRNRS")
            .replace("STMTRS", "CCSTMTRS")
            .replace("BANKACCTFROM", "CCACCTFROM");
        for source in [bank, card] {
            let parsed = parse_ofx_qbo(&source, &units).unwrap();
            assert_eq!(parsed.instrument_account_id, "source");
            assert_eq!(parsed.sequence_number, 42);
            assert_eq!(parsed.lines.len(), 1);
            assert_eq!(parsed.lines[0].booking_date.render(), "2024-02-29");
            assert_eq!(parsed.statement_date.render(), "2024-03-01");
            assert_eq!(parsed.closing_balance, 175);
        }
    }

    #[test]
    fn compact_wrapped_statement_preserves_sequence_and_empty_bank_statement_ties() {
        let units = UnitCatalog::embedded().unwrap();
        let bank = statement();
        let compact = bank
            .replace(
                "<BANKMSGSRSV1><STMTTRNRS><TRNUID>42</TRNUID><STMTRS>",
                "<STMTRS><TRNUID>42</TRNUID>",
            )
            .replace("</STMTTRNRS></BANKMSGSRSV1>", "");
        assert_eq!(
            parse_ofx_qbo(&bank, &units).unwrap(),
            parse_ofx_qbo(&compact, &units).unwrap()
        );
        let empty = bank
            .replace(&format!("<BANKTRANLIST>{TX}</BANKTRANLIST>"), "")
            .replace("1.75", "3.00");
        assert!(parse_ofx_qbo(&empty, &units).unwrap().lines.is_empty());
        assert!(parse_ofx_qbo(&empty.replace("3.00</BALAMT>", "2.00</BALAMT>"), &units).is_err());
    }

    #[test]
    fn refuses_out_of_scope_movements_and_balances() {
        let units = UnitCatalog::embedded().unwrap();
        let bank = statement();
        for (original, replacement) in [
            (
                "<BANKACCTFROM><ACCTID>source</ACCTID></BANKACCTFROM>",
                "<BANKACCTFROM></BANKACCTFROM>",
            ),
            (
                "<OPENBAL>3.00</OPENBAL>",
                "<EXTENSION><OPENBAL>3.00</OPENBAL></EXTENSION>",
            ),
            (
                "</BANKTRANLIST>",
                "</BANKTRANLIST><EXTENSION><STMTTRN></STMTTRN></EXTENSION>",
            ),
            ("</OFX>", "<CCSTMTRS></CCSTMTRS></OFX>"),
            ("</OFX>", "</OFX><EXTRA/>"),
        ] {
            assert!(parse_ofx_qbo(&bank.replace(original, replacement), &units).is_err());
        }
        let moved = bank
            .replace(TX, "")
            .replace("</OFX>", &format!("{TX}</OFX>"));
        assert!(parse_ofx_qbo(&moved, &units).is_err());
    }

    #[test]
    fn validates_clock_and_zone_even_for_civil_projection() {
        for valid in [
            "20240229",
            "20240229000000",
            "20240229235959.123",
            "20240229001500[+5.50:IST]",
            "20240229235959.000[-12]",
        ] {
            assert_eq!(civil_date(valid).unwrap().render(), "2024-02-29");
        }
        for invalid in [
            "20230229",
            "20240229240000",
            "20240229106000",
            "20240229105961",
            "20240229000000.23",
            "20240229000000[+12.5]",
            "20240229000000[0:]",
            "20240229000000[-5:EST]junk",
            "２０２４０２２９",
            "20240229[0]",
        ] {
            assert!(civil_date(invalid).is_err(), "accepted {invalid}");
        }
    }
}
