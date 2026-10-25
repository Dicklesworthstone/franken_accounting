//! Bank statement parsers (`iso20022_camt053`, `bai2_v2`, `ofx_qbo_v2`) and
//! statement sequence / opening-to-closing balance continuity verification
//! (plan §9.5, §15.3, bead `fa-npi`).

use std::borrow::Cow;

use fa_money::{Amount, Side};
use fa_time::DateDay;
use fgdb_crypto::Hasher;

use crate::{FormatError, UnitCatalog, parse_date_iso, parse_exact_decimal};

mod csv_layout;
pub use csv_layout::parse_bank_csv_with_layout;

/// One parsed bank statement line (`BankLine` projection, plan §9.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedBankLine {
    pub line_ordinal: u32,
    pub booking_date: DateDay,
    pub value_date: DateDay,
    pub side: Side,
    pub amount: Amount,
    pub counterparty: String,
    pub reference: String,
    pub line_digest: [u8; 32],
}

/// A parsed bank statement with header balances, sequence number, and lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankStatementExtract {
    pub format_name: &'static str,
    pub instrument_account_id: String,
    pub sequence_number: u64,
    pub currency: String,
    pub statement_date: DateDay,
    /// Signed opening balance (`Credit` / positive bank balance as positive mantissa).
    pub opening_balance: i128,
    /// Signed closing balance.
    pub closing_balance: i128,
    pub lines: Vec<ParsedBankLine>,
}

impl BankStatementExtract {
    /// Verify internal balance continuity (`opening_balance + Σ signed_lines == closing_balance`).
    pub fn verify_internal_balance(&self) -> Result<(), FormatError> {
        let mut running = self.opening_balance;
        for line in &self.lines {
            if line.amount.mantissa <= 0 {
                return Err(FormatError::Parse {
                    format: self.format_name,
                    detail: format!(
                        "bank line #{} must have a strictly positive magnitude; its side carries the sign",
                        line.line_ordinal
                    ),
                });
            }
            let delta = match line.side {
                // On a bank statement from the bank's perspective (or customer cash inflows):
                // Credit (`CRDT`) is a cash inflow (+), Debit (`DBIT`) is a cash outflow (-).
                Side::Credit => line.amount.mantissa,
                Side::Debit => negate_bank_amount(self.format_name, line.amount.mantissa)?,
            };
            running = running
                .checked_add(delta)
                .ok_or_else(|| FormatError::Overflow {
                    format: self.format_name,
                    detail: "bank statement running balance overflow".to_owned(),
                })?;
        }
        if running != self.closing_balance {
            return Err(FormatError::BankContinuity {
                format: self.format_name,
                detail: format!(
                    "statement #{} opening ({}) + net activity != closing ({}) (computed {})",
                    self.sequence_number, self.opening_balance, self.closing_balance, running
                ),
            });
        }
        Ok(())
    }
}

/// Verify statement sequence continuity across an ordered slice of statements
/// for the same instrument (`seq[i] == seq[i-1] + 1` and `opening[i] == closing[i-1]`).
pub fn verify_statement_sequence_continuity(
    statements: &[BankStatementExtract],
) -> Result<(), FormatError> {
    for stmt in statements {
        stmt.verify_internal_balance()?;
    }
    for pair in statements.windows(2) {
        let prev = &pair[0];
        let curr = &pair[1];
        if prev.instrument_account_id != curr.instrument_account_id {
            return Err(FormatError::BankContinuity {
                format: curr.format_name,
                detail: format!(
                    "instrument mismatch between statements ({} vs {})",
                    prev.instrument_account_id, curr.instrument_account_id
                ),
            });
        }
        if prev.currency != curr.currency {
            return Err(FormatError::BankContinuity {
                format: curr.format_name,
                detail: format!(
                    "statement currency changed on {} ({} vs {})",
                    curr.instrument_account_id, prev.currency, curr.currency
                ),
            });
        }
        let next_sequence =
            prev.sequence_number
                .checked_add(1)
                .ok_or_else(|| FormatError::Overflow {
                    format: curr.format_name,
                    detail: "bank statement sequence number overflow".to_owned(),
                })?;
        if curr.sequence_number != next_sequence {
            return Err(FormatError::BankContinuity {
                format: curr.format_name,
                detail: format!(
                    "statement sequence gap on {}: {} followed by {}",
                    curr.instrument_account_id, prev.sequence_number, curr.sequence_number
                ),
            });
        }
        if curr.opening_balance != prev.closing_balance {
            return Err(FormatError::BankContinuity {
                format: curr.format_name,
                detail: format!(
                    "opening balance {} on statement #{} does not equal prior closing balance {} on statement #{}",
                    curr.opening_balance,
                    curr.sequence_number,
                    prev.closing_balance,
                    prev.sequence_number
                ),
            });
        }
    }
    Ok(())
}

/// Parse one ISO 20022 `camt.053` statement into a [`BankStatementExtract`].
///
/// The bounded profile accepts ISO date choices, IBAN/Other account identities,
/// namespace prefixes and currency attributes. Multiple statements, pending
/// entries and date-time choices require explicit selection/conversion upstream.
pub fn parse_camt053(xml: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    parse_camt(xml, units, "iso20022_camt053", "Stmt", false)
}

fn camt_error(format: &'static str, detail: impl Into<String>) -> FormatError {
    FormatError::Parse {
        format,
        detail: detail.into(),
    }
}

fn negate_bank_amount(format: &'static str, amount: i128) -> Result<i128, FormatError> {
    amount.checked_neg().ok_or_else(|| FormatError::Overflow {
        format,
        detail: "bank amount negation overflow".to_owned(),
    })
}

#[derive(Clone, Copy)]
struct CamtBlock<'a> {
    body: &'a str,
    attributes: &'a str,
}

fn bank_xml_name(name: &str) -> bool {
    !name.is_empty()
        && name.split(':').count() <= 2
        && name.split(':').all(|part| {
            part.bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
}

fn bank_xml_character(character: char) -> bool {
    matches!(u32::from(character), 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

/// Decode exactly one XML reference layer. Unknown entities are errors rather
/// than literal identity/reference text, and no external entity is resolved.
fn bank_xml_decode<'a>(format: &'static str, raw: &'a str) -> Result<Cow<'a, str>, FormatError> {
    if !raw.chars().all(bank_xml_character) {
        return Err(camt_error(
            format,
            "invalid XML 1.0 character in bank source",
        ));
    }
    if !raw.contains('&') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut output = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('&') {
        output.push_str(&rest[..start]);
        let entity = &rest[start + 1..];
        let end = entity
            .find(';')
            .ok_or_else(|| camt_error(format, "unterminated XML entity in bank source"))?;
        let name = &entity[..end];
        let character = match name {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let (digits, radix) = if let Some(digits) = name.strip_prefix("#x") {
                    (digits, 16)
                } else if let Some(digits) = name.strip_prefix('#') {
                    (digits, 10)
                } else {
                    return Err(camt_error(format, "undeclared XML entity in bank source"));
                };
                if digits.is_empty()
                    || !digits.bytes().all(|b| {
                        if radix == 16 {
                            b.is_ascii_hexdigit()
                        } else {
                            b.is_ascii_digit()
                        }
                    })
                {
                    return Err(camt_error(
                        format,
                        "invalid numeric XML reference in bank source",
                    ));
                }
                u32::from_str_radix(digits, radix)
                    .ok()
                    .and_then(char::from_u32)
                    .filter(|character| bank_xml_character(*character))
                    .ok_or_else(|| {
                        camt_error(
                            format,
                            "XML character reference is outside the supported character domain",
                        )
                    })?
            }
        };
        output.push(character);
        rest = &entity[end + 1..];
    }
    output.push_str(rest);
    Ok(Cow::Owned(output))
}

/// Scan a complete XML fragment, matching balanced qualified names instead of
/// taking the first text between two tags. This keeps nested `<Dt><Dt>`, quoted
/// attributes and malformed suffixes from changing which source bytes we use.
/// DTDs and other declarations are outside this profile; no entities are loaded.
fn camt_blocks<'a>(
    format: &'static str,
    xml: &'a str,
    tag: &str,
    descendants: bool,
) -> Result<Vec<CamtBlock<'a>>, FormatError> {
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let mut stack: Vec<(&str, &str, usize, bool)> = Vec::new();
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = xml[cursor..].find('<') {
        let start = cursor + relative;
        if stack.is_empty() && !xml[cursor..start].trim().is_empty() {
            return Err(camt_error(format, "text outside bank XML elements"));
        }
        bank_xml_decode(format, &xml[cursor..start])?;
        let suffix = &xml[start..];
        if let Some(comment) = suffix.strip_prefix("<!--") {
            let end = comment
                .find("-->")
                .ok_or_else(|| camt_error(format, "unterminated bank XML comment"))?;
            if comment[..end].contains("--") {
                return Err(camt_error(format, "invalid bank XML comment"));
            }
            cursor = start + 4 + end + 3;
            continue;
        }
        if suffix.starts_with("<?") {
            let end = suffix.find("?>").ok_or_else(|| {
                camt_error(format, "unterminated bank XML processing instruction")
            })?;
            cursor = start + end + 2;
            continue;
        }
        let mut quote = None;
        let mut end = None;
        for (offset, byte) in suffix.bytes().enumerate().skip(1) {
            match (quote, byte) {
                (Some(current), b) if current == b => quote = None,
                (None, b'\'' | b'"') => quote = Some(byte),
                (None, b'>') => {
                    end = Some(start + offset);
                    break;
                }
                (None, b'<') => return Err(camt_error(format, "malformed bank XML tag")),
                _ => {}
            }
        }
        let end = end.ok_or_else(|| camt_error(format, "unterminated bank XML tag"))?;
        let token = xml[start + 1..end].trim();
        if token.starts_with('!') {
            return Err(camt_error(
                format,
                "bank XML declarations and DTDs are outside the bounded profile",
            ));
        }
        if let Some(close) = token.strip_prefix('/') {
            let (name, attributes, body_start, selected) = stack
                .pop()
                .ok_or_else(|| camt_error(format, "unmatched bank XML closing tag"))?;
            if close.trim() != name {
                return Err(camt_error(format, "mismatched bank XML closing tag"));
            }
            if selected {
                found.push((
                    body_start,
                    CamtBlock {
                        body: &xml[body_start..start],
                        attributes,
                    },
                ));
            }
        } else {
            let empty = token.ends_with('/');
            let open = token.strip_suffix('/').unwrap_or(token).trim();
            let split = open.find(char::is_whitespace).unwrap_or(open.len());
            let name = &open[..split];
            if !bank_xml_name(name) {
                return Err(camt_error(format, "invalid bank XML element name"));
            }
            let attributes = open[split..].trim();
            camt_attribute(format, attributes, None)?;
            let selected =
                name.rsplit(':').next() == Some(tag) && (descendants || stack.is_empty());
            if empty {
                if selected {
                    found.push((
                        end,
                        CamtBlock {
                            body: "",
                            attributes,
                        },
                    ));
                }
            } else {
                stack.push((name, attributes, end + 1, selected));
            }
        }
        cursor = end + 1;
    }
    if !stack.is_empty() || !xml[cursor..].trim().is_empty() {
        return Err(camt_error(format, "incomplete bank XML document"));
    }
    found.sort_by_key(|(start, _)| *start);
    Ok(found.into_iter().map(|(_, block)| block).collect())
}

fn camt_attribute<'a>(
    format: &'static str,
    mut attributes: &'a str,
    requested: Option<&str>,
) -> Result<Option<&'a str>, FormatError> {
    let mut seen = Vec::new();
    let mut value = None;
    while !attributes.is_empty() {
        let end = attributes
            .find(|c: char| c.is_whitespace() || c == '=')
            .ok_or_else(|| camt_error(format, "invalid bank XML attribute"))?;
        let name = &attributes[..end];
        if !bank_xml_name(name) || seen.contains(&name) {
            return Err(camt_error(
                format,
                "invalid or duplicate bank XML attribute",
            ));
        }
        seen.push(name);
        let rest = attributes[end..]
            .trim_start()
            .strip_prefix('=')
            .ok_or_else(|| camt_error(format, "bank XML attribute needs ="))?
            .trim_start();
        let quote = rest
            .as_bytes()
            .first()
            .copied()
            .filter(|b| matches!(b, b'\'' | b'"'))
            .ok_or_else(|| camt_error(format, "bank XML attribute must be quoted"))?;
        let end = rest[1..]
            .find(char::from(quote))
            .ok_or_else(|| camt_error(format, "unterminated bank XML attribute"))?
            + 1;
        let contents = &rest[1..end];
        if contents.contains('<') {
            return Err(camt_error(format, "invalid bank XML attribute value"));
        }
        bank_xml_decode(format, contents)?;
        if requested == Some(name) {
            value = Some(contents);
        }
        let tail = &rest[end + 1..];
        if !tail.is_empty() && !tail.starts_with(char::is_whitespace) {
            return Err(camt_error(format, "bank XML attributes need whitespace"));
        }
        attributes = tail.trim_start();
    }
    Ok(value)
}

fn camt_optional<'a>(
    format: &'static str,
    xml: &'a str,
    tag: &str,
) -> Result<Option<CamtBlock<'a>>, FormatError> {
    let blocks = camt_blocks(format, xml, tag, false)?;
    match blocks.as_slice() {
        [] => Ok(None),
        [block] => Ok(Some(*block)),
        _ => Err(camt_error(
            format,
            format!("ambiguous repeated bank XML {tag}"),
        )),
    }
}

fn camt_one<'a>(
    format: &'static str,
    xml: &'a str,
    tag: &str,
) -> Result<CamtBlock<'a>, FormatError> {
    camt_optional(format, xml, tag)?
        .ok_or_else(|| camt_error(format, format!("missing bank XML {tag}")))
}

fn bank_xml_one<'a>(
    format: &'static str,
    xml: &'a str,
    tag: &str,
) -> Result<CamtBlock<'a>, FormatError> {
    let blocks = camt_blocks(format, xml, tag, true)?;
    match blocks.as_slice() {
        [block] => Ok(*block),
        _ => Err(camt_error(
            format,
            format!(
                "bank XML input needs exactly one {tag}; select one complete account statement"
            ),
        )),
    }
}

fn camt_text<'a>(format: &'static str, block: CamtBlock<'a>) -> Result<Cow<'a, str>, FormatError> {
    let text = block.body.trim();
    if text.is_empty() || text.contains('<') {
        return Err(camt_error(
            format,
            "bank XML text value is empty or contains nested elements",
        ));
    }
    bank_xml_decode(format, text)
}

fn camt_date(format: &'static str, block: CamtBlock<'_>) -> Result<DateDay, FormatError> {
    let value = if block.body.contains('<') {
        if camt_optional(format, block.body, "DtTm")?.is_some() {
            return Err(camt_error(
                format,
                "CAMT date-time choices need an explicit civil-date conversion; use Dt",
            ));
        }
        camt_one(format, block.body, "Dt")?
    } else {
        block
    };
    parse_date_iso(format, &camt_text(format, value)?)
}

fn camt_amount(
    format: &'static str,
    xml: &str,
    currency: &str,
    scale: u8,
) -> Result<i128, FormatError> {
    let amount = camt_one(format, xml, "Amt")?;
    if let Some(actual) = camt_attribute(format, amount.attributes, Some("Ccy"))? {
        let actual = bank_xml_decode(format, actual)?;
        if actual.as_ref() != currency {
            return Err(camt_error(
                format,
                format!("CAMT amount currency {actual} differs from account currency {currency}"),
            ));
        }
    }
    let magnitude = parse_exact_decimal(format, &camt_text(format, amount)?, scale)?;
    if magnitude < 0 {
        return Err(camt_error(
            format,
            "CAMT amount must be unsigned; CdtDbtInd carries its sign",
        ));
    }
    Ok(magnitude)
}

fn camt_side(format: &'static str, xml: &str) -> Result<Side, FormatError> {
    match camt_text(format, camt_one(format, xml, "CdtDbtInd")?)?.as_ref() {
        "CRDT" => Ok(Side::Credit),
        "DBIT" => Ok(Side::Debit),
        other => Err(camt_error(
            format,
            format!("invalid CAMT CdtDbtInd {other:?}"),
        )),
    }
}

fn parse_camt(
    xml: &str,
    units: &UnitCatalog,
    format: &'static str,
    container: &str,
    intraday: bool,
) -> Result<BankStatementExtract, FormatError> {
    let statements = camt_blocks(format, xml, container, true)?;
    let [statement] = statements.as_slice() else {
        return Err(camt_error(
            format,
            "CAMT input must contain exactly one statement/report; split multi-account or multi-statement files before import",
        ));
    };
    let stmt = statement.body;
    let seq: u64 = camt_text(format, camt_one(format, stmt, "ElctrncSeqNb")?)?
        .parse()
        .map_err(|_| camt_error(format, "invalid CAMT ElctrncSeqNb"))?;
    let acct = camt_one(format, stmt, "Acct")?;
    let id = camt_one(format, acct.body, "Id")?;
    let id = if id.body.contains('<') {
        match (
            camt_optional(format, id.body, "IBAN")?,
            camt_optional(format, id.body, "Othr")?,
        ) {
            (Some(iban), None) => iban,
            (None, Some(other)) => camt_one(format, other.body, "Id")?,
            _ => {
                return Err(camt_error(
                    format,
                    "CAMT account Id needs exactly one IBAN or Othr/Id",
                ));
            }
        }
    } else {
        id
    };
    let instrument_id = camt_text(format, id)?.into_owned();
    let currency = camt_text(format, camt_one(format, acct.body, "Ccy")?)?.into_owned();
    let (unit_id, unit_scale) =
        units
            .lookup_code(&currency)
            .ok_or_else(|| FormatError::UnknownUnit {
                format,
                unit: currency.clone(),
            })?;

    let mut opening_balance: Option<i128> = None;
    let mut closing_balance: Option<i128> = None;
    let mut statement_date = DateDay(0);

    for bal in camt_blocks(format, stmt, "Bal", false)? {
        let code = if let Some(code) = camt_optional(format, bal.body, "Cd")? {
            if camt_optional(format, bal.body, "Tp")?.is_some() {
                return Err(camt_error(
                    format,
                    "CAMT balance cannot mix flat Cd with a nested Tp choice",
                ));
            }
            code
        } else {
            let kind = camt_one(format, bal.body, "Tp")?;
            let choice = camt_one(format, kind.body, "CdOrPrtry")?;
            camt_one(format, choice.body, "Cd")?
        };
        let code = camt_text(format, code)?;
        if code != "OPBD" && code != "CLBD" && !(intraday && code == "ITBD") {
            continue;
        }
        let dt = camt_date(format, camt_one(format, bal.body, "Dt")?)?;
        let magnitude = camt_amount(format, bal.body, &currency, unit_scale)?;
        let signed = match camt_side(format, bal.body)? {
            Side::Credit => magnitude,
            Side::Debit => negate_bank_amount(format, magnitude)?,
        };
        match code.as_ref() {
            "OPBD" => {
                if opening_balance.replace(signed).is_some() {
                    return Err(camt_error(
                        format,
                        "ambiguous repeated CAMT opening balance",
                    ));
                }
            }
            _ => {
                if closing_balance.replace(signed).is_some() {
                    return Err(camt_error(
                        format,
                        "ambiguous repeated CAMT closing balance",
                    ));
                }
                statement_date = dt;
            }
        }
    }

    let opening_balance =
        opening_balance.ok_or_else(|| camt_error(format, "missing CAMT OPBD balance"))?;
    let closing_balance =
        closing_balance.ok_or_else(|| camt_error(format, "missing CAMT CLBD/ITBD balance"))?;

    let mut lines = Vec::new();
    for (idx, entry) in camt_blocks(format, stmt, "Ntry", false)?
        .into_iter()
        .enumerate()
    {
        let ordinal = u32::try_from(idx)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| FormatError::Overflow {
                format,
                detail: "bank line ordinal overflow".to_owned(),
            })?;
        let ntry = entry.body;
        if let Some(status) = camt_optional(format, ntry, "Sts")? {
            let status = if status.body.contains('<') {
                camt_one(format, status.body, "Cd")?
            } else {
                status
            };
            if camt_text(format, status)? != "BOOK" {
                return Err(camt_error(
                    format,
                    "CAMT import requires booked entries; pending/information entries need a separate selection",
                ));
            }
        }
        let side = camt_side(format, ntry)?;
        let booking_date = camt_date(format, camt_one(format, ntry, "BookgDt")?)?;
        let value_date = camt_optional(format, ntry, "ValDt")?
            .map(|date| camt_date(format, date))
            .transpose()?
            .unwrap_or(booking_date);
        let names = camt_blocks(format, ntry, "Nm", true)?;
        let counterparty = names
            .first()
            .copied()
            .map(|name| camt_text(format, name).map(Cow::into_owned))
            .transpose()?
            .unwrap_or_default();
        let reference = camt_optional(format, ntry, "AcctSvcrRef")?
            .map(|reference| camt_text(format, reference).map(Cow::into_owned))
            .transpose()?
            .unwrap_or_default();
        let mantissa = camt_amount(format, ntry, &currency, unit_scale)?;
        let amount = Amount::new(unit_id, mantissa);
        let line_digest = compute_bank_line_digest(
            &instrument_id,
            seq,
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
        format_name: format,
        instrument_account_id: instrument_id,
        sequence_number: seq,
        currency,
        statement_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

/// Parse a BAI2 cash-management statement into a [`BankStatementExtract`].
///
/// A file whose `02` group header dates itself YYMMDD is read under the
/// standard BAI version 2 profile ([`parse_bai2_standard`]): what a bank
/// sends. The original bounded profile, with ISO civil dates and a
/// six-field `16` record carrying its own date, remains supported for files
/// already written in it; profiles cannot be mixed within one file.
pub fn parse_bai2(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    let standard = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("02,"))
        .and_then(|group| group.split(',').nth(3))
        .is_some_and(|date| date.len() == 6 && date.bytes().all(|b| b.is_ascii_digit()));
    if standard {
        parse_bai2_standard(text, units)
    } else {
        parse_bai2_legacy(text, units)
    }
}

/// The original bounded BAI2 profile: one group and one account, ISO civil
/// dates, comma-separated summary pairs and six-field `16` records;
/// continuation records and multi-account/group envelopes must be split or
/// converted explicitly before import.
fn parse_bai2_legacy(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "bai2_v2";
    let mut instrument_id = String::new();
    let mut currency = String::from("USD");
    let mut seq = 1u64;
    let mut statement_date = DateDay(0);
    let mut opening_balance: Option<i128> = None;
    let mut closing_balance: Option<i128> = None;
    let mut lines = Vec::new();
    let mut group_seen = false;
    let mut account_seen = false;
    let mut account_closed = false;

    for raw in text.lines() {
        let clean = raw.trim().trim_end_matches('/');
        if clean.is_empty() {
            continue;
        }
        let fields: Vec<&str> = clean.split(',').collect();
        match fields[0] {
            "02" => {
                if group_seen || fields.len() < 6 || fields.len() > 8 {
                    return Err(camt_error(
                        FMT,
                        "BAI2 requires exactly one well-formed 02 group in the bounded profile",
                    ));
                }
                group_seen = true;
                // 02,receiver,originator,group_status,as_of_date(YYYY-MM-DD),as_of_time,currency,seq
                statement_date = parse_date_iso(FMT, fields[4])?;
                if fields.len() >= 7 && !fields[6].is_empty() {
                    currency = fields[6].to_owned();
                }
                if fields.len() >= 8 && !fields[7].is_empty() {
                    seq = fields[7].parse().map_err(|_| FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid BAI2 group seq in {raw:?}"),
                    })?;
                }
            }
            "03" => {
                if !group_seen
                    || account_seen
                    || fields.len() < 7
                    || !(fields.len() - 3).is_multiple_of(2)
                {
                    return Err(camt_error(
                        FMT,
                        "BAI2 requires exactly one 03 account after its group, with complete summary pairs",
                    ));
                }
                if fields[1].trim().is_empty() {
                    return Err(camt_error(FMT, "BAI2 account identity is empty"));
                }
                account_seen = true;
                // 03,account_id,currency,010,opening_minor,015,closing_minor
                instrument_id = fields[1].to_owned();
                if !fields[2].is_empty() {
                    currency = fields[2].to_owned();
                }
                let mut idx = 3usize;
                while idx + 1 < fields.len() {
                    let type_code = fields[idx];
                    let amt_minor: i128 =
                        fields[idx + 1].parse().map_err(|_| FormatError::Parse {
                            format: FMT,
                            detail: format!("invalid BAI2 summary amount in {raw:?}"),
                        })?;
                    match type_code {
                        "010" if opening_balance.is_some() => {
                            return Err(camt_error(FMT, "repeated BAI2 opening balance"));
                        }
                        "010" => opening_balance = Some(amt_minor),
                        "015" if closing_balance.is_some() => {
                            return Err(camt_error(FMT, "repeated BAI2 closing balance"));
                        }
                        "015" => closing_balance = Some(amt_minor),
                        _ => {}
                    }
                    idx += 2;
                }
            }
            "16" => {
                if !account_seen || account_closed || fields.len() != 6 {
                    return Err(camt_error(
                        FMT,
                        "BAI2 16 requires six complete fields within the selected open account",
                    ));
                }
                // 16,type_code(1xx..3xx credit / 4xx..6xx debit),amount_minor,date,reference,counterparty
                let (unit_id, _) =
                    units
                        .lookup_code(&currency)
                        .ok_or_else(|| FormatError::UnknownUnit {
                            format: FMT,
                            unit: currency.clone(),
                        })?;
                let type_code: u16 = fields[1].parse().map_err(|_| FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid BAI2 16 type code in {raw:?}"),
                })?;
                let side = match type_code {
                    100..=399 => Side::Credit,
                    400..=699 => Side::Debit,
                    _ => {
                        return Err(camt_error(
                            FMT,
                            "BAI2 16 type code is outside the supported credit/debit classes",
                        ));
                    }
                };
                let mantissa: i128 = fields[2].parse().map_err(|_| FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid BAI2 16 amount in {raw:?}"),
                })?;
                let booking_date = parse_date_iso(FMT, fields[3])?;
                let reference = fields[4].to_owned();
                let counterparty = fields.get(5).copied().unwrap_or("").to_owned();
                let ordinal = (lines.len() as u32) + 1;
                let amount = Amount::new(unit_id, mantissa);
                let line_digest = compute_bank_line_digest(
                    &instrument_id,
                    seq,
                    ordinal,
                    booking_date,
                    side,
                    amount,
                    &reference,
                );
                lines.push(ParsedBankLine {
                    line_ordinal: ordinal,
                    booking_date,
                    value_date: booking_date,
                    side,
                    amount,
                    counterparty,
                    reference,
                    line_digest,
                });
            }
            "49" | "98" | "99" => {
                if !account_seen {
                    return Err(camt_error(FMT, "BAI2 trailer appears before its account"));
                }
                account_closed = true;
            }
            "01" => {}
            _ => {
                return Err(camt_error(
                    FMT,
                    "unrecognized or continuation BAI2 record is outside the bounded profile",
                ));
            }
        }
    }

    if !group_seen || !account_seen {
        return Err(camt_error(
            FMT,
            "BAI2 input needs one 02 group and one 03 account",
        ));
    }
    let opening_balance = opening_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing BAI2 010 opening balance".to_owned(),
    })?;
    let closing_balance = closing_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing BAI2 015 closing balance".to_owned(),
    })?;

    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: instrument_id,
        sequence_number: seq,
        currency,
        statement_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

/// One BAI2 logical record: its code, its fields (a trailing `/` delimiter
/// removed, `88` continuations joined) and the physical records it spans.
struct Bai2Record {
    code: String,
    fields: Vec<String>,
    physical: u64,
}

/// Parse one standard BAI version 2 file (one `01` file, one `02` group with
/// status 1, one `03` account) into a bank statement extract.
///
/// - `01` must declare version 2. Its file identification number, a positive
///   integer, is the statement's sequence number, so chaining a file to its
///   predecessor (`--previous-import`) needs consecutive file numbers.
/// - `02` carries the as-of date (YYMMDD, read as 2000-2099), which is every
///   detail's booking date, and the currency (USD when blank).
/// - `03` carries status and summary items, each a type code, an amount, an
///   item count and a funds type with its extras (`V` value date and time,
///   `S` three availability amounts, `D` a count of day/amount pairs). Status
///   010 (opening ledger) and 015 (closing ledger) are required.
/// - `16` is one detail: a type code in 100..=399 (credit) or 400..=699
///   (debit), an unsigned amount, a funds type with its extras (a `V` value
///   date is the line's value date; otherwise the as-of date), the bank and
///   customer references and a text field that runs to the end of the record.
/// - `88` continues the previous record: another field of an `03`, or more
///   text of a `16` (joined with a space).
/// - `49`, `98` and `99` must state exactly the control totals (the algebraic
///   sum of every `03` and `16` amount) and record counts the file holds.
///
/// Amounts are minor units of the currency at its registered scale (BAI2's
/// implied decimal). Opening + details = closing is verified like every
/// other format.
fn parse_bai2_standard(
    text: &str,
    units: &UnitCatalog,
) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "bai2_v2";
    let mut records: Vec<Bai2Record> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let (code, body) = line
            .split_once(',')
            .ok_or_else(|| camt_error(FMT, format!("BAI2 record without fields: {line:?}")))?;
        if code == "88" {
            let previous = records
                .last_mut()
                .filter(|record| matches!(record.code.as_str(), "03" | "16"))
                .ok_or_else(|| {
                    camt_error(FMT, "a BAI2 88 continuation must follow an 03 or 16 record")
                })?;
            let continued = body.strip_suffix('/').unwrap_or(body);
            if previous.code == "16" {
                let text = previous
                    .fields
                    .last_mut()
                    .ok_or_else(|| camt_error(FMT, "an empty BAI2 16 record"))?;
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(continued);
            } else {
                previous
                    .fields
                    .extend(continued.split(',').map(str::to_owned));
            }
            previous.physical += 1;
            continue;
        }
        let body = body.strip_suffix('/').unwrap_or(body);
        let fields = if code == "16" {
            // The text field, last, may itself contain commas: split only
            // as far as the fixed fields reach once the funds type is known.
            bai2_detail_fields(body)?
        } else {
            body.split(',').map(str::to_owned).collect()
        };
        records.push(Bai2Record {
            code: code.to_owned(),
            fields,
            physical: 1,
        });
    }

    let mut records = records.into_iter().peekable();

    let file = bai2_take(&mut records, "01")?;
    if file.fields.len() < 8 || file.fields[7] != "2" {
        return Err(camt_error(FMT, "BAI2 01 must declare version 2"));
    }
    let seq = file.fields[4]
        .parse::<u64>()
        .ok()
        .filter(|seq| *seq > 0)
        .ok_or_else(|| {
            camt_error(
                FMT,
                "the BAI2 01 file identification number must be a positive integer (it is the statement sequence)",
            )
        })?;
    bai2_date(&file.fields[2])?;

    let group = bai2_take(&mut records, "02")?;
    if group.fields.len() < 4 || group.fields.len() > 7 {
        return Err(camt_error(FMT, "malformed BAI2 02 group header"));
    }
    if group.fields[2] != "1" {
        return Err(camt_error(
            FMT,
            "only a BAI2 group with status 1 (update) is a statement; deletion, correction and test groups are refused",
        ));
    }
    let as_of = bai2_date(&group.fields[3])?;
    let group_currency = match group.fields.get(5).map(String::as_str) {
        None | Some("") => "USD".to_owned(),
        Some(code) => code.to_owned(),
    };

    let account = bai2_take(&mut records, "03")?;
    if account.fields.len() < 2 || account.fields[0].trim().is_empty() {
        return Err(camt_error(FMT, "BAI2 03 needs an account number"));
    }
    let instrument_id = account.fields[0].trim().to_owned();
    let currency = match account.fields[1].as_str() {
        "" => group_currency.clone(),
        code => code.to_owned(),
    };
    let (unit_id, _) = units
        .lookup_code(&currency)
        .ok_or_else(|| FormatError::UnknownUnit {
            format: FMT,
            unit: currency.clone(),
        })?;
    let mut control: i128 = 0;
    let add = |control: &mut i128, amount: i128| -> Result<(), FormatError> {
        *control = control
            .checked_add(amount)
            .ok_or_else(|| FormatError::Overflow {
                format: FMT,
                detail: "BAI2 control total overflow".to_owned(),
            })?;
        Ok(())
    };
    let mut opening = None;
    let mut closing = None;
    let items = &account.fields[2..];
    let mut i = 0usize;
    while i < items.len() {
        let type_code = items[i].as_str();
        if type_code.is_empty() && i + 1 == items.len() {
            break;
        }
        if type_code.len() != 3 || !type_code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(camt_error(
                FMT,
                format!("invalid BAI2 03 type code {type_code:?}"),
            ));
        }
        let amount = items.get(i + 1).map(String::as_str).unwrap_or("");
        let status = type_code < "100";
        let value = if amount.is_empty() {
            None
        } else {
            Some(bai2_amount(amount, status)?)
        };
        if let Some(value) = value {
            add(&mut control, value)?;
        }
        match type_code {
            "010" if opening.is_some() => return Err(camt_error(FMT, "repeated BAI2 010")),
            "010" => opening = value,
            "015" if closing.is_some() => return Err(camt_error(FMT, "repeated BAI2 015")),
            "015" => closing = value,
            _ => {}
        }
        // type, amount, item count, funds type and its extras.
        let mut next = i + 3;
        bai2_funds(items, &mut next)?;
        i = next;
    }
    let opening_balance =
        opening.ok_or_else(|| camt_error(FMT, "BAI2 03 has no 010 opening ledger balance"))?;
    let closing_balance =
        closing.ok_or_else(|| camt_error(FMT, "BAI2 03 has no 015 closing ledger balance"))?;
    let mut account_records = account.physical;

    let mut lines = Vec::new();
    while records.peek().is_some_and(|record| record.code == "16") {
        let detail = bai2_take(&mut records, "16")?;
        account_records += detail.physical;
        let f = &detail.fields;
        let type_code: u16 = f[0]
            .parse()
            .map_err(|_| camt_error(FMT, format!("invalid BAI2 16 type code {:?}", f[0])))?;
        let side = match type_code {
            100..=399 => Side::Credit,
            400..=699 => Side::Debit,
            _ => {
                return Err(camt_error(
                    FMT,
                    format!(
                        "BAI2 16 type code {type_code} is neither a credit (100..=399) nor a debit (400..=699)"
                    ),
                ));
            }
        };
        let mantissa = bai2_amount(&f[1], false)?;
        if mantissa == 0 {
            return Err(camt_error(FMT, "a BAI2 16 detail moves no money"));
        }
        add(&mut control, mantissa)?;
        let mut next = 2usize;
        let value_date = bai2_funds(f, &mut next)?.unwrap_or(as_of);
        let bank_ref = f.get(next).map_or("", |s| s.trim());
        let customer_ref = f.get(next + 1).map_or("", |s| s.trim());
        let text = f.get(next + 2).map_or("", |s| s.trim());
        let reference = if bank_ref.is_empty() {
            customer_ref
        } else {
            bank_ref
        }
        .to_owned();
        let ordinal = u32::try_from(lines.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| FormatError::Overflow {
                format: FMT,
                detail: "BAI2 line ordinal overflow".to_owned(),
            })?;
        let amount = Amount::new(unit_id, mantissa);
        let line_digest = compute_bank_line_digest(
            &instrument_id,
            seq,
            ordinal,
            as_of,
            side,
            amount,
            &reference,
        );
        lines.push(ParsedBankLine {
            line_ordinal: ordinal,
            booking_date: as_of,
            value_date,
            side,
            amount,
            counterparty: text.to_owned(),
            reference,
            line_digest,
        });
    }

    let account_trailer = bai2_take(&mut records, "49")?;
    account_records += account_trailer.physical;
    bai2_trailer(&account_trailer, 2, "49", control, None, account_records)?;
    let group_trailer = bai2_take(&mut records, "98")?;
    let group_records = account_records + group.physical + group_trailer.physical;
    bai2_trailer(&group_trailer, 3, "98", control, Some(1), group_records)?;
    let file_trailer = bai2_take(&mut records, "99")?;
    let file_records = group_records + file.physical + file_trailer.physical;
    bai2_trailer(&file_trailer, 3, "99", control, Some(1), file_records)?;
    if let Some(extra) = records.next() {
        return Err(camt_error(
            FMT,
            format!(
                "BAI2 record {} after the 99 file trailer; one file, group and account are read",
                extra.code
            ),
        ));
    }

    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: instrument_id,
        sequence_number: seq,
        currency,
        statement_date: as_of,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

/// The next BAI2 logical record, which must be `code`.
fn bai2_take(
    records: &mut std::iter::Peekable<std::vec::IntoIter<Bai2Record>>,
    code: &str,
) -> Result<Bai2Record, FormatError> {
    const FMT: &str = "bai2_v2";
    match records.next() {
        Some(record) if record.code == code => Ok(record),
        Some(record) => Err(camt_error(
            FMT,
            format!("expected a BAI2 {code} record, found {}", record.code),
        )),
        None => Err(camt_error(
            FMT,
            format!("BAI2 file ends before its {code} record"),
        )),
    }
}

/// A `16` body split into its fixed fields and a final text field that keeps
/// its commas: type, amount, funds type, the funds type's extras, bank and
/// customer references, then the text.
fn bai2_detail_fields(body: &str) -> Result<Vec<String>, FormatError> {
    const FMT: &str = "bai2_v2";
    let parts: Vec<&str> = body.split(',').collect();
    if parts.len() < 3 {
        return Err(camt_error(
            FMT,
            "BAI2 16 needs a type code, an amount and a funds type",
        ));
    }
    let owned: Vec<String> = parts.iter().map(|s| (*s).to_owned()).collect();
    let mut next = 2usize;
    bai2_funds(&owned, &mut next)?;
    // bank reference, customer reference, then the text (all of the rest).
    // A record may end after its bank reference: the customer reference and
    // the text are then empty.
    let fixed = next + 2;
    let mut fields: Vec<String> = owned.into_iter().take(fixed.min(parts.len())).collect();
    fields.resize(fixed, String::new());
    fields.push(
        parts
            .get(fixed..)
            .map_or(String::new(), |rest| rest.join(",")),
    );
    Ok(fields)
}

/// Read the funds type at `fields[*next]` and its extras, advancing `*next`
/// past them; a `V` value date is returned.
fn bai2_funds(fields: &[String], next: &mut usize) -> Result<Option<DateDay>, FormatError> {
    const FMT: &str = "bai2_v2";
    let funds = fields.get(*next).map_or("", |s| s.trim());
    *next += 1;
    let extra = |next: &mut usize, n: usize| -> Result<(), FormatError> {
        if fields.len() < *next + n {
            return Err(camt_error(FMT, "BAI2 funds type ends before its fields"));
        }
        *next += n;
        Ok(())
    };
    match funds {
        "" | "0" | "1" | "2" | "Z" => Ok(None),
        "V" => {
            let date = bai2_date(fields.get(*next).map_or("", |s| s.trim()))?;
            extra(next, 2)?;
            Ok(Some(date))
        }
        "S" => {
            for k in 0..3 {
                bai2_amount(fields.get(*next + k).map_or("", |s| s.trim()), true)?;
            }
            extra(next, 3)?;
            Ok(None)
        }
        "D" => {
            let count: usize = fields
                .get(*next)
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| camt_error(FMT, "BAI2 funds type D needs a distribution count"))?;
            extra(next, 1)?;
            for k in 0..count {
                bai2_amount(fields.get(*next + 2 * k + 1).map_or("", |s| s.trim()), true)?;
            }
            extra(next, 2 * count)?;
            Ok(None)
        }
        other => Err(camt_error(
            FMT,
            format!("unknown BAI2 funds type {other:?}"),
        )),
    }
}

/// YYMMDD, read as 2000..=2099 (the standard MT940 rule).
fn bai2_date(raw: &str) -> Result<DateDay, FormatError> {
    const FMT: &str = "bai2_v2";
    let digits = |s: &str| s.parse::<u32>().ok();
    if raw.len() != 6 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(camt_error(FMT, format!("BAI2 date {raw:?} is not YYMMDD")));
    }
    let (Some(yy), Some(mm), Some(dd)) = (digits(&raw[..2]), digits(&raw[2..4]), digits(&raw[4..]))
    else {
        return Err(camt_error(FMT, format!("BAI2 date {raw:?} is not YYMMDD")));
    };
    let year = i32::try_from(2000 + yy).map_err(|_| camt_error(FMT, "BAI2 year overflow"))?;
    DateDay::from_ymd(year, mm as u8, dd as u8)
        .map_err(|_| camt_error(FMT, format!("BAI2 date {raw:?} is not a civil date")))
}

/// Minor units: digits, signed (`+`/`-`) only where the field is signed.
fn bai2_amount(raw: &str, signed: bool) -> Result<i128, FormatError> {
    const FMT: &str = "bai2_v2";
    let (negative, digits) = match raw.as_bytes().first() {
        Some(b'-') if signed => (true, &raw[1..]),
        Some(b'+') if signed => (false, &raw[1..]),
        _ => (false, raw),
    };
    if digits.is_empty() || digits.len() > 30 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(camt_error(FMT, format!("invalid BAI2 amount {raw:?}")));
    }
    let value: i128 = digits
        .parse()
        .map_err(|_| camt_error(FMT, format!("invalid BAI2 amount {raw:?}")))?;
    if negative {
        negate_bank_amount(FMT, value)
    } else {
        Ok(value)
    }
}

/// A trailer states exactly the control total, the count of accounts or
/// groups it closes (when it has one) and its scope's physical records.
fn bai2_trailer(
    trailer: &Bai2Record,
    width: usize,
    code: &str,
    control: i128,
    members: Option<u64>,
    records: u64,
) -> Result<(), FormatError> {
    const FMT: &str = "bai2_v2";
    if trailer.fields.len() != width {
        return Err(camt_error(FMT, format!("malformed BAI2 {code} trailer")));
    }
    let stated = bai2_amount(&trailer.fields[0], true)?;
    if stated != control {
        return Err(FormatError::BankContinuity {
            format: FMT,
            detail: format!(
                "BAI2 {code} control total {stated} differs from the file's amounts ({control})"
            ),
        });
    }
    let count = |raw: &str| raw.trim().parse::<u64>().ok();
    if let Some(members) = members
        && count(&trailer.fields[1]) != Some(members)
    {
        return Err(camt_error(
            FMT,
            format!("BAI2 {code} states another number of accounts or groups than the one read"),
        ));
    }
    if count(&trailer.fields[width - 1]) != Some(records) {
        return Err(FormatError::BankContinuity {
            format: FMT,
            detail: format!(
                "BAI2 {code} states {} records; its scope holds {records}",
                trailer.fields[width - 1]
            ),
        });
    }
    Ok(())
}

/// Parse an OFX / Intuit QBO v2 XML statement into a [`BankStatementExtract`].
/// The bounded profile requires one account, explicit OPENBAL and ISO civil
/// dates. SGML, timestamp dates and multiple statements are not inferred.
pub fn parse_ofx_qbo(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "ofx_qbo_v2";
    // Every value is selected by the same complete-document parser. Textual
    // searches could otherwise read fake tags inside a comment, even after
    // the real elements' multiplicity and closing tags had been validated.
    if camt_blocks(FMT, text, "STMTRS", true)?.len() > 1 {
        return Err(camt_error(
            FMT,
            "multiple OFX statements are outside the bounded profile",
        ));
    }
    let currency = camt_text(FMT, bank_xml_one(FMT, text, "CURDEF")?)?.into_owned();
    let (unit_id, unit_scale) =
        units
            .lookup_code(&currency)
            .ok_or_else(|| FormatError::UnknownUnit {
                format: FMT,
                unit: currency.clone(),
            })?;
    let instrument_id = camt_text(FMT, bank_xml_one(FMT, text, "ACCTID")?)?.into_owned();
    let sequences = camt_blocks(FMT, text, "TRNUID", true)?;
    let seq: u64 = match sequences.as_slice() {
        [] => 1,
        [sequence] => camt_text(FMT, *sequence)?
            .parse()
            .map_err(|_| camt_error(FMT, "invalid OFX TRNUID"))?,
        _ => {
            return Err(camt_error(
                FMT,
                "multiple OFX sequences are outside the bounded profile",
            ));
        }
    };
    let opening_balance = parse_exact_decimal(
        FMT,
        &camt_text(FMT, bank_xml_one(FMT, text, "OPENBAL")?)?,
        unit_scale,
    )?;
    let ledger_bal_block = bank_xml_one(FMT, text, "LEDGERBAL")?.body;
    let closing_balance = parse_exact_decimal(
        FMT,
        &camt_text(FMT, camt_one(FMT, ledger_bal_block, "BALAMT")?)?,
        unit_scale,
    )?;
    let statement_date = parse_date_iso(
        FMT,
        &camt_text(FMT, camt_one(FMT, ledger_bal_block, "DTASOF")?)?,
    )?;

    let mut lines = Vec::new();
    for (idx, block) in camt_blocks(FMT, text, "STMTTRN", true)?
        .into_iter()
        .enumerate()
    {
        let trn = block.body;
        if !camt_blocks(FMT, trn, "STMTTRN", true)?.is_empty() {
            return Err(camt_error(
                FMT,
                "nested OFX transaction envelopes are invalid",
            ));
        }
        let ordinal = (idx as u32) + 1;
        let dt = parse_date_iso(FMT, &camt_text(FMT, camt_one(FMT, trn, "DTPOSTED")?)?)?;
        let signed = parse_exact_decimal(
            FMT,
            &camt_text(FMT, camt_one(FMT, trn, "TRNAMT")?)?,
            unit_scale,
        )?;
        let (side, mag) = if signed >= 0 {
            (Side::Credit, signed)
        } else {
            (Side::Debit, negate_bank_amount(FMT, signed)?)
        };
        let reference = camt_text(FMT, camt_one(FMT, trn, "FITID")?)?.into_owned();
        let counterparty = camt_optional(FMT, trn, "NAME")?
            .map(|name| camt_text(FMT, name).map(Cow::into_owned))
            .transpose()?
            .unwrap_or_default();
        let amount = Amount::new(unit_id, mag);
        let line_digest =
            compute_bank_line_digest(&instrument_id, seq, ordinal, dt, side, amount, &reference);
        lines.push(ParsedBankLine {
            line_ordinal: ordinal,
            booking_date: dt,
            value_date: dt,
            side,
            amount,
            counterparty,
            reference,
            line_digest,
        });
    }

    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: instrument_id,
        sequence_number: seq,
        currency,
        statement_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

/// Parse an ISO 20022 `camt.052` intraday account report XML (`BkToCstmrAcctRpt` / `Rpt`)
/// into a [`BankStatementExtract`] (plan §9.5, §15.9; bead `fa-2ek`).
pub fn parse_camt052(xml: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    parse_camt(xml, units, "iso20022_camt052", "Rpt", true)
}

/// Parse a CSV bank statement into a [`BankStatementExtract`] (plan §9.5, §15.9; bead `fa-2ek`).
///
/// Exactly twelve columns, with one consistent statement identity and closing date.
/// Quoted commas, doubled quotes and embedded newlines are supported.
/// Expected header:
/// `sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference`
pub fn parse_bank_csv(csv: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "bank_csv_v1";
    let records = bank_csv_records(csv)?;
    let mut non_empty = records.into_iter();
    let Some(header) = non_empty.next() else {
        return Err(FormatError::Parse {
            format: FMT,
            detail: "empty CSV bank statement".to_owned(),
        });
    };
    const HEADER: [&str; 12] = [
        "sequence_number",
        "instrument_id",
        "currency",
        "statement_date",
        "opening_balance",
        "closing_balance",
        "booking_date",
        "value_date",
        "side",
        "amount",
        "counterparty",
        "reference",
    ];
    if header.iter().map(|field| field.trim()).ne(HEADER) {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!("unexpected bank CSV header {header:?}"),
        });
    }

    let mut instrument_id = String::new();
    let mut seq = 0u64;
    let mut currency = String::new();
    let mut statement_date = DateDay(0);
    let mut opening_balance: Option<i128> = None;
    let mut closing_balance: Option<i128> = None;
    let mut lines = Vec::new();

    for (idx, record) in non_empty.enumerate() {
        let fields: Vec<&str> = record.iter().map(|field| field.trim()).collect();
        if fields.len() != 12 {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("bank CSV row {} must have exactly 12 columns", idx + 1),
            });
        }
        let row_seq: u64 = fields[0].parse().map_err(|_| FormatError::Parse {
            format: FMT,
            detail: format!("invalid sequence_number {:?}", fields[0]),
        })?;
        let row_inst = fields[1];
        if row_inst.is_empty() {
            return Err(FormatError::Parse {
                format: FMT,
                detail: "bank CSV instrument_id must not be empty".to_owned(),
            });
        }
        let row_ccy = fields[2];
        let (unit_id, unit_scale) =
            units
                .lookup_code(row_ccy)
                .ok_or_else(|| FormatError::UnknownUnit {
                    format: FMT,
                    unit: row_ccy.to_owned(),
                })?;
        let row_stmt_date = parse_date_iso(FMT, fields[3])?;
        let row_open = parse_exact_decimal(FMT, fields[4], unit_scale)?;
        let row_close = parse_exact_decimal(FMT, fields[5], unit_scale)?;

        if idx == 0 {
            seq = row_seq;
            instrument_id = row_inst.to_owned();
            currency = row_ccy.to_owned();
            statement_date = row_stmt_date;
            opening_balance = Some(row_open);
            closing_balance = Some(row_close);
        } else if row_seq != seq
            || row_inst != instrument_id
            || row_ccy != currency
            || row_stmt_date != statement_date
            || Some(row_open) != opening_balance
            || Some(row_close) != closing_balance
        {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("inconsistent statement header fields on row {}", idx + 1),
            });
        }

        let booking_date = parse_date_iso(FMT, fields[6])?;
        let value_date = parse_date_iso(FMT, fields[7])?;
        let side = match fields[8] {
            "CRDT" | "Credit" | "CREDIT" => Side::Credit,
            "DBIT" | "Debit" | "DEBIT" => Side::Debit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid bank CSV side {other:?}"),
                });
            }
        };
        let mantissa = parse_exact_decimal(FMT, fields[9], unit_scale)?;
        if mantissa <= 0 {
            return Err(FormatError::Parse {
                format: FMT,
                detail: "bank CSV line amount must be positive".to_owned(),
            });
        }
        let counterparty = fields[10].to_owned();
        let reference = fields[11].to_owned();
        let ordinal = (idx as u32) + 1;
        let amount = Amount::new(unit_id, mantissa);
        let line_digest = compute_bank_line_digest(
            &instrument_id,
            seq,
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

    let opening_balance = opening_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "bank CSV has no data rows".to_owned(),
    })?;
    let closing_balance = closing_balance.unwrap_or(opening_balance);
    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: instrument_id,
        sequence_number: seq,
        currency,
        statement_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

/// Read the declared bank CSV layout without splitting a quoted counterparty,
/// reference, or embedded newline into a different column or transaction.
/// Malformed quotes and extra columns are refused rather than losing input.
fn bank_csv_records(csv: &str) -> Result<Vec<Vec<String>>, FormatError> {
    bank_csv_records_with(csv, ',', 12, usize::MAX, "bank_csv_v1")
}

fn bank_csv_records_with(
    csv: &str,
    delimiter: char,
    max_columns: usize,
    max_records: usize,
    format: &'static str,
) -> Result<Vec<Vec<String>>, FormatError> {
    let invalid = |detail: &str| FormatError::Parse {
        format,
        detail: detail.to_owned(),
    };
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut closed_quote = false;
    let mut chars = csv
        .strip_prefix('\u{feff}')
        .unwrap_or(csv)
        .chars()
        .peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    closed_quote = true;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        match ch {
            '"' if field.is_empty() && !closed_quote => quoted = true,
            ch if ch == delimiter => {
                record.push(core::mem::take(&mut field));
                if record.len() >= max_columns {
                    return Err(invalid(
                        "bank CSV record has more columns than its declared header",
                    ));
                }
                closed_quote = false;
            }
            '\r' | '\n' => {
                if ch == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                if !record.is_empty() || !field.trim().is_empty() || closed_quote {
                    record.push(core::mem::take(&mut field));
                    records.push(core::mem::take(&mut record));
                    if records.len() > max_records {
                        return Err(invalid("bank CSV exceeds the bounded statement line count"));
                    }
                } else {
                    field.clear();
                }
                closed_quote = false;
            }
            '"' => return Err(invalid("unexpected quote in an unquoted bank CSV field")),
            _ if closed_quote => {
                return Err(invalid("unexpected text after a quoted bank CSV field"));
            }
            _ => field.push(ch),
        }
    }
    if quoted {
        return Err(invalid("unterminated quoted bank CSV field"));
    }
    if !record.is_empty() || !field.trim().is_empty() || closed_quote {
        record.push(field);
        records.push(record);
        if records.len() > max_records {
            return Err(invalid("bank CSV exceeds the bounded statement line count"));
        }
    }
    Ok(records)
}

/// Parse one SWIFT MT940 statement into a bank statement extract.
///
/// The standard profile accepts an unwrapped :20:/:25:/:28C:/:60F:/:61:/:86:/:62F:
/// message, comma decimals, and C/D/RC/RD entries. YY dates explicitly mean
/// 2000-2099; an MMDD entry date must resolve uniquely within the opening/closing
/// date interval. Without MMDD, the value date is also the booking date.
/// Transaction :86: narratives are retained in the counterparty projection.
/// Multipart statements, envelopes and supplementary :61: lines need explicit
/// conversion upstream. The original pipe-separated ISO-date profile remains
/// supported, but profiles cannot be mixed within one statement.
pub fn parse_mt940(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    let standard = text
        .lines()
        .find_map(|line| line.trim().strip_prefix(":60F:"))
        .is_some_and(|balance| !balance.contains('|'));
    if standard {
        parse_mt940_standard(text, units)
    } else {
        parse_mt940_legacy(text, units)
    }
}

fn parse_mt940_legacy(
    text: &str,
    units: &UnitCatalog,
) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "swift_mt940";
    let mut instrument_id = String::new();
    let mut seq = 1u64;
    let mut currency = String::new();
    let mut statement_date = DateDay(0);
    let mut opening_balance: Option<i128> = None;
    let mut closing_balance: Option<i128> = None;
    let mut lines: Vec<ParsedBankLine> = Vec::new();
    let mut account_seen = false;
    let mut sequence_seen = false;

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix(":25:") {
            if account_seen || rest.trim().is_empty() {
                return Err(camt_error(
                    FMT,
                    "MT940 requires exactly one nonempty :25: account identity",
                ));
            }
            account_seen = true;
            instrument_id = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix(":28C:") {
            if sequence_seen {
                return Err(camt_error(
                    FMT,
                    "multiple MT940 :28C: statements are outside the bounded profile",
                ));
            }
            sequence_seen = true;
            let num_part = rest.split('/').next().unwrap_or(rest).trim();
            seq = num_part.parse().map_err(|_| FormatError::Parse {
                format: FMT,
                detail: format!("invalid :28C: sequence {rest:?}"),
            })?;
        } else if let Some(rest) = line.strip_prefix(":60F:") {
            if opening_balance.is_some() || !account_seen || !sequence_seen {
                return Err(camt_error(
                    FMT,
                    "MT940 needs exactly one :60F: opening balance after its account and sequence",
                ));
            }
            let (dt, ccy, signed) = parse_mt940_balance(FMT, rest, units)?;
            currency = ccy;
            statement_date = dt;
            opening_balance = Some(signed);
        } else if let Some(rest) = line.strip_prefix(":62F:") {
            if closing_balance.is_some() || opening_balance.is_none() {
                return Err(camt_error(
                    FMT,
                    "MT940 needs exactly one :62F: closing balance after its opening balance",
                ));
            }
            let (dt, ccy, signed) = parse_mt940_balance(FMT, rest, units)?;
            if currency != ccy {
                return Err(FormatError::BankContinuity {
                    format: FMT,
                    detail: "MT940 opening and closing balance currencies differ".to_owned(),
                });
            }
            statement_date = dt;
            closing_balance = Some(signed);
        } else if let Some(rest) = line.strip_prefix(":61:") {
            if opening_balance.is_none() || closing_balance.is_some() {
                return Err(camt_error(
                    FMT,
                    "MT940 :61: transaction must lie between opening and closing balances",
                ));
            }
            // Format: YYYY-MM-DD|C-or-D|amount|reference[|counterparty]
            let parts: Vec<&str> = rest.split('|').map(str::trim).collect();
            if !(4..=5).contains(&parts.len()) {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid :61: line {rest:?}"),
                });
            }
            let dt = parse_date_iso(FMT, parts[0])?;
            let side = match parts[1] {
                "C" | "CRDT" => Side::Credit,
                "D" | "DBIT" => Side::Debit,
                other => {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid :61: indicator {other:?}"),
                    });
                }
            };
            let (unit_id, unit_scale) =
                units
                    .lookup_code(&currency)
                    .ok_or_else(|| FormatError::UnknownUnit {
                        format: FMT,
                        unit: currency.clone(),
                    })?;
            let mantissa = parse_exact_decimal(FMT, parts[2], unit_scale)?;
            let reference = parts[3].to_owned();
            let counterparty = parts.get(4).copied().unwrap_or("").to_owned();
            let ordinal = (lines.len() as u32) + 1;
            let amount = Amount::new(unit_id, mantissa);
            let line_digest = compute_bank_line_digest(
                &instrument_id,
                seq,
                ordinal,
                dt,
                side,
                amount,
                &reference,
            );
            lines.push(ParsedBankLine {
                line_ordinal: ordinal,
                booking_date: dt,
                value_date: dt,
                side,
                amount,
                counterparty,
                reference,
                line_digest,
            });
        } else if line.starts_with(":60M:") || line.starts_with(":62M:") {
            return Err(camt_error(
                FMT,
                "intermediate MT940 balances are outside the single-statement bounded profile",
            ));
        } else if !line.is_empty() && !line.starts_with(":20:") && !line.starts_with(":86:") {
            return Err(camt_error(
                FMT,
                "unrecognized MT940 record is outside the bounded profile",
            ));
        }
    }

    if !account_seen || !sequence_seen {
        return Err(camt_error(
            FMT,
            "MT940 input needs one :25: account and one :28C: sequence",
        ));
    }
    let opening_balance = opening_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing :60F: opening balance in MT940".to_owned(),
    })?;
    let closing_balance = closing_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing :62F: closing balance in MT940".to_owned(),
    })?;
    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: instrument_id,
        sequence_number: seq,
        currency,
        statement_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

fn mt940_required<'a>(
    records: &mut impl Iterator<Item = (&'a str, String)>,
    expected: &str,
) -> Result<String, FormatError> {
    match records.next() {
        Some((tag, body)) if tag == expected => Ok(body),
        _ => Err(camt_error(
            "swift_mt940",
            format!("MT940 requires :{expected}: in statement order"),
        )),
    }
}

fn mt940_text(text: &str, maximum: usize) -> bool {
    !text.trim().is_empty()
        && text.chars().count() <= maximum
        && !text.chars().any(char::is_control)
}

fn parse_mt940_standard(
    text: &str,
    units: &UnitCatalog,
) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "swift_mt940";
    let mut records: Vec<(&str, String)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(field) = line.strip_prefix(':') {
            let (tag, body) = field
                .split_once(':')
                .ok_or_else(|| camt_error(FMT, "malformed MT940 record tag"))?;
            records.push((tag, body.trim().to_owned()));
        } else if let Some((tag, body)) = records.last_mut() {
            if *tag != "86" {
                return Err(camt_error(FMT, "unsupported MT940 continuation record"));
            }
            body.push('\n');
            body.push_str(line);
        } else {
            return Err(camt_error(FMT, "MT940 needs an unwrapped statement body"));
        }
    }

    let mut records = records.into_iter().peekable();
    if !mt940_text(&mt940_required(&mut records, "20")?, 16) {
        return Err(camt_error(FMT, "invalid MT940 message reference"));
    }
    if records.peek().is_some_and(|(tag, _)| *tag == "21")
        && !mt940_text(&mt940_required(&mut records, "21")?, 16)
    {
        return Err(camt_error(FMT, "invalid MT940 related reference"));
    }
    let instrument_id = mt940_required(&mut records, "25")?;
    if !mt940_text(&instrument_id, 35) {
        return Err(camt_error(FMT, "invalid MT940 account identity"));
    }
    let sequence = mt940_required(&mut records, "28C")?;
    let mut sequence_parts = sequence.split('/');
    let number = sequence_parts.next().unwrap_or("");
    let part = sequence_parts.next();
    let valid_number =
        |value: &str| (1..=5).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit());
    if !valid_number(number)
        || part.is_some_and(|value| !valid_number(value) || value.parse::<u64>() != Ok(1))
        || sequence_parts.next().is_some()
    {
        return Err(camt_error(
            FMT,
            "MT940 :28C: needs a statement number and optional first-message /1",
        ));
    }
    let seq = number
        .parse::<u64>()
        .map_err(|_| camt_error(FMT, "invalid MT940 statement number"))?;
    let opening = mt940_required(&mut records, "60F")?;
    let (opening_date, currency, opening_balance) = mt940_standard_balance(&opening, units)?;
    let mut pending = Vec::new();
    while records.peek().is_some_and(|(tag, _)| *tag == "61") {
        let raw = mt940_required(&mut records, "61")?;
        let (mut line, entry_date) = mt940_standard_line(&raw, &currency, units)?;
        if records.peek().is_some_and(|(tag, _)| *tag == "86") {
            let description = mt940_required(&mut records, "86")?;
            if !(1..=6).contains(&description.lines().count())
                || description.lines().any(|part| !mt940_text(part, 65))
            {
                return Err(camt_error(
                    FMT,
                    "MT940 :86: needs at most six nonempty 65-character lines",
                ));
            }
            line.counterparty = description;
        }
        pending.push((line, entry_date));
    }
    let closing = mt940_required(&mut records, "62F")?;
    let (closing_date, closing_currency, closing_balance) =
        mt940_standard_balance(&closing, units)?;
    if closing_currency != currency || closing_date < opening_date {
        return Err(FormatError::BankContinuity {
            format: FMT,
            detail: "MT940 balance currency or date interval is inconsistent".to_owned(),
        });
    }
    // Available balances are metadata, never replacement booked balances.
    let mut available_seen = false;
    let mut forward_seen = false;
    for (tag, body) in records {
        match tag {
            "64" if !available_seen && !forward_seen => available_seen = true,
            "65" => forward_seen = true,
            _ => {
                return Err(camt_error(
                    FMT,
                    "unexpected MT940 record after final closing balance",
                ));
            }
        }
        let (date, balance_currency, _) = mt940_standard_balance(&body, units)?;
        if balance_currency != currency || date < closing_date {
            return Err(camt_error(FMT, "inconsistent MT940 available balance"));
        }
    }

    let mut lines: Vec<ParsedBankLine> = Vec::new();
    for (mut line, entry_date) in pending {
        let booking_date = match entry_date {
            Some(mmdd) => mt940_entry_date(&mmdd, opening_date, closing_date)?,
            None => line.value_date,
        };
        if booking_date < opening_date || booking_date > closing_date {
            return Err(camt_error(
                FMT,
                "MT940 booking date lies outside the statement interval",
            ));
        }
        let ordinal = u32::try_from(lines.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| FormatError::Overflow {
                format: FMT,
                detail: "MT940 line ordinal overflow".to_owned(),
            })?;
        line.line_ordinal = ordinal;
        line.booking_date = booking_date;
        line.line_digest = compute_bank_line_digest(
            &instrument_id,
            seq,
            ordinal,
            booking_date,
            line.side,
            line.amount,
            &line.reference,
        );
        lines.push(line);
    }
    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: instrument_id,
        sequence_number: seq,
        currency,
        statement_date: closing_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;
    Ok(extract)
}

fn mt940_date(raw: &str) -> Result<DateDay, FormatError> {
    const FMT: &str = "swift_mt940";
    if raw.len() != 6 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(camt_error(FMT, "MT940 requires a six-digit YYMMDD date"));
    }
    parse_date_iso(
        FMT,
        &format!("20{}-{}-{}", &raw[..2], &raw[2..4], &raw[4..]),
    )
}

fn mt940_entry_date(
    mmdd: &str,
    opening: DateDay,
    closing: DateDay,
) -> Result<DateDay, FormatError> {
    const FMT: &str = "swift_mt940";
    if mmdd.len() != 4 || !mmdd.bytes().all(|b| b.is_ascii_digit()) {
        return Err(camt_error(FMT, "invalid MT940 MMDD entry date"));
    }
    let mut found = None;
    for year in opening.year()..=closing.year() {
        let candidate = parse_date_iso(FMT, &format!("{year:04}-{}-{}", &mmdd[..2], &mmdd[2..]));
        let Ok(date) = candidate else {
            continue;
        };
        if date < opening || date > closing {
            continue;
        }
        if found.is_some() {
            return Err(camt_error(FMT, "ambiguous MT940 entry-date year"));
        }
        found = Some(date);
    }
    found.ok_or_else(|| camt_error(FMT, "MT940 entry date lies outside the statement interval"))
}

fn mt940_amount(raw: &str, scale: u8) -> Result<i128, FormatError> {
    const FMT: &str = "swift_mt940";
    let (whole, fraction) = raw
        .split_once(',')
        .ok_or_else(|| camt_error(FMT, "MT940 amount requires a decimal comma"))?;
    if raw.len() > 15
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(camt_error(FMT, "invalid unsigned MT940 15d amount"));
    }
    // SWIFT permits an empty fractional part after the mandatory comma.
    let decimal = if fraction.is_empty() {
        whole.to_owned()
    } else {
        format!("{whole}.{fraction}")
    };
    parse_exact_decimal(FMT, &decimal, scale)
}

fn mt940_standard_balance(
    raw: &str,
    units: &UnitCatalog,
) -> Result<(DateDay, String, i128), FormatError> {
    const FMT: &str = "swift_mt940";
    if !raw.is_ascii() || raw.len() < 12 {
        return Err(camt_error(FMT, "invalid MT940 balance record"));
    }
    let date = mt940_date(&raw[1..7])?;
    let currency = &raw[7..10];
    if !currency.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(camt_error(FMT, "invalid MT940 balance currency"));
    }
    let (_, scale) = units
        .lookup_code(currency)
        .ok_or_else(|| FormatError::UnknownUnit {
            format: FMT,
            unit: currency.to_owned(),
        })?;
    let magnitude = mt940_amount(&raw[10..], scale)?;
    let signed = match raw.as_bytes()[0] {
        b'C' => magnitude,
        b'D' => negate_bank_amount(FMT, magnitude)?,
        _ => return Err(camt_error(FMT, "invalid MT940 balance C/D indicator")),
    };
    Ok((date, currency.to_owned(), signed))
}

fn mt940_standard_line(
    raw: &str,
    currency: &str,
    units: &UnitCatalog,
) -> Result<(ParsedBankLine, Option<String>), FormatError> {
    const FMT: &str = "swift_mt940";
    if !raw.is_ascii() || raw.len() < 6 {
        return Err(camt_error(FMT, "invalid MT940 transaction record"));
    }
    let value_date = mt940_date(&raw[..6])?;
    let mut rest = &raw[6..];
    let entry_date = if rest.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        if rest.len() < 4 || !rest[..4].bytes().all(|b| b.is_ascii_digit()) {
            return Err(camt_error(FMT, "invalid MT940 MMDD entry date"));
        }
        let date = rest[..4].to_owned();
        rest = &rest[4..];
        Some(date)
    } else {
        None
    };
    let (side, tail) = if let Some(tail) = rest.strip_prefix("RC") {
        (Side::Debit, tail)
    } else if let Some(tail) = rest.strip_prefix("RD") {
        (Side::Credit, tail)
    } else if let Some(tail) = rest.strip_prefix('C') {
        (Side::Credit, tail)
    } else if let Some(tail) = rest.strip_prefix('D') {
        (Side::Debit, tail)
    } else {
        return Err(camt_error(
            FMT,
            "invalid MT940 transaction C/D/RC/RD indicator",
        ));
    };
    rest = tail;
    if rest.as_bytes().first().is_some_and(u8::is_ascii_uppercase) {
        if rest.as_bytes().first() != currency.as_bytes().get(2) {
            return Err(camt_error(
                FMT,
                "MT940 funds code differs from the account currency",
            ));
        }
        rest = &rest[1..];
    }
    let amount_end = rest
        .find(|c: char| !c.is_ascii_digit() && c != ',')
        .unwrap_or(rest.len());
    let (unit, scale) = units
        .lookup_code(currency)
        .ok_or_else(|| FormatError::UnknownUnit {
            format: FMT,
            unit: currency.to_owned(),
        })?;
    let magnitude = mt940_amount(&rest[..amount_end], scale)?;
    if magnitude == 0 {
        return Err(camt_error(
            FMT,
            "MT940 transaction magnitude must be positive",
        ));
    }
    rest = &rest[amount_end..];
    if rest.len() < 5
        || !matches!(rest.as_bytes()[0], b'N' | b'F' | b'S')
        || !rest[1..4].bytes().all(|b| b.is_ascii_alphanumeric())
        || (rest.starts_with('S') && !rest[1..4].bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(camt_error(
            FMT,
            "invalid MT940 transaction type or missing reference",
        ));
    }
    let reference = &rest[4..];
    let (customer, bank) = match reference.split_once("//") {
        Some((customer, bank)) => (customer, Some(bank)),
        None => (reference, None),
    };
    if !mt940_text(customer, 16)
        || bank.is_some_and(|value| !mt940_text(value, 16) || value.contains("//"))
    {
        return Err(camt_error(
            FMT,
            "invalid or ambiguous MT940 customer/bank reference",
        ));
    }
    Ok((
        ParsedBankLine {
            line_ordinal: 0,
            booking_date: value_date,
            value_date,
            side,
            amount: Amount::new(unit, magnitude),
            counterparty: String::new(),
            reference: reference.to_owned(),
            line_digest: [0; 32],
        },
        entry_date,
    ))
}

fn parse_mt940_balance(
    format: &'static str,
    rest: &str,
    units: &UnitCatalog,
) -> Result<(DateDay, String, i128), FormatError> {
    // Format: C|D|YYYY-MM-DD|CCY|AMOUNT
    let parts: Vec<&str> = rest.split('|').map(str::trim).collect();
    if parts.len() != 4 {
        return Err(FormatError::Parse {
            format,
            detail: format!("invalid MT940 balance field {rest:?}"),
        });
    }
    let dt = parse_date_iso(format, parts[1])?;
    let ccy = parts[2].to_owned();
    let (_, scale) = units
        .lookup_code(&ccy)
        .ok_or_else(|| FormatError::UnknownUnit {
            format,
            unit: ccy.clone(),
        })?;
    let mag = parse_exact_decimal(format, parts[3], scale)?;
    if mag < 0 {
        return Err(FormatError::Parse {
            format,
            detail: "MT940 balance magnitude must be unsigned; C/D carries its sign".to_owned(),
        });
    }
    let signed = match parts[0] {
        "C" => mag,
        "D" => negate_bank_amount(format, mag)?,
        other => {
            return Err(FormatError::Parse {
                format,
                detail: format!("invalid MT940 balance indicator {other:?}"),
            });
        }
    };
    Ok((dt, ccy, signed))
}

pub fn compute_bank_line_digest(
    instrument_id: &str,
    seq: u64,
    ordinal: u32,
    booking_date: DateDay,
    side: Side,
    amount: Amount,
    reference: &str,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:formats:bank_line:v1");
    h.update(&(instrument_id.len() as u64).to_le_bytes());
    h.update(instrument_id.as_bytes());
    h.update(&seq.to_le_bytes());
    h.update(&ordinal.to_le_bytes());
    h.update(&booking_date.0.to_le_bytes());
    h.update(&[side as u8]);
    h.update(&amount.unit.0.to_le_bytes());
    h.update(&amount.mantissa.to_le_bytes());
    h.update(&(reference.len() as u64).to_le_bytes());
    h.update(reference.as_bytes());
    h.finalize().0
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ISO choices deliberately repeat `Dt` and `Id` at different depths.
    // Transaction details also carry amounts, so an entry must select its own
    // direct amount instead of the first descendant with the same local name.
    const CAMT053: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08">
  <BkToCstmrStmt>
    <Stmt>
      <Id>STATEMENT-1</Id><ElctrncSeqNb>1</ElctrncSeqNb>
      <Acct><Id><IBAN>GB29NWBK60161331926819</IBAN></Id><Ccy>USD</Ccy></Acct>
      <Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp>
        <Amt Ccy="USD">1000.00</Amt><CdtDbtInd>CRDT</CdtDbtInd>
        <Dt><Dt>2026-01-01</Dt></Dt></Bal>
      <Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp>
        <Amt Ccy="USD">1250.00</Amt><CdtDbtInd>CRDT</CdtDbtInd>
        <Dt><Dt>2026-01-31</Dt></Dt></Bal>
      <!-- A comment mentioning <Ntry> is not an entry. -->
      <Ntry>
        <NtryDtls><TxDtls><AmtDtls><InstdAmt><Amt Ccy="USD">999.00</Amt></InstdAmt></AmtDtls>
          <RltdPties><Dbtr><Pty><Nm>Acme &amp; Co</Nm></Pty></Dbtr></RltdPties></TxDtls></NtryDtls>
        <Amt Ccy="USD">500.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>
        <BookgDt><Dt>2026-01-10</Dt></BookgDt><ValDt><Dt>2026-01-11</Dt></ValDt>
        <AcctSvcrRef>INV-100</AcctSvcrRef>
      </Ntry>
      <Ntry>
        <Amt Ccy='USD' note='a > b'>250.00</Amt><CdtDbtInd>DBIT</CdtDbtInd><Sts>BOOK</Sts>
        <BookgDt><Dt>2026-01-15</Dt></BookgDt><ValDt><Dt>2026-01-16</Dt></ValDt>
        <AcctSvcrRef>BILL-200</AcctSvcrRef><Nm>Cloud Hosting</Nm>
      </Ntry>
    </Stmt>
  </BkToCstmrStmt>
</Document>"#;

    #[test]
    fn real_camt_choices_currency_attributes_and_namespace_prefixes_preserve_values() {
        let units = UnitCatalog::embedded().unwrap();
        let statement = parse_camt053(CAMT053, &units).unwrap();
        assert_eq!(statement.instrument_account_id, "GB29NWBK60161331926819");
        assert_eq!(statement.sequence_number, 1);
        assert_eq!(statement.statement_date.render(), "2026-01-31");
        assert_eq!(statement.opening_balance, 100_000);
        assert_eq!(statement.closing_balance, 125_000);
        assert_eq!(statement.lines.len(), 2);
        assert_eq!(statement.lines[0].amount.mantissa, 50_000);
        assert_eq!(statement.lines[0].side, Side::Credit);
        assert_eq!(statement.lines[0].booking_date.render(), "2026-01-10");
        assert_eq!(statement.lines[0].value_date.render(), "2026-01-11");
        assert_eq!(statement.lines[0].counterparty, "Acme & Co");
        assert_eq!(statement.lines[0].reference, "INV-100");
        assert_eq!(statement.lines[1].amount.mantissa, 25_000);
        assert_eq!(statement.lines[1].side, Side::Debit);
        assert_eq!(statement.lines[1].value_date.render(), "2026-01-16");

        // Equivalent qualified names must preserve bank-line identities.
        let prefixed = CAMT053
            .replace('<', "<c:")
            .replace("<c:/", "</c:")
            .replace("<c:?", "<?")
            .replace("<c:!", "<!")
            .replace("xmlns=", "xmlns:c=");
        assert_eq!(parse_camt053(&prefixed, &units).unwrap(), statement);

        let intraday = CAMT053
            .replace("camt.053", "camt.052")
            .replace("BkToCstmrStmt", "BkToCstmrAcctRpt")
            .replace("<Stmt>", "<Rpt>")
            .replace("</Stmt>", "</Rpt>")
            .replace("<Cd>CLBD</Cd>", "<Cd>ITBD</Cd>")
            .replace(
                "<IBAN>GB29NWBK60161331926819</IBAN>",
                "<Othr><Id>ACCT-001</Id><SchmeNm><Prtry>LOCAL</Prtry></SchmeNm></Othr>",
            );
        let report = parse_camt052(&intraday, &units).unwrap();
        assert_eq!(report.instrument_account_id, "ACCT-001");
        assert_eq!(report.closing_balance, statement.closing_balance);
        assert_eq!(report.lines[0].value_date, statement.lines[0].value_date);
    }

    #[test]
    fn camt_refuses_partial_ambiguous_or_semantically_invalid_sources() {
        let units = UnitCatalog::embedded().unwrap();
        let cases = [
            CAMT053.replace("</Stmt>", "</Stmt><Stmt/>"),
            format!("{CAMT053}<Ntry>"),
            CAMT053.replace("</ValDt>", "</BookgDt>"),
            CAMT053.replace(
                "<ValDt><Dt>2026-01-11</Dt></ValDt>",
                "<ValDt><Dt>2026-02-30</Dt></ValDt>",
            ),
            CAMT053.replace(
                "<ValDt><Dt>2026-01-11</Dt></ValDt>",
                "<ValDt><DtTm>2026-01-11T23:30:00-05:00</DtTm></ValDt>",
            ),
            CAMT053.replace(
                "<Amt Ccy=\"USD\">500.00</Amt>",
                "<Amt Ccy=\"EUR\">500.00</Amt>",
            ),
            CAMT053.replace(
                "<Amt Ccy=\"USD\">500.00</Amt>",
                "<Amt Ccy=\"USD\" Ccy=\"EUR\">500.00</Amt>",
            ),
            CAMT053.replace("</IBAN>", "</IBAN><Othr><Id>DIFFERENT-ACCOUNT</Id></Othr>"),
            CAMT053.replace("<Cd>OPBD</Cd>", "<Cd>CLBD</Cd>"),
            CAMT053.replace("<Bal><Tp>", "<Bal><Cd>OPBD</Cd><Tp>"),
            CAMT053.replace(
                "<Amt Ccy=\"USD\">500.00</Amt>",
                "<Amt Ccy=\"USD\">-500.00</Amt>",
            ),
            CAMT053.replace(
                "<Amt Ccy=\"USD\">500.00</Amt>",
                "<Amt Ccy=\"USD\">0.00</Amt>",
            ),
            CAMT053.replace("<Cd>BOOK</Cd>", "<Cd>PDNG</Cd>"),
            format!("<!DOCTYPE Document SYSTEM 'file:///not-loaded'>{CAMT053}"),
        ];
        for (index, xml) in cases.into_iter().enumerate() {
            assert!(parse_camt053(&xml, &units).is_err(), "invalid case {index}");
        }

        let absent_value_date = CAMT053.replace("<ValDt><Dt>2026-01-11</Dt></ValDt>", "");
        let statement = parse_camt053(&absent_value_date, &units).unwrap();
        assert_eq!(
            statement.lines[0].value_date,
            statement.lines[0].booking_date
        );
    }

    #[test]
    fn bank_xml_character_references_preserve_values_and_invalid_entities_refuse() {
        let units = UnitCatalog::embedded().unwrap();
        let expected = parse_camt053(CAMT053, &units).unwrap();
        let encoded = CAMT053
            .replace("GB29", "GB&#x32;9")
            .replace("USD", "U&#83;D")
            .replace("2026-01-11", "2026&#45;01&#45;11")
            .replace("500.00", "5&#48;0.00")
            .replace("INV-100", "INV&#45;100")
            .replace("Acme &amp; Co", "Acme &#x26; Co");
        assert_eq!(parse_camt053(&encoded, &units).unwrap(), expected);
        assert_eq!(
            parse_camt053(&format!("\u{feff}{CAMT053}"), &units).unwrap(),
            expected
        );

        for entity in [
            "&unknown;",
            "&unfinished",
            "&#0;",
            "&#xD800;",
            "&#1114112;",
            "&#x110000;",
            "&#x;",
            "&#-1;",
            "raw&text",
            "&#x1;",
            "\u{0}",
        ] {
            let invalid = CAMT053.replace("Acme &amp; Co", entity);
            assert!(
                parse_camt053(&invalid, &units).is_err(),
                "accepted entity {entity:?}"
            );
        }
        assert!(
            parse_camt053(
                &CAMT053.replace("Ccy=\"USD\"", "Ccy=\"U&unknown;D\""),
                &units
            )
            .is_err()
        );
        assert!(parse_camt053(&format!("<!-->{CAMT053}"), &units).is_err());

        // XML decoding is one layer; an escaped ampersand must not turn the
        // subsequent literal character-reference text into a second decode.
        let once = CAMT053.replace("INV-100", "INV&amp;#45;100");
        assert_eq!(
            parse_camt053(&once, &units).unwrap().lines[0].reference,
            "INV&#45;100"
        );
    }

    #[test]
    fn public_balance_checks_refuse_invalid_magnitudes_currency_changes_and_overflow() {
        let units = UnitCatalog::embedded().unwrap();
        let statement = parse_camt053(CAMT053, &units).unwrap();
        for magnitude in [0, -1, i128::MIN] {
            let mut invalid = statement.clone();
            invalid.lines[0].side = Side::Debit;
            invalid.lines[0].amount.mantissa = magnitude;
            assert!(matches!(
                invalid.verify_internal_balance(),
                Err(FormatError::Parse { .. })
            ));
        }
        let mut overflow = statement.clone();
        overflow.opening_balance = i128::MAX;
        assert!(matches!(
            overflow.verify_internal_balance(),
            Err(FormatError::Overflow { .. })
        ));

        let mut prior = statement;
        prior.lines.clear();
        prior.opening_balance = 0;
        prior.closing_balance = 0;
        prior.sequence_number = u64::MAX;
        let mut next = prior.clone();
        next.sequence_number = 0;
        assert!(matches!(
            verify_statement_sequence_continuity(&[prior.clone(), next.clone()]),
            Err(FormatError::Overflow { .. })
        ));
        prior.sequence_number = 0;
        next.sequence_number = 1;
        next.currency = "EUR".to_owned();
        assert!(matches!(
            verify_statement_sequence_continuity(&[prior, next]),
            Err(FormatError::BankContinuity { .. })
        ));
        assert!(matches!(
            parse_mt940_balance("mt940_v1", "D|2026-01-01|USD|-1.00", &units),
            Err(FormatError::Parse { .. })
        ));
    }

    #[test]
    fn legacy_bank_profiles_refuse_multiple_sources_and_partial_transactions() {
        let units = UnitCatalog::embedded().unwrap();
        let bai2 = "02,OWNER,BANK,1,2026-01-31,2359,USD,1/\n\
03,ACCT,USD,010,10000,015,10100/\n\
16,195,100,2026-01-15,REF,Customer/\n";
        assert_eq!(parse_bai2(bai2, &units).unwrap().closing_balance, 10_100);
        for invalid in [
            format!("{bai2}02,OWNER,BANK,1,2026-02-28,2359,USD,2/\n"),
            format!("{bai2}03,OTHER,USD,010,10000,015,10100/\n"),
            format!("{bai2}16,195/\n"),
            format!("{bai2}88,continued-data/\n"),
            bai2.replace("010,10000,015,10100", "010,10000,015,10100,015,10100"),
            bai2.replace("03,ACCT,USD,010,10000,015,10100/\n", ""),
            bai2.replace("16,195,", "16,999,"),
            bai2.replace("16,195,", "49,0/\n16,195,"),
        ] {
            assert!(
                parse_bai2(&invalid, &units).is_err(),
                "accepted BAI2 {invalid}"
            );
        }

        let mt940 = ":20:STATEMENT\n:25:ACCT\n:28C:1/1\n\
:60F:C|2026-01-01|USD|100.00\n\
:61:2026-01-15|C|1.00|REF|Customer\n\
:62F:C|2026-01-31|USD|101.00\n";
        assert_eq!(parse_mt940(mt940, &units).unwrap().closing_balance, 10_100);
        for invalid in [
            format!("{mt940}:25:OTHER\n"),
            format!("{mt940}:28C:2/1\n"),
            format!("{mt940}:60F:C|2026-01-01|USD|100.00\n"),
            format!("{mt940}:62F:C|2026-01-31|USD|101.00\n"),
            format!("{mt940}:62M:C|2026-01-31|USD|101.00\n"),
            format!("{mt940}:61:2026-01-31|C|1.00|LATE\n"),
            mt940.replace(":60F:", ":60M:"),
            mt940.replace(":25:ACCT\n", ""),
            mt940.replace(":28C:1/1\n", ""),
            mt940.replace("2026-01-31|USD|101.00", "2026-01-31|EUR|101.00"),
        ] {
            assert!(
                parse_mt940(&invalid, &units).is_err(),
                "accepted MT940 {invalid}"
            );
        }

        let ofx = "<OFX><TRNUID>1</TRNUID><CURDEF>USD</CURDEF><ACCTID>ACCT</ACCTID>\
<OPENBAL>100.00</OPENBAL>\
<STMTTRN><DTPOSTED>2026-01-15</DTPOSTED><TRNAMT>1.00</TRNAMT><FITID>REF</FITID><NAME>Customer</NAME></STMTTRN>\
<LEDGERBAL><BALAMT>101.00</BALAMT><DTASOF>2026-01-31</DTASOF></LEDGERBAL></OFX>";
        assert_eq!(parse_ofx_qbo(ofx, &units).unwrap().closing_balance, 10_100);
        for extra in [
            "<ACCTID>OTHER</ACCTID>",
            "<CURDEF>EUR</CURDEF>",
            "<OPENBAL>100.00</OPENBAL>",
            "<LEDGERBAL><BALAMT>101.00</BALAMT><DTASOF>2026-01-31</DTASOF></LEDGERBAL>",
            "<TRNUID>2</TRNUID>",
            "<STMTTRN><TRNAMT>1.00</TRNAMT>",
            "</STMTTRN>",
        ] {
            let invalid = ofx.replace("</OFX>", &format!("{extra}</OFX>"));
            assert!(
                parse_ofx_qbo(&invalid, &units).is_err(),
                "accepted OFX {invalid}"
            );
        }
        let duplicate_amount = ofx.replace(
            "<TRNAMT>1.00</TRNAMT>",
            "<TRNAMT>1.00</TRNAMT><TRNAMT>2.00</TRNAMT>",
        );
        assert!(parse_ofx_qbo(&duplicate_amount, &units).is_err());

        let fake_metadata = "<!--<TRNUID>9</TRNUID><CURDEF>EUR</CURDEF><ACCTID>OTHER</ACCTID>\
<OPENBAL>100.00</OPENBAL><LEDGERBAL><BALAMT>999.00</BALAMT><DTASOF>2027-01-31</DTASOF></LEDGERBAL>-->";
        let commented = ofx.replace("<OFX>", &format!("<OFX>{fake_metadata}"));
        assert_eq!(
            parse_ofx_qbo(&commented, &units).unwrap(),
            parse_ofx_qbo(ofx, &units).unwrap()
        );
        let imbalanced = ofx.replace("<OPENBAL>100.00</OPENBAL>", "<OPENBAL>999.00</OPENBAL>");
        let shadowed = imbalanced.replace("<OFX>", &format!("<OFX>{fake_metadata}"));
        assert!(matches!(
            parse_ofx_qbo(&shadowed, &units),
            Err(FormatError::BankContinuity { .. })
        ));

        let encoded = ofx
            .replace("ACCT</ACCTID>", "AC&#67;T</ACCTID>")
            .replace("<TRNAMT>1.00", "<TRNAMT>&#49;.00")
            .replace("<FITID>REF", "<FITID>R&#x45;F");
        assert_eq!(
            parse_ofx_qbo(&encoded, &units).unwrap(),
            parse_ofx_qbo(ofx, &units).unwrap()
        );
        assert!(parse_ofx_qbo(&ofx.replace("Customer", "Customer &unknown;"), &units).is_err());
    }

    const CSV_HEADER: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference";

    fn csv_statement() -> String {
        format!(
            "{CSV_HEADER}\n1,ACCT-001,USD,2026-01-31,0.00,1.00,2026-01-10,2026-01-10,CRDT,1.00,Customer,INV-100\n"
        )
    }

    #[test]
    fn bank_csv_preserves_quoted_fields_and_refuses_ambiguous_layouts() {
        let units = UnitCatalog::embedded().unwrap();
        let csv = format!(
            "\u{feff}{CSV_HEADER}\r\n1,ACCT-001,USD,2026-01-31,0.00,1.00,2026-01-10,2026-01-10,CRDT,1.00,\"Acme, \"\"Ltd\"\"\",\"invoice\n100\"\r\n"
        );
        let statement = parse_bank_csv(&csv, &units).unwrap();
        assert_eq!(statement.lines.len(), 1);
        assert_eq!(statement.lines[0].amount.mantissa, 100);
        assert_eq!(statement.lines[0].counterparty, "Acme, \"Ltd\"");
        assert_eq!(statement.lines[0].reference, "invoice\n100");
        for bad in [
            csv_statement().replace("side,amount", "amount,side"),
            csv_statement().replace("currency,statement_date", "currency,currency"),
            csv_statement().replacen("reference", "reference,ignored", 1),
            csv_statement().replace("Customer,INV-100", "Customer"),
            csv_statement().replace("Customer,INV-100", "Customer,INV-100,"),
            csv_statement().replace("Customer,INV-100", "Customer,INV-100,ignored"),
            csv_statement().replace("Customer,INV-100", "\"Customer,INV-100"),
            csv_statement().replace("Customer,INV-100", "\"Customer\"lost,INV-100"),
            csv_statement().replace("Customer,INV-100", "Cus\"tomer,INV-100"),
            csv_statement().replace("CRDT,1.00", "CRDT,1e0"),
            csv_statement().replace("ACCT-001", ""),
        ] {
            assert!(parse_bank_csv(&bad, &units).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn bank_csv_requires_one_consistent_statement_date() {
        let units = UnitCatalog::embedded().unwrap();
        let csv = format!(
            "{CSV_HEADER}\n1,ACCT-001,USD,2026-01-31,0.00,2.00,2026-01-10,2026-01-10,CRDT,1.00,A,1\n1,ACCT-001,USD,2026-02-28,0.00,2.00,2026-01-10,2026-01-10,CRDT,1.00,B,2\n"
        );
        assert!(matches!(
            parse_bank_csv(&csv, &units),
            Err(FormatError::Parse { detail, .. }) if detail.contains("header")
        ));
    }

    #[test]
    fn bank_csv_mt940_and_camt052_parse_and_verify_continuity() {
        let units = UnitCatalog::embedded().unwrap();

        let csv = "\
sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference
1,ACCT-001,USD,2026-01-31,1000.00,1250.00,2026-01-10,2026-01-10,CRDT,500.00,Acme Customer,INV-100
1,ACCT-001,USD,2026-01-31,1000.00,1250.00,2026-01-15,2026-01-15,DBIT,250.00,Cloud Hosting,BILL-200
";
        let stmt_csv = parse_bank_csv(csv, &units).unwrap();
        assert_eq!(stmt_csv.lines.len(), 2);
        assert_eq!(stmt_csv.opening_balance, 100_000);
        assert_eq!(stmt_csv.closing_balance, 125_000);

        let mt940 = "\
:20:STMT202602
:25:ACCT-001
:28C:2/1
:60F:C|2026-02-01|USD|1250.00
:61:2026-02-05|C|300.00|INV-101|Beta Corp
:61:2026-02-12|D|50.00|FEE-02|Bank Service Fee
:62F:C|2026-02-28|USD|1500.00
";
        let stmt_mt = parse_mt940(mt940, &units).unwrap();
        assert_eq!(stmt_mt.lines.len(), 2);
        assert_eq!(stmt_mt.opening_balance, 125_000);
        assert_eq!(stmt_mt.closing_balance, 150_000);

        verify_statement_sequence_continuity(&[stmt_csv, stmt_mt]).unwrap();

        let camt052 = "\
<BkToCstmrAcctRpt>
  <Rpt>
    <ElctrncSeqNb>3</ElctrncSeqNb>
    <Acct><Id>ACCT-001</Id><Ccy>USD</Ccy></Acct>
    <Bal><Cd>OPBD</Cd><Amt>1500.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt>2026-03-01</Dt></Bal>
    <Bal><Cd>ITBD</Cd><Amt>1425.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt>2026-03-15</Dt></Bal>
    <Ntry>
      <Amt>75.00</Amt><CdtDbtInd>DBIT</CdtDbtInd>
      <BookgDt>2026-03-10</BookgDt><ValDt>2026-03-10</ValDt>
      <AcctSvcrRef>WIRE-301</AcctSvcrRef><Nm>Vendor Co</Nm>
    </Ntry>
  </Rpt>
</BkToCstmrAcctRpt>";
        let stmt_052 = parse_camt052(camt052, &units).unwrap();
        assert_eq!(stmt_052.lines.len(), 1);
        assert_eq!(stmt_052.closing_balance, 142_500);
    }

    const STANDARD_MT940: &str = "\
:20:REAL-STMT-1
:21:RELATED
:25:ACCT-001
:28C:00001/00001
:60F:C251231USD1000,
:61:2601020101CD500,25NTRFINV-100//BANK-001
:86:Acme Customer
Invoice 100
:61:2601050105D100,20FCHGNONREF
:86:Bank fee
:61:260106RCD25,05NTRFRETURN-1
:61:260107RD10,NTRFRETURN-2
:62F:C260131USD1385,
:64:C260131USD1300,
:65:C260202USD1400,
";

    #[test]
    fn swift_mt940_parses_sample() {
        let units = UnitCatalog::embedded().unwrap();
        let statement = parse_mt940(STANDARD_MT940, &units).unwrap();
        assert_eq!(statement.format_name, "swift_mt940");
        assert_eq!(statement.instrument_account_id, "ACCT-001");
        assert_eq!(statement.sequence_number, 1);
        assert_eq!(statement.currency, "USD");
        assert_eq!(statement.statement_date.render(), "2026-01-31");
        assert_eq!(statement.opening_balance, 100_000);
        assert_eq!(statement.closing_balance, 138_500);
        assert_eq!(statement.lines.len(), 4);
        statement.verify_internal_balance().unwrap();
    }

    #[test]
    fn mt940_standard_records_round_trip_through_bank_csv() {
        let units = UnitCatalog::embedded().unwrap();
        let statement = parse_mt940(STANDARD_MT940, &units).unwrap();
        assert_eq!(statement.instrument_account_id, "ACCT-001");
        assert_eq!(statement.sequence_number, 1);
        assert_eq!(statement.currency, "USD");
        assert_eq!(statement.statement_date.render(), "2026-01-31");
        assert_eq!(statement.opening_balance, 100_000);
        assert_eq!(statement.closing_balance, 138_500);
        assert_eq!(statement.lines.len(), 4);
        assert_eq!(statement.lines[0].booking_date.render(), "2026-01-01");
        assert_eq!(statement.lines[0].value_date.render(), "2026-01-02");
        assert_eq!(statement.lines[0].reference, "INV-100//BANK-001");
        assert_eq!(
            statement.lines[0].counterparty,
            "Acme Customer\nInvoice 100"
        );
        assert_eq!(
            statement
                .lines
                .iter()
                .map(|line| (line.side, line.amount.mantissa))
                .collect::<Vec<_>>(),
            vec![
                (Side::Credit, 50_025),
                (Side::Debit, 10_020),
                (Side::Debit, 2_505),
                (Side::Credit, 1_000),
            ]
        );
        assert_eq!(
            parse_mt940(&STANDARD_MT940.replace('\n', "\r\n"), &units).unwrap(),
            statement
        );

        // Exercise every projected field through the independent CSV reader,
        // including quoted multiline narrative and exact integer amounts.
        let decimal = |mantissa: i128| format!("{}.{:02}", mantissa / 100, mantissa % 100);
        let mut csv = format!("{CSV_HEADER}\n");
        for line in &statement.lines {
            let side = if line.side == Side::Credit {
                "CRDT"
            } else {
                "DBIT"
            };
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\"\n",
                statement.sequence_number,
                statement.instrument_account_id,
                statement.currency,
                statement.statement_date.render(),
                decimal(statement.opening_balance),
                decimal(statement.closing_balance),
                line.booking_date.render(),
                line.value_date.render(),
                side,
                decimal(line.amount.mantissa),
                line.counterparty.replace('"', "\"\""),
                line.reference.replace('"', "\"\""),
            ));
        }
        let mut round_trip = parse_bank_csv(&csv, &units).unwrap();
        round_trip.format_name = statement.format_name;
        assert_eq!(round_trip, statement);

        let year_boundary = STANDARD_MT940.replace("2601020101", "2512310101");
        let rolled = parse_mt940(&year_boundary, &units).unwrap();
        assert_eq!(rolled.lines[0].booking_date.render(), "2026-01-01");
        assert_eq!(rolled.lines[0].value_date.render(), "2025-12-31");
    }

    #[test]
    fn mt940_standard_supports_overdrafts_integer_units_and_empty_statements() {
        let units = UnitCatalog::embedded().unwrap();
        let source = "\
:20:JPY-STMT
:25:JPY-ACCOUNT
:28C:1
:60F:D260101JPY100,
:61:260102CY25,S103REF
:62F:D260131JPY75,
";
        let statement = parse_mt940(source, &units).unwrap();
        assert_eq!(statement.opening_balance, -100);
        assert_eq!(statement.closing_balance, -75);
        assert_eq!(statement.lines[0].amount.mantissa, 25);
        assert_eq!(statement.lines[0].side, Side::Credit);
        let empty = source
            .replace(":61:260102CY25,S103REF\n", "")
            .replace("JPY75,", "JPY100,");
        assert!(parse_mt940(&empty, &units).unwrap().lines.is_empty());
        assert!(parse_mt940(&source.replace("25,", "25,0"), &units).is_err());
        assert!(mt940_amount("2,", 38).is_err());
        assert!(mt940_amount("0,", 39).is_err());
    }

    #[test]
    fn mt940_standard_refuses_malformed_ambiguous_and_partial_statements() {
        let units = UnitCatalog::embedded().unwrap();
        let invalid = [
            STANDARD_MT940.replace("2601020101", "2602300101"),
            STANDARD_MT940.replace("2601020101", "2601020230"),
            STANDARD_MT940.replace("2601020101", "260102010"),
            STANDARD_MT940.replace("CD500,25", "CX500,25"),
            STANDARD_MT940.replace("CD500,25", "CD-500,25"),
            STANDARD_MT940.replace("CD500,25", "CD+500,25"),
            STANDARD_MT940.replace("CD500,25", "CD0,"),
            STANDARD_MT940.replace("CD500,25", "CD500,250"),
            STANDARD_MT940.replace("CD500,25", "CD5e2"),
            STANDARD_MT940.replace("CD500,25", "CD500.25"),
            STANDARD_MT940.replace("CD500,25", "CD,25"),
            STANDARD_MT940.replace("CD500,25", "CD5,00,25"),
            STANDARD_MT940.replace("CD500,25", "CD170141183460469231731687303715884105728,"),
            STANDARD_MT940.replace("NTRFINV-100", "QTRFINV-100"),
            STANDARD_MT940.replace("NTRFINV-100", "STRFINV-100"),
            STANDARD_MT940.replace("INV-100//BANK-001", ""),
            STANDARD_MT940.replace("INV-100//BANK-001", "REFERENCE-IS-TOO-LONG"),
            STANDARD_MT940.replace("INV-100//BANK-001", "INV-100//BANK-001//EXTRA"),
            STANDARD_MT940.replace("INV-100//BANK-001", "INV-100//"),
            STANDARD_MT940.replace("C260131USD1385,", "C260131EUR1385,"),
            STANDARD_MT940.replace("C260131USD1385,", "C260131USD1386,"),
            STANDARD_MT940.replace("C251231USD1000,", "C270101USD1000,"),
            STANDARD_MT940.replace("C251231USD1000,", "C250101USD1000,"),
            STANDARD_MT940.replace("C251231USD1000,", "C251231ZZZ1000,"),
            STANDARD_MT940.replace(":20:REAL-STMT-1\n", ""),
            STANDARD_MT940.replace(":28C:00001/00001", ":28C:1/2"),
            STANDARD_MT940.replace(":28C:00001/00001", ":28C:1/1/1"),
            STANDARD_MT940.replace(":28C:00001/00001", ":28C:18446744073709551616"),
            STANDARD_MT940.replace(":60F:", ":60M:"),
            STANDARD_MT940.replace(":62F:", ":62M:"),
            STANDARD_MT940.replace(":62F:C260131USD1385,\n", ""),
            STANDARD_MT940.replace(":61:260102", ":86:ORPHAN\n:61:260102"),
            STANDARD_MT940.replace(":61:260102", ":99:UNKNOWN\n:61:260102"),
            STANDARD_MT940.replace(":61:260102", ":61BROKEN\n:61:260102"),
            STANDARD_MT940.replace("Invoice 100", "1\n2\n3\n4\n5\n6"),
            STANDARD_MT940.replace("Invoice 100", &"x".repeat(66)),
            STANDARD_MT940.replace(":62F:C260131USD1385,", ":62F:C|2026-01-31|USD|1385.00"),
            format!("{STANDARD_MT940}:61:260131C1,NTRFLATE\n"),
            format!("{STANDARD_MT940}:25:OTHER\n"),
            format!("{STANDARD_MT940}{STANDARD_MT940}"),
        ];
        for (index, source) in invalid.into_iter().enumerate() {
            assert!(
                parse_mt940(&source, &units).is_err(),
                "accepted malformed MT940 case {index}: {source}"
            );
        }
        // The continuity rule itself, not another check, refuses a booked
        // closing balance the opening balance and activity do not reach
        // (fa-d22b).
        let unreached = STANDARD_MT940.replace("C260131USD1385,", "C260131USD1386,");
        let refused = parse_mt940(&unreached, &units);
        assert!(
            matches!(refused, Err(FormatError::BankContinuity { .. })),
            "{refused:?}"
        );

        // An equal-and-opposite pair must not disappear just because the
        // statement's booked closing balance is unchanged.
        let balanced_pair = STANDARD_MT940.replace(
            ":62F:",
            ":61:260131C1,NTRFPAIR\n:61:260131D1,NTRFPAIR\n:62F:",
        );
        let statement = parse_mt940(&balanced_pair, &units).unwrap();
        assert_eq!(statement.lines.len(), 6);
        assert_eq!(statement.lines[4].line_ordinal, 5);
        assert_eq!(statement.lines[5].line_ordinal, 6);
        assert_ne!(
            statement.lines[4].line_digest,
            statement.lines[5].line_digest
        );
    }

    /// A standard BAI version 2 file: one 125.00 USD wire credit on the as-of
    /// day, value dated by funds type V. Account control total = 03 amounts
    /// (0 + 12500 + 12500) + the 16 amount (12500) = 37500 over 3 records.
    const STANDARD_BAI2: &str = "01,BANKID,CUSTID,260305,0600,7,,,2/\n\
02,CUSTID,BANKID,1,260305,2359,USD,2/\n\
03,GB29NWBK60161331926819,USD,010,0,,,015,12500,,,100,12500,1,Z/\n\
16,195,12500,V,260305,,WIRE-125,CUST-125,Customer, Co/\n\
49,37500,3/\n\
98,37500,1,5/\n\
99,37500,1,7/\n";

    #[test]
    fn standard_bai2_reads_a_bank_file_with_its_control_totals() {
        let units = UnitCatalog::embedded().unwrap();
        let statement = parse_bai2(STANDARD_BAI2, &units).unwrap();
        assert_eq!(statement.format_name, "bai2_v2");
        assert_eq!(statement.instrument_account_id, "GB29NWBK60161331926819");
        assert_eq!(statement.sequence_number, 7);
        assert_eq!(statement.currency, "USD");
        assert_eq!(statement.statement_date.render(), "2026-03-05");
        assert_eq!(
            (statement.opening_balance, statement.closing_balance),
            (0, 12_500)
        );
        assert_eq!(statement.lines.len(), 1);
        let line = &statement.lines[0];
        assert_eq!(line.side, Side::Credit);
        assert_eq!(line.amount.mantissa, 12_500);
        assert_eq!(line.booking_date.render(), "2026-03-05");
        assert_eq!(line.value_date.render(), "2026-03-05");
        assert_eq!(line.reference, "WIRE-125");
        // The text keeps its comma: it runs to the end of the record.
        assert_eq!(line.counterparty, "Customer, Co");
        // CRLF line ends read the same.
        assert_eq!(
            parse_bai2(&STANDARD_BAI2.replace('\n', "\r\n"), &units).unwrap(),
            statement
        );

        // An 88 continues the 16's text and counts as a record.
        let continued = STANDARD_BAI2
            .replace("Customer, Co/\n", "Customer, Co\n88,Ltd/\n")
            .replace("49,37500,3/", "49,37500,4/")
            .replace("98,37500,1,5/", "98,37500,1,6/")
            .replace("99,37500,1,7/", "99,37500,1,8/");
        let statement = parse_bai2(&continued, &units).unwrap();
        assert_eq!(statement.lines[0].counterparty, "Customer, Co Ltd");

        // Distributed availability (S, D) and a debit with no text: the
        // availability amounts are not control-total amounts.
        let distributed = "01,BANKID,CUSTID,260305,0600,8,,,2/\n\
02,CUSTID,BANKID,1,260305,2359,,2/\n\
03,ACCT-1,,010,10000,,,015,7500,,/\n\
16,175,1000,S,1000,0,0,DEP-1,,Deposit/\n\
16,475,3000,D,2,1,2000,2,1000,CHK-1001,1001/\n\
16,475,500,0,FEE-1,/\n\
49,22000,5/\n\
98,22000,1,7/\n\
99,22000,1,9/\n";
        let statement = parse_bai2(distributed, &units).unwrap();
        assert_eq!(statement.currency, "USD", "a blank currency is USD");
        assert_eq!(
            statement
                .lines
                .iter()
                .map(|l| (l.side, l.amount.mantissa, l.reference.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (Side::Credit, 1_000, "DEP-1"),
                (Side::Debit, 3_000, "CHK-1001"),
                (Side::Debit, 500, "FEE-1"),
            ]
        );
    }

    /// Planted: each integrity rule refuses the file.
    #[test]
    fn standard_bai2_refuses_wrong_totals_counts_classes_and_continuity() {
        let units = UnitCatalog::embedded().unwrap();
        for (what, invalid) in [
            (
                "account control",
                STANDARD_BAI2.replace("49,37500,3/", "49,37501,3/"),
            ),
            (
                "account records",
                STANDARD_BAI2.replace("49,37500,3/", "49,37500,4/"),
            ),
            (
                "group control",
                STANDARD_BAI2.replace("98,37500,1,5/", "98,37400,1,5/"),
            ),
            (
                "group accounts",
                STANDARD_BAI2.replace("98,37500,1,5/", "98,37500,2,5/"),
            ),
            (
                "file records",
                STANDARD_BAI2.replace("99,37500,1,7/", "99,37500,1,8/"),
            ),
            (
                "group status",
                STANDARD_BAI2.replace("02,CUSTID,BANKID,1,", "02,CUSTID,BANKID,4,"),
            ),
            ("version", STANDARD_BAI2.replace(",,,2/\n02", ",,,3/\n02")),
            ("file id", STANDARD_BAI2.replace("0600,7,", "0600,X7,")),
            ("type class", STANDARD_BAI2.replace("16,195,", "16,799,")),
            (
                "funds type",
                STANDARD_BAI2.replace(",V,260305,", ",Q,260305,"),
            ),
            (
                "value date",
                STANDARD_BAI2.replace(",V,260305,", ",V,261305,"),
            ),
            ("closing ledger", STANDARD_BAI2.replace("015,12500,,,", "")),
            (
                "orphan 88",
                STANDARD_BAI2.replace("49,37500,3/\n", "49,37500,3/\n88,more/\n"),
            ),
            (
                "second account",
                STANDARD_BAI2.replace("49,37500,3/\n", "49,37500,3/\n03,OTHER,USD,010,0,,/\n"),
            ),
            ("after trailer", format!("{STANDARD_BAI2}01,AGAIN/\n")),
        ] {
            assert!(
                parse_bai2(&invalid, &units).is_err(),
                "{what}: accepted {invalid}"
            );
        }
        // Opening + details != closing, with totals that agree with the
        // amounts: the continuity rule refuses it.
        let discontinuous = STANDARD_BAI2
            .replace("015,12500,", "015,12400,")
            .replace("49,37500,3/", "49,37400,3/")
            .replace("98,37500,1,5/", "98,37400,1,5/")
            .replace("99,37500,1,7/", "99,37400,1,7/");
        assert!(matches!(
            parse_bai2(&discontinuous, &units),
            Err(FormatError::BankContinuity { .. })
        ));
    }
}
