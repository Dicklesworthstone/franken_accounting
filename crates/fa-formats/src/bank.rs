//! Bank statement parsers (`iso20022_camt053`, `bai2_v2`, `ofx_qbo_v2`) and
//! statement sequence / opening-to-closing balance continuity verification
//! (plan §9.5, §15.3, bead `fa-npi`).

use std::borrow::Cow;

use fa_money::{Amount, Side};
use fa_time::DateDay;
use fgdb_crypto::Hasher;

use crate::{FormatError, UnitCatalog, parse_date_iso, parse_exact_decimal};

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
        if suffix.starts_with("<!--") {
            let end = suffix[4..]
                .find("-->")
                .map(|end| end + 4)
                .ok_or_else(|| camt_error(format, "unterminated bank XML comment"))?;
            if suffix[4..end].contains("--") {
                return Err(camt_error(format, "invalid bank XML comment"));
            }
            cursor = start + end + 3;
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

/// Parse a BAI2 cash-management statement (`01`/`02`/`03`/`16`/`49`/`99`) into a
/// [`BankStatementExtract`]. This bounded profile has one group and one account,
/// ISO civil dates, and comma-separated summary pairs and transaction fields;
/// continuation records and multi-account/group envelopes must be split or
/// converted explicitly before import.
pub fn parse_bai2(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
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
                if !group_seen || account_seen || fields.len() < 7 || (fields.len() - 3) % 2 != 0 {
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
                        "010" => {
                            if opening_balance.replace(amt_minor).is_some() {
                                return Err(camt_error(FMT, "repeated BAI2 opening balance"));
                            }
                        }
                        "015" => {
                            if closing_balance.replace(amt_minor).is_some() {
                                return Err(camt_error(FMT, "repeated BAI2 closing balance"));
                            }
                        }
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
/// Expected header:
/// `sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference`
pub fn parse_bank_csv(csv: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "bank_csv_v1";
    let mut non_empty = csv.lines().map(str::trim).filter(|l| !l.is_empty());
    let Some(header) = non_empty.next() else {
        return Err(FormatError::Parse {
            format: FMT,
            detail: "empty CSV bank statement".to_owned(),
        });
    };
    let cols: Vec<&str> = header.split(',').map(str::trim).collect();
    if cols.len() < 12 || cols[0] != "sequence_number" {
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

    for (idx, line) in non_empty.enumerate() {
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < 12 {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("bank CSV row {} has fewer than 12 columns", idx + 1),
            });
        }
        let row_seq: u64 = fields[0].parse().map_err(|_| FormatError::Parse {
            format: FMT,
            detail: format!("invalid sequence_number {:?}", fields[0]),
        })?;
        let row_inst = fields[1];
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

/// Parse a SWIFT `MT940` statement (`:25:`, `:28C:`, `:60F:`, `:61:`, `:86:`, `:62F:`)
/// into a [`BankStatementExtract`] (plan §9.5, §15.9; bead `fa-2ek`).
/// The bounded profile uses pipe-separated fields and ISO civil dates, with
/// exactly one account, sequence and final opening/closing balance. Intermediate
/// balances and multi-message envelopes require explicit conversion upstream.
pub fn parse_mt940(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
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

fn compute_bank_line_digest(
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
}
