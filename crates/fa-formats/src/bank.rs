//! Bank statement parsers (`iso20022_camt053`, `bai2_v2`, `ofx_qbo_v2`) and
//! statement sequence / opening-to-closing balance continuity verification
//! (plan §9.5, §15.3, bead `fa-npi`).

use fa_money::{Amount, Side};
use fa_time::DateDay;
use fgdb_crypto::Hasher;

use crate::{
    FormatError, UnitCatalog, parse_date_iso, parse_exact_decimal,
    saft::{extract_all_blocks, extract_first_block, xml_unescape},
};

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
            let delta = match line.side {
                // On a bank statement from the bank's perspective (or customer cash inflows):
                // Credit (`CRDT`) is a cash inflow (+), Debit (`DBIT`) is a cash outflow (-).
                Side::Credit => line.amount.mantissa,
                Side::Debit => -line.amount.mantissa,
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
        if curr.sequence_number != prev.sequence_number + 1 {
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

/// Parse an ISO 20022 `camt.053` XML statement into a [`BankStatementExtract`].
pub fn parse_camt053(xml: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "iso20022_camt053";
    let stmt_block = extract_first_block(FMT, xml, "Stmt")?;
    let seq: u64 = extract_first_block(FMT, stmt_block, "ElctrncSeqNb")?
        .trim()
        .parse()
        .map_err(|_| FormatError::Parse {
            format: FMT,
            detail: "invalid ElctrncSeqNb".to_owned(),
        })?;
    let acct_block = extract_first_block(FMT, stmt_block, "Acct")?;
    let instrument_id = xml_unescape(extract_first_block(FMT, acct_block, "Id")?);
    let currency = xml_unescape(extract_first_block(FMT, acct_block, "Ccy")?);
    let (unit_id, unit_scale) =
        units
            .lookup_code(&currency)
            .ok_or_else(|| FormatError::UnknownUnit {
                format: FMT,
                unit: currency.clone(),
            })?;

    let mut opening_balance: Option<i128> = None;
    let mut closing_balance: Option<i128> = None;
    let mut statement_date = DateDay(0);

    for bal_block in extract_all_blocks(stmt_block, "Bal") {
        let code = extract_first_block(FMT, bal_block, "Cd")?.trim();
        let amt_str = extract_first_block(FMT, bal_block, "Amt")?.trim();
        let cdt_dbt = extract_first_block(FMT, bal_block, "CdtDbtInd")?.trim();
        let dt_str = extract_first_block(FMT, bal_block, "Dt")?.trim();
        let dt = parse_date_iso(FMT, dt_str)?;
        let mag = parse_exact_decimal(FMT, amt_str, unit_scale)?;
        let signed = match cdt_dbt {
            "CRDT" => mag,
            "DBIT" => -mag,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid CdtDbtInd {other:?}"),
                });
            }
        };
        match code {
            "OPBD" => opening_balance = Some(signed),
            "CLBD" => {
                closing_balance = Some(signed);
                statement_date = dt;
            }
            _ => {}
        }
    }

    let opening_balance = opening_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing OPBD balance in camt.053".to_owned(),
    })?;
    let closing_balance = closing_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing CLBD balance in camt.053".to_owned(),
    })?;

    let mut lines = Vec::new();
    for (idx, ntry) in extract_all_blocks(stmt_block, "Ntry")
        .into_iter()
        .enumerate()
    {
        let ordinal = (idx as u32) + 1;
        let amt_str = extract_first_block(FMT, ntry, "Amt")?.trim();
        let cdt_dbt = extract_first_block(FMT, ntry, "CdtDbtInd")?.trim();
        let side = match cdt_dbt {
            "CRDT" => Side::Credit,
            "DBIT" => Side::Debit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid Ntry CdtDbtInd {other:?}"),
                });
            }
        };
        let booking_date = parse_date_iso(FMT, extract_first_block(FMT, ntry, "BookgDt")?)?;
        let value_date = extract_first_block(FMT, ntry, "ValDt")
            .ok()
            .and_then(|s| parse_date_iso(FMT, s).ok())
            .unwrap_or(booking_date);
        let counterparty = extract_first_block(FMT, ntry, "Nm")
            .map(xml_unescape)
            .unwrap_or_default();
        let reference = extract_first_block(FMT, ntry, "AcctSvcrRef")
            .map(xml_unescape)
            .unwrap_or_default();
        let mantissa = parse_exact_decimal(FMT, amt_str, unit_scale)?;
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

/// Parse a BAI2 cash-management statement (`01`/`02`/`03`/`16`/`49`/`99`) into a
/// [`BankStatementExtract`].
pub fn parse_bai2(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "bai2_v2";
    let mut instrument_id = String::new();
    let mut currency = String::from("USD");
    let mut seq = 1u64;
    let mut statement_date = DateDay(0);
    let mut opening_balance: Option<i128> = None;
    let mut closing_balance: Option<i128> = None;
    let mut lines = Vec::new();

    for raw in text.lines() {
        let clean = raw.trim().trim_end_matches('/');
        if clean.is_empty() {
            continue;
        }
        let fields: Vec<&str> = clean.split(',').collect();
        match fields[0] {
            "02" if fields.len() >= 6 => {
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
            "03" if fields.len() >= 7 => {
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
                        "010" => opening_balance = Some(amt_minor),
                        "015" => closing_balance = Some(amt_minor),
                        _ => {}
                    }
                    idx += 2;
                }
            }
            "16" if fields.len() >= 6 => {
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
                let side = if type_code < 400 {
                    Side::Credit
                } else {
                    Side::Debit
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
            _ => {}
        }
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
pub fn parse_ofx_qbo(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "ofx_qbo_v2";
    let currency = extract_first_block(FMT, text, "CURDEF")?.trim().to_owned();
    let (unit_id, unit_scale) =
        units
            .lookup_code(&currency)
            .ok_or_else(|| FormatError::UnknownUnit {
                format: FMT,
                unit: currency.clone(),
            })?;
    let instrument_id = extract_first_block(FMT, text, "ACCTID")?.trim().to_owned();
    let seq: u64 = extract_first_block(FMT, text, "TRNUID")
        .unwrap_or("1")
        .trim()
        .parse()
        .map_err(|_| FormatError::Parse {
            format: FMT,
            detail: "invalid TRNUID".to_owned(),
        })?;
    let opening_balance = parse_exact_decimal(
        FMT,
        extract_first_block(FMT, text, "OPENBAL")?.trim(),
        unit_scale,
    )?;
    let ledger_bal_block = extract_first_block(FMT, text, "LEDGERBAL")?;
    let closing_balance = parse_exact_decimal(
        FMT,
        extract_first_block(FMT, ledger_bal_block, "BALAMT")?.trim(),
        unit_scale,
    )?;
    let statement_date = parse_date_iso(
        FMT,
        extract_first_block(FMT, ledger_bal_block, "DTASOF")?.trim(),
    )?;

    let mut lines = Vec::new();
    for (idx, trn) in extract_all_blocks(text, "STMTTRN").into_iter().enumerate() {
        let ordinal = (idx as u32) + 1;
        let dt = parse_date_iso(FMT, extract_first_block(FMT, trn, "DTPOSTED")?.trim())?;
        let signed = parse_exact_decimal(
            FMT,
            extract_first_block(FMT, trn, "TRNAMT")?.trim(),
            unit_scale,
        )?;
        let (side, mag) = if signed >= 0 {
            (Side::Credit, signed)
        } else {
            (Side::Debit, -signed)
        };
        let reference = extract_first_block(FMT, trn, "FITID")?.trim().to_owned();
        let counterparty = extract_first_block(FMT, trn, "NAME")
            .unwrap_or("")
            .trim()
            .to_owned();
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
