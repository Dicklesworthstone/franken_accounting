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

/// Parse an ISO 20022 `camt.052` intraday account report XML (`BkToCstmrAcctRpt` / `Rpt`)
/// into a [`BankStatementExtract`] (plan §9.5, §15.9; bead `fa-2ek`).
pub fn parse_camt052(xml: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "iso20022_camt052";
    let rpt_block = extract_first_block(FMT, xml, "Rpt")?;
    let seq: u64 = extract_first_block(FMT, rpt_block, "ElctrncSeqNb")?
        .trim()
        .parse()
        .map_err(|_| FormatError::Parse {
            format: FMT,
            detail: "invalid ElctrncSeqNb".to_owned(),
        })?;
    let acct_block = extract_first_block(FMT, rpt_block, "Acct")?;
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

    for bal_block in extract_all_blocks(rpt_block, "Bal") {
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
            "CLBD" | "ITBD" => {
                closing_balance = Some(signed);
                statement_date = dt;
            }
            _ => {}
        }
    }

    let opening_balance = opening_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing OPBD balance in camt.052".to_owned(),
    })?;
    let closing_balance = closing_balance.ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "missing CLBD/ITBD balance in camt.052".to_owned(),
    })?;

    let mut lines = Vec::new();
    for (idx, ntry) in extract_all_blocks(rpt_block, "Ntry")
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
pub fn parse_mt940(text: &str, units: &UnitCatalog) -> Result<BankStatementExtract, FormatError> {
    const FMT: &str = "swift_mt940";
    let mut instrument_id = String::new();
    let mut seq = 1u64;
    let mut currency = String::new();
    let mut statement_date = DateDay(0);
    let mut opening_balance: Option<i128> = None;
    let mut closing_balance: Option<i128> = None;
    let mut lines: Vec<ParsedBankLine> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix(":25:") {
            instrument_id = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix(":28C:") {
            let num_part = rest.split('/').next().unwrap_or(rest).trim();
            seq = num_part.parse().map_err(|_| FormatError::Parse {
                format: FMT,
                detail: format!("invalid :28C: sequence {rest:?}"),
            })?;
        } else if let Some(rest) = line.strip_prefix(":60F:") {
            let (dt, ccy, signed) = parse_mt940_balance(FMT, rest, units)?;
            currency = ccy;
            statement_date = dt;
            opening_balance = Some(signed);
        } else if let Some(rest) = line.strip_prefix(":62F:") {
            let (dt, ccy, signed) = parse_mt940_balance(FMT, rest, units)?;
            if currency.is_empty() {
                currency = ccy;
            }
            statement_date = dt;
            closing_balance = Some(signed);
        } else if let Some(rest) = line.strip_prefix(":61:") {
            // Format: YYYY-MM-DD|C|D|<amount>|<reference>|<counterparty>
            let parts: Vec<&str> = rest.split('|').map(str::trim).collect();
            if parts.len() < 4 {
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
        }
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
    let signed = match parts[0] {
        "C" => mag,
        "D" => -mag,
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
