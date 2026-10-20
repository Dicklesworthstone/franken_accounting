//! Beancount v3, hledger, and ledger-cli journal writers, readers, and balance
//! differential oracle (plan §16.3, bead `fa-npi`).
//!
//! No floating-point numbers are permitted; every posting amount and balance
//! assertion is parsed and formatted as an exact fixed-scale `fa_money::Amount`.

use std::collections::BTreeMap;
use std::process::Command;

use fa_model::{AccountType, EntryClass};
use fa_money::{Amount, Side};
use fa_time::DateDay;

use crate::{
    FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal, FormatLeg,
    UnitCatalog, format_account_type, format_date_iso, format_exact_decimal, hex_decode,
    hex_encode, normal_side_for_type, parse_account_type, parse_date_iso, parse_exact_decimal,
};

/// Map a FrankenAccounting `AccountType` to one of Beancount's 5 root account
/// categories (`Assets`, `Liabilities`, `Equity`, `Income`, `Expenses`).
pub fn beancount_root(account_type: AccountType) -> &'static str {
    match account_type {
        AccountType::LIABILITY => "Liabilities",
        AccountType::EQUITY => "Equity",
        AccountType::REVENUE => "Income",
        AccountType::EXPENSE => "Expenses",
        _ => "Assets",
    }
}

/// Format an account as a valid Beancount v3 colon-separated account name
/// (`<Root>:A<code>`).
pub fn to_beancount_account_name(account_type: AccountType, code: &str) -> String {
    let clean: String = code
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{}:A{}", beancount_root(account_type), clean)
}

/// Extract the canonical FrankenAccounting account `code` from a Beancount
/// account name `<Root>:A<code>`.
pub fn from_beancount_account_name(name: &str) -> Result<String, FormatError> {
    let (_, leaf) = name.split_once(":A").ok_or_else(|| FormatError::Parse {
        format: "beancount_v3",
        detail: format!("invalid Beancount account name {name:?} (expected <Root>:A<code>)"),
    })?;
    if leaf.is_empty() {
        return Err(FormatError::Parse {
            format: "beancount_v3",
            detail: format!("empty account code in {name:?}"),
        });
    }
    Ok(leaf.to_owned())
}

/// Write a `FormatJournal` as a deterministic Beancount v3 journal with
/// coordinate certificate metadata, `open` directives, dated transactions,
/// and `balance` assertions.
pub fn write_beancount(journal: &FormatJournal) -> String {
    let mut out = String::new();
    out.push_str("; FrankenAccounting Beancount v3 export (fa-formats, bead fa-npi)\n");
    out.push_str(&format!(
        "; fa_book_name: {}\n",
        journal.coordinate.book_name
    ));
    out.push_str(&format!(
        "; fa_base_unit: {}@{}\n",
        journal.coordinate.base_unit_code, journal.coordinate.base_unit_scale
    ));
    out.push_str(&format!(
        "; fa_effective_through: {}\n",
        format_date_iso(journal.coordinate.effective_through)
    ));
    out.push_str(&format!(
        "; fa_known_at_seq: {}\n",
        journal.coordinate.known_at_seq
    ));
    out.push_str(&format!(
        "; fa_content_digest: {}\n",
        hex_encode(&journal.coordinate.content_digest)
    ));
    out.push_str(&format!(
        "; fa_certificate_digest: {}\n",
        hex_encode(&journal.coordinate.certificate_digest)
    ));
    out.push_str(&format!(
        "option \"title\" \"{}\"\n",
        escape_quotes(&journal.coordinate.book_name)
    ));
    out.push_str(&format!(
        "option \"operating_currency\" \"{}\"\n\n",
        journal.coordinate.base_unit_code
    ));

    let open_day = journal
        .entries
        .first()
        .map_or(DateDay(0), |e| DateDay(e.effective_date.0.min(0)));
    let open_date_str = format_date_iso(open_day);
    let mut acct_type_by_code = BTreeMap::new();
    for acct in &journal.accounts {
        acct_type_by_code.insert(acct.code.as_str(), acct.account_type);
        let bc_acct = to_beancount_account_name(acct.account_type, &acct.code);
        out.push_str(&format!("{open_date_str} open {bc_acct}\n"));
        out.push_str(&format!(
            "  fa_code: \"{}\"\n  fa_name: \"{}\"\n  fa_type: \"{}\"\n",
            escape_quotes(&acct.code),
            escape_quotes(&acct.name),
            format_account_type(acct.account_type),
        ));
    }
    out.push('\n');

    for entry in &journal.entries {
        let date_str = format_date_iso(entry.effective_date);
        out.push_str(&format!(
            "{date_str} * \"{}\"\n",
            escape_quotes(&entry.description)
        ));
        out.push_str(&format!(
            "  fa_entry_id: \"{}\"\n",
            escape_quotes(&entry.entry_id)
        ));
        out.push_str(&format!("  fa_recorded_seq: {}\n", entry.recorded_seq));
        out.push_str(&format!("  fa_class: {}\n", entry.class.0));
        if let Some(mig) = &entry.migrated_from {
            out.push_str(&format!("  fa_migrated_from: \"{}\"\n", escape_quotes(mig)));
        }
        for leg in &entry.legs {
            let acct_ty = acct_type_by_code
                .get(leg.account_code.as_str())
                .copied()
                .unwrap_or(AccountType::ASSET);
            let bc_acct = to_beancount_account_name(acct_ty, &leg.account_code);
            let signed_mantissa = match leg.side {
                Side::Debit => leg.amount.mantissa,
                Side::Credit => -leg.amount.mantissa,
            };
            let amt_str = format_exact_decimal(signed_mantissa, leg.unit_scale);
            match &leg.memo {
                Some(memo) => {
                    out.push_str(&format!(
                        "  {bc_acct}  {amt_str} {} ; memo:{}\n",
                        leg.unit_code, memo
                    ));
                }
                None => {
                    out.push_str(&format!("  {bc_acct}  {amt_str} {}\n", leg.unit_code));
                }
            }
        }
        out.push('\n');
    }

    for asrt in &journal.assertions {
        // Beancount checks balance at the start of the assertion date, so an
        // inclusive as-of assertion on day D is emitted on D + 1.
        let bc_day = DateDay(asrt.as_of.0 + 1);
        let date_str = format_date_iso(bc_day);
        let acct_ty = acct_type_by_code
            .get(asrt.account_code.as_str())
            .copied()
            .unwrap_or(AccountType::ASSET);
        let bc_acct = to_beancount_account_name(acct_ty, &asrt.account_code);
        let signed = match asrt.side {
            Side::Debit => asrt.amount.mantissa,
            Side::Credit => -asrt.amount.mantissa,
        };
        let amt_str = format_exact_decimal(signed, asrt.unit_scale);
        out.push_str(&format!(
            "{date_str} balance {bc_acct} {amt_str} {}\n",
            asrt.unit_code
        ));
    }

    out
}

/// Parse a Beancount v3 journal produced by [`write_beancount`] (or conforming
/// to the FrankenAccounting Beancount subset) into an exact `FormatJournal`.
pub fn read_beancount(text: &str, units: &UnitCatalog) -> Result<FormatJournal, FormatError> {
    const FMT: &str = "beancount_v3";
    let mut book_name = String::from("beancount-import");
    let mut base_unit_code = String::from("USD");
    let mut base_unit_scale = 2u8;
    let mut effective_through = DateDay(0);
    let mut known_at_seq = 0u64;
    let mut expected_content_digest: Option<[u8; 32]> = None;
    let mut expected_cert_digest: Option<[u8; 32]> = None;

    let mut accounts: Vec<FormatAccount> = Vec::new();
    let mut entries: Vec<FormatEntry> = Vec::new();
    let mut assertions: Vec<FormatAssertion> = Vec::new();

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let raw = lines[i];
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            i += 1;
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix(';') {
            let c = comment.trim();
            if let Some(v) = c.strip_prefix("fa_book_name:") {
                book_name = v.trim().to_owned();
            } else if let Some(v) = c.strip_prefix("fa_base_unit:") {
                if let Some((code, scale_s)) = v.trim().split_once('@') {
                    base_unit_code = code.trim().to_owned();
                    base_unit_scale = scale_s.trim().parse().map_err(|_| FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid fa_base_unit scale in {c:?}"),
                    })?;
                }
            } else if let Some(v) = c.strip_prefix("fa_effective_through:") {
                effective_through = parse_date_iso(FMT, v.trim())?;
            } else if let Some(v) = c.strip_prefix("fa_known_at_seq:") {
                known_at_seq = v.trim().parse().map_err(|_| FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid fa_known_at_seq in {c:?}"),
                })?;
            } else if let Some(v) = c.strip_prefix("fa_content_digest:") {
                expected_content_digest = Some(hex_decode(FMT, v.trim())?);
            } else if let Some(v) = c.strip_prefix("fa_certificate_digest:") {
                expected_cert_digest = Some(hex_decode(FMT, v.trim())?);
            }
            i += 1;
            continue;
        }
        if trimmed.starts_with("option ") {
            i += 1;
            continue;
        }

        // Top-level directive starts with YYYY-MM-DD
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() >= 3 && tokens[1] == "open" {
            let bc_acct = tokens[2];
            let mut code = from_beancount_account_name(bc_acct)?;
            let mut name = code.clone();
            let mut acct_type = infer_account_type_from_beancount(bc_acct)?;
            i += 1;
            while i < lines.len() && (lines[i].starts_with("  ") || lines[i].starts_with('\t')) {
                let meta = lines[i].trim();
                if let Some(v) = meta.strip_prefix("fa_code:") {
                    code = unquote(FMT, v.trim())?;
                } else if let Some(v) = meta.strip_prefix("fa_name:") {
                    name = unquote(FMT, v.trim())?;
                } else if let Some(v) = meta.strip_prefix("fa_type:") {
                    let t_str = unquote(FMT, v.trim())?;
                    acct_type = parse_account_type(FMT, &t_str)?;
                }
                i += 1;
            }
            accounts.push(FormatAccount {
                code,
                name,
                account_type: acct_type,
                normal_side: normal_side_for_type(acct_type),
            });
            continue;
        }

        if tokens.len() >= 5 && tokens[1] == "balance" {
            let bc_day = parse_date_iso(FMT, tokens[0])?;
            let as_of = DateDay(bc_day.0 - 1);
            let acct_code = from_beancount_account_name(tokens[2])?;
            let amt_tok = tokens[3];
            let unit_code = tokens[4].to_owned();
            let (unit_id, unit_scale) =
                units
                    .lookup_code(&unit_code)
                    .ok_or_else(|| FormatError::UnknownUnit {
                        format: FMT,
                        unit: unit_code.clone(),
                    })?;
            let signed = parse_exact_decimal(FMT, amt_tok, unit_scale)?;
            let (side, mag) = if signed >= 0 {
                (Side::Debit, signed)
            } else {
                (Side::Credit, -signed)
            };
            assertions.push(FormatAssertion {
                account_code: acct_code,
                as_of,
                side,
                amount: Amount::new(unit_id, mag),
                unit_code,
                unit_scale,
            });
            i += 1;
            continue;
        }

        if tokens.len() >= 3 && (tokens[1] == "*" || tokens[1] == "!") {
            let eff_date = parse_date_iso(FMT, tokens[0])?;
            if eff_date > effective_through {
                effective_through = eff_date;
            }
            let desc_part = trimmed
                .splitn(3, char::is_whitespace)
                .nth(2)
                .unwrap_or("\"\"");
            let description = unquote(FMT, desc_part.trim())?;
            let mut entry_id = format!("BC-{}", entries.len() + 1);
            let mut recorded_seq = (entries.len() as u64) + 1;
            let mut class = EntryClass::ORIGINAL;
            let mut migrated_from = None;
            let mut legs = Vec::new();

            i += 1;
            while i < lines.len() && (lines[i].starts_with("  ") || lines[i].starts_with('\t')) {
                let body = lines[i].trim();
                if body.is_empty() {
                    break;
                }
                if let Some(v) = body.strip_prefix("fa_entry_id:") {
                    entry_id = unquote(FMT, v.trim())?;
                } else if let Some(v) = body.strip_prefix("fa_recorded_seq:") {
                    recorded_seq = v.trim().parse().map_err(|_| FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid fa_recorded_seq {v:?}"),
                    })?;
                } else if let Some(v) = body.strip_prefix("fa_class:") {
                    let tag: u16 = v.trim().parse().map_err(|_| FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid fa_class {v:?}"),
                    })?;
                    class = EntryClass(tag);
                } else if let Some(v) = body.strip_prefix("fa_migrated_from:") {
                    migrated_from = Some(unquote(FMT, v.trim())?);
                } else {
                    let (posting_part, memo) = match body.split_once("; memo:") {
                        Some((p, m)) => (p.trim(), Some(m.trim().to_owned())),
                        None => (body.split(';').next().unwrap_or(body).trim(), None),
                    };
                    let p_tokens: Vec<&str> = posting_part.split_whitespace().collect();
                    if p_tokens.len() != 3 {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: format!(
                                "invalid posting line {body:?} (expected <Account> <Amount> <Unit>)"
                            ),
                        });
                    }
                    let acct_code = from_beancount_account_name(p_tokens[0])?;
                    let amt_tok = p_tokens[1];
                    let unit_code = p_tokens[2].to_owned();
                    let (unit_id, unit_scale) =
                        units
                            .lookup_code(&unit_code)
                            .ok_or_else(|| FormatError::UnknownUnit {
                                format: FMT,
                                unit: unit_code.clone(),
                            })?;
                    let signed = parse_exact_decimal(FMT, amt_tok, unit_scale)?;
                    if signed == 0 {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: format!("zero-amount leg on {acct_code} is forbidden"),
                        });
                    }
                    let (side, mag) = if signed > 0 {
                        (Side::Debit, signed)
                    } else {
                        (Side::Credit, -signed)
                    };
                    legs.push(FormatLeg {
                        account_code: acct_code,
                        side,
                        amount: Amount::new(unit_id, mag),
                        unit_code,
                        unit_scale,
                        memo,
                    });
                }
                i += 1;
            }
            entries.push(FormatEntry {
                entry_id,
                effective_date: eff_date,
                recorded_seq,
                class,
                description,
                migrated_from,
                legs,
            });
            continue;
        }

        return Err(FormatError::Parse {
            format: FMT,
            detail: format!("unrecognized Beancount directive {trimmed:?}"),
        });
    }

    let journal = FormatJournal::new(
        &book_name,
        &base_unit_code,
        base_unit_scale,
        effective_through,
        known_at_seq,
        accounts,
        entries,
        assertions,
    )?;
    if let Some(exp_content) = expected_content_digest {
        journal.coordinate.verify(&exp_content)?;
    }
    if let Some(exp_cert) = expected_cert_digest
        && journal.coordinate.certificate_digest != exp_cert
    {
        return Err(FormatError::CertificateMismatch {
            format: FMT,
            expected_hex: hex_encode(&exp_cert),
            observed_hex: hex_encode(&journal.coordinate.certificate_digest),
        });
    }
    Ok(journal)
}

/// Write a `FormatJournal` as a deterministic `hledger` / `ledger-cli` journal.
pub fn write_hledger(journal: &FormatJournal) -> String {
    let mut out = String::new();
    out.push_str("; FrankenAccounting hledger export (fa-formats, bead fa-npi)\n");
    out.push_str(&format!(
        "; fa_book_name: {}\n",
        journal.coordinate.book_name
    ));
    out.push_str(&format!(
        "; fa_base_unit: {}@{}\n",
        journal.coordinate.base_unit_code, journal.coordinate.base_unit_scale
    ));
    out.push_str(&format!(
        "; fa_effective_through: {}\n",
        format_date_iso(journal.coordinate.effective_through)
    ));
    out.push_str(&format!(
        "; fa_known_at_seq: {}\n",
        journal.coordinate.known_at_seq
    ));
    out.push_str(&format!(
        "; fa_content_digest: {}\n",
        hex_encode(&journal.coordinate.content_digest)
    ));
    out.push_str(&format!(
        "; fa_certificate_digest: {}\n\n",
        hex_encode(&journal.coordinate.certificate_digest)
    ));

    let mut acct_type_by_code = BTreeMap::new();
    for acct in &journal.accounts {
        acct_type_by_code.insert(acct.code.as_str(), acct.account_type);
        let hl_acct = to_beancount_account_name(acct.account_type, &acct.code);
        out.push_str(&format!(
            "account {hl_acct}  ; fa_code:{} fa_type:{} fa_name:{}\n",
            acct.code,
            format_account_type(acct.account_type),
            acct.name
        ));
    }
    out.push('\n');

    for entry in &journal.entries {
        let date_str = format_date_iso(entry.effective_date);
        out.push_str(&format!(
            "{date_str} * {}  ; fa_entry_id:{} fa_seq:{} fa_class:{}\n",
            entry.description, entry.entry_id, entry.recorded_seq, entry.class.0
        ));
        for leg in &entry.legs {
            let acct_ty = acct_type_by_code
                .get(leg.account_code.as_str())
                .copied()
                .unwrap_or(AccountType::ASSET);
            let hl_acct = to_beancount_account_name(acct_ty, &leg.account_code);
            let signed_mantissa = match leg.side {
                Side::Debit => leg.amount.mantissa,
                Side::Credit => -leg.amount.mantissa,
            };
            let amt_str = format_exact_decimal(signed_mantissa, leg.unit_scale);
            out.push_str(&format!("    {hl_acct}    {amt_str} {}\n", leg.unit_code));
        }
        out.push('\n');
    }
    out
}

/// Parse an `hledger` journal produced by [`write_hledger`] into an exact `FormatJournal`.
pub fn read_hledger(text: &str, units: &UnitCatalog) -> Result<FormatJournal, FormatError> {
    const FMT: &str = "hledger_journal";
    let mut book_name = String::from("hledger-import");
    let mut base_unit_code = String::from("USD");
    let mut base_unit_scale = 2u8;
    let mut effective_through = DateDay(0);
    let mut known_at_seq = 0u64;

    let mut accounts: Vec<FormatAccount> = Vec::new();
    let mut entries: Vec<FormatEntry> = Vec::new();

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() {
            i += 1;
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix(';') {
            let c = comment.trim();
            if let Some(v) = c.strip_prefix("fa_book_name:") {
                book_name = v.trim().to_owned();
            } else if let Some(v) = c.strip_prefix("fa_base_unit:") {
                if let Some((code, scale_s)) = v.trim().split_once('@') {
                    base_unit_code = code.trim().to_owned();
                    base_unit_scale = scale_s.trim().parse().map_err(|_| FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid fa_base_unit in {c:?}"),
                    })?;
                }
            } else if let Some(v) = c.strip_prefix("fa_effective_through:") {
                effective_through = parse_date_iso(FMT, v.trim())?;
            } else if let Some(v) = c.strip_prefix("fa_known_at_seq:") {
                known_at_seq = v.trim().parse().map_err(|_| FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid fa_known_at_seq in {c:?}"),
                })?;
            }
            i += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("account ") {
            let (acct_tok, comment_opt) = match rest.split_once(';') {
                Some((a, c)) => (a.trim(), Some(c.trim())),
                None => (rest.trim(), None),
            };
            let mut code = from_beancount_account_name(acct_tok)?;
            let mut acct_type = infer_account_type_from_beancount(acct_tok)?;
            let mut name = code.clone();
            if let Some(c) = comment_opt {
                if let Some((_, after_name)) = c.split_once("fa_name:") {
                    name = after_name.trim().to_owned();
                }
                for tok in c.split_whitespace() {
                    if let Some(v) = tok.strip_prefix("fa_code:") {
                        code = v.to_owned();
                    } else if let Some(v) = tok.strip_prefix("fa_type:") {
                        acct_type = parse_account_type(FMT, v)?;
                    }
                }
            }
            accounts.push(FormatAccount {
                code,
                name,
                account_type: acct_type,
                normal_side: normal_side_for_type(acct_type),
            });
            i += 1;
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() >= 2 && (tokens[1] == "*" || tokens[1] == "!") {
            let eff_date = parse_date_iso(FMT, tokens[0])?;
            if eff_date > effective_through {
                effective_through = eff_date;
            }
            let (header_main, comment_opt) = match trimmed.split_once(';') {
                Some((h, c)) => (h.trim(), Some(c.trim())),
                None => (trimmed, None),
            };
            let description = header_main
                .splitn(3, char::is_whitespace)
                .nth(2)
                .unwrap_or("")
                .trim()
                .to_owned();
            let mut entry_id = format!("HL-{}", entries.len() + 1);
            let mut recorded_seq = (entries.len() as u64) + 1;
            let mut class = EntryClass::ORIGINAL;
            if let Some(c) = comment_opt {
                for tok in c.split_whitespace() {
                    if let Some(v) = tok.strip_prefix("fa_entry_id:") {
                        entry_id = v.to_owned();
                    } else if let Some(v) = tok.strip_prefix("fa_seq:") {
                        recorded_seq = v.parse().map_err(|_| FormatError::Parse {
                            format: FMT,
                            detail: format!("invalid fa_seq {v:?}"),
                        })?;
                    } else if let Some(v) = tok.strip_prefix("fa_class:") {
                        let tag: u16 = v.parse().map_err(|_| FormatError::Parse {
                            format: FMT,
                            detail: format!("invalid fa_class {v:?}"),
                        })?;
                        class = EntryClass(tag);
                    }
                }
            }

            let mut legs = Vec::new();
            i += 1;
            while i < lines.len() && (lines[i].starts_with("  ") || lines[i].starts_with('\t')) {
                let body = lines[i].trim();
                if body.is_empty() {
                    break;
                }
                let p_tokens: Vec<&str> = body
                    .split(';')
                    .next()
                    .unwrap_or(body)
                    .split_whitespace()
                    .collect();
                if p_tokens.len() != 3 {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid hledger posting line {body:?}"),
                    });
                }
                let acct_code = from_beancount_account_name(p_tokens[0])?;
                let amt_tok = p_tokens[1];
                let unit_code = p_tokens[2].to_owned();
                let (unit_id, unit_scale) =
                    units
                        .lookup_code(&unit_code)
                        .ok_or_else(|| FormatError::UnknownUnit {
                            format: FMT,
                            unit: unit_code.clone(),
                        })?;
                let signed = parse_exact_decimal(FMT, amt_tok, unit_scale)?;
                if signed == 0 {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("zero-amount leg on {acct_code} is forbidden"),
                    });
                }
                let (side, mag) = if signed > 0 {
                    (Side::Debit, signed)
                } else {
                    (Side::Credit, -signed)
                };
                legs.push(FormatLeg {
                    account_code: acct_code,
                    side,
                    amount: Amount::new(unit_id, mag),
                    unit_code,
                    unit_scale,
                    memo: None,
                });
                i += 1;
            }
            entries.push(FormatEntry {
                entry_id,
                effective_date: eff_date,
                recorded_seq,
                class,
                description,
                migrated_from: None,
                legs,
            });
            continue;
        }

        return Err(FormatError::Parse {
            format: FMT,
            detail: format!("unrecognized hledger line {trimmed:?}"),
        });
    }

    FormatJournal::new(
        &book_name,
        &base_unit_code,
        base_unit_scale,
        effective_through,
        known_at_seq,
        accounts,
        entries,
        Vec::new(),
    )
}

/// Compare FrankenAccounting balances against an external oracle's `(account_code, unit_code) -> signed_mantissa`
/// map cell-by-cell. Any single-minor-unit difference returns `Err(FormatError::DifferentialMismatch)`
/// naming the exact account and unit.
pub fn compare_balances_exact(
    fixture: &str,
    expected: &BTreeMap<(String, String), i128>,
    observed: &BTreeMap<(String, String), i128>,
) -> Result<(), FormatError> {
    let mut all_keys: std::collections::BTreeSet<(String, String)> =
        expected.keys().cloned().collect();
    all_keys.extend(observed.keys().cloned());

    for (acct, unit) in all_keys {
        let exp = expected
            .get(&(acct.clone(), unit.clone()))
            .copied()
            .unwrap_or(0);
        let obs = observed
            .get(&(acct.clone(), unit.clone()))
            .copied()
            .unwrap_or(0);
        if exp != obs {
            return Err(FormatError::DifferentialMismatch {
                fixture: fixture.to_owned(),
                account_code: acct,
                unit_code: unit,
                expected: exp,
                observed: obs,
            });
        }
    }
    Ok(())
}

/// Whether an external plain-text accounting binary (`bean-check` or `hledger`)
/// is available. This is a presence probe only: no status here means a journal
/// was evaluated or a balance compared (that differential is fa-sa4w).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubprocessOracleStatus {
    /// `<binary> --version` succeeded. Nothing was evaluated.
    Present { binary: String, version: String },
    /// Binary is not installed in `PATH`, or `--version` failed.
    Unrun { binary: String, reason: String },
}

/// Probe whether an external plain-text accounting binary is installed.
/// A `Present` result is not a verification of anything.
pub fn probe_external_oracle_binary(binary: &str) -> SubprocessOracleStatus {
    match Command::new(binary).arg("--version").output() {
        Ok(out) if out.status.success() => {
            let ver = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            SubprocessOracleStatus::Present {
                binary: binary.to_owned(),
                version: ver,
            }
        }
        Ok(out) => SubprocessOracleStatus::Unrun {
            binary: binary.to_owned(),
            reason: format!("--version exited with status {}", out.status),
        },
        Err(e) => SubprocessOracleStatus::Unrun {
            binary: binary.to_owned(),
            reason: format!("binary not found or not executable: {e}"),
        },
    }
}

fn infer_account_type_from_beancount(bc_acct: &str) -> Result<AccountType, FormatError> {
    let root = bc_acct.split(':').next().unwrap_or("");
    match root {
        "Assets" => Ok(AccountType::ASSET),
        "Liabilities" => Ok(AccountType::LIABILITY),
        "Equity" => Ok(AccountType::EQUITY),
        "Income" => Ok(AccountType::REVENUE),
        "Expenses" => Ok(AccountType::EXPENSE),
        other => Err(FormatError::Parse {
            format: "beancount_v3",
            detail: format!("unknown Beancount root account category {other:?}"),
        }),
    }
}

fn escape_quotes(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn unquote(format: &'static str, s: &str) -> Result<String, FormatError> {
    let t = s.trim();
    if t.len() < 2 || !t.starts_with('"') || !t.ends_with('"') {
        return Err(FormatError::Parse {
            format,
            detail: format!("expected quoted string, got {t:?}"),
        });
    }
    let inner = &t[1..t.len() - 1];
    Ok(inner.replace("\\\"", "\"").replace("\\\\", "\\"))
}
