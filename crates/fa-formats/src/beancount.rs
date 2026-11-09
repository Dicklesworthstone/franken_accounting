//! Beancount v3, hledger, and ledger-cli journal writers, readers, and balance
//! differential oracle (plan §16.3, bead `fa-npi`).
//!
//! No floating-point numbers are permitted; every posting amount and balance
//! assertion is parsed and formatted as an exact fixed-scale `fa_money::Amount`.
//!
//! Source newlines and delimiters are data, never additional directives. Both
//! formats retain unsafe book names in `fa_book_name_hex_v1` comments. Beancount
//! uses standard quoted-string escapes and `fa_memo_hex_v1` posting metadata for
//! control/whitespace-sensitive memos. Hledger's unquoted grammar uses optional
//! `fa_code_hex_v1`, `fa_name_hex_v1`, `fa_entry_id_hex_v1`, and
//! `fa_description_hex_v1` tags; each value is exact UTF-8 encoded as hex.
//! Accounts whose normal balance differs from their type carry the optional
//! `fa_normal_side_v1` tag (`D` or `C`), retaining contra-account semantics.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use fa_model::{AccountType, EntryClass};
use fa_money::{Amount, Side};
use fa_time::DateDay;

mod text;

use self::text::{
    beancount_memo_suffix, escape_quotes, hledger_description, inline_text_metadata,
    write_book_name,
};

use crate::{
    FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal, FormatLeg,
    UnitCatalog, format_account_type, format_date_iso, format_dimension_set, format_exact_decimal,
    hex_decode, hex_encode, normal_side_for_type, parse_account_type, parse_date_iso,
    parse_dimension_set, parse_exact_decimal,
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

/// The account codes behind the names a journal declares. An exported name
/// keeps only letters, digits and dashes (`1000.10` is spelled `A1000-10`),
/// so a leg or an assertion is read through the code its account's `open` or
/// `account` directive carries, never from the name alone.
#[derive(Default)]
struct AccountNames(BTreeMap<String, String>);

impl AccountNames {
    /// `name` stands for `code`. Two codes that export to one name are
    /// refused: their legs could not be told apart.
    fn declare(&mut self, format: &'static str, name: &str, code: &str) -> Result<(), FormatError> {
        match self.0.get(name) {
            Some(other) if other != code => Err(FormatError::Parse {
                format,
                detail: format!(
                    "accounts {other:?} and {code:?} both export to the name {name:?}, which keeps only letters, digits and dashes; give one of them another code"
                ),
            }),
            _ => {
                self.0.insert(name.to_owned(), code.to_owned());
                Ok(())
            }
        }
    }

    /// The code `name` stands for: its declared code, else the code the
    /// name itself spells.
    fn code(&self, name: &str) -> Result<String, FormatError> {
        match self.0.get(name) {
            Some(code) => Ok(code.clone()),
            None => from_beancount_account_name(name),
        }
    }
}

/// Write a `FormatJournal` as a deterministic Beancount v3 journal with
/// coordinate certificate metadata, `open` directives, dated transactions,
/// and `balance` assertions. Refuse dates that the four-digit-year profile
/// cannot represent, including an assertion whose next day is out of range.
pub fn write_beancount(journal: &FormatJournal) -> Result<String, FormatError> {
    let mut out = String::new();
    out.push_str("; FrankenAccounting Beancount v3 export (fa-formats, bead fa-npi)\n");
    write_book_name(&mut out, &journal.coordinate.book_name);
    out.push_str(&format!(
        "; fa_base_unit: {}@{}\n",
        journal.coordinate.base_unit_code, journal.coordinate.base_unit_scale
    ));
    out.push_str(&format!(
        "; fa_effective_through: {}\n",
        beancount_date(journal.coordinate.effective_through, "selection cutoff")?
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

    // Recorded order need not be effective-date order, especially in imported
    // legacy books. Every account must be open before its earliest use.
    let open_day = DateDay(
        journal
            .entries
            .iter()
            .map(|entry| entry.effective_date.0)
            .chain(journal.assertions.iter().map(|assertion| assertion.as_of.0))
            .chain(std::iter::once(0))
            .min()
            .unwrap_or(0),
    );
    let open_date_str = beancount_date(open_day, "account opening")?;
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
        if acct.normal_side != normal_side_for_type(acct.account_type) {
            out.push_str(&format!(
                "  fa_normal_side_v1: \"{}\"\n",
                normal_side_code(acct.normal_side)
            ));
        }
        if !acct.roles.is_empty() {
            out.push_str(&format!("  fa_roles_v1: \"{}\"\n", acct.roles.join(",")));
        }
    }
    out.push('\n');

    for entry in &journal.entries {
        let date_str = beancount_date(entry.effective_date, &format!("entry {}", entry.entry_id))?;
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
            let amt_str = beancount_amount(
                leg.amount,
                leg.side,
                leg.unit_scale,
                &format!("entry {} leg on {}", entry.entry_id, leg.account_code),
            )?;
            out.push_str(&format!(
                "  {bc_acct}  {amt_str} {}{}",
                leg.unit_code,
                beancount_memo_suffix(leg.memo.as_deref())
            ));
            if !leg.dimensions.is_empty() {
                out.push_str(&format!(
                    "    fa_dimensions_v1: \"{}\"\n",
                    format_dimension_set(&leg.dimensions)
                ));
            }
        }
        out.push('\n');
    }

    for asrt in &journal.assertions {
        // Beancount checks balance at the start of the assertion date, so an
        // inclusive as-of assertion on day D is emitted on D + 1.
        let bc_day = DateDay(
            asrt.as_of
                .0
                .checked_add(1)
                .ok_or_else(|| FormatError::Overflow {
                    format: "beancount_v3",
                    detail: format!(
                        "next day of balance assertion for account {}",
                        asrt.account_code
                    ),
                })?,
        );
        let date_str = beancount_date(
            bc_day,
            &format!("balance assertion for account {}", asrt.account_code),
        )?;
        let acct_ty = acct_type_by_code
            .get(asrt.account_code.as_str())
            .copied()
            .unwrap_or(AccountType::ASSET);
        let bc_acct = to_beancount_account_name(acct_ty, &asrt.account_code);
        let amt_str = beancount_amount(
            asrt.amount,
            asrt.side,
            asrt.unit_scale,
            &format!("balance assertion for account {}", asrt.account_code),
        )?;
        out.push_str(&format!(
            "{date_str} balance {bc_acct} {amt_str} {}\n",
            asrt.unit_code
        ));
    }

    Ok(out)
}

fn beancount_amount(
    amount: Amount,
    side: Side,
    scale: u8,
    context: &str,
) -> Result<String, FormatError> {
    let magnitude = amount.as_leg(side).map_err(|error| FormatError::Parse {
        format: "beancount_v3",
        detail: format!("{context}: {error}"),
    })?;
    let signed = match side {
        Side::Debit => magnitude,
        Side::Credit => magnitude.checked_neg().map_err(|_| FormatError::Overflow {
            format: "beancount_v3",
            detail: format!("signed amount for {context}"),
        })?,
    };
    let mut text = format_exact_decimal(signed.mantissa, scale);
    // The numeric value alone cannot retain the certified side of zero.
    if side == Side::Credit && magnitude.is_zero() {
        text.insert(0, '-');
    }
    Ok(text)
}

fn normal_side_code(side: Side) -> &'static str {
    match side {
        Side::Debit => "D",
        Side::Credit => "C",
    }
}

fn read_normal_side(
    format: &'static str,
    value: &str,
    side: &mut Option<Side>,
) -> Result<(), FormatError> {
    if side.is_some() {
        return Err(FormatError::Parse {
            format,
            detail: "duplicate fa_normal_side_v1 account metadata".into(),
        });
    }
    *side = Some(match value {
        "D" => Side::Debit,
        "C" => Side::Credit,
        _ => {
            return Err(FormatError::Parse {
                format,
                detail: format!("invalid fa_normal_side_v1 {value:?}; expected D or C"),
            });
        }
    });
    Ok(())
}

fn beancount_date(day: DateDay, context: &str) -> Result<String, FormatError> {
    let (year, _, _) = day.ymd();
    if !(0..=9999).contains(&year) {
        return Err(FormatError::Parse {
            format: "beancount_v3",
            detail: format!(
                "{context} date {} is outside the YYYY-MM-DD profile (years 0000 through 9999)",
                format_date_iso(day)
            ),
        });
    }
    Ok(format_date_iso(day))
}

/// Parse a Beancount v3 journal produced by [`write_beancount`] (or conforming
/// to the FrankenAccounting Beancount subset) into an exact `FormatJournal`.
/// Both original content and coordinate-certificate digests are required.
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
    let mut names = AccountNames::default();

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
            } else if let Some(v) = c.strip_prefix("fa_book_name_hex_v1:") {
                book_name = decode_text_hex(FMT, v.trim())?;
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
            parse_date_iso(FMT, tokens[0])?;
            let bc_acct = tokens[2];
            let mut code = from_beancount_account_name(bc_acct)?;
            let mut name = code.clone();
            let mut acct_type = infer_account_type_from_beancount(bc_acct)?;
            let mut normal_side = None;
            let mut roles = Vec::new();
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
                } else if let Some(v) = meta.strip_prefix("fa_normal_side_v1:") {
                    read_normal_side(FMT, &unquote(FMT, v.trim())?, &mut normal_side)?;
                } else if let Some(v) = meta.strip_prefix("fa_roles_v1:") {
                    roles.extend(unquote(FMT, v.trim())?.split(',').map(str::to_owned));
                }
                i += 1;
            }
            names.declare(FMT, bc_acct, &code)?;
            accounts.push(FormatAccount {
                code,
                name,
                account_type: acct_type,
                normal_side: normal_side.unwrap_or_else(|| normal_side_for_type(acct_type)),
                roles,
            });
            continue;
        }

        if tokens.len() >= 5 && tokens[1] == "balance" {
            let bc_day = parse_date_iso(FMT, tokens[0])?;
            let as_of = DateDay(bc_day.0 - 1);
            let acct_code = names.code(tokens[2])?;
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
            let (side, mag) = if signed > 0 || (signed == 0 && !amt_tok.starts_with('-')) {
                (Side::Debit, signed)
            } else {
                (
                    Side::Credit,
                    signed.checked_neg().ok_or_else(|| FormatError::Overflow {
                        format: FMT,
                        detail: format!("balance assertion magnitude for account {acct_code}"),
                    })?,
                )
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
            let mut dimensioned_legs = BTreeSet::new();

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
                } else if let Some(v) = body.strip_prefix("fa_memo_hex_v1:") {
                    let leg: &mut FormatLeg =
                        legs.last_mut().ok_or_else(|| FormatError::Parse {
                            format: FMT,
                            detail: "memo metadata precedes its posting".into(),
                        })?;
                    if !lines[i].starts_with("    ") || leg.memo.is_some() {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: "duplicate or non-posting memo metadata".into(),
                        });
                    }
                    leg.memo = Some(decode_text_hex(FMT, &unquote(FMT, v.trim())?)?);
                } else if let Some(v) = body.strip_prefix("fa_dimensions_v1:") {
                    let ordinal = legs
                        .len()
                        .checked_sub(1)
                        .ok_or_else(|| FormatError::Parse {
                            format: FMT,
                            detail: "dimension metadata precedes its posting".into(),
                        })?;
                    if !lines[i].starts_with("    ") || !dimensioned_legs.insert(ordinal) {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: "duplicate or non-posting dimension metadata".into(),
                        });
                    }
                    let leg: &mut FormatLeg = &mut legs[ordinal];
                    leg.dimensions = parse_dimension_set(&unquote(FMT, v.trim())?)?;
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
                    let acct_code = names.code(p_tokens[0])?;
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
                        dimensions: Vec::new(),
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

    let (Some(exp_content), Some(exp_cert)) = (expected_content_digest, expected_cert_digest)
    else {
        return Err(FormatError::Parse {
            format: FMT,
            detail: "Beancount content and certificate digests must be supplied together".into(),
        });
    };
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
    journal.coordinate.verify(&exp_content)?;
    if journal.coordinate.certificate_digest != exp_cert {
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
    write_book_name(&mut out, &journal.coordinate.book_name);
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
            "account {hl_acct}  ; {} fa_type:{}{}{} {}\n",
            inline_text_metadata("fa_code", &acct.code, true),
            format_account_type(acct.account_type),
            if acct.normal_side == normal_side_for_type(acct.account_type) {
                String::new()
            } else {
                format!(" fa_normal_side_v1:{}", normal_side_code(acct.normal_side))
            },
            if acct.roles.is_empty() {
                String::new()
            } else {
                format!(" fa_roles_v1:{}", acct.roles.join(","))
            },
            inline_text_metadata("fa_name", &acct.name, false)
        ));
    }
    out.push('\n');

    for entry in &journal.entries {
        let date_str = format_date_iso(entry.effective_date);
        let (description, description_metadata) = hledger_description(&entry.description);
        out.push_str(&format!(
            "{date_str} * {description}  ; {} fa_seq:{} fa_class:{}{description_metadata}\n",
            inline_text_metadata("fa_entry_id", &entry.entry_id, true),
            entry.recorded_seq,
            entry.class.0
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
            if leg.dimensions.is_empty() {
                out.push_str(&format!("    {hl_acct}    {amt_str} {}\n", leg.unit_code));
            } else {
                out.push_str(&format!(
                    "    {hl_acct}    {amt_str} {}  ; fa_dimensions_v1:{}\n",
                    leg.unit_code,
                    format_dimension_set(&leg.dimensions)
                ));
            }
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
    let mut names = AccountNames::default();

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
            } else if let Some(v) = c.strip_prefix("fa_book_name_hex_v1:") {
                book_name = decode_text_hex(FMT, v.trim())?;
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
            let mut normal_side = None;
            let mut name = code.clone();
            let mut roles = Vec::new();
            if let Some(c) = comment_opt {
                // fa_name is the final free-text field. Its contents are
                // source evidence, never additional fa_code/fa_type tags.
                let metadata = if let Some((before_name, after_name)) = c.split_once(" fa_name:") {
                    name = after_name.trim().to_owned();
                    before_name
                } else {
                    c
                };
                for tok in metadata.split_whitespace() {
                    if let Some(v) = tok.strip_prefix("fa_code:") {
                        code = v.to_owned();
                    } else if let Some(v) = tok.strip_prefix("fa_code_hex_v1:") {
                        code = decode_text_hex(FMT, v)?;
                    } else if let Some(v) = tok.strip_prefix("fa_name_hex_v1:") {
                        name = decode_text_hex(FMT, v)?;
                    } else if let Some(v) = tok.strip_prefix("fa_type:") {
                        acct_type = parse_account_type(FMT, v)?;
                    } else if let Some(v) = tok.strip_prefix("fa_normal_side_v1:") {
                        read_normal_side(FMT, v, &mut normal_side)?;
                    } else if let Some(v) = tok.strip_prefix("fa_roles_v1:") {
                        roles.extend(v.split(',').map(str::to_owned));
                    }
                }
            }
            names.declare(FMT, acct_tok, &code)?;
            accounts.push(FormatAccount {
                code,
                name,
                account_type: acct_type,
                normal_side: normal_side.unwrap_or_else(|| normal_side_for_type(acct_type)),
                roles,
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
            let mut description = header_main
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
                    } else if let Some(v) = tok.strip_prefix("fa_entry_id_hex_v1:") {
                        entry_id = decode_text_hex(FMT, v)?;
                    } else if let Some(v) = tok.strip_prefix("fa_description_hex_v1:") {
                        description = decode_text_hex(FMT, v)?;
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
                let dimensions = match body.split_once(';') {
                    Some((_, comment)) => match comment.trim().strip_prefix("fa_dimensions_v1:") {
                        Some(value) => parse_dimension_set(value)?,
                        None => Vec::new(),
                    },
                    None => Vec::new(),
                };
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
                let acct_code = names.code(p_tokens[0])?;
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
                    dimensions,
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
    // ubs:ignore — a presence probe of a caller-named oracle binary; argv only, no shell.
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

fn decode_text_hex(format: &'static str, text: &str) -> Result<String, FormatError> {
    text::decode_text_hex(text).map_err(|detail| FormatError::Parse { format, detail })
}

fn unquote(format: &'static str, text: &str) -> Result<String, FormatError> {
    text::unquote(text).map_err(|detail| FormatError::Parse { format, detail })
}
