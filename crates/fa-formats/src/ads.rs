//! AICPA Audit Data Standards (ADS) General Ledger package writer and
//! round-trip reader with coordinate certificate and `FA-INV-04` refold
//! verification (plan §8.6, §16.3, bead `fa-npi`).

use std::collections::BTreeMap;

use fa_model::EntryClass;
use fa_money::{Amount, Side};

use crate::{
    ExportCoordinate, FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal,
    FormatLeg, UnitCatalog, format_account_type, format_date_iso, format_exact_decimal, hex_decode,
    hex_encode, parse_account_type, parse_date_iso, parse_exact_decimal,
};

const FMT: &str = "aicpa_ads_gl_v2";
const ESCAPED_FMT: &str = "aicpa_ads_gl_v3";

/// An AICPA Audit Data Standards General Ledger export package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdsPackage {
    /// Pipe-separated `Chart_of_Accounts` table.
    pub chart_of_accounts: String,
    /// Pipe-separated `GL_Detail` table (AICPA ADS GL columns).
    pub gl_detail: String,
    /// Pipe-separated `Trial_Balance` table.
    pub trial_balance: String,
    /// Coordinate certificate (`ADS_Coordinate_Certificate.toml`).
    pub certificate_toml: String,
}

/// Write a [`FormatJournal`] as an AICPA Audit Data Standards [`AdsPackage`].
pub fn write_ads_package(journal: &FormatJournal) -> Result<AdsPackage, FormatError> {
    // v2 has literal fields. Keep its existing bytes only when every field
    // is representable; lossless escaped text is a distinct durable version.
    let unsafe_text = |s: &str| {
        s.chars()
            .any(|c| matches!(c, '|' | '\\' | '"') || c.is_control())
    };
    let escaped = unsafe_text(&journal.coordinate.book_name)
        || unsafe_text(&journal.coordinate.base_unit_code)
        || journal
            .accounts
            .iter()
            .any(|a| unsafe_text(&a.code) || unsafe_text(&a.name))
        || journal.entries.iter().any(|e| {
            unsafe_text(&e.entry_id)
                || unsafe_text(&e.description)
                || e.migrated_from
                    .as_deref()
                    .is_some_and(|s| s.is_empty() || unsafe_text(s))
                || e.legs.iter().any(|l| {
                    unsafe_text(&l.account_code)
                        || unsafe_text(&l.unit_code)
                        || l.memo
                            .as_deref()
                            .is_some_and(|s| s.is_empty() || unsafe_text(s))
                })
        })
        || journal
            .assertions
            .iter()
            .any(|a| unsafe_text(&a.account_code) || unsafe_text(&a.unit_code));
    let text = |s: &str| encode_text(s, escaped);
    let mut chart = String::from("GL_Account_Number|GL_Account_Name|Account_Type|Normal_Balance\n");
    for acct in &journal.accounts {
        let side_str = match acct.normal_side {
            Side::Debit => "D",
            Side::Credit => "C",
        };
        chart.push_str(&format!(
            "{}|{}|{}|{}\n",
            text(&acct.code),
            text(&acct.name),
            format_account_type(acct.account_type),
            side_str
        ));
    }

    let mut gl = String::from(
        "Journal_ID|Journal_Entry_Line_Number|Effective_Date|Recorded_Seq|Entry_Class|GL_Account_Number|Debit_Credit_Indicator|Amount|Transaction_Currency|Unit_Scale|JE_Header_Description|Migrated_From|Line_Description\n",
    );
    for entry in &journal.entries {
        let date_str = format_date_iso(entry.effective_date);
        let mig = optional_text(entry.migrated_from.as_deref(), escaped);
        for (idx, leg) in entry.legs.iter().enumerate() {
            let line_no = idx + 1;
            let dc = match leg.side {
                Side::Debit => "D",
                Side::Credit => "C",
            };
            let amt_str = format_exact_decimal(leg.amount.mantissa, leg.unit_scale);
            let memo = optional_text(leg.memo.as_deref(), escaped);
            gl.push_str(&format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
                text(&entry.entry_id),
                line_no,
                date_str,
                entry.recorded_seq,
                entry.class.0,
                text(&leg.account_code),
                dc,
                amt_str,
                text(&leg.unit_code),
                leg.unit_scale,
                text(&entry.description),
                mig,
                memo,
            ));
        }
    }

    let balances = journal.fold_balances()?;
    let mut tb = String::from(
        "GL_Account_Number|As_Of_Date|Debit_Credit_Indicator|Ending_Balance|Currency|Unit_Scale\n",
    );
    let mut unit_scale_by_code = BTreeMap::new();
    for e in &journal.entries {
        for l in &e.legs {
            unit_scale_by_code.insert(l.unit_code.clone(), l.unit_scale);
        }
    }
    for a in &journal.assertions {
        unit_scale_by_code.insert(a.unit_code.clone(), a.unit_scale);
    }

    if !journal.assertions.is_empty() {
        for asrt in &journal.assertions {
            let dc = match asrt.side {
                Side::Debit => "D",
                Side::Credit => "C",
            };
            let amt_str = format_exact_decimal(asrt.amount.mantissa, asrt.unit_scale);
            tb.push_str(&format!(
                "{}|{}|{}|{}|{}|{}\n",
                text(&asrt.account_code),
                format_date_iso(asrt.as_of),
                dc,
                amt_str,
                text(&asrt.unit_code),
                asrt.unit_scale
            ));
        }
    } else {
        for ((acct_code, unit_code), signed_bal) in &balances {
            // A scoped extract's contra legs are context, not balances.
            if journal
                .coordinate
                .account_scope
                .as_ref()
                .is_some_and(|code| code != acct_code)
            {
                continue;
            }
            let scale = unit_scale_by_code.get(unit_code).copied().unwrap_or(2);
            let (dc, mag) = if *signed_bal >= 0 {
                ("D", *signed_bal)
            } else {
                ("C", -*signed_bal)
            };
            let amt_str = format_exact_decimal(mag, scale);
            tb.push_str(&format!(
                "{}|{}|{}|{}|{}|{}\n",
                text(acct_code),
                format_date_iso(journal.coordinate.effective_through),
                dc,
                amt_str,
                text(unit_code),
                scale
            ));
        }
    }

    // Hex metadata is ordinary TOML ASCII and preserves *all* UTF-8 names,
    // including control characters the registry's small TOML reader omits.
    let (format, book_key, unit_key, book_name, unit_code) = if escaped {
        (
            ESCAPED_FMT,
            "book_name_utf8_hex",
            "base_unit_code_utf8_hex",
            hex_encode(journal.coordinate.book_name.as_bytes()),
            hex_encode(journal.coordinate.base_unit_code.as_bytes()),
        )
    } else {
        (
            FMT,
            "book_name",
            "base_unit_code",
            journal.coordinate.book_name.clone(),
            journal.coordinate.base_unit_code.clone(),
        )
    };
    let mut cert = format!(
        "schema_version = 1\nformat = \"{format}\"\n{book_key} = \"{book_name}\"\n{unit_key} = \"{unit_code}\"\nbase_unit_scale = {}\neffective_through = \"{}\"\nknown_at_seq = {}\nentry_count = {}\ncontent_digest = \"{}\"\ncertificate_digest = \"{}\"\n",
        journal.coordinate.base_unit_scale,
        format_date_iso(journal.coordinate.effective_through),
        journal.coordinate.known_at_seq,
        journal.coordinate.entry_count,
        hex_encode(&journal.coordinate.content_digest),
        hex_encode(&journal.coordinate.certificate_digest),
    );
    // A whole-chart package's certificate bytes are unchanged; a scoped one
    // names its account (plan §13.1).
    if let Some(code) = &journal.coordinate.account_scope {
        if escaped {
            cert.push_str(&format!(
                "account_scope_utf8_hex = \"{}\"\n",
                hex_encode(code.as_bytes())
            ));
        } else {
            cert.push_str(&format!("account_scope = \"{code}\"\n"));
        }
    }

    Ok(AdsPackage {
        chart_of_accounts: chart,
        gl_detail: gl,
        trial_balance: tb,
        certificate_toml: cert,
    })
}

/// Read an [`AdsPackage`] back into a [`FormatJournal`], verifying the
/// coordinate certificate, per-entry double-entry balance (`FA-INV-01`), and
/// trial balance tie-out (`FA-INV-04`).
pub fn read_ads_package(
    pkg: &AdsPackage,
    units: &UnitCatalog,
) -> Result<FormatJournal, FormatError> {
    let cert_doc =
        fa_registry::toml::parse(&pkg.certificate_toml).map_err(|e| FormatError::Parse {
            format: FMT,
            detail: format!("certificate_toml: {e}"),
        })?;
    let escaped = match cert_doc.root.get("format").and_then(|v| v.as_str()) {
        Some(FMT) => false,
        Some(ESCAPED_FMT) => true,
        _ => return Err(text_error("unknown or absent ADS format version")),
    };
    if cert_doc.root.get("schema_version").and_then(|v| v.as_int()) != Some(1) {
        return Err(text_error("unsupported ADS coordinate schema version"));
    }
    let book_name = cert_doc
        .root
        .get(if escaped {
            "book_name_utf8_hex"
        } else {
            "book_name"
        })
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing book_name in ADS certificate".to_owned(),
        })?
        .to_owned();
    let book_name = if escaped {
        decode_hex_text(&book_name)?
    } else {
        book_name
    };
    let base_unit_code = cert_doc
        .root
        .get(if escaped {
            "base_unit_code_utf8_hex"
        } else {
            "base_unit_code"
        })
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing base_unit_code in ADS certificate".to_owned(),
        })?
        .to_owned();
    let base_unit_code = if escaped {
        decode_hex_text(&base_unit_code)?
    } else {
        base_unit_code
    };
    let base_unit_scale = cert_doc
        .root
        .get("base_unit_scale")
        .and_then(|v| v.as_int())
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing base_unit_scale in ADS certificate".to_owned(),
        })?;
    let effective_through_str = cert_doc
        .root
        .get("effective_through")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing effective_through in ADS certificate".to_owned(),
        })?;
    let effective_through = parse_date_iso(FMT, effective_through_str)?;
    let known_at_seq = cert_doc
        .root
        .get("known_at_seq")
        .and_then(|v| v.as_int())
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing known_at_seq in ADS certificate".to_owned(),
        })?;
    let expected_count = cert_doc
        .root
        .get("entry_count")
        .and_then(|v| v.as_int())
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| text_error("invalid ADS certificate entry_count"))?;
    let expected_content = hex_decode(
        FMT,
        cert_doc
            .root
            .get("content_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormatError::Parse {
                format: FMT,
                detail: "missing content_digest in ADS certificate".to_owned(),
            })?,
    )?;
    let expected_cert = hex_decode(
        FMT,
        cert_doc
            .root
            .get("certificate_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormatError::Parse {
                format: FMT,
                detail: "missing certificate_digest in ADS certificate".to_owned(),
            })?,
    )?;
    let account_scope = match cert_doc.root.get(if escaped {
        "account_scope_utf8_hex"
    } else {
        "account_scope"
    }) {
        None => None,
        Some(value) => {
            let code = value
                .as_str()
                .ok_or_else(|| text_error("invalid ADS certificate account_scope"))?;
            Some(if escaped {
                decode_hex_text(code)?
            } else {
                code.to_owned()
            })
        }
    };

    let mut accounts = Vec::new();
    for (idx, line) in pkg.chart_of_accounts.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }
        let decoded = decode_row(line, escaped, false)?;
        let cols: Vec<&str> = decoded.iter().map(String::as_str).collect();
        if cols.len() != 4 {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("invalid Chart_of_Accounts row: {line:?}"),
            });
        }
        let account_type = parse_account_type(FMT, cols[2])?;
        let normal_side = match cols[3] {
            "D" => Side::Debit,
            "C" => Side::Credit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid Normal_Balance {other:?}"),
                });
            }
        };
        accounts.push(FormatAccount {
            code: cols[0].to_owned(),
            name: cols[1].to_owned(),
            account_type,
            normal_side,
        });
    }

    let mut entries: Vec<FormatEntry> = Vec::new();
    let mut entry_index: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, line) in pkg.gl_detail.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }
        let raw: Vec<&str> = line.split('|').collect();
        let decoded = decode_row(line, escaped, true)?;
        let cols: Vec<&str> = decoded.iter().map(String::as_str).collect();
        if cols.len() != 13 {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("invalid GL_Detail row (expected 13 columns): {line:?}"),
            });
        }
        let entry_id = cols[0].to_owned();
        let eff_date = parse_date_iso(FMT, cols[2])?;
        let recorded_seq: u64 = cols[3].parse().map_err(|_| FormatError::Parse {
            format: FMT,
            detail: format!("invalid Recorded_Seq in {line:?}"),
        })?;
        let class_tag: u16 = cols[4].parse().map_err(|_| FormatError::Parse {
            format: FMT,
            detail: format!("invalid Entry_Class in {line:?}"),
        })?;
        let acct_code = cols[5].to_owned();
        let side = match cols[6] {
            "D" => Side::Debit,
            "C" => Side::Credit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid Debit_Credit_Indicator {other:?}"),
                });
            }
        };
        let unit_code = cols[8].to_owned();
        let (unit_id, unit_scale) =
            units
                .lookup_code(&unit_code)
                .ok_or_else(|| FormatError::UnknownUnit {
                    format: FMT,
                    unit: unit_code.clone(),
                })?;
        if cols[9].parse::<u8>().ok() != Some(unit_scale) {
            return Err(text_error(
                "GL_Detail Unit_Scale differs from its registered unit",
            ));
        }
        let mantissa = parse_exact_decimal(FMT, cols[7], unit_scale)?;
        let description = cols[10].to_owned();
        let absent = |index: usize| {
            if escaped {
                raw[index] == "\\N"
            } else {
                cols[index].is_empty()
            }
        };
        let migrated_from = if absent(11) {
            None
        } else {
            Some(cols[11].to_owned())
        };
        let memo = if absent(12) {
            None
        } else {
            Some(cols[12].to_owned())
        };

        let pos = match entry_index.get(&entry_id).copied() {
            Some(p) => {
                let prior = &entries[p];
                if prior.effective_date != eff_date
                    || prior.recorded_seq != recorded_seq
                    || prior.class != EntryClass(class_tag)
                    || prior.description != description
                    || prior.migrated_from != migrated_from
                {
                    return Err(text_error(
                        "GL_Detail repeats a journal identity with inconsistent header text or coordinates",
                    ));
                }
                p
            }
            None => {
                let p = entries.len();
                entries.push(FormatEntry {
                    entry_id: entry_id.clone(),
                    effective_date: eff_date,
                    recorded_seq,
                    class: EntryClass(class_tag),
                    description,
                    migrated_from,
                    legs: Vec::new(),
                });
                entry_index.insert(entry_id, p);
                p
            }
        };
        let line_number: usize = cols[1]
            .parse()
            .map_err(|_| text_error("invalid journal line number"))?;
        if entries[pos].legs.len().checked_add(1) != Some(line_number) {
            return Err(text_error(
                "journal line numbers must be consecutive in entry order",
            ));
        }
        entries[pos].legs.push(FormatLeg {
            account_code: acct_code,
            side,
            amount: Amount::new(unit_id, mantissa),
            unit_code,
            unit_scale,
            memo,
        });
    }

    let mut assertions = Vec::new();
    for (idx, line) in pkg.trial_balance.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }
        let decoded = decode_row(line, escaped, false)?;
        let cols: Vec<&str> = decoded.iter().map(String::as_str).collect();
        if cols.len() != 6 {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("invalid Trial_Balance row: {line:?}"),
            });
        }
        let acct_code = cols[0].to_owned();
        let as_of = parse_date_iso(FMT, cols[1])?;
        let side = match cols[2] {
            "D" => Side::Debit,
            "C" => Side::Credit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid TB Debit_Credit_Indicator {other:?}"),
                });
            }
        };
        let unit_code = cols[4].to_owned();
        let (unit_id, unit_scale) =
            units
                .lookup_code(&unit_code)
                .ok_or_else(|| FormatError::UnknownUnit {
                    format: FMT,
                    unit: unit_code.clone(),
                })?;
        let mantissa = parse_exact_decimal(FMT, cols[3], unit_scale)?;
        assertions.push(FormatAssertion {
            account_code: acct_code,
            as_of,
            side,
            amount: Amount::new(unit_id, mantissa),
            unit_code,
            unit_scale,
        });
    }

    let mut journal = FormatJournal::new(
        &book_name,
        &base_unit_code,
        base_unit_scale,
        effective_through,
        known_at_seq,
        accounts,
        entries,
        assertions,
    )?;
    // A scoped package holds exactly its account's extract: every entry
    // names the account and every balance is the account's own.
    if let Some(code) = &account_scope {
        if journal
            .entries
            .iter()
            .any(|e| !e.legs.iter().any(|l| &l.account_code == code))
            || journal.assertions.iter().any(|a| &a.account_code != code)
        {
            return Err(text_error(format!(
                "an ADS package scoped to account {code} holds an entry or a balance of another account only"
            )));
        }
        let coordinate = &journal.coordinate;
        let scoped = ExportCoordinate::compute_digest(
            &coordinate.book_name,
            &coordinate.base_unit_code,
            coordinate.base_unit_scale,
            coordinate.effective_through,
            coordinate.known_at_seq,
            coordinate.entry_count,
            &coordinate.content_digest,
            Some(code),
        );
        journal.coordinate.certificate_digest = scoped;
        journal.coordinate.account_scope = Some(code.clone());
    }

    let expected_coord = ExportCoordinate {
        book_name,
        base_unit_code,
        base_unit_scale,
        effective_through,
        known_at_seq,
        entry_count: journal.entries.len() as u64,
        content_digest: expected_content,
        certificate_digest: expected_cert,
        account_scope,
    };
    if u64::try_from(journal.entries.len()).ok() != Some(expected_count) {
        return Err(text_error(
            "ADS certificate entry_count differs from GL_Detail",
        ));
    }
    expected_coord.verify(&journal.coordinate.content_digest)?;
    if journal.coordinate.certificate_digest != expected_cert {
        return Err(FormatError::CertificateMismatch {
            format: FMT,
            expected_hex: hex_encode(&expected_cert),
            observed_hex: hex_encode(&journal.coordinate.certificate_digest),
        });
    }

    Ok(journal)
}

fn text_error(detail: impl Into<String>) -> FormatError {
    FormatError::Parse {
        format: ESCAPED_FMT,
        detail: detail.into(),
    }
}

fn encode_text(s: &str, escaped: bool) -> String {
    if !escaped {
        return s.to_owned();
    }
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\p"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

fn decode_text(s: &str) -> Result<String, FormatError> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next() {
            Some('\\') => '\\',
            Some('p') => '|',
            Some('n') => '\n',
            Some('r') => '\r',
            Some('u') => {
                let mut scalar = 0_u32;
                for _ in 0..4 {
                    let digit = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or_else(|| text_error("invalid ADS text Unicode escape"))?;
                    scalar = scalar
                        .checked_mul(16)
                        .and_then(|v| v.checked_add(digit))
                        .ok_or_else(|| text_error("ADS text scalar overflow"))?;
                }
                char::from_u32(scalar).ok_or_else(|| text_error("invalid ADS text scalar"))?
            }
            _ => return Err(text_error("unknown or incomplete ADS text escape")),
        });
    }
    if encode_text(&out, true) != s {
        return Err(text_error("noncanonical ADS text encoding"));
    }
    Ok(out)
}

fn optional_text(value: Option<&str>, escaped: bool) -> String {
    match value {
        None if escaped => "\\N".to_owned(),
        None => String::new(),
        Some(s) => encode_text(s, escaped),
    }
}

fn decode_row(line: &str, escaped: bool, gl: bool) -> Result<Vec<String>, FormatError> {
    line.split('|')
        .enumerate()
        .map(|(i, s)| {
            if escaped && gl && matches!(i, 11 | 12) && s == "\\N" {
                Ok(String::new())
            } else if escaped {
                decode_text(s)
            } else {
                Ok(s.to_owned())
            }
        })
        .collect()
}

fn decode_hex_text(s: &str) -> Result<String, FormatError> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err(text_error("invalid ADS UTF-8 hex metadata"));
    }
    let bytes = s
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16);
            let low = char::from(pair[1]).to_digit(16);
            match (high, low) {
                (Some(h), Some(l)) => {
                    u8::try_from(h * 16 + l).map_err(|_| text_error("invalid ADS hex byte"))
                }
                _ => Err(text_error("invalid ADS UTF-8 hex metadata")),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| text_error("ADS metadata is not UTF-8"))
}
