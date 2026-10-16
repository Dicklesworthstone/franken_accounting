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
    let mut chart = String::from("GL_Account_Number|GL_Account_Name|Account_Type|Normal_Balance\n");
    for acct in &journal.accounts {
        let side_str = match acct.normal_side {
            Side::Debit => "D",
            Side::Credit => "C",
        };
        chart.push_str(&format!(
            "{}|{}|{}|{}\n",
            acct.code,
            sanitize_pipe(&acct.name),
            format_account_type(acct.account_type),
            side_str
        ));
    }

    let mut gl = String::from(
        "Journal_ID|Journal_Entry_Line_Number|Effective_Date|Recorded_Seq|Entry_Class|GL_Account_Number|Debit_Credit_Indicator|Amount|Transaction_Currency|Unit_Scale|JE_Header_Description|Migrated_From|Line_Description\n",
    );
    for entry in &journal.entries {
        let date_str = format_date_iso(entry.effective_date);
        let mig = entry.migrated_from.as_deref().unwrap_or("");
        for (idx, leg) in entry.legs.iter().enumerate() {
            let line_no = idx + 1;
            let dc = match leg.side {
                Side::Debit => "D",
                Side::Credit => "C",
            };
            let amt_str = format_exact_decimal(leg.amount.mantissa, leg.unit_scale);
            let memo = leg.memo.as_deref().unwrap_or("");
            gl.push_str(&format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
                sanitize_pipe(&entry.entry_id),
                line_no,
                date_str,
                entry.recorded_seq,
                entry.class.0,
                leg.account_code,
                dc,
                amt_str,
                leg.unit_code,
                leg.unit_scale,
                sanitize_pipe(&entry.description),
                sanitize_pipe(mig),
                sanitize_pipe(memo),
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
                asrt.account_code,
                format_date_iso(asrt.as_of),
                dc,
                amt_str,
                asrt.unit_code,
                asrt.unit_scale
            ));
        }
    } else {
        for ((acct_code, unit_code), signed_bal) in &balances {
            let scale = unit_scale_by_code.get(unit_code).copied().unwrap_or(2);
            let (dc, mag) = if *signed_bal >= 0 {
                ("D", *signed_bal)
            } else {
                ("C", -*signed_bal)
            };
            let amt_str = format_exact_decimal(mag, scale);
            tb.push_str(&format!(
                "{}|{}|{}|{}|{}|{}\n",
                acct_code,
                format_date_iso(journal.coordinate.effective_through),
                dc,
                amt_str,
                unit_code,
                scale
            ));
        }
    }

    let cert = format!(
        "schema_version = 1\nformat = \"aicpa_ads_gl_v2\"\nbook_name = \"{}\"\nbase_unit_code = \"{}\"\nbase_unit_scale = {}\neffective_through = \"{}\"\nknown_at_seq = {}\nentry_count = {}\ncontent_digest = \"{}\"\ncertificate_digest = \"{}\"\n",
        journal.coordinate.book_name,
        journal.coordinate.base_unit_code,
        journal.coordinate.base_unit_scale,
        format_date_iso(journal.coordinate.effective_through),
        journal.coordinate.known_at_seq,
        journal.coordinate.entry_count,
        hex_encode(&journal.coordinate.content_digest),
        hex_encode(&journal.coordinate.certificate_digest),
    );

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
    let book_name = cert_doc
        .root
        .get("book_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing book_name in ADS certificate".to_owned(),
        })?
        .to_owned();
    let base_unit_code = cert_doc
        .root
        .get("base_unit_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing base_unit_code in ADS certificate".to_owned(),
        })?
        .to_owned();
    let base_unit_scale = cert_doc
        .root
        .get("base_unit_scale")
        .and_then(|v| v.as_int())
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing base_unit_scale in ADS certificate".to_owned(),
        })? as u8;
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
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing known_at_seq in ADS certificate".to_owned(),
        })? as u64;
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

    let mut accounts = Vec::new();
    for (idx, line) in pkg.chart_of_accounts.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('|').collect();
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
        let cols: Vec<&str> = line.split('|').collect();
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
        let mantissa = parse_exact_decimal(FMT, cols[7], unit_scale)?;
        let description = cols[10].to_owned();
        let migrated_from = if cols[11].is_empty() {
            None
        } else {
            Some(cols[11].to_owned())
        };
        let memo = if cols[12].is_empty() {
            None
        } else {
            Some(cols[12].to_owned())
        };

        let pos = match entry_index.get(&entry_id).copied() {
            Some(p) => p,
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
        let cols: Vec<&str> = line.split('|').collect();
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

    let expected_coord = ExportCoordinate {
        book_name,
        base_unit_code,
        base_unit_scale,
        effective_through,
        known_at_seq,
        entry_count: journal.entries.len() as u64,
        content_digest: expected_content,
        certificate_digest: expected_cert,
    };
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

fn sanitize_pipe(s: &str) -> String {
    s.replace('|', "/")
}
