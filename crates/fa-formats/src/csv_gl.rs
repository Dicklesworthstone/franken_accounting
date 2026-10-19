//! Canonical CSV General Ledger extract/import (`csv_gl_v1`) and streaming
//! NDJSON General Ledger detail extract (`ndjson_gl_stream_v1`, plan §8.6,
//! §15.3, §15.9, bead `fa-npi`).

use std::collections::BTreeMap;

use fa_model::EntryClass;
use fa_money::{Amount, Side};

use crate::{
    ExportCoordinate, FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal,
    FormatLeg, UnitCatalog, format_account_type, format_date_iso, format_exact_decimal, hex_decode,
    hex_encode, parse_account_type, parse_date_iso, parse_exact_decimal,
};

const FMT_CSV: &str = "csv_gl_v1";
const FMT_NDJSON: &str = "ndjson_gl_stream_v1";

/// Write a [`FormatJournal`] as a canonical CSV General Ledger extract with
/// embedded coordinate header comments, account metadata comments, and a
/// declared 13-column GL row layout.
pub fn write_csv_gl(journal: &FormatJournal) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# fa_csv_gl_v1|book={}|base={}@{}|effective_through={}|known_at={}|entries={}|content_digest={}|certificate_digest={}\n",
        journal.coordinate.book_name,
        journal.coordinate.base_unit_code,
        journal.coordinate.base_unit_scale,
        format_date_iso(journal.coordinate.effective_through),
        journal.coordinate.known_at_seq,
        journal.coordinate.entry_count,
        hex_encode(&journal.coordinate.content_digest),
        hex_encode(&journal.coordinate.certificate_digest),
    ));
    for acct in &journal.accounts {
        let side_s = match acct.normal_side {
            Side::Debit => "D",
            Side::Credit => "C",
        };
        out.push_str(&format!(
            "# fa_account|{}|{}|{}|{}\n",
            acct.code,
            acct.name.replace('|', "/"),
            format_account_type(acct.account_type),
            side_s
        ));
    }
    for asrt in &journal.assertions {
        let side_s = match asrt.side {
            Side::Debit => "D",
            Side::Credit => "C",
        };
        let amt = format_exact_decimal(asrt.amount.mantissa, asrt.unit_scale);
        out.push_str(&format!(
            "# fa_assertion|{}|{}|{}|{}|{}\n",
            asrt.account_code,
            format_date_iso(asrt.as_of),
            side_s,
            amt,
            asrt.unit_code,
        ));
    }
    out.push_str(
        "entry_id,line_no,effective_date,recorded_seq,entry_class,account_code,side,amount,currency,unit_scale,description,migrated_from,memo\n",
    );
    for entry in &journal.entries {
        let date_str = format_date_iso(entry.effective_date);
        let mig = entry.migrated_from.as_deref().unwrap_or("");
        for (idx, leg) in entry.legs.iter().enumerate() {
            let side_s = match leg.side {
                Side::Debit => "D",
                Side::Credit => "C",
            };
            let amt = format_exact_decimal(leg.amount.mantissa, leg.unit_scale);
            let memo = leg.memo.as_deref().unwrap_or("");
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                csv_clean(&entry.entry_id),
                idx + 1,
                date_str,
                entry.recorded_seq,
                entry.class.0,
                csv_clean(&leg.account_code),
                side_s,
                amt,
                csv_clean(&leg.unit_code),
                leg.unit_scale,
                csv_clean(&entry.description),
                csv_clean(mig),
                csv_clean(memo),
            ));
        }
    }
    out
}

/// Read a canonical CSV General Ledger extract produced by [`write_csv_gl`]
/// back into a [`FormatJournal`], verifying the coordinate certificate and
/// `FA-INV-01` / `FA-INV-04` refold balances.
pub fn read_csv_gl(csv: &str, units: &UnitCatalog) -> Result<FormatJournal, FormatError> {
    let mut book_name = String::from("csv-import");
    let mut base_unit_code = String::from("USD");
    let mut base_unit_scale = 2u8;
    let mut effective_through = fa_time::DateDay(0);
    let mut known_at_seq = 0u64;
    let mut expected_content: Option<[u8; 32]> = None;
    let mut expected_cert: Option<[u8; 32]> = None;
    let mut accounts = Vec::new();
    let mut assertions = Vec::new();
    let mut entries: Vec<FormatEntry> = Vec::new();
    let mut entry_index: BTreeMap<String, usize> = BTreeMap::new();

    for (line_idx, raw_line) in csv.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(meta) = line.strip_prefix("# fa_csv_gl_v1|") {
            for kv in meta.split('|') {
                if let Some(v) = kv.strip_prefix("book=") {
                    book_name = v.to_owned();
                } else if let Some(v) = kv.strip_prefix("base=") {
                    if let Some((c, s)) = v.split_once('@') {
                        base_unit_code = c.to_owned();
                        base_unit_scale = s.parse().map_err(|_| FormatError::Parse {
                            format: FMT_CSV,
                            detail: format!("invalid base scale in {kv:?}"),
                        })?;
                    }
                } else if let Some(v) = kv.strip_prefix("effective_through=") {
                    effective_through = parse_date_iso(FMT_CSV, v)?;
                } else if let Some(v) = kv.strip_prefix("known_at=") {
                    known_at_seq = v.parse().map_err(|_| FormatError::Parse {
                        format: FMT_CSV,
                        detail: format!("invalid known_at in {kv:?}"),
                    })?;
                } else if let Some(v) = kv.strip_prefix("content_digest=") {
                    expected_content = Some(hex_decode(FMT_CSV, v)?);
                } else if let Some(v) = kv.strip_prefix("certificate_digest=") {
                    expected_cert = Some(hex_decode(FMT_CSV, v)?);
                }
            }
            continue;
        }
        if let Some(acct_meta) = line.strip_prefix("# fa_account|") {
            let parts: Vec<&str> = acct_meta.split('|').collect();
            if parts.len() != 4 {
                return Err(FormatError::Parse {
                    format: FMT_CSV,
                    detail: format!("invalid # fa_account header {line:?}"),
                });
            }
            let account_type = parse_account_type(FMT_CSV, parts[2])?;
            let normal_side = match parts[3] {
                "D" => Side::Debit,
                "C" => Side::Credit,
                other => {
                    return Err(FormatError::Parse {
                        format: FMT_CSV,
                        detail: format!("invalid account normal side {other:?}"),
                    });
                }
            };
            accounts.push(FormatAccount {
                code: parts[0].to_owned(),
                name: parts[1].to_owned(),
                account_type,
                normal_side,
            });
            continue;
        }
        if let Some(asrt_meta) = line.strip_prefix("# fa_assertion|") {
            let parts: Vec<&str> = asrt_meta.split('|').collect();
            if parts.len() != 5 {
                return Err(FormatError::Parse {
                    format: FMT_CSV,
                    detail: format!("invalid # fa_assertion header {line:?}"),
                });
            }
            let account_code = parts[0].to_owned();
            let as_of = parse_date_iso(FMT_CSV, parts[1])?;
            let side = match parts[2] {
                "D" => Side::Debit,
                "C" => Side::Credit,
                other => {
                    return Err(FormatError::Parse {
                        format: FMT_CSV,
                        detail: format!("invalid assertion side {other:?}"),
                    });
                }
            };
            let unit_code = parts[4].to_owned();
            let (unit_id, unit_scale) =
                units
                    .lookup_code(&unit_code)
                    .ok_or_else(|| FormatError::UnknownUnit {
                        format: FMT_CSV,
                        unit: unit_code.clone(),
                    })?;
            let mantissa = parse_exact_decimal(FMT_CSV, parts[3], unit_scale)?;
            assertions.push(FormatAssertion {
                account_code,
                as_of,
                side,
                amount: Amount::new(unit_id, mantissa),
                unit_code,
                unit_scale,
            });
            continue;
        }
        if line.starts_with('#') || line.starts_with("entry_id,") {
            continue;
        }

        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() != 13 {
            return Err(FormatError::Parse {
                format: FMT_CSV,
                detail: format!(
                    "line {}: expected 13 CSV columns, got {}",
                    line_idx + 1,
                    cols.len()
                ),
            });
        }
        let entry_id = cols[0].to_owned();
        let eff_date = parse_date_iso(FMT_CSV, cols[2])?;
        if eff_date > effective_through {
            effective_through = eff_date;
        }
        let recorded_seq: u64 = cols[3].parse().map_err(|_| FormatError::Parse {
            format: FMT_CSV,
            detail: format!("invalid recorded_seq in {line:?}"),
        })?;
        let class_tag: u16 = cols[4].parse().map_err(|_| FormatError::Parse {
            format: FMT_CSV,
            detail: format!("invalid entry_class in {line:?}"),
        })?;
        let account_code = cols[5].to_owned();
        let side = match cols[6] {
            "D" => Side::Debit,
            "C" => Side::Credit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT_CSV,
                    detail: format!("invalid side {other:?}"),
                });
            }
        };
        let unit_code = cols[8].to_owned();
        let (unit_id, unit_scale) =
            units
                .lookup_code(&unit_code)
                .ok_or_else(|| FormatError::UnknownUnit {
                    format: FMT_CSV,
                    unit: unit_code.clone(),
                })?;
        let mantissa = parse_exact_decimal(FMT_CSV, cols[7], unit_scale)?;
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
            account_code,
            side,
            amount: Amount::new(unit_id, mantissa),
            unit_code,
            unit_scale,
            memo,
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

    if let (Some(exp_content), Some(exp_cert)) = (expected_content, expected_cert) {
        let coord = ExportCoordinate {
            book_name,
            base_unit_code,
            base_unit_scale,
            effective_through,
            known_at_seq,
            entry_count: journal.entries.len() as u64,
            content_digest: exp_content,
            certificate_digest: exp_cert,
        };
        coord.verify(&journal.coordinate.content_digest)?;
    }

    Ok(journal)
}

/// Write a streaming NDJSON General Ledger extract (`fa gl detail --stream`,
/// plan §15.9) with a `gl_stream_header` coordinate row, one `gl_detail_row`
/// per leg, and a `gl_stream_footer` row carrying the total leg count and
/// `FA-INV-04` refold digest. The header carries every coordinate field
/// [`ExportCoordinate::compute`] binds (base unit and scale, content digest),
/// so a consumer recomputes `certificate_digest` from the stream alone; each
/// row carries its entry's class, as the CSV extract does.
pub fn write_ndjson_gl_stream(journal: &FormatJournal) -> Result<String, FormatError> {
    let refold = journal.refold_digest()?;
    let mut out = String::new();
    out.push_str(&format!(
        "{{\"event\":\"gl_stream_header\",\"book_name\":\"{}\",\"base_unit\":\"{}\",\"base_unit_scale\":{},\"effective_through\":\"{}\",\"known_at_seq\":{},\"entry_count\":{},\"content_digest\":\"{}\",\"certificate_digest\":\"{}\"}}\n",
        json_escape(&journal.coordinate.book_name),
        json_escape(&journal.coordinate.base_unit_code),
        journal.coordinate.base_unit_scale,
        format_date_iso(journal.coordinate.effective_through),
        journal.coordinate.known_at_seq,
        journal.coordinate.entry_count,
        hex_encode(&journal.coordinate.content_digest),
        hex_encode(&journal.coordinate.certificate_digest),
    ));

    let mut row_count = 0usize;
    for entry in &journal.entries {
        let eff_date = format_date_iso(entry.effective_date);
        for (idx, leg) in entry.legs.iter().enumerate() {
            row_count += 1;
            let side = match leg.side {
                Side::Debit => "debit",
                Side::Credit => "credit",
            };
            let amt = format_exact_decimal(leg.amount.mantissa, leg.unit_scale);
            out.push_str(&format!(
                "{{\"event\":\"gl_detail_row\",\"ordinal\":{},\"entry_id\":\"{}\",\"line_no\":{},\"effective_date\":\"{}\",\"recorded_seq\":{},\"entry_class\":{},\"account_code\":\"{}\",\"side\":\"{}\",\"amount\":\"{}\",\"mantissa\":\"{}\",\"unit\":\"{}\"}}\n",
                row_count,
                json_escape(&entry.entry_id),
                idx + 1,
                eff_date,
                entry.recorded_seq,
                entry.class.0,
                json_escape(&leg.account_code),
                side,
                amt,
                leg.amount.mantissa,
                json_escape(&leg.unit_code),
            ));
        }
    }

    out.push_str(&format!(
        "{{\"event\":\"gl_stream_footer\",\"row_count\":{},\"refold_digest\":\"{}\"}}\n",
        row_count,
        hex_encode(&refold),
    ));
    Ok(out)
}

/// Verify that an NDJSON GL stream begins with `gl_stream_header`, ends with
/// `gl_stream_footer`, and has `row_count` matching the emitted `gl_detail_row` lines.
pub fn verify_ndjson_gl_stream(ndjson: &str) -> Result<usize, FormatError> {
    let lines: Vec<&str> = ndjson.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return Err(FormatError::Parse {
            format: FMT_NDJSON,
            detail: "stream must contain at least header and footer rows".to_owned(),
        });
    }
    if !lines[0].contains("\"event\":\"gl_stream_header\"") {
        return Err(FormatError::Parse {
            format: FMT_NDJSON,
            detail: "first line is not gl_stream_header".to_owned(),
        });
    }
    let last = lines[lines.len() - 1];
    if !last.contains("\"event\":\"gl_stream_footer\"") {
        return Err(FormatError::Parse {
            format: FMT_NDJSON,
            detail: "last line is not gl_stream_footer".to_owned(),
        });
    }
    let detail_rows = lines.len() - 2;
    for row in &lines[1..lines.len() - 1] {
        if !row.contains("\"event\":\"gl_detail_row\"") {
            return Err(FormatError::Parse {
                format: FMT_NDJSON,
                detail: format!("unexpected middle row {row:?}"),
            });
        }
    }
    let expected_tag = format!("\"row_count\":{detail_rows}");
    if !last.contains(&expected_tag) {
        return Err(FormatError::Parse {
            format: FMT_NDJSON,
            detail: format!("footer row_count does not match {detail_rows} detail rows"),
        });
    }
    Ok(detail_rows)
}

fn csv_clean(s: &str) -> String {
    s.replace([',', '\n', '\r'], " ")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
