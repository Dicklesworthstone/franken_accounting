//! Canonical CSV General Ledger extract/import (`csv_gl_v1`) and streaming
//! NDJSON General Ledger detail extract (`ndjson_gl_stream_v1`, plan §8.6,
//! §15.3, §15.9, bead `fa-npi`).

use std::collections::{BTreeMap, BTreeSet};

use fa_model::EntryClass;
use fa_money::{Amount, Side};

use crate::csv::{CsvRecord, CsvRecords, quote_field};
use crate::{
    ExportCoordinate, FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal,
    FormatLeg, UnitCatalog, format_account_type, format_date_iso, format_exact_decimal, hex_decode,
    hex_encode, parse_account_type, parse_date_iso, parse_exact_decimal,
};

const FMT_CSV: &str = "csv_gl_v1";
const FMT_NDJSON: &str = "ndjson_gl_stream_v1";
const CSV_HEADER: &str = "entry_id,line_no,effective_date,recorded_seq,entry_class,account_code,side,amount,currency,unit_scale,description,migrated_from,memo";

/// Write a [`FormatJournal`] as a canonical CSV General Ledger extract with
/// embedded coordinate header comments, account metadata comments, and a
/// declared 13-column GL row layout. Text uses CSV quoting without sanitizing
/// it. Metadata containing delimiters, controls or boundary whitespace opts
/// into the additive `fa_csv_text_encoding_v1|percent-utf8` comment extension;
/// its textual metadata fields are then percent-encoded UTF-8. Ordinary v1
/// metadata stays unchanged. Readers that do not support the extension fail
/// certificate verification instead of accepting changed text. Sparse
/// `fa_csv_empty_optional_v1` comments retain empty-but-present migration
/// provenance and leg memos, distinct from absent optional text.
pub fn write_csv_gl(journal: &FormatJournal) -> String {
    let mut out = String::new();
    let escaped_metadata = metadata_needs_escape(&journal.coordinate.book_name)
        || metadata_needs_escape(&journal.coordinate.base_unit_code)
        || journal.accounts.iter().any(|account| {
            metadata_needs_escape(&account.code)
                || metadata_needs_escape(&account.name)
                || account.roles.iter().any(|role| metadata_needs_escape(role))
        })
        || journal.assertions.iter().any(|assertion| {
            metadata_needs_escape(&assertion.account_code)
                || metadata_needs_escape(&assertion.unit_code)
        });
    let text = |value: &str| encode_metadata(value, escaped_metadata);
    if escaped_metadata {
        out.push_str("# fa_csv_text_encoding_v1|percent-utf8\n");
    }
    out.push_str(&format!(
        "# fa_csv_gl_v1|book={}|base={}@{}|effective_through={}|known_at={}|entries={}|content_digest={}|certificate_digest={}\n",
        text(&journal.coordinate.book_name),
        text(&journal.coordinate.base_unit_code),
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
            text(&acct.code),
            text(&acct.name),
            format_account_type(acct.account_type),
            side_s
        ));
        if !acct.roles.is_empty() {
            out.push_str(&format!(
                "# fa_account_roles_v1|{}|{}\n",
                text(&acct.code),
                acct.roles
                    .iter()
                    .map(|role| text(role))
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
    }
    for asrt in &journal.assertions {
        let side_s = match asrt.side {
            Side::Debit => "D",
            Side::Credit => "C",
        };
        let amt = format_exact_decimal(asrt.amount.mantissa, asrt.unit_scale);
        out.push_str(&format!(
            "# fa_assertion|{}|{}|{}|{}|{}\n",
            text(&asrt.account_code),
            format_date_iso(asrt.as_of),
            side_s,
            amt,
            text(&asrt.unit_code),
        ));
    }
    for (entry_index, entry) in journal.entries.iter().enumerate() {
        if entry.migrated_from.as_deref() == Some("") {
            out.push_str(&format!(
                "# fa_csv_empty_optional_v1|{}|0|migrated_from\n",
                entry_index + 1
            ));
        }
        for (leg_index, leg) in entry.legs.iter().enumerate() {
            if leg.memo.as_deref() == Some("") {
                out.push_str(&format!(
                    "# fa_csv_empty_optional_v1|{}|{}|memo\n",
                    entry_index + 1,
                    leg_index + 1
                ));
            }
        }
    }
    out.push_str(CSV_HEADER);
    out.push('\n');
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
                quote_field(&entry.entry_id),
                idx + 1,
                date_str,
                entry.recorded_seq,
                entry.class.0,
                quote_field(&leg.account_code),
                side_s,
                amt,
                quote_field(&leg.unit_code),
                leg.unit_scale,
                quote_field(&entry.description),
                quote_field(mig),
                quote_field(memo),
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
    let mut declared_effective_through = false;
    let mut known_at_seq = 0u64;
    let mut expected_content: Option<[u8; 32]> = None;
    let mut expected_cert: Option<[u8; 32]> = None;
    let mut expected_entry_count = None;
    let mut saw_header = false;
    let mut escaped_metadata = false;
    let mut metadata_seen = false;
    let mut empty_fields = BTreeSet::new();
    let mut accounts = Vec::new();
    let mut assertions = Vec::new();
    let mut entries: Vec<FormatEntry> = Vec::new();
    let mut entry_index: BTreeMap<String, usize> = BTreeMap::new();

    for record in CsvRecords::new(csv, FMT_CSV) {
        let (line_idx, line, fields) = match record? {
            CsvRecord::Comment(line) => (0, line, Vec::new()),
            CsvRecord::Row { line, fields } => (line - 1, "", fields),
        };
        if let Some(encoding) = line.strip_prefix("# fa_csv_text_encoding_v1|") {
            if encoding != "percent-utf8" || escaped_metadata || metadata_seen || saw_header {
                return Err(FormatError::Parse {
                    format: FMT_CSV,
                    detail:
                        "CSV text encoding must be percent-utf8 and declared once before metadata"
                            .into(),
                });
            }
            escaped_metadata = true;
            continue;
        }
        let text = |value: &str| decode_metadata(value, escaped_metadata);
        if let Some(meta) = line.strip_prefix("# fa_csv_empty_optional_v1|") {
            metadata_seen = true;
            let parts = meta.split('|').collect::<Vec<_>>();
            let invalid = || FormatError::Parse {
                format: FMT_CSV,
                detail: "invalid, repeated or late empty-optional CSV metadata".into(),
            };
            let [entry, leg, field] = parts.as_slice() else {
                return Err(invalid());
            };
            let entry = entry.parse::<usize>().map_err(|_| invalid())?;
            let leg = leg.parse::<usize>().map_err(|_| invalid())?;
            if saw_header
                || entry == 0
                || !matches!((*field, leg), ("migrated_from", 0) | ("memo", 1..))
                || !empty_fields.insert((entry, leg))
            {
                return Err(invalid());
            }
            continue;
        }
        if let Some(meta) = line.strip_prefix("# fa_csv_gl_v1|") {
            metadata_seen = true;
            for kv in meta.split('|') {
                if let Some(v) = kv.strip_prefix("book=") {
                    book_name = text(v)?;
                } else if let Some(v) = kv.strip_prefix("base=") {
                    if let Some((c, s)) = v.split_once('@') {
                        base_unit_code = text(c)?;
                        base_unit_scale = s.parse().map_err(|_| FormatError::Parse {
                            format: FMT_CSV,
                            detail: format!("invalid base scale in {kv:?}"),
                        })?;
                    }
                } else if let Some(v) = kv.strip_prefix("effective_through=") {
                    effective_through = parse_date_iso(FMT_CSV, v)?;
                    declared_effective_through = true;
                } else if let Some(v) = kv.strip_prefix("known_at=") {
                    known_at_seq = v.parse().map_err(|_| FormatError::Parse {
                        format: FMT_CSV,
                        detail: format!("invalid known_at in {kv:?}"),
                    })?;
                } else if let Some(v) = kv.strip_prefix("entries=") {
                    expected_entry_count =
                        Some(v.parse::<usize>().map_err(|_| FormatError::Parse {
                            format: FMT_CSV,
                            detail: format!("invalid entry count in {kv:?}"),
                        })?);
                } else if let Some(v) = kv.strip_prefix("content_digest=") {
                    expected_content = Some(hex_decode(FMT_CSV, v)?);
                } else if let Some(v) = kv.strip_prefix("certificate_digest=") {
                    expected_cert = Some(hex_decode(FMT_CSV, v)?);
                }
            }
            continue;
        }
        if let Some(acct_meta) = line.strip_prefix("# fa_account|") {
            metadata_seen = true;
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
                code: text(parts[0])?,
                name: text(parts[1])?,
                account_type,
                normal_side,
                roles: Vec::new(),
            });
            continue;
        }
        if let Some(meta) = line.strip_prefix("# fa_account_roles_v1|") {
            metadata_seen = true;
            let (code, roles) = meta.split_once('|').ok_or_else(|| FormatError::Parse {
                format: FMT_CSV,
                detail: "invalid account roles v1 metadata".into(),
            })?;
            let code = text(code)?;
            let account = accounts
                .iter_mut()
                .find(|account| account.code == code)
                .ok_or_else(|| FormatError::UnknownAccount {
                    format: FMT_CSV,
                    account_code: code.clone(),
                })?;
            account
                .roles
                .extend(roles.split(',').map(text).collect::<Result<Vec<_>, _>>()?);
            continue;
        }
        if let Some(asrt_meta) = line.strip_prefix("# fa_assertion|") {
            metadata_seen = true;
            let parts: Vec<&str> = asrt_meta.split('|').collect();
            if parts.len() != 5 {
                return Err(FormatError::Parse {
                    format: FMT_CSV,
                    detail: format!("invalid # fa_assertion header {line:?}"),
                });
            }
            let account_code = text(parts[0])?;
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
            let unit_code = text(parts[4])?;
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
        if line.starts_with('#') {
            continue;
        }

        let cols: Vec<&str> = fields.iter().map(String::as_str).collect();
        if !saw_header {
            if !cols.iter().copied().eq(CSV_HEADER.split(',')) {
                return Err(FormatError::Parse {
                    format: FMT_CSV,
                    detail: format!("line {}: expected the declared CSV GL header", line_idx + 1),
                });
            }
            saw_header = true;
            continue;
        }
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
        let line_no: usize = cols[1].parse().map_err(|_| FormatError::Parse {
            format: FMT_CSV,
            detail: format!("line {}: invalid line_no {:?}", line_idx + 1, cols[1]),
        })?;
        let eff_date = parse_date_iso(FMT_CSV, cols[2])?;
        if !declared_effective_through && eff_date > effective_through {
            effective_through = eff_date;
        }
        let recorded_seq: u64 = cols[3].parse().map_err(|_| FormatError::Parse {
            format: FMT_CSV,
            detail: format!("line {}: invalid recorded_seq {:?}", line_idx + 1, cols[3]),
        })?;
        let class_tag: u16 = cols[4].parse().map_err(|_| FormatError::Parse {
            format: FMT_CSV,
            detail: format!("line {}: invalid entry_class {:?}", line_idx + 1, cols[4]),
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
        if cols[9].parse::<u8>().ok() != Some(unit_scale) {
            return Err(FormatError::Parse {
                format: FMT_CSV,
                detail: format!(
                    "line {}: unit_scale {:?} differs from registered scale {unit_scale} for {unit_code}",
                    line_idx + 1,
                    cols[9]
                ),
            });
        }
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
            Some(p) => {
                let prior = &entries[p];
                if prior.effective_date != eff_date
                    || prior.recorded_seq != recorded_seq
                    || prior.class != EntryClass(class_tag)
                    || prior.description != description
                    || prior.migrated_from != migrated_from
                {
                    return Err(FormatError::Parse {
                        format: FMT_CSV,
                        detail: format!(
                            "line {}: conflicting metadata for CSV entry {entry_id:?}",
                            line_idx + 1
                        ),
                    });
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
                entry_index.insert(entry_id.clone(), p);
                p
            }
        };
        if line_no != entries[pos].legs.len() + 1 {
            return Err(FormatError::Parse {
                format: FMT_CSV,
                detail: format!(
                    "line {}: entry {entry_id:?} needs consecutive line_no {}, got {line_no}",
                    line_idx + 1,
                    entries[pos].legs.len() + 1
                ),
            });
        }
        entries[pos].legs.push(FormatLeg {
            account_code,
            side,
            amount: Amount::new(unit_id, mantissa),
            unit_code,
            unit_scale,
            memo,
        });
    }

    if !saw_header {
        return Err(FormatError::Parse {
            format: FMT_CSV,
            detail: "missing declared CSV GL header".into(),
        });
    }
    if let Some(expected) = expected_entry_count
        && expected != entries.len()
    {
        return Err(FormatError::Parse {
            format: FMT_CSV,
            detail: format!(
                "CSV entry count is {}, header declares {expected}",
                entries.len()
            ),
        });
    }
    if expected_content.is_some() != expected_cert.is_some() {
        return Err(FormatError::Parse {
            format: FMT_CSV,
            detail: "CSV content and certificate digests must be supplied together".into(),
        });
    }
    for (entry_ordinal, leg_ordinal) in empty_fields {
        let invalid = || FormatError::Parse {
            format: FMT_CSV,
            detail: format!(
                "empty-optional CSV metadata names a missing or nonempty field at entry {entry_ordinal}, leg {leg_ordinal}"
            ),
        };
        let entry = entries.get_mut(entry_ordinal - 1).ok_or_else(invalid)?;
        let field = if leg_ordinal == 0 {
            &mut entry.migrated_from
        } else {
            &mut entry
                .legs
                .get_mut(leg_ordinal - 1)
                .ok_or_else(invalid)?
                .memo
        };
        if field.is_some() {
            return Err(invalid());
        }
        *field = Some(String::new());
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
            account_scope: None,
        };
        coord.verify(&journal.coordinate.content_digest)?;
    }

    Ok(journal)
}

fn metadata_needs_escape(value: &str) -> bool {
    value.trim() != value
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'|' | b',' | b'@'))
}

fn encode_metadata(value: &str, escaped: bool) -> String {
    if !escaped {
        return value.to_owned();
    }
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn decode_metadata(value: &str, escaped: bool) -> Result<String, FormatError> {
    if !escaped {
        return Ok(value.to_owned());
    }
    let invalid = || FormatError::Parse {
        format: FMT_CSV,
        detail: "invalid percent-encoded UTF-8 in CSV metadata".into(),
    };
    let mut bytes = value.bytes();
    let mut decoded = Vec::new();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes.next().and_then(|b| char::from(b).to_digit(16));
            let low = bytes.next().and_then(|b| char::from(b).to_digit(16));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(invalid());
            };
            decoded.push((high * 16 + low) as u8);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).map_err(|_| invalid())
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

/// A JSON string body (RFC 8259 §7): backslash, quote and every control
/// character escaped, so one NDJSON record stays one line of valid JSON.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::json_escape;

    /// A control character in a streamed name never splits the record or
    /// leaves invalid JSON; ordinary text is unchanged byte for byte.
    #[test]
    fn json_strings_escape_every_control_character() {
        assert_eq!(json_escape("acme-fy2026-p03"), "acme-fy2026-p03");
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(json_escape("a\nb\rc\td"), r"a\nb\rc\td");
        assert_eq!(json_escape("\u{1}\u{1f}"), r"\u0001\u001f");
        assert!(!json_escape("x\ny\u{0}z").chars().any(char::is_control));
    }
}
