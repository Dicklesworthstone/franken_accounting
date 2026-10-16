//! Litigation discovery load-file writers and parsers (plan §11.8, §13.2; bead `fa-6l9`).
//!
//! Supports deterministic export (and Concordance DAT round-trip verification) for:
//! - `concordance_dat_v1` (`.dat`, standard `\u{0014}` delimiter and `\u{00fe}` text qualifier)
//! - `opticon_opt_v1` (`.opt`, page-level image cross-reference)
//! - `edrm_xml_v1` (`.xml`, EDRM XML v1.2 discovery load file with BLAKE3 commitments)

use crate::FormatError;

/// Standard Concordance field delimiter (ASCII 20 / DC4, `\u{0014}`).
pub const CONCORDANCE_DELIM: char = '\u{0014}';
/// Standard Concordance text qualifier (thorn, `\u{00fe}`, `'þ'`).
pub const CONCORDANCE_QUOTE: char = '\u{00fe}';

/// Confidentiality designation under a matter's protective order (plan §13.2, Appendix A).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidentialityDesignation {
    None = 0,
    Confidential = 1,
    AttorneysEyesOnly = 2,
    HighlyConfidential = 3,
}

impl ConfidentialityDesignation {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::None),
            1 => Some(Self::Confidential),
            2 => Some(Self::AttorneysEyesOnly),
            3 => Some(Self::HighlyConfidential),
            _ => None,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Confidential => "CONFIDENTIAL",
            Self::AttorneysEyesOnly => "ATTORNEYS' EYES ONLY",
            Self::HighlyConfidential => "HIGHLY CONFIDENTIAL",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label.trim() {
            "NONE" | "" => Some(Self::None),
            "CONFIDENTIAL" => Some(Self::Confidential),
            "ATTORNEYS' EYES ONLY" | "AEO" => Some(Self::AttorneysEyesOnly),
            "HIGHLY CONFIDENTIAL" => Some(Self::HighlyConfidential),
            _ => None,
        }
    }
}

/// Selected load-file export format on a `ProductionProfile` (Appendix A `load_file_format: u8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadFileFormat {
    ConcordanceDatOpt = 1,
    EdrmXml = 2,
    Both = 3,
}

impl LoadFileFormat {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::ConcordanceDatOpt),
            2 => Some(Self::EdrmXml),
            3 => Some(Self::Both),
            _ => None,
        }
    }
}

/// Contiguous Bates number range assigned to a produced document in one matter (plan §13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatesRange {
    pub matter_id: String,
    pub prefix: String,
    pub start_number: u64,
    pub end_number: u64,
    pub page_count: u64,
}

impl BatesRange {
    pub fn new(
        matter_id: impl Into<String>,
        prefix: impl Into<String>,
        start_number: u64,
        page_count: u64,
    ) -> Result<Self, FormatError> {
        let matter_id = matter_id.into();
        let prefix = prefix.into();
        if matter_id.trim().is_empty() {
            return Err(FormatError::Parse {
                format: "bates_range",
                detail: "matter_id must not be empty".into(),
            });
        }
        if prefix.trim().is_empty() || prefix.len() > 16 {
            return Err(FormatError::Parse {
                format: "bates_range",
                detail: format!("bates_prefix {prefix:?} must be 1..=16 bytes"),
            });
        }
        if start_number == 0 || page_count == 0 {
            return Err(FormatError::Parse {
                format: "bates_range",
                detail: "start_number and page_count must be >= 1".into(),
            });
        }
        let end_number =
            start_number
                .checked_add(page_count - 1)
                .ok_or_else(|| FormatError::Overflow {
                    format: "bates_range",
                    detail: "Bates number overflow".into(),
                })?;
        Ok(Self {
            matter_id,
            prefix,
            start_number,
            end_number,
            page_count,
        })
    }

    #[must_use]
    pub fn beg_bates(&self) -> String {
        format!("{}-{:08}", self.prefix, self.start_number)
    }

    #[must_use]
    pub fn end_bates(&self) -> String {
        format!("{}-{:08}", self.prefix, self.end_number)
    }

    #[must_use]
    pub fn range_label(&self) -> String {
        format!("{}..={}", self.beg_bates(), self.end_bates())
    }
}

/// One produced document's row in a discovery load file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadFileRecord {
    pub doc_id: String,
    pub document_oid_hex: String,
    pub doc_commit_hex: String,
    pub bates: BatesRange,
    pub designation: ConfidentialityDesignation,
    pub document_kind: String,
    pub mime_type: String,
    pub byte_length: u64,
    pub redacted: bool,
    pub redaction_contract: Option<String>,
    pub exhibit_labels: Vec<String>,
    pub text_path: String,
    pub native_path: String,
}

const DAT_HEADERS: &[&str] = &[
    "DOCID",
    "BEGBATES",
    "ENDBATES",
    "PGCOUNT",
    "MATTER",
    "DESIGNATION",
    "DOCTYPE",
    "MIMETYPE",
    "DOCSIZE",
    "DOCUMENT_OID",
    "BLAKE3_COMMIT",
    "REDACTED",
    "REDACTION_CONTRACT",
    "EXHIBITS",
    "TEXTPATH",
    "NATIVEPATH",
];

fn format_dat_row(cols: &[&str]) -> String {
    let mut line = String::new();
    for (idx, col) in cols.iter().enumerate() {
        if idx > 0 {
            line.push(CONCORDANCE_DELIM);
        }
        line.push(CONCORDANCE_QUOTE);
        for ch in col.chars() {
            if ch == CONCORDANCE_QUOTE || ch == CONCORDANCE_DELIM || ch == '\r' || ch == '\n' {
                line.push(' ');
            } else {
                line.push(ch);
            }
        }
        line.push(CONCORDANCE_QUOTE);
    }
    line
}

/// Render a deterministic Concordance `.dat` load file (`concordance_dat_v1`).
pub fn write_concordance_dat(records: &[LoadFileRecord]) -> Result<String, FormatError> {
    let mut out = format_dat_row(DAT_HEADERS);
    out.push('\n');
    for rec in records {
        if rec.bates.page_count == 0
            || rec.bates.end_number < rec.bates.start_number
            || rec.bates.end_number - rec.bates.start_number + 1 != rec.bates.page_count
        {
            return Err(FormatError::Parse {
                format: "concordance_dat_v1",
                detail: format!("inconsistent Bates range on {}", rec.doc_id),
            });
        }
        let beg = rec.bates.beg_bates();
        let end = rec.bates.end_bates();
        let pg = rec.bates.page_count.to_string();
        let size = rec.byte_length.to_string();
        let redacted = if rec.redacted { "Y" } else { "N" };
        let contract = rec.redaction_contract.as_deref().unwrap_or("");
        let exhibits = rec.exhibit_labels.join(";");
        let row = format_dat_row(&[
            &rec.doc_id,
            &beg,
            &end,
            &pg,
            &rec.bates.matter_id,
            rec.designation.label(),
            &rec.document_kind,
            &rec.mime_type,
            &size,
            &rec.document_oid_hex,
            &rec.doc_commit_hex,
            redacted,
            contract,
            &exhibits,
            &rec.text_path,
            &rec.native_path,
        ]);
        out.push_str(&row);
        out.push('\n');
    }
    Ok(out)
}

fn parse_bates_token(token: &str) -> Result<(String, u64), FormatError> {
    let (prefix, num_str) = token.rsplit_once('-').ok_or_else(|| FormatError::Parse {
        format: "concordance_dat_v1",
        detail: format!("invalid Bates token {token:?}"),
    })?;
    let num = num_str.parse::<u64>().map_err(|_| FormatError::Parse {
        format: "concordance_dat_v1",
        detail: format!("invalid Bates number in {token:?}"),
    })?;
    Ok((prefix.to_string(), num))
}

/// Parse a Concordance `.dat` file produced by [`write_concordance_dat`].
pub fn parse_concordance_dat(input: &str) -> Result<Vec<LoadFileRecord>, FormatError> {
    let mut lines = input.lines().filter(|l| !l.trim().is_empty());
    let header_line = lines.next().ok_or_else(|| FormatError::Parse {
        format: "concordance_dat_v1",
        detail: "empty DAT file".into(),
    })?;
    let parse_cols = |line: &str| -> Result<Vec<String>, FormatError> {
        let parts: Vec<&str> = line.split(CONCORDANCE_DELIM).collect();
        let mut out = Vec::with_capacity(parts.len());
        for p in parts {
            let trimmed = p
                .strip_prefix(CONCORDANCE_QUOTE)
                .and_then(|s| s.strip_suffix(CONCORDANCE_QUOTE))
                .ok_or_else(|| FormatError::Parse {
                    format: "concordance_dat_v1",
                    detail: format!("column missing Concordance thorn quotes: {p:?}"),
                })?;
            out.push(trimmed.to_string());
        }
        Ok(out)
    };
    let headers = parse_cols(header_line)?;
    if headers.iter().map(String::as_str).collect::<Vec<_>>() != DAT_HEADERS {
        return Err(FormatError::Parse {
            format: "concordance_dat_v1",
            detail: format!("unexpected DAT header columns: {headers:?}"),
        });
    }
    let mut records = Vec::new();
    for line in lines {
        let cols = parse_cols(line)?;
        if cols.len() != DAT_HEADERS.len() {
            return Err(FormatError::Parse {
                format: "concordance_dat_v1",
                detail: format!("expected {} columns, got {}", DAT_HEADERS.len(), cols.len()),
            });
        }
        let (prefix_beg, start_number) = parse_bates_token(&cols[1])?;
        let (prefix_end, end_number) = parse_bates_token(&cols[2])?;
        if prefix_beg != prefix_end {
            return Err(FormatError::Parse {
                format: "concordance_dat_v1",
                detail: format!("mismatched Bates prefixes: {prefix_beg} vs {prefix_end}"),
            });
        }
        let page_count = cols[3].parse::<u64>().map_err(|_| FormatError::Parse {
            format: "concordance_dat_v1",
            detail: format!("invalid PGCOUNT {:?}", cols[3]),
        })?;
        let bates = BatesRange::new(cols[4].clone(), prefix_beg, start_number, page_count)?;
        if bates.end_number != end_number {
            return Err(FormatError::Parse {
                format: "concordance_dat_v1",
                detail: format!("ENDBATES {} does not match start+pgcount", cols[2]),
            });
        }
        let designation =
            ConfidentialityDesignation::from_label(&cols[5]).ok_or_else(|| FormatError::Parse {
                format: "concordance_dat_v1",
                detail: format!("unknown DESIGNATION {:?}", cols[5]),
            })?;
        let byte_length = cols[8].parse::<u64>().map_err(|_| FormatError::Parse {
            format: "concordance_dat_v1",
            detail: format!("invalid DOCSIZE {:?}", cols[8]),
        })?;
        let redacted = match cols[11].as_str() {
            "Y" => true,
            "N" => false,
            other => {
                return Err(FormatError::Parse {
                    format: "concordance_dat_v1",
                    detail: format!("invalid REDACTED flag {other:?}"),
                });
            }
        };
        let redaction_contract = if cols[12].is_empty() {
            None
        } else {
            Some(cols[12].clone())
        };
        let exhibit_labels = if cols[13].is_empty() {
            Vec::new()
        } else {
            cols[13].split(';').map(str::to_string).collect()
        };
        records.push(LoadFileRecord {
            doc_id: cols[0].clone(),
            document_oid_hex: cols[9].clone(),
            doc_commit_hex: cols[10].clone(),
            bates,
            designation,
            document_kind: cols[6].clone(),
            mime_type: cols[7].clone(),
            byte_length,
            redacted,
            redaction_contract,
            exhibit_labels,
            text_path: cols[14].clone(),
            native_path: cols[15].clone(),
        });
    }
    Ok(records)
}

/// Render a deterministic Opticon `.opt` page cross-reference load file (`opticon_opt_v1`).
pub fn write_opticon_opt(volume: &str, records: &[LoadFileRecord]) -> Result<String, FormatError> {
    if volume.trim().is_empty() || volume.contains(',') || volume.contains('\n') {
        return Err(FormatError::Parse {
            format: "opticon_opt_v1",
            detail: format!("invalid volume label {volume:?}"),
        });
    }
    let mut out = String::new();
    for rec in records {
        if rec.bates.page_count == 0
            || rec.bates.end_number < rec.bates.start_number
            || rec.bates.end_number - rec.bates.start_number + 1 != rec.bates.page_count
        {
            return Err(FormatError::Parse {
                format: "opticon_opt_v1",
                detail: format!("inconsistent Bates range on {}", rec.doc_id),
            });
        }
        for page_offset in 0..rec.bates.page_count {
            let page_num = rec.bates.start_number + page_offset;
            let page_bates = format!("{}-{page_num:08}", rec.bates.prefix);
            let image_path = format!("IMAGES\\{}\\{page_bates}.tif", rec.bates.matter_id);
            if page_offset == 0 {
                out.push_str(&format!(
                    "{page_bates},{volume},{image_path},Y,,,{}\n",
                    rec.bates.page_count
                ));
            } else {
                out.push_str(&format!("{page_bates},{volume},{image_path},N,,,\n"));
            }
        }
    }
    Ok(out)
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render a deterministic EDRM XML v1.2 discovery load file (`edrm_xml_v1`).
pub fn write_edrm_xml(
    batch_id: &str,
    matter_id: &str,
    bundle_digest_hex: &str,
    records: &[LoadFileRecord],
) -> Result<String, FormatError> {
    if batch_id.trim().is_empty() || matter_id.trim().is_empty() || bundle_digest_hex.len() != 64 {
        return Err(FormatError::Parse {
            format: "edrm_xml_v1",
            detail: "batch_id and matter_id must be non-empty and bundle_digest_hex must be 64 hex chars".into(),
        });
    }
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(
        "<Root MajorVersion=\"1\" MinorVersion=\"2\" Description=\"EDRM XML Load File\">\n",
    );
    xml.push_str(&format!(
        "  <Batch BatchID=\"{}\" MatterID=\"{}\" BundleDigestBlake3=\"{}\">\n",
        xml_escape(batch_id),
        xml_escape(matter_id),
        xml_escape(bundle_digest_hex),
    ));
    xml.push_str("    <Documents>\n");
    for rec in records {
        let beg = rec.bates.beg_bates();
        let end = rec.bates.end_bates();
        let contract = rec.redaction_contract.as_deref().unwrap_or("");
        let exhibits = rec.exhibit_labels.join(";");
        xml.push_str(&format!(
            "      <Document DocID=\"{}\" DocType=\"{}\" MimeType=\"{}\">\n",
            xml_escape(&rec.doc_id),
            xml_escape(&rec.document_kind),
            xml_escape(&rec.mime_type),
        ));
        xml.push_str("        <Fields>\n");
        xml.push_str(&format!(
            "          <Field Name=\"BegBates\" Value=\"{}\"/>\n",
            xml_escape(&beg)
        ));
        xml.push_str(&format!(
            "          <Field Name=\"EndBates\" Value=\"{}\"/>\n",
            xml_escape(&end)
        ));
        xml.push_str(&format!(
            "          <Field Name=\"PageCount\" Value=\"{}\"/>\n",
            rec.bates.page_count
        ));
        xml.push_str(&format!(
            "          <Field Name=\"MatterID\" Value=\"{}\"/>\n",
            xml_escape(&rec.bates.matter_id)
        ));
        xml.push_str(&format!(
            "          <Field Name=\"ConfidentialityDesignation\" Value=\"{}\"/>\n",
            xml_escape(rec.designation.label())
        ));
        xml.push_str(&format!(
            "          <Field Name=\"DocumentOid\" Value=\"{}\"/>\n",
            xml_escape(&rec.document_oid_hex)
        ));
        xml.push_str(&format!(
            "          <Field Name=\"Redacted\" Value=\"{}\"/>\n",
            if rec.redacted { "true" } else { "false" }
        ));
        xml.push_str(&format!(
            "          <Field Name=\"RedactionContract\" Value=\"{}\"/>\n",
            xml_escape(contract)
        ));
        xml.push_str(&format!(
            "          <Field Name=\"Exhibits\" Value=\"{}\"/>\n",
            xml_escape(&exhibits)
        ));
        xml.push_str("        </Fields>\n");
        xml.push_str("        <Files>\n");
        xml.push_str(&format!(
            "          <File FileType=\"Native\" Path=\"{}\" Size=\"{}\">\n",
            xml_escape(&rec.native_path),
            rec.byte_length,
        ));
        xml.push_str(&format!(
            "            <Hash Type=\"BLAKE3\">{}</Hash>\n",
            xml_escape(&rec.doc_commit_hex)
        ));
        xml.push_str("          </File>\n");
        xml.push_str(&format!(
            "          <File FileType=\"Text\" Path=\"{}\"/>\n",
            xml_escape(&rec.text_path)
        ));
        xml.push_str("        </Files>\n");
        xml.push_str("      </Document>\n");
    }
    xml.push_str("    </Documents>\n");
    xml.push_str("  </Batch>\n");
    xml.push_str("</Root>\n");
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records() -> Vec<LoadFileRecord> {
        vec![
            LoadFileRecord {
                doc_id: "DOC-0001".into(),
                document_oid_hex: "11".repeat(32),
                doc_commit_hex: "aa".repeat(32),
                bates: BatesRange::new("MATTER-2026-A", "ACME", 1, 3).unwrap(),
                designation: ConfidentialityDesignation::Confidential,
                document_kind: "Invoice".into(),
                mime_type: "application/pdf".into(),
                byte_length: 12_345,
                redacted: false,
                redaction_contract: None,
                exhibit_labels: vec!["Px-12".into()],
                text_path: "TEXT\\ACME-00000001.txt".into(),
                native_path: "NATIVES\\ACME-00000001.pdf".into(),
            },
            LoadFileRecord {
                doc_id: "DOC-0002".into(),
                document_oid_hex: "22".repeat(32),
                doc_commit_hex: "bb".repeat(32),
                bates: BatesRange::new("MATTER-2026-A", "ACME", 4, 2).unwrap(),
                designation: ConfidentialityDesignation::AttorneysEyesOnly,
                document_kind: "BankStatement".into(),
                mime_type: "application/pdf".into(),
                byte_length: 8_192,
                redacted: true,
                redaction_contract: Some("statement-account-block".into()),
                exhibit_labels: Vec::new(),
                text_path: "TEXT\\ACME-00000004.txt".into(),
                native_path: "NATIVES\\ACME-00000004.bin".into(),
            },
        ]
    }

    #[test]
    fn concordance_dat_round_trips_and_opticon_opt_matches_pages() {
        let recs = sample_records();
        let dat = write_concordance_dat(&recs).expect("write dat");
        let parsed = parse_concordance_dat(&dat).expect("parse dat");
        assert_eq!(parsed, recs);

        let opt = write_opticon_opt("VOL001", &recs).expect("write opt");
        let lines: Vec<&str> = opt.lines().collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(
            lines[0],
            "ACME-00000001,VOL001,IMAGES\\MATTER-2026-A\\ACME-00000001.tif,Y,,,3"
        );
        assert_eq!(
            lines[1],
            "ACME-00000002,VOL001,IMAGES\\MATTER-2026-A\\ACME-00000002.tif,N,,,"
        );
        assert_eq!(
            lines[3],
            "ACME-00000004,VOL001,IMAGES\\MATTER-2026-A\\ACME-00000004.tif,Y,,,2"
        );
    }

    #[test]
    fn edrm_xml_emits_deterministic_fields_and_blake3_hashes() {
        let recs = sample_records();
        let digest = "cc".repeat(32);
        let xml = write_edrm_xml("BATCH-01", "MATTER-2026-A", &digest, &recs).expect("edrm xml");
        assert!(xml.contains("BegBates\" Value=\"ACME-00000001\""));
        assert!(xml.contains("EndBates\" Value=\"ACME-00000003\""));
        assert!(xml.contains("ConfidentialityDesignation\" Value=\"ATTORNEYS&apos; EYES ONLY\""));
        assert!(xml.contains(&format!("<Hash Type=\"BLAKE3\">{}</Hash>", "aa".repeat(32))));
    }
}
