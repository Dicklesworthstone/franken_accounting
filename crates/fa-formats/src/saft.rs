//! OECD SAF-T v2.0 XML audit file writer and round-trip reader with
//! coordinate certificate and `FA-INV-04` refold verification (plan §16.3,
//! bead `fa-npi`).

use fa_model::EntryClass;
use fa_money::{Amount, Side};

use crate::{
    ExportCoordinate, FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal,
    FormatLeg, UnitCatalog, format_account_type, format_date_iso, format_exact_decimal, hex_decode,
    hex_encode, parse_account_type, parse_date_iso, parse_exact_decimal,
};

const FMT: &str = "oecd_saft_v2";

/// Write a [`FormatJournal`] as a canonical OECD SAF-T v2.0 XML document.
pub fn write_saft_xml(journal: &FormatJournal) -> Result<String, FormatError> {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<AuditFile xmlns=\"urn:OECD:StandardAuditFile-Taxation/2.00\">\n");
    xml.push_str("  <Header>\n");
    xml.push_str("    <AuditFileVersion>2.00</AuditFileVersion>\n");
    xml.push_str(&format!(
        "    <CompanyName>{}</CompanyName>\n",
        xml_escape(&journal.coordinate.book_name)
    ));
    xml.push_str(&format!(
        "    <DefaultCurrencyCode>{}</DefaultCurrencyCode>\n",
        xml_escape(&journal.coordinate.base_unit_code)
    ));
    xml.push_str(&format!(
        "    <DefaultCurrencyScale>{}</DefaultCurrencyScale>\n",
        journal.coordinate.base_unit_scale
    ));
    xml.push_str(&format!(
        "    <SelectionEndDate>{}</SelectionEndDate>\n",
        format_date_iso(journal.coordinate.effective_through)
    ));
    xml.push_str(&format!(
        "    <KnownAtSeq>{}</KnownAtSeq>\n",
        journal.coordinate.known_at_seq
    ));
    xml.push_str(&format!(
        "    <ContentDigest>{}</ContentDigest>\n",
        hex_encode(&journal.coordinate.content_digest)
    ));
    xml.push_str(&format!(
        "    <CertificateDigest>{}</CertificateDigest>\n",
        hex_encode(&journal.coordinate.certificate_digest)
    ));
    xml.push_str("  </Header>\n");

    xml.push_str("  <MasterFiles>\n");
    xml.push_str("    <GeneralLedgerAccounts>\n");
    for acct in &journal.accounts {
        let side_str = match acct.normal_side {
            Side::Debit => "Debit",
            Side::Credit => "Credit",
        };
        xml.push_str("      <Account>\n");
        xml.push_str(&format!(
            "        <AccountID>{}</AccountID>\n",
            xml_escape(&acct.code)
        ));
        xml.push_str(&format!(
            "        <AccountDescription>{}</AccountDescription>\n",
            xml_escape(&acct.name)
        ));
        xml.push_str(&format!(
            "        <AccountType>{}</AccountType>\n",
            format_account_type(acct.account_type)
        ));
        xml.push_str(&format!("        <NormalSide>{side_str}</NormalSide>\n"));
        xml.push_str("      </Account>\n");
    }
    xml.push_str("    </GeneralLedgerAccounts>\n");
    xml.push_str("    <BalanceAssertions>\n");
    for asrt in &journal.assertions {
        let side_str = match asrt.side {
            Side::Debit => "Debit",
            Side::Credit => "Credit",
        };
        let amt_str = format_exact_decimal(asrt.amount.mantissa, asrt.unit_scale);
        xml.push_str("      <Assertion>\n");
        xml.push_str(&format!(
            "        <AccountID>{}</AccountID>\n",
            xml_escape(&asrt.account_code)
        ));
        xml.push_str(&format!(
            "        <AsOfDate>{}</AsOfDate>\n",
            format_date_iso(asrt.as_of)
        ));
        xml.push_str(&format!("        <Side>{side_str}</Side>\n"));
        xml.push_str(&format!("        <Amount>{amt_str}</Amount>\n"));
        xml.push_str(&format!(
            "        <CurrencyCode>{}</CurrencyCode>\n",
            xml_escape(&asrt.unit_code)
        ));
        xml.push_str("      </Assertion>\n");
    }
    xml.push_str("    </BalanceAssertions>\n");
    xml.push_str("  </MasterFiles>\n");

    xml.push_str("  <GeneralLedgerEntries>\n");
    xml.push_str(&format!(
        "    <NumberOfEntries>{}</NumberOfEntries>\n",
        journal.entries.len()
    ));
    for entry in &journal.entries {
        xml.push_str("    <Transaction>\n");
        xml.push_str(&format!(
            "      <TransactionID>{}</TransactionID>\n",
            xml_escape(&entry.entry_id)
        ));
        xml.push_str(&format!(
            "      <TransactionDate>{}</TransactionDate>\n",
            format_date_iso(entry.effective_date)
        ));
        xml.push_str(&format!(
            "      <RecordedSeq>{}</RecordedSeq>\n",
            entry.recorded_seq
        ));
        xml.push_str(&format!(
            "      <EntryClass>{}</EntryClass>\n",
            entry.class.0
        ));
        xml.push_str(&format!(
            "      <Description>{}</Description>\n",
            xml_escape(&entry.description)
        ));
        if let Some(mig) = &entry.migrated_from {
            xml.push_str(&format!(
                "      <MigratedFrom>{}</MigratedFrom>\n",
                xml_escape(mig)
            ));
        }
        for (idx, leg) in entry.legs.iter().enumerate() {
            let side_tag = match leg.side {
                Side::Debit => "DebitAmount",
                Side::Credit => "CreditAmount",
            };
            let amt_str = format_exact_decimal(leg.amount.mantissa, leg.unit_scale);
            xml.push_str("      <Line>\n");
            xml.push_str(&format!("        <RecordID>{}</RecordID>\n", idx + 1));
            xml.push_str(&format!(
                "        <AccountID>{}</AccountID>\n",
                xml_escape(&leg.account_code)
            ));
            xml.push_str(&format!("        <{side_tag}>{amt_str}</{side_tag}>\n"));
            xml.push_str(&format!(
                "        <CurrencyCode>{}</CurrencyCode>\n",
                xml_escape(&leg.unit_code)
            ));
            if let Some(memo) = &leg.memo {
                xml.push_str(&format!("        <Memo>{}</Memo>\n", xml_escape(memo)));
            }
            xml.push_str("      </Line>\n");
        }
        xml.push_str("    </Transaction>\n");
    }
    xml.push_str("  </GeneralLedgerEntries>\n");
    xml.push_str("</AuditFile>\n");
    Ok(xml)
}

/// Read an OECD SAF-T v2.0 XML audit file back into a [`FormatJournal`],
/// verifying `<NumberOfEntries>`, per-entry balance (`FA-INV-01`), and the
/// coordinate certificate.
pub fn read_saft_xml(xml: &str, units: &UnitCatalog) -> Result<FormatJournal, FormatError> {
    let header_block = extract_first_block(FMT, xml, "Header")?;
    let book_name = xml_unescape(extract_first_block(FMT, header_block, "CompanyName")?);
    let base_unit_code = xml_unescape(extract_first_block(
        FMT,
        header_block,
        "DefaultCurrencyCode",
    )?);
    let base_unit_scale: u8 = extract_first_block(FMT, header_block, "DefaultCurrencyScale")?
        .trim()
        .parse()
        .map_err(|_| FormatError::Parse {
            format: FMT,
            detail: "invalid DefaultCurrencyScale".to_owned(),
        })?;
    let effective_through = parse_date_iso(
        FMT,
        extract_first_block(FMT, header_block, "SelectionEndDate")?,
    )?;
    let known_at_seq: u64 = extract_first_block(FMT, header_block, "KnownAtSeq")?
        .trim()
        .parse()
        .map_err(|_| FormatError::Parse {
            format: FMT,
            detail: "invalid KnownAtSeq".to_owned(),
        })?;
    let expected_content = hex_decode(
        FMT,
        extract_first_block(FMT, header_block, "ContentDigest")?,
    )?;
    let expected_cert = hex_decode(
        FMT,
        extract_first_block(FMT, header_block, "CertificateDigest")?,
    )?;

    let master_block = extract_first_block(FMT, xml, "MasterFiles")?;
    let gl_accts_block = extract_first_block(FMT, master_block, "GeneralLedgerAccounts")?;
    let mut accounts = Vec::new();
    for acct_block in extract_all_blocks(gl_accts_block, "Account") {
        let code = xml_unescape(extract_first_block(FMT, acct_block, "AccountID")?);
        let name = xml_unescape(extract_first_block(FMT, acct_block, "AccountDescription")?);
        let account_type =
            parse_account_type(FMT, extract_first_block(FMT, acct_block, "AccountType")?)?;
        let normal_side = match extract_first_block(FMT, acct_block, "NormalSide")?.trim() {
            "Debit" => Side::Debit,
            "Credit" => Side::Credit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid NormalSide {other:?}"),
                });
            }
        };
        accounts.push(FormatAccount {
            code,
            name,
            account_type,
            normal_side,
        });
    }

    let mut assertions = Vec::new();
    if let Ok(asrt_parent) = extract_first_block(FMT, master_block, "BalanceAssertions") {
        for ab in extract_all_blocks(asrt_parent, "Assertion") {
            let account_code = xml_unescape(extract_first_block(FMT, ab, "AccountID")?);
            let as_of = parse_date_iso(FMT, extract_first_block(FMT, ab, "AsOfDate")?)?;
            let side = match extract_first_block(FMT, ab, "Side")?.trim() {
                "Debit" => Side::Debit,
                "Credit" => Side::Credit,
                other => {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid Assertion Side {other:?}"),
                    });
                }
            };
            let unit_code = xml_unescape(extract_first_block(FMT, ab, "CurrencyCode")?);
            let (unit_id, unit_scale) =
                units
                    .lookup_code(&unit_code)
                    .ok_or_else(|| FormatError::UnknownUnit {
                        format: FMT,
                        unit: unit_code.clone(),
                    })?;
            let mantissa =
                parse_exact_decimal(FMT, extract_first_block(FMT, ab, "Amount")?, unit_scale)?;
            assertions.push(FormatAssertion {
                account_code,
                as_of,
                side,
                amount: Amount::new(unit_id, mantissa),
                unit_code,
                unit_scale,
            });
        }
    }

    let gl_entries_block = extract_first_block(FMT, xml, "GeneralLedgerEntries")?;
    let declared_count: usize = extract_first_block(FMT, gl_entries_block, "NumberOfEntries")?
        .trim()
        .parse()
        .map_err(|_| FormatError::Parse {
            format: FMT,
            detail: "invalid NumberOfEntries".to_owned(),
        })?;
    let mut entries = Vec::new();
    for tx_block in extract_all_blocks(gl_entries_block, "Transaction") {
        let entry_id = xml_unescape(extract_first_block(FMT, tx_block, "TransactionID")?);
        let effective_date =
            parse_date_iso(FMT, extract_first_block(FMT, tx_block, "TransactionDate")?)?;
        let recorded_seq: u64 = extract_first_block(FMT, tx_block, "RecordedSeq")?
            .trim()
            .parse()
            .map_err(|_| FormatError::Parse {
                format: FMT,
                detail: "invalid RecordedSeq".to_owned(),
            })?;
        let class_tag: u16 = extract_first_block(FMT, tx_block, "EntryClass")?
            .trim()
            .parse()
            .map_err(|_| FormatError::Parse {
                format: FMT,
                detail: "invalid EntryClass".to_owned(),
            })?;
        let description = xml_unescape(extract_first_block(FMT, tx_block, "Description")?);
        let migrated_from = extract_first_block(FMT, tx_block, "MigratedFrom")
            .ok()
            .map(xml_unescape);

        let mut legs = Vec::new();
        for line_block in extract_all_blocks(tx_block, "Line") {
            let account_code = xml_unescape(extract_first_block(FMT, line_block, "AccountID")?);
            let unit_code = xml_unescape(extract_first_block(FMT, line_block, "CurrencyCode")?);
            let (unit_id, unit_scale) =
                units
                    .lookup_code(&unit_code)
                    .ok_or_else(|| FormatError::UnknownUnit {
                        format: FMT,
                        unit: unit_code.clone(),
                    })?;
            let (side, amt_str) =
                if let Ok(dr) = extract_first_block(FMT, line_block, "DebitAmount") {
                    (Side::Debit, dr)
                } else if let Ok(cr) = extract_first_block(FMT, line_block, "CreditAmount") {
                    (Side::Credit, cr)
                } else {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("Line on {account_code} missing DebitAmount/CreditAmount"),
                    });
                };
            let mantissa = parse_exact_decimal(FMT, amt_str, unit_scale)?;
            let memo = extract_first_block(FMT, line_block, "Memo")
                .ok()
                .map(xml_unescape);
            legs.push(FormatLeg {
                account_code,
                side,
                amount: Amount::new(unit_id, mantissa),
                unit_code,
                unit_scale,
                memo,
            });
        }
        entries.push(FormatEntry {
            entry_id,
            effective_date,
            recorded_seq,
            class: EntryClass(class_tag),
            description,
            migrated_from,
            legs,
        });
    }

    if entries.len() != declared_count {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!(
                "NumberOfEntries mismatch: header declares {declared_count}, found {}",
                entries.len()
            ),
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
        account_scope: None,
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

pub(crate) fn extract_first_block<'a>(
    format: &'static str,
    src: &'a str,
    tag: &str,
) -> Result<&'a str, FormatError> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = src.find(&open).ok_or_else(|| FormatError::Parse {
        format,
        detail: format!("missing opening tag <{tag}>"),
    })? + open.len();
    let end_rel = src[start..]
        .find(&close)
        .ok_or_else(|| FormatError::Parse {
            format,
            detail: format!("missing closing tag </{tag}>"),
        })?;
    Ok(&src[start..start + end_rel])
}

pub(crate) fn extract_all_blocks<'a>(src: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(s) = rest.find(&open) {
        let after_open = &rest[s + open.len()..];
        let Some(e) = after_open.find(&close) else {
            break;
        };
        out.push(&after_open[..e]);
        rest = &after_open[e + close.len()..];
    }
    out
}

pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn xml_unescape(s: &str) -> String {
    s.trim()
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}
