//! Bank feeds (`plaid` `transactions_sync`) and warehouse export (`snowflake`,
//! `bigquery`, `s3`) through `flywheel_connectors` (`fwc`) as a separate
//! supervised subprocess (plan §5.7, §9.5, §15, bead `fa-ff6`).
//!
//! Constitutional guarantees:
//! - No connector code or network/async runtime is linked into any FrankenAccounting
//!   crate closure; `fwc` runs as a separate process over stdio.
//! - Connector binary presence is detected explicitly; when `fwc` is absent, the
//!   adapter refuses with exit code `4` (`ENVIRONMENT`) and an actionable install
//!   hint — never fabricating a payload or receipt.
//! - Every raw `fwc` payload is content-addressed as a Docket `Document` with its
//!   receipt hash recorded; each parsed `BankLine` links via `DERIVED_FROM` to
//!   the raw payload `Document`; every warehouse export emits a canonical
//!   `WarehouseExportReceipt` control record.

use std::path::Path;
use std::process::Command;

use fa_model::{DecodeError, EncodeError, Oid, Reader, Writer, domain_digest};
use fa_money::{Amount, Side};
use fa_time::DateDay;
use fgdb_crypto::Hasher;

use crate::{
    FormatError, UnitCatalog,
    bank::{BankStatementExtract, ParsedBankLine, compute_bank_line_digest},
    hex_decode, hex_encode, parse_date_iso, parse_exact_decimal,
};

/// Vendored fixture payload for `fwc` Plaid `transactions_sync`.
pub const FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON: &str =
    include_str!("../corpora/fwc_plaid_transactions_sync_fixture.json");

/// Expected `fwc` robot envelope schema version.
pub const FWC_ROBOT_SCHEMA_VERSION: &str = "fwc.robot.v1";

/// Canonical format tag for `WarehouseExportReceipt` control records.
pub const WAREHOUSE_EXPORT_RECEIPT_FORMAT: &[u8] = b"fa:warehouse-export-receipt:v1";

/// Standard FrankenAccounting CLI/daemon environment exit code (`4`).
pub const EXIT_ENVIRONMENT: i32 = 4;

/// Typed environment refusal when the external `fwc` binary is missing or not executable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwcEnvironmentRefusal {
    pub code: &'static str,
    pub exit_code: i32,
    pub connector: String,
    pub binary: String,
    pub message: String,
    pub fix_hint: String,
}

impl core::fmt::Display for FwcEnvironmentRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "[{}] (exit {}) {}: {} — fix: {}",
            self.code, self.exit_code, self.connector, self.message, self.fix_hint
        )
    }
}

impl std::error::Error for FwcEnvironmentRefusal {}

/// Error returned by supervised `fwc` subprocess invocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FwcSubprocessError {
    /// `fwc` binary is missing or not executable (`exit 4`).
    Environment(FwcEnvironmentRefusal),
    /// Payload or receipt failed format validation.
    Format(FormatError),
}

impl core::fmt::Display for FwcSubprocessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Environment(e) => write!(f, "{e}"),
            Self::Format(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FwcSubprocessError {}

impl From<FormatError> for FwcSubprocessError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

/// Provenance edge linking a derived `BankLine` to its content-addressed raw `fwc` payload `Document`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwcDerivedBankLineLink {
    pub line_ordinal: u32,
    pub line_digest: [u8; 32],
    pub source_document_oid: Oid,
    pub relation: &'static str,
}

/// Certified result of importing a `fwc` Plaid `transactions_sync` feed payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwcBankFeedImportResult {
    pub payload_document_oid: Oid,
    pub fwc_receipt_hash: [u8; 32],
    pub robot_schema_version: String,
    pub extract: BankStatementExtract,
    pub derived_line_links: Vec<FwcDerivedBankLineLink>,
}

/// Supported warehouse export connectors via `fwc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarehouseConnector {
    Snowflake,
    BigQuery,
    S3,
}

impl WarehouseConnector {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Snowflake => "snowflake",
            Self::BigQuery => "bigquery",
            Self::S3 => "s3",
        }
    }

    pub const fn tag(self) -> u8 {
        match self {
            Self::Snowflake => 0,
            Self::BigQuery => 1,
            Self::S3 => 2,
        }
    }

    pub fn parse(raw: &str) -> Result<Self, FormatError> {
        match raw.trim() {
            "snowflake" => Ok(Self::Snowflake),
            "bigquery" => Ok(Self::BigQuery),
            "s3" => Ok(Self::S3),
            other => Err(FormatError::Parse {
                format: "fwc_warehouse_export_v1",
                detail: format!(
                    "unsupported warehouse connector {other:?}; expected snowflake, bigquery, or s3"
                ),
            }),
        }
    }

    fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Self::Snowflake),
            1 => Ok(Self::BigQuery),
            2 => Ok(Self::S3),
            other => Err(r.bad_tag("warehouse_connector", other)),
        }
    }
}

/// Journalable control record receipt for a certified report exported to a data warehouse via `fwc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarehouseExportReceipt {
    pub connector: WarehouseConnector,
    pub destination_ref: String,
    pub report_digest: [u8; 32],
    pub report_certificate_digest: [u8; 32],
    pub payload_document_oid: Oid,
    pub fwc_receipt_hash: [u8; 32],
    pub robot_schema_version: String,
}

impl WarehouseExportReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(WAREHOUSE_EXPORT_RECEIPT_FORMAT)
            .u8(self.connector.tag())
            .str(&self.destination_ref)
            .fixed(&self.report_digest)
            .fixed(&self.report_certificate_digest)
            .fixed(&self.payload_document_oid.0)
            .fixed(&self.fwc_receipt_hash)
            .str(&self.robot_schema_version);
        w.finish()
    }

    pub fn control_record_digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            WAREHOUSE_EXPORT_RECEIPT_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut r = Reader::new(bytes);
        let magic = r
            .fixed::<{ WAREHOUSE_EXPORT_RECEIPT_FORMAT.len() }>("warehouse_receipt.magic")
            .map_err(|e| FormatError::Parse {
                format: "fwc_warehouse_export_v1",
                detail: e.to_string(),
            })?;
        if magic != WAREHOUSE_EXPORT_RECEIPT_FORMAT {
            return Err(FormatError::Parse {
                format: "fwc_warehouse_export_v1",
                detail: "unknown warehouse export receipt header".into(),
            });
        }
        let map_dec = |e: DecodeError| FormatError::Parse {
            format: "fwc_warehouse_export_v1",
            detail: e.to_string(),
        };
        let connector_tag = r.u8("connector").map_err(map_dec)?;
        let connector = WarehouseConnector::from_tag(connector_tag, &r).map_err(map_dec)?;
        let destination_ref = r.str(256, "destination_ref").map_err(map_dec)?.to_string();
        let report_digest = r.fixed::<32>("report_digest").map_err(map_dec)?;
        let report_certificate_digest = r
            .fixed::<32>("report_certificate_digest")
            .map_err(map_dec)?;
        let payload_oid_bytes = r.fixed::<32>("payload_document_oid").map_err(map_dec)?;
        let fwc_receipt_hash = r.fixed::<32>("fwc_receipt_hash").map_err(map_dec)?;
        let robot_schema_version = r
            .str(64, "robot_schema_version")
            .map_err(map_dec)?
            .to_string();
        r.finish().map_err(map_dec)?;
        Ok(Self {
            connector,
            destination_ref,
            report_digest,
            report_certificate_digest,
            payload_document_oid: Oid(payload_oid_bytes),
            fwc_receipt_hash,
            robot_schema_version,
        })
    }
}

/// Compute the content-addressed Docket `Document` `Oid` for a raw `fwc` payload.
#[must_use]
pub fn compute_fwc_payload_document_oid(raw_payload: &[u8]) -> Oid {
    Oid(domain_digest(b"fa:docket:fwc-payload:v1", &[raw_payload]))
}

fn extract_json_string_field<'a>(
    block: &'a str,
    key: &str,
    format: &'static str,
) -> Result<&'a str, FormatError> {
    let pattern = format!("\"{key}\"");
    let pos = block.find(&pattern).ok_or_else(|| FormatError::Parse {
        format,
        detail: format!("missing required field `{key}`"),
    })?;
    let after_key = &block[pos + pattern.len()..];
    let colon = after_key.find(':').ok_or_else(|| FormatError::Parse {
        format,
        detail: format!("malformed field `{key}`: missing ':'"),
    })?;
    let val_part = after_key[colon + 1..].trim_start();
    if !val_part.starts_with('"') {
        let token_end = val_part
            .find(|c: char| c == ',' || c == '}' || c.is_ascii_whitespace())
            .unwrap_or(val_part.len());
        let token = &val_part[..token_end];
        if key == "amount" || key == "opening_balance" || key == "closing_balance" {
            return Err(FormatError::FloatForbidden {
                format,
                token: token.to_owned(),
            });
        }
        return Err(FormatError::Parse {
            format,
            detail: format!("field `{key}` must be a JSON string, got {token:?}"),
        });
    }
    let rest = &val_part[1..];
    let end_quote = rest.find('"').ok_or_else(|| FormatError::Parse {
        format,
        detail: format!("unterminated string in field `{key}`"),
    })?;
    Ok(&rest[..end_quote])
}

fn parse_32_byte_hex(
    hex_str: &str,
    _field: &str,
    format: &'static str,
) -> Result<[u8; 32], FormatError> {
    hex_decode(format, hex_str)
}

/// Parse an `fwc` Plaid `transactions_sync` payload into a [`FwcBankFeedImportResult`],
/// verifying the robot schema version, receipt hash, exact fixed-scale amounts,
/// internal balance continuity, and `BankLine` → `Document` (`DERIVED_FROM`) links.
pub fn parse_fwc_plaid_transactions_sync(
    payload_json: &str,
    units: &UnitCatalog,
) -> Result<FwcBankFeedImportResult, FormatError> {
    const FMT: &str = "fwc_plaid_transactions_sync_v1";

    let robot_schema_version =
        extract_json_string_field(payload_json, "robot_schema_version", FMT)?.to_owned();
    if robot_schema_version != FWC_ROBOT_SCHEMA_VERSION {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!(
                "unsupported robot_schema_version {robot_schema_version:?}; expected {FWC_ROBOT_SCHEMA_VERSION:?}"
            ),
        });
    }
    let connector = extract_json_string_field(payload_json, "connector", FMT)?;
    if connector != "plaid" {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!("expected connector \"plaid\", got {connector:?}"),
        });
    }
    let operation = extract_json_string_field(payload_json, "operation", FMT)?;
    if operation != "transactions_sync" {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!("expected operation \"transactions_sync\", got {operation:?}"),
        });
    }
    let receipt_hex = extract_json_string_field(payload_json, "receipt_hash", FMT)?;
    let fwc_receipt_hash = parse_32_byte_hex(receipt_hex, "receipt_hash", FMT)?;

    let account_id = extract_json_string_field(payload_json, "account_id", FMT)?.to_owned();
    let seq_str = extract_json_string_field(payload_json, "sequence_number", FMT)?;
    let sequence_number: u64 = seq_str.parse().map_err(|_| FormatError::Parse {
        format: FMT,
        detail: format!("invalid sequence_number {seq_str:?}"),
    })?;
    let currency = extract_json_string_field(payload_json, "currency", FMT)?.to_owned();
    let (unit_id, scale) =
        units
            .lookup_code(&currency)
            .ok_or_else(|| FormatError::UnknownUnit {
                format: FMT,
                unit: currency.clone(),
            })?;
    let statement_date = parse_date_iso(
        FMT,
        extract_json_string_field(payload_json, "statement_date", FMT)?,
    )?;
    let opening_balance = parse_exact_decimal(
        FMT,
        extract_json_string_field(payload_json, "opening_balance", FMT)?,
        scale,
    )?;
    let closing_balance = parse_exact_decimal(
        FMT,
        extract_json_string_field(payload_json, "closing_balance", FMT)?,
        scale,
    )?;

    let tx_key = "\"transactions\"";
    let tx_pos = payload_json
        .find(tx_key)
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "missing `transactions` array".into(),
        })?;
    let after_tx = &payload_json[tx_pos + tx_key.len()..];
    let arr_start = after_tx.find('[').ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "malformed `transactions` array".into(),
    })?;
    let arr_end = after_tx.rfind(']').ok_or_else(|| FormatError::Parse {
        format: FMT,
        detail: "unterminated `transactions` array".into(),
    })?;
    let arr_body = &after_tx[arr_start + 1..arr_end];

    let payload_document_oid = compute_fwc_payload_document_oid(payload_json.as_bytes());
    let mut lines = Vec::new();
    let mut derived_line_links = Vec::new();

    let mut cursor = arr_body;
    while let Some(obj_start) = cursor.find('{') {
        let after_start = &cursor[obj_start + 1..];
        let obj_end = after_start.find('}').ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "unterminated transaction object in `transactions`".into(),
        })?;
        let obj_str = &after_start[..obj_end];
        cursor = &after_start[obj_end + 1..];

        let _tx_id = extract_json_string_field(obj_str, "transaction_id", FMT)?;
        let booking_date = parse_date_iso(
            FMT,
            extract_json_string_field(obj_str, "booking_date", FMT)?,
        )?;
        let value_date =
            parse_date_iso(FMT, extract_json_string_field(obj_str, "value_date", FMT)?)?;
        let direction = extract_json_string_field(obj_str, "direction", FMT)?;
        let side = match direction {
            "credit" => Side::Credit,
            "debit" => Side::Debit,
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!(
                        "invalid direction {other:?}; expected \"credit\" or \"debit\""
                    ),
                });
            }
        };
        let amount_mantissa = parse_exact_decimal(
            FMT,
            extract_json_string_field(obj_str, "amount", FMT)?,
            scale,
        )?;
        let counterparty = extract_json_string_field(obj_str, "counterparty", FMT)?.to_owned();
        let reference = extract_json_string_field(obj_str, "reference", FMT)?.to_owned();

        let line_ordinal = (lines.len() as u32) + 1;
        let amount = Amount::new(unit_id, amount_mantissa);
        let line_digest = compute_bank_line_digest(
            &account_id,
            sequence_number,
            line_ordinal,
            booking_date,
            side,
            amount,
            &reference,
        );

        lines.push(ParsedBankLine {
            line_ordinal,
            booking_date,
            value_date,
            side,
            amount,
            counterparty,
            reference,
            line_digest,
        });
        derived_line_links.push(FwcDerivedBankLineLink {
            line_ordinal,
            line_digest,
            source_document_oid: payload_document_oid,
            relation: "DERIVED_FROM",
        });
    }

    let extract = BankStatementExtract {
        format_name: FMT,
        instrument_account_id: account_id,
        sequence_number,
        currency,
        statement_date,
        opening_balance,
        closing_balance,
        lines,
    };
    extract.verify_internal_balance()?;

    Ok(FwcBankFeedImportResult {
        payload_document_oid,
        fwc_receipt_hash,
        robot_schema_version,
        extract,
        derived_line_links,
    })
}

fn missing_fwc_refusal(binary: &Path, connector: &str, detail: &str) -> FwcEnvironmentRefusal {
    FwcEnvironmentRefusal {
        code: "FA-REF-094",
        exit_code: EXIT_ENVIRONMENT,
        connector: connector.to_owned(),
        binary: binary.display().to_string(),
        message: format!(
            "flywheel_connectors (`{}`) is not available ({detail})",
            binary.display()
        ),
        fix_hint: "install flywheel_connectors (`fwc`) on PATH or supply `--fwc-bin <path>`; external connector payloads and receipts are never fabricated".to_owned(),
    }
}

/// Invoke `fwc` as a separate supervised process to fetch bank transactions
/// (`fa bank fetch --connector plaid --account <id> --since <date>`).
///
/// If `fwc` is absent or cannot be executed, returns [`FwcSubprocessError::Environment`]
/// with `exit_code == 4` and the install hint — never a fake pass.
pub fn invoke_fwc_bank_fetch(
    fwc_bin: &Path,
    connector: &str,
    account_id: &str,
    since: DateDay,
    units: &UnitCatalog,
) -> Result<FwcBankFeedImportResult, FwcSubprocessError> {
    let since_str = since.to_string();
    let output = Command::new(fwc_bin)
        .args([
            "robot",
            "invoke",
            "--connector",
            connector,
            "--operation",
            "transactions_sync",
            "--account",
            account_id,
            "--since",
            &since_str,
        ])
        .output()
        .map_err(|err| {
            FwcSubprocessError::Environment(missing_fwc_refusal(
                fwc_bin,
                connector,
                &err.to_string(),
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FwcSubprocessError::Environment(missing_fwc_refusal(
            fwc_bin,
            connector,
            stderr.trim(),
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| FormatError::Parse {
        format: "fwc_plaid_transactions_sync_v1",
        detail: format!("fwc output is not valid UTF-8: {e}"),
    })?;
    Ok(parse_fwc_plaid_transactions_sync(&stdout, units)?)
}

/// Construct and validate a [`WarehouseExportReceipt`] control record from a certified
/// report payload, its certificate digest, and the `fwc` warehouse response JSON.
pub fn build_warehouse_export_receipt(
    connector: WarehouseConnector,
    destination_ref: &str,
    report_bytes: &[u8],
    report_certificate_digest: [u8; 32],
    fwc_response_json: &str,
) -> Result<WarehouseExportReceipt, FormatError> {
    const FMT: &str = "fwc_warehouse_export_v1";
    if destination_ref.trim().is_empty() {
        return Err(FormatError::Parse {
            format: FMT,
            detail: "destination_ref must not be empty".into(),
        });
    }
    let robot_schema_version =
        extract_json_string_field(fwc_response_json, "robot_schema_version", FMT)?.to_owned();
    if robot_schema_version != FWC_ROBOT_SCHEMA_VERSION {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!(
                "unsupported robot_schema_version {robot_schema_version:?}; expected {FWC_ROBOT_SCHEMA_VERSION:?}"
            ),
        });
    }
    let resp_connector = extract_json_string_field(fwc_response_json, "connector", FMT)?;
    if resp_connector != connector.as_str() {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!(
                "fwc warehouse receipt connector mismatch: expected {}, got {resp_connector}",
                connector.as_str()
            ),
        });
    }
    let receipt_hex = extract_json_string_field(fwc_response_json, "receipt_hash", FMT)?;
    let fwc_receipt_hash = parse_32_byte_hex(receipt_hex, "receipt_hash", FMT)?;

    let mut report_hasher = Hasher::new();
    report_hasher.update(b"fa:formats:certified-report:v1");
    report_hasher.update(report_bytes);
    let report_digest = report_hasher.finalize().0;

    let payload_document_oid = compute_fwc_payload_document_oid(fwc_response_json.as_bytes());

    Ok(WarehouseExportReceipt {
        connector,
        destination_ref: destination_ref.to_owned(),
        report_digest,
        report_certificate_digest,
        payload_document_oid,
        fwc_receipt_hash,
        robot_schema_version,
    })
}

/// Invoke `fwc` as a separate supervised process to export a certified report
/// to `snowflake`, `bigquery`, or `s3` (`fa export warehouse --connector <name> --report <cert>`).
///
/// If `fwc` is absent, returns [`FwcSubprocessError::Environment`] with `exit_code == 4`
/// and the install hint — never a fake pass.
pub fn invoke_fwc_warehouse_export(
    fwc_bin: &Path,
    connector: WarehouseConnector,
    destination_ref: &str,
    report_bytes: &[u8],
    report_certificate_digest: [u8; 32],
) -> Result<WarehouseExportReceipt, FwcSubprocessError> {
    let cert_hex = hex_encode(&report_certificate_digest);
    let output = Command::new(fwc_bin)
        .args([
            "robot",
            "export",
            "--connector",
            connector.as_str(),
            "--destination",
            destination_ref,
            "--certificate",
            &cert_hex,
        ])
        .output()
        .map_err(|err| {
            FwcSubprocessError::Environment(missing_fwc_refusal(
                fwc_bin,
                connector.as_str(),
                &err.to_string(),
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FwcSubprocessError::Environment(missing_fwc_refusal(
            fwc_bin,
            connector.as_str(),
            stderr.trim(),
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| FormatError::Parse {
        format: "fwc_warehouse_export_v1",
        detail: format!("fwc output is not valid UTF-8: {e}"),
    })?;
    Ok(build_warehouse_export_receipt(
        connector,
        destination_ref,
        report_bytes,
        report_certificate_digest,
        &stdout,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_plaid_transactions_sync_payload_parses_to_golden_bank_lines_and_links_document() {
        let units = UnitCatalog::embedded().unwrap();
        let result =
            parse_fwc_plaid_transactions_sync(FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON, &units)
                .unwrap();

        assert_eq!(result.robot_schema_version, "fwc.robot.v1");
        assert_eq!(
            hex_encode(&result.fwc_receipt_hash),
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        );
        assert_eq!(result.extract.instrument_account_id, "plaid-acct-chk-1010");
        assert_eq!(result.extract.sequence_number, 1);
        assert_eq!(result.extract.currency, "USD");
        assert_eq!(result.extract.opening_balance, 100_000);
        assert_eq!(result.extract.closing_balance, 125_000);
        assert_eq!(result.extract.lines.len(), 2);

        // Golden check on parsed BankLines:
        let l0 = &result.extract.lines[0];
        assert_eq!(l0.line_ordinal, 1);
        assert_eq!(l0.booking_date.to_string(), "2026-03-10");
        assert_eq!(l0.value_date.to_string(), "2026-03-11");
        assert_eq!(l0.side, Side::Credit);
        assert_eq!(l0.amount.mantissa, 50_000);
        assert_eq!(l0.counterparty, "Acme Corp");
        assert_eq!(l0.reference, "INV-100");

        let l1 = &result.extract.lines[1];
        assert_eq!(l1.line_ordinal, 2);
        assert_eq!(l1.booking_date.to_string(), "2026-03-15");
        assert_eq!(l1.value_date.to_string(), "2026-03-16");
        assert_eq!(l1.side, Side::Debit);
        assert_eq!(l1.amount.mantissa, 25_000);
        assert_eq!(l1.counterparty, "Cloud Hosting Inc");
        assert_eq!(l1.reference, "BILL-200");

        // Verify DERIVED_FROM links to the content-addressed payload Document:
        assert_eq!(result.derived_line_links.len(), 2);
        for (idx, link) in result.derived_line_links.iter().enumerate() {
            assert_eq!(link.source_document_oid, result.payload_document_oid);
            assert_eq!(link.line_digest, result.extract.lines[idx].line_digest);
            assert_eq!(link.relation, "DERIVED_FROM");
        }

        // Planted negative: unquoted float amount is refused with FloatForbidden.
        let bad_float = FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON
            .replace("\"amount\": \"500.00\"", "\"amount\": 500.00");
        assert!(matches!(
            parse_fwc_plaid_transactions_sync(&bad_float, &units),
            Err(FormatError::FloatForbidden { .. })
        ));
    }

    #[test]
    fn missing_fwc_binary_returns_exit_4_environment_refusal_with_install_hint_never_fake() {
        let units = UnitCatalog::embedded().unwrap();
        let nonexistent = Path::new("/nonexistent/bin/fwc-does-not-exist");
        let err = invoke_fwc_bank_fetch(
            nonexistent,
            "plaid",
            "plaid-acct-chk-1010",
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            &units,
        )
        .unwrap_err();

        match err {
            FwcSubprocessError::Environment(refusal) => {
                assert_eq!(refusal.exit_code, 4);
                assert_eq!(refusal.code, "FA-REF-094");
                assert_eq!(refusal.connector, "plaid");
                assert!(
                    refusal
                        .fix_hint
                        .contains("install flywheel_connectors (`fwc`)")
                );
                println!("fwc_missing_bank_fetch_refusal={refusal}");
            }
            other => panic!("expected Environment refusal (exit 4), got: {other:?}"),
        }

        let wh_err = invoke_fwc_warehouse_export(
            nonexistent,
            WarehouseConnector::Snowflake,
            "SNOWFLAKE.FINANCE.CERTIFIED_REPORTS",
            b"certified-report-bytes",
            [0xAA; 32],
        )
        .unwrap_err();

        match wh_err {
            FwcSubprocessError::Environment(refusal) => {
                assert_eq!(refusal.exit_code, 4);
                assert_eq!(refusal.connector, "snowflake");
                assert!(
                    refusal
                        .fix_hint
                        .contains("install flywheel_connectors (`fwc`)")
                );
                println!("fwc_missing_warehouse_export_refusal={refusal}");
            }
            other => panic!("expected Environment refusal (exit 4), got: {other:?}"),
        }
    }

    #[test]
    fn warehouse_export_receipt_round_trips_as_control_record_for_snowflake_bigquery_and_s3() {
        for (connector, dest) in [
            (
                WarehouseConnector::Snowflake,
                "SNOWFLAKE.FINANCE.CERTIFIED_REPORTS",
            ),
            (
                WarehouseConnector::BigQuery,
                "bq://acme-prod/finance/certified_reports",
            ),
            (
                WarehouseConnector::S3,
                "s3://acme-audit-archive/2026Q1/tb.cert",
            ),
        ] {
            let fwc_resp = format!(
                r#"{{
  "robot_schema_version": "fwc.robot.v1",
  "connector": "{}",
  "receipt_hash": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
}}"#,
                connector.as_str()
            );
            let receipt = build_warehouse_export_receipt(
                connector,
                dest,
                b"certified-statement-bytes-v1",
                [0x42; 32],
                &fwc_resp,
            )
            .unwrap();

            let bytes = receipt.canonical_bytes().unwrap();
            let decoded = WarehouseExportReceipt::decode_canonical(&bytes).unwrap();
            assert_eq!(decoded, receipt);
            let control_oid = receipt.control_record_digest().unwrap();
            println!(
                "warehouse_export_receipt connector={} dest={} control_oid={:?}",
                connector.as_str(),
                dest,
                hex_encode(&control_oid.0)
            );
        }
    }
}
