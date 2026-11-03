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
//!
//! The parser accepts the normalized `fwc.robot.v1` envelope illustrated by
//! the retained fixture, with exact declared envelope and transaction fields.
//! This is not the raw Plaid API schema. Parsing checks source representation,
//! exact amounts and continuity; it does not authenticate a live connector or
//! establish that its declared receipt hash was issued by an external service.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use fa_model::json::{Json, parse};
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

fn parse_json_document(text: &str, format: &'static str) -> Result<Json, FormatError> {
    parse(text).map_err(|error| {
        // The shared integer-only decoder rejects these tokens before it can
        // produce a tree. Keep the established FloatForbidden diagnostic;
        // this byte span is only for reporting an already refused token and
        // never substitutes for structural JSON decoding or money parsing.
        if error
            .message
            .starts_with("fractional or exponent numbers are not accepted;")
        {
            let bytes = text.as_bytes();
            let mut start = error.offset;
            while start > 0 && matches!(bytes[start - 1], b'0'..=b'9' | b'-') {
                start -= 1;
            }
            let mut end = error.offset;
            while end < bytes.len()
                && !matches!(
                    bytes[end],
                    b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t'
                )
            {
                end += 1;
            }
            FormatError::FloatForbidden {
                format,
                token: text[start..end].to_owned(),
            }
        } else {
            FormatError::Parse {
                format,
                detail: error.to_string(),
            }
        }
    })
}

fn exact_json_object(
    value: &Json,
    required: &[&str],
    context: &str,
    format: &'static str,
) -> Result<(), FormatError> {
    let Json::Obj(fields) = value else {
        return Err(FormatError::Parse {
            format,
            detail: format!("{context} must be a JSON object"),
        });
    };
    for (key, _) in fields {
        if !required.contains(&key.as_str()) {
            return Err(FormatError::Parse {
                format,
                detail: format!("unsupported field `{key}` in {context}"),
            });
        }
    }
    for key in required {
        if value.get(key).is_none() {
            return Err(FormatError::Parse {
                format,
                detail: format!("missing required field `{key}` in {context}"),
            });
        }
    }
    Ok(())
}

fn json_string_field<'a>(
    object: &'a Json,
    key: &str,
    format: &'static str,
) -> Result<&'a str, FormatError> {
    let value = object.get(key).ok_or_else(|| FormatError::Parse {
        format,
        detail: format!("missing required field `{key}`"),
    })?;
    value.as_str().ok_or_else(|| {
        if key == "amount" || key == "opening_balance" || key == "closing_balance" {
            FormatError::FloatForbidden {
                format,
                token: value.render(),
            }
        } else {
            FormatError::Parse {
                format,
                detail: format!(
                    "field `{key}` must be a JSON string, got {}",
                    value.render()
                ),
            }
        }
    })
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
    let payload = parse_json_document(payload_json, FMT)?;
    exact_json_object(
        &payload,
        &[
            "robot_schema_version",
            "connector",
            "operation",
            "receipt_hash",
            "account_id",
            "sequence_number",
            "currency",
            "statement_date",
            "opening_balance",
            "closing_balance",
            "transactions",
        ],
        "normalized bank feed envelope",
        FMT,
    )?;

    let robot_schema_version = json_string_field(&payload, "robot_schema_version", FMT)?.to_owned();
    if robot_schema_version != FWC_ROBOT_SCHEMA_VERSION {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!(
                "unsupported robot_schema_version {robot_schema_version:?}; expected {FWC_ROBOT_SCHEMA_VERSION:?}"
            ),
        });
    }
    let connector = json_string_field(&payload, "connector", FMT)?;
    if connector != "plaid" {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!("expected connector \"plaid\", got {connector:?}"),
        });
    }
    let operation = json_string_field(&payload, "operation", FMT)?;
    if operation != "transactions_sync" {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!("expected operation \"transactions_sync\", got {operation:?}"),
        });
    }
    let receipt_hex = json_string_field(&payload, "receipt_hash", FMT)?;
    let fwc_receipt_hash = parse_32_byte_hex(receipt_hex, "receipt_hash", FMT)?;

    let account_id = json_string_field(&payload, "account_id", FMT)?.to_owned();
    let seq_str = json_string_field(&payload, "sequence_number", FMT)?;
    let sequence_number: u64 = seq_str.parse().map_err(|_| FormatError::Parse {
        format: FMT,
        detail: format!("invalid sequence_number {seq_str:?}"),
    })?;
    let currency = json_string_field(&payload, "currency", FMT)?.to_owned();
    let (unit_id, scale) =
        units
            .lookup_code(&currency)
            .ok_or_else(|| FormatError::UnknownUnit {
                format: FMT,
                unit: currency.clone(),
            })?;
    let statement_date = parse_date_iso(FMT, json_string_field(&payload, "statement_date", FMT)?)?;
    let opening_balance = parse_exact_decimal(
        FMT,
        json_string_field(&payload, "opening_balance", FMT)?,
        scale,
    )?;
    let closing_balance = parse_exact_decimal(
        FMT,
        json_string_field(&payload, "closing_balance", FMT)?,
        scale,
    )?;

    let transactions = payload
        .get("transactions")
        .and_then(Json::as_arr)
        .ok_or_else(|| FormatError::Parse {
            format: FMT,
            detail: "`transactions` must be a JSON array".into(),
        })?;

    let payload_document_oid = compute_fwc_payload_document_oid(payload_json.as_bytes());
    let mut lines = Vec::new();
    let mut derived_line_links = Vec::new();
    let mut transaction_ids = BTreeSet::new();

    for (index, transaction) in transactions.iter().enumerate() {
        exact_json_object(
            transaction,
            &[
                "transaction_id",
                "booking_date",
                "value_date",
                "direction",
                "amount",
                "counterparty",
                "reference",
            ],
            &format!("transaction {}", index + 1),
            FMT,
        )?;
        let transaction_id = json_string_field(transaction, "transaction_id", FMT)?;
        if transaction_id.is_empty() || !transaction_ids.insert(transaction_id) {
            return Err(FormatError::Parse {
                format: FMT,
                detail: "transaction_id must be nonempty and unique within the feed".into(),
            });
        }
        let booking_date =
            parse_date_iso(FMT, json_string_field(transaction, "booking_date", FMT)?)?;
        let value_date = parse_date_iso(FMT, json_string_field(transaction, "value_date", FMT)?)?;
        let direction = json_string_field(transaction, "direction", FMT)?;
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
        let amount_mantissa =
            parse_exact_decimal(FMT, json_string_field(transaction, "amount", FMT)?, scale)?;
        let counterparty = json_string_field(transaction, "counterparty", FMT)?.to_owned();
        let reference = json_string_field(transaction, "reference", FMT)?.to_owned();

        let line_ordinal = u32::try_from(index)
            .ok()
            .and_then(|ordinal| ordinal.checked_add(1))
            .ok_or_else(|| FormatError::Overflow {
                format: FMT,
                detail: "bank line ordinal overflow".into(),
            })?;
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
    let payload = fetch_fwc_payload(fwc_bin, connector, account_id, since)?;
    Ok(parse_fwc_plaid_transactions_sync(&payload, units)?)
}

/// The raw `transactions_sync` robot payload `fwc` prints for `connector`'s
/// `account_id` since `since`: the exact bytes a retained statement keeps
/// (`fa bank fetch`), unparsed. A missing or failing `fwc` is
/// [`FwcSubprocessError::Environment`] (`exit 4`), never a fabricated payload.
pub fn fetch_fwc_payload(
    fwc_bin: &Path,
    connector: &str,
    account_id: &str,
    since: DateDay,
) -> Result<String, FwcSubprocessError> {
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
    Ok(stdout)
}

/// Construct and validate a [`WarehouseExportReceipt`] control record from a certified
/// report payload, its certificate digest, and the `fwc` warehouse response JSON.
/// The normalized response has exactly `robot_schema_version`, `connector` and
/// `receipt_hash`; the raw response bytes remain the content-addressed source.
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
    let response = parse_json_document(fwc_response_json, FMT)?;
    exact_json_object(
        &response,
        &["robot_schema_version", "connector", "receipt_hash"],
        "normalized warehouse receipt envelope",
        FMT,
    )?;
    let robot_schema_version =
        json_string_field(&response, "robot_schema_version", FMT)?.to_owned();
    if robot_schema_version != FWC_ROBOT_SCHEMA_VERSION {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!(
                "unsupported robot_schema_version {robot_schema_version:?}; expected {FWC_ROBOT_SCHEMA_VERSION:?}"
            ),
        });
    }
    let resp_connector = json_string_field(&response, "connector", FMT)?;
    if resp_connector != connector.as_str() {
        return Err(FormatError::Parse {
            format: FMT,
            detail: format!(
                "fwc warehouse receipt connector mismatch: expected {}, got {resp_connector}",
                connector.as_str()
            ),
        });
    }
    let receipt_hex = json_string_field(&response, "receipt_hash", FMT)?;
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

    fn replace_field(object: &mut Json, key: &str, value: Json) {
        let Json::Obj(fields) = object else {
            panic!("fixture field owner must be an object");
        };
        fields.iter_mut().find(|(name, _)| name == key).unwrap().1 = value;
    }

    fn edit_fixture_transactions(edit: impl FnOnce(&mut Vec<Json>)) -> String {
        let mut payload = parse(FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON).unwrap();
        let Json::Obj(fields) = &mut payload else {
            panic!("fixture envelope must be an object");
        };
        let Json::Arr(transactions) = &mut fields
            .iter_mut()
            .find(|(key, _)| key == "transactions")
            .unwrap()
            .1
        else {
            panic!("fixture transactions must be an array");
        };
        edit(transactions);
        payload.render()
    }

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
    fn normalized_plaid_json_preserves_escaped_text_and_raw_source_links() {
        let units = UnitCatalog::embedded().unwrap();
        let escaped = FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON
            .replace(
                r#""Acme Corp""#,
                r#""Acme \"Holdings\" \u00e9 \ud83d\ude80 } { [ ]""#,
            )
            .replace(
                r#""INV-100""#,
                r#""INV\\archive\/\u0037\" [transactions] } {""#,
            )
            .replace(r#""Cloud Hosting Inc""#, r#""Cloud {region} \"EU\"""#)
            .replace(r#""BILL-200""#, r#""BILL\n200\t\u20ac""#);
        let result = parse_fwc_plaid_transactions_sync(&escaped, &units).unwrap();
        assert_eq!(result.extract.lines.len(), 2);
        assert_eq!(
            result.extract.lines[0].counterparty,
            "Acme \"Holdings\" é 🚀 } { [ ]"
        );
        assert_eq!(
            result.extract.lines[0].reference,
            "INV\\archive/7\" [transactions] } {"
        );
        assert_eq!(
            result.extract.lines[1].counterparty,
            "Cloud {region} \"EU\""
        );
        assert_eq!(result.extract.lines[1].reference, "BILL\n200\t€");
        assert_eq!(result.extract.lines[0].amount.mantissa, 50_000);
        assert_eq!(result.extract.lines[1].amount.mantissa, 25_000);
        assert_eq!(result.extract.closing_balance, 125_000);

        let literal = escaped
            .replace(r"\u00e9", "é")
            .replace(r"\ud83d\ude80", "🚀")
            .replace(r"\u0037", "7")
            .replace(r"\u20ac", "€");
        let equivalent = parse_fwc_plaid_transactions_sync(&literal, &units).unwrap();
        assert_eq!(equivalent.extract, result.extract);
        assert_eq!(equivalent.fwc_receipt_hash, result.fwc_receipt_hash);
        assert_ne!(equivalent.payload_document_oid, result.payload_document_oid);
        for (payload, feed) in [(&escaped, &result), (&literal, &equivalent)] {
            assert_eq!(
                feed.payload_document_oid,
                compute_fwc_payload_document_oid(payload.as_bytes())
            );
            assert_eq!(feed.derived_line_links.len(), 2);
            for (index, link) in feed.derived_line_links.iter().enumerate() {
                assert_eq!(link.line_ordinal, u32::try_from(index + 1).unwrap());
                assert_eq!(link.source_document_oid, feed.payload_document_oid);
                assert_eq!(link.line_digest, feed.extract.lines[index].line_digest);
                assert_eq!(link.relation, "DERIVED_FROM");
            }
        }
    }

    #[test]
    fn normalized_plaid_json_requires_exact_field_scope_and_types() {
        let units = UnitCatalog::embedded().unwrap();
        let fixture = FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON;
        let cases = [
            format!("[{fixture}]"),
            format!(r#"{{"payload":{fixture}}}"#),
            fixture
                .replace("  \"connector\": \"plaid\",\n", "")
                .replace(
                    r#""account_id": "plaid-acct-chk-1010""#,
                    r#""account_id": {"connector":"plaid"}"#,
                ),
            fixture.replace(
                r#""amount": "500.00","#,
                r#""metadata": {"amount":"500.00"},"#,
            ),
            fixture.replace(r#""connector": "plaid""#, r#""connector": ["plaid"]"#),
            fixture.replace(r#""sequence_number": "1""#, r#""sequence_number": 1"#),
            fixture.replace(r#""counterparty": "Acme Corp""#, r#""counterparty": null"#),
            fixture.replace(r#""reference": "INV-100""#, r#""reference": true"#),
            fixture.replace(r#""value_date": "2026-03-11""#, r#""value_date": {}"#),
        ];
        for (index, payload) in cases.iter().enumerate() {
            assert!(
                matches!(
                    parse_fwc_plaid_transactions_sync(payload, &units),
                    Err(FormatError::Parse { .. })
                ),
                "accepted wrong-scope/type case {index}"
            );
        }

        let mut payload = parse(fixture).unwrap();
        for wrong_type in [Json::Null, Json::Str("[]".into()), Json::Obj(Vec::new())] {
            replace_field(&mut payload, "transactions", wrong_type);
            assert!(matches!(
                parse_fwc_plaid_transactions_sync(&payload.render(), &units),
                Err(FormatError::Parse { .. })
            ));
        }
    }

    #[test]
    fn normalized_plaid_json_rejects_malformed_duplicate_and_trailing_data() {
        let units = UnitCatalog::embedded().unwrap();
        let fixture = FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON;
        let cases = [
            format!("{fixture} {{}}"),
            format!("{fixture} null"),
            fixture.replace("},\n    {", "}\n    {"),
            fixture.replace("\n  ]", ",\n  ]"),
            fixture.replace(r#""Acme Corp""#, r#""Acme\q""#),
            fixture.replace(r#""Acme Corp""#, r#""Acme\uD800""#),
            fixture.replace(r#""Acme Corp""#, r#""Acme\uDC00""#),
            fixture.replace(r#""Acme Corp""#, "\"Acme\nCorp\""),
            fixture.replace(
                r#""connector": "plaid""#,
                r#""connector": "plaid", "connector": "plaid""#,
            ),
            fixture.replace(
                r#""connector": "plaid""#,
                r#""connector": "plaid", "\u0063onnector": "other""#,
            ),
            fixture.replace(
                r#""amount": "500.00""#,
                r#""amount": "500.00", "\u0061mount": "0.00""#,
            ),
            fixture.replace(
                r#""reference": "INV-100""#,
                r#""reference": "INV-100", "reference": "DIFFERENT""#,
            ),
        ];
        for (index, payload) in cases.iter().enumerate() {
            assert!(
                matches!(
                    parse_fwc_plaid_transactions_sync(payload, &units),
                    Err(FormatError::Parse { .. })
                ),
                "accepted malformed/duplicate case {index}"
            );
        }
    }

    #[test]
    fn normalized_plaid_json_never_skips_array_members_or_undeclared_data() {
        let units = UnitCatalog::embedded().unwrap();
        for unexpected in [
            Json::Null,
            Json::Bool(true),
            Json::Int(7),
            Json::Str("ignored transaction".into()),
            Json::Arr(Vec::new()),
            Json::Obj(Vec::new()),
        ] {
            let payload = edit_fixture_transactions(|rows| rows.insert(1, unexpected));
            assert!(matches!(
                parse_fwc_plaid_transactions_sync(&payload, &units),
                Err(FormatError::Parse { .. })
            ));
        }
        let nested = edit_fixture_transactions(|rows| {
            rows[0] = Json::Arr(vec![rows[0].clone()]);
        });
        assert!(matches!(
            parse_fwc_plaid_transactions_sync(&nested, &units),
            Err(FormatError::Parse { .. })
        ));
        for payload in [
            FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON.replace(
                r#""transactions": ["#,
                r#""removed": [{"transaction_id":"omitted"}], "transactions": ["#,
            ),
            FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON.replace(
                r#""reference": "INV-100""#,
                r#""reference": "INV-100", "modified_amount": "999.00""#,
            ),
        ] {
            assert!(matches!(
                parse_fwc_plaid_transactions_sync(&payload, &units),
                Err(FormatError::Parse { .. })
            ));
        }
    }

    #[test]
    fn normalized_plaid_json_checks_money_without_float_or_type_coercion() {
        let units = UnitCatalog::embedded().unwrap();
        for (field, original) in [
            ("amount", "500.00"),
            ("opening_balance", "1000.00"),
            ("closing_balance", "1250.00"),
        ] {
            for token in ["500", "500.00", "5e2", "-5E+2", "null", "true", "[]", "{}"] {
                let payload = FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON.replace(
                    &format!("\"{field}\": \"{original}\""),
                    &format!("\"{field}\": {token}"),
                );
                let error = parse_fwc_plaid_transactions_sync(&payload, &units).unwrap_err();
                assert!(
                    matches!(error, FormatError::FloatForbidden { token: ref actual, .. } if actual == token),
                    "wrong refusal for {field}={token}: {error:?}"
                );
            }
        }
        let scientific = FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON
            .replace(r#""amount": "500.00""#, r#""amount": "5e2""#);
        assert!(matches!(
            parse_fwc_plaid_transactions_sync(&scientific, &units),
            Err(FormatError::FloatForbidden { .. })
        ));
    }

    #[test]
    fn normalized_plaid_json_preserves_complete_ordered_transaction_census() {
        let units = UnitCatalog::embedded().unwrap();
        let dropped = edit_fixture_transactions(|rows| {
            rows.remove(1);
        });
        assert!(matches!(
            parse_fwc_plaid_transactions_sync(&dropped, &units),
            Err(FormatError::BankContinuity { .. })
        ));
        let extra = edit_fixture_transactions(|rows| {
            let mut added = rows[0].clone();
            replace_field(
                &mut added,
                "transaction_id",
                Json::Str("extra-credit".into()),
            );
            rows.push(added);
        });
        assert!(matches!(
            parse_fwc_plaid_transactions_sync(&extra, &units),
            Err(FormatError::BankContinuity { .. })
        ));

        // An offsetting pair cannot be silently skipped just because the
        // source still balances. Both additional observations must survive.
        let balanced_extra = edit_fixture_transactions(|rows| {
            let mut credit = rows[0].clone();
            replace_field(
                &mut credit,
                "transaction_id",
                Json::Str("extra-credit".into()),
            );
            replace_field(&mut credit, "reference", Json::Str("EXTRA-CREDIT".into()));
            let mut debit = credit.clone();
            replace_field(
                &mut debit,
                "transaction_id",
                Json::Str("extra-debit".into()),
            );
            replace_field(&mut debit, "direction", Json::Str("debit".into()));
            replace_field(&mut debit, "reference", Json::Str("EXTRA-DEBIT".into()));
            rows.extend([credit, debit]);
        });
        let result = parse_fwc_plaid_transactions_sync(&balanced_extra, &units).unwrap();
        assert_eq!(result.extract.lines.len(), 4);
        assert_eq!(result.derived_line_links.len(), 4);
        let census: Vec<_> = result
            .extract
            .lines
            .iter()
            .map(|line| {
                (
                    line.line_ordinal,
                    line.side,
                    line.amount.mantissa,
                    line.reference.as_str(),
                )
            })
            .collect();
        assert_eq!(
            census,
            [
                (1, Side::Credit, 50_000, "INV-100"),
                (2, Side::Debit, 25_000, "BILL-200"),
                (3, Side::Credit, 50_000, "EXTRA-CREDIT"),
                (4, Side::Debit, 50_000, "EXTRA-DEBIT"),
            ]
        );
        assert_eq!(result.extract.closing_balance, 125_000);
        for (index, link) in result.derived_line_links.iter().enumerate() {
            assert_eq!(link.line_ordinal, u32::try_from(index + 1).unwrap());
            assert_eq!(link.line_digest, result.extract.lines[index].line_digest);
            assert_eq!(link.source_document_oid, result.payload_document_oid);
        }
    }

    #[test]
    fn normalized_plaid_json_refuses_duplicate_or_empty_transaction_identities() {
        let units = UnitCatalog::embedded().unwrap();
        for replacement in ["plaid-tx-001", ""] {
            let payload =
                FIXTURE_FWC_PLAID_TRANSACTIONS_SYNC_JSON.replace("plaid-tx-002", replacement);
            assert!(matches!(
                parse_fwc_plaid_transactions_sync(&payload, &units),
                Err(FormatError::Parse { .. })
            ));
        }
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

    #[test]
    fn warehouse_receipt_decodes_strings_and_keeps_exact_response_commitment() {
        let plain = r#"{
            "robot_schema_version":"fwc.robot.v1",
            "connector":"snowflake",
            "receipt_hash":"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        }"#;
        let escaped = plain
            .replace("fwc.robot.v1", r"fwc.robot.\u00761")
            .replace("snowflake", r"snow\u0066lake")
            .replace("receipt_hash", r"receipt_\u0068ash")
            .replace("112233", r"\u003112233");
        let receipt = build_warehouse_export_receipt(
            WarehouseConnector::Snowflake,
            "AUDIT.REPORTS",
            b"certified-report-bytes",
            [0x42; 32],
            plain,
        )
        .unwrap();
        let decoded = build_warehouse_export_receipt(
            WarehouseConnector::Snowflake,
            "AUDIT.REPORTS",
            b"certified-report-bytes",
            [0x42; 32],
            &escaped,
        )
        .unwrap();
        assert_eq!(decoded.robot_schema_version, "fwc.robot.v1");
        assert_eq!(decoded.connector, receipt.connector);
        assert_eq!(decoded.destination_ref, receipt.destination_ref);
        assert_eq!(decoded.report_digest, receipt.report_digest);
        assert_eq!(
            decoded.report_certificate_digest,
            receipt.report_certificate_digest
        );
        assert_eq!(decoded.fwc_receipt_hash, receipt.fwc_receipt_hash);
        assert_ne!(decoded.payload_document_oid, receipt.payload_document_oid);
        assert_eq!(
            decoded.payload_document_oid,
            compute_fwc_payload_document_oid(escaped.as_bytes())
        );
        assert_eq!(
            WarehouseExportReceipt::decode_canonical(&decoded.canonical_bytes().unwrap()).unwrap(),
            decoded
        );
    }

    #[test]
    fn warehouse_receipt_refuses_nested_shadowed_duplicate_and_extra_data() {
        let valid = r#"{
            "robot_schema_version":"fwc.robot.v1",
            "connector":"snowflake",
            "receipt_hash":"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        }"#;
        let cases = [
            format!("[{valid}]"),
            format!(r#"{{"nested":{valid}}}"#),
            format!("{valid} {{}}"),
            valid.replace(r#""connector":"snowflake""#, r#""connector":"s3""#),
            valid.replace(r#""connector":"snowflake""#, r#""connector":null"#),
            valid.replace(r#""connector":"snowflake""#, r#""connector":"snow\qflake""#),
            valid.replace(
                r#""connector":"snowflake""#,
                r#""connector":"snowflake", "connector":"snowflake""#,
            ),
            valid.replace(
                r#""connector":"snowflake""#,
                r#""connector":"snowflake", "\u0063onnector":"s3""#,
            ),
            valid.replace(
                r#""connector":"snowflake""#,
                r#""connector":"snowflake", "transactions":[]"#,
            ),
            valid.replace(
                r#""receipt_hash":"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff""#,
                r#""receipt_hash":{"receipt_hash":"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"}"#,
            ),
            valid.replace(
                r#""receipt_hash":"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff""#,
                r#""receipt_hash":7"#,
            ),
            valid.replace(
                r#""robot_schema_version":"fwc.robot.v1""#,
                r#""robot_schema_version":"fwc.robot.v2""#,
            ),
        ];
        for (index, response) in cases.iter().enumerate() {
            assert!(
                matches!(
                    build_warehouse_export_receipt(
                        WarehouseConnector::Snowflake,
                        "AUDIT.REPORTS",
                        b"certified-report-bytes",
                        [0x42; 32],
                        response,
                    ),
                    Err(FormatError::Parse { .. })
                ),
                "accepted invalid warehouse response {index}"
            );
        }
    }
}
