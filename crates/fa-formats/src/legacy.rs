//! Legacy-system General Ledger import readers (plan §8.6, bead `fa-qm4t`).
//!
//! Provides deterministic, exact fixed-scale GL readers for:
//! - QuickBooks Desktop IIF (`quickbooks_iif_v1`: `!TRNS`/`!SPL`/`!ENDTRNS` blocks)
//! - QuickBooks Online/Desktop Journal Report CSV (`quickbooks_csv_v1`)
//! - Xero Journal / Account Transactions CSV (`xero_csv_v1`)
//! - NetSuite General Ledger Detail CSV (`netsuite_csv_v1`)
//! - Generic GL CSV with a declared column map (`csv_gl_v1` + `LegacyColumnMap`)
//! - Beancount v3 ledgers (`beancount_v3`: single-unit transactions; see
//!   [`parse_beancount_ledger`] for the subset)
//!
//! Every reader maps legacy rows to balanced `LegacyChunkEntry` items carrying
//! `MigratedProvenance { source_system, source_id, source_recorded_at_ns, source_entered_by, source_approved_by }`,
//! refuses unmapped legacy accounts with the exact `[account_map]` fix hint,
//! refuses floating-point/scientific notation (`FA-INV-05`), and computes the
//! opening-balance trial balance (`Vec<TrialBalanceLine>`) and tie-out
//! attestation digest in the same run.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{BookContext, RunBody, RunMode, TrialBalanceLine};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload, Oid,
    PeriodRef, account_vid, dimension_kind, dimension_value_vid,
};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::VId;

use crate::csv::{CsvRecord, CsvRecords};
use crate::{FormatError, FormatLeg, UnitCatalog, parse_date_iso, parse_exact_decimal};

/// Domain separator for legacy import opening-balance tie-out attestations.
pub const LEGACY_ATTESTATION_DOMAIN: &[u8] = b"fa:formats:legacy-import-attestation:v1";

/// Supported legacy general ledger export formats (plan §8.6, `registries/formats.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyFormat {
    QuickBooksIif,
    QuickBooksCsv,
    XeroCsv,
    NetSuiteCsv,
    GenericCsv,
    Beancount,
    Hledger,
}

impl LegacyFormat {
    #[must_use]
    pub const fn registry_name(self) -> &'static str {
        match self {
            Self::QuickBooksIif => "quickbooks_iif_v1",
            Self::QuickBooksCsv => "quickbooks_csv_v1",
            Self::XeroCsv => "xero_csv_v1",
            Self::NetSuiteCsv => "netsuite_csv_v1",
            Self::GenericCsv => "csv_gl_v1",
            Self::Beancount => "beancount_v3",
            Self::Hledger => "hledger_journal",
        }
    }

    #[must_use]
    pub const fn default_source_system(self) -> &'static str {
        match self {
            Self::QuickBooksIif => "quickbooks-iif",
            Self::QuickBooksCsv => "quickbooks-csv",
            Self::XeroCsv => "xero-csv",
            Self::NetSuiteCsv => "netsuite-csv",
            Self::GenericCsv => "legacy-csv",
            Self::Beancount => "beancount",
            Self::Hledger => "hledger",
        }
    }
}

/// Account mapping table from legacy account identifiers/names to FrankenAccounting
/// leaf account codes, validated against the target book's leaf chart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMap {
    /// Explicit mapping `legacy_account -> fa_leaf_account_code`.
    pub mappings: BTreeMap<String, String>,
    /// Valid leaf account codes in the target FrankenAccounting book.
    pub valid_leaf_accounts: BTreeSet<String>,
    /// If true, allow a legacy account string that already equals a `valid_leaf_accounts`
    /// code even if not explicitly listed in `mappings`.
    pub allow_passthrough_leaf_codes: bool,
}

impl AccountMap {
    /// Construct an `AccountMap` for the given target book leaf account codes.
    #[must_use]
    pub fn new<I, S>(valid_leaf_accounts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            mappings: BTreeMap::new(),
            valid_leaf_accounts: valid_leaf_accounts.into_iter().map(Into::into).collect(),
            allow_passthrough_leaf_codes: true,
        }
    }

    /// Insert a mapping from `legacy_account` to `fa_leaf_code`.
    pub fn insert(&mut self, legacy_account: impl Into<String>, fa_leaf_code: impl Into<String>) {
        self.mappings
            .insert(legacy_account.into(), fa_leaf_code.into());
    }

    /// Resolve a legacy account string to a validated FrankenAccounting leaf account code,
    /// or refuse with `FormatError::UnmappedAccount` naming the exact `[account_map]` fix.
    pub fn resolve(
        &self,
        format: &'static str,
        legacy_account: &str,
    ) -> Result<String, FormatError> {
        let trimmed = legacy_account.trim();
        if let Some(mapped) = self.mappings.get(trimmed) {
            if self.valid_leaf_accounts.contains(mapped) {
                return Ok(mapped.clone());
            }
            let sample_leaf = self
                .valid_leaf_accounts
                .iter()
                .next()
                .map_or("<leaf_account_code>", String::as_str);
            return Err(FormatError::UnmappedAccount {
                format,
                legacy_account: trimmed.to_owned(),
                fix_hint: format!(
                    "mapped target account {mapped:?} is not an active leaf account in the book; update `[account_map]` entry `\"{trimmed}\" = \"{sample_leaf}\"` to name a valid leaf account"
                ),
            });
        }
        if self.allow_passthrough_leaf_codes && self.valid_leaf_accounts.contains(trimmed) {
            return Ok(trimmed.to_owned());
        }
        let sample_leaf = self
            .valid_leaf_accounts
            .iter()
            .next()
            .map_or("1000", String::as_str);
        Err(FormatError::UnmappedAccount {
            format,
            legacy_account: trimmed.to_owned(),
            fix_hint: format!(
                "add `\"{trimmed}\" = \"{sample_leaf}\"` under `[account_map]` in the migration column-map file (or open the target leaf account first)"
            ),
        })
    }
}

/// Declared column-map and account-map specification for generic legacy GL CSV imports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyColumnMap {
    pub source_system: String,
    pub default_unit: String,
    pub entry_id_column: String,
    pub effective_date_column: String,
    pub recorded_at_column: Option<String>,
    pub account_column: String,
    pub debit_column: Option<String>,
    pub credit_column: Option<String>,
    pub signed_amount_column: Option<String>,
    /// A debit/credit indicator column read with `amount_column`, an unsigned
    /// amount: the shape of an export that writes `D`/`C` beside the amount
    /// (FrankenAccounting's own csv-gl among them).
    pub side_column: Option<String>,
    pub amount_column: Option<String>,
    /// The indicator values for a debit and a credit, compared ignoring case
    /// (`D` and `C` unless declared).
    pub debit_marker: String,
    pub credit_marker: String,
    pub unit_column: Option<String>,
    /// Entry-level description in a generic CSV. Nonblank values for one entry
    /// must match exactly; blank rows inherit the first populated value. When
    /// this names the same column as `memo_column`, it instead supplies per-leg
    /// text: every row retains its memo and the first populated memo supplies
    /// the entry summary. An entry with no populated description uses its ID.
    pub description_column: Option<String>,
    /// Per-leg text, which may differ between rows of the same entry.
    pub memo_column: Option<String>,
    pub entered_by_column: Option<String>,
    pub approved_by_column: Option<String>,
    pub account_mappings: BTreeMap<String, String>,
    /// Registered dimension kind -> source column containing its value code.
    /// Blank cells omit the dimension; nonblank codes are preserved exactly.
    pub dimension_columns: BTreeMap<String, String>,
}

impl LegacyColumnMap {
    /// Parse a declared column map (`[columns]`, `[account_map]` and optional
    /// `[dimension_columns]`, for example `department = "Department"`).
    pub fn parse_toml(src: &str) -> Result<Self, FormatError> {
        const FMT: &str = "legacy_column_map.toml";
        let mut section = "";
        let mut cols: BTreeMap<String, String> = BTreeMap::new();
        let mut account_mappings: BTreeMap<String, String> = BTreeMap::new();
        let mut dimension_columns: BTreeMap<String, String> = BTreeMap::new();

        for (line_idx, raw_line) in src.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = &line[1..line.len() - 1];
                if !matches!(section, "columns" | "account_map" | "dimension_columns") {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!(
                            "line {}: unknown section [{section}] (expected [columns], [account_map] or [dimension_columns])",
                            line_idx + 1
                        ),
                    });
                }
                continue;
            }
            let Some((raw_k, raw_v)) = line.split_once('=') else {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!("line {}: expected `key = \"value\"`", line_idx + 1),
                });
            };
            let k = unquote_toml_str(FMT, line_idx + 1, raw_k.trim())?;
            let v = unquote_toml_str(FMT, line_idx + 1, raw_v.trim())?;
            match section {
                "" | "columns" => {
                    if cols.insert(k.clone(), v).is_some() {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: format!("line {}: repeated column-map key {k:?}", line_idx + 1),
                        });
                    }
                }
                "account_map" => {
                    if account_mappings.insert(k.clone(), v).is_some() {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: format!(
                                "line {}: repeated legacy account mapping {k:?}",
                                line_idx + 1
                            ),
                        });
                    }
                }
                "dimension_columns" => {
                    if dimension_kind(&k).is_none() || v.trim().is_empty() || v.trim() != v {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: format!(
                                "line {}: dimension mapping {k:?} must name a registered dimension kind and an exact nonblank source column",
                                line_idx + 1
                            ),
                        });
                    }
                    if dimension_columns.insert(k.clone(), v).is_some() {
                        return Err(FormatError::Parse {
                            format: FMT,
                            detail: format!(
                                "line {}: repeated dimension column mapping {k:?}",
                                line_idx + 1
                            ),
                        });
                    }
                }
                _ => unreachable!(),
            }
        }

        let req = |key: &str| -> Result<String, FormatError> {
            cols.get(key)
                .filter(|v| !v.trim().is_empty())
                .cloned()
                .ok_or_else(|| FormatError::Parse {
                    format: FMT,
                    detail: format!("missing required column mapping `{key}` in [columns]"),
                })
        };
        let opt = |key: &str| -> Option<String> {
            cols.get(key).filter(|v| !v.trim().is_empty()).cloned()
        };

        let debit_column = opt("debit_column");
        let credit_column = opt("credit_column");
        let signed_amount_column = opt("signed_amount_column");
        let side_column = opt("side_column");
        let amount_column = opt("amount_column");
        if side_column.is_some() != amount_column.is_some() {
            return Err(FormatError::Parse {
                format: FMT,
                detail: "`side_column` and `amount_column` are declared together".to_owned(),
            });
        }
        if (debit_column.is_none() || credit_column.is_none())
            && signed_amount_column.is_none()
            && side_column.is_none()
        {
            return Err(FormatError::Parse {
                format: FMT,
                detail: "must declare either (`debit_column` and `credit_column`), `signed_amount_column`, or (`side_column` and `amount_column`) in [columns]".to_owned(),
            });
        }
        let debit_marker = opt("debit_marker").unwrap_or_else(|| "D".to_owned());
        let credit_marker = opt("credit_marker").unwrap_or_else(|| "C".to_owned());
        if debit_marker.eq_ignore_ascii_case(&credit_marker) {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("`debit_marker` and `credit_marker` are both `{debit_marker}`"),
            });
        }

        Ok(Self {
            source_system: opt("source_system").unwrap_or_else(|| "legacy-csv".to_owned()),
            default_unit: opt("default_unit").unwrap_or_else(|| "USD".to_owned()),
            entry_id_column: req("entry_id_column")?,
            effective_date_column: req("effective_date_column")?,
            recorded_at_column: opt("recorded_at_column"),
            account_column: req("account_column")?,
            debit_column,
            credit_column,
            signed_amount_column,
            side_column,
            amount_column,
            debit_marker,
            credit_marker,
            unit_column: opt("unit_column"),
            description_column: opt("description_column"),
            memo_column: opt("memo_column"),
            entered_by_column: opt("entered_by_column"),
            approved_by_column: opt("approved_by_column"),
            account_mappings,
            dimension_columns,
        })
    }

    /// Merge this column map's `[account_map]` entries into `base`.
    #[must_use]
    pub fn apply_to_account_map(&self, mut base: AccountMap) -> AccountMap {
        for (legacy, target) in &self.account_mappings {
            base.insert(legacy.clone(), target.clone());
        }
        base
    }
}

fn unquote_toml_str(format: &'static str, line_no: usize, s: &str) -> Result<String, FormatError> {
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        Ok(s[1..s.len() - 1].replace("\\\"", "\""))
    } else if !s.contains(' ') && !s.contains('"') {
        Ok(s.to_owned())
    } else {
        Err(FormatError::Parse {
            format,
            detail: format!("line {line_no}: invalid string literal {s:?}"),
        })
    }
}

fn parse_date_flexible(format: &'static str, raw: &str) -> Result<DateDay, FormatError> {
    let trimmed = raw.trim();
    if trimmed.contains('/') {
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() == 3 {
            // Support MM/DD/YYYY or YYYY/MM/DD
            let (y_s, m_s, d_s) = if parts[0].len() == 4 {
                (parts[0], parts[1], parts[2])
            } else {
                (parts[2], parts[0], parts[1])
            };
            let y: i32 = y_s.parse().map_err(|_| FormatError::Parse {
                format,
                detail: format!("invalid year in date {trimmed:?}"),
            })?;
            let m: u8 = m_s.parse().map_err(|_| FormatError::Parse {
                format,
                detail: format!("invalid month in date {trimmed:?}"),
            })?;
            let d: u8 = d_s.parse().map_err(|_| FormatError::Parse {
                format,
                detail: format!("invalid day in date {trimmed:?}"),
            })?;
            return DateDay::from_ymd(y, m, d).map_err(|e| FormatError::Parse {
                format,
                detail: format!("invalid civil date {trimmed:?}: {e}"),
            });
        }
    }
    parse_date_iso(format, trimmed)
}

/// Legacy provenance metadata carried on `EntryOrigin::Migration` (plan §8.6, doctrine 6).
///
/// `source_recorded_at_ns` preserves the legacy system's timestamp as provenance and
/// is never interpreted as FrankenAccounting `recorded_at` (`CommitSeq`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigratedProvenance {
    pub source_system: String,
    pub source_id: String,
    pub source_recorded_at_ns: Option<i64>,
    pub source_entered_by: Option<String>,
    pub source_approved_by: Option<String>,
}

/// One balanced legacy journal entry ready to be staged into a `MigrationRun`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyChunkEntry {
    pub provenance: MigratedProvenance,
    pub effective_date: DateDay,
    pub description: String,
    pub legs: Vec<FormatLeg>,
    /// Sparse zero-based leg ordinals -> registered dimension kind/value codes.
    /// This source projection belongs to legacy import, not canonical `FormatLeg`.
    pub leg_dimensions: BTreeMap<usize, BTreeMap<String, String>>,
}

fn dimension_value_problem(kind: &str, code: &str) -> Option<String> {
    // Reuse the native declaration's identifier contract. This validates a
    // reference only; importing history never creates or renames its value.
    fa_journal::dimension::DimensionValueSpec {
        dimension: kind.to_owned(),
        code: code.to_owned(),
        name: code.to_owned(),
        parent: None,
        valid_from: None,
        valid_to: None,
    }
    .problem()
}

impl LegacyChunkEntry {
    fn validate_dimensions(&self, format: &'static str) -> Result<(), FormatError> {
        if self.legs.iter().any(|leg| !leg.dimensions.is_empty()) {
            return Err(FormatError::Parse {
                format,
                detail: format!(
                    "entry {:?}: legacy migration requires explicit named dimension code mappings; native dimension value IDs belong to their source book and must not be silently copied or discarded",
                    self.provenance.source_id
                ),
            });
        }
        for (ordinal, values) in &self.leg_dimensions {
            if *ordinal >= self.legs.len() || values.is_empty() {
                return Err(FormatError::Parse {
                    format,
                    detail: format!(
                        "entry {:?}: dimension projection must name an existing leg and at least one value",
                        self.provenance.source_id
                    ),
                });
            }
            for (kind, code) in values {
                if let Some(problem) = dimension_value_problem(kind, code) {
                    return Err(FormatError::Parse {
                        format,
                        detail: format!(
                            "entry {:?}, leg {}: {problem}",
                            self.provenance.source_id,
                            ordinal + 1
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Complete result of parsing a legacy GL export: ordered `LegacyChunkEntry` items,
/// the folded opening trial balance (`Vec<TrialBalanceLine>`), and a deterministic
/// opening-balance tie-out attestation computed in the same run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyImportBatch {
    pub format: LegacyFormat,
    pub source_system: String,
    pub source_bytes_digest: [u8; 32],
    pub row_count: usize,
    pub chunks: Vec<LegacyChunkEntry>,
    pub trial_balance: Vec<TrialBalanceLine>,
    pub attestation_digest: [u8; 32],
}

impl LegacyImportBatch {
    /// Build a `fa_journal::RunBody` (`RunMode::OpeningOnly`) whose declared
    /// `TrialBalanceLine`s are this batch's exact folded opening balances.
    #[must_use]
    pub fn to_run_body(
        &self,
        book_id: Id128,
        run_key: &str,
        opening_date: DateDay,
        trial_balance_doc: Oid,
    ) -> RunBody {
        RunBody {
            book_id,
            run_key: run_key.to_owned(),
            source_system: self.source_system.clone(),
            mode: RunMode::OpeningOnly,
            trial_balance: trial_balance_doc,
            opening_date,
            lines: self.trial_balance.clone(),
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
        }
    }

    /// Compatibility entry point which refuses to seal without explicit entropy.
    ///
    /// Use [`Self::to_chunk_proposals_with_sealer`] with the caller's secure
    /// sealer, then retain those exact proposals for approval and retry.
    #[allow(clippy::too_many_arguments)]
    pub fn to_chunk_proposals(
        &self,
        _book: &BookContext,
        _run_ref: VId,
        _opening_date: DateDay,
        _opening_period_code: Option<&str>,
        _principal_ref: VId,
        _batch_oid: Oid,
        _evidence: Vec<EvidenceRef>,
    ) -> Result<Vec<EntryPayload>, FormatError> {
        Err(FormatError::Parse {
            format: self.format.registry_name(),
            detail: "migration proposals require fresh capability-supplied salt and nonce for every private field; use to_chunk_proposals_with_sealer with Book::seal_text and retain the resulting exact proposal bytes for approval and retry".into(),
        })
    }

    /// Build opening proposals with the caller's capability-supplied sealer.
    ///
    /// The sealer must supply fresh salt and nonce for every invocation (for
    /// example, `Book::seal_text`). Neither source hashes nor row ordinals are
    /// entropy. Retain these exact proposals before collecting approvals;
    /// regenerating them creates new private commitments and approval digests.
    /// The public idempotency key contains only a version and row ordinal;
    /// the native migration entry identity separately binds the run, while
    /// legacy source IDs remain sealed provenance.
    #[allow(clippy::too_many_arguments)]
    pub fn to_chunk_proposals_with_sealer<E, F>(
        &self,
        book: &BookContext,
        run_ref: VId,
        opening_date: DateDay,
        opening_period_code: Option<&str>,
        principal_ref: VId,
        batch_oid: Oid,
        evidence: Vec<EvidenceRef>,
        mut seal: F,
    ) -> Result<Vec<EntryPayload>, E>
    where
        E: From<FormatError>,
        F: FnMut(&str) -> Result<Erasable<String>, E>,
    {
        let mut proposals = Vec::with_capacity(self.chunks.len());
        for (idx, chunk) in self.chunks.iter().enumerate() {
            chunk.validate_dimensions(self.format.registry_name())?;
            let mut legs = Vec::with_capacity(chunk.legs.len());
            for (ordinal, leg) in chunk.legs.iter().enumerate() {
                let mut payload = LegPayload::simple(
                    leg.side,
                    account_vid(book.book_id, &leg.account_code),
                    leg.amount,
                );
                if let Some(values) = chunk.leg_dimensions.get(&ordinal) {
                    for (kind, code) in values {
                        let kind = dimension_kind(kind).ok_or_else(|| FormatError::Parse {
                            format: self.format.registry_name(),
                            detail: format!("unregistered dimension kind {kind:?}"),
                        })?;
                        payload
                            .dimension_set
                            .push((kind.id, dimension_value_vid(book.book_id, kind.code, code)));
                    }
                    payload.dimension_set.sort_by_key(|(kind, _)| *kind);
                }
                payload.memo = leg.memo.as_deref().map(&mut seal).transpose()?;
                legs.push(payload);
            }
            let unit_totals =
                EntryPayload::fold_unit_totals(&legs).map_err(|e| FormatError::Overflow {
                    format: self.format.registry_name(),
                    detail: e.to_string(),
                })?;

            let source_id = seal(&chunk.provenance.source_id)?;
            let source_entered_by = chunk
                .provenance
                .source_entered_by
                .as_deref()
                .map(&mut seal)
                .transpose()?;
            let source_approved_by = chunk
                .provenance
                .source_approved_by
                .as_deref()
                .map(&mut seal)
                .transpose()?;
            let description = seal(&chunk.description)?;

            let origin = EntryOrigin::Migration {
                run_ref,
                source_system: chunk.provenance.source_system.clone(),
                source_id,
                source_recorded_at_ns: chunk.provenance.source_recorded_at_ns,
                source_entered_by,
                source_approved_by,
                batch_oid,
            };
            let idempotency_key = format!("legacy-opening:v1:{idx}").into_bytes();

            proposals.push(EntryPayload {
                schema_minor: fa_model::entry::EXTENSIONS_MINOR,
                book_id: book.book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::MIGRATION,
                effective_date: opening_date,
                document_date: Some(chunk.effective_date),
                description,
                effective_period: opening_period_code.map(|code| PeriodRef {
                    calendar: book.calendar.id.clone(),
                    code: code.to_owned(),
                }),
                legs,
                control: None,
                unit_totals,
                base_totals: None,
                idempotency_key,
                origin,
                principal_ref,
                session_ref: None,
                evidence: evidence.clone(),
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            });
        }
        Ok(proposals)
    }
}

// ---------------------------------------------------------------------------
// Shared builder: validate balance per entry, fold TrialBalanceLine, attest
// ---------------------------------------------------------------------------

fn finalize_legacy_batch(
    format: LegacyFormat,
    source_system: String,
    raw_src: &str,
    row_count: usize,
    chunks: Vec<LegacyChunkEntry>,
) -> Result<LegacyImportBatch, FormatError> {
    let fmt_name = format.registry_name();
    if chunks.is_empty() {
        return Err(FormatError::Parse {
            format: fmt_name,
            detail: "legacy export contains zero journal entries".to_owned(),
        });
    }

    let mut tb_fold: BTreeMap<(String, UnitId), i128> = BTreeMap::new();
    for chunk in &chunks {
        chunk.validate_dimensions(fmt_name)?;
        if chunk.legs.len() < 2 {
            return Err(FormatError::Parse {
                format: fmt_name,
                detail: format!(
                    "entry {:?} has {} leg(s); requires at least 2",
                    chunk.provenance.source_id,
                    chunk.legs.len()
                ),
            });
        }
        let mut by_unit: BTreeMap<String, (i128, i128)> = BTreeMap::new();
        for leg in &chunk.legs {
            let m = leg.amount.mantissa;
            if m <= 0 {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!(
                        "entry {:?} leg on {} has non-positive mantissa {m}",
                        chunk.provenance.source_id, leg.account_code
                    ),
                });
            }
            let slot = by_unit.entry(leg.unit_code.clone()).or_insert((0, 0));
            match leg.side {
                Side::Debit => {
                    slot.0 = slot.0.checked_add(m).ok_or_else(|| FormatError::Overflow {
                        format: fmt_name,
                        detail: format!("debit overflow in entry {:?}", chunk.provenance.source_id),
                    })?;
                }
                Side::Credit => {
                    slot.1 = slot.1.checked_add(m).ok_or_else(|| FormatError::Overflow {
                        format: fmt_name,
                        detail: format!(
                            "credit overflow in entry {:?}",
                            chunk.provenance.source_id
                        ),
                    })?;
                }
            }

            let signed = match leg.side {
                Side::Debit => m,
                Side::Credit => -m,
            };
            let cell = tb_fold
                .entry((leg.account_code.clone(), leg.amount.unit))
                .or_insert(0);
            *cell = cell
                .checked_add(signed)
                .ok_or_else(|| FormatError::Overflow {
                    format: fmt_name,
                    detail: format!("trial balance fold overflow on {}", leg.account_code),
                })?;
        }

        for (unit_code, (dr, cr)) in by_unit {
            if dr != cr {
                return Err(FormatError::UnbalancedEntry {
                    format: fmt_name,
                    entry_id: chunk.provenance.source_id.clone(),
                    unit_code,
                    debits: dr,
                    credits: cr,
                });
            }
        }
    }

    let mut trial_balance = Vec::new();
    for ((account_code, unit), mantissa) in tb_fold {
        if mantissa != 0 {
            trial_balance.push(TrialBalanceLine {
                account_code,
                unit,
                mantissa,
            });
        }
    }

    let mut src_hasher = Hasher::new();
    src_hasher.update(raw_src.as_bytes());
    let source_bytes_digest = src_hasher.finalize().0;

    let mut att = Hasher::new();
    att.update(LEGACY_ATTESTATION_DOMAIN);
    att.update(fmt_name.as_bytes());
    att.update(&(source_system.len() as u64).to_le_bytes());
    att.update(source_system.as_bytes());
    att.update(&source_bytes_digest);
    att.update(&(row_count as u64).to_le_bytes());
    att.update(&(chunks.len() as u64).to_le_bytes());
    for c in &chunks {
        att.update(&(c.provenance.source_id.len() as u64).to_le_bytes());
        att.update(c.provenance.source_id.as_bytes());
        att.update(&c.effective_date.0.to_le_bytes());
        att.update(
            &c.provenance
                .source_recorded_at_ns
                .unwrap_or(-1)
                .to_le_bytes(),
        );
        att.update(&(c.legs.len() as u64).to_le_bytes());
        for l in &c.legs {
            att.update(&(l.account_code.len() as u64).to_le_bytes());
            att.update(l.account_code.as_bytes());
            att.update(&[match l.side {
                Side::Debit => 0,
                Side::Credit => 1,
            }]);
            att.update(&l.amount.unit.0.to_le_bytes());
            att.update(&l.amount.mantissa.to_le_bytes());
        }
    }
    att.update(&(trial_balance.len() as u64).to_le_bytes());
    for l in &trial_balance {
        att.update(&(l.account_code.len() as u64).to_le_bytes());
        att.update(l.account_code.as_bytes());
        att.update(&l.unit.0.to_le_bytes());
        att.update(&l.mantissa.to_le_bytes());
    }
    // Preserve dimension-free v1 attestations exactly. A dimension projection
    // appends its own framed domain so changed mappings cannot share a digest.
    if chunks.iter().any(|chunk| !chunk.leg_dimensions.is_empty()) {
        att.update(b"fa:formats:legacy-import-dimensions:v1");
        att.update(&(chunks.len() as u64).to_le_bytes());
        for chunk in &chunks {
            att.update(&(chunk.leg_dimensions.len() as u64).to_le_bytes());
            for (ordinal, values) in &chunk.leg_dimensions {
                att.update(&(*ordinal as u64).to_le_bytes());
                att.update(&(values.len() as u64).to_le_bytes());
                for (kind, code) in values {
                    att.update(&(kind.len() as u64).to_le_bytes());
                    att.update(kind.as_bytes());
                    att.update(&(code.len() as u64).to_le_bytes());
                    att.update(code.as_bytes());
                }
            }
        }
    }
    let attestation_digest = att.finalize().0;

    Ok(LegacyImportBatch {
        format,
        source_system,
        source_bytes_digest,
        row_count,
        chunks,
        trial_balance,
        attestation_digest,
    })
}

/// Parse an optional legacy recorded-at timestamp (`YYYY-MM-DDTHH:MM:SSZ`,
/// `YYYY-MM-DD HH:MM:SS`, or integer epoch seconds/nanoseconds) into UTC nanoseconds.
pub fn parse_legacy_timestamp_ns(
    format: &'static str,
    raw: &str,
) -> Result<Option<i64>, FormatError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        let val: i64 = trimmed.parse().map_err(|_| FormatError::Parse {
            format,
            detail: format!("invalid numeric timestamp {trimmed:?}"),
        })?;
        // Heuristic: < 10^12 is epoch seconds; >= 10^12 is nanoseconds.
        let ns = if val < 1_000_000_000_000 {
            val.saturating_mul(1_000_000_000)
        } else {
            val
        };
        return Ok(Some(ns));
    }
    let cleaned = trimmed.trim_end_matches('Z');
    let (date_part, time_part) = cleaned
        .split_once('T')
        .or_else(|| cleaned.split_once(' '))
        .unwrap_or((cleaned, "00:00:00"));
    let day = parse_date_flexible(format, date_part)?;
    let mut t_parts = time_part.split(':');
    let hh: i64 = t_parts
        .next()
        .unwrap_or("0")
        .parse()
        .map_err(|_| FormatError::Parse {
            format,
            detail: format!("invalid hour in timestamp {trimmed:?}"),
        })?;
    let mm: i64 = t_parts
        .next()
        .unwrap_or("0")
        .parse()
        .map_err(|_| FormatError::Parse {
            format,
            detail: format!("invalid minute in timestamp {trimmed:?}"),
        })?;
    let ss_raw = t_parts.next().unwrap_or("0");
    let ss_only = ss_raw.split('.').next().unwrap_or("0");
    let ss: i64 = ss_only.parse().map_err(|_| FormatError::Parse {
        format,
        detail: format!("invalid second in timestamp {trimmed:?}"),
    })?;
    if !(0..24).contains(&hh) || !(0..60).contains(&mm) || !(0..60).contains(&ss) {
        return Err(FormatError::Parse {
            format,
            detail: format!("out-of-range time component in {trimmed:?}"),
        });
    }
    let day_secs = i64::from(day.0) * 86_400 + hh * 3_600 + mm * 60 + ss;
    Ok(Some(day_secs.saturating_mul(1_000_000_000)))
}

// Some exports put transaction metadata on just one of its rows. Retain the
// first supplied value, allow blank rows to inherit it, and refuse contradictory
// values rather than silently attributing every leg to the first row's author
// or legacy timestamp.
fn merge_provenance_field<T: PartialEq>(
    target: &mut Option<T>,
    supplied: Option<T>,
    format: &'static str,
    line: usize,
    field: &'static str,
) -> Result<(), FormatError> {
    if let Some(value) = supplied {
        if target.as_ref().is_some_and(|old| old != &value) {
            return Err(FormatError::Parse {
                format,
                detail: format!("line {line}: conflicting {field} within one legacy entry"),
            });
        }
        if target.is_none() {
            *target = Some(value);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. QuickBooks Desktop IIF (`quickbooks_iif_v1`)
// ---------------------------------------------------------------------------

/// Parse a QuickBooks Desktop IIF (`!TRNS`/`!SPL`/`!ENDTRNS`) export into a `LegacyImportBatch`.
pub fn parse_quickbooks_iif(
    src: &str,
    units: &UnitCatalog,
    account_map: &AccountMap,
    default_unit_code: &str,
) -> Result<LegacyImportBatch, FormatError> {
    const FMT: &str = "quickbooks_iif_v1";
    let (uid, scale) =
        units
            .lookup_code(default_unit_code)
            .ok_or_else(|| FormatError::UnknownUnit {
                format: FMT,
                unit: default_unit_code.to_owned(),
            })?;

    let mut trns_cols: BTreeMap<String, usize> = BTreeMap::new();
    let mut spl_cols: BTreeMap<String, usize> = BTreeMap::new();
    let mut row_count = 0usize;
    let mut chunks = Vec::new();
    let mut current: Option<LegacyChunkEntry> = None;

    for (line_idx, raw_line) in src.lines().enumerate() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with(';') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let tag = fields[0].trim();
        match tag {
            "!TRNS" => {
                trns_cols.clear();
                for (i, h) in fields.iter().enumerate() {
                    trns_cols.insert(h.trim().to_ascii_uppercase(), i);
                }
            }
            "!SPL" => {
                spl_cols.clear();
                for (i, h) in fields.iter().enumerate() {
                    spl_cols.insert(h.trim().to_ascii_uppercase(), i);
                }
            }
            "!ENDTRNS" | "!ACCNT" | "ACCNT" => {}
            "TRNS" => {
                if current.is_some() {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("line {}: nested TRNS before ENDTRNS", line_idx + 1),
                    });
                }
                row_count += 1;
                let get = |col: &str| -> &str {
                    trns_cols
                        .get(col)
                        .and_then(|&i| fields.get(i))
                        .map(|s| s.trim())
                        .unwrap_or("")
                };
                let trns_id = {
                    let id = get("TRNSID");
                    if !id.is_empty() {
                        id.to_owned()
                    } else {
                        let doc = get("DOCNUM");
                        if !doc.is_empty() {
                            doc.to_owned()
                        } else {
                            format!("TRNS-{}", chunks.len() + 1)
                        }
                    }
                };
                let date = parse_date_flexible(FMT, get("DATE"))?;
                let raw_acct = get("ACCNT");
                let acct = account_map.resolve(FMT, raw_acct)?;
                let signed = parse_exact_decimal(FMT, get("AMOUNT"), scale)?;
                if signed == 0 {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("line {}: TRNS AMOUNT cannot be zero", line_idx + 1),
                    });
                }
                let (side, mantissa) = if signed > 0 {
                    (Side::Debit, signed)
                } else {
                    (Side::Credit, -signed)
                };
                let memo = get("MEMO");
                let ts_ns = parse_legacy_timestamp_ns(FMT, get("TIMESTAMP"))?;

                current = Some(LegacyChunkEntry {
                    provenance: MigratedProvenance {
                        source_system: LegacyFormat::QuickBooksIif
                            .default_source_system()
                            .to_owned(),
                        source_id: trns_id,
                        source_recorded_at_ns: ts_ns,
                        source_entered_by: None,
                        source_approved_by: None,
                    },
                    effective_date: date,
                    description: if memo.is_empty() {
                        get("TRNSTYPE").to_owned()
                    } else {
                        memo.to_owned()
                    },
                    legs: vec![FormatLeg {
                        dimensions: Vec::new(),
                        account_code: acct,
                        side,
                        amount: Amount::new(uid, mantissa),
                        unit_code: default_unit_code.to_owned(),
                        unit_scale: scale,
                        memo: (!memo.is_empty()).then(|| memo.to_owned()),
                    }],
                    leg_dimensions: BTreeMap::new(),
                });
            }
            "SPL" => {
                let Some(entry) = current.as_mut() else {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("line {}: SPL outside TRNS..ENDTRNS block", line_idx + 1),
                    });
                };
                row_count += 1;
                let get = |col: &str| -> &str {
                    spl_cols
                        .get(col)
                        .or_else(|| trns_cols.get(col))
                        .and_then(|&i| fields.get(i))
                        .map(|s| s.trim())
                        .unwrap_or("")
                };
                // SPL headers can have a different shape from TRNS. An absent
                // metadata column in a declared SPL header is not permission to
                // reinterpret an unrelated field at the TRNS column's offset.
                let metadata_cols = if spl_cols.is_empty() {
                    &trns_cols
                } else {
                    &spl_cols
                };
                let metadata = |col: &str| -> &str {
                    metadata_cols
                        .get(col)
                        .and_then(|&i| fields.get(i))
                        .map(|s| s.trim())
                        .unwrap_or("")
                };
                let split_date = metadata("DATE");
                if !split_date.is_empty()
                    && parse_date_flexible(FMT, split_date)? != entry.effective_date
                {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!(
                            "line {}: conflicting effective date within one legacy entry",
                            line_idx + 1
                        ),
                    });
                }
                merge_provenance_field(
                    &mut entry.provenance.source_recorded_at_ns,
                    parse_legacy_timestamp_ns(FMT, metadata("TIMESTAMP"))?,
                    FMT,
                    line_idx + 1,
                    "recorded timestamp",
                )?;
                let raw_acct = get("ACCNT");
                let acct = account_map.resolve(FMT, raw_acct)?;
                let signed = parse_exact_decimal(FMT, get("AMOUNT"), scale)?;
                if signed == 0 {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("line {}: SPL AMOUNT cannot be zero", line_idx + 1),
                    });
                }
                let (side, mantissa) = if signed > 0 {
                    (Side::Debit, signed)
                } else {
                    (Side::Credit, -signed)
                };
                let memo = get("MEMO");
                entry.legs.push(FormatLeg {
                    dimensions: Vec::new(),
                    account_code: acct,
                    side,
                    amount: Amount::new(uid, mantissa),
                    unit_code: default_unit_code.to_owned(),
                    unit_scale: scale,
                    memo: (!memo.is_empty()).then(|| memo.to_owned()),
                });
            }
            "ENDTRNS" => {
                let Some(entry) = current.take() else {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("line {}: ENDTRNS without matching TRNS", line_idx + 1),
                    });
                };
                chunks.push(entry);
            }
            other => {
                return Err(FormatError::Parse {
                    format: FMT,
                    detail: format!(
                        "line {}: unsupported IIF record tag {other:?}",
                        line_idx + 1
                    ),
                });
            }
        }
    }

    if current.is_some() {
        return Err(FormatError::Parse {
            format: FMT,
            detail: "unclosed TRNS block at end of IIF file".to_owned(),
        });
    }

    finalize_legacy_batch(
        LegacyFormat::QuickBooksIif,
        LegacyFormat::QuickBooksIif
            .default_source_system()
            .to_owned(),
        src,
        row_count,
        chunks,
    )
}

// ---------------------------------------------------------------------------
// 2. QuickBooks Journal Report CSV (`quickbooks_csv_v1`)
// ---------------------------------------------------------------------------

/// Parse a QuickBooks Online/Desktop Journal Report CSV export into a `LegacyImportBatch`.
pub fn parse_quickbooks_csv(
    src: &str,
    units: &UnitCatalog,
    account_map: &AccountMap,
    default_unit_code: &str,
) -> Result<LegacyImportBatch, FormatError> {
    let col_map = LegacyColumnMap {
        source_system: LegacyFormat::QuickBooksCsv
            .default_source_system()
            .to_owned(),
        default_unit: default_unit_code.to_owned(),
        entry_id_column: "Transaction ID".to_owned(),
        effective_date_column: "Date".to_owned(),
        recorded_at_column: Some("Created At".to_owned()),
        account_column: "Account".to_owned(),
        debit_column: Some("Debit".to_owned()),
        credit_column: Some("Credit".to_owned()),
        signed_amount_column: None,
        side_column: None,
        amount_column: None,
        debit_marker: "D".to_owned(),
        credit_marker: "C".to_owned(),
        unit_column: Some("Currency".to_owned()),
        description_column: Some("Memo/Description".to_owned()),
        memo_column: Some("Memo/Description".to_owned()),
        entered_by_column: Some("Created By".to_owned()),
        approved_by_column: None,
        account_mappings: BTreeMap::new(),
        dimension_columns: BTreeMap::new(),
    };
    parse_tabular_csv_with_format(
        LegacyFormat::QuickBooksCsv,
        src,
        &col_map,
        units,
        account_map,
    )
}

// ---------------------------------------------------------------------------
// 3. Xero Journal / Account Transactions CSV (`xero_csv_v1`)
// ---------------------------------------------------------------------------

/// Parse a Xero Journal CSV export into a `LegacyImportBatch`.
pub fn parse_xero_csv(
    src: &str,
    units: &UnitCatalog,
    account_map: &AccountMap,
    default_unit_code: &str,
) -> Result<LegacyImportBatch, FormatError> {
    let col_map = LegacyColumnMap {
        source_system: LegacyFormat::XeroCsv.default_source_system().to_owned(),
        default_unit: default_unit_code.to_owned(),
        entry_id_column: "JournalNumber".to_owned(),
        effective_date_column: "JournalDate".to_owned(),
        recorded_at_column: Some("CreatedDateUTC".to_owned()),
        account_column: "AccountCode".to_owned(),
        debit_column: Some("Debit".to_owned()),
        credit_column: Some("Credit".to_owned()),
        signed_amount_column: Some("Gross".to_owned()),
        side_column: None,
        amount_column: None,
        debit_marker: "D".to_owned(),
        credit_marker: "C".to_owned(),
        unit_column: Some("Currency".to_owned()),
        description_column: Some("Description".to_owned()),
        memo_column: Some("Reference".to_owned()),
        entered_by_column: Some("CreatedBy".to_owned()),
        approved_by_column: None,
        account_mappings: BTreeMap::new(),
        dimension_columns: BTreeMap::new(),
    };
    parse_tabular_csv_with_format(LegacyFormat::XeroCsv, src, &col_map, units, account_map)
}

// ---------------------------------------------------------------------------
// 4. NetSuite GL Detail CSV (`netsuite_csv_v1`)
// ---------------------------------------------------------------------------

/// Parse a NetSuite General Ledger Detail CSV export into a `LegacyImportBatch`.
pub fn parse_netsuite_csv(
    src: &str,
    units: &UnitCatalog,
    account_map: &AccountMap,
    default_unit_code: &str,
) -> Result<LegacyImportBatch, FormatError> {
    let col_map = LegacyColumnMap {
        source_system: LegacyFormat::NetSuiteCsv.default_source_system().to_owned(),
        default_unit: default_unit_code.to_owned(),
        entry_id_column: "Internal ID".to_owned(),
        effective_date_column: "Date".to_owned(),
        recorded_at_column: Some("System Date".to_owned()),
        account_column: "Account".to_owned(),
        debit_column: Some("Debit".to_owned()),
        credit_column: Some("Credit".to_owned()),
        signed_amount_column: None,
        side_column: None,
        amount_column: None,
        debit_marker: "D".to_owned(),
        credit_marker: "C".to_owned(),
        unit_column: Some("Currency".to_owned()),
        description_column: Some("Memo".to_owned()),
        memo_column: Some("Document Number".to_owned()),
        entered_by_column: Some("Created By".to_owned()),
        approved_by_column: Some("Approved By".to_owned()),
        account_mappings: BTreeMap::new(),
        dimension_columns: BTreeMap::new(),
    };
    parse_tabular_csv_with_format(LegacyFormat::NetSuiteCsv, src, &col_map, units, account_map)
}

// ---------------------------------------------------------------------------
// 5. Generic GL CSV with declared `LegacyColumnMap` (`csv_gl_v1`)
// ---------------------------------------------------------------------------

/// Parse a generic GL CSV export using a declared `LegacyColumnMap` into a `LegacyImportBatch`.
pub fn parse_generic_csv(
    src: &str,
    column_map: &LegacyColumnMap,
    units: &UnitCatalog,
    account_map: &AccountMap,
) -> Result<LegacyImportBatch, FormatError> {
    let merged_map = column_map.apply_to_account_map(account_map.clone());
    parse_tabular_csv_with_format(
        LegacyFormat::GenericCsv,
        src,
        column_map,
        units,
        &merged_map,
    )
}

fn parse_tabular_csv_with_format(
    format: LegacyFormat,
    src: &str,
    column_map: &LegacyColumnMap,
    units: &UnitCatalog,
    account_map: &AccountMap,
) -> Result<LegacyImportBatch, FormatError> {
    let fmt_name = format.registry_name();
    let header_description = format == LegacyFormat::GenericCsv
        && column_map.description_column != column_map.memo_column;
    for (kind, column) in &column_map.dimension_columns {
        if dimension_kind(kind).is_none() || column.trim().is_empty() || column.trim() != column {
            return Err(FormatError::Parse {
                format: fmt_name,
                detail: format!(
                    "dimension mapping {kind:?} must name a registered dimension kind and an exact nonblank source column"
                ),
            });
        }
    }
    let mut header_idx: Option<BTreeMap<String, usize>> = None;
    let mut entry_order: Vec<String> = Vec::new();
    let mut entries_by_id: BTreeMap<String, LegacyChunkEntry> = BTreeMap::new();
    let mut row_count = 0usize;

    for record in CsvRecords::legacy(src, fmt_name) {
        let CsvRecord::Row { line, fields } = record? else {
            continue;
        };
        let line_idx = line - 1;
        if header_idx.is_none() {
            let mut map = BTreeMap::new();
            for (i, h) in fields.iter().enumerate() {
                let name = h.trim();
                if name.is_empty() {
                    return Err(FormatError::Parse {
                        format: fmt_name,
                        detail: format!("line {line}: empty CSV header column {}", i + 1),
                    });
                }
                if map.insert(name.to_owned(), i).is_some() {
                    return Err(FormatError::Parse {
                        format: fmt_name,
                        detail: format!("line {line}: duplicate CSV header column {name:?}"),
                    });
                }
            }
            for req in [
                &column_map.entry_id_column,
                &column_map.effective_date_column,
                &column_map.account_column,
            ] {
                if !map.contains_key(req.as_str()) {
                    return Err(FormatError::Parse {
                        format: fmt_name,
                        detail: format!(
                            "missing required CSV header column {req:?} (found {:?})",
                            map.keys().collect::<Vec<_>>()
                        ),
                    });
                }
            }
            // An explicit generic mapping promises these source columns;
            // misspellings must not silently discard provenance. Built-in
            // vendor profiles retain their historical optional-column support.
            if format == LegacyFormat::GenericCsv {
                for column in [
                    &column_map.recorded_at_column,
                    &column_map.debit_column,
                    &column_map.credit_column,
                    &column_map.signed_amount_column,
                    &column_map.side_column,
                    &column_map.amount_column,
                    &column_map.unit_column,
                    &column_map.description_column,
                    &column_map.memo_column,
                    &column_map.entered_by_column,
                    &column_map.approved_by_column,
                ]
                .into_iter()
                .flatten()
                {
                    if !map.contains_key(column) {
                        return Err(FormatError::Parse {
                            format: fmt_name,
                            detail: format!(
                                "line {line}: missing declared CSV header column {column:?}"
                            ),
                        });
                    }
                }
            }
            for column in column_map.dimension_columns.values() {
                if !map.contains_key(column) {
                    return Err(FormatError::Parse {
                        format: fmt_name,
                        detail: format!(
                            "line {line}: missing declared dimension CSV header column {column:?}"
                        ),
                    });
                }
            }
            let has = |column: &Option<String>| {
                column.as_ref().is_some_and(|name| map.contains_key(name))
            };
            if has(&column_map.debit_column) != has(&column_map.credit_column)
                || has(&column_map.side_column) != has(&column_map.amount_column)
            {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!("line {line}: CSV amount column pairs must both be present"),
                });
            }
            if !has(&column_map.debit_column)
                && !has(&column_map.signed_amount_column)
                && !has(&column_map.side_column)
            {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!(
                        "line {line}: CSV header has no declared amount representation"
                    ),
                });
            }
            header_idx = Some(map);
            continue;
        }

        let headers = header_idx.as_ref().unwrap();
        if fields.len() != headers.len() {
            return Err(FormatError::Parse {
                format: fmt_name,
                detail: format!(
                    "line {line}: CSV record has {} columns; header declares {}",
                    fields.len(),
                    headers.len()
                ),
            });
        }
        let get_raw = |col: &str| -> &str {
            headers
                .get(col)
                .and_then(|&i| fields.get(i))
                .map(String::as_str)
                .unwrap_or("")
        };
        let get = |col: &str| -> &str { get_raw(col).trim() };
        let get_opt = |col: &Option<String>| -> &str { col.as_deref().map(get).unwrap_or("") };
        let get_text = |col: &Option<String>| -> &str { col.as_deref().map(get_raw).unwrap_or("") };

        row_count += 1;
        let entry_id = get_raw(&column_map.entry_id_column);
        if entry_id.trim().is_empty() {
            return Err(FormatError::Parse {
                format: fmt_name,
                detail: format!("line {}: empty entry_id", line_idx + 1),
            });
        }
        let eff_date = parse_date_flexible(fmt_name, get(&column_map.effective_date_column))?;
        let raw_account = get(&column_map.account_column);
        let account_code = account_map.resolve(fmt_name, raw_account)?;

        let unit_raw = get_opt(&column_map.unit_column);
        let unit_code = if unit_raw.is_empty() {
            column_map.default_unit.as_str()
        } else {
            unit_raw
        };
        let (uid, scale) =
            units
                .lookup_code(unit_code)
                .ok_or_else(|| FormatError::UnknownUnit {
                    format: fmt_name,
                    unit: unit_code.to_owned(),
                })?;

        let dr_str = get_opt(&column_map.debit_column);
        let cr_str = get_opt(&column_map.credit_column);
        let signed_str = get_opt(&column_map.signed_amount_column);
        let side_str = get_opt(&column_map.side_column);
        let amount_str = get_opt(&column_map.amount_column);

        let (side, mantissa) = if !dr_str.is_empty() || !cr_str.is_empty() {
            let dr = if dr_str.is_empty() {
                0
            } else {
                parse_exact_decimal(fmt_name, dr_str, scale)?
            };
            let cr = if cr_str.is_empty() {
                0
            } else {
                parse_exact_decimal(fmt_name, cr_str, scale)?
            };
            if (dr > 0 && cr > 0) || (dr == 0 && cr == 0) || dr < 0 || cr < 0 {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!(
                        "line {}: row must have exactly one positive debit or credit (dr={dr}, cr={cr})",
                        line_idx + 1
                    ),
                });
            }
            if dr > 0 {
                (Side::Debit, dr)
            } else {
                (Side::Credit, cr)
            }
        } else if !signed_str.is_empty() {
            let signed = parse_exact_decimal(fmt_name, signed_str, scale)?;
            if signed == 0 {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!("line {}: signed amount cannot be zero", line_idx + 1),
                });
            }
            if signed > 0 {
                (Side::Debit, signed)
            } else {
                (
                    Side::Credit,
                    signed.checked_neg().ok_or_else(|| FormatError::Overflow {
                        format: fmt_name,
                        detail: format!("line {line}: signed CSV amount magnitude overflows i128"),
                    })?,
                )
            }
        } else if !side_str.is_empty() || !amount_str.is_empty() {
            let side = if side_str.eq_ignore_ascii_case(&column_map.debit_marker) {
                Side::Debit
            } else if side_str.eq_ignore_ascii_case(&column_map.credit_marker) {
                Side::Credit
            } else {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!(
                        "line {}: side `{side_str}` is neither the debit marker `{}` nor the credit marker `{}`",
                        line_idx + 1,
                        column_map.debit_marker,
                        column_map.credit_marker
                    ),
                });
            };
            let amount = parse_exact_decimal(fmt_name, amount_str, scale)?;
            if amount <= 0 {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!(
                        "line {}: a side-indicated amount is positive (got `{amount_str}`); its side says which way it moves",
                        line_idx + 1
                    ),
                });
            }
            (side, amount)
        } else {
            return Err(FormatError::Parse {
                format: fmt_name,
                detail: format!(
                    "line {}: missing debit/credit, signed amount, or side and amount",
                    line_idx + 1
                ),
            });
        };

        // Every supplied amount representation is evidence. A priority rule
        // must not hide contradictory gross, signed, or side/amount columns.
        if !signed_str.is_empty() {
            let expected = if side == Side::Debit {
                mantissa
            } else {
                -mantissa
            };
            if parse_exact_decimal(fmt_name, signed_str, scale)? != expected {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!("line {line}: conflicting CSV amount representations"),
                });
            }
        }
        if !side_str.is_empty() || !amount_str.is_empty() {
            let marker = if side == Side::Debit {
                &column_map.debit_marker
            } else {
                &column_map.credit_marker
            };
            if !side_str.eq_ignore_ascii_case(marker)
                || parse_exact_decimal(fmt_name, amount_str, scale)? != mantissa
            {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!("line {line}: conflicting CSV amount representations"),
                });
            }
        }

        let desc = get_text(&column_map.description_column);
        let memo = get_text(&column_map.memo_column);
        let ts_ns = parse_legacy_timestamp_ns(fmt_name, get_opt(&column_map.recorded_at_column))?;
        let entered_by = {
            let v = get_text(&column_map.entered_by_column);
            (!v.is_empty()).then(|| v.to_owned())
        };
        let approved_by = {
            let v = get_text(&column_map.approved_by_column);
            (!v.is_empty()).then(|| v.to_owned())
        };
        let mut dimensions = BTreeMap::new();
        for (kind, column) in &column_map.dimension_columns {
            let code = get_raw(column);
            if code.trim().is_empty() {
                continue;
            }
            if let Some(problem) = dimension_value_problem(kind, code) {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!(
                        "line {line}: dimension {kind:?}: {problem}; nonblank identifiers are never trimmed"
                    ),
                });
            }
            dimensions.insert(kind.clone(), code.to_owned());
        }

        if !entries_by_id.contains_key(entry_id) {
            entry_order.push(entry_id.to_owned());
            entries_by_id.insert(
                entry_id.to_owned(),
                LegacyChunkEntry {
                    provenance: MigratedProvenance {
                        source_system: column_map.source_system.clone(),
                        source_id: entry_id.to_owned(),
                        source_recorded_at_ns: None,
                        source_entered_by: None,
                        source_approved_by: None,
                    },
                    effective_date: eff_date,
                    // Keep absence distinct from a supplied description equal
                    // to the entry ID. Apply the ID fallback after all rows.
                    description: String::new(),
                    legs: Vec::new(),
                    leg_dimensions: BTreeMap::new(),
                },
            );
        }
        let chunk = entries_by_id.get_mut(entry_id).unwrap();
        if chunk.effective_date != eff_date {
            return Err(FormatError::Parse {
                format: fmt_name,
                detail: format!(
                    "line {}: conflicting effective date within one legacy entry",
                    line_idx + 1
                ),
            });
        }
        if !desc.trim().is_empty() {
            if chunk.description.is_empty() {
                chunk.description = desc.to_owned();
            } else if header_description && chunk.description != desc {
                return Err(FormatError::Parse {
                    format: fmt_name,
                    detail: format!(
                        "line {line}: conflicting header description for legacy entry {entry_id:?}; map per-line descriptions with memo_column"
                    ),
                });
            }
        }
        merge_provenance_field(
            &mut chunk.provenance.source_recorded_at_ns,
            ts_ns,
            fmt_name,
            line_idx + 1,
            "recorded timestamp",
        )?;
        merge_provenance_field(
            &mut chunk.provenance.source_entered_by,
            entered_by,
            fmt_name,
            line_idx + 1,
            "entered-by identity",
        )?;
        merge_provenance_field(
            &mut chunk.provenance.source_approved_by,
            approved_by,
            fmt_name,
            line_idx + 1,
            "approved-by identity",
        )?;
        if !dimensions.is_empty() {
            chunk.leg_dimensions.insert(chunk.legs.len(), dimensions);
        }
        chunk.legs.push(FormatLeg {
            dimensions: Vec::new(),
            account_code,
            side,
            amount: Amount::new(uid, mantissa),
            unit_code: unit_code.to_owned(),
            unit_scale: scale,
            memo: (!memo.is_empty()).then(|| memo.to_owned()),
        });
    }

    let chunks: Vec<LegacyChunkEntry> = entry_order
        .into_iter()
        .filter_map(|id| {
            let mut chunk = entries_by_id.remove(&id)?;
            if chunk.description.is_empty() {
                chunk.description = id;
            }
            Some(chunk)
        })
        .collect();

    finalize_legacy_batch(
        format,
        column_map.source_system.clone(),
        src,
        row_count,
        chunks,
    )
}

// ---------------------------------------------------------------------------
// 6. Beancount v3 ledger (`beancount_v3`)
// ---------------------------------------------------------------------------

/// Transaction flags Beancount accepts besides `txn`.
const BEANCOUNT_FLAGS: &str = "*!PSTCURM#?%&";

/// Dated directives that carry no postings; skipped with their metadata.
const BEANCOUNT_INERT: &[&str] = &[
    "open",
    "close",
    "commodity",
    "price",
    "note",
    "document",
    "event",
    "query",
    "custom",
    "balance",
];

/// A transaction while its postings are read.
struct BeancountTxn {
    line: usize,
    date: DateDay,
    description: String,
    legs: Vec<FormatLeg>,
    /// The mapped account of the one posting without an amount.
    elided: Option<String>,
}

/// Parse a Beancount v3 ledger into a `LegacyImportBatch` (plan §8.6, bead
/// `fa-waow`). Each transaction is one entry whose source id is `L<line>`,
/// its header's line number in the retained source; each posting is a leg on
/// its full account name, resolved through `account_map`. A positive amount
/// is a debit.
///
/// The subset maps a ledger without inference beyond Beancount's own:
/// - one posting per transaction may omit its amount; it takes the negated
///   remainder of each unit, one leg per unit that has one (Beancount's rule);
/// - a posting at cost (`{…}`) or price (`@`, `@@`) converts between units,
///   which a legacy leg cannot carry, so it is refused, as are arithmetic
///   amounts, `pad` (Beancount synthesizes its posting), `include` and
///   `plugin` (it may rewrite transactions): import the ledger as Beancount
///   prints it after processing instead;
/// - `option`, the tag and metadata stacks, tag and metadata lines, and the
///   directives that carry no postings are skipped; `balance` assertions are
///   not re-checked here (bean-check is the source's own checker);
/// - a zero posting moves nothing and is dropped.
pub fn parse_beancount_ledger(
    src: &str,
    units: &UnitCatalog,
    account_map: &AccountMap,
) -> Result<LegacyImportBatch, FormatError> {
    const FMT: &str = "beancount_v3";
    let refuse = |line: usize, detail: String| FormatError::Parse {
        format: FMT,
        detail: format!("line {line}: {detail}"),
    };
    let reprint = "import the ledger as Beancount prints it after processing";
    let mut chunks = Vec::new();
    let mut row_count = 0usize;
    let mut current: Option<BeancountTxn> = None;
    for (idx, raw) in src.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_beancount_comment(raw.trim_end_matches('\r'));
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let body = line.trim();
            // Metadata of a directive without postings, or a transaction's
            // metadata, tags and links.
            let Some(txn) = current.as_mut() else {
                continue;
            };
            if is_beancount_metadata(body) || body.starts_with(['#', '^']) {
                continue;
            }
            row_count += 1;
            beancount_posting(txn, body, line_no, units, account_map)?;
            continue;
        }
        if let Some(txn) = current.take() {
            chunks.push(finish_ledger_txn(txn, LegacyFormat::Beancount)?);
        }
        if line.starts_with('*') {
            // An org-mode heading.
            continue;
        }
        let line = line.trim_start();
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or_default();
        match first {
            "option" | "pushtag" | "poptag" | "pushmeta" | "popmeta" => continue,
            "include" => {
                return Err(refuse(
                    line_no,
                    format!("include names another file; {reprint}"),
                ));
            }
            "plugin" => {
                return Err(refuse(
                    line_no,
                    format!("a plugin may rewrite transactions; {reprint}"),
                ));
            }
            _ => {}
        }
        let date = parse_date_iso(FMT, &first.replace('/', "-")).map_err(|_| {
            refuse(
                line_no,
                format!("`{first}` is neither a dated directive nor a known keyword"),
            )
        })?;
        let keyword = words.next().unwrap_or_default();
        if BEANCOUNT_INERT.contains(&keyword) {
            continue;
        }
        if keyword == "pad" {
            return Err(refuse(
                line_no,
                format!(
                    "pad asks Beancount to synthesize a posting; {reprint}, where it is explicit"
                ),
            ));
        }
        let flag =
            keyword == "txn" || (keyword.chars().count() == 1 && BEANCOUNT_FLAGS.contains(keyword));
        if !flag {
            return Err(refuse(
                line_no,
                format!("unsupported directive `{keyword}`"),
            ));
        }
        let after_date = line[first.len()..].trim_start();
        let header = after_date[keyword.len()..].trim();
        let description =
            beancount_description(header).map_err(|detail| refuse(line_no, detail))?;
        current = Some(BeancountTxn {
            line: line_no,
            date,
            description,
            legs: Vec::new(),
            elided: None,
        });
    }
    if let Some(txn) = current.take() {
        chunks.push(finish_ledger_txn(txn, LegacyFormat::Beancount)?);
    }
    finalize_legacy_batch(
        LegacyFormat::Beancount,
        LegacyFormat::Beancount.default_source_system().to_owned(),
        src,
        row_count,
        chunks,
    )
}

/// The line up to a `;` outside a string.
fn strip_beancount_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => return &line[..i],
            _ => {}
        }
    }
    line
}

/// `key: value`, a key starting with a lowercase letter (an account starts
/// with a capital, a flagged posting with its flag).
fn is_beancount_metadata(body: &str) -> bool {
    body.split_once(':').is_some_and(|(key, _)| {
        key.starts_with(|c: char| c.is_ascii_lowercase())
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// A transaction header after its flag: `"payee" "narration"` or
/// `"narration"`, then only tags and links.
fn beancount_description(header: &str) -> Result<String, String> {
    let mut strings = Vec::new();
    let mut rest = header.trim_start();
    while let Some(body) = rest.strip_prefix('"') {
        let mut text = String::new();
        let mut escaped = false;
        let mut end = None;
        for (i, c) in body.char_indices() {
            if escaped {
                text.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                end = Some(i);
                break;
            } else {
                text.push(c);
            }
        }
        let end = end.ok_or_else(|| {
            "an unterminated string (a string spanning lines is not supported)".to_string()
        })?;
        strings.push(text);
        rest = body[end + 1..].trim_start();
    }
    if let Some(word) = rest.split_whitespace().find(|w| !w.starts_with(['#', '^'])) {
        return Err(format!("unexpected `{word}` in a transaction header"));
    }
    match strings.as_slice() {
        [] => Ok(String::new()),
        [narration] => Ok(narration.clone()),
        [payee, narration] => Ok(format!("{payee}: {narration}")),
        _ => Err("a transaction header takes at most a payee and a narration".into()),
    }
}

/// One posting of `txn`: `[flag] Account [amount unit]`.
fn beancount_posting(
    txn: &mut BeancountTxn,
    body: &str,
    line: usize,
    units: &UnitCatalog,
    account_map: &AccountMap,
) -> Result<(), FormatError> {
    const FMT: &str = "beancount_v3";
    let refuse = |detail: String| FormatError::Parse {
        format: FMT,
        detail: format!("line {line}: {detail}"),
    };
    let mut words: Vec<&str> = body.split_whitespace().collect();
    if words.len() > 1 && words[0].chars().count() == 1 && BEANCOUNT_FLAGS.contains(words[0]) {
        words.remove(0);
    }
    let account = words[0];
    if body.contains(['{', '@']) {
        return Err(refuse(format!(
            "the posting on {account} is at cost or price, which converts between units; a legacy leg carries one unit"
        )));
    }
    let account_code = account_map.resolve(FMT, account)?;
    match words[1..] {
        [] => {
            if txn.elided.is_some() {
                return Err(refuse(
                    "a second posting without an amount; Beancount infers at most one".into(),
                ));
            }
            txn.elided = Some(account_code);
            Ok(())
        }
        [number, unit] => {
            let (uid, scale) = units
                .lookup_code(unit)
                .ok_or_else(|| FormatError::UnknownUnit {
                    format: FMT,
                    unit: unit.to_owned(),
                })?;
            if !number
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b',' | b'-' | b'+'))
            {
                return Err(refuse(format!(
                    "`{number}` is an arithmetic amount; write it as one decimal"
                )));
            }
            let signed = parse_exact_decimal(FMT, &number.replace(',', ""), scale)?;
            let (side, mantissa) = match signed.cmp(&0) {
                std::cmp::Ordering::Equal => return Ok(()),
                std::cmp::Ordering::Greater => (Side::Debit, signed),
                std::cmp::Ordering::Less => (
                    Side::Credit,
                    signed.checked_neg().ok_or_else(|| FormatError::Overflow {
                        format: FMT,
                        detail: format!("line {line}: the amount overflows"),
                    })?,
                ),
            };
            txn.legs.push(FormatLeg {
                dimensions: Vec::new(),
                account_code,
                side,
                amount: Amount::new(uid, mantissa),
                unit_code: unit.to_owned(),
                unit_scale: scale,
                memo: None,
            });
            Ok(())
        }
        _ => Err(refuse(format!(
            "the posting on {account} is not `account amount unit`"
        ))),
    }
}

/// The transaction as an entry; its posting without an amount takes each
/// unit's remainder, negated (Beancount's and hledger's rule alike).
fn finish_ledger_txn(
    txn: BeancountTxn,
    format: LegacyFormat,
) -> Result<LegacyChunkEntry, FormatError> {
    let overflow = || FormatError::Overflow {
        format: format.registry_name(),
        detail: format!("line {}: the remainder overflows", txn.line),
    };
    let mut legs = txn.legs;
    if let Some(account_code) = txn.elided {
        let mut net: BTreeMap<(String, UnitId, u8), i128> = BTreeMap::new();
        for leg in &legs {
            let cell = net
                .entry((leg.unit_code.clone(), leg.amount.unit, leg.unit_scale))
                .or_insert(0);
            *cell = match leg.side {
                Side::Debit => cell.checked_add(leg.amount.mantissa),
                Side::Credit => cell.checked_sub(leg.amount.mantissa),
            }
            .ok_or_else(overflow)?;
        }
        for ((unit_code, unit, unit_scale), net) in net {
            let (side, mantissa) = match net.cmp(&0) {
                std::cmp::Ordering::Equal => continue,
                std::cmp::Ordering::Greater => (Side::Credit, net),
                std::cmp::Ordering::Less => (Side::Debit, net.checked_neg().ok_or_else(overflow)?),
            };
            legs.push(FormatLeg {
                dimensions: Vec::new(),
                account_code: account_code.clone(),
                side,
                amount: Amount::new(unit, mantissa),
                unit_code,
                unit_scale,
                memo: None,
            });
        }
    }
    Ok(LegacyChunkEntry {
        provenance: MigratedProvenance {
            source_system: format.default_source_system().to_owned(),
            source_id: format!("L{}", txn.line),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
        },
        effective_date: txn.date,
        description: txn.description,
        legs,
        leg_dimensions: BTreeMap::new(),
    })
}

/// Parse an hledger journal into a `LegacyImportBatch` (plan §8.6, bead
/// `fa-waow`). Each transaction is one entry whose source id is `L<line>`,
/// its header's line number in the retained source; each posting is a leg on
/// its full account name, resolved through `account_map`. A positive amount
/// is a debit.
///
/// The subset maps a journal without inference beyond hledger's own:
/// - a header is `DATE[=DATE2] [*|!] [(CODE)] DESCRIPTION`, the date
///   `YYYY-MM-DD`, `YYYY/MM/DD` or `YYYY.MM.DD`; a secondary date is not the
///   posting date and is dropped;
/// - a posting is `[*|!] ACCOUNT` then two spaces or a tab and its amount; one
///   posting per transaction may omit its amount and takes the negated
///   remainder of each unit;
/// - an amount names its commodity by a registered unit code, before or
///   after the number (`USD 100.00`, `-100.00 EUR`). A symbol such as `$`
///   is refused, since it names no one currency, and so is an amount without
///   a commodity;
/// - the decimal mark is `.` with `,` digit groups, or the reverse after
///   `decimal-mark ,`;
/// - a balance assertion (`= …`) is stripped and not re-checked (hledger is
///   the source's own checker). A cost or price (`@`, `@@`) converts between
///   units and is refused. So are virtual postings (`(…)`, `[…]`), `include`,
///   `alias` and `apply account` (they rewrite accounts), auto postings
///   (`=`), and a year directive (partial dates);
/// - comments (`;`, `#`, `*` and `%` lines, `comment … end comment` blocks,
///   `;` to the end of a line), `account`, `commodity`, `payee`, `tag`, `P`
///   and `D` directives, and periodic transactions (`~`, a forecast) are
///   skipped;
/// - a zero posting moves nothing and is dropped.
pub fn parse_hledger_journal(
    src: &str,
    units: &UnitCatalog,
    account_map: &AccountMap,
) -> Result<LegacyImportBatch, FormatError> {
    const FMT: &str = "hledger_journal";
    let refuse = |line: usize, detail: String| FormatError::Parse {
        format: FMT,
        detail: format!("line {line}: {detail}"),
    };
    let reprint = "import the journal as hledger prints it (hledger print)";
    let mut chunks = Vec::new();
    let mut row_count = 0usize;
    let mut current: Option<BeancountTxn> = None;
    let mut decimal_comma = false;
    let mut in_comment = false;
    let mut in_forecast = false;
    for (idx, raw) in src.lines().enumerate() {
        let line_no = idx + 1;
        let raw = raw.trim_end_matches('\r');
        if in_comment {
            in_comment = raw.trim_end() != "end comment";
            continue;
        }
        if raw.starts_with([';', '#', '*', '%']) {
            continue;
        }
        let line = raw.split(';').next().unwrap_or_default();
        if raw.trim().is_empty() {
            continue;
        }
        if raw.starts_with([' ', '\t']) {
            // A posting, a comment of the transaction, or the indented body
            // of a directive or forecast.
            if in_forecast {
                continue;
            }
            let Some(txn) = current.as_mut() else {
                continue;
            };
            // A `date:` tag gives a posting a date of its own; a legacy entry
            // has one date.
            if let Some((_, comment)) = raw.split_once(';')
                && comment
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .any(|word| word.starts_with("date:"))
            {
                return Err(refuse(
                    line_no,
                    "a `date:` tag dates a posting apart from its transaction; split that posting into a transaction of its own date".into(),
                ));
            }
            if line.trim().is_empty() {
                continue;
            }
            row_count += 1;
            hledger_posting(txn, line.trim(), line_no, units, account_map, decimal_comma)?;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some(txn) = current.take() {
            chunks.push(finish_ledger_txn(txn, LegacyFormat::Hledger)?);
        }
        in_forecast = false;
        let line = line.trim_end();
        let first = line.split_whitespace().next().unwrap_or_default();
        match first {
            "comment" => {
                in_comment = true;
                continue;
            }
            "account" | "commodity" | "payee" | "tag" | "P" | "D" => continue,
            "~" => {
                in_forecast = true;
                continue;
            }
            "decimal-mark" => {
                decimal_comma = match line[first.len()..].trim() {
                    "," => true,
                    "." => false,
                    other => {
                        return Err(refuse(
                            line_no,
                            format!("decimal-mark `{other}` is neither . nor ,"),
                        ));
                    }
                };
                continue;
            }
            "include" => {
                return Err(refuse(
                    line_no,
                    format!("include names another file; {reprint}"),
                ));
            }
            "alias" | "apply" | "end" => {
                return Err(refuse(
                    line_no,
                    format!("`{first}` rewrites account names; {reprint}"),
                ));
            }
            "=" => {
                return Err(refuse(
                    line_no,
                    format!("an auto posting rule adds postings; {reprint}"),
                ));
            }
            "Y" | "year" => {
                return Err(refuse(
                    line_no,
                    format!("a year directive completes partial dates; {reprint}"),
                ));
            }
            _ => {}
        }
        // hledger also writes 2025/3/5; the month and day take two digits.
        let primary = first
            .split('=')
            .next()
            .unwrap_or_default()
            .replace(['/', '.'], "-")
            .split('-')
            .enumerate()
            .map(|(i, part)| {
                if i > 0 && part.len() == 1 {
                    format!("0{part}")
                } else {
                    part.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("-");
        let date = Some(primary.as_str())
            .filter(|text| text.split('-').next().is_some_and(|year| year.len() == 4))
            .and_then(|text| parse_date_iso(FMT, text).ok())
            .ok_or_else(|| {
                refuse(
                    line_no,
                    format!(
                        "`{first}` is neither a dated transaction (YYYY-MM-DD) nor a known directive"
                    ),
                )
            })?;
        let mut header = line[first.len()..].trim_start();
        if let Some(rest) = header
            .strip_prefix('*')
            .or_else(|| header.strip_prefix('!'))
            .filter(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
        {
            header = rest.trim_start();
        }
        if header.starts_with('(')
            && let Some(close) = header.find(')')
        {
            header = header[close + 1..].trim_start();
        }
        current = Some(BeancountTxn {
            line: line_no,
            date,
            description: header.trim().to_string(),
            legs: Vec::new(),
            elided: None,
        });
    }
    if let Some(txn) = current.take() {
        chunks.push(finish_ledger_txn(txn, LegacyFormat::Hledger)?);
    }
    finalize_legacy_batch(
        LegacyFormat::Hledger,
        LegacyFormat::Hledger.default_source_system().to_owned(),
        src,
        row_count,
        chunks,
    )
}

/// `number` (digits, `.` and `,`) as a plain `123.45`, read under the
/// journal's decimal mark: at most one decimal mark, no digit-group mark
/// after it, and digit groups of three after a first group of one to three.
/// Anything else (`1,5` or `1.000,00` under `.`, `1,234.5` under `,`) has no
/// single reading and is `None`, never guessed: a misread mark scales an
/// amount by a power of ten.
fn hledger_number(number: &str, decimal_comma: bool) -> Option<String> {
    let (mark, group) = if decimal_comma {
        (',', '.')
    } else {
        ('.', ',')
    };
    let (whole, fraction) = match number.split_once(mark) {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (number, None),
    };
    if fraction.is_some_and(|f| f.contains([mark, group])) {
        return None;
    }
    if whole.contains(group) {
        let mut groups = whole.split(group);
        let first = groups.next().unwrap_or_default();
        if !(1..=3).contains(&first.len()) || groups.any(|g| g.len() != 3) {
            return None;
        }
    }
    let whole = whole.replace(group, "");
    Some(match fraction {
        Some(fraction) => format!("{whole}.{fraction}"),
        None => whole,
    })
}

/// One hledger posting: its account up to two spaces or a tab, then its
/// amount, if any.
fn hledger_posting(
    txn: &mut BeancountTxn,
    body: &str,
    line: usize,
    units: &UnitCatalog,
    account_map: &AccountMap,
    decimal_comma: bool,
) -> Result<(), FormatError> {
    const FMT: &str = "hledger_journal";
    let refuse = |detail: String| FormatError::Parse {
        format: FMT,
        detail: format!("line {line}: {detail}"),
    };
    let mut body = body;
    if let Some(rest) = body
        .strip_prefix('*')
        .or_else(|| body.strip_prefix('!'))
        .filter(|rest| rest.starts_with([' ', '\t']))
    {
        body = rest.trim_start();
    }
    let split = body
        .find('\t')
        .into_iter()
        .chain(body.find("  "))
        .min()
        .unwrap_or(body.len());
    let account = body[..split].trim();
    if account.starts_with(['(', '[']) {
        return Err(refuse(format!(
            "`{account}` is a virtual posting; a ledger leg is always real and balanced"
        )));
    }
    let account_code = account_map.resolve(FMT, account)?;
    let amount = body[split..].split('=').next().unwrap_or_default().trim();
    if amount.is_empty() {
        if txn.elided.is_some() {
            return Err(refuse(
                "a second posting without an amount; hledger infers at most one".into(),
            ));
        }
        txn.elided = Some(account_code);
        return Ok(());
    }
    if amount.contains('@') {
        return Err(refuse(format!(
            "the posting on {account} has a cost or price, which converts between units; a legacy leg carries one unit"
        )));
    }
    let (negative, unsigned) = match amount.strip_prefix('-') {
        Some(rest) => (true, rest.trim_start()),
        None => (
            false,
            amount.strip_prefix('+').unwrap_or(amount).trim_start(),
        ),
    };
    let numeric = |c: char| c.is_ascii_digit() || c == '.' || c == ',';
    let (commodity, number) = if unsigned.starts_with(|c: char| c.is_ascii_digit()) {
        let end = unsigned
            .find(|c: char| !numeric(c))
            .unwrap_or(unsigned.len());
        (unsigned[end..].trim(), &unsigned[..end])
    } else {
        let start = unsigned
            .find(|c: char| c.is_ascii_digit() || c == '-' || c == '+')
            .unwrap_or(unsigned.len());
        (unsigned[..start].trim(), unsigned[start..].trim())
    };
    let (negative, number) = match number.strip_prefix('-') {
        Some(rest) if !negative => (true, rest),
        _ => (negative, number.strip_prefix('+').unwrap_or(number)),
    };
    let commodity = commodity.trim_matches('"');
    if commodity.is_empty() {
        return Err(refuse(format!(
            "`{amount}` names no commodity; write the unit's code (100.00 USD)"
        )));
    }
    if number.is_empty() || !number.chars().all(numeric) {
        return Err(refuse(format!(
            "`{amount}` is not one decimal amount with its commodity"
        )));
    }
    let (uid, scale) = units
        .lookup_code(commodity)
        .ok_or_else(|| FormatError::UnknownUnit {
            format: FMT,
            unit: commodity.to_owned(),
        })?;
    let plain = hledger_number(number, decimal_comma).ok_or_else(|| {
        refuse(format!(
            "`{amount}`: its digit groups and decimal mark do not read as the journal's decimal mark `{}`; declare `decimal-mark ,` or `decimal-mark .` before it",
            if decimal_comma { ',' } else { '.' }
        ))
    })?;
    let magnitude = parse_exact_decimal(FMT, &plain, scale)?;
    if magnitude == 0 {
        return Ok(());
    }
    txn.legs.push(FormatLeg {
        dimensions: Vec::new(),
        account_code,
        side: if negative { Side::Credit } else { Side::Debit },
        amount: Amount::new(uid, magnitude),
        unit_code: commodity.to_owned(),
        unit_scale: scale,
        memo: None,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa_journal::evidence::{Document, add_document};
    use fa_journal::{
        AccountSpec, ApprovalRequest, BookSpec, Capability, PostRequest, RunControlRequest,
        UnitPolicy, create_book, create_periods, install_chart, open_proposal, open_run,
        plan_run_transition, post, record_approval, transition_period, transition_run,
    };
    use fa_model::{SealKey, SymbolTable};
    use fa_money::UnitRegistry;
    use fa_registers::fold_period_at;
    use fa_time::{FiscalCalendar, PeriodTransition};
    use fgdb::{Database, DatabaseKeys, MemVfs};
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    const PRINCIPAL: VId = VId(7);
    const APPROVER_A: VId = VId(8);
    const APPROVER_B: VId = VId(9);

    fn test_account_map() -> AccountMap {
        let mut map = AccountMap::new(["1000", "1200", "2000", "3000", "4000", "5000"]);
        map.insert("1000 · Checking", "1000");
        map.insert("1200 · Accounts Receivable", "1200");
        map.insert("2000 · Accounts Payable", "2000");
        map.insert("3000 · Opening Balance Equity", "3000");
        map.insert("4000 · Sales Revenue", "4000");
        map.insert("5000 · Hosting Expense", "5000");
        map.insert("200", "4000");
        map.insert("090", "1000");
        map.insert("429", "5000");
        map
    }

    fn csv_columns(extra: &str) -> LegacyColumnMap {
        LegacyColumnMap::parse_toml(&format!(
            "[columns]\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\n{extra}"
        ))
        .expect("declared columns")
    }

    #[test]
    fn legacy_csv_dimensions_preserve_source_leg_identity_and_bind_the_projection() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns(
            "memo_column = \"memo\"\n[dimension_columns]\nproduct = \"product\"\ndepartment = \"department\"\n",
        );
        let source = concat!(
            "entry,date,account,amount,memo,department,product\r\n",
            "A,2025-12-31,1000,12.50,\"first\r\nsecond\",0100001,01\r\n",
            "B,2025-12-31,1000,2.00,other,8800001,\r\n",
            "A,2025-12-31,3000,-12.50,capital, ,\r\n",
            "B,2025-12-31,3000,-2.00,capital,8800001,\r\n",
        );
        let batch = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(batch.row_count, 4);
        assert_eq!(batch.chunks[0].provenance.source_id, "A");
        assert_eq!(batch.chunks[1].provenance.source_id, "B");
        assert_eq!(batch.chunks[0].leg_dimensions.len(), 1);
        assert_eq!(batch.chunks[0].leg_dimensions[&0]["department"], "0100001");
        assert_eq!(batch.chunks[0].leg_dimensions[&0]["product"], "01");
        assert_eq!(batch.chunks[1].leg_dimensions[&1]["department"], "8800001");
        assert_eq!(
            batch.chunks[0].legs[0].memo.as_deref(),
            Some("first\r\nsecond")
        );

        let book = BookContext {
            book_id: Id128([0x64; 16]),
            calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
            units: UnitRegistry::with_defaults(),
            seal_key: SealKey([0x44; 32]),
            symbols: SymbolTable::compiled(),
        };
        let mut counter = 0_u64;
        let proposals = batch
            .to_chunk_proposals_with_sealer(
                &book,
                VId(1),
                DateDay::parse("2026-01-01").unwrap(),
                Some("FY2026-OPEN"),
                PRINCIPAL,
                Oid([0x82; 32]),
                Vec::new(),
                |text| {
                    counter += 1;
                    let mut salt = [0x91; 32];
                    salt[..8].copy_from_slice(&counter.to_le_bytes());
                    let mut nonce = [0x92; 24];
                    nonce[..8].copy_from_slice(&counter.to_le_bytes());
                    Ok::<_, FormatError>(Erasable::seal(
                        &text.to_owned(),
                        None,
                        &book.seal_key,
                        salt,
                        nonce,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            proposals[0].legs[0].dimension_set,
            vec![
                (
                    3,
                    dimension_value_vid(book.book_id, "department", "0100001")
                ),
                (5, dimension_value_vid(book.book_id, "product", "01")),
            ]
        );
        assert!(proposals[0].legs[1].dimension_set.is_empty());

        // Interop's raw native IDs are book-local. A programmatic caller
        // cannot hide them inside a legacy leg and have import discard them
        // or mistake them for codes in the destination book.
        let mut foreign_ids = batch.clone();
        foreign_ids.chunks[0].legs[0].dimensions = vec![(3, 0xab)];
        let mut sealed = 0;
        let error = foreign_ids
            .to_chunk_proposals_with_sealer(
                &book,
                VId(1),
                DateDay::parse("2026-01-01").unwrap(),
                Some("FY2026-OPEN"),
                PRINCIPAL,
                Oid([0x82; 32]),
                Vec::new(),
                |_| {
                    sealed += 1;
                    Err::<Erasable<String>, _>(FormatError::Parse {
                        format: "test",
                        detail: "sealer must not be reached".into(),
                    })
                },
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("explicit named dimension code mappings")
        );
        assert_eq!(
            sealed, 0,
            "no approval proposal or private commitment was generated"
        );

        let mut no_projection = columns.clone();
        no_projection.dimension_columns.clear();
        let plain = parse_generic_csv(source, &no_projection, &units, &accounts).unwrap();
        assert_eq!(batch.source_bytes_digest, plain.source_bytes_digest);
        assert_eq!(batch.trial_balance, plain.trial_balance);
        assert_ne!(batch.attestation_digest, plain.attestation_digest);
        let mut reassigned = columns;
        reassigned
            .dimension_columns
            .insert("department".into(), "product".into());
        let changed = parse_generic_csv(source, &reassigned, &units, &accounts).unwrap();
        assert_ne!(batch.attestation_digest, changed.attestation_digest);
    }

    #[test]
    fn legacy_csv_empty_dimension_projection_preserves_dimension_free_attestations() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let source = "entry,date,account,amount,department\nA,2025-12-31,1000,1.00, \nA,2025-12-31,3000,-1.00,\n";
        let plain = parse_generic_csv(source, &csv_columns(""), &units, &accounts).unwrap();
        let mapped = parse_generic_csv(
            source,
            &csv_columns("[dimension_columns]\ndepartment = \"department\"\n"),
            &units,
            &accounts,
        )
        .unwrap();
        assert_eq!(
            plain, mapped,
            "absent values do not change historical import bytes or digests"
        );
    }

    #[test]
    fn legacy_csv_dimension_mappings_refuse_ambiguity_missing_columns_and_invalid_codes() {
        for declaration in [
            "[dimension_columns]\ndepartment = \"department\"\ndepartment = \"other\"\n",
            "[dimension_columns]\nunknown_kind = \"department\"\n",
            "[dimension_columns]\nparty = \"party\"\n",
            "[dimension_columns]\ndepartment = \" \"\n",
            "[dimension_columns]\ndepartment = \" department\"\n",
        ] {
            let text = format!(
                "[columns]\nentry_id_column=\"entry\"\neffective_date_column=\"date\"\naccount_column=\"account\"\nsigned_amount_column=\"amount\"\n{declaration}"
            );
            assert!(LegacyColumnMap::parse_toml(&text).is_err(), "{declaration}");
        }
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("[dimension_columns]\ndepartment = \"department\"\n");
        let missing =
            "entry,date,account,amount\nA,2025-12-31,1000,1.00\nA,2025-12-31,3000,-1.00\n";
        let error = parse_generic_csv(missing, &columns, &units, &accounts).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing declared dimension CSV header")
        );
        for invalid_code in [" 0100001", "0100001 ", "01 00001", "café", "01\t00001"] {
            let source = format!(
                "entry,date,account,amount,department\nA,2025-12-31,1000,1.00,{invalid_code}\nA,2025-12-31,3000,-1.00,\n"
            );
            let error = parse_generic_csv(&source, &columns, &units, &accounts).unwrap_err();
            assert!(
                error.to_string().contains("line 2: dimension"),
                "{invalid_code:?}: {error}"
            );
        }
        let mut batch = parse_generic_csv(
            "entry,date,account,amount,department\nA,2025-12-31,1000,1.00,0100001\nA,2025-12-31,3000,-1.00,\n",
            &columns, &units, &accounts,
        ).unwrap();
        let values = batch.chunks[0].leg_dimensions[&0].clone();
        batch.chunks[0].leg_dimensions.insert(2, values);
        assert!(
            batch.chunks[0].validate_dimensions("csv").is_err(),
            "no dimension may silently lose its source leg"
        );
    }

    #[test]
    fn legacy_csv_multiline_records_preserve_exact_text_and_interleaved_entries() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("description_column = \"description\"\nmemo_column = \"memo\"\n");
        let source = concat!(
            "\u{feff}# retained source export\r\n",
            "\"entry\",date,account,amount,description,memo\r\n",
            "J-A,2025-12-31,1000,1234.56,\"  Café, Inc.  \",\"Invoice \"\"A\"\"\r\n",
            "# this is memo data, not a comment\"\r\n",
            "J-B,2025-12-30,5000,9.00,Expense,\"first\nsecond\"\r\n",
            "J-A,2025-12-31,3000,-1000.00,\"  Café, Inc.  \",\"  significant spaces  \"\r\n",
            "J-A,2025-12-31,4000,-234.56,\"  Café, Inc.  \",\"\"\r\n",
            "J-B,2025-12-30,1000,-9.00,Expense,last record without newline",
        );
        let batch = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(
            batch.row_count, 5,
            "logical source rows, not physical lines"
        );
        assert_eq!(batch.chunks.len(), 2);
        assert_eq!(batch.chunks[0].provenance.source_id, "J-A");
        assert_eq!(batch.chunks[1].provenance.source_id, "J-B");
        assert_eq!(batch.chunks[0].description, "  Café, Inc.  ");
        assert_eq!(
            batch.chunks[0].legs[0].memo.as_deref(),
            Some("Invoice \"A\"\r\n# this is memo data, not a comment")
        );
        assert_eq!(
            batch.chunks[0].legs[1].memo.as_deref(),
            Some("  significant spaces  ")
        );
        assert_eq!(batch.chunks[0].legs[2].memo, None);
        assert_eq!(
            batch.chunks[1].legs[0].memo.as_deref(),
            Some("first\nsecond")
        );
        let balances: Vec<_> = batch
            .trial_balance
            .iter()
            .map(|line| (line.account_code.as_str(), line.mantissa))
            .collect();
        assert_eq!(
            balances,
            [
                ("1000", 122_556),
                ("3000", -100_000),
                ("4000", -23_456),
                ("5000", 900)
            ]
        );
        let replay = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(batch, replay);
        // Only the record separator changes: the source commitment must still
        // change even though the monetary interpretation is identical.
        let changed = source.replacen("export\r\n", "export\n", 1);
        let changed = parse_generic_csv(&changed, &columns, &units, &accounts).unwrap();
        assert_eq!(batch.chunks, changed.chunks);
        assert_ne!(batch.source_bytes_digest, changed.source_bytes_digest);
        assert_ne!(batch.attestation_digest, changed.attestation_digest);
    }

    #[test]
    fn legacy_csv_conflicting_header_description_is_refused_with_source_context() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("description_column = \"description\"\nmemo_column = \"memo\"\n");
        // Preserve the original multiline regression source: it used to pass
        // while silently dropping Capital, Revenue and Payment as headers.
        let source = concat!(
            "\u{feff}# retained source export\r\n",
            "\"entry\",date,account,amount,description,memo\r\n",
            "J-A,2025-12-31,1000,1234.56,\"  Café, Inc.  \",\"Invoice \"\"A\"\"\r\n",
            "# this is memo data, not a comment\"\r\n",
            "J-B,2025-12-30,5000,9.00,Expense,\"first\nsecond\"\r\n",
            "J-A,2025-12-31,3000,-1000.00,Capital,\"  significant spaces  \"\r\n",
            "J-A,2025-12-31,4000,-234.56,Revenue,\"\"\r\n",
            "J-B,2025-12-30,1000,-9.00,Payment,last record without newline",
        );
        let error = parse_generic_csv(source, &columns, &units, &accounts)
            .expect_err("a separate header description cannot silently lose source text");
        let message = error.to_string();
        assert!(message.contains("line 7: conflicting header description"));
        assert!(message.contains("legacy entry \"J-A\""));
        assert!(message.contains("memo_column"));
    }

    #[test]
    fn legacy_csv_header_descriptions_merge_sparse_interleaved_rows_exactly() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("description_column = \"description\"\nmemo_column = \"memo\"\n");
        let source = concat!(
            "entry,date,account,amount,description,memo\n",
            "J-A,2025-12-31,1000,125.00,\" \t \",\"  cash leg  \"\n",
            "J-B,2025-12-30,5000,9.00,Expense,expense detail\n",
            "J-A,2025-12-31,3000,-100.00,\"  Café, Inc.  \",capital detail\n",
            "J-C,2025-12-29,1000,1.00,,blank header debit\n",
            "J-B,2025-12-30,1000,-9.00,Expense,payment detail\n",
            "J-A,2025-12-31,4000,-25.00,,revenue detail\n",
            "J-C,2025-12-29,1000,-1.00,\"   \",blank header credit\n",
        );
        let batch = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(batch.row_count, 7);
        assert_eq!(batch.chunks.len(), 3);
        assert_eq!(batch.chunks[0].provenance.source_id, "J-A");
        assert_eq!(batch.chunks[0].description, "  Café, Inc.  ");
        assert_eq!(batch.chunks[1].provenance.source_id, "J-B");
        assert_eq!(batch.chunks[1].description, "Expense");
        assert_eq!(batch.chunks[2].provenance.source_id, "J-C");
        assert_eq!(batch.chunks[2].description, "J-C");
        assert_eq!(
            batch.chunks[0]
                .legs
                .iter()
                .map(|leg| (leg.side, leg.amount.mantissa, leg.memo.as_deref()))
                .collect::<Vec<_>>(),
            [
                (Side::Debit, 12_500, Some("  cash leg  ")),
                (Side::Credit, 10_000, Some("capital detail")),
                (Side::Credit, 2_500, Some("revenue detail")),
            ]
        );
        assert_eq!(
            batch
                .trial_balance
                .iter()
                .map(|line| (line.account_code.as_str(), line.mantissa))
                .collect::<Vec<_>>(),
            [
                ("1000", 11_600),
                ("3000", -10_000),
                ("4000", -2_500),
                ("5000", 900)
            ]
        );
    }

    #[test]
    fn legacy_csv_header_description_conflicts_preserve_whitespace_and_literal_ids() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("description_column = \"description\"\n");
        for (first, later) in [("J-A", "Changed"), ("  Header  ", "Header")] {
            let source = format!(
                "entry,date,account,amount,description\nJ-A,2025-12-31,1000,1.00,\"{first}\"\nJ-A,2025-12-31,3000,-1.00,\"{later}\"\n"
            );
            let error = parse_generic_csv(&source, &columns, &units, &accounts).expect_err(
                "nonblank headers must agree byte-for-byte, even when one equals the ID",
            );
            let message = error.to_string();
            assert!(message.contains("line 3: conflicting header description"));
            assert!(message.contains("legacy entry \"J-A\""));
        }
    }

    #[test]
    fn legacy_csv_shared_description_memo_column_preserves_each_leg() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("description_column = \"memo\"\nmemo_column = \"memo\"\n");
        let source = concat!(
            "entry,date,account,amount,memo\n",
            "J-A,2025-12-31,1000,125.00,\"   \"\n",
            "J-A,2025-12-31,3000,-100.00,\"  Capital, Café  \"\n",
            "J-A,2025-12-31,4000,-25.00,\"Revenue\nline detail\"\n",
        );
        let batch = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(batch.row_count, 3);
        assert_eq!(batch.chunks.len(), 1);
        assert_eq!(batch.chunks[0].description, "  Capital, Café  ");
        assert_eq!(
            batch.chunks[0]
                .legs
                .iter()
                .map(|leg| (leg.side, leg.amount.mantissa, leg.memo.as_deref()))
                .collect::<Vec<_>>(),
            [
                (Side::Debit, 12_500, Some("   ")),
                (Side::Credit, 10_000, Some("  Capital, Café  ")),
                (Side::Credit, 2_500, Some("Revenue\nline detail")),
            ]
        );
    }

    #[test]
    fn legacy_csv_refuses_malformed_quotes_and_reports_physical_source_lines() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("memo_column = \"memo\"\n");
        for (memo, diagnostic) in [
            ("unquoted\"text", "unexpected quote"),
            ("\"closed\"suffix", "unexpected text"),
            ("\"never closed", "unterminated quoted CSV field"),
        ] {
            let source = format!(
                "entry,date,account,amount,memo\nJ1,2025-12-31,1000,10.00,{memo}\nJ1,2025-12-31,3000,-10.00,credit\n"
            );
            let error = parse_generic_csv(&source, &columns, &units, &accounts)
                .expect_err("malformed quoting must not be repaired into a balanced entry");
            assert!(matches!(error, FormatError::Parse { detail, .. }
                if detail.contains("line 2") && detail.contains(diagnostic)));
        }
        let source = concat!(
            "entry,date,account,amount,memo\r\n",
            "J1,2025-12-31,1000,10.00,\"first\r\nsecond\"\r\n",
            "J1,2026-01-01,3000,-10.00,credit\r\n",
        );
        let error = parse_generic_csv(source, &columns, &units, &accounts).unwrap_err();
        assert!(matches!(error, FormatError::Parse { detail, .. }
            if detail.contains("line 4") && detail.contains("conflicting effective date")));
    }

    #[test]
    fn legacy_csv_refuses_duplicate_empty_and_ragged_columns() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = csv_columns("memo_column = \"memo\"\n");
        for (source, diagnostic) in [
            (
                "entry,date,account,amount,memo, account\nJ1,2025-12-31,1000,10.00,cash,1000\nJ1,2025-12-31,3000,-10.00,equity,3000\n",
                "duplicate CSV header",
            ),
            (
                "entry,date,account,amount,memo,\nJ1,2025-12-31,1000,10.00,cash,\nJ1,2025-12-31,3000,-10.00,equity,\n",
                "empty CSV header",
            ),
            (
                "entry,date,account,amount,memo\nJ1,2025-12-31,1000,10.00\nJ1,2025-12-31,3000,-10.00,equity\n",
                "line 2: CSV record has 4 columns; header declares 5",
            ),
            (
                "entry,date,account,amount,memo\nJ1,2025-12-31,1000,10.00,cash,ignored\nJ1,2025-12-31,3000,-10.00,equity\n",
                "line 2: CSV record has 6 columns; header declares 5",
            ),
        ] {
            let error = parse_generic_csv(source, &columns, &units, &accounts).unwrap_err();
            assert!(matches!(error, FormatError::Parse { detail, .. }
                if detail.contains(diagnostic)));
        }
    }

    #[test]
    fn legacy_csv_requires_every_explicit_mapping_without_erasing_metadata() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let source =
            "entry,date,account,amount\nJ1,2025-12-31,1000,10.00\nJ1,2025-12-31,3000,-10.00\n";
        parse_generic_csv(source, &csv_columns(""), &units, &accounts).unwrap();
        for mapping in [
            "recorded_at_column",
            "unit_column",
            "description_column",
            "memo_column",
            "entered_by_column",
            "approved_by_column",
        ] {
            let columns = csv_columns(&format!("{mapping} = \"absent\"\n"));
            let error = parse_generic_csv(source, &columns, &units, &accounts).unwrap_err();
            assert!(matches!(error, FormatError::Parse { detail, .. }
                if detail.contains("line 1") && detail.contains("missing declared CSV header column \"absent\"")));
        }
        let minimum = source.replace("-10.00", "-1701411834604692317316873037158841057.28");
        assert!(
            parse_generic_csv(&minimum, &csv_columns(""), &units, &accounts).is_err(),
            "the magnitude of i128::MIN cannot become a positive credit"
        );
    }

    #[test]
    fn vendor_csv_keeps_optional_metadata_and_alternate_xero_amount_layouts() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let quickbooks = "Transaction ID,Date,Account,Debit,Credit\nJ1,2025-12-31,1000,10.00,\nJ1,2025-12-31,3000,,10.00\n";
        let qb = parse_quickbooks_csv(quickbooks, &units, &accounts, "USD").unwrap();
        assert_eq!(qb.chunks[0].provenance.source_entered_by, None);
        let netsuite = quickbooks.replace("Transaction ID", "Internal ID");
        let ns = parse_netsuite_csv(&netsuite, &units, &accounts, "USD").unwrap();
        assert_eq!(ns.trial_balance, qb.trial_balance);
        let xero = "JournalNumber,JournalDate,AccountCode,Gross\nJ1,2025-12-31,1000,10.00\nJ1,2025-12-31,3000,-10.00\n";
        let xero = parse_xero_csv(xero, &units, &accounts, "USD").unwrap();
        assert_eq!(xero.trial_balance, qb.trial_balance);
        let xero_debits = quickbooks
            .replace("Transaction ID", "JournalNumber")
            .replace("Date", "JournalDate")
            .replace("Account", "AccountCode");
        assert_eq!(
            parse_xero_csv(&xero_debits, &units, &accounts, "USD")
                .unwrap()
                .trial_balance,
            qb.trial_balance
        );
        let partial_pair = "Transaction ID,Date,Account,Debit\nJ1,2025-12-31,1000,10.00\n";
        let error = parse_quickbooks_csv(partial_pair, &units, &accounts, "USD").unwrap_err();
        assert!(matches!(error, FormatError::Parse { detail, .. }
            if detail.contains("CSV amount column pairs must both be present")));
    }

    #[test]
    fn quickbooks_iif_parses_and_refuses_unmapped_accounts_with_fix_hint() {
        let units = UnitCatalog::embedded().expect("units");
        let map = test_account_map();
        let iif = "\
!TRNS\tTRNSID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tDOCNUM\tMEMO\tTIMESTAMP
!SPL\tSPLID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tDOCNUM\tMEMO
!ENDTRNS
TRNS\tQB-101\tGENERAL JOURNAL\t2025-12-15\t1000 · Checking\t2500.00\t101\tSeed deposit\t1765756800
SPL\tQB-101-1\tGENERAL JOURNAL\t2025-12-15\t3000 · Opening Balance Equity\t-2000.00\t101\tCapital
SPL\tQB-101-2\tGENERAL JOURNAL\t2025-12-15\t4000 · Sales Revenue\t-500.00\t101\tInitial sale
ENDTRNS
";
        let batch = parse_quickbooks_iif(iif, &units, &map, "USD").expect("valid IIF");
        assert_eq!(batch.row_count, 3);
        assert_eq!(batch.chunks.len(), 1);
        assert_eq!(batch.chunks[0].provenance.source_id, "QB-101");
        assert_eq!(
            batch.chunks[0].provenance.source_recorded_at_ns,
            Some(1_765_756_800_000_000_000)
        );
        assert_eq!(batch.trial_balance.len(), 3);

        // Planted negative: unmapped account produces exact `[account_map]` fix hint.
        let bad_iif = iif.replace("4000 · Sales Revenue", "9999 · Mystery Suspense");
        let err = parse_quickbooks_iif(&bad_iif, &units, &map, "USD")
            .expect_err("unmapped account must fail");
        assert!(
            matches!(
                &err,
                FormatError::UnmappedAccount {
                    legacy_account,
                    fix_hint,
                    ..
                } if legacy_account == "9999 · Mystery Suspense" && fix_hint.contains("[account_map]")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn grouped_csv_rows_preserve_optional_provenance_and_refuse_conflicts() {
        let units = UnitCatalog::embedded().expect("units");
        let accounts = test_account_map();
        let columns = LegacyColumnMap::parse_toml(
            r#"[columns]
source_system = "legacy-provenance-test"
default_unit = "USD"
entry_id_column = "entry"
effective_date_column = "date"
recorded_at_column = "recorded"
account_column = "account"
signed_amount_column = "amount"
description_column = "memo"
memo_column = "memo"
entered_by_column = "entered"
approved_by_column = "approved"
"#,
        )
        .expect("columns");
        let source = "\
entry,date,recorded,account,amount,memo,entered,approved
ENTRY-1,2025-12-31,,1000,125.00,Cash,,
ENTRY-1,2025-12-31,2025-12-31T10:00:00Z,3000,-100.00,Capital,Alice,Carol
ENTRY-1,2025-12-31,,4000,-25.00,Revenue,,
";
        let batch =
            parse_generic_csv(source, &columns, &units, &accounts).expect("sparse metadata");
        assert_eq!(batch.chunks.len(), 1);
        let chunk = &batch.chunks[0];
        assert_eq!(
            chunk.effective_date,
            DateDay::from_ymd(2025, 12, 31).unwrap()
        );
        assert_eq!(
            chunk.provenance.source_recorded_at_ns,
            Some(1_767_175_200_000_000_000)
        );
        assert_eq!(chunk.provenance.source_entered_by.as_deref(), Some("Alice"));
        assert_eq!(
            chunk.provenance.source_approved_by.as_deref(),
            Some("Carol")
        );
        assert_eq!(
            chunk
                .legs
                .iter()
                .map(|leg| leg.memo.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("Cash"), Some("Capital"), Some("Revenue")]
        );

        // Repeated supplied values agree; blank values on either side inherit.
        let repeated = source.replace("Revenue,,", "Revenue,Alice,Carol");
        assert_eq!(
            parse_generic_csv(&repeated, &columns, &units, &accounts)
                .expect("consistent metadata")
                .chunks[0]
                .provenance,
            chunk.provenance
        );

        for (changed, field) in [
            (
                source.replace("ENTRY-1,2025-12-31,,4000", "ENTRY-1,2026-01-01,,4000"),
                "effective date",
            ),
            (
                source.replace(
                    "ENTRY-1,2025-12-31,,4000",
                    "ENTRY-1,2025-12-31,2025-12-31T11:00:00Z,4000",
                ),
                "recorded timestamp",
            ),
            (
                source.replace("Revenue,,", "Revenue,Bob,"),
                "entered-by identity",
            ),
            (
                source.replace("Revenue,,", "Revenue,,Dana"),
                "approved-by identity",
            ),
        ] {
            let error = parse_generic_csv(&changed, &columns, &units, &accounts)
                .expect_err("one entry cannot silently discard inconsistent row metadata");
            assert!(matches!(
                error,
                FormatError::Parse { detail, .. }
                    if detail.contains("line 4") && detail.contains(field)
            ));
        }
    }

    fn real_world_csv_columns(extra: &str) -> LegacyColumnMap {
        LegacyColumnMap::parse_toml(&format!(
            "[columns]\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\nmemo_column = \"memo\"\n{extra}"
        ))
        .expect("explicit CSV columns")
    }

    #[test]
    fn legacy_csv_preserves_multiline_records_bom_quotes_ids_and_exact_large_amounts() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = real_world_csv_columns(
            "recorded_at_column = \"recorded\"\nentered_by_column = \"entered\"\napproved_by_column = \"approved\"\n",
        );
        let source = concat!(
            "\u{feff}# source comment, with an unmatched quote: \"\r\n",
            "entry,date,account,amount,memo,recorded,entered,approved\r\n",
            "\"000001,part \"\"A\"\"\",2025-12-31,1000,90071992547409.93,\"  café, \"\"proof\"\"\r\n",
            "# this is retained evidence, not a comment\n",
            "last line  \",2025-12-31T10:00:00Z,Alice,Carol\r\n",
            "#OTHER,2025-12-31,1000,0.01,small debit,,,\r\n",
            "#OTHER,2025-12-31,3000,-0.01,small credit,,,\r\n",
            "\"000001,part \"\"A\"\"\",2025-12-31,3000,-90071992547409.93,\"credit, account\",,,",
        );
        let batch = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(batch.row_count, 4, "physical lines are not source rows");
        assert_eq!(batch.chunks.len(), 2);
        let first = &batch.chunks[0];
        assert_eq!(first.provenance.source_id, "000001,part \"A\"");
        assert_eq!(first.legs.len(), 2);
        assert_eq!(first.legs[0].amount.mantissa, 9_007_199_254_740_993);
        assert_eq!(first.legs[1].amount.mantissa, 9_007_199_254_740_993);
        assert_eq!(first.legs[0].side, Side::Debit);
        assert_eq!(first.legs[1].side, Side::Credit);
        assert_eq!(
            first.legs[0].memo.as_deref(),
            Some("  café, \"proof\"\r\n# this is retained evidence, not a comment\nlast line  ")
        );
        assert_eq!(first.legs[1].memo.as_deref(), Some("credit, account"));
        assert_eq!(first.provenance.source_entered_by.as_deref(), Some("Alice"));
        assert_eq!(
            first.provenance.source_approved_by.as_deref(),
            Some("Carol")
        );
        assert_eq!(batch.chunks[1].provenance.source_id, "#OTHER");
        assert_eq!(batch.trial_balance[0].mantissa, 9_007_199_254_740_994);

        // The parser never normalizes the retained source commitment, even
        // when an LF-only source happens to yield the same monetary legs.
        let lf_only =
            parse_generic_csv(&source.replace("\r\n", "\n"), &columns, &units, &accounts).unwrap();
        assert_ne!(batch.source_bytes_digest, lf_only.source_bytes_digest);

        let changed = source.replace("\"credit, account\",,,", "\"credit, account\",,Mallory,");
        let error = parse_generic_csv(&changed, &columns, &units, &accounts).unwrap_err();
        assert!(matches!(error, FormatError::Parse { detail, .. }
            if detail.contains("line 8") && detail.contains("entered-by identity")));
    }

    #[test]
    fn legacy_csv_refuses_malformed_quotes_duplicate_headers_and_ragged_rows() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = real_world_csv_columns("");
        let header = "entry,date,account,amount,memo\n";
        for (source, reason) in [
            (
                format!("{header}E\"1,2025-12-31,1000,1.00,memo\n"),
                "unexpected quote",
            ),
            (
                format!("{header}\"E1\"junk,2025-12-31,1000,1.00,memo\n"),
                "unexpected text",
            ),
            (
                format!("{header}E1,2025-12-31,1000,1.00,\"never closed\n"),
                "unterminated quoted",
            ),
            (
                "entry,date,account,amount, amount ,memo\n".to_owned(),
                "duplicate CSV header",
            ),
            (
                format!("{header}E1,2025-12-31,1000,1.00\n"),
                "record has 4 columns; header declares 5",
            ),
            (
                format!("{header}E1,2025-12-31,1000,1.00,memo,discarded\n"),
                "record has 6 columns; header declares 5",
            ),
        ] {
            let error = parse_generic_csv(&source, &columns, &units, &accounts)
                .expect_err("malformed records must never silently become a different ledger");
            assert!(
                matches!(error, FormatError::Parse { detail, .. }
                if detail.contains(reason)),
                "{source}"
            );
        }
    }

    #[test]
    fn legacy_csv_requires_declared_generic_metadata_but_keeps_vendor_optional_columns() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let source = "entry,date,account,amount,memo\nE1,2025-12-31,1000,1.00,cash\nE1,2025-12-31,3000,-1.00,capital\n";
        for key in [
            "recorded_at_column",
            "unit_column",
            "description_column",
            "entered_by_column",
            "approved_by_column",
        ] {
            let columns = real_world_csv_columns(&format!("{key} = \"misspelled\"\n"));
            let error = parse_generic_csv(source, &columns, &units, &accounts).unwrap_err();
            assert!(matches!(error, FormatError::Parse { detail, .. }
                if detail.contains("missing declared CSV header column") && detail.contains("misspelled")));
        }
        let qb = "Transaction ID,Date,Account,Debit,Credit\n001,2025-12-31,1000,1.00,\n001,2025-12-31,3000,,1.00\n";
        let batch = parse_quickbooks_csv(qb, &units, &accounts, "USD").unwrap();
        assert_eq!(batch.chunks[0].provenance.source_id, "001");
        assert_eq!(batch.chunks[0].provenance.source_entered_by, None);
        assert_eq!(batch.chunks[0].legs[0].amount.mantissa, 100);

        // A typo cannot change an explicit map by silently taking its last value.
        for repeated in [
            "entry_id_column = \"other\"\n",
            "[account_map]\n\"legacy\" = \"1000\"\n\"legacy\" = \"3000\"\n",
        ] {
            assert!(LegacyColumnMap::parse_toml(&format!(
                "[columns]\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\n{repeated}"
            )).is_err());
        }
    }

    #[test]
    fn legacy_csv_checks_every_supplied_amount_representation() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = real_world_csv_columns(
            "debit_column = \"debit\"\ncredit_column = \"credit\"\nside_column = \"side\"\namount_column = \"magnitude\"\n",
        );
        let source = concat!(
            "entry,date,account,amount,memo,debit,credit,side,magnitude\n",
            "E1,2025-12-31,1000,12.34,cash,12.34,,D,12.34\n",
            "E1,2025-12-31,3000,-12.34,capital,,12.34,C,12.34\n",
        );
        let batch = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(batch.chunks[0].legs[0].amount.mantissa, 1_234);
        for changed in [
            source.replace(",1000,12.34,", ",1000,12.35,"),
            source.replace(",3000,-12.34,", ",3000,12.34,"),
            source.replace(",D,12.34", ",C,12.34"),
            source.replace(",C,12.34", ",C,12.35"),
        ] {
            let error = parse_generic_csv(&changed, &columns, &units, &accounts).unwrap_err();
            assert!(matches!(error, FormatError::Parse { detail, .. }
                if detail.contains("conflicting CSV amount representations")));
        }
        for token in ["1.234", "1e2", "NaN", "Inf"] {
            let changed = source.replace(",1000,12.34,", &format!(",1000,{token},"));
            assert!(
                parse_generic_csv(&changed, &columns, &units, &accounts).is_err(),
                "even a secondary amount must be exact: {token}"
            );
        }

        // Xero legitimately repeats a signed Gross beside debit/credit; that
        // representation stays accepted when every supplied value agrees.
        let xero = "JournalNumber,JournalDate,AccountCode,Debit,Credit,Gross\n0001,2025-12-31,090,12.34,,12.34\n0001,2025-12-31,200,,12.34,-12.34\n";
        assert_eq!(
            parse_xero_csv(xero, &units, &accounts, "USD")
                .unwrap()
                .row_count,
            2
        );
        assert!(
            parse_xero_csv(&xero.replace(",-12.34", ",12.34"), &units, &accounts, "USD").is_err()
        );
    }

    #[test]
    fn legacy_csv_multiline_records_preserve_text_and_source_identity() {
        let units = UnitCatalog::embedded().expect("units");
        let accounts = test_account_map();
        let columns = LegacyColumnMap::parse_toml(
            "[columns]\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\ndescription_column = \"memo\"\nmemo_column = \"memo\"\n",
        ).unwrap();
        let source = "\u{feff}# retained source\r\nentry,date,account,amount,memo\r\n\"# allocation\",2025-12-31,5000,125.50,\"  Café, \"\"North\"\"\r\n# invoice continuation  \"\r\n\"# allocation\",2025-12-31,1000,-125.50,\"settled\nby transfer\"\r\n";
        let imported = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(
            imported.row_count, 2,
            "logical postings, not physical lines"
        );
        assert_eq!(imported.chunks.len(), 1);
        let entry = &imported.chunks[0];
        assert_eq!(entry.provenance.source_id, "# allocation");
        assert_eq!(
            entry.description,
            "  Café, \"North\"\r\n# invoice continuation  "
        );
        assert_eq!(
            entry.legs[0].memo.as_deref(),
            Some(entry.description.as_str())
        );
        assert_eq!(entry.legs[1].memo.as_deref(), Some("settled\nby transfer"));
        assert_eq!(entry.legs[0].amount.mantissa, 12_550);
        assert_eq!(entry.legs[1].side, Side::Credit);
        assert_eq!(entry.legs[1].amount.mantissa, 12_550);
        // The retained bytes remain the source identity even when the text
        // differs only in an embedded line-ending convention.
        let lf =
            parse_generic_csv(&source.replace("\r\n", "\n"), &columns, &units, &accounts).unwrap();
        assert_ne!(imported.source_bytes_digest, lf.source_bytes_digest);
        assert_eq!(imported.trial_balance, lf.trial_balance);
        let whitespace = parse_generic_csv(
            &source.replace("settled\nby transfer", " \t "),
            &columns,
            &units,
            &accounts,
        )
        .unwrap();
        assert_eq!(whitespace.chunks[0].legs[1].memo.as_deref(), Some(" \t "));
    }

    #[test]
    fn legacy_csv_refuses_ambiguous_headers_ragged_records_and_malformed_quotes() {
        let units = UnitCatalog::embedded().expect("units");
        let accounts = test_account_map();
        let columns = LegacyColumnMap::parse_toml(
            "[columns]\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\nmemo_column = \"memo\"\n",
        ).unwrap();
        let source = "entry,date,account,amount,memo\nA,2025-12-31,1000,10.00,cash\nA,2025-12-31,3000,-10.00,capital\n";
        parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        for (bad, expected) in [
            (
                source.replace("amount,memo", "amount,amount"),
                "duplicate CSV header",
            ),
            (source.replace("amount,memo", "amount,"), "empty CSV header"),
            (
                source.replace("amount,memo", "missing,memo"),
                "missing declared CSV header column",
            ),
            (
                source.replace("10.00,cash", "10.00,cash,discarded"),
                "line 2: CSV record has 6 columns; header declares 5",
            ),
            (
                source.replace("10.00,cash", "10.00"),
                "line 2: CSV record has 4 columns; header declares 5",
            ),
            (
                source.replace("cash", "\"cash\"trailing"),
                "unexpected text after",
            ),
            (source.replace("cash", "ca\"sh"), "unexpected quote"),
            (
                source.replace("capital", "\"capital"),
                "unterminated quoted",
            ),
        ] {
            let error = parse_generic_csv(&bad, &columns, &units, &accounts)
                .expect_err("malformed source cannot silently lose columns or text");
            assert!(
                error.to_string().contains(expected),
                "expected {expected}: {error}"
            );
        }
        let multiline = source
            .replace("cash", "\"cash\ncontinued\"")
            .replace("-10.00,capital", "-10.00,capital,extra");
        let error = parse_generic_csv(&multiline, &columns, &units, &accounts).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("line 4: CSV record has 6 columns; header declares 5")
        );
    }

    #[test]
    fn legacy_csv_never_trims_distinct_journal_or_principal_identities() {
        let units = UnitCatalog::embedded().unwrap();
        let accounts = test_account_map();
        let columns = LegacyColumnMap::parse_toml(
            "[columns]\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\nentered_by_column = \"entered\"\napproved_by_column = \"approved\"\n",
        ).unwrap();
        let source = "entry,date,account,amount,entered,approved\nA,2025-12-31,1000,10.00, Alice , Carol \nA,2025-12-31,3000,-10.00,,\n\" A\",2025-12-31,1000,20.00,Bob,Dana\n\" A\",2025-12-31,3000,-20.00,,\n";
        let batch = parse_generic_csv(source, &columns, &units, &accounts).unwrap();
        assert_eq!(batch.chunks.len(), 2, "source IDs cannot silently merge");
        assert_eq!(batch.chunks[0].provenance.source_id, "A");
        assert_eq!(batch.chunks[1].provenance.source_id, " A");
        assert_eq!(batch.chunks[0].legs.len(), 2);
        assert_eq!(batch.chunks[1].legs.len(), 2);
        assert_eq!(
            batch.chunks[0].provenance.source_entered_by.as_deref(),
            Some(" Alice ")
        );
        assert_eq!(
            batch.chunks[0].provenance.source_approved_by.as_deref(),
            Some(" Carol ")
        );
        let conflicting = source.replace("-10.00,,", "-10.00,Alice,");
        let error = parse_generic_csv(&conflicting, &columns, &units, &accounts).unwrap_err();
        assert!(error.to_string().contains("entered-by identity"), "{error}");
        let blank = source.replace("\" A\"", "\"   \"");
        let error = parse_generic_csv(&blank, &columns, &units, &accounts).unwrap_err();
        assert!(error.to_string().contains("empty entry_id"), "{error}");
    }

    #[test]
    fn a_side_column_reads_unsigned_amounts_by_their_indicator() {
        let units = UnitCatalog::embedded().expect("units");
        let accounts = test_account_map();
        let toml = |extra: &str| {
            format!(
                "[columns]\nsource_system = \"csv-gl\"\nentry_id_column = \"entry_id\"\neffective_date_column = \"effective_date\"\naccount_column = \"account_code\"\nside_column = \"side\"\namount_column = \"amount\"\nunit_column = \"currency\"\n{extra}"
            )
        };
        let columns = LegacyColumnMap::parse_toml(&toml("")).expect("columns");
        // The shape of FrankenAccounting's own csv-gl: `#` metadata, then a
        // D/C indicator beside an unsigned amount.
        let source = "# fa_csv_gl_v1|book=x\nentry_id,effective_date,account_code,side,amount,currency\nE1,2025-12-31,1000,D,125.00,USD\nE1,2025-12-31,3000,c,125.00,USD\n";
        let batch =
            parse_generic_csv(source, &columns, &units, &accounts).expect("side and amount");
        let legs: Vec<(&str, Side, i128)> = batch.chunks[0]
            .legs
            .iter()
            .map(|l| (l.account_code.as_str(), l.side, l.amount.mantissa))
            .collect();
        assert_eq!(
            legs,
            [
                ("1000", Side::Debit, 12_500),
                ("3000", Side::Credit, 12_500)
            ]
        );
        // Declared markers, compared ignoring case.
        let dr_cr =
            LegacyColumnMap::parse_toml(&toml("debit_marker = \"Dr\"\ncredit_marker = \"Cr\"\n"))
                .expect("markers");
        let read = parse_generic_csv(
            &source.replace(",D,", ",Dr,").replace(",c,", ",CR,"),
            &dr_cr,
            &units,
            &accounts,
        )
        .expect("declared markers");
        assert_eq!(read.chunks[0].legs[1].side, Side::Credit);
        // Planted negatives: an unknown indicator, and an amount that is not
        // positive (the indicator, not the sign, says which way it moves).
        for (rows, why) in [
            (source.replace(",c,", ",X,"), "neither the debit marker"),
            (
                source
                    .replace("1000,D,125.00", "1000,D,-125.00")
                    .replace("3000,c,125.00", "3000,c,-125.00"),
                "is positive",
            ),
            (source.replace(",D,125.00,", ",D,0.00,"), "is positive"),
        ] {
            let err = parse_generic_csv(&rows, &columns, &units, &accounts)
                .expect_err(why)
                .to_string();
            assert!(err.contains(why), "{why}: {err}");
        }
        for (config, why) in [
            (
                toml("").replace("amount_column = \"amount\"\n", ""),
                "declared together",
            ),
            (
                toml("debit_marker = \"X\"\ncredit_marker = \"x\"\n"),
                "are both",
            ),
        ] {
            let err = LegacyColumnMap::parse_toml(&config)
                .expect_err(why)
                .to_string();
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    #[test]
    fn iif_splits_bind_declared_dates_and_preserve_optional_timestamps() {
        let units = UnitCatalog::embedded().expect("units");
        let accounts = test_account_map();
        let source = "\
!TRNS\tTRNSID\tDATE\tACCNT\tAMOUNT\tMEMO\tTIMESTAMP
!SPL\tSPLID\tDATE\tACCNT\tAMOUNT\tMEMO\tTIMESTAMP
TRNS\tENTRY-1\t2025-12-31\t1000\t125.00\tCash\t
SPL\tSPL-1\t2025-12-31\t3000\t-100.00\tCapital\t2025-12-31T10:00:00Z
SPL\tSPL-2\t\t4000\t-25.00\tRevenue\t
ENDTRNS
";
        let batch =
            parse_quickbooks_iif(source, &units, &accounts, "USD").expect("sparse metadata");
        assert_eq!(batch.chunks.len(), 1);
        assert_eq!(batch.chunks[0].legs.len(), 3);
        assert_eq!(
            batch.chunks[0].provenance.source_recorded_at_ns,
            Some(1_767_175_200_000_000_000)
        );

        for (changed, field) in [
            (
                source.replace("SPL-2\t\t4000", "SPL-2\t2026-01-01\t4000"),
                "effective date",
            ),
            (
                source.replace("Revenue\t\n", "Revenue\t2025-12-31T11:00:00Z\n"),
                "recorded timestamp",
            ),
        ] {
            let error = parse_quickbooks_iif(&changed, &units, &accounts, "USD")
                .expect_err("conflicting split metadata");
            assert!(matches!(
                error,
                FormatError::Parse { detail, .. }
                    if detail.contains("line 5") && detail.contains(field)
            ));
        }

        // A declared SPL header without metadata must not borrow TRNS offsets
        // that happen to point at a different SPL account, amount or memo.
        let distinct_headers = "\
!TRNS\tTRNSID\tDATE\tACCNT\tAMOUNT\tMEMO\tTIMESTAMP
!SPL\tSPLID\tACCNT\tAMOUNT\tMEMO
TRNS\tENTRY-2\t2025-12-31\t1000\t125.00\tCash\t2025-12-31T10:00:00Z
SPL\tSPL-3\t3000\t-125.00\tCapital
ENDTRNS
";
        let compact = parse_quickbooks_iif(distinct_headers, &units, &accounts, "USD")
            .expect("SPL columns have their own declared shape");
        assert_eq!(compact.chunks[0].legs.len(), 2);
        assert_eq!(
            compact.chunks[0].provenance.source_recorded_at_ns,
            batch.chunks[0].provenance.source_recorded_at_ns
        );
    }

    #[test]
    fn beancount_ledger_maps_full_account_names_and_the_elided_remainder() {
        let units = UnitCatalog::embedded().expect("units");
        let mut map = AccountMap::new(["1000", "3000", "4000", "5000"]);
        map.insert("Assets:Bank:Checking", "1000");
        map.insert("Equity:Opening-Balances", "3000");
        map.insert("Income:Sales", "4000");
        map.insert("Expenses:Auto:Fuel", "5000");
        let ledger = "\
option \"operating_currency\" \"USD\"
* Accounts
2025-01-01 open Assets:Bank:Checking USD
  name: \"Operating account\"
2025-01-01 open Equity:Opening-Balances
2025-01-01 commodity USD
pushtag #migration
2025-12-01 * \"Opening\" \"Capital; contributed\" #seed ^capital-1
  source: \"minutes\"
  Assets:Bank:Checking      1,000.00 USD ; deposit slip
    slip: \"A-17\"
  Equity:Opening-Balances
poptag #migration
2025-12-15 txn \"Fuel and a sale\"
  ! Expenses:Auto:Fuel         40.25 USD
  Assets:Bank:Checking        -40.25 USD
  Income:Sales                 0.00 USD
2025-12-20 balance Assets:Bank:Checking 959.75 USD
2025-12-28 price USD 1.00 USD
";
        let batch = parse_beancount_ledger(ledger, &units, &map).expect("valid ledger");
        assert_eq!(batch.source_system, "beancount");
        assert_eq!(batch.row_count, 5);
        assert_eq!(batch.chunks.len(), 2);
        let opening = &batch.chunks[0];
        assert_eq!(opening.provenance.source_id, "L8");
        assert_eq!(opening.description, "Opening: Capital; contributed");
        let legs: Vec<(&str, Side, i128)> = opening
            .legs
            .iter()
            .map(|l| (l.account_code.as_str(), l.side, l.amount.mantissa))
            .collect();
        assert_eq!(
            legs,
            [
                ("1000", Side::Debit, 100_000),
                ("3000", Side::Credit, 100_000)
            ]
        );
        // The zero posting moved nothing and is dropped; the flag is not an
        // account.
        let fuel = &batch.chunks[1];
        assert_eq!(fuel.provenance.source_id, "L14");
        assert_eq!(fuel.description, "Fuel and a sale");
        assert_eq!(fuel.legs.len(), 2);
        assert_eq!(fuel.legs[0].account_code, "5000");
        let cash = batch
            .trial_balance
            .iter()
            .find(|l| l.account_code == "1000")
            .expect("cash line");
        assert_eq!(cash.mantissa, 95_975);
        // A line led by whitespace other than a space or a tab is read
        // from its first word.
        let led = format!("\u{a0}2025-01-02 open Income:Sales\n{ledger}");
        let read = parse_beancount_ledger(&led, &units, &map).expect("led line");
        assert_eq!(read.chunks.len(), 2);

        // Planted negatives: each names its line and what to do instead.
        for (planted, expected) in [
            (
                ledger.replace("1,000.00 USD", "10 AAPL {100.00 USD}"),
                "at cost or price",
            ),
            (
                ledger.replace("-40.25 USD", "-40.25 USD @ 1.00 USD"),
                "at cost or price",
            ),
            (
                ledger.replace("2025-12-28 price", "2025-12-28 pad Assets:Bank:Checking Equity:Opening-Balances\n2025-12-29 price"),
                "pad asks Beancount",
            ),
            (format!("include \"other.beancount\"\n{ledger}"), "include names another file"),
            (format!("plugin \"beancount.plugins.auto\"\n{ledger}"), "a plugin may rewrite"),
            (
                ledger.replace(
                    "  Assets:Bank:Checking        -40.25 USD\n  Income:Sales                 0.00 USD",
                    "  Assets:Bank:Checking\n  Income:Sales",
                ),
                "a second posting without an amount",
            ),
            (ledger.replace("40.25 USD\n  Assets", "(40 + 0.25) USD\n  Assets"), "not `account amount unit`"),
            (ledger.replace("-40.25 USD", "-40*1 USD"), "arithmetic amount"),
            (ledger.replace("2025-12-20 balance", "2025-12-20 frobnicate"), "unsupported directive"),
            (ledger.replace("\"Fuel and a sale\"", "\"Fuel and a sale"), "unterminated string"),
            (ledger.replace("-40.25 USD", "-40.20 USD"), "unbalanced"),
        ] {
            let err = parse_beancount_ledger(&planted, &units, &map)
                .expect_err(expected)
                .to_string();
            assert!(err.to_lowercase().contains(&expected.to_lowercase()), "{expected}: {err}");
        }
        let unmapped = ledger.replace("Expenses:Auto:Fuel", "Expenses:Auto:Tolls");
        assert!(matches!(
            parse_beancount_ledger(&unmapped, &units, &map),
            Err(FormatError::UnmappedAccount { legacy_account, .. }) if legacy_account == "Expenses:Auto:Tolls"
        ));
        let unknown = ledger.replace("40.25 USD\n  Assets", "40.25 ZZZ\n  Assets");
        assert!(matches!(
            parse_beancount_ledger(&unknown, &units, &map),
            Err(FormatError::UnknownUnit { unit, .. }) if unit == "ZZZ"
        ));
    }

    #[test]
    fn hledger_journal_maps_account_names_amount_styles_and_the_elided_remainder() {
        let units = UnitCatalog::embedded().expect("units");
        let mut map = AccountMap::new(["1000", "3000", "4000", "5000"]);
        map.insert("assets:bank:checking", "1000");
        map.insert("equity:opening balances", "3000");
        map.insert("income:sales", "4000");
        map.insert("expenses:auto:fuel", "5000");
        let journal = "\
; A journal as hledger print writes it.
account assets:bank:checking
commodity USD 1,000.00
P 2025-12-01 EUR 1.10 USD

2025-12-01 * (A-17) Opening | capital contributed  ; deposit slip
    assets:bank:checking      USD 1,000.00  ; slip: A-17
    equity:opening balances

2025/12/15=2025/12/16 ! Fuel and a sale
    ! expenses:auto:fuel          40.25 USD
    assets:bank:checking        -40.25 USD = USD 959.75
    income:sales                 0.00 USD

comment
2025-12-20 not a transaction
end comment

~ monthly from 2026-01
    expenses:auto:fuel   USD 50.00
    assets:bank:checking
";
        let batch = parse_hledger_journal(journal, &units, &map).expect("valid journal");
        assert_eq!(batch.source_system, "hledger");
        assert_eq!(batch.row_count, 5, "the forecast's postings are not rows");
        assert_eq!(batch.chunks.len(), 2);
        let opening = &batch.chunks[0];
        assert_eq!(opening.provenance.source_id, "L6");
        assert_eq!(opening.description, "Opening | capital contributed");
        let legs: Vec<(&str, Side, i128)> = opening
            .legs
            .iter()
            .map(|l| (l.account_code.as_str(), l.side, l.amount.mantissa))
            .collect();
        assert_eq!(
            legs,
            [
                ("1000", Side::Debit, 100_000),
                ("3000", Side::Credit, 100_000)
            ]
        );
        // The secondary date is dropped, the zero posting moves nothing,
        // the status marks are not accounts and the assertion is stripped.
        let fuel = &batch.chunks[1];
        assert_eq!(fuel.provenance.source_id, "L10");
        assert_eq!(fuel.effective_date, DateDay::parse("2025-12-15").unwrap());
        assert_eq!(fuel.description, "Fuel and a sale");
        let legs: Vec<(&str, Side, i128)> = fuel
            .legs
            .iter()
            .map(|l| (l.account_code.as_str(), l.side, l.amount.mantissa))
            .collect();
        assert_eq!(
            legs,
            [("5000", Side::Debit, 4_025), ("1000", Side::Credit, 4_025)]
        );
        let cash = batch
            .trial_balance
            .iter()
            .find(|l| l.account_code == "1000")
            .expect("cash line");
        assert_eq!(cash.mantissa, 95_975);
        // hledger's single-digit month and day.
        let short =
            "2025/12/5 Opening\n    assets:bank:checking  USD 10.00\n    equity:opening balances\n";
        let read = parse_hledger_journal(short, &units, &map).expect("a short date");
        assert_eq!(
            read.chunks[0].effective_date,
            DateDay::parse("2025-12-05").unwrap()
        );
        // A comma decimal mark, after its directive.
        let european = "decimal-mark ,\n2025-12-01 Opening\n    assets:bank:checking  EUR 1.000,50\n    equity:opening balances\n";
        let read = parse_hledger_journal(european, &units, &map).expect("comma decimals");
        assert_eq!(read.chunks[0].legs[0].amount.mantissa, 100_050);
        assert_eq!(read.chunks[0].legs[0].unit_code, "EUR");

        // Planted negatives: each names its line and what to do instead.
        for (planted, expected) in [
            (
                journal.replace("-40.25 USD = USD 959.75", "-40.25 USD @ 1.00 USD"),
                "cost or price",
            ),
            (
                journal.replace("    income:sales ", "    (income:sales) "),
                "virtual posting",
            ),
            (format!("include other.journal\n{journal}"), "include names another file"),
            (format!("alias checking = assets:bank:checking\n{journal}"), "rewrites account names"),
            (format!("apply account business\n{journal}"), "rewrites account names"),
            (format!("= expenses:auto\n    (budget)  1\n{journal}"), "auto posting rule"),
            (format!("Y 2025\n{journal}"), "year directive"),
            (journal.replace("2025/12/15=2025/12/16", "12/15"), "neither a dated transaction"),
            (format!("decimal-mark ;\n{journal}"), "neither . nor ,"),
            (format!("decimal-mark x\n{journal}"), "neither . nor ,"),
            (
                journal.replace(
                    "    assets:bank:checking        -40.25 USD = USD 959.75\n    income:sales                 0.00 USD",
                    "    assets:bank:checking\n    income:sales",
                ),
                "a second posting without an amount",
            ),
            (journal.replace("40.25 USD\n", "40.25\n"), "names no commodity"),
            (journal.replace("-40.25 USD", "-40.20 USD"), "unbalanced"),
            // A mark that does not read as the journal's decimal mark is
            // refused, never guessed: `1,5` is 1.5 to a comma journal and 15
            // to a period one, and `1.000,5` at BTC's scale would read as
            // 1.0005 instead of 1000.5.
            (
                journal.replace("USD 1,000.00  ;", "USD 1,5  ;"),
                "digit groups and decimal mark",
            ),
            (
                format!(
                    "{journal}\n2025-12-31 Coins\n    assets:bank:checking  BTC 1.000,5\n    equity:opening balances\n"
                ),
                "digit groups and decimal mark",
            ),
            (
                "decimal-mark ,\n2025-12-31 Coins\n    assets:bank:checking  1,234.5 BTC\n    equity:opening balances\n"
                    .to_string(),
                "digit groups and decimal mark",
            ),
            // A posting date of its own, on the posting or below it.
            (
                journal.replace("; slip: A-17", "; slip: A-17, date:2025-12-20"),
                "`date:` tag",
            ),
            (
                journal.replace(
                    "    equity:opening balances\n",
                    "    equity:opening balances\n    ; date:2025-12-02\n",
                ),
                "`date:` tag",
            ),
        ] {
            let err = parse_hledger_journal(&planted, &units, &map)
                .expect_err(expected)
                .to_string();
            assert!(err.to_lowercase().contains(&expected.to_lowercase()), "{expected}: {err}");
        }
        let dollar = journal.replace("USD 1,000.00  ;", "$1,000.00  ;");
        assert!(matches!(
            parse_hledger_journal(&dollar, &units, &map),
            Err(FormatError::UnknownUnit { unit, .. }) if unit == "$"
        ));
        let unmapped = journal.replace(
            "expenses:auto:fuel          40.25",
            "expenses:auto:tolls          40.25",
        );
        assert!(matches!(
            parse_hledger_journal(&unmapped, &units, &map),
            Err(FormatError::UnmappedAccount { legacy_account, .. }) if legacy_account == "expenses:auto:tolls"
        ));
    }

    #[test]
    fn all_five_legacy_formats_import_finalize_and_tie_out_in_migration_run() {
        let units = UnitCatalog::embedded().expect("units");
        let map = test_account_map();

        let qb_iif = "\
!TRNS\tTRNSID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tDOCNUM\tMEMO\tTIMESTAMP
!SPL\tSPLID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tDOCNUM\tMEMO
!ENDTRNS
TRNS\tIIF-1\tGENERAL JOURNAL\t2025-12-20\t1000 · Checking\t1500.00\t1\tOpening cash\t2025-12-20T10:00:00Z
SPL\tIIF-1-S\tGENERAL JOURNAL\t2025-12-20\t3000 · Opening Balance Equity\t-1500.00\t1\tOpening equity
ENDTRNS
";
        let qb_csv = "\
Transaction ID,Date,Transaction Type,Num,Account,Debit,Credit,Currency,Memo/Description,Created At,Created By
QBC-201,2025-12-21,Journal Entry,201,1000 · Checking,3200.50,,USD,Client retainer,2025-12-21T14:30:00Z,alice@legacy
QBC-201,2025-12-21,Journal Entry,201,4000 · Sales Revenue,,3200.50,USD,Client retainer,2025-12-21T14:30:00Z,alice@legacy
";
        let xero_csv = "\
JournalNumber,JournalDate,CreatedDateUTC,AccountCode,AccountName,Description,Debit,Credit,Gross,Reference,Currency,CreatedBy
XERO-301,2025-12-22,2025-12-22T09:15:00Z,090,Business Bank,Cloud invoice,850.00,,850.00,INV-99,USD,bob@xero
XERO-301,2025-12-22,2025-12-22T09:15:00Z,200,Sales,Cloud invoice,,850.00,-850.00,INV-99,USD,bob@xero
";
        let netsuite_csv = "\
Internal ID,Date,System Date,Type,Document Number,Account,Debit,Credit,Currency,Memo,Created By,Approved By
NS-401,2025-12-23,2025-12-23T18:00:00Z,Journal,JE-401,5000 · Hosting Expense,425.00,,USD,Server rack,carol@ns,dave@ns
NS-401,2025-12-23,2025-12-23T18:00:00Z,Journal,JE-401,2000 · Accounts Payable,,425.00,USD,Server rack,carol@ns,dave@ns
";
        let generic_col_map_toml = "\
[columns]
source_system = \"sap-r3-csv\"
default_unit = \"USD\"
entry_id_column = \"BELNR\"
effective_date_column = \"BUDAT\"
recorded_at_column = \"CPUDT\"
account_column = \"HKONT\"
signed_amount_column = \"DMBTR\"
description_column = \"SGTXT\"
entered_by_column = \"USNAM\"

[account_map]
\"0000110000\" = \"1200\"
\"0000800000\" = \"4000\"
";
        let generic_csv = "\
BELNR,BUDAT,CPUDT,HKONT,DMBTR,SGTXT,USNAM
SAP-501,2025-12-28,2025-12-28T20:00:00Z,0000110000,1900.25,Year-end AR billing,FI_USER
SAP-501,2025-12-28,2025-12-28T20:00:00Z,0000800000,-1900.25,Year-end AR billing,FI_USER
";
        let generic_col_map =
            LegacyColumnMap::parse_toml(generic_col_map_toml).expect("valid column map");

        let batches = vec![
            parse_quickbooks_iif(qb_iif, &units, &map, "USD").expect("qb_iif"),
            parse_quickbooks_csv(qb_csv, &units, &map, "USD").expect("qb_csv"),
            parse_xero_csv(xero_csv, &units, &map, "USD").expect("xero_csv"),
            parse_netsuite_csv(netsuite_csv, &units, &map, "USD").expect("netsuite_csv"),
            parse_generic_csv(generic_csv, &generic_col_map, &units, &map).expect("generic_csv"),
        ];

        let runtime = RuntimeBuilder::new().build().expect("runtime");
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = MemVfs::new().expect("memory filesystem");
        let dir = vfs.database_dir();
        let keys = DatabaseKeys::new(
            [0x6a; 32],
            DatabaseSecurityNamespaceId([0x6b; 32]),
            [0x6c; 32],
        );
        let mut db = runtime
            .block_on(async {
                Database::create_with_vfs(&ctx.commit(), vfs.clone(), dir, keys).await
            })
            .expect("open");

        let unit_reg = UnitRegistry::with_defaults();
        let usd = unit_reg.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let opening_date = DateDay::from_ymd(2026, 1, 1).expect("2026-01-01");
        let book_id = Id128([0x44; 16]);
        let spec = BookSpec {
            book_id,
            name: "Legacy Cutover Co".into(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(async { create_book(&mut db, &ctx, &spec, &unit_reg, &symbols).await })
            .expect("create_book");
        let book = BookContext {
            book_id,
            calendar: calendar.clone(),
            units: unit_reg,
            seal_key: SealKey([0x55; 32]),
            symbols,
        };

        let chart: Vec<AccountSpec> = [
            ("1000", 1u8, 0u8),
            ("1200", 1, 0),
            ("2000", 2, 1),
            ("3000", 3, 1),
            ("4000", 4, 1),
            ("5000", 5, 0),
        ]
        .into_iter()
        .map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        })
        .collect();
        let chart_desc =
            Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]);
        runtime
            .block_on(async {
                install_chart(
                    &mut db,
                    &ctx,
                    &book,
                    &chart,
                    PRINCIPAL,
                    opening_date,
                    b"chart",
                    chart_desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("chart")
            .expect("admitted");
        runtime
            .block_on(async {
                create_periods(
                    &mut db,
                    &ctx,
                    &book,
                    2026,
                    fgdb_types::VId(1),
                    fa_model::Erasable::seal(
                        &"periods".to_string(),
                        None,
                        &book.seal_key,
                        [1; 32],
                        [2; 24],
                    ),
                    &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"])
                        .unwrap(),
                )
                .await
            })
            .expect("periods")
            .expect("admitted");

        // Lock FY2026-OPEN so Migration entries are admissible there.
        for (i, t) in [
            PeriodTransition::Open,
            PeriodTransition::SoftClose,
            PeriodTransition::Close,
            PeriodTransition::Lock,
        ]
        .into_iter()
        .enumerate()
        {
            let key = format!("lock-open-{i}");
            let desc = Erasable::seal(
                &"period".to_string(),
                None,
                &book.seal_key,
                [1; 32],
                [2; 24],
            );
            let approvals = if matches!(t, PeriodTransition::Lock) {
                let digest = fa_journal::transition_proposal(
                    &book,
                    &fa_journal::policy::calendar_period(&book, "FY2026-OPEN")
                        .expect("calendar period"),
                    fa_time::PeriodState::Closed,
                    fa_time::PeriodState::Locked,
                    PRINCIPAL,
                    1,
                    key.as_bytes(),
                    desc.clone(),
                )
                .proposal_digest()
                .expect("digest");
                let app = runtime
                    .block_on(async {
                        record_approval(
                            &mut db,
                            &ctx,
                            &book,
                            ApprovalRequest {
                                capability: Capability::embedded(APPROVER_A, &["approve"])
                                    .expect("approve"),
                                approved_proposal_digest: digest,
                                role: 0,
                            },
                        )
                        .await
                    })
                    .expect("kernel")
                    .expect("approved");
                vec![app.approval()]
            } else {
                Vec::new()
            };
            runtime
                .block_on(async {
                    transition_period(
                        &mut db,
                        &ctx,
                        &book,
                        "FY2026-OPEN",
                        t,
                        PRINCIPAL,
                        1,
                        key.as_bytes(),
                        desc,
                        &Capability::embedded(PRINCIPAL, &["close"]).expect("close"),
                        &approvals,
                    )
                    .await
                })
                .expect("kernel")
                .expect("transitioned");
        }

        // Deterministic fixture entropy, unique across every field and batch
        // in this test book. Production supplies Book::seal_text instead.
        let mut sealing_counter = 0_u64;
        for batch in &batches {
            let doc_bytes = format!(
                "legacy-tb:{}:{}:{}",
                batch.format.registry_name(),
                batch.row_count,
                crate::hex_encode(&batch.attestation_digest)
            )
            .into_bytes();
            let tb_doc = Document {
                book_id,
                kind: 18,
                mime: "text/csv".into(),
                grade: 3,
                retrieved_by: PRINCIPAL,
                bytes: doc_bytes,
            };
            runtime
                .block_on(async { add_document(&mut db, &ctx, &book, &tb_doc).await })
                .expect("kernel")
                .expect("admitted");
            let tb_evidence = tb_doc.evidence_ref(1);

            let run_key = format!("run-{}", batch.format.registry_name());
            let run_body = batch.to_run_body(
                book.book_id,
                &run_key,
                opening_date,
                tb_evidence.document_oid,
            );
            let open_desc = Erasable::seal(
                &"open legacy migration".to_string(),
                None,
                &book.seal_key,
                [0x11; 32],
                [0x22; 24],
            );
            let open_prop = open_proposal(
                &book,
                PRINCIPAL,
                &run_body,
                vec![tb_evidence],
                format!("open-{run_key}").as_bytes(),
                open_desc,
            )
            .expect("open proposal");
            let opened = runtime
                .block_on(async {
                    open_run(
                        &mut db,
                        &ctx,
                        &book,
                        &run_body,
                        RunControlRequest {
                            proposal: open_prop,
                            capability: Capability::embedded(PRINCIPAL, &["post", "migrate"])
                                .expect("cap"),
                            approvals: Vec::new(),
                        },
                    )
                    .await
                })
                .expect("open_run")
                .expect("run opened");

            let refused = batch.to_chunk_proposals(
                &book,
                opened.run,
                opening_date,
                Some("FY2026-OPEN"),
                PRINCIPAL,
                Oid(batch.source_bytes_digest),
                vec![tb_evidence],
            );
            assert!(
                refused
                    .expect_err("the entropy-free bridge must fail closed")
                    .to_string()
                    .contains("to_chunk_proposals_with_sealer")
            );
            let chunk_proposals = batch
                .to_chunk_proposals_with_sealer(
                    &book,
                    opened.run,
                    opening_date,
                    Some("FY2026-OPEN"),
                    PRINCIPAL,
                    Oid(batch.source_bytes_digest),
                    vec![tb_evidence],
                    |text| {
                        sealing_counter = sealing_counter.checked_add(1).expect("fixture fields");
                        let mut salt = [0x91; 32];
                        salt[..8].copy_from_slice(&sealing_counter.to_le_bytes());
                        let mut nonce = [0x92; 24];
                        nonce[..8].copy_from_slice(&sealing_counter.to_le_bytes());
                        Ok::<_, FormatError>(Erasable::seal(
                            &text.to_string(),
                            None,
                            &book.seal_key,
                            salt,
                            nonce,
                        ))
                    },
                )
                .expect("chunk proposals");

            for (index, (proposal, legacy)) in chunk_proposals.iter().zip(&batch.chunks).enumerate()
            {
                assert_eq!(
                    proposal.idempotency_key,
                    format!("legacy-opening:v1:{index}").as_bytes()
                );
                assert_eq!(proposal.document_date, Some(legacy.effective_date));
                for (posted_leg, source_leg) in proposal.legs.iter().zip(&legacy.legs) {
                    assert_eq!(
                        posted_leg.memo.as_ref().map(|memo| memo
                            .open(&book.seal_key, fa_model::limits::MAX_MEMO_BYTES)
                            .unwrap()),
                        source_leg.memo,
                        "migration preserves the source leg's memo"
                    );
                }
            }

            for prop in chunk_proposals {
                let chunk_digest = prop.proposal_digest().expect("chunk digest");
                let mut chunk_approvals = Vec::new();
                for who in [APPROVER_A, APPROVER_B] {
                    let app = runtime
                        .block_on(async {
                            record_approval(
                                &mut db,
                                &ctx,
                                &book,
                                ApprovalRequest {
                                    capability: Capability::embedded(who, &["approve"])
                                        .expect("approve"),
                                    approved_proposal_digest: chunk_digest,
                                    role: 0,
                                },
                            )
                            .await
                        })
                        .expect("approval")
                        .expect("recorded");
                    chunk_approvals.push(app.approval());
                }
                let posted = runtime
                    .block_on(async {
                        post(
                            &mut db,
                            &ctx,
                            &book,
                            PostRequest {
                                proposal: prop,
                                approvals: chunk_approvals,
                                capability: Capability::embedded(PRINCIPAL, &["post", "migrate"])
                                    .expect("cap"),
                                plan_certificate: None,
                            },
                        )
                        .await
                    })
                    .expect("post chunk")
                    .expect("chunk committed");
                assert!(matches!(posted, fa_journal::Posted::Committed { .. }));
            }

            let fin_desc = Erasable::seal(
                &"finalize legacy migration".to_string(),
                None,
                &book.seal_key,
                [0x33; 32],
                [0x44; 24],
            );
            let finalize_prop = plan_run_transition(
                &db,
                &book,
                opened.run,
                fa_journal::migration::kind::FINALIZE,
                PRINCIPAL,
                format!("fin-{run_key}").as_bytes(),
                fin_desc,
            )
            .expect("plan finalize")
            .expect("tie-out succeeded");

            let fin_digest = finalize_prop.proposal_digest().expect("digest");
            let mut approvals = Vec::new();
            for who in [APPROVER_A, APPROVER_B] {
                let app = runtime
                    .block_on(async {
                        record_approval(
                            &mut db,
                            &ctx,
                            &book,
                            ApprovalRequest {
                                capability: Capability::embedded(who, &["approve"])
                                    .expect("approve"),
                                approved_proposal_digest: fin_digest,
                                role: 0,
                            },
                        )
                        .await
                    })
                    .expect("approval")
                    .expect("recorded");
                approvals.push(app.approval());
            }

            let finalized = runtime
                .block_on(async {
                    transition_run(
                        &mut db,
                        &ctx,
                        &book,
                        RunControlRequest {
                            proposal: finalize_prop,
                            capability: Capability::embedded(PRINCIPAL, &["post", "migrate"])
                                .expect("cap"),
                            approvals,
                        },
                    )
                    .await
                })
                .expect("transition_run")
                .expect("finalized");
            assert_eq!(finalized.to, fa_journal::RunState::Finalized);
            println!(
                "legacy format={} rows={} chunks={} tie_out_attestation={}",
                batch.format.registry_name(),
                batch.row_count,
                batch.chunks.len(),
                crate::hex_encode(&batch.attestation_digest)
            );
        }

        // Verify post-finalization fold of FY2026-OPEN equals the sum of all 5 finalized legacy batches!
        let frontier = db.frontier().expect("frontier");
        let fold =
            fold_period_at(&db, &book, "FY2026-OPEN", Some(frontier)).expect("fold FY2026-OPEN");
        let mut expected_by_acct: BTreeMap<String, i128> = BTreeMap::new();
        for b in &batches {
            for l in &b.trial_balance {
                *expected_by_acct.entry(l.account_code.clone()).or_insert(0) += l.mantissa;
            }
        }
        for (acct, exp) in expected_by_acct {
            let vid = account_vid(book.book_id, &acct);
            let obs = fold
                .cells
                .iter()
                .find(|c| c.key.account == vid && c.key.unit_id == usd.0)
                .and_then(fa_registers::Cell::net)
                .unwrap_or(0);
            assert_eq!(obs, exp, "account {acct} post-migration fold mismatch");
        }
    }
}
