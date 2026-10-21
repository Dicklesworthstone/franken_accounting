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
    PeriodRef, account_vid,
};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::VId;

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
    pub unit_column: Option<String>,
    pub description_column: Option<String>,
    pub memo_column: Option<String>,
    pub entered_by_column: Option<String>,
    pub approved_by_column: Option<String>,
    pub account_mappings: BTreeMap<String, String>,
}

impl LegacyColumnMap {
    /// Parse a declared column-map configuration file (TOML subset with `[columns]` and `[account_map]`).
    pub fn parse_toml(src: &str) -> Result<Self, FormatError> {
        const FMT: &str = "legacy_column_map.toml";
        let mut section = "";
        let mut cols: BTreeMap<String, String> = BTreeMap::new();
        let mut account_mappings: BTreeMap<String, String> = BTreeMap::new();

        for (line_idx, raw_line) in src.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = &line[1..line.len() - 1];
                if !matches!(section, "columns" | "account_map") {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!(
                            "line {}: unknown section [{section}] (expected [columns] or [account_map])",
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
                    cols.insert(k, v);
                }
                "account_map" => {
                    account_mappings.insert(k, v);
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
        if (debit_column.is_none() || credit_column.is_none()) && signed_amount_column.is_none() {
            return Err(FormatError::Parse {
                format: FMT,
                detail: "must declare either (`debit_column` and `credit_column`) or `signed_amount_column` in [columns]".to_owned(),
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
            unit_column: opt("unit_column"),
            description_column: opt("description_column"),
            memo_column: opt("memo_column"),
            entered_by_column: opt("entered_by_column"),
            approved_by_column: opt("approved_by_column"),
            account_mappings,
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

fn parse_csv_fields(line: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if in_quotes && chars.peek() == Some(&'"') {
                current.push('"');
                let _ = chars.next();
            } else {
                in_quotes = !in_quotes;
            }
        } else if c == sep && !in_quotes {
            out.push(current.trim().to_owned());
            current.clear();
        } else {
            current.push(c);
        }
    }
    out.push(current.trim().to_owned());
    out
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
            let mut legs = Vec::with_capacity(chunk.legs.len());
            for leg in &chunk.legs {
                let mut payload = LegPayload::simple(
                    leg.side,
                    account_vid(book.book_id, &leg.account_code),
                    leg.amount,
                );
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
                schema_minor: fa_model::entry::SCHEMA_MINOR,
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
                        account_code: acct,
                        side,
                        amount: Amount::new(uid, mantissa),
                        unit_code: default_unit_code.to_owned(),
                        unit_scale: scale,
                        memo: (!memo.is_empty()).then(|| memo.to_owned()),
                    }],
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
        unit_column: Some("Currency".to_owned()),
        description_column: Some("Memo/Description".to_owned()),
        memo_column: Some("Memo/Description".to_owned()),
        entered_by_column: Some("Created By".to_owned()),
        approved_by_column: None,
        account_mappings: BTreeMap::new(),
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
        unit_column: Some("Currency".to_owned()),
        description_column: Some("Description".to_owned()),
        memo_column: Some("Reference".to_owned()),
        entered_by_column: Some("CreatedBy".to_owned()),
        approved_by_column: None,
        account_mappings: BTreeMap::new(),
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
        unit_column: Some("Currency".to_owned()),
        description_column: Some("Memo".to_owned()),
        memo_column: Some("Document Number".to_owned()),
        entered_by_column: Some("Created By".to_owned()),
        approved_by_column: Some("Approved By".to_owned()),
        account_mappings: BTreeMap::new(),
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
    let mut header_idx: Option<BTreeMap<String, usize>> = None;
    let mut entry_order: Vec<String> = Vec::new();
    let mut entries_by_id: BTreeMap<String, LegacyChunkEntry> = BTreeMap::new();
    let mut row_count = 0usize;

    for (line_idx, raw_line) in src.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = parse_csv_fields(line, ',');
        if header_idx.is_none() {
            let mut map = BTreeMap::new();
            for (i, h) in fields.iter().enumerate() {
                map.insert(h.trim().to_owned(), i);
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
            header_idx = Some(map);
            continue;
        }

        let headers = header_idx.as_ref().unwrap();
        let get = |col: &str| -> &str {
            headers
                .get(col)
                .and_then(|&i| fields.get(i))
                .map(|s| s.trim())
                .unwrap_or("")
        };
        let get_opt = |col: &Option<String>| -> &str { col.as_deref().map(get).unwrap_or("") };

        row_count += 1;
        let entry_id = get(&column_map.entry_id_column);
        if entry_id.is_empty() {
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
                (Side::Credit, -signed)
            }
        } else {
            return Err(FormatError::Parse {
                format: fmt_name,
                detail: format!(
                    "line {}: missing debit/credit or signed amount",
                    line_idx + 1
                ),
            });
        };

        let desc = get_opt(&column_map.description_column);
        let memo = get_opt(&column_map.memo_column);
        let ts_ns = parse_legacy_timestamp_ns(fmt_name, get_opt(&column_map.recorded_at_column))?;
        let entered_by = {
            let v = get_opt(&column_map.entered_by_column);
            (!v.is_empty()).then(|| v.to_owned())
        };
        let approved_by = {
            let v = get_opt(&column_map.approved_by_column);
            (!v.is_empty()).then(|| v.to_owned())
        };

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
                    description: if desc.is_empty() {
                        entry_id.to_owned()
                    } else {
                        desc.to_owned()
                    },
                    legs: Vec::new(),
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
        chunk.legs.push(FormatLeg {
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
        .filter_map(|id| entries_by_id.remove(&id))
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
            chunks.push(finish_beancount_txn(txn)?);
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
        chunks.push(finish_beancount_txn(txn)?);
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
/// unit's remainder, negated.
fn finish_beancount_txn(txn: BeancountTxn) -> Result<LegacyChunkEntry, FormatError> {
    let overflow = || FormatError::Overflow {
        format: "beancount_v3",
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
            source_system: LegacyFormat::Beancount.default_source_system().to_owned(),
            source_id: format!("L{}", txn.line),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
        },
        effective_date: txn.date,
        description: txn.description,
        legs,
    })
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
