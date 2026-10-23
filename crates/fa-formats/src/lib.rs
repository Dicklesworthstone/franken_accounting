//! `fa-formats` — Interop formats, audit data standards, and external oracle
//! bridges (plan §8.6, §9.5, §12.1, §15.3, §15.9, §16.3, §18.1; bead `fa-npi`).
//!
//! Constitutional guarantees:
//! - `#![forbid(unsafe_code)]`
//! - Exact fixed-scale integer arithmetic (`fa_money::Amount`) on every reader
//!   and writer path. Floating-point syntax (`e`/`E`, `NaN`, `Inf`) and
//!   fractional precision exceeding a unit's registered scale are refused.
//! - Every audit-standard export (`aicpa_ads_gl_v2`, `oecd_saft_v2`, `csv_gl_v1`)
//!   carries a deterministic `ExportCoordinate` certificate and satisfies
//!   export→import round-trip identity (`verify_round_trip_identity`) and
//!   `FA-INV-04` refold balance equality.

#![forbid(unsafe_code)]

pub mod ads;
pub mod bank;
pub mod beancount;
pub mod conformance;
pub mod csv_gl;
pub mod fwc;
pub mod legacy;
pub mod load_file;
pub mod part370;
pub mod saft;
pub mod tigerbeetle;
pub mod xbrl;

use core::fmt;
use std::collections::BTreeMap;

use fa_model::{AccountType, EntryClass};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_crypto::Hasher;

/// Errors produced by `fa-formats` readers, writers, and conformance verifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// Syntax or structural parse error at a format boundary.
    Parse {
        format: &'static str,
        detail: String,
    },
    /// Floating-point or scientific notation encountered where exact fixed-scale decimal is required.
    FloatForbidden { format: &'static str, token: String },
    /// Decimal literal cannot be represented exactly at the unit's registered scale.
    ExactDecimal {
        format: &'static str,
        token: String,
        scale: u8,
        reason: String,
    },
    /// Unknown unit code or unit id.
    UnknownUnit { format: &'static str, unit: String },
    /// Unknown account code in an entry leg or assertion.
    UnknownAccount {
        format: &'static str,
        account_code: String,
    },
    /// Legacy account identifier has no mapping to a FrankenAccounting leaf account (§8.6).
    UnmappedAccount {
        format: &'static str,
        legacy_account: String,
        fix_hint: String,
    },
    /// Entry violates per-unit double-entry balance (`FA-INV-01`).
    UnbalancedEntry {
        format: &'static str,
        entry_id: String,
        unit_code: String,
        debits: i128,
        credits: i128,
    },
    /// Arithmetic overflow in an exact fold or control total.
    Overflow {
        format: &'static str,
        detail: String,
    },
    /// Export→import round-trip identity failed.
    RoundTripMismatch { format: String, detail: String },
    /// Coordinate certificate digest mismatch.
    CertificateMismatch {
        format: &'static str,
        expected_hex: String,
        observed_hex: String,
    },
    /// Balance differential mismatch against an external oracle (`Beancount` / `hledger`).
    DifferentialMismatch {
        fixture: String,
        account_code: String,
        unit_code: String,
        expected: i128,
        observed: i128,
    },
    /// TigerBeetle semantic corpus violation.
    TigerBeetleViolation { scenario: String, detail: String },
    /// XBRL calculation linkbase inconsistency.
    XbrlCalculationInconsistency {
        parent_concept: String,
        unit_code: String,
        reported_mantissa: i128,
        computed_children_mantissa: i128,
    },
    /// Bank statement sequence or balance continuity error (§9.5).
    BankContinuity {
        format: &'static str,
        detail: String,
    },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { format, detail } => write!(f, "{format} parse error: {detail}"),
            Self::FloatForbidden { format, token } => {
                write!(
                    f,
                    "{format}: floating-point or scientific notation {token:?} is forbidden"
                )
            }
            Self::ExactDecimal {
                format,
                token,
                scale,
                reason,
            } => {
                write!(
                    f,
                    "{format}: invalid exact decimal {token:?} at scale {scale}: {reason}"
                )
            }
            Self::UnknownUnit { format, unit } => {
                write!(f, "{format}: unknown unit {unit:?}")
            }
            Self::UnknownAccount {
                format,
                account_code,
            } => {
                write!(f, "{format}: unknown account code {account_code:?}")
            }
            Self::UnmappedAccount {
                format,
                legacy_account,
                fix_hint,
            } => {
                write!(
                    f,
                    "{format}: unmapped legacy account {legacy_account:?}; fix: {fix_hint}"
                )
            }
            Self::UnbalancedEntry {
                format,
                entry_id,
                unit_code,
                debits,
                credits,
            } => {
                write!(
                    f,
                    "{format}: entry {entry_id:?} is unbalanced in {unit_code}: debits={debits}, credits={credits}"
                )
            }
            Self::Overflow { format, detail } => {
                write!(f, "{format}: exact integer overflow: {detail}")
            }
            Self::RoundTripMismatch { format, detail } => {
                write!(f, "{format} round-trip identity failed: {detail}")
            }
            Self::CertificateMismatch {
                format,
                expected_hex,
                observed_hex,
            } => {
                write!(
                    f,
                    "{format} coordinate certificate mismatch: expected {expected_hex}, observed {observed_hex}"
                )
            }
            Self::DifferentialMismatch {
                fixture,
                account_code,
                unit_code,
                expected,
                observed,
            } => {
                write!(
                    f,
                    "balance differential mismatch on fixture {fixture:?} account {account_code} ({unit_code}): expected {expected}, observed {observed}"
                )
            }
            Self::TigerBeetleViolation { scenario, detail } => {
                write!(
                    f,
                    "TigerBeetle semantic violation in {scenario:?}: {detail}"
                )
            }
            Self::XbrlCalculationInconsistency {
                parent_concept,
                unit_code,
                reported_mantissa,
                computed_children_mantissa,
            } => {
                write!(
                    f,
                    "XBRL calculation linkbase inconsistency on {parent_concept} ({unit_code}): reported {reported_mantissa}, weighted children sum to {computed_children_mantissa}"
                )
            }
            Self::BankContinuity { format, detail } => {
                write!(f, "{format} continuity check failed: {detail}")
            }
        }
    }
}

impl core::error::Error for FormatError {}

/// Unit metadata lookup `(UnitId, code, scale)` used by format encoders and decoders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitCatalog {
    by_code: BTreeMap<String, (UnitId, u8)>,
    by_id: BTreeMap<UnitId, (String, u8)>,
}

impl UnitCatalog {
    /// Construct a `UnitCatalog` from the embedded `registries/units.toml`.
    pub fn embedded() -> Result<Self, FormatError> {
        let units = fa_registry::parse_units(include_str!("../../../registries/units.toml"))
            .map_err(|e| FormatError::Parse {
                format: "units.toml",
                detail: e.to_string(),
            })?;
        let mut by_code = BTreeMap::new();
        let mut by_id = BTreeMap::new();
        for u in units {
            let uid = UnitId(u.id);
            by_code.insert(u.code.clone(), (uid, u.scale));
            by_id.insert(uid, (u.code, u.scale));
        }
        Ok(Self { by_code, by_id })
    }

    pub fn lookup_code(&self, code: &str) -> Option<(UnitId, u8)> {
        self.by_code.get(code).copied()
    }

    pub fn lookup_id(&self, id: UnitId) -> Option<(&str, u8)> {
        self.by_id.get(&id).map(|(c, s)| (c.as_str(), *s))
    }
}

/// Certified bitemporal coordinate for an exported journal or audit package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportCoordinate {
    pub book_name: String,
    pub base_unit_code: String,
    pub base_unit_scale: u8,
    pub effective_through: DateDay,
    pub known_at_seq: u64,
    pub entry_count: u64,
    pub content_digest: [u8; 32],
    pub certificate_digest: [u8; 32],
}

impl ExportCoordinate {
    pub fn compute(
        book_name: &str,
        base_unit_code: &str,
        base_unit_scale: u8,
        effective_through: DateDay,
        known_at_seq: u64,
        entry_count: u64,
        content_digest: [u8; 32],
    ) -> Self {
        let certificate_digest = Self::compute_digest(
            book_name,
            base_unit_code,
            base_unit_scale,
            effective_through,
            known_at_seq,
            entry_count,
            &content_digest,
        );
        Self {
            book_name: book_name.to_owned(),
            base_unit_code: base_unit_code.to_owned(),
            base_unit_scale,
            effective_through,
            known_at_seq,
            entry_count,
            content_digest,
            certificate_digest,
        }
    }

    pub fn compute_digest(
        book_name: &str,
        base_unit_code: &str,
        base_unit_scale: u8,
        effective_through: DateDay,
        known_at_seq: u64,
        entry_count: u64,
        content_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"fa:formats:coordinate:v1");
        h.update(&(book_name.len() as u64).to_le_bytes());
        h.update(book_name.as_bytes());
        h.update(&(base_unit_code.len() as u64).to_le_bytes());
        h.update(base_unit_code.as_bytes());
        h.update(&[base_unit_scale]);
        h.update(&effective_through.0.to_le_bytes());
        h.update(&known_at_seq.to_le_bytes());
        h.update(&entry_count.to_le_bytes());
        h.update(content_digest);
        h.finalize().0
    }

    pub fn verify(&self, expected_content_digest: &[u8; 32]) -> Result<(), FormatError> {
        if &self.content_digest != expected_content_digest {
            return Err(FormatError::CertificateMismatch {
                format: "ExportCoordinate.content_digest",
                expected_hex: hex_encode(expected_content_digest),
                observed_hex: hex_encode(&self.content_digest),
            });
        }
        let expected_cert = Self::compute_digest(
            &self.book_name,
            &self.base_unit_code,
            self.base_unit_scale,
            self.effective_through,
            self.known_at_seq,
            self.entry_count,
            &self.content_digest,
        );
        if self.certificate_digest != expected_cert {
            return Err(FormatError::CertificateMismatch {
                format: "ExportCoordinate.certificate_digest",
                expected_hex: hex_encode(&expected_cert),
                observed_hex: hex_encode(&self.certificate_digest),
            });
        }
        Ok(())
    }
}

/// Canonical account definition in an interop journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatAccount {
    pub code: String,
    pub name: String,
    pub account_type: AccountType,
    pub normal_side: Side,
}

/// Canonical posting leg in an interop journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatLeg {
    pub account_code: String,
    pub side: Side,
    pub amount: Amount,
    pub unit_code: String,
    pub unit_scale: u8,
    pub memo: Option<String>,
}

/// Canonical journal entry in an interop journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatEntry {
    pub entry_id: String,
    pub effective_date: DateDay,
    pub recorded_seq: u64,
    pub class: EntryClass,
    pub description: String,
    pub migrated_from: Option<String>,
    pub legs: Vec<FormatLeg>,
}

/// Canonical balance assertion in an interop journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatAssertion {
    pub account_code: String,
    pub as_of: DateDay,
    pub side: Side,
    pub amount: Amount,
    pub unit_code: String,
    pub unit_scale: u8,
}

/// Canonical interop journal representation shared by Beancount, hledger,
/// AICPA ADS, OECD SAF-T, and CSV/NDJSON GL extracts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatJournal {
    pub coordinate: ExportCoordinate,
    pub accounts: Vec<FormatAccount>,
    pub entries: Vec<FormatEntry>,
    pub assertions: Vec<FormatAssertion>,
}

/// Proof of export→import round-trip identity and `FA-INV-04` refold equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundTripIdentityProof {
    pub format_name: String,
    pub coordinate_digest: [u8; 32],
    pub canonical_journal_digest: [u8; 32],
    pub refold_digest: [u8; 32],
    pub entry_count: usize,
    pub leg_count: usize,
    pub balances_checked: usize,
}

impl FormatJournal {
    /// Construct a `FormatJournal` with a freshly computed `ExportCoordinate` certificate.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        book_name: &str,
        base_unit_code: &str,
        base_unit_scale: u8,
        effective_through: DateDay,
        known_at_seq: u64,
        mut accounts: Vec<FormatAccount>,
        entries: Vec<FormatEntry>,
        mut assertions: Vec<FormatAssertion>,
    ) -> Result<Self, FormatError> {
        accounts.sort_by(|a, b| a.code.cmp(&b.code));
        assertions.sort_by(|a, b| {
            (a.as_of, &a.account_code, &a.unit_code).cmp(&(b.as_of, &b.account_code, &b.unit_code))
        });
        let content_digest = Self::compute_content_digest(&accounts, &entries, &assertions);
        let coordinate = ExportCoordinate::compute(
            book_name,
            base_unit_code,
            base_unit_scale,
            effective_through,
            known_at_seq,
            entries.len() as u64,
            content_digest,
        );
        let journal = Self {
            coordinate,
            accounts,
            entries,
            assertions,
        };
        let _ = journal.fold_balances()?;
        Ok(journal)
    }

    /// Canonical BLAKE3 digest of `(accounts, entries, assertions)`.
    pub fn compute_content_digest(
        accounts: &[FormatAccount],
        entries: &[FormatEntry],
        assertions: &[FormatAssertion],
    ) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"fa:formats:journal:v1");
        h.update(&(accounts.len() as u64).to_le_bytes());
        for a in accounts {
            h.update(&(a.code.len() as u64).to_le_bytes());
            h.update(a.code.as_bytes());
            h.update(&(a.name.len() as u64).to_le_bytes());
            h.update(a.name.as_bytes());
            h.update(&[a.account_type.0, a.normal_side as u8]);
        }
        h.update(&(entries.len() as u64).to_le_bytes());
        for e in entries {
            h.update(&(e.entry_id.len() as u64).to_le_bytes());
            h.update(e.entry_id.as_bytes());
            h.update(&e.effective_date.0.to_le_bytes());
            h.update(&e.recorded_seq.to_le_bytes());
            h.update(&e.class.0.to_le_bytes());
            h.update(&(e.description.len() as u64).to_le_bytes());
            h.update(e.description.as_bytes());
            match &e.migrated_from {
                Some(m) => {
                    h.update(&[1]);
                    h.update(&(m.len() as u64).to_le_bytes());
                    h.update(m.as_bytes());
                }
                None => {
                    h.update(&[0]);
                }
            }
            h.update(&(e.legs.len() as u64).to_le_bytes());
            for leg in &e.legs {
                h.update(&(leg.account_code.len() as u64).to_le_bytes());
                h.update(leg.account_code.as_bytes());
                h.update(&[leg.side as u8]);
                h.update(&leg.amount.unit.0.to_le_bytes());
                h.update(&leg.amount.mantissa.to_le_bytes());
                h.update(&(leg.unit_code.len() as u64).to_le_bytes());
                h.update(leg.unit_code.as_bytes());
                h.update(&[leg.unit_scale]);
                match &leg.memo {
                    Some(m) => {
                        h.update(&[1]);
                        h.update(&(m.len() as u64).to_le_bytes());
                        h.update(m.as_bytes());
                    }
                    None => {
                        h.update(&[0]);
                    }
                }
            }
        }
        h.update(&(assertions.len() as u64).to_le_bytes());
        for asrt in assertions {
            h.update(&(asrt.account_code.len() as u64).to_le_bytes());
            h.update(asrt.account_code.as_bytes());
            h.update(&asrt.as_of.0.to_le_bytes());
            h.update(&[asrt.side as u8]);
            h.update(&asrt.amount.unit.0.to_le_bytes());
            h.update(&asrt.amount.mantissa.to_le_bytes());
        }
        h.finalize().0
    }

    /// Verify every entry's per-unit double-entry balance (`FA-INV-01`) and
    /// compute exact signed `(Dr - Cr)` balances per `(account_code, unit_code)`.
    pub fn fold_balances(&self) -> Result<BTreeMap<(String, String), i128>, FormatError> {
        let known_accounts: std::collections::BTreeSet<&str> =
            self.accounts.iter().map(|a| a.code.as_str()).collect();
        let mut balances: BTreeMap<(String, String), i128> = BTreeMap::new();

        for entry in &self.entries {
            if entry.legs.is_empty() {
                return Err(FormatError::Parse {
                    format: "FormatJournal",
                    detail: format!("entry {:?} has zero legs", entry.entry_id),
                });
            }
            let mut per_unit: BTreeMap<&str, (i128, i128)> = BTreeMap::new();
            for leg in &entry.legs {
                if !known_accounts.contains(leg.account_code.as_str()) {
                    return Err(FormatError::UnknownAccount {
                        format: "FormatJournal",
                        account_code: leg.account_code.clone(),
                    });
                }
                if leg.amount.mantissa <= 0 {
                    return Err(FormatError::Parse {
                        format: "FormatJournal",
                        detail: format!(
                            "entry {:?} leg on {} has non-positive mantissa {}",
                            entry.entry_id, leg.account_code, leg.amount.mantissa
                        ),
                    });
                }
                let (dr, cr) = per_unit.entry(leg.unit_code.as_str()).or_insert((0, 0));
                match leg.side {
                    Side::Debit => {
                        *dr = dr.checked_add(leg.amount.mantissa).ok_or_else(|| {
                            FormatError::Overflow {
                                format: "FormatJournal",
                                detail: "entry debit sum overflow".to_owned(),
                            }
                        })?;
                    }
                    Side::Credit => {
                        *cr = cr.checked_add(leg.amount.mantissa).ok_or_else(|| {
                            FormatError::Overflow {
                                format: "FormatJournal",
                                detail: "entry credit sum overflow".to_owned(),
                            }
                        })?;
                    }
                }

                let cell = balances
                    .entry((leg.account_code.clone(), leg.unit_code.clone()))
                    .or_insert(0);
                let signed = match leg.side {
                    Side::Debit => leg.amount.mantissa,
                    Side::Credit => -leg.amount.mantissa,
                };
                *cell = cell
                    .checked_add(signed)
                    .ok_or_else(|| FormatError::Overflow {
                        format: "FormatJournal",
                        detail: "account balance fold overflow".to_owned(),
                    })?;
            }
            for (unit_code, (dr, cr)) in per_unit {
                if dr != cr {
                    return Err(FormatError::UnbalancedEntry {
                        format: "FormatJournal",
                        entry_id: entry.entry_id.clone(),
                        unit_code: unit_code.to_owned(),
                        debits: dr,
                        credits: cr,
                    });
                }
            }
        }
        Ok(balances)
    }

    /// Compute the `FA-INV-04` refold digest over all `(account_code, unit_code) -> signed_balance` cells.
    pub fn refold_digest(&self) -> Result<[u8; 32], FormatError> {
        let balances = self.fold_balances()?;
        let mut h = Hasher::new();
        h.update(b"fa:formats:refold:v1");
        h.update(&(balances.len() as u64).to_le_bytes());
        for ((acct, unit), bal) in &balances {
            h.update(&(acct.len() as u64).to_le_bytes());
            h.update(acct.as_bytes());
            h.update(&(unit.len() as u64).to_le_bytes());
            h.update(unit.as_bytes());
            h.update(&bal.to_le_bytes());
        }
        Ok(h.finalize().0)
    }
}

/// Verify that an exported and re-imported `FormatJournal` preserves
/// byte-identical canonical journal content, coordinate certificate, and
/// `FA-INV-04` refold balances.
pub fn verify_round_trip_identity(
    format_name: &str,
    original: &FormatJournal,
    reimported: &FormatJournal,
) -> Result<RoundTripIdentityProof, FormatError> {
    let orig_digest = FormatJournal::compute_content_digest(
        &original.accounts,
        &original.entries,
        &original.assertions,
    );
    original.coordinate.verify(&orig_digest)?;

    let reimp_digest = FormatJournal::compute_content_digest(
        &reimported.accounts,
        &reimported.entries,
        &reimported.assertions,
    );
    reimported.coordinate.verify(&reimp_digest)?;

    if original.accounts != reimported.accounts {
        return Err(FormatError::RoundTripMismatch {
            format: format_name.to_owned(),
            detail: format!(
                "account definitions differ: expected {} accounts, got {}",
                original.accounts.len(),
                reimported.accounts.len()
            ),
        });
    }
    if original.entries.len() != reimported.entries.len() {
        return Err(FormatError::RoundTripMismatch {
            format: format_name.to_owned(),
            detail: format!(
                "entry count differs: expected {}, got {}",
                original.entries.len(),
                reimported.entries.len()
            ),
        });
    }
    for (idx, (e1, e2)) in original
        .entries
        .iter()
        .zip(reimported.entries.iter())
        .enumerate()
    {
        if e1 != e2 {
            return Err(FormatError::RoundTripMismatch {
                format: format_name.to_owned(),
                detail: format!(
                    "entry #{idx} ({:?}) differs after round-trip: expected {} legs, got {} legs",
                    e1.entry_id,
                    e1.legs.len(),
                    e2.legs.len()
                ),
            });
        }
    }
    if orig_digest != reimp_digest {
        return Err(FormatError::RoundTripMismatch {
            format: format_name.to_owned(),
            detail: format!(
                "canonical content digest mismatch: expected {}, got {}",
                hex_encode(&orig_digest),
                hex_encode(&reimp_digest)
            ),
        });
    }

    let orig_balances = original.fold_balances()?;
    let reimp_balances = reimported.fold_balances()?;
    if orig_balances != reimp_balances {
        return Err(FormatError::RoundTripMismatch {
            format: format_name.to_owned(),
            detail: "FA-INV-04 refold balances differ after round-trip".to_owned(),
        });
    }
    let refold_digest = reimported.refold_digest()?;
    let leg_count = reimported.entries.iter().map(|e| e.legs.len()).sum();

    Ok(RoundTripIdentityProof {
        format_name: format_name.to_owned(),
        coordinate_digest: reimported.coordinate.certificate_digest,
        canonical_journal_digest: reimp_digest,
        refold_digest,
        entry_count: reimported.entries.len(),
        leg_count,
        balances_checked: reimp_balances.len(),
    })
}

/// Format an exact `i128` mantissa at `scale` decimal places without floats.
pub fn format_exact_decimal(mantissa: i128, scale: u8) -> String {
    let neg = mantissa < 0;
    let abs = mantissa.unsigned_abs();
    if scale == 0 {
        return if neg {
            format!("-{abs}")
        } else {
            abs.to_string()
        };
    }
    let divisor = 10u128.pow(u32::from(scale));
    let whole = abs / divisor;
    let frac = abs % divisor;
    let width = usize::from(scale);
    if neg {
        format!("-{whole}.{frac:0width$}")
    } else {
        format!("{whole}.{frac:0width$}")
    }
}

/// Parse a decimal token into an exact `i128` mantissa at `scale` decimal
/// places, forbidding scientific notation (`e`/`E`), `NaN`/`Inf`, and excess
/// fractional digits.
pub fn parse_exact_decimal(
    format: &'static str,
    token: &str,
    scale: u8,
) -> Result<i128, FormatError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(FormatError::ExactDecimal {
            format,
            token: token.to_owned(),
            scale,
            reason: "empty amount token".to_owned(),
        });
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains('e') || lower.contains("nan") || lower.contains("inf") {
        return Err(FormatError::FloatForbidden {
            format,
            token: trimmed.to_owned(),
        });
    }
    let (neg, unsigned) = if let Some(rest) = trimmed.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix('+') {
        (false, rest)
    } else {
        (false, trimmed)
    };
    if unsigned.is_empty() {
        return Err(FormatError::ExactDecimal {
            format,
            token: trimmed.to_owned(),
            scale,
            reason: "missing digits after sign".to_owned(),
        });
    }
    let mut parts = unsigned.split('.');
    let whole_str = parts.next().unwrap_or("");
    let frac_str = parts.next();
    if parts.next().is_some() {
        return Err(FormatError::ExactDecimal {
            format,
            token: trimmed.to_owned(),
            scale,
            reason: "multiple decimal points".to_owned(),
        });
    }
    if whole_str.is_empty() || !whole_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FormatError::ExactDecimal {
            format,
            token: trimmed.to_owned(),
            scale,
            reason: "invalid integer digits".to_owned(),
        });
    }
    let whole: i128 = whole_str.parse().map_err(|_| FormatError::ExactDecimal {
        format,
        token: trimmed.to_owned(),
        scale,
        reason: "integer part overflows i128".to_owned(),
    })?;
    let factor = 10i128
        .checked_pow(u32::from(scale))
        .ok_or_else(|| FormatError::ExactDecimal {
            format,
            token: trimmed.to_owned(),
            scale,
            reason: "scale exceeds i128 power of 10".to_owned(),
        })?;
    let scaled_whole = whole
        .checked_mul(factor)
        .ok_or_else(|| FormatError::ExactDecimal {
            format,
            token: trimmed.to_owned(),
            scale,
            reason: "scaled integer overflows i128".to_owned(),
        })?;
    let scaled_frac = match frac_str {
        None => 0i128,
        Some(f) => {
            if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(FormatError::ExactDecimal {
                    format,
                    token: trimmed.to_owned(),
                    scale,
                    reason: "invalid fractional digits".to_owned(),
                });
            }
            if f.len() > usize::from(scale) {
                return Err(FormatError::ExactDecimal {
                    format,
                    token: trimmed.to_owned(),
                    scale,
                    reason: format!(
                        "fractional precision {} exceeds unit scale {scale}",
                        f.len()
                    ),
                });
            }
            let raw_frac: i128 = f.parse().map_err(|_| FormatError::ExactDecimal {
                format,
                token: trimmed.to_owned(),
                scale,
                reason: "fractional part overflows i128".to_owned(),
            })?;
            let pad = u32::from(scale) - (f.len() as u32);
            raw_frac * 10i128.pow(pad)
        }
    };
    let mag = scaled_whole
        .checked_add(scaled_frac)
        .ok_or_else(|| FormatError::ExactDecimal {
            format,
            token: trimmed.to_owned(),
            scale,
            reason: "mantissa addition overflows i128".to_owned(),
        })?;
    if neg {
        mag.checked_neg().ok_or_else(|| FormatError::ExactDecimal {
            format,
            token: trimmed.to_owned(),
            scale,
            reason: "negated mantissa overflows i128".to_owned(),
        })
    } else {
        Ok(mag)
    }
}

/// Format a `DateDay` as `YYYY-MM-DD`.
pub fn format_date_iso(day: DateDay) -> String {
    let (year, month, dom) = day.ymd();
    format!("{year:04}-{month:02}-{dom:02}")
}

/// Parse a `YYYY-MM-DD` string into `DateDay`.
pub fn parse_date_iso(format: &'static str, text: &str) -> Result<DateDay, FormatError> {
    let trimmed = text.trim();
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return Err(FormatError::Parse {
            format,
            detail: format!("invalid YYYY-MM-DD date {trimmed:?}"),
        });
    }
    let year: i32 = parts[0].parse().map_err(|_| FormatError::Parse {
        format,
        detail: format!("invalid year in {trimmed:?}"),
    })?;
    let month: u8 = parts[1].parse().map_err(|_| FormatError::Parse {
        format,
        detail: format!("invalid month in {trimmed:?}"),
    })?;
    let day: u8 = parts[2].parse().map_err(|_| FormatError::Parse {
        format,
        detail: format!("invalid day in {trimmed:?}"),
    })?;
    DateDay::from_ymd(year, month, day).map_err(|e| FormatError::Parse {
        format,
        detail: format!("invalid civil date {trimmed:?}: {e}"),
    })
}

/// Encode bytes as lowercase hex characters (64 characters for a 32-byte digest).
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a 64-character hex string into `[u8; 32]`.
pub fn hex_decode(format: &'static str, text: &str) -> Result<[u8; 32], FormatError> {
    let s = text.trim();
    if s.len() != 64 {
        return Err(FormatError::Parse {
            format,
            detail: format!("expected 64-char hex digest, got len {}", s.len()),
        });
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(format, chunk[0])?;
        let lo = hex_nibble(format, chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(format: &'static str, b: u8) -> Result<u8, FormatError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(FormatError::Parse {
            format,
            detail: format!("invalid hex byte 0x{b:02x}"),
        }),
    }
}

pub(crate) fn parse_account_type(
    format: &'static str,
    text: &str,
) -> Result<AccountType, FormatError> {
    match text.trim() {
        "Asset" => Ok(AccountType::ASSET),
        "Liability" => Ok(AccountType::LIABILITY),
        "Equity" => Ok(AccountType::EQUITY),
        "Revenue" => Ok(AccountType::REVENUE),
        "Expense" => Ok(AccountType::EXPENSE),
        "Memo" => Ok(AccountType::MEMO),
        "Statistical" => Ok(AccountType::STATISTICAL),
        "OffBalance" => Ok(AccountType::OFF_BALANCE),
        other => Err(FormatError::Parse {
            format,
            detail: format!("unknown AccountType {other:?}"),
        }),
    }
}

pub(crate) fn format_account_type(ty: AccountType) -> &'static str {
    ty.name().unwrap_or("Asset")
}

pub(crate) fn normal_side_for_type(ty: AccountType) -> Side {
    match ty.normal_balance() {
        Some(1) => Side::Credit,
        _ => Side::Debit,
    }
}
