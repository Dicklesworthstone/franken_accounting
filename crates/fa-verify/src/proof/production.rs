//! Recipient-scoped journal production with independent selector derivation.
//!
//! V2 prefixes and native v3 balance exports carry every payload, including
//! exclusions. Legacy v1 is sufficient only when every prefix leaf is checked
//! by a selected inclusion. All classes are journal records here, not a
//! posted-balance view. Exact accounts are not subtrees. No document,
//! provenance, signature, permission or accounting-law claim is made.
//! Complete witnesses require whole-prefix disclosure authority.

pub mod derivation;

use core::fmt;
use crate::envelope::LeafEnvelope;
use crate::proof::{
    Checkpoint, RecordCheck, SCOPE_SEQ_RANGE_COMPLETE, VerifyError,
    verify_inclusion, verify_prefix,
};
use derivation::{PrefixKind, read_header, verify_prefix_with_records};

pub const MAX_PRODUCTION_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PRODUCTION_RECORDS: usize = 4096;
pub const MAX_PRODUCTION_LEAVES: usize = 65_536;

/// Independently chosen inclusive bounds. None is unrestricted, not inferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionScope {
    pub first_seq: u64,
    pub known_at: u64,
    pub account: Option<u128>,
    pub effective_days: Option<(i32, i32)>,
}

impl ProductionScope {
    pub fn validate(&self) -> Result<(), ProductionError> {
        if self.first_seq > self.known_at {
            return Err(ProductionError::Request("first_seq exceeds known_at"));
        }
        if self.effective_days.is_some_and(|(first, last)| first > last) {
            return Err(ProductionError::Request("effective-day range is reversed"));
        }
        Ok(())
    }

    fn selects(&self, entry: &LeafEnvelope) -> bool {
        self.first_seq <= entry.commit_seq
            && entry.commit_seq <= self.known_at
            && self.account.is_none_or(|account| entry.account_vids.binary_search(&account).is_ok())
            && self.effective_days.is_none_or(|(first, last)| {
                entry.effective_day.is_some_and(|day| first <= day && day <= last)
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducedEntry {
    pub leaf_index: u64,
    pub envelope: LeafEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProduction {
    pub scope: &'static str,
    pub checkpoint: Checkpoint,
    pub requested: ProductionScope,
    /// Exactly the matching entries; every prefix selector was recomputed.
    pub entries: Vec<ProducedEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProductionError {
    Request(&'static str),
    Limit(&'static str),
    Prefix(VerifyError),
    Record { position: usize, error: VerifyError },
    RecordCount { expected: usize, actual: usize },
    Position { expected: u64, actual: u64 },
    Envelope { index: u64 },
    PayloadRequired { index: u64 },
    ScopeDerivationRequired { index: u64 },
}

impl fmt::Display for ProductionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(why) => write!(f, "invalid entry-production request: {why}"),
            Self::Limit(what) => write!(f, "entry production exceeds the {what} bound"),
            Self::Prefix(error) => write!(f, "production prefix: {error}"),
            Self::Record { position, error } => write!(f, "production record {position}: {error}"),
            Self::RecordCount { expected, actual } => write!(f,
                "scope requires {expected} journal records; production supplies {actual}"),
            Self::Position { expected, actual } => write!(f,
                "production requires next leaf {expected}, not leaf {actual}"),
            Self::Envelope { index } => write!(f, "production leaf {index} differs from the prefix"),
            Self::PayloadRequired { index } => write!(f,
                "production leaf {index} requires its record payload, not just its envelope"),
            Self::ScopeDerivationRequired { index } => write!(f,
                "excluded leaf {index} has unverified scope selectors; supply a payload-complete v2 prefix or the existing fa proof balance v3 export as --prefix; membership alone does not prove a complete extract"),
        }
    }
}

impl core::error::Error for ProductionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Prefix(error) | Self::Record { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// `records` are exactly the matching raw record-bearing inclusions in leaf
/// order. A v2 prefix or native v3 balance export supplies exclusion evidence.
/// V1 is accepted only when all prefix leaves are selected, including an
/// empty prefix. Empty scoped results never excuse missing witnesses. No
/// partial report escapes a failure, including the last selected record.
pub fn verify_production_for(
    prefix_bytes: &[u8],
    records: &[&[u8]],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedProduction, ProductionError> {
    expected.validate()?;
    if expected.known_at > checkpoint.through_seq {
        return Err(ProductionError::Request("known_at is later than the trusted checkpoint"));
    }
    if records.len() > MAX_PRODUCTION_RECORDS {
        return Err(ProductionError::Limit("record count"));
    }
    let total = records.iter().try_fold(prefix_bytes.len(), |total, record| {
        total.checked_add(record.len())
    });
    if total.is_none_or(|bytes| bytes > MAX_PRODUCTION_BYTES) {
        return Err(ProductionError::Limit("aggregate encoded bytes"));
    }
    let preflight = || -> Result<bool, VerifyError> {
        let (mut r, kind) = read_header(prefix_bytes, checkpoint)?;
        r.count(MAX_PRODUCTION_LEAVES, 4, "production.prefix.envelopes")?;
        Ok(kind != PrefixKind::Legacy)
    };
    let complete = preflight().map_err(ProductionError::Prefix)?;
    let prefix = if complete {
        verify_prefix_with_records(prefix_bytes, checkpoint)
    } else {
        verify_prefix(prefix_bytes, checkpoint)
    }.map_err(ProductionError::Prefix)?;
    let count = prefix.envelopes.iter().filter(|entry| expected.selects(entry)).count();
    if count > MAX_PRODUCTION_RECORDS {
        return Err(ProductionError::Limit("selected record count"));
    }
    if count != records.len() {
        return Err(ProductionError::RecordCount { expected: count, actual: records.len() });
    }
    if !complete
        && let Some(index) = prefix.envelopes.iter().position(|entry| !expected.selects(entry))
    {
        return Err(ProductionError::ScopeDerivationRequired { index: index as u64 });
    }
    let selected = prefix.envelopes.into_iter().enumerate()
        .filter(|(_, entry)| expected.selects(entry));
    let mut entries = Vec::with_capacity(count);
    for (position, ((index, envelope), bytes)) in selected.zip(records).enumerate() {
        let index = index as u64;
        let inclusion = verify_inclusion(bytes, checkpoint)
            .map_err(|error| ProductionError::Record { position, error })?;
        if inclusion.leaf_index != index {
            return Err(ProductionError::Position { expected: index, actual: inclusion.leaf_index });
        }
        if inclusion.envelope != envelope {
            return Err(ProductionError::Envelope { index });
        }
        if inclusion.record != RecordCheck::Recomputed {
            return Err(ProductionError::PayloadRequired { index });
        }
        entries.push(ProducedEntry { leaf_index: index, envelope });
    }
    Ok(VerifiedProduction {
        scope: SCOPE_SEQ_RANGE_COMPLETE,
        checkpoint: *checkpoint,
        requested: *expected,
        entries,
    })
}
