//! Recipient-scoped completeness of journal ENTRY production (fa-smx).
//!
//! This composes the existing prefix and record-bearing inclusion formats;
//! it is not a new bundle format. A collection of valid inclusion proofs
//! alone cannot establish that the producer supplied every matching entry.
//! We authenticate the entire prefix, select with the recipient's predicate,
//! and require precisely those records in journal order, payloads included.
//!
//! Selection is over authenticated envelope metadata. All entry classes,
//! including Pending and Migration, are journal records here: neither
//! migration visibility nor posted amounts are inferred. Undated controls
//! match an unrestricted day selector, but not an explicit civil-day range.
//! An account selector means one exact account, not a chart subtree.
//!
//! Completeness concerns matching journal entries only, NOT their cited
//! documents, provenance closure, permissions, accounting correctness or
//! records outside the checkpoint. Payload checks recompute digests and
//! selection fields; they do not interpret every other entry field.
//! The full prefix discloses selection
//! metadata even for excluded entries; this is not a private scope index.

use core::fmt;

use crate::envelope::LeafEnvelope;
use crate::proof::{
    Checkpoint, PREFIX_FORMAT, RecordCheck, SCOPE_SEQ_RANGE_COMPLETE, VerifyError, open, trusted,
    verify_inclusion, verify_prefix,
};

/// Total encoded prefix plus inclusion bytes admitted by this composition.
pub const MAX_PRODUCTION_BYTES: usize = 64 * 1024 * 1024;
/// Policy bounds for this API, not changes to either durable proof format.
pub const MAX_PRODUCTION_RECORDS: usize = 4096;
pub const MAX_PRODUCTION_LEAVES: usize = 65_536;

/// A question chosen independently of the producer and its artifacts.
/// Both recorded and effective ranges are inclusive. `None` is explicitly
/// unrestricted, never a wildcard learned from a supplied proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionScope {
    pub first_seq: u64,
    pub known_at: u64,
    pub account: Option<u128>,
    pub effective_days: Option<(i32, i32)>,
}

impl ProductionScope {
    /// Validate request syntax without observing a proof or a file.
    pub fn validate(&self) -> Result<(), ProductionError> {
        if self.first_seq > self.known_at {
            return Err(ProductionError::Request("first_seq exceeds known_at"));
        }
        if self
            .effective_days
            .is_some_and(|(first, last)| first > last)
        {
            return Err(ProductionError::Request("effective-day range is reversed"));
        }
        Ok(())
    }

    fn selects(&self, entry: &LeafEnvelope) -> bool {
        self.first_seq <= entry.commit_seq
            && entry.commit_seq <= self.known_at
            && self
                .account
                .is_none_or(|account| entry.account_vids.binary_search(&account).is_ok())
            && self.effective_days.is_none_or(|(first, last)| {
                entry
                    .effective_day
                    .is_some_and(|day| first <= day && day <= last)
            })
    }
}

/// Metadata only. The actual payload was checked before this was returned.
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
    /// Exactly the matching entries, not an inclusion-only partial result.
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
}

impl fmt::Display for ProductionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(why) => write!(f, "invalid entry-production request: {why}"),
            Self::Limit(what) => write!(f, "entry production exceeds the {what} bound"),
            Self::Prefix(error) => write!(f, "production prefix: {error}"),
            Self::Record { position, error } => write!(f, "production record {position}: {error}"),
            Self::RecordCount { expected, actual } => write!(
                f,
                "scope requires {expected} journal records; production supplies {actual}"
            ),
            Self::Position { expected, actual } => write!(
                f,
                "production requires next leaf {expected}, not leaf {actual}"
            ),
            Self::Envelope { index } => {
                write!(f, "production leaf {index} differs from the prefix")
            }
            Self::PayloadRequired { index } => write!(
                f,
                "production leaf {index} requires its record payload, not just its envelope"
            ),
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

/// Verify an exact production against independently trusted coordinates.
///
/// `records` are the existing raw inclusion proofs in ascending leaf order;
/// every proof MUST include its record payload. Empty production is valid
/// only when the authenticated prefix contains no matching entries. Neither
/// supplied order nor the recipient predicate is sorted, broadened or fixed.
/// No partial report is returned on any failure, including the last record.
///
/// Reads the full prefix and each inclusion, hashes payloads and rebuilds
/// selection metadata. Input bytes and counts have explicit bounds. There is no
/// signature verification, network, book access or new dependency here.
pub fn verify_production_for(
    prefix_bytes: &[u8],
    records: &[&[u8]],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedProduction, ProductionError> {
    expected.validate()?;
    if expected.known_at > checkpoint.through_seq {
        return Err(ProductionError::Request(
            "known_at is later than the trusted checkpoint",
        ));
    }
    if records.len() > MAX_PRODUCTION_RECORDS {
        return Err(ProductionError::Limit("record count"));
    }
    let total = records
        .iter()
        .try_fold(prefix_bytes.len(), |total, record| {
            total.checked_add(record.len())
        });
    if total.is_none_or(|bytes| bytes > MAX_PRODUCTION_BYTES) {
        return Err(ProductionError::Limit("aggregate encoded bytes"));
    }
    // Check the declared allocation before the general prefix reader reserves
    // storage. Its wire bound is deliberately larger than this API's policy.
    let preflight = || -> Result<(), VerifyError> {
        let mut r = open(prefix_bytes, PREFIX_FORMAT)?;
        trusted(Checkpoint::read(&mut r)?, checkpoint)?;
        r.count(MAX_PRODUCTION_LEAVES, 4, "production.prefix.envelopes")?;
        Ok(())
    };
    preflight().map_err(ProductionError::Prefix)?;
    let prefix = verify_prefix(prefix_bytes, checkpoint).map_err(ProductionError::Prefix)?;
    let count = prefix
        .envelopes
        .iter()
        .filter(|entry| expected.selects(entry))
        .count();
    if count > MAX_PRODUCTION_RECORDS {
        return Err(ProductionError::Limit("selected record count"));
    }
    if count != records.len() {
        return Err(ProductionError::RecordCount {
            expected: count,
            actual: records.len(),
        });
    }
    let selected = prefix
        .envelopes
        .into_iter()
        .enumerate()
        .filter(|(_, entry)| expected.selects(entry));
    let mut entries = Vec::with_capacity(count);
    for (position, ((index, envelope), bytes)) in selected.zip(records).enumerate() {
        // The prefix count is <= 65536 on every admitted host.
        let index = index as u64;
        let inclusion = verify_inclusion(bytes, checkpoint)
            .map_err(|error| ProductionError::Record { position, error })?;
        if inclusion.leaf_index != index {
            return Err(ProductionError::Position {
                expected: index,
                actual: inclusion.leaf_index,
            });
        }
        if inclusion.envelope != envelope {
            return Err(ProductionError::Envelope { index });
        }
        if inclusion.record != RecordCheck::Recomputed {
            return Err(ProductionError::PayloadRequired { index });
        }
        entries.push(ProducedEntry {
            leaf_index: index,
            envelope,
        });
    }
    Ok(VerifiedProduction {
        scope: SCOPE_SEQ_RANGE_COMPLETE,
        checkpoint: *checkpoint,
        requested: *expected,
        entries,
    })
}
