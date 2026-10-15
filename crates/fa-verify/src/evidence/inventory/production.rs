//! Complete citation inventories for a recipient-selected journal extract.
//!
//! Authenticate the complete prefix, select entries locally, require exactly
//! their record-bearing inclusion proofs, then check every citation in each
//! selected payload. This closes two independent omission opportunities:
//! missing entries and missing citations inside a supplied entry. Reusing
//! the existing proof formats introduces neither a bundle nor a trust anchor.
//!
//! Completeness is confined to the original citation lists of the matching
//! journal entries. Document bytes, supplemental evidence, provenance,
//! signatures, permissions, accounting validity and migration visibility
//! are not verified. An empty list is not a claim that evidence was required
//! or sufficient. The full prefix exposes out-of-scope envelope metadata.

pub mod documents;
pub mod prefix;

use core::fmt;

use super::citations_from_proposal;
use crate::evidence::{EvidenceCitation, EvidenceError, included_proposal};
use crate::proof::Checkpoint;
use crate::proof::production::{
    ProducedEntry, ProductionError, ProductionScope, verify_production_for,
};

/// Bound accumulated metadata independently of each entry's 1,024-row limit.
/// The existing production limits additionally bound records, prefix leaves,
/// and aggregate encoded input bytes before authentication begins.
pub const MAX_PRODUCTION_CITATIONS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducedEvidence {
    pub entry: ProducedEntry,
    /// The entire canonical list, including empty lists and multiple roles.
    pub citations: Vec<EvidenceCitation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEvidenceProduction {
    /// `seq_range_complete`, scoped to matching entries and their citations,
    /// never to the document contents or full provenance closure.
    pub scope: &'static str,
    pub checkpoint: Checkpoint,
    pub requested: ProductionScope,
    /// Journal order; even entries without citations are retained.
    pub entries: Vec<ProducedEvidence>,
    /// Citation rows, NOT distinct documents. Repeated documents retain all
    /// of their entry/role associations rather than being deduplicated.
    pub citation_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceProductionError {
    Production(ProductionError),
    Evidence {
        leaf_index: u64,
        error: EvidenceError,
    },
    Limit(&'static str),
}

impl fmt::Display for EvidenceProductionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production(error) => write!(f, "{error}"),
            Self::Evidence { leaf_index, error } => {
                write!(f, "evidence at journal leaf {leaf_index}: {error}")
            }
            Self::Limit(what) => write!(f, "evidence production exceeds the {what} bound"),
        }
    }
}

impl core::error::Error for EvidenceProductionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Production(error) => Some(error),
            Self::Evidence { error, .. } => Some(error),
            Self::Limit(_) => None,
        }
    }
}

impl From<ProductionError> for EvidenceProductionError {
    fn from(error: ProductionError) -> Self {
        Self::Production(error)
    }
}

/// Check completeness of the entry/citation map at independently chosen
/// coordinates. `records` are existing raw inclusion proofs in leaf order.
/// The caller chooses the scope and trusts the checkpoint independently.
///
/// Selection follows `ProductionScope`: inclusive recorded and civil-day
/// ranges, one exact account or all accounts, and all journal entry classes.
/// No hierarchy, entity filter or posted-balance semantics are implied.
/// A requested known-at beyond the checkpoint refuses; earlier horizons
/// select from the complete trusted prefix, not from producer-chosen edges.
///
/// Each proof is authenticated once by the existing production verifier.
/// Only afterwards are the same immutable record bytes borrowed for citation
/// and full entry-frame validation. No partial inventory escapes if any
/// record fails, including the last record or the aggregate citation limit.
pub fn verify_evidence_production_for(
    prefix_bytes: &[u8],
    records: &[&[u8]],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedEvidenceProduction, EvidenceProductionError> {
    let production = verify_production_for(prefix_bytes, records, checkpoint, expected)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(production.entries.len())
        .map_err(|_| EvidenceProductionError::Limit("entry allocation"))?;
    let mut citation_count = 0usize;
    for (entry, record) in production.entries.into_iter().zip(records) {
        let at_leaf = |error| EvidenceProductionError::Evidence {
            leaf_index: entry.leaf_index,
            error,
        };
        // verify_production_for has already authenticated this exact record
        // and its position. Do not call the single-entry verifier again.
        let proposal = included_proposal(record).map_err(at_leaf)?;
        let citations = citations_from_proposal(proposal, &checkpoint.book_id).map_err(at_leaf)?;
        citation_count = citation_count
            .checked_add(citations.len())
            .filter(|count| *count <= MAX_PRODUCTION_CITATIONS)
            .ok_or(EvidenceProductionError::Limit("aggregate citation count"))?;
        entries.push(ProducedEvidence { entry, citations });
    }
    Ok(VerifiedEvidenceProduction {
        scope: production.scope,
        checkpoint: production.checkpoint,
        requested: production.requested,
        entries,
        citation_count,
    })
}
