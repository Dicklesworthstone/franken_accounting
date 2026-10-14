//! Durable handoff of a journal-derived allocation (plan §5.3 / §6.3 / §10.4).
//!
//! An ordinary AllocationReview retains an explicit amount but not the source
//! period or source-history expectation that produced it. This artifact binds
//! all three in ONE recipient-retained digest. It never reconstructs a trusted
//! PreparedBalanceAllocation from untrusted bytes: a consumer must observe the
//! journal again before approval or planning.
//!
//! This is an unsigned request, not a source certificate or an approval. The
//! embedded proposal retains its original ciphertext, driver and metadata;
//! its proposal digest is distinct from both review digests and the source
//! digest. Driver data is not encrypted by this transport. Protect its bytes
//! and obtain the expected digest independently, not from the same untrusted
//! delivery as the artifact. After attempting publication, retry the saved
//! native PostPlan, never prepare or replan from this review automatically.

use fa_model::{EntryPayload, Reader, Writer, domain_digest};

use crate::{
    AllocationReview, AllocationReviewError, BalanceAllocationRequest,
    MAX_ALLOCATION_REVIEW_BYTES, PreparedBalanceAllocation,
};

const MAGIC: &[u8; 14] = b"FA-BAL-REVIEW\0";
const VERSION: u16 = 1;
const MAX_SOURCE_PERIOD_BYTES: usize = 256;
/// Header, bounded source period and expectation, and one complete nested
/// allocation review. Hex/JSON transports must budget their expansion too.
pub const MAX_BALANCE_ALLOCATION_REVIEW_BYTES: usize = MAGIC.len()
    + 4 + 4 + MAX_SOURCE_PERIOD_BYTES + 32 + 4 + MAX_ALLOCATION_REVIEW_BYTES;

/// A source expectation and the unchanged sealed instruction it produced.
/// Private fields prevent independent selector/driver changes after review.
/// Parsing establishes consistency, not current source validity or authorship.
#[derive(Clone, PartialEq, Eq)]
pub struct BalanceAllocationReview {
    source_period: String,
    source_digest: [u8; 32],
    review: AllocationReview,
}

impl core::fmt::Debug for BalanceAllocationReview {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // AllocationReview's own Debug redacts driver values and sealed data.
        f.debug_struct("BalanceAllocationReview")
            .field("review", &self.review)
            .finish_non_exhaustive()
    }
}

impl BalanceAllocationReview {
    /// Seal no new fields and import no evidence. The caller supplies the
    /// template already citing the exact driver, with truthful provenance.
    pub fn new(
        prepared: &PreparedBalanceAllocation,
        template: EntryPayload,
    ) -> Result<Self, AllocationReviewError> {
        Self::from_review(prepared, prepared.review(template)?)
    }

    /// Adopt an already sealed review, preserving its exact proposal identity.
    /// A same-total alternative driver, target order, side or dimensions is
    /// not equivalent to the instruction in the supplied source preparation.
    pub fn from_review(
        prepared: &PreparedBalanceAllocation,
        review: AllocationReview,
    ) -> Result<Self, AllocationReviewError> {
        if prepared.posting() != review.posting() {
            return Err(AllocationReviewError::Invalid(
                "review differs from the source-derived allocation instruction",
            ));
        }
        let result = Self {
            source_period: prepared.request().period.clone(),
            source_digest: prepared.source_digest(),
            review,
        };
        result.canonical_bytes()?;
        Ok(result)
    }

    pub fn source_period(&self) -> &str { &self.source_period }
    pub fn source_digest(&self) -> [u8; 32] { self.source_digest }
    pub fn review(&self) -> &AllocationReview { &self.review }

    /// Reconstruct the selector from the one canonical instruction. Source,
    /// unit, dimensions, law and ordered targets have no second representation
    /// that a parser could accept while the posting interpreter sees another.
    pub fn request(&self) -> BalanceAllocationRequest {
        let posting = self.review.posting();
        BalanceAllocationRequest {
            source: posting.source,
            period: self.source_period.clone(),
            unit: posting.request.total.unit,
            dimensions: posting.dimensions.clone(),
            method: posting.request.method,
            targets: posting.request.targets.clone(),
        }
    }

    /// Exact versioned bytes, including the existing sealed review verbatim.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AllocationReviewError> {
        if self.source_period.is_empty() || self.source_period.len() > MAX_SOURCE_PERIOD_BYTES {
            return Err(AllocationReviewError::Invalid(
                "source period must contain 1 through 256 UTF-8 bytes",
            ));
        }
        let review = self.review.canonical_bytes()?;
        let mut w = Writer::new();
        w.fixed(MAGIC).u16(VERSION).u16(0)
            .str(&self.source_period).fixed(&self.source_digest).bytes(&review);
        let bytes = w.finish()?;
        bounded(&bytes)?;
        Ok(bytes)
    }

    /// Fail closed on unknown versions, excessive lengths, invalid UTF-8,
    /// noncanonical nested proposals, truncation and trailing data. A parsed
    /// source digest remains a CLAIM to compare with the live journal, not a
    /// statement that such a source was ever observed.
    pub fn decode(bytes: &[u8]) -> Result<Self, AllocationReviewError> {
        bounded(bytes)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("balance_review.magic")? != *MAGIC
            || r.u16("balance_review.major")? != VERSION
            || r.u16("balance_review.minor")? != 0
        {
            return Err(AllocationReviewError::Invalid("unsupported source review format"));
        }
        let period = r.bytes(MAX_SOURCE_PERIOD_BYTES, "balance_review.source_period")?;
        let source_period = core::str::from_utf8(period)
            .map_err(|_| AllocationReviewError::Invalid("source period is not UTF-8"))?
            .to_owned();
        let source_digest = r.fixed::<32>("balance_review.source_digest")?;
        let review = AllocationReview::decode(
            r.bytes(MAX_ALLOCATION_REVIEW_BYTES, "balance_review.allocation_review")?,
        )?;
        r.finish()?;
        let result = Self { source_period, source_digest, review };
        if result.canonical_bytes()?.as_slice() != bytes {
            return Err(AllocationReviewError::Invalid("noncanonical source review bytes"));
        }
        Ok(result)
    }

    /// Identity of this complete handoff, not an ApprovalRef proposal digest,
    /// signature, native object identifier or journal-source certificate.
    pub fn digest(&self) -> Result<[u8; 32], AllocationReviewError> {
        Ok(domain_digest(b"fa:balance-allocation-review:v1", &[&self.canonical_bytes()?]))
    }

    /// Check the recipient's independently retained expectation. Source and
    /// nested review digests alone cannot substitute for this compound digest.
    pub fn verify_for(&self, expected: &[u8; 32]) -> Result<(), AllocationReviewError> {
        if self.digest()? != *expected { return Err(AllocationReviewError::Mismatch); }
        Ok(())
    }
}

impl PreparedBalanceAllocation {
    /// Preserve this preparation's source expectation together with one exact
    /// sealed proposal. Persist the returned artifact before handing it off.
    /// Reading it later does not recreate this trusted observation.
    pub fn portable_review(
        &self,
        template: EntryPayload,
    ) -> Result<BalanceAllocationReview, AllocationReviewError> {
        BalanceAllocationReview::new(self, template)
    }
}

fn bounded(bytes: &[u8]) -> Result<(), AllocationReviewError> {
    if bytes.len() > MAX_BALANCE_ALLOCATION_REVIEW_BYTES {
        return Err(AllocationReviewError::TooLarge {
            maximum: MAX_BALANCE_ALLOCATION_REVIEW_BYTES, actual: bytes.len(),
        });
    }
    Ok(())
}

mod native;

#[cfg(test)]
mod tests;
