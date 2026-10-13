//! Exact allocation handoff from review to the existing native posting plan.
//!
//! A review is an unsigned request, not an approval, a certificate, or evidence
//! that a book has admitted it. It preserves the already sealed proposal and
//! the explicit ordered allocation instruction across process restarts and
//! approval publications. No current balance is substituted for its total.
//! The recipient must independently retain its digest before trusting it.
//!
//! Planning accepts that exact review and separately supplied approvals, then
//! rehearses the ordinary kernel at the CURRENT prefix. The kernel verifies
//! the driver document, accounts (including zero-share targets), periods,
//! limits, policy and approvals again. Save the returned PostPlan and use
//! commit_plan for publication and retries; never refresh after an uncertain
//! publication. The review itself neither opens a book nor writes a journal.

use core::fmt;

use asupersync::fs::Vfs;
use fa_intents::{IntentError, PostIntent, PostPlan};
use fa_journal::{AllocationPosting, Refusal, exit};
use fa_model::limits::{MAX_DIMENSIONS_PER_LEG, MAX_ENTRY_BYTES};
use fa_model::{ApprovalRef, DecodeError, EncodeError, EntryPayload, Id128, Reader, Writer, domain_digest};
use fa_money::allocation::{AllocationError, AllocationOutcome, AllocationRequest, MAX_ALLOCATION_REQUEST_BYTES};
use fa_money::Side;
use fa_policy::{Capability, Op};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Book, BookError, Outcome};

const MAGIC: &[u8; 16] = b"FA-ALLOC-REVIEW\0";
const VERSION: u16 = 1;
const MAX_INTENT_BYTES: usize = MAX_ENTRY_BYTES + 32;
/// One bounded sealed intent, its explicit driver instruction, and framing.
/// A hex transport must separately account for its expansion.
pub const MAX_ALLOCATION_REVIEW_BYTES: usize =
    MAX_ENTRY_BYTES + MAX_ALLOCATION_REQUEST_BYTES + 20 * MAX_DIMENSIONS_PER_LEG + 256;

#[derive(Debug)]
pub enum AllocationReviewError {
    Decode(DecodeError),
    Encode(EncodeError),
    Intent(IntentError),
    Arithmetic(AllocationError),
    Posting(Refusal),
    Invalid(&'static str),
    Mismatch,
    TooLarge { maximum: usize, actual: usize },
}

impl fmt::Display for AllocationReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Intent(e) => write!(f, "{e}"),
            Self::Arithmetic(e) => write!(f, "{e}"),
            Self::Posting(e) => write!(f, "{e}"),
            Self::Invalid(why) => write!(f, "invalid allocation review: {why}"),
            Self::Mismatch => write!(f, "allocation review differs from the independently retained digest"),
            Self::TooLarge { maximum, actual } => {
                write!(f, "allocation review length {actual} exceeds {maximum}")
            }
        }
    }
}
impl core::error::Error for AllocationReviewError {}
impl From<DecodeError> for AllocationReviewError {
    fn from(e: DecodeError) -> Self { Self::Decode(e) }
}
impl From<EncodeError> for AllocationReviewError {
    fn from(e: EncodeError) -> Self { Self::Encode(e) }
}
impl From<IntentError> for AllocationReviewError {
    fn from(e: IntentError) -> Self { Self::Intent(e) }
}
impl From<AllocationError> for AllocationReviewError {
    fn from(e: AllocationError) -> Self { Self::Arithmetic(e) }
}
impl From<Refusal> for AllocationReviewError {
    fn from(e: Refusal) -> Self { Self::Posting(e) }
}

/// An exact allocation proposal and its explicit instruction. Fields are
/// private so no target, ciphertext, citation or amount can change after review.
/// The driver is still a claim: import it with truthful provenance separately.
#[derive(Clone, PartialEq, Eq)]
pub struct AllocationReview {
    posting: AllocationPosting,
    intent: PostIntent,
}

// A diagnostic must not inadvertently disclose driver weights or sealed fields.
impl fmt::Debug for AllocationReview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllocationReview")
            .field("law", &self.posting.request.method.law())
            .field("targets", &self.posting.request.targets.len())
            .finish_non_exhaustive()
    }
}

impl AllocationReview {
    /// Build once from an empty-effect Allocation template and an explicit
    /// instruction. The template must already cite the exact driver Workpaper.
    /// No evidence, signature, capability, approval or snapshot is invented.
    pub fn new(posting: AllocationPosting, template: EntryPayload) -> Result<Self, AllocationReviewError> {
        let proposal = posting.proposal(template)?;
        Self::from_proposal(posting, proposal)
    }

    /// Adopt an existing sealed proposal only if the constructor independently
    /// reproduces EVERY field from the given instruction and original metadata.
    /// Same-total changes, extra effects, memos and alternate extensions refuse.
    pub fn from_proposal(posting: AllocationPosting, proposal: EntryPayload) -> Result<Self, AllocationReviewError> {
        let review = Self { posting, intent: PostIntent::new(proposal, Vec::new())? };
        review.canonical_bytes()?;
        Ok(review)
    }

    pub fn proposal(&self) -> &EntryPayload { self.intent.proposal() }
    pub fn posting(&self) -> &AllocationPosting { &self.posting }

    /// Recomputed shares and the full signed rounding transcript, not a claim
    /// that their referenced accounts or evidence have passed kernel admission.
    pub fn outcome(&self) -> Result<AllocationOutcome, AllocationReviewError> {
        self.validate()?;
        Ok(self.posting.request.execute()?)
    }

    /// The digest ApprovalRefs must bind. This is NOT the review digest.
    pub fn proposal_digest(&self) -> Result<[u8; 32], AllocationReviewError> {
        self.validate()?;
        self.proposal().proposal_digest()
            .map_err(|error| AllocationReviewError::Intent(IntentError::Entry(error)))
    }

    fn validate(&self) -> Result<(), AllocationReviewError> {
        if !self.intent.approvals().is_empty() {
            return Err(AllocationReviewError::Invalid("a review carries no approvals"));
        }
        // Reuse the production constructor, not a second interpretation of
        // allocation extension bytes. Keep all metadata and lifecycle fields:
        // the constructor rejects unsupported effects instead of erasing them.
        let mut template = self.proposal().clone();
        template.legs.clear();
        template.unit_totals.clear();
        template.extensions.clear();
        if self.posting.proposal(template)? != *self.proposal() {
            return Err(AllocationReviewError::Invalid("proposal differs from the explicit allocation instruction"));
        }
        Ok(())
    }

    /// Bounded, versioned transport. Both the instruction and sealed intent
    /// are retained and cross-checked; only the intent is handed to the kernel.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AllocationReviewError> {
        self.validate()?;
        let request = self.posting.request.canonical_bytes()?;
        let intent = self.intent.canonical_bytes()?;
        let mut w = Writer::new();
        w.fixed(MAGIC).u16(VERSION).u16(0).u128(self.posting.source.0)
            .u8(match self.posting.source_side { Side::Debit => 0, Side::Credit => 1 })
            .list(&self.posting.dimensions, |w, (dimension, value)| {
                w.u32(*dimension).u128(value.0);
            })
            .bytes(&request).bytes(&intent);
        let bytes = w.finish()?;
        bounded(&bytes)?;
        Ok(bytes)
    }

    /// Parsing establishes internal consistency, never authorship, issuance,
    /// approval or historical accounting validity. All counts and bytes are
    /// bounded; unknown versions, noncanonical data and trailing bytes refuse.
    pub fn decode(bytes: &[u8]) -> Result<Self, AllocationReviewError> {
        bounded(bytes)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<16>("allocation_review.magic")? != *MAGIC
            || r.u16("allocation_review.major")? != VERSION
            || r.u16("allocation_review.minor")? != 0
        {
            return Err(AllocationReviewError::Invalid("unsupported review format"));
        }
        let source = VId(r.u128("allocation_review.source")?);
        let source_side = match r.u8("allocation_review.side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            _ => return Err(AllocationReviewError::Invalid("unknown source side")),
        };
        let dimensions = r.list(MAX_DIMENSIONS_PER_LEG, "allocation_review.dimensions", |r| {
            Ok((r.u32("dimension.id")?, VId(r.u128("dimension.value")?)))
        })?;
        let request = AllocationRequest::decode(r.bytes(MAX_ALLOCATION_REQUEST_BYTES, "allocation_review.request")?)?;
        let intent = PostIntent::decode(r.bytes(MAX_INTENT_BYTES, "allocation_review.intent")?)?;
        r.finish()?;
        let review = Self { posting: AllocationPosting { source, source_side, dimensions, request }, intent };
        if review.canonical_bytes()?.as_slice() != bytes {
            return Err(AllocationReviewError::Invalid("noncanonical review bytes"));
        }
        Ok(review)
    }

    /// Content identity, not a signature or native object-store identifier.
    pub fn digest(&self) -> Result<[u8; 32], AllocationReviewError> {
        Ok(domain_digest(b"fa:allocation-review:v1", &[&self.canonical_bytes()?]))
    }

    /// Bind the artifact to the recipient's independently saved review.
    pub fn verify_for(&self, expected: &[u8; 32]) -> Result<(), AllocationReviewError> {
        if self.digest()? != *expected { return Err(AllocationReviewError::Mismatch); }
        Ok(())
    }
}

fn bounded(bytes: &[u8]) -> Result<(), AllocationReviewError> {
    if bytes.len() > MAX_ALLOCATION_REVIEW_BYTES {
        return Err(AllocationReviewError::TooLarge { maximum: MAX_ALLOCATION_REVIEW_BYTES, actual: bytes.len() });
    }
    Ok(())
}

fn refusal(error: AllocationReviewError) -> Refusal {
    let (code, exit) = if matches!(error, AllocationReviewError::Mismatch) {
        (fa_journal::refusal::code::PLAN_INVALIDATED, exit::CONFLICT)
    } else {
        (fa_journal::refusal::code::STRUCTURE, exit::USAGE)
    };
    Refusal::new(code, exit, error.to_string(), "fa:allocation-review:v1; plan §6.3 / §10.4 / §14.3",
        "use the unchanged saved review and independently retained digest; review any changed instruction before obtaining new approvals")
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Rehearse the exact reviewed allocation with separately obtained approvals.
    /// Approvals may have advanced HEAD; no old plan is refreshed or re-signed.
    /// The explicit total, driver, order, side, dimensions and sealed proposal
    /// remain identical while the real kernel evaluates CURRENT financial law.
    /// A review alone never establishes that the driver document was imported.
    ///
    /// No journal write occurs. Persist the returned native PostPlan BEFORE
    /// commit_plan, and retry that plan after an ambiguous publication outcome.
    pub fn plan_allocation_review(
        &mut self,
        cx: &PurposeContexts,
        review: &AllocationReview,
        expected_review_digest: [u8; 32],
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<PostPlan> {
        cx.txn().checkpoint().map_err(BookError::Context)?;
        let intent = match reviewed_intent(self.context().book_id, review, expected_review_digest, approvals, capability) {
            Ok(intent) => intent,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.plan(cx, intent, capability)
    }
}

// The synchronous and async adapters share this exact payload-only guard.
fn reviewed_intent(
    book: Id128,
    review: &AllocationReview,
    expected: [u8; 32],
    approvals: Vec<ApprovalRef>,
    capability: &Capability,
) -> Result<PostIntent, Refusal> {
    let explicit: Vec<_> = review.proposal().legs.iter()
        .map(|leg| (leg.amount.unit, leg.amount.mantissa)).collect();
    fa_policy::admit(capability, &fa_policy::Intent {
        principal: review.proposal().principal_ref, trunk: true, op: Op::Post,
        book, legs: &explicit,
    }).map_err(|denial| fa_journal::policy::refusal(&denial))?;
    review.verify_for(&expected).map_err(refusal)?;
    PostIntent::new(review.proposal().clone(), approvals)
        .map_err(|error| refusal(error.into()))
}

impl Book {
    /// Synchronous counterpart of AsyncBook::plan_allocation_review. Reuse the
    /// same guard and this Book's existing native planning/runtime adapter.
    /// Preserve the resulting PostPlan before calling Book::commit_plan.
    pub fn plan_allocation_review(
        &mut self,
        review: &AllocationReview,
        expected_review_digest: [u8; 32],
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<PostPlan> {
        let intent = match reviewed_intent(self.context().book_id, review, expected_review_digest, approvals, capability) {
            Ok(intent) => intent,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.plan(intent, capability)
    }
}

mod approval;

#[cfg(test)]
mod tests;
