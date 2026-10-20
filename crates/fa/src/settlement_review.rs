//! Portable settlement reviews and explicit approval-time revalidation.
//!
//! A review retains the exact sealed proposal, every eligible target, and the
//! observed allocation amounts. It is an UNSIGNED request artifact, not a plan
//! certificate, approval, authorization, or proof of its claimed historical
//! snapshot. Decoding checks framing and internal consistency only. Callers
//! must establish the artifact's provenance (for example, compare its digest
//! with the review they saved) before treating it as someone else's judgment.
//!
//! Recording approvals necessarily advances HEAD. The explicit refresh path
//! therefore recomputes the complete request under current authority, accepting
//! a new basis ONLY when the sealed proposal and all allocation witnesses are
//! unchanged. It never silently substitutes a different payment. The ordinary
//! kernel then checks approvals and issues the existing authenticated PostPlan.
//! After attempting publication, retry that PostPlan, not this review.

use core::fmt;
use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_intents::{IntentError, PostIntent};
use fa_journal::{Refusal, exit};
use fa_model::limits::{MAX_ENTRY_BYTES, MAX_SETTLES_PER_LEG};
use fa_model::{ApprovalRef, DecodeError, EncodeError, EntryClass, EntryPayload, Reader, Writer};
use fa_policy::Capability;
use fa_registers::open_items::{SettlementAllocation, SettlementPlan, SettlementRequest};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, Outcome, PreparedSettlement, SettlementPostPlan, SettlementPostRequest};

const MAGIC: &[u8; 21] = b"FA-SETTLEMENT-REVIEW\0";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
// PostIntent's framing is small beside one bounded Entry. Each target uses
// 18 bytes and each allocation 66; the remaining allowance covers framing.
/// Binary transport bound derived from the existing Entry and settlement limits.
/// Hex or other transport encodings must enforce their own expansion bound.
pub const MAX_SETTLEMENT_REVIEW_BYTES: usize = MAX_ENTRY_BYTES + 128 * MAX_SETTLES_PER_LEG + 4096;

#[derive(Debug)]
pub enum SettlementReviewError {
    Decode(DecodeError),
    Encode(EncodeError),
    Intent(IntentError),
    Invalid(&'static str),
    TooLarge { max: usize, actual: usize },
}

impl fmt::Display for SettlementReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Intent(e) => write!(f, "{e}"),
            Self::Invalid(what) => write!(f, "invalid settlement review: {what}"),
            Self::TooLarge { max, actual } => {
                write!(f, "settlement review length {actual} exceeds bound {max}")
            }
        }
    }
}
impl core::error::Error for SettlementReviewError {}
impl From<DecodeError> for SettlementReviewError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<EncodeError> for SettlementReviewError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}
impl From<IntentError> for SettlementReviewError {
    fn from(e: IntentError) -> Self {
        Self::Intent(e)
    }
}

fn invalid(what: &'static str) -> SettlementReviewError {
    SettlementReviewError::Invalid(what)
}
fn bounded(bytes: &[u8]) -> Result<(), SettlementReviewError> {
    if bytes.len() > MAX_SETTLEMENT_REVIEW_BYTES {
        return Err(SettlementReviewError::TooLarge {
            max: MAX_SETTLEMENT_REVIEW_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Unsigned, internally checked review bytes. No capability or approval is
/// carried here. The proposal's full target digests and sealed fields survive
/// process boundaries without resealing plaintext. The claimed old snapshot
/// and before/after amounts become usable only after current revalidation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementReview {
    intent: PostIntent,
    allocation: SettlementPlan,
    payment_leg: u16,
}

impl PreparedSettlement {
    /// Export this preparation for review and approval in another process.
    /// This does not rehearse the kernel or publish a journal object.
    pub fn export_review(&self) -> Result<SettlementReview, SettlementReviewError> {
        let mut applying = self
            .proposal()
            .legs
            .iter()
            .enumerate()
            .filter(|(_, leg)| !leg.settles.is_empty());
        let (ordinal, _) = applying.next().ok_or_else(|| invalid("no applying leg"))?;
        if applying.next().is_some() {
            return Err(invalid("more than one applying leg"));
        }
        let review = SettlementReview {
            intent: PostIntent::new(self.proposal().clone(), Vec::new())?,
            allocation: self.allocation().clone(),
            payment_leg: u16::try_from(ordinal)
                .map_err(|_| invalid("applying ordinal overflow"))?,
        };
        // Includes Entry's own encoded-size bound, not just the vector counts.
        review.canonical_bytes()?;
        Ok(review)
    }
}

impl SettlementReview {
    /// The exact sealed proposal an approval must bind, NOT a posting permit.
    #[must_use]
    pub fn proposal(&self) -> &EntryPayload {
        self.intent.proposal()
    }

    /// Claimed review-time observations; decoding does not authenticate them.
    #[must_use]
    pub fn allocation(&self) -> &SettlementPlan {
        &self.allocation
    }

    #[must_use]
    pub fn payment_leg(&self) -> u16 {
        self.payment_leg
    }

    fn validate(&self) -> Result<(), SettlementReviewError> {
        let proposal = self.proposal();
        if !self.intent.approvals().is_empty()
            || !matches!(proposal.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING)
        {
            return Err(invalid(
                "a review is an unapproved Original or Adjusting intent",
            ));
        }
        let leg = proposal
            .legs
            .get(usize::from(self.payment_leg))
            .ok_or_else(|| invalid("applying leg is missing"))?;
        if proposal
            .legs
            .iter()
            .enumerate()
            .any(|(i, l)| i != usize::from(self.payment_leg) && !l.settles.is_empty())
        {
            return Err(invalid("applications on a different leg"));
        }
        let request = &self.allocation.request;
        if leg.amount.mantissa <= 0
            || request.account != leg.account_ref
            || request.unit_id != leg.amount.unit.0
            || request.side != leg.side
            || request.amount != leg.amount.mantissa
            || request.effective_date != proposal.effective_date
        {
            return Err(invalid("allocation request differs from the applying leg"));
        }
        if request.targets.is_empty()
            || request.targets.len() > MAX_SETTLES_PER_LEG
            || !request.targets.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(invalid(
                "targets must be bounded, nonempty and strictly ascending",
            ));
        }
        let parts = &self.allocation.allocations;
        if parts.is_empty() || parts.len() > MAX_SETTLES_PER_LEG || parts.len() != leg.settles.len()
        {
            return Err(invalid("allocations must match the nonempty applying list"));
        }
        let mut seen = BTreeSet::new();
        let mut total = 0_i128;
        for (part, link) in parts.iter().zip(&leg.settles) {
            let target = (part.entry, part.ordinal);
            if !seen.insert(target)
                || request.targets.binary_search(&target).is_err()
                || target != (link.target.vid, link.ordinal)
                || link.amount.unit != leg.amount.unit
                || part.amount != link.amount.mantissa
                || part.amount <= 0
                || part.open_before < part.amount
                || part.open_before.checked_sub(part.amount) != Some(part.open_after)
            {
                return Err(invalid(
                    "allocation/link identity, unit or open-amount mismatch",
                ));
            }
            total = total
                .checked_add(part.amount)
                .ok_or_else(|| invalid("allocation sum overflow"))?;
        }
        if total > request.amount
            || request.amount.checked_sub(total) != Some(self.allocation.unapplied)
        {
            return Err(invalid("unapplied amount does not conserve the payment"));
        }
        Ok(())
    }

    /// Versioned deterministic bytes, including unused eligible targets and
    /// exact allocation order. No serialization choice changes the proposal.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SettlementReviewError> {
        self.validate()?;
        let intent = self.intent.canonical_bytes()?;
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(MAJOR)
            .u16(MINOR)
            .u64(self.allocation.known_at.0)
            .u16(self.payment_leg)
            .bytes(&intent)
            .list(&self.allocation.request.targets, |w, (entry, ordinal)| {
                w.u128(entry.0).u16(*ordinal);
            })
            .list(&self.allocation.allocations, |w, part| {
                w.u128(part.entry.0)
                    .u16(part.ordinal)
                    .i128(part.amount)
                    .i128(part.open_before)
                    .i128(part.open_after);
            })
            .i128(self.allocation.unapplied);
        let bytes = w.finish()?;
        bounded(&bytes)?;
        Ok(bytes)
    }

    /// Decode untrusted transport. This is structural validation, not proof
    /// that the source book ever had these open amounts at the claimed sequence.
    /// Unknown versions, trailing bytes and unbounded lists fail closed.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementReviewError> {
        bounded(bytes)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<21>("review.magic")? != *MAGIC {
            return Err(invalid("wrong magic"));
        }
        if r.u16("review.major")? != MAJOR || r.u16("review.minor")? != MINOR {
            return Err(invalid("unsupported version"));
        }
        let known_at = CommitSeq(r.u64("review.known_at")?);
        let payment_leg = r.u16("review.payment_leg")?;
        let intent = PostIntent::decode(r.bytes(MAX_SETTLEMENT_REVIEW_BYTES, "review.intent")?)?;
        let targets = r.list(MAX_SETTLES_PER_LEG, "review.targets", |r| {
            Ok((VId(r.u128("target.entry")?), r.u16("target.ordinal")?))
        })?;
        let allocations = r.list(MAX_SETTLES_PER_LEG, "review.allocations", |r| {
            Ok(SettlementAllocation {
                entry: VId(r.u128("allocation.entry")?),
                ordinal: r.u16("allocation.ordinal")?,
                amount: r.i128("allocation.amount")?,
                open_before: r.i128("allocation.open_before")?,
                open_after: r.i128("allocation.open_after")?,
            })
        })?;
        let unapplied = r.i128("review.unapplied")?;
        r.finish()?;
        let proposal = intent.proposal();
        let leg = proposal
            .legs
            .get(usize::from(payment_leg))
            .ok_or_else(|| invalid("applying leg is missing"))?;
        let request = SettlementRequest {
            account: leg.account_ref,
            unit_id: leg.amount.unit.0,
            side: leg.side,
            amount: leg.amount.mantissa,
            effective_date: proposal.effective_date,
            targets,
        };
        let review = Self {
            intent,
            payment_leg,
            allocation: SettlementPlan {
                known_at,
                request,
                allocations,
                unapplied,
            },
        };
        review.validate()?;
        Ok(review)
    }

    /// Content identity for an independently saved review, not a signature,
    /// native ObjectId or ApprovalRef. Compare with a separately trusted digest.
    pub fn digest(&self) -> Result<[u8; 32], SettlementReviewError> {
        Ok(fa_model::domain_digest(
            b"fa:settlement-review:v1",
            &[&self.canonical_bytes()?],
        ))
    }

    fn request(&self) -> Result<SettlementPostRequest, SettlementReviewError> {
        self.validate()?;
        let mut proposal = self.proposal().clone();
        proposal.legs[usize::from(self.payment_leg)].settles.clear();
        Ok(SettlementPostRequest {
            proposal,
            payment_leg: self.payment_leg,
            targets: self.allocation.request.targets.clone(),
        })
    }
}

fn changed() -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED,
        exit::CONFLICT,
        "the current settlement no longer matches the saved review",
        "plan §5.7 / §10.4 / §14.3 (exact reviewed proposal and current approval applicability)",
        "review a fresh settlement and obtain any newly required approvals; after an attempted commit retry its original PostPlan instead",
    )
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Explicitly revalidate a saved review after approval publications or a
    /// process restart. Current read/post scope, expiry and revocation checks
    /// precede target observation in prepare_settlement. No journal write occurs.
    ///
    /// ONLY the known-at coordinate may advance. Every proposal byte (including
    /// full target digests, sealed text, offsets and amounts), eligible target,
    /// allocation order, before/after amount and unapplied amount must match.
    /// Even a competing payment that leaves enough capacity requires new review.
    /// This does not authenticate the claimed OLD snapshot or the review author.
    pub async fn refresh_settlement_review(
        &mut self,
        cx: &PurposeContexts,
        review: &SettlementReview,
        capability: &Capability,
    ) -> Outcome<PreparedSettlement> {
        let request = match review.request() {
            Ok(request) => request,
            Err(error) => {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::STRUCTURE,
                    exit::USAGE,
                    error.to_string(),
                    "fa:settlement-review:v1 (bounded canonical request)",
                    "load an unchanged review exported from settlement preparation",
                )));
            }
        };
        let prepared = match self.prepare_settlement(cx, request, capability).await? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut expected = review.allocation.clone();
        expected.known_at = prepared.allocation().known_at;
        if prepared.allocation().known_at < review.allocation.known_at
            || prepared.proposal() != review.proposal()
            || prepared.allocation() != &expected
        {
            return Ok(Err(changed()));
        }
        Ok(Ok(prepared))
    }

    /// Revalidate a saved review, then run the real kernel with separately
    /// supplied approvals. They must bind review.proposal().proposal_digest(),
    /// not review.digest(). The kernel checks SoD, approval existence/binding,
    /// current policy and every accounting law. No approval is minted here.
    ///
    /// Preserve the returned PostPlan before publication. The strict original
    /// plan_prepared_settlement API and exact commit retry contract are unchanged.
    pub async fn plan_settlement_review(
        &mut self,
        cx: &PurposeContexts,
        review: &SettlementReview,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<SettlementPostPlan> {
        let prepared = match self
            .refresh_settlement_review(cx, review, capability)
            .await?
        {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.plan_prepared_settlement(cx, prepared, approvals, capability)
            .await
    }
}

mod approval;

#[cfg(test)]
mod tests;
