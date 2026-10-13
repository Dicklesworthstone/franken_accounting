//! Portable reviews for all applications in ONE accounting entry.
//!
//! These unsigned request artifacts retain one complete sealed proposal and
//! every allocation witness. They are not approvals, historical certificates,
//! reservations, or authenticated posting plans. Establish provenance using an
//! independently retained digest; decoding alone only checks consistency.
//! Approvers approve proposal().proposal_digest(), NOT this artifact's digest.
//! After attempting publication, retry the saved PostPlan, never this review.

use std::collections::BTreeSet;

use fa_intents::PostIntent;
use fa_model::limits::{MAX_ENTRY_BYTES, MAX_SETTLES_PER_LEG};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, Reader, Writer};
use fa_registers::open_items::{SettlementAllocation, SettlementPlan, SettlementRequest};
use fgdb_types::{CommitSeq, VId};

use crate::settlement_group::{
    MAX_SETTLEMENT_GROUP_LEGS, MAX_SETTLEMENT_GROUP_TARGETS, PreparedSettlementGroup,
    SettlementGroupRequest, SettlementLegAllocation, SettlementLegSelection,
};
use crate::SettlementReviewError;

const MAGIC: &[u8; 27] = b"FA-SETTLEMENT-GROUP-REVIEW\0";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
/// One bounded entry, 18 bytes per eligible target, 66 per application and
/// bounded per-leg framing. Text transports must bound their expansion too.
pub const MAX_SETTLEMENT_GROUP_REVIEW_BYTES: usize =
    MAX_ENTRY_BYTES + 128 * MAX_SETTLEMENT_GROUP_TARGETS + 4096;

fn invalid(message: &'static str) -> SettlementReviewError {
    SettlementReviewError::Invalid(message)
}

fn bounded(bytes: &[u8]) -> Result<(), SettlementReviewError> {
    if bytes.len() > MAX_SETTLEMENT_GROUP_REVIEW_BYTES {
        return Err(SettlementReviewError::TooLarge {
            max: MAX_SETTLEMENT_GROUP_REVIEW_BYTES, actual: bytes.len(),
        });
    }
    Ok(())
}

/// An unsigned, bounded review; private fields are not a posting permission.
/// Unused eligible targets are retained, but their unobserved balances are not
/// historical claims. The full digests of applied targets remain in the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementGroupReview {
    intent: PostIntent,
    known_at: CommitSeq,
    allocations: Vec<SettlementLegAllocation>,
}

impl PreparedSettlementGroup {
    /// Preserve the complete reviewed entry across process boundaries without
    /// resealing its text, changing its identity, or minting an approval.
    pub fn export_review(&self) -> Result<SettlementGroupReview, SettlementReviewError> {
        let review = SettlementGroupReview {
            intent: PostIntent::new(self.proposal().clone(), Vec::new())?,
            known_at: self.known_at(),
            allocations: self.allocations().to_vec(),
        };
        review.canonical_bytes()?;
        Ok(review)
    }
}

impl SettlementGroupReview {
    /// The complete sealed entry whose proposal digest the approvers approve.
    #[must_use]
    pub fn proposal(&self) -> &EntryPayload { self.intent.proposal() }

    /// Claimed old coordinate, not authenticated by this transport envelope.
    #[must_use]
    pub fn known_at(&self) -> CommitSeq { self.known_at }

    /// Per-leg witnesses in ascending applying-leg order; allocation order
    /// within a leg remains the preparer's FIFO order, not identity order.
    #[must_use]
    pub fn allocations(&self) -> &[SettlementLegAllocation] { &self.allocations }

    fn validate(&self) -> Result<(), SettlementReviewError> {
        let proposal = self.proposal();
        if !self.intent.approvals().is_empty()
            || !matches!(proposal.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING)
            || !matches!(&proposal.origin, EntryOrigin::Intent { .. })
        {
            return Err(invalid("group review must be an unapproved Original or Adjusting Intent"));
        }
        if self.allocations.is_empty() || self.allocations.len() > MAX_SETTLEMENT_GROUP_LEGS
            || !self.allocations.windows(2).all(|p| p[0].payment_leg < p[1].payment_leg)
        {
            return Err(invalid("group applying legs must be bounded, nonempty and strictly ascending"));
        }
        let mut selected = BTreeSet::new();
        let mut eligible = BTreeSet::new();
        let mut count = 0_usize;
        for part in &self.allocations {
            selected.insert(usize::from(part.payment_leg));
            let leg = proposal.legs.get(usize::from(part.payment_leg))
                .ok_or_else(|| invalid("group applying leg is missing"))?;
            let allocation = &part.allocation;
            let request = &allocation.request;
            if allocation.known_at != self.known_at || leg.amount.mantissa <= 0
                || request.account != leg.account_ref || request.unit_id != leg.amount.unit.0
                || request.side != leg.side || request.amount != leg.amount.mantissa
                || request.effective_date != proposal.effective_date
            {
                return Err(invalid("group request differs from its applying leg or common basis"));
            }
            if request.targets.is_empty() || request.targets.len() > MAX_SETTLES_PER_LEG
                || !request.targets.windows(2).all(|p| p[0] < p[1])
            {
                return Err(invalid("group targets must be bounded, nonempty and strictly ascending"));
            }
            count = count.checked_add(request.targets.len())
                .filter(|n| *n <= MAX_SETTLEMENT_GROUP_TARGETS)
                .ok_or_else(|| invalid("group exceeds the aggregate eligible-target bound"))?;
            for target in &request.targets {
                if !eligible.insert(*target) {
                    return Err(invalid("group target sets overlap, including unused targets"));
                }
            }
            let applications = &allocation.allocations;
            if applications.is_empty() || applications.len() > MAX_SETTLES_PER_LEG
                || applications.len() != leg.settles.len()
            {
                return Err(invalid("group allocations differ from the nonempty applying list"));
            }
            let mut seen = BTreeSet::new();
            let mut total = 0_i128;
            for (application, link) in applications.iter().zip(&leg.settles) {
                let target = (application.entry, application.ordinal);
                if !seen.insert(target) || request.targets.binary_search(&target).is_err()
                    || target != (link.target.vid, link.ordinal)
                    || link.amount.unit != leg.amount.unit
                    || application.amount != link.amount.mantissa || application.amount <= 0
                    || application.open_before < application.amount
                    || application.open_before.checked_sub(application.amount) != Some(application.open_after)
                {
                    return Err(invalid("group allocation identity, unit or open-amount mismatch"));
                }
                total = total.checked_add(application.amount)
                    .ok_or_else(|| invalid("group allocation sum overflow"))?;
            }
            if total > request.amount || request.amount.checked_sub(total) != Some(allocation.unapplied) {
                return Err(invalid("group unapplied amount does not conserve its payment"));
            }
        }
        if proposal.legs.iter().enumerate().any(|(i, leg)| {
            !selected.contains(&i) && !leg.settles.is_empty()
        }) {
            return Err(invalid("group contains applications on an unreviewed leg"));
        }
        Ok(())
    }

    /// Canonical versioned bytes. The full combined intent occurs exactly once;
    /// per-leg request fields already present in that entry are not duplicated.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SettlementReviewError> {
        self.validate()?;
        let intent = self.intent.canonical_bytes()?;
        let mut w = Writer::new();
        w.fixed(MAGIC).u16(MAJOR).u16(MINOR).u64(self.known_at.0).bytes(&intent)
            .list(&self.allocations, |w, part| {
                w.u16(part.payment_leg)
                    .list(&part.allocation.request.targets, |w, (entry, ordinal)| {
                        w.u128(entry.0).u16(*ordinal);
                    })
                    .list(&part.allocation.allocations, |w, application| {
                        w.u128(application.entry.0).u16(application.ordinal)
                            .i128(application.amount).i128(application.open_before)
                            .i128(application.open_after);
                    })
                    .i128(part.allocation.unapplied);
            });
        let bytes = w.finish()?;
        bounded(&bytes)?;
        Ok(bytes)
    }

    /// Decode untrusted bytes, checking bounds before allocation. Unknown
    /// versions, approvals, noncanonical order, inconsistencies and trailing
    /// bytes fail closed. This does not authenticate the claimed old history.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementReviewError> {
        bounded(bytes)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<27>("group.magic")? != *MAGIC
            || r.u16("group.major")? != MAJOR || r.u16("group.minor")? != MINOR
        {
            return Err(invalid("unsupported group review framing or version"));
        }
        let known_at = CommitSeq(r.u64("group.known_at")?);
        let intent = PostIntent::decode(r.bytes(MAX_SETTLEMENT_GROUP_REVIEW_BYTES, "group.intent")?)?;
        // Reject authority-bearing transport before allocating annotation lists.
        if !intent.approvals().is_empty() {
            return Err(invalid("group review must not carry approvals"));
        }
        let mut count = 0_usize;
        let allocations = r.list(MAX_SETTLEMENT_GROUP_LEGS, "group.legs", |r| {
            let payment_leg = r.u16("group.payment_leg")?;
            let targets = r.list(
                MAX_SETTLES_PER_LEG.min(MAX_SETTLEMENT_GROUP_TARGETS - count),
                "group.targets", |r| {
                    Ok((VId(r.u128("target.entry")?), r.u16("target.ordinal")?))
                },
            )?;
            count += targets.len();
            let applications = r.list(targets.len(), "group.allocations", |r| {
                Ok(SettlementAllocation {
                    entry: VId(r.u128("allocation.entry")?),
                    ordinal: r.u16("allocation.ordinal")?,
                    amount: r.i128("allocation.amount")?,
                    open_before: r.i128("allocation.open_before")?,
                    open_after: r.i128("allocation.open_after")?,
                })
            })?;
            let unapplied = r.i128("group.unapplied")?;
            // Structural ordinal validation follows with a typed review error.
            // No allocation depends on an attacker-supplied ordinal.
            let leg = intent.proposal().legs.get(usize::from(payment_leg));
            let request = SettlementRequest {
                account: leg.map_or(VId(0), |l| l.account_ref),
                unit_id: leg.map_or(0, |l| l.amount.unit.0),
                side: leg.map_or(fa_money::Side::Debit, |l| l.side),
                amount: leg.map_or(0, |l| l.amount.mantissa),
                effective_date: intent.proposal().effective_date, targets,
            };
            Ok(SettlementLegAllocation {
                payment_leg,
                allocation: SettlementPlan { known_at, request, allocations: applications, unapplied },
            })
        })?;
        r.finish()?;
        let review = Self { intent, known_at, allocations };
        review.validate()?;
        Ok(review)
    }

    /// Content identity to compare against an independently saved review.
    /// This is neither an approval digest nor a signature or native ObjectId.
    pub fn digest(&self) -> Result<[u8; 32], SettlementReviewError> {
        Ok(fa_model::domain_digest(b"fa:settlement-group-review:v1", &[&self.canonical_bytes()?]))
    }

    /// Restore exactly the original empty-settles request. This request is not
    /// authority to post: use explicit live revalidation, not convenience
    /// replanning that could silently change the saved allocation witnesses.
    fn request(&self) -> Result<SettlementGroupRequest, SettlementReviewError> {
        self.validate()?;
        let mut proposal = self.proposal().clone();
        let mut payments = Vec::with_capacity(self.allocations.len());
        for part in &self.allocations {
            proposal.legs[usize::from(part.payment_leg)].settles.clear();
            payments.push(SettlementLegSelection {
                payment_leg: part.payment_leg, targets: part.allocation.request.targets.clone(),
            });
        }
        Ok(SettlementGroupRequest { proposal, payments })
    }
}

mod resume;

#[cfg(test)]
mod tests;
