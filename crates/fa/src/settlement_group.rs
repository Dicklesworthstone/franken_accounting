//! Prepare several explicit applications in ONE accounting entry (plan §5.7).
//!
//! Each applying leg has its own eligible targets, native unit and dimensions.
//! Target sets must be disjoint, including unused targets: independent advice
//! must never reserve the same open amount twice. This is not a multi-entry
//! batch, implicit party matching, currency conversion or a balancing rule.
//! The existing single-leg preparer resolves each selection at the same basis;
//! the ordinary posting kernel judges the complete combined entry atomically.

mod review;

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_intents::{PostIntent, PostPlan};
use fa_journal::{Posted, Refusal, exit};
use fa_model::limits::{MAX_LEGS_PER_ENTRY, MAX_SETTLES_PER_LEG};
use fa_model::{ApprovalRef, EntryClass, EntryOrigin, EntryPayload, Id128};
use fa_policy::Capability;
use fa_registers::open_items::SettlementPlan;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome, SettlementPostRequest};

/// Facade work bound, not a change to the model's posting-arity law. Every
/// selection refolds the authoritative report; refuse rather than truncate.
pub const MAX_SETTLEMENT_GROUP_LEGS: usize = 64;
/// Aggregate eligible targets, including those receiving zero allocation.
/// Each applying leg also retains the model's MAX_SETTLES_PER_LEG bound.
pub const MAX_SETTLEMENT_GROUP_TARGETS: usize = 4096;

/// One applying leg and its explicit, same-account/unit/dimension targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementLegSelection {
    pub payment_leg: u16,
    pub targets: Vec<(VId, u16)>,
}

/// A caller-authored complete payment; every settles list starts empty.
/// Cash offsets, valuations and all balancing effects remain explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementGroupRequest {
    pub proposal: EntryPayload,
    pub payments: Vec<SettlementLegSelection>,
}

/// The allocation explanation belonging to one applying leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementLegAllocation {
    pub payment_leg: u16,
    pub allocation: SettlementPlan,
}

/// Exact in-memory review, NOT an authorization or posting certificate.
/// Private fields prevent pairing one proposal with another allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSettlementGroup {
    request: SettlementGroupRequest,
    proposal: EntryPayload,
    allocations: Vec<SettlementLegAllocation>,
    known_at: CommitSeq,
}

impl PreparedSettlementGroup {
    /// The complete proposal whose digest the approvers must approve, never
    /// the intermediate single-leg proposals used internally for preparation.
    #[must_use]
    pub fn proposal(&self) -> &EntryPayload { &self.proposal }

    /// All applying legs in ascending ordinal order, at the same known-at.
    #[must_use]
    pub fn allocations(&self) -> &[SettlementLegAllocation] { &self.allocations }

    #[must_use]
    pub fn known_at(&self) -> CommitSeq { self.known_at }

    /// Canonically ordered original inputs, including every unused target.
    #[must_use]
    pub fn request(&self) -> &SettlementGroupRequest { &self.request }

    #[must_use]
    pub fn into_proposal(self) -> EntryPayload { self.proposal }
}

/// One real kernel plan with all of its per-leg allocation explanations.
/// The ordinary PostPlan is the portable, authenticated execution artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementGroupPostPlan {
    allocations: Vec<SettlementLegAllocation>,
    post: PostPlan,
}

impl SettlementGroupPostPlan {
    #[must_use]
    pub fn allocations(&self) -> &[SettlementLegAllocation] { &self.allocations }

    #[must_use]
    pub fn post_plan(&self) -> &PostPlan { &self.post }

    /// Persist these ordinary PostPlan bytes BEFORE publication. A different
    /// process can decode them and retry AsyncBook::commit_plan unchanged.
    #[must_use]
    pub fn into_post_plan(self) -> PostPlan { self.post }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE, exit::USAGE, message,
        "plan §5.7 (explicit applications in one atomic entry)",
        "supply an Original or Adjusting Intent with empty settles lists, positive applying legs, and disjoint explicit target sets; never split one target across selections",
    )
}

fn invalidated(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED, exit::CONFLICT, message,
        "plan §5.1 / §10.4 (the complete reviewed payment and basis are exact)",
        "review a fresh group; after an uncertain acknowledgement retry the original authenticated PostPlan without preparing or reallocating again",
    )
}

/// Bound all caller-controlled counts before copying the proposal or targets.
fn normalize(mut request: SettlementGroupRequest) -> Result<SettlementGroupRequest, Refusal> {
    let proposal = &request.proposal;
    if request.payments.is_empty() || request.payments.len() > MAX_SETTLEMENT_GROUP_LEGS
        || proposal.legs.len() > MAX_LEGS_PER_ENTRY
    {
        return Err(invalid("settlement group has no selections or exceeds the leg work bound"));
    }
    if !matches!(proposal.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING)
        || !matches!(&proposal.origin, EntryOrigin::Intent { .. })
        || proposal.legs.iter().any(|leg| !leg.settles.is_empty())
    {
        return Err(invalid("group preparation never overwrites applications or invents rule provenance"));
    }
    let mut count = 0_usize;
    for selection in &request.payments {
        if selection.targets.is_empty() || selection.targets.len() > MAX_SETTLES_PER_LEG {
            return Err(invalid("every selection needs a nonempty, model-bounded target set"));
        }
        count = count.checked_add(selection.targets.len())
            .filter(|n| *n <= MAX_SETTLEMENT_GROUP_TARGETS)
            .ok_or_else(|| invalid("settlement group exceeds its aggregate target work bound"))?;
        let leg = proposal.legs.get(usize::from(selection.payment_leg))
            .ok_or_else(|| invalid("an applying ordinal is outside the complete proposal"))?;
        if leg.amount.mantissa <= 0 {
            return Err(invalid("every applying leg must have a positive amount"));
        }
    }
    // Model validation checks shape and field bounds, not economic balance,
    // evidence sufficiency, period state or authority. The kernel judges those.
    proposal.validate().map_err(|error| invalid(error.to_string()))?;
    let mut ordinals = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for selection in &mut request.payments {
        if !ordinals.insert(selection.payment_leg) {
            return Err(invalid("an applying leg occurs more than once"));
        }
        for target in &selection.targets {
            if !targets.insert(*target) {
                return Err(invalid("eligible target sets overlap or contain a duplicate, even if unused"));
            }
        }
        selection.targets.sort_unstable();
    }
    request.payments.sort_by_key(|selection| selection.payment_leg);
    Ok(request)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Prepare all selected legs without writing. Every selection validates
    /// every target, including exhausted/unused targets, through the existing
    /// authoritative preparer. A failure returns no partial preparation.
    /// Permissions cover the FULL entry, not only each selected leg's amount.
    pub fn prepare_settlement_group(
        &self,
        cx: &PurposeContexts,
        request: SettlementGroupRequest,
        capability: &Capability,
    ) -> Outcome<PreparedSettlementGroup> {
        let book = self.context();
        if let Err(denial) = fa_policy::admit_read(
            capability, request.proposal.principal_ref, book.book_id,
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        if request.proposal.book_id != book.book_id || request.proposal.branch_id != Id128::TRUNK {
            return Ok(Err(invalid("the group must name this book's writable trunk")));
        }
        let request = match normalize(request) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut proposal = request.proposal.clone();
        let mut allocations = Vec::with_capacity(request.payments.len());
        let mut known_at = None;
        for selection in &request.payments {
            query.checkpoint().map_err(BookError::Context)?;
            // Always start from the same EMPTY-settles original, never a
            // partly modified entry. No intermediate proposal is published.
            let part = match self.prepare_settlement(cx, SettlementPostRequest {
                proposal: request.proposal.clone(),
                payment_leg: selection.payment_leg,
                targets: selection.targets.clone(),
            }, capability)? {
                Ok(part) => part,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let at = part.allocation().known_at;
            if known_at.is_some_and(|basis| basis != at) {
                return Ok(Err(invalidated("the group selections observed different book sequences")));
            }
            known_at = Some(at);
            let ordinal = usize::from(selection.payment_leg);
            proposal.legs[ordinal].settles = part.proposal().legs[ordinal].settles.clone();
            allocations.push(SettlementLegAllocation {
                payment_leg: selection.payment_leg, allocation: part.allocation().clone(),
            });
        }
        if let Err(error) = proposal.validate() {
            return Ok(Err(invalid(error.to_string())));
        }
        let Some(known_at) = known_at else {
            return Ok(Err(invalid("no settlement selection was prepared")));
        };
        query.checkpoint().map_err(BookError::Context)?;
        Ok(Ok(PreparedSettlementGroup { request, proposal, allocations, known_at }))
    }

    /// Convenience preparation plus rehearsal. Supplied approvals must bind
    /// the complete combined proposal. Review the returned plan before commit.
    pub fn plan_settlement_group(
        &mut self,
        cx: &PurposeContexts,
        request: SettlementGroupRequest,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<SettlementGroupPostPlan> {
        let prepared = match self.prepare_settlement_group(cx, request, capability)? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.plan_prepared_settlement_group(cx, prepared, approvals, capability)
    }

    /// Rehearse the exact in-memory review, without silently reallocating.
    /// An intervening publication invalidates its basis. All selections share
    /// one ordinary kernel transaction, one idempotency key and one certificate.
    pub fn plan_prepared_settlement_group(
        &mut self,
        cx: &PurposeContexts,
        prepared: PreparedSettlementGroup,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<SettlementGroupPostPlan> {
        let book = self.context();
        if let Err(denial) = fa_policy::admit_read(
            capability, prepared.proposal.principal_ref, book.book_id,
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if prepared.proposal.book_id != book.book_id || prepared.proposal.branch_id != Id128::TRUNK {
            return Ok(Err(invalid("the reviewed group belongs to another book or branch")));
        }
        let intent = match PostIntent::new(prepared.proposal, approvals) {
            Ok(intent) => intent,
            Err(error) => return Ok(Err(invalid(error.to_string()))),
        };
        let post = match self.plan(cx, intent, capability)? {
            Ok(post) => post,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if post.certificate().snapshot_seq != prepared.known_at {
            return Ok(Err(invalidated("the reviewed group basis changed before kernel rehearsal")));
        }
        if post.proposal().legs != post.intent().proposal().legs {
            return Ok(Err(invalidated("kernel rehearsal changed the reviewed group legs")));
        }
        Ok(Ok(SettlementGroupPostPlan { allocations: prepared.allocations, post }))
    }

    /// Publish every application as ONE entry or none. Exact retries use the
    /// recorded PostPlan before stale-basis checks, under current authority.
    pub async fn commit_settlement_group_plan(
        &mut self,
        cx: &PurposeContexts,
        plan: SettlementGroupPostPlan,
        capability: &Capability,
    ) -> Outcome<Posted> {
        self.commit_plan(cx, plan.post, capability).await
    }
}

#[cfg(test)]
mod tests;
