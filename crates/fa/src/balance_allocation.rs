//! Allocate an exact, journal-derived period balance (plan §5.3 / §6.3).
//!
//! The selector is one leaf, native unit, period and EXACT dimension set.
//! Only visible posted contributions count, never reservations or a stored
//! register cache. Positive debit balances produce a credit at the source;
//! credit balances produce a debit. This is not an available-cash calculation,
//! an FX conversion, or an assertion that the destination posting period is
//! the source period. The proposal's effective date remains explicit.
//!
//! Preparation writes nothing and does not import or attest a driver. Import
//! the ordinary AllocationPosting basis with its actual provenance, then seal
//! and review the proposal once. Retain the request, source digest and review
//! digest independently. Before planning, re-read the current source: even a
//! same-net replacement of its contributing entries requires a new review.
//! Unrelated publications and approvals may advance HEAD. After attempting
//! publication, retry the original native PostPlan, NEVER this preparation.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::rows::bytes;
use fa_journal::{AllocationPosting, KernelError, Refusal, exit};
use fa_model::limits::MAX_DIMENSIONS_PER_LEG;
use fa_model::symbols::{label, property};
use fa_model::{ApprovalRef, Entry, EntryPayload, Id128, Writer, domain_digest};
use fa_money::allocation::{AllocationMethod, AllocationRequest, AllocationTarget};
use fa_money::{Amount, Side, UnitId};
use fa_policy::{Capability, Op};
use fa_registers::explain::Column;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AllocationReview, AllocationReviewError, AsyncBook, BookError, Outcome, PostPlan};

/// Bound candidate posted source/unit contributions, before dimension filtering.
/// An oversized source refuses, never truncates its total. This does not bound
/// the existing register fold's scan or its own allocations.
pub const MAX_BALANCE_ALLOCATION_CONTRIBUTIONS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceAllocationRequest {
    pub source: VId,
    pub period: String,
    pub unit: UnitId,
    /// Exact equality, not a subset filter. Empty means undimensioned only.
    pub dimensions: Vec<(u32, VId)>,
    pub method: AllocationMethod,
    pub targets: Vec<AllocationTarget>,
}

impl BalanceAllocationRequest {
    fn posting(&self, total: i128, source_side: Side) -> AllocationPosting {
        AllocationPosting {
            source: self.source,
            source_side,
            dimensions: self.dimensions.clone(),
            request: AllocationRequest {
                total: Amount::new(self.unit, total),
                method: self.method,
                targets: self.targets.clone(),
            },
        }
    }

    fn validate(&self) -> Result<(), Refusal> {
        if self.period.is_empty() || self.period.len() > 256 {
            return Err(structure("source period must contain 1 through 256 bytes"));
        }
        if self.targets.len() > fa_journal::allocation::MAX_POSTING_TARGETS
            || self.dimensions.len() > MAX_DIMENSIONS_PER_LEG
        {
            return Err(structure("source instruction exceeds target or dimension bounds"));
        }
        // Reuse the registered instruction's shape checks, including target
        // identities, source exclusion, law, dimensions and transport bounds.
        // The placeholder is never executed, reviewed, imported or posted.
        self.posting(1, Side::Credit).basis_bytes()?;
        Ok(())
    }
}

/// Current source observations and the resulting explicit instruction. This
/// is a preparation, not a certificate, approval or posting permit.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedBalanceAllocation {
    request: BalanceAllocationRequest,
    known_at: CommitSeq,
    source_digest: [u8; 32],
    debits: i128,
    credits: i128,
    contributions: usize,
    posting: AllocationPosting,
}

impl core::fmt::Debug for PreparedBalanceAllocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedBalanceAllocation")
            .field("known_at", &self.known_at)
            .field("contributions", &self.contributions)
            .finish_non_exhaustive()
    }
}

impl PreparedBalanceAllocation {
    pub fn request(&self) -> &BalanceAllocationRequest { &self.request }
    pub fn known_at(&self) -> CommitSeq { self.known_at }
    pub fn source_digest(&self) -> [u8; 32] { self.source_digest }
    pub fn debits(&self) -> i128 { self.debits }
    pub fn credits(&self) -> i128 { self.credits }
    pub fn contributions(&self) -> usize { self.contributions }
    pub fn posting(&self) -> &AllocationPosting { &self.posting }

    /// The template must cite the exact driver, imported separately with its
    /// real grade/uploader. No source attestation or approval is manufactured.
    pub fn review(&self, template: EntryPayload) -> Result<AllocationReview, AllocationReviewError> {
        AllocationReview::new(self.posting.clone(), template)
    }
}

fn structure(message: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE, exit::USAGE,
        format!("balance allocation: {message}"),
        "plan §5.3 / §6.3 (explicit native-unit journal-derived allocation)",
        "select a nonzero posted leaf balance in one unit, period and exact dimension set",
    )
}

fn changed() -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED, exit::CONFLICT,
        "the allocation source or reviewed instruction has changed",
        "plan §5.3 / §6.3 / §10.4 (exact source observations and reviewed proposal)",
        "prepare and review the changed allocation again; after an attempted commit retry its original PostPlan instead",
    )
}

fn corrupt(message: &str) -> BookError {
    KernelError::Corrupt(message.into()).into()
}

fn source_witness_error(error: fa_model::EncodeError) -> BookError {
    corrupt(&format!("allocation source witness encoding failed: {error}"))
}

fn admit(capability: &Capability, book: Id128, principal: VId, op: Op, legs: &[(UnitId, i128)]) -> Result<(), Refusal> {
    fa_policy::admit_read(capability, capability.holder(), book)
        .map_err(|denial| fa_journal::policy::refusal(&denial))?;
    fa_policy::admit(capability, &fa_policy::Intent {
        principal, trunk: true, op, book, legs,
    }).map_err(|denial| fa_journal::policy::refusal(&denial))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Derive the instruction from the current immutable journal. Read/Post,
    /// holder, profile and book scope are checked before observation; current
    /// expiry/revocation precede the fold. All computed leg ceilings are then
    /// checked, including signed residuals, not merely the net source amount.
    /// No evidence import, approval, sealing, planning or journal write occurs.
    pub fn prepare_balance_allocation(
        &self,
        cx: &PurposeContexts,
        request: &BalanceAllocationRequest,
        capability: &Capability,
    ) -> Outcome<PreparedBalanceAllocation> {
        if let Err(refusal) = admit(capability, self.context().book_id, capability.holder(), Op::Post, &[]) {
            return Ok(Err(refusal));
        }
        let prepared = match self.observe_balance_allocation(cx, request, capability, false)? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let outcome = match prepared.posting.request.execute() {
            Ok(outcome) => outcome,
            Err(error) => return Ok(Err(structure(error))),
        };
        let mut legs = vec![(request.unit, prepared.posting.request.total.mantissa)];
        for share in outcome.shares() {
            if share.mantissa != 0 {
                let Some(magnitude) = share.mantissa.checked_abs() else {
                    return Ok(Err(structure("computed leg magnitude exceeds i128")));
                };
                legs.push((share.unit, magnitude));
            }
        }
        if let Err(refusal) = admit(capability, self.context().book_id, capability.holder(), Op::Post, &legs) {
            return Ok(Err(refusal));
        }
        Ok(Ok(prepared))
    }

    /// Revalidate a source-bound review and rehearse through the real kernel.
    /// Source digest commits to book, selector and every selected full entry
    /// digest/ordinal/visibility witness, not just its net amount. It deliberately
    /// excludes HEAD, allowing unrelated commits without changing the source.
    /// This digest is a recipient-retained expectation, NOT a signed proof.
    ///
    /// The exclusive mutable handle and absence of suspension keep source
    /// validation and planning on the same writer's prefix. The native plan
    /// supplies the ordinary unchanged-prefix check at eventual publication.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_balance_allocation_review(
        &mut self,
        cx: &PurposeContexts,
        request: &BalanceAllocationRequest,
        expected_source_digest: [u8; 32],
        review: &AllocationReview,
        expected_review_digest: [u8; 32],
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<PostPlan> {
        let explicit: Vec<_> = review.proposal().legs.iter()
            .map(|leg| (leg.amount.unit, leg.amount.mantissa)).collect();
        if let Err(refusal) = admit(capability, self.context().book_id, review.proposal().principal_ref, Op::Post, &explicit) {
            return Ok(Err(refusal));
        }
        if review.proposal().book_id != self.context().book_id
            || review.proposal().branch_id != Id128::TRUNK
            || review.verify_for(&expected_review_digest).is_err()
        {
            return Ok(Err(changed()));
        }
        let prepared = match self.observe_balance_allocation(cx, request, capability, true)? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if prepared.source_digest != expected_source_digest || prepared.posting != *review.posting() {
            return Ok(Err(changed()));
        }
        self.plan_allocation_review(cx, review, expected_review_digest, approvals, capability)
    }

    // Read-only shared observation. Callers separately admit their actual
    // operation (Post or Approve); no operation is added to this capability.
    fn observe_balance_allocation(
        &self,
        cx: &PurposeContexts,
        request: &BalanceAllocationRequest,
        capability: &Capability,
        revalidating: bool,
    ) -> Outcome<PreparedBalanceAllocation> {
        let book = self.context();
        if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = request.validate() { return Ok(Err(refusal)); }
        if book.units.get(request.unit).is_none() {
            return Ok(Err(structure("unknown native unit")));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| -> Outcome<PreparedBalanceAllocation> {
            let at = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, at) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) = fa_journal::policy::capability_admitted(&self.db, book, capability)? {
                return Ok(Err(refusal));
            }
            let report = fa_registers::explain_balance(
                &self.db, book, request.source, &request.period, Some(at),
            )?;
            let mut entries = BTreeMap::new();
            let mut witnesses = Writer::new();
            witnesses.fixed(&book.book_id.0).u128(request.source.0)
                .str(&request.period).u32(request.unit.0)
                .list(&request.dimensions, |w, (dimension, value)| {
                    w.u32(*dimension).u128(value.0);
                });
            let mut debits = 0_i128;
            let mut credits = 0_i128;
            let mut count = 0_usize;
            let mut candidates = 0_usize;
            for contribution in &report.contributions {
                query.checkpoint().map_err(BookError::Context)?;
                if contribution.column != Column::Posted || contribution.unit_id != request.unit.0 {
                    continue;
                }
                if candidates == MAX_BALANCE_ALLOCATION_CONTRIBUTIONS {
                    return Ok(Err(structure("source exceeds the contribution bound; select a smaller source period")));
                }
                candidates += 1;
                if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(contribution.entry) {
                    let row = self.db.vertex_at(contribution.entry, at).map_err(KernelError::from)?
                        .filter(|row| row.labels.contains(&label::ENTRY))
                        .ok_or_else(|| corrupt("allocation source entry is missing"))?;
                    let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "allocation source")?)
                        .map_err(KernelError::from)?;
                    slot.insert(entry);
                }
                let entry = entries.get(&contribution.entry)
                    .ok_or_else(|| corrupt("resolved allocation source is missing"))?;
                let leg = entry.proposal.legs.get(usize::from(contribution.ordinal))
                    .ok_or_else(|| corrupt("allocation source ordinal is missing"))?;
                if entry.entry_digest != contribution.entry_digest
                    || entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK
                    || leg.account_ref != request.source || leg.amount.unit != request.unit
                    || leg.side != contribution.side || leg.amount.mantissa != contribution.mantissa
                    || contribution.mantissa <= 0
                {
                    return Err(corrupt("allocation source contribution disagrees with its payload"));
                }
                if leg.dimension_set != request.dimensions { continue; }
                count += 1;
                let sum = match leg.side { Side::Debit => &mut debits, Side::Credit => &mut credits };
                *sum = sum.checked_add(leg.amount.mantissa).ok_or(fa_registers::RegisterError::Overflow)?;
                witnesses.u128(contribution.entry.0).fixed(&contribution.entry_digest)
                    .u16(contribution.ordinal).u64(contribution.recorded_at.0).u64(contribution.visible_at.0)
                    .u8(match leg.side { Side::Debit => 0, Side::Credit => 1 }).i128(leg.amount.mantissa);
            }
            let net = debits.checked_sub(credits).ok_or(fa_registers::RegisterError::Overflow)?;
            if net == 0 {
                return Ok(Err(if revalidating { changed() } else {
                    structure("selected posted source balance is zero")
                }));
            }
            let total = net.checked_abs().ok_or(fa_registers::RegisterError::Overflow)?;
            let source_side = if net > 0 { Side::Credit } else { Side::Debit };
            witnesses.u64(count as u64).i128(debits).i128(credits);
            let witness_bytes = witnesses.finish().map_err(source_witness_error)?;
            let source_digest = domain_digest(b"fa:balance-allocation-source:v1", &[&witness_bytes]);
            let posting = request.posting(total, source_side);
            if let Err(refusal) = posting.basis_bytes() { return Ok(Err(refusal)); }
            query.checkpoint().map_err(BookError::Context)?;
            Ok(Ok(PreparedBalanceAllocation {
                request: request.clone(), known_at: at, source_digest,
                debits, credits, contributions: count, posting,
            }))
        })
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Approve the exact instruction only while its independently retained
    /// source expectation still holds. Unlike approving a supplied allocation
    /// alone, source inspection requires Read as well as Approve. Post is
    /// neither required nor manufactured. The preparer cannot self-approve.
    ///
    /// Reuse the same authoritative source selection as planning, including
    /// migration visibility and exact dimensions. Then record the ordinary
    /// proposal-bound approval under current native policy. The approval does
    /// not certify the source digest to third parties, attest driver truth,
    /// import evidence, or grant period/limit permissions. Planning revalidates
    /// the source again after approvals and retains all economic admission.
    ///
    /// An exact approval retry is idempotent while the source is unchanged.
    /// After payment publication, retry the original PostPlan instead.
    #[allow(clippy::too_many_arguments)]
    pub async fn approve_balance_allocation_review(
        &mut self,
        cx: &PurposeContexts,
        request: &BalanceAllocationRequest,
        expected_source_digest: [u8; 32],
        review: &AllocationReview,
        expected_review_digest: [u8; 32],
        capability: &Capability,
    ) -> Outcome<fa_journal::Approved> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let explicit: Vec<_> = review.proposal().legs.iter()
            .map(|leg| (leg.amount.unit, leg.amount.mantissa)).collect();
        if let Err(refusal) = admit(capability, self.context().book_id, capability.holder(), Op::Approve, &explicit) {
            return Ok(Err(refusal));
        }
        if capability.holder() == review.proposal().principal_ref {
            return Ok(Err(Refusal::new(
                fa_journal::refusal::code::APPROVALS, exit::REFUSAL,
                "the balance allocation preparer cannot approve their own proposal",
                "plan §14.3 (separation of preparer and approver)",
                "have a distinct principal inspect the source and review using their own read and approve authority",
            )));
        }
        if review.proposal().book_id != self.context().book_id
            || review.proposal().branch_id != Id128::TRUNK
            || review.verify_for(&expected_review_digest).is_err()
        {
            return Ok(Err(changed()));
        }
        let prepared = match self.observe_balance_allocation(cx, request, capability, true)? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if prepared.source_digest != expected_source_digest || prepared.posting != *review.posting() {
            return Ok(Err(changed()));
        }
        // The exclusive book handle is retained through native publication.
        // Native approval checks expiry/revocation and policy again; the exact
        // same capability is supplied, with no synthesized Read or Post grant.
        self.approve_allocation_review(cx, review, expected_review_digest, capability).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_witness_encoding_failure_is_corruption_not_a_refusal() {
        let error = source_witness_error(fa_model::EncodeError::LengthOverflow);
        match error {
            BookError::Kernel(KernelError::Corrupt(message)) => assert_eq!(
                message,
                "allocation source witness encoding failed: a length does not fit the u32 prefix"
            ),
            other => panic!("unexpected source witness error: {other:?}"),
        }
    }
}
