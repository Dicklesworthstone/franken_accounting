//! Approver-only publication of the exact recipient-selected instruction.

use asupersync::fs::Vfs;
use fa_journal::{Approved, Refusal, exit};
use fa_model::Id128;
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;

use super::{AllocationReview, refusal};
use crate::{AsyncBook, Book, BookError, Outcome};

// No storage observation occurs here. Both adapters then record the same
// proposal digest through their existing native approval implementation.
fn checked_digest(
    book: Id128,
    review: &AllocationReview,
    expected: [u8; 32],
    capability: &Capability,
) -> Result<[u8; 32], Refusal> {
    let proposal = review.proposal();
    let explicit: Vec<_> = proposal
        .legs
        .iter()
        .map(|leg| (leg.amount.unit, leg.amount.mantissa))
        .collect();
    fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal: capability.holder(),
            trunk: true,
            op: Op::Approve,
            book,
            legs: &explicit,
        },
    )
    .map_err(|denial| fa_journal::policy::refusal(&denial))?;
    if proposal.book_id != book || proposal.branch_id != Id128::TRUNK {
        return Err(Refusal::new(
            fa_journal::refusal::code::COORDINATE,
            exit::USAGE,
            "allocation review belongs to a different book or branch",
            "plan §2.2 / §14.3 (approvals belong to the proposal's book)",
            "open the review's book and use authority scoped to that book",
        ));
    }
    if capability.holder() == proposal.principal_ref {
        return Err(Refusal::new(
            fa_journal::refusal::code::APPROVALS,
            exit::REFUSAL,
            "the allocation preparer cannot approve their own proposal",
            "plan §14.3 (separation of preparer and approver)",
            "have a distinct principal review the exact instruction with their own approve capability",
        ));
    }
    review.verify_for(&expected).map_err(refusal)?;
    review.proposal_digest().map_err(refusal)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Record an approval of exactly the saved allocation review. The actor
    /// supplies their own current Approve capability, not the preparer's Post
    /// authority. Its book restriction, profile and per-unit ceilings apply to
    /// EVERY actual source/target leg, including negative-residual side swaps.
    /// A preparer cannot approve their own instruction through this operation.
    ///
    /// The recipient-owned review digest is mandatory. After reconstructing
    /// the exact proposal, the ordinary approval transaction checks expiry and
    /// revocation and records the PROPOSAL digest under the current policy epoch.
    /// No authority is copied from the review, and the review digest is never
    /// mistaken for the proposal digest an ApprovalRef must bind.
    ///
    /// This approves a supplied instruction, not a report read from storage:
    /// it requires neither Read nor Post and opens no protected document. It
    /// does NOT attest the driver's truth, import it, create a Reviewed document
    /// attestation, or claim account/period/limit admission. Those facts remain
    /// the final native plan's checks; even an approved review may be refused.
    /// Exact approval retries use the kernel's existing identity semantics.
    pub async fn approve_allocation_review(
        &mut self,
        cx: &PurposeContexts,
        review: &AllocationReview,
        expected_review_digest: [u8; 32],
        capability: &Capability,
    ) -> Outcome<Approved> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let digest = match checked_digest(
            self.context().book_id,
            review,
            expected_review_digest,
            capability,
        ) {
            Ok(digest) => digest,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // This retains precisely the supplied authority. The native operation
        // witnesses revocation/current policy; this adapter adds no Post grant.
        self.approve(cx, capability.clone(), digest).await
    }
}

impl Book {
    /// Synchronous counterpart of AsyncBook::approve_allocation_review, with
    /// the same limits and scope. Approve a supplied instruction, not its
    /// economic validity; final native planning must still admit every law.
    pub fn approve_allocation_review(
        &mut self,
        review: &AllocationReview,
        expected_review_digest: [u8; 32],
        capability: &Capability,
    ) -> Outcome<Approved> {
        let digest = match checked_digest(
            self.context().book_id,
            review,
            expected_review_digest,
            capability,
        ) {
            Ok(digest) => digest,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.approve(capability.clone(), digest)
    }
}
