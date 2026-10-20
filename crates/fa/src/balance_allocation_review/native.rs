//! One-artifact consumers of the existing source observer and native pipeline.

use asupersync::fs::Vfs;
use fa_journal::{Approved, Refusal, exit};
use fa_model::{ApprovalRef, Id128};
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;

use super::BalanceAllocationReview;
use crate::{AllocationReviewError, AsyncBook, BookError, Outcome, PostPlan};

fn refusal(error: AllocationReviewError) -> Refusal {
    let (code, status) = if matches!(error, AllocationReviewError::Mismatch) {
        (fa_journal::refusal::code::PLAN_INVALIDATED, exit::CONFLICT)
    } else {
        (fa_journal::refusal::code::STRUCTURE, exit::USAGE)
    };
    Refusal::new(
        code,
        status,
        error.to_string(),
        "fa:balance-allocation-review:v1; plan §5.3 / §6.3 / §10.4",
        "use the unchanged saved source review and its independently retained compound digest; after an attempted commit retry the original PostPlan",
    )
}

// Only payload checks occur here. Current expiry/revocation, source history,
// coordinate and exact posting equality are still judged by the shared native
// source workflow below, under the same supplied capability and book handle.
fn checked_review_digest(
    book: Id128,
    artifact: &BalanceAllocationReview,
    expected: [u8; 32],
    op: Op,
    capability: &Capability,
) -> Result<[u8; 32], Refusal> {
    fa_policy::admit_read(capability, capability.holder(), book)
        .map_err(|denial| fa_journal::policy::refusal(&denial))?;
    let proposal = artifact.review().proposal();
    let explicit: Vec<_> = proposal
        .legs
        .iter()
        .map(|leg| (leg.amount.unit, leg.amount.mantissa))
        .collect();
    let principal = if matches!(op, Op::Approve) {
        capability.holder()
    } else {
        proposal.principal_ref
    };
    fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal,
            trunk: true,
            op,
            book,
            legs: &explicit,
        },
    )
    .map_err(|denial| fa_journal::policy::refusal(&denial))?;
    artifact.verify_for(&expected).map_err(refusal)?;
    artifact.review().digest().map_err(refusal)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Plan directly from a restored source-bound handoff. The caller retains
    /// ONE compound digest; this adapter derives the inner review identity and
    /// exact selector only after checking that complete expectation. Read and
    /// Post authority, book scope and every actual leg ceiling remain required.
    ///
    /// The existing observer revalidates every source contribution, including
    /// same-net changes, before the existing native kernel rehearses the exact
    /// sealed proposal. The exclusive handle spans history loading, source
    /// observation and planning at one writer's prefix.
    /// Persist the returned PostPlan before commit_plan; this method never
    /// refreshes a plan following uncertain publication and writes no journal.
    pub async fn plan_balance_allocation(
        &mut self,
        cx: &PurposeContexts,
        review: &BalanceAllocationReview,
        expected_digest: [u8; 32],
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<PostPlan> {
        cx.txn().checkpoint().map_err(BookError::Context)?;
        let inner_digest = match checked_review_digest(
            self.context().book_id,
            review,
            expected_digest,
            Op::Post,
            capability,
        ) {
            Ok(digest) => digest,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = review.request();
        self.plan_balance_allocation_review(
            cx,
            &request,
            review.source_digest(),
            review.review(),
            inner_digest,
            approvals,
            capability,
        )
        .await
    }

    /// Approve from the restored complete handoff under the recipient's own
    /// Read/Approve authority. No Post authority is needed or synthesized; the
    /// existing source workflow rejects self-approval and rechecks the source
    /// before publishing a native approval under current expiry/revocation and
    /// policy. A repeated approval is idempotent while its source still matches.
    ///
    /// Native approval binds the PROPOSAL digest, not this container or a source
    /// certificate. It is not an evidence attestation or target/period admission.
    /// Planning must revalidate this same compound expectation and source again.
    /// After attempting posting, retry its original PostPlan instead of asking
    /// this operation to approve a now-depleted source again.
    pub async fn approve_balance_allocation(
        &mut self,
        cx: &PurposeContexts,
        review: &BalanceAllocationReview,
        expected_digest: [u8; 32],
        capability: &Capability,
    ) -> Outcome<Approved> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let inner_digest = match checked_review_digest(
            self.context().book_id,
            review,
            expected_digest,
            Op::Approve,
            capability,
        ) {
            Ok(digest) => digest,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = review.request();
        self.approve_balance_allocation_review(
            cx,
            &request,
            review.source_digest(),
            review.review(),
            inner_digest,
            capability,
        )
        .await
    }
}
