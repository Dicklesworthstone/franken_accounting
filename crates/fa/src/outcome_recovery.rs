//! Explicit recovery of the journal's common idempotency namespace (§5.9).
//!
//! Legacy history is examined only when an authorized caller requests a
//! rebuild. Preparation verifies the original native entry history and stages
//! the complete recovery without publishing; publication rechecks the original
//! capability and exact basis. Ordinary posting never triggers this scan.

use asupersync::fs::Vfs;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

pub use fa_journal::{OutcomeRebuild, OutcomeRebuildPreview, PreparedOutcomeRebuild};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Verify complete native history and prepare its missing idempotency
    /// outcomes without publishing. Current whole-book Read and SchemaChange
    /// authority precedes history loading, including after checkpoint reopen.
    /// The returned transaction can be reviewed and explicitly aborted.
    pub async fn prepare_outcome_rebuild(
        &mut self,
        cx: &PurposeContexts,
        capability: Capability,
    ) -> Outcome<PreparedOutcomeRebuild> {
        Ok(
            fa_journal::prepare_outcome_rebuild(&mut self.db, cx, &self.context, capability)
                .await?,
        )
    }

    /// Publish exactly the prepared recovery in one native transaction.
    /// The kernel rechecks its original capability, current revocation and
    /// expiry, policy epoch and exact source head. A covered book is a no-op.
    pub async fn publish_outcome_rebuild(
        &mut self,
        cx: &PurposeContexts,
        prepared: PreparedOutcomeRebuild,
    ) -> Outcome<OutcomeRebuild> {
        Ok(fa_journal::publish_outcome_rebuild(&mut self.db, cx, &self.context, prepared).await?)
    }

    /// Explicitly establish common idempotency coverage from verified native
    /// history. No caller-supplied entries or digests enter the rebuild.
    pub async fn rebuild_outcomes(
        &mut self,
        cx: &PurposeContexts,
        capability: Capability,
    ) -> Outcome<OutcomeRebuild> {
        let prepared = match self.prepare_outcome_rebuild(cx, capability).await? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.publish_outcome_rebuild(cx, prepared).await
    }
}
