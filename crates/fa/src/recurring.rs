//! Governed fixed-entry recurrence over committed TimeEvidence ticks.

use asupersync::fs::Vfs;
use fa_model::ApprovalRef;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

pub use fa_journal::recurring::{
    RecurringBatch, RecurringBlocked, RecurringPlan, RecurringRecorded, RecurringSpec,
    RecurringView,
};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Bind a fixed template, explicit monthly cadence and current execution
    /// capability for independent approval. This is an approval proposal; each
    /// due occurrence must still satisfy the ordinary current posting laws.
    pub fn plan_recurring(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        spec: RecurringSpec,
    ) -> Outcome<RecurringPlan> {
        Ok(fa_journal::recurring::plan_recurring(
            &self.db,
            cx,
            &self.context,
            capability,
            spec,
        )?)
    }

    /// Journal an approved recurrence once. Approval publications do not alter
    /// its sealed template or its independently reviewed proposal digest.
    pub async fn create_recurring(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        plan: RecurringPlan,
        approvals: Vec<ApprovalRef>,
    ) -> Outcome<RecurringRecorded> {
        Ok(fa_journal::recurring::create_recurring(
            &mut self.db,
            cx,
            &self.context,
            capability,
            plan,
            approvals,
        )
        .await?)
    }

    /// Inspect schedules at the current journal prefix under whole-book read
    /// authority. Their mutable execution state is verified against history.
    pub fn recurring_schedules(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
    ) -> Outcome<Vec<RecurringView>> {
        self.query(cx, |db, book| {
            Ok(fa_journal::recurring::recurring_schedules(
                db, cx, book, capability,
            )?)
        })
    }

    /// Cancel future occurrences by an immutable ScheduleCancelled control.
    /// The creator or an authorized approver may stop the schedule; committed
    /// occurrences remain part of the ledger and require ordinary corrections.
    pub async fn cancel_recurring(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        name: &str,
        reason: &str,
    ) -> Outcome<RecurringRecorded> {
        let description = self.seal_text(cx, reason)?;
        Ok(fa_journal::recurring::cancel_recurring(
            &mut self.db,
            cx,
            &self.context,
            capability,
            name,
            description,
        )
        .await?)
    }
}
