//! Governed fixed-entry recurrence over committed TimeEvidence ticks.

use asupersync::fs::Vfs;
use fa_model::ApprovalRef;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

pub use fa_journal::recurring::{
    RecurringBatch, RecurringBlocked, RecurringHistory, RecurringPlan, RecurringReadWork,
    RecurringRecorded, RecurringSpec, RecurringView,
};
pub use fa_time::business::{
    AdjustedOccurrence, BusinessCalendar, BusinessDayConvention, BusinessDayError,
};

/// Build an ISO Monday–Friday business calendar with explicit holiday dates.
pub fn weekday_business_calendar(
    holidays: Vec<fa_time::DateDay>,
) -> Result<BusinessCalendar, BusinessDayError> {
    use fa_time::Weekday::{Friday, Monday, Thursday, Tuesday, Wednesday};
    BusinessCalendar::new(&[Monday, Tuesday, Wednesday, Thursday, Friday], holidays)
}

/// Apply `convention` over `calendar` to `view.next_date`, preserving both the
/// contractual unadjusted occurrence date and its adjusted business day.
pub fn adjust_next_occurrence(
    view: &RecurringView,
    calendar: &BusinessCalendar,
    convention: BusinessDayConvention,
) -> Result<Option<AdjustedOccurrence>, BusinessDayError> {
    view.next_date
        .map(|date| {
            Ok(AdjustedOccurrence {
                index: view.next_index,
                unadjusted: date,
                adjusted: calendar.adjust(date, convention)?,
                convention,
            })
        })
        .transpose()
}

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
