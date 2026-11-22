//! Historical open-item and aging reads through the caller's
//! query context. These projections neither create a runtime nor write.

use asupersync::fs::Vfs;
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError};

mod certificate;
pub use certificate::{
    AGING_CERTIFICATE_FORMAT, AGING_OUTPUT_FORMAT, AgingCertificate, AgingRequest, CertifiedAging,
    MAX_AGING_BUCKET_BOUNDS, MAX_AGING_CERTIFICATE_BYTES,
};

mod due_date;
pub use due_date::{
    CertifiedDueDateAging, DUE_DATE_AGING_CERTIFICATE_FORMAT, DUE_DATE_AGING_OUTPUT_FORMAT,
    DueDateAgingCertificate,
};

mod reconciliation;
pub use reconciliation::portfolio;
pub use reconciliation::{
    AGING_RECONCILIATION_CERTIFICATE_FORMAT, AgingReconciliation, AgingReconciliationCertificate,
    AgingReconciliationRequest, AgingReconciliationRow, CertifiedAgingReconciliation,
    CertifiedDueDateAgingReconciliation, DUE_DATE_AGING_RECONCILIATION_CERTIFICATE_FORMAT,
    DueDateAgingReconciliation, DueDateAgingReconciliationCertificate,
    MAX_AGING_RECONCILIATION_BYTES,
};

pub use fa_registers::open_items::aging::{
    AgedOpenItem, AgingAmounts, AgingBand, AgingBuckets, AgingCell, AgingTotal, DueDateAgedItem,
    DueDateAging, EffectiveDateAging, Unscheduled, UnscheduledItem,
};
pub use fa_registers::open_items::history::OpenItemSnapshot;

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Fold open items through an inclusive civil date at one known-at
    /// frontier. Later-effective applications and reversals do not change
    /// this historical balance. This is an embedded read, not session-scoped
    /// authorization or a certified report. Repeated reads at one effective
    /// cutoff reuse an authenticated native prefix and fold its exact suffix.
    pub fn open_items_as_of(
        &self,
        cx: &PurposeContexts,
        account: Option<VId>,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Result<OpenItemSnapshot, BookError> {
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            if let Ok(mut history) = self.open_item_history.try_lock() {
                return fa_registers::open_items::open_items_as_of_carried(
                    &self.db,
                    &query,
                    self.context(),
                    account,
                    effective_through,
                    known_at,
                    &mut history,
                )
                .map_err(BookError::from);
            }
            fa_registers::open_items::history::open_items_as_of(
                &self.db,
                self.context(),
                account,
                effective_through,
                known_at,
            )
            .map_err(BookError::from)
        })
    }

    /// Group historical open amounts into explicit age bands, preserving
    /// separate native-unit debit and credit totals and item-level detail.
    /// Age is measured from the effective date, not an inferred due date.
    /// `None` resolves known-at once and records that prefix in the report.
    pub fn effective_date_aging(
        &self,
        cx: &PurposeContexts,
        account: Option<VId>,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
        buckets: &AgingBuckets,
    ) -> Result<EffectiveDateAging, BookError> {
        let snapshot = self.open_items_as_of(cx, account, effective_through, known_at)?;
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            fa_registers::open_items::aging::age_snapshot(snapshot, buckets)
                .map_err(BookError::from)
        })
    }

    /// Group historical open amounts by days past each contractual due date
    /// the journal records (obligation maturity terms, extension 33), the
    /// earliest installments relieved first. Items without contractual terms
    /// are listed as unscheduled, never given a guessed due date. An embedded
    /// read, not a certified report.
    pub fn due_date_aging(
        &self,
        cx: &PurposeContexts,
        account: Option<VId>,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
        buckets: &AgingBuckets,
    ) -> Result<DueDateAging, BookError> {
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            fa_registers::open_items::aging::due_date_aging(
                &self.db,
                self.context(),
                account,
                effective_through,
                known_at,
                buckets,
            )
            .map_err(BookError::from)
        })
    }
}
