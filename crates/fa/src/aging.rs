//! Historical open-item and effective-date aging reads through the caller's
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

mod reconciliation;
pub use reconciliation::portfolio;
pub use reconciliation::{
    AGING_RECONCILIATION_CERTIFICATE_FORMAT, AgingReconciliation, AgingReconciliationCertificate,
    AgingReconciliationRequest, AgingReconciliationRow, CertifiedAgingReconciliation,
    MAX_AGING_RECONCILIATION_BYTES,
};

pub use fa_registers::open_items::aging::{
    AgedOpenItem, AgingAmounts, AgingBand, AgingBuckets, AgingCell, AgingTotal, EffectiveDateAging,
};
pub use fa_registers::open_items::history::OpenItemSnapshot;

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Fold open items through an inclusive civil date at one known-at
    /// frontier. Later-effective applications and reversals do not change
    /// this historical balance. This is an embedded read, not session-scoped
    /// authorization or a certified report.
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
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            fa_registers::open_items::aging::effective_date_aging(
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
