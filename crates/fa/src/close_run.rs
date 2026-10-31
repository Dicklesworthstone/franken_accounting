//! Reviewed close execution over immutable draft rehearsals (plan §7.5).
//!
//! A run binds its complete dependency graph and each draft's retained review.
//! The journal executes a ready task and records completion in one transaction.
//! The review is evidence of the selected effects; execution still requires
//! current authority, original planner authority and the native posting laws.

use fa_journal::close_run::CloseRunView;
use fa_policy::Capability;
use fa_time::PeriodTransition;

use crate::{Book, Outcome};

/// The independently selected evidence or period action for a close task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewedCloseAction {
    /// Full digest of a retained DraftDiffCertificate, as returned by
    /// `close dry-run --certify`. Its source and output are replayed before
    /// the run is created; an arbitrary digest is never a completed review.
    DraftCertificate([u8; 32]),
    /// A native period transition. Execution consumes a separately reviewed
    /// TransitionPlan and its required independent approvals.
    PeriodTransition(PeriodTransition),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedCloseTask {
    pub id: String,
    pub depends_on: Vec<String>,
    pub action: ReviewedCloseAction,
}

impl Book {
    /// Resolve and replay each retained draft certificate before journaling
    /// an immutable run. This does not promote any draft or change a period.
    /// Dependencies are part of the definition and are validated by the
    /// kernel's graph checks; a later task cannot silently replace a review.
    pub fn start_close_run(
        &mut self,
        capability: Capability,
        name: &str,
        period: &str,
        tasks: Vec<ReviewedCloseTask>,
        description: &str,
    ) -> Outcome<CloseRunView> {
        self.start_reviewed_close_run(capability, name, period, tasks, description)
    }
}
