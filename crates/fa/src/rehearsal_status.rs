//! Freshness of a fully replayed draft or combined close review.

use fa_journal::{Refusal, exit};
use fa_policy::{Capability, denial::code as policy_code};
use fgdb_types::{CommitSeq, VId};

use crate::{Book, Outcome};

/// Whether a historical rehearsal still describes the current work.
///
/// Both variants establish that the complete historical certificate replayed.
/// `Changed` also covers work that current native posting laws refuse. Invalid
/// history, corrupted evidence and missing caller authority remain errors.
/// Neither variant grants permission to promote a draft or execute a close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RehearsalCertificateStatus {
    Current { checked_at: CommitSeq },
    Changed { checked_at: CommitSeq },
}

impl RehearsalCertificateStatus {
    pub(crate) fn at(checked_at: CommitSeq, current: bool) -> Self {
        if current {
            Self::Current { checked_at }
        } else {
            Self::Changed { checked_at }
        }
    }
}

/// Called only after current reviewer admission and full historical replay.
/// A lawful current native refusal means the reviewed work can no longer be
/// reproduced. Codec, verification and foundation failures must never be
/// disguised as a successful freshness answer. A missing original draft is
/// also damage, rather than a lawful lifecycle transition.
pub(crate) fn changed_by_current_refusal(refusal: &Refusal) -> bool {
    // Safety refusals also include missing or misbound original approval
    // evidence. Only current admissibility changes yield a freshness result;
    // evidence failures and unknown safety codes retain their refusal.
    if refusal.exit == exit::SAFETY {
        return matches!(
            refusal.code,
            policy_code::EXPIRED
                | policy_code::REVOKED
                | policy_code::CAPABILITY
                | policy_code::CEILING
                | policy_code::APPROVALS
                | policy_code::SOD
                | fa_journal::refusal::code::PERIOD_LAW
        );
    }
    matches!(refusal.exit, exit::REFUSAL | exit::CONFLICT)
        && refusal.code != fa_journal::refusal::code::DRAFT_UNKNOWN
}

impl Book {
    /// Native trial-balance freshness deliberately ignores PeriodControl.
    /// Rehearsals additionally depend on the selected period's lifecycle:
    /// even a pending terminal task must stop being Current after an external
    /// transition. Authenticate both projections and compare their complete
    /// transition counts, so a close/reopen round trip is not hidden.
    pub(crate) fn rehearsal_period_is_current(
        &self,
        principal: VId,
        capability: &Capability,
        period: &str,
        known_at: CommitSeq,
    ) -> Outcome<bool> {
        let scope = match self.read_scope(principal, capability)? {
            Ok(scope) => scope,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let before_row = match scope.period_at(period, Some(known_at))? {
            Ok(Some(row)) => row,
            Ok(None) => {
                return Ok(Err(crate::draft_review::invalid(
                    "the reviewed period is missing from its historical prefix",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        let current_row = match scope.period_at(period, None)? {
            Ok(Some(row)) => row,
            Ok(None) => {
                return Ok(Err(crate::draft_review::invalid(
                    "the reviewed period is missing from current history",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        let before = self.verify_periods(Some(known_at))?;
        let current = self.verify_periods(None)?;
        if !before.is_green() || !current.is_green() {
            return Ok(Err(crate::draft_review::invalid(
                "the reviewed period lifecycle does not match its retained native history",
            )));
        }
        let before = before.periods.iter().find(|row| row.code == period);
        let current = current.periods.iter().find(|row| row.code == period);
        if before.is_none() || current.is_none() {
            return Ok(Err(crate::draft_review::invalid(
                "the reviewed period has no authenticated native lifecycle",
            )));
        }
        Ok(Ok(before_row == current_row && before == current))
    }
}
