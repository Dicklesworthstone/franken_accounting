//! Period projection verification bound to complete native Entry history.

use asupersync::fs::Vfs;
use fa_policy::{Capability, Op, Reach};
use fgdb::{Database, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::entry_history::{EntryHistoryVerification, verify_entry_history};
use crate::genesis::BookContext;
use crate::period::{PeriodVerification, verify_periods};
use crate::policy;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

/// Complete Entry-history integrity and retained period projections at one
/// captured prefix. A value is returned only after native history integrity
/// succeeds; projection discrepancies remain explicit findings in periods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodHistoryVerification {
    pub history: EntryHistoryVerification,
    pub periods: PeriodVerification,
}

impl PeriodHistoryVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.periods.is_green()
    }
}

/// Load native history and verify both Entry integrity and period projections
/// at the same prefix without publishing a commit. Admission requires current
/// whole-book Read and Verify authority, including for a historical selection.
/// Read-capable agents are admitted under the normal read law.
///
/// None captures HEAD before history loading. An unavailable history window
/// returns the existing native-history refusal, never a partial green result.
pub async fn verify_periods_with_history<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    principal: VId,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Outcome<PeriodHistoryVerification> {
    let query = ctx.query();
    query.checkpoint().map_err(WriteTxnError::Interrupted)?;
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.book_id)
        .and_then(|()| fa_policy::require(capability, Op::Verify, "verifying period history"))
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
    {
        return Ok(Err(policy::refusal(&denial)));
    }
    let head = match policy::current_at(db, book, capability)? {
        Ok(current) => current.at(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let basis = known_at.unwrap_or(head);
    if basis > head {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "verification prefix {} exceeds the book head {}",
                basis.0, head.0
            ),
            "plan §7.1 (recorded prefixes)",
            format!("verify at or before {}", head.0),
        )));
    }
    ctx.commit()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    // Loading may suspend. Authority is current at the head when results are
    // disclosed; the requested historical prefix never revives a revoked token.
    if let Err(refusal) = policy::current_at(db, book, capability)? {
        return Ok(Err(refusal));
    }
    query.checkpoint().map_err(WriteTxnError::Interrupted)?;
    let Some(genesis) = crate::scratch::source_genesis(db)? else {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "the source database holds no book",
            "plan §7.1 (recorded prefixes)",
            "verify an opened book with retained genesis history",
        )));
    };
    if basis < genesis {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "verification prefix {} precedes book genesis {}",
                basis.0, genesis.0
            ),
            "plan §7.1 (recorded prefixes)",
            format!("verify at or after {}", genesis.0),
        )));
    }
    query.with_restriction(|| {
        // Only a Book born with version-1 bytes may use the legacy period
        // baseline. Mutable accumulator properties do not alter this payload.
        let root = crate::rows::book_root();
        let born = db.vertex_at(root, genesis)?.ok_or_else(|| {
            KernelError::Corrupt("the native Book creating snapshot is unavailable".into())
        })?;
        let selected = db.vertex_at(root, basis)?.ok_or_else(|| {
            KernelError::Corrupt("the Book is absent at the verification prefix".into())
        })?;
        let payload = fa_model::symbols::property::FA_PAYLOAD;
        if crate::rows::bytes(&born, payload, "native Book payload")?
            != crate::rows::bytes(&selected, payload, "selected Book payload")?
        {
            return Err(KernelError::Corrupt(
                "the selected Book payload differs from its native birth; a rewrite cannot change legacy period eligibility".into(),
            ));
        }
        let history = verify_entry_history(db, ctx, book, Some(basis))?;
        let periods = verify_periods(db, book, Some(basis))?;
        Ok(Ok(PeriodHistoryVerification { history, periods }))
    })
}
