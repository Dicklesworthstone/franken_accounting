//! Law-bound inventory and securities disposal through the ordinary posting
//! protocol. Preparation derives native quantity and cost applications from
//! immutable history; it neither reserves lots nor grants posting authority.

use asupersync::fs::Vfs;
use fa_journal::KernelError;
use fa_model::{ApprovalRef, EntryPayload};
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, Outcome};

pub use fa_journal::chart::lots::{
    LotPolicy, LotPolicyRecorded, LotPolicyRequest, StoredLotPolicy,
};
pub use fa_journal::disposal::{LotDisposalRequest as LotDisposalPostRequest, PreparedLotDisposal};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Install a journaled lot policy, or change it with the required independent
    /// approvals. Policy selection follows recorded time; a backdated disposal
    /// cannot restore a superseded law. Existing entries retain their own basis.
    pub async fn set_lot_policy(
        &mut self,
        cx: &PurposeContexts,
        request: LotPolicyRequest,
        capability: &Capability,
    ) -> Outcome<LotPolicyRecorded> {
        if let Err(refusal) = self
            .prepare_source_history(cx, request.principal, capability, Op::SchemaChange, &[])
            .await?
        {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::chart::lots::set_lot_policy(
            &mut self.db,
            cx,
            &self.context,
            capability,
            request,
        )
        .await?)
    }

    /// Commit the exact previously reviewed policy proposal. The caller supplies
    /// current authority and approvals; the saved bytes supply neither.
    pub async fn set_lot_policy_proposal(
        &mut self,
        cx: &PurposeContexts,
        proposal: EntryPayload,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<LotPolicyRecorded> {
        if let Err(refusal) = self
            .prepare_source_history(
                cx,
                proposal.principal_ref,
                capability,
                Op::SchemaChange,
                &[],
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::chart::lots::set_lot_policy_proposal(
            &mut self.db,
            cx,
            &self.context,
            capability,
            proposal,
            approvals,
        )
        .await?)
    }

    /// Read the policy in force at a recorded prefix under current whole-book
    /// read authority. A historical selector never revives expired authority.
    pub async fn lot_policy_at(
        &mut self,
        cx: &PurposeContexts,
        account: VId,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<Option<StoredLotPolicy>> {
        if let Err(refusal) = self
            .prepare_report_history(cx, capability.holder(), capability, known_at)
            .await?
        {
            return Ok(Err(refusal));
        }
        self.query(cx, |db, book| {
            if let Err(refusal) =
                fa_journal::policy::admit_reads(db, book, capability.holder(), capability)?
            {
                return Ok(Err(refusal));
            }
            let head = db.frontier().map_err(KernelError::from)?;
            let at = known_at.unwrap_or(head);
            if at > head {
                return Ok(Err(fa_journal::Refusal::new(
                    fa_journal::refusal::code::STRUCTURE,
                    fa_journal::exit::USAGE,
                    "a lot policy cannot select a future recorded sequence",
                    "plan §6.5 (journaled lot policy)",
                    "select HEAD or an existing recorded sequence",
                )));
            }
            Ok(Ok(fa_journal::chart::lots::policy_at(
                db, book, account, at,
            )?))
        })
    }

    /// Derive complete quantity/cost relief against the latest policy and exact
    /// journal basis. Feed the returned proposal to `plan` and `commit_plan`;
    /// the posting kernel independently rederives every leg and application.
    ///
    /// The first profile covers native-cost, dimensionless debit Asset lots on
    /// an AnyUnit account. A stale basis is refused rather than silently choosing
    /// different lots. Retain the resulting PostPlan for uncertain-ack retries.
    pub async fn prepare_lot_disposal(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: &LotDisposalPostRequest,
        template: EntryPayload,
    ) -> Outcome<PreparedLotDisposal> {
        if let Err(refusal) = self
            .prepare_source_history(
                cx,
                template.principal_ref,
                capability,
                Op::Post,
                &[(request.quantity.unit, request.quantity.mantissa)],
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::disposal::prepare_lot_disposal(
            &self.db,
            cx,
            &self.context,
            capability,
            request,
            template,
        )?)
    }
}
