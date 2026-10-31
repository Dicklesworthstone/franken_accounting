//! Immutable acquisition schedules and native cumulative asset charges.

use asupersync::fs::Vfs;
use fa_model::{ApprovalRef, EntryPayload};
use fa_policy::{Capability, Op};
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

pub use fa_journal::asset_cost::{
    AssetChargeBasis, AssetChargeRequest, AssetCostKind, AssetRegister, AssetRegisterRow,
    AssetScheduleRecorded, AssetScheduleRequest, AssetScheduleSpec, PreparedAssetCharge,
    StoredAssetSchedule, asset_schedule_proposal,
};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Asset reports prove immutable source history even for HEAD. General
    /// report preflight may omit hydration for a current-schema checkpoint,
    /// so explicitly load the retained prefix after admitting current Read.
    async fn prepare_asset_history(
        &mut self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<()> {
        if let Err(refusal) = self
            .prepare_report_history(cx, capability.holder(), capability, known_at)
            .await?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        // Each native reader repeats current capability and selected-prefix
        // admission before its fold, including after this awaited hydration.
        Ok(Ok(()))
    }

    /// `fa verify schedules` over complete native history. Current
    /// whole-book Read and Verify admit loading the retained prefix, which
    /// the asset-schedule verifier's entry history needs once a checkpoint
    /// has retired the delta cursor. Nothing is published.
    pub async fn verify_schedules_with_history(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
    ) -> Outcome<fa_journal::ScheduleVerification> {
        if let Err(denial) = fa_policy::require(capability, Op::Verify, "verifying schedules") {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = self.prepare_asset_history(cx, None, capability).await? {
            return Ok(Err(refusal));
        }
        Ok(Ok(self.verify_schedules(cx)?))
    }

    pub async fn create_asset_schedule(
        &mut self,
        cx: &PurposeContexts,
        request: AssetScheduleRequest,
        capability: &Capability,
    ) -> Outcome<AssetScheduleRecorded> {
        if let Err(refusal) = self
            .prepare_source_history(cx, request.principal, capability, Op::SchemaChange, &[])
            .await?
        {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::asset_cost::create_asset_schedule(
            &mut self.db,
            cx,
            &self.context,
            capability,
            request,
        )
        .await?)
    }

    /// Publish the exact review and its current approvals. Immutable terms
    /// cannot be amended or redeclared under another name for the same leg.
    pub async fn create_asset_schedule_proposal(
        &mut self,
        cx: &PurposeContexts,
        proposal: EntryPayload,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<AssetScheduleRecorded> {
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
        Ok(fa_journal::asset_cost::create_asset_schedule_proposal(
            &mut self.db,
            cx,
            &self.context,
            capability,
            proposal,
            approvals,
        )
        .await?)
    }

    pub async fn asset_schedules(
        &mut self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<Vec<StoredAssetSchedule>> {
        if let Err(refusal) = self.prepare_asset_history(cx, known_at, capability).await? {
            return Ok(Err(refusal));
        }
        self.query(cx, |db, book| {
            let at = known_at.unwrap_or(db.frontier().map_err(fa_journal::KernelError::from)?);
            Ok(fa_journal::asset_cost::asset_schedules(
                db, cx, book, capability, at,
            )?)
        })
    }

    /// Inspect acquisition cost, net recognition and remaining basis with Read
    /// authority only. The selected coordinate includes all recorded effects;
    /// it does not filter them by financial effective date.
    pub async fn asset_register(
        &mut self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<AssetRegister> {
        if let Err(refusal) = self.prepare_asset_history(cx, known_at, capability).await? {
            return Ok(Err(refusal));
        }
        self.query(cx, |db, book| {
            let at = known_at.unwrap_or(db.frontier().map_err(fa_journal::KernelError::from)?);
            Ok(fa_journal::asset_cost::asset_register(
                db, cx, book, capability, at,
            )?)
        })
    }

    /// Compute a source-bound charge under current authority. The empty
    /// template identifies exact retries before fresh-source/no-op calculation.
    /// Use PreparedAssetCharge::proposal with ordinary plan and commit_plan.
    pub async fn prepare_asset_charge(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: &AssetChargeRequest,
        template: &EntryPayload,
    ) -> Outcome<PreparedAssetCharge> {
        // This method derives a proposal and writes nothing. Judge it as a
        // plan, as lot disposals are, so an Agent can review a charge
        // without receiving direct trunk authority; posting, committing or
        // promoting it still runs the full trunk admission.
        if let Err(denial) =
            fa_policy::admit_read(capability, template.principal_ref, self.context.book_id)
                .and_then(|()| {
                    fa_policy::admit_base_for_plan(
                        capability,
                        &fa_policy::Intent {
                            principal: template.principal_ref,
                            trunk: true,
                            op: Op::Post,
                            book: self.context.book_id,
                            legs: &[],
                        },
                    )
                })
                .and_then(|()| {
                    fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None)
                })
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = self.prepare_asset_history(cx, None, capability).await? {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::asset_cost::prepare_asset_charge(
            &self.db,
            cx,
            &self.context,
            capability,
            request,
            template,
        )?)
    }
}
