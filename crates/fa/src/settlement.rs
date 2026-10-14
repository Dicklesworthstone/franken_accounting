//! Turn explicit open-item allocation into a real kernel posting plan.
//!
//! The caller supplies the complete payment proposal, including cash,
//! differences and any valuations. Only the selected leg's `settles` list is
//! filled in; no amounts, balancing legs, sealed text or idempotency keys are
//! invented. All selected targets must have the same dimensions as that leg.
//! Preparation is advice, not a reservation. Planning rehearses the production
//! kernel at exactly the allocation's basis; commit uses its authenticated
//! portable PostPlan and atomically retains the ordinary posting evidence.
//!
//! After an uncertain acknowledgement, retry the SAME PostPlan. Reallocating
//! against the now-changed open items would describe a different payment.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_intents::{PostIntent, PostPlan};
use fa_journal::rows::bytes;
use fa_journal::{KernelError, Posted, Refusal, exit};
use fa_model::limits::{MAX_LEGS_PER_ENTRY, MAX_SETTLES_PER_LEG};
use fa_model::symbols::{label, property};
use fa_model::{
    ApprovalRef, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Id128, Settlement,
};
use fa_money::{Amount, UnitId};
use fa_policy::Capability;
use fa_registers::RegisterError;
use fa_registers::open_items::{SettlementPlan, SettlementRequest};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, BookError, Outcome};

/// One explicitly selected payment/receipt leg in a caller-authored proposal.
/// All legs must initially have empty `settles` lists. Other accounting effects
/// remain explicit in the proposal and are judged by the ordinary posting laws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementPostRequest {
    pub proposal: EntryPayload,
    pub payment_leg: u16,
    /// Eligible entry/leg identities, not arbitrary account-wide matching.
    /// Bounded by the model's maximum settlements per leg, including targets
    /// that will receive no allocation. Input order does not affect allocation.
    pub targets: Vec<(VId, u16)>,
}

/// An exact proposal ready for review/approval, but NOT a posting certificate.
/// Preparation performs no journal write and does not exercise all posting laws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSettlement {
    allocation: SettlementPlan,
    proposal: EntryPayload,
}

impl PreparedSettlement {
    #[must_use]
    pub fn allocation(&self) -> &SettlementPlan {
        &self.allocation
    }

    /// Approvals bind this complete proposal, including every resolved target's
    /// full EntryRef. Sealed fields are the caller's original bytes.
    #[must_use]
    pub fn proposal(&self) -> &EntryPayload {
        &self.proposal
    }

    #[must_use]
    pub fn into_proposal(self) -> EntryPayload {
        self.proposal
    }
}

/// A kernel-rehearsed payment plus its allocation explanation. The private
/// fields prevent callers from pairing arbitrary advice with another plan.
/// The ordinary PostPlan is the portable authenticated execution artifact;
/// the allocation explanation is not a new certificate or wire format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementPostPlan {
    allocation: SettlementPlan,
    post: PostPlan,
}

impl SettlementPostPlan {
    #[must_use]
    pub fn allocation(&self) -> &SettlementPlan {
        &self.allocation
    }

    #[must_use]
    pub fn post_plan(&self) -> &PostPlan {
        &self.post
    }

    /// Persist these ordinary PostPlan bytes before attempting commit. They can
    /// be decoded in another process and passed to AsyncBook::commit_plan.
    /// This retains the exact posted effects, not the unused eligibility list.
    #[must_use]
    pub fn into_post_plan(self) -> PostPlan {
        self.post
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §5.7 (explicit open-item applications through the posting kernel)",
        "supply an Original or Adjusting payment with empty settles lists, one positive applying leg, and explicit same-account/unit/dimension targets",
    )
}

fn invalidated(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §5.1 / §10.4 (allocation and kernel rehearsal use the same basis)",
        "prepare and review a fresh settlement; after an uncertain commit retry the original authenticated PostPlan instead of reallocating",
    )
}

fn allocation_request(request: &SettlementPostRequest) -> Result<SettlementRequest, Refusal> {
    let proposal = &request.proposal;
    if !matches!(proposal.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING)
        || !matches!(&proposal.origin, EntryOrigin::Intent { .. })
    {
        return Err(invalid(
            "settlement requires an Intent-origin Original or Adjusting proposal",
        ));
    }
    if proposal.legs.len() > MAX_LEGS_PER_ENTRY
        || request.targets.is_empty()
        || request.targets.len() > MAX_SETTLES_PER_LEG
    {
        return Err(invalid(
            "settlement legs or selected targets exceed the model bounds, or no targets were selected",
        ));
    }
    if proposal.legs.iter().any(|leg| !leg.settles.is_empty()) {
        return Err(invalid(
            "settlement preparation never overwrites or combines existing applications",
        ));
    }
    let leg = proposal
        .legs
        .get(usize::from(request.payment_leg))
        .ok_or_else(|| invalid("the applying leg ordinal is outside the payment proposal"))?;
    if leg.amount.mantissa <= 0 {
        return Err(invalid("the applying leg must have a positive amount"));
    }
    Ok(SettlementRequest {
        account: leg.account_ref,
        unit_id: leg.amount.unit.0,
        side: leg.side,
        amount: leg.amount.mantissa,
        effective_date: proposal.effective_date,
        targets: request.targets.clone(),
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Resolve allocation and full target digests at one HEAD snapshot. Both
    /// whole-book read admission and explicit posting admission precede any
    /// storage observation. This follows the existing book-scoped read posture:
    /// selecting an account does not turn a narrow capability into a read grant.
    ///
    /// Every selected target is checked, even after the payment is exhausted.
    /// Differing dimension sets are refused rather than guessing party/entity
    /// equivalence. If every target is already closed, no payment is prepared.
    /// Overpayments remain explicit unapplied amounts on the applying leg.
    ///
    /// To acquire approvals, first review proposal().proposal_digest(), then
    /// call plan_settlement with the ORIGINAL request and those approvals. An
    /// approval commit advances HEAD, so the fresh preparation must reproduce
    /// the approved proposal; the kernel refuses any changed approval binding.
    pub fn prepare_settlement(
        &self,
        cx: &PurposeContexts,
        request: SettlementPostRequest,
        capability: &Capability,
    ) -> Outcome<PreparedSettlement> {
        let book = self.context();
        let principal = request.proposal.principal_ref;
        if let Err(denial) = fa_policy::admit_read(capability, principal, book.book_id) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        if request.proposal.book_id != book.book_id || request.proposal.branch_id != Id128::TRUNK {
            return Ok(Err(invalid(
                "the payment must target this book's writable trunk",
            )));
        }
        let selection = match allocation_request(&request) {
            Ok(selection) => selection,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let explicit: Vec<_> = request
            .proposal
            .legs
            .iter()
            .map(|leg| (leg.amount.unit, leg.amount.mantissa))
            .collect();
        if let Err(denial) = fa_policy::admit(
            capability,
            &fa_policy::Intent {
                principal,
                trunk: true,
                op: fa_policy::Op::Post,
                book: book.book_id,
                legs: &explicit,
            },
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        query.with_restriction(|| {
            let at = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, at) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) =
                fa_journal::policy::capability_admitted(&self.db, book, capability)?
            {
                return Ok(Err(refusal));
            }
            let report = match fa_registers::open_items::open_items_report(
                &self.db,
                book,
                Some(selection.account),
                Some(at),
            ) {
                Ok(report) => report,
                Err(RegisterError::InvalidSelection(message)) => return Ok(Err(invalid(message))),
                Err(error) => return Err(error.into()),
            };
            let allocation = match report.plan_settlement(&selection) {
                Ok(allocation) => allocation,
                Err(RegisterError::InvalidSelection(message)) => return Ok(Err(invalid(message))),
                Err(error) => return Err(error.into()),
            };
            if allocation.allocations.is_empty() {
                return Ok(Err(invalid(
                    "no selected item has an open amount; no payment was prepared",
                )));
            }
            // Read the immutable payload, not a caller-provided digest or the
            // derived SETTLES/APPLIED projection. Duplicate entry reads are
            // coalesced when several selected legs belong to the same entry.
            let mut entries = BTreeMap::<VId, Entry>::new();
            let dimensions = &request.proposal.legs[usize::from(request.payment_leg)].dimension_set;
            for (vid, ordinal) in &allocation.request.targets {
                query.checkpoint().map_err(BookError::Context)?;
                if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(*vid) {
                    let row = self
                        .db
                        .vertex_at(*vid, at)
                        .map_err(KernelError::from)?
                        .filter(|row| row.labels.contains(&label::ENTRY))
                        .ok_or_else(|| {
                            KernelError::Corrupt("open-item target payload is missing".into())
                        })?;
                    let entry =
                        Entry::decode(&bytes(&row, property::FA_PAYLOAD, "settlement target")?)
                            .map_err(KernelError::from)?;
                    if entry.proposal.book_id != book.book_id
                        || entry.proposal.branch_id != Id128::TRUNK
                    {
                        return Err(KernelError::Corrupt(
                            "open-item target belongs to another coordinate".into(),
                        )
                        .into());
                    }
                    slot.insert(entry);
                }
                let entry = entries.get(vid).ok_or_else(|| {
                    KernelError::Corrupt("resolved settlement target is missing".into())
                })?;
                let leg = entry
                    .proposal
                    .legs
                    .get(usize::from(*ordinal))
                    .ok_or_else(|| {
                        KernelError::Corrupt("open-item target ordinal is missing".into())
                    })?;
                if &leg.dimension_set != dimensions {
                    return Ok(Err(invalid(
                        "settlement target dimensions differ from the applying leg",
                    )));
                }
            }
            let references: BTreeMap<VId, EntryRef> = entries
                .iter()
                .map(|(vid, entry)| (*vid, entry.entry_ref(*vid)))
                .collect();
            let settles = allocation
                .allocations
                .iter()
                .map(|part| {
                    let target = references.get(&part.entry).copied().ok_or_else(|| {
                        KernelError::Corrupt("allocation has no resolved target digest".into())
                    })?;
                    Ok(Settlement {
                        target,
                        ordinal: part.ordinal,
                        amount: Amount::new(UnitId(selection.unit_id), part.amount),
                    })
                })
                .collect::<Result<Vec<_>, KernelError>>()?;
            let mut proposal = request.proposal;
            proposal.legs[usize::from(request.payment_leg)].settles = settles;
            // Model validation checks structure and redundant unit totals. It
            // does not reseal the caller's text or judge economic posting laws.
            if let Err(error) = proposal.validate() {
                return Ok(Err(invalid(error.to_string())));
            }
            query.checkpoint().map_err(BookError::Context)?;
            Ok(Ok(PreparedSettlement {
                allocation,
                proposal,
            }))
        })
    }

    /// Rehearse the completed proposal through all ordinary production laws.
    /// Planning publishes nothing. This convenience path allocates at the
    /// current HEAD; use [`Self::plan_prepared_settlement`] to bind planning to
    /// a preparation already reviewed by the caller. Approvals must bind the
    /// completed proposal, not the original proposal with empty settles lists.
    pub fn plan_settlement(
        &mut self,
        cx: &PurposeContexts,
        request: SettlementPostRequest,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<SettlementPostPlan> {
        let prepared = match self.prepare_settlement(cx, request, capability)? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.plan_prepared_settlement(cx, prepared, approvals, capability)
    }

    /// Rehearse the EXACT preparation the caller reviewed, without allocating
    /// again or silently accepting a newer open-item snapshot. The private
    /// preparation retains the reviewed proposal and its original basis.
    /// A newer basis (even an unrelated publication) requires explicit review
    /// of a fresh preparation. If a target was consumed meanwhile, the kernel
    /// may refuse the application before this method's strict basis check.
    ///
    /// This is not an approval-refresh path: recording a new approval advances
    /// HEAD. To obtain approvals, prepare the proposal, record its digest's
    /// approvals, then use [`Self::plan_settlement`] with the original request;
    /// the kernel checks those approvals against the newly completed proposal.
    /// Review the returned plan before publishing it. Neither path automatically
    /// retries a refusal or submits a payment.
    pub fn plan_prepared_settlement(
        &mut self,
        cx: &PurposeContexts,
        prepared: PreparedSettlement,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<SettlementPostPlan> {
        let book = self.context();
        if let Err(denial) =
            fa_policy::admit_read(capability, prepared.proposal.principal_ref, book.book_id)
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if prepared.proposal.book_id != book.book_id || prepared.proposal.branch_id != Id128::TRUNK
        {
            return Ok(Err(invalid(
                "the reviewed payment belongs to another book or branch",
            )));
        }
        // The real kernel performs current posting admission, revocation and
        // expiry checks before returning an authenticated rehearsal. A prior
        // preparation is never an authority grant, even at the same sequence.
        let intent = match PostIntent::new(prepared.proposal, approvals) {
            Ok(intent) => intent,
            Err(error) => return Ok(Err(invalid(error.to_string()))),
        };
        let post = match self.plan(cx, intent, capability)? {
            Ok(post) => post,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if post.certificate().snapshot_seq != prepared.allocation.known_at {
            return Ok(Err(invalidated(
                "the allocation basis changed before kernel rehearsal",
            )));
        }
        // Balancing requests may legitimately resolve to different amounts in
        // the general posting API. That would invalidate our unapplied amount
        // and allocation explanation even if the resulting entry were lawful.
        if post.proposal().legs != post.intent().proposal().legs {
            return Ok(Err(invalidated(
                "kernel rehearsal changed the payment legs; supply explicit non-balancing amounts",
            )));
        }
        Ok(Ok(SettlementPostPlan {
            allocation: prepared.allocation,
            post,
        }))
    }

    /// Publish the unchanged kernel plan and its durable evidence atomically.
    /// Do NOT reallocate or compare against today's open items here: after a
    /// successful commit they have necessarily changed. The kernel recognizes
    /// the exact recorded plan before its stale-basis check, and still checks
    /// the caller's current authority on every retry.
    pub async fn commit_settlement_plan(
        &mut self,
        cx: &PurposeContexts,
        plan: SettlementPostPlan,
        capability: &Capability,
    ) -> Outcome<Posted> {
        self.commit_plan(cx, plan.post, capability).await
    }
}
