//! Approve an exact saved review without manufacturing posting authority.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::rows::bytes;
use fa_journal::{Approved, KernelError, Refusal, exit};
use fa_model::symbols::{label, property};
use fa_model::{Entry, Id128};
use fa_policy::{Capability, Op};
use fa_registers::RegisterError;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, BookError, Outcome};

use super::{SettlementReview, changed};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Record an approval of the exact settlement proposal the caller reviewed.
    /// The independently retained review digest is mandatory and is checked
    /// before target observation. The review grants no authority: the approver
    /// supplies CURRENT whole-book read and approve capabilities, not post.
    /// Its per-unit ceilings apply to every payment leg, including offsets.
    /// The preparer cannot use this operation to approve their own proposal.
    ///
    /// Recompute all allocation witnesses and full target handles at HEAD before
    /// recording the approval through the ordinary kernel. A changed payment or
    /// open amount refuses without an approval publication; unrelated commits
    /// (including prior approvals) may advance the basis. The digest identifies
    /// an unsigned request, not proof of the review's author or old snapshot.
    ///
    /// This checks the review's current application observations, not all
    /// economic posting laws. The eventual plan still requires the preparer's
    /// posting authority and validates evidence, balance, period, policy and
    /// SoD. The returned ApprovalRef binds the proposal digest, NEVER the review
    /// container digest. No capability is copied from the review or broadened.
    pub async fn approve_settlement_review(
        &mut self,
        cx: &PurposeContexts,
        review: &SettlementReview,
        expected_review_digest: [u8; 32],
        capability: &Capability,
    ) -> Outcome<Approved> {
        let book = self.context();
        if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let explicit: Vec<_> = review
            .proposal()
            .legs
            .iter()
            .map(|leg| (leg.amount.unit, leg.amount.mantissa))
            .collect();
        // Approval authority can have amount ceilings too. Judge the actual
        // payment legs, not an empty approval-control payload, and use the
        // approver as actor without manufacturing a Post grant.
        if let Err(denial) = fa_policy::admit(
            capability,
            &fa_policy::Intent {
                principal: capability.holder(),
                trunk: true,
                op: Op::Approve,
                book: book.book_id,
                legs: &explicit,
            },
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if capability.holder() == review.proposal().principal_ref {
            return Ok(Err(Refusal::new(
                fa_journal::refusal::code::APPROVALS,
                exit::SAFETY,
                "the settlement preparer may not approve their own proposal",
                "plan §14.3 (separation of preparer and approver)",
                "have a different principal with read and approve authority review the saved payment",
            )));
        }
        if review.proposal().book_id != book.book_id || review.proposal().branch_id != Id128::TRUNK
        {
            return Ok(Err(changed()));
        }
        let digest = match review.digest() {
            Ok(digest) => digest,
            Err(error) => {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::STRUCTURE,
                    exit::USAGE,
                    error.to_string(),
                    "fa:settlement-review:v1 (bounded canonical request)",
                    "supply the unchanged review and its independently retained digest",
                )));
            }
        };
        if digest != expected_review_digest {
            return Ok(Err(changed()));
        }
        if let Err(refusal) = self
            .prepare_source_history(cx, capability.holder(), capability, Op::Approve, &explicit)
            .await?
        {
            return Ok(Err(refusal));
        }
        let book = self.context();
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        // The exclusive mutable book handle is retained through recording.
        // No unguarded read from a second handle or capability escalation is
        // needed to re-evaluate the deterministic allocation for an approver.
        let checked = query.with_restriction(|| -> Outcome<[u8; 32]> {
            let at = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, at) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) =
                fa_journal::policy::capability_admitted(&self.db, book, capability)?
            {
                return Ok(Err(refusal));
            }
            if at < review.allocation().known_at {
                return Ok(Err(changed()));
            }
            let request = &review.allocation().request;
            let report = match fa_registers::open_items::open_items_report(
                &self.db,
                book,
                Some(request.account),
                Some(at),
            ) {
                Ok(report) => report,
                Err(RegisterError::InvalidSelection(_)) => return Ok(Err(changed())),
                Err(error) => return Err(error.into()),
            };
            let allocation = match report.plan_settlement(request) {
                Ok(allocation) => allocation,
                Err(RegisterError::InvalidSelection(_)) => return Ok(Err(changed())),
                Err(error) => return Err(error.into()),
            };
            let mut expected = review.allocation().clone();
            expected.known_at = at;
            if allocation != expected {
                return Ok(Err(changed()));
            }
            let applying = &review.proposal().legs[usize::from(review.payment_leg())];
            let mut entries = BTreeMap::new();
            // Check EVERY eligible target, including unused ones. Rebuild full
            // handles from authoritative payloads, not the review's claimed
            // digest or mutable application mirrors.
            for (vid, ordinal) in &request.targets {
                query.checkpoint().map_err(BookError::Context)?;
                if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(*vid) {
                    let row = self
                        .db
                        .vertex_at(*vid, at)
                        .map_err(KernelError::from)?
                        .filter(|row| row.labels.contains(&label::ENTRY))
                        .ok_or_else(|| {
                            KernelError::Corrupt("review target payload is missing".into())
                        })?;
                    let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "review target")?)
                        .map_err(KernelError::from)?;
                    if entry.proposal.book_id != book.book_id
                        || entry.proposal.branch_id != Id128::TRUNK
                    {
                        return Err(KernelError::Corrupt(
                            "review target has a foreign coordinate".into(),
                        )
                        .into());
                    }
                    slot.insert(entry);
                }
                let entry = entries.get(vid).ok_or_else(|| {
                    KernelError::Corrupt("resolved review target is missing".into())
                })?;
                let leg = entry
                    .proposal
                    .legs
                    .get(usize::from(*ordinal))
                    .ok_or_else(|| {
                        KernelError::Corrupt("review target ordinal is missing".into())
                    })?;
                if leg.dimension_set != applying.dimension_set {
                    return Ok(Err(changed()));
                }
            }
            for link in &applying.settles {
                let entry = entries.get(&link.target.vid).ok_or_else(|| {
                    KernelError::Corrupt("review application target is missing".into())
                })?;
                if entry.entry_ref(link.target.vid) != link.target {
                    return Ok(Err(changed()));
                }
            }
            query.checkpoint().map_err(BookError::Context)?;
            Ok(Ok(review
                .proposal()
                .proposal_digest()
                .map_err(KernelError::from)?))
        })?;
        let proposal_digest = match checked {
            Ok(digest) => digest,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // record_approval rechecks current expiry and revocation inside its
        // ordinary transaction and binds the current policy epoch. This clone
        // retains exactly the supplied authority; no operation is added.
        self.approve(cx, capability.clone(), proposal_digest).await
    }
}
