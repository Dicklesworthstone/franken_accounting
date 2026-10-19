//! Retained confirmation of a replayed, exact bank-line proposal.

use super::*;
use fa_journal::bank::{self as native, BankMatchRecorded};
use fa_registers::reconciliation::pinned_bank_candidate;

/// Select the exact bytes emitted by `match_bank_statement`. The proposer is
/// part of those bytes; current authority and confirmation attribution belong
/// to the capability supplied to `confirm_bank_statement_match`.
#[derive(Clone, Debug)]
pub struct BankConfirmationRequest {
    pub manifest_oid: Oid,
    pub line_ordinal: u32,
    pub proposal_digest: [u8; 32],
    pub source_known_at: CommitSeq,
    pub date_window_days: u32,
    pub proposer: VId,
}

#[derive(Clone, Debug)]
pub struct BankStatusRequest {
    pub manifest_oid: Oid,
    pub known_at: Option<CommitSeq>,
}

/// An inventory of immutable confirmation facts for one retained statement.
/// A later reversal does not erase a confirmation. This is not a complete
/// reconciliation fold or an assertion of the account's closing balance.
#[derive(Clone, Debug)]
pub struct BankConfirmationStatus {
    pub manifest_oid: Oid,
    pub manifest: BankImportManifest,
    pub known_at: CommitSeq,
    pub confirmations: Vec<BankMatchRecorded>,
}

fn selection_refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::BANK_MATCH,
        exit::REFUSAL,
        message,
        "plan §5.7 (a confirmed bank match binds the exact retained source and actual cash leg)",
        "run fa bank match under current full-source authority, review an unambiguous proposal, and pass its exact confirmation_command; occupied lines and legs cannot be reused",
    )
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Reopen the retained source, reconstruct the complete pinned proposal,
    /// and publish one native line-to-leg confirmation under current authority.
    /// Exact retries return the original fact even after later journal activity.
    pub async fn confirm_bank_statement_match(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankConfirmationRequest,
    ) -> Outcome<BankMatchRecorded> {
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        if capability.profile() != Profile::Human {
            return Ok(Err(fa_journal::policy::refusal(
                &fa_policy::Denial::ApproverProfile {
                    rule: "bank_match_confirmer".into(),
                    approver: capability.holder(),
                    profile: capability.profile(),
                    allowed: vec!["Human".into()],
                },
            )));
        }
        let seq = self.query(cx, |db, _| {
            Ok(fa_registers::resolve_known_at(
                db,
                Some(request.source_known_at),
            )?)
        })?;
        let verified = match self
            .load_bank_import(cx, capability, request.manifest_oid, seq)
            .await?
        {
            Ok(verified) => verified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let predecessors = match self
            .verify_bank_predecessors(cx, capability, &verified, seq)
            .await?
        {
            Ok(witnesses) => witnesses,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(index) = verified
            .lines
            .iter()
            .position(|line| line.line_ordinal == request.line_ordinal)
        else {
            return Ok(Err(selection_refusal(
                "the selected line ordinal is absent from the retained statement",
            )));
        };
        let context = self.context().clone();
        let match_vid = native::bank_match_vid(
            context.book_id,
            verified.manifest.statement_oid,
            request.line_ordinal,
        );
        match native::read_bank_match(
            &mut self.db,
            cx,
            &context,
            capability,
            match_vid,
            None,
            Some(&verified.manifest),
        )
        .await?
        {
            Err(refusal) => return Ok(Err(refusal)),
            Ok(Some(mut recorded)) => {
                let prior = &recorded.confirmation;
                if prior.manifest_oid != request.manifest_oid
                    || prior.line_ordinal != request.line_ordinal
                    || prior.proposal_digest != request.proposal_digest
                    || prior.source_known_at != request.source_known_at
                    || prior.date_window_days != request.date_window_days
                    || prior.proposer != request.proposer
                {
                    return Ok(Err(selection_refusal(
                        "this bank line already has a different immutable confirmation",
                    )));
                }
                recorded.already_recorded = true;
                return Ok(Ok(recorded));
            }
            Ok(None) => {}
        }
        let report = match self
            .match_bank_statement_for(
                cx,
                capability,
                BankMatchRequest {
                    manifest_oid: request.manifest_oid,
                    known_at: Some(seq),
                    date_window_days: request.date_window_days,
                },
                request.proposer,
            )
            .await?
        {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if report.manifest != verified.manifest || report.lines != verified.lines {
            return Ok(Err(closure_drift(
                "the retained source changed while its confirmation was being prepared",
            )));
        }
        let proposal = &report.proposals[index];
        let Some(candidate_ordinal) = proposal.matched_entry_ordinal else {
            return Ok(Err(selection_refusal(
                "the selected bank line has no exact cash-leg proposal",
            )));
        };
        if proposal
            .oid()
            .map_err(|error| corrupt(error.to_string()))?
            .0
            != request.proposal_digest
        {
            return Ok(Err(selection_refusal(
                "the selected proposal digest does not replay at its source coordinate and current policy",
            )));
        }
        let Some(candidate) = usize::try_from(candidate_ordinal)
            .ok()
            .and_then(|ordinal| report.candidates.get(ordinal))
        else {
            return Err(corrupt(
                "the replayed proposal has an invalid cash-leg ordinal",
            ));
        };
        let window = i32::try_from(request.date_window_days)
            .map_err(|_| corrupt("the admitted bank date window exceeds i32"))?;
        let line = &report.lines[index];
        let mut eligible = 0_usize;
        for item in &report.candidates {
            if pinned_bank_candidate(line, &item.candidate, window)
                .map_err(|error| corrupt(error.to_string()))?
            {
                eligible += 1;
            }
        }
        let mut competitors = 0_usize;
        for other in &report.lines {
            if pinned_bank_candidate(other, &candidate.candidate, window)
                .map_err(|error| corrupt(error.to_string()))?
            {
                competitors += 1;
            }
        }
        if eligible != 1 || competitors != 1 {
            return Ok(Err(selection_refusal(
                "this proposal is ambiguous before candidate consumption; exact confirmation requires one eligible cash leg and one eligible bank line",
            )));
        }
        let mut line_documents = Vec::with_capacity(verified.manifest.line_oids.len());
        for oid in &verified.manifest.line_oids {
            match self.full_bank_document(cx, capability, *oid).await? {
                Ok(document) => line_documents.push(document),
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        let line_document = line_documents[index].clone();
        // Capture precedes source replay; the kernel retains these original
        // point witnesses through the transaction that publishes the match.
        Ok(native::confirm_bank_match(
            &mut self.db,
            cx,
            &context,
            capability,
            native::BankMatchRequest {
                import: verified.witness,
                predecessors: predecessors.into_iter().skip(1).collect(),
                line: line_document,
                lines: line_documents,
                entry_ref: candidate.candidate.entry_ref,
                leg_ordinal: candidate.leg_ordinal,
                source_known_at: seq,
                date_window_days: request.date_window_days,
                candidate_ordinal,
                proposer: request.proposer,
                proposal_digest: request.proposal_digest,
                decision_card: proposal.decision_card.clone(),
            },
        )
        .await?)
    }

    /// Read the recorded confirmations for every retained line, including
    /// explicit absence at the selected prefix. Native birth checks detect
    /// deleted or relabelled facts; a current-label scan cannot drop them.
    pub async fn bank_confirmation_status(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankStatusRequest,
    ) -> Outcome<BankConfirmationStatus> {
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        let seq = self.query(cx, |db, _| {
            Ok(fa_registers::resolve_known_at(db, request.known_at)?)
        })?;
        let verified = match self
            .load_bank_import(cx, capability, request.manifest_oid, seq)
            .await?
        {
            Ok(verified) => verified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = self
            .verify_bank_predecessors(cx, capability, &verified, seq)
            .await?
        {
            return Ok(Err(refusal));
        }
        let context = self.context().clone();
        let mut confirmations = Vec::new();
        for (index, line) in verified.lines.iter().enumerate() {
            let vid = native::bank_match_vid(
                context.book_id,
                verified.manifest.statement_oid,
                line.line_ordinal,
            );
            match native::read_bank_match(
                &mut self.db,
                cx,
                &context,
                capability,
                vid,
                Some(seq),
                Some(&verified.manifest),
            )
            .await?
            {
                Err(refusal) => return Ok(Err(refusal)),
                Ok(None) => {}
                Ok(Some(recorded)) => {
                    if recorded.confirmation.account != verified.manifest.account
                        || recorded.confirmation.line_document_oid
                            != verified.manifest.line_oids[index]
                    {
                        return Ok(Err(selection_refusal(
                            "this source line was confirmed under a different retained interpretation or cash account; inspect the original confirmation manifest",
                        )));
                    }
                    confirmations.push(recorded);
                }
            }
        }
        Ok(Ok(BankConfirmationStatus {
            manifest_oid: request.manifest_oid,
            manifest: verified.manifest,
            known_at: seq,
            confirmations,
        }))
    }
}
