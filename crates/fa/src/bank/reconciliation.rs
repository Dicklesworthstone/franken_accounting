//! Exact statement closing over the retained source and native cash history.

use super::*;

/// The reviewed journal prefix is explicit. A fresh close must still be
/// current at native admission; an exact retry returns its original immutable
/// attestation even after later postings or corrections.
#[derive(Clone, Debug)]
pub struct BankReconciliationRequest {
    pub manifest_oid: Oid,
    pub evaluated_known_at: CommitSeq,
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Attest an exact closing balance only after replaying the original
    /// statement, canonical lines, import receipt and predecessor chain.
    /// The native boundary independently derives the cumulative cash balance
    /// and active match set. No monetary claim supplied by the caller is used.
    pub async fn reconcile_bank_statement(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankReconciliationRequest,
    ) -> Outcome<BankReconciliationRecorded> {
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        if capability.profile() != Profile::Human {
            return Ok(Err(fa_journal::policy::refusal(
                &fa_policy::Denial::ApproverProfile {
                    rule: "bank_statement_reconciler".into(),
                    approver: capability.holder(),
                    profile: capability.profile(),
                    allowed: vec!["Human".into()],
                },
            )));
        }
        let seq = self.query(cx, |db, _| {
            Ok(fa_registers::resolve_known_at(
                db,
                Some(request.evaluated_known_at),
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
        let context = self.context().clone();
        Ok(fa_journal::bank::reconcile_bank_statement(
            &mut self.db,
            cx,
            &context,
            capability,
            fa_journal::bank::BankReconciliationRequest {
                import: verified.witness,
                predecessors: predecessors.into_iter().skip(1).collect(),
                evaluated_known_at: seq,
            },
        )
        .await?)
    }

    /// Verify immutable statement closes and compare their original cash and
    /// match claims with the selected prefix. This is a metadata read under
    /// current Read and Reconcile authority; it does not disclose source text
    /// or pretend that a later change invalidated an earlier historical claim.
    pub async fn bank_reconciliation_status(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankStatusRequest,
    ) -> Outcome<BankReconciliationStatus> {
        let context = self.context().clone();
        Ok(fa_journal::bank::bank_reconciliation_status(
            &mut self.db,
            cx,
            &context,
            capability,
            request.manifest_oid,
            request.known_at,
        )
        .await?)
    }
}
