//! Freshness of a retained report's accounting selection, after full replay.
//!
//! A roll-forward's native input is a whole-book closing balance. Its own
//! selection is narrower: selected posted accounts/units through the closing
//! date, including postings before the activity window that change opening
//! stock. Cash-flow families retain that same source schedule. A later entry
//! outside those coordinates does not supersede the selected report merely
//! because the native evidence closure also contains it.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin};
use fa_notary::Journal;

use super::*;
use crate::CertificateStatus;

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Verify the complete artifact under current read authority, then identify
    /// later journal entries affecting its accounting selection. Historical
    /// replay remains valid when a report is SupersededBy; this method writes
    /// nothing. Recipient-dependent families require the same independently
    /// retained request/definition as replay, even when a digest is supplied.
    ///
    /// Supports native reports, statement comparisons/traces, roll-forwards
    /// (including their GL detail view), and direct, split and policy cash flow.
    /// Other families refuse until their distinct relevance law is implemented.
    pub fn report_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
        expected: ReportArtifactExpectation<'_>,
    ) -> Outcome<CertificateStatus> {
        if let Err(refusal) = self.replay_report_artifact_for(
            cx,
            principal,
            capability,
            bytes,
            expected_digest,
            expected,
        )? {
            return Ok(Err(refusal));
        }
        let artifact = match ReportArtifact::decode(bytes) {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = match &artifact.inner {
            Artifact::Native(_) | Artifact::StatementDiff(_) | Artifact::StatementTrace(_) => {
                return self.certificate_status(cx, artifact.source_certificate());
            }
            Artifact::RollForward(c) => c.as_ref(),
            Artifact::CashFlow(c) => c.source_certificate(),
            Artifact::SplitCashFlow(c) => c.source_certificate(),
            Artifact::PolicyCashFlow(c) => c.certificate.source_certificate().source_certificate(),
            _ => {
                return Ok(Err(invalid(format!(
                    "{} certificate replayed, but its accounting-selection freshness law is not implemented; use its historical replay result",
                    artifact.family().name(),
                ))));
            }
        };
        self.roll_forward_artifact_status(cx, principal, capability, source)
    }

    /// `certificate` belongs to an artifact already replayed in full. Compare
    /// the actual selected schedule as well as enumerating its new causes, so
    /// an unexplained metadata or historical-row change cannot return Current.
    fn roll_forward_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &RollForwardCertificate,
    ) -> Outcome<CertificateStatus> {
        let head = self.head(cx)?;
        let mut request = certificate.request().clone();
        request.known_at = Some(head);
        let mut current = match self.roll_forward(cx, principal, capability, &request)? {
            Ok(report) => report,
            Err(refusal) => {
                return Ok(Err(invalid(format!(
                    "the current selected account schedule no longer evaluates: {}",
                    refusal.message,
                ))));
            }
        };
        // Recorded time is the one expected difference in an unchanged report.
        // Do not normalize dates, scope, account metadata, amounts or citations.
        current.known_at = certificate.known_at().0;
        let current_bytes = current
            .canonical_bytes()
            .map_err(|error| BookError::Kernel(KernelError::Model(error.into())))?;
        self.query(cx, |db, book| {
            let query = cx.query();
            let journal = match Journal::read(db, book, Some(head), None)? {
                Ok(journal) => journal,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let mut entries = BTreeMap::new();
            for leaf in &journal.leaves {
                query.checkpoint().map_err(BookError::Context)?;
                entries.insert(leaf.vid, Entry::decode(&leaf.payload).map_err(KernelError::from)?);
            }
            let accounts: BTreeSet<_> = request.accounts.iter().copied().collect();
            let units: BTreeSet<_> = request.units.iter().copied().collect();
            let selected = |entry: &Entry| {
                let proposal = &entry.proposal;
                !proposal.class.is_control()
                    && proposal.class != EntryClass::PENDING
                    && proposal.effective_date <= request.effective_through
                    && proposal.legs.iter().any(|leg| {
                        accounts.contains(&leg.account_ref)
                            && units.contains(&leg.amount.unit.0)
                            && leg.amount.mantissa != 0
                    })
            };
            let mut visibility = BTreeMap::new();
            let mut later_entries = Vec::new();
            for leaf in &journal.leaves {
                query.checkpoint().map_err(BookError::Context)?;
                if leaf.envelope.commit_seq <= certificate.known_at() {
                    continue;
                }
                let entry = &entries[&leaf.vid];
                let mut relevant = selected(entry)
                    && fa_journal::migration::visible_at(db, entry, head, &mut visibility)?;
                // Staging a migration is invisible. Finalization can make an
                // older staged entry contribute, so the later cause is the
                // immutable finalization control, not the staging sequence.
                if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) =
                    &entry.proposal.control
                    && *kind == fa_journal::migration::kind::FINALIZE
                {
                    for migrated in entries.values() {
                        query.checkpoint().map_err(BookError::Context)?;
                        if matches!(&migrated.proposal.origin,
                            EntryOrigin::Migration { run_ref: origin, .. } if origin == run_ref)
                            && selected(migrated)
                            && fa_journal::migration::visible_at(db, migrated, head, &mut visibility)?
                        {
                            relevant = true;
                        }
                    }
                }
                if relevant {
                    later_entries.push(leaf.vid);
                }
            }
            if !later_entries.is_empty() {
                return Ok(Ok(CertificateStatus::SupersededBy {
                    checked_at: head,
                    later_entries,
                }));
            }
            if current_bytes != certificate.output() {
                return Ok(Err(invalid(
                    "the selected account schedule changed outside later contributing entries; its metadata or historical contributions differ",
                )));
            }
            Ok(Ok(CertificateStatus::Current { checked_at: head }))
        })
    }
}
