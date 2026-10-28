//! Freshness follows the selected native control and party detail, not unrelated
//! populations that the native source retains only to authenticate replay.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{AccountRow, KernelError};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin};
use fa_notary::Journal;

use super::*;
use crate::{BookError, CertificateStatus};

fn account_at<V: Vfs + Clone>(
    db: &fgdb::Database<V>,
    account: VId,
    at: CommitSeq,
) -> Result<Option<AccountRow>, BookError> {
    db.vertex_at(account, at)
        .map_err(KernelError::from)?
        .map(|row| AccountRow::decode(&row).map_err(BookError::from))
        .transpose()
}

fn selected(entry: &Entry, request: &NativeSubledgerRequest) -> bool {
    entry.proposal.effective_date <= request.effective_through
        && entry
            .proposal
            .legs
            .iter()
            .any(|leg| leg.account_ref == request.control_account)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay the original assertion, then compare its current selected scope.
    /// Pending releases count even when their own dates fall after the cutoff.
    pub fn native_subledger_certificate_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &NativeSubledgerCertificate,
    ) -> Outcome<CertificateStatus> {
        let head = match authorize(self, cx, principal, capability, None, false)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let original =
            match self.replay_native_subledger(cx, principal, capability, certificate, &request)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let current = match self.reconcile_native_subledger(
            cx,
            &request.code,
            request.effective_through,
            Some(head),
            capability,
        )? {
            Ok(report) => report,
            Err(refusal) => {
                return Ok(Err(invalid(format!(
                    "current native subledger inputs do not replay: {}",
                    refusal.message,
                ))));
            }
        };
        self.query(cx, |db, book| {
            let before = account_at(db, request.control_account, certificate.known_at())?;
            let now = account_at(db, request.control_account, head)?;
            let unchanged = original.same_assertion(&current) && before == now;
            let journal = match Journal::read(db, book, Some(head), None)? {
                Ok(journal) => journal, Err(refusal) => return Ok(Err(refusal)),
            };
            let mut entries = BTreeMap::new();
            for leaf in &journal.leaves {
                cx.query().checkpoint().map_err(BookError::Context)?;
                entries.insert(leaf.vid, Entry::decode(&leaf.payload).map_err(KernelError::from)?);
            }
            let mut later_entries = BTreeSet::new();
            let mut visibility = BTreeMap::new();
            let mut previous_metadata = before;
            let mut metadata_changes = BTreeMap::new();
            for leaf in &journal.leaves {
                cx.query().checkpoint().map_err(BookError::Context)?;
                if leaf.envelope.commit_seq <= certificate.known_at() { continue; }
                let entry = &entries[&leaf.vid];
                let mut relevant = selected(entry, &request)
                    && fa_journal::migration::visible_at(db, entry, head, &mut visibility)?;
                if entry.proposal.class == EntryClass::RESOLUTION
                    && let Some(target) = entry.proposal.pending.as_ref().and_then(|pending| pending.resolution_of)
                    && let Some(pending) = entries.get(&target.vid)
                {
                    relevant |= selected(pending, &request);
                }
                if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) = &entry.proposal.control
                    && *kind == fa_journal::migration::kind::FINALIZE
                {
                    for migrated in entries.values() {
                        cx.query().checkpoint().map_err(BookError::Context)?;
                        if matches!(&migrated.proposal.origin,
                            EntryOrigin::Migration { run_ref: origin, .. } if origin == run_ref)
                            && selected(migrated, &request)
                            && fa_journal::migration::visible_at(db, migrated, head, &mut visibility)?
                        {
                            relevant = true;
                        }
                    }
                }
                if entry.proposal.class == EntryClass::SCHEMA_CONTROL {
                    let changed = if let Some(changed) = metadata_changes.get(&leaf.envelope.commit_seq) {
                        *changed
                    } else {
                        let current_metadata = account_at(db, request.control_account, leaf.envelope.commit_seq)?;
                        let changed = current_metadata != previous_metadata;
                        previous_metadata = current_metadata;
                        metadata_changes.insert(leaf.envelope.commit_seq, changed);
                        changed
                    };
                    relevant |= changed;
                }
                if relevant { later_entries.insert(leaf.vid); }
            }
            if previous_metadata != now {
                return Ok(Err(invalid(
                    "native subledger assertion changed outside later contributing publications; historical declaration, party detail or control metadata differs",
                )));
            }
            if later_entries.is_empty() {
                return if unchanged {
                    Ok(Ok(CertificateStatus::Current { checked_at: head }))
                } else {
                    Ok(Err(invalid("native subledger output changed without a later selected publication")))
                };
            }
            // Equal aggregate columns do not erase changed contributors. A
            // release and an equal replacement hold still supersede the saved
            // assertion, even though the outstanding pending amount is equal.
            let later_entries: Vec<_> = later_entries.into_iter().collect();
            let cases = crate::certificate::case_status::superseding_cases(
                book.book_id,
                journal.leaves.iter().map(|leaf| {
                    (leaf.vid, leaf.envelope.commit_seq, &entries[&leaf.vid])
                }),
                &later_entries,
            )?;
            Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head, later_entries, cases,
            }))
        })
    }
}
