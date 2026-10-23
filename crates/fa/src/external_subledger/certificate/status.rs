//! Freshness follows the named feed and complete selected control leaf, not
//! the larger native populations retained only to authenticate those inputs.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{AccountRow, KernelError};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin};
use fa_notary::Journal;

use super::*;
use crate::CertificateStatus;
use crate::external_subledger::reconciliation::{Entries, source_of};

fn account_at<V: Vfs + Clone>(
    db: &Database<V>,
    account: VId,
    at: CommitSeq,
) -> Result<Option<AccountRow>, BookError> {
    db.vertex_at(account, at)
        .map_err(KernelError::from)?
        .map(|row| AccountRow::decode(&row).map_err(BookError::from))
        .transpose()
}

fn selected(vid: VId, entries: &Entries, request: &ExternalFeedRequest) -> Result<bool, Refusal> {
    let entry = &entries[&vid].0;
    if entry.proposal.effective_date > request.effective_through {
        return Ok(false);
    }
    Ok(entry
        .proposal
        .legs
        .iter()
        .any(|leg| leg.account_ref == request.control_account)
        || source_of(entries, vid, &request.feed)?.is_some())
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay the saved assertion, then compare its exact current scope.
    /// Backdated postings, same-feed reversals, pending releases, migration
    /// finalization and selected account changes are attributed to immutable
    /// journal entries. Unexplained source or historical changes refuse.
    pub fn external_feed_certificate_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &ExternalFeedCertificate,
    ) -> Outcome<CertificateStatus> {
        let head = match authorize(self, cx, principal, capability, None, false)? {
            Ok(head) => head,
            Err(r) => return Ok(Err(r)),
        };
        let request = match certificate.request() {
            Ok(request) => request,
            Err(r) => return Ok(Err(r)),
        };
        let original =
            match self.replay_external_feed(cx, principal, capability, certificate, &request)? {
                Ok(report) => report,
                Err(r) => return Ok(Err(r)),
            };
        let current_request = ExternalFeedRequest {
            known_at: Some(head),
            ..request.clone()
        };
        let current =
            match self.reconcile_external_feed(cx, principal, capability, &current_request)? {
                Ok(report) => report,
                Err(r) => {
                    return Ok(Err(invalid(format!(
                        "current external-feed inputs do not replay: {}",
                        r.message
                    ))));
                }
            };
        self.query(cx, |db, book| {
            let before = account_at(db, request.control_account, certificate.known_at())?;
            let now = account_at(db, request.control_account, head)?;
            if original.same_assertion(&current) && before == now {
                return Ok(Ok(CertificateStatus::Current {checked_at: head}));
            }
            let journal = match Journal::read(db, book, Some(head), None)? {
                Ok(journal) => journal, Err(r) => return Ok(Err(r)),
            };
            let mut entries = BTreeMap::new();
            for leaf in &journal.leaves {
                cx.query().checkpoint().map_err(BookError::Context)?;
                entries.insert(leaf.vid, (
                    Entry::decode(&leaf.payload).map_err(KernelError::from)?,
                    leaf.envelope.commit_seq,
                ));
            }
            let mut later_entries = BTreeSet::new();
            let mut visibility = BTreeMap::new();
            let mut previous_metadata = before;
            let mut metadata_changes = BTreeMap::new();
            for leaf in &journal.leaves {
                cx.query().checkpoint().map_err(BookError::Context)?;
                if leaf.envelope.commit_seq <= certificate.known_at() { continue; }
                let entry = &entries[&leaf.vid].0;
                let mut relevant = match selected(leaf.vid, &entries, &request) {
                    Ok(value) => value, Err(r) => return Ok(Err(invalid(r.message))),
                } && fa_journal::migration::visible_at(db, entry, head, &mut visibility)?;
                // A resolution releases pending reserves at the recorded
                // frontier even when its own effective date is later.
                if entry.proposal.class == EntryClass::RESOLUTION
                    && let Some(target) = entry.proposal.pending.as_ref().and_then(|p| p.resolution_of)
                    && entries.contains_key(&target.vid)
                {
                    relevant |= match selected(target.vid, &entries, &request) {
                        Ok(value) => value, Err(r) => return Ok(Err(invalid(r.message))),
                    };
                }
                if let Some(ControlPayload::MigrationControl {run_ref, kind, ..}) = &entry.proposal.control
                    && *kind == fa_journal::migration::kind::FINALIZE
                {
                    for (vid, (migrated, _)) in &entries {
                        cx.query().checkpoint().map_err(BookError::Context)?;
                        if matches!(&migrated.proposal.origin,
                            EntryOrigin::Migration {run_ref: origin, ..} if origin == run_ref)
                            && fa_journal::migration::visible_at(db, migrated, head, &mut visibility)?
                        {
                            relevant |= match selected(*vid, &entries, &request) {
                                Ok(value) => value, Err(r) => return Ok(Err(invalid(r.message))),
                            };
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
            if previous_metadata != now || later_entries.is_empty() {
                return Ok(Err(invalid(
                    "the selected external-feed assertion changed outside later contributing publications; historical source or control metadata differs",
                )));
            }
            Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head, later_entries: later_entries.into_iter().collect(),
            }))
        })
    }
}
