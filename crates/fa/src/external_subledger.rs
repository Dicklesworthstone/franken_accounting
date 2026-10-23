//! Retained external-detail documents and matched native summary proposals.

use asupersync::fs::Vfs;
use fa_journal::DocumentRead;
use fa_model::{EntryPayload, EntryRef, Oid};
use fa_policy::{Capability, Op, Reach};
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

pub use fa_journal::external_subledger::{
    EXTERNAL_SUBLEDGER_DOCUMENT_KIND, EXTERNAL_SUBLEDGER_EVIDENCE_ROLE, EXTERNAL_SUBLEDGER_MIME,
    ExternalSubledgerBatch, ExternalSubledgerDetail, ExternalSubledgerReconciliation,
    MAX_EXTERNAL_DETAIL_BYTES, MAX_EXTERNAL_DETAIL_ROWS, MAX_EXTERNAL_SUMMARY_LEGS,
};

fn invalid(message: impl Into<String>) -> fa_journal::Refusal {
    fa_journal::Refusal::new(
        fa_journal::refusal::code::EXTERNAL_SUBLEDGER,
        fa_journal::exit::REFUSAL,
        message,
        "plan §5.6 / FA-INV-12 (external summaries reproduce retained reviewed detail)",
        "retain a canonical external-detail Workpaper, have an independent principal review it, then prepare an Original summary at its declared effective date",
    )
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read the exact retained source document under current Read and Post
    /// authority, then derive a complete native summary. This writes no entry
    /// or approval; the normal PostPlan kernel rechecks source, review,
    /// uniqueness, scope, period law and every generated leg at publication.
    pub async fn prepare_external_subledger(
        &mut self,
        cx: &PurposeContexts,
        document: Oid,
        mut template: EntryPayload,
        capability: &Capability,
    ) -> Outcome<EntryPayload> {
        let admission =
            fa_policy::admit_read(capability, template.principal_ref, self.context().book_id)
                .and_then(|()| {
                    fa_policy::require(
                        capability,
                        Op::Post,
                        "preparing an external subledger summary",
                    )
                })
                .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None));
        if let Err(denial) = admission {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let admitted = self.query(cx, |db, book| {
            Ok(fa_journal::policy::current_at(db, book, capability)?.map(|_| ()))
        })?;
        if let Err(refusal) = admitted {
            return Ok(Err(refusal));
        }
        let source = match self.read_document_for(cx, capability, &document).await? {
            Ok(DocumentRead::Full(source)) => source,
            Ok(DocumentRead::Redacted(_)) => {
                return Ok(Err(invalid(
                    "a redacted detail document cannot reproduce complete summary effects",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        if source.kind != EXTERNAL_SUBLEDGER_DOCUMENT_KIND
            || source.book_id != self.context().book_id
        {
            return Ok(Err(invalid(
                "external detail must be a Workpaper retained by this book",
            )));
        }
        let batch = match ExternalSubledgerBatch::decode(&source.bytes) {
            Ok(batch) => batch,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if batch.book_id != self.context().book_id || template.book_id != batch.book_id {
            return Ok(Err(invalid(
                "external detail and proposal must belong to this book",
            )));
        }
        let citation = match batch.evidence() {
            Ok(citation) => citation,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if citation.document_oid != document || citation.doc_commit != source.doc_commit() {
            return Ok(Err(invalid(
                "external detail does not reproduce the selected source document commitment",
            )));
        }
        if !template.evidence.contains(&citation) {
            template.evidence.push(citation);
            template.evidence.sort();
        }
        // The document read may have suspended for retained blob I/O. An
        // authority revoked meanwhile cannot obtain a prepared summary.
        let admitted = self.query(cx, |db, book| {
            Ok(fa_journal::policy::current_at(db, book, capability)?.map(|_| ()))
        })?;
        if let Err(refusal) = admitted {
            return Ok(Err(refusal));
        }
        Ok(batch.proposal(template))
    }

    /// Recompute one source/summary pair against the prefix where it was
    /// committed. Later source reviews or postings cannot repair old evidence.
    /// The current capability must admit the selected whole-book observation.
    pub fn reconcile_external_subledger_feed(
        &self,
        cx: &PurposeContexts,
        entry: EntryRef,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<ExternalSubledgerReconciliation> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(fa_journal::external_subledger::reconcile_at(
                db, book, entry, at,
            )?)
        })
    }
}
