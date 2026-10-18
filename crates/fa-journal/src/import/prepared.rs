//! Shared import admission and single-transaction publication.
//!
//! The transaction retains its original capability, policy and identity
//! witnesses across external I/O and any caller-controlled preparation delay.

use asupersync::fs::Vfs;
use fa_model::symbols::{label, relation};
use fa_model::{ControlPayload, Entry, entry_mirrors, entry_vid};
use fa_policy::{Capability, Intent, Party};
use fa_registry::evidence_policy::EvidencePolicy;
use fgdb::{Database, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::custody::{custody_vid, stage_receipt};
use crate::evidence::{document_vid, drift, inline_document_bound, stage_document, verify_row};
use crate::genesis::BookContext;
use crate::policy::{authorize_approvals, capability_witness, epoch_witness, refusal, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::edge_id;

use super::{
    ImportDocument, ImportRecorded, ImportRequest, prepare, receipt_of, recorded_or_conflict,
};

/// An exact retry needs no publication; a new run retains all original witnesses.
#[derive(Debug)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum ImportPreparation {
    AlreadyRecorded(ImportRecorded),
    Ready(Box<PreparedImport>),
}

/// A whole import, ready to publish. No document, custody event, import edge
/// or run entry is visible until `commit` succeeds. External bytes may already
/// be durable; dropping/aborting this object can leave only unreferenced blobs.
#[must_use]
pub struct PreparedImport {
    txn: WriteTxn,
    book: BookContext,
    capability: Capability,
    entry: Entry,
    run: VId,
    recorded: Vec<fa_model::Oid>,
    already_held: Vec<fa_model::Oid>,
}

impl core::fmt::Debug for PreparedImport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedImport")
            .field("run", &self.run)
            .field("basis", &self.txn.basis())
            .field("new_documents", &self.recorded.len())
            .finish_non_exhaustive()
    }
}

fn conflict(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        message,
        "FG-LAW-FCW-01 (the original import admission, policy and document identity witnesses)",
        "retry the complete import under current authority; already-held documents keep their first custody receipts",
    )
}

impl PreparedImport {
    #[must_use]
    pub fn basis(&self) -> CommitSeq {
        self.txn.basis()
    }

    #[must_use]
    pub fn run(&self) -> VId {
        self.run
    }

    pub fn abort(self) {
        self.txn.abort();
    }

    /// Bind an already-validated account mapping to this import's original
    /// transaction. A later account change invalidates the retained read witness.
    /// This adds no graph effects and never refreshes publication authority.
    pub fn witness_account<V: Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        expected: &crate::rows::AccountRow,
    ) -> Outcome<()> {
        if expected.vid != fa_model::account_vid(self.book.book_id, &expected.code) {
            return Ok(Err(conflict("the import account mapping belongs to another book")));
        }
        let Some(row) = self.txn.vertex(db, expected.vid)? else {
            return Ok(Err(conflict("the import account disappeared before preparation")));
        };
        if !row.labels.contains(&label::ACCOUNT)
            || crate::rows::AccountRow::decode(&row)? != *expected
        {
            return Ok(Err(conflict("the import account changed before preparation")));
        }
        Ok(Ok(()))
    }

    /// Recheck expiry and commit the original witnessed transaction. Never
    /// refresh its policy/revocation witnesses after external bytes are written.
    pub async fn commit<V: Vfs + Clone>(
        self,
        db: &mut Database<V>,
        cx: &PurposeContexts,
    ) -> Outcome<ImportRecorded> {
        let Self {
            mut txn,
            book,
            capability,
            entry,
            run,
            recorded,
            already_held,
        } = self;
        let commit = cx.commit();
        if let Err(error) = commit.checkpoint() {
            txn.abort();
            return Err(WriteTxnError::Interrupted(error).into());
        }
        if let Err(denial) = fa_policy::current(&capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(refusal(&denial)));
        }
        match txn.commit(db, &commit).await {
            Ok(seq) => {
                let receipt = receipt_of(&entry, run, seq).ok_or_else(|| {
                    KernelError::Corrupt("an import run without its receipt".into())
                })?;
                Ok(Ok(ImportRecorded {
                    receipt,
                    recorded,
                    already_held,
                    already_recorded: false,
                }))
            }
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
                Ok(Err(conflict(format!(
                    "a concurrent commit invalidated an import witness: {detail}"
                ))))
            }
            Err(WriteTxnError::Write(
                fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
            )) => match db.vertex(run)? {
                Some(row) => {
                    recorded_or_conflict(&book, &row, &entry.proposal, &entry.proposal_digest)
                }
                None => Ok(Err(conflict(
                    "a document in this import was recorded concurrently",
                ))),
            },
            Err(error) => Err(error.into()),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(super) enum Admission {
    AlreadyRecorded(ImportRecorded),
    New(Box<AdmittedImport>),
}

pub(super) struct AdmittedImport {
    pub(super) txn: WriteTxn,
    pub(super) book: BookContext,
    capability: Capability,
    entry: Entry,
    run: VId,
    pub(super) documents: Vec<ImportDocument>,
    already_held: Vec<fa_model::Oid>,
}

impl AdmittedImport {
    /// Storage changes only document payload placement; every other row is
    /// constructed once here and is identical for inline and external intake.
    pub(super) fn batches_with(
        &self,
        cx: &PurposeContexts,
        mut stage: impl FnMut(&mut WriteBatch, &ImportDocument) -> Result<(), KernelError>,
    ) -> Result<Vec<WriteBatch>, KernelError> {
        let Some(ControlPayload::ImportRun { source, .. }) = &self.entry.proposal.control else {
            return Err(KernelError::Corrupt(
                "prepared import has no source receipt".into(),
            ));
        };
        let mut custody = WriteBatch::new(relation::CUSTODY_OF);
        custody.create_vertex(self.run, vec![label::ENTRY], entry_mirrors(&self.entry)?);
        let mut imported = WriteBatch::new(relation::IMPORTED_BY);
        for doc in &self.documents {
            cx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
            stage(&mut custody, doc)?;
            let receipt = stage_receipt(
                &mut custody,
                &self.book,
                &doc.document,
                source.clone(),
                self.entry.proposal.principal_ref,
                Some(self.run),
            )?;
            debug_assert_eq!(receipt, custody_vid(self.book.book_id, &doc.oid, 0));
            imported.add_edge(
                edge_id(relation::IMPORTED_BY, receipt, self.run),
                receipt,
                self.run,
                vec![],
            );
        }
        let mut batches = vec![custody, imported];
        batches.retain(|batch| !batch.is_empty());
        Ok(batches)
    }

    pub(super) fn stage<V: Vfs + Clone>(
        mut self,
        db: &mut Database<V>,
        batches: Vec<WriteBatch>,
    ) -> Result<Box<PreparedImport>, KernelError> {
        if let Err(error) = self.txn.write_ordered(db, batches) {
            self.txn.abort();
            return Err(error.into());
        }
        Ok(Box::new(PreparedImport {
            txn: self.txn,
            book: self.book,
            capability: self.capability,
            entry: self.entry,
            run: self.run,
            recorded: self.documents.into_iter().map(|doc| doc.oid).collect(),
            already_held: self.already_held,
        }))
    }
}

/// Admit before hashing, reading document metadata or writing any blob.
/// `None` means the existing inline-only API; a store supplies its own bound.
pub(super) fn admit<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    req: ImportRequest,
    store_bound: Option<u64>,
) -> Outcome<Admission> {
    cx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    let steward = steward()?;
    let key = fa_policy::sod::control_key("ImportControl", None, "Import");
    let Some(op) = steward.preparer_op(&key) else {
        return Err(KernelError::Corrupt(
            "sod_policy.toml has no import-run rule".into(),
        ));
    };
    if let Err(denial) = fa_policy::admit(
        capability,
        &Intent {
            principal: req.principal,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(refusal(&denial)));
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(refusal(&denial)));
    }
    let policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let derived_grade = crate::upload::upload_grade(&policy, capability.profile())?;
    let machine_grade = crate::upload::upload_grade(&policy, fa_policy::Profile::Agent)?;
    let txn_cx = cx.txn();
    let txn = db.begin(&txn_cx)?;
    if let Err(refused) = capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refused));
    }
    let epoch = epoch_witness(&txn, db)?;
    let limit = store_bound.unwrap_or_else(|| inline_document_bound(&policy));
    let (proposal, docs) = match prepare(
        book,
        &policy,
        capability,
        derived_grade,
        machine_grade,
        req,
        limit,
    ) {
        Ok(prepared) => prepared,
        Err(refused) => {
            txn.abort();
            return Ok(Err(refused));
        }
    };
    let digest = proposal.proposal_digest()?;
    let run = entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    if let Some(row) = txn.vertex(db, run)? {
        txn.abort();
        return Ok(
            recorded_or_conflict(book, &row, &proposal, &digest)?.map(Admission::AlreadyRecorded)
        );
    }
    let preparer = Party {
        principal: proposal.principal_ref,
        profile: capability.profile(),
    };
    if let Err(refused) =
        authorize_approvals(&txn, db, book, &[], &digest, epoch, &key, 0, preparer)?
    {
        txn.abort();
        return Ok(Err(refused));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut documents = Vec::new();
    let mut already_held = Vec::new();
    for doc in docs {
        cx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
        match txn.vertex(db, document_vid(&doc.oid))? {
            Some(row) => {
                let stored = match verify_row(&row, &policy) {
                    Ok(stored) => stored,
                    Err(why) => {
                        txn.abort();
                        return Ok(Err(drift(&doc.oid, &why)));
                    }
                };
                if stored.oid() != doc.oid || stored.doc_commit != doc.doc_commit {
                    txn.abort();
                    return Ok(Err(drift(
                        &doc.oid,
                        "the full document identity differs from the requested import",
                    )));
                }
                already_held.push(doc.oid);
            }
            None => documents.push(doc),
        }
    }
    Ok(Ok(Admission::New(Box::new(AdmittedImport {
        txn,
        book: book.clone(),
        capability: capability.clone(),
        entry,
        run,
        documents,
        already_held,
    }))))
}

/// Prepare an inline import without publishing any graph effects.
/// Exact retries still require current, non-revoked import authority.
pub fn prepare_import<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    req: ImportRequest,
) -> Outcome<ImportPreparation> {
    let admitted = match admit(db, cx, book, capability, req, None)? {
        Err(refused) => return Ok(Err(refused)),
        Ok(Admission::AlreadyRecorded(recorded)) => {
            return Ok(Ok(ImportPreparation::AlreadyRecorded(recorded)));
        }
        Ok(Admission::New(admitted)) => admitted,
    };
    let batches = match admitted.batches_with(cx, |batch, doc| {
        stage_document(batch, &admitted.book, &doc.document, &doc.kind)
    }) {
        Ok(batches) => batches,
        Err(error) => {
            admitted.txn.abort();
            return Err(error);
        }
    };
    Ok(Ok(ImportPreparation::Ready(admitted.stage(db, batches)?)))
}
