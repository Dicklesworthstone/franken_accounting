//! Capability-bound document uploads (plan §9.3, fa-vwf).
//!
//! Unlike the embedded-owner `evidence::add_document` API, this entrypoint
//! accepts no caller-selected uploader or provenance grade. Uploads create
//! evidence objects, not monetary entries or branch-control entries: an Agent
//! with `post` may supply evidence, but this never permits it to post on trunk.
//! Human uploads are HumanUpload; machine uploads are conservatively
//! AgentUpload, never Connector, ThirdPartySigned or Generated. Those stronger
//! receipt-derived grades need their own verified acquisition paths.
//!
//! The caller must bind the capability from its authenticated session. This
//! module enforces that capability; it does not authenticate its transport.
//! Inline documents and their custody receipts publish in one witnessed
//! transaction. Existing raw intake APIs remain trusted embedded-owner APIs;
//! this module does not claim that those APIs or the CLI have been migrated.

use fa_model::{IntakeSource, Oid};
use fa_model::symbols::relation;
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fgdb::{Database, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use crate::evidence::{
    Document, DocumentAdded, document_vid, drift, intake_check, stage_document, verify_row,
};
use crate::genesis::BookContext;
use crate::policy;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

/// Bytes supplied by a session. Identity and provenance are derived, not input.
#[derive(Clone, Debug)]
pub struct UploadRequest {
    pub kind: u8,
    pub mime: String,
    pub bytes: Vec<u8>,
    /// An optional assertion, never a choice: it must equal the derived grade.
    pub asserted_grade: Option<u8>,
}

/// A repeat is complete; a new document retains its admission witnesses.
#[derive(Debug)]
#[must_use]
pub enum UploadPreparation {
    AlreadyRecorded(DocumentAdded),
    Ready(Box<PreparedUpload>),
}

#[derive(Debug)]
struct UploadSummary {
    oid: Oid,
    doc_commit: [u8; 32],
    kind: u8,
    grade: u8,
    size: u64,
}

/// The immutable document, receipt, and original capability witnesses.
/// Dropping or aborting this value publishes neither document nor receipt.
#[derive(Debug)]
#[must_use]
pub struct PreparedUpload {
    txn: WriteTxn,
    capability: Capability,
    summary: UploadSummary,
}

impl PreparedUpload {
    #[must_use]
    pub fn basis(&self) -> CommitSeq {
        self.txn.basis()
    }

    #[must_use]
    pub fn document_oid(&self) -> Oid {
        self.summary.oid
    }

    pub fn abort(self) {
        self.txn.abort();
    }

    /// Recheck sequence expiry and publish with the original revocation
    /// witnesses. An intervening revocation is a conflict, not refreshed away.
    pub async fn commit<V: asupersync::fs::Vfs + Clone>(
        self,
        db: &mut Database<V>,
        cx: &PurposeContexts,
    ) -> Outcome<DocumentAdded> {
        let commit = cx.commit();
        commit.checkpoint().map_err(WriteTxnError::Interrupted)?;
        let Self { mut txn, capability, summary } = self;
        if let Err(denial) = fa_policy::current(&capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(policy::refusal(&denial)));
        }
        match txn.commit(db, &commit).await {
            Ok(recorded_at) => Ok(Ok(DocumentAdded {
                oid: summary.oid,
                doc_commit: summary.doc_commit,
                vid: document_vid(&summary.oid),
                kind: summary.kind,
                grade: summary.grade,
                size: summary.size,
                recorded_at,
                already_recorded: false,
            })),
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { .. }
                | fgdb::WriteError::AlreadyLive { .. }
                | fgdb::WriteError::IdentitySpent { .. })) => Ok(Err(Refusal::new(
                    code::CONFLICT,
                    exit::CONFLICT,
                    "document intake lost an admission or identity witness",
                    "FA-INV-05; FA-INV-10; FG-LAW-FCW-01",
                    "retry the upload under current session authority; an existing document retains its original provenance and receipt",
                ))),
            Err(error) => Err(error.into()),
        }
    }
}

/// The registered grade of an upload, without reading storage or accepting a
/// caller's account of who supplied it. System uploads are self-sourced too.
pub fn upload_grade(policy: &EvidencePolicy, profile: Profile) -> Result<u8, KernelError> {
    let name = match profile {
        Profile::Human => "HumanUpload",
        Profile::Agent | Profile::System => "AgentUpload",
    };
    let grade = policy.grade_by_name(name).ok_or_else(|| {
        KernelError::Corrupt(format!("evidence policy has no {name} grade"))
    })?;
    if !grade.intake {
        return Err(KernelError::Corrupt(format!(
            "evidence policy does not admit the derived {name} upload grade"
        )));
    }
    Ok(grade.tag)
}

/// Run every intake and authority check without publishing. In particular,
/// unauthorized repeats cannot observe whether the document already exists.
pub fn prepare_upload<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: UploadRequest,
) -> Outcome<UploadPreparation> {
    cx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    if let Err(denial) = fa_policy::require(capability, Op::Post, "uploading evidence")
        .and_then(|()| fa_policy::scope(capability, book.book_id))
    {
        return Ok(Err(policy::refusal(&denial)));
    }
    let policy = EvidencePolicy::embedded()
        .map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let grade = upload_grade(&policy, capability.profile())?;
    if request.asserted_grade.is_some_and(|asserted| asserted != grade) {
        return Ok(Err(Refusal::new(
            code::GRADE_UNVERIFIED,
            exit::REFUSAL,
            format!(
                "the asserted provenance grade does not equal the upload grade derived from the {} session",
                capability.profile().name(),
            ),
            "plan §9.3; FA-INV-05; fa-vwf (provenance is derived from the acquisition path)",
            "omit the grade assertion; a human Reviewed attestation, not relabeling an upload, satisfies the self-sourced evidence gate",
        )));
    }
    let document = Document {
        book_id: book.book_id,
        kind: request.kind,
        mime: request.mime,
        grade,
        retrieved_by: capability.holder(),
        bytes: request.bytes,
    };
    let kind = match intake_check(&policy, book, &document, policy.max_document_bytes) {
        Ok(kind) => kind,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source = IntakeSource::Upload { principal: capability.holder() };
    if let Err(refusal) = crate::custody::admit_source(&source) {
        return Ok(Err(refusal));
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&denial)));
    }
    let txn_cx = cx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(refusal) = policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = policy::epoch_witness(&txn, db)?;
    let oid = document.oid();
    let vid = document_vid(&oid);
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        let stored = match verify_row(&row, &policy) {
            Ok(stored) => stored,
            Err(why) => return Ok(Err(drift(&oid, &why))),
        };
        // The identity is content based, not uploader based. A new upload
        // assertion must never rewrite or upgrade an earlier machine receipt.
        return Ok(Ok(UploadPreparation::AlreadyRecorded(DocumentAdded {
            oid: stored.oid(),
            doc_commit: stored.doc_commit,
            vid,
            kind: stored.kind,
            grade: stored.grade,
            size: stored.size,
            recorded_at: row.created_at,
            already_recorded: true,
        })));
    }
    let summary = UploadSummary {
        oid,
        doc_commit: document.doc_commit(),
        kind: document.kind,
        grade: document.grade,
        size: u64::try_from(document.bytes.len())
            .map_err(|_| KernelError::Corrupt("document size exceeds u64".into()))?,
    };
    let mut batch = WriteBatch::new(relation::CUSTODY_OF);
    stage_document(&mut batch, book, &document, &kind)?;
    crate::custody::stage_receipt(
        &mut batch, book, &document, source, capability.holder(), None,
    )?;
    if let Err(error) = txn.write_ordered(db, vec![batch]) {
        txn.abort();
        return Err(error.into());
    }
    Ok(Ok(UploadPreparation::Ready(Box::new(PreparedUpload {
        txn,
        capability: capability.clone(),
        summary,
    }))))
}

/// Upload an inline document and its custody receipt under session authority.
/// Refusals write nothing. A repeat returns the first intake's metadata.
pub async fn upload_document<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: UploadRequest,
) -> Outcome<DocumentAdded> {
    match prepare_upload(db, cx, book, capability, request)? {
        Err(refusal) => Ok(Err(refusal)),
        Ok(UploadPreparation::AlreadyRecorded(added)) => Ok(Ok(added)),
        Ok(UploadPreparation::Ready(prepared)) => prepared.commit(db, cx).await,
    }
}
