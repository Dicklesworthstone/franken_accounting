//! Capability-gated compact evidence export (plan §9.1/§9.6).
//!
//! Both facades use the existing protected document reader. Full documents
//! require its ordinary read policy; governed documents remain redacted unless
//! the holder has privileged authority. Produce is an additional permission,
//! never a substitute for read or privileged. No export derives a new view,
//! reads a withheld original, changes custody, or writes an accounting object.

use asupersync::fs::Vfs;
use fa_journal::{DocumentRead, KernelError, Refusal, exit};
use fa_model::{Id128, Oid};
use fa_notary::disclosure::{self, DisclosureExportError};
use fa_notary::document::DocumentProofTree;
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Book, BookError, Outcome};

pub use fa_docket::{DisclosureAccess, DocumentDisclosureArtifact};

fn export_refusal(error: DisclosureExportError) -> Refusal {
    let (code, class, fix) = match &error {
        DisclosureExportError::Withheld { .. } => (
            fa_journal::refusal::code::CAPABILITY,
            exit::SAFETY,
            "request only chunks disclosed by the governed view; produce does not grant privileged access",
        ),
        DisclosureExportError::Commitment | DisclosureExportError::View(_) => (
            fa_journal::refusal::code::REDACTION_PROOF,
            exit::VERIFICATION,
            "preserve the damaged evidence and investigate its commitment or chunk shape; do not substitute another view",
        ),
        DisclosureExportError::ByteLimit { .. } | DisclosureExportError::CountLimit { .. } => (
            crate::proof::code::PROOF_EXPORT_LIMIT,
            exit::USAGE,
            "request a smaller nonempty subset within the portable disclosure limits",
        ),
        _ => (
            fa_journal::refusal::code::STRUCTURE,
            exit::USAGE,
            "request existing whole-chunk indexes in strictly ascending order without duplicates",
        ),
    };
    Refusal::new(
        code,
        class,
        error.to_string(),
        "plan §9.1 / §9.6 (exact disclosure under current read, produce and redaction authority)",
        fix,
    )
}

fn preflight(book: Id128, capability: &Capability, requested: &[u64]) -> Result<(), Refusal> {
    fa_policy::admit_read(capability, capability.holder(), book)
        .and_then(|()| {
            fa_policy::require(capability, Op::Produce, "exporting document disclosures")
        })
        .map_err(|denial| fa_journal::policy::refusal(&denial))?;
    disclosure::validate_request(requested).map_err(export_refusal)
}

fn finish(
    book: Id128,
    document: Oid,
    requested: &[u64],
    read: DocumentRead,
) -> Outcome<DocumentDisclosureArtifact> {
    let (kind, document_length, doc_commit, access, produced) = match read {
        DocumentRead::Full(doc) => {
            if doc.book_id != book {
                return Err(KernelError::Corrupt(
                    "disclosure reader returned another book's document".into(),
                )
                .into());
            }
            let tree = DocumentProofTree::new(doc.kind, &doc.bytes)
                .map_err(|e| KernelError::Corrupt(format!("disclosure document length: {e}")))?;
            let doc_commit = tree.doc_commit();
            if fa_journal::evidence::document_oid(book, &doc_commit) != document {
                return Err(KernelError::Corrupt(
                    "disclosure reader returned another document identity".into(),
                )
                .into());
            }
            (
                doc.kind,
                doc.bytes.len() as u64,
                doc_commit,
                DisclosureAccess::Full,
                tree.disclosure_bytes(requested),
            )
        }
        DocumentRead::Redacted(view) => {
            if view.original != document
                || fa_journal::evidence::document_oid(book, &view.doc_commit) != document
            {
                return Err(KernelError::Corrupt(
                    "disclosure view is bound to another document".into(),
                )
                .into());
            }
            (
                view.kind,
                view.size,
                view.doc_commit,
                DisclosureAccess::Redacted {
                    contract: view.contract,
                },
                disclosure::disclosure_from_view(&view, requested, &view.doc_commit),
            )
        }
    };
    let bytes = match produced {
        Ok(bytes) => bytes,
        Err(DisclosureExportError::Encode(error)) => {
            return Err(KernelError::Model(error.into()).into());
        }
        Err(error) => return Ok(Err(export_refusal(error))),
    };
    Ok(Ok(DocumentDisclosureArtifact {
        document,
        doc_commit,
        kind,
        document_length,
        requested_chunks: requested.to_vec(),
        access,
        bytes,
    }))
}

impl Book {
    /// Export exactly the requested whole document chunks under current read
    /// and produce authority. The existing protected reader validates expiry,
    /// book caveats, revocation and the governed redaction contract before any
    /// document bytes reach the encoder. A missing view is a refusal, not a
    /// fallback to full bytes. Export and all refusals leave the book unchanged.
    ///
    /// The returned bytes can be saved by the caller and checked using:
    /// `fa-verify document --proof FILE --document-commit TRUSTED_FILE --chunks I,J`.
    /// The trusted file is exactly 32 raw bytes, obtained independently by the
    /// recipient. Membership proves neither authorization nor provenance.
    pub fn export_document_disclosure(
        &mut self,
        capability: &Capability,
        document: &Oid,
        requested_chunks: &[u64],
    ) -> Outcome<DocumentDisclosureArtifact> {
        let book = self.context().book_id;
        if let Err(refusal) = preflight(book, capability, requested_chunks) {
            return Ok(Err(refusal));
        }
        // Never use add_document/fetch_document or caller-selected contracts.
        let read = match self.read_document_for(capability, document)? {
            Ok(read) => read,
            Err(refusal) => return Ok(Err(refusal)),
        };
        finish(book, *document, requested_chunks, read)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// The same protected export on the caller's runtime/filesystem. Read and
    /// produce admission precedes request inspection and storage observation.
    /// Cancellation is checked before reading and before/after encoding; no
    /// new runtime, detached task, view derivation or publication is introduced.
    pub async fn export_document_disclosure(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        document: &Oid,
        requested_chunks: &[u64],
    ) -> Outcome<DocumentDisclosureArtifact> {
        let book = self.context().book_id;
        if let Err(refusal) = preflight(book, capability, requested_chunks) {
            return Ok(Err(refusal));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        let read = match self.read_document_for(cx, capability, document).await? {
            Ok(read) => read,
            Err(refusal) => return Ok(Err(refusal)),
        };
        query.checkpoint().map_err(BookError::Context)?;
        let artifact =
            query.with_restriction(|| finish(book, *document, requested_chunks, read))?;
        query.checkpoint().map_err(BookError::Context)?;
        Ok(artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BookKeys, Entropy};
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::{Budget, Cx};
    use fa_journal::{BookSpec, Document};
    use fa_model::symbols::{property, relation};
    use fa_money::UnitRegistry;
    use fa_time::{DateDay, FiscalCalendar};
    use fgdb::{MemVfs, WriteBatch};
    use fgdb_types::VId;
    use std::path::Path;

    const PRINCIPAL: VId = VId(7);
    fn cap(ops: &[&str]) -> Capability {
        Capability::embedded(PRINCIPAL, ops).unwrap()
    }

    struct Harness {
        runtime: Runtime,
        root: Cx,
        book: AsyncBook<MemVfs>,
        doc: Document,
    }

    impl Harness {
        fn new(kind: u8) -> Self {
            let runtime = RuntimeBuilder::new().build().unwrap();
            let root = runtime.request_cx_with_budget(Budget::INFINITE);
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let book_id = Id128([91; 16]);
            let spec = BookSpec {
                book_id,
                name: "Protected disclosure".into(),
                base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("disclosure", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            };
            let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
            let mut book = runtime
                .block_on(AsyncBook::create_with_vfs(
                    &cx,
                    vfs,
                    Path::new("protected-disclosure"),
                    BookKeys::for_development(91),
                    spec,
                    Entropy::deterministic(91),
                ))
                .unwrap();
            let doc = Document {
                book_id,
                kind,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: PRINCIPAL,
                bytes: vec![42; 8193],
            };
            runtime
                .block_on(book.add_document(&cx, &doc))
                .unwrap()
                .unwrap();
            Self {
                runtime,
                root,
                book,
                doc,
            }
        }
        fn cx(&self) -> PurposeContexts {
            PurposeContexts::narrow_runtime_root(&self.root)
        }
        fn head(&self) -> fgdb_types::CommitSeq {
            self.book.head(&self.cx()).unwrap()
        }
        fn export(
            &mut self,
            capability: &Capability,
            chunks: &[u64],
        ) -> Outcome<DocumentDisclosureArtifact> {
            let cx = self.cx();
            self.runtime.block_on(self.book.export_document_disclosure(
                &cx,
                capability,
                &self.doc.oid(),
                chunks,
            ))
        }
        fn poison_original(&mut self) {
            let cx = self.cx();
            let mut batch = WriteBatch::new(relation::CUSTODY_OF);
            batch.set_vertex_property(
                fa_journal::evidence::document_vid(&self.doc.oid()),
                property::FA_PAYLOAD,
                Some(fa_journal::rows::scalar_bytes("payload", vec![255]).unwrap()),
            );
            self.runtime
                .block_on(self.book.db.write(&cx.commit(), batch))
                .unwrap();
        }
    }

    #[test]
    fn exporting_a_governed_view_never_reads_or_repairs_the_original_payload() {
        let mut h = Harness::new(5);
        let cx = h.cx();
        h.runtime
            .block_on(
                h.book
                    .derive_redacted_view(&cx, &cap(&["privileged"]), &h.doc.oid()),
            )
            .unwrap()
            .unwrap();
        let expected = h
            .export(&cap(&["read", "produce"]), &[1, 2])
            .unwrap()
            .unwrap();
        h.poison_original();
        let head = h.head();
        // The stored view still verifies. Export must not fetch hidden original
        // bytes to rebuild paths, even when doing so would fail decoding.
        let redacted = h
            .export(&cap(&["read", "produce"]), &[1, 2])
            .unwrap()
            .unwrap();
        assert_eq!(redacted, expected);
        assert!(matches!(
            redacted.access,
            DisclosureAccess::Redacted { contract: 1 }
        ));
        assert_eq!(
            h.export(&cap(&["read", "produce"]), &[0, 1])
                .unwrap()
                .unwrap_err()
                .code,
            fa_journal::refusal::code::CAPABILITY
        );
        assert_eq!(
            h.export(&cap(&["read", "produce", "privileged"]), &[1])
                .unwrap()
                .unwrap_err()
                .code,
            fa_journal::refusal::code::DOCUMENT_DRIFT
        );
        assert_eq!(h.head(), head, "reads do not repair or publish");
    }

    #[test]
    fn missing_expired_and_revoked_authority_precedes_damaged_document_observation() {
        let mut h = Harness::new(1);
        let reader = cap(&["read", "produce"]);
        h.export(&reader, &[0]).unwrap().unwrap();
        h.poison_original();
        let head = h.head();
        for denied in [
            cap(&["read"]),
            cap(&["produce"]),
            cap(&["privileged", "produce"]),
        ] {
            assert_eq!(
                h.export(&denied, &[0]).unwrap().unwrap_err().code,
                fa_journal::refusal::code::CAPABILITY
            );
        }
        let expired = reader.clone().expiring_at(head);
        assert_eq!(
            h.export(&expired, &[0]).unwrap().unwrap_err().code,
            "FA-REF-014"
        );
        assert_eq!(h.head(), head);
        let cx = h.cx();
        let context = h.book.context().clone();
        let request = fa_journal::RevocationRequest {
            capability: cap(&["issue_capability"]),
            revoked: reader.commitment().unwrap(),
            effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
            idempotency_key: b"revoke-export".to_vec(),
            description: h.book.seal_text(&cx, "revoke document export").unwrap(),
        };
        h.runtime
            .block_on(fa_journal::revoke_capability(
                &mut h.book.db,
                &cx,
                &context,
                request,
            ))
            .unwrap()
            .unwrap();
        let head = h.head();
        assert_eq!(
            h.export(&reader, &[0]).unwrap().unwrap_err().code,
            "FA-REF-023"
        );
        assert_eq!(h.head(), head);
    }
}
