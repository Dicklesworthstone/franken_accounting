#![forbid(unsafe_code)]
//! Docket — documents, content-addressed receipts, intake sources, evidence
//! minimums, attestations, governed redaction views, legal holds, and
//! capability-gated disclosures (plan §9).

pub mod intake;
pub mod search;

pub use fa_journal::{
    AttestationClaim, Attested, BlobStore, CustodyBody, CustodyEvent, CustodyMoved,
    DerivedExtractionInfo, DerivedExtractionMetadata, DerivedFromDocumentSummary, Document,
    DocumentAdded, DocumentEvidenceSummary, DocumentRead, DocumentRecord, EvidenceExplanation,
    ExtractionMethod, ImportRecorded, ImportRequest, LegalHold, LegalHoldPlaced, LegalHoldReleased,
    LegalHoldRequest, Pinned, PreparedUpload, RedactedView, ReleasePlan, RunReceipt, Storage,
    UploadPreparation, UploadRequest, ViewChunk, ViewDerived, active_legal_holds, add_document,
    add_document_external, custody_chain, decode_derivation, decode_extraction_derivation,
    derive_redacted_view, document_record, document_sources, encode_derivation,
    encode_extraction_derivation, explain_entry_evidence, fetch_document, fetch_document_with,
    import_run, place_legal_hold, plan_release, prepare_upload, read_attestation, read_document,
    read_document_for, read_document_for_with, read_legal_hold, record_manual_assertion,
    record_review, redacted_view_vid, release_legal_hold, transfer_custody, upload_document,
    verify_receipt, verify_receipt_in,
};
use fa_model::Oid;
use fgdb_types::VId;
pub use intake::{
    DeflateError, DerivedDocumentResult, ExternalToolOutcome, FocrConfig, FwConfig,
    GRADE_AGENT_UPLOAD, GRADE_HUMAN_UPLOAD, KIND_WORKPAPER, PdfCryptoError,
    decrypt_pdf_standard_security, extract_pdf_text_layer, extract_pdf_text_string, inflate_zlib,
    is_standard_security_encrypted, recover_file_encryption_key_v5_r5, resolve_binary_in_path,
    run_focr_extraction, run_fw_extraction,
};
pub use search::{
    FSLX_SEGMENT_FORMAT, FslxDocEntry, FslxPosting, FslxSegment, QuillLexicalIndex,
    SEARCH_CORPUS_DOMAIN, SEARCH_MANIFEST_FORMAT, SearchError, SearchHit, SearchIndexManifest,
    SearchIndexableRecord, SearchRecordId, SearchRecordKind, SearchVerificationReceipt,
    VerificationDriftDetails, tokenize_with_offsets,
};

/// The protected reader's decision, not a permission supplied by a request.
/// This local metadata is not authenticated by the compact membership proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisclosureAccess {
    Full,
    Redacted { contract: u16 },
}

/// Only the requested chunks and their paths leave the book. The document
/// commitment is convenient for citation matching, but recipients must obtain
/// and trust it separately rather than treating this artifact as its own anchor.
#[derive(Clone, PartialEq, Eq)]
pub struct DocumentDisclosureArtifact {
    pub document: Oid,
    pub doc_commit: [u8; 32],
    pub kind: u8,
    pub document_length: u64,
    pub requested_chunks: Vec<u64>,
    pub access: DisclosureAccess,
    /// Raw fa:document-disclosure:v1 bytes for `fa-verify document`.
    /// These contain sensitive disclosed data; Debug deliberately omits them.
    pub bytes: Vec<u8>,
}

impl core::fmt::Debug for DocumentDisclosureArtifact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DocumentDisclosureArtifact")
            .field("document", &self.document)
            .field("kind", &self.kind)
            .field("document_length", &self.document_length)
            .field("requested_chunks", &self.requested_chunks)
            .field("access", &self.access)
            .field("proof_byte_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Select a recorded entry and one of its exact evidence citations. A caller
/// must obtain the expected entry digest independently of the returned proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceDisclosureRequest {
    /// None selects the latest already recorded checkpoint; none is created.
    pub state: Option<Oid>,
    pub entry: VId,
    pub expected_entry_digest: [u8; 32],
    pub document: Oid,
    pub role: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docket_disclosure_artifact_debug_omits_sensitive_bytes() {
        let artifact = DocumentDisclosureArtifact {
            document: Oid([0x42; 32]),
            doc_commit: [0x11; 32],
            kind: 1,
            document_length: 128,
            requested_chunks: vec![0, 1],
            access: DisclosureAccess::Redacted { contract: 7 },
            bytes: b"SENSITIVE_SECRET_PAYLOAD".to_vec(),
        };
        let rendered = format!("{artifact:?}");
        assert!(!rendered.contains("SENSITIVE_SECRET_PAYLOAD"));
        assert!(rendered.contains("proof_byte_length: 24"));
    }
}
