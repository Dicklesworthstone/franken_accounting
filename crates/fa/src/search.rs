//! Full-text search over the journal (plan §9, bead fa-qip): fa-docket's
//! deterministic BM25 index ("Quill"), rebuilt from the journal at one
//! recorded frontier for each query and never stored, so it is never more
//! authoritative than the journal (FA-INV-04) and can never drift from it.
//!
//! It indexes entries (each committed entry's description and leg memos,
//! opened with the book's key) and the documents a caller supplies as
//! records (`fa search` reads each through the caller's capability and
//! passes the text [`document_search_text`] gives). A field the book's key
//! does not open (erased, or sealed under a subject's own key) contributes
//! nothing, so erased text is never indexed and never appears in a snippet.
//! Entries and documents share one index when both are searched, so their
//! scores are comparable; a kind filter indexes only that kind.
//! Scores are exact fixed-point integers; no amount is ever parsed from a hit.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_docket::search::{
    QuillLexicalIndex, SearchError, SearchHit, SearchIndexableRecord, SearchRecordId,
    SearchRecordKind,
};
use fa_journal::KernelError;
use fa_model::limits;
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, BookError};

/// One search over the journal at one recorded frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResults {
    /// The frontier the index was rebuilt at.
    pub known_at: CommitSeq,
    /// How many entries and documents carried searchable text.
    pub records: usize,
    /// The index manifest's digest: the same journal prefix rebuilds the
    /// same index.
    pub index_digest: [u8; 32],
    /// Best first (BM25 score, then the index's own deterministic order).
    pub hits: Vec<SearchHit>,
}

fn search_error(error: SearchError) -> BookError {
    match error {
        SearchError::Input(message) => {
            BookError::Registers(fa_registers::RegisterError::InvalidSelection(message))
        }
        other => BookError::Kernel(KernelError::Corrupt(format!("search index: {other}"))),
    }
}

/// The text a document contributes to search: a derived document's
/// extracted text (`fa document extract`; any other derivation, nothing), or
/// a document's own bytes when they are UTF-8 and its media type is no
/// binary format; nothing for anything else, or for blank text. A PDF or
/// image is searched through its derived text, never its raw bytes, which
/// may happen to be UTF-8.
#[must_use]
pub fn document_search_text(document: &fa_journal::Document) -> Option<String> {
    let text = if fa_journal::decode_derivation(&document.bytes).is_ok() {
        fa_journal::decode_extraction_derivation(&document.bytes)
            .ok()?
            .1
            .extracted_text
    } else {
        let mime = document.mime.to_ascii_lowercase();
        if mime.starts_with("application/pdf")
            || ["image/", "audio/", "video/"]
                .iter()
                .any(|binary| mime.starts_with(binary))
        {
            return None;
        }
        std::str::from_utf8(&document.bytes).ok()?.to_string()
    };
    (!text.trim().is_empty()).then_some(text)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Rank the entries visible at `known_at` (the head when `None`) whose
    /// description or memos match `query`, together with `documents` (the
    /// caller's records, read under its capability), in one index. `kind`
    /// searches only that kind of record: entries are indexed only when it
    /// admits them, so the index (and its digest) is over the kinds searched.
    pub fn search(
        &self,
        cx: &PurposeContexts,
        query: &str,
        known_at: Option<CommitSeq>,
        documents: &[SearchIndexableRecord],
        kind: Option<SearchRecordKind>,
    ) -> Result<SearchResults, BookError> {
        self.query(cx, |db, book| {
            let seq = fa_registers::resolve_known_at(db, known_at)?;
            let key = &book.seal_key;
            let mut records = Vec::new();
            if kind.is_none_or(|only| only == SearchRecordKind::Entry) {
                for (vid, entry, recorded_at) in fa_registers::entries_at(db, book, seq)? {
                    let proposal = &entry.proposal;
                    let mut text = proposal
                        .description
                        .open(key, limits::MAX_DESCRIPTION_BYTES)
                        .unwrap_or_default();
                    for leg in &proposal.legs {
                        if let Some(memo) = leg
                            .memo
                            .as_ref()
                            .and_then(|memo| memo.open(key, limits::MAX_MEMO_BYTES).ok())
                        {
                            text.push('\n');
                            text.push_str(&memo);
                        }
                    }
                    if text.trim().is_empty() {
                        continue;
                    }
                    records.push(SearchIndexableRecord {
                        id: SearchRecordId::Entry(vid),
                        recorded_at: recorded_at.0,
                        subject_ref: None,
                        text,
                    });
                }
            }
            records.extend(documents.iter().cloned());
            let (index, manifest) = QuillLexicalIndex::rebuild_deterministic(
                book.book_id,
                seq.0,
                &records,
                &BTreeSet::new(),
            )
            .map_err(search_error)?;
            let index_digest = manifest
                .digest()
                .map_err(|e| KernelError::Corrupt(format!("search manifest: {e}")))?
                .0;
            Ok(SearchResults {
                known_at: seq,
                records: records.len(),
                index_digest,
                hits: index.search(query, kind),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use fa_journal::{DerivedExtractionMetadata, Document, ExtractionMethod};
    use fa_model::{Id128, Oid};
    use fgdb_types::VId;

    use super::document_search_text;

    fn document(mime: &str, bytes: &[u8]) -> Document {
        Document {
            book_id: Id128([7; 16]),
            kind: 1,
            mime: mime.into(),
            grade: 3,
            retrieved_by: VId(1),
            bytes: bytes.to_vec(),
        }
    }

    fn extraction(text: &str) -> Vec<u8> {
        fa_journal::encode_extraction_derivation(
            &[Oid([0x42; 32])],
            &DerivedExtractionMetadata {
                method: ExtractionMethod::PdfTextLayer,
                tool_name: "fa-docket/pdf-text-layer".into(),
                tool_version: "0.0.1".into(),
                model_artifact_hash: None,
                command_line: Vec::new(),
                replayable: true,
                extracted_text: text.into(),
                raw_tool_output: Vec::new(),
            },
        )
        .unwrap()
    }

    /// A text document is searched by its bytes and a derivation by its
    /// extracted text, never its envelope; a binary format's bytes are
    /// never searched even when they decode, and blank text is nothing.
    #[test]
    fn documents_are_searched_by_their_text_or_their_extraction_only() {
        let text = document("text/plain", b"Harbor Street lease");
        assert_eq!(
            document_search_text(&text).as_deref(),
            Some("Harbor Street lease")
        );
        let derived = document("text/plain", &extraction("ACME SUPPLIES INC."));
        assert_eq!(
            document_search_text(&derived).as_deref(),
            Some("ACME SUPPLIES INC.")
        );
        for mime in ["application/pdf", "Image/PNG", "audio/wav", "video/mp4"] {
            assert_eq!(
                document_search_text(&document(mime, b"%PDF-1.7 ACME")),
                None
            );
        }
        assert_eq!(
            document_search_text(&document("text/plain", b" \n\t")),
            None
        );
        assert_eq!(
            document_search_text(&document("text/plain", &[0xff, 0xfe])),
            None
        );
        let blank = document("text/plain", &extraction("  \n"));
        assert_eq!(document_search_text(&blank), None);
        let other = fa_journal::encode_derivation(&[Oid([0x42; 32])], b"Harbor").unwrap();
        assert_eq!(document_search_text(&document("text/plain", &other)), None);
    }
}
