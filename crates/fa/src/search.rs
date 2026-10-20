//! Full-text search over the journal (plan §9, bead fa-qip): fa-docket's
//! deterministic BM25 index ("Quill"), rebuilt from the journal at one
//! recorded frontier for each query and never stored, so it is never more
//! authoritative than the journal (FA-INV-04) and can never drift from it.
//!
//! This slice indexes entries: each committed entry's description and leg
//! memos, opened with the book's key. A field that key does not open (erased,
//! or sealed under a subject's own key) contributes nothing, so erased text
//! is never indexed and never appears in a snippet. Scores are exact
//! fixed-point integers; no amount is ever parsed from a hit.

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
    /// How many entries carried searchable text.
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

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Rank the entries visible at `known_at` (the head when `None`) whose
    /// description or memos match `query`.
    pub fn search_entries(
        &self,
        cx: &PurposeContexts,
        query: &str,
        known_at: Option<CommitSeq>,
    ) -> Result<SearchResults, BookError> {
        self.query(cx, |db, book| {
            let seq = fa_registers::resolve_known_at(db, known_at)?;
            let key = &book.seal_key;
            let mut records = Vec::new();
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
                hits: index.search(query, Some(SearchRecordKind::Entry)),
            })
        })
    }
}
