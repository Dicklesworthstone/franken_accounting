//! Quill — deterministic pure-Rust BM25 full-text search over evidence
//! `Document` derived text layers (`fa-646`), entry descriptions/memos, and
//! forensic `Finding` summaries (plan §9, bead `fa-qip`).
//!
//! Doctrine guarantees:
//! - **Derived register posture (FA-INV-04):** The search index is never
//!   authoritative, never included in an outsider bundle, and is deterministically
//!   rebuilt from the journal and verified by `verify_search_index` (comparing
//!   the journal document-set hash against the index manifest).
//! - **Subject-key erasure compliance:** Records carrying a `subject_ref` whose
//!   per-Party key is absent or destroyed are excluded on rebuild and purged
//!   immediately upon `erase_subject_key`, leaving zero plaintext tokens in any
//!   `FslxSegment` or posting list.
//! - **Zero floating-point arithmetic & zero wall-clock access:** BM25 scoring
//!   uses exact 64/128-bit fixed-point integer arithmetic (`score_micro` at
//!   scale $10^6$). No amounts are ever parsed from search hits.

use std::collections::{BTreeMap, BTreeSet};
use core::fmt;

use fa_model::{DecodeError, EncodeError, Id128, Oid, Reader, Writer, domain_digest};
use fgdb_types::VId;

pub const FSLX_SEGMENT_FORMAT: &[u8] = b"fa:fslx-segment:v1";
pub const SEARCH_MANIFEST_FORMAT: &[u8] = b"fa:search-manifest:v1";
pub const SEARCH_CORPUS_DOMAIN: &[u8] = b"fa:search-corpus:v1";

const MAX_TERMS: usize = 262_144;
const MAX_POSTINGS_PER_TERM: usize = 262_144;
const MAX_DOCS_PER_SEGMENT: usize = 262_144;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

/// BM25 fixed-point scale ($10^6$ micro-units).
const MICRO: u128 = 1_000_000;
/// Standard BM25 $k_1 = 1.2$ in micro-units.
const BM25_K1_MICRO: u128 = 1_200_000;
/// Standard BM25 $b = 0.75$ numerator ($3 / 4$).
const BM25_B_NUM: u128 = 3;
const BM25_B_DEN: u128 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationDriftDetails {
    pub expected_corpus_hash: Oid,
    pub actual_corpus_hash: Oid,
    pub expected_manifest_digest: Oid,
    pub actual_manifest_digest: Oid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchError {
    Input(String),
    VerificationDrift(Box<VerificationDriftDetails>),
    Decode(DecodeError),
    Encode(EncodeError),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(msg) => write!(f, "search input error: {msg}"),
            Self::VerificationDrift(details) => write!(
                f,
                "search index drift detected: expected corpus {:?} (manifest {:?}), found corpus {:?} (manifest {:?}); run `fa verify search` or rebuild index",
                details.expected_corpus_hash,
                details.expected_manifest_digest,
                details.actual_corpus_hash,
                details.actual_manifest_digest
            ),
            Self::Decode(e) => write!(f, "search decode error: {e}"),
            Self::Encode(e) => write!(f, "search encode error: {e}"),
        }
    }
}

impl core::error::Error for SearchError {}

impl From<DecodeError> for SearchError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<EncodeError> for SearchError {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

/// Discriminator for `--kind document|entry|finding` (`fa-qip`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchRecordKind {
    Document,
    Entry,
    Finding,
}

impl SearchRecordKind {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Document => 1,
            Self::Entry => 2,
            Self::Finding => 3,
        }
    }

    pub fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(Self::Document),
            2 => Ok(Self::Entry),
            3 => Ok(Self::Finding),
            _ => Err(r.bad_tag("search.record_kind", tag)),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Entry => "entry",
            Self::Finding => "finding",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, SearchError> {
        match raw {
            "document" => Ok(Self::Document),
            "entry" => Ok(Self::Entry),
            "finding" => Ok(Self::Finding),
            other => Err(SearchError::Input(format!(
                "unknown search kind `{other}`; expected document|entry|finding"
            ))),
        }
    }
}

/// Stable identifier of an indexed record: Document `Oid`, Entry `VId`, or Finding `VId` (`fa-qip`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchRecordId {
    Document(Oid),
    Entry(VId),
    Finding(VId),
}

impl SearchRecordId {
    pub const fn kind(&self) -> SearchRecordKind {
        match self {
            Self::Document(_) => SearchRecordKind::Document,
            Self::Entry(_) => SearchRecordKind::Entry,
            Self::Finding(_) => SearchRecordKind::Finding,
        }
    }

    pub fn canonical_hex(&self) -> String {
        match self {
            Self::Document(oid) => oid.0.iter().map(|b| format!("{b:02x}")).collect(),
            Self::Entry(vid) | Self::Finding(vid) => format!("{:032x}", vid.0),
        }
    }

    fn write_to(&self, w: &mut Writer) {
        w.u8(self.kind().tag());
        match self {
            Self::Document(oid) => {
                w.fixed(&oid.0);
            }
            Self::Entry(vid) | Self::Finding(vid) => {
                w.u128(vid.0);
            }
        }
    }

    fn read_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let tag = r.u8("record_id.tag")?;
        let kind = SearchRecordKind::from_tag(tag, r)?;
        match kind {
            SearchRecordKind::Document => Ok(Self::Document(Oid(r.fixed::<32>("document_oid")?))),
            SearchRecordKind::Entry => Ok(Self::Entry(VId(r.u128("entry_vid")?))),
            SearchRecordKind::Finding => Ok(Self::Finding(VId(r.u128("finding_vid")?))),
        }
    }
}

/// Input record extracted from the journal for full-text indexing (`fa-qip`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchIndexableRecord {
    pub id: SearchRecordId,
    pub recorded_at: u64,
    /// Optional subject key reference (`Erasable<T>.subject_ref`). When present,
    /// the record's text is indexed iff `subject_ref` is present in `live_subject_keys`.
    pub subject_ref: Option<Id128>,
    pub text: String,
}

/// Stored metadata for one document inside an `FslxSegment`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FslxDocEntry {
    pub id: SearchRecordId,
    pub recorded_at: u64,
    pub subject_ref: Option<Id128>,
    pub token_len: u32,
    pub text: String,
}

/// One posting entry in an `FslxSegment` inverted list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FslxPosting {
    pub doc_ordinal: u32,
    pub term_freq: u32,
    pub first_char_offset: u32,
}

/// Immutable FSLX lexical segment over a `CommitSeq` window (`fa-qip`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FslxSegment {
    pub from_seq: u64,
    pub through_seq: u64,
    pub docs: Vec<FslxDocEntry>,
    pub postings: BTreeMap<String, Vec<FslxPosting>>,
}

impl FslxSegment {
    pub fn build(from_seq: u64, through_seq: u64, mut docs: Vec<FslxDocEntry>) -> Self {
        docs.sort_by(|a, b| {
            a.recorded_at
                .cmp(&b.recorded_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let mut postings: BTreeMap<String, Vec<FslxPosting>> = BTreeMap::new();
        for (idx, doc) in docs.iter_mut().enumerate() {
            let tokens = tokenize_with_offsets(&doc.text);
            doc.token_len = tokens.len() as u32;
            let mut per_term: BTreeMap<String, (u32, u32)> = BTreeMap::new();
            for (term, byte_offset) in tokens {
                let entry = per_term.entry(term).or_insert((0, byte_offset as u32));
                entry.0 = entry.0.saturating_add(1);
            }
            for (term, (tf, first_char_offset)) in per_term {
                postings.entry(term).or_default().push(FslxPosting {
                    doc_ordinal: idx as u32,
                    term_freq: tf,
                    first_char_offset,
                });
            }
        }
        Self {
            from_seq,
            through_seq,
            docs,
            postings,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(FSLX_SEGMENT_FORMAT)
            .u64(self.from_seq)
            .u64(self.through_seq)
            .list(&self.docs, |w, doc| {
                doc.id.write_to(w);
                w.u64(doc.recorded_at)
                    .opt(doc.subject_ref.as_ref(), |w, subj| {
                        w.fixed(&subj.0);
                    })
                    .u32(doc.token_len)
                    .str(&doc.text);
            });
        let terms: Vec<(&String, &Vec<FslxPosting>)> = self.postings.iter().collect();
        w.list(&terms, |w, (term, list)| {
            w.str(term).list(list, |w, p| {
                w.u32(p.doc_ordinal)
                    .u32(p.term_freq)
                    .u32(p.first_char_offset);
            });
        });
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            FSLX_SEGMENT_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ FSLX_SEGMENT_FORMAT.len() }>("fslx.magic")?;
        if magic != FSLX_SEGMENT_FORMAT {
            return Err(r.invalid("FSLX segment header"));
        }
        let from_seq = r.u64("from_seq")?;
        let through_seq = r.u64("through_seq")?;
        let doc_count = r.count(MAX_DOCS_PER_SEGMENT, "docs")?;
        let mut docs = Vec::with_capacity(doc_count);
        for _ in 0..doc_count {
            let id = SearchRecordId::read_from(&mut r)?;
            let recorded_at = r.u64("recorded_at")?;
            let subject_ref = r
                .opt("subject_ref", |r| r.fixed::<16>("subject_ref"))?
                .map(Id128);
            let token_len = r.u32("token_len")?;
            let text = r.str(MAX_TEXT_BYTES, "text")?.to_string();
            docs.push(FslxDocEntry {
                id,
                recorded_at,
                subject_ref,
                token_len,
                text,
            });
        }
        let term_count = r.count(MAX_TERMS, "postings")?;
        let mut postings = BTreeMap::new();
        for _ in 0..term_count {
            let term = r.str(256, "term")?.to_string();
            let p_count = r.count(MAX_POSTINGS_PER_TERM, "posting_list")?;
            let mut list = Vec::with_capacity(p_count);
            for _ in 0..p_count {
                list.push(FslxPosting {
                    doc_ordinal: r.u32("doc_ordinal")?,
                    term_freq: r.u32("term_freq")?,
                    first_char_offset: r.u32("first_char_offset")?,
                });
            }
            postings.insert(term, list);
        }
        r.finish()?;
        Ok(Self {
            from_seq,
            through_seq,
            docs,
            postings,
        })
    }
}

/// Deterministic manifest committing the state of a rebuilt or maintained search index (`fa-qip`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchIndexManifest {
    pub book_id: Id128,
    pub known_at: u64,
    pub corpus_hash: Oid,
    pub segment_digests: Vec<Oid>,
    pub indexed_record_count: u64,
    pub erased_record_count: u64,
}

impl SearchIndexManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(SEARCH_MANIFEST_FORMAT)
            .fixed(&self.book_id.0)
            .u64(self.known_at)
            .fixed(&self.corpus_hash.0)
            .list(&self.segment_digests, |w, d| {
                w.fixed(&d.0);
            })
            .u64(self.indexed_record_count)
            .u64(self.erased_record_count);
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            SEARCH_MANIFEST_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }
}

/// Verification receipt returned by `verify_search_index` (`fa verify search`, `fa-qip`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchVerificationReceipt {
    pub book_id: Id128,
    pub known_at: u64,
    pub corpus_hash: Oid,
    pub manifest_digest: Oid,
    pub indexed_record_count: u64,
    pub erased_record_count: u64,
}

/// Ranked BM25 lexical search hit (`fa search`, `fa-qip`).
///
/// Carries the record identifier (`Document` `Oid`, `Entry` `VId`, or `Finding` `VId`),
/// deterministic fixed-point BM25 score (`score_micro`), matched terms, and snippet.
/// Never parses or exposes monetary amounts as authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchHit {
    pub id: SearchRecordId,
    pub kind: SearchRecordKind,
    pub recorded_at: u64,
    pub score_micro: u64,
    pub matched_terms: Vec<String>,
    pub snippet: String,
}

/// Quill pure-Rust BM25 lexical index with FSLX segments and delta-visible indexing (`fa-qip`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuillLexicalIndex {
    pub book_id: Id128,
    pub known_at: u64,
    pub segments: Vec<FslxSegment>,
    pub delta_records: Vec<FslxDocEntry>,
    pub erased_record_count: u64,
    pub live_subject_keys: BTreeSet<Id128>,
}

impl QuillLexicalIndex {
    /// Deterministic full rebuild from journal records at `known_at` (`fa-qip`).
    pub fn rebuild_deterministic(
        book_id: Id128,
        known_at: u64,
        records: &[SearchIndexableRecord],
        live_subject_keys: &BTreeSet<Id128>,
    ) -> Result<(Self, SearchIndexManifest), SearchError> {
        let mut docs = Vec::new();
        let mut erased_record_count: u64 = 0;

        for rec in records {
            if rec.recorded_at > known_at {
                continue;
            }
            if let Some(subj) = rec.subject_ref
                && !live_subject_keys.contains(&subj)
            {
                erased_record_count += 1;
                continue;
            }
            docs.push(FslxDocEntry {
                id: rec.id,
                recorded_at: rec.recorded_at,
                subject_ref: rec.subject_ref,
                token_len: 0,
                text: rec.text.clone(),
            });
        }

        let segment = FslxSegment::build(0, known_at, docs);
        let index = Self {
            book_id,
            known_at,
            segments: vec![segment],
            delta_records: Vec::new(),
            erased_record_count,
            live_subject_keys: live_subject_keys.clone(),
        };
        let manifest = index.manifest()?;
        Ok((index, manifest))
    }

    /// Append a delta-visible record immediately without rebuilding existing segments (`fa-qip`).
    pub fn append_delta(&mut self, record: SearchIndexableRecord) {
        if record.recorded_at > self.known_at {
            self.known_at = record.recorded_at;
        }
        if let Some(subj) = record.subject_ref
            && !self.live_subject_keys.contains(&subj)
        {
            self.erased_record_count += 1;
            return;
        }
        let token_len = tokenize_with_offsets(&record.text).len() as u32;
        self.delta_records.push(FslxDocEntry {
            id: record.id,
            recorded_at: record.recorded_at,
            subject_ref: record.subject_ref,
            token_len,
            text: record.text,
        });
    }

    /// Compact the delta buffer into a new immutable `FslxSegment`.
    pub fn flush_delta_segment(&mut self) {
        if self.delta_records.is_empty() {
            return;
        }
        let drained: Vec<FslxDocEntry> = core::mem::take(&mut self.delta_records);
        let from_seq = drained.iter().map(|d| d.recorded_at).min().unwrap_or(0);
        let through_seq = drained
            .iter()
            .map(|d| d.recorded_at)
            .max()
            .unwrap_or(self.known_at);
        self.segments
            .push(FslxSegment::build(from_seq, through_seq, drained));
    }

    /// Destroy a subject key (`fa-qip` / `fa-v74`): removes every document/entry/finding
    /// bound to `subject_ref` from all FSLX segments and the delta buffer so zero
    /// plaintext tokens remain reachable in the index.
    pub fn erase_subject_key(&mut self, subject_ref: Id128) {
        self.live_subject_keys.remove(&subject_ref);

        let before_delta = self.delta_records.len();
        self.delta_records
            .retain(|d| d.subject_ref != Some(subject_ref));
        self.erased_record_count += (before_delta - self.delta_records.len()) as u64;

        let mut rebuilt_segments = Vec::with_capacity(self.segments.len());
        for seg in self.segments.drain(..) {
            let before = seg.docs.len();
            let remaining: Vec<FslxDocEntry> = seg
                .docs
                .into_iter()
                .filter(|d| d.subject_ref != Some(subject_ref))
                .collect();
            self.erased_record_count += (before - remaining.len()) as u64;
            rebuilt_segments.push(FslxSegment::build(seg.from_seq, seg.through_seq, remaining));
        }
        self.segments = rebuilt_segments;
    }

    /// Compute the deterministic `SearchIndexManifest` for the current state (`fa-qip`).
    pub fn manifest(&self) -> Result<SearchIndexManifest, SearchError> {
        let mut all_docs: Vec<&FslxDocEntry> = self
            .segments
            .iter()
            .flat_map(|s| s.docs.iter())
            .chain(self.delta_records.iter())
            .collect();
        all_docs.sort_by(|a, b| {
            a.recorded_at
                .cmp(&b.recorded_at)
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut w = Writer::new();
        w.fixed(&self.book_id.0)
            .u64(self.known_at)
            .list(&all_docs, |w, d| {
                d.id.write_to(w);
                w.u64(d.recorded_at).str(&d.text);
            });
        let corpus_bytes = w.finish()?;
        let corpus_hash = Oid(domain_digest(SEARCH_CORPUS_DOMAIN, &[&corpus_bytes]));

        let mut segment_digests = Vec::with_capacity(self.segments.len());
        for seg in &self.segments {
            segment_digests.push(seg.digest()?);
        }
        Ok(SearchIndexManifest {
            book_id: self.book_id,
            known_at: self.known_at,
            corpus_hash,
            segment_digests,
            indexed_record_count: all_docs.len() as u64,
            erased_record_count: self.erased_record_count,
        })
    }

    /// Verify that this index matches a fresh deterministic rebuild from the journal (`fa verify search`).
    pub fn verify_against_journal(
        &self,
        records: &[SearchIndexableRecord],
        live_subject_keys: &BTreeSet<Id128>,
    ) -> Result<SearchVerificationReceipt, SearchError> {
        let (_, expected_manifest) =
            Self::rebuild_deterministic(self.book_id, self.known_at, records, live_subject_keys)?;
        let actual_manifest = self.manifest()?;
        let expected_digest = expected_manifest.digest()?;
        let actual_digest = actual_manifest.digest()?;

        if expected_manifest.corpus_hash != actual_manifest.corpus_hash
            || expected_digest != actual_digest
        {
            return Err(SearchError::VerificationDrift(Box::new(
                VerificationDriftDetails {
                    expected_corpus_hash: expected_manifest.corpus_hash,
                    actual_corpus_hash: actual_manifest.corpus_hash,
                    expected_manifest_digest: expected_digest,
                    actual_manifest_digest: actual_digest,
                },
            )));
        }

        Ok(SearchVerificationReceipt {
            book_id: self.book_id,
            known_at: self.known_at,
            corpus_hash: actual_manifest.corpus_hash,
            manifest_digest: actual_digest,
            indexed_record_count: actual_manifest.indexed_record_count,
            erased_record_count: actual_manifest.erased_record_count,
        })
    }

    /// Execute a ranked BM25 lexical search over all FSLX segments and delta records (`fa-qip`).
    ///
    /// Returns an empty `Vec` when no documents match (exit 0 in CLI contract).
    pub fn search(&self, query: &str, kind_filter: Option<SearchRecordKind>) -> Vec<SearchHit> {
        let mut query_terms: Vec<String> = tokenize_with_offsets(query)
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        query_terms.sort_unstable();
        query_terms.dedup();
        if query_terms.is_empty() {
            return Vec::new();
        }

        // Collect all visible documents across segments and the delta buffer
        let delta_seg = if self.delta_records.is_empty() {
            None
        } else {
            Some(FslxSegment::build(
                0,
                self.known_at,
                self.delta_records.clone(),
            ))
        };
        let all_segments: Vec<&FslxSegment> = self
            .segments
            .iter()
            .chain(delta_seg.as_ref())
            .collect();

        let total_docs: u128 = all_segments.iter().map(|s| s.docs.len() as u128).sum();
        if total_docs == 0 {
            return Vec::new();
        }
        let total_tokens: u128 = all_segments
            .iter()
            .flat_map(|s| s.docs.iter())
            .map(|d| u128::from(d.token_len.max(1)))
            .sum();
        let avgdl_micro: u128 = ((total_tokens * MICRO) / total_docs).max(1);

        // Compute global document frequency per query term
        let mut doc_freqs: BTreeMap<&str, u128> = BTreeMap::new();
        for term in &query_terms {
            let df: u128 = all_segments
                .iter()
                .map(|s| s.postings.get(term).map_or(0, |list| list.len() as u128))
                .sum();
            doc_freqs.insert(term.as_str(), df);
        }

        // Accumulate BM25 score per (seg_idx, doc_ordinal)
        let mut doc_scores: BTreeMap<(usize, u32), (u64, Vec<String>, u32)> = BTreeMap::new();
        for (seg_idx, seg) in all_segments.iter().enumerate() {
            for term in &query_terms {
                let df = *doc_freqs.get(term.as_str()).unwrap_or(&0);
                if df == 0 {
                    continue;
                }
                let idf_micro = bm25_idf_micro(total_docs, df);
                if let Some(list) = seg.postings.get(term) {
                    for posting in list {
                        let doc = &seg.docs[posting.doc_ordinal as usize];
                        if let Some(filter) = kind_filter
                            && doc.id.kind() != filter
                        {
                            continue;
                        }
                        let tf = u128::from(posting.term_freq);
                        let dl = u128::from(doc.token_len.max(1));
                        let tf_norm_micro = bm25_tf_norm_micro(tf, dl, avgdl_micro);
                        let term_score_micro = ((idf_micro * tf_norm_micro) / MICRO) as u64;

                        let entry = doc_scores
                            .entry((seg_idx, posting.doc_ordinal))
                            .or_insert_with(|| (0, Vec::new(), posting.first_char_offset));
                        entry.0 = entry.0.saturating_add(term_score_micro.max(1));
                        entry.1.push(term.clone());
                        if posting.first_char_offset < entry.2 {
                            entry.2 = posting.first_char_offset;
                        }
                    }
                }
            }
        }

        let mut hits = Vec::with_capacity(doc_scores.len());
        for ((seg_idx, doc_ordinal), (score_micro, matched_terms, first_offset)) in doc_scores {
            let doc = &all_segments[seg_idx].docs[doc_ordinal as usize];
            let snippet = build_snippet(&doc.text, first_offset as usize, &matched_terms);
            hits.push(SearchHit {
                id: doc.id,
                kind: doc.id.kind(),
                recorded_at: doc.recorded_at,
                score_micro,
                matched_terms,
                snippet,
            });
        }

        hits.sort_by(|a, b| {
            b.score_micro
                .cmp(&a.score_micro)
                .then_with(|| a.recorded_at.cmp(&b.recorded_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        hits
    }
}

/// Tokenize input text into lowercase alphanumeric terms and their byte offsets.
pub fn tokenize_with_offsets(text: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start_byte = 0;

    for (idx, ch) in text.char_indices() {
        if ch.is_alphanumeric() {
            if current.is_empty() {
                start_byte = idx;
            }
            for lower in ch.to_lowercase() {
                current.push(lower);
            }
        } else if !current.is_empty() {
            out.push((core::mem::take(&mut current), start_byte));
        }
    }
    if !current.is_empty() {
        out.push((current, start_byte));
    }
    out
}

/// Pure-integer BM25 IDF in micro-units:
/// $\ln\left(1 + \frac{N - df + 0.5}{df + 0.5}\right)$ approximated deterministically via
/// integer $\log_2$ and linear mantissa interpolation in micro-units (zero floats).
fn bm25_idf_micro(total_docs: u128, df: u128) -> u128 {
    let num = (2 * total_docs.saturating_sub(df) + 1) * MICRO;
    let den = 2 * df + 1;
    let ratio_micro = num / den;
    let arg_micro = MICRO + ratio_micro; // >= 1_000_000

    // Integer log2(arg_micro / 1_000_000) in micro-bits, then * ln(2) (693_147 / 1_000_000)
    let bits = 127u32.saturating_sub(arg_micro.leading_zeros());
    let base_bits = 127u32.saturating_sub(MICRO.leading_zeros()); // 19
    let shift = bits.saturating_sub(base_bits);
    let scaled = arg_micro >> shift;
    let frac_micro = scaled.saturating_sub(MICRO);
    let log2_micro = u128::from(shift) * MICRO + frac_micro;
    ((log2_micro * 693_147) / MICRO).max(1_000)
}

/// Pure-integer BM25 TF normalization in micro-units:
/// $\frac{tf \cdot (k_1 + 1)}{tf + k_1 \cdot (1 - b + b \cdot \frac{dl}{avgdl})}$.
fn bm25_tf_norm_micro(tf: u128, dl: u128, avgdl_micro: u128) -> u128 {
    let num = tf * (BM25_K1_MICRO + MICRO) * MICRO;
    // (1 - b) = 0.25 = 250_000 micro; b * dl / avgdl = (3 * dl * 10^12) / (4 * avgdl_micro)
    let one_minus_b_micro = ((BM25_B_DEN - BM25_B_NUM) * MICRO) / BM25_B_DEN;
    let b_dl_ratio_micro = (BM25_B_NUM * dl * MICRO * MICRO) / (BM25_B_DEN * avgdl_micro.max(1));
    let length_norm_micro = one_minus_b_micro + b_dl_ratio_micro;
    let k1_norm_micro = (BM25_K1_MICRO * length_norm_micro) / MICRO;
    let den_micro = tf * MICRO + k1_norm_micro.max(1);
    num / den_micro
}

fn build_snippet(text: &str, first_offset: usize, matched_terms: &[String]) -> String {
    let start = text
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= first_offset.saturating_sub(24))
        .unwrap_or(0);
    let end = text
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| i >= (first_offset + 96).min(text.len()))
        .unwrap_or(text.len());
    let window = text[start..end].trim();
    let mut out = String::with_capacity(window.len() + 16);
    let mut run_start: Option<usize> = None;

    for (idx, ch) in window.char_indices() {
        if ch.is_alphanumeric() {
            if run_start.is_none() {
                run_start = Some(idx);
            }
        } else {
            if let Some(s) = run_start.take() {
                let token = &window[s..idx];
                let lower = token.to_lowercase();
                if matched_terms.iter().any(|t| t == &lower) {
                    out.push('[');
                    out.push_str(token);
                    out.push(']');
                } else {
                    out.push_str(token);
                }
            }
            out.push(ch);
        }
    }
    if let Some(s) = run_start {
        let token = &window[s..];
        let lower = token.to_lowercase();
        if matched_terms.iter().any(|t| t == &lower) {
            out.push('[');
            out.push_str(token);
            out.push(']');
        } else {
            out.push_str(token);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_records() -> (Vec<SearchIndexableRecord>, BTreeSet<Id128>) {
        let party_alice = Id128([0xA1; 16]);
        let party_bob = Id128([0xB2; 16]);
        let mut live_keys = BTreeSet::new();
        live_keys.insert(party_alice);
        live_keys.insert(party_bob);

        let records = vec![
            SearchIndexableRecord {
                id: SearchRecordId::Document(Oid([0x11; 32])),
                recorded_at: 2,
                subject_ref: None,
                text: "Invoice INV-2026-0042 from CloudHost Inc for March dedicated server cluster hosting".into(),
            },
            SearchIndexableRecord {
                id: SearchRecordId::Document(Oid([0x22; 32])),
                recorded_at: 3,
                subject_ref: Some(party_alice),
                text: "Consulting agreement addendum for Alice Mercer executive advisory retainer".into(),
            },
            SearchIndexableRecord {
                id: SearchRecordId::Entry(VId(101)),
                recorded_at: 4,
                subject_ref: Some(party_alice),
                text: "Accrued executive advisory retainer for Alice Mercer March period".into(),
            },
            SearchIndexableRecord {
                id: SearchRecordId::Entry(VId(102)),
                recorded_at: 5,
                subject_ref: Some(party_bob),
                text: "Reimbursement memo for Bob Vance travel and freight logistics".into(),
            },
            SearchIndexableRecord {
                id: SearchRecordId::Finding(VId(501)),
                recorded_at: 6,
                subject_ref: None,
                text: "Cutoff anomaly flagged on dedicated server cluster hosting invoice near quarter close".into(),
            },
        ];
        (records, live_keys)
    }

    #[test]
    fn deterministic_rebuild_pins_manifest_digest_and_verifies_against_journal() {
        let book_id = Id128([0x44; 16]);
        let (records, live_keys) = fixture_records();

        let (idx1, man1) =
            QuillLexicalIndex::rebuild_deterministic(book_id, 10, &records, &live_keys).unwrap();
        let (idx2, man2) =
            QuillLexicalIndex::rebuild_deterministic(book_id, 10, &records, &live_keys).unwrap();
        assert_eq!(man1, man2);
        assert_eq!(man1.digest().unwrap(), man2.digest().unwrap());
        assert_eq!(man1.indexed_record_count, 5);
        assert_eq!(man1.erased_record_count, 0);

        // FSLX segment round-trips byte-for-byte
        let seg_bytes = idx1.segments[0].canonical_bytes().unwrap();
        let decoded_seg = FslxSegment::decode(&seg_bytes).unwrap();
        assert_eq!(idx1.segments[0], decoded_seg);

        // `verify_against_journal` succeeds on matching state
        let receipt = idx1.verify_against_journal(&records, &live_keys).unwrap();
        assert_eq!(receipt.manifest_digest, man1.digest().unwrap());
        assert_eq!(receipt.corpus_hash, idx2.manifest().unwrap().corpus_hash);

        // Planted drift: mutating a record in the journal without rebuilding is caught by verify
        let mut drifted_records = records.clone();
        drifted_records[0].text.push_str(" tampered");
        let err = idx1
            .verify_against_journal(&drifted_records, &live_keys)
            .unwrap_err();
        assert!(matches!(err, SearchError::VerificationDrift(_)));
    }

    #[test]
    fn subject_key_erasure_removes_all_subject_text_from_index_and_matches_fresh_rebuild() {
        let book_id = Id128([0x44; 16]);
        let (records, mut live_keys) = fixture_records();
        let party_alice = Id128([0xA1; 16]);

        let (mut idx, _) =
            QuillLexicalIndex::rebuild_deterministic(book_id, 10, &records, &live_keys).unwrap();

        // Before erasure, searching for "Alice Mercer" returns 2 hits (Document + Entry)
        let before_hits = idx.search("Alice Mercer retainer", None);
        assert_eq!(before_hits.len(), 2);

        // Destroy Alice's subject key
        idx.erase_subject_key(party_alice);
        live_keys.remove(&party_alice);

        // After erasure, searching for "Alice", "Mercer", or "retainer" returns 0 hits
        assert!(idx.search("Alice", None).is_empty());
        assert!(idx.search("Mercer", None).is_empty());
        assert!(idx.search("retainer", None).is_empty());

        // And the raw FSLX segment bytes contain zero occurrences of "Alice" or "Mercer"
        let seg_bytes = idx.segments[0].canonical_bytes().unwrap();
        let seg_str = String::from_utf8_lossy(&seg_bytes);
        assert!(!seg_str.contains("Alice"));
        assert!(!seg_str.contains("Mercer"));

        // And the index after in-place erasure verifies identically against a fresh rebuild with Alice's key absent
        let receipt = idx.verify_against_journal(&records, &live_keys).unwrap();
        assert_eq!(receipt.indexed_record_count, 3);
        assert_eq!(receipt.erased_record_count, 2);
    }

    #[test]
    fn bm25_ranked_search_kind_filtering_delta_visibility_and_snippets_work() {
        let book_id = Id128([0x44; 16]);
        let (records, live_keys) = fixture_records();
        let (mut idx, _) =
            QuillLexicalIndex::rebuild_deterministic(book_id, 10, &records, &live_keys).unwrap();

        // Query matching both Document(0x11) and Finding(501)
        let hits = idx.search("dedicated server cluster hosting", None);
        assert_eq!(hits.len(), 2);
        assert!(hits[0].score_micro > 0);
        assert!(hits[0].snippet.contains("[dedicated]"));

        // Kind filter: `--kind finding`
        let finding_hits = idx.search(
            "dedicated server cluster hosting",
            Some(SearchRecordKind::Finding),
        );
        assert_eq!(finding_hits.len(), 1);
        assert_eq!(finding_hits[0].id, SearchRecordId::Finding(VId(501)));

        // Delta-visible indexing: append a new entry and search immediately before segment flush
        idx.append_delta(SearchIndexableRecord {
            id: SearchRecordId::Entry(VId(103)),
            recorded_at: 11,
            subject_ref: None,
            text: "Wire settlement confirmation for semiconductor lithography equipment".into(),
        });
        let delta_hits = idx.search("lithography semiconductor", None);
        assert_eq!(delta_hits.len(), 1);
        assert_eq!(delta_hits[0].id, SearchRecordId::Entry(VId(103)));

        // Empty results return empty Vec (exit 0)
        assert!(idx.search("nonexistent_token_xyz987", None).is_empty());
    }
}
