//! A source's declared feed population, compared with checked posted children.
//!
//! A manifest is retained and independently reviewed as a Workpaper. It is not
//! another posting and does not relax a child batch's immutable bounds. This
//! module proves equality with a supplied population; the storage caller must
//! select every original summary for the feed and inclusive effective window
//! at one fixed recorded prefix and verify each child's historical evidence.
//! Equality with this declaration does not establish the source system's truth.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::limits::MAX_DIMENSIONS_PER_LEG;
use fa_model::symbols::property;
use fa_model::{EntryRef, EvidenceRef, Id128, Oid, Reader, Writer};
use fa_money::{Side, UnitId};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use super::{
    EXTERNAL_SUBLEDGER_DOCUMENT_KIND, EXTERNAL_SUBLEDGER_EVIDENCE_ROLE,
    ExternalSubledgerReconciliation, MAX_EXTERNAL_DETAIL_ROWS, MAX_EXTERNAL_SUMMARY_LEGS, corrupt,
    identifier, invalid, review_from_row,
};
use crate::attestation::{Review, review_vid};
use crate::evidence::{doc_commit, document_oid, document_vid, verify_row};
use crate::{BookContext, Outcome, Refusal};

pub const EXTERNAL_FEED_MANIFEST_FORMAT: &[u8] = b"fa:external-feed-manifest:v1";
pub const EXTERNAL_FEED_MANIFEST_MIME: &str = "application/vnd.franken.subledger-manifest.v1";
pub const EXTERNAL_FEED_MANIFEST_REPORT_FORMAT: &[u8] =
    b"fa:external-feed-manifest-verification:v1";
pub const MAX_EXTERNAL_MANIFEST_CHILDREN: usize = 4096;
pub const MAX_EXTERNAL_MANIFEST_TOTALS: usize = 4096;
pub const MAX_EXTERNAL_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_EXTERNAL_MANIFEST_REPORT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedManifestChild {
    pub batch_key: String,
    /// The Workpaper commitment returned by `ExternalSubledgerBatch::evidence`.
    pub detail_commit: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedManifestTotal {
    pub account: VId,
    pub unit: UnitId,
    pub dimensions: Vec<(u32, VId)>,
    pub debits: i128,
    pub credits: i128,
}

type Cell = (VId, UnitId, Vec<(u32, VId)>);

impl ExternalFeedManifestTotal {
    fn key(&self) -> Cell {
        (self.account, self.unit, self.dimensions.clone())
    }
}

/// The expected complete population of original source batches in a window.
/// Children are strictly ordered by batch key and totals by account, unit and
/// dimensions. Duplicate identities or cells refuse; no input is deduplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedManifest {
    pub book_id: Id128,
    pub feed: String,
    pub extract_id: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    pub children: Vec<ExternalFeedManifestChild>,
    pub detail_rows: u64,
    pub totals: Vec<ExternalFeedManifestTotal>,
}

fn dimensions_valid(values: &[(u32, VId)]) -> bool {
    values.len() <= MAX_DIMENSIONS_PER_LEG && values.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

fn add_size(size: &mut usize, amount: usize, limit: usize) -> Result<(), Refusal> {
    *size = size
        .checked_add(amount)
        .filter(|size| *size <= limit)
        .ok_or_else(|| {
            invalid("complete feed manifest exceeds its byte bound; nothing was truncated")
        })?;
    Ok(())
}

fn write_dimensions(w: &mut Writer, values: &[(u32, VId)]) {
    w.list(values, |w, (kind, value)| {
        w.u32(*kind).u128(value.0);
    });
}

impl ExternalFeedManifest {
    fn validate(&self) -> Result<usize, Refusal> {
        if !identifier(&self.feed, 64) || !identifier(&self.extract_id, 128) {
            return Err(invalid(
                "manifest feed and extract_id require bounded nonpersonal identifiers",
            ));
        }
        if self.effective_from > self.effective_through {
            return Err(invalid("manifest effective window is reversed"));
        }
        if self.children.len() > MAX_EXTERNAL_MANIFEST_CHILDREN
            || self.totals.len() > MAX_EXTERNAL_MANIFEST_TOTALS
        {
            return Err(invalid(
                "manifest exceeds 4096 children or 4096 gross total cells",
            ));
        }
        if self
            .children
            .windows(2)
            .any(|pair| pair[0].batch_key >= pair[1].batch_key)
        {
            return Err(invalid(
                "manifest children must be unique and strictly ordered by batch key",
            ));
        }
        if self
            .totals
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(invalid(
                "manifest total cells must be unique and strictly ordered by account, unit and dimensions",
            ));
        }
        let max_rows = (self.children.len() as u64)
            .checked_mul(MAX_EXTERNAL_DETAIL_ROWS as u64)
            .ok_or_else(|| invalid("manifest row-count bound overflow"))?;
        if self.detail_rows < self.children.len() as u64 || self.detail_rows > max_rows {
            return Err(invalid(
                "manifest row count is outside the declared child population's bounds",
            ));
        }
        if self.children.is_empty() != self.totals.is_empty() {
            return Err(invalid(
                "an empty manifest requires zero rows and no total cells; a nonempty manifest requires totals",
            ));
        }
        let mut size = EXTERNAL_FEED_MANIFEST_FORMAT.len()
            + 16
            + 4
            + self.feed.len()
            + 4
            + self.extract_id.len()
            + 4
            + 4
            + 8
            + 4
            + 4;
        for child in &self.children {
            if !identifier(&child.batch_key, 128) || child.detail_commit == [0; 32] {
                return Err(invalid(
                    "each manifest child requires a bounded batch key and a nonzero detail commitment",
                ));
            }
            add_size(
                &mut size,
                4 + child.batch_key.len() + 32,
                MAX_EXTERNAL_MANIFEST_BYTES,
            )?;
        }
        for total in &self.totals {
            if !dimensions_valid(&total.dimensions)
                || total.debits < 0
                || total.credits < 0
                || (total.debits == 0 && total.credits == 0)
            {
                return Err(invalid(
                    "manifest total cells require ordered bounded dimensions and nonnegative gross sides with at least one positive side",
                ));
            }
            add_size(
                &mut size,
                56 + total.dimensions.len() * 20,
                MAX_EXTERNAL_MANIFEST_BYTES,
            )?;
        }
        Ok(size)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let size = self.validate()?;
        let mut w = Writer::with_capacity(size);
        w.fixed(EXTERNAL_FEED_MANIFEST_FORMAT)
            .fixed(&self.book_id.0)
            .str(&self.feed)
            .str(&self.extract_id)
            .i32(self.effective_from.0)
            .i32(self.effective_through.0)
            .u64(self.detail_rows)
            .list(&self.children, |w, child| {
                w.str(&child.batch_key).fixed(&child.detail_commit);
            })
            .list(&self.totals, |w, total| {
                w.u128(total.account.0).u32(total.unit.0);
                write_dimensions(w, &total.dimensions);
                w.i128(total.debits).i128(total.credits);
            });
        let bytes = w.finish().map_err(invalid)?;
        if bytes.len() != size {
            return Err(invalid("manifest encoded size differs from its bound"));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EXTERNAL_MANIFEST_BYTES {
            return Err(invalid("manifest exceeds the 1 MiB document bound"));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<{ EXTERNAL_FEED_MANIFEST_FORMAT.len() }>("manifest.format")
            .map_err(invalid)?
            .as_slice()
            != EXTERNAL_FEED_MANIFEST_FORMAT
        {
            return Err(invalid("unsupported external feed manifest format"));
        }
        let book_id = Id128(r.fixed("manifest.book").map_err(invalid)?);
        let feed = r.str(64, "manifest.feed").map_err(invalid)?.into();
        let extract_id = r.str(128, "manifest.extract").map_err(invalid)?.into();
        let effective_from = DateDay(r.i32("manifest.from").map_err(invalid)?);
        let effective_through = DateDay(r.i32("manifest.through").map_err(invalid)?);
        let detail_rows = r.u64("manifest.rows").map_err(invalid)?;
        let children = r
            .list(MAX_EXTERNAL_MANIFEST_CHILDREN, "manifest.children", |r| {
                Ok(ExternalFeedManifestChild {
                    batch_key: r.str(128, "manifest.child.key")?.into(),
                    detail_commit: r.fixed("manifest.child.commit")?,
                })
            })
            .map_err(invalid)?;
        let totals = r
            .list(MAX_EXTERNAL_MANIFEST_TOTALS, "manifest.totals", |r| {
                let account = VId(r.u128("manifest.total.account")?);
                let unit = UnitId(r.u32("manifest.total.unit")?);
                let dimensions =
                    r.list(MAX_DIMENSIONS_PER_LEG, "manifest.total.dimensions", |r| {
                        Ok((
                            r.u32("manifest.dimension.kind")?,
                            VId(r.u128("manifest.dimension.value")?),
                        ))
                    })?;
                Ok(ExternalFeedManifestTotal {
                    account,
                    unit,
                    dimensions,
                    debits: r.i128("manifest.total.debits")?,
                    credits: r.i128("manifest.total.credits")?,
                })
            })
            .map_err(invalid)?;
        r.finish().map_err(invalid)?;
        let value = Self {
            book_id,
            feed,
            extract_id,
            effective_from,
            effective_through,
            children,
            detail_rows,
            totals,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical external feed manifest"));
        }
        Ok(value)
    }

    pub fn evidence(&self) -> Result<EvidenceRef, Refusal> {
        let commitment = doc_commit(EXTERNAL_SUBLEDGER_DOCUMENT_KIND, &self.canonical_bytes()?);
        Ok(EvidenceRef {
            document_oid: document_oid(self.book_id, &commitment),
            doc_commit: commitment,
            role: EXTERNAL_SUBLEDGER_EVIDENCE_ROLE,
        })
    }

    /// Compare a complete, independently verified population of original
    /// summaries selected at one recorded prefix. Reversals are not children:
    /// they change accounting activity, not whether a source batch arrived.
    /// Missing or extra children yield `Incomplete`; a changed child digest,
    /// or wrong totals/counts for an otherwise exact population, yields
    /// `Mismatch`. All cells are still reported for an incomplete population.
    pub fn verify(
        &self,
        batches: &[ExternalSubledgerReconciliation],
    ) -> Result<ExternalFeedManifestVerification, Refusal> {
        self.validate()?;
        if batches.len() > MAX_EXTERNAL_MANIFEST_CHILDREN {
            return Err(invalid(
                "observed feed population exceeds 4096 children; nothing was truncated",
            ));
        }
        let expected: BTreeMap<_, _> = self
            .children
            .iter()
            .map(|child| (child.batch_key.as_str(), child.detail_commit))
            .collect();
        let mut children = BTreeMap::new();
        let mut actual_detail_rows = 0u64;
        let mut actual: BTreeMap<Cell, [i128; 2]> = BTreeMap::new();
        for batch in batches {
            if !batch.reconciled
                || batch.feed != self.feed
                || batch.effective_date < self.effective_from
                || batch.effective_date > self.effective_through
                || !identifier(&batch.batch_key, 128)
                || batch.detail_rows == 0
                || batch.detail_rows > MAX_EXTERNAL_DETAIL_ROWS
                || batch.summary_legs.len() < 2
                || batch.summary_legs.len() > MAX_EXTERNAL_SUMMARY_LEGS
                || batch.evidence.doc_commit == [0; 32]
                || batch.evidence.role != EXTERNAL_SUBLEDGER_EVIDENCE_ROLE
                || batch.evidence.document_oid
                    != document_oid(self.book_id, &batch.evidence.doc_commit)
            {
                return Err(invalid(
                    "manifest comparison requires independently verified children from this book, feed and effective window",
                ));
            }
            let observed = ExternalFeedManifestObservedChild {
                batch_key: batch.batch_key.clone(),
                entry: batch.entry,
                recorded_at: batch.recorded_at,
                effective_date: batch.effective_date,
                evidence: batch.evidence,
                review: batch.review,
                detail_rows: batch.detail_rows as u64,
            };
            if children.insert(batch.batch_key.clone(), observed).is_some() {
                return Err(invalid(
                    "two observed summaries consume the same manifest child key",
                ));
            }
            actual_detail_rows = actual_detail_rows
                .checked_add(batch.detail_rows as u64)
                .ok_or_else(|| invalid("manifest observed row count overflow"))?;
            for leg in &batch.summary_legs {
                if leg.amount.mantissa <= 0 || !dimensions_valid(&leg.dimension_set) {
                    return Err(invalid("manifest child has invalid gross posting effects"));
                }
                let key = (leg.account_ref, leg.amount.unit, leg.dimension_set.clone());
                let sides = actual.entry(key).or_default();
                let side = usize::from(leg.side == Side::Credit);
                sides[side] = sides[side]
                    .checked_add(leg.amount.mantissa)
                    .ok_or_else(|| {
                        invalid("manifest gross total overflows the exact i128 amount domain")
                    })?;
                if actual.len() > MAX_EXTERNAL_MANIFEST_TOTALS {
                    return Err(invalid(
                        "observed feed exceeds 4096 gross total cells; nothing was truncated",
                    ));
                }
            }
        }
        let missing: Vec<_> = self
            .children
            .iter()
            .filter(|child| !children.contains_key(&child.batch_key))
            .map(|child| child.batch_key.clone())
            .collect();
        let unexpected: Vec<_> = children
            .keys()
            .filter(|key| !expected.contains_key(key.as_str()))
            .cloned()
            .collect();
        let digest_mismatches: Vec<_> = children
            .values()
            .filter_map(|child| {
                expected
                    .get(child.batch_key.as_str())
                    .and_then(|expected_commit| {
                        (*expected_commit != child.evidence.doc_commit).then(|| {
                            ExternalFeedManifestDigestMismatch {
                                batch_key: child.batch_key.clone(),
                                expected_commit: *expected_commit,
                                actual_commit: child.evidence.doc_commit,
                            }
                        })
                    })
            })
            .collect();
        let declared: BTreeMap<_, _> = self
            .totals
            .iter()
            .map(|total| (total.key(), [total.debits, total.credits]))
            .collect();
        let keys: BTreeSet<_> = declared.keys().chain(actual.keys()).cloned().collect();
        let totals: Vec<_> = keys
            .into_iter()
            .map(|(account, unit, dimensions)| {
                let key = (account, unit, dimensions.clone());
                let expected = declared.get(&key).copied().unwrap_or([0; 2]);
                let actual = actual.get(&key).copied().unwrap_or([0; 2]);
                ExternalFeedManifestTotalComparison {
                    account,
                    unit,
                    dimensions,
                    expected_debits: expected[0],
                    expected_credits: expected[1],
                    actual_debits: actual[0],
                    actual_credits: actual[1],
                }
            })
            .collect();
        let status = if !digest_mismatches.is_empty() {
            ExternalFeedManifestStatus::Mismatch
        } else if !missing.is_empty() || !unexpected.is_empty() {
            ExternalFeedManifestStatus::Incomplete
        } else if actual_detail_rows != self.detail_rows
            || totals.iter().any(|total| !total.matches())
        {
            ExternalFeedManifestStatus::Mismatch
        } else {
            ExternalFeedManifestStatus::Complete
        };
        let report = ExternalFeedManifestVerification {
            manifest: self.clone(),
            children: children.into_values().collect(),
            missing,
            unexpected,
            digest_mismatches,
            actual_detail_rows,
            totals,
            status,
        };
        report.canonical_bytes()?;
        Ok(report)
    }
}

/// Bind supplied bytes to the immutable Workpaper and independent review
/// visible at the report's selected prefix. The caller authorizes and obtains
/// the bytes through the ordinary redaction-aware document read first; this
/// helper supports both inline and externally stored document payloads.
pub fn reviewed_manifest_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    document: Oid,
    bytes: &[u8],
    known_at: CommitSeq,
) -> Outcome<(ExternalFeedManifest, Review)> {
    let manifest = match ExternalFeedManifest::decode(bytes) {
        Ok(manifest) => manifest,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let citation = match manifest.evidence() {
        Ok(citation) => citation,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if manifest.book_id != book.book_id || citation.document_oid != document {
        return Ok(Err(invalid(
            "manifest belongs to another book or retained document",
        )));
    }
    let vid = document_vid(&document);
    let Some(row) = db.vertex_at(vid, known_at)? else {
        return Ok(Err(invalid(
            "manifest Workpaper is absent at the selected prefix",
        )));
    };
    let policy = EvidencePolicy::embedded().map_err(corrupt)?;
    let retained = match verify_row(&row, &policy) {
        Ok(retained) => retained,
        Err(error) => return Ok(Err(invalid(error))),
    };
    if retained.book_id != book.book_id
        || retained.kind != EXTERNAL_SUBLEDGER_DOCUMENT_KIND
        || retained.mime != EXTERNAL_FEED_MANIFEST_MIME
        || retained.size != bytes.len() as u64
        || retained.doc_commit != citation.doc_commit
        || retained.oid() != document
    {
        return Ok(Err(invalid(
            "retained manifest Workpaper metadata or commitment differs",
        )));
    }
    let Some(original) = db.vertex_at(vid, row.created_at)? else {
        return Ok(Err(invalid(
            "manifest Workpaper birth history is unavailable",
        )));
    };
    if original.created_at != row.created_at
        || original.labels != row.labels
        || [
            property::FA_PAYLOAD,
            property::FA_DIGEST,
            property::BOOK_ID,
            property::CODE,
        ]
        .iter()
        .any(|key| crate::rows::prop(&original, *key) != crate::rows::prop(&row, *key))
    {
        return Ok(Err(invalid(
            "manifest Workpaper changed after its original receipt",
        )));
    }
    let review_id = review_vid(book.book_id, &document);
    let Some(review_row) = db.vertex_at(review_id, known_at)? else {
        return Ok(Err(invalid(
            "manifest Workpaper has no independent review at the selected prefix",
        )));
    };
    let review = match review_from_row(&review_row, book.book_id, &retained) {
        Ok(review) => review,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(original_review) = db.vertex_at(review_id, review_row.created_at)? else {
        return Ok(Err(invalid("manifest review birth history is unavailable")));
    };
    if original_review != review_row {
        return Ok(Err(invalid(
            "manifest review changed after its original publication",
        )));
    }
    Ok(Ok((manifest, review)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalFeedManifestStatus {
    Complete,
    Incomplete,
    Mismatch,
}

impl ExternalFeedManifestStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Mismatch => "mismatch",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Incomplete => 1,
            Self::Mismatch => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedManifestObservedChild {
    pub batch_key: String,
    pub entry: EntryRef,
    pub recorded_at: CommitSeq,
    pub effective_date: DateDay,
    pub evidence: EvidenceRef,
    pub review: Review,
    pub detail_rows: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedManifestDigestMismatch {
    pub batch_key: String,
    pub expected_commit: [u8; 32],
    pub actual_commit: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedManifestTotalComparison {
    pub account: VId,
    pub unit: UnitId,
    pub dimensions: Vec<(u32, VId)>,
    pub expected_debits: i128,
    pub expected_credits: i128,
    pub actual_debits: i128,
    pub actual_credits: i128,
}

impl ExternalFeedManifestTotalComparison {
    #[must_use]
    pub const fn matches(&self) -> bool {
        self.expected_debits == self.actual_debits && self.expected_credits == self.actual_credits
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedManifestVerification {
    pub manifest: ExternalFeedManifest,
    pub children: Vec<ExternalFeedManifestObservedChild>,
    pub missing: Vec<String>,
    pub unexpected: Vec<String>,
    pub digest_mismatches: Vec<ExternalFeedManifestDigestMismatch>,
    pub actual_detail_rows: u64,
    pub totals: Vec<ExternalFeedManifestTotalComparison>,
    pub status: ExternalFeedManifestStatus,
}

impl ExternalFeedManifestVerification {
    /// Deterministic output for an enclosing fixed-prefix certificate. This
    /// encoding binds the complete declaration, every observed child and
    /// review, and both gross sides of every compared cell.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let manifest = self.manifest.canonical_bytes()?;
        if self.children.len() > MAX_EXTERNAL_MANIFEST_CHILDREN
            || self.missing.len() > MAX_EXTERNAL_MANIFEST_CHILDREN
            || self.unexpected.len() > MAX_EXTERNAL_MANIFEST_CHILDREN
            || self.digest_mismatches.len() > MAX_EXTERNAL_MANIFEST_CHILDREN
            || self.totals.len() > MAX_EXTERNAL_MANIFEST_TOTALS * 2
        {
            return Err(invalid(
                "manifest verification output exceeds its population bounds",
            ));
        }
        let mut size =
            4 + EXTERNAL_FEED_MANIFEST_REPORT_FORMAT.len() + 4 + manifest.len() + 5 * 4 + 8 + 1;
        for child in &self.children {
            if !identifier(&child.batch_key, 128) {
                return Err(invalid("manifest output child has an invalid batch key"));
            }
            add_size(
                &mut size,
                169 + child.batch_key.len(),
                MAX_EXTERNAL_MANIFEST_REPORT_BYTES,
            )?;
        }
        for key in self.missing.iter().chain(&self.unexpected) {
            if !identifier(key, 128) {
                return Err(invalid(
                    "manifest output has an invalid missing or extra key",
                ));
            }
            add_size(&mut size, 4 + key.len(), MAX_EXTERNAL_MANIFEST_REPORT_BYTES)?;
        }
        for child in &self.digest_mismatches {
            if !identifier(&child.batch_key, 128) {
                return Err(invalid("manifest mismatch has an invalid batch key"));
            }
            add_size(
                &mut size,
                68 + child.batch_key.len(),
                MAX_EXTERNAL_MANIFEST_REPORT_BYTES,
            )?;
        }
        for total in &self.totals {
            if !dimensions_valid(&total.dimensions) {
                return Err(invalid("manifest output has invalid dimensions"));
            }
            add_size(
                &mut size,
                88 + total.dimensions.len() * 20,
                MAX_EXTERNAL_MANIFEST_REPORT_BYTES,
            )?;
        }
        let mut w = Writer::with_capacity(size);
        w.bytes(EXTERNAL_FEED_MANIFEST_REPORT_FORMAT)
            .bytes(&manifest)
            .list(&self.children, |w, child| {
                w.str(&child.batch_key)
                    .u128(child.entry.vid.0)
                    .fixed(&child.entry.entry_digest)
                    .u64(child.recorded_at.0)
                    .i32(child.effective_date.0)
                    .fixed(&child.evidence.document_oid.0)
                    .fixed(&child.evidence.doc_commit)
                    .u8(child.evidence.role)
                    .u128(child.review.attestation.0)
                    .u128(child.review.reviewer.0)
                    .u64(child.detail_rows);
            })
            .list(&self.missing, |w, key| {
                w.str(key);
            })
            .list(&self.unexpected, |w, key| {
                w.str(key);
            })
            .list(&self.digest_mismatches, |w, child| {
                w.str(&child.batch_key)
                    .fixed(&child.expected_commit)
                    .fixed(&child.actual_commit);
            })
            .u64(self.actual_detail_rows)
            .list(&self.totals, |w, total| {
                w.u128(total.account.0).u32(total.unit.0);
                write_dimensions(w, &total.dimensions);
                w.i128(total.expected_debits)
                    .i128(total.expected_credits)
                    .i128(total.actual_debits)
                    .i128(total.actual_credits);
            })
            .u8(self.status.tag());
        let bytes = w.finish().map_err(invalid)?;
        if bytes.len() != size {
            return Err(invalid(
                "manifest verification encoded size differs from its bound",
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
