//! Matched external subledger summaries (plan §5.6, FA-INV-12).
//!
//! Detail is retained as an independently reviewed Workpaper, never posted a
//! second time. An Original entry binds the complete canonical detail bytes
//! and posts their gross per-account/unit/dimension/side fold. The ordinary
//! balance, period, account, authority and evidence laws still apply.
//!
//! This proves a named feed batch's summary, not that an entire control
//! account contains only external feeds or that the source system supplied
//! every transaction. Source identifiers are opaque digests, not personal data.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::entry::EXTERNAL_SUBLEDGER_EXTENSION;
use fa_model::limits::MAX_DIMENSIONS_PER_LEG;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload, Reader,
    Writer, domain_digest, entry_mirrors,
};
use fa_money::{Amount, Side, UnitId};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn};
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::attestation::{AttestationClaim, Review, Subject, review_vid, verify_attestation_row};
use crate::evidence::{DocumentRecord, doc_commit, document_oid, document_vid, verify_row};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, scalar_bytes};

pub const EXTERNAL_SUBLEDGER_DOCUMENT_KIND: u8 = 21;
pub const EXTERNAL_SUBLEDGER_EVIDENCE_ROLE: u8 = 1;
pub const EXTERNAL_SUBLEDGER_MIME: &str = "application/vnd.franken.subledger-detail.v1";
pub const MAX_EXTERNAL_DETAIL_ROWS: usize = 128;
pub const MAX_EXTERNAL_SUMMARY_LEGS: usize = 32;
pub const MAX_EXTERNAL_DETAIL_BYTES: usize = 8192;
const FORMAT: &[u8] = b"fa:external-subledger-detail:v1";

/// One source-row contribution to the asserted summary. The source digest
/// commits the external row including its source identity; it must be unique.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalSubledgerDetail {
    pub source_digest: [u8; 32],
    pub account: VId,
    pub side: Side,
    pub amount: Amount,
    pub dimensions: Vec<(u32, VId)>,
}

/// Explicit native effects of one source batch, including all counterpart
/// effects. An imbalance is refused by Folio; this format never inserts a plug.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalSubledgerBatch {
    pub book_id: Id128,
    pub feed: String,
    pub batch_key: String,
    pub effective_date: DateDay,
    pub rows: Vec<ExternalSubledgerDetail>,
}

type SummaryKey = (VId, UnitId, Vec<(u32, VId)>, u8);

fn side_tag(side: Side) -> u8 {
    match side {
        Side::Debit => 0,
        Side::Credit => 1,
    }
}

fn identifier(value: &str, bound: usize) -> bool {
    !value.is_empty()
        && value.len() <= bound
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn invalid(message: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::EXTERNAL_SUBLEDGER,
        exit::REFUSAL,
        format!("external subledger feed: {message}"),
        "plan §5.6 / FA-INV-12 (the reviewed detail batch must exactly reproduce the summary)",
        "prepare a complete native detail batch, retain it as a Workpaper, have another principal review it, then prepare the summary from that document",
    )
}

fn corrupt(message: impl core::fmt::Display) -> KernelError {
    KernelError::Corrupt(format!("external subledger feed: {message}"))
}

impl ExternalSubledgerBatch {
    fn validate(&self) -> Result<(), Refusal> {
        if !identifier(&self.feed, 64) || !identifier(&self.batch_key, 128) {
            return Err(invalid(
                "feed and batch_key must be nonempty bounded identifiers using letters, digits or ._:/-",
            ));
        }
        if self.rows.is_empty() || self.rows.len() > MAX_EXTERNAL_DETAIL_ROWS {
            return Err(invalid("detail requires between 1 and 128 source rows"));
        }
        if self
            .rows
            .windows(2)
            .any(|pair| pair[0].source_digest >= pair[1].source_digest)
        {
            return Err(invalid(
                "detail source digests must be unique and strictly increasing",
            ));
        }
        for row in &self.rows {
            if row.source_digest == [0; 32] || row.amount.mantissa <= 0 {
                return Err(invalid(
                    "every detail row requires a nonzero source digest and a positive native amount",
                ));
            }
            if row.dimensions.len() > MAX_DIMENSIONS_PER_LEG
                || row.dimensions.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            {
                return Err(invalid(
                    "detail dimensions must be bounded and strictly ordered by dimension id",
                ));
            }
        }
        Ok(())
    }

    /// The exact bytes imported as a Workpaper. Ordering is explicit and
    /// survives replay; the constructor does not deduplicate source records.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        self.validate()?;
        let mut w = Writer::new();
        w.fixed(FORMAT)
            .fixed(&self.book_id.0)
            .str(&self.feed)
            .str(&self.batch_key)
            .i32(self.effective_date.0)
            .list(&self.rows, |w, row| {
                w.fixed(&row.source_digest)
                    .u128(row.account.0)
                    .u8(side_tag(row.side))
                    .u32(row.amount.unit.0)
                    .i128(row.amount.mantissa)
                    .list(&row.dimensions, |w, (kind, value)| {
                        w.u32(*kind).u128(value.0);
                    });
            });
        let bytes = w.finish().map_err(invalid)?;
        if bytes.len() > MAX_EXTERNAL_DETAIL_BYTES {
            return Err(invalid(
                "detail exceeds the 8192-byte posting bound; split the source into separately identified complete batches",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EXTERNAL_DETAIL_BYTES {
            return Err(invalid("detail exceeds the 8192-byte posting bound"));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<{ FORMAT.len() }>("external-detail.format")
            .map_err(invalid)?
            .as_slice()
            != FORMAT
        {
            return Err(invalid("unsupported external detail format"));
        }
        let book_id = Id128(r.fixed::<16>("external-detail.book").map_err(invalid)?);
        let feed = r.str(64, "external-detail.feed").map_err(invalid)?.into();
        let batch_key = r.str(128, "external-detail.batch").map_err(invalid)?.into();
        let effective_date = DateDay(r.i32("external-detail.effective").map_err(invalid)?);
        let rows = r
            .list(MAX_EXTERNAL_DETAIL_ROWS, "external-detail.rows", |r| {
                let source_digest = r.fixed::<32>("external-detail.source")?;
                let account = VId(r.u128("external-detail.account")?);
                let side = match r.u8("external-detail.side")? {
                    0 => Side::Debit,
                    1 => Side::Credit,
                    tag => return Err(r.bad_tag("external-detail.side", tag)),
                };
                let amount = Amount::new(
                    UnitId(r.u32("external-detail.unit")?),
                    r.i128("external-detail.mantissa")?,
                );
                let dimensions =
                    r.list(MAX_DIMENSIONS_PER_LEG, "external-detail.dimensions", |r| {
                        Ok((r.u32("dimension.kind")?, VId(r.u128("dimension.value")?)))
                    })?;
                Ok(ExternalSubledgerDetail {
                    source_digest,
                    account,
                    side,
                    amount,
                    dimensions,
                })
            })
            .map_err(invalid)?;
        r.finish().map_err(invalid)?;
        let batch = Self {
            book_id,
            feed,
            batch_key,
            effective_date,
            rows,
        };
        if batch.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical external detail encoding"));
        }
        Ok(batch)
    }

    pub fn evidence(&self) -> Result<EvidenceRef, Refusal> {
        let commitment = doc_commit(EXTERNAL_SUBLEDGER_DOCUMENT_KIND, &self.canonical_bytes()?);
        Ok(EvidenceRef {
            document_oid: document_oid(self.book_id, &commitment),
            doc_commit: commitment,
            role: EXTERNAL_SUBLEDGER_EVIDENCE_ROLE,
        })
    }

    /// Debit and credit columns remain separate, including offsetting rows
    /// on the same account. Party/entity dimensions never disappear in a net.
    pub fn summary_legs(&self) -> Result<Vec<LegPayload>, Refusal> {
        self.validate()?;
        let mut sums: BTreeMap<SummaryKey, i128> = BTreeMap::new();
        for row in &self.rows {
            let key = (
                row.account,
                row.amount.unit,
                row.dimensions.clone(),
                side_tag(row.side),
            );
            let total = sums.entry(key).or_default();
            *total = total.checked_add(row.amount.mantissa).ok_or_else(|| {
                invalid("gross detail column overflows the exact i128 amount domain")
            })?;
        }
        if sums.len() < 2 || sums.len() > MAX_EXTERNAL_SUMMARY_LEGS {
            return Err(invalid(
                "a summary requires between 2 and 32 gross posting legs",
            ));
        }
        Ok(sums
            .into_iter()
            .map(|((account, unit, dimensions, side), amount)| {
                let mut leg = LegPayload::simple(
                    if side == 0 { Side::Debit } else { Side::Credit },
                    account,
                    Amount::new(unit, amount),
                );
                leg.dimension_set = dimensions;
                leg
            })
            .collect())
    }

    /// Fill an empty Original Intent template from the caller's complete
    /// detail effects. No current balance or inferred balancing leg is used.
    pub fn proposal(&self, mut template: EntryPayload) -> Result<EntryPayload, Refusal> {
        if template.class != EntryClass::ORIGINAL
            || !matches!(&template.origin, EntryOrigin::Intent { .. })
            || template.book_id != self.book_id
            || template.effective_date != self.effective_date
            || !template.legs.is_empty()
            || !template.unit_totals.is_empty()
            || !template.extensions.is_empty()
            || template.control.is_some()
            || template.base_totals.is_some()
            || template.pending.is_some()
            || !template.supersession.is_empty()
        {
            return Err(invalid(
                "use an empty Original Intent template with the detail batch's book and effective date",
            ));
        }
        let evidence = self.evidence()?;
        if !template.evidence.contains(&evidence) {
            return Err(invalid(
                "the template must cite the exact detail Workpaper as Source evidence",
            ));
        }
        template.legs = self.summary_legs()?;
        template.unit_totals = EntryPayload::fold_unit_totals(&template.legs).map_err(invalid)?;
        template.schema_minor = template.schema_minor.max(fa_model::entry::EXTENSIONS_MINOR);
        template.extensions = vec![(EXTERNAL_SUBLEDGER_EXTENSION, self.canonical_bytes()?)];
        template.validate().map_err(invalid)?;
        Ok(template)
    }

    /// The book/feed/source-batch identity is independent of the preparer
    /// and retry key. A second writer cannot post the same source batch again.
    #[must_use]
    pub fn identity(&self) -> VId {
        let digest = domain_digest(
            b"fa:vid:external-subledger-batch:v1",
            &[
                &self.book_id.0,
                self.feed.as_bytes(),
                self.batch_key.as_bytes(),
            ],
        );
        let mut low = [0; 16];
        low.copy_from_slice(&digest[..16]);
        VId(u128::from_le_bytes(low))
    }
}

/// Pure source-to-effects check, shared by admission and historical replay.
/// Equality includes gross columns and dimensions, not just net balances.
pub fn validate_summary(
    proposal: &EntryPayload,
) -> Result<Option<ExternalSubledgerBatch>, Refusal> {
    let Some((_, bytes)) = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == EXTERNAL_SUBLEDGER_EXTENSION)
    else {
        return Ok(None);
    };
    let batch = ExternalSubledgerBatch::decode(bytes)?;
    if proposal.class != EntryClass::ORIGINAL
        || !matches!(&proposal.origin, EntryOrigin::Intent { .. })
        || proposal.extensions.len() != 1
        || proposal.book_id != batch.book_id
        || proposal.effective_date != batch.effective_date
        || proposal.control.is_some()
        || proposal.base_totals.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
        || !proposal.evidence.contains(&batch.evidence()?)
    {
        return Err(invalid(
            "summary coordinate, class, lifecycle or source commitment differs from its detail batch",
        ));
    }
    if proposal.legs != batch.summary_legs()? {
        return Err(invalid(
            "summary legs do not equal the complete gross detail fold by account, unit, side and dimensions",
        ));
    }
    Ok(Some(batch))
}

fn review_from_row(
    row: &VertexRow,
    book: Id128,
    document: &DocumentRecord,
) -> Result<Review, Refusal> {
    let stored = verify_attestation_row(row).map_err(invalid)?;
    if stored.attestation.book_id != book
        || stored.attestation.subject != Subject::Document(document.oid())
        || !matches!(&stored.attestation.claim, AttestationClaim::Reviewed { .. })
        || stored.attestation.principal == document.retrieved_by
    {
        return Err(invalid(
            "the source requires an independent Reviewed attestation over the exact Workpaper",
        ));
    }
    Ok(Review {
        attestation: row.vid,
        reviewer: stored.attestation.principal,
    })
}

/// Called after ordinary request admission and exact retry recognition.
/// All evidence and the absent feed identity are point-read witnesses in the
/// same transaction that publishes the accounting entry and its identity.
pub(crate) fn witness<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    batch: &ExternalSubledgerBatch,
) -> Outcome<Review> {
    let citation = match batch.evidence() {
        Ok(citation) => citation,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let policy = EvidencePolicy::embedded().map_err(corrupt)?;
    let Some(row) = txn.vertex(db, document_vid(&citation.document_oid))? else {
        return Ok(Err(invalid(
            "the exact detail Workpaper has not been retained",
        )));
    };
    let document = match verify_row(&row, &policy) {
        Ok(document) => document,
        Err(error) => return Ok(Err(invalid(error))),
    };
    if document.book_id != book.book_id
        || document.oid() != citation.document_oid
        || document.doc_commit != citation.doc_commit
        || document.kind != EXTERNAL_SUBLEDGER_DOCUMENT_KIND
    {
        return Ok(Err(invalid(
            "retained detail document differs from the summary's commitment",
        )));
    }
    let Some(review_row) = txn.vertex(db, review_vid(book.book_id, &citation.document_oid))? else {
        return Ok(Err(invalid(
            "the detail Workpaper has no independent Reviewed attestation",
        )));
    };
    let review = match review_from_row(&review_row, book.book_id, &document) {
        Ok(review) => review,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if txn.vertex(db, batch.identity())?.is_some() {
        return Ok(Err(invalid(format!(
            "source batch {}/{} already has a committed summary; retry its original idempotency key or issue a separately identified correction batch",
            batch.feed, batch.batch_key,
        ))));
    }
    Ok(Ok(review))
}

fn projection(
    batch: &ExternalSubledgerBatch,
    entry: EntryRef,
) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
    let citation = batch
        .evidence()
        .map_err(|refusal| corrupt(refusal.message))?;
    let mut w = Writer::new();
    w.fixed(b"fa:external-subledger-summary:v1")
        .fixed(&batch.book_id.0)
        .str(&batch.feed)
        .str(&batch.batch_key)
        .u128(entry.vid.0)
        .fixed(&entry.entry_digest)
        .fixed(&citation.document_oid.0)
        .fixed(&citation.doc_commit);
    let payload = w.finish()?;
    let mut props = vec![
        (
            property::FA_DIGEST,
            scalar_bytes(
                "external feed digest",
                domain_digest(b"fa:external-subledger-summary:v1", &[&payload]).to_vec(),
            )?,
        ),
        (
            property::FA_PAYLOAD,
            scalar_bytes("external feed payload", payload)?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("external feed book", batch.book_id.0.to_vec())?,
        ),
        (
            property::TARGET_REF,
            scalar_bytes("external feed entry", entry.vid.0.to_le_bytes().to_vec())?,
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

pub(crate) fn stage(
    write: &mut WriteBatch,
    batch: &ExternalSubledgerBatch,
    entry: EntryRef,
) -> Result<(), KernelError> {
    write.create_vertex(
        batch.identity(),
        vec![label::EXTERNAL_SUBLEDGER_BATCH],
        projection(batch, entry)?,
    );
    Ok(())
}

pub(crate) fn review_edge(entry: VId, review: Review) -> WriteBatch {
    let mut write = WriteBatch::new(relation::REVIEWED_BY);
    write.add_edge(
        edge_id(relation::REVIEWED_BY, entry, review.attestation),
        entry,
        review.attestation,
        vec![],
    );
    write
}

/// A checked historical matched pair. The retained canonical entry and the
/// exact source document reproduce the same gross effects at entry creation.
/// This is a mechanical reconciliation, not a legal or source-completeness claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalSubledgerReconciliation {
    pub entry: EntryRef,
    pub recorded_at: CommitSeq,
    pub feed: String,
    pub batch_key: String,
    pub effective_date: DateDay,
    pub evidence: EvidenceRef,
    pub review: Review,
    pub detail_rows: usize,
    pub summary_legs: Vec<LegPayload>,
    pub reconciled: bool,
}

/// The caller must admit whole-book reads before entering this storage path.
/// Every dependency is read at the entry's recorded prefix, so a later review
/// cannot retroactively validate an unreviewed summary.
pub fn reconcile_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    target: EntryRef,
    known_at: CommitSeq,
) -> Outcome<ExternalSubledgerReconciliation> {
    let Some(row) = db.vertex_at(target.vid, known_at)? else {
        return Ok(Err(invalid(
            "the selected summary entry is absent at this prefix",
        )));
    };
    let Some((entry, recorded_at)) = crate::post::read_entry_at(db, target.vid, known_at)? else {
        return Ok(Err(invalid("the selected summary is not an entry")));
    };
    if entry.entry_ref(target.vid) != target
        || entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || entry_mirrors(&entry)? != row.props
    {
        return Ok(Err(invalid(
            "summary reference, coordinate or mirrors differ",
        )));
    }
    let batch = match validate_summary(&entry.proposal) {
        Ok(Some(batch)) => batch,
        Ok(None) => return Ok(Err(invalid("entry is not an external subledger summary"))),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let citation = match batch.evidence() {
        Ok(citation) => citation,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(document_row) = db.vertex_at(document_vid(&citation.document_oid), recorded_at)?
    else {
        return Ok(Err(invalid(
            "detail document is absent at the summary's recorded prefix",
        )));
    };
    let policy = EvidencePolicy::embedded().map_err(corrupt)?;
    let document = match verify_row(&document_row, &policy) {
        Ok(document) => document,
        Err(error) => return Ok(Err(invalid(error))),
    };
    if document.book_id != book.book_id
        || document.oid() != citation.document_oid
        || document.doc_commit != citation.doc_commit
        || document.kind != EXTERNAL_SUBLEDGER_DOCUMENT_KIND
    {
        return Ok(Err(invalid(
            "retained source commitment differs from the summary",
        )));
    }
    let Some(review_row) = db.vertex_at(
        review_vid(book.book_id, &citation.document_oid),
        recorded_at,
    )?
    else {
        return Ok(Err(invalid(
            "review is absent at the summary's recorded prefix",
        )));
    };
    let review = match review_from_row(&review_row, book.book_id, &document) {
        Ok(review) => review,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(identity) = db.vertex_at(batch.identity(), recorded_at)? else {
        return Ok(Err(invalid(
            "summary's source-batch identity projection is absent",
        )));
    };
    if identity.labels != vec![label::EXTERNAL_SUBLEDGER_BATCH]
        || identity.props != projection(&batch, target)?
        || identity.created_at != recorded_at
    {
        return Ok(Err(invalid(
            "summary's source-batch identity projection differs",
        )));
    }
    let expected_edge = edge_id(relation::REVIEWED_BY, target.vid, review.attestation);
    if !db.edges_at(recorded_at)?.iter().any(|edge| {
        edge.entry.eid == expected_edge
            && edge.entry.relation == relation::REVIEWED_BY
            && edge.entry.src == target.vid
            && edge.entry.dst == review.attestation
            && edge.props.is_empty()
    }) {
        return Ok(Err(invalid(
            "summary's independently reviewed source lineage is missing",
        )));
    }
    let summary_legs = entry.proposal.legs;
    Ok(Ok(ExternalSubledgerReconciliation {
        entry: target,
        recorded_at,
        feed: batch.feed,
        batch_key: batch.batch_key,
        effective_date: batch.effective_date,
        evidence: citation,
        review,
        detail_rows: batch.rows.len(),
        summary_legs,
        reconciled: true,
    }))
}

/// Verify the exact projection population as well as each summary. Used by
/// projection verification so an orphan or deleted identity cannot disappear.
pub fn verify_all_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<String>, KernelError> {
    let rows = db.vertices_at(at)?;
    let mut expected = BTreeSet::new();
    let mut drift = Vec::new();
    for row in rows.iter().filter(|row| row.labels.contains(&label::ENTRY)) {
        let entry = match crate::rows::bytes(row, property::FA_PAYLOAD, "entry")
            .and_then(|bytes| Entry::decode(&bytes).map_err(KernelError::from))
        {
            Ok(entry) => entry,
            Err(error) => {
                drift.push(format!(
                    "entry {:032x}: cannot verify external feed closure: {error}",
                    row.vid.0
                ));
                continue;
            }
        };
        if !entry
            .proposal
            .extensions
            .iter()
            .any(|(tag, _)| *tag == EXTERNAL_SUBLEDGER_EXTENSION)
        {
            continue;
        }
        match validate_summary(&entry.proposal) {
            Ok(Some(batch)) => {
                if !expected.insert(batch.identity()) {
                    drift.push(format!(
                        "duplicate summary for {}/{}",
                        batch.feed, batch.batch_key
                    ));
                }
                match rows.iter().find(|stored| stored.vid == batch.identity()) {
                    Some(stored)
                        if stored.labels == vec![label::EXTERNAL_SUBLEDGER_BATCH]
                            && stored.created_at == row.created_at
                            && stored.props == projection(&batch, entry.entry_ref(row.vid))? => {}
                    _ => drift.push(format!(
                        "missing or altered external feed identity for {}/{}",
                        batch.feed, batch.batch_key
                    )),
                }
            }
            Ok(None) => continue,
            Err(refusal) => {
                drift.push(refusal.message);
                continue;
            }
        }
        if let Err(refusal) = reconcile_at(db, book, entry.entry_ref(row.vid), at)? {
            drift.push(refusal.message);
        }
    }
    for row in rows
        .iter()
        .filter(|row| row.labels.contains(&label::EXTERNAL_SUBLEDGER_BATCH))
    {
        if !expected.contains(&row.vid) {
            drift.push(format!("orphan external feed identity {:032x}", row.vid.0));
        }
    }
    Ok(drift)
}

#[cfg(test)]
mod tests;
