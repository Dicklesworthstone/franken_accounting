//! Bounded retained detail and its original authenticated evidence records.

use super::{
    VerifiedExternalFeedBatch, VerifiedExternalFeedSummaryLeg, framed_digest, identifier, invalid,
};
use crate::codec::Reader;
use crate::envelope::{KIND_ATTESTATION, KIND_IMPORT_RECEIPT, LeafEnvelope, skip_erasable};
use crate::report::{ReportError, failed, metadata, text};
use std::collections::BTreeMap;

const DETAIL_FORMAT: &[u8] = b"fa:external-subledger-detail:v1";

pub(super) struct Batch {
    pub feed: String,
    pub batch_key: String,
    pub effective_date: i32,
    pub rows: Vec<VerifiedExternalFeedSummaryLeg>,
    pub summary: Vec<VerifiedExternalFeedSummaryLeg>,
    pub document_oid: [u8; 32],
    pub doc_commit: [u8; 32],
}

fn dimensions(r: &mut Reader<'_>) -> Result<Vec<(u32, u128)>, ReportError> {
    let count = r.count(64, 20, "external_detail.dimensions")?;
    let mut values = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let kind = r.u32("external_detail.dimension.kind")?;
        if previous.is_some_and(|before| before >= kind) {
            return Err(invalid(
                "external detail dimensions are not strictly ordered",
            ));
        }
        previous = Some(kind);
        values.push((kind, r.u128("external_detail.dimension.value")?));
    }
    Ok(values)
}

fn credit(r: &mut Reader<'_>) -> Result<bool, ReportError> {
    match r.u8("external_detail.side")? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("external detail has an unknown monetary side")),
    }
}

/// Compare the entire canonical LegPayload, including the absent base amount,
/// memo and settlements that a native complete external summary requires.
fn summary_legs(proposal: &[u8]) -> Result<Vec<VerifiedExternalFeedSummaryLeg>, ReportError> {
    let mut r = Reader::new(proposal);
    r.u16("entry.major")?;
    r.u16("entry.minor")?;
    r.fixed::<16>("entry.book")?;
    r.fixed::<16>("entry.branch")?;
    r.u16("entry.class")?;
    r.i32("entry.effective")?;
    if r.present("entry.document_date")? {
        r.i32("entry.document_date")?;
    }
    skip_erasable(&mut r, "entry.description")?;
    if r.present("entry.period")? {
        r.bytes(128, "entry.calendar")?;
        r.bytes(128, "entry.period")?;
    }
    let count = r.count(32, 47, "external_summary.legs")?;
    let mut legs = Vec::with_capacity(count);
    for _ in 0..count {
        let credit = credit(&mut r)?;
        let account = r.u128("external_summary.account")?;
        let unit = r.u32("external_summary.unit")?;
        let amount = r.i128("external_summary.amount")?;
        if r.present("external_summary.base_amount")? {
            return Err(invalid(
                "external summary carries a base amount absent from its detail",
            ));
        }
        let dimension_set = dimensions(&mut r)?;
        if r.present("external_summary.memo")?
            || r.count(0, 70, "external_summary.settlements")? != 0
        {
            return Err(invalid(
                "external summary carries memo or settlements absent from its detail",
            ));
        }
        legs.push(VerifiedExternalFeedSummaryLeg {
            account,
            unit,
            credit,
            amount,
            dimension_set,
        });
    }
    Ok(legs)
}

pub(super) fn batch(
    bytes: &[u8],
    valid_shape: bool,
    envelope: &LeafEnvelope,
    info: &metadata::EntryInfo<'_>,
    proposal: &[u8],
    units: &[u32],
) -> Result<Batch, ReportError> {
    if !valid_shape || bytes.len() > 8192 {
        return Err(invalid(
            "external detail requires its bounded sole Original Intent extension without lifecycle or base valuation",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.fixed::<{ DETAIL_FORMAT.len() }>("external_detail.format")?
        .as_slice()
        != DETAIL_FORMAT
    {
        return Err(invalid("unsupported external detail format"));
    }
    let book = r.fixed::<16>("external_detail.book")?;
    let feed = text(&mut r, 64, "external_detail.feed")?.to_string();
    let batch_key = text(&mut r, 128, "external_detail.batch_key")?.to_string();
    let effective_date = r.i32("external_detail.effective")?;
    if book != envelope.book_id
        || envelope.effective_day != Some(effective_date)
        || !identifier(&feed, 64)
        || !identifier(&batch_key, 128)
    {
        return Err(invalid(
            "external detail identity or coordinate differs from its summary",
        ));
    }
    let count = r.count(128, 73, "external_detail.rows")?;
    if count == 0 {
        return Err(invalid("external detail batch is empty"));
    }
    let mut previous = None;
    let mut rows = Vec::with_capacity(count);
    let mut sums = BTreeMap::<(u128, u32, Vec<(u32, u128)>, bool), i128>::new();
    for _ in 0..count {
        let digest = r.fixed::<32>("external_detail.source_digest")?;
        if digest == [0; 32] || previous.is_some_and(|before| before >= digest) {
            return Err(invalid(
                "external detail source digests are zero, duplicated or unordered",
            ));
        }
        previous = Some(digest);
        let account = r.u128("external_detail.account")?;
        let credit = credit(&mut r)?;
        let unit = r.u32("external_detail.unit")?;
        let amount = r.i128("external_detail.amount")?;
        let dimension_set = dimensions(&mut r)?;
        if amount <= 0 || units.binary_search(&unit).is_err() {
            return Err(invalid(
                "external detail requires positive amounts in registered native units",
            ));
        }
        let sum = sums
            .entry((account, unit, dimension_set.clone(), credit))
            .or_default();
        *sum = sum
            .checked_add(amount)
            .ok_or_else(|| failed("exact_arithmetic", "external detail summary overflow"))?;
        rows.push(VerifiedExternalFeedSummaryLeg {
            account,
            unit,
            credit,
            amount,
            dimension_set,
        });
    }
    r.finish("external detail batch")?;
    if !(2..=32).contains(&sums.len()) {
        return Err(invalid(
            "external detail must produce 2 through 32 complete summary legs",
        ));
    }
    let summary: Vec<_> = sums
        .into_iter()
        .map(
            |((account, unit, dimension_set, credit), amount)| VerifiedExternalFeedSummaryLeg {
                account,
                unit,
                credit,
                amount,
                dimension_set,
            },
        )
        .collect();
    if summary != summary_legs(proposal)? {
        return Err(invalid(
            "external summary differs from the complete gross detail fold",
        ));
    }
    let doc_commit = crate::document::doc_commit(21, bytes);
    let document_oid = framed_digest(b"fa:oid:document:v1", &[&book, &doc_commit]);
    if !info.evidence.contains(&(document_oid, doc_commit, 1)) {
        return Err(invalid(
            "external summary does not cite its exact Workpaper as Source evidence",
        ));
    }
    Ok(Batch {
        feed,
        batch_key,
        effective_date,
        rows,
        summary,
        document_oid,
        doc_commit,
    })
}

struct Intake {
    position: (u64, u32),
    principal: u128,
    doc_commit: [u8; 32],
}

struct Review {
    position: (u64, u32),
    principal: u128,
    human_profile: bool,
}

pub(super) struct Evidence {
    book: [u8; 16],
    intakes: BTreeMap<[u8; 32], Intake>,
    reviews: BTreeMap<[u8; 32], Review>,
}

impl Evidence {
    /// All payloads have already passed `check_record` and prefix authentication.
    /// Only original records at the selected frontier can support a batch; a
    /// later checkpoint's newly recorded review cannot repair an older claim.
    pub(super) fn read(
        envelopes: &[LeafEnvelope],
        records: &[(usize, &[u8])],
        book: &[u8; 16],
        known_at: u64,
    ) -> Result<Self, ReportError> {
        let mut result = Self {
            book: *book,
            intakes: BTreeMap::new(),
            reviews: BTreeMap::new(),
        };
        for (envelope, &(len, payload)) in envelopes.iter().zip(records) {
            if envelope.commit_seq > known_at || envelope.book_id != *book {
                continue;
            }
            if envelope.kind == KIND_IMPORT_RECEIPT {
                let mut r = Reader::new(&payload[..len]);
                if r.u16("custody.version")? != 1 || r.fixed::<16>("custody.book")? != *book {
                    return Err(invalid("unsupported external source intake record"));
                }
                let document = r.fixed("custody.document")?;
                if r.u32("custody.index")? != 0
                    || r.fixed::<32>("custody.previous")? != [0; 32]
                    || r.u8("custody.body")? != 1
                {
                    return Err(invalid(
                        "external source intake is not its original receipt",
                    ));
                }
                match r.u8("custody.source")? {
                    1 => {
                        r.u128("custody.source.principal")?;
                    }
                    2 => {
                        text(&mut r, 256, "custody.source.name")?;
                        text(&mut r, 256, "custody.source.version")?;
                    }
                    3 => {
                        text(&mut r, 256, "custody.source.message")?;
                    }
                    4 => {
                        text(&mut r, 256, "custody.source.device")?;
                    }
                    _ => return Err(invalid("external source intake has an unknown source")),
                }
                let principal = r.u128("custody.received_by")?;
                let doc_commit = r.fixed("custody.digest_at_receipt")?;
                if r.present("custody.run")? {
                    r.u128("custody.run")?;
                }
                r.count(0, 1, "custody.transformations")?;
                r.finish("external source intake")?;
                if result
                    .intakes
                    .insert(
                        document,
                        Intake {
                            position: envelope.position(),
                            principal,
                            doc_commit,
                        },
                    )
                    .is_some()
                {
                    return Err(invalid(
                        "duplicate original document intake in selected prefix",
                    ));
                }
            } else if envelope.kind == KIND_ATTESTATION && envelope.class == 2 {
                let mut r = Reader::new(&payload[..len]);
                if r.u16("review.version")? != 1
                    || r.fixed::<16>("review.book")? != *book
                    || r.u8("review.claim")? != 2
                {
                    return Err(invalid("unsupported external source Reviewed record"));
                }
                let count = r.count(4096, 32, "review.against")?;
                let mut against = Vec::with_capacity(count);
                for _ in 0..count {
                    against.push(r.fixed::<32>("review.against.document")?);
                }
                if against.windows(2).any(|pair| pair[0] >= pair[1])
                    || r.count(1, 33, "review.subjects")? != 1
                    || r.u8("review.subject.kind")? != 1
                {
                    return Err(invalid(
                        "Reviewed record has a noncanonical document subject",
                    ));
                }
                let document = r.fixed::<32>("review.subject")?;
                let principal = r.u128("review.principal")?;
                if against.contains(&document) || r.count(0, 32, "review.evidence")? != 0 {
                    return Err(invalid(
                        "Reviewed record cites itself or unsupported evidence",
                    ));
                }
                r.finish("external source review")?;
                // The stored profile is an authenticated statement, not proof
                // that a real person held an independent historical capability.
                let human_profile = payload.get(len + 33) == Some(&0);
                if result
                    .reviews
                    .insert(
                        document,
                        Review {
                            position: envelope.position(),
                            principal,
                            human_profile,
                        },
                    )
                    .is_some()
                {
                    return Err(invalid(
                        "duplicate Reviewed document identity in selected prefix",
                    ));
                }
            }
        }
        Ok(result)
    }

    pub(super) fn bind(
        &self,
        batch: &Batch,
        entry: u128,
        envelope: &LeafEnvelope,
    ) -> Result<VerifiedExternalFeedBatch, ReportError> {
        let intake = self.intakes.get(&batch.document_oid).ok_or_else(|| {
            invalid("external source Workpaper has no authenticated original ImportReceipt")
        })?;
        let review = self.reviews.get(&batch.document_oid).ok_or_else(|| {
            invalid("external source Workpaper has no authenticated Reviewed record")
        })?;
        if intake.doc_commit != batch.doc_commit
            || intake.position >= review.position
            || review.position >= envelope.position()
            || review.principal == intake.principal
            || !review.human_profile
        {
            return Err(invalid(
                "external source original intake, distinct recorded reviewer or publication chronology differs",
            ));
        }
        Ok(VerifiedExternalFeedBatch {
            entry,
            entry_digest: envelope.record_digest,
            recorded_at: envelope.commit_seq,
            feed: batch.feed.clone(),
            batch_key: batch.batch_key.clone(),
            effective_date: batch.effective_date,
            document_oid: batch.document_oid,
            doc_commit: batch.doc_commit,
            evidence_role: 1,
            review_attestation: metadata::framed_identity(
                b"fa:vid:attestation-review:v1",
                &[&self.book, &batch.document_oid],
            ),
            reviewer: review.principal,
            detail_rows: batch.rows.len(),
            summary_legs: batch.summary.clone(),
            reconciled: true,
        })
    }
}
