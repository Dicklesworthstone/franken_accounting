//! Functional statements verify recorded valuations before summing them.
//!
//! A retained base amount is not trusted merely because the journal balances.
//! Bind every cited rate to its immutable content identity and historical Rate
//! row, then let the journal owner recompute each registered FX law, including
//! source-bound carrying relief and exact reversal inheritance.

use super::*;
use fa_journal::evidence::{DocumentRecord, Storage, document_vid};
use fa_journal::fx::{RATE_DOCUMENT_KIND, RATE_EVIDENCE_ROLE};

pub(crate) fn verify_sources<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Outcome<()> {
    let query = cx.query();
    // A visible-row fold alone cannot detect a retired journal entry or an
    // incomplete resident history after reopening a checkpoint.
    fa_journal::verify_entry_history(db, cx, book, Some(at))?;
    let mut rates = BTreeMap::new();
    for row in db.vertices_at(at).map_err(fa_journal::KernelError::from)? {
        query.checkpoint().map_err(BookError::Context)?;
        if row.labels.contains(&label::DOCUMENT)
            && matches!(fa_journal::rows::prop(&row, property::CODE),
                Some(fgdb_types::CanonicalScalar::Text(code)) if code.as_bytes() == b"Rate")
        {
            let record = DocumentRecord::decode(&bytes(
                &row,
                property::FA_PAYLOAD,
                "functional Rate projection",
            )?)?;
            if record.kind != RATE_DOCUMENT_KIND
                || record.book_id != book.book_id
                || document_vid(&record.oid()) != row.vid
                || !matches!(&record.storage, Storage::Inline(_))
                || bytes(&row, property::FA_DIGEST, "Rate projection digest")? != record.doc_commit
                || bytes(&row, property::BOOK_ID, "Rate projection book")? != book.book_id.0
            {
                return Ok(Err(invalid(
                    "the certified Rate projection contains a row whose content, kind or book differs from its mirrors",
                )));
            }
        }
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "valued entry")?)
            .map_err(fa_journal::KernelError::from)?;
        let Some(totals) = &entry.proposal.base_totals else {
            continue;
        };
        for oid in &totals.rate_doc_oids {
            let Some(citation) = entry.proposal.evidence.iter().find(|evidence| {
                evidence.document_oid == *oid && evidence.role == RATE_EVIDENCE_ROLE
            }) else {
                return Ok(Err(invalid(format!(
                    "functional valuation on entry {:032x} has no Rate citation for {}",
                    row.vid.0,
                    hex(&oid.0),
                ))));
            };
            if rates
                .insert(*oid, citation.doc_commit)
                .is_some_and(|previous| previous != citation.doc_commit)
            {
                return Ok(Err(invalid(
                    "functional valuations bind conflicting commitments for one Rate document",
                )));
            }
        }
    }
    for (oid, commitment) in rates {
        query.checkpoint().map_err(BookError::Context)?;
        let vid = document_vid(&oid);
        let Some(row) = db
            .vertex_at(vid, at)
            .map_err(fa_journal::KernelError::from)?
        else {
            return Ok(Err(invalid(format!(
                "functional valuation Rate document {} is missing at the selected prefix",
                hex(&oid.0),
            ))));
        };
        let payload = bytes(&row, property::FA_PAYLOAD, "functional Rate document")?;
        let record = DocumentRecord::decode(&payload)?;
        if !row.labels.contains(&label::DOCUMENT)
            || record.book_id != book.book_id
            || record.kind != RATE_DOCUMENT_KIND
            || record.oid() != oid
            || record.doc_commit != commitment
            || !matches!(&record.storage, Storage::Inline(_))
            || bytes(&row, property::FA_DIGEST, "Rate document digest")? != commitment
            || bytes(&row, property::BOOK_ID, "Rate document book")? != book.book_id.0
            || text(&row, property::CODE, "Rate document kind")? != "Rate"
        {
            return Ok(Err(invalid(format!(
                "functional valuation Rate document {} differs from its citation, identity or certified Rate projection",
                hex(&oid.0),
            ))));
        }
        // Custody transfers may version a Document row. Compare only its
        // immutable source fields, not its mutable custody length or timestamp.
        let Some(current) = db.vertex(vid).map_err(fa_journal::KernelError::from)? else {
            return Ok(Err(invalid(format!(
                "functional valuation Rate document {} was retired",
                hex(&oid.0),
            ))));
        };
        if !current.labels.contains(&label::DOCUMENT)
            || [
                property::FA_PAYLOAD,
                property::FA_DIGEST,
                property::BOOK_ID,
                property::CODE,
            ]
            .iter()
            .any(|key| fa_journal::rows::prop(&current, *key) != fa_journal::rows::prop(&row, *key))
        {
            return Ok(Err(invalid(format!(
                "functional valuation Rate document {} was rewritten",
                hex(&oid.0),
            ))));
        }
    }
    let verified = fa_journal::verify_fx_conversions(db, cx, book, at)?;
    if let Some(drift) = verified.drift.first() {
        return Ok(Err(invalid(format!(
            "functional valuation does not replay for entry {:032x} under {}: {}",
            drift.entry.0, drift.law, drift.problem,
        ))));
    }
    Ok(Ok(()))
}
