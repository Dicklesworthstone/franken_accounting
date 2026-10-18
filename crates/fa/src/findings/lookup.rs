//! Resolve a Finding vertex handle back to its verified source observation.
//! The native row is only a bounded locator; it never supplies a trusted result.

use super::*;
use fa_lantern::{Coordinate, Finding};
use fa_model::Reader;

mod inventory;
pub use inventory::{FindingRunCursor, FindingRunPage, FindingRunPageRequest, FindingRunSummary, MAX_FINDING_RUN_PAGE};

/// A single occurrence, with its original certified coordinate and publication.
/// The entire source run and required graph edges were checked before selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedFinding {
    pub finding_vid: VId,
    pub run_vid: VId,
    pub certificate_digest: [u8; 32],
    pub ordinal: u32,
    pub recorded_at: CommitSeq,
    pub producer: VId,
    pub coordinate: Coordinate,
    pub finding: Finding,
}

fn locator(payload: &[u8], book: Id128, selected: VId) -> Result<([u8; 32], u32), Refusal> {
    // Fixed-size locator fields only. Check before decoding or allocating from
    // a hostile graph payload. A run index is not a finding occurrence.
    if payload.len() != FINDING_RECORD_FORMAT.len() + 16 + 32 + 4 + 32 {
        return Err(invalid("finding locator has an invalid length"));
    }
    let body = payload
        .strip_prefix(FINDING_RECORD_FORMAT)
        .ok_or_else(|| invalid("the handle does not name a version-one finding occurrence"))?;
    let fail = |e| invalid(format!("finding locator decoding: {e}"));
    let mut r = Reader::new(body);
    let source_book = Id128(r.fixed::<16>("finding book").map_err(fail)?);
    let certificate = r.fixed::<32>("finding certificate").map_err(fail)?;
    let ordinal = r.u32("finding ordinal").map_err(fail)?;
    // Verified later against the certificate's actual canonical Finding.
    let _value_digest = r.fixed::<32>("finding value digest").map_err(fail)?;
    r.finish().map_err(fail)?;
    if source_book != book
        || ordinal as usize >= MAX_RECORDED_FINDINGS
        || finding_vid(book, &certificate, ordinal) != selected
    {
        return Err(invalid(
            "finding locator book, identity or occurrence is inconsistent",
        ));
    }
    Ok((certificate, ordinal))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Resolve an opaque Finding VId after reopening, without requiring the host
    /// to remember its certificate. Current whole-book authority precedes lookup;
    /// complete native replay precedes returning the single selected occurrence.
    pub async fn finding_by_vid(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        selected: VId,
    ) -> Outcome<RecordedFinding> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        let coordinates = self.query(cx, |db, book| {
            let head = db.frontier().map_err(KernelError::from)?;
            let Some(row) = db.vertex_at(selected, head).map_err(KernelError::from)? else {
                return Ok(Err(invalid("finding handle does not exist or has been retired")));
            };
            if row.labels.as_slice() != [label::FINDING]
                || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == book.book_id.0)
            {
                return Ok(Err(invalid("handle is not a finding in this book")));
            }
            let Some(CanonicalScalar::Bytes(payload)) = prop(&row, property::FA_PAYLOAD) else {
                return Ok(Err(invalid("finding locator is missing its canonical bytes")));
            };
            Ok(locator(payload.as_slice(), book.book_id, selected))
        })?;
        let (digest, ordinal) = match coordinates {
            Ok(c) => c,
            Err(r) => return Ok(Err(r)),
        };
        let run = match self
            .read_findings(cx, principal, capability, &digest)
            .await?
        {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        if run.finding_ids.get(ordinal as usize) != Some(&selected) {
            return Ok(Err(invalid(
                "finding handle is not in the original certified run",
            )));
        }
        let Some(finding) = run.report.findings.get(ordinal as usize) else {
            return Ok(Err(invalid(
                "finding occurrence exceeds its complete source run",
            )));
        };
        let result = RecordedFinding {
            finding_vid: selected,
            run_vid: run.run_vid,
            certificate_digest: digest,
            ordinal,
            recorded_at: run.recorded_at,
            producer: run.producer,
            coordinate: run.report.coordinate,
            finding: finding.clone(),
        };
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        Ok(Ok(result))
    }
}
