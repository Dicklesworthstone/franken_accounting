//! Source references already bound by the published bank document encodings.
//!
//! These readers do not reinterpret amounts or certify the parser's method.
//! They validate the complete existing versioned wire before projecting its
//! explicit source pointers. The bank facade still reparses original evidence.

use fa_model::{Oid, Reader, limits};
use fa_registry::evidence_policy::EvidencePolicy;

use crate::{Document, Refusal};

use super::invalid;

const MANIFEST_MAGIC: &[u8; 14] = b"FA-BANK-IMPORT";
const LINE_DOMAIN: &[u8] = b"fa:bank-line-doc:v1";

pub(super) fn sources(
    document: &Document,
    policy: &EvidencePolicy,
) -> Result<Option<Vec<Oid>>, Refusal> {
    if document.bytes.starts_with(MANIFEST_MAGIC) {
        check_kind(document, policy, "Workpaper")?;
        return manifest_sources(document).map(Some);
    }
    let mut reader = Reader::new(&document.bytes);
    if reader.bytes(64, "bank_line.domain").ok() != Some(LINE_DOMAIN) {
        return Ok(None);
    }
    check_kind(document, policy, "Other")?;
    line_sources(reader).map(Some)
}

fn check_kind(document: &Document, policy: &EvidencePolicy, expected: &str) -> Result<(), Refusal> {
    if policy.kind_by_name(expected).map(|kind| kind.tag) != Some(document.kind) {
        return Err(invalid(format!(
            "the canonical bank source format requires document kind {expected}"
        )));
    }
    Ok(())
}

fn malformed(error: fa_model::DecodeError) -> Refusal {
    invalid(error.to_string())
}

fn line_sources(mut reader: Reader<'_>) -> Result<Vec<Oid>, Refusal> {
    let statement = Oid(reader.fixed("bank_line.statement_oid").map_err(malformed)?);
    reader.u64("bank_line.statement_seq").map_err(malformed)?;
    reader.u32("bank_line.line_ordinal").map_err(malformed)?;
    reader.i32("bank_line.booking_date").map_err(malformed)?;
    reader.i32("bank_line.value_date").map_err(malformed)?;
    if reader.u8("bank_line.side").map_err(malformed)? > 1 {
        return Err(invalid("bank line has an invalid debit/credit side"));
    }
    reader.u32("bank_line.unit").map_err(malformed)?;
    if reader.i128("bank_line.mantissa").map_err(malformed)? <= 0 {
        return Err(invalid("bank line requires a positive exact amount"));
    }
    reader
        .str(limits::MAX_MEMO_BYTES, "bank_line.counterparty")
        .map_err(malformed)?;
    reader
        .str(limits::MAX_MEMO_BYTES, "bank_line.reference")
        .map_err(malformed)?;
    reader.finish().map_err(malformed)?;
    Ok(vec![statement])
}

fn manifest_sources(document: &Document) -> Result<Vec<Oid>, Refusal> {
    let manifest = crate::import::BankImportManifest::decode(&document.bytes).map_err(malformed)?;
    if manifest.book_id != document.book_id {
        return Err(invalid("bank manifest source list belongs to another book"));
    }
    // These are the current statement's parser inputs. The separately
    // authenticated BankStatementLink binds prior-import continuity and its
    // two ImportRuns; a prior statement is never re-imported as current input.
    let mut sources = manifest.line_oids;
    sources.push(manifest.statement_oid);
    sources.sort();
    if sources.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("a bank manifest lists each source exactly once"));
    }
    Ok(sources)
}
