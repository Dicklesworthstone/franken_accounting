//! Complete-prefix transport for the existing one-book group reports.
//!
//! Native v6 and functional v7 certificates retain their exact report bytes.
//! The closure adds the historical BookSpec (entity codes/names, calendar and
//! functional unit) and the original role/rounding registries. Journaled OWNS
//! and role controls remain inside the authenticated, payload-complete prefix;
//! no current graph projection is substituted for those historical records.
//! The BookSpec is a declared report basis bound by the expected certificate
//! and signed bundle, not a separate claim of checkpoint membership at genesis.

use std::collections::BTreeMap;

use fa_journal::genesis::BookSpec;
use fa_journal::migration::RunBody;
use fa_journal::refusal::Outcome;
use fa_model::{Oid, Reader};
use fgdb_types::{CommitSeq, VId};

use crate::{Bundle, Journal, StoredCheckpoint};

use super::{BookClosure, MAX_FUNCTIONAL_BOOK_BYTES, assemble_inner, functional, refused};

const NATIVE_REGISTRIES: [&str; 6] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "account_roles",
    "rounding_laws",
];
const FUNCTIONAL_REGISTRIES: [&str; 7] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "account_roles",
    "fx_laws",
    "rounding_laws",
];

/// Return the valuation posture only for the exact sequence-selected trunk
/// consolidation header. Complete certificate replay precedes assembly; the
/// independent verifier checks its full encoding and recomputes its output.
pub(super) fn profile(certificate: &[u8], journal: &Journal, known_at: CommitSeq) -> Option<bool> {
    let read = || -> Result<Option<bool>, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let format =
            reader.fixed::<{ b"fa:report-certificate:v6".len() }>("consolidation format")?;
        let (functional, output, selector) = match &format {
            b"fa:report-certificate:v6" => (false, "fa:consolidation:v1", 4),
            b"fa:report-certificate:v7" => (true, "fa:functional-consolidation:v1", 5),
            _ => return Ok(None),
        };
        if reader.str(64, "scope")? != "fa-fold-over-prefix" {
            return Ok(None);
        }
        reader.str(64, "authority")?;
        if reader.str(64, "output")? != output
            || reader.fixed::<16>("book")? != journal.book_id.0
            || reader.fixed::<16>("branch")? != [0; 16]
            || journal.branch_id != fa_model::Id128::TRUNK
            || reader.u64("known-at")? != known_at.0
            || reader.u8("selector")? != selector
            || reader.str(128, "consolidation period")?.is_empty()
        {
            return Ok(None);
        }
        Ok(Some(functional))
    };
    read().ok().flatten()
}

/// Package a replayed one-book consolidation with its exact historical inputs.
/// Native v6 carries six registries and no Rate documents. Functional v7 adds
/// the FX registry and every authenticated Rate document its retained values
/// consume. Both use major 3's BookSpec/rate closure; no new certificate format,
/// rewritten output or inferred group membership is introduced.
#[allow(clippy::too_many_arguments)]
pub fn assemble(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &BTreeMap<VId, RunBody>,
    registries: &[(String, Vec<u8>)],
    book_spec: &[u8],
    rates: &[(Oid, Vec<u8>)],
) -> Outcome<Bundle> {
    let Some(valued) = profile(certificate, journal, known_at) else {
        return Ok(Err(refused(
            "portable consolidation requires this book's sequence-selected trunk v6 native or v7 functional certificate",
        )));
    };
    let expected = if valued {
        FUNCTIONAL_REGISTRIES.as_slice()
    } else {
        NATIVE_REGISTRIES.as_slice()
    };
    if registries
        .iter()
        .map(|(name, _)| name.as_str())
        .ne(expected.iter().copied())
        || registries
            .iter()
            .any(|(_, bytes)| bytes.len() > 1024 * 1024)
    {
        return Ok(Err(refused(
            "portable consolidation requires its exact account-role and rounding registry closure: six bounded documents for native v6, seven including FX laws for functional v7",
        )));
    }
    if book_spec.len() > MAX_FUNCTIONAL_BOOK_BYTES || !book_spec.starts_with(&2u16.to_le_bytes()) {
        return Ok(Err(refused(
            "portable consolidation requires its bounded historical canonical version-2 BookSpec",
        )));
    }
    let spec = BookSpec::decode(book_spec)?;
    if spec.book_id != journal.book_id
        || spec.canonical_bytes()? != book_spec
        || spec.entities.len() < 2
    {
        return Ok(Err(refused(
            "portable consolidation requires this book's exact declared group of at least two legal entities",
        )));
    }
    if valued {
        if let Err(refusal) = functional::validate(journal, known_at, book_spec, rates)? {
            return Ok(Err(refusal));
        }
    } else if !rates.is_empty() {
        return Ok(Err(refused(
            "native consolidation carries native amounts and cannot attach a functional Rate closure",
        )));
    }
    assemble_inner(
        journal,
        checkpoint,
        certificate,
        known_at,
        bodies,
        registries,
        Some(BookClosure { book_spec, rates }),
    )
}
