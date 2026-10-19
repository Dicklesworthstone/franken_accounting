//! Content-bound provenance for documents in one atomic import.
//!
//! The source list is part of the derived document's immutable bytes and
//! therefore of the import receipt. Graph edges only project that list.

use fa_model::{Oid, Reader, Writer, limits::MAX_IMPORT_DOCUMENTS};
use fa_registry::evidence_policy::EvidencePolicy;

use crate::Document;
use crate::refusal::{Refusal, code, exit};

mod native_bank;

const DOMAIN: &[u8] = b"fa:derived-document:v1";

pub(super) fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENT_INTAKE,
        exit::USAGE,
        message,
        "plan §9.1–9.3; FA-INV-05 (immutable DERIVED_FROM lineage)",
        "import the complete source documents and newly derived documents together; preserve the canonical source list and payload",
    )
}

/// Wrap a payload with its complete, sorted, distinct document-source list.
/// This is an assertion of derivation, not an independent proof of its method.
pub fn encode_derivation(sources: &[Oid], payload: &[u8]) -> Result<Vec<u8>, Refusal> {
    if sources.is_empty() || sources.len() > MAX_IMPORT_DOCUMENTS {
        return Err(invalid(
            "a derived document needs 1..=max_import_documents sources",
        ));
    }
    let mut sources = sources.to_vec();
    sources.sort();
    if sources.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("a derived document lists each source once"));
    }
    let mut writer = Writer::new();
    writer
        .bytes(DOMAIN)
        .list(&sources, |w, oid| {
            w.fixed(&oid.0);
        })
        .bytes(payload);
    writer.finish().map_err(|error| invalid(error.to_string()))
}

/// Decode the bound source list and borrow the payload without copying it.
pub fn decode_derivation(bytes: &[u8]) -> Result<(Vec<Oid>, &[u8]), Refusal> {
    let malformed = |error: fa_model::DecodeError| invalid(error.to_string());
    let mut reader = Reader::new(bytes);
    if reader.bytes(64, "derivation.domain").map_err(malformed)? != DOMAIN {
        return Err(invalid(
            "document is not a canonical derived-document envelope",
        ));
    }
    let sources = reader
        .list(MAX_IMPORT_DOCUMENTS, "derivation.sources", |r| {
            Ok(Oid(r.fixed("derivation.source")?))
        })
        .map_err(malformed)?;
    if sources.is_empty() || sources.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "derivation sources must be nonempty, sorted and distinct",
        ));
    }
    let payload = reader
        .bytes(bytes.len(), "derivation.payload")
        .map_err(malformed)?;
    reader.finish().map_err(malformed)?;
    Ok((sources, payload))
}

/// Read complete source pointers from a canonical generic derivation envelope,
/// BankLine v1, or bank-import manifest v1. The exact bytes and document kind
/// determine the interpretation; a caller cannot supply an unrelated edge list.
/// These pointers assert derivation and do not prove the derivation method.
pub fn document_sources(document: &Document) -> Result<Vec<Oid>, Refusal> {
    let policy = EvidencePolicy::embedded().map_err(|error| invalid(error.to_string()))?;
    sources_with_policy(document, &policy)
}

pub(super) fn sources_with_policy(
    document: &Document,
    policy: &EvidencePolicy,
) -> Result<Vec<Oid>, Refusal> {
    if let Some(sources) = native_bank::sources(document, policy)? {
        return Ok(sources);
    }
    decode_derivation(&document.bytes).map(|(sources, _)| sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_is_bound_canonical_and_not_replaceable_by_trailing_bytes() {
        let a = Oid([1; 32]);
        let b = Oid([2; 32]);
        let encoded = encode_derivation(&[b, a], b"derived text").unwrap();
        let (sources, payload) = decode_derivation(&encoded).unwrap();
        assert_eq!(sources, [a, b]);
        assert_eq!(payload, b"derived text");
        assert_ne!(encoded, encode_derivation(&[a], b"derived text").unwrap());
        assert!(encode_derivation(&[a, a], b"text").is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_derivation(&trailing).is_err());
    }
}
