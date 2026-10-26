//! The bytes of the documents a case adds (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §2.6, §2.7; bead fa-yugf.15, A7a). Originals are never committed (§4.2)
//! and tests never read the fetch cache (§4.3), so every document the runner
//! adds is one of these renderings.
//!
//! - **Citation stub** (`fa:case-source-stub:v1`): the canonical bytes of a
//!   `sources.toml` row, one `key=value` line each for `id`, `title`,
//!   `accession`, `original_url`, `sha256`, `assertion_status` and
//!   `retrieval_route`; a fact-level stub adds `anchor` and `quote_sha256`.
//! - **Placeholder** (`fa:case-placeholder:v1`): the fact id and "the record
//!   describes this document; its bytes are not public". It is never a
//!   citation stub.

use super::fact::Fact;
use super::source::Source;

/// The placeholder's fixed statement (§2.6 `evidence_attached`).
pub const PLACEHOLDER_STATEMENT: &str =
    "the record describes this document; its bytes are not public";

/// The EDGAR accession number in an `original_url`
/// (`…/Archives/edgar/data/<cik>/<18 digits>/<file>`), written
/// `NNNNNNNNNN-NN-NNNNNN`; empty when the URL carries none.
#[must_use]
pub fn accession(original_url: &str) -> String {
    original_url
        .split('/')
        .find(|seg| seg.len() == 18 && seg.bytes().all(|b| b.is_ascii_digit()))
        .map(|a| format!("{}-{}-{}", &a[..10], &a[10..12], &a[12..]))
        .unwrap_or_default()
}

fn line(out: &mut String, key: &str, value: &str) {
    // A value never spans lines: a stray newline would forge a key.
    out.push_str(key);
    out.push('=');
    out.push_str(&value.replace(['\n', '\r'], " "));
    out.push('\n');
}

/// A source's citation stub.
#[must_use]
pub fn source_stub(source: &Source) -> Vec<u8> {
    stub(source, None)
}

/// A fact-level citation stub: the source's lines plus the fact's `anchor`
/// and `quote_sha256`. `None` when the fact is not sourced from `source`.
#[must_use]
pub fn fact_stub(source: &Source, fact: &Fact) -> Option<Vec<u8>> {
    let s = fact.sourced().filter(|s| s.source == source.id)?;
    Some(stub(
        source,
        Some((s.anchor.as_str(), s.quote_sha256.as_str())),
    ))
}

fn stub(source: &Source, fact: Option<(&str, &str)>) -> Vec<u8> {
    let mut out = String::from("fa:case-source-stub:v1\n");
    line(&mut out, "id", &source.id);
    line(&mut out, "title", &source.title);
    line(&mut out, "accession", &accession(&source.original_url));
    line(&mut out, "original_url", &source.original_url);
    line(&mut out, "sha256", &source.sha256);
    line(
        &mut out,
        "assertion_status",
        source.assertion_status.as_str(),
    );
    line(&mut out, "retrieval_route", source.retrieval_route.as_str());
    if let Some((anchor, quote_sha256)) = fact {
        line(&mut out, "anchor", anchor);
        line(&mut out, "quote_sha256", quote_sha256);
    }
    out.into_bytes()
}

/// A reconstruction placeholder for the document `fact` describes.
#[must_use]
pub fn placeholder(fact: &str) -> Vec<u8> {
    let mut out = String::from("fa:case-placeholder:v1\n");
    line(&mut out, "fact", fact);
    line(&mut out, "statement", PLACEHOLDER_STATEMENT);
    out.into_bytes()
}

/// What a filler document says: it is harness filler, not a record.
pub const FILLER_STATEMENT: &str =
    "harness filler a case generates around its documented entries; it records no event";

/// The `fa:case-filler:v1` document every member of `case`'s filler variant
/// `variant` cites (plan §2.7): kind Other, reviewed by
/// `case-second-reader`, never a provenance stub or a placeholder.
#[must_use]
pub fn filler(case: &str, variant: &str) -> Vec<u8> {
    let mut out = String::from("fa:case-filler:v1\n");
    line(&mut out, "case", case);
    line(&mut out, "variant", variant);
    line(&mut out, "statement", FILLER_STATEMENT);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::CASE_EXTENSIONS;
    use crate::cases::tests::{load_files, pilot};

    #[test]
    fn stub_bytes_rerender_identically_from_the_sources_row() {
        let case = load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("the pilot loads");
        let src = case
            .sources
            .iter()
            .find(|s| s.id == "SRC-WC-001")
            .expect("SRC-WC-001");
        let stub = source_stub(src);
        assert_eq!(stub, source_stub(src), "a re-render is byte-identical");
        assert_eq!(
            String::from_utf8(stub).expect("utf-8"),
            "fa:case-source-stub:v1\n\
             id=SRC-WC-001\n\
             title=Report of Investigation by the Special Investigative Committee of the Board of Directors of WorldCom, Inc.\n\
             accession=0000931763-03-001862\n\
             original_url=https://www.sec.gov/Archives/edgar/data/723527/000093176303001862/dex991.htm\n\
             sha256=7aea64fc1af13c030ce0fca1edf3c9a5a3faa183617c8b251d7c4ad079556ba8\n\
             assertion_status=investigative_finding\n\
             retrieval_route=archive_capture\n"
        );
        // A fact-level stub adds the anchor and quote hash; a fact of another
        // source has none.
        let f4 = case.facts.iter().find(|f| f.id == "F4").expect("F4");
        let fact =
            String::from_utf8(fact_stub(src, f4).expect("F4 is SRC-WC-001's")).expect("utf-8");
        assert!(fact.ends_with(
            "anchor=p108:l20-22\nquote_sha256=7f61ad3dada1a0f9ff4c59b8c23965cac4822f3d323df550dbefe8bf9c15966b\n"
        ));
        let other = case
            .sources
            .iter()
            .find(|s| s.id == "SRC-WC-406")
            .expect("406");
        assert!(fact_stub(other, f4).is_none());
        // An edited row re-renders differently.
        let mut edited = src.clone();
        edited.sha256 = "0".repeat(64);
        assert_ne!(source_stub(&edited), source_stub(src));
        assert_eq!(
            String::from_utf8(placeholder("F4")).expect("utf-8"),
            "fa:case-placeholder:v1\nfact=F4\nstatement=the record describes this document; its bytes are not public\n"
        );
        assert_eq!(accession("https://example.org/no-accession.htm"), "");
    }
}
