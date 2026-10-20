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
const EXTRACTION_DOMAIN: &[u8] = b"fa:derived-extraction:v1";
const MAX_TOOL_STR_BYTES: usize = 512;
const MAX_CMD_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_EXTRACTION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// How a derived text document was extracted from its source document(s) (plan §9.1–9.3; `fa-646`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtractionMethod {
    /// Deterministic text-layer extraction from an embedded PDF stream (`replayable = true`).
    PdfTextLayer = 1,
    /// Subprocess OCR via `franken_ocr` (`focr` robot JSON, `replayable = false`).
    FrankenOcr = 2,
    /// Subprocess ASR via `franken_whisper` (`fw` robot NDJSON, `replayable = false`).
    FrankenWhisper = 3,
}

impl ExtractionMethod {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::PdfTextLayer),
            2 => Some(Self::FrankenOcr),
            3 => Some(Self::FrankenWhisper),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PdfTextLayer => "pdf_text_layer",
            Self::FrankenOcr => "franken_ocr",
            Self::FrankenWhisper => "franken_whisper",
        }
    }

    /// Whether the extraction is deterministically replayable without external models/GPUs.
    #[must_use]
    pub const fn default_replayable(self) -> bool {
        match self {
            Self::PdfTextLayer => true,
            Self::FrankenOcr | Self::FrankenWhisper => false,
        }
    }
}

/// Content-bound extraction metadata stored inside a derived text document's
/// `fa:derived-document:v1` payload (`fa:derived-extraction:v1`, plan §9.1–9.3).
///
/// Structural boundary: derived text documents carry UTF-8 text and tool provenance
/// for search, redaction, and human review (`record_review`); they never produce
/// `Amount`s or `LegPayload`s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedExtractionMetadata {
    pub method: ExtractionMethod,
    pub tool_name: String,
    pub tool_version: String,
    pub model_artifact_hash: Option<[u8; 32]>,
    pub command_line: Vec<String>,
    pub replayable: bool,
    pub extracted_text: String,
    pub raw_tool_output: Vec<u8>,
}

/// Encode `DerivedExtractionMetadata` inside a canonical `fa:derived-document:v1`
/// envelope bound to `sources`.
pub fn encode_extraction_derivation(
    sources: &[Oid],
    metadata: &DerivedExtractionMetadata,
) -> Result<Vec<u8>, Refusal> {
    if metadata.tool_name.is_empty() || metadata.tool_name.len() > MAX_TOOL_STR_BYTES {
        return Err(invalid(
            "extraction tool_name must be 1..=512 UTF-8 bytes",
        ));
    }
    if metadata.tool_version.is_empty() || metadata.tool_version.len() > MAX_TOOL_STR_BYTES {
        return Err(invalid(
            "extraction tool_version must be 1..=512 UTF-8 bytes",
        ));
    }
    if metadata.command_line.len() > MAX_CMD_ARGS
        || metadata
            .command_line
            .iter()
            .any(|arg| arg.is_empty() || arg.len() > MAX_ARG_BYTES)
    {
        return Err(invalid(
            "extraction command_line exceeds argument count or length bounds",
        ));
    }
    if metadata.extracted_text.len() > MAX_EXTRACTION_PAYLOAD_BYTES
        || metadata.raw_tool_output.len() > MAX_EXTRACTION_PAYLOAD_BYTES
    {
        return Err(invalid(
            "extraction text or raw tool output exceeds maximum payload bound",
        ));
    }
    match metadata.method {
        ExtractionMethod::PdfTextLayer if !metadata.replayable => {
            return Err(invalid(
                "PdfTextLayer extraction is deterministic and must record replayable = true",
            ));
        }
        ExtractionMethod::FrankenOcr | ExtractionMethod::FrankenWhisper if metadata.replayable => {
            return Err(invalid(
                "external subprocess OCR/ASR extraction must record replayable = false",
            ));
        }
        _ => {}
    }
    let mut inner = Writer::new();
    inner
        .bytes(EXTRACTION_DOMAIN)
        .u8(metadata.method.tag())
        .str(&metadata.tool_name)
        .str(&metadata.tool_version)
        .opt(metadata.model_artifact_hash.as_ref(), |w, hash| {
            w.fixed(hash);
        })
        .list(&metadata.command_line, |w, arg| {
            w.str(arg);
        })
        .bool(metadata.replayable)
        .str(&metadata.extracted_text)
        .bytes(&metadata.raw_tool_output);
    let inner_bytes = inner.finish().map_err(|error| invalid(error.to_string()))?;
    encode_derivation(sources, &inner_bytes)
}

/// Decode a `fa:derived-document:v1` envelope whose inner payload is a canonical
/// `fa:derived-extraction:v1` record.
pub fn decode_extraction_derivation(
    bytes: &[u8],
) -> Result<(Vec<Oid>, DerivedExtractionMetadata), Refusal> {
    let (sources, payload) = decode_derivation(bytes)?;
    let malformed = |error: fa_model::DecodeError| invalid(error.to_string());
    let mut reader = Reader::new(payload);
    if reader
        .bytes(64, "extraction.domain")
        .map_err(malformed)?
        != EXTRACTION_DOMAIN
    {
        return Err(invalid(
            "derived document payload is not a canonical fa:derived-extraction:v1 record",
        ));
    }
    let method_tag = reader.u8("extraction.method").map_err(malformed)?;
    let Some(method) = ExtractionMethod::from_tag(method_tag) else {
        return Err(invalid(format!(
            "unrecognized extraction method tag {method_tag}"
        )));
    };
    let tool_name = reader
        .str(MAX_TOOL_STR_BYTES, "extraction.tool_name")
        .map_err(malformed)?
        .to_string();
    let tool_version = reader
        .str(MAX_TOOL_STR_BYTES, "extraction.tool_version")
        .map_err(malformed)?
        .to_string();
    if tool_name.is_empty() || tool_version.is_empty() {
        return Err(invalid(
            "extraction tool_name and tool_version must be non-empty",
        ));
    }
    let model_artifact_hash = reader
        .opt("extraction.model_artifact_hash", |r| {
            r.fixed("extraction.model_artifact_hash.digest")
        })
        .map_err(malformed)?;
    let command_line = reader
        .list(MAX_CMD_ARGS, "extraction.command_line", |r| {
            let arg = r.str(MAX_ARG_BYTES, "extraction.arg")?;
            Ok(arg.to_string())
        })
        .map_err(malformed)?;
    if command_line.iter().any(String::is_empty) {
        return Err(invalid(
            "extraction command_line arguments must be non-empty",
        ));
    }
    let replayable = reader.bool("extraction.replayable").map_err(malformed)?;
    match method {
        ExtractionMethod::PdfTextLayer if !replayable => {
            return Err(invalid(
                "PdfTextLayer extraction must have replayable = true",
            ));
        }
        ExtractionMethod::FrankenOcr | ExtractionMethod::FrankenWhisper if replayable => {
            return Err(invalid(
                "subprocess OCR/ASR extraction must have replayable = false",
            ));
        }
        _ => {}
    }
    let extracted_text = reader
        .str(MAX_EXTRACTION_PAYLOAD_BYTES, "extraction.extracted_text")
        .map_err(malformed)?
        .to_string();
    let raw_tool_output = reader
        .bytes(MAX_EXTRACTION_PAYLOAD_BYTES, "extraction.raw_tool_output")
        .map_err(malformed)?
        .to_vec();
    reader.finish().map_err(malformed)?;
    Ok((
        sources,
        DerivedExtractionMetadata {
            method,
            tool_name,
            tool_version,
            model_artifact_hash,
            command_line,
            replayable,
            extracted_text,
            raw_tool_output,
        },
    ))
}

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

    #[test]
    fn extraction_derivation_round_trips_and_enforces_replayability_law() {
        let src = Oid([0x42; 32]);
        let pdf_meta = DerivedExtractionMetadata {
            method: ExtractionMethod::PdfTextLayer,
            tool_name: "fa-docket/pdf-text-layer".to_string(),
            tool_version: "0.0.1".to_string(),
            model_artifact_hash: None,
            command_line: Vec::new(),
            replayable: true,
            extracted_text: "INVOICE 1042\nTOTAL DUE: $1,234.56 USD".to_string(),
            raw_tool_output: Vec::new(),
        };
        let encoded = encode_extraction_derivation(&[src], &pdf_meta).unwrap();
        let (sources, decoded) = decode_extraction_derivation(&encoded).unwrap();
        assert_eq!(sources, vec![src]);
        assert_eq!(decoded, pdf_meta);

        // PdfTextLayer cannot claim replayable = false.
        let mut bad_pdf = pdf_meta;
        bad_pdf.replayable = false;
        assert!(encode_extraction_derivation(&[src], &bad_pdf).is_err());

        // FrankenOcr / FrankenWhisper cannot claim replayable = true.
        let bad_ocr = DerivedExtractionMetadata {
            method: ExtractionMethod::FrankenOcr,
            tool_name: "focr".to_string(),
            tool_version: "0.2.0".to_string(),
            model_artifact_hash: Some([0xAB; 32]),
            command_line: vec!["focr".to_string(), "scan.png".to_string()],
            replayable: true,
            extracted_text: "SCANNED RECEIPT".to_string(),
            raw_tool_output: br#"{"text":"SCANNED RECEIPT"}"#.to_vec(),
        };
        assert!(encode_extraction_derivation(&[src], &bad_ocr).is_err());
    }
}
