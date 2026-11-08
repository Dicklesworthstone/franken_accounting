//! Transport for conditional additive scenario mathematics. The signed trunk
//! report and journaled Open/Plan records are evidence; hypothetical postings
//! remain assumptions. This format never claims native scratch admission or
//! independent membership of the substrate markers named by the SeqMap.

use fa_journal::{Refusal, exit};
use fa_model::{Oid, Writer};
use fgdb_crypto::Hasher;

use crate::Bundle;

pub const SCENARIO_MATH_BUNDLE_FORMAT: &[u8] = b"fa:scenario-math-bundle:v1";
pub const NATIVE_ORIGINAL_ADDITIVE_METHOD: &str = "native-original-additive:v1";
pub const MAX_SCENARIO_MATH_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SCENARIO_DOCUMENTS: usize = 65_536;

/// Full bytes required by the Open assumptions or the selected Plan evidence.
/// Disclosure authority is checked by the facade before constructing these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioDocument {
    pub oid: Oid,
    pub kind: u8,
    pub bytes: Vec<u8>,
}

fn refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §13.3 / §15.2 (conditional scenario mathematics over complete authenticated inputs)",
        "retain the original v2 scenario certificate, its complete signed fork prefix and exact Open/Plan records, and disclose every assumption and cited document",
    )
}

/// Assemble an already replayed v2 scenario certificate and a complete native
/// trunk report bundle. Documents are the exact ascending union of assumptions
/// and selected intent evidence. The facade checks the supported posting profile
/// and source coverage; the independent verifier rederives both from the bytes.
///
/// Wire: bytes(format), bytes(method), bytes(scenario certificate),
/// bytes(trunk report bundle), bytes(SeqMap), list(oid[32], kind u8, bytes).
/// A detached ProductionReceipt signs this outer bundle's digest, never the
/// nested trunk report's digest. Empty changes still require the whole closure.
pub fn assemble(
    certificate: &[u8],
    trunk_bundle: &[u8],
    seq_map: &[u8],
    documents: &[ScenarioDocument],
) -> Result<Bundle, Refusal> {
    if documents.len() > MAX_SCENARIO_DOCUMENTS
        || documents.windows(2).any(|pair| pair[0].oid >= pair[1].oid)
    {
        return Err(refused(
            "scenario documents must be bounded, distinct and ascending",
        ));
    }
    let mut size = certificate.len();
    for part in [trunk_bundle.len(), seq_map.len(), 128] {
        size = size
            .checked_add(part)
            .ok_or_else(|| refused("scenario bundle size overflow"))?;
    }
    for document in documents {
        size = size
            .checked_add(document.bytes.len())
            .and_then(|n| n.checked_add(37))
            .ok_or_else(|| refused("scenario document closure size overflow"))?;
    }
    if size > MAX_SCENARIO_MATH_BYTES {
        return Err(refused("scenario mathematical closure exceeds 64 MiB"));
    }
    let mut w = Writer::new();
    w.bytes(SCENARIO_MATH_BUNDLE_FORMAT)
        .str(NATIVE_ORIGINAL_ADDITIVE_METHOD)
        .bytes(certificate)
        .bytes(trunk_bundle)
        .bytes(seq_map)
        .list(documents, |w, document| {
            w.fixed(&document.oid.0)
                .u8(document.kind)
                .bytes(&document.bytes);
        });
    let bytes = w.finish().map_err(|error| refused(error.to_string()))?;
    if bytes.len() > MAX_SCENARIO_MATH_BYTES {
        return Err(refused("scenario mathematical closure exceeds 64 MiB"));
    }
    let mut digest = Hasher::new();
    digest.update(SCENARIO_MATH_BUNDLE_FORMAT);
    digest.update(&bytes);
    Ok(Bundle {
        bytes,
        digest: digest.finalize().0,
    })
}
