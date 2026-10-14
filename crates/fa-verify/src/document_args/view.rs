//! Kernel-view evidence adapter. The entry authenticates the citation and
//! original locator, not the redaction contract or permission to disclose.

use std::path::Path;

use fa_verify::Checkpoint;
use fa_verify::evidence::{EvidenceExpectation, VerifiedEvidenceView, verify_evidence_view_for};
use fa_verify::redaction::MAX_VIEW_BYTES;

use crate::{Failure, array, checkpoint_json, hex, object, quote, read_bounded};

pub(super) fn run(
    path: &Path,
    entry_proof: &[u8],
    checkpoint: &Checkpoint,
    expected: &EvidenceExpectation,
    indexes: &[u64],
    json: bool,
) -> Result<String, Failure> {
    // A fully disclosed 64 MiB document has additional canonical framing.
    // Do not accidentally reuse the narrower compact-proof file ceiling.
    let bytes = read_bounded(path, MAX_VIEW_BYTES)?;
    let report = verify_evidence_view_for(entry_proof, &bytes, checkpoint, expected, indexes)
        .map_err(|error| Failure::verification(error.to_string()))?;
    Ok(render(&report, json))
}

fn render(report: &VerifiedEvidenceView<'_>, json: bool) -> String {
    let entry = &report.inclusion;
    let citation = &report.citation;
    if !json {
        return format!(
            "Verified evidence view: entry {} at sequence {} (scope: {}), citing document {} with role {}; {} exact requested chunks (scope: {}).\nTrusted checkpoint: {}.\nDocument commitment authenticated through the entry: {}.\nRedaction contract {} is unverified metadata. View digest {} is computed, not independently authenticated.\nSignatures, authorization, provenance, citation-role truth, accounting laws, redaction policy, undisclosed bytes and production completeness were not checked. No document bytes are printed.",
            hex(&entry.envelope.record_digest), entry.envelope.commit_seq, entry.scope,
            hex(&citation.document_oid), citation.role, report.disclosed.len(), report.disclosure_scope,
            entry.checkpoint, hex(&citation.doc_commit), report.unverified_contract,
            hex(&report.view_commit)
        );
    }
    object([
        ("anchor", object([
            ("format", quote("unsigned_raw_checkpoint")),
            ("signature_verification", quote("not_performed")),
            ("source", quote("operator_trusted_checkpoint")),
        ])),
        ("checkpoint", checkpoint_json(&entry.checkpoint)),
        ("checks", array([
            "trusted_checkpoint_matches", "requested_entry_digest", "record_recomputation",
            "leaf_inclusion", "requested_document_and_role", "book_scoped_document_identity",
            "authenticated_view_locator", "canonical_view_shape", "requested_chunk_set",
            "document_chunk_membership",
        ].map(|name| object([("name", quote(name)), ("status", quote("pass"))])))),
        ("citation", object([
            ("document_oid", quote(&hex(&citation.document_oid))),
            ("doc_commit", quote(&hex(&citation.doc_commit))),
            ("role", citation.role.to_string()),
        ])),
        ("data", object([
            ("entry_digest", quote(&hex(&entry.envelope.record_digest))),
            ("leaf_index", quote(&entry.leaf_index.to_string())),
            ("recorded_at", quote(&entry.envelope.commit_seq.to_string())),
            ("record_check", quote("recomputed")),
            ("chunks", array(report.disclosed.iter().map(|chunk| object([
                ("byte_length", chunk.bytes.len().to_string()),
                ("index", quote(&chunk.index.to_string())),
            ])))),
            ("document_kind", report.kind.to_string()),
            ("document_length_bytes", quote(&report.size.to_string())),
            ("requested_chunks", report.disclosed.len().to_string()),
            ("withheld_chunks", report.withheld_chunks.to_string()),
            ("view_commit", quote(&hex(&report.view_commit))),
            ("view_commit_status", quote("computed_not_authenticated")),
        ])),
        ("unverified_metadata", object([
            ("contract", report.unverified_contract.to_string()),
            ("status", quote("not_authenticated_by_entry_or_document_commitment")),
        ])),
        ("not_checked", array([
            "signatures", "authorization", "provenance", "citation_role_truth",
            "accounting_laws", "redaction_policy", "undisclosed_bytes", "production_completeness",
        ].map(quote))),
        ("artifact_format", quote("redacted_view_v1")),
        ("event", quote("proof_verified")),
        ("proof_kind", quote("evidence_document")),
        ("scope", quote(report.disclosure_scope)),
        ("scopes", object([
            ("entry", quote(entry.scope)), ("disclosure", quote(report.disclosure_scope)),
        ])),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}
