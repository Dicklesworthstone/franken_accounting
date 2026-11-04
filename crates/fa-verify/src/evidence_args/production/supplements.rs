//! Explicit original-plus-supplement reports; legacy production output is unchanged.

use fa_verify::evidence::EvidenceCitation;
use fa_verify::evidence::inventory::production::documents::VerifiedDocumentContent;
use fa_verify::evidence::inventory::production::supplements::{
    VerifiedSupplementedDocumentProduction, VerifiedSupplementedEvidenceProduction,
};
use fa_verify::proof::production::MAX_PRODUCTION_BYTES;

use crate::{Failure, array, hex, object, quote};

#[derive(Clone, Copy)]
struct Documents<'a> {
    rows: &'a [VerifiedDocumentContent],
    byte_count: u64,
    scope: &'static str,
}

pub(super) fn render_inventory(
    report: &VerifiedSupplementedEvidenceProduction,
    json: bool,
) -> Result<String, Failure> {
    render(report, None, json)
}

pub(super) fn render_documents(
    report: &VerifiedSupplementedDocumentProduction,
    json: bool,
) -> Result<String, Failure> {
    render(
        &report.inventory,
        Some(Documents {
            rows: &report.documents,
            byte_count: report.document_byte_count,
            scope: report.document_scope,
        }),
        json,
    )
}

fn citation(citation: &EvidenceCitation) -> String {
    object([
        ("document_oid", quote(&hex(&citation.document_oid))),
        ("doc_commit", quote(&hex(&citation.doc_commit))),
        ("role", citation.role.to_string()),
    ])
}

fn render(
    report: &VerifiedSupplementedEvidenceProduction,
    documents: Option<Documents<'_>>,
    json: bool,
) -> Result<String, Failure> {
    let rendered = if json {
        render_json(report, documents)
    } else {
        render_human(report, documents)
    };
    if rendered.len() > MAX_PRODUCTION_BYTES {
        return Err(Failure::verification(
            "supplemented evidence production report exceeds 64 MiB",
        ));
    }
    Ok(rendered)
}

fn render_human(
    report: &VerifiedSupplementedEvidenceProduction,
    documents: Option<Documents<'_>>,
) -> String {
    let inventory = &report.inventory;
    let scope = &inventory.requested;
    let mut text = format!(
        "Verified original-plus-supplement evidence production: {} matching entries, {} original citation rows, {} supplemental records, {} total citation rows.\nEntry scope: {}. Recorded sequences {} through {}; exact account {:?}; inclusive civil days {:?}.\nTrusted checkpoint: {}.\n",
        inventory.entries.len(),
        inventory.citation_count,
        report.supplements.len(),
        report.citation_count,
        inventory.scope,
        scope.first_seq,
        scope.known_at,
        scope.account.map(|id| format!("{id:032x}")),
        scope.effective_days,
        inventory.checkpoint,
    );
    text.push_str("Original citations and later attachments were selected directly from the authenticated native prefix. Attachments are complete for the selected entries within that prefix through known-at; this does not establish pre-accumulator history. No separate record set was supplied or checked.\n");
    for original in &inventory.entries {
        let entry = &original.entry;
        text.push_str(&format!(
            "original leaf {} entry {} recorded at {}: {} citations\n",
            entry.leaf_index,
            hex(&entry.envelope.record_digest),
            entry.envelope.commit_seq,
            original.citations.len(),
        ));
        for cited in &original.citations {
            text.push_str(&format!(
                "  document {} commit {} role {}\n",
                hex(&cited.document_oid),
                hex(&cited.doc_commit),
                cited.role,
            ));
        }
    }
    for supplement in &report.supplements {
        text.push_str(&format!(
            "supplement leaf {} digest {} recorded at {}: target {:032x} digest {}, attached by {:032x}, {} citations\n",
            supplement.leaf_index,
            hex(&supplement.record_digest),
            supplement.recorded_at,
            supplement.entry_vid,
            hex(&supplement.entry_digest),
            supplement.attached_by,
            supplement.citations.len(),
        ));
        for cited in &supplement.citations {
            text.push_str(&format!(
                "  document {} commit {} role {}\n",
                hex(&cited.document_oid),
                hex(&cited.doc_commit),
                cited.role,
            ));
        }
    }
    if let Some(documents) = documents {
        text.push_str(&format!(
            "Document scope: {}; {} distinct documents, {} bytes recomputed across original and supplemental citations.\n",
            documents.scope,
            documents.rows.len(),
            documents.byte_count,
        ));
        for document in documents.rows {
            text.push_str(&format!(
                "document {} kind {}: {} bytes recomputed, {} citations\n",
                hex(&document.document_oid),
                document.kind,
                document.byte_length,
                document.citation_count,
            ));
        }
    } else {
        text.push_str("Document bytes were not supplied or verified.\n");
    }
    text.push_str("Full provenance, rules, events, approvals, custody, signatures, permissions, evidence sufficiency, kind/role truth, accounting laws and migration visibility were not verified. No entry or document payload bytes are printed.");
    text
}

fn render_json(
    report: &VerifiedSupplementedEvidenceProduction,
    documents: Option<Documents<'_>>,
) -> String {
    let inventory = &report.inventory;
    let scope = &inventory.requested;
    let checkpoint = &inventory.checkpoint;
    let mut data = vec![
        ("entry_count", inventory.entries.len().to_string()),
        (
            "original_citation_count",
            inventory.citation_count.to_string(),
        ),
        ("supplement_count", report.supplements.len().to_string()),
        ("citation_count", report.citation_count.to_string()),
        (
            "entries",
            array(inventory.entries.iter().map(|original| {
                let entry = &original.entry;
                object([
                    ("source", quote("original")),
                    ("leaf_index", quote(&entry.leaf_index.to_string())),
                    ("entry_digest", quote(&hex(&entry.envelope.record_digest))),
                    ("recorded_at", quote(&entry.envelope.commit_seq.to_string())),
                    (
                        "within_commit_ordinal",
                        entry.envelope.within_commit_ordinal.to_string(),
                    ),
                    ("citation_count", original.citations.len().to_string()),
                    ("citations", array(original.citations.iter().map(citation))),
                ])
            })),
        ),
        (
            "supplements",
            array(report.supplements.iter().map(|supplement| {
                object([
                    ("source", quote("supplement")),
                    ("leaf_index", quote(&supplement.leaf_index.to_string())),
                    ("record_digest", quote(&hex(&supplement.record_digest))),
                    ("recorded_at", quote(&supplement.recorded_at.to_string())),
                    (
                        "entry_vid",
                        quote(&format!("{:032x}", supplement.entry_vid)),
                    ),
                    ("entry_digest", quote(&hex(&supplement.entry_digest))),
                    (
                        "attached_by",
                        quote(&format!("{:032x}", supplement.attached_by)),
                    ),
                    ("citation_count", supplement.citations.len().to_string()),
                    (
                        "citations",
                        array(supplement.citations.iter().map(citation)),
                    ),
                ])
            })),
        ),
    ];
    let mut checks = vec![
        "trusted_checkpoint_matches",
        "complete_prefix",
        "recipient_scope",
        "complete_prefix_record_selection",
        "record_recomputation",
        "complete_citation_lists",
        "book_scoped_document_identities",
        "entry_frames",
        "supplement_target_identities",
        "supplement_target_order",
        "supplement_known_at",
        "complete_supplement_set",
    ];
    let mut not_checked = vec![
        "full_provenance_closure",
        "rules",
        "events",
        "approvals",
        "custody",
        "signatures",
        "authorization",
        "evidence_sufficiency",
        "kind_role_truth",
        "accounting_laws",
        "migration_visibility",
    ];
    if let Some(documents) = documents {
        data.extend([
            ("document_count", documents.rows.len().to_string()),
            (
                "document_byte_count",
                quote(&documents.byte_count.to_string()),
            ),
            (
                "documents",
                array(documents.rows.iter().map(|document| {
                    object([
                        ("document_oid", quote(&hex(&document.document_oid))),
                        ("doc_commit", quote(&hex(&document.doc_commit))),
                        ("kind", document.kind.to_string()),
                        ("byte_length", quote(&document.byte_length.to_string())),
                        ("citation_count", document.citation_count.to_string()),
                    ])
                })),
            ),
        ]);
        checks.extend([
            "exact_distinct_document_set",
            "document_commitment_recomputation",
        ]);
    } else {
        not_checked.push("document_bytes");
    }
    object([
        (
            "anchor",
            object([
                ("format", quote("unsigned_raw_checkpoint")),
                ("source", quote("operator_trusted_checkpoint")),
                ("signature_verification", quote("not_performed")),
            ]),
        ),
        (
            "checkpoint",
            object([
                ("book_id", quote(&hex(&checkpoint.book_id))),
                ("branch_id", quote(&hex(&checkpoint.branch_id))),
                ("leaf_count", quote(&checkpoint.leaf_count.to_string())),
                ("root", quote(&hex(&checkpoint.root))),
                ("through_seq", quote(&checkpoint.through_seq.to_string())),
            ]),
        ),
        (
            "requested_scope",
            object([
                ("first_seq", quote(&scope.first_seq.to_string())),
                ("known_at", quote(&scope.known_at.to_string())),
                (
                    "account",
                    scope
                        .account
                        .map_or_else(|| "null".into(), |id| quote(&format!("{id:032x}"))),
                ),
                (
                    "effective_days",
                    scope.effective_days.map_or_else(
                        || "null".into(),
                        |(first, last)| {
                            object([
                                ("first", quote(&first.to_string())),
                                ("last", quote(&last.to_string())),
                            ])
                        },
                    ),
                ),
            ]),
        ),
        (
            "coverage",
            object([
                ("entries", quote("complete_for_requested_scope")),
                ("original_citations", quote("complete_for_selected_entries")),
                (
                    "supplemental_evidence",
                    quote("complete_for_selected_entries_in_trusted_prefix_through_known_at"),
                ),
                (
                    "document_bytes",
                    quote(if documents.is_some() {
                        "complete_and_recomputed"
                    } else {
                        "not_verified"
                    }),
                ),
                ("full_provenance_closure", quote("not_verified")),
                ("outside_scope", quote("not_claimed")),
            ]),
        ),
        ("data", object(data)),
        (
            "checks",
            array(
                checks
                    .into_iter()
                    .map(|name| object([("name", quote(name)), ("status", quote("pass"))])),
            ),
        ),
        ("not_checked", array(not_checked.into_iter().map(quote))),
        (
            "document_scope",
            documents.map_or_else(|| "null".into(), |docs| quote(docs.scope)),
        ),
        ("scope", quote(inventory.scope)),
        ("evidence_mode", quote("original_plus_supplements")),
        ("record_source", quote("complete_native_prefix")),
        ("separate_record_set_checked", "false".into()),
        ("request_check", quote("recipient_scope")),
        ("event", quote("proof_verified")),
        (
            "proof_kind",
            quote(if documents.is_some() {
                "supplemented_evidence_document_production"
            } else {
                "supplemented_evidence_production"
            }),
        ),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}
