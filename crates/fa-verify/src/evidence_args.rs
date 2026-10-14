//! Offline evidence inventories; parse the recipient's complete request
//! before observing a file, then emit metadata only after every check passes.

mod allocation;
mod production;

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::evidence::inventory::{
    VerifiedEvidenceInventory, validate_citation_request, verify_evidence_inventory_exact,
    verify_evidence_inventory_for,
};
use fa_verify::evidence::{EvidenceCitation, MAX_EVIDENCE_PER_ENTRY, MAX_PROOF_BYTES};

use crate::{Failure, array, hex, object, quote, read_bounded, read_checkpoint};

const HELP: &str = "Usage:
  fa-verify evidence allocation --help  (independent allocation arithmetic and exact driver)
  fa-verify evidence production --help  (complete scoped entry/citation inventories)
  fa-verify evidence --proof INCLUSION --checkpoint TRUSTED_FILE --expect-entry HEX64 [--json]
  fa-verify evidence --proof INCLUSION --checkpoint TRUSTED_FILE --expect-entry HEX64 \\
    --expect-citation OID64:COMMIT64:ROLE [--expect-citation ...] [--json]
  fa-verify evidence --proof INCLUSION --checkpoint TRUSTED_FILE --expect-entry HEX64 \\
    --expect-empty [--json]

INCLUSION is an existing raw inclusion proof containing its entry payload,
not a bundle. TRUSTED_FILE contains exactly 80 raw checkpoint bytes. Obtain
and trust the checkpoint and expected entry digest separately from the proof.

The command inventories EVERY citation in the requested authenticated entry.
Each row contains its book-scoped document OID, public document commitment,
and exact role tag. No document or protected entry payload bytes are printed.

Optional --expect-citation checks an EXACT recipient-owned citation set, not
a subset. Each OID and commitment is 64 ASCII hex digits; ROLE is a decimal
integer 0..255. Supply at most 1024 rows in strictly ascending binary order
by (OID, commitment, role); duplicates and unsorted rows are usage errors.
The command never sorts or deduplicates them. Use --expect-empty to require
no citations; it is mutually exclusive with --expect-citation. Without either
option the entry digest is still mandatory, but the citation set is learned
from the authenticated entry. Never copy expectations from untrusted input.

Scope remains inclusion. The list is complete FOR THIS ENTRY ONLY: it does
not prove complete journal coverage, real-world evidence, or production.
Signatures, document bytes, custody, role truth, accounting laws, disclosure
authority and redaction policy are NOT checked. Use fa-verify document to
check separately requested chunks against an authenticated citation.
The inclusion proof is bounded to 64 MiB. No book, keys or network are needed.
Exit codes: 0 verified/help; 2 usage; 5 file/output I/O; 8 verification failed.";

struct Request {
    proof: PathBuf,
    checkpoint: PathBuf,
    entry_digest: [u8; 32],
    citations: Option<Vec<EvidenceCitation>>,
}

fn digest(text: &str) -> Result<[u8; 32], Failure> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage(
            "digests require exactly 64 ASCII hexadecimal digits",
        ));
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Failure::usage("invalid digest"))?;
    }
    Ok(result)
}

fn citation(text: &str) -> Result<EvidenceCitation, Failure> {
    // Two fixed-width digests, two separators, and at most three role digits.
    if !(131..=133).contains(&text.len()) || !text.is_ascii() {
        return Err(Failure::usage(
            "--expect-citation requires OID64:COMMIT64:ROLE",
        ));
    }
    let mut fields = text.split(':');
    let oid = fields.next().unwrap_or_default();
    let commitment = fields.next().unwrap_or_default();
    let role = fields.next().unwrap_or_default();
    if fields.next().is_some()
        || role.is_empty()
        || role.len() > 3
        || !role.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Failure::usage(
            "--expect-citation requires OID64:COMMIT64:ROLE",
        ));
    }
    Ok(EvidenceCitation {
        document_oid: digest(oid)?,
        doc_commit: digest(commitment)?,
        role: role
            .parse::<u8>()
            .map_err(|_| Failure::usage("citation role must be a decimal integer 0..255"))?,
    })
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let (mut proof, mut checkpoint, mut entry) = (None, None, None);
    let mut citations = Vec::new();
    let (mut expect_empty, mut json) = (false, false);
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if argument == "--json" || argument == "--expect-empty" {
            let seen = if argument == "--json" {
                &mut json
            } else {
                &mut expect_empty
            };
            if *seen {
                return Err(Failure::usage(
                    "each boolean option may be supplied only once",
                ));
            }
            *seen = true;
            index += 1;
            continue;
        }
        let name = argument
            .to_str()
            .ok_or_else(|| Failure::usage("unknown evidence option"))?;
        if !matches!(
            name,
            "--proof" | "--checkpoint" | "--expect-entry" | "--expect-citation"
        ) {
            return Err(Failure::usage(
                "unknown evidence option; run fa-verify evidence --help",
            ));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
            return Err(Failure::usage(format!(
                "{name} requires a value; use ./ for filenames beginning with --"
            )));
        }
        if name == "--expect-citation" {
            if citations.len() == MAX_EVIDENCE_PER_ENTRY {
                return Err(Failure::usage(
                    "at most 1024 expected citations are permitted",
                ));
            }
            let text = value
                .to_str()
                .ok_or_else(|| Failure::usage("citations must be ASCII"))?;
            citations.push(citation(text)?);
        } else {
            let slot = match name {
                "--proof" => &mut proof,
                "--checkpoint" => &mut checkpoint,
                _ => &mut entry,
            };
            if slot.replace(value).is_some() {
                return Err(Failure::usage(format!("{name} may be supplied only once")));
            }
        }
        index += 2;
    }
    if expect_empty && !citations.is_empty() {
        return Err(Failure::usage(
            "--expect-empty cannot be combined with --expect-citation",
        ));
    }
    validate_citation_request(&citations).map_err(|error| Failure::usage(error.to_string()))?;
    let proof = proof.ok_or_else(|| Failure::usage("--proof is required"))?;
    let checkpoint = checkpoint.ok_or_else(|| Failure::usage("--checkpoint is required"))?;
    let entry = entry
        .ok_or_else(|| Failure::usage("--expect-entry is required independently of the proof"))?;
    let text = entry
        .to_str()
        .ok_or_else(|| Failure::usage("--expect-entry must be ASCII hex"))?;
    Ok(Request {
        proof: PathBuf::from(proof),
        checkpoint: PathBuf::from(checkpoint),
        entry_digest: digest(text)?,
        citations: if expect_empty || !citations.is_empty() {
            Some(citations)
        } else {
            None
        },
    })
}

pub(super) fn run(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.get(1).and_then(|argument| argument.to_str()) == Some("allocation") {
        return allocation::run(&args[1..], json);
    }
    if args.get(1).and_then(|argument| argument.to_str()) == Some("production") {
        return production::run(&args[1..], json);
    }
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    let request = parse(args)?;
    let checkpoint = read_checkpoint(&request.checkpoint)?;
    let proof = read_bounded(&request.proof, MAX_PROOF_BYTES)?;
    let report = match &request.citations {
        Some(citations) => {
            verify_evidence_inventory_exact(&proof, &checkpoint, &request.entry_digest, citations)
        }
        None => verify_evidence_inventory_for(&proof, &checkpoint, &request.entry_digest),
    }
    .map_err(|error| Failure::verification(error.to_string()))?;
    Ok(render(&report, request.citations.is_some(), json))
}

fn render(report: &VerifiedEvidenceInventory, exact: bool, json: bool) -> String {
    let inclusion = &report.inclusion;
    let request_check = if exact {
        "entry_and_exact_citations"
    } else {
        "entry_only"
    };
    if !json {
        let mut text = format!(
            "Verified evidence inventory (scope: {}): {} citations in entry {} at sequence {}.\nCoverage: complete citation list for this entry only. Request check: {request_check}.\n",
            inclusion.scope,
            report.citations.len(),
            hex(&inclusion.envelope.record_digest),
            inclusion.envelope.commit_seq,
        );
        for citation in &report.citations {
            text.push_str(&format!(
                "document {} commit {} role {}\n",
                hex(&citation.document_oid),
                hex(&citation.doc_commit),
                citation.role,
            ));
        }
        text.push_str("Document bytes, signatures, custody, role truth, accounting laws, authorization, redaction policy, journal coverage and production completeness were not checked. No payload bytes are printed.");
        return text;
    }
    let checkpoint = &inclusion.checkpoint;
    let mut checks = vec![
        "trusted_checkpoint_matches",
        "requested_entry_digest",
        "record_recomputation",
        "leaf_inclusion",
        "canonical_complete_citation_list",
        "book_scoped_document_identities",
        "entry_frame",
    ];
    if exact {
        checks.push("exact_requested_citation_set");
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
        // u64 coordinates remain exact for JSON consumers using IEEE doubles.
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
            "checks",
            array(
                checks
                    .into_iter()
                    .map(|name| object([("name", quote(name)), ("status", quote("pass"))])),
            ),
        ),
        (
            "coverage",
            object([
                ("citations", quote("complete_for_requested_entry")),
                ("journal", quote("single_included_entry")),
                ("document_bytes", quote("not_verified")),
            ]),
        ),
        (
            "data",
            object([
                (
                    "entry_digest",
                    quote(&hex(&inclusion.envelope.record_digest)),
                ),
                ("leaf_index", quote(&inclusion.leaf_index.to_string())),
                (
                    "recorded_at",
                    quote(&inclusion.envelope.commit_seq.to_string()),
                ),
                ("record_check", quote("recomputed")),
                ("citation_count", report.citations.len().to_string()),
                (
                    "citations",
                    array(report.citations.iter().map(|citation| {
                        object([
                            ("document_oid", quote(&hex(&citation.document_oid))),
                            ("doc_commit", quote(&hex(&citation.doc_commit))),
                            ("role", citation.role.to_string()),
                        ])
                    })),
                ),
            ]),
        ),
        ("request_check", quote(request_check)),
        (
            "not_checked",
            array(
                [
                    "document_bytes",
                    "signatures",
                    "custody",
                    "citation_role_truth",
                    "accounting_laws",
                    "authorization",
                    "redaction_policy",
                    "journal_coverage",
                    "production_completeness",
                ]
                .map(quote),
            ),
        ),
        ("event", quote("proof_verified")),
        ("proof_kind", quote("evidence_inventory")),
        ("scope", quote(inclusion.scope)),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}
