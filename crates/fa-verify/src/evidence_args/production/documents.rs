//! Full original-cited document bytes alongside the existing production proofs.

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::evidence::inventory::production::documents::{
    DocumentContent, MAX_PRODUCTION_DOCUMENTS, VerifiedDocumentProduction,
    verify_document_production_for,
};
use fa_verify::proof::production::MAX_PRODUCTION_BYTES;

use crate::{Failure, array, hex, object, quote, read_bounded, read_checkpoint};

const HELP: &str = "Usage:
  fa-verify evidence production documents --prefix PREFIX --checkpoint TRUSTED_FILE \\
    --expect-first-seq U64 --expect-known-at U64 --expect-account HEX32|all \\
    --expect-days FIRST:LAST|all [--record INCLUSION ...] \\
    [--document OID64 KIND FILE ...] [--json]

The recipient independently chooses all four --expect-* selectors and trusts
exactly 80 raw checkpoint bytes. Their meanings are unchanged from evidence
production: inclusive sequence/day bounds, an exact account or all, and a
known-at horizon no later than the checkpoint. Records are supplied in leaf
order. The full authenticated prefix exposes out-of-scope envelope metadata.

--document consumes THREE arguments: 64 ASCII hex digits for the document
locator, a decimal u8 kind tag, and a path to its complete canonical bytes.
Repeat it once per distinct document, in strictly ascending locator order.
Every document originally cited by a selected entry is required, including
empty documents. Repeated citations/roles share one file. Missing, extra,
duplicate, substituted or corrupt files fail the entire verification.
No --document options succeed only for an authenticated empty citation set.

Expected document commitments come only from authenticated entry citations,
never from these options or a producer manifest. Kind, length and every byte
are recomputed. Kind/role tags are bound, not interpreted as economic facts.
No new bundle format, book, keys, network or signature trust is introduced.

Limits: 64 MiB TOTAL prefix + ALL record proofs + ALL document bytes; 4096
records, 65536 prefix leaves, citations and distinct documents. Each file is
read against the remaining total budget. Use ./ for paths beginning with --.
All argument syntax is checked before any file is opened. Non-UTF-8 paths
are supported. Success/error output never contains entry or document payloads.

Coverage is original cited document bytes only. Supplemental evidence, rules,
events, approvals, custody, signatures, permissions, evidence sufficiency,
accounting laws and migration visibility are NOT verified. Partial/redacted
views cannot fulfill this full-byte mode; use the separate disclosure modes.
Exit codes: 0 verified/help; 2 usage; 5 file/output I/O; 8 verification failed.";

struct DocumentFile {
    oid: [u8; 32],
    kind: u8,
    path: PathBuf,
}

fn oid(value: &OsString) -> Result<[u8; 32], Failure> {
    let text = value.to_str().ok_or_else(|| Failure::usage("document locator must be ASCII hex"))?;
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage("document locator requires exactly 64 ASCII hex digits"));
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Failure::usage("invalid document locator"))?;
    }
    Ok(result)
}

fn kind(value: &OsString) -> Result<u8, Failure> {
    let text = value.to_str().ok_or_else(|| Failure::usage("document kind must be ASCII decimal"))?;
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage("document kind requires a decimal u8 tag"));
    }
    text.parse().map_err(|_| Failure::usage("document kind exceeds u8"))
}

fn reserve<T>(values: &mut Vec<T>, count: usize) -> Result<(), Failure> {
    values.try_reserve_exact(count)
        .map_err(|_| Failure::verification("document production allocation exceeds available capacity"))
}

fn parse(args: &[OsString]) -> Result<(super::Request, Vec<DocumentFile>), Failure> {
    let mut base = Vec::new();
    reserve(&mut base, args.len())?;
    base.push("documents".into());
    let mut documents: Vec<DocumentFile> = Vec::new();
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if argument == "--document" {
            if documents.len() == MAX_PRODUCTION_DOCUMENTS {
                return Err(Failure::usage("at most 65536 --document options are permitted"));
            }
            let fields = args.get(index + 1..index + 4)
                .ok_or_else(|| Failure::usage("--document requires OID64 KIND FILE"))?;
            let oid = oid(&fields[0])?;
            let kind = kind(&fields[1])?;
            if fields[2].is_empty() || fields[2].to_str().is_some_and(|text| text.starts_with("--")) {
                return Err(Failure::usage("--document requires a path; use ./ for paths beginning with --"));
            }
            if documents.last().is_some_and(|previous| previous.oid >= oid) {
                return Err(Failure::usage("document locators must be strictly ascending and unique"));
            }
            // Amortized growth, still bounded by MAX_PRODUCTION_DOCUMENTS.
            documents.try_reserve(1)
                .map_err(|_| Failure::verification("document argument allocation failed"))?;
            documents.push(DocumentFile { oid, kind, path: PathBuf::from(&fields[2]) });
            index += 4;
        } else {
            base.push(argument.clone());
            index += 1;
            // Consume a base option's value as a unit; never mistake a path
            // or missing-value token for a new document declaration.
            if argument != "--json" {
                if let Some(value) = args.get(index) {
                    base.push(value.clone());
                    index += 1;
                }
            }
        }
    }
    // Reuse all mandatory scope and duplicate-option validation unchanged.
    Ok((super::parse(&base)?, documents))
}

pub(super) fn run(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    let (request, files) = parse(args)?;
    let checkpoint = read_checkpoint(&request.checkpoint)?;
    if request.scope.known_at > checkpoint.through_seq {
        return Err(Failure::verification("known_at is later than the trusted checkpoint"));
    }
    let prefix = read_bounded(&request.prefix, MAX_PRODUCTION_BYTES)?;
    let mut remaining = MAX_PRODUCTION_BYTES - prefix.len();
    let mut records = Vec::new();
    reserve(&mut records, request.records.len())?;
    for path in &request.records {
        let bytes = read_bounded(path, remaining)?;
        remaining -= bytes.len();
        records.push(bytes);
    }
    let mut content = Vec::new();
    reserve(&mut content, files.len())?;
    for file in &files {
        let bytes = read_bounded(&file.path, remaining)?;
        remaining -= bytes.len();
        content.push(bytes);
    }
    let mut record_slices = Vec::new();
    reserve(&mut record_slices, records.len())?;
    record_slices.extend(records.iter().map(Vec::as_slice));
    let mut documents = Vec::new();
    reserve(&mut documents, files.len())?;
    documents.extend(files.iter().zip(&content).map(|(file, bytes)| DocumentContent {
        document_oid: file.oid, kind: file.kind, bytes,
    }));
    let report = verify_document_production_for(
        &prefix, &record_slices, &documents, &checkpoint, &request.scope,
    ).map_err(|error| Failure::verification(error.to_string()))?;
    let rendered = render(&report, json);
    // Fixed-size hex/numeric metadata plus bounded counts; no caller strings
    // or payloads are rendered. Keep an explicit publication bound as well.
    if rendered.len() > MAX_PRODUCTION_BYTES {
        return Err(Failure::verification("document production report exceeds 64 MiB"));
    }
    Ok(rendered)
}

fn render(report: &VerifiedDocumentProduction, json: bool) -> String {
    let inventory = &report.inventory;
    let checkpoint = &inventory.checkpoint;
    let scope = &inventory.requested;
    if !json {
        let mut text = format!(
            "Verified original-cited document production: {} entries, {} citation rows, {} distinct documents, {} document bytes.\nEntry scope: {}; document scope: {}.\nTrusted checkpoint: {}.\nRecorded sequences {} through {}; exact account {:?}; inclusive civil days {:?}.\n",
            inventory.entries.len(), inventory.citation_count, report.documents.len(),
            report.document_byte_count, inventory.scope, report.document_scope, checkpoint,
            scope.first_seq, scope.known_at,
            scope.account.map(|account| format!("{account:032x}")), scope.effective_days,
        );
        for entry in &inventory.entries {
            text.push_str(&format!("leaf {} entry {} sequence {}: {} citations\n",
                entry.entry.leaf_index, hex(&entry.entry.envelope.record_digest),
                entry.entry.envelope.commit_seq, entry.citations.len()));
            for citation in &entry.citations {
                text.push_str(&format!("  document {} commit {} role {}\n",
                    hex(&citation.document_oid), hex(&citation.doc_commit), citation.role));
            }
        }
        for doc in &report.documents {
            text.push_str(&format!("document {} kind {}: {} bytes recomputed, {} citations\n",
                hex(&doc.document_oid), doc.kind, doc.byte_length, doc.citation_count));
        }
        text.push_str("Original cited bytes only, not full provenance. Supplemental evidence, rules, events, approvals, custody, signatures, permissions, evidence sufficiency, accounting laws and migration visibility were not verified. No payload bytes are printed.");
        return text;
    }
    object([
        ("anchor", object([
            ("source", quote("operator_trusted_checkpoint")),
            ("format", quote("unsigned_raw_checkpoint")),
            ("signature_verification", quote("not_performed")),
        ])),
        ("checkpoint", object([
            ("book_id", quote(&hex(&checkpoint.book_id))),
            ("branch_id", quote(&hex(&checkpoint.branch_id))),
            ("root", quote(&hex(&checkpoint.root))),
            ("leaf_count", quote(&checkpoint.leaf_count.to_string())),
            ("through_seq", quote(&checkpoint.through_seq.to_string())),
        ])),
        ("requested_scope", object([
            ("first_seq", quote(&scope.first_seq.to_string())),
            ("known_at", quote(&scope.known_at.to_string())),
            ("account", scope.account.map_or_else(|| "null".into(), |id| quote(&format!("{id:032x}")))),
            ("effective_days", scope.effective_days.map_or_else(|| "null".into(), |(first, last)| object([
                ("first", quote(&first.to_string())), ("last", quote(&last.to_string())),
            ]))),
        ])),
        ("coverage", object([
            ("entries", quote("complete_for_requested_scope")),
            ("citations", quote("complete_for_selected_entries")),
            ("original_cited_document_bytes", quote("complete_and_recomputed")),
            ("supplemental_evidence", quote("not_verified")),
            ("full_provenance_closure", quote("not_verified")),
            ("outside_scope", quote("not_claimed")),
        ])),
        ("data", object([
            ("entry_count", inventory.entries.len().to_string()),
            ("citation_count", inventory.citation_count.to_string()),
            ("document_count", report.documents.len().to_string()),
            ("document_byte_count", quote(&report.document_byte_count.to_string())),
            ("entries", array(inventory.entries.iter().map(|entry| object([
                ("leaf_index", quote(&entry.entry.leaf_index.to_string())),
                ("entry_digest", quote(&hex(&entry.entry.envelope.record_digest))),
                ("recorded_at", quote(&entry.entry.envelope.commit_seq.to_string())),
                ("within_commit_ordinal", entry.entry.envelope.within_commit_ordinal.to_string()),
                ("citations", array(entry.citations.iter().map(|citation| object([
                    ("document_oid", quote(&hex(&citation.document_oid))),
                    ("doc_commit", quote(&hex(&citation.doc_commit))),
                    ("role", citation.role.to_string()),
                ])))),
            ])))),
            ("documents", array(report.documents.iter().map(|doc| object([
                ("document_oid", quote(&hex(&doc.document_oid))),
                ("doc_commit", quote(&hex(&doc.doc_commit))),
                ("kind", doc.kind.to_string()),
                ("byte_length", quote(&doc.byte_length.to_string())),
                ("citation_count", doc.citation_count.to_string()),
            ])))),
        ])),
        ("not_checked", array([
            "supplemental_evidence", "full_provenance_closure", "rules", "events", "approvals",
            "custody", "signatures", "authorization", "evidence_sufficiency", "kind_role_truth",
            "accounting_laws", "migration_visibility",
        ].map(quote))),
        ("document_scope", quote(report.document_scope)),
        ("scope", quote(inventory.scope)),
        ("request_check", quote("recipient_scope")),
        ("event", quote("proof_verified")),
        ("proof_kind", quote("evidence_document_production")),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_bounds_document_count_without_opening_any_files() {
        let mut args: Vec<OsString> = vec!["documents".into()];
        for index in 0..=MAX_PRODUCTION_DOCUMENTS {
            args.extend(["--document".into(), format!("{index:064x}").into(),
                "1".into(), "not-opened".into()]);
        }
        let error = parse(&args).err().expect("excess document count must refuse");
        assert_eq!(error.exit, 2);
        assert!(error.message.contains("65536"));
    }
}
