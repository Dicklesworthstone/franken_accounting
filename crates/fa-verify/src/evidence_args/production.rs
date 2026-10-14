//! Offline complete-scope evidence inventories using existing raw proofs.

mod documents;

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::evidence::inventory::production::{
    VerifiedEvidenceProduction, verify_evidence_production_for,
};
use fa_verify::proof::production::{MAX_PRODUCTION_BYTES, MAX_PRODUCTION_RECORDS, ProductionScope};

use crate::{Failure, array, hex, object, quote, read_bounded, read_checkpoint};

const HELP: &str = "Usage:
  fa-verify evidence production --prefix PREFIX --checkpoint TRUSTED_FILE \\
    --expect-first-seq U64 --expect-known-at U64 --expect-account HEX32|all \\
    --expect-days FIRST:LAST|all [--record INCLUSION ...] [--json]

For full cited document bytes as well, run:
  fa-verify evidence production documents --help

PREFIX is the existing raw complete-prefix proof. Supply precisely the
matching record-bearing inclusion proofs with repeated --record options,
in ascending leaf order. An empty list is accepted only when the verified
prefix establishes that the recipient's scope has no matching entries.
No file is a bundle, and no producer-supplied manifest is trusted.

All four --expect-* options are mandatory, independently chosen by the
recipient. Recorded sequence and signed i32 civil-day bounds are inclusive.
An account is one exact numeric u128 ID as 32 ASCII hexadecimal digits, not
an account code or subtree. Literal all means unrestricted; it is never
inferred from input. --expect-days all includes undated controls. Every
journal entry class is selected alike: this is not a posted-balance view.
The known-at horizon may be earlier than the trusted checkpoint, never later.

TRUSTED_FILE is exactly 80 raw checkpoint bytes, trusted independently.
The command authenticates the complete entry set and every original citation
list, including empty lists and repeated document/role associations. It does
not verify document contents, supplemental evidence, signatures, custody,
provenance, permissions, evidence sufficiency, accounting laws or migration
visibility. The full prefix exposes envelope metadata outside the scope;
this is not a private scope index or an authorization to export those bytes.

Limits: 64 MiB TOTAL prefix plus inclusion bytes, 4096 supplied records,
65536 prefix leaves and 65536 accumulated citations. Output contains only
metadata and is buffered until every verification succeeds. No entry or
document payload is printed. No book, keys or network are required.
Exit codes: 0 verified/help; 2 usage; 5 file/output I/O; 8 verification failed.";

struct Request {
    prefix: PathBuf,
    checkpoint: PathBuf,
    records: Vec<PathBuf>,
    scope: ProductionScope,
}

fn sequence(text: &str) -> Result<u64, Failure> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage("sequence bounds must be unsigned decimal u64 values"));
    }
    text.parse().map_err(|_| Failure::usage("sequence bound exceeds u64"))
}

fn day(text: &str) -> Result<i32, Failure> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if text.len() > 11 || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage("civil-day bounds must be signed decimal i32 values"));
    }
    text.parse().map_err(|_| Failure::usage("civil-day bound exceeds i32"))
}

fn days(text: &str) -> Result<Option<(i32, i32)>, Failure> {
    if text == "all" { return Ok(None); }
    let (first, last) = text.split_once(':')
        .ok_or_else(|| Failure::usage("--expect-days requires FIRST:LAST or all"))?;
    Ok(Some((day(first)?, day(last)?)))
}

fn account(text: &str) -> Result<Option<u128>, Failure> {
    if text == "all" { return Ok(None); }
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage("--expect-account requires exactly 32 ASCII hex digits or all"));
    }
    u128::from_str_radix(text, 16).map(Some)
        .map_err(|_| Failure::usage("invalid exact account ID"))
}

fn required_text<'a>(value: Option<&'a OsString>, name: &str) -> Result<&'a str, Failure> {
    value.ok_or_else(|| Failure::usage(format!("{name} is required independently of the proofs")))?
        .to_str().ok_or_else(|| Failure::usage(format!("{name} must be ASCII")))
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let (mut prefix, mut checkpoint, mut first, mut known, mut accounts, mut effective) =
        (None, None, None, None, None, None);
    let mut records = Vec::new();
    let mut json = false;
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if argument == "--json" {
            if json { return Err(Failure::usage("--json may be supplied only once")); }
            json = true;
            index += 1;
            continue;
        }
        let name = argument.to_str().ok_or_else(|| Failure::usage("unknown production option"))?;
        if !matches!(name, "--prefix" | "--checkpoint" | "--record" | "--expect-first-seq"
            | "--expect-known-at" | "--expect-account" | "--expect-days")
        {
            return Err(Failure::usage("unknown production option; run fa-verify evidence production --help"));
        }
        let value = args.get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
            return Err(Failure::usage(format!("{name} requires a value; use ./ for a filename beginning with --")));
        }
        if name == "--record" {
            if records.len() == MAX_PRODUCTION_RECORDS {
                return Err(Failure::usage("at most 4096 --record options are permitted"));
            }
            records.push(PathBuf::from(value));
        } else {
            let slot = match name {
                "--prefix" => &mut prefix,
                "--checkpoint" => &mut checkpoint,
                "--expect-first-seq" => &mut first,
                "--expect-known-at" => &mut known,
                "--expect-account" => &mut accounts,
                _ => &mut effective,
            };
            if slot.replace(value).is_some() {
                return Err(Failure::usage(format!("{name} may be supplied only once")));
            }
        }
        index += 2;
    }
    let scope = ProductionScope {
        first_seq: sequence(required_text(first, "--expect-first-seq")?)?,
        known_at: sequence(required_text(known, "--expect-known-at")?)?,
        account: account(required_text(accounts, "--expect-account")?)?,
        effective_days: days(required_text(effective, "--expect-days")?)?,
    };
    scope.validate().map_err(|error| Failure::usage(error.to_string()))?;
    Ok(Request {
        prefix: PathBuf::from(prefix.ok_or_else(|| Failure::usage("--prefix is required"))?),
        checkpoint: PathBuf::from(checkpoint.ok_or_else(|| Failure::usage("--checkpoint is required"))?),
        records,
        scope,
    })
}

pub(super) fn run(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.get(1).is_some_and(|argument| argument == "documents") {
        return documents::run(&args[1..], json);
    }
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    // Complete syntax validation before observing any supplied file path.
    let request = parse(args)?;
    let checkpoint = read_checkpoint(&request.checkpoint)?;
    if request.scope.known_at > checkpoint.through_seq {
        return Err(Failure::verification("known_at is later than the trusted checkpoint"));
    }
    let prefix = read_bounded(&request.prefix, MAX_PRODUCTION_BYTES)?;
    let mut remaining = MAX_PRODUCTION_BYTES - prefix.len();
    let mut records = Vec::new();
    records.try_reserve_exact(request.records.len())
        .map_err(|_| Failure::verification("record allocation exceeds available capacity"))?;
    for path in &request.records {
        // The remaining TOTAL budget applies before every read, including
        // metadata and growth checks; not 64 MiB separately for every file.
        let bytes = read_bounded(path, remaining)?;
        remaining -= bytes.len();
        records.push(bytes);
    }
    let slices: Vec<_> = records.iter().map(Vec::as_slice).collect();
    let report = verify_evidence_production_for(&prefix, &slices, &checkpoint, &request.scope)
        .map_err(|error| Failure::verification(error.to_string()))?;
    Ok(render(&report, json))
}

fn render(report: &VerifiedEvidenceProduction, json: bool) -> String {
    let scope = &report.requested;
    if !json {
        let mut text = format!(
            "Verified evidence production (scope: {}): {} matching entries, {} original citation rows.\nRecorded sequences {} through {}; exact account {:?}; inclusive civil days {:?}.\nTrusted checkpoint: {}.\n",
            report.scope, report.entries.len(), report.citation_count,
            scope.first_seq, scope.known_at, scope.account.map(|account| format!("{account:032x}")),
            scope.effective_days, report.checkpoint,
        );
        for inventory in &report.entries {
            let entry = &inventory.entry;
            text.push_str(&format!(
                "leaf {} entry {} sequence {}: {} citations\n",
                entry.leaf_index, hex(&entry.envelope.record_digest),
                entry.envelope.commit_seq, inventory.citations.len(),
            ));
            for citation in &inventory.citations {
                text.push_str(&format!("  document {} commit {} role {}\n",
                    hex(&citation.document_oid), hex(&citation.doc_commit), citation.role));
            }
        }
        text.push_str("Complete only for the requested journal entries and their original citation lists. Document bytes, supplemental evidence, signatures, provenance, permissions, evidence sufficiency, accounting laws and migration visibility were not verified. No payload bytes are printed.");
        return text;
    }
    let checkpoint = &report.checkpoint;
    object([
        ("anchor", object([
            ("format", quote("unsigned_raw_checkpoint")),
            ("source", quote("operator_trusted_checkpoint")),
            ("signature_verification", quote("not_performed")),
        ])),
        ("checkpoint", object([
            ("book_id", quote(&hex(&checkpoint.book_id))),
            ("branch_id", quote(&hex(&checkpoint.branch_id))),
            ("leaf_count", quote(&checkpoint.leaf_count.to_string())),
            ("root", quote(&hex(&checkpoint.root))),
            ("through_seq", quote(&checkpoint.through_seq.to_string())),
        ])),
        ("checks", array([
            "trusted_checkpoint_matches", "complete_prefix", "recipient_scope",
            "exact_record_set", "record_recomputation", "complete_citation_lists",
            "book_scoped_document_identities", "entry_frames",
        ].map(|name| object([("name", quote(name)), ("status", quote("pass"))])))),
        ("coverage", object([
            ("entries", quote("complete_for_requested_scope")),
            ("citations", quote("complete_for_selected_entries")),
            ("document_bytes", quote("not_verified")),
            ("supplemental_evidence", quote("not_verified")),
            ("outside_scope", quote("not_claimed")),
        ])),
        ("requested_scope", object([
            ("first_seq", quote(&scope.first_seq.to_string())),
            ("known_at", quote(&scope.known_at.to_string())),
            ("account", scope.account.map_or_else(|| "null".into(), |account| quote(&format!("{account:032x}")))),
            ("effective_days", scope.effective_days.map_or_else(|| "null".into(), |(first, last)| object([
                ("first", quote(&first.to_string())), ("last", quote(&last.to_string())),
            ]))),
        ])),
        ("data", object([
            ("entry_count", report.entries.len().to_string()),
            ("citation_count", report.citation_count.to_string()),
            ("entries", array(report.entries.iter().map(|inventory| {
                let entry = &inventory.entry;
                object([
                    ("leaf_index", quote(&entry.leaf_index.to_string())),
                    ("entry_digest", quote(&hex(&entry.envelope.record_digest))),
                    ("recorded_at", quote(&entry.envelope.commit_seq.to_string())),
                    ("within_commit_ordinal", entry.envelope.within_commit_ordinal.to_string()),
                    ("citation_count", inventory.citations.len().to_string()),
                    ("citations", array(inventory.citations.iter().map(|citation| object([
                        ("document_oid", quote(&hex(&citation.document_oid))),
                        ("doc_commit", quote(&hex(&citation.doc_commit))),
                        ("role", citation.role.to_string()),
                    ])))),
                ])
            }))),
        ])),
        ("not_checked", array([
            "document_bytes", "supplemental_evidence", "signatures", "provenance",
            "authorization", "evidence_sufficiency", "citation_role_truth", "accounting_laws",
            "migration_visibility", "complete_document_production",
        ].map(quote))),
        ("request_check", quote("recipient_scope")),
        ("event", quote("proof_verified")),
        ("proof_kind", quote("evidence_production")),
        ("scope", quote(report.scope)),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}
