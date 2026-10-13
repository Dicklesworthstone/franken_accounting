//! Offline document-disclosure command with a recipient-owned trust anchor.
//! Parsing completes before any input file is opened. A successful report
//! contains metadata only; neither stdout nor diagnostics dump source bytes.

mod view;

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::disclosure::{self, MAX_DISCLOSURE_CHUNKS};
use fa_verify::evidence::{self, EvidenceExpectation, VerifiedEvidenceDisclosure};

use crate::{Failure, array, checkpoint_json, hex, object, quote, read_bounded, read_checkpoint};

const HELP: &str = "Usage:
  fa-verify document --proof DISCLOSURE --document-commit TRUSTED_FILE --chunks 0,4 [--json]
  fa-verify document --proof DISCLOSURE --entry-proof INCLUSION --checkpoint TRUSTED_FILE \\
    --expect-entry HEX64 --expect-document HEX64 --expect-role U8 --chunks 0,4 [--json]

In journal-authenticated mode, replace --proof DISCLOSURE with --view VIEW
to check a raw kernel RedactedView v1. The two options are mutually exclusive;
--view requires the journal anchor, never --document-commit.

DISCLOSURE is raw fa:document-disclosure:v1; VIEW is raw RedactedView v1,
not a bundle. Views have a 64 MiB document bound plus canonical framing.
View chunk indices must be below 16384; compact proofs retain u64 indices. --chunks is the recipient's exact nonempty, strictly increasing
comma-separated decimal request. No requested index is inferred from input.

Choose exactly ONE trust mode:
  --document-commit: a file of exactly 32 independently trusted raw bytes.
  --entry-proof and --checkpoint: authenticate the document citation through
    the requested journal entry. The inclusion proof MUST carry its record.
    The checkpoint is exactly 80 raw bytes, obtained and trusted separately.
    --expect-entry is the entry's 32-byte digest as 64 hexadecimal digits.
    --expect-document is its document OID (not doc_commit), also HEX64.
    --expect-role is the exact citation-role tag, a decimal integer 0..255.
    All five options are required together. They cannot be combined with
    --document-commit. Never copy expected values from untrusted artifacts.

In entry mode the commitment comes only from the authenticated citation.
The report distinguishes journal inclusion from document membership_only.
It never prints document bytes or claims signature verification, authority
to disclose, provenance, truth of the citation role, accounting correctness,
redaction-policy compliance or complete production of evidence.
Compact and inclusion proofs are bounded to 64 MiB; the view bound also
includes framing. A view's locator must match the authenticated citation;
its contract and computed view digest are not independently authenticated.
No book, keys or network are needed.
Exit codes: 0 verified/help; 2 usage; 5 file/output I/O; 8 verification failed.";

enum Anchor {
    Document(PathBuf),
    Entry {
        proof: PathBuf,
        checkpoint: PathBuf,
        expected: EvidenceExpectation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DisclosureKind {
    Compact,
    View,
}

struct Request {
    proof: PathBuf,
    kind: DisclosureKind,
    anchor: Anchor,
    indexes: Vec<u64>,
}

fn indexes(value: &str) -> Result<Vec<u64>, Failure> {
    if value.len() > MAX_DISCLOSURE_CHUNKS * 21 {
        return Err(Failure::usage("--chunks exceeds the bounded recipient request"));
    }
    let mut indexes = Vec::new();
    for token in value.split(',') {
        if indexes.len() == MAX_DISCLOSURE_CHUNKS {
            return Err(Failure::usage(format!(
                "--chunks admits at most {MAX_DISCLOSURE_CHUNKS} indexes"
            )));
        }
        if token.is_empty() || token.len() > 20 || !token.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Failure::usage(
                "--chunks requires comma-separated unsigned decimal indexes, e.g. 0,4",
            ));
        }
        indexes.push(token.parse::<u64>().map_err(|_| {
            Failure::usage("a --chunks index exceeds u64")
        })?);
    }
    disclosure::validate_request(&indexes)
        .map_err(|error| Failure::usage(error.to_string()))?;
    Ok(indexes)
}

fn digest(value: &OsString, name: &str) -> Result<[u8; 32], Failure> {
    let text = value.to_str().ok_or_else(|| {
        Failure::usage(format!("{name} requires exactly 64 ASCII hexadecimal digits"))
    })?;
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage(format!(
            "{name} requires exactly 64 ASCII hexadecimal digits"
        )));
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Failure::usage(format!("invalid {name}")))?;
    }
    Ok(result)
}

fn role(value: &OsString) -> Result<u8, Failure> {
    let text = value.to_str().ok_or_else(|| {
        Failure::usage("--expect-role requires a decimal citation-role tag 0..255")
    })?;
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage("--expect-role requires a decimal citation-role tag 0..255"));
    }
    text.parse::<u8>().map_err(|_| {
        Failure::usage("--expect-role requires a decimal citation-role tag 0..255")
    })
}

fn required<'a>(value: Option<&'a OsString>, name: &str) -> Result<&'a OsString, Failure> {
    value.ok_or_else(|| Failure::usage(format!("{name} is required in journal-authenticated mode")))
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let (mut proof, mut view, mut commitment, mut requested) = (None, None, None, None);
    let (mut entry_proof, mut checkpoint) = (None, None);
    let (mut entry, mut document, mut expected_role) = (None, None, None);
    let mut json = false;
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if argument == "--json" {
            if json {
                return Err(Failure::usage("--json may be supplied only once"));
            }
            json = true;
            index += 1;
            continue;
        }
        let (name, slot) = match argument.to_str() {
            Some("--proof") => ("--proof", &mut proof),
            Some("--view") => ("--view", &mut view),
            Some("--document-commit") => ("--document-commit", &mut commitment),
            Some("--chunks") => ("--chunks", &mut requested),
            Some("--entry-proof") => ("--entry-proof", &mut entry_proof),
            Some("--checkpoint") => ("--checkpoint", &mut checkpoint),
            Some("--expect-entry") => ("--expect-entry", &mut entry),
            Some("--expect-document") => ("--expect-document", &mut document),
            Some("--expect-role") => ("--expect-role", &mut expected_role),
            _ => return Err(Failure::usage(format!(
                "unknown document argument {argument:?}; run fa-verify document --help"
            ))),
        };
        if slot.is_some() {
            return Err(Failure::usage(format!("{name} may be supplied only once")));
        }
        let value = args.get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
            return Err(Failure::usage(format!(
                "{name} requires a value; use ./ for a filename beginning with --"
            )));
        }
        *slot = Some(value);
        index += 2;
    }
    let (proof, kind) = match (proof, view) {
        (Some(path), None) => (PathBuf::from(path), DisclosureKind::Compact),
        (None, Some(path)) => (PathBuf::from(path), DisclosureKind::View),
        _ => return Err(Failure::usage("supply exactly one of --proof or --view")),
    };
    let requested = requested.ok_or_else(|| Failure::usage(
        "--chunks is required; specify the recipient's exact request, never infer it from the proof"
    ))?;
    let indexes = indexes(requested.to_str().ok_or_else(|| {
        Failure::usage("--chunks must be an ASCII decimal index list")
    })?)?;
    let journal_mode = [entry_proof, checkpoint, entry, document, expected_role]
        .iter().any(Option::is_some);
    let anchor = match (commitment, journal_mode) {
        (Some(_), true) => return Err(Failure::usage(
            "--document-commit cannot be combined with journal-authenticated evidence options"
        )),
        (Some(path), false) => Anchor::Document(PathBuf::from(path)),
        (None, false) => return Err(Failure::usage(
            "choose --document-commit or all journal-authenticated evidence options; run fa-verify document --help"
        )),
        (None, true) => Anchor::Entry {
            proof: PathBuf::from(required(entry_proof, "--entry-proof")?),
            checkpoint: PathBuf::from(required(checkpoint, "--checkpoint")?),
            expected: EvidenceExpectation {
                entry_digest: digest(required(entry, "--expect-entry")?, "--expect-entry")?,
                document_oid: digest(required(document, "--expect-document")?, "--expect-document")?,
                role: role(required(expected_role, "--expect-role")?)?,
            },
        },
    };
    if kind == DisclosureKind::View {
        if !matches!(&anchor, Anchor::Entry { .. }) {
            return Err(Failure::usage("--view requires journal-authenticated evidence options"));
        }
        // Compact proofs can sparsely name u64 indices. Only the complete
        // kernel-view format inherits the shipped kernel's document bound.
        evidence::validate_request(&indexes)
            .map_err(|error| Failure::usage(error.to_string()))?;
    }
    Ok(Request { proof, kind, anchor, indexes })
}

pub(super) fn run(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    // This resolves both trust modes, all expected values and every flag
    // before observing even the existence of any supplied path.
    let request = parse(args)?;
    match &request.anchor {
        Anchor::Document(path) => document_report(&request, path, json),
        Anchor::Entry { proof, checkpoint, expected } => {
            let checkpoint = read_checkpoint(checkpoint)?;
            let entry_proof = read_bounded(proof, evidence::MAX_PROOF_BYTES)?;
            if request.kind == DisclosureKind::View {
                return view::run(
                    &request.proof, &entry_proof, &checkpoint, expected, &request.indexes, json,
                );
            }
            let disclosure = read_bounded(&request.proof, disclosure::MAX_PROOF_BYTES)?;
            let report = evidence::verify_evidence_disclosure_for(
                &entry_proof, &disclosure, &checkpoint, expected, &request.indexes,
            ).map_err(|error| Failure::verification(error.to_string()))?;
            Ok(evidence_report(&report, json))
        }
    }
}

fn document_report(request: &Request, path: &std::path::Path, json: bool) -> Result<String, Failure> {
    let bytes = read_bounded(path, 32)?;
    let trusted: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        Failure::verification("--document-commit must contain exactly 32 raw bytes, not hex text")
    })?;
    let proof = read_bounded(&request.proof, disclosure::MAX_PROOF_BYTES)?;
    let report = disclosure::verify(&proof, &request.indexes, &trusted)
        .map_err(|error| Failure::verification(error.to_string()))?;
    if !json {
        return Ok(format!(
            "Verified document disclosure (scope: {}): {} requested chunks, kind {}, document length {} bytes.\nTrusted doc_commit: {}.\nSignatures, provenance, authorization, undisclosed bytes and production completeness were not verified.",
            report.scope, report.chunks.len(), report.kind, report.document_length, hex(&trusted)
        ));
    }
    Ok(object([
        ("anchor", object([
            ("format", quote("raw_document_commitment")),
            ("signature_verification", quote("not_performed")),
            ("source", quote("operator_trusted_document_commitment")),
        ])),
        ("checks", array(["requested_chunk_set", "document_chunk_membership"].map(|name| {
            object([("name", quote(name)), ("status", quote("pass"))])
        }))),
        ("data", object([
            ("chunks", array(report.chunks.iter().map(|chunk| object([
                ("byte_length", chunk.byte_length.to_string()),
                ("index", quote(&chunk.index.to_string())),
            ])))),
            ("document_kind", report.kind.to_string()),
            ("document_length_bytes", quote(&report.document_length.to_string())),
            ("requested_chunks", request.indexes.len().to_string()),
        ])),
        ("document_commit", quote(&hex(&trusted))),
        ("event", quote("proof_verified")),
        ("proof_kind", quote("document")),
        ("scope", quote(report.scope)),
        ("v", "1".into()),
        ("verified", "true".into()),
    ]))
}

fn evidence_report(report: &VerifiedEvidenceDisclosure, json: bool) -> String {
    let entry = &report.inclusion;
    let citation = &report.citation;
    let disclosure = &report.disclosure;
    if !json {
        return format!(
            "Verified evidence disclosure: entry {} at sequence {} (scope: {}), citing document {} with role {}; {} exact requested chunks (scope: {}).\nTrusted checkpoint: {}.\nDocument commitment authenticated through the entry: {}.\nSignatures, authorization, provenance, citation-role truth, accounting laws, redaction policy, undisclosed bytes and production completeness were not checked. No document bytes are printed.",
            hex(&entry.envelope.record_digest), entry.envelope.commit_seq, entry.scope,
            hex(&citation.document_oid), citation.role, disclosure.chunks.len(), disclosure.scope,
            entry.checkpoint, hex(&citation.doc_commit)
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
            "requested_chunk_set", "document_chunk_membership",
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
            ("chunks", array(disclosure.chunks.iter().map(|chunk| object([
                ("byte_length", chunk.byte_length.to_string()),
                ("index", quote(&chunk.index.to_string())),
            ])))),
            ("document_kind", disclosure.kind.to_string()),
            ("document_length_bytes", quote(&disclosure.document_length.to_string())),
            ("requested_chunks", disclosure.chunks.len().to_string()),
        ])),
        ("not_checked", array([
            "signatures", "authorization", "provenance", "citation_role_truth",
            "accounting_laws", "redaction_policy", "undisclosed_bytes", "production_completeness",
        ].map(quote))),
        ("event", quote("proof_verified")),
        ("proof_kind", quote("evidence_document")),
        // Keep the document claim membership-only. Inclusion is an additional
        // predicate, never grounds to relabel the production as complete.
        ("scope", quote(disclosure.scope)),
        ("scopes", object([
            ("entry", quote(entry.scope)), ("disclosure", quote(disclosure.scope)),
        ])),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<OsString> {
        ["document", "--proof", "absent-proof", "--document-commit", "absent-anchor"]
            .into_iter().chain(extra.iter().copied()).map(OsString::from).collect()
    }

    #[test]
    fn recipient_indexes_are_exact_bounded_and_never_sorted_or_deduplicated() {
        let valid = indexes("0,4,18446744073709551615")
            .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(valid, vec![0, 4, u64::MAX]);
        for value in ["", ",", "0,", ",0", "0,,1", "1,0", "0,0", "-1", "+1",
            "0, 1", "0x10", "18446744073709551616", "1.0", "０"]
        {
            assert!(indexes(value).is_err(), "{value}");
        }
        let maximum = (0..MAX_DISCLOSURE_CHUNKS).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(indexes(&maximum).unwrap_or_else(|e| panic!("{}", e.message)).len(), MAX_DISCLOSURE_CHUNKS);
        assert!(indexes(&format!("{maximum},{MAX_DISCLOSURE_CHUNKS}")).is_err());
    }

    #[test]
    fn missing_duplicate_and_foreign_options_refuse_before_any_file_observation() {
        let valid = parse(&args(&["--chunks", "0,4", "--json"]))
            .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(valid.indexes, vec![0, 4]);
        for extra in [
            vec![], vec!["--chunks"], vec!["--chunks", "1,0"],
            vec!["--chunks", "0", "--chunks", "0"],
            vec!["--chunks", "0", "--proof", "another"],
            vec!["--chunks", "0", "--document-commit", "another"],
            vec!["--chunks", "0", "--json", "--json"],
            vec!["--chunks", "0", "--checkpoint", "checkpoint"],
            vec!["--chunks", "0", "--expect-account", "0"],
        ] {
            let error = run(&args(&extra), true).err().expect("usage refusal");
            assert_eq!(error.exit, 2, "{:?}: {}", extra, error.message);
        }
    }

    fn journal_args() -> Vec<OsString> {
        ["document", "--proof", "absent-disclosure", "--chunks", "0,4",
            "--entry-proof", "absent-entry", "--checkpoint", "absent-checkpoint",
            "--expect-entry", &"ab".repeat(32), "--expect-document", &"CD".repeat(32),
            "--expect-role", "3", "--json"]
            .into_iter().map(OsString::from).collect()
    }

    #[test]
    fn journal_mode_requires_every_independently_supplied_anchor_and_question() {
        let args = journal_args();
        let parsed = parse(&args).unwrap_or_else(|e| panic!("{}", e.message));
        let Anchor::Entry { expected, .. } = parsed.anchor else { panic!("journal mode") };
        assert_eq!(expected.entry_digest, [0xab; 32]);
        assert_eq!(expected.document_oid, [0xcd; 32]);
        assert_eq!(expected.role, 3);
        assert_eq!(parsed.indexes, [0, 4]);
        for index in (1..15).step_by(2) {
            let mut missing = args.clone();
            drop(missing.drain(index..index + 2));
            assert_eq!(run(&missing, true).err().expect("usage").exit, 2);
            let mut duplicate = args.clone();
            duplicate.extend_from_slice(&args[index..index + 2]);
            assert_eq!(run(&duplicate, true).err().expect("usage").exit, 2);
        }
        let mut mixed = args;
        mixed.extend([OsString::from("--document-commit"), OsString::from("absent-anchor")]);
        assert_eq!(run(&mixed, true).err().expect("mixed trust modes").exit, 2);
    }

    #[test]
    fn malformed_recipient_digests_and_roles_are_usage_errors_before_io() {
        for index in [10, 12] {
            for value in ["", "aa", &"g".repeat(64), &"é".repeat(32), &format!("0x{}", "aa".repeat(32))] {
                let mut args = journal_args();
                args[index] = OsString::from(value);
                assert_eq!(run(&args, true).err().expect("invalid digest").exit, 2);
            }
        }
        for value in ["", "+1", "-1", "1.0", " 1", "256", "65535", "１"] {
            let mut args = journal_args();
            args[14] = OsString::from(value);
            assert_eq!(run(&args, true).err().expect("invalid role").exit, 2);
        }
        for value in ["0", "255"] {
            assert!(role(&OsString::from(value)).is_ok());
        }
    }

    #[test]
    fn view_mode_requires_one_artifact_and_journal_authority_before_io() {
        let mut args = journal_args();
        args[1] = "--view".into();
        assert_eq!(parse(&args).unwrap_or_else(|e| panic!("{}", e.message)).kind, DisclosureKind::View);
        for extra in [vec!["--proof", "other"], vec!["--view", "other"],
            vec!["--document-commit", "other"]]
        {
            let mut invalid = args.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert_eq!(run(&invalid, true).err().expect("usage before missing files").exit, 2);
        }
        let direct = ["document", "--view", "absent", "--document-commit", "absent", "--chunks", "0"]
            .map(OsString::from);
        assert_eq!(run(&direct, true).err().expect("no anchor fallback").exit, 2);
    }

    #[test]
    fn view_request_bounds_do_not_weaken_sparse_compact_requests() {
        let mut args = journal_args();
        args[1] = "--view".into();
        args[4] = "16383".into();
        assert!(parse(&args).is_ok());
        for value in ["16384", "18446744073709551615"] {
            args[4] = value.into();
            assert_eq!(run(&args, true).err().expect("view usage bound").exit, 2);
            args[1] = "--proof".into();
            assert!(parse(&args).is_ok(), "compact sparse index {value}");
            args[1] = "--view".into();
        }
    }

}