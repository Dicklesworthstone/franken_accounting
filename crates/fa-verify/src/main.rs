//! Air-gapped verification of the existing raw accumulator proof formats.
//!
//! The checkpoint is a separate operator-trusted input, never extracted
//! from the untrusted proof. Neither raw checkpoint format carries a
//! signature. A consistency proof's next checkpoint is only a claim; that
//! proof authenticates tree extension, not the claimed sequence boundary.

#![forbid(unsafe_code)]

mod balance_args;
mod document_args;
mod evidence_args;
mod prefix_report;

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fa_verify::blake3::hex;
use fa_verify::{
    BalanceExpectation, Checkpoint, RecordCheck, VerifyError, verify_balance, verify_balance_for,
    verify_consistency, verify_inclusion,
};

/// A process-level allocation/input bound, independent of each format's
/// narrower field bounds. Larger exports must be checked by an embedding
/// with its own explicit resource policy; this executable refuses them.
const MAX_PROOF_BYTES: usize = fa_verify::migration_balance::MAX_BALANCE_PROOF_BYTES;

const HELP: &str = "fa-verify — independent verification of raw accounting proofs

Usage:
  fa-verify inclusion --proof FILE --checkpoint TRUSTED_FILE [--json]
  fa-verify prefix --proof FILE --checkpoint TRUSTED_FILE [--json]
  fa-verify balance --proof FILE --checkpoint TRUSTED_FILE [--json]
  fa-verify consistency --proof FILE --checkpoint TRUSTED_FILE --next-checkpoint CLAIMED_FILE [--json]
  fa-verify redacted-view --view FILE --document-commit HEX64 --expect-chunks I,J [--json]
  fa-verify document --proof FILE --document-commit TRUSTED_FILE --chunks 0,4 [--json]

Evidence citation inventories (complete for one requested entry only):
  fa-verify evidence --proof FILE --checkpoint TRUSTED_FILE --expect-entry HEX64 [--json]
  fa-verify evidence --help

All inputs are raw canonical bytes, not hex text or a bundle. A checkpoint
is exactly 80 bytes. Obtain and trust --checkpoint independently of the
proof. It is unsigned here: signatures and origin authenticity are not
checked. --next-checkpoint is the claimed extension, not a trusted anchor.
Inclusion proofs may already contain their record; output says whether
its payload was recomputed. Prefix v1 checks envelope membership only.
Prefix v2 (fa proof prefix --with-record) checks every entry payload and
rebuilds its selectors. Output distinguishes record_check and scope_derivation.
Prefixes do not assert posted balances, accounting validity or document bytes.
Balance v3 checks every prefix entry payload before selecting posted amounts
in one account/unit, with an optional inclusive civil-day cutoff. It discloses
all prefix entry payloads, not just entries for the requested account.
Partial legacy v1/v2 balances report membership_only: selected sums are checked,
but account balance completeness is not established. Check balance_complete.

To require a balance proof to answer YOUR independently chosen question:
  --expect-account HEX32 --expect-unit U32 --expect-through DAY|none
All three are required together. DAY is the signed i32 civil-day number
reported as effective_through_day; none explicitly means no cutoff, never
any cutoff. Optional --expect-debits I128 --expect-credits I128 must appear
together and are exact nonnegative gross mantissas, not decimal amounts.
These options require complete recomputation: partial legacy proofs fail
with exit 8 even when their scope and amounts match. A complete proof for a
different scope or amount also fails. Without these options inspect scope
and balance_complete; membership_only is not a verified account balance.
Never copy expected values from the untrusted proof or its packaging.

Compact document disclosures use the portable fa:document-disclosure:v1
format with the document command. Its --document-commit is a FILE containing
exactly 32 raw doc_commit bytes, not hex text or an 80-byte checkpoint.
Obtain this commitment independently. --chunks is the recipient's nonempty,
strictly increasing comma-separated decimal request (at most 16384 indexes),
never inferred from the proof. Whole chunks only; no partial redactions.
Output is membership_only and never echoes disclosed document content.

Accumulator and compact proof files are limited to 64 MiB. For kernel RedactedView v1
inputs, run fa-verify redacted-view --help. That command uses a document
commitment, not a checkpoint, and a framing-aware view size bound.
No book, keys, or network are required.
Exit codes: 0 verified/help; 2 usage; 5 file/output I/O; 8 verification failed.";

#[derive(Clone, Copy)]
enum Kind {
    Inclusion,
    Consistency,
    Prefix,
    Balance,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Inclusion => "inclusion",
            Self::Consistency => "consistency",
            Self::Prefix => "prefix",
            Self::Balance => "balance",
        }
    }
}

struct Request {
    kind: Kind,
    proof: PathBuf,
    checkpoint: PathBuf,
    next_checkpoint: Option<PathBuf>,
    expectation: Option<BalanceExpectation>,
}

struct Failure {
    exit: u8,
    class: &'static str,
    message: String,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            exit: 2,
            class: "usage",
            message: message.into(),
        }
    }

    fn io(message: impl Into<String>) -> Self {
        Self {
            exit: 5,
            class: "foundation",
            message: message.into(),
        }
    }

    fn verification(message: impl Into<String>) -> Self {
        Self {
            exit: 8,
            class: "verification",
            message: message.into(),
        }
    }

    fn json(&self) -> String {
        object([
            ("class", quote(self.class)),
            ("event", quote("error")),
            ("exit", self.exit.to_string()),
            ("message", quote(&self.message)),
            ("refusal_id", "null".into()),
            ("v", "1".into()),
            ("verified", "false".into()),
        ])
    }
}

impl From<VerifyError> for Failure {
    fn from(error: VerifyError) -> Self {
        Self::verification(error.to_string())
    }
}

/// Validate the entire invocation before opening any input. Paths are
/// OsStrings so a legitimate non-UTF-8 filename remains usable.
fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let kind = match args.first().and_then(|arg| arg.to_str()) {
        Some("inclusion") => Kind::Inclusion,
        Some("consistency") => Kind::Consistency,
        Some("prefix") => Kind::Prefix,
        Some("balance") => Kind::Balance,
        _ => {
            return Err(Failure::usage(
                "choose inclusion, consistency, prefix, or balance; run fa-verify --help",
            ));
        }
    };
    let (mut proof, mut checkpoint, mut next_checkpoint) = (None, None, None);
    let mut balance = balance_args::BalanceArgs::default();
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
        if balance.consume(args, index)? {
            index += 2;
            continue;
        }
        let (name, slot) = match argument.to_str() {
            Some("--proof") => ("--proof", &mut proof),
            Some("--checkpoint") => ("--checkpoint", &mut checkpoint),
            Some("--next-checkpoint") => ("--next-checkpoint", &mut next_checkpoint),
            _ => {
                return Err(Failure::usage(format!(
                    "unknown argument {:?}; run fa-verify --help",
                    argument
                )));
            }
        };
        if slot.is_some() {
            return Err(Failure::usage(format!("{name} may be supplied only once")));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a raw canonical input file")))?;
        if value.is_empty() || value.to_str().is_some_and(|path| path.starts_with("--")) {
            return Err(Failure::usage(format!(
                "{name} requires a file path; use ./ for a filename beginning with --"
            )));
        }
        *slot = Some(PathBuf::from(value));
        index += 2;
    }
    let proof = proof.ok_or_else(|| Failure::usage("--proof is required"))?;
    let checkpoint = checkpoint.ok_or_else(|| {
        Failure::usage("--checkpoint is required; a proof cannot supply its own trusted anchor")
    })?;
    match (kind, next_checkpoint.is_some()) {
        (Kind::Consistency, false) => {
            return Err(Failure::usage(
                "consistency requires --next-checkpoint naming the claimed extension",
            ));
        }
        (Kind::Inclusion | Kind::Prefix | Kind::Balance, true) => {
            return Err(Failure::usage(
                "--next-checkpoint is admitted only for consistency",
            ));
        }
        _ => {}
    }
    Ok(Request {
        kind,
        proof,
        checkpoint,
        next_checkpoint,
        expectation: balance.finish(matches!(kind, Kind::Balance))?,
    })
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, Failure> {
    let file =
        File::open(path).map_err(|error| Failure::io(format!("{}: {error}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|error| Failure::io(format!("{}: {error}", path.display())))?;
    if metadata.len() > maximum as u64 {
        return Err(Failure::verification(format!(
            "{}: input exceeds the {maximum}-byte bound",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::io(format!("{}: {error}", path.display())))?;
    // The second bound also covers a file growing after metadata was read.
    if bytes.len() > maximum {
        return Err(Failure::verification(format!(
            "{}: input exceeds the {maximum}-byte bound",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_checkpoint(path: &Path) -> Result<Checkpoint, Failure> {
    let bytes = read_bounded(path, Checkpoint::ENCODED_LEN)?;
    Checkpoint::decode(&bytes)
        .map_err(|error| Failure::verification(format!("{}: {error}", path.display())))
}

struct Report {
    kind: Kind,
    checkpoint: Checkpoint,
    scope: &'static str,
    checks: Vec<&'static str>,
    data: String,
    detail: String,
}

fn verify(request: &Request) -> Result<Report, Failure> {
    let checkpoint = read_checkpoint(&request.checkpoint)?;
    let next = request
        .next_checkpoint
        .as_deref()
        .map(read_checkpoint)
        .transpose()?;
    let proof = read_bounded(&request.proof, MAX_PROOF_BYTES)?;
    let mut report = Report {
        kind: request.kind,
        checkpoint,
        scope: "",
        checks: vec!["trusted_checkpoint_matches"],
        data: String::new(),
        detail: String::new(),
    };
    match request.kind {
        Kind::Inclusion => {
            let verified = verify_inclusion(&proof, &checkpoint)?;
            let record = match verified.record {
                RecordCheck::NotSupplied => "not_supplied",
                RecordCheck::Recomputed => {
                    report.checks.push("record_recomputation");
                    "recomputed"
                }
            };
            report.scope = verified.scope;
            report
                .checks
                .extend(["leaf_inclusion", "recorded_coordinate"]);
            report.data = object([
                ("class", verified.envelope.class.to_string()),
                ("leaf_index", verified.leaf_index.to_string()),
                ("record_check", quote(record)),
                (
                    "record_digest",
                    quote(&hex(&verified.envelope.record_digest)),
                ),
                ("recorded_at", verified.envelope.commit_seq.to_string()),
            ]);
            report.detail = format!(
                "leaf {} at sequence {}; record {record}",
                verified.leaf_index, verified.envelope.commit_seq
            );
        }
        Kind::Consistency => {
            let claimed =
                next.ok_or_else(|| Failure::usage("consistency requires --next-checkpoint"))?;
            let verified = verify_consistency(&proof, &checkpoint, &claimed)?;
            report.scope = verified.scope;
            report
                .checks
                .extend(["claimed_checkpoint_matches", "tree_extension"]);
            report.data = object([
                ("claimed_checkpoint", checkpoint_json(&verified.extended)),
                (
                    "claimed_sequence_boundary",
                    quote("not_verified_by_consistency"),
                ),
            ]);
            report.detail = format!(
                "{} leaves extend {} leaves; next checkpoint is a producer claim, not another trusted anchor; its sequence boundary is not authenticated by this proof",
                verified.extended.leaf_count, checkpoint.leaf_count
            );
        }
        Kind::Prefix => prefix_report::verify(&proof, &checkpoint, &mut report)?,
        Kind::Balance => {
            let verified = match &request.expectation {
                Some(expected) => verify_balance_for(&proof, &checkpoint, expected)
                    .map_err(|error| Failure::verification(error.to_string()))?,
                None => verify_balance(&proof, &checkpoint)?,
            };
            if let Some(expected) = &request.expectation {
                report.checks.push("requested_balance_scope");
                if expected.amounts.is_some() {
                    report.checks.push("requested_balance_amounts");
                }
            }
            let claim = verified.claim;
            let complete = verified.scope == fa_verify::balance::SCOPE_RECOMPUTATION;
            report.scope = verified.scope;
            report.checks.push("complete_prefix");
            if complete {
                report.checks.extend([
                    "exact_contributing_record_set",
                    "record_recomputation",
                    "scope_derivation",
                    "posted_balance_recomputation",
                ]);
            } else {
                report.checks.extend([
                    "selected_record_recomputation",
                    "selected_amount_recomputation",
                ]);
            }
            report.data = object([
                ("account", quote(&format!("{:032x}", claim.account))),
                ("balance_complete", complete.to_string()),
                (
                    "contributing_leaves",
                    verified.contributing.len().to_string(),
                ),
                ("credits_mantissa", quote(&claim.credits.to_string())),
                ("debits_mantissa", quote(&claim.debits.to_string())),
                (
                    "effective_through_day",
                    claim
                        .effective_through
                        .map_or_else(|| "null".into(), |day| day.to_string()),
                ),
                (
                    "scope_derivation",
                    quote(if complete { "all_prefix_payloads_checked" } else { "not_verified" }),
                ),
                ("unit", claim.unit.to_string()),
            ]);
            let amount_kind = if complete { "posted" } else { "selected-payload" };
            report.detail = format!(
                "account {:032x}, unit {}: {amount_kind} debits {}, credits {} (exact mantissas); {} contributing leaves; inclusive cutoff day {:?}",
                claim.account,
                claim.unit,
                claim.debits,
                claim.credits,
                verified.contributing.len(),
                claim.effective_through
            );
            if !complete {
                report.detail.push_str(
                    "; account balance completeness NOT proven; omitted payloads leave scope selectors unverified",
                );
            }
            report.detail.push_str(match request.expectation {
                Some(BalanceExpectation { amounts: Some(_), .. }) =>
                    "; recipient scope and exact gross amounts matched",
                Some(_) => "; recipient scope matched; amounts learned from the verified proof",
                None => "; no independently specified balance request was checked",
            });
        }
    }
    Ok(report)
}

fn checkpoint_json(checkpoint: &Checkpoint) -> String {
    object([
        ("book_id", quote(&hex(&checkpoint.book_id))),
        ("branch_id", quote(&hex(&checkpoint.branch_id))),
        ("leaf_count", checkpoint.leaf_count.to_string()),
        ("root", quote(&hex(&checkpoint.root))),
        ("through_seq", checkpoint.through_seq.to_string()),
    ])
}

impl Report {
    fn json(&self) -> String {
        object([
            (
                "anchor",
                object([
                    ("format", quote("unsigned_raw_checkpoint")),
                    ("signature_verification", quote("not_performed")),
                    ("source", quote("operator_trusted_checkpoint")),
                ]),
            ),
            ("checkpoint", checkpoint_json(&self.checkpoint)),
            (
                "checks",
                array(
                    self.checks
                        .iter()
                        .map(|name| object([("name", quote(name)), ("status", quote("pass"))])),
                ),
            ),
            ("data", self.data.clone()),
            ("event", quote("proof_verified")),
            ("proof_kind", quote(self.kind.name())),
            ("scope", quote(self.scope)),
            ("v", "1".into()),
            ("verified", "true".into()),
        ])
    }

    fn human(&self) -> String {
        format!(
            "Verified {} (scope: {}): {}.\nTrusted checkpoint: {}.\nAnchor: operator-trusted unsigned checkpoint; signatures and origin authenticity were not checked.",
            self.kind.name(),
            self.scope,
            self.detail,
            self.checkpoint
        )
    }
}

/// Minimal JSON rendering for this binary's closed output schema. Amounts
/// are strings of exact mantissas; no JSON parser, float, or dependency is
/// introduced into the independent verifier.
fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                out.push_str("\\u00");
                let value = c as usize;
                out.push(char::from(b"0123456789abcdef"[value >> 4]));
                out.push(char::from(b"0123456789abcdef"[value & 15]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn object(fields: impl IntoIterator<Item = (&'static str, String)>) -> String {
    format!(
        "{{{}}}",
        fields
            .into_iter()
            .map(|(key, value)| format!("{}:{value}", quote(key)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}

fn output(text: &str) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    writeln!(lock, "{text}")?;
    lock.flush()
}

fn diagnostic(text: &str) {
    let _ = writeln!(std::io::stderr().lock(), "fa-verify: {text}");
}

// The offline view command has a document anchor, not a journal checkpoint.
// Keep its request and report separate so it cannot inherit checkpoint claims.
mod redacted_view_cli {
    use super::{Failure, OsString, PathBuf, array, hex, object, quote, read_bounded};
    use fa_verify::document::DOC_CHUNK_BYTES;
    use fa_verify::redaction::{MAX_VIEW_BYTES, MAX_VIEW_CHUNKS, verify_view_for};

    const HELP: &str = "Usage:
  fa-verify redacted-view --view FILE --document-commit HEX64 --expect-chunks 0,2 [--json]

FILE contains the kernel's raw canonical RedactedView v1 bytes, not a bundle
or the compact document-disclosure format. HEX64 is the independently
trusted public document commitment. Obtain it separately from the view.
--expect-chunks is the exact nonempty, ascending list of zero-based chunk
indices expected by the recipient; duplicates and extra disclosures fail.
Do not copy the commitment or expected indices from the untrusted view.

Scope is membership_only. Contract and original-locator metadata are not
authenticated by the document commitment. Signatures, authorization,
redaction policy, provenance and journal inclusion are not checked. The
report prints verified offsets and lengths, NEVER document payload bytes.
Documents are limited to 64 MiB; the view bound also includes wire framing.
Exit codes: 0 verified/help; 2 usage; 5 file/output I/O; 8 verification failed.";

    struct ViewRequest {
        path: PathBuf,
        commitment: [u8; 32],
        indexes: Vec<u64>,
    }

    fn commitment(text: &str) -> Result<[u8; 32], Failure> {
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Failure::usage("--document-commit requires exactly 64 hexadecimal digits"));
        }
        let mut digest = [0u8; 32];
        for (index, slot) in digest.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .map_err(|_| Failure::usage("invalid hexadecimal document commitment"))?;
        }
        Ok(digest)
    }

    fn indexes(text: &str) -> Result<Vec<u64>, Failure> {
        // At most five decimal digits per supported index and one comma.
        // Bound text before collecting; do not silently sort or deduplicate.
        if text.is_empty() || text.len() > MAX_VIEW_CHUNKS * 6 {
            return Err(Failure::usage("--expect-chunks requires a bounded nonempty index list"));
        }
        let mut result = Vec::new();
        for field in text.split(',') {
            if result.len() == MAX_VIEW_CHUNKS
                || field.is_empty()
                || field.len() > 5
                || !field.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Failure::usage("--expect-chunks requires comma-separated decimal indices"));
            }
            let index = field.parse::<u64>()
                .map_err(|_| Failure::usage("invalid disclosure index"))?;
            if index >= MAX_VIEW_CHUNKS as u64 {
                return Err(Failure::usage("disclosure index exceeds the supported document bound"));
            }
            if result.last().is_some_and(|previous| *previous >= index) {
                return Err(Failure::usage("disclosure indices must be strictly ascending without duplicates"));
            }
            result.push(index);
        }
        Ok(result)
    }

    // Consume every argument, including unsupported/duplicate flags, before
    // opening a file. Only the file path may contain non-UTF-8 bytes.
    fn parse(args: &[OsString]) -> Result<ViewRequest, Failure> {
        let (mut path, mut anchor, mut requested) = (None, None, None);
        let mut json = false;
        let mut index = 0;
        while let Some(arg) = args.get(index) {
            if arg == "--json" {
                if json {
                    return Err(Failure::usage("--json may be supplied only once"));
                }
                json = true;
                index += 1;
                continue;
            }
            let (name, slot) = match arg.to_str() {
                Some("--view") => ("--view", &mut path),
                Some("--document-commit") => ("--document-commit", &mut anchor),
                Some("--expect-chunks") => ("--expect-chunks", &mut requested),
                _ => return Err(Failure::usage("redacted-view accepts only --view, --document-commit, --expect-chunks and --json")),
            };
            if slot.is_some() {
                return Err(Failure::usage(format!("{name} may be supplied only once")));
            }
            let value = args.get(index + 1)
                .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
            if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
                return Err(Failure::usage(format!("{name} requires a value; use ./ for a path beginning with --")));
            }
            *slot = Some(value);
            index += 2;
        }
        let path = path.ok_or_else(|| Failure::usage("--view is required"))?;
        let anchor = anchor.ok_or_else(|| Failure::usage("--document-commit is required independently of the view"))?;
        let requested = requested.ok_or_else(|| Failure::usage("--expect-chunks is required independently of the view"))?;
        Ok(ViewRequest {
            path: PathBuf::from(path),
            commitment: commitment(anchor.to_str().ok_or_else(|| Failure::usage("document commitment must be ASCII hex"))?)?,
            indexes: indexes(requested.to_str().ok_or_else(|| Failure::usage("disclosure indices must be ASCII decimal"))?)?,
        })
    }

    fn check(request: &ViewRequest, bytes: &[u8], json: bool) -> Result<String, Failure> {
        let report = verify_view_for(bytes, &request.commitment, &request.indexes)
            .map_err(|error| Failure::verification(error.to_string()))?;
        if !json {
            return Ok(format!(
                "Verified redacted-view (scope: {}): {} requested chunks belong to document {} (kind {}, {} bytes); {} chunks withheld.\nView digest (computed, not independently authenticated): {}.\nOriginal locator and contract are unverified metadata. Authorization, redaction policy, provenance, signatures, journal inclusion and production completeness were not checked. No document bytes are printed.",
                report.scope, report.disclosed.len(), hex(&report.doc_commit), report.kind,
                report.size, report.withheld_chunks, hex(&report.view_commit)
            ));
        }
        Ok(object([
            ("anchor", object([
                ("source", quote("operator_trusted_document_commitment")),
                ("doc_commit", quote(&hex(&report.doc_commit))),
                ("signature_verification", quote("not_performed")),
            ])),
            ("checks", array([
                "document_commitment", "canonical_view_shape",
                "requested_disclosure_set", "disclosed_chunk_membership",
            ].into_iter().map(|name| object([
                ("name", quote(name)), ("status", quote("pass")),
            ])))),
            ("data", object([
                ("document_kind", report.kind.to_string()),
                ("document_length", report.size.to_string()),
                ("disclosed_chunks", array(report.disclosed.iter().map(|chunk| object([
                    ("index", chunk.index.to_string()),
                    ("offset", (chunk.index * DOC_CHUNK_BYTES as u64).to_string()),
                    ("length", chunk.bytes.len().to_string()),
                ])))),
                ("withheld_chunks", report.withheld_chunks.to_string()),
                ("view_commit", quote(&hex(&report.view_commit))),
                ("view_commit_status", quote("computed_not_authenticated")),
            ])),
            ("unverified_metadata", object([
                ("original_oid", quote(&hex(&report.unverified_metadata.original))),
                ("contract", report.unverified_metadata.contract.to_string()),
                ("status", quote("not_authenticated_by_document_commitment")),
            ])),
            ("not_checked", array([
                "authorization", "redaction_policy", "provenance",
                "journal_inclusion", "production_completeness",
            ].into_iter().map(quote))),
            ("event", quote("proof_verified")),
            ("proof_kind", quote("redacted_view")),
            ("scope", quote(report.scope)),
            ("v", "1".into()),
            ("verified", "true".into()),
        ]))
    }

    pub(super) fn run(args: &[OsString], json: bool) -> Result<String, Failure> {
        if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h" | "help")) {
            return Ok(HELP.into());
        }
        let request = parse(args)?;
        let bytes = read_bounded(&request.path, MAX_VIEW_BYTES)?;
        check(&request, &bytes, json)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(anchor: &str, requested: &str) -> Vec<OsString> {
            ["--view", "not-opened.view", "--document-commit", anchor,
                "--expect-chunks", requested, "--json"]
                .into_iter().map(OsString::from).collect()
        }

        fn request() -> ViewRequest {
            parse(&args(&"ab".repeat(32), "0,2"))
                .unwrap_or_else(|failure| panic!("{}", failure.message))
        }

        #[test]
        fn requests_are_strict_and_document_scoped_before_io() {
            let valid = request();
            assert_eq!(valid.commitment, [0xab; 32]);
            assert_eq!(valid.indexes, [0, 2]);
            assert_eq!(commitment(&"AB".repeat(32)).ok(), Some([0xab; 32]));
            for text in ["", "0,", ",0", "0,0", "2,0", "+1", "-1", "1.0", "0, 2", "16384", "18446744073709551615"] {
                assert!(parse(&args(&"ab".repeat(32), text)).is_err(), "{text}");
            }
            for anchor in ["", "ab", &"g".repeat(64), &"é".repeat(32)] {
                assert!(parse(&args(anchor, "0")).is_err());
            }
            assert!(indexes(&"0,".repeat(MAX_VIEW_CHUNKS + 1)).is_err());
        }

        #[test]
        fn unknown_repeated_missing_and_checkpoint_arguments_are_refused() {
            let base = args(&"ab".repeat(32), "0");
            for extra in [
                vec!["--json"], vec!["--view", "another"],
                vec!["--document-commit", "aa"], vec!["--expect-chunks", "1"],
                vec!["--checkpoint", "unrelated"], vec!["--expect-account", "0"],
            ] {
                let mut bad = base.clone();
                bad.extend(extra.into_iter().map(OsString::from));
                let failure = parse(&bad).err().expect("invalid invocation");
                assert_eq!(failure.exit, 2);
            }
            for end in 0..6 {
                assert!(parse(&base[..end]).is_err());
            }
        }

        fn view(doc: &[u8]) -> (Vec<u8>, [u8; 32]) {
            let anchor = fa_verify::document::doc_commit(1, doc);
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(&[17; 32]);
            bytes.extend_from_slice(&7u16.to_le_bytes());
            bytes.push(1);
            bytes.extend_from_slice(&(doc.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&anchor);
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&(doc.len() as u32).to_le_bytes());
            bytes.extend_from_slice(doc);
            (bytes, anchor)
        }

        #[test]
        fn reports_keep_claim_boundaries_and_never_emit_payload_bytes() {
            let secret = b"disclosed evidence not for stdout";
            let (bytes, anchor) = view(secret);
            let request = ViewRequest {
                path: PathBuf::from("unused"), commitment: anchor, indexes: vec![0],
            };
            let json = check(&request, &bytes, true)
                .unwrap_or_else(|failure| panic!("{}", failure.message));
            for field in ["\"scope\":\"membership_only\"", "\"verified\":true",
                "operator_trusted_document_commitment", "unverified_metadata",
                "not_authenticated_by_document_commitment", "computed_not_authenticated"] {
                assert!(json.contains(field), "{json}");
            }
            assert!(!json.contains("operator_trusted_checkpoint"));
            assert!(!json.contains(std::str::from_utf8(secret).unwrap()));
            let secret_hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
            assert!(!json.contains(&secret_hex));
            assert!(!json.contains('\n'));
            let human = check(&request, &bytes, false)
                .unwrap_or_else(|failure| panic!("{}", failure.message));
            assert!(human.contains("unverified metadata"));
            assert!(!human.contains(std::str::from_utf8(secret).unwrap()));
            let mut corrupt = bytes.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            let failure = check(&request, &corrupt, true).err().expect("tamper rejected");
            assert_eq!(failure.exit, 8);
            assert!(failure.json().contains("\"verified\":false"));
            assert!(!failure.json().contains("proof_verified"));
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h" | "help")) {
        return match output(HELP) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                diagnostic(&error.to_string());
                ExitCode::from(5)
            }
        };
    }
    let json = args.iter().any(|argument| argument == "--json");
    let result = if args.first().and_then(|arg| arg.to_str()) == Some("redacted-view") {
        redacted_view_cli::run(&args[1..], json)
    } else if args.first().and_then(|arg| arg.to_str()) == Some("document") {
        document_args::run(&args, json)
    } else if args.first().and_then(|arg| arg.to_str()) == Some("evidence") {
        evidence_args::run(&args, json)
    } else {
        parse(&args).and_then(|request| verify(&request)).map(|report| {
            if json { report.json() } else { report.human() }
        })
    };
    match result {
        Ok(text) => {
            match output(&text) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    diagnostic(&error.to_string());
                    ExitCode::from(5)
                }
            }
        }
        Err(failure) => {
            if json && let Err(error) = output(&failure.json()) {
                diagnostic(&format!("{}; output: {error}", failure.message));
                return ExitCode::from(5);
            }
            diagnostic(&failure.message);
            ExitCode::from(failure.exit)
        }
    }
}
