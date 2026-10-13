//! Air-gapped verification of the existing raw accumulator proof formats.
//!
//! The checkpoint is a separate operator-trusted input, never extracted
//! from the untrusted proof. Neither raw checkpoint format carries a
//! signature. A consistency proof's next checkpoint is only a claim; that
//! proof authenticates tree extension, not the claimed sequence boundary.

#![forbid(unsafe_code)]

mod balance_args;

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fa_verify::blake3::hex;
use fa_verify::{
    BalanceExpectation, Checkpoint, RecordCheck, VerifyError, verify_balance, verify_balance_for,
    verify_consistency, verify_inclusion, verify_prefix,
};

/// A process-level allocation/input bound, independent of each format's
/// narrower field bounds. Larger exports must be checked by an embedding
/// with its own explicit resource policy; this executable refuses them.
const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;

const HELP: &str = "fa-verify — independent verification of raw accounting proofs

Usage:
  fa-verify inclusion --proof FILE --checkpoint TRUSTED_FILE [--json]
  fa-verify prefix --proof FILE --checkpoint TRUSTED_FILE [--json]
  fa-verify balance --proof FILE --checkpoint TRUSTED_FILE [--json]
  fa-verify consistency --proof FILE --checkpoint TRUSTED_FILE --next-checkpoint CLAIMED_FILE [--json]

All inputs are raw canonical bytes, not hex text or a bundle. A checkpoint
is exactly 80 bytes. Obtain and trust --checkpoint independently of the
proof. It is unsigned here: signatures and origin authenticity are not
checked. --next-checkpoint is the claimed extension, not a trusted anchor.
Inclusion proofs may already contain their record; output says whether
its payload was recomputed. Prefix proofs check envelopes, not payloads.
Balance proofs check posted amounts in one account/unit from inception,
with an optional inclusive civil-day cutoff carried in the proof.

To require a balance proof to answer YOUR independently chosen question:
  --expect-account HEX32 --expect-unit U32 --expect-through DAY|none
All three are required together. DAY is the signed i32 civil-day number
reported as effective_through_day; none explicitly means no cutoff, never
any cutoff. Optional --expect-debits I128 --expect-credits I128 must appear
together and are exact nonnegative gross mantissas, not decimal amounts.
A valid proof for a different scope or amount fails with exit 8. Without
these options only the proof's own claim is verified. Never copy expected
values from the untrusted proof or its packaging.

Proof files are limited to 64 MiB. No book, keys, or network are required.
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
        Kind::Prefix => {
            let verified = verify_prefix(&proof, &checkpoint)?;
            report.scope = verified.scope;
            report
                .checks
                .extend(["complete_prefix", "journal_order", "recorded_coordinates"]);
            report.data = object([
                ("envelopes", verified.envelopes.len().to_string()),
                ("record_check", quote("not_supplied")),
            ]);
            report.detail = format!(
                "all {} leaf envelopes in journal order; payloads were not recomputed",
                verified.envelopes.len()
            );
        }
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
            report.scope = verified.scope;
            report.checks.extend([
                "complete_prefix",
                "exact_contributing_record_set",
                "record_recomputation",
                "posted_balance_recomputation",
            ]);
            report.data = object([
                ("account", quote(&format!("{:032x}", claim.account))),
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
                ("unit", claim.unit.to_string()),
            ]);
            report.detail = format!(
                "account {:032x}, unit {}: posted debits {}, credits {} (exact mantissas); {} contributing leaves; inclusive cutoff day {:?}",
                claim.account,
                claim.unit,
                claim.debits,
                claim.credits,
                verified.contributing.len(),
                claim.effective_through
            );
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
    match parse(&args).and_then(|request| verify(&request)) {
        Ok(report) => {
            let text = if json { report.json() } else { report.human() };
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
