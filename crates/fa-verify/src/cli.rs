//! The `fa-verify` command line (plan §13.3: "it ships as a static binary
//! and as a library … its output is a verification report with every
//! check's result and scope label").
//!
//! ```text
//! fa-verify <command> <file> [options] [--json] [--hex]
//!
//!   state        <state>                         an AccumulatorState's bytes on their own
//!   checkpoint   <checkpoint> --key K...         a TransparencyCheckpoint signed by a trusted key
//!   inclusion    <proof> --checkpoint C ANCHOR   an entry recorded within the checkpoint's prefix
//!   prefix       <proof> --checkpoint C ANCHOR   the complete prefix (seq_range_complete)
//!   balance      <proof> --checkpoint C ANCHOR   a posted balance refolded (recomputation)
//!   scope        <proof> --checkpoint C --key K --account A --from D --to D [--prefix P]
//!                                                one account's day interval (scope_index_complete)
//!   consistency  <proof> --trusted C --claimed C ANCHOR
//!                                                the claimed checkpoint extends the trusted one
//!   doc-commit   <document> --kind N [--expect H]
//!                                                a document's public commitment from its bytes
//!   bundle       <bundle> --key K... [--receipt R]
//!                                                an evidence bundle, every predicate graded
//!   report       <bundle> --key K... [--units N,N,...]
//!                                                a native report; statement units come from the recipient
//! ```
//!
//! `ANCHOR` is how the caller trusts the checkpoint, and there are exactly
//! two ways: `--key K...` (a signed `TransparencyCheckpoint` whose signature
//! by one of the keys verifies first), or `--unsigned-checkpoint` (a raw
//! 80-byte checkpoint statement the caller obtained and trusts out of band;
//! no signature or origin is checked, and the report says so). A proof never
//! supplies its own anchor, and a scope's question (`--account`, `--from`,
//! `--to`) comes from the caller, never from the proof. The proof may be
//! named positionally or with `--proof`; `--checkpoint`/`--next-checkpoint`
//! are accepted for `consistency` as `--trusted`/`--claimed`.
//!
//! Every check is `pass`, `fail`, or `unrun` (a check it rests on did not
//! pass); only `pass` is green.
//!
//! Exit codes: `0` every check passed, `8` a check failed or did not run
//! (the artifact does not verify, or an input exceeds the
//! [`MAX_INPUT_BYTES`] bound), `2` usage (an unknown command or flag, a
//! missing, repeated, inapplicable or malformed argument; every argument is
//! judged before any file is opened), `5` an input file could not be read.
//! Robot mode (`--json`) prints one deterministic JSON object on stdout;
//! otherwise the report is text. A usage or I/O error is also a diagnostic
//! line on stderr. Bare `fa-verify`, `help` and `--help` print the usage and
//! exit `0`.
//!
//! Inputs are the artifacts' raw bytes; `--hex` reads every input file as
//! hexadecimal text instead (whitespace ignored), as the golden fixtures
//! store them.

use crate::ads::{AdsReport, verify_ads};
use crate::blake3::hex;
use crate::bundle::{BundleReport, BundleScope, Grade, verify_bundle};
use crate::checkpoint::{CheckpointError, SignedCheckpoint, verify_checkpoint};
use crate::document::doc_commit;
use crate::envelope::LeafEnvelope;
use crate::proof::{
    Checkpoint, RecordCheck, VerifyError, verify_consistency, verify_inclusion, verify_prefix,
};
use crate::scope::{IndexDerivation, ScopeClaim, verify_scope};
use crate::state::verify_state;
use crate::verify_balance;

/// What a run prints and how it exits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
}

pub const EXIT_VERIFIED: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_IO: i32 = 5;
pub const EXIT_FAILED: i32 = 8;

/// The largest input file this verifier judges (64 MiB). A larger export is
/// refused (exit 8), never read in part; an embedding with its own resource
/// policy can call the library directly.
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// The library grammar's usage text (the `fa-verify` binary appends it to
/// its own `--help`).
pub const USAGE: &str = "\
fa-verify — the dependency-free verifier (FrankenAccounting plan §13.3)

usage: fa-verify <command> <file> [options] [--json] [--hex]

commands:
  state        <state>                          an AccumulatorState's bytes on their own
  checkpoint   <checkpoint> --key K...          a TransparencyCheckpoint signed by a trusted key
               [--witness W... [--quorum N]]    and cosigned by N of the named witnesses (default
                                                all): witnessed detection, never prevention
  inclusion    <proof> --checkpoint C ANCHOR    an entry recorded within the checkpoint's prefix
  prefix       <proof> --checkpoint C ANCHOR    every leaf of the prefix (seq_range_complete)
  balance      <proof> --checkpoint C ANCHOR    a posted balance refolded (recomputation)
  scope        <proof> --checkpoint C --key K --account A --from D --to D [--prefix P]
                                                one account's day interval (scope_index_complete)
  consistency  <proof> --trusted C --claimed C ANCHOR
                                                the claimed checkpoint extends the trusted one
  doc-commit   <document> --kind N [--expect H] a document's public commitment from its bytes
  bundle       <bundle> --key K... [--receipt R]
                                                an evidence bundle (.fab), every predicate graded
  report       <bundle> --key K... [--checkpoint C] [--receipt R] [--expect H]
               [--units N,N,...]               independently recompute native or dimension-filtered
                                                trial balances, statements, open items, balance explanations,
                                                effective-date aging, reconciliation, account roll-forwards or direct cash flows.
                                                V1 statements require --units;
                                                V2 registry bundles require --receipt or trusted --expect
  ads          <dir> --key K... [--receipt R]   an ADS extract (fa export ads --with-proofs): its
                                                bundle graded, then GL_Detail exactly the entries it
                                                proves through the certificate's cutoff,
                                                Trial_Balance exactly their refold and, against a
                                                complete prefix, Chart_of_Accounts its declarations
  saft         <dir> --key K... [--receipt R]   a SAF-T 2.00 extract (fa export saft --with-proofs),
                                                judged as ads: transactions, balance assertions and
                                                accounts, read without the producer's parser

ANCHOR — how you trust the checkpoint (exactly one; a proof never supplies its own):
  --key K...             C is a signed TransparencyCheckpoint; its signature by one of
                         these keys is verified first (scope and bundle require this)
  --unsigned-checkpoint  C is a raw 80-byte checkpoint statement that you obtained and
                         trust independently; no signature or origin is checked here.
                         For consistency the --claimed checkpoint is the producer's claim,
                         not a trusted anchor: its sequence boundary is not authenticated

options:
  --proof P      the proof file (instead of naming it positionally)
  --key K        a trusted Ed25519 public key, 64 hex characters (repeatable)
  --account A    an account vid: decimal, or 0x followed by up to 32 hex characters
  --from D --to D  an inclusive effective-day interval (days since 1970-01-01)
  --receipt R    a bundle's detached production receipt
  --units N,N,...  V1 statements require 1..=4096 strictly ascending unique native unit IDs;
                 obtain the complete list independently. For V1 it is a report premise,
                 not proof of unit registration or labels. For V2 the list is optional;
                 if supplied it must exactly match the authenticated registry closure.
  --json         one JSON report on stdout (robot mode)
  --hex          read every input file as hexadecimal text

Input files are limited to 64 MiB. No book, network or other program is used.
The raw --proof/--checkpoint grammar (operator-trusted 80-byte checkpoints, balance
expectations) and the document and redacted-view commands: fa-verify --help.
exit codes: 0 verified · 2 usage · 5 file I/O · 8 verification failed
";

const COMMANDS: [&str; 12] = [
    "state",
    "checkpoint",
    "inclusion",
    "prefix",
    "balance",
    "scope",
    "consistency",
    "doc-commit",
    "bundle",
    "report",
    "ads",
    "saft",
];

/// Flags that take a value, and the switches.
const VALUE_FLAGS: [&str; 16] = [
    "--key",
    "--witness",
    "--quorum",
    "--proof",
    "--checkpoint",
    "--next-checkpoint",
    "--trusted",
    "--claimed",
    "--account",
    "--from",
    "--to",
    "--prefix",
    "--kind",
    "--expect",
    "--receipt",
    "--units",
];
const SWITCHES: [&str; 3] = ["--json", "--hex", "--unsigned-checkpoint"];

/// The flags each command admits beyond `--json` and `--hex`. Anything else
/// is refused before a file is opened.
fn admitted(command: &str) -> &'static [&'static str] {
    match command {
        "checkpoint" => &["--key", "--witness", "--quorum"],
        "inclusion" | "prefix" | "balance" => {
            &["--proof", "--checkpoint", "--key", "--unsigned-checkpoint"]
        }
        // `--unsigned-checkpoint` is admitted only to be refused with the
        // reason: a scope proof rests on the signed scope-index root.
        "scope" => &[
            "--proof",
            "--checkpoint",
            "--key",
            "--unsigned-checkpoint",
            "--account",
            "--from",
            "--to",
            "--prefix",
        ],
        "consistency" => &[
            "--proof",
            "--trusted",
            "--claimed",
            "--checkpoint",
            "--next-checkpoint",
            "--key",
            "--unsigned-checkpoint",
        ],
        "doc-commit" => &["--kind", "--expect"],
        "bundle" | "ads" | "saft" => &["--key", "--receipt"],
        "report" => &["--key", "--receipt", "--checkpoint", "--expect", "--units"],
        _ => &[],
    }
}

// ---- a minimal deterministic JSON writer -----------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

impl Json {
    fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Int(n) => out.push_str(&n.to_string()),
            Self::Str(s) => write_str(out, s),
            Self::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    /// The scalar rendered for the text report.
    fn text(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            other => {
                let mut s = String::new();
                other.write(&mut s);
                s
            }
        }
    }
}

fn s(v: impl Into<String>) -> Json {
    Json::Str(v.into())
}

fn h(bytes: &[u8]) -> Json {
    Json::Str(hex(bytes))
}

/// A `u64` count or index; beyond `i64` it is rendered as a string.
fn n(v: u64) -> Json {
    i64::try_from(v).map_or_else(|_| Json::Str(v.to_string()), Json::Int)
}

/// Amounts are exact: rendered as decimal strings, never as JSON numbers a
/// consumer might round.
fn amount(v: i128) -> Json {
    Json::Str(v.to_string())
}

fn day(d: Option<i32>) -> Json {
    d.map_or(Json::Null, |d| Json::Int(i64::from(d)))
}

// ---- the report --------------------------------------------------------------

/// A check's result: only `Pass` is green.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
    /// Not evaluated: a check it rests on did not pass.
    Unrun,
}

impl Verdict {
    fn word(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Unrun => "unrun",
        }
    }
}

struct Check {
    name: &'static str,
    scope: &'static str,
    verdict: Verdict,
    detail: Vec<(&'static str, Json)>,
    reason: Option<String>,
}

impl Check {
    fn pass(name: &'static str, scope: &'static str, detail: Vec<(&'static str, Json)>) -> Self {
        Self {
            name,
            scope,
            verdict: Verdict::Pass,
            detail,
            reason: None,
        }
    }

    fn fail(name: &'static str, scope: &'static str, e: &VerifyError) -> Self {
        Self {
            name,
            scope,
            verdict: Verdict::Fail,
            detail: Vec::new(),
            reason: Some(e.to_string()),
        }
    }

    fn json(&self) -> Json {
        Json::Obj(vec![
            ("check", s(self.name)),
            ("scope", s(self.scope)),
            ("result", s(self.verdict.word())),
            ("detail", Json::Obj(self.detail.clone())),
            ("reason", self.reason.clone().map_or(Json::Null, Json::Str)),
        ])
    }
}

/// Why a run ended without a report: bad usage (exit 2), an unreadable input
/// (exit 5), or an input over [`MAX_INPUT_BYTES`] that is refused unread
/// (exit 8).
struct Usage {
    message: String,
    fix: String,
    exit: i32,
    verdict: &'static str,
}

fn usage(message: impl Into<String>, fix: impl Into<String>) -> Usage {
    Usage {
        message: message.into(),
        fix: fix.into(),
        exit: EXIT_USAGE,
        verdict: "usage",
    }
}

fn report(command: &str, json: bool, checks: &[Check]) -> Output {
    let verified = !checks.is_empty() && checks.iter().all(|c| matches!(c.verdict, Verdict::Pass));
    let exit = if verified { EXIT_VERIFIED } else { EXIT_FAILED };
    let stdout = if json {
        let mut out = String::new();
        Json::Obj(vec![
            ("v", Json::Int(1)),
            ("tool", s("fa-verify")),
            ("command", s(command)),
            ("verdict", s(if verified { "verified" } else { "failed" })),
            (
                "checks",
                Json::List(checks.iter().map(Check::json).collect()),
            ),
            ("error", Json::Null),
        ])
        .write(&mut out);
        out.push('\n');
        out
    } else {
        let mut out = format!(
            "fa-verify {command}: {}\n",
            if verified { "VERIFIED" } else { "FAILED" }
        );
        for c in checks {
            let mark = c.verdict.word().to_ascii_uppercase();
            out.push_str(&format!("{mark} {} ({})", c.name, c.scope));
            if let Some(r) = &c.reason {
                out.push_str(&format!(": {r}"));
            }
            out.push('\n');
            for (k, v) in &c.detail {
                out.push_str(&format!("  {k}: {}\n", v.text()));
            }
        }
        out
    };
    let stderr = if verified {
        String::new()
    } else {
        let failed = checks
            .iter()
            .filter(|c| !matches!(c.verdict, Verdict::Pass))
            .count();
        format!(
            "fa-verify: {command}: not verified ({failed} of {} checks did not pass)\n",
            checks.len()
        )
    };
    Output {
        exit,
        stdout,
        stderr,
    }
}

fn usage_output(command: &str, json: bool, u: &Usage) -> Output {
    if json {
        let mut out = String::new();
        Json::Obj(vec![
            ("v", Json::Int(1)),
            ("tool", s("fa-verify")),
            ("command", s(command)),
            ("verdict", s(u.verdict)),
            ("checks", Json::List(Vec::new())),
            (
                "error",
                Json::Obj(vec![("message", s(&u.message)), ("fix", s(&u.fix))]),
            ),
        ])
        .write(&mut out);
        out.push('\n');
        Output {
            exit: u.exit,
            stdout: out,
            stderr: format!("fa-verify: {}\n", u.message),
        }
    } else {
        Output {
            exit: u.exit,
            stdout: String::new(),
            stderr: format!("fa-verify: {}\n  fix: {}\n", u.message, u.fix),
        }
    }
}

// ---- arguments -----------------------------------------------------------------

/// Optimal-string-alignment distance, for "did you mean" suggestions.
fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

fn closest<'a>(word: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (distance(word, c), *c))
        .filter(|(d, _)| *d <= 2)
        .min()
        .map(|(_, c)| c)
}

struct Args {
    command: String,
    positional: Vec<String>,
    values: Vec<(String, String)>,
    json: bool,
    hex: bool,
}

impl Args {
    fn one(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, flag: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn has(&self, flag: &str) -> bool {
        self.values.iter().any(|(f, _)| f == flag)
    }

    /// The value of `flag`, or of its `alias`; naming both is ambiguous.
    fn either(&self, flag: &str, alias: &str) -> Result<Option<&str>, Usage> {
        match (self.one(flag), self.one(alias)) {
            (Some(_), Some(_)) => Err(usage(
                format!("`{flag}` and `{alias}` name the same input"),
                format!("pass `{flag}` once"),
            )),
            (a, b) => Ok(a.or(b)),
        }
    }

    /// Refuse, before any file is opened, a flag `command` does not take.
    fn admitted_by(&self, command: &str) -> Result<(), Usage> {
        let admitted = admitted(command);
        for (flag, _) in &self.values {
            if flag != "--json" && flag != "--hex" && !admitted.contains(&flag.as_str()) {
                return Err(usage(
                    format!("`{flag}` does not apply to `{command}`"),
                    format!("drop `{flag}`; run `fa-verify --help` for what `{command}` takes"),
                ));
            }
        }
        Ok(())
    }
}

fn parse(args: &[String]) -> Result<Args, Usage> {
    let mut command = None;
    let mut positional = Vec::new();
    let mut values = Vec::new();
    let (mut json, mut hex) = (false, false);
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if SWITCHES.contains(&a.as_str()) {
            if values.iter().any(|(f, _)| f == a) {
                return Err(usage(
                    format!("`{a}` may be supplied only once"),
                    format!("drop the repeated `{a}`"),
                ));
            }
            match a.as_str() {
                "--json" => json = true,
                "--hex" => hex = true,
                _ => {}
            }
            values.push((a.clone(), String::new()));
        } else if a.starts_with("--") {
            let (flag, inline) = match a.split_once('=') {
                Some((f, v)) => (f.to_string(), Some(v.to_string())),
                None => (a.clone(), None),
            };
            if !VALUE_FLAGS.contains(&flag.as_str()) {
                let known: Vec<&str> = VALUE_FLAGS.iter().chain(&SWITCHES).copied().collect();
                let hint = closest(&flag, &known).map_or_else(
                    || "run `fa-verify --help`".to_string(),
                    |c| format!("did you mean `{c}`?"),
                );
                return Err(usage(format!("unknown flag `{flag}`"), hint));
            }
            let value = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    args.get(i)
                        .filter(|v| !v.starts_with("--"))
                        .cloned()
                        .ok_or_else(|| {
                            usage(
                                format!("`{flag}` needs a value"),
                                format!(
                                    "pass `{flag} <value>` (write ./--name for a file whose name begins with --)"
                                ),
                            )
                        })?
                }
            };
            if value.is_empty() {
                return Err(usage(
                    format!("`{flag}` needs a non-empty value"),
                    format!("pass `{flag} <value>`"),
                ));
            }
            if !matches!(flag.as_str(), "--key" | "--witness")
                && values.iter().any(|(f, _)| *f == flag)
            {
                return Err(usage(
                    format!("`{flag}` may be supplied only once"),
                    format!("pass one `{flag}`; only `--key` and `--witness` repeat"),
                ));
            }
            values.push((flag, value));
        } else if command.is_none() {
            command = Some(a.clone());
        } else {
            positional.push(a.clone());
        }
        i += 1;
    }
    Ok(Args {
        command: command.unwrap_or_default(),
        positional,
        values,
        json,
        hex,
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let value = |c: u8| (c as char).to_digit(16);
    digits
        .chunks(2)
        .map(|p| u8::try_from(value(p[0])? * 16 + value(p[1])?).ok())
        .collect()
}

fn key(text: &str) -> Result<[u8; 32], Usage> {
    let key: [u8; 32] = unhex(text).and_then(|b| b.try_into().ok()).ok_or_else(|| {
        usage(
            format!("`--key {text}` is not 64 hex characters"),
            "pass the book's checkpoint public key as 64 hex characters",
        )
    })?;
    // Trusted-key admission (ruling 3392): a key that is not a curve point
    // or is a small-order point is never trusted.
    crate::ed25519::check_public_key(&key).map_err(|reason| {
        usage(
            format!("`--key {text}` cannot be trusted: {reason}"),
            "pass the book's checkpoint public key (Book::checkpoint_public_key)",
        )
    })?;
    Ok(key)
}

fn account(text: &str) -> Result<u128, Usage> {
    let parsed = match text.strip_prefix("0x") {
        Some(h) if !h.is_empty() && h.len() <= 32 => u128::from_str_radix(h, 16).ok(),
        Some(_) => None,
        None => text.parse::<u128>().ok(),
    };
    parsed.ok_or_else(|| {
        usage(
            format!("`--account {text}` is not an account vid"),
            "pass a decimal vid or 0x followed by up to 32 hex characters",
        )
    })
}

/// Statements include zero-valued lines for the recipient's complete native
/// unit universe. Never derive that universe from the output being checked.
fn statement_units(raw: &str) -> Result<Vec<u32>, Usage> {
    let invalid = || {
        usage(
            "`--units` requires 1..=4096 strictly ascending unique decimal u32 unit IDs",
            "pass the complete independently obtained unit ID list, for example --units 0,1,2; omit --units for a trial balance or a version-2 registry bundle",
        )
    };
    let mut units = Vec::new();
    for token in raw.split(',') {
        if units.len() == 4096 || token.is_empty() || !token.bytes().all(|c| c.is_ascii_digit()) {
            return Err(invalid());
        }
        let id = token.parse::<u32>().map_err(|_| invalid())?;
        if units.last().is_some_and(|previous| *previous >= id) {
            return Err(invalid());
        }
        units.push(id);
    }
    Ok(units)
}

fn int<T: std::str::FromStr>(args: &Args, flag: &str, what: &str) -> Result<T, Usage> {
    let raw = args.one(flag).ok_or_else(|| {
        usage(
            format!("{what} needs `{flag}`"),
            format!("pass `{flag} <n>`"),
        )
    })?;
    raw.parse::<T>().map_err(|_| {
        usage(
            format!("`{flag} {raw}` is not a valid number"),
            format!("pass `{flag} <n>`"),
        )
    })
}

type Read<'a> = &'a dyn Fn(&str) -> std::io::Result<Vec<u8>>;

fn oversized(path: &str) -> Usage {
    Usage {
        message: format!("`{path}`: input exceeds the {MAX_INPUT_BYTES}-byte bound"),
        fix: "verify a smaller artifact (an earlier checkpoint, an inclusion proof, or a narrower scope), or call the fa_verify library under your own resource policy".to_string(),
        exit: EXIT_FAILED,
        verdict: "failed",
    }
}

/// Read one input. A reader that enforces [`MAX_INPUT_BYTES`] before
/// allocating reports an oversized file as `ErrorKind::FileTooLarge`; the
/// bound is checked again here for readers that do not.
fn load(read: Read<'_>, path: &str, hex_input: bool) -> Result<Vec<u8>, Usage> {
    let bytes = read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::FileTooLarge {
            oversized(path)
        } else {
            Usage {
                message: format!("cannot read `{path}`: {e}"),
                fix: "check the path and its permissions".to_string(),
                exit: EXIT_IO,
                verdict: "io_error",
            }
        }
    })?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(oversized(path));
    }
    if hex_input {
        let text = String::from_utf8(bytes).map_err(|_| {
            usage(
                format!("`{path}` is not hex text"),
                "drop `--hex` for raw bytes",
            )
        })?;
        unhex(&text).ok_or_else(|| {
            usage(
                format!("`{path}` is not hex text"),
                "drop `--hex` for raw bytes",
            )
        })
    } else {
        Ok(bytes)
    }
}

// ---- commands ----------------------------------------------------------------

fn checkpoint_check(signed: &Result<SignedCheckpoint, VerifyError>) -> Check {
    match signed {
        Err(e) => Check::fail("checkpoint", "signature", e),
        Ok(c) => Check::pass(
            "checkpoint",
            "signature",
            vec![
                ("oid", h(&c.oid)),
                ("book_id", h(&c.checkpoint.book_id)),
                ("branch_id", h(&c.checkpoint.branch_id)),
                ("through_seq", n(c.checkpoint.through_seq)),
                ("leaf_count", n(c.checkpoint.leaf_count)),
                ("root", h(&c.checkpoint.root)),
                ("state_oid", h(&c.state_oid)),
                ("scope_index_root", h(&c.scope_index_root)),
                (
                    "substrate_chain_commitment",
                    h(&c.substrate_chain_commitment),
                ),
                (
                    "signed_by",
                    Json::List(c.signed_by.iter().map(|k| h(k)).collect()),
                ),
                (
                    "not_judged",
                    Json::List(c.not_judged.iter().map(|k| h(k)).collect()),
                ),
            ],
        ),
    }
}

/// The witnesses' cosignatures (plan §13.5, fa-qtfd): at least `quorum` of
/// the `named` witness keys signed the checkpoint's body. The claim is
/// witnessed detection (checkpoints that later disagree expose a fork),
/// never prevention: no witness policy with intersecting quorums is judged.
fn witness_check(
    signed: &Result<SignedCheckpoint, VerifyError>,
    named: usize,
    quorum: usize,
) -> Check {
    let (signed_by, failure) = match signed {
        Ok(c) => (c.signed_by.clone(), None),
        Err(VerifyError::Checkpoint(CheckpointError::NoTrustedSignature)) => (Vec::new(), None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let detail = vec![
        ("claim", s("witnessed_detection")),
        ("quorum", n(u64::try_from(quorum).unwrap_or(u64::MAX))),
        ("named", n(u64::try_from(named).unwrap_or(u64::MAX))),
        (
            "signed",
            n(u64::try_from(signed_by.len()).unwrap_or(u64::MAX)),
        ),
        (
            "signed_by",
            Json::List(signed_by.iter().map(|k| h(k)).collect()),
        ),
    ];
    match failure {
        Some(why) => Check {
            name: "witnesses",
            scope: "quorum",
            verdict: Verdict::Fail,
            detail,
            reason: Some(why),
        },
        None if signed_by.len() >= quorum => Check::pass("witnesses", "quorum", detail),
        None => Check {
            name: "witnesses",
            scope: "quorum",
            verdict: Verdict::Fail,
            detail,
            reason: Some(format!(
                "{} of the {named} named witnesses signed; the quorum is {quorum}",
                signed_by.len()
            )),
        },
    }
}

fn envelope_detail(index: u64, e: &LeafEnvelope) -> Json {
    Json::Obj(vec![
        ("leaf_index", n(index)),
        ("commit_seq", n(e.commit_seq)),
        ("ordinal", Json::Int(i64::from(e.within_commit_ordinal))),
        ("record_digest", h(&e.record_digest)),
        ("class", Json::Int(i64::from(e.class))),
        ("effective_day", day(e.effective_day)),
    ])
}

/// How the caller trusts a checkpoint (the `ANCHOR` of the usage text).
enum Trust {
    /// A signed `TransparencyCheckpoint`, judged against these keys.
    Keys(Vec<[u8; 32]>),
    /// A raw 80-byte checkpoint statement the caller trusts out of band.
    Unsigned,
}

/// The `--key`s or `--unsigned-checkpoint`, exactly one of them; parsed
/// before any file is opened.
fn trust(args: &Args) -> Result<Trust, Usage> {
    let keys = args.all("--key");
    match (keys.is_empty(), args.has("--unsigned-checkpoint")) {
        (false, true) => Err(usage(
            "`--key` and `--unsigned-checkpoint` are two different anchors",
            "pass `--key` for a signed checkpoint, or `--unsigned-checkpoint` for a raw one you trust independently",
        )),
        (true, false) => Err(usage(
            "no trusted anchor: a checkpoint is judged only against keys you name, or as a raw checkpoint you say you trust",
            "pass the book's checkpoint public key with `--key <64 hex>`, or `--unsigned-checkpoint` for a raw 80-byte checkpoint obtained independently",
        )),
        (true, true) => Ok(Trust::Unsigned),
        (false, false) => Ok(Trust::Keys(
            keys.into_iter().map(key).collect::<Result<_, _>>()?,
        )),
    }
}

/// The checkpoint file a command names under `flag` (or its `alias`).
fn checkpoint_path<'a>(args: &'a Args, flag: &str, alias: Option<&str>) -> Result<&'a str, Usage> {
    let path = match alias {
        Some(alias) => args.either(flag, alias)?,
        None => args.one(flag),
    };
    path.ok_or_else(|| {
        usage(
            format!("`{}` needs `{flag} <file>`", args.command),
            format!("pass the checkpoint the proof is judged against with `{flag}`"),
        )
    })
}

/// A checkpoint whose anchor check passed, with its signed form when the
/// caller trusted it through `--key`.
type Anchored = Option<(Checkpoint, Option<SignedCheckpoint>)>;

/// The checkpoint a proof is judged against: its check, and the checkpoint
/// itself when that check passed.
fn anchor(
    trust: &Trust,
    path: &str,
    role: &'static str,
    args: &Args,
    read: Read<'_>,
) -> Result<(Check, Anchored), Usage> {
    let bytes = load(read, path, args.hex)?;
    Ok(match trust {
        Trust::Keys(keys) => {
            let signed = verify_checkpoint(&bytes, keys);
            let check = checkpoint_check(&signed);
            (check, signed.ok().map(|c| (c.checkpoint, Some(c))))
        }
        Trust::Unsigned => match Checkpoint::decode(&bytes) {
            Err(e) => (
                Check::fail(role, unsigned_scope(role), &VerifyError::from(e)),
                None,
            ),
            Ok(cp) => {
                let mut detail = vec![
                    ("format", s("unsigned_raw_checkpoint")),
                    ("book_id", h(&cp.book_id)),
                    ("branch_id", h(&cp.branch_id)),
                    ("through_seq", n(cp.through_seq)),
                    ("leaf_count", n(cp.leaf_count)),
                    ("root", h(&cp.root)),
                    ("signature_verification", s("not_performed")),
                ];
                if role == "claimed_checkpoint" {
                    detail.push((
                        "claimed_sequence_boundary",
                        s("not_verified_by_consistency"),
                    ));
                }
                (
                    Check::pass(role, unsigned_scope(role), detail),
                    Some((cp, None)),
                )
            }
        },
    })
}

/// The scope label of an unsigned checkpoint: the trusted one rests on the
/// caller's own trust; a claimed one is only the producer's claim.
fn unsigned_scope(role: &str) -> &'static str {
    if role == "claimed_checkpoint" {
        "producer_claim"
    } else {
        "operator_trusted"
    }
}

fn subject<'a>(args: &'a Args, what: &str) -> Result<&'a str, Usage> {
    match (args.positional.as_slice(), args.one("--proof")) {
        ([one], None) => Ok(one.as_str()),
        ([], Some(one)) => Ok(one),
        ([], None) => Err(usage(
            format!("`{}` needs {what}", args.command),
            format!("fa-verify {} <file> …", args.command),
        )),
        (_, Some(_)) => Err(usage(
            format!("`{}` names its file twice", args.command),
            format!(
                "name the file positionally or with `--proof`, not both: fa-verify {} <file> …",
                args.command
            ),
        )),
        _ => Err(usage(
            format!(
                "`{}` takes one file, got {}",
                args.command,
                args.positional.len()
            ),
            format!("fa-verify {} <file> …", args.command),
        )),
    }
}

fn run_command(args: &Args, read: Read<'_>) -> Result<Vec<Check>, Usage> {
    let cmd = args.command.as_str();
    if !COMMANDS.contains(&cmd) {
        return unreachable_command(cmd);
    }
    args.admitted_by(cmd)?;
    match cmd {
        "state" => {
            let bytes = load(read, subject(args, "a state file")?, args.hex)?;
            Ok(vec![match verify_state(&bytes) {
                Err(e) => Check::fail("state", "state", &e),
                Ok(st) => Check::pass(
                    "state",
                    "state",
                    vec![
                        ("oid", h(&st.oid)),
                        ("through_seq", n(st.checkpoint.through_seq)),
                        ("leaf_count", n(st.checkpoint.leaf_count)),
                        ("root", h(&st.checkpoint.root)),
                        ("peaks", n(st.peaks.len() as u64)),
                        (
                            "prev_state_oid",
                            st.prev_state_oid.map_or(Json::Null, |o| h(&o)),
                        ),
                        (
                            "signatures",
                            s("unsigned (a TransparencyCheckpoint signs it)"),
                        ),
                    ],
                ),
            }])
        }
        "checkpoint" => {
            let file = subject(args, "a checkpoint file")?;
            let keys = args.all("--key");
            if keys.is_empty() {
                return Err(usage(
                    "no trusted key: a checkpoint is judged only against keys you name",
                    "pass the book's checkpoint public key with `--key <64 hex>`",
                ));
            }
            let keys: Vec<[u8; 32]> = keys.into_iter().map(key).collect::<Result<_, _>>()?;
            let witnesses: Vec<[u8; 32]> = args
                .all("--witness")
                .into_iter()
                .map(key)
                .collect::<Result<_, _>>()?;
            let quorum = match args.one("--quorum") {
                None => witnesses.len(),
                Some(text) => text.parse::<usize>().map_err(|_| {
                    usage(
                        format!("--quorum {text} is not a count"),
                        "pass how many named witnesses must have signed, e.g. --quorum 2",
                    )
                })?,
            };
            if args.one("--quorum").is_some() && (witnesses.is_empty() || quorum == 0) {
                return Err(usage(
                    "--quorum counts the --witness keys that signed: name at least one witness and a quorum of at least 1",
                    "fa-verify checkpoint <file> --key <book key> --witness <key>... --quorum <n>",
                ));
            }
            if witnesses.iter().any(|w| keys.contains(w)) {
                return Err(usage(
                    "a witness key is also a --key: a witness must be independent of the key it cosigns",
                    "name the book's key with --key and each witness's own key with --witness",
                ));
            }
            let bytes = load(read, file, args.hex)?;
            let mut checks = vec![checkpoint_check(&verify_checkpoint(&bytes, &keys))];
            if !witnesses.is_empty() {
                checks.push(witness_check(
                    &verify_checkpoint(&bytes, &witnesses),
                    witnesses.len(),
                    quorum,
                ));
            }
            Ok(checks)
        }
        "inclusion" | "prefix" | "balance" | "scope" => {
            let proof_path = subject(args, "a proof file")?;
            let checkpoint_file = checkpoint_path(args, "--checkpoint", None)?;
            let trust = trust(args)?;
            if cmd == "scope" && matches!(trust, Trust::Unsigned) {
                return Err(usage(
                    "`scope` needs a signed checkpoint: the scope-index root it proves against is part of the signed statement",
                    "pass the book's checkpoint public key with `--key <64 hex>`",
                ));
            }
            let claim = if cmd == "scope" {
                let account = account(args.one("--account").ok_or_else(|| {
                    usage(
                        "`scope` needs `--account`",
                        "pass the account vid you are asking about",
                    )
                })?)?;
                let from = int::<i32>(args, "--from", "`scope`")?;
                let to = int::<i32>(args, "--to", "`scope`")?;
                Some(ScopeClaim { account, from, to })
            } else {
                None
            };
            let (anchor_check, anchored) =
                anchor(&trust, checkpoint_file, "checkpoint", args, read)?;
            let prefix = match args.one("--prefix") {
                Some(p) => Some(load(read, p, args.hex)?),
                None => None,
            };
            let proof = load(read, proof_path, args.hex)?;
            let mut checks = vec![anchor_check];
            let Some((cp, signed)) = anchored else {
                return Ok(checks);
            };
            checks.push(match cmd {
                "inclusion" => match verify_inclusion(&proof, &cp) {
                    Err(e) => Check::fail("inclusion", "inclusion", &e),
                    Ok(inc) => Check::pass(
                        "inclusion",
                        inc.scope,
                        vec![
                            ("leaf", envelope_detail(inc.leaf_index, &inc.envelope)),
                            (
                                "record",
                                s(match inc.record {
                                    RecordCheck::NotSupplied => "not_supplied",
                                    RecordCheck::Recomputed => "recomputed",
                                }),
                            ),
                        ],
                    ),
                },
                "prefix" => match verify_prefix(&proof, &cp) {
                    Err(e) => Check::fail("prefix", "seq_range_complete", &e),
                    Ok(p) => Check::pass(
                        "prefix",
                        p.scope,
                        vec![("leaves", n(p.envelopes.len() as u64))],
                    ),
                },
                "balance" => match verify_balance(&proof, &cp) {
                    Err(e) => Check::fail("balance", "recomputation", &e),
                    Ok(b) => Check::pass(
                        "balance",
                        b.scope,
                        vec![
                            ("account", s(format!("0x{:032x}", b.claim.account))),
                            ("unit", Json::Int(i64::from(b.claim.unit))),
                            ("effective_through", day(b.claim.effective_through)),
                            ("debits", amount(b.claim.debits)),
                            ("credits", amount(b.claim.credits)),
                            (
                                "contributing",
                                Json::List(b.contributing.iter().map(|i| n(*i)).collect()),
                            ),
                        ],
                    ),
                },
                _ => {
                    let claim = claim.unwrap_or(ScopeClaim {
                        account: 0,
                        from: 0,
                        to: 0,
                    });
                    // `scope` admits only `--key` trust (refused above), so a
                    // passing anchor is always a signed checkpoint.
                    let scoped = signed.as_ref().map_or_else(
                        || {
                            Err(VerifyError::Format {
                                expected: crate::checkpoint::CHECKPOINT_BODY_DOMAIN,
                            })
                        },
                        |signed| verify_scope(&proof, signed, &claim, prefix.as_deref()),
                    );
                    match scoped {
                        Err(e) => Check::fail("scope", "scope_index_complete", &e),
                        Ok(r) => Check::pass(
                            "scope",
                            r.scope,
                            vec![
                                ("account", s(format!("0x{:032x}", r.account))),
                                ("from", Json::Int(i64::from(r.from))),
                                ("to", Json::Int(i64::from(r.to))),
                                (
                                    "leaves",
                                    Json::List(
                                        r.leaves
                                            .iter()
                                            .map(|(i, e)| envelope_detail(*i, e))
                                            .collect(),
                                    ),
                                ),
                                (
                                    "index_derivation",
                                    match &r.index_derivation {
                                        IndexDerivation::Recomputed => {
                                            s("recomputed from the complete prefix")
                                        }
                                        IndexDerivation::Signed { by } => Json::Obj(vec![(
                                            "signed_by",
                                            Json::List(by.iter().map(|k| h(k)).collect()),
                                        )]),
                                    },
                                ),
                            ],
                        ),
                    }
                }
            });
            Ok(checks)
        }
        "consistency" => {
            let proof_path = subject(args, "a proof file")?;
            let trusted_file = checkpoint_path(args, "--trusted", Some("--checkpoint"))?;
            let claimed_file = checkpoint_path(args, "--claimed", Some("--next-checkpoint"))?;
            let trust = trust(args)?;
            let (trusted_check, trusted) = anchor(&trust, trusted_file, "checkpoint", args, read)?;
            let (claimed_check, claimed) =
                anchor(&trust, claimed_file, "claimed_checkpoint", args, read)?;
            let proof = load(read, proof_path, args.hex)?;
            let mut checks = vec![trusted_check, claimed_check];
            if let (Some((t, _)), Some((c, _))) = (&trusted, &claimed) {
                checks.push(match verify_consistency(&proof, t, c) {
                    Err(e) => Check::fail("consistency", "consistency", &e),
                    Ok(r) => Check::pass(
                        "consistency",
                        r.scope,
                        vec![
                            ("trusted_leaf_count", n(r.trusted.leaf_count)),
                            ("extended_leaf_count", n(r.extended.leaf_count)),
                            ("extended_through_seq", n(r.extended.through_seq)),
                        ],
                    ),
                });
            }
            Ok(checks)
        }
        "doc-commit" => {
            let bytes = load(read, subject(args, "a document file")?, args.hex)?;
            let kind = int::<u8>(args, "--kind", "`doc-commit`")?;
            let commit = doc_commit(kind, &bytes);
            let mut detail = vec![
                ("kind", Json::Int(i64::from(kind))),
                ("length", n(bytes.len() as u64)),
                ("doc_commit", h(&commit)),
            ];
            match args.one("--expect") {
                None => Ok(vec![Check::pass("doc_commit", "public_commitment", detail)]),
                Some(e) => {
                    let expected = unhex(e).filter(|b| b.len() == 32).ok_or_else(|| {
                        usage(
                            format!("`--expect {e}` is not 64 hex characters"),
                            "pass the doc_commit the entry's evidence cites",
                        )
                    })?;
                    detail.push(("expected", h(&expected)));
                    let matches = expected == commit;
                    Ok(vec![Check {
                        name: "doc_commit",
                        scope: "public_commitment",
                        verdict: if matches {
                            Verdict::Pass
                        } else {
                            Verdict::Fail
                        },
                        detail,
                        reason: (!matches).then(|| {
                            "the bytes and kind do not produce the expected doc_commit".to_string()
                        }),
                    }])
                }
            }
        }
        "bundle" => {
            let file = subject(args, "a bundle file")?;
            let keys = args.all("--key");
            if keys.is_empty() {
                return Err(usage(
                    "no trusted key: a bundle is judged only against keys you name",
                    "pass the book's checkpoint public key with `--key <64 hex>`",
                ));
            }
            let keys: Vec<[u8; 32]> = keys.into_iter().map(key).collect::<Result<_, _>>()?;
            let bytes = load(read, file, args.hex)?;
            let receipt = match args.one("--receipt") {
                Some(p) => Some(load(read, p, args.hex)?),
                None => None,
            };
            Ok(match verify_bundle(&bytes, &keys, receipt.as_deref()) {
                Err(e) => vec![Check {
                    name: "bundle",
                    scope: "format",
                    verdict: Verdict::Fail,
                    detail: Vec::new(),
                    reason: Some(e.to_string()),
                }],
                Ok(report) => bundle_checks(&report),
            })
        }
        "report" => {
            let file = subject(args, "a report bundle file")?;
            let keys = args.all("--key");
            if keys.is_empty() {
                return Err(usage(
                    "no trusted key: report verification needs recipient-owned checkpoint keys",
                    "pass --key <64 hex> from an independent trusted source",
                ));
            }
            let keys: Vec<[u8; 32]> = keys.into_iter().map(key).collect::<Result<_, _>>()?;
            let expected_digest: Option<[u8; 32]> = args
                .one("--expect")
                .map(|raw| {
                    unhex(raw)
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or_else(|| {
                            usage(
                                format!("`--expect {raw}` is not 64 hex characters"),
                                "pass the independently selected report certificate digest (the outer certificate for composed aging, reconciliation, roll-forward and cash-flow reports)",
                            )
                        })
                })
                .transpose()?;
            let units = args.one("--units").map(statement_units).transpose()?;
            let mut checks = Vec::new();
            let expected_checkpoint = if let Some(path) = args.one("--checkpoint") {
                let bytes = load(read, path, args.hex)?;
                let signed = verify_checkpoint(&bytes, &keys);
                checks.push(checkpoint_check(&signed));
                match signed {
                    Ok(signed) => Some(signed.checkpoint),
                    Err(_) => return Ok(checks),
                }
            } else {
                None
            };
            let bytes = load(read, file, args.hex)?;
            let receipt = args
                .one("--receipt")
                .map(|p| load(read, p, args.hex))
                .transpose()?;
            let verified = match units.as_deref() {
                Some(units) => crate::report::verify_statement_report_expected(
                    &bytes,
                    &keys,
                    expected_checkpoint.as_ref(),
                    receipt.as_deref(),
                    units,
                    expected_digest.as_ref(),
                ),
                None => crate::report::verify_report_expected(
                    &bytes,
                    &keys,
                    expected_checkpoint.as_ref(),
                    receipt.as_deref(),
                    expected_digest.as_ref(),
                ),
            };
            match verified {
                Err(error) => checks.push(Check {
                    name: error.predicate,
                    scope: "recomputation",
                    verdict: Verdict::Fail,
                    detail: Vec::new(),
                    reason: Some(error.detail),
                }),
                Ok(report) => {
                    checks.push(Check::pass(
                        "report_bundle",
                        report.scope,
                        vec![
                            ("bundle_digest", h(&report.bundle_digest)),
                            ("certificate_digest", h(&report.certificate_digest)),
                            ("output_digest", h(&report.output_digest)),
                            ("known_at", n(report.known_at)),
                            ("effective_through", day(report.effective_through)),
                            (
                                "report_mode",
                                s(if report.explanation.is_some() {
                                    "balance_explanation"
                                } else if report.aging_reconciliation.is_some() {
                                    "aging_reconciliation"
                                } else if report.aging.is_some() {
                                    "effective_date_aging"
                                } else if let Some(cash) = &report.cash_flow {
                                    if cash.policy.is_some() {
                                        "policy_cash_flow"
                                    } else {
                                        "cash_flow"
                                    }
                                } else if report.roll_forward.is_some() {
                                    "roll_forward"
                                } else if report.open_items.is_some() {
                                    "open_items"
                                } else if report.activity {
                                    "activity"
                                } else {
                                    "stock"
                                }),
                            ),
                            ("records", n(report.checked_records as u64)),
                            (
                                "rows",
                                n(if let Some(explanation) = &report.explanation {
                                    explanation.contributions.len()
                                } else if let Some(comparison) = &report.aging_reconciliation {
                                    comparison.rows.len()
                                } else if let Some(aging) = &report.aging {
                                    aging.items.len()
                                } else if let Some(cash) = &report.cash_flow {
                                    cash.units.len()
                                } else if let Some(schedule) = &report.roll_forward {
                                    schedule.rows.len()
                                } else if let Some(open_items) = &report.open_items {
                                    open_items.items.len()
                                } else if let Some(statement) = &report.statement {
                                    statement.lines.len()
                                } else {
                                    report.rows.len()
                                } as u64),
                            ),
                            ("unit_universe_source", s(report.unit_universe_source)),
                            (
                                "native_read_attestations",
                                s("retained; not used as outsider proofs"),
                            ),
                        ],
                    ));
                    if let Some(time) = &report.time_selection {
                        checks.push(Check::pass(
                            "time_selection",
                            "authenticated_tick_bucket",
                            vec![
                                ("requested_utc_ns", n(time.requested_utc_ns)),
                                ("frontier", n(time.frontier)),
                                ("resolved_seq", n(time.resolved_seq)),
                                ("precision_grade", s("tick_bucket")),
                                ("lower_entry", s(format!("{:032x}", time.lower_entry))),
                                ("lower_recorded_at", n(time.lower.recorded_at)),
                                ("lower_observed_utc_ns", n(time.lower.observed_utc_ns)),
                                (
                                    "upper_entry",
                                    time.upper_entry
                                        .map_or(Json::Null, |entry| s(format!("{entry:032x}"))),
                                ),
                                (
                                    "upper_recorded_at",
                                    time.upper.map_or(Json::Null, |tick| n(tick.recorded_at)),
                                ),
                                (
                                    "upper_observed_utc_ns",
                                    time.upper
                                        .map_or(Json::Null, |tick| n(tick.observed_utc_ns)),
                                ),
                                ("source_grade", s(time.source_grade())),
                                ("physical_commit_time", s("not_judged")),
                                ("external_utc_accuracy", s("not_judged")),
                                ("book_genesis_policy_admission", s("not_judged")),
                            ],
                        ));
                    }
                    if let Some(dimension) = &report.dimension {
                        checks.push(Check::pass(
                            "dimension_filter",
                            "authenticated_journal",
                            vec![
                                ("dimension", s(&dimension.dimension)),
                                ("value", s(&dimension.value)),
                                (
                                    "included_values",
                                    Json::List(dimension.values.iter().map(s).collect()),
                                ),
                                (
                                    "selection",
                                    s("tagged legs, including declared descendants"),
                                ),
                                ("monetary_footing", s("not required for a filtered view")),
                            ],
                        ));
                    }
                    if let Some(statement) = &report.statement {
                        checks.extend(statement_checks(statement, report.unit_universe_source));
                    }
                    if let Some(open_items) = &report.open_items {
                        checks.extend(open_items_checks(open_items));
                    }
                    if let Some(explanation) = &report.explanation {
                        checks.extend(explanation_checks(explanation));
                    }
                    if let Some(aging) = &report.aging {
                        checks.extend(aging_checks(aging));
                    }
                    if let Some(comparison) = &report.aging_reconciliation {
                        checks.extend(reconciliation_checks(comparison));
                        checks.extend(aging_checks(&comparison.aging));
                    }
                    if let Some(schedule) = &report.roll_forward {
                        checks.extend(roll_forward_checks(schedule));
                    }
                    if let Some(cash) = &report.cash_flow {
                        checks.extend(cash_flow_checks(cash));
                    }
                    for row in &report.rows {
                        checks.push(Check::pass(
                            "trial_balance_row",
                            "recomputation",
                            vec![
                                ("account", s(format!("{:032x}", row.account))),
                                ("code", s(&row.code)),
                                ("unit", n(u64::from(row.unit))),
                                ("debits", s(row.debits.to_string())),
                                ("credits", s(row.credits.to_string())),
                                ("debits_pending", s(row.debits_pending.to_string())),
                                ("credits_pending", s(row.credits_pending.to_string())),
                            ],
                        ));
                    }
                    checks.push(Check::pass(
                        "canonical_report",
                        report.scope,
                        vec![("output_digest", h(&report.output_digest))],
                    ));
                    if let Some(receipt) = report.receipt {
                        checks.push(Check::pass(
                            "production_receipt",
                            "signature",
                            vec![("signed_by", h(&receipt.signed_by))],
                        ));
                    }
                }
            }
            Ok(checks)
        }
        "ads" => {
            let dir = subject(args, "an ADS package directory")?;
            let keys = args.all("--key");
            if keys.is_empty() {
                return Err(usage(
                    "no trusted key: an ADS extract is judged only against keys you name",
                    "pass the book's checkpoint public key with `--key <64 hex>`",
                ));
            }
            let keys: Vec<[u8; 32]> = keys.into_iter().map(key).collect::<Result<_, _>>()?;
            let text = |name: &str| -> Result<String, Usage> {
                let path = format!("{dir}/{name}");
                String::from_utf8(load(read, &path, false)?).map_err(|_| {
                    usage(
                        format!("`{path}` is not UTF-8 text"),
                        "name the directory `fa export ads --with-proofs --out <dir>` wrote",
                    )
                })
            };
            let certificate = text("ADS_Coordinate_Certificate.toml")?;
            let chart_of_accounts = text("Chart_of_Accounts.txt")?;
            let gl_detail = text("GL_Detail.txt")?;
            let trial_balance = text("Trial_Balance.txt")?;
            let bundle = load(read, &format!("{dir}/ADS_Proof.fab"), false)?;
            let receipt = match args.one("--receipt") {
                Some(p) => load(read, p, args.hex)?,
                None => load(read, &format!("{dir}/ADS_Proof.receipt"), false)?,
            };
            Ok(
                match verify_ads(
                    &certificate,
                    &chart_of_accounts,
                    &gl_detail,
                    &trial_balance,
                    &bundle,
                    &keys,
                    Some(&receipt),
                ) {
                    Err(e) => vec![Check {
                        name: "bundle",
                        scope: "format",
                        verdict: Verdict::Fail,
                        detail: Vec::new(),
                        reason: Some(e.to_string()),
                    }],
                    Ok(report) => ads_checks(&report, "ads_extract"),
                },
            )
        }
        "saft" => {
            let dir = subject(args, "a SAF-T package directory")?;
            let keys = args.all("--key");
            if keys.is_empty() {
                return Err(usage(
                    "no trusted key: a SAF-T extract is judged only against keys you name",
                    "pass the book's checkpoint public key with `--key <64 hex>`",
                ));
            }
            let keys: Vec<[u8; 32]> = keys.into_iter().map(key).collect::<Result<_, _>>()?;
            let path = format!("{dir}/SAF-T.xml");
            let xml = String::from_utf8(load(read, &path, false)?).map_err(|_| {
                usage(
                    format!("`{path}` is not UTF-8 text"),
                    "name the directory `fa export saft --with-proofs --out <dir>` wrote",
                )
            })?;
            let bundle = load(read, &format!("{dir}/SAFT_Proof.fab"), false)?;
            let receipt = match args.one("--receipt") {
                Some(p) => load(read, p, args.hex)?,
                None => load(read, &format!("{dir}/SAFT_Proof.receipt"), false)?,
            };
            Ok(
                match crate::saft::verify_saft(&xml, &bundle, &keys, Some(&receipt)) {
                    Err(e) => vec![Check {
                        name: "bundle",
                        scope: "format",
                        verdict: Verdict::Fail,
                        detail: Vec::new(),
                        reason: Some(e.to_string()),
                    }],
                    Ok(report) => ads_checks(&report, "saft_extract"),
                },
            )
        }
        _ => unreachable_command(cmd),
    }
}

fn account_check(name: &'static str, account: &crate::report::VerifiedReportAccount) -> Check {
    let policy = match account.unit_policy {
        crate::report::OpenItemUnitPolicy::Single(unit) => format!("single:{unit}"),
        crate::report::OpenItemUnitPolicy::AnyCurrency => "any_currency".into(),
        crate::report::OpenItemUnitPolicy::AnyUnit => "any_unit".into(),
    };
    Check::pass(
        name,
        "recomputation",
        vec![
            ("account", s(format!("{:032x}", account.account))),
            ("code", s(&account.code)),
            ("name", s(&account.name)),
            ("account_type", n(u64::from(account.account_type))),
            (
                "normal_balance",
                s(if account.normal_balance == 0 {
                    "debit"
                } else {
                    "credit"
                }),
            ),
            ("is_leaf", Json::Bool(account.is_leaf)),
            ("unit_policy", s(policy)),
            (
                "limit_lower",
                account
                    .limit
                    .as_ref()
                    .and_then(|limit| limit.lower)
                    .map_or(Json::Null, |value| s(value.to_string())),
            ),
            (
                "limit_upper",
                account
                    .limit
                    .as_ref()
                    .and_then(|limit| limit.upper)
                    .map_or(Json::Null, |value| s(value.to_string())),
            ),
            (
                "limit_scope",
                account.limit.as_ref().map_or(Json::Null, |limit| {
                    s(if limit.period_scoped {
                        "period"
                    } else {
                        "lifetime"
                    })
                }),
            ),
            ("created_at", n(account.created_at)),
        ],
    )
}

fn explanation_checks(report: &crate::report::VerifiedBalanceExplanation) -> Vec<Check> {
    let mut checks = vec![
        Check::pass(
            "balance_explanation",
            "authenticated_parameters",
            vec![
                ("account", s(format!("{:032x}", report.account))),
                ("period", s(&report.period)),
                ("known_at", n(report.known_at)),
                ("unit_universe_source", s("authenticated-registry")),
                ("reason_code_source", s("authenticated-registry")),
                ("history", s("complete recorded-time cell history")),
                (
                    "evidence_heads",
                    s("committed citations; document authenticity not judged"),
                ),
            ],
        ),
        account_check("balance_explanation_account", &report.account_row),
        Check::pass(
            "balance_explanation_fold",
            "recomputation",
            vec![
                ("scope", s("whole selected period")),
                ("fold_digest", h(&report.fold_digest)),
                ("watermark", report.watermark.map_or(Json::Null, n)),
                (
                    "last_changed_at",
                    report.last_changed_at().map_or(Json::Null, n),
                ),
                ("posted_cells", n(report.cells.len() as u64)),
                ("pending_cells", n(report.pending.len() as u64)),
            ],
        ),
    ];
    for (column, cells) in [("posted", &report.cells), ("pending", &report.pending)] {
        for cell in cells {
            checks.push(Check::pass(
                "balance_explanation_cell",
                "recomputation",
                vec![
                    ("account", s(format!("{:032x}", cell.account))),
                    ("period", s(&cell.period)),
                    ("unit", n(u64::from(cell.unit_id))),
                    ("column", s(column)),
                    ("debits", s(cell.debits.to_string())),
                    ("credits", s(cell.credits.to_string())),
                    ("entry_count", n(cell.entry_count)),
                ],
            ));
        }
    }
    for c in &report.contributions {
        checks.push(Check::pass(
            "balance_contribution",
            "recomputation",
            vec![
                ("entry", s(format!("{:032x}", c.entry))),
                ("entry_digest", h(&c.entry_digest)),
                ("class", n(u64::from(c.class))),
                ("effective_date", day(Some(c.effective_date))),
                ("recorded_at", n(c.recorded_at)),
                ("visible_at", n(c.visible_at)),
                ("ordinal", n(u64::from(c.ordinal))),
                ("side", s(if c.debit { "debit" } else { "credit" })),
                ("unit", n(u64::from(c.unit_id))),
                ("mantissa", s(c.mantissa.to_string())),
                ("column", s(c.column.name())),
                ("released_at", c.released_at.map_or(Json::Null, n)),
                (
                    "resolves",
                    c.resolves.map_or(Json::Null, |id| s(format!("{id:032x}"))),
                ),
            ],
        ));
        for lineage in &c.supersedes {
            let reason = &report.supersession_reasons[&lineage.reason_code];
            checks.push(Check::pass(
                "balance_contribution_supersession",
                "authenticated_journal",
                vec![
                    ("entry", s(format!("{:032x}", c.entry))),
                    ("ordinal", n(u64::from(c.ordinal))),
                    ("target", s(format!("{:032x}", lineage.target))),
                    ("target_digest", h(&lineage.entry_digest)),
                    ("kind", n(u64::from(lineage.kind))),
                    ("reason_code", n(u64::from(lineage.reason_code))),
                    ("reason_name", s(&reason.name)),
                    ("reason_meaning", s(&reason.meaning)),
                ],
            ));
        }
        for evidence in &c.evidence {
            checks.push(Check::pass(
                "balance_contribution_evidence",
                "authenticated_journal",
                vec![
                    ("entry", s(format!("{:032x}", c.entry))),
                    ("ordinal", n(u64::from(c.ordinal))),
                    ("document_oid", h(&evidence.document_oid)),
                    ("doc_commit", h(&evidence.doc_commit)),
                    ("role", n(u64::from(evidence.role))),
                ],
            ));
        }
    }
    for change in &report.history {
        checks.push(Check::pass(
            "balance_history",
            "recomputation",
            vec![
                ("recorded_at", n(change.recorded_at)),
                ("unit", n(u64::from(change.unit_id))),
                ("debits", s(change.debits.to_string())),
                ("credits", s(change.credits.to_string())),
                ("debits_pending", s(change.debits_pending.to_string())),
                ("credits_pending", s(change.credits_pending.to_string())),
            ],
        ));
    }
    checks
}

fn open_items_checks(report: &crate::report::VerifiedOpenItems) -> Vec<Check> {
    let mut checks = vec![Check::pass(
        "open_items_parameters",
        "authenticated_parameters",
        vec![
            (
                "account_filter",
                report
                    .account_filter
                    .map_or(Json::Null, |id| s(format!("{id:032x}"))),
            ),
            ("unit_universe_source", s("authenticated-registry")),
            (
                "application_history",
                s("complete; reversed applications retained"),
            ),
            ("amount_basis", s("native units")),
        ],
    )];
    for account in report.accounts.values() {
        checks.push(account_check("open_item_account", account));
    }
    for item in &report.items {
        checks.push(Check::pass(
            "open_item",
            "recomputation",
            vec![
                ("entry", s(format!("{:032x}", item.entry))),
                ("ordinal", n(u64::from(item.ordinal))),
                ("account", s(format!("{:032x}", item.account))),
                ("unit", n(u64::from(item.unit_id))),
                ("side", s(if item.debit { "debit" } else { "credit" })),
                ("effective_date", day(Some(item.effective_date))),
                ("recorded_at", n(item.recorded_at)),
                ("original", s(item.original.to_string())),
                ("applied", s(item.applied.to_string())),
                ("applied_out", s(item.applied_out.to_string())),
                ("open", s(item.open.to_string())),
                ("applications", n(item.applications.len() as u64)),
            ],
        ));
        for application in &item.applications {
            checks.push(Check::pass(
                "open_item_application",
                "recomputation",
                vec![
                    ("target_entry", s(format!("{:032x}", item.entry))),
                    ("target_ordinal", n(u64::from(item.ordinal))),
                    ("entry", s(format!("{:032x}", application.entry))),
                    ("ordinal", n(u64::from(application.ordinal))),
                    ("amount", s(application.amount.to_string())),
                    ("recorded_at", n(application.recorded_at)),
                    ("live", Json::Bool(application.live)),
                ],
            ));
        }
    }
    checks
}

fn reconciliation_checks(report: &crate::report::VerifiedAgingReconciliation) -> Vec<Check> {
    let mut checks = vec![
        Check::pass(
            "aging_reconciliation",
            "recomputation",
            vec![
                ("book", h(&report.book_id)),
                ("known_at", n(report.known_at)),
                ("effective_through", day(Some(report.effective_through))),
                ("account", s(format!("{:032x}", report.account.account))),
                ("reconciled", Json::Bool(report.is_reconciled())),
                ("units", n(report.rows.len() as u64)),
                (
                    "aging_certificate_digest",
                    h(&report.aging_certificate_digest),
                ),
                (
                    "control_certificate_digest",
                    h(&report.control_certificate_digest),
                ),
                (
                    "scope",
                    s("selected-account consistency at one recorded prefix and effective cutoff"),
                ),
                (
                    "comparison",
                    s("posted debit net minus open debit net, separately per native unit"),
                ),
                (
                    "pending",
                    s("reported separately; excluded from the comparison"),
                ),
                ("external_subledger", s("not judged")),
            ],
        ),
        account_check("aging_reconciliation_account", &report.account),
    ];
    for row in &report.rows {
        checks.push(Check::pass(
            "aging_reconciliation_row",
            "recomputation",
            vec![
                ("account", s(format!("{:032x}", report.account.account))),
                ("unit", n(u64::from(row.unit_id))),
                ("posted_debits", s(row.posted_debits.to_string())),
                ("posted_credits", s(row.posted_credits.to_string())),
                ("pending_debits", s(row.pending_debits.to_string())),
                ("pending_credits", s(row.pending_credits.to_string())),
                ("open_debits", s(row.open_debits.to_string())),
                ("open_credits", s(row.open_credits.to_string())),
                ("open_item_count", n(row.open_item_count)),
                ("posted_net", s(row.posted_net.to_string())),
                ("open_net", s(row.open_net.to_string())),
                ("difference", s(row.difference.to_string())),
                ("reconciled", Json::Bool(row.difference == 0)),
            ],
        ));
    }
    checks
}

fn aging_checks(report: &crate::report::VerifiedAging) -> Vec<Check> {
    let mut checks = vec![Check::pass(
        "aging_parameters",
        "authenticated_parameters",
        vec![
            ("book", h(&report.book_id)),
            ("known_at", n(report.known_at)),
            ("effective_through", day(Some(report.effective_through))),
            (
                "account_filter",
                report
                    .account_filter
                    .map_or(Json::Null, |id| s(format!("{id:032x}"))),
            ),
            (
                "source_certificate_digest",
                h(&report.source_certificate_digest),
            ),
            (
                "age_basis",
                s("civil days since effective date; no contractual due date inferred"),
            ),
            (
                "selection",
                s("effective cutoff before settlement and reversal netting"),
            ),
            (
                "amount_basis",
                s("native units; separate debit and credit totals"),
            ),
            (
                "producer_authorization",
                s("not judged; saved capability bytes grant no current authority"),
            ),
        ],
    )];
    for (index, band) in report.bands.iter().enumerate() {
        checks.push(Check::pass(
            "aging_band",
            "recomputation",
            vec![
                ("bucket", n(index as u64)),
                ("lower_inclusive", n(band.lower_inclusive)),
                (
                    "upper_inclusive",
                    band.upper_inclusive.map_or(Json::Null, n),
                ),
            ],
        ));
    }
    for aged in &report.items {
        let item = &aged.item;
        checks.push(Check::pass(
            "aging_item",
            "recomputation",
            vec![
                ("entry", s(format!("{:032x}", item.entry))),
                ("ordinal", n(u64::from(item.ordinal))),
                ("account", s(format!("{:032x}", item.account))),
                ("unit", n(u64::from(item.unit_id))),
                ("side", s(if item.debit { "debit" } else { "credit" })),
                ("effective_date", day(Some(item.effective_date))),
                ("recorded_at", n(item.recorded_at)),
                ("original", s(item.original.to_string())),
                ("applied", s(item.applied.to_string())),
                ("applied_out", s(item.applied_out.to_string())),
                ("open", s(item.open.to_string())),
                ("age_days", n(aged.age_days)),
                ("bucket", n(aged.bucket as u64)),
                ("applications", n(item.applications.len() as u64)),
            ],
        ));
        for application in &item.applications {
            checks.push(Check::pass(
                "aging_application",
                "recomputation",
                vec![
                    ("target_entry", s(format!("{:032x}", item.entry))),
                    ("target_ordinal", n(u64::from(item.ordinal))),
                    ("entry", s(format!("{:032x}", application.entry))),
                    ("ordinal", n(u64::from(application.ordinal))),
                    ("amount", s(application.amount.to_string())),
                    ("recorded_at", n(application.recorded_at)),
                    ("live", Json::Bool(application.live)),
                ],
            ));
        }
    }
    for cell in &report.cells {
        checks.push(Check::pass(
            "aging_cell",
            "recomputation",
            vec![
                ("account", s(format!("{:032x}", cell.account))),
                ("unit", n(u64::from(cell.unit_id))),
                ("bucket", n(cell.bucket as u64)),
                ("debits", s(cell.amounts.debits.to_string())),
                ("credits", s(cell.amounts.credits.to_string())),
                ("item_count", n(cell.amounts.item_count)),
            ],
        ));
    }
    for total in &report.totals {
        checks.push(Check::pass(
            "aging_total",
            "recomputation",
            vec![
                ("account", s(format!("{:032x}", total.account))),
                ("unit", n(u64::from(total.unit_id))),
                ("debits", s(total.amounts.debits.to_string())),
                ("credits", s(total.amounts.credits.to_string())),
                ("item_count", n(total.amounts.item_count)),
            ],
        ));
    }
    checks
}

fn roll_forward_checks(report: &crate::report::VerifiedRollForward) -> Vec<Check> {
    let mut checks = vec![Check::pass(
        "roll_forward_parameters",
        "authenticated_parameters",
        vec![
            ("book", h(&report.book_id)),
            ("known_at", n(report.known_at)),
            ("label", s(&report.label)),
            ("effective_from", day(Some(report.effective_from))),
            ("effective_through", day(Some(report.effective_through))),
            (
                "source_certificate_digest",
                h(&report.source_certificate_digest),
            ),
            (
                "units",
                Json::List(
                    report
                        .units
                        .iter()
                        .map(|&unit| n(u64::from(unit)))
                        .collect(),
                ),
            ),
            ("amount_basis", s("native units; debit minus credit")),
            (
                "classification_basis",
                s(
                    "recorded entry class, numeric supersession reasons and Rule-origin version; rule execution not judged",
                ),
            ),
        ],
    )];
    for account in &report.accounts {
        checks.push(Check::pass(
            "roll_forward_account",
            "authenticated_metadata",
            vec![
                ("account", s(format!("{:032x}", account.id))),
                ("code", s(&account.code)),
                ("name", s(&account.name)),
                ("account_type", n(u64::from(account.account_type))),
                ("is_leaf", Json::Bool(account.is_leaf)),
            ],
        ));
    }
    for (index, bucket) in report.buckets.iter().enumerate() {
        checks.push(Check::pass(
            "roll_forward_bucket",
            "recomputation",
            vec![
                ("bucket", n(index as u64)),
                ("class", n(u64::from(bucket.class))),
                ("reason_code", s(&bucket.reason_code)),
                (
                    "rule_digest",
                    bucket
                        .rule_digest
                        .as_ref()
                        .map_or(Json::Null, |digest| h(digest)),
                ),
            ],
        ));
    }
    for row in &report.rows {
        checks.push(Check::pass(
            "roll_forward_row",
            "recomputation",
            vec![
                ("account", s(format!("{:032x}", row.account_id))),
                ("unit", n(u64::from(row.unit_id))),
                ("opening", amount(row.opening)),
                (
                    "activity",
                    Json::List(row.activity.iter().copied().map(amount).collect()),
                ),
                ("net_change", amount(row.net_change)),
                ("closing", amount(row.closing)),
            ],
        ));
    }
    for movement in &report.movements {
        checks.push(Check::pass(
            "roll_forward_movement",
            "recomputation",
            vec![
                ("entry_digest", h(&movement.entry_digest)),
                ("leg_index", n(u64::from(movement.leg_index))),
                ("recorded_seq", n(movement.recorded_seq)),
                ("effective_day", day(Some(movement.effective_day))),
                ("account", s(format!("{:032x}", movement.account_id))),
                ("unit", n(u64::from(movement.unit_id))),
                ("class", n(u64::from(movement.bucket.class))),
                ("reason_code", s(&movement.bucket.reason_code)),
                (
                    "rule_digest",
                    movement
                        .bucket
                        .rule_digest
                        .as_ref()
                        .map_or(Json::Null, |digest| h(digest)),
                ),
                ("debits", amount(movement.debits)),
                ("credits", amount(movement.credits)),
            ],
        ));
    }
    checks
}

fn cash_activity(activity: crate::report::CashFlowActivity) -> &'static str {
    use crate::report::CashFlowActivity;
    match activity {
        CashFlowActivity::Operating => "operating",
        CashFlowActivity::Investing => "investing",
        CashFlowActivity::Financing => "financing",
        CashFlowActivity::ExchangeEffect => "exchange_effect",
        CashFlowActivity::InternalTransfer => "internal_transfer",
    }
}

fn cash_basis(basis: crate::report::CashFlowDecisionBasis) -> &'static str {
    use crate::report::CashFlowDecisionBasis;
    match basis {
        CashFlowDecisionBasis::AccountRules => "account_rules",
        CashFlowDecisionBasis::ExplicitOverride => "explicit_override",
        CashFlowDecisionBasis::InternalTransfer => "internal_transfer",
    }
}

fn cash_section(section: crate::report::CashFlowSection) -> Json {
    Json::Obj(vec![
        ("inflows", amount(section.inflows)),
        ("outflows", amount(section.outflows)),
        ("net", amount(section.net)),
    ])
}

fn cash_flow_checks(report: &crate::report::VerifiedCashFlow) -> Vec<Check> {
    let ledger = &report.ledger;
    let mut checks = vec![Check::pass(
        "cash_flow_parameters",
        "authenticated_parameters",
        vec![
            ("book", h(&ledger.book_id)),
            ("known_at", n(ledger.known_at)),
            ("label", s(&ledger.label)),
            ("definition", s(&report.definition.name)),
            ("effective_from", day(Some(ledger.effective_from))),
            ("effective_through", day(Some(ledger.effective_through))),
            (
                "source_certificate_digest",
                h(&report.source_certificate_digest),
            ),
            (
                "units",
                Json::List(
                    ledger
                        .units
                        .iter()
                        .map(|&unit| n(u64::from(unit)))
                        .collect(),
                ),
            ),
            (
                "cash_accounts",
                Json::List(
                    report
                        .definition
                        .cash_accounts
                        .iter()
                        .map(|id| s(format!("{id:032x}")))
                        .collect(),
                ),
            ),
            (
                "amount_basis",
                s("registered native units; debit minus credit; no cross-unit conversion"),
            ),
            (
                "gross_basis",
                s("net only within original entry, native unit and activity section"),
            ),
            (
                "running_balance_basis",
                s("effective-day order, then recorded sequence and original leg citation"),
            ),
            ("economic_classification", s("not_judged")),
            ("cash_equivalence", s("not_judged")),
            ("definition_approval", s("not_judged")),
        ],
    )];
    for account in &ledger.accounts {
        checks.push(Check::pass(
            "cash_flow_account",
            "authenticated_metadata",
            vec![
                ("account", s(format!("{:032x}", account.id))),
                ("code", s(&account.code)),
                ("name", s(&account.name)),
                ("account_type", n(u64::from(account.account_type))),
                ("is_leaf", Json::Bool(account.is_leaf)),
            ],
        ));
    }
    for (index, bucket) in ledger.buckets.iter().enumerate() {
        checks.push(Check::pass(
            "cash_flow_bucket",
            "recomputation",
            vec![
                ("bucket", n(index as u64)),
                ("class", n(u64::from(bucket.class))),
                ("reason_code", s(&bucket.reason_code)),
                (
                    "rule_digest",
                    bucket
                        .rule_digest
                        .as_ref()
                        .map_or(Json::Null, |digest| h(digest)),
                ),
                ("rule_execution", s("not_judged")),
            ],
        ));
    }
    for (index, cell) in ledger.cells.iter().enumerate() {
        checks.push(Check::pass(
            "cash_flow_cell",
            "recomputation",
            vec![
                ("cell", n(index as u64)),
                ("account", s(format!("{:032x}", cell.account_id))),
                ("unit", n(u64::from(cell.unit_id))),
                ("opening", amount(cell.opening)),
                ("debits", amount(cell.debits)),
                ("credits", amount(cell.credits)),
                ("net_change", amount(cell.net_change)),
                ("closing", amount(cell.closing)),
                ("line_start", n(u64::from(cell.line_start))),
                ("line_end", n(u64::from(cell.line_end))),
            ],
        ));
    }
    let activities: std::collections::BTreeMap<_, _> = report
        .definition
        .assignments
        .iter()
        .map(|assignment| {
            (
                (assignment.entry_digest, assignment.leg_index),
                assignment.activity,
            )
        })
        .collect();
    for line in &ledger.lines {
        checks.push(Check::pass(
            "cash_flow_movement",
            "recomputation",
            vec![
                ("cell", n(u64::from(line.cell_index))),
                ("entry_digest", h(&line.entry_digest)),
                ("leg_index", n(u64::from(line.leg_index))),
                ("recorded_seq", n(line.recorded_seq)),
                ("effective_day", day(Some(line.effective_day))),
                ("bucket", n(u64::from(line.bucket_index))),
                ("debits", amount(line.debits)),
                ("credits", amount(line.credits)),
                ("running_balance", amount(line.running_balance)),
                (
                    "activity",
                    activities
                        .get(&(line.entry_digest, line.leg_index))
                        .map_or(Json::Null, |&activity| s(cash_activity(activity))),
                ),
            ],
        ));
    }
    for unit in &report.units {
        checks.push(Check::pass(
            "cash_flow_unit",
            "recomputation",
            vec![
                ("unit", n(u64::from(unit.unit_id))),
                ("opening", amount(unit.opening)),
                ("operating", cash_section(unit.operating)),
                ("investing", cash_section(unit.investing)),
                ("financing", cash_section(unit.financing)),
                ("exchange_effects", cash_section(unit.exchange_effects)),
                ("net_change", amount(unit.net_change)),
                ("closing", amount(unit.closing)),
            ],
        ));
    }
    if let Some(verified) = &report.policy {
        checks.push(Check::pass(
            "cash_flow_policy",
            "authenticated_parameters",
            vec![
                ("source_certificate_digest", h(&verified.source_certificate_digest)),
                ("name", s(&verified.policy.name)),
                ("cash_accounts", Json::List(verified.policy.cash_accounts.iter().map(|id| s(format!("{id:032x}"))).collect())),
                ("decision_basis", s("every original nonzero counterpart in the same entry and native unit, plus explicit overrides")),
                ("policy_approval", s("not_judged")),
            ],
        ));
        for rule in &verified.policy.account_rules {
            checks.push(Check::pass(
                "cash_flow_rule",
                "authenticated_parameters",
                vec![
                    ("account", s(format!("{:032x}", rule.account_id))),
                    ("activity", s(cash_activity(rule.activity))),
                    ("historical_account", s("existing monetary leaf")),
                ],
            ));
        }
        for assignment in &verified.policy.overrides {
            checks.push(Check::pass(
                "cash_flow_override",
                "authenticated_parameters",
                vec![
                    ("entry_digest", h(&assignment.entry_digest)),
                    ("leg_index", n(u64::from(assignment.leg_index))),
                    ("activity", s(cash_activity(assignment.activity))),
                ],
            ));
        }
        for decision in &verified.decisions {
            checks.push(Check::pass(
                "cash_flow_decision",
                "recomputation",
                vec![
                    ("entry_digest", h(&decision.entry_digest)),
                    ("leg_index", n(u64::from(decision.leg_index))),
                    ("activity", s(cash_activity(decision.activity))),
                    ("basis", s(cash_basis(decision.basis))),
                ],
            ));
        }
    }
    checks
}

fn statement_checks(
    statement: &crate::report::VerifiedStatement,
    unit_universe_source: &str,
) -> Vec<Check> {
    let authenticated_registry = unit_universe_source == "authenticated-registry";
    let mut checks = vec![Check::pass(
        "statement_parameters",
        if authenticated_registry {
            "authenticated_parameters"
        } else {
            "recipient_selected_units"
        },
        vec![
            ("definition", s(&statement.definition_name)),
            ("definition_digest", h(&statement.definition_digest)),
            ("kind", s(statement.kind)),
            ("unit_universe_source", s(unit_universe_source)),
            (
                "units",
                Json::List(
                    statement
                        .units
                        .iter()
                        .map(|unit| n(u64::from(*unit)))
                        .collect(),
                ),
            ),
            (
                "unit_registration",
                s(if authenticated_registry {
                    "canonical registry closure bound to a trusted certificate pin or signed receipt; journaled activation not verified"
                } else {
                    "not authenticated by the checkpoint prefix"
                }),
            ),
            ("unit_labels", s("not verified")),
            (
                "definition_authority",
                s(if authenticated_registry {
                    "bound to a recipient-selected certificate digest or signed production receipt"
                } else {
                    "report parameter; independent approval is not established"
                }),
            ),
        ],
    )];
    checks.push(Check::pass(
        "statement_definition",
        "recomputation",
        vec![
            ("name", s(&statement.definition_name)),
            ("version", n(u64::from(statement.definition_version))),
            ("definition_digest", h(&statement.definition_digest)),
            ("mapped_accounts", n(statement.mappings.len() as u64)),
        ],
    ));
    for column in &statement.columns {
        checks.push(Check::pass(
            "statement_column",
            "recomputation",
            vec![
                ("label", s(&column.label)),
                (
                    "periods",
                    Json::List(column.periods.iter().map(s).collect()),
                ),
                ("effective_from", day(column.effective_from)),
                ("effective_through", day(Some(column.effective_through))),
            ],
        ));
    }
    for line in &statement.lines {
        checks.push(Check::pass(
            "statement_line",
            "recomputation",
            vec![
                ("code", s(&line.code)),
                ("label", s(&line.label)),
                ("unit", n(u64::from(line.unit))),
                (
                    "amounts",
                    Json::List(
                        line.amounts
                            .iter()
                            .map(|amount| s(amount.to_string()))
                            .collect(),
                    ),
                ),
            ],
        ));
    }
    checks
}

/// The bundle's checks, then the extract's: exactly the proven selection.
fn ads_checks(report: &AdsReport, name: &'static str) -> Vec<Check> {
    let mut checks = bundle_checks(&report.bundle);
    let detail = vec![
        ("effective_through", s(report.effective_through.as_str())),
        ("known_at_seq", report.known_at_seq.map_or(Json::Null, n)),
        (
            "account_scope",
            report.account_scope.as_deref().map_or(Json::Null, s),
        ),
        ("entries", n(report.entries)),
        ("rows", n(report.rows)),
        ("tb_rows", n(report.tb_rows)),
        ("chart_rows", report.chart_rows.map_or(Json::Null, n)),
        (
            "units",
            Json::List(
                report
                    .units
                    .iter()
                    .map(|(code, id)| {
                        Json::Obj(vec![
                            ("code", s(code.as_str())),
                            ("unit_id", Json::Int(i64::from(*id))),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    checks.push(if report.verified() {
        Check::pass(name, "completeness", detail)
    } else {
        Check {
            name,
            scope: "completeness",
            verdict: if report.bundle.verified() {
                Verdict::Fail
            } else {
                Verdict::Unrun
            },
            detail,
            reason: Some(report.failures.join("; ")),
        }
    });
    checks
}

/// The bundle's identity, then every graded predicate in report order.
fn bundle_checks(report: &BundleReport) -> Vec<Check> {
    let m = &report.manifest;
    let scope = match &m.scope {
        BundleScope::Prefix => s("prefix"),
        BundleScope::Account(c) => Json::Obj(vec![
            ("account", s(format!("0x{:032x}", c.account))),
            ("from", Json::Int(i64::from(c.from))),
            ("to", Json::Int(i64::from(c.to))),
        ]),
        BundleScope::Entries(leaves) => Json::Obj(vec![(
            "leaves",
            Json::List(leaves.iter().map(|i| n(*i)).collect()),
        )]),
    };
    let mut checks = vec![Check::pass(
        "bundle",
        "format",
        vec![
            ("bundle_digest", h(&report.digest)),
            (
                "format",
                s(format!(
                    "{}.{}",
                    report.summary.format.0, report.summary.format.1
                )),
            ),
            ("book_id", h(&m.book_id)),
            ("branch_id", h(&m.branch_id)),
            ("through_seq", n(m.through_seq)),
            ("leaf_count", n(m.leaf_count)),
            ("checkpoint_oid", h(&m.checkpoint_oid)),
            ("scope", scope),
            ("completeness", s(m.completeness.label())),
            ("entries", n(report.summary.entries)),
            ("documents", n(report.summary.documents)),
            ("inline", n(report.summary.inline)),
            ("balances", n(report.summary.balances.len() as u64)),
        ],
    )];
    for c in &report.checks {
        let (verdict, reason) = match &c.grade {
            Grade::Pass => (Verdict::Pass, None),
            Grade::Fail(why) => (Verdict::Fail, Some(why.clone())),
            Grade::Unrun(why) => (Verdict::Unrun, Some(why.clone())),
        };
        let mut detail = vec![("subject", s(&c.subject))];
        if c.check == "production_receipt"
            && let Some(r) = &report.receipt
        {
            detail.extend([
                (
                    "producer_principal",
                    s(format!("0x{:032x}", r.producer_principal)),
                ),
                ("produced_at_seq", n(r.produced_at_seq)),
                ("capability_commitment", h(&r.capability_commitment)),
                (
                    "time_evidence_oid",
                    r.time_evidence_oid.map_or_else(
                        || s("absent (interim: TimeEvidence is not yet bound)"),
                        |o| h(&o),
                    ),
                ),
                ("signed_by", h(&r.signed_by)),
            ]);
        }
        checks.push(Check {
            name: c.check,
            scope: c.scope,
            verdict,
            detail,
            reason,
        });
    }
    checks
}

fn unreachable_command(cmd: &str) -> Result<Vec<Check>, Usage> {
    let hint = closest(cmd, &COMMANDS).map_or_else(
        || "run `fa-verify --help`".to_string(),
        |c| format!("did you mean `{c}`?"),
    );
    Err(usage(format!("unknown command `{cmd}`"), hint))
}

/// Run `fa-verify` with `args` (without the program name), reading input
/// files through `read`.
pub fn run(args: &[String], read: Read<'_>) -> Output {
    let help = args.is_empty()
        || args.iter().any(|a| a == "--help" || a == "-h")
        || args.first().is_some_and(|a| a == "help");
    if help {
        return Output {
            exit: EXIT_VERIFIED,
            stdout: USAGE.to_string(),
            stderr: String::new(),
        };
    }
    let json = args.iter().any(|a| a == "--json");
    let parsed = match parse(args) {
        Ok(p) => p,
        Err(u) => return usage_output("", json, &u),
    };
    if parsed.command.is_empty() {
        return usage_output("", json, &usage("no command", "run `fa-verify --help`"));
    }
    match run_command(&parsed, read) {
        Ok(checks) => report(&parsed.command, parsed.json, &checks),
        Err(u) => usage_output(&parsed.command, parsed.json, &u),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconciliation_renders_discrepancies_as_verified_data_with_exact_amounts() {
        use crate::report::*;
        let report = VerifiedAgingReconciliation {
            book_id: [3; 16],
            known_at: 9,
            effective_through: 40,
            account: VerifiedReportAccount {
                account: 9,
                code: "ar".into(),
                name: "Receivable".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: OpenItemUnitPolicy::AnyCurrency,
                limit: None,
                created_at: 2,
            },
            aging: VerifiedAging {
                book_id: [3; 16],
                known_at: 9,
                effective_through: 40,
                account_filter: Some(9),
                source_certificate_digest: [4; 32],
                bands: vec![],
                items: vec![],
                cells: vec![],
                totals: vec![],
            },
            control_rows: vec![],
            rows: vec![VerifiedAgingReconciliationRow {
                unit_id: 7,
                posted_debits: i128::MAX,
                posted_credits: 0,
                pending_debits: 27,
                pending_credits: 0,
                open_debits: 10,
                open_credits: 0,
                open_item_count: 1,
                posted_net: i128::MAX,
                open_net: 10,
                difference: i128::MAX - 10,
            }],
            aging_certificate_digest: [5; 32],
            control_certificate_digest: [6; 32],
        };
        let checks = reconciliation_checks(&report);
        assert_eq!(
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            [
                "aging_reconciliation",
                "aging_reconciliation_account",
                "aging_reconciliation_row",
            ]
        );
        assert!(
            checks
                .iter()
                .all(|check| matches!(check.verdict, Verdict::Pass))
        );
        let mut json = String::new();
        for check in checks {
            check.json().write(&mut json);
        }
        for expected in [
            format!("\"posted_debits\":\"{}\"", i128::MAX),
            format!("\"difference\":\"{}\"", i128::MAX - 10),
            "\"pending_debits\":\"27\"".into(),
            "\"reconciled\":false".into(),
            "\"unit\":7".into(),
            format!("\"aging_certificate_digest\":\"{}\"", "05".repeat(32)),
            format!("\"control_certificate_digest\":\"{}\"", "06".repeat(32)),
            "\"external_subledger\":\"not judged\"".into(),
        ] {
            assert!(json.contains(&expected), "{expected}: {json}");
        }
    }

    #[test]
    fn balance_explanation_renders_exact_history_and_authenticated_provenance() {
        use crate::report::{
            ExplanationCell, ExplanationCellChange, ExplanationColumn, ExplanationContribution,
            ExplanationEvidence, ExplanationReason, ExplanationSupersession, OpenItemUnitPolicy,
            VerifiedBalanceExplanation, VerifiedReportAccount,
        };
        let report = VerifiedBalanceExplanation {
            account: 9,
            account_row: VerifiedReportAccount {
                account: 9,
                code: "cash".into(),
                name: "Cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: OpenItemUnitPolicy::Single(1),
                limit: None,
                created_at: 2,
            },
            period: "P1".into(),
            known_at: 9,
            fold_digest: [3; 32],
            watermark: Some(9),
            cells: vec![ExplanationCell {
                account: 9,
                unit_id: 1,
                period: "P1".into(),
                debits: 0,
                credits: i128::MAX,
                entry_count: 1,
            }],
            pending: vec![],
            contributions: vec![ExplanationContribution {
                entry: 2,
                entry_digest: [4; 32],
                class: 4,
                effective_date: 10,
                recorded_at: 9,
                visible_at: 9,
                ordinal: 0,
                debit: false,
                unit_id: 1,
                mantissa: i128::MAX,
                column: ExplanationColumn::Posted,
                released_at: None,
                resolves: None,
                supersedes: vec![ExplanationSupersession {
                    target: 1,
                    entry_digest: [5; 32],
                    kind: 1,
                    reason_code: 1,
                }],
                evidence: vec![ExplanationEvidence {
                    document_oid: [7; 32],
                    doc_commit: [8; 32],
                    role: 2,
                }],
            }],
            history: vec![ExplanationCellChange {
                recorded_at: 9,
                unit_id: 1,
                debits: 0,
                credits: i128::MAX,
                debits_pending: 0,
                credits_pending: 0,
            }],
            supersession_reasons: std::collections::BTreeMap::from([(
                1,
                ExplanationReason {
                    code: 1,
                    name: "Historical name".into(),
                    meaning: "Historical reason meaning".into(),
                },
            )]),
        };
        let checks = explanation_checks(&report);
        assert_eq!(
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            [
                "balance_explanation",
                "balance_explanation_account",
                "balance_explanation_fold",
                "balance_explanation_cell",
                "balance_contribution",
                "balance_contribution_supersession",
                "balance_contribution_evidence",
                "balance_history",
            ]
        );
        let mut json = String::new();
        for check in checks {
            Json::Obj(check.detail).write(&mut json);
        }
        for expected in [
            format!("\"mantissa\":\"{}\"", i128::MAX),
            format!("\"credits\":\"{}\"", i128::MAX),
            "\"reason_code\":1".into(),
            "\"reason_name\":\"Historical name\"".into(),
            "\"reason_meaning\":\"Historical reason meaning\"".into(),
            "\"entry_count\":1".into(),
            "\"scope\":\"whole selected period\"".into(),
            format!("\"document_oid\":\"{}\"", "07".repeat(32)),
            format!("\"doc_commit\":\"{}\"", "08".repeat(32)),
            "\"evidence_heads\":\"committed citations; document authenticity not judged\"".into(),
        ] {
            assert!(json.contains(&expected), "{expected}: {json}");
        }
    }

    #[test]
    fn roll_forward_renders_exact_signed_rows_and_complete_classified_citations() {
        use crate::report::*;
        let bucket = RollForwardBucket {
            class: 4,
            reason_code: "supersession:1,2".into(),
            rule_digest: Some([7; 32]),
        };
        let report = VerifiedRollForward {
            book_id: [3; 16],
            known_at: 9,
            label: "Lead schedule".into(),
            effective_from: 10,
            effective_through: 40,
            source_certificate_digest: [4; 32],
            accounts: vec![RollForwardAccount {
                id: 1,
                code: "1000".into(),
                name: "Cash".into(),
                account_type: 1,
                is_leaf: true,
            }],
            units: vec![0],
            buckets: vec![bucket.clone()],
            rows: vec![RollForwardRow {
                account_id: 1,
                unit_id: 0,
                opening: i128::MAX,
                activity: vec![-i128::MAX],
                net_change: -i128::MAX,
                closing: 0,
            }],
            movements: vec![RollForwardMovement {
                entry_digest: [5; 32],
                leg_index: 2,
                recorded_seq: 8,
                effective_day: 30,
                account_id: 1,
                unit_id: 0,
                bucket,
                debits: 0,
                credits: i128::MAX,
            }],
        };
        let checks = roll_forward_checks(&report);
        assert_eq!(
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            [
                "roll_forward_parameters",
                "roll_forward_account",
                "roll_forward_bucket",
                "roll_forward_row",
                "roll_forward_movement",
            ]
        );
        let render = |index: usize| {
            let mut value = String::new();
            Json::Obj(checks[index].detail.clone()).write(&mut value);
            value
        };
        assert!(render(0).contains("rule execution not judged"));
        assert!(render(2).contains("\"reason_code\":\"supersession:1,2\""));
        assert!(render(2).contains(&format!("\"rule_digest\":\"{}\"", "07".repeat(32))));
        assert!(render(3).contains(&format!("\"activity\":[\"{}\"]", -i128::MAX)));
        assert!(render(3).contains(&format!("\"opening\":\"{}\"", i128::MAX)));
        assert!(render(4).contains("\"recorded_seq\":8"));
        assert!(render(4).contains("\"leg_index\":2"));
        assert!(render(4).contains(&format!("\"entry_digest\":\"{}\"", "05".repeat(32))));
        assert!(render(4).contains(&format!("\"credits\":\"{}\"", i128::MAX)));
    }

    #[test]
    fn cash_flow_renders_exact_gross_sections_gl_and_policy_derivation() {
        use crate::report::*;
        let assignment = CashFlowAssignment {
            entry_digest: [5; 32],
            leg_index: 2,
            activity: CashFlowActivity::Operating,
        };
        let mut report = VerifiedCashFlow {
            source_certificate_digest: [4; 32],
            ledger: VerifiedGeneralLedger {
                book_id: [3; 16],
                known_at: 9,
                label: "Cash source".into(),
                effective_from: 10,
                effective_through: 40,
                accounts: vec![RollForwardAccount {
                    id: 1,
                    code: "1000".into(),
                    name: "Cash".into(),
                    account_type: 1,
                    is_leaf: true,
                }],
                units: vec![0, 7],
                buckets: vec![RollForwardBucket {
                    class: 4,
                    reason_code: "supersession:1".into(),
                    rule_digest: Some([7; 32]),
                }],
                cells: vec![
                    GeneralLedgerCell {
                        account_id: 1,
                        unit_id: 0,
                        opening: i128::MAX,
                        debits: 0,
                        credits: i128::MAX,
                        net_change: -i128::MAX,
                        closing: 0,
                        line_start: 0,
                        line_end: 1,
                    },
                    GeneralLedgerCell {
                        account_id: 1,
                        unit_id: 7,
                        opening: 0,
                        debits: 0,
                        credits: 0,
                        net_change: 0,
                        closing: 0,
                        line_start: 1,
                        line_end: 1,
                    },
                ],
                lines: vec![GeneralLedgerLine {
                    cell_index: 0,
                    entry_digest: [5; 32],
                    leg_index: 2,
                    recorded_seq: 8,
                    effective_day: 30,
                    bucket_index: 0,
                    debits: 0,
                    credits: i128::MAX,
                    running_balance: 0,
                }],
            },
            definition: CashFlowDefinition {
                name: "Cash policy €".into(),
                cash_accounts: vec![1],
                assignments: vec![assignment.clone()],
            },
            units: vec![
                CashFlowUnit {
                    unit_id: 0,
                    opening: i128::MAX,
                    operating: CashFlowSection {
                        inflows: 0,
                        outflows: i128::MAX,
                        net: -i128::MAX,
                    },
                    investing: CashFlowSection::default(),
                    financing: CashFlowSection::default(),
                    exchange_effects: CashFlowSection::default(),
                    net_change: -i128::MAX,
                    closing: 0,
                },
                CashFlowUnit {
                    unit_id: 7,
                    opening: 0,
                    operating: CashFlowSection::default(),
                    investing: CashFlowSection::default(),
                    financing: CashFlowSection::default(),
                    exchange_effects: CashFlowSection::default(),
                    net_change: 0,
                    closing: 0,
                },
            ],
            policy: Some(VerifiedCashFlowPolicy {
                source_certificate_digest: [6; 32],
                policy: CashFlowPolicy {
                    name: "Cash policy €".into(),
                    cash_accounts: vec![1],
                    account_rules: vec![CashFlowAccountRule {
                        account_id: 9,
                        activity: CashFlowActivity::Investing,
                    }],
                    overrides: vec![assignment],
                },
                decisions: vec![CashFlowPolicyDecision {
                    entry_digest: [5; 32],
                    leg_index: 2,
                    activity: CashFlowActivity::Operating,
                    basis: CashFlowDecisionBasis::ExplicitOverride,
                }],
            }),
        };
        let checks = cash_flow_checks(&report);
        assert_eq!(
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            [
                "cash_flow_parameters",
                "cash_flow_account",
                "cash_flow_bucket",
                "cash_flow_cell",
                "cash_flow_cell",
                "cash_flow_movement",
                "cash_flow_unit",
                "cash_flow_unit",
                "cash_flow_policy",
                "cash_flow_rule",
                "cash_flow_override",
                "cash_flow_decision",
            ]
        );
        let render = |index: usize| {
            let mut value = String::new();
            Json::Obj(checks[index].detail.clone()).write(&mut value);
            value
        };
        assert!(render(0).contains("\"economic_classification\":\"not_judged\""));
        assert!(render(0).contains("\"units\":[0,7]"));
        assert!(render(2).contains("\"reason_code\":\"supersession:1\""));
        assert!(render(3).contains(&format!("\"credits\":\"{}\"", i128::MAX)));
        assert!(render(4).contains("\"line_start\":1,\"line_end\":1"));
        assert!(render(5).contains(&format!("\"entry_digest\":\"{}\"", "05".repeat(32))));
        assert!(render(5).contains("\"recorded_seq\":8"));
        assert!(render(5).contains("\"leg_index\":2"));
        assert!(render(5).contains("\"running_balance\":\"0\""));
        assert!(render(6).contains(&format!(
            "\"operating\":{{\"inflows\":\"0\",\"outflows\":\"{}\",\"net\":\"{}\"}}",
            i128::MAX,
            -i128::MAX
        )));
        assert!(render(7).contains("\"unit\":7,\"opening\":\"0\""));
        assert!(render(8).contains(&format!(
            "\"source_certificate_digest\":\"{}\"",
            "06".repeat(32)
        )));
        assert!(render(9).contains("\"activity\":\"investing\""));
        assert!(render(11).contains("\"basis\":\"explicit_override\""));
        report.policy = None;
        assert_eq!(cash_flow_checks(&report).len(), 8);
        assert_eq!(
            cash_basis(CashFlowDecisionBasis::AccountRules),
            "account_rules"
        );
        assert_eq!(
            cash_basis(CashFlowDecisionBasis::InternalTransfer),
            "internal_transfer"
        );
    }

    #[test]
    fn aging_renders_effective_age_bands_exact_totals_and_undone_applications() {
        use crate::report::*;
        let amounts = VerifiedAgingAmounts {
            debits: i128::MAX,
            credits: 0,
            item_count: 1,
        };
        let report = VerifiedAging {
            book_id: [3; 16],
            known_at: 9,
            effective_through: 40,
            account_filter: Some(9),
            source_certificate_digest: [4; 32],
            bands: vec![VerifiedAgingBand {
                lower_inclusive: 0,
                upper_inclusive: None,
            }],
            items: vec![VerifiedAgedOpenItem {
                item: VerifiedOpenItem {
                    entry: 1,
                    ordinal: 0,
                    account: 9,
                    unit_id: 1,
                    debit: true,
                    effective_date: 10,
                    recorded_at: 3,
                    original: i128::MAX,
                    applied: 0,
                    applied_out: 0,
                    open: i128::MAX,
                    applications: vec![VerifiedApplication {
                        entry: 2,
                        ordinal: 1,
                        amount: 40,
                        recorded_at: 4,
                        live: false,
                    }],
                },
                age_days: 30,
                bucket: 0,
            }],
            cells: vec![VerifiedAgingCell {
                account: 9,
                unit_id: 1,
                bucket: 0,
                amounts: amounts.clone(),
            }],
            totals: vec![VerifiedAgingTotal {
                account: 9,
                unit_id: 1,
                amounts,
            }],
        };
        let checks = aging_checks(&report);
        assert_eq!(
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            [
                "aging_parameters",
                "aging_band",
                "aging_item",
                "aging_application",
                "aging_cell",
                "aging_total",
            ]
        );
        let render = |index: usize| {
            let mut rendered = String::new();
            Json::Obj(checks[index].detail.clone()).write(&mut rendered);
            rendered
        };
        assert!(render(0).contains("no contractual due date inferred"));
        assert!(render(1).contains("\"upper_inclusive\":null"));
        assert!(render(2).contains(&format!("\"open\":\"{}\"", i128::MAX)));
        assert!(render(2).contains("\"age_days\":30"));
        assert!(render(3).contains("\"live\":false"));
        assert!(render(4).contains(&format!("\"debits\":\"{}\"", i128::MAX)));
        assert!(render(5).contains("\"credits\":\"0\""));
    }

    #[test]
    fn open_items_render_exact_amounts_and_undone_application_history() {
        let report = crate::report::VerifiedOpenItems {
            account_filter: Some(9),
            accounts: std::collections::BTreeMap::new(),
            items: vec![crate::report::VerifiedOpenItem {
                entry: 1,
                ordinal: 0,
                account: 9,
                unit_id: 1,
                debit: true,
                effective_date: 10,
                recorded_at: 3,
                original: i128::MAX,
                applied: 0,
                applied_out: 0,
                open: i128::MAX,
                applications: vec![crate::report::VerifiedApplication {
                    entry: 2,
                    ordinal: 1,
                    amount: 40,
                    recorded_at: 4,
                    live: false,
                }],
            }],
        };
        let checks = open_items_checks(&report);
        assert_eq!(
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            [
                "open_items_parameters",
                "open_item",
                "open_item_application"
            ]
        );
        let mut rendered = String::new();
        Json::Obj(checks[1].detail.clone()).write(&mut rendered);
        assert!(rendered.contains(&format!("\"open\":\"{}\"", i128::MAX)));
        rendered.clear();
        Json::Obj(checks[2].detail.clone()).write(&mut rendered);
        assert!(rendered.contains("\"live\":false"));
        assert!(rendered.contains("\"amount\":\"40\""));
    }
    use std::collections::BTreeMap;

    const ACCUMULATOR: &str = include_str!("../tests/fixtures/accumulator_v1.txt");
    const CHECKPOINT: &str = include_str!("../tests/fixtures/checkpoint_v1.txt");
    const BUNDLE: &str = include_str!("../tests/fixtures/bundle_v1.txt");

    /// The pinned vectors as an in-memory file system (hex text, so the
    /// tests also exercise `--hex`).
    fn files() -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        for line in ACCUMULATOR
            .lines()
            .chain(CHECKPOINT.lines())
            .chain(BUNDLE.lines())
        {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let (name, hexed) = line.split_once(' ').unwrap();
            out.insert(name.to_string(), hexed.as_bytes().to_vec());
        }
        out
    }

    fn key_hex() -> String {
        String::from_utf8(files()["public_key"].clone()).unwrap()
    }

    fn run_with(args: &[&str], fs: &BTreeMap<String, Vec<u8>>) -> Output {
        let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        let read = |p: &str| {
            fs.get(p)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))
        };
        run(&args, &read)
    }

    /// `bundle` grades every predicate: the pinned bundles verify with the
    /// pinned key, the prefix bundle with its receipt; a receipt over
    /// another bundle fails only its own check; another key fails the
    /// checkpoint and leaves what rests on it unrun (exit 8); a missing key
    /// and `--receipt` on another command are usage (exit 2).
    #[test]
    fn bundles_are_graded_predicate_by_predicate() {
        let fs = files();
        let key = key_hex();
        for name in ["bundle_prefix", "bundle_account", "bundle_entries"] {
            let out = run_with(&["bundle", name, "--key", &key, "--hex", "--json"], &fs);
            assert_eq!(out.exit, 0, "{name}: {}", out.stdout);
            assert!(
                out.stdout.contains("\"verdict\":\"verified\""),
                "{}",
                out.stdout
            );
        }
        let with_receipt: [&str; 7] = [
            "bundle",
            "bundle_prefix",
            "--key",
            &key,
            "--receipt",
            "receipt",
            "--hex",
        ];
        let out = run_with(&with_receipt, &fs);
        assert_eq!(out.exit, 0, "{}", out.stdout);
        assert!(
            out.stdout.contains("PASS production_receipt (production)"),
            "{}",
            out.stdout
        );
        let mut elsewhere = with_receipt;
        elsewhere[1] = "bundle_account";
        let out = run_with(&elsewhere, &fs);
        assert_eq!(out.exit, 8);
        assert_eq!(out.stdout.matches("FAIL ").count(), 1, "{}", out.stdout);
        assert!(
            out.stdout.contains("FAIL production_receipt"),
            "{}",
            out.stdout
        );
        let other = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let out = run_with(
            &[
                "bundle",
                "bundle_entries",
                "--key",
                other,
                "--hex",
                "--json",
            ],
            &fs,
        );
        assert_eq!(out.exit, 8);
        assert!(
            out.stdout.contains("\"result\":\"unrun\""),
            "{}",
            out.stdout
        );
        assert_eq!(run_with(&["bundle", "bundle_prefix", "--hex"], &fs).exit, 2);
        let out = run_with(
            &[
                "checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--receipt",
                "receipt",
                "--hex",
            ],
            &fs,
        );
        assert_eq!(out.exit, 2);
        assert!(
            out.stderr
                .contains("`--receipt` does not apply to `checkpoint`"),
            "{}",
            out.stderr
        );
    }

    #[test]
    fn help_is_exit_zero_and_names_every_command() {
        for args in [&[][..], &["--help"][..], &["help"][..]] {
            let out = run_with(args, &files());
            assert_eq!(out.exit, 0);
            for c in COMMANDS {
                assert!(out.stdout.contains(c), "{c}");
            }
        }
    }

    /// Every command over the pinned vectors verifies, in both modes, and
    /// the JSON report is one deterministic line naming each check's scope.
    #[test]
    fn the_pinned_vectors_verify_through_every_command() {
        let fs = files();
        let key = key_hex();
        let cases: Vec<Vec<&str>> = vec![
            vec!["state", "state"],
            vec!["checkpoint", "checkpoint", "--key", &key],
            vec![
                "inclusion",
                "inclusion",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
            ],
            vec![
                "prefix",
                "prefix",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
            ],
            vec![
                "balance",
                "balance",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
            ],
            vec![
                "scope",
                "scope",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--account",
                "0x10",
                "--from",
                "20527",
                "--to",
                "20527",
                "--prefix",
                "prefix",
            ],
            vec![
                "scope",
                "scope_empty",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--account",
                "32",
                "--from",
                "20528",
                "--to",
                "20600",
            ],
        ];
        for case in cases {
            let mut args = case.clone();
            args.push("--hex");
            let text = run_with(&args, &fs);
            assert_eq!(text.exit, 0, "{case:?}: {}{}", text.stdout, text.stderr);
            assert!(text.stdout.contains("VERIFIED"), "{}", text.stdout);
            args.push("--json");
            let json = run_with(&args, &fs);
            assert_eq!(json.exit, 0, "{case:?}");
            assert!(
                json.stdout.starts_with("{\"v\":1,\"tool\":\"fa-verify\""),
                "{}",
                json.stdout
            );
            assert!(json.stdout.contains("\"verdict\":\"verified\""));
            assert_eq!(json.stdout.lines().count(), 1);
            assert_eq!(run_with(&args, &fs), json, "deterministic");
        }
        let scope = run_with(
            &[
                "scope",
                "scope",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--account",
                "0x10",
                "--from",
                "20527",
                "--to",
                "20527",
                "--prefix",
                "prefix",
                "--hex",
                "--json",
            ],
            &fs,
        );
        assert!(scope.stdout.contains("\"scope\":\"scope_index_complete\""));
        assert!(scope.stdout.contains("recomputed from the complete prefix"));
        let balance = run_with(
            &[
                "balance",
                "balance",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--hex",
                "--json",
            ],
            &fs,
        );
        assert!(balance.stdout.contains("\"scope\":\"membership_only\""));
    }

    #[test]
    fn report_expectation_is_a_digest_and_invalid_syntax_precedes_io() {
        let key = key_hex();
        // This digest is a small-order curve encoding. Digests are not keys:
        // successful syntax admission must reach the nonexistent bundle file.
        let digest = "00".repeat(32);
        let missing = |_: &str| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "fixture"));
        let args = [
            "report", "missing", "--key", &key, "--expect", &digest, "--json",
        ]
        .map(str::to_string);
        assert_eq!(run(&args, &missing).exit, EXIT_IO);
        let no_read = |_: &str| -> std::io::Result<Vec<u8>> {
            panic!("invalid report digest must refuse before any file read")
        };
        let malformed = [
            "report",
            "missing",
            "--key",
            &key,
            "--expect",
            "not-a-digest",
        ]
        .map(str::to_string);
        assert_eq!(run(&malformed, &no_read).exit, EXIT_USAGE);
    }

    #[test]
    fn statement_unit_input_is_bounded_canonical_and_refused_before_io() {
        let key = key_hex();
        let no_read = |_: &str| -> std::io::Result<Vec<u8>> {
            panic!("invalid statement unit parameters must refuse before file I/O")
        };
        for units in [
            "",
            ",",
            "0,",
            "0,,1",
            "1,0",
            "0,0",
            "-1",
            "+1",
            "1.0",
            "0, 1",
            "4294967296",
        ] {
            let args = [
                "report", "missing", "--key", &key, "--units", units, "--json",
            ]
            .map(str::to_string);
            let output = run(&args, &no_read);
            assert_eq!(output.exit, EXIT_USAGE, "{units}: {}", output.stdout);
        }
        for count in [4095, 4096] {
            let input = (0..count)
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let parsed =
                statement_units(&input).unwrap_or_else(|_| panic!("valid boundary {count}"));
            assert_eq!(parsed.len(), count);
        }
        let oversized = (0..4097)
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let args = ["report", "missing", "--key", &key, "--units", &oversized].map(str::to_string);
        assert_eq!(run(&args, &no_read).exit, EXIT_USAGE);
        assert_eq!(
            statement_units("0,1,4294967295").unwrap_or_else(|_| panic!("u32 boundary")),
            vec![0, 1, u32::MAX]
        );
        let misplaced = ["bundle", "missing", "--key", &key, "--units", "0"].map(str::to_string);
        assert_eq!(run(&misplaced, &no_read).exit, EXIT_USAGE);
        let repeated = [
            "report", "missing", "--key", &key, "--units", "0", "--units", "1",
        ]
        .map(str::to_string);
        assert_eq!(run(&repeated, &no_read).exit, EXIT_USAGE);
        let missing = |_: &str| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "fixture"));
        let valid = ["report", "missing", "--key", &key, "--units", "0,1"].map(str::to_string);
        assert_eq!(run(&valid, &missing).exit, EXIT_IO);
    }

    #[test]
    fn statement_result_preserves_exact_columns_and_declares_unit_premise() {
        let statement = crate::report::VerifiedStatement {
            definition_name: "income-statement".into(),
            definition_version: 1,
            definition_digest: [7; 32],
            mappings: Vec::new(),
            kind: "IncomeStatement",
            columns: vec![
                crate::report::StatementColumn {
                    label: "current".into(),
                    periods: vec!["FY2026-P01".into()],
                    effective_from: Some(20_454),
                    effective_through: 20_484,
                },
                crate::report::StatementColumn {
                    label: "comparative".into(),
                    periods: vec!["FY2025-P01".into()],
                    effective_from: Some(20_089),
                    effective_through: 20_119,
                },
            ],
            lines: vec![crate::report::StatementLine {
                code: "income".into(),
                label: "Net income".into(),
                unit: 0,
                amounts: vec![i128::MAX, i128::MIN],
            }],
            units: vec![0, 1],
        };
        let checks = statement_checks(&statement, "recipient-supplied");
        let output = report("report", true, &checks);
        assert_eq!(output.exit, EXIT_VERIFIED);
        assert!(
            output
                .stdout
                .contains("\"unit_universe_source\":\"recipient-supplied\"")
        );
        assert!(
            output
                .stdout
                .contains("not authenticated by the checkpoint prefix")
        );
        assert!(
            output
                .stdout
                .contains("independent approval is not established")
        );
        assert!(output.stdout.contains("\"units\":[0,1]"));
        assert!(output.stdout.contains("\"label\":\"comparative\""));
        assert!(output.stdout.contains("\"periods\":[\"FY2025-P01\"]"));
        assert!(output.stdout.contains(&format!(
            "\"amounts\":[\"{}\",\"{}\"]",
            i128::MAX,
            i128::MIN
        )));
        let human = report("report", false, &checks);
        assert!(human.stdout.contains("statement_line (recomputation)"));
        assert!(human.stdout.contains("recipient-supplied"));
        assert!(human.stdout.contains(&i128::MIN.to_string()));
    }

    /// A tampered artifact, an untrusted key, or a question the proof does
    /// not answer each exit 8 with the failing check named; nothing about
    /// the artifact ever exits 0 or 2 then.
    #[test]
    fn tampered_artifacts_and_wrong_questions_exit_8() {
        let key = key_hex();
        let mut fs = files();
        let flip = |fs: &mut BTreeMap<String, Vec<u8>>, name: &str, at: usize| {
            let v = fs.get_mut(name).unwrap();
            v[at] = if v[at] == b'0' { b'1' } else { b'0' };
        };
        flip(&mut fs, "checkpoint", 200);
        let out = run_with(
            &[
                "prefix",
                "prefix",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--hex",
                "--json",
            ],
            &fs,
        );
        assert_eq!(out.exit, 8, "{}", out.stdout);
        assert!(out.stdout.contains("\"verdict\":\"failed\""));
        assert!(
            out.stdout
                .contains("\"check\":\"checkpoint\",\"scope\":\"signature\",\"result\":\"fail\"")
        );

        let fs = files();
        // A valid key that did not sign (RFC 8032 TEST 1's public key).
        let other = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let out = run_with(&["checkpoint", "checkpoint", "--key", other, "--hex"], &fs);
        assert_eq!(out.exit, 8);
        assert!(
            out.stdout.contains("no signature by a key you trust"),
            "{}",
            out.stdout
        );
        // A key that cannot be trusted at all (the identity, a small-order
        // point) is refused at admission (ruling 3392), as usage.
        let identity = format!("01{}", "00".repeat(31));
        let out = run_with(
            &["checkpoint", "checkpoint", "--key", &identity, "--hex"],
            &fs,
        );
        assert_eq!(out.exit, 2, "{}", out.stderr);
        assert!(out.stderr.contains("small-order"), "{}", out.stderr);

        let mut fs = files();
        flip(&mut fs, "inclusion", 300);
        let out = run_with(
            &[
                "inclusion",
                "inclusion",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--hex",
            ],
            &fs,
        );
        assert_eq!(out.exit, 8, "{}", out.stdout);
        assert!(out.stdout.contains("PASS checkpoint") && out.stdout.contains("FAIL inclusion"));

        let fs = files();
        let out = run_with(
            &[
                "scope",
                "scope",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--account",
                "0x10",
                "--from",
                "20527",
                "--to",
                "20528",
                "--hex",
            ],
            &fs,
        );
        assert_eq!(out.exit, 8, "another question");
        assert!(
            out.stdout.contains("another scope than the one asked"),
            "{}",
            out.stdout
        );

        let out = run_with(
            &[
                "doc-commit",
                "state",
                "--kind",
                "1",
                "--expect",
                &"00".repeat(32),
                "--hex",
            ],
            &fs,
        );
        assert_eq!(out.exit, 8);
    }

    /// Usage errors exit 2, name what was wrong and how to fix it, and
    /// suggest the closest command or flag.
    #[test]
    fn usage_errors_exit_2_and_name_the_fix() {
        let fs = files();
        let key = key_hex();
        let out = run_with(&["chekpoint", "checkpoint", "--key", &key], &fs);
        assert_eq!(out.exit, 2);
        assert!(
            out.stderr.contains("did you mean `checkpoint`?"),
            "{}",
            out.stderr
        );
        let out = run_with(&["checkpoint", "checkpoint", "--kye", &key], &fs);
        assert_eq!(out.exit, 2);
        assert!(
            out.stderr.contains("did you mean `--key`?"),
            "{}",
            out.stderr
        );
        let out = run_with(&["checkpoint", "checkpoint", "--hex"], &fs);
        assert_eq!(out.exit, 2);
        assert!(out.stderr.contains("--key"), "{}", out.stderr);
        let out = run_with(
            &[
                "prefix",
                "missing",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--hex",
                "--json",
            ],
            &fs,
        );
        assert_eq!(out.exit, 5, "an unreadable input is I/O (5), not usage");
        assert!(
            out.stdout.contains("\"verdict\":\"io_error\"")
                && out.stdout.contains("cannot read `missing`")
        );
        let out = run_with(
            &[
                "scope",
                "scope",
                "--checkpoint",
                "checkpoint",
                "--key",
                &key,
                "--hex",
            ],
            &fs,
        );
        assert_eq!(out.exit, 2, "a scope needs the caller's question");
        let out = run_with(&["state", "state"], &fs);
        assert_eq!(
            out.exit, 8,
            "hex text read as raw bytes does not decode: a verification failure"
        );
    }

    #[test]
    fn json_strings_are_escaped() {
        let mut out = String::new();
        Json::Str("a\"b\\c\nd\u{1}".into()).write(&mut out);
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\u0001\"");
        assert_eq!(distance("chekpoint", "checkpoint"), 1);
        assert_eq!(distance("--kye", "--key"), 1);
    }
}
