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

use crate::blake3::hex;
use crate::bundle::{BundleReport, BundleScope, Grade, verify_bundle};
use crate::checkpoint::{SignedCheckpoint, verify_checkpoint};
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

const USAGE: &str = "\
fa-verify — the dependency-free verifier (FrankenAccounting plan §13.3)

usage: fa-verify <command> <file> [options] [--json] [--hex]

commands:
  state        <state>                          an AccumulatorState's bytes on their own
  checkpoint   <checkpoint> --key K...          a TransparencyCheckpoint signed by a trusted key
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
  --json         one JSON report on stdout (robot mode)
  --hex          read every input file as hexadecimal text

Input files are limited to 64 MiB. No book, network or other program is used.
exit codes: 0 verified · 2 usage · 5 file I/O · 8 verification failed
";

const COMMANDS: [&str; 9] = [
    "state",
    "checkpoint",
    "inclusion",
    "prefix",
    "balance",
    "scope",
    "consistency",
    "doc-commit",
    "bundle",
];

/// Flags that take a value, and the switches.
const VALUE_FLAGS: [&str; 13] = [
    "--key",
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
];
const SWITCHES: [&str; 3] = ["--json", "--hex", "--unsigned-checkpoint"];

/// The flags each command admits beyond `--json` and `--hex`. Anything else
/// is refused before a file is opened.
fn admitted(command: &str) -> &'static [&'static str] {
    match command {
        "checkpoint" => &["--key"],
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
        "bundle" => &["--key", "--receipt"],
        _ => &[],
    }
}

// ---- a minimal deterministic JSON writer -----------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Null,
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
            if flag != "--key" && values.iter().any(|(f, _)| *f == flag) {
                return Err(usage(
                    format!("`{flag}` may be supplied only once"),
                    format!("pass one `{flag}`; only `--key` repeats"),
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
            let bytes = load(read, file, args.hex)?;
            Ok(vec![checkpoint_check(&verify_checkpoint(&bytes, &keys))])
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
        _ => unreachable_command(cmd),
    }
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
            out.stderr.contains("applies to `bundle` only"),
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
        assert!(balance.stdout.contains("\"scope\":\"recomputation\""));
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
