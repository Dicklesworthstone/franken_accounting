//! The `fa-verify` command line (plan §13.3: "it ships as a static binary
//! and as a library … its output is a verification report with every
//! check's result and scope label").
//!
//! ```text
//! fa-verify <command> <file> [options] [--json] [--hex]
//!
//!   state        <state>                         an AccumulatorState's bytes on their own
//!   checkpoint   <checkpoint> --key K...         a TransparencyCheckpoint signed by a trusted key
//!   inclusion    <proof> --checkpoint C --key K  an entry recorded within the checkpoint's prefix
//!   prefix       <proof> --checkpoint C --key K  the complete prefix (seq_range_complete)
//!   balance      <proof> --checkpoint C --key K  a posted balance refolded (recomputation)
//!   scope        <proof> --checkpoint C --key K --account A --from D --to D [--prefix P]
//!                                                one account's day interval (scope_index_complete)
//!   consistency  <proof> --trusted C --claimed C --key K
//!                                                the claimed checkpoint extends the trusted one
//!   doc-commit   <document> --kind N [--expect H]
//!                                                a document's public commitment from its bytes
//! ```
//!
//! Every artifact a command depends on is checked in the same run: a proof
//! is only ever judged against a checkpoint whose signature by one of the
//! `--key`s verified first, and a scope's question (`--account`, `--from`,
//! `--to`) comes from the caller, never from the proof.
//!
//! Exit codes: `0` every check passed, `8` a check failed (the artifact does
//! not verify), `2` usage (an unknown command or flag, a missing or
//! malformed argument, an unreadable file). Robot mode (`--json`) prints one
//! deterministic JSON object on stdout; otherwise the report is text. A
//! usage error in text mode goes to stderr. Bare `fa-verify`, `help` and
//! `--help` print the usage and exit `0`.
//!
//! Inputs are the artifacts' raw bytes; `--hex` reads every input file as
//! hexadecimal text instead (whitespace ignored), as the golden fixtures
//! store them.

use crate::balance::verify_balance;
use crate::blake3::hex;
use crate::checkpoint::{SignedCheckpoint, verify_checkpoint};
use crate::document::doc_commit;
use crate::envelope::LeafEnvelope;
use crate::proof::{RecordCheck, VerifyError, verify_consistency, verify_inclusion, verify_prefix};
use crate::scope::{IndexDerivation, ScopeClaim, verify_scope};
use crate::state::verify_state;

/// What a run prints and how it exits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
}

pub const EXIT_VERIFIED: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_FAILED: i32 = 8;

const USAGE: &str = "\
fa-verify — the dependency-free verifier (FrankenAccounting plan §13.3)

usage: fa-verify <command> <file> [options] [--json] [--hex]

commands:
  state        <state>                          an AccumulatorState's bytes on their own
  checkpoint   <checkpoint> --key K...          a TransparencyCheckpoint signed by a trusted key
  inclusion    <proof> --checkpoint C --key K   an entry recorded within the checkpoint's prefix
  prefix       <proof> --checkpoint C --key K   every leaf of the prefix (seq_range_complete)
  balance      <proof> --checkpoint C --key K   a posted balance refolded (recomputation)
  scope        <proof> --checkpoint C --key K --account A --from D --to D [--prefix P]
                                                one account's day interval (scope_index_complete)
  consistency  <proof> --trusted C --claimed C --key K
                                                the claimed checkpoint extends the trusted one
  doc-commit   <document> --kind N [--expect H] a document's public commitment from its bytes

options:
  --key K        a trusted Ed25519 public key, 64 hex characters (repeatable)
  --account A    an account vid: decimal, or 0x followed by up to 32 hex characters
  --from D --to D  an inclusive effective-day interval (days since 1970-01-01)
  --json         one JSON report on stdout (robot mode)
  --hex          read every input file as hexadecimal text

exit codes: 0 verified · 2 usage · 8 verification failed
";

const COMMANDS: [&str; 8] = [
    "state",
    "checkpoint",
    "inclusion",
    "prefix",
    "balance",
    "scope",
    "consistency",
    "doc-commit",
];

/// Flags that take a value, and the switches.
const VALUE_FLAGS: [&str; 10] = [
    "--key",
    "--checkpoint",
    "--trusted",
    "--claimed",
    "--account",
    "--from",
    "--to",
    "--prefix",
    "--kind",
    "--expect",
];
const SWITCHES: [&str; 2] = ["--json", "--hex"];

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

struct Check {
    name: &'static str,
    scope: &'static str,
    passed: bool,
    detail: Vec<(&'static str, Json)>,
    reason: Option<String>,
}

impl Check {
    fn pass(name: &'static str, scope: &'static str, detail: Vec<(&'static str, Json)>) -> Self {
        Self {
            name,
            scope,
            passed: true,
            detail,
            reason: None,
        }
    }

    fn fail(name: &'static str, scope: &'static str, e: &VerifyError) -> Self {
        Self {
            name,
            scope,
            passed: false,
            detail: Vec::new(),
            reason: Some(e.to_string()),
        }
    }

    fn json(&self) -> Json {
        Json::Obj(vec![
            ("check", s(self.name)),
            ("scope", s(self.scope)),
            ("result", s(if self.passed { "pass" } else { "fail" })),
            ("detail", Json::Obj(self.detail.clone())),
            ("reason", self.reason.clone().map_or(Json::Null, Json::Str)),
        ])
    }
}

struct Usage {
    message: String,
    fix: String,
}

fn usage(message: impl Into<String>, fix: impl Into<String>) -> Usage {
    Usage {
        message: message.into(),
        fix: fix.into(),
    }
}

fn report(command: &str, json: bool, checks: &[Check]) -> Output {
    let verified = !checks.is_empty() && checks.iter().all(|c| c.passed);
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
            let mark = if c.passed { "PASS" } else { "FAIL" };
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
    Output {
        exit,
        stdout,
        stderr: String::new(),
    }
}

fn usage_output(command: &str, json: bool, u: &Usage) -> Output {
    if json {
        let mut out = String::new();
        Json::Obj(vec![
            ("v", Json::Int(1)),
            ("tool", s("fa-verify")),
            ("command", s(command)),
            ("verdict", s("usage")),
            ("checks", Json::List(Vec::new())),
            (
                "error",
                Json::Obj(vec![("message", s(&u.message)), ("fix", s(&u.fix))]),
            ),
        ])
        .write(&mut out);
        out.push('\n');
        Output {
            exit: EXIT_USAGE,
            stdout: out,
            stderr: String::new(),
        }
    } else {
        Output {
            exit: EXIT_USAGE,
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
}

fn parse(args: &[String]) -> Result<Args, Usage> {
    let mut command = None;
    let mut positional = Vec::new();
    let mut values = Vec::new();
    let (mut json, mut hex) = (false, false);
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--json" {
            json = true;
        } else if a == "--hex" {
            hex = true;
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
                    args.get(i).cloned().ok_or_else(|| {
                        usage(
                            format!("`{flag}` needs a value"),
                            format!("pass `{flag} <value>`"),
                        )
                    })?
                }
            };
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

fn load(read: Read<'_>, path: &str, hex_input: bool) -> Result<Vec<u8>, Usage> {
    let bytes =
        read(path).map_err(|e| usage(format!("cannot read `{path}`: {e}"), "check the path"))?;
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

/// Verify the `--checkpoint` (or another named flag) against the `--key`s.
fn signed_checkpoint(
    args: &Args,
    flag: &str,
    read: Read<'_>,
) -> Result<Result<SignedCheckpoint, VerifyError>, Usage> {
    let path = args.one(flag).ok_or_else(|| {
        usage(
            format!("`{}` needs `{flag} <file>`", args.command),
            format!("pass the signed checkpoint the proof is against with `{flag}`"),
        )
    })?;
    let keys = args.all("--key");
    if keys.is_empty() {
        return Err(usage(
            "no trusted key: a checkpoint is judged only against keys you name",
            "pass the book's checkpoint public key with `--key <64 hex>`",
        ));
    }
    let keys: Vec<[u8; 32]> = keys.into_iter().map(key).collect::<Result<_, _>>()?;
    let bytes = load(read, path, args.hex)?;
    Ok(verify_checkpoint(&bytes, &keys))
}

fn subject<'a>(args: &'a Args, what: &str) -> Result<&'a str, Usage> {
    match args.positional.as_slice() {
        [one] => Ok(one),
        [] => Err(usage(
            format!("`{}` needs {what}", args.command),
            format!("fa-verify {} <file> …", args.command),
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
            let signed = signed_checkpoint(args, "--checkpoint", read)?;
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
            let prefix = match args.one("--prefix") {
                Some(p) if cmd == "scope" => Some(load(read, p, args.hex)?),
                Some(_) => {
                    return Err(usage(
                        "`--prefix` applies to `scope` only",
                        "drop `--prefix`",
                    ));
                }
                None => None,
            };
            let proof = load(read, proof_path, args.hex)?;
            let mut checks = vec![checkpoint_check(&signed)];
            let Ok(signed) = signed else {
                return Ok(checks);
            };
            let cp = signed.checkpoint;
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
                    match verify_scope(&proof, &signed, &claim, prefix.as_deref()) {
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
            let trusted = signed_checkpoint(args, "--trusted", read)?;
            let claimed = signed_checkpoint(args, "--claimed", read)?;
            let proof = load(read, proof_path, args.hex)?;
            let mut checks = vec![checkpoint_check(&trusted), checkpoint_check(&claimed)];
            if let (Ok(t), Ok(c)) = (&trusted, &claimed) {
                checks.push(
                    match verify_consistency(&proof, &t.checkpoint, &c.checkpoint) {
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
                    },
                );
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
                        passed: matches,
                        detail,
                        reason: (!matches).then(|| {
                            "the bytes and kind do not produce the expected doc_commit".to_string()
                        }),
                    }])
                }
            }
        }
        _ => unreachable_command(cmd),
    }
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

    /// The pinned vectors as an in-memory file system (hex text, so the
    /// tests also exercise `--hex`).
    fn files() -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        for line in ACCUMULATOR.lines().chain(CHECKPOINT.lines()) {
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
        assert_eq!(out.exit, 2);
        assert!(
            out.stdout.contains("\"verdict\":\"usage\"")
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
