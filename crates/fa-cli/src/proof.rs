//! Export existing Notary formats for the independent `fa-verify` executable.

use std::io::Write;

use fa::{ProofKind, ProofRequest};
use fa_model::{Oid, account_vid};
use fa_policy::Op;
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa proof signed-checkpoint|checkpoint|inclusion|consistency|prefix|balance --state <oid|latest> [--out <new-file>] --json";

fn fixed_hex<const N: usize>(text: &str, what: &str) -> Result<[u8; N], Fail> {
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(usage(
            format!("{what} requires exactly {} hexadecimal digits", N * 2),
            EXAMPLE,
        ));
    }
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| usage(format!("invalid {what} hexadecimal input"), EXAMPLE))?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| usage(format!("invalid {what} hexadecimal input"), EXAMPLE))?;
    }
    Ok(result)
}

fn required<'a>(args: &'a Args, flag: &str) -> Result<&'a str, Fail> {
    args.flag(flag)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| {
            usage(
                format!("proof {} requires {flag}", args.positional[1]),
                EXAMPLE,
            )
        })
}

pub(crate) fn proof_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage("proof needs exactly one proof kind", EXAMPLE));
    }
    let kind = args.positional[1].as_str();
    for flag in [
        "--state",
        "--next-state",
        "--entry",
        "--account",
        "--unit",
        "--as-of",
        "--out",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("proof takes only one {flag}"), EXAMPLE));
        }
    }
    if args
        .switches
        .iter()
        .filter(|flag| *flag == "--with-record")
        .count()
        > 1
    {
        return Err(usage("proof takes --with-record only once", EXAMPLE));
    }
    let applicable: &[&str] = match kind {
        "signed-checkpoint" | "checkpoint" | "prefix" => &[],
        "inclusion" => &["--entry"],
        "consistency" => &["--next-state"],
        "balance" => &["--account", "--unit", "--as-of"],
        _ => return Err(usage(format!("unknown proof kind {kind}"), EXAMPLE)),
    };
    for flag in ["--next-state", "--entry", "--account", "--unit", "--as-of"] {
        if args.flag(flag).is_some() && !applicable.contains(&flag) {
            return Err(usage(
                format!("{flag} does not apply to proof {kind}"),
                EXAMPLE,
            ));
        }
    }
    if args.switch("--with-record") && kind != "inclusion" {
        return Err(usage(
            "--with-record applies only to inclusion proofs",
            EXAMPLE,
        ));
    }
    let state = match args.flag("--state") {
        None | Some("latest") => None,
        Some(text) => Some(Oid(fixed_hex(text, "--state")?)),
    };
    let entry = if kind == "inclusion" {
        let text = required(args, "--entry")?;
        let bytes = fixed_hex::<16>(text.strip_prefix("E:").unwrap_or(text), "--entry")?;
        Some(VId(u128::from_be_bytes(bytes)))
    } else {
        None
    };
    let next_state = if kind == "consistency" {
        Some(Oid(fixed_hex(
            required(args, "--next-state")?,
            "--next-state",
        )?))
    } else {
        None
    };
    let account = if kind == "balance" {
        Some(required(args, "--account")?)
    } else {
        None
    };
    let unit = if kind == "balance" {
        Some(required(args, "--unit")?)
    } else {
        None
    };
    let cutoff = args
        .flag("--as-of")
        .map(|text| {
            DateDay::parse(text).map_err(|e| {
                usage(
                    format!("--as-of: {e}"),
                    "pass an inclusive civil date YYYY-MM-DD",
                )
            })
        })
        .transpose()?;
    let output = args.flag("--out");
    if output.is_some_and(|path| path.is_empty() || path == "-") {
        return Err(usage(
            "--out names a new binary file; - is not an output file",
            "omit --out to receive the complete proof as inline hex",
        ));
    }
    // A bound MCP host reuses its launch capability. Only the ordinary
    // embedded-owner route supplies these implied read/production operations.
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "produce"])?;
    for op in [Op::Read, Op::Produce] {
        fa_policy::require(&capability, op, "exporting accounting proofs")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let book = ctx.books.open(args)?;
    let proof_kind = match kind {
        "checkpoint" => ProofKind::Checkpoint,
        "signed-checkpoint" => ProofKind::SignedCheckpoint,
        "prefix" => ProofKind::Prefix,
        "inclusion" => ProofKind::Inclusion {
            entry: entry.ok_or_else(|| usage("--entry is required", EXAMPLE))?,
            with_record: args.switch("--with-record"),
        },
        "consistency" => ProofKind::Consistency {
            next_state: next_state.ok_or_else(|| usage("--next-state is required", EXAMPLE))?,
        },
        "balance" => {
            let code = account.ok_or_else(|| usage("--account is required", EXAMPLE))?;
            let unit_code = unit.ok_or_else(|| usage("--unit is required", EXAMPLE))?;
            let unit = book.context().units.lookup(unit_code).ok_or_else(|| {
                usage(
                    format!("unit {unit_code} is not registered in this book"),
                    "use an exact unit code from this book's canonical registry",
                )
            })?;
            ProofKind::Balance {
                account: account_vid(book.context().book_id, code),
                unit,
                effective_through: cutoff,
            }
        }
        _ => return Err(usage("unknown proof kind", EXAMPLE)),
    };
    let artifact = book.export_proof(
        principal,
        &capability,
        ProofRequest {
            state,
            kind: proof_kind,
        },
    )??;
    // Hex doubles wire size. Keep room for the JSON response envelope and
    // checkpoint metadata; file exports retain the full 64 MiB binary limit.
    let max_inline = crate::verbs::registry()
        .map_err(|e| Fail::Internal(e.into()))?
        .daemon
        .max_frame_bytes
        .saturating_sub(32 * 1024)
        / 2;
    if output.is_none() && artifact.bytes.len() > max_inline {
        return Err(fa_journal::Refusal::new(
            fa::proof::code::PROOF_EXPORT_LIMIT,
            fa_journal::exit::USAGE,
            "the proof is too large for the inline JSON transport",
            "plan §13.1–§13.3 (complete proofs are never truncated)",
            "the owner can export a binary --out file; a bound MCP caller must select an earlier checkpoint or an inclusion proof",
        ).into());
    }
    if let Some(path) = output {
        write_new(
            &ctx.files.resolve(path),
            path,
            &artifact.bytes,
            "proof",
            "--out",
        )?;
    }
    let state = &artifact.checkpoint;
    let checkpoint = fa::proof::checkpoint_bytes(state)?;
    let next_bytes = artifact
        .next_checkpoint
        .as_ref()
        .map(fa::proof::checkpoint_bytes)
        .transpose()?;
    let claim = match proof_kind {
        ProofKind::Inclusion { entry, with_record } => obj(vec![
            ("entry", s(format!("{:032x}", entry.0))),
            ("with_record", Json::Bool(with_record)),
        ]),
        ProofKind::Balance {
            account,
            unit,
            effective_through,
        } => obj(vec![
            ("account", s(format!("{:032x}", account.0))),
            ("unit", Json::Int(i128::from(unit.0))),
            (
                "effective_through",
                effective_through.map_or(Json::Null, |day| s(day.to_string())),
            ),
        ]),
        _ => obj(vec![]),
    };
    ctx.out.at_book(&book)?;
    ctx.out.known_at(state.state.through_seq);
    if let Some(day) = cutoff {
        ctx.out.effective(format!("as-of:{day}"));
    }
    let encoded = output.is_none().then(|| hex(&artifact.bytes));
    let public_key = hex(&book.checkpoint_public_key());
    let signed = matches!(proof_kind, ProofKind::SignedCheckpoint);
    let trust_note = if signed {
        format!(
            "This is the signed TransparencyCheckpoint; check it with `fa-verify checkpoint <file> --key {public_key}`, and judge proofs against it with `--checkpoint <file> --key {public_key}`."
        )
    } else {
        format!(
            "Judge it against the state's signed checkpoint (`fa proof signed-checkpoint`) with `--key {public_key}`, or against the raw statement with `--unsigned-checkpoint` once you trust that statement independently."
        )
    };
    let human = format!(
        "Exported {} (scope: {}) from checkpoint {} through sequence {}: {} bytes{}.\n{trust_note}{}",
        proof_kind.name(),
        proof_kind.scope(),
        hex(&state.oid.0),
        state.state.through_seq.0,
        artifact.bytes.len(),
        output.map_or_else(String::new, |path| format!(" in {path}")),
        encoded
            .as_ref()
            .map_or_else(String::new, |bytes| format!("\nProof bytes (hex): {bytes}")),
    );
    ctx.out.event(
        "proof_exported",
        vec![
            ("kind", s(proof_kind.name())),
            ("scope", s(proof_kind.scope())),
            ("state_oid", s(hex(&state.oid.0))),
            ("recorded_at", Json::Int(i128::from(state.recorded_at.0))),
            (
                "through_seq",
                Json::Int(i128::from(state.state.through_seq.0)),
            ),
            ("leaf_count", Json::Int(i128::from(state.state.leaf_count))),
            ("root", s(hex(&state.state.root))),
            ("checkpoint_bytes", s(hex(&checkpoint))),
            (
                "next_state_oid",
                artifact
                    .next_checkpoint
                    .as_ref()
                    .map_or(Json::Null, |next| s(hex(&next.oid.0))),
            ),
            (
                "next_checkpoint_bytes",
                next_bytes
                    .as_ref()
                    .map_or(Json::Null, |bytes| s(hex(bytes))),
            ),
            ("signatures", s(if signed { "ed25519" } else { "unsigned" })),
            (
                "trust",
                s(if signed {
                    "checkpoint_public_key"
                } else {
                    "external_checkpoint_required"
                }),
            ),
            ("checkpoint_public_key", s(&public_key)),
            ("claim", claim),
            ("byte_len", Json::Int(artifact.bytes.len() as i128)),
            ("bytes", encoded.as_ref().map_or(Json::Null, s)),
            ("file", output.map_or(Json::Null, s)),
        ],
        &human,
    );
    Ok(())
}

/// Write `bytes` to a new private file (`0600`); an existing path is never
/// overwritten.
fn write_new(
    target: &std::path::Path,
    path: &str,
    bytes: &[u8],
    what: &str,
    flag: &str,
) -> Result<(), Fail> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(target).map_err(|e| {
        Fail::Io(format!("cannot create {what} file {path}: {e}; choose a new {flag} path; an existing file is never overwritten"))
    })?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| {
        Fail::Io(format!("could not finish {what} file {path}: {e}; preserve the partial file and retry with a new path"))
    })
}

const BUNDLE_EXAMPLE: &str = "fa bundle produce [--state <oid|latest>] [--account <code> --from YYYY-MM-DD --to YYYY-MM-DD | --entry <vid>...] [--balance <code>:<UNIT>[:YYYY-MM-DD]]... [--inline-documents] [--out <new.fab> --receipt-out <new-file>] --json";

/// `fa bundle produce` (plan §13.2): an evidence bundle over a recorded
/// state's prefix (the default), one account's effective-day interval, or
/// named entries, with optional recomputed balances, and its detached
/// production receipt signed by the book's key. Nothing is written to the
/// book; `fa-verify bundle <file> --key <checkpoint_public_key> --receipt
/// <receipt>` checks both offline.
pub(crate) fn bundle_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("produce") || args.positional.len() != 2 {
        return Err(usage("bundle has one subcommand: produce", BUNDLE_EXAMPLE));
    }
    for flag in [
        "--state",
        "--account",
        "--from",
        "--to",
        "--out",
        "--receipt-out",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("bundle takes only one {flag}"),
                BUNDLE_EXAMPLE,
            ));
        }
    }
    let state = match args.flag("--state") {
        None | Some("latest") => None,
        Some(text) => Some(Oid(fixed_hex(text, "--state")?)),
    };
    let entries = args.flag_all("--entry");
    let account = args.flag("--account");
    let interval = (args.flag("--from"), args.flag("--to"));
    if account.is_some() && !entries.is_empty() {
        return Err(usage(
            "a bundle has one scope: --account with --from/--to, or --entry, or neither (the complete prefix)",
            BUNDLE_EXAMPLE,
        ));
    }
    if account.is_none() && (interval.0.is_some() || interval.1.is_some()) {
        return Err(usage(
            "--from and --to bound an --account scope",
            BUNDLE_EXAMPLE,
        ));
    }
    let day = |flag: &str, text: Option<&str>| -> Result<i32, Fail> {
        let text = text.ok_or_else(|| {
            usage(
                format!("an --account scope needs {flag} YYYY-MM-DD"),
                BUNDLE_EXAMPLE,
            )
        })?;
        DateDay::parse(text).map(|d| d.0).map_err(|e| {
            usage(
                format!("{flag}: {e}"),
                "pass an inclusive civil date YYYY-MM-DD",
            )
        })
    };
    let output = args.flag("--out");
    let receipt_output = args.flag("--receipt-out");
    if output.is_some() != receipt_output.is_some() {
        return Err(usage(
            "--out and --receipt-out go together: the receipt is the bundle's detached signature",
            BUNDLE_EXAMPLE,
        ));
    }
    for path in [output, receipt_output].into_iter().flatten() {
        if path.is_empty() || path == "-" {
            return Err(usage(
                "--out and --receipt-out name new binary files; - is not an output file",
                "omit both to receive the bundle and its receipt as inline hex",
            ));
        }
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "produce"])?;
    for op in [Op::Read, Op::Produce] {
        fa_policy::require(&capability, op, "producing an evidence bundle")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let mut book = ctx.books.open(args)?;
    let book_id = book.context().book_id;
    let scope = if let Some(code) = account {
        let from = day("--from", interval.0)?;
        let to = day("--to", interval.1)?;
        fa::BundleScope::Index(fa::ScopeRequest::Account {
            account: account_vid(book_id, code),
            from,
            to,
        })
    } else if !entries.is_empty() {
        let mut vids = Vec::with_capacity(entries.len());
        for text in &entries {
            let bytes = fixed_hex::<16>(text.strip_prefix("E:").unwrap_or(text), "--entry")?;
            vids.push(VId(u128::from_be_bytes(bytes)));
        }
        fa::BundleScope::Entries(vids)
    } else {
        fa::BundleScope::Prefix
    };
    let scope_name = match &scope {
        fa::BundleScope::Prefix => "prefix",
        fa::BundleScope::Index(_) => "account",
        fa::BundleScope::Entries(_) => "entries",
    };
    let mut balances = Vec::new();
    for spec in args.flag_all("--balance") {
        let malformed = || {
            usage(
                format!("--balance {spec}: expected <account-code>:<UNIT>[:YYYY-MM-DD]"),
                BUNDLE_EXAMPLE,
            )
        };
        let mut parts = spec.split(':');
        let (Some(code), Some(unit_code)) = (parts.next(), parts.next()) else {
            return Err(malformed());
        };
        let effective_through = parts
            .next()
            .map(|text| {
                DateDay::parse(text).map(|d| d.0).map_err(|e| {
                    usage(
                        format!("--balance {spec}: {e}"),
                        "pass an inclusive civil date YYYY-MM-DD",
                    )
                })
            })
            .transpose()?;
        if parts.next().is_some() || code.is_empty() {
            return Err(malformed());
        }
        let unit = book.context().units.lookup(unit_code).ok_or_else(|| {
            usage(
                format!("unit {unit_code} is not registered in this book"),
                "use an exact unit code from this book's canonical registry",
            )
        })?;
        balances.push(fa::BalanceRequest {
            account: account_vid(book_id, code),
            unit: unit.0,
            effective_through,
        });
    }
    let request = fa::BundleRequest {
        scope,
        balances,
        inline_documents: args.switch("--inline-documents"),
    };
    let Some(produced) = book.produce_bundle(principal, &capability, state, &request)?? else {
        return Err(fa_journal::Refusal::new(
            fa::proof::code::PROOF_STATE_UNKNOWN,
            fa_journal::exit::USAGE,
            match state {
                Some(oid) => format!(
                    "accumulator state {} is not on this book's recorded checkpoint chain",
                    hex(&oid.0)
                ),
                None => "the book has no recorded accumulator checkpoint to produce against".into(),
            },
            "plan §13.2 (a bundle is produced against a journaled AccumulatorState)",
            "use fa verify accumulator --json to find a recorded state; the owner can publish one with fa checkpoint create --grant witness",
        )
        .into());
    };
    let max_inline = crate::verbs::registry()
        .map_err(|e| Fail::Internal(e.into()))?
        .daemon
        .max_frame_bytes
        .saturating_sub(32 * 1024)
        / 2;
    if output.is_none() && produced.bundle.bytes.len() + produced.receipt.len() > max_inline {
        return Err(fa_journal::Refusal::new(
            fa::proof::code::PROOF_EXPORT_LIMIT,
            fa_journal::exit::USAGE,
            "the bundle is too large for the inline JSON transport",
            "plan §13.1–§13.3 (complete bundles are never truncated)",
            "the owner can write --out and --receipt-out files; a bound MCP caller must narrow the scope (an account interval or named entries) or drop inline documents",
        )
        .into());
    }
    if let (Some(path), Some(receipt_path)) = (output, receipt_output) {
        write_new(
            &ctx.files.resolve(path),
            path,
            &produced.bundle.bytes,
            "bundle",
            "--out",
        )?;
        write_new(
            &ctx.files.resolve(receipt_path),
            receipt_path,
            &produced.receipt,
            "receipt",
            "--receipt-out",
        )?;
    }
    let public_key = hex(&book.checkpoint_public_key());
    ctx.out.at_book(&book)?;
    let digest = hex(&produced.bundle.digest);
    let verify = match (output, receipt_output) {
        (Some(path), Some(receipt_path)) => {
            format!("fa-verify bundle {path} --key {public_key} --receipt {receipt_path}")
        }
        _ => format!(
            "write bytes and receipt to files, then: fa-verify bundle <bundle-file> --key {public_key} --receipt <receipt-file>"
        ),
    };
    let human = format!(
        "Produced evidence bundle {digest} ({} bytes, scope {scope_name}, {} balance(s)){}.\nVerify it offline: {verify}",
        produced.bundle.bytes.len(),
        request.balances.len(),
        output.map_or_else(String::new, |path| format!(" in {path}")),
    );
    let inline = |bytes: &[u8]| {
        if output.is_none() {
            s(hex(bytes))
        } else {
            Json::Null
        }
    };
    ctx.out.event(
        "bundle_produced",
        vec![
            ("scope", s(scope_name)),
            ("digest", s(&digest)),
            ("byte_len", Json::Int(produced.bundle.bytes.len() as i128)),
            ("receipt_len", Json::Int(produced.receipt.len() as i128)),
            ("balances", Json::Int(request.balances.len() as i128)),
            ("inline_documents", Json::Bool(request.inline_documents)),
            ("checkpoint_public_key", s(&public_key)),
            ("bytes", inline(&produced.bundle.bytes)),
            ("receipt", inline(&produced.receipt)),
            ("file", output.map_or(Json::Null, s)),
            ("receipt_file", receipt_output.map_or(Json::Null, s)),
            ("verify", s(&verify)),
        ],
        &human,
    );
    Ok(())
}
