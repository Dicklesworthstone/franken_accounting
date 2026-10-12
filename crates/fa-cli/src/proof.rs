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

const EXAMPLE: &str = "fa proof checkpoint|inclusion|consistency|prefix|balance --state <oid|latest> [--out <new-file>] --json";

fn fixed_hex<const N: usize>(text: &str, what: &str) -> Result<[u8; N], Fail> {
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(usage(
            format!("{what} requires exactly {} hexadecimal digits", N * 2),
            EXAMPLE,
        ));
    }
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
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
        "checkpoint" | "prefix" => &[],
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
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(ctx.files.resolve(path)).map_err(|e| {
            Fail::Io(format!("cannot create proof file {path}: {e}; choose a new --out path; an existing file is never overwritten"))
        })?;
        file.write_all(&artifact.bytes).and_then(|()| file.sync_all()).map_err(|e| {
            Fail::Io(format!("could not finish proof file {path}: {e}; preserve the partial file and retry with a new path"))
        })?;
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
    let human = format!(
        "Exported {} (scope: {}) from unsigned checkpoint {} through sequence {}: {} bytes{}.\nEstablish trust in the checkpoint separately before using fa-verify.{}",
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
            ("signatures", s("unsigned")),
            ("trust", s("external_checkpoint_required")),
            ("claim", claim),
            ("byte_len", Json::Int(artifact.bytes.len() as i128)),
            ("bytes", encoded.as_ref().map_or(Json::Null, s)),
            ("file", output.map_or(Json::Null, s)),
        ],
        &human,
    );
    Ok(())
}
