//! `fa principal key new|add` (plan §14.5 non-repudiation, bead fa-kae): a
//! principal's Ed25519 signing key, made and held by the client, and its
//! registration as the next generation of the principal's key chain. Once a
//! principal has a key, `fa approve --proposal <digest> --sign-key <file>`
//! signs its approvals; the kernel refuses its unsigned ones.
//!
//! Both read or write a secret on the host, so neither runs inside `fad`
//! (the daemon never holds a principal's key) and neither is an MCP tool.

use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{Ctx, Fail, date_flag, hex, usage};
use crate::json::{Json, s};

const NEW_EXAMPLE: &str = "fa principal key new --out <new key file> --json";
const ADD_EXAMPLE: &str = "fa principal key add --sign-key <key file> [--endorse-key <current key file>] [--as <principal>] [--date YYYY-MM-DD] [--key K] [--description <text>] --book <dir> --json";
const KEY_FIX: &str = "make one with fa principal key new --out <new file>";

/// `fa principal …`.
pub(crate) fn principal_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let action = args.positional.get(2).map(String::as_str);
    match (args.positional.get(1).map(String::as_str), action) {
        (Some("key"), Some("new")) => key_new(ctx, args),
        (Some("key"), Some("add")) => key_add(ctx, args),
        _ => Err(usage(
            "principal key takes new or add",
            format!("{NEW_EXAMPLE}, then {ADD_EXAMPLE}"),
        )),
    }
}

/// A signing key is the client's: refuse to read one inside `fad`.
pub(crate) fn refuse_in_daemon(ctx: &Ctx<'_>, flag: &str) -> Result<(), Fail> {
    if ctx.routed_through_daemon() {
        return Err(usage(
            format!(
                "{flag} names a principal's signing key, which the client holds and fad never reads"
            ),
            "run this command with --via direct (stop the book's fad first if it holds the writer lease)",
        ));
    }
    Ok(())
}

/// A principal's key file ([`crate::notary::load_key_file`]).
pub(crate) fn load_principal_key(
    ctx: &Ctx<'_>,
    args: &Args,
    flag: &str,
) -> Result<Option<fa::SigningKey>, Fail> {
    match args.flag_all(flag).as_slice() {
        [] => Ok(None),
        [path] => {
            refuse_in_daemon(ctx, flag)?;
            crate::notary::load_key_file(&ctx.files, path, "a principal key file", KEY_FIX)
                .map(Some)
        }
        _ => Err(usage(format!("only one {flag}"), ADD_EXAMPLE)),
    }
}

/// `fa principal key new --out <new file>`: a new Ed25519 key from the
/// operating system's entropy in a new 0600 file. No book is opened.
fn key_new(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 3 || args.flag_all("--out").len() != 1 {
        return Err(usage(
            "principal key new takes exactly one --out and no other argument",
            NEW_EXAMPLE,
        ));
    }
    refuse_in_daemon(ctx, "--out")?;
    let out = args.require("--out", "a new file for the key")?;
    let public = crate::notary::write_new_key_file(&ctx.files, out, "principal key", NEW_EXAMPLE)?;
    let key_id = fa_policy::principal_key::key_id(&public);
    ctx.out.event(
        "principal_key_created",
        vec![
            ("public_key", s(hex(&public))),
            ("key_id", s(hex(&key_id))),
            ("out", s(out)),
        ],
        &format!(
            "Principal key written to {out} (0600). Register it with fa principal key add --sign-key {out}; key id {}.",
            hex(&key_id)
        ),
    );
    Ok(())
}

/// `fa principal key add --sign-key <file> [--endorse-key <file>]`: journal
/// the key as the next generation of the acting principal's chain, proved
/// by the key itself and, to rotate, endorsed by the current key.
fn key_add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 3 {
        return Err(usage(
            "principal key add takes no positional argument",
            ADD_EXAMPLE,
        ));
    }
    let key = load_principal_key(ctx, args, "--sign-key")?
        .ok_or_else(|| usage("principal key add needs --sign-key <key file>", ADD_EXAMPLE))?;
    let endorse = load_principal_key(ctx, args, "--endorse-key")?;
    let capability = ctx.capability(args, &["approve"])?;
    let principal = capability.holder();
    let mut book = ctx.books.open(args)?;
    let chain = book.principal_keys(principal)?;
    // Re-adding a key the chain holds is a retry: it answers with the
    // recorded generation, endorsed as it was.
    let retry = chain.iter().any(|g| g.key.public_key == key.public_key());
    match (chain.len(), &endorse) {
        _ if retry => {}
        (0, Some(_)) => {
            return Err(usage(
                "the principal has no signing key yet, so there is nothing to endorse with",
                "register the first key with --sign-key alone",
            ));
        }
        (n, None) if n > 0 => {
            return Err(usage(
                format!(
                    "the principal already has {n} key generation(s): a new key must be endorsed by the current one"
                ),
                "add --endorse-key <the current key file>",
            ));
        }
        _ => {}
    }
    let default_date = book
        .spec()?
        .opening_date
        .or_else(|| book.periods().ok()?.first().map(|p| p.start))
        .unwrap_or(DateDay(0));
    let date = date_flag(args, default_date)?;
    let public = key.public_key();
    let key_id = fa_policy::principal_key::key_id(&public);
    let idempotency_key = args.flag("--key").map_or_else(
        || [b"principal-key:".as_slice(), &key_id].concat(),
        |k| k.as_bytes().to_vec(),
    );
    let default_desc = format!("principal signing key {}", hex(&key_id));
    let description = args.flag("--description").unwrap_or(&default_desc);
    let registered = book.register_principal_key(
        capability,
        &key,
        endorse.as_ref(),
        date,
        &idempotency_key,
        description,
    )??;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "principal_key_registered",
        vec![
            ("principal", s(format!("{:032x}", principal.0))),
            ("generation", Json::Int(i128::from(registered.generation))),
            ("key_id", s(hex(&registered.key_id))),
            ("public_key", s(hex(&public))),
            (
                "control_entry",
                s(format!("{:032x}", registered.control_entry.0)),
            ),
            (
                "recorded_at",
                Json::Int(i128::from(registered.recorded_at.0)),
            ),
            ("already_recorded", Json::Bool(registered.already_recorded)),
        ],
        &format!(
            "signing key {} is generation {} of principal {:032x} ({}); its approvals must now be signed with it",
            hex(&registered.key_id),
            registered.generation,
            principal.0,
            if registered.already_recorded {
                "already recorded"
            } else {
                "recorded"
            }
        ),
    );
    Ok(())
}
