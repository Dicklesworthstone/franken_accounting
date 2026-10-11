//! The unsigned entry accumulator on the CLI (plan §13.2, fa-l3c).
//!
//! These commands publish and recompute the existing Notary state objects.
//! They do not issue a signed TransparencyCheckpoint or an evidence bundle.

use crate::json::{Json, obj, s};
use fa_policy::{Capability, Op};

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, principal, unhandled, usage};

fn arguments(args: &Args, example: &str) -> Result<(), Fail> {
    if let Some(extra) = args.positional.get(2) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    for flag in ["--period", "--fiscal-year"] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!(
                    "{flag} cannot select an accumulator checkpoint; each state covers an entry prefix"
                ),
                example,
            ));
        }
    }
    Ok(())
}

pub(crate) fn checkpoint_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("create") {
        return Err(unhandled(
            "checkpoint",
            args.positional.get(1).map(String::as_str),
        ));
    }
    const EXAMPLE: &str = "fa checkpoint create --grant witness --book <dir> --json";
    arguments(args, EXAMPLE)?;
    // The local CLI binds an explicit grant to its operator, like posting.
    // Refuse missing authority before opening or observing the book; the
    // facade independently enforces the same boundary for library callers.
    let actor = principal(args);
    let capability = Capability::embedded(actor, &args.flag_all("--grant"))
        .map_err(|error| usage(error.to_string(), EXAMPLE))?;
    // The book is not open yet, so its id (the `books` caveat's subject) is
    // unknown here; a self-issued embedded capability is Human, the actor's,
    // and carries no `books` caveat, so admission reduces to the op check.
    // The facade's admission judges the whole intent, book included.
    fa_policy::require(&capability, Op::Witness, "writing this intent (`witness`)")
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    let mut book = ctx.books.open(args)?;
    let created = book.checkpoint(actor, &capability)??;
    ctx.out.at_book(&book)?;
    let stored = &created.stored;
    let state = &stored.state;
    ctx.out.event(
        "checkpoint_created",
        vec![
            ("book", s(hex(&state.book_id.0))),
            ("branch", s(hex(&state.branch_id.0))),
            ("oid", s(hex(&stored.oid.0))),
            ("recorded_at", Json::Int(i128::from(stored.recorded_at.0))),
            ("through_seq", Json::Int(i128::from(state.through_seq.0))),
            ("leaf_count", Json::Int(i128::from(state.leaf_count))),
            ("root", s(hex(&state.root))),
            ("prev_state_oid", state.prev_state_oid.map_or(Json::Null, |oid| s(hex(&oid.0)))),
            ("signatures", s("unsigned")),
            ("scope", s("entry_prefix")),
        ],
        &format!(
            "Created unsigned entry accumulator checkpoint {}: {} entries through sequence {}, recorded at {}. Root {}.",
            hex(&stored.oid.0), state.leaf_count, state.through_seq.0,
            stored.recorded_at.0, hex(&state.root),
        ),
    );
    Ok(())
}

pub(crate) fn verify_accumulator(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    arguments(args, "fa verify accumulator --book <dir> --json")?;
    let book = ctx.books.open(args)?;
    let result = book.verify_accumulator()?;
    let green = result.is_green();
    let through = if green {
        result.states.first().map(|state| state.through_seq.0)
    } else {
        None
    };
    let status = if !green {
        "failed"
    } else if result.states.is_empty() {
        "no_checkpoints"
    } else {
        "verified"
    };
    let states = result
        .states
        .iter()
        .map(|state| {
            obj(vec![
                ("oid", s(hex(&state.oid.0))),
                ("through_seq", Json::Int(i128::from(state.through_seq.0))),
                ("recorded_at", Json::Int(i128::from(state.recorded_at.0))),
                ("leaf_count", Json::Int(i128::from(state.leaf_count))),
                ("finding", state.finding.as_ref().map_or(Json::Null, s)),
            ])
        })
        .collect();
    let fields = vec![
        ("status", s(status)),
        ("signatures", s("unsigned")),
        ("scope", s("entry_prefix")),
        ("states_checked", Json::Int(result.states.len() as i128)),
        ("broken", result.broken.as_ref().map_or(Json::Null, s)),
        (
            "verified_through",
            through.map_or(Json::Null, |seq| Json::Int(i128::from(seq))),
        ),
        ("states", Json::Arr(states)),
        (
            "unchained",
            Json::Arr(
                result
                    .unchained
                    .iter()
                    .map(|vid| s(format!("{:032x}", vid.0)))
                    .collect(),
            ),
        ),
    ];
    if !green {
        let findings = result
            .states
            .iter()
            .filter(|state| state.finding.is_some())
            .count();
        return Err(Fail::Verification {
            message: format!(
                "entry accumulator differs from the journal: {findings} state findings, {} unchained states{}",
                result.unchained.len(),
                result
                    .broken
                    .as_ref()
                    .map_or_else(String::new, |why| format!("; broken chain: {why}")),
            ),
            detail: obj(fields),
            cite: None,
            fix: None,
        });
    }
    let human = match through {
        None => "No accumulator checkpoints to verify; run `fa checkpoint create --grant witness`."
            .to_string(),
        Some(seq) => format!(
            "Entry accumulator verified by recomputation: {} checkpoints through sequence {seq} (unsigned).",
            result.states.len(),
        ),
    };
    ctx.out.event("accumulator_verified", fields, &human);
    Ok(())
}
