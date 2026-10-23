//! `fa diff --from <seq|instant> [--to HEAD|<seq>|<instant>]` (plan §15.3,
//! Time and close): one trial-balance question (`--period`/`--fiscal-year`
//! with optional `--activity`, or `--as-of`) at two recorded frontiers, the
//! rows whose balance changed, and every entry recorded in between, whatever
//! date it carries. An entry dated into an earlier period is listed in the
//! window it was recorded in, so a reader sees what changed in the books
//! since a report was run.
//!
//! It lists every entry in the window, so it is admitted as a whole-book
//! read before anything is observed: a token carrying any scope caveat is
//! refused, never filtered.

use fa::{Book, TrialBalanceSelection};
use fa_money::{Amount, UnitId};
use fa_registry::reason_codes::ReasonCodes;
use fa_time::DateDay;
use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, admit_whole_book_read, lineage_json, render_amount, selected_periods, usage,
};
use crate::json::{Json, obj, s};

const EXAMPLE: &str =
    "fa diff --from 40 [--to HEAD] --period FY2026-P03 [--activity] --book <dir> --json";
const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;

/// A `--from`/`--to` value: `HEAD` (`None`), a commit sequence, or an
/// RFC3339 instant resolved through the book's retained time evidence.
fn frontier(args: &Args, flag: &str, book: &Book) -> Result<Option<CommitSeq>, Fail> {
    match args.flag(flag) {
        None | Some("HEAD") => Ok(None),
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => value
            .parse::<u64>()
            .map(|seq| Some(CommitSeq(seq)))
            .map_err(|_| usage(format!("{flag} commit sequence exceeds u64"), EXAMPLE)),
        Some(value) => {
            let instant = fa_time::UtcInstant::parse(value).map_err(|error| {
                usage(
                    format!("invalid {flag} selector: {error}"),
                    format!("{flag} HEAD, <u64 commit sequence>, or 2026-03-15T00:00:00Z"),
                )
            })?;
            let time = book.resolve_known_at_instant(instant.unix_ns())??;
            Ok(Some(CommitSeq(time.resolution.resolved_seq)))
        }
    }
}

pub(crate) fn diff_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 1 {
        return Err(usage("fa diff takes no positional argument", EXAMPLE));
    }
    for flag in ["--from", "--to", "--as-of", "--limit"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("{flag} may be supplied only once"), EXAMPLE));
        }
    }
    if args.flag("--from").is_none() {
        return Err(usage(
            "--from is required: the recorded sequence (or instant) the diff starts from",
            EXAMPLE,
        ));
    }
    let limit = match args.flag("--limit") {
        None => DEFAULT_LIMIT,
        Some(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=MAX_LIMIT).contains(n))
            .ok_or_else(|| usage(format!("--limit `{raw}` is not 1..={MAX_LIMIT}"), EXAMPLE))?,
    };
    let capability = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        admit_whole_book_read(book, &capability, &[], "diffing the ledger")
    })?;
    let selection = if let Some(date) = args.flag("--as-of") {
        if args.flag("--period").is_some()
            || args.flag("--fiscal-year").is_some()
            || args.switch("--activity")
        {
            return Err(usage(
                "--as-of cannot be combined with --period, --fiscal-year or --activity",
                EXAMPLE,
            ));
        }
        let day = DateDay::parse(date).map_err(|e| {
            usage(
                format!("{e}; --as-of requires a civil date"),
                "--as-of YYYY-MM-DD",
            )
        })?;
        TrialBalanceSelection::AsOf(day)
    } else {
        let periods = selected_periods(args, &book)?;
        if args.switch("--activity") {
            TrialBalanceSelection::Activity(periods)
        } else {
            TrialBalanceSelection::Periods(periods)
        }
    };
    let from = match frontier(args, "--from", &book)? {
        Some(seq) => seq,
        None => book.head()?,
    };
    let to = frontier(args, "--to", &book)?;
    let diff = book.ledger_diff(&selection, from, to)?;
    ctx.out.known_at(diff.to);
    let units = &book.context().units;
    let money =
        |unit: u32, mantissa: i128| render_amount(Amount::new(UnitId(unit), mantissa), units);
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    let selected = match (&diff.effective_through, diff.periods.is_empty()) {
        (Some(day), true) => format!("as of {}", day.render()),
        _ => diff.periods.join(", "),
    };
    let mut human = vec![format!(
        "ledger diff over {selected}{} from sequence {} to {}: {} changed row(s), {} entr{} recorded",
        if diff.activity { " (activity)" } else { "" },
        diff.from.0,
        diff.to.0,
        diff.changes.len(),
        diff.entries.len(),
        if diff.entries.len() == 1 { "y" } else { "ies" },
    )];
    let mut changes = Vec::with_capacity(diff.changes.len());
    for row in &diff.changes {
        let delta = money(row.unit_id, row.delta)?;
        let pending_delta = money(row.unit_id, row.pending_delta)?;
        let pending = if row.pending_delta == 0 {
            String::new()
        } else {
            format!("  (pending {pending_delta})")
        };
        human.push(format!(
            "  {:<12} {:>20}  {}{pending}",
            row.code, delta, row.name
        ));
        changes.push(obj(vec![
            ("account", s(format!("{:032x}", row.account.0))),
            ("code", s(&row.code)),
            ("name", s(&row.name)),
            ("before_debits", s(money(row.unit_id, row.before_debits)?)),
            ("before_credits", s(money(row.unit_id, row.before_credits)?)),
            ("after_debits", s(money(row.unit_id, row.after_debits)?)),
            ("after_credits", s(money(row.unit_id, row.after_credits)?)),
            ("delta", s(delta)),
            (
                "before_debits_pending",
                s(money(row.unit_id, row.before_debits_pending)?),
            ),
            (
                "before_credits_pending",
                s(money(row.unit_id, row.before_credits_pending)?),
            ),
            (
                "after_debits_pending",
                s(money(row.unit_id, row.after_debits_pending)?),
            ),
            (
                "after_credits_pending",
                s(money(row.unit_id, row.after_credits_pending)?),
            ),
            ("pending_delta", s(pending_delta)),
        ]));
    }
    let shown = &diff.entries[..diff.entries.len().min(limit)];
    let entries: Vec<Json> = shown
        .iter()
        .map(|entry| {
            obj(vec![
                ("vid", s(format!("{:032x}", entry.vid.0))),
                ("recorded_at", Json::Int(i128::from(entry.recorded_at.0))),
                ("class", s(entry.class.name().unwrap_or("?"))),
                ("effective_date", s(entry.effective_date.render())),
                ("period", entry.period.as_ref().map_or(Json::Null, s)),
                (
                    "supersedes",
                    Json::Arr(
                        entry
                            .supersedes
                            .iter()
                            .map(|link| lineage_json(link, &reasons))
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    for entry in shown {
        human.push(format!(
            "  {:032x}  seq {:>6}  {:<14} {}  {}",
            entry.vid.0,
            entry.recorded_at.0,
            entry.class.name().unwrap_or("?"),
            entry.effective_date.render(),
            entry.period.as_deref().unwrap_or("-"),
        ));
    }
    if shown.len() < diff.entries.len() {
        human.push(format!(
            "  … and {} more (raise --limit, at most {MAX_LIMIT})",
            diff.entries.len() - shown.len()
        ));
    }
    ctx.out.event(
        "ledger_diff",
        vec![
            ("from", Json::Int(i128::from(diff.from.0))),
            ("to", Json::Int(i128::from(diff.to.0))),
            ("periods", Json::Arr(diff.periods.iter().map(s).collect())),
            (
                "effective_through",
                diff.effective_through
                    .map_or(Json::Null, |day| s(day.render())),
            ),
            ("activity", Json::Bool(diff.activity)),
            ("changes", Json::Arr(changes)),
            ("entries_total", Json::Int(diff.entries.len() as i128)),
            ("entries", Json::Arr(entries)),
        ],
        &human.join("\n"),
    );
    Ok(())
}
