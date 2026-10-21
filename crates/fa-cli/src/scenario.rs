//! `fa scenario fork|run|list|show|diff|discard` (plan §15.2, §15.6.5;
//! bead fa-k07b): counterfactual scenarios over a fixed trunk prefix.
//!
//! A scenario forks at a trunk sequence (HEAD by default), optionally names
//! the date its counterfactual starts and the documents its assumptions rest
//! on, and collects intents that run only in its materialization (a scratch
//! replay of the trunk prefix plus its intents, where every posting law runs
//! again). `fa scenario diff` is the ledger-level difference against trunk
//! as known at the fork: per (account, unit), exact. Trunk receives the
//! scenario's records, never its entries.

use fa_journal::refusal::{Refusal, code, exit};
use fa_model::Oid;
use fa_money::{Amount, UnitId};
use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, control_date, draft_intent_json, hex, parse_json, plan_document_into_scenario,
    render_amount, usage,
};
use crate::json::{Json, obj, s};

const FORK_EXAMPLE: &str = "fa scenario fork but-for-breach --from 2025-07-01 [--at HEAD|<seq>] [--evidence <oid>]... --json";
const DIFF_EXAMPLE: &str =
    "fa scenario diff but-for-breach --period FY2025-P12 [--activity] --json";

pub(crate) fn scenario_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("fork") => fork(ctx, args),
        Some("run") => {
            let name = scenario_name(args, "run")?.to_string();
            let path = args.require("--intent", "entry.json (or - for stdin)")?;
            let text = ctx.files.read_text(path)?;
            let doc = parse_json(path, &text)?;
            plan_document_into_scenario(ctx, args, &name, None, &doc)
        }
        Some("list") => list(ctx, args),
        Some("show") => show(ctx, args),
        Some("diff") => diff(ctx, args),
        Some("discard") => discard(ctx, args),
        _ => Err(usage(
            "scenario has the subcommands fork, run, list, show, diff and discard",
            FORK_EXAMPLE,
        )),
    }
}

fn scenario_name<'a>(args: &'a Args, sub: &str) -> Result<&'a str, Fail> {
    match args.positional.get(2) {
        Some(name) if args.positional.len() == 3 => Ok(name.as_str()),
        _ => Err(usage(
            format!("scenario {sub} takes exactly one scenario name"),
            format!("fa scenario {sub} <name>"),
        )),
    }
}

fn unknown(name: &str) -> Fail {
    Refusal::new(
        code::SCENARIO_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no scenario named `{name}`"),
        "plan §15.2 (scenarios; bead fa-k07b)",
        format!(
            "list the book's scenarios with `fa scenario list --json`, or fork this one with `fa scenario fork {}`",
            fa_journal::refusal::command_word(name)
        ),
    )
    .at("scenario", name)
    .into()
}

fn vid_hex(v: fgdb_types::VId) -> Json {
    s(format!("{:032x}", v.0))
}

fn recorded_fields(
    name: &str,
    recorded: &fa_journal::ScenarioRecorded,
) -> Vec<(&'static str, Json)> {
    vec![
        ("scenario", vid_hex(recorded.scenario)),
        ("name", s(name)),
        ("control_entry", vid_hex(recorded.control_entry)),
        ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
        ("already_recorded", Json::Bool(recorded.already_recorded)),
    ]
}

/// One scenario as robot data.
fn scenario_json(view: &fa_journal::ScenarioView) -> Json {
    obj(vec![
        ("scenario", vid_hex(view.vid)),
        ("name", s(&view.body.name)),
        ("owner", vid_hex(view.body.owner)),
        ("state", s(view.state.name())),
        ("opened_at", Json::Int(i128::from(view.opened_at.0))),
        ("fork_at", Json::Int(i128::from(view.body.fork_at.0))),
        ("from", view.body.from.map_or(Json::Null, |d| s(d.render()))),
        (
            "assumptions",
            Json::Arr(view.assumptions.iter().map(|o| s(hex(&o.0))).collect()),
        ),
        ("intents", Json::Int(view.intents.len() as i128)),
        (
            "discarded_at",
            view.discarded
                .as_ref()
                .map_or(Json::Null, |c| Json::Int(i128::from(c.recorded_at.0))),
        ),
    ])
}

/// `--at HEAD|<seq>`: the trunk sequence to fork at (`None`: the head).
fn fork_at(args: &Args) -> Result<Option<CommitSeq>, Fail> {
    if args.flag_all("--at").len() > 1 {
        return Err(usage("scenario fork takes one --at", FORK_EXAMPLE));
    }
    match args.flag("--at") {
        None | Some("HEAD") => Ok(None),
        Some(text) => text
            .parse::<u64>()
            .map(|n| Some(CommitSeq(n)))
            .map_err(|_| {
                usage(
                    format!("--at `{text}` is neither HEAD nor a commit sequence"),
                    FORK_EXAMPLE,
                )
            }),
    }
}

fn fork(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let name = scenario_name(args, "fork")?.to_string();
    let at = fork_at(args)?;
    if args.flag_all("--from").len() > 1 {
        return Err(usage("scenario fork takes one --from", FORK_EXAMPLE));
    }
    let from = args
        .flag("--from")
        .map(|text| {
            fa_time::DateDay::parse(text)
                .map_err(|e| usage(format!("--from: {e}"), "--from YYYY-MM-DD"))
        })
        .transpose()?;
    let mut assumptions = Vec::new();
    for text in args.flag_all("--evidence") {
        assumptions.push(Oid(crate::document::hex32(text, "--evidence")?));
    }
    let capability = ctx.capability(args, &["post"])?;
    let mut book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let default_desc = format!("scenario {name}");
    let description = args.flag("--description").unwrap_or(&default_desc);
    let recorded = book.open_scenario(
        capability,
        &name,
        fa_journal::ScenarioFork {
            at,
            from,
            assumptions,
        },
        date,
        description,
    )??;
    let view = book.scenario(&name)?.ok_or_else(|| unknown(&name))?;
    ctx.out.at_book(&book)?;
    let mut fields = recorded_fields(&name, &recorded);
    fields.push(("fork_at", Json::Int(i128::from(view.body.fork_at.0))));
    fields.push(("from", view.body.from.map_or(Json::Null, |d| s(d.render()))));
    fields.push((
        "assumptions",
        Json::Arr(view.assumptions.iter().map(|o| s(hex(&o.0))).collect()),
    ));
    ctx.out.event(
        "scenario_forked",
        fields,
        &format!(
            "scenario {name} {} at trunk sequence {}{} (record {})",
            if recorded.already_recorded {
                "was already forked"
            } else {
                "forked"
            },
            view.body.fork_at.0,
            view.body
                .from
                .map_or_else(String::new, |d| format!(", counterfactual from {d}")),
            recorded.recorded_at.0
        ),
    );
    Ok(())
}

const RECEIVERSHIP_EXAMPLE: &str =
    "fa book fork receivership --authority <order-oid> [--at HEAD|<seq>] --json";

/// `fa book fork receivership --authority <order> [--at HEAD|<seq>]` (plan
/// §15.6, "The trustee or receiver takes over"; fa-k07b): a book-scope legal
/// hold over everything recorded through the appointment sequence, on the
/// order's authority, then the `receivership` scenario forked at that
/// sequence with the order as its assumption document. The estate posts in
/// it with `--scenario receivership` until substrate branches land.
pub(crate) fn fork_receivership(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(2).map(String::as_str) {
        Some(fa_journal::RECEIVERSHIP) if args.positional.len() == 3 => {}
        _ => {
            return Err(usage(
                "book fork takes the branch `receivership` (plan §15.6); a counterfactual is `fa scenario fork <name>`",
                RECEIVERSHIP_EXAMPLE,
            ));
        }
    }
    let authority = match args.flag_all("--authority").as_slice() {
        [one] => Oid(crate::document::hex32(one, "--authority")?),
        [] => {
            return Err(usage(
                "a receivership rests on the appointing order: record it with `fa document add <order> --kind <Kind>` and pass its oid as --authority",
                RECEIVERSHIP_EXAMPLE,
            ));
        }
        _ => {
            return Err(usage(
                "book fork receivership takes one --authority",
                RECEIVERSHIP_EXAMPLE,
            ));
        }
    };
    let at = match args.flag_all("--at").as_slice() {
        [] | ["HEAD"] => None,
        [seq] => Some(CommitSeq(seq.parse::<u64>().map_err(|_| {
            usage(
                format!("--at `{seq}` is neither HEAD nor a commit sequence"),
                RECEIVERSHIP_EXAMPLE,
            )
        })?)),
        _ => {
            return Err(usage(
                "book fork receivership takes one --at",
                RECEIVERSHIP_EXAMPLE,
            ));
        }
    };
    let capability = ctx.capability(args, &["receivership", "hold", "post"])?;
    let mut book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let description = args
        .flag("--description")
        .unwrap_or(fa_journal::RECEIVERSHIP);
    let forked = book.fork_receivership(capability, authority, at, date, description)??;
    ctx.out.at_book(&book)?;
    let already = forked.hold.already_recorded && forked.branch.already_recorded;
    ctx.out.event(
        "receivership_forked",
        vec![
            ("appointment", Json::Int(i128::from(forked.appointment.0))),
            ("authority", s(hex(&authority.0))),
            ("hold_vid", vid_hex(forked.hold.hold)),
            (
                "hold_recorded_at",
                Json::Int(i128::from(forked.hold.recorded_at.0)),
            ),
            ("scenario", vid_hex(forked.branch.scenario)),
            ("branch", s(fa_journal::RECEIVERSHIP)),
            ("control_entry", vid_hex(forked.branch.control_entry)),
            (
                "recorded_at",
                Json::Int(i128::from(forked.branch.recorded_at.0)),
            ),
            ("already_recorded", Json::Bool(already)),
        ],
        &format!(
            "receivership {} at appointment sequence {}: legal hold {:032x} pins everything recorded through it; the estate posts with --scenario receivership and reads with --branch scenario:receivership",
            if already {
                "was already forked"
            } else {
                "forked"
            },
            forked.appointment.0,
            forked.hold.hold.0
        ),
    );
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "scenario list takes no argument",
            "fa scenario list --json",
        ));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let scenarios = book.scenarios()?;
    ctx.out.at_book(&book)?;
    let human = if scenarios.is_empty() {
        "no scenarios in this book".to_string()
    } else {
        scenarios
            .iter()
            .map(|v| {
                format!(
                    "{} {} fork_at={} {} intent(s)",
                    v.body.name,
                    v.state.name(),
                    v.body.fork_at.0,
                    v.intents.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    ctx.out.event(
        "scenarios",
        vec![(
            "scenarios",
            Json::Arr(scenarios.iter().map(scenario_json).collect()),
        )],
        &human,
    );
    Ok(())
}

/// `fa branch list` (plan §15.3 Drafts and scenarios; fa-waow): every
/// branch of the book in one listing, the drafts by opening sequence and the
/// scenarios by forking sequence, as `fa draft list` and `fa scenario list`
/// show them.
pub(crate) fn branch_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa branch list --book <dir> --json";
    if args.positional.get(1).map(String::as_str) != Some("list") || args.positional.len() != 2 {
        return Err(usage("branch needs list", EXAMPLE));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let drafts = book.drafts()?;
    let scenarios = book.scenarios()?;
    ctx.out.at_book(&book)?;
    let mut human: Vec<String> = drafts
        .iter()
        .map(|d| {
            format!(
                "draft    {} {} {} intent(s)",
                d.body.name,
                d.state.name(),
                d.intents.len()
            )
        })
        .chain(scenarios.iter().map(|v| {
            format!(
                "scenario {} {} fork_at={} {} intent(s)",
                v.body.name,
                v.state.name(),
                v.body.fork_at.0,
                v.intents.len()
            )
        }))
        .collect();
    if human.is_empty() {
        human.push("no drafts or scenarios in this book (trunk only)".to_string());
    }
    ctx.out.event(
        "branches",
        vec![
            (
                "drafts",
                Json::Arr(drafts.iter().map(crate::cli::draft_json).collect()),
            ),
            (
                "scenarios",
                Json::Arr(scenarios.iter().map(scenario_json).collect()),
            ),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let name = scenario_name(args, "show")?.to_string();
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let view = book.scenario(&name)?.ok_or_else(|| unknown(&name))?;
    ctx.out.at_book(&book)?;
    let intents: Vec<Json> = view
        .intents
        .iter()
        .map(|i| draft_intent_json(&book, i))
        .collect();
    ctx.out.event(
        "scenario_detail",
        vec![
            ("scenario", scenario_json(&view)),
            ("intents", Json::Arr(intents)),
        ],
        &format!(
            "scenario {name}: {}, forked at trunk sequence {}, {} intent(s)",
            view.state.name(),
            view.body.fork_at.0,
            view.intents.len()
        ),
    );
    Ok(())
}

fn diff(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let name = scenario_name(args, "diff")?.to_string();
    let periods: Vec<String> = args
        .flag_all("--period")
        .into_iter()
        .map(str::to_string)
        .collect();
    if periods.is_empty() {
        return Err(usage(
            "scenario diff needs at least one --period",
            DIFF_EXAMPLE,
        ));
    }
    let activity = args.switch("--activity");
    let who = ctx.principal(args);
    // Certifying publishes a retained certificate: read and produce.
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let ops: &[&str] = if certify {
        &["read", "produce"]
    } else {
        &["read"]
    };
    let cap = ctx.capability(args, ops)?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    if !certify {
        let diff = book.scenario_diff(&name, &periods, activity)??;
        ctx.out.at_book(&book)?;
        return render_scenario_diff(&ctx.out, &book, &diff, None);
    }
    if let Some(path) = args.flag("--certificate-out")
        && (path.is_empty() || path == "-")
    {
        return Err(usage(
            "--certificate-out names a new file; - is not an output file",
            "use --certify to receive the complete certificate as hex on stdout",
        ));
    }
    let certified = book.certify_scenario_diff(who, &cap, &name, &periods, activity)??;
    let retained = book.retain_scenario_diff(who, &cap, &certified.certificate)??;
    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
    let bytes = artifact.canonical_bytes()?;
    if let Some(path) = args.flag("--certificate-out") {
        crate::cli::write_new_output_file(
            &ctx.files,
            path,
            &bytes,
            "certificate",
            "--certificate-out",
        )?;
    }
    ctx.out.at_book(&book)?;
    let digest = hex(artifact.digest());
    render_scenario_diff(&ctx.out, &book, &certified.report, Some(&digest))?;
    crate::notary::emit_report_artifact(
        &ctx.out,
        args,
        &artifact,
        fa::SCENARIO_DIFF_OUTPUT_FORMAT,
        &bytes,
        &retained,
    );
    Ok(())
}

/// The `scenario_diff` event: from `fa scenario diff`, and from `fa replay`
/// of its certificate (`certificate` names it in the envelope).
pub(crate) fn render_scenario_diff(
    out: &crate::cli::Out,
    book: &fa::Book,
    diff: &fa::ScenarioDiff,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let name = &diff.name;
    let activity = diff.activity;
    let units = &book.context().units;
    let money =
        |unit: u32, mantissa: i128| render_amount(Amount::new(UnitId(unit), mantissa), units);
    let mut rows = Vec::with_capacity(diff.rows.len());
    let mut human = vec![format!(
        "scenario {name} vs trunk at sequence {} over {}{}: {} changed row(s)",
        diff.fork_at.0,
        diff.periods.join(", "),
        if activity { " (activity)" } else { "" },
        diff.rows.len()
    )];
    for row in &diff.rows {
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
        rows.push(obj(vec![
            ("account", vid_hex(row.account)),
            ("code", s(&row.code)),
            ("name", s(&row.name)),
            ("trunk_debits", s(money(row.unit_id, row.trunk_debits)?)),
            ("trunk_credits", s(money(row.unit_id, row.trunk_credits)?)),
            (
                "scenario_debits",
                s(money(row.unit_id, row.scenario_debits)?),
            ),
            (
                "scenario_credits",
                s(money(row.unit_id, row.scenario_credits)?),
            ),
            ("delta", s(delta)),
            (
                "trunk_debits_pending",
                s(money(row.unit_id, row.trunk_debits_pending)?),
            ),
            (
                "trunk_credits_pending",
                s(money(row.unit_id, row.trunk_credits_pending)?),
            ),
            (
                "scenario_debits_pending",
                s(money(row.unit_id, row.scenario_debits_pending)?),
            ),
            (
                "scenario_credits_pending",
                s(money(row.unit_id, row.scenario_credits_pending)?),
            ),
            ("pending_delta", s(pending_delta)),
        ]));
    }
    out.event_with_certificate(
        "scenario_diff",
        vec![
            ("scenario", vid_hex(diff.scenario)),
            ("name", s(&diff.name)),
            ("fork_at", Json::Int(i128::from(diff.fork_at.0))),
            ("from", diff.from.map_or(Json::Null, |d| s(d.render()))),
            (
                "assumptions",
                Json::Arr(diff.assumptions.iter().map(|o| s(hex(&o.0))).collect()),
            ),
            ("periods", Json::Arr(diff.periods.iter().map(s).collect())),
            ("activity", Json::Bool(diff.activity)),
            ("intents", Json::Int(diff.intents as i128)),
            ("body_digest", s(hex(&diff.body_digest))),
            ("intents_digest", s(hex(&diff.intents_digest))),
            ("seq_map_digest", s(hex(&diff.seq_map_digest))),
            (
                "scenario_known_at",
                Json::Int(i128::from(diff.scenario_known_at.0)),
            ),
            ("rows", Json::Arr(rows)),
        ],
        &human.join("\n"),
        certificate,
    );
    Ok(())
}

fn discard(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let name = scenario_name(args, "discard")?.to_string();
    let capability = ctx.capability(args, &["post"])?;
    let mut book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let default_desc = format!("discard scenario {name}");
    let description = args
        .flag("--reason")
        .or_else(|| args.flag("--description"))
        .unwrap_or(&default_desc);
    let recorded = book.discard_scenario(capability, &name, date, description)??;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "scenario_discarded",
        recorded_fields(&name, &recorded),
        &format!(
            "scenario {name} {} (record {}); its history is kept",
            if recorded.already_recorded {
                "was already discarded"
            } else {
                "discarded"
            },
            recorded.recorded_at.0
        ),
    );
    Ok(())
}
