//! `fa case open|determine|rehearse|show|list` (plan §8.3, Appendix B
//! `OpenRestatementCase`; bead fa-75j4): restatement cases, the control
//! objects that make a material correction legal in a `Closed` or `Locked`
//! period.
//!
//! A case is opened over the periods it affects (`Proposed`), and its
//! determination (for a `Restatement`, the non-reliance determination that
//! starts the Item 4.02 clock) is journaled with its day and authority
//! document (`Determined`). It is rehearsed on a scenario whose diff
//! certificate is replayed, retained and attached (`Rehearsed`). Approval,
//! posting, disclosure and closing are later slices: a case cannot yet leave
//! `Rehearsed`.

use fa_journal::{CaseKind, CaseRecorded, CaseView, Determination};
use fa_model::Oid;
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{Ctx, Fail, control_date, hex, usage};
use crate::json::{Json, obj, s};

const OPEN_EXAMPLE: &str = "fa case open --kind Restatement|Revision|PriorPeriodAdjustment|PolicyChangeRetrospective --periods <code>[,<code>]... [--narrative <oid>] [--determined-on YYYY-MM-DD --authority <oid>] [--key K] --json";
const DETERMINE_EXAMPLE: &str =
    "fa case determine <case> --on YYYY-MM-DD --authority <oid> [--key K] --json";
const REHEARSE_EXAMPLE: &str = "fa case rehearse <case> --certificate <scenario-diff-certificate> [--key K] --json  (fa scenario diff <name> --period <code> --certificate-out <file> writes one)";

pub(crate) fn case_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("open") => open(ctx, args),
        Some("determine") => determine(ctx, args),
        Some("rehearse") => rehearse(ctx, args),
        Some("show") => show(ctx, args),
        Some("list") => list(ctx, args),
        _ => Err(usage(
            "case needs open, determine, rehearse, show or list",
            OPEN_EXAMPLE,
        )),
    }
}

fn one_flag<'a>(args: &'a Args, flag: &str, example: &str) -> Result<Option<&'a str>, Fail> {
    if args.flag_all(flag).len() > 1 {
        return Err(usage(format!("{flag} is given once"), example));
    }
    Ok(args.flag(flag))
}

fn document(text: &str, flag: &str) -> Result<Oid, Fail> {
    crate::document::hex32(text, flag).map(Oid)
}

fn day(text: &str, flag: &str, example: &str) -> Result<DateDay, Fail> {
    DateDay::parse(text).map_err(|e| usage(format!("{flag} `{text}`: {e:?}"), example))
}

fn ordinal(args: &Args, sub: &str, example: &str) -> Result<u32, Fail> {
    match (args.positional.get(2), args.positional.len()) {
        (Some(text), 3) => text.parse::<u32>().ok().filter(|n| *n > 0).ok_or_else(|| {
            usage(
                format!("case {sub}: `{text}` is not a case number"),
                example,
            )
        }),
        _ => Err(usage(
            format!("case {sub} takes exactly one case number"),
            example,
        )),
    }
}

/// One case as robot data.
fn case_json(view: &CaseView) -> Json {
    let body = &view.body;
    let vid = |v: fgdb_types::VId| s(format!("{:032x}", v.0));
    obj(vec![
        ("case", Json::Int(i128::from(body.ordinal))),
        ("vid", vid(view.vid)),
        ("kind", s(body.kind.name())),
        ("state", s(view.state.name())),
        ("periods", Json::Arr(body.periods.iter().map(s).collect())),
        (
            "narrative",
            body.narrative.map_or(Json::Null, |d| s(hex(&d.0))),
        ),
        (
            "determination",
            view.determination.map_or(Json::Null, |d| {
                obj(vec![
                    ("day", s(d.day.render())),
                    ("authority", s(hex(&d.authority.0))),
                ])
            }),
        ),
        (
            "rehearsal",
            view.rehearsal.as_ref().map_or(Json::Null, |r| {
                obj(vec![
                    ("scenario", s(&r.scenario)),
                    ("certificate", s(hex(&r.certificate))),
                    ("fork_at", Json::Int(i128::from(r.fork_at.0))),
                    ("periods", Json::Arr(r.periods.iter().map(s).collect())),
                    (
                        "intents",
                        Json::Arr(r.intents.iter().map(|v| vid(*v)).collect()),
                    ),
                ])
            }),
        ),
        (
            "transitions",
            Json::Arr(
                view.transitions
                    .iter()
                    .map(|t| {
                        obj(vec![
                            ("from", t.from.map_or(Json::Null, |f| s(f.name()))),
                            ("to", s(t.to.name())),
                            ("control_entry", vid(t.control_entry)),
                            ("recorded_at", Json::Int(i128::from(t.recorded_at.0))),
                            ("principal", vid(t.principal)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn line(view: &CaseView) -> String {
    format!(
        "case {} {} {} over {}{}",
        view.body.ordinal,
        view.body.kind.name(),
        view.state.name(),
        view.body.periods.join(", "),
        view.determination
            .map_or_else(String::new, |d| format!(" (determined {})", d.day.render()))
    )
}

fn recorded(ctx: &mut Ctx<'_>, event: &str, done: &CaseRecorded, verb: &str) {
    ctx.out.event(
        event,
        vec![
            ("case", case_json(&done.case)),
            ("control_entry", s(format!("{:032x}", done.control_entry.0))),
            ("recorded_at", Json::Int(i128::from(done.recorded_at.0))),
            ("already_recorded", Json::Bool(done.already_recorded)),
        ],
        &format!(
            "{}{} (record {}); approval, posting and disclosure are later fa-75j4 slices",
            if done.already_recorded {
                format!("already {verb}: ")
            } else {
                format!("{verb}: ")
            },
            line(&done.case),
            done.recorded_at.0
        ),
    );
}

fn open(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "case open takes no positional argument",
            OPEN_EXAMPLE,
        ));
    }
    for flag in [
        "--kind",
        "--narrative",
        "--determined-on",
        "--authority",
        "--key",
        "--date",
    ] {
        one_flag(args, flag, OPEN_EXAMPLE)?;
    }
    let names = CaseKind::ALL.map(CaseKind::name).join("|");
    let kind_text = args
        .flag("--kind")
        .ok_or_else(|| usage("case open needs --kind", OPEN_EXAMPLE))?;
    let kind = CaseKind::parse(kind_text).ok_or_else(|| {
        usage(
            format!("--kind `{kind_text}` is not a registered case kind"),
            format!("--kind {names}"),
        )
    })?;
    let periods: Vec<String> = args
        .flag_all("--periods")
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if periods.is_empty() {
        return Err(usage(
            "case open needs --periods naming the periods the case affects",
            OPEN_EXAMPLE,
        ));
    }
    let narrative = args
        .flag("--narrative")
        .map(|t| document(t, "--narrative"))
        .transpose()?;
    let determination = match (args.flag("--determined-on"), args.flag("--authority")) {
        (None, None) => None,
        (Some(on), Some(authority)) => Some(Determination {
            day: day(on, "--determined-on", OPEN_EXAMPLE)?,
            authority: document(authority, "--authority")?,
        }),
        _ => {
            return Err(usage(
                "a determination at open names both --determined-on and --authority",
                OPEN_EXAMPLE,
            ));
        }
    };
    let key = match args.flag("--key") {
        Some(key) => key.to_string(),
        // The request itself: the same command opens the same case once.
        None => {
            let mut sorted = periods.clone();
            sorted.sort();
            sorted.dedup();
            hex(&fa_model::domain_digest(
                b"fa-cli:case-open-key:v1",
                &[
                    &[kind.tag()],
                    sorted.join(",").as_bytes(),
                    narrative.as_ref().map_or(&[][..], |d| &d.0[..]),
                    &determination.map_or_else(Vec::new, |d| {
                        let mut b = d.day.0.to_le_bytes().to_vec();
                        b.extend_from_slice(&d.authority.0);
                        b
                    }),
                ],
            ))
        }
    };
    let capability = ctx.capability(args, &["restate"])?;
    let mut book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let done = book.open_case(
        capability,
        kind,
        periods,
        narrative,
        determination,
        date,
        key.as_bytes(),
    )??;
    ctx.out.at_book(&book)?;
    recorded(ctx, "case_opened", &done, "opened");
    Ok(())
}

fn determine(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let ordinal = ordinal(args, "determine", DETERMINE_EXAMPLE)?;
    for flag in ["--on", "--authority", "--key", "--date"] {
        one_flag(args, flag, DETERMINE_EXAMPLE)?;
    }
    let on = args
        .flag("--on")
        .ok_or_else(|| usage("case determine needs --on <day>", DETERMINE_EXAMPLE))?;
    let authority = args.flag("--authority").ok_or_else(|| {
        usage(
            "case determine needs --authority <oid>: the document that records who determined it",
            DETERMINE_EXAMPLE,
        )
    })?;
    let determination = Determination {
        day: day(on, "--on", DETERMINE_EXAMPLE)?,
        authority: document(authority, "--authority")?,
    };
    let key = match args.flag("--key") {
        Some(key) => key.to_string(),
        None => hex(&fa_model::domain_digest(
            b"fa-cli:case-determine-key:v1",
            &[
                &ordinal.to_le_bytes(),
                &determination.day.0.to_le_bytes(),
                &determination.authority.0,
            ],
        )),
    };
    let capability = ctx.capability(args, &["restate"])?;
    let mut book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let done = book.determine_case(capability, ordinal, determination, date, key.as_bytes())??;
    ctx.out.at_book(&book)?;
    recorded(ctx, "case_determined", &done, "determined");
    Ok(())
}

fn rehearse(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let ordinal = ordinal(args, "rehearse", REHEARSE_EXAMPLE)?;
    for flag in ["--certificate", "--key", "--date"] {
        one_flag(args, flag, REHEARSE_EXAMPLE)?;
    }
    let path = args.flag("--certificate").ok_or_else(|| {
        usage(
            "case rehearse needs --certificate <file>: the scenario's diff certificate",
            REHEARSE_EXAMPLE,
        )
    })?;
    // Authority before any read of the certificate file or the book.
    let capability = ctx.capability(args, &["restate", "read", "produce"])?;
    let certificate = fa::ScenarioDiffCertificate::decode(&ctx.files.read_bytes(path)?)?;
    let key = match args.flag("--key") {
        Some(key) => key.to_string(),
        None => hex(&fa_model::domain_digest(
            b"fa-cli:case-rehearse-key:v1",
            &[&ordinal.to_le_bytes(), certificate.digest()],
        )),
    };
    let mut book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let done = book.rehearse_case(capability, ordinal, &certificate, date, key.as_bytes())??;
    ctx.out.at_book(&book)?;
    recorded(ctx, "case_rehearsed", &done, "rehearsed");
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let ordinal = ordinal(args, "show", "fa case show <case> --json")?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let Some(view) = book.case(ordinal)? else {
        return Err(Fail::Refusal(fa_journal::refusal::Refusal::new(
            fa_journal::refusal::code::CASE_UNKNOWN,
            fa_journal::refusal::exit::REFUSAL,
            format!("this book has no restatement case {ordinal}"),
            "plan §8.3 (a RestatementCase is opened with OpenRestatementCase)",
            "list the book's cases with `fa case list --json`",
        )));
    };
    ctx.out.at_book(&book)?;
    ctx.out
        .event("case", vec![("case", case_json(&view))], &line(&view));
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage("case list takes no argument", "fa case list --json"));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let views = book.cases()?;
    ctx.out.at_book(&book)?;
    let human = if views.is_empty() {
        "no restatement cases in this book".to_string()
    } else {
        views.iter().map(line).collect::<Vec<_>>().join("\n")
    };
    ctx.out.event(
        "cases",
        vec![("cases", Json::Arr(views.iter().map(case_json).collect()))],
        &human,
    );
    Ok(())
}
