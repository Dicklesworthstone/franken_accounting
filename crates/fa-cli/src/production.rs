//! `fa production open|list|show|document` and `fa produce` (plan §13.2,
//! §0.4 decision 4; bead fa-6l9): litigation productions with journaled
//! Bates numbering.
//!
//! A matter's profile fixes its Bates prefix and first number once. `fa
//! produce` journals the next numbers for each document the matter has not
//! produced (a produced document keeps its range), then writes the volume
//! into a new directory: the Concordance DAT and Opticon OPT load files and
//! each fully readable document's native. A document the capability reads
//! only through its redacted view is listed as redacted and ships no bytes.

use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{ProducedDocument, ProductionProfile, ProductionView, RecordedRange};
use fa_model::Oid;

use crate::args::Args;
use crate::cli::{Ctx, Fail, control_date, hex, usage, write_new_output_file};
use crate::json::{Json, obj, s};

const OPEN_EXAMPLE: &str = "fa production open <matter> --bates-prefix <PREFIX> [--start <n>] [--load-file dat] [--protective-order <oid>] --json";
const PRODUCE_EXAMPLE: &str = "fa produce --matter <matter> --document <oid>[:pages[:designation]]... --out <new-dir> [--volume VOL001] --json";
/// The designation names `--document` accepts, by tag (Appendix A).
const DESIGNATIONS: [&str; 4] = ["none", "confidential", "aeo", "highly-confidential"];

pub(crate) fn production_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("open") => open(ctx, args),
        Some("list") => list(ctx, args),
        Some("show") => show(ctx, args),
        Some("document") => document(ctx, args),
        _ => Err(usage(
            "production has the subcommands open, list, show and document",
            OPEN_EXAMPLE,
        )),
    }
}

fn one_positional<'a>(args: &'a Args, sub: &str, what: &str) -> Result<&'a str, Fail> {
    match args.positional.get(2) {
        Some(value) if args.positional.len() == 3 => Ok(value.as_str()),
        _ => Err(usage(
            format!("production {sub} takes exactly one {what}"),
            format!("fa production {sub} <{what}> --json"),
        )),
    }
}

fn one_flag<'a>(args: &'a Args, flag: &str, example: &str) -> Result<Option<&'a str>, Fail> {
    if args.flag_all(flag).len() > 1 {
        return Err(usage(format!("{flag} is given once"), example));
    }
    Ok(args.flag(flag))
}

fn unknown(matter: &str) -> Fail {
    Refusal::new(
        code::PRODUCTION_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no production profile for matter `{matter}`"),
        "plan §13.2 (a ProductionProfile governs a matter's productions)",
        "list the book's matters with `fa production list --json`, or open one with `fa production open <matter> --bates-prefix <PREFIX>`",
    )
    .into()
}

fn vid_hex(v: fgdb_types::VId) -> Json {
    s(format!("{:032x}", v.0))
}

fn seq(v: fgdb_types::CommitSeq) -> Json {
    Json::Int(i128::from(v.0))
}

fn load_file_name(tag: u8) -> &'static str {
    match tag {
        1 => "dat",
        2 => "edrm",
        3 => "both",
        _ => "unregistered",
    }
}

fn designation_name(tag: u8) -> &'static str {
    DESIGNATIONS
        .get(usize::from(tag))
        .copied()
        .unwrap_or("unregistered")
}

/// One matter's profile as robot data.
fn summary_json(view: &ProductionView) -> Json {
    let p = &view.profile;
    obj(vec![
        ("matter", s(&p.matter)),
        ("profile", vid_hex(view.vid)),
        ("bates_prefix", s(&p.bates_prefix)),
        ("first_bates", Json::Int(i128::from(p.first_bates))),
        ("next_bates", Json::Int(i128::from(view.next_bates))),
        ("load_file", s(load_file_name(p.load_file_format))),
        (
            "protective_order",
            p.protective_order.map_or(Json::Null, |o| s(hex(&o.0))),
        ),
        ("state", s(view.state.name())),
        ("opened_at", seq(view.opened_at)),
        ("opened_by", vid_hex(view.opened_by)),
        ("documents", Json::Int(view.ranges.len() as i128)),
    ])
}

/// One assigned range as robot data; `with_matter` leads with the matter,
/// for a document's ranges across matters.
fn range_json(profile: &ProductionProfile, r: &RecordedRange, with_matter: bool) -> Json {
    let mut fields = Vec::with_capacity(10);
    if with_matter {
        fields.push(("matter", s(&profile.matter)));
    }
    fields.extend([
        ("document", s(hex(&r.range.document.0))),
        ("doc_commit", s(hex(&r.range.doc_commit))),
        ("beg_bates", s(profile.label(r.range.start))),
        ("end_bates", s(profile.label(r.range.end))),
        ("pages", Json::Int(i128::from(r.range.pages()))),
        ("designation", s(designation_name(r.range.designation))),
        ("record", vid_hex(r.record)),
        ("recorded_at", seq(r.recorded_at)),
        ("produced_by", vid_hex(r.produced_by)),
    ]);
    obj(fields)
}

fn open(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let matter = one_positional(args, "open", "matter")?.to_string();
    let prefix = args.require(
        "--bates-prefix",
        "the matter's Bates prefix, for example ACME-SEC",
    )?;
    if args.flag_all("--bates-prefix").len() > 1 {
        return Err(usage("--bates-prefix is given once", OPEN_EXAMPLE));
    }
    let first_bates = match one_flag(args, "--start", OPEN_EXAMPLE)? {
        None => 1,
        Some(text) => text.parse::<u64>().map_err(|_| {
            usage(
                format!("--start `{text}` is not a Bates number"),
                "--start <n>   (the matter's first Bates number, 1 by default)",
            )
        })?,
    };
    let load_file_format = match one_flag(args, "--load-file", OPEN_EXAMPLE)? {
        None | Some("dat") => 1,
        Some(other @ ("edrm" | "both")) => {
            return Err(usage(
                format!(
                    "--load-file {other}: EDRM XML needs the production bundle, which this build does not write (bead fa-6l9); it writes Concordance DAT/OPT"
                ),
                "--load-file dat",
            ));
        }
        Some(other) => {
            return Err(usage(
                format!("--load-file `{other}` is not a load-file format"),
                "--load-file dat",
            ));
        }
    };
    let protective_order = one_flag(args, "--protective-order", OPEN_EXAMPLE)?
        .map(|text| crate::document::hex32(text, "--protective-order").map(Oid))
        .transpose()?;
    let key = one_flag(args, "--key", OPEN_EXAMPLE)?
        .unwrap_or("open")
        .to_string();
    let capability = ctx.capability(args, &["produce"])?;
    let mut book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let profile = ProductionProfile {
        book_id: book.context().book_id,
        matter: matter.clone(),
        bates_prefix: prefix.to_string(),
        first_bates,
        load_file_format,
        protective_order,
    };
    let opened = book.open_production(capability, profile, date, key.as_bytes())??;
    let view = book.production(&matter)?.ok_or_else(|| unknown(&matter))?;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "production_opened",
        vec![
            ("production", summary_json(&view)),
            ("control_entry", vid_hex(opened.control_entry)),
            ("recorded_at", seq(opened.recorded_at)),
            ("already_recorded", Json::Bool(opened.already_recorded)),
        ],
        &format!(
            "matter {matter}: production profile {} (Bates {}..., record {})",
            if opened.already_recorded {
                "was already open"
            } else {
                "opened"
            },
            view.profile.label(view.profile.first_bates),
            opened.recorded_at.0
        ),
    );
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "production list takes no argument",
            "fa production list --json",
        ));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let views = book.productions()?;
    ctx.out.at_book(&book)?;
    let human = if views.is_empty() {
        "no production profiles in this book".to_string()
    } else {
        views
            .iter()
            .map(|v| {
                format!(
                    "{} prefix={} next={} {} document(s)",
                    v.profile.matter,
                    v.profile.bates_prefix,
                    v.profile.label(v.next_bates),
                    v.ranges.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    ctx.out.event(
        "productions",
        vec![(
            "productions",
            Json::Arr(views.iter().map(summary_json).collect()),
        )],
        &human,
    );
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let matter = one_positional(args, "show", "matter")?.to_string();
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let view = book.production(&matter)?.ok_or_else(|| unknown(&matter))?;
    ctx.out.at_book(&book)?;
    let mut human = vec![format!(
        "matter {matter}: Bates prefix {}, next {}, {} document(s)",
        view.profile.bates_prefix,
        view.profile.label(view.next_bates),
        view.ranges.len()
    )];
    for r in &view.ranges {
        human.push(format!(
            "  {}..={} {} ({} pages, {})",
            view.profile.label(r.range.start),
            view.profile.label(r.range.end),
            hex(&r.range.document.0),
            r.range.pages(),
            designation_name(r.range.designation)
        ));
    }
    ctx.out.event(
        "production_detail",
        vec![
            ("production", summary_json(&view)),
            (
                "ranges",
                Json::Arr(
                    view.ranges
                        .iter()
                        .map(|r| range_json(&view.profile, r, false))
                        .collect(),
                ),
            ),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn document(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let text = one_positional(args, "document", "oid")?;
    let oid = Oid(crate::document::hex32(text, "the document oid")?);
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let ranges = book.document_bates_ranges(&oid)?;
    ctx.out.at_book(&book)?;
    let human = if ranges.is_empty() {
        format!(
            "document {} has not been produced in any matter",
            hex(&oid.0)
        )
    } else {
        ranges
            .iter()
            .map(|(p, r)| {
                format!(
                    "{}: {}..={}",
                    p.matter,
                    p.label(r.range.start),
                    p.label(r.range.end)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let rows = ranges.iter().map(|(p, r)| range_json(p, r, true)).collect();
    ctx.out.event(
        "document_bates_ranges",
        vec![("document", s(hex(&oid.0))), ("ranges", Json::Arr(rows))],
        &human,
    );
    Ok(())
}

/// `<oid>[:pages[:designation]]`: pages may be empty (`<oid>::aeo`).
fn parse_document(text: &str) -> Result<ProducedDocument, Fail> {
    let mut parts = text.split(':');
    let oid = parts.next().unwrap_or_default();
    let document = Oid(crate::document::hex32(oid, "--document")?);
    let pages = match parts.next() {
        None | Some("") => None,
        Some(p) => Some(p.parse::<u64>().map_err(|_| {
            usage(
                format!("--document {text}: `{p}` is not a page count"),
                PRODUCE_EXAMPLE,
            )
        })?),
    };
    let designation = match parts.next() {
        None | Some("") => None,
        Some(d) => {
            let tag = DESIGNATIONS.iter().position(|n| *n == d).ok_or_else(|| {
                usage(
                    format!(
                        "--document {text}: `{d}` is not a designation ({})",
                        DESIGNATIONS.join(", ")
                    ),
                    PRODUCE_EXAMPLE,
                )
            })?;
            Some(u8::try_from(tag).unwrap_or(u8::MAX))
        }
    };
    if parts.next().is_some() {
        return Err(usage(
            format!("--document {text} has more than oid, pages and designation"),
            PRODUCE_EXAMPLE,
        ));
    }
    Ok(ProducedDocument {
        document,
        pages,
        designation,
    })
}

/// `fa produce`: journal the Bates numbers, then write the volume into a
/// new directory. The directory is refused before anything is journaled,
/// and the default key is the request itself, so re-running the identical
/// command after a failed write returns the recorded production.
pub(crate) fn produce_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 1 {
        return Err(usage(
            "produce takes no positional argument",
            PRODUCE_EXAMPLE,
        ));
    }
    let matter = args.require(
        "--matter",
        "the matter whose profile numbers this production",
    )?;
    if args.flag_all("--matter").len() > 1 {
        return Err(usage("--matter is given once", PRODUCE_EXAMPLE));
    }
    let named = args.flag_all("--document");
    if named.is_empty() {
        return Err(usage(
            "produce needs at least one --document",
            PRODUCE_EXAMPLE,
        ));
    }
    let documents = named
        .iter()
        .map(|d| parse_document(d))
        .collect::<Result<Vec<_>, _>>()?;
    let out = args.require("--out", "a new directory for the production volume")?;
    if out.is_empty() || out == "-" || args.flag_all("--out").len() > 1 {
        return Err(usage(
            "--out names one new directory; - is not a directory",
            PRODUCE_EXAMPLE,
        ));
    }
    let volume = one_flag(args, "--volume", PRODUCE_EXAMPLE)?
        .unwrap_or(fa::DEFAULT_PRODUCTION_VOLUME)
        .to_string();
    let key = match one_flag(args, "--key", PRODUCE_EXAMPLE)? {
        Some(k) => k.to_string(),
        None => {
            let parts: Vec<&[u8]> = std::iter::once(matter.as_bytes())
                .chain(named.iter().map(|d| d.as_bytes()))
                .collect();
            format!(
                "produce:{}",
                hex(&fa_model::domain_digest(b"fa:cli-produce-key:v1", &parts))
            )
        }
    };
    let capability = ctx.capability(args, &["read", "produce"])?;
    let mut book = ctx.books.open(args)?;
    let target = ctx.files.resolve(out);
    if target.exists() {
        return Err(usage(
            format!("{out} already exists; a production volume is written into a new directory"),
            "choose a new --out directory; an existing path is never reused",
        ));
    }
    let date = control_date(args, &book)?;
    // Every document's read is judged before the numbers are journaled.
    let (produced, volume) = book.produce_volume(
        &capability,
        matter,
        documents,
        &volume,
        date,
        key.as_bytes(),
    )??;
    std::fs::create_dir(&target).map_err(|e| {
        usage(
            format!("cannot create the production directory {out}: {e}"),
            "choose a new --out directory; the Bates numbers stay journaled, and the identical command returns this production",
        )
    })?;
    let mut files = vec![
        (
            format!("{}.dat", volume.volume),
            volume.dat.clone().into_bytes(),
        ),
        (
            format!("{}.opt", volume.volume),
            volume.opt.clone().into_bytes(),
        ),
    ];
    if !volume.natives.is_empty() {
        std::fs::create_dir(target.join("NATIVES")).map_err(|e| {
            Fail::Environment(format!(
                "could not create {out}/NATIVES: {e}; the Bates numbers stay journaled, so rerun the identical command with a new --out"
            ))
        })?;
        files.extend(volume.natives.iter().cloned());
    }
    let mut written = Vec::with_capacity(files.len());
    for (name, bytes) in &files {
        let path = format!("{out}/{name}");
        write_new_output_file(&ctx.files, &path, bytes, "production", "--out")?;
        written.push(obj(vec![
            ("name", s(name)),
            ("bytes", Json::Int(bytes.len() as i128)),
            (
                "digest",
                s(hex(&fa_model::domain_digest(
                    b"fa:production-file:v1",
                    &[bytes],
                ))),
            ),
        ]));
    }
    ctx.out.at_book(&book)?;
    let profile = &produced.profile;
    let ranges: Vec<Json> = produced
        .ranges
        .iter()
        .zip(&volume.records)
        .map(|(r, record)| {
            obj(vec![
                ("document", s(hex(&r.range.document.0))),
                ("beg_bates", s(profile.label(r.range.start))),
                ("end_bates", s(profile.label(r.range.end))),
                ("pages", Json::Int(i128::from(r.range.pages()))),
                ("designation", s(designation_name(r.range.designation))),
                ("assigned", Json::Bool(r.assigned)),
                ("redacted", Json::Bool(record.redacted)),
                (
                    "native",
                    if record.native_path.is_empty() {
                        Json::Null
                    } else {
                        s(&record.native_path)
                    },
                ),
            ])
        })
        .collect();
    let assigned = produced.ranges.iter().filter(|r| r.assigned).count();
    let (record, recorded_at) = produced
        .record
        .map_or((Json::Null, Json::Null), |(v, at)| (vid_hex(v), seq(at)));
    ctx.out.event(
        "production_recorded",
        vec![
            ("matter", s(&profile.matter)),
            ("record", record),
            ("recorded_at", recorded_at),
            ("already_recorded", Json::Bool(produced.already_recorded)),
            ("next_bates", s(profile.label(produced.next_bates))),
            ("volume", s(&volume.volume)),
            ("out", s(out)),
            ("ranges", Json::Arr(ranges)),
            ("files", Json::Arr(written)),
        ],
        &format!(
            "matter {}: {} document(s) in {out} ({assigned} newly numbered, next {})",
            profile.matter,
            produced.ranges.len(),
            profile.label(produced.next_bates)
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_arguments_name_pages_and_designations_or_refuse() {
        let oid = "ab".repeat(32);
        let parsed = |text: &str| parse_document(text).ok().map(|d| (d.pages, d.designation));
        assert_eq!(parsed(&oid), Some((None, None)));
        assert_eq!(parsed(&format!("{oid}:12:aeo")), Some((Some(12), Some(2))));
        assert_eq!(
            parsed(&format!("{oid}::confidential")),
            Some((None, Some(1)))
        );
        for bad in [
            format!("{oid}:x"),
            format!("{oid}:1:secret"),
            format!("{oid}:1:aeo:extra"),
            "abc".to_string(),
        ] {
            assert!(parse_document(&bad).is_err(), "{bad}");
        }
        assert_eq!(designation_name(3), "highly-confidential");
        assert_eq!(load_file_name(1), "dat");
    }
}
