//! `fa export` (plan §8.6, §15.9): the committed journal at one coordinate
//! in an interop format. `fa-formats` writes the AICPA ADS GL package, OECD
//! SAF-T, the CSV GL extract, Beancount or hledger from the facade's single
//! `FormatJournal` selection, so every format exports the same legs. Each
//! export carries its coordinate certificate: the book, base unit, effective
//! through, known-at sequence, entry count and content digest. Nothing is
//! written to the book. `--out` names a new file (a new directory for the
//! four-table ADS package); without it the content is returned inline.

use fa_policy::Op;
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, known_at_flag, usage, write_new_output_file};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa export ads|saft|csv-gl|beancount|hledger|ndjson|xbrl (--period <code> | --as-of YYYY-MM-DD) [--as-known-at HEAD|<seq>|<RFC3339>] [--out <new path>] --json";

/// One output file of an export: its name in the package and its bytes.
struct ExportFile {
    name: &'static str,
    content: String,
}

pub(crate) fn export_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let format = match args.positional.get(1).map(String::as_str) {
        Some(format @ ("ads" | "saft" | "csv-gl" | "beancount" | "hledger" | "ndjson" | "xbrl"))
            if args.positional.len() == 2 =>
        {
            format
        }
        Some(other) if args.positional.len() == 2 => {
            return Err(usage(format!("unknown export format `{other}`"), EXAMPLE));
        }
        _ => return Err(usage("export needs exactly one format", EXAMPLE)),
    };
    for flag in [
        "--period",
        "--as-of",
        "--as-known-at",
        "--known-at",
        "--out",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("export takes only one {flag}"), EXAMPLE));
        }
    }
    let output = args.flag("--out");
    if output.is_some_and(|path| path.is_empty() || path == "-") {
        return Err(usage(
            "--out names a new file (a new directory for ads); - is not an output path",
            "omit --out to receive the complete export inline",
        ));
    }
    // An export discloses the journal to an outsider, as a proof or a
    // bundle does: authority is checked before the book is read.
    let capability = ctx.capability(args, &["read", "produce"])?;
    for op in [Op::Read, Op::Produce] {
        fa_policy::require(&capability, op, "exporting the journal")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let book = ctx.books.open(args)?;
    let through = match (args.flag("--period"), args.flag("--as-of")) {
        (Some(code), None) => {
            let periods = book.periods()?;
            let period = periods.iter().find(|p| p.code == code).ok_or_else(|| {
                usage(
                    format!("no period `{code}` in this book"),
                    "fa period list --json names the periods",
                )
            })?;
            DateDay(period.end.0 - 1)
        }
        (None, Some(date)) => DateDay::parse(date)
            .map_err(|e| usage(format!("--as-of: {e}"), "--as-of YYYY-MM-DD"))?,
        _ => {
            return Err(usage(
                "export needs exactly one of --period <code> (through its last day) or --as-of YYYY-MM-DD",
                EXAMPLE,
            ));
        }
    };
    let (known_at, _) = known_at_flag(args, &book, &ctx.out)?;
    let journal = book.format_journal(through, known_at)?;
    let written = |e: fa_formats::FormatError| Fail::Internal(format!("{format} writer: {e}"));
    let files = match format {
        "ads" => {
            let package = fa_formats::ads::write_ads_package(&journal).map_err(written)?;
            vec![
                ExportFile {
                    name: "Chart_of_Accounts.txt",
                    content: package.chart_of_accounts,
                },
                ExportFile {
                    name: "GL_Detail.txt",
                    content: package.gl_detail,
                },
                ExportFile {
                    name: "Trial_Balance.txt",
                    content: package.trial_balance,
                },
                ExportFile {
                    name: "ADS_Coordinate_Certificate.toml",
                    content: package.certificate_toml,
                },
            ]
        }
        "saft" => vec![ExportFile {
            name: "SAF-T.xml",
            content: fa_formats::saft::write_saft_xml(&journal).map_err(written)?,
        }],
        "csv-gl" => vec![ExportFile {
            name: "gl.csv",
            content: fa_formats::csv_gl::write_csv_gl(&journal),
        }],
        "beancount" => vec![ExportFile {
            name: "journal.beancount",
            content: fa_formats::beancount::write_beancount(&journal),
        }],
        "ndjson" => vec![ExportFile {
            name: "gl.ndjson",
            content: fa_formats::csv_gl::write_ndjson_gl_stream(&journal).map_err(written)?,
        }],
        "xbrl" => vec![ExportFile {
            name: "instance.xbrl",
            content: fa_formats::xbrl::write_format_journal_xbrl_xml(&journal).map_err(written)?,
        }],
        _ => vec![ExportFile {
            name: "journal.hledger",
            content: fa_formats::beancount::write_hledger(&journal),
        }],
    };
    let total: usize = files.iter().map(|f| f.content.len()).sum();
    let max_inline = crate::verbs::registry()
        .map_err(|e| Fail::Internal(e.into()))?
        .daemon
        .max_frame_bytes
        .saturating_sub(32 * 1024);
    if output.is_none() && total > max_inline {
        return Err(usage(
            format!(
                "the {format} export is {total} bytes, beyond the inline transport's {max_inline}; nothing was truncated"
            ),
            "write it to a new path with --out, or narrow it with --as-of or --period",
        ));
    }
    let mut paths = Vec::new();
    if let Some(path) = output {
        if format == "ads" {
            std::fs::create_dir(ctx.files.resolve(path)).map_err(|e| {
                usage(
                    format!("cannot create the ADS package directory {path}: {e}"),
                    "choose a new --out directory; an existing path is never reused",
                )
            })?;
            for file in &files {
                let inner = format!("{path}/{}", file.name);
                write_new_output_file(
                    &ctx.files,
                    &inner,
                    file.content.as_bytes(),
                    "export",
                    "--out",
                )?;
                paths.push(inner);
            }
        } else {
            write_new_output_file(
                &ctx.files,
                path,
                files[0].content.as_bytes(),
                "export",
                "--out",
            )?;
            paths.push(path.to_string());
        }
    }
    let out = &ctx.out;
    out.at_book(&book)?;
    let coordinate = &journal.coordinate;
    let files_json: Vec<Json> = files
        .iter()
        .map(|file| {
            obj(vec![
                ("name", s(file.name)),
                ("bytes", Json::Int(file.content.len() as i128)),
                (
                    "digest",
                    s(hex(&fa_model::domain_digest(
                        b"fa:export-file:v1",
                        &[file.content.as_bytes()],
                    ))),
                ),
                (
                    "content",
                    if output.is_some() {
                        Json::Null
                    } else {
                        s(file.content.as_str())
                    },
                ),
            ])
        })
        .collect();
    out.event(
        "journal_exported",
        vec![
            ("format", s(format)),
            (
                "effective_through",
                s(coordinate.effective_through.render()),
            ),
            ("known_at", Json::Int(i128::from(coordinate.known_at_seq))),
            ("entries", Json::Int(i128::from(coordinate.entry_count))),
            ("accounts", Json::Int(journal.accounts.len() as i128)),
            ("content_digest", s(hex(&coordinate.content_digest))),
            ("certificate_digest", s(hex(&coordinate.certificate_digest))),
            ("out", output.map_or(Json::Null, s)),
            ("files", Json::Arr(files_json)),
        ],
        &format!(
            "exported {} entries through {} at known-at {} as {format}{}",
            coordinate.entry_count,
            coordinate.effective_through.render(),
            coordinate.known_at_seq,
            if paths.is_empty() {
                String::new()
            } else {
                format!(" to {}", paths.join(", "))
            },
        ),
    );
    Ok(())
}
