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
use crate::cli::{Ctx, Fail, hex, known_at_read_flag, usage, write_new_output_file};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa export ads|saft|csv-gl|beancount|hledger|ndjson|xbrl (--period <code> | --as-of YYYY-MM-DD) [--as-known-at HEAD|<seq>|<RFC3339>] [--out <new path>] --json, fa export ads [--account <code>] (--period <code> | --as-of YYYY-MM-DD) --out <new dir> --with-proofs [--state <oid|latest>] --json, fa export saft (--period <code> | --as-of YYYY-MM-DD) --out <new dir> --with-proofs [--state <oid|latest>] --json, or fa export warehouse --connector snowflake|bigquery|s3 [--destination <ref>] (--report <C:oid|oid|certificate-file> | --period <code> | --as-of YYYY-MM-DD) [--as-known-at HEAD|<seq>|<RFC3339>] [--out <new path>] --json";
const WAREHOUSE_EXAMPLE: &str = "fa export warehouse --connector snowflake|bigquery|s3 [--destination <ref>] (--report <C:oid|oid|certificate-file> | --period <code> | --as-of YYYY-MM-DD) [--as-known-at HEAD|<seq>|<RFC3339>] [--out <new path>] --json";
/// The complete-prefix bundle and its receipt an ADS extract is proved with.
const PROOF_BUNDLE: &str = "ADS_Proof.fab";
const PROOF_RECEIPT: &str = "ADS_Proof.receipt";
/// The same pair beside a SAF-T extract.
const SAFT_PROOF_BUNDLE: &str = "SAFT_Proof.fab";
const SAFT_PROOF_RECEIPT: &str = "SAFT_Proof.receipt";

/// The bundle and receipt file names a proved `format` package carries.
fn proof_files(format: &str) -> (&'static str, &'static str) {
    if format == "saft" {
        (SAFT_PROOF_BUNDLE, SAFT_PROOF_RECEIPT)
    } else {
        (PROOF_BUNDLE, PROOF_RECEIPT)
    }
}

/// One output file of an export: its name in the package and its bytes.
struct ExportFile {
    name: &'static str,
    content: String,
}

pub(crate) fn export_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let format = match args.positional.get(1).map(String::as_str) {
        Some("warehouse") if args.positional.len() == 2 => {
            return export_warehouse_cmd(ctx, args);
        }
        Some(
            format @ ("ads" | "saft" | "csv-gl" | "beancount" | "hledger" | "ndjson" | "xbrl"),
        ) if args.positional.len() == 2 => format,
        Some(other) if args.positional.len() == 2 => {
            return Err(usage(format!("unknown export format `{other}`"), EXAMPLE));
        }
        _ => return Err(usage("export needs exactly one format", EXAMPLE)),
    };
    for flag in ["--connector", "--destination", "--report"] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!("{flag} belongs to `fa export warehouse`"),
                WAREHOUSE_EXAMPLE,
            ));
        }
    }
    for flag in [
        "--period",
        "--as-of",
        "--as-known-at",
        "--known-at",
        "--out",
        "--state",
        "--account",
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
    // An ADS or SAF-T extract with its proofs (plan §13.1, fa-2q91): the
    // complete prefix of a recorded accumulator state, and the extract
    // selected at exactly that state's sequence, so fa-verify ads or saft can
    // check every row. A proved SAF-T file is written into a new directory
    // beside its bundle and receipt, as the ADS package is.
    let with_proofs = args.switch("--with-proofs");
    if with_proofs
        && (!matches!(format, "ads" | "saft")
            || output.is_none()
            || args.flag("--as-known-at").is_some()
            || args.flag("--known-at").is_some())
    {
        return Err(usage(
            "--with-proofs proves an ADS or SAF-T package written to a new --out directory, at its proof state's own sequence: no --as-known-at",
            "fa export ads|saft --period <code> --out <new dir> --with-proofs [--state <oid|latest>] --json",
        ));
    }
    if !with_proofs && args.flag("--state").is_some() {
        return Err(usage(
            "--state names the accumulator state an ADS extract is proved against; it goes with --with-proofs",
            "add --with-proofs, or drop --state",
        ));
    }
    let state = match args.flag("--state") {
        None | Some("latest") => None,
        Some(text) => Some(fa_model::Oid(crate::proof::fixed_hex(text, "--state")?)),
    };
    // One account's extract (plan §13.1): every entry with a leg on it, and
    // its balance. With --with-proofs the bundle proves that account's
    // entries complete through the cutoff (ScopeIndexComplete).
    let account = args.flag("--account");
    if account.is_some() && format != "ads" {
        return Err(usage(
            "--account scopes an ADS extract to one account; other formats export the whole chart",
            "fa export ads --account <code> --period <code> --out <new dir> [--with-proofs] --json",
        ));
    }
    // An export discloses the journal to an outsider, as a proof or a
    // bundle does: authority is checked before the book is read.
    let capability = ctx.capability(args, &["read", "produce"])?;
    for op in [Op::Read, Op::Produce] {
        fa_policy::require(&capability, op, "exporting the journal")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let selection = match (args.flag("--period"), args.flag("--as-of")) {
        (Some(code), None) => fa::TrialBalanceSelection::Periods(vec![code.to_string()]),
        (None, Some(date)) => fa::TrialBalanceSelection::AsOf(
            DateDay::parse(date)
                .map_err(|e| usage(format!("--as-of: {e}"), "--as-of YYYY-MM-DD"))?,
        ),
        _ => {
            return Err(usage(
                "export needs exactly one of --period <code> (through its last day) or --as-of YYYY-MM-DD",
                EXAMPLE,
            ));
        }
    };
    let mut selected = None;
    let mut proved = None;
    let book = ctx.books.open_admitted(args, |book| {
        // The bundle is produced first (its own admission precedes every
        // read of the journal); the read scope borrows the book after it.
        // An account's bundle ends at the cutoff, so a --period cutoff is
        // read first under the admitted read scope (at a pinned capability's
        // own pin), and checked again at the proof's own sequence below.
        let planned_cutoff = match (with_proofs, account, &selection) {
            (true, Some(_), fa::TrialBalanceSelection::Periods(_)) => {
                let at = match capability.known_at_pin() {
                    Some(pin) => Some(pin.min(book.head()?)),
                    None => None,
                };
                let scope = book.read_scope(capability.holder(), &capability)??;
                let seq = scope.admit_report(&selection.clone().into(), at)??;
                Some(cutoff_at(&scope, &selection, seq)?)
            }
            (true, Some(_), fa::TrialBalanceSelection::AsOf(day)) => Some(*day),
            _ => None,
        };
        let proved_at = if with_proofs {
            let scope = match (account, planned_cutoff) {
                (Some(code), Some(cutoff)) => fa::BundleScope::Index(fa::ScopeRequest::Account {
                    account: fa_model::account_vid(book.context().book_id, code),
                    from: i32::MIN,
                    to: cutoff.0,
                }),
                _ => fa::BundleScope::Prefix,
            };
            let request = fa::BundleRequest {
                scope,
                balances: Vec::new(),
                inline_documents: false,
            };
            let Some(produced) =
                book.produce_bundle(capability.holder(), &capability, state, &request)??
            else {
                return Err(fa_journal::Refusal::new(
                    fa::proof::code::PROOF_STATE_UNKNOWN,
                    fa_journal::exit::USAGE,
                    match state {
                        Some(oid) => format!(
                            "accumulator state {} is not on this book's recorded checkpoint chain",
                            hex(&oid.0)
                        ),
                        None => "the book has no recorded accumulator checkpoint to prove the extract against".into(),
                    },
                    "plan §13.1 (fa export ads --with-proofs proves the extract against a journaled AccumulatorState)",
                    "use fa verify accumulator --json to find a recorded state; the owner can publish one with fa checkpoint create --grant witness",
                )
                .into());
            };
            let through = produced.checkpoint.checkpoint.body.statement.through_seq;
            proved = Some((produced, hex(&book.checkpoint_public_key())));
            Some(through)
        } else {
            None
        };
        let scope = book.read_scope(capability.holder(), &capability)??;
        let known_at = match proved_at {
            Some(through) => Some(through),
            None => known_at_read_flag(args, book, &ctx.out, &capability)?.0,
        };
        // An export is cumulative stock, even when --period names its
        // boundary. Admit that reach before reading any period or entry.
        let seq = scope.admit_report(&selection.clone().into(), known_at)??;
        let through = cutoff_at(&scope, &selection, seq)?;
        if planned_cutoff.is_some_and(|planned| planned != through) {
            return Err(Fail::Internal(format!(
                "the account bundle's cutoff is not the period's end at the proof state's sequence {}",
                seq.0
            )));
        }
        let journal = book.format_journal(through, Some(seq))?;
        // A migration chunk counts only when its run makes it visible, and
        // fa-verify learns that from migration-aware balance proofs, which
        // carry the run bodies (fa-mv0f). So a proved whole-chart extract is
        // produced again at the same state with a balance over every chart
        // account in every unit its legs use, cut off at the extract's
        // cutoff. That covers each cell a chunk, visible or not, could touch,
        // and is a second witness of every Trial_Balance row.
        if account.is_none()
            && let Some((first, key)) = proved.take()
        {
            let book_id = book.context().book_id;
            let mut units: std::collections::BTreeSet<u32> = journal
                .entries
                .iter()
                .flat_map(|e| e.legs.iter().map(|l| l.amount.unit.0))
                .collect();
            units.insert(book.spec()?.base_unit.0);
            let balances = journal
                .accounts
                .iter()
                .flat_map(|a| {
                    let vid = fa_model::account_vid(book_id, &a.code);
                    units.iter().map(move |unit| fa::BalanceRequest {
                        account: vid,
                        unit: *unit,
                        effective_through: Some(through.0),
                    })
                })
                .collect();
            let request = fa::BundleRequest {
                scope: fa::BundleScope::Prefix,
                balances,
                inline_documents: false,
            };
            let state = first.checkpoint.checkpoint.body.state_oid;
            let again = book
                .produce_bundle(capability.holder(), &capability, Some(state), &request)??
                .ok_or_else(|| {
                    Fail::Internal("the proof state is no longer on the checkpoint chain".into())
                })?;
            proved = Some((again, key));
        }
        selected = Some(match account {
            None => journal,
            Some(code) => journal.scoped_to_account(code).map_err(|_| {
                usage(
                    format!("no account `{code}` in this book's chart at {}", seq.0),
                    "name a chart account (fa chart show --json)",
                )
            })?,
        });
        Ok(())
    })?;
    let journal = selected.ok_or_else(|| Fail::Internal("export selection is missing".into()))?;
    // One account's proof is its scope-index run: it holds no migration
    // run's lifecycle controls and no balance, so fa-verify cannot decide
    // whether a migration entry in it counts (fa-mv0f), and refuses it.
    let chunks = journal
        .entries
        .iter()
        .filter(|e| e.class == fa_model::EntryClass::MIGRATION)
        .count();
    if with_proofs && account.is_some() && chunks > 0 {
        ctx.out.warn(format!(
            "this account's extract holds {chunks} migration {} whose run visibility its account bundle cannot prove, so fa-verify ads will refuse {}; the whole-chart extract (no --account) carries the balances that prove it",
            if chunks == 1 { "entry" } else { "entries" },
            if chunks == 1 { "it" } else { "them" },
        ));
    }
    let files = render_files(format, &journal)?;
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
        if format == "ads" || with_proofs {
            std::fs::create_dir(ctx.files.resolve(path)).map_err(|e| {
                usage(
                    format!("cannot create the {format} package directory {path}: {e}"),
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
            if let Some((produced, _)) = &proved {
                let (bundle, receipt) = proof_files(format);
                for (name, bytes) in [
                    (bundle, produced.bundle.bytes.as_slice()),
                    (receipt, produced.receipt.as_slice()),
                ] {
                    let inner = format!("{path}/{name}");
                    write_new_output_file(&ctx.files, &inner, bytes, "export", "--out")?;
                    paths.push(inner);
                }
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
    out.known_at(fgdb_types::CommitSeq(coordinate.known_at_seq));
    let listed = files_json(&files, output.is_none());
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
            ("account_scope", account.map_or(Json::Null, s)),
            ("files", Json::Arr(listed)),
            (
                "proof",
                proved.as_ref().map_or(Json::Null, |(produced, key)| {
                    let statement = &produced.checkpoint.checkpoint.body.statement;
                    obj(vec![
                        ("bundle", s(proof_files(format).0)),
                        ("receipt", s(proof_files(format).1)),
                        ("bundle_digest", s(hex(&produced.bundle.digest))),
                        (
                            "state",
                            s(hex(&produced.checkpoint.checkpoint.body.state_oid.0)),
                        ),
                        (
                            "through_seq",
                            Json::Int(i128::from(statement.through_seq.0)),
                        ),
                        (
                            "completeness",
                            s(if account.is_some() {
                                "scope_index_complete"
                            } else {
                                "seq_range_complete"
                            }),
                        ),
                        ("checkpoint_public_key", s(key.as_str())),
                    ])
                }),
            ),
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

/// The inclusive effective cutoff an export selects at `seq`: the last day
/// of the --period named, or the --as-of day.
fn cutoff_at(
    scope: &fa::ReadScope<'_>,
    selection: &fa::TrialBalanceSelection,
    seq: fgdb_types::CommitSeq,
) -> Result<DateDay, Fail> {
    match selection {
        fa::TrialBalanceSelection::Periods(periods) => {
            let code = &periods[0];
            let period = scope.period_at(code, Some(seq))??.ok_or_else(|| {
                usage(
                    format!("no period `{code}` in this book at {}", seq.0),
                    "select a period recorded at the requested known-at sequence",
                )
            })?;
            Ok(DateDay(period.end.0 - 1))
        }
        fa::TrialBalanceSelection::AsOf(day) => Ok(*day),
        fa::TrialBalanceSelection::Activity(_) => Err(Fail::Internal(
            "an export cannot select period activity".into(),
        )),
    }
}

/// The four tables of an ADS package, in the order `fa export ads` writes
/// them into its directory.
const ADS_FILES: [&str; 4] = [
    "Chart_of_Accounts.txt",
    "GL_Detail.txt",
    "Trial_Balance.txt",
    "ADS_Coordinate_Certificate.toml",
];

/// The files `fa export <format>` writes for `journal`, in package order.
fn render_files(
    format: &str,
    journal: &fa_formats::FormatJournal,
) -> Result<Vec<ExportFile>, Fail> {
    let written = |e: fa_formats::FormatError| Fail::Internal(format!("{format} writer: {e}"));
    Ok(match format {
        "ads" => {
            let package = fa_formats::ads::write_ads_package(journal).map_err(written)?;
            let [chart, detail, trial, certificate] = ADS_FILES;
            vec![
                ExportFile {
                    name: chart,
                    content: package.chart_of_accounts,
                },
                ExportFile {
                    name: detail,
                    content: package.gl_detail,
                },
                ExportFile {
                    name: trial,
                    content: package.trial_balance,
                },
                ExportFile {
                    name: certificate,
                    content: package.certificate_toml,
                },
            ]
        }
        "saft" => vec![ExportFile {
            name: "SAF-T.xml",
            content: fa_formats::saft::write_saft_xml(journal).map_err(written)?,
        }],
        "csv-gl" => vec![ExportFile {
            name: "gl.csv",
            content: fa_formats::csv_gl::write_csv_gl(journal),
        }],
        "beancount" => vec![ExportFile {
            name: "journal.beancount",
            content: fa_formats::beancount::write_beancount(journal),
        }],
        "ndjson" => vec![ExportFile {
            name: "gl.ndjson",
            content: fa_formats::csv_gl::write_ndjson_gl_stream(journal).map_err(written)?,
        }],
        "xbrl" => vec![ExportFile {
            name: "instance.xbrl",
            content: fa_formats::xbrl::write_format_journal_xbrl_xml(journal).map_err(written)?,
        }],
        _ => vec![ExportFile {
            name: "journal.hledger",
            content: fa_formats::beancount::write_hledger(journal),
        }],
    })
}

/// Each file's name, length and digest (fa:export-file:v1), with its
/// content when it is returned inline.
fn files_json(files: &[ExportFile], inline: bool) -> Vec<Json> {
    files
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
                    if inline {
                        s(file.content.as_str())
                    } else {
                        Json::Null
                    },
                ),
            ])
        })
        .collect()
}

const VERIFY_EXAMPLE: &str = "fa verify export ads|saft|csv-gl|beancount|hledger|ndjson|xbrl|warehouse <the exported file, or the ads package directory> --json";
const VERIFY_FIX: &str = "export again with fa export at the coordinate you need and verify that file; an edited export is not the book's";
const VERIFY_CITE: &str = "plan §16 (export then import is the identity on folds) and the export's coordinate certificate (content_digest over the canonical journal, certificate_digest over its coordinate)";

/// `fa export warehouse` (plan §5.7, §15; beads fa-ff6, fa-lzrn): invoke the
/// host's `fwc` connector (`snowflake`, `bigquery`, `s3`) as a supervised
/// subprocess over a verified report certificate or journal coordinate, and
/// emit the canonical `WarehouseExportReceipt` control record.
fn export_warehouse_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.switch("--with-proofs") || args.flag("--state").is_some() {
        return Err(usage(
            "--with-proofs and --state belong to `fa export ads`",
            WAREHOUSE_EXAMPLE,
        ));
    }
    for flag in [
        "--connector",
        "--destination",
        "--report",
        "--period",
        "--as-of",
        "--as-known-at",
        "--known-at",
        "--out",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("export warehouse takes only one {flag}"),
                WAREHOUSE_EXAMPLE,
            ));
        }
    }
    let connector_raw = args.require("--connector", "snowflake|bigquery|s3")?;
    let connector = fa_formats::fwc::WarehouseConnector::parse(connector_raw)
        .map_err(|e| usage(format!("--connector: {e}"), WAREHOUSE_EXAMPLE))?;
    let destination = args.flag("--destination").unwrap_or(connector.as_str());
    if destination.trim().is_empty() {
        return Err(usage("--destination must not be empty", WAREHOUSE_EXAMPLE));
    }
    let output = args.flag("--out");
    if let Some(path) = output {
        if path.is_empty() || path == "-" {
            return Err(usage(
                "--out names a new file for the warehouse export receipt; - is not an output path",
                "omit --out to receive the receipt inline",
            ));
        }
        if ctx.files.resolve(path).exists() {
            return Err(usage(
                format!("output file {path} already exists; an existing path is never overwritten"),
                "choose a new --out path",
            ));
        }
    }
    let capability = ctx.capability(args, &["read", "produce"])?;
    for op in [Op::Read, Op::Produce] {
        fa_policy::require(
            &capability,
            op,
            "exporting a certified report to a warehouse",
        )
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let report_arg = args.flag("--report");
    if report_arg.is_some()
        && (args.flag("--period").is_some()
            || args.flag("--as-of").is_some()
            || args.flag("--as-known-at").is_some()
            || args.flag("--known-at").is_some())
    {
        return Err(usage(
            "--report carries its own certified coordinate; do not combine it with --period, --as-of, or --as-known-at",
            WAREHOUSE_EXAMPLE,
        ));
    }
    let selection = if report_arg.is_none() {
        Some(match (args.flag("--period"), args.flag("--as-of")) {
            (Some(code), None) => fa::TrialBalanceSelection::Periods(vec![code.to_string()]),
            (None, Some(date)) => fa::TrialBalanceSelection::AsOf(
                DateDay::parse(date)
                    .map_err(|e| usage(format!("--as-of: {e}"), "--as-of YYYY-MM-DD"))?,
            ),
            _ => {
                return Err(usage(
                    "export warehouse needs --report <certificate> or one of --period <code> or --as-of YYYY-MM-DD",
                    WAREHOUSE_EXAMPLE,
                ));
            }
        })
    } else {
        None
    };

    let mut prepared: Option<(Vec<u8>, [u8; 32], fa_formats::FormatJournal)> = None;
    let book = ctx.books.open_admitted(args, |book| {
        let principal = capability.holder();
        if let Some(report_path) = report_arg {
            let _ = book.read_scope(principal, &capability)??;
            let cert_bytes = crate::notary::read_certificate_bytes(
                book,
                &ctx.files,
                report_path,
                principal,
                &capability,
            )?;
            let artifact = fa::ReportArtifact::decode(&cert_bytes)?;
            crate::notary::prepare_artifact_history(
                book,
                principal,
                &capability,
                &artifact,
                &cert_bytes,
            )?;
            if artifact.family() == fa::ReportArtifactFamily::ScenarioDiff {
                let certificate = fa::ScenarioDiffCertificate::decode(&cert_bytes)?;
                book.replay_scenario_diff(principal, &capability, &certificate)??;
            } else {
                book.replay_report_artifact_for(
                    principal,
                    &capability,
                    &cert_bytes,
                    Some(artifact.digest()),
                    fa::ReportArtifactExpectation::AsSupplied,
                )??;
            }
            let seq = artifact.known_at();
            let through = book
                .periods()?
                .into_iter()
                .filter(|p| p.created_at <= seq)
                .map(|p| DateDay(p.end.0 - 1))
                .max()
                .or_else(|| book.spec().ok().and_then(|s| s.opening_date))
                .unwrap_or(DateDay(0));
            let _ = book
                .read_scope(principal, &capability)??
                .admit_report(&fa::TrialBalanceSelection::AsOf(through).into(), Some(seq))??;
            let journal = book.format_journal(through, Some(seq))?;
            prepared = Some((cert_bytes, *artifact.digest(), journal));
        } else if let Some(selection) = &selection {
            let scope = book.read_scope(principal, &capability)??;
            let known_at = known_at_read_flag(args, book, &ctx.out, &capability)?.0;
            let seq = scope.admit_report(&selection.clone().into(), known_at)??;
            let through = match selection {
                fa::TrialBalanceSelection::Periods(periods) => {
                    let code = &periods[0];
                    let period = scope.period_at(code, Some(seq))??.ok_or_else(|| {
                        usage(
                            format!("no period `{code}` in this book at {}", seq.0),
                            "select a period recorded at the requested known-at sequence",
                        )
                    })?;
                    DateDay(period.end.0 - 1)
                }
                fa::TrialBalanceSelection::AsOf(day) => *day,
                fa::TrialBalanceSelection::Activity(_) => {
                    return Err(Fail::Internal(
                        "an export cannot select period activity".into(),
                    ));
                }
            };
            let journal = book.format_journal(through, Some(seq))?;
            let stream = fa_formats::csv_gl::write_ndjson_gl_stream(&journal)
                .map_err(|e| Fail::Internal(format!("warehouse ndjson writer: {e}")))?;
            let cert_digest = journal.coordinate.certificate_digest;
            prepared = Some((stream.into_bytes(), cert_digest, journal));
        }
        Ok(())
    })?;
    let (report_bytes, cert_digest, journal) =
        prepared.ok_or_else(|| Fail::Internal("warehouse export selection is missing".into()))?;
    let receipt = fa_formats::fwc::invoke_fwc_warehouse_export(
        std::path::Path::new("fwc"),
        connector,
        destination,
        &report_bytes,
        cert_digest,
    )
    .map_err(|err| match err {
        fa_formats::fwc::FwcSubprocessError::Environment(refusal) => Fail::Environment(format!(
            "`fwc` did not run: {}; install flywheel_connectors (`fwc` on PATH)",
            refusal.message
        )),
        fa_formats::fwc::FwcSubprocessError::Format(error) => usage(
            format!("the fwc warehouse receipt: {error}"),
            WAREHOUSE_EXAMPLE,
        ),
    })?;
    let canonical = receipt
        .canonical_bytes()
        .map_err(|e| Fail::Internal(format!("warehouse receipt encode: {e}")))?;
    let control_oid = receipt
        .control_record_digest()
        .map_err(|e| Fail::Internal(format!("warehouse control digest: {e}")))?;
    let decoded = fa_formats::fwc::WarehouseExportReceipt::decode_canonical(&canonical)
        .map_err(|e| Fail::Internal(format!("warehouse receipt decode: {e}")))?;
    debug_assert_eq!(decoded, receipt);
    let coordinate = &journal.coordinate;
    let files = vec![ExportFile {
        name: "Warehouse_Export_Receipt.toml",
        content: render_warehouse_receipt_file(&receipt, &canonical, &control_oid, coordinate),
    }];
    if let Some(path) = output {
        write_new_output_file(
            &ctx.files,
            path,
            files[0].content.as_bytes(),
            "export",
            "--out",
        )?;
    }
    let out = &ctx.out;
    out.at_book(&book)?;
    out.known_at(fgdb_types::CommitSeq(coordinate.known_at_seq));
    let listed = files_json(&files, output.is_none());
    out.event(
        "journal_exported",
        vec![
            ("format", s("warehouse")),
            (
                "effective_through",
                s(coordinate.effective_through.render()),
            ),
            ("known_at", Json::Int(i128::from(coordinate.known_at_seq))),
            ("entries", Json::Int(i128::from(coordinate.entry_count))),
            ("accounts", Json::Int(journal.accounts.len() as i128)),
            ("content_digest", s(hex(&control_oid.0))),
            (
                "certificate_digest",
                s(hex(&receipt.report_certificate_digest)),
            ),
            ("out", output.map_or(Json::Null, s)),
            ("account_scope", Json::Null),
            ("files", Json::Arr(listed)),
            ("proof", Json::Null),
        ],
        &format!(
            "exported certified report {} to warehouse {}:{} (control record {}, fwc receipt {})",
            hex(&receipt.report_certificate_digest),
            receipt.connector.as_str(),
            receipt.destination_ref,
            hex(&control_oid.0),
            hex(&receipt.fwc_receipt_hash),
        ),
    );
    Ok(())
}

fn render_warehouse_receipt_file(
    receipt: &fa_formats::fwc::WarehouseExportReceipt,
    canonical_bytes: &[u8],
    control_oid: &fa_model::Oid,
    coordinate: &fa_formats::ExportCoordinate,
) -> String {
    format!(
        "schema = \"fa.warehouse_export_receipt.v1\"\nconnector = {:?}\ndestination_ref = {:?}\nreport_digest = \"{}\"\nreport_certificate_digest = \"{}\"\npayload_document_oid = \"{}\"\nfwc_receipt_hash = \"{}\"\nrobot_schema_version = {:?}\ncontrol_record_oid = \"{}\"\ncanonical_hex = \"{}\"\neffective_through = \"{}\"\nknown_at_seq = {}\n",
        receipt.connector.as_str(),
        receipt.destination_ref,
        hex(&receipt.report_digest),
        hex(&receipt.report_certificate_digest),
        hex(&receipt.payload_document_oid.0),
        hex(&receipt.fwc_receipt_hash),
        receipt.robot_schema_version,
        hex(&control_oid.0),
        hex(canonical_bytes),
        coordinate.effective_through.render(),
        coordinate.known_at_seq,
    )
}

fn decode_hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for &[hi, lo] in bytes.as_chunks::<2>().0 {
        let hi = (hi as char).to_digit(16)?;
        let lo = (lo as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// The coordinate an export claims: where to select the book's journal
/// again, and the certificate digest its reader verified, when it verifies
/// one.
struct Claimed {
    effective_through: DateDay,
    known_at: u64,
    certificate_digest: Option<String>,
}

/// `fa verify export <format> <path>` (plan §16: export then import is the
/// identity on folds; bead fa-lzrn). The export is re-read with its
/// format's reader, and the book's journal is selected again at the
/// coordinate the export carries. What the re-read must match follows
/// registries/formats.toml:
/// - the audit standards and the CSV extract re-read to the identical
///   journal under their verified coordinate certificate;
/// - Beancount and hledger, balance-differential formats, refold to the
///   same balances;
/// - an XBRL instance re-reads its coordinate and calculation linkbase;
/// - an NDJSON stream re-reads its framing and header.
///
/// In every format each file must then be byte for byte what `fa export`
/// writes there. Nothing is written to the book.
pub(crate) fn verify_export(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, format, path] = args.positional.as_slice() else {
        return Err(usage(
            "verify export needs the format and the exported file (the package directory for ads)",
            VERIFY_EXAMPLE,
        ));
    };
    let (format, path) = (format.as_str(), path.as_str());
    if !matches!(
        format,
        "ads" | "saft" | "csv-gl" | "beancount" | "hledger" | "ndjson" | "xbrl" | "warehouse"
    ) {
        return Err(usage(
            format!("unknown export format `{format}`"),
            VERIFY_EXAMPLE,
        ));
    }
    if format == "warehouse" {
        return verify_warehouse_export(ctx, args, path);
    }
    if format == "ads" && path == "-" {
        return Err(usage(
            "an ads export is a package directory, not stdin",
            VERIFY_EXAMPLE,
        ));
    }
    let contents = if format == "ads" {
        // Host-path containment judged the package directory; its tables
        // must be regular files in it, never links that lead elsewhere.
        for name in ADS_FILES {
            let inner = format!("{path}/{name}");
            let regular = std::fs::symlink_metadata(ctx.files.resolve(&inner))
                .is_ok_and(|meta| meta.file_type().is_file());
            if !regular {
                return Err(usage(
                    format!("{inner} is not a regular file of an ads package"),
                    "pass the directory fa export ads --out wrote, with its four tables",
                ));
            }
        }
        ADS_FILES
            .iter()
            .map(|name| ctx.files.read_text(&format!("{path}/{name}")))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        vec![ctx.files.read_text(path)?]
    };
    let failed = |message: String| Fail::Verification {
        message,
        detail: obj(vec![("format", s(format)), ("file", s(path))]),
        cite: Some(VERIFY_CITE.into()),
        fix: Some(VERIFY_FIX.into()),
    };
    let unread = |e: fa_formats::FormatError| {
        failed(format!(
            "the {format} export does not re-read as an fa export: {e}"
        ))
    };
    let units = fa_formats::UnitCatalog::embedded()
        .map_err(|e| Fail::Internal(format!("unit catalog: {e}")))?;
    let first = contents.first().map_or("", String::as_str);
    let parsed = match format {
        "ads" => {
            let [chart, detail, trial, certificate] = contents.as_slice() else {
                return Err(Fail::Internal("an ads package has four files".into()));
            };
            let package = fa_formats::ads::AdsPackage {
                chart_of_accounts: chart.clone(),
                gl_detail: detail.clone(),
                trial_balance: trial.clone(),
                certificate_toml: certificate.clone(),
            };
            Some(fa_formats::ads::read_ads_package(&package, &units).map_err(unread)?)
        }
        "saft" => Some(fa_formats::saft::read_saft_xml(first, &units).map_err(unread)?),
        "csv-gl" => Some(fa_formats::csv_gl::read_csv_gl(first, &units).map_err(unread)?),
        "beancount" => Some(fa_formats::beancount::read_beancount(first, &units).map_err(unread)?),
        "hledger" => Some(fa_formats::beancount::read_hledger(first, &units).map_err(unread)?),
        _ => None,
    };
    let identity = matches!(format, "ads" | "saft" | "csv-gl");
    let (claimed, reread) = match (&parsed, format) {
        (Some(journal), _) => (
            Claimed {
                effective_through: journal.coordinate.effective_through,
                known_at: journal.coordinate.known_at_seq,
                certificate_digest: identity.then(|| hex(&journal.coordinate.certificate_digest)),
            },
            if identity { "journal" } else { "balances" },
        ),
        (None, "xbrl") => {
            let (coordinate, _) =
                fa_formats::xbrl::verify_format_journal_xbrl_xml(first).map_err(unread)?;
            (
                Claimed {
                    effective_through: coordinate.effective_through,
                    known_at: coordinate.known_at_seq,
                    certificate_digest: Some(hex(&coordinate.certificate_digest)),
                },
                "coordinate",
            )
        }
        (None, _) => {
            fa_formats::csv_gl::verify_ndjson_gl_stream(first).map_err(unread)?;
            (ndjson_coordinate(first).map_err(&failed)?, "framing")
        }
    };
    let capability = ctx.capability(args, &["read", "verify"])?;
    for op in [Op::Read, Op::Verify] {
        fa_policy::require(&capability, op, "verifying an export against the journal")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let mut selected = None;
    let book = ctx.books.open_admitted(args, |book| {
        let scope = book.read_scope(capability.holder(), &capability)??;
        let selection = fa::TrialBalanceSelection::AsOf(claimed.effective_through);
        let seq = scope.admit_report(
            &selection.into(),
            Some(fgdb_types::CommitSeq(claimed.known_at)),
        )??;
        selected = Some(book.format_journal(claimed.effective_through, Some(seq))?);
        Ok(())
    })?;
    let journal =
        selected.ok_or_else(|| Fail::Internal("verify export selection is missing".into()))?;
    let coordinate = &journal.coordinate;
    let book_digest = hex(&coordinate.certificate_digest);
    if let Some(claimed_digest) = &claimed.certificate_digest
        && *claimed_digest != book_digest
    {
        return Err(failed(format!(
            "the export's coordinate certificate {claimed_digest} is not this book's at effective_through {}, known-at {} ({book_digest}): another book's export, or an edited coordinate",
            claimed.effective_through.render(),
            claimed.known_at,
        )));
    }
    match &parsed {
        Some(again) if identity => {
            fa_formats::verify_round_trip_identity(format, &journal, again).map_err(|e| {
                failed(format!(
                    "the {format} export re-reads to a different journal than the book's at its coordinate: {e}"
                ))
            })?;
        }
        Some(again) => {
            let folded = |j: &fa_formats::FormatJournal| {
                j.fold_balances()
                    .map_err(|e| failed(format!("the {format} export does not refold: {e}")))
            };
            if folded(again)? != folded(&journal)? {
                return Err(failed(format!(
                    "the {format} export refolds to different balances than the book's at its coordinate"
                )));
            }
        }
        None => {}
    }
    let expected = render_files(format, &journal)?;
    for (file, found) in expected.iter().zip(&contents) {
        if file.content != *found {
            let line = file
                .content
                .lines()
                .zip(found.lines())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| file.content.lines().count().min(found.lines().count()));
            return Err(failed(format!(
                "{} differs from what fa export {format} writes at this coordinate, first at line {}",
                file.name,
                line + 1
            )));
        }
    }
    let legs: usize = journal.entries.iter().map(|e| e.legs.len()).sum();
    let refold = journal
        .refold_digest()
        .map_err(|e| Fail::Internal(format!("refold digest: {e}")))?;
    let out = &ctx.out;
    out.at_book(&book)?;
    out.known_at(fgdb_types::CommitSeq(coordinate.known_at_seq));
    out.event(
        "export_verified",
        vec![
            ("format", s(format)),
            ("file", s(path)),
            (
                "effective_through",
                s(coordinate.effective_through.render()),
            ),
            ("known_at", Json::Int(i128::from(coordinate.known_at_seq))),
            ("entries", Json::Int(i128::from(coordinate.entry_count))),
            ("legs", Json::Int(legs as i128)),
            ("content_digest", s(hex(&coordinate.content_digest))),
            ("certificate_digest", s(&book_digest)),
            ("refold_digest", s(hex(&refold))),
            ("reread", s(reread)),
            ("files", Json::Arr(files_json(&expected, false))),
        ],
        &format!(
            "verified the {format} export {path}: byte for byte what fa export writes through {} at known-at {} ({} entries, {legs} legs); re-read: {reread}",
            coordinate.effective_through.render(),
            coordinate.known_at_seq,
            coordinate.entry_count,
        ),
    );
    Ok(())
}

/// The coordinate an NDJSON GL stream's `gl_stream_header` line claims.
fn ndjson_coordinate(stream: &str) -> Result<Claimed, String> {
    let header = stream
        .lines()
        .next()
        .and_then(|line| crate::json::parse(line).ok())
        .ok_or("the ndjson export has no JSON header line")?;
    let text = |key: &str| {
        header
            .get(key)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("the ndjson header has no {key}"))
    };
    let effective_through = DateDay::parse(text("effective_through")?)
        .map_err(|e| format!("the ndjson header's effective_through: {e}"))?;
    let known_at = match header.get("known_at_seq") {
        Some(Json::Int(seq)) => u64::try_from(*seq)
            .map_err(|_| "the ndjson header's known_at_seq is not a sequence".to_string())?,
        _ => return Err("the ndjson header has no known_at_seq".into()),
    };
    Ok(Claimed {
        effective_through,
        known_at,
        certificate_digest: Some(text("certificate_digest")?.to_string()),
    })
}

fn verify_warehouse_export(ctx: &mut Ctx<'_>, args: &Args, path: &str) -> Result<(), Fail> {
    let text = ctx.files.read_text(path)?;
    let failed = |message: String| Fail::Verification {
        message,
        detail: obj(vec![("format", s("warehouse")), ("file", s(path))]),
        cite: Some(VERIFY_CITE.into()),
        fix: Some(VERIFY_FIX.into()),
    };
    let mut canonical_hex: Option<String> = None;
    let mut control_oid_hex: Option<String> = None;
    let mut effective_through_raw: Option<String> = None;
    let mut known_at_raw: Option<u64> = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        match k {
            "canonical_hex" => {
                canonical_hex = Some(v.trim_matches('"').to_string());
            }
            "control_record_oid" => {
                control_oid_hex = Some(v.trim_matches('"').to_string());
            }
            "effective_through" => {
                effective_through_raw = Some(v.trim_matches('"').to_string());
            }
            "known_at_seq" => {
                known_at_raw = Some(v.parse::<u64>().map_err(|_| {
                    failed("warehouse receipt known_at_seq is not a sequence".into())
                })?);
            }
            _ => {}
        }
    }
    let canonical_hex =
        canonical_hex.ok_or_else(|| failed("warehouse receipt has no canonical_hex".into()))?;
    let canonical_bytes = decode_hex_bytes(&canonical_hex)
        .ok_or_else(|| failed("warehouse receipt canonical_hex is not valid hex".into()))?;
    let receipt = fa_formats::fwc::WarehouseExportReceipt::decode_canonical(&canonical_bytes)
        .map_err(|e| failed(format!("warehouse receipt decode: {e}")))?;
    let control_oid = receipt
        .control_record_digest()
        .map_err(|e| Fail::Internal(format!("warehouse control digest: {e}")))?;
    if control_oid_hex.as_deref() != Some(hex(&control_oid.0).as_str()) {
        return Err(failed(
            "warehouse receipt control_record_oid does not match its canonical bytes".into(),
        ));
    }
    let effective_through = DateDay::parse(
        effective_through_raw
            .as_deref()
            .ok_or_else(|| failed("warehouse receipt has no effective_through".into()))?,
    )
    .map_err(|e| failed(format!("warehouse receipt effective_through: {e}")))?;
    let known_at =
        known_at_raw.ok_or_else(|| failed("warehouse receipt has no known_at_seq".into()))?;
    let capability = ctx.capability(args, &["read", "verify"])?;
    for op in [Op::Read, Op::Verify] {
        fa_policy::require(&capability, op, "verifying a warehouse export receipt")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let mut selected = None;
    let book = ctx.books.open_admitted(args, |book| {
        let scope = book.read_scope(capability.holder(), &capability)??;
        let selection = fa::TrialBalanceSelection::AsOf(effective_through);
        let seq =
            scope.admit_report(&selection.into(), Some(fgdb_types::CommitSeq(known_at)))??;
        let journal = book.format_journal(effective_through, Some(seq))?;
        if receipt.report_certificate_digest != journal.coordinate.certificate_digest {
            let cert_bytes = book
                .read_report_artifact(
                    capability.holder(),
                    &capability,
                    &receipt.report_certificate_digest,
                )??
                .canonical_bytes()?;
            let artifact = fa::ReportArtifact::decode(&cert_bytes)?;
            crate::notary::prepare_artifact_history(
                book,
                capability.holder(),
                &capability,
                &artifact,
                &cert_bytes,
            )?;
            if artifact.family() == fa::ReportArtifactFamily::ScenarioDiff {
                let certificate = fa::ScenarioDiffCertificate::decode(&cert_bytes)?;
                book.replay_scenario_diff(capability.holder(), &capability, &certificate)??;
            } else {
                book.replay_report_artifact_for(
                    capability.holder(),
                    &capability,
                    &cert_bytes,
                    Some(artifact.digest()),
                    fa::ReportArtifactExpectation::AsSupplied,
                )??;
            }
        }
        selected = Some(journal);
        Ok(())
    })?;
    let journal = selected
        .ok_or_else(|| Fail::Internal("verify warehouse export selection is missing".into()))?;
    let expected = render_warehouse_receipt_file(
        &receipt,
        &canonical_bytes,
        &control_oid,
        &journal.coordinate,
    );
    if expected != text {
        return Err(failed(
            "warehouse receipt file differs from the canonical receipt at its coordinate".into(),
        ));
    }
    let expected_files = vec![ExportFile {
        name: "Warehouse_Export_Receipt.toml",
        content: expected,
    }];
    let legs: usize = journal.entries.iter().map(|e| e.legs.len()).sum();
    let refold = journal
        .refold_digest()
        .map_err(|e| Fail::Internal(format!("refold digest: {e}")))?;
    let coordinate = &journal.coordinate;
    let out = &ctx.out;
    out.at_book(&book)?;
    out.known_at(fgdb_types::CommitSeq(coordinate.known_at_seq));
    out.event(
        "export_verified",
        vec![
            ("format", s("warehouse")),
            ("file", s(path)),
            (
                "effective_through",
                s(coordinate.effective_through.render()),
            ),
            ("known_at", Json::Int(i128::from(coordinate.known_at_seq))),
            ("entries", Json::Int(i128::from(coordinate.entry_count))),
            ("legs", Json::Int(legs as i128)),
            ("content_digest", s(hex(&control_oid.0))),
            (
                "certificate_digest",
                s(hex(&receipt.report_certificate_digest)),
            ),
            ("refold_digest", s(hex(&refold))),
            ("reread", s("receipt")),
            ("files", Json::Arr(files_json(&expected_files, false))),
        ],
        &format!(
            "verified the warehouse export receipt {path} for {}:{} (control record {})",
            receipt.connector.as_str(),
            receipt.destination_ref,
            hex(&control_oid.0),
        ),
    );
    Ok(())
}
