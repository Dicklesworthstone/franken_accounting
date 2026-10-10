//! `fa` — the FrankenAccounting command line (plan §15.3, Appendix D).
//!
//! Contract: stdout is data, stderr is diagnostics; `--json` turns every
//! result into one JSON object per line with an `event` discriminator; the
//! exit code is the verdict (0 ok · 2 usage · 3 accounting-law refusal ·
//! 4 environment · 5 foundation · 6 conflict · 7 safety · 8 verification;
//! 1 is never emitted); empty results exit 0; bare `fa` prints triage and
//! exits; there is no TUI.

mod args;
mod json;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fa::book::{Book, BookError, BookKeys, Entropy};
use fa_journal::BookContext;
use fa_journal::{
    AccountSpec, BookSpec, Capability, PostRequest, Posted, Refusal, UnitPolicy, exit,
};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, PeriodRef,
    account_vid, principal_vid,
};
use fa_model::{ControlPayload, Disposition, Pending};
use fa_money::{Amount, Side};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

use crate::args::{Args, UsageError, nearest};
use crate::json::{Json, obj, s};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const VERBS: &[&str] = &[
    "book",
    "chart",
    "period",
    "post",
    "reserve",
    "resolve",
    "tb",
    "open-items",
    "verify",
    "registers",
    "entry",
    "capabilities",
    "robot-docs",
    "help",
];

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&argv))
}

/// What a command can end with besides success.
enum Fail {
    Usage(UsageError),
    Refusal(Refusal),
    Book(BookError),
    Verification(String, Json),
}

impl From<UsageError> for Fail {
    fn from(e: UsageError) -> Self {
        Self::Usage(e)
    }
}
impl From<BookError> for Fail {
    fn from(e: BookError) -> Self {
        Self::Book(e)
    }
}
impl From<Refusal> for Fail {
    fn from(r: Refusal) -> Self {
        Self::Refusal(r)
    }
}

fn usage(message: impl Into<String>, fix: impl Into<String>) -> Fail {
    Fail::Usage(UsageError {
        message: message.into(),
        fix: fix.into(),
    })
}

struct Out {
    json: bool,
}

impl Out {
    fn event(&self, name: &str, mut fields: Vec<(&str, Json)>, human: &str) {
        if self.json {
            fields.push(("event", s(name)));
            println!("{}", obj(fields).render());
        } else if !human.is_empty() {
            println!("{human}");
        }
    }
}

fn run(argv: &[String]) -> u8 {
    let args = match args::parse(argv) {
        Ok(a) => a,
        Err(e) => {
            return finish(
                &Out {
                    json: argv.iter().any(|a| a == "--json"),
                },
                Err(Fail::Usage(e)),
            );
        }
    };
    let out = Out {
        json: args.switch("--json"),
    };
    finish(&out, dispatch(&out, &args))
}

fn finish(out: &Out, result: Result<(), Fail>) -> u8 {
    match result {
        Ok(()) => exit::SUCCESS,
        Err(Fail::Usage(e)) => {
            out.event(
                "usage_error",
                vec![
                    ("exit", Json::Int(i128::from(exit::USAGE))),
                    ("message", s(&e.message)),
                    ("fix", s(&e.fix)),
                ],
                "",
            );
            eprintln!("usage: {}\n  fix: {}", e.message, e.fix);
            exit::USAGE
        }
        Err(Fail::Refusal(r)) => {
            out.event(
                "refusal",
                vec![
                    ("code", s(r.code)),
                    ("exit", Json::Int(i128::from(r.exit))),
                    ("message", s(&r.message)),
                    ("cite", s(&r.cite)),
                    ("fix", s(&r.fix)),
                ],
                "",
            );
            eprintln!("refused {r}");
            r.exit
        }
        Err(Fail::Book(e)) => {
            let code = e.exit();
            out.event(
                "error",
                vec![
                    ("exit", Json::Int(i128::from(code))),
                    ("message", s(e.to_string())),
                ],
                "",
            );
            eprintln!("error (exit {code}): {e}");
            code
        }
        Err(Fail::Verification(message, detail)) => {
            out.event(
                "verification_failed",
                vec![
                    ("exit", Json::Int(i128::from(exit::VERIFICATION))),
                    ("message", s(&message)),
                    ("detail", detail),
                ],
                "",
            );
            eprintln!(
                "verification failed (exit {}): {message}",
                exit::VERIFICATION
            );
            exit::VERIFICATION
        }
    }
}

fn dispatch(out: &Out, args: &Args) -> Result<(), Fail> {
    if args.switch("--version") {
        out.event(
            "version",
            vec![("version", s(VERSION))],
            &format!("fa {VERSION}"),
        );
        return Ok(());
    }
    let verb = args.positional.first().map(String::as_str);
    if args.switch("--help") || verb == Some("help") {
        print!("{}", help_text());
        return Ok(());
    }
    if (verb != Some("tb") && (args.flag("--as-of").is_some() || args.switch("--activity")))
        || (!matches!(verb, Some("tb" | "open-items")) && args.flag("--as-known-at").is_some())
    {
        return Err(usage(
            "--as-of and --activity are supported only by `fa tb`; --as-known-at by `fa tb` and `fa open-items`",
            "fa tb --as-of 2026-03-15 --as-known-at HEAD --book <dir>",
        ));
    }
    match verb {
        None => {
            print!("{}", triage_text());
            Ok(())
        }
        Some("capabilities") => capabilities(out),
        Some("robot-docs") => robot_docs(args),
        Some("book") => book_cmd(out, args),
        Some("chart") => chart_cmd(out, args),
        Some("period") => period_cmd(out, args),
        Some("post") => post_cmd(out, args, None),
        Some("reserve") => post_cmd(out, args, Some(EntryClass::PENDING)),
        Some("resolve") => post_cmd(out, args, Some(EntryClass::RESOLUTION)),
        Some("tb") => tb_cmd(out, args),
        Some("open-items") => open_items_cmd(out, args),
        Some("verify") => verify_cmd(out, args),
        Some("registers") => registers_cmd(out, args),
        Some("entry") => entry_cmd(out, args),
        Some(other) => Err(usage(
            format!("unknown command `{other}`"),
            match nearest(other, VERBS) {
                Some(n) => format!("did you mean `fa {n}`?"),
                None => "run `fa --help`".to_string(),
            },
        )),
    }
}

// ---------------------------------------------------------------------------
// Docs
// ---------------------------------------------------------------------------

fn triage_text() -> String {
    format!(
        "fa {VERSION} — FrankenAccounting\n\
         A double-entry, evidence-native ledger on FrankenGraphDB. Agents: add --json to any command.\n\n\
         start here\n  \
         fa book create --book <dir> --name \"My Co\" [--base-unit USD]\n  \
         fa chart import <chart.json> --book <dir>\n  \
         fa period create --fiscal-year 2026 --book <dir>; fa period open FY2026-P03 --book <dir>\n  \
         fa post --intent entry.json --book <dir> --json\n  \
         fa reserve --intent hold.json --book <dir> --json; fa resolve --intent res.json --book <dir> --json\n  \
         fa tb --period FY2026-P03 --book <dir> --json\n  \
         fa verify registers --period FY2026-P03 --book <dir>\n\n\
         discover\n  \
         fa capabilities --json · fa robot-docs guide|exit-codes|examples · fa --help\n\n\
         exit codes: 0 ok · 2 usage · 3 accounting-law refusal · 4 environment · 5 foundation · 6 conflict · 7 safety · 8 verification (never 1)\n"
    )
}

fn help_text() -> String {
    format!(
        "{}\ncommands\n  \
         book create|info\n  \
         chart import <file.json> | chart list\n  \
         period create --fiscal-year N | period list | period open|soft-close|close|lock|reopen <code> [--to open|soft-closed] [--reason N] [--key K] [--date YYYY-MM-DD]\n  \
         post --intent <file.json|-> [--grant <op>]... [--as <principal>]\n  \
         reserve --intent <hold.json> (a Pending: amounts reserved, nothing posted)\n  \
         resolve --intent <res.json> (resolves <hold vid>; disposition posts (legs drawn from the hold) | voids)\n  \
         tb ((--period <code>)... | --fiscal-year N) [--activity] [--as-known-at HEAD|<seq>]\n  \
         tb --as-of YYYY-MM-DD [--as-known-at HEAD|<seq>]\n  \
         Stock balances include opening history; --activity is selected-period movement. Instants are unsupported.\n  \
         open-items [--account <code>] [--as-known-at HEAD|<seq>]   (plan §5.7: each live posted leg, its applications, its open amount)\n  \
         verify registers --period <code> | verify open-items\n  \
         registers materialize --period <code>\n  \
         entry show <vid-hex>\n  \
         capabilities | robot-docs guide|exit-codes|examples\n\n\
         global flags\n  \
         --book <dir> (or FA_BOOK) · --keys <file> (default <dir>/book.keys) · --json · --as <principal> (default operator)\n",
        triage_text()
    )
}

fn capabilities(out: &Out) -> Result<(), Fail> {
    let exits = fa_registry::ExitCodes::embedded().map_err(BookError::Registry)?;
    let codes: Vec<Json> = exits
        .rows
        .iter()
        .map(|r| {
            obj(vec![
                ("code", Json::Int(i128::from(r.code))),
                ("name", s(&r.name)),
                ("meaning", s(&r.meaning)),
            ])
        })
        .collect();
    let classes = fa_registry::EntryClasses::embedded().map_err(BookError::Registry)?;
    let class_names: Vec<Json> = classes.rows.iter().map(|c| s(&c.name)).collect();
    let fields = vec![
        ("version", s(VERSION)),
        ("verbs", Json::Arr(VERBS.iter().map(|v| s(*v)).collect())),
        ("exit_codes", Json::Arr(codes)),
        ("entry_classes", Json::Arr(class_names)),
        (
            "robot_mode",
            obj(vec![
                ("flag", s("--json")),
                (
                    "envelope",
                    s(
                        "one JSON object per line; `event` discriminates: result events, refusal, error, usage_error, verification_failed",
                    ),
                ),
            ]),
        ),
        ("stdout", s("data")),
        ("stderr", s("diagnostics")),
        ("tui", Json::Bool(false)),
    ];
    if out.json {
        out.event("capabilities", fields, "");
    } else {
        println!("{}", obj(fields).render());
    }
    Ok(())
}

fn robot_docs(args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("exit-codes") => {
            let exits = fa_registry::ExitCodes::embedded().map_err(BookError::Registry)?;
            for r in &exits.rows {
                println!("{} {:<13} {}", r.code, r.name, r.meaning);
            }
            Ok(())
        }
        Some("guide") => {
            print!("{}", GUIDE);
            Ok(())
        }
        Some("examples") => {
            print!("{}", EXAMPLES);
            Ok(())
        }
        other => Err(usage(
            format!("robot-docs needs a topic, got {other:?}"),
            "fa robot-docs guide|exit-codes|examples",
        )),
    }
}

const GUIDE: &str = "fa robot-docs guide\n\
\n\
1. Every command accepts --json. Parse stdout line by line; each line is one JSON object with an `event` field.\n\
2. Read the exit code before the output: 0 success (empty results are 0), 2 usage, 3 accounting-law refusal, 4 environment, 5 foundation/I-O, 6 conflict (retry with a fresh read), 7 safety block (period law, capability), 8 verification failure. 1 is never emitted.\n\
3. A refusal is data: {event:\"refusal\", code:\"FA-REF-nnn\", exit, message, cite, fix}. Do the `fix`; do not invent a leg, a date, or an approval.\n\
4. Amounts are strings with the unit: \"1500.00 USD\". Never floats. Dates are civil YYYY-MM-DD; recorded time is assigned by the journal, never supplied.\n\
5. Corrections are new entries (Reversal, Replacement, Reclassification) that cite the original; nothing is edited in place.\n\
6. Idempotency: every intent carries idempotency_key; resubmitting returns the recorded outcome (event \"recorded\"), never a duplicate.\n\
7. Posting into a non-Open period is decided by the admissibility matrix; the refusal cites the (class, state) cell and names the admissible class or capability.\n\
8. Two-phase: `fa reserve` posts a Pending (amounts in the pending columns, never posted); `fa resolve` names it with `resolves` and either posts a sub-vector (`legs`, each drawn from one hold leg — same account and side, at most the reserved amount; add `source_ordinal` when the hold has several such legs) or voids it (`disposition: \"voids\"`). The rest of the hold is released either way. One resolution per hold: a second is exit 6 (FA-REF-062); resolving a non-hold is FA-REF-060.\n\
9. Application: a leg may carry `settles: [{entry, ordinal, amount}]` to apply itself to an open item — the opposite side on the same account and unit, at most the item's open amount (FA-REF-072 names what is open). `fa open-items --account <code>` lists items with their applications. Reversing a receipt reopens the invoice (its applications are undone, never re-entered); an invoice with live applications cannot be reversed until its receipts are (FA-REF-073).\n";

const EXAMPLES: &str = "fa robot-docs examples\n\
\n\
# chart.json\n\
{\"accounts\":[{\"code\":\"1000\",\"name\":\"Cash\",\"type\":\"Asset\",\"leaf\":true,\"unit\":\"USD\"},\n\
              {\"code\":\"6000\",\"name\":\"Rent\",\"type\":\"Expense\",\"leaf\":true,\"unit\":\"USD\"}]}\n\
\n\
# entry.json\n\
{\"class\":\"Original\",\"effective_date\":\"2026-03-15\",\"description\":\"March rent\",\"idempotency_key\":\"inv-1001\",\n\
 \"legs\":[{\"side\":\"debit\",\"account\":\"6000\",\"amount\":\"1500.00 USD\"},\n\
          {\"side\":\"credit\",\"account\":\"1000\",\"amount\":\"1500.00 USD\"}]}\n\
\n\
fa book create --book ./books/myco --name \"My Co\" --json\n\
fa chart import chart.json --book ./books/myco --json\n\
fa period create --fiscal-year 2026 --book ./books/myco --json\n\
fa period open FY2026-P03 --book ./books/myco --json\n\
fa post --intent entry.json --book ./books/myco --json      # exit 0, event posted\n\
fa post --intent entry.json --book ./books/myco --json      # exit 0, event recorded (same idempotency_key)\n\
fa tb --period FY2026-P03 --book ./books/myco --json\n\
fa tb --as-of 2026-03-15 --as-known-at HEAD --book ./books/myco --json\n\
fa tb --period FY2026-P03 --activity --book ./books/myco --json\n\
fa registers materialize --period FY2026-P03 --book ./books/myco\n\
fa verify registers --period FY2026-P03 --book ./books/myco  # exit 8 on drift\n\
\n\
# hold.json (a Pending: 80.00 reserved, nothing posted)\n\
{\"effective_date\":\"2026-03-10\",\"description\":\"PO 77 hold\",\"idempotency_key\":\"hold-77\",\n\
 \"legs\":[{\"side\":\"debit\",\"account\":\"6000\",\"amount\":\"80.00 USD\"},{\"side\":\"credit\",\"account\":\"1000\",\"amount\":\"80.00 USD\"}]}\n\
# res.json (posts 60.00 of the hold; the other 20.00 is released)\n\
{\"resolves\":\"<vid from the reserve event>\",\"effective_date\":\"2026-03-20\",\"idempotency_key\":\"res-77\",\n\
 \"legs\":[{\"side\":\"debit\",\"account\":\"6000\",\"amount\":\"60.00 USD\"},{\"side\":\"credit\",\"account\":\"1000\",\"amount\":\"60.00 USD\"}]}\n\
# void.json (releases the whole hold)\n\
{\"resolves\":\"<vid>\",\"disposition\":\"voids\",\"effective_date\":\"2026-03-21\",\"idempotency_key\":\"void-77\"}\n\
fa reserve --intent hold.json --book ./books/myco --json      # exit 0, event posted, class Pending\n\
fa resolve --intent res.json --book ./books/myco --json       # exit 0, event posted, class Resolution\n\
fa resolve --intent void.json --book ./books/myco --json      # exit 6, FA-REF-062: the hold is already resolved\n\
\n\
# invoice.json / receipt.json (the receipt's credit leg settles the invoice's debit leg 0)\n\
{\"effective_date\":\"2026-03-05\",\"idempotency_key\":\"inv-9\",\"legs\":[{\"side\":\"debit\",\"account\":\"1200\",\"amount\":\"500.00 USD\"},{\"side\":\"credit\",\"account\":\"4000\",\"amount\":\"500.00 USD\"}]}\n\
{\"effective_date\":\"2026-03-20\",\"idempotency_key\":\"rcpt-9\",\"legs\":[{\"side\":\"debit\",\"account\":\"1000\",\"amount\":\"300.00 USD\"},\n\
  {\"side\":\"credit\",\"account\":\"1200\",\"amount\":\"300.00 USD\",\"settles\":[{\"entry\":\"<invoice vid>\",\"ordinal\":0,\"amount\":\"300.00 USD\"}]}]}\n\
fa open-items --account 1200 --book ./books/myco --json       # open 200.00 on the invoice's leg 0\n\
fa verify open-items --book ./books/myco                      # exit 8 if an applied mirror drifts from the fold\n";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn book_dir(args: &Args) -> Result<PathBuf, Fail> {
    if let Some(d) = args.flag("--book") {
        return Ok(PathBuf::from(d));
    }
    if let Ok(d) = std::env::var("FA_BOOK")
        && !d.is_empty()
    {
        return Ok(PathBuf::from(d));
    }
    Err(usage(
        "no book directory",
        "--book <dir> (or export FA_BOOK=<dir>)",
    ))
}

fn keys_path(args: &Args, dir: &Path) -> PathBuf {
    args.flag("--keys")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("book.keys"))
}

fn open_book(args: &Args) -> Result<Book, Fail> {
    let dir = book_dir(args)?;
    let keys = BookKeys::load(&keys_path(args, &dir))?;
    Ok(Book::open_dir(&dir, keys, Entropy::production())?)
}

fn principal(args: &Args) -> VId {
    principal_vid(args.flag("--as").unwrap_or("operator"))
}

fn date_flag(args: &Args, default: DateDay) -> Result<DateDay, Fail> {
    match args.flag("--date") {
        None => Ok(default),
        Some(d) => DateDay::parse(d)
            .map_err(|e| usage(format!("--date `{d}`: {e:?}"), "--date YYYY-MM-DD")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read_text(path: &str) -> Result<String, Fail> {
    if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .map_err(|e| usage(format!("stdin: {e}"), "pipe the JSON document to stdin"))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| {
            usage(
                format!("{path}: {e}"),
                "pass a readable file, or `-` for stdin",
            )
        })
    }
}

fn parse_json(path: &str, text: &str) -> Result<Json, Fail> {
    json::parse(text).map_err(|e| usage(format!("{path}: {e}"), "fa robot-docs examples"))
}

fn req_str<'a>(doc: &'a Json, key: &str, what: &str) -> Result<&'a str, Fail> {
    doc.get(key).and_then(Json::as_str).ok_or_else(|| {
        usage(
            format!("{what}: `{key}` must be a string"),
            "fa robot-docs examples",
        )
    })
}

// ---------------------------------------------------------------------------
// book
// ---------------------------------------------------------------------------

fn book_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("create") => {
            let dir = book_dir(args)?;
            let name = args.require("--name", "\"My Co\"")?;
            let units = fa_registry::units_embedded().map_err(BookError::Registry)?;
            let base = args.flag("--base-unit").unwrap_or("USD");
            let base_unit = units.lookup(base).ok_or_else(|| {
                usage(
                    format!("unknown base unit `{base}`"),
                    "--base-unit USD|EUR|GBP|JPY|CHF|CAD|AUD|KWD",
                )
            })?;
            let kind = args.flag("--calendar").unwrap_or("monthly");
            if kind != "monthly" {
                return Err(usage(
                    format!("calendar `{kind}` is not available from the CLI yet"),
                    "--calendar monthly (4-4-5 and 52/53-week calendars land with the next slice)",
                ));
            }
            let ysm: u8 = args
                .flag("--year-start-month")
                .unwrap_or("1")
                .parse()
                .map_err(|_| usage("--year-start-month must be 1..=12", "--year-start-month 1"))?;
            let adj: u8 = args
                .flag("--adjustment-periods")
                .unwrap_or("1")
                .parse()
                .map_err(|_| {
                    usage(
                        "--adjustment-periods must be 0..=4",
                        "--adjustment-periods 1",
                    )
                })?;
            let calendar = FiscalCalendar::monthly("fiscal", ysm, adj).map_err(|e| {
                usage(
                    format!("calendar: {e:?}"),
                    "--year-start-month 1..=12 --adjustment-periods 0..=4",
                )
            })?;
            let entropy = Entropy::production();
            let keys = BookKeys::generate(&entropy)?;
            let mut id = [0u8; 16];
            entropy.fill(&mut id).map_err(BookError::Entropy)?;
            let book_id = Id128(id);
            let keys_file = keys_path(args, &dir);
            std::fs::create_dir_all(&dir).map_err(|e| BookError::Io(dir.clone(), e))?;
            keys.save(&keys_file)?;
            let book = Book::create_dir(
                &dir,
                keys,
                BookSpec {
                    book_id,
                    name: name.to_string(),
                    base_unit,
                    calendar,
                },
                entropy,
            )?;
            out.event(
                "book_created",
                vec![
                    ("book_id", s(book_id.to_hex())),
                    ("dir", s(dir.display().to_string())),
                    ("keys", s(keys_file.display().to_string())),
                    ("name", s(name)),
                    ("base_unit", s(base)),
                    ("calendar", s(&book.context().calendar.id)),
                ],
                &format!(
                    "created book {} in {} (keys: {}; keep them, they are never regenerated)",
                    book_id.to_hex(),
                    dir.display(),
                    keys_file.display()
                ),
            );
            Ok(())
        }
        Some("info") => {
            let book = open_book(args)?;
            let ctx = book.context();
            let periods = book.periods()?;
            let mut by_state: Vec<(String, i128)> = Vec::new();
            for p in &periods {
                match by_state.iter_mut().find(|(n, _)| *n == p.state.name()) {
                    Some((_, n)) => *n += 1,
                    None => by_state.push((p.state.name().to_string(), 1)),
                }
            }
            let unit = ctx
                .units
                .get(ctx.units.lookup("USD").unwrap_or(fa_money::UnitId(0)))
                .map(|u| u.code.clone())
                .unwrap_or_default();
            out.event(
                "book",
                vec![
                    ("book_id", s(ctx.book_id.to_hex())),
                    ("calendar", s(&ctx.calendar.id)),
                    ("periods", Json::Int(periods.len() as i128)),
                    (
                        "periods_by_state",
                        Json::Obj(
                            by_state
                                .into_iter()
                                .map(|(k, v)| (k, Json::Int(v)))
                                .collect(),
                        ),
                    ),
                    ("accounts", Json::Int(book.accounts()?.len() as i128)),
                    (
                        "units_registered",
                        Json::Int(ctx.units.iter().count() as i128),
                    ),
                ],
                &format!(
                    "book {} · calendar {} · {} periods · {} accounts · base unit {}",
                    ctx.book_id.to_hex(),
                    ctx.calendar.id,
                    periods.len(),
                    book.accounts()?.len(),
                    unit
                ),
            );
            Ok(())
        }
        other => Err(usage(
            format!("book needs create|info, got {other:?}"),
            "fa book create --book <dir> --name \"My Co\"",
        )),
    }
}

// ---------------------------------------------------------------------------
// chart
// ---------------------------------------------------------------------------

fn chart_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("import") => {
            let path = args.positional.get(2).ok_or_else(|| {
                usage(
                    "chart import needs a file",
                    "fa chart import chart.json --book <dir>",
                )
            })?;
            let text = read_text(path)?;
            let doc = parse_json(path, &text)?;
            let mut book = open_book(args)?;
            let units = &book.context().units;
            let rows = doc.get("accounts").and_then(Json::as_arr).ok_or_else(|| {
                usage(
                    "chart: `accounts` must be an array",
                    "fa robot-docs examples",
                )
            })?;
            let mut accounts = Vec::with_capacity(rows.len());
            for (i, row) in rows.iter().enumerate() {
                let what = format!("accounts[{i}]");
                let code = req_str(row, "code", &what)?;
                let name = row.get("name").and_then(Json::as_str).unwrap_or(code);
                let type_name = req_str(row, "type", &what)?;
                let account_type = AccountType::ALL
                    .iter()
                    .find(|(_, n, ..)| n.eq_ignore_ascii_case(type_name))
                    .map(|(t, ..)| *t)
                    .ok_or_else(|| {
                        usage(
                            format!("{what}: unknown type `{type_name}`"),
                            "type: Asset|Liability|Equity|Revenue|Expense|Memo|Statistical",
                        )
                    })?;
                let normal_balance = AccountType(account_type).normal_balance().unwrap_or(0);
                let is_leaf = row.get("leaf").and_then(Json::as_bool).unwrap_or(true);
                let unit_policy = match row.get("unit").and_then(Json::as_str) {
                    None | Some("any") => UnitPolicy::AnyUnit,
                    Some("any-currency") => UnitPolicy::AnyCurrency,
                    Some(u) => UnitPolicy::Single(units.lookup(u).ok_or_else(|| {
                        usage(
                            format!("{what}: unknown unit `{u}`"),
                            "unit: USD|EUR|…|any|any-currency",
                        )
                    })?),
                };
                let parent_code = row.get("parent").and_then(Json::as_str).map(str::to_string);
                accounts.push(AccountSpec {
                    code: code.to_string(),
                    name: name.to_string(),
                    account_type,
                    normal_balance,
                    is_leaf,
                    unit_policy,
                    parent_code,
                });
            }
            let date = date_flag(args, DateDay(0))?;
            let key = match args.flag("--key") {
                Some(k) => k.as_bytes().to_vec(),
                None => format!(
                    "chart:{}",
                    hex(&fa_model::domain_digest(b"fa:chart:v1", &[text.as_bytes()])[..8])
                )
                .into_bytes(),
            };
            let installed = book.install_chart(&accounts, principal(args), date, &key)??;
            out.event(
                "chart_installed",
                vec![
                    ("accounts", Json::Int(installed.accounts as i128)),
                    (
                        "control_entry",
                        s(format!("{:032x}", installed.control_entry.0)),
                    ),
                    (
                        "recorded_at",
                        Json::Int(i128::from(installed.recorded_at.0)),
                    ),
                ],
                &format!(
                    "installed {} accounts (control entry {:032x}, recorded at {})",
                    installed.accounts, installed.control_entry.0, installed.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("list") => {
            let book = open_book(args)?;
            let rows = book.accounts()?;
            let units = &book.context().units;
            let items: Vec<Json> = rows
                .iter()
                .map(|a| {
                    obj(vec![
                        ("code", s(&a.code)),
                        ("name", s(&a.name)),
                        ("type", s(AccountType(a.account_type).name().unwrap_or("?"))),
                        ("leaf", Json::Bool(a.is_leaf)),
                        (
                            "unit",
                            s(match a.unit_policy {
                                UnitPolicy::Single(u) => {
                                    units.get(u).map(|u| u.code.clone()).unwrap_or_default()
                                }
                                UnitPolicy::AnyCurrency => "any-currency".into(),
                                UnitPolicy::AnyUnit => "any".into(),
                            }),
                        ),
                    ])
                })
                .collect();
            if out.json {
                out.event("accounts", vec![("accounts", Json::Arr(items))], "");
            } else {
                for a in &rows {
                    println!(
                        "{:<12} {:<32} {:<12} {}",
                        a.code,
                        a.name,
                        AccountType(a.account_type).name().unwrap_or("?"),
                        if a.is_leaf { "leaf" } else { "summary" }
                    );
                }
            }
            Ok(())
        }
        other => Err(usage(
            format!("chart needs import|list, got {other:?}"),
            "fa chart import chart.json --book <dir>",
        )),
    }
}

// ---------------------------------------------------------------------------
// period
// ---------------------------------------------------------------------------

fn period_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    let sub = args.positional.get(1).map(String::as_str);
    match sub {
        Some("create") => {
            let fy: i32 = args
                .require("--fiscal-year", "2026")?
                .parse()
                .map_err(|_| usage("--fiscal-year must be a year", "--fiscal-year 2026"))?;
            let mut book = open_book(args)?;
            let (seq, periods) = book.create_periods(fy)?;
            let codes: Vec<Json> = periods.iter().map(|p| s(&p.code)).collect();
            out.event("periods_created", vec![("fiscal_year", Json::Int(i128::from(fy))), ("periods", Json::Arr(codes)), ("recorded_at", Json::Int(i128::from(seq.0)))], &format!("created {} periods for FY{fy} (all Future; open them with `fa period open <code>`)", periods.len()));
            Ok(())
        }
        Some("list") => {
            let book = open_book(args)?;
            let rows = book.periods()?;
            let items: Vec<Json> = rows
                .iter()
                .map(|p| {
                    obj(vec![
                        ("code", s(&p.code)),
                        ("state", s(p.state.name())),
                        ("kind", s(kind_name(p.kind))),
                        ("start", s(p.start.render())),
                        ("end", s(p.end.render())),
                        ("fiscal_year", Json::Int(i128::from(p.fiscal_year))),
                    ])
                })
                .collect();
            if out.json {
                out.event("periods", vec![("periods", Json::Arr(items))], "");
            } else {
                for p in &rows {
                    println!(
                        "{:<14} {:<10} {:<11} {} .. {}",
                        p.code,
                        p.state.name(),
                        kind_name(p.kind),
                        p.start.render(),
                        p.end.render()
                    );
                }
            }
            Ok(())
        }
        Some(t @ ("open" | "soft-close" | "close" | "lock" | "reopen")) => {
            let code = args.positional.get(2).ok_or_else(|| {
                usage(
                    format!("period {t} needs a period code"),
                    format!("fa period {t} FY2026-P03 --book <dir>"),
                )
            })?;
            let transition = match t {
                "open" => PeriodTransition::Open,
                "soft-close" => PeriodTransition::SoftClose,
                "close" => PeriodTransition::Close,
                "lock" => PeriodTransition::Lock,
                _ => PeriodTransition::Reopen {
                    to: match args.flag("--to").unwrap_or("open") {
                        "open" => PeriodState::Open,
                        "soft-closed" => PeriodState::SoftClosed,
                        other => {
                            return Err(usage(format!("--to `{other}`"), "--to open|soft-closed"));
                        }
                    },
                },
            };
            let reason: u16 = args.flag("--reason").unwrap_or("0").parse().map_err(|_| {
                usage(
                    "--reason must be a registered reason code (u16)",
                    "--reason 0",
                )
            })?;
            let mut book = open_book(args)?;
            let current = book
                .periods()?
                .into_iter()
                .find(|p| &p.code == code)
                .map(|p| p.state.name())
                .unwrap_or("Unknown");
            let key = args
                .flag("--key")
                .map(|k| k.as_bytes().to_vec())
                .unwrap_or_else(|| format!("period:{code}:{current}:{t}").into_bytes());
            let date = date_flag(
                args,
                book.periods()?
                    .into_iter()
                    .find(|p| &p.code == code)
                    .map(|p| p.start)
                    .unwrap_or(DateDay(0)),
            )?;
            let tr =
                book.transition_period(code, transition, principal(args), reason, date, &key)??;
            out.event(
                "period_transitioned",
                vec![
                    ("period", s(&tr.period)),
                    ("from", s(tr.from.name())),
                    ("to", s(tr.to.name())),
                    ("control_entry", s(format!("{:032x}", tr.control_entry.0))),
                    ("recorded_at", Json::Int(i128::from(tr.recorded_at.0))),
                ],
                &format!(
                    "{}: {} → {} (recorded at {})",
                    tr.period,
                    tr.from.name(),
                    tr.to.name(),
                    tr.recorded_at.0
                ),
            );
            Ok(())
        }
        other => Err(usage(
            format!("period needs create|list|open|soft-close|close|lock|reopen, got {other:?}"),
            "fa period open FY2026-P03 --book <dir>",
        )),
    }
}

fn kind_name(k: PeriodKind) -> &'static str {
    match k {
        PeriodKind::Normal => "Normal",
        PeriodKind::Adjustment => "Adjustment",
        PeriodKind::Opening => "Opening",
        PeriodKind::Closing => "Closing",
        PeriodKind::Historical => "Historical",
    }
}

// ---------------------------------------------------------------------------
// post
// ---------------------------------------------------------------------------

/// A 32-hex entry identity from an intent field.
fn parse_vid(text: &str, what: &str) -> Result<VId, Fail> {
    u128::from_str_radix(text, 16).map(VId).map_err(|_| {
        usage(
            format!("{what} `{text}` is not a 32-hex vid"),
            format!("{what}: the `vid` from the posted event"),
        )
    })
}

/// The `legs` array of an intent: each leg with its optional `source_ordinal`
/// (meaningful only for a Resolution(Posts)).
/// A leg's `settles` array: `{entry, ordinal, amount}` per application; the
/// entry's current digest is read from the book so the handle self-verifies.
fn parse_settles(
    leg_doc: &Json,
    what: &str,
    ctx: &BookContext,
    book: &Book,
) -> Result<Vec<fa_model::Settlement>, Fail> {
    let Some(list) = leg_doc.get("settles") else {
        return Ok(Vec::new());
    };
    let Some(list) = list.as_arr() else {
        return Err(usage(
            format!("{what}: `settles` must be an array"),
            "settles: [{\"entry\": \"<vid>\", \"ordinal\": 0, \"amount\": \"300.00 USD\"}]",
        ));
    };
    let mut out = Vec::with_capacity(list.len());
    for (j, item) in list.iter().enumerate() {
        let what = format!("{what}.settles[{j}]");
        let vid = parse_vid(req_str(item, "entry", &what)?, &format!("{what}.entry"))?;
        let Some((target, _)) = book.read_entry(vid)? else {
            return Err(usage(
                format!("{what}: no entry {:032x} in this book", vid.0),
                "fa open-items --account <code> lists the open items to apply to",
            ));
        };
        let ordinal = match item.get("ordinal") {
            Some(Json::Int(n)) => u16::try_from(*n).map_err(|_| {
                usage(
                    format!("{what}: ordinal {n} is out of range"),
                    "ordinal: the 0-based index of the open item's leg",
                )
            })?,
            Some(other) => match other.as_str().and_then(|t| t.parse::<u16>().ok()) {
                Some(n) => n,
                None => {
                    return Err(usage(
                        format!("{what}: ordinal must be a small non-negative integer"),
                        "ordinal: the 0-based index of the open item's leg",
                    ));
                }
            },
            None => 0,
        };
        let amount_s = req_str(item, "amount", &what)?;
        let amount = Amount::parse(amount_s, &ctx.units).map_err(|e| {
            usage(
                format!("{what}: amount `{amount_s}`: {e:?}"),
                "amount: \"300.00 USD\" (exact, in the leg's unit)",
            )
        })?;
        out.push(fa_model::Settlement {
            target: target.entry_ref(vid),
            ordinal,
            amount,
        });
    }
    Ok(out)
}

fn parse_legs(
    doc: &Json,
    ctx: &BookContext,
    book: &Book,
) -> Result<Vec<(LegPayload, Option<u16>)>, Fail> {
    let legs_doc = doc.get("legs").and_then(Json::as_arr).ok_or_else(|| {
        usage(
            "intent: `legs` must be an array (or `reverses` a vid)",
            "fa robot-docs examples",
        )
    })?;
    let mut legs = Vec::with_capacity(legs_doc.len());
    for (i, l) in legs_doc.iter().enumerate() {
        let what = format!("legs[{i}]");
        let side = match req_str(l, "side", &what)? {
            "debit" | "dr" | "Debit" => Side::Debit,
            "credit" | "cr" | "Credit" => Side::Credit,
            other => {
                return Err(usage(
                    format!("{what}: side `{other}`"),
                    "side: debit|credit",
                ));
            }
        };
        let account = req_str(l, "account", &what)?;
        let amount_s = req_str(l, "amount", &what)?;
        let amount = Amount::parse(amount_s, &ctx.units).map_err(|e| {
            usage(
                format!("{what}: amount `{amount_s}`: {e:?}"),
                "amount: \"1500.00 USD\" (exact, at the unit's scale, non-negative)",
            )
        })?;
        let ordinal = match l.get("source_ordinal") {
            None => None,
            Some(Json::Int(n)) => Some(u16::try_from(*n).map_err(|_| {
                usage(
                    format!("{what}: source_ordinal {n} is out of range"),
                    "source_ordinal: the 0-based index of the hold leg this leg draws from",
                )
            })?),
            Some(other) => match other.as_str().and_then(|t| t.parse::<u16>().ok()) {
                Some(n) => Some(n),
                None => {
                    return Err(usage(
                        format!("{what}: source_ordinal must be a small non-negative integer"),
                        "source_ordinal: the 0-based index of the hold leg this leg draws from",
                    ));
                }
            },
        };
        let mut leg = LegPayload::simple(side, account_vid(ctx.book_id, account), amount);
        leg.settles = parse_settles(l, &what, ctx, book)?;
        legs.push((leg, ordinal));
    }
    Ok(legs)
}

fn post_cmd(out: &Out, args: &Args, forced: Option<EntryClass>) -> Result<(), Fail> {
    let path = args.require("--intent", "entry.json (or - for stdin)")?;
    let text = read_text(path)?;
    let doc = parse_json(path, &text)?;
    let mut book = open_book(args)?;
    let ctx = book.context().clone();
    let class_name = doc
        .get("class")
        .and_then(Json::as_str)
        .unwrap_or(match forced {
            Some(EntryClass::PENDING) => "Pending",
            Some(EntryClass::RESOLUTION) => "Resolution",
            _ => "Original",
        });
    let class = EntryClass::from_name(class_name).ok_or_else(|| {
        usage(
            format!("unknown class `{class_name}`"),
            "class: Original|Adjusting|Reversal|Pending|Resolution|…",
        )
    })?;
    for key in ["timeout_ns", "timeout", "expires", "expiry", "expires_at"] {
        if doc.get(key).is_some() {
            return Err(usage(
                format!(
                    "`{key}`: timed holds are not available yet, and a timed reservation is never silently made permanent"
                ),
                "remove the field to reserve without a timeout, or wait for the TimeEvidence tick and expiry-sweep slice (plan §5.4)",
            ));
        }
    }
    if forced.is_some_and(|f| f != class) {
        return Err(usage(
            format!(
                "`fa {}` posts a {} but the intent says class `{class_name}`",
                if forced == Some(EntryClass::PENDING) {
                    "reserve"
                } else {
                    "resolve"
                },
                forced.and_then(EntryClass::name).unwrap_or("?")
            ),
            "remove `class` from the intent, or use `fa post`",
        ));
    }
    let date_s = req_str(&doc, "effective_date", "intent")?;
    let effective_date = DateDay::parse(date_s).map_err(|e| {
        usage(
            format!("effective_date `{date_s}`: {e:?}"),
            "effective_date: \"YYYY-MM-DD\"",
        )
    })?;
    let key = req_str(&doc, "idempotency_key", "intent")?;
    let description = doc.get("description").and_then(Json::as_str).unwrap_or("");
    // A Reversal names its target; its legs are the exact side-swap of the
    // target's, derived here so an agent never has to retype amounts. A
    // Resolution names the hold it resolves and either posts a sub-vector
    // drawn leg by leg from it or voids it (plan §5.4).
    let mut supersession = Vec::new();
    let mut pending = None;
    let mut control = None;
    let legs: Vec<LegPayload> = if let Some(target_s) = doc.get("reverses").and_then(Json::as_str) {
        let vid = parse_vid(target_s, "reverses")?;
        let Some((target, _)) = book.read_entry(vid)? else {
            return Err(usage(
                format!("reverses: no entry {target_s} in this book"),
                "fa entry show <vid> to check the identity",
            ));
        };
        supersession.push(fa_model::Supersession {
            target: target.entry_ref(vid),
            kind: fa_model::SupersessionKind::Reverses,
            reason_code: 0,
        });
        if doc.get("legs").is_some() {
            return Err(usage(
                "a Reversal's legs are derived from the target; do not supply `legs`",
                "remove `legs`; a different correction is a Replacement",
            ));
        }
        target
            .proposal
            .legs
            .iter()
            .map(|l| {
                // Every field survives except the applications: the undo of
                // a reversed entry's applications is derived by the kernel,
                // never re-entered (plan §5.7).
                let mut swapped = l.clone();
                swapped.side = if l.side == Side::Debit {
                    Side::Credit
                } else {
                    Side::Debit
                };
                swapped.settles = Vec::new();
                swapped
            })
            .collect()
    } else if class == EntryClass::RESOLUTION {
        let target_s = doc.get("resolves").and_then(Json::as_str).ok_or_else(|| {
            usage(
                "a Resolution names the hold it resolves: `resolves` (vid)",
                "resolves: the `vid` from the reserve event; disposition: \"posts\" with legs, or \"voids\"",
            )
        })?;
        let vid = parse_vid(target_s, "resolves")?;
        let Some((hold, _)) = book.read_entry(vid)? else {
            return Err(usage(
                format!("resolves: no entry {target_s} in this book"),
                "fa entry show <vid> to check the identity",
            ));
        };
        let resolution_of = Some(hold.entry_ref(vid));
        let disposition =
            doc.get("disposition")
                .and_then(Json::as_str)
                .unwrap_or(if doc.get("legs").is_some() {
                    "posts"
                } else {
                    "voids"
                });
        match disposition {
            "voids" | "void" | "release" => {
                if doc.get("legs").is_some() {
                    return Err(usage(
                        "a Voids resolution carries no legs",
                        "remove `legs`, or set disposition to \"posts\"",
                    ));
                }
                control = Some(ControlPayload::ReservationRelease);
                pending = Some(Pending {
                    timeout_ns: None,
                    resolution_of,
                    disposition: Some(Disposition::Voids),
                });
                Vec::new()
            }
            "posts" | "post" => {
                let mut pairs: Vec<(u16, LegPayload)> = Vec::new();
                for (i, (leg, explicit)) in parse_legs(&doc, &ctx, &book)?.into_iter().enumerate() {
                    let ordinal = match explicit {
                        Some(o) => o,
                        None => {
                            let candidates: Vec<usize> = hold
                                .proposal
                                .legs
                                .iter()
                                .enumerate()
                                .filter(|(_, t)| {
                                    t.account_ref == leg.account_ref && t.side == leg.side
                                })
                                .map(|(o, _)| o)
                                .collect();
                            match candidates.as_slice() {
                                [one] => u16::try_from(*one).map_err(|_| {
                                    usage("the hold has more than u16 legs", "fa entry show <vid>")
                                })?,
                                [] => {
                                    return Err(usage(
                                        format!(
                                            "legs[{i}]: the hold has no {} leg on that account",
                                            if leg.side == Side::Debit {
                                                "debit"
                                            } else {
                                                "credit"
                                            }
                                        ),
                                        "post only accounts and sides the hold reserved (fa entry show <hold vid>); anything else is a Voids plus a new Original",
                                    ));
                                }
                                many => {
                                    return Err(usage(
                                        format!(
                                            "legs[{i}]: the hold has several matching legs (ordinals {many:?})"
                                        ),
                                        "add \"source_ordinal\" to the leg",
                                    ));
                                }
                            }
                        }
                    };
                    if pairs.iter().any(|(o, _)| *o == ordinal) {
                        return Err(usage(
                            format!("legs[{i}]: source_ordinal {ordinal} is used twice"),
                            "one posted leg per hold leg",
                        ));
                    }
                    pairs.push((ordinal, leg));
                }
                pairs.sort_by_key(|(o, _)| *o);
                pending = Some(Pending {
                    timeout_ns: None,
                    resolution_of,
                    disposition: Some(Disposition::Posts {
                        source_ordinals: pairs.iter().map(|(o, _)| *o).collect(),
                    }),
                });
                pairs.into_iter().map(|(_, l)| l).collect()
            }
            other => {
                return Err(usage(
                    format!("disposition `{other}`"),
                    "disposition: posts|voids",
                ));
            }
        }
    } else {
        if class == EntryClass::PENDING {
            pending = Some(Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            });
        }
        let parsed = parse_legs(&doc, &ctx, &book)?;
        if let Some(i) = parsed.iter().position(|(_, o)| o.is_some()) {
            return Err(usage(
                format!("legs[{i}]: `source_ordinal` belongs to a Resolution(Posts) only"),
                "remove it, or set resolves/disposition to post a sub-vector of a hold",
            ));
        }
        parsed.into_iter().map(|(l, _)| l).collect()
    };
    let unit_totals = EntryPayload::fold_unit_totals(&legs)
        .map_err(fa_journal::KernelError::Model)
        .map_err(BookError::Kernel)?;
    let effective_period = doc
        .get("effective_period")
        .and_then(Json::as_str)
        .map(|c| PeriodRef {
            calendar: ctx.calendar.id.clone(),
            code: c.to_string(),
        });
    let who = principal(args);
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: ctx.book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date,
        document_date: None,
        description: book.seal_text(description)?,
        effective_period,
        legs,
        control,
        unit_totals,
        base_totals: None,
        idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid(fa_model::domain_digest(
                b"fa:intent:v1",
                &[&ctx.book_id.0, &who.0.to_le_bytes(), key.as_bytes()],
            )),
            intent_kind: 1,
        },
        principal_ref: who,
        session_ref: None,
        evidence: Vec::new(),
        supersession,
        pending,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let mut ops = vec!["post"];
    ops.extend(args.flag_all("--grant"));
    let req = PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::with_ops(&ops),
    };
    match book.post(req)?? {
        Posted::Committed {
            entry_ref,
            recorded_at,
            period,
        } => {
            out.event(
                "posted",
                vec![
                    ("class", s(class_name)),
                    ("vid", s(format!("{:032x}", entry_ref.vid.0))),
                    ("entry_digest", s(hex(&entry_ref.entry_digest))),
                    ("recorded_at", Json::Int(i128::from(recorded_at.0))),
                    ("period", s(&period)),
                ],
                &format!(
                    "posted {:032x} in {period}, recorded at {} (entry_digest {})",
                    entry_ref.vid.0,
                    recorded_at.0,
                    hex(&entry_ref.entry_digest)
                ),
            );
        }
        Posted::AlreadyRecorded {
            entry_ref,
            recorded_at,
        } => {
            out.event(
                "recorded",
                vec![("vid", s(format!("{:032x}", entry_ref.vid.0))), ("entry_digest", s(hex(&entry_ref.entry_digest))), ("recorded_at", Json::Int(i128::from(recorded_at.0)))],
                &format!("already recorded as {:032x} at {} (same idempotency_key); nothing new was written", entry_ref.vid.0, recorded_at.0),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// tb / verify / registers / entry
// ---------------------------------------------------------------------------

fn selected_periods(args: &Args, book: &Book) -> Result<Vec<String>, Fail> {
    if args.flag_all("--fiscal-year").len() > 1
        || (args.flag("--fiscal-year").is_some() && args.flag("--period").is_some())
    {
        return Err(usage(
            "select repeated --period values or one --fiscal-year, not both",
            "--period FY2026-P03 (repeatable) or --fiscal-year 2026",
        ));
    }
    let mut periods: Vec<String> = args
        .flag_all("--period")
        .iter()
        .map(|p| (*p).to_string())
        .collect();
    if let Some(fy) = args.flag("--fiscal-year") {
        let fy: i32 = fy
            .parse()
            .map_err(|_| usage("--fiscal-year must be a year", "--fiscal-year 2026"))?;
        periods.extend(
            book.periods()?
                .into_iter()
                .filter(|p| p.fiscal_year == fy)
                .map(|p| p.code),
        );
    }
    if periods.is_empty() {
        return Err(usage(
            "no periods selected",
            "--period FY2026-P03 (repeatable) or --fiscal-year 2026",
        ));
    }
    periods.sort();
    periods.dedup();
    Ok(periods)
}

fn tb_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    let book = open_book(args)?;
    if args.positional.len() != 1 {
        return Err(usage("unexpected trial-balance argument", "fa tb --help"));
    }
    if args.flag("--date").is_some() {
        return Err(usage(
            "--date is a period-transition flag, not a balance selector",
            "fa tb --as-of YYYY-MM-DD for a stock position on a day, or --period <code>",
        ));
    }
    for flag in ["--as-of", "--as-known-at"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("{flag} may be supplied only once"),
                "fa tb --help",
            ));
        }
    }
    let known_at = match args.flag("--as-known-at") {
        None | Some("HEAD") => None,
        Some(value) => {
            let sequence = if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                value.parse::<u64>().ok()
            } else {
                None
            };
            Some(CommitSeq(sequence.ok_or_else(|| usage(
                "--as-known-at requires HEAD or an unsigned CommitSeq; instant selectors are unsupported",
                "--as-known-at HEAD or --as-known-at <u64 commit sequence>",
            ))?))
        }
    };
    let (periods, tb) = if let Some(date) = args.flag("--as-of") {
        if args.flag("--period").is_some()
            || args.flag("--fiscal-year").is_some()
            || args.switch("--activity")
        {
            return Err(usage(
                "--as-of cannot be combined with --period, --fiscal-year or --activity",
                "fa tb --as-of 2026-03-15 --book <dir>",
            ));
        }
        let day = DateDay::parse(date).map_err(|e| {
            usage(
                format!("{e}; --as-of requires a civil date; instant selectors are unsupported"),
                "--as-of YYYY-MM-DD",
            )
        })?;
        (Vec::new(), book.balance_as_of(day, known_at)?)
    } else {
        let periods = selected_periods(args, &book)?;
        let tb = if args.switch("--activity") {
            book.period_activity(&periods, known_at)?
        } else {
            book.trial_balance_at(&periods, known_at)?
        };
        (periods, tb)
    };
    let units = &book.context().units;
    let render = |unit: u32, m: i128| Amount::new(fa_money::UnitId(unit), m).render(units);
    let rows: Vec<Json> = tb
        .rows
        .iter()
        .map(|r| {
            obj(vec![
                ("code", s(&r.code)),
                ("name", s(&r.name)),
                ("type", s(r.account_type.name().unwrap_or("?"))),
                ("debits", s(render(r.unit_id, r.debits))),
                ("credits", s(render(r.unit_id, r.credits))),
                ("net", s(render(r.unit_id, r.debits - r.credits))),
                ("debits_pending", s(render(r.unit_id, r.debits_pending))),
                ("credits_pending", s(render(r.unit_id, r.credits_pending))),
            ])
        })
        .collect();
    let pending_totals: Vec<Json> = tb
        .pending_unit_totals
        .iter()
        .map(|(u, (d, c))| {
            obj(vec![
                (
                    "unit",
                    s(units
                        .get(fa_money::UnitId(*u))
                        .map(|x| x.code.clone())
                        .unwrap_or_default()),
                ),
                ("debits_pending", s(render(*u, *d))),
                ("credits_pending", s(render(*u, *c))),
            ])
        })
        .collect();
    let totals: Vec<Json> = tb
        .unit_totals
        .iter()
        .map(|(u, (d, c))| {
            obj(vec![
                (
                    "unit",
                    s(units
                        .get(fa_money::UnitId(*u))
                        .map(|x| x.code.clone())
                        .unwrap_or_default()),
                ),
                ("debits", s(render(*u, *d))),
                ("credits", s(render(*u, *c))),
            ])
        })
        .collect();
    if out.json {
        out.event(
            "trial_balance",
            vec![
                ("periods", Json::Arr(periods.iter().map(s).collect())),
                ("known_at", Json::Int(i128::from(tb.known_at.0))),
                (
                    "effective_through",
                    tb.effective_through.map_or(Json::Null, |d| s(d.render())),
                ),
                ("activity", Json::Bool(tb.activity)),
                ("mode", s(if tb.activity { "activity" } else { "stock" })),
                ("rows", Json::Arr(rows)),
                ("unit_totals", Json::Arr(totals)),
                ("pending_unit_totals", Json::Arr(pending_totals)),
                ("balanced", Json::Bool(tb.is_balanced())),
            ],
            "",
        );
    } else {
        if let Some(day) = tb.effective_through {
            println!("trial balance through {day} · known at {}", tb.known_at.0);
        } else {
            println!(
                "period activity · {} · known at {}",
                periods.join(", "),
                tb.known_at.0
            );
        }
        println!(
            "{:<10} {:<28} {:>22} {:>22} {:>22} {:>22}",
            "code",
            "account",
            "posted debits",
            "posted credits",
            "pending debits",
            "pending credits"
        );
        for r in &tb.rows {
            println!(
                "{:<10} {:<28} {:>22} {:>22} {:>22} {:>22}",
                r.code,
                r.name,
                render(r.unit_id, r.debits),
                render(r.unit_id, r.credits),
                render(r.unit_id, r.debits_pending),
                render(r.unit_id, r.credits_pending)
            );
        }
        let total_units: std::collections::BTreeSet<_> = tb
            .unit_totals
            .keys()
            .chain(tb.pending_unit_totals.keys())
            .copied()
            .collect();
        for u in total_units {
            let (d, c) = tb.unit_totals.get(&u).copied().unwrap_or_default();
            let (pd, pc) = tb.pending_unit_totals.get(&u).copied().unwrap_or_default();
            println!(
                "{:<39} {:>22} {:>22} {:>22} {:>22}",
                "total",
                render(u, d),
                render(u, c),
                render(u, pd),
                render(u, pc)
            );
        }
        println!("balanced: {}", tb.is_balanced());
    }
    Ok(())
}

fn drift_json(drifts: &[fa_registers::Drift]) -> Vec<Json> {
    drifts
        .iter()
        .map(|d| {
            obj(vec![
                ("account", s(format!("{:032x}", d.key.account.0))),
                ("unit_id", Json::Int(i128::from(d.key.unit_id))),
                (
                    "stored",
                    d.stored.map_or(Json::Null, |(dd, cc, n)| {
                        obj(vec![
                            ("debits", Json::Int(dd)),
                            ("credits", Json::Int(cc)),
                            ("entry_count", Json::Int(i128::from(n))),
                        ])
                    }),
                ),
                (
                    "refolded",
                    obj(vec![
                        ("debits", Json::Int(d.refolded.0)),
                        ("credits", Json::Int(d.refolded.1)),
                        ("entry_count", Json::Int(i128::from(d.refolded.2))),
                    ]),
                ),
            ])
        })
        .collect()
}

fn verify_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("registers") => {
            let book = open_book(args)?;
            let periods = selected_periods(args, &book)?;
            let mut all_green = true;
            let mut details = Vec::new();
            let mut diagnostics = Vec::new();
            for p in &periods {
                let v = book.verify_registers(p)?;
                diagnostics.extend(v.projection_errors.iter().map(|e| format!("{p}: {e}")));
                if !v.drift.is_empty() {
                    diagnostics.push(format!("{p}: {} posted cells differ", v.drift.len()));
                }
                if !v.pending_drift.is_empty() {
                    diagnostics.push(format!(
                        "{p}: {} pending cells differ",
                        v.pending_drift.len()
                    ));
                }
                all_green &= v.is_green();
                details.push(obj(vec![
                    ("period", s(p)),
                    ("green", Json::Bool(v.is_green())),
                    ("cells_checked", Json::Int(v.cells_checked as i128)),
                    ("refold_digest", s(hex(&v.refold_digest))),
                    (
                        "stored_digest",
                        v.stored_digest.map_or(Json::Null, |d| s(hex(&d))),
                    ),
                    ("drift", Json::Arr(drift_json(&v.drift))),
                    ("pending_drift", Json::Arr(drift_json(&v.pending_drift))),
                    (
                        "projection_errors",
                        Json::Arr(v.projection_errors.iter().map(s).collect()),
                    ),
                ]));
            }
            if all_green {
                out.event(
                    "registers_verified",
                    vec![("periods", Json::Arr(details))],
                    &format!("registers verified by refold: {} green", periods.join(", ")),
                );
                Ok(())
            } else {
                Err(Fail::Verification(
                    format!(
                        "stored registers differ from the refold in {}{}",
                        periods.join(", "),
                        if diagnostics.is_empty() {
                            String::new()
                        } else {
                            format!("; {}", diagnostics.join("; "))
                        }
                    ),
                    Json::Arr(details),
                ))
            }
        }
        Some("open-items") => {
            let book = open_book(args)?;
            let v = book.verify_open_items()?;
            let drift: Vec<Json> = v
                .drift
                .iter()
                .map(|d| {
                    obj(vec![
                        ("entry", s(format!("{:032x}", d.entry.0))),
                        ("ordinal", Json::Int(i128::from(d.ordinal))),
                        ("stored", d.stored.map_or(Json::Null, Json::Int)),
                        ("refolded", Json::Int(d.refolded)),
                    ])
                })
                .collect();
            let fields = vec![
                ("known_at", Json::Int(i128::from(v.known_at.0))),
                ("legs_checked", Json::Int(v.legs_checked as i128)),
                ("drift", Json::Arr(drift)),
            ];
            if v.is_green() {
                out.event(
                    "open_items_verified",
                    fields,
                    &format!(
                        "open items verified by refold: {} legs, applied mirrors agree",
                        v.legs_checked
                    ),
                );
                Ok(())
            } else {
                Err(Fail::Verification(
                    format!(
                        "{} applied mirrors differ from the open-item fold",
                        v.drift.len()
                    ),
                    obj(fields),
                ))
            }
        }
        other => Err(usage(
            format!("verify needs `registers` or `open-items`, got {other:?}"),
            "fa verify registers --period FY2026-P03 --book <dir> | fa verify open-items --book <dir>",
        )),
    }
}

fn open_items_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    let book = open_book(args)?;
    if args.positional.len() != 1 {
        return Err(usage(
            "unexpected open-items argument",
            "fa open-items [--account <code>] [--as-known-at HEAD|<seq>] --book <dir>",
        ));
    }
    let ctx = book.context().clone();
    let account = args
        .flag("--account")
        .map(|code| account_vid(ctx.book_id, code));
    let known_at = match args.flag("--as-known-at") {
        None | Some("HEAD") => None,
        Some(value) => Some(CommitSeq(value.parse::<u64>().map_err(|_| {
            usage(
                "--as-known-at requires HEAD or an unsigned CommitSeq",
                "--as-known-at HEAD or --as-known-at <u64 commit sequence>",
            )
        })?)),
    };
    let items = book.open_items(account, known_at)?;
    let codes: std::collections::BTreeMap<VId, String> = book
        .accounts()?
        .into_iter()
        .map(|a| (a.vid, a.code))
        .collect();
    let code_of = |vid: VId| {
        codes
            .get(&vid)
            .cloned()
            .unwrap_or_else(|| format!("{:032x}", vid.0))
    };
    let render = |unit: u32, m: i128| Amount::new(fa_money::UnitId(unit), m).render(&ctx.units);
    let rows: Vec<Json> = items
        .iter()
        .map(|i| {
            obj(vec![
                ("entry", s(format!("{:032x}", i.entry.0))),
                ("ordinal", Json::Int(i128::from(i.ordinal))),
                ("account", s(code_of(i.account))),
                (
                    "side",
                    s(if i.side == Side::Debit {
                        "debit"
                    } else {
                        "credit"
                    }),
                ),
                ("effective_date", s(i.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(i.recorded_at.0))),
                ("original", s(render(i.unit_id, i.original))),
                ("applied", s(render(i.unit_id, i.applied))),
                ("applied_out", s(render(i.unit_id, i.applied_out))),
                ("open", s(render(i.unit_id, i.open))),
                (
                    "applications",
                    Json::Arr(
                        i.applications
                            .iter()
                            .map(|a| {
                                obj(vec![
                                    ("entry", s(format!("{:032x}", a.entry.0))),
                                    ("ordinal", Json::Int(i128::from(a.ordinal))),
                                    ("amount", s(render(i.unit_id, a.amount))),
                                    ("recorded_at", Json::Int(i128::from(a.recorded_at.0))),
                                    ("live", Json::Bool(a.live)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    if out.json {
        out.event(
            "open_items",
            vec![
                ("account", args.flag("--account").map_or(Json::Null, s)),
                ("count", Json::Int(items.len() as i128)),
                ("items", Json::Arr(rows)),
            ],
            "",
        );
    } else {
        println!(
            "{:<10} {:<34} {:>3} {:<6} {:>18} {:>18} {:>18} {:>18}",
            "account", "entry", "leg", "side", "original", "applied", "applied_out", "open"
        );
        for i in &items {
            println!(
                "{:<10} {:<34} {:>3} {:<6} {:>18} {:>18} {:>18} {:>18}",
                code_of(i.account),
                format!("{:032x}", i.entry.0),
                i.ordinal,
                if i.side == Side::Debit {
                    "debit"
                } else {
                    "credit"
                },
                render(i.unit_id, i.original),
                render(i.unit_id, i.applied),
                render(i.unit_id, i.applied_out),
                render(i.unit_id, i.open)
            );
        }
        println!("{} open item(s)", items.len());
    }
    Ok(())
}

fn registers_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("materialize") => {
            let mut book = open_book(args)?;
            let periods = selected_periods(args, &book)?;
            for p in &periods {
                let (fold, seq) = book.materialize_registers(p)?;
                out.event(
                    "registers_materialized",
                    vec![
                        ("period", s(p)),
                        ("cells", Json::Int(fold.cells.len() as i128)),
                        ("pending_cells", Json::Int(fold.pending.len() as i128)),
                        ("entries", Json::Int(fold.entries as i128)),
                        (
                            "watermark",
                            fold.watermark
                                .map_or(Json::Null, |w| Json::Int(i128::from(w.0))),
                        ),
                        ("fold_digest", s(hex(&fold.fold_digest))),
                        ("recorded_at", Json::Int(i128::from(seq.0))),
                    ],
                    &format!(
                        "{p}: {} posted cells from {} posting entries, {} pending cells (fold digest {})",
                        fold.cells.len(),
                        fold.entries,
                        fold.pending.len(),
                        hex(&fold.fold_digest[..8])
                    ),
                );
            }
            Ok(())
        }
        other => Err(usage(
            format!("registers needs `materialize`, got {other:?}"),
            "fa registers materialize --period FY2026-P03 --book <dir>",
        )),
    }
}

fn entry_cmd(out: &Out, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("show") => {
            let vid_s = args.positional.get(2).ok_or_else(|| {
                usage(
                    "entry show needs a vid (32 hex)",
                    "fa entry show <vid> --book <dir>",
                )
            })?;
            let vid = u128::from_str_radix(vid_s, 16).map_err(|_| {
                usage(
                    format!("`{vid_s}` is not a 32-hex vid"),
                    "use the `vid` from the posted event",
                )
            })?;
            let book = open_book(args)?;
            let units = &book.context().units;
            match book.read_entry(VId(vid))? {
                None => {
                    out.event(
                        "entry",
                        vec![("found", Json::Bool(false)), ("vid", s(vid_s))],
                        &format!("no entry {vid_s}"),
                    );
                    Ok(())
                }
                Some((entry, seq)) => {
                    let legs: Vec<Json> = entry
                        .proposal
                        .legs
                        .iter()
                        .map(|l| {
                            obj(vec![
                                (
                                    "side",
                                    s(if l.side == Side::Debit {
                                        "debit"
                                    } else {
                                        "credit"
                                    }),
                                ),
                                ("account", s(format!("{:032x}", l.account_ref.0))),
                                ("amount", s(l.amount.render(units))),
                            ])
                        })
                        .collect();
                    let fields = vec![
                        ("found", Json::Bool(true)),
                        ("vid", s(vid_s)),
                        ("class", s(entry.proposal.class.name().unwrap_or("?"))),
                        ("effective_date", s(entry.proposal.effective_date.render())),
                        ("recorded_at", Json::Int(i128::from(seq.0))),
                        ("entry_digest", s(hex(&entry.entry_digest))),
                        ("proposal_digest", s(hex(&entry.proposal_digest))),
                        ("approvals", Json::Int(entry.approvals.len() as i128)),
                        ("legs", Json::Arr(legs)),
                    ];
                    let human = format!(
                        "{} {} recorded at {} · {} legs · entry_digest {}",
                        entry.proposal.class.name().unwrap_or("?"),
                        entry.proposal.effective_date.render(),
                        seq.0,
                        entry.proposal.legs.len(),
                        hex(&entry.entry_digest)
                    );
                    out.event("entry", fields, &human);
                    Ok(())
                }
            }
        }
        other => Err(usage(
            format!("entry needs `show`, got {other:?}"),
            "fa entry show <vid> --book <dir>",
        )),
    }
}
