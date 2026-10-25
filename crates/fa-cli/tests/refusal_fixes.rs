//! Refusal-fix executability (bead fa-wgsj; plan §16.6 "every refusal has a
//! fix that, applied, succeeds on the fixture"; G3 "zero useless_error
//! outcomes"). Each case triggers a catalog refusal on its own real fixture
//! book through the `fa` binary, applies the refusal's structured fix (the
//! Appendix D object, bead fa-6his), and checks the documented outcome:
//!
//! - **field change**: `fix.or_field_change.one_of[0]` is written into the
//!   named field of the refused intent, which is resubmitted;
//! - **command**: `fix.argv` runs against the book, then the refused request
//!   is resubmitted;
//! - **rerun**: the refused command runs again with `fix.rerun_with` added;
//! - **alternative**: `alternatives[i]` runs against the book, then the
//!   refused request is resubmitted;
//! - **inform**: `fix.argv` is a read (its `[[bound]]` rule needs only `read`) that must
//!   succeed; the refusal stands by design (the period law is never escaped
//!   by re-dating), so nothing is resubmitted;
//! - **judgment**: the refusal carries no mechanical fix (no command, field
//!   change or rerun arguments) because the remedy is the preparer's
//!   decision; the case states why.
//!
//! A step may lead to a named next refusal, which then gets its own fix; a
//! step whose resubmission returns the same refusal instance fails, as does
//! a fix command naming a verb the registry does not have. Every step is
//! logged: trigger, refusal object, applied fix, outcome. Catalog codes no
//! case triggers are counted and printed, not claimed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

fn tmp(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "fa-refusal-fixes-{}-{name}-{n}",
            std::process::id()
        ));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("create {}: {e}", d.display()),
        }
    }
}

/// `fa --book <book> <args>` → (exit, last robot line). Every line is
/// checked against the registry's schema.
fn fa(book: &Path, args: &[String]) -> (i32, Json) {
    let out = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let reg = registry().expect("verbs.toml");
    for line in stdout.lines() {
        if let Err(e) = reg.check_line(line) {
            panic!("args={args:?}: {e}");
        }
    }
    let last = stdout
        .lines()
        .last()
        .map(|l| json::parse(l).expect("robot JSON"))
        .unwrap_or_else(|| panic!("robot mode is never silent: {args:?}"));
    (out.status.code().unwrap_or(-1), last)
}

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_string()).collect()
}

/// A fixture book: a summary `100` over two cash leaves, a EUR cash leaf, a
/// USD expense, an any-currency expense, receivables and revenue; FY2026 with March and April
/// open; one source document. `entities` declares legal entities.
fn book(name: &str, entities: &[&str]) -> (PathBuf, PathBuf, String) {
    let dir = tmp(name);
    let book = dir.join("book");
    let mut create = argv(&["book", "create", "--name", "Fixes Co", "--json"]);
    for e in entities {
        create.extend(argv(&["--entity", e]));
    }
    assert_eq!(fa(&book, &create).0, 0);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[
            {"code":"100","name":"Cash and equivalents","type":"Asset","leaf":false,"unit":"USD"},
            {"code":"1000","name":"Operating cash","type":"Asset","leaf":true,"unit":"USD","parent":"100"},
            {"code":"1010","name":"Petty cash","type":"Asset","leaf":true,"unit":"USD","parent":"100"},
            {"code":"1300","name":"Euro cash","type":"Asset","leaf":true,"unit":"EUR"},
            {"code":"6000","name":"Rent","type":"Expense","unit":"USD"},
            {"code":"6050","name":"Rent abroad","type":"Expense","unit":"any-currency"},
            {"code":"1200","name":"Receivables","type":"Asset","leaf":true,"unit":"USD"},
            {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    )
    .expect("chart");
    let chart = chart.display().to_string();
    for step in [
        argv(&["chart", "import", &chart, "--json"]),
        argv(&["period", "create", "--fiscal-year", "2026", "--json"]),
        argv(&["period", "open", "FY2026-P03", "--json"]),
        argv(&["period", "open", "FY2026-P04", "--json"]),
    ] {
        let (code, line) = fa(&book, &step);
        assert_eq!(code, 0, "{step:?}: {}", line.render());
    }
    let source = dir.join("source.txt");
    std::fs::write(&source, "INVOICE (refusal fixes fixture)").expect("source");
    let (code, line) = fa(
        &book,
        &argv(&[
            "document",
            "add",
            &source.display().to_string(),
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
            "--json",
        ]),
    );
    assert_eq!(code, 0, "{}", line.render());
    let oid = line
        .get("data")
        .and_then(|d| d.get("oid"))
        .and_then(Json::as_str)
        .expect("document oid")
        .to_string();
    (dir, book, oid)
}

/// What a case submits: a post intent (resubmitted after a field change) or
/// a plain command line.
#[derive(Clone)]
enum Request {
    Post { intent: Json, extra: Vec<String> },
    Argv(Vec<String>),
}

/// How a step applies the refusal's fix.
#[derive(Clone, Copy, Debug)]
enum Apply {
    FieldChange,
    Command,
    Rerun,
    Alternative(usize),
    Inform,
    Judgment(&'static str),
}

/// What a trigger can name: the vid of a committed base entry, when the
/// case asks for one (a post's evidence is supplied when it runs).
struct Given {
    vid: Option<String>,
}

struct Case {
    name: &'static str,
    entities: &'static [&'static str],
    /// Commands run on the fixture before the trigger.
    setup: &'static [&'static [&'static str]],
    /// An entry posted first (its vid goes to the trigger), if any.
    base: Option<fn() -> Json>,
    /// A request run after the base that must succeed, if any.
    prepare: Option<fn(&Given) -> Request>,
    trigger: fn(&Given) -> Request,
    /// Each expected refusal code and how its fix is applied, in order.
    steps: &'static [(&'static str, Apply)],
}

fn leg(side: &str, account: &str, amount: &str) -> Json {
    Json::Obj(vec![
        ("side".into(), Json::Str(side.into())),
        ("account".into(), Json::Str(account.into())),
        ("amount".into(), Json::Str(amount.into())),
    ])
}

fn intent(key: &str, date: &str, legs: Vec<Json>) -> Json {
    Json::Obj(vec![
        ("effective_date".into(), Json::Str(date.into())),
        ("idempotency_key".into(), Json::Str(key.into())),
        ("description".into(), Json::Str(key.into())),
        ("legs".into(), Json::Arr(legs)),
    ])
}

/// A balanced March rent entry, key `base`.
fn rent_base() -> Json {
    intent(
        "base",
        "2026-03-05",
        vec![
            leg("debit", "6000", "7.00 USD"),
            leg("credit", "1000", "7.00 USD"),
        ],
    )
}

/// A 100.00 USD March invoice: receivables against revenue, key `invoice`.
fn invoice_base() -> Json {
    intent(
        "invoice",
        "2026-03-05",
        vec![
            leg("debit", "1200", "100.00 USD"),
            leg("credit", "4000", "100.00 USD"),
        ],
    )
}

/// A balanced April rent entry, key `april-base`.
fn april_rent_base() -> Json {
    intent(
        "april-base",
        "2026-04-05",
        vec![
            leg("debit", "6000", "7.00 USD"),
            leg("credit", "1000", "7.00 USD"),
        ],
    )
}

/// A 7.00 USD March hold (`class = Pending`), key `hold`.
fn hold_base() -> Json {
    let mut entry = intent(
        "hold",
        "2026-03-05",
        vec![
            leg("debit", "6000", "7.00 USD"),
            leg("credit", "1000", "7.00 USD"),
        ],
    );
    set_field(&mut entry, "class", "Pending");
    entry
}

fn post(intent: Json) -> Request {
    Request::Post {
        intent,
        extra: Vec::new(),
    }
}

/// Run `req`; `n` numbers the intent file so each submission is its own.
fn run(dir: &Path, book: &Path, ev: &str, req: &Request, n: usize) -> (i32, Json, Vec<String>) {
    let args = match req {
        Request::Post { intent, extra } => {
            let file = dir.join(format!("intent-{n}.json"));
            std::fs::write(&file, intent.render()).expect("intent");
            let mut args = argv(&[
                "post",
                "--intent",
                &file.display().to_string(),
                "--evidence",
                ev,
                "--json",
            ]);
            args.extend(extra.iter().cloned());
            args
        }
        Request::Argv(a) => a.clone(),
    };
    let (code, line) = fa(book, &args);
    (code, line, args)
}

fn strings(v: Option<&Json>) -> Vec<String> {
    v.and_then(Json::as_arr)
        .map(|a| {
            a.iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Write `value` into `field` of the intent: a dotted path whose segments
/// may index arrays (`legs[1].settles[0].amount`, `idempotency_key`).
fn set_field(intent: &mut Json, field: &str, value: &str) {
    let parts: Vec<&str> = field.split('.').collect();
    let mut at = intent;
    for (k, part) in parts.iter().enumerate() {
        let (name, index) = match part.split_once('[') {
            Some((name, rest)) => (
                name,
                Some(rest.trim_end_matches(']').parse::<usize>().expect("index")),
            ),
            None => (*part, None),
        };
        let Json::Obj(fields) = at else {
            panic!("`{field}`: `{name}`'s parent is not an object");
        };
        if k + 1 == parts.len() && index.is_none() {
            match fields.iter_mut().find(|(f, _)| f == name) {
                Some(slot) => slot.1 = Json::Str(value.into()),
                None => fields.push((name.to_string(), Json::Str(value.into()))),
            }
            return;
        }
        let child = fields
            .iter_mut()
            .find(|(f, _)| f == name)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("`{field}`: no `{name}`"));
        at = match index {
            Some(i) => {
                let Json::Arr(items) = child else {
                    panic!("`{field}`: `{name}` is not an array");
                };
                &mut items[i]
            }
            None => child,
        };
    }
    panic!("`{field}` names no scalar");
}

/// The registry verb a fix's argv runs (through an alias when it is one).
fn fix_verb<'r>(
    reg: &'r fa_cli::verbs::Registry,
    fix_argv: &[String],
) -> Option<&'r fa_cli::verbs::Verb> {
    let first = fix_argv.first()?;
    reg.verb(first)
        .or_else(|| reg.alias(first).and_then(|a| reg.verb(a.expands.first()?)))
}

/// Run one case; returns the codes it exercised.
fn execute(case: &Case) -> Vec<&'static str> {
    let (dir, book, ev) = book(case.name, case.entities);
    for step in case.setup {
        let (code, line) = fa(&book, &argv(step));
        assert_eq!(code, 0, "{}: setup {step:?}: {}", case.name, line.render());
    }
    let reg = registry().expect("verbs.toml");
    let vid = case.base.map(|base| {
        let (code, line, _) = run(&dir, &book, &ev, &post(base()), 0);
        assert_eq!(code, 0, "{}: base entry: {}", case.name, line.render());
        line.get("data")
            .and_then(|d| d.get("vid"))
            .and_then(Json::as_str)
            .expect("base vid")
            .to_string()
    });
    if let Some(prepare) = case.prepare {
        let (code, line, args) = run(&dir, &book, &ev, &prepare(&Given { vid: vid.clone() }), 100);
        assert_eq!(
            code,
            0,
            "{}: prepare {args:?}: {}",
            case.name,
            line.render()
        );
    }
    let mut req = (case.trigger)(&Given { vid });
    let mut seen = BTreeSet::new();
    let mut n = 0;
    for (want, apply) in case.steps {
        n += 1;
        let (code, line, args) = run(&dir, &book, &ev, &req, n);
        let data = line.get("data").expect("data");
        let refusal = data
            .get("refusal")
            .filter(|r| **r != Json::Null)
            .unwrap_or_else(|| {
                panic!(
                    "{}: {args:?} should refuse {want}, got exit {code}: {}",
                    case.name,
                    line.render()
                )
            });
        println!(
            "{} step {n}: trigger {args:?} -> exit {code} refusal {}",
            case.name,
            refusal.render()
        );
        let got = refusal.get("code").and_then(Json::as_str).unwrap_or("");
        assert_eq!(got, *want, "{}: {}", case.name, refusal.render());
        let id = refusal
            .get("id")
            .and_then(Json::as_str)
            .expect("id")
            .to_string();
        assert!(
            seen.insert(id.clone()),
            "{}: applying the fix led back to the same refusal {id}",
            case.name
        );
        let fix = refusal.get("fix").expect("fix");
        let fix_argv = strings(fix.get("argv"));
        let rerun = strings(fix.get("rerun_with"));
        let change = fix.get("or_field_change").filter(|c| **c != Json::Null);
        match apply {
            Apply::FieldChange => {
                let change = change.unwrap_or_else(|| panic!("{}: no field change", case.name));
                let field = change.get("field").and_then(Json::as_str).expect("field");
                let value = strings(change.get("one_of"))
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| panic!("{}: field change admits no value", case.name));
                println!("{} step {n}: apply {field} = {value}", case.name);
                match &mut req {
                    // A field the post's command line carries as a flag
                    // (draft, scenario) is that flag; any other is the
                    // intent's.
                    Request::Post { intent, extra } => {
                        let flag = format!("--{}", field.replace('_', "-"));
                        match extra.iter().position(|w| *w == flag) {
                            Some(i) if i + 1 < extra.len() => extra[i + 1] = value,
                            _ => set_field(intent, field, &value),
                        }
                    }
                    // On a command line the field is its flag.
                    Request::Argv(a) => {
                        let flag = format!("--{}", field.replace('_', "-"));
                        match a.iter().position(|w| *w == flag) {
                            Some(i) if i + 1 < a.len() => a[i + 1] = value,
                            _ => a.extend([flag, value]),
                        }
                    }
                }
            }
            Apply::Command | Apply::Inform => {
                assert!(!fix_argv.is_empty(), "{}: no fix command", case.name);
                let verb = fix_verb(reg, &fix_argv)
                    .unwrap_or_else(|| panic!("{}: fix names no verb: {fix_argv:?}", case.name));
                if matches!(apply, Apply::Inform) {
                    // A read is a command whose `[[bound]]` rule needs only
                    // `read` (verbs.toml `writes` is per verb: `chart`
                    // writes through `chart import`, `chart list` reads).
                    let parsed =
                        fa_cli::args::parse(&fix_argv, &reg.value_flags(), &reg.switches())
                            .expect("fix argv parses");
                    let ops = fa_cli::cli::bound_command_ops(&verb.name, &parsed);
                    assert!(
                        ops.is_some_and(|ops| ops.iter().all(|op| *op == fa_policy::Op::Read)),
                        "{}: an informational fix must be a read: {fix_argv:?} needs {ops:?}",
                        case.name
                    );
                }
                let mut command = fix_argv.clone();
                if !command.iter().any(|a| a == "--json") {
                    command.push("--json".into());
                }
                let (code, line) = fa(&book, &command);
                println!(
                    "{} step {n}: apply {command:?} -> exit {code} {}",
                    case.name,
                    line.get("event").map(Json::render).unwrap_or_default()
                );
                assert_eq!(code, 0, "{}: fix {command:?}: {}", case.name, line.render());
                if matches!(apply, Apply::Inform) {
                    return case.steps.iter().map(|(c, _)| *c).collect();
                }
            }
            Apply::Alternative(i) => {
                let alternatives = strings(refusal.get("alternatives"));
                let line = alternatives
                    .get(*i)
                    .unwrap_or_else(|| panic!("{}: no alternative {i}", case.name));
                let mut command: Vec<String> = line
                    .split_whitespace()
                    .skip(1)
                    .map(str::to_string)
                    .collect();
                assert!(
                    fix_verb(reg, &command).is_some(),
                    "{}: alternative names no verb: {line}",
                    case.name
                );
                if !command.iter().any(|a| a == "--json") {
                    command.push("--json".into());
                }
                let (code, out) = fa(&book, &command);
                println!(
                    "{} step {n}: apply alternative {command:?} -> exit {code} {}",
                    case.name,
                    out.get("event").map(Json::render).unwrap_or_default()
                );
                assert_eq!(
                    code,
                    0,
                    "{}: alternative {command:?}: {}",
                    case.name,
                    out.render()
                );
            }
            Apply::Rerun => {
                assert!(!rerun.is_empty(), "{}: no rerun arguments", case.name);
                println!("{} step {n}: apply rerun with {rerun:?}", case.name);
                match &mut req {
                    Request::Post { extra, .. } => extra.extend(rerun),
                    Request::Argv(a) => a.extend(rerun),
                }
            }
            Apply::Judgment(why) => {
                assert!(
                    fix_argv.is_empty() && rerun.is_empty() && change.is_none(),
                    "{}: a judgment case must carry no mechanical fix: {}",
                    case.name,
                    refusal.render()
                );
                println!("{} step {n}: judgment: {why}", case.name);
                return case.steps.iter().map(|(c, _)| *c).collect();
            }
        }
    }
    n += 1;
    let (code, line, args) = run(&dir, &book, &ev, &req, n);
    println!(
        "{} final: {args:?} -> exit {code} {}",
        case.name,
        line.get("event").map(Json::render).unwrap_or_default()
    );
    assert_eq!(
        code,
        0,
        "{}: the fixed request should succeed: {}",
        case.name,
        line.render()
    );
    case.steps.iter().map(|(c, _)| *c).collect()
}

const CASES: &[Case] = &[
    Case {
        name: "summary-account",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            post(intent(
                "summary",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "100", "5.00 USD"),
                ],
            ))
        },
        steps: &[("FA-REF-002", Apply::FieldChange)],
    },
    Case {
        name: "unit-policy",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            post(intent(
                "euros",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 EUR"),
                    leg("credit", "1300", "5.00 EUR"),
                ],
            ))
        },
        steps: &[("FA-REF-003", Apply::FieldChange)],
    },
    Case {
        name: "missing-entity",
        entities: &["US:US Co", "UK:UK Co"],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            post(intent(
                "entityless",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ))
        },
        // Each leg names its entity in turn (the first declared one).
        steps: &[
            ("FA-REF-005", Apply::FieldChange),
            ("FA-REF-005", Apply::FieldChange),
        ],
    },
    Case {
        name: "period-never-created",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            post(intent(
                "next-year",
                "2027-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ))
        },
        // Create the year, then the period law names the open command.
        steps: &[
            ("FA-REF-021", Apply::Command),
            ("FA-REF-010", Apply::Command),
        ],
    },
    Case {
        name: "softclosed-without-grant",
        entities: &[],
        setup: &[&["period", "soft-close", "FY2026-P04", "--json"]],
        base: None,
        prepare: None,
        trigger: |_| {
            post(intent(
                "late-april",
                "2026-04-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ))
        },
        steps: &[("FA-REF-011", Apply::Rerun)],
    },
    Case {
        name: "close-unconfirmed",
        entities: &[],
        setup: &[&["period", "soft-close", "FY2026-P04", "--json"]],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "period",
                "close",
                "FY2026-P04",
                "--reason",
                "Scheduled",
                "--json",
            ]))
        },
        steps: &[("FA-REF-007", Apply::Rerun)],
    },
    Case {
        name: "unknown-account",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            post(intent(
                "unknown",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "9999", "5.00 USD"),
                ],
            ))
        },
        steps: &[("FA-REF-004", Apply::Inform)],
    },
    Case {
        name: "closed-period",
        entities: &[],
        base: None,
        prepare: None,
        setup: &[
            &["period", "soft-close", "FY2026-P03", "--json"],
            &[
                "period",
                "close",
                "FY2026-P03",
                "--reason",
                "Scheduled",
                "--yes",
                "--json",
            ],
        ],
        trigger: |_| {
            post(intent(
                "march-late",
                "2026-03-21",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ))
        },
        steps: &[("FA-REF-010", Apply::Inform)],
    },
    Case {
        name: "unbalanced",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            post(intent(
                "unbalanced",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "4.00 USD"),
                ],
            ))
        },
        steps: &[(
            "FA-REF-001",
            Apply::Judgment(
                "which account explains the gap is the preparer's decision; where.short_side and where.gap name what is missing",
            ),
        )],
    },
];

const MORE_CASES: &[Case] = &[
    Case {
        name: "reversal-reason",
        entities: &[],
        setup: &[],
        base: Some(rent_base),
        prepare: None,
        trigger: |g| {
            Request::Argv(argv(&[
                "reverse",
                g.vid.as_deref().expect("base vid"),
                "--reason",
                "Duplicat",
                "--json",
            ]))
        },
        // The nearest registered spelling comes first.
        steps: &[("FA-REF-054", Apply::FieldChange)],
    },
    Case {
        name: "unknown-draft",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| Request::Post {
            intent: intent(
                "into-draft",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ),
            extra: argv(&["--draft", "q3-accruals"]),
        },
        // `fa draft new q3-accruals`, then the same plan lands in it.
        steps: &[("FA-REF-157", Apply::Alternative(0))],
    },
    Case {
        name: "unknown-scenario",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| Request::Post {
            intent: intent(
                "into-scenario",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ),
            extra: argv(&["--scenario", "what-if"]),
        },
        steps: &[("FA-REF-162", Apply::Alternative(0))],
    },
    Case {
        name: "closed-draft",
        entities: &[],
        setup: &[
            &["draft", "new", "q3-accruals", "--json"],
            &[
                "draft",
                "discard",
                "q3-accruals",
                "--reason",
                "superseded",
                "--json",
            ],
        ],
        base: None,
        prepare: None,
        // The fix names a fresh draft; planning into it meets FA-REF-157,
        // whose alternative opens it, and the plan lands there.
        trigger: |_| Request::Post {
            intent: intent(
                "into-closed-draft",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ),
            extra: argv(&["--draft", "q3-accruals"]),
        },
        steps: &[
            ("FA-REF-158", Apply::FieldChange),
            ("FA-REF-157", Apply::Alternative(0)),
        ],
    },
    Case {
        name: "discarded-scenario",
        entities: &[],
        setup: &[
            &["scenario", "fork", "what-if", "--json"],
            &[
                "scenario",
                "discard",
                "what-if",
                "--reason",
                "abandoned",
                "--json",
            ],
        ],
        base: None,
        prepare: None,
        // As for drafts: a fresh scenario, forked by FA-REF-162's alternative.
        trigger: |_| Request::Post {
            intent: intent(
                "into-discarded-scenario",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ),
            extra: argv(&["--scenario", "what-if"]),
        },
        steps: &[
            ("FA-REF-163", Apply::FieldChange),
            ("FA-REF-162", Apply::Alternative(0)),
        ],
    },
    Case {
        name: "scenario-before-start",
        entities: &[],
        setup: &[&[
            "scenario",
            "fork",
            "but-for",
            "--from",
            "2026-03-15",
            "--json",
        ]],
        base: None,
        prepare: None,
        // The counterfactual starts on the 15th: the fix redates the intent
        // to that day and it runs in the scenario.
        trigger: |_| Request::Post {
            intent: intent(
                "too-early",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            ),
            extra: argv(&["--scenario", "but-for"]),
        },
        steps: &[("FA-REF-164", Apply::FieldChange)],
    },
    Case {
        name: "unknown-production",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        // Inform: the matter list is a read; the refusal stands.
        trigger: |_| Request::Argv(argv(&["production", "show", "no-such-matter", "--json"])),
        steps: &[("FA-REF-170", Apply::Inform)],
    },
    Case {
        name: "unknown-case",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        // Inform: the case list is a read; the refusal stands.
        trigger: |_| Request::Argv(argv(&["case", "show", "7", "--json"])),
        steps: &[("FA-REF-175", Apply::Inform)],
    },
    Case {
        name: "undeclared-entity",
        entities: &["US:US Co", "UK:UK Co"],
        setup: &[],
        base: None,
        prepare: None,
        // Both legs name an entity the book never declared; each is moved to
        // a declared one in turn.
        trigger: |_| {
            let mut entry = intent(
                "foreign-entity",
                "2026-03-10",
                vec![
                    leg("debit", "6000", "5.00 USD"),
                    leg("credit", "1000", "5.00 USD"),
                ],
            );
            set_field(&mut entry, "legs[0].entity", "FR");
            set_field(&mut entry, "legs[1].entity", "FR");
            post(entry)
        },
        steps: &[
            ("FA-REF-104", Apply::FieldChange),
            ("FA-REF-104", Apply::FieldChange),
        ],
    },
    Case {
        name: "illegal-transition",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        // May is Future: it opens before it can soft-close.
        trigger: |_| Request::Argv(argv(&["period", "soft-close", "FY2026-P05", "--json"])),
        steps: &[("FA-REF-040", Apply::Command)],
    },
    Case {
        name: "idempotency-conflict",
        entities: &[],
        setup: &[],
        base: Some(rent_base),
        prepare: None,
        // The same key with different content: the refusal suggests a key
        // derived from the new content, and the new content posts under it.
        trigger: |_| {
            post(intent(
                "base",
                "2026-03-05",
                vec![
                    leg("debit", "6000", "8.00 USD"),
                    leg("credit", "1000", "8.00 USD"),
                ],
            ))
        },
        steps: &[("FA-REF-032", Apply::FieldChange)],
    },
    Case {
        name: "over-application",
        entities: &[],
        setup: &[],
        base: Some(invoice_base),
        prepare: None,
        // A 150.00 USD receipt applies all of itself to a 100.00 USD
        // invoice; the open amount is the field change.
        trigger: |g| {
            let vid = g.vid.clone().expect("invoice vid");
            let mut settle = leg("credit", "1200", "150.00 USD");
            if let Json::Obj(fields) = &mut settle {
                fields.push((
                    "settles".into(),
                    Json::Arr(vec![Json::Obj(vec![
                        ("entry".into(), Json::Str(vid)),
                        ("ordinal".into(), Json::Int(0)),
                        ("amount".into(), Json::Str("150.00 USD".into())),
                    ])]),
                ));
            }
            post(intent(
                "receipt",
                "2026-03-12",
                vec![leg("debit", "1000", "150.00 USD"), settle],
            ))
        },
        steps: &[("FA-REF-072", Apply::FieldChange)],
    },
    Case {
        name: "instant-before-ticks",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "tb",
                "--period",
                "FY2026-P03",
                "--as-known-at",
                "2020-01-01T00:00:00Z",
                "--json",
            ]))
        },
        steps: &[("FA-REF-151", Apply::FieldChange)],
    },
    Case {
        name: "already-reversed",
        entities: &[],
        setup: &[],
        base: Some(rent_base),
        prepare: Some(|g| {
            Request::Argv(argv(&[
                "reverse",
                g.vid.as_deref().expect("base vid"),
                "--reason",
                "Duplicate",
                "--json",
            ]))
        }),
        trigger: |g| {
            Request::Argv(argv(&[
                "reverse",
                g.vid.as_deref().expect("base vid"),
                "--reason",
                "WrongAccount",
                "--json",
            ]))
        },
        // A second reversal with another reason is new content for the same
        // identity: the fix shows the existing reversal, and the second one
        // stands refused.
        steps: &[("FA-REF-052", Apply::Inform)],
    },
    Case {
        name: "reverse-pending-target",
        entities: &[],
        setup: &[],
        base: Some(hold_base),
        prepare: None,
        trigger: |g| {
            Request::Argv(argv(&[
                "reverse",
                g.vid.as_deref().expect("hold vid"),
                "--reason",
                "Duplicate",
                "--json",
            ]))
        },
        steps: &[("FA-REF-050", Apply::Inform)],
    },
    Case {
        name: "reversal-before-target-period",
        entities: &[],
        setup: &[],
        base: Some(april_rent_base),
        prepare: None,
        trigger: |g| {
            Request::Argv(argv(&[
                "reverse",
                g.vid.as_deref().expect("april vid"),
                "--reason",
                "Duplicate",
                "--effective",
                "2026-03-10",
                "--json",
            ]))
        },
        steps: &[("FA-REF-053", Apply::FieldChange)],
    },
    Case {
        name: "resolve-posted-target",
        entities: &[],
        setup: &[],
        base: Some(rent_base),
        prepare: None,
        trigger: |g| Request::Post {
            intent: Json::Obj(vec![
                ("class".into(), Json::Str("Resolution".into())),
                ("resolves".into(), Json::Str(g.vid.clone().expect("rent vid"))),
                ("disposition".into(), Json::Str("voids".into())),
                ("effective_date".into(), Json::Str("2026-03-10".into())),
                ("idempotency_key".into(), Json::Str("void-posted".into())),
                ("description".into(), Json::Str("void-posted".into())),
            ]),
            extra: argv(&["--yes"]),
        },
        steps: &[("FA-REF-060", Apply::Inform)],
    },
    Case {
        name: "resolution-exceeds-reserved",
        entities: &[],
        setup: &[],
        base: Some(hold_base),
        prepare: None,
        trigger: |g| {
            post(Json::Obj(vec![
                ("class".into(), Json::Str("Resolution".into())),
                ("resolves".into(), Json::Str(g.vid.clone().expect("hold vid"))),
                ("disposition".into(), Json::Str("posts".into())),
                ("amount".into(), Json::Str("10.00 USD".into())),
                ("effective_date".into(), Json::Str("2026-03-10".into())),
                ("idempotency_key".into(), Json::Str("resolve-hold".into())),
                ("description".into(), Json::Str("resolve-hold".into())),
            ]))
        },
        steps: &[("FA-REF-061", Apply::FieldChange)],
    },
    Case {
        name: "already-resolved",
        entities: &[],
        setup: &[],
        base: Some(hold_base),
        prepare: Some(|g| Request::Post {
            intent: Json::Obj(vec![
                ("class".into(), Json::Str("Resolution".into())),
                ("resolves".into(), Json::Str(g.vid.clone().expect("hold vid"))),
                ("disposition".into(), Json::Str("voids".into())),
                ("effective_date".into(), Json::Str("2026-03-10".into())),
                ("idempotency_key".into(), Json::Str("first-void".into())),
                ("description".into(), Json::Str("first-void".into())),
            ]),
            extra: argv(&["--yes"]),
        }),
        trigger: |g| Request::Post {
            intent: Json::Obj(vec![
                ("class".into(), Json::Str("Resolution".into())),
                ("resolves".into(), Json::Str(g.vid.clone().expect("hold vid"))),
                ("disposition".into(), Json::Str("voids".into())),
                ("effective_date".into(), Json::Str("2026-03-11".into())),
                ("idempotency_key".into(), Json::Str("second-void".into())),
                ("description".into(), Json::Str("second-void".into())),
            ]),
            extra: argv(&["--yes"]),
        },
        steps: &[("FA-REF-062", Apply::Inform)],
    },
    Case {
        name: "settle-pending-target",
        entities: &[],
        setup: &[],
        base: Some(hold_base),
        prepare: None,
        trigger: |g| {
            let vid = g.vid.clone().expect("hold vid");
            let mut settle = leg("credit", "1200", "7.00 USD");
            if let Json::Obj(fields) = &mut settle {
                fields.push((
                    "settles".into(),
                    Json::Arr(vec![Json::Obj(vec![
                        ("entry".into(), Json::Str(vid)),
                        ("ordinal".into(), Json::Int(0)),
                        ("amount".into(), Json::Str("7.00 USD".into())),
                    ])]),
                ));
            }
            post(intent(
                "settle-hold",
                "2026-03-12",
                vec![leg("debit", "1000", "7.00 USD"), settle],
            ))
        },
        steps: &[("FA-REF-070", Apply::Inform)],
    },
    Case {
        name: "settle-bad-ordinal",
        entities: &[],
        setup: &[],
        base: Some(invoice_base),
        prepare: None,
        trigger: |g| {
            let vid = g.vid.clone().expect("invoice vid");
            let mut settle = leg("credit", "1200", "100.00 USD");
            if let Json::Obj(fields) = &mut settle {
                fields.push((
                    "settles".into(),
                    Json::Arr(vec![Json::Obj(vec![
                        ("entry".into(), Json::Str(vid)),
                        ("ordinal".into(), Json::Int(9)),
                        ("amount".into(), Json::Str("100.00 USD".into())),
                    ])]),
                ));
            }
            post(intent(
                "settle-ordinal",
                "2026-03-12",
                vec![leg("debit", "1000", "100.00 USD"), settle],
            ))
        },
        steps: &[("FA-REF-071", Apply::FieldChange)],
    },
    Case {
        name: "reverse-with-live-applications",
        entities: &[],
        setup: &[],
        base: Some(invoice_base),
        prepare: Some(|g| {
            let vid = g.vid.clone().expect("invoice vid");
            let mut settle = leg("credit", "1200", "40.00 USD");
            if let Json::Obj(fields) = &mut settle {
                fields.push((
                    "settles".into(),
                    Json::Arr(vec![Json::Obj(vec![
                        ("entry".into(), Json::Str(vid)),
                        ("ordinal".into(), Json::Int(0)),
                        ("amount".into(), Json::Str("40.00 USD".into())),
                    ])]),
                ));
            }
            post(intent(
                "partial-receipt",
                "2026-03-12",
                vec![leg("debit", "1000", "40.00 USD"), settle],
            ))
        }),
        trigger: |g| {
            Request::Argv(argv(&[
                "reverse",
                g.vid.as_deref().expect("invoice vid"),
                "--reason",
                "Duplicate",
                "--json",
            ]))
        },
        steps: &[("FA-REF-073", Apply::Inform)],
    },
    Case {
        name: "unknown-document",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "document",
                "show",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--json",
            ]))
        },
        steps: &[("FA-REF-081", Apply::Inform)],
    },
    Case {
        name: "proof-without-checkpoint",
        entities: &[],
        setup: &[],
        base: Some(rent_base),
        prepare: None,
        trigger: |g| {
            Request::Argv(argv(&[
                "proof",
                "inclusion",
                "--entry",
                g.vid.as_deref().expect("rent vid"),
                "--json",
            ]))
        },
        steps: &[("FA-REF-145", Apply::Alternative(0))],
    },
    Case {
        name: "not-issued-to-recipient",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "tb",
                "--period",
                "FY2026-P03",
                "--as-issued-to",
                "board",
                "--json",
            ]))
        },
        steps: &[("FA-REF-173", Apply::Inform)],
    },
    Case {
        name: "unknown-engagement",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| Request::Argv(argv(&["engagement", "show", "no-such-engagement", "--json"])),
        steps: &[("FA-REF-180", Apply::Inform)],
    },
    Case {
        name: "unknown-adjustment",
        entities: &[],
        setup: &[&[
            "engagement",
            "open",
            "fy26-audit",
            "--kind",
            "audit",
            "--period",
            "FY2026-P03",
            "--overall",
            "1000.00 USD",
            "--performance",
            "750.00 USD",
            "--clearly-trivial",
            "50.00 USD",
            "--json",
        ]],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "adjustment",
                "pass",
                "--engagement",
                "fy26-audit",
                "--proposal",
                "9",
                "--reason",
                "ClearlyTrivial",
                "--json",
            ]))
        },
        steps: &[("FA-REF-184", Apply::Inform)],
    },
    Case {
        name: "reclassification-exceeds-remaining",
        entities: &[],
        setup: &[],
        base: Some(rent_base),
        prepare: None,
        trigger: |g| {
            Request::Argv(argv(&[
                "reclass",
                g.vid.as_deref().expect("rent vid"),
                "--from",
                "6000",
                "--to",
                "6050",
                "--amount",
                "10.00 USD",
                "--reason",
                "WrongAccount",
                "--json",
            ]))
        },
        steps: &[("FA-REF-185", Apply::FieldChange)],
    },
    Case {
        name: "query-profile-unknown-period",
        entities: &[],
        setup: &[],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "query",
                "MATCH (e:Entry) FOR PERIOD 'FY2026-P99' RETURN e",
                "--json",
            ]))
        },
        steps: &[("FA-REF-188", Apply::Inform)],
    },
    Case {
        name: "documentation-completion-after-window",
        entities: &[],
        setup: &[&[
            "engagement",
            "open",
            "fy26-audit",
            "--kind",
            "audit",
            "--period",
            "FY2026-P03",
            "--overall",
            "1000.00 USD",
            "--performance",
            "750.00 USD",
            "--clearly-trivial",
            "50.00 USD",
            "--json",
        ]],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "engagement",
                "complete",
                "fy26-audit",
                "--report-release",
                "2026-04-15",
                "--completion-date",
                "2026-05-31",
                "--json",
            ]))
        },
        steps: &[("FA-REF-190", Apply::FieldChange)],
    },
    Case {
        name: "carry-forward-self",
        entities: &[],
        setup: &[&[
            "engagement",
            "open",
            "fy26-audit",
            "--kind",
            "audit",
            "--period",
            "FY2026-P03",
            "--overall",
            "1000.00 USD",
            "--performance",
            "750.00 USD",
            "--clearly-trivial",
            "50.00 USD",
            "--json",
        ]],
        base: None,
        prepare: None,
        trigger: |_| {
            Request::Argv(argv(&[
                "engagement",
                "carry-forward",
                "fy26-audit",
                "--from",
                "fy26-audit",
                "--json",
            ]))
        },
        steps: &[("FA-REF-191", Apply::Inform)],
    },
];

/// Catalog codes not triggered by the single-command CLI harness, with the
/// exact reason each belongs outside the single-step CLI fixture loop.
const UNTRIGGERED_WITH_REASON: &[(&str, &str)] = &[
    ("FA-REF-008", "multi-principal SoD workflow (preparer vs approver)"),
    ("FA-REF-012", "multi-principal approval collection over proposal digest"),
    ("FA-REF-013", "Agent-profile token / MCP session confinement"),
    ("FA-REF-014", "issued capability token past CommitSeq expiry"),
    ("FA-REF-015", "issued capability token per-leg amount ceiling"),
    ("FA-REF-016", "approval digest mismatch against modified proposal"),
    ("FA-REF-017", "unknown approval vertex citation"),
    ("FA-REF-018", "concurrent writer lease held by another process / fad"),
    ("FA-REF-019", "library-level unregistered policy activation"),
    ("FA-REF-020", "ambiguous civil date shared with opening/adjustment/closing period"),
    ("FA-REF-022", "approval recorded under an older security policy epoch"),
    ("FA-REF-023", "revoked capability token"),
    ("FA-REF-030", "concurrent first-committer-wins transaction race"),
    ("FA-REF-031", "concurrent period transition race"),
    ("FA-REF-033", "sealed field opened with non-matching key"),
    ("FA-REF-034", "dry-run plan committed after intervening book advancement"),
    ("FA-REF-041", "CLI preflight validates period transition reason before kernel"),
    ("FA-REF-051", "CLI reverse derives exact side-swap legs from target"),
    ("FA-REF-080", "CLI post requires --evidence flag or event citation at preflight"),
    ("FA-REF-082", "CLI resolves document commitment directly from book store"),
    ("FA-REF-083", "document intake bounds / MIME preflight"),
    ("FA-REF-084", "CLI preflight restricts --grade to HumanUpload|AgentUpload"),
    ("FA-REF-085", "store corruption / document commitment drift (exit 8)"),
    ("FA-REF-086", "multi-principal Reviewed attestation over AgentUpload evidence"),
    ("FA-REF-087", "CLI document attach resolves target EntryRef from book"),
    ("FA-REF-088", "Appendix H R-ERASE interim posture (erasure tombstones absent)"),
    ("FA-REF-090", "account lower_bound availability breach"),
    ("FA-REF-091", "account upper_bound availability breach"),
    ("FA-REF-092", "i128 register capacity ceiling"),
    ("FA-REF-093", "CLI preflight validates --balancing leg index and shape"),
    ("FA-REF-094", "daemon / library TimeEvidence monotonic clock rollback"),
    ("FA-REF-095", "timed Pending hold without prior TimeEvidence tick"),
    ("FA-REF-096", "timed Pending hold deadline u64 overflow"),
    ("FA-REF-097", "manual Posts resolution after committed tick passed deadline"),
    ("FA-REF-098", "library-only Expires disposition (CLI restricts disposition to posts|voids)"),
    ("FA-REF-099", "library-only ScheduleCancel control entry"),
    ("FA-REF-100", "library-only EntryPayload structural invariant check"),
    ("FA-REF-101", "library-only control payload submitted to post"),
    ("FA-REF-102", "class not yet admitted by direct post"),
    ("FA-REF-103", "library-only EntryPayload book_id mismatch"),
    ("FA-REF-110", "attestation subject unknown or class disallows ManualAssertion"),
    ("FA-REF-111", "multi-principal self-review SoD check on AgentUpload"),
    ("FA-REF-112", "CLI preflight validates manual assertion reason code"),
    ("FA-REF-113", "store corruption / attestation payload drift (exit 8)"),
    ("FA-REF-114", "broken document custody chain"),
    ("FA-REF-115", "import run receipt OID list mismatch (exit 8)"),
    ("FA-REF-116", "missing document blob in store (exit 5)"),
    ("FA-REF-117", "erasure blocked by active legal hold"),
    ("FA-REF-118", "release of unknown or already-released legal hold"),
    ("FA-REF-119", "custody transfer by non-custodian principal"),
    ("FA-REF-120", "inclusion proof requested for entry after checkpoint frontier"),
    ("FA-REF-121", "store corruption / accumulator chain drift (exit 8)"),
    ("FA-REF-122", "concurrent checkpoint compare-and-set race"),
    ("FA-REF-123", "concurrent aggregate basis race during checkpoint"),
    ("FA-REF-124", "consistency proof over non-extending accumulator states (exit 8)"),
    ("FA-REF-125", "proof requested at sequence beyond book head"),
    ("FA-REF-126", "library-only unsupported ScopeIndexComplete predicate"),
    ("FA-REF-127", "corrupt checkpoint state recomputation failure (exit 8)"),
    ("FA-REF-128", "bundle inline documents requested without privileged capability"),
    ("FA-REF-129", "bundle exceeds standalone verifier size / balance count limit"),
    ("FA-REF-130", "migration chunk staged into finalized or abandoned MigrationRun"),
    ("FA-REF-131", "migration finalize trial-balance tie-out mismatch"),
    ("FA-REF-132", "migration chunk dated outside declared run periods"),
    ("FA-REF-133", "balance proof over unfinalized staged migration history"),
    ("FA-REF-134", "scratch replay over unsupported non-accounting commit history"),
    ("FA-REF-135", "scratch replay SeqMap verification failure (exit 8)"),
    ("FA-REF-140", "assert-balance value disagrees with journal fold"),
    ("FA-REF-141", "legal hold cites unknown subject vertex"),
    ("FA-REF-142", "unprivileged read of governed document without derived redacted view"),
    ("FA-REF-143", "corrupt redacted view commitment proof (exit 8)"),
    ("FA-REF-144", "sweep under uncorroborated TimeEvidence tick (monotonic_ok = false)"),
    ("FA-REF-146", "proof export exceeds inline transport limit"),
    ("FA-REF-150", "corrupt or tampered report certificate replay (exit 8)"),
    ("FA-REF-152", "statement definition mapping partition / period check"),
    ("FA-REF-153", "internal unwinding panic handler (exit 5)"),
    ("FA-REF-154", "library-only unregistered raw UnitId"),
    ("FA-REF-155", "key file permissions not 0600 (exit 4)"),
    ("FA-REF-156", "unissued capability token file"),
    ("FA-REF-159", "certificate replay under mismatched embedded registry digest (exit 4)"),
    ("FA-REF-160", "library-only unpaired Replacement entry"),
    ("FA-REF-161", "AS ORIGINALLY REPORTED on period with neither issuance nor lock"),
    ("FA-REF-165", "bank statement import predecessor continuity mismatch"),
    ("FA-REF-166", "shared daily capability gross-debit ceiling exceeded"),
    ("FA-REF-167", "store corruption / daily usage cell refold mismatch (exit 8)"),
    ("FA-REF-168", "bank match confirmation ambiguity or occupied line/leg"),
    ("FA-REF-169", "store corruption / bank match confirmation drift (exit 8)"),
    ("FA-REF-171", "production reassigns Bates range of already-produced document"),
    ("FA-REF-172", "statement issuance cites uncertified or mismatched period certificate"),
    ("FA-REF-174", "AS REPORTED IN cites certificate that does not report the period"),
    ("FA-REF-176", "out-of-order RestatementCase lifecycle transition"),
    ("FA-REF-177", "case rehearsal diff certificate missing affected period or closed scenario"),
    ("FA-REF-178", "case-bound entry posted outside Approved RestatementCase"),
    ("FA-REF-179", "case disclosure document lacks independent Reviewed attestation"),
    ("FA-REF-181", "adjustment proposal already booked or passed"),
    ("FA-REF-182", "booked adjustment entry legs or period differ from proposal"),
    ("FA-REF-183", "proposed adjustment dated outside engagement scope_periods"),
    ("FA-REF-186", "concurrent period state change during post (FCW witness)"),
    ("FA-REF-187", "Revision entry in case scenario fails Revises delta shape"),
    ("FA-REF-189", "GQL query aggregates or compares amounts across mixed units"),
    ("FA-REF-192", "external subledger feed lacks independently reviewed detail workpaper"),
    ("FA-REF-193", "PDF text extraction on image/scan without text layer"),
    ("FA-REF-194", "consolidation missing ownership stake, role, or intercompany counterpart"),
    ("FA-REF-195", "dimension value outside valid_from..valid_to window"),
    ("FA-REF-196", "Canon rule static type/unit/balance check failure"),
    ("FA-REF-197", "Restatement entry in case scenario fails Restates delta shape"),
    ("FA-REF-198", "gross native/functional activity exceeds register_capacity"),
    ("FA-REF-199", "retention cut inside active RetentionPolicy floor"),
    ("FA-REF-200", "register checkpoint cadence exceeds active RetentionPolicy floor"),
];

#[test]
fn every_triggerable_fix_executes() {
    let reg = registry().expect("verbs.toml");
    let catalog = fa_registry::refusal_catalog::RefusalCatalog::embedded().expect("catalog");
    for row in &catalog.rows {
        let mut spans: Vec<&str> = row
            .fix
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|s| s.starts_with("fa "))
            .collect();
        if row.fix.starts_with("fa ") {
            spans.push(&row.fix);
        }
        for span in spans {
            let words: Vec<String> = span
                .split_whitespace()
                .skip(1)
                .map(|w| w.trim_end_matches([',', ';', ')']).to_string())
                .collect();
            if words
                .first()
                .is_some_and(|w| !w.starts_with('<') && !w.starts_with('-'))
            {
                assert!(
                    fix_verb(reg, &words).is_some(),
                    "catalog row {} ({}) fix {:?} names an unregistered verb in {:?}",
                    row.code,
                    row.name,
                    row.fix,
                    span
                );
            }
        }
    }
    let mut covered = BTreeSet::new();
    for case in CASES.iter().chain(MORE_CASES) {
        covered.extend(execute(case));
    }
    let documented: BTreeSet<&str> = UNTRIGGERED_WITH_REASON.iter().map(|(c, _)| *c).collect();
    assert_eq!(
        documented.len(),
        UNTRIGGERED_WITH_REASON.len(),
        "duplicate code in UNTRIGGERED_WITH_REASON"
    );
    for code in &covered {
        assert!(
            !documented.contains(code),
            "{code} is both triggered by a case and listed in UNTRIGGERED_WITH_REASON"
        );
    }
    let untriggered: Vec<&str> = catalog
        .rows
        .iter()
        .map(|r| r.code.as_str())
        .filter(|c| !covered.contains(c))
        .collect();
    for code in &untriggered {
        assert!(
            documented.contains(code),
            "catalog code {code} is neither triggered by a case nor documented in UNTRIGGERED_WITH_REASON"
        );
    }
    println!(
        "fix executability: {} of {} catalog codes triggered and their fixes applied: {covered:?}; {} documented non-single-step codes",
        covered.len(),
        catalog.rows.len(),
        untriggered.len(),
    );
}

/// Planted negatives for the harness itself: a fix naming a verb the
/// registry lacks is refused, and a fix that leads back to the same refusal
/// instance fails.
#[test]
fn fix_naming_unknown_verb_fails() {
    let reg = registry().expect("verbs.toml");
    assert!(fix_verb(reg, &argv(&["amalgamate", "--all"])).is_none());
    assert!(fix_verb(reg, &argv(&["period", "list", "--json"])).is_some());
    // An "informational" fix that re-reads is not a repair of a refusal it
    // cannot change: resubmitting the closed-period post after reading the
    // period list returns the same instance, which the harness rejects.
    let closed = &CASES
        .iter()
        .find(|c| c.name == "closed-period")
        .expect("closed-period case");
    let planted = Case {
        name: "planted-same-refusal",
        entities: closed.entities,
        setup: closed.setup,
        base: None,
        prepare: None,
        trigger: closed.trigger,
        steps: &[
            ("FA-REF-010", Apply::Command),
            ("FA-REF-010", Apply::Command),
        ],
    };
    let outcome = std::panic::catch_unwind(|| execute(&planted));
    let message = outcome
        .err()
        .and_then(|e| e.downcast::<String>().ok())
        .map(|s| *s)
        .unwrap_or_default();
    assert!(
        message.contains("led back to the same refusal"),
        "the harness must reject a fix that changes nothing: {message:?}"
    );
}
