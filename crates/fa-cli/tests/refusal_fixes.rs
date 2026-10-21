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
/// USD expense and an any-currency expense; FY2026 with March and April
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
            {"code":"6050","name":"Rent abroad","type":"Expense","unit":"any-currency"}]}"#,
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
    Inform,
    Judgment(&'static str),
}

struct Case {
    name: &'static str,
    entities: &'static [&'static str],
    /// Commands run on the fixture before the trigger.
    setup: &'static [&'static [&'static str]],
    trigger: fn(&str) -> Request,
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

/// Write `value` into `field` (`legs[N].name` or a top-level name) of the
/// intent.
fn set_field(intent: &mut Json, field: &str, value: &str) {
    let Json::Obj(top) = intent else {
        panic!("intent is not an object");
    };
    if let Some(rest) = field.strip_prefix("legs[") {
        let (index, key) = rest.split_once("].").expect("legs[N].field");
        let index: usize = index.parse().expect("leg index");
        let legs = top
            .iter_mut()
            .find(|(k, _)| k == "legs")
            .map(|(_, v)| v)
            .expect("legs");
        let Json::Arr(legs) = legs else {
            panic!("legs is not an array");
        };
        let Json::Obj(leg) = &mut legs[index] else {
            panic!("leg is not an object");
        };
        match leg.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = Json::Str(value.into()),
            None => leg.push((key.to_string(), Json::Str(value.into()))),
        }
    } else {
        match top.iter_mut().find(|(k, _)| k == field) {
            Some(slot) => slot.1 = Json::Str(value.into()),
            None => top.push((field.to_string(), Json::Str(value.into()))),
        }
    }
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
    let mut req = (case.trigger)(&ev);
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
                let Request::Post { intent, .. } = &mut req else {
                    panic!("{}: a field change applies to an intent", case.name);
                };
                set_field(intent, field, &value);
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

#[test]
fn every_triggerable_fix_executes() {
    let mut covered = BTreeSet::new();
    for case in CASES {
        covered.extend(execute(case));
    }
    let catalog = fa_registry::refusal_catalog::RefusalCatalog::embedded().expect("catalog");
    let untriggered: Vec<&str> = catalog
        .rows
        .iter()
        .map(|r| r.code.as_str())
        .filter(|c| !covered.contains(c))
        .collect();
    println!(
        "fix executability: {} of {} catalog codes triggered and their fixes applied: {covered:?}; not yet triggered by any case: {}",
        covered.len(),
        catalog.rows.len(),
        untriggered.join(" ")
    );
}

/// Planted negatives for the harness itself: a fix naming a verb the
/// registry lacks is refused, and a fix that leads back to the same refusal
/// instance fails.
#[test]
fn fix_naming_unknown_verb_fails() {
    let reg = registry().expect("verbs.toml");
    assert!(fix_verb(reg, &argv(&["consolidate", "--all"])).is_none());
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
