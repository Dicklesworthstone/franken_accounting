//! The plan Appendix D refusal object on the real `fa` binary (bead
//! fa-6his): a catalog refusal's `error` event carries `refusal` with the
//! instance id, `where`, `why`, a structured `fix` and the docs command, and
//! every `fa …` command the refusal catalog's fixes name parses against
//! `verbs.toml`.

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
            "fa-refusal-object-{}-{name}-{n}",
            std::process::id()
        ));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("create {}: {e}", d.display()),
        }
    }
}

/// Run `fa --book <book> <args>`; robot lines are checked against the
/// registry's schema.
fn fa(book: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if args.contains(&"--json") {
        let reg = registry().expect("verbs.toml");
        for line in stdout.lines() {
            if let Err(e) = reg.check_line(line) {
                panic!("args={args:?}: {e}");
            }
        }
    }
    (out.status.code().unwrap_or(-1), stdout)
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).expect("write fixture");
    p.display().to_string()
}

/// A book with a summary `100` over three cash-like leaves and an expense,
/// FY2026 created, March open, and one source document to cite.
fn book(name: &str) -> (PathBuf, PathBuf, String) {
    let dir = tmp(name);
    let book = dir.join("book");
    assert_eq!(fa(&book, &["book", "create", "--name", "Refusal Co"]).0, 0);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
            {"code":"100","name":"Cash and equivalents","type":"Asset","leaf":false,"unit":"USD"},
            {"code":"1100","name":"Money market fund","type":"Asset","leaf":true,"unit":"USD","parent":"100"},
            {"code":"1010","name":"Petty cash","type":"Asset","leaf":true,"unit":"USD","parent":"100"},
            {"code":"1000","name":"Operating cash","type":"Asset","leaf":true,"unit":"USD","parent":"100"},
            {"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(fa(&book, &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(&book, &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(fa(&book, &["period", "open", "FY2026-P03"]).0, 0);
    let source = write(&dir, "source.txt", "INVOICE (refusal object fixture)");
    let (code, out) = fa(
        &book,
        &[
            "document",
            "add",
            &source,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let doc = json::parse(out.lines().last().expect("a line")).expect("robot JSON");
    let oid = doc
        .get("data")
        .and_then(|d| d.get("oid"))
        .and_then(Json::as_str)
        .expect("document oid")
        .to_string();
    (dir, book, oid)
}

/// Post `legs` on `date` and return the exit and the `error` event's data.
fn refused_post(
    dir: &Path,
    book: &Path,
    ev: &str,
    key: &str,
    date: &str,
    legs: &str,
) -> (i32, Json) {
    let intent = write(
        dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"{date}","description":"{key}","idempotency_key":"{key}","legs":{legs}}}"#
        ),
    );
    let (code, out) = fa(
        book,
        &["post", "--intent", &intent, "--evidence", ev, "--json"],
    );
    let line = out
        .lines()
        .map(|l| json::parse(l).expect("robot JSON"))
        .find(|l| l.get("event").and_then(Json::as_str) == Some("error"))
        .unwrap_or_else(|| panic!("no error event: {out}"));
    println!("{key}: {}", line.render());
    (code, line.get("data").cloned().expect("data"))
}

fn text<'a>(v: &'a Json, path: &[&str]) -> &'a str {
    let mut at = v;
    for k in path {
        at = at
            .get(k)
            .unwrap_or_else(|| panic!("missing {path:?} in {}", v.render()));
    }
    at.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string in {}", v.render()))
}

fn strings(v: &Json, path: &[&str]) -> Vec<String> {
    let mut at = v;
    for k in path {
        at = at
            .get(k)
            .unwrap_or_else(|| panic!("missing {path:?} in {}", v.render()));
    }
    at.as_arr()
        .unwrap_or_else(|| panic!("{path:?} is not an array in {}", v.render()))
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

/// The instance id is the code, `:`, and 16 lowercase hex digits.
fn assert_instance(refusal: &Json, code: &str) -> String {
    let id = text(refusal, &["id"]);
    let hex = id
        .strip_prefix(&format!("{code}:"))
        .unwrap_or_else(|| panic!("{id} does not carry {code}"));
    assert_eq!(hex.len(), 16, "{id}");
    assert!(
        hex.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "{id}"
    );
    assert_eq!(text(refusal, &["code"]), code);
    assert_eq!(
        text(refusal, &["docs"]),
        format!("fa explain refusal {code}")
    );
    id.to_string()
}

#[test]
fn unbalanced_has_structured_where_why_fix() {
    let (dir, book, ev) = book("unbalanced");
    let (code, data) = refused_post(
        &dir,
        &book,
        &ev,
        "unbalanced",
        "2026-03-10",
        r#"[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"9.00 USD"}]"#,
    );
    assert_eq!(code, 3);
    assert_eq!(
        text(&data, &["refusal_id"]),
        "FA-REF-001",
        "the flat code stays"
    );
    let refusal = data.get("refusal").expect("refusal");
    assert_instance(refusal, "FA-REF-001");
    assert_eq!(text(refusal, &["where", "unit"]), "USD");
    assert_eq!(text(refusal, &["where", "debits"]), "10.00 USD");
    assert_eq!(text(refusal, &["where", "credits"]), "9.00 USD");
    assert_eq!(text(refusal, &["where", "short_side"]), "credit");
    assert_eq!(text(refusal, &["where", "gap"]), "1.00 USD");
    assert_eq!(text(refusal, &["why", "law"]), "FA-INV-01.per-unit");
    assert!(
        text(refusal, &["fix", "text"]).contains("add a credit leg of 1.00 USD"),
        "{}",
        refusal.render()
    );
    assert!(
        text(refusal, &["what_failed"]).contains("debits 10.00 USD ≠ credits 9.00 USD"),
        "amounts render at the unit's scale: {}",
        refusal.render()
    );
    // The kernel names the gap; it never posts a balancing leg.
    let (code, tb) = fa(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(code, 0, "{tb}");
    assert!(!tb.contains("\"6000\""), "nothing posted: {tb}");
}

#[test]
fn summary_account_names_the_nearest_leaf_and_the_field_to_change() {
    let (dir, book, ev) = book("summary");
    let (code, data) = refused_post(
        &dir,
        &book,
        &ev,
        "to-summary",
        "2026-03-10",
        r#"[{"side":"debit","account":"6000","amount":"5.00 USD"},{"side":"credit","account":"100","amount":"5.00 USD"}]"#,
    );
    assert_eq!(code, 3);
    let refusal = data.get("refusal").expect("refusal");
    let id = assert_instance(refusal, "FA-REF-002");
    assert_eq!(
        refusal.get("where").and_then(|w| w.get("leg")),
        Some(&Json::Int(1)),
        "{}",
        refusal.render()
    );
    assert_eq!(text(refusal, &["where", "account"]), "100");
    assert_eq!(text(refusal, &["why", "law"]), "FA-INV-01.leaf-only");
    assert_eq!(
        text(refusal, &["fix", "or_field_change", "field"]),
        "legs[1].account"
    );
    // Nearest by name: the leaves sharing "cash" with the summary's name
    // first (in code order), then the rest.
    assert_eq!(
        strings(refusal, &["fix", "or_field_change", "one_of"]),
        ["1000", "1010", "1100"]
    );
    assert!(
        text(refusal, &["fix", "text"]).contains("`1000` is the nearest by name"),
        "{}",
        refusal.render()
    );
    assert_eq!(
        text(refusal, &["fix", "command"]),
        "fa chart list --json",
        "{}",
        refusal.render()
    );
    assert_eq!(
        strings(refusal, &["fix", "argv"]),
        ["chart", "list", "--json"]
    );

    // The instance id expands its code from the catalog and is echoed back.
    let (code, out) = fa(&book, &["explain", "refusal", &id, "--json"]);
    assert_eq!(code, 0, "{out}");
    let explained = json::parse(out.lines().last().expect("a line")).expect("robot JSON");
    let explained = explained.get("data").expect("data");
    assert_eq!(text(explained, &["id"]), "FA-REF-002");
    assert_eq!(text(explained, &["instance"]), id);
    let (code, out) = fa(
        &book,
        &["explain", "refusal", "FA-REF-002:nothex", "--json"],
    );
    assert_eq!(code, 2, "a malformed instance id is a usage error: {out}");
}

#[test]
fn closed_period_cites_the_matrix_cell() {
    let (dir, book, ev) = book("closed");
    let march = "FY2026-P03";
    assert_eq!(fa(&book, &["period", "soft-close", march]).0, 0);
    let (code, out) = fa(
        &book,
        &[
            "period",
            "close",
            march,
            "--reason",
            "Scheduled",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, data) = refused_post(
        &dir,
        &book,
        &ev,
        "late",
        "2026-03-21",
        r#"[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]"#,
    );
    assert_eq!(code, 7);
    let refusal = data.get("refusal").expect("refusal");
    assert_instance(refusal, "FA-REF-010");
    assert_eq!(text(refusal, &["where", "period"]), march);
    assert_eq!(text(refusal, &["where", "effective_date"]), "2026-03-21");
    assert_eq!(text(refusal, &["why", "matrix", "state"]), "Closed");
    assert_eq!(text(refusal, &["why", "matrix", "class"]), "Original");
    assert_eq!(
        text(refusal, &["fix", "command"]),
        "fa period list --json",
        "{}",
        refusal.render()
    );
}

#[test]
fn a_unit_the_account_refuses_names_the_admitted_unit() {
    let (dir, book, ev) = book("unit-policy");
    let (code, data) = refused_post(
        &dir,
        &book,
        &ev,
        "in-euros",
        "2026-03-10",
        r#"[{"side":"debit","account":"6000","amount":"5.00 EUR"},{"side":"credit","account":"1000","amount":"5.00 EUR"}]"#,
    );
    assert_eq!(code, 3);
    let refusal = data.get("refusal").expect("refusal");
    assert_instance(refusal, "FA-REF-003");
    assert_eq!(
        refusal.get("where").and_then(|w| w.get("leg")),
        Some(&Json::Int(0)),
        "{}",
        refusal.render()
    );
    assert_eq!(text(refusal, &["where", "account"]), "6000");
    assert_eq!(text(refusal, &["where", "unit"]), "EUR");
    assert_eq!(text(refusal, &["why", "law"]), "FA-INV-01.unit-policy");
    assert_eq!(
        text(refusal, &["fix", "or_field_change", "field"]),
        "legs[0].amount.unit"
    );
    assert_eq!(
        strings(refusal, &["fix", "or_field_change", "one_of"]),
        ["USD"]
    );
    assert!(
        text(refusal, &["fix", "text"]).contains("post in the account's unit (USD)"),
        "the policy is named, not debug-printed: {}",
        refusal.render()
    );
}

/// A failure that is not a catalog refusal carries `refusal: null`.
#[test]
fn a_usage_error_has_no_refusal_object() {
    let dir = tmp("usage");
    let (code, out) = fa(&dir.join("book"), &["tb", "--no-such-flag", "--json"]);
    assert_eq!(code, 2, "{out}");
    let line = json::parse(out.lines().last().expect("a line")).expect("robot JSON");
    assert_eq!(
        line.get("data").and_then(|d| d.get("refusal")),
        Some(&Json::Null)
    );
}

/// Every command a refusal catalog fix names in backticks is a real `fa`
/// command: its verb (or alias), subcommand and flags parse against
/// `verbs.toml`. A placeholder slot (`<FY>`, `{account}`) is a template and
/// is skipped, so this binds only the concrete spellings agents copy.
#[test]
fn fix_argv_parses_against_verbs() {
    let catalog = fa_registry::refusal_catalog::RefusalCatalog::embedded().expect("catalog");
    let reg = registry().expect("verbs.toml");
    let mut checked = 0;
    let mut bad = Vec::new();
    for row in &catalog.rows {
        for span in row.fix.split('`').skip(1).step_by(2) {
            if !span.starts_with("fa ") || span.contains(['<', '>', '{', '}', '…', '[', ']', '|'])
            {
                continue;
            }
            checked += 1;
            if let Err(why) = parses(reg, span) {
                bad.push(format!("{}: `{span}`: {why}", row.code));
            }
        }
    }
    println!("checked {checked} concrete fix commands");
    assert!(checked > 0, "the catalog names concrete commands");
    assert!(
        bad.is_empty(),
        "catalog fixes that do not parse:\n{}",
        bad.join("\n")
    );
    // Planted negatives: the same check refuses an unknown verb, an unknown
    // subcommand and a flag the verb does not take.
    for planted in [
        "fa consolidate --all",
        "fa chart frobnicate",
        "fa tb --not-a-flag",
    ] {
        assert!(parses(reg, planted).is_err(), "{planted}");
    }
}

/// Whether `line` parses as one `fa` command against the registry.
fn parses(reg: &fa_cli::verbs::Registry, line: &str) -> Result<(), String> {
    let tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    let rest = &tokens[1..];
    let parsed =
        fa_cli::args::parse(rest, &reg.value_flags(), &reg.switches()).map_err(|e| e.message)?;
    let word = parsed.positional.first().ok_or("no verb")?;
    let mut positional = match reg.alias(word) {
        Some(a) => a.expands.clone(),
        None => vec![word.clone()],
    };
    positional.extend(parsed.positional.iter().skip(1).cloned());
    let verb = reg
        .verb(&positional[0])
        .ok_or_else(|| format!("unknown verb {}", positional[0]))?;
    if !verb.subcommands.is_empty() {
        match positional.get(1) {
            Some(sub) if verb.subcommands.contains(sub) => {}
            None if verb.default_subcommand.is_some() => {}
            other => return Err(format!("`{}` has no subcommand {other:?}", verb.name)),
        }
    }
    for flag in parsed.flags.keys().chain(&parsed.switches) {
        let global = reg.global.flags.contains(flag) || reg.global.switches.contains(flag);
        if !global && !verb.accepts(flag) {
            return Err(format!("{flag} is not a flag of `fa {}`", verb.name));
        }
    }
    Ok(())
}
