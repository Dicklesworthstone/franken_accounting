//! The simulated-agent corpus (bead fa-12x slice 2; plan §15.6, Gate G3).
//!
//! A scripted agent — no model — runs the workflows this build's verbs
//! support the way an agent runs them: it sets a book up by following `fa
//! next`, and when a command fails it follows the `error` event's `fix`.
//! Following a fix means one of: running the `fa …` commands the fix names
//! (placeholders such as `<file>` filled with what the workflow knows),
//! rerunning with the switch the fix names, taking the correction it
//! offers, or amending the intent the way the fix says (the fix must name
//! what the amendment changes). Then the agent retries.
//!
//! An outcome is a `useless_error` when a failure carries no fix, a fix
//! that names nothing the agent can act on, a placeholder the agent cannot
//! fill, or a remedy that does not succeed when followed. The corpus
//! asserts zero useless errors. Every workflow keeps a transcript (each
//! command, its exit, its event, and the error's refusal and fix), written
//! beside its book and printed when the workflow fails.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

const CHART: &str = r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Equity","type":"Equity","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"},{"code":"6100","name":"Bank fees","type":"Expense","unit":"USD"}]}"#;

fn tmp(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("fa-corpus-{}-{name}-{n}", std::process::id()));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("{}: {e}", d.display()),
        }
    }
}

/// An entry intent: one debit and one credit of `amount` USD.
fn entry(date: &str, key: &str, debit: &str, credit: &str, amount: &str) -> String {
    format!(
        r#"{{"effective_date":"{date}","description":"{key}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
    )
}

/// Split a command into words; double quotes group a word.
fn words(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in command.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut word));
                    any = false;
                }
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(word);
    }
    out
}

/// The `fa …` commands a fix names, in order: each backticked command, and
/// a bare command after a colon (`…: fa period open P`).
fn commands_in(fix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, part) in fix.split('`').enumerate() {
        if i % 2 == 1 && part.starts_with("fa ") {
            out.push(part.to_string());
        }
    }
    if out.is_empty()
        && let Some(at) = fix.find(": fa ")
    {
        let rest = &fix[at + 2..];
        let end = rest.find([';', ',', ')']).unwrap_or(rest.len());
        out.push(rest[..end].trim().to_string());
    }
    out
}

/// The correction a usage fix offers: `did you mean `X`?`.
fn correction(fix: &str) -> Option<&str> {
    let rest = &fix[fix.find("did you mean `")? + "did you mean `".len()..];
    Some(&rest[..rest.find('`')?])
}

/// How the agent follows a failure's fix.
enum Follow<'a> {
    /// Run the fix's commands that start with these prefixes, in order.
    Run(&'a [&'a str]),
    /// The fix says to rerun the same command with this switch.
    Rerun(&'a str),
    /// The fix offers a correction the retry takes.
    Correct,
    /// The fix says how to amend the intent: it names each of these.
    Amend(&'a [&'a str]),
}

/// One command's outcome: its exit and its robot lines.
struct Step {
    code: i32,
    lines: Vec<Json>,
}

impl Step {
    fn last(&self) -> Json {
        self.lines.last().cloned().unwrap_or(Json::Null)
    }

    fn event(&self) -> String {
        self.last()
            .get("event")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string()
    }

    fn data(&self) -> Json {
        self.last().get("data").cloned().unwrap_or(Json::Null)
    }

    fn error(&self) -> Option<Json> {
        self.lines
            .iter()
            .find(|l| l.get("event").and_then(Json::as_str) == Some("error"))
            .and_then(|l| l.get("data").cloned())
    }
}

fn text(j: &Json, key: &str) -> String {
    j.get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_string()
}

struct Agent {
    workflow: &'static str,
    dir: PathBuf,
    book: PathBuf,
    vars: BTreeMap<String, String>,
    transcript: String,
    useless: Vec<String>,
    surprises: Vec<String>,
}

impl Agent {
    fn new(workflow: &'static str) -> Self {
        let dir = tmp(workflow);
        let book = dir.join("book");
        Self {
            workflow,
            dir,
            book,
            vars: BTreeMap::new(),
            transcript: String::new(),
            useless: Vec::new(),
            surprises: Vec::new(),
        }
    }

    fn file(&self, name: &str, contents: &str) -> String {
        let p = self.dir.join(name);
        std::fs::write(&p, contents).expect("write a workflow file");
        p.display().to_string()
    }

    fn know(&mut self, placeholder: &str, value: impl Into<String>) {
        self.vars.insert(placeholder.to_string(), value.into());
    }

    fn useless(&mut self, what: String) {
        let _ = writeln!(self.transcript, "  !! useless_error: {what}");
        self.useless.push(what);
    }

    fn surprise(&mut self, what: String) {
        let _ = writeln!(self.transcript, "  !! unexpected: {what}");
        self.surprises.push(what);
    }

    /// Fill a word's placeholders from what the agent knows.
    fn fill(&self, word: &str) -> Result<String, String> {
        let mut out = String::new();
        let mut rest = word;
        while let Some(open) = rest.find('<') {
            let Some(close) = rest[open..].find('>') else {
                break;
            };
            let key = &rest[open..open + close + 1];
            let value = self
                .vars
                .get(key)
                .ok_or_else(|| format!("cannot fill `{key}` in `{word}`"))?;
            out.push_str(&rest[..open]);
            out.push_str(value);
            rest = &rest[open + close + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// A named command as argv (without `fa`), placeholders filled.
    fn expand(&self, command: &str) -> Result<Vec<String>, String> {
        let words = words(command);
        if words.first().map(String::as_str) != Some("fa") {
            return Err(format!("`{command}` is not an fa command"));
        }
        words[1..].iter().map(|w| self.fill(w)).collect()
    }

    /// Run `fa` with this book in robot mode; every line must be on schema.
    fn run(&mut self, argv: &[String]) -> Step {
        let argv: Vec<&String> = argv.iter().filter(|a| *a != "--json").collect();
        let out = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&self.book)
            .args(&argv)
            .arg("--json")
            .env_remove("FA_BOOK")
            .output()
            .expect("run fa");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let reg = registry().expect("verbs.toml");
        let mut lines = Vec::new();
        for line in stdout.lines() {
            if let Err(e) = reg.check_line(line) {
                self.surprise(format!("off-schema line: {e:?}: {line}"));
            }
            lines.push(json::parse(line).unwrap_or(Json::Null));
        }
        let step = Step {
            code: out.status.code().unwrap_or(-1),
            lines,
        };
        let shown: Vec<&str> = argv.iter().map(|a| a.as_str()).collect();
        let _ = writeln!(
            self.transcript,
            "$ fa {} --json\n  -> exit {} `{}`",
            shown.join(" "),
            step.code,
            step.event()
        );
        if let Some(error) = step.error() {
            let _ = writeln!(
                self.transcript,
                "     {} ({}): {}\n     fix: {}",
                text(&error, "class"),
                error
                    .get("refusal_id")
                    .and_then(Json::as_str)
                    .unwrap_or("-"),
                text(&error, "message"),
                text(&error, "fix")
            );
        }
        // What the agent learns from a success: the identities it prints.
        let data = step.data();
        for (key, placeholders) in [
            ("oid", &["<document oid>", "<oid>"][..]),
            ("vid", &["<vid>"][..]),
            ("proposal_digest", &["<proposal_digest>"][..]),
        ] {
            if step.code == 0
                && let Some(v) = data.get(key).and_then(Json::as_str)
            {
                for p in placeholders {
                    self.vars.insert((*p).to_string(), v.to_string());
                }
            }
        }
        step
    }

    fn run_args(&mut self, argv: &[&str]) -> Step {
        let filled: Result<Vec<String>, String> = argv.iter().map(|a| self.fill(a)).collect();
        match filled {
            Ok(argv) => self.run(&argv),
            Err(why) => panic!("{}: the workflow's own command: {why}", self.workflow),
        }
    }

    /// The workflow intends `argv` to succeed with `event`.
    fn ok(&mut self, argv: &[&str], event: &str) -> Step {
        let step = self.run_args(argv);
        self.done(&step, event);
        step
    }

    /// The step must be a success with `event`.
    fn done(&mut self, step: &Step, event: &str) {
        if step.code != 0 || step.event() != event {
            self.surprise(format!(
                "expected `{event}` (exit 0), got `{}` (exit {})",
                step.event(),
                step.code
            ));
        }
    }

    /// `step` failed with `expect` (a refusal id, or the class of a failure
    /// without one): follow its fix as `follow` says, then retry with
    /// `retry` (filled), or, without one, take the last followed command
    /// as the completion. Returns the final step.
    fn follow(
        &mut self,
        step: Step,
        expect: &str,
        follow: Follow<'_>,
        retry: Option<&[&str]>,
        rerun: &[&str],
    ) -> Step {
        let Some(error) = step.error() else {
            self.surprise(format!(
                "expected `{expect}`, got `{}` (exit {})",
                step.event(),
                step.code
            ));
            return step;
        };
        let id = error
            .get("refusal_id")
            .and_then(Json::as_str)
            .map_or_else(|| text(&error, "class"), str::to_string);
        if id != expect {
            self.surprise(format!("expected `{expect}`, got `{id}`"));
            return step;
        }
        let fix = text(&error, "fix");
        if fix.trim().is_empty() {
            self.useless(format!("`{id}` carries no fix"));
            return step;
        }
        let mut last = None;
        let mut retry: Option<Vec<String>> = match retry {
            None => None,
            Some(r) => match r.iter().map(|a| self.fill(a)).collect() {
                Ok(argv) => Some(argv),
                Err(why) => panic!("{}: the workflow's retry: {why}", self.workflow),
            },
        };
        match follow {
            Follow::Run(prefixes) => {
                let named = commands_in(&fix);
                for prefix in prefixes {
                    let Some(command) = named.iter().find(|c| c.starts_with(prefix)) else {
                        self.useless(format!("`{id}`: the fix does not name `{prefix} …`: {fix}"));
                        return step;
                    };
                    let argv = match self.expand(command) {
                        Ok(argv) => argv,
                        Err(why) => {
                            self.useless(format!("`{id}`: {why}"));
                            return step;
                        }
                    };
                    let s = self.run(&argv);
                    if s.code != 0 {
                        self.useless(format!("`{id}`: the fix's `{command}` exits {}", s.code));
                        return s;
                    }
                    last = Some(s);
                }
            }
            Follow::Rerun(switch) => {
                if !fix.contains(&format!("with {switch}")) {
                    self.useless(format!(
                        "`{id}`: the fix does not say to rerun with {switch}: {fix}"
                    ));
                    return step;
                }
                let mut again: Vec<String> = rerun.iter().map(|a| (*a).to_string()).collect();
                again.push(switch.to_string());
                retry = Some(again);
            }
            Follow::Correct => {
                let Some(word) = correction(&fix) else {
                    self.useless(format!("`{id}`: the fix offers no correction: {fix}"));
                    return step;
                };
                let taken = retry.as_ref().is_some_and(|r| {
                    word.split_whitespace()
                        .filter(|w| *w != "fa")
                        .all(|w| r.iter().any(|a| a == w))
                });
                if !taken {
                    self.surprise(format!("the retry does not take the correction `{word}`"));
                    return step;
                }
            }
            Follow::Amend(tokens) => {
                for t in tokens {
                    if !fix.contains(t) {
                        self.useless(format!("`{id}`: the fix does not name `{t}`: {fix}"));
                        return step;
                    }
                }
            }
        }
        let fin = match retry {
            Some(argv) => self.run(&argv),
            None => match last {
                Some(s) => s,
                None => panic!("{}: a follow with nothing to run", self.workflow),
            },
        };
        if fin.code != 0 {
            self.useless(format!(
                "`{id}`: following the fix did not succeed (exit {}, `{}`)",
                fin.code,
                fin.event()
            ));
        }
        fin
    }

    /// Set the book up the way an agent does: create it, then run what
    /// `fa next` names (filling its placeholders) until it names the trial
    /// balance. Returns the open period.
    fn bootstrap(&mut self) -> String {
        self.ok(&["book", "create", "--name", "Corpus Co"], "book_created");
        let chart = self.file("chart.json", CHART);
        self.know("<chart.json>", chart);
        self.know("<N>", "2026");
        for _ in 0..8 {
            let step = self.ok(&["next"], "next_step");
            let command = text(&step.data(), "command");
            if let Some(period) = command
                .strip_prefix("fa tb --period ")
                .and_then(|r| r.split_whitespace().next())
            {
                return period.to_string();
            }
            match self.expand(&command) {
                Ok(argv) => {
                    let s = self.run(&argv);
                    if s.code != 0 {
                        self.useless(format!(
                            "`fa next` named `{command}`, which exits {}",
                            s.code
                        ));
                        break;
                    }
                }
                Err(why) => {
                    self.useless(format!("`fa next`: {why}"));
                    break;
                }
            }
        }
        self.surprise("`fa next` never reached the trial balance".to_string());
        String::new()
    }

    /// Write the transcript and assert the workflow saw no useless error.
    fn finish(self) {
        let path = self.dir.join("transcript.txt");
        let _ = std::fs::write(&path, &self.transcript);
        assert!(
            self.useless.is_empty() && self.surprises.is_empty(),
            "workflow `{}`: useless_error {:?}, unexpected {:?}\n--- transcript ({}) ---\n{}",
            self.workflow,
            self.useless,
            self.surprises,
            path.display(),
            self.transcript
        );
    }
}

/// A fresh book, set up only from what `fa next` says, ends healthy.
#[test]
fn the_agent_sets_a_book_up_by_following_fa_next() {
    let mut a = Agent::new("setup");
    let period = a.bootstrap();
    assert!(period.starts_with("FY2026-"), "{period}");
    let triage = a.ok(&["triage"], "book_triage");
    assert_eq!(text(&triage.data(), "health"), "ok");
    a.ok(&["tb", "--period", &period], "trial_balance");
    a.finish();
}

/// Plan §9: an entry without a document is refused; the fix names the
/// intake; the agent's own upload needs a reviewer; then it posts.
#[test]
fn the_agent_books_an_invoice_and_has_its_upload_reviewed() {
    let mut a = Agent::new("invoice");
    a.bootstrap();
    let rent = a.file(
        "rent.json",
        &entry("2026-01-15", "rent-01", "6000", "1000", "1500.00"),
    );
    let invoice = a.file("invoice.txt", "INVOICE 2026-01: January rent, 1500.00 USD");
    a.know("<entry.json>", &rent);
    a.know("<file>", &invoice);
    a.know("<Kind>", "Invoice");
    a.know("<reviewer>", "controller");
    let cite = ["post", "--intent", rent.as_str(), "--evidence", "<oid>"];
    let s = a.run_args(&["post", "--intent", &rent]);
    let s = a.follow(
        s,
        "FA-REF-080",
        Follow::Run(&["fa document add"]),
        Some(&cite),
        &[],
    );
    // The agent's upload is self-sourced: a reviewer other than the
    // uploader makes it count.
    let s = a.follow(
        s,
        "FA-REF-086",
        Follow::Run(&["fa attest review"]),
        Some(&cite),
        &[],
    );
    a.done(&s, "posted");
    a.finish();
}

/// Plan §9.2: where no document exists, the fix names the plan, the
/// preparer's ManualAssertion over it, and the post of exactly that plan.
#[test]
fn the_agent_books_a_bank_fee_for_which_no_document_exists() {
    let mut a = Agent::new("fee");
    a.bootstrap();
    let fee = a.file(
        "fee.json",
        &entry("2026-01-31", "fee-01", "6100", "1000", "12.00"),
    );
    let plan = a.dir.join("fee.plan").display().to_string();
    a.know("<entry.json>", &fee);
    a.know("<file>", &plan);
    a.know("<code>", "NoDocumentIssued");
    a.know(
        "<text>",
        "the bank charges this fee monthly and shows it only as a statement line",
    );
    let s = a.run_args(&["post", "--intent", &fee]);
    let s = a.follow(
        s,
        "FA-REF-080",
        Follow::Run(&["fa post --intent", "fa attest manual", "fa post --plan"]),
        None,
        &[],
    );
    a.done(&s, "posted");
    a.finish();
}

/// Period law (plan §7): a date in a Future period names the open; a
/// close is gated (FA-REF-007) and names --yes; a date in the closed
/// period names posting in an Open period instead.
#[test]
fn the_agent_meets_the_period_law_and_the_close_gate() {
    let mut a = Agent::new("periods");
    let open = a.bootstrap();
    let invoice = a.file(
        "invoice.txt",
        "INVOICE: office rent, signed by the landlord",
    );
    let s = a.ok(
        &[
            "document",
            "add",
            &invoice,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
        "document",
    );
    let oid = text(&s.data(), "oid");
    // A date in a Future period: the fix opens it.
    let feb = a.file(
        "feb.json",
        &entry("2026-02-10", "rent-02", "6000", "1000", "1500.00"),
    );
    let post_feb = ["post", "--intent", feb.as_str(), "--evidence", oid.as_str()];
    let s = a.run_args(&post_feb);
    let s = a.follow(
        s,
        "FA-REF-010",
        Follow::Run(&["fa period open"]),
        Some(&post_feb),
        &[],
    );
    a.done(&s, "posted");
    // Closing cannot be undone in practice: confirmed only with --yes.
    let close = ["period", "close", open.as_str()];
    let s = a.run_args(&close);
    let s = a.follow(s, "FA-REF-007", Follow::Rerun("--yes"), None, &close);
    a.done(&s, "period_transitioned");
    // The closed period refuses an ordinary entry; the fix says to post in
    // an Open period, which the agent does by redating the intent.
    let late = a.file(
        "late.json",
        &entry("2026-01-20", "late-01", "6000", "1000", "40.00"),
    );
    let redated = a.file(
        "redated.json",
        &entry("2026-02-20", "late-01", "6000", "1000", "40.00"),
    );
    let s = a.run_args(&["post", "--intent", &late, "--evidence", &oid]);
    let s = a.follow(
        s,
        "FA-REF-010",
        Follow::Amend(&["Open period"]),
        Some(&["post", "--intent", &redated, "--evidence", &oid]),
        &[],
    );
    a.done(&s, "posted");
    a.finish();
}

/// Typos: a verb, a subcommand and a flag one edit away are corrected by
/// the fix; the agent takes the correction.
#[test]
fn the_agent_recovers_from_typos_by_taking_the_offered_correction() {
    let mut a = Agent::new("typos");
    let open = a.bootstrap();
    let s = a.run_args(&["tirage"]);
    let s = a.follow(s, "usage", Follow::Correct, Some(&["triage"]), &[]);
    a.done(&s, "book_triage");
    let s = a.run_args(&["period", "lst"]);
    let s = a.follow(s, "usage", Follow::Correct, Some(&["period", "list"]), &[]);
    a.done(&s, "periods");
    let s = a.run_args(&["tb", "--perod", &open]);
    let s = a.follow(
        s,
        "usage",
        Follow::Correct,
        Some(&["tb", "--period", &open]),
        &[],
    );
    a.done(&s, "trial_balance");
    a.finish();
}

/// Derived state: registers that drift from the journal fail verification
/// (exit 8) with a fix that rebuilds them from the journal; then verify is
/// green. A book that does not exist names how to create one.
#[test]
fn the_agent_repairs_drifted_registers_and_finds_a_missing_book() {
    let mut a = Agent::new("drift");
    let open = a.bootstrap();
    let invoice = a.file("invoice.txt", "INVOICE: utilities");
    let s = a.ok(
        &[
            "document",
            "add",
            &invoice,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
        "document",
    );
    let oid = text(&s.data(), "oid");
    let one = a.file(
        "one.json",
        &entry("2026-01-05", "u-1", "6000", "1000", "10.00"),
    );
    let two = a.file(
        "two.json",
        &entry("2026-01-06", "u-2", "6000", "1000", "20.00"),
    );
    a.ok(&["post", "--intent", &one, "--evidence", &oid], "posted");
    a.ok(
        &["registers", "materialize", "--period", &open],
        "registers_materialized",
    );
    a.ok(&["post", "--intent", &two, "--evidence", &oid], "posted");
    let verify = ["verify", "registers", "--period", open.as_str()];
    let s = a.run_args(&verify);
    let s = a.follow(
        s,
        "verification",
        Follow::Run(&["fa registers materialize"]),
        Some(&verify),
        &[],
    );
    a.done(&s, "registers_verified");
    // A book directory with nothing in it.
    let mut lost = Agent::new("missing-book");
    lost.know("<name>", "Recovered Co");
    let s = lost.run_args(&["tb", "--period", "FY2026-P01"]);
    let s = lost.follow(
        s,
        "environment",
        Follow::Run(&["fa book create"]),
        Some(&["book", "info"]),
        &[],
    );
    lost.done(&s, "book");
    lost.finish();
    a.finish();
}
