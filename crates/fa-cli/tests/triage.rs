//! `fa triage`, `fa next` and bare `fa` (plan §15.3; bead fa-g8em): the
//! survey reports what the dedicated commands report, `fa next` ranks for
//! the caller's capability, and bare `fa` finds the book and its daemon
//! without opening either.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn temporary(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-triage-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("{}: {error}", path.display()),
        }
    }
}

/// Run the real binary in `cwd` with `envs`; every stdout line must be a
/// registered robot line. Returns the exit and the last line.
fn run_in(cwd: &Path, envs: &[(&str, &str)], args: &[&str]) -> (i32, Json) {
    let registry = fa_cli::verbs::registry().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .current_dir(cwd)
        .args(["--via", "direct", "--json", "--no-color"])
        .args(args)
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .envs(envs.iter().copied())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    for line in stdout.lines() {
        registry
            .check_line(line)
            .unwrap_or_else(|error| panic!("{error}\n{line}"));
    }
    let last = stdout
        .lines()
        .last()
        .unwrap_or_else(|| panic!("{args:?}: no output"));
    (
        output.status.code().unwrap_or(-1),
        json::parse(last).unwrap(),
    )
}

fn data(value: &Json) -> &Json {
    value.get("data").unwrap()
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: {other:?}"),
    }
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

struct Fixture {
    root: PathBuf,
    evidence: String,
}

impl Fixture {
    /// A book with a Saturday posting (a `jet.weekend` finding), drafts, and
    /// a materialized register cache that later postings leave behind.
    fn new(name: &str) -> Self {
        let root = temporary(name);
        let f = Self {
            root,
            evidence: String::new(),
        };
        f.ok(&["book", "create", "--name", "Triage Co"]);
        std::fs::write(
            f.root.join("chart.json"),
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"}]}"#,
        )
        .unwrap();
        f.ok(&["chart", "import", "chart.json"]);
        f.ok(&["period", "create", "--fiscal-year", "2026"]);
        f.ok(&["period", "open", "FY2026-P01"]);
        std::fs::write(
            f.root.join("source.txt"),
            "The supporting document for every fixture posting.",
        )
        .unwrap();
        let document = f.ok(&[
            "document",
            "add",
            "source.txt",
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ]);
        Self {
            evidence: text(data(&document), "oid").to_string(),
            ..f
        }
    }

    fn run(&self, args: &[&str]) -> (i32, Json) {
        let mut full = vec!["--book", "book"];
        full.extend_from_slice(args);
        run_in(&self.root, &[], &full)
    }

    fn ok(&self, args: &[&str]) -> Json {
        let (exit, line) = self.run(args);
        assert_eq!(exit, 0, "{args:?}: {line:?}");
        line
    }

    fn intent(&self, key: &str, day: &str, amount: &str) -> String {
        let name = format!("{key}.json");
        std::fs::write(
            self.root.join(&name),
            format!(
                r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"1000","amount":"{amount}"}},{{"side":"credit","account":"3000","amount":"{amount}"}}]}}"#
            ),
        )
        .unwrap();
        name
    }

    fn post(&self, key: &str, day: &str, amount: &str) {
        let intent = self.intent(key, day, amount);
        self.ok(&["post", "--intent", &intent, "--evidence", &self.evidence]);
    }

    /// Two Saturday postings and a weekday one, two recorded weekend runs
    /// (the first finding of the second acknowledged), two drafts (one
    /// holding an intent), and a register cache one posting behind.
    fn populated(name: &str) -> Self {
        let f = Self::new(name);
        f.post("saturday", "2026-01-10", "100.00 USD");
        f.ok(&["finding", "record", "jet.weekend", "--as", "investigator"]);
        f.post("second-saturday", "2026-01-17", "25.00 USD");
        let run = f.ok(&["finding", "record", "jet.weekend", "--as", "investigator"]);
        let first = rows(data(&run), "finding_ids")[0]
            .as_str()
            .unwrap()
            .to_string();
        f.ok(&[
            "finding",
            "review",
            &first,
            "--action",
            "acknowledge",
            "--note",
            "Reviewed the Saturday source",
            "--as",
            "reviewer",
        ]);
        f.ok(&["draft", "new", "accruals"]);
        f.ok(&["draft", "new", "empty"]);
        let planned = f.intent("drafted", "2026-01-20", "5.00 USD");
        f.ok(&[
            "post",
            "--intent",
            &planned,
            "--evidence",
            &f.evidence,
            "--draft",
            "accruals",
        ]);
        f.ok(&[
            "registers",
            "materialize",
            "--period",
            "FY2026-P01",
            "--yes",
        ]);
        f.post("weekday", "2026-01-21", "7.00 USD");
        f
    }
}

#[test]
fn fields_match_dedicated_commands() {
    let f = Fixture::populated("fields");
    let triage = f.ok(&["triage"]);
    let survey = data(&triage);

    // Findings: every recorded run, and what is still Open in each.
    let runs = f.ok(&["finding", "runs"]);
    let recorded = rows(data(&runs), "runs");
    assert_eq!(recorded.len(), 2);
    assert_eq!(
        number(survey, "finding_runs"),
        number(data(&runs), "total_recorded_runs")
    );
    let mut open: std::collections::BTreeMap<String, i128> = std::collections::BTreeMap::new();
    for run in recorded {
        let certificate = format!("C:{}", text(run, "certificate"));
        let listed = f.ok(&["finding", "list", "--certificate", &certificate]);
        for finding in rows(data(&listed), "findings") {
            if text(finding, "status") == "Open" {
                let severity = text(finding.get("finding").unwrap(), "severity").to_string();
                *open.entry(severity).or_default() += 1;
            }
        }
    }
    let by_severity = survey.get("open_findings_by_severity").unwrap();
    let Json::Obj(cells) = by_severity else {
        panic!("{by_severity:?}");
    };
    // Every severity is listed, zero included (robot objects are written in
    // canonical key order).
    let mut names: Vec<&str> = cells.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["Critical", "High", "Info", "Low", "Medium"]);
    for (severity, count) in cells {
        assert_eq!(
            Some(count),
            Some(&Json::Int(open.get(severity).copied().unwrap_or(0))),
            "{severity}"
        );
    }
    let open_total: i128 = open.values().sum();
    // Three findings were recorded (one, then two); one is acknowledged.
    assert_eq!(open_total, 2, "{open:?}");

    // Drafts: what `fa draft list` shows open, and those holding intents.
    let drafts = f.ok(&["draft", "list"]);
    let listed = rows(data(&drafts), "drafts");
    let open_drafts: Vec<_> = listed
        .iter()
        .filter(|d| text(d, "state") == "open")
        .collect();
    assert_eq!(number(survey, "open_drafts"), open_drafts.len() as i128);
    assert_eq!(
        number(survey, "drafts_awaiting_promotion"),
        open_drafts
            .iter()
            .filter(|d| number(d, "intents") > 0)
            .count() as i128
    );
    assert_eq!(number(survey, "drafts_awaiting_promotion"), 1);

    // Register lag: what `fa verify registers` reports for the period.
    let verified = f.ok(&["verify", "registers", "--period", "FY2026-P01"]);
    let check = &rows(data(&verified), "periods")[0];
    let lag = rows(survey, "register_watermark_lag");
    assert_eq!(lag.len(), 1, "one materialized period");
    assert_eq!(text(&lag[0], "period"), "FY2026-P01");
    assert_eq!(number(&lag[0], "lag_entries"), number(check, "lag_entries"));
    assert_eq!(number(&lag[0], "lag_entries"), 1);
    assert_eq!(text(&lag[0], "cache_status"), text(check, "cache_status"));
    assert_eq!(
        lag[0].get("verified_through"),
        check.get("verified_through")
    );

    // The steps the state calls for name what to look at.
    let actions: Vec<&str> = rows(&triage, "next_actions")
        .iter()
        .map(|a| text(a, "command"))
        .collect();
    assert!(
        actions
            .iter()
            .any(|c| c.starts_with("fa finding list --certificate C:")),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"fa draft show accruals --json"),
        "{actions:?}"
    );
    // Planted negative: a book with nothing to review asks for nothing.
    let quiet = Fixture::new("quiet");
    let survey = quiet.ok(&["triage"]);
    assert_eq!(number(data(&survey), "finding_runs"), 0);
    assert_eq!(number(data(&survey), "drafts_awaiting_promotion"), 0);
    assert!(rows(data(&survey), "register_watermark_lag").is_empty());
    assert!(
        !rows(&survey, "next_actions")
            .iter()
            .any(|a| text(a, "command").starts_with("fa finding")
                || text(a, "command").starts_with("fa draft")),
        "{survey:?}"
    );
}

#[test]
fn next_respects_caller_capability() {
    let f = Fixture::populated("next");
    // The book writes triage can suggest: setup, resolutions and repairs.
    let writes = |command: &str| {
        [
            "fa chart import",
            "fa period ",
            "fa resolve",
            "fa registers ",
            "fa recover ",
        ]
        .iter()
        .any(|write| command.starts_with(write))
    };
    let commands = |line: &Json| -> Vec<String> {
        let mut all: Vec<String> = data(line)
            .get("command")
            .and_then(Json::as_str)
            .map(str::to_string)
            .into_iter()
            .collect();
        all.extend(
            rows(line, "next_actions")
                .iter()
                .map(|a| text(a, "command").to_string()),
        );
        all
    };
    // The owner is offered the book's order, which includes a book write
    // (folding the lagging register cache in).
    let owner = commands(&f.ok(&["next"]));
    assert!(owner.iter().any(|c| writes(c)), "{owner:?}");

    let issue = |holder: &str, profile: &str, ops: &[&str]| -> String {
        let token = format!("{holder}.token");
        let mut args = vec![
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            profile,
            "--out",
            &token,
            "--grant",
            "issue_capability",
        ];
        for op in ops {
            args.extend(["--op", *op, "--grant", *op]);
        }
        f.ok(&args);
        token
    };
    // Planted negative: an Agent token is never offered a write to the book.
    let agent = issue("agent", "agent", &["read", "post"]);
    let offered = commands(&f.ok(&["--token", &agent, "next"]));
    assert!(!offered.is_empty(), "the reads are still offered");
    assert!(
        offered.iter().all(|c| !writes(c)),
        "an Agent is offered a write: {offered:?}"
    );
    // A Human reader runs the reads first; the steps it cannot run follow,
    // naming the ops they need.
    let reader = issue("reader", "human", &["read"]);
    let line = f.ok(&["--token", &reader, "next"]);
    let first = text(data(&line), "command");
    assert!(!writes(first), "{first}");
    let needing: Vec<&Json> = rows(&line, "next_actions")
        .iter()
        .filter(|a| text(a, "why").contains("which this capability does not hold"))
        .collect();
    assert!(!needing.is_empty(), "{line:?}");
    let after_first_needing = rows(&line, "next_actions")
        .iter()
        .skip_while(|a| !text(a, "why").contains("which this capability does not hold"))
        .all(|a| text(a, "why").contains("which this capability does not hold"));
    assert!(after_first_needing, "runnable steps come first: {line:?}");
}

/// fa-g8em: a write a draft can take is offered to an Agent as that draft
/// (plan §15.2): outstanding holds are resolved by a Human with `fa
/// resolve`, and by an Agent through `fa draft new` and `fa draft plan`, for
/// a Human approver to promote. The Agent is still never offered `fa
/// resolve` itself.
#[test]
fn an_agent_is_offered_a_draft_for_the_holds_it_cannot_resolve() {
    let f = Fixture::new("holds");
    std::fs::write(
        f.root.join("hold.json"),
        r#"{"class":"Pending","effective_date":"2026-01-12","idempotency_key":"hold-1","legs":[{"side":"debit","account":"1000","amount":"20.00 USD"},{"side":"credit","account":"3000","amount":"20.00 USD"}]}"#,
    )
    .unwrap();
    f.ok(&["post", "--intent", "hold.json", "--evidence", &f.evidence]);
    let commands = |line: &Json| -> Vec<(String, String)> {
        let mut all: Vec<(String, String)> = Vec::new();
        if let Some(command) = data(line).get("command").and_then(Json::as_str) {
            all.push((command.to_string(), text(data(line), "why").to_string()));
        }
        for action in rows(line, "next_actions") {
            all.push((
                text(action, "command").to_string(),
                text(action, "why").to_string(),
            ));
        }
        all
    };
    let owner = commands(&f.ok(&["next"]));
    assert!(
        owner.iter().any(|(c, _)| c.starts_with("fa resolve")),
        "{owner:?}"
    );
    assert!(
        !owner.iter().any(|(c, _)| c.starts_with("fa draft new")),
        "{owner:?}"
    );

    let issue = |holder: &str, profile: &str, ops: &[&str]| -> String {
        let token = format!("{holder}.token");
        let mut args = vec![
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            profile,
            "--out",
            &token,
            "--grant",
            "issue_capability",
        ];
        for op in ops {
            args.extend(["--op", *op, "--grant", *op]);
        }
        f.ok(&args);
        token
    };
    let agent = issue("agent", "agent", &["read", "post"]);
    let offered = commands(&f.ok(&["--token", &agent, "next"]));
    assert!(
        !offered.iter().any(|(c, _)| c.starts_with("fa resolve")),
        "an Agent is offered a trunk write: {offered:?}"
    );
    let (_, why) = offered
        .iter()
        .find(|(c, _)| c == "fa draft new resolve-holds --json")
        .unwrap_or_else(|| panic!("the draft replaces the resolution: {offered:?}"));
    assert!(why.contains("reserved amounts"), "{why}");
    assert!(
        why.contains("fa draft plan resolve-holds --intent"),
        "{why}"
    );
    assert!(why.contains("Human approver"), "{why}");

    // A Human holding post resolves on trunk itself: no draft is offered.
    let human = issue("preparer", "human", &["read", "post"]);
    let offered = commands(&f.ok(&["--token", &human, "next"]));
    assert!(
        offered.iter().any(|(c, _)| c.starts_with("fa resolve")),
        "{offered:?}"
    );
    assert!(
        !offered.iter().any(|(c, _)| c.starts_with("fa draft new")),
        "{offered:?}"
    );
}

#[test]
fn bare_fa_detects_book_and_daemon() {
    let f = Fixture::new("bare");
    let book = f.root.join("book");
    let elsewhere = temporary("elsewhere");

    // No book named and none here.
    let (exit, line) = run_in(&elsewhere, &[], &[]);
    assert_eq!(exit, 0);
    assert_eq!(text(&line, "event"), "triage");
    assert_eq!(data(&line).get("book"), Some(&Json::Null));
    assert_eq!(data(&line).get("daemon"), Some(&Json::Null));
    assert!(text(data(&line), "text").contains("no book"), "{line:?}");
    assert!(text(data(&line), "text").contains("fa book create"));

    // Named by --book, by FA_BOOK, and found in the working directory.
    let book_text = book.display().to_string();
    for (cwd, envs, args) in [
        (&elsewhere, vec![], vec!["--book", book_text.as_str()]),
        (&elsewhere, vec![("FA_BOOK", book_text.as_str())], vec![]),
        (&book, vec![], vec![]),
    ] {
        let (exit, line) = run_in(cwd, &envs, &args);
        assert_eq!(exit, 0, "{line:?}");
        let found = text(data(&line), "book");
        assert!(
            Path::new(found).canonicalize().unwrap() == book.canonicalize().unwrap(),
            "{found} is not {book_text}"
        );
        assert_eq!(text(data(&line), "daemon"), "absent", "{line:?}");
        let help = text(data(&line), "text");
        assert!(
            help.contains(&format!("fa triage --book {found} --json")),
            "{help}"
        );
        assert!(help.contains("no fad serves it"), "{help}");
    }

    // A held lease whose socket nobody answers.
    let registry = fa_cli::verbs::registry().unwrap();
    let lease = fa_cli::lease::Lease::acquire(
        &book,
        &registry.daemon.lease,
        &format!("fad pid={}", std::process::id()),
    )
    .expect("lease");
    let (_, line) = run_in(&elsewhere, &[], &["--book", &book_text]);
    assert_eq!(text(data(&line), "daemon"), "not answering", "{line:?}");
    assert!(text(data(&line), "text").contains("fad status --book"));
    drop(lease);

    // Planted negative: a directory that is not a book is named, not opened.
    let (exit, line) = run_in(&elsewhere, &[], &["--book", elsewhere.to_str().unwrap()]);
    assert_eq!(exit, 0);
    assert_eq!(data(&line).get("daemon"), Some(&Json::Null));
    assert!(
        text(data(&line), "text").contains("is not a book"),
        "{line:?}"
    );
    assert!(
        std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
        "bare fa wrote nothing"
    );
}
