//! fa-0x0: an issued token's scope caveats (periods, an effective-date
//! bound, a known-at pin) are judged before a read's query is constructed
//! (doctrine 8). An out-of-scope read is refused, FA-REF-011 exit 7, and
//! never answered with a filtered result; an issuer can never mint a grant
//! that drops one of its own caveats.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-read-scope-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    }
}

fn data(event: &Json) -> &Json {
    event.get("data").expect("event data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing string {key}: {value:?}"))
}

fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(value)) => *value,
        _ => panic!("missing integer {key}: {value:?}"),
    }
}

/// A book with Cash and Revenue, March and April open, one cited receipt,
/// and one posting in each month.
struct Fixture {
    dir: PathBuf,
    march: Json,
}

impl Fixture {
    fn new() -> Self {
        let mut fixture = Self {
            dir: temporary(),
            march: Json::Null,
        };
        fixture.ok(&["book", "create", "--name", "Scoped reads"]);
        std::fs::write(
            fixture.dir.join("chart.json"),
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","leaf":true,"unit":"USD"}]}"#,
        )
        .unwrap();
        fixture.ok(&["chart", "import", "chart.json"]);
        fixture.ok(&["period", "create", "--fiscal-year", "2026"]);
        fixture.ok(&["period", "open", "FY2026-P03"]);
        fixture.ok(&["period", "open", "FY2026-P04"]);
        std::fs::write(
            fixture.dir.join("receipt.txt"),
            b"Receipts for March and April",
        )
        .unwrap();
        let document = fixture.ok(&[
            "document",
            "add",
            "receipt.txt",
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ]);
        let evidence = text(data(&document), "oid").to_string();
        fixture.march = fixture.post(&evidence, "march", "2026-03-10", "5.00");
        fixture.post(&evidence, "april", "2026-04-10", "7.00");
        fixture
    }

    fn run(&self, args: &[&str]) -> (i32, Json) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .current_dir(&self.dir)
            .args(["--book", "book"])
            .args(args)
            .arg("--json")
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .output()
            .expect("run fa");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
        fa_cli::verbs::registry()
            .unwrap()
            .check_line(lines[0])
            .unwrap_or_else(|error| panic!("robot schema: {error}\n{stdout}\n{stderr}"));
        (
            output.status.code().unwrap_or(-1),
            json::parse(lines[0]).unwrap(),
        )
    }

    fn ok(&self, args: &[&str]) -> Json {
        let (exit, event) = self.run(args);
        assert_eq!(exit, 0, "args={args:?}\n{event:?}");
        event
    }

    /// Refused for its scope before any query: FA-REF-011, exit 7, naming
    /// the caveat; never an answer.
    fn out_of_scope(&self, args: &[&str], caveat: &str) {
        let (exit, event) = self.run(args);
        assert_eq!(exit, 7, "args={args:?}\n{event:?}");
        assert_eq!(text(&event, "event"), "error", "{event:?}");
        assert_eq!(text(data(&event), "refusal_id"), "FA-REF-011", "{event:?}");
        assert!(
            text(data(&event), "message").contains(caveat),
            "args={args:?}: {event:?}"
        );
    }

    fn post(&self, evidence: &str, key: &str, date: &str, amount: &str) -> Json {
        let name = format!("{key}.json");
        std::fs::write(
            self.dir.join(&name),
            format!(
                r#"{{"idempotency_key":"{key}","effective_date":"{date}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
            ),
        )
        .unwrap();
        self.ok(&["post", "--intent", &name, "--evidence", evidence])
    }

    /// A read-only Human token for `holder`, issued by the embedded owner
    /// with the given scope flags; returns the token file and commitment.
    fn issue(&self, holder: &str, scope: &[&str]) -> (String, String) {
        self.issue_ops(holder, &["read"], scope)
    }

    fn issue_ops(&self, holder: &str, ops: &[&str], scope: &[&str]) -> (String, String) {
        let token = format!("{holder}.token");
        let mut args = vec![
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            "human",
            "--out",
            &token,
            "--grant",
            "issue_capability",
        ];
        for op in ops {
            args.extend(["--op", *op, "--grant", *op]);
        }
        args.extend_from_slice(scope);
        let issued = self.ok(&args);
        let commitment = text(data(&issued), "commitment").to_string();
        (token, commitment)
    }

    fn scope_of(&self, commitment: &str) -> Json {
        let detail = self.ok(&["capability", "show", "--commitment", commitment]);
        data(&detail).get("capability").unwrap().clone()
    }

    fn rows(&self, args: &[&str]) -> Json {
        data(&self.ok(args)).get("rows").unwrap().clone()
    }
}

#[test]
fn scoped_tokens_read_inside_their_caveats_and_are_refused_outside_them() {
    let f = Fixture::new();
    let march_vid = text(data(&f.march), "vid").to_string();
    let pin = number(data(&f.march), "recorded_at");
    let pin_text = pin.to_string();

    // A token confined to March reads March's activity and its explanations.
    let (march, commitment) = f.issue("auditor-march", &["--period", "FY2026-P03"]);
    let scope = f.scope_of(&commitment);
    assert_eq!(
        scope.get("periods"),
        Some(&Json::Arr(vec![json::s("FY2026-P03")])),
        "{scope:?}"
    );
    assert_eq!(scope.get("known_at_most"), Some(&Json::Null));
    assert_eq!(scope.get("effective_through"), Some(&Json::Null));
    let read = f.ok(&[
        "--token",
        &march,
        "tb",
        "--period",
        "FY2026-P03",
        "--activity",
    ]);
    assert_eq!(
        data(&read).get("rows"),
        Some(&f.rows(&["tb", "--period", "FY2026-P03", "--activity"])),
        "the same rows the owner reads, not a filtered subset"
    );
    let served = data(&read).get("served").unwrap();
    assert_eq!(text(served, "mode"), "literal", "{read:?}");
    assert!(text(served, "reason").contains("FA-REF-011"), "{read:?}");
    f.ok(&[
        "--token",
        &march,
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
    ]);
    for args in [
        vec!["explain", "period", "FY2026-P03"],
        vec!["explain", "register", "1000", "--period", "FY2026-P03"],
    ] {
        let mut scoped = vec!["--token", march.as_str()];
        scoped.extend(args);
        f.ok(&scoped);
    }
    // Everything else is refused before its query, never filtered: a stock
    // balance and an as-of balance reach every earlier period, April is
    // outside the scope, open items reach the whole book, and an entry's
    // period (for its display, explanation, lineage or evidence) is unknown
    // until it is read.
    for args in [
        vec!["tb", "--period", "FY2026-P03"],
        vec!["tb", "--period", "FY2026-P04", "--activity"],
        vec!["tb", "--as-of", "2026-03-20"],
        vec!["tb", "--period", "FY2026-P04", "--activity", "--certify"],
        vec!["explain", "balance", "1000", "--period", "FY2026-P04"],
        vec!["explain", "period", "FY2026-P04"],
        vec!["explain", "register", "1000", "--period", "FY2026-P04"],
        vec!["open-items"],
        vec!["entry", "show", &march_vid],
        vec!["explain", "entry", &march_vid],
        vec!["explain", "lineage", &march_vid],
        vec!["explain", "evidence", &march_vid],
    ] {
        let mut scoped = vec!["--token", march.as_str()];
        scoped.extend(args);
        f.out_of_scope(&scoped, "`periods`");
    }

    // A token bounded to effective dates through March 31 reads stock
    // balances through March, never April.
    let (through, _) = f.issue("auditor-q1", &["--effective-through", "2026-03-31"]);
    assert_eq!(
        f.rows(&["--token", &through, "tb", "--period", "FY2026-P03"]),
        f.rows(&["tb", "--period", "FY2026-P03"]),
    );
    f.ok(&["--token", &through, "tb", "--as-of", "2026-03-20"]);
    f.out_of_scope(
        &["--token", &through, "tb", "--period", "FY2026-P04"],
        "`effective`",
    );
    f.out_of_scope(&["--token", &through, "open-items"], "`effective`");

    // A token pinned at the March posting reads that frontier and nothing
    // recorded after it: the April posting is invisible to it, and the head
    // is refused rather than answered as of the pin.
    let (pinned, commitment) = f.issue("auditor-pinned", &["--known-at-most", &pin_text]);
    assert_eq!(
        f.scope_of(&commitment).get("known_at_most"),
        Some(&Json::Int(pin))
    );
    let at_pin = f.rows(&[
        "--token",
        &pinned,
        "tb",
        "--period",
        "FY2026-P04",
        "--as-known-at",
        &pin_text,
    ]);
    assert_eq!(
        at_pin,
        f.rows(&["tb", "--period", "FY2026-P04", "--as-known-at", &pin_text])
    );
    assert_ne!(at_pin, f.rows(&["tb", "--period", "FY2026-P04"]));
    f.ok(&[
        "--token",
        &pinned,
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--as-known-at",
        &pin_text,
    ]);
    f.ok(&[
        "--token",
        &pinned,
        "explain",
        "lineage",
        &march_vid,
        "--as-known-at",
        &pin_text,
    ]);
    // A register explanation also verifies the stored cells at the head,
    // so a pinned token is refused it even at its pin.
    f.out_of_scope(
        &[
            "--token",
            &pinned,
            "explain",
            "register",
            "1000",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &pin_text,
        ],
        "`known_at`",
    );
    for args in [
        vec!["tb", "--period", "FY2026-P04"],
        vec!["entry", "show", &march_vid],
        vec!["open-items"],
        vec!["explain", "period", "FY2026-P03"],
        vec!["explain", "entry", &march_vid],
        vec!["explain", "lineage", &march_vid],
        vec!["explain", "evidence", &march_vid],
        vec!["explain", "register", "1000", "--period", "FY2026-P03"],
    ] {
        let mut scoped = vec!["--token", pinned.as_str()];
        scoped.extend(args);
        f.out_of_scope(&scoped, "`known_at`");
    }
}

#[test]
fn exports_enforce_the_same_scope_as_stock_reads_before_disclosing_or_writing() {
    let f = Fixture::new();
    let pin = number(data(&f.march), "recorded_at");
    let pin_text = pin.to_string();
    let (pinned, _) = f.issue_ops(
        "export-pinned",
        &["read", "produce"],
        &["--known-at-most", &pin_text],
    );
    let selected = [
        "export",
        "csv-gl",
        "--period",
        "FY2026-P04",
        "--as-known-at",
        &pin_text,
    ];
    let mut scoped = vec!["--token", pinned.as_str()];
    scoped.extend(selected);
    let exported = f.ok(&scoped);
    let owner = f.ok(&selected);
    assert_eq!(data(&exported), data(&owner));
    assert_eq!(number(data(&exported), "entries"), 1);
    assert_eq!(number(data(&exported), "known_at"), pin);
    assert_eq!(number(exported.get("coordinate").unwrap(), "known_at"), pin);
    assert_eq!(
        number(
            data(&f.ok(&["export", "csv-gl", "--period", "FY2026-P04"])),
            "entries"
        ),
        2,
        "the historical export must not silently substitute today's journal"
    );

    // Every format shares admission, including ADS's directory output.
    for format in [
        "ads",
        "saft",
        "csv-gl",
        "beancount",
        "hledger",
        "ndjson",
        "xbrl",
    ] {
        let path = format!("refused-{format}");
        f.out_of_scope(
            &[
                "--token",
                &pinned,
                "export",
                format,
                "--as-of",
                "2026-04-30",
                "--out",
                &path,
            ],
            "`known_at`",
        );
        assert!(
            !f.dir.join(path).exists(),
            "refusal creates no export file or directory"
        );
    }
    f.out_of_scope(
        &[
            "--token",
            &pinned,
            "export",
            "csv-gl",
            "--as-of",
            "2026-04-30",
            "--as-known-at",
            &(pin + 1).to_string(),
        ],
        "`known_at`",
    );
    // Resolving an instant currently observes TimeEvidence at HEAD; it is
    // refused before that lookup, even when no tick exists for the instant.
    f.out_of_scope(
        &[
            "--token",
            &pinned,
            "export",
            "csv-gl",
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            "2026-03-31T00:00:00Z",
        ],
        "`known_at`",
    );

    let (march, _) = f.issue_ops(
        "export-march",
        &["read", "produce"],
        &["--period", "FY2026-P03"],
    );
    // --period sets a cumulative boundary, not an activity-only export.
    f.out_of_scope(
        &[
            "--token",
            &march,
            "export",
            "csv-gl",
            "--period",
            "FY2026-P03",
        ],
        "`periods`",
    );
    let (through, _) = f.issue_ops(
        "export-through",
        &["read", "produce"],
        &["--effective-through", "2026-03-31"],
    );
    let bounded = f.ok(&[
        "--token",
        &through,
        "export",
        "csv-gl",
        "--period",
        "FY2026-P03",
    ]);
    assert_eq!(
        data(&bounded),
        data(&f.ok(&["export", "csv-gl", "--as-of", "2026-03-31"]))
    );
    f.out_of_scope(
        &[
            "--token",
            &through,
            "export",
            "csv-gl",
            "--period",
            "FY2026-P04",
        ],
        "`effective`",
    );
    let (account, _) = f.issue_ops(
        "export-account",
        &["read", "produce"],
        &["--account", "1000"],
    );
    f.out_of_scope(
        &[
            "--token",
            &account,
            "export",
            "csv-gl",
            "--period",
            "FY2026-P03",
        ],
        "`accounts`",
    );
    let (reader, _) = f.issue("export-without-produce", &[]);
    f.out_of_scope(
        &[
            "--token",
            &reader,
            "export",
            "csv-gl",
            "--period",
            "FY2026-P03",
        ],
        "`produce`",
    );

    // A later period's existence must not be borrowed from the head while
    // resolving an otherwise authorized historical export.
    f.ok(&["period", "create", "--fiscal-year", "2027"]);
    let (exit, unknown) = f.run(&[
        "--token",
        &pinned,
        "export",
        "csv-gl",
        "--period",
        "FY2027-P01",
        "--as-known-at",
        &pin_text,
    ]);
    assert_eq!(exit, 2, "{unknown:?}");
    assert!(
        text(data(&unknown), "message").contains("no period `FY2027-P01`"),
        "{unknown:?}"
    );
}

#[test]
fn event_reads_and_book_surveys_require_current_authority_at_their_actual_reach() {
    let f = Fixture::new();
    let document = f.ok(&[
        "document",
        "add",
        "receipt.txt",
        "--kind",
        "Receipt",
        "--grade",
        "HumanUpload",
    ]);
    let evidence = text(data(&document), "oid");
    let march = f.ok(&[
        "event",
        "record",
        "--code",
        "EV-MARCH",
        "--kind",
        "sale",
        "--occurred-on",
        "2026-03-15",
        "--description",
        "March event",
        "--evidence",
        evidence,
    ]);
    let pin = number(data(&march), "recorded_at");
    let pin_text = pin.to_string();
    f.ok(&[
        "event",
        "record",
        "--code",
        "EV-APRIL",
        "--kind",
        "sale",
        "--occurred-on",
        "2026-04-15",
        "--description",
        "April event",
        "--evidence",
        evidence,
    ]);
    let (pinned, commitment) = f.issue("events-pinned", &["--known-at-most", &pin_text]);
    for args in [
        vec![
            "event",
            "show",
            "EV-MARCH",
            "--as-known-at",
            pin_text.as_str(),
        ],
        vec!["event", "list", "--as-known-at", pin_text.as_str()],
    ] {
        let mut scoped = vec!["--token", pinned.as_str()];
        scoped.extend_from_slice(&args);
        let read = f.ok(&scoped);
        assert_eq!(data(&read), data(&f.ok(&args)));
        assert_eq!(number(read.get("coordinate").unwrap(), "known_at"), pin);
    }
    assert_eq!(
        number(
            data(&f.ok(&[
                "--token",
                &pinned,
                "event",
                "list",
                "--as-known-at",
                &pin_text
            ])),
            "count"
        ),
        1
    );
    assert_eq!(number(data(&f.ok(&["event", "list"])), "count"), 2);

    for (holder, scope, caveat) in [
        ("survey-period", vec!["--period", "FY2026-P03"], "`periods`"),
        (
            "survey-effective",
            vec!["--effective-through", "2026-03-31"],
            "`effective`",
        ),
        ("survey-account", vec!["--account", "1000"], "`accounts`"),
    ] {
        let (token, _) = f.issue(holder, &scope);
        for args in [
            vec!["event", "show", "EV-MARCH"],
            vec!["event", "show", "EV-UNKNOWN"],
            vec!["event", "list"],
            vec!["triage"],
            vec!["next"],
        ] {
            let mut scoped = vec!["--token", token.as_str()];
            scoped.extend(args);
            f.out_of_scope(&scoped, caveat);
        }
    }
    for args in [
        vec!["event", "show", "EV-MARCH"],
        vec!["event", "list"],
        vec!["event", "list", "--as-known-at", "2026-03-31T00:00:00Z"],
        vec!["triage"],
        vec!["next"],
    ] {
        let mut scoped = vec!["--token", pinned.as_str()];
        scoped.extend(args);
        f.out_of_scope(&scoped, "`known_at`");
    }

    let (reader, _) = f.issue("survey-reader", &[]);
    for verb in ["triage", "next"] {
        assert_eq!(
            data(&f.ok(&["--token", &reader, verb])),
            data(&f.ok(&[verb]))
        );
    }
    let (writer, _) = f.issue_ops("survey-no-read", &["post"], &[]);
    for args in [
        vec!["event", "show", "EV-MARCH"],
        vec!["event", "list"],
        vec!["triage"],
        vec!["next"],
    ] {
        let mut denied = vec!["--token", writer.as_str()];
        denied.extend(args);
        f.out_of_scope(&denied, "`read`");
    }

    // Historical selection never resurrects a token revoked now.
    f.ok(&[
        "capability",
        "revoke",
        "--commitment",
        &commitment,
        "--grant",
        "issue_capability",
        "--yes",
    ]);
    let (exit, refused) = f.run(&[
        "--token",
        &pinned,
        "event",
        "list",
        "--as-known-at",
        &pin_text,
    ]);
    assert_eq!(exit, 7, "{refused:?}");
    assert!(
        text(data(&refused), "message").contains("revoked"),
        "{refused:?}"
    );
}

#[test]
fn a_scoped_issuer_issues_nothing_and_an_unknown_period_is_usage() {
    let f = Fixture::new();
    let (lead, _) = f.issue(
        "lead",
        &["--op", "issue_capability", "--period", "FY2026-P03"],
    );
    let head = |f: &Fixture| {
        number(
            f.ok(&["book", "info"]).get("coordinate").unwrap(),
            "known_at",
        )
    };
    // Issuance is a whole-book act: an issuer confined to March is refused
    // before anything is journaled, whatever scope the grant would carry,
    // so it can never mint a grant wider than itself.
    for (holder, scope) in [
        ("junior-wide", vec![]),
        ("junior", vec!["--period", "FY2026-P03"]),
    ] {
        let token = format!("{holder}.token");
        let mut args = vec![
            "capability",
            "issue",
            "--issuer-token",
            lead.as_str(),
            "--holder",
            holder,
            "--profile",
            "human",
            "--op",
            "read",
            "--out",
            token.as_str(),
        ];
        args.extend(scope);
        let before = head(&f);
        f.out_of_scope(&args, "`periods`");
        assert_eq!(head(&f), before, "nothing is journaled");
        assert!(
            !f.dir.join(&token).exists(),
            "a refused grant writes no token"
        );
    }

    // A period the book does not have is a usage error before issuance.
    let before = head(&f);
    let (exit, unknown) = f.run(&[
        "capability",
        "issue",
        "--holder",
        "auditor-unknown",
        "--profile",
        "human",
        "--op",
        "read",
        "--period",
        "FY2099-P01",
        "--out",
        "unknown.token",
        "--grant",
        "issue_capability",
    ]);
    assert_eq!(exit, 2, "{unknown:?}");
    assert_eq!(head(&f), before);
    assert!(!f.dir.join("unknown.token").exists());
}
