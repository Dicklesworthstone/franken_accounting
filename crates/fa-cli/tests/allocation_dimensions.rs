//! Cost-center allocation through separate CLI processes and reopened books.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .expect(key)
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).as_str().expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match get(value, key) {
        Json::Int(value) => *value,
        value => panic!("{key} must be an integer: {value:?}"),
    }
}

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .output()
        .expect("run allocation CLI");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("args={args:?}: {error}\n{stdout}\n{stderr}"));
    let event = json::parse(lines[0]).unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        text(&event, "event") == "error",
        code != 0,
        "{stdout}\n{stderr}"
    );
    (code, event)
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, event) = run(book, args);
    assert_eq!(code, 0, "args={args:?}: {}", event.render());
    event
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.display().to_string()
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    dimensions: BTreeMap<String, (i128, String)>,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir().join(format!(
                "fa-allocation-dimensions-{}-{n}",
                std::process::id()
            ));
            match std::fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create {}: {error}", candidate.display()),
            }
        };
        let book = dir.join("book");
        ok(
            &book,
            &["book", "create", "--name", "Department allocation"],
        );
        let chart = write(
            &dir,
            "chart.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6100","name":"Rent","type":"Expense","unit":"USD"}]}"#,
        );
        ok(&book, &["chart", "import", &chart]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P03"]);
        let mut dimensions = BTreeMap::new();
        for name in ["SHARED", "ENG", "SALES"] {
            let recorded = ok(
                &book,
                &["dimension", "add", "cost_center", name, "--name", name],
            );
            let value = get(&recorded, "value");
            dimensions.insert(
                name.to_string(),
                (
                    integer(value, "dimension_id"),
                    text(value, "vid").to_string(),
                ),
            );
        }
        ok(&book, &["dimension", "require", "cost_center", "6100"]);
        let bill = write(&dir, "rent.txt", "March rent bill: 100.00 USD");
        let evidence = ok(
            &book,
            &[
                "document",
                "add",
                &bill,
                "--kind",
                "Invoice",
                "--grade",
                "HumanUpload",
            ],
        );
        let seed = write(
            &dir,
            "seed.json",
            r#"{"effective_date":"2026-03-05","idempotency_key":"shared-rent","legs":[{"side":"debit","account":"6100","amount":"100.00 USD","dimensions":{"cost_center":"SHARED"}},{"side":"credit","account":"1000","amount":"100.00 USD"}]}"#,
        );
        ok(
            &book,
            &[
                "post",
                "--intent",
                &seed,
                "--evidence",
                text(&evidence, "oid"),
            ],
        );
        Self {
            dir,
            book,
            dimensions,
        }
    }

    fn head(&self) -> i128 {
        integer(
            get(&ok(&self.book, &["book", "info"]), "coordinate"),
            "known_at",
        )
    }

    fn allocation(&self, key: &str, source: &str, method: &str, targets: &str) -> String {
        write(
            &self.dir,
            &format!("{key}.json"),
            format!(
                r#"{{"source":"6100","dimensions":{{"cost_center":"SHARED"}},"effective_date":"2026-03-10","idempotency_key":"{key}","description":"Allocate shared rent",{source},{method},"targets":{targets}}}"#
            ),
        )
    }

    fn review(&self, key: &str, intent: &str) -> (Json, String) {
        let path = self.dir.join(format!("{key}.review")).display().to_string();
        let before = self.head();
        let event = ok(
            &self.book,
            &["allocate", "--intent", intent, "--review-out", &path],
        );
        assert_eq!(self.head(), before, "review must publish nothing");
        (event, path)
    }

    fn import_driver(&self, review_path: &str, key: &str) {
        let review = fa::AllocationReview::decode(&std::fs::read(review_path).unwrap()).unwrap();
        let path = write(
            &self.dir,
            &format!("{key}.basis"),
            review.posting().basis_bytes().unwrap(),
        );
        ok(
            &self.book,
            &[
                "document",
                "add",
                &path,
                "--kind",
                "Workpaper",
                "--grade",
                "HumanUpload",
            ],
        );
    }

    fn assert_dimensions(&self, leg: &Json, value: &str) {
        let dimensions = get(leg, "dimensions").as_arr().unwrap();
        assert_eq!(dimensions.len(), 1);
        assert_eq!(
            integer(&dimensions[0], "dimension"),
            self.dimensions[value].0
        );
        assert_eq!(text(&dimensions[0], "value"), self.dimensions[value].1);
    }

    fn assert_cell(&self, value: &str, debits: &str, credits: &str) {
        let selector = format!("cost_center={value}");
        let tb = ok(
            &self.book,
            &["tb", "--period", "FY2026-P03", "--dimension", &selector],
        );
        let row = get(&tb, "rows")
            .as_arr()
            .unwrap()
            .iter()
            .find(|row| text(row, "code") == "6100")
            .expect("rent account in selected dimension");
        assert_eq!(text(row, "debits"), debits);
        assert_eq!(text(row, "credits"), credits);
    }
}

const TARGETS: &str = r#"[{"account":"6100","weight":3,"dimensions":{"cost_center":"ENG"}},{"account":"6100","weight":2,"dimensions":{"cost_center":"SALES"}}]"#;

#[test]
fn dimensional_allocation_review_approval_plan_and_exact_retry_preserve_destination_cells() {
    let f = Fixture::new();
    let intent = f.allocation(
        "rent-explicit",
        r#""total":"100.00 USD","source_side":"credit""#,
        r#""method":"largest_remainder""#,
        TARGETS,
    );
    let (review, path) = f.review("explicit", &intent);
    let legs = get(&review, "legs").as_arr().unwrap();
    assert_eq!(legs.len(), 3);
    for (leg, value, amount) in [
        (&legs[0], "SHARED", "100.00 USD"),
        (&legs[1], "ENG", "60.00 USD"),
        (&legs[2], "SALES", "40.00 USD"),
    ] {
        assert_eq!(text(leg, "account"), "6100");
        assert_eq!(text(leg, "amount"), amount);
        f.assert_dimensions(leg, value);
    }
    let approved = ok(
        &f.book,
        &[
            "allocate",
            "approve",
            "--review",
            &path,
            "--digest",
            text(&review, "review_digest"),
            "--as",
            "controller",
        ],
    );

    // Preserve the original key and private-field seals, changing only the
    // destination dimensions and their necessarily changed driver binding.
    let original = fa::AllocationReview::decode(&std::fs::read(&path).unwrap()).unwrap();
    let mut posting = original.posting().clone();
    let first = posting.target_cells[0].dimensions.clone();
    posting.target_cells[0].dimensions = posting.target_cells[1].dimensions.clone();
    posting.target_cells[1].dimensions = first;
    for (target, cell) in posting
        .request
        .targets
        .iter_mut()
        .zip(&posting.target_cells)
    {
        target.id = cell.identity().unwrap();
    }
    let mut template = original.proposal().clone();
    let old_driver = original
        .posting()
        .driver_evidence(template.book_id)
        .unwrap();
    template.evidence.retain(|evidence| *evidence != old_driver);
    template
        .evidence
        .push(posting.driver_evidence(template.book_id).unwrap());
    template.evidence.sort_unstable();
    template.legs.clear();
    template.unit_totals.clear();
    template.extensions.clear();
    let changed = fa::AllocationReview::new(posting, template).unwrap();
    assert_eq!(
        changed.proposal().description,
        original.proposal().description
    );
    assert_eq!(
        changed.proposal().idempotency_key,
        original.proposal().idempotency_key
    );
    assert_ne!(
        changed.proposal_digest().unwrap(),
        original.proposal_digest().unwrap()
    );
    let changed_path = write(&f.dir, "swapped.review", changed.canonical_bytes().unwrap());
    let changed_digest = hex(&changed.digest().unwrap());
    f.import_driver(&changed_path, "swapped");
    let before = f.head();
    let (code, refusal) = run(
        &f.book,
        &[
            "allocate",
            "--review",
            &changed_path,
            "--digest",
            &changed_digest,
            "--approval",
            text(&approved, "approval_vid"),
            "--dry-run",
        ],
    );
    assert_ne!(code, 0, "{}", refusal.render());
    assert_eq!(f.head(), before);
    f.assert_cell("SHARED", "100.00 USD", "0.00 USD");

    let plan_path = f.dir.join("allocation.plan").display().to_string();
    let plan = ok(
        &f.book,
        &[
            "allocate",
            "--review",
            &path,
            "--digest",
            text(&review, "review_digest"),
            "--approval",
            text(&approved, "approval_vid"),
            "--dry-run",
            "--plan-out",
            &plan_path,
        ],
    );
    assert!(
        get(&plan, "next_actions")
            .render()
            .contains("--grant 'read'"),
        "allocation commit guidance must preserve its read/post capability"
    );
    let planned_legs = get(&plan, "legs").as_arr().unwrap();
    f.assert_dimensions(&planned_legs[1], "ENG");
    f.assert_dimensions(&planned_legs[2], "SALES");
    let before = f.head();
    let committed = ok(
        &f.book,
        &["commit", "--plan", &plan_path, "--grant", "read"],
    );
    assert_eq!(f.head(), before + 1);
    let retry = ok(
        &f.book,
        &["commit", "--plan", &plan_path, "--grant", "read"],
    );
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(text(&retry, "vid"), text(&committed, "vid"));
    assert_eq!(f.head(), before + 1);
    f.assert_cell("SHARED", "100.00 USD", "100.00 USD");
    f.assert_cell("ENG", "60.00 USD", "0.00 USD");
    f.assert_cell("SALES", "40.00 USD", "0.00 USD");
}

#[test]
fn balance_derived_allocation_keeps_source_and_target_dimension_cells_separate() {
    let f = Fixture::new();
    let intent = f.allocation(
        "rent-balance",
        r#""source_period":"FY2026-P03","unit":"USD""#,
        r#""method":"largest_remainder""#,
        TARGETS,
    );
    let (review, path) = f.review("balance", &intent);
    assert_eq!(text(&review, "kind"), "balance");
    assert_eq!(text(&review, "total"), "100.00 USD");
    let approved = ok(
        &f.book,
        &[
            "allocate",
            "approve",
            "--review",
            &path,
            "--digest",
            text(&review, "review_digest"),
            "--as",
            "controller",
        ],
    );
    ok(
        &f.book,
        &[
            "allocate",
            "--review",
            &path,
            "--digest",
            text(&review, "review_digest"),
            "--approval",
            text(&approved, "approval_vid"),
        ],
    );
    f.assert_cell("SHARED", "100.00 USD", "100.00 USD");
    f.assert_cell("ENG", "60.00 USD", "0.00 USD");
    f.assert_cell("SALES", "40.00 USD", "0.00 USD");
    // A subsequent balance allocation sees the now-zero source cell, not
    // the 100.00 USD retained in the account's other destination cells.
    let next = f.allocation(
        "rent-balance-again",
        r#""source_period":"FY2026-P03","unit":"USD""#,
        r#""method":"largest_remainder""#,
        TARGETS,
    );
    let before = f.head();
    let (code, refused) = run(&f.book, &["allocate", "--intent", &next, "--review-only"]);
    assert_ne!(code, 0, "{}", refused.render());
    assert_eq!(f.head(), before);
}

#[test]
fn dimensional_residual_recipient_is_explicit_and_target_dimensions_are_never_ignored() {
    let f = Fixture::new();
    let targets = r#"[{"account":"6100","weight":1,"dimensions":{"cost_center":"ENG"}},{"account":"6100","weight":1,"dimensions":{"cost_center":"SALES"}}]"#;
    let ambiguous = f.allocation(
        "ambiguous-residual",
        r#""total":"0.01 USD","source_side":"credit""#,
        r#""method":"pro_rata","rounding":"HalfEven","recipient":"6100""#,
        targets,
    );
    let before = f.head();
    let (code, refused) = run(
        &f.book,
        &["allocate", "--intent", &ambiguous, "--review-only"],
    );
    assert_eq!(code, 2, "{}", refused.render());
    assert!(
        refused
            .render()
            .contains("exactly one declared target cell")
    );
    assert_eq!(f.head(), before);
    let explicit = f.allocation(
        "explicit-residual",
        r#""total":"0.01 USD","source_side":"credit""#,
        r#""method":"pro_rata","rounding":"HalfEven","recipient":{"account":"6100","dimensions":{"cost_center":"SALES"}}"#,
        targets,
    );
    let (review, _) = f.review("residual", &explicit);
    let legs = get(&review, "legs").as_arr().unwrap();
    assert_eq!(legs.len(), 2, "zero shares have no posting leg");
    assert_eq!(text(&legs[1], "amount"), "0.01 USD");
    f.assert_dimensions(&legs[1], "SALES");

    for (key, targets, expected_exit) in [
        (
            "malformed-dimensions",
            r#"[{"account":"6100","weight":1,"dimensions":"ENG"}]"#,
            2,
        ),
        (
            "duplicate-cell",
            r#"[{"account":"6100","weight":1,"dimensions":{"cost_center":"ENG"}},{"account":"6100","weight":1,"dimensions":{"cost_center":"ENG"}}]"#,
            2,
        ),
        (
            "source-cell",
            r#"[{"account":"6100","weight":1,"dimensions":{"cost_center":"SHARED"}}]"#,
            2,
        ),
    ] {
        let intent = f.allocation(
            key,
            r#""total":"1.00 USD","source_side":"credit""#,
            r#""method":"largest_remainder""#,
            targets,
        );
        let before = f.head();
        let (code, refused) = run(&f.book, &["allocate", "--intent", &intent, "--review-only"]);
        assert_eq!(code, expected_exit, "{}", refused.render());
        assert_eq!(f.head(), before);
    }
}

#[test]
fn zero_share_destinations_still_require_existing_and_mandatory_dimension_values() {
    let f = Fixture::new();
    for (key, targets, expected_exit, reason) in [
        (
            "zero-unknown-dimension",
            r#"[{"account":"6100","weight":1,"dimensions":{"cost_center":"ENG"}},{"account":"6100","weight":0,"dimensions":{"cost_center":"UNDECLARED"}}]"#,
            2,
            "does not exist in this book",
        ),
        (
            "zero-missing-dimension",
            r#"[{"account":"6100","weight":1,"dimensions":{"cost_center":"ENG"}},{"account":"6100","weight":0,"dimensions":{}}]"#,
            3,
            "requires a cost_center value",
        ),
    ] {
        let intent = f.allocation(
            key,
            r#""total":"1.00 USD","source_side":"credit""#,
            r#""method":"largest_remainder""#,
            targets,
        );
        let (review, path) = f.review(key, &intent);
        assert_eq!(get(&review, "legs").as_arr().unwrap().len(), 2);
        let approved = ok(
            &f.book,
            &[
                "allocate",
                "approve",
                "--review",
                &path,
                "--digest",
                text(&review, "review_digest"),
                "--as",
                "controller",
            ],
        );
        f.import_driver(&path, key);
        let before = f.head();
        let (code, refused) = run(
            &f.book,
            &[
                "allocate",
                "--review",
                &path,
                "--digest",
                text(&review, "review_digest"),
                "--approval",
                text(&approved, "approval_vid"),
                "--dry-run",
            ],
        );
        assert_eq!(code, expected_exit, "{}", refused.render());
        assert!(refused.render().contains(reason), "{}", refused.render());
        assert_eq!(f.head(), before);
        f.assert_cell("SHARED", "100.00 USD", "0.00 USD");
    }
}
