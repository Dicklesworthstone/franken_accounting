//! Exercise native asset schedules and source-derived charges through the real
//! CLI, including retained reviews, cumulative rounding, plans and refusals.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy, PostIntent, PostPlan};
use fa_cli::json::{self, Json};
use fa_journal::refusal::code;
use fa_model::{AssetScheduleSpec, ControlPayload, Entry, EntryClass};
use fa_money::{Amount, Side, UnitRegistry};
use fgdb_types::VId;

const FIRST: &str = "FY2026-P01";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match value.get(key).expect(key) {
        Json::Int(value) => *value,
        other => panic!("{key} is not an integer: {other:?}"),
    }
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value.get(key).and_then(Json::as_arr).expect(key)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn call(book: &Path, step: &str, args: &[&str], expected: i32) -> Json {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(["--via", "direct"])
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .stdin(Stdio::null())
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "{step}: argv={args:?}\nstdout={stdout}\nstderr={stderr}"
    );
    let envelope = json::parse(lines[0]).unwrap_or_else(|error| {
        panic!("{step}: invalid robot JSON: {error:?}\nstdout={stdout}\nstderr={stderr}")
    });
    eprintln!(
        "{step}: argv={args:?} exit={status} event={:?} refusal={:?} known_at={:?}\nstdout={stdout}\nstderr={stderr}",
        envelope.get("event"),
        envelope.get("data").and_then(|data| data.get("refusal_id")),
        envelope
            .get("coordinate")
            .and_then(|coordinate| coordinate.get("known_at")),
    );
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{step}: {error}\nstdout={stdout}\nstderr={stderr}"));
    assert_eq!(
        status, expected,
        "{step}: argv={args:?}\nstdout={stdout}\nstderr={stderr}"
    );
    envelope
}

fn ok(book: &Path, step: &str, args: &[&str]) -> Json {
    call(book, step, args, 0)
}

fn head(book: &Path) -> i128 {
    let info = ok(book, "read frontier", &["book", "info"]);
    integer(info.get("coordinate").unwrap(), "known_at")
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
    acquisition: String,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let path = std::env::temp_dir().join(format!(
                "fa-asset-cost-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create retained fixture {}: {error}", path.display()),
            }
        };
        let book = dir.join("book");
        ok(
            &book,
            "create book",
            &["book", "create", "--name", "Asset cost CLI"],
        );
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"1500","name":"Long lived asset","type":"Asset","unit":"USD"},
            {"code":"1590","name":"Accumulated cost","type":"Asset","normal_balance":"credit","unit":"USD"},
            {"code":"3000","name":"Capital","type":"Equity","unit":"USD"},
            {"code":"6100","name":"Asset cost expense","type":"Expense","unit":"USD"}
        ]}"#).unwrap();
        ok(
            &book,
            "import chart",
            &["chart", "import", chart.to_str().unwrap()],
        );
        ok(
            &book,
            "materialize year",
            &["period", "create", "--fiscal-year", "2026"],
        );
        for period in [FIRST, "FY2026-P02", "FY2026-P03", "FY2026-P04"] {
            ok(&book, "open service period", &["period", "open", period]);
        }
        let source = dir.join("invoice.txt");
        std::fs::write(
            &source,
            "Acquisition invoice and approved service-life estimate.",
        )
        .unwrap();
        let document = ok(
            &book,
            "retain invoice",
            &[
                "document",
                "add",
                source.to_str().unwrap(),
                "--kind",
                "Invoice",
                "--grade",
                "HumanUpload",
            ],
        );
        let mut fixture = Self {
            dir,
            book,
            evidence: format!("D:{}", text(data(&document), "oid")),
            acquisition: String::new(),
        };
        let acquisition = fixture.post_source("asset-acquisition", "1500", "1000", "100.00");
        fixture.acquisition = text(data(&acquisition), "vid").into();
        fixture
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    fn post_source(&self, key: &str, debit: &str, credit: &str, amount: &str) -> Json {
        let path = self.path(&format!("{key}.json"));
        std::fs::write(
            &path,
            format!(
                r#"{{
            "effective_date":"2026-01-05","idempotency_key":"{key}","legs":[
                {{"side":"debit","account":"{debit}","amount":"{amount} USD"}},
                {{"side":"credit","account":"{credit}","amount":"{amount} USD"}}
            ]}}"#
            ),
        )
        .unwrap();
        ok(
            &self.book,
            key,
            &["post", "--intent", &path, "--evidence", &self.evidence],
        )
    }

    fn schedule_args<'a>(&'a self, name: &'a str, kind: &'a str, salvage: &'a str) -> Vec<&'a str> {
        vec![
            "schedule",
            "asset",
            "create",
            name,
            "--kind",
            kind,
            "--acquisition",
            &self.acquisition,
            "--leg",
            "0",
            "--first-period",
            FIRST,
            "--periods",
            "3",
            "--salvage",
            salvage,
            "--expense",
            "6100",
            "--accumulated",
            "1590",
            "--rounding-law",
            "HalfEven",
            "--date",
            "2026-01-05",
            "--key",
            name,
        ]
    }

    fn schedule(&self, name: &str, kind: &str, salvage: &str) -> (Json, Json, AssetScheduleSpec) {
        let before = head(&self.book);
        let path = self.path(&format!("{name}.review"));
        let mut args = self.schedule_args(name, kind, salvage);
        args.extend(["--review-out", &path]);
        let review = ok(&self.book, "review immutable schedule", &args);
        assert_eq!(text(&review, "event"), "asset_schedule_review");
        assert_eq!(
            head(&self.book),
            before,
            "schedule review publishes nothing"
        );
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, decode_hex(text(data(&review), "bytes")));
        let intent = PostIntent::decode(&bytes).unwrap();
        assert_eq!(intent.canonical_bytes().unwrap(), bytes);
        assert_eq!(
            hex(&intent.digest().unwrap()),
            text(data(&review), "review_digest")
        );
        assert_eq!(
            hex(&intent.proposal().proposal_digest().unwrap()),
            text(data(&review), "proposal_digest")
        );
        assert_eq!(intent.proposal().class, EntryClass::SCHEMA_CONTROL);
        let Some(ControlPayload::SchemaChange {
            kind,
            canonical_bytes,
        }) = &intent.proposal().control
        else {
            panic!("schedule review must retain a schema-control proposal");
        };
        assert_eq!(*kind, fa_model::asset_cost::SCHEMA_CHANGE_ASSET_SCHEDULE);
        let spec = AssetScheduleSpec::decode(canonical_bytes).unwrap();
        assert_eq!(spec.name, name);
        assert_eq!(
            spec.acquisition.vid.0,
            u128::from_str_radix(&self.acquisition, 16).unwrap()
        );
        assert_eq!(spec.acquisition_ordinal, 0);
        assert_eq!(spec.useful_life_periods, 3);
        let recorded = ok(
            &self.book,
            "record exact schedule review",
            &[
                "schedule",
                "asset",
                "create",
                name,
                "--review",
                &path,
                "--digest",
                text(data(&review), "review_digest"),
            ],
        );
        assert_eq!(text(&recorded, "event"), "asset_schedule_recorded");
        assert_eq!(
            data(&recorded).get("already_recorded"),
            Some(&Json::Bool(false))
        );
        let historical = ok(
            &self.book,
            "schedule absent before registration",
            &[
                "schedule",
                "asset",
                "list",
                "--as-known-at",
                &before.to_string(),
            ],
        );
        assert_eq!(integer(data(&historical), "known_at"), before);
        assert!(rows(data(&historical), "schedules").is_empty());
        let shown = ok(
            &self.book,
            "show schedule",
            &["schedule", "asset", "show", name],
        );
        assert_eq!(
            rows(data(&shown), "schedules"),
            std::slice::from_ref(data(&recorded).get("schedule").unwrap())
        );
        (review, recorded, spec)
    }

    fn charge_args<'a>(
        &'a self,
        verb: &'a str,
        name: &'a str,
        period: &'a str,
        key: &'a str,
    ) -> Vec<&'a str> {
        vec![
            verb,
            "--schedule",
            name,
            "--period",
            period,
            "--key",
            key,
            "--evidence",
            &self.evidence,
        ]
    }

    fn review(&self, verb: &str, name: &str, period: &str, key: &str) -> Json {
        let mut args = self.charge_args(verb, name, period, key);
        args.push("--review-only");
        let before = head(&self.book);
        let reviewed = ok(&self.book, "review cumulative charge", &args);
        assert_eq!(text(&reviewed, "event"), "asset_charge_review");
        assert_eq!(integer(data(&reviewed), "known_at"), before);
        assert_eq!(head(&self.book), before, "charge review publishes nothing");
        reviewed
    }

    fn post_review(&self, verb: &str, review: &Json) -> Json {
        ok(
            &self.book,
            "post unchanged charge",
            &[
                verb,
                "--review",
                text(data(review), "bytes"),
                "--digest",
                text(data(review), "review_digest"),
            ],
        )
    }

    fn plan(&self, verb: &str, review: &Json, name: &str) -> (String, PostPlan) {
        let path = self.path(name);
        let before = head(&self.book);
        let planned = ok(
            &self.book,
            "plan unchanged charge",
            &[
                verb,
                "--review",
                text(data(review), "bytes"),
                "--digest",
                text(data(review), "review_digest"),
                "--dry-run",
                "--plan-out",
                &path,
            ],
        );
        assert_eq!(text(&planned, "event"), "plan");
        assert_eq!(head(&self.book), before, "planning publishes nothing");
        let plan = PostPlan::decode(&std::fs::read(&path).unwrap()).unwrap();
        (path, plan)
    }

    fn commit(&self, path: &str) -> Json {
        ok(
            &self.book,
            "commit native plan",
            &["commit", "--plan", path, "--grant", "read", "--yes"],
        )
    }

    fn entry(&self, vid: &str) -> Entry {
        let keys = BookKeys::load(&self.book.join("book.keys")).unwrap();
        let book = Book::open_dir(&self.book, keys, Entropy::production()).unwrap();
        book.read_entry(VId(u128::from_str_radix(vid, 16).unwrap()))
            .unwrap()
            .unwrap()
            .0
    }
}

fn assert_charge(
    review: &Json,
    spec: &AssetScheduleSpec,
    amount: &str,
    period: &str,
    date: &str,
) -> PostIntent {
    let units = UnitRegistry::embedded().unwrap();
    let expected = Amount::parse(amount, &units).unwrap();
    assert_eq!(text(data(review), "cost"), "100.00 USD");
    assert_eq!(text(data(review), "delta"), amount);
    let bytes = decode_hex(text(data(review), "bytes"));
    let intent = PostIntent::decode(&bytes).unwrap();
    assert_eq!(intent.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        hex(&intent.digest().unwrap()),
        text(data(review), "review_digest")
    );
    assert_eq!(
        hex(&intent.proposal().proposal_digest().unwrap()),
        text(data(review), "proposal_digest")
    );
    let proposal = intent.proposal();
    assert_eq!(proposal.class, EntryClass::ADJUSTING);
    assert_eq!(
        proposal.effective_date,
        fa_time::DateDay::parse(date).unwrap()
    );
    assert_eq!(proposal.effective_period.as_ref().unwrap().code, period);
    assert_eq!(proposal.legs.len(), 2);
    assert_eq!(rows(data(review), "legs").len(), 2);
    for (index, account, side) in [
        (0, spec.expense_account, Side::Debit),
        (1, spec.accumulated_account, Side::Credit),
    ] {
        assert_eq!(proposal.legs[index].account_ref, account);
        assert_eq!(proposal.legs[index].side, side);
        assert_eq!(proposal.legs[index].amount, expected);
        assert_eq!(text(&rows(data(review), "legs")[index], "amount"), amount);
        assert_eq!(
            text(&rows(data(review), "legs")[index], "account_vid"),
            format!("{:032x}", account.0)
        );
    }
    let basis = proposal.asset_charge_basis().unwrap().unwrap();
    assert_eq!(basis.through_period.code, period);
    assert_eq!(
        i128::from(basis.known_at.0),
        integer(data(review), "known_at")
    );
    assert_eq!(
        format!("{:032x}", basis.schedule.vid.0),
        text(data(review), "schedule_entry")
    );
    assert_eq!(
        hex(&basis.schedule.entry_digest),
        text(data(review), "schedule_digest")
    );
    assert_eq!(text(data(review), "kind"), spec.kind.name());
    assert_eq!(
        proposal.evidence.len(),
        1,
        "the invoice survives review and plan transport"
    );
    intent
}

#[test]
fn depreciation_review_plan_commit_rounding_and_exact_retries_preserve_the_acquisition() {
    let f = Fixture::new();
    let acquisition = f.entry(&f.acquisition);
    let (schedule_review, recorded, spec) = f.schedule("press", "depreciation", "0.00 USD");
    let first = f.review("depreciate", "press", FIRST, "press-january");
    let intent = assert_charge(&first, &spec, "33.33 USD", FIRST, "2026-01-31");
    assert_eq!(text(data(&first), "target"), "33.33 USD");
    assert_eq!(text(data(&first), "recognized"), "0.00 USD");
    let (path, plan) = f.plan("depreciate", &first, "january.plan");
    assert_eq!(
        plan.proposal(),
        intent.proposal(),
        "planning preserves the exact reviewed bytes"
    );
    let posted = f.commit(&path);
    assert_eq!(text(&posted, "event"), "plan_committed");
    assert_eq!(
        f.entry(text(data(&posted), "vid")).proposal,
        *intent.proposal()
    );

    // Cumulative rounding allocates the middle cent: round(100 * 2/3) minus
    // the already posted 33.33 is 33.34, not another independently rounded 33.33.
    for (period, key, amount, target, recognized, date) in [
        (
            "FY2026-P02",
            "press-february",
            "33.34 USD",
            "66.67 USD",
            "33.33 USD",
            "2026-02-28",
        ),
        (
            "FY2026-P03",
            "press-march",
            "33.33 USD",
            "100.00 USD",
            "66.67 USD",
            "2026-03-31",
        ),
    ] {
        let review = f.review("depreciate", "press", period, key);
        let intent = assert_charge(&review, &spec, amount, period, date);
        assert_eq!(text(data(&review), "target"), target);
        assert_eq!(text(data(&review), "recognized"), recognized);
        let posted = f.post_review("depreciate", &review);
        assert_eq!(text(&posted, "event"), "posted");
        assert_eq!(
            f.entry(text(data(&posted), "vid")).proposal,
            *intent.proposal()
        );
    }
    let before = head(&f.book);
    let noop = ok(
        &f.book,
        "fully depreciated asset is a no-op",
        &f.charge_args("depreciate", "press", "FY2026-P04", "press-complete"),
    );
    assert_eq!(text(&noop, "event"), "asset_charge_noop");
    for (field, amount) in [
        ("cost", "100.00 USD"),
        ("target", "100.00 USD"),
        ("recognized", "100.00 USD"),
        ("delta", "0.00 USD"),
    ] {
        assert_eq!(text(data(&noop), field), amount, "{field}");
    }
    assert_eq!(integer(data(&noop), "known_at"), before);

    let retry = f.post_review("depreciate", &first);
    assert_eq!(text(&retry, "event"), "recorded");
    assert_eq!(text(data(&retry), "vid"), text(data(&posted), "vid"));
    let plan_retry = f.commit(&path);
    assert_eq!(
        data(&plan_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&plan_retry), "vid"), text(data(&posted), "vid"));
    let schedule_retry = ok(
        &f.book,
        "schedule retry after later charges",
        &[
            "schedule",
            "asset",
            "create",
            "press",
            "--review",
            text(data(&schedule_review), "bytes"),
            "--digest",
            text(data(&schedule_review), "review_digest"),
        ],
    );
    assert_eq!(
        data(&schedule_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        data(&schedule_retry).get("schedule"),
        data(&recorded).get("schedule")
    );
    assert_eq!(
        head(&f.book),
        before,
        "no-op and exact retries must publish nothing"
    );
    assert_eq!(
        f.entry(&f.acquisition),
        acquisition,
        "charges never rewrite original acquisition cost"
    );
}

#[test]
fn amortization_catches_up_skipped_periods_and_preserves_salvage() {
    let f = Fixture::new();
    let (_, _, spec) = f.schedule("license", "amortization", "10.00 USD");
    let first = f.review("amortize", "license", FIRST, "license-january");
    assert_charge(&first, &spec, "30.00 USD", FIRST, "2026-01-31");
    assert_eq!(text(data(&first), "target"), "30.00 USD");
    assert_eq!(text(data(&first), "recognized"), "0.00 USD");
    // An unrelated journal append leaves the independently derived asset
    // state unchanged, so the retained monetary proposal remains usable.
    f.post_source("unrelated-capital", "1000", "3000", "1.00");
    f.post_review("amortize", &first);
    let catchup = f.review("amortize", "license", "FY2026-P03", "license-catchup");
    let intent = assert_charge(&catchup, &spec, "60.00 USD", "FY2026-P03", "2026-03-31");
    assert_eq!(text(data(&catchup), "target"), "90.00 USD");
    assert_eq!(text(data(&catchup), "recognized"), "30.00 USD");
    let posted = f.post_review("amortize", &catchup);
    assert_eq!(
        f.entry(text(data(&posted), "vid")).proposal,
        *intent.proposal()
    );
    let before = head(&f.book);
    for period in ["FY2026-P03", "FY2026-P04"] {
        let noop = ok(
            &f.book,
            "salvage is not amortized",
            &f.charge_args("amortize", "license", period, "license-complete"),
        );
        assert_eq!(text(&noop, "event"), "asset_charge_noop");
        assert_eq!(text(data(&noop), "target"), "90.00 USD");
        assert_eq!(text(data(&noop), "recognized"), "90.00 USD");
        assert_eq!(text(data(&noop), "delta"), "0.00 USD");
    }
    assert_eq!(head(&f.book), before);
}

#[test]
fn stale_charge_reviews_and_plans_refuse_without_publishing_and_fresh_review_recovers() {
    let f = Fixture::new();
    let (_, _, spec) = f.schedule("press", "depreciation", "0.00 USD");
    let reviewed = f.review("depreciate", "press", "FY2026-P02", "stale-press");
    assert_charge(&reviewed, &spec, "66.67 USD", "FY2026-P02", "2026-02-28");
    let (plan, _) = f.plan("depreciate", &reviewed, "stale.plan");
    let competing = f.review("depreciate", "press", FIRST, "competing-press");
    assert_charge(&competing, &spec, "33.33 USD", FIRST, "2026-01-31");
    f.post_review("depreciate", &competing);
    let before = head(&f.book);
    let restore = vec![
        "depreciate",
        "--review",
        text(data(&reviewed), "bytes"),
        "--digest",
        text(data(&reviewed), "review_digest"),
    ];
    let mut replan = restore.clone();
    replan.push("--dry-run");
    for args in [
        restore,
        replan,
        vec!["commit", "--plan", &plan, "--grant", "read", "--yes"],
    ] {
        let refused = call(&f.book, "refuse obsolete native basis", &args, 6);
        assert_eq!(text(data(&refused), "refusal_id"), code::PLAN_INVALIDATED);
        assert_eq!(head(&f.book), before);
    }
    let fresh = f.review("depreciate", "press", "FY2026-P02", "fresh-press");
    assert_charge(&fresh, &spec, "33.34 USD", "FY2026-P02", "2026-02-28");
    assert_eq!(text(data(&fresh), "target"), "66.67 USD");
    assert_eq!(text(data(&fresh), "recognized"), "33.33 USD");
    assert_ne!(
        text(data(&fresh), "review_digest"),
        text(data(&reviewed), "review_digest")
    );
    assert_eq!(
        text(&f.post_review("depreciate", &fresh), "event"),
        "posted"
    );
}

#[test]
fn malformed_asset_commands_and_changed_reviews_cannot_publish() {
    let f = Fixture::new();
    let before = head(&f.book);
    for (flag, value) in [
        ("--kind", "mark-to-market"),
        ("--leg", "-1"),
        ("--periods", "three"),
        ("--periods", "0"),
        ("--periods", "1201"),
        ("--salvage", "-0.01 USD"),
        ("--rounding-law", "nearest-ish"),
        ("--date", "2026-02-30"),
    ] {
        let mut args = f.schedule_args("invalid", "depreciation", "0.00 USD");
        let index = args.iter().position(|arg| *arg == flag).unwrap();
        args[index + 1] = value;
        call(&f.book, "reject malformed schedule selector", &args, 2);
        assert_eq!(head(&f.book), before);
    }
    let overlong = "n".repeat(fa_model::asset_cost::MAX_ASSET_SCHEDULE_NAME + 1);
    for name in ["", overlong.as_str()] {
        let mut args = f.schedule_args(name, "depreciation", "0.00 USD");
        let key = args.iter().position(|arg| *arg == "--key").unwrap();
        args[key + 1] = "invalid-name";
        call(&f.book, "reject invalid schedule name", &args, 2);
        assert_eq!(head(&f.book), before);
    }
    for (flag, value) in [
        ("--salvage", "100.01 USD"),
        ("--salvage", "0.00 EUR"),
        ("--expense", "1500"),
        ("--accumulated", "1000"),
        ("--leg", "1"),
    ] {
        let mut args = f.schedule_args("invalid", "depreciation", "0.00 USD");
        let index = args.iter().position(|arg| *arg == flag).unwrap();
        args[index + 1] = value;
        let refused = call(
            &f.book,
            "reject invalid source or accounting route",
            &args,
            2,
        );
        assert_eq!(text(data(&refused), "refusal_id"), code::STRUCTURE);
        assert_eq!(head(&f.book), before);
    }
    let (schedule_review, _, _) = f.schedule("press", "depreciation", "0.00 USD");
    let reviewed = f.review("depreciate", "press", FIRST, "retained-press");
    let before = head(&f.book);
    let restore = vec![
        "depreciate",
        "--review",
        text(data(&reviewed), "bytes"),
        "--digest",
        text(data(&reviewed), "review_digest"),
    ];
    let mut changed_key = restore.clone();
    changed_key.extend(["--key", "unreviewed-key"]);
    let mut changed_evidence = restore.clone();
    changed_evidence.extend(["--evidence", &f.evidence]);
    let mut approval_without_review =
        f.charge_args("depreciate", "press", FIRST, "unreviewed-approval");
    approval_without_review.extend(["--approval", "00000000000000000000000000000001"]);
    let mut schedule_approval = f.schedule_args("unreviewed-schedule", "depreciation", "0.00 USD");
    schedule_approval.extend(["--approval", "00000000000000000000000000000001"]);
    for args in [
        changed_key,
        changed_evidence,
        approval_without_review,
        schedule_approval,
        vec!["depreciate", "--review", "00", "--digest", ZERO_DIGEST],
        vec![
            "depreciate",
            "--review",
            text(data(&reviewed), "bytes"),
            "--digest",
            ZERO_DIGEST,
        ],
        vec![
            "amortize",
            "--review",
            text(data(&reviewed), "bytes"),
            "--digest",
            text(data(&reviewed), "review_digest"),
        ],
        vec![
            "schedule",
            "asset",
            "create",
            "other-name",
            "--review",
            text(data(&schedule_review), "bytes"),
            "--digest",
            text(data(&schedule_review), "review_digest"),
        ],
    ] {
        call(
            &f.book,
            "reject malformed or changed retained review",
            &args,
            2,
        );
        assert_eq!(head(&f.book), before);
    }
    let wrong_kind = call(
        &f.book,
        "refuse wrong charge kind",
        &f.charge_args("amortize", "press", FIRST, "wrong-kind"),
        2,
    );
    assert_eq!(text(data(&wrong_kind), "refusal_id"), code::STRUCTURE);
    assert_eq!(head(&f.book), before);
    assert_eq!(
        text(&f.post_review("depreciate", &reviewed), "event"),
        "posted",
        "refusals must not consume the reviewed outcome"
    );
}

#[test]
fn typed_and_raw_reversals_retain_the_exact_asset_charge_basis() {
    let f = Fixture::new();
    f.schedule("press", "depreciation", "0.00 USD");
    let review = f.review("depreciate", "press", FIRST, "press-charge");
    let posted = f.post_review("depreciate", &review);
    let original_vid = text(data(&posted), "vid");
    let original = f.entry(original_vid);
    let basis = original.proposal.asset_charge_basis().unwrap().unwrap();
    let reverse_args = [
        "reverse",
        original_vid,
        "--reason",
        "WrongAmount",
        "--grant",
        "read",
    ];
    let reversed = ok(&f.book, "reverse governed asset charge", &reverse_args);
    assert_eq!(text(&reversed, "event"), "reversed");
    let reversal_vid = text(data(&reversed), "vid");
    let reversal = f.entry(reversal_vid);
    assert_eq!(reversal.proposal.class, EntryClass::REVERSAL);
    assert!(reversal.proposal.schema_minor >= fa_model::entry::ASSET_CHARGE_SCHEMA_MINOR);
    assert_eq!(
        reversal.proposal.asset_charge_basis().unwrap().unwrap(),
        basis
    );
    assert_eq!(reversal.proposal.extensions, original.proposal.extensions);
    assert_eq!(reversal.proposal.legs.len(), original.proposal.legs.len());
    for (actual, original) in reversal.proposal.legs.iter().zip(&original.proposal.legs) {
        let mut opposite = original.clone();
        opposite.side = match original.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        assert_eq!(*actual, opposite);
    }
    let before_retry = head(&f.book);
    let retry = ok(&f.book, "retry exact asset reversal", &reverse_args);
    assert_eq!(text(data(&retry), "vid"), reversal_vid);
    assert_eq!(head(&f.book), before_retry);

    let restore_path = f.path("restore-charge.json");
    std::fs::write(
        &restore_path,
        format!(
            r#"{{"class":"Reversal","reverses":"{reversal_vid}","reason":"DataEntryError","idempotency_key":"restore-press-charge"}}"#
        ),
    )
    .unwrap();
    let restored = ok(
        &f.book,
        "restore asset charge through raw reversal intent",
        &["post", "--intent", &restore_path, "--grant", "read"],
    );
    let restored = f.entry(text(data(&restored), "vid"));
    assert_eq!(restored.proposal.class, EntryClass::REVERSAL);
    assert!(restored.proposal.schema_minor >= fa_model::entry::ASSET_CHARGE_SCHEMA_MINOR);
    assert_eq!(
        restored.proposal.asset_charge_basis().unwrap().unwrap(),
        basis
    );
    assert_eq!(restored.proposal.extensions, original.proposal.extensions);
    assert_eq!(restored.proposal.legs, original.proposal.legs);
    let before_retry = head(&f.book);
    let retry = f.post_review("depreciate", &review);
    assert_eq!(text(data(&retry), "vid"), original_vid);
    assert_eq!(head(&f.book), before_retry);
    ok(
        &f.book,
        "verify restored schedule history",
        &["verify", "schedules"],
    );
}
