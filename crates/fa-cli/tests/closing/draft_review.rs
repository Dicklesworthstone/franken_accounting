//! Existing draft review, exact retained replay and launch-bound authority.

use super::*;
use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};

const DRAFT: &str = "close-12";
const PERIOD: &str = "FY2026-P12";
const OWNER: &str = "close-preparer";

fn open(f: &Fixture) {
    ok(&f.book, &["draft", "new", DRAFT, "--as", OWNER]);
}

fn plan(f: &Fixture, key: &str, class: &str, debit: &str, credit: &str, amount: &str) {
    let path = write(
        &f.dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"class":"{class}","effective_date":"2026-12-30","description":"Reviewed draft adjustment","idempotency_key":"{key}","evidence":["{}"],"legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#,
            f.evidence,
        ),
    );
    ok(
        &f.book,
        &["draft", "plan", DRAFT, "--intent", &path, "--as", OWNER],
    );
}

fn dry_run() -> [&'static str; 6] {
    ["close", "dry-run", "--period", PERIOD, "--draft", DRAFT]
}

fn rows(book: &Path) -> Json {
    get(&ok(book, &["tb", "--period", PERIOD]), "rows").clone()
}

fn balances(diff: &Json, code: &str) -> Json {
    get(diff, "rows")
        .as_arr()
        .expect("rows")
        .iter()
        .find(|row| text(row, "code") == code)
        .unwrap_or_else(|| panic!("missing {code}: {}", diff.render()))
        .clone()
}

fn lines(stdout: &str) -> Vec<Json> {
    let registry = fa_cli::verbs::registry().expect("registry");
    stdout
        .lines()
        .map(|line| {
            registry.check_line(line).expect("registered complete line");
            json::parse(line).expect("robot JSON")
        })
        .collect()
}

fn many(book: &Path, args: &[&str]) -> (i32, Vec<Json>) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(result.stdout).expect("UTF-8 stdout");
    assert!(
        !stdout.is_empty(),
        "args={args:?}: {}",
        String::from_utf8_lossy(&result.stderr),
    );
    (result.status.code().unwrap_or(-1), lines(&stdout))
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn retained_atomic_draft_review_replays_after_more_plans_checkpoint_and_promotion() {
    let f = Fixture::new(false);
    f.post("source-sale", "1000", "4000", "100.00");
    open(&f);
    plan(&f, "expense-15", "Original", "6000", "1000", "15.00");
    plan(&f, "expense-5", "Original", "6000", "1000", "5.00");
    let before = head(&f.book);
    let original_rows = rows(&f.book);
    let original_draft = get(&ok(&f.book, &["draft", "show", DRAFT]), "draft").clone();

    let report = ok(&f.book, &dry_run());
    assert_eq!(text(&report, "event"), "draft_diff");
    assert_eq!(integer(&report, "source_known_at"), before);
    assert_eq!(integer(&report, "rehearsal_known_at"), before + 1);
    assert_eq!(integer(&report, "plans"), 2);
    assert_eq!(get(&report, "entries").as_arr().unwrap().len(), 2);
    assert_eq!(text(&balances(&report, "1000"), "delta"), "-20.00 USD");
    assert_eq!(
        text(&balances(&report, "1000"), "trunk_debits"),
        "100.00 USD"
    );
    assert_eq!(
        text(&balances(&report, "1000"), "draft_credits"),
        "20.00 USD"
    );
    assert_eq!(text(&balances(&report, "6000"), "delta"), "20.00 USD");
    assert_eq!(
        head(&f.book),
        before,
        "an ordinary review publishes nothing"
    );
    assert_eq!(rows(&f.book), original_rows);
    assert_eq!(
        get(&ok(&f.book, &["draft", "show", DRAFT]), "draft"),
        &original_draft,
    );

    let certificate_file = f.dir.join("draft.cert");
    let certificate_path = certificate_file.display().to_string();
    let mut request = dry_run().to_vec();
    request.extend(["--certificate-out", certificate_path.as_str()]);
    let (code, output) = many(&f.book, &request);
    assert_eq!(code, 0, "{output:?}");
    assert_eq!(output.len(), 2, "{output:?}");
    assert_eq!(text(&output[0], "event"), "draft_diff");
    assert_eq!(text(&output[1], "event"), "report_certificate");
    assert_eq!(get(&output[0], "data"), get(&report, "data"));
    assert_eq!(text(&output[1], "output_format"), "fa:draft-diff:v1");
    assert_eq!(integer(&output[1], "known_at"), before);
    let digest = text(&output[1], "oid").to_string();
    assert_eq!(text(&output[0], "certificate"), digest);
    let bytes = decode_hex(text(&output[1], "bytes"));
    assert_eq!(std::fs::read(&certificate_file).unwrap(), bytes);
    let certificate = fa::DraftDiffCertificate::decode(&bytes).expect("typed draft certificate");
    assert_eq!(certificate.canonical_bytes().unwrap(), bytes);
    assert_eq!(certificate.source().plans.len(), 2);
    assert_eq!(certificate.known_at().0 as i128, before);
    assert_eq!(certificate.rehearsal_known_at().0 as i128, before + 1);
    assert_eq!(certificate.format(), fa::DRAFT_DIFF_CERTIFICATE_FORMAT);
    assert!(head(&f.book) > before, "retention records metadata only");
    assert_eq!(rows(&f.book), original_rows);
    assert_eq!(
        get(&ok(&f.book, &["draft", "show", DRAFT]), "draft"),
        &original_draft,
    );

    plan(&f, "expense-later", "Original", "6000", "1000", "10.00");
    ok(&f.book, &["checkpoint", "create", "--grant", "witness"]);
    let current = ok(&f.book, &dry_run());
    assert_eq!(integer(&current, "plans"), 3);
    assert_eq!(text(&balances(&current, "6000"), "delta"), "30.00 USD");
    let locator = format!("C:{digest}");
    let replay_before = head(&f.book);
    let replayed = ok(&f.book, &["replay", &locator]);
    assert_eq!(get(&replayed, "data"), get(&report, "data"));
    assert_eq!(head(&f.book), replay_before);
    assert_eq!(rows(&f.book), original_rows);

    let promoted = ok(
        &f.book,
        &["draft", "promote", DRAFT, "--as", "controller", "--yes"],
    );
    assert_eq!(get(&promoted, "entries").as_arr().unwrap().len(), 3);
    assert_eq!(
        text(
            get(&ok(&f.book, &["draft", "show", DRAFT]), "draft"),
            "state"
        ),
        "promoted",
    );
    let promoted_rows = rows(&f.book);
    let promoted_head = head(&f.book);
    let result_path = f.dir.join("replayed-draft.bin").display().to_string();
    let (code, replayed) = many(&f.book, &["replay", &locator, "--output", &result_path]);
    assert_eq!(code, 0, "{replayed:?}");
    assert_eq!(replayed.len(), 2, "{replayed:?}");
    assert_eq!(get(&replayed[0], "data"), get(&report, "data"));
    assert_eq!(text(&replayed[1], "event"), "report_replayed");
    assert_eq!(text(&replayed[1], "family"), "draft-diff");
    assert_eq!(integer(&replayed[1], "known_at"), before);
    assert_eq!(
        integer(&replayed[1], "output_bytes"),
        certificate.output().len() as i128,
    );
    assert_eq!(std::fs::read(&result_path).unwrap(), certificate.output());
    assert_eq!(head(&f.book), promoted_head);
    assert_eq!(rows(&f.book), promoted_rows);
    let (code, refused) = run(&f.book, &dry_run());
    assert_eq!(code, 3, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-158");
    assert_eq!(head(&f.book), promoted_head);
}

#[test]
fn draft_review_keeps_pending_and_zero_net_gross_changes_visible() {
    let f = Fixture::new(false);
    f.post("opening-cash", "1000", "4000", "100.00");
    open(&f);
    plan(&f, "gross-debit", "Original", "6000", "1000", "12.00");
    plan(&f, "gross-credit", "Original", "1000", "6000", "12.00");
    plan(&f, "pending-only", "Pending", "6000", "1000", "7.00");
    let before = head(&f.book);
    let source = rows(&f.book);
    let report = ok(&f.book, &dry_run());
    assert_eq!(integer(&report, "plans"), 3);
    assert_eq!(get(&report, "rows").as_arr().unwrap().len(), 2);
    for account in ["1000", "6000"] {
        assert_eq!(text(&balances(&report, account), "delta"), "0.00 USD");
    }
    let expense = balances(&report, "6000");
    assert_eq!(text(&expense, "draft_debits"), "12.00 USD");
    assert_eq!(text(&expense, "draft_credits"), "12.00 USD");
    assert_eq!(text(&expense, "draft_debits_pending"), "7.00 USD");
    assert_eq!(text(&expense, "pending_delta"), "7.00 USD");
    let cash = balances(&report, "1000");
    assert_eq!(text(&cash, "draft_credits_pending"), "7.00 USD");
    assert_eq!(text(&cash, "pending_delta"), "-7.00 USD");
    assert_eq!(rows(&f.book), source);
    assert_eq!(head(&f.book), before);
}

fn bound(f: &Fixture, grants: &[&str], args: &[&str]) -> (u8, Vec<Json>) {
    let authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "review-agent",
        LaunchProfile::Agent,
        grants,
    )
    .expect("fixed authority");
    let mut argv: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    argv.push("--json".into());
    let (code, output) = fa_cli::entry::fa_with_authority(
        &argv,
        Files {
            cwd: None,
            stdin: Stdin::Missing,
        },
        &authority,
        true,
    );
    assert!(!output.stdout.is_empty(), "{}", output.stderr);
    (code, lines(&output.stdout))
}

/// Every write since `before` is an AccessEvent of a read-only bound session
/// (fa-7dw): refusals and plain reviews publish nothing else.
fn only_access_events(f: &Fixture, before: i128) {
    let accessed = integer(
        get(
            &ok(&f.book, &["access", "log", "--since", &before.to_string()]),
            "data",
        ),
        "count",
    );
    assert_eq!(
        head(&f.book),
        before + accessed,
        "only the session's AccessEvents were written"
    );
}

#[test]
fn draft_review_requires_current_read_and_certification_requires_produce() {
    let f = Fixture::new(false);
    open(&f);
    plan(&f, "review-one", "Original", "6000", "1000", "3.00");
    let before = head(&f.book);
    let (code, output) = bound(&f, &["read"], &dry_run());
    assert_eq!(code, 0, "{output:?}");
    assert_eq!(text(&output[0], "event"), "draft_diff");
    // A read-only bound review writes only its AccessEvent (fa-7dw).
    let accessed = integer(
        get(
            &ok(&f.book, &["access", "log", "--since", &before.to_string()]),
            "data",
        ),
        "count",
    );
    assert_eq!(accessed, 1);
    assert_eq!(head(&f.book), before + accessed);

    let mut certify = dry_run().to_vec();
    certify.push("--certify");
    let (code, output) = bound(&f, &["read"], &certify);
    assert_eq!(code, 7, "{output:?}");
    assert_eq!(output.len(), 1, "{output:?}");
    assert_eq!(text(&output[0], "event"), "error");
    only_access_events(&f, before);
    let (code, output) = bound(
        &f,
        &["produce"],
        &[
            "close",
            "dry-run",
            "--period",
            PERIOD,
            "--draft",
            "unknown-draft",
        ],
    );
    assert_eq!(code, 7, "authority before draft existence: {output:?}");
    only_access_events(&f, before);

    let (code, output) = bound(&f, &["read", "produce"], &certify);
    assert_eq!(code, 0, "{output:?}");
    assert_eq!(output.len(), 2, "{output:?}");
    assert_eq!(text(&output[1], "event"), "report_certificate");
    assert_eq!(
        text(
            get(&ok(&f.book, &["draft", "show", DRAFT]), "draft"),
            "state"
        ),
        "open",
    );
}
