//! Bounded attachment groups exercise the ordinary kernel publication path.
//! These are synthetic accounting fixtures, with explicit AgentUpload custody
//! and a distinct fixture reviewer; they are not independent human audits.

use super::{ok, tmp, write};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use fa::{Book, BookKeys, Entropy};
use fa_cli::authority::LaunchAuthority;
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json, obj, s};
use fa_policy::{Capability, CapabilityToken, Op, Profile, possession_digest};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

fn data(value: &Json) -> &Json {
    value.get("data").unwrap()
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).unwrap()
}

fn integer(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(value)) => *value,
        other => panic!("{key}: expected integer, got {other:?}"),
    }
}

fn events(stdout: &str) -> Vec<Json> {
    stdout
        .lines()
        .map(|line| {
            fa_cli::verbs::registry().unwrap().check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect()
}

fn array(values: &[String]) -> Vec<u8> {
    Json::Arr(values.iter().map(s).collect())
        .render()
        .into_bytes()
}

fn vid(value: &str) -> VId {
    VId(u128::from_str_radix(value, 16).unwrap())
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Fixture {
    dir: PathBuf,
    path: PathBuf,
    entries: Vec<(String, String)>,
    documents: Vec<(String, String)>,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let dir = tmp("attachment-groups").unwrap();
        let path = dir.join("book");
        ok(
            &path,
            &["book", "create", "--name", "Attachment fixtures", "--json"],
        );
        let chart = write(
            &dir,
            "chart.json",
            br#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
        );
        ok(&path, &["chart", "import", &chart, "--json"]);
        ok(
            &path,
            &["period", "create", "--fiscal-year", "2026", "--json"],
        );
        ok(&path, &["period", "open", "FY2026-P03", "--json"]);
        let mut documents = Vec::new();
        for index in 0..4 {
            let file = write(
                &dir,
                &format!("source-{index}.txt"),
                format!("Synthetic invoice/supporting document {index}").as_bytes(),
            );
            let output = events(&ok(
                &path,
                &[
                    "document",
                    "add",
                    &file,
                    "--kind",
                    "Invoice",
                    "--grade",
                    "AgentUpload",
                    "--as",
                    "attachment-fixture-uploader",
                    "--json",
                ],
            ));
            assert_eq!(output.len(), 1);
            assert_eq!(text(data(&output[0]), "grade"), "AgentUpload");
            assert_eq!(
                data(&output[0]).get("self_sourced"),
                Some(&Json::Bool(true))
            );
            let oid = text(data(&output[0]), "oid").to_owned();
            let commit = text(data(&output[0]), "doc_commit").to_owned();
            let reviewed = events(&ok(
                &path,
                &[
                    "document",
                    "attest",
                    "review",
                    &oid,
                    "--as",
                    "attachment-fixture-reviewer",
                    "--json",
                ],
            ));
            assert_eq!(text(data(&reviewed[0]), "claim"), "Reviewed");
            assert_eq!(text(data(&reviewed[0]), "subject"), oid);
            documents.push((oid, commit));
        }
        let mut fixture = Self {
            dir,
            path,
            entries: Vec::new(),
            documents,
        };
        let mut book = fixture.open();
        for index in 0..count {
            let input = format!(
                r#"{{"idempotency_key":"group-entry-{index}","evidence":["{}"],{}}}"#,
                fixture.documents[0].0,
                super::RENT,
            );
            let (status, output) = fixture.invoke(
                &mut book,
                &["post".into(), "--intent".into(), "-".into()],
                Stdin::Forwarded(input.into_bytes()),
            );
            assert_eq!(status, 0, "{output:?}");
            assert_eq!(output.len(), 1);
            assert_eq!(text(&output[0], "event"), "posted");
            fixture.entries.push((
                text(data(&output[0]), "vid").to_owned(),
                text(data(&output[0]), "entry_digest").to_owned(),
            ));
        }
        drop(book);
        fixture
    }

    fn open(&self) -> Book {
        Book::open_dir(
            &self.path,
            BookKeys::load(&self.path.join("book.keys")).unwrap(),
            Entropy::deterministic(227),
        )
        .unwrap()
    }

    fn invoke(&self, book: &mut Book, args: &[String], stdin: Stdin) -> (u8, Vec<Json>) {
        let mut args = args.to_vec();
        args.push("--json".into());
        // The same held-book execution used by fad, with forwarded bytes and
        // no files root. No target-list host path is opened on the daemon.
        let (status, captured) = fa_cli::cli::run_for_daemon(
            &args,
            book,
            self.path.clone(),
            None,
            Some(self.dir.clone()),
            stdin,
            true,
        );
        (status, events(&captured.stdout))
    }

    fn refs(&self) -> Vec<String> {
        self.documents.iter().map(|(oid, _)| oid.clone()).collect()
    }

    fn args(refs: &[String]) -> Vec<String> {
        let mut args = ["document", "attach", "--entries", "-"]
            .map(str::to_owned)
            .to_vec();
        for reference in refs {
            args.extend(["--evidence".into(), reference.clone()]);
        }
        args
    }

    fn attach(&self, book: &mut Book, input: Vec<u8>, refs: &[String]) -> (u8, Vec<Json>) {
        self.invoke(book, &Self::args(refs), Stdin::Forwarded(input))
    }

    fn targets(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(entry, _)| entry.clone())
            .collect()
    }

    fn expected_documents(&self) -> Json {
        let mut documents = self.documents.clone();
        documents.sort();
        Json::Arr(
            documents
                .iter()
                .map(|(oid, commit)| {
                    obj(vec![
                        ("document_oid", s(oid)),
                        ("doc_commit", s(commit)),
                        ("role", s("Source")),
                    ])
                })
                .collect(),
        )
    }
}

#[test]
fn attachment_groups_preserve_order_native_identities_and_durable_evidence() {
    let fixture = Fixture::new(2);
    let mut book = fixture.open();
    let original = fixture
        .targets()
        .iter()
        .map(|entry| book.read_entry(vid(entry)).unwrap())
        .collect::<Vec<_>>();
    let before = book.head().unwrap().0;
    let targets = vec![
        format!("E:{}", fixture.entries[1].0.to_uppercase()),
        fixture.entries[0].0.clone(),
    ];
    let input = array(&targets);
    let (status, first) = fixture.attach(&mut book, input.clone(), &fixture.refs());
    assert_eq!(status, 0, "{first:?}");
    assert_eq!(first.len(), 2);
    assert_eq!(book.head().unwrap().0, before + 2);
    for (index, receipt) in first.iter().enumerate() {
        assert_eq!(text(receipt, "event"), "evidence_attached");
        assert_eq!(text(data(receipt), "entry"), fixture.entries[1 - index].0);
        assert_eq!(
            text(data(receipt), "entry_digest"),
            fixture.entries[1 - index].1
        );
        assert_eq!(
            data(receipt).get("documents"),
            Some(&fixture.expected_documents())
        );
        assert_eq!(
            integer(data(receipt), "recorded_at"),
            i128::from(before) + index as i128 + 1
        );
        assert_eq!(
            data(receipt).get("already_recorded"),
            Some(&Json::Bool(false))
        );
        assert_eq!(
            receipt.get("book").and_then(Json::as_str),
            Some(book.context().book_id.to_hex().as_str())
        );
    }
    assert_ne!(
        data(&first[0]).get("supplement_vid"),
        data(&first[1]).get("supplement_vid")
    );
    let (status, retry) = fixture.attach(&mut book, input, &fixture.refs());
    assert_eq!(status, 0, "{retry:?}");
    assert_eq!(retry.len(), first.len());
    assert_eq!(book.head().unwrap().0, before + 2);
    for (old, repeated) in first.iter().zip(&retry) {
        for key in [
            "supplement_vid",
            "entry",
            "entry_digest",
            "documents",
            "body_digest",
            "recorded_at",
        ] {
            assert_eq!(data(old).get(key), data(repeated).get(key), "{key}");
        }
        assert_eq!(
            data(repeated).get("already_recorded"),
            Some(&Json::Bool(true))
        );
    }
    // The legacy single-target command uses exactly the same content identity.
    let mut single = vec![
        "document".into(),
        "attach".into(),
        fixture.entries[0].0.clone(),
    ];
    for reference in fixture.refs() {
        single.extend(["--evidence".into(), reference]);
    }
    let (status, legacy) = fixture.invoke(&mut book, &single, Stdin::Missing);
    assert_eq!(status, 0);
    assert_eq!(legacy.len(), 1);
    assert_eq!(data(&legacy[0]), data(&retry[1]));
    drop(book);
    let reopened = fixture.open();
    assert_eq!(reopened.head().unwrap().0, before + 2);
    for (index, (entry, digest)) in fixture.entries.iter().enumerate() {
        assert_eq!(reopened.read_entry(vid(entry)).unwrap(), original[index]);
        let explanation = reopened
            .explain_entry_evidence(vid(entry))
            .unwrap()
            .unwrap();
        assert_eq!(hex(&explanation.entry_digest), *digest);
        assert_eq!(
            explanation.documents.len(),
            1,
            "original evidence was changed"
        );
        assert_eq!(explanation.supplements.len(), 1);
        let supplement = &explanation.supplements[0];
        let receipt = data(&first[1 - index]);
        assert_eq!(
            format!("{:032x}", supplement.vid.0),
            text(receipt, "supplement_vid")
        );
        assert_eq!(hex(&supplement.body_digest), text(receipt, "body_digest"));
        assert_eq!(
            supplement.recorded_at.0 as i128,
            integer(receipt, "recorded_at")
        );
        assert_eq!(supplement.documents.len(), 4);
    }
}

#[test]
fn attachment_groups_prevalidate_every_target_and_shared_citation_before_writing() {
    let fixture = Fixture::new(2);
    let mut book = fixture.open();
    let before = book.head().unwrap();
    let valid = s(&fixture.entries[0].0).render();
    let alias = s(format!("E:{}", fixture.entries[0].0.to_uppercase())).render();
    let cases = vec![
        b"[]".to_vec(),
        b"{}".to_vec(),
        b"[".to_vec(),
        vec![0xff],
        format!("[{valid},\"bad-later-target\"]").into_bytes(),
        format!("[{valid},false]").into_bytes(),
        format!("[{valid},{alias}]").into_bytes(),
        array(&(1..=4097).map(|n| format!("{n:032x}")).collect::<Vec<_>>()),
        vec![b' '; 1024 * 1024 + 1],
    ];
    for input in cases {
        let (status, output) = fixture.attach(&mut book, input, &fixture.refs());
        assert_eq!(status, 2, "{output:?}");
        assert_eq!(output.len(), 1);
        assert_eq!(text(&output[0], "event"), "error");
        assert_eq!(book.head().unwrap(), before);
    }
    let input = array(&fixture.targets());
    for refs in [
        Vec::new(),
        vec![fixture.documents[0].0.clone(), "not-a-document-oid".into()],
        vec![
            fixture.documents[0].0.clone(),
            format!("{}:UnregisteredRole", fixture.documents[1].0),
        ],
        vec![
            fixture.documents[0].0.clone(),
            format!("D:{}:Source", fixture.documents[0].0.to_uppercase()),
        ],
        vec![fixture.documents[0].0.clone(); 1025],
    ] {
        let (status, output) = fixture.attach(&mut book, input.clone(), &refs);
        assert_eq!(status, 2, "{output:?}");
        assert_eq!(output.len(), 1);
        assert_eq!(book.head().unwrap(), before);
    }
    let mut refs = fixture.refs();
    refs.push(format!("{}:Contract", fixture.documents[0].0));
    let many = array(&(1..=4096).map(|n| format!("{n:032x}")).collect::<Vec<_>>());
    let (status, output) = fixture.attach(&mut book, many, &refs);
    assert_eq!(status, 2, "{output:?}");
    assert!(
        output[0].render().contains("16384"),
        "product must be bounded before targets are observed"
    );
    assert_eq!(book.head().unwrap(), before);
    for extra in [
        vec!["--entries".into(), "[]".into()],
        vec![fixture.entries[0].0.clone()],
    ] {
        let mut args = Fixture::args(&fixture.refs());
        args.extend(extra);
        let (status, output) = fixture.invoke(&mut book, &args, Stdin::Forwarded(input.clone()));
        assert_eq!(status, 2, "{output:?}");
        assert_eq!(output.len(), 1);
        assert_eq!(book.head().unwrap(), before);
    }
    let (status, output) =
        fixture.invoke(&mut book, &Fixture::args(&fixture.refs()), Stdin::Missing);
    assert_eq!(status, 2, "{output:?}");
    assert_eq!(book.head().unwrap(), before);
    // A syntactically valid unknown document reaches the ordinary native law.
    let (status, output) = fixture.attach(&mut book, input, &["ab".repeat(32)]);
    assert_eq!(status, 3, "{output:?}");
    assert_eq!(text(data(&output[0]), "refusal_id"), "FA-REF-081");
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn attachment_groups_retain_a_native_prefix_and_retry_it_without_new_history() {
    let fixture = Fixture::new(1);
    let mut book = fixture.open();
    let before = book.head().unwrap().0;
    let input = array(&[fixture.entries[0].0.clone(), "ff".repeat(16)]);
    let (status, first) = fixture.attach(&mut book, input.clone(), &fixture.refs());
    assert_eq!(status, 2, "{first:?}");
    assert_eq!(first.len(), 2);
    assert_eq!(text(&first[0], "event"), "evidence_attached");
    assert_eq!(text(data(&first[0]), "entry"), fixture.entries[0].0);
    assert_eq!(text(&first[1], "event"), "error");
    assert_eq!(book.head().unwrap().0, before + 1);
    let (status, repeated) = fixture.attach(&mut book, input, &fixture.refs());
    assert_eq!(status, 2, "{repeated:?}");
    assert_eq!(repeated.len(), 2);
    for key in ["supplement_vid", "body_digest", "recorded_at"] {
        assert_eq!(data(&first[0]).get(key), data(&repeated[0]).get(key));
    }
    assert_eq!(
        data(&repeated[0]).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(&repeated[1], "event"), "error");
    assert_eq!(book.head().unwrap().0, before + 1);
}

#[test]
fn attachment_groups_recheck_expiry_before_target_existence_and_exact_retry() {
    let fixture = Fixture::new(2);
    let mut book = fixture.open();
    let issuer = Capability::embedded(
        fa_model::principal_vid("attachment-issuer"),
        &["issue_capability", "read", "post"],
    )
    .unwrap();
    let before_issue = book.head().unwrap();
    let secret = [0x71; 32];
    let capability = Capability::new(
        fa_model::principal_vid("attachment-expiry"),
        Profile::Human,
        &[Op::Read, Op::Post],
        issuer.holder(),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret))
    // Issuance and the bound document command's ordinary AccessEvent each
    // advance once, then precisely one attachment reaches this expiry.
    .expiring_at(CommitSeq(before_issue.0 + 3));
    book.issue_capability(
        issuer,
        capability.clone(),
        DateDay::parse("2026-01-01").unwrap(),
        b"attachment-group-expiry",
        "one attachment before expiry",
    )
    .unwrap()
    .unwrap();
    let token = CapabilityToken::new("attachment-expiry", capability, secret).unwrap();
    let authority =
        LaunchAuthority::from_operator_token(fixture.path.clone(), None, &token).unwrap();
    drop(book);
    // Shared syntax is prevalidated before even the bound access record.
    // A valid first citation must not hide malformed or duplicate later ones.
    for refs in [
        vec![fixture.documents[0].0.clone(), "malformed-later-oid".into()],
        vec![
            fixture.documents[0].0.clone(),
            format!("{}:UnregisteredRole", fixture.documents[1].0),
        ],
        vec![
            fixture.documents[0].0.clone(),
            format!("D:{}:Source", fixture.documents[0].0.to_uppercase()),
        ],
    ] {
        let mut malformed = Fixture::args(&refs);
        malformed.push("--json".into());
        let (status, captured) = fa_with_authority(
            &malformed,
            Files {
                cwd: Some(fixture.dir.clone()),
                stdin: Stdin::Forwarded(array(&fixture.targets())),
            },
            &authority,
            true,
        );
        let output = events(&captured.stdout);
        assert_eq!(status, 2, "{output:?}");
        assert_eq!(output.len(), 1);
        assert_eq!(fixture.open().head().unwrap().0, before_issue.0 + 1);
    }
    let mut args = Fixture::args(&fixture.refs());
    args.push("--json".into());
    let execute = |targets: &[String]| {
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(fixture.dir.clone()),
                stdin: Stdin::Forwarded(array(targets)),
            },
            &authority,
            true,
        );
        (status, events(&captured.stdout))
    };
    let targets = vec![fixture.entries[0].0.clone(), "ff".repeat(16)];
    let (status, first) = execute(&targets);
    assert_eq!(status, 7, "{first:?}");
    assert_eq!(first.len(), 2);
    assert_eq!(text(&first[0], "event"), "evidence_attached");
    assert_eq!(text(data(&first[0]), "entry"), fixture.entries[0].0);
    assert_eq!(text(data(&first[1]), "refusal_id"), "FA-REF-014");
    assert_eq!(fixture.open().head().unwrap().0, before_issue.0 + 3);
    // Both existing and nonexistent targets, and a committed exact retry,
    // receive the same authority refusal before revealing an identity receipt.
    for target in [
        fixture.entries[0].0.clone(),
        fixture.entries[1].0.clone(),
        "ff".repeat(16),
    ] {
        let (status, output) = execute(&[target]);
        assert_eq!(status, 7, "{output:?}");
        assert_eq!(output.len(), 1);
        assert_eq!(text(data(&output[0]), "refusal_id"), "FA-REF-014");
        assert_eq!(fixture.open().head().unwrap().0, before_issue.0 + 3);
    }

    // The direct token route must admit expiry before reading real process
    // stdin. Malformed supplied bytes would otherwise win as a usage error.
    let token_path = write(
        &fixture.dir,
        "expired-token.cap",
        &token.canonical_bytes().unwrap(),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.path)
        .args(["--token", &token_path, "--via", "direct"])
        .args(&args)
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(b"[") {
        // An early authority refusal may close its pipe before the parent
        // writes; neither this race nor waiting for EOF is required to admit.
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let output = child.wait_with_output().unwrap();
    let process_events = events(std::str::from_utf8(&output.stdout).unwrap());
    assert_eq!(
        output.status.code(),
        Some(7),
        "{process_events:?}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(process_events.len(), 1, "{process_events:?}");
    assert_eq!(text(&process_events[0], "event"), "error");
    assert_eq!(text(data(&process_events[0]), "refusal_id"), "FA-REF-014");
    assert_eq!(
        fixture.open().head().unwrap().0,
        before_issue.0 + 3,
        "process-input refusal publishes neither an AccessEvent nor evidence"
    );

    // Fresh authority for the same holder recovers the exact supplement;
    // its ordinary access audit remains a real, separate publication.
    let mut book = fixture.open();
    let issuer = Capability::embedded(
        fa_model::principal_vid("attachment-issuer"),
        &["issue_capability", "read", "post"],
    )
    .unwrap();
    let secret = [0x72; 32];
    let capability = Capability::new(
        fa_model::principal_vid("attachment-expiry"),
        Profile::Human,
        &[Op::Read, Op::Post],
        issuer.holder(),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret));
    book.issue_capability(
        issuer,
        capability.clone(),
        DateDay::parse("2026-01-01").unwrap(),
        b"attachment-group-renewed",
        "fresh authority for exact attachment retry",
    )
    .unwrap()
    .unwrap();
    let token = CapabilityToken::new("attachment-expiry", capability, secret).unwrap();
    let renewed = LaunchAuthority::from_operator_token(fixture.path.clone(), None, &token).unwrap();
    let before_retry = book.head().unwrap().0;
    drop(book);
    let (status, captured) = fa_with_authority(
        &args,
        Files {
            cwd: Some(fixture.dir.clone()),
            stdin: Stdin::Forwarded(array(&[fixture.entries[0].0.clone()])),
        },
        &renewed,
        true,
    );
    let repeated = events(&captured.stdout);
    assert_eq!(status, 0, "{repeated:?}");
    assert_eq!(repeated.len(), 1);
    assert_eq!(
        data(&repeated[0]).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for key in [
        "supplement_vid",
        "body_digest",
        "recorded_at",
        "entry_digest",
        "documents",
    ] {
        assert_eq!(data(&repeated[0]).get(key), data(&first[0]).get(key));
    }
    assert_eq!(
        fixture.open().head().unwrap().0,
        before_retry + 1,
        "only the ordinary AccessEvent is new"
    );
}

#[test]
fn attachment_groups_read_real_stdin_at_the_exact_limit_and_keep_roles_distinct() {
    let fixture = Fixture::new(2);
    let before = fixture.open().head().unwrap().0;
    let oid = &fixture.documents[0].0;
    let contract = format!("{oid}:Contract");
    let mut input = array(&fixture.targets());
    input.resize(1024 * 1024, b' ');
    let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.path)
        .args([
            "document",
            "attach",
            "--entries",
            "-",
            "--evidence",
            oid,
            "--evidence",
            &contract,
            "--json",
        ])
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = events(std::str::from_utf8(&output.stdout).unwrap());
    assert_eq!(output.len(), 2);
    for receipt in output {
        let cited = data(&receipt)
            .get("documents")
            .and_then(Json::as_arr)
            .unwrap();
        assert_eq!(
            cited.len(),
            2,
            "different registered roles are distinct citations"
        );
        let roles = cited
            .iter()
            .map(|reference| text(reference, "role"))
            .collect::<BTreeSet<_>>();
        assert_eq!(roles, BTreeSet::from(["Source", "Contract"]));
        for reference in cited {
            assert_eq!(text(reference, "document_oid"), oid);
            assert_eq!(text(reference, "doc_commit"), fixture.documents[0].1);
        }
    }
    assert_eq!(fixture.open().head().unwrap().0, before + 2);
}

#[test]
fn attachment_groups_record_and_retry_1091_targets_with_one_held_book() {
    let fixture = Fixture::new(1091);
    let mut book = fixture.open();
    let before = book.head().unwrap().0;
    let input = array(&fixture.targets());
    let (status, first) = fixture.attach(&mut book, input.clone(), &fixture.refs());
    assert_eq!(status, 0, "attachment group failed: {:?}", first.last());
    assert_eq!(first.len(), 1091);
    assert_eq!(book.head().unwrap().0, before + 1091);
    let mut supplements = BTreeSet::new();
    for (index, (receipt, (entry, digest))) in first.iter().zip(&fixture.entries).enumerate() {
        assert_eq!(text(receipt, "event"), "evidence_attached");
        assert_eq!(text(data(receipt), "entry"), entry);
        assert_eq!(text(data(receipt), "entry_digest"), digest);
        assert_eq!(
            data(receipt).get("documents"),
            Some(&fixture.expected_documents())
        );
        assert_eq!(
            integer(data(receipt), "recorded_at"),
            i128::from(before) + index as i128 + 1
        );
        assert!(supplements.insert(text(data(receipt), "supplement_vid")));
    }
    let (status, repeated) = fixture.attach(&mut book, input, &fixture.refs());
    assert_eq!(status, 0, "{:?}", repeated.last());
    assert_eq!(repeated.len(), 1091);
    assert_eq!(book.head().unwrap().0, before + 1091);
    for (old, retry) in first.iter().zip(&repeated) {
        for key in [
            "supplement_vid",
            "entry",
            "entry_digest",
            "documents",
            "body_digest",
            "recorded_at",
        ] {
            assert_eq!(data(old).get(key), data(retry).get(key), "{key}");
        }
        assert_eq!(data(retry).get("already_recorded"), Some(&Json::Bool(true)));
    }
    drop(book);
    let reopened = fixture.open();
    assert_eq!(reopened.head().unwrap().0, before + 1091);
    for index in [0, 1090] {
        let retained = reopened
            .explain_entry_evidence(vid(&fixture.entries[index].0))
            .unwrap()
            .unwrap();
        assert_eq!(retained.supplements.len(), 1);
        assert_eq!(
            retained.supplements[0].recorded_at.0,
            before + index as u64 + 1
        );
        assert_eq!(retained.supplements[0].documents.len(), 4);
        assert_eq!(hex(&retained.entry_digest), fixture.entries[index].1);
    }
}

#[test]
fn attachment_groups_bound_the_real_daemon_frame_and_remain_outside_mcp() {
    let registry = fa_cli::verbs::registry().unwrap();
    assert!(
        registry
            .verbs
            .iter()
            .find(|verb| verb.name == "document")
            .unwrap()
            .flags
            .iter()
            .any(|flag| flag == "--entries")
    );
    let parsed = fa_registry::toml::parse(fa_cli::verbs::SOURCE).unwrap();
    let steward = parsed.arrays["mcp.tool"]
        .iter()
        .find(|tool| {
            tool.get("verb").and_then(fa_registry::toml::Value::as_str) == Some("document")
                && tool.get("name").and_then(fa_registry::toml::Value::as_str) == Some("steward")
        })
        .unwrap();
    assert!(
        steward["flags"]
            .as_array()
            .unwrap()
            .iter()
            .all(|flag| flag.as_str() != Some("--entries")),
        "group attachments need equivalent MCP per-target controls before exposure"
    );

    // At most4096 envelopes and16384 citations. The4-citations×4096
    // corner maximizes both simultaneously; larger per-entry lists reduce
    // envelope count. Use the actual robot and daemon serializers, the
    // longest encoded role, maximum sequences, all finite ops, and a256-byte
    // issued principal whose control characters expand twice on the wire.
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    let role = policy
        .roles
        .iter()
        .max_by_key(|role| s(&role.name).render().len())
        .unwrap()
        .name
        .as_str();
    let citation = obj(vec![
        ("document_oid", s("ff".repeat(32))),
        ("doc_commit", s("ff".repeat(32))),
        ("role", s(role)),
    ]);
    let receipt = obj(vec![
        ("supplement_vid", s("ff".repeat(16))),
        ("entry", s("ff".repeat(16))),
        ("entry_digest", s("ff".repeat(32))),
        ("documents", Json::Arr(vec![citation; 4])),
        ("body_digest", s("ff".repeat(32))),
        ("recorded_at", Json::Int(i128::from(u64::MAX))),
        ("already_recorded", Json::Bool(false)),
    ]);
    let mut line = fa_cli::cli::robot_line(
        "evidence_attached",
        receipt,
        Some(&fa_cli::cli::At {
            book: "ff".repeat(16),
            branch: "trunk".into(),
            known_at: CommitSeq(u64::MAX),
            effective: "all".into(),
        }),
        &[],
    );
    let Json::Obj(fields) = &mut line else {
        panic!("robot envelope")
    };
    let (_, authority) = fields
        .iter_mut()
        .find(|(key, _)| key == "authority")
        .unwrap();
    let principal = "\u{1}".repeat(fa_policy::capability::MAX_TOKEN_PRINCIPAL_BYTES);
    let secret = [0x52; 32];
    let capability = Capability::new(
        fa_model::principal_vid(&principal),
        Profile::Human,
        &Op::ALL,
        fa_model::principal_vid("attachment-frame-issuer"),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret));
    let token = CapabilityToken::new(principal, capability, secret).unwrap();
    *authority = LaunchAuthority::from_operator_token(std::env::temp_dir(), None, &token)
        .unwrap()
        .envelope_json();
    let line = format!("{}\n", line.render());
    registry.check_line(line.trim_end()).unwrap();
    let response = fa_cli::wire::Response {
        op: fa_cli::wire::Op::Run,
        exit: 0,
        stdout: line.repeat(4096),
        stderr: String::new(),
    };
    let encoded = response.to_json(registry.daemon.protocol).render();
    let frame = fa_cli::wire::encode(encoded.as_bytes(), registry.daemon.max_frame_bytes).unwrap();
    assert!(
        encoded.len() < registry.daemon.max_frame_bytes / 2,
        "bounded group lost its substantial wire margin: {} bytes",
        encoded.len()
    );
    assert_eq!(frame.len(), encoded.len() + fa_cli::wire::PREFIX_BYTES);
    assert_eq!(
        u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
        encoded.len()
    );
}
