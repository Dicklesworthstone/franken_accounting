use super::*;

fn digests(prepared: &Json) -> Vec<String> {
    rows(data(prepared), "chunks")
        .iter()
        .map(|chunk| text(chunk, "proposal_digest").to_owned())
        .collect()
}

fn group(values: &[String]) -> String {
    Json::Arr(values.iter().map(|value| s(value.as_str())).collect()).render()
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

fn forwarded(fixture: &Fixture, bytes: Vec<u8>) -> (u8, Vec<Json>) {
    let mut book = fixture.open();
    let args = ["approve", "--proposals", "-", "--json"].map(str::to_owned);
    let (status, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        None,
        Some(fixture.dir.clone()),
        Stdin::Forwarded(bytes),
        true,
    );
    (status, events(&captured.stdout))
}

#[test]
fn approval_groups_preserve_order_retry_identity_and_independent_reviewers() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    let mut requested = digests(&prepared);
    assert_eq!(requested.len(), 2);
    requested.reverse();
    let input = group(&requested);
    let before = head(&fixture.book);
    let (status, first) = run_events(
        &fixture.book,
        &[
            "approve",
            "--proposals",
            &input,
            "--as",
            "group-reviewer-one",
        ],
    );
    assert_eq!(status, 0, "{first:?}");
    assert_eq!(first.len(), 2);
    assert_eq!(head(&fixture.book), before + 2);
    for (receipt, digest) in first.iter().zip(&requested) {
        assert_eq!(text(receipt, "event"), "approved");
        assert_eq!(text(data(receipt), "approved_digest"), digest);
        assert_eq!(
            data(receipt).get("already_recorded"),
            Some(&Json::Bool(false))
        );
    }
    let after = head(&fixture.book);
    let (status, retry) = run_events(
        &fixture.book,
        &[
            "approve",
            "--proposals",
            &input,
            "--as",
            "group-reviewer-one",
        ],
    );
    assert_eq!(status, 0);
    assert_eq!(head(&fixture.book), after);
    for (old, repeated) in first.iter().zip(&retry) {
        assert_eq!(
            data(old).get("approval_vid"),
            data(repeated).get("approval_vid")
        );
        assert_eq!(
            data(old).get("recorded_at"),
            data(repeated).get("recorded_at")
        );
        assert_eq!(
            data(repeated).get("already_recorded"),
            Some(&Json::Bool(true))
        );
    }
    // Recording several digests never supplies a second principal for one digest.
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--chunk",
            "0",
            "--approval",
            text(data(&first[1]), "approval_vid"),
        ],
    );
    assert_eq!(status, 7, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-012");
    assert_eq!(head(&fixture.book), after);
    let (status, second) = run_events(
        &fixture.book,
        &[
            "approve",
            "--proposals",
            &input,
            "--as",
            "group-reviewer-two",
        ],
    );
    assert_eq!(status, 0);
    for index in 0..2 {
        let first_vid = text(data(&first[1 - index]), "approval_vid");
        let second_vid = text(data(&second[1 - index]), "approval_vid");
        assert_ne!(first_vid, second_vid);
        fixture.stage(package, index, &[first_vid, second_vid]);
    }
    fixture.finalize("approval-group-finalize.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");
}

#[test]
fn approval_groups_prevalidate_every_member_and_bound_forwarded_input() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let digest = digests(&prepared).remove(0);
    let valid = s(&digest).render();
    let alias = s(digest.to_ascii_uppercase()).render();
    let cases = vec![
        b"[]".to_vec(),
        b"{}".to_vec(),
        b"[".to_vec(),
        format!("[{valid},\"invalid-later-member\"]").into_bytes(),
        format!("[{valid},false]").into_bytes(),
        format!("[{valid},{valid}]").into_bytes(),
        format!("[{valid},{alias}]").into_bytes(),
        group(&vec![digest.clone(); 4097]).into_bytes(),
        vec![b' '; 1024 * 1024 + 1],
        vec![0xff],
    ];
    let before = head(&fixture.book);
    for bytes in cases {
        let (status, output) = forwarded(&fixture, bytes);
        assert_eq!(status, 2, "{output:?}");
        assert_eq!(output.len(), 1);
        assert_eq!(text(&output[0], "event"), "error");
        assert_eq!(head(&fixture.book), before);
    }
    let input = group(&[digest.clone()]);
    for extra in [
        vec!["--proposal", &digest],
        vec!["--review", "-"],
        vec!["--digest", &digest],
        vec!["--proposals", &input],
        vec!["unexpected-positional"],
    ] {
        let mut args = vec!["approve", "--proposals", &input];
        args.extend(extra);
        let (status, output) = run_events(&fixture.book, &args);
        assert_eq!(status, 2, "{output:?}");
        assert_eq!(output.len(), 1);
        assert_eq!(head(&fixture.book), before);
    }
    let (status, output) = forwarded(&fixture, input.into_bytes());
    assert_eq!(status, 0, "{output:?}");
    assert_eq!(output.len(), 1);
    assert_eq!(text(&output[0], "event"), "approved");
    assert_eq!(head(&fixture.book), before + 1);
}

#[test]
fn approval_groups_read_real_process_stdin_at_the_exact_byte_limit() {
    use std::io::Write;
    use std::process::Stdio;
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let mut input = group(&digests(&prepared)).into_bytes();
    input.resize(1024 * 1024, b' ');
    let before = head(&fixture.book);
    let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.book)
        .args([
            "approve",
            "--proposals",
            "-",
            "--as",
            "process-stdin-reviewer",
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = events(std::str::from_utf8(&output.stdout).unwrap());
    assert_eq!(output.len(), 2);
    assert!(
        output
            .iter()
            .all(|event| text(event, "event") == "approved")
    );
    assert_eq!(head(&fixture.book), before + 2);
}

#[test]
fn approval_groups_record_and_retry_more_than_a_thousand_native_members() {
    let fixture = Fixture::quickbooks();
    // Native approval binds an opaque digest. Distinct deterministic fixture
    // digests exercise the same long-lived book path needed by large imports.
    let requested = (1..=1105)
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    let input = group(&requested).into_bytes();
    let before = head(&fixture.book);
    let (status, first) = forwarded(&fixture, input.clone());
    assert_eq!(status, 0, "{first:?}");
    assert_eq!(first.len(), 1105);
    assert_eq!(head(&fixture.book), before + 1105);
    for (index, (receipt, digest)) in first.iter().zip(&requested).enumerate() {
        assert_eq!(text(receipt, "event"), "approved");
        assert_eq!(text(data(receipt), "approved_digest"), digest);
        assert_eq!(
            integer(data(receipt), "recorded_at"),
            before + index as i128 + 1
        );
    }
    let (status, retry) = forwarded(&fixture, input);
    assert_eq!(status, 0, "{retry:?}");
    assert_eq!(retry.len(), 1105);
    assert_eq!(head(&fixture.book), before + 1105);
    for (old, repeated) in first.iter().zip(&retry) {
        assert_eq!(
            data(old).get("approval_vid"),
            data(repeated).get("approval_vid")
        );
        assert_eq!(
            data(old).get("recorded_at"),
            data(repeated).get("recorded_at")
        );
        assert_eq!(
            data(repeated).get("already_recorded"),
            Some(&Json::Bool(true))
        );
    }
}

#[test]
fn approval_groups_recheck_current_authority_between_members_and_before_retry() {
    use fa_policy::{CapabilityToken, Op, Profile, possession_digest};
    use fa_time::DateDay;
    use fgdb_types::CommitSeq;
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let requested = digests(&prepared);
    let input = group(&requested);
    let mut book = fixture.open();
    let issuer = Capability::embedded(
        fa_model::principal_vid("approval-group-issuer"),
        &["issue_capability", "approve"],
    )
    .unwrap();
    let before_issue = book.head().unwrap();
    let secret = [0x49; 32];
    let capability = Capability::new(
        fa_model::principal_vid("expiry-reviewer"),
        Profile::Human,
        &[Op::Approve],
        issuer.holder(),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret))
    .expiring_at(CommitSeq(before_issue.0 + 2));
    book.issue_capability(
        issuer,
        capability.clone(),
        DateDay::parse("2026-01-01").unwrap(),
        b"approval-group-expiry",
        "one publication before expiry",
    )
    .unwrap()
    .unwrap();
    let token = CapabilityToken::new("expiry-reviewer", capability, secret).unwrap();
    let authority =
        LaunchAuthority::from_operator_token(fixture.book.clone(), None, &token).unwrap();
    drop(book);
    let args = ["approve", "--proposals", "-", "--json"].map(str::to_owned);
    let execute = || {
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(fixture.dir.clone()),
                stdin: Stdin::Forwarded(input.as_bytes().to_vec()),
            },
            &authority,
            true,
        );
        (status, events(&captured.stdout))
    };
    let (status, output) = execute();
    assert_eq!(status, 7, "{output:?}");
    assert_eq!(
        output.len(),
        2,
        "one durable approval followed by the refusal"
    );
    assert_eq!(text(&output[0], "event"), "approved");
    assert_eq!(text(data(&output[0]), "approved_digest"), requested[0]);
    assert_eq!(text(&output[1], "event"), "error");
    let after = head(&fixture.book);
    assert_eq!(after, i128::from(before_issue.0 + 2));
    let (status, retry) = execute();
    assert_eq!(status, 7, "{retry:?}");
    assert_eq!(
        retry.len(),
        1,
        "expired authority cannot recover an identity receipt"
    );
    assert_eq!(text(&retry[0], "event"), "error");
    assert_eq!(head(&fixture.book), after);
}

#[test]
fn approval_groups_preserve_legacy_last_value_and_native_signing_requirements() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let requested = digests(&prepared);
    let (status, output) = run_events(
        &fixture.book,
        &[
            "approve",
            "--proposal",
            &requested[0],
            "--proposal",
            &requested[1],
            "--as",
            "legacy-reviewer",
        ],
    );
    assert_eq!(status, 0);
    assert_eq!(output.len(), 1);
    assert_eq!(text(data(&output[0]), "approved_digest"), requested[1]);
    let key = fixture.dir.join("group-reviewer.key").display().to_string();
    ok(&fixture.book, &["principal", "key", "new", "--out", &key]);
    ok(
        &fixture.book,
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &key,
            "--as",
            "signed-group-reviewer",
        ],
    );
    let input = group(&requested);
    let before = head(&fixture.book);
    let (status, output) = run_events(
        &fixture.book,
        &[
            "approve",
            "--proposals",
            &input,
            "--as",
            "signed-group-reviewer",
        ],
    );
    assert_ne!(status, 0);
    assert_eq!(output.len(), 1);
    assert_eq!(text(data(&output[0]), "refusal_id"), "FA-REF-205");
    assert_eq!(head(&fixture.book), before);
    let args = [
        "approve",
        "--proposals",
        &input,
        "--as",
        "signed-group-reviewer",
        "--sign-key",
        &key,
    ];
    let (status, first) = run_events(&fixture.book, &args);
    assert_eq!(status, 0, "{first:?}");
    assert_eq!(first.len(), 2);
    assert_eq!(head(&fixture.book), before + 2);
    let (status, repeated) = run_events(&fixture.book, &args);
    assert_eq!(status, 0, "{repeated:?}");
    assert_eq!(head(&fixture.book), before + 2);
    for (old, retry) in first.iter().zip(&repeated) {
        assert_eq!(
            data(old).get("approval_vid"),
            data(retry).get("approval_vid")
        );
        assert_eq!(data(old).get("recorded_at"), data(retry).get("recorded_at"));
        assert_eq!(data(retry).get("already_recorded"), Some(&Json::Bool(true)));
    }
}
