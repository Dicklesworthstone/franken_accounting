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
    let input = group(std::slice::from_ref(&digest));
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
    let execute = |stdin, sign_key: Option<&str>| {
        let mut args = args.to_vec();
        if let Some(path) = sign_key {
            args.extend(["--sign-key".to_owned(), path.to_owned()]);
        }
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(fixture.dir.clone()),
                stdin,
            },
            &authority,
            true,
        );
        (status, events(&captured.stdout))
    };
    let (status, output) = execute(Stdin::Forwarded(input.as_bytes().to_vec()), None);
    assert_eq!(status, 7, "{output:?}");
    assert_eq!(
        output.len(),
        2,
        "one durable approval followed by the refusal"
    );
    assert_eq!(text(&output[0], "event"), "approved");
    assert_eq!(text(data(&output[0]), "approved_digest"), requested[0]);
    assert_eq!(text(&output[1], "event"), "error");
    assert_eq!(text(data(&output[1]), "refusal_id"), "FA-REF-014");
    let after = head(&fixture.book);
    assert_eq!(after, i128::from(before_issue.0 + 2));
    let missing_key = fixture.dir.join("missing-principal.key");
    assert!(!missing_key.exists());
    let malformed_key = fixture.file("malformed-principal.key", "not a principal signing key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&malformed_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    for sign_key in [
        None,
        Some(missing_key.to_str().unwrap()),
        Some(malformed_key.as_str()),
    ] {
        for stdin in [
            Stdin::Forwarded(input.as_bytes().to_vec()),
            Stdin::Missing,
            Stdin::Forwarded(b"[".to_vec()),
            Stdin::Forwarded(vec![b' '; 1024 * 1024 + 1]),
        ] {
            let (status, retry) = execute(stdin, sign_key);
            assert_eq!(status, 7, "{retry:?}");
            assert_eq!(
                retry.len(),
                1,
                "expired authority neither recovers a receipt nor observes group input or signing-key files"
            );
            assert_eq!(text(&retry[0], "event"), "error");
            assert_eq!(text(data(&retry[0]), "refusal_id"), "FA-REF-014");
            assert_eq!(head(&fixture.book), after);
        }
    }
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

#[test]
fn approval_groups_bind_each_signed_proposal_and_check_current_keys_on_retry() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let requested = digests(&prepared);
    assert_eq!(requested.len(), 2);
    let input = group(&requested);
    let who = "signed-group-reviewer";
    let create_key = |name: &str| {
        let path = fixture.dir.join(name).display().to_string();
        let created = ok(&fixture.book, &["principal", "key", "new", "--out", &path]);
        (path, text(data(&created), "key_id").to_owned())
    };
    let (first_key, first_key_id) = create_key("signed-first.key");
    let (next_key, _) = create_key("signed-next.key");
    let (wrong_key, _) = create_key("signed-stranger.key");
    let added = ok(
        &fixture.book,
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &first_key,
            "--as",
            who,
        ],
    );
    assert_eq!(integer(data(&added), "generation"), 0);
    let signed = |selection: &str, key: &str| {
        run_events(
            &fixture.book,
            &[
                "approve",
                "--proposals",
                selection,
                "--as",
                who,
                "--sign-key",
                key,
            ],
        )
    };
    let before = head(&fixture.book);
    let (status, refused) = signed(&input, &wrong_key);
    assert_eq!(status, 7, "{refused:?}");
    assert_eq!(refused.len(), 1);
    assert_eq!(text(data(&refused[0]), "refusal_id"), "FA-REF-205");
    assert_eq!(head(&fixture.book), before);

    let (status, approvals) = signed(&input, &first_key);
    assert_eq!(status, 0, "{approvals:?}");
    assert_eq!(approvals.len(), requested.len());
    assert_eq!(head(&fixture.book), before + requested.len() as i128);
    for (index, (receipt, digest)) in approvals.iter().zip(&requested).enumerate() {
        assert_eq!(text(receipt, "event"), "approved");
        assert_eq!(text(data(receipt), "approved_digest"), digest);
        assert_eq!(
            integer(data(receipt), "recorded_at"),
            before + index as i128 + 1
        );
    }

    // Consume both signatures through the ordinary native two-person law.
    // Only staging/finalization makes their approved proposals visible.
    let (status, independent) = run_events(
        &fixture.book,
        &[
            "approve",
            "--proposals",
            &input,
            "--as",
            "signed-group-second-reviewer",
        ],
    );
    assert_eq!(status, 0, "{independent:?}");
    assert_eq!(independent.len(), requested.len());
    assert_eq!(fixture.cash(None), "0.00 USD");
    for index in 0..requested.len() {
        fixture.stage(
            text(data(&prepared), "package_oid"),
            index,
            &[
                text(data(&approvals[index]), "approval_vid"),
                text(data(&independent[index]), "approval_vid"),
            ],
        );
    }
    assert_eq!(fixture.cash(None), "0.00 USD");
    fixture.finalize("signed-group-finalization.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");

    let rotated = ok(
        &fixture.book,
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &next_key,
            "--endorse-key",
            &first_key,
            "--as",
            who,
        ],
    );
    assert_eq!(integer(data(&rotated), "generation"), 1);
    let after_rotation = head(&fixture.book);
    // A stale key cannot use an old receipt to bypass the current key check.
    // A new signature cannot overwrite the old same-epoch approval identity.
    for (key, exit, refusal) in [
        (first_key.as_str(), 7, "FA-REF-205"),
        (next_key.as_str(), 6, "FA-REF-032"),
    ] {
        let (status, refused) = signed(&input, key);
        assert_eq!(status, exit, "{refused:?}");
        assert_eq!(refused.len(), 1);
        assert_eq!(text(data(&refused[0]), "refusal_id"), refusal);
        assert_eq!(head(&fixture.book), after_rotation);
    }
    let new_digests = ["6d".repeat(32), "6e".repeat(32)];
    assert!(new_digests.iter().all(|digest| !requested.contains(digest)));
    let (status, fresh) = signed(&group(&new_digests), &next_key);
    assert_eq!(status, 0, "{fresh:?}");
    assert_eq!(fresh.len(), 2);
    for (receipt, digest) in fresh.iter().zip(&new_digests) {
        assert_eq!(text(data(receipt), "approved_digest"), digest);
        assert_eq!(
            data(receipt).get("already_recorded"),
            Some(&Json::Bool(false))
        );
    }
    assert_eq!(head(&fixture.book), after_rotation + 2);
    let (status, verified) = run_events(&fixture.book, &["verify", "book"]);
    assert_eq!(status, 0, "{verified:?}");
    let verdict = verified.last().expect("complete book verification verdict");
    assert_eq!(text(verdict, "event"), "book_verification");
    assert_eq!(data(verdict).get("green"), Some(&Json::Bool(true)));
    assert!(
        rows(data(verdict), "targets")
            .iter()
            .all(|target| text(target, "verdict") == "pass")
    );

    // The outsider verifier checks both cited signatures independently of
    // CLI/kernel admission, retaining generation zero through the rotation.
    ok(
        &fixture.book,
        &["checkpoint", "create", "--grant", "witness"],
    );
    let bundle_path = fixture.dir.join("signed-group.fab");
    let receipt_path = fixture.dir.join("signed-group.receipt");
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--out",
            &bundle_path.display().to_string(),
            "--receipt-out",
            &receipt_path.display().to_string(),
        ],
    );
    let unhex = |value: &str| -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    let checkpoint_key: [u8; 32] = unhex(text(data(&produced), "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let bundle = std::fs::read(&bundle_path).unwrap();
    let receipt = std::fs::read(&receipt_path).unwrap();
    let report = fa_verify::verify_bundle(&bundle, &[checkpoint_key], Some(&receipt)).unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert!(report.receipt.is_some());
    let summary = report.summary.approvals.expect("signed approval section");
    assert_eq!(summary.signed, 2);
    assert_eq!(summary.key_records, 2);
    for approval in &approvals {
        let identity = text(data(approval), "approval_vid");
        let checked = report
            .checks
            .iter()
            .find(|check| {
                check.check == "approval"
                    && check.subject.starts_with(&format!("approval {identity} "))
            })
            .expect("each selected proposal has a verified retained approval");
        assert_eq!(checked.grade, fa_verify::Grade::Pass);
        assert!(checked.subject.ends_with("signed by key generation 0"));
    }

    // Copy one valid signature onto the other proposal in the real bundle.
    // Each must fail its own exact digest check despite both sharing a signer.
    let mut trailer = vec![1, 0, 0, 0, 0, 0];
    trailer.extend_from_slice(&unhex(&first_key_id));
    let positions: Vec<_> = bundle
        .windows(trailer.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == trailer.as_slice()).then_some(at + 6))
        .collect();
    assert_eq!(positions.len(), 2);
    let mut signatures = std::collections::BTreeMap::new();
    for key_at in positions {
        let digest = hex(&bundle[key_at - 49..key_at - 17]);
        assert!(requested.contains(&digest));
        assert!(signatures.insert(digest, key_at + 32).is_none());
    }
    for index in 0..requested.len() {
        let target = signatures[&requested[index]];
        let other = signatures[&requested[1 - index]];
        assert_ne!(&bundle[target..target + 64], &bundle[other..other + 64]);
        let mut forged = bundle.clone();
        forged[target..target + 64].copy_from_slice(&bundle[other..other + 64]);
        let checked = fa_verify::verify_bundle(&forged, &[checkpoint_key], None).unwrap();
        assert!(!checked.verified());
        let identity = text(data(&approvals[index]), "approval_vid");
        assert!(checked.checks.iter().any(|check| {
            check.check == "approval"
                && check.subject.starts_with(&format!("approval {identity} "))
                && matches!(&check.grade, fa_verify::Grade::Fail(why) if why.contains("not generation 0's signature"))
        }), "{:?}", checked.checks);
    }
}
