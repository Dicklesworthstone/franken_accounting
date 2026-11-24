//! A principal keeps its signing key while the daemon owns the writer lease.
//! Exercise the public preparation and detached commit over a real Unix socket.

use super::*;

fn daemon_head(book: &str) -> u64 {
    let (exit, out, error) = fad(&["status", "--book", book, "--json"]);
    assert_eq!(exit, 0, "{out}{error}");
    field(&out, "known_at")
        .expect("daemon's current coordinate")
        .parse()
        .expect("numeric frontier")
}

#[test]
fn client_signs_approval_while_fad_keeps_the_writer_lease_and_cannot_read_key_files() {
    let dir = tmp("client-signing");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let current_key = dir.join("controller.key").display().to_string();
    let wrong_key = dir.join("unrelated.key").display().to_string();
    let token_path = dir.join("controller.token").display().to_string();
    for key in [&current_key, &wrong_key] {
        ok(&["principal", "key", "new", "--out", key, "--json"]);
    }
    ok(&[
        "principal",
        "key",
        "add",
        "--sign-key",
        &current_key,
        "--as",
        "controller",
        "--date",
        "2026-03-15",
        "--key",
        "controller-signing-key",
        "--book",
        &b,
        "--via",
        "direct",
        "--json",
    ]);
    ok(&[
        "capability",
        "issue",
        "--holder",
        "controller",
        "--profile",
        "human",
        "--op",
        "read",
        "--op",
        "approve",
        "--book-scope",
        "--out",
        &token_path,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--grant",
        "approve",
        "--book",
        &b,
        "--json",
    ]);
    let token = std::fs::read(&token_path).expect("issued holder token");
    let digest = "4a".repeat(32);
    let reg = registry().expect("verbs.toml");
    let socket = book.join(&reg.daemon.socket);
    // The daemon has no files-root grant. The client's key path can only be
    // resolved in the client process; publication must still use the daemon.
    let mut daemon = start_without_files_root(&book);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(Lease::holder(&book, &reg.daemon.lease).is_some());
        let before = daemon_head(&b);
        let prepared = ok(&[
            "approve",
            "--proposal",
            &digest,
            "--prepare-signature",
            "--token",
            &token_path,
            "--book",
            &b,
            "--via",
            "fad",
            "--json",
        ]);
        assert_eq!(checked(&prepared), vec!["approval_signing_request"]);
        assert_eq!(daemon_head(&b), before, "preparation publishes nothing");

        let signed = |key: &str| {
            fa(&[
                "approve",
                "--proposal",
                &digest,
                "--sign-key",
                key,
                "--token",
                &token_path,
                "--book",
                &b,
                "--via",
                "fad",
                "--json",
            ])
        };
        let (exit, out, error) = signed(&wrong_key);
        assert_eq!(exit, 7, "{out}{error}");
        assert!(out.contains("FA-REF-205"), "{out}{error}");
        assert_eq!(daemon_head(&b), before);

        // Automatic remote signing needs an independently book-scoped token.
        // Disable any ambient FA_TOKEN so this remains an actual missing-token
        // request even when the test runner itself was launched with one.
        let argv = [
            "approve",
            "--proposal",
            &digest,
            "--sign-key",
            &current_key,
            "--as",
            "controller",
            "--book",
            &b,
            "--via",
            "fad",
            "--json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let (exit, out) =
            fa_cli::entry::fa_with_env_token(&argv, None, fa_cli::cli::Files::default(), true);
        checked(&out.stdout);
        assert_ne!(exit, 0, "{}{}", out.stdout, out.stderr);
        assert_eq!(daemon_head(&b), before);

        // A caller bypassing the client exchange still cannot make the daemon
        // load a principal key. Only public preparation and signature arguments
        // are accepted by the supported flow.
        let raw = client::call(
            &socket,
            &Request {
                op: Op::Run,
                argv: [
                    "approve",
                    "--proposal",
                    &digest,
                    "--sign-key",
                    &current_key,
                    "--book",
                    &b,
                    "--json",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                cwd: None,
                stdin: None,
                token: Some(token.clone()),
            },
            &reg.daemon,
        )
        .unwrap();
        assert_ne!(raw.exit, 0, "{}{}", raw.stdout, raw.stderr);
        checked(&raw.stdout);
        assert_eq!(daemon_head(&b), before);

        let (exit, approved, error) = signed(&current_key);
        assert_eq!(exit, 0, "{approved}{error}");
        assert_eq!(checked(&approved), vec!["approved"]);
        assert_eq!(field(&approved, "already_recorded"), Some("false"));
        assert_eq!(field(&approved, "approved_digest"), Some(digest.as_str()));
        let approval_vid = field(&approved, "approval_vid").unwrap().to_string();
        let recorded_at = field(&approved, "recorded_at").unwrap().to_string();
        let recorded_head = daemon_head(&b);
        assert_eq!(recorded_head, before + 1);
        assert!(Lease::holder(&book, &reg.daemon.lease).is_some());

        let (exit, retry, error) = signed(&current_key);
        assert_eq!(exit, 0, "{retry}{error}");
        assert_eq!(field(&retry, "already_recorded"), Some("true"));
        assert_eq!(field(&retry, "approval_vid"), Some(approval_vid.as_str()));
        assert_eq!(field(&retry, "recorded_at"), Some(recorded_at.as_str()));
        assert_eq!(daemon_head(&b), recorded_head);

        // A signature must not install a credential on the resident handle.
        // Even an exact retry must still carry the current principal signature.
        let (exit, out, error) = fa(&[
            "approve",
            "--proposal",
            &digest,
            "--token",
            &token_path,
            "--book",
            &b,
            "--via",
            "fad",
            "--json",
        ]);
        assert_eq!(exit, 7, "{out}{error}");
        assert!(out.contains("FA-REF-205"), "{out}{error}");
        assert_eq!(daemon_head(&b), recorded_head);
        (approval_vid, recorded_at)
    }));

    // Always release the owned process and writer lease, including on failure.
    let (stop_exit, stopped, stop_error) = fad(&["stop", "--book", &b, "--json"]);
    if stop_exit != 0 && daemon.child.try_wait().ok().flatten().is_none() {
        let _ = daemon.child.kill();
    }
    let (exit, rest) = daemon.finish();
    let (approval_vid, recorded_at) = match result {
        Ok(recorded) => recorded,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert_eq!(stop_exit, 0, "{stopped}{stop_error}");
    assert_eq!(exit, 0, "{rest}");
    assert_eq!(checked(&rest), vec!["fad_stopped"]);
    assert_eq!(Lease::holder(&book, &reg.daemon.lease), None);

    // The existing direct signer recognizes the same durable signature and
    // outcome after the daemon closes; the exchange created no second dialect.
    let reopened = ok(&[
        "approve",
        "--proposal",
        &digest,
        "--sign-key",
        &current_key,
        "--token",
        &token_path,
        "--book",
        &b,
        "--via",
        "direct",
        "--json",
    ]);
    assert_eq!(field(&reopened, "already_recorded"), Some("true"));
    assert_eq!(
        field(&reopened, "approval_vid"),
        Some(approval_vid.as_str())
    );
    assert_eq!(field(&reopened, "recorded_at"), Some(recorded_at.as_str()));
}
