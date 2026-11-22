//! Selected Canon rules enter owned drafts through the CLI, retain their
//! native intent across restarts, and revalidate activation at promotion.

use super::*;

const SOURCE: &str = r#"rule draft_accrual v1 for event Sale produces Adjusting {
  authority {
    debit "1000" upto "40.00 USD"
    credit "6000" upto "40.00 USD"
  }
  let net = event.resource("net", "USD")
  debit "1000" net
  credit "6000" net
}"#;

fn ok(book: &Path, args: &[&str]) -> String {
    let (code, out, err) = fa(Some(book), args);
    assert_eq!(code, 0, "{args:?}\n{out}\n{err}");
    out
}

fn open(book: &Path) -> fa::Book {
    let keys = fa::BookKeys::load(&book.join("book.keys")).unwrap();
    fa::Book::open_dir(book, keys, fa::Entropy::deterministic(0xc34)).unwrap()
}

fn activate(book: &Path, dir: &Path, version: u32, from: &str) -> String {
    let source = write(
        dir,
        &format!("draft-v{version}.rule"),
        &SOURCE.replace(" v1 ", &format!(" v{version} ")),
    );
    let digest = text(
        &doc(&ok(book, &["rule", "propose", &source, "--json"])),
        "ir_digest",
    )
    .to_string();
    let activation = doc(&ok(
        book,
        &[
            "rule",
            "activate",
            &digest,
            "--from",
            from,
            "--dry-run",
            "--json",
        ],
    ));
    let path = write(
        dir,
        &format!("draft-v{version}.activation"),
        text(&activation, "bytes"),
    );
    let proposal = text(&activation, "proposal_digest");
    let approve = |who: &str| {
        text(
            &doc(&ok(
                book,
                &["approve", "--proposal", proposal, "--as", who, "--json"],
            )),
            "approval_vid",
        )
        .to_string()
    };
    let (a, b) = (approve("controller-a"), approve("controller-b"));
    ok(
        book,
        &[
            "rule",
            "activate",
            "--plan",
            &path,
            "--approval",
            &a,
            "--approval",
            &b,
            "--json",
        ],
    );
    digest
}

fn fixture(name: &str) -> std::io::Result<(PathBuf, PathBuf, String)> {
    let (book, evidence, dir) = envelope_book(name)?;
    ok(
        &book,
        &[
            "event",
            "record",
            "--code",
            "EV-DRAFT",
            "--kind",
            "sale",
            "--occurred-on",
            "2026-03-12",
            "--evidence",
            &evidence,
            "--resource",
            "net:40.00 USD",
            "--json",
        ],
    );
    let digest = activate(&book, &dir, 1, "2026-03-01");
    Ok((book, dir, digest))
}

#[test]
fn selected_rule_and_business_aliases_retain_one_agent_draft_for_independent_promotion()
-> std::io::Result<()> {
    use fa_cli::authority::{LaunchAuthority, LaunchProfile};
    use fa_cli::cli::Files;
    use fa_cli::entry::fa_with_authority;

    let (book, _, digest) = fixture("canon-agent-draft")?;
    let authority = LaunchAuthority::new(
        book.clone(),
        None,
        "canon-agent",
        LaunchProfile::Agent,
        &["read", "post"],
    )
    .unwrap();
    let invoke = |args: &[&str]| {
        let argv = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        let (code, captured) = fa_with_authority(&argv, Files::default(), &authority, true);
        check_robot_output(args, i32::from(code), &captured.stdout);
        assert_eq!(code, 0, "{args:?}: {captured:?}");
        captured.stdout
    };
    invoke(&["draft", "new", "rule-review", "--json"]);
    let planned = invoke(&[
        "rule",
        "derive",
        "--rule",
        &digest,
        "--event",
        "EV-DRAFT",
        "--draft",
        "rule-review",
        "--json",
    ]);
    assert_eq!(text(&robot_line(&planned), "event"), "draft_planned");
    let receipt = doc(&planned);
    assert_eq!(receipt.get("already_recorded"), Some(&Json::Bool(false)));
    let entry = fgdb_types::VId(u128::from_str_radix(text(&receipt, "entry"), 16).unwrap());
    let retained = open(&book).draft("rule-review").unwrap().unwrap();
    assert_eq!(retained.intents.len(), 1);
    let member = &retained.intents[0];
    assert_eq!(member.intent.proposal().principal_ref, retained.body.owner);
    assert_eq!(
        member.intent.proposal().class,
        fa_model::EntryClass::ADJUSTING
    );
    assert!(matches!(
        &member.intent.proposal().origin,
        fa_model::EntryOrigin::Rule { .. }
    ));
    let reviewed = member.resolved_entry.clone().expect("exact reviewed entry");
    assert!(open(&book).read_entry(entry).unwrap().is_none());

    // Both business names share the selected rule's semantic key and retained
    // capability. Freshly sealed CLI proposals recover the same Plan record.
    for verb in ["accrue", "defer"] {
        let retry = doc(&invoke(&[
            verb,
            "--rule",
            &digest,
            "--event",
            "EV-DRAFT",
            "--draft",
            "rule-review",
            "--json",
        ]));
        assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
        assert_eq!(
            text(&retry, "control_entry"),
            text(&receipt, "control_entry")
        );
        assert_eq!(int(&retry, "recorded_at"), int(&receipt, "recorded_at"));
        assert_eq!(open(&book).draft("rule-review").unwrap().unwrap(), retained);
        assert!(open(&book).read_entry(entry).unwrap().is_none());
    }

    // A read-only launch cannot reuse the otherwise valid draft request.
    let read_only = LaunchAuthority::new(
        book.clone(),
        None,
        "canon-agent",
        LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let args = [
        "rule",
        "derive",
        "--rule",
        &digest,
        "--event",
        "EV-DRAFT",
        "--draft",
        "rule-review",
        "--json",
    ];
    let argv = args
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();
    let (code, captured) = fa_with_authority(&argv, Files::default(), &read_only, true);
    check_robot_output(&args, i32::from(code), &captured.stdout);
    assert_eq!(code, 7, "{captured:?}");
    assert_eq!(open(&book).draft("rule-review").unwrap().unwrap(), retained);
    assert!(open(&book).read_entry(entry).unwrap().is_none());

    let promoted = doc(&ok(
        &book,
        &[
            "draft",
            "promote",
            "rule-review",
            "--as",
            "controller",
            "--yes",
            "--json",
        ],
    ));
    assert_eq!(
        arr(&promoted, "entries"),
        &[Json::Str(format!("{:032x}", entry.0))]
    );
    let (published, at) = open(&book).read_entry(entry).unwrap().unwrap();
    assert_eq!(published, reviewed);
    assert_eq!(Some(i128::from(at.0)), int(&promoted, "recorded_at"));
    let head = open(&book).head().unwrap();
    let retry = doc(&ok(
        &book,
        &[
            "draft",
            "promote",
            "rule-review",
            "--as",
            "controller",
            "--yes",
            "--json",
        ],
    ));
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(int(&retry, "recorded_at"), int(&promoted, "recorded_at"));
    assert_eq!(open(&book).head().unwrap(), head);
    Ok(())
}

#[test]
fn selected_rule_draft_promotion_refuses_a_new_activation_even_with_equal_legs()
-> std::io::Result<()> {
    let (book, dir, digest) = fixture("canon-stale-draft")?;
    ok(
        &book,
        &["draft", "new", "stale-rule", "--as", "preparer", "--json"],
    );
    let planned = doc(&ok(
        &book,
        &[
            "rule",
            "derive",
            "--rule",
            &digest,
            "--event",
            "EV-DRAFT",
            "--draft",
            "stale-rule",
            "--as",
            "preparer",
            "--json",
        ],
    ));
    let entry = fgdb_types::VId(u128::from_str_radix(text(&planned, "entry"), 16).unwrap());
    let retained = open(&book).draft("stale-rule").unwrap().unwrap();
    assert!(open(&book).read_entry(entry).unwrap().is_none());

    // The new version derives identical amounts, but the reviewed request
    // still binds v1. Promotion must not silently substitute the active v2.
    let replacement = activate(&book, &dir, 2, "2026-03-10");
    assert_ne!(replacement, digest);
    let head = open(&book).head().unwrap();
    let (code, out, err) = fa(
        Some(&book),
        &[
            "draft",
            "promote",
            "stale-rule",
            "--as",
            "controller",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (3, Some("FA-REF-196")),
        "{out}\n{err}"
    );
    assert!(out.contains("not in force"), "{out}");
    assert_eq!(open(&book).head().unwrap(), head);
    assert_eq!(open(&book).draft("stale-rule").unwrap().unwrap(), retained);
    assert!(open(&book).read_entry(entry).unwrap().is_none());
    Ok(())
}

#[test]
fn rule_draft_option_conflicts_refuse_before_reading_sources() -> std::io::Result<()> {
    let (book, _, dir) = envelope_book("canon-draft-options")?;
    let digest = "12".repeat(32);
    let missing = dir.join("missing.rule");
    let missing = missing.to_str().unwrap();
    let path = dir.join("must-not-exist.plan");
    let path_text = path.to_str().unwrap();
    let cases = [
        vec!["rule", "derive", "--event", "MISSING", "--draft", "review"],
        vec![
            "rule",
            "derive",
            "--rule",
            &digest,
            "--event",
            "MISSING",
            "--draft",
            "review",
            "--dry-run",
        ],
        vec![
            "rule",
            "derive",
            "--rule",
            &digest,
            "--event",
            "MISSING",
            "--draft",
            "review",
            "--dry-run",
            "--plan-out",
            path_text,
        ],
        vec![
            "rule", "derive", "--rule", &digest, "--event", "MISSING", "--draft", "review",
            "--draft", "other",
        ],
        vec!["rule", "check", missing, "--draft", "review"],
        vec!["rule", "propose", missing, "--draft", "review"],
        vec!["rule", "activate", &digest, "--draft", "review"],
        vec![
            "accrue",
            "--rule",
            &digest,
            "--event",
            "MISSING",
            "--draft",
            "review",
            "--dry-run",
        ],
        vec![
            "defer",
            "--rule",
            &digest,
            "--event",
            "MISSING",
            "--draft",
            "review",
            "--dry-run",
        ],
    ];
    let head = open(&book).head().unwrap();
    for mut args in cases {
        args.push("--yes");
        args.push("--json");
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 2, "{args:?}\n{out}\n{err}");
        assert!(text(&doc(&out), "message").contains("--draft"), "{out}");
        assert_eq!(open(&book).head().unwrap(), head);
        assert!(!path.exists());
    }
    Ok(())
}
