//! Real launch-bound correction preparation and independent atomic promotion.

use super::*;

pub(super) fn agent(f: &Fixture, principal: &str, ops: &[&str]) -> LaunchAuthority {
    LaunchAuthority::new(f.book.clone(), None, principal, LaunchProfile::Agent, ops).unwrap()
}

pub(super) fn bound(
    authority: &LaunchAuthority,
    args: &[&str],
    input: Option<&str>,
) -> (u8, Vec<Json>) {
    let mut argv: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    argv.push("--json".to_owned());
    let (exit, output) = fa_with_authority(
        &argv,
        Files {
            cwd: None,
            stdin: input.map_or(Stdin::Missing, |input| {
                Stdin::Forwarded(input.as_bytes().to_vec())
            }),
        },
        authority,
        true,
    );
    let events: Vec<Json> = output
        .stdout
        .lines()
        .map(|line| {
            fa_cli::verbs::registry()
                .unwrap()
                .check_line(line)
                .unwrap_or_else(|error| panic!("{error}: {output:?}"));
            let event = json::parse(line).unwrap();
            assert_eq!(event.get("authority"), Some(&authority.envelope_json()));
            event
        })
        .collect();
    assert!(!events.is_empty(), "{args:?}: {output:?}");
    if exit != 0 {
        assert_eq!(events.len(), 1, "{output:?}");
        assert_eq!(text(&events[0], "event"), "error", "{output:?}");
    }
    (exit, events)
}

pub(super) fn corrected(key: &str, amount: &str) -> String {
    format!(
        r#"{{"idempotency_key":"{key}","description":"Reviewed corrected amount","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#,
    )
}

pub(super) fn original(f: &Fixture) -> Json {
    ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("correction-original", "10.00"),
            "--evidence",
            &f.evidence,
        ],
    )
}

fn prepare(
    f: &Fixture,
    authority: &LaunchAuthority,
    verb: &str,
    target: &str,
    draft: &str,
    body: &str,
) -> (u8, Vec<Json>) {
    bound(
        authority,
        &[
            verb,
            target,
            "--reason",
            "WrongAmount",
            if verb == "replace" {
                "--intent"
            } else {
                "--replace-with"
            },
            "-",
            "--evidence",
            &f.evidence,
            "--draft",
            draft,
        ],
        Some(body),
    )
}

#[test]
fn an_agent_retains_a_complete_correction_for_independent_atomic_promotion() {
    for verb in ["replace", "reverse"] {
        let f = Fixture::new();
        let posted = original(&f);
        let target = text(&posted, "vid");
        let authority = agent(&f, "correction-agent", &["read", "post"]);
        assert_eq!(bound(&authority, &["draft", "new", "fix"], None).0, 0);
        let initial_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
        let before = head(&f.book);
        let body = corrected("corrected", "12.00");
        let (exit, planned) = prepare(&f, &authority, verb, target, "fix", &body);
        assert_eq!(exit, 0, "{planned:?}");
        assert_eq!(planned.len(), 2);
        assert_eq!(head(&f.book), before + 1, "one indivisible Plan record");
        assert_eq!(text(&planned[0], "event"), "draft_planned");
        assert_eq!(text(&planned[1], "event"), "draft_planned");
        assert_eq!(
            text(&planned[0], "control_entry"),
            text(&planned[1], "control_entry")
        );
        assert_eq!(
            text(&planned[0], "plan_digest"),
            text(&planned[1], "plan_digest")
        );
        for member in &planned {
            assert_eq!(
                get(
                    &ok(&f.book, &["entry", "show", text(member, "entry")]),
                    "found"
                ),
                &Json::Bool(false)
            );
        }
        assert_eq!(
            get(&ok(&f.book, &["tb", "--period", "FY2026-P03"]), "rows"),
            get(&initial_tb, "rows")
        );
        let (exit, retry) = prepare(&f, &authority, verb, target, "fix", &body);
        assert_eq!(exit, 0, "{retry:?}");
        assert!(
            retry
                .iter()
                .all(|event| get(event, "already_recorded") == &Json::Bool(true))
        );
        assert_eq!(head(&f.book), before + 1);
        let (exit, denied) = run(
            &f.book,
            &[
                "draft",
                "promote",
                "fix",
                "--as",
                "correction-agent",
                "--yes",
            ],
            None,
        );
        assert_eq!(exit, 7, "{}", denied.render());
        assert_eq!(head(&f.book), before + 1);

        // Branch reads materialize the complete native pair in scratch. The
        // bound read's access receipt may advance the control-only frontier.
        let (exit, preview) = bound(
            &authority,
            &["tb", "--period", "FY2026-P03", "--branch", "draft:fix"],
            None,
        );
        assert_eq!(exit, 0, "{preview:?}");
        assert_eq!(preview.len(), 1);
        assert_ne!(get(&preview[0], "rows"), get(&initial_tb, "rows"));
        let before_promotion = head(&f.book);
        let promoted = ok(
            &f.book,
            &["draft", "promote", "fix", "--as", "controller", "--yes"],
        );
        assert_eq!(head(&f.book), before_promotion + 1);
        assert_eq!(get(&promoted, "entries").as_arr().unwrap().len(), 2);
        for (index, member) in planned.iter().enumerate() {
            let stored = ok(&f.book, &["entry", "show", text(member, "entry")]);
            assert_eq!(text(&stored, "class"), ["Reversal", "Replacement"][index]);
            assert_eq!(
                text(&stored, "proposal_digest"),
                text(member, "proposal_digest")
            );
            assert_eq!(
                integer(&stored, "recorded_at"),
                integer(&promoted, "recorded_at")
            );
            assert_eq!(
                text(&get(&stored, "supersedes").as_arr().unwrap()[0], "entry"),
                target
            );
        }
        assert_eq!(
            get(&ok(&f.book, &["tb", "--period", "FY2026-P03"]), "rows"),
            get(&preview[0], "rows")
        );
        let (exit, retry) = prepare(&f, &authority, verb, target, "fix", &body);
        assert_eq!(exit, 0, "{retry:?}");
        assert!(
            retry
                .iter()
                .all(|event| get(event, "already_recorded") == &Json::Bool(true))
        );
        let retry = ok(
            &f.book,
            &["draft", "promote", "fix", "--as", "controller", "--yes"],
        );
        assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
        assert_eq!(head(&f.book), before_promotion + 1);
    }
}

#[test]
fn correction_drafts_refuse_mixed_members_and_incompatible_planning_modes() {
    let f = Fixture::new();
    let posted = original(&f);
    let target = text(&posted, "vid");
    let authority = agent(&f, "correction-agent", &["read", "post"]);
    for name in ["ordinary", "fix"] {
        assert_eq!(bound(&authority, &["draft", "new", name], None).0, 0);
    }
    ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("ordinary", "1.00"),
            "--evidence",
            &f.evidence,
            "--draft",
            "ordinary",
            "--as",
            "correction-agent",
        ],
    );
    let body = corrected("corrected", "12.00");
    let before = head(&f.book);
    let (exit, refused) = prepare(&f, &authority, "replace", target, "ordinary", &body);
    assert_eq!(exit, 2, "{refused:?}");
    assert_eq!(head(&f.book), before);
    let plan_path = f.dir.join("incompatible.plan");
    let plan_path_text = plan_path.to_str().unwrap();
    for flags in [
        vec!["--dry-run"],
        vec!["--dry-run", "--plan-out", plan_path_text],
    ] {
        let mut args = vec![
            "replace",
            target,
            "--reason",
            "WrongAmount",
            "--intent",
            "-",
            "--draft",
            "fix",
        ];
        args.extend(flags);
        let (exit, refused) = run(&f.book, &args, Some(body.as_bytes()));
        assert_eq!(exit, 2, "{}", refused.render());
        assert!(text(&refused, "message").contains("--draft"));
        assert_eq!(head(&f.book), before);
        assert!(!plan_path.exists());
    }
    let (exit, planned) = prepare(&f, &authority, "replace", target, "fix", &body);
    assert_eq!(exit, 0, "{planned:?}");
    let before = head(&f.book);
    let (exit, refused) = run(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("cannot-mix", "1.00"),
            "--evidence",
            &f.evidence,
            "--draft",
            "fix",
            "--as",
            "correction-agent",
        ],
        None,
    );
    assert_eq!(exit, 2, "{}", refused.render());
    assert_eq!(head(&f.book), before);
    let (exit, refused) = prepare(
        &f,
        &authority,
        "replace",
        target,
        "fix",
        &corrected("another", "13.00"),
    );
    assert_eq!(exit, 6, "{refused:?}");
    assert_eq!(head(&f.book), before);
}

#[test]
fn discarded_correction_retries_preserve_the_review_and_refuse_another_owner() {
    let f = Fixture::new();
    let posted = original(&f);
    let target = text(&posted, "vid");
    let owner = agent(&f, "correction-agent", &["read", "post"]);
    let outsider = agent(&f, "other-agent", &["read", "post"]);
    assert_eq!(bound(&owner, &["draft", "new", "fix"], None).0, 0);
    let body = corrected("corrected", "12.00");
    let before = head(&f.book);
    let (exit, refused) = prepare(&f, &outsider, "replace", target, "fix", &body);
    assert_eq!(exit, 7, "{refused:?}");
    assert_eq!(head(&f.book), before);
    let (exit, planned) = prepare(&f, &owner, "replace", target, "fix", &body);
    assert_eq!(exit, 0, "{planned:?}");
    ok(
        &f.book,
        &["draft", "discard", "fix", "--as", "correction-agent"],
    );
    let before = head(&f.book);
    let (exit, retry) = prepare(&f, &owner, "replace", target, "fix", &body);
    assert_eq!(exit, 0, "{retry:?}");
    assert!(
        retry
            .iter()
            .all(|event| get(event, "already_recorded") == &Json::Bool(true))
    );
    let (exit, refused) = prepare(
        &f,
        &owner,
        "replace",
        target,
        "fix",
        &corrected("corrected", "13.00"),
    );
    assert_eq!(exit, 6, "{refused:?}");
    assert_eq!(head(&f.book), before);
    for member in &planned {
        assert_eq!(
            get(
                &ok(&f.book, &["entry", "show", text(member, "entry")]),
                "found"
            ),
            &Json::Bool(false)
        );
    }
}
