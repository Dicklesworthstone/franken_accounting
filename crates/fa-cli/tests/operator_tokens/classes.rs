//! fa-3vg1: an issued Human token's class caveat governs control writes and
//! approvals as well as postings. Use actual CLI issuance/serialization;
//! the MCP launch ceiling would reject these operations independently.

use super::*;
use fa_model::EntryClass;

fn issue(f: &mut Fixture, holder: &str, op: &str, class: Option<&str>) -> LaunchAuthority {
    let output = format!("{holder}.token");
    let mut words = vec![
        "capability",
        "issue",
        "--holder",
        holder,
        "--profile",
        "human",
        "--op",
        op,
        "--out",
        &output,
        "--grant",
        "issue_capability",
        "--grant",
        op,
    ];
    if let Some(class) = class {
        words.extend(["--class", class]);
    }
    if op == "close" {
        words.extend(["--op", "read", "--grant", "read"]);
    }
    let issued = f.owner(&words);
    assert_eq!(text(&issued, "event"), "capability_issued");
    let token = CapabilityToken::decode(&std::fs::read(f.dir.join(&output)).unwrap()).unwrap();
    assert_eq!(token.capability().profile(), Profile::Human);
    assert_eq!(
        token.capability().classes().cloned(),
        class.map(|name| std::collections::BTreeSet::from([EntryClass::from_name(name).unwrap()])),
        "the issued token must retain the CLI's actual class restriction"
    );
    f.authority(&token)
}

fn state(f: &Fixture) -> fa_time::PeriodState {
    f.book
        .periods()
        .unwrap()
        .into_iter()
        .find(|period| period.code == PERIOD)
        .unwrap()
        .state
}

fn denied_for_classes(f: &mut Fixture, authority: &LaunchAuthority, words: &[&str]) -> Json {
    // The existing helper checks FA-REF-011, exit 7, and an unchanged head.
    // Assert the actual caveat too, so a missing op or launch ceiling cannot
    // stand in for enforcement of the class boundary.
    let refused = f.refused(authority, words, "FA-REF-011");
    assert!(
        text(&refused, "message").contains("`classes`"),
        "{}",
        refused.render()
    );
    assert_eq!(
        field(&refused, "authority")
            .get("profile")
            .and_then(Json::as_str),
        Some("Human")
    );
    refused
}

#[test]
fn a_class_scoped_token_writes_no_control_of_another_class() {
    let mut f = Fixture::new(0xe1);
    let original = issue(
        &mut f,
        "original-only-controller",
        "close",
        Some("Original"),
    );
    assert_eq!(state(&f), fa_time::PeriodState::Open);
    for ending in ["--dry-run", "--yes"] {
        for _ in 0..2 {
            let refused = denied_for_classes(
                &mut f,
                &original,
                &["period", "close", PERIOD, "--reason", "Scheduled", ending],
            );
            assert!(
                text(&refused, "message").contains("PeriodControl"),
                "{}",
                refused.render()
            );
            assert_eq!(state(&f), fa_time::PeriodState::Open);
        }
    }

    // The same real operation succeeds with its matching class and with no
    // class caveat. Fresh books ensure each positive actually publishes a
    // new control instead of returning a previously recorded close.
    let journal = |book: &fa::Book| {
        let fa::QuerySelection::Native(query) =
            fa::compile_query("MATCH (e:Entry) RETURN e,e._fa_payload AS payload ORDER BY e")
                .unwrap()
                .selection
        else {
            panic!("the journal population query must be native");
        };
        book.query_native(&query, book.head().unwrap(), None)
            .unwrap()
            .unwrap()
            .rows
    };
    for (seed, class, holder) in [
        (0xe2, Some("PeriodControl"), "period-only-controller"),
        (0xe3, None, "unscoped-controller"),
    ] {
        let mut f = Fixture::new(seed);
        let authority = issue(&mut f, holder, "close", class);
        let before = f.book.head().unwrap();
        let entries = journal(&f.book);
        let periods = f.book.periods().unwrap();
        let plan = f.ok(
            &authority,
            &[
                "period",
                "close",
                PERIOD,
                "--reason",
                "Scheduled",
                "--dry-run",
            ],
            None,
        );
        let access = f.book.access_log(before).unwrap();
        assert_eq!(
            access.len(),
            1,
            "delivering the plan owes one access receipt"
        );
        assert_eq!(access[0].record.command, "period close");
        assert_eq!(access[0].record.principal, authority.principal_vid());
        assert_eq!(access[0].record.principal_name, holder);
        assert_eq!(
            access[0].record.capability_commitment,
            authority.capability().commitment().unwrap()
        );
        assert_eq!(access[0].observed_at, before);
        assert_eq!(access[0].recorded_at.0, before.0 + 1);
        assert_eq!(
            f.book.head().unwrap(),
            access[0].recorded_at,
            "the plan publishes only its access receipt"
        );
        assert_eq!(
            journal(&f.book),
            entries,
            "the plan changes no journal entry"
        );
        assert_eq!(
            f.book.periods().unwrap(),
            periods,
            "the plan changes no period"
        );
        assert!(!text(&plan, "proposal_digest").is_empty());
        let closed = f.ok(
            &authority,
            &["period", "close", PERIOD, "--reason", "Scheduled", "--yes"],
            None,
        );
        assert_eq!(text(&closed, "to"), "Closed");
        assert_eq!(state(&f), fa_time::PeriodState::Closed);
        assert!(f.book.head().unwrap() > before);
    }

    // Exercise whole-book control admission via admit_within_class / admit_class
    // (`SchemaControl` chart open): a token scoped to `Original` is refused
    // naming the target control class, while a token scoped to `SchemaControl`
    // succeeds.
    let mut schema_f = Fixture::new(0xe5);
    let account_file = schema_f.dir.join("new-account.json");
    std::fs::write(
        &account_file,
        r#"{"code":"6250","name":"Supplies","type":"Expense","unit":"USD"}"#,
    )
    .unwrap();
    let open_args = [
        "chart",
        "open",
        "new-account.json",
        "--opened",
        "2026-03-01",
        "--key",
        "class-scoped-schema-open",
    ];
    let wrong_schema = issue(
        &mut schema_f,
        "original-only-schema",
        "schema_change",
        Some("Original"),
    );
    let schema_refused = denied_for_classes(&mut schema_f, &wrong_schema, &open_args);
    assert!(
        text(&schema_refused, "message").contains("SchemaControl"),
        "{}",
        schema_refused.render()
    );

    let right_schema = issue(
        &mut schema_f,
        "schema-only-controller",
        "schema_change",
        Some("SchemaControl"),
    );
    let added = schema_f.ok(&right_schema, &open_args, None);
    assert_eq!(text(&added, "action"), "open");
}

#[test]
fn a_class_scoped_approver_cannot_approve_another_class_through_an_opaque_digest() {
    let mut f = Fixture::new(0xe4);
    let original = issue(
        &mut f,
        "original-only-approver",
        "approve",
        Some("Original"),
    );
    let period = issue(
        &mut f,
        "period-only-approver",
        "approve",
        Some("PeriodControl"),
    );
    let unscoped = issue(&mut f, "unscoped-approver", "approve", None);
    f.owner(&["period", "close", PERIOD, "--reason", "Scheduled", "--yes"]);
    // A genuine PeriodControl proposal, not a fabricated digest. The opaque
    // approval endpoint has only its digest, so even a matching class caveat
    // cannot be satisfied there without the canonical proposal payload.
    let plan = f.owner(&[
        "period",
        "lock",
        PERIOD,
        "--reason",
        "AuditComplete",
        "--dry-run",
    ]);
    let digest = text(&plan, "proposal_digest").to_string();
    let words = ["approve", "--proposal", digest.as_str()];
    for authority in [&original, &period] {
        for _ in 0..2 {
            denied_for_classes(&mut f, authority, &words);
        }
    }
    let before = f.book.head().unwrap();
    let approved = f.ok(&unscoped, &words, None);
    assert_eq!(text(&approved, "event"), "approved");
    assert_eq!(text(&approved, "approved_digest"), digest);
    assert_eq!(field(&approved, "already_recorded"), &Json::Bool(false));
    assert!(f.book.head().unwrap() > before);
}
