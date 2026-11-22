//! Complete event derivations retain one native group through the public CLI.

use super::*;

const FEE: &str = r#"rule private_draft_fee v1 for event Sale produces Adjusting {
  authority {
    debit "1000" upto "2.00 USD"
    credit "6000" upto "2.00 USD"
  }
  debit "1000" "2.00 USD"
  credit "6000" "2.00 USD"
}"#;

fn receipts(stdout: &str) -> Vec<Json> {
    stdout
        .lines()
        .map(|line| {
            let envelope = json::parse(line).unwrap();
            assert_eq!(text(&envelope, "event"), "draft_planned", "{line}");
            envelope.get("data").unwrap().clone()
        })
        .collect()
}

fn cash_debits(stdout: &str) -> String {
    arr(&doc(stdout), "rows")
        .iter()
        .find(|row| text(row, "code") == "1000")
        .map_or_else(String::new, |row| text(row, "debits").to_string())
}

#[test]
fn post_only_automatic_group_retries_rehearses_and_promotes_every_exact_member()
-> std::io::Result<()> {
    let (book, dir, _) = fixture("canon-automatic-confined-draft")?;
    activate_source(&book, &dir, 1, "2026-03-01", FEE);
    let name = "complete-event";
    let authority = post_only_authority(&book, "complete-event-agent", Some(name));
    let (code, out) = bound_rule(&authority, &["draft", "new", name, "--json"]);
    assert_eq!(code, 0, "{out:?}");
    let before = ok(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let command = [
        "rule", "derive", "--event", "EV-DRAFT", "--draft", name, "--json",
    ];
    let (code, out) = bound_rule(&authority, &command);
    assert_eq!(code, 0, "{out:?}");
    assert!(!out.stdout.contains("private_draft_fee"), "{out:?}");
    assert!(!out.stdout.contains("draft_accrual"), "{out:?}");
    let recorded = receipts(&out.stdout);
    assert_eq!(recorded.len(), 2);
    assert_eq!(
        text(&recorded[0], "control_entry"),
        text(&recorded[1], "control_entry"),
        "the complete group must be retained in one Plan record"
    );
    assert_eq!(
        int(&recorded[0], "recorded_at"),
        int(&recorded[1], "recorded_at")
    );
    let retained = open(&book).draft(name).unwrap().unwrap();
    assert_eq!(retained.intents.len(), 2);
    let entries = recorded
        .iter()
        .map(|row| fgdb_types::VId(u128::from_str_radix(text(row, "entry"), 16).unwrap()))
        .collect::<Vec<_>>();
    let reviewed = retained
        .intents
        .iter()
        .map(|member| member.resolved_entry.clone().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        reviewed
            .iter()
            .map(|entry| entry.proposal.legs[0].amount.mantissa)
            .collect::<Vec<_>>(),
        [4000, 200]
    );
    for entry in &entries {
        assert!(open(&book).read_entry(*entry).unwrap().is_none());
    }
    let after = ok(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(arr(&doc(&before), "rows"), arr(&doc(&after), "rows"));

    // The second command reopens the book and freshly seals every proposal.
    // Its complete semantic group still returns the original atomic receipt.
    let (code, retry) = bound_rule(&authority, &command);
    assert_eq!(code, 0, "{retry:?}");
    let retry = receipts(&retry.stdout);
    assert_eq!(retry.len(), recorded.len());
    for (old, new) in recorded.iter().zip(&retry) {
        assert_eq!(new.get("already_recorded"), Some(&Json::Bool(true)));
        for key in ["entry", "control_entry"] {
            assert_eq!(text(old, key), text(new, key));
        }
        assert_eq!(int(old, "recorded_at"), int(new, "recorded_at"));
    }
    assert_eq!(open(&book).draft(name).unwrap().unwrap(), retained);

    for args in [
        vec!["rule", "list", "--json"],
        vec!["event", "list", "--json"],
        vec!["tb", "--period", "FY2026-P03", "--json"],
        vec!["rule", "derive", "--event", "EV-DRAFT", "--json"],
    ] {
        let (code, refused) = bound_rule(&authority, &args);
        assert_eq!(code, 7, "{args:?}: {refused:?}");
        assert_eq!(field(&refused.stdout, "refusal_id"), Some("FA-REF-011"));
    }

    let rehearsal = ok(
        &book,
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--branch",
            "draft:complete-event",
            "--as",
            "independent-reviewer",
            "--json",
        ],
    );
    assert_eq!(cash_debits(&rehearsal), "42.00 USD");
    for entry in &entries {
        assert!(open(&book).read_entry(*entry).unwrap().is_none());
    }
    let promoted = doc(&ok(
        &book,
        &[
            "draft",
            "promote",
            name,
            "--as",
            "controller",
            "--yes",
            "--json",
        ],
    ));
    assert_eq!(arr(&promoted, "entries").len(), 2);
    for (vid, expected) in entries.iter().zip(&reviewed) {
        let (actual, at) = open(&book).read_entry(*vid).unwrap().unwrap();
        assert_eq!(&actual, expected);
        assert_eq!(int(&promoted, "recorded_at"), Some(i128::from(at.0)));
    }
    assert_eq!(
        cash_debits(&ok(&book, &["tb", "--period", "FY2026-P03", "--json"])),
        "42.00 USD"
    );
    Ok(())
}

#[test]
fn automatic_draft_rehearsal_and_promotion_refuse_a_new_matching_rule() -> std::io::Result<()> {
    let (book, dir, _) = fixture("canon-automatic-catalog-drift")?;
    ok(
        &book,
        &[
            "draft",
            "new",
            "catalog-review",
            "--as",
            "preparer",
            "--json",
        ],
    );
    let planned = receipts(&ok(
        &book,
        &[
            "rule",
            "derive",
            "--event",
            "EV-DRAFT",
            "--draft",
            "catalog-review",
            "--as",
            "preparer",
            "--json",
        ],
    ));
    assert_eq!(planned.len(), 1);
    let retained = open(&book).draft("catalog-review").unwrap().unwrap();
    let entry = fgdb_types::VId(u128::from_str_radix(text(&planned[0], "entry"), 16).unwrap());
    // The original version and its exact legs still exist and are active.
    // Only the completeness of the selected catalog has changed.
    activate_source(&book, &dir, 1, "2026-03-01", FEE);
    let head = open(&book).head().unwrap();
    for args in [
        vec![
            "tb",
            "--period",
            "FY2026-P03",
            "--branch",
            "draft:catalog-review",
            "--as",
            "reviewer",
            "--json",
        ],
        vec![
            "draft",
            "promote",
            "catalog-review",
            "--as",
            "controller",
            "--yes",
            "--json",
        ],
    ] {
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(
            (code, field(&out, "refusal_id")),
            (3, Some("FA-REF-196")),
            "{args:?}: {out}\n{err}"
        );
        assert_eq!(open(&book).head().unwrap(), head);
        assert_eq!(
            open(&book).draft("catalog-review").unwrap().unwrap(),
            retained
        );
        assert!(open(&book).read_entry(entry).unwrap().is_none());
    }
    Ok(())
}

#[test]
fn automatic_draft_refuses_missing_inputs_and_wrong_ownership_without_partial_members()
-> std::io::Result<()> {
    let (book, dir, _) = fixture("canon-automatic-draft-boundaries")?;
    let source = r#"rule private_input_dependent_rule v1 for event Sale produces Adjusting {
      inputs { private_fee: amount("USD") }
      authority {
        debit "1000" upto "40.00 USD"
        credit "6000" upto "40.00 USD"
      }
      debit "1000" private_fee
      credit "6000" private_fee
    }"#;
    activate_source(&book, &dir, 1, "2026-03-01", source);
    let name = "owned-auto";
    let authority = post_only_authority(&book, "automatic-boundary-agent", Some(name));
    let (code, out) = bound_rule(&authority, &["draft", "new", name, "--json"]);
    assert_eq!(code, 0, "{out:?}");
    let head = open(&book).head().unwrap();
    let retained = open(&book).draft(name).unwrap().unwrap();
    let (code, out) = bound_rule(
        &authority,
        &[
            "rule", "derive", "--event", "EV-DRAFT", "--draft", name, "--json",
        ],
    );
    assert_eq!(code, 3, "{out:?}");
    assert_eq!(field(&out.stdout, "refusal_id"), Some("FA-REF-196"));
    for secret in ["private_input_dependent_rule", "private_fee"] {
        assert!(!out.stdout.contains(secret), "{out:?}");
    }
    assert_eq!(open(&book).head().unwrap(), head);
    assert_eq!(open(&book).draft(name).unwrap().unwrap(), retained);
    assert!(retained.intents.is_empty());

    let (code, out) = bound_rule(
        &authority,
        &[
            "rule",
            "derive",
            "--event",
            "MISSING",
            "--draft",
            "someone-else",
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out:?}");
    assert_eq!(field(&out.stdout, "refusal_id"), Some("FA-REF-011"));
    assert_eq!(open(&book).head().unwrap(), head);
    assert!(open(&book).draft("someone-else").unwrap().is_none());

    // Automatic selection never treats supplied values or a custom key as
    // permission to skip an input-dependent rule or change group identity.
    for extra in [
        vec!["--input", "private_fee=1.00 USD"],
        vec!["--key", "override"],
    ] {
        let mut args = vec![
            "rule", "derive", "--event", "EV-DRAFT", "--draft", name, "--json",
        ];
        args.extend(extra);
        let (code, out) = bound_rule(&authority, &args);
        assert_eq!(code, 2, "{args:?}: {out:?}");
        assert_eq!(open(&book).head().unwrap(), head);
        assert_eq!(open(&book).draft(name).unwrap().unwrap(), retained);
    }
    Ok(())
}
