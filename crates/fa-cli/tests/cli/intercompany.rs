//! Ordinary post JSON admits complete native pairs and retains exact reversals.
use super::*;

#[test]
fn intercompany_json_posts_retries_refuses_reuse_and_reverses() -> std::io::Result<()> {
    let dir = tmp("intercompany")?;
    let book = dir.join("book");
    let run = |args: &[&str]| {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(&book), &argv);
        assert_eq!(code, 0, "args={argv:?}\n{out}\n{err}");
        out
    };
    run(&[
        "book", "create", "--name", "Group",
        "--entity", "A:Alpha", "--entity", "B:Beta",
    ]);
    run(&["chart", "import", "--template", "us-gaap-smb"]);
    run(&["period", "create", "--fiscal-year", "2026"]);
    run(&["period", "open", "FY2026-P03"]);
    let evidence = source_doc(&dir, &book);
    let original = r#"{
        "effective_date":"2026-03-15",
        "idempotency_key":"intercompany-entry",
        "description":"Internal service sale",
        "intercompany_pairs":[{"pair_key":"sale-A-B","left_leg":1,"right_leg":2}],
        "legs":[
            {"side":"debit","account":"1200","amount":"1.00 USD","entity":"A"},
            {"side":"credit","account":"4000","amount":"1.00 USD","entity":"A"},
            {"side":"debit","account":"6000","amount":"1.00 USD","entity":"B"},
            {"side":"credit","account":"1000","amount":"1.00 USD","entity":"B"}
        ]
    }"#;
    let intent = write(&dir, "intercompany.json", original);
    let posted = run(&["post", "--intent", &intent, "--evidence", &evidence]);
    let vid = field(&posted, "vid").unwrap().to_string();
    assert_eq!(field(&posted, "event"), Some("posted"));
    let retry = run(&["post", "--intent", &intent, "--evidence", &evidence]);
    assert_eq!(field(&retry, "event"), Some("recorded"));
    assert_eq!(field(&retry, "vid"), Some(vid.as_str()));
    let verified = run(&["verify", "projections"]);
    assert_eq!(field(&verified, "edges_checked"), Some("17"));

    let reused = write(
        &dir,
        "reused.json",
        &original.replace("intercompany-entry", "different-entry"),
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &reused, "--evidence", &evidence, "--json"],
    );
    assert_eq!(code, 6, "{out}\n{err}");
    assert!(out.contains("pair_key"), "{out}");

    for (name, terms) in [
        ("foreign-book", r#""pair_key":"sale-A-B","left_leg":1,"right_leg":2,"book":"other""#),
        ("incomplete", r#""pair_key":"sale-A-B","left_leg":1"#),
        ("reused-leg", r#""pair_key":"sale-A-B","left_leg":1,"right_leg":1"#),
    ] {
        let invalid = write(
            &dir,
            &format!("{name}.json"),
            &original.replace(
                r#""pair_key":"sale-A-B","left_leg":1,"right_leg":2"#,
                terms,
            ),
        );
        let (code, out, err) = fa(
            Some(&book),
            &["post", "--intent", &invalid, "--evidence", &evidence, "--json"],
        );
        assert_eq!(code, 2, "{name}: {out}\n{err}");
    }
    let reversal = run(&["reverse", &vid, "--reason", "Duplicate"]);
    let reversed = field(&reversal, "vid").unwrap().to_string();
    let verified = run(&["verify", "projections"]);
    assert_eq!(field(&verified, "edges_checked"), Some("34"));
    run(&["reverse", &reversed, "--reason", "Duplicate"]);
    let verified = run(&["verify", "projections"]);
    assert_eq!(field(&verified, "edges_checked"), Some("51"));
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &reused, "--evidence", &evidence, "--json"],
    );
    assert_eq!(code, 6, "{out}\n{err}");
    run(&["verify", "entities", "--period", "FY2026-P03"]);
    Ok(())
}
