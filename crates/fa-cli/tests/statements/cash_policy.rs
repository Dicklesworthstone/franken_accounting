//! Operator workflows for journaled cash classifications. Every command uses
//! the real CLI and the parent harness checks each robot event against the
//! verb registry. Expected amounts come from Fixture's original USD/JPY posts.

use super::*;

const NAME: &str = "approved-cash";
const LABEL: &str = "Approved March cash";

fn event<'a>(events: &'a [Json], name: &str) -> &'a Json {
    data(
        events
            .iter()
            .find(|value| text(value, "event") == name)
            .unwrap_or_else(|| panic!("missing {name}: {events:?}")),
    )
}

fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(value)) => *value,
        other => panic!("{key} must be an integer: {other:?}"),
    }
}

fn head(fixture: &Fixture) -> i128 {
    let events = ok(&fixture.book, &["book", "info"]);
    number(events[0].get("coordinate").unwrap(), "known_at")
}

fn write(fixture: &Fixture, name: &str, contents: &str) -> PathBuf {
    let path = fixture.dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn rules(rent_activity: &str) -> String {
    format!(
        r#"{{"name":"{NAME}","cash_accounts":["1000","1100"],"account_rules":[{{"account":"3000","activity":"financing"}},{{"account":"4000","activity":"operating"}},{{"account":"6000","activity":"{rent_activity}"}},{{"account":"4100","activity":"operating"}},{{"account":"6100","activity":"operating"}}],"overrides":[]}}"#,
    )
}

struct Review {
    path: PathBuf,
    digest: String,
}

fn review(fixture: &Fixture, version: u32, from: &str, key: &str, rent_activity: &str) -> Review {
    let file = write(fixture, &format!("{key}.json"), &rules(rent_activity));
    let path = fixture.dir.join(format!("{key}.plan"));
    let before = head(fixture);
    let result = ok(
        &fixture.book,
        &[
            "cash-policy",
            "define",
            "--file",
            file.to_str().unwrap(),
            "--policy-version",
            &version.to_string(),
            "--from",
            from,
            "--key",
            key,
            "--plan-out",
            path.to_str().unwrap(),
        ],
    );
    let plan = event(&result, "cash_flow_policy_plan");
    assert_eq!(number(plan, "version"), i128::from(version));
    assert_eq!(text(plan, "policy"), NAME);
    assert_eq!(head(fixture), before, "review does not activate a policy");
    assert!(path.is_file(), "the operator receives a saved review");
    Review {
        path,
        digest: text(plan, "proposal_digest").into(),
    }
}

fn approve(fixture: &Fixture, review: &Review, principal: &str) -> String {
    let approved = ok(
        &fixture.book,
        &["approve", "--proposal", &review.digest, "--as", principal],
    );
    text(data(&approved[0]), "approval_vid").into()
}

fn activation_args<'a>(review: &'a Review, approvals: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "cash-policy",
        "activate",
        "--plan",
        review.path.to_str().unwrap(),
        "--digest",
        &review.digest,
        "--yes",
    ];
    for approval in approvals {
        args.extend(["--approval", *approval]);
    }
    args
}

fn activate(fixture: &Fixture, review: &Review) -> Vec<Json> {
    let a = approve(fixture, review, "cash-controller-a");
    let b = approve(fixture, review, "cash-controller-b");
    ok(&fixture.book, &activation_args(review, &[&a, &b]))
}

fn refused(fixture: &Fixture, args: &[&str], expected_exit: i32) {
    let before = head(fixture);
    let (exit, events, stderr) = run(&fixture.book, args);
    assert_eq!(exit, expected_exit, "args={args:?}: {events:?}\n{stderr}");
    assert_eq!(events.len(), 1, "a refusal emits no partial report or plan");
    assert_eq!(text(&events[0], "event"), "error");
    assert_eq!(head(fixture), before, "a refusal publishes nothing");
}

fn report_args<'a>() -> Vec<&'a str> {
    vec![
        "gl",
        "cash-flow",
        "--policy-name",
        NAME,
        "--account",
        "1000,1100",
        "--unit",
        "USD,JPY",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--label",
        LABEL,
    ]
}

fn show_args<'a>() -> Vec<&'a str> {
    vec![
        "cash-policy",
        "show",
        "--name",
        NAME,
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
    ]
}

fn unit<'a>(report: &'a Json, code: &str) -> &'a Json {
    array(report, "units")
        .iter()
        .find(|unit| text(unit, "unit") == code)
        .unwrap_or_else(|| panic!("missing {code}: {report:?}"))
}

fn assert_original_cash(report: &Json) {
    let usd = unit(report, "USD");
    assert_eq!(text(usd, "opening"), "275.00 USD");
    assert_eq!(text(usd, "net_change"), "80.00 USD");
    assert_eq!(text(usd, "closing"), "355.00 USD");
    let operating = usd.get("operating").unwrap();
    assert_eq!(text(operating, "inflows"), "90.00 USD");
    assert_eq!(text(operating, "outflows"), "10.00 USD");
    assert_eq!(text(operating, "net"), "80.00 USD");
    let jpy = unit(report, "JPY");
    assert_eq!(text(jpy, "opening"), "0 JPY");
    assert_eq!(text(jpy, "net_change"), "89 JPY");
    assert_eq!(text(jpy, "closing"), "89 JPY");
    let operating = jpy.get("operating").unwrap();
    assert_eq!(text(operating, "inflows"), "111 JPY");
    assert_eq!(text(operating, "outflows"), "22 JPY");
    assert_eq!(text(operating, "net"), "89 JPY");
    assert_eq!(array(report, "decisions").len(), 4);
    assert!(
        array(report, "decisions")
            .iter()
            .all(|decision| text(decision, "basis") == "account_rules")
    );
}

#[test]
fn cash_policy_activation_requires_the_review_digest_and_two_distinct_approvers() {
    let fixture = Fixture::new();
    refused(&fixture, &show_args(), 2);
    let review = review(&fixture, 1, "2026-01-01", "cash-v1", "operating");
    refused(&fixture, &activation_args(&review, &[]), 7);
    let a = approve(&fixture, &review, "cash-controller-a");
    refused(&fixture, &activation_args(&review, &[&a]), 7);
    refused(&fixture, &activation_args(&review, &[&a, &a]), 7);
    let b = approve(&fixture, &review, "cash-controller-b");
    let self_approved = ok(&fixture.book, &["approve", "--proposal", &review.digest]);
    refused(
        &fixture,
        &activation_args(
            &review,
            &[&a, text(data(&self_approved[0]), "approval_vid")],
        ),
        7,
    );

    let wrong_digest = "ff".repeat(32);
    let mut wrong = activation_args(&review, &[&a, &b]);
    wrong[5] = &wrong_digest;
    refused(&fixture, &wrong, 2);
    refused(
        &fixture,
        &[
            "cash-policy",
            "activate",
            "--plan",
            review.path.to_str().unwrap(),
            "--approval",
            &a,
            "--approval",
            &b,
            "--yes",
        ],
        2,
    );

    let activated = ok(&fixture.book, &activation_args(&review, &[&a, &b]));
    let first = event(&activated, "cash_flow_policy_activated");
    assert_eq!(first.get("already_recorded"), Some(&Json::Bool(false)));
    let at = head(&fixture);
    let retried = ok(&fixture.book, &activation_args(&review, &[&a, &b]));
    let retried = event(&retried, "cash_flow_policy_activated");
    assert_eq!(retried.get("already_recorded"), Some(&Json::Bool(true)));
    for field in ["activation", "definition_digest", "chart_digest"] {
        assert_eq!(text(first, field), text(retried, field));
    }
    assert_eq!(number(first, "recorded_at"), number(retried, "recorded_at"));
    assert_eq!(
        head(&fixture),
        at,
        "exact retry records no second activation"
    );
    let shown = ok(&fixture.book, &show_args());
    let policy = event(&shown, "cash_flow_policy");
    assert_eq!(number(policy, "version"), 1);
    assert_eq!(text(policy, "activation"), text(first, "activation"));
    assert_eq!(array(policy, "cash_accounts").len(), 2);
    assert_eq!(array(policy, "account_rules").len(), 5);
    assert_eq!(head(&fixture), at, "show is a pure historical read");

    let overrides = rules("operating").replace(
        "\"overrides\":[]",
        &format!(
            r#""overrides":[{{"entry_digest":"{}","leg_index":0,"activity":"financing"}}]"#,
            "00".repeat(32),
        ),
    );
    let file = write(&fixture, "forbidden-overrides.json", &overrides);
    let plan = fixture.dir.join("forbidden-overrides.plan");
    refused(
        &fixture,
        &[
            "cash-policy",
            "define",
            "--file",
            file.to_str().unwrap(),
            "--policy-version",
            "2",
            "--from",
            "2026-03-01",
            "--key",
            "forbidden-overrides",
            "--plan-out",
            plan.to_str().unwrap(),
        ],
        2,
    );
    assert!(
        !plan.exists(),
        "invalid rules do not leave a review artifact"
    );
    let verified = ok(&fixture.book, &["verify", "projections"]);
    assert!(array(event(&verified, "projections_verified"), "drift").is_empty());
}

#[test]
fn named_cash_policy_keeps_both_times_and_retained_proofs_after_later_versions() {
    let fixture = Fixture::new();
    let first = review(&fixture, 1, "2026-01-01", "cash-v1", "operating");
    let activated = activate(&fixture, &first);
    let first_seq = number(
        event(&activated, "cash_flow_policy_activated"),
        "recorded_at",
    );
    let before_activation = (first_seq - 1).to_string();
    let mut absent = show_args();
    absent.extend(["--as-known-at", &before_activation]);
    refused(&fixture, &absent, 2);

    let at = head(&fixture);
    let at_string = at.to_string();
    let certificate_file = fixture.dir.join("approved-cash.certificate");
    let mut args = report_args();
    args.extend([
        "--as-known-at",
        &at_string,
        "--certificate-out",
        certificate_file.to_str().unwrap(),
    ]);
    let certified = ok(&fixture.book, &args);
    let original = event(&certified, "policy_cash_flow").clone();
    assert_original_cash(&original);
    assert_eq!(
        number(event(&certified, "cash_flow_policy_selected"), "version"),
        1
    );
    let metadata = event(&certified, "report_certificate");
    let certificate = unhex(text(metadata, "bytes"));
    assert_eq!(std::fs::read(&certificate_file).unwrap(), certificate);
    let artifact = fa::ReportArtifact::decode(&certificate).unwrap();
    let locator = format!("C:{}", text(metadata, "oid"));
    let expected = format!(
        r#"{{"kind":"policy-cash-flow","accounts":["1000","1100"],"units":["USD","JPY"],"label":"{LABEL}","from":"2026-03-01","through":"2026-03-31","known_at":{at},"policy":{}}}"#,
        rules("operating"),
    );

    // The second reviewer changes the classification effective in March;
    // a later recorded sale also changes the head's monetary answer.
    let second = review(&fixture, 2, "2026-03-01", "cash-v2", "investing");
    activate(&fixture, &second);
    fixture.post("later-cash-sale", "2026-03-20", "1000", "4000", "5.00 USD");
    let current = ok(&fixture.book, &report_args());
    assert_eq!(
        number(event(&current, "cash_flow_policy_selected"), "version"),
        2
    );
    let current_usd = unit(event(&current, "policy_cash_flow"), "USD");
    assert_eq!(text(current_usd, "closing"), "360.00 USD");
    assert_eq!(
        text(current_usd.get("operating").unwrap(), "net"),
        "95.00 USD"
    );
    assert_eq!(
        text(current_usd.get("investing").unwrap(), "net"),
        "-10.00 USD"
    );

    let mut historical = report_args();
    historical.extend(["--as-known-at", &at_string]);
    let historical = ok(&fixture.book, &historical);
    assert_eq!(
        number(event(&historical, "cash_flow_policy_selected"), "version"),
        1
    );
    assert_eq!(event(&historical, "policy_cash_flow"), &original);
    let mut crossing = report_args();
    crossing[9] = "2026-02-01";
    refused(&fixture, &crossing, 2);
    crossing.extend(["--as-known-at", &at_string]);
    let earlier = ok(&fixture.book, &crossing);
    assert_eq!(
        number(event(&earlier, "cash_flow_policy_selected"), "version"),
        1
    );
    let earlier_usd = unit(event(&earlier, "policy_cash_flow"), "USD");
    assert_eq!(text(earlier_usd, "opening"), "0.00 USD");
    assert_eq!(text(earlier_usd, "closing"), "355.00 USD");

    let replay_output = fixture.dir.join("approved-cash-replayed.report");
    let before_replay = head(&fixture);
    let replay = ok(
        &fixture.book,
        &[
            "replay",
            &locator,
            "--expect",
            &expected,
            "--output",
            replay_output.to_str().unwrap(),
        ],
    );
    let receipt = event(&replay, "report_replayed");
    assert_eq!(text(receipt, "family"), "policy-cash-flow");
    assert_eq!(number(receipt, "known_at"), at);
    assert_eq!(
        text(receipt, "output_digest"),
        text(metadata, "output_digest")
    );
    assert_eq!(std::fs::read(replay_output).unwrap(), artifact.output());
    assert_eq!(
        head(&fixture),
        before_replay,
        "retained replay publishes nothing"
    );
    assert!(
        replay
            .iter()
            .all(|row| text(row, "event") != "cash_flow_policy_selected")
    );

    // The complete report prefix includes the real producer's PolicyControl
    // and typed definition. This crosses the model/independent-parser boundary;
    // no handcrafted activation or delivered expectation substitutes for it.
    let checkpoint = ok(
        &fixture.book,
        &["checkpoint", "create", "--grant", "witness"],
    );
    let checkpoint = text(event(&checkpoint, "checkpoint_created"), "oid");
    let signed = ok(
        &fixture.book,
        &["proof", "signed-checkpoint", "--state", checkpoint],
    );
    let key: [u8; 32] = unhex(text(
        event(&signed, "proof_exported"),
        "checkpoint_public_key",
    ))
    .try_into()
    .unwrap();
    for (wrong, exit) in [
        (
            expected.replace(
                &format!("\"known_at\":{at}"),
                &format!("\"known_at\":{}", at + 1),
            ),
            8,
        ),
        (
            expected.replace(&rules("operating"), &rules("investing")),
            8,
        ),
        (
            expected.replace("\"kind\":\"policy-cash-flow\"", "\"kind\":\"unsupported\""),
            2,
        ),
    ] {
        assert_ne!(
            wrong, expected,
            "each control changes the recipient's question"
        );
        refused(
            &fixture,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--expect",
                &wrong,
                "--state",
                checkpoint,
            ],
            exit,
        );
    }
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--expect",
            &expected,
            "--state",
            checkpoint,
        ],
    );
    let produced = data(&produced[0]);
    assert_eq!(text(produced, "scope"), "report");
    let bundle = unhex(text(produced, "bytes"));
    let receipt = unhex(text(produced, "receipt"));
    assert!(
        bundle
            .windows(b"fa:cash-flow-policy-definition:v1".len())
            .any(|bytes| bytes == b"fa:cash-flow-policy-definition:v1"),
        "the independent verifier must see the new typed activation body"
    );
    let verified = fa_verify::report::verify_report_expected(
        &bundle,
        &[key],
        None,
        Some(&receipt),
        Some(artifact.digest()),
    )
    .expect("independent replay of a producer-created cash-policy activation");
    assert_eq!(verified.known_at, u64::try_from(at).unwrap());
    assert_eq!(verified.certificate_digest, *artifact.digest());
    assert_eq!(verified.output, artifact.output());
    let cash = verified.cash_flow.unwrap();
    assert!(cash.policy.is_some());
    let mut amounts = cash
        .units
        .iter()
        .map(|unit| {
            (
                unit.opening,
                unit.operating.inflows,
                unit.operating.outflows,
                unit.operating.net,
                unit.closing,
            )
        })
        .collect::<Vec<_>>();
    amounts.sort_unstable();
    assert_eq!(
        amounts,
        vec![(0, 111, 22, 89, 89), (27_500, 9_000, 1_000, 8_000, 35_500)]
    );
    let mut wrong_pin = *artifact.digest();
    wrong_pin[0] ^= 1;
    assert!(
        fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(&wrong_pin),
        )
        .is_err()
    );
    ok(&fixture.book, &["verify", "projections"]);
}

#[test]
fn named_indirect_cash_reconciles_each_currency_and_refuses_classification_overrides() {
    let fixture = Fixture::new();
    let plan = review(&fixture, 1, "2026-01-01", "cash-v1", "operating");
    activate(&fixture, &plan);
    let mut args = report_args();
    args.extend(["--indirect", "--income-period", "FY2026-P03"]);
    let report = ok(&fixture.book, &args);
    let indirect = event(&report, "indirect_cash_flow");
    assert_eq!(text(indirect, "cash_policy"), NAME);
    for (code, income, opening, closing, zero) in [
        ("USD", "80.00 USD", "275.00 USD", "355.00 USD", "0.00 USD"),
        ("JPY", "89 JPY", "0 JPY", "89 JPY", "0 JPY"),
    ] {
        let row = unit(indirect, code);
        for field in ["net_income", "operating", "direct_operating", "net_change"] {
            assert_eq!(text(row, field), income, "{code}/{field}");
        }
        assert_eq!(text(row, "opening"), opening);
        assert_eq!(text(row, "closing"), closing);
        for field in [
            "non_cash",
            "working_capital",
            "non_operating",
            "operating_residual",
        ] {
            assert_eq!(text(row, field), zero, "{code}/{field}");
        }
    }
    assert!(array(indirect, "contributions").is_empty());

    let side_inputs = write(
        &fixture,
        "indirect-adjustments.json",
        r#"{"name":"approved-indirect","adjustments":[]}"#,
    );
    let mut with_side_inputs = args.clone();
    with_side_inputs.extend(["--policy", side_inputs.to_str().unwrap()]);
    let with_side_inputs = ok(&fixture.book, &with_side_inputs);
    let adjusted = event(&with_side_inputs, "indirect_cash_flow");
    assert_eq!(text(adjusted, "policy"), "approved-indirect");
    assert_eq!(adjusted.get("units"), indirect.get("units"));

    // Even empty alternate classification families are forbidden: omitting
    // their rows does not grant permission to reinterpret an approved policy.
    for (index, extra) in [
        r#""account_rules":[]"#,
        r#""cash_accounts":["1000"]"#,
        r#""assignments":[]"#,
        r#""overrides":[]"#,
        r#""splits":[]"#,
        r#""cash_policy":"unapproved-cash""#,
    ]
    .into_iter()
    .enumerate()
    {
        let file = write(
            &fixture,
            &format!("forbidden-side-input-{index}.json"),
            &format!(r#"{{"adjustments":[],{extra}}}"#),
        );
        let output = fixture
            .dir
            .join(format!("forbidden-side-input-{index}.certificate"));
        let mut forbidden = args.clone();
        forbidden.extend([
            "--policy",
            file.to_str().unwrap(),
            "--certificate-out",
            output.to_str().unwrap(),
        ]);
        refused(&fixture, &forbidden, 2);
        assert!(!output.exists(), "refusal leaves no certificate output");
    }
    let file = write(
        &fixture,
        "alternate-direct-policy.json",
        &rules("investing"),
    );
    let mut direct = report_args();
    direct.extend(["--policy", file.to_str().unwrap()]);
    refused(&fixture, &direct, 2);
}
