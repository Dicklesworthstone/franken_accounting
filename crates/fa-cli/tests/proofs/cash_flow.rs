//! Cash turnover and policy derivation survive every retained export route.

use super::*;

#[test]
fn retained_direct_and_policy_cash_flow_export_the_original_gross_movements() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("cash-opening", "2026-03-05", "10.00", &evidence);
    let refunded = fixture.post("cash-refunded", "2026-03-10", "12.34", &evidence);
    fixture.post("cash-receipt", "2026-03-20", "7.66", &evidence);
    ok(
        &fixture.book,
        &[
            "reverse",
            text(&refunded, "vid"),
            "--reason",
            "WrongAccount",
        ],
    );
    let known_at = fixture.head();
    let at = known_at.to_string();
    let policy_file = write(
        &fixture.dir,
        "cash-policy.json",
        r#"{"name":"operating-policy","cash_accounts":["1000"],"account_rules":[{"account":"4000","activity":"operating"}],"overrides":[]}"#,
    );
    let policy_path = fixture.dir.join("policy.certificate");
    let policy_metadata = aging::certify(
        &fixture,
        &[
            "gl",
            "cash-flow",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--from",
            "2026-03-10",
            "--to",
            "2026-03-31",
            "--label",
            "Cash turnover",
            "--as-known-at",
            &at,
            "--policy",
            &policy_file,
            "--certificate-out",
            policy_path.to_str().unwrap(),
        ],
    );
    let policy = fa::cash_flow_policy::CashFlowPolicyCertificate::decode(&unhex(text(
        &policy_metadata,
        "bytes",
    )))
    .unwrap();
    assert_eq!(policy.decisions().len(), 3);

    // Retain the same explicit choices as a direct certificate. This removes
    // the policy wrapper, but must preserve the complete cash computation.
    let assignments = policy
        .source_certificate()
        .definition()
        .assignments
        .iter()
        .map(|assignment| {
            format!(
                r#"{{"entry_digest":"{}","leg_index":{},"activity":"operating"}}"#,
                fa_verify::blake3::hex(&assignment.entry_digest),
                assignment.leg_index,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let direct_file = write(
        &fixture.dir,
        "cash-direct.json",
        &format!(
            r#"{{"name":"operating-policy","cash_accounts":["1000"],"assignments":[{assignments}]}}"#
        ),
    );
    let direct_path = fixture.dir.join("direct.certificate");
    let direct_metadata = aging::certify(
        &fixture,
        &[
            "gl",
            "cash-flow",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--from",
            "2026-03-10",
            "--to",
            "2026-03-31",
            "--label",
            "Cash turnover",
            "--as-known-at",
            &at,
            "--policy",
            &direct_file,
            "--certificate-out",
            direct_path.to_str().unwrap(),
        ],
    );
    let direct = fa::CashFlowCertificate::decode(&unhex(text(&direct_metadata, "bytes"))).unwrap();
    assert_eq!(direct, *policy.source_certificate());
    assert_ne!(direct.digest(), policy.digest());

    fixture.post("cash-later-backdate", "2026-03-10", "99.00", &evidence);
    let checkpoint = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&checkpoint, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let before = fixture.head();
    let authority = LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "cash-reader",
        LaunchProfile::Agent,
        &["read", "produce"],
    )
    .unwrap();

    for (metadata, path, has_policy, inner_pin) in [
        (
            &policy_metadata,
            &policy_path,
            true,
            *policy.source_certificate().digest(),
        ),
        (
            &direct_metadata,
            &direct_path,
            false,
            *direct.source_certificate().digest(),
        ),
    ] {
        let encoded = unhex(text(metadata, "bytes"));
        assert_eq!(std::fs::read(path).unwrap(), encoded);
        let artifact = fa::ReportArtifact::decode(&encoded).unwrap();
        let expected = fa_verify::blake3::hex(artifact.digest());
        let locator = format!("C:{}", text(metadata, "oid"));
        let mut original_bundle = None;
        for source in [locator.as_str(), path.to_str().unwrap()] {
            let produced = ok(
                &fixture.book,
                &[
                    "bundle",
                    "produce",
                    "--certificate",
                    source,
                    "--state",
                    text(&checkpoint, "oid"),
                ],
            );
            assert_eq!(text(&produced, "scope"), "report");
            assert!(text(&produced, "verify").contains(&format!("--expect {expected}")));
            let bundle = bytes(&produced);
            let receipt = unhex(text(&produced, "receipt"));
            let verified = fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(artifact.digest()),
            )
            .expect("independent cash-flow replay after a later backdated post");
            assert_eq!(verified.certificate_digest, *artifact.digest());
            assert_eq!(verified.output, artifact.output());
            assert_eq!(verified.known_at, known_at);
            assert_eq!(verified.unit_universe_source, "authenticated-registry");
            let cash = verified.cash_flow.unwrap();
            assert_eq!(cash.ledger.lines.len(), 3);
            assert_eq!(cash.units.len(), 1);
            let unit = &cash.units[0];
            assert_eq!(unit.opening, 1000);
            assert_eq!(unit.operating.inflows, 2000);
            assert_eq!(unit.operating.outflows, 1234);
            assert_eq!(unit.operating.net, 766);
            assert_eq!(unit.net_change, 766);
            assert_eq!(unit.closing, 1766);
            assert_eq!(cash.policy.is_some(), has_policy);
            if let Some(policy) = cash.policy {
                assert_eq!(policy.decisions.len(), 3);
                assert_eq!(policy.policy.account_rules.len(), 1);
            }
            assert!(
                fa_verify::report::verify_report_expected(
                    &bundle,
                    &[key],
                    None,
                    Some(&receipt),
                    Some(&inner_pin),
                )
                .is_err(),
                "a nested report cannot pin the outer classification question"
            );
            if let Some(expected) = &original_bundle {
                assert_eq!(&bundle, expected);
            } else {
                original_bundle = Some(bundle);
            }
        }
        let argv = [
            "bundle",
            "produce",
            "--certificate",
            "-",
            "--state",
            text(&checkpoint, "oid"),
            "--json",
        ]
        .map(str::to_string);
        let (exit, output) = fa_with_authority(
            &argv,
            Files {
                cwd: None,
                stdin: Stdin::Forwarded(encoded),
            },
            &authority,
            true,
        );
        assert_eq!(exit, 0, "{}{}", output.stdout, output.stderr);
        let produced = parse_line(&output.stdout, &output.stderr);
        assert_eq!(bytes(&produced), original_bundle.unwrap());
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let args = [
            "report",
            "cash.fab",
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--receipt",
            "cash.receipt",
            "--expect",
            &expected,
            "--json",
        ]
        .map(str::to_string);
        let read = |name: &str| match name {
            "cash.fab" => Ok(bundle.clone()),
            "cash.receipt" => Ok(receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                name.to_string(),
            )),
        };
        let result = fa_verify::cli::run(&args, &read);
        assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
        assert!(result.stdout.contains("\"verdict\":\"verified\""));
        assert!(result.stdout.contains("operating-policy"));
        let mut wrong = args;
        wrong[7] = fa_verify::blake3::hex(&inner_pin);
        assert_eq!(fa_verify::cli::run(&wrong, &read).exit, 8);
    }
    fixture.assert_proof_accesses_since(before, "cash-reader", 2);
}
