//! The original indirect artifact exports through files, locators and bound stdin.

use super::*;

fn policy(inputs: &Inputs, kind: fa::CashFlowBasisKind) -> String {
    let sale = inputs.line(&inputs.sale, "1000");
    match kind {
        fa::CashFlowBasisKind::Explicit => inputs.policy(&format!(
            r#""assignments":[{},{},{}]"#,
            assignment(sale, "operating"),
            assignment(inputs.line(&inputs.payments[0], "1000"), "financing"),
            assignment(inputs.line(&inputs.payments[1], "1000"), "operating"),
        )),
        fa::CashFlowBasisKind::Policy => inputs.policy(
            r#""account_rules":[{"account":"4000","activity":"operating"},{"account":"2000","activity":"financing"},{"account":"6100","activity":"operating"},{"account":"1500","activity":"investing"}],"overrides":[]"#,
        ),
        fa::CashFlowBasisKind::Split => {
            let payment = inputs.line(&inputs.payments[0], "1000");
            inputs.policy(&format!(
                r#""splits":[{{"entry_digest":"{}","leg_index":{},"reason":"Cash revenue","portions":[{{"activity":"operating","amount":"200.00 USD"}}]}},{{"entry_digest":"{}","leg_index":{},"reason":"Original principal and interest","portions":[{{"activity":"operating","amount":"10.00 USD"}},{{"activity":"financing","amount":"100.00 USD"}}]}}]"#,
                text(sale, "entry_digest"), integer(sale, "leg_index"),
                text(payment, "entry_digest"), integer(payment, "leg_index"),
            ))
        }
    }
}

#[test]
fn all_indirect_bases_export_original_certificates_and_recompute_offline() {
    for kind in [
        fa::CashFlowBasisKind::Explicit,
        fa::CashFlowBasisKind::Policy,
        fa::CashFlowBasisKind::Split,
    ] {
        let inputs = Inputs::new(kind == fa::CashFlowBasisKind::Split);
        let f = &inputs.fixture;
        let policy = policy(&inputs, kind);
        let expected = inputs.expected(&policy);
        let policy_file = write(&f.dir, "portable-indirect-policy.json", &policy);
        let certificate_path = f.dir.join("portable-indirect.certificate");
        let at = inputs.known_at.to_string();
        let mut args = report_args(&policy_file, &at);
        args.extend(["--certificate-out", certificate_path.to_str().unwrap()]);
        let metadata = aging::certify(f, &args);
        let encoded = unhex(text(&metadata, "bytes"));
        let certificate = fa::IndirectCashFlowCertificate::decode(&encoded).unwrap();
        assert_eq!(certificate.source_certificate().kind(), kind);
        assert_eq!(std::fs::read(&certificate_path).unwrap(), encoded);
        let locator = format!("C:{}", text(&metadata, "oid"));
        f.post(
            "portable-indirect-later-cash",
            "2026-03-20",
            "99.00",
            &inputs.evidence,
        );
        let checkpoint = f.checkpoint();
        let signed = exported(
            &f.book,
            &["signed-checkpoint", "--state", text(&checkpoint, "oid")],
        );
        let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
            .try_into()
            .unwrap();
        let anchor = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
        let before = f.head();
        assert_eq!(
            run(&f.book, &["bundle", "produce", "--certificate", &locator]).0,
            2
        );
        for wrong in [
            expected.replace(
                "Original depreciation expense",
                "A different supporting judgment",
            ),
            expected.replace("FY2026-P03", "FY2026-P02"),
        ] {
            let (exit, refusal) = run(
                &f.book,
                &[
                    "bundle",
                    "produce",
                    "--certificate",
                    &locator,
                    "--expect",
                    &wrong,
                ],
            );
            assert_eq!(exit, 8, "{}", refusal.render());
        }
        let mut original_bundle = None;
        for source in [locator.as_str(), certificate_path.to_str().unwrap()] {
            let produced = ok(
                &f.book,
                &[
                    "bundle",
                    "produce",
                    "--certificate",
                    source,
                    "--expect",
                    &expected,
                    "--state",
                    text(&checkpoint, "oid"),
                ],
            );
            let bundle = bytes(&produced);
            let receipt = unhex(text(&produced, "receipt"));
            let verified = fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                Some(&anchor.checkpoint),
                Some(&receipt),
                Some(certificate.digest()),
            )
            .unwrap();
            assert_eq!(verified.output, certificate.output());
            assert_eq!(verified.known_at, inputs.known_at);
            let indirect = verified.indirect_cash_flow.unwrap();
            assert_eq!(indirect.definition.name, "indirect-March");
            assert_eq!(indirect.contributions.len(), 1);
            let usd = indirect
                .units
                .iter()
                .find(|unit| unit.non_cash != 0)
                .unwrap();
            assert_eq!(
                [
                    usd.net_income,
                    usd.non_cash,
                    usd.operating,
                    usd.direct_operating,
                    usd.operating_residual,
                    usd.opening,
                    usd.financing,
                    usd.net_change,
                    usd.closing
                ],
                [
                    17_000, 2_000, 19_000, 19_000, 0, 100_000, -10_000, 9_000, 109_000
                ],
            );
            assert!(text(&produced, "verify").contains(&format!(
                "--expect {}",
                fa_verify::blake3::hex(certificate.digest()),
            )));
            if let Some(original) = &original_bundle {
                assert_eq!(&bundle, original);
            } else {
                original_bundle = Some(bundle);
            }
        }
        assert_eq!(f.head(), before);
        let authority = LaunchAuthority::new(
            f.book.clone(),
            None,
            "indirect-reader",
            LaunchProfile::Agent,
            &["read", "produce"],
        )
        .unwrap();
        let argv = [
            "bundle",
            "produce",
            "--certificate",
            "-",
            "--expect",
            &expected,
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
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        assert_eq!(bundle, original_bundle.unwrap());
        let digest = fa_verify::blake3::hex(certificate.digest());
        let argv = [
            "report",
            "indirect.fab",
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--receipt",
            "indirect.receipt",
            "--expect",
            &digest,
            "--json",
        ]
        .map(str::to_string);
        let read = |name: &str| match name {
            "indirect.fab" => Ok(bundle.clone()),
            "indirect.receipt" => Ok(receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                name.to_string(),
            )),
        };
        let verified = fa_verify::cli::run(&argv, &read);
        assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
        assert!(
            verified
                .stdout
                .contains("\"report_mode\":\"indirect_cash_flow\"")
        );
        assert!(verified.stdout.contains("Original depreciation expense"));
        f.assert_proof_accesses_since(before, "indirect-reader", 1);
    }
}
