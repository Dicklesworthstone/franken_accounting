//! Mixed loan payments and reusable classification policies feed indirect cash.
//! Expectations are assembled from the user's original inputs, never from a
//! delivered certificate or its generated replay command.

use super::*;

const LABEL: &str = "March indirect cash";

struct Inputs {
    fixture: Fixture,
    evidence: String,
    sale: Json,
    payments: Vec<Json>,
    depreciation: Json,
    detail: Json,
    known_at: u64,
}

fn post(f: &Fixture, evidence: &str, key: &str, day: &str, legs: &str) -> Json {
    let intent = write(
        &f.dir,
        &format!("{key}.json"),
        &format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{legs}]}}"#),
    );
    ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", evidence],
    )
}

impl Inputs {
    fn new(mixed_payment: bool) -> Self {
        let fixture = Fixture::new();
        let chart = write(
            &fixture.dir,
            "indirect-chart.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1500","name":"Equipment","type":"Asset","unit":"USD"},{"code":"1590","name":"Accumulated depreciation","type":"Asset","unit":"USD"},{"code":"2000","name":"Loan","type":"Liability","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6100","name":"Interest","type":"Expense","unit":"USD"},{"code":"6200","name":"Depreciation","type":"Expense","unit":"USD"}]}"#,
        );
        ok(&fixture.book, &["chart", "import", &chart]);
        ok(
            &fixture.book,
            &["period", "create", "--fiscal-year", "2026"],
        );
        for period in ["FY2026-P02", "FY2026-P03"] {
            ok(&fixture.book, &["period", "open", period]);
        }
        let evidence_file = write(
            &fixture.dir,
            "bank.txt",
            "Loan, receipts and depreciation evidence.",
        );
        let evidence = ok(
            &fixture.book,
            &[
                "document",
                "add",
                &evidence_file,
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        );
        let evidence = text(&evidence, "oid").to_string();
        post(
            &fixture,
            &evidence,
            "loan-opening",
            "2026-02-20",
            r#"{"side":"debit","account":"1000","amount":"1000.00 USD"},{"side":"credit","account":"2000","amount":"1000.00 USD"}"#,
        );
        let sale = post(
            &fixture,
            &evidence,
            "cash-sale",
            "2026-03-10",
            r#"{"side":"debit","account":"1000","amount":"200.00 USD"},{"side":"credit","account":"4000","amount":"200.00 USD"}"#,
        );
        let payments = if mixed_payment {
            vec![post(
                &fixture,
                &evidence,
                "loan-payment",
                "2026-03-15",
                r#"{"side":"debit","account":"2000","amount":"100.00 USD"},{"side":"debit","account":"6100","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"110.00 USD"}"#,
            )]
        } else {
            vec![
                post(
                    &fixture,
                    &evidence,
                    "principal-payment",
                    "2026-03-15",
                    r#"{"side":"debit","account":"2000","amount":"100.00 USD"},{"side":"credit","account":"1000","amount":"100.00 USD"}"#,
                ),
                post(
                    &fixture,
                    &evidence,
                    "interest-payment",
                    "2026-03-15",
                    r#"{"side":"debit","account":"6100","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}"#,
                ),
            ]
        };
        let depreciation = post(
            &fixture,
            &evidence,
            "noncash-depreciation",
            "2026-03-31",
            r#"{"side":"debit","account":"6200","amount":"20.00 USD"},{"side":"credit","account":"1590","amount":"20.00 USD"}"#,
        );
        let known_at = fixture.head();
        let detail = ok(
            &fixture.book,
            &[
                "gl",
                "detail",
                "--account",
                "1000,6200",
                "--unit",
                "USD",
                "--from",
                "2026-03-01",
                "--to",
                "2026-03-31",
                "--as-known-at",
                &known_at.to_string(),
            ],
        );
        Self {
            fixture,
            evidence,
            sale,
            payments,
            depreciation,
            detail,
            known_at,
        }
    }

    fn line(&self, entry: &Json, account: &str) -> &Json {
        get(&self.detail, "lines")
            .as_arr()
            .unwrap()
            .iter()
            .find(|line| {
                text(line, "entry_digest") == text(entry, "entry_digest")
                    && text(line, "account") == account
            })
            .expect("the original posted leg, not a manufactured classification leg")
    }

    fn policy(&self, classification: &str) -> String {
        let depreciation = self.line(&self.depreciation, "6200");
        format!(
            r#"{{"name":"indirect-March","cash_policy":"documented-cash","cash_accounts":["1000"],{classification},"adjustments":[{{"entry_digest":"{}","leg_index":{},"category":"non_cash","sign":"debit_minus_credit","reason":"Original depreciation expense"}}]}}"#,
            text(depreciation, "entry_digest"),
            integer(depreciation, "leg_index"),
        )
    }

    fn expected(&self, policy: &str) -> String {
        format!(
            r#"{{"kind":"indirect-cash-flow","accounts":["1000"],"units":["USD"],"label":"{LABEL}","from":"2026-03-01","through":"2026-03-31","known_at":{},"income_periods":["FY2026-P03"],"policy":{policy}}}"#,
            self.known_at,
        )
    }
}

fn assignment(line: &Json, activity: &str) -> String {
    format!(
        r#"{{"entry_digest":"{}","leg_index":{},"activity":"{activity}"}}"#,
        text(line, "entry_digest"),
        integer(line, "leg_index"),
    )
}

fn report_args<'a>(policy_file: &'a str, known_at: &'a str) -> Vec<&'a str> {
    vec![
        "gl",
        "cash-flow",
        "--indirect",
        "--income-period",
        "FY2026-P03",
        "--account",
        "1000",
        "--unit",
        "USD",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--label",
        LABEL,
        "--as-known-at",
        known_at,
        "--policy",
        policy_file,
    ]
}

fn assert_economic_result(report: &Json) {
    assert_eq!(text(report, "event"), "indirect_cash_flow");
    assert_eq!(text(report, "policy"), "indirect-March");
    assert_eq!(text(report, "cash_policy"), "documented-cash");
    let units = get(report, "units").as_arr().unwrap();
    assert_eq!(units.len(), 1);
    for (field, amount) in [
        ("net_income", "170.00 USD"),
        ("non_cash", "20.00 USD"),
        ("operating", "190.00 USD"),
        ("direct_operating", "190.00 USD"),
        ("operating_residual", "0.00 USD"),
        ("opening", "1000.00 USD"),
        ("financing", "-100.00 USD"),
        ("net_change", "90.00 USD"),
        ("closing", "1090.00 USD"),
    ] {
        assert_eq!(text(&units[0], field), amount, "{field}");
    }
    let contributions = get(report, "contributions").as_arr().unwrap();
    assert_eq!(contributions.len(), 1);
    assert_eq!(text(&contributions[0], "account"), "6200");
    assert_eq!(text(&contributions[0], "amount"), "20.00 USD");
}

fn certify_and_replay(
    inputs: &Inputs,
    policy: &str,
    kind: fa::CashFlowBasisKind,
) -> (Json, String) {
    let f = &inputs.fixture;
    let policy_file = write(&f.dir, "indirect-policy.json", policy);
    let at = inputs.known_at.to_string();
    let mut args = report_args(&policy_file, &at);
    assert_economic_result(&ok(&f.book, &args));
    let saved = f.dir.join("indirect.certificate");
    args.extend(["--certificate-out", saved.to_str().unwrap()]);
    let metadata = aging::certify(f, &args);
    assert_eq!(text(&metadata, "output_format"), "fa:indirect-cash-flow:v2");
    let encoded = unhex(text(&metadata, "bytes"));
    assert_eq!(std::fs::read(&saved).unwrap(), encoded);
    let format = b"fa:indirect-cash-flow-certificate:v2";
    assert_eq!(&encoded[..4], &(format.len() as u32).to_le_bytes());
    assert_eq!(&encoded[4..4 + format.len()], format);
    let certificate = fa::IndirectCashFlowCertificate::decode(&encoded).unwrap();
    assert_eq!(certificate.source_certificate().kind(), kind);
    assert_eq!(certificate.known_at().0, inputs.known_at);
    let artifact = fa::ReportArtifact::decode(&encoded).unwrap();
    let locator = format!("C:{}", text(&metadata, "oid"));
    let expected = inputs.expected(policy);
    let current = ok(
        &f.book,
        &["certificate", "status", &locator, "--expect", &expected],
    );
    assert_eq!(text(&current, "status"), "Current");

    // Reopening and a later backdated receipt cannot rewrite the retained view.
    f.post(
        "later-backdated-cash",
        "2026-03-20",
        "99.00",
        &inputs.evidence,
    );
    f.checkpoint();
    let frontier = f.head();
    for (index, source) in [locator.as_str(), saved.to_str().unwrap()]
        .into_iter()
        .enumerate()
    {
        let output = f.dir.join(format!("replayed-{index}.report"));
        let replayed = ok(
            &f.book,
            &[
                "replay",
                source,
                "--expect",
                &expected,
                "--output",
                output.to_str().unwrap(),
            ],
        );
        assert_eq!(text(&replayed, "family"), "indirect-cash-flow");
        assert_eq!(
            text(&replayed, "output_digest"),
            text(&metadata, "output_digest")
        );
        assert_eq!(std::fs::read(output).unwrap(), artifact.output());
        assert_eq!(
            f.head(),
            frontier,
            "native replay does not append a journal record"
        );
    }
    (metadata, locator)
}

fn refuse_expectation(inputs: &Inputs, locator: &str, policy: &str) {
    let expected = inputs.expected(policy);
    let (code, error) = run(
        &inputs.fixture.book,
        &["replay", locator, "--expect", &expected],
    );
    assert_eq!(code, 8, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-150");
}

#[test]
fn one_bank_leg_splits_principal_and_interest_into_a_retained_indirect_report() {
    let inputs = Inputs::new(true);
    let sale = inputs.line(&inputs.sale, "1000");
    let payment = inputs.line(&inputs.payments[0], "1000");
    assert_eq!(text(payment, "credits"), "110.00 USD");
    let policy = inputs.policy(&format!(
        r#""splits":[{{"entry_digest":"{}","leg_index":{},"reason":"Cash revenue","portions":[{{"activity":"operating","amount":"200.00 USD"}}]}},{{"entry_digest":"{}","leg_index":{},"reason":"Documented principal and interest","portions":[{{"activity":"operating","amount":"10.00 USD"}},{{"activity":"financing","amount":"100.00 USD"}}]}}]"#,
        text(sale, "entry_digest"), integer(sale, "leg_index"),
        text(payment, "entry_digest"), integer(payment, "leg_index"),
    ));
    let (metadata, locator) = certify_and_replay(&inputs, &policy, fa::CashFlowBasisKind::Split);
    let certificate =
        fa::IndirectCashFlowCertificate::decode(&unhex(text(&metadata, "bytes"))).unwrap();
    let fa::CashFlowBasisCertificate::Split(source) = certificate.source_certificate() else {
        panic!("the original split certificate must remain the indirect source");
    };
    assert_eq!(source.definition().splits.len(), 2);
    let split = source
        .definition()
        .splits
        .iter()
        .find(|split| fa_verify::blake3::hex(&split.entry_digest) == text(payment, "entry_digest"))
        .unwrap();
    assert_eq!(
        split.portions.len(),
        2,
        "one original bank leg, two classifications"
    );
    assert_eq!(
        split
            .portions
            .iter()
            .map(|portion| portion.amount)
            .sum::<i128>(),
        11_000
    );

    refuse_expectation(
        &inputs,
        &locator,
        &policy.replace(
            "Documented principal and interest",
            "A different accounting judgment",
        ),
    );
    // A well-formed EUR split still cannot replace the cited USD cash leg.
    // Change both portions so this reaches native source binding, rather than
    // the earlier malformed mixed-currency-input check.
    let foreign_currency = policy
        .replace("10.00 USD", "10.00 EUR")
        .replace("100.00 USD", "100.00 EUR");
    refuse_expectation(&inputs, &locator, &foreign_currency);

    let at = inputs.known_at.to_string();
    for (name, invalid) in [
        (
            "mixed-portion-currencies.json",
            policy.replace("10.00 USD", "10.00 EUR"),
        ),
        ("foreign-currency.json", foreign_currency),
        (
            "conflicting-bases.json",
            policy.replace(r#""splits":"#, r#""assignments":[],"splits":"#),
        ),
    ] {
        let file = write(&inputs.fixture.dir, name, &invalid);
        let (code, error) = run(&inputs.fixture.book, &report_args(&file, &at));
        assert_ne!(
            code,
            0,
            "invalid cash basis was admitted: {}",
            error.render()
        );
    }
}

#[test]
fn policy_basis_replay_binds_unused_rules_overrides_and_the_classification_family() {
    let inputs = Inputs::new(false);
    let sale = inputs.line(&inputs.sale, "1000");
    let original_override = assignment(sale, "operating");
    let policy = inputs.policy(&format!(
        r#""account_rules":[{{"account":"4000","activity":"operating"}},{{"account":"2000","activity":"financing"}},{{"account":"6100","activity":"operating"}},{{"account":"1500","activity":"investing"}}],"overrides":[{original_override}]"#,
    ));
    let (metadata, locator) = certify_and_replay(&inputs, &policy, fa::CashFlowBasisKind::Policy);
    let certificate =
        fa::IndirectCashFlowCertificate::decode(&unhex(text(&metadata, "bytes"))).unwrap();
    let fa::CashFlowBasisCertificate::Policy(source) = certificate.source_certificate() else {
        panic!("the full reusable policy must remain the indirect source");
    };
    assert_eq!(
        source.policy().account_rules.len(),
        4,
        "the unused rule is retained"
    );
    assert_eq!(
        source.policy().overrides.len(),
        1,
        "the redundant override is provenance"
    );

    refuse_expectation(
        &inputs,
        &locator,
        &policy.replace(
            r#""account":"1500","activity":"investing""#,
            r#""account":"1500","activity":"financing""#,
        ),
    );
    refuse_expectation(
        &inputs,
        &locator,
        &policy.replace(
            &format!(r#""overrides":[{original_override}]"#),
            r#""overrides":[]"#,
        ),
    );
    let explicit = inputs.policy(&format!(
        r#""assignments":[{},{},{}]"#,
        assignment(sale, "operating"),
        assignment(inputs.line(&inputs.payments[0], "1000"), "financing"),
        assignment(inputs.line(&inputs.payments[1], "1000"), "operating"),
    ));
    // This other basis computes the same totals; it still cannot answer the
    // recipient's independently selected policy question.
    let file = write(&inputs.fixture.dir, "equal-explicit.json", &explicit);
    assert_economic_result(&ok(
        &inputs.fixture.book,
        &report_args(&file, &inputs.known_at.to_string()),
    ));
    refuse_expectation(&inputs, &locator, &explicit);
}

#[test]
fn original_split_cash_certificate_exports_by_oid_file_and_bound_stdin() {
    let inputs = Inputs::new(true);
    let f = &inputs.fixture;
    let sale = inputs.line(&inputs.sale, "1000");
    let payment = inputs.line(&inputs.payments[0], "1000");
    let policy = format!(
        r#"{{"name":"split-March","cash_accounts":["1000"],"splits":[{{"entry_digest":"{}","leg_index":{},"reason":"Cash revenue","portions":[{{"activity":"operating","amount":"200.00 USD"}}]}},{{"entry_digest":"{}","leg_index":{},"reason":"Documented principal and interest","portions":[{{"activity":"operating","amount":"10.00 USD"}},{{"activity":"financing","amount":"100.00 USD"}}]}}]}}"#,
        text(sale, "entry_digest"),
        integer(sale, "leg_index"),
        text(payment, "entry_digest"),
        integer(payment, "leg_index"),
    );
    let expected = format!(
        r#"{{"kind":"split-cash-flow","accounts":["1000"],"units":["USD"],"label":"March split cash","from":"2026-03-01","through":"2026-03-31","known_at":{},"policy":{policy}}}"#,
        inputs.known_at,
    );
    let policy_path = write(&f.dir, "split-policy.json", &policy);
    let certificate_path = f.dir.join("split.certificate");
    let metadata = aging::certify(
        f,
        &[
            "gl",
            "cash-flow",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--from",
            "2026-03-01",
            "--to",
            "2026-03-31",
            "--label",
            "March split cash",
            "--as-known-at",
            &inputs.known_at.to_string(),
            "--policy",
            &policy_path,
            "--certificate-out",
            certificate_path.to_str().unwrap(),
        ],
    );
    let encoded = unhex(text(&metadata, "bytes"));
    let certificate = fa::cash_flow_split::CashFlowSplitCertificate::decode(&encoded).unwrap();
    assert_eq!(std::fs::read(&certificate_path).unwrap(), encoded);
    let locator = format!("C:{}", text(&metadata, "oid"));
    f.post(
        "split-later-backdated",
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
    let (code, _) = run(&f.book, &["bundle", "produce", "--certificate", &locator]);
    assert_eq!(
        code, 2,
        "export requires independently retained expected inputs"
    );
    for (question, exit) in [
        (expected.replace("split-cash-flow", "indirect-cash-flow"), 2),
        (
            expected.replace("Documented principal and interest", "Another judgment"),
            8,
        ),
        (expected.replace("100.00 USD", "101.00 USD"), 8),
    ] {
        let (code, error) = run(
            &f.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--expect",
                &question,
            ],
        );
        assert_eq!(code, exit, "{}", error.render());
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
        assert!(text(&produced, "verify").contains(&format!(
            "--expect {}",
            fa_verify::blake3::hex(certificate.digest()),
        )));
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
        let split = verified.split_cash_flow.unwrap();
        assert_eq!(split.ledger.lines.len(), 2);
        assert_eq!(split.definition.splits.len(), 2);
        let unit = &split.units[0];
        assert_eq!(
            (
                unit.opening,
                unit.operating.net,
                unit.financing.net,
                unit.net_change,
                unit.closing
            ),
            (100_000, 19_000, -10_000, 9_000, 109_000),
        );
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(certificate.source_certificate().digest()),
            )
            .is_err()
        );
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
        "split-reader",
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
        "split.fab",
        "--key",
        text(&signed, "checkpoint_public_key"),
        "--receipt",
        "split.receipt",
        "--expect",
        &digest,
        "--json",
    ]
    .map(str::to_string);
    let read = |name: &str| match name {
        "split.fab" => Ok(bundle.clone()),
        "split.receipt" => Ok(receipt.clone()),
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
            .contains("\"report_mode\":\"split_cash_flow\"")
    );
    assert!(
        verified
            .stdout
            .contains("Documented principal and interest")
    );
    f.assert_proof_accesses_since(before, "split-reader", 1);
}
