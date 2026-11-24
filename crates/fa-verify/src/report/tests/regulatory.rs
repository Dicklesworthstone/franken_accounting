//! Regulatory fixtures reuse signed journal evidence but hand-encode the
//! schedule definition and calculate the expected GL projection separately.
use super::*;

fn definition(activity: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:custom-statement-def:v1")
        .bytes(if activity {
            b"bank_income"
        } else {
            b"bank_stock"
        })
        .bytes(b"General-ledger regulatory projection")
        .u32(1)
        .u8(u8::from(activity))
        .count(3);
    if activity {
        w.bytes(b"revenue")
            .bytes(b"Revenue")
            .u8(0)
            .u8(2)
            .count(1)
            .bytes(b"4000")
            .u8(1)
            .bytes(b"expense")
            .bytes(b"Expenses")
            .u8(0)
            .u8(3)
            .count(1)
            .bytes(b"5")
            .u8(0)
            .bytes(b"income")
            .bytes(b"Net income")
            .u8(1)
            .count(1)
            .bytes(b"revenue")
            .count(1)
            .bytes(b"expense")
            .count(0);
    } else {
        w.bytes(b"assets")
            .bytes(b"Assets")
            .u8(0)
            .u8(3)
            .count(1)
            .bytes(b"1")
            .u8(0)
            .bytes(b"equity")
            .bytes(b"Liabilities and equity")
            .u8(0)
            .u8(1)
            .count(4)
            .u8(2)
            .u8(3)
            .u8(4)
            .u8(5)
            .u8(1)
            .bytes(b"check")
            .bytes(b"Balance check")
            .u8(1)
            .count(1)
            .bytes(b"assets")
            .count(1)
            .bytes(b"equity")
            .count(1)
            .bytes(b"check");
    }
    w.buf
}

fn schedule(activity: bool, form: u8, instruction: &str, inputs: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:regulatory-schedule-def:v1")
        .u8(form)
        .bytes(if activity { b"RI" } else { b"RC" })
        .bytes(instruction.as_bytes())
        .bytes(&definition(activity))
        .count(inputs.len());
    for (line, kind, attribute) in inputs {
        w.bytes(line.as_bytes())
            .bytes(kind.as_bytes())
            .bytes(attribute.as_bytes());
    }
    w.buf
}

fn projection(activity: bool) -> VerifiedStatement {
    let definition = definition(activity);
    let mut result = super::expected(activity);
    result.definition_name = if activity {
        "bank_income"
    } else {
        "bank_stock"
    }
    .into();
    result.definition_digest = hash_parts(
        b"fa:custom-statement-def:v1",
        &[&(definition.len() as u32).to_le_bytes(), &definition],
    );
    let rows = if activity {
        [
            ("revenue", "Revenue", 1234, 0),
            ("expense", "Expenses", 234, 0),
            ("income", "Net income", 1000, 0),
        ]
    } else {
        [
            ("assets", "Assets", 1500, 500),
            ("equity", "Liabilities and equity", 1500, 500),
            ("check", "Balance check", 0, 0),
        ]
    };
    result.lines = rows
        .into_iter()
        .flat_map(|(code, label, current, comparative)| {
            (0..13).map(move |unit| StatementLine {
                code: code.into(),
                label: label.into(),
                unit,
                amounts: if unit == 0 {
                    vec![current, comparative]
                } else {
                    vec![0, 0]
                },
            })
        })
        .collect();
    if !activity {
        for mapping in &mut result.mappings {
            if mapping.account_type != 1 {
                mapping.line_code = "equity".into();
            }
        }
    }
    result
}

fn output(activity: bool, expected: &VerifiedStatement) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:regulatory-schedule:v1")
        .bytes(&output_bytes(expected, &definition(activity), 9));
    w.buf
}

/// Replace only the definition, output and certificate identity of a v4
/// fixture. Its checkpoint signature, complete records, prefix and registries
/// survive exactly. The new schedule still needs the recipient's own pin.
fn wrap(base: &[u8], schedule: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut bundle = Reader::new(base);
    assert_eq!(bundle.bytes(64, "format").unwrap(), REPORT_BUNDLE_FORMAT);
    let major = bundle.u16("major").unwrap();
    let minor = bundle.u16("minor").unwrap();
    let original = bundle
        .bytes(MAX_REPORT_BUNDLE_BYTES, "certificate")
        .unwrap();
    let rest = &base[base.len() - bundle.remaining()..];
    let mut r = Reader::new(original);
    assert_eq!(
        r.fixed::<24>("format").unwrap(),
        *STATEMENT_CERTIFICATE_FORMAT
    );
    let scope = r.bytes(64, "scope").unwrap();
    let authority = r.bytes(64, "authority").unwrap();
    assert_eq!(r.bytes(64, "output format").unwrap(), b"fa:statement:v1");
    let book = r.fixed::<16>("book").unwrap();
    let branch = r.fixed::<16>("branch").unwrap();
    let known_at = r.u64("known at").unwrap();
    assert_eq!(r.u8("selector").unwrap(), 2);
    r.bytes(65_536, "definition").unwrap();
    let start = original.len() - r.remaining();
    strings(&mut r, "periods").unwrap();
    strings(&mut r, "comparative").unwrap();
    r.fixed::<32>("registry digest").unwrap();
    r.fixed::<32>("root").unwrap();
    r.u64("leaves").unwrap();
    let n = r.count(11, 4, "native inputs").unwrap();
    for _ in 0..n {
        r.bytes(1024 * 1024, "native input").unwrap();
    }
    let end = original.len() - r.remaining();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "output").unwrap();
    r.fixed::<32>("output digest").unwrap();
    assert!(!r.present("time selection").unwrap());
    r.fixed::<32>("digest").unwrap();
    r.finish("source certificate").unwrap();
    let mut cert = Writer::default();
    cert.fixed(b"fa:report-certificate:v9")
        .bytes(scope)
        .bytes(authority)
        .bytes(b"fa:regulatory-schedule:v1")
        .fixed(&book)
        .fixed(&branch)
        .u64(known_at)
        .u8(7)
        .bytes(schedule)
        .fixed(&original[start..end])
        .bytes(output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[output]))
        .u8(0);
    let digest = hash_parts(b"fa:report-certificate:v9", &[&cert.buf]);
    cert.fixed(&digest);
    let mut out = Writer::default();
    out.bytes(REPORT_BUNDLE_FORMAT)
        .u16(major)
        .u16(minor)
        .bytes(&cert.buf)
        .fixed(rest);
    (out.buf, digest)
}

#[test]
fn regulatory_schedules_recompute_stock_activity_comparatives_and_declared_input_boundary() {
    for activity in [false, true] {
        let expected = projection(activity);
        let (base, anchor, _) = super::fixture(activity, &super::expected(activity));
        let line = if activity { "revenue" } else { "assets" };
        for (form, name) in [(0, "FFIEC031"), (1, "FFIEC041"), (2, "FRY9C")] {
            let schedule = schedule(activity, form, "2026Q1", &[(line, "Loan", "category")]);
            let (bytes, trusted) = wrap(&base, &schedule, &output(activity, &expected));
            let verified = verify_statement_fixture(&bytes, anchor.clone(), trusted).unwrap();
            assert_eq!(verified.checked_records, 10);
            assert_eq!(verified.known_at, 9);
            assert_eq!(verified.activity, activity);
            assert_eq!(verified.unit_universe_source, "authenticated-registry");
            assert!(verified.statement.is_none());
            assert!(verified.custom_statement.is_none());
            let report = verified.regulatory_schedule.unwrap();
            assert_eq!(report.statement, expected);
            assert_eq!(report.form, name);
            assert_eq!(report.instruction_version, "2026Q1");
            assert_eq!(report.schedule_code, if activity { "RI" } else { "RC" });
            assert_eq!(
                report.schedule_digest,
                hash_parts(
                    b"fa:regulatory-schedule-def:v1",
                    &[&(schedule.len() as u32).to_le_bytes(), &schedule]
                )
            );
            assert!(!report.instrument_inputs_read);
            assert_eq!(
                report.declared_instrument_inputs,
                [RegulatoryInstrumentInput {
                    line_code: line.into(),
                    instrument_kind: "Loan".into(),
                    attribute_name: "category".into(),
                }]
            );
        }
    }
}

#[test]
fn resealed_regulatory_amounts_mappings_and_comparatives_are_rejected() {
    for activity in [false, true] {
        let (base, anchor, _) = super::fixture(activity, &super::expected(activity));
        let schedule = schedule(activity, 1, "2026Q1", &[]);
        for change in 0..4 {
            let mut expected = projection(activity);
            match change {
                0 => expected.lines[0].amounts[0] += 1,
                1 => {
                    expected.mappings.retain(|mapping| mapping.code != "5001");
                }
                2 => expected.columns[1].effective_through -= 1,
                3 => expected.lines.retain(|line| line.unit != 12),
                _ => unreachable!(),
            }
            let (bytes, digest) = wrap(&base, &schedule, &output(activity, &expected));
            assert_eq!(
                verify_statement_fixture(&bytes, anchor.clone(), digest)
                    .unwrap_err()
                    .predicate,
                "regulatory_schedule_recomputation"
            );
        }
    }
}

#[test]
fn regulatory_definition_and_complete_registry_require_recipient_authority() {
    let (base, anchor, _) = super::fixture(true, &super::expected(true));
    let output = output(true, &projection(true));
    let original = schedule(true, 1, "2026Q1", &[("revenue", "Loan", "category")]);
    let (bytes, trusted) = wrap(&base, &original, &output);
    assert_eq!(
        verify_report_with(&bytes, &[], None, None, None, |_, _| Ok(anchor.clone()))
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );
    for changed in [
        schedule(true, 2, "2026Q1", &[("revenue", "Loan", "category")]),
        schedule(true, 1, "2026Q2", &[("revenue", "Loan", "category")]),
        schedule(true, 1, "2026Q1", &[]),
        schedule(true, 1, "2026Q1", &[("revenue", "Loan", "risk_weight")]),
    ] {
        let (changed, _) = wrap(&base, &changed, &output);
        assert_eq!(
            verify_statement_fixture(&changed, anchor.clone(), trusted)
                .unwrap_err()
                .predicate,
            "recipient_certificate"
        );
    }
    let docs = registries();
    for changed in [docs[..3].to_vec(), {
        let mut extra = docs.clone();
        extra.push(("rounding_laws".into(), Vec::new()));
        extra
    }] {
        let (base, anchor, _) = pack(
            &history(),
            &super::definition(true),
            &output_bytes(&super::expected(true), &super::definition(true), 9),
            &changed,
            closure(&docs),
        );
        let (bytes, trusted) = wrap(&base, &original, &output);
        assert!(verify_statement_fixture(&bytes, anchor, trusted).is_err());
    }
}

#[test]
fn regulatory_decoder_rejects_invalid_metadata_and_instrument_declarations() {
    let (base, anchor, _) = super::fixture(false, &super::expected(false));
    let output = output(false, &projection(false));
    let mut trailing = schedule(false, 1, "2026Q1", &[]);
    trailing.push(0);
    for malformed in [
        schedule(false, 3, "2026Q1", &[]),
        schedule(false, 1, " ", &[]),
        schedule(false, 1, "2026Q1", &[("absent", "Loan", "category")]),
        schedule(false, 1, "2026Q1", &[("assets", " ", "category")]),
        schedule(false, 1, "2026Q1", &[("assets", "Loan", " ")]),
        trailing,
    ] {
        let (bytes, trusted) = wrap(&base, &malformed, &output);
        assert!(verify_statement_fixture(&bytes, anchor.clone(), trusted).is_err());
    }
}

#[test]
fn regulatory_bundles_refuse_instant_selection_and_unauthenticated_registry_profiles() {
    let (base, anchor, _) = super::fixture(false, &super::expected(false));
    let (bytes, trusted) = wrap(
        &base,
        &schedule(false, 1, "2026Q1", &[]),
        &output(false, &projection(false)),
    );
    let mut r = Reader::new(&bytes);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    let original = r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    let tail = &bytes[bytes.len() - r.remaining()..];
    for major in [1, 3] {
        let mut invalid = Writer::default();
        invalid
            .bytes(REPORT_BUNDLE_FORMAT)
            .u16(major)
            .u16(0)
            .bytes(original)
            .fixed(tail);
        assert!(verify_statement_fixture(&invalid.buf, anchor.clone(), trusted).is_err());
    }
    // A structurally canonical instant selector remains outside this bounded
    // sequence-only family, even with a new valid certificate commitment.
    assert_eq!(original[original.len() - 33], 0);
    let mut cert = Writer::default();
    cert.fixed(&original[..original.len() - 33])
        .u8(1)
        .u64(1)
        .u64(10)
        .u64(9)
        .u64(1)
        .u64(0)
        .u8(0)
        .u8(1)
        .u8(0)
        .u128(1)
        .u8(0);
    let digest = hash_parts(b"fa:report-certificate:v9", &[&cert.buf]);
    cert.fixed(&digest);
    let mut invalid = Writer::default();
    invalid
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&cert.buf)
        .fixed(tail);
    assert_eq!(
        verify_statement_fixture(&invalid.buf, anchor, digest)
            .unwrap_err()
            .predicate,
        "supported_report"
    );
}

#[test]
fn standalone_cli_recomputes_signed_regulatory_projection_without_claiming_instrument_values() {
    let signed = unhex(include_str!("signed-bundle.hex"));
    let schedule = schedule(true, 1, "2026Q1", &[("revenue", "Loan", "category")]);
    let (bundle, trusted) = wrap(&signed, &schedule, &output(true, &projection(true)));
    let digest = crate::blake3::hex(&trusted);
    let checkpoint = unhex(include_str!("signed-checkpoint.hex"));
    let read = |path: &str| match path {
        "regulatory.bundle" => Ok(bundle.clone()),
        "regulatory.checkpoint" => Ok(checkpoint.clone()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "unknown fixture input",
        )),
    };
    let args: Vec<String> = [
        "report",
        "regulatory.bundle",
        "--key",
        TRUSTED_KEY,
        "--checkpoint",
        "regulatory.checkpoint",
        "--expect",
        &digest,
        "--json",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let result = crate::cli::run(&args, &read);
    assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    for fragment in [
        "\"report_mode\":\"regulatory_schedule\"",
        "regulatory_schedule_recomputation",
        "general_ledger_projection",
        "\"instrument_inputs_read\":false",
        "\"declared_inputs\"",
        "\"attribute\":\"category\"",
        "\"code\":\"revenue\"",
        "\"amounts\":[\"1234\",\"0\"]",
        "\"regulatory_compliance\":\"not_judged\"",
    ] {
        assert!(
            result.stdout.contains(fragment),
            "{fragment}: {}",
            result.stdout
        );
    }
}
