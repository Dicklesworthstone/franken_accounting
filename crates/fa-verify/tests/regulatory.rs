//! Public v9 regulatory replay over the existing independently signed journal.
//!
//! These frozen certificates were hand-encoded from explicit arithmetic: P2
//! revenue 1,234 less expense 234 gives income 1,000; closing assets/equity are
//! 1,500, versus 500 in P1. All twelve other registered units have zero rows.
//! Each certificate is attached to the original signed prefix without changing
//! its checkpoint, journal records, or registry documents. The hostile vectors
//! have valid recomputed output/certificate hashes and their own explicit pins.
//! No producer crate, private fold, fake signature checker, or dev dependency is
//! used. These custom GL schedules do not establish regulatory filing compliance.

#![forbid(unsafe_code)]

use fa_verify::report::{VerifiedReport, verify_report_expected};

const BASE: &str = include_str!("../src/report/tests/signed-bundle.hex");
const CHECKPOINT: &str = include_str!("../src/report/tests/signed-checkpoint.hex");
const KEY: &str = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61";

type Case = (&'static str, &'static str);

const INCOME: [Case; 3] = [
    (
        include_str!("regulatory/valid-income-0.certificate.hex"),
        "206866b1dc9d6d709ed373a32d58be732b51c7b14e535f04570a9d11bc2fbace",
    ),
    (
        include_str!("regulatory/valid-income-1.certificate.hex"),
        "ac63af3ad016ca5cf6e6ebe8e47c5d0f0e7377244a18b08aecc72cd84c2bc8f8",
    ),
    (
        include_str!("regulatory/valid-income-2.certificate.hex"),
        "440fb0946fde175c97d23c06f5f87e643e04da73d2707de485c2a7ff2355fcfa",
    ),
];
const STOCK: [Case; 3] = [
    (
        include_str!("regulatory/valid-stock-0.certificate.hex"),
        "edf232355aed79d4b21a446c03087e00cf886540e1de8ddacc1fd30a30102038",
    ),
    (
        include_str!("regulatory/valid-stock-1.certificate.hex"),
        "54093c75a09daecbd89a1181de3e058c3dc4b6295d3ba73e2c6a46b7b6b9ff6a",
    ),
    (
        include_str!("regulatory/valid-stock-2.certificate.hex"),
        "560d56353112104c5c2e130a5fa9ba2821fb9480c3148a48d20d5ad57b2d2c79",
    ),
];

fn unhex(text: &str) -> Vec<u8> {
    let bytes: Vec<_> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixed(text: &str) -> [u8; 32] {
    unhex(text).try_into().unwrap()
}

fn count(bytes: &[u8], at: &mut usize) -> usize {
    let result = u32::from_le_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    result
}

fn skip_frame(bytes: &[u8], at: &mut usize) {
    let length = count(bytes, at);
    *at += length;
    assert!(*at <= bytes.len());
}

fn bundle(case: Case) -> Vec<u8> {
    let base = unhex(BASE);
    let mut at = 0;
    skip_frame(&base, &mut at);
    at += 4; // Bundle major/minor, followed by the framed certificate.
    let length_at = at;
    let length = count(&base, &mut at);
    let certificate = unhex(case.0);
    assert_eq!(&certificate[certificate.len() - 32..], &fixed(case.1));
    let mut result = base[..length_at].to_vec();
    result.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
    result.extend_from_slice(&certificate);
    result.extend_from_slice(&base[at + length..]);
    result
}

fn verify(case: Case) -> VerifiedReport {
    let key = fixed(KEY);
    let checkpoint = fa_verify::verify_checkpoint(&unhex(CHECKPOINT), &[key]).unwrap();
    verify_report_expected(
        &bundle(case),
        &[key],
        Some(&checkpoint.checkpoint),
        None,
        Some(&fixed(case.1)),
    )
    .unwrap()
}

fn refusal(case: Case) -> &'static str {
    verify_report_expected(
        &bundle(case),
        &[fixed(KEY)],
        None,
        None,
        Some(&fixed(case.1)),
    )
    .unwrap_err()
    .predicate
}

fn assert_projection(verified: VerifiedReport, form: usize, activity: bool) {
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.known_at, 9);
    assert_eq!(verified.checked_records, 10);
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    let schedule = verified.regulatory_schedule.unwrap();
    assert_eq!(schedule.form, ["FFIEC031", "FFIEC041", "FRY9C"][form]);
    assert_eq!(
        schedule.schedule_code,
        if activity {
            "RI"
        } else if form == 2 {
            "HC"
        } else {
            "RC"
        }
    );
    assert_eq!(schedule.instruction_version, "2026Q1");
    assert!(!schedule.instrument_inputs_read);
    assert_eq!(schedule.declared_instrument_inputs.len(), 1);
    let declared = &schedule.declared_instrument_inputs[0];
    assert_eq!(
        declared.line_code,
        if activity { "revenue" } else { "assets" }
    );
    assert_eq!(declared.instrument_kind, "Loan");
    assert_eq!(declared.attribute_name, "category");
    let statement = schedule.statement;
    assert_eq!(statement.units, (0..13).collect::<Vec<_>>());
    assert_eq!(statement.columns.len(), 2);
    assert_eq!(statement.columns[0].periods, ["P2"]);
    assert_eq!(statement.columns[1].periods, ["P1"]);
    assert_eq!(statement.columns[0].effective_from, activity.then_some(31));
    assert_eq!(statement.columns[1].effective_from, activity.then_some(0));
    assert_eq!(statement.columns[0].effective_through, 58);
    assert_eq!(statement.columns[1].effective_through, 30);
    let expected = if activity {
        [
            ("revenue", [1234, 0]),
            ("expense", [234, 0]),
            ("income", [1000, 0]),
        ]
    } else {
        [
            ("assets", [1500, 500]),
            ("equity", [1500, 500]),
            ("check", [0, 0]),
        ]
    };
    assert_eq!(statement.lines.len(), 39);
    for (code, values) in expected {
        for unit in 0..13 {
            let matching: Vec<_> = statement
                .lines
                .iter()
                .filter(|line| line.code == code && line.unit == unit)
                .collect();
            assert_eq!(matching.len(), 1, "{code} unit {unit}");
            assert_eq!(matching[0].amounts, if unit == 0 { values } else { [0, 0] });
        }
    }
    assert!(statement.mappings.iter().all(|mapping| mapping.is_leaf));
    assert!(
        !statement
            .mappings
            .iter()
            .any(|mapping| ["1100", "6000"].contains(&mapping.code.as_str()))
    );
    assert!(
        statement
            .mappings
            .iter()
            .any(|mapping| mapping.code == "5001")
    );
}

#[test]
fn regulatory_public_signed_activity_replays_three_forms_and_all_registered_units() {
    for (form, case) in INCOME.into_iter().enumerate() {
        assert_projection(verify(case), form, true);
    }
}

#[test]
fn regulatory_public_signed_stock_replays_prior_period_carry_and_comparatives() {
    for (form, case) in STOCK.into_iter().enumerate() {
        assert_projection(verify(case), form, false);
    }
}

#[test]
fn regulatory_public_rejects_resealed_amount_zero_row_mapping_and_comparative_edits() {
    for case in [
        (
            include_str!("regulatory/wrong-amount.certificate.hex"),
            "0c408477d33c50b82892d190596cdd8bbcf9f6ca3a948c22494db83ff54401ec",
        ),
        (
            include_str!("regulatory/missing-zero-unit.certificate.hex"),
            "5934c8af9c67f7c2d94b23e3e9ed7cfc52b93fc175beafd4648416cedd8cd801",
        ),
        (
            include_str!("regulatory/wrong-mapping.certificate.hex"),
            "2b408007cc6dd894e2fa71f194df16350f7cf7b006551a905cef621d4472b62f",
        ),
        (
            include_str!("regulatory/wrong-comparative.certificate.hex"),
            "0984a2cb39472a929d0f9165f9c27675dab9f8ba9091acdcea34147482be166e",
        ),
    ] {
        assert_eq!(refusal(case), "regulatory_schedule_recomputation");
    }
}

#[test]
fn regulatory_public_requires_valid_declarations_and_complete_registry_closure() {
    assert_eq!(
        refusal((
            include_str!("regulatory/unknown-declared-line.certificate.hex"),
            "0905a68d651f68ac09bfbf19d85546ffd9b289cee4d10efc9abbbad5de11a471"
        )),
        "regulatory_definition"
    );
    let mut incomplete = bundle(INCOME[1]);
    let mut at = 0;
    skip_frame(&incomplete, &mut at); // Bundle format.
    at += 4;
    for _ in 0..3 {
        // Certificate, checkpoint, complete prefix.
        skip_frame(&incomplete, &mut at);
    }
    for _ in 0..count(&incomplete, &mut at) {
        at += 4; // Record proposal length.
        skip_frame(&incomplete, &mut at);
    }
    assert_eq!(count(&incomplete, &mut at), 0); // Migration bodies.
    let count_at = at;
    assert_eq!(count(&incomplete, &mut at), 4);
    for _ in 0..3 {
        skip_frame(&incomplete, &mut at); // Document name.
        skip_frame(&incomplete, &mut at); // Canonical bytes.
    }
    incomplete.truncate(at);
    incomplete[count_at..count_at + 4].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(
        verify_report_expected(
            &incomplete,
            &[fixed(KEY)],
            None,
            None,
            Some(&fixed(INCOME[1].1))
        )
        .unwrap_err()
        .predicate,
        "registry_closure"
    );
}

#[test]
fn regulatory_public_requires_recipient_certificate_authority() {
    let bytes = bundle(INCOME[0]);
    assert_eq!(
        verify_report_expected(&bytes, &[fixed(KEY)], None, None, None)
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );
    assert_eq!(
        verify_report_expected(&bytes, &[fixed(KEY)], None, None, Some(&[255; 32]))
            .unwrap_err()
            .predicate,
        "recipient_certificate"
    );
}

#[test]
fn regulatory_public_cli_reports_gl_scope_and_unjudged_instrument_and_filing_claims() {
    let args = [
        "report",
        "bundle",
        "--key",
        KEY,
        "--checkpoint",
        "checkpoint",
        "--expect",
        INCOME[1].1,
        "--json",
    ]
    .map(str::to_string);
    let result = fa_verify::cli::run(&args, &|path| match path {
        "bundle" => Ok(bundle(INCOME[1])),
        "checkpoint" => Ok(unhex(CHECKPOINT)),
        _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, path)),
    });
    assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    for claim in [
        "\"report_mode\":\"regulatory_schedule\"",
        "\"calculation\":\"general_ledger_projection\"",
        "\"instrument_inputs_read\":false",
        "\"instrument_values\":\"not_judged\"",
        "\"published_regulatory_instructions\":\"not_judged\"",
        "\"regulatory_compliance\":\"not_judged\"",
    ] {
        assert!(result.stdout.contains(claim), "{claim}: {}", result.stdout);
    }
}
