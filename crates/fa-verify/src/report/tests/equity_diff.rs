//! Literal journal inputs and a separate equity wire encoder. Monetary answers
//! below are hand-calculated; no equity projection or comparison derives them.
use super::*;
use crate::report::{EquityRollForwardDiffRequest, VerifiedEquityRollForwardDiff};

const EQUITY_FORMAT: &[u8] = b"fa:equity-roll-forward-certificate:v2";
const EQUITY_DOMAIN: &[u8] = b"fa:equity-roll-forward-certificate-digest:v2";
const DIFF_FORMAT: &[u8] = b"fa:equity-roll-forward-diff-certificate:v1";
const DIFF_DOMAIN: &[u8] = b"fa:equity-roll-forward-diff-certificate-digest:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:equity-roll-forward-diff-source:v1";
const BEFORE: [i128; 15] = [
    1000, 0, 1000, 0, 1000, 200, 50, -75, 0, 0, 175, 975, 200, 1175, 0,
];
const AFTER: [i128; 15] = [
    1000, 0, 1000, -80, 920, 200, 50, -75, 0, 0, 95, 895, 200, 1095, 0,
];
const DELTAS: [i128; 15] = [0, 0, 0, -80, -80, 0, 0, 0, 0, 0, -80, -80, 0, -80, 0];
const ACCOUNTS: &[(&str, &str, u8)] = &[
    ("1000", "Cash", 1),
    ("3000", "Capital", 3),
    ("3100", "Distributions", 3),
    ("4000", "Sales", 4),
    ("5000", "Expense", 5),
    ("5001", "Unused expense", 5),
];

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    hash_parts(domain, &[&(bytes.len() as u32).to_le_bytes(), bytes])
}

fn request() -> EquityRollForwardDiffRequest {
    EquityRollForwardDiffRequest {
        before: 7,
        after: 8,
        label: "Equity bridge".into(),
        effective_from: 10,
        effective_through: 20,
        units: vec![0, 1],
        issuance_accounts: vec![account_id("3000")],
        distribution_accounts: vec![account_id("3100")],
    }
}

fn chart(accounts: &[(&str, &str, u8)]) -> Vec<u8> {
    let mut w = Writer::default();
    w.count(accounts.len());
    for (code, name, kind) in accounts {
        w.bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(*kind)
            .u8(u8::from([2, 3, 4].contains(kind)))
            .u8(1)
            .fixed(&1i64.to_le_bytes())
            .u8(0);
    }
    w.buf
}

fn prior_period(record: Record) -> Record {
    // This native record declares both immutable case membership (tag 23) and
    // the prior fiscal period (tag 36), using the published extension format.
    let mut bytes = record.bytes[..record.len].to_vec();
    bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
    let mut member = Writer::default();
    member.u16(1).u32(7).u128(99);
    let mut period = Writer::default();
    period.u16(1).bytes(b"cy").bytes(b"FY2025");
    let mut w = Writer::default();
    w.fixed(&bytes)
        .count(2)
        .u16(23)
        .bytes(&member.buf)
        .u16(36)
        .bytes(&period.buf);
    seal(w.buf, record.envelope.commit_seq)
}

fn records() -> Vec<Record> {
    let mut records = schema();
    records[0] = record(
        17,
        1,
        0,
        b"equity-chart",
        0,
        Some((1, &chart(ACCOUNTS))),
        None,
        None,
    );
    for (seq, day, class, inputs) in [
        (3, 5, 1, [leg("1000", true, 1000), leg("3000", false, 1000)]),
        (4, 12, 1, [leg("1000", true, 300), leg("4000", false, 300)]),
        (5, 14, 1, [leg("5000", true, 100), leg("1000", false, 100)]),
        (6, 15, 1, [leg("1000", true, 50), leg("3000", false, 50)]),
        (7, 16, 1, [leg("3100", true, 75), leg("1000", false, 75)]),
        (8, 10, 15, [leg("3000", true, 80), leg("1000", false, 80)]),
    ] {
        let input = dated(
            posting(class, seq, &seq.to_le_bytes(), &inputs, None, None),
            day,
        )
        .0;
        records.push(if class == 15 {
            prior_period(input)
        } else {
            input
        });
    }
    // Both original sources predate this metadata, but the recipient sees it
    // inside the covering signed checkpoint. It must not change either scope.
    records.push(record(
        17,
        9,
        0,
        b"future-equity-chart",
        0,
        Some((1, &chart(&[("5002", "Future expense", 5)]))),
        None,
        None,
    ));
    records
}

fn native_rows(known_at: u64) -> Vec<ReportRow> {
    let ppa = if known_at == 8 { 80 } else { 0 };
    [
        ("1000", 1350, 175 + ppa),
        ("3000", ppa, 1050),
        ("3100", 75, 0),
        ("4000", 0, 300),
        ("5000", 100, 0),
    ]
    .into_iter()
    .map(|(code, debits, credits)| {
        let (_, name, kind) = ACCOUNTS.iter().find(|a| a.0 == code).unwrap();
        ReportRow {
            account: account_id(code),
            code: code.into(),
            name: (*name).into(),
            account_type: *kind,
            unit: 1,
            debits,
            credits,
            debits_pending: 0,
            credits_pending: 0,
        }
    })
    .collect()
}

fn lead(records: &[Record], known_at: u64) -> VerifiedRollForward {
    let ordinary = classification(1, "", None);
    let ppa = classification(15, "", None);
    let accounts: Vec<_> = ACCOUNTS[1..]
        .iter()
        .map(|(code, name, kind)| RollForwardAccount {
            id: account_id(code),
            code: (*code).into(),
            name: (*name).into(),
            account_type: *kind,
            is_leaf: true,
        })
        .collect();
    let mut rows = Vec::new();
    for (index, account) in accounts.iter().enumerate() {
        let opening = [-1000, 0, 0, 0, 0][index];
        let activity = [-50, 75, -300, 100, 0][index];
        let adjustment = if index == 0 && known_at == 8 { 80 } else { 0 };
        for unit in [0, 1] {
            let values = if unit == 0 {
                [0, 0, 0]
            } else {
                [opening, activity, adjustment]
            };
            let change = values[1] + values[2];
            rows.push(RollForwardRow {
                account_id: account.id,
                unit_id: unit,
                opening: values[0],
                activity: if known_at == 8 {
                    vec![values[1], values[2]]
                } else {
                    vec![values[1]]
                },
                net_change: change,
                closing: values[0] + change,
            });
        }
    }
    let mut movements = vec![
        movement(&records[3], 1, "4000", false, 300, &ordinary),
        movement(&records[4], 0, "5000", true, 100, &ordinary),
        movement(&records[5], 1, "3000", false, 50, &ordinary),
        movement(&records[6], 0, "3100", true, 75, &ordinary),
    ];
    if known_at == 8 {
        movements.push(movement(&records[7], 0, "3000", true, 80, &ppa));
    }
    VerifiedRollForward {
        book_id: BOOK,
        known_at,
        label: "Equity bridge".into(),
        effective_from: 10,
        effective_through: 20,
        source_certificate_digest: [0; 32],
        accounts,
        units: vec![0, 1],
        buckets: if known_at == 8 {
            vec![ordinary, ppa]
        } else {
            vec![ordinary]
        },
        rows,
        movements,
    }
}

fn equity_output(records: &[Record], known_at: u64, accounts: &[RollForwardAccount]) -> Vec<u8> {
    let mut statement = Writer::default();
    statement
        .fixed(b"fa:equity-roll-forward:v2")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at)
        .bytes(b"Equity bridge")
        .i32(10)
        .i32(20)
        .count(2);
    for (unit, amounts) in [
        (0, [0; 15]),
        (1, if known_at == 8 { AFTER } else { BEFORE }),
    ] {
        statement.u32(unit);
        for value in amounts {
            statement.i128(value);
        }
    }
    let mut w = Writer::default();
    w.bytes(b"fa:equity-roll-forward-report:v2")
        .bytes(&statement.buf)
        .count(accounts.len());
    for a in accounts {
        w.u128(a.id)
            .bytes(a.code.as_bytes())
            .bytes(a.name.as_bytes())
            .u8(a.account_type)
            .u8(1);
    }
    w.count(if known_at == 8 { 3 } else { 2 });
    for (index, ordinal, kind, code, debits, credits) in [
        (5, 1, 1, "3000", 0, 50),
        (6, 0, 2, "3100", 75, 0),
        (7, 0, 5, "3000", 80, 0),
    ] {
        let record = &records[index];
        if record.envelope.commit_seq > known_at {
            continue;
        }
        w.fixed(&record.envelope.record_digest)
            .u32(ordinal)
            .u64(record.envelope.commit_seq)
            .i32(record.envelope.effective_day.unwrap())
            .u16(record.envelope.class)
            .u8(kind)
            .u128(account_id(code))
            .u32(1)
            .i128(debits)
            .i128(credits);
        if kind == 5 {
            w.u8(1).u32(7).u8(1).bytes(b"cy").bytes(b"FY2025");
        } else {
            w.u8(0).u8(0);
        }
    }
    w.buf
}

fn equity_certificate(
    source: &[u8],
    roles: (&[u128], &[u128]),
    output: &[u8],
    version: u16,
) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(if version == 2 {
        EQUITY_FORMAT
    } else {
        b"fa:equity-roll-forward-certificate:v1"
    })
    .bytes(source);
    for role in [roles.0, roles.1] {
        w.count(role.len());
        for id in role {
            w.u128(*id);
        }
    }
    w.bytes(output);
    let hash = digest(
        if version == 2 {
            EQUITY_DOMAIN
        } else {
            b"fa:equity-roll-forward-certificate-digest:v1"
        },
        &w.buf,
    );
    w.fixed(&hash);
    w.buf
}

fn extract(bundle: &[u8]) -> (&[u8], &[u8]) {
    let mut r = Reader::new(bundle);
    assert_eq!(r.bytes(64, "format").unwrap(), REPORT_BUNDLE_FORMAT);
    assert_eq!(r.u16("major").unwrap(), 2);
    assert_eq!(r.u16("minor").unwrap(), 0);
    let certificate = r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    (certificate, &bundle[bundle.len() - r.remaining()..])
}

struct Fixture {
    transport: Vec<u8>,
    anchor: SignedCheckpoint,
    before: Vec<u8>,
    after: Vec<u8>,
    before_output: Vec<u8>,
    after_output: Vec<u8>,
}

fn fixture() -> Fixture {
    let records = records();
    let mut sources = Vec::new();
    let mut outputs = Vec::new();
    let mut transport = Vec::new();
    let mut anchor = None;
    for at in [7, 8] {
        let (native, signed, native_digest) =
            source_bundle(&records, at, 20, &native_rows(at), &[]);
        let mut lead = lead(&records, at);
        lead.source_certificate_digest = native_digest;
        let (roll, _) = wrap(&native, &lead);
        let (roll_certificate, _) = extract(&roll);
        let output = equity_output(&records, at, &lead.accounts);
        sources.push(equity_certificate(
            roll_certificate,
            (
                &request().issuance_accounts,
                &request().distribution_accounts,
            ),
            &output,
            2,
        ));
        outputs.push(output);
        transport = native;
        anchor = Some(signed);
    }
    Fixture {
        transport,
        anchor: anchor.unwrap(),
        before: sources[0].clone(),
        after: sources[1].clone(),
        before_output: outputs[0].clone(),
        after_output: outputs[1].clone(),
    }
}

fn comparison_output(f: &Fixture) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:equity-roll-forward-diff:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(7)
        .u64(8)
        .fixed(&digest(SOURCE_DOMAIN, &f.before_output))
        .fixed(&digest(SOURCE_DOMAIN, &f.after_output))
        .bytes(b"Equity bridge")
        .i32(10)
        .i32(20)
        .count(2);
    for (unit, old, new, delta) in [(0, [0; 15], [0; 15], [0; 15]), (1, BEFORE, AFTER, DELTAS)] {
        w.u32(unit);
        for index in 0..15 {
            w.i128(old[index]).i128(new[index]).i128(delta[index]);
        }
    }
    w.buf
}

fn comparison_certificate(before: &[u8], after: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(DIFF_FORMAT)
        .bytes(before)
        .bytes(after)
        .u128(PRINCIPAL)
        .fixed(&[9; 32])
        .bytes(output);
    let pin = digest(DIFF_DOMAIN, &w.buf);
    w.fixed(&pin);
    (w.buf, pin)
}

fn bundle(f: &Fixture, before: &[u8], after: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let (_, tail) = extract(&f.transport);
    let (certificate, pin) = comparison_certificate(before, after, output);
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&certificate)
        .fixed(tail);
    (w.buf, pin)
}

fn verify(
    f: &Fixture,
    before: &[u8],
    after: &[u8],
    output: &[u8],
    expected: Option<&EquityRollForwardDiffRequest>,
) -> Result<VerifiedReport, ReportError> {
    let (bundle, pin) = bundle(f, before, after, output);
    verify_report_with_recipient_inputs(
        &bundle,
        &[],
        None,
        None,
        Some(&pin),
        None,
        None,
        expected,
        |_, _| Ok(f.anchor.clone()),
    )
}

#[test]
fn equity_diff_replays_original_ppa_case_citations_and_all_fifteen_exact_lines() {
    let f = fixture();
    let output = comparison_output(&f);
    let verified = verify(&f, &f.before, &f.after, &output, Some(&request())).unwrap();
    let diff: &VerifiedEquityRollForwardDiff = verified.equity_roll_forward_diff.as_ref().unwrap();
    assert_eq!(verified.output, output);
    assert!(verified.equity_roll_forward.is_none());
    assert_eq!(diff.before.known_at, 7);
    assert_eq!(diff.after.known_at, 8);
    assert_eq!(diff.before.accounts.len(), 5);
    assert_eq!(diff.after.accounts.len(), 5);
    assert_eq!(diff.before.movements.len(), 2);
    assert_eq!(diff.after.movements.len(), 3);
    let movement = &diff.after.movements[2];
    assert_eq!(
        movement.kind,
        crate::report::EquityActivityKind::PriorPeriodAdjustment
    );
    assert_eq!(
        (movement.debits, movement.credits, movement.case_ordinal),
        (80, 0, Some(7))
    );
    assert_eq!(movement.relates_to, Some(("cy".into(), "FY2025".into())));
    assert_eq!(diff.units.len(), 2);
    assert_eq!(diff.units[0].lines.len(), 15);
    assert!(
        diff.units[0]
            .lines
            .iter()
            .all(|line| (line.before, line.after, line.delta) == (0, 0, 0))
    );
    assert_eq!(
        diff.units[1]
            .lines
            .iter()
            .map(|line| line.before)
            .collect::<Vec<_>>(),
        BEFORE
    );
    assert_eq!(
        diff.units[1]
            .lines
            .iter()
            .map(|line| line.after)
            .collect::<Vec<_>>(),
        AFTER
    );
    assert_eq!(
        diff.units[1]
            .lines
            .iter()
            .map(|line| line.delta)
            .collect::<Vec<_>>(),
        DELTAS
    );
    assert_eq!(diff.before_digest, digest(SOURCE_DOMAIN, &f.before_output));
    assert_eq!(diff.after_digest, digest(SOURCE_DOMAIN, &f.after_output));
}

#[test]
fn equity_diff_needs_an_independent_exact_question_even_with_a_fresh_outer_pin() {
    let f = fixture();
    let output = comparison_output(&f);
    assert_eq!(
        verify(&f, &f.before, &f.after, &output, None)
            .unwrap_err()
            .predicate,
        "equity_diff_request"
    );
    for mutation in 0..8 {
        let mut expected = request();
        match mutation {
            0 => expected.before = 6,
            1 => expected.after = 9,
            2 => expected.label.push('!'),
            3 => expected.effective_from = 9,
            4 => expected.effective_through = 21,
            5 => expected.units = vec![1],
            6 => expected.issuance_accounts.clear(),
            7 => expected.distribution_accounts.clear(),
            _ => unreachable!(),
        }
        assert_eq!(
            verify(&f, &f.before, &f.after, &output, Some(&expected))
                .unwrap_err()
                .predicate,
            "equity_diff_request",
            "mutation {mutation}"
        );
    }
    assert_eq!(
        verify(&f, &f.after, &f.before, &output, Some(&request()))
            .unwrap_err()
            .predicate,
        "equity_diff_request"
    );
    assert_eq!(
        verify(&f, &f.before, &f.before, &output, Some(&request()))
            .unwrap_err()
            .predicate,
        "equity_diff_request"
    );
}

#[test]
fn equity_diff_resealed_false_sources_deltas_and_source_commitments_refuse() {
    let f = fixture();
    let output = comparison_output(&f);
    // Change each monetary triple independently, after all transport hashes are
    // resealed. Even a cancelling false before/after claim must be rejected.
    let row_start = output.len() - 2 * (4 + 15 * 48);
    for index in 0..15 {
        for column in 0..3 {
            let mut forged = output.clone();
            let at = row_start + (4 + 15 * 48) + 4 + index * 48 + column * 16;
            forged[at..at + 16].copy_from_slice(&777i128.to_le_bytes());
            assert_eq!(
                verify(&f, &f.before, &f.after, &forged, Some(&request()))
                    .unwrap_err()
                    .predicate,
                "equity_diff_recomputation"
            );
        }
    }
    let mut wrong_digest = output.clone();
    let first_digest = 4 + b"fa:equity-roll-forward-diff:v1".len() + 32 + 16;
    wrong_digest[first_digest] ^= 1;
    assert_eq!(
        verify(&f, &f.before, &f.after, &wrong_digest, Some(&request()))
            .unwrap_err()
            .predicate,
        "equity_diff_recomputation"
    );
    let decoded = crate::report::equity::decode(&f.after).unwrap();
    let mut forged_source_output = f.after_output.clone();
    // Last movement's recorded case ordinal is four bytes before its relates-to
    // option and two framed strings. Preserve amounts while falsifying lineage.
    let case_at = forged_source_output.len() - (1 + 4 + 2 + 4 + 6) - 4;
    assert_eq!(
        &forged_source_output[case_at..case_at + 4],
        &7u32.to_le_bytes()
    );
    forged_source_output[case_at..case_at + 4].copy_from_slice(&8u32.to_le_bytes());
    let forged = equity_certificate(
        decoded.source,
        (&decoded.issuance_accounts, &decoded.distribution_accounts),
        &forged_source_output,
        2,
    );
    assert_eq!(
        verify(&f, &f.before, &forged, &output, Some(&request()))
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
    let legacy = equity_certificate(
        decoded.source,
        (&decoded.issuance_accounts, &decoded.distribution_accounts),
        decoded.output,
        1,
    );
    assert_eq!(
        verify(&f, &f.before, &legacy, &output, Some(&request()))
            .unwrap_err()
            .predicate,
        "equity_diff_source"
    );
    let roles = equity_certificate(
        decoded.source,
        (&[], &decoded.distribution_accounts),
        decoded.output,
        2,
    );
    assert_eq!(
        verify(&f, &f.before, &roles, &output, Some(&request()))
            .unwrap_err()
            .predicate,
        "equity_diff_request"
    );
}

#[test]
fn equity_diff_canonical_expectation_is_bounded_sorted_and_not_an_artifact() {
    let expected = request();
    let bytes = expected.canonical_bytes().unwrap();
    assert_eq!(
        EquityRollForwardDiffRequest::decode(&bytes).unwrap(),
        expected
    );
    for mutation in 0..8 {
        let mut invalid = expected.clone();
        match mutation {
            0 => invalid.before = invalid.after + 1,
            1 => invalid.units.clear(),
            2 => invalid.units = vec![1, 0],
            3 => invalid.units = vec![0, 0],
            4 => invalid.issuance_accounts = vec![9, 8],
            5 => invalid.distribution_accounts = invalid.issuance_accounts.clone(),
            6 => invalid.label = " ".into(),
            7 => invalid.effective_from = invalid.effective_through + 1,
            _ => unreachable!(),
        }
        assert!(invalid.canonical_bytes().is_err(), "mutation {mutation}");
    }
    for cut in [0, 4, bytes.len() - 1] {
        assert!(EquityRollForwardDiffRequest::decode(&bytes[..cut]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(EquityRollForwardDiffRequest::decode(&trailing).is_err());
    let f = fixture();
    assert!(EquityRollForwardDiffRequest::decode(&f.after).is_err());
}

#[test]
fn equity_diff_requires_complete_payloads_and_original_source_family() {
    let f = fixture();
    let output = comparison_output(&f);
    let (mut bytes, pin) = bundle(&f, &f.before, &f.after, &output);
    let mut r = Reader::new(&bytes);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    r.bytes(1024, "checkpoint").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "prefix").unwrap();
    let count_at = bytes.len() - r.remaining();
    assert_eq!(r.u32("records").unwrap(), 9);
    bytes[count_at..count_at + 4].copy_from_slice(&8u32.to_le_bytes());
    let error = verify_report_with_recipient_inputs(
        &bytes,
        &[],
        None,
        None,
        Some(&pin),
        None,
        None,
        Some(&request()),
        |_, _| Ok(f.anchor.clone()),
    )
    .unwrap_err();
    assert_eq!(error.predicate, "record_completeness");

    // Native or lead-schedule certificates cannot masquerade as an original
    // equity source, even after the outer comparison is freshly committed.
    let (native, _) = extract(&f.transport);
    assert!(verify(&f, native, &f.after, &output, Some(&request())).is_err());
    let decoded = crate::report::equity::decode(&f.before).unwrap();
    assert!(verify(&f, decoded.source, &f.after, &output, Some(&request())).is_err());

    // A request is also refused on an otherwise ordinary source report.
    let (_, tail) = extract(&f.transport);
    let mut standalone = Writer::default();
    standalone
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&f.after)
        .fixed(tail);
    let after_digest = crate::report::equity::decode(&f.after).unwrap().digest;
    assert_eq!(
        verify_report_with_recipient_inputs(
            &standalone.buf,
            &[],
            None,
            None,
            Some(&after_digest),
            None,
            None,
            Some(&request()),
            |_, _| Ok(f.anchor.clone()),
        )
        .unwrap_err()
        .predicate,
        "equity_diff_request"
    );
    // Conversely, adding the new family must not change standalone v2 replay.
    assert_eq!(
        verify_report_with(
            &standalone.buf,
            &[],
            None,
            None,
            Some(&after_digest),
            |_, _| Ok(f.anchor.clone()),
        )
        .unwrap()
        .equity_roll_forward
        .unwrap()
        .units[1]
            .prior_period_adjustments,
        -80
    );
}

#[test]
fn equity_diff_delta_overflow_is_an_exact_refusal_not_a_wrapping_comparison() {
    let f = fixture();
    let output = comparison_output(&f);
    let report = verify(&f, &f.before, &f.after, &output, Some(&request())).unwrap();
    let mut original = report.equity_roll_forward_diff.unwrap();
    // Exercise the pure delta boundary with two individually representable
    // amounts. Expected refusal follows i128 arithmetic, not an encoded golden.
    original.before.units[1].opening_contributed_equity = -1;
    original.after.units[1].opening_contributed_equity = i128::MAX;
    let (raw, _) = comparison_certificate(&f.before, &f.after, &output);
    let certificate = crate::report::equity_diff::decode(&raw).unwrap();
    assert_eq!(
        crate::report::equity_diff::derive(&certificate, original.before, original.after,)
            .unwrap_err()
            .predicate,
        "exact_arithmetic"
    );
}

#[test]
fn equity_diff_equal_frontiers_require_byte_identical_original_certificates() {
    let f = fixture();
    let mut expected = request();
    expected.after = expected.before;
    let source_digest = digest(SOURCE_DOMAIN, &f.before_output);
    let mut w = Writer::default();
    w.bytes(b"fa:equity-roll-forward-diff:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(7)
        .u64(7)
        .fixed(&source_digest)
        .fixed(&source_digest)
        .bytes(b"Equity bridge")
        .i32(10)
        .i32(20)
        .count(2);
    for (unit, amounts) in [(0, [0; 15]), (1, BEFORE)] {
        w.u32(unit);
        for value in amounts {
            w.i128(value).i128(value).i128(0);
        }
    }
    let report = verify(&f, &f.before, &f.before, &w.buf, Some(&expected)).unwrap();
    assert!(
        report
            .equity_roll_forward_diff
            .unwrap()
            .units
            .iter()
            .flat_map(|unit| &unit.lines)
            .all(|line| line.delta == 0)
    );

    // Retain the same source question and monetary output, but change one
    // opaque read-attestation byte in its native certificate and reseal every
    // containing certificate. Equal frontiers still require the original bytes.
    let equity = crate::report::equity::decode(&f.before).unwrap();
    let roll = crate::report::roll_forward::decode(equity.source).unwrap();
    let mut native = roll.source.to_vec();
    let marker = b"opaque native read";
    let at = native
        .windows(marker.len())
        .position(|part| part == marker)
        .unwrap();
    native[at] = b'O';
    let end = native.len() - 32;
    let hash = hash_parts(CERTIFICATE_FORMAT, &[&native[..end]]);
    native[end..].copy_from_slice(&hash);
    let (altered_roll, _) = outer(
        &native,
        &roll.accounts,
        &roll.units,
        roll.label,
        roll.effective_from,
        roll.effective_through,
        roll.output,
    );
    let altered = equity_certificate(
        &altered_roll,
        (&equity.issuance_accounts, &equity.distribution_accounts),
        equity.output,
        2,
    );
    assert_eq!(
        verify(&f, &f.before, &altered, &w.buf, Some(&expected))
            .unwrap_err()
            .predicate,
        "equity_diff_source"
    );
}
