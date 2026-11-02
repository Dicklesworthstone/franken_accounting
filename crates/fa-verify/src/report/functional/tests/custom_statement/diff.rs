//! Independent same-layout comparisons. Both exact statements, both rounded
//! presentations and every delta are written from the arithmetic below; no
//! comparison or report evaluator manufactures the expected bytes.

use super::*;

const BEFORE: u64 = 5;
const AFTER: u64 = 7;

struct Fixture {
    records: Vec<Record>,
    rates: Vec<RateFixture>,
    activation: u128,
}

struct Output {
    bytes: Vec<u8>,
    inner: Vec<u8>,
}

fn fixture() -> Fixture {
    let (mut records, old_rate, activation_id) = super::fixture();
    records.truncate(5);
    let new_rate = rate_fixture(2, 1, 3, 58);
    records.push(intake(&new_rate, 6));
    let expense = pair(1, 2)
        .into_iter()
        .enumerate()
        .map(|(index, mut leg)| {
            leg.code = if index == 0 { "5000" } else { "1000" };
            leg
        })
        .collect::<Vec<_>>();
    records.push(entry(
        7,
        1,
        41,
        b"comparison-small-expense",
        &expense,
        Some((3, &new_rate, None)),
        None,
        None,
    ));
    records.push(activation(&records, 8, b"comparison-new-layout", 2));
    let later_sale = pair(9, 18)
        .into_iter()
        .enumerate()
        .map(|(index, mut leg)| {
            leg.code = if index == 0 { "1000" } else { "4000" };
            leg
        })
        .collect::<Vec<_>>();
    records.push(entry(
        9,
        1,
        40,
        b"comparison-later-backdate",
        &later_sale,
        Some((3, &new_rate, None)),
        None,
        None,
    ));
    Fixture {
        records,
        rates: vec![old_rate, new_rate],
        activation: activation_id,
    }
}

fn amounts(functional: bool, at: u64) -> [i128; 3] {
    match (functional, at == BEFORE) {
        (false, true) => [9, 0, 9],
        (false, false) => [9, 1, 8],
        (true, true) => [14, 0, 14],
        (true, false) => [14, 2, 12],
    }
}

fn units(functional: bool) -> Vec<u32> {
    if functional {
        vec![0]
    } else {
        (0..13).collect()
    }
}

fn output(functional: bool, at: u64, activation: u128, defect: u8) -> Output {
    let definition = layout(1);
    let digest = definition_digest(&definition);
    let selected_units = units(functional);
    let active = u32::from(!functional);
    let exact_values = amounts(functional, at);
    // Both sources have the SAME presented amounts despite a real expense:
    // 9 -> 8 native, or 14 -> 12 base, each rounds to 1 at scale ten.
    let shown = [1_i128, 0, 1];
    let rows = [
        ("revenue", "Revenue"),
        ("expense", "Expenses"),
        ("net", "Net income"),
    ];
    let mut inner = Writer::default();
    inner
        .fixed(b"FA-STATEMENT\0")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(at)
        .bytes(b"company-income")
        .u32(1)
        .fixed(&digest)
        .bytes(&definition);
    columns(&mut inner);
    inner.count(rows.len() * selected_units.len());
    for (index, (code, label)) in rows.iter().enumerate() {
        for &unit in &selected_units {
            let value = if unit == active {
                exact_values[index]
            } else {
                0
            };
            inner
                .bytes(code.as_bytes())
                .bytes(label.as_bytes())
                .u32(unit)
                .count(2)
                .i128(value + i128::from(defect == 1 && index == 0 && unit == active))
                .i128(0);
        }
    }
    inner.count(if defect == 3 { 2 } else { 3 });
    for (code, label, typ, line) in [
        ("4000", "Revenue", 4, "revenue"),
        ("5000", "Expenses", 5, "expense"),
        ("5001", "Unused expense", 5, "expense"),
    ] {
        if defect == 3 && code == "5001" {
            continue;
        }
        inner
            .u128(id(code))
            .bytes(code.as_bytes())
            .bytes(label.as_bytes())
            .u8(typ)
            .u8(1)
            .bytes(line.as_bytes());
    }
    let mut presentation = Writer::default();
    presentation
        .fixed(b"fa:presented-statement:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(at)
        .bytes(b"company-income")
        .u32(1)
        .fixed(&digest)
        .u16(3)
        .u8(1)
        .i128(10);
    columns(&mut presentation);
    presentation.count(rows.len() * selected_units.len());
    for &unit in &selected_units {
        for (index, (code, label)) in rows.iter().enumerate() {
            let (exact, display) = if unit == active {
                (exact_values[index], shown[index])
            } else {
                (0, 0)
            };
            presentation
                .bytes(code.as_bytes())
                .bytes(label.as_bytes())
                .u32(unit)
                .count(2)
                .i128(exact)
                .i128(0)
                .count(2)
                .i128(display + i128::from(defect == 2 && index == 0 && unit == active))
                .i128(0)
                .count(2)
                .i128(display * 10 - exact)
                .i128(0)
                .u8(0);
        }
    }
    let mut result = Writer::default();
    result.fixed(if functional {
        custom::FUNCTIONAL_OUTPUT_FORMAT
    } else {
        custom::NATIVE_OUTPUT_FORMAT
    });
    if functional {
        result.bytes(b"retained-base-amounts").u32(0);
    }
    result
        .u128(activation)
        .bytes(&inner.buf)
        .u8(1)
        .bytes(&presentation.buf);
    Output {
        bytes: result.buf,
        inner: inner.buf,
    }
}

fn source(fixture: &Fixture, functional: bool, at: u64, output: &Output, defect: u8) -> Vec<u8> {
    let docs = documents(functional);
    let historical = fixture
        .records
        .iter()
        .filter(|record| record.envelope.kind == KIND_ENTRY && record.envelope.commit_seq <= at)
        .map(|record| leaf_hash(&record.envelope.encode()))
        .collect::<Vec<_>>();
    let mut spec = Writer::default();
    spec.fixed(b"fa:presentation-rounding-spec:v1")
        .u16(3)
        .u8(if defect == 3 { 2 } else { 1 })
        .bytes(b"rounding")
        .bytes(b"Rounding");
    let format = if functional {
        custom::FUNCTIONAL_FORMAT
    } else {
        custom::NATIVE_FORMAT
    };
    let mut w = Writer::default();
    w.fixed(format)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(if functional {
            custom::FUNCTIONAL_OUTPUT_FORMAT
        } else {
            custom::NATIVE_OUTPUT_FORMAT
        })
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(at)
        .u8(if functional { 10 } else { 9 })
        .bytes(&layout(if defect == 5 { 2 } else { 1 }))
        .u128(fixture.activation + u128::from(defect == 1))
        .u64(if defect == 2 { 2 } else { 3 })
        .count(1)
        .bytes(if defect == 4 { b"P1" } else { b"P2" })
        .count(1)
        .bytes(b"P1")
        .u8(1)
        .bytes(&spec.buf)
        .fixed(&if defect == 6 {
            [0xee; 32]
        } else {
            closure(&docs)
        })
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64)
        .count(if functional { 13 } else { 12 });
    for _ in 0..if functional { 13 } else { 12 } {
        w.bytes(b"opaque retained native input attestation");
    }
    w.bytes(&output.bytes)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output.bytes]))
        .u8(0);
    let pin = hash_parts(format, &[&w.buf]);
    w.fixed(&pin);
    w.buf
}

fn bridge(functional: bool, before: &Output, after: &Output, false_delta: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(if functional {
        b"fa:functional-custom-statement-diff:v1"
    } else {
        b"fa:custom-statement-diff:v1"
    });
    if functional {
        w.u32(0).bytes(b"retained-base-amounts");
    }
    let source_domain: &[u8] = if functional {
        b"fa:functional-custom-statement-diff-source:v1"
    } else {
        b"fa:custom-statement-diff-source:v1"
    };
    w.fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(BEFORE)
        .u64(AFTER)
        .fixed(&framed_hash(source_domain, &[&before.inner]))
        .fixed(&framed_hash(source_domain, &[&after.inner]))
        .fixed(&definition_digest(&layout(1)));
    columns(&mut w);
    let selected_units = units(functional);
    w.count(3 * selected_units.len());
    for (index, (code, label)) in [
        ("revenue", "Revenue"),
        ("expense", "Expenses"),
        ("net", "Net income"),
    ]
    .iter()
    .enumerate()
    {
        for &unit in &selected_units {
            let old = if unit == u32::from(!functional) {
                amounts(functional, BEFORE)[index]
            } else {
                0
            };
            let new = if unit == u32::from(!functional) {
                amounts(functional, AFTER)[index]
            } else {
                0
            };
            let delta = if false_delta && index == 1 {
                0
            } else {
                new - old
            };
            w.bytes(code.as_bytes())
                .bytes(label.as_bytes())
                .u32(unit)
                .count(2)
                .i128(old)
                .i128(0)
                .count(2)
                .i128(new)
                .i128(0)
                .count(2)
                .i128(delta)
                .i128(0);
        }
    }
    w.count(0);
    w.buf
}

fn outer(
    functional: bool,
    before: &[u8],
    after: &[u8],
    output: &[u8],
    builtin_domain: bool,
) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    let (format, digest_domain): (&[u8], &[u8]) = match (functional, builtin_domain) {
        (false, false) => (
            b"fa:custom-statement-diff-certificate:v1",
            b"fa:custom-statement-diff-certificate-digest:v1",
        ),
        (true, false) => (
            b"fa:functional-custom-statement-diff-certificate:v1",
            b"fa:functional-custom-statement-diff-certificate-digest:v1",
        ),
        (false, true) => (
            b"fa:statement-diff-certificate:v1",
            b"fa:statement-diff-certificate-digest:v1",
        ),
        (true, true) => (
            b"fa:functional-statement-diff-certificate:v1",
            b"fa:functional-statement-diff-certificate-digest:v1",
        ),
    };
    w.bytes(format)
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .bytes(before)
        .bytes(after)
        .bytes(output);
    let pin = framed_hash(digest_domain, &[&w.buf]);
    w.fixed(&pin);
    (w.buf, pin)
}

fn bundle(
    fixture: &Fixture,
    functional: bool,
    certificate: &[u8],
    rates: &[RateFixture],
    omit_payload: bool,
) -> (Vec<u8>, SignedCheckpoint) {
    let all = fixture
        .records
        .iter()
        .map(|record| record.envelope.encode())
        .collect::<Vec<_>>();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: 9,
        leaf_count: all.len() as u64,
        root: root_of(&all.iter().map(|bytes| leaf_hash(bytes)).collect::<Vec<_>>()),
    };
    let mut proof = Writer::default();
    proof
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .count(all.len());
    for envelope in &all {
        proof.bytes(envelope);
    }
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(if functional { 3 } else { 2 })
        .u16(0)
        .bytes(certificate)
        .bytes(b"externally authenticated fixture checkpoint")
        .bytes(&proof.buf)
        .count(fixture.records.len() - usize::from(omit_payload));
    for (index, record) in fixture.records.iter().enumerate() {
        if omit_payload && index == 0 {
            continue;
        }
        w.u32(record.len as u32).bytes(&record.bytes);
    }
    let docs = documents(functional);
    w.count(0).count(docs.len());
    for (name, bytes) in docs {
        w.bytes(name.as_bytes()).bytes(&bytes);
    }
    if functional {
        w.bytes(&book(&[])).count(rates.len());
        let mut sorted = rates.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|rate| rate.oid);
        for rate in sorted {
            w.fixed(&rate.oid).bytes(&rate.document);
        }
    }
    (
        w.buf,
        SignedCheckpoint {
            checkpoint,
            state_oid: [0; 32],
            scope_index_root: [0; 32],
            substrate_chain_commitment: [0; 32],
            witness_policy_oid: None,
            time_evidence_oid: None,
            body_digest: [0; 32],
            oid: [0; 32],
            signed_by: Vec::new(),
            not_judged: Vec::new(),
        },
    )
}

#[test]
fn custom_comparisons_recompute_exact_changes_hidden_by_identical_presentations() {
    let fixture = fixture();
    for functional in [false, true] {
        let before = output(functional, BEFORE, fixture.activation, 0);
        let after = output(functional, AFTER, fixture.activation, 0);
        let a = source(&fixture, functional, BEFORE, &before, 0);
        let b = source(&fixture, functional, AFTER, &after, 0);
        let expected = bridge(functional, &before, &after, false);
        let (certificate, pin) = outer(functional, &a, &b, &expected, false);
        let (bytes, signed) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
        let verified = verify(&bytes, &signed, Some(&pin)).unwrap();
        assert_eq!(verified.output, expected);
        assert_eq!(verified.known_at, AFTER);
        assert_eq!(verified.certificate_digest, pin);
        let comparison = verified.statement_diff.unwrap();
        assert_eq!(comparison.before_known_at, BEFORE);
        assert_eq!(comparison.after_known_at, AFTER);
        assert_eq!(comparison.lines.len(), 3 * units(functional).len());
        let custom = comparison.custom.unwrap();
        assert_eq!(custom.activation.activation, fixture.activation);
        assert_eq!(custom.activation.activated_at, 3);
        assert!(!custom.activation.approval_admission_verified);
        let old = custom.before_presented.unwrap();
        let new = custom.after_presented.unwrap();
        assert_eq!(old.lines.len(), new.lines.len());
        for (a, b) in old.lines.iter().zip(&new.lines) {
            assert_eq!(a.presented_amounts, b.presented_amounts);
        }
        let expense = comparison
            .lines
            .iter()
            .find(|line| line.code == "expense" && line.unit == u32::from(!functional))
            .unwrap();
        assert_eq!(expense.before, [0, 0]);
        assert_eq!(expense.after, [if functional { 2 } else { 1 }, 0]);
        assert_eq!(expense.delta, expense.after);
        let net = comparison
            .lines
            .iter()
            .find(|line| line.code == "net" && line.unit == u32::from(!functional))
            .unwrap();
        assert_eq!(net.delta, [if functional { -2 } else { -1 }, 0]);
        for source in [&a, &b] {
            let source_pin: [u8; 32] = source[source.len() - 32..].try_into().unwrap();
            assert!(verify(&bytes, &signed, Some(&source_pin)).is_err());
        }
    }
}

#[test]
fn resealed_custom_comparisons_reject_false_sources_rounding_and_exact_deltas() {
    let fixture = fixture();
    for functional in [false, true] {
        let before = output(functional, BEFORE, fixture.activation, 0);
        let after = output(functional, AFTER, fixture.activation, 0);
        let a = source(&fixture, functional, BEFORE, &before, 0);
        let b = source(&fixture, functional, AFTER, &after, 0);
        for defect in 1..=3 {
            for corrupt_before in [false, true] {
                let changed = output(
                    functional,
                    if corrupt_before { BEFORE } else { AFTER },
                    fixture.activation,
                    defect,
                );
                let (old, new) = if corrupt_before {
                    (&changed, &after)
                } else {
                    (&before, &changed)
                };
                let a = source(&fixture, functional, BEFORE, old, 0);
                let b = source(&fixture, functional, AFTER, new, 0);
                let claim = bridge(functional, old, new, false);
                let (certificate, pin) = outer(functional, &a, &b, &claim, false);
                let (bytes, signed) =
                    bundle(&fixture, functional, &certificate, &fixture.rates, false);
                assert!(
                    verify(&bytes, &signed, Some(&pin)).is_err(),
                    "defect {defect}, before={corrupt_before}, functional={functional}"
                );
            }
        }
        let (certificate, pin) = outer(
            functional,
            &a,
            &b,
            &bridge(functional, &before, &after, true),
            false,
        );
        let (bytes, signed) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
        assert!(
            verify(&bytes, &signed, Some(&pin)).is_err(),
            "an exact expense cannot be replaced by its zero presented delta"
        );
    }
}

#[test]
fn custom_comparison_identity_activation_presentation_epoch_and_family_cannot_drift() {
    let fixture = fixture();
    for functional in [false, true] {
        let before = output(functional, BEFORE, fixture.activation, 0);
        let after = output(functional, AFTER, fixture.activation, 0);
        let a = source(&fixture, functional, BEFORE, &before, 0);
        let b = source(&fixture, functional, AFTER, &after, 0);
        let claim = bridge(functional, &before, &after, false);
        for defect in 1..=6 {
            let changed = source(&fixture, functional, AFTER, &after, defect);
            let (certificate, pin) = outer(functional, &a, &changed, &claim, false);
            let (bytes, signed) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
            assert!(
                verify(&bytes, &signed, Some(&pin)).is_err(),
                "changed source selection or registry defect {defect}"
            );
        }
        for (a, b, builtin_domain) in [(&a, &b, true), (&b, &a, false), (&a, &a, false)] {
            let (certificate, pin) = outer(functional, a, b, &claim, builtin_domain);
            let (bytes, signed) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
            assert!(verify(&bytes, &signed, Some(&pin)).is_err());
        }
        let other = output(!functional, AFTER, fixture.activation, 0);
        let other_source = source(&fixture, !functional, AFTER, &other, 0);
        let (certificate, pin) = outer(functional, &a, &other_source, &claim, false);
        let (bytes, signed) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
        assert!(verify(&bytes, &signed, Some(&pin)).is_err());
    }
}

#[test]
fn functional_custom_comparison_requires_each_historical_rate_and_complete_prefix() {
    let fixture = fixture();
    let before = output(true, BEFORE, fixture.activation, 0);
    let after = output(true, AFTER, fixture.activation, 0);
    let a = source(&fixture, true, BEFORE, &before, 0);
    let b = source(&fixture, true, AFTER, &after, 0);
    let (certificate, pin) = outer(true, &a, &b, &bridge(true, &before, &after, false), false);
    for rates in [&fixture.rates[..1], &fixture.rates[1..], &[]] {
        let (bytes, signed) = bundle(&fixture, true, &certificate, rates, false);
        assert!(verify(&bytes, &signed, Some(&pin)).is_err());
    }
    let unrelated = [rate_fixture(99, 1, 3, 58)];
    let (bytes, signed) = bundle(&fixture, true, &certificate, &unrelated, false);
    assert!(verify(&bytes, &signed, Some(&pin)).is_err());
    let (bytes, signed) = bundle(&fixture, true, &certificate, &fixture.rates, true);
    assert!(verify(&bytes, &signed, Some(&pin)).is_err());
}
