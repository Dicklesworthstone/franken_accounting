//! Complete portable custom statements: expected accounting and presentation
//! bytes are hand-derived, independently of the custom replay implementation.

use super::*;
use crate::report::{VerifiedReport, custom_statement as custom};

#[path = "custom_statement/diff.rs"]
mod diff;

const KNOWN_AT: u64 = 6;

fn layout(version: u32) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:custom-statement-def:v1")
        .bytes(b"company-income")
        .bytes(b"Company income")
        .u32(version)
        .u8(1)
        .count(3);
    w.bytes(b"revenue")
        .bytes(b"Revenue")
        .u8(0)
        .u8(2)
        .count(1)
        .bytes(b"4000")
        .u8(1);
    w.bytes(b"expense")
        .bytes(b"Expenses")
        .u8(0)
        .u8(3)
        .count(1)
        .bytes(b"5")
        .u8(0);
    w.bytes(b"net")
        .bytes(b"Net income")
        .u8(1)
        .count(1)
        .bytes(b"revenue")
        .count(1)
        .bytes(b"expense")
        .count(0);
    w.buf
}

fn definition_digest(bytes: &[u8]) -> [u8; 32] {
    framed_hash(b"fa:custom-statement-def:v1", &[bytes])
}

fn activation(records: &[Record], seq: u64, key: &[u8], version: u32) -> Record {
    let digest = definition_digest(&layout(version));
    let object = framed_hash(b"fa:vid:statement-definition:v1", &[&BOOK, &digest]);
    let mut controls: Vec<_> = records
        .iter()
        .filter(|record| record.envelope.class == 17)
        .map(|record| {
            (
                record.envelope.commit_seq,
                handle(record).0,
                record.envelope.record_digest,
            )
        })
        .collect();
    controls.sort_by_key(|(seq, identity, _)| (*seq, *identity));
    let mut chart = Writer::default();
    chart.fixed(&BOOK).count(controls.len());
    for (seq, identity, digest) in controls {
        chart.u64(seq).u128(identity).fixed(&digest);
    }
    let chart_digest = framed_hash(b"fa:statement-chart-basis:v1", &[&chart.buf]);
    let mut w = prefix(18, 31);
    // Entry minor 1 retains acceptance-level Approval references separately
    // from the proposal. The prototype does not invent Approval-row proofs.
    w.buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    w.count(0)
        .u8(1)
        .u8(3)
        .u128(u128::from_le_bytes(object[..16].try_into().unwrap()))
        .u8(0)
        .u8(1)
        .count(1)
        .u8(1)
        .fixed(&chart_digest)
        .u16(0x5354)
        .count(0)
        .u8(0)
        .bytes(key)
        .u8(3)
        .u16(3)
        .fixed(&digest)
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0)
        .count(0);
    let len = w.buf.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let mut acceptance = Writer::default();
    acceptance
        .u8(0)
        .count(2)
        .u128(1001)
        .fixed(&proposal_digest)
        .u128(1002)
        .fixed(&proposal_digest);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &acceptance.buf]);
    w.fixed(&acceptance.buf)
        .fixed(&proposal_digest)
        .fixed(&digest);
    let envelope = envelope_of_entry(&w.buf, len, seq, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}

fn fixture() -> (Vec<Record>, RateFixture, u128) {
    let mut records = schema();
    let mut chart = Writer::default();
    chart.count(4);
    for (code, label, typ) in [
        ("1000", "Cash", 1),
        ("4000", "Revenue", 4),
        ("5000", "Expenses", 5),
        ("5001", "Unused expense", 5),
    ] {
        chart
            .bytes(code.as_bytes())
            .bytes(label.as_bytes())
            .u8(typ)
            .u8(u8::from(typ == 4))
            .u8(1)
            .fixed(&(-1i64).to_le_bytes())
            .u8(0);
    }
    records[0] = schema_record(1, 1, &chart.buf);
    let activated = activation(&records, 3, b"layout-v1", 1);
    let activated_id = handle(&activated).0;
    records.push(activated);
    let rate = rate_fixture(3, 2, 3, 58);
    records.push(intake(&rate, 4));
    let sale = pair(9, 14)
        .into_iter()
        .enumerate()
        .map(|(i, mut leg)| {
            leg.code = if i == 0 { "1000" } else { "4000" };
            leg
        })
        .collect::<Vec<_>>();
    let expense = pair(5, 8)
        .into_iter()
        .enumerate()
        .map(|(i, mut leg)| {
            leg.code = if i == 0 { "5000" } else { "1000" };
            leg
        })
        .collect::<Vec<_>>();
    records.push(entry(
        5,
        1,
        40,
        b"sale",
        &sale,
        Some((3, &rate, None)),
        None,
        None,
    ));
    records.push(entry(
        6,
        1,
        41,
        b"expense",
        &expense,
        Some((3, &rate, None)),
        None,
        None,
    ));
    // The recipient checkpoint extends beyond the certificate. Neither a new
    // named version nor a backdated transaction can alter the retained answer.
    records.push(activation(&records, 7, b"layout-v2", 2));
    records.push(entry(
        8,
        1,
        40,
        b"later-sale",
        &sale,
        Some((3, &rate, None)),
        None,
        None,
    ));
    (records, rate, activated_id)
}

fn columns(w: &mut Writer) {
    w.count(2);
    for (label, period, from, through) in [("current", "P2", 31, 58), ("comparative", "P1", 0, 30)]
    {
        w.bytes(label.as_bytes())
            .count(1)
            .bytes(period.as_bytes())
            .u8(1)
            .i32(from)
            .i32(through);
    }
}

fn expected(functional: bool, activation: u128, defect: u8) -> Vec<u8> {
    let definition = layout(1);
    let digest = definition_digest(&definition);
    let units: Vec<_> = if functional {
        vec![0]
    } else {
        (0..13).collect()
    };
    let active_unit = u32::from(!functional);
    let amounts = if functional { [14, 8, 6] } else { [9, 5, 4] };
    let shown = if functional { [1, 1, 1] } else { [1, 0, 0] };
    let rows = [
        ("revenue", "Revenue"),
        ("expense", "Expenses"),
        ("net", "Net income"),
    ];
    let mut exact = Writer::default();
    exact
        .fixed(b"FA-STATEMENT\0")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(KNOWN_AT)
        .bytes(b"company-income")
        .u32(1)
        .fixed(&digest)
        .bytes(&definition);
    columns(&mut exact);
    exact.count(3 * units.len());
    for (index, (code, label)) in rows.iter().enumerate() {
        for &unit in &units {
            let amount = if unit == active_unit {
                amounts[index]
            } else {
                0
            };
            exact
                .bytes(code.as_bytes())
                .bytes(label.as_bytes())
                .u32(unit)
                .count(2)
                .i128(amount + i128::from(defect == 1 && index == 0 && unit == active_unit))
                .i128(0);
        }
    }
    exact.count(if defect == 2 { 2 } else { 3 });
    for (code, label, typ, line) in [
        ("4000", "Revenue", 4, "revenue"),
        ("5000", "Expenses", 5, "expense"),
        ("5001", "Unused expense", 5, "expense"),
    ] {
        if defect == 2 && code == "5001" {
            continue;
        }
        exact
            .u128(id(code))
            .bytes(code.as_bytes())
            .bytes(label.as_bytes())
            .u8(typ)
            .u8(1)
            .bytes(line.as_bytes());
    }
    let mut presented = Writer::default();
    presented
        .fixed(b"fa:presented-statement:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(KNOWN_AT)
        .bytes(b"company-income")
        .u32(1)
        .fixed(&digest)
        .u16(3)
        .u8(1)
        .i128(10);
    columns(&mut presented);
    presented.count(3 * units.len() + 1);
    for &unit in &units {
        for (index, (code, label)) in rows.iter().enumerate() {
            if index == 2 && unit == active_unit {
                let residual = if functional { 1 } else { -1 };
                presented
                    .bytes(b"net_rounding")
                    .bytes(b"Rounding (Net income)")
                    .u32(unit)
                    .count(2)
                    .i128(0)
                    .i128(0)
                    .count(2)
                    .i128(residual + i128::from(defect == 3))
                    .i128(0)
                    .count(2)
                    .i128(residual * 10)
                    .i128(0)
                    .u8(1);
            }
            let (exact, display) = if unit == active_unit {
                (amounts[index], shown[index])
            } else {
                (0, 0)
            };
            presented
                .bytes(code.as_bytes())
                .bytes(label.as_bytes())
                .u32(unit)
                .count(2)
                .i128(exact)
                .i128(0)
                .count(2)
                .i128(display)
                .i128(0)
                .count(2)
                .i128(display * 10 - exact)
                .i128(0)
                .u8(0);
        }
    }
    let mut output = Writer::default();
    output.fixed(if functional {
        custom::FUNCTIONAL_OUTPUT_FORMAT
    } else {
        custom::NATIVE_OUTPUT_FORMAT
    });
    if functional {
        output.bytes(b"retained-base-amounts").u32(0);
    }
    output
        .u128(activation)
        .bytes(&exact.buf)
        .u8(1)
        .bytes(&presented.buf);
    output.buf
}

#[allow(clippy::too_many_arguments)]
fn pack(
    records: &[Record],
    functional: bool,
    activation: u128,
    output: &[u8],
    docs: &[(String, Vec<u8>)],
    rates: &[RateFixture],
    omit_payload: bool,
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let historical: Vec<_> = records
        .iter()
        .filter(|record| {
            record.envelope.kind == KIND_ENTRY && record.envelope.commit_seq <= KNOWN_AT
        })
        .map(|record| leaf_hash(&record.envelope.encode()))
        .collect();
    let mut spec = Writer::default();
    spec.fixed(b"fa:presentation-rounding-spec:v1")
        .u16(3)
        .u8(1)
        .bytes(b"rounding")
        .bytes(b"Rounding");
    let format = if functional {
        custom::FUNCTIONAL_FORMAT
    } else {
        custom::NATIVE_FORMAT
    };
    let mut cert = Writer::default();
    cert.fixed(format)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(if functional {
            custom::FUNCTIONAL_OUTPUT_FORMAT
        } else {
            custom::NATIVE_OUTPUT_FORMAT
        })
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(KNOWN_AT)
        .u8(if functional { 10 } else { 9 })
        .bytes(&layout(1))
        .u128(activation)
        .u64(3)
        .count(1)
        .bytes(b"P2")
        .count(1)
        .bytes(b"P1")
        .u8(1)
        .bytes(&spec.buf)
        .fixed(&closure(docs))
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64);
    let inputs = if functional { 13 } else { 12 };
    cert.count(inputs);
    for _ in 0..inputs {
        cert.bytes(b"opaque retained native input attestation");
    }
    cert.bytes(output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[output]))
        .u8(0);
    let pin = hash_parts(format, &[&cert.buf]);
    cert.fixed(&pin);
    let all: Vec<_> = records
        .iter()
        .map(|record| record.envelope.encode())
        .collect();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: 8,
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
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(if functional { 3 } else { 2 })
        .u16(0)
        .bytes(&cert.buf)
        .bytes(b"externally authenticated fixture checkpoint")
        .bytes(&proof.buf)
        .count(records.len() - usize::from(omit_payload));
    for (index, record) in records.iter().enumerate() {
        if omit_payload && index == 0 {
            continue;
        }
        bundle.u32(record.len as u32).bytes(&record.bytes);
    }
    bundle.count(0).count(docs.len());
    for (name, bytes) in docs {
        bundle.bytes(name.as_bytes()).bytes(bytes);
    }
    if functional {
        bundle.bytes(&book(&[])).count(rates.len());
        let mut rates: Vec<_> = rates.iter().collect();
        rates.sort_by_key(|rate| rate.oid);
        for rate in rates {
            bundle.fixed(&rate.oid).bytes(&rate.document);
        }
    }
    let signed = SignedCheckpoint {
        checkpoint,
        state_oid: [0; 32],
        scope_index_root: [0; 32],
        substrate_chain_commitment: [0; 32],
        witness_policy_oid: None,
        time_evidence_oid: None,
        body_digest: [0; 32],
        oid: [0; 32],
        signed_by: vec![],
        not_judged: vec![],
    };
    (bundle.buf, signed, pin)
}

fn documents(functional: bool) -> Vec<(String, Vec<u8>)> {
    registries()
        .into_iter()
        .filter(|(name, _)| functional || name != "fx_laws")
        .collect()
}

fn verify(
    bundle: &[u8],
    signed: &SignedCheckpoint,
    pin: Option<&[u8; 32]>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with_inputs(
        bundle,
        &[],
        Some(&signed.checkpoint),
        None,
        pin,
        None,
        |_, _| Ok(signed.clone()),
    )
}

#[test]
fn complete_native_and_functional_custom_bundles_recompute_pinned_history_and_rounding() {
    let (records, rate, activation) = fixture();
    for functional in [false, true] {
        let output = expected(functional, activation, 0);
        let (bundle, signed, pin) = pack(
            &records,
            functional,
            activation,
            &output,
            &documents(functional),
            std::slice::from_ref(&rate),
            false,
        );
        let report = verify(&bundle, &signed, Some(&pin)).unwrap();
        assert_eq!(report.output, output);
        assert_eq!(report.scope, "recomputation");
        assert_eq!(report.known_at, KNOWN_AT);
        assert_eq!(report.checkpoint.checkpoint.through_seq, 8);
        let custom = report.custom_statement.unwrap();
        assert_eq!(custom.statement.mappings.len(), 3);
        assert_eq!(custom.statement.columns.len(), 2);
        assert_eq!(custom.functional_unit, functional.then_some(0));
        assert_eq!(custom.activation.activation, activation);
        assert_eq!(custom.activation.approval_refs.len(), 2);
        assert!(!custom.activation.approval_admission_verified);
        assert!(!custom.activation.definition_birth_verified);
        let residual = custom
            .presented
            .unwrap()
            .lines
            .into_iter()
            .find(|line| line.is_residual_line)
            .unwrap();
        assert_eq!(
            residual.presented_amounts,
            [if functional { 1 } else { -1 }, 0]
        );
        assert_eq!(
            verify(&bundle, &signed, None).unwrap_err().predicate,
            "report_input_authority"
        );
        assert_eq!(
            verify(&bundle, &signed, Some(&[99; 32]))
                .unwrap_err()
                .predicate,
            "recipient_certificate"
        );
    }
}

#[test]
fn custom_bundles_refuse_resealed_false_amounts_omitted_zero_mappings_and_residuals() {
    let (records, rate, activation) = fixture();
    for functional in [false, true] {
        for defect in 1..=3 {
            let (bundle, signed, pin) = pack(
                &records,
                functional,
                activation,
                &expected(functional, activation, defect),
                &documents(functional),
                std::slice::from_ref(&rate),
                false,
            );
            assert_eq!(
                verify(&bundle, &signed, Some(&pin)).unwrap_err().predicate,
                "custom_statement_recomputation"
            );
        }
        let (bundle, signed, pin) = pack(
            &records,
            functional,
            activation,
            &expected(functional, activation, 0),
            &documents(functional),
            std::slice::from_ref(&rate),
            true,
        );
        assert_eq!(
            verify(&bundle, &signed, Some(&pin)).unwrap_err().predicate,
            "record_completeness"
        );
    }
}

#[test]
fn custom_rounding_registry_semantics_remain_bound_after_resealing_all_outer_digests() {
    let (records, rate, activation) = fixture();
    for functional in [false, true] {
        let mut docs = documents(functional);
        let rounding = &mut docs.last_mut().unwrap().1;
        let text = b"Round half toward positive infinity.";
        let at = rounding
            .windows(text.len())
            .position(|bytes| bytes == text)
            .unwrap();
        rounding[at] = b'X';
        let (bundle, signed, pin) = pack(
            &records,
            functional,
            activation,
            &expected(functional, activation, 0),
            &docs,
            std::slice::from_ref(&rate),
            false,
        );
        assert_eq!(
            verify(&bundle, &signed, Some(&pin)).unwrap_err().predicate,
            "registry_closure"
        );
    }
}

#[test]
fn functional_custom_statements_require_original_rates_and_cannot_substitute_a_new_quote() {
    let (records, rate, activation) = fixture();
    for rates in [
        vec![],
        vec![rate_fixture(17, 10, 3, 58)],
        vec![rate.clone(), rate_fixture(17, 10, 3, 58)],
    ] {
        let (bundle, signed, pin) = pack(
            &records,
            true,
            activation,
            &expected(true, activation, 0),
            &documents(true),
            &rates,
            false,
        );
        assert!(verify(&bundle, &signed, Some(&pin)).is_err());
    }
    let (bundle, signed, pin) = pack(
        &records,
        true,
        activation ^ 1,
        &expected(true, activation, 0),
        &documents(true),
        &[rate],
        false,
    );
    assert_eq!(
        verify(&bundle, &signed, Some(&pin)).unwrap_err().predicate,
        "custom_statement_activation"
    );
}
