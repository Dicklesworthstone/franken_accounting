//! Posted original legs and signed complete prefixes, replayed without the book.

use super::*;
use fa::cash_flow_split::{CashFlowSplitCertificate, CertifiedSplitCashFlow};
use fa_model::{Reader, Writer};

fn certify(
    h: &Harness,
    request: &RollForwardRequest,
    definition: &CashFlowSplitDefinition,
) -> CertifiedSplitCashFlow {
    h.book
        .certify_split_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            request,
            definition,
        )
        .unwrap()
        .unwrap()
}

fn checkpoint(h: &mut Harness) -> Oid {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.checkpoint(&cx, PRINCIPAL, &cap(&["witness"])))
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid
}

fn produce(
    h: &mut Harness,
    state: Option<Oid>,
    certificate: &CashFlowSplitCertificate,
    request: &RollForwardRequest,
    definition: &CashFlowSplitDefinition,
) -> fa::Outcome<Option<fa::ProducedBundle>> {
    let cx = h.cx();
    h.runtime.block_on(h.book.produce_split_cash_flow_bundle(
        &cx,
        PRINCIPAL,
        &cap(&["read", "produce"]),
        state,
        certificate,
        request,
        definition,
    ))
}

fn replace_outer(bundle: &[u8], outer: &[u8]) -> Vec<u8> {
    let mut reader = Reader::new(bundle);
    let domain = reader.bytes(64, "domain").unwrap();
    let major = reader.u16("major").unwrap();
    let minor = reader.u16("minor").unwrap();
    reader.bytes(64 * 1024 * 1024, "old certificate").unwrap();
    let tail = &bundle[bundle.len() - reader.remaining()..];
    let mut writer = Writer::new();
    writer
        .bytes(domain)
        .u16(major)
        .u16(minor)
        .bytes(outer)
        .fixed(tail);
    writer.finish().unwrap()
}

fn repaired(
    certificate: &CashFlowSplitCertificate,
    definition: &CashFlowSplitDefinition,
    output: &[u8],
) -> CashFlowSplitCertificate {
    let mut writer = Writer::new();
    writer
        .str(fa::cash_flow_split::CASH_FLOW_SPLIT_CERTIFICATE_FORMAT)
        .bytes(&certificate.source_certificate().canonical_bytes().unwrap())
        .bytes(&definition.canonical_bytes().unwrap())
        .bytes(output);
    let mut bytes = writer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:cash-flow-split-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    CashFlowSplitCertificate::decode(&bytes).unwrap()
}

#[test]
fn signed_split_bundle_preserves_original_legs_portions_transfers_and_historical_zeros() {
    use CashFlowActivity::{Financing as F, InternalTransfer as T, Operating as O};
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    let k = (1i128 << 55) + 1;
    h.loan(k);
    h.post(
        11,
        b"mixed-cash-and-internal-transfer",
        h.usd,
        &[
            ("1000", D, 150 * k),
            ("1010", C, 50 * k),
            ("4000", C, 100 * k),
        ],
    );
    let request = h.request();
    let mut definition = h.definition();
    let ledger = h.ledger();
    for split in &mut definition.splits {
        let line = ledger
            .lines()
            .iter()
            .find(|line| {
                line.entry_digest == split.entry_digest && line.leg_index == split.leg_index
            })
            .unwrap();
        split.portions = if line.credits == 100 * k {
            portions(&[(O, 7 * k), (F, 93 * k)])
        } else if line.debits == 150 * k {
            portions(&[(O, 100 * k), (T, 50 * k)])
        } else {
            assert_eq!(line.credits, 50 * k);
            portions(&[(T, 50 * k)])
        };
    }
    let certified = certify(&h, &request, &definition);
    let certificate = certified.certificate();
    h.post(
        12,
        b"later-backdated-cash",
        h.usd,
        &[("1000", D, 9), ("4000", C, 9)],
    );
    let state = checkpoint(&mut h);
    let before = h.head();
    let produced = produce(&mut h, Some(state), certificate, &request, &definition)
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = produce(&mut h, Some(state), certificate, &request, &definition)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(produced.receipt, repeated.receipt);
    assert_eq!(h.head(), before, "export never appends a book record");
    let key = h.book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .unwrap();
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.known_at, request.known_at.unwrap().0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.receipt.is_some());
    assert!(verified.cash_flow.is_none());
    let split = verified.split_cash_flow.unwrap();
    assert_eq!(
        split.source_certificate_digest,
        *certificate.source_certificate().digest()
    );
    assert_eq!(split.ledger.lines.len(), 3);
    assert_eq!(split.ledger.cells.len(), 4);
    assert_eq!(split.definition.splits.len(), 3);
    assert_eq!(
        split
            .definition
            .splits
            .iter()
            .map(|s| s.portions.len())
            .sum::<usize>(),
        5
    );
    let usd = split
        .units
        .iter()
        .find(|row| row.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (
            usd.opening,
            usd.operating.inflows,
            usd.operating.outflows,
            usd.financing.outflows,
            usd.net_change,
            usd.closing
        ),
        (500 * k, 100 * k, 7 * k, 93 * k, 0, 500 * k)
    );
    let jpy = split
        .units
        .iter()
        .find(|row| row.unit_id == h.jpy.0)
        .unwrap();
    assert_eq!((jpy.opening, jpy.net_change, jpy.closing), (0, 0, 0));
    assert!(
        fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            Some(certificate.source_certificate().digest()),
        )
        .is_err(),
        "the inner lead schedule does not pin split decisions"
    );
}

#[test]
fn split_bundle_rejects_repaired_output_and_portions_even_with_a_matching_forged_pin() {
    let mut h = Harness::new();
    h.loan(1);
    let request = h.request();
    let definition = h.loan_definition(1);
    let certified = certify(&h, &request, &definition);
    let certificate = certified.certificate();
    let mut output = certificate.output().to_vec();
    *output.last_mut().unwrap() ^= 1;
    let changed_output = repaired(certificate, certificate.definition(), &output);
    // Both copies and the outer unkeyed digest are repaired. The declared
    // portions still overallocate an authenticated original cash leg.
    let mut changed = certificate.definition().clone();
    changed.splits[0].portions[0].amount += 1;
    let mut reader = Reader::new(certificate.output());
    let format = reader.str(64, "split output format").unwrap();
    let ledger = reader.bytes(64 * 1024 * 1024, "split ledger").unwrap();
    reader
        .bytes(32 * 1024 * 1024, "original definition")
        .unwrap();
    let tail = &certificate.output()[certificate.output().len() - reader.remaining()..];
    let mut writer = Writer::new();
    writer
        .str(format)
        .bytes(ledger)
        .bytes(&changed.canonical_bytes().unwrap())
        .fixed(tail);
    let changed_portions = repaired(certificate, &changed, &writer.finish().unwrap());
    let state = checkpoint(&mut h);
    let produced = produce(&mut h, Some(state), certificate, &request, &definition)
        .unwrap()
        .unwrap()
        .unwrap();
    let before = h.head();
    for bad in [&changed_output, &changed_portions] {
        let refusal = produce(&mut h, Some(state), bad, &request, &definition)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
        assert!(
            fa_verify::report::verify_report_expected(
                &replace_outer(&produced.bundle.bytes, &bad.canonical_bytes().unwrap()),
                &[h.book.checkpoint_public_key()],
                None,
                None,
                Some(bad.digest()),
            )
            .is_err()
        );
    }
    assert_eq!(h.head(), before);
}

#[test]
fn split_export_requires_current_authority_and_independent_exact_request() {
    let mut h = Harness::new();
    h.loan(1);
    let request = h.request();
    let definition = h.loan_definition(1);
    let certified = certify(&h, &request, &definition);
    let certificate = certified.certificate();
    assert!(
        produce(&mut h, None, certificate, &request, &definition)
            .unwrap()
            .unwrap()
            .is_none()
    );
    let state = checkpoint(&mut h);
    let before = h.head();
    let cx = h.cx();
    for capability in [
        cap(&["read"]),
        cap(&["produce"]),
        cap(&["read", "produce"]).for_accounts(&["1000"]).unwrap(),
        cap(&["read", "produce"])
            .for_periods(&["FY2026-P01"])
            .unwrap(),
        cap(&["read", "produce"]).known_at_most(before),
        cap(&["read", "produce"]).effective_through(day(20)),
    ] {
        let refusal = h
            .runtime
            .block_on(h.book.produce_split_cash_flow_bundle(
                &cx,
                PRINCIPAL,
                &capability,
                Some(state),
                certificate,
                &request,
                &definition,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY, "{refusal:?}");
    }
    let mut expected = request.clone();
    expected.known_at = None;
    assert!(
        produce(&mut h, Some(state), certificate, &expected, &definition)
            .unwrap()
            .is_err()
    );
    let mut changed = definition.clone();
    changed.splits[0].reason.push_str(" revised");
    assert!(
        produce(&mut h, Some(state), certificate, &request, &changed)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), before);
}
