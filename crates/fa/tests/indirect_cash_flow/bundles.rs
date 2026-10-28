//! Complete indirect workpapers independently recomputed from signed history.

use super::*;
use fa::{CashFlowBasisKind, CertifiedIndirectCashFlow, IndirectCashFlowCertificate};
use fa_model::{Reader, Writer};

fn fixture(kind: CashFlowBasisKind, k: i128) -> (Harness, IndirectCashFlowRequest) {
    if kind == CashFlowBasisKind::Split {
        return super::bases::loan_fixture(k);
    }
    let mut h = Harness::new();
    h.scenario(k);
    let request = if kind == CashFlowBasisKind::Policy {
        super::bases::policy_request(&h)
    } else {
        h.request()
    };
    (h, request)
}

fn certify(h: &Harness, request: &IndirectCashFlowRequest) -> CertifiedIndirectCashFlow {
    h.book
        .certify_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap()
}

fn source_digest(certificate: &IndirectCashFlowCertificate) -> &[u8; 32] {
    match certificate.source_certificate() {
        fa::CashFlowBasisCertificate::Explicit(source) => source.digest(),
        fa::CashFlowBasisCertificate::Policy(source) => source.digest(),
        fa::CashFlowBasisCertificate::Split(source) => source.digest(),
    }
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
    certificate: &IndirectCashFlowCertificate,
    expected: &IndirectCashFlowRequest,
) -> fa::Outcome<Option<fa::ProducedBundle>> {
    let cx = h.cx();
    h.runtime.block_on(h.book.produce_indirect_cash_flow_bundle(
        &cx,
        PRINCIPAL,
        &cap(&["read", "produce"]),
        state,
        certificate,
        expected,
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

fn repair_output(
    certificate: &IndirectCashFlowCertificate,
    output: &[u8],
) -> IndirectCashFlowCertificate {
    let explicit = certificate.source_certificate().kind() == CashFlowBasisKind::Explicit;
    let format = if explicit {
        fa::indirect_cash_flow::INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT
    } else {
        fa::indirect_cash_flow::INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT_V2
    };
    let mut writer = Writer::new();
    writer.bytes(format);
    if !explicit {
        writer.u8(certificate.source_certificate().kind() as u8);
    }
    writer.bytes(&certificate.source_certificate().canonical_bytes().unwrap());
    writer.list(certificate.income_periods(), |writer, period| {
        writer.str(period);
    });
    let definition = certificate.definition();
    writer
        .str(&definition.name)
        .list(&definition.adjustments, |writer, adjustment| {
            writer
                .fixed(&adjustment.entry_digest)
                .u32(adjustment.leg_index)
                .u8(adjustment.category as u8)
                .u8(adjustment.sign as u8)
                .str(&adjustment.reason);
        })
        .bytes(output);
    let mut bytes = writer.finish().unwrap();
    let domain: &[u8] = if explicit {
        b"fa:indirect-cash-flow-certificate-digest:v1"
    } else {
        b"fa:indirect-cash-flow-certificate-digest:v2"
    };
    let digest = fa_model::domain_digest(domain, &[&bytes]);
    bytes.extend_from_slice(&digest);
    IndirectCashFlowCertificate::decode(&bytes).unwrap()
}

#[test]
fn indirect_bundles_recompute_income_original_adjustments_and_all_three_cash_bases() {
    use Side::{Credit as C, Debit as D};
    for kind in [
        CashFlowBasisKind::Explicit,
        CashFlowBasisKind::Policy,
        CashFlowBasisKind::Split,
    ] {
        let k = if kind == CashFlowBasisKind::Split {
            (1i128 << 80) + 17
        } else {
            1
        };
        let (mut h, request) = fixture(kind, k);
        let certified = certify(&h, &request);
        let certificate = certified.certificate();
        let later_day = DateDay(request.cash.effective_from.0 + 7);
        h.post_on(
            later_day,
            b"later-cash",
            h.usd,
            &[("1000", D, 9), ("4000", C, 9)],
        );
        h.post_on(
            later_day,
            b"later-depreciation",
            h.usd,
            &[("6100", D, 3), ("1590", C, 3)],
        );
        let state = checkpoint(&mut h);
        let before = h.head();
        let produced = produce(&mut h, Some(state), certificate, &request)
            .unwrap()
            .unwrap()
            .unwrap();
        let repeated = produce(&mut h, Some(state), certificate, &request)
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
        assert_eq!(produced.receipt, repeated.receipt);
        assert_eq!(h.head(), before);
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
        assert_eq!(verified.known_at, request.cash.known_at.unwrap().0);
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        let report = verified.indirect_cash_flow.unwrap();
        assert_eq!(
            report.source_certificate_digest,
            *source_digest(certificate)
        );
        assert_eq!(report.definition.name, request.definition.name);
        assert_eq!(
            report.contributions.len(),
            request.definition.adjustments.len()
        );
        let detail = report.non_cash_source.as_ref().unwrap();
        assert!(
            detail
                .accounts
                .iter()
                .all(|account| account.id != h.id("1000").0)
        );
        assert!(!detail.lines.is_empty());
        let usd = report
            .units
            .iter()
            .find(|unit| unit.unit_id == h.usd.0)
            .unwrap();
        let expected = if kind == CashFlowBasisKind::Split {
            [
                170 * k,
                20 * k,
                0,
                0,
                190 * k,
                190 * k,
                0,
                1000 * k,
                0,
                -100 * k,
                0,
                90 * k,
                1090 * k,
            ]
        } else {
            [70, 10, -30, -20, 30, 30, 0, 0, 10, 100, 0, 140, 140]
        };
        assert_eq!(
            [
                usd.net_income,
                usd.non_cash,
                usd.working_capital,
                usd.non_operating,
                usd.operating,
                usd.direct_operating,
                usd.operating_residual,
                usd.opening,
                usd.investing,
                usd.financing,
                usd.exchange_effects,
                usd.net_change,
                usd.closing,
            ],
            expected
        );
        let zero = report
            .units
            .iter()
            .find(|unit| unit.unit_id == h.jpy.0)
            .unwrap();
        assert_eq!((zero.net_income, zero.operating, zero.closing), (0, 0, 0));
        assert!(matches!(
            (kind, report.cash),
            (
                CashFlowBasisKind::Explicit,
                fa_verify::report::VerifiedCashFlowBasis::Explicit(_)
            ) | (
                CashFlowBasisKind::Policy,
                fa_verify::report::VerifiedCashFlowBasis::Policy(_)
            ) | (
                CashFlowBasisKind::Split,
                fa_verify::report::VerifiedCashFlowBasis::Split(_)
            )
        ));
        assert!(
            fa_verify::report::verify_report_expected(
                &produced.bundle.bytes,
                &[key],
                None,
                Some(&produced.receipt),
                Some(source_digest(certificate)),
            )
            .is_err(),
            "a cash source digest does not pin the indirect workpaper"
        );
    }
}

#[test]
fn forged_indirect_income_and_final_amounts_fail_after_repairing_the_outer_digest() {
    for kind in [CashFlowBasisKind::Explicit, CashFlowBasisKind::Split] {
        let (mut h, request) = fixture(kind, 1);
        let certified = certify(&h, &request);
        let certificate = certified.certificate();
        let mut final_amount = certificate.output().to_vec();
        *final_amount.last_mut().unwrap() ^= 1;
        let changed_total = repair_output(certificate, &final_amount);
        let mut reader = Reader::new(certificate.output());
        let format = reader.str(64, "format").unwrap();
        let mut writer = Writer::new();
        writer.str(format);
        if kind != CashFlowBasisKind::Explicit {
            writer.u8(reader.u8("basis").unwrap());
        }
        writer.bytes(reader.bytes(64 * 1024 * 1024, "cash").unwrap());
        let mut income = reader.bytes(64 * 1024 * 1024, "income").unwrap().to_vec();
        *income.last_mut().unwrap() ^= 1;
        writer
            .bytes(&income)
            .fixed(&certificate.output()[certificate.output().len() - reader.remaining()..]);
        let changed_income = repair_output(certificate, &writer.finish().unwrap());
        let state = checkpoint(&mut h);
        let produced = produce(&mut h, Some(state), certificate, &request)
            .unwrap()
            .unwrap()
            .unwrap();
        let before = h.head();
        for bad in [&changed_total, &changed_income] {
            assert!(
                produce(&mut h, Some(state), bad, &request)
                    .unwrap()
                    .is_err()
            );
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
}

#[test]
fn indirect_export_requires_current_authority_and_the_complete_independent_question() {
    let (mut h, request) = fixture(CashFlowBasisKind::Explicit, 1);
    let certified = certify(&h, &request);
    let certificate = certified.certificate();
    assert!(
        produce(&mut h, None, certificate, &request)
            .unwrap()
            .unwrap()
            .is_none()
    );
    let state = checkpoint(&mut h);
    let before = h.head();
    let cx = h.cx();
    for denied in [
        cap(&["read"]),
        cap(&["produce"]),
        cap(&["read", "produce"]).for_accounts(&["1000"]).unwrap(),
        cap(&["read", "produce"]).known_at_most(before),
    ] {
        let refusal = h
            .runtime
            .block_on(h.book.produce_indirect_cash_flow_bundle(
                &cx,
                PRINCIPAL,
                &denied,
                Some(state),
                certificate,
                &request,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
    }
    let mut missing_special = request.clone();
    missing_special
        .income_periods
        .retain(|period| period != "FY2026-OPEN");
    let mut unfixed = request.clone();
    unfixed.cash.known_at = None;
    let mut reason = request.clone();
    reason.definition.adjustments[0].reason.push_str(" revised");
    let mut sign = request.clone();
    sign.definition.adjustments[0].sign = match sign.definition.adjustments[0].sign {
        AdjustmentSign::DebitMinusCredit => AdjustmentSign::CreditMinusDebit,
        AdjustmentSign::CreditMinusDebit => AdjustmentSign::DebitMinusCredit,
    };
    for changed in [missing_special, unfixed, reason, sign] {
        assert!(
            produce(&mut h, Some(state), certificate, &changed)
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(h.head(), before);
}
