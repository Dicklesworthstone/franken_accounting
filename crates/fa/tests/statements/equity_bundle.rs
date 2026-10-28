//! Equity is recomputed by the standalone verifier from the signed native
//! history, including zero leaves, explicit owner roles and historical scope.

use super::*;
use fa::{EquityRollForwardCertificate, EquityRollForwardRequest, RollForwardCertificate};

fn capability() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap()
}

fn checkpoint(book: &mut Book) -> Oid {
    let witness = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    book.checkpoint(PRINCIPAL, &witness)
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid
}

fn certify(fixture: &mut Fixture) -> fa::CertifiedEquityRollForward {
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    for (code, name) in [("3100", "Common stock"), ("3200", "Dividends")] {
        fixture
            .book
            .open_account(
                &account(code, name, AccountType::EQUITY),
                day(2025, 12, 1),
                None,
                PRINCIPAL,
                day(2025, 12, 1),
                code.as_bytes(),
                &schema,
            )
            .unwrap()
            .unwrap();
    }
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 1, 10),
        b"equity-opening",
        usd,
        ("1000", "3000"),
        1_000,
    );
    fixture.transfer(
        day(2026, 2, 2),
        b"equity-issuance",
        usd,
        ("1000", "3100"),
        50,
    );
    fixture.transfer(
        day(2026, 2, 3),
        b"equity-distribution",
        usd,
        ("3200", "1000"),
        75,
    );
    fixture.transfer(day(2026, 2, 4), b"equity-sale", usd, ("1000", "4000"), 300);
    fixture.transfer(
        day(2026, 2, 5),
        b"equity-expense",
        usd,
        ("6000", "1000"),
        100,
    );
    let id = fixture.book.context().book_id;
    let request = EquityRollForwardRequest {
        units: vec![fixture.jpy.0, usd.0],
        label: "Historical changes in equity".into(),
        effective_from: day(2026, 2, 1),
        effective_through: day(2026, 2, 28),
        known_at: Some(fixture.book.head().unwrap()),
        issuance_accounts: vec![account_vid(id, "3100")],
        distribution_accounts: vec![account_vid(id, "3200")],
    };
    fixture
        .book
        .certify_equity_roll_forward(PRINCIPAL, &capability(), &request)
        .unwrap()
        .unwrap()
}

fn replace_outer(bundle: &[u8], outer: &[u8]) -> Vec<u8> {
    let at = 4 + fa_notary::report::REPORT_BUNDLE_FORMAT.len() + 4;
    let old_len = u32::from_le_bytes(bundle[at..at + 4].try_into().unwrap()) as usize;
    let mut bytes = bundle[..at].to_vec();
    bytes.extend_from_slice(&u32::try_from(outer.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(outer);
    bytes.extend_from_slice(&bundle[at + 4 + old_len..]);
    bytes
}

fn reseal(
    certificate: &EquityRollForwardCertificate,
    source: &RollForwardCertificate,
    output: &[u8],
) -> EquityRollForwardCertificate {
    let request = certificate.request();
    let mut writer = fa_model::Writer::new();
    writer
        .bytes(fa::EQUITY_CERTIFICATE_FORMAT)
        .bytes(&source.canonical_bytes().unwrap())
        .list(&request.issuance_accounts, |writer, account| {
            writer.u128(account.0);
        })
        .list(&request.distribution_accounts, |writer, account| {
            writer.u128(account.0);
        })
        .bytes(output);
    let mut bytes = writer.finish().unwrap();
    let digest =
        fa_model::domain_digest(b"fa:equity-roll-forward-certificate-digest:v2", &[&bytes]);
    bytes.extend_from_slice(&digest);
    EquityRollForwardCertificate::decode(&bytes).unwrap()
}

#[test]
fn native_equity_bundle_recomputes_owner_changes_income_zeros_and_the_original_prefix() {
    let mut fixture = Fixture::new(0x98);
    let certified = certify(&mut fixture);
    let certificate = &certified.certificate;
    let known_at = certificate.known_at();
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 2, 4),
        b"equity-later-backdate",
        usd,
        ("1000", "4000"),
        999,
    );
    // A later chart expansion must not change the historical complete selection.
    fixture
        .book
        .open_account(
            &account("6200", "Later expense", AccountType::EXPENSE),
            day(2026, 2, 1),
            None,
            PRINCIPAL,
            day(2026, 3, 1),
            b"equity-later-leaf",
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    let state = checkpoint(&mut fixture.book);
    let before = fixture.book.head().unwrap();
    let produced = fixture
        .book
        .produce_equity_roll_forward_bundle(PRINCIPAL, &capability(), Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let again = fixture
        .book
        .produce_equity_roll_forward_bundle(PRINCIPAL, &capability(), Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, again.bundle.bytes);
    assert_eq!(produced.receipt, again.receipt);
    assert_eq!(fixture.book.head().unwrap(), before);
    let key = fixture.book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .expect("independently recompute the retained equity statement");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.known_at, known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.rows.is_empty());
    assert!(verified.statement.is_none());
    assert!(verified.roll_forward.is_none());
    assert!(verified.cash_flow.is_none());
    let equity = verified.equity_roll_forward.unwrap();
    assert_eq!(equity.accounts.len(), 6);
    assert!(equity.accounts.iter().any(|account| account.code == "6100"));
    assert!(!equity.accounts.iter().any(|account| account.code == "6200"));
    assert_eq!(equity.units.len(), 2);
    let usd = equity
        .units
        .iter()
        .find(|unit| unit.unit_id == usd.0)
        .unwrap();
    assert_eq!(usd.opening_total_equity, 1_000);
    assert_eq!(usd.net_income, 200);
    assert_eq!(usd.issuances, 50);
    assert_eq!(usd.distributions, -75);
    assert_eq!(usd.closing_transfers_net, 0);
    assert_eq!(usd.net_equity_change, 175);
    assert_eq!(usd.closing_total_equity, 1_175);
    assert_eq!(usd.equity_tie_out_residual, 0);
    let unused = equity
        .units
        .iter()
        .find(|unit| unit.unit_id == fixture.jpy.0)
        .unwrap();
    assert_eq!(unused.opening_total_equity, 0);
    assert_eq!(unused.net_equity_change, 0);
    assert_eq!(unused.closing_total_equity, 0);
    assert_eq!(equity.movements.len(), 2);

    assert!(
        fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            Some(certificate.source_certificate().digest()),
        )
        .is_err(),
        "the nested lead schedule cannot pin the owner classifications"
    );
    assert!(fa_verify::report::verify_report_expected(
        &produced.bundle.bytes, &[key], None, None, None,
    ).is_err(), "an unauthenticated outer classification cannot verify");
    assert!(
        fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            Some(certificate.digest()),
        )
        .is_ok(),
        "an independently retained outer pin is sufficient"
    );
}

#[test]
fn native_equity_export_and_offline_replay_reject_resealed_lies_and_omitted_zero_leaves() {
    let mut fixture = Fixture::new(0x99);
    let certified = certify(&mut fixture);
    let certificate = &certified.certificate;
    let state = checkpoint(&mut fixture.book);
    let produced = fixture
        .book
        .produce_equity_roll_forward_bundle(PRINCIPAL, &capability(), Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let key = fixture.book.checkpoint_public_key();

    // Re-seal a changed movement citation: public hashes alone still agree.
    let mut report = certified.report.clone();
    report.movements[0].entry_digest[0] ^= 1;
    let changed = reseal(
        certificate,
        certificate.source_certificate(),
        &report.canonical_bytes().unwrap(),
    );
    assert!(
        fixture
            .book
            .produce_equity_roll_forward_bundle(PRINCIPAL, &capability(), Some(state), &changed,)
            .unwrap()
            .is_err()
    );
    let tampered = replace_outer(&produced.bundle.bytes, &changed.canonical_bytes().unwrap());
    let failure = fa_verify::report::verify_report_expected(
        &tampered,
        &[key],
        None,
        None,
        Some(changed.digest()),
    )
    .unwrap_err();
    assert_eq!(failure.predicate, "report_recomputation");

    // This is a valid, independently replayable lead schedule. Its omission of
    // an unused income leaf still makes it an incomplete equity statement.
    let mut partial = certificate.source_certificate().request().clone();
    let unused = account_vid(fixture.book.context().book_id, "6100");
    partial.accounts.retain(|account| *account != unused);
    let partial = fixture
        .book
        .certify_roll_forward(PRINCIPAL, &capability(), &partial)
        .unwrap()
        .unwrap();
    let omitted = reseal(certificate, &partial.certificate, certificate.output());
    assert!(
        fixture
            .book
            .produce_equity_roll_forward_bundle(PRINCIPAL, &capability(), Some(state), &omitted,)
            .unwrap()
            .is_err()
    );
    let tampered = replace_outer(&produced.bundle.bytes, &omitted.canonical_bytes().unwrap());
    let failure = fa_verify::report::verify_report_expected(
        &tampered,
        &[key],
        None,
        None,
        Some(omitted.digest()),
    )
    .unwrap_err();
    assert_eq!(failure.predicate, "equity_completeness");
}
