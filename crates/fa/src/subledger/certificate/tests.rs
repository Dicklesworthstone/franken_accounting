use super::*;
use crate::{
    Book, BookKeys, CertificateStatus, Entropy, ReportArtifact, ReportArtifactExpectation,
};
use fa_journal::{AccountSpec, BookSpec, UnitPolicy};
use fa_model::{AccountType, account_vid};
use fa_money::UnitRegistry;
use fa_time::FiscalCalendar;

const PRINCIPAL: VId = VId(151);

fn fixture() -> (Book, NativeSubledgerRequest, Capability) {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let mut book = Book::create_memory(
        BookKeys::for_development(151),
        BookSpec {
            book_id: Id128([151; 16]),
            name: "Certified native subledger".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("native-cert", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(151),
    )
    .unwrap();
    let date = DateDay::from_ymd(2026, 3, 31).unwrap();
    let cap = Capability::embedded(PRINCIPAL, &["read", "produce", "schema_change"]).unwrap();
    book.install_chart(
        &[AccountSpec {
            code: "AR".into(),
            name: "Receivables".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        }],
        PRINCIPAL,
        date,
        b"chart",
        &cap,
    )
    .unwrap()
    .unwrap();
    let spec = NativeSubledgerSpec {
        code: "CUSTOMERS".into(),
        name: "Trade receivables".into(),
        kind: super::super::NativeSubledgerKind::Receivables,
        control_account: account_vid(book.context().book_id, "AR"),
    };
    book.create_native_subledger(&spec, PRINCIPAL, date, b"native", &cap)
        .unwrap()
        .unwrap();
    let request = NativeSubledgerRequest {
        code: spec.code,
        control_account: spec.control_account,
        effective_through: date,
        known_at: Some(book.head().unwrap()),
    };
    (book, request, cap)
}

#[test]
fn repaired_outer_output_still_has_to_replay_the_original_native_source() {
    let (book, request, cap) = fixture();
    let original = book
        .certify_native_subledger(PRINCIPAL, &cap, &request)
        .unwrap()
        .unwrap();
    let mut forged = original.certificate.clone();
    *forged.output.last_mut().unwrap() ^= 1;
    forged.digest = domain_digest(DIGEST, &[&forged.body_bytes().unwrap()]);
    let bytes = forged.canonical_bytes().unwrap();
    let decoded = NativeSubledgerCertificate::decode(&bytes).unwrap();
    assert_eq!(
        book.replay_native_subledger(PRINCIPAL, &cap, &decoded, &request)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION,
        "a repaired checksum does not verify the reconciliation verdict"
    );
    assert_eq!(
        book.replay_report_artifact_for(
            PRINCIPAL,
            &cap,
            &bytes,
            Some(decoded.digest()),
            ReportArtifactExpectation::NativeSubledger(&request),
        )
        .unwrap()
        .unwrap_err()
        .exit,
        exit::VERIFICATION
    );
    assert_eq!(
        book.replay_native_subledger(PRINCIPAL, &cap, &original.certificate, &request)
            .unwrap()
            .unwrap(),
        original.report
    );
    let mut omitted = original.certificate.clone();
    let entry_input = omitted
        .source
        .inputs
        .iter()
        .position(|input| input.statement.contains("(n:Entry)"))
        .unwrap();
    omitted.source.inputs.remove(entry_input);
    assert!(
        omitted.body_bytes().is_err(),
        "declaration and party controls cannot be omitted"
    );
}

#[test]
fn explicit_scope_and_current_authority_are_required_before_retention() {
    let (mut book, request, cap) = fixture();
    let before = book.head().unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["produce"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read", "produce"])
            .unwrap()
            .for_accounts(&["AR"])
            .unwrap(),
    ] {
        assert_eq!(
            book.certify_native_subledger(PRINCIPAL, &denied, &request)
                .unwrap()
                .unwrap_err()
                .code,
            fa_journal::refusal::code::CAPABILITY
        );
    }
    let certified = book
        .certify_native_subledger(PRINCIPAL, &cap, &request)
        .unwrap()
        .unwrap();
    assert_eq!(
        book.head().unwrap(),
        before,
        "certification itself publishes nothing"
    );
    let certificate = &certified.certificate;
    let bytes = certificate.canonical_bytes().unwrap();
    assert_eq!(
        ReportArtifact::decode(&bytes).unwrap().family(),
        crate::ReportArtifactFamily::NativeSubledger
    );
    assert!(
        book.replay_report_artifact_for(
            PRINCIPAL,
            &cap,
            &bytes,
            Some(certificate.digest()),
            ReportArtifactExpectation::AsSupplied,
        )
        .unwrap()
        .is_err()
    );
    let mut wrong = request.clone();
    wrong.code = "ANOTHER".into();
    assert!(
        book.replay_native_subledger(PRINCIPAL, &cap, certificate, &wrong)
            .unwrap()
            .is_err()
    );
    wrong = request.clone();
    wrong.control_account = VId(99);
    assert!(
        book.replay_native_subledger(PRINCIPAL, &cap, certificate, &wrong)
            .unwrap()
            .is_err()
    );
    wrong = request.clone();
    wrong.effective_through.0 += 1;
    assert!(
        book.replay_native_subledger(PRINCIPAL, &cap, certificate, &wrong)
            .unwrap()
            .is_err()
    );
    wrong = request.clone();
    wrong.known_at = None;
    assert!(
        book.replay_native_subledger(PRINCIPAL, &cap, certificate, &wrong)
            .unwrap()
            .is_err()
    );
    let retained = book
        .retain_report_artifact_for(
            PRINCIPAL,
            &cap,
            &bytes,
            Some(certificate.digest()),
            ReportArtifactExpectation::NativeSubledger(&request),
        )
        .unwrap()
        .unwrap();
    assert!(book.head().unwrap() >= retained.recorded_at);
    assert!(
        matches!(
            book.native_subledger_certificate_status(PRINCIPAL, &cap, certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::Current { .. }
        ),
        "retention metadata does not stale the accounting assertion"
    );
    let read = Capability::embedded(PRINCIPAL, &["read"])
        .unwrap()
        .known_at_most(certificate.known_at());
    assert_eq!(
        book.replay_native_subledger(PRINCIPAL, &read, certificate, &request)
            .unwrap()
            .unwrap(),
        certified.report
    );
    assert_eq!(
        book.native_subledger_certificate_status(PRINCIPAL, &read, certificate)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY,
        "HEAD freshness needs present scope"
    );
    let other = Capability::embedded(VId(152), &["read"]).unwrap();
    assert_eq!(
        book.replay_native_subledger(PRINCIPAL, &other, certificate, &request)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
}
