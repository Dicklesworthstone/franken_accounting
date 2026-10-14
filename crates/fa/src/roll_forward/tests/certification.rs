//! Exercise the real kernel and retained native source, not a mock certificate.

use super::*;
use fa_model::{Writer, domain_digest};
use crate::ReportCertificate;

fn certify(h: &Harness, request: &RollForwardRequest) -> CertifiedRollForward {
    h.book.certify_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap().unwrap()
}

fn replay(h: &Harness, certificate: &RollForwardCertificate) -> RollForward {
    h.book.replay_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), certificate)
        .unwrap().unwrap()
}

/// An attacker knows the public digest algorithm. Rehashing a forged schedule
/// must not grant it the meaning of a successfully replayed native certificate.
fn frame(source: &ReportCertificate, request: &RollForwardRequest, output: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(ROLL_FORWARD_CERTIFICATE_FORMAT).bytes(&source.canonical_bytes().unwrap())
        .list(&request.accounts, |w, account| { w.u128(account.0); })
        .list(&request.units, |w, unit| { w.u32(*unit); })
        .str(&request.label).i32(request.effective_from.0).i32(request.effective_through.0)
        .bytes(output);
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(b"fa:roll-forward-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    bytes
}

#[test]
fn exact_native_schedule_round_trips_with_canonical_scope_and_no_writes() {
    let mut h = Harness::new();
    let exact = (1_i128 << 100) + 1;
    h.post(1, b"opening", h.usd, exact);
    h.post(10, b"first", h.usd, 50);
    h.post(20, b"last", h.usd, -20);
    h.post(21, b"outside", h.usd, 7);
    h.post(10, b"yen", h.jpy, -50);
    let at = h.head();
    let mut request = h.request();
    request.units.push(h.jpy.0);
    let certified = certify(&h, &request);
    assert_eq!(certified.report, h.read(&request));
    let cash = row(&certified.report, h.id("1000"), h.usd);
    assert_eq!((cash.opening, cash.net_change, cash.closing), (exact, 30, exact + 30));
    assert_eq!(row(&certified.report, h.id("1000"), h.jpy).closing, -50);
    assert_eq!(row(&certified.report, h.id("6100"), h.usd).closing, 0);
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let decoded = RollForwardCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.request().known_at, Some(at));
    assert_eq!(decoded.output(), certified.report.canonical_bytes().unwrap());
    assert_eq!(replay(&h, &decoded), certified.report);
    request.accounts.reverse();
    request.units.reverse();
    assert_eq!(certify(&h, &request).certificate.canonical_bytes().unwrap(), bytes);
    assert_eq!(h.head(), at, "certification, replay and decoding publish nothing");
}

#[test]
fn portable_certificate_replays_original_prefix_after_late_posting_and_reopen() {
    let mut h = Harness::new();
    h.post(1, b"opening", h.usd, 100);
    h.post(10, b"first", h.usd, 50);
    let certified = certify(&h, &h.request());
    let saved = certified.certificate.canonical_bytes().unwrap();
    h.post(11, b"late-effective", h.usd, 9);
    assert_eq!(row(&h.read(&h.request()), h.id("1000"), h.usd).closing, 159);
    let head = h.head();
    let Harness { runtime, root, book, vfs, usd, jpy, evidence } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let book = runtime.block_on(AsyncBook::open_with_vfs(
        &cx, vfs.clone(), Path::new("roll-forward-book"), BookKeys::for_development(113),
        Entropy::deterministic(114),
    )).unwrap();
    let h = Harness { runtime, root, book, vfs, usd, jpy, evidence };
    assert_eq!(replay(&h, &RollForwardCertificate::decode(&saved).unwrap()), certified.report);
    assert_eq!(h.head(), head);
}

#[test]
fn rehashed_omission_of_offsetting_entries_cannot_pass_native_replay() {
    let mut h = Harness::new();
    h.post(10, b"incoming", h.usd, 50);
    h.post(11, b"outgoing", h.usd, -50);
    let certified = certify(&h, &h.request());
    assert_eq!(certified.report.movements.len(), 4);
    assert!(certified.report.rows.iter().all(|row| {
        row.opening == 0 && row.net_change == 0 && row.closing == 0
    }));
    let mut omitted = certified.report.clone();
    omitted.movements.clear(); // every amount and even every bucket still agrees
    let bytes = frame(certified.certificate.source_certificate(), certified.certificate.request(),
        &omitted.canonical_bytes().unwrap());
    let forged = RollForwardCertificate::decode(&bytes).unwrap();
    let at = h.head();
    assert!(h.book.replay_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged)
        .unwrap().is_err());
    assert_eq!(h.head(), at);
}

#[test]
fn rehashed_amount_metadata_and_entry_citation_changes_are_detected() {
    let mut h = Harness::new();
    h.post(10, b"source", h.usd, 100);
    let certified = certify(&h, &h.request());
    for case in 0..4 {
        let mut report = certified.report.clone();
        match case {
            0 => report.movements[0].entry_digest[0] ^= 1,
            1 => report.accounts[0].name.push_str(" altered"),
            2 => report.rows[0].closing += 1,
            _ => report.movements[0].bucket.reason_code = "invented reason".into(),
        }
        let forged = RollForwardCertificate::decode(&frame(
            certified.certificate.source_certificate(), certified.certificate.request(),
            &report.canonical_bytes().unwrap(),
        )).unwrap();
        assert!(h.book.replay_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged)
            .unwrap().is_err(), "case {case}");
    }
}

#[test]
fn same_totals_in_an_independent_history_are_not_the_certified_source() {
    let mut first = Harness::new();
    let mut other = Harness::new();
    first.post(10, b"original-entry", first.usd, 100);
    other.post(10, b"different-entry", other.usd, 100);
    let certificate = certify(&first, &first.request()).certificate;
    assert_eq!(row(&first.read(&first.request()), first.id("1000"), first.usd).closing,
        row(&other.read(&other.request()), other.id("1000"), other.usd).closing);
    assert!(other.book.replay_roll_forward(&other.cx(), PRINCIPAL, &cap(&["read"]), &certificate)
        .unwrap().is_err());
}

#[test]
fn certification_and_replay_require_current_authority_not_artifact_possession() {
    let h = Harness::new();
    let request = h.request();
    let certificate = certify(&h, &request).certificate;
    let at = h.head();
    for operations in [vec!["read"], vec!["produce"], vec!["post"]] {
        assert!(h.book.certify_roll_forward(&h.cx(), PRINCIPAL, &cap(&operations), &request)
            .unwrap().is_err());
    }
    assert!(h.book.certify_roll_forward(&h.cx(), VId(99), &cap(&["read", "produce"]), &request)
        .unwrap().is_err());
    assert!(h.book.replay_roll_forward(&h.cx(), PRINCIPAL, &cap(&["produce"]), &certificate)
        .unwrap().is_err());
    assert!(h.book.replay_roll_forward(&h.cx(), VId(99), &cap(&["read"]), &certificate)
        .unwrap().is_err());
    assert_eq!(h.head(), at);
}

#[test]
fn alternate_scope_encodings_truncation_and_untrusted_counts_fail_closed() {
    let h = Harness::new();
    let certificate = certify(&h, &h.request()).certificate;
    let bytes = certificate.canonical_bytes().unwrap();
    for length in [0, 4, bytes.len() / 2, bytes.len() - 1] {
        assert!(RollForwardCertificate::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone(); trailing.push(0);
    assert!(RollForwardCertificate::decode(&trailing).is_err());
    let mut altered = bytes; *altered.last_mut().unwrap() ^= 1;
    assert!(RollForwardCertificate::decode(&altered).is_err());
    let mut request = certificate.request().clone();
    request.accounts.reverse();
    assert!(RollForwardCertificate::decode(&frame(certificate.source_certificate(), &request,
        certificate.output())).is_err());
    request.accounts = vec![request.accounts[0], request.accounts[0]];
    assert!(RollForwardCertificate::decode(&frame(certificate.source_certificate(), &request,
        certificate.output())).is_err());
    for count in [0, 4096, u32::MAX] {
        let mut w = Writer::new();
        w.bytes(ROLL_FORWARD_CERTIFICATE_FORMAT)
            .bytes(&certificate.source_certificate().canonical_bytes().unwrap())
            .u32(count).u128(1);
        assert!(RollForwardCertificate::decode(&w.finish().unwrap()).is_err());
    }
}

#[test]
fn selector_and_output_headers_cannot_be_substituted_independently() {
    let h = Harness::new();
    let certificate = certify(&h, &h.request()).certificate;
    for case in 0..3 {
        let mut request = certificate.request().clone();
        match case {
            0 => request.label.push_str(" altered"),
            1 => request.effective_from = day(11),
            _ => request.effective_through = day(21),
        }
        assert!(RollForwardCertificate::decode(&frame(certificate.source_certificate(), &request,
            certificate.output())).is_err(), "case {case}");
    }
    for request in [
        RollForwardRequest { accounts: vec![], ..h.request() },
        RollForwardRequest { accounts: vec![VId(u128::MAX)], ..h.request() },
        RollForwardRequest { known_at: Some(CommitSeq(h.head().0 + 1)), ..h.request() },
    ] {
        assert!(h.book.certify_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request)
            .unwrap().is_err());
    }
}
