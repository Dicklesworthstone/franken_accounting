//! Real native replay precedes every request-bound workpaper export.

use super::*;

fn certified(h: &Harness, request: &RollForwardRequest) -> CertifiedRollForward {
    h.book.certify_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap().unwrap()
}

fn export(h: &Harness, certificate: &RollForwardCertificate, expected: &RollForwardRequest) -> String {
    h.book.roll_forward_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), certificate, expected)
        .unwrap().unwrap()
}

#[test]
fn recipient_scope_is_independent_including_zero_leaves_units_labels_and_prefix() {
    let h = Harness::new();
    let certificate = certified(&h, &h.request()).certificate;
    let mut expected = h.request();
    expected.known_at = Some(h.head());
    expected.accounts.reverse();
    assert!(h.book.replay_roll_forward_for(&h.cx(), PRINCIPAL, &cap(&["read"]), &certificate, &expected)
        .unwrap().is_ok());
    for case in 0..7 {
        let mut wrong = expected.clone();
        match case {
            0 => wrong.known_at = None,
            1 => wrong.known_at = Some(CommitSeq(h.head().0 - 1)),
            2 => { wrong.accounts.pop(); }
            3 => wrong.units.push(h.jpy.0),
            4 => wrong.label.push_str(" substituted"),
            5 => wrong.effective_from = day(11),
            _ => wrong.effective_through = day(21),
        }
        assert!(h.book.replay_roll_forward_for(&h.cx(), PRINCIPAL, &cap(&["read"]), &certificate, &wrong)
            .unwrap().is_err(), "case {case}");
        assert!(h.book.roll_forward_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &certificate, &wrong)
            .unwrap().is_err(), "case {case}");
    }
}

#[test]
fn exact_jsonl_keeps_zero_cells_native_units_buckets_and_every_citation() {
    let mut h = Harness::new();
    let exact = (1_i128 << 100) + 1;
    h.post(1, b"opening", h.usd, exact);
    h.post(10, b"movement", h.usd, 50);
    h.post(10, b"yen", h.jpy, -50);
    let mut expected = h.request();
    expected.units.push(h.jpy.0);
    expected.known_at = Some(h.head());
    expected.label = "Report \"A\"\n€".into();
    let certified = certified(&h, &expected);
    let at = h.head();
    let text = export(&h, &certified.certificate, &expected);
    assert!(text.contains(&format!("\"opening\":\"{exact}\"")));
    assert!(text.contains("\"code\":\"USD\""));
    assert!(text.contains("\"code\":\"JPY\""));
    assert!(text.contains("\"label\":\"Report \\\"A\\\"\\n€\""));
    assert_eq!(text.lines().filter(|line| line.contains("\"event\":\"roll_forward_account\"")).count(), 3);
    assert_eq!(text.lines().filter(|line| line.contains("\"event\":\"roll_forward_row\"")).count(), 6);
    assert_eq!(text.lines().filter(|line| line.contains("\"event\":\"roll_forward_movement\"")).count(), 4);
    assert!(text.contains("\"activity\":[\"0\"],\"net_change\":\"0\",\"closing\":\"0\""));
    assert!(text.contains("\"outsider_completeness_proof\":false"));
    assert!(text.contains("\"period_close_authorized\":false"));
    for movement in &certified.report.movements {
        let digest: String = movement.entry_digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(text.contains(&format!("\"entry_digest\":\"{digest}\"")));
    }
    assert_eq!(export(&h, &certified.certificate, &expected), text);
    h.post(11, b"late", h.usd, 9);
    assert!(h.head() > at);
    assert_eq!(export(&h, &certified.certificate, &expected), text, "do not refresh the delivered basis");
}

#[test]
fn selected_workpaper_does_not_print_unselected_accounts_from_native_source() {
    let mut h = Harness::new();
    h.post(10, b"source", h.usd, 100);
    let expected = RollForwardRequest {
        accounts: vec![h.id("1000")], known_at: Some(h.head()), ..h.request()
    };
    let certificate = certified(&h, &expected).certificate;
    let text = export(&h, &certificate, &expected);
    assert!(text.contains(&format!("\"account\":\"{:032x}\"", h.id("1000").0)));
    assert!(!text.contains(&format!("\"account\":\"{:032x}\"", h.id("3000").0)));
    assert!(!text.contains(&format!("\"account\":\"{:032x}\"", h.id("6100").0)));
    assert_eq!(text.lines().filter(|line| line.contains("\"event\":\"roll_forward_movement\"")).count(), 1);
    assert!(!text.contains("source_certificate"));
}

#[test]
fn export_needs_produce_authority_even_after_a_successful_read_replay() {
    let h = Harness::new();
    let expected = RollForwardRequest { known_at: Some(h.head()), ..h.request() };
    let certificate = certified(&h, &expected).certificate;
    let at = h.head();
    assert!(h.book.replay_roll_forward_for(&h.cx(), PRINCIPAL, &cap(&["read"]), &certificate, &expected)
        .unwrap().is_ok());
    for ops in [vec!["read"], vec!["produce"], vec!["post"]] {
        assert!(h.book.roll_forward_jsonl(&h.cx(), PRINCIPAL, &cap(&ops), &certificate, &expected)
            .unwrap().is_err());
    }
    assert!(h.book.roll_forward_jsonl(&h.cx(), VId(99), &cap(&["read", "produce"]), &certificate, &expected)
        .unwrap().is_err());
    assert_eq!(h.head(), at);
}
