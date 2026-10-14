use super::*;
use crate::roll_forward::RollForwardCertificate;

fn certify(h: &Harness, request: &RollForwardRequest) -> CertifiedGeneralLedger {
    h.book
        .certify_general_ledger(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap()
}

#[test]
fn source_roundtrip_replays_the_same_general_ledger_without_writing() {
    let mut h = Harness::new();
    h.post(1, b"opening", h.usd, 100);
    h.post(15, b"one", h.usd, -20);
    h.post(10, b"two", h.usd, 10);
    let mut expected = h.request();
    expected.known_at = Some(h.head());
    let before = h.head();
    let certified = certify(&h, &expected);
    assert_eq!(certified.report(), &h.read(&expected));
    let bytes = certified.source_certificate().canonical_bytes().unwrap();
    let source = RollForwardCertificate::decode(&bytes).unwrap();
    let replay = h
        .book
        .replay_general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &source, &expected)
        .unwrap()
        .unwrap();
    assert_eq!(
        replay.canonical_bytes().unwrap(),
        certified.report().canonical_bytes().unwrap()
    );
    assert_eq!(source.canonical_bytes().unwrap(), bytes);
    assert_eq!(h.head(), before);
}

#[test]
fn delivered_sources_cannot_substitute_scope_zero_leaves_dates_labels_units_or_head() {
    let h = Harness::new();
    let mut expected = h.request();
    expected.known_at = Some(h.head());
    let certified = certify(&h, &expected);
    let source = certified.source_certificate();
    for changed in [
        RollForwardRequest {
            accounts: vec![h.id("1000"), h.id("3000")],
            ..expected.clone()
        },
        RollForwardRequest {
            units: vec![h.jpy.0],
            ..expected.clone()
        },
        RollForwardRequest {
            effective_from: day(11),
            ..expected.clone()
        },
        RollForwardRequest {
            effective_through: day(19),
            ..expected.clone()
        },
        RollForwardRequest {
            label: "Substituted scope".into(),
            ..expected.clone()
        },
        RollForwardRequest {
            known_at: None,
            ..expected.clone()
        },
        RollForwardRequest {
            known_at: Some(CommitSeq(h.head().0 + 1)),
            ..expected.clone()
        },
    ] {
        assert!(
            h.book
                .replay_general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), source, &changed)
                .unwrap()
                .is_err()
        );
        assert!(
            h.book
                .general_ledger_jsonl(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    source,
                    &changed
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn later_offsetting_entries_leave_old_workpaper_stable_but_are_not_netted_from_current_detail() {
    let mut h = Harness::new();
    h.post(10, b"original", h.usd, 100);
    let mut expected = h.request();
    expected.known_at = Some(h.head());
    let certified = certify(&h, &expected);
    let source = certified.source_certificate();
    let original = h
        .book
        .general_ledger_jsonl(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            source,
            &expected,
        )
        .unwrap()
        .unwrap();
    h.post(11, b"later-plus", h.usd, 7);
    h.post(11, b"later-minus", h.usd, -7);
    let current = h.read(&h.request());
    assert_eq!(
        current.cell(h.id("1000"), h.usd.0).unwrap().closing,
        certified
            .report()
            .cell(h.id("1000"), h.usd.0)
            .unwrap()
            .closing
    );
    assert_eq!(current.lines().len(), certified.report().lines().len() + 4);
    assert_eq!(
        h.book
            .general_ledger_jsonl(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                source,
                &expected
            )
            .unwrap()
            .unwrap(),
        original
    );
}

#[test]
fn identical_closing_stock_and_coordinate_do_not_authenticate_another_journal_history() {
    let mut a = Harness::new();
    let mut b = Harness::new();
    a.post(10, b"one", a.usd, 10);
    a.post(10, b"two", a.usd, -10);
    b.post(10, b"one", b.usd, 5);
    b.post(10, b"two", b.usd, -5);
    assert_eq!(a.head(), b.head());
    let mut expected = a.request();
    expected.known_at = Some(a.head());
    let certified = certify(&a, &expected);
    assert_eq!(
        certified
            .report()
            .cell(a.id("1000"), a.usd.0)
            .unwrap()
            .closing,
        b.read(&expected)
            .cell(b.id("1000"), b.usd.0)
            .unwrap()
            .closing
    );
    assert!(
        b.book
            .replay_general_ledger(
                &b.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                certified.source_certificate(),
                &expected
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn workpaper_retains_exact_selected_units_cells_citations_and_large_mantissas_only() {
    let mut h = Harness::new();
    let large = (1i128 << 100) + 17;
    h.post(10, b"dollars", h.usd, large);
    h.post(20, b"yen", h.jpy, -7);
    let mut expected = h.request();
    expected.accounts = vec![h.id("1000"), h.id("6100")];
    expected.units.push(h.jpy.0);
    expected.label = "Ledger € \"quoted\"\n\\".into();
    expected.known_at = Some(h.head());
    let certified = certify(&h, &expected);
    let text = h
        .book
        .general_ledger_jsonl(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            certified.source_certificate(),
            &expected,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\"event\":\"general_ledger_line\""))
            .count(),
        2
    );
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\"event\":\"general_ledger_cell\""))
            .count(),
        4
    );
    assert!(text.contains(&format!("\"running_balance\":\"{large}\"")));
    assert!(text.contains("\"running_balance\":\"-7\""));
    assert!(text.contains("\"code\":\"USD\""));
    assert!(text.contains("\"code\":\"JPY\""));
    assert!(text.contains("\"code\":\"6100\""));
    assert!(!text.contains("\"code\":\"3000\""));
    assert!(!text.contains(&format!("\"account\":\"{:032x}\"", h.id("3000").0)));
    assert!(text.contains("Ledger € \\\"quoted\\\"\\n\\\\"));
    assert!(text.contains("\"native_history_replayed\":true"));
    assert!(text.contains("\"outsider_completeness_proof\":false"));
    assert!(!text.contains("General ledger posting"));
    assert!(!text.contains("test source evidence"));
    assert!(!text.contains("source_certificate_bytes"));
    assert!(text.ends_with("}\n"));
}

#[test]
fn export_and_certification_need_produce_authority_but_replay_only_needs_read() {
    let h = Harness::new();
    let mut expected = h.request();
    expected.known_at = Some(h.head());
    let certified = certify(&h, &expected);
    assert!(
        h.book
            .certify_general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &expected)
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .replay_general_ledger(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                certified.source_certificate(),
                &expected
            )
            .unwrap()
            .is_ok()
    );
    for (principal, capability) in [
        (PRINCIPAL, cap(&["read"])),
        (PRINCIPAL, cap(&["produce"])),
        (VId(99), cap(&["read", "produce"])),
    ] {
        assert!(
            h.book
                .general_ledger_jsonl(
                    &h.cx(),
                    principal,
                    &capability,
                    certified.source_certificate(),
                    &expected
                )
                .unwrap()
                .is_err()
        );
    }
}
