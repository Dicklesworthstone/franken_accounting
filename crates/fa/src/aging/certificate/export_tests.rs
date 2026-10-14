use super::*;

#[test]
fn workpapers_replay_every_row_keep_large_numbers_and_ignore_later_head() {
    let mut h = Harness::new();
    let exact = (1_i128 << 90) + 1;
    let invoice = h.post(
        "DO_NOT_DISCLOSE_DESCRIPTION",
        "2026-03-01",
        h.usd,
        ("ar", "sales"),
        exact,
        None,
    );
    h.post(
        "payment",
        "2026-03-15",
        h.usd,
        ("cash", "ar"),
        40,
        Some(invoice),
    );
    h.post("eur", "2026-03-01", h.eur, ("ar", "sales"), 7, None);
    let good = h.certify(&h.request("2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let export = |h: &Harness| {
        h.book
            .effective_date_aging_jsonl(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &good.certificate,
                &expected,
            )
            .unwrap()
            .unwrap()
    };
    let text = export(&h);
    assert!(text.contains("\"event\":\"aging_workpaper\""));
    assert!(text.contains("\"age_basis\":\"effective_date\""));
    assert!(text.contains("\"due_date_claim\":false"));
    assert!(text.contains("\"name\":\"ar account\""));
    assert!(text.contains("\"code\":\"USD\""));
    assert!(text.contains("\"code\":\"EUR\""));
    assert!(text.contains(&format!("\"original_mantissa\":\"{exact}\"")));
    assert!(text.contains(&format!("\"open_mantissa\":\"{}\"", exact - 40)));
    assert!(text.contains("\"event\":\"aging_application\""));
    assert!(!text.contains("DO_NOT_DISCLOSE_DESCRIPTION"));
    assert!(!text.contains("Historical aging evidence"));
    let rows = 1
        + 1
        + 2
        + good.report.bands.len()
        + good.report.items.len()
        + good
            .report
            .items
            .iter()
            .map(|r| r.item.applications.len())
            .sum::<usize>()
        + good.report.cells.len()
        + good.report.totals.len();
    assert_eq!(text.lines().count(), rows);
    let saved_head = h.head();
    assert_eq!(export(&h), text);
    assert_eq!(h.head(), saved_head);
    h.post("new-head", "2026-03-30", h.usd, ("ar", "sales"), 11, None);
    let h = h.reopen();
    assert_eq!(export(&h), text);
}

#[test]
fn a_valid_certificate_for_another_question_is_not_the_requested_workpaper() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let good = h.certify(&h.request("2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let mut wrong = Vec::new();
    let mut r = expected.clone();
    r.known_at = None;
    wrong.push(r);
    let mut r = expected.clone();
    r.known_at = Some(CommitSeq(r.known_at.unwrap().0 - 1));
    wrong.push(r);
    let mut r = expected.clone();
    r.effective_through = day("2026-03-30");
    wrong.push(r);
    let mut r = expected.clone();
    r.account = Some(h.id("ap"));
    wrong.push(r);
    let mut r = expected.clone();
    r.account = None;
    wrong.push(r);
    let mut r = expected.clone();
    r.buckets = AgingBuckets::new(vec![30]).unwrap();
    wrong.push(r);
    for request in wrong {
        assert!(
            h.book
                .replay_effective_date_aging_for(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &good.certificate,
                    &request
                )
                .unwrap()
                .is_err()
        );
        assert!(
            h.book
                .effective_date_aging_jsonl(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    &good.certificate,
                    &request
                )
                .unwrap()
                .is_err()
        );
    }
    let changed = h.certify(&h.request("2026-03-30"));
    assert_eq!(
        h.replay(&changed.certificate),
        changed.report,
        "the substituted source is genuinely valid"
    );
    assert!(
        h.book
            .effective_date_aging_jsonl(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &changed.certificate,
                &expected
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(
        h.book
            .replay_effective_date_aging_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &good.certificate,
                &expected
            )
            .unwrap()
            .unwrap(),
        good.report
    );
}

#[test]
fn workpaper_requires_produce_and_never_returns_resealed_false_output() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let good = h.certify(&h.request("2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let head = h.head();
    for ops in [&["read"][..], &["produce"][..], &["post"][..]] {
        let denial = h
            .book
            .effective_date_aging_jsonl(&h.cx(), PRINCIPAL, &cap(ops), &good.certificate, &expected)
            .unwrap()
            .unwrap_err();
        assert_eq!(denial.code, fa_journal::refusal::code::CAPABILITY);
    }
    let mut report = good.report.clone();
    report.totals[0].amounts.debits += 1;
    let fake = reseal(&good.certificate, output_bytes(&report).unwrap());
    assert_eq!(
        h.book
            .effective_date_aging_jsonl(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &fake,
                &expected
            )
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
    assert_eq!(h.head(), head);
}

#[test]
fn selected_empty_accounts_and_historical_account_names_remain_explicit() {
    let mut h = Harness::new();
    let good = h.certify(&h.request("2026-03-31"));
    let expected = good.certificate.request().unwrap();
    let cx = h.cx();
    let mut change = WriteBatch::new(relation::CHILD_OF);
    change.compare_and_set_vertex_property(
        h.id("ar"),
        property::NAME,
        Some(CanonicalScalar::ucs_basic_text("ar account").unwrap()),
        CanonicalScalar::ucs_basic_text("later account name").unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), change))
        .unwrap();
    let text = h
        .book
        .effective_date_aging_jsonl(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &good.certificate,
            &expected,
        )
        .unwrap()
        .unwrap();
    assert!(text.contains("\"name\":\"ar account\""));
    assert!(!text.contains("later account name"));
    assert!(!text.contains("\"event\":\"aged_open_item\""));
    assert_eq!(text.lines().count(), 2 + good.report.bands.len());
}
