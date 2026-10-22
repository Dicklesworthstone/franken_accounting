//! Complete CLI layout -> original evidence -> replay workflow.
use super::*;

const LAYOUT: &str = r#"{"version":1,"name":"download-v1","headers":["Date","Description","Amount"],"delimiter":";","decimal_separator":",","date_format":"DD/MM/YYYY","booking_date":"Date","reference":"Description","amount":{"column":"Amount","positive":"credit"},"statement":{"instrument_id":"BANK-123","sequence_number":1,"currency":"USD","statement_date":"2026-03-31","opening_balance":"0,00","closing_balance":"100,00"}}"#;
const SOURCE: &str =
    "Date;Description;Amount\r\n05/03/2026;SALE-1;150,00\r\n06/03/2026;BILL-1;-50,00\r\n";

#[test]
fn custom_layout_import_is_atomic_replayable_and_content_idempotent() {
    let f = Fixture::new();
    f.post("custom-sale", "2026-03-05", "debit", "150.00", "SALE-1");
    f.post("custom-bill", "2026-03-06", "credit", "50.00", "BILL-1");
    let source = f.file("download.csv", SOURCE);
    let layout = f.file("layout.json", LAYOUT);
    let before = head(&f.book);
    let imported = ok(
        &f.book,
        &[
            "bank",
            "import",
            &source,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--layout",
            &layout,
        ],
    );
    let result = data(&imported);
    assert_eq!(head(&f.book), before + 1);
    assert_eq!(text(result, "layout_name"), "download-v1");
    assert_eq!(text(result, "layout_digest").len(), 64);
    assert_eq!(text(result, "opening_balance"), "0.00 USD");
    assert_eq!(text(result, "closing_balance"), "100.00 USD");
    assert_eq!(text(result, "continuity"), "unlinked");
    assert_eq!(integer(result, "line_count"), 2);
    let retained = ok_privileged(
        &f.book,
        &["document", "read", text(result, "statement_oid")],
    );
    assert_eq!(
        text(data(&retained).get("text").unwrap(), "untrusted_content"),
        SOURCE
    );

    // Every invocation reopens the book. Inline and file declarations canonicalize
    // to the same semantics and return the first receipt without full-source read authority.
    let before = head(&f.book);
    let retry = ok(
        &f.book,
        &[
            "bank",
            "import",
            &source,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--layout",
            LAYOUT,
        ],
    );
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for key in [
        "manifest_oid",
        "statement_oid",
        "statement_commit",
        "receipt_hash",
        "layout_digest",
        "recorded_at",
    ] {
        assert_eq!(data(&retry).get(key), result.get(key), "{key}");
    }
    assert_eq!(head(&f.book), before);

    let matched = ok_privileged(
        &f.book,
        &["bank", "match", "--import", text(result, "manifest_oid")],
    );
    assert_eq!(integer(data(&matched), "proposed_count"), 2);
    assert_eq!(integer(data(&matched), "unmatched_count"), 0);
    let changed = LAYOUT.replace("\"reference\":\"Description\"", "\"reference\":\"Date\"");
    let before = head(&f.book);
    let (status, refusal) = run(
        &f.book,
        &[
            "bank",
            "import",
            &source,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--layout",
            &changed,
        ],
    );
    assert_ne!(status, 0, "{}", refusal.render());
    assert_eq!(
        text(data(&refusal), "refusal_id"),
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(
        head(&f.book),
        before,
        "one source/account cannot change its recorded mapping"
    );
}

#[test]
fn malformed_layout_or_source_refuses_without_publishing() {
    let f = Fixture::new();
    let source = f.file("download.csv", SOURCE);
    for layout in [
        LAYOUT.replace("\"positive\":\"credit\"", "\"positive\":\"automatic\""),
        LAYOUT.replace("\"date_format\":\"DD/MM/YYYY\"", "\"date_format\":\"auto\""),
        LAYOUT.replace("\"currency\":\"USD\"", "\"currency\":\"UNREGISTERED\""),
        LAYOUT.replace("\"opening_balance\":\"0,00\"", "\"opening_balance\":0"),
        LAYOUT.replace(
            "\"closing_balance\":\"100,00\"",
            "\"closing_balance\":\"100,01\"",
        ),
        LAYOUT.replace("\"booking_date\":\"Date\"", "\"booking_date\":\"Missing\""),
        LAYOUT.replace("\"version\":1", "\"version\":1,\"guess\":true"),
    ] {
        let before = head(&f.book);
        let (status, refusal) = run(
            &f.book,
            &[
                "bank",
                "import",
                &source,
                "--bank-format",
                "csv",
                "--account",
                "1000",
                "--layout",
                &layout,
            ],
        );
        assert_ne!(status, 0, "{}", refusal.render());
        assert_eq!(head(&f.book), before);
    }
    for malformed in [
        SOURCE.replace("150,00", "150,001"),
        SOURCE.replace("05/03/2026", "03/05/2026"),
        SOURCE.replace("Date;Description", "Description;Date"),
    ] {
        let source = f.file("invalid-download.csv", &malformed);
        let before = head(&f.book);
        let (status, refusal) = run(
            &f.book,
            &[
                "bank",
                "import",
                &source,
                "--bank-format",
                "csv",
                "--account",
                "1000",
                "--layout",
                LAYOUT,
            ],
        );
        assert_ne!(status, 0, "{}", refusal.render());
        assert_eq!(head(&f.book), before);
    }
    let before = head(&f.book);
    let (status, _) = run(
        &f.book,
        &[
            "bank",
            "import",
            &source,
            "--bank-format",
            "ofx",
            "--account",
            "1000",
            "--layout",
            LAYOUT,
        ],
    );
    assert_ne!(status, 0);
    assert_eq!(head(&f.book), before);
}
