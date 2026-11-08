//! A real reopened CLI book serves functional activity across maintenance,
//! new journal tails and explicit rebuilds; certification stays independent.

use super::*;

#[test]
fn functional_registers_continue_and_rebuild_without_changing_certified_activity() {
    let fixture = Fixture::new();
    fixture.post("maintained-initial", "2026-01-05", "100.00", 11);
    let original = head(&fixture.book).to_string();
    let activity = ["tb", "--functional", "--activity", "--period", "FY2026-P01"];
    let initial = ok(&fixture.book, &activity);
    assert_eq!(total_debits(&initial), "110.00 USD");
    let verify = ["verify", "registers", "--functional", "--period", "FY2026-P01"];
    let absent = ok(&fixture.book, &verify);
    assert_eq!(text(&absent, "event"), "functional_registers_verified");
    assert_eq!(text(&rows(data(&absent), "periods")[0], "status"), "absent");
    let advance = ["registers", "advance", "--functional", "--period", "FY2026-P01"];
    let cold = ok(&fixture.book, &advance);
    assert_eq!(text(&cold, "event"), "functional_registers_advanced");
    assert_eq!(data(&cold).get("rebuilt"), Some(&Json::Bool(true)));
    assert_eq!(data(&cold).get("wrote"), Some(&Json::Bool(true)));
    assert_eq!(text(data(&cold), "base_unit"), "USD");
    assert!(integer(data(&cold), "entries_decoded") > 0);
    assert_eq!(integer(data(&cold), "legs_folded"), 2);
    assert_eq!(integer(data(&cold), "entries"), 1);

    // Each helper launches a new process: no process-local decoded-entry
    // cache can explain the continued amount columns.
    let maintained = ok(&fixture.book, &activity);
    assert_eq!(total_debits(&maintained), "110.00 USD");
    fixture.post("maintained-tail", "2026-01-06", "20.00", 12);
    let before_read = head(&fixture.book);
    let with_tail = ok(&fixture.book, &activity);
    assert_eq!(total_debits(&with_tail), "134.00 USD");
    assert_eq!(integer(data(&with_tail), "entries"), 2);
    assert_eq!(head(&fixture.book), before_read, "serving does not maintain implicitly");
    let warm = ok(&fixture.book, &advance);
    assert_eq!(data(&warm).get("rebuilt"), Some(&Json::Bool(false)));
    assert_eq!(data(&warm).get("wrote"), Some(&Json::Bool(true)));
    assert_eq!(integer(data(&warm), "legs_folded"), 2);
    assert_eq!(integer(data(&warm), "entries"), 2);
    let before_noop = head(&fixture.book);
    let noop = ok(&fixture.book, &advance);
    assert_eq!(data(&noop).get("wrote"), Some(&Json::Bool(false)));
    assert_eq!(integer(data(&noop), "entries_decoded"), 0);
    assert_eq!(integer(data(&noop), "legs_folded"), 0);
    assert_eq!(head(&fixture.book), before_noop);
    let verified = ok(&fixture.book, &verify);
    let checked = &rows(data(&verified), "periods")[0];
    assert_eq!(text(checked, "status"), "verified_prefix");
    assert_eq!(integer(checked, "through"), integer(data(&warm), "through"));
    assert_eq!(head(&fixture.book), before_noop);

    // The original prefix predates the first snapshot. Historical selection
    // must fall back or select an earlier exact snapshot, never read today's
    // maintained amount columns as yesterday's balances.
    let mut historical = activity.to_vec();
    historical.extend(["--as-known-at", &original]);
    let old = ok(&fixture.book, &historical);
    assert_eq!(data(&old), data(&initial));
    let mut old_verify = verify.to_vec();
    old_verify.extend(["--as-known-at", &original]);
    let old_cache = ok(&fixture.book, &old_verify);
    assert_eq!(text(&rows(data(&old_cache), "periods")[0], "status"), "absent");
    let (status, _) = run(&fixture.book, &[
        "registers", "materialize", "--functional", "--period", "FY2026-P01",
    ]);
    assert_eq!(status, 2);
    assert_eq!(head(&fixture.book), before_noop);
    let rebuilt = ok(&fixture.book, &[
        "registers", "materialize", "--functional", "--period", "FY2026-P01", "--yes",
    ]);
    assert_eq!(data(&rebuilt).get("rebuilt"), Some(&Json::Bool(true)));
    assert_eq!(integer(data(&rebuilt), "legs_folded"), 4);
    assert_eq!(total_debits(&ok(&fixture.book, &activity)), "134.00 USD");

    let pin = head(&fixture.book).to_string();
    let mut selected = activity.to_vec();
    selected.extend(["--as-known-at", &pin]);
    let plain = ok(&fixture.book, &selected);
    let path = fixture.dir.join("maintained-functional.cert");
    selected.extend(["--certificate-out", path.to_str().unwrap()]);
    let certified = ok_many(&fixture.book, &selected);
    assert_eq!(data(&certified[0]), data(&plain));
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.starts_with(b"fa:report-certificate:v10"));
    let reference = format!("C:{}", text(data(&certified[1]), "oid"));
    assert_eq!(ok_many(&fixture.book, &["replay", &reference])[0], certified[0]);
}
