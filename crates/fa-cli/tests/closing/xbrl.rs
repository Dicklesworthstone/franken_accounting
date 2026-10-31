//! Real Closing entries must not erase XBRL income activity.

use super::*;
use fa_formats::xbrl::{
    read_xbrl_income_attribution, read_xbrl_instance_xml, verify_format_journal_xbrl_xml,
    write_xbrl_instance_xml,
};

fn logged(f: &Fixture, args: &[&str]) -> Json {
    let (code, result) = run(&f.book, args);
    eprintln!(
        "xbrl-closing argv={args:?} exit={code} result={}",
        result.render()
    );
    assert_eq!(code, 0, "args={args:?}: {}", result.render());
    result
}

fn export(f: &Fixture, name: &str, known_at: Option<u64>) -> (String, String) {
    let path = f.dir.join(format!("{name}.xbrl")).display().to_string();
    let pin = known_at.map(|seq| seq.to_string());
    let mut args = vec!["export", "xbrl", "--as-of", "2026-12-31", "--out", &path];
    if let Some(pin) = &pin {
        args.extend(["--as-known-at", pin]);
    }
    logged(f, &args);
    let xml = std::fs::read_to_string(&path).unwrap();
    let (_, report) = verify_format_journal_xbrl_xml(&xml).unwrap();
    assert_eq!(report.checks_passed, 4);
    assert!(read_xbrl_income_attribution(&xml).unwrap().is_some());
    logged(f, &["verify", "export", "xbrl", &path]);
    (path, xml)
}

fn fact(xml: &str, concept: &str) -> i128 {
    read_xbrl_instance_xml(xml)
        .unwrap()
        .facts
        .iter()
        .find(|fact| fact.concept == concept && fact.unit_code == "USD")
        .unwrap()
        .mantissa
}

fn income(xml: &str, revenue: i128, expense: i128, nci: i128, profit: i128) {
    assert_eq!(fact(xml, "us-gaap:Revenues"), revenue);
    assert_eq!(fact(xml, "us-gaap:OperatingExpenses"), expense);
    assert_eq!(fact(xml, "us-gaap:ProfitLoss"), profit);
    assert_eq!(
        fact(
            xml,
            "us-gaap:NetIncomeLossAttributableToNoncontrollingInterest"
        ),
        nci
    );
    assert_eq!(fact(xml, "us-gaap:NetIncomeLoss"), profit - nci);
}

#[test]
fn xbrl_income_survives_real_year_end_close_source_reversals_and_reclose() {
    const SEED: u8 = 0xec;
    let f = Fixture::with_chart_and_keys(true, CHART, Some(SEED));
    f.post("xbrl-sale", "1000", "4000", "100.00");
    let path = write(
        &f.dir,
        "expense.json",
        r#"{
        "effective_date":"2026-12-30","description":"Underlying expense",
        "idempotency_key":"xbrl-expense",
        "legs":[
            {"side":"debit","account":"6000","amount":"40.00 USD"},
            {"side":"credit","account":"1000","amount":"40.00 USD"}
        ]}"#,
    );
    let expense = logged(&f, &["post", "--intent", &path, "--evidence", &f.evidence]);
    let (before_path, before) = export(&f, "before-close", None);
    let (before_coordinate, _) = verify_format_journal_xbrl_xml(&before).unwrap();
    income(&before, 10_000, 4_000, 0, 6_000);

    let closed = f.close_now("xbrl-first-close");
    assert_eq!(text(&closed, "class"), "Closing");
    logged(&f, &["verify", "close", "FY2026"]);
    let (closed_path, closed_xml) = export(&f, "after-close", None);
    income(&closed_xml, 10_000, 4_000, 0, 6_000);
    assert_eq!(fact(&closed_xml, "us-gaap:StockholdersEquity"), 6_000);
    assert_eq!(fact(&closed_xml, "us-gaap:Assets"), 6_000);
    let (closed_coordinate, _) = verify_format_journal_xbrl_xml(&closed_xml).unwrap();

    // A coherent zero-income replacement passes standalone XML arithmetic.
    // The retained historical activity, not a self-asserted metadata digest,
    // makes book-backed verification refuse the old stock-as-income defect.
    let mut altered = read_xbrl_instance_xml(&closed_xml).unwrap();
    for item in &mut altered.facts {
        if matches!(
            item.concept.as_str(),
            "us-gaap:Revenues"
                | "us-gaap:OperatingExpenses"
                | "us-gaap:ProfitLoss"
                | "us-gaap:NetIncomeLossAttributableToNoncontrollingInterest"
                | "us-gaap:NetIncomeLoss"
        ) {
            item.mantissa = 0;
        }
    }
    let comment = closed_xml
        .lines()
        .find(|line| line.starts_with("<!-- fa:xbrl-coordinate "))
        .unwrap();
    let altered_xml =
        write_xbrl_instance_xml(&altered).replacen('\n', &format!("\n{comment}\n"), 1);
    assert!(verify_format_journal_xbrl_xml(&altered_xml).is_ok());
    let tampered = write(&f.dir, "stock-as-income.xbrl", &altered_xml);
    let (code, refused) = run(&f.book, &["verify", "export", "xbrl", &tampered]);
    eprintln!(
        "xbrl-closing tampered export exit={code} result={}",
        refused.render()
    );
    assert_eq!(code, 8, "{}", refused.render());

    // Both published older profiles still replay against the book, with
    // exactly their historical stock-based income semantics.
    let old_profiles = {
        let book = fa::Book::open_dir(
            &f.book,
            fa::BookKeys::for_development(SEED),
            fa::Entropy::deterministic(44),
        )
        .unwrap();
        let journal = book
            .format_journal(
                closed_coordinate.effective_through,
                Some(fgdb_types::CommitSeq(closed_coordinate.known_at_seq)),
            )
            .unwrap();
        [
            (
                "legacy",
                fa_formats::xbrl::write_legacy_format_journal_xbrl_xml(&journal).unwrap(),
            ),
            (
                "equity-v1",
                fa_formats::xbrl::write_format_journal_xbrl_xml(&journal).unwrap(),
            ),
        ]
    };
    for (name, xml) in old_profiles {
        assert!(read_xbrl_income_attribution(&xml).unwrap().is_none());
        assert_eq!(fact(&xml, "us-gaap:NetIncomeLoss"), 0);
        let path = write(&f.dir, &format!("{name}.xbrl"), &xml);
        logged(&f, &["verify", "export", "xbrl", &path]);
    }

    // Closing is not itself reversible. Reverse and restore a lawful source
    // entry, then delta-close it; every source-chain state keeps its income.
    let mut target = text(&expense, "vid").to_string();
    for (key, expense, profit) in [
        ("xbrl-undo-expense", 0, 10_000),
        ("xbrl-restore-expense", 4_000, 6_000),
    ] {
        let reversed = logged(
            &f,
            &["reverse", &target, "--reason", "WrongAmount", "--key", key],
        );
        target = text(&reversed, "vid").to_string();
        let (_, xml) = export(&f, key, None);
        income(&xml, 10_000, expense, 0, profit);
        f.close_now(&format!("{key}-reclose"));
        let (_, xml) = export(&f, &format!("{key}-closed"), None);
        income(&xml, 10_000, expense, 0, profit);
        assert_eq!(fact(&xml, "us-gaap:StockholdersEquity"), profit);
    }
    logged(&f, &["verify", "export", "xbrl", &before_path]);
    logged(&f, &["verify", "export", "xbrl", &closed_path]);
    let (_, replayed) = export(
        &f,
        "historical-before",
        Some(before_coordinate.known_at_seq),
    );
    assert_eq!(replayed, before);
    let (_, replayed) = export(
        &f,
        "historical-closed",
        Some(closed_coordinate.known_at_seq),
    );
    assert_eq!(replayed, closed_xml);

    // A later effective year is outside both stock and cumulative activity.
    logged(&f, &["period", "create", "--fiscal-year", "2027"]);
    logged(&f, &["period", "open", "FY2027-P01"]);
    let future = write(
        &f.dir,
        "future.json",
        r#"{
        "effective_date":"2027-01-10","idempotency_key":"xbrl-next-year",
        "legs":[
            {"side":"debit","account":"1000","amount":"1000.00 USD"},
            {"side":"credit","account":"4000","amount":"1000.00 USD"}
        ]}"#,
    );
    logged(
        &f,
        &["post", "--intent", &future, "--evidence", &f.evidence],
    );
    let (_, xml) = export(&f, "prior-year-after-future-post", None);
    income(&xml, 10_000, 4_000, 0, 6_000);
    assert_eq!(fact(&xml, "us-gaap:Assets"), 6_000);
}

#[test]
fn xbrl_closed_income_uses_historical_noncontrolling_allocation_roles() {
    let chart = r#"{"accounts":[
        {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
        {"code":"3000","name":"Parent retained earnings","type":"Equity","unit":"USD"},
        {"code":"3100","name":"Other equity","type":"Equity","unit":"USD","roles":["noncontrolling_interest"]},
        {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},
        {"code":"5900","name":"Allocation","type":"Expense","unit":"USD","roles":["noncontrolling_interest_income"]},
        {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
    ]}"#;
    let f = Fixture::with_chart(false, chart);
    logged(
        &f,
        &[
            "close",
            "map",
            "--route",
            "4000:3000",
            "--route",
            "6000:3000",
            "--route",
            "5900:3000",
            "--effective-from",
            "2026-01-01",
            "--key",
            "nci-routes",
        ],
    );
    f.post("nci-sale", "1000", "4000", "100.00");
    f.post("nci-expense", "6000", "1000", "40.00");
    f.post("nci-allocation", "5900", "3100", "12.00");
    f.close_now("nci-close");
    let (path, xml) = export(&f, "nci-closed", None);
    income(&xml, 10_000, 4_000, 1_200, 6_000);
    assert_eq!(fact(&xml, "us-gaap:StockholdersEquity"), 4_800);
    assert_eq!(fact(&xml, "us-gaap:MinorityInterest"), 1_200);
    let (coordinate, _) = verify_format_journal_xbrl_xml(&xml).unwrap();

    logged(
        &f,
        &[
            "chart",
            "role",
            "5900",
            "noncontrolling_interest_income",
            "--remove",
        ],
    );
    logged(&f, &["verify", "export", "xbrl", &path]);
    let (_, historical) = export(&f, "nci-historical", Some(coordinate.known_at_seq));
    assert_eq!(historical, xml);
    let (_, current) = export(&f, "nci-current-role", None);
    income(&current, 10_000, 5_200, 0, 4_800);
}
