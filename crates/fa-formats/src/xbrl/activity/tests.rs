use super::*;
use crate::xbrl::{
    read_xbrl_instance_xml, verify_format_journal_xbrl_xml, write_format_journal_xbrl_xml,
    write_format_journal_xbrl_xml_with_activity, write_format_journal_xbrl_xml_with_equity,
    write_legacy_format_journal_xbrl_xml,
};
use crate::{FormatAccount, FormatEntry, FormatLeg};
use fa_model::EntryClass;
use fa_money::{Amount, Side, UnitRegistry};

fn fixture(
    revenue: i128,
    expense: i128,
    nci: i128,
    closed: bool,
) -> (FormatJournal, XbrlReportInputs) {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let day = DateDay::from_ymd(2026, 12, 31).unwrap();
    let accounts = [
        ("1000", AccountType::ASSET),
        ("3000", AccountType::EQUITY),
        ("3100", AccountType::EQUITY),
        ("4000", AccountType::REVENUE),
        ("5900", AccountType::EXPENSE),
        ("6000", AccountType::EXPENSE),
    ]
    .into_iter()
    .map(|(code, kind)| FormatAccount {
        code: code.into(),
        name: format!("Account {code}"),
        account_type: kind,
        normal_side: if matches!(kind, AccountType::ASSET | AccountType::EXPENSE) {
            Side::Debit
        } else {
            Side::Credit
        },

        roles: Vec::new(),
    })
    .collect();
    let leg = |account: &str, side, amount| FormatLeg {
        account_code: account.into(),
        side,
        amount: Amount::new(usd, amount),
        unit_code: "USD".into(),
        unit_scale: 2,
        memo: None,
    };
    let entry = |id: u64, class, legs| FormatEntry {
        entry_id: id.to_string(),
        effective_date: day,
        recorded_seq: id,
        class,
        description: format!("Activity {id}"),
        migrated_from: None,
        legs,
    };
    let mut entries = vec![
        entry(
            1,
            EntryClass::ORIGINAL,
            vec![
                leg("1000", Side::Debit, revenue),
                leg("4000", Side::Credit, revenue),
            ],
        ),
        entry(
            2,
            EntryClass::ORIGINAL,
            vec![
                leg("6000", Side::Debit, expense),
                leg("1000", Side::Credit, expense),
            ],
        ),
    ];
    if nci != 0 {
        let (debit, credit) = if nci > 0 {
            ("5900", "3100")
        } else {
            ("3100", "5900")
        };
        entries.push(entry(
            3,
            EntryClass::ORIGINAL,
            vec![
                leg(debit, Side::Debit, nci.checked_abs().unwrap()),
                leg(credit, Side::Credit, nci.checked_abs().unwrap()),
            ],
        ));
    }
    if closed {
        let mut closing = vec![
            leg("4000", Side::Debit, revenue),
            leg("6000", Side::Credit, expense),
        ];
        if nci != 0 {
            closing.push(leg(
                "5900",
                if nci > 0 { Side::Credit } else { Side::Debit },
                nci.checked_abs().unwrap(),
            ));
        }
        let parent = revenue
            .checked_sub(expense)
            .unwrap()
            .checked_sub(nci)
            .unwrap();
        if parent != 0 {
            closing.push(leg(
                "3000",
                if parent > 0 {
                    Side::Credit
                } else {
                    Side::Debit
                },
                parent.checked_abs().unwrap(),
            ));
        }
        entries.push(entry(4, EntryClass::CLOSING, closing));
    }
    let journal = FormatJournal::new(
        "Income activity",
        "USD",
        2,
        day,
        4,
        accounts,
        entries,
        vec![],
    )
    .unwrap();
    let inputs = XbrlReportInputs {
        equity: XbrlEquityAttribution {
            noncontrolling_accounts: BTreeSet::from(["3100".into()]),
        },
        noncontrolling_income_accounts: BTreeSet::from(["5900".into()]),
        known_at_seq: 4,
        effective_through: day,
        income_balances: BTreeMap::from([
            (
                ("4000".into(), "USD".into()),
                revenue.checked_neg().unwrap(),
            ),
            (("6000".into(), "USD".into()), expense),
            (("5900".into(), "USD".into()), nci),
        ]),
    };
    (journal, inputs)
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

#[test]
fn income_activity_survives_closing_and_separates_parent_and_noncontrolling_profit() {
    for (revenue, expense, nci) in [
        (10_000, 4_000, 1_200),
        (4_000, 10_000, -1_200),
        (10_000, 4_000, 0),
    ] {
        let group = revenue - expense;
        let parent = group - nci;
        for closed in [false, true] {
            let (journal, inputs) = fixture(revenue, expense, nci, closed);
            let xml = write_format_journal_xbrl_xml_with_activity(&journal, &inputs).unwrap();
            assert_eq!(fact(&xml, "us-gaap:Revenues"), revenue);
            assert_eq!(fact(&xml, "us-gaap:OperatingExpenses"), expense);
            assert_eq!(fact(&xml, "us-gaap:ProfitLoss"), group);
            assert_eq!(
                fact(
                    &xml,
                    "us-gaap:NetIncomeLossAttributableToNoncontrollingInterest"
                ),
                nci
            );
            assert_eq!(fact(&xml, "us-gaap:NetIncomeLoss"), parent);
            assert_eq!(fact(&xml, "us-gaap:StockholdersEquity"), parent);
            assert_eq!(fact(&xml, "us-gaap:MinorityInterest"), nci);
            assert_eq!(
                fact(
                    &xml,
                    "us-gaap:StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest"
                ),
                group
            );
            let (coordinate, report) = verify_format_journal_xbrl_xml(&xml).unwrap();
            assert_eq!(coordinate, journal.coordinate);
            assert_eq!(report.checks_passed, 4);
            assert_eq!(report.role_uri, INCOME_ROLE);
            let parsed = read_xbrl_income_attribution(&xml).unwrap().unwrap();
            assert_eq!(
                parsed.noncontrolling_income_accounts,
                inputs.noncontrolling_income_accounts
            );
            assert_eq!(parsed, inputs.attribution().unwrap());

            // Published older profiles keep their stock-based income bytes;
            // v2 must not silently change historical export reproduction.
            for old in [
                write_legacy_format_journal_xbrl_xml(&journal).unwrap(),
                write_format_journal_xbrl_xml_with_equity(&journal, &inputs.equity).unwrap(),
                write_format_journal_xbrl_xml(&journal).unwrap(),
            ] {
                assert!(read_xbrl_income_attribution(&old).unwrap().is_none());
                assert!(verify_format_journal_xbrl_xml(&old).is_ok());
                assert_eq!(
                    fact(&old, "us-gaap:NetIncomeLoss"),
                    if closed { 0 } else { parent }
                );
            }
        }
    }
}

#[test]
fn income_activity_checks_coordinate_chart_roles_units_and_integrity() {
    let (journal, inputs) = fixture(10_000, 4_000, 1_200, true);
    let xml = write_format_journal_xbrl_xml_with_activity(&journal, &inputs).unwrap();
    assert!(
        verify_format_journal_xbrl_xml(&xml.replace(INCOME_PROFILE, "closing-excluded-v999"))
            .is_err()
    );
    assert!(
        verify_format_journal_xbrl_xml(&xml.replace(
            "noncontrolling_income_accounts=\"35393030\"",
            "noncontrolling_income_accounts=\"36303030\"",
        ))
        .is_err()
    );
    let mut wrong = inputs.clone();
    wrong.known_at_seq += 1;
    assert!(write_format_journal_xbrl_xml_with_activity(&journal, &wrong).is_err());
    let mut wrong = inputs.clone();
    wrong.effective_through = DateDay(inputs.effective_through.0 - 1);
    assert!(write_format_journal_xbrl_xml_with_activity(&journal, &wrong).is_err());
    for code in ["3000", "9999"] {
        let mut wrong = inputs.clone();
        wrong.noncontrolling_income_accounts = BTreeSet::from([code.into()]);
        assert!(write_format_journal_xbrl_xml_with_activity(&journal, &wrong).is_err());
    }
    for (account, unit) in [("1000", "USD"), ("9999", "USD"), ("4000", "EUR")] {
        let mut wrong = inputs.clone();
        wrong
            .income_balances
            .insert((account.into(), unit.into()), 1);
        assert!(write_format_journal_xbrl_xml_with_activity(&journal, &wrong).is_err());
    }
    let mut overflow = inputs;
    overflow
        .income_balances
        .insert(("4000".into(), "USD".into()), i128::MIN);
    assert!(matches!(
        write_format_journal_xbrl_xml_with_activity(&journal, &overflow),
        Err(FormatError::Overflow { .. })
    ));
}
