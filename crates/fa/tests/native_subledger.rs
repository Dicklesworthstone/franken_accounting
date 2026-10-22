//! Native subledger definitions and direct-library read authority.

use fa::{Book, BookKeys, Entropy, NativeSubledgerKind, NativeSubledgerSpec};
use fa_journal::{AccountSpec, BookSpec, UnitPolicy};
use fa_model::{AccountType, Id128, account_vid};
use fa_money::UnitRegistry;
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::VId;

const PRINCIPAL: VId = VId(150);

fn setup() -> (Book, DateDay, Capability) {
    let units = UnitRegistry::embedded().unwrap();
    let usd = units.lookup("USD").unwrap();
    let mut book = Book::create_memory(
        BookKeys::for_development(150),
        BookSpec {
            book_id: Id128([150; 16]),
            name: "Native subledgers".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("native-subledger", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(150),
    )
    .unwrap();
    let date = DateDay::from_ymd(2026, 1, 1).unwrap();
    let capability = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let accounts = [
        ("1200", AccountType::ASSET, 0),
        ("2000", AccountType::LIABILITY, 1),
    ]
    .map(|(code, kind, normal_balance)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    });
    book.install_chart(&accounts, PRINCIPAL, date, b"chart", &capability)
        .unwrap()
        .unwrap();
    (book, date, capability)
}

#[test]
fn ar_and_ap_definitions_preserve_chart_history_and_reconcile_empty_control_leaves() {
    let (mut book, date, capability) = setup();
    let before = book.head().unwrap();
    for (code, kind, account) in [
        ("AR", NativeSubledgerKind::Receivables, "1200"),
        ("AP", NativeSubledgerKind::Payables, "2000"),
    ] {
        let spec = NativeSubledgerSpec {
            code: code.into(),
            name: code.into(),
            kind,
            control_account: account_vid(book.context().book_id, account),
        };
        let created = book
            .create_native_subledger(&spec, PRINCIPAL, date, code.as_bytes(), &capability)
            .unwrap()
            .unwrap();
        let chart = book
            .accounts_at(created.subledger.recorded_at, &capability)
            .unwrap()
            .unwrap();
        assert_eq!(
            chart
                .iter()
                .find(|row| row.code == account)
                .unwrap()
                .created_at,
            created.subledger.recorded_at
        );
        let report = book
            .reconcile_native_subledger(code, date, None, &capability)
            .unwrap()
            .unwrap();
        assert!(report.reconciled);
        assert!(report.rows.is_empty());
        assert!(report.totals.is_empty());
    }
    assert!(
        book.native_subledgers(Some(before), &capability)
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        book.accounts_at(before, &capability)
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    let all = book.native_subledgers(None, &capability).unwrap().unwrap();
    assert_eq!(
        all.iter()
            .map(|item| item.spec.code.as_str())
            .collect::<Vec<_>>(),
        ["AP", "AR"]
    );
}

#[test]
fn direct_library_reads_enforce_whole_book_and_explicit_known_at_bounds() {
    let (mut book, date, capability) = setup();
    let spec = NativeSubledgerSpec {
        code: "AR".into(),
        name: "Receivables".into(),
        kind: NativeSubledgerKind::Receivables,
        control_account: account_vid(book.context().book_id, "1200"),
    };
    let created = book
        .create_native_subledger(&spec, PRINCIPAL, date, b"ar", &capability)
        .unwrap()
        .unwrap();
    let pin = created.subledger.recorded_at;
    let scoped = Capability::embedded(PRINCIPAL, &["read"])
        .unwrap()
        .for_accounts(&["1200"])
        .unwrap();
    let head = book.head().unwrap();
    assert_eq!(
        book.native_subledgers(None, &scoped)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-011"
    );
    assert_eq!(
        book.reconcile_native_subledger("AR", date, None, &scoped)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-011"
    );
    let bounded = Capability::embedded(PRINCIPAL, &["read"])
        .unwrap()
        .known_at_most(pin)
        .on_branch(Id128::TRUNK)
        .unwrap();
    assert_eq!(
        book.native_subledgers(None, &bounded)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-011"
    );
    assert_eq!(
        book.native_subledgers(Some(pin), &bounded)
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert!(
        book.reconcile_native_subledger("AR", date, Some(pin), &bounded)
            .unwrap()
            .unwrap()
            .reconciled
    );
    assert_eq!(book.head().unwrap(), head);
}
