//! Governed closing-route and chart history through the public Book facade.

use fa::{Book, BookKeys, Entropy};
use fa_journal::{AccountSpec, BookSpec, UnitPolicy};
use fa_model::{AccountType, Id128, account_vid};
use fa_money::UnitRegistry;
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::VId;

const PRINCIPAL: VId = VId(148);

#[test]
fn closing_routes_and_account_names_share_the_explicit_authorized_prefix() {
    let units = UnitRegistry::embedded().unwrap();
    let usd = units.lookup("USD").unwrap();
    let book_id = Id128([148; 16]);
    let mut book = Book::create_memory(
        BookKeys::for_development(148),
        BookSpec {
            book_id,
            name: "Closing history".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("closing-history", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(148),
    )
    .unwrap();
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    let schema = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let account = |code: &str, kind: AccountType| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: 1,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    };
    book.install_chart(
        &[
            account("3000", AccountType::EQUITY),
            account("4000", AccountType::REVENUE),
        ],
        PRINCIPAL,
        day,
        b"closing-history-chart",
        &schema,
    )
    .unwrap()
    .unwrap();
    let nominal = account_vid(book_id, "4000");
    let equity = account_vid(book_id, "3000");
    let description = book.seal_text("Original closing route").unwrap();
    let original = book
        .set_closing_routes(
            fa::ClosingRoutesRequest {
                principal: PRINCIPAL,
                effective_from: day,
                routes: [(nominal, equity)].into(),
                idempotency_key: b"closing-history-route".to_vec(),
                description,
            },
            &schema,
        )
        .unwrap()
        .unwrap();
    let pin = original.recorded_at;
    let reader = Capability::embedded(PRINCIPAL, &["read"])
        .unwrap()
        .known_at_most(pin)
        .on_branch(Id128::TRUNK)
        .unwrap();
    assert_eq!(book.head().unwrap(), pin);
    let routes = book
        .closing_routes_at(day, Some(pin), &reader)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(routes.routes, [(nominal, equity)].into());
    assert_eq!(routes.digest, original.digest);
    let historical = book.accounts_at(pin, &reader).unwrap().unwrap();
    let names: Vec<_> = historical.iter().map(|row| row.code.as_str()).collect();
    assert_eq!(names, ["3000", "4000"]);
    let implicit = book
        .closing_routes_at(day, None, &reader)
        .unwrap()
        .unwrap_err();
    assert_eq!(implicit.code, "FA-REF-011");
    assert!(implicit.message.contains("known_at"));

    // A subsequently journaled account and revised map belong only to the
    // newer prefix. Neither names nor destinations can leak into the old one.
    book.open_account(
        &account("3001", AccountType::EQUITY),
        day,
        None,
        PRINCIPAL,
        day,
        b"later-closing-equity",
        &schema,
    )
    .unwrap()
    .unwrap();
    let later_equity = account_vid(book_id, "3001");
    let description = book.seal_text("Revised closing route").unwrap();
    book.set_closing_routes(
        fa::ClosingRoutesRequest {
            principal: PRINCIPAL,
            effective_from: day,
            routes: [(nominal, later_equity)].into(),
            idempotency_key: b"later-closing-route".to_vec(),
            description,
        },
        &schema,
    )
    .unwrap()
    .unwrap();
    let head = book.head().unwrap();
    assert!(head > pin);
    let retained = book
        .closing_routes_at(day, Some(pin), &reader)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(retained.routes, routes.routes);
    assert_eq!(retained.digest, routes.digest);
    let retained_accounts = book.accounts_at(pin, &reader).unwrap().unwrap();
    assert_eq!(
        retained_accounts
            .iter()
            .map(|row| row.code.as_str())
            .collect::<Vec<_>>(),
        names,
    );
    let current = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    assert_eq!(book.accounts_at(head, &current).unwrap().unwrap().len(), 3);
    assert_eq!(
        book.closing_routes_at(day, None, &current)
            .unwrap()
            .unwrap()
            .unwrap()
            .routes,
        [(nominal, later_equity)].into(),
    );
    assert_eq!(
        book.accounts_at(head, &reader).unwrap().unwrap_err().code,
        "FA-REF-011",
    );
    for at in [Some(head), None] {
        assert_eq!(
            book.closing_routes_at(day, at, &reader)
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011",
        );
    }
    assert_eq!(book.head().unwrap(), head);

    book.revoke_capability(
        Capability::embedded(PRINCIPAL, &["issue_capability"]).unwrap(),
        reader.commitment().unwrap(),
        day,
        b"revoke-closing-history-reader",
        "The historical reader is revoked",
    )
    .unwrap()
    .unwrap();
    let revoked_at = book.head().unwrap();
    assert_eq!(
        book.accounts_at(pin, &reader).unwrap().unwrap_err().code,
        "FA-REF-023",
    );
    assert_eq!(
        book.closing_routes_at(day, Some(pin), &reader)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023",
    );
    assert_eq!(book.head().unwrap(), revoked_at);
}
