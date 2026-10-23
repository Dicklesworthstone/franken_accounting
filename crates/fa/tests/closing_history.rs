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

fn carrying_proposal(
    book: &Book,
    key: &[u8],
    class: fa_model::EntryClass,
    legs: Vec<fa_model::LegPayload>,
    evidence: fa_model::EvidenceRef,
) -> fa_model::EntryPayload {
    fa_model::EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.context().book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date: DateDay::from_ymd(2026, 12, 30).unwrap(),
        document_date: None,
        description: book
            .seal_text("Retained carrying-value closing fixture")
            .unwrap(),
        effective_period: None,
        unit_totals: fa_model::EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: fa_model::EntryOrigin::Intent {
            intent_oid: evidence.document_oid,
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![evidence],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

fn carrying_post(
    book: &mut Book,
    key: &[u8],
    debit_nominal: bool,
    native: i128,
    numerator: u128,
    evidence: fa_model::EvidenceRef,
) {
    let usd = book.context().units.lookup("USD").unwrap();
    let eur = book.context().units.lookup("EUR").unwrap();
    let rate = fa::FxRateDocument::new(
        fa::FxRateTerms {
            base_unit: usd,
            quote_unit: eur,
            rate_num: numerator,
            rate_den: 10,
            rounding: fa_money::RoundingLaw::HalfEven,
        },
        DateDay::from_ymd(2026, 12, 30).unwrap(),
        1_767_571_200_000_000_000,
        fa::FxRatePurpose::SpotClose,
        std::str::from_utf8(key).unwrap(),
    )
    .unwrap();
    let capability = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
    let rate_oid = book
        .upload_fx_rate(&capability, &rate)
        .unwrap()
        .unwrap()
        .oid;
    let (debit, credit) = if debit_nominal {
        ("4000", "1000")
    } else {
        ("1000", "4000")
    };
    let legs = [
        (fa_money::Side::Debit, debit),
        (fa_money::Side::Credit, credit),
    ]
    .into_iter()
    .map(|(side, code)| {
        fa_model::LegPayload::simple(
            side,
            account_vid(book.context().book_id, code),
            fa_money::Amount::new(eur, native),
        )
    })
    .collect();
    let proposal = carrying_proposal(book, key, fa_model::EntryClass::ORIGINAL, legs, evidence);
    let valued = book
        .value_fx_proposal(&capability, proposal, fa::FxLawId::SpotClose, &[rate_oid])
        .unwrap()
        .unwrap();
    book.post(fa_journal::PostRequest {
        proposal: valued,
        approvals: Vec::new(),
        capability,
        plan_certificate: None,
    })
    .unwrap()
    .unwrap();
}

#[test]
fn carrying_close_facade_preserves_zero_native_loss_and_historical_functional_certificate() {
    let units = UnitRegistry::embedded().unwrap();
    let usd = units.lookup("USD").unwrap();
    let book_id = Id128([149; 16]);
    let mut book = Book::create_memory(
        BookKeys::for_development(149),
        BookSpec {
            book_id,
            name: "Retained carrying close".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("carrying-close", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(149),
    )
    .unwrap();
    let cap = |ops: &[&str]| Capability::embedded(PRINCIPAL, ops).unwrap();
    let schema = cap(&["read", "schema_change"]);
    let first_day = DateDay::from_ymd(2026, 1, 1).unwrap();
    let accounts: Vec<_> = [
        ("1000", AccountType::ASSET),
        ("3000", AccountType::EQUITY),
        ("4000", AccountType::REVENUE),
    ]
    .into_iter()
    .map(|(code, kind)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: u8::from(kind != AccountType::ASSET),
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    })
    .collect();
    book.install_chart(
        &accounts,
        PRINCIPAL,
        first_day,
        b"carrying-close-chart",
        &schema,
    )
    .unwrap()
    .unwrap();
    book.create_periods(2026, PRINCIPAL, &schema)
        .unwrap()
        .unwrap();
    for period in ["FY2026-P12", "FY2026-CLOSE"] {
        book.transition_period(
            period,
            fa_time::PeriodTransition::Open,
            PRINCIPAL,
            1,
            period.as_bytes(),
            &cap(&["close"]),
        )
        .unwrap()
        .unwrap();
    }
    let description = book.seal_text("Reviewed retained earnings route").unwrap();
    book.set_closing_routes(
        fa::ClosingRoutesRequest {
            principal: PRINCIPAL,
            effective_from: first_day,
            routes: [(account_vid(book_id, "4000"), account_vid(book_id, "3000"))].into(),
            idempotency_key: b"carrying-close-routes".to_vec(),
            description,
        },
        &schema,
    )
    .unwrap()
    .unwrap();
    let workpaper = book
        .upload_document(
            &cap(&["post"]),
            fa_journal::UploadRequest {
                kind: fa_registry::evidence_policy::EvidencePolicy::embedded()
                    .unwrap()
                    .kind_by_name("Workpaper")
                    .unwrap()
                    .tag,
                mime: "text/plain".into(),
                bytes: b"Reviewed source transactions and exact closing computation".to_vec(),
                asserted_grade: None,
            },
        )
        .unwrap()
        .unwrap();
    let evidence = fa_model::EvidenceRef {
        document_oid: workpaper.oid,
        doc_commit: workpaper.doc_commit,
        role: 1,
    };
    carrying_post(&mut book, b"native-credit", false, 10_000, 11, evidence);
    carrying_post(&mut book, b"native-debit", true, 10_000, 12, evidence);
    let request = fa::YearEndCloseRequest {
        fiscal_year: 2026,
        closing_period: "FY2026-CLOSE".into(),
    };
    let closing = cap(&["read", "post", "close"]);
    let before = book.head().unwrap();
    for denied in [
        cap(&["read"]),
        closing.clone().for_accounts(&["4000"]).unwrap(),
        closing.clone().known_at_most(before),
    ] {
        assert_eq!(
            book.prepare_year_end_close(&request, &denied)
                .unwrap()
                .unwrap_err()
                .exit,
            7
        );
    }
    assert_eq!(book.head().unwrap(), before);
    let prepared = book
        .prepare_year_end_close(&request, &closing)
        .unwrap()
        .unwrap();
    assert!(
        !prepared.is_noop(),
        "zero native amounts cannot erase a retained functional loss"
    );
    assert_eq!(prepared.residuals().len(), 1);
    assert_eq!(
        (
            prepared.residuals()[0].net,
            prepared.residuals()[0].base_net
        ),
        (0, 1_000)
    );
    let mut template = carrying_proposal(
        &book,
        b"carrying-first-close",
        fa_model::EntryClass::CLOSING,
        Vec::new(),
        evidence,
    );
    template.effective_date = prepared.closing_date();
    template.effective_period = Some(fa_model::PeriodRef {
        calendar: book.context().calendar.id.clone(),
        code: request.closing_period.clone(),
    });
    let intent = fa::PostIntent::new(prepared.proposal(template).unwrap(), Vec::new()).unwrap();
    let plan = book.plan(intent, &closing).unwrap().unwrap();
    book.commit_plan(plan, &closing).unwrap().unwrap();
    let closed_at = book.head().unwrap();
    let reader = cap(&["read"]);
    let verified = book
        .verify_year_end_close(2026, None, &reader)
        .unwrap()
        .unwrap();
    assert!(verified.is_green() && !verified.needs_reclose);
    assert_eq!(verified.base_unit, usd);
    assert!(
        verified
            .residuals
            .iter()
            .all(|row| row.net == 0 && row.base_net == 0)
    );
    let selection = fa::StatementSelection {
        definition: fa::StatementDefinition::embedded("income-statement").unwrap(),
        periods: vec!["FY2026-P12".into(), "FY2026-CLOSE".into()],
        comparative: Vec::new(),
    };
    let certified = book
        .certify_functional_statement(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            selection.clone(),
            None,
        )
        .unwrap()
        .unwrap();
    let net_income = |statement: &fa::Statement| {
        statement
            .lines
            .iter()
            .find(|line| line.code == "net_income" && line.unit_id == usd.0)
            .unwrap()
            .amounts[0]
    };
    assert_eq!(net_income(&certified.statement), -1_000);
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let retained = fa::ReportCertificate::decode(&bytes).unwrap();

    carrying_post(&mut book, b"later-valued-sale", false, 1_000, 13, evidence);
    let bounded = reader.clone().known_at_most(closed_at);
    let historical = book
        .verify_year_end_close(2026, Some(closed_at), &bounded)
        .unwrap()
        .unwrap();
    assert!(historical.is_green() && !historical.needs_reclose);
    assert_eq!(
        book.verify_year_end_close(2026, None, &bounded)
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    assert!(
        book.verify_year_end_close(2026, None, &reader)
            .unwrap()
            .unwrap()
            .needs_reclose
    );
    let delta = book
        .prepare_year_end_close(&request, &closing)
        .unwrap()
        .unwrap();
    assert_eq!(
        (delta.residuals()[0].net, delta.residuals()[0].base_net),
        (-1_000, -1_300)
    );
    assert_eq!(delta.legs().len(), 2);
    let current = book
        .functional_statement(PRINCIPAL, &reader, selection, None)
        .unwrap()
        .unwrap();
    assert_eq!(net_income(&current), 300);
    assert_eq!(
        book.replay_report(&retained).unwrap().unwrap(),
        fa::ReportOutput::FunctionalStatement(Box::new(certified.statement))
    );
}
