//! Functional stock keeps prior-period carrying values, with independent
//! effective-date and recorded-history boundaries over real retained invoices.

#![forbid(unsafe_code)]

use fa::{Book, BookError, BookKeys, Entropy, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms};
use fa_journal::refusal::code;
use fa_journal::{AccountSpec, BookSpec, PostRequest, UnitPolicy, UploadRequest};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload,
    Oid, account_vid,
};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_policy::Capability;
use fa_registers::{FunctionalStockFold, RegisterError};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(1);

fn day(month: u8, day: u8) -> DateDay {
    DateDay::from_ymd(2026, month, day).unwrap()
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Fixture {
    book: Book,
    usd: UnitId,
    eur: UnitId,
    invoice: EvidenceRef,
}

impl Fixture {
    fn new() -> Self {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let mut book = Book::create_memory(
            BookKeys::for_development(0xe4),
            BookSpec {
                book_id: Id128([0xe4; 16]),
                name: "Cumulative functional stock".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("fx-stock", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(228),
        )
        .unwrap();
        let accounts: Vec<_> = [("1200", AccountType::ASSET), ("4000", AccountType::REVENUE)]
            .into_iter()
            .map(|(code, kind)| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: kind.0,
                normal_balance: u8::from(kind == AccountType::REVENUE),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect();
        book.install_chart(
            &accounts,
            PRINCIPAL,
            day(1, 1),
            b"fx-stock-chart",
            &cap(&["schema_change"]),
        )
        .unwrap()
        .unwrap();
        book.create_periods(2026, PRINCIPAL, &cap(&["schema_change"]))
            .unwrap()
            .unwrap();
        for period in ["FY2026-P01", "FY2026-P02"] {
            book.transition_period(
                period,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                period.as_bytes(),
                &cap(&["close"]),
            )
            .unwrap()
            .unwrap();
        }
        let invoice = book
            .upload_document(
                &cap(&["post"]),
                UploadRequest {
                    kind: EvidencePolicy::embedded()
                        .unwrap()
                        .kind_by_name("Invoice")
                        .unwrap()
                        .tag,
                    mime: "text/plain".into(),
                    bytes: b"Retained invoices across January and February 2026".to_vec(),
                    asserted_grade: None,
                },
            )
            .unwrap()
            .unwrap();
        Self {
            book,
            usd,
            eur,
            invoice: EvidenceRef {
                document_oid: invoice.oid,
                doc_commit: invoice.doc_commit,
                role: 1,
            },
        }
    }

    fn proposal(&self, key: &[u8], effective: DateDay, cents: i128) -> EntryPayload {
        let book_id = self.book.context().book_id;
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "1200"),
                Amount::new(self.eur, cents),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "4000"),
                Amount::new(self.eur, cents),
            ),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: effective,
            document_date: None,
            description: self.book.seal_text("Carried foreign invoice").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: self.invoice.document_oid,
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.invoice],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn rate(&mut self, effective: DateDay, numerator: u128, source: &str) -> Oid {
        let divisor = [10, 5, 2, 1]
            .into_iter()
            .find(|divisor| numerator % *divisor == 0)
            .unwrap();
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: numerator / divisor,
                rate_den: 10 / divisor,
                rounding: RoundingLaw::HalfEven,
            },
            effective,
            1_767_571_200_000_000_000,
            FxRatePurpose::SpotClose,
            source,
        )
        .unwrap();
        self.book
            .upload_fx_rate(&cap(&["post"]), &rate)
            .unwrap()
            .unwrap()
            .oid
    }

    fn post(&mut self, key: &[u8], effective: DateDay, cents: i128, numerator: u128) -> EntryRef {
        let rate = self.rate(effective, numerator, "Original carrying-value evidence");
        let proposal = self.proposal(key, effective, cents);
        let valued = self
            .book
            .value_fx_proposal(
                &cap(&["read", "post"]),
                proposal,
                FxLawId::SpotClose,
                &[rate],
            )
            .unwrap()
            .unwrap();
        self.book
            .post(request(valued))
            .unwrap()
            .unwrap()
            .entry_ref()
    }

    fn stock(&mut self, effective: DateDay, known_at: Option<CommitSeq>) -> FunctionalStockFold {
        let before = self.book.head().unwrap();
        let stock = self
            .book
            .functional_balance_as_of(&cap(&["read"]), effective, known_at)
            .unwrap()
            .unwrap();
        assert_eq!(self.book.head().unwrap(), before);
        stock
    }
}

fn request(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: Vec::new(),
        capability: cap(&["post"]),
        plan_certificate: None,
    }
}

#[test]
fn stock_carries_earlier_periods_and_keeps_effective_and_recorded_boundaries_separate() {
    let mut f = Fixture::new();
    let first = f.post(b"january", day(1, 5), 10_000, 11);
    let original = f.book.read_entry(first.vid).unwrap().unwrap();
    let first_pin = f.book.head().unwrap();
    let january = f.stock(day(1, 31), Some(first_pin));
    assert_eq!(january.entries, 1);
    assert_eq!(january.total_debits().unwrap(), 11_000);
    assert_eq!(january.total_credits().unwrap(), 11_000);
    assert_eq!(january.watermark, Some(first_pin));
    assert!(f.stock(day(1, 4), None).cells.is_empty());
    assert_eq!(f.stock(day(1, 5), None).total_debits().unwrap(), 11_000);

    f.post(b"february", day(2, 5), 5_000, 12);
    let two_invoice_pin = f.book.head().unwrap();
    let carried = f.stock(day(2, 28), Some(two_invoice_pin));
    assert_eq!(carried.total_debits().unwrap(), 17_000);
    assert_eq!(carried.total_credits().unwrap(), 17_000);
    assert_eq!(carried.entries, 2);
    let activity = f
        .book
        .functional_period_activity(&cap(&["read"]), "FY2026-P02", None)
        .unwrap()
        .unwrap();
    assert_eq!(activity.total_debits().unwrap(), 6_000);
    assert_eq!(activity.entries, 1);
    assert_eq!(f.stock(day(1, 31), None).total_debits().unwrap(), 11_000);

    // A later publication effective in January affects current January stock,
    // but cannot enter a report pinned before that publication.
    f.post(b"late-january", day(1, 20), 2_000, 13);
    assert_eq!(f.stock(day(1, 31), None).total_debits().unwrap(), 13_600);
    assert_eq!(f.stock(day(1, 31), Some(first_pin)), january);
    assert_eq!(f.stock(day(2, 28), Some(two_invoice_pin)), carried);
    let current = f.stock(day(2, 28), None);
    assert_eq!(current.total_debits().unwrap(), 19_600);
    assert_eq!(current.total_credits().unwrap(), 19_600);
    assert_eq!(current.entries, 3);
    assert_eq!(current.effective_through, day(2, 28));
    assert_eq!(current.base_unit, f.usd);
    assert!(current.pending.is_empty());
    let receivable = current
        .cells
        .iter()
        .find(|cell| cell.key.account == account_vid(f.book.context().book_id, "1200"))
        .unwrap();
    assert_eq!((receivable.debits, receivable.credits), (19_600, 0));
    assert_eq!(receivable.net(), Some(19_600));
    assert_eq!(receivable.entry_count, 3);
    let native = f.book.balance_as_of(day(2, 28), None).unwrap();
    assert_eq!(native.unit_totals.get(&f.eur.0), Some(&(17_000, 17_000)));

    // Merely retaining a newer quote for the same source date cannot revalue
    // any old entry or replace its original source evidence.
    f.rate(
        day(1, 5),
        90,
        "Later alternative quote, not a revaluation posting",
    );
    let unchanged = f.stock(day(2, 28), None);
    assert_eq!(unchanged.cells, current.cells);
    assert_eq!(unchanged.pending, current.pending);
    assert_eq!(unchanged.entries, current.entries);
    assert_eq!(f.book.read_entry(first.vid).unwrap().unwrap(), original);
}

#[test]
fn unvalued_foreign_entries_refuse_only_when_their_effective_and_known_prefixes_are_selected() {
    let mut f = Fixture::new();
    f.post(b"valued-january", day(1, 5), 10_000, 11);
    let pin = f.book.head().unwrap();
    let unvalued = f.proposal(b"unvalued-february", day(2, 5), 5_000);
    f.book.post(request(unvalued)).unwrap().unwrap();
    let head = f.book.head().unwrap();
    assert_eq!(f.stock(day(1, 31), None).total_debits().unwrap(), 11_000);
    assert_eq!(
        f.stock(day(2, 28), Some(pin)).total_debits().unwrap(),
        11_000
    );
    assert!(matches!(
        f.book
            .functional_balance_as_of(&cap(&["read"]), day(2, 28), None),
        Err(BookError::Registers(RegisterError::ProjectionDrift(_)))
    ));
    assert_eq!(f.book.head().unwrap(), head);
}

#[test]
fn fixed_prefix_stock_still_requires_current_whole_book_authority() {
    let mut f = Fixture::new();
    f.post(b"authorized-january", day(1, 5), 10_000, 11);
    let pin = f.book.head().unwrap();
    let historical = f.stock(day(2, 28), Some(pin));
    let limited = cap(&["read"]).known_at_most(pin);
    f.rate(
        day(1, 5),
        12,
        "Later rate advances current authority sequence",
    );
    let head = f.book.head().unwrap();
    assert_eq!(
        f.book
            .functional_balance_as_of(&limited, day(2, 28), Some(pin))
            .unwrap()
            .unwrap(),
        historical
    );
    assert_eq!(
        f.book
            .functional_balance_as_of(&limited, day(2, 28), None)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    for denied in [
        cap(&["post"]),
        cap(&["read"]).for_accounts(&["1200"]).unwrap(),
        cap(&["read"]).for_books(&[Id128([0x7a; 16])]).unwrap(),
        cap(&["read"]).expiring_at(head),
    ] {
        let refusal = f
            .book
            .functional_balance_as_of(&denied, day(2, 28), Some(pin))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, 7);
        assert_eq!(f.book.head().unwrap(), head);
    }
    let future = CommitSeq(head.0.checked_add(1).unwrap());
    assert_eq!(
        f.book
            .functional_balance_as_of(&cap(&["read"]), day(2, 28), Some(future))
            .unwrap()
            .unwrap_err()
            .code,
        code::STRUCTURE
    );
    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            limited.commitment().unwrap(),
            day(2, 5),
            b"revoke-fx-stock-reader",
            "Revoke historical functional stock access",
        )
        .unwrap()
        .unwrap();
    let revoked_head = f.book.head().unwrap();
    assert_eq!(
        f.book
            .functional_balance_as_of(&limited, day(2, 28), Some(pin))
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
    assert_eq!(f.book.head().unwrap(), revoked_head);
}

fn statement_selection(name: &str, comparative: bool) -> fa::StatementSelection {
    fa::StatementSelection {
        definition: fa::StatementDefinition::embedded(name).unwrap(),
        periods: vec!["FY2026-P02".into()],
        comparative: if comparative {
            vec!["FY2026-P01".into()]
        } else {
            Vec::new()
        },
    }
}

fn statement_amounts<'a>(statement: &'a fa::Statement, code: &str, unit: UnitId) -> &'a [i128] {
    &statement
        .lines
        .iter()
        .find(|line| line.code == code && line.unit_id == unit.0)
        .unwrap_or_else(|| panic!("missing {code}/{}: {statement:?}", unit.0))
        .amounts
}

#[test]
fn functional_statements_combine_retained_rates_and_replay_comparatives_after_backdates() {
    let mut f = Fixture::new();
    f.post(b"statement-january", day(1, 5), 10_000, 11);
    f.post(b"statement-february", day(2, 5), 20_000, 12);
    let pin = f.book.head().unwrap();
    let balance_selection = statement_selection("balance-sheet", true);
    let native = f
        .book
        .statement(balance_selection.clone(), Some(pin))
        .unwrap()
        .unwrap();
    assert_eq!(
        statement_amounts(&native, "assets", f.eur),
        &[30_000, 10_000]
    );
    assert_eq!(statement_amounts(&native, "assets", f.usd), &[0, 0]);
    let balance = f
        .book
        .functional_statement(
            PRINCIPAL,
            &cap(&["read"]),
            balance_selection.clone(),
            Some(pin),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        statement_amounts(&balance, "assets", f.usd),
        &[35_000, 11_000]
    );
    assert_eq!(
        statement_amounts(&balance, "total_equity", f.usd),
        &[35_000, 11_000]
    );
    assert_eq!(statement_amounts(&balance, "balance_check", f.usd), &[0, 0]);
    assert!(balance.lines.iter().all(|line| line.unit_id == f.usd.0));
    assert_eq!(balance.mappings.len(), 2);
    assert_eq!(
        f.book.head().unwrap(),
        pin,
        "report must not publish a conversion"
    );

    let income_selection = statement_selection("income-statement", true);
    let income = f
        .book
        .certify_functional_statement(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            income_selection.clone(),
            Some(pin),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        statement_amounts(&income.statement, "net_income", f.usd),
        &[24_000, 11_000]
    );
    assert!(matches!(
        income.certificate.selection,
        fa::ReportSelection::FunctionalStatement(_)
    ));
    let bytes = income.certificate.canonical_bytes().unwrap();
    let saved = fa::ReportCertificate::decode(&bytes).unwrap();
    assert_eq!(saved, income.certificate);
    let native_income = f
        .book
        .certify_statement(income_selection.clone(), Some(pin))
        .unwrap()
        .unwrap();
    assert_ne!(native_income.certificate.digest, saved.digest);
    assert_ne!(native_income.certificate.output, saved.output);
    let replay = f.book.replay_report(&saved).unwrap().unwrap();
    assert_eq!(
        replay,
        fa::ReportOutput::FunctionalStatement(Box::new(income.statement.clone()))
    );
    assert_eq!(replay.canonical_bytes().unwrap(), saved.output);
    assert_eq!(
        f.book.head().unwrap(),
        pin,
        "constructing a certificate is read-only"
    );

    // A new quote is evidence, not permission to revalue old entries.
    f.rate(day(1, 5), 90, "Unselected newer quote for statement test");
    assert!(matches!(
        f.book.certificate_status(&saved).unwrap().unwrap(),
        fa::CertificateStatus::Current { .. }
    ));
    let unchanged = f
        .book
        .functional_statement(PRINCIPAL, &cap(&["read"]), balance_selection.clone(), None)
        .unwrap()
        .unwrap();
    assert_eq!(
        statement_amounts(&unchanged, "assets", f.usd),
        &[35_000, 11_000]
    );

    let later = f.post(b"statement-backdate", day(1, 20), 1_000, 13);
    assert!(
        matches!(f.book.certificate_status(&saved).unwrap().unwrap(),
        fa::CertificateStatus::SupersededBy { later_entries, .. } if later_entries.contains(&later.vid))
    );
    assert_eq!(f.book.replay_report(&saved).unwrap().unwrap(), replay);
    let historical = f
        .book
        .functional_statement(
            PRINCIPAL,
            &cap(&["read"]),
            balance_selection.clone(),
            Some(pin),
        )
        .unwrap()
        .unwrap();
    assert_eq!(historical, balance);
    let current = f
        .book
        .functional_statement(PRINCIPAL, &cap(&["read"]), balance_selection, None)
        .unwrap()
        .unwrap();
    assert_eq!(
        statement_amounts(&current, "assets", f.usd),
        &[36_300, 12_300]
    );
    let current_income = f
        .book
        .functional_statement(PRINCIPAL, &cap(&["read"]), income_selection, None)
        .unwrap()
        .unwrap();
    assert_eq!(
        statement_amounts(&current_income, "net_income", f.usd),
        &[24_000, 12_300]
    );
}

#[test]
fn functional_statement_scope_and_produce_authority_precede_historical_reads() {
    let mut f = Fixture::new();
    f.post(b"statement-authority", day(1, 5), 10_000, 11);
    let pin = f.book.head().unwrap();
    let selection = statement_selection("balance-sheet", true);
    let expected = f
        .book
        .functional_statement(PRINCIPAL, &cap(&["read"]), selection.clone(), Some(pin))
        .unwrap()
        .unwrap();
    let limited = cap(&["read"]).known_at_most(pin);
    f.rate(day(1, 5), 12, "Advance authority frontier");
    assert_eq!(
        f.book
            .functional_statement(PRINCIPAL, &limited, selection.clone(), Some(pin))
            .unwrap()
            .unwrap(),
        expected
    );
    let head = f.book.head().unwrap();
    for denied in [
        cap(&["post"]),
        cap(&["read"]).for_accounts(&["1200"]).unwrap(),
        cap(&["read"]).for_books(&[Id128([0x7b; 16])]).unwrap(),
        cap(&["read"]).expiring_at(head),
    ] {
        assert_eq!(
            f.book
                .functional_statement(PRINCIPAL, &denied, selection.clone(), Some(pin))
                .unwrap()
                .unwrap_err()
                .exit,
            7
        );
    }
    assert_eq!(
        f.book
            .functional_statement(VId(2), &cap(&["read"]), selection.clone(), Some(pin))
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    assert_eq!(
        f.book
            .certify_functional_statement(PRINCIPAL, &cap(&["read"]), selection.clone(), Some(pin))
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    assert_eq!(f.book.head().unwrap(), head);
    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            limited.commitment().unwrap(),
            day(2, 5),
            b"revoke-functional-statement",
            "Historical statements do not resurrect revoked authority",
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        f.book
            .functional_statement(PRINCIPAL, &limited, selection, Some(pin))
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
}

#[test]
fn functional_statement_refuses_unvalued_foreign_contributions_at_the_selected_prefix() {
    let mut f = Fixture::new();
    f.post(b"statement-valued", day(1, 5), 10_000, 11);
    let pin = f.book.head().unwrap();
    let unvalued = f.proposal(b"statement-unvalued", day(2, 5), 5_000);
    f.book.post(request(unvalued)).unwrap().unwrap();
    let head = f.book.head().unwrap();
    let selection = statement_selection("balance-sheet", true);
    let historical = f
        .book
        .functional_statement(PRINCIPAL, &cap(&["read"]), selection.clone(), Some(pin))
        .unwrap()
        .unwrap();
    assert_eq!(
        statement_amounts(&historical, "assets", f.usd),
        &[11_000, 11_000]
    );
    assert!(matches!(
        f.book
            .functional_statement(PRINCIPAL, &cap(&["read"]), selection, None),
        Err(BookError::Registers(RegisterError::ProjectionDrift(_)))
    ));
    assert_eq!(f.book.head().unwrap(), head);
}

#[path = "fx_stock/portable.rs"]
mod portable;
