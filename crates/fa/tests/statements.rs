//! End-to-end statement regressions through the public facade and its real
//! memory and directory books. Every monetary input is admitted by the posting kernel.

use std::path::Path;

use fa::{
    Book, BookKeys, CertificateStatus, Entropy, ReportCertificate, ReportOutput, Statement,
    StatementDefinition, StatementSelection,
};
use fa_journal::{AccountSpec, BookSpec, Capability, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{
    AccountType, Disposition, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128,
    LegPayload, Oid, Pending, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const PRINCIPAL: VId = VId(1);
const DECEMBER: &str = "FY2025-P12";
const JANUARY: &str = "FY2026-P01";
const FEBRUARY: &str = "FY2026-P02";
const MARCH: &str = "FY2026-P03";

fn day(year: i32, month: u8, day: u8) -> DateDay {
    DateDay::from_ymd(year, month, day).unwrap()
}

fn account(code: &str, name: &str, account_type: AccountType) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type: account_type.0,
        normal_balance: u8::from(matches!(
            account_type,
            AccountType::LIABILITY | AccountType::EQUITY | AccountType::REVENUE
        )),
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    }
}

struct Fixture {
    book: Book,
    usd: UnitId,
    jpy: UnitId,
    evidence: Vec<EvidenceRef>,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        Self::at(seed, None)
    }

    fn at(seed: u8, directory: Option<&Path>) -> Self {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let jpy = units.lookup("JPY").unwrap();
        let book_id = Id128([seed; 16]);
        let spec = BookSpec {
            book_id,
            name: "Statement integration fixture".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("statement-calendar", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let keys = BookKeys::for_development(seed);
        let entropy = Entropy::deterministic(u64::from(seed));
        let mut book = match directory {
            Some(directory) => Book::create_dir(directory, keys, spec, entropy),
            None => Book::create_memory(keys, spec, entropy),
        }
        .unwrap();
        book.install_chart(
            &[
                account("1000", "Cash", AccountType::ASSET),
                account("2000", "Borrowings", AccountType::LIABILITY),
                account("3000", "Capital", AccountType::EQUITY),
                account("4000", "Revenue", AccountType::REVENUE),
                account("6000", "Operating expense", AccountType::EXPENSE),
                account("6100", "Unused expense", AccountType::EXPENSE),
            ],
            PRINCIPAL,
            day(2025, 12, 1),
            b"statement-chart",
            &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
        let schema =
            fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap();
        book.create_periods(2025, schema.holder(), &schema)
            .unwrap()
            .unwrap();
        book.create_periods(2026, schema.holder(), &schema)
            .unwrap()
            .unwrap();
        let close = Capability::embedded(PRINCIPAL, &["close"]).unwrap();
        for period in [DECEMBER, JANUARY, FEBRUARY, MARCH] {
            book.transition_period(
                period,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                period.as_bytes(),
                &close,
            )
            .unwrap()
            .unwrap();
        }
        let source = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Source evidence for admitted statement integration postings".to_vec(),
        };
        book.add_document(&source).unwrap().unwrap();
        Self {
            book,
            usd,
            jpy,
            evidence: vec![source.evidence_ref(1)],
        }
    }

    fn legs(&self, unit: UnitId, accounts: (&str, &str), amount: i128) -> Vec<LegPayload> {
        let book_id = self.book.context().book_id;
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, accounts.0),
                Amount::new(unit, amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, accounts.1),
                Amount::new(unit, amount),
            ),
        ]
    }

    fn proposal(
        &self,
        date: DateDay,
        key: &[u8],
        class: EntryClass,
        legs: Vec<LegPayload>,
    ) -> EntryPayload {
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: date,
            document_date: None,
            description: self.book.seal_text("Statement fixture posting").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0x53; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn commit(&mut self, proposal: EntryPayload) -> Posted {
        self.book
            .post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            })
            .unwrap()
            .unwrap()
    }

    fn transfer(
        &mut self,
        date: DateDay,
        key: &[u8],
        unit: UnitId,
        accounts: (&str, &str),
        amount: i128,
    ) -> Posted {
        let proposal = self.proposal(
            date,
            key,
            EntryClass::ORIGINAL,
            self.legs(unit, accounts, amount),
        );
        self.commit(proposal)
    }
}

fn selection(name: &str, current: &str, comparative: &str) -> StatementSelection {
    StatementSelection {
        definition: StatementDefinition::embedded(name).unwrap(),
        periods: vec![current.into()],
        comparative: vec![comparative.into()],
    }
}

fn amounts<'a>(statement: &'a Statement, line: &str, unit: UnitId) -> &'a [i128] {
    &statement
        .lines
        .iter()
        .find(|row| row.code == line && row.unit_id == unit.0)
        .unwrap_or_else(|| panic!("missing statement line `{line}` in unit {}", unit.0))
        .amounts
}

fn replay(book: &Book, certificate: &ReportCertificate) -> Statement {
    let output = book.replay_report(certificate).unwrap().unwrap();
    assert_eq!(output.canonical_bytes().unwrap(), certificate.output);
    match output {
        ReportOutput::Statement(statement) => *statement,
        other => panic!("statement certificate selected another report: {other:?}"),
    }
}

#[test]
fn historical_stock_carries_prior_year_earnings_while_income_selects_period_activity() {
    let mut fixture = Fixture::new(0x91);
    let (usd, jpy) = (fixture.usd, fixture.jpy);
    for (key, accounts, amount) in [
        (b"dec-capital".as_slice(), ("1000", "3000"), 1_000),
        (b"dec-loan".as_slice(), ("1000", "2000"), 250),
        (b"dec-revenue".as_slice(), ("1000", "4000"), 400),
        (b"dec-expense".as_slice(), ("6000", "1000"), 100),
    ] {
        fixture.transfer(day(2025, 12, 15), key, usd, accounts, amount);
    }
    fixture.transfer(
        day(2025, 12, 15),
        b"jpy-capital",
        jpy,
        ("1000", "3000"),
        9_000,
    );
    for (key, unit, accounts, amount) in [
        (b"jan-revenue".as_slice(), usd, ("1000", "4000"), 200),
        (b"jan-expense".as_slice(), usd, ("6000", "1000"), 50),
        (b"jpy-revenue".as_slice(), jpy, ("1000", "4000"), 700),
        (b"jpy-expense".as_slice(), jpy, ("6000", "1000"), 300),
    ] {
        fixture.transfer(day(2026, 1, 15), key, unit, accounts, amount);
    }
    let at = fixture.book.head().unwrap();
    let stock = fixture
        .book
        .statement(selection("balance-sheet", JANUARY, DECEMBER), Some(at))
        .unwrap()
        .unwrap();
    let income = fixture
        .book
        .statement(selection("income-statement", JANUARY, DECEMBER), Some(at))
        .unwrap()
        .unwrap();

    assert_eq!(stock.known_at, at.0);
    assert_eq!(income.known_at, at.0);
    assert_eq!(
        fixture.book.head().unwrap(),
        at,
        "statement reads append nothing"
    );
    for statement in [&stock, &income] {
        assert_eq!(statement.columns.len(), 2);
        assert_eq!(statement.columns[0].label, "current");
        assert_eq!(statement.columns[1].label, "comparative");
        assert_eq!(statement.columns[0].periods, vec![JANUARY.to_string()]);
        assert_eq!(statement.columns[1].periods, vec![DECEMBER.to_string()]);
        assert_eq!(statement.columns[0].effective_through, day(2026, 1, 31));
        assert_eq!(statement.columns[1].effective_through, day(2025, 12, 31));
    }
    assert!(
        stock
            .columns
            .iter()
            .all(|column| column.effective_from.is_none())
    );
    assert_eq!(income.columns[0].effective_from, Some(day(2026, 1, 1)));
    assert_eq!(income.columns[1].effective_from, Some(day(2025, 12, 1)));
    assert_eq!(amounts(&stock, "assets", usd), [1_700, 1_550]);
    assert_eq!(amounts(&stock, "liabilities", usd), [250, 250]);
    assert_eq!(amounts(&stock, "equity", usd), [1_000, 1_000]);
    assert_eq!(amounts(&stock, "unclosed_earnings", usd), [450, 300]);
    assert_eq!(amounts(&stock, "total_equity", usd), [1_450, 1_300]);
    assert_eq!(amounts(&stock, "assets", jpy), [9_400, 9_000]);
    assert_eq!(amounts(&stock, "unclosed_earnings", jpy), [400, 0]);
    assert_eq!(amounts(&stock, "balance_check", usd), [0, 0]);
    assert_eq!(amounts(&stock, "balance_check", jpy), [0, 0]);
    assert_eq!(amounts(&income, "revenue", usd), [200, 400]);
    assert_eq!(amounts(&income, "expense", usd), [50, 100]);
    assert_eq!(amounts(&income, "net_income", usd), [150, 300]);
    assert_eq!(amounts(&income, "net_income", jpy), [400, 0]);
    let eur = fixture.book.context().units.lookup("EUR").unwrap();
    assert_eq!(amounts(&stock, "assets", eur), [0, 0]);
    assert_eq!(amounts(&income, "net_income", eur), [0, 0]);
}

#[test]
fn retained_comparatives_replay_after_later_and_backdated_postings() {
    let mut fixture = Fixture::new(0x92);
    let usd = fixture.usd;
    fixture.transfer(day(2026, 1, 15), b"jan-sale", usd, ("1000", "4000"), 300);
    fixture.transfer(day(2026, 2, 15), b"feb-sale", usd, ("1000", "4000"), 500);
    fixture.transfer(day(2026, 2, 15), b"feb-cost", usd, ("6000", "1000"), 40);
    let at = fixture.book.head().unwrap();
    let mut saved = Vec::new();
    for name in ["balance-sheet", "income-statement"] {
        let chosen = selection(name, FEBRUARY, JANUARY);
        let before_read = fixture.book.head().unwrap();
        let certified = fixture
            .book
            .certify_statement(chosen.clone(), Some(at))
            .unwrap()
            .unwrap();
        assert_eq!(certified.statement.known_at, at.0);
        assert_eq!(certified.certificate.known_at, at);
        assert_eq!(certified.certificate.selection, chosen.clone().into());
        assert_eq!(
            certified.certificate.output,
            certified.statement.canonical_bytes().unwrap()
        );
        assert_eq!(certified.certificate.output_format(), "fa:statement:v1");
        assert!(
            certified
                .certificate
                .inputs
                .iter()
                .all(|input| input.plan.snapshot_seq == at)
        );
        assert_eq!(
            fixture
                .book
                .certify_report(chosen.clone().into(), Some(at))
                .unwrap()
                .unwrap()
                .certificate,
            certified.certificate
        );
        assert_eq!(
            fixture.book.statement(chosen, Some(at)).unwrap().unwrap(),
            certified.statement
        );
        let bytes = certified.certificate.canonical_bytes().unwrap();
        assert!(bytes.starts_with(fa::certificate::STATEMENT_CERTIFICATE_FORMAT));
        assert_eq!(
            ReportCertificate::decode(&bytes).unwrap(),
            certified.certificate
        );
        assert_eq!(
            replay(&fixture.book, &certified.certificate),
            certified.statement
        );
        assert_eq!(
            fixture.book.head().unwrap(),
            before_read,
            "certification and replay are reads"
        );

        let retained = fixture
            .book
            .retain_certificate(&certified.certificate)
            .unwrap()
            .unwrap();
        let loaded = fixture
            .book
            .read_certificate(&retained.digest)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, certified.certificate);
        assert_eq!(
            fixture.book.retain_certificate(&loaded).unwrap().unwrap(),
            retained
        );
        assert_eq!(fixture.book.head().unwrap(), retained.recorded_at);
        saved.push((certified, bytes, retained));
    }
    fixture.transfer(
        day(2026, 3, 15),
        b"unrelated-march",
        usd,
        ("1000", "4000"),
        777,
    );
    for (certified, _, _) in &saved {
        assert!(matches!(
            fixture
                .book
                .certificate_status(&certified.certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::Current { .. }
        ));
        assert_eq!(
            replay(&fixture.book, &certified.certificate),
            certified.statement
        );
    }

    let correction = fixture.transfer(
        day(2026, 1, 20),
        b"backdated-comparative",
        usd,
        ("1000", "4000"),
        25,
    );
    let head = fixture.book.head().unwrap();
    for (certified, original_bytes, retained) in saved {
        assert_eq!(
            fixture
                .book
                .certificate_status(&certified.certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries: vec![correction.entry_ref().vid],
            }
        );
        let loaded = fixture
            .book
            .read_certificate(&retained.digest)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.canonical_bytes().unwrap(), original_bytes);
        assert_eq!(replay(&fixture.book, &loaded), certified.statement);
        let chosen = selection(&certified.statement.definition_name, FEBRUARY, JANUARY);
        assert_eq!(
            fixture
                .book
                .certify_statement(chosen.clone(), Some(at))
                .unwrap()
                .unwrap()
                .certificate,
            loaded
        );
        let current = fixture.book.statement(chosen, Some(head)).unwrap().unwrap();
        if current.definition_name == "balance-sheet" {
            assert_eq!(amounts(&certified.statement, "assets", usd), [760, 300]);
            assert_eq!(amounts(&current, "assets", usd), [785, 325]);
        } else {
            assert_eq!(amounts(&certified.statement, "net_income", usd), [460, 300]);
            assert_eq!(amounts(&current, "net_income", usd), [460, 325]);
        }
    }
    assert_eq!(
        fixture.book.head().unwrap(),
        head,
        "historical replay never republishes a report"
    );
}

#[test]
fn large_retained_certificate_survives_reopen_as_native_fragments_without_a_blob() {
    let seed = 0x96;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fa-certificate-storage-{}-{suffix}",
        std::process::id()
    ));
    // Keep the book for failure diagnosis. The unique directory is created
    // exclusively; no pre-existing data is reused.
    std::fs::create_dir(&directory).unwrap();
    let mut fixture = Fixture::at(seed, Some(&directory));
    let usd = fixture.usd;
    fixture.transfer(day(2026, 1, 15), b"jan-sale", usd, ("1000", "4000"), 300);
    fixture.transfer(day(2026, 2, 15), b"feb-sale", usd, ("1000", "4000"), 500);
    fixture.transfer(day(2026, 2, 15), b"feb-cost", usd, ("6000", "1000"), 40);
    let certified = fixture
        .book
        .certify_statement(selection("balance-sheet", FEBRUARY, JANUARY), None)
        .unwrap()
        .unwrap();
    let certificate = certified.certificate;
    let canonical = certificate.canonical_bytes().unwrap();
    // Native rows store byte scalars as 8-byte memcomparable groups, about
    // 9/8 of the raw bytes. Compare the actual scalar encoding, not the raw
    // certificate length: this payload alone cannot fit in one row, even
    // before the row's other properties and metadata.
    let encoded_payload = CanonicalScalar::bytes(canonical.clone())
        .unwrap()
        .encode()
        .unwrap();
    assert!(
        encoded_payload.len() > 16 * 1024,
        "this regression must exceed one substrate row: {} encoded payload bytes",
        encoded_payload.len()
    );
    let retained = fixture
        .book
        .retain_certificate(&certificate)
        .unwrap()
        .unwrap();
    // c9b1c775 (fa-9ae, report_certificate_storage.toml): above one native
    // row, retention publishes a manifest plus ordered native fragments in ONE
    // transaction and never writes the legacy `fa:certificate-external:v1`
    // blob. Check the bytes on disk independently of the producer's helpers.
    let mut matching = Vec::new();
    for shard in std::fs::read_dir(directory.join("blobs")).unwrap() {
        let shard = shard.unwrap();
        if shard.file_type().unwrap().is_dir() {
            for item in std::fs::read_dir(shard.path()).unwrap() {
                let path = item.unwrap().path();
                if std::fs::read(&path).unwrap() == canonical {
                    matching.push(path);
                }
            }
        }
    }
    assert!(
        matching.is_empty(),
        "new retention writes native fragments, never a blob sidecar: {matching:?}"
    );
    drop(fixture);
    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap();
    let head = book.head().unwrap();
    assert_eq!(head, retained.recorded_at);
    let loaded = book.read_certificate(&retained.digest).unwrap().unwrap();
    assert_eq!(loaded, certificate);
    assert_eq!(loaded.canonical_bytes().unwrap(), canonical);
    assert_eq!(replay(&book, &loaded), certified.statement);
    assert_eq!(book.retain_certificate(&loaded).unwrap().unwrap(), retained);
    assert_eq!(
        book.retain_certificate(&certificate).unwrap().unwrap(),
        retained
    );
    assert_eq!(
        book.head().unwrap(),
        head,
        "an exact retry publishes nothing"
    );
    // Missing, rewritten, restored and late fragments (and the no-repair rule
    // for each) are exercised against real native rows in
    // crates/fa/src/certificate_store/tests.rs; the legacy external-blob read
    // path keeps its missing/changed-bytes coverage there too.
}

#[test]
fn reservations_do_not_change_statements_and_resolution_posts_use_their_own_period() {
    let mut fixture = Fixture::new(0x93);
    let usd = fixture.usd;
    fixture.transfer(day(2026, 1, 10), b"capital", usd, ("1000", "3000"), 1_000);
    fixture.transfer(day(2026, 1, 15), b"sale", usd, ("1000", "4000"), 300);
    let before = fixture.book.head().unwrap();
    let mut saved = Vec::new();
    for name in ["balance-sheet", "income-statement"] {
        saved.push(
            fixture
                .book
                .certify_statement(selection(name, FEBRUARY, JANUARY), Some(before))
                .unwrap()
                .unwrap(),
        );
    }
    let mut pending = fixture.proposal(
        day(2026, 1, 20),
        b"expense-reservation",
        EntryClass::PENDING,
        fixture.legs(usd, ("6000", "1000"), 200),
    );
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let hold = fixture.commit(pending).entry_ref();
    let held_at = fixture.book.head().unwrap();
    assert_eq!(
        fixture
            .book
            .period_activity(&[JANUARY.into()], Some(held_at))
            .unwrap()
            .pending_unit_totals[&usd.0],
        (200, 200)
    );
    for certified in &saved {
        let current = fixture
            .book
            .statement(
                selection(&certified.statement.definition_name, FEBRUARY, JANUARY),
                Some(held_at),
            )
            .unwrap()
            .unwrap();
        assert_eq!(current.lines, certified.statement.lines);
        assert_eq!(current.mappings, certified.statement.mappings);
        assert!(matches!(
            fixture
                .book
                .certificate_status(&certified.certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::Current { .. }
        ));
    }

    let mut resolution = fixture.proposal(
        day(2026, 2, 5),
        b"expense-fulfilled",
        EntryClass::RESOLUTION,
        fixture.legs(usd, ("6000", "1000"), 75),
    );
    resolution.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(hold),
        disposition: Some(Disposition::Posts {
            source_ordinals: vec![0, 1],
        }),
    });
    let posted = fixture.commit(resolution);
    let head = fixture.book.head().unwrap();
    assert_eq!(
        fixture
            .book
            .period_activity(&[JANUARY.into()], Some(head))
            .unwrap()
            .pending_unit_totals[&usd.0],
        (0, 0)
    );
    assert_eq!(
        fixture
            .book
            .period_activity(&[JANUARY.into()], Some(held_at))
            .unwrap()
            .pending_unit_totals[&usd.0],
        (200, 200)
    );
    for certified in saved {
        assert_eq!(
            replay(&fixture.book, &certified.certificate),
            certified.statement
        );
        assert_eq!(
            fixture
                .book
                .certificate_status(&certified.certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries: vec![posted.entry_ref().vid],
            }
        );
        let current = fixture
            .book
            .statement(
                selection(&certified.statement.definition_name, FEBRUARY, JANUARY),
                Some(head),
            )
            .unwrap()
            .unwrap();
        if current.definition_name == "balance-sheet" {
            assert_eq!(amounts(&current, "assets", usd), [1_225, 1_300]);
            assert_eq!(amounts(&current, "unclosed_earnings", usd), [225, 300]);
            assert_eq!(amounts(&current, "balance_check", usd), [0, 0]);
        } else {
            assert_eq!(amounts(&current, "expense", usd), [75, 0]);
            assert_eq!(amounts(&current, "net_income", usd), [-75, 300]);
        }
    }
}

#[test]
fn historical_zero_leaf_mappings_survive_a_later_covered_chart_extension() {
    let mut fixture = Fixture::new(0x94);
    let usd = fixture.usd;
    fixture.transfer(day(2026, 1, 15), b"sale", usd, ("1000", "4000"), 120);
    fixture.transfer(day(2026, 1, 15), b"expense", usd, ("6000", "1000"), 20);
    let chosen = selection("income-statement", JANUARY, DECEMBER);
    let at = fixture.book.head().unwrap();
    let certified = fixture
        .book
        .certify_statement(chosen.clone(), Some(at))
        .unwrap()
        .unwrap();
    assert_eq!(
        certified
            .statement
            .mappings
            .iter()
            .map(|mapping| (
                mapping.account.code.as_str(),
                mapping.account.name.as_str(),
                mapping.line_code.as_str(),
            ))
            .collect::<Vec<_>>(),
        vec![
            ("4000", "Revenue", "revenue"),
            ("6000", "Operating expense", "expense"),
            ("6100", "Unused expense", "expense"),
        ]
    );
    let retained = fixture
        .book
        .retain_certificate(&certified.certificate)
        .unwrap()
        .unwrap();

    fixture
        .book
        .install_chart(
            &[account(
                "1200",
                "Unused additional asset",
                AccountType::ASSET,
            )],
            PRINCIPAL,
            day(2026, 1, 20),
            b"uncovered-chart-extension",
            &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        fixture
            .book
            .certificate_status(&certified.certificate)
            .unwrap()
            .unwrap(),
        CertificateStatus::Current { .. }
    ));

    let added = fixture
        .book
        .install_chart(
            &[account("6200", "Later expense", AccountType::EXPENSE)],
            PRINCIPAL,
            day(2026, 1, 20),
            b"covered-chart-extension",
            &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    let current = fixture
        .book
        .statement(chosen.clone(), Some(added.recorded_at))
        .unwrap()
        .unwrap();
    assert_eq!(
        current.lines, certified.statement.lines,
        "adding an unused leaf creates no monetary movement"
    );
    assert_eq!(
        current.definition_bytes,
        certified.statement.definition_bytes
    );
    assert_eq!(
        current.mappings.len(),
        certified.statement.mappings.len() + 1
    );
    let mapping = current
        .mappings
        .iter()
        .find(|mapping| mapping.account.code == "6200")
        .unwrap();
    assert_eq!(mapping.account.name, "Later expense");
    assert_eq!(mapping.line_code, "expense");
    assert_eq!(
        fixture
            .book
            .certificate_status(&certified.certificate)
            .unwrap()
            .unwrap(),
        CertificateStatus::SupersededBy {
            checked_at: added.recorded_at,
            later_entries: vec![added.control_entry],
        }
    );
    assert_eq!(
        fixture
            .book
            .statement(chosen.clone(), Some(at))
            .unwrap()
            .unwrap(),
        certified.statement
    );
    let loaded = fixture
        .book
        .read_certificate(&retained.digest)
        .unwrap()
        .unwrap();
    assert_eq!(loaded, certified.certificate);
    assert_eq!(replay(&fixture.book, &loaded), certified.statement);
    assert_eq!(
        fixture
            .book
            .certify_statement(chosen, Some(at))
            .unwrap()
            .unwrap()
            .certificate,
        loaded
    );
    assert_eq!(fixture.book.head().unwrap(), added.recorded_at);
}

#[test]
fn invalid_plain_and_certified_selections_refuse_without_changing_the_book() {
    let mut fixture = Fixture::new(0x95);
    let usd = fixture.usd;
    fixture.transfer(day(2026, 1, 15), b"sale", usd, ("1000", "4000"), 120);
    let at = fixture.book.head().unwrap();
    let valid = selection("income-statement", JANUARY, DECEMBER);
    let before = fixture
        .book
        .statement(valid.clone(), Some(at))
        .unwrap()
        .unwrap();
    let mut empty = valid.clone();
    empty.periods.clear();
    for (chosen, known_at) in [
        (selection("balance-sheet", "FY2099-P01", JANUARY), Some(at)),
        (empty, Some(at)),
        (valid.clone(), Some(CommitSeq(at.0.checked_add(1).unwrap()))),
    ] {
        let plain = fixture
            .book
            .statement(chosen.clone(), known_at)
            .unwrap()
            .unwrap_err();
        let certified = fixture
            .book
            .certify_statement(chosen, known_at)
            .unwrap()
            .unwrap_err();
        for refusal in [plain, certified] {
            assert_eq!(refusal.code, fa::statements::STATEMENT_INVALID);
            assert_eq!(refusal.exit, fa_journal::exit::REFUSAL);
        }
        assert_eq!(
            fixture.book.head().unwrap(),
            at,
            "a rejected report appends nothing"
        );
    }
    assert_eq!(
        fixture.book.statement(valid, None).unwrap().unwrap(),
        before
    );
}
