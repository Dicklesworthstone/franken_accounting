//! Outsider verification of real native statements. The verifier receives
//! exported bytes and a separately chosen key/checkpoint; it never reads the
//! source book or calls the statement producer's arithmetic.

use super::*;

pub(super) fn tick(book: &mut Book, ns: u64, monotonic_ok: bool) {
    let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let capability = Capability::embedded(PRINCIPAL, &["witness"]).unwrap();
    runtime
        .block_on(book.record_tick(&root, ns, monotonic_ok, &capability))
        .unwrap()
        .unwrap();
}

#[test]
fn report_bundles_admit_head_before_certificate_and_checkpoint_selection() {
    let mut fixture = Fixture::new(0xe7);
    fixture.transfer(
        day(2026, 1, 15),
        b"bundle-scope-original",
        fixture.usd,
        ("1000", "4000"),
        150,
    );
    let certificate = fixture
        .book
        .certify_trial_balance(
            fa::TrialBalanceSelection::Periods(vec![JANUARY.into()]),
            None,
        )
        .unwrap()
        .unwrap()
        .certificate;
    let original = produce(&mut fixture.book, &certificate);
    let original_state = original.checkpoint.checkpoint.body.state_oid;
    fixture.transfer(
        day(2026, 1, 20),
        b"bundle-scope-later",
        fixture.usd,
        ("1000", "4000"),
        900,
    );
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let latest = fixture
        .book
        .checkpoint(PRINCIPAL, &capability)
        .unwrap()
        .unwrap();
    let before = fixture.book.head().unwrap();
    let mut tampered = certificate.clone();
    tampered.digest[0] ^= 1;
    let mut foreign = certificate.clone();
    foreign.book_id = Id128([0xff; 16]);
    for (caveat, denied) in [
        (
            "accounts",
            capability.clone().for_accounts(&["1000"]).unwrap(),
        ),
        (
            "periods",
            capability.clone().for_periods(&[JANUARY]).unwrap(),
        ),
        (
            "effective",
            capability.clone().effective_through(day(2026, 1, 31)),
        ),
        (
            "known_at",
            capability.clone().known_at_most(certificate.known_at),
        ),
        ("known_at", capability.clone().known_at_most(before)),
        (
            "branch",
            capability.clone().on_branch(Id128([0xf1; 16])).unwrap(),
        ),
        (
            "books",
            capability.clone().for_books(&[Id128([0xf2; 16])]).unwrap(),
        ),
    ] {
        let mut expected = None;
        for source in [&certificate, &tampered, &foreign] {
            for state in [
                None,
                Some(original_state),
                Some(latest.stored.oid),
                Some(Oid([0xff; 32])),
            ] {
                let refusal = fixture
                    .book
                    .produce_report_bundle(PRINCIPAL, &denied, state, source)
                    .unwrap()
                    .unwrap_err();
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
                assert!(refusal.message.contains(&format!("`{caveat}`")));
                if let Some(expected) = &expected {
                    assert_eq!(
                        &refusal, expected,
                        "authority precedes every source observation"
                    );
                } else {
                    expected = Some(refusal);
                }
            }
        }
    }
    let historical = fixture
        .book
        .produce_report_bundle(PRINCIPAL, &capability, Some(original_state), &certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(historical.bundle.bytes, original.bundle.bytes);
    let verified = fa_verify::report::verify_report_expected(
        &historical.bundle.bytes,
        &[fixture.book.checkpoint_public_key()],
        None,
        Some(&historical.receipt),
        Some(&certificate.digest),
    )
    .unwrap();
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(fixture.book.head().unwrap(), before);
}

#[test]
fn instant_reports_export_the_original_tick_frontier_and_verify_offline() {
    let mut fixture = Fixture::new(0xec);
    let base = fa_time::UtcInstant::parse("2026-01-15T00:00:00Z")
        .unwrap()
        .unix_ns();
    tick(&mut fixture.book, base + 100, false);
    fixture.transfer(
        day(2026, 1, 15),
        b"first-tick-bucket",
        fixture.usd,
        ("1000", "4000"),
        150,
    );
    let balance = fa::TrialBalanceSelection::Periods(vec![JANUARY.into()]);
    let statement = StatementSelection {
        definition: StatementDefinition::embedded("income-statement").unwrap(),
        periods: vec![JANUARY.into()],
        comparative: Vec::new(),
    };
    let mut certificates = vec![
        fixture
            .book
            .certify_trial_balance_at_instant(balance.clone(), base + 105)
            .unwrap()
            .unwrap()
            .certificate,
        fixture
            .book
            .certify_statement_at_instant(statement.clone(), base + 105)
            .unwrap()
            .unwrap()
            .certificate,
    ];
    let original_known_at = certificates[0].known_at;
    assert!(certificates.iter().all(|certificate| {
        certificate
            .time_selection
            .as_ref()
            .unwrap()
            .resolution
            .upper
            .is_none()
    }));
    tick(&mut fixture.book, base + 110, true);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let earlier_checkpoint = fixture
        .book
        .checkpoint(PRINCIPAL, &capability)
        .unwrap()
        .unwrap();
    fixture.transfer(
        day(2026, 1, 15),
        b"later-tick-bucket",
        fixture.usd,
        ("1000", "4000"),
        900,
    );
    tick(&mut fixture.book, base + 120, true);
    certificates.extend([
        fixture
            .book
            .certify_trial_balance_at_instant(balance, base + 105)
            .unwrap()
            .unwrap()
            .certificate,
        fixture
            .book
            .certify_statement_at_instant(statement, base + 105)
            .unwrap()
            .unwrap()
            .certificate,
    ]);
    assert_eq!(certificates[0].output, certificates[2].output);
    assert_eq!(certificates[1].output, certificates[3].output);
    let head = fixture.book.head().unwrap();
    let refusal = fixture
        .book
        .produce_report_bundle(
            PRINCIPAL,
            &capability,
            Some(earlier_checkpoint.checkpoint.checkpoint.body.state_oid),
            &certificates[2],
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_notary::code::SCOPE_UNSUPPORTED);
    assert_eq!(fixture.book.head().unwrap(), head);
    for certificate in &certificates {
        let produced = produce(&mut fixture.book, certificate);
        let key = fixture.book.checkpoint_public_key();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            Some(&certificate.digest),
        )
        .unwrap();
        assert_eq!(verified.output, certificate.output);
        assert_eq!(verified.known_at, original_known_at.0);
        let time = verified.time_selection.unwrap();
        let retained = certificate.time_selection.as_ref().unwrap();
        assert_eq!(time.frontier, retained.resolution.frontier);
        assert_eq!(time.lower_entry, retained.lower_entry.0);
        assert_eq!(time.upper_entry, retained.upper_entry.map(|id| id.0));
        assert_eq!(time.source_grade(), "uncorroborated_daemon_clock");
        let command = fa_verify::cli::run(
            &[
                "report".into(),
                "bundle".into(),
                "--key".into(),
                key.iter().map(|byte| format!("{byte:02x}")).collect(),
                "--receipt".into(),
                "receipt".into(),
                "--json".into(),
            ],
            &|path| match path {
                "bundle" => Ok(produced.bundle.bytes.clone()),
                "receipt" => Ok(produced.receipt.clone()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("unexpected input {path}"),
                )),
            },
        );
        assert_eq!(command.exit, 0, "{}", command.stdout);
        assert!(
            command
                .stdout
                .contains("\"scope\":\"authenticated_tick_bucket\"")
        );
        assert!(
            command
                .stdout
                .contains("\"source_grade\":\"uncorroborated_daemon_clock\"")
        );
        assert!(
            command
                .stdout
                .contains("\"external_utc_accuracy\":\"not_judged\"")
        );
    }
}

#[test]
fn instant_report_production_refuses_unauthenticated_opening_date_policy() {
    let units = UnitRegistry::embedded().unwrap();
    let usd = units.lookup("USD").unwrap();
    let mut book = Book::create_memory(
        BookKeys::for_development(0xed),
        BookSpec {
            book_id: Id128([0xed; 16]),
            name: "Opening-date instant export refusal".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("opening-policy", 1, 0).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: Some(day(2026, 1, 1)),
        },
        Entropy::deterministic(0xed),
    )
    .unwrap();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    book.install_chart(
        &[account("1000", "Cash", AccountType::ASSET)],
        PRINCIPAL,
        day(2026, 1, 1),
        b"opening-policy-chart",
        &schema,
    )
    .unwrap()
    .unwrap();
    book.create_periods(2026, PRINCIPAL, &schema)
        .unwrap()
        .unwrap();
    let instant = fa_time::UtcInstant::parse("2026-01-15T00:00:00Z")
        .unwrap()
        .unix_ns();
    tick(&mut book, instant, true);
    let certificate = book
        .certify_trial_balance_at_instant(
            fa::TrialBalanceSelection::AsOf(day(2026, 1, 15)),
            instant,
        )
        .unwrap()
        .unwrap()
        .certificate;
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let before = book.head().unwrap();
    let refusal = book
        .produce_report_bundle(PRINCIPAL, &capability, None, &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_notary::code::SCOPE_UNSUPPORTED);
    assert!(refusal.message.contains("opening-date admission"));
    assert_eq!(book.head().unwrap(), before);
}

fn unit_ids(book: &Book) -> Vec<u32> {
    book.context().units.iter().map(|(id, _)| id.0).collect()
}

pub(super) fn produce(book: &mut Book, certificate: &ReportCertificate) -> fa::ProducedBundle {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let checkpoint = book.checkpoint(PRINCIPAL, &capability).unwrap().unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let head = book.head().unwrap();
    let produced = book
        .produce_report_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        book.head().unwrap(),
        head,
        "export publishes no accounting effects"
    );
    let repeated = book
        .produce_report_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(produced.receipt, repeated.receipt);
    produced
}

fn verify(
    book: &Book,
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
) -> fa_verify::report::VerifiedReport {
    let key = book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_statement_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        &unit_ids(book),
        Some(&certificate.digest),
    )
    .expect("the independently authenticated journal must reproduce every statement byte");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.statement.is_some());
    assert!(verified.receipt.is_some());
    assert!(
        verified.rows.is_empty(),
        "statement lines are not trial-balance rows"
    );
    verified
}

// Exercise the public legacy assembler with exactly the authenticated
// checkpoint records from a real v2 export. Journal's vertex keys only order
// records here; the reconstructed statement must equal the signed checkpoint.
fn legacy_bundle(
    book: &Book,
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
) -> fa_notary::Bundle {
    let mut reader = fa_model::Reader::new(&produced.bundle.bytes);
    let bound = fa_notary::report::MAX_REPORT_BUNDLE_BYTES;
    assert_eq!(
        reader.bytes(64, "format").unwrap(),
        fa_notary::report::REPORT_BUNDLE_FORMAT
    );
    assert_eq!(reader.u16("major").unwrap(), 2);
    assert_eq!(reader.u16("minor").unwrap(), 0);
    let _ = reader.bytes(bound, "certificate").unwrap();
    let signed = reader.bytes(bound, "checkpoint").unwrap();
    let checkpoint = fa_verify::verify_checkpoint(signed, &[book.checkpoint_public_key()]).unwrap();
    let prefix = fa_verify::verify_prefix(
        reader.bytes(bound, "prefix").unwrap(),
        &checkpoint.checkpoint,
    )
    .unwrap();
    assert_eq!(
        reader.u32("records").unwrap() as usize,
        prefix.envelopes.len()
    );
    let records = prefix
        .envelopes
        .iter()
        .enumerate()
        .map(|(index, envelope)| {
            let _ = reader.u32("proposal_len").unwrap();
            let payload = reader.bytes(bound, "payload").unwrap();
            (
                VId(index as u128 + 1),
                fa_notary::Record::decode(envelope.kind, payload).unwrap(),
                CommitSeq(envelope.commit_seq),
            )
        })
        .collect();
    assert_eq!(
        reader.u32("migrations").unwrap(),
        0,
        "fixture has no migrations"
    );
    let journal = fa_notary::Journal::from_records_with_evidence(
        certificate.book_id,
        CommitSeq(checkpoint.checkpoint.through_seq),
        Some(CommitSeq(0)),
        records,
    )
    .unwrap();
    assert_eq!(
        journal.statement(),
        produced.checkpoint.checkpoint.body.statement
    );
    fa_notary::report::assemble(
        &journal,
        &produced.checkpoint,
        &certificate.canonical_bytes().unwrap(),
        certificate.known_at,
        &std::collections::BTreeMap::new(),
    )
    .unwrap()
    .unwrap()
}

#[test]
fn historical_native_statements_export_comparatives_zero_leaves_and_pending_exclusion() {
    let mut fixture = Fixture::new(0xea);
    let (usd, jpy) = (fixture.usd, fixture.jpy);
    fixture.transfer(
        day(2025, 12, 15),
        b"portable-capital",
        usd,
        ("1000", "3000"),
        1_000,
    );
    for (key, date, unit, accounts, amount) in [
        (
            b"portable-jan-sale".as_slice(),
            day(2026, 1, 15),
            usd,
            ("1000", "4000"),
            300,
        ),
        (
            b"portable-jan-cost".as_slice(),
            day(2026, 1, 15),
            usd,
            ("6000", "1000"),
            50,
        ),
        (
            b"portable-jpy-sale".as_slice(),
            day(2026, 1, 15),
            jpy,
            ("1000", "4000"),
            700,
        ),
        (
            b"portable-jpy-cost".as_slice(),
            day(2026, 1, 15),
            jpy,
            ("6000", "1000"),
            300,
        ),
        (
            b"portable-feb-sale".as_slice(),
            day(2026, 2, 15),
            usd,
            ("1000", "4000"),
            500,
        ),
        (
            b"portable-feb-cost".as_slice(),
            day(2026, 2, 15),
            usd,
            ("6000", "1000"),
            40,
        ),
    ] {
        fixture.transfer(date, key, unit, accounts, amount);
    }
    let mut hold = fixture.proposal(
        day(2026, 1, 20),
        b"portable-unfulfilled-reservation",
        EntryClass::PENDING,
        fixture.legs(usd, ("6000", "1000"), 200),
    );
    hold.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    fixture.commit(hold);
    let known_at = fixture.book.head().unwrap();
    let mut reports = Vec::new();
    for name in ["balance-sheet", "income-statement"] {
        let certified = fixture
            .book
            .certify_statement(selection(name, FEBRUARY, JANUARY), Some(known_at))
            .unwrap()
            .unwrap();
        assert_eq!(certified.statement.columns.len(), 2);
        assert!(
            certified
                .statement
                .mappings
                .iter()
                .any(|mapping| mapping.account.code == "6100")
        );
        let eur = fixture.book.context().units.lookup("EUR").unwrap();
        if name == "balance-sheet" {
            assert_eq!(amounts(&certified.statement, "assets", usd), [1_710, 1_250]);
            assert_eq!(
                amounts(&certified.statement, "unclosed_earnings", usd),
                [710, 250]
            );
            assert_eq!(amounts(&certified.statement, "assets", jpy), [400, 400]);
            assert_eq!(amounts(&certified.statement, "assets", eur), [0, 0]);
        } else {
            assert_eq!(amounts(&certified.statement, "net_income", usd), [460, 250]);
            assert_eq!(amounts(&certified.statement, "net_income", jpy), [0, 400]);
            assert_eq!(amounts(&certified.statement, "net_income", eur), [0, 0]);
        }
        let retained = fixture
            .book
            .retain_certificate(
                PRINCIPAL,
                &Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap(),
                &certified.certificate,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            fixture
                .book
                .read_certificate(&retained.digest)
                .unwrap()
                .unwrap(),
            certified.certificate
        );
        reports.push(certified);
    }
    // Both a backdated amount and a zero-balance mapping change are later
    // knowledge. They are in the exported signed prefix, outside the answer.
    fixture.transfer(
        day(2026, 1, 20),
        b"portable-late-comparative",
        usd,
        ("1000", "4000"),
        25,
    );
    fixture
        .book
        .install_chart(
            &[account(
                "6200",
                "Later unspent expense",
                AccountType::EXPENSE,
            )],
            PRINCIPAL,
            day(2026, 1, 20),
            b"portable-later-account",
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    for certified in reports {
        let produced = produce(&mut fixture.book, &certified.certificate);
        let verified = verify(&fixture.book, &produced, &certified.certificate);
        assert!(verified.checked_records as u64 > certified.certificate.journal_leaves);
        assert_eq!(
            verified.output,
            certified.statement.canonical_bytes().unwrap()
        );
    }
}

#[test]
fn atomic_pending_resolutions_export_and_replay_as_one_accounting_frontier() {
    let mut fixture = Fixture::new(0xf1);
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 1, 10),
        b"atomic-capital",
        usd,
        ("1000", "3000"),
        1_000,
    );
    let maintain = Capability::embedded(PRINCIPAL, &["read", "verify", "maintain"]).unwrap();
    fixture
        .book
        .advance_registers(PRINCIPAL, &maintain, JANUARY)
        .unwrap()
        .unwrap();
    fixture
        .book
        .advance_registers(PRINCIPAL, &maintain, FEBRUARY)
        .unwrap()
        .unwrap();
    let before = fixture.book.head().unwrap();
    let book_id = fixture.book.context().book_id;
    let mut proposals = Vec::new();
    for (label, accounts, reserved, posted, resolution_first) in [
        ("void", ("6000", "1000"), 700, 0, false),
        ("posts", ("1000", "4000"), 500, 300, true),
    ] {
        let mut pending = fixture.proposal(
            day(2026, 1, 20),
            b"atomic-hold",
            EntryClass::PENDING,
            fixture.legs(usd, accounts, reserved),
        );
        pending.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        let vid = (0u64..)
            .find_map(|nonce| {
                pending.idempotency_key = format!("atomic-{label}-{nonce}").into_bytes();
                let vid = fa_model::entry_vid(
                    book_id,
                    &PRINCIPAL.0.to_le_bytes(),
                    &pending.idempotency_key,
                );
                ((fa_journal::rows::resolution_vid(vid).0 < vid.0) == resolution_first)
                    .then_some(vid)
            })
            .unwrap();
        let target = fa_model::EntryRef {
            vid,
            entry_digest: pending.clone().seal(Vec::new(), None).unwrap().entry_digest,
        };
        let mut resolution = fixture.proposal(
            day(2026, 2, 5),
            format!("atomic-{label}-resolution").as_bytes(),
            EntryClass::RESOLUTION,
            if posted == 0 {
                Vec::new()
            } else {
                fixture.legs(usd, accounts, posted)
            },
        );
        resolution.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(if posted == 0 {
                Disposition::Voids
            } else {
                Disposition::Posts {
                    source_ordinals: vec![0, 1],
                }
            }),
        });
        if posted == 0 {
            resolution.control = Some(fa_model::ControlPayload::ReservationRelease);
        }
        proposals.extend([pending, resolution]);
    }
    let batch = |key: &[u8], members: Vec<EntryPayload>| {
        fa_intents::PostBatch::new(
            key.to_vec(),
            members
                .into_iter()
                .map(|p| fa_intents::PostIntent::new(p, Vec::new()).unwrap())
                .collect(),
        )
        .unwrap()
    };
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let refused = fixture
        .book
        .post_batch(
            batch(
                b"atomic-forward-reference",
                vec![proposals[1].clone(), proposals[0].clone()],
            ),
            &capability,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-060");
    assert_eq!(fixture.book.head().unwrap(), before);
    let posted = fixture
        .book
        .post_batch(batch(b"atomic-resolve", proposals), &capability)
        .unwrap()
        .unwrap();
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    assert_eq!(posted.entries.len(), 4);
    let known_at = posted.recorded_at;
    for period in [JANUARY, FEBRUARY] {
        let literal = fixture.book.fold_period(period).unwrap();
        let maintained = fixture
            .book
            .advance_registers(PRINCIPAL, &maintain, period)
            .unwrap()
            .unwrap();
        assert!(!maintained.rebuilt);
        assert_eq!(maintained.fold, literal);
        assert!(literal.pending.is_empty());
        assert!(literal.pending_holds().is_empty());
    }
    for at in [before, known_at] {
        let certified = fixture
            .book
            .certify_trial_balance(
                fa::TrialBalanceSelection::Periods(vec![FEBRUARY.into()]),
                Some(at),
            )
            .unwrap()
            .unwrap();
        assert_eq!(certified.report.pending_unit_totals[&usd.0], (0, 0));
        let produced = produce(&mut fixture.book, &certified.certificate);
        let key = fixture.book.checkpoint_public_key();
        let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&checkpoint.checkpoint),
            Some(&produced.receipt),
            Some(&certified.certificate.digest),
        )
        .unwrap();
        assert_eq!(verified.output, certified.certificate.output);
        for name in ["balance-sheet", "income-statement"] {
            let certified = fixture
                .book
                .certify_statement(selection(name, FEBRUARY, JANUARY), Some(at))
                .unwrap()
                .unwrap();
            let fulfilled = if at == before { 0 } else { 300 };
            if name == "balance-sheet" {
                assert_eq!(
                    amounts(&certified.statement, "assets", usd),
                    [1_000 + fulfilled, 1_000]
                );
            } else {
                assert_eq!(
                    amounts(&certified.statement, "net_income", usd),
                    [fulfilled, 0]
                );
            }
            let produced = produce(&mut fixture.book, &certified.certificate);
            verify(&fixture.book, &produced, &certified.certificate);
        }
    }
}

fn close_year(fixture: &mut Fixture) {
    let book_id = fixture.book.context().book_id;
    let close = Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap();
    fixture
        .book
        .transition_period(
            "FY2026-CLOSE",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"portable-open-closing",
            &close,
        )
        .unwrap()
        .unwrap();
    let description = fixture
        .book
        .seal_text("Reviewed portable statement closing map")
        .unwrap();
    fixture
        .book
        .set_closing_routes(
            fa::ClosingRoutesRequest {
                principal: PRINCIPAL,
                effective_from: day(2026, 1, 1),
                routes: ["4000", "6000", "6100"]
                    .into_iter()
                    .map(|code| (account_vid(book_id, code), account_vid(book_id, "3000")))
                    .collect(),
                idempotency_key: b"portable-closing-map".to_vec(),
                description,
            },
            &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    let workpaper = Document {
        book_id,
        kind: fa_registry::evidence_policy::EvidencePolicy::embedded()
            .unwrap()
            .kind_by_name("Workpaper")
            .unwrap()
            .tag,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Reviewed native fiscal-year balances and closing destinations".to_vec(),
    };
    fixture.book.add_document(&workpaper).unwrap().unwrap();
    let prepared = fixture
        .book
        .prepare_year_end_close(
            &fa::YearEndCloseRequest {
                fiscal_year: 2026,
                closing_period: "FY2026-CLOSE".into(),
            },
            &close,
        )
        .unwrap()
        .unwrap();
    let mut template = fixture.proposal(
        day(2026, 12, 31),
        b"portable-year-end-close",
        EntryClass::CLOSING,
        Vec::new(),
    );
    template.effective_period = Some(fa_model::PeriodRef {
        calendar: fixture.book.context().calendar.id.clone(),
        code: "FY2026-CLOSE".into(),
    });
    template.evidence = vec![workpaper.evidence_ref(1)];
    fixture
        .book
        .post(PostRequest {
            proposal: prepared.proposal(template).unwrap(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: close,
        })
        .unwrap()
        .unwrap();
}

#[test]
fn native_offline_income_excludes_real_closing_but_keeps_source_reversals_and_adjustments() {
    let mut fixture = Fixture::new(0xeb);
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 1, 15),
        b"portable-close-sale",
        usd,
        ("1000", "4000"),
        10_000,
    );
    let expense = fixture
        .transfer(
            day(2026, 1, 15),
            b"portable-close-cost",
            usd,
            ("6000", "1000"),
            2_000,
        )
        .entry_ref();
    close_year(&mut fixture);
    // Closing is not itself reversible. Correct its underlying expense in a
    // lawful Normal period and include the resulting unclosed earnings.
    let (source, _) = fixture.book.read_entry(expense.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        leg.settles.clear();
    }
    let mut reversal = fixture.proposal(
        day(2026, 1, 15),
        b"portable-undo-cost",
        EntryClass::REVERSAL,
        legs,
    );
    reversal.supersession = vec![fa_model::Supersession {
        target: expense,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    let reversed = fixture.commit(reversal).entry_ref();
    let mut adjustment = fixture.proposal(
        day(2026, 12, 31),
        b"portable-closing-adjustment",
        EntryClass::ADJUSTING,
        fixture.legs(usd, ("6000", "1000"), 500),
    );
    adjustment.effective_period = Some(fa_model::PeriodRef {
        calendar: fixture.book.context().calendar.id.clone(),
        code: "FY2026-CLOSE".into(),
    });
    fixture.commit(adjustment);
    for name in ["balance-sheet", "income-statement"] {
        let certified = fixture
            .book
            .certify_statement(
                StatementSelection {
                    definition: StatementDefinition::embedded(name).unwrap(),
                    periods: vec![JANUARY.into(), "FY2026-CLOSE".into()],
                    comparative: vec![JANUARY.into()],
                },
                None,
            )
            .unwrap()
            .unwrap();
        if name == "income-statement" {
            assert_eq!(amounts(&certified.statement, "expense", usd), [500, 0]);
            assert_eq!(
                amounts(&certified.statement, "net_income", usd),
                [9_500, 10_000]
            );
        } else {
            assert_eq!(amounts(&certified.statement, "equity", usd), [8_000, 0]);
            assert_eq!(
                amounts(&certified.statement, "unclosed_earnings", usd),
                [1_500, 10_000]
            );
            assert_eq!(amounts(&certified.statement, "balance_check", usd), [0, 0]);
        }
        let produced = produce(&mut fixture.book, &certified.certificate);
        verify(&fixture.book, &produced, &certified.certificate);
    }
    // Reverse the reversal as well. Its target has the kernel's target-derived
    // identity, not the caller's original key-derived Entry identity.
    let (source, _) = fixture.book.read_entry(reversed.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        leg.settles.clear();
    }
    let mut restored = fixture.proposal(
        day(2026, 1, 15),
        b"portable-restore-cost",
        EntryClass::REVERSAL,
        legs,
    );
    restored.supersession = vec![fa_model::Supersession {
        target: reversed,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    fixture.commit(restored);
    let certified = fixture
        .book
        .certify_statement(
            StatementSelection {
                definition: StatementDefinition::embedded("income-statement").unwrap(),
                periods: vec![JANUARY.into(), "FY2026-CLOSE".into()],
                comparative: vec![JANUARY.into()],
            },
            None,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        amounts(&certified.statement, "net_income", usd),
        [7_500, 8_000]
    );
    let produced = produce(&mut fixture.book, &certified.certificate);
    verify(&fixture.book, &produced, &certified.certificate);
}

pub(super) fn reseal(certificate: &mut ReportCertificate) {
    certificate.output_digest =
        fa_verify::blake3::hash_parts(b"fa:report-output:v1", &[&certificate.output]);
    let body = certificate.canonical_bytes().unwrap();
    let format = &body[..fa::certificate::REPORT_CERTIFICATE_FORMAT.len()];
    assert!(
        format == fa::certificate::STATEMENT_CERTIFICATE_FORMAT
            || format == fa::certificate::REPORT_CERTIFICATE_FORMAT
    );
    certificate.digest = fa_verify::blake3::hash_parts(format, &[&body[..body.len() - 32]]);
    // Keep each negative vector internally consistent, so a malformed
    // certificate checksum cannot mask the authority or recomputation checks.
    assert_eq!(
        ReportCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap(),
        *certificate
    );
}

pub(super) fn replace_certificate(bundle: &[u8], certificate: &ReportCertificate) -> Vec<u8> {
    let domain_len = u32::from_le_bytes(bundle[..4].try_into().unwrap()) as usize;
    let at = 4 + domain_len + 4;
    let old_len = u32::from_le_bytes(bundle[at..at + 4].try_into().unwrap()) as usize;
    let bytes = certificate.canonical_bytes().unwrap();
    let mut changed = bundle[..at].to_vec();
    changed.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    changed.extend_from_slice(&bytes);
    changed.extend_from_slice(&bundle[at + 4 + old_len..]);
    changed
}

#[test]
fn authenticated_registry_upgrades_preserve_supported_semantics_or_refuse() {
    let mut fixture = Fixture::new(0xad);
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 1, 15),
        b"registry-upgrade-sale",
        usd,
        ("1000", "4000"),
        300,
    );
    let certified = fixture
        .book
        .certify_statement(selection("income-statement", JANUARY, DECEMBER), None)
        .unwrap()
        .unwrap();
    let produced = produce(&mut fixture.book, &certified.certificate);
    verify(&fixture.book, &produced, &certified.certificate);
    let key = fixture.book.checkpoint_public_key();
    let sources = [
        (
            "account_types",
            include_str!("../../../../registries/account_types.toml"),
        ),
        (
            "entry_classes",
            include_str!("../../../../registries/entry_classes.toml"),
        ),
        ("units", include_str!("../../../../registries/units.toml")),
        (
            "foundations",
            include_str!("../../../../franken-stack.lock"),
        ),
    ];
    let documents: Vec<_> = sources
        .iter()
        .map(|(name, text)| (*name, fa_registry::toml::parse(text).unwrap()))
        .collect();
    let encode = |docs: &[(&str, fa_registry::toml::Document)]| {
        let mut writer = fa_model::Writer::new();
        writer.list(docs, |w, (name, doc)| {
            w.str(name).bytes(&doc.canonical_bytes());
        });
        writer.finish().unwrap()
    };
    let original = encode(&documents);
    assert!(produced.bundle.bytes.ends_with(&original));

    for change in [
        "foundation_metadata",
        "supersession",
        "open_item_law",
        "control_supersession",
        "unknown_class_field",
        "duplicate_control_id",
        "duplicate_control_name",
        "control_posting_class",
    ] {
        use fa_registry::toml::Value;
        let mut documents = documents.clone();
        if change == "foundation_metadata" {
            // Foundation provenance is authenticated but does not supply an
            // outsider's accounting algorithm. A new provenance field alone
            // must not require the old executable to recompute this statement.
            documents[3].1.root.insert(
                "upgrade_evidence".into(),
                Value::Str("independent recomputation fixture".into()),
            );
        } else {
            let classes = &mut documents[1].1;
            match change {
                "supersession" => {
                    classes.arrays.get_mut("class").unwrap()[4]
                        .insert("supersession".into(), Value::Str("none".into()));
                }
                "open_item_law" => {
                    classes.arrays.get_mut("class").unwrap()[1]
                        .insert("carries_open_items".into(), Value::Bool(true));
                }
                "control_supersession" => {
                    classes.arrays.get_mut("class").unwrap()[21]
                        .insert("supersession".into(), Value::Str("reverses".into()));
                }
                "unknown_class_field" => {
                    classes.arrays.get_mut("class").unwrap()[0]
                        .insert("changes_visibility".into(), Value::Bool(true));
                }
                "duplicate_control_id" => {
                    classes.arrays.get_mut("control_kind").unwrap()[1]
                        .insert("id".into(), Value::Int(3));
                }
                "duplicate_control_name" => {
                    classes.arrays.get_mut("control_kind").unwrap()[1]
                        .insert("name".into(), Value::Str("policy_activation".into()));
                }
                "control_posting_class" => {
                    classes.arrays.get_mut("control_kind").unwrap()[1]
                        .insert("class".into(), Value::Str("Original".into()));
                }
                _ => unreachable!(),
            }
        }
        let mut transcript = Vec::new();
        for (name, doc) in &documents {
            transcript.extend_from_slice(name.as_bytes());
            transcript.push(0);
            transcript.extend_from_slice(&fa_verify::blake3::hash_parts(
                b"fa:registry-canonical-digest:v1",
                &[&doc.canonical_bytes()],
            ));
        }
        let mut certificate = certified.certificate.clone();
        certificate.registry_digest =
            fa_verify::blake3::hash_parts(b"fa:report-registry-closure:v2", &[&transcript]);
        reseal(&mut certificate);
        let mut changed = replace_certificate(&produced.bundle.bytes, &certificate);
        changed.truncate(changed.len() - original.len());
        changed.extend_from_slice(&encode(&documents));
        // Deliberately authenticate the altered certificate. These cases must
        // reach the semantic gate rather than fail an old digest or receipt.
        let result = fa_verify::report::verify_report_expected(
            &changed,
            &[key],
            None,
            None,
            Some(&certificate.digest),
        );
        if change == "foundation_metadata" {
            assert_eq!(result.unwrap().output, certified.certificate.output);
        } else {
            assert_eq!(
                result.unwrap_err().predicate,
                "registry_closure",
                "{change}"
            );
        }
    }
}

#[test]
fn resealed_statement_forgeries_and_missing_authenticated_records_are_refused() {
    let mut fixture = Fixture::new(0xec);
    let usd = fixture.usd;
    let sale = fixture
        .transfer(
            day(2026, 1, 15),
            b"portable-forgery-sale",
            usd,
            ("1000", "4000"),
            300,
        )
        .entry_ref();
    let certified = fixture
        .book
        .certify_statement(selection("income-statement", JANUARY, DECEMBER), None)
        .unwrap()
        .unwrap();
    let produced = produce(&mut fixture.book, &certified.certificate);
    verify(&fixture.book, &produced, &certified.certificate);
    let key = fixture.book.checkpoint_public_key();
    let units = unit_ids(&fixture.book);
    let expected = certified.certificate.digest;
    let legacy = legacy_bundle(&fixture.book, &produced, &certified.certificate);
    let legacy_verified = fa_verify::report::verify_statement_report_expected(
        &legacy.bytes,
        &[key],
        None,
        None,
        &units,
        Some(&expected),
    )
    .unwrap();
    assert_eq!(legacy_verified.output, certified.certificate.output);
    assert_eq!(legacy_verified.unit_universe_source, "recipient-supplied");
    let eur = fixture.book.context().units.lookup("EUR").unwrap().0;
    for corruption in ["amount", "mapping", "definition", "zero_unit"] {
        let mut certificate = certified.certificate.clone();
        let mut statement = certified.statement.clone();
        match corruption {
            "amount" => {
                // Change both affected amount lines consistently: a renderer
                // that merely checks net-income arithmetic would accept it.
                for line in &mut statement.lines {
                    if line.unit_id == usd.0
                        && matches!(line.code.as_str(), "revenue" | "net_income")
                    {
                        line.amounts[0] = 301;
                    }
                }
                certificate.output = statement.canonical_bytes().unwrap();
            }
            "mapping" => {
                // The unused expense is still part of the authenticated chart
                // partition; dropping a zero-valued account is not harmless.
                statement
                    .mappings
                    .retain(|mapping| mapping.account.code != "6100");
                certificate.output = statement.canonical_bytes().unwrap();
            }
            "definition" => {
                let fa::ReportSelection::Statement(selection) = &mut certificate.selection else {
                    panic!("native statement")
                };
                selection.definition = StatementDefinition::embedded("balance-sheet").unwrap();
            }
            "zero_unit" => {
                // The recipient's full unit universe also requires zero
                // columns. It is never learned from the forged output.
                statement.lines.retain(|line| line.unit_id != eur);
                certificate.output = statement.canonical_bytes().unwrap();
            }
            _ => unreachable!(),
        }
        reseal(&mut certificate);
        let changed = replace_certificate(&produced.bundle.bytes, &certificate);
        // The recipient retains the original certificate, independently
        // of this changed bundle. Resealing cannot substitute another report.
        assert_eq!(
            fa_verify::report::verify_statement_report_expected(
                &changed,
                &[key],
                None,
                None,
                &units,
                Some(&expected),
            )
            .unwrap_err()
            .predicate,
            "recipient_certificate",
            "accepted {corruption} forgery against the retained certificate"
        );
        // Preserve the legacy recomputation vector as well: an explicit
        // unit universe does not authenticate the producer's output, so the
        // independent fold must still reject each internally resealed lie.
        let changed_legacy = replace_certificate(&legacy.bytes, &certificate);
        assert!(
            fa_verify::report::verify_statement_report(
                &changed_legacy, &[key], None, None, &units,
            ).is_err(),
            "accepted legacy {corruption} forgery"
        );
    }
    let (source, _) = fixture.book.read_entry(sale.vid).unwrap().unwrap();
    let source = source.encode().unwrap();
    let locations: Vec<_> = produced
        .bundle
        .bytes
        .windows(source.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == source).then_some(at))
        .collect();
    assert_eq!(
        locations.len(),
        1,
        "the authenticated source payload appears once"
    );
    let at = locations[0];
    let mut modified = produced.bundle.bytes.clone();
    modified[at + source.len() - 1] ^= 1;
    assert_eq!(
        fa_verify::report::verify_statement_report_expected(
            &modified,
            &[key],
            None,
            None,
            &units,
            Some(&expected),
        )
        .unwrap_err()
        .predicate,
        "record_derivation"
    );
    let mut omitted = produced.bundle.bytes.clone();
    omitted.drain(at..at + source.len());
    assert!(
        fa_verify::report::verify_statement_report_expected(
            &omitted,
            &[key],
            None,
            None,
            &units,
            Some(&expected),
        )
        .is_err()
    );
    assert_eq!(
        fa_verify::report::verify_statement_report_expected(
            &produced.bundle.bytes,
            &[],
            None,
            None,
            &units,
            Some(&expected),
        )
        .unwrap_err()
        .predicate,
        "checkpoint_signature"
    );
    assert_eq!(
        fa_verify::report::verify_report(&produced.bundle.bytes, &[key], None, None)
            .unwrap_err()
            .predicate,
        "report_input_authority",
        "a registry-bearing statement needs a trusted receipt or recipient pin"
    );
    assert_eq!(
        fa_verify::report::verify_statement_report(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            &units,
        )
        .unwrap_err()
        .predicate,
        "report_input_authority",
        "explicit units cannot bypass v2 input authority"
    );
    assert_eq!(
        fa_verify::report::verify_report_expected(
            &legacy.bytes,
            &[key],
            None,
            None,
            Some(&expected),
        )
        .unwrap_err()
        .predicate,
        "statement_units",
        "a legacy statement's full unit universe remains an explicit recipient premise"
    );
    let without_explicit_units = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        None,
        None,
        Some(&expected),
    )
    .unwrap();
    assert_eq!(without_explicit_units.output, certified.certificate.output);
    assert_eq!(
        without_explicit_units.unit_universe_source,
        "authenticated-registry"
    );
    let missing_unit: Vec<_> = units.iter().copied().filter(|unit| *unit != eur).collect();
    assert_eq!(
        fa_verify::report::verify_statement_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            &missing_unit,
            Some(&expected),
        )
        .unwrap_err()
        .predicate,
        "statement_units",
        "omitting a zero-activity recipient unit changes the complete report"
    );
    assert!(
        fa_verify::report::verify_statement_report(
            &legacy.bytes,
            &[key],
            None,
            None,
            &missing_unit,
        )
        .is_err(),
        "legacy explicit units must still reproduce every zero-activity line"
    );
}

/// fa-70h4 equivalence campaign. Over seeded histories of later and
/// backdated postings, every certified trial balance and statement the book
/// replays in place is reproduced, from the report bundle the book produces
/// for it, by the independent verifier's own fold against the book's signed
/// checkpoint. Its output bytes and certificate digest must equal the
/// certificate's. A bundle with one flipped byte never verifies.
#[test]
fn produced_report_bundles_recompute_every_certified_report_across_seeded_histories() {
    let pairs = [
        ("1000", "4000"),
        ("6000", "1000"),
        ("1000", "2000"),
        ("1000", "3000"),
        ("6100", "2000"),
    ];
    let periods = [JANUARY, FEBRUARY, MARCH];
    let mut checked = 0usize;
    for seed in 0..4u8 {
        let mut fixture = Fixture::new(0xb0 + seed);
        let usd = fixture.usd;
        let mut state = 0x9E37_79B9_7F4A_7C15_u64 ^ u64::from(seed);
        let mut draw = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let mut frontiers = Vec::new();
        for n in 0..12u64 {
            let date = day(2026, 1 + draw(3) as u8, 1 + draw(27) as u8);
            let accounts = pairs[draw(pairs.len() as u64) as usize];
            let key = format!("campaign-{seed}-{n}");
            fixture.transfer(date, key.as_bytes(), usd, accounts, 1 + draw(9_000) as i128);
            if n % 4 == 3 {
                frontiers.push(fixture.book.head().unwrap());
            }
        }
        for at in frontiers {
            let period = periods[draw(periods.len() as u64) as usize];
            let mut chosen: Vec<fa::ReportSelection> =
                vec![fa::TrialBalanceSelection::Periods(vec![period.into()]).into()];
            for name in ["balance-sheet", "income-statement"] {
                chosen.push(selection(name, FEBRUARY, JANUARY).into());
            }
            for selection in chosen {
                let what = format!("seed {seed} at {} {selection:?}", at.0);
                let certificate = fixture
                    .book
                    .certify_report(selection, Some(at))
                    .unwrap()
                    .unwrap()
                    .certificate;
                let produced = produce(&mut fixture.book, &certificate);
                let key = fixture.book.checkpoint_public_key();
                let anchor =
                    fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
                let statement = matches!(certificate.selection, fa::ReportSelection::Statement(_));
                let units = unit_ids(&fixture.book);
                let check = |bytes: &[u8]| {
                    if statement {
                        fa_verify::report::verify_statement_report_expected(
                            bytes,
                            &[key],
                            Some(&anchor.checkpoint),
                            Some(&produced.receipt),
                            &units,
                            Some(&certificate.digest),
                        )
                    } else {
                        fa_verify::report::verify_report_expected(
                            bytes,
                            &[key],
                            Some(&anchor.checkpoint),
                            Some(&produced.receipt),
                            Some(&certificate.digest),
                        )
                    }
                };
                let verified = check(&produced.bundle.bytes)
                    .unwrap_or_else(|e| panic!("{what}: the verifier refused the bundle: {e:?}"));
                assert_eq!(verified.output, certificate.output, "{what}: output bytes");
                assert_eq!(verified.certificate_digest, certificate.digest, "{what}");
                assert_eq!(verified.known_at, at.0, "{what}");
                assert_eq!(verified.scope, "recomputation", "{what}");
                let mut forged = produced.bundle.bytes.clone();
                let flip = draw(forged.len() as u64) as usize;
                forged[flip] ^= 0x01;
                assert!(
                    check(&forged).is_err(),
                    "{what}: a bundle with byte {flip} flipped verified"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 4 * 3 * 3, "every seeded report was checked");
}

fn declare_report_dimension(
    fixture: &mut Fixture,
    dimension: &str,
    code: &str,
    parent: Option<&str>,
) {
    let capability = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    fixture
        .book
        .create_dimension_value(
            &fa::dimension::DimensionValueSpec {
                dimension: dimension.into(),
                code: code.into(),
                name: format!("Portable report {dimension} {code}"),
                parent: parent.map(str::to_owned),
                valid_from: None,
                valid_to: None,
            },
            PRINCIPAL,
            format!("dimension-{dimension}-{code}").as_bytes(),
            &capability,
        )
        .unwrap()
        .unwrap();
}

fn dimension_report_legs(
    fixture: &Fixture,
    dimension: &str,
    value: &str,
    amount: i128,
) -> Vec<LegPayload> {
    let mut legs = fixture.legs(fixture.usd, ("6000", "1000"), amount);
    // Deliberately tag only the expense. A dimension report is a leg filter:
    // selecting the whole balanced entry would fabricate a cash contribution.
    legs[0].dimension_set = vec![(
        fa_model::dimension_kind(dimension).unwrap().id,
        fa_model::dimension_value_vid(fixture.book.context().book_id, dimension, value),
    )];
    legs
}

fn portable_dimension_selection(
    selection: fa::TrialBalanceSelection,
    dimension: &str,
    value: &str,
) -> fa::ReportSelection {
    fa::ReportSelection::DimensionTrialBalance {
        selection,
        dimension: dimension.into(),
        value: value.into(),
    }
}

fn verify_dimension_bundle(
    book: &mut Book,
    certified: &fa::CertifiedReport,
    expected_values: &[&str],
    expected_posted: i128,
    expected_pending: i128,
) -> fa_verify::report::VerifiedReport {
    let ReportOutput::DimensionTrialBalance(native) = &certified.report else {
        panic!("the selected native output must be a dimensional trial balance");
    };
    assert_eq!(
        native.values,
        expected_values
            .iter()
            .map(|v| (*v).to_owned())
            .collect::<Vec<_>>()
    );
    let usd = book.context().units.lookup("USD").unwrap().0;
    assert_eq!(native.trial_balance.unit_totals[&usd], (expected_posted, 0));
    assert_eq!(
        native.trial_balance.pending_unit_totals[&usd],
        (expected_pending, 0)
    );
    let certificate = &certified.certificate;
    assert!(
        certificate
            .canonical_bytes()
            .unwrap()
            .starts_with(b"fa:report-certificate:v8")
    );
    let produced = produce(book, certificate);
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .unwrap();
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.output, native.canonical_bytes().unwrap());
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, certificate.known_at.0);
    let filter = verified.dimension.as_ref().unwrap();
    assert_eq!(filter.dimension, native.dimension);
    assert_eq!(filter.value, native.value);
    assert_eq!(filter.values, native.values);
    assert!(verified.statement.is_none());
    assert_eq!(
        verified.rows.len(),
        1,
        "untagged cash must not enter the report"
    );
    let expense = &verified.rows[0];
    assert_eq!(expense.code, "6000");
    assert_eq!(expense.unit, usd);
    assert_eq!(
        (
            expense.debits,
            expense.credits,
            expense.debits_pending,
            expense.credits_pending,
        ),
        (expected_posted, 0, expected_pending, 0)
    );
    verified
}

#[test]
fn dimension_bundles_fold_descendant_legs_and_cross_period_pending_resolutions() {
    use fa::TrialBalanceSelection::{Activity, AsOf, Periods};

    let mut fixture = Fixture::new(0xe4);
    for (dimension, code, parent) in [
        ("cost_center", "TOP", None),
        ("cost_center", "CC10", Some("TOP")),
        ("cost_center", "CC11", Some("CC10")),
        ("cost_center", "OTHER", None),
        ("department", "CC11", None),
    ] {
        declare_report_dimension(&mut fixture, dimension, code, parent);
    }
    for (key, date, dimension, value, amount) in [
        ("root", day(2026, 1, 10), "cost_center", "TOP", 20),
        ("descendant", day(2026, 1, 15), "cost_center", "CC11", 100),
        ("sibling", day(2026, 1, 15), "cost_center", "OTHER", 900),
        ("other-kind", day(2026, 1, 15), "department", "CC11", 800),
        ("next-period", day(2026, 2, 5), "cost_center", "CC10", 30),
    ] {
        let proposal = fixture.proposal(
            date,
            key.as_bytes(),
            EntryClass::ORIGINAL,
            dimension_report_legs(&fixture, dimension, value, amount),
        );
        fixture.commit(proposal);
    }
    let mut hold = fixture.proposal(
        day(2026, 1, 20),
        b"dimension-reservation",
        EntryClass::PENDING,
        dimension_report_legs(&fixture, "cost_center", "CC11", 70),
    );
    hold.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let target = fixture.commit(hold).entry_ref();
    let held_at = fixture.book.head().unwrap();
    let mut resolution = fixture.proposal(
        day(2026, 2, 10),
        b"dimension-partial-post",
        EntryClass::RESOLUTION,
        dimension_report_legs(&fixture, "cost_center", "CC11", 30),
    );
    resolution.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(target),
        disposition: Some(Disposition::Posts {
            source_ordinals: vec![0, 1],
        }),
    });
    fixture.commit(resolution);
    let resolved_at = fixture.book.head().unwrap();

    // Resolution releases the whole original hold at known_at, regardless
    // of its February effective date; only the posted sub-vector moves there.
    for (selection, at, posted, pending) in [
        (Periods(vec![FEBRUARY.into()]), held_at, 150, 70),
        (Periods(vec![FEBRUARY.into()]), resolved_at, 180, 0),
        (Activity(vec![JANUARY.into()]), resolved_at, 120, 0),
        (Activity(vec![FEBRUARY.into()]), resolved_at, 60, 0),
        (AsOf(day(2026, 1, 31)), held_at, 120, 70),
        (AsOf(day(2026, 1, 31)), resolved_at, 120, 0),
    ] {
        let certified = fixture
            .book
            .certify_report(
                portable_dimension_selection(selection, "cost_center", "TOP"),
                Some(at),
            )
            .unwrap()
            .unwrap();
        verify_dimension_bundle(
            &mut fixture.book,
            &certified,
            &["CC10", "CC11", "TOP"],
            posted,
            pending,
        );
    }
    for (dimension, value, amount) in [("cost_center", "OTHER", 900), ("department", "CC11", 800)] {
        let certified = fixture
            .book
            .certify_report(
                portable_dimension_selection(AsOf(day(2026, 1, 31)), dimension, value),
                Some(resolved_at),
            )
            .unwrap()
            .unwrap();
        verify_dimension_bundle(&mut fixture.book, &certified, &[value], amount, 0);
    }
}

#[test]
fn historical_dimension_bundles_do_not_adopt_later_descendants_or_activity() {
    let mut fixture = Fixture::new(0xe5);
    declare_report_dimension(&mut fixture, "cost_center", "TOP", None);
    declare_report_dimension(&mut fixture, "cost_center", "CC10", Some("TOP"));
    let first = fixture.proposal(
        day(2026, 1, 15),
        b"original-dimension-activity",
        EntryClass::ORIGINAL,
        dimension_report_legs(&fixture, "cost_center", "CC10", 100),
    );
    fixture.commit(first);
    let selection = portable_dimension_selection(
        fa::TrialBalanceSelection::AsOf(day(2026, 1, 31)),
        "cost_center",
        "TOP",
    );
    let historical = fixture
        .book
        .certify_report(selection.clone(), None)
        .unwrap()
        .unwrap();
    declare_report_dimension(&mut fixture, "cost_center", "CC11", Some("CC10"));
    let later = fixture.proposal(
        day(2026, 1, 16),
        b"later-descendant-activity",
        EntryClass::ORIGINAL,
        dimension_report_legs(&fixture, "cost_center", "CC11", 50),
    );
    fixture.commit(later);
    let current = fixture
        .book
        .certify_report(selection.clone(), None)
        .unwrap()
        .unwrap();
    // Closing a value governs future posting admission. It must not erase the
    // already recorded tagged legs or descendants from historical reports.
    let schema = fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    fixture
        .book
        .close_dimension_value(
            &fa::dimension::DimensionCloseSpec {
                dimension: "cost_center".into(),
                code: "CC10".into(),
                closed_on: day(2026, 2, 1),
            },
            PRINCIPAL,
            b"close-report-cost-center",
            &schema,
        )
        .unwrap()
        .unwrap();
    let after_close = fixture
        .book
        .certify_report(selection, None)
        .unwrap()
        .unwrap();
    verify_dimension_bundle(&mut fixture.book, &historical, &["CC10", "TOP"], 100, 0);
    verify_dimension_bundle(
        &mut fixture.book,
        &current,
        &["CC10", "CC11", "TOP"],
        150,
        0,
    );
    verify_dimension_bundle(
        &mut fixture.book,
        &after_close,
        &["CC10", "CC11", "TOP"],
        150,
        0,
    );
}

#[test]
fn instant_dimension_bundles_pin_hierarchy_to_resolved_sequence_not_tick_frontier() {
    let mut fixture = Fixture::new(0xe6);
    declare_report_dimension(&mut fixture, "cost_center", "TOP", None);
    declare_report_dimension(&mut fixture, "cost_center", "CC10", Some("TOP"));
    let base = fa_time::UtcInstant::parse("2026-01-15T00:00:00Z")
        .unwrap()
        .unix_ns();
    tick(&mut fixture.book, base + 100, false);
    let first = fixture.proposal(
        day(2026, 1, 15),
        b"dimension-first-bucket",
        EntryClass::ORIGINAL,
        dimension_report_legs(&fixture, "cost_center", "CC10", 40),
    );
    fixture.commit(first);
    let selection = portable_dimension_selection(
        fa::TrialBalanceSelection::Periods(vec![JANUARY.into()]),
        "cost_center",
        "TOP",
    );
    let open = fixture
        .book
        .certify_report_at_instant(selection.clone(), base + 105)
        .unwrap()
        .unwrap();
    tick(&mut fixture.book, base + 110, true);
    declare_report_dimension(&mut fixture, "cost_center", "CC11", Some("CC10"));
    let later = fixture.proposal(
        day(2026, 1, 15),
        b"dimension-later-bucket",
        EntryClass::ORIGINAL,
        dimension_report_legs(&fixture, "cost_center", "CC11", 80),
    );
    fixture.commit(later);
    tick(&mut fixture.book, base + 120, true);
    let closed = fixture
        .book
        .certify_report_at_instant(selection.clone(), base + 105)
        .unwrap()
        .unwrap();
    assert_eq!(open.certificate.known_at, closed.certificate.known_at);
    assert_eq!(open.certificate.output, closed.certificate.output);
    assert!(
        open.certificate
            .time_selection
            .as_ref()
            .unwrap()
            .resolution
            .upper
            .is_none()
    );
    assert!(
        closed
            .certificate
            .time_selection
            .as_ref()
            .unwrap()
            .resolution
            .upper
            .is_some()
    );
    for certified in [&open, &closed] {
        let verified =
            verify_dimension_bundle(&mut fixture.book, certified, &["CC10", "TOP"], 40, 0);
        let time = verified.time_selection.unwrap();
        let native = certified.certificate.time_selection.as_ref().unwrap();
        assert_eq!(time.frontier, native.resolution.frontier);
        assert_eq!(time.resolved_seq, certified.certificate.known_at.0);
        assert_eq!(time.source_grade(), "uncorroborated_daemon_clock");
    }
    let current = fixture
        .book
        .certify_report_at_instant(selection, base + 120)
        .unwrap()
        .unwrap();
    let verified = verify_dimension_bundle(
        &mut fixture.book,
        &current,
        &["CC10", "CC11", "TOP"],
        120,
        0,
    );
    assert_eq!(
        verified.time_selection.unwrap().source_grade(),
        "corroborated_daemon_clock"
    );
}
