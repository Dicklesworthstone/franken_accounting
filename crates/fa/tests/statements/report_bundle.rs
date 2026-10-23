//! Outsider verification of real native statements. The verifier receives
//! exported bytes and a separately chosen key/checkpoint; it never reads the
//! source book or calls the statement producer's arithmetic.

use super::*;

fn unit_ids(book: &Book) -> Vec<u32> {
    book.context().units.iter().map(|(id, _)| id.0).collect()
}

fn produce(book: &mut Book, certificate: &ReportCertificate) -> fa::ProducedBundle {
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
    let verified = fa_verify::report::verify_statement_report(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        &unit_ids(book),
    )
    .expect("the independently authenticated journal must reproduce every statement byte");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert!(verified.statement.is_some());
    assert!(verified.receipt.is_some());
    assert!(
        verified.rows.is_empty(),
        "statement lines are not trial-balance rows"
    );
    verified
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
            .retain_certificate(&certified.certificate)
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

fn reseal(certificate: &mut ReportCertificate) {
    certificate.output_digest =
        fa_verify::blake3::hash_parts(b"fa:report-output:v1", &[&certificate.output]);
    let body = certificate.canonical_bytes().unwrap();
    assert!(body.starts_with(fa::certificate::STATEMENT_CERTIFICATE_FORMAT));
    certificate.digest = fa_verify::blake3::hash_parts(
        fa::certificate::STATEMENT_CERTIFICATE_FORMAT,
        &[&body[..body.len() - 32]],
    );
    // Ensure a negative vector is internally consistent, so rejection must
    // come from report recomputation, not a broken certificate checksum.
    assert_eq!(
        ReportCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap(),
        *certificate
    );
}

fn replace_certificate(bundle: &[u8], certificate: &ReportCertificate) -> Vec<u8> {
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
        // No receipt is supplied here: exercise the verifier even when a
        // hostile producer has resealed its own certificate and output.
        assert!(
            fa_verify::report::verify_statement_report(&changed, &[key], None, None, &units)
                .is_err(),
            "accepted {corruption} forgery"
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
        fa_verify::report::verify_statement_report(&modified, &[key], None, None, &units)
            .unwrap_err()
            .predicate,
        "record_derivation"
    );
    let mut omitted = produced.bundle.bytes.clone();
    omitted.drain(at..at + source.len());
    assert!(
        fa_verify::report::verify_statement_report(&omitted, &[key], None, None, &units).is_err()
    );
    assert_eq!(
        fa_verify::report::verify_statement_report(&produced.bundle.bytes, &[], None, None, &units)
            .unwrap_err()
            .predicate,
        "checkpoint_signature"
    );
    assert_eq!(
        fa_verify::report::verify_report(&produced.bundle.bytes, &[key], None, None)
            .unwrap_err()
            .predicate,
        "statement_units",
        "a statement's registered unit universe is an explicit recipient premise"
    );
    let missing_unit: Vec<_> = units.iter().copied().filter(|unit| *unit != eur).collect();
    assert!(
        fa_verify::report::verify_statement_report(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            &missing_unit,
        )
        .is_err(),
        "omitting a zero-activity recipient unit changes the complete report"
    );
}
