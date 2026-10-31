//! Actual group certificates exported by the native producer and recomputed
//! by the std-only verifier, including retained functional valuations and a
//! checkpoint newer than the certified accounting and ownership prefix.

use fa::{Book, BookKeys, Entropy, ReportCertificate, ReportOutput, ReportSelection};
use fa_journal::{AccountSpec, BookSpec, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LEGAL_ENTITY_DIMENSION,
    LegPayload, Oid, OwnershipPct, RelationshipKind, RelationshipSpec, account_vid,
    entity_value_vid, legal_entity_vid,
};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::VId;

const PRINCIPAL: VId = VId(0xc6);
const PERIOD: &str = "FY2026-P01";

fn day(day: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, day).unwrap()
}

fn capability(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Group {
    book: Book,
    usd: UnitId,
    eur: UnitId,
    evidence: EvidenceRef,
    rate: Oid,
}

impl Group {
    fn new(seed: u8) -> Self {
        Self::with_tier(seed, false)
    }

    fn with_tier(seed: u8, tiered: bool) -> Self {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let book_id = Id128([seed; 16]);
        let mut entities = vec![("P", "Parent & Co"), ("S", "Subsidiary")];
        if tiered {
            entities.push(("T", "Lower subsidiary"));
        }
        let spec = BookSpec {
            book_id,
            name: "Portable group with a minority shareholder".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("group-calendar", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: entities
                .into_iter()
                .map(|(code, name)| fa_journal::genesis::LegalEntitySpec {
                    code: code.into(),
                    name: name.into(),
                    functional_unit: usd,
                })
                .collect(),
            opening_date: None,
        };
        let mut book = Book::create_memory(
            BookKeys::for_development(seed),
            spec,
            Entropy::deterministic(u64::from(seed)),
        )
        .unwrap();
        let schema = capability(&["read", "schema_change"]);
        let mut accounts: Vec<_> = [
            ("1000", "Cash", AccountType::ASSET),
            ("1300", "Due from group", AccountType::ASSET),
            ("1500", "Subsidiary investment", AccountType::ASSET),
            ("2300", "Due to group", AccountType::LIABILITY),
            ("3000", "Share capital", AccountType::EQUITY),
            ("3200", "Minority equity", AccountType::EQUITY),
            ("4000", "Sales", AccountType::REVENUE),
            ("5900", "Minority share of income", AccountType::EXPENSE),
        ]
        .into_iter()
        .map(|(code, name, kind)| AccountSpec {
            code: code.into(),
            name: name.into(),
            account_type: kind.0,
            normal_balance: u8::from(matches!(
                kind,
                AccountType::LIABILITY | AccountType::EQUITY | AccountType::REVENUE
            )),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
        if tiered {
            accounts.push(AccountSpec {
                code: "3300".into(),
                name: "Post-acquisition reserves".into(),
                account_type: AccountType::EQUITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            });
        }
        book.install_chart(&accounts, PRINCIPAL, day(1), b"group-chart", &schema)
            .unwrap()
            .unwrap();
        for (code, role) in [
            ("1300", "intercompany"),
            ("2300", "intercompany"),
            ("1500", "investment_in_subsidiary"),
            ("3000", "contributed_capital"),
            ("3200", "noncontrolling_interest"),
            ("5900", "noncontrolling_interest_income"),
        ] {
            book.record_account_role(
                &fa::account_role::AccountRoleSpec {
                    account: account_vid(book_id, code),
                    role: role.into(),
                    assigned: true,
                },
                PRINCIPAL,
                format!("role-{code}").as_bytes(),
                &schema,
            )
            .unwrap()
            .unwrap();
        }
        book.create_periods(2026, PRINCIPAL, &schema)
            .unwrap()
            .unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"open-january",
            &capability(&["close"]),
        )
        .unwrap()
        .unwrap();
        book.record_relationship(
            &RelationshipSpec {
                from: legal_entity_vid(book_id, "P"),
                to: legal_entity_vid(book_id, "S"),
                kind: RelationshipKind::Owns {
                    pct: OwnershipPct::new(4, 5).unwrap(),
                },
                basis: "equity_voting".into(),
                valid_from: day(1),
                valid_to: None,
            },
            PRINCIPAL,
            day(1),
            b"owns-four-fifths",
            &schema,
        )
        .unwrap()
        .unwrap();
        let poster = capability(&["read", "post"]);
        let source = book
            .upload_document(
                &poster,
                fa_journal::UploadRequest {
                    kind: 21,
                    mime: "text/plain".into(),
                    bytes: b"Reviewed group capital, intercompany advance and subsidiary sales"
                        .to_vec(),
                    asserted_grade: None,
                },
            )
            .unwrap()
            .unwrap();
        let evidence = EvidenceRef {
            document_oid: source.oid,
            doc_commit: source.doc_commit,
            role: 1,
        };
        let rate = fa::FxRateDocument::new(
            fa::FxRateTerms {
                base_unit: usd,
                quote_unit: eur,
                rate_num: 3,
                rate_den: 2,
                rounding: RoundingLaw::HalfEven,
            },
            day(15),
            1_768_435_200_000_000_000,
            fa::FxRatePurpose::SpotClose,
            "retained group sales rate",
        )
        .unwrap();
        let rate = book.upload_fx_rate(&poster, &rate).unwrap().unwrap().oid;
        let mut group = Self {
            book,
            usd,
            eur,
            evidence,
            rate,
        };
        group.transfer("parent-capital", "P", "1000", "3000", usd, 2_000_000);
        group.transfer("subsidiary-capital", "S", "1000", "3000", usd, 1_000_000);
        group.transfer("parent-investment", "P", "1500", "1000", usd, 800_000);
        group.transfer("parent-advance", "P", "1300", "1000", usd, 100_000);
        group.transfer("subsidiary-advance", "S", "1000", "2300", usd, 100_000);
        group.transfer("subsidiary-usd-sales", "S", "1000", "4000", usd, 20_000);
        group.transfer("subsidiary-eur-sales", "S", "1000", "4000", eur, 501);
        if tiered {
            group
                .book
                .record_relationship(
                    &RelationshipSpec {
                        from: legal_entity_vid(book_id, "S"),
                        to: legal_entity_vid(book_id, "T"),
                        kind: RelationshipKind::Owns {
                            pct: OwnershipPct::new(3, 4).unwrap(),
                        },
                        basis: "equity_voting".into(),
                        valid_from: day(1),
                        valid_to: None,
                    },
                    PRINCIPAL,
                    day(1),
                    b"lower-owns-three-quarters",
                    &schema,
                )
                .unwrap()
                .unwrap();
            group.transfer("lower-capital", "T", "1000", "3000", usd, 200_000);
            group.transfer("subsidiary-investment", "S", "1500", "1000", usd, 150_000);
            group.transfer("subsidiary-reserves", "S", "1000", "3300", usd, 4_000);
            group.transfer("lower-reserves", "T", "1000", "3300", usd, 8_000);
            group.transfer("lower-usd-sales", "T", "1000", "4000", usd, 10_000);
            group.transfer("lower-eur-sales", "T", "1000", "4000", eur, 503);
        }
        group
    }

    fn transfer(
        &mut self,
        key: &str,
        entity: &str,
        debit: &str,
        credit: &str,
        unit: UnitId,
        amount: i128,
    ) {
        let book_id = self.book.context().book_id;
        let legs = [(Side::Debit, debit), (Side::Credit, credit)]
            .into_iter()
            .map(|(side, account)| {
                let mut leg = LegPayload::simple(
                    side,
                    account_vid(book_id, account),
                    Amount::new(unit, amount),
                );
                leg.dimension_set =
                    vec![(LEGAL_ENTITY_DIMENSION, entity_value_vid(book_id, entity))];
                leg
            })
            .collect::<Vec<_>>();
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(15),
            document_date: None,
            description: self.book.seal_text(key).unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: self.evidence.document_oid,
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let poster = capability(&["read", "post"]);
        let proposal = if unit == self.eur {
            self.book
                .value_fx_proposal(&poster, proposal, fa::FxLawId::SpotClose, &[self.rate])
                .unwrap()
                .unwrap()
        } else {
            proposal
        };
        self.book
            .post(PostRequest {
                proposal,
                approvals: Vec::new(),
                capability: poster,
                plan_certificate: None,
            })
            .unwrap()
            .unwrap();
    }

    fn checkpoint(&mut self) {
        let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        runtime
            .block_on(self.book.record_tick(
                &root,
                1_769_904_000_000_000_000,
                false,
                &capability(&["witness"]),
            ))
            .unwrap()
            .unwrap();
        self.book
            .checkpoint(PRINCIPAL, &capability(&["read", "produce", "witness"]))
            .unwrap()
            .unwrap();
    }
}

fn line(statement: &fa::Statement, unit: UnitId, code: &str) -> i128 {
    statement
        .lines
        .iter()
        .find(|line| line.unit_id == unit.0 && line.code == code)
        .unwrap()
        .amounts[0]
}

fn assert_json_check(output: &str, name: &str, fields: &[&str]) {
    // Keep every assertion within the same check so a value in another unit,
    // statement or elimination cannot satisfy the expected accounting result.
    let prefix = format!("\"{name}\",");
    assert!(
        output.split("{\"check\":").skip(1).any(|check| {
            check.starts_with(&prefix)
                && check.contains("\"result\":\"pass\"")
                && fields.iter().all(|field| check.contains(field))
        }),
        "missing passing {name} with {fields:?}: {output}"
    );
}

fn assert_portable(book: &mut Book, certificate: &ReportCertificate, rate: Option<Oid>) {
    let producer = capability(&["read", "produce"]);
    let before = book.head().unwrap();
    let first = book
        .produce_report_bundle(PRINCIPAL, &producer, None, certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let second = book
        .produce_report_bundle(PRINCIPAL, &producer, None, certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.bundle.bytes, second.bundle.bytes);
    assert_eq!(first.receipt, second.receipt);
    assert_eq!(first.documents, rate.into_iter().collect::<Vec<_>>());
    let verified = fa_verify::report::verify_report_expected(
        &first.bundle.bytes,
        &[book.checkpoint_public_key()],
        None,
        Some(&first.receipt),
        Some(&certificate.digest),
    )
    .unwrap();
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.output_digest, certificate.output_digest);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.periods, [PERIOD]);
    assert!(verified.consolidation.is_some());
    assert!(verified.checkpoint.checkpoint.through_seq > certificate.known_at.0);

    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "group.bundle".into(),
            "--key".into(),
            book.checkpoint_public_key()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            "--receipt".into(),
            "group.receipt".into(),
            "--expect".into(),
            certificate
                .digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            "--json".into(),
        ],
        &|path| match path {
            "group.bundle" => Ok(first.bundle.bytes.clone()),
            "group.receipt" => Ok(first.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unexpected input {path}"),
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}\n{}", command.stdout, command.stderr);
    assert!(command.stderr.is_empty());
    let json = &command.stdout;
    let functional = match &certificate.selection {
        ReportSelection::Consolidation { .. } => false,
        ReportSelection::FunctionalConsolidation { .. } => true,
        _ => panic!("expected a group certificate"),
    };
    let (mode, basis, total_equity, nci_equity, controlling_equity, income) = if functional {
        (
            "functional_consolidation",
            "retained-base-amounts",
            "2220752",
            "204150",
            "2016602",
            "16602",
        )
    } else {
        (
            "consolidation",
            "native-units",
            "2220000",
            "204000",
            "2016000",
            "16000",
        )
    };
    let units = UnitRegistry::embedded().unwrap();
    let usd = units.lookup("USD").unwrap();
    let usd_json = format!("\"unit\":{},", usd.0);
    assert_json_check(
        json,
        "report_bundle",
        &[&format!("\"report_mode\":\"{mode}\"")],
    );
    assert_json_check(
        json,
        "consolidation_basis",
        &[
            "\"period\":\"FY2026-P01\"",
            &format!("\"valuation_basis\":\"{basis}\""),
            "\"rounding_law\":\"HalfEven\"",
            "\"ownership_and_roles\":\"authenticated historical journal controls\"",
            "\"genesis_registration\":\"not_judged\"",
            "\"registry_activation\":\"not_judged\"",
            "\"economic_truth\":\"not_judged\"",
        ],
    );
    assert_json_check(
        json,
        "consolidation_member",
        &[
            "\"entity\":\"S\"",
            "\"name\":\"Subsidiary\"",
            "\"parent\":\"P\"",
            "\"ownership_bps\":8000}",
        ],
    );
    assert_json_check(
        json,
        "consolidation_elimination_leg",
        &[
            "\"column\":\"stock\"",
            &format!(
                "\"account\":\"{:032x}\"",
                account_vid(certificate.book_id, "1300").0
            ),
            &usd_json,
            "\"debits\":\"0\"",
            "\"credits\":\"100000\"",
        ],
    );
    assert_json_check(
        json,
        "consolidation_equity_reconciliation",
        &[
            &usd_json,
            "\"parent_total_equity\":\"2000000\"",
            &format!("\"noncontrolling_interest_equity\":\"{nci_equity}\""),
            &format!("\"controlling_interest_equity\":\"{controlling_equity}\""),
            &format!("\"consolidated_total_equity\":\"{total_equity}\""),
        ],
    );
    for (definition, kind) in [
        ("balance-sheet", "BalanceSheet"),
        ("income-statement", "IncomeStatement"),
    ] {
        assert_json_check(
            json,
            "statement_parameters",
            &[
                &format!("\"definition\":\"{definition}\""),
                &format!("\"kind\":\"{kind}\""),
                "\"unit_universe_source\":\"authenticated-registry\"",
            ],
        );
    }
    for (code, amount) in [
        ("assets", total_equity),
        ("total_equity", total_equity),
        ("balance_check", "0"),
        ("net_income", income),
    ] {
        assert_json_check(
            json,
            "statement_line",
            &[
                &format!("\"code\":\"{code}\""),
                &usd_json,
                &format!("\"amounts\":[\"{amount}\"]"),
            ],
        );
    }
    if !functional {
        let eur_json = format!("\"unit\":{},", units.lookup("EUR").unwrap().0);
        assert_json_check(
            json,
            "statement_line",
            &[
                "\"code\":\"net_income\"",
                &eur_json,
                "\"amounts\":[\"401\"]",
            ],
        );
        assert_json_check(
            json,
            "consolidation_equity_reconciliation",
            &[
                &eur_json,
                "\"noncontrolling_interest_equity\":\"100\"",
                "\"consolidated_total_equity\":\"501\"",
            ],
        );
    }
    assert_eq!(
        book.head().unwrap(),
        before,
        "producing a group proof publishes nothing"
    );
    let mut wrong_certificate = certificate.digest;
    wrong_certificate[0] ^= 1;
    assert!(
        fa_verify::report::verify_report_expected(
            &first.bundle.bytes,
            &[book.checkpoint_public_key()],
            None,
            Some(&first.receipt),
            Some(&wrong_certificate),
        )
        .is_err()
    );
}

#[test]
fn native_and_functional_group_bundles_recompute_old_prefix_after_later_activity_and_role_changes()
{
    let mut group = Group::new(0xc6);
    let producer = capability(&["read", "produce"]);
    let pin = group.book.head().unwrap();
    let native = group
        .book
        .certify_report(
            ReportSelection::Consolidation {
                period: PERIOD.into(),
            },
            Some(pin),
        )
        .unwrap()
        .unwrap();
    let ReportOutput::Consolidation(native_group) = &native.report else {
        panic!("native group");
    };
    assert_eq!(
        line(&native_group.run.income_statement, group.usd, "net_income"),
        16_000
    );
    assert_eq!(
        line(&native_group.run.income_statement, group.eur, "net_income"),
        401
    );
    assert_eq!(native_group.members[1].ownership_bps, Some(8_000));
    assert!(!native_group.run.eliminations.is_empty());
    let functional = group
        .book
        .certify_functional_consolidation(PRINCIPAL, &producer, PERIOD, Some(pin))
        .unwrap()
        .unwrap();
    let ReportOutput::FunctionalConsolidation(functional_group) = &functional.report else {
        panic!("functional group");
    };
    assert_eq!(functional_group.base_unit, group.usd);
    assert_eq!(
        line(
            &functional_group.group.run.income_statement,
            group.usd,
            "net_income"
        ),
        16_602
    );
    assert_eq!(
        functional_group.group.run.equity_reconciliations[0].non_controlling_interest_equity,
        204_150
    );
    assert_eq!(
        functional_group.group.run.equity_reconciliations[0].consolidated_total_equity,
        2_220_752
    );
    assert_eq!(group.book.head().unwrap(), pin, "certification is a read");

    for certificate in [&native.certificate, &functional.certificate] {
        group
            .book
            .retain_certificate(PRINCIPAL, &producer, certificate)
            .unwrap()
            .unwrap();
        let loaded = group
            .book
            .read_certificate(&certificate.digest)
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded.canonical_bytes().unwrap(),
            certificate.canonical_bytes().unwrap()
        );
    }
    group.transfer(
        "later-backdated-sales",
        "S",
        "1000",
        "4000",
        group.usd,
        7_777,
    );
    group
        .book
        .record_account_role(
            &fa::account_role::AccountRoleSpec {
                account: account_vid(group.book.context().book_id, "3200"),
                role: "noncontrolling_interest".into(),
                assigned: false,
            },
            PRINCIPAL,
            b"later-nci-role-removal",
            &capability(&["read", "schema_change"]),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        group
            .book
            .consolidation(PERIOD, None, &capability(&["read"]))
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-194"
    );
    group.checkpoint();
    assert_portable(&mut group.book, &native.certificate, None);
    assert_portable(&mut group.book, &functional.certificate, Some(group.rate));
}

#[test]
fn group_production_checks_current_whole_book_authority_before_certificate_or_checkpoint() {
    let mut group = Group::new(0xc7);
    let certificate = group
        .book
        .certify_report(
            ReportSelection::Consolidation {
                period: PERIOD.into(),
            },
            None,
        )
        .unwrap()
        .unwrap()
        .certificate;
    let before = group.book.head().unwrap();
    let mut changed = certificate.clone();
    changed.digest[0] ^= 1;
    let mut foreign = certificate.clone();
    foreign.book_id = Id128([0xff; 16]);
    for denied in [
        capability(&["read"]),
        capability(&["read", "produce"])
            .for_accounts(&["1000"])
            .unwrap(),
        capability(&["read", "produce"])
            .for_periods(&[PERIOD])
            .unwrap(),
        capability(&["read", "produce"]).known_at_most(before),
    ] {
        let mut original = None;
        for source in [&certificate, &changed, &foreign] {
            for checkpoint in [None, Some(Oid([0xff; 32]))] {
                let refusal = group
                    .book
                    .produce_report_bundle(PRINCIPAL, &denied, checkpoint, source)
                    .unwrap()
                    .unwrap_err();
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
                if let Some(expected) = &original {
                    assert_eq!(&refusal, expected);
                } else {
                    original = Some(refusal);
                }
            }
        }
    }
    assert_eq!(group.book.head().unwrap(), before);
}

#[test]
fn tiered_group_native_and_functional_reports_replay_and_verify_offline_after_source_changes() {
    let mut group = Group::with_tier(0xc8, true);
    let producer = capability(&["read", "produce"]);
    let pin = group.book.head().unwrap();
    let native = group
        .book
        .certify_report(
            ReportSelection::Consolidation {
                period: PERIOD.into(),
            },
            Some(pin),
        )
        .unwrap()
        .unwrap();
    let functional = group
        .book
        .certify_functional_consolidation(PRINCIPAL, &producer, PERIOD, Some(pin))
        .unwrap()
        .unwrap();
    let ReportOutput::Consolidation(native_group) = &native.report else {
        panic!("native three-level group");
    };
    let ReportOutput::FunctionalConsolidation(functional_group) = &functional.report else {
        panic!("functional three-level group");
    };
    // Native USD: 250,000 minority capital + 4,000 reserves + 8,000 earnings.
    // EUR: T's 503 => controlling377/NCI126; S's (501+377) => controlling702/NCI176.
    for (unit, total, minority, earnings) in [
        (group.usd, 2_292_000, 262_000, 22_000),
        (group.eur, 1_004, 302, 702),
    ] {
        let equity = native_group
            .run
            .equity_reconciliations
            .iter()
            .find(|row| row.unit_id == unit.0)
            .unwrap();
        assert_eq!(equity.consolidated_total_equity, total);
        assert_eq!(equity.non_controlling_interest_equity, minority);
        assert_eq!(
            line(&native_group.run.income_statement, unit, "net_income"),
            earnings
        );
        assert_eq!(
            line(&native_group.run.balance_sheet, unit, "balance_check"),
            0
        );
    }
    // The retained EUR valuations are 752 and 754 USD minor units. T's
    // 10,754 earnings yields controlling8066, then S's 28,818 yields23054.
    let functional_eq = &functional_group.group.run.equity_reconciliations[0];
    assert_eq!(functional_eq.consolidated_total_equity, 2_293_506);
    assert_eq!(functional_eq.non_controlling_interest_equity, 262_452);
    assert_eq!(functional_eq.controlling_interest_equity, 2_031_054);
    assert_eq!(
        line(
            &functional_group.group.run.income_statement,
            group.usd,
            "net_income"
        ),
        23_054
    );

    for certificate in [&native.certificate, &functional.certificate] {
        group
            .book
            .retain_certificate(PRINCIPAL, &producer, certificate)
            .unwrap()
            .unwrap();
        assert!(matches!(
            group.book.certificate_status(certificate).unwrap().unwrap(),
            fa::CertificateStatus::Current { .. }
        ));
    }
    // A later descendant posting changes the current result, but cannot
    // change either historical certificate's rounded intermediate shares.
    group.transfer("later-lower-sales", "T", "1000", "4000", group.usd, 333);
    for certificate in [&native.certificate, &functional.certificate] {
        assert!(matches!(
            group.book.certificate_status(certificate).unwrap().unwrap(),
            fa::CertificateStatus::SupersededBy { .. }
        ));
    }
    // A second active parent makes today's group ambiguous. Historical
    // replay and its portable closure must use the original single-parent graph.
    let book_id = group.book.context().book_id;
    group
        .book
        .record_relationship(
            &RelationshipSpec {
                from: legal_entity_vid(book_id, "P"),
                to: legal_entity_vid(book_id, "T"),
                kind: RelationshipKind::Owns {
                    pct: OwnershipPct::new(1, 5).unwrap(),
                },
                basis: "equity_voting".into(),
                valid_from: day(1),
                valid_to: None,
            },
            PRINCIPAL,
            day(1),
            b"later-ambiguous-lower-parent",
            &capability(&["read", "schema_change"]),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        group
            .book
            .consolidation(PERIOD, None, &capability(&["read"]))
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-194"
    );
    group.checkpoint();
    for certificate in [&native.certificate, &functional.certificate] {
        let replayed = group.book.replay_report(certificate).unwrap().unwrap();
        assert_eq!(replayed.canonical_bytes().unwrap(), certificate.output);
        let produced = group
            .book
            .produce_report_bundle(PRINCIPAL, &producer, None, certificate)
            .unwrap()
            .unwrap()
            .unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[group.book.checkpoint_public_key()],
            None,
            Some(&produced.receipt),
            Some(&certificate.digest),
        )
        .unwrap();
        assert_eq!(verified.output, certificate.output);
        assert_eq!(verified.known_at, pin.0);
        assert!(verified.consolidation.is_some());
        assert!(verified.checkpoint.checkpoint.through_seq > pin.0);
        let mut tampered = produced.bundle.bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            fa_verify::report::verify_report_expected(
                &tampered,
                &[group.book.checkpoint_public_key()],
                None,
                Some(&produced.receipt),
                Some(&certificate.digest),
            )
            .is_err()
        );
    }
}
