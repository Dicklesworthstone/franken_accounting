//! Public revaluation derives signed, cumulative adjustments from retained
//! invoices and closing-rate evidence, then uses the ordinary native plan path.

#![forbid(unsafe_code)]

use fa::{
    Book, BookKeys, Entropy, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms,
    FxRevaluationRequest, FxRevaluationRoute, FxRevaluationRoutesRecorded,
    FxRevaluationRoutesRequest, PreparedFxRevaluation,
};
use fa_intents::{PostIntent, PostPlan};
use fa_journal::fx::{RATE_DOCUMENT_KIND, RATE_EVIDENCE_ROLE};
use fa_journal::refusal::code;
use fa_journal::{
    AccountSpec, BookSpec, DocumentAdded, DocumentRead, PostRequest, Posted, UnitPolicy,
    UploadRequest,
};
use fa_model::entry::FX_REVALUATION_EXTENSION;
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, FxRevaluationBasis,
    Id128, LegPayload, Oid, PeriodRef, account_vid,
};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_policy::Capability;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(1);
const PERIOD: &str = "FY2026-P01";
const RATE_MIME: &str = "application/vnd.franken.fx-rate.v1";

fn day(value: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, value).unwrap()
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn author() -> Capability {
    cap(&["read", "post"])
}

struct Fixture {
    book: Book,
    usd: UnitId,
    eur: UnitId,
    invoice: EvidenceRef,
    routes: FxRevaluationRoutesRecorded,
}

impl Fixture {
    fn new() -> Self {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let mut book = Book::create_memory(
            BookKeys::for_development(0xe9),
            BookSpec {
                book_id: Id128([0xe9; 16]),
                name: "Source-bound functional revaluation".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("fx-revaluation-facade", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(233),
        )
        .unwrap();
        let accounts: Vec<_> = [
            ("1200", AccountType::ASSET, eur),
            ("1290", AccountType::ASSET, usd),
            ("2200", AccountType::LIABILITY, eur),
            ("2290", AccountType::LIABILITY, usd),
            ("4000", AccountType::REVENUE, eur),
            ("4700", AccountType::REVENUE, usd),
            ("6000", AccountType::EXPENSE, eur),
            ("6700", AccountType::EXPENSE, usd),
        ]
        .into_iter()
        .map(|(code, kind, unit)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(matches!(
                kind,
                AccountType::LIABILITY | AccountType::REVENUE
            )),
            is_leaf: true,
            unit_policy: UnitPolicy::Single(unit),
            parent_code: None,
            limit: None,
        })
        .collect();
        let schema = cap(&["read", "schema_change"]);
        book.install_chart(&accounts, PRINCIPAL, day(1), b"revaluation-chart", &schema)
            .unwrap()
            .unwrap();
        book.create_periods(2026, PRINCIPAL, &schema)
            .unwrap()
            .unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"open-revaluation-period",
            &cap(&["close"]),
        )
        .unwrap()
        .unwrap();
        let book_id = book.context().book_id;
        let description = book
            .seal_text("Reviewed monetary exposure destinations")
            .unwrap();
        let routes = book
            .set_fx_revaluation_routes(
                FxRevaluationRoutesRequest {
                    principal: PRINCIPAL,
                    effective_from: day(1),
                    routes: [
                        (
                            account_vid(book_id, "1200"),
                            FxRevaluationRoute {
                                valuation_account: account_vid(book_id, "1290"),
                                unrealized_account: account_vid(book_id, "4700"),
                            },
                        ),
                        (
                            account_vid(book_id, "2200"),
                            FxRevaluationRoute {
                                valuation_account: account_vid(book_id, "2290"),
                                unrealized_account: account_vid(book_id, "6700"),
                            },
                        ),
                    ]
                    .into(),
                    idempotency_key: b"revaluation-routes".to_vec(),
                    description,
                },
                &schema,
            )
            .unwrap()
            .unwrap();
        let document = book
            .upload_document(
                &cap(&["post"]),
                UploadRequest {
                    kind: EvidencePolicy::embedded()
                        .unwrap()
                        .kind_by_name("Invoice")
                        .unwrap()
                        .tag,
                    mime: "text/plain".into(),
                    bytes: b"Retained customer and supplier invoices in EUR".to_vec(),
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
                document_oid: document.oid,
                doc_commit: document.doc_commit,
                role: 1,
            },
            routes,
        }
    }

    fn account(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }

    fn rate(
        &self,
        numerator: u128,
        date: DateDay,
        purpose: FxRatePurpose,
        source: &str,
    ) -> FxRateDocument {
        FxRateDocument::new(
            FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: numerator,
                rate_den: 10,
                rounding: RoundingLaw::HalfEven,
            },
            date,
            1_767_571_200_000_000_000,
            purpose,
            source,
        )
        .unwrap()
    }

    fn upload(&mut self, rate: &FxRateDocument) -> DocumentAdded {
        self.book
            .upload_fx_rate(&cap(&["post"]), rate)
            .unwrap()
            .unwrap()
    }

    fn closing_rate(&mut self, numerator: u128) -> DocumentAdded {
        let rate = self.rate(
            numerator,
            day(31),
            FxRatePurpose::PeriodClose,
            "Retained January closing quote",
        );
        self.upload(&rate)
    }

    fn template(&self, key: &[u8], class: EntryClass, effective_date: DateDay) -> EntryPayload {
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date,
            document_date: None,
            description: self
                .book
                .seal_text("Explicit reviewed functional-currency adjustment")
                .unwrap(),
            effective_period: None,
            legs: Vec::new(),
            control: None,
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: self.invoice.document_oid,
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn post_source(&mut self, key: &[u8], liability: bool, amount: i128) -> EntryRef {
        let spot = self.rate(
            11,
            day(5),
            FxRatePurpose::SpotClose,
            "Original invoice spot quote",
        );
        let rate = self.upload(&spot);
        let mut proposal = self.template(key, EntryClass::ORIGINAL, day(5));
        proposal.legs = if liability {
            vec![
                LegPayload::simple(
                    Side::Debit,
                    self.account("6000"),
                    Amount::new(self.eur, amount),
                ),
                LegPayload::simple(
                    Side::Credit,
                    self.account("2200"),
                    Amount::new(self.eur, amount),
                ),
            ]
        } else {
            vec![
                LegPayload::simple(
                    Side::Debit,
                    self.account("1200"),
                    Amount::new(self.eur, amount),
                ),
                LegPayload::simple(
                    Side::Credit,
                    self.account("4000"),
                    Amount::new(self.eur, amount),
                ),
            ]
        };
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        proposal.evidence.push(self.invoice);
        let valued = self
            .book
            .value_fx_proposal(&author(), proposal, FxLawId::SpotClose, &[rate.oid])
            .unwrap()
            .unwrap();
        self.book
            .post(PostRequest {
                proposal: valued,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            })
            .unwrap()
            .unwrap()
            .entry_ref()
    }

    fn request(&self, source: &str, rate_document: Oid) -> FxRevaluationRequest {
        FxRevaluationRequest {
            period: PERIOD.into(),
            source_account: self.account(source),
            rate_document,
            entity: None,
        }
    }

    fn prepare(&mut self, source: &str, rate: Oid) -> PreparedFxRevaluation {
        let before = self.book.head().unwrap();
        let request = self.request(source, rate);
        let prepared = self
            .book
            .prepare_fx_revaluation(&request, &author())
            .unwrap()
            .unwrap();
        assert_eq!(
            self.book.head().unwrap(),
            before,
            "review publishes nothing"
        );
        assert_eq!(prepared.known_at(), before);
        prepared
    }

    fn proposal(&self, prepared: &PreparedFxRevaluation, key: &[u8]) -> EntryPayload {
        let mut template = self.template(key, EntryClass::REVALUATION, prepared.closing_date());
        template.effective_period = Some(PeriodRef {
            calendar: self.book.context().calendar.id.clone(),
            code: PERIOD.into(),
        });
        prepared.proposal(template).unwrap()
    }

    fn plan(&mut self, proposal: EntryPayload) -> PostPlan {
        let before = self.book.head().unwrap();
        let plan = self
            .book
            .plan(
                PostIntent::new(proposal.clone(), Vec::new()).unwrap(),
                &author(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            self.book.head().unwrap(),
            before,
            "planning publishes nothing"
        );
        assert_eq!(plan.proposal(), &proposal);
        plan
    }

    fn commit(&mut self, prepared: &PreparedFxRevaluation, key: &[u8]) -> (Posted, Vec<u8>) {
        let proposal = self.proposal(prepared, key);
        let plan = self.plan(proposal.clone());
        let portable = plan.canonical_bytes().unwrap();
        let posted = self
            .book
            .commit_plan(PostPlan::decode(&portable).unwrap(), &author())
            .unwrap()
            .unwrap();
        let (entry, recorded_at) = self
            .book
            .read_entry(posted.entry_ref().vid)
            .unwrap()
            .unwrap();
        assert_eq!(entry.proposal, proposal);
        assert_eq!(recorded_at, posted.recorded_at());
        assert!(entry.proposal.evidence.contains(&EvidenceRef {
            document_oid: prepared.basis().rate_document,
            doc_commit: prepared.basis().rate_commit,
            role: RATE_EVIDENCE_ROLE,
        }));
        let raw = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
            .unwrap();
        assert_eq!(
            FxRevaluationBasis::decode(&raw.1).unwrap(),
            *prepared.basis()
        );
        (posted, portable)
    }
}

#[test]
fn retained_asset_and_liability_revaluation_posts_only_the_signed_cumulative_delta() {
    let mut f = Fixture::new();
    let asset_entry = f.post_source(b"customer-invoice", false, 10_000);
    let liability_entry = f.post_source(b"supplier-invoice", true, 10_000);
    let original_asset = f.book.read_entry(asset_entry.vid).unwrap().unwrap();
    let original_liability = f.book.read_entry(liability_entry.vid).unwrap().unwrap();
    let closing = f.closing_rate(12);
    let document = f
        .book
        .read_document_for(&cap(&["read"]), &closing.oid)
        .unwrap()
        .unwrap();
    let DocumentRead::Full(document) = document else {
        panic!("Rate evidence must be fully readable under its governing policy")
    };
    assert_eq!(document.kind, RATE_DOCUMENT_KIND);
    assert_eq!(document.mime, RATE_MIME);
    assert_eq!(
        document.grade,
        EvidencePolicy::embedded()
            .unwrap()
            .grade_by_name("HumanUpload")
            .unwrap()
            .tag
    );
    assert_eq!(document.oid(), closing.oid);
    assert_eq!(document.doc_commit(), closing.doc_commit);
    assert_eq!(
        FxRateDocument::decode(&document.bytes).unwrap().purpose,
        FxRatePurpose::PeriodClose
    );

    let asset = f.prepare("1200", closing.oid);
    assert_eq!(asset.source_native_net(), Amount::new(f.eur, 10_000));
    assert_eq!(asset.source_base_net(), Amount::new(f.usd, 11_000));
    assert_eq!(asset.prior_adjustment_net().mantissa, 0);
    assert_eq!(asset.current_carrying_net().mantissa, 11_000);
    assert_eq!(asset.target_base_net().mantissa, 12_000);
    assert_eq!(asset.delta(), Amount::new(f.usd, 1_000));
    assert_eq!(asset.closing_date(), day(31));
    assert_eq!(asset.basis().rate_document, closing.oid);
    assert_eq!(asset.basis().rate_commit, closing.doc_commit);
    assert_eq!(asset.basis().routes_entry, f.routes.control_entry);
    assert_eq!(asset.basis().routes_digest, f.routes.digest);
    assert_eq!(asset.legs()[0].account_ref, f.account("1290"));
    assert_eq!(asset.legs()[0].side, Side::Debit);
    assert_eq!(asset.legs()[1].account_ref, f.account("4700"));
    assert_eq!(asset.legs()[1].side, Side::Credit);
    assert!(
        asset
            .legs()
            .iter()
            .all(|leg| leg.amount == Amount::new(f.usd, 1_000))
    );
    let (first_adjustment, first_plan) = f.commit(&asset, b"asset-close-120");

    let liability = f.prepare("2200", closing.oid);
    assert_eq!(liability.source_native_net(), Amount::new(f.eur, -10_000));
    assert_eq!(liability.source_base_net(), Amount::new(f.usd, -11_000));
    assert_eq!(liability.current_carrying_net().mantissa, -11_000);
    assert_eq!(liability.target_base_net().mantissa, -12_000);
    assert_eq!(liability.delta(), Amount::new(f.usd, -1_000));
    assert_eq!(liability.legs()[0].account_ref, f.account("2290"));
    assert_eq!(liability.legs()[0].side, Side::Credit);
    assert_eq!(liability.legs()[1].account_ref, f.account("6700"));
    assert_eq!(liability.legs()[1].side, Side::Debit);
    f.commit(&liability, b"liability-close-120");

    for source in ["1200", "2200"] {
        let no_change = f.prepare(source, closing.oid);
        assert!(no_change.is_noop());
        assert!(no_change.legs().is_empty());
        assert_eq!(no_change.delta().mantissa, 0);
        let before = f.book.head().unwrap();
        let mut empty = f.template(b"no-empty-adjustment", EntryClass::REVALUATION, day(31));
        empty.effective_period = Some(PeriodRef {
            calendar: f.book.context().calendar.id.clone(),
            code: PERIOD.into(),
        });
        assert!(no_change.proposal(empty).is_err());
        assert_eq!(f.book.head().unwrap(), before);
    }

    let next_quote = f.closing_rate(13);
    for (source, sign, key) in [
        ("1200", 1, b"asset-close-130".as_slice()),
        ("2200", -1, b"liability-close-130".as_slice()),
    ] {
        let next = f.prepare(source, next_quote.oid);
        assert_eq!(next.source_base_net().mantissa, sign * 11_000);
        assert_eq!(next.prior_adjustment_net().mantissa, sign * 1_000);
        assert_eq!(next.current_carrying_net().mantissa, sign * 12_000);
        assert_eq!(next.target_base_net().mantissa, sign * 13_000);
        assert_eq!(next.delta().mantissa, sign * 1_000);
        f.commit(&next, key);
    }
    let before_retry = f.book.head().unwrap();
    let retried = f
        .book
        .commit_plan(PostPlan::decode(&first_plan).unwrap(), &author())
        .unwrap()
        .unwrap();
    assert!(matches!(retried, Posted::AlreadyRecorded { .. }));
    assert_eq!(retried.entry_ref(), first_adjustment.entry_ref());
    assert_eq!(retried.recorded_at(), first_adjustment.recorded_at());
    assert_eq!(f.book.head().unwrap(), before_retry);
    assert_eq!(
        f.book.read_entry(asset_entry.vid).unwrap().unwrap(),
        original_asset
    );
    assert_eq!(
        f.book.read_entry(liability_entry.vid).unwrap().unwrap(),
        original_liability
    );
    let functional = f
        .book
        .functional_balance_as_of(&cap(&["read"]), day(31), None)
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            functional.total_debits().unwrap(),
            functional.total_credits().unwrap()
        ),
        (26_000, 26_000)
    );
    let native = f.book.balance_as_of(day(31), None).unwrap();
    assert_eq!(native.unit_totals.get(&f.eur.0), Some(&(20_000, 20_000)));
    assert_eq!(native.unit_totals.get(&f.usd.0), Some(&(4_000, 4_000)));
}

#[test]
fn later_foreign_exposure_invalidates_both_saved_review_and_saved_plan() {
    let mut f = Fixture::new();
    f.post_source(b"reviewed-exposure", false, 10_000);
    let closing = f.closing_rate(12);
    let reviewed = f.prepare("1200", closing.oid);
    let proposal = f.proposal(&reviewed, b"stale-revaluation");
    let plan = f.plan(proposal.clone()).canonical_bytes().unwrap();
    f.post_source(b"later-exposure", false, 5_000);
    let before = f.book.head().unwrap();
    let refused = f
        .book
        .commit_plan(PostPlan::decode(&plan).unwrap(), &author())
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED);
    assert_eq!(refused.exit, 6);
    assert_eq!(f.book.head().unwrap(), before);
    let refused = f
        .book
        .post(PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: author(),
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED);
    assert_eq!(f.book.head().unwrap(), before);
    let refreshed = f.prepare("1200", closing.oid);
    assert_ne!(refreshed.source_digest(), reviewed.source_digest());
    assert_eq!(refreshed.source_native_net().mantissa, 15_000);
    assert_eq!(refreshed.current_carrying_net().mantissa, 16_500);
    assert_eq!(refreshed.target_base_net().mantissa, 18_000);
    assert_eq!(refreshed.delta().mantissa, 1_500);
    f.commit(&refreshed, b"fresh-revaluation");
}

#[test]
fn revaluation_refuses_unretained_or_wrong_rate_evidence_without_publication() {
    let mut f = Fixture::new();
    f.post_source(b"rate-evidence-exposure", false, 10_000);
    let valid = f.rate(
        12,
        day(31),
        FxRatePurpose::PeriodClose,
        "Valid retained closing source",
    );
    let valid_rate = f.upload(&valid);
    let mut wrong_date = valid.clone();
    wrong_date.as_of = day(30);
    let mut wrong_purpose = valid.clone();
    wrong_purpose.purpose = FxRatePurpose::SpotClose;
    let mut wrong_rounding = valid.clone();
    wrong_rounding.rounding = RoundingLaw::HalfUp;
    let mut wrong_quote = valid.clone();
    wrong_quote.quote_unit = UnitRegistry::embedded().unwrap().lookup("GBP").unwrap();
    let mut wrong_base = valid.clone();
    wrong_base.base_unit = UnitRegistry::embedded().unwrap().lookup("GBP").unwrap();
    let mut cases = vec![("missing", Oid([0xf9; 32]), code::EVIDENCE_UNKNOWN)];
    for (label, rate) in [
        ("date", wrong_date),
        ("purpose", wrong_purpose),
        ("rounding", wrong_rounding),
        ("quote", wrong_quote),
        ("base", wrong_base),
    ] {
        cases.push((label, f.upload(&rate).oid, code::STRUCTURE));
    }
    for (label, kind, mime, bytes) in [
        (
            "malformed",
            RATE_DOCUMENT_KIND,
            RATE_MIME,
            b"rate=1.20; no canonical source".to_vec(),
        ),
        (
            "kind",
            1,
            RATE_MIME,
            f.rate(
                12,
                day(31),
                FxRatePurpose::PeriodClose,
                "Wrong-kind canonical rate",
            )
            .canonical_bytes()
            .unwrap(),
        ),
        (
            "mime",
            RATE_DOCUMENT_KIND,
            "text/plain",
            f.rate(
                12,
                day(31),
                FxRatePurpose::PeriodClose,
                "Wrong-media canonical rate",
            )
            .canonical_bytes()
            .unwrap(),
        ),
    ] {
        let document = f
            .book
            .upload_document(
                &cap(&["post"]),
                UploadRequest {
                    kind,
                    mime: mime.into(),
                    bytes,
                    asserted_grade: None,
                },
            )
            .unwrap()
            .unwrap();
        cases.push((label, document.oid, code::STRUCTURE));
    }
    for (label, oid, expected) in cases {
        let request = f.request("1200", oid);
        let before = f.book.head().unwrap();
        let refused = f
            .book
            .prepare_fx_revaluation(&request, &author())
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, expected, "{label}: {refused}");
        assert_eq!(f.book.head().unwrap(), before, "{label}");
    }
    assert_eq!(f.prepare("1200", valid_rate.oid).delta().mantissa, 1_000);
}

#[test]
fn governed_redacted_sources_cannot_supply_revaluation_bytes() {
    let mut f = Fixture::new();
    f.post_source(b"governed-source-exposure", false, 10_000);
    let rate = f.rate(
        12,
        day(31),
        FxRatePurpose::PeriodClose,
        "Governed source bytes",
    );
    let bank_kind = EvidencePolicy::embedded()
        .unwrap()
        .kind_by_name("BankStatement")
        .unwrap()
        .tag;
    let governed = f
        .book
        .upload_document(
            &cap(&["post"]),
            UploadRequest {
                kind: bank_kind,
                mime: RATE_MIME.into(),
                bytes: rate.canonical_bytes().unwrap(),
                asserted_grade: None,
            },
        )
        .unwrap()
        .unwrap();
    f.book
        .derive_redacted_view(&cap(&["read", "privileged"]), &governed.oid)
        .unwrap()
        .unwrap();
    let restricted = cap(&["read", "post", "privileged"])
        .with_redaction(1)
        .unwrap();
    assert!(matches!(
        f.book
            .read_document_for(&restricted, &governed.oid)
            .unwrap()
            .unwrap(),
        DocumentRead::Redacted(_)
    ));
    let request = f.request("1200", governed.oid);
    let before = f.book.head().unwrap();
    let refused = f
        .book
        .prepare_fx_revaluation(&request, &restricted)
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CAPABILITY);
    assert_eq!(refused.exit, 7);
    assert_eq!(f.book.head().unwrap(), before);
    let full = cap(&["read", "post", "privileged"]);
    let wrong_kind = f
        .book
        .prepare_fx_revaluation(&request, &full)
        .unwrap()
        .unwrap_err();
    assert_eq!(wrong_kind.code, code::STRUCTURE);
    assert_eq!(f.book.head().unwrap(), before);

    // The current redaction contract governs BankStatement, not Rate. Its
    // presence does not invent a Privileged requirement for a genuine Rate.
    let actual = f.closing_rate(12);
    let request = f.request("1200", actual.oid);
    let ordinary = author().with_redaction(1).unwrap();
    let prepared = f
        .book
        .prepare_fx_revaluation(&request, &ordinary)
        .unwrap()
        .unwrap();
    assert_eq!(prepared.delta().mantissa, 1_000);
    assert_eq!(prepared.basis().rate_document, actual.oid);
}

#[test]
fn current_whole_book_authority_precedes_source_access_and_historical_route_reads() {
    let mut f = Fixture::new();
    let route_pin = f.routes.recorded_at;
    let reader = cap(&["read"]).known_at_most(route_pin);
    let historical = f
        .book
        .fx_revaluation_routes_at(day(31), Some(route_pin), &reader)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(historical.digest, f.routes.digest);
    f.post_source(b"authority-exposure", false, 10_000);
    let closing = f.closing_rate(12);
    let head = f.book.head().unwrap();
    let missing = f.request("1200", Oid([0xfb; 32]));
    for denied in [
        cap(&["read"]),
        cap(&["post"]),
        author().for_accounts(&["1200", "1290", "4700"]).unwrap(),
        author().for_periods(&[PERIOD]).unwrap(),
        author().for_books(&[Id128([0xff; 16])]).unwrap(),
        author().known_at_most(head),
        author().expiring_at(head),
    ] {
        let refused = f
            .book
            .prepare_fx_revaluation(&missing, &denied)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refused.exit, 7,
            "authority must win before unknown source: {refused}"
        );
        assert_eq!(f.book.head().unwrap(), head);
    }
    assert_eq!(
        f.book
            .fx_revaluation_routes_at(day(31), Some(route_pin), &reader)
            .unwrap()
            .unwrap()
            .unwrap(),
        historical
    );
    assert_eq!(
        f.book
            .fx_revaluation_routes_at(day(31), None, &reader)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    assert_eq!(
        f.book
            .fx_revaluation_routes_at(day(31), Some(CommitSeq(head.0 + 1)), &cap(&["read"]))
            .unwrap()
            .unwrap_err()
            .code,
        code::STRUCTURE
    );
    assert_eq!(f.book.head().unwrap(), head);
    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            author().commitment().unwrap(),
            day(5),
            b"revoke-revaluation-author",
            "Withdraw current source authority",
        )
        .unwrap()
        .unwrap();
    let revoked = f.book.head().unwrap();
    let request = f.request("1200", closing.oid);
    assert_eq!(
        f.book
            .prepare_fx_revaluation(&request, &author())
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
    assert_eq!(f.book.head().unwrap(), revoked);
    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            reader.commitment().unwrap(),
            day(5),
            b"revoke-route-history-reader",
            "Withdraw historical route authority",
        )
        .unwrap()
        .unwrap();
    let revoked = f.book.head().unwrap();
    assert_eq!(
        f.book
            .fx_revaluation_routes_at(day(31), Some(route_pin), &reader)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
    assert_eq!(f.book.head().unwrap(), revoked);
}
