//! Real retained rate evidence and posted invoices exercise the FX facade.
//! Expected functional amounts are literal, independent of the planner.

#![forbid(unsafe_code)]

use fa::{Book, BookError, BookKeys, Entropy, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms};
use fa_journal::fx::{RATE_DOCUMENT_KIND, RATE_EVIDENCE_ROLE};
use fa_journal::refusal::code;
use fa_journal::{AccountSpec, BookSpec, DocumentRead, PostRequest, UnitPolicy, UploadRequest};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_policy::{Capability, Op, Profile};
use fa_registers::{FunctionalCellKey, FunctionalFold, RegisterError};
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

fn grade(name: &str) -> u8 {
    EvidencePolicy::embedded()
        .unwrap()
        .grade_by_name(name)
        .unwrap()
        .tag
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
        let spec = BookSpec {
            book_id: Id128([0xf3; 16]),
            name: "Retained FX facade".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("fx-facade", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let mut book = Book::create_memory(
            BookKeys::for_development(0xf3),
            spec,
            Entropy::deterministic(243),
        )
        .unwrap();
        let accounts: Vec<_> = [("1200", AccountType::ASSET), ("4000", AccountType::REVENUE)]
            .into_iter()
            .map(|(account, kind)| AccountSpec {
                code: account.into(),
                name: account.into(),
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
            day(1),
            b"fx-chart",
            &cap(&["schema_change"]),
        )
        .unwrap()
        .unwrap();
        book.create_periods(2026, PRINCIPAL, &cap(&["schema_change"]))
            .unwrap()
            .unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"fx-open",
            &cap(&["close"]),
        )
        .unwrap()
        .unwrap();
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
                    bytes: b"Customer invoice: EUR 100.00 on 2026-01-05".to_vec(),
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

    fn proposal(&self, key: &[u8]) -> EntryPayload {
        let book_id = self.book.context().book_id;
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "1200"),
                Amount::new(self.eur, 10_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "4000"),
                Amount::new(self.eur, 10_000),
            ),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(5),
            document_date: None,
            description: self.book.seal_text("Foreign customer invoice").unwrap(),
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

    fn rate(&self, numerator: u128, source: &str) -> FxRateDocument {
        FxRateDocument::new(
            FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: numerator,
                rate_den: 10,
                rounding: RoundingLaw::HalfEven,
            },
            day(5),
            1_767_571_200_000_000_000,
            FxRatePurpose::SpotClose,
            source,
        )
        .unwrap()
    }

    fn upload_rate(&mut self, rate: &FxRateDocument) -> Oid {
        self.book
            .upload_fx_rate(&cap(&["post"]), rate)
            .unwrap()
            .unwrap()
            .oid
    }

    fn value(&mut self, proposal: EntryPayload, rate: Oid) -> EntryPayload {
        let head = self.book.head().unwrap();
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
        assert_eq!(self.book.head().unwrap(), head);
        valued
    }

    fn activity(&mut self, known_at: Option<CommitSeq>) -> FunctionalFold {
        let head = self.book.head().unwrap();
        let result = self
            .book
            .functional_period_activity(&cap(&["read"]), PERIOD, known_at)
            .unwrap()
            .unwrap();
        assert_eq!(self.book.head().unwrap(), head);
        result
    }
}

fn post_request(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: Vec::new(),
        capability: cap(&["post"]),
        plan_certificate: None,
    }
}

#[test]
fn retained_rate_values_a_real_invoice_without_revaluing_history() {
    let mut f = Fixture::new();
    let rate = f.rate(11, "Uploader supplied January 5 close");
    let before_upload = f.book.head().unwrap();
    let receipt = f
        .book
        .upload_fx_rate(&cap(&["post"]), &rate)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.oid, rate.oid(f.book.context().book_id).unwrap());
    assert_eq!(receipt.doc_commit, rate.doc_commit().unwrap());
    assert_eq!(receipt.grade, grade("HumanUpload"));
    assert!(receipt.recorded_at > before_upload);
    assert_eq!(f.book.custody_chain(&receipt.oid).unwrap().len(), 1);
    let DocumentRead::Full(document) = f
        .book
        .read_document_for(&cap(&["read"]), &receipt.oid)
        .unwrap()
        .unwrap()
    else {
        panic!("ordinary retained Rate evidence must be fully readable");
    };
    assert_eq!(document.kind, RATE_DOCUMENT_KIND);
    assert_eq!(document.mime, RATE_MIME);
    assert_eq!(document.retrieved_by, PRINCIPAL);
    assert_eq!(document.bytes, rate.canonical_bytes().unwrap());
    assert_eq!(FxRateDocument::decode(&document.bytes).unwrap(), rate);

    let proposal = f.proposal(b"foreign-invoice-one");
    let native_totals = proposal.unit_totals.clone();
    let valued = f.value(proposal, receipt.oid);
    assert_eq!(valued.unit_totals, native_totals);
    assert_eq!(valued.legs.len(), 2);
    for leg in &valued.legs {
        assert_eq!(leg.amount, Amount::new(f.eur, 10_000));
        assert_eq!(leg.base_amount, Some(Amount::new(f.usd, 11_000)));
    }
    let totals = valued.base_totals.as_ref().unwrap();
    assert_eq!((totals.debits, totals.credits), (11_000, 11_000));
    assert_eq!(totals.fx_law_oid, FxLawId::SpotClose.oid());
    assert_eq!(totals.rate_doc_oids, [receipt.oid]);
    assert_eq!(totals.residual, None);
    assert!(valued.evidence.contains(&EvidenceRef {
        document_oid: receipt.oid,
        doc_commit: receipt.doc_commit,
        role: RATE_EVIDENCE_ROLE,
    }));
    let before_post = f.book.head().unwrap();
    let posted = f.book.post(post_request(valued.clone())).unwrap().unwrap();
    let (entry, recorded_at) = f.book.read_entry(posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(recorded_at, posted.recorded_at());
    assert_eq!(entry.proposal, valued);
    let historical = f.activity(Some(posted.recorded_at()));
    assert_eq!(historical.entries, 1);
    assert_eq!(historical.total_debits().unwrap(), 11_000);
    assert_eq!(historical.total_credits().unwrap(), 11_000);
    assert!(historical.pending.is_empty());
    let receivable = historical
        .cell(&FunctionalCellKey {
            account: account_vid(f.book.context().book_id, "1200"),
            unit_id: f.usd.0,
            period: PERIOD.into(),
            entity: None,
        })
        .unwrap();
    assert_eq!((receivable.debits, receivable.credits), (11_000, 0));
    assert_eq!(f.activity(Some(before_post)).total_debits().unwrap(), 0);

    let revised_rate = f.rate(12, "Later independently uploaded close");
    let revised_oid = f.upload_rate(&revised_rate);
    let after_rate = f.activity(None);
    assert_eq!(after_rate.total_debits().unwrap(), 11_000);
    assert_eq!(after_rate.fold_digest, historical.fold_digest);
    let proposal = f.proposal(b"foreign-invoice-two");
    let second = f.value(proposal, revised_oid);
    f.book.post(post_request(second)).unwrap().unwrap();
    let current = f.activity(None);
    assert_eq!(current.entries, 2);
    assert_eq!(current.total_debits().unwrap(), 23_000);
    assert_eq!(current.total_credits().unwrap(), 23_000);
    assert_eq!(f.activity(Some(posted.recorded_at())), historical);
}

#[test]
fn posting_recomputes_a_balanced_but_false_functional_valuation() {
    let mut f = Fixture::new();
    let rate = f.rate(11, "Original posted rate");
    let oid = f.upload_rate(&rate);
    let proposal = f.proposal(b"tampered-functional-amount");
    let correct = f.value(proposal, oid);
    let mut forged = correct.clone();
    for leg in &mut forged.legs {
        leg.base_amount = Some(Amount::new(f.usd, 11_100));
    }
    let totals = forged.base_totals.as_mut().unwrap();
    totals.debits = 11_100;
    totals.credits = 11_100;
    let before = f.book.head().unwrap();
    let denied = f.book.post(post_request(forged)).unwrap().unwrap_err();
    assert_eq!(denied.code, code::UNBALANCED);
    assert_eq!(f.book.head().unwrap(), before);
    f.book.post(post_request(correct)).unwrap().unwrap();
    assert_eq!(f.activity(None).total_debits().unwrap(), 11_000);
}

#[test]
fn period_average_requires_the_posting_periods_last_included_date() {
    let mut f = Fixture::new();
    let mut average = f.rate(11, "Uploaded January period average");
    average.purpose = FxRatePurpose::PeriodAverage;
    average.as_of = day(31);
    let oid = f.upload_rate(&average);
    let proposal = f.proposal(b"january-average-invoice");
    let before = f.book.head().unwrap();
    let valued = f
        .book
        .value_fx_proposal(
            &cap(&["read", "post"]),
            proposal,
            FxLawId::PeriodAverage,
            &[oid],
        )
        .unwrap()
        .unwrap();
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(valued.effective_date, day(5));
    let totals = valued.base_totals.as_ref().unwrap();
    assert_eq!(totals.fx_law_oid, FxLawId::PeriodAverage.oid());
    assert_eq!(totals.rate_doc_oids, [oid]);
    assert_eq!((totals.debits, totals.credits), (11_000, 11_000));
    for leg in &valued.legs {
        assert_eq!(leg.amount, Amount::new(f.eur, 10_000));
        assert_eq!(leg.base_amount, Some(Amount::new(f.usd, 11_000)));
    }
    f.book.post(post_request(valued)).unwrap().unwrap();
    assert_eq!(f.activity(None).total_debits().unwrap(), 11_000);

    for date in [day(30), DateDay::from_ymd(2026, 2, 28).unwrap()] {
        let mut wrong_period = average.clone();
        wrong_period.as_of = date;
        let oid = f.upload_rate(&wrong_period);
        let before = f.book.head().unwrap();
        let proposal = f.proposal(b"wrong-average-period");
        let denied = f
            .book
            .value_fx_proposal(
                &cap(&["read", "post"]),
                proposal,
                FxLawId::PeriodAverage,
                &[oid],
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(denied.code, code::STRUCTURE, "{}", date.render());
        assert_eq!(f.book.head().unwrap(), before);
    }
}

#[test]
fn valuation_refuses_missing_malformed_or_inapplicable_rate_evidence() {
    let mut f = Fixture::new();
    let valid = f.rate(11, "Valid quote");
    let valid_oid = f.upload_rate(&valid);
    let mut wrong_date = f.rate(11, "Previous day quote");
    wrong_date.as_of = day(4);
    let wrong_date_oid = f.upload_rate(&wrong_date);
    let mut wrong_purpose = f.rate(11, "Period close is not an invoice spot quote");
    wrong_purpose.purpose = FxRatePurpose::PeriodClose;
    let wrong_purpose_oid = f.upload_rate(&wrong_purpose);
    let duplicate = f.rate(12, "Competing quote for the same currency");
    let duplicate_oid = f.upload_rate(&duplicate);
    let mut wrong_rounding = f.rate(11, "HalfUp quote outside the declared SpotClose law");
    wrong_rounding.rounding = RoundingLaw::HalfUp;
    let wrong_rounding_oid = f.upload_rate(&wrong_rounding);
    let malformed = f
        .book
        .upload_document(
            &cap(&["post"]),
            UploadRequest {
                kind: RATE_DOCUMENT_KIND,
                mime: RATE_MIME.into(),
                bytes: b"rate=1.10; no canonical evidence".to_vec(),
                asserted_grade: None,
            },
        )
        .unwrap()
        .unwrap();
    let wrong_kind = f
        .book
        .upload_document(
            &cap(&["post"]),
            UploadRequest {
                kind: 1,
                mime: RATE_MIME.into(),
                bytes: valid.canonical_bytes().unwrap(),
                asserted_grade: None,
            },
        )
        .unwrap()
        .unwrap();
    let other = f.rate(11, "Correct bytes with an incorrect media type");
    let wrong_mime = f
        .book
        .upload_document(
            &cap(&["post"]),
            UploadRequest {
                kind: RATE_DOCUMENT_KIND,
                mime: "text/plain".into(),
                bytes: other.canonical_bytes().unwrap(),
                asserted_grade: None,
            },
        )
        .unwrap()
        .unwrap();

    let cases = [
        ("missing rate", vec![Oid([0x99; 32])], FxLawId::SpotClose),
        ("no rate", vec![], FxLawId::SpotClose),
        ("malformed rate", vec![malformed.oid], FxLawId::SpotClose),
        (
            "wrong document kind",
            vec![wrong_kind.oid],
            FxLawId::SpotClose,
        ),
        ("wrong MIME", vec![wrong_mime.oid], FxLawId::SpotClose),
        ("wrong date", vec![wrong_date_oid], FxLawId::SpotClose),
        ("wrong purpose", vec![wrong_purpose_oid], FxLawId::SpotClose),
        (
            "ambiguous quote",
            vec![valid_oid, duplicate_oid],
            FxLawId::SpotClose,
        ),
        (
            "wrong rounding",
            vec![wrong_rounding_oid],
            FxLawId::SpotClose,
        ),
        (
            "unsupported law",
            vec![valid_oid],
            FxLawId::PeriodEndRevaluation,
        ),
    ];
    for (reason, oids, law) in cases {
        let before = f.book.head().unwrap();
        let proposal = f.proposal(reason.as_bytes());
        let denied = f
            .book
            .value_fx_proposal(&cap(&["read", "post", "privileged"]), proposal, law, &oids)
            .unwrap()
            .expect_err(reason);
        let expected = if reason == "missing rate" {
            code::EVIDENCE_UNKNOWN
        } else {
            code::STRUCTURE
        };
        assert_eq!(denied.code, expected, "{reason}");
        assert_eq!(f.book.head().unwrap(), before, "{reason}");
    }
}

#[test]
fn functional_activity_refuses_unvalued_foreign_postings() {
    let mut f = Fixture::new();
    let before = f.book.head().unwrap();
    let proposal = f.proposal(b"unvalued-native-invoice");
    f.book.post(post_request(proposal)).unwrap().unwrap();
    let head = f.book.head().unwrap();
    let result = f
        .book
        .functional_period_activity(&cap(&["read"]), PERIOD, None);
    assert!(matches!(
        result,
        Err(BookError::Registers(RegisterError::ProjectionDrift(_)))
    ));
    assert_eq!(f.book.head().unwrap(), head);
    let historical = f.activity(Some(before));
    assert_eq!(historical.entries, 0);
    assert!(historical.cells.is_empty());
}

#[test]
fn current_authority_bounds_valuation_and_historical_functional_reads() {
    let mut f = Fixture::new();
    let rate = f.rate(11, "Authority fixture rate");
    let oid = f.upload_rate(&rate);
    let proposal = f.proposal(b"authority-invoice");
    let valued = f.value(proposal.clone(), oid);
    let posted = f.book.post(post_request(valued)).unwrap().unwrap();
    let pin = posted.recorded_at();
    let historical = f.activity(Some(pin));
    let limited = cap(&["read"]).known_at_most(pin);
    let later_rate = f.rate(12, "Later visible source");
    f.upload_rate(&later_rate);
    let head = f.book.head().unwrap();
    assert_eq!(
        f.book
            .functional_period_activity(&limited, PERIOD, Some(pin))
            .unwrap()
            .unwrap(),
        historical
    );
    assert_eq!(
        f.book
            .functional_period_activity(&limited, PERIOD, None)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    for denied_cap in [
        cap(&["post"]),
        cap(&["read"]).for_accounts(&["1200"]).unwrap(),
        cap(&["read"]).for_books(&[Id128([0x66; 16])]).unwrap(),
        cap(&["read"]).expiring_at(head),
    ] {
        let denied = f
            .book
            .functional_period_activity(&denied_cap, PERIOD, Some(pin))
            .unwrap()
            .unwrap_err();
        assert_eq!(denied.exit, 7);
        assert_eq!(f.book.head().unwrap(), head);
    }
    for denied_cap in [
        cap(&["read"]),
        cap(&["post"]),
        cap(&["read", "post"]).for_accounts(&["1200"]).unwrap(),
        cap(&["read", "post"]).expiring_at(head),
    ] {
        let denied = f
            .book
            .value_fx_proposal(&denied_cap, proposal.clone(), FxLawId::SpotClose, &[oid])
            .unwrap()
            .unwrap_err();
        assert_eq!(denied.exit, 7);
        assert_eq!(f.book.head().unwrap(), head);
    }
    let future = CommitSeq(head.0.checked_add(1).unwrap());
    let denied = f
        .book
        .functional_period_activity(&cap(&["read"]), PERIOD, Some(future))
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, code::STRUCTURE);
    assert_eq!(f.book.head().unwrap(), head);
    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            limited.commitment().unwrap(),
            day(5),
            b"revoke-fx-history-reader",
            "Revoke the historical functional reader",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    let denied = f
        .book
        .functional_period_activity(&limited, PERIOD, Some(pin))
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "FA-REF-023");
    assert_eq!(f.book.head().unwrap(), revoked_at);
}

#[test]
fn typed_rate_upload_preserves_the_original_uploader_evidence_grade() {
    let mut f = Fixture::new();
    let rate = f.rate(11, "Agent supplied quote, not a provider receipt");
    let agent = Capability::new(VId(2), Profile::Agent, &[Op::Post], PRINCIPAL).unwrap();
    let first = f.book.upload_fx_rate(&agent, &rate).unwrap().unwrap();
    assert_eq!(first.grade, grade("AgentUpload"));
    let head = f.book.head().unwrap();
    let repeat = f
        .book
        .upload_fx_rate(&cap(&["post"]), &rate)
        .unwrap()
        .unwrap();
    assert!(repeat.already_recorded);
    assert_eq!(repeat.oid, first.oid);
    assert_eq!(repeat.doc_commit, first.doc_commit);
    assert_eq!(repeat.recorded_at, first.recorded_at);
    assert_eq!(repeat.grade, grade("AgentUpload"));
    assert_eq!(f.book.custody_chain(&first.oid).unwrap().len(), 1);
    let denied = f
        .book
        .upload_fx_rate(&cap(&["read"]), &rate)
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, code::CAPABILITY);
    assert_eq!(f.book.head().unwrap(), head);
}

fn draft_source_capability(f: &Fixture, name: &str, ceiling: i128) -> Capability {
    Capability::new(VId(41), Profile::Agent, &[Op::Post], PRINCIPAL)
        .unwrap()
        .on_branch(fa_model::draft_branch(f.book.context().book_id, name))
        .unwrap()
        .with_ceiling(f.eur, ceiling)
        .unwrap()
}

#[test]
fn draft_source_fx_retains_exact_effects_without_granting_read_or_trunk_authority() {
    let mut f = Fixture::new();
    let rate = f.rate(11, "Named draft purchase rate");
    let oid = f.upload_rate(&rate);
    let name = "private-fx-import";
    let planner = draft_source_capability(&f, name, 10_000);
    f.book
        .open_draft(planner.clone(), name, day(5), "Draft FX import")
        .unwrap()
        .unwrap();
    let mut proposal = f.proposal(b"draft-source-purchase");
    proposal.principal_ref = planner.holder();
    let literal = f
        .book
        .value_fx_proposal(
            &Capability::embedded(planner.holder(), &["read", "post"]).unwrap(),
            proposal.clone(),
            FxLawId::SpotClose,
            &[oid],
        )
        .unwrap()
        .unwrap();
    let head = f.book.head().unwrap();
    let valued = f
        .book
        .value_fx_proposal_in_draft(&planner, name, proposal.clone(), FxLawId::SpotClose, &[oid])
        .unwrap()
        .unwrap();
    assert_eq!(valued, literal);
    assert_eq!(valued.base_totals.as_ref().unwrap().debits, 11_000);
    assert_eq!(f.book.head().unwrap(), head, "derivation never publishes");
    assert_eq!(
        f.book
            .read_document_for(&planner, &oid)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    assert!(
        f.book
            .read_scope(planner.holder(), &planner)
            .unwrap()
            .is_err()
    );
    assert_eq!(
        f.book
            .functional_period_activity(&planner, PERIOD, None)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );

    for (capability, selected_name) in [
        (planner.clone(), "somebody-elses-draft"),
        (
            Capability::new(planner.holder(), Profile::Agent, &[Op::Post], PRINCIPAL).unwrap(),
            name,
        ),
        (planner.clone().expiring_at(head), name),
        (draft_source_capability(&f, name, 9_999), name),
    ] {
        let denied = f
            .book
            .value_fx_proposal_in_draft(
                &capability,
                selected_name,
                proposal.clone(),
                FxLawId::SpotClose,
                &[Oid([0xee; 32])],
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(denied.exit, 7, "{denied}");
        assert_eq!(f.book.head().unwrap(), head);
    }
    let mut direct = post_request(valued.clone());
    direct.capability = planner.clone();
    assert!(f.book.post(direct).unwrap().is_err());
    let planned = f
        .book
        .plan_into_draft(
            planner.clone(),
            name,
            fa_intents::PostIntent::new(valued.clone(), Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let reviewed = &planned.plan.as_ref().unwrap().members()[0].entry;
    assert_eq!(reviewed.proposal, valued);
    assert_eq!(f.activity(None).entries, 0);
    let promoted = f
        .book
        .promote_draft(
            cap(&["read", "approve"]),
            name,
            day(5),
            "Promote the reviewed FX purchase",
        )
        .unwrap()
        .unwrap();
    assert_eq!(promoted.entries.len(), 1);
    assert_eq!(promoted.entries[0].entry_digest, reviewed.entry_digest);
    assert_eq!(f.activity(None).entries, 1);
    let after = f.book.head().unwrap();
    let denied = f
        .book
        .value_fx_proposal_in_draft(
            &planner,
            name,
            proposal,
            FxLawId::SpotClose,
            &[Oid([0xee; 32])],
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, code::DRAFT_NOT_OPEN);
    assert_eq!(f.book.head().unwrap(), after);
}

#[test]
fn draft_source_subledger_admits_generated_amounts_and_rechecks_revocation() {
    let mut f = Fixture::new();
    let name = "private-subledger-import";
    let planner = draft_source_capability(&f, name, 10_000);
    f.book
        .open_draft(planner.clone(), name, day(5), "Draft summary import")
        .unwrap()
        .unwrap();
    let book_id = f.book.context().book_id;
    let detail = fa::ExternalSubledgerBatch {
        book_id,
        feed: "synthetic-import".into(),
        batch_key: "two-rows-plus-offset".into(),
        effective_date: day(5),
        rows: [
            (1, "1200", Side::Debit, 6_000),
            (2, "1200", Side::Debit, 6_000),
            (3, "4000", Side::Credit, 12_000),
        ]
        .into_iter()
        .map(
            |(source, account, side, amount)| fa::ExternalSubledgerDetail {
                source_digest: [source; 32],
                account: account_vid(book_id, account),
                side,
                amount: Amount::new(f.eur, amount),
                dimensions: Vec::new(),
            },
        )
        .collect(),
    };
    let source = f
        .book
        .upload_document(
            &cap(&["post"]),
            UploadRequest {
                kind: fa::EXTERNAL_SUBLEDGER_DOCUMENT_KIND,
                mime: fa::EXTERNAL_SUBLEDGER_MIME.into(),
                bytes: detail.canonical_bytes().unwrap(),
                asserted_grade: None,
            },
        )
        .unwrap()
        .unwrap();
    let mut template = f.proposal(b"draft-source-summary");
    template.principal_ref = planner.holder();
    template.legs.clear();
    template.unit_totals.clear();
    template.evidence.clear();
    let head = f.book.head().unwrap();
    let denied = f
        .book
        .prepare_external_subledger_in_draft(&planner, name, source.oid, template.clone())
        .unwrap()
        .unwrap_err();
    assert!(denied.message.contains("ceiling"), "{denied}");
    assert_eq!(denied.code, fa_policy::denial::code::CEILING);
    assert_eq!(
        denied.message,
        "generated posting effects exceed the capability's permitted scope or amount ceiling"
    );
    assert!(
        denied.detail.is_none(),
        "denied summary must not leak: {denied:?}"
    );
    assert_eq!(
        f.book.head().unwrap(),
        head,
        "a generated excess never returns effects or writes"
    );

    let allowed = draft_source_capability(&f, name, 12_000);
    let literal = f
        .book
        .prepare_external_subledger(
            source.oid,
            template.clone(),
            &Capability::embedded(planner.holder(), &["read", "post"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    let generated = f
        .book
        .prepare_external_subledger_in_draft(&allowed, name, source.oid, template.clone())
        .unwrap()
        .unwrap();
    assert_eq!(generated, literal);
    assert_eq!(generated.legs.len(), 2);
    assert!(
        generated
            .legs
            .iter()
            .all(|leg| leg.amount.mantissa == 12_000)
    );
    assert_eq!(f.book.head().unwrap(), head);
    assert_eq!(
        f.book
            .read_document_for(&allowed, &source.oid)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );

    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            allowed.commitment().unwrap(),
            day(5),
            b"revoke-summary-planner",
            "Revoke the draft source planner",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    let denied = f
        .book
        .prepare_external_subledger_in_draft(&allowed, name, Oid([0xee; 32]), template)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denied.code, "FA-REF-023",
        "authority precedes an unknown source lookup"
    );
    let denied = f
        .book
        .plan_into_draft(
            allowed,
            name,
            fa_intents::PostIntent::new(generated, Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denied.code, "FA-REF-023",
        "a prepared proposal retains no posting authority"
    );
    assert_eq!(f.book.head().unwrap(), revoked_at);
}

#[test]
fn draft_source_factories_reject_unrelated_documents_and_rate_media_types() {
    let mut f = Fixture::new();
    let name = "typed-source-boundary";
    let planner = draft_source_capability(&f, name, 10_000);
    f.book
        .open_draft(
            planner.clone(),
            name,
            day(5),
            "Only typed source preparation",
        )
        .unwrap()
        .unwrap();
    let rate = f.rate(11, "Correct typed Rate source");
    let rate_oid = f.upload_rate(&rate);
    let mislabeled = f.rate(12, "Rate bytes under an unrelated media type");
    let wrong_mime = f
        .book
        .upload_document(
            &cap(&["post"]),
            UploadRequest {
                kind: RATE_DOCUMENT_KIND,
                mime: "text/plain".into(),
                bytes: mislabeled.canonical_bytes().unwrap(),
                asserted_grade: None,
            },
        )
        .unwrap()
        .unwrap();
    let mut proposal = f.proposal(b"typed-source-only");
    proposal.principal_ref = planner.holder();
    let head = f.book.head().unwrap();
    for oid in [f.invoice.document_oid, wrong_mime.oid] {
        let refused = f
            .book
            .value_fx_proposal_in_draft(
                &planner,
                name,
                proposal.clone(),
                FxLawId::SpotClose,
                &[oid],
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, code::CAPABILITY);
        assert!(!refused.message.contains("Customer invoice"));
        assert_eq!(f.book.head().unwrap(), head);
    }
    proposal.legs.clear();
    proposal.unit_totals.clear();
    proposal.evidence.clear();
    for oid in [f.invoice.document_oid, rate_oid] {
        let refused = f
            .book
            .prepare_external_subledger_in_draft(&planner, name, oid, proposal.clone())
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refused.code,
            code::CAPABILITY,
            "the source family must be refused before decoding another document format"
        );
        assert_eq!(f.book.head().unwrap(), head);
    }
    assert_eq!(f.book.draft(name).unwrap().unwrap().intents.len(), 0);
}

#[test]
fn confined_carrying_facade_derives_only_effects_and_keeps_rate_disclosure_typed() {
    let mut f = Fixture::new();
    let accounts = [
        ("1000", AccountType::ASSET),
        ("2990", AccountType::LIABILITY),
        ("7000", AccountType::EXPENSE),
    ]
    .into_iter()
    .map(|(code, kind)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: u8::from(kind == AccountType::LIABILITY),
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    })
    .collect::<Vec<_>>();
    f.book
        .install_chart(
            &accounts,
            PRINCIPAL,
            day(1),
            b"confined-carrying-routes",
            &cap(&["schema_change"]),
        )
        .unwrap()
        .unwrap();
    let spot = f.rate(11, "Invoice carrying basis");
    let spot_oid = f.upload_rate(&spot);
    let source = f.proposal(b"confined-carrying-invoice");
    let valued = f.value(source, spot_oid);
    let posted = f.book.post(post_request(valued)).unwrap().unwrap();
    let settlement = FxRateDocument::new(
        FxRateTerms {
            base_unit: f.usd,
            quote_unit: f.eur,
            rate_num: 13,
            rate_den: 10,
            rounding: RoundingLaw::HalfEven,
        },
        day(5),
        1,
        FxRatePurpose::Settlement,
        "Named partial settlement quote",
    )
    .unwrap();
    let settlement_oid = f.upload_rate(&settlement);
    let name = "confined-carrying-facade";
    let planner = draft_source_capability(&f, name, 1_000)
        .with_ceiling(f.usd, 1_300)
        .unwrap();
    f.book
        .open_draft(planner.clone(), name, day(5), "Review partial settlement")
        .unwrap()
        .unwrap();
    let book_id = f.book.context().book_id;
    let input = fa::FxSettlementRequest {
        target: posted.entry_ref(),
        target_ordinal: 0,
        amount: Amount::new(f.eur, 1_000),
        settlement_amount: Amount::new(f.usd, 1_300),
        settlement_account: account_vid(book_id, "1000"),
        conversion_account: account_vid(book_id, "2990"),
        realized_fx_account: account_vid(book_id, "7000"),
        rate_document: settlement_oid,
    };
    let mut template = f.proposal(b"confined-carrying-payment");
    template.principal_ref = planner.holder();
    template.legs.clear();
    template.unit_totals.clear();
    let literal = f
        .book
        .prepare_fx_settlement_group(
            &Capability::embedded(planner.holder(), &["read", "post"]).unwrap(),
            std::slice::from_ref(&input),
            template.clone(),
        )
        .unwrap()
        .unwrap()
        .into_proposal();
    let head = f.book.head().unwrap();
    assert_eq!(
        f.book
            .draft_source_entry_ref(&planner, name, posted.entry_ref().vid)
            .unwrap()
            .unwrap(),
        Some(posted.entry_ref())
    );
    assert_eq!(
        f.book
            .draft_source_entry_ref(&planner, name, VId(0xdead))
            .unwrap()
            .unwrap(),
        None
    );
    let generated = f
        .book
        .prepare_fx_settlement_group_in_draft(
            &planner,
            name,
            std::slice::from_ref(&input),
            template.clone(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(generated, literal);
    assert_eq!(generated.legs[0].amount.mantissa, 1_000);
    assert_eq!(generated.legs[0].base_amount.unwrap().mantissa, 1_100);
    assert_eq!(
        generated
            .legs
            .iter()
            .find(|leg| leg.account_ref == input.realized_fx_account)
            .unwrap()
            .amount
            .mantissa,
        200
    );
    assert_eq!(f.book.head().unwrap(), head);
    assert_eq!(
        f.book
            .prepare_fx_settlement_group(&planner, std::slice::from_ref(&input), template.clone(),)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    assert_eq!(
        f.book
            .read_document_for(&planner, &settlement_oid)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );

    let mut wrong_source = input.clone();
    wrong_source.rate_document = f.invoice.document_oid;
    let denied = f
        .book
        .prepare_fx_settlement_group_in_draft(&planner, name, &[wrong_source], template.clone())
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, code::CAPABILITY);
    assert!(!denied.message.contains("Customer invoice"));
    assert_eq!(f.book.head().unwrap(), head);

    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            planner.commitment().unwrap(),
            day(5),
            b"revoke-confined-carrying",
            "Withdraw the source planner",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    let denied = f
        .book
        .prepare_fx_settlement_group_in_draft(&planner, name, &[input], template)
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "FA-REF-023");
    assert_eq!(f.book.head().unwrap(), revoked_at);
}
