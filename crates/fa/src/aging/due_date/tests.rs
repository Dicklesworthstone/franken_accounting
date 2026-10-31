use super::*;

use crate::{BookKeys, Entropy};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::obligation::{InlineObligationTerms, ObligationInstallment, ObligationStatus};
use fa_model::symbols::{property, relation};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, LegPayload, Oid,
    Settlement, account_vid,
};
use fa_money::{Amount, UnitId, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;
use std::path::Path;

const BOOK: Id128 = Id128([0x76; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "due-date-aging-cert-book";

fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    evidence: EvidenceRef,
    receivable: bool,
}

impl Harness {
    fn new() -> Self {
        Self::with_receivable(false)
    }

    fn with_receivable(receivable: bool) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let vfs = MemVfs::new().unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                BookKeys::for_development(0x76),
                BookSpec {
                    book_id: BOOK,
                    name: "Contractual aging fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(118),
            ))
            .unwrap();
        let accounts = [
            ("ap", AccountType::LIABILITY),
            ("ar", AccountType::ASSET),
            ("cash", AccountType::ASSET),
            ("expense", AccountType::EXPENSE),
        ]
        .map(|(code, kind)| AccountSpec {
            code: code.into(),
            name: format!("{code} account"),
            account_type: kind.0,
            normal_balance: u8::from(kind == AccountType::LIABILITY),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        });
        runtime
            .block_on(book.install_chart(
                &cx,
                &accounts,
                PRINCIPAL,
                day("2026-01-01"),
                b"chart",
                &cap(&["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.create_periods(&cx, 2026, PRINCIPAL, &cap(&["schema_change"])))
            .unwrap()
            .unwrap();
        for period in ["FY2026-P03", "FY2026-P04"] {
            runtime
                .block_on(book.transition_period(
                    &cx,
                    period,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    period.as_bytes(),
                    &cap(&["close"]),
                ))
                .unwrap()
                .unwrap();
        }
        let document = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Contract and installment schedule".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            evidence: document.evidence_ref(1),
            receivable,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn post(
        &mut self,
        key: &str,
        date: &str,
        amount: i128,
        terms: Option<(ObligationStatus, Vec<(&str, i128)>)>,
        settles: Option<EntryRef>,
    ) -> EntryRef {
        let cx = self.cx();
        let (debit, credit) = if self.receivable {
            if settles.is_some() {
                ("cash", "ar")
            } else {
                ("ar", "expense")
            }
        } else if settles.is_some() {
            ("ap", "cash")
        } else {
            ("expense", "ap")
        };
        let mut legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(BOOK, debit),
                Amount::new(self.usd, amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(BOOK, credit),
                Amount::new(self.usd, amount),
            ),
        ];
        if let Some(target) = settles {
            legs[usize::from(self.receivable)].settles.push(Settlement {
                target,
                ordinal: u16::from(!self.receivable),
                amount: Amount::new(self.usd, amount),
            });
        }
        let extensions = terms
            .into_iter()
            .map(|(status, installments)| {
                let terms = [InlineObligationTerms {
                    ordinal: u16::from(!self.receivable),
                    status,
                    installments: installments
                        .into_iter()
                        .map(|(date, amount)| ObligationInstallment {
                            due_date: day(date),
                            amount,
                        })
                        .collect(),
                }];
                if self.receivable {
                    InlineObligationTerms::to_receivable_extension(&terms)
                } else {
                    InlineObligationTerms::to_extension(&terms)
                }
                .unwrap()
            })
            .collect::<Vec<_>>();
        let proposal = EntryPayload {
            // An extension block needs a minor that admits one (Appendix A
            // fa:entry:v1), as every product path that attaches terms writes.
            schema_minor: if extensions.is_empty() {
                0
            } else {
                fa_model::entry::EXTENSIONS_MINOR
            },
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&cx, key).unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([8; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions,
            tags: Vec::new(),
        };
        self.runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(&["post"]),
                },
            ))
            .unwrap()
            .unwrap()
            .entry_ref()
    }

    fn invoice(&mut self) -> EntryRef {
        self.post(
            "invoice",
            "2026-03-01",
            1_000,
            Some((
                ObligationStatus::Contractual,
                vec![("2026-03-31", 600), ("2026-04-30", 400)],
            )),
            None,
        )
    }

    fn request(&self, cutoff: &str) -> AgingRequest {
        AgingRequest {
            account: Some(account_vid(BOOK, if self.receivable { "ar" } else { "ap" })),
            effective_through: day(cutoff),
            known_at: None,
            buckets: AgingBuckets::thirty_day(),
        }
    }

    fn certify(&self, request: &AgingRequest) -> CertifiedDueDateAging {
        self.book
            .certify_due_date_aging(&self.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
            .unwrap()
            .unwrap()
    }

    fn replay(&self, certificate: &DueDateAgingCertificate) -> DueDateAging {
        self.book
            .replay_due_date_aging(&self.cx(), PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap()
    }

    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            evidence,
            receivable,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                BookKeys::for_development(0x76),
                Entropy::deterministic(119),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            evidence,
            receivable,
        }
    }
}

#[test]
fn receivable_due_dates_survive_partial_receipts_historical_replay_and_reopen() {
    let mut h = Harness::with_receivable(true);
    let invoice = h.invoice();
    let at_due = h.certify(&h.request("2026-03-31"));
    assert_eq!(at_due.report.items.len(), 2);
    assert!(at_due.report.items.iter().all(|row| row.days_past_due == 0));
    assert_eq!(
        (
            at_due.report.totals[0].amounts.debits,
            at_due.report.totals[0].amounts.credits
        ),
        (1_000, 0)
    );
    let overdue = h.certify(&h.request("2026-04-01"));
    let first = overdue
        .report
        .items
        .iter()
        .find(|row| row.due_date == day("2026-03-31"))
        .unwrap();
    assert_eq!((first.open, first.days_past_due, first.bucket), (600, 1, 1));
    h.post("partial-receipt", "2026-04-15", 700, None, Some(invoice));
    let after_receipt = h.certify(&h.request("2026-05-01"));
    assert_eq!(after_receipt.report.items.len(), 1);
    let remaining = &after_receipt.report.items[0];
    assert_eq!(
        (remaining.open, remaining.due_date, remaining.days_past_due),
        (300, day("2026-04-30"), 1)
    );
    assert_eq!(
        (
            remaining.item.original,
            remaining.item.applied,
            remaining.item.open
        ),
        (1_000, 700, 300)
    );
    assert_eq!(
        (
            after_receipt.report.totals[0].amounts.debits,
            after_receipt.report.totals[0].amounts.credits
        ),
        (300, 0)
    );
    for (key, amount, terms) in [
        ("plain-receivable", 50, None),
        (
            "missing-receivable",
            100,
            Some((ObligationStatus::MissingMaturity, vec![])),
        ),
        (
            "disputed-receivable",
            150,
            Some((ObligationStatus::Disputed { reason_code: 7 }, vec![])),
        ),
    ] {
        h.post(key, "2026-03-02", amount, terms, None);
    }
    let current = h.certify(&h.request("2026-05-01"));
    assert_eq!(current.report.unscheduled.len(), 3);
    assert_eq!(
        (
            current.report.unscheduled_totals[0].amounts.debits,
            current.report.unscheduled_totals[0].amounts.credits
        ),
        (300, 0)
    );
    for expected in [
        Unscheduled::NoTerms,
        Unscheduled::MissingMaturity,
        Unscheduled::Disputed { reason_code: 7 },
    ] {
        assert!(
            current
                .report
                .unscheduled
                .iter()
                .any(|row| row.reason == expected)
        );
    }
    let h = h.reopen();
    for certified in [at_due, overdue, after_receipt, current] {
        assert_eq!(h.replay(&certified.certificate), certified.report);
        let mut substituted = certified.report.clone();
        substituted.items[0].due_date = day("2026-03-30");
        let fake = reseal(&certified.certificate, &substituted);
        assert_eq!(
            h.book
                .replay_due_date_aging(&h.cx(), PRINCIPAL, &cap(&["read"]), &fake)
                .unwrap()
                .unwrap_err()
                .exit,
            exit::VERIFICATION
        );
    }
}

#[test]
fn certified_due_date_aging_refolds_installments_before_partial_settlement() {
    let mut h = Harness::new();
    let invoice = h.invoice();
    h.post("partial-payment", "2026-04-15", 700, None, Some(invoice));
    let head = h.head();
    let at_due = h.certify(&h.request("2026-03-31"));
    assert_eq!(at_due.report.items.len(), 2);
    assert!(
        at_due
            .report
            .items
            .iter()
            .all(|item| item.days_past_due == 0)
    );
    assert_eq!(at_due.report.totals[0].amounts.credits, 1_000);
    let first_overdue = h.certify(&h.request("2026-04-01"));
    let overdue = first_overdue
        .report
        .items
        .iter()
        .find(|item| item.due_date == day("2026-03-31"))
        .unwrap();
    assert_eq!(
        (overdue.open, overdue.days_past_due, overdue.bucket),
        (600, 1, 1)
    );
    assert!(
        overdue.item.applications.is_empty(),
        "effective cutoff precedes the payment"
    );
    let after_payment = h.certify(&h.request("2026-05-01"));
    assert_eq!(after_payment.report.items.len(), 1);
    let remainder = &after_payment.report.items[0];
    assert_eq!(
        (remainder.open, remainder.due_date, remainder.days_past_due),
        (300, day("2026-04-30"), 1)
    );
    assert_eq!((remainder.item.open, remainder.item.applied), (300, 700));
    assert_eq!(remainder.item.applications.len(), 1);
    assert_eq!(after_payment.report.totals[0].amounts.credits, 300);
    for certified in [at_due, first_overdue, after_payment] {
        assert_eq!(certified.report.known_at, head);
        assert_eq!(h.replay(&certified.certificate), certified.report);
    }
    assert_eq!(h.head(), head, "certification and replay are reads");
}

#[test]
fn certified_due_date_aging_keeps_missing_and_disputed_terms_explicit() {
    let mut h = Harness::new();
    let plain = h.post("no-terms", "2026-03-01", 100, None, None);
    let missing = h.post(
        "missing",
        "2026-03-02",
        200,
        Some((ObligationStatus::MissingMaturity, vec![])),
        None,
    );
    let disputed = h.post(
        "disputed",
        "2026-03-03",
        300,
        Some((
            ObligationStatus::Disputed { reason_code: 7 },
            vec![("2026-03-20", 300)],
        )),
        None,
    );
    let certified = h.certify(&h.request("2026-03-31"));
    assert!(certified.report.items.is_empty());
    assert!(certified.report.cells.is_empty());
    assert!(certified.report.totals.is_empty());
    assert_eq!(certified.report.unscheduled.len(), 3);
    for (entry, reason) in [
        (plain, Unscheduled::NoTerms),
        (missing, Unscheduled::MissingMaturity),
        (disputed, Unscheduled::Disputed { reason_code: 7 }),
    ] {
        assert_eq!(
            certified
                .report
                .unscheduled
                .iter()
                .find(|row| row.item.entry == entry.vid)
                .unwrap()
                .reason,
            reason
        );
    }
    assert_eq!(certified.report.unscheduled_totals[0].amounts.credits, 600);
    assert_eq!(certified.report.unscheduled_totals[0].amounts.item_count, 3);
    assert_eq!(h.replay(&certified.certificate), certified.report);
}

#[test]
fn due_date_reconciliation_includes_all_terms_and_counts_original_items_once() {
    let mut h = Harness::new();
    let invoice = h.invoice();
    h.post("partial", "2026-04-15", 700, None, Some(invoice));
    h.post("no-terms", "2026-03-01", 100, None, None);
    h.post(
        "missing",
        "2026-03-02",
        200,
        Some((ObligationStatus::MissingMaturity, vec![])),
        None,
    );
    h.post(
        "disputed",
        "2026-03-03",
        300,
        Some((
            ObligationStatus::Disputed { reason_code: 7 },
            vec![("2026-03-20", 300)],
        )),
        None,
    );
    let head = h.head();
    for (cutoff, expected_open, scheduled_parts) in
        [("2026-04-01", 1_600, 2), ("2026-05-01", 900, 1)]
    {
        let request = crate::AgingReconciliationRequest {
            account: account_vid(BOOK, "ap"),
            effective_through: day(cutoff),
            known_at: Some(head),
            buckets: AgingBuckets::thirty_day(),
        };
        let certified = h
            .book
            .certify_due_date_aging_reconciliation(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &request,
            )
            .unwrap()
            .unwrap();
        let report = &certified.report;
        assert!(report.is_reconciled());
        assert_eq!(report.aging().items.len(), scheduled_parts);
        assert_eq!(report.aging().unscheduled.len(), 3);
        let row = &report.rows()[0];
        assert_eq!((row.open_credits, row.open_item_count), (expected_open, 4));
        assert_eq!(
            (row.open_net, row.posted_net, row.difference),
            (-expected_open, -expected_open, 0)
        );
        assert_eq!(report.control_rows()[0].credits, 1_600);
        let decoded = crate::DueDateAgingReconciliationCertificate::decode(
            &certified.certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, certified.certificate);
        assert_eq!(decoded.request().unwrap(), request);
        assert_eq!(
            h.book
                .reconcile_due_date_aging(&h.cx(), PRINCIPAL, &cap(&["read"]), &request,)
                .unwrap()
                .unwrap(),
            *report
        );
        assert_eq!(
            h.book
                .replay_due_date_aging_reconciliation(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &decoded,
                    &request,
                )
                .unwrap()
                .unwrap(),
            *report
        );
        assert_eq!(
            h.book
                .certify_due_date_aging_reconciliation_from_sources(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    decoded.aging_source(),
                    decoded.control_source(),
                    &request,
                )
                .unwrap()
                .unwrap()
                .certificate,
            decoded
        );
        assert!(
            crate::AgingReconciliationCertificate::decode(&decoded.canonical_bytes().unwrap(),)
                .is_err(),
            "the aging bases have distinct certificate contracts"
        );
    }
    assert_eq!(h.head(), head);
}

#[test]
fn due_date_reconciliation_rejects_repaired_comparisons_and_wrong_fixed_questions() {
    let mut h = Harness::new();
    h.invoice();
    h.post("unscheduled", "2026-03-02", 100, None, None);
    let request = crate::AgingReconciliationRequest {
        account: account_vid(BOOK, "ap"),
        effective_through: day("2026-04-01"),
        known_at: Some(h.head()),
        buckets: AgingBuckets::thirty_day(),
    };
    let certified = h
        .book
        .certify_due_date_aging_reconciliation(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &request,
        )
        .unwrap()
        .unwrap();
    let certificate = &certified.certificate;
    let mut incomplete = certified.report.aging().clone();
    incomplete.unscheduled.clear();
    incomplete.unscheduled_totals.clear();
    let incomplete_source = reseal(certificate.aging_source(), &incomplete);
    assert_eq!(
        h.book
            .certify_due_date_aging_reconciliation_from_sources(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &incomplete_source,
                certificate.control_source(),
                &request,
            )
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION,
        "omitting unscheduled liabilities must not produce a reconciled certificate"
    );
    let mut bytes = certificate.canonical_bytes().unwrap();
    let digest_at = bytes.len() - 32;
    bytes[digest_at - 1] ^= 1; // Flip the comparison conclusion, then repair its digest.
    let digest = fa_model::domain_digest(
        b"fa:due-date-aging-reconciliation-digest:v1",
        &[&bytes[..digest_at]],
    );
    bytes[digest_at..].copy_from_slice(&digest);
    let forged = crate::DueDateAgingReconciliationCertificate::decode(&bytes).unwrap();
    assert_eq!(
        h.book
            .replay_due_date_aging_reconciliation(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &forged,
                &request,
            )
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
    let mut wrong = Vec::new();
    let mut altered = request.clone();
    altered.account = account_vid(BOOK, "expense");
    wrong.push(altered);
    let mut altered = request.clone();
    altered.effective_through = day("2026-04-02");
    wrong.push(altered);
    let mut altered = request.clone();
    altered.known_at = None;
    wrong.push(altered);
    let mut altered = request.clone();
    altered.known_at = Some(CommitSeq(h.head().0 - 1));
    wrong.push(altered);
    let mut altered = request.clone();
    altered.buckets = AgingBuckets::new(vec![0, 60]).unwrap();
    wrong.push(altered);
    for expected in wrong {
        let expected_exit = if expected.known_at.is_none() {
            exit::USAGE
        } else {
            exit::VERIFICATION
        };
        assert_eq!(
            h.book
                .replay_due_date_aging_reconciliation(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    certificate,
                    &expected,
                )
                .unwrap()
                .unwrap_err()
                .exit,
            expected_exit
        );
    }
    let original_head = h.head();
    h.post("later", "2026-03-03", 50, None, None);
    let later = h
        .book
        .certify_due_date_aging_reconciliation(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &crate::AgingReconciliationRequest {
                known_at: None,
                ..request.clone()
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        h.book
            .certify_due_date_aging_reconciliation_from_sources(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                certificate.aging_source(),
                later.certificate.control_source(),
                &request,
            )
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
    let h = h.reopen();
    assert_eq!(
        h.book
            .replay_due_date_aging_reconciliation(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                certificate,
                &request,
            )
            .unwrap()
            .unwrap(),
        certified.report
    );
    let artifact = crate::ReportArtifact::try_from(certificate).unwrap();
    assert_eq!(artifact.known_at(), original_head);
    assert!(matches!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &artifact.canonical_bytes().unwrap(),
                Some(artifact.digest()),
                crate::ReportArtifactExpectation::DueDateAgingReconciliation(&request),
            )
            .unwrap()
            .unwrap(),
        crate::CertificateStatus::SupersededBy { .. }
    ));
}

#[test]
fn due_date_certificate_roundtrips_and_replays_saved_prefix_after_later_terms() {
    let mut h = Harness::new();
    h.invoice();
    let certified = h.certify(&h.request("2026-04-01"));
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let decoded = DueDateAgingCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.producer(), PRINCIPAL);
    assert_eq!(
        *decoded.capability_commitment(),
        cap(&["read", "produce"]).commitment().unwrap()
    );
    assert_eq!(
        decoded.request().unwrap().known_at,
        Some(certified.report.known_at)
    );
    assert!(
        crate::AgingCertificate::decode(&bytes).is_err(),
        "the bases have distinct formats"
    );
    h.post(
        "later-backdated-terms",
        "2026-03-02",
        50,
        Some((ObligationStatus::Contractual, vec![("2026-03-10", 50)])),
        None,
    );
    let h = h.reopen();
    assert_eq!(h.replay(&decoded), certified.report);
    let from_source = h
        .book
        .certify_due_date_aging_from_source(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            decoded.source(),
            day("2026-04-01"),
            &AgingBuckets::thirty_day(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(from_source.certificate, decoded);
    assert_eq!(
        h.certify(&h.request("2026-04-01")).report.totals[0]
            .amounts
            .credits,
        1_050
    );
    let effective = h
        .book
        .certify_effective_date_aging(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &h.request("2026-04-01"),
        )
        .unwrap()
        .unwrap();
    let effective_bytes = effective.certificate.canonical_bytes().unwrap();
    assert_eq!(
        crate::AgingCertificate::decode(&effective_bytes).unwrap(),
        effective.certificate
    );
    assert!(DueDateAgingCertificate::decode(&effective_bytes).is_err());
}

fn reseal(certificate: &DueDateAgingCertificate, report: &DueDateAging) -> DueDateAgingCertificate {
    DueDateAgingCertificate::seal(
        certificate.source.clone(),
        certificate.effective_through,
        certificate.buckets.clone(),
        certificate.producer,
        certificate.capability_commitment,
        output_bytes(report).unwrap(),
    )
    .unwrap()
}

#[test]
fn repaired_digests_cannot_change_due_dates_relief_unscheduled_reasons_or_totals() {
    let mut h = Harness::new();
    let invoice = h.invoice();
    h.post("payment", "2026-04-15", 700, None, Some(invoice));
    h.post("no-terms", "2026-03-02", 50, None, None);
    let certified = h.certify(&h.request("2026-05-01"));
    let mut mutations = Vec::new();
    let mut report = certified.report.clone();
    report.items[0].due_date = day("2026-03-31");
    mutations.push(report);
    let mut report = certified.report.clone();
    report.items[0].open += 1;
    mutations.push(report);
    let mut report = certified.report.clone();
    report.items[0].item.applications[0].live = false;
    mutations.push(report);
    let mut report = certified.report.clone();
    report.items[0].days_past_due += 1;
    mutations.push(report);
    let mut report = certified.report.clone();
    report.unscheduled[0].reason = Unscheduled::Disputed { reason_code: 7 };
    mutations.push(report);
    let mut report = certified.report.clone();
    report.unscheduled_totals[0].amounts.credits += 1;
    mutations.push(report);
    let mut report = certified.report.clone();
    report.items.clear();
    mutations.push(report);
    for report in mutations {
        let fake = reseal(&certified.certificate, &report);
        let decoded = DueDateAgingCertificate::decode(&fake.canonical_bytes().unwrap()).unwrap();
        let refusal = h
            .book
            .replay_due_date_aging(&h.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::VERIFICATION, "{refusal:?}");
    }
}

#[test]
fn due_date_containers_and_requests_reject_malformed_or_unbounded_inputs() {
    let h = Harness::new();
    let certificate = h.certify(&h.request("2026-03-31")).certificate;
    let bytes = certificate.canonical_bytes().unwrap();
    for length in (0..bytes.len())
        .step_by(37)
        .chain(bytes.len().saturating_sub(64)..bytes.len())
    {
        assert!(DueDateAgingCertificate::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(DueDateAgingCertificate::decode(&trailing).is_err());
    let source_size = certificate.source().canonical_bytes().unwrap().len();
    let count_offset = 4 + DUE_DATE_AGING_CERTIFICATE_FORMAT.len() + 16 + 32 + 4 + source_size + 4;
    let mut huge = bytes.clone();
    huge[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(DueDateAgingCertificate::decode(&huge).is_err());
    let mut changed = bytes;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(DueDateAgingCertificate::decode(&changed).is_err());
    assert!(total([MAX_AGING_CERTIFICATE_BYTES + 1]).is_err());
    assert!(total([usize::MAX, 1]).is_err());
    let mut over_bounds = h.request("2026-03-31");
    over_bounds.buckets = AgingBuckets::new((0..129).collect()).unwrap();
    let mut future = h.request("2026-03-31");
    future.known_at = Some(CommitSeq(h.head().0 + 1));
    for request in [over_bounds, future] {
        assert!(
            h.book
                .certify_due_date_aging(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request)
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn due_date_authorization_precedes_observation_on_every_entrypoint() {
    let mut h = Harness::new();
    let invoice = h.invoice();
    let request = h.request("2026-04-01");
    let certificate = h.certify(&request).certificate;
    let reconciliation_request = crate::AgingReconciliationRequest {
        account: account_vid(BOOK, "ap"),
        effective_through: request.effective_through,
        known_at: Some(certificate.source().known_at),
        buckets: request.buckets.clone(),
    };
    let reconciliation = h
        .book
        .certify_due_date_aging_reconciliation(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &reconciliation_request,
        )
        .unwrap()
        .unwrap()
        .certificate;
    let cx = h.cx();
    let row = cx
        .query()
        .with_restriction(|| h.book.db.vertex(invoice.vid))
        .unwrap()
        .unwrap();
    let original = fa_journal::rows::prop(&row, property::FA_PAYLOAD)
        .cloned()
        .unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        invoice.vid,
        property::FA_PAYLOAD,
        Some(original),
        CanonicalScalar::bytes(Vec::new()).unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let head = h.head();
    let unrestricted = cap(&["read", "produce"]);
    let restricted = [
        cap(&["post"]),
        unrestricted
            .clone()
            .for_books(&[Id128([0x81; 16])])
            .unwrap(),
        unrestricted.clone().expiring_at(head),
        unrestricted.clone().for_accounts(&["ap"]).unwrap(),
        unrestricted.clone().for_periods(&["FY2026-P03"]).unwrap(),
        unrestricted.clone().effective_through(day("2026-04-01")),
        unrestricted.clone().on_branch(Id128([0x44; 16])).unwrap(),
        unrestricted.known_at_most(CommitSeq(certificate.source().known_at.0 - 1)),
    ];
    for capability in restricted {
        // Both bases scan whole-book native control inputs. Even an account
        // caveat matching the displayed leaf cannot authorize that scan.
        for result in [
            h.book
                .reconcile_effective_date_aging(
                    &cx,
                    PRINCIPAL,
                    &capability,
                    &reconciliation_request,
                )
                .map(|result| result.map(|_| ())),
            h.book
                .reconcile_due_date_aging(&cx, PRINCIPAL, &capability, &reconciliation_request)
                .map(|result| result.map(|_| ())),
            h.book
                .certify_due_date_aging_reconciliation(
                    &cx,
                    PRINCIPAL,
                    &capability,
                    &reconciliation_request,
                )
                .map(|result| result.map(|_| ())),
            h.book
                .replay_due_date_aging_reconciliation(
                    &cx,
                    PRINCIPAL,
                    &capability,
                    &reconciliation,
                    &reconciliation_request,
                )
                .map(|result| result.map(|_| ())),
            h.book
                .certify_due_date_aging_reconciliation_from_sources(
                    &cx,
                    PRINCIPAL,
                    &capability,
                    reconciliation.aging_source(),
                    reconciliation.control_source(),
                    &reconciliation_request,
                )
                .map(|result| result.map(|_| ())),
        ] {
            assert_eq!(result.unwrap().unwrap_err().exit, exit::SAFETY);
        }
        let result = h
            .book
            .certify_due_date_aging(&cx, PRINCIPAL, &capability, &request)
            .unwrap()
            .unwrap_err();
        assert_eq!(result.exit, exit::SAFETY);
        let result = h
            .book
            .certify_due_date_aging_from_source(
                &cx,
                PRINCIPAL,
                &capability,
                certificate.source(),
                request.effective_through,
                &request.buckets,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(result.exit, exit::SAFETY);
        let result = h
            .book
            .replay_due_date_aging(&cx, PRINCIPAL, &capability, &certificate)
            .unwrap()
            .unwrap_err();
        assert_eq!(result.exit, exit::SAFETY);
        let result = h
            .book
            .replay_due_date_aging_for(&cx, PRINCIPAL, &capability, &certificate, &request)
            .unwrap()
            .unwrap_err();
        assert_eq!(result.exit, exit::SAFETY);
    }
    assert!(
        h.book
            .certify_due_date_aging(&cx, PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
    assert_eq!(
        h.book
            .certify_due_date_aging_reconciliation(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &reconciliation_request,
            )
            .unwrap()
            .unwrap_err()
            .exit,
        exit::SAFETY
    );
    assert_eq!(
        h.book
            .replay_due_date_aging_reconciliation(
                &cx,
                VId(8),
                &cap(&["read"]),
                &reconciliation,
                &reconciliation_request,
            )
            .unwrap()
            .unwrap_err()
            .exit,
        exit::SAFETY
    );
    assert!(
        h.book
            .certify_due_date_aging(&cx, VId(8), &cap(&["read", "produce"]), &request)
            .unwrap()
            .is_err()
    );
    assert!(!matches!(
        h.book
            .replay_due_date_aging(&cx, PRINCIPAL, &cap(&["read"]), &certificate),
        Ok(Ok(_))
    ));
    assert_eq!(h.head(), head);
}

#[test]
fn due_date_replay_binds_the_recipients_fixed_account_date_prefix_and_buckets() {
    let mut h = Harness::new();
    h.invoice();
    let certified = h.certify(&h.request("2026-04-01"));
    let expected = certified.certificate.request().unwrap();
    assert_eq!(
        h.book
            .replay_due_date_aging_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &certified.certificate,
                &expected,
            )
            .unwrap()
            .unwrap(),
        certified.report
    );
    let mut mismatches = Vec::new();
    let mut request = expected.clone();
    request.known_at = None;
    mismatches.push(request);
    let mut request = expected.clone();
    request.known_at = Some(CommitSeq(expected.known_at.unwrap().0 - 1));
    mismatches.push(request);
    let mut request = expected.clone();
    request.account = None;
    mismatches.push(request);
    let mut request = expected.clone();
    request.effective_through = day("2026-03-31");
    mismatches.push(request);
    let mut request = expected;
    request.buckets = AgingBuckets::new(vec![30]).unwrap();
    mismatches.push(request);
    for request in mismatches {
        assert!(
            h.book
                .replay_due_date_aging_for(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &certified.certificate,
                    &request,
                )
                .unwrap()
                .is_err()
        );
    }
}
