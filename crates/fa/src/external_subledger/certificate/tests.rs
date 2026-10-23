use super::*;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::symbols::{property, relation};
use fa_model::{
    AccountType, ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef,
    EvidenceRef, LegPayload, Oid, Pending, Supersession, SupersessionKind, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;
use std::path::Path;

use crate::external_subledger::{
    EXTERNAL_SUBLEDGER_DOCUMENT_KIND, EXTERNAL_SUBLEDGER_MIME, ExternalSubledgerBatch,
    ExternalSubledgerDetail,
};
use crate::{BookKeys, CertificateStatus, Entropy};

const BOOK: Id128 = Id128([0x93; 16]);
const PRINCIPAL: VId = VId(7);
const REVIEWER: VId = VId(8);

fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    evidence: EvidenceRef,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                MemVfs::new().unwrap(),
                Path::new("external-feed-certificate"),
                BookKeys::for_development(0x93),
                BookSpec {
                    book_id: BOOK,
                    name: "External control reconciliation".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(0x93),
            ))
            .unwrap();
        let accounts = [
            ("control", AccountType::ASSET),
            ("cash", AccountType::ASSET),
            ("sales", AccountType::REVENUE),
            ("expense", AccountType::EXPENSE),
        ]
        .map(|(code, kind)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(kind == AccountType::REVENUE),
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
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
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P03",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                b"open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"ordinary supporting invoice".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            usd,
            evidence: document.evidence_ref(1),
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn id(&self, code: &str) -> VId {
        account_vid(BOOK, code)
    }
    fn legs(&self, debit: &str, credit: &str, amount: i128) -> Vec<LegPayload> {
        vec![
            LegPayload::simple(Side::Debit, self.id(debit), Amount::new(self.usd, amount)),
            LegPayload::simple(Side::Credit, self.id(credit), Amount::new(self.usd, amount)),
        ]
    }
    fn proposal(&self, key: &str, date: &str, legs: Vec<LegPayload>) -> EntryPayload {
        EntryPayload {
            schema_minor: 0,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&self.cx(), key).unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([5; 32]),
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
        }
    }
    fn post(&mut self, proposal: EntryPayload) -> EntryRef {
        let cx = self.cx();
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
    fn batch(&mut self, key: &str, date: &str, amount: i128) -> EntryRef {
        let detail = ExternalSubledgerBatch {
            book_id: BOOK,
            feed: "customer-ar".into(),
            batch_key: key.into(),
            effective_date: day(date),
            rows: vec![
                ExternalSubledgerDetail {
                    source_digest: [1; 32],
                    account: self.id("control"),
                    side: Side::Debit,
                    amount: Amount::new(self.usd, amount / 2),
                    dimensions: Vec::new(),
                },
                ExternalSubledgerDetail {
                    source_digest: [2; 32],
                    account: self.id("control"),
                    side: Side::Debit,
                    amount: Amount::new(self.usd, amount - amount / 2),
                    dimensions: Vec::new(),
                },
                ExternalSubledgerDetail {
                    source_digest: [3; 32],
                    account: self.id("sales"),
                    side: Side::Credit,
                    amount: Amount::new(self.usd, amount),
                    dimensions: Vec::new(),
                },
            ],
        };
        let document = Document {
            book_id: BOOK,
            kind: EXTERNAL_SUBLEDGER_DOCUMENT_KIND,
            mime: EXTERNAL_SUBLEDGER_MIME.into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: detail.canonical_bytes().unwrap(),
        };
        let cx = self.cx();
        self.runtime
            .block_on(self.book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        let citation = detail.evidence().unwrap();
        self.runtime
            .block_on(self.book.record_review(
                &cx,
                &Capability::embedded(REVIEWER, &["approve"]).unwrap(),
                &citation.document_oid,
                Vec::new(),
            ))
            .unwrap()
            .unwrap();
        let mut template = self.proposal(key, date, Vec::new());
        template.evidence = vec![citation];
        let proposal = self
            .runtime
            .block_on(self.book.prepare_external_subledger(
                &cx,
                citation.document_oid,
                template,
                &cap(&["read", "post"]),
            ))
            .unwrap()
            .unwrap();
        self.post(proposal)
    }
    fn reverse(&mut self, target: EntryRef, key: &str, date: &str) -> EntryRef {
        let (entry, _) = self
            .book
            .query(&self.cx(), |db, _| {
                Ok(fa_journal::post::read_entry(db, target.vid)?.unwrap())
            })
            .unwrap();
        let legs = entry
            .proposal
            .legs
            .into_iter()
            .map(|mut leg| {
                leg.side = if leg.side == Side::Debit {
                    Side::Credit
                } else {
                    Side::Debit
                };
                leg
            })
            .collect();
        let mut proposal = self.proposal(key, date, legs);
        proposal.class = EntryClass::REVERSAL;
        proposal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        self.post(proposal)
    }
    fn request(&self, through: &str) -> ExternalFeedRequest {
        ExternalFeedRequest {
            feed: "customer-ar".into(),
            control_account: self.id("control"),
            effective_through: day(through),
            known_at: None,
        }
    }
    fn certify(&self, request: &ExternalFeedRequest) -> CertifiedExternalFeed {
        self.book
            .certify_external_feed(&self.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
            .unwrap()
            .unwrap()
    }
    fn replay(&self, certificate: &ExternalFeedCertificate) -> ExternalFeedReconciliation {
        self.book
            .replay_external_feed(
                &self.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                certificate,
                &certificate.request().unwrap(),
            )
            .unwrap()
            .unwrap()
    }
    fn status(&self, certificate: &ExternalFeedCertificate) -> CertificateStatus {
        self.book
            .external_feed_certificate_status(&self.cx(), PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap()
    }
}

#[test]
fn whole_feed_binds_gross_detail_and_reversal_ancestry_at_both_coordinates() {
    let mut h = Harness::new();
    let original = h.batch("first", "2026-03-10", 10_000);
    let certified = h.certify(&h.request("2026-03-15"));
    assert!(certified.report.reconciled);
    assert_eq!(certified.report.batches.len(), 1);
    assert_eq!(certified.report.batches[0].detail_rows, 3);
    assert_eq!(certified.report.rows[0].detail_debits, 10_000);
    assert_eq!(certified.report.totals[0].register_debits, 10_000);
    let reversal = h.reverse(original, "reversal", "2026-03-12");
    h.reverse(reversal, "reverse-reversal", "2026-03-13");
    let current = h.certify(&h.request("2026-03-15"));
    assert!(current.report.reconciled);
    assert_eq!(current.report.batches.len(), 1);
    assert_eq!(current.report.contributions.len(), 3);
    assert_eq!(current.report.rows[0].detail_debits, 20_000);
    assert_eq!(current.report.rows[0].detail_credits, 10_000);
    assert_eq!(h.replay(&certified.certificate), certified.report);
    assert!(matches!(h.status(&certified.certificate),
        CertificateStatus::SupersededBy {later_entries, ..} if later_entries.len() == 2));
    let before_reversal = h.certify(&h.request("2026-03-11"));
    assert_eq!(before_reversal.report.contributions.len(), 1);
    assert_eq!(before_reversal.report.rows[0].control_credits, 0);
}

#[test]
fn zero_net_uncovered_activity_is_visible_and_unrelated_or_future_entries_do_not_supersede() {
    let mut h = Harness::new();
    h.batch("first", "2026-03-10", 10_000);
    let saved = h.certify(&h.request("2026-03-15"));
    let unrelated = h.proposal("unrelated", "2026-03-11", h.legs("expense", "cash", 500));
    h.post(unrelated);
    h.batch("future", "2026-03-20", 2_000);
    assert!(matches!(
        h.status(&saved.certificate),
        CertificateStatus::Current { .. }
    ));
    let contamination = h.proposal("zero-net", "2026-03-12", h.legs("control", "control", 100));
    let posted = h.post(contamination);
    let dirty = h.certify(&h.request("2026-03-15"));
    assert!(!dirty.report.reconciled);
    assert_eq!(dirty.report.unattributed.len(), 2);
    assert_eq!(dirty.report.rows[0].detail_debits, 10_000);
    assert_eq!(dirty.report.rows[0].control_debits, 10_100);
    assert_eq!(dirty.report.rows[0].control_credits, 100);
    assert_eq!(h.replay(&dirty.certificate), dirty.report);
    assert!(matches!(h.status(&saved.certificate),
        CertificateStatus::SupersededBy {later_entries, ..} if later_entries == [posted.vid]));
}

#[test]
fn pending_release_after_the_effective_cutoff_supersedes_the_original_reservation() {
    let mut h = Harness::new();
    let mut pending = h.proposal("hold", "2026-03-10", h.legs("control", "cash", 400));
    pending.class = EntryClass::PENDING;
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let held = h.post(pending);
    let saved = h.certify(&h.request("2026-03-15"));
    assert!(!saved.report.reconciled);
    assert_eq!(saved.report.totals[0].pending_debits, 400);
    let mut release = h.proposal("release", "2026-03-20", Vec::new());
    release.class = EntryClass::RESOLUTION;
    release.control = Some(ControlPayload::ReservationRelease);
    release.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(held),
        disposition: Some(Disposition::Voids),
    });
    let released = h.post(release);
    let current = h.certify(&h.request("2026-03-15"));
    assert!(current.report.reconciled);
    assert!(current.report.rows.is_empty());
    assert_eq!(h.replay(&saved.certificate), saved.report);
    assert!(matches!(h.status(&saved.certificate),
        CertificateStatus::SupersededBy {later_entries, ..} if later_entries == [released.vid]));
}

#[test]
fn checksum_repair_cannot_forge_output_source_closure_or_recipient_question() {
    let mut h = Harness::new();
    h.batch("first", "2026-03-10", 10_000);
    let saved = h.certify(&h.request("2026-03-15"));
    let original = &saved.certificate;
    let bytes = original.canonical_bytes().unwrap();
    assert_eq!(ExternalFeedCertificate::decode(&bytes).unwrap(), *original);
    let mut wrong = original.request().unwrap();
    for request in [
        ExternalFeedRequest {
            feed: "different".into(),
            ..wrong.clone()
        },
        ExternalFeedRequest {
            control_account: h.id("cash"),
            ..wrong.clone()
        },
        ExternalFeedRequest {
            effective_through: day("2026-03-14"),
            ..wrong.clone()
        },
        ExternalFeedRequest {
            known_at: None,
            ..wrong.clone()
        },
    ] {
        assert_eq!(
            h.book
                .replay_external_feed(&h.cx(), PRINCIPAL, &cap(&["read"]), original, &request,)
                .unwrap()
                .unwrap_err()
                .exit,
            exit::VERIFICATION
        );
    }
    let mut forged = original.clone();
    *forged.output.last_mut().unwrap() ^= 1;
    forged.digest = domain_digest(DIGEST, &[&forged.body_bytes().unwrap()]);
    let decoded = ExternalFeedCertificate::decode(&forged.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        h.book
            .replay_external_feed(&h.cx(), PRINCIPAL, &cap(&["read"]), &decoded, &wrong,)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
    forged = original.clone();
    forged.inputs.remove(0);
    assert!(forged.body_bytes().is_err());
    forged = original.clone();
    forged.inputs[0].statement = forged.inputs[1].statement.clone();
    assert!(forged.body_bytes().is_err());
    let bounded = cap(&["read"]).known_at_most(original.known_at());
    assert!(
        h.book
            .replay_external_feed(&h.cx(), PRINCIPAL, &bounded, original, &wrong,)
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        h.book
            .external_feed_certificate_status(&h.cx(), PRINCIPAL, &bounded, original,)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    wrong.known_at = Some(CommitSeq(original.known_at().0 - 1));
    assert_eq!(
        h.book
            .replay_external_feed(&h.cx(), PRINCIPAL, &cap(&["read"]), original, &wrong,)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
}

#[test]
fn changed_review_refuses_current_truth_but_preserves_older_replay_and_checks_authority_first() {
    let mut h = Harness::new();
    h.batch("first", "2026-03-10", 10_000);
    let saved = h.certify(&h.request("2026-03-15"));
    let review = saved.report.batches[0].review.attestation;
    let cx = h.cx();
    let old = cx
        .query()
        .with_restriction(|| h.book.db.vertex(review))
        .unwrap()
        .unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        review,
        property::FA_DIGEST,
        fa_journal::rows::prop(&old, property::FA_DIGEST).cloned(),
        CanonicalScalar::bytes(vec![0; 32]).unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let request = h.request("2026-03-15");
    for capability in [
        cap(&["post"]),
        cap(&["produce"]),
        cap(&["read"]).for_accounts(&["control"]).unwrap(),
    ] {
        assert_eq!(
            h.book
                .reconcile_external_feed(&cx, PRINCIPAL, &capability, &request,)
                .unwrap()
                .unwrap_err()
                .code,
            fa_journal::refusal::code::CAPABILITY
        );
        assert_eq!(
            h.runtime
                .block_on(
                    h.book
                        .prepare_external_feed_history(&cx, PRINCIPAL, &capability, None,)
                )
                .unwrap()
                .unwrap_err()
                .code,
            fa_journal::refusal::code::CAPABILITY
        );
    }
    assert!(
        h.book
            .reconcile_external_feed(&cx, PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.replay(&saved.certificate), saved.report);
    assert_eq!(
        h.book
            .external_feed_certificate_status(&cx, PRINCIPAL, &cap(&["read"]), &saved.certificate,)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
}
