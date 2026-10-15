//! Real native transactions exercise the storage representation; actual
//! journal-derived report certificates exercise its public AsyncBook path.

use super::*;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use crate::{AsyncBook, BookKeys, Entropy, ReportSelection};
use fa_journal::{AccountSpec, BookSpec, Capability, Document, PostRequest, UnitPolicy};
use fa_model::{AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;

const BOOK: Id128 = Id128([0xc1; 16]);
const PRINCIPAL: VId = VId(1);
const PERIOD: &str = "FY2026-P01";

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let units = UnitRegistry::embedded().unwrap();
        let book = runtime.block_on(AsyncBook::create_with_vfs(
            &cx, vfs.clone(), std::path::Path::new("certificate-book"),
            BookKeys::for_development(0xc1),
            BookSpec {
                book_id: BOOK,
                name: "Native certificate storage".into(),
                base_unit: units.lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("certificate-storage", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(193),
        )).unwrap();
        Self { runtime, root, book, vfs }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn write(&mut self, batch: WriteBatch) -> CommitSeq {
        let cx = self.cx();
        self.runtime.block_on(self.book.db.write(&cx.commit(), batch)).unwrap()
    }

    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn retain(&mut self, certificate: &ReportCertificate) -> Result<RetainedCertificate, Refusal> {
        let cx = self.cx();
        self.runtime.block_on(self.book.retain_certificate(&cx, certificate)).unwrap()
    }

    fn read(&self, digest: &[u8; 32]) -> Result<ReportCertificate, Refusal> {
        let cx = self.cx();
        self.runtime.block_on(self.book.read_certificate(&cx, digest)).unwrap()
    }

    fn reopen(self) -> Self {
        let Self { runtime, root, book, vfs } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime.block_on(AsyncBook::open_with_vfs(
            &cx, vfs.clone(), std::path::Path::new("certificate-book"),
            BookKeys::for_development(0xc1), Entropy::deterministic(194),
        )).unwrap();
        Self { runtime, root, book, vfs }
    }

    fn certificate(&self) -> ReportCertificate {
        self.book.certify_report(
            &self.cx(), ReportSelection::ExplainBalance {
                account: account_vid(BOOK, "1000"), period: PERIOD.into(),
            }, None,
        ).unwrap().unwrap().certificate
    }

    fn populated() -> (Self, ReportCertificate) {
        let mut h = Self::new();
        let cx = h.cx();
        let accounts: Vec<_> = [("1000", AccountType::ASSET, 0), ("4000", AccountType::REVENUE, 1)]
            .into_iter().map(|(code, kind, normal_balance)| AccountSpec {
                code: code.into(), name: code.into(), account_type: kind.0,
                normal_balance, is_leaf: true, unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None, limit: None,
            }).collect();
        h.runtime.block_on(h.book.install_chart(
            &cx, &accounts, PRINCIPAL, DateDay::from_ymd(2026, 1, 1).unwrap(), b"chart",
        )).unwrap().unwrap();
        h.runtime.block_on(h.book.create_periods(&cx, 2026)).unwrap();
        h.runtime.block_on(h.book.transition_period(
            &cx, PERIOD, PeriodTransition::Open, PRINCIPAL, 1,
            DateDay::from_ymd(2026, 1, 1).unwrap(), b"open",
            &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        )).unwrap().unwrap();
        for n in 0..64 { h.post(n); }
        let certificate = h.certificate();
        assert!(certificate.output.len() > chunks::CHUNK_BYTES,
            "fixture must exercise more than one native row, not an inline certificate");
        (h, certificate)
    }

    fn post(&mut self, n: u32) {
        let cx = self.cx();
        let source = Document {
            book_id: BOOK, kind: 1, mime: "text/plain".into(), grade: 3,
            retrieved_by: PRINCIPAL, bytes: b"admitted report storage test evidence".to_vec(),
        };
        self.runtime.block_on(self.book.add_document(&cx, &source)).unwrap().unwrap();
        let usd = self.book.context().units.lookup("USD").unwrap();
        let legs = vec![
            LegPayload::simple(Side::Debit, account_vid(BOOK, "1000"), Amount::new(usd, 100)),
            LegPayload::simple(Side::Credit, account_vid(BOOK, "4000"), Amount::new(usd, 100)),
        ];
        let proposal = EntryPayload {
            schema_minor: 0, book_id: BOOK, branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay::from_ymd(2026, 1, 15).unwrap(), document_date: None,
            description: self.book.seal_text(&cx, "certificate storage posting").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(), legs,
            control: None, base_totals: None, idempotency_key: format!("post-{n}").into_bytes(),
            origin: EntryOrigin::Intent { intent_oid: Oid([0xc2; 32]), intent_kind: 1 },
            principal_ref: PRINCIPAL, session_ref: None, evidence: vec![source.evidence_ref(1)],
            supersession: Vec::new(), pending: None, external_ids: Vec::new(),
            extensions: Vec::new(), tags: Vec::new(),
        };
        self.runtime.block_on(self.book.post(&cx, PostRequest {
            proposal, approvals: Vec::new(), plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        })).unwrap().unwrap();
    }
}

#[test]
fn native_rows_cross_the_inline_boundary_with_one_atomic_publication() {
    let mut h = Harness::new();
    let cx = h.cx();
    let book = h.book.context().clone();
    for size in [1, chunks::CHUNK_BYTES, chunks::CHUNK_BYTES + 1,
        2 * chunks::CHUNK_BYTES, 2 * chunks::CHUNK_BYTES + 17] {
        // This subcomponent test uses arbitrary bytes, not a forged report.
        // Report validation is exercised by the public-facade test below.
        let expected: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let digest = domain_digest(b"test:certificate-storage", &[&expected]);
        let vid = certificate_vid(BOOK, &digest);
        let before = h.head();
        let batch = chunks::stage(&cx.query(), &book, &digest, vid, expected.clone()).unwrap().unwrap();
        let recorded_at = h.write(batch);
        assert_eq!(recorded_at.0, before.0 + 1);
        assert!(h.book.db.vertex_at(vid, before).unwrap().is_none());
        let row = h.book.db.vertex(vid).unwrap().unwrap();
        let payload = record_payload(&row, &book, &digest, vid).unwrap();
        match chunks::Manifest::decode(payload).unwrap() {
            None => {
                assert!(size <= chunks::CHUNK_BYTES);
                assert_eq!(payload, expected);
            }
            Some(manifest) => {
                assert!(size > chunks::CHUNK_BYTES);
                let actual = chunks::read(&h.book.db, &cx.query(), &book, &digest, &row, recorded_at, manifest)
                    .unwrap().unwrap();
                assert_eq!(actual, expected);
            }
        }
        assert_eq!(h.head(), recorded_at);
    }
}

#[test]
fn large_native_report_retains_reopens_replays_and_retries_without_changing_exported_bytes() {
    let (mut h, certificate) = Harness::populated();
    let encoded = certificate.canonical_bytes().unwrap();
    let before = h.head();
    let ack = h.retain(&certificate).unwrap();
    assert_eq!(ack.recorded_at.0, before.0 + 1);
    assert_eq!(h.read(&certificate.digest).unwrap(), certificate);
    assert_eq!(h.retain(&certificate).unwrap(), ack);
    assert_eq!(h.head(), ack.recorded_at);
    let mut h = h.reopen();
    assert_eq!(h.read(&certificate.digest).unwrap().canonical_bytes().unwrap(), encoded);
    h.post(64);
    let later = h.head();
    assert_eq!(h.read(&certificate.digest).unwrap(), certificate);
    let report = h.book.replay_report(&h.cx(), &certificate).unwrap().unwrap();
    assert_eq!(report.canonical_bytes().unwrap(), certificate.output);
    assert_eq!(h.retain(&certificate).unwrap(), ack);
    assert_eq!(h.head(), later);
}

#[test]
fn an_existing_fragment_identity_aborts_retention_without_publishing_the_root_or_other_parts() {
    let (mut h, certificate) = Harness::populated();
    let root = certificate_vid(BOOK, &certificate.digest);
    let fragment = chunks::fragment_vid(BOOK, &certificate.digest, 1);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    stage_record(&mut batch, h.book.context(), &certificate.digest, fragment, vec![0xff]).unwrap();
    h.write(batch);
    let before = h.head();
    assert_eq!(h.retain(&certificate).unwrap_err().code, crate::certificate::code::CERTIFICATE_INVALID);
    assert_eq!(h.head(), before);
    assert!(h.book.db.vertex(root).unwrap().is_none());
    assert!(h.book.db.vertex(chunks::fragment_vid(BOOK, &certificate.digest, 0)).unwrap().is_none());
    assert_eq!(h.book.db.vertex(fragment).unwrap().unwrap().created_at, before);
}

#[test]
fn incomplete_roots_are_neither_readable_nor_repaired_by_idempotent_retention() {
    let (mut h, certificate) = Harness::populated();
    let manifest = chunks::Manifest::new(certificate.canonical_bytes().unwrap().len()).unwrap();
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    stage_record(&mut batch, h.book.context(), &certificate.digest,
        certificate_vid(BOOK, &certificate.digest), manifest.encode().unwrap()).unwrap();
    h.write(batch);
    let before = h.head();
    assert_eq!(h.read(&certificate.digest).unwrap_err().code, crate::certificate::code::CERTIFICATE_INVALID);
    assert_eq!(h.retain(&certificate).unwrap_err().code, crate::certificate::code::CERTIFICATE_INVALID);
    assert_eq!(h.head(), before);
    assert!(h.book.db.vertex(chunks::fragment_vid(BOOK, &certificate.digest, 0)).unwrap().is_none());
}

#[test]
fn restoring_exact_root_or_fragment_bytes_does_not_erase_rewrite_history() {
    for root in [true, false] {
        let (mut h, certificate) = Harness::populated();
        h.retain(&certificate).unwrap();
        let vid = if root { certificate_vid(BOOK, &certificate.digest) }
            else { chunks::fragment_vid(BOOK, &certificate.digest, 0) };
        let row = h.book.db.vertex(vid).unwrap().unwrap();
        let original = prop(&row, property::FA_PAYLOAD).unwrap().clone();
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        batch.set_vertex_property(vid, property::FA_PAYLOAD, Some(scalar_bytes("tampered", vec![0xff]).unwrap()));
        h.write(batch);
        assert!(h.read(&certificate.digest).is_err());
        let mut restore = WriteBatch::new(relation::DERIVED_FROM);
        restore.set_vertex_property(vid, property::FA_PAYLOAD, Some(original));
        h.write(restore);
        let before = h.head();
        assert_eq!(h.read(&certificate.digest).unwrap_err().code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(h.retain(&certificate).unwrap_err().code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(h.head(), before);
    }
}

#[test]
fn invalid_full_certificate_is_refused_before_any_storage_publication() {
    let (mut h, mut certificate) = Harness::populated();
    let before = h.head();
    certificate.output[0] ^= 1;
    assert_eq!(h.retain(&certificate).unwrap_err().code, crate::certificate::code::CERTIFICATE_INVALID);
    assert_eq!(h.head(), before);
    assert!(h.book.db.vertex(certificate_vid(BOOK, &certificate.digest)).unwrap().is_none());
}

mod adversarial;
