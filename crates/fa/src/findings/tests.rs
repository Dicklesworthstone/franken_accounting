use super::*;
use crate::{BookKeys, Entropy, ProcedureRequest, ReportArtifact};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use std::path::Path;

const PRINCIPAL: VId = VId(83);
fn cap(ops: &[&str]) -> Capability { Capability::embedded(PRINCIPAL, ops).unwrap() }
fn day(n: u8) -> DateDay { DateDay::from_ymd(2026, 1, n).unwrap() }

struct Fixture {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    unit: UnitId,
    evidence: Vec<EvidenceRef>,
    seed: u8,
    next: u32,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let unit = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime.block_on(AsyncBook::create_with_vfs(
            &cx, vfs.clone(), Path::new("findings"), BookKeys::for_development(seed),
            BookSpec { book_id: Id128([seed; 16]), name: "Finding publication".into(), base_unit: unit,
                calendar: FiscalCalendar::monthly("findings", 1, 0).unwrap(), time_zone_policy: None,
                entities: Vec::new(), opening_date: None }, Entropy::deterministic(u64::from(seed)),
        )).unwrap();
        let chart: Vec<_> = [("1000", AccountType::ASSET), ("1010", AccountType::ASSET), ("3000", AccountType::EQUITY)]
            .into_iter().map(|(code, kind)| AccountSpec { code: code.into(), name: code.into(),
                account_type: kind.0, normal_balance: u8::from(kind == AccountType::EQUITY), is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency, parent_code: None, limit: None }).collect();
        runtime.block_on(book.install_chart(&cx, &chart, PRINCIPAL, day(1), b"chart")).unwrap().unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
        runtime.block_on(book.transition_period(&cx, "FY2026-P01", PeriodTransition::Open,
            PRINCIPAL, 1, day(1), b"open", &cap(&["close"]))).unwrap().unwrap();
        let document = Document { book_id: book.context().book_id, kind: 1, mime: "text/plain".into(),
            grade: 3, retrieved_by: PRINCIPAL, bytes: b"Native evidence for findings".to_vec() };
        runtime.block_on(book.add_document(&cx, &document)).unwrap().unwrap();
        Self { runtime, root, book, vfs, unit, evidence: vec![document.evidence_ref(1)], seed, next: 0 }
    }
    fn cx(&self) -> PurposeContexts { PurposeContexts::narrow_runtime_root(&self.root) }
    fn head(&self) -> CommitSeq { self.book.head(&self.cx()).unwrap() }
    fn id(&self, code: &str) -> VId { account_vid(self.book.context().book_id, code) }
    fn post(&mut self, date: u8, from: &str, to: &str, amount: i128) -> VId {
        self.next += 1;
        let cx = self.cx();
        let legs = vec![LegPayload::simple(Side::Credit, self.id(from), Amount::new(self.unit, amount)),
            LegPayload::simple(Side::Debit, self.id(to), Amount::new(self.unit, amount))];
        let proposal = EntryPayload { schema_minor: 0, book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK, class: EntryClass::ORIGINAL, effective_date: day(date), document_date: None,
            description: self.book.seal_text(&cx, "Real source transaction").unwrap(), effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(), legs, control: None, base_totals: None,
            idempotency_key: self.next.to_le_bytes().to_vec(),
            origin: EntryOrigin::Intent { intent_oid: Oid([1;32]), intent_kind: 1 }, principal_ref: PRINCIPAL,
            session_ref: None, evidence: self.evidence.clone(), supersession: Vec::new(), pending: None,
            external_ids: Vec::new(), tags: Vec::new(), extensions: Vec::new() };
        let result = self.runtime.block_on(self.book.post(&cx, PostRequest { proposal, approvals: Vec::new(),
            plan_certificate: None, capability: cap(&["post"]) })).unwrap().unwrap();
        match result { Posted::Committed { entry_ref, .. } => entry_ref.vid, _ => panic!("fresh transaction") }
    }
    fn certify(&mut self, id: &str, source: Option<VId>) -> ProcedureCertificate {
        let cx = self.cx();
        let inputs = fa_lantern::catalog::Inputs { account: source.map(|_| self.id("1000")), source };
        let mut request = ProcedureRequest::new(id, inputs).unwrap();
        request.effective_through = Some(day(31));
        let certified = self.book.certify_procedure(&cx, PRINCIPAL, &cap(&["read", "produce"]), &request).unwrap().unwrap();
        let artifact = ReportArtifact::try_from(&certified.certificate).unwrap();
        self.runtime.block_on(self.book.retain_report_artifact(&cx, PRINCIPAL, &cap(&["read", "produce"]),
            &artifact.canonical_bytes().unwrap(), Some(artifact.digest()))).unwrap().unwrap();
        certified.certificate
    }
    fn record(&mut self, digest: &[u8;32]) -> Result<RecordedFindings, Refusal> {
        let cx = self.cx();
        self.runtime.block_on(self.book.record_findings(&cx, PRINCIPAL, &cap(&["read", "produce"]), digest)).unwrap()
    }
    fn read(&self, digest: &[u8;32]) -> Result<RecordedFindings, Refusal> {
        self.runtime.block_on(self.book.read_findings(&self.cx(), PRINCIPAL, &cap(&["read"]), digest)).unwrap()
    }
    fn count(&self) -> usize {
        self.book.query(&self.cx(), |db, _| Ok(db.vertices_at(db.frontier().map_err(KernelError::from)?)
            .map_err(KernelError::from)?.iter().filter(|r| r.labels.contains(&label::FINDING)).count())).unwrap()
    }
    fn reopen(self) -> Self {
        let Self { runtime, root, book, vfs, unit, evidence, seed, next } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime.block_on(AsyncBook::open_with_vfs(&cx, vfs.clone(), Path::new("findings"),
            BookKeys::for_development(seed), Entropy::deterministic(u64::from(seed)))).unwrap();
        Self { runtime, root, book, vfs, unit, evidence, seed, next }
    }
}

#[test]
fn whole_run_has_one_birth_replays_after_reopen_and_retries_without_posting() {
    let mut f = Fixture::new(111);
    let source = f.post(10, "3000", "1000", 100);
    f.post(11, "1000", "1010", 80);
    for id in ["trace.network_fifo", "trace.network_lifo", "trace.network_libr", "trace.network_pro_rata"] {
        let cert = f.certify(id, Some(source));
        let at = f.head();
        let before = f.book.query(&f.cx(), |db, book| Ok(fa_registers::entries_at(db, book, at)?.len())).unwrap();
        let recorded = f.record(cert.digest()).unwrap();
        assert_eq!(recorded.recorded_at.0, at.0 + 1);
        assert_eq!(recorded.report, *cert.report());
        assert_eq!(recorded.finding_ids.len(), cert.report().findings.len());
        assert_eq!(recorded.report.findings.iter().map(|v| v.statistic.value).sum::<i128>(), 100);
        let after = f.book.query(&f.cx(), |db, book| Ok(fa_registers::entries_at(db, book, recorded.recorded_at)?.len())).unwrap();
        assert_eq!(before, after, "findings never add accounting entries");
        assert_eq!(f.record(cert.digest()).unwrap(), recorded);
        assert_eq!(f.head(), recorded.recorded_at);
        f = f.reopen();
        f.post(1, "3000", "1000", 7);
        let head = f.head();
        assert_eq!(f.read(cert.digest()).unwrap(), recorded);
        assert_eq!(f.record(cert.digest()).unwrap(), recorded);
        assert_eq!(f.head(), head);
    }
}

#[test]
fn every_citation_becomes_a_same_birth_edge_without_losing_ordered_paths() {
    let mut f = Fixture::new(112);
    let source = f.post(10, "3000", "1000", 10);
    let moved = f.post(11, "1000", "1010", 10);
    let cert = f.certify("trace.network_fifo", Some(source));
    let recorded = f.record(cert.digest()).unwrap();
    assert!(recorded.report.findings[0].cites.contains(&Cite::Entry(moved)));
    let checked = f.book.query(&f.cx(), |db, book| {
        for (id, finding) in recorded.finding_ids.iter().zip(&recorded.report.findings) {
            for cite in &finding.cites {
                let dst = target(cite, book);
                let edge = db.edge_at(edge_id(relation::CITES, *id, dst), recorded.recorded_at).map_err(KernelError::from)?.unwrap();
                assert_eq!(edge.entry.created_at, recorded.recorded_at);
                assert!(cite.resolves(db, book, cert.known_at())?);
            }
        }
        Ok(())
    });
    checked.unwrap();
    assert_eq!(f.read(cert.digest()).unwrap().report.findings, cert.report().findings);
}

#[test]
fn current_authority_and_complete_retained_source_precede_any_publication() {
    let mut f = Fixture::new(113);
    f.post(10, "3000", "1000", 100);
    let cert = f.certify("jet.weekend", None);
    let at = f.head();
    for denied in [cap(&["read"]), cap(&["produce"]), cap(&["read", "produce"]).expiring_at(at),
        cap(&["read", "produce"]).for_accounts(&["1000"]).unwrap()] {
        let cx = f.cx();
        let refusal = f.runtime.block_on(f.book.record_findings(&cx, PRINCIPAL, &denied, &[0;32])).unwrap().unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY);
    }
    assert!(f.record(&[0;32]).is_err());
    assert_eq!(f.head(), at);
    assert_eq!(f.count(), 0);
    let recorded = f.record(cert.digest()).unwrap();
    let denied = cap(&["read"]).expiring_at(f.head());
    assert_eq!(f.runtime.block_on(f.book.read_findings(&f.cx(), PRINCIPAL, &denied, cert.digest())).unwrap().unwrap_err().exit, exit::SAFETY);
    assert_eq!(f.head(), recorded.recorded_at);
}

#[test]
fn empty_run_is_durable_and_cannot_be_confused_with_never_recorded() {
    let mut f = Fixture::new(114);
    f.post(5, "3000", "1000", 3); // Monday, not a weekend.
    let cert = f.certify("jet.weekend", None);
    assert!(cert.report().findings.is_empty());
    assert!(f.read(cert.digest()).is_err());
    let r = f.record(cert.digest()).unwrap();
    assert!(r.finding_ids.is_empty());
    assert_eq!(f.count(), 1, "the complete zero-findings run has an index");
    assert_eq!(f.record(cert.digest()).unwrap(), r);
    assert_eq!(f.read(cert.digest()).unwrap(), r);
}

#[test]
fn modified_then_restored_finding_or_edge_cannot_be_repaired_by_retry() {
    for edge_attack in [false, true] {
        let mut f = Fixture::new(if edge_attack { 115 } else { 116 });
        f.post(10, "3000", "1000", 10);
        let cert = f.certify("jet.weekend", None);
        let r = f.record(cert.digest()).unwrap();
        let fid = r.finding_ids[0];
        let dst = target(&r.report.findings[0].cites[0], f.book.context());
        let mut bad = WriteBatch::new(relation::CITES);
        let original = f.book.query(&f.cx(), |db, _| Ok(db.vertex_at(fid, r.recorded_at).map_err(KernelError::from)?.unwrap())).unwrap();
        if edge_attack { bad.set_edge_property(edge_id(relation::CITES, fid, dst), property::FA_DIGEST,
            Some(CanonicalScalar::bytes(vec![0;32]).unwrap())); }
        else { bad.set_vertex_property(fid, property::FA_DIGEST, Some(CanonicalScalar::bytes(vec![0;32]).unwrap())); }
        let cx = f.cx();
        f.runtime.block_on(f.book.db.write(&cx.commit(), bad)).unwrap();
        let head = f.head();
        assert!(f.read(cert.digest()).is_err());
        assert!(f.record(cert.digest()).is_err());
        assert_eq!(f.head(), head);
        let mut restore = WriteBatch::new(relation::CITES);
        if edge_attack { restore.set_edge_property(edge_id(relation::CITES, fid, dst), property::FA_DIGEST, None); }
        else { restore.set_vertex_property(fid, property::FA_DIGEST, prop(&original, property::FA_DIGEST).cloned()); }
        f.runtime.block_on(f.book.db.write(&cx.commit(), restore)).unwrap();
        assert!(f.read(cert.digest()).is_err(), "exact restoration cannot erase the rewrite");
        assert!(f.record(cert.digest()).is_err());
    }
}

#[test]
fn orphan_identity_aborts_the_entire_transaction_without_a_run_index() {
    let mut f = Fixture::new(117);
    f.post(10, "3000", "1000", 1);
    f.post(11, "3000", "1000", 1);
    let cert = f.certify("jet.weekend", None);
    assert_eq!(cert.report().findings.len(), 2);
    let blocked = finding_vid(f.book.context().book_id, cert.digest(), 1);
    let mut bad = WriteBatch::new(relation::DERIVED_FROM);
    bad.create_vertex(blocked, vec![label::FINDING], vec![]);
    let cx = f.cx();
    f.runtime.block_on(f.book.db.write(&cx.commit(), bad)).unwrap();
    let head = f.head();
    assert!(f.record(cert.digest()).is_err());
    assert_eq!(f.head(), head);
    assert_eq!(f.count(), 1, "no root or first finding leaked on failed staging");
    assert!(f.read(cert.digest()).is_err());
}
