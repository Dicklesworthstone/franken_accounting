use super::*;

use std::path::Path;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::symbols::{property, relation};
use fa_model::{AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef,
    LegPayload, Oid, Settlement, account_vid};
use fa_money::{Amount, UnitId, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;
use crate::{BookKeys, Entropy};

const BOOK: Id128 = Id128([0x72; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "aging-cert-book";
fn day(text: &str) -> DateDay { DateDay::parse(text).unwrap() }
fn cap(ops: &[&str]) -> Capability { Capability::embedded(PRINCIPAL, ops).unwrap() }
fn keys() -> BookKeys { BookKeys::for_development(0x72) }
fn account(code: &str, kind: AccountType) -> AccountSpec {
    AccountSpec { code: code.into(), name: format!("{code} account"), account_type: kind.0,
        normal_balance: u8::from(matches!(kind, AccountType::LIABILITY | AccountType::REVENUE)),
        is_leaf: true, unit_policy: UnitPolicy::AnyCurrency, parent_code: None, limit: None }
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    eur: UnitId,
    evidence: EvidenceRef,
}
impl Harness {
    fn new() -> Self { Self::in_book(BOOK) }
    fn in_book(book_id: Id128) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let vfs = MemVfs::new().unwrap();
        let mut book = runtime.block_on(AsyncBook::create_with_vfs(&cx, vfs.clone(), Path::new(PATH), keys(), BookSpec {
            book_id, name: "Historical aging fixture".into(), base_unit: usd,
            calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(), time_zone_policy: None,
            entities: Vec::new(), opening_date: None,
        }, Entropy::deterministic(114))).unwrap();
        runtime.block_on(book.install_chart(&cx, &[
            account("ar", AccountType::ASSET), account("cash", AccountType::ASSET),
            account("sales", AccountType::REVENUE), account("ap", AccountType::LIABILITY),
            account("expense", AccountType::EXPENSE),
        ], PRINCIPAL, day("2026-01-01"), b"chart")).unwrap().unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
        runtime.block_on(book.transition_period(&cx, "FY2026-P03", PeriodTransition::Open,
            PRINCIPAL, 1, day("2026-03-01"), b"open", &cap(&["close"]))).unwrap().unwrap();
        let document = Document { book_id, kind: 1, mime: "text/plain".into(), grade: 3,
            retrieved_by: PRINCIPAL, bytes: b"Historical aging evidence".to_vec() };
        runtime.block_on(book.add_document(&cx, &document)).unwrap().unwrap();
        Self { runtime, root, vfs, book, usd, eur, evidence: document.evidence_ref(1) }
    }
    fn cx(&self) -> PurposeContexts { PurposeContexts::narrow_runtime_root(&self.root) }
    fn head(&self) -> CommitSeq { self.book.head(&self.cx()).unwrap() }
    fn id(&self, code: &str) -> VId { account_vid(self.book.context().book_id, code) }
    #[allow(clippy::too_many_arguments)]
    fn post(&mut self, key: &str, date: &str, unit: UnitId, accounts: (&str, &str),
        amount: i128, target: Option<EntryRef>) -> EntryRef
    {
        let cx = self.cx();
        let mut legs = vec![
            LegPayload::simple(Side::Debit, self.id(accounts.0), Amount::new(unit, amount)),
            LegPayload::simple(Side::Credit, self.id(accounts.1), Amount::new(unit, amount)),
        ];
        if let Some(target) = target {
            legs[1].settles.push(Settlement { target, ordinal: 0, amount: Amount::new(unit, amount) });
        }
        let proposal = EntryPayload {
            schema_minor: 0, book_id: self.book.context().book_id, branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL, effective_date: day(date), document_date: None,
            description: self.book.seal_text(&cx, key).unwrap(), effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(), legs, control: None,
            base_totals: None, idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent { intent_oid: Oid([8; 32]), intent_kind: 1 },
            principal_ref: PRINCIPAL, session_ref: None, evidence: vec![self.evidence],
            supersession: Vec::new(), pending: None, external_ids: Vec::new(),
            extensions: Vec::new(), tags: Vec::new(),
        };
        self.runtime.block_on(self.book.post(&cx, PostRequest {
            proposal, approvals: Vec::new(), plan_certificate: None, capability: cap(&["post"]),
        })).unwrap().unwrap().entry_ref()
    }
    fn request(&self, cutoff: &str) -> AgingRequest {
        AgingRequest { account: Some(self.id("ar")), effective_through: day(cutoff),
            known_at: None, buckets: AgingBuckets::thirty_day() }
    }
    fn certify(&self, request: &AgingRequest) -> CertifiedAging {
        self.book.certify_effective_date_aging(&self.cx(), PRINCIPAL,
            &cap(&["read", "produce"]), request).unwrap().unwrap()
    }
    fn replay(&self, certificate: &AgingCertificate) -> EffectiveDateAging {
        self.book.replay_effective_date_aging(&self.cx(), PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap().unwrap()
    }
    fn reopen(self) -> Self {
        let Self { runtime, root, vfs, book, usd, eur, evidence } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime.block_on(AsyncBook::open_with_vfs(&cx, vfs.clone(), Path::new(PATH), keys(),
            Entropy::deterministic(115))).unwrap();
        Self { runtime, root, vfs, book, usd, eur, evidence }
    }
}

fn reseal(c: &AgingCertificate, output: Vec<u8>) -> AgingCertificate {
    AgingCertificate::seal(c.source.clone(), c.effective_through, c.buckets.clone(),
        c.producer, c.capability_commitment, output).unwrap()
}

#[test]
fn partial_and_later_effective_payments_are_refolded_before_aging() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let before_payment = h.head();
    h.post("payment", "2026-03-15", h.usd, ("cash", "ar"), 40, Some(invoice));
    h.post("later-payment", "2026-03-25", h.usd, ("cash", "ar"), 20, Some(invoice));
    let head = h.head();
    let early = h.certify(&h.request("2026-03-10"));
    let middle = h.certify(&h.request("2026-03-20"));
    let late = h.certify(&h.request("2026-03-31"));
    for (certificate, expected) in [(&early, 100), (&middle, 60), (&late, 40)] {
        assert_eq!(certificate.report.known_at, head);
        assert_eq!(certificate.report.items.len(), 1);
        assert_eq!(certificate.report.items[0].item.open, expected);
        assert_eq!(certificate.report.totals[0].amounts.debits, expected);
        assert_eq!(h.replay(&certificate.certificate), certificate.report);
    }
    assert!(early.report.items[0].item.applications.is_empty());
    assert_eq!(middle.report.items[0].item.applications.len(), 1);
    assert_eq!(late.report.items[0].item.applications.len(), 2);
    assert_eq!(middle.report.items[0].age_days, 19);
    assert_eq!(middle.report.items[0].bucket, 1);
    let mut original = h.request("2026-03-31"); original.known_at = Some(before_payment);
    assert_eq!(h.certify(&original).report.items[0].item.open, 100);
    let ReportOutput::OpenItems(all_time) = h.book.replay_report(&h.cx(), middle.certificate.source())
        .unwrap().unwrap() else { panic!("wrong native source"); };
    assert_eq!(all_time.items.iter().find(|i| i.entry == invoice.vid).unwrap().open, 40,
        "filtering the already-netted source would incorrectly yield 40 instead of 60");
    assert_eq!(h.head(), head, "certification and replay append nothing");
}

#[test]
fn saved_sources_roundtrip_reopen_and_never_slide_to_later_head() {
    let mut h = Harness::new();
    h.post("first", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let old = h.certify(&h.request("2026-03-31"));
    let encoded = old.certificate.canonical_bytes().unwrap();
    let source_bytes = old.certificate.source().canonical_bytes().unwrap();
    let decoded = AgingCertificate::decode(&encoded).unwrap();
    assert_eq!(decoded, old.certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(decoded.output(), output_bytes(&old.report).unwrap());
    assert_eq!(decoded.producer(), PRINCIPAL);
    assert_eq!(*decoded.capability_commitment(), cap(&["read", "produce"]).commitment().unwrap());
    h.post("later", "2026-03-02", h.usd, ("ar", "sales"), 17, None);
    let h = h.reopen();
    assert_eq!(h.replay(&decoded), old.report);
    let from_source = h.book.certify_effective_date_aging_from_source(&h.cx(), PRINCIPAL,
        &cap(&["read", "produce"]), decoded.source(), day("2026-03-31"), &AgingBuckets::thirty_day())
        .unwrap().unwrap();
    assert_eq!(from_source.certificate, decoded);
    assert_eq!(from_source.certificate.source().canonical_bytes().unwrap(), source_bytes);
    assert_eq!(h.certify(&h.request("2026-03-31")).report.totals[0].amounts.debits, 117);
}

#[test]
fn exact_native_debit_credit_and_payable_totals_are_never_netted() {
    let mut h = Harness::new();
    let exact = (1_i128 << 90) + 1;
    h.post("usd", "2026-03-01", h.usd, ("ar", "sales"), exact, None);
    h.post("credit", "2026-03-01", h.usd, ("cash", "ar"), exact, None);
    h.post("eur", "2026-03-01", h.eur, ("ar", "sales"), 7, None);
    h.post("ap", "2026-03-01", h.usd, ("expense", "ap"), 19, None);
    let report = h.certify(&h.request("2026-03-31"));
    let usd = report.report.totals.iter().find(|t| t.unit_id == h.usd.0).unwrap();
    assert_eq!(usd.amounts.debits, exact);
    assert_eq!(usd.amounts.credits, exact);
    assert_eq!(usd.amounts.item_count, 2);
    let eur = report.report.totals.iter().find(|t| t.unit_id == h.eur.0).unwrap();
    assert_eq!(eur.amounts.debits, 7);
    assert_eq!(eur.amounts.credits, 0);
    assert_eq!(h.replay(&report.certificate), report.report);
    let mut payable = h.request("2026-03-31"); payable.account = Some(h.id("ap"));
    let payable = h.certify(&payable);
    assert_eq!(payable.report.totals[0].amounts.debits, 0);
    assert_eq!(payable.report.totals[0].amounts.credits, 19);
}

#[test]
fn repaired_checksums_do_not_authenticate_false_items_cells_or_totals() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post("payment", "2026-03-10", h.usd, ("cash", "ar"), 40, Some(invoice));
    let good = h.certify(&h.request("2026-03-31"));
    let mut altered = Vec::new();
    let mut r = good.report.clone(); r.items[0].item.open += 1; altered.push(r);
    let mut r = good.report.clone(); r.items[0].item.applications[0].live = false; altered.push(r);
    let mut r = good.report.clone(); r.items[0].item.applications[0].entry = VId(999); altered.push(r);
    let mut r = good.report.clone(); r.items[0].age_days += 1; altered.push(r);
    let mut r = good.report.clone(); r.cells[0].amounts.debits += 1; altered.push(r);
    let mut r = good.report.clone(); r.totals[0].amounts.credits = 1; altered.push(r);
    let mut r = good.report.clone(); r.items.clear(); altered.push(r);
    for changed in altered {
        let fake = reseal(&good.certificate, output_bytes(&changed).unwrap());
        let decoded = AgingCertificate::decode(&fake.canonical_bytes().unwrap()).unwrap();
        let denial = h.book.replay_effective_date_aging(&h.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap().unwrap_err();
        assert_eq!(denial.exit, exit::VERIFICATION);
    }
}

#[test]
fn source_substitution_and_changed_cutoff_or_buckets_cannot_reuse_saved_output() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let first = h.certify(&h.request("2026-03-31"));
    h.post("later", "2026-03-05", h.usd, ("ar", "sales"), 7, None);
    let second = h.certify(&h.request("2026-03-31"));
    let c = &first.certificate;
    let bad = [
        AgingCertificate::seal(second.certificate.source.clone(), c.effective_through, c.buckets.clone(),
            c.producer, c.capability_commitment, c.output.clone()).unwrap(),
        AgingCertificate::seal(c.source.clone(), day("2026-03-30"), c.buckets.clone(),
            c.producer, c.capability_commitment, c.output.clone()).unwrap(),
        AgingCertificate::seal(c.source.clone(), c.effective_through, AgingBuckets::new(vec![30]).unwrap(),
            c.producer, c.capability_commitment, c.output.clone()).unwrap(),
    ];
    for fake in bad {
        assert!(h.book.replay_effective_date_aging(&h.cx(), PRINCIPAL, &cap(&["read"]), &fake).unwrap().is_err());
    }
}

#[test]
fn malformed_containers_and_oversized_requests_fail_without_writes() {
    let h = Harness::new();
    let c = h.certify(&h.request("2026-03-31")).certificate;
    let bytes = c.canonical_bytes().unwrap();
    for length in (0..bytes.len()).step_by(37).chain(bytes.len().saturating_sub(64)..bytes.len()) {
        assert!(AgingCertificate::decode(&bytes[..length]).is_err());
    }
    for at in [0, 4, bytes.len() - 1] {
        let mut changed = bytes.clone(); changed[at] ^= 1;
        assert!(AgingCertificate::decode(&changed).is_err());
    }
    let mut trailing = bytes.clone(); trailing.push(0);
    assert!(AgingCertificate::decode(&trailing).is_err());
    let source_size = c.source.canonical_bytes().unwrap().len();
    let count_offset = 4 + AGING_CERTIFICATE_FORMAT.len() + 16 + 32 + 4 + source_size + 4;
    let mut huge = bytes; huge[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(AgingCertificate::decode(&huge).is_err());
    let mut changed = c.clone(); changed.source.output_digest[0] ^= 1;
    assert!(changed.canonical_bytes().is_err());
    assert!(total([MAX_AGING_CERTIFICATE_BYTES + 1]).is_err());
    assert!(total([usize::MAX, 1]).is_err());
    let head = h.head();
    let mut large = h.request("2026-03-31"); large.buckets = AgingBuckets::new((0..129).collect()).unwrap();
    let mut future = h.request("2026-03-31"); future.known_at = Some(CommitSeq(head.0 + 1));
    for request in [large, future] {
        assert!(h.book.certify_effective_date_aging(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request)
            .unwrap().is_err());
    }
    assert_eq!(h.head(), head);
}

#[test]
fn empty_results_and_explicit_bucket_extremes_are_successful() {
    let h = Harness::new();
    for bounds in [vec![], vec![0], vec![u32::MAX], (0..128).collect()] {
        let mut request = h.request("2026-03-31"); request.buckets = AgingBuckets::new(bounds).unwrap();
        let certified = h.certify(&request);
        assert!(certified.report.items.is_empty());
        assert!(certified.report.cells.is_empty());
        assert!(certified.report.totals.is_empty());
        assert_eq!(h.replay(&certified.certificate), certified.report);
        assert_eq!(certified.certificate.request().unwrap().known_at, Some(h.head()));
    }
}

#[test]
fn authorization_and_book_binding_precede_historical_observation() {
    let mut h = Harness::new();
    let entry = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let request = h.request("2026-03-31");
    let certificate = h.certify(&request).certificate;
    let other = Harness::in_book(Id128([0x73; 16]));
    assert_eq!(other.book.replay_effective_date_aging(&other.cx(), PRINCIPAL, &cap(&["read"]), &certificate)
        .unwrap().unwrap_err().exit, exit::VERIFICATION);
    let cx = h.cx();
    let row = cx.query().with_restriction(|| h.book.db.vertex(entry.vid)).unwrap().unwrap();
    let original = fa_journal::rows::prop(&row, property::FA_PAYLOAD).cloned().unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(entry.vid, property::FA_PAYLOAD, Some(original),
        CanonicalScalar::bytes(Vec::new()).unwrap(), WriteMismatchPolicy::AbortWrite);
    h.runtime.block_on(h.book.db.write(&cx.commit(), damage)).unwrap();
    let head = h.head();
    for ops in [&["post"][..], &["read"][..], &["produce"][..]] {
        let denial = h.book.certify_effective_date_aging(&cx, PRINCIPAL, &cap(ops), &request).unwrap().unwrap_err();
        assert_eq!(denial.code, fa_journal::refusal::code::CAPABILITY);
    }
    assert_eq!(h.book.replay_effective_date_aging(&cx, PRINCIPAL, &cap(&["produce"]), &certificate)
        .unwrap().unwrap_err().code, fa_journal::refusal::code::CAPABILITY);
    assert!(h.book.certify_effective_date_aging(&cx, VId(8), &cap(&["read", "produce"]), &request).unwrap().is_err());
    assert!(h.book.certify_effective_date_aging_from_source(&cx, PRINCIPAL, &cap(&["read"]),
        certificate.source(), day("2026-03-31"), &AgingBuckets::thirty_day()).unwrap().is_err());
    assert!(!matches!(h.book.replay_effective_date_aging(&cx, PRINCIPAL, &cap(&["read"]), &certificate), Ok(Ok(_))));
    assert_eq!(h.head(), head);
}

#[test]
fn backdated_application_cutoff_is_refused_instead_of_losing_balances() {
    let mut h = Harness::new();
    let invoice = h.post("future-invoice", "2026-03-20", h.usd, ("ar", "sales"), 100, None);
    h.post("backdated-payment", "2026-03-10", h.usd, ("cash", "ar"), 40, Some(invoice));
    let head = h.head();
    let bad = h.book.certify_effective_date_aging(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]),
        &h.request("2026-03-15")).unwrap().unwrap_err();
    assert!(bad.message.contains("splits a settlement"));
    assert_eq!(h.certify(&h.request("2026-03-31")).report.items[0].item.open, 60);
    assert_eq!(h.head(), head);
}
