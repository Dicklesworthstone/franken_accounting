//! A held receipt settles only its posted sub-vector, in the resolving commit.
//! Fixtures are synthetic; every assertion runs against the real kernel/store.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::post::read_entry;
use fa_journal::rows::{applied, edge_id, leg_vid, resolution_vid};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, Document, PostPreparation, PostRequest, Posted,
    PreparedPost, Refusal, UnitPolicy, add_document, create_book, create_periods,
    install_chart, post, prepare_post, transition_period,
};
use fa_model::symbols::relation;
use fa_model::{
    Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, EvidenceRef,
    Id128, LegPayload, Oid, Pending, SealKey, Settlement, Supersession, SupersessionKind,
    SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

const ACTOR: VId = VId(41);

struct Fixture {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    unit: UnitId,
    cash: VId,
    receivable: VId,
    revenue: VId,
    evidence: EvidenceRef,
}

impl Fixture {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([61; 32], DatabaseSecurityNamespaceId([62; 32]), [63; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let unit = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("resolution-test", 1, 0).unwrap();
        let book_id = Id128([64; 16]);
        let symbols = SymbolTable::compiled();
        let spec = BookSpec {
            book_id,
            name: "Synthetic settlement fixture".into(),
            base_unit: unit,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime.block_on(create_book(&mut db, &cx, &spec, &units, &symbols)).unwrap();
        let book = BookContext {
            book_id,
            calendar,
            units,
            seal_key: SealKey([65; 32]),
            symbols,
        };
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        let chart: Vec<_> = [("1000", 1, 0), ("1200", 1, 0), ("4000", 4, 1)]
            .into_iter()
            .map(|(code, account_type, normal_balance)| AccountSpec {
                code: code.into(), name: code.into(), account_type, normal_balance,
                is_leaf: true, unit_policy: UnitPolicy::Single(unit),
                parent_code: None, limit: None,
            })
            .collect();
        let seal = |text: &str| {
            Erasable::seal(&text.to_string(), None, &book.seal_key, [66; 32], [67; 24])
        };
        runtime.block_on(install_chart(
            &mut db, &cx, &book, &chart, ACTOR, day, b"fixture-chart", seal("chart"),
        )).unwrap().unwrap();
        runtime.block_on(create_periods(&mut db, &cx, &book, 2026)).unwrap();
        let closer = Capability::embedded(ACTOR, &["close"]).unwrap();
        for (period, key) in [("FY2026-P03", b"march" as &[u8]), ("FY2026-P04", b"april")] {
            runtime.block_on(transition_period(
                &mut db, &cx, &book, period, PeriodTransition::Open, ACTOR, 1,
                day, key, seal("open"), &closer, &[],
            )).unwrap().unwrap();
        }
        let document = Document {
            book_id, kind: 1, mime: "text/plain".into(), grade: 3,
            retrieved_by: ACTOR, bytes: b"Synthetic invoice for settlement tests".to_vec(),
        };
        let added = runtime.block_on(add_document(&mut db, &cx, &book, &document))
            .unwrap().unwrap();
        Self {
            runtime, root, db, book, unit,
            cash: account_vid(book_id, "1000"),
            receivable: account_vid(book_id, "1200"),
            revenue: account_vid(book_id, "4000"),
            evidence: EvidenceRef { document_oid: added.oid, doc_commit: added.doc_commit, role: 1 },
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn proposal(&self, class: EntryClass, key: &[u8], legs: Vec<LegPayload>) -> EntryPayload {
        let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        EntryPayload {
            schema_minor: 0, book_id: self.book.book_id, branch_id: Id128::TRUNK, class,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(), document_date: None,
            description: Erasable::seal(&"Synthetic receipt".to_string(), None,
                &self.book.seal_key, [68; 32], [69; 24]),
            effective_period: None, legs, control: None, unit_totals, base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent { intent_oid: Oid([70; 32]), intent_kind: 1 },
            principal_ref: ACTOR, session_ref: None, evidence: vec![self.evidence],
            supersession: Vec::new(), pending: None, external_ids: Vec::new(),
            tags: Vec::new(), extensions: Vec::new(),
        }
    }

    fn request(&self, proposal: EntryPayload) -> PostRequest {
        PostRequest { proposal, approvals: Vec::new(), plan_certificate: None,
            capability: Capability::embedded(ACTOR, &["post"]).unwrap() }
    }

    fn post(&mut self, proposal: EntryPayload) -> Result<Posted, Refusal> {
        let cx = self.cx();
        let request = self.request(proposal);
        self.runtime.block_on(post(&mut self.db, &cx, &self.book, request)).unwrap()
    }

    fn prepare(&mut self, proposal: EntryPayload) -> Box<PreparedPost> {
        let cx = self.cx();
        let request = self.request(proposal);
        match prepare_post(&mut self.db, &cx, &self.book, request).unwrap().unwrap() {
            PostPreparation::Ready(prepared) => prepared,
            other => panic!("expected new preparation, got {other:?}"),
        }
    }

    fn commit(&mut self, prepared: Box<PreparedPost>) -> Result<Posted, Refusal> {
        let cx = self.cx();
        self.runtime.block_on(prepared.commit(&mut self.db, &cx)).unwrap()
    }

    fn invoice(&mut self, amount: i128, key: &[u8]) -> EntryRef {
        let proposal = self.proposal(EntryClass::ORIGINAL, key, vec![
            LegPayload::simple(Side::Debit, self.receivable, Amount::new(self.unit, amount)),
            LegPayload::simple(Side::Credit, self.revenue, Amount::new(self.unit, amount)),
        ]);
        self.post(proposal).unwrap().entry_ref()
    }

    fn hold(&mut self, amount: i128, key: &[u8]) -> EntryRef {
        let mut proposal = self.receipt(amount, key);
        proposal.class = EntryClass::PENDING;
        proposal.pending = Some(Pending { timeout_ns: None, resolution_of: None, disposition: None });
        self.post(proposal).unwrap().entry_ref()
    }

    fn receipt(&self, amount: i128, key: &[u8]) -> EntryPayload {
        self.proposal(EntryClass::ORIGINAL, key, vec![
            LegPayload::simple(Side::Debit, self.cash, Amount::new(self.unit, amount)),
            LegPayload::simple(Side::Credit, self.receivable, Amount::new(self.unit, amount)),
        ])
    }

    fn resolution(&self, hold: EntryRef, invoice: EntryRef, amount: i128, key: &[u8]) -> EntryPayload {
        let mut proposal = self.receipt(amount, key);
        proposal.class = EntryClass::RESOLUTION;
        proposal.pending = Some(Pending {
            timeout_ns: None, resolution_of: Some(hold),
            disposition: Some(Disposition::Posts { source_ordinals: vec![0, 1] }),
        });
        proposal.legs[1].settles.push(Settlement {
            target: invoice, ordinal: 0, amount: Amount::new(self.unit, amount),
        });
        proposal
    }

    fn reversal(&self, target: EntryRef, key: &[u8]) -> EntryPayload {
        let (entry, _) = read_entry(&self.db, target.vid).unwrap().unwrap();
        let legs = entry.proposal.legs.iter().map(|leg| {
            let mut swapped = leg.clone();
            swapped.side = if leg.side == Side::Debit { Side::Credit } else { Side::Debit };
            swapped.settles.clear();
            swapped
        }).collect();
        let mut proposal = self.proposal(EntryClass::REVERSAL, key, legs);
        proposal.supersession = vec![Supersession {
            target, kind: SupersessionKind::Reverses, reason_code: 1,
        }];
        proposal
    }

    fn applied(&self, target: EntryRef) -> i128 {
        let row = self.db.vertex(leg_vid(target.vid, 0)).unwrap().unwrap();
        applied(&row).unwrap().unwrap()
    }
}

#[test]
fn partial_resolution_settles_at_publication_and_retry_does_not_apply_twice() {
    let mut f = Fixture::new();
    let invoice = f.invoice(100, b"invoice");
    let hold = f.hold(100, b"hold");
    let hold_before = read_entry(&f.db, hold.vid).unwrap().unwrap().0.encode().unwrap();
    let proposal = f.resolution(hold, invoice, 60, b"resolve");
    let head = f.db.frontier().unwrap();
    let prepared = f.prepare(proposal.clone());
    assert_eq!(f.applied(invoice), 0, "planning cannot settle the invoice");
    assert_eq!(f.db.frontier().unwrap(), head);
    let posted = f.commit(prepared).unwrap();
    assert_eq!(posted.entry_ref().vid, resolution_vid(hold.vid));
    assert_eq!(posted.recorded_at().0, head.0 + 1);
    assert_eq!(f.applied(invoice), 60);
    let edge = edge_id(relation::SETTLES, leg_vid(posted.entry_ref().vid, 1), leg_vid(invoice.vid, 0));
    assert!(f.db.edge(edge).unwrap().is_some());
    let resolved = read_entry(&f.db, posted.entry_ref().vid).unwrap().unwrap().0;
    assert_eq!(resolved.proposal.legs[1].settles, proposal.legs[1].settles);
    assert_eq!(resolved.proposal.legs[0].amount.mantissa, 60);
    let head = f.db.frontier().unwrap();
    let retry = f.post(proposal).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(f.applied(invoice), 60);
    assert_eq!(f.db.frontier().unwrap(), head);
    assert_eq!(read_entry(&f.db, hold.vid).unwrap().unwrap().0.encode().unwrap(), hold_before);
}

#[test]
fn refused_applications_do_not_resolve_the_hold_or_modify_any_invoice() {
    let mut f = Fixture::new();
    let invoice = f.invoice(100, b"invoice");
    let hold = f.hold(200, b"hold");
    let head = f.db.frontier().unwrap();
    let over = f.resolution(hold, invoice, 101, b"over");
    assert_eq!(f.post(over).unwrap_err().code, "FA-REF-072");
    let mut wrong_side = f.resolution(hold, invoice, 50, b"wrong-side");
    wrong_side.legs[1].settles[0].ordinal = 1;
    assert_eq!(f.post(wrong_side).unwrap_err().code, "FA-REF-071");
    assert_eq!(f.applied(invoice), 0);
    assert_eq!(f.db.frontier().unwrap(), head);
    assert!(f.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
    assert!(f.post(f.resolution(hold, invoice, 100, b"good")).is_ok());
}

#[test]
fn settlement_cannot_exceed_the_resolved_leg_or_its_original_reservation() {
    let mut f = Fixture::new();
    let invoice = f.invoice(200, b"invoice");
    let hold = f.hold(100, b"hold");
    let head = f.db.frontier().unwrap();
    let mut too_much_application = f.resolution(hold, invoice, 60, b"too-much");
    too_much_application.legs[1].settles[0].amount.mantissa = 61;
    assert_eq!(f.post(too_much_application).unwrap_err().code, "FA-REF-071");
    let too_much_posted = f.resolution(hold, invoice, 101, b"too-much-posted");
    assert_eq!(f.post(too_much_posted).unwrap_err().code, "FA-REF-061");
    assert_eq!(f.applied(invoice), 0);
    assert_eq!(f.db.frontier().unwrap(), head);
    assert!(f.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
}

#[test]
fn competing_resolutions_cannot_overapply_a_shared_invoice() {
    let mut f = Fixture::new();
    let invoice = f.invoice(100, b"invoice");
    let first_hold = f.hold(70, b"first-hold");
    let second_hold = f.hold(70, b"second-hold");
    let first = f.prepare(f.resolution(first_hold, invoice, 70, b"first"));
    let second_proposal = f.resolution(second_hold, invoice, 70, b"second");
    let second = f.prepare(second_proposal.clone());
    f.commit(first).unwrap();
    let head = f.db.frontier().unwrap();
    assert_eq!(f.commit(second).unwrap_err().exit, 6);
    assert_eq!(f.post(second_proposal).unwrap_err().code, "FA-REF-072");
    assert_eq!(f.applied(invoice), 70);
    assert_eq!(f.db.frontier().unwrap(), head);
    assert!(f.db.vertex(resolution_vid(second_hold.vid)).unwrap().is_none());
    f.post(f.resolution(second_hold, invoice, 30, b"replanned")).unwrap();
    assert_eq!(f.applied(invoice), 100);
}

#[test]
fn reversing_a_posted_resolution_undoes_its_applications_without_reviving_the_hold() {
    let mut f = Fixture::new();
    let invoice = f.invoice(100, b"invoice");
    let hold = f.hold(100, b"hold");
    let proposal = f.resolution(hold, invoice, 60, b"resolve");
    let resolution = f.post(proposal.clone()).unwrap();
    let reversal = f.post(f.reversal(resolution.entry_ref(), b"reverse")).unwrap();
    assert_eq!(f.applied(invoice), 0);
    let edge = edge_id(relation::UNSETTLES,
        leg_vid(reversal.entry_ref().vid, 1), leg_vid(invoice.vid, 0));
    assert!(f.db.edge(edge).unwrap().is_some());
    let head = f.db.frontier().unwrap();
    assert!(matches!(f.post(proposal).unwrap(), Posted::AlreadyRecorded { .. }));
    assert_eq!(f.post(f.resolution(hold, invoice, 40, b"second-resolution")).unwrap_err().code,
        "FA-REF-062", "the reservation is resolved exactly once, even after correction");
    assert_eq!(f.applied(invoice), 0);
    assert_eq!(f.db.frontier().unwrap(), head);
}

#[test]
fn pending_legs_still_cannot_apply_and_cross_period_resolutions_apply_only_when_posted() {
    let mut f = Fixture::new();
    let invoice = f.invoice(100, b"invoice");
    let mut pending = f.receipt(80, b"invalid-hold");
    pending.class = EntryClass::PENDING;
    pending.pending = Some(Pending { timeout_ns: None, resolution_of: None, disposition: None });
    pending.legs[1].settles = vec![Settlement {
        target: invoice, ordinal: 0, amount: Amount::new(f.unit, 80),
    }];
    let head = f.db.frontier().unwrap();
    assert_eq!(f.post(pending).unwrap_err().code, "FA-REF-102");
    assert_eq!(f.db.frontier().unwrap(), head);
    let hold = f.hold(80, b"valid-hold");
    let mut resolution = f.resolution(hold, invoice, 80, b"april-resolution");
    resolution.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
    let posted = f.post(resolution).unwrap();
    assert_eq!(posted.period(), Some("FY2026-P04"));
    assert_eq!(f.applied(invoice), 80);
    let restored = read_entry(&f.db, hold.vid).unwrap().unwrap().0;
    assert!(restored.proposal.legs.iter().all(|leg| leg.settles.is_empty()));
}

#[test]
fn aborting_a_resolution_discards_both_application_and_resolution_identity() {
    let mut f = Fixture::new();
    let invoice = f.invoice(100, b"invoice");
    let hold = f.hold(100, b"hold");
    let head = f.db.frontier().unwrap();
    let proposal = f.resolution(hold, invoice, 60, b"resolve");
    f.prepare(proposal.clone()).abort();
    assert_eq!(f.applied(invoice), 0);
    assert_eq!(f.db.frontier().unwrap(), head);
    assert!(f.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
    f.post(proposal).unwrap();
    assert_eq!(f.applied(invoice), 60);
}
