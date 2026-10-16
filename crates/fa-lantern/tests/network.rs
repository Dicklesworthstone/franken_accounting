//! Network tracing through real admitted journal entries, not synthetic flows.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::*;
use fa_lantern::{Cite, LanternError, Params, ProcedureRun, catalog};
use fa_model::{AccountType, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LEGAL_ENTITY_DIMENSION, LegPayload, Oid, SealKey, SymbolTable, account_vid, entity_value_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(7);
const IDS: [&str; 4] = ["trace.network_fifo", "trace.network_lifo", "trace.network_libr", "trace.network_pro_rata"];

fn day(n: u8) -> DateDay { DateDay::from_ymd(2026, 1, n).unwrap() }

struct Fixture {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    jpy: UnitId,
    evidence: Vec<EvidenceRef>,
    nonce: u8,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new([seed; 32], DatabaseSecurityNamespaceId([seed; 32]), [seed; 32]);
        let mut db = runtime.block_on(async { Database::open_memory(&ctx.commit(), keys).await }).unwrap();
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let jpy = units.lookup("JPY").unwrap();
        let book_id = Id128([seed; 16]);
        let calendar = FiscalCalendar::monthly("network", 1, 1).unwrap();
        let spec = BookSpec {
            book_id, name: "Network tracing fixture".into(), base_unit: usd,
            calendar: calendar.clone(), time_zone_policy: None, opening_date: None,
            entities: vec![genesis::LegalEntitySpec { code: "A".into(), name: "Entity A".into() }, genesis::LegalEntitySpec { code: "B".into(), name: "Entity B".into() }],
        };
        let symbols = SymbolTable::compiled();
        runtime.block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await }).unwrap();
        let book = BookContext { book_id, calendar, units, seal_key: SealKey([seed; 32]), symbols };
        let chart: Vec<AccountSpec> = [
            ("1000", AccountType::ASSET), ("1010", AccountType::ASSET), ("1020", AccountType::ASSET),
            ("3000", AccountType::EQUITY), ("4000", AccountType::REVENUE), ("6000", AccountType::EXPENSE),
        ].into_iter().map(|(code, kind)| AccountSpec { code: code.into(), name: code.into(), account_type: kind.0, normal_balance: u8::from(matches!(kind, AccountType::EQUITY | AccountType::REVENUE)), is_leaf: true, unit_policy: UnitPolicy::AnyCurrency, parent_code: None, limit: None }).collect();
        let seal = |text: &str| Erasable::seal(&text.to_string(), None, &book.seal_key, [1; 32], [1; 24]);
        runtime.block_on(async { install_chart(&mut db, &ctx, &book, &chart, PRINCIPAL, day(1), b"chart", seal("chart")).await }).unwrap().unwrap();
        runtime.block_on(async { create_periods(&mut db, &ctx, &book, 2026).await }).unwrap();
        runtime.block_on(async { transition_period(&mut db, &ctx, &book, "FY2026-P01", PeriodTransition::Open, PRINCIPAL, 1, day(1), b"open", seal("open"), &Capability::embedded(PRINCIPAL, &["close"]).unwrap(), &[]).await }).unwrap().unwrap();
        let source = Document { book_id, kind: 1, mime: "text/plain".into(), grade: 3, retrieved_by: PRINCIPAL, bytes: b"Admitted transfer evidence, network integration fixture".to_vec() };
        runtime.block_on(async { evidence::add_document(&mut db, &ctx, &book, &source).await }).unwrap().unwrap();
        Self { runtime, root, db, book, usd, jpy, evidence: vec![source.evidence_ref(1)], nonce: 1 }
    }

    fn account(&self, code: &str) -> VId { account_vid(self.book.book_id, code) }

    fn leg(&self, entity: &str, unit: UnitId, account: &str, side: Side, amount: i128) -> LegPayload {
        let mut leg = LegPayload::simple(side, self.account(account), Amount::new(unit, amount));
        leg.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, entity_value_vid(self.book.book_id, entity))];
        leg
    }

    fn transfer(&mut self, entity: &str, unit: UnitId, date: u8, from: &str, to: &str, amount: i128) -> VId {
        self.post(date, vec![self.leg(entity, unit, to, Side::Debit, amount), self.leg(entity, unit, from, Side::Credit, amount)])
    }

    fn post(&mut self, date: u8, legs: Vec<LegPayload>) -> VId {
        self.nonce += 1;
        let proposal = EntryPayload {
            schema_minor: 0, book_id: self.book.book_id, branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL, effective_date: day(date), document_date: None,
            description: Erasable::seal(&"Network fixture transfer".to_string(), None, &self.book.seal_key, [self.nonce; 32], [self.nonce; 24]),
            effective_period: None, unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(), legs,
            control: None, base_totals: None, idempotency_key: vec![self.nonce],
            origin: EntryOrigin::Intent { intent_oid: Oid([1; 32]), intent_kind: 1 },
            principal_ref: PRINCIPAL, session_ref: None, evidence: self.evidence.clone(), supersession: Vec::new(), pending: None, external_ids: Vec::new(), extensions: Vec::new(), tags: Vec::new(),
        };
        let ctx = PurposeContexts::narrow_runtime_root(&self.root);
        let request = PostRequest { proposal, approvals: Vec::new(), plan_certificate: None, capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap() };
        let posted = self.runtime.block_on(async { post(&mut self.db, &ctx, &self.book, request).await }).unwrap().unwrap();
        match posted { Posted::Committed { entry_ref, .. } => entry_ref.vid, _ => panic!("fresh posting did not commit") }
    }

    fn run(&self, id: &str, source: VId, cutoff: u8, known_at: Option<CommitSeq>, bounds: &[(&str, i128)]) -> Result<ProcedureRun, LanternError> {
        let mut params = Params::defaults(id)?;
        for (name, value) in bounds { params = params.set(name, *value)?; }
        let p = catalog::build(id, params, catalog::Inputs { account: Some(self.account("1000")), source: Some(source) })?;
        fa_lantern::run(&self.db, &self.book, known_at, Some(day(cutoff)), p.as_ref())
    }

    fn amount(&self, run: &ProcedureRun, account: &str, name: &str) -> i128 {
        run.findings.iter().filter(|f| f.cites.first() == Some(&Cite::Account(self.account(account))) && f.statistic.name == name).map(|f| f.statistic.value).sum()
    }
}

#[test]
fn actual_postings_follow_full_paths_and_historical_cutoffs() {
    let mut f = Fixture::new(0x71);
    let source = f.transfer("A", f.usd, 1, "3000", "1000", 10000);
    let prefix = f.db.frontier().expect("read journal frontier");
    let hop2 = f.transfer("A", f.usd, 2, "1000", "1010", 8000);
    let hop3 = f.transfer("A", f.usd, 3, "1010", "1020", 6000);
    let spend = f.transfer("A", f.usd, 4, "1020", "6000", 1000);
    for id in IDS {
        let r = f.run(id, source, 31, None, &[]).unwrap();
        assert_eq!(f.amount(&r, "1000", "held_mantissa"), 2000);
        assert_eq!(f.amount(&r, "1010", "held_mantissa"), 2000);
        assert_eq!(f.amount(&r, "1020", "held_mantissa"), 5000);
        assert_eq!(f.amount(&r, "6000", "spent_mantissa"), 1000);
        assert_eq!(r.findings.iter().map(|finding| finding.statistic.value).sum::<i128>(), 10000);
        let spent = r.findings.iter().find(|finding| finding.statistic.name == "spent_mantissa").unwrap();
        assert_eq!(spent.cites[2..].chunks_exact(3).map(|hop| hop[0].clone()).collect::<Vec<_>>(), [Cite::Entry(source), Cite::Entry(hop2), Cite::Entry(hop3), Cite::Entry(spend)]);
        for finding in &r.findings {
            for cite in &finding.cites { assert!(cite.resolves(&f.db, &f.book, r.coordinate.known_at).unwrap()); }
            assert!(finding.narrative.len() <= fa_lantern::MAX_NARRATIVE_BYTES);
        }
        let old = f.run(id, source, 31, Some(prefix), &[]).unwrap();
        assert_eq!(f.amount(&old, "1000", "held_mantissa"), 10000);
        assert_eq!(old.findings.len(), 1);
        let earlier = f.run(id, source, 2, None, &[]).unwrap();
        assert_eq!(f.amount(&earlier, "1010", "held_mantissa"), 8000);
        assert_eq!(f.amount(&earlier, "1020", "held_mantissa"), 0);
        let again = f.run(id, source, 31, None, &[]).unwrap();
        assert_eq!(r.findings_digest, again.findings_digest);
        let p = catalog::build(id, Params::defaults(id).unwrap(), catalog::Inputs { account: Some(f.account("1000")), source: Some(source) }).unwrap();
        let snapshot = fa_lantern::Snapshot::read(&f.db, &f.book, None, Some(day(31))).unwrap();
        assert_eq!(r.findings_digest, fa_lantern::run_over(&snapshot.with_entries_reversed(), &f.book, p.as_ref()).unwrap().findings_digest);
    }
}

#[test]
fn another_entity_or_currency_cannot_supply_clean_funding() {
    let mut f = Fixture::new(0x72);
    let foreign_entity = f.transfer("B", f.usd, 1, "3000", "1000", 900000);
    let foreign_unit = f.transfer("A", f.jpy, 1, "3000", "1000", 900000);
    let source = f.transfer("A", f.usd, 2, "3000", "1000", 10000);
    f.transfer("A", f.usd, 3, "1000", "1010", 10000);
    for id in IDS {
        let r = f.run(id, source, 31, None, &[]).unwrap();
        assert_eq!(f.amount(&r, "1000", "held_mantissa"), 0);
        assert_eq!(f.amount(&r, "1010", "held_mantissa"), 10000);
        assert!(r.findings.iter().flat_map(|f| &f.cites).all(|c| *c != Cite::Entry(foreign_entity) && *c != Cite::Entry(foreign_unit)));
    }
    let ambiguous = f.post(4, vec![f.leg("A", f.usd, "1000", Side::Debit, 100), f.leg("A", f.usd, "3000", Side::Credit, 100), f.leg("B", f.usd, "1000", Side::Debit, 100), f.leg("B", f.usd, "3000", Side::Credit, 100)]);
    for id in IDS { assert!(matches!(f.run(id, ambiguous, 31, None, &[]), Err(LanternError::Parameter { name, .. }) if name == "source")); }
}

#[test]
fn mixed_cash_entries_are_netted_and_bounds_never_publish_partial_schedules() {
    let mut f = Fixture::new(0x73);
    let source = f.post(1, vec![f.leg("A", f.usd, "1000", Side::Debit, 10000), f.leg("A", f.usd, "1000", Side::Credit, 8000), f.leg("A", f.usd, "4000", Side::Credit, 2000)]);
    f.transfer("A", f.usd, 2, "1000", "1010", 1000);
    let head = f.db.frontier().expect("read journal frontier");
    for id in IDS {
        let r = f.run(id, source, 31, None, &[]).unwrap();
        assert_eq!(f.amount(&r, "1000", "held_mantissa"), 1000);
        assert_eq!(f.amount(&r, "1010", "held_mantissa"), 1000);
        for name in ["max_hops", "max_steps", "max_input_legs", "max_transfers", "max_fragments"] {
            assert!(matches!(f.run(id, source, 31, None, &[(name, 1)]), Err(LanternError::Parameter { name: failed, .. }) if failed == name), "{id}: {name}");
        }
        assert_eq!(f.db.frontier().expect("read journal frontier"), head);
    }
}

#[test]
fn commingled_journal_network_distinguishes_all_four_laws_exactly() {
    let mut f = Fixture::new(0x74);
    f.transfer("A", f.usd, 1, "3000", "1010", 100);
    f.transfer("A", f.usd, 1, "3000", "1000", 100);
    let source = f.transfer("A", f.usd, 2, "3000", "1000", 100);
    f.transfer("A", f.usd, 3, "1000", "1010", 150);
    f.transfer("A", f.usd, 4, "1010", "6000", 225);
    for (id, at_source, at_destination, spent) in [
        ("trace.network_fifo", 50, 25, 25),
        ("trace.network_lifo", 0, 0, 100),
        ("trace.network_libr", 50, 25, 25),
        ("trace.network_pro_rata", 25, 7, 68),
    ] {
        let r = f.run(id, source, 31, None, &[]).unwrap();
        assert_eq!(f.amount(&r, "1000", "held_mantissa"), at_source, "{id}");
        assert_eq!(f.amount(&r, "1010", "held_mantissa"), at_destination, "{id}");
        assert_eq!(f.amount(&r, "6000", "spent_mantissa"), spent, "{id}");
        assert_eq!(r.findings.iter().map(|finding| finding.statistic.value).sum::<i128>(), 100, "{id}");
    }
}
