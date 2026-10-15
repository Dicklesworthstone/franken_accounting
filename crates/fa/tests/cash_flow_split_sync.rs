//! The synchronous production handle shares the native split and replay laws.
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{BookKeys, Capability, Entropy, RollForwardRequest};
use fa::cash_flow_split::{CashFlowLegSplit, CashFlowPortion, CashFlowSplitDefinition};
use fa::general_ledger::CashFlowActivity;
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{VId, context::PurposeContexts};

const PRINCIPAL: VId = VId(1);
fn day(d: u8) -> DateDay { DateDay::from_ymd(2026, 1, d).unwrap() }
fn cap(ops: &[&str]) -> Capability { Capability::embedded(PRINCIPAL, ops).unwrap() }
fn portions(parts: &[(CashFlowActivity, i128)]) -> Vec<CashFlowPortion> {
    parts.iter().map(|(activity, amount)| CashFlowPortion { activity: *activity, amount: *amount }).collect()
}

use fa::Book;
use fa::cash_flow_split::CashFlowSplitCertificate;

fn sync_fixture() -> (Book, Runtime, Cx, RollForwardRequest, CashFlowSplitDefinition) {
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let units = UnitRegistry::embedded().unwrap();
    let usd = units.lookup("USD").unwrap();
    let jpy = units.lookup("JPY").unwrap();
    let book_id = Id128([131; 16]);
    let mut book = Book::create_memory(BookKeys::for_development(131), BookSpec {
        book_id, name: "Synchronous cash reports".into(), base_unit: usd,
        calendar: FiscalCalendar::monthly("sync-cash", 1, 1).unwrap(),
        time_zone_policy: None, entities: Vec::new(), opening_date: None,
    }, Entropy::deterministic(131)).unwrap();
    let id = |code| account_vid(book_id, code);
    let accounts: Vec<_> = [("1000", 1), ("2300", 2), ("3000", 3), ("6100", 5)]
        .into_iter().map(|(code, account_type)| AccountSpec {
            code: code.into(), name: code.into(), account_type,
            normal_balance: u8::from([2, 3].contains(&account_type)), is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency, parent_code: None, limit: None,
        }).collect();
    book.install_chart(&accounts, PRINCIPAL, day(1), b"sync-chart").unwrap().unwrap();
    book.create_periods(2026).unwrap();
    book.transition_period("FY2026-P01", PeriodTransition::Open, PRINCIPAL, 1,
        day(1), b"sync-open", &cap(&["close"])).unwrap().unwrap();
    let doc = Document { book_id, kind: 1, mime: "text/plain".into(), grade: 3,
        retrieved_by: PRINCIPAL, bytes: b"Synchronous cash evidence".to_vec() };
    book.add_document(&doc).unwrap().unwrap();
    for (date, key, rows) in [
        (1, b"opening".as_slice(), vec![("1000", Side::Debit, 500), ("3000", Side::Credit, 500)]),
        (10, b"payment".as_slice(), vec![("1000", Side::Credit, 100), ("2300", Side::Debit, 93), ("6100", Side::Debit, 7)]),
    ] {
        let legs = rows.into_iter().map(|(code, side, amount)|
            LegPayload::simple(side, id(code), Amount::new(usd, amount))).collect();
        let proposal = EntryPayload {
            schema_minor: 0, book_id, branch_id: Id128::TRUNK, class: EntryClass::ORIGINAL,
            effective_date: day(date), document_date: None,
            description: book.seal_text("Synchronous test posting").unwrap(), effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(), legs, control: None,
            base_totals: None, idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent { intent_oid: Oid([57; 32]), intent_kind: 1 },
            principal_ref: PRINCIPAL, session_ref: None, evidence: vec![doc.evidence_ref(1)],
            supersession: Vec::new(), pending: None, external_ids: Vec::new(),
            tags: Vec::new(), extensions: Vec::new(),
        };
        book.post(PostRequest { proposal, approvals: Vec::new(), plan_certificate: None,
            capability: cap(&["post"]) }).unwrap().unwrap();
    }
    let request = RollForwardRequest { accounts: vec![id("1000")], units: vec![usd.0, jpy.0],
        label: "Synchronous January".into(), effective_from: day(10), effective_through: day(20),
        known_at: Some(book.head().unwrap()) };
    let ledger = book.general_ledger(PRINCIPAL, &cap(&["read"]), &request).unwrap().unwrap();
    let line = &ledger.lines()[0];
    let definition = CashFlowSplitDefinition { name: "Reviewed loan split".into(), cash_accounts: vec![id("1000").0],
        splits: vec![CashFlowLegSplit { entry_digest: line.entry_digest, leg_index: line.leg_index,
            reason: "Loan principal and interest".into(),
            portions: portions(&[(CashFlowActivity::Operating, 7), (CashFlowActivity::Financing, 93)]),
        }] };
    (book, runtime, root, request, definition)
}

#[test]
fn synchronous_read_certification_and_portable_replay_share_exact_output_without_writes() {
    let (book, _runtime, root, request, definition) = sync_fixture();
    let query = PurposeContexts::narrow_runtime_root(&root).query();
    let head = book.head().unwrap();
    let report = book.split_cash_flow(&query, PRINCIPAL, &cap(&["read"]), &request, &definition).unwrap().unwrap();
    let usd = book.context().units.lookup("USD").unwrap();
    let row = report.units().iter().find(|row| row.unit_id == usd.0).unwrap();
    assert_eq!((row.opening, row.operating.outflows, row.financing.outflows, row.closing), (500, 7, 93, 400));
    let certified = book.certify_split_cash_flow(&query, PRINCIPAL, &cap(&["read", "produce"]), &request, &definition).unwrap().unwrap();
    assert_eq!(certified.report(), &report);
    let certificate = CashFlowSplitCertificate::decode(&certified.certificate().canonical_bytes().unwrap()).unwrap();
    assert_eq!(book.replay_split_cash_flow(&query, PRINCIPAL, &cap(&["read"]), &certificate, &request, &definition)
        .unwrap().unwrap().canonical_bytes().unwrap(), report.canonical_bytes().unwrap());
    assert_eq!(book.head().unwrap(), head);
}

#[test]
fn synchronous_adapter_cannot_grant_read_produce_or_change_the_independent_request() {
    let (book, _runtime, root, request, definition) = sync_fixture();
    let query = PurposeContexts::narrow_runtime_root(&root).query();
    assert!(book.split_cash_flow(&query, PRINCIPAL, &cap(&["post"]), &request, &definition).unwrap().is_err());
    assert!(book.certify_split_cash_flow(&query, PRINCIPAL, &cap(&["read"]), &request, &definition).unwrap().is_err());
    assert!(book.certify_split_cash_flow(&query, VId(99), &cap(&["read", "produce"]), &request, &definition).unwrap().is_err());
    let certified = book.certify_split_cash_flow(&query, PRINCIPAL, &cap(&["read", "produce"]), &request, &definition).unwrap().unwrap();
    let mut changed = request.clone(); changed.known_at = None;
    assert!(book.replay_split_cash_flow(&query, PRINCIPAL, &cap(&["read"]), certified.certificate(), &changed, &definition).unwrap().is_err());
    let mut different = definition.clone(); different.splits[0].reason.push('!');
    assert!(book.replay_split_cash_flow(&query, PRINCIPAL, &cap(&["read"]), certified.certificate(), &request, &different).unwrap().is_err());
}

#[test]
fn synchronous_replay_rejects_changed_financial_bytes_even_with_a_recomputed_digest() {
    let (book, _runtime, root, request, definition) = sync_fixture();
    let query = PurposeContexts::narrow_runtime_root(&root).query();
    let certified = book.certify_split_cash_flow(&query, PRINCIPAL, &cap(&["read", "produce"]), &request, &definition).unwrap().unwrap();
    let mut bytes = certified.certificate().canonical_bytes().unwrap();
    let body = bytes.len() - 32;
    bytes[body - 1] ^= 1;
    let digest = fa_model::domain_digest(b"fa:cash-flow-split-certificate-digest:v1", &[&bytes[..body]]);
    bytes[body..].copy_from_slice(&digest);
    let certificate = CashFlowSplitCertificate::decode(&bytes).unwrap();
    let refusal = book.replay_split_cash_flow(&query, PRINCIPAL, &cap(&["read"]), &certificate, &request, &definition).unwrap().unwrap_err();
    assert_eq!(refusal.code, "FA-REF-150");
    assert_eq!(refusal.exit, 8);
}
