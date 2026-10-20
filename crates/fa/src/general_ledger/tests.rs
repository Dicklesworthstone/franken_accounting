use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, Oid, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;

use crate::{BookKeys, Entropy};

const PRINCIPAL: VId = VId(1);
fn day(d: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, d).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    jpy: UnitId,
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let jpy = units.lookup("JPY").unwrap();
        let book_id = Id128([119; 16]);
        let spec = BookSpec {
            book_id,
            name: "General ledger integration".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("general-ledger", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                Path::new("general-ledger-book"),
                BookKeys::for_development(119),
                spec,
                Entropy::deterministic(119),
            ))
            .unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET),
            ("3000", AccountType::EQUITY),
            ("6100", AccountType::EXPENSE),
        ]
        .into_iter()
        .map(|(code, kind)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(kind == AccountType::EQUITY),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
        runtime
            .block_on(book.install_chart(
                &cx,
                &accounts,
                PRINCIPAL,
                day(1),
                b"gl-chart",
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
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
                "FY2026-P01",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                b"gl-open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let doc = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"General ledger test source evidence".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            usd,
            jpy,
            evidence: vec![doc.evidence_ref(1)],
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn request(&self) -> RollForwardRequest {
        RollForwardRequest {
            accounts: vec![self.id("1000"), self.id("3000"), self.id("6100")],
            units: vec![self.usd.0],
            label: "January activity".into(),
            effective_from: day(10),
            effective_through: day(20),
            known_at: None,
        }
    }
    fn post(&mut self, date: u8, key: &[u8], unit: UnitId, net: i128) {
        let cx = self.cx();
        let (debit, credit) = if net >= 0 {
            ("1000", "3000")
        } else {
            ("3000", "1000")
        };
        let amount = Amount::new(unit, net.abs());
        let legs = vec![
            LegPayload::simple(Side::Debit, self.id(debit), amount),
            LegPayload::simple(Side::Credit, self.id(credit), amount),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&cx, "General ledger posting").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([57; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
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
            .unwrap();
    }
    fn read(&self, request: &RollForwardRequest) -> GeneralLedger {
        self.book
            .general_ledger(&self.cx(), PRINCIPAL, &cap(&["read"]), request)
            .unwrap()
            .unwrap()
    }
    fn source(&self) -> RollForward {
        self.book
            .roll_forward(&self.cx(), PRINCIPAL, &cap(&["read"]), &self.request())
            .unwrap()
            .unwrap()
    }
}

fn details<'a>(report: &'a GeneralLedger, cell: &GeneralLedgerCell) -> &'a [GeneralLedgerLine] {
    &report.lines()[cell.line_start as usize..cell.line_end as usize]
}

#[test]
fn native_ledger_orders_effective_dates_then_recorded_time_and_reconciles_turnover() {
    let mut h = Harness::new();
    h.post(1, b"opening", h.usd, 100);
    h.post(15, b"recorded-first", h.usd, 25);
    h.post(10, b"late-effective-first", h.usd, -30);
    h.post(10, b"same-day-later", h.usd, 5);
    h.post(21, b"outside-window", h.usd, 7);
    let before = h.head();
    let report = h.read(&h.request());
    let cash = report.cell(h.id("1000"), h.usd.0).unwrap();
    assert_eq!(
        (
            cash.opening,
            cash.debits,
            cash.credits,
            cash.net_change,
            cash.closing
        ),
        (100, 30, 30, 0, 100)
    );
    let lines = details(&report, cash);
    assert_eq!(
        lines
            .iter()
            .map(|line| line.running_balance)
            .collect::<Vec<_>>(),
        [70, 75, 100]
    );
    assert_eq!(
        lines
            .iter()
            .map(|line| line.effective_day)
            .collect::<Vec<_>>(),
        [day(10), day(10), day(15)]
    );
    assert!(lines[0].recorded_seq < lines[1].recorded_seq);
    assert!(lines[2].recorded_seq < lines[0].recorded_seq);
    assert_eq!(report.lines().len(), 6); // no cancellation/netting of the six native legs
    let equity = report.cell(h.id("3000"), h.usd.0).unwrap();
    assert_eq!((equity.opening, equity.closing), (-100, -100));
    assert_eq!(h.head(), before);
}

#[test]
fn inclusive_boundaries_units_zero_cells_and_scope_permutations_are_preserved() {
    let mut h = Harness::new();
    let large = (1i128 << 100) + 17;
    h.post(10, b"first-boundary", h.usd, large);
    h.post(20, b"last-boundary", h.jpy, -large);
    let mut request = h.request();
    request.units.push(h.jpy.0);
    let report = h.read(&request);
    assert_eq!(report.cells().len(), 6);
    assert_eq!(report.cell(h.id("1000"), h.usd.0).unwrap().closing, large);
    assert_eq!(report.cell(h.id("1000"), h.jpy.0).unwrap().closing, -large);
    for unit in [h.usd, h.jpy] {
        let empty = report.cell(h.id("6100"), unit.0).unwrap();
        assert_eq!((empty.opening, empty.closing), (0, 0));
        assert!(details(&report, empty).is_empty());
    }
    assert!(report.cell(VId(u128::MAX), h.usd.0).is_none());
    let original = report.canonical_bytes().unwrap();
    request.accounts.reverse();
    request.units.reverse();
    assert_eq!(h.read(&request).canonical_bytes().unwrap(), original);
}

#[test]
fn a_late_entry_changes_current_detail_but_not_the_original_known_at() {
    let mut h = Harness::new();
    h.post(1, b"opening", h.usd, 100);
    h.post(15, b"original", h.usd, 10);
    let mut pinned = h.request();
    pinned.known_at = Some(h.head());
    let original = h.read(&pinned).canonical_bytes().unwrap();
    h.post(10, b"retroactive", h.usd, -20);
    assert_eq!(h.read(&pinned).canonical_bytes().unwrap(), original);
    let report = h.read(&h.request());
    assert_eq!(
        details(&report, report.cell(h.id("1000"), h.usd.0).unwrap())
            .iter()
            .map(|line| line.running_balance)
            .collect::<Vec<_>>(),
        [80, 90]
    );
}

#[test]
fn present_authority_and_valid_scope_are_required_before_native_reads() {
    let h = Harness::new();
    let request = h.request();
    for (principal, capability) in [(PRINCIPAL, cap(&["post"])), (VId(99), cap(&["read"]))] {
        assert!(
            h.book
                .general_ledger(&h.cx(), principal, &capability, &request)
                .unwrap()
                .is_err()
        );
    }
    for invalid in [
        RollForwardRequest {
            known_at: Some(CommitSeq(h.head().0 + 1)),
            ..request.clone()
        },
        RollForwardRequest {
            effective_through: day(9),
            ..request.clone()
        },
        RollForwardRequest {
            accounts: vec![h.id("1000"), h.id("1000")],
            ..request.clone()
        },
        RollForwardRequest {
            units: vec![u32::MAX],
            ..request.clone()
        },
    ] {
        assert!(
            h.book
                .general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &invalid)
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn zero_activity_does_not_erase_selected_opening_stock() {
    let mut h = Harness::new();
    h.post(1, b"opening", h.usd, 100);
    let report = h.read(&h.request());
    assert!(report.lines().is_empty());
    assert_eq!(report.cells().len(), 3);
    let cash = report.cell(h.id("1000"), h.usd.0).unwrap();
    assert_eq!(
        (cash.opening, cash.closing, cash.line_start, cash.line_end),
        (100, 100, 0, 0)
    );
}

#[test]
fn corrupted_stock_duplicate_citations_and_out_of_scope_movements_are_not_rendered() {
    let mut h = Harness::new();
    h.post(10, b"entry", h.usd, 20);
    let source = h.source();
    let mut broken = source.clone();
    broken.rows[0].closing += 1;
    assert!(project(broken, &h.cx().query()).unwrap().is_err());
    let mut broken = source.clone();
    broken.movements.push(broken.movements[0].clone());
    assert!(project(broken, &h.cx().query()).unwrap().is_err());
    let mut broken = source.clone();
    broken.movements[0].account_id = u128::MAX;
    assert!(project(broken, &h.cx().query()).unwrap().is_err());
    let mut broken = source;
    broken.movements[0].recorded_seq = broken.known_at + 1;
    assert!(project(broken, &h.cx().query()).unwrap().is_err());
}

#[test]
fn same_day_legs_have_a_total_order_independent_of_input_storage_order() {
    let mut h = Harness::new();
    h.post(10, b"one", h.usd, 20);
    h.post(10, b"two", h.usd, -5);
    let source = h.source();
    let expected = project(source.clone(), &h.cx().query())
        .unwrap()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let mut permuted = source;
    permuted.movements.reverse();
    assert_eq!(
        project(permuted, &h.cx().query())
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        expected
    );
}

#[test]
fn integer_and_output_bounds_fail_closed_without_saturation_or_truncation() {
    assert!(add(i128::MAX, 1).is_err());
    assert!(sub(i128::MIN, 1).is_err());
    assert_eq!(add(i128::MIN, i128::MAX).unwrap(), -1);
    assert_eq!(
        length(MAX_GENERAL_LEDGER_BYTES, 0).unwrap(),
        MAX_GENERAL_LEDGER_BYTES
    );
    assert!(length(MAX_GENERAL_LEDGER_BYTES, 1).is_err());
    assert!(length(usize::MAX, 1).is_err());
    let mut h = Harness::new();
    h.post(10, b"entry", h.usd, 1);
    let mut source = h.source();
    source
        .rows
        .resize(MAX_GENERAL_LEDGER_CELLS + 1, source.rows[0].clone());
    assert!(project(source, &h.cx().query()).unwrap().is_err());
}

#[test]
fn byte_layout_is_little_endian_length_prefixed_and_keeps_large_signed_values() {
    let mut out = Bytes::default();
    out.string("€").unwrap();
    out.add(&(-((1i128 << 100) + 17)).to_le_bytes()).unwrap();
    assert_eq!(&out.0[..7], &[3, 0, 0, 0, 0xe2, 0x82, 0xac]);
    assert_eq!(
        i128::from_le_bytes(out.0[7..].try_into().unwrap()),
        -((1i128 << 100) + 17)
    );
}

fn cash_selection(h: &Harness) -> RollForwardRequest {
    RollForwardRequest {
        accounts: vec![h.id("1000")],
        known_at: Some(h.head()),
        ..h.request()
    }
}

// The harness posts cash against equity, so these are explicitly financing
// movements. Production classifications remain the caller's accounting input.
fn cash_definition(source: &GeneralLedger) -> CashFlowDefinition {
    CashFlowDefinition {
        name: "owner-funding-v1".into(),
        cash_accounts: source.accounts().iter().map(|account| account.id).collect(),
        assignments: source
            .lines()
            .iter()
            .map(|line| CashFlowAssignment {
                entry_digest: line.entry_digest,
                leg_index: line.leg_index,
                activity: CashFlowActivity::Financing,
            })
            .collect(),
    }
}

#[test]
fn native_cash_flow_matches_the_admitted_snapshot_without_posting() {
    let mut h = Harness::new();
    h.post(1, b"cash-opening", h.usd, 100);
    h.post(10, b"cash-first-boundary", h.usd, 50);
    h.post(15, b"cash-withdrawal", h.usd, -20);
    h.post(20, b"cash-last-boundary", h.usd, 30);
    h.post(21, b"cash-outside-window", h.usd, 700);
    let request = cash_selection(&h);
    let source = h.read(&request);
    let definition = cash_definition(&source);
    let original = source.canonical_bytes().unwrap();
    let before = h.head();
    let classified = source
        .classify_cash_flow(&h.cx().query(), &definition)
        .unwrap()
        .unwrap();
    let report = h
        .book
        .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &definition)
        .unwrap()
        .unwrap();
    assert_eq!(
        report.canonical_bytes().unwrap(),
        classified.canonical_bytes().unwrap()
    );
    assert_eq!(report.source().canonical_bytes().unwrap(), original);
    assert_eq!(report.source().known_at(), before);
    assert_eq!(report.source().lines().len(), 3);
    let unit = &report.units()[0];
    assert_eq!(
        (unit.opening, unit.net_change, unit.closing),
        (100, 60, 160)
    );
    assert_eq!(
        unit.financing,
        CashFlowSection {
            inflows: 80,
            outflows: 20,
            net: 60
        }
    );
    assert_eq!(h.head(), before);
}

#[test]
fn native_cash_flow_requires_current_read_authority_even_for_an_empty_period() {
    let h = Harness::new();
    let request = cash_selection(&h);
    let definition = cash_definition(&h.read(&request));
    let before = h.head();
    for (principal, capability) in [(PRINCIPAL, cap(&["post"])), (VId(99), cap(&["read"]))] {
        assert!(
            h.book
                .cash_flow(&h.cx(), principal, &capability, &request, &definition)
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(h.head(), before);
}

#[test]
fn native_cash_flow_keeps_a_pinned_prefix_and_refuses_stale_unpinned_assignments() {
    let mut h = Harness::new();
    h.post(1, b"cash-opening", h.usd, 100);
    h.post(15, b"cash-original", h.usd, 10);
    let pinned = cash_selection(&h);
    let definition = cash_definition(&h.read(&pinned));
    let original = h
        .book
        .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &pinned, &definition)
        .unwrap()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    h.post(10, b"cash-late-effective", h.usd, -20);
    assert_eq!(
        h.book
            .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &pinned, &definition)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        original
    );
    let current = RollForwardRequest {
        known_at: None,
        ..pinned
    };
    assert!(
        h.book
            .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &current, &definition)
            .unwrap()
            .is_err()
    );
}

#[test]
fn native_cash_flow_keeps_large_opposing_currencies_separate() {
    let mut h = Harness::new();
    let large = (1i128 << 100) + 17;
    h.post(10, b"cash-usd", h.usd, large);
    h.post(20, b"cash-jpy", h.jpy, -large);
    let mut request = cash_selection(&h);
    request.units.push(h.jpy.0);
    let definition = cash_definition(&h.read(&request));
    let report = h
        .book
        .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &definition)
        .unwrap()
        .unwrap();
    assert_eq!(report.units().len(), 2);
    for (unit_id, expected) in [(h.usd.0, large), (h.jpy.0, -large)] {
        let unit = report
            .units()
            .iter()
            .find(|unit| unit.unit_id == unit_id)
            .unwrap();
        assert_eq!(
            (unit.opening, unit.net_change, unit.closing),
            (0, expected, expected)
        );
        assert_eq!(unit.financing.net, expected);
    }
}

#[test]
fn native_cash_flow_requires_every_citation_even_when_cash_change_is_zero() {
    let mut h = Harness::new();
    h.post(10, b"cash-plus", h.usd, 20);
    h.post(15, b"cash-minus", h.usd, -20);
    let request = cash_selection(&h);
    let definition = cash_definition(&h.read(&request));
    let mut missing = definition.clone();
    missing.assignments.clear();
    let mut duplicate = definition.clone();
    duplicate.assignments[1] = duplicate.assignments[0].clone();
    let mut foreign = definition;
    foreign.assignments[0].entry_digest = [255; 32];
    let before = h.head();
    for invalid in [missing, duplicate, foreign] {
        assert!(
            h.book
                .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &invalid)
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(h.head(), before);
}

#[test]
fn native_cash_flow_does_not_drop_opening_stock_in_an_empty_window() {
    let mut h = Harness::new();
    h.post(1, b"cash-before-window", h.usd, 100);
    let request = cash_selection(&h);
    let definition = cash_definition(&h.read(&request));
    assert!(definition.assignments.is_empty());
    let report = h
        .book
        .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &definition)
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            report.units()[0].opening,
            report.units()[0].net_change,
            report.units()[0].closing
        ),
        (100, 0, 100)
    );
}

#[test]
fn native_cash_flow_refuses_non_cash_account_types_instead_of_filtering_them() {
    let h = Harness::new();
    let request = h.request();
    let definition = cash_definition(&h.read(&request));
    assert!(
        h.book
            .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &definition)
            .unwrap()
            .is_err()
    );
}

#[test]
fn native_cash_flow_does_not_invent_internal_transfers_from_net_zero_cash() {
    let mut h = Harness::new();
    h.post(10, b"cash-contribution", h.usd, 20);
    h.post(15, b"cash-distribution", h.usd, -20);
    let request = cash_selection(&h);
    let mut definition = cash_definition(&h.read(&request));
    for assignment in &mut definition.assignments {
        assignment.activity = CashFlowActivity::InternalTransfer;
    }
    assert!(
        h.book
            .cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &request, &definition)
            .unwrap()
            .is_err()
    );
}

mod replay;
