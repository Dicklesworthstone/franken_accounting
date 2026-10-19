use super::*;

use super::super::AgingTotal;
use crate::{BookKeys, Entropy};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::symbols::{property, relation};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload,
    Oid, Settlement, account_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;
use std::path::Path;

const BOOK: Id128 = Id128([0x79; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "aging-reconciliation-book";
fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn keys() -> BookKeys {
    BookKeys::for_development(0x79)
}
fn account(code: &str, kind: AccountType) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: format!("{code} account"),
        account_type: kind.0,
        normal_balance: u8::from(matches!(
            kind,
            AccountType::LIABILITY | AccountType::REVENUE
        )),
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    }
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
    fn new() -> Self {
        Self::in_book(BOOK)
    }
    fn in_book(book_id: Id128) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let vfs = MemVfs::new().unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                keys(),
                BookSpec {
                    book_id,
                    name: "Open-item/control reconciliation fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(121),
            ))
            .unwrap();
        let mut summary = account("summary", AccountType::ASSET);
        summary.is_leaf = false;
        runtime
            .block_on(book.install_chart(
                &cx,
                &[
                    account("ar", AccountType::ASSET),
                    account("cash", AccountType::ASSET),
                    account("sales", AccountType::REVENUE),
                    account("ap", AccountType::LIABILITY),
                    account("expense", AccountType::EXPENSE),
                    summary,
                ],
                PRINCIPAL,
                day("2026-01-01"),
                b"chart",
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.create_periods(
                &cx,
                2026,
                fgdb_types::VId(1),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P03",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day("2026-03-01"),
                b"open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Open-item/control evidence".to_vec(),
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
            eur,
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
        account_vid(self.book.context().book_id, code)
    }
    #[allow(clippy::too_many_arguments)]
    fn post(
        &mut self,
        key: &str,
        date: &str,
        unit: UnitId,
        accounts: (&str, &str),
        amount: i128,
        target: Option<EntryRef>,
    ) -> EntryRef {
        let cx = self.cx();
        let mut legs = vec![
            LegPayload::simple(Side::Debit, self.id(accounts.0), Amount::new(unit, amount)),
            LegPayload::simple(Side::Credit, self.id(accounts.1), Amount::new(unit, amount)),
        ];
        if let Some(target) = target {
            legs[1].settles.push(Settlement {
                target,
                ordinal: 0,
                amount: Amount::new(unit, amount),
            });
        }
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
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
                intent_oid: Oid([9; 32]),
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
    fn request(&self, code: &str, cutoff: &str) -> AgingReconciliationRequest {
        AgingReconciliationRequest {
            account: self.id(code),
            effective_through: day(cutoff),
            known_at: None,
            buckets: AgingBuckets::thirty_day(),
        }
    }
    fn report(&self, request: &AgingReconciliationRequest) -> AgingReconciliation {
        self.book
            .reconcile_effective_date_aging(&self.cx(), PRINCIPAL, &cap(&["read"]), request)
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
            eur,
            evidence,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                keys(),
                Entropy::deterministic(122),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            eur,
            evidence,
        }
    }
}

#[test]
fn partial_full_and_future_effective_settlements_tie_at_both_coordinates() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let before_payment = h.head();
    h.post(
        "partial",
        "2026-03-15",
        h.usd,
        ("cash", "ar"),
        40,
        Some(invoice),
    );
    h.post(
        "remainder",
        "2026-03-25",
        h.usd,
        ("cash", "ar"),
        60,
        Some(invoice),
    );
    let at = h.head();
    for (cutoff, expected, credits, items) in [
        ("2026-03-10", 100, 0, 1),
        ("2026-03-20", 60, 40, 1),
        ("2026-03-31", 0, 100, 0),
    ] {
        let report = h.report(&h.request("ar", cutoff));
        assert!(report.is_reconciled());
        assert_eq!(report.known_at(), at);
        assert_eq!(report.effective_through(), day(cutoff));
        assert_eq!(report.aging().items.len(), items);
        let row = &report.rows()[0];
        assert_eq!((row.posted_debits, row.posted_credits), (100, credits));
        assert_eq!(
            (row.posted_net, row.open_net, row.difference),
            (expected, expected, 0)
        );
        assert_eq!(row.open_debits, expected);
        assert_eq!(report.control_rows()[0].account, h.id("ar"));
    }
    let mut old = h.request("ar", "2026-03-31");
    old.known_at = Some(before_payment);
    let original = h.report(&old);
    assert_eq!(original.rows()[0].open_net, 100);
    let h = h.reopen();
    assert_eq!(h.report(&old), original);
    assert_eq!(
        h.head(),
        at,
        "reads publish neither corrections nor derived mirrors"
    );
}

#[test]
fn large_native_debits_credits_and_payables_remain_distinct() {
    let mut h = Harness::new();
    let exact = (1_i128 << 90) + 1;
    h.post("debit", "2026-03-01", h.usd, ("ar", "sales"), exact, None);
    h.post("credit", "2026-03-02", h.usd, ("cash", "ar"), exact, None);
    h.post("eur", "2026-03-03", h.eur, ("ar", "sales"), 7, None);
    h.post("payable", "2026-03-04", h.usd, ("expense", "ap"), 19, None);
    let report = h.report(&h.request("ar", "2026-03-31"));
    assert_eq!(report.rows().len(), 2);
    let usd = report
        .rows()
        .iter()
        .find(|row| row.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (usd.open_debits, usd.open_credits, usd.open_net),
        (exact, exact, 0)
    );
    assert_eq!(usd.open_item_count, 2);
    assert!(report.is_reconciled());
    let payable = h.report(&h.request("ap", "2026-03-31"));
    assert_eq!(payable.rows()[0].posted_net, -19);
    assert_eq!(payable.rows()[0].open_net, -19);
    assert_eq!(payable.rows()[0].open_credits, 19);
    assert!(payable.is_reconciled());
}

#[test]
fn empty_accounts_are_explicit_but_missing_summary_and_future_selections_refuse() {
    let h = Harness::new();
    let request = h.request("ar", "2026-03-31");
    let empty = h.report(&request);
    assert!(empty.is_reconciled());
    assert!(empty.rows().is_empty());
    assert_eq!(empty.account().vid, h.id("ar"));
    assert_eq!(empty.account().name, "ar account");
    let mut future = request.clone();
    future.known_at = Some(CommitSeq(h.head().0 + 1));
    let mut excessive = request.clone();
    excessive.buckets = AgingBuckets::new((0..129).collect()).unwrap();
    for invalid in [
        h.request("missing", "2026-03-31"),
        h.request("summary", "2026-03-31"),
        future,
        excessive,
    ] {
        assert_eq!(
            h.book
                .reconcile_effective_date_aging(&h.cx(), PRINCIPAL, &cap(&["read"]), &invalid)
                .unwrap()
                .unwrap_err()
                .exit,
            exit::USAGE
        );
    }
}

#[test]
fn denied_authority_precedes_damaged_historical_chart_observation() {
    let mut h = Harness::new();
    let request = h.request("ar", "2026-03-31");
    let cx = h.cx();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        h.id("ar"),
        property::POSTING,
        Some(CanonicalScalar::Int(1)),
        CanonicalScalar::Int(0),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let head = h.head();
    for (principal, capability) in [(PRINCIPAL, cap(&["post"])), (VId(8), cap(&["read"]))] {
        assert_eq!(
            h.book
                .reconcile_effective_date_aging(&cx, principal, &capability, &request)
                .unwrap()
                .unwrap_err()
                .code,
            fa_journal::refusal::code::CAPABILITY
        );
    }
    assert_eq!(h.head(), head);
}

#[test]
fn a_backdated_application_split_by_the_cutoff_is_not_silently_reconciled() {
    let mut h = Harness::new();
    let invoice = h.post(
        "later-invoice",
        "2026-03-20",
        h.usd,
        ("ar", "sales"),
        100,
        None,
    );
    h.post(
        "early-application",
        "2026-03-01",
        h.usd,
        ("cash", "ar"),
        40,
        Some(invoice),
    );
    let request = h.request("ar", "2026-03-10");
    assert_eq!(
        h.book
            .reconcile_effective_date_aging(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::USAGE
    );
    assert!(h.report(&h.request("ar", "2026-03-31")).is_reconciled());
}

// Pure fold-composition fixtures intentionally plant discrepancies. They do
// not claim that corrupt or unsupported posting classes passed the kernel.
fn pieces() -> (AccountRow, EffectiveDateAging, TrialBalance) {
    let account = AccountRow {
        vid: VId(1),
        code: "ar".into(),
        name: "Receivable".into(),
        account_type: AccountType::ASSET.0,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        limit: None,
        created_at: CommitSeq(1),
    };
    let aging = EffectiveDateAging {
        book_id: BOOK,
        known_at: CommitSeq(9),
        effective_through: day("2026-03-31"),
        account: Some(account.vid),
        bands: AgingBuckets::thirty_day().bands(),
        items: Vec::new(),
        cells: Vec::new(),
        totals: vec![AgingTotal {
            account: account.vid,
            unit_id: 1,
            amounts: AgingAmounts {
                debits: 60,
                credits: 0,
                item_count: 1,
            },
        }],
    };
    let control = TrialBalance {
        periods: vec!["FY2026-P03".into()],
        known_at: aging.known_at,
        effective_through: Some(aging.effective_through),
        activity: false,
        rows: vec![TbRow {
            account: account.vid,
            code: account.code.clone(),
            name: account.name.clone(),
            account_type: AccountType::ASSET,
            unit_id: 1,
            debits: 100,
            credits: 40,
            debits_pending: 13,
            credits_pending: 17,
        }],
        unit_totals: BTreeMap::new(),
        pending_unit_totals: BTreeMap::new(),
    };
    (account, aging, control)
}

#[test]
fn gross_turnover_and_reservations_are_not_residual_open_amounts() {
    let (account, aging, mut control) = pieces();
    let mut pending_only = control.rows[0].clone();
    pending_only.unit_id = 2;
    pending_only.debits = 0;
    pending_only.credits = 0;
    control.rows.push(pending_only);
    let report = assemble(account, aging, control).unwrap();
    assert!(report.is_reconciled());
    assert_eq!(report.rows.len(), 2);
    assert_eq!(
        (
            report.rows[0].pending_debits,
            report.rows[0].pending_credits
        ),
        (13, 17)
    );
    assert_eq!(report.rows[1].open_item_count, 0);
    assert_eq!(report.rows[1].difference, 0);
}

#[test]
fn unmatched_units_and_equal_opposite_currency_discrepancies_never_cancel() {
    let (account, mut aging, mut control) = pieces();
    control.rows[0].debits = 110;
    let mut other = control.rows[0].clone();
    other.unit_id = 2;
    other.debits = 0;
    other.credits = 10;
    control.rows.push(other);
    aging.totals.push(AgingTotal {
        account: account.vid,
        unit_id: 3,
        amounts: AgingAmounts {
            debits: 5,
            credits: 0,
            item_count: 1,
        },
    });
    let report = assemble(account, aging, control).unwrap();
    assert!(!report.is_reconciled());
    assert_eq!(
        report
            .rows
            .iter()
            .map(|row| (row.unit_id, row.difference))
            .collect::<Vec<_>>(),
        vec![(1, 10), (2, -10), (3, -5)]
    );
}

#[test]
fn changed_coordinates_duplicate_units_negative_sums_and_overflow_are_rejected() {
    let (account, aging, control) = pieces();
    let mut wrong = control.clone();
    wrong.known_at = CommitSeq(8);
    let mut activity = control.clone();
    activity.activity = true;
    let mut cutoff = control.clone();
    cutoff.effective_through = Some(day("2026-03-30"));
    let mut duplicate = control.clone();
    duplicate.rows.push(duplicate.rows[0].clone());
    let mut negative = control.clone();
    negative.rows[0].debits = -1;
    for invalid in [wrong, activity, cutoff, duplicate, negative] {
        assert!(assemble(account.clone(), aging.clone(), invalid).is_err());
    }
    let mut duplicate = aging.clone();
    duplicate.totals.push(duplicate.totals[0].clone());
    assert!(assemble(account.clone(), duplicate, control.clone()).is_err());
    let mut credit = aging;
    credit.totals[0].amounts.debits = 0;
    credit.totals[0].amounts.credits = i128::MAX;
    let mut debit = control;
    debit.rows[0].debits = i128::MAX;
    debit.rows[0].credits = 0;
    assert!(matches!(
        assemble(account, credit, debit),
        Err(BookError::Registers(RegisterError::Overflow))
    ));
}

mod certificate;
