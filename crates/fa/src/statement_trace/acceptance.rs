use super::*;

use crate::{BookKeys, Entropy, StatementDefinition, StatementSelection};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::symbols::relation;
use fa_model::{AccountType, EntryPayload, EvidenceRef, LegPayload, Oid, Pending, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;
use std::path::Path;

pub(super) const PRINCIPAL: VId = VId(7);
const BOOK: Id128 = Id128([0x73; 16]);
const PATH: &str = "statement-trace-book";
pub(super) fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
pub(super) fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn keys() -> BookKeys {
    BookKeys::for_development(0x73)
}
pub(super) fn account(code: &str, kind: AccountType) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: format!("{code} name"),
        account_type: kind.0,
        normal_balance: u8::from(matches!(
            kind,
            AccountType::LIABILITY | AccountType::EQUITY | AccountType::REVENUE
        )),
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    }
}

pub(super) struct Harness {
    pub(super) runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    pub(super) book: AsyncBook<MemVfs>,
    pub(super) usd: UnitId,
    pub(super) eur: UnitId,
    evidence: EvidenceRef,
    pub(super) chart_entry: VId,
}

impl Harness {
    pub(super) fn new() -> Self {
        Self::in_book(BOOK)
    }
    pub(super) fn in_book(book_id: Id128) -> Self {
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
                    name: "Publication trace fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(115),
            ))
            .unwrap();
        let installed = runtime
            .block_on(book.install_chart(
                &cx,
                &[
                    account("cash", AccountType::ASSET),
                    account("capital", AccountType::EQUITY),
                    account("sales", AccountType::REVENUE),
                    account("expense", AccountType::EXPENSE),
                ],
                PRINCIPAL,
                day("2025-01-01"),
                b"chart",
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        for year in [2025, 2026] {
            runtime
                .block_on(
                    book.create_periods(
                        &cx,
                        year,
                        fgdb_types::VId(1),
                        &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"])
                            .unwrap(),
                    ),
                )
                .unwrap()
                .unwrap();
        }
        for (period, date) in [
            ("FY2025-P03", "2025-03-01"),
            ("FY2026-P03", "2026-03-01"),
            ("FY2026-P04", "2026-04-01"),
        ] {
            runtime
                .block_on(book.transition_period(
                    &cx,
                    period,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    day(date),
                    period.as_bytes(),
                    &cap(&["close"]),
                ))
                .unwrap()
                .unwrap();
        }
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"source evidence for statement publication trace".to_vec(),
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
            chart_entry: installed.control_entry,
        }
    }
    pub(super) fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    pub(super) fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    pub(super) fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn post(
        &mut self,
        key: &str,
        date: &str,
        unit: UnitId,
        accounts: (&str, &str),
        amount: i128,
        pending: bool,
    ) -> Posted {
        let cx = self.cx();
        let legs = vec![
            LegPayload::simple(Side::Debit, self.id(accounts.0), Amount::new(unit, amount)),
            LegPayload::simple(Side::Credit, self.id(accounts.1), Amount::new(unit, amount)),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: if pending {
                EntryClass::PENDING
            } else {
                EntryClass::ORIGINAL
            },
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
            pending: pending.then_some(Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            }),
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
    }
    pub(super) fn initial(&mut self) {
        self.post(
            "capital",
            "2025-03-10",
            self.usd,
            ("cash", "capital"),
            100,
            false,
        );
        self.post(
            "sales",
            "2026-03-10",
            self.usd,
            ("cash", "sales"),
            50,
            false,
        );
        self.post("eur", "2026-03-10", self.eur, ("cash", "sales"), 30, false);
    }
    pub(super) fn request(&self, before: CommitSeq, name: &str) -> StatementTraceRequest {
        StatementTraceRequest {
            comparison: StatementDiffRequest {
                selection: StatementSelection {
                    definition: StatementDefinition::embedded(name).unwrap(),
                    periods: vec!["FY2026-P03".into()],
                    comparative: vec!["FY2025-P03".into()],
                },
                before,
                after: None,
            },
            max_publications: 32,
        }
    }
    pub(super) fn trace(&self, request: &StatementTraceRequest) -> StatementTrace {
        self.book
            .statement_trace(&self.cx(), PRINCIPAL, &cap(&["read"]), request)
            .unwrap()
            .unwrap()
    }
    pub(super) fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            eur,
            evidence,
            chart_entry,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                keys(),
                Entropy::deterministic(116),
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
            chart_entry,
        }
    }
}

fn delta(step: &StatementPublication, line: &str, unit: UnitId) -> Vec<i128> {
    step.changes
        .iter()
        .find(|row| row.code == line && row.unit_id == unit.0)
        .map_or(vec![0, 0], |row| row.delta.clone())
}

#[test]
fn real_postings_cancel_without_hiding_their_history_and_survive_reopen() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    let debit = h.post(
        "expense",
        "2026-03-15",
        h.usd,
        ("expense", "cash"),
        15,
        false,
    );
    let credit = h.post(
        "offset",
        "2026-03-15",
        h.usd,
        ("cash", "expense"),
        15,
        false,
    );
    h.post("hold", "2026-03-15", h.usd, ("cash", "capital"), 5, true);
    h.post("april", "2026-04-15", h.usd, ("cash", "capital"), 20, false);
    let cx = h.cx();
    h.runtime
        .block_on(h.book.install_chart(
            &cx,
            &[account("unused", AccountType::EXPENSE)],
            PRINCIPAL,
            day("2026-04-20"),
            b"unused-account",
            &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let after = h.head();
    let mut request = h.request(before, "balance-sheet");
    request.comparison.after = Some(after);
    let trace = h.trace(&request);
    assert_eq!(trace.publications().len() as u64, after.0 - before.0);
    assert_eq!(trace.publications().len(), 5);
    assert!(!trace.summary().amounts_changed());
    assert!(trace.had_changes());
    assert_eq!(
        trace.publications()[0].entries[0].entry_ref,
        debit.entry_ref()
    );
    assert_eq!(
        trace.publications()[1].entries[0].entry_ref,
        credit.entry_ref()
    );
    assert_eq!(
        delta(&trace.publications()[0], "assets", h.usd),
        vec![-15, 0]
    );
    assert_eq!(
        delta(&trace.publications()[1], "assets", h.usd),
        vec![15, 0]
    );
    assert!(trace.publications()[2].is_unchanged());
    assert!(trace.publications()[3].is_unchanged());
    assert_eq!(
        trace.publications()[4].mapping_changes[0].account_id,
        h.id("unused").0
    );
    assert_eq!(trace.publications()[4].entries[0].posting_date, None);
    let net = h
        .book
        .statement_diff(&cx, PRINCIPAL, &cap(&["read"]), &request.comparison)
        .unwrap()
        .unwrap();
    assert_eq!(trace.summary(), &net);
    let bytes = trace.canonical_bytes().unwrap();
    assert_eq!(h.head(), after);
    let h = h.reopen();
    assert_eq!(h.trace(&request).canonical_bytes().unwrap(), bytes);
    assert_eq!(h.head(), after);
}

#[test]
fn prior_year_and_native_currency_impacts_use_the_production_stock_activity_rules() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post("prior", "2025-03-20", h.usd, ("expense", "cash"), 10, false);
    h.post(
        "current",
        "2026-03-20",
        h.usd,
        ("expense", "cash"),
        15,
        false,
    );
    h.post(
        "foreign",
        "2026-03-20",
        h.eur,
        ("expense", "cash"),
        7,
        false,
    );
    let stock = h.trace(&h.request(before, "balance-sheet"));
    assert_eq!(
        delta(&stock.publications()[0], "assets", h.usd),
        vec![-10, -10]
    );
    assert_eq!(
        delta(&stock.publications()[1], "assets", h.usd),
        vec![-15, 0]
    );
    assert_eq!(delta(&stock.publications()[2], "assets", h.usd), vec![0, 0]);
    assert_eq!(
        delta(&stock.publications()[2], "assets", h.eur),
        vec![-7, 0]
    );
    let income = h.trace(&h.request(before, "income-statement"));
    let expense = income
        .summary()
        .before()
        .mappings
        .iter()
        .find(|row| row.account.id == h.id("expense").0)
        .unwrap()
        .line_code
        .clone();
    assert_eq!(
        delta(&income.publications()[0], &expense, h.usd),
        vec![0, 10]
    );
    assert_eq!(
        delta(&income.publications()[1], &expense, h.usd),
        vec![15, 0]
    );
    assert_eq!(
        delta(&income.publications()[2], &expense, h.eur),
        vec![7, 0]
    );
}

#[test]
fn authority_and_work_bounds_precede_damaged_history_and_refusals_publish_nothing() {
    let mut h = Harness::new();
    let before = h.head();
    let cx = h.cx();
    let old = cx
        .query()
        .with_restriction(|| h.book.db.vertex(h.chart_entry))
        .unwrap()
        .unwrap();
    let original = fa_journal::rows::prop(&old, property::FA_PAYLOAD)
        .cloned()
        .unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        h.chart_entry,
        property::FA_PAYLOAD,
        Some(original),
        CanonicalScalar::bytes(Vec::new()).unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let head = h.head();
    let request = h.request(before, "balance-sheet");
    for (principal, capability) in [
        (PRINCIPAL, cap(&["post"])),
        (PRINCIPAL, cap(&["produce"])),
        (VId(9), cap(&["read"])),
    ] {
        let refusal = h
            .book
            .statement_trace(&cx, principal, &capability, &request)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
    }
    for limit in [0, MAX_STATEMENT_TRACE_PUBLICATIONS + 1] {
        let mut limited = request.clone();
        limited.max_publications = limit;
        assert_eq!(
            h.book
                .statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &limited)
                .unwrap()
                .unwrap_err()
                .code,
            crate::statements::STATEMENT_INVALID
        );
    }
    let mut future = request.clone();
    future.comparison.after = Some(CommitSeq(head.0 + 1));
    assert!(
        h.book
            .statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &future)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), head);
    assert!(!matches!(
        h.book
            .statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &request),
        Ok(Ok(_))
    ));
}
