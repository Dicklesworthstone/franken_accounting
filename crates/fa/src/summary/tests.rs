//! Summary reads over actual kernel-posted entries on the in-memory substrate.
//! No stored balance or forged journal payload supplies a positive result.

use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest};
use fa_model::symbols::{property, relation};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, Oid, Pending, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;

use crate::{BookKeys, Entropy};

const BOOK: Id128 = Id128([0x39; 16]);
const PRINCIPAL: VId = VId(7);

fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn vid(code: &str) -> VId {
    account_vid(BOOK, code)
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn account(code: &str, parent: Option<&str>, leaf: bool, equity: bool) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: format!("{code} name"),
        account_type: if equity { 3 } else { 1 },
        normal_balance: u8::from(equity),
        is_leaf: leaf,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: parent.map(str::to_string),
        limit: None,
    }
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    evidence: EvidenceRef,
    usd: UnitId,
    eur: UnitId,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                MemVfs::new().unwrap(),
                Path::new("summary-book"),
                BookKeys::for_development(61),
                BookSpec {
                    book_id: BOOK,
                    name: "Summary report fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(61),
            ))
            .unwrap();
        let accounts = vec![
            account("assets", None, false, false),
            account("liquidity", Some("assets"), false, false),
            account("bank", Some("liquidity"), true, false),
            account("receivable", Some("assets"), true, false),
            account("equity", None, false, true),
            account("capital", Some("equity"), true, true),
            account("assets-but-unrelated", None, true, false),
            account("empty", None, false, false),
        ];
        runtime
            .block_on(book.install_chart(
                &cx,
                &accounts,
                PRINCIPAL,
                day("2026-02-01"),
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
        for (period, date) in [("FY2026-P02", "2026-02-01"), ("FY2026-P03", "2026-03-01")] {
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
        let doc = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"summary fixture source invoice".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            evidence: doc.evidence_ref(1),
            usd,
            eur,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn post(
        &mut self,
        key: &str,
        date: &str,
        class: EntryClass,
        legs: Vec<(Side, &str, UnitId, i128)>,
    ) {
        let cx = self.cx();
        let legs = legs
            .into_iter()
            .map(|(side, code, unit, amount)| {
                LegPayload::simple(side, vid(code), Amount::new(unit, amount))
            })
            .collect::<Vec<_>>();
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class,
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
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: (class == EntryClass::PENDING).then_some(Pending {
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
            .unwrap();
    }

    fn pair(
        &mut self,
        key: &str,
        date: &str,
        debit: &str,
        credit: &str,
        unit: UnitId,
        amount: i128,
    ) {
        self.post(
            key,
            date,
            EntryClass::ORIGINAL,
            vec![
                (Side::Debit, debit, unit, amount),
                (Side::Credit, credit, unit, amount),
            ],
        );
    }

    fn report(
        &self,
        scope: SummaryScope,
        selection: TrialBalanceSelection,
        at: Option<CommitSeq>,
    ) -> SummaryTrialBalance {
        self.book
            .summary_trial_balance(
                &self.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &SummaryRequest {
                    selection,
                    scope,
                    known_at: at,
                },
            )
            .unwrap()
            .unwrap()
    }

    fn chart(&self, at: CommitSeq) -> ChartSnapshot {
        self.cx()
            .query()
            .with_restriction(|| fa_journal::chart::read_at(&self.book.db, self.book.context(), at))
            .unwrap()
    }
}

fn march() -> TrialBalanceSelection {
    TrialBalanceSelection::AsOf(day("2026-03-31"))
}
fn selected(codes: &[&str]) -> SummaryScope {
    SummaryScope::Selected(codes.iter().map(|code| vid(code)).collect())
}
fn group<'a>(report: &'a SummaryTrialBalance, code: &str) -> &'a SummaryGroup {
    report
        .groups
        .iter()
        .find(|group| group.account.code == code)
        .unwrap()
}
fn columns(group: &SummaryGroup, unit: UnitId) -> [i128; 4] {
    let row = group.rows.iter().find(|row| row.unit_id == unit.0).unwrap();
    [
        row.debits,
        row.credits,
        row.debits_pending,
        row.credits_pending,
    ]
}

#[test]
fn nested_summaries_preserve_units_gross_transfers_pending_columns_and_literal_totals() {
    let mut h = Harness::new();
    h.pair("cash", "2026-03-10", "bank", "capital", h.usd, 100);
    h.pair("invoice", "2026-03-11", "receivable", "capital", h.usd, 70);
    h.pair("eur", "2026-03-12", "bank", "capital", h.eur, 20);
    // Both sides land below assets, exactly once each. A summary is never
    // added back to the source fold as another posting.
    h.pair("transfer", "2026-03-13", "bank", "receivable", h.usd, 25);
    h.post(
        "hold",
        "2026-03-14",
        EntryClass::PENDING,
        vec![
            (Side::Debit, "bank", h.usd, 9),
            (Side::Credit, "capital", h.usd, 9),
        ],
    );
    let at = h.head();
    let report = h.report(SummaryScope::AllRoots, march(), None);
    assert_eq!(report.source.known_at, at);
    assert_eq!(columns(group(&report, "assets"), h.usd), [195, 25, 9, 0]);
    assert_eq!(columns(group(&report, "equity"), h.usd), [0, 170, 0, 9]);
    assert_eq!(columns(group(&report, "assets"), h.eur), [20, 0, 0, 0]);
    assert_eq!(columns(group(&report, "equity"), h.eur), [0, 20, 0, 0]);
    assert_eq!(report.unit_totals[&h.usd.0], (195, 195));
    assert_eq!(report.unit_totals[&h.eur.0], (20, 20));
    assert_eq!(report.pending_unit_totals[&h.usd.0], (9, 9));
    assert_eq!(report.unit_totals, report.source.unit_totals);
    assert_eq!(
        report.pending_unit_totals,
        report.source.pending_unit_totals
    );
    assert!(report.is_complete_and_balanced());
    assert_eq!(
        group(&report, "assets")
            .leaves
            .iter()
            .map(|a| a.code.as_str())
            .collect::<Vec<_>>(),
        vec!["bank", "receivable"]
    );
    assert!(group(&report, "empty").leaves.is_empty());
    assert!(group(&report, "empty").rows.is_empty());
    assert_eq!(group(&report, "assets-but-unrelated").leaves.len(), 1);
    assert!(group(&report, "assets-but-unrelated").rows.is_empty());
    assert!(
        report
            .source
            .rows
            .iter()
            .all(|row| row.account != vid("assets"))
    );
    assert_eq!(h.head(), at, "summary reporting publishes nothing");
}

#[test]
fn selected_subtrees_are_canonical_and_balanced_partial_reports_stay_explicitly_partial() {
    let mut h = Harness::new();
    h.pair("posting", "2026-03-10", "bank", "capital", h.usd, 500);
    let first = h.report(selected(&["assets", "equity"]), march(), None);
    let second = h.report(selected(&["equity", "assets"]), march(), None);
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap()
    );
    assert_eq!(first.unit_totals[&h.usd.0], (500, 500));
    assert!(!first.is_complete());
    assert!(!first.is_complete_and_balanced());
    assert_eq!(
        first
            .uncovered_leaves
            .iter()
            .map(|a| a.code.as_str())
            .collect::<Vec<_>>(),
        vec!["assets-but-unrelated"]
    );
    let leaf = h.report(selected(&["bank"]), march(), None);
    let nested = h.report(selected(&["liquidity"]), march(), None);
    assert_eq!(
        columns(&leaf.groups[0], h.usd),
        columns(&nested.groups[0], h.usd)
    );
    assert_eq!(leaf.groups[0].leaves, nested.groups[0].leaves);
    assert_eq!(
        leaf.source, nested.source,
        "selection does not change the literal fold"
    );
}

#[test]
fn overlap_duplicates_unknown_accounts_and_future_frontiers_refuse_without_writes() {
    let h = Harness::new();
    let at = h.head();
    for scope in [
        selected(&["assets", "liquidity"]),
        selected(&["liquidity", "bank"]),
        selected(&["assets", "bank"]),
        selected(&["bank", "bank"]),
        selected(&["missing"]),
    ] {
        let result = h
            .book
            .summary_trial_balance(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &SummaryRequest {
                    selection: march(),
                    scope,
                    known_at: None,
                },
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(result.code, fa_journal::refusal::code::STRUCTURE);
        assert_eq!(result.exit, exit::USAGE);
    }
    let beyond = h
        .book
        .summary_trial_balance(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &SummaryRequest {
                selection: march(),
                scope: SummaryScope::AllRoots,
                known_at: Some(CommitSeq(at.0 + 1)),
            },
        )
        .unwrap()
        .unwrap_err();
    assert!(beyond.message.contains("beyond"));
    assert_eq!(h.head(), at);
}

#[test]
fn historical_chart_and_stock_activity_selectors_remain_fixed_after_later_publications() {
    let mut h = Harness::new();
    h.pair("feb", "2026-02-15", "bank", "capital", h.usd, 10);
    h.pair("mar", "2026-03-15", "bank", "capital", h.usd, 20);
    let at = h.head();
    let stock = h.report(
        SummaryScope::AllRoots,
        TrialBalanceSelection::Periods(vec!["FY2026-P03".into()]),
        Some(at),
    );
    let flow = h.report(
        SummaryScope::AllRoots,
        TrialBalanceSelection::Activity(vec!["FY2026-P03".into(), "FY2026-P03".into()]),
        Some(at),
    );
    assert_eq!(columns(group(&stock, "assets"), h.usd)[0], 30);
    assert_eq!(columns(group(&flow, "assets"), h.usd)[0], 20);
    assert!(!stock.source.activity);
    assert!(flow.source.activity);
    let before_march = h.report(
        SummaryScope::AllRoots,
        TrialBalanceSelection::AsOf(day("2026-03-14")),
        Some(at),
    );
    assert_eq!(columns(group(&before_march, "assets"), h.usd)[0], 10);
    let original_bytes = stock.canonical_bytes().unwrap();
    h.pair("late", "2026-03-20", "bank", "capital", h.usd, 40);
    let cx = h.cx();
    h.runtime
        .block_on(h.book.install_chart(
            &cx,
            &[account("later-root", None, true, false)],
            PRINCIPAL,
            day("2026-03-21"),
            b"later-chart",
            &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let repeated = h.report(
        SummaryScope::AllRoots,
        TrialBalanceSelection::Periods(vec!["FY2026-P03".into()]),
        Some(at),
    );
    assert_eq!(repeated.canonical_bytes().unwrap(), original_bytes);
    assert!(
        !repeated
            .groups
            .iter()
            .any(|g| g.account.code == "later-root")
    );
    let now = h.report(SummaryScope::AllRoots, march(), None);
    assert_eq!(columns(group(&now, "assets"), h.usd)[0], 70);
    assert!(now.groups.iter().any(|g| g.account.code == "later-root"));
    assert!(
        h.book
            .summary_trial_balance(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &SummaryRequest {
                    selection: march(),
                    scope: selected(&["later-root"]),
                    known_at: Some(at),
                }
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn empty_summaries_empty_selections_and_empty_activity_are_successful_without_fake_units() {
    let h = Harness::new();
    let all = h.report(SummaryScope::AllRoots, march(), None);
    assert!(all.is_complete_and_balanced());
    assert!(all.source.rows.is_empty());
    assert!(all.unit_totals.is_empty());
    assert!(all.groups.iter().all(|g| g.rows.is_empty()));
    let empty = h.report(selected(&["empty"]), march(), None);
    assert_eq!(empty.groups.len(), 1);
    assert!(empty.groups[0].leaves.is_empty());
    assert!(empty.groups[0].rows.is_empty());
    assert!(!empty.is_complete());
    let none = h.report(SummaryScope::Selected(Vec::new()), march(), None);
    assert!(none.groups.is_empty());
    assert!(none.unit_totals.is_empty());
    assert_eq!(none.uncovered_leaves.len(), 4);
}

#[test]
fn read_authority_precedes_selection_and_chart_observation_including_corrupt_mirrors() {
    let mut h = Harness::new();
    let historical = h.head();
    let good = h.report(SummaryScope::AllRoots, march(), Some(historical));
    let cx = h.cx();
    let mut corruption = WriteBatch::new(relation::CHILD_OF);
    corruption.compare_and_set_vertex_property(
        vid("bank"),
        property::POSTING,
        Some(CanonicalScalar::Int(1)),
        CanonicalScalar::Int(0),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), corruption))
        .unwrap();
    let at = h.head();
    let request = SummaryRequest {
        selection: march(),
        scope: SummaryScope::AllRoots,
        known_at: None,
    };
    let no_read = h
        .book
        .summary_trial_balance(&cx, PRINCIPAL, &cap(&["post"]), &request)
        .unwrap()
        .unwrap_err();
    assert_eq!(no_read.code, fa_journal::refusal::code::CAPABILITY);
    let hidden = SummaryRequest {
        scope: selected(&["absent"]),
        known_at: Some(CommitSeq(u64::MAX)),
        ..request.clone()
    };
    assert_eq!(
        h.book
            .summary_trial_balance(&cx, PRINCIPAL, &cap(&["post"]), &hidden)
            .unwrap()
            .unwrap_err(),
        no_read
    );
    assert!(
        h.book
            .summary_trial_balance(&cx, VId(8), &cap(&["read"]), &request)
            .unwrap()
            .is_err(),
        "a capability is bound to its holder"
    );
    assert!(matches!(
        h.book
            .summary_trial_balance(&cx, PRINCIPAL, &cap(&["read"]), &request),
        Err(BookError::Kernel(KernelError::Corrupt(_)))
    ));
    assert_eq!(
        h.report(SummaryScope::AllRoots, march(), Some(historical)),
        good
    );
    assert_eq!(
        h.head(),
        at,
        "denial and corruption checking publish nothing"
    );
}

#[test]
fn source_duplicate_metadata_and_total_drift_are_not_silently_rolled_up() {
    let mut h = Harness::new();
    h.pair("real", "2026-03-10", "bank", "capital", h.usd, 100);
    let report = h.report(SummaryScope::AllRoots, march(), None);
    let chart = h.chart(report.source.known_at);
    let roots = selected_roots(&chart, &SummaryScope::AllRoots).unwrap();
    let mut duplicate = report.source.clone();
    duplicate.rows.push(duplicate.rows[0].clone());
    let mut renamed = report.source.clone();
    renamed.rows[0].name.push_str(" changed");
    let mut drift = report.source.clone();
    drift.unit_totals.get_mut(&h.usd.0).unwrap().0 += 1;
    let mut later = report.source.clone();
    later.known_at = CommitSeq(later.known_at.0 + 1);
    for source in [duplicate, renamed, drift, later] {
        assert!(matches!(
            aggregate(BOOK, &chart, source, &roots),
            Err(RegisterError::Kernel(KernelError::Corrupt(_)))
        ));
    }
}

#[test]
fn summary_amount_arithmetic_checks_overflow_and_keeps_every_output_field_bound() {
    let row = TbRow {
        account: vid("bank"),
        code: "bank".into(),
        name: "bank name".into(),
        account_type: AccountType(1),
        unit_id: 1,
        debits: 1,
        credits: 0,
        debits_pending: 0,
        credits_pending: 0,
    };
    assert!(matches!(
        add(&mut [i128::MAX, 0, 0, 0], &row),
        Err(RegisterError::Overflow)
    ));
    let mut negative = row.clone();
    negative.debits = -1;
    assert!(add(&mut [0; 4], &negative).is_err());
    let mut exact = [i128::MAX - 1, 0, 0, 0];
    add(&mut exact, &row).unwrap();
    assert_eq!(exact[0], i128::MAX);
    let h = Harness::new();
    let report = h.report(SummaryScope::AllRoots, march(), None);
    let original = report.canonical_bytes().unwrap();
    assert!(original.starts_with(OUTPUT_FORMAT));
    let mut changed = report.clone();
    changed.groups[0].account.name.push_str(" changed");
    assert_ne!(changed.canonical_bytes().unwrap(), original);
    let mut changed = report.clone();
    changed
        .groups
        .iter_mut()
        .find(|g| !g.leaves.is_empty())
        .unwrap()
        .leaves
        .pop();
    assert_ne!(changed.canonical_bytes().unwrap(), original);
    let mut changed = report;
    changed.source.known_at = CommitSeq(changed.source.known_at.0 + 1);
    assert_ne!(changed.canonical_bytes().unwrap(), original);
}
