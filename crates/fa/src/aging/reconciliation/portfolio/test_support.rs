use super::*;

use crate::{BookKeys, Entropy};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, LegPayload, Oid,
    Settlement, account_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use std::path::Path;

pub(super) const PRINCIPAL: VId = VId(7);
const BOOK: Id128 = Id128([0x74; 16]);
const PATH: &str = "aging-portfolio-book";
pub(super) fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
pub(super) fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn keys() -> BookKeys {
    BookKeys::for_development(0x74)
}
fn account(code: &str, kind: AccountType, is_leaf: bool) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: format!("{code} account"),
        account_type: kind.0,
        normal_balance: u8::from(matches!(
            kind,
            AccountType::LIABILITY | AccountType::REVENUE
        )),
        is_leaf,
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
}

impl Harness {
    pub(super) fn new() -> Self {
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
                    book_id: BOOK,
                    name: "Portfolio fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(116),
            ))
            .unwrap();
        runtime
            .block_on(book.install_chart(
                &cx,
                &[
                    account("ar", AccountType::ASSET, true),
                    account("cash", AccountType::ASSET, true),
                    account("sales", AccountType::REVENUE, true),
                    account("ap", AccountType::LIABILITY, true),
                    account("expense", AccountType::EXPENSE, true),
                    account("idle", AccountType::ASSET, true),
                    account("summary", AccountType::ASSET, false),
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
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Portfolio accounting evidence".to_vec(),
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
    pub(super) fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    pub(super) fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    pub(super) fn id(&self, code: &str) -> VId {
        account_vid(BOOK, code)
    }
    pub(super) fn request(&self) -> AgingPortfolioRequest {
        AgingPortfolioRequest {
            scope: AgingAccountScope::AllPosting,
            effective_through: day("2026-03-31"),
            known_at: None,
            buckets: AgingBuckets::thirty_day(),
        }
    }
    pub(super) fn report(&self, request: &AgingPortfolioRequest) -> AgingPortfolio {
        self.book
            .reconcile_aging_portfolio(&self.cx(), PRINCIPAL, &cap(&["read"]), request)
            .unwrap()
            .unwrap()
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn post(
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
            book_id: BOOK,
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
                intent_oid: Oid([8; 32]),
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
    pub(super) fn post_allocation(
        &mut self,
        key: &str,
        date: &str,
        unit: UnitId,
        debit_account: &str,
        credit_account: &str,
        amount: i128,
    ) -> EntryRef {
        use fa_journal::allocation::{ALLOCATION_DOCUMENT_KIND, AllocationPosting};
        use fa_money::allocation::{AllocationMethod, AllocationRequest, AllocationTarget};
        let cx = self.cx();
        let allocation = AllocationPosting {
            source: self.id(debit_account),
            source_side: Side::Debit,
            dimensions: Vec::new(),
            request: AllocationRequest {
                total: Amount::new(unit, amount),
                method: AllocationMethod::LargestRemainder,
                targets: vec![AllocationTarget {
                    id: self.id(credit_account).0,
                    basis: 1,
                }],
            },
        };
        let driver_doc = Document {
            book_id: BOOK,
            kind: ALLOCATION_DOCUMENT_KIND,
            mime: "application/octet-stream".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: allocation.basis_bytes().unwrap(),
        };
        self.runtime
            .block_on(self.book.add_document(&cx, &driver_doc))
            .unwrap()
            .unwrap();
        let template = EntryPayload {
            schema_minor: 0,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ALLOCATION,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&cx, key).unwrap(),
            effective_period: None,
            unit_totals: Vec::new(),
            legs: Vec::new(),
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([8; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![allocation.driver_evidence(BOOK).unwrap()],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let proposal = allocation.proposal(template).unwrap();
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
    pub(super) fn add_leaf(&mut self, code: &str) {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.install_chart(
                &cx,
                &[account(code, AccountType::ASSET, true)],
                PRINCIPAL,
                day("2026-03-01"),
                code.as_bytes(),
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
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
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                keys(),
                Entropy::deterministic(117),
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
    pub(super) fn sources(&self) -> (ChartSnapshot, EffectiveDateAging, TrialBalance) {
        let request = self.request();
        let at = self.head();
        let cx = self.cx();
        let query = cx.query();
        let chart = query
            .with_restriction(|| fa_journal::chart::read_at(&self.book.db, self.book.context(), at))
            .unwrap();
        let aging = self
            .book
            .effective_date_aging(
                &cx,
                None,
                request.effective_through,
                Some(at),
                &request.buckets,
            )
            .unwrap();
        let control = query
            .with_restriction(|| {
                fa_registers::balance_as_of(
                    &self.book.db,
                    self.book.context(),
                    request.effective_through,
                    Some(at),
                )
            })
            .unwrap();
        (chart, aging, control)
    }
}
