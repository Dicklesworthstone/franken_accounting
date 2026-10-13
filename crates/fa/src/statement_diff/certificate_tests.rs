use super::*;

use crate::{BookKeys, Entropy, StatementDefinition, StatementSelection};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::symbols::{property, relation};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, Oid, Pending,
    account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;
use std::path::Path;

const BOOK: Id128 = Id128([0x61; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "statement-diff-book";
fn day(s: &str) -> DateDay {
    DateDay::parse(s).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn keys() -> BookKeys {
    BookKeys::for_development(0x61)
}
fn account(code: &str, kind: AccountType) -> AccountSpec {
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

struct Harness {
    runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    eur: UnitId,
    evidence: EvidenceRef,
    chart_entry: VId,
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
                    name: "Statement bridge fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(97),
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
            ))
            .unwrap()
            .unwrap();
        for year in [2025, 2026] {
            runtime.block_on(book.create_periods(&cx, year)).unwrap();
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
            bytes: b"source evidence for statement bridge postings".to_vec(),
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
        pending: bool,
    ) {
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
            .unwrap();
    }
    fn initial(&mut self) {
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
    fn request(&self, before: CommitSeq, name: &str) -> StatementDiffRequest {
        StatementDiffRequest {
            selection: StatementSelection {
                definition: StatementDefinition::embedded(name).unwrap(),
                periods: vec!["FY2026-P03".into()],
                comparative: vec!["FY2025-P03".into()],
            },
            before,
            after: None,
        }
    }
    fn certify(&self, request: &StatementDiffRequest) -> CertifiedStatementDiff {
        self.book
            .certify_statement_diff(&self.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
            .unwrap()
            .unwrap()
    }
    fn replay(&self, certificate: &StatementDiffCertificate) -> StatementDiff {
        self.book
            .replay_statement_diff(&self.cx(), PRINCIPAL, &cap(&["read"]), certificate)
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
                Entropy::deterministic(98),
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

fn delta(diff: &StatementDiff, line: &str, unit: UnitId) -> Vec<i128> {
    diff.lines()
        .iter()
        .find(|l| l.code == line && l.unit_id == unit.0)
        .unwrap()
        .delta
        .clone()
}

#[test]
fn kernel_posted_two_frontier_bridge_certifies_replays_and_survives_reopen() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post(
        "late-expense",
        "2026-03-15",
        h.usd,
        ("expense", "cash"),
        15,
        false,
    );
    let after = h.head();
    let request = h.request(before, "balance-sheet");
    let certified = h.certify(&request);
    assert_eq!(certified.report.before().known_at, before.0);
    assert_eq!(certified.report.after().known_at, after.0);
    assert_eq!(delta(&certified.report, "assets", h.usd), vec![-15, 0]);
    assert_eq!(
        delta(&certified.report, "unclosed_expense", h.usd),
        vec![15, 0]
    );
    assert_eq!(delta(&certified.report, "assets", h.eur), vec![0, 0]);
    assert_eq!(certified.certificate.producer(), PRINCIPAL);
    assert_eq!(
        *certified.certificate.capability_commitment(),
        cap(&["read", "produce"]).commitment().unwrap()
    );
    assert_eq!(
        certified.certificate.output(),
        certified.report.canonical_bytes().unwrap()
    );
    let literal = h
        .book
        .statement_diff(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
        .unwrap()
        .unwrap();
    assert_eq!(literal, certified.report);
    let encoded = certified.certificate.canonical_bytes().unwrap();
    let decoded = StatementDiffCertificate::decode(&encoded).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(h.head(), after, "reading and certifying append nothing");
    let h = h.reopen();
    assert_eq!(h.replay(&decoded), certified.report);
    let (a, b) = decoded.sources();
    let reused = h
        .book
        .compare_statement_certificates(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), a, b)
        .unwrap()
        .unwrap();
    assert_eq!(reused.certificate, decoded);
    assert_eq!(h.head(), after);
}

#[test]
fn prior_year_adjustments_reach_stock_and_only_the_correct_activity_column() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post(
        "retroactive",
        "2025-03-20",
        h.usd,
        ("expense", "cash"),
        10,
        false,
    );
    h.post(
        "current",
        "2026-03-20",
        h.usd,
        ("expense", "cash"),
        15,
        false,
    );
    let bs = h.certify(&h.request(before, "balance-sheet"));
    assert_eq!(delta(&bs.report, "assets", h.usd), vec![-25, -10]);
    assert_eq!(delta(&bs.report, "unclosed_expense", h.usd), vec![25, 10]);
    let income = h.certify(&h.request(before, "income-statement"));
    let expense_line = income
        .report
        .before()
        .mappings
        .iter()
        .find(|m| m.account.id == h.id("expense").0)
        .unwrap()
        .line_code
        .clone();
    assert_eq!(delta(&income.report, &expense_line, h.usd), vec![15, 10]);
    assert_eq!(h.replay(&income.certificate), income.report);
    assert_eq!(h.replay(&bs.certificate), bs.report);
}

#[test]
fn pending_and_later_effective_entries_do_not_change_march_but_chart_membership_does() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post("pending", "2026-03-15", h.usd, ("cash", "capital"), 9, true);
    h.post(
        "future-effective",
        "2026-04-15",
        h.usd,
        ("cash", "capital"),
        20,
        false,
    );
    let unchanged = h.certify(&h.request(before, "balance-sheet"));
    assert!(unchanged.report.is_unchanged());
    let cx = h.cx();
    h.runtime
        .block_on(h.book.install_chart(
            &cx,
            &[account("unused", AccountType::EXPENSE)],
            PRINCIPAL,
            day("2026-04-20"),
            b"new-account",
        ))
        .unwrap()
        .unwrap();
    let changed = h.certify(&h.request(before, "balance-sheet"));
    assert!(!changed.report.amounts_changed());
    assert!(!changed.report.is_unchanged());
    assert_eq!(changed.report.mapping_changes().len(), 1);
    assert_eq!(
        changed.report.mapping_changes()[0].account_id,
        h.id("unused").0
    );
    assert_eq!(h.replay(&unchanged.certificate), unchanged.report);
    assert_eq!(h.replay(&changed.certificate), changed.report);
}

#[test]
fn repairing_an_outer_digest_cannot_substitute_valid_sources_or_false_deltas() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post(
        "change",
        "2026-03-15",
        h.usd,
        ("expense", "cash"),
        15,
        false,
    );
    let good = h.certify(&h.request(before, "balance-sheet"));
    let c = good.certificate;
    let mut false_output = c.output.clone();
    *false_output.last_mut().unwrap() ^= 1;
    let changed = StatementDiffCertificate::seal(
        c.before.clone(),
        c.after.clone(),
        c.producer,
        c.capability_commitment,
        false_output,
    )
    .unwrap();
    let wrong_before = StatementDiffCertificate::seal(
        c.after.clone(),
        c.after.clone(),
        c.producer,
        c.capability_commitment,
        c.output.clone(),
    )
    .unwrap();
    let wrong_after = StatementDiffCertificate::seal(
        c.before.clone(),
        c.before.clone(),
        c.producer,
        c.capability_commitment,
        c.output.clone(),
    )
    .unwrap();
    for fake in [changed, wrong_before, wrong_after] {
        let parsed = StatementDiffCertificate::decode(&fake.canonical_bytes().unwrap()).unwrap();
        let refusal = h
            .book
            .replay_statement_diff(&h.cx(), PRINCIPAL, &cap(&["read"]), &parsed)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(refusal.exit, exit::VERIFICATION);
    }
}

#[test]
fn malformed_container_or_either_corrupted_source_is_not_accepted() {
    let mut h = Harness::new();
    h.initial();
    let c = h.certify(&h.request(h.head(), "balance-sheet")).certificate;
    let bytes = c.canonical_bytes().unwrap();
    for end in [0, 1, 4, 20, bytes.len() / 2, bytes.len() - 1] {
        assert!(StatementDiffCertificate::decode(&bytes[..end]).is_err());
    }
    for at in [0, 4, bytes.len() / 2, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(StatementDiffCertificate::decode(&changed).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(StatementDiffCertificate::decode(&trailing).is_err());
    for old in [true, false] {
        let mut changed = c.clone();
        if old {
            changed.before.output_digest[0] ^= 1;
        } else {
            changed.after.output_digest[0] ^= 1;
        }
        assert!(changed.canonical_bytes().is_err());
    }
    assert!(total([MAX_STATEMENT_DIFF_CERTIFICATE_BYTES + 1]).is_err());
    assert!(total([usize::MAX, 1]).is_err());
}

#[test]
fn authorization_precedes_frontier_chart_and_certificate_observation() {
    let mut h = Harness::new();
    h.initial();
    let request = h.request(h.head(), "balance-sheet");
    let c = h.certify(&request).certificate;
    let cx = h.cx();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        h.id("cash"),
        property::POSTING,
        Some(CanonicalScalar::Int(1)),
        CanonicalScalar::Int(0),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let at = h.head();
    for ops in [&["post"][..], &["read"][..], &["produce"][..]] {
        let r = h
            .book
            .certify_statement_diff(&cx, PRINCIPAL, &cap(ops), &request)
            .unwrap()
            .unwrap_err();
        assert_eq!(r.code, fa_journal::refusal::code::CAPABILITY);
    }
    assert_eq!(
        h.book
            .statement_diff(&cx, PRINCIPAL, &cap(&["produce"]), &request)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    assert!(
        h.book
            .certify_statement_diff(&cx, VId(8), &cap(&["read", "produce"]), &request)
            .unwrap()
            .is_err()
    );
    assert_eq!(
        h.book
            .replay_statement_diff(&cx, PRINCIPAL, &cap(&["produce"]), &c)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    assert_eq!(
        h.book
            .compare_statement_certificates(&cx, PRINCIPAL, &cap(&["read"]), &c.before, &c.after)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    assert_eq!(h.head(), at);
}

#[test]
fn foreign_books_and_rewritten_history_cannot_replay_a_comparison() {
    let mut h = Harness::new();
    h.initial();
    let c = h.certify(&h.request(h.head(), "balance-sheet")).certificate;
    let other = Harness::in_book(Id128([0x62; 16]));
    assert_eq!(
        other
            .book
            .replay_statement_diff(&other.cx(), PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION
    );
    let cx = h.cx();
    let row = cx
        .query()
        .with_restriction(|| h.book.db.vertex(h.chart_entry))
        .unwrap()
        .unwrap();
    let original = fa_journal::rows::prop(&row, property::FA_PAYLOAD)
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
    assert!(!matches!(
        h.book
            .replay_statement_diff(&cx, PRINCIPAL, &cap(&["read"]), &c),
        Ok(Ok(_))
    ));
}

#[test]
fn future_reversed_and_changed_report_questions_refuse_without_writes() {
    let mut h = Harness::new();
    h.initial();
    let at = h.head();
    let good = h.certify(&h.request(at, "balance-sheet"));
    let mut future = h.request(at, "balance-sheet");
    future.after = Some(CommitSeq(at.0 + 1));
    let mut reversed = h.request(at, "balance-sheet");
    reversed.after = Some(CommitSeq(at.0 - 1));
    for bad in [future, reversed] {
        assert!(
            h.book
                .certify_statement_diff(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &bad)
                .unwrap()
                .is_err()
        );
    }
    let income = h.certify(&h.request(at, "income-statement"));
    assert!(
        h.book
            .compare_statement_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &good.certificate.before,
                &income.certificate.after
            )
            .unwrap()
            .is_err()
    );
    let mut same = h.request(at, "balance-sheet");
    same.after = Some(at);
    same.selection.periods.push("FY2026-P03".into());
    assert_eq!(h.certify(&same).certificate, good.certificate);
    assert_eq!(h.head(), at);
}

#[test]
fn replayed_workpapers_keep_exact_rows_and_do_not_drift_after_later_postings() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post(
        "workpaper-expense",
        "2026-03-15",
        h.usd,
        ("expense", "cash"),
        15,
        false,
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.book.install_chart(
            &cx,
            &[account("unposted", AccountType::EXPENSE)],
            PRINCIPAL,
            day("2026-03-20"),
            b"workpaper-chart",
        ))
        .unwrap()
        .unwrap();
    let certified = h.certify(&h.request(before, "balance-sheet"));
    let authority = cap(&["read", "produce"]);
    let first = h
        .book
        .statement_diff_workpaper(&cx, PRINCIPAL, &authority, &certified.certificate)
        .unwrap()
        .unwrap();
    assert_eq!(
        first.certificate_bytes(),
        certified.certificate.canonical_bytes().unwrap()
    );
    assert_eq!(
        first.jsonl().lines().count(),
        1 + certified.report.before().columns.len()
            + certified.report.lines().len()
            + certified.report.mapping_changes().len()
    );
    assert!(
        first
            .jsonl()
            .contains("\"delta_mantissas\":[\"-15\",\"0\"]")
    );
    assert!(first.jsonl().contains("\"event\":\"mapping_change\""));
    assert!(first.jsonl().contains("\"code\":\"unposted\""));
    assert!(first.markdown().contains("Account mapping changes"));
    assert!(first.markdown().contains("unposted"));
    assert!(first.markdown().contains("not an assertion of issuance"));
    assert!(first.markdown().contains("| 150 | 135 | -15 |"));
    let at = h.head();
    assert!(
        h.book
            .statement_diff_workpaper(&cx, PRINCIPAL, &cap(&["read"]), &certified.certificate)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    h.post(
        "after-workpaper",
        "2026-03-25",
        h.usd,
        ("cash", "sales"),
        17,
        false,
    );
    let again = h
        .book
        .statement_diff_workpaper(&cx, PRINCIPAL, &authority, &certified.certificate)
        .unwrap()
        .unwrap();
    assert_eq!(
        again, first,
        "a saved workpaper replays its original two prefixes"
    );
}

#[test]
fn workpaper_generation_never_discloses_an_unreplayable_comparison() {
    let mut h = Harness::new();
    h.initial();
    let c = h.certify(&h.request(h.head(), "balance-sheet")).certificate;
    let mut wrong = c.output.clone();
    *wrong.last_mut().unwrap() ^= 1;
    let fake = StatementDiffCertificate::seal(
        c.before,
        c.after,
        c.producer,
        c.capability_commitment,
        wrong,
    )
    .unwrap();
    let r = h
        .book
        .statement_diff_workpaper(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &fake)
        .unwrap()
        .unwrap_err();
    assert_eq!(r.exit, exit::VERIFICATION);
    assert_eq!(r.code, crate::certificate::code::CERTIFICATE_INVALID);
}
