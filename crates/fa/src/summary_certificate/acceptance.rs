//! Composed certificates over real kernel-posted books and retained native
//! read certificates. No planted payload is used as a positive accounting fact.

use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::symbols::{property, relation};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, Oid, Pending, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{MemVfs, WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;

use crate::{BookKeys, Entropy};

const BOOK: Id128 = Id128([0x59; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "summary-certificate-book";

fn day(value: &str) -> DateDay {
    DateDay::parse(value).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn keys() -> BookKeys {
    BookKeys::for_development(73)
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
    vfs: MemVfs,
    evidence: EvidenceRef,
    chart_entry: VId,
    usd: UnitId,
    eur: UnitId,
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
                    name: "Summary certificate fixture".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(73),
            ))
            .unwrap();
        let chart = [
            account("assets", None, false, false),
            account("cash", Some("assets"), true, false),
            account("receivable", Some("assets"), true, false),
            account("equity", None, false, true),
            account("capital", Some("equity"), true, true),
            account("unselected", None, true, false),
            account("empty", None, false, false),
        ];
        let installed = runtime
            .block_on(book.install_chart(
                &cx,
                &chart,
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
        for period in ["FY2026-P02", "FY2026-P03"] {
            runtime
                .block_on(book.transition_period(
                    &cx,
                    period,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
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
            bytes: b"summary certificate source invoice".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            evidence: document.evidence_ref(1),
            chart_entry: installed.control_entry,
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
    fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }

    fn request(&self, scope: SummaryScope, selection: TrialBalanceSelection) -> SummaryRequest {
        SummaryRequest {
            selection,
            scope,
            known_at: None,
        }
    }

    fn selected(&self, codes: &[&str]) -> SummaryScope {
        SummaryScope::Selected(codes.iter().map(|code| self.id(code)).collect())
    }

    fn post(&mut self, key: &str, date: &str, unit: UnitId, amount: i128, pending: bool) {
        let cx = self.cx();
        let legs = vec![
            LegPayload::simple(Side::Debit, self.id("cash"), Amount::new(unit, amount)),
            LegPayload::simple(Side::Credit, self.id("capital"), Amount::new(unit, amount)),
        ];
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
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
                intent_oid: Oid([1; 32]),
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

    fn certify(&self, request: &SummaryRequest) -> CertifiedSummaryTrialBalance {
        self.book
            .certify_summary_trial_balance(
                &self.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                request,
            )
            .unwrap()
            .unwrap()
    }

    fn replay(&self, certificate: &SummaryCertificate) -> SummaryTrialBalance {
        self.book
            .replay_summary_trial_balance(&self.cx(), PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap()
    }

    fn status(&self, certificate: &SummaryCertificate) -> SummaryCertificateStatus {
        self.book
            .summary_certificate_status(&self.cx(), PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap()
    }

    fn install_empty_root(&mut self) {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.install_chart(
                &cx,
                &[account("later-unposted", None, true, false)],
                PRINCIPAL,
                day("2026-03-31"),
                b"later-chart",
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
    }

    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            book,
            vfs,
            evidence,
            chart_entry,
            usd,
            eur,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                keys(),
                Entropy::deterministic(74),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            evidence,
            chart_entry,
            usd,
            eur,
        }
    }
}

fn march() -> TrialBalanceSelection {
    TrialBalanceSelection::AsOf(day("2026-03-31"))
}

#[test]
fn kernel_posted_summary_certificates_roundtrip_and_replay_exactly_after_reopen() {
    let mut h = Harness::new();
    h.post("usd", "2026-03-10", h.usd, 125, false);
    h.post("eur", "2026-03-11", h.eur, 73, false);
    h.post("pending", "2026-03-12", h.usd, 9, true);
    let at = h.head();
    let certified = h.certify(&h.request(SummaryScope::AllRoots, march()));
    assert!(certified.report.is_complete_and_balanced());
    assert_eq!(certified.report.unit_totals[&h.usd.0], (125, 125));
    assert_eq!(certified.report.unit_totals[&h.eur.0], (73, 73));
    assert_eq!(certified.report.pending_unit_totals[&h.usd.0], (9, 9));
    assert_eq!(certified.certificate.known_at(), at);
    assert_eq!(certified.certificate.book_id(), BOOK);
    assert_eq!(
        certified.certificate.output(),
        certified.report.canonical_bytes().unwrap()
    );
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let decoded = SummaryCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    assert_eq!(h.replay(&decoded), certified.report);
    assert!(
        matches!(h.status(&decoded), SummaryCertificateStatus::Current { checked_at } if checked_at == at)
    );
    assert_eq!(
        h.head(),
        at,
        "certification, replay and status never publish"
    );
    let h = h.reopen();
    assert_eq!(h.replay(&decoded), certified.report);
    assert_eq!(h.head(), at);
}

#[test]
fn period_stock_activity_and_inclusive_dates_keep_their_exact_source_selector() {
    let mut h = Harness::new();
    h.post("february", "2026-02-15", h.usd, 10, false);
    h.post("march", "2026-03-15", h.usd, 20, false);
    for (selection, expected) in [
        (
            TrialBalanceSelection::Periods(vec!["FY2026-P03".into()]),
            30,
        ),
        (
            TrialBalanceSelection::Activity(vec!["FY2026-P03".into(), "FY2026-P03".into()]),
            20,
        ),
        (TrialBalanceSelection::AsOf(day("2026-03-14")), 10),
        (TrialBalanceSelection::AsOf(day("2026-03-15")), 30),
    ] {
        let certified = h.certify(&h.request(SummaryScope::AllRoots, selection));
        assert_eq!(certified.report.unit_totals[&h.usd.0], (expected, expected));
        assert_eq!(h.replay(&certified.certificate), certified.report);
    }
    // An empty period list selects nothing: it is refused like every trial
    // balance selection, never read as "every period".
    assert!(
        h.book
            .certify_summary_trial_balance(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &h.request(
                    SummaryScope::AllRoots,
                    TrialBalanceSelection::Periods(Vec::new())
                ),
            )
            .is_err()
    );
}

#[test]
fn canonical_root_order_does_not_hide_partial_or_empty_coverage() {
    let h = Harness::new();
    let first = h.certify(&h.request(h.selected(&["assets", "equity"]), march()));
    let reversed = h.certify(&h.request(h.selected(&["equity", "assets"]), march()));
    assert_eq!(
        first.certificate.canonical_bytes().unwrap(),
        reversed.certificate.canonical_bytes().unwrap()
    );
    assert!(!first.report.is_complete());
    assert_eq!(first.report.uncovered_leaves.len(), 1);
    let all = h.certify(&h.request(SummaryScope::AllRoots, march()));
    let none = h.certify(&h.request(SummaryScope::Selected(Vec::new()), march()));
    let empty = h.certify(&h.request(h.selected(&["empty"]), march()));
    assert!(all.report.is_complete_and_balanced());
    assert!(none.report.groups.is_empty());
    assert!(!none.report.is_complete());
    assert!(empty.report.groups[0].leaves.is_empty());
    assert!(empty.report.groups[0].rows.is_empty());
    assert_ne!(all.certificate.digest(), none.certificate.digest());
    for certified in [first, all, none, empty] {
        assert_eq!(h.replay(&certified.certificate), certified.report);
    }
}

#[test]
fn later_relevant_postings_change_freshness_without_rewriting_the_historical_result() {
    let mut h = Harness::new();
    h.post("old", "2026-03-10", h.usd, 100, false);
    let certified = h.certify(&h.request(
        SummaryScope::AllRoots,
        TrialBalanceSelection::AsOf(day("2026-03-15")),
    ));
    let original = certified.certificate.canonical_bytes().unwrap();
    h.post("later-effective", "2026-03-20", h.usd, 30, false);
    assert!(matches!(
        h.status(&certified.certificate),
        SummaryCertificateStatus::Current { .. }
    ));
    h.post("retroactive", "2026-03-14", h.usd, 50, false);
    let at = h.head();
    let (checked_at, current) = match h.status(&certified.certificate) {
        SummaryCertificateStatus::Changed {
            checked_at,
            current,
        } => Some((checked_at, current)),
        _ => None,
    }
    .expect("the same effective selector includes the newly recorded posting");
    assert_eq!(checked_at, at);
    assert_eq!(current.source.known_at, at);
    assert_eq!(current.unit_totals[&h.usd.0], (150, 150));
    assert_eq!(h.replay(&certified.certificate), certified.report);
    assert_eq!(certified.certificate.canonical_bytes().unwrap(), original);
    assert_eq!(h.head(), at);
}

#[test]
fn a_chart_only_change_is_not_current_merely_because_money_totals_still_match() {
    let mut h = Harness::new();
    h.post("posting", "2026-03-10", h.usd, 100, false);
    let all = h.certify(&h.request(SummaryScope::AllRoots, march()));
    let partial = h.certify(&h.request(h.selected(&["assets", "equity"]), march()));
    h.install_empty_root();
    for certified in [all, partial] {
        let current = match h.status(&certified.certificate) {
            SummaryCertificateStatus::Changed { current, .. } => Some(current),
            _ => None,
        }
        .expect("new unposted chart membership must change the exact report");
        assert_eq!(current.unit_totals, certified.report.unit_totals);
        assert_eq!(
            current.pending_unit_totals,
            certified.report.pending_unit_totals
        );
        assert!(
            current
                .groups
                .iter()
                .any(|g| g.account.code == "later-unposted")
                || current
                    .uncovered_leaves
                    .iter()
                    .any(|a| a.code == "later-unposted")
        );
        assert_eq!(h.replay(&certified.certificate), certified.report);
    }
}

#[test]
fn resealing_false_output_or_rebound_scope_does_not_make_it_replayable() {
    let mut h = Harness::new();
    h.post("real", "2026-03-10", h.usd, 100, false);
    let certified = h.certify(&h.request(SummaryScope::AllRoots, march()));
    let mut wrong = certified.report.clone();
    let row = wrong
        .groups
        .iter_mut()
        .find(|g| g.account.code == "assets")
        .unwrap()
        .rows
        .iter_mut()
        .find(|row| row.unit_id == h.usd.0)
        .unwrap();
    row.debits = row.debits.checked_add(1).unwrap();
    let wrong_amount = SummaryCertificate::seal(
        certified.certificate.source.clone(),
        SummaryScope::AllRoots,
        wrong.canonical_bytes().unwrap(),
    )
    .unwrap();
    let rebound_scope = SummaryCertificate::seal(
        certified.certificate.source.clone(),
        h.selected(&["assets"]),
        certified.certificate.output.clone(),
    )
    .unwrap();
    let mut wrong_membership = certified.report.clone();
    wrong_membership
        .groups
        .iter_mut()
        .find(|g| g.account.code == "assets")
        .unwrap()
        .leaves
        .pop();
    let wrong_membership = SummaryCertificate::seal(
        certified.certificate.source.clone(),
        SummaryScope::AllRoots,
        wrong_membership.canonical_bytes().unwrap(),
    )
    .unwrap();
    let at = h.head();
    for fake in [wrong_amount, rebound_scope, wrong_membership] {
        // These artifacts have honest encodings and internally consistent
        // public digests. Only semantic replay can reject their false claim.
        let parsed = SummaryCertificate::decode(&fake.canonical_bytes().unwrap()).unwrap();
        let refusal = h
            .book
            .replay_summary_trial_balance(&h.cx(), PRINCIPAL, &cap(&["read"]), &parsed)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(refusal.exit, exit::VERIFICATION);
    }
    assert_eq!(h.head(), at);
}

#[test]
fn malformed_encoded_artifacts_and_corrupted_source_certificates_are_refused() {
    let h = Harness::new();
    let certified = h.certify(&h.request(SummaryScope::AllRoots, march()));
    let bytes = certified.certificate.canonical_bytes().unwrap();
    for at in [0, 4, bytes.len() / 2, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(SummaryCertificate::decode(&changed).is_err());
    }
    for end in [0, 1, 4, bytes.len() / 2, bytes.len() - 1] {
        assert!(SummaryCertificate::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(SummaryCertificate::decode(&trailing).is_err());
    let mut bad_source = certified.certificate.source.clone();
    bad_source.output_digest[0] ^= 1;
    assert!(
        SummaryCertificate::seal(
            bad_source,
            SummaryScope::AllRoots,
            certified.certificate.output.clone()
        )
        .is_err()
    );
}

#[test]
fn current_holder_read_and_produce_admission_precedes_even_a_corrupt_chart() {
    let mut h = Harness::new();
    let certified = h.certify(&h.request(SummaryScope::AllRoots, march()));
    let cx = h.cx();
    let mut damaged = WriteBatch::new(relation::CHILD_OF);
    damaged.compare_and_set_vertex_property(
        h.id("cash"),
        property::POSTING,
        Some(CanonicalScalar::Int(1)),
        CanonicalScalar::Int(0),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damaged))
        .unwrap();
    let at = h.head();
    let request = h.request(SummaryScope::AllRoots, march());
    for ops in [&["post"][..], &["read"][..], &["produce"][..]] {
        let refusal = h
            .book
            .certify_summary_trial_balance(&cx, PRINCIPAL, &cap(ops), &request)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
    }
    assert!(
        h.book
            .certify_summary_trial_balance(&cx, VId(8), &cap(&["read", "produce"]), &request)
            .unwrap()
            .is_err()
    );
    assert_eq!(
        h.book
            .replay_summary_trial_balance(
                &cx,
                PRINCIPAL,
                &cap(&["produce"]),
                &certified.certificate
            )
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    assert_eq!(
        h.book
            .summary_certificate_status(&cx, PRINCIPAL, &cap(&["produce"]), &certified.certificate)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    // The historical certificate is still reproducible, but today's damaged
    // chart is not a valid current report and cannot produce a Current status.
    assert_eq!(h.replay(&certified.certificate), certified.report);
    assert!(!matches!(
        h.book
            .summary_certificate_status(&cx, PRINCIPAL, &cap(&["read"]), &certified.certificate),
        Ok(Ok(_))
    ));
    assert_eq!(h.head(), at);
}

#[test]
fn summary_scope_admission_keeps_snapshot_reads_and_requires_head_for_certificates() {
    fn denied<T: std::fmt::Debug>(outcome: Outcome<T>, caveat: &str) {
        let refusal = outcome.unwrap().unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
        assert_eq!(refusal.exit, exit::SAFETY);
        assert!(refusal.message.contains(caveat), "{refusal:?}");
    }

    let mut h = Harness::new();
    h.post("retained", "2026-03-10", h.usd, 100, false);
    let pin = h.head();
    let mut request = h.request(h.selected(&["assets"]), march());
    request.known_at = Some(pin);
    let good = h.certify(&request);
    h.post("later", "2026-03-20", h.usd, 25, false);
    let head = h.head();
    assert!(head > pin);
    let cx = h.cx();
    let authority = cap(&["read", "produce"]);
    let admitted = authority
        .clone()
        .for_books(&[BOOK])
        .unwrap()
        .on_branch(Id128::TRUNK)
        .unwrap();
    let pinned = admitted.clone().known_at_most(pin);
    assert_eq!(
        h.book
            .summary_trial_balance(&cx, PRINCIPAL, &pinned, &request)
            .unwrap()
            .unwrap(),
        good.report
    );
    assert_eq!(
        h.book
            .certify_summary_trial_balance(&cx, PRINCIPAL, &admitted, &request)
            .unwrap()
            .unwrap(),
        good
    );
    assert_eq!(
        h.book
            .replay_summary_trial_balance(&cx, PRINCIPAL, &admitted, &good.certificate)
            .unwrap()
            .unwrap(),
        good.report
    );
    // Certificate generation/replay inspects current immutable-entry and
    // registry integrity; its selected report prefix is not its full reach.
    denied(
        h.book
            .certify_summary_trial_balance(&cx, PRINCIPAL, &pinned, &request),
        "known_at",
    );
    denied(
        h.book
            .replay_summary_trial_balance(&cx, PRINCIPAL, &pinned, &good.certificate),
        "known_at",
    );

    // Even selecting one root and one effective cutoff reads the full
    // native source, including uncovered leaves and retained input closure.
    for (caveat, scoped) in [
        (
            "accounts",
            authority.clone().for_accounts(&["assets"]).unwrap(),
        ),
        (
            "periods",
            authority.clone().for_periods(&["FY2026-P03"]).unwrap(),
        ),
        (
            "effective",
            authority.clone().effective_through(day("2026-03-31")),
        ),
        (
            "known_at",
            authority.clone().known_at_most(CommitSeq(pin.0 - 1)),
        ),
        (
            "branch",
            authority.clone().on_branch(Id128([0xd1; 16])).unwrap(),
        ),
        (
            "books",
            authority.clone().for_books(&[Id128([0xf1; 16])]).unwrap(),
        ),
    ] {
        denied(
            h.book
                .summary_trial_balance(&cx, PRINCIPAL, &scoped, &request),
            caveat,
        );
        denied(
            h.book
                .certify_summary_trial_balance(&cx, PRINCIPAL, &scoped, &request),
            caveat,
        );
        denied(
            h.book
                .replay_summary_trial_balance(&cx, PRINCIPAL, &scoped, &good.certificate),
            caveat,
        );
        denied(
            h.book
                .summary_certificate_status(&cx, PRINCIPAL, &scoped, &good.certificate),
            caveat,
        );
        let mut damaged = good.certificate.clone();
        damaged.source.output_digest[0] ^= 1;
        denied(
            h.book
                .replay_summary_trial_balance(&cx, PRINCIPAL, &scoped, &damaged),
            caveat,
        );
        denied(
            h.book
                .summary_certificate_status(&cx, PRINCIPAL, &scoped, &damaged),
            caveat,
        );
    }

    let mut at_head = request.clone();
    at_head.known_at = None;
    denied(
        h.book
            .summary_trial_balance(&cx, PRINCIPAL, &pinned, &at_head),
        "known_at",
    );
    denied(
        h.book
            .certify_summary_trial_balance(&cx, PRINCIPAL, &pinned, &at_head),
        "known_at",
    );
    denied(
        h.book
            .summary_certificate_status(&cx, PRINCIPAL, &pinned, &good.certificate),
        "known_at",
    );
    let mut damaged = good.certificate.clone();
    damaged.digest[0] ^= 1;
    // Freshness must judge its eventual HEAD read before attempting replay.
    denied(
        h.book
            .summary_certificate_status(&cx, PRINCIPAL, &pinned, &damaged),
        "known_at",
    );
    assert_eq!(
        h.book
            .replay_summary_trial_balance(&cx, PRINCIPAL, &admitted, &damaged)
            .unwrap()
            .unwrap_err()
            .code,
        crate::certificate::code::CERTIFICATE_INVALID
    );
    let mut moved = good.certificate.clone();
    moved.source.known_at = head;
    denied(
        h.book
            .replay_summary_trial_balance(&cx, PRINCIPAL, &pinned, &moved),
        "known_at",
    );
    let expired = h
        .book
        .summary_trial_balance(&cx, PRINCIPAL, &pinned.expiring_at(head), &request)
        .unwrap()
        .unwrap_err();
    assert_eq!(expired.code, "FA-REF-014");
    assert_eq!(expired.exit, exit::SAFETY);
    assert!(
        matches!(h.status(&good.certificate), SummaryCertificateStatus::Changed { checked_at, .. } if checked_at == head)
    );
    assert_eq!(h.head(), head);
}

#[test]
fn foreign_books_and_rewritten_journal_history_cannot_be_reported_as_current() {
    let mut h = Harness::new();
    let certified = h.certify(&h.request(SummaryScope::AllRoots, march()));
    let other = Harness::in_book(Id128([0x60; 16]));
    let refusal = other
        .book
        .replay_summary_trial_balance(
            &other.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &certified.certificate,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert!(refusal.message.contains("another book"));
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
        h.book.replay_summary_trial_balance(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &certified.certificate
        ),
        Ok(Ok(_))
    ));
    assert!(!matches!(
        h.book
            .summary_certificate_status(&cx, PRINCIPAL, &cap(&["read"]), &certified.certificate),
        Ok(Ok(_))
    ));
}
