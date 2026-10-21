//! fa-lantern against the real in-memory substrate: every first-slice
//! procedure finds exactly the anomalies planted in a small corpus and cites
//! only handles that resolve; rankings are deterministic under the witness
//! and a planted order-dependent ranking is not; the projections conserve
//! each entry's credits under the registered allocation law; the folds agree
//! with fa-reference's naive procedures over the same rows; the work
//! counters stay inside the registered bounds; registry binding refuses
//! unregistered or misversioned code. Every planted set is named beside the
//! corpus so the calibration manifest the test prints is auditable.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{Document, add_document};
use fa_journal::policy::{ApprovalRequest, Approved, record_approval};
use fa_journal::*;
use fa_lantern::aging::OpenItemsAging;
use fa_lantern::cutoff::PeriodBoundary;
use fa_lantern::digits::FirstDigit;
use fa_lantern::duplicates::{SameSameDifferent, SameSameSame};
use fa_lantern::graph::{RoundTrips, Structuring};
use fa_lantern::jet::{
    PeriodEndTiming, PostClosing, RoundAmounts, SelfApproved, ThinDescriptions, Weekend,
};
use fa_lantern::numbers::SequenceGaps;
use fa_lantern::projection::{documents, money_flow, preparers};
use fa_lantern::trace::{Law, Trace};
use fa_lantern::witness;
use fa_lantern::witness::determinism;
use fa_lantern::{
    Cite, Finding, LanternError, Params, Procedure, ProcedureRun, Severity, Snapshot, Statistic,
    Work, run, run_over,
};
use fa_model::{
    AccountType, ApprovalRef, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef,
    ExternalId, Id128, LegPayload, Oid, SealKey, SupersessionKind, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::lantern as naive;
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

#[path = "lantern/bank_reconciliation.rs"]
mod bank_reconciliation_tests;

#[path = "lantern/graph_arithmetic.rs"]
mod graph_arithmetic_tests;

#[path = "lantern/graph_units.rs"]
mod graph_unit_tests;

const PREPARER: VId = VId(7);
const REVIEWER: VId = VId(8);

fn day(y: i32, m: u8, d: u8) -> DateDay {
    DateDay::from_ymd(y, m, d).unwrap()
}

/// One corpus entry and what is planted in it.
#[derive(Clone)]
struct Spec {
    date: DateDay,
    document_date: Option<DateDay>,
    description: &'static str,
    legs: Vec<(&'static str, Side, i128)>,
    external_ids: Vec<(&'static str, &'static str)>,
    /// The preparer approves the proposal before posting (planted).
    self_approve: bool,
    /// A reviewer approves it (a control).
    review: bool,
    /// Posted under `post_softclosed` into a soft-closed period (planted).
    soft_closed: bool,
}

impl Spec {
    fn simple(date: DateDay, debit: &'static str, credit: &'static str, cents: i128) -> Self {
        Self {
            date,
            document_date: None,
            description: "ordinary transaction",
            legs: vec![(debit, Side::Debit, cents), (credit, Side::Credit, cents)],
            external_ids: Vec::new(),
            self_approve: false,
            review: false,
            soft_closed: false,
        }
    }
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    evidence: Vec<EvidenceRef>,
    next_key: u32,
    next_salt: u8,
    /// Posted corpus entries in order: `(vid, recorded_at)`.
    posted: Vec<(VId, CommitSeq)>,
}

impl Harness {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn account(&self, code: &str) -> VId {
        account_vid(self.book.book_id, code)
    }

    fn seal(&mut self, text: &str) -> Erasable<String> {
        self.next_salt = self.next_salt.wrapping_add(1);
        Erasable::seal(
            &text.to_string(),
            None,
            &self.book.seal_key,
            [self.next_salt; 32],
            [self.next_salt; 24],
        )
    }

    fn proposal(&mut self, spec: &Spec) -> EntryPayload {
        self.next_key += 1;
        let legs: Vec<LegPayload> = spec
            .legs
            .iter()
            .map(|(code, side, cents)| {
                LegPayload::simple(*side, self.account(code), Amount::new(self.usd, *cents))
            })
            .collect();
        let description = self.seal(spec.description);
        let mut external_ids = Vec::new();
        for (system, id) in &spec.external_ids {
            let id = self.seal(id);
            external_ids.push(ExternalId {
                system: (*system).to_string(),
                id,
            });
        }
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: spec.date,
            document_date: spec.document_date,
            description,
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: self.next_key.to_le_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: PREPARER,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids,
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn approve(&mut self, approver: VId, digest: [u8; 32]) -> ApprovalRef {
        let req = ApprovalRequest {
            capability: Capability::embedded(approver, &["approve"]).expect("approve"),
            approved_proposal_digest: digest,
            role: 0,
        };
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        match self
            .runtime
            .block_on(async move { record_approval(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("approval recorded")
        {
            Approved::Recorded { approval, .. } | Approved::AlreadyRecorded { approval, .. } => {
                approval
            }
        }
    }

    fn post(&mut self, spec: &Spec) -> VId {
        let proposal = self.proposal(spec);
        let digest = proposal.proposal_digest().expect("digest");
        let mut approvals = Vec::new();
        if spec.self_approve {
            approvals.push(self.approve(PREPARER, digest));
        }
        if spec.review {
            approvals.push(self.approve(REVIEWER, digest));
        }
        let ops: &[&str] = if spec.soft_closed {
            &["post", "post_softclosed"]
        } else {
            &["post"]
        };
        let req = PostRequest {
            proposal,
            approvals,
            plan_certificate: None,
            capability: Capability::embedded(PREPARER, ops).expect("ops"),
        };
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let outcome = self
            .runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("admitted");
        let (vid, recorded_at) = match outcome {
            Posted::Committed {
                entry_ref,
                recorded_at,
                ..
            } => Some((entry_ref.vid, recorded_at)),
            _ => None,
        }
        .expect("a fresh corpus entry commits");
        self.posted.push((vid, recorded_at));
        vid
    }

    fn transition(&mut self, period: &str, transition: PeriodTransition, key: &[u8]) {
        let description = self.seal("period transition");
        let ctx = self.ctx();
        self.runtime
            .block_on(async {
                transition_period(
                    &mut self.db,
                    &ctx,
                    &self.book,
                    period,
                    transition,
                    PREPARER,
                    1,
                    key,
                    description,
                    &Capability::embedded(PREPARER, &["close"]).expect("close"),
                    &[],
                )
                .await
            })
            .expect("kernel")
            .expect("transition admitted");
    }

    fn period_code(&self, date: DateDay) -> String {
        self.book
            .calendar
            .periods_for_year(date.year())
            .unwrap()
            .into_iter()
            .find(|p| p.contains(date) && p.kind == PeriodKind::Normal)
            .unwrap()
            .code
    }

    fn period_end(&self, date: DateDay) -> DateDay {
        self.book
            .calendar
            .periods_for_year(date.year())
            .unwrap()
            .into_iter()
            .find(|p| p.contains(date) && p.kind == PeriodKind::Normal)
            .unwrap()
            .end
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot::read(&self.db, &self.book, None, Some(day(2026, 4, 30))).expect("snapshot")
    }

    fn run(&self, p: &dyn Procedure) -> ProcedureRun {
        run(&self.db, &self.book, None, Some(day(2026, 4, 30)), p).expect("run")
    }

    fn index_of(&self, vid: VId) -> usize {
        self.posted
            .iter()
            .position(|(v, _)| *v == vid)
            .expect("a corpus entry")
    }

    /// The corpus index an entry citation names.
    fn entry_index(&self, c: &Cite) -> usize {
        match c {
            Cite::Entry(v) => Some(self.index_of(*v)),
            _ => None,
        }
        .expect("an entry citation")
    }

    /// The corpus indexes of a finding citing exactly two entries.
    fn entry_pair(&self, f: &Finding) -> (usize, usize) {
        match f.cites.as_slice() {
            [Cite::Entry(a), Cite::Entry(b)] => Some((self.index_of(*a), self.index_of(*b))),
            _ => None,
        }
        .expect("two entry citations")
    }

    /// The corpus indexes a run's findings cite as entries.
    fn cited_entries(&self, run: &ProcedureRun) -> BTreeSet<usize> {
        run.findings
            .iter()
            .flat_map(|f| f.cites.iter())
            .filter_map(|c| match c {
                Cite::Entry(v) => Some(self.index_of(*v)),
                _ => None,
            })
            .collect()
    }

    fn assert_cites_resolve(&self, run: &ProcedureRun) {
        for f in &run.findings {
            for c in &f.cites {
                assert!(
                    c.resolves(&self.db, &self.book, run.coordinate.known_at)
                        .expect("resolution read"),
                    "{}: citation {c:?} does not resolve",
                    run.procedure
                );
            }
        }
    }
}

fn harness() -> Harness {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x51; 32],
        DatabaseSecurityNamespaceId([0x52; 32]),
        [0x53; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([0x4c; 16]);
    let spec = BookSpec {
        book_id,
        name: "Lantern Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
        .expect("create_book");
    let book = BookContext {
        book_id,
        calendar,
        units,
        seal_key: SealKey([0x33; 32]),
        symbols,
    };
    let chart: Vec<AccountSpec> = [
        ("1000", "Cash", 1u8, 0u8),
        ("1010", "Bank B", 1, 0),
        ("1020", "Trust account", 1, 0),
        ("1200", "Receivables", 1, 0),
        ("2000", "Payables", 2, 1),
        ("4000", "Revenue", 4, 1),
        ("6000", "Rent", 5, 0),
        ("7000", "Utilities", 5, 0),
    ]
    .iter()
    .map(|(code, name, account_type, normal_balance)| AccountSpec {
        code: (*code).into(),
        name: (*name).into(),
        account_type: *account_type,
        normal_balance: *normal_balance,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    })
    .collect();
    let first = day(2026, 1, 1);
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PREPARER,
                first,
                b"chart",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
                &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
    runtime
        .block_on(async {
            create_periods(
                &mut db,
                &ctx,
                &book,
                2026,
                fgdb_types::VId(1),
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("periods")
        .expect("admitted");
    let source = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: b"INVOICE (lantern fixture source document)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
        .expect("kernel")
        .expect("admitted");
    let mut h = Harness {
        runtime,
        root,
        db,
        book,
        usd,
        evidence: vec![source.evidence_ref(1)],
        next_key: 0,
        next_salt: 10,
        posted: Vec::new(),
    };
    for (month, key) in [
        (1u8, &b"open-jan"[..]),
        (2, b"open-feb"),
        (3, b"open-mar"),
        (4, b"open-apr"),
    ] {
        let code = h.period_code(day(2026, month, 15));
        h.transition(&code, PeriodTransition::Open, key);
    }
    h
}

/// The planted corpus: thirty Original entries. 2026-01-01 is a Thursday,
/// so Jan 10 and Mar 28 are Saturdays and Mar 15 is a Sunday.
struct Corpus {
    specs: Vec<Spec>,
    round: BTreeSet<usize>,
    weekend: BTreeSet<usize>,
    period_end: BTreeSet<usize>,
    post_closing: BTreeSet<usize>,
    self_approved: BTreeSet<usize>,
    thin: BTreeSet<usize>,
    same_same_same: Vec<Vec<usize>>,
    same_same_different: Vec<(usize, usize)>,
    sequence_gap_missing: Vec<u64>,
    cutoff: BTreeSet<usize>,
    /// `(outbound, return)` round trips between asset accounts.
    round_trips: Vec<(usize, usize)>,
    /// `(payer, receiver, entries)` sub-threshold chains.
    structuring: Vec<(&'static str, &'static str, Vec<usize>)>,
    /// The commingled account and the tainted deposit for the tracing laws.
    trace: (&'static str, usize),
}

fn corpus() -> Corpus {
    let mut s = Vec::new();
    // 0: weekend (Saturday).
    s.push(Spec::simple(day(2026, 1, 10), "6000", "1000", 123_456));
    // 1: round (5,000.00 is a multiple of 1,000.00; both legs).
    s.push(Spec::simple(day(2026, 1, 14), "6000", "1000", 50_000_000));
    // 2: thin description.
    let mut thin = Spec::simple(day(2026, 1, 20), "7000", "1000", 8712);
    thin.description = "ok";
    s.push(thin);
    // 3: late in its period (Jan 30, one day before the last day).
    s.push(Spec::simple(day(2026, 1, 30), "6000", "1000", 99_999));
    // 4-6: an external sequence with 3 and 4 missing.
    for (i, (d, cents, id)) in [
        (3u8, 25_000, "INV-0001"),
        (5, 26_000, "INV-0002"),
        (9, 27_000, "INV-0005"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut e = Spec::simple(day(2026, 2, d), "7000", "2000", cents);
        e.external_ids = vec![("vendor", id)];
        let _ = i;
        s.push(e);
    }
    // 7, 8: same legs, same date; 9: same legs 13 days later.
    s.push(Spec::simple(day(2026, 2, 12), "6000", "1000", 125_000));
    s.push(Spec::simple(day(2026, 2, 12), "6000", "1000", 125_000));
    s.push(Spec::simple(day(2026, 2, 25), "6000", "1000", 125_000));
    // 10: a receivable (open item) in March.
    s.push(Spec::simple(day(2026, 3, 5), "1200", "4000", 10_000));
    // 11: cutoff — document dated in February, effective in March.
    let mut cut = Spec::simple(day(2026, 3, 20), "7000", "2000", 41_000);
    cut.document_date = Some(day(2026, 2, 27));
    s.push(cut);
    // 12: weekend (Saturday).
    s.push(Spec::simple(day(2026, 3, 28), "7000", "1000", 7330));
    // 13: an entry its preparer would have approved. The kernel refuses a
    // self-approval outright (SoD on every attached approval), so a
    // kernel-posted book never holds one and jet.self_approved finds none
    // here; the detector is for imported history. 14: reviewed (the control).
    let own = Spec::simple(day(2026, 3, 10), "6000", "1000", 30_000);
    s.push(own);
    let mut reviewed = Spec::simple(day(2026, 3, 11), "6000", "1000", 31_000);
    reviewed.review = true;
    s.push(reviewed);
    // 15: posted after March is soft-closed (the harness closes March
    // before posting it); Monday so it is not a weekend hit.
    let mut late = Spec::simple(day(2026, 3, 16), "7000", "1000", 4500);
    late.soft_closed = true;
    s.push(late);
    // 16, 17: older receivables for the aging buckets.
    s.push(Spec::simple(day(2026, 1, 8), "1200", "4000", 40_000));
    s.push(Spec::simple(day(2026, 2, 20), "1200", "4000", 5000));
    // 18, 19: value leaves Cash for Bank B and returns two days later in the
    // same amount (the kiting motif), mid-period.
    s.push(Spec::simple(day(2026, 2, 16), "1010", "1000", 275_500));
    s.push(Spec::simple(day(2026, 2, 18), "1000", "1010", 275_500));
    // 20, 21: the same motif returning six days before April's end.
    s.push(Spec::simple(day(2026, 4, 21), "1010", "1000", 133_700));
    s.push(Spec::simple(day(2026, 4, 24), "1000", "1010", 133_700));
    // 22-24: three receipts from one payer, each just under 10,000.00,
    // within four days (structuring).
    s.push(Spec::simple(day(2026, 2, 17), "1000", "4000", 950_100));
    s.push(Spec::simple(day(2026, 2, 19), "1000", "4000", 970_300));
    s.push(Spec::simple(day(2026, 2, 20), "1000", "4000", 990_700));
    // 25-29: a commingled trust account. Clean 600.00 opens it; the claimant
    // deposits 400.00 (26); 700.00 leaves; clean 300.00 arrives; 200.00
    // leaves. At Apr 30 the laws disagree: LIBR 300.00 (the lowest balance
    // after the deposit), FIFO 100.00, LIFO 0, pro rata 80.00.
    s.push(Spec::simple(day(2026, 4, 1), "1020", "4000", 60_000));
    s.push(Spec::simple(day(2026, 4, 2), "1020", "4000", 40_000));
    s.push(Spec::simple(day(2026, 4, 6), "6000", "1020", 70_000));
    s.push(Spec::simple(day(2026, 4, 7), "1020", "4000", 30_000));
    s.push(Spec::simple(day(2026, 4, 8), "6000", "1020", 20_000));
    Corpus {
        specs: s,
        round: [1].into(),
        weekend: [0, 12].into(),
        period_end: [3].into(),
        post_closing: [15].into(),
        self_approved: BTreeSet::new(),
        thin: [2].into(),
        same_same_same: vec![vec![7, 8]],
        same_same_different: vec![(7, 9), (8, 9)],
        sequence_gap_missing: vec![2],
        cutoff: [11].into(),
        round_trips: vec![(18, 19), (20, 21)],
        structuring: vec![("4000", "1000", vec![22, 23, 24])],
        trace: ("1020", 26),
    }
}

/// Post the corpus; March is soft-closed before entry 15.
fn posted_corpus() -> (Harness, Corpus) {
    let mut h = harness();
    let c = corpus();
    for (i, spec) in c.specs.iter().enumerate() {
        if i == 15 {
            let march = h.period_code(day(2026, 3, 15));
            h.transition(&march, PeriodTransition::SoftClose, b"soft-close-mar");
        }
        h.post(spec);
    }
    (h, c)
}

fn calibrate(name: &str, planted: &BTreeSet<usize>, found: &BTreeSet<usize>) {
    let tp = planted.intersection(found).count();
    println!(
        "calibration procedure={name} planted={} found={} tp={tp} precision={tp}/{} recall={tp}/{}",
        planted.len(),
        found.len(),
        found.len(),
        planted.len()
    );
    assert_eq!(
        found, planted,
        "{name}: found {found:?}, planted {planted:?}"
    );
}

#[test]
fn procedures_find_the_planted_anomalies_and_cite_only_resolving_handles() {
    let (h, c) = posted_corpus();
    let snapshot = h.snapshot();
    assert_eq!(
        snapshot.entries.iter().filter(|e| e.posts()).count(),
        c.specs.len()
    );
    let march = h.period_code(day(2026, 3, 15));
    assert!(
        snapshot.transitions[&march]
            .iter()
            .any(|t| t.to == fa_time::PeriodState::SoftClosed),
        "the soft close is in the snapshot's transition history"
    );

    let r = h.run(&RoundAmounts::new().unwrap());
    h.assert_cites_resolve(&r);
    calibrate("jet.round_amounts", &c.round, &h.cited_entries(&r));
    assert_eq!(
        r.findings[0].severity,
        Severity::Medium,
        "both legs are round"
    );
    assert_eq!(r.findings[0].statistic.value, 2);
    assert_eq!(r.findings[0].statistic.population, 2 * c.specs.len() as u64);
    assert_eq!(
        r.findings[0]
            .cites
            .iter()
            .filter(|c| matches!(c, Cite::Leg { .. }))
            .count(),
        2
    );
    assert_eq!(r.claim, fa_registry::procedures::Claim::Statistical);
    assert_eq!(r.evidence, "FA-EVID-L01");

    let r = h.run(&Weekend::new().unwrap());
    h.assert_cites_resolve(&r);
    calibrate("jet.weekend", &c.weekend, &h.cited_entries(&r));
    assert!(r.findings.iter().all(|f| f.statistic.value == 6));

    let r = h.run(&PeriodEndTiming::new().unwrap());
    h.assert_cites_resolve(&r);
    calibrate("jet.period_end_timing", &c.period_end, &h.cited_entries(&r));
    assert_eq!(r.findings[0].statistic.value, 1);

    let r = h.run(&PostClosing::new().unwrap());
    h.assert_cites_resolve(&r);
    calibrate("jet.post_closing", &c.post_closing, &h.cited_entries(&r));
    assert!(r.findings[0].narrative.contains("SoftClosed"));

    let r = h.run(&SelfApproved::new().unwrap());
    h.assert_cites_resolve(&r);
    calibrate("jet.self_approved", &c.self_approved, &h.cited_entries(&r));
    assert!(
        r.findings.is_empty(),
        "the kernel admits no self-approval to find"
    );

    let r = h.run(&ThinDescriptions::new().unwrap());
    h.assert_cites_resolve(&r);
    calibrate("jet.thin_descriptions", &c.thin, &h.cited_entries(&r));
    assert_eq!(r.findings[0].statistic.value, 2);

    let r = h.run(&SameSameSame::new().unwrap());
    h.assert_cites_resolve(&r);
    let groups: Vec<Vec<usize>> = r
        .findings
        .iter()
        .map(|f| f.cites.iter().map(|c| h.entry_index(c)).collect())
        .collect();
    println!(
        "calibration procedure=duplicates.same_same_same planted={:?} found={groups:?}",
        c.same_same_same
    );
    assert_eq!(groups, c.same_same_same);

    let r = h.run(&SameSameDifferent::new().unwrap());
    h.assert_cites_resolve(&r);
    let mut pairs: Vec<(usize, usize)> = r.findings.iter().map(|f| h.entry_pair(f)).collect();
    pairs.sort_unstable();
    println!(
        "calibration procedure=duplicates.same_same_different planted={:?} found={pairs:?}",
        c.same_same_different
    );
    assert_eq!(pairs, c.same_same_different);
    assert!(r.findings.iter().all(|f| f.statistic.value == 13));

    let r = h.run(&SequenceGaps::new().unwrap());
    h.assert_cites_resolve(&r);
    let missing: Vec<u64> = r
        .findings
        .iter()
        .map(|f| f.statistic.value as u64)
        .collect();
    println!(
        "calibration procedure=numbers.sequence_gaps planted={:?} found={missing:?}",
        c.sequence_gap_missing
    );
    assert_eq!(missing, c.sequence_gap_missing);
    assert_eq!(h.cited_entries(&r), [5, 6].into());
    assert!(
        !r.findings[0].narrative.contains("INV"),
        "an erasable id never reaches a narrative"
    );

    let r = h.run(&PeriodBoundary::new().unwrap());
    h.assert_cites_resolve(&r);
    calibrate("cutoff.period_boundary", &c.cutoff, &h.cited_entries(&r));
    assert_eq!(
        r.findings[0]
            .cites
            .iter()
            .filter(|c| matches!(c, Cite::Period(_)))
            .count(),
        2
    );
    assert_eq!(r.findings[0].statistic.value, 21);
}

#[test]
fn benford_claims_nothing_below_the_minimum_population_and_scores_above_it() {
    let (h, c) = posted_corpus();
    let legs = c.specs.len() as u64;
    let r = h.run(&FirstDigit::new().unwrap());
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].severity, Severity::Info);
    assert_eq!(r.findings[0].statistic.name, "population");
    assert_eq!(r.findings[0].statistic.population, legs);
    assert!(r.findings[0].narrative.contains("no conformity is claimed"));

    let params = Params::defaults(FirstDigit::ID)
        .unwrap()
        .set("min_population", 1)
        .unwrap();
    let r = h.run(&FirstDigit::with(params));
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.statistic.name, "mad");
    assert_eq!(f.statistic.scale, 9);
    assert_eq!(f.statistic.population, legs);
    assert!(
        f.cites.is_empty(),
        "a population statistic cites no single handle"
    );
    assert!(f.narrative.contains("chi-square"));
    // The same counts through the naive oracle give the same MAD.
    let rows = naive_rows(&h, &c);
    let counts = naive::first_digit_counts_for(&rows, h.usd.0, true);
    assert_eq!(counts.iter().sum::<u64>(), legs);
    assert_eq!(f.statistic.value, naive::benford_mad_1e9(&counts));
    assert_eq!(
        fa_lantern::digits::mad_1e9(&counts).unwrap(),
        f.statistic.value
    );
}

#[test]
fn aging_buckets_open_items_to_the_declared_date() {
    let (h, c) = posted_corpus();
    // Ages at 2026-04-30: entry 16 (Jan 8) 112 days, 17 (Feb 20) 69 days,
    // 10 (Mar 5) 56 days.
    let r = h.run(&OpenItemsAging::new().unwrap());
    h.assert_cites_resolve(&r);
    assert!(
        r.inputs.is_empty(),
        "the date is the coordinate, not an input"
    );
    assert_eq!(r.coordinate.effective_through, Some(day(2026, 4, 30)));
    let receivables = h.account("1200");
    let f = r
        .findings
        .iter()
        .find(|f| f.cites.first() == Some(&Cite::Account(receivables)))
        .expect("the receivables account is aged");
    assert_eq!(
        f.severity,
        Severity::High,
        "400.00 of 550.00 is older than 90 days"
    );
    assert_eq!(f.statistic.value, 40_000);
    assert_eq!(f.statistic.name, "open_past_90_days");
    assert!(
        f.narrative
            .contains("..=30: 0, ..=60: 10000, ..=90: 5000, older: 40000"),
        "{}",
        f.narrative
    );
    assert_eq!(
        f.cites.len(),
        2,
        "the account and the one leg older than the last edge"
    );
    // Nothing in the corpus is settled, so every leg is an open item and the
    // oracle for the finding count is the set of (account, side) pairs.
    let sides: BTreeSet<(String, bool)> = c
        .specs
        .iter()
        .flat_map(|s| {
            s.legs
                .iter()
                .map(|(code, side, _)| ((*code).to_string(), *side == Side::Debit))
        })
        .collect();
    assert_eq!(
        r.findings.len(),
        sides.len(),
        "one finding per account and side with an open leg"
    );
    assert!(
        r.findings
            .iter()
            .filter(|f| f.cites.first() != Some(&Cite::Account(receivables)))
            .all(|f| f.severity == Severity::Info
                || f.severity == Severity::Medium
                || f.severity == Severity::High)
    );
    // Bucket edges must ascend.
    let bad = Params::defaults(OpenItemsAging::ID)
        .unwrap()
        .set("bucket_2", 10)
        .unwrap();
    assert!(matches!(
        run(
            &h.db,
            &h.book,
            None,
            Some(day(2026, 4, 30)),
            &OpenItemsAging::with(bad)
        ),
        Err(LanternError::Parameter { .. })
    ));
    // Without a declared effective date there is no historical fold to age:
    // the refusal names the coordinate to declare.
    let err = run(&h.db, &h.book, None, None, &OpenItemsAging::new().unwrap())
        .expect_err("aging without an effective date is refused");
    assert!(
        matches!(&err, LanternError::Parameter { name, message, .. }
            if name == "effective_through" && message.contains("effective date")),
        "{err:?}"
    );
}

/// A deliberately order-dependent ranking under a registered id: the
/// determinism witness must reject it.
struct OrderDependent {
    params: Params,
}

impl Procedure for OrderDependent {
    fn id(&self) -> &'static str {
        "jet.weekend"
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        work.entry();
        let first = snapshot
            .entries
            .iter()
            .find(|e| e.posts())
            .expect("a posting");
        Ok(vec![Finding {
            procedure: "jet.weekend".into(),
            version: 1,
            severity: Severity::Low,
            statistic: Statistic::count("first", 0, 1),
            cites: vec![Cite::Entry(first.vid)],
            narrative: "whichever entry came first".into(),
        }])
    }
}

#[test]
fn rankings_are_deterministic_and_an_order_dependent_ranking_fails_the_witness() {
    let (h, _) = posted_corpus();
    let snapshot = h.snapshot();
    let procedures: Vec<Box<dyn Procedure>> = vec![
        Box::new(RoundAmounts::new().unwrap()),
        Box::new(PeriodEndTiming::new().unwrap()),
        Box::new(PostClosing::new().unwrap()),
        Box::new(Weekend::new().unwrap()),
        Box::new(SelfApproved::new().unwrap()),
        Box::new(ThinDescriptions::new().unwrap()),
        Box::new(SameSameSame::new().unwrap()),
        Box::new(SameSameDifferent::new().unwrap()),
        Box::new(SequenceGaps::new().unwrap()),
        Box::new(FirstDigit::with(
            Params::defaults(FirstDigit::ID)
                .unwrap()
                .set("min_population", 1)
                .unwrap(),
        )),
        Box::new(PeriodBoundary::new().unwrap()),
        Box::new(OpenItemsAging::new().unwrap()),
        Box::new(RoundTrips::new().unwrap()),
        Box::new(Structuring::new().unwrap()),
        Box::new(Trace::new(Law::Libr, h.account("1020"), h.posted[26].0).unwrap()),
        Box::new(Trace::new(Law::Fifo, h.account("1020"), h.posted[26].0).unwrap()),
        Box::new(Trace::new(Law::Lifo, h.account("1020"), h.posted[26].0).unwrap()),
        Box::new(Trace::new(Law::ProRata, h.account("1020"), h.posted[26].0).unwrap()),
    ];
    for p in &procedures {
        let w = determinism(&snapshot, &h.book, p.as_ref()).expect("witness");
        println!(
            "witness procedure={} digest={:02x?} deterministic={}",
            w.procedure,
            &w.digest[..4],
            w.deterministic()
        );
        assert!(w.deterministic(), "{w:?}");
        // A fresh read of the same coordinate reproduces the digest.
        let again = run(&h.db, &h.book, None, Some(day(2026, 4, 30)), p.as_ref()).unwrap();
        println!("{}", again.log_line());
        assert_eq!(again.findings_digest, w.digest);
        // Work stays inside the registered complexity bound.
        let row = fa_lantern::bind(p.id()).expect("registered row");
        assert!(
            again
                .work
                .within_registered_bound(&row.complexity, &snapshot),
            "{} ({}) exceeded bound: {:?}",
            again.procedure,
            row.complexity,
            again.work
        );
    }
    let planted = OrderDependent {
        params: Params::defaults("jet.weekend").unwrap(),
    };
    let w = determinism(&snapshot, &h.book, &planted).expect("witness runs");
    assert!(w.repeated, "two runs over one order agree");
    assert!(!w.entry_order, "reversing the stream changes the ranking");
    assert!(!w.deterministic());
}

#[test]
fn registry_binding_refuses_unregistered_misversioned_or_foreign_parameters() {
    struct Shape {
        id: &'static str,
        version: u16,
        params: Params,
    }
    impl Procedure for Shape {
        fn id(&self) -> &'static str {
            self.id
        }
        fn version(&self) -> u16 {
            self.version
        }
        fn params(&self) -> &Params {
            &self.params
        }
        fn run(
            &self,
            _: &Snapshot,
            _: &BookContext,
            _: &mut Work,
        ) -> Result<Vec<Finding>, LanternError> {
            Ok(Vec::new())
        }
    }
    let (h, _) = posted_corpus();
    let snapshot = h.snapshot();
    let weekend = Params::defaults("jet.weekend").unwrap();
    assert!(matches!(
        run_over(&snapshot, &h.book, &Shape { id: "graph.kiting", version: 1, params: weekend.clone() }),
        Err(LanternError::Unregistered { procedure }) if procedure == "graph.kiting"
    ));
    assert!(matches!(
        run_over(
            &snapshot,
            &h.book,
            &Shape {
                id: "jet.weekend",
                version: 2,
                params: weekend.clone()
            }
        ),
        Err(LanternError::Version {
            code: 2,
            registry: 1,
            ..
        })
    ));
    assert!(matches!(
        run_over(
            &snapshot,
            &h.book,
            &Shape {
                id: "jet.round_amounts",
                version: 1,
                params: weekend
            }
        ),
        Err(LanternError::Parameter { name, .. }) if name == "params"
    ));
    // A legitimate empty run still certifies.
    let ok = run_over(
        &snapshot,
        &h.book,
        &Shape {
            id: "jet.weekend",
            version: 1,
            params: Params::defaults("jet.weekend").unwrap(),
        },
    )
    .unwrap();
    assert!(ok.findings.is_empty());
    assert_eq!(ok.population, snapshot.entries.len() as u64);
}

#[test]
fn projections_conserve_credits_under_the_allocation_law() {
    let mut h = harness();
    let jan = h.period_code(day(2026, 1, 15));
    // 100.00 from Cash to Rent 30.00 and Utilities 70.00: exact shares.
    let mut a = Spec::simple(day(2026, 1, 12), "6000", "1000", 10_000);
    a.legs = vec![
        ("6000", Side::Debit, 3000),
        ("7000", Side::Debit, 7000),
        ("1000", Side::Credit, 10_000),
    ];
    h.post(&a);
    // 0.50 from Cash and 0.50 from Payables to Rent 0.33, Utilities 0.33,
    // Receivables 0.34. Since b6293c20 each credit is allocated by the
    // largest-remainder law against the *remaining* debit capacity, so both
    // margins conserve: every debit receives exactly its amount. (The old
    // independent per-credit split sent 17 + 17 cents into the 33-cent Rent
    // leg.) Which tie gets the odd cent follows account identity, so the
    // assertions below pin the margins and the one-cent bound, not the tie.
    let mut b = Spec::simple(day(2026, 1, 13), "6000", "1000", 100);
    b.legs = vec![
        ("6000", Side::Debit, 33),
        ("7000", Side::Debit, 33),
        ("1200", Side::Debit, 34),
        ("1000", Side::Credit, 50),
        ("2000", Side::Credit, 50),
    ];
    b.review = true;
    h.post(&b);
    let snapshot = h.snapshot();
    let flow = money_flow(&snapshot).unwrap();
    assert_eq!(flow.entries, 2);
    let edge = |from: &str, to: &str| {
        flow.edges
            .iter()
            .find(|e| e.from == h.account(from) && e.to == h.account(to))
            .map(|e| (e.mantissa, e.contributions, e.period.clone()))
    };
    // Entry a's exact shares, plus entry b's share within one cent of the
    // proportional 16.5/16.5/17 (largest remainder), on every pair.
    for (from, to, base, contributions) in [
        ("1000", "6000", 3000, 2),
        ("1000", "7000", 7000, 2),
        ("1000", "1200", 0, 1),
        ("2000", "6000", 0, 1),
        ("2000", "7000", 0, 1),
        ("2000", "1200", 0, 1),
    ] {
        let (mantissa, count, period) = edge(from, to).expect("an edge for every pair");
        assert!(
            (base + 16..=base + 17).contains(&mantissa),
            "{from}->{to}: {mantissa}"
        );
        assert_eq!(
            (count, period.as_str()),
            (contributions, jan.as_str()),
            "{from}->{to}"
        );
    }
    // Both margins conserve exactly: what each account credited, and what
    // each account was debited.
    let margin = |account: &str, outgoing: bool| -> i128 {
        flow.edges
            .iter()
            .filter(|e| {
                if outgoing {
                    e.from == h.account(account)
                } else {
                    e.to == h.account(account)
                }
            })
            .map(|e| e.mantissa)
            .sum()
    };
    assert_eq!(margin("1000", true), 10_000 + 50, "cash credited");
    assert_eq!(margin("2000", true), 50, "payables credited");
    assert_eq!(margin("6000", false), 3000 + 33, "rent debited");
    assert_eq!(margin("7000", false), 7000 + 33, "utilities debited");
    assert_eq!(margin("1200", false), 34, "receivables debited");
    let total: i128 = flow.edges.iter().map(|e| e.mantissa).sum();
    assert_eq!(
        total,
        10_000 + 100,
        "every credit cent lands on one debit account"
    );
    assert_eq!(
        money_flow(&snapshot.with_entries_reversed())
            .unwrap()
            .digest,
        flow.digest
    );

    let p = preparers(&snapshot).unwrap();
    assert_eq!(p.rows.len(), 5, "one row per (preparer, account, unit)");
    let rent = p
        .rows
        .iter()
        .find(|r| r.account == h.account("6000"))
        .unwrap();
    assert_eq!(
        (rent.principal, rent.debits, rent.credits, rent.entries),
        (PREPARER, 3033, 0, 2)
    );
    assert_eq!(p.approvals.len(), 1);
    assert_eq!(
        (
            p.approvals[0].approver,
            p.approvals[0].preparer,
            p.approvals[0].entries
        ),
        (REVIEWER, PREPARER, 1)
    );

    let d = documents(&snapshot).unwrap();
    assert_eq!(d.entries_without_evidence, 0);
    assert_eq!(d.rows.len(), 1);
    assert_eq!((d.rows[0].role, d.rows[0].entries), (1, 2));
    assert_eq!(d.rows[0].document, h.evidence[0].document_oid.0);
}

/// The corpus as fa-reference's naive procedures see it.
fn naive_rows(h: &Harness, c: &Corpus) -> Vec<naive::Row> {
    c.specs
        .iter()
        .enumerate()
        .map(|(index, s)| naive::Row {
            index,
            date: s.date,
            document_date: s.document_date,
            period: h.period_code(s.date),
            period_start: None,
            period_end: h.period_end(s.date),
            legs: s
                .legs
                .iter()
                .map(|(code, side, cents)| naive::Leg {
                    account: (*code).to_string(),
                    debit: *side == Side::Debit,
                    unit: h.usd.0,
                    scale: 2,
                    mantissa: *cents,
                })
                .collect(),
            preparer: "P7".into(),
            approvers: match (s.self_approve, s.review) {
                (true, _) => vec!["P7".into()],
                (false, true) => vec!["P8".into()],
                _ => Vec::new(),
            },
            description_chars: Some(s.description.chars().count()),
            external_ids: s
                .external_ids
                .iter()
                .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
                .collect(),
            recorded_after_close: s.soft_closed,
            reverses: None,
            replaces: None,
        })
        .collect()
}

#[test]
fn the_folds_agree_with_the_reference_oracle_on_the_same_rows() {
    let (h, c) = posted_corpus();
    let rows = naive_rows(&h, &c);
    let set = |v: Vec<usize>| -> BTreeSet<usize> { v.into_iter().collect() };

    let r = h.run(&RoundAmounts::new().unwrap());
    let naive_round: BTreeMap<usize, usize> = naive::round_amounts(&rows, 3).into_iter().collect();
    let lantern_round: BTreeMap<usize, usize> = r
        .findings
        .iter()
        .map(|f| (h.entry_index(&f.cites[0]), f.statistic.value as usize))
        .collect();
    assert_eq!(lantern_round, naive_round);

    assert_eq!(
        h.cited_entries(&h.run(&Weekend::new().unwrap())),
        set(naive::weekend(&rows))
    );
    assert_eq!(
        h.cited_entries(&h.run(&PeriodEndTiming::new().unwrap())),
        set(naive::period_end_timing(&rows, 3))
    );
    assert_eq!(
        h.cited_entries(&h.run(&PostClosing::new().unwrap())),
        set(naive::post_closing(&rows))
    );
    assert_eq!(
        h.cited_entries(&h.run(&SelfApproved::new().unwrap())),
        set(naive::self_approved(&rows))
    );
    assert_eq!(
        h.cited_entries(&h.run(&ThinDescriptions::new().unwrap())),
        set(naive::thin_descriptions(&rows, 4))
    );
    let r = h.run(&SameSameSame::new().unwrap());
    let groups: Vec<Vec<usize>> = r
        .findings
        .iter()
        .map(|f| f.cites.iter().map(|c| h.entry_index(c)).collect())
        .collect();
    assert_eq!(groups, naive::same_same_same(&rows));
    let r = h.run(&SameSameDifferent::new().unwrap());
    let mut pairs: Vec<(usize, usize)> = r.findings.iter().map(|f| h.entry_pair(f)).collect();
    pairs.sort_unstable();
    assert_eq!(pairs, naive::same_same_different(&rows, 30));
    let r = h.run(&SequenceGaps::new().unwrap());
    let gaps: Vec<u64> = r
        .findings
        .iter()
        .map(|f| f.statistic.value as u64)
        .collect();
    assert_eq!(
        gaps,
        naive::sequence_gaps(&rows)
            .into_iter()
            .map(|(_, m)| m)
            .collect::<Vec<_>>()
    );
    let period_of = |d: DateDay| h.period_code(d);
    assert_eq!(
        h.cited_entries(&h.run(&PeriodBoundary::new().unwrap())),
        set(naive::cutoff(&rows, &period_of))
    );
}

#[test]
fn graph_procedures_find_planted_round_trips_and_structuring_and_agree_with_the_oracle() {
    let (h, c) = posted_corpus();
    let rows = naive_rows(&h, &c);
    let codes = ["1000", "1010", "1200", "2000", "4000", "6000", "7000"];
    let code_of: BTreeMap<VId, &str> = codes.iter().map(|code| (h.account(code), *code)).collect();

    // Round trips: the two planted pairs, the near-period-end one scored High.
    let r = h.run(&RoundTrips::new().unwrap());
    h.assert_cites_resolve(&r);
    let planted: BTreeSet<usize> = c.round_trips.iter().flat_map(|(a, b)| [*a, *b]).collect();
    calibrate("graph.round_trips", &planted, &h.cited_entries(&r));
    let mut pairs: Vec<(usize, usize, Severity)> = r
        .findings
        .iter()
        .map(|f| {
            match f.cites.as_slice() {
                [
                    Cite::Entry(a),
                    Cite::Entry(b),
                    Cite::Account(_),
                    Cite::Account(_),
                ] => Some((h.index_of(*a), h.index_of(*b), f.severity)),
                _ => None,
            }
            .expect("two entries then the two accounts")
        })
        .collect();
    pairs.sort_unstable();
    assert_eq!(
        pairs,
        vec![(18, 19, Severity::Medium), (20, 21, Severity::High)]
    );
    for f in &r.findings {
        assert_eq!(f.statistic.name, "round_trip_mantissa");
        println!("round trip severity={} {}", f.severity.name(), f.narrative);
    }
    assert_eq!(
        pairs.iter().map(|(a, b, _)| (*a, *b)).collect::<Vec<_>>(),
        naive::round_trips(&rows, 5, &|code| code.starts_with('1'))
    );
    // Planted negative: a one-day window admits neither trip.
    let tight = RoundTrips::with(
        Params::defaults(RoundTrips::ID)
            .unwrap()
            .set("window_days", 1)
            .unwrap(),
    );
    assert!(h.run(&tight).findings.is_empty());

    // Structuring: the one planted chain, as the oracle sees it.
    let r = h.run(&Structuring::new().unwrap());
    h.assert_cites_resolve(&r);
    let planted: BTreeSet<usize> = c
        .structuring
        .iter()
        .flat_map(|(_, _, idx)| idx.iter().copied())
        .collect();
    calibrate("graph.structuring", &planted, &h.cited_entries(&r));
    let mut chains: Vec<(String, String, Vec<usize>)> = r
        .findings
        .iter()
        .map(|f| {
            match f.cites.as_slice() {
                [Cite::Account(to), Cite::Account(from), rest @ ..] => Some((
                    code_of[from].to_string(),
                    code_of[to].to_string(),
                    rest.iter().map(|c| h.entry_index(c)).collect::<Vec<_>>(),
                )),
                _ => None,
            }
            .expect("the receiving and paying accounts then the entries")
        })
        .collect();
    chains.sort();
    let expected: Vec<(String, String, Vec<usize>)> = c
        .structuring
        .iter()
        .map(|(from, to, idx)| ((*from).to_string(), (*to).to_string(), idx.clone()))
        .collect();
    assert_eq!(chains, expected);
    assert_eq!(chains, naive::structuring(&rows, 1_000_000, 800_000, 7, 3));
    let f = &r.findings[0];
    assert_eq!(f.statistic.name, "chain_mantissa");
    assert_eq!(f.statistic.value, 950_100 + 970_300 + 990_700);
    assert_eq!(
        f.severity,
        Severity::High,
        "three deposits sum past twice the threshold"
    );
    println!("structuring severity={} {}", f.severity.name(), f.narrative);
    // Planted negatives: a four-deposit minimum finds nothing; an inverted
    // floor is refused before any leg is read.
    let strict = Structuring::with(
        Params::defaults(Structuring::ID)
            .unwrap()
            .set("min_count", 4)
            .unwrap(),
    );
    assert!(h.run(&strict).findings.is_empty());
    let inverted = Structuring::with(
        Params::defaults(Structuring::ID)
            .unwrap()
            .set("floor", 1_000_000)
            .unwrap(),
    );
    assert!(matches!(
        run(&h.db, &h.book, None, Some(day(2026, 4, 30)), &inverted),
        Err(LanternError::Parameter { name, .. }) if name == "floor"
    ));
}

#[test]
fn tracing_laws_follow_the_planted_deposit_and_agree_with_the_oracle() {
    let (h, c) = posted_corpus();
    let rows = naive_rows(&h, &c);
    let (code, source) = c.trace;
    let account = h.account(code);
    let source_vid = h.posted[source].0;
    let claim = day(2026, 4, 30);
    let laws = [
        (Law::Libr, naive::TraceLaw::Libr, 30_000),
        (Law::Fifo, naive::TraceLaw::Fifo, 10_000),
        (Law::Lifo, naive::TraceLaw::Lifo, 0),
        (Law::ProRata, naive::TraceLaw::ProRata, 8_000),
    ];
    for (law, naive_law, expected) in laws {
        let r = h.run(&Trace::new(law, account, source_vid).unwrap());
        h.assert_cites_resolve(&r);
        assert_eq!(r.procedure, law.id());
        assert_eq!(
            r.inputs,
            vec![
                ("account".to_string(), format!("{:032x}", account.0)),
                ("source".to_string(), format!("{:032x}", source_vid.0)),
            ]
        );
        assert_eq!(r.findings.len(), 1, "one finding per run");
        let f = &r.findings[0];
        println!("trace law={} {}", law.name(), f.narrative);
        assert_eq!(f.statistic.name, "traced_mantissa");
        assert_eq!(
            f.statistic.value,
            expected,
            "{}: {}",
            law.name(),
            f.narrative
        );
        assert_eq!(
            f.severity,
            Severity::Info,
            "a tracing result is a computation"
        );
        assert_eq!(f.cites[0], Cite::Account(account));
        assert_eq!(f.cites[1], Cite::Entry(source_vid));
        let mut cited: Vec<usize> = f.cites[2..].iter().map(|c| h.entry_index(c)).collect();
        cited.sort_unstable();
        let (naive_traced, naive_carriers) = naive::trace(&rows, code, source, claim, naive_law);
        assert_eq!(f.statistic.value, naive_traced, "{}", law.name());
        assert_eq!(cited, naive_carriers, "{}", law.name());
    }
    // LIBR cites the withdrawal at which the balance bottomed; FIFO cites
    // both withdrawals; LIFO only the first; pro rata both.
    let cited = |law: Law| -> Vec<usize> {
        let r = h.run(&Trace::new(law, account, source_vid).unwrap());
        let mut v: Vec<usize> = r.findings[0].cites[2..]
            .iter()
            .map(|c| h.entry_index(c))
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(cited(Law::Libr), vec![27]);
    assert_eq!(cited(Law::Fifo), vec![27, 29]);
    assert_eq!(cited(Law::Lifo), vec![27]);
    assert_eq!(cited(Law::ProRata), vec![27, 29]);
    // Planted negatives: a source that never deposited into the account, an
    // unregistered intraday order, and a run without an effective date.
    let stranger = h.posted[0].0;
    let err = run(
        &h.db,
        &h.book,
        None,
        Some(claim),
        &Trace::new(Law::Libr, account, stranger).unwrap(),
    )
    .expect_err("a stranger entry is refused");
    assert!(
        matches!(&err, LanternError::Parameter { name, .. } if name == "source"),
        "{err:?}"
    );
    let value_date = Trace::with(
        Law::Fifo,
        Params::defaults(Law::Fifo.id())
            .unwrap()
            .set("intraday_order", 1)
            .unwrap(),
        account,
        source_vid,
    );
    assert!(matches!(
        run(&h.db, &h.book, None, Some(claim), &value_date),
        Err(LanternError::Parameter { name, .. }) if name == "intraday_order"
    ));
    assert!(matches!(
        run(
            &h.db,
            &h.book,
            None,
            None,
            &Trace::new(Law::ProRata, account, source_vid).unwrap()
        ),
        Err(LanternError::Parameter { name, .. }) if name == "effective_through"
    ));
    // Withdrawals-first and deposits-first orderings agree here, since no
    // two movements share a date; the claim date before the second
    // withdrawal changes every law's answer.
    let early = run(
        &h.db,
        &h.book,
        None,
        Some(day(2026, 4, 7)),
        &Trace::new(Law::Fifo, account, source_vid).unwrap(),
    )
    .unwrap();
    assert_eq!(early.findings[0].statistic.value, 30_000);
    assert_eq!(early.coordinate.effective_through, Some(day(2026, 4, 7)));
}

/// fa-jt7p defects 1 and 2, planted: same-day movements follow the recorded
/// (statement) order, never the entry identity hash; and a deposit into an
/// overdrawn account is traceable only above the overdraft. Every law
/// agrees with the oracle on both.
#[test]
fn tracing_follows_recorded_same_day_order_and_repays_an_overdraft_first() {
    let mut h = harness();
    let traced = |h: &Harness, law: Law, account: VId, source: VId, params: Option<Params>| {
        let procedure = match params {
            Some(p) => Trace::with(law, p, account, source),
            None => Trace::new(law, account, source).unwrap(),
        };
        let r = run(&h.db, &h.book, None, Some(day(2026, 3, 31)), &procedure).unwrap();
        println!("trace law={} {}", law.name(), r.findings[0].narrative);
        r.findings[0].statistic.value
    };
    let rows_of = |h: &Harness, specs: &[Spec]| -> Vec<naive::Row> {
        specs
            .iter()
            .enumerate()
            .map(|(index, spec)| naive::Row {
                index,
                date: spec.date,
                document_date: None,
                period: h.period_code(spec.date),
                period_start: None,
                period_end: h.period_end(spec.date),
                legs: spec
                    .legs
                    .iter()
                    .map(|(code, side, cents)| naive::Leg {
                        account: (*code).to_string(),
                        debit: *side == Side::Debit,
                        unit: 0,
                        scale: 2,
                        mantissa: *cents,
                    })
                    .collect(),
                preparer: String::new(),
                approvers: Vec::new(),
                description_chars: Some(0),
                external_ids: Vec::new(),
                recorded_after_close: false,
                reverses: None,
                replaces: None,
            })
            .collect()
    };

    // Same-day order on the trust account: clean opening money, then the
    // tainted deposit S and a withdrawal W recorded after it on one day.
    // Recorded order: S then W, so LIFO draws the deposit first.
    let ordered = vec![
        Spec::simple(day(2026, 3, 2), "1020", "4000", 100_000),
        Spec::simple(day(2026, 3, 9), "1020", "4000", 50_000),
        Spec::simple(day(2026, 3, 9), "6000", "1020", 60_000),
    ];
    let first = h.posted.len();
    for spec in &ordered {
        h.post(spec);
    }
    assert!(
        h.posted[first + 1].1 < h.posted[first + 2].1,
        "S is recorded before W"
    );
    let trust = h.account("1020");
    let source = h.posted[first + 1].0;
    let rows = rows_of(&h, &ordered);
    for (law, naive_law, expected) in [
        (Law::Libr, naive::TraceLaw::Libr, 50_000),
        (Law::Fifo, naive::TraceLaw::Fifo, 50_000),
        (Law::Lifo, naive::TraceLaw::Lifo, 0),
        (Law::ProRata, naive::TraceLaw::ProRata, 30_000),
    ] {
        let value = traced(&h, law, trust, source, None);
        assert_eq!(value, expected, "{}", law.name());
        let (naive_value, _) = naive::trace(&rows, "1020", 1, day(2026, 3, 31), naive_law);
        assert_eq!(value, naive_value, "{} vs the oracle", law.name());
    }
    // WithdrawalsFirst puts W before S on that day: every law then traces
    // the whole deposit.
    for law in [Law::Libr, Law::Fifo, Law::Lifo, Law::ProRata] {
        let params = Params::defaults(law.id())
            .unwrap()
            .set("intraday_order", 2)
            .unwrap();
        assert_eq!(
            traced(&h, law, trust, source, Some(params)),
            50_000,
            "{}",
            law.name()
        );
    }

    // An overdraft on bank B: 100.00 overdrawn, then a 500.00 deposit, then
    // a 1,000.00 deposit and a 700.00 withdrawal. Only 400.00 of the first
    // deposit ever sat in the account.
    let overdrawn = vec![
        Spec::simple(day(2026, 3, 3), "7000", "1010", 10_000),
        Spec::simple(day(2026, 3, 10), "1010", "4000", 50_000),
        Spec::simple(day(2026, 3, 11), "1010", "4000", 100_000),
        Spec::simple(day(2026, 3, 12), "6000", "1010", 70_000),
    ];
    let first = h.posted.len();
    for spec in &overdrawn {
        h.post(spec);
    }
    let bank = h.account("1010");
    let source = h.posted[first + 1].0;
    let rows = rows_of(&h, &overdrawn);
    // After the deposit: 400 tainted. The 1,000 deposit is clean. The 700
    // withdrawal: FIFO takes the 400 tainted then 300 clean; LIFO takes 700
    // clean; pro rata splits 700 by 400:1000 (200 tainted); LIBR's lowest
    // balance after the deposit is 400 + 1000 - 700 = 700, so it keeps 400.
    for (law, naive_law, expected) in [
        (Law::Libr, naive::TraceLaw::Libr, 40_000),
        (Law::Fifo, naive::TraceLaw::Fifo, 0),
        (Law::Lifo, naive::TraceLaw::Lifo, 40_000),
        (Law::ProRata, naive::TraceLaw::ProRata, 20_000),
    ] {
        let value = traced(&h, law, bank, source, None);
        assert_eq!(value, expected, "{}", law.name());
        let (naive_value, _) = naive::trace(&rows, "1010", 1, day(2026, 3, 31), naive_law);
        assert_eq!(value, naive_value, "{} vs the oracle", law.name());
    }
}

#[test]
fn the_catalog_builds_every_registered_procedure_and_refuses_what_it_cannot() {
    let (h, _) = posted_corpus();
    let rows = fa_lantern::catalog::registered().unwrap();
    assert_eq!(rows.len(), 60, "every registry row is listed");
    let mut ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), rows.len(), "ids are unique");
    let trust = h.account("1020");
    let source = h.posted[26].0;
    for row in &rows {
        let inputs = fa_lantern::catalog::Inputs {
            account: Some(trust),
            source: Some(source),
        };
        // Every registered row has an implementation in this build.
        let built = fa_lantern::catalog::build(&row.id, Params::defaults(&row.id).unwrap(), inputs)
            .expect("registered rows build");
        assert_eq!(built.id(), row.id, "{}", row.id);
        assert_eq!(built.version(), row.version, "{}", row.id);
        let r = if row.id == fa_lantern::bank_reconciliation::BankStatementDrift::ID {
            let snapshot = bank_reconciliation_tests::snapshot(&h, None, Some(day(2026, 4, 30)));
            run_over(&snapshot, &h.book, built.as_ref())
        } else {
            run(&h.db, &h.book, None, Some(day(2026, 4, 30)), built.as_ref())
        }
        .expect("every catalog procedure runs with its complete admitted input closure");
        h.assert_cites_resolve(&r);
        println!("catalog procedure={} findings={}", row.id, r.findings.len());
    }
    // A trace without its declared inputs is refused naming the input.
    let err = fa_lantern::catalog::build(
        "trace.libr",
        Params::defaults("trace.libr").unwrap(),
        fa_lantern::catalog::Inputs::default(),
    )
    .err()
    .expect("missing input is refused");
    assert!(
        matches!(&err, LanternError::Parameter { name, .. } if name == "account"),
        "{err:?}"
    );
    // An unregistered id is refused by the registry, not guessed.
    assert!(matches!(
        fa_lantern::catalog::build(
            "graph.kiting",
            Params::defaults("jet.weekend").unwrap(),
            fa_lantern::catalog::Inputs::default()
        ),
        Err(LanternError::Unregistered { .. })
    ));
}

#[allow(clippy::too_many_arguments)]
fn make_snapshot_entry(
    h: &mut Harness,
    vid: VId,
    recorded_at: CommitSeq,
    date: DateDay,
    period: &str,
    class: EntryClass,
    legs: Vec<(&str, Side, UnitId, i128)>,
    supersession: Vec<fa_model::Supersession>,
    effective_period: Option<fa_model::PeriodRef>,
    document_date: Option<DateDay>,
    origin: Option<EntryOrigin>,
    approvals: Vec<(VId, VId)>,
) -> fa_lantern::snapshot::SnapshotEntry {
    let mut proposal = h.proposal(&Spec::simple(date, "6000", "1000", 100));
    proposal.class = class;
    proposal.document_date = document_date;
    proposal.effective_period = effective_period;
    proposal.legs = legs
        .into_iter()
        .map(|(code, side, unit, mantissa)| {
            LegPayload::simple(side, h.account(code), Amount::new(unit, mantissa))
        })
        .collect();
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    proposal.supersession = supersession;
    if let Some(origin) = origin {
        proposal.origin = origin;
    }
    let entry = proposal.seal(Vec::new(), None).expect("seal entry");
    fa_lantern::snapshot::SnapshotEntry {
        vid,
        entry,
        recorded_at,
        period: period.to_string(),
        approvals,
    }
}

/// fa-vil6 items 1 & 3: supersession netting in tracing, projections, and
/// duplicate detection.
///
/// 1. Tainted deposit 500.00 on day 1, erroneous clean deposit 1,000.00 on
///    day 2, and its Reversal on day 3 (which reverses day 2's entry via
///    `SupersessionKind::Reverses` rather than acting as an independent third-
///    party withdrawal): all four tracing laws keep the full 500.00 tainted
///    balance (not 0), and projections (`money_flow`, `preparers`, `documents`)
///    exclude the reversed pair.
/// 2. An entry corrected via Reversal + Replacement (`SupersessionKind::Replaces`)
///    keeping the same legs is NOT flagged by `SameSameSame` or
///    `SameSameDifferent`, while two independent entries with the same legs ARE
///    flagged.
#[test]
fn supersession_netting_and_correction_lineage_exclusion() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = Some(day(2026, 1, 31));
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;
    let trust = h.account("1020");

    // E1: Tainted deposit 500.00 into Trust (1020) on Jan 2.
    let e1 = make_snapshot_entry(
        &mut h,
        VId(101),
        CommitSeq(10),
        day(2026, 1, 2),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1020", Side::Debit, usd, 50_000),
            ("4000", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    // E2: Erroneous clean deposit 1,000.00 into Trust (1020) on Jan 5.
    let e2 = make_snapshot_entry(
        &mut h,
        VId(102),
        CommitSeq(11),
        day(2026, 1, 5),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1020", Side::Debit, usd, 100_000),
            ("4000", Side::Credit, usd, 100_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    let e2_ref = fa_model::EntryRef {
        vid: e2.vid,
        entry_digest: e2.entry.entry_digest,
    };
    // E3: Reversal of E2 on Jan 6 (credits 1020 for 1,000.00). Without
    // supersession netting, FIFO/LIBR would treat E3 as a 1,000.00 withdrawal
    // that drains E1's 500.00 first!
    let e3 = make_snapshot_entry(
        &mut h,
        VId(103),
        CommitSeq(12),
        day(2026, 1, 6),
        &jan,
        EntryClass::REVERSAL,
        vec![
            ("4000", Side::Debit, usd, 100_000),
            ("1020", Side::Credit, usd, 100_000),
        ],
        vec![fa_model::Supersession {
            target: e2_ref,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }],
        None,
        None,
        None,
        Vec::new(),
    );
    // E4: Replacement of E2 on Jan 6 with the same legs on Cash (1000) instead
    // of Trust, plus E5 which replaces E4 on the same legs to test duplicate
    // correction-lineage exclusion.
    let e4 = make_snapshot_entry(
        &mut h,
        VId(104),
        CommitSeq(13),
        day(2026, 1, 10),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 25_000),
            ("1000", Side::Credit, usd, 25_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    let e4_ref = fa_model::EntryRef {
        vid: e4.vid,
        entry_digest: e4.entry.entry_digest,
    };
    let e5 = make_snapshot_entry(
        &mut h,
        VId(105),
        CommitSeq(14),
        day(2026, 1, 10),
        &jan,
        EntryClass::REPLACEMENT,
        vec![
            ("6000", Side::Debit, usd, 25_000),
            ("1000", Side::Credit, usd, 25_000),
        ],
        vec![fa_model::Supersession {
            target: e4_ref,
            kind: SupersessionKind::Replaces,
            reason_code: 1,
        }],
        None,
        None,
        None,
        Vec::new(),
    );
    snapshot.entries = vec![e1, e2, e3, e4, e5];

    let rows = vec![
        naive::Row {
            index: 0,
            date: day(2026, 1, 2),
            document_date: None,
            period: jan.clone(),
            period_start: None,
            period_end: day(2026, 2, 1),
            legs: vec![
                naive::Leg {
                    account: "1020".into(),
                    debit: true,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 50_000,
                },
                naive::Leg {
                    account: "4000".into(),
                    debit: false,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 50_000,
                },
            ],
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(10),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        },
        naive::Row {
            index: 1,
            date: day(2026, 1, 5),
            document_date: None,
            period: jan.clone(),
            period_start: None,
            period_end: day(2026, 2, 1),
            legs: vec![
                naive::Leg {
                    account: "1020".into(),
                    debit: true,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 100_000,
                },
                naive::Leg {
                    account: "4000".into(),
                    debit: false,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 100_000,
                },
            ],
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(10),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        },
        naive::Row {
            index: 2,
            date: day(2026, 1, 6),
            document_date: None,
            period: jan.clone(),
            period_start: None,
            period_end: day(2026, 2, 1),
            legs: vec![
                naive::Leg {
                    account: "4000".into(),
                    debit: true,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 100_000,
                },
                naive::Leg {
                    account: "1020".into(),
                    debit: false,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 100_000,
                },
            ],
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(10),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: Some(1),
            replaces: None,
        },
        naive::Row {
            index: 3,
            date: day(2026, 1, 10),
            document_date: None,
            period: jan.clone(),
            period_start: None,
            period_end: day(2026, 2, 1),
            legs: vec![
                naive::Leg {
                    account: "6000".into(),
                    debit: true,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 25_000,
                },
                naive::Leg {
                    account: "1000".into(),
                    debit: false,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 25_000,
                },
            ],
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(10),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        },
        naive::Row {
            index: 4,
            date: day(2026, 1, 10),
            document_date: None,
            period: jan,
            period_start: None,
            period_end: day(2026, 2, 1),
            legs: vec![
                naive::Leg {
                    account: "6000".into(),
                    debit: true,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 25_000,
                },
                naive::Leg {
                    account: "1000".into(),
                    debit: false,
                    unit: usd.0,
                    scale: 2,
                    mantissa: 25_000,
                },
            ],
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(10),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: Some(3),
        },
    ];

    for (law, naive_law) in [
        (Law::Libr, naive::TraceLaw::Libr),
        (Law::Fifo, naive::TraceLaw::Fifo),
        (Law::Lifo, naive::TraceLaw::Lifo),
        (Law::ProRata, naive::TraceLaw::ProRata),
    ] {
        let r = run_over(
            &snapshot,
            &h.book,
            &Trace::new(law, trust, VId(101)).unwrap(),
        )
        .unwrap();
        assert_eq!(r.findings[0].statistic.value, 50_000, "{}", law.name());
        let (naive_val, _) = naive::trace(&rows, "1020", 0, day(2026, 1, 31), naive_law);
        assert_eq!(r.findings[0].statistic.value, naive_val);
    }

    // Projections fold only live postings (E1 and E5; E2+E3 reversed, E4 replaced).
    let flow = money_flow(&snapshot).unwrap();
    assert_eq!(flow.entries, 2);
    let total: i128 = flow.edges.iter().map(|e| e.mantissa).sum();
    assert_eq!(total, 50_000 + 25_000);

    // Duplicates: E4 and E5 share supersession lineage (E5 replaces E4), so
    // neither SameSameSame nor SameSameDifferent flags them.
    let sss = run_over(&snapshot, &h.book, &SameSameSame::new().unwrap()).unwrap();
    assert!(sss.findings.is_empty());
    assert!(naive::same_same_same(&rows).is_empty());
    let ssd = run_over(&snapshot, &h.book, &SameSameDifferent::new().unwrap()).unwrap();
    assert!(ssd.findings.is_empty());
    assert!(naive::same_same_different(&rows, 30).is_empty());
}

/// fa-vil6 item 2: Benford's first-digit test samples one side (Debit default)
/// of one currency (USD = 840 default) so a two-leg double-entry posting is
/// counted once, never twice, and foreign currencies / share quantities are not
/// pooled into the USD population.
#[test]
fn benford_samples_one_side_and_one_currency_without_double_counting() {
    let mut h = harness();
    let jpy = h.book.units.lookup("JPY").unwrap();
    let shares = h.book.units.lookup("SHARE").unwrap();

    let mut snapshot = h.snapshot();
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;

    // 1 USD entry (2 legs: 1 debit, 1 credit), 1 JPY entry (2 legs), 1 SHARE entry (2 legs).
    let e_usd = make_snapshot_entry(
        &mut h,
        VId(201),
        CommitSeq(20),
        day(2026, 1, 10),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 12_345),
            ("1000", Side::Credit, usd, 12_345),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    let e_jpy = make_snapshot_entry(
        &mut h,
        VId(202),
        CommitSeq(21),
        day(2026, 1, 11),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, jpy, 900_000),
            ("1000", Side::Credit, jpy, 900_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    let e_shares = make_snapshot_entry(
        &mut h,
        VId(203),
        CommitSeq(22),
        day(2026, 1, 12),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, shares, 500),
            ("1000", Side::Credit, shares, 500),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    snapshot.entries = vec![e_usd, e_jpy, e_shares];

    // Default (USD = 840, side = 0 Debit): population is 1 (not 2, not 6).
    let r_usd = run_over(
        &snapshot,
        &h.book,
        &FirstDigit::with(
            Params::defaults(FirstDigit::ID)
                .unwrap()
                .set("min_population", 1)
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(r_usd.findings[0].statistic.population, 1);

    // JPY = 392, side = 1 Credit: population is 1 (the JPY credit leg).
    let r_jpy = run_over(
        &snapshot,
        &h.book,
        &FirstDigit::with(
            Params::defaults(FirstDigit::ID)
                .unwrap()
                .set("min_population", 1)
                .unwrap()
                .set("currency_iso4217", 392)
                .unwrap()
                .set("side", 1)
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(r_jpy.findings[0].statistic.population, 1);
}

/// fa-vil6 item 4: cutoff.period_boundary honors `effective_period` when a
/// document is dated on the civil date shared by a normal year-end period and
/// an adjustment period (`FY2026-A1`).
#[test]
fn cutoff_honors_effective_period_discriminator_in_adjustment_periods() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    // Ensure FY2026-A1 is in the snapshot's period map (created by create_periods(2026)).
    assert!(snapshot.periods.contains_key("FY2026-A1"));
    let usd = h.usd;
    let adj_ref = fa_model::PeriodRef {
        calendar: "cal".into(),
        code: "FY2026-A1".into(),
    };

    // Entry 1: Adjusting entry in FY2026-A1 dated 2026-12-31 with document_date
    // 2026-12-31 -> same period (`FY2026-A1`), NOT a cutoff mismatch!
    let e_same = make_snapshot_entry(
        &mut h,
        VId(301),
        CommitSeq(30),
        day(2026, 12, 31),
        "FY2026-A1",
        EntryClass::ADJUSTING,
        vec![
            ("6000", Side::Debit, usd, 10_000),
            ("2000", Side::Credit, usd, 10_000),
        ],
        Vec::new(),
        Some(adj_ref.clone()),
        Some(day(2026, 12, 31)),
        None,
        Vec::new(),
    );
    // Entry 2: Adjusting entry in FY2026-A1 dated 2026-12-31 with document_date
    // 2026-11-28 (`FY2026-P11`) -> cross-period cutoff finding!
    let e_cross = make_snapshot_entry(
        &mut h,
        VId(302),
        CommitSeq(31),
        day(2026, 12, 31),
        "FY2026-A1",
        EntryClass::ADJUSTING,
        vec![
            ("6000", Side::Debit, usd, 20_000),
            ("2000", Side::Credit, usd, 20_000),
        ],
        Vec::new(),
        Some(adj_ref),
        Some(day(2026, 11, 28)),
        None,
        Vec::new(),
    );
    snapshot.entries = vec![e_same, e_cross];

    let r = run_over(&snapshot, &h.book, &PeriodBoundary::new().unwrap()).unwrap();
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].cites[0], Cite::Entry(VId(302)));
}

/// fa-vil6 item 5: graph.round_trips matches each outbound transfer and each
/// return transfer at most once (earliest unmatched return in the window), and
/// runs in O(L log L).
#[test]
fn round_trips_matches_one_to_one_without_reusing_endpoints() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;

    // 1 outbound transfer (1000 -> 1010 on Jan 10) followed by 2 returns
    // (1010 -> 1000 on Jan 11 and Jan 12) in the same amount.
    let e_out = make_snapshot_entry(
        &mut h,
        VId(401),
        CommitSeq(40),
        day(2026, 1, 10),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1010", Side::Debit, usd, 50_000),
            ("1000", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    let e_ret1 = make_snapshot_entry(
        &mut h,
        VId(402),
        CommitSeq(41),
        day(2026, 1, 11),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 50_000),
            ("1010", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    let e_ret2 = make_snapshot_entry(
        &mut h,
        VId(403),
        CommitSeq(42),
        day(2026, 1, 12),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 50_000),
            ("1010", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    snapshot.entries = vec![e_out, e_ret1, e_ret2];

    let r = run_over(&snapshot, &h.book, &RoundTrips::new().unwrap()).unwrap();
    assert_eq!(
        r.findings.len(),
        1,
        "one outbound transfer can be returned at most once"
    );
    assert_eq!(r.findings[0].cites[0], Cite::Entry(VId(401)));
    assert_eq!(r.findings[0].cites[1], Cite::Entry(VId(402)));
}

/// fa-vil6 item 6: jet.self_approved positively detects both a snapshot entry
/// carrying a self-approval vertex and a migrated entry (`EntryOrigin::Migration`)
/// whose `source_entered_by` and `source_approved_by` match.
#[test]
fn self_approved_detects_migrated_and_snapshot_self_approvals() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;

    let alice_entered = h.seal("alice@legacy.example");
    let alice_approved = h.seal("alice@legacy.example");
    let bob_approved = h.seal("bob@legacy.example");
    let mig1_id = h.seal("MIG-1");
    let mig2_id = h.seal("MIG-2");

    // 1. Migrated entry where alice both entered and approved in the source system.
    let e_mig_self = make_snapshot_entry(
        &mut h,
        VId(501),
        CommitSeq(50),
        day(2026, 1, 10),
        &jan,
        EntryClass::MIGRATION,
        vec![
            ("6000", Side::Debit, usd, 10_000),
            ("1000", Side::Credit, usd, 10_000),
        ],
        Vec::new(),
        None,
        None,
        Some(EntryOrigin::Migration {
            run_ref: VId(900),
            source_system: "legacy_erp".into(),
            source_id: mig1_id,
            source_recorded_at_ns: None,
            source_entered_by: Some(alice_entered.clone()),
            source_approved_by: Some(alice_approved),
            batch_oid: Oid([9; 32]),
        }),
        Vec::new(),
    );
    // 2. Migrated entry where alice entered and bob approved (control: clean).
    let e_mig_clean = make_snapshot_entry(
        &mut h,
        VId(502),
        CommitSeq(51),
        day(2026, 1, 11),
        &jan,
        EntryClass::MIGRATION,
        vec![
            ("6000", Side::Debit, usd, 10_000),
            ("1000", Side::Credit, usd, 10_000),
        ],
        Vec::new(),
        None,
        None,
        Some(EntryOrigin::Migration {
            run_ref: VId(900),
            source_system: "legacy_erp".into(),
            source_id: mig2_id,
            source_recorded_at_ns: None,
            source_entered_by: Some(alice_entered),
            source_approved_by: Some(bob_approved),
            batch_oid: Oid([9; 32]),
        }),
        Vec::new(),
    );
    // 3. Snapshot entry whose approval list names its own preparer (PREPARER).
    let e_snap_self = make_snapshot_entry(
        &mut h,
        VId(503),
        CommitSeq(52),
        day(2026, 1, 12),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 10_000),
            ("1000", Side::Credit, usd, 10_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        vec![(VId(901), PREPARER)],
    );
    snapshot.entries = vec![e_mig_self, e_mig_clean, e_snap_self];

    let r = run_over(&snapshot, &h.book, &SelfApproved::new().unwrap()).unwrap();
    let cited: Vec<VId> = r
        .findings
        .iter()
        .map(|f| match &f.cites[0] {
            Cite::Entry(v) => *v,
            other => panic!("expected entry cite, got {other:?}"),
        })
        .collect();
    assert_eq!(cited, vec![VId(501), VId(503)]);
}

/// fa-vil6 item 7: complexity witness across 10^2, 10^3, and 10^4 entry corpora
/// verifies that every procedure's work counters obey its registered asymptotic
/// complexity in `registries/procedures.toml`.
#[test]
fn complexity_witness_holds_across_100_1000_and_10000_entries() {
    let mut h = harness();
    let base = h.snapshot();
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;
    let desc = h.seal("synthetic scale entry");
    let legs = vec![
        LegPayload::simple(Side::Debit, h.account("1010"), Amount::new(usd, 12_345)),
        LegPayload::simple(Side::Credit, h.account("1000"), Amount::new(usd, 12_345)),
    ];
    let totals = EntryPayload::fold_unit_totals(&legs).unwrap();
    let template_proposal = EntryPayload {
        schema_minor: 0,
        book_id: h.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(2026, 1, 15),
        document_date: Some(day(2026, 1, 15)),
        description: desc,
        effective_period: None,
        unit_totals: totals,
        legs,
        control: None,
        base_totals: None,
        idempotency_key: vec![1, 2, 3, 4],
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: PREPARER,
        session_ref: None,
        evidence: h.evidence.clone(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let template_entry = template_proposal.seal(Vec::new(), None).unwrap();

    for scale in [100usize, 1_000, 10_000] {
        let mut snapshot = base.clone();
        snapshot.entries = (0..scale)
            .map(|i| {
                let mut entry = template_entry.clone();
                // Vary amounts and dates so buckets are realistic while keeping
                // construction fast across 10,000 entries.
                let amount = 10_000 + (i as i128 % 97) * 100;
                entry.proposal.effective_date = day(2026, 1, 1 + (i % 28) as u8);
                entry.proposal.legs[0].amount = Amount::new(usd, amount);
                entry.proposal.legs[1].amount = Amount::new(usd, amount);
                fa_lantern::snapshot::SnapshotEntry {
                    vid: VId(10_000 + i as u128),
                    entry,
                    recorded_at: CommitSeq(100 + i as u64),
                    period: jan.clone(),
                    approvals: Vec::new(),
                }
            })
            .collect();

        let procedures: Vec<Box<dyn Procedure>> = vec![
            Box::new(RoundAmounts::new().unwrap()),
            Box::new(PeriodEndTiming::new().unwrap()),
            Box::new(PostClosing::new().unwrap()),
            Box::new(Weekend::new().unwrap()),
            Box::new(SelfApproved::new().unwrap()),
            Box::new(ThinDescriptions::new().unwrap()),
            Box::new(SameSameSame::new().unwrap()),
            Box::new(SameSameDifferent::new().unwrap()),
            Box::new(SequenceGaps::new().unwrap()),
            Box::new(FirstDigit::new().unwrap()),
            Box::new(PeriodBoundary::new().unwrap()),
            Box::new(RoundTrips::new().unwrap()),
            Box::new(Structuring::new().unwrap()),
            Box::new(Trace::new(Law::Libr, h.account("1010"), VId(10_000)).unwrap()),
        ];

        for p in &procedures {
            let run = run_over(&snapshot, &h.book, p.as_ref()).unwrap();
            let row = fa_lantern::bind(p.id()).unwrap();
            assert!(
                run.work.within_registered_bound(&row.complexity, &snapshot),
                "scale={scale} procedure={} complexity='{}' work={:?}",
                run.procedure,
                row.complexity,
                run.work
            );
        }
    }
}

#[test]
fn fa_gen_labeled_scenario_corpora_calibrate_lantern_procedures() {
    use fa_gen::{GenConfig, ScenarioKind, generate};

    for scenario in ScenarioKind::ALL {
        let corpus = generate(GenConfig::new(scenario, 7));
        let runtime = RuntimeBuilder::new().build().expect("runtime");
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [0x61; 32],
            DatabaseSecurityNamespaceId([0x62; 32]),
            [0x63; 32],
        );
        let mut db = runtime
            .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
            .expect("open_memory");
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let mut book_id_bytes = [0u8; 16];
        book_id_bytes[0] = scenario.tag();
        let book_id = Id128(book_id_bytes);
        let spec = BookSpec {
            book_id,
            name: corpus.book_name.clone(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
            .expect("create_book");
        let book = BookContext {
            book_id,
            calendar,
            units,
            seal_key: SealKey([0x33; 32]),
            symbols,
        };
        let chart: Vec<AccountSpec> = corpus
            .accounts
            .iter()
            .map(|a| AccountSpec {
                code: a.code.clone(),
                name: a.name.clone(),
                account_type: a.account_type,
                normal_balance: a.normal_balance,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            })
            .collect();
        let jan1 = day(corpus.fiscal_year, 1, 1);
        let chart_desc = Erasable::seal(
            &"gen-chart".to_string(),
            None,
            &book.seal_key,
            [9; 32],
            [9; 24],
        );
        runtime
            .block_on(async {
                install_chart(
                    &mut db,
                    &ctx,
                    &book,
                    &chart,
                    PREPARER,
                    jan1,
                    b"gen-chart",
                    chart_desc,
                    &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("install_chart")
            .expect("chart admitted");
        let (_, periods) = runtime
            .block_on(async {
                create_periods(
                    &mut db,
                    &ctx,
                    &book,
                    corpus.fiscal_year,
                    fgdb_types::VId(1),
                    fa_model::Erasable::seal(
                        &"periods".to_string(),
                        None,
                        &book.seal_key,
                        [1; 32],
                        [2; 24],
                    ),
                    &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"])
                        .unwrap(),
                )
                .await
            })
            .expect("create_periods")
            .expect("admitted");
        for (idx, p) in periods
            .iter()
            .filter(|p| p.kind == fa_time::PeriodKind::Normal)
            .enumerate()
        {
            let desc = Erasable::seal(
                &"open".to_string(),
                None,
                &book.seal_key,
                [idx as u8; 32],
                [idx as u8; 24],
            );
            runtime
                .block_on(async {
                    transition_period(
                        &mut db,
                        &ctx,
                        &book,
                        &p.code,
                        PeriodTransition::Open,
                        PREPARER,
                        1,
                        format!("open-{}", p.code).as_bytes(),
                        desc,
                        &Capability::embedded(PREPARER, &["close"]).unwrap(),
                        &[],
                    )
                    .await
                })
                .unwrap()
                .unwrap();
        }
        let doc = Document {
            book_id: book.book_id,
            kind: 1,
            mime: "text/plain".to_string(),
            grade: 3,
            retrieved_by: PREPARER,
            bytes: b"fa-gen voucher".to_vec(),
        };
        runtime
            .block_on(async { add_document(&mut db, &ctx, &book, &doc).await })
            .unwrap()
            .unwrap();
        let evidence = vec![doc.evidence_ref(1)];

        let mut posted_vids = vec![VId(0); corpus.entries.len()];
        let mut salt = 1u8;
        let mut post_idx = |idx: usize, db: &mut Database<MemVfs>| {
            let e = &corpus.entries[idx];
            salt = salt.wrapping_add(1);
            let description =
                Erasable::seal(&e.description, None, &book.seal_key, [salt; 32], [salt; 24]);
            let mut external_ids = Vec::new();
            for (sys, id) in &e.external_ids {
                salt = salt.wrapping_add(1);
                external_ids.push(ExternalId {
                    system: sys.clone(),
                    id: Erasable::seal(id, None, &book.seal_key, [salt; 32], [salt; 24]),
                });
            }
            let legs: Vec<LegPayload> = e
                .legs
                .iter()
                .map(|l| {
                    LegPayload::simple(
                        l.side,
                        account_vid(book.book_id, &l.account_code),
                        Amount::new(usd, l.cents),
                    )
                })
                .collect();
            let proposal = EntryPayload {
                schema_minor: 0,
                book_id: book.book_id,
                branch_id: Id128::TRUNK,
                class: e.class,
                effective_date: e.effective_date,
                document_date: e.document_date,
                description,
                effective_period: None,
                unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
                legs,
                control: None,
                base_totals: None,
                idempotency_key: e.key.as_bytes().to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                principal_ref: PREPARER,
                session_ref: None,
                evidence: evidence.clone(),
                supersession: Vec::new(),
                pending: None,
                external_ids,
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            let digest = proposal.proposal_digest().unwrap();
            let ops: &[&str] = if e.post_after_soft_close {
                &["post", "post_softclosed"]
            } else {
                &["post"]
            };
            if e.self_approve {
                let req = ApprovalRequest {
                    capability: Capability::embedded(PREPARER, &["approve"]).unwrap(),
                    approved_proposal_digest: digest,
                    role: 0,
                };
                let (Approved::Recorded { approval, .. }
                | Approved::AlreadyRecorded { approval, .. }) = runtime
                    .block_on(async { record_approval(db, &ctx, &book, req).await })
                    .unwrap()
                    .unwrap();
                let refused_req = PostRequest {
                    proposal: proposal.clone(),
                    approvals: vec![approval],
                    plan_certificate: None,
                    capability: Capability::embedded(PREPARER, ops).unwrap(),
                };
                let refusal = runtime
                    .block_on(async { post(db, &ctx, &book, refused_req).await })
                    .unwrap()
                    .expect_err("FA-INV-06 must refuse native self-approval");
                assert_eq!(refusal.code, "FA-REF-008");
            }
            let mut approvals = Vec::new();
            if e.review {
                let req = ApprovalRequest {
                    capability: Capability::embedded(REVIEWER, &["approve"]).unwrap(),
                    approved_proposal_digest: digest,
                    role: 0,
                };
                let (Approved::Recorded { approval, .. }
                | Approved::AlreadyRecorded { approval, .. }) = runtime
                    .block_on(async { record_approval(db, &ctx, &book, req).await })
                    .unwrap()
                    .unwrap();
                approvals.push(approval);
            }
            let req = PostRequest {
                proposal,
                approvals,
                plan_certificate: None,
                capability: Capability::embedded(PREPARER, ops).unwrap(),
            };
            if let Posted::Committed { entry_ref, .. } = runtime
                .block_on(async { post(db, &ctx, &book, req).await })
                .unwrap()
                .unwrap()
            {
                posted_vids[idx] = entry_ref.vid;
            }
        };

        for (idx, ge) in corpus.entries.iter().enumerate() {
            if !ge.post_after_soft_close {
                post_idx(idx, &mut db);
            }
        }
        for (t_idx, t) in corpus.transitions.iter().enumerate() {
            let desc = Erasable::seal(
                &t.description,
                None,
                &book.seal_key,
                [(220 + t_idx) as u8; 32],
                [(220 + t_idx) as u8; 24],
            );
            runtime
                .block_on(async {
                    transition_period(
                        &mut db,
                        &ctx,
                        &book,
                        &t.period_code,
                        t.transition,
                        PREPARER,
                        1,
                        format!("trans-{t_idx}").as_bytes(),
                        desc,
                        &Capability::embedded(PREPARER, &["close"]).unwrap(),
                        &[],
                    )
                    .await
                })
                .unwrap()
                .unwrap();
        }
        for (idx, ge) in corpus.entries.iter().enumerate() {
            if ge.post_after_soft_close {
                post_idx(idx, &mut db);
            }
        }

        let mut snapshot = Snapshot::read(&db, &book, None, Some(corpus.snapshot_cutoff)).unwrap();
        for (idx, ge) in corpus.entries.iter().enumerate() {
            if ge.self_approve {
                let target_vid = posted_vids[idx];
                if let Some(se) = snapshot.entries.iter_mut().find(|e| e.vid == target_vid) {
                    let entered = Erasable::seal(
                        &"preparer@legacy.example".to_string(),
                        None,
                        &book.seal_key,
                        [77; 32],
                        [77; 24],
                    );
                    let approved = Erasable::seal(
                        &"preparer@legacy.example".to_string(),
                        None,
                        &book.seal_key,
                        [78; 32],
                        [78; 24],
                    );
                    let mig_id = Erasable::seal(&ge.key, None, &book.seal_key, [79; 32], [79; 24]);
                    se.entry.proposal.origin = EntryOrigin::Migration {
                        run_ref: VId(900),
                        source_system: "legacy_erp".into(),
                        source_id: mig_id,
                        source_recorded_at_ns: None,
                        source_entered_by: Some(entered),
                        source_approved_by: Some(approved),
                        batch_oid: Oid([9; 32]),
                    };
                }
            }
        }

        let procedures: Vec<Box<dyn Procedure>> = vec![
            Box::new(RoundAmounts::new().unwrap()),
            Box::new(PeriodEndTiming::new().unwrap()),
            Box::new(PostClosing::new().unwrap()),
            Box::new(Weekend::new().unwrap()),
            Box::new(SelfApproved::new().unwrap()),
            Box::new(ThinDescriptions::new().unwrap()),
            Box::new(PeriodBoundary::new().unwrap()),
            Box::new(SameSameSame::new().unwrap()),
            Box::new(SameSameDifferent::new().unwrap()),
            Box::new(SequenceGaps::new().unwrap()),
            Box::new(RoundTrips::new().unwrap()),
            Box::new(Structuring::new().unwrap()),
        ];

        for proc in &procedures {
            let res = run_over(&snapshot, &book, proc.as_ref()).unwrap();
            let cited: BTreeSet<usize> = res
                .findings
                .iter()
                .flat_map(|f| f.cites.iter())
                .filter_map(|c| match c {
                    Cite::Entry(vid) => posted_vids.iter().position(|v| v == vid),
                    _ => None,
                })
                .collect();
            let expected = corpus.expected_entries_for_procedure(proc.id());
            if scenario == ScenarioKind::CleanRetailer {
                assert!(
                    res.findings.is_empty(),
                    "clean-retailer must have 0 findings on {}",
                    proc.id()
                );
            } else {
                assert!(
                    expected.is_subset(&cited),
                    "{scenario}/{}: expected planted entries {expected:?} in cited {cited:?}",
                    proc.id()
                );
            }
        }
    }
}

/// fa-jt7p defects 4 & 7:
/// - A `duplicates.same_same_same` group larger than `MAX_CITES` (4,096)
///   truncates its citation list to `MAX_CITES` while preserving the full
///   group count in `statistic.value` and passing `Finding::check`.
/// - `jet.thin_descriptions` counts and reports descriptions that cannot be
///   opened under the book's seal key as `unreadable_descriptions` (`Info`),
///   never silently skipping them or misreporting them as thin.
#[test]
fn large_duplicate_group_truncates_cites_to_max_cites_and_unreadable_descriptions_are_counted() {
    let mut h = harness();
    let base = h.snapshot();
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;

    let template = make_snapshot_entry(
        &mut h,
        VId(50_000),
        CommitSeq(100),
        day(2026, 1, 15),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 10_000),
            ("1000", Side::Credit, usd, 10_000),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );

    let group_size = fa_lantern::MAX_CITES + 10;
    let mut snapshot = base.clone();
    snapshot.entries = (0..group_size)
        .map(|i| {
            let mut e = template.clone();
            e.vid = VId(50_000 + i as u128);
            e.recorded_at = CommitSeq(100 + i as u64);
            e
        })
        .collect();

    let sss = run_over(&snapshot, &h.book, &SameSameSame::new().unwrap()).expect(
        "a duplicate group larger than MAX_CITES must succeed without overflowing Finding::check",
    );
    assert_eq!(sss.findings.len(), 1);
    assert_eq!(sss.findings[0].statistic.value, group_size as i128);
    assert_eq!(sss.findings[0].cites.len(), fa_lantern::MAX_CITES);
    assert!(
        sss.findings[0]
            .narrative
            .contains("(the first 4096 by entry id cited)")
    );

    // Unreadable description: sealed under a foreign key.
    let mut foreign = template.clone();
    foreign.vid = VId(99_001);
    foreign.recorded_at = CommitSeq(9_001);
    foreign.entry.proposal.description = Erasable::seal(
        &"foreign-sealed description".to_string(),
        None,
        &SealKey([0xEE; 32]),
        [1; 32],
        [2; 24],
    );
    let mut thin_snap = base;
    thin_snap.entries = vec![template, foreign];
    let td = run_over(&thin_snap, &h.book, &ThinDescriptions::new().unwrap()).unwrap();
    assert_eq!(td.findings.len(), 1);
    assert_eq!(td.findings[0].severity, Severity::Info);
    assert_eq!(td.findings[0].statistic.name, "unreadable_descriptions");
    assert_eq!(td.findings[0].statistic.value, 1);
    assert_eq!(td.findings[0].statistic.population, 2);
    assert_eq!(td.findings[0].cites, vec![Cite::Entry(VId(99_001))]);
    assert!(
        td.findings[0]
            .narrative
            .contains("counted as unreadable, not thin")
    );
}

/// fa-jt7p defect 5 & budget exhaustion:
/// - `benford.first_digit` falls back to MAD-only when the eligible leg
///   population exceeds `MAX_POPULATION` (1,000,000), succeeding instead of
///   failing with an overflow error.
/// - `run_over_with_budget` refuses with `LanternError::BudgetExhausted` and an
///   actionable `fix_hint` when the work counter exceeds the caller's budget.
#[test]
fn benford_mad_fallback_above_one_million_legs_and_budget_exhaustion_refusal() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;

    // Build 1,001 entries each with 1,000 USD debit legs (+ 1 balancing credit leg)
    // = 1,001,000 eligible debit legs (> MAX_POPULATION = 1,000,000).
    let mut legs = Vec::with_capacity(1_001);
    for d in 0..1_000usize {
        let lead = (d % 9 + 1) as i128;
        legs.push(LegPayload::simple(
            Side::Debit,
            h.account("6000"),
            Amount::new(usd, lead * 100),
        ));
    }
    let total_debit: i128 = legs.iter().map(|l| l.amount.mantissa).sum();
    legs.push(LegPayload::simple(
        Side::Credit,
        h.account("1000"),
        Amount::new(usd, total_debit),
    ));

    let mut proposal = h.proposal(&Spec::simple(day(2026, 1, 15), "6000", "1000", 100));
    proposal.legs = legs;
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let sealed = proposal.seal(Vec::new(), None).unwrap();

    snapshot.entries = (0..1_001usize)
        .map(|i| fa_lantern::snapshot::SnapshotEntry {
            vid: VId(70_000 + i as u128),
            entry: sealed.clone(),
            recorded_at: CommitSeq(200 + i as u64),
            period: jan.clone(),
            approvals: Vec::new(),
        })
        .collect();

    let benford = run_over(&snapshot, &h.book, &FirstDigit::new().unwrap())
        .expect("Benford above 10^6 legs must succeed using MAD-only fallback");
    assert_eq!(benford.findings.len(), 1);
    assert_eq!(benford.findings[0].statistic.name, "mad");
    assert_eq!(benford.findings[0].statistic.population, 1_001_000);
    assert!(
        benford.findings[0]
            .narrative
            .contains("chi-square not computed above 1000000 legs")
    );

    // Budget exhaustion returns LanternError::BudgetExhausted with a fix hint.
    let err =
        fa_lantern::run_over_with_budget(&snapshot, &h.book, &FirstDigit::new().unwrap(), Some(10))
            .expect_err("work > budget must be refused");
    assert!(matches!(
        err,
        LanternError::BudgetExhausted {
            ref procedure,
            used,
            budget: 10,
            ..
        } if procedure == "benford.first_digit" && used > 10
    ));
    assert!(
        err.fix_hint()
            .as_deref()
            .is_some_and(|f| f.contains("--effective-through"))
    );
}

/// fa-jt7p defects 6, 8 & 9:
/// `graph.structuring` filters transfers by `currency_iso4217` (default 840 =
/// USD), reports the currency's registered `scale` on `Statistic`, and agrees
/// with `fa_reference::lantern::structuring_for_unit`.
#[test]
fn structuring_respects_currency_iso4217_across_multi_unit_transfers_and_agrees_with_oracle() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;
    let jpy = h.book.units.lookup("JPY").unwrap();
    let share = h.book.units.lookup("SHARE").unwrap();

    // 3 USD transfers (scale 2), 3 JPY transfers (scale 0), and 3 SHARE transfers
    // all with mantissa 900_000..920_000 in 800_000..1_000_000.
    let mut entries = Vec::new();
    let mut rows = Vec::new();
    for (u_idx, (unit, scale)) in [(usd, 2u32), (jpy, 0), (share, 0)].into_iter().enumerate() {
        for step in 0..3usize {
            let idx = u_idx * 3 + step;
            let d = day(2026, 1, 10 + step as u8);
            let m = 900_000 + (step as i128) * 10_000;
            entries.push(make_snapshot_entry(
                &mut h,
                VId(80_000 + idx as u128),
                CommitSeq(300 + idx as u64),
                d,
                &jan,
                EntryClass::ORIGINAL,
                vec![
                    ("1000", Side::Debit, unit, m),
                    ("4000", Side::Credit, unit, m),
                ],
                Vec::new(),
                None,
                None,
                None,
                Vec::new(),
            ));
            rows.push(naive::Row {
                index: idx,
                date: d,
                document_date: None,
                period: jan.clone(),
                period_start: None,
                period_end: day(2026, 2, 1),
                legs: vec![
                    naive::Leg {
                        account: "1000".into(),
                        debit: true,
                        unit: unit.0,
                        scale,
                        mantissa: m,
                    },
                    naive::Leg {
                        account: "4000".into(),
                        debit: false,
                        unit: unit.0,
                        scale,
                        mantissa: m,
                    },
                ],
                preparer: "P7".into(),
                approvers: Vec::new(),
                description_chars: Some(10),
                external_ids: Vec::new(),
                recorded_after_close: false,
                reverses: None,
                replaces: None,
            });
        }
    }
    snapshot.entries = entries;

    // Default (USD = 840): only the 3 USD entries (80_000..=80_002) are cited, with scale = 2.
    let r_usd = run_over(&snapshot, &h.book, &Structuring::new().unwrap()).unwrap();
    assert_eq!(r_usd.findings.len(), 1);
    assert_eq!(r_usd.findings[0].statistic.scale, 2);
    assert_eq!(
        r_usd.findings[0].cites[2..],
        [
            Cite::Entry(VId(80_000)),
            Cite::Entry(VId(80_001)),
            Cite::Entry(VId(80_002))
        ]
    );
    assert_eq!(
        naive::structuring_for_unit(&rows, Some(usd.0), 1_000_000, 800_000, 7, 3),
        vec![("4000".into(), "1000".into(), vec![0, 1, 2])]
    );

    // JPY (ISO 4217 = 392): only the 3 JPY entries (80_003..=80_005) are cited, with scale = 0.
    let jpy_params = Params::defaults(Structuring::ID)
        .unwrap()
        .set("currency_iso4217", 392)
        .unwrap();
    let r_jpy = run_over(&snapshot, &h.book, &Structuring::with(jpy_params)).unwrap();
    assert_eq!(r_jpy.findings.len(), 1);
    assert_eq!(r_jpy.findings[0].statistic.scale, 0);
    assert_eq!(
        r_jpy.findings[0].cites[2..],
        [
            Cite::Entry(VId(80_003)),
            Cite::Entry(VId(80_004)),
            Cite::Entry(VId(80_005))
        ]
    );
    assert_eq!(
        naive::structuring_for_unit(&rows, Some(jpy.0), 1_000_000, 800_000, 7, 3),
        vec![("4000".into(), "1000".into(), vec![3, 4, 5])]
    );
}

#[test]
fn phase_19_5b_remaining_jet_digit_and_number_procedures_and_oracles() {
    use fa_lantern::digits::{FirstTwoDigits, SecondDigit};
    use fa_lantern::jet::{
        IntercompanyUnmatched, LargeRoundReversals, ManualVsRule, SuspenseAging, UnusualAccounts,
        UnusualPreparers,
    };
    use fa_lantern::numbers::{RelativeSizeFactor, ThresholdSplitting};

    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = Some(day(2026, 2, 28));
    let jan = h.period_code(day(2026, 1, 15));
    let feb = h.period_code(day(2026, 2, 10));
    let usd = h.usd;

    // Install a suspense account (9999) and an intercompany account (IC10) in snapshot.accounts
    let susp_vid = account_vid(h.book.book_id, "9999");
    snapshot.accounts.insert(
        susp_vid,
        fa_journal::rows::AccountRow {
            vid: susp_vid,
            code: "9999".into(),
            name: "Unallocated Suspense Clearing".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            limit: None,
            created_at: CommitSeq(1),
        },
    );
    let ic_vid = account_vid(h.book.book_id, "IC10");
    snapshot.accounts.insert(
        ic_vid,
        fa_journal::rows::AccountRow {
            vid: ic_vid,
            code: "IC10".into(),
            name: "Intercompany Due From Sub".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            limit: None,
            created_at: CommitSeq(1),
        },
    );

    let rule_origin = Some(EntryOrigin::Rule {
        rule_version_oid: Oid([5; 32]),
        event_ref: VId(1),
        inputs_digest: [6; 32],
    });

    // 4 common entries on (6000, 1000) prepared by PREPARER with Rule origin
    let mut entries = Vec::new();
    let mut naive_rows = Vec::new();
    for i in 0..4usize {
        let m = match i {
            0 => 1_200,
            1 => 1_500,
            2 => 1_800,
            _ => 25_000, // 25_000 / 1_800 = 13.88x (>= 5.00x RSF!)
        };
        let d = day(2026, 1, 5 + i as u8);
        entries.push(make_snapshot_entry(
            &mut h,
            VId(90_000 + i as u128),
            CommitSeq(400 + i as u64),
            d,
            &jan,
            EntryClass::ORIGINAL,
            vec![
                ("6000", Side::Debit, usd, m),
                ("1000", Side::Credit, usd, m),
            ],
            Vec::new(),
            None,
            Some(d),
            rule_origin.clone(),
            Vec::new(),
        ));
        naive_rows.push(naive::Row {
            index: i,
            date: d,
            document_date: Some(d),
            period: jan.clone(),
            period_start: None,
            period_end: day(2026, 2, 1),
            legs: vec![
                naive::Leg {
                    account: "6000".into(),
                    debit: true,
                    unit: usd.0,
                    scale: 2,
                    mantissa: m,
                },
                naive::Leg {
                    account: "1000".into(),
                    debit: false,
                    unit: usd.0,
                    scale: 2,
                    mantissa: m,
                },
            ],
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(12),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        });
    }

    // Entry 4: Rare account pair (7000, 2000), prepared by REVIEWER on 6000, Manual origin on rule-heavy 6000
    let mut e_rare = make_snapshot_entry(
        &mut h,
        VId(90_004),
        CommitSeq(404),
        day(2026, 1, 12),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 1_100),
            ("2000", Side::Credit, usd, 1_100),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 12)),
        None, // Intent (manual) origin
        Vec::new(),
    );
    e_rare.entry.proposal.principal_ref = REVIEWER;
    entries.push(e_rare);
    naive_rows.push(naive::Row {
        index: 4,
        date: day(2026, 1, 12),
        document_date: Some(day(2026, 1, 12)),
        period: jan.clone(),
        period_start: None,
        period_end: day(2026, 2, 1),
        legs: vec![
            naive::Leg {
                account: "6000".into(),
                debit: true,
                unit: usd.0,
                scale: 2,
                mantissa: 1_100,
            },
            naive::Leg {
                account: "2000".into(),
                debit: false,
                unit: usd.0,
                scale: 2,
                mantissa: 1_100,
            },
        ],
        preparer: "P8".into(),
        approvers: Vec::new(),
        description_chars: Some(12),
        external_ids: Vec::new(),
        recorded_after_close: false,
        reverses: None,
        replaces: None,
    });

    // Entry 5 & 6: Round amount 500_000 ($5,000.00) on Jan 30 reversed on Feb 3 (`jet.large_round_reversals`)
    let e_round = make_snapshot_entry(
        &mut h,
        VId(90_005),
        CommitSeq(405),
        day(2026, 1, 30),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1100", Side::Debit, usd, 500_000),
            ("4000", Side::Credit, usd, 500_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 30)),
        None,
        Vec::new(),
    );
    let e_round_ref = fa_model::EntryRef {
        vid: e_round.vid,
        entry_digest: e_round.entry.entry_digest,
    };
    let e_round_rev = make_snapshot_entry(
        &mut h,
        VId(90_006),
        CommitSeq(406),
        day(2026, 2, 3),
        &feb,
        EntryClass::REVERSAL,
        vec![
            ("4000", Side::Debit, usd, 500_000),
            ("1100", Side::Credit, usd, 500_000),
        ],
        vec![fa_model::Supersession {
            target: e_round_ref,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }],
        None,
        Some(day(2026, 2, 3)),
        None,
        Vec::new(),
    );
    entries.push(e_round);
    entries.push(e_round_rev);

    // Entry 7: Stale suspense posting on 9999 dated Jan 10 (49 days old at Feb 28 > 7 days)
    let mut e_susp = make_snapshot_entry(
        &mut h,
        VId(90_007),
        CommitSeq(407),
        day(2026, 1, 10),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 30_000),
            ("4000", Side::Credit, usd, 30_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 10)),
        None,
        Vec::new(),
    );
    e_susp.entry.proposal.legs[0].account_ref = susp_vid;
    entries.push(e_susp);

    // Entry 8: Unmatched intercompany posting on IC10
    let mut e_ic = make_snapshot_entry(
        &mut h,
        VId(90_008),
        CommitSeq(408),
        day(2026, 1, 15),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 75_000),
            ("4000", Side::Credit, usd, 75_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 15)),
        None,
        Vec::new(),
    );
    e_ic.entry.proposal.legs[0].account_ref = ic_vid;
    entries.push(e_ic);

    // Entries 9 & 10: Threshold splitting — two $6,000.00 (600_000) postings on (7000, 1000) within 2 days
    for (k, d) in [(9usize, day(2026, 2, 10)), (10, day(2026, 2, 11))] {
        entries.push(make_snapshot_entry(
            &mut h,
            VId(90_000 + k as u128),
            CommitSeq(400 + k as u64),
            d,
            &feb,
            EntryClass::ORIGINAL,
            vec![
                ("7000", Side::Debit, usd, 600_000),
                ("1000", Side::Credit, usd, 600_000),
            ],
            Vec::new(),
            None,
            Some(d),
            None,
            Vec::new(),
        ));
    }

    snapshot.entries = entries;

    // 1. jet.unusual_accounts & oracle
    let ua = run_over(&snapshot, &h.book, &UnusualAccounts::new().unwrap()).unwrap();
    assert!(!ua.findings.is_empty());
    witness::determinism(&snapshot, &h.book, &UnusualAccounts::new().unwrap()).unwrap();
    assert_eq!(naive::unusual_accounts(&naive_rows, 1, 5), vec![4]);

    // 2. jet.unusual_preparers
    let up = run_over(&snapshot, &h.book, &UnusualPreparers::new().unwrap()).unwrap();
    assert!(
        up.findings
            .iter()
            .any(|f| f.cites.contains(&Cite::Entry(VId(90_004))))
    );
    witness::determinism(&snapshot, &h.book, &UnusualPreparers::new().unwrap()).unwrap();

    // 3. jet.manual_vs_rule
    let mvr = run_over(&snapshot, &h.book, &ManualVsRule::new().unwrap()).unwrap();
    assert!(
        mvr.findings
            .iter()
            .any(|f| f.cites.contains(&Cite::Entry(VId(90_004))))
    );
    witness::determinism(&snapshot, &h.book, &ManualVsRule::new().unwrap()).unwrap();

    // 4. jet.large_round_reversals
    let lrr = run_over(&snapshot, &h.book, &LargeRoundReversals::new().unwrap()).unwrap();
    assert_eq!(lrr.findings.len(), 1);
    assert!(lrr.findings[0].cites.contains(&Cite::Entry(VId(90_005))));
    assert!(lrr.findings[0].cites.contains(&Cite::Entry(VId(90_006))));
    witness::determinism(&snapshot, &h.book, &LargeRoundReversals::new().unwrap()).unwrap();

    // 5. jet.suspense_aging
    let sa = run_over(&snapshot, &h.book, &SuspenseAging::new().unwrap()).unwrap();
    assert_eq!(sa.findings.len(), 1);
    assert!(sa.findings[0].cites.contains(&Cite::Account(susp_vid)));
    witness::determinism(&snapshot, &h.book, &SuspenseAging::new().unwrap()).unwrap();

    // 6. jet.intercompany_unmatched
    let icu = run_over(&snapshot, &h.book, &IntercompanyUnmatched::new().unwrap()).unwrap();
    assert_eq!(icu.findings.len(), 1);
    assert!(icu.findings[0].cites.contains(&Cite::Entry(VId(90_008))));
    witness::determinism(&snapshot, &h.book, &IntercompanyUnmatched::new().unwrap()).unwrap();

    // 7. benford.second_digit & benford.first_two_digits & oracles
    let sd = run_over(
        &snapshot,
        &h.book,
        &SecondDigit::with(
            Params::defaults(SecondDigit::ID)
                .unwrap()
                .set("min_population", 1)
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(sd.findings.len(), 1);
    witness::determinism(&snapshot, &h.book, &SecondDigit::new().unwrap()).unwrap();
    let naive_sd: u64 = naive::second_digit_counts_for(&naive_rows, Some(usd.0), true)
        .iter()
        .sum();
    assert_eq!(naive_sd, 5);

    let ftd = run_over(
        &snapshot,
        &h.book,
        &FirstTwoDigits::with(
            Params::defaults(FirstTwoDigits::ID)
                .unwrap()
                .set("min_population", 1)
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(ftd.findings.len(), 1);
    witness::determinism(&snapshot, &h.book, &FirstTwoDigits::new().unwrap()).unwrap();
    let naive_ftd: u64 = naive::first_two_digits_counts_for(&naive_rows, Some(usd.0), true)
        .iter()
        .sum();
    assert_eq!(naive_ftd, 5);

    // 8. numbers.relative_size_factor & oracle
    let rsf = run_over(&snapshot, &h.book, &RelativeSizeFactor::new().unwrap()).unwrap();
    assert!(!rsf.findings.is_empty());
    witness::determinism(&snapshot, &h.book, &RelativeSizeFactor::new().unwrap()).unwrap();
    let oracle_rsf = naive::relative_size_factor_by_account(&naive_rows, 3, 50_000);
    assert_eq!(oracle_rsf.len(), 1);
    assert_eq!(oracle_rsf[0].0, "6000");

    // 9. numbers.threshold_splitting
    let ts = run_over(&snapshot, &h.book, &ThresholdSplitting::new().unwrap()).unwrap();
    assert_eq!(ts.findings.len(), 1);
    assert!(ts.findings[0].cites.contains(&Cite::Entry(VId(90_009))));
    assert!(ts.findings[0].cites.contains(&Cite::Entry(VId(90_010))));
    witness::determinism(&snapshot, &h.book, &ThresholdSplitting::new().unwrap()).unwrap();
}

#[test]
fn phase_19_5b_fnx_graph_procedures_with_cgse_witnesses() {
    use fa_lantern::graph::{
        CircularFlows, Communities, Concentration, IdentityResolution, Layering,
        RelatedPartyExposure, ShellSignature,
    };

    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = Some(day(2026, 1, 31));
    let jan = h.period_code(day(2026, 1, 15));
    let usd = h.usd;
    let seal_key = h.book.seal_key.clone();
    let seal = |s: &str, tag: u8| {
        Erasable::seal(
            &s.to_string(),
            None,
            &seal_key,
            [tag; 32],
            [tag.wrapping_add(1); 24],
        )
    };

    // Populate REA parties and relationships for graph.related_party_exposure,
    // graph.shell_signature, and graph.identity_resolution
    let p_root = fa_model::party_vid(h.book.book_id, "HOLDCO");
    let p_root_val = fa_model::party_value_vid(h.book.book_id, "HOLDCO");
    let p_aff1 = fa_model::party_vid(h.book.book_id, "AFFIL-1");
    let p_aff1_val = fa_model::party_value_vid(h.book.book_id, "AFFIL-1");
    let p_aff2 = fa_model::party_vid(h.book.book_id, "AFFIL-2");
    let p_aff2_val = fa_model::party_value_vid(h.book.book_id, "AFFIL-2");

    snapshot.rea.parties.insert(
        p_root,
        fa_journal::rea::PartyRow {
            vid: p_root,
            dimension_value_vid: p_root_val,
            code: "HOLDCO".into(),
            kind: fa_model::PartyKind::RelatedEntity,
            name: seal("Parent HoldCo", 1),
            identifiers: Vec::new(),
            external_ids: Vec::new(),
            created_at: CommitSeq(1),
        },
    );
    snapshot.rea.parties.insert(
        p_aff1,
        fa_journal::rea::PartyRow {
            vid: p_aff1,
            dimension_value_vid: p_aff1_val,
            code: "AFFIL-1".into(),
            kind: fa_model::PartyKind::Vendor,
            name: seal("Affiliate One LLC", 2),
            identifiers: vec![("bank_account".into(), seal("IBAN-SHARED-777", 3))],
            external_ids: Vec::new(),
            created_at: CommitSeq(2),
        },
    );
    snapshot.rea.parties.insert(
        p_aff2,
        fa_journal::rea::PartyRow {
            vid: p_aff2,
            dimension_value_vid: p_aff2_val,
            code: "AFFIL-2".into(),
            kind: fa_model::PartyKind::Vendor,
            name: seal("Affiliate Two LLC", 4),
            identifiers: vec![("bank_account".into(), seal("IBAN-SHARED-777", 5))],
            external_ids: Vec::new(),
            created_at: CommitSeq(3),
        },
    );
    snapshot
        .rea
        .relationships
        .push(fa_journal::rea::RelationshipRow {
            eid: fgdb_types::EId(1),
            spec: fa_model::RelationshipSpec {
                from: p_root,
                to: p_aff1,
                kind: fa_model::RelationshipKind::Controls,
                basis: "majority_voting_control".into(),
                valid_from: day(2026, 1, 1),
                valid_to: None,
            },
            recorded_at: CommitSeq(4),
            control_entry: VId(500),
        });

    // Build a 3-cycle (1000 -> 1010 -> 1020 -> 1000) and a 3-hop layering chain
    // (4000 -> 1000 -> 1010 -> 6000), attaching p_aff1_val on the first entry
    let mut e1 = make_snapshot_entry(
        &mut h,
        VId(91_001),
        CommitSeq(501),
        day(2026, 1, 5),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1010", Side::Debit, usd, 100_000),
            ("1000", Side::Credit, usd, 100_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 5)),
        None,
        Vec::new(),
    );
    e1.entry.proposal.legs[0]
        .dimension_set
        .push((fa_model::PARTY_DIMENSION, p_aff1_val));
    e1.entry.proposal.evidence.clear();
    let mut e2 = make_snapshot_entry(
        &mut h,
        VId(91_002),
        CommitSeq(502),
        day(2026, 1, 6),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1020", Side::Debit, usd, 95_000),
            ("1010", Side::Credit, usd, 95_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 6)),
        None,
        Vec::new(),
    );
    e2.entry.proposal.evidence.clear();
    let mut e3 = make_snapshot_entry(
        &mut h,
        VId(91_003),
        CommitSeq(503),
        day(2026, 1, 7),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 90_000),
            ("1020", Side::Credit, usd, 90_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 7)),
        None,
        Vec::new(),
    );
    e3.entry.proposal.evidence.clear();
    let mut e4 = make_snapshot_entry(
        &mut h,
        VId(91_004),
        CommitSeq(504),
        day(2026, 1, 8),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 85_000),
            ("1020", Side::Credit, usd, 85_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 8)),
        None,
        Vec::new(),
    );
    e4.entry.proposal.evidence.clear();
    snapshot.entries = vec![e1, e2, e3, e4];

    // 1. graph.circular_flows
    let cf = run_over(&snapshot, &h.book, &CircularFlows::new().unwrap()).unwrap();
    assert!(!cf.findings.is_empty());
    assert!(cf.findings[0].narrative.contains("cgse_witness="));
    witness::determinism(&snapshot, &h.book, &CircularFlows::new().unwrap()).unwrap();

    // 2. graph.layering
    let lay = run_over(&snapshot, &h.book, &Layering::new().unwrap()).unwrap();
    assert!(!lay.findings.is_empty());
    assert!(lay.findings[0].narrative.contains("cgse_witness="));
    witness::determinism(&snapshot, &h.book, &Layering::new().unwrap()).unwrap();

    // 3. graph.communities
    let comm = run_over(&snapshot, &h.book, &Communities::new().unwrap()).unwrap();
    assert!(!comm.findings.is_empty());
    assert!(comm.findings[0].narrative.contains("cgse_witness="));
    witness::determinism(&snapshot, &h.book, &Communities::new().unwrap()).unwrap();

    // 4. graph.related_party_exposure
    let rpe = run_over(&snapshot, &h.book, &RelatedPartyExposure::new().unwrap()).unwrap();
    assert_eq!(rpe.findings.len(), 1);
    assert!(rpe.findings[0].cites.contains(&Cite::Entry(VId(91_001))));
    assert!(rpe.findings[0].narrative.contains("cgse_witness="));
    witness::determinism(&snapshot, &h.book, &RelatedPartyExposure::new().unwrap()).unwrap();

    // 5. graph.shell_signature
    let ss = run_over(&snapshot, &h.book, &ShellSignature::new().unwrap()).unwrap();
    assert!(!ss.findings.is_empty());
    assert!(ss.findings[0].narrative.contains("cgse_witness="));
    witness::determinism(&snapshot, &h.book, &ShellSignature::new().unwrap()).unwrap();

    // 6. graph.concentration
    let conc = run_over(&snapshot, &h.book, &Concentration::new().unwrap()).unwrap();
    assert!(!conc.findings.is_empty());
    assert!(conc.findings[0].narrative.contains("cgse_witness="));
    witness::determinism(&snapshot, &h.book, &Concentration::new().unwrap()).unwrap();

    // 7. graph.identity_resolution
    let ir = run_over(&snapshot, &h.book, &IdentityResolution::new().unwrap()).unwrap();
    assert_eq!(ir.findings.len(), 1);
    assert!(ir.findings[0].cites.contains(&Cite::Principal(p_aff1)));
    assert!(ir.findings[0].cites.contains(&Cite::Principal(p_aff2)));
    assert!(ir.findings[0].narrative.contains("cgse_witness="));
    witness::determinism(&snapshot, &h.book, &IdentityResolution::new().unwrap()).unwrap();
}

#[test]
fn phase_19_5b_reconciliation_completeness_and_audit_procedures() {
    use fa_journal::attestation::{
        Attestation, AttestationClaim, CapabilityBinding, RegisterEqualsClaim, StoredAttestation,
        Subject,
    };
    use fa_lantern::aging::InventoryAging;
    use fa_lantern::cutoff::{
        ConfirmCoverage, ExpenseCapitalization, PartyMasterChanges, PayrollGhost, ReconBookToBook,
        ReconIntercompany, ReconLapping, ReversalPatterns, SubsequentEvents, UnrecordedLiabilities,
    };

    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = Some(day(2026, 4, 30));
    let jan = h.period_code(day(2026, 1, 15));
    let feb = h.period_code(day(2026, 2, 10));
    let usd = h.usd;
    let seal_key = h.book.seal_key.clone();
    let seal = |s: &str, tag: u8| {
        Erasable::seal(
            &s.to_string(),
            None,
            &seal_key,
            [tag; 32],
            [tag.wrapping_add(1); 24],
        )
    };

    // Add an intercompany account IC20 and an inventory account 1300
    let ic_vid = account_vid(h.book.book_id, "IC20");
    snapshot.accounts.insert(
        ic_vid,
        fa_journal::rows::AccountRow {
            vid: ic_vid,
            code: "IC20".into(),
            name: "Intercompany Receivable".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            limit: None,
            created_at: CommitSeq(1),
        },
    );
    let inv_vid = account_vid(h.book.book_id, "1300");
    snapshot.accounts.insert(
        inv_vid,
        fa_journal::rows::AccountRow {
            vid: inv_vid,
            code: "1300".into(),
            name: "Merchandise Inventory".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            limit: None,
            created_at: CommitSeq(1),
        },
    );
    let capex_vid = account_vid(h.book.book_id, "1500");
    snapshot.accounts.insert(
        capex_vid,
        fa_journal::rows::AccountRow {
            vid: capex_vid,
            code: "1500".into(),
            name: "Network Property & CapEx".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            limit: None,
            created_at: CommitSeq(1),
        },
    );
    let payroll_vid = account_vid(h.book.book_id, "6300");
    snapshot.accounts.insert(
        payroll_vid,
        fa_journal::rows::AccountRow {
            vid: payroll_vid,
            code: "6300".into(),
            name: "Wages & Salaries Expense".into(),
            account_type: AccountType::EXPENSE.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            limit: None,
            created_at: CommitSeq(1),
        },
    );

    // Parties for lapping & payroll & master changes
    let pa = fa_model::party_vid(h.book.book_id, "CUST-A");
    let pa_val = fa_model::party_value_vid(h.book.book_id, "CUST-A");
    let pb = fa_model::party_vid(h.book.book_id, "CUST-B");
    let pb_val = fa_model::party_value_vid(h.book.book_id, "CUST-B");
    snapshot.rea.parties.insert(
        pa,
        fa_journal::rea::PartyRow {
            vid: pa,
            dimension_value_vid: pa_val,
            code: "CUST-A".into(),
            kind: fa_model::PartyKind::Customer,
            name: seal("Customer A", 10),
            identifiers: vec![("bank".into(), seal("SHARED-BANK-1", 11))],
            external_ids: Vec::new(),
            created_at: CommitSeq(1),
        },
    );
    snapshot.rea.parties.insert(
        pb,
        fa_journal::rea::PartyRow {
            vid: pb,
            dimension_value_vid: pb_val,
            code: "CUST-B".into(),
            kind: fa_model::PartyKind::Customer,
            name: seal("Customer B", 12),
            identifiers: vec![("bank".into(), seal("SHARED-BANK-1", 13))],
            external_ids: Vec::new(),
            created_at: CommitSeq(2),
        },
    );

    // Mark FY2026-P01 as soft-closed for subsequent events review
    snapshot.transitions.insert(
        jan.clone(),
        vec![fa_lantern::Transition {
            recorded_at: CommitSeq(590),
            from: PeriodState::Open,
            to: PeriodState::SoftClosed,
        }],
    );

    // 1. Intercompany imbalance entry on IC20
    let mut e_ic = make_snapshot_entry(
        &mut h,
        VId(92_001),
        CommitSeq(601),
        day(2026, 1, 10),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 40_000),
            ("4000", Side::Credit, usd, 40_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 10)),
        None,
        Vec::new(),
    );
    e_ic.entry.proposal.legs[0].account_ref = ic_vid;

    // 2. Lapping triple on AR (1100):
    //    - Jan 10: CUST-A debit 50_000
    //    - Jan 12: CUST-B credit 50_000
    //    - Jan 15: CUST-A credit 50_000
    let mut e_lap1 = make_snapshot_entry(
        &mut h,
        VId(92_002),
        CommitSeq(602),
        day(2026, 1, 10),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1200", Side::Debit, usd, 50_000),
            ("4000", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 10)),
        None,
        Vec::new(),
    );
    e_lap1.entry.proposal.legs[0]
        .dimension_set
        .push((fa_model::PARTY_DIMENSION, pa_val));
    let mut e_lap2 = make_snapshot_entry(
        &mut h,
        VId(92_003),
        CommitSeq(603),
        day(2026, 1, 12),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 50_000),
            ("1200", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 12)),
        None,
        Vec::new(),
    );
    e_lap2.entry.proposal.legs[1]
        .dimension_set
        .push((fa_model::PARTY_DIMENSION, pb_val));
    let mut e_lap3 = make_snapshot_entry(
        &mut h,
        VId(92_004),
        CommitSeq(604),
        day(2026, 1, 15),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 50_000),
            ("1200", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 15)),
        None,
        Vec::new(),
    );
    e_lap3.entry.proposal.legs[1]
        .dimension_set
        .push((fa_model::PARTY_DIMENSION, pa_val));

    // 3. Unrecorded liability: effective Feb 10 (FY2026-P02), document_date Jan 25 (FY2026-P01), touches 6000 Expense
    let e_unrec = make_snapshot_entry(
        &mut h,
        VId(92_005),
        CommitSeq(605),
        day(2026, 2, 10),
        &feb,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 120_000),
            ("2000", Side::Credit, usd, 120_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 25)),
        None,
        Vec::new(),
    );

    // 4. Subsequent event + cross-period reversal pattern: Adjusting/Reversal in Feb reversing Jan entry
    let e_jan_orig = make_snapshot_entry(
        &mut h,
        VId(92_011),
        CommitSeq(601),
        day(2026, 1, 28),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1200", Side::Debit, usd, 200_000),
            ("4000", Side::Credit, usd, 200_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 28)),
        None,
        Vec::new(),
    );
    let e_orig_ref = fa_model::EntryRef {
        vid: e_jan_orig.vid,
        entry_digest: e_jan_orig.entry.entry_digest,
    };
    let e_subseq = make_snapshot_entry(
        &mut h,
        VId(92_006),
        CommitSeq(606),
        day(2026, 2, 5),
        &feb,
        EntryClass::REVERSAL,
        vec![
            ("4000", Side::Debit, usd, 200_000),
            ("1200", Side::Credit, usd, 200_000),
        ],
        vec![fa_model::Supersession {
            target: e_orig_ref,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }],
        None,
        Some(day(2026, 2, 5)),
        None,
        Vec::new(),
    );

    // 5. Party master change control entry at CommitSeq(600) for CUST-A
    let upd_bytes = fa_model::PartyIdentifierUpdate {
        party_vid: pa,
        identifiers: vec![("bank".into(), seal("NEW-IBAN", 14))],
    }
    .encode()
    .unwrap();
    let mut e_ctrl = make_snapshot_entry(
        &mut h,
        VId(92_007),
        CommitSeq(600),
        day(2026, 1, 9),
        "",
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 100),
            ("4000", Side::Credit, usd, 100),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    e_ctrl.entry.proposal.class = EntryClass::SCHEMA_CONTROL;
    e_ctrl.entry.proposal.legs.clear();
    e_ctrl.entry.proposal.unit_totals.clear();
    e_ctrl.entry.proposal.control = Some(fa_model::ControlPayload::SchemaChange {
        kind: fa_model::rea::SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS,
        canonical_bytes: upd_bytes,
    });

    // 6. Payroll ghost entry (weekend payroll disbursement on Saturday Feb 14)
    let mut e_pay = make_snapshot_entry(
        &mut h,
        VId(92_008),
        CommitSeq(608),
        day(2026, 2, 14),
        &feb,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 350_000),
            ("1000", Side::Credit, usd, 350_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 2, 14)),
        None,
        Vec::new(),
    );
    e_pay.entry.proposal.legs[0].account_ref = payroll_vid;
    e_pay.entry.proposal.legs[0]
        .dimension_set
        .push((fa_model::PARTY_DIMENSION, pa_val));

    // 7. Improper expense capitalization: Debit 1500 CapEx, Credit 6000 Expense
    let mut e_capex = make_snapshot_entry(
        &mut h,
        VId(92_009),
        CommitSeq(609),
        day(2026, 1, 20),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 800_000),
            ("6000", Side::Credit, usd, 800_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 20)),
        None,
        Vec::new(),
    );
    e_capex.entry.proposal.legs[0].account_ref = capex_vid;

    // 8. Stale inventory on 1300 dated Jan 2 (118 days without relief by Apr 30 > 90 days)
    let mut e_inv = make_snapshot_entry(
        &mut h,
        VId(92_010),
        CommitSeq(610),
        day(2026, 1, 2),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 250_000),
            ("2000", Side::Credit, usd, 250_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 2)),
        None,
        Vec::new(),
    );
    e_inv.entry.proposal.legs[0].account_ref = inv_vid;

    snapshot.entries = vec![
        e_ic, e_lap1, e_lap2, e_lap3, e_unrec, e_jan_orig, e_subseq, e_ctrl, e_pay, e_capex, e_inv,
    ];

    // Add a RegisterEquals attestation on Cash (1000) in FY2026-P01 claiming 999_999 (diverging from fold)
    let reg_claim = RegisterEqualsClaim {
        account: h.account("1000"),
        unit_id: usd.0,
        period: jan.clone(),
        entity: None,
        mantissa: 999_999,
        as_of_effective: day(2026, 1, 31),
        evaluated_known_at: CommitSeq(700),
        fold_digest: [0xAB; 32],
    };
    let cell = reg_claim.cell_digest();
    snapshot.attestations.insert(
        VId(95_001),
        StoredAttestation {
            attestation: Attestation {
                book_id: h.book.book_id,
                claim: AttestationClaim::RegisterEquals(reg_claim),
                subject: Subject::Cell(cell),
                principal: REVIEWER,
                evidence_refs: Vec::new(),
            },
            signed_digest: [0xCD; 32],
            binding: CapabilityBinding {
                profile: Profile::Human,
                capability_commitment: [0xEF; 32],
            },
        },
    );

    // Run and verify all 10 reconciliation/completeness/audit + inventory aging procedures:
    let r_ic = run_over(&snapshot, &h.book, &ReconIntercompany::new().unwrap()).unwrap();
    assert_eq!(r_ic.findings.len(), 1);
    assert_eq!(r_ic.findings[0].severity, Severity::Critical);
    witness::determinism(&snapshot, &h.book, &ReconIntercompany::new().unwrap()).unwrap();

    let r_lap = run_over(&snapshot, &h.book, &ReconLapping::new().unwrap()).unwrap();
    assert_eq!(r_lap.findings.len(), 1);
    witness::determinism(&snapshot, &h.book, &ReconLapping::new().unwrap()).unwrap();

    let r_b2b = run_over(&snapshot, &h.book, &ReconBookToBook::new().unwrap()).unwrap();
    assert_eq!(r_b2b.findings.len(), 1);
    assert_eq!(r_b2b.findings[0].severity, Severity::Critical);
    witness::determinism(&snapshot, &h.book, &ReconBookToBook::new().unwrap()).unwrap();

    let r_ul = run_over(&snapshot, &h.book, &UnrecordedLiabilities::new().unwrap()).unwrap();
    assert!(!r_ul.findings.is_empty());
    assert!(
        r_ul.findings
            .iter()
            .any(|f| f.cites.contains(&Cite::Entry(VId(92_005))))
    );
    witness::determinism(&snapshot, &h.book, &UnrecordedLiabilities::new().unwrap()).unwrap();

    let r_sub = run_over(&snapshot, &h.book, &SubsequentEvents::new().unwrap()).unwrap();
    assert!(!r_sub.findings.is_empty());
    assert!(
        r_sub
            .findings
            .iter()
            .any(|f| f.cites.contains(&Cite::Entry(VId(92_006))))
    );
    witness::determinism(&snapshot, &h.book, &SubsequentEvents::new().unwrap()).unwrap();

    let r_pmc = run_over(&snapshot, &h.book, &PartyMasterChanges::new().unwrap()).unwrap();
    assert!(!r_pmc.findings.is_empty());
    assert!(
        r_pmc
            .findings
            .iter()
            .any(|f| f.cites.contains(&Cite::Entry(VId(92_007))))
    );
    witness::determinism(&snapshot, &h.book, &PartyMasterChanges::new().unwrap()).unwrap();

    let r_pg = run_over(&snapshot, &h.book, &PayrollGhost::new().unwrap()).unwrap();
    assert!(!r_pg.findings.is_empty());
    assert!(
        r_pg.findings
            .iter()
            .any(|f| f.cites.contains(&Cite::Entry(VId(92_008))))
    );
    witness::determinism(&snapshot, &h.book, &PayrollGhost::new().unwrap()).unwrap();

    let r_cap = run_over(&snapshot, &h.book, &ExpenseCapitalization::new().unwrap()).unwrap();
    assert_eq!(r_cap.findings.len(), 1);
    assert!(r_cap.findings[0].cites.contains(&Cite::Entry(VId(92_009))));
    witness::determinism(&snapshot, &h.book, &ExpenseCapitalization::new().unwrap()).unwrap();

    let r_inv = run_over(&snapshot, &h.book, &InventoryAging::new().unwrap()).unwrap();
    assert_eq!(r_inv.findings.len(), 1);
    assert!(r_inv.findings[0].cites.contains(&Cite::Account(inv_vid)));
    witness::determinism(&snapshot, &h.book, &InventoryAging::new().unwrap()).unwrap();

    let r_rev = run_over(&snapshot, &h.book, &ReversalPatterns::new().unwrap()).unwrap();
    assert_eq!(r_rev.findings.len(), 1);
    assert!(r_rev.findings[0].cites.contains(&Cite::Entry(VId(92_006))));
    witness::determinism(&snapshot, &h.book, &ReversalPatterns::new().unwrap()).unwrap();

    let r_cc = run_over(&snapshot, &h.book, &ConfirmCoverage::new().unwrap()).unwrap();
    assert!(!r_cc.findings.is_empty());
    witness::determinism(&snapshot, &h.book, &ConfirmCoverage::new().unwrap()).unwrap();
}

/// Deterministic SplitMix64 generator + greedy shrinker (`fs-propcheck` style,
/// zero floats, no ambient entropy) for `fa-vpk` property and differential suites.
struct PropGen {
    state: u64,
}

impl PropGen {
    const fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn u64_in(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        let span = (hi_inclusive - lo).saturating_add(1);
        if span == 0 {
            self.next_u64()
        } else {
            lo + (self.next_u64() % span)
        }
    }
}

fn shrink_u64(v: u64) -> Vec<u64> {
    if v == 0 {
        return Vec::new();
    }
    let mut out = vec![0];
    let mut cur = v / 2;
    while cur > 0 && v - cur != 0 {
        out.push(v - cur);
        cur /= 2;
    }
    if v > 1 {
        out.push(v - 1);
    }
    out.dedup();
    out
}

fn shrink_vec_u64(xs: &[u64]) -> Vec<Vec<u64>> {
    let mut out = Vec::new();
    for i in 0..xs.len() {
        for cand in shrink_u64(xs[i]) {
            let mut next = xs.to_vec();
            next[i] = cand;
            out.push(next);
        }
    }
    out
}

fn check_property_with_shrinking<T: Clone>(
    base_seed: u64,
    cases: u64,
    mut make: impl FnMut(&mut PropGen) -> T,
    mut shrink: impl FnMut(&T) -> Vec<T>,
    mut check: impl FnMut(&T) -> Result<(), String>,
) -> Result<(), (u64, T, T, usize, String)> {
    for case in 0..cases {
        let case_seed = base_seed.wrapping_add(case.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut g = PropGen::from_seed(case_seed);
        let original = make(&mut g);
        if let Err(mut reason) = check(&original) {
            let mut minimal = original.clone();
            let mut steps = 0usize;
            while steps < 256 {
                let mut improved = false;
                for cand in shrink(&minimal) {
                    if let Err(r) = check(&cand) {
                        minimal = cand;
                        reason = r;
                        steps += 1;
                        improved = true;
                        break;
                    }
                }
                if !improved {
                    break;
                }
            }
            return Err((case_seed, original, minimal, steps, reason));
        }
    }
    Ok(())
}

#[test]
fn statistical_audit_lane_oracles_numpy_sampling_and_propcheck_suites() {
    use fa_lantern::digits::{
        BENFORD_1E9, BENFORD_FIRST_TWO_1E9, BENFORD_SECOND_1E9, FirstTwoDigits, SecondDigit,
        chi_square_1e6, chi_square_table_1e6, expected_counts_1e9, first_digit_expected_counts,
        first_two_digits_expected_counts, ks_1e9, ks_critical_1e9, ks_table_1e9, mad_1e9,
        mad_table_1e9, second_digit_expected_counts,
    };
    use fa_lantern::sample::{
        Pcg64Dxsm, PopulationItem, SamplePopulation, SeedSequence, sample_mus,
        sample_stratified_neyman, sample_uniform,
    };
    use fa_registry::procedures::Claim;

    // 1. Registry claim class check: statistical procedures are registered with Claim::Statistical.
    let registered = fa_lantern::catalog::registered().unwrap();
    for id in [
        "benford.first_digit",
        "benford.second_digit",
        "benford.first_two_digits",
        "numbers.relative_size_factor",
        "numbers.threshold_splitting",
    ] {
        let row = registered
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("missing procedure {id}"));
        assert_eq!(row.claim, Claim::Statistical);
        assert_eq!(row.claim.name(), "statistical");
    }

    // 2. End-to-end Benford procedure runs emit KS + chi-square in certified narratives
    // and match `fa-reference::lantern` naive oracles on the posted corpus.
    let (h, c) = posted_corpus();
    let rows = naive_rows(&h, &c);
    let counts1 = naive::first_digit_counts_for(&rows, h.usd.0, true);
    let r1 = h.run(&FirstDigit::with(
        Params::defaults(FirstDigit::ID)
            .unwrap()
            .set("min_population", 1)
            .unwrap(),
    ));
    assert_eq!(r1.findings.len(), 1);
    assert!(r1.findings[0].narrative.contains("chi-square"));
    assert!(r1.findings[0].narrative.contains("KS "));
    assert_eq!(
        ks_1e9(&counts1).unwrap(),
        naive::naive_ks_table_1e9(&counts1, &BENFORD_1E9)
    );
    assert_eq!(
        ks_table_1e9(&counts1, &BENFORD_1E9).unwrap(),
        naive::naive_ks_table_1e9(&counts1, &BENFORD_1E9)
    );
    assert_eq!(
        chi_square_1e6(&counts1).unwrap(),
        naive::naive_chi_square_table_1e6(&counts1, &BENFORD_1E9)
    );
    assert_eq!(
        chi_square_table_1e6(&counts1, &BENFORD_1E9).unwrap(),
        naive::naive_chi_square_table_1e6(&counts1, &BENFORD_1E9)
    );
    assert_eq!(
        mad_table_1e9(&counts1, &BENFORD_1E9).unwrap(),
        naive::naive_mad_table_1e9(&counts1, &BENFORD_1E9)
    );

    let r2 = h.run(&SecondDigit::with(
        Params::defaults(SecondDigit::ID)
            .unwrap()
            .set("min_population", 1)
            .unwrap(),
    ));
    assert_eq!(r2.findings.len(), 1);
    assert!(r2.findings[0].narrative.contains("KS "));

    let r12 = h.run(&FirstTwoDigits::with(
        Params::defaults(FirstTwoDigits::ID)
            .unwrap()
            .set("min_population", 1)
            .unwrap(),
    ));
    assert_eq!(r12.findings.len(), 1);
    assert!(r12.findings[0].narrative.contains("KS "));

    // 3. Planted-negative test for the greedy shrinker: a property that fails for
    // `n >= 42` shrinks deterministically to the minimal counterexample `42`.
    let planted_err = check_property_with_shrinking(
        0xCAFE_BABE,
        32,
        |g| g.u64_in(100, 10_000),
        |&v| shrink_u64(v),
        |&v| {
            if v >= 42 {
                Err(format!("{v} >= 42"))
            } else {
                Ok(())
            }
        },
    )
    .expect_err("planted property must fail and shrink");
    assert_eq!(planted_err.2, 42);
    assert!(planted_err.3 > 0);

    // 4. Property suite: Benford expected-count conservation and oracle agreement
    // across 9, 10, and 90 buckets.
    check_property_with_shrinking(
        0x2026_1020_0001,
        64,
        |g| g.u64_in(1, 500_000),
        |&n| shrink_u64(n),
        |&n| {
            if n == 0 {
                return Ok(());
            }
            let e1 = first_digit_expected_counts(n).map_err(|e| e.to_string())?;
            if e1.iter().sum::<u64>() != n {
                return Err(format!("9-bucket sum != {n}"));
            }
            if e1.to_vec() != naive::naive_benford_expected_counts(n, &BENFORD_1E9) {
                return Err("9-bucket oracle mismatch".into());
            }
            let e2 = second_digit_expected_counts(n).map_err(|e| e.to_string())?;
            if e2.iter().sum::<u64>() != n {
                return Err(format!("10-bucket sum != {n}"));
            }
            if e2.to_vec() != naive::naive_benford_expected_counts(n, &BENFORD_SECOND_1E9) {
                return Err("10-bucket oracle mismatch".into());
            }
            let e12 = first_two_digits_expected_counts(n).map_err(|e| e.to_string())?;
            if e12.iter().sum::<u64>() != n {
                return Err(format!("90-bucket sum != {n}"));
            }
            if e12.to_vec() != naive::naive_benford_expected_counts(n, &BENFORD_FIRST_TWO_1E9) {
                return Err("90-bucket oracle mismatch".into());
            }
            let _ = expected_counts_1e9(n, &BENFORD_1E9).map_err(|e| e.to_string())?;
            let c10 = ks_critical_1e9(n, 1_000).map_err(|e| e.to_string())?;
            let c05 = ks_critical_1e9(n, 500).map_err(|e| e.to_string())?;
            let c01 = ks_critical_1e9(n, 100).map_err(|e| e.to_string())?;
            if !(c10 <= c05 && c05 <= c01) {
                return Err("KS critical values must increase as alpha decreases".into());
            }
            Ok(())
        },
    )
    .unwrap();

    // 5. Property suite: MAD, chi-square, and KS non-negativity and exact differential
    // agreement with `fa-reference::lantern` across generated 9-bucket histograms.
    check_property_with_shrinking(
        0x2026_1020_0002,
        64,
        |g| (0..9).map(|_| g.u64_in(0, 5_000)).collect::<Vec<u64>>(),
        |xs| shrink_vec_u64(xs),
        |xs| {
            let counts: [u64; 9] = core::array::from_fn(|i| xs[i]);
            let mad = mad_1e9(&counts).map_err(|e| e.to_string())?;
            let chi = chi_square_1e6(&counts).map_err(|e| e.to_string())?;
            let ks = ks_1e9(&counts).map_err(|e| e.to_string())?;
            if mad < 0 || chi < 0 || !(0..=1_000_000_000).contains(&ks) {
                return Err(format!(
                    "out-of-range statistic: mad={mad}, chi={chi}, ks={ks}"
                ));
            }
            if mad != naive::benford_mad_1e9(&counts)
                || mad != naive::naive_mad_table_1e9(&counts, &BENFORD_1E9)
            {
                return Err("MAD oracle mismatch".into());
            }
            if chi != naive::naive_chi_square_table_1e6(&counts, &BENFORD_1E9) {
                return Err("chi-square oracle mismatch".into());
            }
            if ks != naive::naive_ks_table_1e9(&counts, &BENFORD_1E9) {
                return Err("KS oracle mismatch".into());
            }
            Ok(())
        },
    )
    .unwrap();

    // 6. Property suite: `SeedSequence` + `Pcg64Dxsm` jump-ahead (`advance`) and
    // MUS / uniform / stratified sampling invariants across generated seeds.
    check_property_with_shrinking(
        0x2026_1020_0003,
        32,
        |g| (g.next_u64(), g.u64_in(1, 64)),
        |&(seed, steps)| {
            shrink_u64(steps)
                .into_iter()
                .filter(|&s| s >= 1)
                .map(|s| (seed, s))
                .collect()
        },
        |&(seed, steps)| {
            let seq = SeedSequence::from_seed(seed);
            if seq.generate_state_u64(4).len() != 4 {
                return Err("SeedSequence must emit 4 u64 words".into());
            }
            let mut stepped = Pcg64Dxsm::from_seed(seed);
            for _ in 0..steps {
                let _ = stepped.next_u64();
            }
            let mut advanced = Pcg64Dxsm::from_seed(seed);
            advanced.advance(u128::from(steps));
            if stepped.raw_state() != advanced.raw_state() {
                return Err("Pcg64Dxsm::advance diverged from sequential stepping".into());
            }

            let usd = UnitId(1);
            let items: Vec<PopulationItem> = (0..8)
                .map(|idx| PopulationItem {
                    item_id: format!("ITEM-{idx:02}"),
                    reference_vid: VId((idx + 1) as u128),
                    stratum: Some(if idx < 4 { "s1" } else { "s2" }.into()),
                    book_value: Amount::new(usd, ((idx as i128) + 1) * 10_000),
                })
                .collect();
            let pop = SamplePopulation::new("prop-pop", usd, items).map_err(|e| e.to_string())?;
            let mus =
                sample_mus(&pop, seed, Amount::new(usd, 55_000)).map_err(|e| e.to_string())?;
            let raw: Vec<(String, i128)> = pop
                .items
                .iter()
                .map(|i| (i.item_id.clone(), i.book_value.mantissa))
                .collect();
            let oracle_mus = naive::naive_sample_mus(&raw, mus.start_dollar_mantissa, 55_000);
            if mus.certificate.selected_item_ids != oracle_mus {
                return Err("sample_mus diverged from naive_sample_mus".into());
            }
            let uni = sample_uniform(&pop, seed, 4).map_err(|e| e.to_string())?;
            if uni.selected.len() != 4 {
                return Err("sample_uniform selected count mismatch".into());
            }
            let epoch = [0x42; 32];
            let strat = sample_stratified_neyman(&pop, seed, 4, Some(epoch), epoch, VId(1))
                .map_err(|e| e.to_string())?;
            if strat.selected.len() != 4 {
                return Err("sample_stratified_neyman selected count mismatch".into());
            }
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn fa_y4v_solvency_lookback_ponzi_distribution_and_damages_procedures() {
    use fa_journal::attestation::{
        Attestation, AttestationClaim, CapabilityBinding, RegisterEqualsClaim, StoredAttestation,
        Subject,
    };
    use fa_lantern::cutoff::{
        DamagesButFor, DistributionProRata, DistributionRisingTide, LookbackFraudulentTransfer,
        LookbackPreferences, PonziNetInvestment, SolvencyBalanceSheetTest, SolvencyCashFlowTest,
        compute_scenario_but_for_damages,
    };
    use fa_model::{AccountType, EntryClass, account_vid};
    use fa_policy::Profile;

    let mut h = harness();
    let usd = h.usd;
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = Some(day(2026, 4, 30));

    let inv_cap_vid = account_vid(h.book.book_id, "2100");
    snapshot.accounts.insert(
        inv_cap_vid,
        fa_journal::rows::AccountRow {
            vid: inv_cap_vid,
            code: "2100".into(),
            name: "Investor Capital Liability".into(),
            account_type: AccountType::LIABILITY.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            limit: None,
            created_at: CommitSeq(1),
        },
    );

    let seal_key = h.book.seal_key.clone();
    let seal = move |text: &str, salt: u8| {
        fa_model::Erasable::seal(
            &text.to_string(),
            None,
            &seal_key,
            [salt; 32],
            [salt.wrapping_add(1); 24],
        )
    };

    // Register parties:
    // - VEND-PREF (non-insider vendor with §547(c)(1), (c)(2), and (c)(4) defenses)
    // - INSIDER-P (related party via RELATED_TO edge)
    // - INV-WIN, INV-A, INV-B, INV-C (Ponzi investors)
    let mut add_party = |code: &str, kind: fa_model::PartyKind, salt: u8| -> (VId, VId) {
        let pvid = fa_model::party_vid(h.book.book_id, code);
        let pval = fa_model::party_value_vid(h.book.book_id, code);
        snapshot.rea.parties.insert(
            pvid,
            fa_journal::rea::PartyRow {
                vid: pvid,
                dimension_value_vid: pval,
                code: code.into(),
                kind,
                name: seal(code, salt),
                identifiers: Vec::new(),
                external_ids: Vec::new(),
                created_at: CommitSeq(1),
            },
        );
        (pvid, pval)
    };

    let (_vend_vid, vend_val) = add_party("VEND-PREF", fa_model::PartyKind::Vendor, 21);
    let (insider_vid, insider_val) = add_party("INSIDER-P", fa_model::PartyKind::RelatedEntity, 23);
    let (_win_vid, win_val) = add_party("INV-WIN", fa_model::PartyKind::Counterparty, 25);
    let (_inva_vid, inva_val) = add_party("INV-A", fa_model::PartyKind::Counterparty, 27);
    let (_invb_vid, invb_val) = add_party("INV-B", fa_model::PartyKind::Counterparty, 29);
    let (_invc_vid, invc_val) = add_party("INV-C", fa_model::PartyKind::Counterparty, 31);

    // Active RELATED_TO edge marking INSIDER-P as an insider
    snapshot
        .rea
        .relationships
        .push(fa_journal::rea::RelationshipRow {
            eid: fgdb_types::EId(96_001),
            spec: fa_model::RelationshipSpec {
                from: insider_vid,
                to: insider_vid,
                kind: fa_model::RelationshipKind::RelatedTo,
                basis: "executive_officer_or_director".into(),
                valid_from: day(2025, 1, 1),
                valid_to: None,
            },
            recorded_at: CommitSeq(2),
            control_entry: VId(96_000),
        });

    let jan = h.period_code(day(2026, 1, 15));
    let feb = h.period_code(day(2026, 2, 15));
    let mar = h.period_code(day(2026, 3, 15));
    let apr = h.period_code(day(2026, 4, 15));

    // Helper to attach party dimension to all legs of an entry
    let tag_party = |e: &mut fa_lantern::SnapshotEntry, pval: VId| {
        for leg in &mut e.entry.proposal.legs {
            leg.dimension_set.push((fa_model::PARTY_DIMENSION, pval));
        }
    };

    // --- 1. Ponzi investor flows on 2100 Investor Capital ---
    // INV-WIN: invests 100_000 on Jan 5, withdraws 140_000 on Feb 10 (net winner, clawback = 40_000)
    let mut e_win_in = make_snapshot_entry(
        &mut h,
        VId(97_001),
        CommitSeq(701),
        day(2026, 1, 5),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 100_000),
            ("2000", Side::Credit, usd, 100_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 5)),
        None,
        Vec::new(),
    );
    e_win_in.entry.proposal.legs[1].account_ref = inv_cap_vid;
    tag_party(&mut e_win_in, win_val);

    let mut e_win_out = make_snapshot_entry(
        &mut h,
        VId(97_002),
        CommitSeq(702),
        day(2026, 2, 10),
        &feb,
        EntryClass::ORIGINAL,
        vec![
            ("2000", Side::Debit, usd, 140_000),
            ("1000", Side::Credit, usd, 140_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 2, 10)),
        None,
        Vec::new(),
    );
    e_win_out.entry.proposal.legs[0].account_ref = inv_cap_vid;
    tag_party(&mut e_win_out, win_val);

    // INV-A: invests 100_000 on Jan 6, withdraws 0 (0% pre-receivership recovery)
    let mut e_a_in = make_snapshot_entry(
        &mut h,
        VId(97_003),
        CommitSeq(703),
        day(2026, 1, 6),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 100_000),
            ("2000", Side::Credit, usd, 100_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 6)),
        None,
        Vec::new(),
    );
    e_a_in.entry.proposal.legs[1].account_ref = inv_cap_vid;
    tag_party(&mut e_a_in, inva_val);

    // INV-B: invests 100_000 on Jan 7, withdraws 50_000 on Feb 12 (50% pre-receivership recovery)
    let mut e_b_in = make_snapshot_entry(
        &mut h,
        VId(97_004),
        CommitSeq(704),
        day(2026, 1, 7),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 100_000),
            ("2000", Side::Credit, usd, 100_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 7)),
        None,
        Vec::new(),
    );
    e_b_in.entry.proposal.legs[1].account_ref = inv_cap_vid;
    tag_party(&mut e_b_in, invb_val);

    let mut e_b_out = make_snapshot_entry(
        &mut h,
        VId(97_005),
        CommitSeq(705),
        day(2026, 2, 12),
        &feb,
        EntryClass::ORIGINAL,
        vec![
            ("2000", Side::Debit, usd, 50_000),
            ("1000", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 2, 12)),
        None,
        Vec::new(),
    );
    e_b_out.entry.proposal.legs[0].account_ref = inv_cap_vid;
    tag_party(&mut e_b_out, invb_val);

    // INV-C: invests 100_000 on Jan 8, withdraws 80_000 on Feb 15 (80% pre-receivership recovery)
    let mut e_c_in = make_snapshot_entry(
        &mut h,
        VId(97_006),
        CommitSeq(706),
        day(2026, 1, 8),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 100_000),
            ("2000", Side::Credit, usd, 100_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 8)),
        None,
        Vec::new(),
    );
    e_c_in.entry.proposal.legs[1].account_ref = inv_cap_vid;
    tag_party(&mut e_c_in, invc_val);

    let mut e_c_out = make_snapshot_entry(
        &mut h,
        VId(97_007),
        CommitSeq(707),
        day(2026, 2, 15),
        &feb,
        EntryClass::ORIGINAL,
        vec![
            ("2000", Side::Debit, usd, 80_000),
            ("1000", Side::Credit, usd, 80_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 2, 15)),
        None,
        Vec::new(),
    );
    e_c_out.entry.proposal.legs[0].account_ref = inv_cap_vid;
    tag_party(&mut e_c_out, invc_val);

    // --- 2. Preference payments & §547(c)(1), (c)(2), (c)(4) defenses for VEND-PREF ---
    // Baseline payment before the 90-day window (Jan 10, doc_date Dec 11 -> 30 days to pay)
    let mut e_pref_base = make_snapshot_entry(
        &mut h,
        VId(97_008),
        CommitSeq(708),
        day(2026, 1, 10),
        &jan,
        EntryClass::ORIGINAL,
        vec![
            ("2000", Side::Debit, usd, 25_000),
            ("1000", Side::Credit, usd, 25_000),
        ],
        Vec::new(),
        None,
        Some(day(2025, 12, 11)),
        None,
        Vec::new(),
    );
    tag_party(&mut e_pref_base, vend_val);

    // Preference window [Jan 30, Apr 30]:
    // (a) §547(c)(1) contemporaneous exchange: paid Mar 5, doc_date Mar 2 (3 days <= 5) -> 20_000
    let mut e_pref_c1 = make_snapshot_entry(
        &mut h,
        VId(97_009),
        CommitSeq(709),
        day(2026, 3, 5),
        &mar,
        EntryClass::ORIGINAL,
        vec![
            ("2000", Side::Debit, usd, 20_000),
            ("1000", Side::Credit, usd, 20_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 3, 2)),
        None,
        Vec::new(),
    );
    tag_party(&mut e_pref_c1, vend_val);

    // (b) §547(c)(2) ordinary course: paid Mar 20, doc_date Feb 16 (32 days vs 30 baseline, diff 2 <= 15) -> 35_000
    let mut e_pref_c2 = make_snapshot_entry(
        &mut h,
        VId(97_010),
        CommitSeq(710),
        day(2026, 3, 20),
        &mar,
        EntryClass::ORIGINAL,
        vec![
            ("2000", Side::Debit, usd, 35_000),
            ("1000", Side::Credit, usd, 35_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 2, 16)),
        None,
        Vec::new(),
    );
    tag_party(&mut e_pref_c2, vend_val);

    // (c) Unprotected late payment: paid Apr 10, doc_date Jan 25 (75 days > 30 + 15) -> 100_000
    let mut e_pref_unprot = make_snapshot_entry(
        &mut h,
        VId(97_011),
        CommitSeq(711),
        day(2026, 4, 10),
        &apr,
        EntryClass::ORIGINAL,
        vec![
            ("2000", Side::Debit, usd, 100_000),
            ("1000", Side::Credit, usd, 100_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 25)),
        None,
        Vec::new(),
    );
    tag_party(&mut e_pref_unprot, vend_val);

    // (d) §547(c)(4) subsequent new value: unpaid credit invoice on Apr 18 after the Apr 10 payment -> 40_000
    let mut e_pref_c4 = make_snapshot_entry(
        &mut h,
        VId(97_012),
        CommitSeq(712),
        day(2026, 4, 18),
        &apr,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 40_000),
            ("2000", Side::Credit, usd, 40_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 4, 18)),
        None,
        Vec::new(),
    );
    tag_party(&mut e_pref_c4, vend_val);

    // --- 3. Insider preference & fraudulent transfer to INSIDER-P ---
    // Uncorroborated round transfer of 50_000 to INSIDER-P on Apr 25 while insolvent (4 badges of fraud)
    let mut e_fraud = make_snapshot_entry(
        &mut h,
        VId(97_013),
        CommitSeq(713),
        day(2026, 4, 25),
        &apr,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 50_000),
            ("1000", Side::Credit, usd, 50_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 1, 1)),
        None,
        Vec::new(),
    );
    e_fraud.entry.proposal.evidence.clear();
    e_fraud.entry.proposal.description = seal("xfer", 35);
    tag_party(&mut e_fraud, insider_val);

    snapshot.entries = vec![
        e_win_in,
        e_win_out,
        e_a_in,
        e_b_in,
        e_b_out,
        e_c_in,
        e_c_out,
        e_pref_base,
        e_pref_c1,
        e_pref_c2,
        e_pref_unprot,
        e_pref_c4,
        e_fraud,
    ];

    // Add a counterfactual baseline RegisterEquals attestation on Revenue (4000) in Apr claiming 125_000
    let rev_claim = RegisterEqualsClaim {
        account: h.account("4000"),
        unit_id: usd.0,
        period: apr.clone(),
        entity: None,
        mantissa: -125_000,
        as_of_effective: day(2026, 4, 30),
        evaluated_known_at: CommitSeq(720),
        fold_digest: [0x11; 32],
    };
    let rev_cell = rev_claim.cell_digest();
    snapshot.attestations.insert(
        VId(97_500),
        StoredAttestation {
            attestation: Attestation {
                book_id: h.book.book_id,
                claim: AttestationClaim::RegisterEquals(rev_claim),
                subject: Subject::Cell(rev_cell),
                principal: REVIEWER,
                evidence_refs: Vec::new(),
            },
            signed_digest: [0x22; 32],
            binding: CapabilityBinding {
                profile: Profile::Human,
                capability_commitment: [0x33; 32],
            },
        },
    );

    // 1. Balance-sheet solvency test
    let bs_proc = SolvencyBalanceSheetTest::new().unwrap();
    let r_bs = run_over(&snapshot, &h.book, &bs_proc).unwrap();
    assert_eq!(r_bs.findings.len(), 1);
    assert_eq!(r_bs.findings[0].severity, Severity::Critical);
    assert_eq!(r_bs.findings[0].statistic.name, "insolvency_deficit");
    assert!(
        witness::determinism(&snapshot, &h.book, &bs_proc)
            .unwrap()
            .deterministic()
    );

    // 2. Cash-flow solvency test
    let cf_proc = SolvencyCashFlowTest::new().unwrap();
    let r_cf = run_over(&snapshot, &h.book, &cf_proc).unwrap();
    assert_eq!(r_cf.findings.len(), 1);
    assert_eq!(r_cf.findings[0].severity, Severity::High);
    assert_eq!(r_cf.findings[0].statistic.name, "cash_flow_shortfall");
    assert!(
        witness::determinism(&snapshot, &h.book, &cf_proc)
            .unwrap()
            .deterministic()
    );

    // 3. Avoidable preferences with §547(c)(1), (c)(2), and (c)(4) defenses
    let pref_proc = LookbackPreferences::new().unwrap();
    let r_pref = run_over(&snapshot, &h.book, &pref_proc).unwrap();
    let vend_finding = r_pref
        .findings
        .iter()
        .find(|f| f.narrative.contains("VEND-PREF"))
        .expect("VEND-PREF preference finding");
    // Gross = 20_000 + 35_000 + 100_000 = 155_000; c1 = 20_000; c2 = 35_000; c4 = 40_000 => net = 60_000
    assert_eq!(vend_finding.statistic.value, 60_000);
    assert!(vend_finding.narrative.contains("gross_preference=155000"));
    assert!(vend_finding.narrative.contains("c1_contemporaneous=20000"));
    assert!(vend_finding.narrative.contains("c2_ordinary_course=35000"));
    assert!(vend_finding.narrative.contains("c4_new_value=40000"));
    assert!(
        r_pref
            .findings
            .iter()
            .any(|f| f.narrative.contains("INSIDER-P (insider=true)")),
        "insider transfer flagged with insider=true"
    );
    assert!(
        witness::determinism(&snapshot, &h.book, &pref_proc)
            .unwrap()
            .deterministic()
    );

    // 4. Fraudulent transfer lookback (§548 & UVTA)
    let ft_proc = LookbackFraudulentTransfer::new().unwrap();
    let r_ft = run_over(&snapshot, &h.book, &ft_proc).unwrap();
    assert!(
        r_ft.findings
            .iter()
            .any(|f| f.cites.contains(&Cite::Entry(VId(97_013)))
                && f.severity == Severity::Critical
                && f.statistic.value == 50_000)
    );
    assert!(
        witness::determinism(&snapshot, &h.book, &ft_proc)
            .unwrap()
            .deterministic()
    );

    // 5. Ponzi net-investment schedule (Madoff net-equity method)
    let ponzi_proc = PonziNetInvestment::new().unwrap();
    let r_ponzi = run_over(&snapshot, &h.book, &ponzi_proc).unwrap();
    let win_f = r_ponzi
        .findings
        .iter()
        .find(|f| f.narrative.contains("INV-WIN"))
        .expect("INV-WIN finding");
    assert_eq!(win_f.statistic.name, "fictitious_profit_clawback");
    assert_eq!(win_f.statistic.value, 40_000);
    for (code, expected_claim) in [("INV-A", 100_000), ("INV-B", 50_000), ("INV-C", 20_000)] {
        let f = r_ponzi
            .findings
            .iter()
            .find(|f| f.narrative.contains(code))
            .expect(code);
        assert_eq!(f.statistic.name, "net_equity_claim");
        assert_eq!(f.statistic.value, expected_claim);
    }
    assert!(
        witness::determinism(&snapshot, &h.book, &ponzi_proc)
            .unwrap()
            .deterministic()
    );

    // 6. Rising-tide distribution (SEC v. Huber) vs Pro-rata distribution (Cunningham v. Brown)
    // Pool = 70_000 across INV-A (0% recovered), INV-B (50% recovered), INV-C (80% recovered).
    let rt_proc = DistributionRisingTide::with(
        Params::defaults(DistributionRisingTide::ID)
            .unwrap()
            .set("distributable_pool", 70_000)
            .unwrap(),
    );
    let r_rt = run_over(&snapshot, &h.book, &rt_proc).unwrap();
    let rt_by_inv = |code: &str| -> i128 {
        r_rt.findings
            .iter()
            .find(|f| f.narrative.contains(code))
            .expect(code)
            .statistic
            .value
    };
    assert_eq!(rt_by_inv("INV-A"), 60_000);
    assert_eq!(rt_by_inv("INV-B"), 10_000);
    assert_eq!(rt_by_inv("INV-C"), 0);
    assert_eq!(
        rt_by_inv("INV-A") + rt_by_inv("INV-B") + rt_by_inv("INV-C"),
        70_000
    );
    assert!(
        witness::determinism(&snapshot, &h.book, &rt_proc)
            .unwrap()
            .deterministic()
    );

    let pr_proc = DistributionProRata::with(
        Params::defaults(DistributionProRata::ID)
            .unwrap()
            .set("distributable_pool", 70_000)
            .unwrap(),
    );
    let r_pr = run_over(&snapshot, &h.book, &pr_proc).unwrap();
    let pr_by_inv = |code: &str| -> i128 {
        r_pr.findings
            .iter()
            .find(|f| f.narrative.contains(code))
            .expect(code)
            .statistic
            .value
    };
    assert_eq!(pr_by_inv("INV-A"), 41_177);
    assert_eq!(pr_by_inv("INV-B"), 20_588);
    assert_eq!(pr_by_inv("INV-C"), 8_235);
    assert_eq!(
        pr_by_inv("INV-A") + pr_by_inv("INV-B") + pr_by_inv("INV-C"),
        70_000
    );
    assert!(
        witness::determinism(&snapshot, &h.book, &pr_proc)
            .unwrap()
            .deterministic()
    );

    // 7. But-for damages schedule (both single-snapshot and scenario scratch-book comparison)
    let bf_proc = DamagesButFor::new().unwrap();
    let r_bf = run_over(&snapshot, &h.book, &bf_proc).unwrap();
    assert_eq!(r_bf.findings.len(), 1);
    assert_eq!(r_bf.findings[0].statistic.name, "but_for_damages_delta");
    assert_eq!(r_bf.findings[0].statistic.value, 125_000);
    assert!(
        witness::determinism(&snapshot, &h.book, &bf_proc)
            .unwrap()
            .deterministic()
    );

    let mut scenario_snap = snapshot.clone();
    let e_counterfactual = make_snapshot_entry(
        &mut h,
        VId(97_999),
        CommitSeq(799),
        day(2026, 4, 28),
        &apr,
        EntryClass::ORIGINAL,
        vec![
            ("1000", Side::Debit, usd, 125_000),
            ("4000", Side::Credit, usd, 125_000),
        ],
        Vec::new(),
        None,
        Some(day(2026, 4, 28)),
        None,
        Vec::new(),
    );
    scenario_snap.entries.push(e_counterfactual);
    let scenario_findings =
        compute_scenario_but_for_damages(&snapshot, &scenario_snap, &h.book).unwrap();
    assert_eq!(scenario_findings.len(), 2);
    assert!(
        scenario_findings
            .iter()
            .all(|f| f.statistic.value == 125_000)
    );
}
