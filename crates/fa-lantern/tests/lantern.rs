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
use fa_lantern::jet::{
    PeriodEndTiming, PostClosing, RoundAmounts, SelfApproved, ThinDescriptions, Weekend,
};
use fa_lantern::numbers::SequenceGaps;
use fa_lantern::projection::{documents, money_flow, preparers};
use fa_lantern::witness::determinism;
use fa_lantern::{
    Cite, Finding, LanternError, Params, Procedure, ProcedureRun, Severity, Snapshot, Statistic,
    Work, run, run_over,
};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, ExternalId, Id128,
    LegPayload, Oid, SealKey, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::lantern as naive;
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

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
        let date = day(2026, 1, 1);
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
                    date,
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
        Snapshot::read(&self.db, &self.book, None).expect("snapshot")
    }

    fn run(&self, p: &dyn Procedure) -> ProcedureRun {
        run(&self.db, &self.book, None, p).expect("run")
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
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
    runtime
        .block_on(async { create_periods(&mut db, &ctx, &book, 2026).await })
        .expect("periods");
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

/// The planted corpus: eighteen Original entries. 2026-01-01 is a Thursday,
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
    // 13: self-approved; 14: reviewed (the control).
    let mut own = Spec::simple(day(2026, 3, 10), "6000", "1000", 30_000);
    own.self_approve = true;
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
    Corpus {
        specs: s,
        round: [1].into(),
        weekend: [0, 12].into(),
        period_end: [3].into(),
        post_closing: [15].into(),
        self_approved: [13].into(),
        thin: [2].into(),
        same_same_same: vec![vec![7, 8]],
        same_same_different: vec![(7, 9), (8, 9)],
        sequence_gap_missing: vec![2],
        cutoff: [11].into(),
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
    assert_eq!(r.findings[0].severity, Severity::High);
    assert!(
        r.findings[0]
            .cites
            .iter()
            .any(|c| matches!(c, Cite::Approval(_))),
        "the self-approval is cited by handle"
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
    let legs = 2 * c.specs.len() as u64;
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
    let counts = naive::first_digit_counts(&rows);
    assert_eq!(counts.iter().sum::<u64>(), legs);
    assert_eq!(f.statistic.value, naive::benford_mad_1e9(&counts));
    assert_eq!(
        fa_lantern::digits::mad_1e9(&counts).unwrap(),
        f.statistic.value
    );
}

#[test]
fn aging_buckets_open_items_to_the_declared_date() {
    let (h, _) = posted_corpus();
    // Ages at 2026-04-30: entry 16 (Jan 8) 112 days, 17 (Feb 20) 69 days,
    // 10 (Mar 5) 56 days.
    let r = h.run(&OpenItemsAging::new(day(2026, 4, 30)).unwrap());
    h.assert_cites_resolve(&r);
    assert_eq!(
        r.inputs,
        vec![("as_of".to_string(), "2026-04-30".to_string())]
    );
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
    assert_eq!(
        r.findings.len(),
        6,
        "every account with an open leg gets one finding"
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
            &OpenItemsAging::with(bad, day(2026, 4, 30))
        ),
        Err(LanternError::Parameter { .. })
    ));
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
        Box::new(OpenItemsAging::new(day(2026, 4, 30)).unwrap()),
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
        let again = run(&h.db, &h.book, None, p.as_ref()).unwrap();
        assert_eq!(again.findings_digest, w.digest);
        // Work stays inside the registered bounds.
        let n = snapshot.entries.len() as u64;
        assert!(
            again.work.entries <= n,
            "{}: {:?}",
            again.procedure,
            again.work
        );
        assert!(
            again.work.legs <= 4 * n,
            "{}: {:?}",
            again.procedure,
            again.work
        );
        assert!(
            again.work.comparisons <= n * n,
            "{}: {:?}",
            again.procedure,
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
    // Receivables 0.34: each credit allocates 16.5/16.5/17 cents, and the
    // largest-remainder law hands the residual cent to the lowest index.
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
    assert_eq!(edge("1000", "6000"), Some((3000 + 17, 2, jan.clone())));
    assert_eq!(edge("1000", "7000"), Some((7000 + 16, 2, jan.clone())));
    assert_eq!(edge("1000", "1200"), Some((17, 1, jan.clone())));
    assert_eq!(edge("2000", "6000"), Some((17, 1, jan.clone())));
    assert_eq!(edge("2000", "7000"), Some((16, 1, jan.clone())));
    assert_eq!(edge("2000", "1200"), Some((17, 1, jan)));
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
