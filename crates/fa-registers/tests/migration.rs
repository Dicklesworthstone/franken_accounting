//! Migration runs against the reference oracle (plan §8.6, bead fa-xo0).
//!
//! A seeded history of runs — opened over a declared legacy trial balance,
//! staged chunk by chunk, finalized under two approvals or abandoned and
//! retried under a new key — interleaved with ordinary trunk posts, is
//! applied to the real kernel on the substrate and to the oracle. Every
//! verdict must agree, and at every recorded known-at coordinate the
//! kernel's folds of the Opening period and of P01 must equal the oracle's
//! literal folds under the FA-INV-07 migration predicate: a chunk counts
//! only where its run is finalized. Crash points (lab VFS) show the
//! activation is all or nothing.

use std::collections::BTreeMap;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{Document, add_document};
use fa_journal::migration::{kind, read_run};
use fa_journal::*;
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, EvidenceRef, Id128,
    LegPayload, Oid, PeriodRef, SealKey, Settlement, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::{
    Account, FullDetailSpec, Intent, Known, Leg, Limit, Oracle, RunSpec, TrialBalance, Verdict,
};
use fa_registers::fold_period_at;
use fa_time::{DateDay, FiscalCalendar, PeriodState, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(7);
const BOB: VId = VId(8);
const CAROL: VId = VId(9);
const OPENING: &str = "FY2026-OPEN";
const P01: &str = "FY2026-P01";
/// Accounts a chunk may move; "1500" is limited (a staged chunk never
/// moves a limit in this slice).
const FREE: [&str; 6] = ["1000", "1200", "2000", "3000", "4000", "6000"];

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

struct Kernel {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    vfs: MemVfs,
    /// The legacy trial balance document (Spreadsheet, HumanUpload).
    tb: EvidenceRef,
}

impl Kernel {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
}

fn db_keys() -> DatabaseKeys {
    DatabaseKeys::new(
        [0x6a; 32],
        DatabaseSecurityNamespaceId([0x6b; 32]),
        [0x6c; 32],
    )
}

fn usd() -> UnitId {
    UnitRegistry::with_defaults().lookup("USD").unwrap()
}

fn opening_date() -> DateDay {
    DateDay::from_ymd(2026, 1, 1).unwrap()
}

/// A book with the chart, FY2026's periods, FY2026-OPEN locked (Migration
/// is admissible only there) and P01 open, and the trial balance document.
fn setup() -> (Kernel, Oracle) {
    setup_with(None)
}

/// The fixture book. `go_live`: the book's opening date (plan §7.2) and the
/// live period it starts, which is the one opened; every Normal period before
/// it is born Historical and Locked. `None`: no opening date, and P01 opens.
fn setup_with(go_live: Option<(DateDay, &str)>) -> (Kernel, Oracle) {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let vfs = MemVfs::new().expect("memory filesystem");
    let dir = vfs.database_dir();
    let mut db = runtime
        .block_on(async {
            Database::create_with_vfs(&ctx.commit(), vfs.clone(), dir, db_keys()).await
        })
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([0x6d; 16]);
    let spec = BookSpec {
        book_id,
        name: "Migration Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: go_live.map(|(day, _)| day),
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
        .expect("create_book");
    let book = BookContext {
        book_id,
        calendar: calendar.clone(),
        units,
        seal_key: SealKey([0x11; 32]),
        symbols,
    };
    let mut chart: Vec<AccountSpec> = FREE
        .iter()
        .map(|code| {
            let (ty, normal) = match &code[..1] {
                "1" => (1, 0),
                "2" => (2, 1),
                "3" => (3, 1),
                "4" => (4, 1),
                _ => (5, 0),
            };
            AccountSpec {
                code: (*code).into(),
                name: (*code).into(),
                account_type: ty,
                normal_balance: normal,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            }
        })
        .collect();
    chart.push(AccountSpec {
        code: "1500".into(),
        name: "1500".into(),
        account_type: 1,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: Some(BalanceLimit {
            lower: Some(0),
            upper: None,
            scope: LimitScope::Lifetime,
        }),
    });
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PRINCIPAL,
                opening_date(),
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
    let tb_doc = Document {
        book_id,
        kind: 18,
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"account,unit,net\nlegacy trial balance (migration fixture)\n".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &tb_doc).await })
        .expect("kernel")
        .expect("the trial balance document is admitted");
    let mut k = Kernel {
        runtime,
        root,
        db,
        book,
        vfs,
        tb: tb_doc.evidence_ref(1),
    };
    let mut oracle = Oracle::new(calendar);
    for code in FREE.iter().chain(["1500"].iter()) {
        oracle.add_account(Account {
            code: (*code).into(),
            is_leaf: true,
            unit: Some(usd.0),
        });
    }
    oracle.set_limit(
        "1500",
        Limit {
            normal: fa_reference::Side::Debit,
            lower: Some(0),
            upper: None,
            per_period: false,
        },
    );
    if let Some((day, _)) = go_live {
        oracle.set_opening_date(day);
    }
    oracle.create_periods(2026);
    // The Opening period is Locked for the run: walked there when it is a
    // live period, born Locked when it precedes the book's opening date
    // (the pre_opening rule, ruling 3685).
    let born_locked = oracle.period_state(OPENING) == Some(PeriodState::Locked);
    let transitions = if born_locked {
        Vec::new()
    } else {
        vec![
            PeriodTransition::Open,
            PeriodTransition::SoftClose,
            PeriodTransition::Close,
            PeriodTransition::Lock,
        ]
    };
    for (i, t) in transitions.into_iter().enumerate() {
        transition(&mut k, OPENING, t, &format!("lock-opening-{i}"));
        oracle.transition(OPENING, t).expect("oracle");
    }
    let live = go_live.map_or(P01, |(_, code)| code);
    transition(&mut k, live, PeriodTransition::Open, "open-live");
    oracle
        .transition(live, PeriodTransition::Open)
        .expect("oracle");
    (k, oracle)
}

fn transition(k: &mut Kernel, code: &str, t: PeriodTransition, key: &str) {
    // Lock is dual-controlled (sod_policy.toml): Bob approves exactly the
    // proposal this transition commits. Lock is legal only from Closed.
    let approvals = if matches!(t, PeriodTransition::Lock) {
        let digest = transition_proposal(
            &k.book,
            code,
            PeriodState::Closed,
            PeriodState::Locked,
            PRINCIPAL,
            1,
            opening_date(),
            key.as_bytes(),
            sealed(&k.book, "period"),
        )
        .proposal_digest()
        .expect("digest");
        approve_by(k, digest, &[BOB])
    } else {
        Vec::new()
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    let desc = sealed(book, "period");
    k.runtime
        .block_on(async move {
            transition_period(
                db,
                &ctx,
                book,
                code,
                t,
                PRINCIPAL,
                1,
                opening_date(),
                key.as_bytes(),
                desc,
                &capability(&["close"]),
                &approvals,
            )
            .await
        })
        .expect("kernel")
        .expect("transition");
}

/// Sealed with fixed salt and nonce, so a retried proposal is byte-identical.
fn sealed(book: &BookContext, text: &str) -> Erasable<String> {
    Erasable::seal(&text.to_string(), None, &book.seal_key, [1; 32], [2; 24])
}

fn leg(side: fa_reference::Side, account: &str, mantissa: i128) -> Leg {
    Leg {
        side,
        account: account.into(),
        unit: usd().0,
        entity: None,
        mantissa,
    }
}

fn chunk_intent(key: &str, legs: Vec<Leg>) -> Intent {
    Intent {
        class: "Migration".into(),
        date: opening_date(),
        discriminator: Some(OPENING.into()),
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into(), "migrate".into()],
        approvals: 2,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    }
}

fn trunk_intent(key: &str, legs: Vec<Leg>) -> Intent {
    Intent {
        class: "Original".into(),
        date: DateDay::from_ymd(2026, 1, 15).unwrap(),
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    }
}

fn body_of(k: &Kernel, spec: &RunSpec) -> RunBody {
    RunBody {
        book_id: k.book.book_id,
        run_key: spec.key.clone(),
        source_system: "legacy-gl".into(),
        mode: if spec.full_detail.is_some() {
            RunMode::FullDetail
        } else if spec.periods.is_empty() {
            RunMode::OpeningOnly
        } else {
            RunMode::PeriodBalances
        },
        trial_balance: k.tb.document_oid,
        opening_date: spec.opening_date,
        lines: spec
            .lines
            .iter()
            .map(|(a, u, m)| TrialBalanceLine {
                account_code: a.clone(),
                unit: UnitId(*u),
                mantissa: *m,
            })
            .collect(),
        // Each elapsed period's trial balance is stated in the fixture
        // document too (one document may state several).
        periods: spec
            .periods
            .iter()
            .map(|(code, lines)| PeriodBalance {
                period_code: code.clone(),
                trial_balance: k.tb.document_oid,
                lines: lines
                    .iter()
                    .map(|(a, u, m)| TrialBalanceLine {
                        account_code: a.clone(),
                        unit: UnitId(*u),
                        mantissa: *m,
                    })
                    .collect(),
            })
            .collect(),
        detail_base: spec
            .full_detail
            .as_ref()
            .map(|f| {
                f.detail_base
                    .iter()
                    .map(|(a, u, m)| TrialBalanceLine {
                        account_code: a.clone(),
                        unit: UnitId(*u),
                        mantissa: *m,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        sole_opening_source: spec.full_detail.as_ref().is_some_and(|f| f.sole),
    }
}

/// A trial balance in USD from `(account, net in debit sign)`, zero lines
/// omitted, ascending by account.
fn usd_lines(nets: &[(&str, i128)]) -> Vec<(String, u32, i128)> {
    let mut out: Vec<(String, u32, i128)> = nets
        .iter()
        .filter(|(_, m)| *m != 0)
        .map(|(a, m)| ((*a).to_string(), usd().0, *m))
        .collect();
    out.sort();
    out
}

/// Create fiscal year `fy`'s periods on both sides.
fn create_year(k: &mut Kernel, oracle: &mut Oracle, fy: i32) {
    let ctx = k.ctx();
    let (db, book) = (&mut k.db, &k.book);
    k.runtime
        .block_on(async move { create_periods(db, &ctx, book, fy).await })
        .expect("periods");
    oracle.create_periods(fy);
}

fn capability(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).expect("registered ops")
}

/// Bob and Carol (Humans, `approve`) approve `digest`.
fn approve(k: &mut Kernel, digest: [u8; 32]) -> Vec<ApprovalRef> {
    approve_by(k, digest, &[BOB, CAROL])
}

/// Each of `approvers` (Humans, `approve`) approves `digest`.
fn approve_by(k: &mut Kernel, digest: [u8; 32], approvers: &[VId]) -> Vec<ApprovalRef> {
    let mut out = Vec::new();
    for &who in approvers {
        let ctx = k.ctx();
        let db = &mut k.db;
        let book = &k.book;
        let req = ApprovalRequest {
            capability: Capability::embedded(who, &["approve"]).expect("approve"),
            approved_proposal_digest: digest,
            role: 0,
        };
        let approved = k
            .runtime
            .block_on(async move { record_approval(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("approval recorded");
        out.push(approved.approval());
    }
    out
}

fn kernel_open(
    k: &mut Kernel,
    spec: &RunSpec,
    key: &str,
    ops: &[&str],
) -> Result<RunControlled, Refusal> {
    let body = body_of(k, spec);
    let proposal = open_proposal(
        &k.book,
        PRINCIPAL,
        &body,
        vec![k.tb],
        key.as_bytes(),
        sealed(&k.book, "open run"),
    )
    .expect("proposal");
    let req = RunControlRequest {
        proposal,
        capability: capability(ops),
        approvals: Vec::new(),
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { open_run(db, &ctx, book, &body, req).await })
        .expect("kernel")
}

/// How a planted chunk departs from a well-formed one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Chunk,
    /// Migration class with an ordinary Intent origin: no run named.
    NoRun,
    /// An Original carrying migration provenance.
    ProvenanceOnOriginal,
}

fn chunk_payload(
    k: &Kernel,
    run: VId,
    intent: &Intent,
    shape: Shape,
    legacy_ns: Option<i64>,
) -> EntryPayload {
    let legs: Vec<LegPayload> = intent
        .legs
        .iter()
        .map(|l| {
            LegPayload::simple(
                if l.side == fa_reference::Side::Debit {
                    Side::Debit
                } else {
                    Side::Credit
                },
                account_vid(k.book.book_id, &l.account),
                Amount::new(usd(), l.mantissa),
            )
        })
        .collect();
    let unit_totals = EntryPayload::fold_unit_totals(&legs).expect("small amounts");
    let origin = match shape {
        Shape::NoRun => EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        Shape::Chunk | Shape::ProvenanceOnOriginal => EntryOrigin::Migration {
            run_ref: run,
            source_system: "legacy-gl".into(),
            source_id: Erasable::seal(
                &format!("JE-{}", String::from_utf8_lossy(&intent.key)),
                None,
                &k.book.seal_key,
                [3; 32],
                [4; 24],
            ),
            source_recorded_at_ns: legacy_ns,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: Oid([5; 32]),
        },
    };
    EntryPayload {
        schema_minor: 0,
        book_id: k.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::from_name(&intent.class).expect("registered class"),
        effective_date: intent.date,
        document_date: None,
        description: sealed(&k.book, "migrated"),
        effective_period: intent.discriminator.as_ref().map(|c| PeriodRef {
            calendar: "cal".into(),
            code: c.clone(),
        }),
        legs,
        control: None,
        unit_totals,
        base_totals: None,
        idempotency_key: intent.key.clone(),
        origin,
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![k.tb],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

fn kernel_post(
    k: &mut Kernel,
    proposal: EntryPayload,
    ops: &[&str],
    approved: bool,
) -> Result<Posted, Refusal> {
    let approvals = if approved {
        approve(k, proposal.proposal_digest().expect("digest"))
    } else {
        Vec::new()
    };
    let req = PostRequest {
        proposal,
        approvals,
        capability: capability(ops),
        plan_certificate: None,
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
}

fn kernel_plan(k: &Kernel, run: VId, control: u8, key: &str) -> Result<EntryPayload, Refusal> {
    plan_run_transition(
        &k.db,
        &k.book,
        run,
        control,
        PRINCIPAL,
        key.as_bytes(),
        sealed(&k.book, "run transition"),
    )
    .expect("kernel")
}

fn kernel_transition(
    k: &mut Kernel,
    proposal: EntryPayload,
    approved: bool,
) -> Result<RunControlled, Refusal> {
    let approvals = if approved {
        approve(k, proposal.proposal_digest().expect("digest"))
    } else {
        Vec::new()
    };
    let req = RunControlRequest {
        proposal,
        capability: capability(&["post", "migrate"]),
        approvals,
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { transition_run(db, &ctx, book, req).await })
        .expect("kernel")
}

/// A kernel verdict and an oracle verdict must name the same outcome.
fn agree(
    step: u64,
    what: &str,
    kernel: Result<(), &'static str>,
    oracle: Result<(), &'static str>,
) {
    assert_eq!(kernel, oracle, "step {step}: {what}");
}

fn code_of<T>(r: &Result<T, Refusal>) -> Result<(), &'static str> {
    r.as_ref().map(|_| ()).map_err(|e| e.code)
}

/// What a kernel post did: posted, recorded, or refused.
fn outcome_kind(r: &Result<Posted, Refusal>) -> &'static str {
    match r {
        Ok(Posted::Committed { .. }) => "posted",
        Ok(Posted::AlreadyRecorded { .. }) => "recorded",
        Err(_) => "refused",
    }
}

/// What the oracle did, in [`outcome_kind`]'s words.
fn verdict_kind(v: &Verdict) -> &'static str {
    match v {
        Verdict::Posted { .. } => "posted",
        Verdict::Recorded { .. } => "recorded",
        Verdict::Refused { .. } => "refused",
    }
}

fn verdict_code(v: &Verdict) -> Result<(), &'static str> {
    match v {
        Verdict::Posted { .. } | Verdict::Recorded { .. } => Ok(()),
        Verdict::Refused { code } => Err(code),
    }
}

/// The kernel's fold of `period` at `seq` against the oracle's at `known`.
fn assert_fold(k: &Kernel, oracle: &Oracle, period: &str, seq: CommitSeq, known: Known, step: u64) {
    let fold = fold_period_at(&k.db, &k.book, period, Some(seq)).expect("fold");
    let codes: BTreeMap<VId, &str> = FREE
        .iter()
        .chain(["1500"].iter())
        .map(|c| (account_vid(k.book.book_id, c), *c))
        .collect();
    let kernel: BTreeMap<(String, u32), (i128, i128, u64)> = fold
        .cells
        .iter()
        .map(|c| {
            (
                (codes[&c.key.account].to_string(), c.key.unit_id),
                (c.debits, c.credits, c.entry_count),
            )
        })
        .collect();
    let model: BTreeMap<(String, u32), (i128, i128, u64)> = oracle
        .activity_known(&[period], known)
        .into_iter()
        .map(|(key, c)| {
            (
                key,
                (
                    c.debits.to_i128().unwrap(),
                    c.credits.to_i128().unwrap(),
                    c.entry_count,
                ),
            )
        })
        .collect();
    assert_eq!(
        kernel, model,
        "step {step}: {period} at {} vs {known:?}",
        seq.0
    );
}

/// A balanced run: `chunks` two-leg pairs over the free accounts; the
/// declared lines are their net per account (debit sign), zeros dropped.
fn plan_run(rng: &mut Rng, key: &str) -> (RunSpec, Vec<Vec<Leg>>) {
    loop {
        let n = 2 + rng.below(3) as usize;
        let mut chunks = Vec::new();
        let mut net: BTreeMap<String, i128> = BTreeMap::new();
        for _ in 0..n {
            let a = FREE[rng.below(6) as usize];
            let mut b = FREE[rng.below(6) as usize];
            while b == a {
                b = FREE[rng.below(6) as usize];
            }
            let x = 1 + i128::from(rng.below(50_000));
            *net.entry(a.into()).or_default() += x;
            *net.entry(b.into()).or_default() -= x;
            chunks.push(vec![
                leg(fa_reference::Side::Debit, a, x),
                leg(fa_reference::Side::Credit, b, x),
            ]);
        }
        let lines: Vec<(String, u32, i128)> = net
            .into_iter()
            .filter(|(_, m)| *m != 0)
            .map(|(a, m)| (a, usd().0, m))
            .collect();
        if !lines.is_empty() {
            return (
                RunSpec {
                    key: key.into(),
                    opening_date: opening_date(),
                    lines,
                    periods: Vec::new(),
                    full_detail: None,
                },
                chunks,
            );
        }
    }
}

struct LiveRun {
    vid: VId,
    oracle: usize,
    chunks: Vec<Vec<Leg>>,
    posted: usize,
    /// Chunk keys, reused verbatim by a retry run.
    prefix: String,
    key: String,
    /// Each posted chunk's legacy timestamp (an identical retry repeats it).
    legacy: Vec<Option<i64>>,
}

#[derive(Default)]
struct Floors {
    opened: usize,
    chunks: usize,
    finalized: usize,
    abandoned: usize,
    retried: usize,
    legacy_timestamps: usize,
    recorded: usize,
    trunk: usize,
    refused: BTreeMap<&'static str, usize>,
    known_checks: usize,
}

#[test]
fn kernel_and_oracle_agree_on_migration_runs() {
    let (mut k, mut oracle) = setup();
    let mut rng = Rng(0x00C0_FFEE_D00D_5EED);
    let mut runs: Vec<LiveRun> = Vec::new();
    let mut closed: Vec<usize> = Vec::new();
    let mut checkpoints: Vec<(CommitSeq, Known)> = Vec::new();
    let mut f = Floors::default();
    let mut retry_of: Option<String> = None;
    let mut serial = 0u64;

    for step in 0..440u64 {
        serial += 1;
        let roll = rng.below(100);
        let open_runs: Vec<usize> = (0..runs.len()).filter(|i| !closed.contains(i)).collect();
        if roll < 10 || open_runs.is_empty() {
            // Open a run; sometimes a planted refusal.
            let key = format!("run-{serial}");
            let (mut spec, chunks) = plan_run(&mut rng, &key);
            let prefix = retry_of.take().unwrap_or_else(|| format!("c{serial}"));
            let plant = rng.below(10);
            let mut ops = vec!["post", "migrate"];
            match plant {
                0 => {
                    // The declared balance does not balance (131).
                    spec.lines[0].2 += 1;
                }
                1 => spec.opening_date = DateDay::from_ymd(2026, 1, 2).unwrap(),
                2 => ops = vec!["post"],
                3 if !runs.is_empty() => {
                    // A run key already used (032).
                    spec.key = runs[rng.below(runs.len() as u64) as usize].key.clone();
                }
                _ => {}
            }
            let control_key = format!("open-{serial}");
            let kernel = kernel_open(&mut k, &spec, &control_key, &ops);
            let owned_ops: Vec<String> = ops.iter().map(|o| (*o).to_string()).collect();
            let model = oracle.open_run(&spec, control_key.as_bytes(), &owned_ops);
            agree(step, "open", code_of(&kernel), model.map(|_| ()));
            assert_eq!(
                kernel.is_ok(),
                model.is_ok(),
                "step {step}: the kernel and the oracle disagree on whether the run opened"
            );
            match kernel {
                Ok(opened) => {
                    let index = model.expect("the oracle opened it too");
                    assert_eq!(opened.to, RunState::Open);
                    f.opened += 1;
                    runs.push(LiveRun {
                        vid: opened.run,
                        oracle: index,
                        chunks,
                        posted: 0,
                        prefix,
                        key: spec.key.clone(),
                        legacy: Vec::new(),
                    });
                }
                Err(r) => refuse(&mut f, r.code),
            }
        } else if roll < 55 {
            // Post into a run: the next planned chunk, or a planted negative.
            let i = open_runs[rng.below(open_runs.len() as u64) as usize];
            let plant = rng.below(16);
            let (vid, oi) = (runs[i].vid, runs[i].oracle);
            let next = runs[i].posted;
            if next >= runs[i].chunks.len() && plant > 9 {
                continue;
            }
            let base = runs[i]
                .chunks
                .get(next)
                .cloned()
                .unwrap_or_else(|| runs[i].chunks[0].clone());
            let key = format!("{}-{next}", runs[i].prefix);
            let mut intent = chunk_intent(&key, base.clone());
            let mut shape = Shape::Chunk;
            let mut approved = true;
            let mut legacy = None;
            let mut target = (vid, Some(oi));
            let mut advances = next < runs[i].chunks.len();
            let mut planted = true;
            match plant {
                0 => {
                    intent.legs[1].mantissa += 1; // unbalanced: 001
                    intent.key = format!("bad-{serial}").into_bytes();
                    advances = false;
                }
                1 => {
                    // Dated in P02, naming no period: 132.
                    intent.date = DateDay::from_ymd(2026, 2, 10).unwrap();
                    intent.discriminator = None;
                    intent.key = format!("p02-{serial}").into_bytes();
                    advances = false;
                }
                2 if !closed.is_empty() => {
                    // Into a finalized or abandoned run: 130.
                    let c = closed[rng.below(closed.len() as u64) as usize];
                    target = (runs[c].vid, Some(runs[c].oracle));
                    intent.key = format!("late-{serial}").into_bytes();
                    advances = false;
                }
                3 => {
                    shape = Shape::NoRun;
                    intent.key = format!("norun-{serial}").into_bytes();
                    target = (vid, None);
                    advances = false;
                }
                4 => {
                    shape = Shape::ProvenanceOnOriginal;
                    intent.class = "Original".into();
                    intent.key = format!("prov-{serial}").into_bytes();
                    advances = false;
                }
                5 => {
                    // A limited account: not in this slice (102).
                    intent.legs[0].account = "1500".into();
                    intent.key = format!("lim-{serial}").into_bytes();
                    advances = false;
                }
                6 => {
                    approved = false; // 012
                    intent.approvals = 0;
                    intent.key = format!("noappr-{serial}").into_bytes();
                    advances = false;
                }
                7 if next > 0 => {
                    // An identical retry of the last chunk: the recorded outcome.
                    intent = chunk_intent(
                        &format!("{}-{}", runs[i].prefix, next - 1),
                        runs[i].chunks[next - 1].clone(),
                    );
                    legacy = runs[i].legacy[next - 1];
                    advances = false;
                }
                8 if next > 0 => {
                    // The same key with different content: 032.
                    intent = chunk_intent(
                        &format!("{}-{}", runs[i].prefix, next - 1),
                        base.iter()
                            .map(|l| Leg {
                                mantissa: l.mantissa + 1,
                                ..l.clone()
                            })
                            .collect(),
                    );
                    advances = false;
                }
                9..=11 => {
                    // A legacy timestamp long before genesis: provenance
                    // only, never recorded time (doctrine 6).
                    legacy = Some(-1_000_000_000_000_000_000);
                    planted = false;
                }
                _ => planted = false,
            }
            if !advances && !planted {
                continue;
            }
            let proposal = chunk_payload(&k, target.0, &intent, shape, legacy);
            let before = k.db.frontier().unwrap();
            let kernel = kernel_post(&mut k, proposal, &["post", "migrate"], approved);
            let model = match (shape, target.1) {
                (Shape::Chunk, Some(o)) | (Shape::ProvenanceOnOriginal, Some(o)) => {
                    oracle.post_migration(o, &intent)
                }
                _ => oracle.post(&intent),
            };
            agree(step, "chunk", code_of(&kernel), verdict_code(&model));
            assert_eq!(
                outcome_kind(&kernel),
                verdict_kind(&model),
                "step {step}: kernel {kernel:?} vs oracle {model:?}"
            );
            match &kernel {
                Ok(Posted::Committed { recorded_at, .. }) => {
                    // Recorded time is the commit's sequence, whatever the
                    // legacy system claimed.
                    assert!(*recorded_at > before, "step {step}");
                    assert_eq!(*recorded_at, k.db.frontier().unwrap());
                    if legacy.is_some() {
                        f.legacy_timestamps += 1;
                    }
                    if advances {
                        runs[i].posted += 1;
                        runs[i].legacy.push(legacy);
                        f.chunks += 1;
                    }
                }
                Ok(Posted::AlreadyRecorded { .. }) => f.recorded += 1,
                Err(r) => refuse(&mut f, r.code),
            }
        } else if roll < 72 {
            // Finalize a run.
            let i = open_runs[rng.below(open_runs.len() as u64) as usize];
            let (vid, oi) = (runs[i].vid, runs[i].oracle);
            let plant = rng.below(8);
            let key = format!("fin-{serial}");
            if plant == 0 && runs[i].posted == runs[i].chunks.len() {
                // A stale plan: planned, then a net-zero chunk lands (030).
                let stale = kernel_plan(&k, vid, kind::FINALIZE, &key).expect("plans");
                let planned = oracle.run_chunks(oi);
                let zero = chunk_intent(
                    &format!("{}-zero-{serial}", runs[i].prefix),
                    vec![
                        leg(fa_reference::Side::Debit, "1000", 7),
                        leg(fa_reference::Side::Credit, "1000", 7),
                    ],
                );
                let zero_payload = chunk_payload(&k, vid, &zero, Shape::Chunk, None);
                let posted = kernel_post(&mut k, zero_payload, &["post", "migrate"], true);
                let model = oracle.post_migration(oi, &zero);
                agree(
                    step,
                    "net-zero chunk",
                    code_of(&posted),
                    verdict_code(&model),
                );
                let kernel = kernel_transition(&mut k, stale, true);
                let ops = vec!["post".to_string(), "migrate".to_string()];
                let model = oracle.finalize_run(oi, planned, key.as_bytes(), &ops, 2);
                agree(step, "stale finalize", code_of(&kernel), model);
                if let Err(r) = kernel {
                    refuse(&mut f, r.code);
                }
                continue;
            }
            let approved = plant != 1;
            let ops = vec!["post".to_string(), "migrate".to_string()];
            match kernel_plan(&k, vid, kind::FINALIZE, &key) {
                Ok(proposal) => {
                    let planned = oracle.run_chunks(oi);
                    let kernel = kernel_transition(&mut k, proposal, approved);
                    let model = oracle.finalize_run(
                        oi,
                        planned,
                        key.as_bytes(),
                        &ops,
                        if approved { 2 } else { 0 },
                    );
                    agree(step, "finalize", code_of(&kernel), model);
                    match kernel {
                        Ok(done) => {
                            assert_eq!(done.to, RunState::Finalized);
                            assert_eq!(done.chunks.len(), planned);
                            f.finalized += 1;
                            closed.push(i);
                        }
                        Err(r) => refuse(&mut f, r.code),
                    }
                }
                Err(r) => {
                    let model =
                        oracle.finalize_run(oi, oracle.run_chunks(oi), key.as_bytes(), &ops, 2);
                    agree(step, "finalize plan", Err(r.code), model);
                    refuse(&mut f, r.code);
                }
            }
        } else if roll < 78 {
            // Abandon a run; usually retry it under a new key with the same chunk keys.
            let i = open_runs[rng.below(open_runs.len() as u64) as usize];
            let (vid, oi) = (runs[i].vid, runs[i].oracle);
            let key = format!("abn-{serial}");
            let proposal = kernel_plan(&k, vid, kind::ABANDON, &key).expect("an open run plans");
            let planned = oracle.run_chunks(oi);
            let kernel = kernel_transition(&mut k, proposal, false);
            let ops = vec!["post".to_string(), "migrate".to_string()];
            let model = oracle.abandon_run(oi, planned, key.as_bytes(), &ops);
            agree(step, "abandon", code_of(&kernel), model);
            assert_eq!(kernel.expect("abandoned").to, RunState::Abandoned);
            f.abandoned += 1;
            closed.push(i);
            if rng.chance(70) {
                retry_of = Some(runs[i].prefix.clone());
                f.retried += 1;
            }
        } else if roll < 84 && !closed.is_empty() {
            // Finalize (or abandon) a closed run again: 130 from the plan.
            let c = closed[rng.below(closed.len() as u64) as usize];
            let key = format!("again-{serial}");
            let kernel = kernel_plan(&k, runs[c].vid, kind::FINALIZE, &key);
            let ops = vec!["post".to_string(), "migrate".to_string()];
            let model = oracle.finalize_run(
                runs[c].oracle,
                oracle.run_chunks(runs[c].oracle),
                key.as_bytes(),
                &ops,
                2,
            );
            agree(step, "finalize twice", code_of(&kernel), model);
            refuse(&mut f, kernel.expect_err("a closed run never plans").code);
        } else {
            // Ordinary trunk activity in P01.
            let a = FREE[rng.below(6) as usize];
            let mut b = FREE[rng.below(6) as usize];
            while b == a {
                b = FREE[rng.below(6) as usize];
            }
            let x = 1 + i128::from(rng.below(9_000));
            let intent = trunk_intent(
                &format!("t-{serial}"),
                vec![
                    leg(fa_reference::Side::Debit, a, x),
                    leg(fa_reference::Side::Credit, b, x),
                ],
            );
            let proposal = EntryPayload {
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                ..chunk_payload(&k, VId(0), &intent, Shape::NoRun, None)
            };
            let kernel = kernel_post(&mut k, proposal, &["post"], false);
            let model = oracle.post(&intent);
            agree(step, "trunk", code_of(&kernel), verdict_code(&model));
            f.trunk += 1;
        }
        checkpoints.push((k.db.frontier().unwrap(), oracle.known()));
        if step % 20 == 19 {
            for (seq, known) in checkpoints.iter().step_by(4) {
                assert_fold(&k, &oracle, OPENING, *seq, *known, step);
                assert_fold(&k, &oracle, P01, *seq, *known, step);
                f.known_checks += 1;
            }
        }
    }
    // Every recorded coordinate, at the end.
    for (seq, known) in &checkpoints {
        assert_fold(&k, &oracle, OPENING, *seq, *known, 440);
    }
    // Abandoned runs' chunks stay journaled: their entries still read back.
    for c in &closed {
        if oracle.run_state(runs[*c].oracle) == Some(fa_reference::RunState::Abandoned)
            && runs[*c].posted > 0
        {
            let vid = fa_model::migration_entry_vid(
                k.book.book_id,
                runs[*c].vid,
                format!("{}-0", runs[*c].prefix).as_bytes(),
            );
            assert!(
                k.db.vertex(vid).unwrap().is_some(),
                "an abandoned run's chunk is journaled, never deleted"
            );
        }
    }

    // Coverage floors: every outcome the law can reach, reached repeatedly.
    let floors: [(&str, usize, usize); 9] = [
        ("runs opened", f.opened, 10),
        ("chunks staged", f.chunks, 30),
        ("runs finalized", f.finalized, 3),
        ("runs abandoned", f.abandoned, 2),
        ("retry runs reusing chunk keys", f.retried, 2),
        (
            "legacy timestamps as provenance only",
            f.legacy_timestamps,
            3,
        ),
        ("identical retries recorded", f.recorded, 3),
        ("trunk posts", f.trunk, 20),
        ("known-at comparisons", f.known_checks, 100),
    ];
    for (what, got, floor) in floors {
        assert!(got >= floor, "{what}: {got} < {floor}");
    }
    for code in [
        "FA-REF-001", // an unbalanced chunk
        "FA-REF-131", // a fold that does not tie out (or a declared balance that does not balance)
        "FA-REF-130", // a closed run: a chunk, or a second Finalize
        "FA-REF-132", // outside a run: no run, provenance on an Original, a Normal period
        "FA-REF-012", // a chunk or a Finalize without its approvals
        "FA-REF-032", // a run key reused, or a chunk key with new content
        "FA-REF-102", // a chunk on a limited account
    ] {
        let got = f.refused.get(code).copied().unwrap_or(0);
        assert!(got >= 3, "{code} planted {got} times: {:?}", f.refused);
    }
}

fn refuse(f: &mut Floors, code: &'static str) {
    *f.refused.entry(code).or_default() += 1;
}

/// Drop the handle (a crash) and reopen the store over the same in-memory
/// filesystem: exactly what committed survives.
fn crash_and_reopen(k: Kernel) -> Kernel {
    let Kernel {
        runtime,
        root,
        db,
        book,
        vfs,
        tb,
    } = k;
    drop(db);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let dir = vfs.database_dir();
    let db = runtime
        .block_on(async {
            Database::open_with_vfs(&ctx.commit(), vfs.clone(), dir, db_keys()).await
        })
        .expect("reopen after the crash");
    Kernel {
        runtime,
        root,
        db,
        book,
        vfs,
        tb,
    }
}

/// The Opening period's fold as `account → net` (debit sign), zeros dropped.
fn opening_net(k: &Kernel, at: Option<CommitSeq>) -> BTreeMap<String, i128> {
    let codes: BTreeMap<VId, &str> = FREE
        .iter()
        .map(|c| (account_vid(k.book.book_id, c), *c))
        .collect();
    fold_period_at(&k.db, &k.book, OPENING, at)
        .expect("fold")
        .cells
        .iter()
        .map(|c| (codes[&c.key.account].to_string(), c.net()))
        .filter(|(_, net)| *net != 0)
        .collect()
}

fn declared(spec: &RunSpec) -> BTreeMap<String, i128> {
    spec.lines.iter().map(|(a, _, m)| (a.clone(), *m)).collect()
}

fn post_chunk(k: &mut Kernel, run: VId, key: &str, legs: Vec<Leg>) -> Posted {
    let intent = chunk_intent(key, legs);
    let proposal = chunk_payload(k, run, &intent, Shape::Chunk, None);
    kernel_post(k, proposal, &["post", "migrate"], true).expect("the chunk stages")
}

/// Crash points around activation (fa-kjl acceptance): between chunks the
/// run stays Open and its committed chunks invisible; a Finalize staged but
/// not published changes nothing; after the Finalize publishes, the whole
/// run is visible at every known-at from its commit on, and never before.
#[test]
fn activation_is_all_or_nothing_across_crash_points() {
    let (mut k, _) = setup();
    let mut rng = Rng(0x0BAD_CAFE);
    let (spec, chunks) = plan_run(&mut rng, "crash-run");
    let run = kernel_open(&mut k, &spec, "open-crash", &["post", "migrate"])
        .expect("opens")
        .run;
    post_chunk(&mut k, run, "crash-0", chunks[0].clone());

    // Crash between chunks: chunk 1 staged in a transaction that never commits.
    let staged = fa_model::migration_entry_vid(k.book.book_id, run, b"crash-1");
    let purposes = k.ctx();
    let txn_cx = purposes.txn();
    let mut doomed = k.db.begin(&txn_cx).expect("begin");
    let mut write = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
    write.create_vertex(staged, vec![fa_model::symbols::label::ENTRY], Vec::new());
    doomed
        .write_ordered(&mut k.db, vec![write])
        .expect("staged, never committed");
    let committed = k.db.frontier().unwrap();
    drop(doomed);
    let mut k = crash_and_reopen(k);
    assert_eq!(k.db.frontier().unwrap(), committed);
    assert_eq!(
        read_run(&k.db, run, None).unwrap().unwrap().state,
        RunState::Open
    );
    let first = fa_model::migration_entry_vid(k.book.book_id, run, b"crash-0");
    assert!(
        k.db.vertex(first).unwrap().is_some(),
        "chunk 0 is journaled"
    );
    assert!(k.db.vertex(staged).unwrap().is_none(), "chunk 1 never was");
    assert!(
        opening_net(&k, None).is_empty(),
        "an Open run's chunks are invisible"
    );

    for (i, legs) in chunks.iter().enumerate().skip(1) {
        post_chunk(&mut k, run, &format!("crash-{i}"), legs.clone());
    }
    assert!(opening_net(&k, None).is_empty());

    // Crash before the Finalize publishes: the activation's compare-and-set
    // staged, then dropped.
    let proposal = kernel_plan(&k, run, kind::FINALIZE, "fin-crash").expect("ties out");
    let digest = proposal.proposal_digest().unwrap();
    let approvals = approve(&mut k, digest);
    let purposes = k.ctx();
    let txn_cx = purposes.txn();
    let mut doomed = k.db.begin(&txn_cx).expect("begin");
    let mut write = WriteBatch::new(fa_model::symbols::relation::CONTROLS);
    write.compare_and_set_vertex_property(
        run,
        fa_model::symbols::property::STATE,
        Some(fgdb_types::CanonicalScalar::Int(0)),
        fgdb_types::CanonicalScalar::Int(1),
        fgdb::WriteMismatchPolicy::AbortWrite,
    );
    doomed
        .write_ordered(&mut k.db, vec![write])
        .expect("staged, never committed");
    let before_finalize = k.db.frontier().unwrap();
    drop(doomed);
    let mut k = crash_and_reopen(k);
    assert_eq!(k.db.frontier().unwrap(), before_finalize);
    assert_eq!(
        read_run(&k.db, run, None).unwrap().unwrap().state,
        RunState::Open
    );
    assert!(opening_net(&k, None).is_empty());

    // The Finalize publishes (the same approved proposal), then a crash.
    let req = RunControlRequest {
        proposal,
        capability: capability(&["post", "migrate"]),
        approvals,
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    let done = k
        .runtime
        .block_on(async move { transition_run(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("finalized");
    assert_eq!(done.chunks.len(), chunks.len());
    let k = crash_and_reopen(k);
    assert_eq!(
        read_run(&k.db, run, None).unwrap().unwrap().state,
        RunState::Finalized
    );
    assert_eq!(
        opening_net(&k, None),
        declared(&spec),
        "the whole run, at once"
    );
    assert_eq!(
        opening_net(&k, Some(done.recorded_at)),
        declared(&spec),
        "visible from the Finalize's own commit"
    );
    assert!(
        opening_net(&k, Some(before_finalize)).is_empty(),
        "and never at an earlier known-at"
    );
    assert_eq!(
        read_run(&k.db, run, Some(before_finalize))
            .unwrap()
            .unwrap()
            .state,
        RunState::Open
    );
}

#[test]
fn migration_controls_refuse_base_totals_without_consuming_their_keys() {
    let (mut k, _) = setup();
    let (spec, _) = plan_run(&mut Rng(0x00F1_7001), "valued-control");
    let body = body_of(&k, &spec);
    let totals = || fa_model::BaseTotals {
        unit_id: usd().0,
        debits: 0,
        credits: 0,
        fx_law_oid: Oid([0x91; 32]),
        rate_doc_oids: vec![Oid([0x92; 32])],
        residual: None,
    };
    let mut proposal = open_proposal(
        &k.book,
        PRINCIPAL,
        &body,
        vec![k.tb],
        b"valued-open",
        sealed(&k.book, "open run"),
    )
    .unwrap();
    proposal.base_totals = Some(totals());
    let encoded = proposal.clone().seal(Vec::new(), None).unwrap();
    assert_eq!(
        fa_model::Entry::decode(&encoded.encode().unwrap()).unwrap(),
        encoded,
        "publication refusal preserves the existing durable decoder"
    );
    let head = k.db.frontier().unwrap();
    let req = RunControlRequest {
        proposal,
        capability: capability(&["post", "migrate"]),
        approvals: Vec::new(),
    };
    let ctx = k.ctx();
    let refusal = k
        .runtime
        .block_on(open_run(&mut k.db, &ctx, &k.book, &body, req))
        .unwrap()
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-100", exit::USAGE));
    assert!(refusal.message.contains("base_totals"), "{refusal}");
    assert_eq!(k.db.frontier().unwrap(), head);

    let run = kernel_open(&mut k, &spec, "valued-open", &["post", "migrate"])
        .expect("a native control with the same key opens")
        .run;
    let clean = kernel_plan(&k, run, kind::ABANDON, "valued-abandon").unwrap();
    let mut valued = clean.clone();
    valued.base_totals = Some(totals());
    let head = k.db.frontier().unwrap();
    let refusal = kernel_transition(&mut k, valued, false).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-100", exit::USAGE));
    assert!(refusal.message.contains("base_totals"), "{refusal}");
    assert_eq!(k.db.frontier().unwrap(), head);
    assert_eq!(
        read_run(&k.db, run, None).unwrap().unwrap().state,
        RunState::Open
    );
    kernel_transition(&mut k, clean, false).expect("the same valid transition still works");
    assert_eq!(
        read_run(&k.db, run, None).unwrap().unwrap().state,
        RunState::Abandoned
    );
}

/// An invalid final chunk (fa-kjl acceptance): Finalize refuses and names
/// the lines that do not tie out; the run is abandoned (its chunks stay
/// journaled and invisible); a retry under a new run key reuses the chunk
/// keys — the identity includes the run — and finalizes.
#[test]
fn an_invalid_final_chunk_is_abandoned_and_the_retry_finalizes() {
    let (mut k, mut oracle) = setup();
    let mut rng = Rng(0x00F1_4A11);
    let (spec, chunks) = plan_run(&mut rng, "run-a");
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let run_a = kernel_open(&mut k, &spec, "open-a", &["post", "migrate"])
        .expect("opens")
        .run;
    let oracle_a = oracle
        .open_run(&spec, b"open-a", &ops)
        .expect("oracle opens");
    let last = chunks.len() - 1;
    for (i, legs) in chunks.iter().enumerate() {
        let mut legs = legs.clone();
        if i == last {
            for l in &mut legs {
                l.mantissa += 5; // balanced, but not the legacy figure
            }
        }
        let intent = chunk_intent(&format!("chunk-{i}"), legs.clone());
        post_chunk(&mut k, run_a, &format!("chunk-{i}"), legs);
        assert!(matches!(
            oracle.post_migration(oracle_a, &intent),
            Verdict::Posted { .. }
        ));
    }
    let refused = kernel_plan(&k, run_a, kind::FINALIZE, "fin-a").expect_err("does not tie out");
    assert_eq!(refused.code, "FA-REF-131", "{refused}");
    assert_eq!(
        oracle.finalize_run(oracle_a, chunks.len(), b"fin-a", &ops, 2),
        Err("FA-REF-131")
    );
    let bad = &chunks[last][0].account;
    assert!(refused.message.contains(&format!("`{bad}`")), "{refused}");
    // Defence in depth: a Finalize built by hand, binding the run's true
    // chunk digest, approved twice, still refuses at commit (the kernel
    // refolds; it never trusts the plan).
    let run = read_run(&k.db, run_a, None).unwrap().expect("run A");
    let tie = tie_out(&k.db, &k.book, &run, k.db.frontier().unwrap()).unwrap();
    assert!(!tie.mismatches.is_empty());
    let forged = fa_journal::migration::control_proposal(
        &k.book,
        PRINCIPAL,
        run_a,
        run.body.digest().unwrap(),
        kind::FINALIZE,
        tie.digest,
        run.body.opening_date,
        b"fin-forged",
        sealed(&k.book, "run transition"),
        Vec::new(),
    );
    let r = kernel_transition(&mut k, forged, true).expect_err("the fold does not tie out");
    assert_eq!((r.code, r.exit), ("FA-REF-131", exit::REFUSAL), "{r}");
    assert_eq!(
        read_run(&k.db, run_a, None).unwrap().unwrap().state,
        RunState::Open
    );

    let abandon = kernel_plan(&k, run_a, kind::ABANDON, "abn-a").expect("an open run plans");
    let abandoned = kernel_transition(&mut k, abandon, false).expect("abandoned");
    assert_eq!(abandoned.to, RunState::Abandoned);
    oracle
        .abandon_run(oracle_a, chunks.len(), b"abn-a", &ops)
        .expect("oracle abandons");

    // The retry: a new run key, the same chunk keys.
    let mut retry = spec.clone();
    retry.key = "run-b".into();
    let run_b = kernel_open(&mut k, &retry, "open-b", &["post", "migrate"])
        .expect("opens")
        .run;
    let oracle_b = oracle
        .open_run(&retry, b"open-b", &ops)
        .expect("oracle opens");
    for (i, legs) in chunks.iter().enumerate() {
        let posted = post_chunk(&mut k, run_b, &format!("chunk-{i}"), legs.clone());
        assert!(
            matches!(posted, Posted::Committed { .. }),
            "a new run is a new identity, never the abandoned run's recorded outcome"
        );
        assert!(matches!(
            oracle.post_migration(oracle_b, &chunk_intent(&format!("chunk-{i}"), legs.clone())),
            Verdict::Posted { .. }
        ));
    }
    let before = k.db.frontier().unwrap();
    let known_before = oracle.known();
    let fin = kernel_plan(&k, run_b, kind::FINALIZE, "fin-b").expect("ties out");
    kernel_transition(&mut k, fin, true).expect("finalized");
    oracle
        .finalize_run(oracle_b, chunks.len(), b"fin-b", &ops, 2)
        .expect("oracle finalizes");

    assert_eq!(
        opening_net(&k, None),
        declared(&spec),
        "run B only, never run A"
    );
    assert_fold(
        &k,
        &oracle,
        OPENING,
        k.db.frontier().unwrap(),
        oracle.known(),
        0,
    );
    assert_fold(&k, &oracle, OPENING, before, known_before, 0);
    for i in 0..chunks.len() {
        let a =
            fa_model::migration_entry_vid(k.book.book_id, run_a, format!("chunk-{i}").as_bytes());
        assert!(
            k.db.vertex(a).unwrap().is_some(),
            "run A's chunks stay journaled"
        );
    }
    // A closed run takes nothing more: a late chunk into A is 130.
    let late = chunk_intent("late", chunks[0].clone());
    let late_payload = chunk_payload(&k, run_a, &late, Shape::Chunk, None);
    let r = kernel_post(&mut k, late_payload, &["post", "migrate"], true)
        .expect_err("an abandoned run is closed");
    assert_eq!(r.code, "FA-REF-130", "{r}");
}

fn empty_scratch(k: &Kernel) -> Database<MemVfs> {
    let ctx = k.ctx();
    k.runtime
        .block_on(async { Database::open_memory(&ctx.commit(), db_keys()).await })
        .expect("a fresh scratch database")
}

fn replay(
    k: &mut Kernel,
    target: &mut Database<MemVfs>,
    prefix: CommitSeq,
) -> Result<SeqMap, Refusal> {
    let ctx = k.ctx();
    let id = k.book.book_id;
    let (db, runtime) = (&mut k.db, &k.runtime);
    runtime
        .block_on(async move { replay_into(db, target, &ctx, id, Some(prefix)).await })
        .expect("kernel")
}

fn verify(k: &Kernel, target: &Database<MemVfs>, map: &SeqMap) -> Result<(), Refusal> {
    fa_registers::replay::verify_replay(&k.db, target, &k.book, map)
        .expect("kernel")
        .map(|_| ())
}

/// A scratch book's fold of `period` at `scratch_seq` against the oracle.
fn assert_scratch_fold(
    k: &Kernel,
    scratch: &Database<MemVfs>,
    oracle: &Oracle,
    period: &str,
    scratch_seq: CommitSeq,
    known: Known,
) {
    let codes: BTreeMap<VId, &str> = FREE
        .iter()
        .chain(["1500"].iter())
        .map(|c| (account_vid(k.book.book_id, c), *c))
        .collect();
    let fold = fold_period_at(scratch, &k.book, period, Some(scratch_seq)).expect("scratch fold");
    let got: BTreeMap<(String, u32), (i128, i128)> = fold
        .cells
        .iter()
        .map(|c| {
            (
                (codes[&c.key.account].to_string(), c.key.unit_id),
                (c.debits, c.credits),
            )
        })
        .collect();
    let want: BTreeMap<(String, u32), (i128, i128)> = oracle
        .activity_known(&[period], known)
        .into_iter()
        .map(|(key, c)| {
            (
                key,
                (c.debits.to_i128().unwrap(), c.credits.to_i128().unwrap()),
            )
        })
        .collect();
    assert_eq!(
        got, want,
        "{period} at scratch {} vs {known:?}",
        scratch_seq.0
    );
}

fn kernel_post_req(k: &mut Kernel, req: PostRequest) -> Result<Posted, Refusal> {
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
}

/// A raw substrate write (planted history fa itself never produces).
fn write_raw(k: &mut Kernel, batch: WriteBatch) {
    let ctx = k.ctx();
    let db = &mut k.db;
    k.runtime
        .block_on(async move { db.write(&ctx.commit(), batch).await })
        .expect("raw write");
}

/// Plan §15.2 against the oracle: a history of finalized and abandoned runs,
/// trunk posts, an approval recorded for a not-yet-posted proposal, and
/// maintenance commits (materialized registers) replays into a scratch book
/// at several prefixes. Every map verifies; at every recorded coordinate the
/// scratch fold at the translated sequence equals the oracle's; maintenance
/// is never replayed; the approval binds the same proposal on both books.
/// Planted: a gap, a non-monotone map, a wrong marker, shifted scratch
/// sequences (135), and history a replay does not reproduce (134).
#[test]
fn scratch_replay_equals_the_source_at_every_mapped_seq() {
    let (mut k, mut oracle) = setup();
    let mut rng = Rng(0x005C_4A7C_4E00);
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let mut checkpoints: Vec<(CommitSeq, Known)> = vec![(k.db.frontier().unwrap(), oracle.known())];
    let mut maintenance_commits = Vec::new();
    for r in 0..3 {
        let (spec, chunks) = plan_run(&mut rng, &format!("replay-run-{r}"));
        let run = kernel_open(
            &mut k,
            &spec,
            &format!("replay-open-{r}"),
            &["post", "migrate"],
        )
        .expect("opens")
        .run;
        let o = oracle
            .open_run(&spec, format!("replay-open-{r}").as_bytes(), &ops)
            .expect("oracle opens");
        checkpoints.push((k.db.frontier().unwrap(), oracle.known()));
        for (i, legs) in chunks.iter().enumerate() {
            let key = format!("replay-{r}-{i}");
            post_chunk(&mut k, run, &key, legs.clone());
            assert!(matches!(
                oracle.post_migration(o, &chunk_intent(&key, legs.clone())),
                Verdict::Posted { .. }
            ));
            checkpoints.push((k.db.frontier().unwrap(), oracle.known()));
            let amount = 100 + i128::try_from(i).unwrap();
            let trunk = trunk_intent(
                &format!("replay-t-{r}-{i}"),
                vec![
                    leg(fa_reference::Side::Debit, "6000", amount),
                    leg(fa_reference::Side::Credit, "1000", amount),
                ],
            );
            let proposal = EntryPayload {
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                ..chunk_payload(&k, VId(0), &trunk, Shape::NoRun, None)
            };
            kernel_post(&mut k, proposal, &["post"], false).expect("trunk posts");
            assert!(matches!(oracle.post(&trunk), Verdict::Posted { .. }));
            checkpoints.push((k.db.frontier().unwrap(), oracle.known()));
        }
        let finalize = r != 1;
        let control = if finalize {
            kind::FINALIZE
        } else {
            kind::ABANDON
        };
        let close_key = format!("replay-close-{r}");
        let plan = kernel_plan(&k, run, control, &close_key).expect("plans");
        kernel_transition(&mut k, plan, finalize).expect("closes");
        if finalize {
            oracle
                .finalize_run(o, chunks.len(), close_key.as_bytes(), &ops, 2)
                .expect("oracle finalizes");
        } else {
            oracle
                .abandon_run(o, chunks.len(), close_key.as_bytes(), &ops)
                .expect("oracle abandons");
        }
        checkpoints.push((k.db.frontier().unwrap(), oracle.known()));
        // Maintenance: materialize the Opening period's register.
        let fold = fa_registers::fold_period(&k.db, &k.book, OPENING).expect("fold");
        let ctx = k.ctx();
        let (db, book) = (&mut k.db, &k.book);
        let seq = k
            .runtime
            .block_on(async move { fa_registers::materialize(db, &ctx, book, &fold).await })
            .expect("materialized");
        maintenance_commits.push(seq);
        checkpoints.push((seq, oracle.known()));
        // Maintenance: the native register maintainer advances P01's cells
        // and cursor (its first call creates the RegisterState vertex, later
        // ones move its properties); once, a rebuild replaces them.
        let ctx = k.ctx();
        let (db, book) = (&mut k.db, &k.book);
        let maintained = k
            .runtime
            .block_on(async move {
                if r == 2 {
                    fa_registers::rebuild(db, &ctx, book, P01).await
                } else {
                    fa_registers::advance(db, &ctx, book, P01).await
                }
            })
            .expect("maintained");
        assert!(maintained.wrote, "every round publishes");
        maintenance_commits.push(maintained.published_at);
        checkpoints.push((maintained.published_at, oracle.known()));
    }
    // An approval recorded for a proposal not yet posted anywhere.
    let pending = trunk_intent(
        "replay-approved",
        vec![
            leg(fa_reference::Side::Debit, "1200", 4_242),
            leg(fa_reference::Side::Credit, "4000", 4_242),
        ],
    );
    let approved_proposal = EntryPayload {
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        ..chunk_payload(&k, VId(0), &pending, Shape::NoRun, None)
    };
    let approvals = approve(&mut k, approved_proposal.proposal_digest().unwrap());
    let head = k.db.frontier().unwrap();
    assert!(
        k.db.vertices_at(head)
            .unwrap()
            .iter()
            .any(|v| v.labels.contains(&fa_model::symbols::label::REGISTER_STATE)),
        "the source holds the maintainer's state"
    );

    let mut refused: BTreeMap<&'static str, usize> = BTreeMap::new();
    let prefixes = [
        checkpoints[checkpoints.len() / 3].0,
        checkpoints[2 * checkpoints.len() / 3].0,
        head,
    ];
    let mut last = None;
    for prefix in prefixes {
        let mut scratch = empty_scratch(&k);
        let map = replay(&mut k, &mut scratch, prefix).expect("replays");
        verify(&k, &scratch, &map).expect("the map verifies");
        assert!(map.pairs.iter().all(|p| p.source_seq <= prefix));
        for m in maintenance_commits.iter().filter(|m| **m <= prefix) {
            assert!(
                map.pairs.iter().all(|p| p.source_seq != *m),
                "a maintenance-only commit is never replayed"
            );
        }
        let at = scratch.frontier().unwrap();
        assert!(
            scratch
                .vertices_at(at)
                .unwrap()
                .iter()
                .all(|v| !v.labels.contains(&fa_model::symbols::label::REGISTER)),
            "no materialized register reaches a scratch book"
        );
        assert!(
            scratch
                .vertices_at(at)
                .unwrap()
                .iter()
                .all(|v| !v.labels.contains(&fa_model::symbols::label::REGISTER_STATE)),
            "no maintainer state reaches a scratch book"
        );
        // The map answers only inside [0, source_prefix].
        assert_eq!(
            map.translate(map.source_prefix),
            map.pairs.last().map(|p| p.scratch_seq)
        );
        assert_eq!(map.translate(CommitSeq(map.source_prefix.0 + 1)), None);
        for (seq, known) in checkpoints.iter().filter(|(s, _)| *s <= prefix) {
            let scratch_seq = map.translate(*seq).expect("after genesis");
            assert_scratch_fold(&k, &scratch, &oracle, OPENING, scratch_seq, *known);
            assert_scratch_fold(&k, &scratch, &oracle, P01, scratch_seq, *known);
        }

        // Planted maps (135).
        let n = map.pairs.len();
        let mut gap = map.clone();
        gap.pairs.remove(n / 2);
        let mut swapped = map.clone();
        let (a, b) = (
            swapped.pairs[n - 2].scratch_seq,
            swapped.pairs[n - 1].scratch_seq,
        );
        swapped.pairs[n - 2].scratch_seq = b;
        swapped.pairs[n - 1].scratch_seq = a;
        let mut marker = map.clone();
        marker.pairs[n / 2].source_marker[0] ^= 0xff;
        let mut shifted = map.clone();
        for p in &mut shifted.pairs {
            p.scratch_seq = CommitSeq(p.scratch_seq.0.saturating_sub(1));
        }
        for bad in [&gap, &swapped, &marker, &shifted] {
            let r = verify(&k, &scratch, bad).expect_err("a planted map");
            assert_eq!((r.code, r.exit), ("FA-REF-135", exit::VERIFICATION), "{r}");
            *refused.entry("FA-REF-135").or_default() += 1;
        }
        // At the head, a prefix moved past the source's frontier and nothing
        // else changed: the commit set through it is the same, so only the
        // frontier check sees it.
        if prefix == head {
            let mut future = map.clone();
            future.source_prefix = CommitSeq(head.0 + 1);
            let r = verify(&k, &scratch, &future).expect_err("a prefix past the frontier");
            assert_eq!((r.code, r.exit), ("FA-REF-135", exit::VERIFICATION), "{r}");
            assert!(r.message.contains("past the source frontier"), "{r}");
            *refused.entry("FA-REF-135").or_default() += 1;
        }
        last = Some((scratch, map));
    }

    // Before the book's genesis there is no book to replay: the replay is
    // refused (100), and a map claiming such a prefix is refused (135) even
    // over an empty database, where an empty map would otherwise match.
    let genesis =
        k.db.vertex(fa_journal::rows::book_root())
            .unwrap()
            .expect("the source book")
            .created_at;
    assert!(genesis.0 >= 1, "genesis is a commit");
    let before_genesis = CommitSeq(genesis.0 - 1);
    let mut nothing = empty_scratch(&k);
    let r = replay(&mut k, &mut nothing, before_genesis).expect_err("no book yet");
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    assert!(r.message.contains("precedes the book's genesis"), "{r}");
    let empty = SeqMap {
        source_book: k.book.book_id,
        source_prefix: before_genesis,
        pairs: Vec::new(),
    };
    let r = verify(&k, &nothing, &empty).expect_err("an empty map is not a scratch book");
    assert_eq!((r.code, r.exit), ("FA-REF-135", exit::VERIFICATION), "{r}");
    *refused.entry("FA-REF-135").or_default() += 1;

    // The approval recorded before the replay binds the same proposal on the
    // scratch book: posted there with it, and then on the source, the two
    // entries are the same object.
    let (mut scratch, _) = last.expect("a head replay");
    let ctx = k.ctx();
    let req = PostRequest {
        proposal: approved_proposal.clone(),
        approvals: approvals.clone(),
        capability: capability(&["post"]),
        plan_certificate: None,
    };
    let book = &k.book;
    let on_scratch = k
        .runtime
        .block_on(async { post(&mut scratch, &ctx, book, req).await })
        .expect("kernel")
        .expect("the approval holds on the scratch book");
    let req = PostRequest {
        proposal: approved_proposal,
        approvals,
        capability: capability(&["post"]),
        plan_certificate: None,
    };
    let on_source = kernel_post_req(&mut k, req).expect("and on the source");
    assert_eq!(
        on_scratch.entry_ref(),
        on_source.entry_ref(),
        "identity and digest preserved"
    );

    // History a replay does not reproduce (134): a deleted vertex (twice,
    // different objects) and a removed property — none of which fa writes.
    for planted in 0..3u128 {
        let (mut src, _) = setup();
        let mut w = WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
        if planted < 2 {
            w.create_vertex(
                VId(0xdead + planted),
                vec![fa_model::symbols::label::DOCUMENT],
                Vec::new(),
            );
        } else {
            w.set_vertex_property(
                fa_journal::rows::book_root(),
                fa_model::symbols::property::NAME,
                None,
            );
        }
        write_raw(&mut src, w);
        if planted < 2 {
            let mut d = WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
            d.delete_vertex(VId(0xdead + planted));
            write_raw(&mut src, d);
        }
        let mut scratch = empty_scratch(&src);
        let at = src.db.frontier().unwrap();
        let r = replay(&mut src, &mut scratch, at).expect_err("not reproducible");
        assert_eq!((r.code, r.exit), ("FA-REF-134", exit::FOUNDATION), "{r}");
        *refused.entry("FA-REF-134").or_default() += 1;
    }
    for code in ["FA-REF-134", "FA-REF-135"] {
        let got = refused.get(code).copied().unwrap_or(0);
        assert!(got >= 3, "{code} planted {got} times");
    }

    // The same families on maintenance are dropped, not refused: a
    // RegisterState vertex with an edge, then a property removal and the
    // edge's retirement, then the vertex's, replay to nothing.
    let (mut src, _) = setup();
    let before = src.db.frontier().unwrap();
    let state = VId(0x5747_e000);
    let root = fa_journal::rows::book_root();
    let rel = fa_model::symbols::relation::IN_BOOK;
    let eid = fa_journal::rows::edge_id(rel, state, root);
    let mut w = WriteBatch::new(rel);
    w.create_vertex(
        state,
        vec![fa_model::symbols::label::REGISTER_STATE],
        Vec::new(),
    );
    w.set_vertex_property(
        state,
        fa_model::symbols::property::NAME,
        Some(fgdb_types::CanonicalScalar::Int(1)),
    );
    w.add_edge(eid, state, root, Vec::new());
    write_raw(&mut src, w);
    let mut w = WriteBatch::new(rel);
    w.set_vertex_property(state, fa_model::symbols::property::NAME, None);
    w.delete_edge(eid);
    write_raw(&mut src, w);
    let mut w = WriteBatch::new(rel);
    w.delete_vertex(state);
    write_raw(&mut src, w);
    let mut scratch = empty_scratch(&src);
    let at = src.db.frontier().unwrap();
    assert!(at > before);
    let map = replay(&mut src, &mut scratch, at).expect("maintenance is dropped, not refused");
    assert!(map.pairs.iter().all(|p| p.source_seq <= before));
    verify(&src, &scratch, &map).expect("the map verifies");
}

/// A replay is about objects, not only totals: two books with the same
/// postings under different idempotency keys fold to identical cells but
/// hold different entries (their identities differ). One book's SeqMap
/// verifies against its own scratch replay and refuses (135) against the
/// other's, though every fold agrees — only the entry comparison sees it.
#[test]
fn a_scratch_book_with_equal_folds_but_other_entries_is_refused() {
    let build = |suffix: &str| {
        let (mut k, _) = setup();
        for i in 0..3i128 {
            let trunk = trunk_intent(
                &format!("same-{suffix}-{i}"),
                vec![
                    leg(fa_reference::Side::Debit, "6000", 500 + i),
                    leg(fa_reference::Side::Credit, "1000", 500 + i),
                ],
            );
            let proposal = EntryPayload {
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                ..chunk_payload(&k, VId(0), &trunk, Shape::NoRun, None)
            };
            kernel_post(&mut k, proposal, &["post"], false).expect("posts");
        }
        let mut scratch = empty_scratch(&k);
        let head = k.db.frontier().unwrap();
        let map = replay(&mut k, &mut scratch, head).expect("replays");
        (k, scratch, map)
    };
    let (a, a_scratch, a_map) = build("a");
    let (_b, b_scratch, _) = build("b");
    verify(&a, &a_scratch, &a_map).expect("its own replay verifies");
    let last = a_map.pairs.last().unwrap().scratch_seq;
    let fold = |db: &Database<MemVfs>| {
        fold_period_at(db, &a.book, P01, Some(last))
            .expect("fold")
            .cells
    };
    assert_eq!(fold(&a_scratch), fold(&b_scratch), "the folds agree");
    let r = verify(&a, &b_scratch, &a_map).expect_err("other objects");
    assert_eq!((r.code, r.exit), ("FA-REF-135", exit::VERIFICATION), "{r}");
    assert!(r.message.contains("different entries"), "{r}");
}

#[test]
fn maintainer_tracks_migration_visibility_across_activation_and_abandonment() {
    let (mut k, mut oracle) = setup();
    let mut rng = Rng(0x00A6_71A7_E001);
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let advance = |k: &mut Kernel| {
        let ctx = k.ctx();
        k.runtime
            .block_on(fa_registers::advance(&mut k.db, &ctx, &k.book, OPENING))
            .expect("the maintainer advances")
    };
    let mut baseline = advance(&mut k).fold;
    for r in 0..3 {
        let key = format!("maintained-run-{r}");
        let open_key = format!("maintained-open-{r}");
        let (spec, chunks) = plan_run(&mut rng, &key);
        let run = kernel_open(&mut k, &spec, &open_key, &["post", "migrate"])
            .expect("opens")
            .run;
        let o = oracle
            .open_run(&spec, open_key.as_bytes(), &ops)
            .expect("oracle opens");
        for (i, legs) in chunks.iter().enumerate() {
            let chunk_key = format!("maintained-{r}-{i}");
            post_chunk(&mut k, run, &chunk_key, legs.clone());
            assert!(matches!(
                oracle.post_migration(o, &chunk_intent(&chunk_key, legs.clone())),
                Verdict::Posted { .. }
            ));
            // One run leaves every chunk in the unread suffix; another
            // consumes each invisible chunk before its later activation.
            if r != 2 {
                let staged = advance(&mut k);
                assert!(!staged.rebuilt);
                assert_eq!(staged.fold, baseline, "Open chunks never contribute");
                assert!(
                    fa_registers::verify_period(&k.db, &k.book, OPENING)
                        .unwrap()
                        .is_green()
                );
            }
        }
        let before = k.db.frontier().unwrap();
        let known_before = oracle.known();
        let finalize = r != 0;
        let kind = if finalize {
            kind::FINALIZE
        } else {
            kind::ABANDON
        };
        let close_key = format!("maintained-close-{r}");
        let plan = kernel_plan(&k, run, kind, &close_key).expect("plans");
        let transition = kernel_transition(&mut k, plan, finalize).expect("closes");
        if finalize {
            oracle
                .finalize_run(o, chunks.len(), close_key.as_bytes(), &ops, 2)
                .expect("oracle finalizes");
        } else {
            oracle
                .abandon_run(o, chunks.len(), close_key.as_bytes(), &ops)
                .expect("oracle abandons");
        }
        let published = advance(&mut k);
        assert_eq!(published.rebuilt, finalize);
        if finalize {
            assert_eq!(published.fold.watermark, Some(transition.recorded_at));
            assert_eq!(
                published.fold,
                fold_period_at(&k.db, &k.book, OPENING, published.fold.watermark).unwrap(),
                "the contributing watermark includes migration activation"
            );
            let account = account_vid(k.book.book_id, &spec.lines[0].0);
            let explanation = fa_registers::explain_balance(&k.db, &k.book, account, OPENING, None)
                .expect("the activation has an explanation");
            assert_eq!(explanation.last_changed_at(), Some(transition.recorded_at));
            for contribution in &explanation.contributions {
                let (entry, recorded_at) = fa_journal::post::read_entry(&k.db, contribution.entry)
                    .unwrap()
                    .expect("the entry is still journaled");
                assert_eq!(contribution.recorded_at, recorded_at);
                if matches!(entry.proposal.origin, EntryOrigin::Migration { run_ref, .. } if run_ref == run)
                {
                    assert_eq!(contribution.visible_at, transition.recorded_at);
                    assert!(contribution.recorded_at < contribution.visible_at);
                }
            }
            for change in &explanation.history {
                let historical =
                    fold_period_at(&k.db, &k.book, OPENING, Some(change.recorded_at)).unwrap();
                let amounts = historical
                    .cells
                    .iter()
                    .find(|c| c.key.account == account && c.key.unit_id == change.unit_id)
                    .map_or((0, 0), |c| (c.debits, c.credits));
                assert_eq!((change.debits, change.credits), amounts);
            }
        }
        let entity = fa_registers::fold_period_by_entity(&k.db, &k.book, OPENING, None)
            .expect("entity fold");
        assert_eq!(entity.watermark, published.fold.watermark);
        if let Some(at) = entity.watermark {
            let historical = fa_registers::fold_period_by_entity(&k.db, &k.book, OPENING, Some(at))
                .expect("entity fold at its watermark");
            assert_eq!(historical.cells, entity.cells);
            assert_eq!(historical.pending, entity.pending);
            assert_eq!(historical.fold_digest, entity.fold_digest);
        }
        assert_eq!(
            published.fold,
            fold_period_at(&k.db, &k.book, OPENING, None).unwrap()
        );
        assert_fold(&k, &oracle, OPENING, before, known_before, r);
        assert_fold(
            &k,
            &oracle,
            OPENING,
            k.db.frontier().unwrap(),
            oracle.known(),
            r,
        );
        assert!(
            fa_registers::verify_period(&k.db, &k.book, OPENING)
                .unwrap()
                .is_green()
        );
        let repeated = advance(&mut k);
        assert!(!repeated.wrote, "activation contributes exactly once");
        assert_eq!(repeated.fold, published.fold);
        baseline = published.fold;
    }
}

const GO_LIVE_PERIOD: &str = "FY2026-P04";

fn go_live() -> DateDay {
    DateDay::from_ymd(2026, 4, 1).unwrap()
}

/// A chunk staged in elapsed period `period`, dated `date` inside it.
fn period_chunk(key: &str, period: Option<&str>, date: DateDay, legs: Vec<Leg>) -> Intent {
    Intent {
        date,
        discriminator: period.map(str::to_string),
        ..chunk_intent(key, legs)
    }
}

/// Stage `intent` into `run` on both sides; both must agree on the verdict.
fn stage_both(
    k: &mut Kernel,
    oracle: &mut Oracle,
    run: (VId, usize),
    intent: &Intent,
    step: u64,
    what: &str,
) -> Result<(), &'static str> {
    let proposal = chunk_payload(k, run.0, intent, Shape::Chunk, None);
    let kernel = kernel_post(k, proposal, &["post", "migrate"], true);
    let model = oracle.post_migration(run.1, intent);
    agree(step, what, code_of(&kernel), verdict_code(&model));
    code_of(&kernel)
}

/// A legacy trial balance over cash 1000, equity 3000, revenue 4000, expense
/// 6000 and payables 2000 (zero lines omitted, ascending by account).
fn tb(cash: i128, payables: i128, revenue: i128, expense: i128) -> Vec<(String, u32, i128)> {
    [
        ("1000", cash),
        ("2000", payables),
        ("3000", -10_000),
        ("4000", revenue),
        ("6000", expense),
    ]
    .into_iter()
    .filter(|(_, m)| *m != 0)
    .map(|(a, m)| (a.to_string(), usd().0, m))
    .collect()
}

/// Plan §8.6 PeriodBalances (the mid-year go-live) and §7.2 Historical
/// periods, kernel against oracle. A book going live on April 1 is born with
/// P01–P03 Historical and Locked. A PeriodBalances run stages the opening
/// balances (January 1) and one chunk per elapsed period; they are invisible
/// until Finalize, which ties out cumulatively per period; afterwards every
/// period folds as the oracle's. Planted, each reaching one check: an
/// Original in a Historical period (010, the Historical rule, not the Locked
/// matrix cell); opening a Historical period (040, the Historical rule, not
/// the state machine); a body that skips a period (100); a PeriodBalances run
/// in a book with no opening date (100); a chunk naming no period (132); a
/// chunk in a period the run does not declare (132); an OpeningOnly run's
/// chunk in a Historical period (132); and a mismatch confined to P02 (131,
/// every mismatched line naming P02) while P03's cumulative still ties out.
#[test]
fn period_balances_tie_out_cumulatively_and_historical_periods_admit_only_migration() {
    let (mut k, mut oracle) = setup_with(Some((go_live(), GO_LIVE_PERIOD)));
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    let day = |m: u8, d: u8| DateDay::from_ymd(2026, m, d).unwrap();
    let mut step = 0u64;
    let mut next = || {
        step += 1;
        step
    };

    // An Original dated in P02, a Historical period: refused by the
    // Historical rule (its cite), whatever the Locked matrix cell says.
    let original = Intent {
        date: day(2, 10),
        ..trunk_intent(
            "into-history",
            vec![leg(dr, "6000", 50), leg(cr, "1000", 50)],
        )
    };
    let payload = chunk_payload(&k, VId(0), &original, Shape::NoRun, None);
    let r =
        kernel_post(&mut k, payload, &["post"], false).expect_err("history admits only Migration");
    assert_eq!((r.code, r.exit), ("FA-REF-010", exit::SAFETY), "{r}");
    assert!(
        r.cite.contains("Historical periods admit only Migration"),
        "{r}"
    );
    assert_eq!(verdict_code(&oracle.post(&original)), Err("FA-REF-010"));

    // Opening P02: the Historical rule's refusal, not the state machine's.
    let opened = {
        let ctx = k.ctx();
        let (db, book) = (&mut k.db, &k.book);
        let desc = sealed(book, "period");
        k.runtime
            .block_on(async move {
                transition_period(
                    db,
                    &ctx,
                    book,
                    "FY2026-P02",
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    day(2, 1),
                    b"open-history",
                    desc,
                    &capability(&["close"]),
                    &[],
                )
                .await
            })
            .expect("kernel")
    };
    let r = opened.expect_err("a Historical period never transitions");
    assert_eq!(r.code, "FA-REF-040", "{r}");
    assert!(r.message.contains("is Historical"), "{r}");
    assert_eq!(
        oracle.transition("FY2026-P02", PeriodTransition::Open),
        Err("FA-REF-040")
    );

    let p01 = tb(10_500, 0, -500, 0);
    let p02 = tb(10_300, 0, -500, 200);
    let p03 = tb(10_600, 0, -800, 200);
    let spec = |key: &str, periods: Vec<(&str, TrialBalance)>| RunSpec {
        full_detail: None,
        key: key.into(),
        opening_date: opening_date(),
        lines: tb(10_000, 0, 0, 0),
        periods: periods
            .into_iter()
            .map(|(p, l)| (p.to_string(), l))
            .collect(),
    };

    // A body that skips P02 is refused at the Open (100, the history check).
    let skips = spec(
        "skips",
        vec![(P01, p01.clone()), ("FY2026-P03", p03.clone())],
    );
    let r = kernel_open(&mut k, &skips, "open-skips", &["post", "migrate"])
        .expect_err("every elapsed period, in order");
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    assert!(r.message.contains("elapsed periods"), "{r}");
    assert_eq!(
        oracle.open_run(&skips, b"open-skips", &ops),
        Err("FA-REF-100")
    );

    // Run A: P02 is short 100 of cash (parked in payables) and P03 makes it
    // good, so only P02's cumulative trial balance fails to tie out.
    let a_spec = spec(
        "mismatch",
        vec![
            (P01, p01.clone()),
            ("FY2026-P02", p02.clone()),
            ("FY2026-P03", p03.clone()),
        ],
    );
    let a = kernel_open(&mut k, &a_spec, "open-a", &["post", "migrate"])
        .expect("opens")
        .run;
    let oa = oracle
        .open_run(&a_spec, b"open-a", &ops)
        .expect("oracle opens");
    let a_chunks = [
        period_chunk(
            "a-open",
            Some(OPENING),
            opening_date(),
            vec![leg(dr, "1000", 10_000), leg(cr, "3000", 10_000)],
        ),
        period_chunk(
            "a-p01",
            Some(P01),
            day(1, 31),
            vec![leg(dr, "1000", 500), leg(cr, "4000", 500)],
        ),
        period_chunk(
            "a-p02",
            Some("FY2026-P02"),
            day(2, 28),
            vec![
                leg(dr, "6000", 200),
                leg(cr, "1000", 100),
                leg(cr, "2000", 100),
            ],
        ),
        period_chunk(
            "a-p03",
            Some("FY2026-P03"),
            day(3, 31),
            vec![
                leg(dr, "1000", 200),
                leg(dr, "2000", 100),
                leg(cr, "4000", 300),
            ],
        ),
    ];
    for intent in &a_chunks {
        let s = next();
        stage_both(&mut k, &mut oracle, (a, oa), intent, s, "run A chunk").expect("stages");
    }
    let tie = tie_out(
        &k.db,
        &k.book,
        &read_run(&k.db, a, None).unwrap().unwrap(),
        k.db.frontier().unwrap(),
    )
    .expect("tie-out");
    assert_eq!(tie.chunks.len(), 4);
    assert!(!tie.mismatches.is_empty());
    assert!(
        tie.mismatches
            .iter()
            .all(|l| l.period.as_deref() == Some("FY2026-P02")),
        "only P02 fails: {:?}",
        tie.mismatches
    );
    let r = kernel_plan(&k, a, kind::FINALIZE, "finalize-a").expect_err("P02 does not tie out");
    assert_eq!((r.code, r.exit), ("FA-REF-131", exit::REFUSAL), "{r}");
    assert!(r.message.contains("through `FY2026-P02`"), "{r}");
    assert_eq!(
        oracle.finalize_run(oa, 4, b"finalize-a", &ops, 2),
        Err("FA-REF-131")
    );
    let abandon = kernel_plan(&k, a, kind::ABANDON, "abandon-a").expect("plans");
    kernel_transition(&mut k, abandon, false).expect("abandons");
    oracle
        .abandon_run(oa, 4, b"abandon-a", &ops)
        .expect("oracle abandons");

    // Run B, well formed. Planted chunks first: no period named (132 at the
    // naming rule), a period the run does not declare (132 at the run rule).
    let b_spec = spec(
        "go-live",
        vec![(P01, p01), ("FY2026-P02", p02), ("FY2026-P03", p03)],
    );
    let b = kernel_open(&mut k, &b_spec, "open-b", &["post", "migrate"])
        .expect("opens")
        .run;
    let ob = oracle
        .open_run(&b_spec, b"open-b", &ops)
        .expect("oracle opens");
    let unnamed = period_chunk(
        "b-unnamed",
        None,
        day(1, 31),
        vec![leg(dr, "1000", 500), leg(cr, "4000", 500)],
    );
    let s = next();
    assert_eq!(
        stage_both(
            &mut k,
            &mut oracle,
            (b, ob),
            &unnamed,
            s,
            "a chunk naming no period"
        ),
        Err("FA-REF-132")
    );
    let live = period_chunk(
        "b-live",
        Some(GO_LIVE_PERIOD),
        day(4, 10),
        vec![leg(dr, "1000", 500), leg(cr, "4000", 500)],
    );
    let s = next();
    assert_eq!(
        stage_both(
            &mut k,
            &mut oracle,
            (b, ob),
            &live,
            s,
            "a chunk in an undeclared period"
        ),
        Err("FA-REF-132")
    );
    let b_chunks = [
        period_chunk(
            "b-open",
            Some(OPENING),
            opening_date(),
            vec![leg(dr, "1000", 10_000), leg(cr, "3000", 10_000)],
        ),
        period_chunk(
            "b-p01",
            Some(P01),
            day(1, 31),
            vec![leg(dr, "1000", 500), leg(cr, "4000", 500)],
        ),
        period_chunk(
            "b-p02",
            Some("FY2026-P02"),
            day(2, 28),
            vec![leg(dr, "6000", 200), leg(cr, "1000", 200)],
        ),
        period_chunk(
            "b-p03",
            Some("FY2026-P03"),
            day(3, 31),
            vec![leg(dr, "1000", 300), leg(cr, "4000", 300)],
        ),
    ];
    for intent in &b_chunks {
        let s = next();
        stage_both(&mut k, &mut oracle, (b, ob), intent, s, "run B chunk").expect("stages");
    }

    // An OpeningOnly run's chunk in a Historical period: 132 at the run rule.
    let c_spec = spec("opening-only", Vec::new());
    let c = kernel_open(&mut k, &c_spec, "open-c", &["post", "migrate"])
        .expect("opens")
        .run;
    let oc = oracle
        .open_run(&c_spec, b"open-c", &ops)
        .expect("oracle opens");
    let historical = period_chunk(
        "c-p01",
        Some(P01),
        day(1, 31),
        vec![leg(dr, "1000", 500), leg(cr, "4000", 500)],
    );
    let s = next();
    assert_eq!(
        stage_both(
            &mut k,
            &mut oracle,
            (c, oc),
            &historical,
            s,
            "OpeningOnly into history"
        ),
        Err("FA-REF-132")
    );

    // Staged: every period folds empty on both sides.
    let periods = [OPENING, P01, "FY2026-P02", "FY2026-P03"];
    for p in periods {
        let s = next();
        assert_fold(&k, &oracle, p, k.db.frontier().unwrap(), oracle.known(), s);
        assert!(
            fold_period_at(&k.db, &k.book, p, None)
                .unwrap()
                .cells
                .is_empty(),
            "{p} staged"
        );
    }

    // Finalize B: every period folds as the oracle's, and P02 is its chunk.
    let fin = kernel_plan(&k, b, kind::FINALIZE, "finalize-b").expect("ties out");
    kernel_transition(&mut k, fin, true).expect("finalizes");
    oracle
        .finalize_run(ob, 4, b"finalize-b", &ops, 2)
        .expect("oracle finalizes");
    for p in periods {
        let s = next();
        assert_fold(&k, &oracle, p, k.db.frontier().unwrap(), oracle.known(), s);
        assert!(
            !fold_period_at(&k.db, &k.book, p, None)
                .unwrap()
                .cells
                .is_empty(),
            "{p} active"
        );
    }
    let p02 = fold_period_at(&k.db, &k.book, "FY2026-P02", None).unwrap();
    let cash = p02
        .cells
        .iter()
        .find(|c| c.key.account == account_vid(k.book.book_id, "1000"))
        .expect("cash moved in P02");
    assert_eq!((cash.debits, cash.credits), (0, 200));

    // A book with no opening date has no Historical period to declare.
    let (mut plain, mut plain_oracle) = setup();
    let r = kernel_open(&mut plain, &b_spec, "open-plain", &["post", "migrate"])
        .expect_err("no opening date");
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    assert!(r.message.contains("no opening date"), "{r}");
    assert_eq!(
        plain_oracle.open_run(&b_spec, b"open-plain", &ops),
        Err("FA-REF-100")
    );
}

/// fa-kjl acceptance example: draft-to-trunk digests and approvals (plan
/// §15.2). A proposal approved in a scratch book posts there under that
/// approval. On trunk, the same proposal citing the same approval is refused
/// 017: the approval is a scratch object, not a trunk one. Recorded on trunk
/// (its identity derives from book, approver, digest and epoch, so it is the
/// same reference), it admits the proposal, and the trunk entry is the
/// scratch entry, identity and digest preserved.
#[test]
fn an_approval_recorded_in_a_scratch_book_binds_nothing_on_trunk() {
    let (mut k, _) = setup();
    let mut scratch = empty_scratch(&k);
    let head = k.db.frontier().unwrap();
    let map = replay(&mut k, &mut scratch, head).expect("replays");
    verify(&k, &scratch, &map).expect("the map verifies");
    let intent = trunk_intent(
        "draft-approved",
        vec![
            leg(fa_reference::Side::Debit, "6000", 321),
            leg(fa_reference::Side::Credit, "1000", 321),
        ],
    );
    let proposal = EntryPayload {
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        ..chunk_payload(&k, VId(0), &intent, Shape::NoRun, None)
    };
    let digest = proposal.proposal_digest().expect("digest");
    let ctx = k.ctx();
    let book = &k.book;
    let req = ApprovalRequest {
        capability: Capability::embedded(BOB, &["approve"]).expect("approve"),
        approved_proposal_digest: digest,
        role: 0,
    };
    let drafted_approval = k
        .runtime
        .block_on(async { record_approval(&mut scratch, &ctx, book, req).await })
        .expect("kernel")
        .expect("recorded in the scratch book")
        .approval();
    let req = PostRequest {
        proposal: proposal.clone(),
        approvals: vec![drafted_approval],
        capability: capability(&["post"]),
        plan_certificate: None,
    };
    let drafted = k
        .runtime
        .block_on(async { post(&mut scratch, &ctx, book, req).await })
        .expect("kernel")
        .expect("posts in the scratch book");
    let req = PostRequest {
        proposal: proposal.clone(),
        approvals: vec![drafted_approval],
        capability: capability(&["post"]),
        plan_certificate: None,
    };
    let r = kernel_post_req(&mut k, req).expect_err("the approval is not a trunk object");
    assert_eq!(r.code, "FA-REF-017", "{r}");
    let trunk_approval = approve_by(&mut k, digest, &[BOB]);
    assert_eq!(trunk_approval, vec![drafted_approval], "the same reference");
    let req = PostRequest {
        proposal,
        approvals: trunk_approval,
        capability: capability(&["post"]),
        plan_certificate: None,
    };
    let promoted = kernel_post_req(&mut k, req).expect("posts on trunk");
    assert_eq!(
        promoted.entry_ref(),
        drafted.entry_ref(),
        "identity and digest preserved from draft to trunk"
    );
}

/// Stage each chunk on both sides; every one must stage.
fn stage_all(
    k: &mut Kernel,
    oracle: &mut Oracle,
    run: (VId, usize),
    chunks: &[Intent],
    what: &str,
) {
    for (i, intent) in chunks.iter().enumerate() {
        stage_both(k, oracle, run, intent, i as u64, what).expect("stages");
    }
}

/// Finalize `run` on both sides, planned over `chunks` chunks.
fn finalize_both(k: &mut Kernel, oracle: &mut Oracle, run: (VId, usize), chunks: usize, key: &str) {
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let plan = kernel_plan(k, run.0, kind::FINALIZE, key).expect("ties out");
    kernel_transition(k, plan, true).expect("finalizes");
    oracle
        .finalize_run(run.1, chunks, key.as_bytes(), &ops, 2)
        .expect("oracle finalizes");
}

fn full_detail(
    key: &str,
    lines: TrialBalance,
    periods: Vec<(String, TrialBalance)>,
    detail_base: TrialBalance,
    sole: bool,
) -> RunSpec {
    RunSpec {
        key: key.into(),
        opening_date: opening_date(),
        lines,
        periods,
        full_detail: Some(FullDetailSpec { detail_base, sole }),
    }
}

/// A sole-source historical import keeps its year-end closing chunk visible.
/// Migration retains its own class, not the source's original accounting class;
/// an income fold must refuse that ambiguous Closing-period chunk rather than
/// silently treating its equity transfer as negative revenue.
#[test]
fn income_activity_refuses_visible_migration_in_a_closing_period() {
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    let (mut k, mut oracle) = setup_with(Some((opening_date(), P01)));
    create_year(&mut k, &mut oracle, 2025);
    let earned = usd_lines(&[("1000", 300), ("4000", -300)]);
    let periods = (1..=12)
        .map(|month| {
            (
                format!("FY2025-P{month:02}"),
                if month < 3 {
                    Vec::new()
                } else {
                    earned.clone()
                },
            )
        })
        .collect();
    let spec = full_detail("statement-history", Vec::new(), periods, Vec::new(), true);
    let run = kernel_open(
        &mut k,
        &spec,
        "open-statement-history",
        &["post", "migrate"],
    )
    .expect("opens a sole-source historical run")
    .run;
    let reference = oracle
        .open_run(&spec, b"open-statement-history", &ops)
        .unwrap();
    stage_all(
        &mut k,
        &mut oracle,
        (run, reference),
        &[
            period_chunk(
                "earned",
                Some("FY2025-P03"),
                DateDay::from_ymd(2025, 3, 15).unwrap(),
                vec![leg(dr, "1000", 300), leg(cr, "4000", 300)],
            ),
            period_chunk(
                "closed",
                Some("FY2025-CLOSE"),
                DateDay::from_ymd(2025, 12, 31).unwrap(),
                vec![leg(dr, "4000", 300), leg(cr, "3000", 300)],
            ),
        ],
        "historical statement source",
    );
    let staged = k.db.frontier().unwrap();
    let closing = ["FY2025-CLOSE".to_string()];
    assert!(
        fa_registers::period_activity_excluding_classes(
            &k.db,
            &k.book,
            &closing,
            Some(staged),
            &[EntryClass::CLOSING],
        )
        .unwrap()
        .rows
        .is_empty(),
        "unfinalized migration remains invisible"
    );
    finalize_both(
        &mut k,
        &mut oracle,
        (run, reference),
        2,
        "finalize-statement-history",
    );
    let ordinary = fa_registers::period_activity(&k.db, &k.book, &closing, None).unwrap();
    assert_eq!(ordinary.unit_totals[&usd().0], (300, 300));
    let refused = fa_registers::period_activity_excluding_classes(
        &k.db,
        &k.book,
        &closing,
        None,
        &[EntryClass::CLOSING],
    )
    .expect_err("the retained Migration class does not establish its source classification");
    assert!(
        matches!(refused, fa_registers::RegisterError::InvalidSelection(ref why)
        if why.contains("migration entry") && why.contains("FY2025-CLOSE"))
    );
    let income = fa_registers::period_activity_excluding_classes(
        &k.db,
        &k.book,
        &["FY2025-P03".into()],
        None,
        &[EntryClass::CLOSING],
    )
    .unwrap();
    assert_eq!(
        income
            .rows
            .iter()
            .find(|row| row.code == "4000")
            .unwrap()
            .credits,
        300
    );
    assert!(
        fa_registers::period_activity_excluding_classes(
            &k.db,
            &k.book,
            &closing,
            Some(staged),
            &[EntryClass::CLOSING],
        )
        .unwrap()
        .rows
        .is_empty(),
        "historical visibility remains pinned after finalization"
    );
}

/// Plan §8.6 FullDetail (ruling 3675), kernel against oracle. Prior years: a
/// book going live at the fiscal-year start imports FY2025 legacy detail;
/// the detail ties out cumulatively, the Opening chunk ties to the chain at
/// the opening date, and the detail, dated before the run's opening date,
/// stays out of every fold: FY2025's periods fold empty on both sides, so
/// nothing is counted twice. Mid-year: a book going live April 1 imports
/// January–March detail on top of the January 1 opening balances; that
/// detail is dated on or after the run's opening date and counts. Planted:
/// an Opening chunk whose lines disagree with the chain at the fiscal-year
/// start (131, every mismatch naming the Opening period); a non-sole run
/// whose periods start after its opening date (100).
#[test]
fn full_detail_counts_detail_by_date_and_ties_the_opening_to_the_chain() {
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    let day = |y: i32, m: u8, d: u8| DateDay::from_ymd(y, m, d).unwrap();

    // Prior years: the go-live is 2026-01-01, so FY2025 is Historical.
    let (mut k, mut oracle) = setup_with(Some((opening_date(), P01)));
    create_year(&mut k, &mut oracle, 2025);
    let funded = usd_lines(&[("1000", 1_000), ("3000", -1_000)]);
    let billed = usd_lines(&[("1000", 700), ("1200", 300), ("3000", -1_000)]);
    let prior = full_detail(
        "prior-years",
        billed.clone(),
        (1..=12)
            .map(|m| {
                let cum = if m < 6 {
                    funded.clone()
                } else {
                    billed.clone()
                };
                (format!("FY2025-P{m:02}"), cum)
            })
            .collect(),
        Vec::new(),
        false,
    );
    let run = kernel_open(&mut k, &prior, "open-prior", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&prior, b"open-prior", &ops)
        .expect("oracle opens");
    let chunks = [
        period_chunk(
            "prior-open",
            Some(OPENING),
            opening_date(),
            vec![
                leg(dr, "1000", 700),
                leg(dr, "1200", 300),
                leg(cr, "3000", 1_000),
            ],
        ),
        period_chunk(
            "prior-jan",
            Some("FY2025-P01"),
            day(2025, 1, 15),
            vec![leg(dr, "1000", 1_000), leg(cr, "3000", 1_000)],
        ),
        period_chunk(
            "prior-jun",
            Some("FY2025-P06"),
            day(2025, 6, 10),
            vec![leg(dr, "1200", 300), leg(cr, "1000", 300)],
        ),
    ];
    stage_all(&mut k, &mut oracle, (run, o), &chunks, "prior-year chunk");
    finalize_both(&mut k, &mut oracle, (run, o), 3, "finalize-prior");
    for p in [OPENING, "FY2025-P01", "FY2025-P06"] {
        assert_fold(&k, &oracle, p, k.db.frontier().unwrap(), oracle.known(), 1);
    }
    for p in ["FY2025-P01", "FY2025-P06"] {
        assert!(
            fold_period_at(&k.db, &k.book, p, None)
                .unwrap()
                .cells
                .is_empty(),
            "{p}: detail before the opening date is summarized, not counted"
        );
    }
    assert!(
        !fold_period_at(&k.db, &k.book, OPENING, None)
            .unwrap()
            .cells
            .is_empty()
    );

    // Mid-year: the go-live is April 1; January–March detail counts.
    let (mut k, mut oracle) = setup_with(Some((go_live(), GO_LIVE_PERIOD)));
    let base = usd_lines(&[("1000", 5_000), ("3000", -5_000)]);
    let after_p01 = usd_lines(&[("1000", 5_500), ("3000", -5_000), ("4000", -500)]);
    let after_p03 = usd_lines(&[
        ("1000", 5_300),
        ("3000", -5_000),
        ("4000", -500),
        ("6000", 200),
    ]);
    let mid_periods = || {
        vec![
            (P01.to_string(), after_p01.clone()),
            ("FY2026-P02".to_string(), after_p01.clone()),
            ("FY2026-P03".to_string(), after_p03.clone()),
        ]
    };
    let detail = |prefix: &str| {
        [
            period_chunk(
                &format!("{prefix}-jan"),
                Some(P01),
                day(2026, 1, 20),
                vec![leg(dr, "1000", 500), leg(cr, "4000", 500)],
            ),
            period_chunk(
                &format!("{prefix}-mar"),
                Some("FY2026-P03"),
                day(2026, 3, 5),
                vec![leg(dr, "6000", 200), leg(cr, "1000", 200)],
            ),
        ]
    };

    // Planted: periods that start after the run's opening date (100).
    let late = full_detail(
        "late",
        base.clone(),
        mid_periods().into_iter().skip(1).collect(),
        after_p01.clone(),
        false,
    );
    let r = kernel_open(&mut k, &late, "open-late", &["post", "migrate"])
        .expect_err("the chain has no value at the opening date");
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    assert!(r.message.contains("after the run's opening date"), "{r}");
    assert_eq!(
        oracle.open_run(&late, b"open-late", &ops),
        Err("FA-REF-100")
    );

    // Planted: the Opening chunk carries 6,000 while the chain says 5,000.
    let off = usd_lines(&[("1000", 6_000), ("3000", -6_000)]);
    let wrong = full_detail(
        "wrong-opening",
        off.clone(),
        mid_periods(),
        base.clone(),
        false,
    );
    let run = kernel_open(&mut k, &wrong, "open-wrong", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&wrong, b"open-wrong", &ops)
        .expect("oracle opens");
    let mut chunks = vec![period_chunk(
        "wrong-open",
        Some(OPENING),
        opening_date(),
        vec![leg(dr, "1000", 6_000), leg(cr, "3000", 6_000)],
    )];
    chunks.extend(detail("wrong"));
    stage_all(
        &mut k,
        &mut oracle,
        (run, o),
        &chunks,
        "mismatched run chunk",
    );
    let tie = tie_out(
        &k.db,
        &k.book,
        &read_run(&k.db, run, None).unwrap().unwrap(),
        k.db.frontier().unwrap(),
    )
    .expect("tie-out");
    assert!(!tie.mismatches.is_empty());
    assert!(
        tie.mismatches
            .iter()
            .all(|l| l.period.as_deref() == Some(OPENING)),
        "only the Opening/chain check fails: {:?}",
        tie.mismatches
    );
    let r = kernel_plan(&k, run, kind::FINALIZE, "finalize-wrong").expect_err("disagrees");
    assert_eq!((r.code, r.exit), ("FA-REF-131", exit::REFUSAL), "{r}");
    assert!(r.message.contains(&format!("through `{OPENING}`")), "{r}");
    assert_eq!(
        oracle.finalize_run(o, 3, b"finalize-wrong", &ops, 2),
        Err("FA-REF-131")
    );
    let abandon = kernel_plan(&k, run, kind::ABANDON, "abandon-wrong").expect("plans");
    kernel_transition(&mut k, abandon, false).expect("abandons");
    oracle
        .abandon_run(o, 3, b"abandon-wrong", &ops)
        .expect("oracle abandons");

    // The well-formed mid-year run: opening plus January–March detail.
    let mid = full_detail("mid-year", base.clone(), mid_periods(), base.clone(), false);
    let run = kernel_open(&mut k, &mid, "open-mid", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&mid, b"open-mid", &ops)
        .expect("oracle opens");
    let mut chunks = vec![period_chunk(
        "mid-open",
        Some(OPENING),
        opening_date(),
        vec![leg(dr, "1000", 5_000), leg(cr, "3000", 5_000)],
    )];
    chunks.extend(detail("mid"));
    stage_all(&mut k, &mut oracle, (run, o), &chunks, "mid-year chunk");
    finalize_both(&mut k, &mut oracle, (run, o), 3, "finalize-mid");
    for p in [OPENING, P01, "FY2026-P02", "FY2026-P03"] {
        assert_fold(&k, &oracle, p, k.db.frontier().unwrap(), oracle.known(), 2);
    }
    assert!(
        !fold_period_at(&k.db, &k.book, P01, None)
            .unwrap()
            .cells
            .is_empty(),
        "detail on or after the opening date counts"
    );
}

/// Plan §8.6 FullDetail sole source (ruling 3675), kernel against oracle: a
/// book going live April 1 imports its whole history from inception
/// (January 1); there is no Opening chunk, no opening lines and no
/// `detail_base`, and every detail chunk counts once the run is finalized.
/// Planted: a sole-source body with opening lines (100), one with a
/// non-empty `detail_base` (100), and an Opening chunk staged into the
/// sole-source run (132).
#[test]
fn a_sole_source_full_detail_run_is_its_own_opening() {
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    let day = |m: u8, d: u8| DateDay::from_ymd(2026, m, d).unwrap();
    let (mut k, mut oracle) = setup_with(Some((go_live(), GO_LIVE_PERIOD)));
    let funded = usd_lines(&[("1000", 2_000), ("3000", -2_000)]);
    let spent = usd_lines(&[("1000", 1_800), ("3000", -2_000), ("6000", 200)]);
    let periods = vec![
        (P01.to_string(), funded.clone()),
        ("FY2026-P02".to_string(), funded.clone()),
        ("FY2026-P03".to_string(), spent),
    ];

    for (key, bad) in [
        (
            "with-lines",
            full_detail(
                "sole-lines",
                funded.clone(),
                periods.clone(),
                Vec::new(),
                true,
            ),
        ),
        (
            "with-base",
            full_detail(
                "sole-base",
                Vec::new(),
                periods.clone(),
                funded.clone(),
                true,
            ),
        ),
    ] {
        let r = kernel_open(&mut k, &bad, key, &["post", "migrate"])
            .expect_err("a sole source declares no opening");
        assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{key}: {r}");
        assert!(r.message.contains("sole-source"), "{key}: {r}");
        assert_eq!(
            oracle.open_run(&bad, key.as_bytes(), &ops),
            Err("FA-REF-100"),
            "{key}"
        );
    }

    let sole = full_detail("inception", Vec::new(), periods, Vec::new(), true);
    let run = kernel_open(&mut k, &sole, "open-sole", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&sole, b"open-sole", &ops)
        .expect("oracle opens");
    let opening_chunk = period_chunk(
        "sole-open",
        Some(OPENING),
        opening_date(),
        vec![leg(dr, "1000", 2_000), leg(cr, "3000", 2_000)],
    );
    assert_eq!(
        stage_both(
            &mut k,
            &mut oracle,
            (run, o),
            &opening_chunk,
            0,
            "an Opening chunk"
        ),
        Err("FA-REF-132")
    );
    let chunks = [
        period_chunk(
            "sole-jan",
            Some(P01),
            day(1, 2),
            vec![leg(dr, "1000", 2_000), leg(cr, "3000", 2_000)],
        ),
        period_chunk(
            "sole-mar",
            Some("FY2026-P03"),
            day(3, 9),
            vec![leg(dr, "6000", 200), leg(cr, "1000", 200)],
        ),
    ];
    stage_all(&mut k, &mut oracle, (run, o), &chunks, "sole-source chunk");
    finalize_both(&mut k, &mut oracle, (run, o), 2, "finalize-sole");
    for p in [OPENING, P01, "FY2026-P02", "FY2026-P03"] {
        assert_fold(&k, &oracle, p, k.db.frontier().unwrap(), oracle.known(), 3);
    }
    assert!(
        !fold_period_at(&k.db, &k.book, P01, None)
            .unwrap()
            .cells
            .is_empty(),
        "every detail chunk counts"
    );
    assert!(
        fold_period_at(&k.db, &k.book, OPENING, None)
            .unwrap()
            .cells
            .is_empty()
    );
}

/// Ruling 3685, kernel against oracle: the legacy year-end close lands in
/// its own Closing period, never re-dated. A book going live 2026-01-01
/// imports FY2025 P&L detail. FY2025's special periods precede the opening
/// date, so they are born Locked, keep their kind and admit only Migration:
/// an Original there is refused 010 by the pre_opening rule (its cite, not
/// the Locked matrix cell), and a transition is refused 040. Declared
/// periods carry pre-closing trial balances; the chain walks the calendar
/// (Opening, P01…P12, Adjustment, Closing). With the Closing chunk omitted,
/// the chain at the opening date still carries the revenue, so the run is
/// refused 131 with every mismatch naming the Opening period. With it
/// present, the chain is post-closing and ties, and the detail and the close,
/// dated before the opening date, stay out of every fold.
#[test]
fn a_prior_year_close_lands_in_its_closing_period_and_ties_the_opening() {
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    let day = |y: i32, m: u8, d: u8| DateDay::from_ymd(y, m, d).unwrap();
    let (mut k, mut oracle) = setup_with(Some((opening_date(), P01)));
    create_year(&mut k, &mut oracle, 2025);
    let close = "FY2025-CLOSE";

    // An Original into the pre-opening Closing period: the rule's 010.
    let original = Intent {
        date: day(2025, 12, 31),
        discriminator: Some(close.into()),
        ..trunk_intent(
            "into-the-close",
            vec![leg(dr, "6000", 10), leg(cr, "1000", 10)],
        )
    };
    let payload = chunk_payload(&k, VId(0), &original, Shape::NoRun, None);
    let r = kernel_post(&mut k, payload, &["post"], false)
        .expect_err("a pre-opening period admits only Migration");
    assert_eq!((r.code, r.exit), ("FA-REF-010", exit::SAFETY), "{r}");
    assert!(
        r.cite.contains("periods before the book's opening date"),
        "{r}"
    );
    assert_eq!(verdict_code(&oracle.post(&original)), Err("FA-REF-010"));

    // Its transition: the rule's 040.
    let opened = {
        let ctx = k.ctx();
        let (db, book) = (&mut k.db, &k.book);
        let desc = sealed(book, "period");
        k.runtime
            .block_on(async move {
                transition_period(
                    db,
                    &ctx,
                    book,
                    close,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    day(2025, 12, 31),
                    b"open-the-close",
                    desc,
                    &capability(&["close"]),
                    &[],
                )
                .await
            })
            .expect("kernel")
    };
    let r = opened.expect_err("a pre-opening period never transitions");
    assert_eq!(r.code, "FA-REF-040", "{r}");
    assert!(r.message.contains("before the book's opening date"), "{r}");
    assert_eq!(
        oracle.transition(close, PeriodTransition::Open),
        Err("FA-REF-040")
    );

    // FY2025 earned 800 of revenue in March; the legacy close moved it to
    // equity on 2025-12-31. Period balances are pre-closing; the opening
    // balance is post-closing.
    let earned = usd_lines(&[("1000", 800), ("4000", -800)]);
    let periods: Vec<(String, TrialBalance)> = (1..=12)
        .map(|m| {
            let cum = if m < 3 { Vec::new() } else { earned.clone() };
            (format!("FY2025-P{m:02}"), cum)
        })
        .collect();
    let opening_lines = usd_lines(&[("1000", 800), ("3000", -800)]);
    let opening_chunk = |key: &str| {
        period_chunk(
            key,
            Some(OPENING),
            opening_date(),
            vec![leg(dr, "1000", 800), leg(cr, "3000", 800)],
        )
    };
    let revenue = |key: &str| {
        period_chunk(
            key,
            Some("FY2025-P03"),
            day(2025, 3, 15),
            vec![leg(dr, "1000", 800), leg(cr, "4000", 800)],
        )
    };
    let the_close = |key: &str| {
        period_chunk(
            key,
            Some(close),
            day(2025, 12, 31),
            vec![leg(dr, "4000", 800), leg(cr, "3000", 800)],
        )
    };

    // Planted: the close omitted.
    let omitted = full_detail(
        "close-omitted",
        opening_lines.clone(),
        periods.clone(),
        Vec::new(),
        false,
    );
    let run = kernel_open(&mut k, &omitted, "open-omitted", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&omitted, b"open-omitted", &ops)
        .expect("oracle opens");
    stage_all(
        &mut k,
        &mut oracle,
        (run, o),
        &[opening_chunk("om-open"), revenue("om-rev")],
        "close-omitted chunk",
    );
    let tie = tie_out(
        &k.db,
        &k.book,
        &read_run(&k.db, run, None).unwrap().unwrap(),
        k.db.frontier().unwrap(),
    )
    .expect("tie-out");
    assert!(!tie.mismatches.is_empty());
    assert!(
        tie.mismatches
            .iter()
            .all(|l| l.period.as_deref() == Some(OPENING)),
        "only the Opening/chain check fails: {:?}",
        tie.mismatches
    );
    let r = kernel_plan(&k, run, kind::FINALIZE, "finalize-omitted").expect_err("unclosed");
    assert_eq!((r.code, r.exit), ("FA-REF-131", exit::REFUSAL), "{r}");
    assert_eq!(
        oracle.finalize_run(o, 2, b"finalize-omitted", &ops, 2),
        Err("FA-REF-131")
    );
    let abandon = kernel_plan(&k, run, kind::ABANDON, "abandon-omitted").expect("plans");
    kernel_transition(&mut k, abandon, false).expect("abandons");
    oracle
        .abandon_run(o, 2, b"abandon-omitted", &ops)
        .expect("oracle abandons");

    // The close present, in its own Closing period: the run ties out.
    let present = full_detail("close-present", opening_lines, periods, Vec::new(), false);
    let run = kernel_open(&mut k, &present, "open-present", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&present, b"open-present", &ops)
        .expect("oracle opens");
    stage_all(
        &mut k,
        &mut oracle,
        (run, o),
        &[
            opening_chunk("pr-open"),
            revenue("pr-rev"),
            the_close("pr-close"),
        ],
        "close-present chunk",
    );
    finalize_both(&mut k, &mut oracle, (run, o), 3, "finalize-present");
    for p in [OPENING, "FY2025-P03", close] {
        assert_fold(&k, &oracle, p, k.db.frontier().unwrap(), oracle.known(), 4);
    }
    for p in ["FY2025-P03", close] {
        assert!(
            fold_period_at(&k.db, &k.book, p, None)
                .unwrap()
                .cells
                .is_empty(),
            "{p}: summarized by the opening entry, not counted"
        );
    }
}

/// Stage `intent` into `run` on both sides: the chunk's entry reference and
/// its index in the oracle's journal.
fn stage_ref(
    k: &mut Kernel,
    oracle: &mut Oracle,
    run: (VId, usize),
    intent: &Intent,
) -> (EntryRef, usize) {
    let proposal = chunk_payload(k, run.0, intent, Shape::Chunk, None);
    let posted = kernel_post(k, proposal, &["post", "migrate"], true).expect("the kernel stages");
    let index = posted_index(&oracle.post_migration(run.1, intent)).expect("the oracle stages");
    (posted.entry_ref(), index)
}

fn posted_index(v: &Verdict) -> Option<usize> {
    match v {
        Verdict::Posted { index, .. } => Some(*index),
        Verdict::Recorded { .. } | Verdict::Refused { .. } => None,
    }
}

/// The kernel proposal for `intent`, its `settles` (oracle journal indices)
/// as settlements against the kernel entries `refs` names.
fn settling_payload(
    k: &Kernel,
    run: VId,
    intent: &Intent,
    shape: Shape,
    refs: &BTreeMap<usize, EntryRef>,
) -> EntryPayload {
    let mut proposal = chunk_payload(k, run, intent, shape, None);
    for s in &intent.settles {
        proposal.legs[s.leg].settles.push(Settlement {
            target: *refs.get(&s.target).expect("a posted target"),
            ordinal: u16::try_from(s.ordinal).expect("small ordinal"),
            amount: Amount::new(usd(), s.mantissa),
        });
    }
    proposal
}

/// A trunk receipt (cash 1000 against receivables 1200) applying `amount`
/// to journal entry `target`'s leg `ordinal`.
fn receipt(key: &str, target: usize, ordinal: usize, amount: i128) -> Intent {
    Intent {
        settles: vec![fa_reference::Settle {
            leg: 1,
            target,
            ordinal,
            mantissa: amount,
        }],
        ..trunk_intent(
            key,
            vec![
                leg(fa_reference::Side::Debit, "1000", amount),
                leg(fa_reference::Side::Credit, "1200", amount),
            ],
        )
    }
}

/// Post the trunk `intent` on both sides; a posted entry joins `refs`.
fn post_receipt(
    k: &mut Kernel,
    oracle: &mut Oracle,
    intent: &Intent,
    refs: &mut BTreeMap<usize, EntryRef>,
) -> (Result<Posted, Refusal>, Verdict) {
    let proposal = settling_payload(k, VId(0), intent, Shape::NoRun, refs);
    let kernel = kernel_post(k, proposal, &["post"], false);
    let model = oracle.post(intent);
    if let (Ok(p), Some(i)) = (&kernel, posted_index(&model)) {
        refs.insert(i, p.entry_ref());
    }
    (kernel, model)
}

/// Ruling 3733, kernel against oracle: open-item migration. A migrated leg
/// is an open item iff its run is Finalized and its chunk counts (the
/// migration predicate, the run state a point witness), and a chunk carries
/// no settles (C2, the interim posture). A book going live 2026-01-01
/// imports FY2025 receivables detail in a FullDetail run whose Opening
/// chunk carries one leg per open invoice (the importer's shape, plan
/// §8.6). Planted, each reaching one check: a detail chunk carrying a legacy
/// application (071); a receipt against the Opening chunk while its run is
/// staged (070, Open); against an abandoned run's chunk (070, Abandoned);
/// against FY2025 detail the opening balances summarize (070); and an
/// over-application of a migrated invoice (072). Once the run is Finalized,
/// receipts settle the Opening legs, and the kernel's open items equal the
/// oracle's leg for leg, with every applied mirror verified.
#[test]
fn migrated_legs_are_open_items_once_their_run_finalizes_and_their_chunk_counts() {
    let ops = vec!["post".to_string(), "migrate".to_string()];
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    let day = |y: i32, m: u8, d: u8| DateDay::from_ymd(y, m, d).unwrap();
    let (mut k, mut oracle) = setup_with(Some((opening_date(), P01)));
    create_year(&mut k, &mut oracle, 2025);
    let mut refs: BTreeMap<usize, EntryRef> = BTreeMap::new();

    // An abandoned OpeningOnly run's chunk: receivables 50.
    let abandoned = RunSpec {
        key: "c-abandoned".into(),
        opening_date: opening_date(),
        lines: usd_lines(&[("1200", 50), ("3000", -50)]),
        periods: Vec::new(),
        full_detail: None,
    };
    let run = kernel_open(&mut k, &abandoned, "open-abandoned", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&abandoned, b"open-abandoned", &ops)
        .expect("oracle opens");
    let (r, abandoned_chunk) = stage_ref(
        &mut k,
        &mut oracle,
        (run, o),
        &chunk_intent("ab-open", vec![leg(dr, "1200", 50), leg(cr, "3000", 50)]),
    );
    refs.insert(abandoned_chunk, r);
    let plan = kernel_plan(&k, run, kind::ABANDON, "abandon-c").expect("plans");
    kernel_transition(&mut k, plan, false).expect("abandons");
    oracle
        .abandon_run(o, 1, b"abandon-c", &ops)
        .expect("oracle abandons");

    // The FullDetail run: a legacy invoice of 300 in June 2025, the legacy
    // close, and the opening receivables as two open invoices (100, 200).
    let periods: Vec<(String, TrialBalance)> = (1..=12)
        .map(|m| {
            let cum = if m < 6 {
                Vec::new()
            } else {
                usd_lines(&[("1200", 300), ("4000", -300)])
            };
            (format!("FY2025-P{m:02}"), cum)
        })
        .collect();
    let spec = full_detail(
        "c-run",
        usd_lines(&[("1200", 300), ("3000", -300)]),
        periods,
        Vec::new(),
        false,
    );
    let run = kernel_open(&mut k, &spec, "open-c", &["post", "migrate"])
        .expect("opens")
        .run;
    let o = oracle
        .open_run(&spec, b"open-c", &ops)
        .expect("oracle opens");
    let invoice = period_chunk(
        "c-inv",
        Some("FY2025-P06"),
        day(2025, 6, 10),
        vec![leg(dr, "1200", 300), leg(cr, "4000", 300)],
    );
    let (r, legacy_invoice) = stage_ref(&mut k, &mut oracle, (run, o), &invoice);
    refs.insert(legacy_invoice, r);

    // Planted (C2): a legacy payment applying to the legacy invoice.
    let payment = Intent {
        settles: vec![fa_reference::Settle {
            leg: 1,
            target: legacy_invoice,
            ordinal: 0,
            mantissa: 100,
        }],
        ..period_chunk(
            "c-pay",
            Some("FY2025-P07"),
            day(2025, 7, 1),
            vec![leg(dr, "1000", 100), leg(cr, "1200", 100)],
        )
    };
    let proposal = settling_payload(&k, run, &payment, Shape::Chunk, &refs);
    let r = kernel_post(&mut k, proposal, &["post", "migrate"], true)
        .expect_err("a chunk carries no settles");
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL), "{r}");
    assert!(r.fix.contains("net of its legacy applications"), "{r}");
    assert_eq!(
        verdict_code(&oracle.post_migration(o, &payment)),
        Err("FA-REF-071")
    );

    let close = period_chunk(
        "c-close",
        Some("FY2025-CLOSE"),
        day(2025, 12, 31),
        vec![leg(dr, "4000", 300), leg(cr, "3000", 300)],
    );
    let (r, i) = stage_ref(&mut k, &mut oracle, (run, o), &close);
    refs.insert(i, r);
    let (r, opening) = stage_ref(
        &mut k,
        &mut oracle,
        (run, o),
        &chunk_intent(
            "c-open",
            vec![
                leg(dr, "1200", 100),
                leg(dr, "1200", 200),
                leg(cr, "3000", 300),
            ],
        ),
    );
    refs.insert(opening, r);

    // Staged: nothing of the run is open yet.
    let (kernel, model) = post_receipt(
        &mut k,
        &mut oracle,
        &receipt("rc-staged", opening, 0, 100),
        &mut refs,
    );
    let r = kernel.expect_err("a staged run's leg is not open");
    assert_eq!((r.code, r.exit), ("FA-REF-070", exit::REFUSAL), "{r}");
    assert!(r.message.contains("which is Open"), "{r}");
    assert_eq!(verdict_code(&model), Err("FA-REF-070"));
    // Abandoned: never open.
    let (kernel, model) = post_receipt(
        &mut k,
        &mut oracle,
        &receipt("rc-abandoned", abandoned_chunk, 0, 50),
        &mut refs,
    );
    let r = kernel.expect_err("an abandoned run's leg is never open");
    assert_eq!(r.code, "FA-REF-070", "{r}");
    assert!(r.message.contains("which is Abandoned"), "{r}");
    assert_eq!(verdict_code(&model), Err("FA-REF-070"));

    finalize_both(&mut k, &mut oracle, (run, o), 3, "finalize-c");

    // Not counting: the June invoice is summarized by the opening balances.
    let (kernel, model) = post_receipt(
        &mut k,
        &mut oracle,
        &receipt("rc-detail", legacy_invoice, 0, 100),
        &mut refs,
    );
    let r = kernel.expect_err("summarized detail is not open");
    assert_eq!(r.code, "FA-REF-070", "{r}");
    assert!(
        r.message
            .contains("summarized by the run's opening balances"),
        "{r}"
    );
    assert!(r.fix.contains("settle the Opening leg"), "{r}");
    assert_eq!(verdict_code(&model), Err("FA-REF-070"));

    // Counting: the Opening legs are open items.
    let (kernel, model) = post_receipt(
        &mut k,
        &mut oracle,
        &receipt("rc-a", opening, 0, 100),
        &mut refs,
    );
    kernel.expect("invoice A clears");
    assert!(matches!(model, Verdict::Posted { .. }));
    let (kernel, model) = post_receipt(
        &mut k,
        &mut oracle,
        &receipt("rc-b-over", opening, 1, 250),
        &mut refs,
    );
    let r = kernel.expect_err("over-applied");
    assert_eq!(r.code, "FA-REF-072", "{r}");
    assert_eq!(verdict_code(&model), Err("FA-REF-072"));
    let (kernel, model) = post_receipt(
        &mut k,
        &mut oracle,
        &receipt("rc-b", opening, 1, 150),
        &mut refs,
    );
    kernel.expect("invoice B part-pays");
    assert!(matches!(model, Verdict::Posted { .. }));

    // The open items, leg for leg: the Opening legs (A cleared, 50 of B
    // open) and the receipts; neither the summarized detail nor the
    // abandoned chunk.
    let by_vid: BTreeMap<VId, usize> = refs.iter().map(|(i, r)| (r.vid, *i)).collect();
    let items = fa_registers::open_items(&k.db, &k.book, None, None).expect("open items");
    let kernel_items: BTreeMap<(usize, usize), (i128, i128, i128)> = items
        .iter()
        .map(|it| {
            let index = *by_vid.get(&it.entry).expect("a posted entry");
            (
                (index, usize::from(it.ordinal)),
                (it.original, it.applied, it.applied_out),
            )
        })
        .collect();
    assert_eq!(kernel_items, oracle.open_items());
    let vid_of = |i: usize| refs.get(&i).expect("posted").vid;
    let b = items
        .iter()
        .find(|it| it.entry == vid_of(opening) && it.ordinal == 1)
        .expect("invoice B is an open item");
    assert_eq!((b.original, b.applied, b.open), (200, 150, 50));
    assert!(
        items
            .iter()
            .all(|it| it.entry != vid_of(legacy_invoice) && it.entry != vid_of(abandoned_chunk)),
        "summarized detail and abandoned chunks carry no open item"
    );
    assert!(
        fa_registers::verify_open_items(&k.db, &k.book, None)
            .expect("verify")
            .is_green()
    );
}
