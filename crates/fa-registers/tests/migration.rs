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
use fa_journal::migration::kind;
use fa_journal::*;
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload,
    Oid, PeriodRef, SealKey, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::{Account, Intent, Known, Leg, Limit, Oracle, RunSpec, Verdict};
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
    oracle.create_periods(2026);
    for (i, t) in [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
        PeriodTransition::Lock,
    ]
    .into_iter()
    .enumerate()
    {
        transition(&mut k, OPENING, t, &format!("lock-opening-{i}"));
        oracle.transition(OPENING, t).expect("oracle");
    }
    transition(&mut k, P01, PeriodTransition::Open, "open-p01");
    oracle
        .transition(P01, PeriodTransition::Open)
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
        resolves: None,
        settles: Vec::new(),
    }
}

fn body_of(k: &Kernel, spec: &RunSpec) -> RunBody {
    RunBody {
        book_id: k.book.book_id,
        run_key: spec.key.clone(),
        source_system: "legacy-gl".into(),
        mode: RunMode::OpeningOnly,
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
    }
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
        k.tb,
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
            match (kernel, model) {
                (Ok(opened), Ok(index)) => {
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
                (Err(r), Err(_)) => refuse(&mut f, r.code),
                _ => panic!(
                    "step {step}: the kernel and the oracle disagree on whether the run opened"
                ),
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
                    // Dated in P02, a Normal period: 132.
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
            match (&kernel, &model) {
                (Ok(Posted::Committed { recorded_at, .. }), Verdict::Posted { .. }) => {
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
                (Ok(Posted::AlreadyRecorded { .. }), Verdict::Recorded { .. }) => f.recorded += 1,
                (Err(r), Verdict::Refused { .. }) => refuse(&mut f, r.code),
                _ => panic!("step {step}: kernel {kernel:?} vs oracle {model:?}"),
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
