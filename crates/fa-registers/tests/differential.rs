//! The reference differential (plan §16.2, bead fa-d93): one seeded history
//! of posts, reversals, retries, and period transitions is applied to the
//! real kernel on the substrate and to the naive oracle; every verdict and
//! every register cell must agree. The oracle has its own arithmetic and its
//! own copy of the refusal codes, so agreement is evidence about the kernel,
//! not an echo.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::*;
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, Id128, LegPayload, Oid, PeriodRef,
    SealKey, Supersession, SupersessionKind, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::{Account, Intent, Leg, Oracle, Verdict};
use fa_registers::{fold_period, trial_balance};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

const PRINCIPAL: VId = VId(7);

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
}

impl Kernel {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
}

const ACCOUNTS: &[(&str, u8, bool)] = &[
    ("1000", 1, true),
    ("6000", 5, true),
    ("4000", 4, true),
    ("1", 1, false),
];

fn setup() -> (Kernel, Oracle, Vec<String>) {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x7a; 32],
        DatabaseSecurityNamespaceId([0x7b; 32]),
        [0x7c; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([0xd; 16]);
    let spec = BookSpec {
        book_id,
        name: "Diff Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
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
    let chart: Vec<AccountSpec> = ACCOUNTS
        .iter()
        .map(|(code, ty, leaf)| AccountSpec {
            code: (*code).into(),
            name: (*code).into(),
            account_type: *ty,
            normal_balance: 0,
            is_leaf: *leaf,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
        })
        .collect();
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PRINCIPAL,
                day,
                b"chart",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
    let (_, periods) = runtime
        .block_on(async { create_periods(&mut db, &ctx, &book, 2026).await })
        .expect("periods");
    let normal: Vec<String> = periods
        .iter()
        .filter(|p| p.kind == PeriodKind::Normal)
        .map(|p| p.code.clone())
        .collect();

    let mut oracle = Oracle::new(calendar);
    for (code, _, leaf) in ACCOUNTS {
        oracle.add_account(Account {
            code: (*code).into(),
            is_leaf: *leaf,
            unit: Some(usd.0),
        });
    }
    oracle.create_periods(2026);
    (
        Kernel {
            runtime,
            root,
            db,
            book,
        },
        oracle,
        normal,
    )
}

fn to_kernel_legs(book_id: Id128, usd: UnitId, legs: &[Leg]) -> Vec<LegPayload> {
    legs.iter()
        .map(|l| {
            LegPayload::simple(
                if l.side == fa_reference::Side::Debit {
                    Side::Debit
                } else {
                    Side::Credit
                },
                account_vid(book_id, &l.account),
                Amount::new(usd, l.mantissa),
            )
        })
        .collect()
}

fn kernel_post(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
) -> Result<Posted, Refusal> {
    let legs = to_kernel_legs(k.book.book_id, usd, &intent.legs);
    let unit_totals =
        EntryPayload::fold_unit_totals(&legs).expect("no overflow in generated amounts");
    let supersession = intent
        .reverses
        .map(|i| {
            vec![Supersession {
                target: refs[i],
                kind: SupersessionKind::Reverses,
                reason_code: 0,
            }]
        })
        .unwrap_or_default();
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: k.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::from_name(&intent.class).expect("registered class"),
        effective_date: intent.date,
        document_date: None,
        // Constant on purpose: the retry comparison covers it, and the oracle
        // does not model descriptions.
        description: Erasable::seal(
            &"generated".to_string(),
            None,
            &k.book.seal_key,
            [1; 32],
            [2; 24],
        ),
        effective_period: intent.discriminator.as_ref().map(|c| PeriodRef {
            calendar: "cal".into(),
            code: c.clone(),
        }),
        legs,
        control: None,
        unit_totals,
        base_totals: None,
        idempotency_key: intent.key.clone(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: Vec::new(),
        supersession,
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
    };
    let ops: Vec<&str> = intent.ops.iter().map(String::as_str).collect();
    let req = PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::with_ops(&ops),
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
}

fn kernel_transition(
    k: &mut Kernel,
    code: &str,
    t: PeriodTransition,
    step: u64,
) -> Result<Transitioned, Refusal> {
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    let key = format!("t-{step}");
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
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
                day,
                key.as_bytes(),
                Erasable::seal(
                    &"period".to_string(),
                    None,
                    &book.seal_key,
                    [3; 32],
                    [4; 24],
                ),
            )
            .await
        })
        .expect("kernel")
}

#[test]
fn kernel_and_oracle_agree_on_a_generated_history() {
    let (mut k, mut oracle, periods) = setup();
    let usd = k.book.units.lookup("USD").unwrap();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let dates = [
        DateDay::from_ymd(2026, 2, 10).unwrap(),
        DateDay::from_ymd(2026, 3, 15).unwrap(),
        DateDay::from_ymd(2026, 3, 31).unwrap(),
        DateDay::from_ymd(2026, 4, 2).unwrap(),
    ];
    let classes = [
        "Original",
        "Original",
        "Original",
        "Adjusting",
        "Reversal",
        "Reversal",
        "Replacement",
        "Pending",
    ];
    let leaf_codes = ["1000", "6000", "4000"];
    let mut history: Vec<Intent> = Vec::new();
    let mut posted_intents: Vec<Intent> = Vec::new();
    let mut reversed_targets: BTreeSet<usize> = BTreeSet::new();
    // Kernel handles of posted entries, indexed like the oracle's journal.
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut posted = 0u32;
    let mut recorded = 0u32;
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();

    for step in 0..360u64 {
        if rng.chance(15) {
            let code = periods[1 + rng.below(3) as usize].clone(); // Feb, Mar, Apr
            let t = match rng.below(5) {
                0 => PeriodTransition::Open,
                1 => PeriodTransition::SoftClose,
                2 => PeriodTransition::Close,
                3 => PeriodTransition::Lock,
                _ => PeriodTransition::Reopen {
                    to: PeriodState::Open,
                },
            };
            let kernel = kernel_transition(&mut k, &code, t, step);
            let model = oracle.transition(&code, t);
            match (kernel, model) {
                (Ok(tr), Ok((from, to))) => assert_eq!(
                    (tr.from, tr.to),
                    (from, to),
                    "step {step}: transition {code} {t:?}"
                ),
                (Err(r), Err(c)) => {
                    assert_eq!(r.code, c, "step {step}: transition refusal {code} {t:?}")
                }
                (kr, mr) => assert_eq!(
                    format!("kernel {kr:?}"),
                    format!("oracle {mr:?}"),
                    "step {step}: transition {code} {t:?} disagreement"
                ),
            }
            continue;
        }

        // Retry an earlier intent: identical (expect recorded) or with a
        // different date (expect an idempotency conflict).
        let intent = if !history.is_empty() && rng.chance(12) {
            if rng.chance(50) && !posted_intents.is_empty() {
                // An exact resubmission of something that posted: recorded.
                posted_intents[rng.below(posted_intents.len() as u64) as usize].clone()
            } else {
                // The same key with a different date: a conflict (or the
                // same refusal as before, when the original never posted).
                let mut again = history[rng.below(history.len() as u64) as usize].clone();
                again.date = dates[rng.below(4) as usize];
                again
            }
        } else {
            let class = classes[rng.below(classes.len() as u64) as usize];
            let ops: Vec<String> = if rng.chance(35) {
                vec!["post".into(), "post_closed".into()]
            } else {
                vec!["post".into()]
            };
            let key = format!("k{step}").into_bytes();
            if class == "Reversal" && !refs.is_empty() {
                // Prefer a target nobody has reversed yet, so the reversal
                // law itself (shape, identity) is exercised, not only the
                // already-reversed conflict.
                let unreversed: Vec<usize> = (0..refs.len())
                    .filter(|i| !reversed_targets.contains(i))
                    .collect();
                let target = if !unreversed.is_empty() && rng.chance(80) {
                    unreversed[rng.below(unreversed.len() as u64) as usize]
                } else {
                    rng.below(refs.len() as u64) as usize
                };
                let original = oracle.entry(target).expect("posted entry");
                let mut legs: Vec<Leg> = original
                    .legs
                    .iter()
                    .map(|l| Leg {
                        side: l.side.flipped(),
                        account: l.account.clone(),
                        unit: l.unit,
                        mantissa: l.mantissa,
                    })
                    .collect();
                if rng.chance(15) {
                    // Same amounts (still balanced), different account: not the exact side-swap.
                    legs[0].account = if legs[0].account == "1000" {
                        "6000".into()
                    } else {
                        "1000".into()
                    };
                }
                Intent {
                    class: class.into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs,
                    key,
                    ops,
                    approvals: 0,
                    reverses: Some(target),
                }
            } else {
                let class = if class == "Reversal" {
                    "Original"
                } else {
                    class
                };
                let n_legs = 2 + rng.below(3) as usize;
                let mut legs = Vec::with_capacity(n_legs);
                for i in 0..n_legs {
                    let account = if rng.chance(4) {
                        "1"
                    } else {
                        leaf_codes[rng.below(3) as usize]
                    };
                    let mantissa = 1 + rng.below(50_000) as i128;
                    let side = if i < n_legs - 1 && rng.chance(50) {
                        fa_reference::Side::Debit
                    } else {
                        fa_reference::Side::Credit
                    };
                    legs.push(Leg {
                        side,
                        account: account.into(),
                        unit: usd.0,
                        mantissa,
                    });
                }
                // Balance most of the time by fixing the last leg.
                let debits: i128 = legs[..n_legs - 1]
                    .iter()
                    .filter(|l| l.side == fa_reference::Side::Debit)
                    .map(|l| l.mantissa)
                    .sum();
                let credits: i128 = legs[..n_legs - 1]
                    .iter()
                    .filter(|l| l.side == fa_reference::Side::Credit)
                    .map(|l| l.mantissa)
                    .sum();
                if rng.chance(85) {
                    let last = &mut legs[n_legs - 1];
                    if debits > credits {
                        last.side = fa_reference::Side::Credit;
                        last.mantissa = debits - credits;
                    } else {
                        last.side = fa_reference::Side::Debit;
                        last.mantissa = (credits - debits).max(1);
                    }
                }
                let date = dates[rng.below(4) as usize];
                let discriminator =
                    (date == dates[2] && rng.chance(30)).then(|| "FY2026-A1".to_string());
                Intent {
                    class: class.into(),
                    date,
                    discriminator,
                    legs,
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                }
            }
        };
        history.push(intent.clone());

        let kernel = kernel_post(&mut k, &intent, usd, &refs);
        let model = oracle.post(&intent);
        match (&kernel, &model) {
            (
                Ok(Posted::Committed {
                    period, entry_ref, ..
                }),
                Verdict::Posted { period: p, index },
            ) => {
                assert_eq!(period, p, "step {step}: period");
                assert_eq!(*index, refs.len(), "step {step}: journal index");
                refs.push(*entry_ref);
                posted += 1;
                posted_intents.push(intent.clone());
                if let Some(t) = intent.reverses {
                    reversed_targets.insert(t);
                }
            }
            (Ok(Posted::AlreadyRecorded { entry_ref, .. }), Verdict::Recorded { index }) => {
                assert_eq!(*entry_ref, refs[*index], "step {step}: recorded handle");
                recorded += 1;
            }
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, *code, "step {step}: refusal code for {intent:?}");
                *refused.entry(code).or_insert(0) += 1;
            }
            _ => assert_eq!(
                format!("kernel {kernel:?}"),
                format!("oracle {model:?}"),
                "step {step}: disagreement on {intent:?}"
            ),
        }
    }

    // The history exercised every outcome kind, so agreement is not vacuous.
    assert!(posted >= 30, "posted {posted}");
    assert!(recorded >= 3, "recorded {recorded}");
    for must in [
        "FA-REF-001",
        "FA-REF-010",
        "FA-REF-032",
        "FA-REF-051",
        "FA-REF-102",
    ] {
        assert!(
            refused.contains_key(must),
            "refusal {must} never exercised: {refused:?}"
        );
    }
    assert_eq!(oracle.journal_len() as u32, posted);

    // Every register cell of every period agrees, cell by cell, and the
    // kernel's trial balance over all periods nets to zero per unit.
    for code in &periods {
        let kernel_fold = fold_period(&k.db, &k.book, code).unwrap();
        let model_fold = oracle.fold(code);
        assert_eq!(
            kernel_fold.cells.len(),
            model_fold.len(),
            "{code}: cell count"
        );
        for cell in &kernel_fold.cells {
            let account_code = ACCOUNTS
                .iter()
                .map(|(c, ..)| *c)
                .find(|c| account_vid(k.book.book_id, c) == cell.key.account)
                .expect("known account");
            let m = model_fold.get(&(account_code.to_string(), cell.key.unit_id));
            assert!(m.is_some(), "{code}: oracle lacks cell {account_code}");
            let m = m.expect("asserted above");
            assert_eq!(
                m.debits.to_i128(),
                Some(cell.debits),
                "{code}/{account_code} debits"
            );
            assert_eq!(
                m.credits.to_i128(),
                Some(cell.credits),
                "{code}/{account_code} credits"
            );
            assert_eq!(
                m.entry_count, cell.entry_count,
                "{code}/{account_code} entry_count"
            );
        }
    }
    let tb = trial_balance(&k.db, &k.book, &periods).unwrap();
    assert!(tb.is_balanced(), "{:?}", tb.unit_totals);
}
