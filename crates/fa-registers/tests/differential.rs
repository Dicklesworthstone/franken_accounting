//! The reference differential (plan §16.2, bead fa-d93): one seeded history
//! of posts and period transitions is applied to the real kernel on the
//! substrate and to the naive oracle; every verdict and every register cell
//! must agree. The oracle has its own arithmetic and its own copy of the
//! refusal codes, so agreement is evidence about the kernel, not an echo.

use std::collections::BTreeMap;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::*;
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, PeriodRef, SealKey,
    SymbolTable, account_vid,
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
                &mut db, &ctx, &book, &chart, PRINCIPAL, day, b"chart", [5; 32], [6; 24],
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

fn kernel_post(k: &mut Kernel, intent: &Intent, usd: UnitId, step: u64) -> Result<Posted, Refusal> {
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
                Amount::new(usd, l.mantissa),
            )
        })
        .collect();
    let unit_totals =
        EntryPayload::fold_unit_totals(&legs).expect("no overflow in generated amounts");
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: k.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::from_name(&intent.class).expect("registered class"),
        effective_date: intent.date,
        document_date: None,
        description: Erasable::seal(
            &format!("step {step}"),
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
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
    };
    let ops: Vec<&str> = intent.ops.iter().map(String::as_str).collect();
    let req = PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        principal_scope: PRINCIPAL.0.to_le_bytes().to_vec(),
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
                [3; 32],
                [4; 24],
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
        "Reversal",
        "Adjusting",
        "Replacement",
    ];
    let leaf_codes = ["1000", "6000", "4000"];
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut posted = 0u32;
    let mut recorded = 0u32;
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();

    for step in 0..160u64 {
        if rng.chance(20) {
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
                (kr, mr) => panic_step(
                    step,
                    &format!("transition {code} {t:?}: kernel {kr:?} vs oracle {mr:?}"),
                ),
            }
            continue;
        }
        let n_legs = 2 + rng.below(3) as usize;
        let mut legs = Vec::with_capacity(n_legs);
        let mut debit_total = 0i128;
        for i in 0..n_legs {
            let account = if rng.chance(4) {
                "1"
            } else {
                leaf_codes[rng.below(3) as usize]
            };
            let mantissa = 1 + rng.below(50_000) as i128;
            let side = if i < n_legs - 1 {
                if rng.chance(50) {
                    fa_reference::Side::Debit
                } else {
                    fa_reference::Side::Credit
                }
            } else {
                fa_reference::Side::Credit
            };
            if side == fa_reference::Side::Debit {
                debit_total += mantissa;
            }
            legs.push(Leg {
                side,
                account: account.into(),
                unit: usd.0,
                mantissa,
            });
        }
        // Make it balance most of the time by fixing the last leg.
        let credit_so_far: i128 = legs[..n_legs - 1]
            .iter()
            .filter(|l| l.side == fa_reference::Side::Credit)
            .map(|l| l.mantissa)
            .sum();
        let needed = debit_total - credit_so_far;
        if needed > 0 && rng.chance(85) {
            legs[n_legs - 1].mantissa = needed;
        } else if needed <= 0 {
            legs[n_legs - 1].side = fa_reference::Side::Debit;
            legs[n_legs - 1].mantissa = (credit_so_far - debit_total).max(1);
        }
        let key = if !keys.is_empty() && rng.chance(12) {
            keys[rng.below(keys.len() as u64) as usize].clone()
        } else {
            format!("k{step}").into_bytes()
        };
        keys.push(key.clone());
        let date = dates[rng.below(4) as usize];
        let discriminator = (date == dates[2] && rng.chance(30)).then(|| "FY2026-A1".to_string());
        let ops: Vec<String> = if rng.chance(35) {
            vec!["post".into(), "post_closed".into()]
        } else {
            vec!["post".into()]
        };
        let intent = Intent {
            class: classes[rng.below(6) as usize].into(),
            date,
            discriminator,
            legs,
            key,
            ops,
            approvals: 0,
        };

        let kernel = kernel_post(&mut k, &intent, usd, step);
        let model = oracle.post(&intent);
        match (&kernel, &model) {
            (Ok(Posted::Committed { period, .. }), Verdict::Posted { period: p, .. }) => {
                assert_eq!(period, p, "step {step}: period");
                posted += 1;
            }
            (Ok(Posted::AlreadyRecorded { .. }), Verdict::Recorded { .. }) => recorded += 1,
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, *code, "step {step}: refusal code for {intent:?}");
                *refused.entry(code).or_insert(0) += 1;
            }
            _ => panic_step(
                step,
                &format!("{intent:?}: kernel {kernel:?} vs oracle {model:?}"),
            ),
        }
    }

    // The history exercised every outcome kind, so agreement is not vacuous.
    assert!(posted >= 20, "posted {posted}");
    assert!(recorded >= 3, "recorded {recorded}");
    assert!(refused.len() >= 4, "refusal kinds {refused:?}");
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
            let m = model_fold
                .get(&(account_code.to_string(), cell.key.unit_id))
                .unwrap_or_else(|| {
                    panic_step(0, &format!("{code}: oracle lacks cell {account_code}"))
                });
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

fn panic_step(step: u64, what: &str) -> ! {
    // One place, so the scanner's panic inventory names exactly this: the
    // differential found a disagreement, which is the test's reason to exist.
    assert!(false, "differential disagreement at step {step}: {what}");
    unreachable!()
}
