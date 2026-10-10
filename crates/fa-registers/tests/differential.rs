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
    ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, Id128,
    LegPayload, Oid, Pending, PeriodRef, SealKey, Settlement, Supersession, SupersessionKind,
    SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::{Account, Cell, Int, Intent, Leg, Oracle, Resolve, Settle, Verdict};
use fa_registers::{
    TrialBalance, balance_as_of, fold_period, open_items, period_activity, trial_balance,
    trial_balance_at, verify_open_items,
};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

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
    ("1200", 1, true),
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
    kernel_post_raw(k, intent, usd, refs).expect("kernel")
}

fn kernel_post_raw(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
) -> Result<Result<Posted, Refusal>, KernelError> {
    let mut legs = to_kernel_legs(k.book.book_id, usd, &intent.legs);
    for s in &intent.settles {
        legs[s.leg].settles.push(Settlement {
            target: refs[s.target],
            ordinal: u16::try_from(s.ordinal).expect("small ordinal"),
            amount: Amount::new(usd, s.mantissa),
        });
    }
    let unit_totals =
        EntryPayload::fold_unit_totals(&legs).expect("no overflow in generated amounts");
    let pending = match (intent.class.as_str(), &intent.resolves) {
        ("Pending", _) => Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        }),
        (_, Some(r)) => Some(Pending {
            timeout_ns: None,
            resolution_of: Some(refs[r.target]),
            disposition: Some(match &r.posts {
                Some(ordinals) => Disposition::Posts {
                    source_ordinals: ordinals.clone(),
                },
                None => Disposition::Voids,
            }),
        }),
        _ => None,
    };
    let control = match &pending {
        Some(Pending {
            disposition: Some(Disposition::Voids),
            ..
        }) => Some(ControlPayload::ReservationRelease),
        _ => None,
    };
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
        control,
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
        pending,
        external_ids: Vec::new(),
        extensions: Vec::new(),
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
        "Pending",
        "Resolution",
        "Resolution",
        "Resolution",
        "Invoice",
        "Invoice",
        "Receipt",
        "Receipt",
        "Receipt",
    ];
    let leaf_codes = ["1000", "6000", "4000"];
    let mut history: Vec<Intent> = Vec::new();
    let mut posted_intents: Vec<Intent> = Vec::new();
    let mut reversed_targets: BTreeSet<usize> = BTreeSet::new();
    // Journal indexes of posted holds, and of holds that have a resolution.
    let mut holds: Vec<usize> = Vec::new();
    let mut resolved_targets: BTreeSet<usize> = BTreeSet::new();
    let mut posted_holds = 0u32;
    let mut posted_resolutions = (0u32, 0u32); // (Posts, Voids)
    // Journal indexes of posted invoices (Dr 1200 / Cr 4000) and counts of
    // posted applications and of reversals that undid one.
    let mut invoices: Vec<usize> = Vec::new();
    // Planted negative: the first Posts resolution against an open hold is
    // deliberately malformed (FA-REF-061), so the shape law is exercised on
    // every seed rather than by luck.
    let mut planted_shape = false;
    // Planted negatives: each of these refusals is produced deterministically
    // at the first step where its precondition holds, then removed; the rest
    // of the history is random. Coverage by construction, not by seed luck.
    let mut needed: BTreeSet<&'static str> = [
        "FA-REF-032",
        "FA-REF-070",
        "FA-REF-071",
        "FA-REF-072",
        "FA-REF-073",
    ]
    .into_iter()
    .collect();
    let mut applications_posted = 0u32;
    let mut undone = 0u32;
    // Kernel handles of posted entries, indexed like the oracle's journal.
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut posted = 0u32;
    let mut recorded = 0u32;
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();

    for step in 0..640u64 {
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

        let open_now = oracle.open_items();
        let mut planted: Option<Intent> = None;
        let fresh_key = format!("planted-{step}").into_bytes();
        let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
            side,
            account: account.into(),
            unit: usd.0,
            mantissa,
        };
        if needed.contains("FA-REF-032")
            && let Some(plain) = posted_intents
                .iter()
                .find(|i| i.reverses.is_none() && i.resolves.is_none() && i.settles.is_empty())
        {
            // Same key, different date: an idempotency conflict.
            let mut again = plain.clone();
            again.date = if again.date == dates[0] {
                dates[1]
            } else {
                dates[0]
            };
            planted = Some(again);
        } else if needed.contains("FA-REF-073")
            && let Some((i, _)) = invoices
                .iter()
                .filter_map(|i| open_now.get(&(*i, 0)).map(|(_, a, _)| (*i, *a)))
                .find(|(_, applied)| *applied > 0)
        {
            // Reversing an invoice with a live application.
            let original = oracle.entry(i).expect("posted invoice");
            planted = Some(Intent {
                class: "Reversal".into(),
                date: dates[1],
                discriminator: None,
                legs: original
                    .legs
                    .iter()
                    .map(|l| leg(l.side.flipped(), &l.account, l.mantissa))
                    .collect(),
                key: fresh_key.clone(),
                ops: vec!["post".into(), "post_closed".into()],
                approvals: 0,
                reverses: Some(i),
                resolves: None,
                settles: Vec::new(),
            });
        } else if (needed.contains("FA-REF-072") || needed.contains("FA-REF-071"))
            && let Some((i, open)) = invoices
                .iter()
                .filter_map(|i| open_now.get(&(*i, 0)).map(|(o, a, out)| (*i, o - out - a)))
                .find(|(_, open)| *open > 0)
        {
            // Over the open amount (072) or against the revenue leg (071).
            let (amount, ordinal) = if needed.contains("FA-REF-072") {
                (open + 1, 0)
            } else {
                (1, 1)
            };
            planted = Some(Intent {
                class: "Original".into(),
                date: dates[1],
                discriminator: None,
                legs: vec![
                    leg(fa_reference::Side::Debit, "1000", amount),
                    leg(fa_reference::Side::Credit, "1200", amount),
                ],
                key: fresh_key.clone(),
                ops: vec!["post".into(), "post_closed".into()],
                approvals: 0,
                reverses: None,
                resolves: None,
                settles: vec![Settle {
                    leg: 1,
                    target: i,
                    ordinal,
                    mantissa: amount,
                }],
            });
        } else if needed.contains("FA-REF-070")
            && let Some(h) = holds.first()
        {
            // A hold is not an open item.
            planted = Some(Intent {
                class: "Original".into(),
                date: dates[1],
                discriminator: None,
                legs: vec![
                    leg(fa_reference::Side::Debit, "1000", 7),
                    leg(fa_reference::Side::Credit, "1200", 7),
                ],
                key: fresh_key,
                ops: vec!["post".into(), "post_closed".into()],
                approvals: 0,
                reverses: None,
                resolves: None,
                settles: vec![Settle {
                    leg: 1,
                    target: *h,
                    ordinal: 1,
                    mantissa: 7,
                }],
            });
        }
        // Retry an earlier intent: identical (expect recorded) or with a
        // different date (expect an idempotency conflict).
        let intent = if let Some(p) = planted {
            p
        } else if !history.is_empty() && rng.chance(12) {
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
            if class == "Invoice" {
                let amount = 1_000 + rng.below(90_000) as i128;
                Intent {
                    class: "Original".into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs: vec![
                        Leg {
                            side: fa_reference::Side::Debit,
                            account: "1200".into(),
                            unit: usd.0,
                            mantissa: amount,
                        },
                        Leg {
                            side: fa_reference::Side::Credit,
                            account: "4000".into(),
                            unit: usd.0,
                            mantissa: amount,
                        },
                    ],
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                    resolves: None,
                    settles: Vec::new(),
                }
            } else if class == "Receipt" && !refs.is_empty() {
                // A receipt applies its credit leg to an open invoice leg:
                // mostly within the open amount, sometimes over it
                // (FA-REF-072), sometimes to the revenue leg (071), sometimes
                // to a non-invoice or a reversed one (070).
                let open_now = oracle.open_items();
                let live_invoices: Vec<(usize, i128)> = invoices
                    .iter()
                    .filter_map(|i| {
                        open_now
                            .get(&(*i, 0))
                            .map(|(orig, applied, out)| (*i, orig - out - applied))
                            .filter(|(_, open)| *open > 0)
                    })
                    .collect();
                let (target, open) = if !live_invoices.is_empty() && rng.chance(85) {
                    live_invoices[rng.below(live_invoices.len() as u64) as usize]
                } else {
                    (rng.below(refs.len() as u64) as usize, 0)
                };
                let amount = if open > 0 && rng.chance(75) {
                    1 + rng.below(open as u64) as i128
                } else {
                    open + 1 + rng.below(5_000) as i128
                };
                let ordinal = if rng.chance(10) { 1 } else { 0 };
                Intent {
                    class: "Original".into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs: vec![
                        Leg {
                            side: fa_reference::Side::Debit,
                            account: "1000".into(),
                            unit: usd.0,
                            mantissa: amount,
                        },
                        Leg {
                            side: fa_reference::Side::Credit,
                            account: "1200".into(),
                            unit: usd.0,
                            mantissa: amount,
                        },
                    ],
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                    resolves: None,
                    settles: vec![Settle {
                        leg: 1,
                        target,
                        ordinal,
                        mantissa: amount,
                    }],
                }
            } else if class == "Resolution" && !refs.is_empty() {
                // Prefer an unresolved hold, so the resolution law itself is
                // exercised; sometimes a posted non-hold (FA-REF-060) or an
                // already-resolved hold (FA-REF-062).
                let open: Vec<usize> = holds
                    .iter()
                    .copied()
                    .filter(|i| !resolved_targets.contains(i))
                    .collect();
                let force_shape = !planted_shape && !open.is_empty();
                let target = if force_shape || (!open.is_empty() && rng.chance(80)) {
                    open[rng.below(open.len() as u64) as usize]
                } else {
                    rng.below(refs.len() as u64) as usize
                };
                let original = oracle.entry(target).expect("posted entry");
                let (legs, posts) = if force_shape || rng.chance(50) {
                    // A balanced sub-vector: a total t ≤ T allocated greedily
                    // over the debit legs and over the credit legs, in order.
                    let total: i128 = original
                        .legs
                        .iter()
                        .filter(|l| l.side == fa_reference::Side::Debit)
                        .map(|l| l.mantissa)
                        .sum();
                    let t = 1 + rng.below(total.max(1) as u64) as i128;
                    let mut legs: Vec<Leg> = Vec::new();
                    let mut ordinals: Vec<u16> = Vec::new();
                    let mut remaining = [t, t];
                    for (i, l) in original.legs.iter().enumerate() {
                        let slot = if l.side == fa_reference::Side::Debit {
                            0
                        } else {
                            1
                        };
                        let take = remaining[slot].min(l.mantissa);
                        if take > 0 {
                            remaining[slot] -= take;
                            legs.push(Leg {
                                side: l.side,
                                account: l.account.clone(),
                                unit: l.unit,
                                mantissa: take,
                            });
                            ordinals.push(i as u16);
                        }
                    }
                    if (force_shape || rng.chance(25)) && !legs.is_empty() {
                        // Same amounts (still balanced), different account:
                        // not drawn from the hold (FA-REF-061).
                        legs[0].account = if legs[0].account == "1000" {
                            "6000".into()
                        } else {
                            "1000".into()
                        };
                    }
                    (legs, Some(ordinals))
                } else {
                    (Vec::new(), None)
                };
                Intent {
                    class: class.into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs,
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                    resolves: Some(Resolve { target, posts }),
                    settles: Vec::new(),
                }
            } else if class == "Reversal" && !refs.is_empty() {
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
                if rng.chance(15) && !legs.is_empty() {
                    // Same amounts (still balanced), different account: not
                    // the exact side-swap. (A voided hold has no legs; its
                    // "reversal" is refused as a non-posted target.)
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
                    resolves: None,
                    settles: Vec::new(),
                }
            } else {
                let class = if matches!(class, "Reversal" | "Resolution" | "Receipt") {
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
                    resolves: None,
                    settles: Vec::new(),
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
                if intent.class == "Pending" {
                    holds.push(*index);
                    posted_holds += 1;
                }
                if intent.class == "Original"
                    && intent.legs.len() == 2
                    && intent.legs[0].account == "1200"
                    && intent.settles.is_empty()
                {
                    invoices.push(*index);
                }
                if !intent.settles.is_empty() {
                    applications_posted += 1;
                }
                if let Some(t) = intent.reverses
                    && oracle.entry(t).is_some_and(|e| !e.settles.is_empty())
                {
                    undone += 1;
                }
                if let Some(r) = &intent.resolves {
                    resolved_targets.insert(r.target);
                    if r.posts.is_some() {
                        posted_resolutions.0 += 1;
                    } else {
                        posted_resolutions.1 += 1;
                    }
                }
            }
            (Ok(Posted::AlreadyRecorded { entry_ref, .. }), Verdict::Recorded { index }) => {
                assert_eq!(*entry_ref, refs[*index], "step {step}: recorded handle");
                recorded += 1;
            }
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, *code, "step {step}: refusal code for {intent:?}");
                *refused.entry(code).or_insert(0) += 1;
                if *code == "FA-REF-061" {
                    planted_shape = true;
                }
                needed.remove(*code);
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
    assert!(posted_holds >= 5, "holds {posted_holds}");
    assert!(
        applications_posted >= 5,
        "applications {applications_posted}"
    );
    assert!(undone >= 1, "no reversal undid an application");
    assert!(
        posted_resolutions.0 >= 3 && posted_resolutions.1 >= 3,
        "resolutions (posts, voids) {posted_resolutions:?}"
    );
    for must in [
        "FA-REF-001",
        "FA-REF-010",
        "FA-REF-032",
        "FA-REF-051",
        "FA-REF-060",
        "FA-REF-061",
        "FA-REF-062",
        "FA-REF-070",
        "FA-REF-071",
        "FA-REF-072",
        "FA-REF-073",
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
    // The pending registers agree too: unresolved holds, keyed on the hold's
    // own period; a resolution in any period releases the full hold once.
    for code in &periods {
        let kernel_fold = fold_period(&k.db, &k.book, code).unwrap();
        let model_pending = oracle.pending_fold(code);
        assert_eq!(
            kernel_fold.pending.len(),
            model_pending.len(),
            "{code}: pending cell count"
        );
        for cell in &kernel_fold.pending {
            let account_code = ACCOUNTS
                .iter()
                .map(|(c, ..)| *c)
                .find(|c| account_vid(k.book.book_id, c) == cell.key.account)
                .expect("known account");
            let m = model_pending.get(&(account_code.to_string(), cell.key.unit_id));
            assert!(
                m.is_some(),
                "{code}: oracle lacks pending cell {account_code}"
            );
            let m = m.expect("asserted above");
            assert_eq!(
                m.debits.to_i128(),
                Some(cell.debits),
                "{code}/{account_code} pending debits"
            );
            assert_eq!(
                m.credits.to_i128(),
                Some(cell.credits),
                "{code}/{account_code} pending credits"
            );
            assert_eq!(
                m.entry_count, cell.entry_count,
                "{code}/{account_code} pending count"
            );
        }
    }
    // Open items agree leg by leg (original, applied, open), and the kernel's
    // applied mirrors verify against the fold.
    let kernel_items = open_items(&k.db, &k.book, None, None).unwrap();
    let model_items = oracle.open_items();
    assert_eq!(kernel_items.len(), model_items.len(), "open item count");
    for item in &kernel_items {
        let index = refs
            .iter()
            .position(|r| r.vid == item.entry)
            .expect("kernel open item belongs to a posted entry");
        let model = model_items
            .get(&(index, usize::from(item.ordinal)))
            .copied();
        assert!(
            model.is_some(),
            "oracle lacks open item {index}/{}",
            item.ordinal
        );
        let (original, applied, applied_out) = model.expect("asserted above");
        assert_eq!(item.original, original, "{index}/{} original", item.ordinal);
        assert_eq!(item.applied, applied, "{index}/{} applied", item.ordinal);
        assert_eq!(
            item.applied_out, applied_out,
            "{index}/{} applied_out",
            item.ordinal
        );
        assert_eq!(
            item.open,
            original - applied_out - applied,
            "{index}/{} open",
            item.ordinal
        );
    }
    let verified = verify_open_items(&k.db, &k.book, None).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert!(verified.legs_checked > 0);

    // Corruption negative: a leg whose applied mirror is removed is drift to
    // the verifier and corruption to the kernel — never an implicit zero
    // that would admit a fresh over-application.
    let victim = kernel_items
        .iter()
        .find(|i| i.applied > 0)
        .expect("some live leg has an application");
    let victim_leg = fa_journal::rows::leg_vid(victim.entry, victim.ordinal);
    {
        let ctx = k.ctx();
        let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
        batch.set_vertex_property(victim_leg, fa_model::symbols::property::APPLIED, None);
        k.runtime
            .block_on(async { k.db.write(&ctx.commit(), batch).await })
            .expect("plant the missing mirror");
    }
    let verified = verify_open_items(&k.db, &k.book, None).unwrap();
    assert!(!verified.is_green(), "{verified:?}");
    assert!(
        verified
            .drift
            .iter()
            .any(|d| d.entry == victim.entry && d.ordinal == victim.ordinal && d.stored.is_none()),
        "{verified:?}"
    );
    let victim_index = refs
        .iter()
        .position(|r| r.vid == victim.entry)
        .expect("victim is a posted entry");
    // The corruption check lives behind the period law, so post into a
    // period both engines agree is Open: reopen March deterministically
    // (both engines, refusals ignored in lockstep) before the probe.
    for (n, t) in [
        PeriodTransition::Open,
        PeriodTransition::Reopen {
            to: PeriodState::Open,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let kernel = kernel_transition(&mut k, &periods[2], t, 9_000 + n as u64);
        let model = oracle.transition(&periods[2], t);
        assert_eq!(kernel.is_ok(), model.is_ok(), "reopen March for the probe");
    }
    assert_eq!(
        oracle.period_state(&periods[2]),
        Some(PeriodState::Open),
        "March must be Open for the corruption probe"
    );
    let receipt = Intent {
        class: "Original".into(),
        date: dates[1],
        discriminator: None,
        legs: vec![
            Leg {
                side: fa_reference::Side::Debit,
                account: "1000".into(),
                unit: usd.0,
                mantissa: 1,
            },
            Leg {
                side: fa_reference::Side::Credit,
                account: "1200".into(),
                unit: usd.0,
                mantissa: 1,
            },
        ],
        key: b"after-corruption".to_vec(),
        ops: vec!["post".into(), "post_closed".into()],
        approvals: 0,
        reverses: None,
        resolves: None,
        settles: vec![Settle {
            leg: 1,
            target: victim_index,
            ordinal: usize::from(victim.ordinal),
            mantissa: 1,
        }],
    };
    let outcome = kernel_post_raw(&mut k, &receipt, usd, &refs);
    assert!(
        matches!(outcome, Err(KernelError::Corrupt(_))),
        "a missing mirror must be corruption, got {outcome:?}"
    );
    // A negative mirror (which would inflate the open amount) and a mirror
    // above the leg's capacity are corruption too, and drift to the verifier.
    for (what, bad) in [("negative", -100i128), ("oversized", i128::MAX / 4)] {
        let ctx = k.ctx();
        let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
        batch.set_vertex_property(
            victim_leg,
            fa_model::symbols::property::APPLIED,
            Some(fa_journal::rows::mantissa_scalar("applied", bad).unwrap()),
        );
        k.runtime
            .block_on(async { k.db.write(&ctx.commit(), batch).await })
            .expect("plant the bad mirror");
        let verified = verify_open_items(&k.db, &k.book, None).unwrap();
        assert!(!verified.is_green(), "{what}: {verified:?}");
        let mut probe = receipt.clone();
        probe.key = format!("after-{what}").into_bytes();
        let outcome = kernel_post_raw(&mut k, &probe, usd, &refs);
        assert!(
            matches!(outcome, Err(KernelError::Corrupt(_))),
            "a {what} mirror must be corruption, got {outcome:?}"
        );
    }
    let tb = trial_balance(&k.db, &k.book, &periods).unwrap();
    assert!(tb.is_balanced(), "{:?}", tb.unit_totals);
}

fn create_year(k: &mut Kernel, oracle: &mut Oracle, year: i32) -> CommitSeq {
    let ctx = k.ctx();
    let (seq, _) = k
        .runtime
        .block_on(async { create_periods(&mut k.db, &ctx, &k.book, year).await })
        .expect("create real period definitions");
    oracle.create_periods(year);
    seq
}

fn open_period(k: &mut Kernel, oracle: &mut Oracle, code: &str, step: u64) {
    let transition =
        kernel_transition(k, code, PeriodTransition::Open, step).expect("open real period");
    let expected = oracle
        .transition(code, PeriodTransition::Open)
        .expect("open oracle period");
    assert_eq!((transition.from, transition.to), expected);
}

fn temporal_intent(
    date: (i32, u8, u8),
    adjustment: Option<&str>,
    debit: &str,
    credit: &str,
    amount: i128,
    key: &[u8],
    unit: UnitId,
) -> Intent {
    Intent {
        class: if adjustment.is_some() {
            "Adjusting"
        } else {
            "Original"
        }
        .into(),
        date: DateDay::from_ymd(date.0, date.1, date.2).unwrap(),
        discriminator: adjustment.map(str::to_owned),
        legs: vec![
            Leg {
                side: fa_reference::Side::Debit,
                account: debit.into(),
                unit: unit.0,
                mantissa: amount,
            },
            Leg {
                side: fa_reference::Side::Credit,
                account: credit.into(),
                unit: unit.0,
                mantissa: amount,
            },
        ],
        key: key.to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        resolves: None,
        settles: Vec::new(),
    }
}

/// Record the correspondence without teaching the oracle about CommitSeq.
/// Period creation and control commits advance only the substrate sequence.
fn post_temporal(k: &mut Kernel, oracle: &mut Oracle, intent: &Intent) -> (CommitSeq, usize) {
    let usd = k.book.units.lookup("USD").unwrap();
    let posted = kernel_post(k, intent, usd, &[]).expect("real monetary commit");
    let Posted::Committed {
        recorded_at,
        period,
        ..
    } = posted
    else {
        panic!("fixture must append a new entry: {posted:?}");
    };
    let expected_index = oracle.journal_len();
    assert_eq!(
        oracle.post(intent),
        Verdict::Posted {
            index: expected_index,
            period
        }
    );
    (recorded_at, oracle.journal_len())
}

fn assert_temporal_report(
    report: &TrialBalance,
    expected: BTreeMap<(String, u32), Cell>,
    known_at: CommitSeq,
    cutoff: Option<DateDay>,
) {
    assert_eq!(report.known_at, known_at);
    assert_eq!(report.effective_through, cutoff);
    assert_eq!(report.activity, cutoff.is_none());
    let actual: BTreeMap<_, _> = report
        .rows
        .iter()
        .map(|row| ((row.code.clone(), row.unit_id), (row.debits, row.credits)))
        .collect();
    assert_eq!(actual.len(), report.rows.len(), "duplicate report row");
    let expected_rows: BTreeMap<_, _> = expected
        .iter()
        .map(|(key, cell)| {
            (
                key.clone(),
                (
                    cell.debits.to_i128().unwrap(),
                    cell.credits.to_i128().unwrap(),
                ),
            )
        })
        .collect();
    assert_eq!(actual, expected_rows);

    // Totals use the oracle's limb arithmetic as well, independently of the
    // report's money path and independently of its is_balanced convenience.
    let mut totals: BTreeMap<u32, (Int, Int)> = BTreeMap::new();
    for ((_, unit), cell) in expected {
        let total = totals.entry(unit).or_insert((Int::zero(), Int::zero()));
        total.0 = total.0.add(&cell.debits);
        total.1 = total.1.add(&cell.credits);
    }
    let totals: BTreeMap<_, _> = totals
        .into_iter()
        .map(|(unit, (d, c))| (unit, (d.to_i128().unwrap(), c.to_i128().unwrap())))
        .collect();
    assert_eq!(report.unit_totals, totals);
}

fn assert_amounts(report: &TrialBalance, code: &str, debits: i128, credits: i128) {
    let row = report
        .rows
        .iter()
        .find(|row| row.code == code)
        .expect("account row");
    assert_eq!((row.debits, row.credits), (debits, credits), "{code}");
}

#[test]
fn temporal_stock_and_activity_agree_with_literal_journal_prefixes() {
    let (mut k, mut oracle, _) = setup();
    let usd = k.book.units.lookup("USD").unwrap();
    create_year(&mut k, &mut oracle, 2025);
    create_year(&mut k, &mut oracle, 2027);
    for (step, code) in ["FY2025-P12", "FY2026-P12", "FY2026-A1", "FY2027-P01"]
        .iter()
        .enumerate()
    {
        open_period(&mut k, &mut oracle, code, step as u64);
    }
    // §7.5: no opening entry. Prior-year cash 100 carries through a normal
    // Dec31 receipt 40 and a distinct same-date audit adjustment 7.
    let posts = [
        temporal_intent((2025, 12, 20), None, "1000", "4000", 100, b"prior", usd),
        temporal_intent((2026, 12, 31), None, "1000", "4000", 40, b"dec", usd),
        temporal_intent(
            (2026, 12, 31),
            Some("FY2026-A1"),
            "1000",
            "4000",
            7,
            b"adj",
            usd,
        ),
        temporal_intent((2027, 1, 10), None, "1000", "4000", 20, b"jan", usd),
        temporal_intent((2027, 1, 25), None, "6000", "1000", 9, b"later-day", usd),
    ];
    let checkpoints: Vec<_> = posts
        .iter()
        .map(|intent| post_temporal(&mut k, &mut oracle, intent))
        .collect();
    let (old_seq, old_prefix) = checkpoints[4];
    assert_eq!(old_prefix, 5);
    let dec31 = DateDay::from_ymd(2026, 12, 31).unwrap();
    let jan15 = DateDay::from_ymd(2027, 1, 15).unwrap();
    let jan31 = DateDay::from_ymd(2027, 1, 31).unwrap();
    let december = vec!["FY2026-P12".to_string()];
    let january = vec!["FY2027-P01".to_string()];
    let adjustment = vec!["FY2026-A1".to_string()];

    let dec_stock = trial_balance_at(&k.db, &k.book, &december, Some(old_seq)).unwrap();
    assert_temporal_report(
        &dec_stock,
        oracle.stock_at(dec31, old_prefix),
        old_seq,
        Some(dec31),
    );
    assert_amounts(&dec_stock, "1000", 147, 0);
    assert_amounts(&dec_stock, "4000", 0, 147);
    // Selecting the adjustment period has the same stock cutoff as Dec31,
    // but activity has a separate identity and includes only the 7 entry.
    let adj_stock = trial_balance_at(&k.db, &k.book, &adjustment, Some(old_seq)).unwrap();
    assert_temporal_report(
        &adj_stock,
        oracle.stock_at(dec31, old_prefix),
        old_seq,
        Some(dec31),
    );
    let dec_flow = period_activity(&k.db, &k.book, &december, Some(old_seq)).unwrap();
    assert_temporal_report(
        &dec_flow,
        oracle.activity_at(&["FY2026-P12"], old_prefix),
        old_seq,
        None,
    );
    assert_amounts(&dec_flow, "1000", 40, 0);
    let adj_flow = period_activity(&k.db, &k.book, &adjustment, Some(old_seq)).unwrap();
    assert_temporal_report(
        &adj_flow,
        oracle.activity_at(&["FY2026-A1"], old_prefix),
        old_seq,
        None,
    );
    assert_amounts(&adj_flow, "1000", 7, 0);

    let jan_stock = trial_balance_at(&k.db, &k.book, &january, Some(old_seq)).unwrap();
    assert_temporal_report(
        &jan_stock,
        oracle.stock_at(jan31, old_prefix),
        old_seq,
        Some(jan31),
    );
    assert_amounts(&jan_stock, "1000", 167, 9);
    assert_amounts(&jan_stock, "6000", 9, 0);
    let jan_flow = period_activity(&k.db, &k.book, &january, Some(old_seq)).unwrap();
    assert_temporal_report(
        &jan_flow,
        oracle.activity_at(&["FY2027-P01"], old_prefix),
        old_seq,
        None,
    );
    assert_amounts(&jan_flow, "1000", 20, 9);
    let midmonth = balance_as_of(&k.db, &k.book, jan15, Some(old_seq)).unwrap();
    assert_temporal_report(
        &midmonth,
        oracle.stock_at(jan15, old_prefix),
        old_seq,
        Some(jan15),
    );
    assert_amounts(&midmonth, "1000", 167, 0);
    assert!(
        midmonth.rows.iter().all(|row| row.code != "6000"),
        "Jan25 expense leaked into Jan15"
    );

    // This late-recorded backdate changes HEAD stock and December flow, but
    // cannot change either report at the saved recorded-time coordinate.
    let late = temporal_intent((2026, 12, 5), None, "1000", "4000", 3, b"backdate", usd);
    let (new_seq, new_prefix) = post_temporal(&mut k, &mut oracle, &late);
    assert_eq!(new_prefix, 6);
    assert!(new_seq > old_seq);
    assert_eq!(
        trial_balance_at(&k.db, &k.book, &december, Some(old_seq)).unwrap(),
        dec_stock
    );
    assert_eq!(
        period_activity(&k.db, &k.book, &december, Some(old_seq)).unwrap(),
        dec_flow
    );
    assert_eq!(
        balance_as_of(&k.db, &k.book, jan15, Some(old_seq)).unwrap(),
        midmonth
    );
    let new_dec = trial_balance_at(&k.db, &k.book, &december, None).unwrap();
    assert_temporal_report(
        &new_dec,
        oracle.stock_at(dec31, new_prefix),
        new_seq,
        Some(dec31),
    );
    assert_amounts(&new_dec, "1000", 150, 0);
    let new_jan = trial_balance_at(&k.db, &k.book, &january, None).unwrap();
    assert_temporal_report(
        &new_jan,
        oracle.stock_at(jan31, new_prefix),
        new_seq,
        Some(jan31),
    );
    assert_amounts(&new_jan, "1000", 170, 9);
    let new_flow = period_activity(&k.db, &k.book, &december, None).unwrap();
    assert_temporal_report(
        &new_flow,
        oracle.activity_at(&["FY2026-P12"], new_prefix),
        new_seq,
        None,
    );
    assert_amounts(&new_flow, "1000", 43, 0);
    let repeated = vec!["FY2026-P12".into(), "FY2026-A1".into(), "FY2026-P12".into()];
    let combined = period_activity(&k.db, &k.book, &repeated, None).unwrap();
    assert_temporal_report(
        &combined,
        oracle.activity_at(&["FY2026-P12", "FY2026-A1", "FY2026-P12"], new_prefix),
        new_seq,
        None,
    );
    assert_amounts(&combined, "1000", 50, 0);
    let unique = vec!["FY2026-A1".into(), "FY2026-P12".into()];
    assert_eq!(
        combined,
        period_activity(&k.db, &k.book, &unique, None).unwrap()
    );
}

#[test]
fn temporal_reports_resolve_period_metadata_at_the_recorded_snapshot() {
    let (mut k, mut oracle, _) = setup();
    open_period(&mut k, &mut oracle, "FY2026-P01", 0);
    let usd = k.book.units.lookup("USD").unwrap();
    let intent = temporal_intent((2026, 1, 10), None, "1000", "4000", 11, b"snapshot", usd);
    let (seq, prefix) = post_temporal(&mut k, &mut oracle, &intent);
    let year_end = DateDay::from_ymd(2026, 12, 31).unwrap();
    let year_end_period = vec!["FY2026-P12".to_string()];
    let before = trial_balance_at(&k.db, &k.book, &year_end_period, Some(seq)).unwrap();
    assert_temporal_report(
        &before,
        oracle.stock_at(year_end, prefix),
        seq,
        Some(year_end),
    );
    assert_amounts(&before, "1000", 11, 0);
    let future_day = DateDay::from_ymd(2027, 1, 31).unwrap();
    let day_before = balance_as_of(&k.db, &k.book, future_day, Some(seq)).unwrap();

    let metadata_seq = create_year(&mut k, &mut oracle, 2027);
    assert!(metadata_seq > seq);
    assert_eq!(
        oracle.journal_len(),
        prefix,
        "metadata is not a monetary entry"
    );
    assert_eq!(
        trial_balance_at(&k.db, &k.book, &year_end_period, Some(seq)).unwrap(),
        before
    );
    assert_eq!(
        balance_as_of(&k.db, &k.book, future_day, Some(seq)).unwrap(),
        day_before
    );
    let later_period = vec!["FY2027-P01".to_string()];
    assert!(
        trial_balance_at(&k.db, &k.book, &later_period, Some(seq)).is_err(),
        "period created later leaked into old snapshot"
    );
    assert!(
        period_activity(&k.db, &k.book, &later_period, Some(seq)).is_err(),
        "activity resolved a period that did not exist yet"
    );
    let current = trial_balance_at(&k.db, &k.book, &later_period, None).unwrap();
    assert_temporal_report(
        &current,
        oracle.stock_at(future_day, prefix),
        metadata_seq,
        Some(future_day),
    );
    assert_amounts(&current, "1000", 11, 0);
}
