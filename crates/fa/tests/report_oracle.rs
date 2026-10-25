//! Differential reference-oracle campaign for allocation laws and the
//! report families: roll-forward, general-ledger detail, effective-date
//! aging (with control reconciliation), direct cash flow, and indirect
//! cash flow (bead `fa-5kve`).
//!
//! Compare production (`fa_money::allocation`, `fa::Book`) against the naïve
//! `std` + `fa-time` + `Int`-only implementation in `fa_reference`.

use std::collections::BTreeMap;

use fa::{
    AdjustmentCategory, AdjustmentSign, AgingBuckets, AgingReconciliationRequest, Book, BookKeys,
    Capability, CashFlowActivity, CashFlowAssignment, CashFlowDefinition, Entropy,
    IndirectCashFlowAdjustment, IndirectCashFlowDefinition, IndirectCashFlowRequest,
    RollForwardRequest,
};
use fa_journal::{AccountSpec, BookSpec, Document, LegalEntitySpec, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128,
    LEGAL_ENTITY_DIMENSION, LegPayload, Oid, Settlement, Supersession, SupersessionKind,
    account_vid, entity_value_vid,
};
use fa_money::allocation::{
    equal_split_residual_first, largest_remainder, pro_rata_residual_to_named, waterfall,
};
use fa_money::wide::U256;
use fa_money::{Amount, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_reference::reports::{
    self, CashActivity, IndirectCategory, OracleIndirectAdjustment, RoundingMode,
};
use fa_reference::{
    Account as OracleAccount, Int, Intent as OracleIntent, Leg as OracleLeg, Oracle,
    Settle as OracleSettle, Side as OracleSide, Verdict,
};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition, WeekPattern, Weekday, YearEndRule};
use fgdb_bigint::{BigInt, LimbLimit};
use fgdb_types::VId;

const PRINCIPAL: VId = VId(1);

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn to_ref_mode(law: RoundingLaw) -> RoundingMode {
    match law {
        RoundingLaw::HalfUp => RoundingMode::HalfUp,
        RoundingLaw::HalfDown => RoundingMode::HalfDown,
        RoundingLaw::HalfEven => RoundingMode::HalfEven,
        RoundingLaw::HalfAwayFromZero => RoundingMode::HalfAwayFromZero,
        RoundingLaw::HalfTowardZero => RoundingMode::HalfTowardZero,
        RoundingLaw::Ceiling => RoundingMode::Ceiling,
        RoundingLaw::Floor => RoundingMode::Floor,
        RoundingLaw::TowardZero => RoundingMode::TowardZero,
        RoundingLaw::AwayFromZero => RoundingMode::AwayFromZero,
    }
}

#[test]
fn int_arithmetic_matches_fgdb_bigint_and_u256() {
    let limit = LimbLimit::new(16);
    let samples: Vec<u128> = vec![
        0,
        1,
        2,
        3,
        7,
        u128::from(u64::MAX) - 1,
        u128::from(u64::MAX),
        u128::from(u64::MAX) + 1,
        (1u128 << 96) + 123_456_789,
        i128::MAX as u128,
        (i128::MAX as u128) + 1,
        u128::MAX - 1,
        u128::MAX,
    ];

    for &a in &samples {
        for &b in &samples {
            let ia = Int::from_u128(a);
            let ib = Int::from_u128(b);
            let ba = BigInt::from_u128(a);
            let bb = BigInt::from_u128(b);

            let prod_int = ia.mul(&ib);
            let prod_big = ba.checked_mul(&bb, limit).unwrap();
            let prod_u256 = U256::from_u128(a).checked_mul_u128(b).unwrap();

            // Reconstruct U256 from Int via division by 2^128.
            let two_128 = Int::from_u128(1u128 << 64).mul(&Int::from_u128(1u128 << 64));
            let (hi_int, lo_int) = prod_int.div_rem(&two_128).unwrap();
            assert_eq!(hi_int.to_u128().unwrap(), prod_u256.hi);
            assert_eq!(lo_int.to_u128().unwrap(), prod_u256.lo);

            if b != 0 {
                let (q_int, r_int) = prod_int.div_rem(&ib).unwrap();
                let (q_big, r_big) = prod_big.checked_div_rem(&bb, limit).unwrap();
                assert_eq!(q_int, ia);
                assert!(r_int.is_zero());
                assert_eq!(
                    BigInt::from_u128(q_int.to_u128().unwrap()),
                    q_big,
                    "quotient mismatch for a={a}, b={b}"
                );
                assert!(r_big.is_zero());

                let (q2, r2) = ia.div_rem(&ib).unwrap();
                assert_eq!(q2.to_u128().unwrap(), a / b);
                assert_eq!(r2.to_u128().unwrap(), a % b);
            } else {
                assert!(ia.div_rem(&ib).is_none());
            }
        }
    }

    // Randomized 256-bit dividend / 128-bit divisor check against U256::checked_div_rem.
    let mut rng = 0xFA5C_5EED_0001_u64;
    for _ in 0..256 {
        let hi = u128::from(splitmix64(&mut rng));
        let lo = (u128::from(splitmix64(&mut rng)) << 64) | u128::from(splitmix64(&mut rng));
        let div =
            ((u128::from(splitmix64(&mut rng)) << 64) | u128::from(splitmix64(&mut rng))).max(1);

        let u_num = U256 { hi, lo };
        let u_den = U256::from_u128(div);
        let (u_q, u_r) = u_num.checked_div_rem(u_den).unwrap();

        let two_128 = Int::from_u128(1u128 << 64).mul(&Int::from_u128(1u128 << 64));
        let i_num = Int::from_u128(hi).mul(&two_128).add(&Int::from_u128(lo));
        let i_den = Int::from_u128(div);
        let (i_q, i_r) = i_num.div_rem(&i_den).unwrap();
        let (i_q_hi, i_q_lo) = i_q.div_rem(&two_128).unwrap();
        assert_eq!(i_q_hi.to_u128().unwrap(), u_q.hi);
        assert_eq!(i_q_lo.to_u128().unwrap(), u_q.lo);
        assert_eq!(i_r.to_u128().unwrap(), u_r.to_u128().unwrap());
    }
}

#[test]
fn allocation_laws_match_reference_oracle_and_kill_planted_mutations() {
    let unit = UnitId(1);
    let mut rng = 0xA110_CA7E_5EED_u64;

    let mut totals = vec![
        0i128,
        1,
        -1,
        2,
        -2,
        7,
        -7,
        100,
        -100,
        101,
        -101,
        999_999,
        -999_999,
        i128::MAX,
        -i128::MAX,
        i128::MIN,
    ];
    for _ in 0..48 {
        let raw = (i128::from(splitmix64(&mut rng)) << 32) ^ i128::from(splitmix64(&mut rng));
        totals.push(raw);
    }

    let weight_sets: Vec<Vec<u128>> = vec![
        vec![1],
        vec![1, 1],
        vec![1, 1, 1],
        vec![1, 2, 3],
        vec![3, 3, 3, 1],
        vec![5, 0, 5],
        vec![0, 7, 0, 13, 29],
        vec![u128::MAX, u128::MAX],
        vec![0, u128::MAX, 1],
        vec![13, 21, 34, 55, 89, 144],
    ];

    for &total in &totals {
        let amt = Amount::new(unit, total);

        for weights in &weight_sets {
            let prod_lr = largest_remainder(amt, weights)
                .unwrap()
                .into_iter()
                .map(|a| a.mantissa)
                .collect::<Vec<_>>();
            let ref_lr = reports::largest_remainder(total, weights).unwrap();
            assert_eq!(
                prod_lr, ref_lr,
                "largest_remainder mismatch for total={total}, weights={weights:?}"
            );

            // Planted mutation kill check: perturbing share[0] by +1/-1 is detected.
            if prod_lr.len() >= 2 {
                let mut mutated = prod_lr.clone();
                mutated[0] = mutated[0].wrapping_add(1);
                mutated[1] = mutated[1].wrapping_sub(1);
                assert_ne!(
                    mutated, ref_lr,
                    "planted largest_remainder perturbation must be caught"
                );
            }

            // Test pro_rata_residual_to_named across all 9 rounding laws.
            if total.unsigned_abs() <= (i128::MAX as u128) - 32 {
                for law in RoundingLaw::ALL {
                    for target in [0, weights.len() / 2, weights.len() - 1] {
                        let prod_pr = pro_rata_residual_to_named(amt, weights, target, law);
                        let ref_pr = reports::pro_rata_residual_to_named(
                            total,
                            weights,
                            target,
                            to_ref_mode(law),
                        );
                        match (prod_pr, ref_pr) {
                            (Ok(p), Ok(r)) => {
                                let p_rounded: Vec<i128> =
                                    p.rounded_shares.iter().map(|a| a.mantissa).collect();
                                let p_shares: Vec<i128> =
                                    p.shares.iter().map(|a| a.mantissa).collect();
                                assert_eq!(
                                    p_rounded, r.rounded_shares,
                                    "pro_rata rounded_shares mismatch for total={total}, law={law:?}, target={target}"
                                );
                                assert_eq!(
                                    p.residual.mantissa, r.residual,
                                    "pro_rata residual mismatch for total={total}, law={law:?}, target={target}"
                                );
                                assert_eq!(
                                    p_shares, r.shares,
                                    "pro_rata shares mismatch for total={total}, law={law:?}, target={target}"
                                );
                            }
                            (Err(_), Err(_)) => {}
                            (p, r) => panic!(
                                "pro_rata outcome mismatch for total={total}, law={law:?}: prod={p:?}, ref={r:?}"
                            ),
                        }
                    }
                }
            }
        }

        // Equal split residual first
        for count in [1usize, 2, 3, 5, 7, 16] {
            let prod_es = equal_split_residual_first(amt, count)
                .unwrap()
                .into_iter()
                .map(|a| a.mantissa)
                .collect::<Vec<_>>();
            let ref_es = reports::equal_split_residual_first(total, count).unwrap();
            assert_eq!(
                prod_es, ref_es,
                "equal_split_residual_first mismatch for total={total}, count={count}"
            );
        }

        // Waterfall
        let mag = total.unsigned_abs();
        let cap1 = mag / 3;
        let cap2 = mag / 2;
        let cap3 = mag - cap1 - cap2;
        let caps = vec![cap1, 0, cap2, cap3, 100];
        let prod_wf = waterfall(amt, &caps)
            .unwrap()
            .into_iter()
            .map(|a| a.mantissa)
            .collect::<Vec<_>>();
        let ref_wf = reports::waterfall(total, &caps).unwrap();
        assert_eq!(
            prod_wf, ref_wf,
            "waterfall mismatch for total={total}, caps={caps:?}"
        );

        // Short waterfall must refuse in both production and reference oracle.
        if mag > 0 {
            let short_caps = vec![mag - 1];
            assert!(waterfall(amt, &short_caps).is_err());
            assert!(reports::waterfall(total, &short_caps).is_err());
        }
    }
}

fn calendar_for_kind(kind_idx: usize) -> FiscalCalendar {
    match kind_idx % 3 {
        0 => FiscalCalendar::monthly("cal-monthly", 1, 0).unwrap(),
        1 => FiscalCalendar::weeks(
            "cal-445",
            WeekPattern::W445,
            YearEndRule::LastWeekdayOfMonth {
                weekday: Weekday::Saturday,
                month: 12,
            },
            0,
        )
        .unwrap(),
        _ => FiscalCalendar::week_52_53(
            "cal-5253",
            YearEndRule::WeekdayNearestEnd {
                weekday: Weekday::Saturday,
                month: 12,
            },
            0,
        )
        .unwrap(),
    }
}

fn cap(principal: VId, ops: &[&str]) -> Capability {
    Capability::embedded(principal, ops).unwrap()
}

struct CommittedEntry {
    vid: VId,
    digest: [u8; 32],
    oracle_index: usize,
    prod_legs: Vec<LegPayload>,
}

#[test]
fn report_families_match_reference_oracle_across_multiseed_campaign_and_kill_planted_mutations() {
    let seed_count: usize = std::env::var("FA_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);

    let units_reg = UnitRegistry::embedded().unwrap();
    let usd = units_reg.lookup("USD").unwrap();
    let eur = units_reg.lookup("EUR").unwrap();
    let jpy = units_reg.lookup("JPY").unwrap();

    for seed in 0..seed_count {
        let mut rng = 0xFA50_0000_0000_0000_u64 ^ (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);

        // Dimensions from bead fa-5kve:
        // {1, 3 units} x {1, 2 entities} x {3, 12 accounts} x 3 calendar kinds
        let active_units: Vec<UnitId> = if seed % 2 == 0 {
            vec![usd]
        } else {
            vec![usd, eur, jpy]
        };
        let entity_count = if (seed / 2) % 2 == 0 { 1 } else { 2 };
        let account_count = if (seed / 4) % 2 == 0 { 5 } else { 12 };
        let calendar = calendar_for_kind(seed / 8);

        let periods_2026 = calendar.periods_for_year(2026).unwrap();
        let p1 = &periods_2026[0];
        let p2 = &periods_2026[1];

        let book_id = Id128([(seed as u8).wrapping_add(1); 16]);
        let entities: Vec<LegalEntitySpec> = (0..entity_count)
            .map(|e_idx| LegalEntitySpec {
                code: format!("E{e_idx}"),
                name: format!("Entity {e_idx}"),
                functional_unit: usd,
            })
            .collect();

        let spec = BookSpec {
            book_id,
            name: format!("Oracle Campaign Seed {seed}"),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: entities.clone(),
            opening_date: None,
        };

        let mut book = Book::create_memory(
            BookKeys::for_development(seed as u8),
            spec,
            Entropy::deterministic(seed as u64),
        )
        .unwrap();

        // Base 5 monetary leaf accounts cover Asset (Cash + AR), Equity, Revenue, Expense.
        // When account_count == 12, add 7 additional leaf accounts across all 5 types.
        let mut account_defs: Vec<(&str, AccountType)> = vec![
            ("1000", AccountType::ASSET),   // Primary Cash
            ("1100", AccountType::ASSET),   // Accounts Receivable (open items)
            ("3000", AccountType::EQUITY),  // Contributed Equity
            ("4000", AccountType::REVENUE), // Operating Revenue
            ("6000", AccountType::EXPENSE), // Operating / Non-cash Expense
        ];
        if account_count > 5 {
            account_defs.extend([
                ("1010", AccountType::ASSET), // Secondary Cash (for internal transfers)
                ("1200", AccountType::ASSET), // Inventory / Equipment
                ("2000", AccountType::LIABILITY), // Accounts Payable / Working Capital
                ("2100", AccountType::LIABILITY), // Debt / Financing
                ("3100", AccountType::EQUITY), // Additional Equity
                ("4100", AccountType::REVENUE), // Service Revenue
                ("6100", AccountType::EXPENSE), // Depreciation / Non-Cash Expense
            ]);
        }

        let chart_specs: Vec<AccountSpec> = account_defs
            .iter()
            .map(|(code, kind)| AccountSpec {
                code: (*code).into(),
                name: format!("Account {code}"),
                account_type: kind.0,
                normal_balance: u8::from(matches!(
                    *kind,
                    AccountType::LIABILITY | AccountType::EQUITY | AccountType::REVENUE
                )),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect();

        book.install_chart(
            &chart_specs,
            PRINCIPAL,
            p1.start,
            b"install-chart",
            &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
        book.create_periods(
            2026,
            fgdb_types::VId(1),
            &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();

        let mut oracle = Oracle::new(calendar.clone());
        let entity_code_refs: Vec<&str> = entities.iter().map(|e| e.code.as_str()).collect();
        oracle.declare_entities(&entity_code_refs);
        for (code, _) in &account_defs {
            oracle.add_account(OracleAccount {
                code: (*code).to_string(),
                is_leaf: true,
                unit: None,
            });
        }
        oracle.create_periods(2026);

        for code in [&p1.code, &p2.code] {
            book.transition_period(
                code,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                format!("open-{code}").as_bytes(),
                &cap(PRINCIPAL, &["close"]),
            )
            .unwrap()
            .unwrap();
            oracle.transition(code, PeriodTransition::Open).unwrap();
        }

        let doc = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: format!("Evidence for seed {seed}").into_bytes(),
        };
        book.add_document(&doc).unwrap().unwrap();
        let evidence: Vec<EvidenceRef> = vec![doc.evidence_ref(1)];

        let mut cash_classifications: BTreeMap<(usize, usize), CashActivity> = BTreeMap::new();
        let mut cash_assignments: Vec<CashFlowAssignment> = Vec::new();
        let mut indirect_oracle_adjs: Vec<OracleIndirectAdjustment> = Vec::new();
        let mut indirect_prod_adjs: Vec<IndirectCashFlowAdjustment> = Vec::new();

        let cash_codes: Vec<String> = if account_count > 5 {
            vec!["1000".into(), "1010".into()]
        } else {
            vec!["1000".into()]
        };

        let pick_entity = |rng: &mut u64| -> (Vec<(u32, VId)>, Option<String>) {
            if entity_count == 1 {
                (Vec::new(), None)
            } else {
                let idx = (splitmix64(rng) as usize) % entity_count;
                let e = &entities[idx];
                (
                    vec![(LEGAL_ENTITY_DIMENSION, entity_value_vid(book_id, &e.code))],
                    Some(e.code.clone()),
                )
            }
        };

        // Helper to post an Original entry in both Book and Oracle.
        let mut post_seq = 0u64;
        #[allow(clippy::type_complexity)]
        let mut post_original = |book: &mut Book,
                                 oracle: &mut Oracle,
                                 day: DateDay,
                                 legs_spec: Vec<(
            &str,
            Side,
            UnitId,
            i128,
            Vec<Settlement>,
            Vec<(usize, usize, i128)>,
        )>,
                                 dims: (Vec<(u32, VId)>, Option<String>)|
         -> CommittedEntry {
            post_seq += 1;
            let key = format!("seed-{seed}-post-{post_seq}").into_bytes();
            let mut prod_legs = Vec::with_capacity(legs_spec.len());
            let mut oracle_legs = Vec::with_capacity(legs_spec.len());
            let mut oracle_settles = Vec::new();

            for (leg_idx, (code, side, unit, mantissa, settles, o_settles)) in
                legs_spec.into_iter().enumerate()
            {
                let mut leg = LegPayload::simple(
                    side,
                    account_vid(book_id, code),
                    Amount::new(unit, mantissa),
                );
                leg.dimension_set = dims.0.clone();
                leg.settles = settles;
                prod_legs.push(leg);

                oracle_legs.push(OracleLeg {
                    account: code.to_string(),
                    entity: dims.1.clone(),
                    unit: unit.0,
                    side: match side {
                        Side::Debit => OracleSide::Debit,
                        Side::Credit => OracleSide::Credit,
                    },
                    mantissa,
                });
                for (target_entry, target_leg, s_amt) in o_settles {
                    oracle_settles.push(OracleSettle {
                        leg: leg_idx,
                        target: target_entry,
                        ordinal: target_leg,
                        mantissa: s_amt,
                    });
                }
            }

            let proposal = EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: day,
                document_date: None,
                description: book.seal_text("campaign-entry").unwrap(),
                effective_period: None,
                unit_totals: EntryPayload::fold_unit_totals(&prod_legs).unwrap(),
                legs: prod_legs.clone(),
                control: None,
                base_totals: None,
                idempotency_key: key.clone(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([(seed as u8).wrapping_add(17); 32]),
                    intent_kind: 1,
                },
                principal_ref: PRINCIPAL,
                session_ref: None,
                evidence: evidence.clone(),
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                tags: Vec::new(),
                extensions: Vec::new(),
            };

            let posted = book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(PRINCIPAL, &["post"]),
                })
                .unwrap()
                .unwrap();

            let verdict = oracle.post(&OracleIntent {
                class: "Original".into(),
                date: day,
                discriminator: None,
                legs: oracle_legs,
                key,
                ops: vec!["post".into()],
                approvals: 0,
                reverses: None,
                supersession_reason: 1,
                resolves: None,
                settles: oracle_settles,
            });
            let oracle_index = match verdict {
                Verdict::Posted { index, .. } => index,
                other => panic!("expected Oracle::post to succeed, got {other:?}"),
            };

            let entry_ref = posted.entry_ref();
            CommittedEntry {
                vid: entry_ref.vid,
                digest: entry_ref.entry_digest,
                oracle_index,
                prod_legs,
            }
        };

        // 1. Period 1 opening postings (before p2.start):
        //    - Capital contribution: Dr 1000 Cash, Cr 3000 Equity
        //    - Receivable invoice: Dr 1100 AR, Cr 4000 Revenue (creates open item in P1)
        let p1_day1 = p1.start;
        let p1_day2 = DateDay((p1.start.0 + 2).min(p1.end.0 - 1));
        #[allow(clippy::type_complexity)]
        let mut p1_invoices: Vec<(
            CommittedEntry,
            UnitId,
            i128,
            (Vec<(u32, VId)>, Option<String>),
        )> = Vec::new();

        for &u in &active_units {
            let cap_amt = 10_000 + (splitmix64(&mut rng) % 50_000) as i128;
            let dims = pick_entity(&mut rng);
            let _cap_entry = post_original(
                &mut book,
                &mut oracle,
                p1_day1,
                vec![
                    ("1000", Side::Debit, u, cap_amt, Vec::new(), Vec::new()),
                    ("3000", Side::Credit, u, cap_amt, Vec::new(), Vec::new()),
                ],
                dims,
            );

            let inv_amt = 2_000 + (splitmix64(&mut rng) % 8_000) as i128;
            let inv_dims = pick_entity(&mut rng);
            let inv_entry = post_original(
                &mut book,
                &mut oracle,
                p1_day2,
                vec![
                    ("1100", Side::Debit, u, inv_amt, Vec::new(), Vec::new()),
                    ("4000", Side::Credit, u, inv_amt, Vec::new(), Vec::new()),
                ],
                inv_dims.clone(),
            );
            p1_invoices.push((inv_entry, u, inv_amt, inv_dims));
        }

        let known_after_p1_seq = book.head().unwrap();
        let known_after_p1_oracle = oracle.entries().len();

        // 2. Period 2 activity (within [p2.start, p2.end - 1]):
        let p2_day1 = p2.start;
        let p2_day2 = DateDay((p2.start.0 + 3).min(p2.end.0 - 1));
        let p2_day3 = DateDay((p2.start.0 + 6).min(p2.end.0 - 1));
        let p2_end_inclusive = DateDay(p2.end.0 - 1);

        for (inv_entry, u, inv_amt, inv_dims) in &p1_invoices {
            // (a) Cash sale in P2: Dr 1000 Cash (Operating), Cr 4000 Revenue
            let cash_sale = 1_500 + (splitmix64(&mut rng) % 4_000) as i128;
            let sale_dims = pick_entity(&mut rng);
            let e_sale = post_original(
                &mut book,
                &mut oracle,
                p2_day1,
                vec![
                    ("1000", Side::Debit, *u, cash_sale, Vec::new(), Vec::new()),
                    ("4000", Side::Credit, *u, cash_sale, Vec::new(), Vec::new()),
                ],
                sale_dims,
            );
            cash_classifications.insert((e_sale.oracle_index, 0), CashActivity::Operating);
            cash_assignments.push(CashFlowAssignment {
                entry_digest: e_sale.digest,
                leg_index: 0,
                activity: CashFlowActivity::Operating,
            });

            // (b) Partial collection of P1 receivable invoice in P2:
            //     Dr 1000 Cash (Operating), Cr 1100 AR (settling leg 0 of inv_entry; WorkingCapital adjustment +collect_amt)
            //     A foreign collection is posted unapplied, its credit an open
            //     item of its own: a foreign application relieves the open
            //     item's base carrying value (fa-pvt7, RemainingCarryingValue
            //     from a Settlement rate), and these foreign invoices carry
            //     no base valuation, so an unbound one is FA-REF-071.
            let collect_amt = inv_amt / 2;
            let (settle_prod, settle_oracle) = if *u == usd {
                (
                    vec![Settlement {
                        target: EntryRef {
                            vid: inv_entry.vid,
                            entry_digest: inv_entry.digest,
                        },
                        ordinal: 0,
                        amount: Amount::new(*u, collect_amt),
                    }],
                    vec![(inv_entry.oracle_index, 0usize, collect_amt)],
                )
            } else {
                (Vec::new(), Vec::new())
            };
            let e_collect = post_original(
                &mut book,
                &mut oracle,
                p2_day2,
                vec![
                    ("1000", Side::Debit, *u, collect_amt, Vec::new(), Vec::new()),
                    (
                        "1100",
                        Side::Credit,
                        *u,
                        collect_amt,
                        settle_prod,
                        settle_oracle,
                    ),
                ],
                inv_dims.clone(),
            );
            cash_classifications.insert((e_collect.oracle_index, 0), CashActivity::Operating);
            cash_assignments.push(CashFlowAssignment {
                entry_digest: e_collect.digest,
                leg_index: 0,
                activity: CashFlowActivity::Operating,
            });
            // Credit to AR (1100) reduces working capital -> increases operating cash relative to P2 net income
            indirect_oracle_adjs.push(OracleIndirectAdjustment {
                entry_index: e_collect.oracle_index,
                leg_index: 1,
                category: IndirectCategory::WorkingCapital,
                debit_minus_credit: false, // CreditMinusDebit => +collect_amt
            });
            indirect_prod_adjs.push(IndirectCashFlowAdjustment {
                entry_digest: e_collect.digest,
                leg_index: 1,
                category: AdjustmentCategory::WorkingCapital,
                sign: AdjustmentSign::CreditMinusDebit,
                reason: "AR collection in P2".into(),
            });

            // (c) Non-cash expense in P2: Dr 6000 Expense, Cr 1100 AR (or 2000 AP when 12 accounts)
            //     Reduces net income by exp_amt without cash outflow -> NonCash adjustment +exp_amt
            let exp_amt = 400 + (splitmix64(&mut rng) % 900) as i128;
            let credit_acc = if account_count > 5 { "2000" } else { "1100" };
            let exp_dims = pick_entity(&mut rng);
            let e_exp = post_original(
                &mut book,
                &mut oracle,
                p2_day2,
                vec![
                    ("6000", Side::Debit, *u, exp_amt, Vec::new(), Vec::new()),
                    (
                        credit_acc,
                        Side::Credit,
                        *u,
                        exp_amt,
                        Vec::new(),
                        Vec::new(),
                    ),
                ],
                exp_dims,
            );
            indirect_oracle_adjs.push(OracleIndirectAdjustment {
                entry_index: e_exp.oracle_index,
                leg_index: 0,
                category: IndirectCategory::NonCash,
                debit_minus_credit: true, // DebitMinusCredit on Dr Expense => +exp_amt
            });
            indirect_prod_adjs.push(IndirectCashFlowAdjustment {
                entry_digest: e_exp.digest,
                leg_index: 0,
                category: AdjustmentCategory::NonCash,
                sign: AdjustmentSign::DebitMinusCredit,
                reason: "Accrued non-cash expense".into(),
            });

            // (d) Financing cash inflow in P2: Dr 1000 Cash (Financing), Cr 3000 Equity
            let fin_amt = 800 + (splitmix64(&mut rng) % 2_000) as i128;
            let fin_dims = pick_entity(&mut rng);
            let e_fin = post_original(
                &mut book,
                &mut oracle,
                p2_day3,
                vec![
                    ("1000", Side::Debit, *u, fin_amt, Vec::new(), Vec::new()),
                    ("3000", Side::Credit, *u, fin_amt, Vec::new(), Vec::new()),
                ],
                fin_dims,
            );
            cash_classifications.insert((e_fin.oracle_index, 0), CashActivity::Financing);
            cash_assignments.push(CashFlowAssignment {
                entry_digest: e_fin.digest,
                leg_index: 0,
                activity: CashFlowActivity::Financing,
            });

            // (e) When 12 accounts exist, also post an InternalTransfer between 1000 and 1010
            //     and an Investing purchase of 1200 Inventory/Equipment.
            if account_count > 5 {
                let xfer_amt = 300 + (splitmix64(&mut rng) % 500) as i128;
                let xfer_dims = pick_entity(&mut rng);
                let e_xfer = post_original(
                    &mut book,
                    &mut oracle,
                    p2_day3,
                    vec![
                        ("1010", Side::Debit, *u, xfer_amt, Vec::new(), Vec::new()),
                        ("1000", Side::Credit, *u, xfer_amt, Vec::new(), Vec::new()),
                    ],
                    xfer_dims,
                );
                cash_classifications
                    .insert((e_xfer.oracle_index, 0), CashActivity::InternalTransfer);
                cash_classifications
                    .insert((e_xfer.oracle_index, 1), CashActivity::InternalTransfer);
                cash_assignments.push(CashFlowAssignment {
                    entry_digest: e_xfer.digest,
                    leg_index: 0,
                    activity: CashFlowActivity::InternalTransfer,
                });
                cash_assignments.push(CashFlowAssignment {
                    entry_digest: e_xfer.digest,
                    leg_index: 1,
                    activity: CashFlowActivity::InternalTransfer,
                });

                let inv_purchase = 250 + (splitmix64(&mut rng) % 400) as i128;
                let inv_p_dims = pick_entity(&mut rng);
                let e_inv = post_original(
                    &mut book,
                    &mut oracle,
                    p2_day3,
                    vec![
                        (
                            "1200",
                            Side::Debit,
                            *u,
                            inv_purchase,
                            Vec::new(),
                            Vec::new(),
                        ),
                        (
                            "1000",
                            Side::Credit,
                            *u,
                            inv_purchase,
                            Vec::new(),
                            Vec::new(),
                        ),
                    ],
                    inv_p_dims,
                );
                cash_classifications.insert((e_inv.oracle_index, 1), CashActivity::Investing);
                cash_assignments.push(CashFlowAssignment {
                    entry_digest: e_inv.digest,
                    leg_index: 1,
                    activity: CashFlowActivity::Investing,
                });

                // Mixed cash + operating revenue entry (fa-gb47):
                // Dr 1010 100 / Cr 1000 80 / Cr 4000 20 must net intra-entry cash
                // movement so gross operating inflows = +20, outflows = 0, net = +20.
                let mixed_dims = pick_entity(&mut rng);
                let e_mixed = post_original(
                    &mut book,
                    &mut oracle,
                    p2_day3,
                    vec![
                        ("1010", Side::Debit, *u, 100, Vec::new(), Vec::new()),
                        ("1000", Side::Credit, *u, 80, Vec::new(), Vec::new()),
                        ("4000", Side::Credit, *u, 20, Vec::new(), Vec::new()),
                    ],
                    mixed_dims,
                );
                cash_classifications.insert((e_mixed.oracle_index, 0), CashActivity::Operating);
                cash_classifications.insert((e_mixed.oracle_index, 1), CashActivity::Operating);
                cash_assignments.push(CashFlowAssignment {
                    entry_digest: e_mixed.digest,
                    leg_index: 0,
                    activity: CashFlowActivity::Operating,
                });
                cash_assignments.push(CashFlowAssignment {
                    entry_digest: e_mixed.digest,
                    leg_index: 1,
                    activity: CashFlowActivity::Operating,
                });
                eprintln!(
                    "oracle mixed-cash entry: seed={seed} unit={} oracle_idx={} legs=[(1010,D,100),(1000,C,80),(4000,C,20)] class=Operating",
                    u.0, e_mixed.oracle_index
                );
            }

            // (f) Also test a posted entry followed by its exact Reversal in P2!
            let rev_amt = 111 + (splitmix64(&mut rng) % 333) as i128;
            let rev_dims = pick_entity(&mut rng);
            let e_mistake = post_original(
                &mut book,
                &mut oracle,
                p2_day2,
                vec![
                    ("1000", Side::Debit, *u, rev_amt, Vec::new(), Vec::new()),
                    ("3000", Side::Credit, *u, rev_amt, Vec::new(), Vec::new()),
                ],
                rev_dims.clone(),
            );
            cash_classifications.insert((e_mistake.oracle_index, 0), CashActivity::Financing);
            cash_assignments.push(CashFlowAssignment {
                entry_digest: e_mistake.digest,
                leg_index: 0,
                activity: CashFlowActivity::Financing,
            });

            // Build exact side-swapped Reversal in both Book and Oracle.
            let rev_key = format!("rev-seed-{seed}-u-{}", u.0).into_bytes();
            let rev_legs: Vec<LegPayload> = e_mistake
                .prod_legs
                .iter()
                .map(|l| LegPayload {
                    side: match l.side {
                        Side::Debit => Side::Credit,
                        Side::Credit => Side::Debit,
                    },
                    ..l.clone()
                })
                .collect();
            let rev_proposal = EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::REVERSAL,
                effective_date: p2_day3,
                document_date: None,
                description: book.seal_text("reverse-mistake").unwrap(),
                effective_period: None,
                unit_totals: EntryPayload::fold_unit_totals(&rev_legs).unwrap(),
                legs: rev_legs,
                control: None,
                base_totals: None,
                idempotency_key: rev_key.clone(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([(seed as u8).wrapping_add(31); 32]),
                    intent_kind: 4,
                },
                principal_ref: PRINCIPAL,
                session_ref: None,
                evidence: evidence.clone(),
                supersession: vec![Supersession {
                    kind: SupersessionKind::Reverses,
                    target: EntryRef {
                        vid: e_mistake.vid,
                        entry_digest: e_mistake.digest,
                    },
                    reason_code: 1,
                }],
                pending: None,
                external_ids: Vec::new(),
                tags: Vec::new(),
                extensions: Vec::new(),
            };
            let rev_posted = book
                .post(PostRequest {
                    proposal: rev_proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(PRINCIPAL, &["post"]),
                })
                .unwrap()
                .unwrap();

            let rev_verdict = oracle.post(&OracleIntent {
                class: "Reversal".into(),
                date: p2_day3,
                discriminator: None,
                legs: vec![
                    OracleLeg {
                        account: "1000".into(),
                        entity: rev_dims.1.clone(),
                        unit: u.0,
                        side: OracleSide::Credit,
                        mantissa: rev_amt,
                    },
                    OracleLeg {
                        account: "3000".into(),
                        entity: rev_dims.1,
                        unit: u.0,
                        side: OracleSide::Debit,
                        mantissa: rev_amt,
                    },
                ],
                key: rev_key,
                ops: vec!["post".into()],
                approvals: 0,
                reverses: Some(e_mistake.oracle_index),
                supersession_reason: 1,
                resolves: None,
                settles: Vec::new(),
            });
            let rev_oracle_idx = match rev_verdict {
                Verdict::Posted { index, .. } => index,
                other => panic!("expected Oracle reversal to succeed, got {other:?}"),
            };
            let rev_ref = rev_posted.entry_ref();
            cash_classifications.insert((rev_oracle_idx, 0), CashActivity::Financing);
            cash_assignments.push(CashFlowAssignment {
                entry_digest: rev_ref.entry_digest,
                leg_index: 0,
                activity: CashFlowActivity::Financing,
            });
        }

        let head_seq = book.head().unwrap();
        let head_oracle = oracle.entries().len();
        let all_account_codes: Vec<String> =
            account_defs.iter().map(|(c, _)| (*c).to_string()).collect();
        let all_account_vids: Vec<VId> = all_account_codes
            .iter()
            .map(|c| account_vid(book_id, c))
            .collect();
        let unit_ids: Vec<u32> = active_units.iter().map(|u| u.0).collect();

        // -------------------------------------------------------------------
        // A. Trial Balance (stock & period activity) at both known_at frontiers
        // -------------------------------------------------------------------
        for (seq, o_len, cutoff) in [
            (known_after_p1_seq, known_after_p1_oracle, p1_day2),
            (head_seq, head_oracle, p2_end_inclusive),
        ] {
            let tb = book.balance_as_of(cutoff, Some(seq)).unwrap();
            let o_stock = oracle.stock_known(cutoff, oracle.known_after(o_len));
            for row in &tb.rows {
                let cell = o_stock
                    .get(&(row.code.clone(), row.unit_id))
                    .expect("oracle stock row");
                assert_eq!(
                    row.debits,
                    cell.debits.to_i128().unwrap(),
                    "seed={seed} stock debits mismatch for ({}, {})",
                    row.code,
                    row.unit_id
                );
                assert_eq!(
                    row.credits,
                    cell.credits.to_i128().unwrap(),
                    "seed={seed} stock credits mismatch for ({}, {})",
                    row.code,
                    row.unit_id
                );
            }
        }

        // -------------------------------------------------------------------
        // B. Roll-Forward Differential Check (P2 interval at HEAD and at P1)
        // -------------------------------------------------------------------
        let rf_request = RollForwardRequest {
            accounts: all_account_vids.clone(),
            units: unit_ids.clone(),
            label: format!("Seed {seed} P2 Roll-Forward"),
            effective_from: p2.start,
            effective_through: p2_end_inclusive,
            known_at: Some(head_seq),
        };
        let prod_rf = book
            .roll_forward(PRINCIPAL, &cap(PRINCIPAL, &["read"]), &rf_request)
            .unwrap()
            .unwrap();
        let ref_rf = reports::roll_forward(
            &oracle,
            oracle.known_after(head_oracle),
            p2.start,
            p2_end_inclusive,
            &all_account_codes,
            &unit_ids,
        );
        for row in &prod_rf.rows {
            let code = prod_rf
                .accounts
                .iter()
                .find(|a| a.id == row.account_id)
                .unwrap()
                .code
                .clone();
            let o_row = &ref_rf[&(code.clone(), row.unit_id)];
            assert_eq!(
                Int::from_i128(row.opening),
                o_row.opening,
                "seed={seed} roll-forward opening mismatch for ({code}, {})",
                row.unit_id
            );
            assert_eq!(
                Int::from_i128(row.net_change),
                o_row.net_change,
                "seed={seed} roll-forward net_change mismatch for ({code}, {})",
                row.unit_id
            );
            assert_eq!(
                Int::from_i128(row.closing),
                o_row.closing,
                "seed={seed} roll-forward closing mismatch for ({code}, {})",
                row.unit_id
            );
            for (b_idx, bucket) in prod_rf.buckets.iter().enumerate() {
                let class_name = bucket.class.name().unwrap();
                let o_class_amt = o_row
                    .by_class
                    .get(class_name)
                    .cloned()
                    .unwrap_or_else(Int::zero);
                // Sum all buckets in prod_rf sharing the same class name.
                let prod_class_sum: i128 = prod_rf
                    .buckets
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| b.class == bucket.class)
                    .map(|(i, _)| row.activity[i])
                    .sum();
                assert_eq!(
                    Int::from_i128(prod_class_sum),
                    o_class_amt,
                    "seed={seed} roll-forward bucket {b_idx} ({class_name}) mismatch for ({code}, {})",
                    row.unit_id
                );
            }
        }
        // Planted mutation kill check on roll-forward:
        {
            let mut mutated_closing = prod_rf.rows[0].closing;
            mutated_closing += 1;
            let first_code = prod_rf
                .accounts
                .iter()
                .find(|a| a.id == prod_rf.rows[0].account_id)
                .unwrap()
                .code
                .clone();
            assert_ne!(
                Int::from_i128(mutated_closing),
                ref_rf[&(first_code, prod_rf.rows[0].unit_id)].closing,
                "planted roll-forward closing perturbation must be caught"
            );
        }

        // -------------------------------------------------------------------
        // C. General-Ledger Detail Differential Check
        // -------------------------------------------------------------------
        let prod_gl = book
            .general_ledger(PRINCIPAL, &cap(PRINCIPAL, &["read"]), &rf_request)
            .unwrap()
            .unwrap();
        let ref_gl = reports::gl_detail(
            &oracle,
            oracle.known_after(head_oracle),
            p2.start,
            p2_end_inclusive,
            &all_account_codes,
            &unit_ids,
        );
        for cell in prod_gl.cells() {
            let code = prod_gl
                .accounts()
                .iter()
                .find(|a| a.id == cell.account_id)
                .unwrap()
                .code
                .clone();
            let o_cell = &ref_gl[&(code.clone(), cell.unit_id)];
            assert_eq!(Int::from_i128(cell.opening), o_cell.opening);
            assert_eq!(Int::from_i128(cell.debits), o_cell.debits);
            assert_eq!(Int::from_i128(cell.credits), o_cell.credits);
            assert_eq!(Int::from_i128(cell.net_change), o_cell.net_change);
            assert_eq!(Int::from_i128(cell.closing), o_cell.closing);

            let prod_lines = &prod_gl.lines()[cell.line_start as usize..cell.line_end as usize];
            assert_eq!(
                prod_lines.len(),
                o_cell.lines.len(),
                "seed={seed} GL line count mismatch for ({code}, {})",
                cell.unit_id
            );
            for (p_line, o_line) in prod_lines.iter().zip(&o_cell.lines) {
                assert_eq!(p_line.effective_day, o_line.effective_day);
                assert_eq!(p_line.leg_index as usize, o_line.leg_index);
                assert_eq!(p_line.debits, o_line.debits);
                assert_eq!(p_line.credits, o_line.credits);
                assert_eq!(
                    Int::from_i128(p_line.running_balance),
                    o_line.running_balance,
                    "seed={seed} GL running balance mismatch for ({code}, {})",
                    cell.unit_id
                );
            }
        }
        // Planted mutation kill check on GL detail running balance:
        if let Some(first_line) = prod_gl.lines().first() {
            let cell = &prod_gl.cells()[first_line.cell_index as usize];
            let code = prod_gl
                .accounts()
                .iter()
                .find(|a| a.id == cell.account_id)
                .unwrap()
                .code
                .clone();
            let o_line = &ref_gl[&(code, cell.unit_id)].lines[0];
            assert_ne!(
                Int::from_i128(first_line.running_balance.wrapping_add(1)),
                o_line.running_balance,
                "planted GL running_balance perturbation must be caught"
            );
        }

        // -------------------------------------------------------------------
        // D. Effective-Date Aging & Control Reconciliation Differential Check
        // -------------------------------------------------------------------
        let bucket_bounds = [0u32, 5, 15, 30, 60];
        let aging_buckets = AgingBuckets::new(bucket_bounds.to_vec()).unwrap();
        let ar_vid = account_vid(book_id, "1100");
        let prod_aging = book
            .effective_date_aging(
                Some(ar_vid),
                p2_end_inclusive,
                Some(head_seq),
                &aging_buckets,
            )
            .unwrap();
        let prod_recon = book
            .reconcile_effective_date_aging(
                PRINCIPAL,
                &cap(PRINCIPAL, &["read"]),
                &AgingReconciliationRequest {
                    account: ar_vid,
                    effective_through: p2_end_inclusive,
                    known_at: Some(head_seq),
                    buckets: aging_buckets.clone(),
                },
            )
            .unwrap()
            .unwrap();
        assert!(
            prod_recon.is_reconciled(),
            "seed={seed} AR aging reconciliation must tie to control TB"
        );

        let ref_aging = reports::aging(
            &oracle,
            head_oracle,
            Some("1100"),
            p2_end_inclusive,
            &bucket_bounds,
        );
        for total in &prod_aging.totals {
            let o_acc = &ref_aging[&("1100".to_string(), total.unit_id)];
            assert_eq!(Int::from_i128(total.amounts.debits), o_acc.total_debits);
            assert_eq!(Int::from_i128(total.amounts.credits), o_acc.total_credits);
            assert_eq!(
                Int::from_i128(total.amounts.debits - total.amounts.credits),
                o_acc.total_net
            );
            assert_eq!(
                o_acc.total_net, o_acc.control_net,
                "seed={seed} oracle open_net must equal control_net on AR 1100"
            );
        }
        for cell in &prod_aging.cells {
            let o_band = &ref_aging[&("1100".to_string(), cell.unit_id)].bands[cell.bucket];
            assert_eq!(Int::from_i128(cell.amounts.debits), o_band.debits);
            assert_eq!(Int::from_i128(cell.amounts.credits), o_band.credits);
            assert_eq!(
                Int::from_i128(cell.amounts.debits - cell.amounts.credits),
                o_band.net
            );
            assert_eq!(cell.amounts.item_count as usize, o_band.item_count);
        }
        for r_row in prod_recon.rows() {
            let o_acc = &ref_aging[&("1100".to_string(), r_row.unit_id)];
            assert_eq!(Int::from_i128(r_row.open_net), o_acc.total_net);
            assert_eq!(Int::from_i128(r_row.posted_net), o_acc.control_net);
            assert_eq!(r_row.difference, 0);
        }
        // Planted mutation kill check on Aging:
        {
            let first_u = active_units[0].0;
            let o_acc = &ref_aging[&("1100".to_string(), first_u)];
            assert_ne!(
                o_acc.total_net.add(&Int::from_i128(1)),
                o_acc.control_net,
                "planted aging open_net perturbation must break control tie-out"
            );
        }

        // -------------------------------------------------------------------
        // E. Direct Cash Flow Differential Check
        // -------------------------------------------------------------------
        let cash_vids: Vec<VId> = cash_codes.iter().map(|c| account_vid(book_id, c)).collect();
        let cash_rf_request = RollForwardRequest {
            accounts: cash_vids.clone(),
            units: unit_ids.clone(),
            label: format!("Seed {seed} P2 Cash"),
            effective_from: p2.start,
            effective_through: p2_end_inclusive,
            known_at: Some(head_seq),
        };
        let cf_def = CashFlowDefinition {
            name: format!("seed-{seed}-cf"),
            cash_accounts: cash_vids.iter().map(|v| v.0).collect(),
            assignments: cash_assignments.clone(),
        };
        let prod_cf = book
            .cash_flow(
                PRINCIPAL,
                &cap(PRINCIPAL, &["read"]),
                &cash_rf_request,
                &cf_def,
            )
            .unwrap()
            .unwrap();
        let ref_cf = reports::direct_cash_flow(
            &oracle,
            oracle.known_after(head_oracle),
            p2.start,
            p2_end_inclusive,
            &cash_codes,
            &unit_ids,
            &cash_classifications,
        )
        .unwrap();

        for p_unit in prod_cf.units() {
            let o_unit = &ref_cf[&p_unit.unit_id];
            assert_eq!(Int::from_i128(p_unit.opening), o_unit.opening);
            assert_eq!(
                Int::from_i128(p_unit.operating.inflows),
                o_unit.operating.inflows
            );
            assert_eq!(
                Int::from_i128(p_unit.operating.outflows),
                o_unit.operating.outflows
            );
            assert_eq!(Int::from_i128(p_unit.operating.net), o_unit.operating.net);
            assert_eq!(
                Int::from_i128(p_unit.investing.inflows),
                o_unit.investing.inflows
            );
            assert_eq!(
                Int::from_i128(p_unit.investing.outflows),
                o_unit.investing.outflows
            );
            assert_eq!(Int::from_i128(p_unit.investing.net), o_unit.investing.net);
            assert_eq!(
                Int::from_i128(p_unit.financing.inflows),
                o_unit.financing.inflows
            );
            assert_eq!(
                Int::from_i128(p_unit.financing.outflows),
                o_unit.financing.outflows
            );
            assert_eq!(Int::from_i128(p_unit.financing.net), o_unit.financing.net);
            assert_eq!(
                Int::from_i128(p_unit.exchange_effects.net),
                o_unit.exchange_effects.net
            );
            assert_eq!(Int::from_i128(p_unit.net_change), o_unit.net_change);
            assert_eq!(Int::from_i128(p_unit.closing), o_unit.closing);
        }
        // Planted mutation kill check on Direct Cash Flow: omitting an assignment must fail.
        {
            let mut incomplete = cash_classifications.clone();
            let first_key = *incomplete.keys().next().unwrap();
            incomplete.remove(&first_key);
            assert!(
                reports::direct_cash_flow(
                    &oracle,
                    oracle.known_after(head_oracle),
                    p2.start,
                    p2_end_inclusive,
                    &cash_codes,
                    &unit_ids,
                    &incomplete,
                )
                .is_err(),
                "unclassified cash leg must be refused by reference oracle"
            );
        }

        // -------------------------------------------------------------------
        // F. Indirect Cash Flow Differential Check
        // -------------------------------------------------------------------
        let icf_request = IndirectCashFlowRequest {
            cash: cash_rf_request,
            cash_definition: cf_def,
            income_periods: vec![p2.code.clone()],
            definition: IndirectCashFlowDefinition {
                name: format!("seed-{seed}-icf"),
                adjustments: indirect_prod_adjs,
            },
        };
        let prod_icf = book
            .indirect_cash_flow(PRINCIPAL, &cap(PRINCIPAL, &["read"]), &icf_request)
            .unwrap()
            .unwrap();

        // Compute P2 Net Income in the reference oracle:
        // Revenue (4000, 4100) credits minus debits, minus Expense (6000, 6100) debits minus credits.
        let o_p2_fold = oracle.activity_known(&[p2.code.as_str()], oracle.known_after(head_oracle));
        let mut o_net_income_by_unit: BTreeMap<u32, Int> = BTreeMap::new();
        for &u in &unit_ids {
            let mut ni = Int::zero();
            for (code, kind) in &account_defs {
                if let Some(cell) = o_p2_fold.get(&((*code).to_string(), u)) {
                    if *kind == AccountType::REVENUE {
                        ni = ni.add(&cell.credits.sub(&cell.debits));
                    } else if *kind == AccountType::EXPENSE {
                        ni = ni.sub(&cell.debits.sub(&cell.credits));
                    }
                }
            }
            o_net_income_by_unit.insert(u, ni);
        }

        let ref_icf = reports::indirect_cash_flow(
            &oracle,
            oracle.known_after(head_oracle),
            p2.start,
            p2_end_inclusive,
            &cash_codes,
            &o_net_income_by_unit,
            &ref_cf,
            &indirect_oracle_adjs,
        )
        .unwrap();

        for p_unit in prod_icf.units() {
            let o_unit = &ref_icf[&p_unit.unit_id];
            assert_eq!(Int::from_i128(p_unit.net_income), o_unit.net_income);
            assert_eq!(Int::from_i128(p_unit.non_cash), o_unit.non_cash);
            assert_eq!(
                Int::from_i128(p_unit.working_capital),
                o_unit.working_capital
            );
            assert_eq!(Int::from_i128(p_unit.non_operating), o_unit.non_operating);
            assert_eq!(Int::from_i128(p_unit.operating), o_unit.operating);
            assert_eq!(
                Int::from_i128(p_unit.direct_operating),
                o_unit.direct_operating
            );
            assert_eq!(p_unit.operating_residual, 0);
            assert!(o_unit.operating_residual.is_zero());
            assert_eq!(Int::from_i128(p_unit.opening), o_unit.opening);
            assert_eq!(Int::from_i128(p_unit.investing), o_unit.investing);
            assert_eq!(Int::from_i128(p_unit.financing), o_unit.financing);
            assert_eq!(
                Int::from_i128(p_unit.exchange_effects),
                o_unit.exchange_effects
            );
            assert_eq!(Int::from_i128(p_unit.net_change), o_unit.net_change);
            assert_eq!(Int::from_i128(p_unit.closing), o_unit.closing);
        }
        // Planted mutation kill check on Indirect Cash Flow: flipping an adjustment sign breaks tie-out.
        {
            let mut bad_adjs = indirect_oracle_adjs.clone();
            bad_adjs[0].debit_minus_credit = !bad_adjs[0].debit_minus_credit;
            assert!(
                reports::indirect_cash_flow(
                    &oracle,
                    oracle.known_after(head_oracle),
                    p2.start,
                    p2_end_inclusive,
                    &cash_codes,
                    &o_net_income_by_unit,
                    &ref_cf,
                    &bad_adjs,
                )
                .is_err(),
                "flipped indirect adjustment sign must fail reconciliation"
            );
        }
    }
}
