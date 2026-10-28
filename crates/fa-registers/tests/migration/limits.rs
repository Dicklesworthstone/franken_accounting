//! Migration activation against stored cells, the register reconstruction,
//! and the independent limb-integer oracle. Staged chunks never consume or
//! create availability; the single Finalize boundary is the movement.

use super::*;
use fa_model::Pending;

fn ops() -> Vec<String> {
    vec!["post".into(), "migrate".into()]
}

fn open_both(k: &mut Kernel, oracle: &mut Oracle, spec: &RunSpec) -> (VId, usize) {
    let key = format!("open-{}", spec.key);
    let run = kernel_open(k, spec, &key, &["post", "migrate"])
        .expect("opens")
        .run;
    let model = oracle
        .open_run(spec, key.as_bytes(), &ops())
        .expect("oracle opens");
    (run, model)
}

fn live(
    k: &mut Kernel,
    oracle: &mut Oracle,
    key: &str,
    debit: &str,
    credit: &str,
    amount: i128,
    pending: bool,
) {
    let mut intent = trunk_intent(
        key,
        vec![
            leg(fa_reference::Side::Debit, debit, amount),
            leg(fa_reference::Side::Credit, credit, amount),
        ],
    );
    if oracle.period_state(P01) == Some(PeriodState::Locked) {
        intent.date = DateDay::from_ymd(2026, 4, 15).unwrap();
    }
    if pending {
        intent.class = "Pending".into();
    }
    let mut proposal = chunk_payload(k, VId(0), &intent, Shape::NoRun, None);
    if pending {
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
    }
    kernel_post(k, proposal, &["post"], false).expect("live movement");
    assert!(
        matches!(oracle.post(&intent), Verdict::Posted { .. }),
        "{key}"
    );
}

fn cut(k: &Kernel, oracle: &Oracle) -> (CommitSeq, Known) {
    (k.db.frontier().unwrap(), oracle.known())
}

fn assert_cell(
    k: &Kernel,
    oracle: &Oracle,
    period: Option<&str>,
    at: (CommitSeq, Known),
    sums: [i128; 4],
    generation: u64,
) {
    let verified = fa_registers::verify_availability(&k.db, &k.book, Some(at.0))
        .expect("reconstruction is bounded");
    assert!(verified.is_green(), "{verified:?}");
    let cell = &verified
        .accounts
        .iter()
        .find(|a| a.code == "1500" && a.period.as_deref() == period)
        .expect("limited account cell")
        .cell;
    assert_eq!(
        [
            cell.debits_posted,
            cell.credits_posted,
            cell.debits_pending,
            cell.credits_pending,
        ],
        sums,
        "{period:?} at {:?}",
        at.0
    );
    assert_eq!(
        u64::try_from(cell.generation).ok(),
        Some(generation),
        "{period:?} at {:?}",
        at.0
    );
    let model = oracle.availability_known("1500", period, at.1);
    assert_eq!(
        [
            model.debits_posted.to_i128().unwrap(),
            model.credits_posted.to_i128().unwrap(),
            model.debits_pending.to_i128().unwrap(),
            model.credits_pending.to_i128().unwrap(),
        ],
        sums,
        "independent oracle at {at:?}"
    );
    assert_eq!(model.generation, generation);
}

fn refused_finalize(
    k: &mut Kernel,
    oracle: &mut Oracle,
    run: (VId, usize),
    chunks: usize,
    key: &str,
    code: &str,
) {
    let proposal = kernel_plan(k, run.0, kind::FINALIZE, key).expect("ties out");
    let approvals = approve(k, proposal.proposal_digest().unwrap());
    let request = RunControlRequest {
        proposal,
        capability: capability(&["post", "migrate"]),
        approvals,
    };
    let ctx = k.ctx();
    let before = k.db.frontier().unwrap();
    let refusal = k
        .runtime
        .block_on(transition_run(&mut k.db, &ctx, &k.book, request))
        .expect("kernel")
        .expect_err("activation must refuse");
    assert_eq!((refusal.code, refusal.exit), (code, 3), "{refusal}");
    assert_eq!(k.db.frontier().unwrap(), before, "no partial activation");
    assert_eq!(
        read_run(&k.db, run.0, None).unwrap().unwrap().state,
        RunState::Open
    );
    assert_eq!(
        oracle.finalize_run(run.1, chunks, key.as_bytes(), &ops(), 2),
        Err(code)
    );
}

#[test]
fn migration_into_limited_account_reconstructs_its_limit_cell() {
    let (mut k, mut oracle) = setup();
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    live(&mut k, &mut oracle, "fund", "1500", "3000", 100, false);
    live(&mut k, &mut oracle, "reserve", "6000", "1500", 80, true);
    let before = cut(&k, &oracle);
    let spec = RunSpec {
        key: "limited".into(),
        opening_date: opening_date(),
        lines: usd_lines(&[("1500", 50), ("3000", -60), ("6000", 10)]),
        periods: vec![],
        full_detail: None,
    };
    let run = open_both(&mut k, &mut oracle, &spec);
    let chunks = [
        chunk_intent("deposited", vec![leg(dr, "1500", 60), leg(cr, "3000", 60)]),
        chunk_intent("spent", vec![leg(dr, "6000", 10), leg(cr, "1500", 10)]),
        // A zero-net chunk still contributes both gross sides. The run as
        // a whole advances the cell once, not once per chunk or side.
        chunk_intent("gross", vec![leg(dr, "1500", 25), leg(cr, "1500", 25)]),
    ];
    stage_all(&mut k, &mut oracle, run, &chunks, "limited chunk");
    let staged = cut(&k, &oracle);
    for at in [before, staged] {
        assert_cell(&k, &oracle, None, at, [100, 0, 0, 80], 2);
    }
    let plan = kernel_plan(&k, run.0, kind::FINALIZE, "activate").unwrap();
    kernel_transition(&mut k, plan.clone(), true).unwrap();
    oracle
        .finalize_run(run.1, 3, b"activate", &ops(), 2)
        .unwrap();
    let activated = cut(&k, &oracle);
    assert_cell(&k, &oracle, None, activated, [185, 35, 0, 80], 3);
    for at in [before, staged] {
        assert_cell(&k, &oracle, None, at, [100, 0, 0, 80], 2);
    }

    // A recorded retry neither needs fresh approvals nor moves a cell.
    kernel_transition(&mut k, plan, false).expect("recorded retry");
    oracle
        .finalize_run(run.1, 3, b"activate", &ops(), 0)
        .expect("recorded model retry");
    assert_eq!(cut(&k, &oracle), activated);
    assert_cell(&k, &oracle, None, activated, [185, 35, 0, 80], 3);

    let abandoned = RunSpec {
        key: "discarded".into(),
        lines: usd_lines(&[("1500", -1_000), ("6000", 1_000)]),
        ..spec
    };
    let abandoned_run = open_both(&mut k, &mut oracle, &abandoned);
    stage_all(
        &mut k,
        &mut oracle,
        abandoned_run,
        &[chunk_intent(
            "never-visible",
            vec![leg(dr, "6000", 1_000), leg(cr, "1500", 1_000)],
        )],
        "even an unavailable amount may stage",
    );
    let plan = kernel_plan(&k, abandoned_run.0, kind::ABANDON, "abandon").unwrap();
    kernel_transition(&mut k, plan, false).unwrap();
    oracle
        .abandon_run(abandoned_run.1, 1, b"abandon", &ops())
        .unwrap();
    assert_cell(&k, &oracle, None, cut(&k, &oracle), [185, 35, 0, 80], 3);

    // Imported availability is spendable, while existing reservations remain
    // protected. The lower bound is exact: 150 - 80 = 70.
    live(
        &mut k,
        &mut oracle,
        "spend-import",
        "6000",
        "1500",
        70,
        false,
    );
    assert_cell(&k, &oracle, None, cut(&k, &oracle), [185, 105, 0, 80], 4);
    let over = trunk_intent("over", vec![leg(dr, "6000", 1), leg(cr, "1500", 1)]);
    let proposal = chunk_payload(&k, VId(0), &over, Shape::NoRun, None);
    assert_eq!(
        kernel_post(&mut k, proposal, &["post"], false)
            .unwrap_err()
            .code,
        "FA-REF-090"
    );
    assert_eq!(verdict_code(&oracle.post(&over)), Err("FA-REF-090"));
    assert_cell(&k, &oracle, None, activated, [185, 35, 0, 80], 3);
}

#[test]
fn migration_limits_judge_current_reservations_only_at_finalize() {
    let (mut k, mut oracle) = setup();
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    live(&mut k, &mut oracle, "fund", "1500", "3000", 100, false);
    live(&mut k, &mut oracle, "reserve", "6000", "1500", 80, true);
    let spec = RunSpec {
        key: "outgoing".into(),
        opening_date: opening_date(),
        lines: usd_lines(&[("1500", -30), ("6000", 30)]),
        periods: vec![],
        full_detail: None,
    };
    let run = open_both(&mut k, &mut oracle, &spec);
    stage_all(
        &mut k,
        &mut oracle,
        run,
        &[chunk_intent(
            "legacy-outgoing",
            vec![leg(dr, "6000", 30), leg(cr, "1500", 30)],
        )],
        "stage before checking availability",
    );
    let staged = cut(&k, &oracle);
    refused_finalize(&mut k, &mut oracle, run, 1, "activate", "FA-REF-090");
    assert_cell(&k, &oracle, None, cut(&k, &oracle), [100, 0, 0, 80], 2);
    live(&mut k, &mut oracle, "new-funds", "1500", "3000", 20, false);
    finalize_both(&mut k, &mut oracle, run, 1, "activate");
    assert_cell(&k, &oracle, None, cut(&k, &oracle), [120, 30, 0, 80], 4);
    assert_cell(&k, &oracle, None, staged, [100, 0, 0, 80], 2);
}

#[test]
fn migration_limits_enforce_upper_bounds_and_gross_representation() {
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    for (name, funded, pending, imported, upper, code) in [
        ("upper", 50, 20, 40, Some(100), "FA-REF-091"),
        ("gross", 1, 0, i128::MAX, None, "FA-REF-092"),
    ] {
        let (mut k, mut oracle) = setup_with_limit(
            None,
            BalanceLimit {
                lower: Some(0),
                upper,
                scope: LimitScope::Lifetime,
            },
        );
        live(&mut k, &mut oracle, "fund", "1500", "3000", funded, false);
        if pending > 0 {
            live(
                &mut k,
                &mut oracle,
                "incoming",
                "1500",
                "3000",
                pending,
                true,
            );
        }
        let spec = RunSpec {
            key: name.into(),
            opening_date: opening_date(),
            lines: usd_lines(&[("1500", imported), ("3000", -imported)]),
            periods: vec![],
            full_detail: None,
        };
        let run = open_both(&mut k, &mut oracle, &spec);
        stage_all(
            &mut k,
            &mut oracle,
            run,
            &[chunk_intent(
                "import",
                vec![leg(dr, "1500", imported), leg(cr, "3000", imported)],
            )],
            "limits are deferred to activation",
        );
        refused_finalize(&mut k, &mut oracle, run, 1, "activate", code);
        assert_cell(
            &k,
            &oracle,
            None,
            cut(&k, &oracle),
            [funded, 0, pending, 0],
            if pending > 0 { 2 } else { 1 },
        );
    }
}

#[test]
fn migration_limits_keep_each_chunks_original_budget_period() {
    let (mut k, mut oracle) = setup_with_limit(
        Some((go_live(), GO_LIVE_PERIOD)),
        BalanceLimit {
            lower: None,
            upper: Some(100),
            scope: LimitScope::Period,
        },
    );
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    live(&mut k, &mut oracle, "current", "1500", "3000", 70, false);
    live(
        &mut k,
        &mut oracle,
        "current-incoming",
        "1500",
        "3000",
        20,
        true,
    );
    let opening = usd_lines(&[("1500", 80), ("3000", -80)]);
    let january = usd_lines(&[("1500", 110), ("3000", -80), ("4000", -30)]);
    let february = usd_lines(&[("1500", 170), ("3000", -80), ("4000", -90)]);
    let spec = RunSpec {
        key: "period-caps".into(),
        opening_date: opening_date(),
        lines: opening,
        periods: vec![
            (P01.into(), january),
            ("FY2026-P02".into(), february.clone()),
            ("FY2026-P03".into(), february),
        ],
        full_detail: None,
    };
    let run = open_both(&mut k, &mut oracle, &spec);
    let chunks = [
        chunk_intent("opening", vec![leg(dr, "1500", 80), leg(cr, "3000", 80)]),
        period_chunk(
            "jan-a",
            Some(P01),
            DateDay::from_ymd(2026, 1, 10).unwrap(),
            vec![leg(dr, "1500", 10), leg(cr, "4000", 10)],
        ),
        period_chunk(
            "jan-b",
            Some(P01),
            DateDay::from_ymd(2026, 1, 20).unwrap(),
            vec![leg(dr, "1500", 20), leg(cr, "4000", 20)],
        ),
        period_chunk(
            "feb",
            Some("FY2026-P02"),
            DateDay::from_ymd(2026, 2, 10).unwrap(),
            vec![leg(dr, "1500", 60), leg(cr, "4000", 60)],
        ),
    ];
    stage_all(&mut k, &mut oracle, run, &chunks, "period-limited chunk");
    let staged = cut(&k, &oracle);
    for period in [OPENING, P01, "FY2026-P02"] {
        assert_cell(&k, &oracle, Some(period), staged, [0; 4], 0);
    }
    finalize_both(&mut k, &mut oracle, run, 4, "activate-periods");
    let activated = cut(&k, &oracle);
    for (period, posted, generation) in [
        (OPENING, 80, 1),
        (P01, 30, 1),
        ("FY2026-P02", 60, 1),
        ("FY2026-P03", 0, 0),
    ] {
        assert_cell(
            &k,
            &oracle,
            Some(period),
            activated,
            [posted, 0, 0, 0],
            generation,
        );
        assert_cell(&k, &oracle, Some(period), staged, [0; 4], 0);
    }
    assert_cell(
        &k,
        &oracle,
        Some(GO_LIVE_PERIOD),
        activated,
        [70, 0, 20, 0],
        2,
    );
}

#[test]
fn migration_limits_refuse_gross_chunk_overflow_even_when_the_net_ties() {
    let (mut k, mut oracle) = setup();
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    let spec = RunSpec {
        key: "gross-chunks".into(),
        opening_date: opening_date(),
        lines: usd_lines(&[("1500", 1), ("3000", -1)]),
        periods: vec![],
        full_detail: None,
    };
    let run = open_both(&mut k, &mut oracle, &spec);
    // Each large chunk is itself zero-net. Tie-out is independent of the
    // substrate's vertex iteration order; aggregate gross totals still
    // exceed the cell domain before any movement can be published.
    let amount = i128::MAX / 2 + 1;
    let chunks = [
        chunk_intent(
            "large-debit",
            vec![leg(dr, "1500", amount), leg(cr, "1500", amount)],
        ),
        chunk_intent(
            "large-credit",
            vec![leg(dr, "1500", amount), leg(cr, "1500", amount)],
        ),
        chunk_intent("one-more", vec![leg(dr, "1500", 1), leg(cr, "3000", 1)]),
    ];
    stage_all(
        &mut k,
        &mut oracle,
        run,
        &chunks,
        "bounded individual chunks",
    );
    refused_finalize(&mut k, &mut oracle, run, 3, "activate", "FA-REF-092");
    assert_cell(&k, &oracle, None, cut(&k, &oracle), [0; 4], 0);
}

#[test]
fn migration_limits_full_detail_obeys_opening_cutoff_and_sole_source() {
    let (dr, cr) = (fa_reference::Side::Debit, fa_reference::Side::Credit);
    for sole in [false, true] {
        let (mut k, mut oracle) = setup_with_limit(
            Some((opening_date(), P01)),
            BalanceLimit {
                lower: Some(0),
                upper: Some(100),
                scope: LimitScope::Lifetime,
            },
        );
        create_year(&mut k, &mut oracle, 2025);
        let funded = usd_lines(&[("1500", 100), ("3000", -100)]);
        let spent = usd_lines(&[("1500", 70), ("3000", -100), ("6000", 30)]);
        let periods = (1..=12)
            .map(|month| {
                (
                    format!("FY2025-P{month:02}"),
                    if month < 6 {
                        funded.clone()
                    } else {
                        spent.clone()
                    },
                )
            })
            .collect();
        let spec = full_detail(
            if sole { "sole" } else { "anchored" },
            if sole { Vec::new() } else { spent },
            periods,
            Vec::new(),
            sole,
        );
        let run = open_both(&mut k, &mut oracle, &spec);
        let mut chunks = vec![
            period_chunk(
                "historical-funds",
                Some("FY2025-P01"),
                DateDay::from_ymd(2025, 1, 15).unwrap(),
                vec![leg(dr, "1500", 100), leg(cr, "3000", 100)],
            ),
            period_chunk(
                "historical-spend",
                Some("FY2025-P06"),
                DateDay::from_ymd(2025, 6, 15).unwrap(),
                vec![leg(dr, "6000", 30), leg(cr, "1500", 30)],
            ),
        ];
        if !sole {
            chunks.push(chunk_intent(
                "opening-anchor",
                vec![
                    leg(dr, "1500", 70),
                    leg(dr, "6000", 30),
                    leg(cr, "3000", 100),
                ],
            ));
        }
        stage_all(
            &mut k,
            &mut oracle,
            run,
            &chunks,
            "full-detail limited chunk",
        );
        let staged = cut(&k, &oracle);
        assert_cell(&k, &oracle, None, staged, [0; 4], 0);
        finalize_both(&mut k, &mut oracle, run, chunks.len(), "activate-detail");
        let sums = if sole { [100, 30, 0, 0] } else { [70, 0, 0, 0] };
        assert_cell(&k, &oracle, None, cut(&k, &oracle), sums, 1);
        assert_cell(&k, &oracle, None, staged, [0; 4], 0);
        for period in [OPENING, "FY2025-P01", "FY2025-P06"] {
            assert_fold(
                &k,
                &oracle,
                period,
                k.db.frontier().unwrap(),
                oracle.known(),
                0,
            );
        }
    }
}
