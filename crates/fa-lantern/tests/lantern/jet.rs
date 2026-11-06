//! Journal-entry findings over native postings: evidence provenance (fa-81lu)
//! and the registered debit/credit account-pair population (fa-3afh).

use super::*;
use fa_journal::attestation::record_review;
use fa_journal::evidence::{SupplementalEvidence, attach_evidence};
use fa_lantern::jet::{SelfSourcedEvidence, UnusualAccounts};
use fa_lantern::{default_budget, run_over_metered};
use fa_model::EntryRef;

/// evidence_policy.toml's `AgentUpload` grade (self-sourced).
const AGENT_UPLOAD: u8 = 4;

/// Records a document of `grade` that `by` brought in; its citation in
/// role 1.
fn document(h: &mut Harness, grade: u8, by: VId, text: &[u8]) -> EvidenceRef {
    let doc = Document {
        book_id: h.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade,
        retrieved_by: by,
        bytes: text.to_vec(),
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async { add_document(db, &ctx, book, &doc).await })
        .expect("kernel")
        .expect("admitted");
    doc.evidence_ref(1)
}

/// `reviewer` records a Reviewed attestation over `document`.
fn review(h: &mut Harness, reviewer: VId, document: Oid) {
    let capability = Capability::embedded(reviewer, &["approve"]).expect("approve");
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async {
            record_review(
                db,
                &ctx,
                book,
                &capability,
                None,
                reviewer,
                document,
                Vec::new(),
            )
            .await
        })
        .expect("kernel")
        .expect("admitted");
}

/// The preparer attaches `documents` to the committed `entry`.
fn attach(h: &mut Harness, entry: VId, documents: Vec<EvidenceRef>) {
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let entry_digest = snapshot
        .entries
        .iter()
        .find(|e| e.vid == entry)
        .expect("posted")
        .entry
        .entry_digest;
    let supplement = SupplementalEvidence {
        book_id: h.book.book_id,
        entry_ref: EntryRef {
            vid: entry,
            entry_digest,
        },
        documents,
        attached_by: PREPARER,
    };
    let capability = Capability::embedded(PREPARER, &["post"]).expect("post");
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async { attach_evidence(db, &ctx, book, &capability, &supplement).await })
        .expect("kernel")
        .expect("admitted");
}

fn flagged(run: &ProcedureRun) -> Vec<VId> {
    let entries: Vec<VId> = run
        .findings
        .iter()
        .filter_map(|f| match f.cites.first() {
            Some(Cite::Entry(v)) => Some(*v),
            _ => None,
        })
        .collect();
    assert_eq!(
        entries.len(),
        run.findings.len(),
        "a finding cites its entry first"
    );
    entries
}

#[test]
fn period_end_timing_widens_civil_day_distances_before_comparing_the_window() {
    let mut h = harness();
    let posted = h.post(&Spec::simple(day(2026, 3, 15), "6000", "1000", 100));
    let mut source = h.snapshot();
    source.entries.retain(|entry| entry.vid == posted);
    // Exercise the public procedure snapshot boundary, starting with a real
    // posting. These altered snapshots are arithmetic inputs, not certificates
    // of posting admission at the extreme dates.
    for (start, end, effective, window, expected) in [
        (i32::MIN, i32::MAX, i32::MIN, 3, None),
        (i32::MIN, i32::MIN + 1, i32::MIN, 3, Some(0)),
        (i32::MAX - 4, i32::MAX, i32::MAX - 1, 3, Some(0)),
        (i32::MAX - 4, i32::MAX, i32::MAX - 3, 3, Some(2)),
        (i32::MAX - 4, i32::MAX, i32::MAX - 4, 3, None),
        (i32::MIN, i32::MAX, -1, i32::MAX, None),
        (i32::MIN, i32::MAX, 0, i32::MAX, Some(2_147_483_646)),
    ] {
        let calendar = FiscalCalendar::custom(
            "boundary",
            vec![fa_time::CustomYear {
                fiscal_year: 2026,
                bounds: vec![DateDay(start), DateDay(end)],
            }],
            0,
        )
        .unwrap();
        assert!(calendar.periods_for_year(2026).unwrap()[0].contains(DateDay(effective)));

        let mut snapshot = source.clone();
        snapshot.entries[0].entry.proposal.effective_date = DateDay(effective);
        let code = snapshot.entries[0].period.clone();
        let period = snapshot.periods.get_mut(&code).unwrap();
        period.start = DateDay(start);
        period.end = DateDay(end);
        let procedure = PeriodEndTiming::with(
            Params::defaults(PeriodEndTiming::ID)
                .unwrap()
                .set("window_days", i128::from(window))
                .unwrap(),
        );
        let result = run_over(&snapshot, &h.book, &procedure).unwrap();
        assert_eq!(result.work.entries, 1);
        assert_eq!(result.work.legs, 0);
        assert_eq!(
            flagged(&result),
            if expected.is_some() {
                vec![posted]
            } else {
                vec![]
            }
        );
        if let Some(days) = expected {
            assert_eq!(
                result.findings[0].statistic,
                Statistic::count("days_to_period_end", days, 1)
            );
            assert_eq!(
                result.findings[0].cites,
                vec![Cite::Entry(posted), Cite::Period(code.clone())]
            );
        }

        let rows = [naive::Row {
            index: 0,
            date: DateDay(effective),
            document_date: None,
            period: code,
            period_start: Some(DateDay(start)),
            period_end: DateDay(end),
            legs: Vec::new(),
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: None,
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        }];
        assert_eq!(
            naive::period_end_timing(&rows, window),
            if expected.is_some() { vec![0] } else { vec![] }
        );
    }
}

#[test]
fn self_sourced_evidence_flags_agent_upload_only() {
    let mut h = harness();
    let person = h.evidence[0];
    let agent = document(
        &mut h,
        AGENT_UPLOAD,
        PREPARER,
        b"RECEIPT (an agent's upload)",
    );
    let late = document(
        &mut h,
        AGENT_UPLOAD,
        PREPARER,
        b"MEMO (an agent's later upload)",
    );
    // An Original needs one document; a self-sourced one counts once a
    // principal other than its uploader reviews it (FA-REF-086 before).
    review(&mut h, REVIEWER, agent.document_oid);
    let mut both = vec![person, agent];
    both.sort();

    h.evidence = vec![agent];
    let own = h.post(&Spec::simple(day(2026, 3, 9), "6000", "1000", 4_200));
    h.evidence = both;
    let mixed = h.post(&Spec::simple(day(2026, 3, 10), "6000", "1000", 4_300));
    h.evidence = vec![person];
    let independent = h.post(&Spec::simple(day(2026, 3, 11), "6000", "1000", 4_400));
    // A supplement of the agent's own leaves a person-supported entry alone.
    attach(&mut h, independent, vec![late]);

    let procedure = SelfSourcedEvidence::new().unwrap();
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    assert_eq!(snapshot.supplements[&independent][0].documents, vec![late]);
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    h.assert_cites_resolve(&r);
    println!("self_sourced findings={:?}", r.findings);
    assert_eq!(
        flagged(&r),
        vec![own],
        "only the entry whose only evidence is the agent's"
    );
    let f = &r.findings[0];
    assert_eq!(
        f.cites,
        vec![Cite::Entry(own), Cite::Document(agent.document_oid)]
    );
    assert_eq!(
        f.statistic,
        Statistic::count("self_sourced_documents", 1, 3)
    );
    assert_eq!(
        f.severity,
        Severity::Medium,
        "reviewed by someone other than its uploader"
    );
    assert!(!flagged(&r).contains(&mixed) && !flagged(&r).contains(&independent));
    let row = fa_lantern::bind(SelfSourcedEvidence::ID).unwrap();
    assert!(
        r.work.within_registered_bound(&row.complexity, &snapshot),
        "{:?}",
        r.work
    );
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );

    // The same entry without its review is High: severity reads the reviews.
    let mut unreviewed = snapshot.clone();
    unreviewed.attestations.clear();
    let r = run_over(&unreviewed, &h.book, &procedure).unwrap();
    assert_eq!(flagged(&r), vec![own]);
    assert_eq!(r.findings[0].severity, Severity::High);

    // A supplement a person supplied takes the entry out of the population's
    // hits: its evidence is no longer only the book's own.
    let receipt = document(&mut h, 3, REVIEWER, b"BANK ADVICE (a person's upload)");
    attach(&mut h, own, vec![receipt]);
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

fn pair_procedure(max_pair_count: u32, min_population: u32) -> UnusualAccounts {
    UnusualAccounts::with(
        Params::defaults(UnusualAccounts::ID)
            .unwrap()
            .set("max_pair_count", i128::from(max_pair_count))
            .unwrap()
            .set("min_population", i128::from(min_population))
            .unwrap(),
    )
}

/// Reference inputs come from the same posting intents, never the procedure's
/// account keys, frequency map or findings.
fn pair_reference_rows(h: &Harness, specs: &[Spec]) -> Vec<naive::Row> {
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| naive::Row {
            index,
            date: spec.date,
            document_date: spec.document_date,
            period: h.period_code(spec.date),
            period_start: None,
            period_end: h.period_end(spec.date),
            legs: spec
                .legs
                .iter()
                .map(|(account, side, mantissa)| naive::Leg {
                    account: (*account).into(),
                    debit: *side == Side::Debit,
                    unit: h.usd.0,
                    scale: 2,
                    mantissa: *mantissa,
                })
                .collect(),
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(spec.description.chars().count()),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        })
        .collect()
}

#[test]
fn unusual_accounts_counts_account_pairs_as_registered() {
    let mut h = harness();
    let date = day(2026, 3, 9);
    let mut specs = Vec::new();
    // Each cash/revenue and cash/payable pair is ordinary. Combining those
    // two credits into one entry does not make either pair rare.
    for _ in 0..3 {
        specs.push(Spec::simple(date, "1000", "4000", 100));
        specs.push(Spec::simple(date, "1000", "2000", 10));
    }
    let mut combined = Spec::simple(date, "1000", "4000", 100);
    combined.legs = vec![
        ("1000", Side::Debit, 110),
        ("4000", Side::Credit, 100),
        ("2000", Side::Credit, 10),
    ];
    specs.push(combined);
    for spec in &specs {
        h.post(spec);
    }
    let procedure = UnusualAccounts::new().unwrap();
    let control = h.run(&procedure);
    let reference = naive::unusual_accounts(&pair_reference_rows(&h, &specs), 1, 5);
    assert!(reference.is_empty());
    assert_eq!(h.cited_entries(&control), reference.into_iter().collect());
    assert!(control.findings.is_empty(), "{:?}", control.findings);

    // A genuinely new pair is still reported beside that clean control.
    specs.push(Spec::simple(date, "1010", "1200", 50));
    let rare = h.post(specs.last().unwrap());
    let result = h.run(&procedure);
    let reference = naive::unusual_accounts(&pair_reference_rows(&h, &specs), 1, 5);
    assert_eq!(reference, vec![7]);
    assert_eq!(h.cited_entries(&result), reference.into_iter().collect());
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].cites[0], Cite::Entry(rare));
    assert_eq!(
        result.findings[0].statistic,
        Statistic::count("pair_occurrences", 1, 8)
    );
    assert_eq!(result.version, 2);
    h.assert_cites_resolve(&result);

    // The minimum population is inclusive, and a zero occurrence threshold
    // cannot flag a pair that actually appeared in the admitted population.
    assert_eq!(
        h.cited_entries(&h.run(&pair_procedure(1, 8))),
        BTreeSet::from([7])
    );
    assert!(h.run(&pair_procedure(1, 9)).findings.is_empty());
    assert!(h.run(&pair_procedure(0, 1)).findings.is_empty());
}

#[test]
fn unusual_account_pairs_deduplicate_legs_and_directions_and_keep_stable_citations() {
    let mut h = harness();
    let date = day(2026, 3, 10);
    let make = |legs| {
        let mut spec = Spec::simple(date, "1000", "4000", 25);
        spec.legs = legs;
        spec
    };
    let specs = vec![
        Spec::simple(date, "1000", "4000", 25),
        Spec::simple(date, "4000", "1000", 25),
        make(vec![
            ("1000", Side::Debit, 10),
            ("1000", Side::Debit, 15),
            ("4000", Side::Credit, 12),
            ("4000", Side::Credit, 13),
        ]),
        // Both directions of the same pair coexist in one entry. This also
        // introduces one self-pair per account, a valid net-zero posting.
        make(vec![
            ("1000", Side::Debit, 7),
            ("4000", Side::Debit, 3),
            ("1000", Side::Credit, 2),
            ("4000", Side::Credit, 8),
        ]),
        Spec::simple(date, "1000", "1000", 3),
        Spec::simple(date, "4000", "4000", 3),
        // The two debit accounts must not add another cash/revenue pair.
        make(vec![
            ("1000", Side::Debit, 10),
            ("4000", Side::Debit, 10),
            ("1010", Side::Credit, 20),
        ]),
    ];
    for spec in &specs {
        h.post(spec);
    }
    let procedure = pair_procedure(4, 1);
    let result = h.run(&procedure);
    let reference = naive::unusual_accounts(&pair_reference_rows(&h, &specs), 4, 1);
    assert_eq!(reference, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(h.cited_entries(&result), reference.into_iter().collect());
    let counts: BTreeMap<_, _> = result
        .findings
        .iter()
        .map(|finding| (h.entry_index(&finding.cites[0]), finding.statistic.value))
        .collect();
    assert_eq!(
        counts,
        BTreeMap::from([(0, 4), (1, 4), (2, 4), (3, 2), (4, 2), (5, 2), (6, 1)])
    );
    assert_eq!(
        h.cited_entries(&h.run(&pair_procedure(1, 1))),
        BTreeSet::from([6])
    );
    let both_directions = result
        .findings
        .iter()
        .find(|finding| h.entry_index(&finding.cites[0]) == 3)
        .unwrap();
    assert_eq!(
        both_directions.cites,
        vec![
            Cite::Entry(h.posted[3].0),
            Cite::Account(h.account("1000").min(h.account("4000"))),
        ],
        "equal-frequency self-pairs select one canonical witness, without duplicate citations"
    );
    h.assert_cites_resolve(&result);

    let snapshot = h.snapshot();
    for permuted in [
        snapshot.with_entries_reversed(),
        snapshot.with_legs_reversed(),
    ] {
        let replay = run_over(&permuted, &h.book, &procedure).unwrap();
        assert_eq!(replay.findings, result.findings);
        assert_eq!(replay.findings_digest, result.findings_digest);
        assert_eq!(replay.work, result.work);
    }
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
}

#[test]
fn unusual_account_pairs_match_reference_across_generated_posting_histories() {
    const ACCOUNTS: [&str; 8] = [
        "1000", "1010", "1020", "1200", "2000", "4000", "6000", "7000",
    ];
    for seed in [7_u64, 31, 509, 65_537] {
        let mut state = seed;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            usize::try_from(state >> 32).unwrap()
        };
        let mut h = harness();
        let mut specs = Vec::new();
        for _ in 0..16 {
            let debit_count = 1 + next() % 3;
            let credit_count = 1 + next() % 3;
            let mut spec = Spec::simple(day(2026, 3, 11), "1000", "4000", 1);
            spec.legs.clear();
            for _ in 0..debit_count {
                spec.legs.push((
                    ACCOUNTS[next() % ACCOUNTS.len()],
                    Side::Debit,
                    i128::try_from(credit_count).unwrap(),
                ));
            }
            for _ in 0..credit_count {
                spec.legs.push((
                    ACCOUNTS[next() % ACCOUNTS.len()],
                    Side::Credit,
                    i128::try_from(debit_count).unwrap(),
                ));
            }
            h.post(&spec);
            specs.push(spec);
        }
        let rows = pair_reference_rows(&h, &specs);
        for threshold in [0_u32, 1, 2, 4, 16] {
            let procedure = pair_procedure(threshold, 5);
            let result = h.run(&procedure);
            let expected = naive::unusual_accounts(&rows, usize::try_from(threshold).unwrap(), 5);
            assert_eq!(
                h.cited_entries(&result),
                expected.into_iter().collect(),
                "seed={seed} threshold={threshold} findings={:?}",
                result.findings
            );
            h.assert_cites_resolve(&result);
        }
    }
}

#[test]
fn unusual_account_pairs_refuse_dense_expansion_at_the_work_budget() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let mut proposal = h.proposal(&Spec::simple(day(2026, 3, 12), "1000", "4000", 64));
    proposal.legs.clear();
    let prototype = snapshot.accounts[&h.account("1000")].clone();
    for i in 0_u64..128 {
        let vid = VId(100_000 + u128::from(i));
        let mut account = prototype.clone();
        account.vid = vid;
        account.code = format!("pair-{i}");
        snapshot.accounts.insert(vid, account);
        proposal.legs.push(LegPayload::simple(
            if i < 64 { Side::Debit } else { Side::Credit },
            vid,
            Amount::new(h.usd, 1),
        ));
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    snapshot.entries = vec![fa_lantern::SnapshotEntry {
        vid: VId(200_000),
        entry: proposal.seal(Vec::new(), None).unwrap(),
        recorded_at: snapshot.coordinate.known_at,
        period: h.period_code(day(2026, 3, 12)),
        approvals: Vec::new(),
    }];
    let procedure = pair_procedure(1, 1);
    // Entry + 128 legs consume 129 units. Stop inside pair generation, after
    // 50 of the 4096 candidates, before any partial finding can escape.
    let error = run_over_metered(&snapshot, &h.book, &procedure, Some(179), None)
        .expect_err("dense pair expansion must be metered inside the entry");
    assert!(
        matches!(&error, LanternError::BudgetExhausted { procedure, used: 180, budget: 179, .. }
            if procedure == UnusualAccounts::ID),
        "{error:?}"
    );
    assert!(error.fix_hint().unwrap().contains("work budget"));

    let budget = default_budget(UnusualAccounts::ID, &snapshot).unwrap();
    let complete = run_over_metered(&snapshot, &h.book, &procedure, Some(budget), None).unwrap();
    assert_eq!(complete.findings.len(), 1);
    assert_eq!(complete.work.entries, 1);
    assert_eq!(complete.work.legs, 128);
    assert_eq!(complete.work.comparisons, 8193);
    assert_eq!(
        complete.findings[0].statistic,
        Statistic::count("pair_occurrences", 1, 1)
    );
    let row = fa_lantern::bind(UnusualAccounts::ID).unwrap();
    assert!(
        complete
            .work
            .within_registered_bound(&row.complexity, &snapshot)
    );
    let error = run_over_metered(
        &snapshot,
        &h.book,
        &procedure,
        Some(complete.work.total() - 1),
        None,
    )
    .expect_err("the second pass must also charge every pair lookup");
    assert!(matches!(error, LanternError::BudgetExhausted { .. }));
}
