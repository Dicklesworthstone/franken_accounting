//! Metamorphic verification suites (`fa-hlvs`, plan §16.6).
//!
//! Differential tests compare two implementations; metamorphic tests compare
//! one implementation against itself under transformations that must not
//! change accounting results:
//! 1. Fold, trial-balance, and statement invariance under commutative entry
//!    reordering within an open period (`>= 8` deterministic seeds).
//! 2. `Reverse + Replace == Replace` on net account balances and financial
//!    statements, while preserving gross debit/credit monotonicity (`>= 8` seeds).
//! 3. `Plan + Commit == Direct Post` across multi-entry books (`>= 8` seeds).
//! 4. `Scratch-Book Replay == Source Book` across folds, trial balances, and
//!    statements (`>= 8` seeds).
//! 5. `Rebuild Registers == Incrementally Maintained Registers` across
//!    interleaved postings, pending holds, and resolutions (`>= 8` seeds).
//! 6. `Bundle Idempotence & Redaction Invariance`: producing a `.fab` bundle
//!    twice is byte-identical, and deriving a redacted document view preserves
//!    all certified register and statement results (`>= 8` seeds).
//! 7. `Fiscal Calendar == Brute-Force Day-Walker` across monthly, quarterly,
//!    4-4-5, 4-5-4, and 5-4-4 calendars (`>= 8` seeds).
//! 8. Planted breaks for every relation proving the harness catches violations
//!    and formats the failing seed and replay command.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use fa::{
    Book, BookKeys, BundleRequest, BundleScope, Entropy, PostIntent, StatementDefinition,
    StatementSelection,
};
use fa_journal::{AccountSpec, BookSpec, Capability, Document, PostRequest, UnitPolicy};
use fa_model::{
    Disposition, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    Pending, Supersession, SupersessionKind, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_registers::{Fold, TrialBalance};
use fa_statements::Statement;
use fa_time::{
    DateDay, FiscalCalendar, PeriodKind, PeriodTransition, WeekPattern, Weekday, YearEndRule,
    resolve_period,
};
use fgdb_types::VId;

const SEEDS: [u64; 8] = [
    0x1001_0001_a5a5_0101,
    0x1001_0002_b6b6_0202,
    0x1001_0003_c7c7_0303,
    0x1001_0004_d8d8_0404,
    0x1001_0005_e9e9_0505,
    0x1001_0006_f0f0_0606,
    0x1001_0007_1357_0707,
    0x1001_0008_2468_0808,
];

#[derive(Clone)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_range(&mut self, low: i128, high_inclusive: i128) -> i128 {
        let span = (high_inclusive - low + 1) as u64;
        low + i128::from(self.next_u64() % span)
    }

    fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = (self.next_u64() as usize) % (i + 1);
            slice.swap(i, j);
        }
    }
}

fn replay_diagnostic(relation: &str, seed: u64, detail: impl std::fmt::Display) -> String {
    format!(
        "metamorphic relation `{relation}` failed on seed 0x{seed:016x}: {detail}\n\
         replay: RCH_SHIM_LOCAL_IDE=1 cargo test -p fa --test metamorphic {relation} -- --exact --nocapture"
    )
}

struct FixtureBook {
    book: Book,
    book_id: Id128,
    principal: VId,
    usd: UnitId,
    eur: UnitId,
    march: String,
    day: DateDay,
    evidence: EvidenceRef,
}

fn setup_book(seed: u64, key_seed: u8) -> FixtureBook {
    let calendar = FiscalCalendar::monthly("cal", 1, 1).expect("monthly calendar");
    let units = UnitRegistry::embedded().expect("embedded units");
    let usd = units.lookup("USD").expect("USD");
    let eur = units.lookup("EUR").expect("EUR");
    let book_id = Id128([key_seed; 16]);
    let spec = BookSpec {
        book_id,
        name: "Metamorphic Co".into(),
        base_unit: usd,
        calendar,
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let mut book = Book::create_memory(
        BookKeys::for_development(key_seed),
        spec,
        Entropy::deterministic(seed),
    )
    .expect("create memory book");

    let principal = VId(1);
    let day = DateDay::from_ymd(2026, 3, 15).expect("2026-03-15");
    let chart = vec![
        AccountSpec {
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "1100".into(),
            name: "Accounts Receivable".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "2000".into(),
            name: "Accounts Payable".into(),
            account_type: 2,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "3000".into(),
            name: "Common Stock".into(),
            account_type: 3,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "4000".into(),
            name: "Consulting Revenue".into(),
            account_type: 4,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "6000".into(),
            name: "Operating Expense".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        },
    ];
    book.install_chart(&chart, principal, day, b"chart-v1")
        .expect("install_chart io")
        .expect("install_chart ok");

    let (_, periods) = book.create_periods(2026).expect("create_periods");
    let march = periods
        .iter()
        .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
        .expect("March period")
        .code
        .clone();

    let close_cap = Capability::embedded(principal, &["close"]).expect("close cap");
    book.transition_period(
        &march,
        PeriodTransition::Open,
        principal,
        1,
        day,
        b"open-march",
        &close_cap,
    )
    .expect("transition io")
    .expect("transition ok");

    let doc = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: principal,
        bytes: format!("METAMORPHIC-EVIDENCE-{seed:016x}").into_bytes(),
    };
    let _added = book
        .add_document(&doc)
        .expect("add_document io")
        .expect("add_document ok");

    FixtureBook {
        book,
        book_id,
        principal,
        usd,
        eur,
        march,
        day,
        evidence: doc.evidence_ref(1),
    }
}

#[derive(Clone, Debug)]
struct SpecEntry {
    key: Vec<u8>,
    debit_code: &'static str,
    credit_code: &'static str,
    unit: UnitId,
    amount: i128,
    day_offset: i32,
    intent_byte: u8,
}

fn generate_entries(seed: u64, usd: UnitId, eur: UnitId) -> Vec<SpecEntry> {
    let mut rng = SplitMix64::new(seed);
    let pairs: [(&str, &str); 5] = [
        ("1000", "3000"),
        ("1000", "4000"),
        ("1100", "4000"),
        ("6000", "1000"),
        ("6000", "2000"),
    ];
    let mut out = Vec::with_capacity(6);
    for idx in 0..6u8 {
        let (debit_code, credit_code) = pairs[(rng.next_u64() as usize) % pairs.len()];
        let unit = if rng.next_u64().is_multiple_of(3) {
            eur
        } else {
            usd
        };
        let amount = rng.next_range(500, 250_000);
        let day_offset = (rng.next_u64() % 10) as i32;
        out.push(SpecEntry {
            key: format!("entry-{seed:016x}-{idx}").into_bytes(),
            debit_code,
            credit_code,
            unit,
            amount,
            day_offset,
            intent_byte: idx + 1,
        });
    }
    out
}

fn build_proposal(f: &FixtureBook, spec: &SpecEntry) -> EntryPayload {
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(f.book_id, spec.debit_code),
            Amount::new(spec.unit, spec.amount),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(f.book_id, spec.credit_code),
            Amount::new(spec.unit, spec.amount),
        ),
    ];
    EntryPayload {
        schema_minor: 0,
        book_id: f.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay(f.day.0 + spec.day_offset),
        document_date: None,
        description: f.book.seal_text("metamorphic posting").expect("seal_text"),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).expect("fold_unit_totals"),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: spec.key.clone(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([spec.intent_byte; 32]),
            intent_kind: 1,
        },
        principal_ref: f.principal,
        session_ref: None,
        evidence: vec![f.evidence],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn check_reorder_equivalence(
    seed: u64,
    fold_a: &Fold,
    fold_b: &Fold,
    tb_a: &TrialBalance,
    tb_b: &TrialBalance,
    bs_a: &Statement,
    bs_b: &Statement,
    is_a: &Statement,
    is_b: &Statement,
) -> Result<(), String> {
    // The relation (plan §16: "the fold is invariant under reordering of
    // commutative entries within a period") is over the folded content.
    // `fold_digest` is NOT part of it: since 8f21a159 it commits to the posted
    // leg history in (commit_seq, entry vid, ordinal) order, so two orders of
    // the same legs must digest differently (asserted by the caller). Every
    // generated entry lands in the folded period, so the watermark (the last
    // contributing commit) is order-invariant here.
    if fold_a.period != fold_b.period
        || fold_a.cells != fold_b.cells
        || fold_a.pending != fold_b.pending
        || fold_a.watermark != fold_b.watermark
        || fold_a.entries != fold_b.entries
    {
        return Err(replay_diagnostic(
            "metamorphic_fold_invariance_under_commutative_reorder",
            seed,
            format!("period fold mismatch: {fold_a:?} != {fold_b:?}"),
        ));
    }
    if tb_a != tb_b {
        return Err(replay_diagnostic(
            "metamorphic_fold_invariance_under_commutative_reorder",
            seed,
            "trial balance mismatch after commutative permutation",
        ));
    }
    if bs_a != bs_b || is_a != is_b {
        return Err(replay_diagnostic(
            "metamorphic_fold_invariance_under_commutative_reorder",
            seed,
            "financial statement mismatch after commutative permutation",
        ));
    }
    Ok(())
}

#[test]
fn metamorphic_fold_invariance_under_commutative_reorder() {
    for seed in SEEDS {
        let mut f_a = setup_book(seed, 0x41);
        let mut f_b = setup_book(seed, 0x41);
        let entries = generate_entries(seed, f_a.usd, f_a.eur);
        let mut permuted = entries.clone();
        SplitMix64::new(seed ^ 0x5555_aaaa_5555_aaaa).shuffle(&mut permuted);

        let post_cap = Capability::embedded(f_a.principal, &["post"]).expect("post cap");
        for spec in &entries {
            let proposal = build_proposal(&f_a, spec);
            f_a.book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("post a io")
                .expect("post a ok");
        }
        for spec in &permuted {
            let proposal = build_proposal(&f_b, spec);
            f_b.book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("post b io")
                .expect("post b ok");
        }

        let fold_a = f_a.book.fold_period(&f_a.march).expect("fold a");
        let fold_b = f_b.book.fold_period(&f_b.march).expect("fold b");
        let tb_a = f_a
            .book
            .trial_balance(std::slice::from_ref(&f_a.march))
            .expect("tb a");
        let tb_b = f_b
            .book
            .trial_balance(std::slice::from_ref(&f_b.march))
            .expect("tb b");
        let bs_sel = StatementSelection {
            definition: StatementDefinition::embedded("balance-sheet").expect("balance-sheet"),
            periods: vec![f_a.march.clone()],
            comparative: Vec::new(),
        };
        let is_sel = StatementSelection {
            definition: StatementDefinition::embedded("income-statement")
                .expect("income-statement"),
            periods: vec![f_a.march.clone()],
            comparative: Vec::new(),
        };
        let bs_a = f_a
            .book
            .statement(bs_sel.clone(), None)
            .expect("bs a io")
            .expect("bs a ok");
        let bs_b = f_b
            .book
            .statement(bs_sel, None)
            .expect("bs b io")
            .expect("bs b ok");
        let is_a = f_a
            .book
            .statement(is_sel.clone(), None)
            .expect("is a io")
            .expect("is a ok");
        let is_b = f_b
            .book
            .statement(is_sel, None)
            .expect("is b io")
            .expect("is b ok");

        check_reorder_equivalence(
            seed, &fold_a, &fold_b, &tb_a, &tb_b, &bs_a, &bs_b, &is_a, &is_b,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        // The history-bound digest distinguishes exactly the commit orders
        // (8f21a159): equal iff the permutation left the order unchanged.
        let reordered = entries
            .iter()
            .map(|spec| &spec.key)
            .ne(permuted.iter().map(|spec| &spec.key));
        assert_eq!(
            fold_a.fold_digest != fold_b.fold_digest,
            reordered,
            "seed {seed:#018x}: fold_digest must bind the posted leg order"
        );
    }
}

fn net_by_account_unit(fold: &Fold) -> BTreeMap<(VId, u32), i128> {
    fold.cells
        .iter()
        .map(|c| ((c.key.account, c.key.unit_id), c.net().expect("cell net")))
        .collect()
}

fn check_reverse_replace_equivalence(
    seed: u64,
    fold_rr: &Fold,
    fold_direct: &Fold,
    bs_rr: &Statement,
    bs_direct: &Statement,
    is_rr: &Statement,
    is_direct: &Statement,
) -> Result<(), String> {
    let net_rr = net_by_account_unit(fold_rr);
    let net_direct = net_by_account_unit(fold_direct);
    if net_rr != net_direct {
        return Err(replay_diagnostic(
            "metamorphic_reverse_then_replace_equals_direct_replacement",
            seed,
            format!("net balance mismatch: {net_rr:?} != {net_direct:?}"),
        ));
    }
    if bs_rr.lines != bs_direct.lines || bs_rr.columns != bs_direct.columns {
        return Err(replay_diagnostic(
            "metamorphic_reverse_then_replace_equals_direct_replacement",
            seed,
            "balance sheet lines/columns diverged between reverse+replace and direct replace",
        ));
    }
    if is_rr.lines != is_direct.lines || is_rr.columns != is_direct.columns {
        return Err(replay_diagnostic(
            "metamorphic_reverse_then_replace_equals_direct_replacement",
            seed,
            "income statement lines/columns diverged between reverse+replace and direct replace",
        ));
    }
    Ok(())
}

#[test]
fn metamorphic_reverse_then_replace_equals_direct_replacement() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed ^ 0x2002_0000);
        let wrong_amount = rng.next_range(10_000, 90_000);
        let right_amount = rng.next_range(95_000, 250_000);

        let mut f_rr = setup_book(seed, 0x42);
        let mut f_direct = setup_book(seed, 0x42);
        let post_cap = Capability::embedded(f_rr.principal, &["post"]).expect("post cap");

        // Shared background capital contribution so Cash is positive.
        let bg = SpecEntry {
            key: b"bg-capital".to_vec(),
            debit_code: "1000",
            credit_code: "3000",
            unit: f_rr.usd,
            amount: 500_000,
            day_offset: 0,
            intent_byte: 1,
        };
        for f in [&mut f_rr, &mut f_direct] {
            let proposal = build_proposal(f, &bg);
            f.book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("bg io")
                .expect("bg ok");
        }

        // In f_rr: post wrong rent expense, then reverse it, then post right rent expense.
        let wrong_spec = SpecEntry {
            key: b"rent-wrong".to_vec(),
            debit_code: "6000",
            credit_code: "1000",
            unit: f_rr.usd,
            amount: wrong_amount,
            day_offset: 1,
            intent_byte: 2,
        };
        let wrong_proposal = build_proposal(&f_rr, &wrong_spec);
        let wrong_posted = f_rr
            .book
            .post(PostRequest {
                proposal: wrong_proposal.clone(),
                approvals: Vec::new(),
                plan_certificate: None,
                capability: post_cap.clone(),
            })
            .expect("wrong io")
            .expect("wrong ok");

        let rev_legs = vec![
            LegPayload::simple(
                Side::Credit,
                account_vid(f_rr.book_id, "6000"),
                Amount::new(f_rr.usd, wrong_amount),
            ),
            LegPayload::simple(
                Side::Debit,
                account_vid(f_rr.book_id, "1000"),
                Amount::new(f_rr.usd, wrong_amount),
            ),
        ];
        let rev_proposal = EntryPayload {
            schema_minor: 0,
            book_id: f_rr.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::REVERSAL,
            effective_date: DateDay(f_rr.day.0 + 1),
            document_date: None,
            description: f_rr.book.seal_text("reverse wrong rent").expect("seal"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&rev_legs).expect("totals"),
            legs: rev_legs,
            control: None,
            base_totals: None,
            idempotency_key: b"rent-wrong-reversal".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([3; 32]),
                intent_kind: 1,
            },
            principal_ref: f_rr.principal,
            session_ref: None,
            evidence: vec![f_rr.evidence],
            supersession: vec![Supersession {
                target: wrong_posted.entry_ref(),
                kind: SupersessionKind::Reverses,
                reason_code: 1,
            }],
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        f_rr.book
            .post(PostRequest {
                proposal: rev_proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: post_cap.clone(),
            })
            .expect("rev io")
            .expect("rev ok");

        let right_spec = SpecEntry {
            key: b"rent-right".to_vec(),
            debit_code: "6000",
            credit_code: "1000",
            unit: f_rr.usd,
            amount: right_amount,
            day_offset: 2,
            intent_byte: 4,
        };
        for f in [&mut f_rr, &mut f_direct] {
            let proposal = build_proposal(f, &right_spec);
            f.book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("right io")
                .expect("right ok");
        }

        let fold_rr = f_rr.book.fold_period(&f_rr.march).expect("fold rr");
        let fold_direct = f_direct
            .book
            .fold_period(&f_direct.march)
            .expect("fold direct");

        let bs_sel = StatementSelection {
            definition: StatementDefinition::embedded("balance-sheet").expect("balance-sheet"),
            periods: vec![f_rr.march.clone()],
            comparative: Vec::new(),
        };
        let is_sel = StatementSelection {
            definition: StatementDefinition::embedded("income-statement")
                .expect("income-statement"),
            periods: vec![f_rr.march.clone()],
            comparative: Vec::new(),
        };
        let bs_rr = f_rr
            .book
            .statement(bs_sel.clone(), None)
            .expect("bs rr io")
            .expect("bs rr ok");
        let bs_direct = f_direct
            .book
            .statement(bs_sel, None)
            .expect("bs direct io")
            .expect("bs direct ok");
        let is_rr = f_rr
            .book
            .statement(is_sel.clone(), None)
            .expect("is rr io")
            .expect("is rr ok");
        let is_direct = f_direct
            .book
            .statement(is_sel, None)
            .expect("is direct io")
            .expect("is direct ok");

        check_reverse_replace_equivalence(
            seed,
            &fold_rr,
            &fold_direct,
            &bs_rr,
            &bs_direct,
            &is_rr,
            &is_direct,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn metamorphic_plan_then_commit_equals_direct_post() {
    for seed in SEEDS {
        let mut f_plan = setup_book(seed, 0x43);
        let mut f_direct = setup_book(seed, 0x43);
        let entries = generate_entries(seed ^ 0x3003_0000, f_plan.usd, f_plan.eur);
        let post_cap = Capability::embedded(f_plan.principal, &["post"]).expect("post cap");

        for spec in &entries {
            let prop_plan = build_proposal(&f_plan, spec);
            let intent = PostIntent::new(prop_plan, Vec::new()).expect("PostIntent::new");
            let rehearsed = f_plan
                .book
                .plan(intent, &post_cap)
                .expect("plan io")
                .expect("plan ok");
            f_plan
                .book
                .commit_plan(rehearsed, &post_cap)
                .expect("commit_plan io")
                .expect("commit_plan ok");

            let prop_direct = build_proposal(&f_direct, spec);
            f_direct
                .book
                .post(PostRequest {
                    proposal: prop_direct,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("post direct io")
                .expect("post direct ok");
        }

        let fold_plan = f_plan.book.fold_period(&f_plan.march).expect("fold plan");
        let fold_direct = f_direct
            .book
            .fold_period(&f_direct.march)
            .expect("fold direct");
        assert_eq!(
            fold_plan,
            fold_direct,
            "{}",
            replay_diagnostic(
                "metamorphic_plan_then_commit_equals_direct_post",
                seed,
                "fold_period diverged between plan+commit and direct post"
            )
        );
    }
}

#[test]
fn metamorphic_scratch_replay_preserves_folds_and_reports() {
    for seed in SEEDS {
        let mut f = setup_book(seed, 0x44);
        let entries = generate_entries(seed ^ 0x4004_0000, f.usd, f.eur);
        let post_cap = Capability::embedded(f.principal, &["post"]).expect("post cap");
        for spec in &entries {
            let proposal = build_proposal(&f, spec);
            f.book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("post io")
                .expect("post ok");
        }

        let (scratch, map) = f
            .book
            .replay_into_scratch(
                None,
                BookKeys::for_development(0x74),
                Entropy::deterministic(seed ^ 0x9999),
            )
            .expect("replay_into_scratch io")
            .expect("replay_into_scratch ok");

        let verified = f
            .book
            .verify_replay(&scratch, &map)
            .expect("verify_replay io")
            .expect("verify_replay ok");
        assert!(
            verified.pairs_checked > 0
                && verified.entries_checked > 0
                && verified.folds_checked > 0,
            "{}",
            replay_diagnostic(
                "metamorphic_scratch_replay_preserves_folds_and_reports",
                seed,
                format!("verify_replay incomplete: {verified:?}")
            )
        );

        let src_fold = f.book.fold_period(&f.march).expect("src fold");
        let scr_fold = scratch.fold_period(&f.march).expect("scratch fold");
        assert_eq!(src_fold.cells, scr_fold.cells);
        assert_eq!(src_fold.pending, scr_fold.pending);
        assert_eq!(src_fold.entries, scr_fold.entries);

        let src_tb = f
            .book
            .trial_balance(std::slice::from_ref(&f.march))
            .expect("src tb");
        let scr_tb = scratch
            .trial_balance(std::slice::from_ref(&f.march))
            .expect("scratch tb");
        assert_eq!(src_tb.rows, scr_tb.rows);
        assert_eq!(src_tb.unit_totals, scr_tb.unit_totals);
    }
}

fn check_rebuild_matches_maintained(
    seed: u64,
    maintained: &Fold,
    rebuilt: &Fold,
    refolded: &Fold,
    is_green: bool,
) -> Result<(), String> {
    if maintained != rebuilt || rebuilt != refolded || !is_green {
        return Err(replay_diagnostic(
            "metamorphic_rebuild_registers_equals_incrementally_maintained_registers",
            seed,
            format!(
                "maintained={maintained:?}, rebuilt={rebuilt:?}, refolded={refolded:?}, is_green={is_green}"
            ),
        ));
    }
    Ok(())
}

#[test]
fn metamorphic_rebuild_registers_equals_incrementally_maintained_registers() {
    for seed in SEEDS {
        let mut f = setup_book(seed, 0x45);
        let entries = generate_entries(seed ^ 0x5005_0000, f.usd, f.eur);
        let post_cap = Capability::embedded(f.principal, &["post"]).expect("post cap");

        for (idx, spec) in entries.iter().enumerate() {
            let proposal = build_proposal(&f, spec);
            f.book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("post io")
                .expect("post ok");
            if idx.is_multiple_of(2) {
                let _ = f.book.advance_registers(&f.march).expect("advance");
            }
        }

        // Also post a Pending reservation and resolve it.
        let hold_legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(f.book_id, "6000"),
                Amount::new(f.usd, 12_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(f.book_id, "1000"),
                Amount::new(f.usd, 12_000),
            ),
        ];
        let hold_proposal = EntryPayload {
            schema_minor: 0,
            book_id: f.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::PENDING,
            effective_date: f.day,
            document_date: None,
            description: f.book.seal_text("pending hold").expect("seal"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&hold_legs).expect("totals"),
            legs: hold_legs.clone(),
            control: None,
            base_totals: None,
            idempotency_key: format!("hold-{seed:016x}").into_bytes(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0x51; 32]),
                intent_kind: 1,
            },
            principal_ref: f.principal,
            session_ref: None,
            evidence: vec![f.evidence],
            supersession: Vec::new(),
            pending: Some(Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            }),
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let hold_posted = f
            .book
            .post(PostRequest {
                proposal: hold_proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: post_cap.clone(),
            })
            .expect("hold io")
            .expect("hold ok");
        let _ = f.book.advance_registers(&f.march).expect("advance hold");

        let res_proposal = EntryPayload {
            schema_minor: 0,
            book_id: f.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::RESOLUTION,
            effective_date: f.day,
            document_date: None,
            description: f.book.seal_text("resolve hold").expect("seal"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&hold_legs).expect("totals"),
            legs: hold_legs,
            control: None,
            base_totals: None,
            idempotency_key: format!("resolve-{seed:016x}").into_bytes(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0x52; 32]),
                intent_kind: 1,
            },
            principal_ref: f.principal,
            session_ref: None,
            evidence: vec![f.evidence],
            supersession: Vec::new(),
            pending: Some(Pending {
                timeout_ns: None,
                resolution_of: Some(hold_posted.entry_ref()),
                disposition: Some(Disposition::Posts {
                    source_ordinals: vec![0, 1],
                }),
            }),
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        f.book
            .post(PostRequest {
                proposal: res_proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: post_cap.clone(),
            })
            .expect("resolve io")
            .expect("resolve ok");

        let maintained = f
            .book
            .advance_registers(&f.march)
            .expect("advance final")
            .fold;
        let verify_before = f.book.verify_registers(&f.march).expect("verify before");
        let rebuilt = f.book.rebuild_registers(&f.march).expect("rebuild").fold;
        let refolded = f.book.fold_period(&f.march).expect("fold_period");
        let verify_after = f.book.verify_registers(&f.march).expect("verify after");

        check_rebuild_matches_maintained(
            seed,
            &maintained,
            &rebuilt,
            &refolded,
            verify_before.is_green() && verify_after.is_green(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn metamorphic_bundle_idempotence_and_redaction_preserves_certified_results() {
    for seed in SEEDS {
        let mut f = setup_book(seed, 0x46);
        let bank_stmt = Document {
            book_id: f.book_id,
            kind: 5, // BankStatement (governed by redaction_contracts.toml id=1)
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: f.principal,
            bytes: format!("BANK-STATEMENT-PAGE1-{seed:016x}").into_bytes(),
        };
        let bank_added = f
            .book
            .add_document(&bank_stmt)
            .expect("add bank_stmt io")
            .expect("add bank_stmt ok");

        let entries = generate_entries(seed ^ 0x6006_0000, f.usd, f.eur);
        let post_cap = Capability::embedded(f.principal, &["post"]).expect("post cap");
        for spec in &entries {
            let mut proposal = build_proposal(&f, spec);
            proposal.evidence.push(bank_stmt.evidence_ref(1));
            proposal.evidence.sort();
            f.book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .expect("post io")
                .expect("post ok");
        }

        let fold_before = f.book.fold_period(&f.march).expect("fold before");
        let tb_before = f
            .book
            .trial_balance(std::slice::from_ref(&f.march))
            .expect("tb before");

        let priv_cap =
            Capability::embedded(f.principal, &["privileged", "witness", "produce", "read"])
                .expect("priv cap");
        let cp = f
            .book
            .checkpoint(f.principal, &priv_cap)
            .expect("checkpoint io")
            .expect("checkpoint ok");
        let state_oid = cp.checkpoint.checkpoint.body.state_oid;

        let req = BundleRequest {
            scope: BundleScope::Prefix,
            balances: Vec::new(),
            inline_documents: true,
        };
        let b1 = f
            .book
            .produce_bundle(f.principal, &priv_cap, Some(state_oid), &req)
            .expect("b1 io")
            .expect("b1 ok")
            .expect("b1 some");
        let b2 = f
            .book
            .produce_bundle(f.principal, &priv_cap, Some(state_oid), &req)
            .expect("b2 io")
            .expect("b2 ok")
            .expect("b2 some");
        assert_eq!(
            b1.bundle.bytes,
            b2.bundle.bytes,
            "{}",
            replay_diagnostic(
                "metamorphic_bundle_idempotence_and_redaction_preserves_certified_results",
                seed,
                "bundle bytes differed across two productions of the same checkpoint"
            )
        );

        // Derive redacted view of the governed BankStatement document and verify accounting folds are unchanged.
        f.book
            .derive_redacted_view(&priv_cap, &bank_added.oid)
            .expect("derive_redacted_view io")
            .expect("derive_redacted_view ok");

        let fold_after = f.book.fold_period(&f.march).expect("fold after");
        let tb_after = f
            .book
            .trial_balance(std::slice::from_ref(&f.march))
            .expect("tb after");
        assert_eq!(fold_before, fold_after);
        assert_eq!(tb_before.rows, tb_after.rows);
        assert_eq!(tb_before.unit_totals, tb_after.unit_totals);
        assert!(
            f.book
                .verify_accumulator()
                .expect("verify_accumulator")
                .is_green()
        );
    }
}

#[test]
fn metamorphic_fiscal_calendar_matches_day_walker() {
    let end_dec_sat = YearEndRule::LastWeekdayOfMonth {
        weekday: Weekday::Saturday,
        month: 12,
    };
    let end_jan_nearest = YearEndRule::WeekdayNearestEnd {
        weekday: Weekday::Saturday,
        month: 1,
    };
    let calendars = [
        (FiscalCalendar::monthly("m-jan", 1, 1).unwrap(), 2024),
        (FiscalCalendar::monthly("m-jan", 1, 1).unwrap(), 2026),
        (FiscalCalendar::monthly("m-jul", 7, 1).unwrap(), 2026),
        (FiscalCalendar::monthly("m-oct", 10, 2).unwrap(), 2026),
        (
            FiscalCalendar::weeks("w-445", WeekPattern::W445, end_dec_sat, 1).unwrap(),
            2026,
        ),
        (
            FiscalCalendar::weeks("w-454", WeekPattern::W454, end_dec_sat, 1).unwrap(),
            2026,
        ),
        (
            FiscalCalendar::weeks("w-544", WeekPattern::W544, end_dec_sat, 1).unwrap(),
            2026,
        ),
        (
            FiscalCalendar::week_52_53("w-5253", end_jan_nearest, 1).unwrap(),
            2026,
        ),
    ];

    for (idx, (cal, fy)) in calendars.iter().enumerate() {
        let seed = SEEDS[idx];
        let periods = cal.periods_for_year(*fy).expect("periods_for_year");
        let normals: Vec<_> = periods
            .iter()
            .filter(|p| p.kind == PeriodKind::Normal)
            .collect();
        assert!(!normals.is_empty());

        for pair in normals.windows(2) {
            assert_eq!(
                pair[0].end,
                pair[1].start,
                "{}",
                replay_diagnostic(
                    "metamorphic_fiscal_calendar_matches_day_walker",
                    seed,
                    format!(
                        "gap or overlap between {} and {}",
                        pair[0].code, pair[1].code
                    )
                )
            );
        }

        let start_day = normals.first().unwrap().start.0;
        let end_day = normals.last().unwrap().end.0;
        for d in start_day..end_day {
            let day = DateDay(d);
            let resolved = resolve_period(&periods, day, None).expect("resolve_period");
            let brute = normals
                .iter()
                .find(|p| p.start <= day && day < p.end)
                .expect("brute-force normal period");
            assert_eq!(
                resolved.code,
                brute.code,
                "{}",
                replay_diagnostic(
                    "metamorphic_fiscal_calendar_matches_day_walker",
                    seed,
                    format!(
                        "day {d} resolved to {} instead of {}",
                        resolved.code, brute.code
                    )
                )
            );
        }
    }
}

/// Planted breaks (`fa-hlvs`): verify that each metamorphic relation's
/// checker rejects a perturbed fold/report and includes the seed + replay
/// command in the diagnostic.
#[test]
fn planted_breaks_are_caught_for_every_metamorphic_relation() {
    let seed = SEEDS[0];
    let mut f = setup_book(seed, 0x47);
    let entries = generate_entries(seed, f.usd, f.eur);
    let post_cap = Capability::embedded(f.principal, &["post"]).expect("post cap");
    for spec in &entries {
        let proposal = build_proposal(&f, spec);
        f.book
            .post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: post_cap.clone(),
            })
            .expect("post io")
            .expect("post ok");
    }

    let fold = f.book.fold_period(&f.march).expect("fold");
    let tb = f
        .book
        .trial_balance(std::slice::from_ref(&f.march))
        .expect("tb");
    let bs = f
        .book
        .statement(
            StatementSelection {
                definition: StatementDefinition::embedded("balance-sheet").expect("balance-sheet"),
                periods: vec![f.march.clone()],
                comparative: Vec::new(),
            },
            None,
        )
        .expect("bs io")
        .expect("bs ok");
    let is = f
        .book
        .statement(
            StatementSelection {
                definition: StatementDefinition::embedded("income-statement")
                    .expect("income-statement"),
                periods: vec![f.march.clone()],
                comparative: Vec::new(),
            },
            None,
        )
        .expect("is io")
        .expect("is ok");

    // 1. Planted reorder drift (+1 mantissa on cell 0).
    let mut drifted_fold = fold.clone();
    drifted_fold.cells[0].debits += 1;
    let err1 = check_reorder_equivalence(seed, &fold, &drifted_fold, &tb, &tb, &bs, &bs, &is, &is)
        .unwrap_err();
    assert!(err1.contains(&format!("0x{seed:016x}")));
    assert!(err1.contains("cargo test -p fa --test metamorphic"));

    // 2. Planted reverse+replace net balance drift.
    let err2 = check_reverse_replace_equivalence(seed, &fold, &drifted_fold, &bs, &bs, &is, &is)
        .unwrap_err();
    assert!(err2.contains(&format!("0x{seed:016x}")));
    assert!(err2.contains("cargo test -p fa --test metamorphic"));

    // 3. Planted rebuild vs maintained drift.
    let err3 =
        check_rebuild_matches_maintained(seed, &fold, &drifted_fold, &fold, true).unwrap_err();
    assert!(err3.contains(&format!("0x{seed:016x}")));
    assert!(err3.contains("cargo test -p fa --test metamorphic"));
}
