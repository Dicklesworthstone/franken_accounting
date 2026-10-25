//! The TigerBeetle semantic corpus through the posting kernel (bead fa-w3n6,
//! plan §5.4, §16.3).
//!
//! Each scenario of `corpora/tigerbeetle_semantics.toml` becomes kernel
//! requests on a fresh in-memory book: a transfer is an Original, a pending
//! transfer a Pending hold whose timeout is anchored to a journaled tick,
//! `post_pending` a `Resolution(Posts)` drawing both legs, `void_pending` a
//! `Resolution(Voids)`, and an expiry the sweep's `Resolution(Expires)` once a
//! tick past the deadline is journaled. Every outcome and every account's four
//! sub-vectors (`debits_pending`, `debits_posted`, `credits_pending`,
//! `credits_posted`, read from the trial-balance fold) must equal the
//! scenario's expectations. A limited account's `LimitCell`, the kernel's
//! availability witness, must carry the same four fields.
//!
//! Every corpus account is a debit-normal Asset, so a positive
//! `max_debit_net` is the kernel's upper bound
//! (`debits_posted + debits_pending - credits_posted <= max`, plan §5.4).
//! TigerBeetle itself is not run: the expectations are the corpus's, written
//! from TigerBeetle's documented semantics.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_formats::tigerbeetle::{TbCorpus, TbScenario, TbStep};
use fa_journal::evidence::{Document, add_document};
use fa_journal::refusal::Refusal;
use fa_journal::{
    AccountSpec, BalanceLimit, BookContext, BookSpec, Capability, LimitCell, LimitScope, Op,
    PostRequest, Posted, Profile, SweepRequest, TickRequest, UnitPolicy, create_book,
    create_periods, install_chart, limit_cell_vid, post, record_tick, sweep, transition_period,
};
use fa_model::{
    ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable,
    EvidenceRef, Id128, LegPayload, Oid, Pending, SealKey, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

const PRINCIPAL: VId = VId(7);
const DAY_NS: u64 = 86_400_000_000_000;

/// The corpus's refusal vocabulary, by the kernel's catalog code.
fn refusal_label(r: &Refusal) -> String {
    match r.code {
        // A second resolution of one hold (TigerBeetle
        // `pending_transfer_already_posted` / `_voided`).
        "FA-REF-062" => "refused_already_resolved".into(),
        // A post past an account's upper bound
        // (`net + pending_in + x > upper_bound`; TigerBeetle `exceeds_*`).
        "FA-REF-091" => "refused_exceeds_limit".into(),
        // A posted sub-vector larger than its hold
        // (TigerBeetle `exceeds_pending_transfer_amount`).
        "FA-REF-061" => "refused_exceeds_pending".into(),
        other => format!("refused_{other}"),
    }
}

/// One scenario's book: the real kernel over an in-memory substrate.
struct Kernel {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    accounts: BTreeMap<String, (VId, UnitId, bool)>,
    evidence: Vec<EvidenceRef>,
    holds: BTreeMap<String, (EntryRef, String, String, UnitId)>,
    march: String,
    latest_tick_ns: u64,
    nonce: u8,
}

impl Kernel {
    fn new(index: u8, scenario: &TbScenario) -> Self {
        let runtime = RuntimeBuilder::new().build().expect("runtime");
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [0x5a; 32],
            DatabaseSecurityNamespaceId([0x5b; 32]),
            [0x5c; 32],
        );
        let mut db = runtime
            .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
            .expect("open");
        let units = UnitRegistry::with_defaults();
        let base = units.lookup("USD").expect("USD");
        let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let book_id = Id128([index; 16]);
        let spec = BookSpec {
            book_id,
            name: format!("TigerBeetle corpus {}", scenario.id),
            base_unit: base,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
            .expect("create_book");
        let book = BookContext {
            book_id,
            calendar,
            units,
            seal_key: SealKey([0x11; 32]),
            symbols,
        };

        let mut accounts = BTreeMap::new();
        let mut chart = Vec::new();
        for account in &scenario.accounts {
            let unit = book.units.lookup(&account.unit).expect("registered unit");
            let limited = account.max_debit_net > 0;
            chart.push(AccountSpec {
                code: account.code.clone(),
                name: format!("TigerBeetle account {}", account.code),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(unit),
                parent_code: None,
                limit: limited.then_some(BalanceLimit {
                    lower: None,
                    upper: Some(account.max_debit_net),
                    scope: LimitScope::Lifetime,
                }),
            });
            accounts.insert(
                account.code.clone(),
                (account_vid(book_id, &account.code), unit, limited),
            );
        }
        let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
        runtime
            .block_on(async {
                install_chart(
                    &mut db,
                    &ctx,
                    &book,
                    &chart,
                    PRINCIPAL,
                    day(1),
                    b"tb-chart",
                    seal(&book, "chart", 5),
                    &schema,
                )
                .await
            })
            .expect("kernel")
            .expect("chart installs");
        let (_, periods) = runtime
            .block_on(async {
                create_periods(
                    &mut db,
                    &ctx,
                    &book,
                    2026,
                    PRINCIPAL,
                    seal(&book, "periods", 6),
                    &schema,
                )
                .await
            })
            .expect("kernel")
            .expect("periods");
        let march = periods
            .iter()
            .find(|p| p.contains(day(15)) && p.kind == PeriodKind::Normal)
            .expect("March")
            .code
            .clone();
        runtime
            .block_on(async {
                transition_period(
                    &mut db,
                    &ctx,
                    &book,
                    &march,
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    b"open-march",
                    seal(&book, "open March", 7),
                    &Capability::embedded(PRINCIPAL, &["close", "reopen", "post"]).unwrap(),
                    &[],
                )
                .await
            })
            .expect("kernel")
            .expect("March opens");
        let source = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: format!("Transfer orders for TigerBeetle scenario {}", scenario.id).into_bytes(),
        };
        runtime
            .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
            .expect("kernel")
            .expect("the source document is admitted");
        Self {
            runtime,
            root,
            db,
            book,
            accounts,
            evidence: vec![source.evidence_ref(1)],
            holds: BTreeMap::new(),
            march,
            latest_tick_ns: 0,
            nonce: 10,
        }
    }

    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn next_nonce(&mut self) -> u8 {
        self.nonce = self.nonce.checked_add(1).expect("nonce space");
        self.nonce
    }

    fn account(&self, code: &str) -> (VId, UnitId) {
        let (vid, unit, _) = self.accounts[code];
        (vid, unit)
    }

    fn transfer_legs(&self, debit: &str, credit: &str, amount: i128) -> Vec<LegPayload> {
        let (dr, unit) = self.account(debit);
        let (cr, _) = self.account(credit);
        vec![
            LegPayload::simple(Side::Debit, dr, Amount::new(unit, amount)),
            LegPayload::simple(Side::Credit, cr, Amount::new(unit, amount)),
        ]
    }

    fn proposal(
        &mut self,
        on: i32,
        key: &str,
        class: EntryClass,
        legs: Vec<LegPayload>,
    ) -> EntryPayload {
        let nonce = self.next_nonce();
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: day(on),
            document_date: None,
            description: seal(&self.book, key, nonce),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn post(&mut self, proposal: EntryPayload) -> Result<Posted, Refusal> {
        let ctx = self.ctx();
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        };
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
    }

    /// Journal a corroborated daemon-clock tick at `on` (plus a nonce, so
    /// ticks strictly increase), unless a later one is already recorded.
    fn tick(&mut self, on: i32) -> u64 {
        let nonce = self.next_nonce();
        let observed = day_ns(on) + u64::from(nonce);
        if observed <= self.latest_tick_ns {
            return self.latest_tick_ns;
        }
        let ctx = self.ctx();
        let req = TickRequest {
            observed_utc_ns: observed,
            source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
            monotonic_ok: true,
            principal_ref: PRINCIPAL,
            capability: Capability::embedded(PRINCIPAL, &["witness"]).unwrap(),
            idempotency_key: format!("tick-{observed}").into_bytes(),
            description: seal(&self.book, "tick", nonce),
        };
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move { record_tick(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("tick recorded");
        self.latest_tick_ns = observed;
        observed
    }

    /// The book's intrinsic sweep under its `System` capability; the holds
    /// it expired.
    fn sweep_expiry(&mut self) -> Result<Vec<EntryRef>, Refusal> {
        let ctx = self.ctx();
        let system = fa_journal::rows::system_principal(self.book.book_id);
        let req = SweepRequest {
            principal_ref: system,
            capability: Capability::new(system, Profile::System, &[Op::Post], system).unwrap(),
            max_batch: 8,
        };
        let mut nonce = self.next_nonce();
        let (db, book) = (&mut self.db, &self.book);
        let swept = self
            .runtime
            .block_on(async move {
                let mut describe = |text: &str| {
                    nonce = nonce.wrapping_add(1);
                    Ok(seal(book, text, nonce))
                };
                sweep(db, &ctx, book, &req, &mut describe).await
            })
            .expect("kernel")?;
        Ok(swept
            .expiry
            .iter()
            .flat_map(|batch| batch.expired.iter().map(|(hold, _)| *hold))
            .collect())
    }

    /// Run one corpus step through the kernel; its corpus outcome.
    fn run(&mut self, step: &TbStep) -> String {
        match step {
            TbStep::Post {
                id,
                debit_account,
                credit_account,
                amount,
                day,
            } => {
                let legs = self.transfer_legs(debit_account, credit_account, *amount);
                let proposal = self.proposal(*day, id, EntryClass::ORIGINAL, legs);
                outcome(id, self.post(proposal))
            }
            TbStep::Pending {
                id,
                debit_account,
                credit_account,
                amount,
                day,
                expiry_day,
            } => {
                // The timeout is anchored to the latest journaled tick, so
                // one is recorded at the transfer's day first.
                let anchor = self.tick(*day);
                let deadline = day_ns(*expiry_day) + (anchor - day_ns(*day));
                let legs = self.transfer_legs(debit_account, credit_account, *amount);
                let mut proposal = self.proposal(*day, id, EntryClass::PENDING, legs);
                proposal.pending = Some(Pending {
                    timeout_ns: Some(deadline - anchor),
                    resolution_of: None,
                    disposition: None,
                });
                let (_, unit) = self.account(debit_account);
                match self.post(proposal) {
                    Ok(posted) => {
                        self.holds.insert(
                            id.clone(),
                            (
                                posted.entry_ref(),
                                debit_account.clone(),
                                credit_account.clone(),
                                unit,
                            ),
                        );
                        outcome(id, Ok(posted))
                    }
                    Err(r) => outcome(id, Err(r)),
                }
            }
            TbStep::Capture {
                id,
                pending_id,
                amount,
                day,
            } => {
                let Some((hold, debit, credit, _)) = self.holds.get(pending_id).cloned() else {
                    return format!("{id}:refused_unknown_pending");
                };
                let legs = self.transfer_legs(&debit, &credit, *amount);
                let mut proposal = self.proposal(*day, id, EntryClass::RESOLUTION, legs);
                proposal.pending = Some(Pending {
                    timeout_ns: None,
                    resolution_of: Some(hold),
                    disposition: Some(Disposition::Posts {
                        source_ordinals: vec![0, 1],
                    }),
                });
                outcome(id, self.post(proposal))
            }
            TbStep::Void {
                id,
                pending_id,
                day,
            } => {
                let Some((hold, ..)) = self.holds.get(pending_id).cloned() else {
                    return format!("{id}:refused_unknown_pending");
                };
                let mut proposal = self.proposal(*day, id, EntryClass::RESOLUTION, Vec::new());
                proposal.control = Some(ControlPayload::ReservationRelease);
                proposal.pending = Some(Pending {
                    timeout_ns: None,
                    resolution_of: Some(hold),
                    disposition: Some(Disposition::Voids),
                });
                outcome(id, self.post(proposal))
            }
            TbStep::Expire {
                id,
                pending_id,
                day,
            } => {
                let Some((hold, ..)) = self.holds.get(pending_id).cloned() else {
                    return format!("{id}:refused_unknown_pending");
                };
                self.tick(*day);
                match self.sweep_expiry() {
                    Ok(expired) if expired.contains(&hold) => format!("{id}:committed"),
                    Ok(_) => format!("{id}:refused_not_yet_expired"),
                    Err(r) => format!("{id}:{}", refusal_label(&r)),
                }
            }
        }
    }

    /// Every corpus account's four sub-vectors from the trial-balance fold,
    /// in the corpus's account order, plus each limited account's cell.
    fn balances(&self, scenario: &TbScenario) -> (Vec<String>, Vec<String>) {
        let tb =
            fa_registers::trial_balance(&self.db, &self.book, std::slice::from_ref(&self.march))
                .expect("fold");
        let mut folded = Vec::new();
        let mut cells = Vec::new();
        for account in &scenario.accounts {
            let (vid, _, limited) = self.accounts[&account.code];
            let [dp, dpost, cp, cpost] = tb.rows.iter().filter(|row| row.account == vid).fold(
                [0i128; 4],
                |[dp, dpost, cp, cpost], row| {
                    let add = |sum: i128, column: i128| sum.checked_add(column).expect("i128 sum");
                    [
                        add(dp, row.debits_pending),
                        add(dpost, row.debits),
                        add(cp, row.credits_pending),
                        add(cpost, row.credits),
                    ]
                },
            );
            let summary = format!(
                "{}:dp={dp}:dpost={dpost}:cp={cp}:cpost={cpost}",
                account.code
            );
            if limited {
                let row = self
                    .db
                    .vertex(limit_cell_vid(vid))
                    .expect("read")
                    .expect("a limited account owns a LimitCell");
                let cell = LimitCell::decode_bound(&row, vid, None).expect("cell");
                let witnessed = format!(
                    "{}:dp={}:dpost={}:cp={}:cpost={}",
                    account.code,
                    cell.debits_pending,
                    cell.debits_posted,
                    cell.credits_pending,
                    cell.credits_posted
                );
                if witnessed != summary {
                    cells.push(format!("cell {witnessed} != fold {summary}"));
                }
            }
            folded.push(summary);
        }
        (folded, cells)
    }
}

fn day(on: i32) -> DateDay {
    DateDay::from_ymd(2026, 3, u8::try_from(on).expect("a day of March")).unwrap()
}

fn day_ns(on: i32) -> u64 {
    u64::try_from(day(on).0).unwrap() * DAY_NS
}

fn seal(book: &BookContext, text: &str, nonce: u8) -> Erasable<String> {
    Erasable::seal(
        &text.to_string(),
        None,
        &book.seal_key,
        [nonce; 32],
        [nonce; 24],
    )
}

fn outcome(id: &str, result: Result<Posted, Refusal>) -> String {
    match result {
        Ok(Posted::Committed { .. }) => format!("{id}:committed"),
        Ok(Posted::AlreadyRecorded { .. }) => format!("{id}:recorded"),
        Err(r) => format!("{id}:{}", refusal_label(&r)),
    }
}

#[test]
fn corpus_runs_through_kernel() {
    let corpus = TbCorpus::embedded().expect("tigerbeetle_semantics.toml");
    assert!(!corpus.scenarios.is_empty());
    let mut failures = Vec::new();
    for (index, scenario) in corpus.scenarios.iter().enumerate() {
        let index = u8::try_from(index + 1).expect("scenario count");
        let mut kernel = Kernel::new(index, scenario);
        let outcomes: Vec<String> = scenario.steps.iter().map(|s| kernel.run(s)).collect();
        let (balances, cells) = kernel.balances(scenario);
        println!(
            "kernel TigerBeetle scenario {} (divergence {}): outcomes expected={:?} observed={:?}; balances expected={:?} observed={:?}; limit cells {}",
            scenario.id,
            scenario.divergence,
            scenario.expected_outcomes,
            outcomes,
            scenario.expected_balances,
            balances,
            if cells.is_empty() {
                "agree with the fold".to_string()
            } else {
                cells.join(", ")
            }
        );
        if outcomes != scenario.expected_outcomes {
            failures.push(format!(
                "{}: outcomes expected {:?}, the kernel gave {:?}",
                scenario.id, scenario.expected_outcomes, outcomes
            ));
        }
        if balances != scenario.expected_balances {
            failures.push(format!(
                "{}: balances expected {:?}, the kernel folded {:?}",
                scenario.id, scenario.expected_balances, balances
            ));
        }
        for cell in cells {
            failures.push(format!("{}: {cell}", scenario.id));
        }
    }
    assert!(
        failures.is_empty(),
        "the kernel disagrees with the TigerBeetle corpus:\n{}",
        failures.join("\n")
    );
}
