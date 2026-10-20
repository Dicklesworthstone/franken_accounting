//! Shared cumulative daily limits use the real native transaction/history.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::policy::{IssuanceRequest, RevocationRequest, issue_capability, revoke_capability};
use fa_journal::usage::{UsageCell, UsageDebit, UsageKey, UsageVerification, verify_usage};
use fa_journal::*;
use fa_model::symbols::{label, relation};
use fa_model::{
    ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef,
    Id128, LegPayload, Oid, Pending, SealKey, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Capability, Op, Profile, possession_digest};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

const OWNER: VId = VId(7);
const HOLDER: VId = VId(21);
const NS_PER_DAY: u64 = 86_400_000_000_000;

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    quota: Capability,
    evidence: Vec<EvidenceRef>,
}

fn owner() -> Capability {
    Capability::embedded(OWNER, &["post", "issue_capability", "read", "rule_change"]).unwrap()
}

fn day() -> DateDay {
    DateDay::from_ymd(2026, 3, 15).unwrap()
}

fn seal(book: &BookContext, value: &str) -> Erasable<String> {
    Erasable::seal(&value.to_string(), None, &book.seal_key, [51; 32], [52; 24])
}

impl Harness {
    fn new(limit: i128, utc: bool, tick: bool) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([41; 32], DatabaseSecurityNamespaceId([42; 32]), [43; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("usage", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: Id128([44; 16]),
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([45; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "Shared quota".into(),
            base_unit: usd,
            calendar,
            time_zone_policy: utc.then_some(TimeZonePolicy::Utc),
            entities: Vec::new(),
            opening_date: None,
        };
        runtime
            .block_on(create_book(&mut db, &cx, &spec, &units, &symbols))
            .unwrap();
        let chart: Vec<_> = [("1000", 1), ("6000", 5)]
            .into_iter()
            .map(|(code, account_type)| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            })
            .collect();
        let schema = Capability::embedded(OWNER, &["schema_change"]).unwrap();
        runtime
            .block_on(install_chart(
                &mut db,
                &cx,
                &book,
                &chart,
                OWNER,
                day(),
                b"chart",
                seal(&book, "chart"),
                &schema,
            ))
            .unwrap()
            .unwrap();
        let (_, periods) = runtime
            .block_on(create_periods(
                &mut db,
                &cx,
                &book,
                2026,
                OWNER,
                seal(&book, "periods"),
                &schema,
            ))
            .unwrap()
            .unwrap();
        let march = &periods
            .iter()
            .find(|p| p.kind == PeriodKind::Normal && p.contains(day()))
            .unwrap()
            .code;
        runtime
            .block_on(transition_period(
                &mut db,
                &cx,
                &book,
                march,
                PeriodTransition::Open,
                OWNER,
                1,
                b"open",
                seal(&book, "open"),
                &Capability::embedded(OWNER, &["close"]).unwrap(),
                &[],
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id: book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: OWNER,
            bytes: b"Retained invoice for native cumulative debit tests".to_vec(),
        };
        runtime
            .block_on(add_document(&mut db, &cx, &book, &document))
            .unwrap()
            .unwrap();
        let quota = Capability::new(
            HOLDER,
            Profile::Human,
            &[Op::Post, Op::IssueCapability],
            OWNER,
        )
        .unwrap()
        .holder_bound(possession_digest(&[53; 32]))
        .with_daily_total(usd, limit)
        .unwrap();
        let mut h = Self {
            runtime,
            root,
            db,
            book,
            usd,
            quota,
            evidence: vec![document.evidence_ref(1)],
        };
        let quota = h.quota.clone();
        h.issue(&owner(), &quota, b"root").unwrap();
        if tick {
            h.tick(
                u64::try_from(day().0).unwrap() * NS_PER_DAY + 1_000_000_000,
                b"tick",
            );
        }
        h
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.db.frontier().unwrap()
    }
    fn issue(
        &mut self,
        issuer: &Capability,
        issued: &Capability,
        key: &[u8],
    ) -> Result<fa_journal::policy::Issued, Refusal> {
        let cx = self.cx();
        let request = IssuanceRequest {
            capability: issuer.clone(),
            issued: issued.clone(),
            effective_date: day(),
            idempotency_key: key.to_vec(),
            description: seal(&self.book, "issue quota"),
        };
        self.runtime
            .block_on(issue_capability(&mut self.db, &cx, &self.book, request))
            .unwrap()
    }
    fn tick(&mut self, observed_utc_ns: u64, key: &[u8]) {
        self.tick_with_status(observed_utc_ns, key, true);
    }
    fn tick_with_status(&mut self, observed_utc_ns: u64, key: &[u8], monotonic_ok: bool) {
        let cx = self.cx();
        let request = TickRequest {
            observed_utc_ns,
            source: sweep::SOURCE_DAEMON_CLOCK,
            monotonic_ok,
            principal_ref: OWNER,
            capability: Capability::embedded(OWNER, &["witness"]).unwrap(),
            idempotency_key: key.to_vec(),
            description: seal(&self.book, "clock"),
        };
        self.runtime
            .block_on(record_tick(&mut self.db, &cx, &self.book, request))
            .unwrap()
            .unwrap();
    }
    fn proposal(&self, principal: VId, cents: i128, key: &[u8]) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(self.book.book_id, "6000"),
                Amount::new(self.usd, cents),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(self.book.book_id, "1000"),
                Amount::new(self.usd, cents),
            ),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: seal(&self.book, "spend"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([54; 32]),
                intent_kind: 1,
            },
            principal_ref: principal,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }
    fn request(&self, proposal: EntryPayload, capability: &Capability) -> PostRequest {
        PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: capability.clone(),
        }
    }
    fn post(&mut self, proposal: EntryPayload, capability: &Capability) -> Result<Posted, Refusal> {
        let cx = self.cx();
        let request = self.request(proposal, capability);
        self.runtime
            .block_on(post(&mut self.db, &cx, &self.book, request))
            .unwrap()
    }
    fn prepare(&mut self, proposal: EntryPayload, capability: &Capability) -> Box<PreparedPost> {
        let cx = self.cx();
        let request = self.request(proposal, capability);
        match prepare_post(&mut self.db, &cx, &self.book, request)
            .unwrap()
            .unwrap()
        {
            PostPreparation::Ready(prepared) => prepared,
            PostPreparation::AlreadyRecorded(_) => panic!("fresh preparation required"),
        }
    }
    fn commit(&mut self, prepared: Box<PreparedPost>) -> Result<Posted, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(prepared.commit(&mut self.db, &cx))
            .unwrap()
    }
    fn key(&self) -> UsageKey {
        UsageKey {
            book_id: self.book.book_id,
            root_issuance: self.quota.commitment().unwrap(),
            day: day(),
            unit: self.usd,
        }
    }
    fn cell(&self) -> UsageCell {
        UsageCell::from_row(
            &self.db.vertex(self.key().cell_vid()).unwrap().unwrap(),
            self.key(),
        )
        .unwrap()
    }
    fn check(&self, at: Option<CommitSeq>) -> UsageVerification {
        verify_usage(&self.db, &self.cx(), &self.book, at).unwrap()
    }
    fn write(&mut self, change: WriteBatch) {
        let cx = self.cx();
        self.runtime
            .block_on(self.db.write(&cx.commit(), change))
            .unwrap();
    }
    fn batch(&mut self, key: &[u8], amounts: &[i128]) -> Result<BatchPosted, Refusal> {
        let intents = amounts
            .iter()
            .enumerate()
            .map(|(index, amount)| {
                let member_key = format!("{}-{index}", String::from_utf8_lossy(key));
                PostIntent::new(
                    self.proposal(HOLDER, *amount, member_key.as_bytes()),
                    Vec::new(),
                )
                .unwrap()
            })
            .collect();
        let batch = PostBatch::new(key.to_vec(), intents).unwrap();
        let cx = self.cx();
        self.runtime
            .block_on(post_batch(
                &mut self.db,
                &cx,
                &self.book,
                self.quota.clone(),
                batch,
            ))
            .unwrap()
    }
}

#[test]
fn complete_gross_debits_share_a_root_across_calls_descendants_and_retries() {
    let mut h = Harness::new(100_000, true, true);
    let root = h.quota.clone();
    let child = |holder, bound| {
        Capability::new(holder, Profile::Human, &[Op::Post], HOLDER)
            .unwrap()
            .holder_bound(possession_digest(&[55; 32]))
            .with_daily_total(h.usd, bound)
            .unwrap()
            .with_daily_root(root.commitment().unwrap())
            .unwrap()
    };
    let alice = child(VId(31), 100_000);
    let bob = child(VId(32), 100_000);
    h.issue(&root, &alice, b"alice").unwrap();
    h.issue(&root, &bob, b"bob").unwrap();
    let first = h.proposal(alice.holder(), 60_000, b"first");
    let original_digest = first.proposal_digest().unwrap();
    let recorded = h.post(first.clone(), &alice).unwrap();
    let at = h.head();
    assert!(matches!(
        h.post(first, &alice).unwrap(),
        Posted::AlreadyRecorded { .. }
    ));
    assert_eq!(h.head(), at);
    let entry = post::read_entry(&h.db, recorded.entry_ref().vid)
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        entry.proposal_digest, original_digest,
        "usage must not change the approved proposal"
    );
    assert_eq!(h.cell().gross_debits, 60_000);
    let refusal = h
        .post(h.proposal(bob.holder(), 50_000, b"split"), &bob)
        .unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (refusal::code::DAILY_CEILING, exit::SAFETY)
    );
    assert_eq!(h.head(), at);
    h.post(h.proposal(bob.holder(), 40_000, b"remaining"), &bob)
        .unwrap();
    assert_eq!((h.cell().gross_debits, h.cell().generation), (100_000, 2));
    let report = h.check(None);
    assert!(report.is_green(), "{report:?}");
    assert_eq!((report.charges_checked, report.cells_checked), (2, 1));
    assert!(h.check(Some(at)).is_green());
}

#[test]
fn issuance_cannot_drop_widen_or_reset_daily_lineage_or_units() {
    let mut h = Harness::new(100, true, true);
    let root = h.quota.clone();
    let child = Capability::new(VId(31), Profile::Human, &[Op::Post], HOLDER)
        .unwrap()
        .holder_bound(possession_digest(&[55; 32]));
    let root_id = root.commitment().unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let bad = [
        child.clone(),
        child.clone().with_daily_total(h.usd, 100).unwrap(),
        child
            .clone()
            .with_daily_total(h.usd, 101)
            .unwrap()
            .with_daily_root(root_id)
            .unwrap(),
        child
            .clone()
            .with_daily_total(eur, 1)
            .unwrap()
            .with_daily_root(root_id)
            .unwrap(),
        child
            .clone()
            .with_daily_total(h.usd, 1)
            .unwrap()
            .with_daily_root([99; 32])
            .unwrap(),
    ];
    let before = h.head();
    for (index, cap) in bad.iter().enumerate() {
        assert_eq!(
            h.issue(&root, cap, format!("bad-{index}").as_bytes())
                .unwrap_err()
                .code,
            "FA-REF-011"
        );
    }
    assert_eq!(h.head(), before);
    let narrow = child
        .with_daily_total(h.usd, 70)
        .unwrap()
        .with_daily_root(root_id)
        .unwrap();
    h.issue(&root, &narrow, b"narrow").unwrap();
    h.post(h.proposal(HOLDER, 60, b"root-spend"), &root)
        .unwrap();
    assert_eq!(
        h.post(h.proposal(narrow.holder(), 11, b"narrow-spend"), &narrow)
            .unwrap_err()
            .code,
        refusal::code::DAILY_CEILING
    );
    let request = RevocationRequest {
        capability: owner(),
        revoked: root_id,
        effective_date: day(),
        idempotency_key: b"revoke-root".to_vec(),
        description: seal(&h.book, "revoke root"),
    };
    let cx = h.cx();
    h.runtime
        .block_on(revoke_capability(&mut h.db, &cx, &h.book, request))
        .unwrap()
        .unwrap();
    let mut unknown = h.proposal(narrow.holder(), 1, b"revoked");
    unknown.legs[0].account_ref = VId(999);
    assert_eq!(
        h.post(unknown, &narrow).unwrap_err().code,
        "FA-REF-023",
        "root revocation wins before chart observation"
    );
}

#[test]
fn scoped_daily_posts_need_only_actual_post_authority_and_keep_portable_plan_scope() {
    let mut h = Harness::new(100, true, true);
    let root = h.quota.clone();
    let scoped = Capability::new(VId(31), Profile::Human, &[Op::Post], HOLDER)
        .unwrap()
        .holder_bound(possession_digest(&[57; 32]))
        .for_accounts(&["1000", "6000"])
        .unwrap()
        .for_periods(&["FY2026-P03"])
        .unwrap()
        .effective_through(day())
        .with_daily_total(h.usd, 100)
        .unwrap()
        .with_daily_root(root.commitment().unwrap())
        .unwrap();
    h.issue(&root, &scoped, b"scoped-quota").unwrap();
    assert!(
        !scoped.holds(Op::Read),
        "internal quota proof hydration requires no new Read grant"
    );
    h.post(h.proposal(scoped.holder(), 40, b"within-scope"), &scoped)
        .unwrap();
    assert_eq!(h.cell().gross_debits, 40);
    let before = h.head();
    let mut outside_account = h.proposal(scoped.holder(), 1, b"outside-account");
    outside_account.legs[0].account_ref = VId(999);
    let mut outside_date = h.proposal(scoped.holder(), 1, b"outside-date");
    outside_date.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
    let mut outside_period = h.proposal(scoped.holder(), 1, b"outside-period");
    outside_period.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
    for proposal in [outside_account, outside_date, outside_period] {
        assert_eq!(
            h.post(proposal, &scoped).unwrap_err().code,
            refusal::code::CAPABILITY
        );
    }
    assert_eq!(h.head(), before);
    assert_eq!(h.cell().gross_debits, 40);
    // Portable plans already require whole-book scope, independently of daily
    // usage. Hydration must neither grant that scope nor impose it on posts.
    let intent =
        PostIntent::new(h.proposal(scoped.holder(), 20, b"scoped-plan"), Vec::new()).unwrap();
    let cx = h.cx();
    let expected = plan::plan_post(&mut h.db, &cx, &h.book, scoped.clone(), intent.clone())
        .unwrap()
        .unwrap_err();
    let actual = h
        .runtime
        .block_on(plan::plan_post_with_history(
            &mut h.db, &cx, &h.book, scoped, intent,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(actual, expected);
    assert_eq!(h.head(), before);
    assert!(h.check(None).is_green());
}

#[test]
fn pending_and_resolution_posts_charge_gross_and_voids_do_not_refund() {
    let mut h = Harness::new(100, true, true);
    let cap = h.quota.clone();
    let mut hold = h.proposal(HOLDER, 30, b"hold");
    hold.class = EntryClass::PENDING;
    hold.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let held = h.post(hold, &cap).unwrap().entry_ref();
    let mut posts = h.proposal(HOLDER, 30, b"posts");
    posts.class = EntryClass::RESOLUTION;
    posts.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(held),
        disposition: Some(Disposition::Posts {
            source_ordinals: vec![0, 1],
        }),
    });
    h.post(posts, &cap).unwrap();
    assert_eq!((h.cell().gross_debits, h.cell().generation), (60, 2));
    let mut hold = h.proposal(HOLDER, 20, b"hold-void");
    hold.class = EntryClass::PENDING;
    hold.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let held = h.post(hold, &cap).unwrap().entry_ref();
    let mut void = h.proposal(HOLDER, 1, b"void");
    void.class = EntryClass::RESOLUTION;
    void.legs.clear();
    void.unit_totals.clear();
    void.control = Some(ControlPayload::ReservationRelease);
    void.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(held),
        disposition: Some(Disposition::Voids),
    });
    h.post(void, &cap).unwrap();
    assert_eq!((h.cell().gross_debits, h.cell().generation), (80, 3));
    assert_eq!(
        h.post(h.proposal(HOLDER, 21, b"no-refund"), &cap)
            .unwrap_err()
            .code,
        refusal::code::DAILY_CEILING
    );
    assert!(h.check(None).is_green());
}

#[test]
fn gross_debits_are_summed_within_an_entry_independently_of_per_leg_ceilings() {
    let mut h = Harness::new(50, true, true);
    let root = h.quota.clone();
    let cap = Capability::new(VId(31), Profile::Human, &[Op::Post], HOLDER)
        .unwrap()
        .holder_bound(possession_digest(&[56; 32]))
        .with_ceiling(h.usd, 40)
        .unwrap()
        .with_daily_total(h.usd, 50)
        .unwrap()
        .with_daily_root(root.commitment().unwrap())
        .unwrap();
    h.issue(&root, &cap, b"per-leg-and-daily").unwrap();
    let mut split = h.proposal(cap.holder(), 30, b"four-legs");
    split.legs.extend(split.legs.clone());
    split.unit_totals = EntryPayload::fold_unit_totals(&split.legs).unwrap();
    let at = h.head();
    assert_eq!(
        h.post(split, &cap).unwrap_err().code,
        refusal::code::DAILY_CEILING,
        "every leg is below40, but total gross debit60 exceeds50"
    );
    assert_eq!(h.head(), at);
    assert!(h.db.vertex(h.key().cell_vid()).unwrap().is_none());
    let mut fits = h.proposal(cap.holder(), 20, b"four-smaller-legs");
    fits.legs.extend(fits.legs.clone());
    fits.unit_totals = EntryPayload::fold_unit_totals(&fits.legs).unwrap();
    h.post(fits, &cap).unwrap();
    assert_eq!(h.cell().gross_debits, 40);
    assert!(h.check(None).is_green());
}

#[test]
fn planning_aborts_usage_batches_accumulate_and_conflicting_preparations_do_not_double_spend() {
    let mut h = Harness::new(100, true, true);
    let cap = h.quota.clone();
    let cx = h.cx();
    let intent = PostIntent::new(h.proposal(HOLDER, 60, b"dry-run"), Vec::new()).unwrap();
    let at = h.head();
    let plan = plan::plan_post(&mut h.db, &cx, &h.book, cap.clone(), intent)
        .unwrap()
        .unwrap();
    assert_eq!(h.head(), at);
    assert!(h.db.vertex(h.key().cell_vid()).unwrap().is_none());
    let p1 = h.prepare(h.proposal(HOLDER, 60, b"a"), &cap);
    let p2 = h.prepare(h.proposal(HOLDER, 60, b"b"), &cap);
    h.commit(p1).unwrap();
    assert_eq!(h.commit(p2).unwrap_err().exit, exit::CONFLICT);
    assert_eq!(h.cell().gross_debits, 60);
    let at = h.head();
    assert!(
        h.runtime
            .block_on(plan::commit_plan(&mut h.db, &cx, &h.book, cap, plan))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    assert_eq!(
        h.batch(b"overflow", &[20, 21]).unwrap_err().code,
        refusal::code::DAILY_CEILING
    );
    assert_eq!(
        h.head(),
        at,
        "later member refusal rolls back the whole batch"
    );
    assert_eq!(h.cell().gross_debits, 60);
    let batch = h.batch(b"fits", &[20, 20]).unwrap();
    assert_eq!(batch.entries.len(), 2);
    assert_eq!((h.cell().gross_debits, h.cell().generation), (100, 3));
    let head = h.head();
    assert!(h.batch(b"fits", &[20, 20]).unwrap().already_recorded);
    assert_eq!(h.head(), head);
    let report = h.check(None);
    assert!(report.is_green(), "{report:?}");
    assert_eq!(report.charges_checked, 3);
}

#[test]
fn replacement_plans_charge_both_members_atomically_and_never_charge_an_exact_retry() {
    let mut h = Harness::new(100, true, true);
    // The original uses an unbounded owner. The correction's daily quota
    // must charge both its reversal and corrected posting, with no refund.
    let original = h
        .post(h.proposal(OWNER, 30, b"pair-quota-original"), &owner())
        .unwrap()
        .entry_ref();
    let cap = h.quota.clone();
    let correction = |h: &Harness, corrected: i128| {
        let mut reversal = h.proposal(HOLDER, 30, b"pair-quota-reversal");
        reversal.class = EntryClass::REVERSAL;
        for leg in &mut reversal.legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
        }
        reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
        reversal.supersession = vec![fa_model::Supersession {
            target: original,
            kind: fa_model::SupersessionKind::Reverses,
            reason_code: 1,
        }];
        let mut replacement = h.proposal(HOLDER, corrected, b"pair-quota-replacement");
        replacement.class = EntryClass::REPLACEMENT;
        replacement.supersession = vec![fa_model::Supersession {
            target: original,
            kind: fa_model::SupersessionKind::Replaces,
            reason_code: 1,
        }];
        (
            PostIntent::new(reversal, Vec::new()).unwrap(),
            PostIntent::new(replacement, Vec::new()).unwrap(),
        )
    };
    let cx = h.cx();
    let at = h.head();
    let vertices = h.db.vertices().unwrap();
    let (reversal, replacement) = correction(&h, 71);
    let refusal = h
        .runtime
        .block_on(plan_replacement_with_history(
            &mut h.db,
            &cx,
            &h.book,
            cap.clone(),
            reversal,
            replacement,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, refusal::code::DAILY_CEILING, "{refusal}");
    assert_eq!(h.head(), at);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.db.vertex(h.key().cell_vid()).unwrap().is_none());

    let (reversal, replacement) = correction(&h, 70);
    let plan = h
        .runtime
        .block_on(plan_replacement_with_history(
            &mut h.db,
            &cx,
            &h.book,
            cap.clone(),
            reversal,
            replacement,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(h.head(), at);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    let (first, second) = h
        .runtime
        .block_on(commit_replacement_plan(
            &mut h.db,
            &cx,
            &h.book,
            cap.clone(),
            plan.clone(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(first.recorded_at(), second.recorded_at());
    assert_eq!(h.head().0, at.0 + 1);
    assert_eq!((h.cell().gross_debits, h.cell().generation), (100, 2));
    for (generation, entry, gross, total) in [
        (1, first.entry_ref(), 30, 30),
        (2, second.entry_ref(), 70, 100),
    ] {
        let row = h.db.vertex(h.key().debit_vid(generation)).unwrap().unwrap();
        let debit = UsageDebit::from_row(&row).unwrap();
        assert_eq!(row.created_at, first.recorded_at());
        assert_eq!(
            (debit.entry, debit.gross_debits, debit.total_gross_debits),
            (entry, gross, total)
        );
    }
    let report = h.check(None);
    assert!(report.is_green(), "{report:?}");
    assert_eq!((report.charges_checked, report.cells_checked), (2, 1));

    let at = h.head();
    let retry = h
        .runtime
        .block_on(commit_replacement_plan(
            &mut h.db,
            &cx,
            &h.book,
            cap.clone(),
            plan.clone(),
        ))
        .unwrap()
        .unwrap();
    assert!(matches!(retry.0, Posted::AlreadyRecorded { .. }));
    assert!(matches!(retry.1, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.0.entry_ref(), first.entry_ref());
    assert_eq!(retry.1.entry_ref(), second.entry_ref());
    assert_eq!(h.head(), at);
    assert_eq!((h.cell().gross_debits, h.cell().generation), (100, 2));

    let request = RevocationRequest {
        capability: owner(),
        revoked: cap.commitment().unwrap(),
        effective_date: day(),
        idempotency_key: b"revoke-pair-quota".to_vec(),
        description: seal(&h.book, "revoke pair quota"),
    };
    h.runtime
        .block_on(revoke_capability(&mut h.db, &cx, &h.book, request))
        .unwrap()
        .unwrap();
    let at = h.head();
    let refusal = h
        .runtime
        .block_on(commit_replacement_plan(&mut h.db, &cx, &h.book, cap, plan))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal.code, "FA-REF-023",
        "current revocation precedes recorded outcomes"
    );
    assert_eq!(h.head(), at);
    assert_eq!((h.cell().gross_debits, h.cell().generation), (100, 2));
}

#[test]
fn a_committed_plan_consumes_once_and_tick_or_root_revocation_invalidates_prepared_usage() {
    let mut h = Harness::new(100, true, true);
    let cap = h.quota.clone();
    let cx = h.cx();
    let intent = PostIntent::new(h.proposal(HOLDER, 40, b"planned"), Vec::new()).unwrap();
    let plan = h
        .runtime
        .block_on(plan::plan_post_with_history(
            &mut h.db,
            &cx,
            &h.book,
            cap.clone(),
            intent,
        ))
        .unwrap()
        .unwrap();
    assert!(h.db.vertex(h.key().cell_vid()).unwrap().is_none());
    let first = h
        .runtime
        .block_on(plan::commit_plan(
            &mut h.db,
            &cx,
            &h.book,
            cap.clone(),
            plan.clone(),
        ))
        .unwrap()
        .unwrap();
    let at = h.head();
    let retry = h
        .runtime
        .block_on(plan::commit_plan(&mut h.db, &cx, &h.book, cap, plan))
        .unwrap()
        .unwrap();
    assert_eq!(first.entry_ref(), retry.entry_ref());
    assert_eq!(h.head(), at);
    assert_eq!((h.cell().gross_debits, h.cell().generation), (40, 1));
    assert!(h.check(None).is_green());
    for revoke in [false, true] {
        let mut h = Harness::new(100, true, true);
        let cap = h.quota.clone();
        let prepared = h.prepare(h.proposal(HOLDER, 60, b"prepared"), &cap);
        if revoke {
            let request = RevocationRequest {
                capability: owner(),
                revoked: cap.commitment().unwrap(),
                effective_date: day(),
                idempotency_key: b"revoke-between-prepare-commit".to_vec(),
                description: seal(&h.book, "revoke"),
            };
            let cx = h.cx();
            h.runtime
                .block_on(revoke_capability(&mut h.db, &cx, &h.book, request))
                .unwrap()
                .unwrap();
        } else {
            h.tick(
                u64::try_from(day().0).unwrap() * NS_PER_DAY + 2_000_000_000,
                b"tick-between-prepare-commit",
            );
        }
        let before = h.head();
        assert_eq!(h.commit(prepared).unwrap_err().exit, exit::CONFLICT);
        assert_eq!(h.head(), before);
        assert!(h.db.vertex(h.key().cell_vid()).unwrap().is_none());
    }
}

#[test]
fn calendar_and_committed_tick_select_the_day_independently_of_effective_date() {
    for (utc, tick, code) in [(false, true, "FA-REF-102"), (true, false, "FA-REF-095")] {
        let mut h = Harness::new(100, utc, tick);
        let cap = h.quota.clone();
        let at = h.head();
        assert_eq!(
            h.post(h.proposal(HOLDER, 1, b"no-clock"), &cap)
                .unwrap_err()
                .code,
            code
        );
        assert_eq!(h.head(), at);
    }
    let mut h = Harness::new(100, true, true);
    let cap = h.quota.clone();
    let old = h.proposal(HOLDER, 100, b"old-day");
    h.post(old.clone(), &cap).unwrap();
    let tomorrow = (u64::try_from(day().0).unwrap() + 1) * NS_PER_DAY + 1_000_000_000;
    h.tick_with_status(tomorrow, b"next-day-uncorroborated", false);
    let next = h.proposal(HOLDER, 100, b"new-day-backdated");
    assert_eq!(h.post(next.clone(), &cap).unwrap_err().code, "FA-REF-144");
    h.tick(tomorrow + 1_000_000_000, b"next-day");
    h.post(old, &cap).unwrap();
    h.post(next, &cap).unwrap();
    let report = h.check(None);
    assert!(report.is_green(), "{report:?}");
    assert_eq!((report.charges_checked, report.cells_checked), (2, 2));
}

#[test]
fn restored_cells_and_deleted_or_relabelled_receipts_never_restore_capacity() {
    for attack in 0..6 {
        let mut h = Harness::new(100, true, true);
        let cap = h.quota.clone();
        h.post(h.proposal(HOLDER, 60, b"first"), &cap).unwrap();
        let old = h.cell();
        let intact = h.head();
        if attack == 0 {
            h.post(h.proposal(HOLDER, 40, b"second"), &cap).unwrap();
        }
        let mut damage = WriteBatch::new(relation::HAS_LEG);
        match attack {
            0 => {
                for (key, value) in old.properties().unwrap() {
                    damage.set_vertex_property(old.key.cell_vid(), key, Some(value));
                }
            }
            1 => {
                damage.delete_vertex(old.key.cell_vid());
            }
            2 => {
                damage.delete_vertex(old.key.cell_vid());
                damage.delete_vertex(old.key.debit_vid(1));
            }
            3 => {
                damage.delete_vertex(old.key.cell_vid());
                damage.set_vertex_label(old.key.debit_vid(1), label::USAGE_DEBIT, false);
                damage.set_vertex_label(old.key.debit_vid(1), label::DOCUMENT, true);
            }
            4 => {
                damage.set_vertex_label(old.key.cell_vid(), label::USAGE_CELL, false);
                damage.set_vertex_label(old.key.debit_vid(1), label::USAGE_DEBIT, false);
            }
            _ => {
                let row = h.db.vertex(old.key.debit_vid(1)).unwrap().unwrap();
                let mut receipt = UsageDebit::from_row(&row).unwrap();
                receipt.generation = 9;
                receipt.previous_gross_debits = 1;
                receipt.gross_debits = 1;
                receipt.total_gross_debits = 2;
                let forged = UsageCell {
                    key: old.key,
                    generation: 9,
                    gross_debits: 2,
                };
                for (key, value) in forged.properties().unwrap() {
                    damage.set_vertex_property(old.key.cell_vid(), key, Some(value));
                }
                damage.create_vertex(
                    receipt.vid(),
                    vec![label::USAGE_DEBIT],
                    receipt.properties().unwrap(),
                );
            }
        }
        h.write(damage);
        let before = h.head();
        let report = h.check(None);
        assert!(!report.is_green(), "attack {attack}: {report:?}");
        assert!(
            h.check(Some(intact)).is_green(),
            "later damage cannot rewrite an earlier checked prefix"
        );
        assert_eq!(h.head(), before, "verification is read only");
        let refusal = h
            .post(h.proposal(HOLDER, 1, b"try-reset"), &cap)
            .unwrap_err();
        assert_eq!(
            refusal.code,
            refusal::code::USAGE_MISMATCH,
            "attack {attack}: {refusal}"
        );
        assert_eq!(h.head(), before, "damaged state cannot publish a spend");
    }
}

#[test]
fn jointly_rewriting_the_source_receipt_and_cell_cannot_restore_spent_capacity() {
    let mut h = Harness::new(100, true, true);
    let cap = h.quota.clone();
    let source = h
        .post(h.proposal(HOLDER, 60, b"original-sixty"), &cap)
        .unwrap()
        .entry_ref();
    let intact = h.head();
    let source_row = h.db.vertex(source.vid).unwrap().unwrap();
    let original = fa_model::Entry::decode(
        &rows::bytes(
            &source_row,
            fa_model::symbols::property::FA_PAYLOAD,
            "source entry",
        )
        .unwrap(),
    )
    .unwrap();
    let mut proposal = original.proposal;
    for leg in &mut proposal.legs {
        leg.amount.mantissa = 1;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let rewritten = proposal
        .seal(original.approvals, original.plan_certificate)
        .unwrap();
    let old = h.cell();
    let mut receipt =
        UsageDebit::from_row(&h.db.vertex(old.key.debit_vid(1)).unwrap().unwrap()).unwrap();
    receipt.entry = rewritten.entry_ref(source.vid);
    receipt.gross_debits = 1;
    receipt.total_gross_debits = 1;
    let cell = UsageCell {
        gross_debits: 1,
        ..old
    };
    let mut damage = WriteBatch::new(relation::HAS_LEG);
    for (key, value) in fa_model::entry_mirrors(&rewritten).unwrap() {
        damage.set_vertex_property(source.vid, key, Some(value));
    }
    for (key, value) in receipt.properties().unwrap() {
        damage.set_vertex_property(receipt.vid(), key, Some(value));
    }
    for (key, value) in cell.properties().unwrap() {
        damage.set_vertex_property(cell.key.cell_vid(), key, Some(value));
    }
    h.write(damage);
    let before = h.head();
    let source_row = h.db.vertex(source.vid).unwrap().unwrap();
    let receipt_row = h.db.vertex(receipt.vid()).unwrap().unwrap();
    assert_eq!(source_row.created_at, before);
    assert_eq!(receipt_row.created_at, before);
    assert_ne!(before, intact);
    assert_eq!(UsageDebit::from_row(&receipt_row).unwrap(), receipt);
    assert_eq!(h.cell(), cell);
    assert!(h.check(Some(intact)).is_green());
    assert!(!h.check(None).is_green());
    // The rewritten rows agree on a version timestamp, digest and total1.
    // Only their native births expose the original60 before this new60.
    let refused = h
        .post(h.proposal(HOLDER, 60, b"attempt-second-sixty"), &cap)
        .unwrap_err();
    assert_eq!(refused.code, refusal::code::USAGE_MISMATCH);
    assert!(refused.message.contains("native births"));
    assert_eq!(h.head(), before);
    assert_eq!(h.cell(), cell);
}
