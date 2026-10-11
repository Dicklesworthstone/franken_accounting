//! The Genesis behaviours of bead fa-op5, against the real in-memory
//! substrate: a balanced entry commits with its mirrors and edges in one
//! transaction; an unbalanced one is refused (exit 3, FA-REF-001); a post
//! into a Closed period is refused (exit 7, the matrix cell cited) while a
//! Reversal under `post_closed` is admitted; an identical retry is the
//! recorded outcome and a changed one is a conflict (exit 6); a period
//! transition is a control record with no legs (fa-bvx); unsupported classes
//! are refused rather than admitted; the two-phase pair (fa-rqe, plan §5.4)
//! reserves, posts a sub-vector or voids, exactly once per pending entry.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{
    Document, DocumentAdded, EvidenceAttached, SupplementalEvidence, add_document, attach_evidence,
    document_vid, read_document, supplements_of,
};
use fa_journal::post::read_entry;
use fa_journal::rows::{applied, book_root, edge_id, leg_vid, resolution_vid, reversal_vid};
use fa_journal::*;
use fa_model::symbols::{property, relation};
use fa_model::{
    ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable,
    EvidenceRef, Id128, LegPayload, Oid, Pending, SealKey, Settlement, Supersession,
    SupersessionKind, SymbolTable, account_vid, entry_vid, period_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, VId};

const PRINCIPAL: VId = VId(7);

/// Registry tags (`evidence_policy.toml`) the evidence tests name.
const INVOICE: u8 = 1;
const RECEIPT: u8 = 3;
const HUMAN_UPLOAD: u8 = 3;
const AGENT_UPLOAD: u8 = 4;
const ROLE_SOURCE: u8 = 1;

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    rent: VId,
    assets: VId,
    receivable: VId,
    revenue: VId,
    march: String,
    april: String,
    /// A real source document recorded at setup; every proposal cites it
    /// (FA-INV-05 `evidence-minimum`).
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn day(&self) -> DateDay {
        DateDay::from_ymd(2026, 3, 15).unwrap()
    }

    fn proposal(&self, legs: Vec<LegPayload>, key: &[u8], class: EntryClass) -> EntryPayload {
        let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: self.day(),
            document_date: None,
            description: Erasable::seal(
                &"March rent".to_string(),
                None,
                &self.book.seal_key,
                [1; 32],
                [2; 24],
            ),
            effective_period: None,
            legs,
            control: None,
            unit_totals,
            base_totals: None,
            idempotency_key: key.to_vec(),
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

    fn rent_legs(&self, cents: i128) -> Vec<LegPayload> {
        vec![
            LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, cents)),
        ]
    }

    fn reversal_of(&self, target: EntryRef, cents: i128, key: &[u8]) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Credit, self.rent, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Debit, self.cash, Amount::new(self.usd, cents)),
        ];
        let mut p = self.proposal(legs, key, EntryClass::REVERSAL);
        p.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        p
    }

    /// A hold: the legs are reserved, never posted (plan §5.4).
    fn pending(&self, legs: Vec<LegPayload>, key: &[u8]) -> EntryPayload {
        let mut p = self.proposal(legs, key, EntryClass::PENDING);
        p.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        p
    }

    /// `Resolution(Posts)`: the posted sub-vector with its source ordinals.
    fn resolution_posts(
        &self,
        target: EntryRef,
        legs: Vec<LegPayload>,
        source_ordinals: Vec<u16>,
        key: &[u8],
    ) -> EntryPayload {
        let mut p = self.proposal(legs, key, EntryClass::RESOLUTION);
        p.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Posts { source_ordinals }),
        });
        p
    }

    /// `Resolution(Voids)`: no legs, the `ReservationRelease` control.
    fn resolution_voids(&self, target: EntryRef, key: &[u8]) -> EntryPayload {
        let mut p = self.proposal(Vec::new(), key, EntryClass::RESOLUTION);
        p.control = Some(ControlPayload::ReservationRelease);
        p.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Voids),
        });
        p
    }

    /// An invoice: Dr receivable / Cr revenue.
    fn invoice(&self, cents: i128, key: &[u8]) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Debit, self.receivable, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.revenue, Amount::new(self.usd, cents)),
        ];
        self.proposal(legs, key, EntryClass::ORIGINAL)
    }

    /// A receipt: Dr cash / Cr receivable, the credit leg applying `settles`.
    fn receipt(&self, cents: i128, settles: Vec<Settlement>, key: &[u8]) -> EntryPayload {
        let mut credit =
            LegPayload::simple(Side::Credit, self.receivable, Amount::new(self.usd, cents));
        credit.settles = settles;
        let legs = vec![
            LegPayload::simple(Side::Debit, self.cash, Amount::new(self.usd, cents)),
            credit,
        ];
        self.proposal(legs, key, EntryClass::ORIGINAL)
    }

    fn applied_to(&self, entry: VId, ordinal: u16) -> i128 {
        applied(
            &self
                .db
                .vertex(leg_vid(entry, ordinal))
                .unwrap()
                .expect("leg row"),
        )
        .unwrap()
        .unwrap_or(0)
    }

    /// The exact side-swap of a posted entry, read back from the book.
    fn reversal_of_entry(&self, target: EntryRef, key: &[u8]) -> EntryPayload {
        let (original, _) = read_entry(&self.db, target.vid)
            .unwrap()
            .expect("target row");
        let legs = original
            .proposal
            .legs
            .iter()
            .map(|l| {
                LegPayload::simple(
                    if l.side == Side::Debit {
                        Side::Credit
                    } else {
                        Side::Debit
                    },
                    l.account_ref,
                    l.amount,
                )
            })
            .collect();
        let mut p = self.proposal(legs, key, EntryClass::REVERSAL);
        p.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        p
    }

    fn request(&self, proposal: EntryPayload, ops: &[&str]) -> PostRequest {
        // Some tests post as another principal; the capability is that
        // principal's own (fa-llx: a capability authorizes its holder only).
        let holder = proposal.principal_ref;
        PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(holder, ops).expect("registered ops"),
        }
    }

    fn document(&self, kind: u8, grade: u8, bytes: &[u8]) -> Document {
        Document {
            book_id: self.book.book_id,
            kind,
            mime: "text/plain".into(),
            grade,
            retrieved_by: PRINCIPAL,
            bytes: bytes.to_vec(),
        }
    }

    fn add_document(&mut self, doc: &Document) -> Result<DocumentAdded, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { add_document(db, &ctx, book, doc).await })
            .expect("kernel")
    }

    fn post(&mut self, req: PostRequest) -> Result<Posted, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
    }

    fn transition(
        &mut self,
        code: &str,
        t: PeriodTransition,
        key: &[u8],
    ) -> Result<Transitioned, Refusal> {
        let day = DateDay::from_ymd(2026, 3, 1).unwrap();
        let seal_key = self.book.seal_key.clone();
        let description =
            || Erasable::seal(&"period".to_string(), None, &seal_key, [3; 32], [4; 24]);
        // Lock and Reopen are dual-controlled (sod_policy.toml, fa-llx): a
        // second Human approves exactly the proposal this transition commits.
        // An unknown period has no row and no proposal to approve.
        let from = self
            .db
            .vertex(period_vid("cal", code))
            .unwrap()
            .map(|row| PeriodRow::decode(&row).unwrap().state);
        let legal = from.and_then(|from| {
            fa_time::period::transition(from, t)
                .ok()
                .map(|to| (from, to))
        });
        let approvals = match (t, legal) {
            (PeriodTransition::Lock | PeriodTransition::Reopen { .. }, Some((from, to))) => {
                let digest = transition_proposal(
                    &self.book,
                    code,
                    from,
                    to,
                    PRINCIPAL,
                    1,
                    day,
                    key,
                    description(),
                )
                .proposal_digest()
                .expect("digest");
                vec![self.approve_transition(digest)]
            }
            _ => Vec::new(),
        };
        let description = description();
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
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
                    key,
                    description,
                    &Capability::embedded(PRINCIPAL, &["close", "reopen"]).expect("ops"),
                    &approvals,
                )
                .await
            })
            .expect("kernel")
    }

    /// A Human approver other than the preparer records an approval of `digest`.
    fn approve_transition(&mut self, digest: [u8; 32]) -> fa_model::ApprovalRef {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = ApprovalRequest {
            capability: Capability::embedded(VId(70), &["approve"]).expect("approve"),
            approved_proposal_digest: digest,
            role: 0,
        };
        self.runtime
            .block_on(async move { record_approval(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("approval recorded")
            .approval()
    }

    fn period_state(&self, code: &str) -> PeriodState {
        PeriodRow::decode(
            &self
                .db
                .vertex(period_vid("cal", code))
                .unwrap()
                .expect("period row"),
        )
        .unwrap()
        .state
    }
}

/// The handle and period of a fresh commit; `None` for a recorded outcome.
fn committed(p: &Posted) -> Option<(EntryRef, String)> {
    match p {
        Posted::Committed {
            entry_ref, period, ..
        } => Some((*entry_ref, period.clone())),
        Posted::AlreadyRecorded { .. } => None,
    }
}

fn harness() -> Harness {
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
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([9; 16]);
    let spec = BookSpec {
        book_id,
        name: "Test Co".into(),
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
        calendar,
        units,
        seal_key: SealKey([0x11; 32]),
        symbols,
    };

    let chart = vec![
        AccountSpec {
            code: "1".into(),
            name: "Assets".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: false,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: Some("1".into()),
            limit: None,
        },
        AccountSpec {
            code: "6000".into(),
            name: "Rent".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "1200".into(),
            name: "Receivable".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: Some("1".into()),
            limit: None,
        },
        AccountSpec {
            code: "4000".into(),
            name: "Revenue".into(),
            account_type: 4,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    ];
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    let installed = runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PRINCIPAL,
                day,
                b"chart-1",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
            )
            .await
        })
        .expect("kernel")
        .expect("chart installs");
    assert_eq!(installed.accounts, 5);
    assert_eq!(
        fa_journal::genesis::list_accounts(&db)
            .unwrap()
            .iter()
            .map(|a| a.code.as_str())
            .collect::<Vec<_>>(),
        vec!["1", "1000", "1200", "4000", "6000"]
    );

    let (_, periods) = runtime
        .block_on(async { create_periods(&mut db, &ctx, &book, 2026).await })
        .expect("periods");
    let march = periods
        .iter()
        .find(|p| {
            p.contains(DateDay::from_ymd(2026, 3, 15).unwrap()) && p.kind == PeriodKind::Normal
        })
        .unwrap()
        .code
        .clone();
    let april = periods
        .iter()
        .find(|p| {
            p.contains(DateDay::from_ymd(2026, 4, 15).unwrap()) && p.kind == PeriodKind::Normal
        })
        .unwrap()
        .code
        .clone();

    let mut h = Harness {
        runtime,
        root,
        db,
        cash: account_vid(book_id, "1000"),
        rent: account_vid(book_id, "6000"),
        assets: account_vid(book_id, "1"),
        receivable: account_vid(book_id, "1200"),
        revenue: account_vid(book_id, "4000"),
        book,
        usd,
        march: march.clone(),
        april,
        evidence: Vec::new(),
    };
    let source = h.document(
        INVOICE,
        HUMAN_UPLOAD,
        b"INVOICE 2026-0315 Test Co: March rent and services (fixture source document)",
    );
    h.add_document(&source)
        .expect("the fixture document is admitted");
    h.evidence = vec![source.evidence_ref(ROLE_SOURCE)];
    h.transition(&march, PeriodTransition::Open, b"open-march")
        .expect("march opens");
    h
}

#[test]
fn balanced_entry_commits_with_mirrors_and_edges_in_one_transaction() {
    let mut h = harness();
    let proposal = h.proposal(h.rent_legs(120_000), b"inv-1", EntryClass::ORIGINAL);
    let expected = proposal.clone().seal(Vec::new(), None).unwrap();
    let posted = h.post(h.request(proposal, &["post"])).expect("admitted");
    assert!(
        matches!(posted, Posted::Committed { .. }),
        "expected a fresh commit, got {posted:?}"
    );
    let entry_ref = posted.entry_ref();
    let recorded_at = posted.recorded_at();
    assert_eq!(posted.period(), Some(h.march.as_str()));
    assert_eq!(entry_ref.entry_digest, expected.entry_digest);
    // Recorded time is the substrate's commit sequence, not anything we supplied.
    let (back, created_at) = read_entry(&h.db, entry_ref.vid)
        .unwrap()
        .expect("entry row");
    assert_eq!(back, expected);
    assert_eq!(created_at, recorded_at);
    for (i, leg) in expected.proposal.legs.iter().enumerate() {
        let row =
            h.db.vertex(leg_vid(entry_ref.vid, i as u16))
                .unwrap()
                .expect("leg row");
        let side = row
            .props
            .iter()
            .find(|(k, _)| *k == property::SIDE)
            .map(|(_, v)| v.clone());
        assert_eq!(
            side,
            Some(CanonicalScalar::Int(if leg.side == Side::Debit {
                0
            } else {
                1
            }))
        );
        assert!(
            row.props
                .iter()
                .any(|(k, v)| *k == property::AMOUNT && matches!(v, CanonicalScalar::Decimal(_)))
        );
        assert!(
            h.db.edge(edge_id(relation::HAS_LEG, entry_ref.vid, row.vid))
                .unwrap()
                .is_some()
        );
        assert!(
            h.db.edge(edge_id(relation::POSTS_TO, row.vid, leg.account_ref))
                .unwrap()
                .is_some()
        );
    }
    assert!(
        h.db.edge(edge_id(
            relation::IN_PERIOD,
            entry_ref.vid,
            period_vid("cal", &h.march)
        ))
        .unwrap()
        .is_some()
    );
    assert!(h.db.vertex(book_root()).unwrap().is_some());
    assert_eq!(
        fa_journal::genesis::read_book_spec(&h.db)
            .unwrap()
            .map(|s| s.name),
        Some("Test Co".to_string())
    );
}

#[test]
fn unbalanced_entry_is_refused_with_exit_3_and_nothing_written() {
    let mut h = harness();
    let legs = vec![
        LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 120_000)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 119_999)),
    ];
    let proposal = h.proposal(legs, b"inv-2", EntryClass::ORIGINAL);
    let r = h.post(h.request(proposal, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-001", exit::REFUSAL));
    assert!(r.message.contains("USD"), "{}", r.message);
    // Rendered at the unit's scale: the one-cent gap, never "1 USD".
    assert!(r.fix.contains("credit leg of 0.01 USD"), "{}", r.fix);
    assert!(
        r.message
            .contains("debits 1200.00 USD ≠ credits 1199.99 USD (difference 0.01 USD)"),
        "{}",
        r.message
    );
    let vid = fa_model::entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"inv-2");
    assert!(h.db.vertex(vid).unwrap().is_none());
}

#[test]
fn closed_period_refuses_originals_and_admits_an_exact_reversal_under_post_closed() {
    let mut h = harness();
    let march = h.march.clone();
    let original = h
        .post(h.request(
            h.proposal(h.rent_legs(5_000), b"orig", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("admitted")
        .entry_ref();
    h.transition(&march, PeriodTransition::SoftClose, b"sc")
        .expect("soft close");
    let t = h
        .transition(&march, PeriodTransition::Close, b"c")
        .expect("close");
    assert_eq!(
        (t.from, t.to),
        (PeriodState::SoftClosed, PeriodState::Closed)
    );

    let late = h.proposal(h.rent_legs(5_000), b"late-1", EntryClass::ORIGINAL);
    let r = h
        .post(h.request(late, &["post", "post_closed"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-010", exit::SAFETY));
    assert!(
        r.cite.contains("Original") && r.cite.contains("Closed"),
        "{}",
        r.cite
    );

    // Reversal in a Closed period: needs post_closed.
    let reversal = h.reversal_of(original, 5_000, b"rev-1");
    let r = h.post(h.request(reversal.clone(), &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("post_closed"), "{}", r.message);
    let posted = h
        .post(h.request(reversal.clone(), &["post", "post_closed"]))
        .expect("admitted");
    assert!(matches!(posted, Posted::Committed { .. }));
    assert_eq!(
        posted.entry_ref().vid,
        reversal_vid(original.vid),
        "identity derived from the target"
    );
    assert!(
        h.db.edge(edge_id(
            relation::SUPERSEDES,
            posted.entry_ref().vid,
            original.vid
        ))
        .unwrap()
        .is_some()
    );

    // The identical reversal again: recorded. A different reversal of the same target: conflict.
    let again = h
        .post(h.request(reversal, &["post", "post_closed"]))
        .expect("recorded");
    assert!(matches!(again, Posted::AlreadyRecorded { .. }));
    let other = h.reversal_of(original, 5_000, b"rev-2");
    let r = h
        .post(h.request(other, &["post", "post_closed"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-052", exit::CONFLICT));
}

#[test]
fn reversal_law_requires_a_witnessed_target_and_the_exact_side_swap() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(h.rent_legs(700), b"o", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("admitted")
        .entry_ref();
    // Wrong amount: not the side-swap.
    let r = h
        .post(h.request(h.reversal_of(original, 701, b"r1"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-051", exit::REFUSAL));
    // Stale handle: digest mismatch.
    let stale = EntryRef {
        vid: original.vid,
        entry_digest: [0; 32],
    };
    let r = h
        .post(h.request(h.reversal_of(stale, 700, b"r2"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-050", exit::REFUSAL));
    // No target at all.
    let mut none = h.reversal_of(original, 700, b"r3");
    none.supersession.clear();
    let r = h.post(h.request(none, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-050", exit::REFUSAL));
    // Unknown target.
    let ghost = EntryRef {
        vid: VId(123_456),
        entry_digest: [0; 32],
    };
    let r = h
        .post(h.request(h.reversal_of(ghost, 700, b"r4"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-050", exit::REFUSAL));
    // The exact swap posts, and the fold nets the pair to zero.
    let posted = h
        .post(h.request(h.reversal_of(original, 700, b"r5"), &["post"]))
        .expect("admitted");
    assert!(matches!(posted, Posted::Committed { .. }));
}

#[test]
fn a_period_never_opened_refuses_with_the_open_fix() {
    let mut h = harness();
    let mut proposal = h.proposal(h.rent_legs(100), b"apr-1", EntryClass::ORIGINAL);
    proposal.effective_date = DateDay::from_ymd(2026, 4, 2).unwrap();
    let r = h.post(h.request(proposal, &["post"])).unwrap_err();
    assert_eq!(r.code, "FA-REF-010");
    assert!(r.cite.contains("Future"), "{}", r.cite);
    assert!(
        r.fix.contains(&format!("fa period open {}", h.april)),
        "{}",
        r.fix
    );
}

#[test]
fn identical_retry_is_recorded_and_a_changed_retry_is_a_conflict() {
    let mut h = harness();
    let p = h.proposal(h.rent_legs(100), b"dup", EntryClass::ORIGINAL);
    let first = h.post(h.request(p.clone(), &["post"])).expect("first");
    assert!(matches!(first, Posted::Committed { .. }), "{first:?}");
    // Same bytes: the recorded outcome, nothing new written.
    let second = h.post(h.request(p, &["post"])).expect("second");
    assert!(
        matches!(second, Posted::AlreadyRecorded { .. }),
        "{second:?}"
    );
    assert_eq!(first.entry_ref(), second.entry_ref());
    assert_eq!(first.recorded_at(), second.recorded_at());
    // Same key, different amount: a conflict, exit 6, and the journal is unchanged.
    let changed = h.proposal(h.rent_legs(999), b"dup", EntryClass::ORIGINAL);
    let r = h.post(h.request(changed, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT));
    assert!(
        r.message
            .contains(&format!("{:032x}", first.entry_ref().vid.0)),
        "{}",
        r.message
    );
    let (back, _) = read_entry(&h.db, first.entry_ref().vid)
        .unwrap()
        .expect("row");
    assert_eq!(
        back.proposal.legs[0].amount.mantissa, 100,
        "the first intent's amount is what was recorded"
    );
}

#[test]
fn summary_account_unknown_account_and_unit_policy_are_refused() {
    let mut h = harness();
    let legs = vec![
        LegPayload::simple(Side::Debit, h.assets, Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 100)),
    ];
    let r = h
        .post(h.request(h.proposal(legs, b"s1", EntryClass::ORIGINAL), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-002", exit::REFUSAL));

    let legs = vec![
        LegPayload::simple(Side::Debit, VId(424242), Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 100)),
    ];
    let r = h
        .post(h.request(h.proposal(legs, b"s2", EntryClass::ORIGINAL), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-004", exit::REFUSAL));

    let eur = h.book.units.lookup("EUR").unwrap();
    let legs = vec![
        LegPayload::simple(Side::Debit, h.rent, Amount::new(eur, 100)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(eur, 100)),
    ];
    let r = h
        .post(h.request(h.proposal(legs, b"s3", EntryClass::ORIGINAL), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-003", exit::REFUSAL));
    assert!(r.message.contains("EUR"), "{}", r.message);
}

#[test]
fn control_classes_unsupported_classes_and_structure_errors_are_refused_by_kind() {
    let mut h = harness();
    let mut p = h.proposal(Vec::new(), b"ctl", EntryClass::PERIOD_CONTROL);
    p.control = Some(ControlPayload::TimeTick {
        observed_utc_ns: 1,
        source: 0,
        monotonic_ok: true,
    });
    let r = h.post(h.request(p, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-101", exit::USAGE));

    let one_leg = h.proposal(
        vec![LegPayload::simple(
            Side::Debit,
            h.rent,
            Amount::new(h.usd, 1),
        )],
        b"one",
        EntryClass::ORIGINAL,
    );
    let r = h.post(h.request(one_leg, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE));

    // A registered class this slice does not enforce is refused, naming its bead.
    for class in [
        EntryClass::REPLACEMENT,
        EntryClass::CLOSING,
        EntryClass::RESTATEMENT,
    ] {
        let r = h
            .post(h.request(
                h.proposal(h.rent_legs(1), b"cls", class),
                &["post", "post_closed", "restate", "migrate"],
            ))
            .unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-102", exit::REFUSAL), "{class:?}");
        assert!(
            r.fix.contains("fa-") || r.fix.contains("plan §"),
            "{}",
            r.fix
        );
    }
    // Migration is enforced (fa-xo0): an entry naming no run is outside the
    // run law, refused before any read.
    let r = h
        .post(h.request(
            h.proposal(h.rent_legs(1), b"mig", EntryClass::MIGRATION),
            &["post", "migrate"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-132", exit::REFUSAL), "{r}");
    assert!(r.cite.contains("plan §8.6"), "{}", r.cite);
    // Adjusting is a plain posting class and is admitted.
    let posted = h
        .post(h.request(
            h.proposal(h.rent_legs(2), b"adj", EntryClass::ADJUSTING),
            &["post"],
        ))
        .expect("admitted");
    assert!(matches!(posted, Posted::Committed { .. }));
}

#[test]
fn period_transition_is_a_control_record_with_no_legs_and_moves_the_state_mirror() {
    let mut h = harness();
    let april = h.april.clone();
    let t = h
        .transition(&april, PeriodTransition::Open, b"open-april")
        .expect("opens");
    assert_eq!((t.from, t.to), (PeriodState::Future, PeriodState::Open));
    let (entry, created_at) = read_entry(&h.db, t.control_entry)
        .unwrap()
        .expect("control entry");
    assert_eq!(created_at, t.recorded_at);
    assert!(entry.proposal.legs.is_empty());
    assert_eq!(entry.proposal.class, EntryClass::PERIOD_CONTROL);
    assert!(matches!(
        entry.proposal.control,
        Some(ControlPayload::PeriodTransition { from, to, ref period_ref, .. }) if from == PeriodState::Future.tag() && to == PeriodState::Open.tag() && period_ref.code == april
    ));
    assert_eq!(h.period_state(&april), PeriodState::Open);
    assert_eq!(
        fa_journal::genesis::list_periods(&h.db)
            .unwrap()
            .iter()
            .filter(|p| p.state == PeriodState::Open)
            .count(),
        2
    );

    let r = h
        .transition(&april, PeriodTransition::Lock, b"lock-april")
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-040", exit::SAFETY));
    assert_eq!(h.period_state(&april), PeriodState::Open);
    let r = h
        .transition("FY2031-P01", PeriodTransition::Open, b"nope")
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-021", exit::SAFETY));
}

#[test]
fn equivalence_is_plaintext_level_and_never_crosses_principals() {
    let mut h = harness();
    let p = h.proposal(h.rent_legs(300), b"salted", EntryClass::ORIGINAL);
    let first = h.post(h.request(p.clone(), &["post"])).expect("first");
    // Same content, freshly sealed description (different salt and nonce):
    // the prepared bytes differ, the semantic transcript does not → recorded.
    let mut resealed = p.clone();
    resealed.description = Erasable::seal(
        &"March rent".to_string(),
        None,
        &h.book.seal_key,
        [9; 32],
        [8; 24],
    );
    assert_ne!(
        resealed.proposal_digest().unwrap(),
        p.proposal_digest().unwrap()
    );
    let again = h.post(h.request(resealed, &["post"])).expect("recorded");
    assert!(matches!(again, Posted::AlreadyRecorded { .. }), "{again:?}");
    assert_eq!(again.entry_ref(), first.entry_ref());
    // A different description under the same key: conflict.
    let mut other = p.clone();
    other.description = Erasable::seal(
        &"Not rent".to_string(),
        None,
        &h.book.seal_key,
        [9; 32],
        [8; 24],
    );
    let r = h.post(h.request(other, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT));
    // Another principal reversing an already-reversed target is a conflict
    // even with identical content: no equality oracle across principals.
    let original = first.entry_ref();
    let rev = h.reversal_of(original, 300, b"r-a");
    h.post(h.request(rev.clone(), &["post"])).expect("reversal");
    let mut foreign = rev.clone();
    foreign.principal_ref = VId(99);
    let req = h.request(foreign, &["post"]);
    let r = h.post(req).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-052", exit::CONFLICT));
}

#[test]
fn a_hold_reserves_and_its_one_resolution_posts_a_sub_vector_drawn_leg_by_leg() {
    let mut h = harness();
    // Reserve 80.00: Dr rent / Cr cash. Nothing is posted; the legs exist
    // as reserved legs with their account edges, in March.
    let hold = h
        .post(h.request(h.pending(h.rent_legs(8_000), b"hold-1"), &["post"]))
        .expect("admitted");
    let (hold_ref, period) = committed(&hold).expect("a fresh hold commits");
    assert_eq!(period, h.march);
    let (stored, _) = read_entry(&h.db, hold_ref.vid).unwrap().expect("hold row");
    assert_eq!(stored.proposal.class, EntryClass::PENDING);
    for ordinal in 0..2u16 {
        assert!(
            h.db.vertex(leg_vid(hold_ref.vid, ordinal))
                .unwrap()
                .is_some()
        );
    }

    // The sub-vector law: wrong ordinal, wrong account, more than reserved,
    // and an unbalanced sub-vector are refused by kind; nothing is written.
    let sixty = h.rent_legs(6_000);
    let r = h
        .post(h.request(
            h.resolution_posts(hold_ref, sixty.clone(), vec![0, 5], b"res-bad-1"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-061", exit::REFUSAL));
    let swapped_accounts = vec![
        LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, 6_000)),
        LegPayload::simple(Side::Credit, h.rent, Amount::new(h.usd, 6_000)),
    ];
    let r = h
        .post(h.request(
            h.resolution_posts(hold_ref, swapped_accounts, vec![0, 1], b"res-bad-2"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-061", exit::REFUSAL));
    let r = h
        .post(h.request(
            h.resolution_posts(hold_ref, h.rent_legs(8_001), vec![0, 1], b"res-bad-3"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-061", exit::REFUSAL));
    assert!(
        r.message.contains("8001") && r.message.contains("8000"),
        "{}",
        r.message
    );
    let unbalanced = vec![
        LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 6_000)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 5_000)),
    ];
    let r = h
        .post(h.request(
            h.resolution_posts(hold_ref, unbalanced, vec![0, 1], b"res-bad-4"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-001", exit::REFUSAL));
    assert!(h.db.vertex(resolution_vid(hold_ref.vid)).unwrap().is_none());

    // Only a pending entry is resolved: an Original is FA-REF-060.
    let original = h
        .post(h.request(
            h.proposal(h.rent_legs(100), b"orig", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("admitted")
        .entry_ref();
    let r = h
        .post(h.request(
            h.resolution_posts(original, h.rent_legs(100), vec![0, 1], b"res-bad-5"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-060", exit::REFUSAL));
    let stale = EntryRef {
        vid: hold_ref.vid,
        entry_digest: [0; 32],
    };
    let r = h
        .post(h.request(h.resolution_voids(stale, b"res-bad-6"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-060", exit::REFUSAL));

    // Post 60.00 of the 80.00 hold. The identity is derived from the hold.
    let posts = h.resolution_posts(hold_ref, sixty, vec![0, 1], b"res-1");
    let resolved = h
        .post(h.request(posts.clone(), &["post"]))
        .expect("admitted");
    let (res_ref, period) = committed(&resolved).expect("the first resolution commits");
    assert_eq!(res_ref.vid, resolution_vid(hold_ref.vid));
    assert_eq!(period, h.march);
    let edge =
        h.db.edge(edge_id(relation::RESOLVES, res_ref.vid, hold_ref.vid))
            .unwrap()
            .expect("RESOLVES edge");
    assert!(
        edge.props
            .iter()
            .any(|(k, v)| *k == property::DISPOSITION && *v == CanonicalScalar::Int(0)),
        "{:?}",
        edge.props
    );
    for ordinal in 0..2u16 {
        let lvid = leg_vid(res_ref.vid, ordinal);
        assert!(h.db.vertex(lvid).unwrap().is_some());
        assert!(
            h.db.edge(edge_id(relation::HAS_LEG, res_ref.vid, lvid))
                .unwrap()
                .is_some()
        );
    }

    // Exactly one resolution per hold: the identical retry is the recorded
    // outcome; a void, a second posting, and another principal's identical
    // resolution are conflicts (exit 6) that write nothing.
    let again = h
        .post(h.request(posts.clone(), &["post"]))
        .expect("recorded");
    assert_eq!(again.entry_ref(), res_ref);
    assert!(matches!(again, Posted::AlreadyRecorded { .. }));
    let r = h
        .post(h.request(h.resolution_voids(hold_ref, b"res-2"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-062", exit::CONFLICT));
    let r = h
        .post(h.request(
            h.resolution_posts(hold_ref, h.rent_legs(2_000), vec![0, 1], b"res-3"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-062", exit::CONFLICT));
    let mut other = posts;
    other.principal_ref = VId(8);
    let r = h.post(h.request(other, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-062", exit::CONFLICT));
}

#[test]
fn releases_stay_admissible_after_close_and_lock_while_posts_follow_the_matrix() {
    let mut h = harness();
    let hold_a = h
        .post(h.request(h.pending(h.rent_legs(500), b"hold-a"), &["post"]))
        .expect("admitted")
        .entry_ref();
    let hold_b = h
        .post(h.request(h.pending(h.rent_legs(700), b"hold-b"), &["post"]))
        .expect("admitted")
        .entry_ref();
    h.transition(&h.march.clone(), PeriodTransition::SoftClose, b"sc")
        .expect("soft-closes");
    h.transition(&h.march.clone(), PeriodTransition::Close, b"c")
        .expect("closes");
    // Closed: a new hold is refused; Posts needs post_closed; Voids admits.
    let r = h
        .post(h.request(h.pending(h.rent_legs(1), b"hold-c"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-010", exit::SAFETY));
    let r = h
        .post(h.request(
            h.resolution_posts(hold_a, h.rent_legs(500), vec![0, 1], b"ra"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.cite.contains("Resolution(Posts)"), "{}", r.cite);
    let posted = h
        .post(h.request(
            h.resolution_posts(hold_a, h.rent_legs(500), vec![0, 1], b"ra"),
            &["post", "post_closed"],
        ))
        .expect("admitted with post_closed");
    assert!(matches!(posted, Posted::Committed { .. }));
    // Locked: Posts is refused outright and the fix names Voids; Voids admits
    // without any extra capability (plan §5.4: a hold never becomes
    // unreleasable because its period closed).
    h.transition(&h.march.clone(), PeriodTransition::Lock, b"l")
        .expect("locks");
    let r = h
        .post(h.request(
            h.resolution_posts(hold_b, h.rent_legs(700), vec![0, 1], b"rb"),
            &["post", "post_closed"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-010", exit::SAFETY));
    assert!(r.fix.contains("Voids"), "{}", r.fix);
    let voided = h
        .post(h.request(h.resolution_voids(hold_b, b"rb"), &["post"]))
        .expect("a release admits in Locked");
    let (void_ref, _) = committed(&voided).expect("a release in Locked commits");
    assert_eq!(void_ref.vid, resolution_vid(hold_b.vid));
    let (stored, _) = read_entry(&h.db, void_ref.vid).unwrap().expect("void row");
    assert!(stored.proposal.legs.is_empty());
    assert_eq!(
        stored.proposal.control,
        Some(ControlPayload::ReservationRelease)
    );
    let edge =
        h.db.edge(edge_id(relation::RESOLVES, void_ref.vid, hold_b.vid))
            .unwrap()
            .expect("RESOLVES edge");
    assert!(
        edge.props
            .iter()
            .any(|(k, v)| *k == property::DISPOSITION && *v == CanonicalScalar::Int(1))
    );
}

/// Plan §5.4 at the kernel boundary (fa-ctf): a timed hold needs a committed
/// tick to anchor on, and `Expires` is the sweep's — never posted. The sweep
/// itself is exercised against the oracle in fa-registers' differential.
#[test]
fn a_timed_hold_needs_a_tick_and_expires_is_never_posted() {
    let mut h = harness();
    let mut timed = h.pending(h.rent_legs(10), b"timed");
    timed.pending = Some(Pending {
        timeout_ns: Some(5),
        resolution_of: None,
        disposition: None,
    });
    let r = h.post(h.request(timed, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-095", exit::REFUSAL));
    assert!(r.fix.contains("tick"), "{}", r.fix);
    assert_eq!(latest_tick(&h.db).unwrap(), None, "no tick was journaled");
    let hold = h
        .post(h.request(h.pending(h.rent_legs(10), b"hold"), &["post"]))
        .expect("admitted")
        .entry_ref();
    let mut expires = h.resolution_voids(hold, b"exp");
    expires.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(hold),
        disposition: Some(Disposition::Expires { at_tick: 9 }),
    });
    let r = h.post(h.request(expires, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-098", exit::USAGE));
    assert!(r.fix.contains("Resolution(Voids)"), "{}", r.fix);
    assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
}

/// Plan §7.6/§7.7 at the kernel boundary (fa-ctf slice 2): this book's
/// genesis declares no `time_zone_policy`, so no tick can become the date a
/// scheduled reversal waits for — the request is refused (FA-REF-102,
/// naming the field), never given an implicit zone; and only an Adjusting
/// entry schedules its reversal, for a later date.
#[test]
fn a_scheduled_reversal_needs_a_declared_time_zone_policy() {
    let mut h = harness();
    let april = DateDay::from_ymd(2026, 4, 1).unwrap();
    let accrual = with_auto_reverse(
        h.proposal(h.rent_legs(10), b"accrual", EntryClass::ADJUSTING),
        april,
    );
    let r = h.post(h.request(accrual, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-102", exit::REFUSAL), "{r}");
    assert!(r.fix.contains("time_zone_policy"), "{}", r.fix);
    let original = with_auto_reverse(
        h.proposal(h.rent_legs(10), b"original", EntryClass::ORIGINAL),
        april,
    );
    let r = h.post(h.request(original, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    let early = with_auto_reverse(
        h.proposal(h.rent_legs(10), b"early", EntryClass::ADJUSTING),
        h.day(),
    );
    let r = h.post(h.request(early, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    assert!(
        h.db.vertex(entry_vid(
            h.book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            b"accrual"
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
fn a_foreign_book_or_branch_coordinate_is_refused_before_any_read() {
    let mut h = harness();
    let frontier = h.db.frontier().unwrap();
    let mut other_book = h.proposal(h.rent_legs(5), b"ob", EntryClass::ORIGINAL);
    other_book.book_id = Id128([0xee; 16]);
    let r = h.post(h.request(other_book, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-103", exit::USAGE));
    let mut branch = h.proposal(h.rent_legs(5), b"br", EntryClass::ORIGINAL);
    branch.branch_id = Id128([1; 16]);
    let r = h.post(h.request(branch, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-103", exit::USAGE));
    assert_eq!(h.db.frontier().unwrap(), frontier, "refusals write nothing");
    let posted = h
        .post(h.request(
            h.proposal(h.rent_legs(5), b"ok", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("the right coordinate posts");
    assert!(matches!(posted, Posted::Committed { .. }));
}

#[test]
fn reversal_targets_are_posted_entries_and_non_entries_are_typed_refusals() {
    let mut h = harness();
    let hold = h
        .post(h.request(h.pending(h.rent_legs(900), b"hold"), &["post"]))
        .expect("admitted")
        .entry_ref();
    let frontier = h.db.frontier().unwrap();
    // A hold posted nothing: reversing it is refused and the fix names Voids.
    let r = h
        .post(h.request(h.reversal_of(hold, 900, b"rev-hold"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-050", exit::REFUSAL));
    assert!(r.fix.contains("Voids"), "{}", r.fix);
    // An account vertex is not an entry: typed refusal, never a corruption
    // error, for both laws.
    let not_an_entry = EntryRef {
        vid: h.cash,
        entry_digest: [7; 32],
    };
    let r = h
        .post(h.request(h.reversal_of(not_an_entry, 1, b"rev-acct"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-050", exit::REFUSAL));
    let r = h
        .post(h.request(h.resolution_voids(not_an_entry, b"res-acct"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-060", exit::REFUSAL));
    assert_eq!(h.db.frontier().unwrap(), frontier, "refusals write nothing");

    // Resolution(Posts) is a posted entry: its exact side-swap reverses the
    // posted sub-vector (and recreates no reservation — a Reversal has no
    // pending block at all).
    let posted = h
        .post(h.request(
            h.resolution_posts(hold, h.rent_legs(600), vec![0, 1], b"res"),
            &["post"],
        ))
        .expect("admitted")
        .entry_ref();
    let reversed = h
        .post(h.request(h.reversal_of(posted, 600, b"rev-res"), &["post"]))
        .expect("a posted sub-vector reverses");
    let (rev_ref, _) = committed(&reversed).expect("commits");
    let (stored, _) = read_entry(&h.db, rev_ref.vid).unwrap().expect("row");
    assert!(stored.proposal.pending.is_none());
    assert_eq!(stored.proposal.legs.len(), 2);
    // A release posted nothing and is final.
    let hold_2 = h
        .post(h.request(h.pending(h.rent_legs(50), b"hold-2"), &["post"]))
        .expect("admitted")
        .entry_ref();
    let void_ref = h
        .post(h.request(h.resolution_voids(hold_2, b"void-2"), &["post"]))
        .expect("admitted")
        .entry_ref();
    let r = h
        .post(h.request(h.reversal_of(void_ref, 50, b"rev-void"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-050", exit::REFUSAL));
}

#[test]
fn rich_leg_fields_without_a_law_are_refused_not_admitted() {
    let mut h = harness();
    let frontier = h.db.frontier().unwrap();
    let base = h.proposal(h.rent_legs(10), b"rich", EntryClass::ORIGINAL);
    let mut converted = base.clone();
    converted.legs[0].base_amount = Some(Amount::new(h.usd, 10));
    let mut entity = base.clone();
    // Dimension 1 is the legal entity (fa-bvx): it has its law. Any other
    // dimension still waits for the dimension registry slice.
    let mut dimensioned = base;
    dimensioned.legs[0].dimension_set = vec![(2, VId(99))];
    for (what, p) in [("base_amount", converted), ("dimension_set", dimensioned)] {
        let r = h.post(h.request(p, &["post"])).unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-102", exit::REFUSAL), "{what}");
        assert!(r.message.contains(what), "{what}: {}", r.message);
    }
    // This book declares no legal entities, so a leg naming one is refused.
    entity.legs[0].dimension_set = vec![(fa_model::LEGAL_ENTITY_DIMENSION, VId(99))];
    let r = h.post(h.request(entity, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-104", exit::REFUSAL), "{r}");
    assert!(r.message.contains("declares no legal entities"), "{r}");
    assert_eq!(h.db.frontier().unwrap(), frontier, "refusals write nothing");
}

fn settle(target: EntryRef, ordinal: u16, usd: UnitId, cents: i128) -> Settlement {
    Settlement {
        target,
        ordinal,
        amount: Amount::new(usd, cents),
    }
}

#[test]
fn applications_settle_open_items_within_the_open_amount_and_reversal_undoes_them() {
    let mut h = harness();
    let usd = h.usd;
    let invoice = h
        .post(h.request(h.invoice(50_000, b"inv-1"), &["post"]))
        .expect("admitted")
        .entry_ref();
    assert_eq!(h.applied_to(invoice.vid, 0), 0);

    // Structure (decided from the payload, nothing written): applying more
    // than the leg carries, a non-positive amount, the same target twice, a
    // Reversal with settles, a hold with settles.
    let frontier = h.db.frontier().unwrap();
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(invoice, 0, usd, 101)], b"r-over-leg"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL));
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(invoice, 0, usd, 0)], b"r-zero"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL));
    let r = h
        .post(h.request(
            h.receipt(
                100,
                vec![settle(invoice, 0, usd, 50), settle(invoice, 0, usd, 50)],
                b"r-twice",
            ),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL));
    let mut hold = h.pending(h.rent_legs(100), b"hold-settles");
    hold.legs[1].settles = vec![settle(invoice, 0, usd, 1)];
    let r = h.post(h.request(hold, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-102", exit::REFUSAL));
    assert_eq!(h.db.frontier().unwrap(), frontier);

    // Target and shape against the witnessed invoice: unknown entry, an
    // account vertex, a stale handle, the revenue leg (other account), the
    // same side, a leg ordinal that does not exist, a hold as target.
    let ghost = EntryRef {
        vid: VId(424_242),
        entry_digest: [0; 32],
    };
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(ghost, 0, usd, 100)], b"r-ghost"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-070", exit::REFUSAL));
    let not_an_entry = EntryRef {
        vid: h.receivable,
        entry_digest: [0; 32],
    };
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(not_an_entry, 0, usd, 100)], b"r-acct"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-070", exit::REFUSAL));
    let stale = EntryRef {
        vid: invoice.vid,
        entry_digest: [9; 32],
    };
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(stale, 0, usd, 100)], b"r-stale"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-070", exit::REFUSAL));
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(invoice, 1, usd, 100)], b"r-revenue"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL));
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(invoice, 2, usd, 100)], b"r-ordinal"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL));
    let mut same_side = h.invoice(100, b"inv-same-side");
    same_side.legs[0].settles = vec![settle(invoice, 0, usd, 100)];
    let r = h.post(h.request(same_side, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL));
    let hold = h
        .post(h.request(h.pending(h.rent_legs(100), b"hold"), &["post"]))
        .expect("admitted")
        .entry_ref();
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(hold, 1, usd, 100)], b"r-hold"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-070", exit::REFUSAL));
    assert_eq!(h.applied_to(invoice.vid, 0), 0);

    // 300.00 of the 500.00 invoice is received: SETTLES edge, applied mirror.
    let receipt_1 = h
        .post(h.request(
            h.receipt(30_000, vec![settle(invoice, 0, usd, 30_000)], b"rcpt-1"),
            &["post"],
        ))
        .expect("admitted")
        .entry_ref();
    assert_eq!(h.applied_to(invoice.vid, 0), 30_000);
    let edge =
        h.db.edge(edge_id(
            relation::SETTLES,
            leg_vid(receipt_1.vid, 1),
            leg_vid(invoice.vid, 0),
        ))
        .unwrap()
        .expect("SETTLES edge");
    assert!(edge.props.iter().any(|(k, v)| *k == property::AMOUNT_BYTES
        && *v == CanonicalScalar::bytes(30_000i128.to_le_bytes().to_vec()).unwrap()));

    // Over-application names the open amount; the identical retry is recorded.
    let r = h
        .post(h.request(
            h.receipt(25_000, vec![settle(invoice, 0, usd, 25_000)], b"rcpt-2"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-072", exit::REFUSAL));
    assert!(r.message.contains("20000"), "{}", r.message);
    assert_eq!(h.applied_to(invoice.vid, 0), 30_000);
    let again = h
        .post(h.request(
            h.receipt(30_000, vec![settle(invoice, 0, usd, 30_000)], b"rcpt-1"),
            &["post"],
        ))
        .expect("recorded");
    assert!(matches!(again, Posted::AlreadyRecorded { .. }));
    assert_eq!(h.applied_to(invoice.vid, 0), 30_000);

    // The invoice cannot be reversed while a receipt is applied to it.
    let r = h
        .post(h.request(h.reversal_of_entry(invoice, b"rev-inv-live"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-073", exit::REFUSAL));

    // Reversing the receipt undoes its application exactly: UNSETTLES edge,
    // applied back to zero, and the second receipt now fits.
    let rev_1 = h
        .post(h.request(h.reversal_of_entry(receipt_1, b"rev-rcpt-1"), &["post"]))
        .expect("admitted")
        .entry_ref();
    assert_eq!(h.applied_to(invoice.vid, 0), 0);
    assert!(
        h.db.edge(edge_id(
            relation::UNSETTLES,
            leg_vid(rev_1.vid, 1),
            leg_vid(invoice.vid, 0)
        ))
        .unwrap()
        .is_some()
    );
    let (stored, _) = read_entry(&h.db, rev_1.vid).unwrap().expect("row");
    assert!(stored.proposal.legs.iter().all(|l| l.settles.is_empty()));
    let receipt_2 = h
        .post(h.request(
            h.receipt(25_000, vec![settle(invoice, 0, usd, 25_000)], b"rcpt-2"),
            &["post"],
        ))
        .expect("admitted")
        .entry_ref();
    assert_eq!(h.applied_to(invoice.vid, 0), 25_000);
    // Reversing the reversal of an applying entry would re-apply: refused.
    let r = h
        .post(h.request(h.reversal_of_entry(rev_1, b"rev-rev-1"), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-102", exit::REFUSAL));
    // Once the last receipt is reversed, the invoice itself can be reversed,
    // and nothing can be applied to a reversed entry.
    h.post(h.request(h.reversal_of_entry(receipt_2, b"rev-rcpt-2"), &["post"]))
        .expect("admitted");
    assert_eq!(h.applied_to(invoice.vid, 0), 0);
    h.post(h.request(h.reversal_of_entry(invoice, b"rev-inv"), &["post"]))
        .expect("admitted");
    let r = h
        .post(h.request(
            h.receipt(100, vec![settle(invoice, 0, usd, 100)], b"r-reversed"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-070", exit::REFUSAL));
}

#[test]
fn a_reversal_chain_of_any_length_keeps_liveness_by_parity_and_settles_the_revived_original() {
    let mut h = harness();
    let usd = h.usd;
    let original = h
        .post(h.request(h.invoice(100, b"inv-chain"), &["post"]))
        .expect("admitted")
        .entry_ref();
    // Sixty-six successive reversals, each targeting the previous entry.
    let mut tip = original;
    for i in 0..66u32 {
        tip = h
            .post(h.request(
                h.reversal_of_entry(tip, format!("rev-{i}").as_bytes()),
                &["post"],
            ))
            .expect("every reversal of a reversal is admitted")
            .entry_ref();
    }
    // Even parity: the original is live again, so a receipt may settle it
    // (witnessed applied mirror becomes 1).
    let receipt = h
        .post(h.request(
            h.receipt(1, vec![settle(original, 0, usd, 1)], b"rcpt-after-66"),
            &["post"],
        ))
        .expect("the revived original is an open item");
    assert!(matches!(receipt, Posted::Committed { .. }));
    assert_eq!(h.applied_to(original.vid, 0), 1);
    // A 67th reversal (odd parity) reverses the original again: a further
    // application against it is refused as a reversed target.
    let r67 = h.post(h.request(h.reversal_of_entry(tip, b"rev-66"), &["post"]));
    assert!(r67.is_ok(), "{r67:?}");
    let r = h
        .post(h.request(
            h.receipt(1, vec![settle(original, 0, usd, 1)], b"rcpt-after-67"),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-070", exit::REFUSAL));
}

// ---------------------------------------------------------------------------
// Evidence (fa-lp6, plan §9.1–§9.3): content-addressed Documents
// ---------------------------------------------------------------------------

#[test]
fn documents_are_content_addressed_idempotent_and_verified_on_read() {
    let mut h = harness();
    let bytes = b"BILL 77 from Landlord LLC: April rent 1,200.00 USD";
    let doc = h.document(INVOICE, HUMAN_UPLOAD, bytes);
    let added = h.add_document(&doc).expect("admitted");
    assert!(!added.already_recorded);
    assert_eq!(
        added.doc_commit,
        fa_journal::evidence::doc_commit(INVOICE, bytes)
    );
    assert_eq!(added.oid, doc.oid());
    assert_eq!(added.vid, document_vid(&doc.oid()));
    assert_eq!(added.size, bytes.len() as u64);
    // The vertex is a Document, recorded at the commit that created it.
    let row = h.db.vertex(added.vid).unwrap().expect("document row");
    assert_eq!(row.labels, vec![fa_model::symbols::label::DOCUMENT]);
    assert_eq!(row.created_at, added.recorded_at);
    // Reading verifies the bytes against the commitment and returns them.
    assert_eq!(read_document(&h.db, &added.oid).unwrap(), Some(doc.clone()));
    // The same bytes of the same kind are the recorded outcome, whatever grade
    // the second intake declares: the first intake's grade stands.
    let again = h
        .add_document(&h.document(INVOICE, AGENT_UPLOAD, bytes))
        .expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(
        (again.oid, again.grade, again.recorded_at),
        (added.oid, HUMAN_UPLOAD, added.recorded_at)
    );
    // The kind is part of the commitment: the same bytes as a Receipt are a
    // different document.
    let receipt = h
        .add_document(&h.document(RECEIPT, HUMAN_UPLOAD, bytes))
        .expect("admitted");
    assert!(!receipt.already_recorded);
    assert_ne!(receipt.oid, added.oid);
    assert_ne!(receipt.doc_commit, added.doc_commit);
    // An oid this book never recorded reads as absent.
    assert_eq!(read_document(&h.db, &Oid([0xee; 32])).unwrap(), None);
}

#[test]
fn document_intake_refuses_empty_oversized_unregistered_and_unverifiable_input() {
    let mut h = harness();
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    let body = b"WIRE CONFIRMATION 9 (fixture)";
    let mut cases: Vec<(&str, Document, &str, u8)> = vec![
        (
            "empty",
            h.document(INVOICE, HUMAN_UPLOAD, b""),
            "FA-REF-083",
            exit::USAGE,
        ),
        (
            "unregistered kind",
            h.document(0, HUMAN_UPLOAD, body),
            "FA-REF-083",
            exit::USAGE,
        ),
        (
            "unregistered kind 99",
            h.document(99, HUMAN_UPLOAD, body),
            "FA-REF-083",
            exit::USAGE,
        ),
        (
            "unregistered grade",
            h.document(INVOICE, 99, body),
            "FA-REF-083",
            exit::USAGE,
        ),
        (
            "ThirdPartySigned is never declared at intake",
            h.document(INVOICE, 1, body),
            "FA-REF-084",
            exit::REFUSAL,
        ),
        (
            "Generated is never declared at intake",
            h.document(INVOICE, 5, body),
            "FA-REF-084",
            exit::REFUSAL,
        ),
        (
            "oversized",
            h.document(
                INVOICE,
                HUMAN_UPLOAD,
                &vec![b'x'; usize::try_from(policy.max_document_bytes).unwrap() + 1],
            ),
            "FA-REF-083",
            exit::USAGE,
        ),
    ];
    let mut bad_mime = h.document(INVOICE, HUMAN_UPLOAD, body);
    bad_mime.mime = "text plain".into();
    cases.push(("mime with a space", bad_mime, "FA-REF-083", exit::USAGE));
    let mut no_mime = h.document(INVOICE, HUMAN_UPLOAD, body);
    no_mime.mime = String::new();
    cases.push(("empty mime", no_mime, "FA-REF-083", exit::USAGE));
    let mut foreign = h.document(INVOICE, HUMAN_UPLOAD, body);
    foreign.book_id = Id128([1; 16]);
    cases.push(("a foreign book", foreign, "FA-REF-103", exit::USAGE));
    for (what, doc, code, exit_class) in cases {
        let r = h.add_document(&doc).unwrap_err();
        assert_eq!((r.code, r.exit), (code, exit_class), "{what}: {r}");
        assert!(!r.fix.is_empty(), "{what}: a refusal names the fix");
        // Nothing was written at the identity the document would have had.
        assert!(
            h.db.vertex(document_vid(&doc.oid())).unwrap().is_none(),
            "{what}: a refused intake writes nothing"
        );
    }
    // The grade refusal cites the registry row.
    let r = h.add_document(&h.document(INVOICE, 1, body)).unwrap_err();
    assert!(r.cite.contains("ThirdPartySigned"), "{}", r.cite);
    // And the honest declaration of the same bytes is admitted.
    assert!(
        h.add_document(&h.document(INVOICE, AGENT_UPLOAD, body))
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Evidence minimum at commit (fa-lp6, FA-INV-05 `evidence-minimum`)
// ---------------------------------------------------------------------------

#[test]
fn an_entry_below_its_evidence_minimum_is_refused_and_a_cited_document_is_linked() {
    let mut h = harness();
    let mut bare = h.proposal(h.rent_legs(50_000), b"ev-bare", EntryClass::ORIGINAL);
    bare.evidence.clear();
    let evid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"ev-bare");

    // No citation: refused, naming the registry row and the intake command.
    let r = h.post(h.request(bare.clone(), &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-080", exit::REFUSAL), "{r}");
    assert!(r.cite.contains("class = \"Original\""), "{}", r.cite);
    assert!(r.fix.contains("fa document add"), "{}", r.fix);

    // A citation of a document the book does not hold.
    let ghost = h.document(INVOICE, HUMAN_UPLOAD, b"an invoice nobody recorded");
    let mut p = bare.clone();
    p.evidence = vec![ghost.evidence_ref(ROLE_SOURCE)];
    let r = h.post(h.request(p, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-081", exit::REFUSAL), "{r}");

    // A citation under a commitment that is not the document's.
    let mut wrong = h.evidence[0];
    wrong.doc_commit = [0; 32];
    let mut p = bare.clone();
    p.evidence = vec![wrong];
    let r = h.post(h.request(p, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-082", exit::REFUSAL), "{r}");

    // A second citation of a held document under a wrong commitment is
    // refused even when the first citation is right (review D1): every
    // citation's commitment is checked, not one per document.
    let good = h.evidence[0];
    assert!(
        good.doc_commit < [0xff; 32],
        "the forged citation sorts second"
    );
    for role in [good.role, 2] {
        let forged = EvidenceRef {
            doc_commit: [0xff; 32],
            role,
            ..good
        };
        let mut p = bare.clone();
        p.evidence = vec![good, forged];
        let r = h.post(h.request(p, &["post"])).unwrap_err();
        assert_eq!(
            (r.code, r.exit),
            ("FA-REF-082", exit::REFUSAL),
            "role {role}: {r}"
        );
    }

    // An unregistered role is a structural error.
    let mut odd = h.evidence[0];
    odd.role = 99;
    let mut p = bare.clone();
    p.evidence = vec![odd];
    let r = h.post(h.request(p, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");

    // Every refusal left the book unchanged.
    assert!(h.db.vertex(evid).unwrap().is_none());

    // Cited (one document in two roles, a second document): committed, one
    // EVIDENCED_BY edge per distinct document, the citations carried exactly.
    let support = h.document(RECEIPT, AGENT_UPLOAD, b"bank receipt for the rent");
    h.add_document(&support).expect("admitted");
    let source = h.evidence[0];
    let mut also = source;
    also.role = 2;
    let mut cites = vec![source, also, support.evidence_ref(2)];
    cites.sort();
    let mut p = bare.clone();
    p.evidence = cites.clone();
    let entry = h
        .post(h.request(p, &["post"]))
        .expect("admitted")
        .entry_ref()
        .vid;
    assert_eq!(entry, evid);
    for d in [
        document_vid(&source.document_oid),
        document_vid(&support.oid()),
    ] {
        assert!(
            h.db.edge(edge_id(relation::EVIDENCED_BY, entry, d))
                .unwrap()
                .is_some(),
            "EVIDENCED_BY to {d:?}"
        );
    }
    let (back, _) = read_entry(&h.db, entry).unwrap().expect("entry row");
    assert_eq!(back.proposal.evidence, cites);
}

#[test]
fn target_classes_rest_on_their_target_while_a_hold_needs_its_own_document() {
    let mut h = harness();
    let original = h
        .post(h.request(h.invoice(700, b"ev-inv"), &["post"]))
        .expect("admitted")
        .entry_ref();
    // A reversal's closure is the reversed entry: no document of its own.
    let mut rev = h.reversal_of_entry(original, b"ev-rev");
    rev.evidence.clear();
    let r = h.post(h.request(rev, &["post"]));
    assert!(r.is_ok(), "{r:?}");

    // A hold is the claim its resolution posts: it carries the document.
    let mut hold = h.pending(h.rent_legs(900), b"ev-hold");
    hold.evidence.clear();
    let r = h.post(h.request(hold, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-080", exit::REFUSAL), "{r}");
    assert!(r.cite.contains("class = \"Pending\""), "{}", r.cite);
    let pending = h
        .post(h.request(h.pending(h.rent_legs(900), b"ev-hold"), &["post"]))
        .expect("reserves")
        .entry_ref();
    // Its resolution posts on the hold's closure, citing nothing.
    let mut res = h.resolution_posts(pending, h.rent_legs(900), vec![0, 1], b"ev-res");
    res.evidence.clear();
    let r = h.post(h.request(res, &["post"]));
    assert!(r.is_ok(), "{r:?}");

    // An Adjusting entry, like an Original, needs its document.
    let mut adj = h.proposal(h.rent_legs(10), b"ev-adj", EntryClass::ADJUSTING);
    adj.evidence.clear();
    let r = h.post(h.request(adj, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-080", exit::REFUSAL), "{r}");
}

// ---------------------------------------------------------------------------
// Evidence: a Document's mirrors never outrank its payload (fa-lp6, review
// WhiteCreek 3097)
// ---------------------------------------------------------------------------

impl Harness {
    /// A raw substrate write outside every kernel law: the corruption an
    /// insider or a storage fault could leave behind.
    fn write_raw(&mut self, batch: fgdb::WriteBatch) {
        let ctx = self.ctx();
        let db = &mut self.db;
        self.runtime
            .block_on(async move { db.write(&ctx.commit(), batch).await })
            .expect("raw write");
    }

    fn post_citing(&mut self, doc: &Document, key: &[u8]) -> Result<Posted, Refusal> {
        let mut p = self.proposal(self.rent_legs(7_000), key, EntryClass::ORIGINAL);
        p.evidence = vec![doc.evidence_ref(ROLE_SOURCE)];
        let req = self.request(p, &["post"]);
        self.post(req)
    }
}

#[test]
fn a_document_whose_mirrors_drift_from_its_payload_is_refused_and_an_untouched_one_posts() {
    let mut h = harness();
    let kind_drift = h.document(
        INVOICE,
        HUMAN_UPLOAD,
        b"INVOICE 501 (kind mirror rewritten)",
    );
    let commit_drift = h.document(
        INVOICE,
        HUMAN_UPLOAD,
        b"INVOICE 502 (commitment mirror rewritten)",
    );
    let intact = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 503 (untouched)");
    for d in [&kind_drift, &commit_drift, &intact] {
        h.add_document(d).expect("admitted");
    }
    // Rewrite one mirror on each of two documents, outside every law: the
    // kind mirror says Rate (an Invoice payload), the commitment mirror is
    // zeroed. The payloads are untouched.
    let mut batch = fgdb::WriteBatch::new(relation::EVIDENCED_BY);
    batch.set_vertex_property(
        document_vid(&kind_drift.oid()),
        property::CODE,
        Some(CanonicalScalar::ucs_basic_text("Rate").unwrap()),
    );
    batch.set_vertex_property(
        document_vid(&commit_drift.oid()),
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
    );
    h.write_raw(batch);

    for (doc, key) in [
        (&kind_drift, b"drift-kind" as &[u8]),
        (&commit_drift, b"drift-commit"),
    ] {
        // A post citing it is refused with exit 8; nothing is written.
        let r = h.post_citing(doc, key).unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-085", exit::VERIFICATION), "{r}");
        let evid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
        assert!(h.db.vertex(evid).unwrap().is_none());
        // Reading it back, or re-adding the same bytes, never vouches for it.
        assert!(
            matches!(read_document(&h.db, &doc.oid()), Err(KernelError::Corrupt(ref why)) if why.contains("FA-REF-085")),
            "{:?}",
            read_document(&h.db, &doc.oid())
        );
        let again = h.add_document(doc).unwrap_err();
        assert_eq!((again.code, again.exit), ("FA-REF-085", exit::VERIFICATION));
    }
    // The refusal names the payload's kind, the authority, not the mirror's.
    let r = h.post_citing(&kind_drift, b"drift-kind-2").unwrap_err();
    assert!(r.message.contains("`Invoice`"), "{}", r.message);
    // The untouched document still posts and reads back verified.
    assert!(matches!(
        h.post_citing(&intact, b"intact").expect("admitted"),
        Posted::Committed { .. }
    ));
    assert_eq!(
        read_document(&h.db, &intact.oid()).unwrap(),
        Some(intact.clone())
    );
}

// ---------------------------------------------------------------------------
// Evidence attached after commit is a new object (fa-lp6, plan §9.2)
// ---------------------------------------------------------------------------

impl Harness {
    fn attach(
        &mut self,
        s: &SupplementalEvidence,
        ops: &[&str],
    ) -> Result<EvidenceAttached, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        // The capability is the attacher's own (fa-llx).
        let cap = Capability::embedded(s.attached_by, ops).expect("registered ops");
        self.runtime
            .block_on(async move { attach_evidence(db, &ctx, book, &cap, s).await })
            .expect("kernel")
    }
}

#[test]
fn evidence_attached_after_commit_is_a_new_object_and_the_entry_never_changes() {
    let mut h = harness();
    let posted = h
        .post(h.request(
            h.proposal(h.rent_legs(9_000), b"supp-target", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("admitted");
    let target = posted.entry_ref();
    let (before, _) = read_entry(&h.db, target.vid).unwrap().expect("entry row");
    let receipt = h.document(RECEIPT, HUMAN_UPLOAD, b"bank receipt for supp-target");
    h.add_document(&receipt).expect("admitted");
    let mut docs = vec![receipt.evidence_ref(2), h.evidence[0]];
    docs.sort();
    let supp = SupplementalEvidence {
        book_id: h.book.book_id,
        entry_ref: target,
        documents: docs.clone(),
        attached_by: PRINCIPAL,
    };
    let attached = h.attach(&supp, &["post"]).expect("attached");
    assert!(!attached.already_recorded);
    assert!(attached.recorded_at > posted.recorded_at());

    // The entry is byte-for-byte what it was: its own evidence list is the
    // original one, and its digests still verify.
    let (after, _) = read_entry(&h.db, target.vid).unwrap().expect("entry row");
    assert_eq!(after, before);
    assert_eq!(after.proposal.evidence, h.evidence);
    // SUPPLEMENTS -> the entry; EVIDENCED_BY -> each distinct document.
    assert!(
        h.db.edge(edge_id(relation::SUPPLEMENTS, attached.vid, target.vid))
            .unwrap()
            .is_some()
    );
    for d in [
        document_vid(&receipt.oid()),
        document_vid(&h.evidence[0].document_oid),
    ] {
        assert!(
            h.db.edge(edge_id(relation::EVIDENCED_BY, attached.vid, d))
                .unwrap()
                .is_some()
        );
    }
    // It reads back verified, recorded at its own commit.
    assert_eq!(
        supplements_of(&h.db, &h.book, target.vid).unwrap(),
        vec![(supp.clone(), attached.recorded_at)]
    );
    // The same attachment again is the recorded outcome.
    let again = h.attach(&supp, &["post"]).expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(
        (again.vid, again.recorded_at),
        (attached.vid, attached.recorded_at)
    );

    // Refusals write nothing.
    let with = |documents: Vec<fa_model::EvidenceRef>, entry_ref: EntryRef| SupplementalEvidence {
        book_id: h.book.book_id,
        entry_ref,
        documents,
        attached_by: VId(8),
    };
    let ghost = h.document(INVOICE, HUMAN_UPLOAD, b"never recorded");
    let mut wrong_commit = receipt.evidence_ref(2);
    wrong_commit.doc_commit = [0; 32];
    let mut wrong_digest = target;
    wrong_digest.entry_digest[0] ^= 1;
    let not_an_entry = EntryRef {
        vid: document_vid(&receipt.oid()),
        entry_digest: [0; 32],
    };
    let mut unsorted = docs.clone();
    unsorted.reverse();
    let post: &[&str] = &["post"];
    let none: &[&str] = &[];
    let cases: Vec<(&str, SupplementalEvidence, &[&str], &str, u8)> = vec![
        (
            "no post capability",
            with(docs.clone(), target),
            none,
            "FA-REF-011",
            exit::SAFETY,
        ),
        (
            "wrong entry digest",
            with(docs.clone(), wrong_digest),
            post,
            "FA-REF-087",
            exit::REFUSAL,
        ),
        (
            "unknown entry",
            with(
                docs.clone(),
                EntryRef {
                    vid: VId(0xdead),
                    entry_digest: [0; 32],
                },
            ),
            post,
            "FA-REF-087",
            exit::REFUSAL,
        ),
        (
            "a document is not an entry",
            with(docs.clone(), not_an_entry),
            post,
            "FA-REF-087",
            exit::REFUSAL,
        ),
        (
            "unknown document",
            with(vec![ghost.evidence_ref(1)], target),
            post,
            "FA-REF-081",
            exit::REFUSAL,
        ),
        (
            "wrong commitment",
            with(vec![wrong_commit], target),
            post,
            "FA-REF-082",
            exit::REFUSAL,
        ),
        (
            "no documents",
            with(Vec::new(), target),
            post,
            "FA-REF-100",
            exit::USAGE,
        ),
        (
            "unsorted documents",
            with(unsorted, target),
            post,
            "FA-REF-100",
            exit::USAGE,
        ),
    ];
    for (what, s, ops, code, exit_class) in cases {
        let r = h.attach(&s, ops).unwrap_err();
        assert_eq!((r.code, r.exit), (code, exit_class), "{what}: {r}");
    }
    assert_eq!(
        supplements_of(&h.db, &h.book, target.vid).unwrap().len(),
        1,
        "refused attachments wrote nothing"
    );
}

// ---------------------------------------------------------------------------
// Self-sourced evidence does not meet the minimum until reviewed (fa-lp6,
// plan §9.3; the Reviewed attestation itself is tested below, fa-g21)
// ---------------------------------------------------------------------------

#[test]
fn self_sourced_documents_do_not_meet_the_minimum_until_reviewed() {
    let mut h = harness();
    let agents = h.document(INVOICE, AGENT_UPLOAD, b"an invoice an agent uploaded");
    h.add_document(&agents).expect("admitted");

    // Only the agent's document: refused, naming fa-g21; nothing written.
    let r = h.post_citing(&agents, b"self-only").unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-086", exit::REFUSAL), "{r}");
    assert!(r.cite.contains("Reviewed"), "{}", r.cite);
    assert!(r.fix.contains("record_review"), "{}", r.fix);
    assert!(r.fix.contains("--grade HumanUpload"), "{}", r.fix);
    let evid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"self-only");
    assert!(h.db.vertex(evid).unwrap().is_none());

    // Alongside a document a person supplied: admitted.
    let mut p = h.proposal(h.rent_legs(7_000), b"self-plus-human", EntryClass::ORIGINAL);
    let mut cites = vec![agents.evidence_ref(ROLE_SOURCE), h.evidence[0]];
    cites.sort();
    p.evidence = cites;
    let req = h.request(p, &["post"]);
    assert!(h.post(req).is_ok());

    // A reversal rests on its target, whatever it cites.
    let target = h
        .post(h.request(h.invoice(500, b"self-target"), &["post"]))
        .expect("admitted")
        .entry_ref();
    let mut rev = h.reversal_of_entry(target, b"self-rev");
    rev.evidence = vec![agents.evidence_ref(ROLE_SOURCE)];
    let req = h.request(rev, &["post"]);
    let r = h.post(req);
    assert!(r.is_ok(), "{r:?}");
}

// ---------------------------------------------------------------------------
// Attestations (fa-g21, plan §9.2–§9.3): a Reviewed attestation by another
// principal promotes a self-sourced document; the preparer's ManualAssertion
// stands in for a document where the class's row admits one. Each step logs
// what the kernel decided (`cargo test -- --nocapture`).
// ---------------------------------------------------------------------------

const REVIEWER: VId = VId(8);
const OTHER_REVIEWER: VId = VId(9);

impl Harness {
    fn review_as(
        &mut self,
        cap: &Capability,
        reviewer: VId,
        document: Oid,
        against: Vec<Oid>,
    ) -> Result<Attested, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move {
                record_review(db, &ctx, book, cap, reviewer, document, against).await
            })
            .expect("kernel")
    }

    fn review(
        &mut self,
        reviewer: VId,
        document: Oid,
        against: Vec<Oid>,
    ) -> Result<Attested, Refusal> {
        let cap = Capability::embedded(reviewer, &["approve"]).expect("approve");
        self.review_as(&cap, reviewer, document, against)
    }

    fn statement(&self, text: &str, nonce: u8) -> Erasable<String> {
        Erasable::seal(
            &text.to_string(),
            None,
            &self.book.seal_key,
            [nonce; 32],
            [nonce; 24],
        )
    }

    fn assert_manually(
        &mut self,
        holder: VId,
        proposal: &EntryPayload,
        reason: u16,
        statement: Erasable<String>,
    ) -> Result<Attested, Refusal> {
        let ctx = self.ctx();
        let cap = Capability::embedded(holder, &["post"]).expect("post");
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move {
                record_manual_assertion(db, &ctx, book, &cap, proposal, reason, statement).await
            })
            .expect("kernel")
    }

    /// Write `a` as a stored Attestation with every mirror right, outside
    /// every law: a forged row the kernel would never have recorded.
    fn forge(&mut self, a: &fa_journal::attestation::Attestation) -> VId {
        use fa_journal::attestation::CapabilityBinding;
        use fa_model::symbols::label;
        let vid = a.vid().expect("an identity");
        let binding = CapabilityBinding {
            profile: fa_policy::Profile::Human,
            capability_commitment: [0xf0; 32],
        };
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(a.canonical_bytes(&binding).unwrap()).unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(a.signed_digest().unwrap().to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(a.book_id.0.to_vec()).unwrap(),
            ),
            (
                property::CODE,
                CanonicalScalar::ucs_basic_text(a.claim.name()).unwrap(),
            ),
        ];
        props.sort_by_key(|(k, _)| k.0);
        let mut batch = fgdb::WriteBatch::new(relation::ATTESTS);
        batch.create_vertex(vid, vec![label::ATTESTATION], props);
        self.write_raw(batch);
        vid
    }
}

fn entry_absent(h: &Harness, key: &[u8]) -> bool {
    let evid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    h.db.vertex(evid).unwrap().is_none()
}

#[test]
fn a_review_by_another_approver_promotes_an_agent_upload_and_self_review_is_refused() {
    use fa_journal::attestation::{AttestationClaim, Subject, review_vid};
    let mut h = harness();
    let agents = h.document(INVOICE, AGENT_UPLOAD, b"INVOICE 601 (an agent uploaded it)");
    h.add_document(&agents).expect("admitted");
    let oid = agents.oid();

    // Unreviewed: refused 086, naming the Reviewed remedy; nothing written.
    let r = h.post_citing(&agents, b"g21-before").unwrap_err();
    eprintln!(
        "g21 review: post before any review -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-086", exit::REFUSAL), "{r}");
    assert!(r.fix.contains("record_review"), "{}", r.fix);
    assert!(entry_absent(&h, b"g21-before"));

    // The uploader reviewing its own upload: SoD, exit 7, nothing written.
    let r = h.review(PRINCIPAL, oid, Vec::new()).unwrap_err();
    eprintln!("g21 review: self-review -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-111", exit::SAFETY), "{r}");
    assert!(
        h.db.vertex(review_vid(h.book.book_id, &oid))
            .unwrap()
            .is_none()
    );

    // The Human-profile hook: a capability without `approve` is refused, and
    // an Agent capability is refused before any read (it can never hold it).
    let post_only = Capability::embedded(REVIEWER, &["post"]).expect("post");
    let r = h
        .review_as(&post_only, REVIEWER, oid, Vec::new())
        .unwrap_err();
    eprintln!(
        "g21 review: reviewer without approve -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY), "{r}");
    let agent = fa_policy::Capability::new(
        REVIEWER,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        REVIEWER,
    )
    .expect("an agent capability");
    let r = h.review_as(&agent, REVIEWER, oid, Vec::new()).unwrap_err();
    eprintln!("g21 review: agent reviewer -> {} {}", r.code, r.message);
    assert_eq!(r.code, "FA-REF-013", "{r}");

    // A document the book does not hold, as the subject or compared against.
    let ghost = h.document(INVOICE, HUMAN_UPLOAD, b"never recorded");
    let r = h.review(REVIEWER, ghost.oid(), Vec::new()).unwrap_err();
    eprintln!("g21 review: unheld subject -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-110", exit::REFUSAL), "{r}");
    let r = h.review(REVIEWER, oid, vec![ghost.oid()]).unwrap_err();
    eprintln!("g21 review: unheld comparison -> {} {}", r.code, r.message);
    assert_eq!(r.code, "FA-REF-110", "{r}");
    let r = h.review(REVIEWER, oid, vec![oid]).unwrap_err();
    assert_eq!(
        r.code, "FA-REF-100",
        "a document is not compared against itself: {r}"
    );

    // Another approver reviews it against the person's invoice: recorded,
    // with ATTESTS to the document and every mirror its payload states.
    let against = vec![h.evidence[0].document_oid];
    let reviewed = h.review(REVIEWER, oid, against.clone()).expect("recorded");
    eprintln!(
        "g21 review: recorded {:032x} at {:?}",
        reviewed.vid.0, reviewed.recorded_at
    );
    assert!(!reviewed.already_recorded);
    assert_eq!(reviewed.vid, review_vid(h.book.book_id, &oid));
    assert!(
        h.db.edge(edge_id(relation::ATTESTS, reviewed.vid, document_vid(&oid)))
            .unwrap()
            .is_some()
    );
    let (stored, seq) = read_attestation(&h.db, reviewed.vid)
        .unwrap()
        .expect("readable");
    assert_eq!(seq, reviewed.recorded_at);
    assert_eq!(stored.attestation.principal, REVIEWER);
    assert_eq!(stored.attestation.subject, Subject::Document(oid));
    assert_eq!(
        stored.attestation.claim,
        AttestationClaim::Reviewed {
            against: against.clone()
        }
    );
    assert_eq!(stored.binding.profile, fa_policy::Profile::Human);
    assert_eq!(stored.signed_digest, reviewed.signed_digest);

    // The same review again is the recorded outcome; another reviewer, or
    // another comparison, is a conflict (one Reviewed per document).
    let again = h.review(REVIEWER, oid, against.clone()).expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(again.recorded_at, reviewed.recorded_at);
    let r = h.review(OTHER_REVIEWER, oid, Vec::new()).unwrap_err();
    eprintln!("g21 review: a second reviewer -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT), "{r}");

    // Now the agent's upload counts: the post commits, linked to it.
    let posted = h.post_citing(&agents, b"g21-after").expect("admitted");
    let (entry, _) = committed(&posted).expect("committed");
    eprintln!(
        "g21 review: post after the review -> committed {:032x}",
        entry.vid.0
    );
    assert!(
        h.db.edge(edge_id(
            relation::EVIDENCED_BY,
            entry.vid,
            document_vid(&oid)
        ))
        .unwrap()
        .is_some()
    );
    let (_, entry_seq) = read_entry(&h.db, entry.vid).unwrap().expect("entry");
    assert!(
        reviewed.recorded_at < entry_seq,
        "the review was known first"
    );
}

#[test]
fn a_preparers_manual_assertion_stands_in_for_a_document_only_where_registered() {
    use fa_journal::attestation::{AttestationClaim, Subject, manual_assertion_vid};
    let mut h = harness();
    let mut original = h.proposal(h.rent_legs(4_200), b"g21-manual", EntryClass::ORIGINAL);
    original.evidence = Vec::new();
    let digest = original.proposal_digest().unwrap();

    // No document, no assertion: 080, whose fix names the assertion.
    let r = h.post(h.request(original.clone(), &["post"])).unwrap_err();
    eprintln!("g21 manual: post with neither -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-080", exit::REFUSAL), "{r}");
    assert!(r.fix.contains("record_manual_assertion"), "{}", r.fix);

    // An unregistered reason: exit 2, listing the registered ones.
    let text = "the landlord issues no invoice; rent is fixed by the lease of 2025-12-01";
    let r = h
        .assert_manually(PRINCIPAL, &original, 999, h.statement(text, 1))
        .unwrap_err();
    eprintln!("g21 manual: reason 999 -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-112", exit::USAGE), "{r}");
    assert!(r.fix.contains("1 NoDocumentIssued"), "{}", r.fix);

    // A class whose row admits no assertion.
    let mut hold = h.pending(h.rent_legs(4_200), b"g21-manual-hold");
    hold.evidence = Vec::new();
    let r = h
        .assert_manually(PRINCIPAL, &hold, 1, h.statement(text, 2))
        .unwrap_err();
    eprintln!("g21 manual: a Pending proposal -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-110", exit::REFUSAL), "{r}");

    // Not the preparer's: the capability is not the proposal's principal.
    let r = h
        .assert_manually(REVIEWER, &original, 1, h.statement(text, 3))
        .unwrap_err();
    eprintln!("g21 manual: another principal -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY), "{r}");

    // A blank statement, or one sealed under a key this book does not hold.
    let r = h
        .assert_manually(PRINCIPAL, &original, 1, h.statement("   ", 4))
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-100", "{r}");
    let foreign = Erasable::seal(
        &text.to_string(),
        None,
        &SealKey([0x99; 32]),
        [5; 32],
        [5; 24],
    );
    let r = h
        .assert_manually(PRINCIPAL, &original, 1, foreign)
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-100", "{r}");
    assert!(
        h.db.vertex(manual_assertion_vid(h.book.book_id, &digest))
            .unwrap()
            .is_none(),
        "no refused assertion was written"
    );

    // The preparer's assertion with a registered reason: recorded.
    let asserted = h
        .assert_manually(PRINCIPAL, &original, 1, h.statement(text, 6))
        .expect("recorded");
    eprintln!(
        "g21 manual: recorded {:032x} at {:?}",
        asserted.vid.0, asserted.recorded_at
    );
    assert_eq!(asserted.vid, manual_assertion_vid(h.book.book_id, &digest));
    let (stored, _) = read_attestation(&h.db, asserted.vid)
        .unwrap()
        .expect("readable");
    assert_eq!(stored.attestation.subject, Subject::Proposal(digest));
    assert_eq!(stored.attestation.principal, PRINCIPAL);
    let manual = match &stored.attestation.claim {
        AttestationClaim::ManualAssertion {
            reason_code,
            statement,
        } => Some((*reason_code, statement.clone())),
        AttestationClaim::Reviewed { .. } | AttestationClaim::RegisterEquals(_) => None,
    };
    let (reason_code, statement) = manual.expect("a ManualAssertion");
    assert_eq!(reason_code, 1);
    assert_eq!(
        statement
            .open(&h.book.seal_key, fa_model::limits::MAX_DESCRIPTION_BYTES)
            .unwrap(),
        text
    );
    // Re-sealed, the same statement is the recorded outcome; another is a conflict.
    let again = h
        .assert_manually(PRINCIPAL, &original, 1, h.statement(text, 7))
        .expect("recorded");
    assert!(again.already_recorded);
    let r = h
        .assert_manually(PRINCIPAL, &original, 2, h.statement("lost in the move", 8))
        .unwrap_err();
    eprintln!(
        "g21 manual: a different assertion -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT), "{r}");

    // The proposal it binds now posts, and the assertion ATTESTS the entry.
    let posted = h.post(h.request(original, &["post"])).expect("admitted");
    let (entry, _) = committed(&posted).expect("committed");
    eprintln!(
        "g21 manual: post with the assertion -> committed {:032x}",
        entry.vid.0
    );
    assert!(
        h.db.edge(edge_id(relation::ATTESTS, asserted.vid, entry.vid))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        h.db.in_neighbours(entry.vid, relation::ATTESTS).unwrap(),
        vec![asserted.vid]
    );

    // It binds that proposal only: another one without a document is 080.
    let mut other = h.proposal(
        h.rent_legs(4_200),
        b"g21-manual-other",
        EntryClass::ORIGINAL,
    );
    other.evidence = Vec::new();
    let r = h.post(h.request(other, &["post"])).unwrap_err();
    assert_eq!(r.code, "FA-REF-080", "{r}");

    // Adjusting admits one too.
    let mut adjusting = h.proposal(h.rent_legs(900), b"g21-manual-adj", EntryClass::ADJUSTING);
    adjusting.evidence = Vec::new();
    h.assert_manually(
        PRINCIPAL,
        &adjusting,
        4,
        h.statement("year-end accrual estimate", 9),
    )
    .expect("recorded");
    let r = h.post(h.request(adjusting, &["post"]));
    eprintln!("g21 manual: an Adjusting with an assertion -> {r:?}");
    assert!(matches!(r, Ok(Posted::Committed { .. })), "{r:?}");
}

#[test]
fn forged_attestations_are_refused_where_the_kernel_relies_on_them() {
    use fa_journal::attestation::{Attestation, AttestationClaim, Subject};
    let mut h = harness();

    // A self-review written outside the law: the post re-checks SoD (111).
    let agents = h.document(INVOICE, AGENT_UPLOAD, b"INVOICE 701 (agent upload)");
    h.add_document(&agents).expect("admitted");
    h.forge(&Attestation {
        book_id: h.book.book_id,
        claim: AttestationClaim::Reviewed {
            against: Vec::new(),
        },
        subject: Subject::Document(agents.oid()),
        principal: PRINCIPAL,
        evidence_refs: Vec::new(),
    });
    let r = h.post_citing(&agents, b"g21-forged-self").unwrap_err();
    eprintln!(
        "g21 forged: a stored self-review -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-111", exit::SAFETY), "{r}");
    assert!(entry_absent(&h, b"g21-forged-self"));

    // An assertion with a reason the registry does not hold: 112 at post.
    let mut p = h.proposal(h.rent_legs(300), b"g21-forged-reason", EntryClass::ORIGINAL);
    p.evidence = Vec::new();
    h.forge(&Attestation {
        book_id: h.book.book_id,
        claim: AttestationClaim::ManualAssertion {
            reason_code: 999,
            statement: h.statement("forged", 1),
        },
        subject: Subject::Proposal(p.proposal_digest().unwrap()),
        principal: PRINCIPAL,
        evidence_refs: Vec::new(),
    });
    let r = h.post(h.request(p, &["post"])).unwrap_err();
    eprintln!(
        "g21 forged: an unregistered stored reason -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-112", exit::USAGE), "{r}");
    assert!(entry_absent(&h, b"g21-forged-reason"));

    // An assertion by someone other than the preparer: drift (113, exit 8).
    let mut p = h.proposal(
        h.rent_legs(300),
        b"g21-forged-principal",
        EntryClass::ORIGINAL,
    );
    p.evidence = Vec::new();
    h.forge(&Attestation {
        book_id: h.book.book_id,
        claim: AttestationClaim::ManualAssertion {
            reason_code: 1,
            statement: h.statement("forged", 2),
        },
        subject: Subject::Proposal(p.proposal_digest().unwrap()),
        principal: REVIEWER,
        evidence_refs: Vec::new(),
    });
    let r = h.post(h.request(p, &["post"])).unwrap_err();
    eprintln!(
        "g21 forged: another principal's assertion -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-113", exit::VERIFICATION), "{r}");
    assert!(entry_absent(&h, b"g21-forged-principal"));

    // A real review whose claim mirror is rewritten: drift at post and on read.
    let other = h.document(INVOICE, AGENT_UPLOAD, b"INVOICE 702 (agent upload)");
    h.add_document(&other).expect("admitted");
    let reviewed = h
        .review(REVIEWER, other.oid(), Vec::new())
        .expect("recorded");
    let mut batch = fgdb::WriteBatch::new(relation::ATTESTS);
    batch.set_vertex_property(
        reviewed.vid,
        property::CODE,
        Some(CanonicalScalar::ucs_basic_text("ManualAssertion").unwrap()),
    );
    h.write_raw(batch);
    let r = h.post_citing(&other, b"g21-drift").unwrap_err();
    eprintln!("g21 forged: a drifted review -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-113", exit::VERIFICATION), "{r}");
    assert!(entry_absent(&h, b"g21-drift"));
    assert!(
        matches!(read_attestation(&h.db, reviewed.vid), Err(KernelError::Corrupt(ref why)) if why.contains("FA-REF-113")),
        "{:?}",
        read_attestation(&h.db, reviewed.vid)
    );
    // Recording the same review again never vouches for the drifted row.
    let r = h.review(REVIEWER, other.oid(), Vec::new()).unwrap_err();
    assert_eq!(r.code, "FA-REF-113", "{r}");
}

// ---------------------------------------------------------------------------
// Chain of custody and import runs (fa-txf, plan §9.3). Each step logs what
// the kernel decided (`cargo test -- --nocapture`).
// ---------------------------------------------------------------------------

impl Harness {
    fn transfer(
        &mut self,
        holder: VId,
        document: Oid,
        from: VId,
        to: VId,
    ) -> Result<fa_journal::CustodyMoved, Refusal> {
        let ctx = self.ctx();
        let cap = Capability::embedded(holder, &["post"]).expect("post");
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(
                async move { transfer_custody(db, &ctx, book, &cap, document, from, to).await },
            )
            .expect("kernel")
    }

    fn import(
        &mut self,
        cap: &Capability,
        source: fa_model::IntakeSource,
        key: &[u8],
        documents: Vec<Document>,
    ) -> Result<fa_journal::ImportRecorded, Refusal> {
        let ctx = self.ctx();
        let req = fa_journal::ImportRequest {
            principal: cap.holder(),
            source,
            idempotency_key: key.to_vec(),
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            description: Erasable::seal(
                &"import run".to_string(),
                None,
                &self.book.seal_key,
                [21; 32],
                [21; 24],
            ),
            documents,
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { import_run(db, &ctx, book, cap, req).await })
            .expect("kernel")
    }

    /// Write a Document vertex outside every law, with every mirror right
    /// and `custody_len` as given (absent: a document with no receipt).
    fn write_document_raw(&mut self, doc: &Document, custody_len: Option<i64>) {
        use fa_model::symbols::label;
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(doc.canonical_bytes().unwrap()).unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(doc.doc_commit().to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(doc.book_id.0.to_vec()).unwrap(),
            ),
            (
                property::CODE,
                CanonicalScalar::ucs_basic_text("Invoice").unwrap(),
            ),
        ];
        if let Some(n) = custody_len {
            props.push((property::CUSTODY_LEN, CanonicalScalar::Int(n)));
        }
        props.sort_by_key(|(k, _)| k.0);
        let mut batch = fgdb::WriteBatch::new(relation::CUSTODY_OF);
        batch.create_vertex(document_vid(&doc.oid()), vec![label::DOCUMENT], props);
        self.write_raw(batch);
    }

    /// Write a custody event outside every law, with every mirror right.
    fn write_event_raw(&mut self, event: &fa_journal::CustodyEvent) {
        use fa_model::symbols::label;
        let vid = fa_journal::custody::custody_vid(event.book_id, &event.document_oid, event.index);
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(event.canonical_bytes().unwrap()).unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(event.digest().unwrap().to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(event.book_id.0.to_vec()).unwrap(),
            ),
        ];
        props.sort_by_key(|(k, _)| k.0);
        let event_label = if event.index == 0 {
            label::IMPORT_RECEIPT
        } else {
            label::CUSTODY_TRANSFER
        };
        let mut batch = fgdb::WriteBatch::new(relation::CUSTODY_OF);
        batch.create_vertex(vid, vec![event_label], props);
        self.write_raw(batch);
    }

    fn set_custody_len(&mut self, oid: &Oid, n: i64) {
        let mut batch = fgdb::WriteBatch::new(relation::CUSTODY_OF);
        batch.set_vertex_property(
            document_vid(oid),
            property::CUSTODY_LEN,
            Some(CanonicalScalar::Int(n)),
        );
        self.write_raw(batch);
    }
}

fn receipt_event(doc: &Document, source: fa_model::IntakeSource) -> fa_journal::CustodyEvent {
    fa_journal::CustodyEvent {
        book_id: doc.book_id,
        document_oid: doc.oid(),
        index: 0,
        prev_digest: [0; 32],
        body: fa_journal::CustodyBody::Receipt {
            source,
            received_by: doc.retrieved_by,
            digest_at_receipt: doc.doc_commit(),
            run_ref: None,
        },
    }
}

#[test]
fn every_intake_writes_its_receipt_and_custody_passes_only_from_its_holder() {
    use fa_journal::CustodyBody;
    use fa_journal::custody::custody_vid;
    let mut h = harness();
    let doc = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 801 (custody fixture)");
    let added = h.add_document(&doc).expect("admitted");
    let oid = doc.oid();

    // Intake wrote custody event 0 in the same commit, linked to the document.
    let chain = custody_chain(&h.db, &oid).unwrap();
    eprintln!(
        "txf custody: intake {} -> chain of {} at {:?}",
        fa_journal::evidence::hex(&oid.0),
        chain.len(),
        added.recorded_at
    );
    assert_eq!(chain.len(), 1);
    assert_eq!(
        chain[0].1, added.recorded_at,
        "receipt and document commit together"
    );
    assert_eq!(
        chain[0].0.body,
        CustodyBody::Receipt {
            source: fa_model::IntakeSource::Upload {
                principal: PRINCIPAL
            },
            received_by: PRINCIPAL,
            digest_at_receipt: doc.doc_commit(),
            run_ref: None,
        }
    );
    let receipt = custody_vid(h.book.book_id, &oid, 0);
    assert!(
        h.db.edge(edge_id(relation::CUSTODY_OF, receipt, document_vid(&oid)))
            .unwrap()
            .is_some()
    );
    // A repeat intake is the recorded outcome: still one receipt.
    assert!(h.add_document(&doc).expect("recorded").already_recorded);
    assert_eq!(custody_chain(&h.db, &oid).unwrap().len(), 1);

    // The holder hands it on: event 1, chained to the receipt.
    let moved = h
        .transfer(PRINCIPAL, oid, PRINCIPAL, REVIEWER)
        .expect("recorded");
    eprintln!(
        "txf custody: transfer 7 -> 8 recorded as event {}",
        moved.index
    );
    assert_eq!(moved.index, 1);
    let chain = custody_chain(&h.db, &oid).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].0.prev_digest, chain[0].0.digest().unwrap());
    assert_eq!(chain[1].0.holder(), REVIEWER);

    // The former holder can no longer hand it on (SoD-class refusal, exit 7);
    // a capability that is not `from`'s is refused before any read.
    let r = h
        .transfer(PRINCIPAL, oid, PRINCIPAL, OTHER_REVIEWER)
        .unwrap_err();
    eprintln!(
        "txf custody: transfer by a former holder -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-119", exit::SAFETY), "{r}");
    let r = h
        .transfer(PRINCIPAL, oid, REVIEWER, OTHER_REVIEWER)
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-011", "{r}");
    assert_eq!(
        custody_chain(&h.db, &oid).unwrap().len(),
        2,
        "nothing written"
    );

    // A complete two-event chain is citable.
    let posted = h.post_citing(&doc, b"txf-custody-ok");
    eprintln!("txf custody: post citing it -> {posted:?}");
    assert!(matches!(posted, Ok(Posted::Committed { .. })), "{posted:?}");
}

#[test]
fn a_document_without_a_complete_custody_chain_cannot_be_cited() {
    use fa_model::IntakeSource;
    let mut h = harness();

    // (a) A document with no receipt at all.
    let bare = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 811 (no receipt)");
    h.write_document_raw(&bare, None);
    // (b) A chain whose length says 2 but whose link 1 was never written.
    let gap = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 812 (missing link)");
    h.add_document(&gap).expect("admitted");
    h.set_custody_len(&gap.oid(), 2);
    // (c) A transfer that does not chain to the receipt.
    let unchained = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 813 (unchained)");
    h.add_document(&unchained).expect("admitted");
    h.write_event_raw(&fa_journal::CustodyEvent {
        book_id: unchained.book_id,
        document_oid: unchained.oid(),
        index: 1,
        prev_digest: [0xab; 32],
        body: fa_journal::CustodyBody::Transfer {
            from: PRINCIPAL,
            to: REVIEWER,
        },
    });
    h.set_custody_len(&unchained.oid(), 2);
    // (d) A receipt from a connector this book does not register.
    let foreign = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 814 (unregistered source)");
    h.write_document_raw(&foreign, Some(1));
    h.write_event_raw(&receipt_event(
        &foreign,
        IntakeSource::Connector {
            name: "bank-feed".into(),
            version: "1".into(),
        },
    ));
    // (e) A transfer recorded by a principal that did not hold it.
    let stolen = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 815 (not the holder)");
    h.add_document(&stolen).expect("admitted");
    let receipt = receipt_event(
        &stolen,
        IntakeSource::Upload {
            principal: PRINCIPAL,
        },
    );
    h.write_event_raw(&fa_journal::CustodyEvent {
        index: 1,
        prev_digest: receipt.digest().unwrap(),
        body: fa_journal::CustodyBody::Transfer {
            from: OTHER_REVIEWER,
            to: REVIEWER,
        },
        ..receipt
    });
    h.set_custody_len(&stolen.oid(), 2);

    for (doc, key, link, why) in [
        (&bare, b"txf-bare" as &[u8], "link 0", "no ImportReceipt"),
        (&gap, b"txf-gap", "link 1", "is missing"),
        (&unchained, b"txf-unchained", "link 1", "does not chain"),
        (&foreign, b"txf-foreign", "link 0", "unregistered source"),
        (&stolen, b"txf-stolen", "link 1", "did not hold"),
    ] {
        let r = h.post_citing(doc, key).unwrap_err();
        eprintln!(
            "txf custody: citing a broken chain -> {} {}",
            r.code, r.message
        );
        assert_eq!((r.code, r.exit), ("FA-REF-114", exit::REFUSAL), "{r}");
        assert!(r.message.contains(link), "{}", r.message);
        assert!(r.message.contains(why), "{}", r.message);
        assert!(entry_absent(&h, key));
    }
    // An intact document beside them still posts.
    let intact = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 816 (intact)");
    h.add_document(&intact).expect("admitted");
    assert!(matches!(
        h.post_citing(&intact, b"txf-intact"),
        Ok(Posted::Committed { .. })
    ));
}

#[test]
fn an_import_run_records_its_documents_under_a_receipt_that_recomputes() {
    use fa_journal::CustodyBody;
    use fa_journal::import::oids_root;
    use fa_model::IntakeSource;
    let mut h = harness();
    let connector = IntakeSource::Connector {
        name: "fa-import".into(),
        version: "1".into(),
    };
    let held = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 901 (already held)");
    h.add_document(&held).expect("admitted");
    let docs: Vec<Document> = [
        b"INVOICE 902 (imported)" as &[u8],
        b"INVOICE 903 (imported)",
        b"RECEIPT 904 (imported)",
    ]
    .iter()
    .map(|b| h.document(INVOICE, HUMAN_UPLOAD, b))
    .chain([held.clone()])
    .collect();
    let importer = Capability::embedded(PRINCIPAL, &["post"]).expect("post");

    let run = h
        .import(&importer, connector.clone(), b"run-1", docs.clone())
        .expect("recorded");
    let mut oids: Vec<Oid> = docs.iter().map(Document::oid).collect();
    oids.sort();
    eprintln!(
        "txf import: run {:032x} -> {} documents, {} bytes, root {}, receipt {}",
        run.receipt.run.0,
        run.receipt.document_count,
        run.receipt.byte_count,
        fa_journal::evidence::hex(&run.receipt.oids_root),
        fa_journal::evidence::hex(&run.receipt.receipt_hash)
    );
    assert_eq!(run.receipt.document_count, 4);
    let bytes: u64 = docs.iter().map(|d| d.bytes.len() as u64).sum();
    assert_eq!(run.receipt.byte_count, bytes);
    assert_eq!(run.receipt.oids_root, oids_root(&oids));
    assert_eq!(run.already_held, vec![held.oid()]);
    assert_eq!(run.recorded.len(), 3);
    assert!(verify_receipt(&run.receipt, h.book.book_id, &oids).is_ok());
    // The journal binds what the hash does not: the sequence that recorded
    // the run. A receipt shifted only in `recorded_at` passes the offline
    // check (no claim) and is refused against the journal (exit 8).
    assert_eq!(
        verify_receipt_in(&h.db, h.book.book_id, &run.receipt, &oids).unwrap(),
        Ok(())
    );
    let shifted = fa_journal::RunReceipt {
        recorded_at: fgdb_types::CommitSeq(run.receipt.recorded_at.0 + 1),
        ..run.receipt.clone()
    };
    assert!(verify_receipt(&shifted, h.book.book_id, &oids).is_ok());
    let r = verify_receipt_in(&h.db, h.book.book_id, &shifted, &oids)
        .unwrap()
        .unwrap_err();
    eprintln!(
        "txf import: a receipt with recorded_at shifted -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-115", exit::VERIFICATION), "{r}");
    assert!(
        r.message.contains(&format!(
            "recorded at sequence {}",
            run.receipt.recorded_at.0
        )),
        "{r}"
    );
    let elsewhere = fa_journal::RunReceipt {
        run: fgdb_types::VId(0xabc),
        ..run.receipt.clone()
    };
    let r = verify_receipt_in(&h.db, h.book.book_id, &elsewhere, &oids)
        .unwrap()
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-115", "{r}");
    assert_eq!(
        fa_journal::import::read_run(&h.db, run.receipt.run).unwrap(),
        Some(run.receipt.clone())
    );

    // A tampered, short, or reordered oid list does not verify (exit 8).
    let mut tampered = oids.clone();
    tampered[1].0[0] ^= 1;
    let mut reordered = oids.clone();
    reordered.swap(0, 1);
    for (what, list) in [
        ("tampered", tampered),
        ("short", oids[..3].to_vec()),
        ("reordered", reordered),
    ] {
        let r = verify_receipt(&run.receipt, h.book.book_id, &list).unwrap_err();
        eprintln!("txf import: a {what} oid list -> {} {}", r.code, r.message);
        assert_eq!((r.code, r.exit), ("FA-REF-115", exit::VERIFICATION));
    }

    // Each recorded document's receipt names the run and its source; the
    // already-held one keeps its upload receipt.
    for oid in &run.recorded {
        let chain = custody_chain(&h.db, oid).unwrap();
        let receipt_of = match &chain[0].0.body {
            CustodyBody::Receipt {
                source, run_ref, ..
            } => Some((source.clone(), *run_ref)),
            CustodyBody::Transfer { .. } => None,
        };
        let (source, run_ref) = receipt_of.expect("custody event 0 is a receipt");
        assert_eq!(
            (source, run_ref),
            (connector.clone(), Some(run.receipt.run))
        );
        let receipt = fa_journal::custody::custody_vid(h.book.book_id, oid, 0);
        assert!(
            h.db.edge(edge_id(relation::IMPORTED_BY, receipt, run.receipt.run))
                .unwrap()
                .is_some()
        );
    }
    assert!(matches!(
        &custody_chain(&h.db, &held.oid()).unwrap()[0].0.body,
        CustodyBody::Receipt { run_ref: None, .. }
    ));
    // An imported document is citable through its run's receipt.
    let imported = docs.iter().find(|d| d.oid() == run.recorded[0]).unwrap();
    assert!(matches!(
        h.post_citing(imported, b"txf-imported"),
        Ok(Posted::Committed { .. })
    ));

    // The same run again is its recorded receipt; another under the key is 032.
    let again = h
        .import(&importer, connector.clone(), b"run-1", docs.clone())
        .expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(again.receipt, run.receipt);
    let r = h
        .import(&importer, connector.clone(), b"run-1", docs[..2].to_vec())
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT), "{r}");

    // Refused before any read: an unregistered source, a repeated document,
    // an empty run, an Agent on trunk, a principal without `post`.
    let fresh = |b: &[u8]| h.document(INVOICE, HUMAN_UPLOAD, b);
    let one = vec![fresh(b"INVOICE 905")];
    let cases: Vec<(&str, Capability, IntakeSource, Vec<Document>, &str)> = vec![
        (
            "unregistered connector",
            importer.clone(),
            IntakeSource::Connector {
                name: "bank-feed".into(),
                version: "1".into(),
            },
            one.clone(),
            "FA-REF-083",
        ),
        (
            "unregistered device",
            importer.clone(),
            IntakeSource::Scan {
                device: "office-scanner".into(),
            },
            one.clone(),
            "FA-REF-083",
        ),
        (
            "a repeated document",
            importer.clone(),
            connector.clone(),
            vec![one[0].clone(), one[0].clone()],
            "FA-REF-100",
        ),
        (
            "an empty run",
            importer.clone(),
            connector.clone(),
            Vec::new(),
            "FA-REF-100",
        ),
        (
            "an agent on trunk",
            fa_policy::Capability::new(
                PRINCIPAL,
                fa_policy::Profile::Agent,
                &[fa_policy::Op::Post],
                PRINCIPAL,
            )
            .unwrap(),
            connector.clone(),
            one.clone(),
            "FA-REF-013",
        ),
        (
            "no post op",
            Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
            connector.clone(),
            one.clone(),
            "FA-REF-011",
        ),
    ];
    for (i, (what, cap, source, docs, code)) in cases.into_iter().enumerate() {
        let key = format!("run-bad-{i}");
        let r = h.import(&cap, source, key.as_bytes(), docs).unwrap_err();
        eprintln!("txf import: {what} -> {} {}", r.code, r.message);
        assert_eq!(r.code, code, "{what}: {r}");
    }
    assert!(
        custody_chain(&h.db, &one[0].oid()).unwrap().is_empty(),
        "nothing written"
    );
}
