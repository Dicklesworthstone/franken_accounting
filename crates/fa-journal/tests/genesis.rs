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
    Document, DocumentAdded, EvidenceAttached, Storage, SupplementalEvidence, add_document,
    add_document_external, attach_evidence, document_record, document_vid, fetch_document,
    read_document, supplements_of,
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

#[path = "genesis/account_role.rs"]
mod account_role_tests;
#[path = "genesis/carrying.rs"]
mod carrying_tests;
#[path = "genesis/closing_carrying.rs"]
mod closing_carrying_tests;
#[path = "genesis/external_subledger.rs"]
mod external_subledger_tests;
#[path = "genesis/fx_law.rs"]
mod fx_law_tests;
#[path = "genesis/outcome_batch_integrity.rs"]
mod outcome_batch_integrity_tests;
#[path = "genesis/outcome_keys.rs"]
mod outcome_key_tests;
#[path = "genesis/recurring.rs"]
mod recurring_tests;
#[path = "genesis/register_capacity.rs"]
mod register_capacity;
#[path = "genesis/scheduled_admission.rs"]
mod scheduled_admission_tests;
#[path = "genesis/subledger.rs"]
mod subledger_tests;

#[path = "genesis/outcome_recovery.rs"]
mod outcome_recovery_tests;

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
    legacy_storage: Option<(MemVfs, DatabaseKeys)>,
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

    fn post_pair(
        &mut self,
        reversal: PostRequest,
        replacement: PostRequest,
    ) -> Result<(Posted, Posted), Refusal> {
        let ctx = self.ctx();
        self.runtime
            .block_on(fa_journal::post::post_replacement_pair(
                &mut self.db,
                &ctx,
                &self.book,
                reversal,
                replacement,
            ))
            .expect("kernel")
    }

    fn transition(
        &mut self,
        code: &str,
        t: PeriodTransition,
        key: &[u8],
    ) -> Result<Transitioned, Refusal> {
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
                let period =
                    fa_journal::policy::calendar_period(&self.book, code).expect("calendar period");
                let digest = transition_proposal(
                    &self.book,
                    &period,
                    from,
                    to,
                    PRINCIPAL,
                    1,
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
                    key,
                    description,
                    &Capability::embedded(PRINCIPAL, &["close", "reopen", "post"]).expect("ops"),
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

fn replacement_proposal(target: EntryRef, mut proposal: EntryPayload) -> EntryPayload {
    proposal.class = EntryClass::REPLACEMENT;
    proposal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Replaces,
        reason_code: 1,
    }];
    proposal
}

fn harness() -> Harness {
    harness_with_entities(Vec::new())
}

fn harness_with_entities(entities: Vec<LegalEntitySpec>) -> Harness {
    harness_configured(entities, None, None)
}

fn harness_configured(
    entities: Vec<LegalEntitySpec>,
    time_zone_policy: Option<TimeZonePolicy>,
    cash_limit: Option<BalanceLimit>,
) -> Harness {
    harness_configured_coverage(entities, time_zone_policy, cash_limit, true)
}

fn harness_legacy() -> Harness {
    harness_configured_coverage(Vec::new(), None, None, false)
}

fn harness_configured_coverage(
    entities: Vec<LegalEntitySpec>,
    time_zone_policy: Option<TimeZonePolicy>,
    cash_limit: Option<BalanceLimit>,
    coverage: bool,
) -> Harness {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x5a; 32],
        DatabaseSecurityNamespaceId([0x5b; 32]),
        [0x5c; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys.clone()).await })
        .expect("open");
    let mut legacy_storage = None;

    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([9; 16]);
    let spec = BookSpec {
        book_id,
        name: "Test Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy,
        entities,
        opening_date: None,
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
        .expect("create_book");
    if !coverage {
        // Reconstruct a separate original pre-protocol genesis. Never
        // delete or relabel the modern immutable marker to fake old history.
        let coverage_vid = fa_journal::outcome::coverage_vid(book_id);
        let mut rows = db.vertices().unwrap();
        assert_eq!(rows.iter().filter(|row| row.vid == coverage_vid).count(), 1);
        rows.retain(|row| row.vid != coverage_vid);
        rows.sort_by_key(|row| row.birth_ordinal);
        let mut vertices = fgdb::WriteBatch::new(relation::IN_BOOK);
        for row in rows {
            assert!(
                row.labels
                    .iter()
                    .all(|label| *label != fa_model::symbols::label::ENTRY)
            );
            vertices.create_vertex(row.vid, row.labels, row.props);
        }
        let mut edges = std::collections::BTreeMap::new();
        for edge in db.edges_at(db.frontier().unwrap()).unwrap() {
            edges
                .entry(edge.entry.relation)
                .or_insert_with(|| fgdb::WriteBatch::new(edge.entry.relation))
                .add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
        }
        let vfs = ctx.commit().with_restriction(MemVfs::new).unwrap();
        let mut legacy = runtime
            .block_on(Database::create_with_vfs(
                &ctx.commit(),
                vfs.clone(),
                vfs.database_dir(),
                keys.clone(),
            ))
            .unwrap();
        let mut txn = legacy.begin(&ctx.txn()).unwrap();
        let mut stages = vec![vertices];
        stages.extend(edges.into_values());
        txn.write_ordered(&mut legacy, stages).unwrap();
        runtime
            .block_on(txn.commit(&mut legacy, &ctx.commit()))
            .unwrap();
        legacy_storage = Some((vfs, keys));
        db = legacy;
    }
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
            limit: cash_limit,
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
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
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
        .block_on(async {
            create_periods(
                &mut db,
                &ctx,
                &book,
                2026,
                PRINCIPAL,
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("periods")
        .expect("admitted");
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
        legacy_storage,
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
fn schema_valid_bulk_entry_exposes_native_row_capacity_without_partial_publication() {
    // fa-fdt: reproduce the current storage gap, not a smaller accounting
    // limit. When the representation is repaired, replace the refusal below
    // with the bead's post/reopen/fold/certify/verify positive acceptance.
    let mut h = harness();
    let key = b"bulk-capacity";
    let legs = (0..256).flat_map(|_| h.rent_legs(1)).collect::<Vec<_>>();
    assert_eq!(legs.len(), 512);
    assert!(legs.len() < fa_model::limits::MAX_LEGS_PER_ENTRY);
    let proposal = h.proposal(legs, key, EntryClass::ORIGINAL);
    let expected = proposal.clone().seal(Vec::new(), None).unwrap();
    let bytes = expected.encode().unwrap();
    assert!(bytes.len() > 16 * 1024);
    assert!(bytes.len() < fa_model::limits::MAX_ENTRY_BYTES);
    assert_eq!(fa_model::Entry::decode(&bytes).unwrap(), expected);

    let vid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    let before = h.db.frontier().unwrap();
    // Call the kernel directly: Harness::post intentionally unwraps its
    // foundation result, whereas this defect is native storage admission.
    for _ in 0..2 {
        let req = h.request(proposal.clone(), &["post"]);
        let ctx = h.ctx();
        let result = h.runtime.block_on(post(&mut h.db, &ctx, &h.book, req));
        let error = result.expect_err("the pinned native row cannot store this entry");
        let KernelError::Txn(fgdb::WriteTxnError::Write(
            fgdb::WriteError::VertexStorageAdmission {
                vid: rejected,
                source,
            },
        )) = error
        else {
            panic!("expected the native entry-row capacity failure, got {error:?}");
        };
        assert_eq!(rejected, vid);
        let diagnostic = source.to_string();
        let (stored_bytes, limit) = diagnostic
            .strip_prefix("vertex row needs ")
            .and_then(|s| s.split_once(" stored bytes; admission limit is "))
            .expect("RowExceedsStorageLimit diagnostic");
        assert_eq!(limit, "16384");
        assert!(stored_bytes.parse::<usize>().unwrap() > 16 * 1024);
        eprintln!(
            "fa-fdt: 512 schema-valid legs, {} payload bytes: {diagnostic}",
            bytes.len()
        );
        assert_eq!(h.db.frontier().unwrap(), before);
        assert!(read_entry(&h.db, vid).unwrap().is_none());
        for ordinal in 0..512 {
            let leg = leg_vid(vid, ordinal);
            assert!(h.db.vertex(leg).unwrap().is_none());
            assert!(
                h.db.edge(edge_id(relation::HAS_LEG, vid, leg))
                    .unwrap()
                    .is_none()
            );
        }
    }

    // The failed attempt spends neither the journal identity nor its key.
    // The same real evidence and capability admit a smaller balanced entry,
    // whose exact retry returns that outcome without another commit.
    let small = h.proposal(h.rent_legs(256), key, EntryClass::ORIGINAL);
    let small_expected = small.clone().seal(Vec::new(), None).unwrap();
    let posted = h.post(h.request(small.clone(), &["post"])).unwrap();
    assert!(matches!(posted, Posted::Committed { .. }));
    assert_eq!(posted.entry_ref().vid, vid);
    let (back, recorded_at) = read_entry(&h.db, vid).unwrap().unwrap();
    assert_eq!(back, small_expected);
    assert_eq!(recorded_at, posted.recorded_at());
    let after = h.db.frontier().unwrap();
    let retried = h.post(h.request(small, &["post"])).unwrap();
    assert!(matches!(retried, Posted::AlreadyRecorded { .. }));
    assert_eq!(retried.entry_ref(), posted.entry_ref());
    assert_eq!(retried.recorded_at(), posted.recorded_at());
    assert_eq!(h.db.frontier().unwrap(), after);
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
    // The fix names exactly the posted classes the matrix admits here
    // (fa-l93 D8), each with the op its cell requires.
    assert_eq!(
        r.fix,
        "keep the entry's true effective date; never re-date it to escape the period law: a Closed period admits Adjusting (with `post_closed` and 1 approval), Closing (with `close` and 1 approval), Reclassification (with `post_closed` and 1 approval), Reversal (with `post_closed`); a reopen of a Closed period is case-bound and refused in this build; `fa period list --json` shows each period's state"
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
fn reversals_cannot_precede_the_target_period_but_may_use_an_earlier_day_in_it() {
    let mut h = harness();
    h.transition("FY2026-P04", PeriodTransition::Open, b"open-april-order")
        .unwrap();
    h.transition("FY2026-P05", PeriodTransition::Open, b"open-may-order")
        .unwrap();
    for (index, date) in ["2026-04-01", "2026-05-01"].into_iter().enumerate() {
        let mut original = h.proposal(
            h.rent_legs(700),
            format!("ordered-original-{index}").as_bytes(),
            EntryClass::ORIGINAL,
        );
        original.effective_date = DateDay::parse("2026-04-15").unwrap();
        let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
        let mut reversal =
            h.reversal_of(target, 700, format!("ordered-reversal-{index}").as_bytes());
        reversal.effective_date = DateDay::parse("2026-03-31").unwrap();
        let head = h.db.frontier().unwrap();
        let refusal = h.post(h.request(reversal.clone(), &["post"])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-053", exit::REFUSAL));
        assert!(refusal.fix.contains("FY2026-P04"));
        assert_eq!(
            h.db.frontier().unwrap(),
            head,
            "an invalid reversal wrote nothing"
        );
        reversal.effective_date = DateDay::parse(date).unwrap();
        let posted = h.post(h.request(reversal, &["post"])).unwrap();
        assert!(matches!(posted, Posted::Committed { .. }), "{date}");
    }
}

#[test]
fn special_period_classes_and_reversal_order_are_enforced_even_on_shared_dates() {
    let mut h = harness();
    h.transition("FY2026-P12", PeriodTransition::Open, b"open-december-order")
        .unwrap();
    for (code, day) in [
        ("FY2026-OPEN", "2026-01-01"),
        ("FY2026-A1", "2026-12-31"),
        ("FY2026-CLOSE", "2026-12-31"),
    ] {
        h.transition(code, PeriodTransition::Open, code.as_bytes())
            .unwrap();
        for class in [EntryClass::ORIGINAL, EntryClass::PENDING] {
            let key = format!("special-{code}-{}", class.0);
            let mut proposal = if class == EntryClass::PENDING {
                h.pending(h.rent_legs(50), key.as_bytes())
            } else {
                h.proposal(h.rent_legs(50), key.as_bytes(), class)
            };
            proposal.effective_date = DateDay::parse(day).unwrap();
            proposal.effective_period = Some(fa_model::PeriodRef {
                calendar: "cal".into(),
                code: code.into(),
            });
            let head = h.db.frontier().unwrap();
            let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-010", exit::SAFETY));
            assert!(refusal.message.contains(code));
            assert_eq!(h.db.frontier().unwrap(), head);
        }
        let mut adjusting = h.proposal(
            h.rent_legs(50),
            format!("adjust-{code}").as_bytes(),
            EntryClass::ADJUSTING,
        );
        adjusting.effective_date = DateDay::parse(day).unwrap();
        adjusting.effective_period = Some(fa_model::PeriodRef {
            calendar: "cal".into(),
            code: code.into(),
        });
        let original = h.post(h.request(adjusting, &["post"])).unwrap().entry_ref();
        if code == "FY2026-OPEN" {
            h.transition("FY2026-P01", PeriodTransition::Open, b"open-january-order")
                .unwrap();
            let mut reversal = h.reversal_of(original, 50, b"reverse-opening-in-normal");
            reversal.effective_date = DateDay::parse("2026-01-02").unwrap();
            assert!(matches!(
                h.post(h.request(reversal, &["post"])).unwrap(),
                Posted::Committed { .. }
            ));
        }
        if code == "FY2026-A1" {
            // P12 and A1 share December 31; calendar ordinal, not date,
            // prevents the reversal from predating the adjusting entry.
            let mut reversal = h.reversal_of(original, 50, b"shared-day-reversal");
            reversal.effective_date = DateDay::parse("2026-12-31").unwrap();
            let head = h.db.frontier().unwrap();
            let refusal = h.post(h.request(reversal.clone(), &["post"])).unwrap_err();
            assert_eq!(refusal.code, "FA-REF-053");
            assert_eq!(h.db.frontier().unwrap(), head);
            reversal.effective_period = Some(fa_model::PeriodRef {
                calendar: "cal".into(),
                code: code.into(),
            });
            assert_eq!(
                h.post(h.request(reversal.clone(), &["post"]))
                    .unwrap_err()
                    .code,
                "FA-REF-010"
            );
            let ctx = h.ctx();
            h.runtime
                .block_on(create_periods(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    2027,
                    PRINCIPAL,
                    fa_model::Erasable::seal(
                        &"periods".to_string(),
                        None,
                        &h.book.seal_key,
                        [1; 32],
                        [2; 24],
                    ),
                    &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                ))
                .unwrap()
                .unwrap();
            h.transition(
                "FY2027-P01",
                PeriodTransition::Open,
                b"open-next-year-order",
            )
            .unwrap();
            reversal.effective_date = DateDay::parse("2027-01-01").unwrap();
            reversal.effective_period = None;
            assert!(matches!(
                h.post(h.request(reversal, &["post"])).unwrap(),
                Posted::Committed { .. }
            ));
        }
    }
}

#[test]
fn corrections_require_registered_reasons_and_other_requires_particulars() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(h.rent_legs(80), b"reason-original", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let before = read_entry(&h.db, original.vid).unwrap().unwrap();
    let mut reversal = h.reversal_of(original, 80, b"reason-reversal");
    // 12 is ScheduledAccrualReversal: reserved for the kernel's own scheduled
    // reversal, never a manual reason (fa-cvg).
    for reason in [0, 12, u16::MAX] {
        reversal.supersession[0].reason_code = reason;
        let head = h.db.frontier().unwrap();
        let refusal = h.post(h.request(reversal.clone(), &["post"])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-054", exit::REFUSAL));
        assert!(refusal.fix.contains("WrongAccount"));
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    reversal.supersession[0].reason_code = 11;
    reversal.description = Erasable::seal(
        &" \t\n".to_string(),
        None,
        &h.book.seal_key,
        [11; 32],
        [12; 24],
    );
    assert_eq!(
        h.post(h.request(reversal.clone(), &["post"]))
            .unwrap_err()
            .code,
        "FA-REF-054"
    );
    reversal.description = Erasable::seal(
        &"Customer withdrew the order before fulfilment".to_string(),
        None,
        &h.book.seal_key,
        [13; 32],
        [14; 24],
    );
    let posted = h.post(h.request(reversal.clone(), &["post"])).unwrap();
    assert_eq!(
        read_entry(&h.db, posted.entry_ref().vid)
            .unwrap()
            .unwrap()
            .0
            .proposal
            .supersession[0]
            .reason_code,
        11
    );
    assert_eq!(
        read_entry(&h.db, original.vid).unwrap().unwrap(),
        before,
        "the original is immutable"
    );
    let head = h.db.frontier().unwrap();
    assert!(matches!(
        h.post(h.request(reversal.clone(), &["post"])).unwrap(),
        Posted::AlreadyRecorded { .. }
    ));
    reversal.supersession[0].reason_code = 2;
    assert_eq!(
        h.post(h.request(reversal, &["post"])).unwrap_err().code,
        "FA-REF-052"
    );
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "retry and changed reason wrote nothing"
    );
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

/// fa-l93 D13 (FA-INV-09): an identical period-transition retry returns
/// the recorded outcome and writes nothing; a new key, or the same key
/// naming another transition, is still the state machine's refusal.
#[test]
fn an_identical_period_transition_retry_returns_the_recorded_outcome() {
    let mut h = harness();
    let march = h.march.clone();
    // The harness's last commit opened March under the key `open-march`.
    let head = h.db.frontier().unwrap();
    let again = h
        .transition(&march, PeriodTransition::Open, b"open-march")
        .expect("an identical retry is the recorded outcome");
    assert!(again.already_recorded);
    assert_eq!(
        (again.from, again.to),
        (PeriodState::Future, PeriodState::Open)
    );
    assert_eq!(again.recorded_at, head);
    assert_eq!(
        again.control_entry,
        entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"open-march")
    );
    assert!(again.minted.is_empty() && again.blocked.is_empty());
    assert_eq!(h.db.frontier().unwrap(), head, "nothing new was written");

    let r = h
        .transition(&march, PeriodTransition::Open, b"open-march-again")
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-040", "a new key is a new request: {r}");
    let r = h
        .transition(&march, PeriodTransition::Lock, b"open-march")
        .unwrap_err();
    assert_eq!(
        r.code, "FA-REF-040",
        "the key names another transition: {r}"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

/// fa-ih4: lawful requests ahead of the book's setup are typed refusals,
/// never `KernelError::Corrupt` (exit 5): a date in a fiscal year nobody
/// created, and a raw unit id no registered unit version carries on an
/// account whose policy admits any unit. Nothing is written either way.
#[test]
fn uncreated_periods_and_unregistered_units_are_refused_not_corrupt() {
    let mut h = harness();
    let head = h.db.frontier().unwrap();

    let mut ahead = h.proposal(h.rent_legs(100), b"ahead", EntryClass::ORIGINAL);
    ahead.effective_date = DateDay::from_ymd(2028, 2, 10).unwrap();
    let r = h.post(h.request(ahead, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-021", exit::SAFETY), "{r}");
    assert!(r.message.contains("FY2028-P02"), "{r}");
    assert_eq!(
        r.fix,
        "fa period create --fiscal-year 2028, then fa period open FY2028-P02"
    );
    assert_eq!(h.db.frontier().unwrap(), head);

    let any_unit = |code: &str| AccountSpec {
        code: code.into(),
        name: format!("Clearing {code}"),
        account_type: 1,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::AnyUnit,
        parent_code: None,
        limit: None,
    };
    let ctx = h.ctx();
    let day = h.day();
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &[any_unit("9100"), any_unit("9200")],
            PRINCIPAL,
            day,
            b"chart-any-unit",
            Erasable::seal(
                &"clearing".to_string(),
                None,
                &h.book.seal_key,
                [7; 32],
                [8; 24],
            ),
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .expect("kernel")
        .expect("the clearing accounts install");
    let head = h.db.frontier().unwrap();
    let unregistered = UnitId(4242);
    assert!(h.book.units.get(unregistered).is_none());
    let (debit, credit) = (
        account_vid(h.book.book_id, "9100"),
        account_vid(h.book.book_id, "9200"),
    );
    let legs = vec![
        LegPayload::simple(Side::Debit, debit, Amount::new(unregistered, 100)),
        LegPayload::simple(Side::Credit, credit, Amount::new(unregistered, 100)),
    ];
    let r = h
        .post(h.request(
            h.proposal(legs, b"raw-unit", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-154", exit::REFUSAL), "{r}");
    assert!(r.message.contains("unit id 4242"), "{r}");
    assert_eq!(h.db.frontier().unwrap(), head);

    // The same accounts accept a registered unit of any kind.
    let legs = vec![
        LegPayload::simple(Side::Debit, debit, Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, credit, Amount::new(h.usd, 100)),
    ];
    assert!(matches!(
        h.post(h.request(
            h.proposal(legs, b"usd-clearing", EntryClass::ORIGINAL),
            &["post"]
        ))
        .unwrap(),
        Posted::Committed { .. }
    ));

    // fa-l93 D9: a leg naming a live vertex that is not an Account (here
    // the book root) is the unknown-account refusal, not a corrupt row.
    let head = h.db.frontier().unwrap();
    let legs = vec![
        LegPayload::simple(Side::Debit, book_root(), Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 100)),
    ];
    let r = h
        .post(h.request(
            h.proposal(legs, b"not-an-account", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-004", exit::REFUSAL), "{r}");
    assert!(r.message.contains("not an account"), "{r}");
    assert_eq!(h.db.frontier().unwrap(), head);
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

    // A Replacement posts only paired with its Reversal in one batch
    // (FA-INV-08.replacement-paired); alone it is refused.
    let r = h
        .post(h.request(
            h.proposal(h.rent_legs(1), b"cls", EntryClass::REPLACEMENT),
            &["post", "post_closed", "restate", "migrate"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-160", exit::REFUSAL), "{r}");
    assert!(r.message.contains("paired Reversal"), "{r}");
    assert!(r.fix.contains("fa reverse <target vid>"), "{r}");
    // A registered class this slice does not enforce is refused, naming its bead.
    let r = h
        .post(h.request(
            h.proposal(h.rent_legs(1), b"cls", EntryClass::CLOSING),
            &["post", "post_closed", "restate", "migrate"],
        ))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-102", exit::REFUSAL), "{r}");
    assert!(
        r.fix.contains("fa-") || r.fix.contains("plan §"),
        "{}",
        r.fix
    );
    // A PriorPeriodAdjustment is a restatement case's entry (fa-75j4): alone,
    // or claiming a case on any path but the case's own Post, it is refused,
    // and no other class may claim a case.
    let claim = CaseMember {
        ordinal: 1,
        plan: VId(9),
    }
    .canonical_bytes()
    .unwrap();
    let mut claimed = h.proposal(
        h.rent_legs(1),
        b"ppa-claimed",
        EntryClass::PRIOR_PERIOD_ADJUSTMENT,
    );
    claimed.schema_minor = fa_model::entry::SCHEMA_MINOR;
    claimed.extensions = vec![(fa_model::entry::CASE_MEMBER_EXTENSION, claim.clone())];
    let mut stray = h.proposal(h.rent_legs(1), b"stray-claim", EntryClass::ORIGINAL);
    stray.schema_minor = fa_model::entry::SCHEMA_MINOR;
    stray.extensions = vec![(fa_model::entry::CASE_MEMBER_EXTENSION, claim)];
    let alone = h.proposal(h.rent_legs(1), b"ppa", EntryClass::PRIOR_PERIOD_ADJUSTMENT);
    // A Revision, too, posts only as its Revision case's entry (slice 4b),
    // and a Restatement only as its Restatement case's (fa-651f).
    let revision = h.proposal(h.rent_legs(1), b"revision", EntryClass::REVISION);
    let restatement = h.proposal(h.rent_legs(1), b"restatement", EntryClass::RESTATEMENT);
    for (proposal, says) in [
        (alone, "posted only in its case's batch"),
        (revision, "posted only in its case's batch"),
        (restatement, "posted only in its case's batch"),
        (claimed, "posted only in its case's batch"),
        (stray, "only a case-bound entry names a case"),
    ] {
        let r = h
            .post(h.request(proposal, &["post", "restate"]))
            .unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-178", exit::REFUSAL), "{r}");
        assert!(r.message.contains(says), "{r}");
        assert!(r.fix.contains("fa case post"), "{r}");
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
fn unchecked_base_totals_are_refused_before_publication() {
    let mut h = harness();
    let frontier = h.db.frontier().unwrap();
    let native = h.proposal(
        h.rent_legs(10),
        b"unchecked-fx-totals",
        EntryClass::ORIGINAL,
    );
    // Even balanced claimed totals are unsupported without a registered FX
    // law and witnessed rate documents. None of these claims has leg values.
    for (debits, credits) in [(10, 10), (10, 11), (-1, -1)] {
        let mut proposal = native.clone();
        proposal.base_totals = Some(fa_model::BaseTotals {
            unit_id: h.usd.0,
            debits,
            credits,
            fx_law_oid: Oid([0x91; 32]),
            rate_doc_oids: vec![Oid([0x92; 32])],
            residual: Some(fa_model::Residual {
                leg_ordinal: 0,
                amount: Amount::new(h.usd, 1),
            }),
        });
        proposal.validate().expect("structurally encodable claim");
        let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-102", exit::REFUSAL));
        assert!(refusal.message.contains("base_totals"), "{refusal}");
        assert!(refusal.fix.contains("fa-p7r"), "{refusal}");
        assert_eq!(
            h.db.frontier().unwrap(),
            frontier,
            "no unchecked FX publication"
        );
    }
    // Refusing an unsupported valuation must neither disable ordinary native
    // posting nor consume its idempotency key.
    let posted = h
        .post(h.request(native.clone(), &["post"]))
        .expect("native post");
    let (entry_ref, _) = committed(&posted).expect("fresh native commit");
    let (stored, _) = read_entry(&h.db, entry_ref.vid).unwrap().unwrap();
    assert_eq!(stored.proposal, native);
}

#[test]
fn unverified_plan_and_origin_claims_are_refused_without_consuming_identity() {
    let mut h = harness();
    let frontier = h.db.frontier().unwrap();
    let native = h.proposal(
        h.rent_legs(10),
        b"unverified-provenance",
        EntryClass::ORIGINAL,
    );
    let origins = [
        (
            "Sweep",
            EntryOrigin::Sweep {
                sweep_kind: 1,
                tick_evidence_oid: Oid([0x74; 32]),
            },
        ),
        (
            "Schedule",
            EntryOrigin::Schedule {
                schedule_ref: VId(0x75),
                trigger: fa_model::ScheduleTrigger::Sweep {
                    tick_ref: VId(0x76),
                },
            },
        ),
        (
            "Control",
            EntryOrigin::Control {
                control_kind: fa_model::ControlKind::TIME_TICK,
                spec_body_digest: [0x77; 32],
            },
        ),
    ];
    for (name, origin) in origins {
        let mut proposal = native.clone();
        proposal.origin = origin;
        proposal
            .validate()
            .expect("the claim is structurally encodable");
        let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-102", exit::REFUSAL));
        assert!(
            refusal.message.contains(&format!("entry.origin.{name}")),
            "{refusal}"
        );
        assert!(refusal.cite.contains("FA-INV-05"), "{refusal}");
        assert!(!refusal.fix.is_empty(), "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), frontier, "{name}: no publication");
    }
    // A claimed Rule origin is verified rather than refused as minted-only
    // (fa-c34 slice 4): event closure runs first, so a claim citing an event
    // this book never recorded is refused under FA-INV-05's event closure,
    // before the rule version or its re-derivation is consulted.
    let mut claimed = native.clone();
    claimed.origin = EntryOrigin::Rule {
        rule_version_oid: Oid([0x71; 32]),
        event_ref: VId(0x72),
        inputs_digest: [0x73; 32],
    };
    claimed
        .validate()
        .expect("the claim is structurally encodable");
    let refusal = h.post(h.request(claimed, &["post"])).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-080", exit::REFUSAL));
    assert!(
        refusal.message.contains("does not exist in this book"),
        "{refusal}"
    );
    assert!(refusal.cite.contains("FA-INV-05"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), frontier, "Rule: no publication");
    let mut certified = h.request(native.clone(), &["post"]);
    certified.plan_certificate = Some(Oid([0x78; 32]));
    let refusal = h.post(certified).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-102", exit::REFUSAL));
    assert!(refusal.message.contains("plan_certificate"), "{refusal}");
    assert!(refusal.fix.contains("fa-we7"), "{refusal}");
    assert_eq!(
        h.db.frontier().unwrap(),
        frontier,
        "no unchecked certificate"
    );

    let accepted = h
        .post(h.request(native.clone(), &["post"]))
        .expect("authored intent");
    let (entry_ref, _) = committed(&accepted).expect("identity was not consumed");
    let (stored, _) = read_entry(&h.db, entry_ref.vid).unwrap().unwrap();
    assert_eq!(stored.proposal, native);
    assert_eq!(stored.plan_certificate, None);
    assert!(matches!(
        h.post(h.request(native, &["post"])).unwrap(),
        Posted::AlreadyRecorded { .. }
    ));
}

#[test]
fn rich_leg_fields_without_a_law_are_refused_not_admitted() {
    let mut h = harness();
    let frontier = h.db.frontier().unwrap();
    let base = h.proposal(h.rent_legs(10), b"rich", EntryClass::ORIGINAL);
    let mut converted = base.clone();
    converted.legs[0].base_amount = Some(Amount::new(h.usd, 10));
    let mut entity = base.clone();
    let mut tagged = base.clone();
    // Dimension 1 is the legal entity (fa-bvx), 12 the party, and 2..=9
    // the registered kinds (fa-ficc): each has its law. An id no dimension
    // holds has none.
    let mut dimensioned = base;
    dimensioned.legs[0].dimension_set = vec![(13, VId(99))];
    for (what, p) in [("base_amount", converted), ("dimension_set", dimensioned)] {
        let r = h.post(h.request(p, &["post"])).unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-102", exit::REFUSAL), "{what}");
        assert!(r.message.contains(what), "{what}: {}", r.message);
    }
    // A registered kind's law: a cost center value the book never created
    // is refused, naming the dimension.
    tagged.legs[0].dimension_set = vec![(2, VId(99))];
    let r = h.post(h.request(tagged, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    assert!(r.message.contains("cost_center value"), "{r}");
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
fn prepared_receipts_compete_for_the_same_open_amount_in_both_commit_orders() {
    // Two real substrate transactions retain the same application witness.
    // This enumerates these two commit orders, not a lab/DPOR campaign.
    let prepare = |h: &mut Harness, proposal: EntryPayload| {
        let ctx = h.ctx();
        let request = h.request(proposal, &["post"]);
        match prepare_post(&mut h.db, &ctx, &h.book, request)
            .expect("prepare kernel")
            .expect("receipt admitted at its basis")
        {
            PostPreparation::Ready(prepared) => Some(prepared),
            PostPreparation::AlreadyRecorded(_) => None,
        }
        .expect("a distinct receipt must be fresh")
    };
    let commit = |h: &mut Harness, prepared: Box<PreparedPost>| {
        let ctx = h.ctx();
        let db = &mut h.db;
        h.runtime
            .block_on(async move { prepared.commit(db, &ctx).await })
            .expect("commit kernel")
    };
    for winner_index in [0, 1] {
        let mut h = harness();
        let usd = h.usd;
        let invoice = h
            .post(h.request(h.invoice(10_000, b"race-invoice"), &["post"]))
            .expect("invoice committed")
            .entry_ref();
        let basis = h.db.frontier().unwrap();
        let keys: [&[u8]; 2] = [b"race-receipt-a", b"race-receipt-b"];
        let proposals = keys.map(|key| h.receipt(6_000, vec![settle(invoice, 0, usd, 6_000)], key));
        let identities = keys.map(|key| entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key));
        assert_ne!(identities[0], identities[1]);

        // Preparation checks the complete target reference, not just its vid.
        let mut stale = proposals[0].clone();
        stale.legs[1].settles[0].target.entry_digest[0] ^= 1;
        let request = h.request(stale, &["post"]);
        let ctx = h.ctx();
        let refused = prepare_post(&mut h.db, &ctx, &h.book, request)
            .expect("stale-reference kernel")
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-070", exit::REFUSAL));
        assert_eq!(h.db.frontier().unwrap(), basis);

        let first = prepare(&mut h, proposals[0].clone());
        let second = prepare(&mut h, proposals[1].clone());
        assert_eq!(first.basis(), basis);
        assert_eq!(second.basis(), basis);
        assert_eq!(
            h.db.frontier().unwrap(),
            basis,
            "preparation publishes nothing"
        );
        assert_eq!(h.applied_to(invoice.vid, 0), 0);
        for vid in identities {
            assert!(read_entry(&h.db, vid).unwrap().is_none());
        }
        let (winner, loser) = if winner_index == 0 {
            (first, second)
        } else {
            (second, first)
        };
        let loser_index = 1 - winner_index;
        let won = commit(&mut h, winner).expect("first prepared receipt commits");
        assert!(matches!(won, Posted::Committed { .. }));
        assert_eq!(won.entry_ref().vid, identities[winner_index]);
        let after_winner = h.db.frontier().unwrap();
        assert_eq!(after_winner.0, basis.0 + 1);
        assert_eq!(won.recorded_at(), after_winner);
        assert_eq!(h.applied_to(invoice.vid, 0), 6_000);

        let refused = commit(&mut h, loser).expect_err("stale application witness conflicts");
        assert_eq!((refused.code, refused.exit), ("FA-REF-030", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), after_winner, "no second commit");
        assert_eq!(h.applied_to(invoice.vid, 0), 6_000, "no double application");
        let loser_vid = identities[loser_index];
        assert!(read_entry(&h.db, loser_vid).unwrap().is_none());
        for ordinal in [0, 1] {
            assert!(h.db.vertex(leg_vid(loser_vid, ordinal)).unwrap().is_none());
        }
        assert!(
            h.db.edge(edge_id(
                relation::SETTLES,
                leg_vid(loser_vid, 1),
                leg_vid(invoice.vid, 0),
            ))
            .unwrap()
            .is_none()
        );
        let (stored, recorded_at) = read_entry(&h.db, won.entry_ref().vid)
            .unwrap()
            .expect("winning entry");
        assert_eq!(stored.entry_digest, won.entry_ref().entry_digest);
        assert_eq!(recorded_at, after_winner);
        assert_eq!(
            stored.proposal.legs[1].settles,
            vec![settle(invoice, 0, usd, 6_000)]
        );
        let edge =
            h.db.edge(edge_id(
                relation::SETTLES,
                leg_vid(won.entry_ref().vid, 1),
                leg_vid(invoice.vid, 0),
            ))
            .unwrap()
            .expect("winning settlement edge");
        assert!(edge.props.iter().any(|(key, value)| {
            *key == property::AMOUNT_BYTES
                && *value == CanonicalScalar::bytes(6_000i128.to_le_bytes().to_vec()).unwrap()
        }));

        let again = h
            .post(h.request(proposals[winner_index].clone(), &["post"]))
            .expect("winner retry is already recorded");
        assert!(matches!(again, Posted::AlreadyRecorded { .. }));
        assert_eq!(again.entry_ref(), won.entry_ref());
        assert_eq!(again.recorded_at(), won.recorded_at());
        assert_eq!(h.db.frontier().unwrap(), after_winner);
        assert_eq!(h.applied_to(invoice.vid, 0), 6_000);

        let refused = h
            .post(h.request(proposals[loser_index].clone(), &["post"]))
            .expect_err("a fresh 60 receipt exceeds the remaining 40");
        assert_eq!((refused.code, refused.exit), ("FA-REF-072", exit::REFUSAL));
        assert!(
            refused.message.contains("only 40.00 USD is open"),
            "{}",
            refused.message
        );
        assert!(
            refused.fix.contains("apply at most 40.00 USD"),
            "the fix names an amount that can be pasted back: {}",
            refused.fix
        );
        assert_eq!(h.db.frontier().unwrap(), after_winner);
        assert_eq!(h.applied_to(invoice.vid, 0), 6_000);

        // The failed receipt's key was never consumed, so its corrected
        // 40 receipt can commit and settle the invoice exactly once.
        let remainder = h.receipt(
            4_000,
            vec![settle(invoice, 0, usd, 4_000)],
            keys[loser_index],
        );
        let completed = h
            .post(h.request(remainder, &["post"]))
            .expect("remaining 40 commits");
        assert!(matches!(completed, Posted::Committed { .. }));
        assert_eq!(completed.entry_ref().vid, loser_vid);
        assert_eq!(completed.recorded_at().0, after_winner.0 + 1);
        assert_eq!(h.db.frontier().unwrap(), completed.recorded_at());
        assert_eq!(h.applied_to(invoice.vid, 0), 10_000);
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
    assert!(
        r.message.contains("but only 200.00 USD is open"),
        "{}",
        r.message
    );
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
    // A 67th reversal (odd parity) would reverse the original again while
    // `receipt` is still applied against it, stranding the application: refused
    // with FA-REF-073 until the applying receipt is reversed first.
    let receipt_ref = receipt.entry_ref();
    let r67_refused = h
        .post(h.request(h.reversal_of_entry(tip, b"rev-66"), &["post"]))
        .unwrap_err();
    assert_eq!(
        (r67_refused.code, r67_refused.exit),
        ("FA-REF-073", exit::REFUSAL)
    );
    assert!(
        r67_refused
            .message
            .contains(&format!("{:032x}", original.vid.0)),
        "refusal names the ancestor carrying the live application: {}",
        r67_refused.message
    );
    let rev_receipt = h.post(h.request(
        h.reversal_of_entry(receipt_ref, b"rev-rcpt-after-66"),
        &["post"],
    ));
    assert!(rev_receipt.is_ok(), "{rev_receipt:?}");
    assert_eq!(h.applied_to(original.vid, 0), 0);
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
    assert_eq!(
        read_document(&h.db, &added.oid).unwrap().unwrap(),
        Some(doc.clone())
    );
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
    assert_eq!(
        read_document(&h.db, &Oid([0xee; 32])).unwrap().unwrap(),
        None
    );
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

/// The inline bound is what one substrate row holds: a document at the
/// bound with the longest admitted MIME is recorded inline and reads back,
/// and one byte more is the typed intake refusal naming the blob store,
/// never the substrate's RowExceedsStorageLimit (exit 5). Before the bound
/// was derived from the row, a 16 KiB document failed in storage while the
/// policy promised inline bytes up to 16 MiB.
#[test]
fn the_inline_document_bound_fits_one_substrate_row() {
    use fa_journal::evidence::{MAX_INLINE_DOCUMENT_BYTES, inline_document_bound};
    let mut h = harness();
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    let bound = inline_document_bound(&policy);
    assert_eq!(
        bound,
        MAX_INLINE_DOCUMENT_BYTES.min(policy.max_document_bytes)
    );
    let size = usize::try_from(bound).unwrap();

    let mut at_bound = h.document(INVOICE, HUMAN_UPLOAD, &vec![b'q'; size]);
    at_bound.mime = "m".repeat(policy.max_mime_bytes);
    let added = h.add_document(&at_bound).expect("the bound fits one row");
    assert_eq!(added.size, bound);
    let record = document_record(&h.db, &added.oid).unwrap().unwrap();
    assert!(matches!(record.storage, Storage::Inline(_)));
    assert_eq!(
        read_document(&h.db, &added.oid).unwrap().unwrap(),
        Some(at_bound)
    );

    let head = h.db.frontier().unwrap();
    let past = h.document(INVOICE, HUMAN_UPLOAD, &vec![b'r'; size + 1]);
    let r = h.add_document(&past).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-083", exit::USAGE), "{r}");
    assert!(r.fix.contains("blob store"), "{r}");
    assert_eq!(h.db.frontier().unwrap(), head);
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
            matches!(read_document(&h.db, &doc.oid()), Ok(Err(ref r)) if r.code == "FA-REF-085"),
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
        read_document(&h.db, &intact.oid()).unwrap().unwrap(),
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
        AttestationClaim::Reviewed { .. }
        | AttestationClaim::RegisterEquals(_)
        | AttestationClaim::Reconciled(_)
        | AttestationClaim::Confirmed { .. }
        | AttestationClaim::Represented { .. }
        | AttestationClaim::ExhibitMarked { .. } => None,
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

// ---------------------------------------------------------------------------
// External document storage (fa-txf part B, plan §9.1): bytes in the book's
// blob store, the commitment inline, every read verified.
// ---------------------------------------------------------------------------

fn blob_store_in<V: asupersync::fs::Vfs + Clone>(h: &Harness, vfs: V, root: &str) -> BlobStore<V> {
    let directory = h
        .runtime
        .block_on(fa_journal::blob::DurableDirectory::create(
            &h.ctx().commit(),
            vfs,
            std::path::Path::new(root),
        ))
        .expect("durable store directory");
    BlobStore::open(1, directory).expect("store 1")
}

fn blob_store(h: &Harness, root: &str) -> BlobStore<fgdb::MemVfs> {
    blob_store_in(h, fgdb::MemVfs::new().expect("memvfs"), root)
}

/// A blob store over the substrate's lab VFS, rooted three directories deep.
fn fault_store(
    h: &Harness,
    vfs: &fgdb_sim::vfs::FaultVfs<fgdb::MemVfs>,
) -> BlobStore<fgdb_sim::vfs::FaultVfs<fgdb::MemVfs>> {
    blob_store_in(h, vfs.clone(), "deep/nested/blobs")
}

fn lab_vfs(plan: fgdb_sim::vfs::FaultPlan) -> fgdb_sim::vfs::FaultVfs<fgdb::MemVfs> {
    fgdb_sim::vfs::FaultVfs::new(fgdb::MemVfs::new().expect("memvfs"), plan)
}

impl Harness {
    fn add_external_to<V: asupersync::fs::Vfs + Clone>(
        &mut self,
        store: &BlobStore<V>,
        doc: &Document,
    ) -> Result<DocumentAdded, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { add_document_external(db, &ctx, book, store, doc).await })
            .expect("kernel")
    }

    fn fetch_from<V: asupersync::fs::Vfs + Clone>(
        &self,
        store: &BlobStore<V>,
        oid: &Oid,
    ) -> Result<Option<Document>, Refusal> {
        let ctx = self.ctx();
        let db = &self.db;
        self.runtime
            .block_on(async move { fetch_document(db, &ctx, store, oid).await })
            .expect("kernel")
    }
}

/// Directory durability moved to the store constructor. Existing names may
/// still owe fences after an interrupted mkdir chain. The unfenced control
/// loses that chain; both creating and reopening an anchor must preserve it.
#[test]
fn a_durable_store_anchor_fences_preexisting_unsynced_ancestors() {
    use asupersync::fs::Vfs;
    use fa_journal::blob::DurableDirectory;
    use fgdb_sim::vfs::{FaultPlan, Trigger};
    let h = harness();
    let ctx = h.ctx();
    for mode in ["unfenced", "create", "open"] {
        let vfs = lab_vfs(FaultPlan {
            dirent_loss: Trigger::Always,
            ..FaultPlan::faultless()
        });
        h.runtime.block_on(async {
            let path = std::path::Path::new("./deep/nested/blobs");
            ctx.commit()
                .with_restriction_async(vfs.create_dir_all(path))
                .await
                .unwrap();
            assert!(
                vfs.pending_dirent_ops() >= 3,
                "{mode}: unfenced mkdir chain"
            );
            let anchor = match mode {
                "create" => Some(
                    DurableDirectory::create(&ctx.commit(), vfs.clone(), path)
                        .await
                        .unwrap(),
                ),
                "open" => Some(
                    DurableDirectory::open_existing(&ctx.commit(), vfs.clone(), path)
                        .await
                        .unwrap(),
                ),
                _ => None,
            };
            if let Some(anchor) = &anchor {
                assert!(anchor.path().is_absolute());
                assert_eq!(vfs.pending_dirent_ops(), 0, "{mode}: every ancestor fenced");
            }
            vfs.crash().await.unwrap();
            let observed = ctx.query().with_restriction_async(vfs.metadata(path)).await;
            if anchor.is_some() {
                assert!(
                    observed.unwrap().is_dir(),
                    "{mode}: the full chain survives"
                );
            } else {
                assert_eq!(
                    observed.unwrap_err().kind(),
                    std::io::ErrorKind::NotFound,
                    "the unfenced control proves the crash loses these names"
                );
            }
        });
    }
}

/// A symlink can skip the target's own ancestors in the caller's lexical
/// chain. Use the real host VFS beneath FaultVfs so symlink resolution is
/// real and a directory crash can expose the missing target-parent fence.
#[cfg(unix)]
#[test]
fn a_symlinked_store_anchor_fences_the_canonical_target_ancestors() {
    use asupersync::fs::{OpenOptions, UnixVfs, Vfs, VfsFile};
    use fa_journal::blob::DurableDirectory;
    use fgdb_sim::vfs::{FaultPlan, FaultVfs, Trigger};
    let h = harness();
    let ctx = h.ctx();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("fa-symlink-anchor-{}-{suffix}", std::process::id()));
    for canonical_fences in [false, true] {
        let root = base.join(if canonical_fences {
            "fenced"
        } else {
            "lexical-only"
        });
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let target = root.join("real/deep");
        let alias = root.join("alias");
        let path = alias.join("store");
        let vfs = FaultVfs::new(
            UnixVfs::new(),
            FaultPlan {
                dirent_loss: Trigger::Always,
                ..FaultPlan::faultless()
            },
        );
        h.runtime.block_on(async {
            ctx.commit()
                .with_restriction_async(vfs.create_dir_all(&target))
                .await
                .unwrap();
            assert_eq!(vfs.pending_dirent_ops(), 2, "target ancestors owe fences");
            std::os::unix::fs::symlink(&target, &alias).unwrap();
            if canonical_fences {
                let anchor = DurableDirectory::create(&ctx.commit(), vfs.clone(), &path)
                    .await
                    .unwrap();
                assert_eq!(anchor.path(), target.join("store"));
                assert_eq!(vfs.pending_dirent_ops(), 0);
            } else {
                // The old barrier: sync only the lexical chain. Opening
                // alias syncs deep, but never syncs real's entry for deep.
                ctx.commit()
                    .with_restriction_async(async {
                        vfs.create_dir_all(&path).await.unwrap();
                        for ancestor in path.ancestors() {
                            vfs.open(ancestor, &OpenOptions::new().read(true))
                                .await
                                .unwrap()
                                .sync_all()
                                .await
                                .unwrap();
                        }
                    })
                    .await;
                assert_eq!(vfs.pending_dirent_ops(), 1, "the skipped target parent");
            }
            vfs.crash().await.unwrap();
            let observed = ctx
                .query()
                .with_restriction_async(vfs.metadata(&path))
                .await;
            if canonical_fences {
                assert!(observed.unwrap().is_dir(), "the canonical chain survives");
            } else {
                assert_eq!(observed.unwrap_err().kind(), std::io::ErrorKind::NotFound);
            }
        });
    }
}

/// The publication fence under the substrate's lab VFS (WhiteCreek 3440,
/// CobaltGull 3452). With `dirent_loss = Always` a crash rolls back every
/// namespace change whose parent directory was never honestly synced: the
/// classic fsync-the-file, forget-the-directory loss. An external document's
/// blob, published through `put` and only then journaled, owes nothing when
/// intake returns and reads back after the crash; the faultless plan is the
/// harness's control.
#[test]
fn an_external_blob_survives_a_crash_that_loses_every_unsynced_name() {
    use fgdb_sim::vfs::{FaultPlan, Trigger};
    for (what, plan) in [
        ("faultless (the control)", FaultPlan::faultless()),
        (
            "every unsynced name lost",
            FaultPlan {
                dirent_loss: Trigger::Always,
                ..FaultPlan::faultless()
            },
        ),
    ] {
        let mut h = harness();
        let vfs = lab_vfs(plan);
        let store = fault_store(&h, &vfs);
        let doc = h.document(
            INVOICE,
            HUMAN_UPLOAD,
            format!("INVOICE 991 (crash fixture: {what}) ")
                .repeat(150)
                .as_bytes(),
        );
        h.add_external_to(&store, &doc).expect("recorded");
        assert_eq!(
            vfs.pending_dirent_ops(),
            0,
            "{what}: nothing owes a sync once intake returns"
        );
        h.runtime.block_on(vfs.crash()).expect("crash");
        let reopened = fault_store(&h, &vfs);
        let read = h.fetch_from(&reopened, &doc.oid());
        eprintln!(
            "txf fence: {what} -> crash generation {}, read {:?}",
            vfs.generation(),
            read.as_ref().map(|d| d.as_ref().map(|d| d.bytes.len()))
        );
        assert_eq!(read, Ok(Some(doc)), "{what}");
    }
}

/// The planted negative: the same intake through a lab VFS whose directory
/// syncs lie. The names stay pending, the crash takes them, and the journal
/// row then names a blob that is gone: the read is FA-REF-116 (exit 5),
/// never a silent null. This is what the fence prevents, and proves the
/// crash test above can see an unfenced publication.
#[test]
fn a_lying_directory_sync_loses_the_blob_and_the_read_says_so() {
    use fgdb_sim::vfs::{FaultPlan, Trigger};
    let mut h = harness();
    let vfs = lab_vfs(FaultPlan {
        dirent_loss: Trigger::Always,
        dirent_lie: Trigger::Always,
        ..FaultPlan::faultless()
    });
    let store = fault_store(&h, &vfs);
    let doc = h.document(
        INVOICE,
        HUMAN_UPLOAD,
        "INVOICE 992 (lying directory syncs) "
            .repeat(150)
            .as_bytes(),
    );
    h.add_external_to(&store, &doc)
        .expect("recorded: the lie reported success");
    assert!(
        vfs.pending_dirent_ops() > 0,
        "the lying syncs settled nothing"
    );
    h.runtime.block_on(vfs.crash()).expect("crash");
    let r = h
        .fetch_from(&fault_store(&h, &vfs), &doc.oid())
        .unwrap_err();
    eprintln!(
        "txf fence: lying directory syncs, then a crash -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-116", exit::FOUNDATION), "{r}");
}

/// Ordering, and the retry WhiteCreek 3459 named. A publication the lab VFS
/// refuses — the first write (ENOSPC) or the sync write-back (a zero space
/// budget) — never reaches the journal: intake is FA-REF-116 and nothing is
/// written. Then the retry, after a first put interrupted between creating
/// its shard and syncing it: it finds the shard present, fences it and the
/// established store anyway, and its blob survives a crash that loses every
/// unsynced name. Constructor-level ancestor recovery is exercised above.
#[test]
fn a_blob_not_made_durable_never_reaches_the_journal_and_a_retry_fences_the_chain() {
    use fgdb_sim::vfs::{FaultPlan, Trigger};
    for (what, plan) in [
        (
            "the first write refused",
            FaultPlan {
                write_enospc: Trigger::Always,
                ..FaultPlan::faultless()
            },
        ),
        (
            "the sync write-back refused",
            FaultPlan {
                space_budget: Some(0),
                ..FaultPlan::faultless()
            },
        ),
    ] {
        let mut h = harness();
        let store = fault_store(&h, &lab_vfs(plan));
        let doc = h.document(
            INVOICE,
            HUMAN_UPLOAD,
            format!("INVOICE 993 ({what}) ").repeat(150).as_bytes(),
        );
        let head = h.db.frontier().unwrap();
        let r = h.add_external_to(&store, &doc).unwrap_err();
        eprintln!("txf fence: {what} -> {} {}", r.code, r.message);
        assert_eq!(
            (r.code, r.exit),
            ("FA-REF-116", exit::FOUNDATION),
            "{what}: {r}"
        );
        assert_eq!(h.db.frontier().unwrap(), head, "{what}: nothing journaled");
        assert!(
            h.db.vertex(document_vid(&doc.oid())).unwrap().is_none(),
            "{what}: no row names the blob"
        );
    }

    let mut h = harness();
    let vfs = lab_vfs(FaultPlan {
        write_enospc: Trigger::At(1),
        dirent_loss: Trigger::Always,
        ..FaultPlan::faultless()
    });
    let store = fault_store(&h, &vfs);
    let doc = h.document(
        INVOICE,
        HUMAN_UPLOAD,
        "INVOICE 994 (interrupted, then retried) "
            .repeat(150)
            .as_bytes(),
    );
    let r = h.add_external_to(&store, &doc).unwrap_err();
    assert_eq!(r.code, "FA-REF-116", "the interrupted first put: {r}");
    assert!(
        vfs.pending_dirent_ops() > 0,
        "the interrupted put left its directories unsynced"
    );
    h.add_external_to(&store, &doc).expect("the retry records");
    assert_eq!(
        vfs.pending_dirent_ops(),
        0,
        "the retry fenced every name the interrupted put left owing"
    );
    h.runtime.block_on(vfs.crash()).expect("crash");
    assert_eq!(
        h.fetch_from(&fault_store(&h, &vfs), &doc.oid()),
        Ok(Some(doc))
    );
}

/// The publication fence (WhiteCreek 3440/3445) on a root nested three
/// directories deep that does not exist yet: the anchor creates and fences
/// its chain, `put` creates and fences its shard, publishes under its own
/// staged name, and a second put of the same locator is harmless.
#[test]
fn a_blob_publishes_into_a_fresh_nested_root_and_republishes_harmlessly() {
    let h = harness();
    let store = blob_store(&h, "deep/nested/blobs");
    let bytes = b"BLOB (publication fixture)".to_vec();
    let locator = fa_journal::blob::locator_of(&[7; 32]);
    let ctx = h.ctx();
    h.runtime.block_on(async {
        store
            .put(&ctx.commit(), &locator, &bytes)
            .await
            .expect("published");
        store
            .put(&ctx.commit(), &locator, &bytes)
            .await
            .expect("republished");
        assert_eq!(
            store
                .get(&ctx.query(), &locator, bytes.len() as u64)
                .await
                .expect("read"),
            Some(bytes.clone())
        );
        let other = fa_journal::blob::locator_of(&[8; 32]);
        assert_eq!(
            store.get(&ctx.query(), &other, 64).await.expect("read"),
            None,
            "a blob never published reads as absent, not as an error"
        );
    });
}

/// A store over the host VFS at a relative root (WhiteCreek 3508): every
/// directory the publication fence syncs has a nonempty spelling. The host
/// VFS refuses a `..` component (asupersync `validate_safe_path`, at
/// rename), so the root must sit under the working directory, and changing
/// this process's working directory would race the other tests. The test
/// re-runs itself in a child process whose working directory is a fresh
/// temporary directory. The child opens `nested/store`, changes cwd, then
/// publishes; the parent reads the original absolute path, so a child that
/// ran nothing or a store that followed the changed cwd cannot pass.
#[test]
fn a_blob_publishes_through_a_relative_unix_root_without_changing_cwd() {
    const CHILD: &str = "FA_RELATIVE_BLOB_ROOT_CHILD";
    let locator = fa_journal::blob::locator_of(&[0x73; 32]);
    if std::env::var_os(CHILD).is_some() {
        let h = harness();
        let store = blob_store_in(&h, asupersync::fs::UnixVfs::new(), "nested/store");
        let later = std::env::current_dir().unwrap().join("later-cwd");
        std::fs::create_dir(&later).unwrap();
        std::env::set_current_dir(&later).unwrap();
        let ctx = h.ctx();
        h.runtime.block_on(async {
            store
                .put(&ctx.commit(), &locator, b"relative host blob")
                .await
                .expect("every directory sync uses a nonempty pathname");
            assert_eq!(
                store.get(&ctx.query(), &locator, 64).await.unwrap(),
                Some(b"relative host blob".to_vec())
            );
        });
        return;
    }
    let cwd = std::env::current_dir().unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("fa-relative-blobs-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "a_blob_publishes_through_a_relative_unix_root_without_changing_cwd",
            "--exact",
        ])
        .env(CHILD, "1")
        .current_dir(&base)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "the child failed:\n{}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let published = base.join("nested/store").join(&locator[..2]).join(&locator);
    assert_eq!(
        std::fs::read(&published).expect("the child published under its relative root"),
        b"relative host blob"
    );
    assert!(base.join("later-cwd").is_dir());
    assert!(!base.join("later-cwd/nested").exists());
    assert_eq!(std::env::current_dir().unwrap(), cwd);
}

impl Harness {
    fn add_external(
        &mut self,
        store: &BlobStore<fgdb::MemVfs>,
        doc: &Document,
    ) -> Result<DocumentAdded, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { add_document_external(db, &ctx, book, store, doc).await })
            .expect("kernel")
    }

    fn fetch(
        &self,
        store: &BlobStore<fgdb::MemVfs>,
        oid: &Oid,
    ) -> Result<Option<Document>, Refusal> {
        let ctx = self.ctx();
        let db = &self.db;
        self.runtime
            .block_on(async move { fetch_document(db, &ctx, store, oid).await })
            .expect("kernel")
    }
}

#[test]
fn an_external_document_reads_back_verified_and_a_missing_or_changed_blob_is_refused() {
    let mut h = harness();
    let store = blob_store(&h, "blobs");
    let doc = h.document(
        INVOICE,
        HUMAN_UPLOAD,
        &b"INVOICE 990 (external storage fixture) ".repeat(200),
    );
    let added = h.add_external(&store, &doc).expect("recorded");
    eprintln!(
        "txf external: recorded {} ({} bytes) in store {} at {:?}",
        fa_journal::evidence::hex(&added.oid.0),
        added.size,
        store.id(),
        added.recorded_at
    );
    // The journal holds the commitment and the locator, not the bytes.
    let record = document_record(&h.db, &added.oid).unwrap().expect("held");
    assert_eq!(
        record.storage,
        Storage::External {
            store: 1,
            locator: fa_journal::blob::locator_of(&doc.doc_commit()),
        }
    );
    assert_eq!(
        (record.size, record.doc_commit),
        (added.size, doc.doc_commit())
    );
    // Read back byte-identically, the commitment recomputed from the bytes.
    assert_eq!(h.fetch(&store, &added.oid).unwrap(), Some(doc.clone()));
    // Without its store a read is a typed refusal naming the store, never null.
    let r = read_document(&h.db, &added.oid).unwrap().unwrap_err();
    eprintln!(
        "txf external: read without the store -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-116", exit::FOUNDATION), "{r}");
    // Citing it needs no bytes: the evidence law reads the record.
    assert!(matches!(
        h.post_citing(&doc, b"txf-external"),
        Ok(Posted::Committed { .. })
    ));
    // The same bytes again (inline or external) are the recorded outcome.
    assert!(h.add_document(&doc).expect("recorded").already_recorded);

    // A store that holds no such blob: exit 5, never a silent null.
    let empty = blob_store(&h, "elsewhere");
    let r = h.fetch(&empty, &added.oid).unwrap_err();
    eprintln!("txf external: a missing blob -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-116", exit::FOUNDATION), "{r}");
    // A blob whose bytes changed: drift, exit 8, never the changed bytes.
    let locator = fa_journal::blob::locator_of(&doc.doc_commit());
    let mut changed = doc.bytes.clone();
    changed[0] ^= 0x20;
    h.runtime
        .block_on(async { store.put(&h.ctx().commit(), &locator, &changed).await })
        .expect("overwrite the blob outside every law");
    let r = h.fetch(&store, &added.oid).unwrap_err();
    eprintln!("txf external: a changed blob -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-085", exit::VERIFICATION), "{r}");
    // A blob replaced by more bytes than the record names (WhiteCreek 3464):
    // drift, exit 8, and the store never reads past the recorded size + 1.
    let mut longer = doc.bytes.clone();
    longer.extend_from_slice(b" and then some more bytes than the record names");
    h.runtime
        .block_on(async { store.put(&h.ctx().commit(), &locator, &longer).await })
        .expect("overwrite the blob outside every law");
    let r = h.fetch(&store, &added.oid).unwrap_err();
    eprintln!(
        "txf external: an oversized blob -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-085", exit::VERIFICATION), "{r}");
    let read = h
        .runtime
        .block_on(async { store.get(&h.ctx().query(), &locator, 10).await })
        .expect("read")
        .expect("present");
    assert_eq!(read, longer[..11], "a read stops at limit + 1 bytes");
    // Restoring the right bytes restores the read.
    h.runtime
        .block_on(async { store.put(&h.ctx().commit(), &locator, &doc.bytes).await })
        .expect("restore");
    assert_eq!(h.fetch(&store, &added.oid).unwrap(), Some(doc));
}

#[test]
fn a_document_past_the_inline_bound_is_refused_inline_and_admitted_by_a_store() {
    let mut h = harness();
    let bound = 16 * 1024 * 1024;
    let big = h.document(INVOICE, HUMAN_UPLOAD, &vec![b'x'; bound + 1]);
    let r = h.add_document(&big).unwrap_err();
    eprintln!(
        "txf external: inline past the bound -> {} {}",
        r.code, r.message
    );
    assert_eq!(r.code, "FA-REF-083", "{r}");
    assert!(r.fix.contains("blob store"), "{}", r.fix);
    let store = blob_store(&h, "blobs");
    let added = h.add_external(&store, &big).expect("admitted by the store");
    assert_eq!(added.size, u64::try_from(bound + 1).unwrap());
    assert_eq!(h.fetch(&store, &added.oid).unwrap(), Some(big));
}

// ---------------------------------------------------------------------------
// Legal holds (fa-txf, plan §8.5, §14.6): a hold pins its subjects against
// erasure until a second, Human principal approves its release; it never
// pins the two-phase reservation sweep.
// ---------------------------------------------------------------------------

/// The Human approver of a hold's release (not its preparer).
const RELEASE_APPROVER: VId = VId(71);

impl Harness {
    fn place_hold(
        &mut self,
        cap: &Capability,
        subjects: Vec<VId>,
        authority: Oid,
        key: &[u8],
    ) -> Result<LegalHoldPlaced, Refusal> {
        self.place_reach(cap, HoldReach::Subjects(subjects), authority, key)
    }

    fn place_reach(
        &mut self,
        cap: &Capability,
        reach: HoldReach,
        authority: Oid,
        key: &[u8],
    ) -> Result<LegalHoldPlaced, Refusal> {
        let ctx = self.ctx();
        let req = LegalHoldRequest {
            principal: cap.holder(),
            reach,
            authority,
            effective_date: DateDay::from_ymd(2026, 3, 20).unwrap(),
            idempotency_key: key.to_vec(),
            description: self.statement("legal hold", 61),
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { place_legal_hold(db, &ctx, book, cap, req).await })
            .expect("kernel")
    }

    fn plan_hold_release(&self, hold: VId, key: &[u8]) -> Result<ReleasePlan, Refusal> {
        plan_release(
            &self.db,
            &self.book,
            hold,
            PRINCIPAL,
            DateDay::from_ymd(2026, 3, 25).unwrap(),
            key,
            self.statement("hold release", 62),
        )
        .expect("kernel")
    }

    fn release_hold(
        &mut self,
        plan: &ReleasePlan,
        approvals: &[fa_model::ApprovalRef],
    ) -> Result<LegalHoldReleased, Refusal> {
        let ctx = self.ctx();
        let cap = Capability::embedded(plan.principal_ref, &["hold"]).expect("hold");
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(
                async move { release_legal_hold(db, &ctx, book, &cap, plan, approvals).await },
            )
            .expect("kernel")
    }

    fn approve_digest(
        &mut self,
        approver: VId,
        digest: [u8; 32],
    ) -> Result<fa_model::ApprovalRef, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = ApprovalRequest {
            capability: Capability::embedded(approver, &["approve"]).expect("approve"),
            approved_proposal_digest: digest,
            role: 0,
        };
        self.runtime
            .block_on(async move { record_approval(db, &ctx, book, req).await })
            .expect("kernel")
            .map(|a| a.approval())
    }

    fn erase(&self, cap: &Capability, subject: VId) -> Refusal {
        fa_journal::evidence::erasure_cut(&self.db, &self.book, cap, subject).expect("kernel")
    }

    /// Revoke `revoked` (plan §14.2) under the issuer's capability.
    fn revoke(&mut self, revoked: &Capability, n: u8) {
        let ctx = self.ctx();
        let req = RevocationRequest {
            capability: Capability::embedded(PRINCIPAL, &["issue_capability"]).expect("issue"),
            revoked: revoked.commitment().expect("commitment"),
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            idempotency_key: vec![b'r', n],
            description: self.statement("revocation", n),
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { revoke_capability(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("revoked");
    }

    fn holds_on(&self, subject: VId) -> Vec<VId> {
        active_legal_holds(&self.db, self.book.book_id, subject).expect("kernel")
    }

    fn tick(&mut self, observed_utc_ns: u64, key: &[u8], nonce: u8) -> Ticked {
        let ctx = self.ctx();
        let req = TickRequest {
            observed_utc_ns,
            source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
            monotonic_ok: true,
            principal_ref: PRINCIPAL,
            capability: Capability::embedded(PRINCIPAL, &["witness"]).expect("witness"),
            idempotency_key: key.to_vec(),
            description: self.statement("tick", nonce),
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { record_tick(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("tick recorded")
    }

    fn sweep_expiry(&mut self) -> Swept {
        let ctx = self.ctx();
        let system = fa_journal::rows::system_principal(self.book.book_id);
        let req = SweepRequest {
            principal_ref: system,
            capability: Capability::new(system, Profile::System, &[Op::Post], system)
                .expect("a System capability"),
            max_batch: 8,
        };
        let db = &mut self.db;
        let book = &self.book;
        let mut nonce = 70u8;
        self.runtime
            .block_on(async move {
                let mut describe = |text: &str| {
                    nonce += 1;
                    Ok(Erasable::seal(
                        &text.to_string(),
                        None,
                        &book.seal_key,
                        [nonce; 32],
                        [nonce; 24],
                    ))
                };
                sweep(db, &ctx, book, &req, &mut describe).await
            })
            .expect("kernel")
            .expect("swept")
    }
}

#[test]
fn a_legal_hold_pins_its_subjects_until_a_second_human_approves_its_release() {
    let mut h = harness();
    let order = h.document(INVOICE, HUMAN_UPLOAD, b"PRESERVATION ORDER 2026-17");
    h.add_document(&order).expect("admitted");
    let invoice = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 1717 (under hold)");
    h.add_document(&invoice).expect("admitted");
    let doc = document_vid(&invoice.oid());
    let entry = h
        .post(h.request(
            h.proposal(h.rent_legs(25), b"held-entry", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("posted")
        .entry_ref()
        .vid;
    let free = h
        .post(h.request(
            h.proposal(h.rent_legs(26), b"free-entry", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("posted")
        .entry_ref()
        .vid;
    let counsel = Capability::embedded(PRINCIPAL, &["hold"]).expect("hold");
    let eraser = Capability::embedded(PRINCIPAL, &["erase"]).expect("erase");

    let placed = h
        .place_hold(&counsel, vec![entry, doc], order.oid(), b"hold-1")
        .expect("placed");
    eprintln!(
        "txf hold: placed {:032x} over {} subjects at seq {}",
        placed.hold.0,
        placed.subjects.len(),
        placed.recorded_at.0
    );
    let mut both = vec![entry, doc];
    both.sort_by_key(|v| v.0);
    assert_eq!(placed.subjects, both, "the scope is canonical (ascending)");
    assert!(!placed.already_recorded);
    for s in &both {
        assert_eq!(h.holds_on(*s), vec![placed.hold]);
        assert!(
            h.db.edge(edge_id(relation::HOLDS, placed.hold, *s))
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(h.holds_on(free), Vec::<VId>::new());
    let read = read_legal_hold(&h.db, h.book.book_id, placed.hold)
        .unwrap()
        .expect("a placed hold");
    assert_eq!(
        (
            read.authority,
            read.issued_by,
            &read.subjects,
            read.released
        ),
        (order.oid(), PRINCIPAL, &both, None)
    );
    assert_eq!(read.placed_at, placed.recorded_at);

    // The same placement again is its recorded outcome; the key under other
    // content is an idempotency conflict.
    let again = h
        .place_hold(&counsel, vec![doc, entry], order.oid(), b"hold-1")
        .expect("recorded");
    assert!(again.already_recorded);
    assert_eq!((again.hold, again.subjects), (placed.hold, both.clone()));
    let r = h
        .place_hold(&counsel, vec![entry], order.oid(), b"hold-1")
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT), "{r}");

    // Erasure of a held subject is refused naming the hold (exit 7); of an
    // unheld one it is the registered absence; without `erase`, the
    // capability refuses before anything is read.
    let r = h.erase(&eraser, entry);
    eprintln!(
        "txf hold: erasure of a held entry -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-117", exit::SAFETY), "{r}");
    assert!(
        r.message.contains(&format!("{:032x}", placed.hold.0)),
        "{r}"
    );
    assert!(!r.fix.contains("fa "), "no verb exists to name: {}", r.fix);
    assert_eq!(h.erase(&eraser, doc).code, "FA-REF-117");
    let r = h.erase(&eraser, free);
    assert_eq!((r.code, r.exit), ("FA-REF-088", exit::REFUSAL), "{r}");
    assert_eq!(h.erase(&counsel, entry).code, "FA-REF-011");

    // A second hold over one subject: both active there, ascending.
    let second = h
        .place_hold(&counsel, vec![entry], order.oid(), b"hold-2")
        .expect("placed");
    let mut two = vec![placed.hold, second.hold];
    two.sort_by_key(|v| v.0);
    assert_eq!(h.holds_on(entry), two);
    assert_eq!(h.holds_on(doc), vec![placed.hold]);

    // Every placement law refuses, and nothing is written.
    // An Agent is refused on trunk before its ops are looked at.
    let agent = Capability::new(PRINCIPAL, Profile::Agent, &[Op::Post], VId(1)).expect("agent");
    let head = h.db.frontier().unwrap();
    let cases: Vec<(&str, &Capability, Vec<VId>, Oid, &str)> = vec![
        ("no subjects", &counsel, vec![], order.oid(), "FA-REF-100"),
        (
            "a repeated subject",
            &counsel,
            vec![entry, entry],
            order.oid(),
            "FA-REF-100",
        ),
        (
            "a subject the book does not hold",
            &counsel,
            vec![entry, VId(0xdead)],
            order.oid(),
            "FA-REF-141",
        ),
        (
            "a subject that is neither entry, document nor party",
            &counsel,
            vec![book_root()],
            order.oid(),
            "FA-REF-141",
        ),
        (
            "an authority the book does not hold",
            &counsel,
            vec![entry],
            Oid([9; 32]),
            "FA-REF-081",
        ),
        (
            "a capability without hold",
            &eraser,
            vec![entry],
            order.oid(),
            "FA-REF-011",
        ),
        (
            "an Agent on trunk",
            &agent,
            vec![entry],
            order.oid(),
            "FA-REF-013",
        ),
    ];
    for (i, (what, cap, subjects, authority, want)) in cases.into_iter().enumerate() {
        let key = format!("refused-{i}");
        let r = h
            .place_hold(cap, subjects, authority, key.as_bytes())
            .unwrap_err();
        eprintln!("txf hold: {what} -> {} {}", r.code, r.message);
        assert_eq!(r.code, want, "{what}: {r}");
        assert_eq!(h.db.frontier().unwrap(), head, "{what}: nothing written");
    }

    // Release: planned, approved by a Human other than its preparer.
    let plan = h
        .plan_hold_release(placed.hold, b"release-1")
        .expect("planned");
    assert_eq!((plan.hold, plan.authority), (placed.hold, order.oid()));
    let digest = plan.proposal_digest(&h.book).unwrap();
    let r = h.release_hold(&plan, &[]).unwrap_err();
    eprintln!(
        "txf hold: release without approval -> {} {}",
        r.code, r.message
    );
    assert_eq!(r.code, "FA-REF-012", "{r}");
    let own = h.approve_digest(PRINCIPAL, digest).expect("recorded");
    let r = h.release_hold(&plan, &[own]).unwrap_err();
    eprintln!(
        "txf hold: release approved by its preparer -> {} {}",
        r.code, r.message
    );
    assert_eq!(r.code, "FA-REF-008", "{r}");
    assert_eq!(h.holds_on(doc), vec![placed.hold], "nothing released");
    let approval = h
        .approve_digest(RELEASE_APPROVER, digest)
        .expect("recorded");
    let released = h.release_hold(&plan, &[approval]).expect("released");
    eprintln!(
        "txf hold: released {:032x} by {:032x} at seq {}",
        released.hold.0, released.release.0, released.recorded_at.0
    );
    assert!(!released.already_recorded);
    assert_eq!(
        released.release,
        fa_journal::legal_hold::release_vid(h.book.book_id, placed.hold)
    );
    assert_eq!(h.holds_on(doc), Vec::<VId>::new());
    assert_eq!(h.holds_on(entry), vec![second.hold]);
    assert_eq!(
        read_legal_hold(&h.db, h.book.book_id, placed.hold)
            .unwrap()
            .expect("still a hold")
            .released,
        Some((released.release, released.recorded_at))
    );
    // The document is no longer pinned; the entry still is, by the second hold.
    assert_eq!(h.erase(&eraser, doc).code, "FA-REF-088");
    let r = h.erase(&eraser, entry);
    assert_eq!(r.code, "FA-REF-117");
    assert!(
        r.message.contains(&format!("{:032x}", second.hold.0)),
        "{r}"
    );
    assert!(
        !r.message.contains(&format!("{:032x}", placed.hold.0)),
        "{r}"
    );

    // The same release again is its recorded outcome; another release of the
    // same hold, or a new plan for it, is refused.
    let again = h.release_hold(&plan, &[approval]).expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(again.release, released.release);
    let other = ReleasePlan {
        idempotency_key: b"release-2".to_vec(),
        ..plan.clone()
    };
    let r = h.release_hold(&other, &[approval]).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-118", exit::REFUSAL), "{r}");
    let r = h.plan_hold_release(placed.hold, b"release-3").unwrap_err();
    assert_eq!(r.code, "FA-REF-118", "{r}");
    // What is not a placed hold cannot be released.
    for (what, vid) in [("a posting entry", free), ("an unknown vid", VId(0xbeef))] {
        let r = h.plan_hold_release(vid, b"release-x").unwrap_err();
        eprintln!("txf hold: release of {what} -> {} {}", r.code, r.message);
        assert_eq!(r.code, "FA-REF-118", "{what}");
    }
    // A plan that names another authority is not this hold's, even approved.
    let forged = ReleasePlan {
        authority: invoice.oid(),
        ..h.plan_hold_release(second.hold, b"release-4")
            .expect("planned")
    };
    let digest = forged.proposal_digest(&h.book).unwrap();
    let approval = h
        .approve_digest(RELEASE_APPROVER, digest)
        .expect("recorded");
    let r = h.release_hold(&forged, &[approval]).unwrap_err();
    assert_eq!(r.code, "FA-REF-118", "{r}");
    assert_eq!(h.holds_on(entry), vec![second.hold]);

    // A revoked eraser is refused at the head (023) before the subject is
    // read, so it learns neither the hold nor the absence; before its
    // revocation the same token saw the hold, and a live token still does
    // (fa-bcd, CobaltGull 3429).
    let gone = Capability::embedded(VId(12), &["erase"]).expect("erase");
    assert_eq!(h.erase(&gone, entry).code, "FA-REF-117");
    h.revoke(&gone, 68);
    for subject in [entry, free] {
        let r = h.erase(&gone, subject);
        eprintln!("txf hold: a revoked eraser -> {} {}", r.code, r.message);
        assert_eq!(r.code, "FA-REF-023", "{r}");
        assert!(
            !r.message.contains(&format!("{:032x}", second.hold.0)),
            "{r}"
        );
    }
    assert_eq!(h.erase(&eraser, entry).code, "FA-REF-117");
}

/// A book-scope hold (plan §15.6, the receiver's pre-appointment trunk; fa-k07b)
/// pins every entry, document and party recorded at or before its sequence
/// and nothing recorded after it, through one book-level cell.
#[test]
fn a_book_scope_hold_pins_everything_recorded_through_its_sequence() {
    let mut h = harness();
    let order = h.document(INVOICE, HUMAN_UPLOAD, b"RECEIVERSHIP ORDER 2026-21");
    h.add_document(&order).expect("admitted");
    let invoice = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 2101 (pre-appointment)");
    h.add_document(&invoice).expect("admitted");
    let held_doc = document_vid(&invoice.oid());
    let held_entry = h
        .post(h.request(
            h.proposal(h.rent_legs(31), b"pre-appointment", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("posted")
        .entry_ref()
        .vid;
    let appointment = h.db.frontier().unwrap();
    let later_entry = h
        .post(h.request(
            h.proposal(h.rent_legs(32), b"post-appointment", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("posted")
        .entry_ref()
        .vid;
    let later = h.document(INVOICE, HUMAN_UPLOAD, b"INVOICE 2102 (post-appointment)");
    h.add_document(&later).expect("admitted");
    let later_doc = document_vid(&later.oid());
    let counsel = Capability::embedded(PRINCIPAL, &["hold"]).expect("hold");
    let eraser = Capability::embedded(PRINCIPAL, &["erase"]).expect("erase");

    // Refused before anything is written: sequence 0, a sequence the book
    // has not recorded, and a capability without hold.
    let head = h.db.frontier().unwrap();
    let cases: Vec<(&str, &Capability, fgdb_types::CommitSeq, &str)> = vec![
        (
            "through sequence 0",
            &counsel,
            fgdb_types::CommitSeq(0),
            "FA-REF-100",
        ),
        (
            "through an unrecorded sequence",
            &counsel,
            fgdb_types::CommitSeq(head.0 + 5),
            "FA-REF-141",
        ),
        (
            "a capability without hold",
            &eraser,
            appointment,
            "FA-REF-011",
        ),
    ];
    for (i, (what, cap, through, want)) in cases.into_iter().enumerate() {
        let key = format!("book-refused-{i}");
        let r = h
            .place_reach(
                cap,
                HoldReach::Through(through),
                order.oid(),
                key.as_bytes(),
            )
            .unwrap_err();
        eprintln!("k07b book hold: {what} -> {} {}", r.code, r.message);
        assert_eq!(r.code, want, "{what}: {r}");
        assert_eq!(h.db.frontier().unwrap(), head, "{what}: nothing written");
    }

    let placed = h
        .place_reach(
            &counsel,
            HoldReach::Through(appointment),
            order.oid(),
            b"book-hold",
        )
        .expect("placed");
    eprintln!(
        "k07b book hold: placed {:032x} through seq {} at seq {}",
        placed.hold.0, appointment.0, placed.recorded_at.0
    );
    assert_eq!(
        (placed.subjects.clone(), placed.through),
        (Vec::new(), Some(appointment))
    );
    assert!(
        h.db.edge(edge_id(relation::HOLDS, placed.hold, book_root()))
            .unwrap()
            .is_some(),
        "the hold points at the book root"
    );
    // Everything recorded at or before the appointment is held, the
    // authority document included; nothing recorded after it is.
    for (what, subject) in [
        ("the pre-appointment entry", held_entry),
        ("the pre-appointment document", held_doc),
        ("the order", document_vid(&order.oid())),
    ] {
        assert_eq!(h.holds_on(subject), vec![placed.hold], "{what}");
    }
    for (what, subject) in [
        ("the post-appointment entry", later_entry),
        ("the post-appointment document", later_doc),
        ("the hold's own placement", placed.hold),
        ("the book root", book_root()),
    ] {
        assert_eq!(h.holds_on(subject), Vec::<VId>::new(), "{what}");
    }
    let r = h.erase(&eraser, held_entry);
    assert_eq!((r.code, r.exit), ("FA-REF-117", exit::SAFETY), "{r}");
    assert!(
        r.message.contains(&format!("{:032x}", placed.hold.0)),
        "{r}"
    );
    assert_eq!(h.erase(&eraser, held_doc).code, "FA-REF-117");
    assert_eq!(h.erase(&eraser, later_doc).code, "FA-REF-088");
    let read = read_legal_hold(&h.db, h.book.book_id, placed.hold)
        .unwrap()
        .expect("a placed hold");
    assert_eq!(
        (
            read.authority,
            read.through,
            read.subjects.len(),
            read.released
        ),
        (order.oid(), Some(appointment), 0, None)
    );

    // The same placement again is its recorded outcome.
    let again = h
        .place_reach(
            &counsel,
            HoldReach::Through(appointment),
            order.oid(),
            b"book-hold",
        )
        .expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(
        (again.hold, again.through),
        (placed.hold, Some(appointment))
    );

    // Through the head: the head when placed, and the same request again is
    // that recorded hold however far the head has moved.
    let head = h.db.frontier().unwrap();
    let at_head = h
        .place_reach(&counsel, HoldReach::ThroughHead, order.oid(), b"head-hold")
        .expect("placed");
    assert_eq!(at_head.through, Some(head));
    assert_eq!(h.holds_on(later_doc), vec![at_head.hold]);
    let retried = h
        .place_reach(&counsel, HoldReach::ThroughHead, order.oid(), b"head-hold")
        .expect("recorded");
    assert!(retried.already_recorded);
    assert_eq!((retried.hold, retried.through), (at_head.hold, Some(head)));
    let mut covering = vec![placed.hold, at_head.hold];
    covering.sort_by_key(|v| v.0);
    assert_eq!(h.holds_on(held_doc), covering);
    let plan = h
        .plan_hold_release(at_head.hold, b"head-release")
        .expect("planned");
    let digest = plan.proposal_digest(&h.book).unwrap();
    let approval = h
        .approve_digest(RELEASE_APPROVER, digest)
        .expect("recorded");
    h.release_hold(&plan, &[approval]).expect("released");
    assert_eq!(h.holds_on(later_doc), Vec::<VId>::new());
    assert_eq!(h.holds_on(held_doc), vec![placed.hold]);

    // A subject hold on a covered entry stands beside the book hold.
    let named = h
        .place_hold(&counsel, vec![held_entry], order.oid(), b"named-hold")
        .expect("placed");
    let mut both = vec![placed.hold, named.hold];
    both.sort_by_key(|v| v.0);
    assert_eq!(h.holds_on(held_entry), both);

    // Releasing the book hold, approved by a second Human, unpins what only
    // it held.
    let plan = h
        .plan_hold_release(placed.hold, b"book-release")
        .expect("planned");
    let digest = plan.proposal_digest(&h.book).unwrap();
    let approval = h
        .approve_digest(RELEASE_APPROVER, digest)
        .expect("recorded");
    let released = h.release_hold(&plan, &[approval]).expect("released");
    eprintln!(
        "k07b book hold: released {:032x} at seq {}",
        released.hold.0, released.recorded_at.0
    );
    assert_eq!(h.holds_on(held_doc), Vec::<VId>::new());
    assert_eq!(h.holds_on(held_entry), vec![named.hold]);
    assert_eq!(h.erase(&eraser, held_doc).code, "FA-REF-088");
    assert_eq!(h.erase(&eraser, held_entry).code, "FA-REF-117");
}

/// Ruling 3251: a hold pins the record, never the reservation. A Pending
/// under hold still expires at its deadline, and the hold still stands on it.
#[test]
fn a_held_pending_still_expires_at_its_deadline() {
    let mut h = harness();
    let order = h.document(INVOICE, HUMAN_UPLOAD, b"PRESERVATION ORDER 2026-18");
    h.add_document(&order).expect("admitted");
    h.tick(1_000, b"tick-1", 63);
    let mut timed = h.pending(h.rent_legs(10), b"timed-held");
    timed.pending = Some(Pending {
        timeout_ns: Some(10),
        resolution_of: None,
        disposition: None,
    });
    let pending = h
        .post(h.request(timed, &["post"]))
        .expect("admitted")
        .entry_ref();
    let counsel = Capability::embedded(PRINCIPAL, &["hold"]).expect("hold");
    let placed = h
        .place_hold(&counsel, vec![pending.vid], order.oid(), b"hold-pending")
        .expect("placed");
    h.tick(1_020, b"tick-2", 64);
    let swept = h.sweep_expiry();
    let expired: Vec<(EntryRef, EntryRef)> = swept
        .expiry
        .iter()
        .flat_map(|b| b.expired.iter().cloned())
        .collect();
    eprintln!(
        "txf hold: the sweep expired {} held Pending(s)",
        expired.len()
    );
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].0, pending);
    assert_eq!(expired[0].1.vid, resolution_vid(pending.vid));
    assert!(h.db.vertex(resolution_vid(pending.vid)).unwrap().is_some());
    let (resolution, born) = read_entry(&h.db, expired[0].1.vid).unwrap().unwrap();
    let claim =
        h.db.vertex(fa_model::intent_outcome_vid(
            h.book.book_id,
            &resolution.proposal.principal_ref.0.to_le_bytes(),
            &resolution.proposal.idempotency_key,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        claim.created_at, born,
        "automatic expiry reserves its key atomically"
    );
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(expired[0].1.vid.0.to_le_bytes().to_vec()).unwrap())
    );
    // The record is still preserved: the hold stands, erasure is refused.
    assert_eq!(h.holds_on(pending.vid), vec![placed.hold]);
    let eraser = Capability::embedded(PRINCIPAL, &["erase"]).expect("erase");
    assert_eq!(h.erase(&eraser, pending.vid).code, "FA-REF-117");
}

// ---------------------------------------------------------------------------
// Redacted views (fa-txf C2, plan §9.6): a privileged holder derives a view
// that proves itself against the document's commitment; a reader without
// `privileged` gets only the view, decided before any read of the bytes.
// ---------------------------------------------------------------------------

/// `evidence_policy.toml` kind tag of a bank statement (contract 1 governs it).
const BANK_STATEMENT: u8 = 5;

impl Harness {
    fn derive_view(
        &mut self,
        cap: &Capability,
        store: &BlobStore<fgdb::MemVfs>,
        oid: Oid,
    ) -> Result<ViewDerived, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { derive_redacted_view(db, &ctx, book, cap, store, oid).await })
            .expect("kernel")
    }

    fn read_for(
        &mut self,
        cap: &Capability,
        store: &BlobStore<fgdb::MemVfs>,
        oid: Oid,
    ) -> Result<DocumentRead, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { read_document_for(db, &ctx, book, cap, store, oid).await })
            .expect("kernel")
    }
}

fn redacted(read: DocumentRead) -> Option<RedactedView> {
    match read {
        DocumentRead::Redacted(view) => Some(view),
        DocumentRead::Full(_) => None,
    }
}

#[test]
fn a_privileged_holder_derives_the_view_a_reader_gets_in_place_of_the_bytes() {
    let mut h = harness();
    let store = blob_store(&h, "blobs");
    let account = b"ACCOUNT 0012-3456-7890";
    let mut bytes = b"STATEMENT OF ACCOUNT; HOLDER J. DOE; ".to_vec();
    bytes.extend_from_slice(account);
    bytes.extend(b"; ROUTING 021000021\n".repeat(200));
    bytes.extend(b"2026-03-03 RENT -450.00\n".repeat(300));
    let statement = h.document(BANK_STATEMENT, HUMAN_UPLOAD, &bytes);
    h.add_document(&statement).expect("admitted");
    let unviewed = h.document(BANK_STATEMENT, HUMAN_UPLOAD, b"STATEMENT 2 (no view yet)");
    h.add_document(&unviewed).expect("admitted");
    let invoice = h.document(
        INVOICE,
        HUMAN_UPLOAD,
        b"INVOICE 77 (no contract governs it)",
    );
    h.add_document(&invoice).expect("admitted");
    let counsel = Capability::embedded(PRINCIPAL, &["privileged"]).expect("privileged");
    let reader = Capability::embedded(VId(9), &["read"]).expect("read");
    let privileged_reader =
        Capability::embedded(VId(10), &["read", "privileged"]).expect("read, privileged");

    // Before any view exists, a plain reader is refused, never served bytes.
    let r = h.read_for(&reader, &store, statement.oid()).unwrap_err();
    eprintln!(
        "txf redaction: a read before derivation -> {} {}",
        r.code, r.message
    );
    assert_eq!((r.code, r.exit), ("FA-REF-142", exit::REFUSAL), "{r}");
    assert!(r.fix.contains("privileged"), "{}", r.fix);

    // Derivation needs `privileged`, a governed kind, a document of the book.
    let head = h.db.frontier().unwrap();
    for (what, cap, oid, want) in [
        ("a reader", &reader, statement.oid(), "FA-REF-011"),
        ("an ungoverned kind", &counsel, invoice.oid(), "FA-REF-100"),
        ("an unknown document", &counsel, Oid([3; 32]), "FA-REF-081"),
    ] {
        let r = h.derive_view(cap, &store, oid).unwrap_err();
        eprintln!(
            "txf redaction: derivation by {what} -> {} {}",
            r.code, r.message
        );
        assert_eq!(r.code, want, "{what}: {r}");
    }
    assert_eq!(h.db.frontier().unwrap(), head, "nothing written");

    let derived = h
        .derive_view(&counsel, &store, statement.oid())
        .expect("derived");
    eprintln!(
        "txf redaction: view {:032x} of {} under contract {}, view_commit {}",
        derived.view.0,
        fa_journal::evidence::hex(&statement.oid().0),
        derived.contract,
        fa_journal::evidence::hex(&derived.view_commit)
    );
    assert_eq!(
        (derived.view, derived.contract, derived.already_recorded),
        (
            redacted_view_vid(h.book.book_id, &statement.oid(), 1),
            1,
            false
        )
    );
    assert!(
        h.db.edge(edge_id(
            relation::REDACTS,
            derived.view,
            document_vid(&statement.oid())
        ))
        .unwrap()
        .is_some()
    );
    let again = h
        .derive_view(&counsel, &store, statement.oid())
        .expect("recorded");
    assert!(again.already_recorded);
    assert_eq!(
        (again.view, again.view_commit),
        (derived.view, derived.view_commit)
    );

    // The plain reader now gets the view: chunk 0 (the account block)
    // withheld, the rest disclosed, the commitment rebuilt from the view.
    let view = redacted(
        h.read_for(&reader, &store, statement.oid())
            .expect("a view"),
    )
    .expect("a redacted view, not the bytes");
    assert_eq!(view.verify(), Ok(()));
    assert_eq!(view.doc_commit, statement.doc_commit());
    assert!(matches!(view.chunks[0], ViewChunk::Withheld(_)));
    assert!(view.chunks.len() >= 3);
    let mut disclosed = 0;
    for (offset, chunk) in view.disclosed() {
        let o = usize::try_from(offset).unwrap();
        assert!(o >= 4096, "nothing of the account block is disclosed");
        assert_eq!(&statement.bytes[o..o + chunk.len()], chunk);
        disclosed += chunk.len();
    }
    assert_eq!(disclosed, statement.bytes.len() - 4096);
    let wire = view.canonical_bytes().unwrap();
    assert!(
        !wire.windows(account.len()).any(|w| w == account),
        "the account number never reaches the reader"
    );

    // A reader that reveals gets the verified bytes; an ungoverned kind is
    // read in full by anyone with `read`; no `read` is refused first.
    assert_eq!(
        h.read_for(&privileged_reader, &store, statement.oid()),
        Ok(DocumentRead::Full(statement.clone()))
    );
    assert_eq!(
        h.read_for(&reader, &store, invoice.oid()),
        Ok(DocumentRead::Full(invoice.clone()))
    );
    assert_eq!(
        h.read_for(&counsel, &store, statement.oid())
            .unwrap_err()
            .code,
        "FA-REF-011"
    );

    // A stored view is served only when it proves the commitment the book
    // recorded for the document, rebuilds it, and withholds exactly the
    // contract's chunks (WhiteCreek 3428); otherwise 143 (exit 8), never
    // served. Each forgery is planted at its target's view identity with a
    // recomputed view commitment.
    let foreign_target = h.document(BANK_STATEMENT, HUMAN_UPLOAD, b"STATEMENT 3 (target)");
    h.add_document(&foreign_target).expect("admitted");
    let mut leaky_bytes = b"ACCOUNT 9999-0000-1111; ".to_vec();
    leaky_bytes.extend(b"2026-03-05 FEE -12.00\n".repeat(250));
    let leaky = h.document(BANK_STATEMENT, HUMAN_UPLOAD, &leaky_bytes);
    h.add_document(&leaky).expect("admitted");
    // (1) A leaf changed: the view no longer rebuilds its commitment.
    let mut tampered = RedactedView::derive(&unviewed, 1, &[(0, 4096)]);
    if let ViewChunk::Withheld(leaf) = &mut tampered.chunks[0] {
        leaf[0] ^= 1;
    }
    // (2) A coherent view of other bytes, relabelled with the target's oid.
    let mut foreign = RedactedView::derive(
        &h.document(BANK_STATEMENT, HUMAN_UPLOAD, b"SOMEONE ELSE'S STATEMENT"),
        1,
        &[(0, 4096)],
    );
    foreign.original = foreign_target.oid();
    assert_eq!(foreign.verify(), Ok(()), "internally consistent");
    // (3) The genuine document with its privileged chunk disclosed.
    let disclosing = RedactedView::derive(&leaky, 1, &[]);
    assert_eq!(disclosing.verify(), Ok(()), "internally consistent");
    for (what, view, target) in [
        ("a changed leaf", tampered, unviewed.oid()),
        ("a foreign document's view", foreign, foreign_target.oid()),
        ("the privileged chunk disclosed", disclosing, leaky.oid()),
    ] {
        let mut batch = fgdb::WriteBatch::new(relation::REDACTS);
        batch.create_vertex(
            redacted_view_vid(h.book.book_id, &target, 1),
            vec![fa_model::symbols::label::REDACTED_VIEW],
            vec![
                (
                    property::FA_PAYLOAD,
                    CanonicalScalar::bytes(view.canonical_bytes().unwrap()).unwrap(),
                ),
                (
                    property::FA_DIGEST,
                    CanonicalScalar::bytes(view.view_commit().unwrap().to_vec()).unwrap(),
                ),
            ],
        );
        h.write_raw(batch);
        let r = h.read_for(&reader, &store, target).unwrap_err();
        eprintln!("txf redaction: {what} -> {} {}", r.code, r.message);
        assert_eq!(
            (r.code, r.exit),
            ("FA-REF-143", exit::VERIFICATION),
            "{what}: {r}"
        );
        // Derivation over a forged row refuses rather than overwrite it.
        let r = h.derive_view(&counsel, &store, target).unwrap_err();
        assert_eq!(r.code, "FA-REF-143", "{what}: {r}");
    }

    // A revoked capability learns nothing, not even whether a view exists:
    // 023 before any other read, for a reader and for a deriver alike.
    let deriver = Capability::embedded(VId(11), &["privileged"]).expect("privileged");
    for (n, revoked) in [(66u8, &reader), (67, &deriver)] {
        h.revoke(revoked, n);
    }
    let head = h.db.frontier().unwrap();
    let r = h.read_for(&reader, &store, statement.oid()).unwrap_err();
    assert_eq!(r.code, "FA-REF-023", "{r}");
    let r = h.derive_view(&deriver, &store, unviewed.oid()).unwrap_err();
    eprintln!(
        "txf redaction: a revoked deriver -> {} {}",
        r.code, r.message
    );
    assert_eq!(r.code, "FA-REF-023", "{r}");
    assert_eq!(h.db.frontier().unwrap(), head, "nothing written");
}

fn assert_leg_projections(h: &Harness) -> ProjectionVerification {
    let report = verify_projections(&h.db, &h.book, None).expect("projection snapshot");
    assert!(report.is_green(), "{report:?}");
    report
}

#[test]
fn projection_verification_covers_posted_pending_resolved_reversed_and_control_entries() {
    let mut h = harness();
    let empty = assert_leg_projections(&h);
    assert!(empty.entries_checked > 0, "the setup journals controls");
    assert_eq!((empty.legs_checked, empty.edges_checked), (0, 0));

    let invoice = h
        .post(h.request(h.invoice(1_200, b"projection-invoice"), &["post"]))
        .unwrap()
        .entry_ref();
    let first = assert_leg_projections(&h);
    assert_eq!((first.legs_checked, first.edges_checked), (2, 6));
    let unit = fa_model::unit_vid(h.book.book_id, "USD@v0");
    for ordinal in 0..2 {
        let lvid = leg_vid(invoice.vid, ordinal);
        let edge =
            h.db.edge(edge_id(relation::IN_UNIT, lvid, unit))
                .unwrap()
                .expect("a currency link is created with each leg");
        assert_eq!(edge.entry.src, lvid);
        assert_eq!(edge.entry.dst, unit);
        assert!(edge.props.is_empty());
        assert_eq!(
            h.db.vertex(lvid).unwrap().unwrap().created_at,
            h.db.vertex(invoice.vid).unwrap().unwrap().created_at,
            "payload and Leg are published by the same transaction"
        );
    }

    let receipt = h.receipt(
        500,
        vec![Settlement {
            target: invoice,
            ordinal: 0,
            amount: Amount::new(h.usd, 500),
        }],
        b"projection-receipt",
    );
    let receipt = h.post(h.request(receipt, &["post"])).unwrap().entry_ref();
    assert_eq!(h.applied_to(invoice.vid, 0), 500);
    assert_eq!(assert_leg_projections(&h).legs_checked, 4);

    let reversal = h.reversal_of_entry(receipt, b"projection-reversal");
    h.post(h.request(reversal, &["post"])).unwrap();
    assert_eq!(h.applied_to(invoice.vid, 0), 0);
    assert_eq!(assert_leg_projections(&h).legs_checked, 6);

    let pending = h.pending(h.rent_legs(900), b"projection-hold");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    assert_eq!(assert_leg_projections(&h).legs_checked, 8);
    let resolution =
        h.resolution_posts(hold, h.rent_legs(400), vec![0, 1], b"projection-resolution");
    h.post(h.request(resolution, &["post"])).unwrap();
    assert_eq!(assert_leg_projections(&h).legs_checked, 10);

    let pending = h.pending(h.rent_legs(700), b"projection-void-hold");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let before_void = assert_leg_projections(&h);
    let void = h.resolution_voids(hold, b"projection-void");
    h.post(h.request(void, &["post"])).unwrap();
    let after_void = assert_leg_projections(&h);
    assert_eq!(after_void.entries_checked, before_void.entries_checked + 1);
    assert_eq!(after_void.legs_checked, before_void.legs_checked);
    assert_eq!(after_void.edges_checked, before_void.edges_checked);
}

#[test]
fn projection_verifier_detects_every_scalar_mirror_and_preserves_known_at() {
    let mut h = harness();
    let proposal = h.proposal(
        h.rent_legs(12_345),
        b"projection-mirrors",
        EntryClass::ORIGINAL,
    );
    let posted = h.post(h.request(proposal, &["post"])).unwrap();
    let entry = posted.entry_ref();
    let prefix = posted.recorded_at();
    let payload = read_entry(&h.db, entry.vid).unwrap().unwrap();
    assert_leg_projections(&h);
    let lvid = leg_vid(entry.vid, 0);
    let pristine = h.db.vertex(lvid).unwrap().unwrap();
    let cases = vec![
        (
            property::FA_EFFECTIVE_DAY,
            Some(CanonicalScalar::Int(i64::from(h.day().0) + 1)),
            "_fa_effective_day",
        ),
        (property::SIDE, Some(CanonicalScalar::Int(1)), "side"),
        (
            property::ACCOUNT_REF,
            Some(CanonicalScalar::bytes(h.cash.0.to_le_bytes().to_vec()).unwrap()),
            "account_ref",
        ),
        (
            property::UNIT_ID,
            Some(CanonicalScalar::Int(999)),
            "unit_id",
        ),
        (property::AMOUNT, Some(CanonicalScalar::Null), "amount"),
        (
            property::AMOUNT_BYTES,
            Some(CanonicalScalar::bytes(12_345_i128.to_le_bytes().to_vec()).unwrap()),
            "amount_bytes",
        ),
        (property::ORDINAL, Some(CanonicalScalar::Int(7)), "ordinal"),
        (property::AMOUNT, None, "amount"),
    ];
    for (key, value, field) in cases {
        let mut corrupt = fgdb::WriteBatch::new(relation::HAS_LEG);
        corrupt.set_vertex_property(lvid, key, value);
        h.write_raw(corrupt);
        let report = verify_projections(&h.db, &h.book, None).unwrap();
        assert!(!report.is_green(), "{field} was not detected");
        assert!(
            report.drift.iter().any(|message| {
                message.contains(&format!("{:032x}", lvid.0))
                    && message.contains(&format!("{field} mirror"))
            }),
            "{report:?}"
        );
        assert!(
            verify_projections(&h.db, &h.book, Some(prefix))
                .unwrap()
                .is_green(),
            "current drift must not contaminate the earlier snapshot"
        );
        assert_eq!(read_entry(&h.db, entry.vid).unwrap().unwrap(), payload);
        let mut restore = fgdb::WriteBatch::new(relation::HAS_LEG);
        restore.set_vertex_property(lvid, key, fa_journal::rows::prop(&pristine, key).cloned());
        h.write_raw(restore);
        assert_leg_projections(&h);
    }
}

#[test]
fn projection_verifier_checks_the_exact_wide_amount_fallback() {
    let mut h = harness();
    let proposal = h.proposal(
        h.rent_legs(i128::MAX),
        b"projection-wide",
        EntryClass::ORIGINAL,
    );
    let posted = h.post(h.request(proposal, &["post"])).unwrap();
    let lvid = leg_vid(posted.entry_ref().vid, 0);
    let row = h.db.vertex(lvid).unwrap().unwrap();
    assert_eq!(
        fa_journal::rows::prop(&row, property::AMOUNT),
        Some(&CanonicalScalar::Null)
    );
    assert_eq!(
        fa_journal::rows::bytes(&row, property::AMOUNT_BYTES, "wide amount").unwrap(),
        i128::MAX.to_le_bytes()
    );
    assert_leg_projections(&h);
    let mut missing = fgdb::WriteBatch::new(relation::HAS_LEG);
    missing.set_vertex_property(lvid, property::AMOUNT_BYTES, None);
    h.write_raw(missing);
    let report = verify_projections(&h.db, &h.book, None).unwrap();
    assert!(!report.is_green());
    assert!(
        report
            .drift
            .iter()
            .any(|message| message.contains("amount_bytes mirror")),
        "{report:?}"
    );
}

#[test]
fn projection_verifier_rejects_missing_extra_and_misdirected_topology() {
    use fa_model::symbols::label;
    use fgdb_types::EId;

    for plant in 0..7 {
        let mut h = harness();
        let p = h.proposal(
            h.rent_legs(100),
            b"projection-topology",
            EntryClass::ORIGINAL,
        );
        let posted = h.post(h.request(p, &["post"])).unwrap();
        let entry = posted.entry_ref().vid;
        let lvid = leg_vid(entry, 0);
        let mut corrupt = match plant {
            0 | 1 | 4 | 5 => fgdb::WriteBatch::new(relation::HAS_LEG),
            2 | 3 => fgdb::WriteBatch::new(relation::POSTS_TO),
            _ => fgdb::WriteBatch::new(relation::IN_UNIT),
        };
        match plant {
            0 => {
                corrupt.delete_edge(edge_id(relation::HAS_LEG, entry, lvid));
            }
            1 => {
                corrupt.set_edge_property(
                    edge_id(relation::HAS_LEG, entry, lvid),
                    property::ORDINAL,
                    Some(CanonicalScalar::Int(9)),
                );
            }
            2 => {
                corrupt.add_edge(
                    edge_id(relation::POSTS_TO, lvid, h.cash),
                    lvid,
                    h.cash,
                    vec![],
                );
            }
            3 => {
                corrupt.add_edge(EId(0xe17e), lvid, h.rent, vec![]);
            }
            4 => {
                let extra = VId(0x1e6);
                let props = h.db.vertex(lvid).unwrap().unwrap().props;
                corrupt.create_vertex(extra, vec![label::LEG], props);
                corrupt.add_edge(
                    edge_id(relation::HAS_LEG, entry, extra),
                    entry,
                    extra,
                    vec![(property::ORDINAL, CanonicalScalar::Int(2))],
                );
            }
            5 => {
                corrupt.set_vertex_label(lvid, label::LEG, false);
            }
            _ => {
                let unit = fa_model::unit_vid(h.book.book_id, "USD@v0");
                corrupt.delete_edge(edge_id(relation::IN_UNIT, lvid, unit));
            }
        }
        h.write_raw(corrupt);
        let report = verify_projections(&h.db, &h.book, None).unwrap();
        assert!(!report.is_green(), "topology plant {plant}: {report:?}");
        assert!(
            verify_projections(&h.db, &h.book, Some(posted.recorded_at()))
                .unwrap()
                .is_green()
        );
    }
}

#[test]
fn dimension_edges_are_published_with_legs_and_their_metadata_is_verified() {
    let mut h = harness_with_entities(vec![LegalEntitySpec {
        code: "co".into(),
        name: "Test legal entity".into(),
        functional_unit: UnitId(0),
    }]);
    let entity = fa_model::entity_value_vid(h.book.book_id, "co");
    let mut p = h.proposal(h.rent_legs(100), b"projection-entity", EntryClass::ORIGINAL);
    for leg in &mut p.legs {
        leg.dimension_set = vec![(fa_model::LEGAL_ENTITY_DIMENSION, entity)];
    }
    let posted = h.post(h.request(p, &["post"])).unwrap();
    let report = assert_leg_projections(&h);
    assert_eq!((report.legs_checked, report.edges_checked), (2, 8));
    let lvid = leg_vid(posted.entry_ref().vid, 0);
    let eid = edge_id(relation::FOR, lvid, entity);
    let edge = h.db.edge(eid).unwrap().expect("the dimension projection");
    assert_eq!(edge.entry.src, lvid);
    assert_eq!(edge.entry.dst, entity);
    assert_eq!(
        edge.props,
        vec![(
            property::DIMENSION_ID,
            CanonicalScalar::Int(i64::from(fa_model::LEGAL_ENTITY_DIMENSION)),
        )]
    );
    let mut corrupt = fgdb::WriteBatch::new(relation::FOR);
    corrupt.set_edge_property(eid, property::DIMENSION_ID, Some(CanonicalScalar::Int(999)));
    h.write_raw(corrupt);
    let report = verify_projections(&h.db, &h.book, None).unwrap();
    assert!(!report.is_green());
    assert!(
        report
            .drift
            .iter()
            .any(|message| message.contains("FOR edge") && message.contains("properties")),
        "{report:?}"
    );
    assert!(
        verify_projections(&h.db, &h.book, Some(posted.recorded_at()))
            .unwrap()
            .is_green()
    );
}

#[test]
fn journaled_units_are_runtime_truth_and_binary_extensions_do_not_install_units() {
    let h = harness();
    let mut supported = h.book.units.clone();
    let extra = supported
        .register(fa_money::Unit {
            code: "FUTURE".into(),
            version: 0,
            scale: 4,
            kind: fa_money::UnitKind::Custom,
            rounding_default: fa_money::RoundingLaw::Floor,
        })
        .unwrap();
    let loaded = genesis::read_units(&h.db, h.book.book_id, &supported).unwrap();
    assert!(
        loaded.get(extra).is_none(),
        "binary additions must be journaled before use"
    );
    assert_eq!(
        loaded.iter().collect::<Vec<_>>(),
        h.book.units.iter().collect::<Vec<_>>()
    );
    for (id, unit) in loaded.iter() {
        let vid = fa_model::unit_vid(h.book.book_id, &format!("{}@v{}", unit.code, unit.version));
        let row = h.db.vertex(vid).unwrap().unwrap();
        let bytes = rows::bytes(&row, property::FA_PAYLOAD, "unit.payload").unwrap();
        let definition = fa_model::UnitDefinition::decode(&bytes).unwrap();
        assert_eq!(definition.id, id);
        assert_eq!(&definition.unit, unit);
    }
}

#[test]
fn unit_reconciliation_refuses_every_changed_historical_meaning() {
    let h = harness();
    for change in [
        "code", "version", "scale", "kind", "ISO", "rounding", "missing",
    ] {
        let mut supported = UnitRegistry::empty();
        for (id, unit) in h.book.units.iter() {
            if change == "missing" && id.0 + 1 == h.book.units.len() as u32 {
                continue;
            }
            let mut unit = unit.clone();
            if id == h.usd {
                match change {
                    "code" => unit.code = "CHANGED".into(),
                    "version" => unit.version = 1,
                    "scale" => unit.scale = 4,
                    "kind" => unit.kind = fa_money::UnitKind::Custom,
                    "ISO" => unit.kind = fa_money::UnitKind::Currency { iso4217: 978 },
                    "rounding" => unit.rounding_default = fa_money::RoundingLaw::HalfUp,
                    "missing" => {}
                    _ => unreachable!(),
                }
            }
            supported.register(unit).unwrap();
        }
        let before = h.db.frontier().unwrap();
        let error = genesis::read_units(&h.db, h.book.book_id, &supported)
            .unwrap_err()
            .to_string();
        let field = match change {
            "ISO" | "kind" => "kind/ISO",
            "rounding" => "default rounding law",
            "missing" => "unsupported unit",
            other => other,
        };
        assert!(error.contains(field), "{change}: {error}");
        assert_eq!(h.db.frontier().unwrap(), before);
    }
}

#[test]
fn unit_payload_and_table_commitment_damage_are_refused_without_repair() {
    for damage in [
        "truncated",
        "major",
        "minor",
        "missing_payload",
        "payload_type",
        "missing_table",
        "table_type",
        "table_digest",
        "last_membership",
        "book_id",
        "code",
        "version",
        "id",
        "scale",
    ] {
        let mut h = harness();
        let uvid = fa_model::unit_vid(h.book.book_id, "USD@v0");
        let row = h.db.vertex(uvid).unwrap().unwrap();
        let mut payload = rows::bytes(&row, property::FA_PAYLOAD, "unit.payload").unwrap();
        let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
        match damage {
            "truncated" | "major" | "minor" => {
                match damage {
                    "truncated" => {
                        payload.pop();
                    }
                    "major" => payload[4] = 2,
                    "minor" => payload[6] = 1,
                    _ => unreachable!(),
                }
                batch.set_vertex_property(
                    uvid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(payload).unwrap()),
                );
            }
            "missing_payload" => {
                batch.set_vertex_property(uvid, property::FA_PAYLOAD, None);
            }
            "payload_type" => {
                batch.set_vertex_property(
                    uvid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::Int(1)),
                );
            }
            "missing_table" => {
                batch.set_vertex_property(book_root(), property::UNIT_TABLE_DIGEST, None);
            }
            "table_type" => {
                batch.set_vertex_property(
                    book_root(),
                    property::UNIT_TABLE_DIGEST,
                    Some(CanonicalScalar::Int(1)),
                );
            }
            "table_digest" => {
                batch.set_vertex_property(
                    book_root(),
                    property::UNIT_TABLE_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
                );
            }
            "last_membership" => {
                let (_, last) = h.book.units.iter().last().unwrap();
                let last_vid =
                    fa_model::unit_vid(h.book.book_id, &format!("{}@v{}", last.code, last.version));
                batch.delete_edge(edge_id(relation::IN_BOOK, last_vid, book_root()));
            }
            "book_id" => {
                batch.set_vertex_property(
                    uvid,
                    property::BOOK_ID,
                    Some(CanonicalScalar::bytes(vec![0xff; 16]).unwrap()),
                );
            }
            "code" => {
                batch.set_vertex_property(
                    uvid,
                    property::CODE,
                    Some(CanonicalScalar::ucs_basic_text("CHANGED").unwrap()),
                );
            }
            "version" => {
                batch.set_vertex_property(uvid, property::VERSION, Some(CanonicalScalar::Int(1)));
            }
            "id" => {
                batch.set_vertex_property(uvid, property::UNIT_ID, Some(CanonicalScalar::Int(99)));
            }
            "scale" => {
                batch.set_vertex_property(uvid, property::SCALE, Some(CanonicalScalar::Int(4)));
            }
            _ => unreachable!(),
        }
        h.write_raw(batch);
        let before = h.db.frontier().unwrap();
        let error = genesis::read_units(&h.db, h.book.book_id, &h.book.units)
            .unwrap_err()
            .to_string();
        if damage.starts_with("missing") {
            assert!(error.contains("pre-payload"), "{damage}: {error}");
            assert!(error.contains("no backfill"), "{damage}: {error}");
        } else {
            assert!(error.contains("unit"), "{damage}: {error}");
        }
        assert_eq!(
            h.db.frontier().unwrap(),
            before,
            "{damage} must not repair silently"
        );
    }
}

impl Harness {
    fn post_plan(&mut self, request: PostRequest) -> Result<fa_intents::PostPlan, Refusal> {
        assert!(request.plan_certificate.is_none());
        let intent =
            fa_intents::PostIntent::new(request.proposal, request.approvals).expect("typed intent");
        let ctx = self.ctx();
        plan_post(&mut self.db, &ctx, &self.book, request.capability, intent)
            .expect("planning kernel")
    }

    fn publish_plan(
        &mut self,
        plan: fa_intents::PostPlan,
        capability: &Capability,
    ) -> Result<Posted, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let capability = capability.clone();
        self.runtime
            .block_on(async move { commit_plan(db, &ctx, book, capability, plan).await })
            .expect("plan commit kernel")
    }

    fn replacement_plan(
        &mut self,
        reversal: PostRequest,
        replacement: PostRequest,
    ) -> Result<fa_intents::ReplacementPlan, Refusal> {
        assert!(reversal.plan_certificate.is_none());
        assert!(replacement.plan_certificate.is_none());
        assert_eq!(
            reversal.capability.commitment().unwrap(),
            replacement.capability.commitment().unwrap()
        );
        let first = fa_intents::PostIntent::new(reversal.proposal, reversal.approvals).unwrap();
        let second =
            fa_intents::PostIntent::new(replacement.proposal, replacement.approvals).unwrap();
        let ctx = self.ctx();
        plan_replacement(
            &mut self.db,
            &ctx,
            &self.book,
            reversal.capability,
            first,
            second,
        )
        .expect("replacement planning kernel")
    }

    fn publish_replacement_plan(
        &mut self,
        plan: fa_intents::ReplacementPlan,
        capability: &Capability,
    ) -> Result<(Posted, Posted), Refusal> {
        let ctx = self.ctx();
        self.runtime
            .block_on(commit_replacement_plan(
                &mut self.db,
                &ctx,
                &self.book,
                capability.clone(),
                plan,
            ))
            .expect("replacement plan commit kernel")
    }

    fn planned_rent_correction(&self, target: EntryRef) -> (PostRequest, PostRequest) {
        (
            self.request(
                self.reversal_of_entry(target, b"portable-pair-reversal"),
                &["post"],
            ),
            self.request(
                replacement_proposal(
                    target,
                    self.proposal(
                        self.rent_legs(125),
                        b"portable-pair-replacement",
                        EntryClass::REPLACEMENT,
                    ),
                ),
                &["post"],
            ),
        )
    }
}

/// fa-llx: `commit_plan` admits only whole-book tokens, so a token with a
/// scope caveat is refused a plan up front, even for an entry its caveat
/// admits, and nothing is written.
#[test]
fn a_scoped_token_is_refused_a_plan_it_could_never_commit() {
    let mut h = harness();
    let proposal = h.proposal(h.rent_legs(12_345), b"scoped-plan", EntryClass::ORIGINAL);
    let mut request = h.request(proposal.clone(), &["post"]);
    request.capability = Capability::embedded(PRINCIPAL, &["post"])
        .unwrap()
        .for_periods(&[h.march.as_str()])
        .unwrap();
    let basis = h.db.frontier().unwrap();
    let before_vertices = h.db.vertices().unwrap();
    let refusal = h.post_plan(request).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-011");
    assert!(
        refusal
            .message
            .starts_with("the capability's `periods` caveat"),
        "{}",
        refusal.message
    );
    assert_eq!(h.db.frontier().unwrap(), basis);
    assert_eq!(h.db.vertices().unwrap(), before_vertices);
    h.post_plan(h.request(proposal, &["post"]))
        .expect("the same intent plans under a whole-book token");
}

/// fa-llx: a plan made under a whole-book token and presented with a scoped
/// token is refused by `commit_plan`'s whole-book admission; nothing is
/// recorded, and the planning token still commits it.
#[test]
fn a_scoped_token_cannot_commit_a_whole_book_plan() {
    let mut h = harness();
    let proposal = h.proposal(h.rent_legs(12_345), b"scoped-commit", EntryClass::ORIGINAL);
    let plan = h
        .post_plan(h.request(proposal, &["post"]))
        .expect("whole-book plan");
    let scoped = Capability::embedded(PRINCIPAL, &["post"])
        .unwrap()
        .for_periods(&[h.march.as_str()])
        .unwrap();
    let basis = h.db.frontier().unwrap();
    let refusal = h.publish_plan(plan.clone(), &scoped).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-011");
    assert!(
        refusal
            .message
            .starts_with("the capability's `periods` caveat"),
        "{}",
        refusal.message
    );
    assert_eq!(h.db.frontier().unwrap(), basis, "nothing is recorded");
    let cvid = plan_certificate_vid(h.book.book_id, &plan.certificate().digest().unwrap());
    assert!(h.db.vertex(cvid).unwrap().is_none());
    let whole = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let posted = h
        .publish_plan(plan, &whole)
        .expect("the planning token commits it");
    assert_eq!(posted.recorded_at().0, basis.0 + 1);
}

/// Plan §15.3: an Agent-profile capability may rehearse a trunk post. The
/// rehearsal runs every posting law and writes nothing. Its plan binds the
/// Agent's capability, so the Agent's commit is still FA-REF-013, a Human's
/// is refused because it does not hold the proposal's principal, and a
/// direct post by the Agent is still FA-REF-013. Nothing is recorded by any
/// of them.
#[test]
fn an_agent_rehearses_a_trunk_post_that_commits_for_no_one() {
    let mut h = harness();
    let agent_vid = VId(31);
    let agent = fa_policy::Capability::new(
        agent_vid,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Read, fa_policy::Op::Post],
        PRINCIPAL,
    )
    .expect("an agent may hold post");
    let mut proposal = h.proposal(
        h.rent_legs(12_345),
        b"agent-rehearsal",
        EntryClass::ORIGINAL,
    );
    proposal.principal_ref = agent_vid;
    let request = PostRequest {
        proposal: proposal.clone(),
        approvals: Vec::new(),
        capability: agent.clone(),
        plan_certificate: None,
    };
    let basis = h.db.frontier().unwrap();
    let before_vertices = h.db.vertices().unwrap();
    let plan = h
        .post_plan(request.clone())
        .expect("an Agent rehearses a trunk post under every posting law");
    let hex = |bytes: &[u8; 32]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    eprintln!(
        "agent rehearsal: proposal {} effects {} basis {}",
        hex(&plan.certificate().proposal_digest),
        hex(&plan.certificate().effects_digest),
        plan.certificate().snapshot_seq.0
    );
    assert_eq!(plan.certificate().principal, agent_vid);
    assert_eq!(plan.certificate().snapshot_seq, basis);
    assert_eq!(
        h.db.frontier().unwrap(),
        basis,
        "the rehearsal writes nothing"
    );
    assert_eq!(h.db.vertices().unwrap(), before_vertices);

    let r = h.publish_plan(plan.clone(), &agent).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-013", exit::SAFETY), "{r}");
    assert!(r.fix.contains("--dry-run"), "{}", r.fix);
    let human = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let r = h.publish_plan(plan, &human).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY), "{r}");
    let r = h.post(request).unwrap_err();
    assert_eq!(r.code, "FA-REF-013", "{r}");
    assert_eq!(h.db.frontier().unwrap(), basis, "nothing was recorded");
    assert_eq!(h.db.vertices().unwrap(), before_vertices);

    // A rehearsal is not a weaker law: an unbalanced Agent intent is refused
    // exactly as a Human's is.
    let mut unbalanced = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 100)),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 99)),
        ],
        b"agent-unbalanced",
        EntryClass::ORIGINAL,
    );
    unbalanced.principal_ref = agent_vid;
    let r = h
        .post_plan(PostRequest {
            proposal: unbalanced,
            approvals: Vec::new(),
            capability: agent,
            plan_certificate: None,
        })
        .unwrap_err();
    eprintln!("agent rehearsal: unbalanced -> {} {}", r.code, r.message);
    assert_ne!(
        r.code, "FA-REF-013",
        "the posting law refuses, not the profile: {r}"
    );
    assert_eq!(h.db.frontier().unwrap(), basis);
}

#[test]
fn portable_post_plan_is_zero_write_and_retains_exact_evidence_with_its_entry() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(h.rent_legs(12_345), b"portable-plan", EntryClass::ORIGINAL);
    let request = h.request(proposal.clone(), &["post"]);
    let basis = h.db.frontier().unwrap();
    let before_vertices = h.db.vertices().unwrap();
    let plan = h.post_plan(request).expect("full rehearsal admitted");
    assert_eq!(h.db.frontier().unwrap(), basis);
    assert_eq!(h.db.vertices().unwrap(), before_vertices);
    assert_eq!(plan.certificate().snapshot_seq, basis);
    assert_eq!(plan.certificate().period, h.march);
    assert_eq!(plan.proposal(), &proposal);
    assert_eq!(plan.intent().proposal(), &proposal);
    assert_eq!(
        plan.certificate().proposal_digest,
        proposal.proposal_digest().unwrap()
    );
    assert_eq!(
        plan.certificate().intent_digest,
        plan.intent().digest().unwrap()
    );
    let digest = plan.certificate().digest().unwrap();
    let cvid = plan_certificate_vid(h.book.book_id, &digest);
    assert!(
        h.db.vertex(cvid).unwrap().is_none(),
        "dry-run retains no graph record"
    );

    // Portable bytes preserve the original ciphertext/salt/nonce. Repeating
    // the same exact rehearsal at this basis is deterministic.
    let bytes = plan.canonical_bytes().unwrap();
    let decoded = fa_intents::PostPlan::decode(&bytes).unwrap();
    assert_eq!(decoded, plan);
    let repeat = h.post_plan(h.request(proposal.clone(), &["post"])).unwrap();
    assert_eq!(repeat, plan);
    let mut resealed = proposal;
    resealed.description = Erasable::seal(
        &"March rent".to_string(),
        None,
        &h.book.seal_key,
        [9; 32],
        [8; 24],
    );
    let resealed_intent = fa_intents::PostIntent::new(resealed, Vec::new()).unwrap();
    assert_ne!(
        resealed_intent.digest().unwrap(),
        plan.intent().digest().unwrap()
    );

    let posted = h
        .publish_plan(decoded, &capability)
        .expect("verified publication");
    assert!(matches!(posted, Posted::Committed { .. }));
    assert_eq!(posted.recorded_at().0, basis.0 + 1);
    let (entry, recorded_at) = read_entry(&h.db, posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(&entry, plan.prepared_entry());
    assert_eq!(recorded_at, posted.recorded_at());
    assert!(
        entry.plan_certificate.is_none(),
        "graph evidence is not a native OID"
    );
    let retained = h.db.vertex(cvid).unwrap().unwrap();
    assert_eq!(retained.created_at, posted.recorded_at());
    assert_eq!(
        fa_journal::rows::bytes(&retained, property::FA_PAYLOAD, "plan").unwrap(),
        bytes,
    );
    assert_eq!(
        fa_journal::rows::bytes(&retained, property::FA_DIGEST, "digest").unwrap(),
        digest,
    );
    let cites =
        h.db.edge(edge_id(relation::CITES, posted.entry_ref().vid, cvid))
            .unwrap()
            .unwrap();
    assert_eq!(cites.entry.created_at, posted.recorded_at());
    assert_eq!(
        (cites.entry.src, cites.entry.dst),
        (posted.entry_ref().vid, cvid)
    );
    let after = h.db.frontier().unwrap();
    let retry = h
        .publish_plan(plan.clone(), &capability)
        .expect("exact outcome retry");
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), after);

    // The public raw-post boundary remains closed to arbitrary ObjectIds.
    let mut raw = h.request(
        h.proposal(h.rent_legs(1), b"fake-native-oid", EntryClass::ORIGINAL),
        &["post"],
    );
    raw.plan_certificate = Some(Oid(digest));
    assert_eq!(h.post(raw).unwrap_err().code, "FA-REF-102");
    assert_eq!(h.db.frontier().unwrap(), after);
}

#[test]
fn portable_post_plan_authentication_and_actual_effect_comparison_both_fail_closed() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(h.rent_legs(1_000), b"plan-tamper", EntryClass::ORIGINAL);
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    let before = h.db.frontier().unwrap();
    for damage in [
        "effects",
        "basis",
        "epoch",
        "period",
        "capability",
        "expiry",
        "tag",
    ] {
        let mut certificate = plan.certificate().clone();
        match damage {
            "effects" => certificate.effects_digest[0] ^= 1,
            "basis" => certificate.snapshot_seq.0 += 1,
            "epoch" => certificate.security_policy_epoch += 1,
            "period" => certificate.period = h.april.clone(),
            "capability" => certificate.capability_commitment[0] ^= 1,
            "expiry" => certificate.expires_at = Some(fgdb_types::CommitSeq(before.0 + 5)),
            "tag" => certificate.authentication[0] ^= 1,
            _ => unreachable!(),
        }
        let changed = fa_intents::PostPlan::new(
            plan.intent().clone(),
            plan.prepared_entry().clone(),
            certificate,
        )
        .unwrap();
        let refusal = h.publish_plan(changed, &capability).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-034", exit::CONFLICT),
            "{damage}"
        );
        assert_eq!(h.db.frontier().unwrap(), before, "{damage}");
    }

    // A test issuer holding the actual book key can make an authentic but
    // false effects claim. The kernel must still compare the native staged
    // transaction; verifying only the authentication tag would admit this.
    let mut certificate = plan.certificate().clone();
    certificate.effects_digest[0] ^= 1;
    let key = fgdb_crypto::derive_key("fa:post-plan-authentication-key:v1", &h.book.seal_key.0);
    certificate.authentication =
        fgdb_crypto::keyed_hash(&key, &certificate.authentication_bytes().unwrap()).0;
    let changed = fa_intents::PostPlan::new(
        plan.intent().clone(),
        plan.prepared_entry().clone(),
        certificate,
    )
    .unwrap();
    let refusal = h.publish_plan(changed, &capability).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-034", exit::CONFLICT));
    assert!(refusal.message.contains("native effects"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(
        h.db.vertex(entry_vid(
            h.book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            b"plan-tamper"
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
fn portable_post_plan_rejects_changed_intent_even_with_recomputed_public_digests() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(h.rent_legs(1_000), b"plan-body", EntryClass::ORIGINAL);
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    let before = h.db.frontier().unwrap();
    let mut proposal = plan.intent().proposal().clone();
    for leg in &mut proposal.legs {
        leg.amount.mantissa += 1;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let intent = fa_intents::PostIntent::new(proposal.clone(), Vec::new()).unwrap();
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let mut certificate = plan.certificate().clone();
    certificate.intent_digest = intent.digest().unwrap();
    certificate.proposal_digest = entry.proposal_digest;
    let forged = fa_intents::PostPlan::new(intent, entry, certificate).unwrap();
    let refusal = h.publish_plan(forged, &capability).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-034", exit::CONFLICT));
    assert!(
        refusal.message.contains("authenticated fields changed"),
        "{refusal}"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn portable_post_plan_invalidation_and_exact_retry_have_distinct_basis_rules() {
    for change in ["unrelated", "close", "epoch"] {
        let mut h = harness();
        let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
        let proposal = h.proposal(h.rent_legs(500), b"stale-plan", EntryClass::ORIGINAL);
        let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
        match change {
            "unrelated" => {
                h.post(h.request(h.invoice(100, b"other-entry"), &["post"]))
                    .unwrap();
            }
            "close" => {
                let march = h.march.clone();
                h.transition(&march, PeriodTransition::SoftClose, b"soft-close-plan")
                    .unwrap();
                h.transition(&march, PeriodTransition::Close, b"close-plan")
                    .unwrap();
            }
            "epoch" => {
                // A planted epoch change exercises stale-basis behavior
                // independently of the policy activation command's laws.
                let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
                batch.set_vertex_property(
                    book_root(),
                    property::SECURITY_POLICY_EPOCH,
                    Some(CanonicalScalar::Int(1)),
                );
                h.write_raw(batch);
            }
            _ => unreachable!(),
        }
        let before = h.db.frontier().unwrap();
        let refusal = h.publish_plan(plan, &capability).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-034", exit::CONFLICT),
            "{change}"
        );
        assert_eq!(h.db.frontier().unwrap(), before, "{change}");
    }

    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(h.rent_legs(500), b"recorded-plan", EntryClass::ORIGINAL);
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    // fa-1nx: pure metadata commits (e.g. a retained report Certificate) advance
    // the raw commit sequence without moving the accounting frontier, so they
    // must not invalidate an outstanding PostPlan.
    let mut cert_batch = fgdb::WriteBatch::new(relation::IN_BOOK);
    cert_batch.create_vertex(
        VId(0xDEAD_BEEF_CAFE_0001),
        vec![fa_model::symbols::label::CERTIFICATE],
        vec![(
            property::FA_DIGEST,
            CanonicalScalar::bytes(vec![0xAB; 32]).unwrap(),
        )],
    );
    h.write_raw(cert_batch);
    assert!(h.db.frontier().unwrap() > plan.certificate().snapshot_seq);
    let posted = h.publish_plan(plan.clone(), &capability).unwrap();
    assert!(matches!(posted, Posted::Committed { .. }));
    assert_eq!(
        posted.recorded_at().0,
        plan.certificate().snapshot_seq.0 + 2
    );
    h.post(h.request(h.invoice(100, b"after-plan"), &["post"]))
        .unwrap();
    let before = h.db.frontier().unwrap();
    let retry = h.publish_plan(plan, &capability).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn portable_post_plan_cannot_claim_a_direct_post_or_changed_retaining_evidence() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(
        h.rent_legs(500),
        b"direct-not-planned",
        EntryClass::ORIGINAL,
    );
    let plan = h.post_plan(h.request(proposal.clone(), &["post"])).unwrap();
    h.post(h.request(proposal, &["post"])).unwrap();
    let before = h.db.frontier().unwrap();
    assert_eq!(
        h.publish_plan(plan, &capability).unwrap_err().code,
        "FA-REF-034"
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    for damage in ["payload", "digest", "book", "entry", "cites"] {
        let mut h = harness();
        let proposal = h.proposal(h.rent_legs(500), b"retention-damage", EntryClass::ORIGINAL);
        let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
        let posted = h.publish_plan(plan.clone(), &capability).unwrap();
        let cvid = plan_certificate_vid(h.book.book_id, &plan.certificate().digest().unwrap());
        let mut batch = fgdb::WriteBatch::new(relation::CITES);
        match damage {
            "payload" => {
                batch.set_vertex_property(cvid, property::FA_PAYLOAD, None);
            }
            "digest" => {
                batch.set_vertex_property(
                    cvid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
                );
            }
            "book" => {
                batch.set_vertex_property(
                    cvid,
                    property::BOOK_ID,
                    Some(CanonicalScalar::bytes(vec![0; 16]).unwrap()),
                );
            }
            "entry" => {
                batch.set_vertex_property(
                    posted.entry_ref().vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
                );
            }
            "cites" => {
                batch.delete_edge(edge_id(relation::CITES, posted.entry_ref().vid, cvid));
            }
            _ => unreachable!(),
        }
        h.write_raw(batch);
        let before = h.db.frontier().unwrap();
        let refusal = h.publish_plan(plan, &capability).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-034", exit::CONFLICT),
            "{damage}"
        );
        assert_eq!(h.db.frontier().unwrap(), before, "{damage}");
    }
}

#[test]
fn portable_post_plan_never_grants_authority_or_revives_an_expired_capability() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(h.rent_legs(500), b"plan-authority", EntryClass::ORIGINAL);
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    let before = h.db.frontier().unwrap();
    let agent = Capability::new(
        PRINCIPAL,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap();
    let refusal = h.publish_plan(plan.clone(), &agent).unwrap_err();
    assert_eq!(refusal.exit, exit::SAFETY, "{refusal}");
    let other = Capability::embedded(VId(99), &["post"]).unwrap();
    assert!(h.publish_plan(plan.clone(), &other).is_err());
    let changed_capability = capability.clone().with_ceiling(h.usd, 1_000).unwrap();
    assert_eq!(
        h.publish_plan(plan, &changed_capability).unwrap_err().code,
        "FA-REF-034"
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    let expiring = capability.expiring_at(fgdb_types::CommitSeq(before.0 + 1));
    let mut request = h.request(
        h.proposal(h.rent_legs(500), b"plan-expiry", EntryClass::ORIGINAL),
        &["post"],
    );
    request.capability = expiring.clone();
    let plan = h.post_plan(request).unwrap();
    let posted = h.publish_plan(plan.clone(), &expiring).unwrap();
    let refusal = h.publish_plan(plan, &expiring).unwrap_err();
    assert!(refusal.message.contains("expired"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
}

#[test]
fn portable_post_plans_cover_application_undo_and_target_derived_resolution_identities() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let invoice = h
        .post(h.request(h.invoice(1_000, b"plan-invoice"), &["post"]))
        .unwrap()
        .entry_ref();
    let receipt = h.receipt(600, vec![settle(invoice, 0, h.usd, 600)], b"plan-receipt");
    let plan = h.post_plan(h.request(receipt, &["post"])).unwrap();
    assert_eq!(
        h.applied_to(invoice.vid, 0),
        0,
        "rehearsal leaves applied unchanged"
    );
    let receipt = h.publish_plan(plan, &capability).unwrap().entry_ref();
    assert_eq!(h.applied_to(invoice.vid, 0), 600);
    let reversal = h.reversal_of_entry(receipt, b"plan-unsettle");
    let plan = h.post_plan(h.request(reversal, &["post"])).unwrap();
    assert_eq!(
        h.applied_to(invoice.vid, 0),
        600,
        "undo rehearsal writes nothing"
    );
    let undone = h.publish_plan(plan.clone(), &capability).unwrap();
    assert_eq!(undone.entry_ref().vid, reversal_vid(receipt.vid));
    assert_eq!(h.applied_to(invoice.vid, 0), 0);
    assert_eq!(
        h.publish_plan(plan, &capability).unwrap().entry_ref(),
        undone.entry_ref()
    );

    let hold = h.pending(h.rent_legs(800), b"planned-hold");
    let plan = h.post_plan(h.request(hold, &["post"])).unwrap();
    let hold = h.publish_plan(plan, &capability).unwrap().entry_ref();
    let resolution = h.resolution_posts(hold, h.rent_legs(500), vec![0, 1], b"planned-resolution");
    let plan = h.post_plan(h.request(resolution, &["post"])).unwrap();
    assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
    let resolved = h.publish_plan(plan.clone(), &capability).unwrap();
    assert_eq!(resolved.entry_ref().vid, resolution_vid(hold.vid));
    assert_eq!(
        h.publish_plan(plan, &capability).unwrap().entry_ref(),
        resolved.entry_ref()
    );
}

#[test]
fn portable_post_plan_retains_requested_and_resolved_balancing_legs() {
    let mut h = harness_configured(
        Vec::new(),
        None,
        Some(BalanceLimit {
            lower: Some(-700),
            upper: None,
            scope: LimitScope::Lifetime,
        }),
    );
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let mut proposal = h.proposal(h.rent_legs(1_000), b"plan-balancing", EntryClass::ORIGINAL);
    proposal.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
    proposal.extensions.push((
        fa_model::entry::BALANCING_EXTENSION,
        limit::balancing_bytes(1, 1_000),
    ));
    let basis = h.db.frontier().unwrap();
    let cell = h.db.vertex(limit_cell_vid(h.cash)).unwrap().unwrap();
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    assert_eq!(plan.intent().proposal().legs[0].amount.mantissa, 1_000);
    assert_eq!(plan.proposal().legs[0].amount.mantissa, 700);
    assert_eq!(plan.proposal().legs[1].amount.mantissa, 700);
    assert_ne!(
        plan.intent().proposal().proposal_digest().unwrap(),
        plan.certificate().proposal_digest
    );
    assert_eq!(h.db.frontier().unwrap(), basis);
    assert_eq!(h.db.vertex(limit_cell_vid(h.cash)).unwrap().unwrap(), cell);
    let wire = plan.canonical_bytes().unwrap();
    let plan = fa_intents::PostPlan::decode(&wire).unwrap();
    let posted = h.publish_plan(plan.clone(), &capability).unwrap();
    let (entry, _) = read_entry(&h.db, posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(entry.proposal.legs[0].amount.mantissa, 700);
    let retry = h.publish_plan(plan, &capability).unwrap();
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
}

#[test]
fn portable_post_plan_preserves_scheduled_reversal_and_cancellation_digests() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = with_auto_reverse(
        h.proposal(h.rent_legs(100), b"planned-accrual", EntryClass::ADJUSTING),
        DateDay::from_ymd(2026, 4, 1).unwrap(),
    );
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    let basis = h.db.frontier().unwrap();
    assert_eq!(
        verify_schedules(&h.db, &h.book).unwrap().schedules_checked,
        0
    );
    let posted = h.publish_plan(plan, &capability).unwrap();
    assert_eq!(posted.recorded_at().0, basis.0 + 1);
    let schedule = schedule::decode_schedule(
        &h.db
            .vertex(fa_journal::rows::schedule_vid(posted.entry_ref().vid))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(schedule.target, posted.entry_ref());
    assert_eq!(schedule.recorded_at, posted.recorded_at());
    let verified = verify_schedules(&h.db, &h.book).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert_eq!(verified.schedules_checked, 1);
    let reversal = h.reversal_of_entry(posted.entry_ref(), b"planned-manual-reversal");
    let plan = h.post_plan(h.request(reversal, &["post"])).unwrap();
    assert_eq!(verify_schedules(&h.db, &h.book).unwrap().cancelled, 0);
    h.publish_plan(plan, &capability).unwrap();
    let verified = verify_schedules(&h.db, &h.book).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert_eq!(verified.cancelled, 1);
}

#[test]
fn portable_post_plan_requires_real_approvals_before_issuing_a_certificate() {
    let mut h = harness();
    let march = h.march.clone();
    h.transition(&march, PeriodTransition::Close, b"close-for-approved-plan")
        .unwrap();
    let capability = Capability::embedded(PRINCIPAL, &["post", "post_closed"]).unwrap();
    let proposal = h.proposal(h.rent_legs(100), b"approved-plan", EntryClass::ADJUSTING);
    let mut request = h.request(proposal.clone(), &["post", "post_closed"]);
    let before = h.db.frontier().unwrap();
    let refusal = h.post_plan(request.clone()).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-012", "{refusal}");
    assert_eq!(
        h.db.frontier().unwrap(),
        before,
        "failed rehearsal records nothing"
    );
    let approval = h.approve_transition(proposal.proposal_digest().unwrap());
    request.approvals = vec![approval];
    let plan = h.post_plan(request).unwrap();
    assert_eq!(plan.approvals(), &[approval]);
    assert_eq!(plan.certificate().snapshot_seq, h.db.frontier().unwrap());
    let posted = h.publish_plan(plan.clone(), &capability).unwrap();
    let (entry, _) = read_entry(&h.db, posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(entry.approvals, vec![approval]);
    assert_eq!(
        h.publish_plan(plan, &capability).unwrap().entry_ref(),
        posted.entry_ref()
    );
}

#[test]
fn portable_post_plan_checks_revocation_before_fresh_commit_and_recorded_outcome() {
    for already_recorded in [false, true] {
        let mut h = harness();
        let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
        let proposal = h.proposal(h.rent_legs(100), b"revoked-plan", EntryClass::ORIGINAL);
        let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
        if already_recorded {
            h.publish_plan(plan.clone(), &capability).unwrap();
        }
        let revoke = RevocationRequest {
            capability: Capability::embedded(VId(99), &["issue_capability"]).unwrap(),
            revoked: capability.commitment().unwrap(),
            effective_date: h.day(),
            idempotency_key: b"revoke-plan-capability".to_vec(),
            description: Erasable::seal(
                &"revoke planning authority".to_string(),
                None,
                &h.book.seal_key,
                [17; 32],
                [18; 24],
            ),
        };
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { revoke_capability(db, &ctx, book, revoke).await })
            .expect("revocation kernel")
            .expect("capability revoked");
        let before = h.db.frontier().unwrap();
        let refusal = h.publish_plan(plan, &capability).unwrap_err();
        assert!(
            refusal.message.contains("revoked"),
            "{already_recorded}: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), before);
    }
}

#[test]
fn portable_post_plan_wire_refuses_new_versions_verbs_and_caller_envelope_oids() {
    let mut h = harness();
    let proposal = h.proposal(h.rent_legs(100), b"plan-wire", EntryClass::ORIGINAL);
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    let bytes = plan.canonical_bytes().unwrap();
    for offset in [0, 13, 15] {
        let mut changed = bytes.clone();
        changed[offset] = 255;
        assert!(
            fa_intents::PostPlan::decode(&changed).is_err(),
            "plan offset {offset}"
        );
    }
    for end in [0, 13, 16, 20, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            fa_intents::PostPlan::decode(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(fa_intents::PostPlan::decode(&trailing).is_err());
    let intent = plan.intent().canonical_bytes().unwrap();
    for offset in [10, 12, 14] {
        let mut changed = intent.clone();
        changed[offset] = 255;
        assert!(
            fa_intents::PostIntent::decode(&changed).is_err(),
            "intent offset {offset}"
        );
    }
    let envelope = plan
        .intent()
        .proposal()
        .clone()
        .seal(plan.approvals().to_vec(), Some(Oid([55; 32])))
        .unwrap();
    let mut wire = fa_model::Writer::new();
    wire.fixed(b"FA-INTENT\0")
        .u16(1)
        .u16(0)
        .u8(0)
        .bytes(&envelope.encode().unwrap());
    let refusal = fa_intents::PostIntent::decode(&wire.finish().unwrap()).unwrap_err();
    assert!(
        refusal.to_string().contains("caller cannot supply"),
        "{refusal}"
    );
}

#[test]
fn portable_post_plan_retry_rejects_later_versions_even_when_exact_bytes_are_restored() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(h.rent_legs(100), b"restored-plan", EntryClass::ORIGINAL);
    let plan = h.post_plan(h.request(proposal, &["post"])).unwrap();
    let posted = h.publish_plan(plan.clone(), &capability).unwrap();
    let evid = posted.entry_ref().vid;
    let cvid = plan_certificate_vid(h.book.book_id, &plan.certificate().digest().unwrap());
    let eid = edge_id(relation::CITES, evid, cvid);
    let original_entry = h.db.vertex(evid).unwrap().unwrap();
    let original_certificate = h.db.vertex(cvid).unwrap().unwrap();
    let mut damage = fgdb::WriteBatch::new(relation::CITES);
    for vid in [evid, cvid] {
        damage.set_vertex_property(
            vid,
            property::FA_DIGEST,
            Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
        );
    }
    damage.set_edge_property(
        eid,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
    );
    h.write_raw(damage);
    let mut restore = fgdb::WriteBatch::new(relation::CITES);
    for row in [&original_entry, &original_certificate] {
        let digest = fa_journal::rows::prop(row, property::FA_DIGEST)
            .unwrap()
            .clone();
        restore.set_vertex_property(row.vid, property::FA_DIGEST, Some(digest));
    }
    restore.set_edge_property(eid, property::FA_DIGEST, None);
    h.write_raw(restore);
    let current_entry = h.db.vertex(evid).unwrap().unwrap();
    let current_certificate = h.db.vertex(cvid).unwrap().unwrap();
    let current_edge = h.db.edge(eid).unwrap().unwrap();
    assert_eq!(current_entry.props, original_entry.props);
    assert_eq!(current_certificate.props, original_certificate.props);
    assert!(current_entry.created_at > posted.recorded_at());
    assert!(current_certificate.created_at > posted.recorded_at());
    assert_eq!(current_entry.created_at, current_certificate.created_at);
    assert_eq!(current_edge.entry.created_at, current_entry.created_at);
    assert!(current_edge.props.is_empty());
    let before = h.db.frontier().unwrap();
    let refusal = h.publish_plan(plan, &capability).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn period_state_mirror_refolds_from_journaled_period_control_transitions() {
    let mut h = harness();
    // In `harness()`, March (`h.march`) was already opened at setup (1 transition).
    let at_open = h.db.frontier().unwrap();
    let v_open = verify_periods(&h.db, &h.book, None).unwrap();
    assert!(v_open.is_green(), "{:?}", v_open.drift);
    assert_eq!(v_open.known_at, at_open);
    assert_eq!(v_open.transitions_checked, 1);
    let march_open = v_open
        .periods
        .iter()
        .find(|p| p.code == h.march)
        .expect("march row");
    assert_eq!(march_open.born_state, PeriodState::Future);
    assert_eq!(march_open.stored_state, Some(PeriodState::Open));
    assert_eq!(march_open.refolded_state, PeriodState::Open);
    assert_eq!(march_open.transitions, 1);
    assert!(march_open.green);

    // Move April through Open -> SoftClose -> Reopen(Open) -> Close -> Lock.
    let april = h.april.clone();
    let t1 = h
        .transition(&april, PeriodTransition::Open, b"p-apr-open")
        .unwrap();
    let t2 = h
        .transition(&april, PeriodTransition::SoftClose, b"p-apr-soft")
        .unwrap();
    let t3 = h
        .transition(
            &april,
            PeriodTransition::Reopen {
                to: PeriodState::Open,
            },
            b"p-apr-reopen",
        )
        .unwrap();
    let t4 = h
        .transition(&april, PeriodTransition::Close, b"p-apr-close")
        .unwrap();
    let t5 = h
        .transition(&april, PeriodTransition::Lock, b"p-apr-lock")
        .unwrap();

    let v_head = verify_periods(&h.db, &h.book, None).unwrap();
    assert!(v_head.is_green(), "{:?}", v_head.drift);
    assert_eq!(v_head.transitions_checked, 6);
    let apr_head = v_head
        .periods
        .iter()
        .find(|p| p.code == april)
        .expect("april row");
    assert_eq!(apr_head.born_state, PeriodState::Future);
    assert_eq!(apr_head.stored_state, Some(PeriodState::Locked));
    assert_eq!(apr_head.refolded_state, PeriodState::Locked);
    assert_eq!(apr_head.transitions, 5);
    assert!(apr_head.green);

    // Historical known_at prefixes refold the exact intermediate states.
    for (seq, expected_state, expected_count) in [
        (at_open, PeriodState::Future, 0usize),
        (t1.recorded_at, PeriodState::Open, 1),
        (t2.recorded_at, PeriodState::SoftClosed, 2),
        (t3.recorded_at, PeriodState::Open, 3),
        (t4.recorded_at, PeriodState::Closed, 4),
        (t5.recorded_at, PeriodState::Locked, 5),
    ] {
        let v_at = verify_periods(&h.db, &h.book, Some(seq)).unwrap();
        assert!(v_at.is_green(), "at {}: {:?}", seq.0, v_at.drift);
        let row = v_at
            .periods
            .iter()
            .find(|p| p.code == april)
            .expect("april row at seq");
        assert_eq!(row.stored_state, Some(expected_state));
        assert_eq!(row.refolded_state, expected_state);
        assert_eq!(row.transitions, expected_count);
    }
}

#[test]
fn period_verification_detects_planted_state_and_topology_drift_without_mutation() {
    for plant in [
        "wrong-state",
        "missing-state",
        "missing-in-period",
        "missing-in-book",
        "misdated-control",
    ] {
        let mut h = harness();
        let clean_seq = h.db.frontier().unwrap();
        let pvid = period_vid(&h.book.calendar.id, &h.march);
        let transitions = period_transitions(&h.db, &h.book, &h.march).unwrap();
        assert_eq!(transitions.len(), 1);
        let evid = transitions[0].entry_vid;

        match plant {
            "wrong-state" => {
                let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
                batch.set_vertex_property(
                    pvid,
                    property::STATE,
                    Some(CanonicalScalar::Int(i64::from(PeriodState::Locked.tag()))),
                );
                h.write_raw(batch);
            }
            "missing-state" => {
                let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
                batch.set_vertex_property(pvid, property::STATE, None);
                h.write_raw(batch);
            }
            "missing-in-period" => {
                let mut batch = fgdb::WriteBatch::new(relation::IN_PERIOD);
                batch.delete_edge(edge_id(relation::IN_PERIOD, evid, pvid));
                h.write_raw(batch);
            }
            "missing-in-book" => {
                let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
                batch.delete_edge(edge_id(relation::IN_BOOK, pvid, book_root()));
                h.write_raw(batch);
            }
            "misdated-control" => {
                // March's Open control, re-sealed one day later (still inside
                // March) with every mirror rewritten to match, so only the
                // period law's date (fa-87r) can tell it apart.
                let (entry, _) = read_entry(&h.db, evid).unwrap().expect("control entry");
                let mut proposal = entry.proposal.clone();
                assert_eq!(proposal.effective_date, transitions[0].effective_date);
                proposal.effective_date = DateDay(proposal.effective_date.0 + 1);
                let misdated = proposal.seal(entry.approvals.clone(), None).unwrap();
                let mut batch = fgdb::WriteBatch::new(relation::IN_PERIOD);
                for (key, value) in fa_model::entry_mirrors(&misdated).unwrap() {
                    batch.set_vertex_property(evid, key, Some(value));
                }
                h.write_raw(batch);
            }
            _ => unreachable!(),
        }

        let damaged_seq = h.db.frontier().unwrap();
        let v = verify_periods(&h.db, &h.book, None).unwrap();
        assert!(!v.is_green(), "{plant}: expected drift");
        assert_eq!(
            h.db.frontier().unwrap(),
            damaged_seq,
            "{plant}: verify_periods must not mutate the book"
        );
        match plant {
            "wrong-state" => {
                let row = v.periods.iter().find(|p| p.code == h.march).unwrap();
                assert_eq!(row.stored_state, Some(PeriodState::Locked));
                assert_eq!(row.refolded_state, PeriodState::Open);
                assert!(!row.green);
                assert!(
                    v.drift.iter().any(|d| d.contains(&h.march)
                        && d.contains("Locked")
                        && d.contains("Open")),
                    "{:?}",
                    v.drift
                );
            }
            "missing-state" => {
                let row = v.periods.iter().find(|p| p.code == h.march).unwrap();
                assert_eq!(row.stored_state, None);
                assert_eq!(row.refolded_state, PeriodState::Open);
                assert!(!row.green);
                assert!(
                    v.drift
                        .iter()
                        .any(|d| d.contains(&h.march) && d.contains("missing/corrupt")),
                    "{:?}",
                    v.drift
                );
            }
            "missing-in-period" => {
                assert!(
                    v.drift
                        .iter()
                        .any(|d| d.contains("IN_PERIOD") && d.contains(&h.march)),
                    "{:?}",
                    v.drift
                );
            }
            "missing-in-book" => {
                assert!(
                    v.drift
                        .iter()
                        .any(|d| d.contains("IN_BOOK") && d.contains(&h.march)),
                    "{:?}",
                    v.drift
                );
            }
            "misdated-control" => {
                assert_eq!(v.drift.len(), 1, "{:?}", v.drift);
                assert!(
                    v.drift[0].contains("period law dates")
                        && v.drift[0].contains(&h.march)
                        && v.drift[0].contains("2026-03-02")
                        && v.drift[0].contains("2026-03-01"),
                    "{:?}",
                    v.drift
                );
            }
            _ => unreachable!(),
        }

        // The earlier committed prefix before the planted drift remains green.
        let v_clean = verify_periods(&h.db, &h.book, Some(clean_seq)).unwrap();
        assert!(v_clean.is_green(), "{plant}: {:?}", v_clean.drift);
    }
}

#[test]
fn instant_resolution_keeps_opening_date_at_its_saved_frontier() {
    use fa_time::UtcInstant;

    let mut h = harness();
    let lower = UtcInstant::parse("2026-03-15T12:00:00Z").unwrap().unix_ns();
    let upper = UtcInstant::parse("2026-03-16T12:00:00Z").unwrap().unix_ns();
    let first = h.tick(lower, b"historical-instant-lower", 1);
    let second = h.tick(upper, b"historical-instant-upper", 2);
    let frontier = h.db.frontier().unwrap();
    let selected = lower + 1;
    let original = resolve_instant_at(&h.db, &h.ctx().query(), &h.book, selected, Some(frontier))
        .unwrap()
        .unwrap();
    assert_eq!(original.lower_entry, first.entry_ref.vid);
    assert_eq!(original.upper_entry, Some(second.entry_ref.vid));

    let mut spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    spec.opening_date = Some(DateDay::from_ymd(2026, 4, 1).unwrap());
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        book_root(),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(spec.canonical_bytes().unwrap()).unwrap()),
    );
    h.write_raw(damage);
    let april = UtcInstant::parse("2026-04-02T00:00:00Z").unwrap().unix_ns();
    h.tick(april, b"later-instant", 3);
    let head = h.db.frontier().unwrap();

    let current = resolve_instant_at(&h.db, &h.ctx().query(), &h.book, selected, None)
        .unwrap()
        .unwrap_err();
    assert_eq!((current.code, current.exit), ("FA-REF-151", exit::REFUSAL));
    assert!(current.message.contains("BeforeBookGenesis"));
    assert_eq!(
        resolve_instant_at(&h.db, &h.ctx().query(), &h.book, selected, Some(frontier))
            .unwrap()
            .unwrap(),
        original,
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn instant_before_book_genesis_and_non_increasing_ticks_are_refused() {
    use fa_journal::genesis::BookSpec;
    use fa_journal::sweep::{SOURCE_DAEMON_CLOCK, TickRequest, latest_tick, record_tick};
    use fa_policy::Capability;
    use fa_time::UtcInstant;

    let mut h = harness();
    let march_15 = UtcInstant::parse("2026-03-15T12:00:00Z").unwrap().unix_ns();
    let first = h.tick(march_15, b"tick-1", 1);
    assert_eq!(latest_tick(&h.db).unwrap(), Some(first.tick));

    // Equal or decreasing ticks are refused with FA-REF-094 (TICK_ORDER) and
    // never move the book's latest tick or append a commit.
    let head_before = h.db.frontier().unwrap();
    for (bad_ns, key, nonce) in [
        (march_15, &b"tick-equal"[..], 2u8),
        (march_15 - 1, &b"tick-rollback"[..], 3u8),
    ] {
        let ctx = h.ctx();
        let req = TickRequest {
            observed_utc_ns: bad_ns,
            source: SOURCE_DAEMON_CLOCK,
            monotonic_ok: true,
            principal_ref: PRINCIPAL,
            capability: Capability::embedded(PRINCIPAL, &["witness"]).expect("witness"),
            idempotency_key: key.to_vec(),
            description: h.statement("bad-tick", nonce),
        };
        let refusal = h
            .runtime
            .block_on(record_tick(&mut h.db, &ctx, &h.book, req))
            .expect("kernel")
            .expect_err("non-increasing tick must be refused");
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-094", exit::REFUSAL),
            "{refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head_before);
        assert_eq!(latest_tick(&h.db).unwrap(), Some(first.tick));
    }

    // On a book with an opening_date (migration genesis), any instant before
    // the book's migration genesis is refused with BeforeBookGenesis (FA-REF-151)
    // rather than reconstructing legacy known-at.
    let mut spec = fa_journal::genesis::read_book_spec(&h.db)
        .unwrap()
        .expect("book spec");
    spec.opening_date = Some(DateDay::from_ymd(2026, 4, 1).unwrap());
    let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        book_root(),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(BookSpec::canonical_bytes(&spec).unwrap()).unwrap()),
    );
    h.write_raw(batch);
    let april_tick = UtcInstant::parse("2026-04-02T00:00:00Z").unwrap().unix_ns();
    let second = h.tick(april_tick, b"tick-2", 4);

    let legacy_instant = UtcInstant::parse("2025-12-31T23:59:59Z").unwrap().unix_ns();
    let refusal = resolve_instant_at(&h.db, &h.ctx().query(), &h.book, legacy_instant, None)
        .expect("kernel")
        .expect_err("legacy instant before opening_date must be refused");
    assert_eq!(
        (refusal.code, refusal.exit),
        ("FA-REF-151", exit::REFUSAL),
        "{refusal}"
    );
    assert!(
        refusal.message.contains("BeforeBookGenesis"),
        "expected BeforeBookGenesis in refusal message: {refusal}"
    );
    assert!(refusal.cite.contains("§8.6"), "{refusal}");

    // An instant at or after the migration genesis and retained tick resolves cleanly.
    let resolved = resolve_instant_at(&h.db, &h.ctx().query(), &h.book, april_tick + 50, None)
        .expect("kernel")
        .expect("resolved after migration genesis");
    assert_eq!(resolved.lower_entry, second.entry_ref.vid);
}

#[test]
fn memo_off_balance_and_statistical_legs_obey_fa_inv_01_memo() {
    use fa_model::AccountType;
    let mut h = harness();
    let usd = h.book.units.lookup("USD").unwrap();
    let each = h.book.units.lookup("EACH").unwrap();
    let hour = h.book.units.lookup("HOUR").unwrap();

    let extra_accounts = [
        AccountSpec {
            code: "8510".into(),
            name: "OffBalanceCommitment".into(),
            account_type: AccountType::OFF_BALANCE.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "8520".into(),
            name: "OffBalanceCounter".into(),
            account_type: AccountType::OFF_BALANCE.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "9100".into(),
            name: "Headcount".into(),
            account_type: AccountType::STATISTICAL.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(each),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "9200".into(),
            name: "BillableHours".into(),
            account_type: AccountType::STATISTICAL.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(hour),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "1990".into(),
            name: "AssetEach".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        },
    ];
    {
        let desc = h.statement("install-memo-offbal-stat", 91);
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &extra_accounts,
                    PRINCIPAL,
                    DateDay::from_ymd(2026, 3, 15).unwrap(),
                    b"install-memo-offbal-stat",
                    desc,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("installed");
    }

    let vid = |h: &Harness, code: &str| account_vid(h.book.book_id, code);

    // 1. Single-leg entry in USD on Statistical account is refused at structure (FA-REF-100).
    let bad_usd = h.proposal(
        vec![LegPayload::simple(
            Side::Debit,
            vid(&h, "9100"),
            Amount::new(usd, 10),
        )],
        b"bad-usd-1leg",
        EntryClass::ORIGINAL,
    );
    let r = h.post(h.request(bad_usd, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");

    // 2. Single-leg entry in EACH on Asset or OffBalance is refused at Step 6 (FA-REF-001).
    for (key, acct) in [
        (&b"bad-each-asset"[..], "1990"),
        (&b"bad-each-offbal"[..], "8510"),
    ] {
        let p = h.proposal(
            vec![LegPayload::simple(
                Side::Debit,
                vid(&h, acct),
                Amount::new(each, 10),
            )],
            key,
            EntryClass::ORIGINAL,
        );
        let r = h.post(h.request(p, &["post"])).unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-001", exit::REFUSAL), "{r}");
    }

    // 3. Balanced OffBalance entry in USD posts cleanly; cross-class Asset + OffBalance fails FA-REF-001.
    let cross = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, h.cash, Amount::new(usd, 5_000)),
            LegPayload::simple(Side::Credit, vid(&h, "8520"), Amount::new(usd, 5_000)),
        ],
        b"bad-cross-asset-offbal",
        EntryClass::ORIGINAL,
    );
    let r = h.post(h.request(cross, &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-001", exit::REFUSAL), "{r}");

    let offbal_ok = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, vid(&h, "8510"), Amount::new(usd, 50_000)),
            LegPayload::simple(Side::Credit, vid(&h, "8520"), Amount::new(usd, 50_000)),
        ],
        b"ok-offbal-commitment",
        EntryClass::ORIGINAL,
    );
    assert!(h.post(h.request(offbal_ok, &["post"])).is_ok());

    // 4. Single-leg Statistical entry in EACH posts cleanly, and its 1-leg Reversal succeeds.
    let stat_ok = h.proposal(
        vec![LegPayload::simple(
            Side::Debit,
            vid(&h, "9100"),
            Amount::new(each, 17),
        )],
        b"ok-stat-headcount",
        EntryClass::ORIGINAL,
    );
    let posted_stat = h
        .post(h.request(stat_ok, &["post"]))
        .expect("single-sided statistical post");
    let rev_stat = h.reversal_of_entry(posted_stat.entry_ref(), b"rev-stat-headcount");
    assert_eq!(rev_stat.legs.len(), 1);
    assert_eq!(rev_stat.legs[0].side, Side::Credit);
    let reversed = h
        .post(h.request(rev_stat, &["post"]))
        .expect("single-sided statistical reversal");
    assert!(matches!(reversed, Posted::Committed { .. }));
}

#[test]
fn portable_replacement_plan_is_zero_write_and_retains_one_atomic_pair_certificate() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(
                h.rent_legs(100),
                b"portable-pair-original",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let (reversal, replacement) = h.planned_rent_correction(original);
    let capability = reversal.capability.clone();
    let basis = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let plan = h
        .replacement_plan(reversal.clone(), replacement.clone())
        .unwrap();
    assert_eq!(h.db.frontier().unwrap(), basis);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(
        h.replacement_plan(reversal.clone(), replacement.clone())
            .unwrap(),
        plan
    );
    // Only the reversal's native Entry bytes change. The replacement and
    // its own local effects stay identical, but the joint effects must bind
    // the changed first member as well as the final member's transaction.
    let mut changed_reversal = reversal;
    changed_reversal.proposal.description = h.statement("Reviewed correction reason", 219);
    let changed = h.replacement_plan(changed_reversal, replacement).unwrap();
    assert_eq!(
        changed.replacement().prepared_entry(),
        plan.replacement().prepared_entry()
    );
    assert_ne!(
        changed.reversal().prepared_entry(),
        plan.reversal().prepared_entry()
    );
    assert_ne!(
        changed.reversal().certificate().effects_digest,
        plan.reversal().certificate().effects_digest
    );
    let bytes = plan.canonical_bytes().unwrap();
    assert_eq!(fa_intents::ReplacementPlan::decode(&bytes).unwrap(), plan);
    assert_ne!(
        plan.certificate_digest().unwrap(),
        plan.reversal().certificate().digest().unwrap()
    );
    assert_eq!(plan.reversal().certificate().snapshot_seq, basis);
    assert_eq!(
        plan.reversal().certificate().effects_digest,
        plan.replacement().certificate().effects_digest
    );

    // A member carries a joint-domain authentication tag. Extracting either
    // syntactically valid PostPlan cannot publish half the reviewed change.
    for member in [plan.reversal(), plan.replacement()] {
        assert_eq!(
            h.publish_plan(member.clone(), &capability)
                .unwrap_err()
                .code,
            "FA-REF-034"
        );
        assert_eq!(h.db.frontier().unwrap(), basis);
    }
    for offset in [0, 16, 18] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(fa_intents::ReplacementPlan::decode(&changed).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(fa_intents::ReplacementPlan::decode(&trailing).is_err());
    assert!(
        fa_intents::ReplacementPlan::new(plan.replacement().clone(), plan.reversal().clone())
            .is_err()
    );

    let (first, second) = h
        .publish_replacement_plan(plan.clone(), &capability)
        .unwrap();
    assert!(matches!(first, Posted::Committed { .. }));
    assert!(matches!(second, Posted::Committed { .. }));
    assert_eq!(first.recorded_at(), second.recorded_at());
    assert_eq!(first.recorded_at().0, basis.0 + 1);
    let cvid = plan_certificate_vid(h.book.book_id, &plan.certificate_digest().unwrap());
    let certificate = h.db.vertex(cvid).unwrap().unwrap();
    assert_eq!(certificate.created_at, first.recorded_at());
    assert_eq!(
        fa_journal::rows::bytes(&certificate, property::FA_PAYLOAD, "plan").unwrap(),
        bytes
    );
    for (outcome, member) in [(&first, plan.reversal()), (&second, plan.replacement())] {
        let (stored, at) = read_entry(&h.db, outcome.entry_ref().vid).unwrap().unwrap();
        assert_eq!(&stored, member.prepared_entry());
        assert_eq!(at, first.recorded_at());
        let edge =
            h.db.edge(edge_id(relation::CITES, outcome.entry_ref().vid, cvid))
                .unwrap()
                .unwrap();
        assert_eq!(edge.entry.created_at, at);
    }
    // Later accounting activity invalidates an unpublished plan, but cannot
    // erase a complete original outcome after a lost acknowledgement.
    h.post(h.request(
        h.proposal(h.rent_legs(2), b"after-portable-pair", EntryClass::ORIGINAL),
        &["post"],
    ))
    .unwrap();
    let head = h.db.frontier().unwrap();
    let retry = h.publish_replacement_plan(plan, &capability).unwrap();
    for (actual, original) in [(&retry.0, &first), (&retry.1, &second)] {
        assert!(matches!(actual, Posted::AlreadyRecorded { .. }));
        assert_eq!(actual.entry_ref(), original.entry_ref());
        assert_eq!(actual.recorded_at(), original.recorded_at());
    }
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn portable_replacement_plan_authenticates_both_members_and_rechecks_actual_native_effects() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(
                h.rent_legs(100),
                b"pair-auth-original",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let (reversal, replacement) = h.planned_rent_correction(original);
    let capability = reversal.capability.clone();
    let plan = h.replacement_plan(reversal, replacement).unwrap();
    let before = h.db.frontier().unwrap();
    let rebuild = |change: &dyn Fn(&mut fa_intents::PlanCertificate)| {
        let member = |m: &fa_intents::PostPlan| {
            let mut certificate = m.certificate().clone();
            change(&mut certificate);
            fa_intents::PostPlan::new(m.intent().clone(), m.prepared_entry().clone(), certificate)
                .unwrap()
        };
        fa_intents::ReplacementPlan::new(member(plan.reversal()), member(plan.replacement()))
            .unwrap()
    };
    for damage in ["effects", "basis", "epoch", "capability", "expiry", "tag"] {
        let changed = rebuild(&|certificate| match damage {
            "effects" => certificate.effects_digest[0] ^= 1,
            "basis" => certificate.snapshot_seq.0 += 1,
            "epoch" => certificate.security_policy_epoch += 1,
            "capability" => certificate.capability_commitment[0] ^= 1,
            "expiry" => certificate.expires_at = Some(fgdb_types::CommitSeq(before.0 + 5)),
            "tag" => certificate.authentication[0] ^= 1,
            _ => unreachable!(),
        });
        assert_eq!(
            h.publish_replacement_plan(changed, &capability)
                .unwrap_err()
                .code,
            "FA-REF-034",
            "{damage}"
        );
        assert_eq!(h.db.frontier().unwrap(), before);
    }
    for change_first in [true, false] {
        let change = |m: &fa_intents::PostPlan| {
            let mut certificate = m.certificate().clone();
            certificate.period = h.april.clone();
            fa_intents::PostPlan::new(m.intent().clone(), m.prepared_entry().clone(), certificate)
                .unwrap()
        };
        let changed = if change_first {
            fa_intents::ReplacementPlan::new(change(plan.reversal()), plan.replacement().clone())
        } else {
            fa_intents::ReplacementPlan::new(plan.reversal().clone(), change(plan.replacement()))
        }
        .unwrap();
        assert_eq!(
            h.publish_replacement_plan(changed, &capability)
                .unwrap_err()
                .code,
            "FA-REF-034"
        );
    }
    // Even an issuer with the book key cannot replace comparison against the
    // actual pair transaction with a false but authentically signed claim.
    let false_plan = rebuild(&|certificate| certificate.effects_digest[0] ^= 1);
    let key = fgdb_crypto::derive_key(
        "fa:replacement-plan-authentication-key:v1",
        &h.book.seal_key.0,
    );
    let tag = fgdb_crypto::keyed_hash(&key, &false_plan.authentication_bytes().unwrap()).0;
    let sign = |m: &fa_intents::PostPlan| {
        let mut certificate = m.certificate().clone();
        certificate.authentication = tag;
        fa_intents::PostPlan::new(m.intent().clone(), m.prepared_entry().clone(), certificate)
            .unwrap()
    };
    let changed = fa_intents::ReplacementPlan::new(
        sign(false_plan.reversal()),
        sign(false_plan.replacement()),
    )
    .unwrap();
    let refusal = h
        .publish_replacement_plan(changed, &capability)
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-034");
    assert!(refusal.message.contains("native effects"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(h.db.vertex(reversal_vid(original.vid)).unwrap().is_none());
    assert!(
        h.db.vertex(fa_journal::rows::replacement_vid(original.vid))
            .unwrap()
            .is_none()
    );
}

#[test]
fn portable_replacement_plan_reuses_settlement_capacity_only_inside_the_atomic_overlay() {
    let mut h = harness();
    let invoice = h
        .post(h.request(h.invoice(10_000, b"planned-pair-invoice"), &["post"]))
        .unwrap()
        .entry_ref();
    let applies = |amount| Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(h.usd, amount),
    };
    let receipt_proposal = h.receipt(8_000, vec![applies(8_000)], b"planned-pair-receipt");
    let corrected = h.receipt(6_000, vec![applies(6_000)], b"planned-pair-corrected");
    let receipt = h
        .post(h.request(receipt_proposal, &["post"]))
        .unwrap()
        .entry_ref();
    let reversal = h.request(
        h.reversal_of_entry(receipt, b"planned-pair-undo"),
        &["post"],
    );
    let replacement = h.request(replacement_proposal(receipt, corrected), &["post"]);
    let capability = reversal.capability.clone();
    let before = h.db.frontier().unwrap();
    let plan = h.replacement_plan(reversal, replacement).unwrap();
    assert_eq!(h.applied_to(invoice.vid, 0), 8_000);
    assert_eq!(h.db.frontier().unwrap(), before);
    let (first, second) = h.publish_replacement_plan(plan, &capability).unwrap();
    assert_eq!(first.recorded_at(), second.recorded_at());
    assert_eq!(h.applied_to(invoice.vid, 0), 6_000);
    for (rel, source) in [
        (relation::UNSETTLES, first.entry_ref().vid),
        (relation::SETTLES, second.entry_ref().vid),
    ] {
        let edge =
            h.db.edge(edge_id(rel, leg_vid(source, 1), leg_vid(invoice.vid, 0)))
                .unwrap()
                .unwrap();
        assert_eq!(edge.entry.created_at, first.recorded_at());
    }
}

#[test]
fn portable_replacement_plan_requires_approvals_and_never_grants_agents_commit_authority() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(
                h.rent_legs(100),
                b"pair-authority-original",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let (mut reversal, mut replacement) = h.planned_rent_correction(original);
    let agent = Capability::new(
        PRINCIPAL,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap();
    reversal.capability = agent.clone();
    replacement.capability = agent.clone();
    let before = h.db.frontier().unwrap();
    let plan = h
        .replacement_plan(reversal.clone(), replacement.clone())
        .unwrap();
    assert_eq!(
        h.publish_replacement_plan(plan.clone(), &agent)
            .unwrap_err()
            .code,
        "FA-REF-013"
    );
    let human = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    assert_eq!(
        h.publish_replacement_plan(plan, &human).unwrap_err().code,
        "FA-REF-034"
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    h.transition(
        &h.march.clone(),
        PeriodTransition::Close,
        b"planned-pair-close",
    )
    .unwrap();
    let capability = Capability::embedded(PRINCIPAL, &["post", "post_closed"]).unwrap();
    reversal.capability = capability.clone();
    replacement.capability = capability.clone();
    let before = h.db.frontier().unwrap();
    assert_eq!(
        h.replacement_plan(reversal.clone(), replacement.clone())
            .unwrap_err()
            .code,
        "FA-REF-012"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    replacement
        .approvals
        .push(h.approve_transition(replacement.proposal.proposal_digest().unwrap()));
    reversal
        .approvals
        .push(h.approve_transition(reversal.proposal.proposal_digest().unwrap()));
    let plan = h.replacement_plan(reversal, replacement).unwrap();
    assert_eq!(plan.reversal().approvals().len(), 1);
    assert_eq!(plan.replacement().approvals().len(), 1);
    // Removing either approval and rehashing all public fields cannot borrow
    // the authentic pair tag, including the optional reversal approval.
    for remove_first in [true, false] {
        let strip = |m: &fa_intents::PostPlan| {
            let intent =
                fa_intents::PostIntent::new(m.intent().proposal().clone(), Vec::new()).unwrap();
            let entry = m.proposal().clone().seal(Vec::new(), None).unwrap();
            let mut certificate = m.certificate().clone();
            certificate.intent_digest = intent.digest().unwrap();
            fa_intents::PostPlan::new(intent, entry, certificate).unwrap()
        };
        let changed = if remove_first {
            fa_intents::ReplacementPlan::new(strip(plan.reversal()), plan.replacement().clone())
        } else {
            fa_intents::ReplacementPlan::new(plan.reversal().clone(), strip(plan.replacement()))
        }
        .unwrap();
        let before = h.db.frontier().unwrap();
        assert_eq!(
            h.publish_replacement_plan(changed, &capability)
                .unwrap_err()
                .code,
            "FA-REF-034"
        );
        assert_eq!(h.db.frontier().unwrap(), before);
    }
    h.publish_replacement_plan(plan, &capability).unwrap();
}

#[test]
fn portable_replacement_plan_refuses_stale_basis_direct_outcomes_and_damaged_retention() {
    for damage in [
        "stale",
        "direct",
        "certificate",
        "reversal",
        "replacement",
        "first_cites",
        "second_cites",
    ] {
        let mut h = harness();
        let original = h
            .post(h.request(
                h.proposal(
                    h.rent_legs(100),
                    b"pair-retention-original",
                    EntryClass::ORIGINAL,
                ),
                &["post"],
            ))
            .unwrap()
            .entry_ref();
        let (reversal, replacement) = h.planned_rent_correction(original);
        let capability = reversal.capability.clone();
        let plan = h
            .replacement_plan(reversal.clone(), replacement.clone())
            .unwrap();
        if damage == "stale" {
            h.post(h.request(
                h.proposal(h.rent_legs(1), b"pair-stale-head", EntryClass::ORIGINAL),
                &["post"],
            ))
            .unwrap();
        } else if damage == "direct" {
            h.post_pair(reversal, replacement).unwrap();
        } else {
            let (first, second) = h
                .publish_replacement_plan(plan.clone(), &capability)
                .unwrap();
            let cvid = plan_certificate_vid(h.book.book_id, &plan.certificate_digest().unwrap());
            let mut batch = fgdb::WriteBatch::new(relation::CITES);
            let vertex = match damage {
                "certificate" => Some(cvid),
                "reversal" => Some(first.entry_ref().vid),
                "replacement" => Some(second.entry_ref().vid),
                _ => None,
            };
            if let Some(vid) = vertex {
                batch.set_vertex_property(
                    vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
                );
            } else {
                let vid = if damage == "first_cites" {
                    first.entry_ref().vid
                } else {
                    second.entry_ref().vid
                };
                batch.delete_edge(edge_id(relation::CITES, vid, cvid));
            }
            h.write_raw(batch);
        }
        let head = h.db.frontier().unwrap();
        assert_eq!(
            h.publish_replacement_plan(plan, &capability)
                .unwrap_err()
                .code,
            "FA-REF-034",
            "{damage}"
        );
        assert_eq!(h.db.frontier().unwrap(), head, "{damage}");
        if damage == "stale" {
            assert!(h.db.vertex(reversal_vid(original.vid)).unwrap().is_none());
            assert!(
                h.db.vertex(fa_journal::rows::replacement_vid(original.vid))
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[test]
fn portable_replacement_plan_refuses_invalid_second_member_without_staging_a_public_half() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(
                h.rent_legs(100),
                b"pair-invalid-original",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let (reversal, mut replacement) = h.planned_rent_correction(original);
    replacement.proposal.legs[1].amount = Amount::new(h.usd, 124);
    replacement.proposal.unit_totals =
        EntryPayload::fold_unit_totals(&replacement.proposal.legs).unwrap();
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    assert_eq!(
        h.replacement_plan(reversal, replacement).unwrap_err().code,
        "FA-REF-001"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    // An independently recorded reversal is legitimate history, but cannot
    // become half of a new atomic plan. Refuse it without diagnosing ledger
    // corruption or publishing the absent replacement.
    let (reversal, replacement) = h.planned_rent_correction(original);
    h.post(reversal.clone()).unwrap();
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.replacement_plan(reversal, replacement).unwrap_err();
    assert_eq!(refusal.exit, exit::CONFLICT, "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn replacement_pair_commits_reversal_and_replacement_in_one_batch_and_explains_net_lineage() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(
                h.rent_legs(10_000),
                b"orig-to-replace",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .expect("original post")
        .entry_ref();

    let rev_proposal = h.reversal_of(original, 10_000, b"pair-rev");
    let mut rep_proposal = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 12_500)),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 12_500)),
        ],
        b"pair-rep",
        EntryClass::REPLACEMENT,
    );
    rep_proposal.supersession = vec![Supersession {
        target: original,
        kind: SupersessionKind::Replaces,
        reason_code: 1,
    }];

    let rev_req = h.request(rev_proposal, &["post"]);
    let rep_req = h.request(rep_proposal, &["post"]);
    let ctx = h.ctx();
    let (rev_posted, rep_posted) = h
        .runtime
        .block_on(fa_journal::post::post_replacement_pair(
            &mut h.db, &ctx, &h.book, rev_req, rep_req,
        ))
        .expect("kernel")
        .expect("paired replacement committed");

    // Both entries committed in the exact same transaction at the same CommitSeq.
    assert_eq!(rev_posted.recorded_at(), rep_posted.recorded_at());
    assert!(matches!(rev_posted, Posted::Committed { .. }));
    assert!(matches!(rep_posted, Posted::Committed { .. }));

    // Lineage explanation folds the 3 entries (Original + Reversal + Replacement)
    // to the Replacement's net legs (+12_500 rent, -12_500 cash).
    let lineage = fa_journal::post::explain_entry_lineage(&h.db, &h.book, original.vid, None)
        .expect("explain lineage")
        .expect("found");
    assert_eq!(lineage.root_vid, original.vid);
    assert_eq!(lineage.replaced_by, Some(rep_posted.entry_ref().vid));
    assert!(!lineage.fully_reversed);
    assert_eq!(lineage.entries.len(), 3);
    let net: std::collections::BTreeMap<VId, i128> = lineage
        .net_positions
        .iter()
        .map(|p| (p.account_ref, p.net_debit))
        .collect();
    assert_eq!(net.get(&h.rent), Some(&12_500));
    assert_eq!(net.get(&h.cash), Some(&-12_500));
}

#[test]
fn replacement_pair_reuses_released_settlement_capacity_and_retains_its_evidence() {
    let mut h = harness();
    let invoice = h
        .post(h.request(h.invoice(10_000, b"pair-invoice"), &["post"]))
        .unwrap()
        .entry_ref();
    let applies = |amount| Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(h.usd, amount),
    };
    let receipt_proposal = h.receipt(8_000, vec![applies(8_000)], b"pair-receipt");
    let corrected = h.receipt(6_000, vec![applies(6_000)], b"pair-corrected-receipt");
    let receipt = h
        .post(h.request(receipt_proposal, &["post"]))
        .unwrap()
        .entry_ref();
    assert_eq!(h.applied_to(invoice.vid, 0), 8_000);
    let reversal = h.request(
        h.reversal_of_entry(receipt, b"pair-undo-receipt"),
        &["post"],
    );
    let replacement = h.request(replacement_proposal(receipt, corrected), &["post"]);
    let (reversed, replaced) = h.post_pair(reversal, replacement).unwrap();
    assert_eq!(reversed.recorded_at(), replaced.recorded_at());
    assert_eq!(h.applied_to(invoice.vid, 0), 6_000);
    let invoice_leg = leg_vid(invoice.vid, 0);
    for (relation, source) in [
        (relation::UNSETTLES, leg_vid(reversed.entry_ref().vid, 1)),
        (relation::SETTLES, leg_vid(replaced.entry_ref().vid, 1)),
    ] {
        assert!(
            h.db.edge(edge_id(relation, source, invoice_leg))
                .unwrap()
                .is_some()
        );
    }
    let document = document_vid(&h.evidence[0].document_oid);
    assert!(
        h.db.edge(edge_id(
            relation::EVIDENCED_BY,
            replaced.entry_ref().vid,
            document
        ))
        .unwrap()
        .is_some()
    );
    let remaining = Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(h.usd, 4_000),
    };
    h.post(h.request(
        h.receipt(4_000, vec![remaining], b"pair-final-receipt"),
        &["post"],
    ))
    .unwrap();
    assert_eq!(h.applied_to(invoice.vid, 0), 10_000);
}

#[test]
fn replacement_pair_updates_limited_cash_from_the_reversal_overlay() {
    let mut h = harness_configured(
        Vec::new(),
        None,
        Some(BalanceLimit {
            lower: Some(0),
            upper: None,
            scope: limit::LimitScope::Lifetime,
        }),
    );
    h.post(h.request(
        h.receipt(10_000, Vec::new(), b"pair-cash-funding"),
        &["post"],
    ))
    .unwrap();
    let target = h
        .post(h.request(
            h.proposal(h.rent_legs(8_000), b"pair-cash-spend", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let cell = limit::limit_cell_vid(h.cash);
    let before =
        limit::LimitCell::decode_for(&h.db.vertex(cell).unwrap().unwrap(), h.cash).unwrap();
    assert_eq!(before.availability(Side::Debit).unwrap().0, 2_000);
    let reversal = h.request(
        h.reversal_of_entry(target, b"pair-cash-reversal"),
        &["post"],
    );
    let replacement = h.request(
        replacement_proposal(
            target,
            h.proposal(
                h.rent_legs(9_000),
                b"pair-cash-replacement",
                EntryClass::REPLACEMENT,
            ),
        ),
        &["post"],
    );
    let (reversed, replaced) = h.post_pair(reversal, replacement).unwrap();
    assert_eq!(reversed.recorded_at(), replaced.recorded_at());
    let after = limit::LimitCell::decode_for(&h.db.vertex(cell).unwrap().unwrap(), h.cash).unwrap();
    assert_eq!(after.generation, before.generation + 2);
    assert_eq!(
        (after.debits_posted, after.credits_posted),
        (18_000, 17_000)
    );
    assert_eq!(after.availability(Side::Debit).unwrap().0, 1_000);
    let head = h.db.frontier().unwrap();
    let refused = h
        .post(h.request(
            h.proposal(
                h.rent_legs(1_001),
                b"pair-cash-overdraft",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-090", "{refused}");
    assert_eq!(h.db.frontier().unwrap(), head);
    h.post(h.request(
        h.proposal(h.rent_legs(1_000), b"pair-cash-exact", EntryClass::ORIGINAL),
        &["post"],
    ))
    .unwrap();
    let exhausted =
        limit::LimitCell::decode_for(&h.db.vertex(cell).unwrap().unwrap(), h.cash).unwrap();
    assert_eq!(exhausted.availability(Side::Debit).unwrap().0, 0);
}

#[test]
fn replacement_pair_retries_bind_both_proposals_and_approval_envelopes() {
    let mut h = harness();
    let target = h
        .post(h.request(
            h.proposal(
                h.rent_legs(100),
                b"pair-retry-original",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let reversal = h.request(
        h.reversal_of_entry(target, b"pair-retry-reversal"),
        &["post"],
    );
    let replacement = h.request(
        replacement_proposal(
            target,
            h.proposal(
                h.rent_legs(125),
                b"pair-retry-replacement",
                EntryClass::REPLACEMENT,
            ),
        ),
        &["post"],
    );
    let (first_reversal, first_replacement) =
        h.post_pair(reversal.clone(), replacement.clone()).unwrap();
    assert_eq!(
        first_replacement.entry_ref().vid,
        fa_journal::rows::replacement_vid(target.vid)
    );
    let head = h.db.frontier().unwrap();
    let (retry_reversal, retry_replacement) =
        h.post_pair(reversal.clone(), replacement.clone()).unwrap();
    assert!(matches!(retry_reversal, Posted::AlreadyRecorded { .. }));
    assert!(matches!(retry_replacement, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry_reversal.entry_ref(), first_reversal.entry_ref());
    assert_eq!(retry_replacement.entry_ref(), first_replacement.entry_ref());
    assert_eq!(
        retry_replacement.recorded_at(),
        first_replacement.recorded_at()
    );
    assert_eq!(h.db.frontier().unwrap(), head);

    // Re-sealing identical text changes prepared bytes, but the same
    // principal's semantic retry still returns the original pair.
    let mut resealed_reversal = reversal.clone();
    let mut resealed_replacement = replacement.clone();
    resealed_reversal.proposal.description = h.statement("March rent", 221);
    resealed_replacement.proposal.description = h.statement("March rent", 222);
    assert_ne!(
        resealed_reversal.proposal.proposal_digest().unwrap(),
        reversal.proposal.proposal_digest().unwrap()
    );
    assert_ne!(
        resealed_replacement.proposal.proposal_digest().unwrap(),
        replacement.proposal.proposal_digest().unwrap()
    );
    let (resealed_rev, resealed_rep) = h
        .post_pair(resealed_reversal, resealed_replacement)
        .unwrap();
    assert!(matches!(resealed_rev, Posted::AlreadyRecorded { .. }));
    assert!(matches!(resealed_rep, Posted::AlreadyRecorded { .. }));
    assert_eq!(resealed_rev.entry_ref(), first_reversal.entry_ref());
    assert_eq!(resealed_rep.entry_ref(), first_replacement.entry_ref());
    assert_eq!(resealed_rev.recorded_at(), first_reversal.recorded_at());
    assert_eq!(resealed_rep.recorded_at(), first_replacement.recorded_at());
    assert_eq!(h.db.frontier().unwrap(), head);

    let mut changed = replacement.clone();
    changed.proposal.idempotency_key = b"pair-retry-another-key".to_vec();
    assert_eq!(
        h.post_pair(reversal.clone(), changed).unwrap_err().exit,
        exit::CONFLICT
    );
    let mut changed = replacement.clone();
    changed.proposal.legs = h.rent_legs(126);
    changed.proposal.unit_totals = EntryPayload::fold_unit_totals(&changed.proposal.legs).unwrap();
    assert_eq!(
        h.post_pair(reversal.clone(), changed).unwrap_err().exit,
        exit::CONFLICT
    );
    let mut changed = reversal.clone();
    changed.proposal.supersession[0].reason_code = 2;
    assert_eq!(
        h.post_pair(changed, replacement.clone()).unwrap_err().exit,
        exit::CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), head);

    for change_reversal in [true, false] {
        let mut rev = reversal.clone();
        let mut rep = replacement.clone();
        let request = if change_reversal { &mut rev } else { &mut rep };
        request
            .approvals
            .push(h.approve_transition(request.proposal.proposal_digest().unwrap()));
        let head = h.db.frontier().unwrap();
        assert_eq!(h.post_pair(rev, rep).unwrap_err().exit, exit::CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn replacement_pair_uses_its_actual_class_approval_digest_in_a_closed_period() {
    let mut h = harness();
    let target = h
        .post(h.request(
            h.proposal(
                h.rent_legs(100),
                b"pair-closed-original",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    h.transition(
        &h.march.clone(),
        PeriodTransition::Close,
        b"pair-close-march",
    )
    .unwrap();
    let reversal = h.request(
        h.reversal_of_entry(target, b"pair-closed-reversal"),
        &["post", "post_closed"],
    );
    let mut replacement = h.request(
        replacement_proposal(
            target,
            h.proposal(
                h.rent_legs(125),
                b"pair-closed-replacement",
                EntryClass::REPLACEMENT,
            ),
        ),
        &["post", "post_closed"],
    );
    let head = h.db.frontier().unwrap();
    assert_eq!(
        h.post_pair(reversal.clone(), replacement.clone())
            .unwrap_err()
            .code,
        "FA-REF-012"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    let digest = replacement.proposal.proposal_digest().unwrap();
    replacement.approvals.push(h.approve_transition(digest));
    let (reversed, replaced) = h.post_pair(reversal, replacement.clone()).unwrap();
    assert_eq!(reversed.recorded_at(), replaced.recorded_at());
    let (stored, _) = read_entry(&h.db, replaced.entry_ref().vid)
        .unwrap()
        .unwrap();
    assert_eq!(stored.proposal.class, EntryClass::REPLACEMENT);
    assert_eq!(stored.proposal_digest, digest);
    assert_eq!(stored.approvals, replacement.approvals);
}

#[test]
fn replacement_pair_failure_publishes_neither_member_and_authorizes_before_target_reads() {
    let mut h = harness();
    let target = h
        .post(h.request(
            h.proposal(
                h.rent_legs(100),
                b"pair-refused-original",
                EntryClass::ORIGINAL,
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let reversal = h.request(
        h.reversal_of_entry(target, b"pair-refused-reversal"),
        &["post"],
    );
    let replacement = h.request(
        replacement_proposal(
            target,
            h.proposal(
                h.rent_legs(125),
                b"pair-refused-replacement",
                EntryClass::REPLACEMENT,
            ),
        ),
        &["post"],
    );
    let head = h.db.frontier().unwrap();
    let mut no_evidence = replacement.clone();
    no_evidence.proposal.evidence.clear();
    let refusal = h.post_pair(reversal.clone(), no_evidence).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-080", "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    assert!(
        h.db.vertex(fa_journal::rows::replacement_vid(target.vid))
            .unwrap()
            .is_none()
    );

    let denied = h.request(replacement.proposal.clone(), &[]);
    let existing = h.post_pair(reversal.clone(), denied.clone()).unwrap_err();
    let mut missing_rev = reversal.clone();
    let mut missing_rep = denied;
    let missing = EntryRef {
        vid: VId(0xffff_ffff),
        entry_digest: [0x91; 32],
    };
    missing_rev.proposal.supersession[0].target = missing;
    missing_rep.proposal.supersession[0].target = missing;
    let absent = h.post_pair(missing_rev, missing_rep).unwrap_err();
    assert_eq!(existing, absent);
    assert_eq!(h.db.frontier().unwrap(), head);

    // An already published standalone reversal cannot gain a replacement
    // in a later commit, even with otherwise valid requests.
    h.post(reversal.clone()).unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(
        h.post_pair(reversal, replacement).unwrap_err().exit,
        exit::CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn legacy_replacement_pair_retry_preserves_the_recorded_identity_without_new_writes() {
    // Immutable history produced by the earlier pair writer used a
    // principal/key-derived Replacement VID. Seed that representation in
    // one native commit; every subsequent action uses the public kernel.
    let mut h = harness_legacy();
    let original = h.proposal(
        h.rent_legs(100),
        b"legacy-pair-original",
        EntryClass::ORIGINAL,
    );
    let target = outcome_recovery_tests::write_legacy(&mut h, original);
    let reversal = h.request(
        h.reversal_of_entry(target, b"legacy-pair-reversal"),
        &["post"],
    );
    let replacement = h.request(
        replacement_proposal(
            target,
            h.proposal(
                h.rent_legs(125),
                b"legacy-pair-replacement",
                EntryClass::REPLACEMENT,
            ),
        ),
        &["post"],
    );
    let legacy_vid = entry_vid(
        h.book.book_id,
        &replacement.proposal.principal_ref.0.to_le_bytes(),
        &replacement.proposal.idempotency_key,
    );
    let mut entries = fgdb::WriteBatch::new(relation::HAS_LEG);
    let mut supersedes = fgdb::WriteBatch::new(relation::SUPERSEDES);
    let mut in_period = fgdb::WriteBatch::new(relation::IN_PERIOD);
    let mut evidence = fgdb::WriteBatch::new(relation::EVIDENCED_BY);
    let mut posts_to = fgdb::WriteBatch::new(relation::POSTS_TO);
    let mut in_unit = fgdb::WriteBatch::new(relation::IN_UNIT);
    let source = document_vid(&h.evidence[0].document_oid);
    for (vid, request) in [
        (reversal_vid(target.vid), &reversal),
        (legacy_vid, &replacement),
    ] {
        let entry = request
            .proposal
            .clone()
            .seal(request.approvals.clone(), None)
            .unwrap();
        entries.create_vertex(
            vid,
            vec![fa_model::symbols::label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        for (i, leg) in entry.proposal.legs.iter().enumerate() {
            let ordinal = u16::try_from(i).unwrap();
            let lvid = leg_vid(vid, ordinal);
            let mut props =
                fa_model::leg_mirrors(leg, ordinal, entry.proposal.effective_date, &h.book.units)
                    .unwrap();
            props.push((
                property::APPLIED,
                fa_journal::rows::mantissa_scalar("applied", 0).unwrap(),
            ));
            entries.create_vertex(lvid, vec![fa_model::symbols::label::LEG], props);
            entries.add_edge(
                edge_id(relation::HAS_LEG, vid, lvid),
                vid,
                lvid,
                vec![(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
            );
            posts_to.add_edge(
                edge_id(relation::POSTS_TO, lvid, leg.account_ref),
                lvid,
                leg.account_ref,
                vec![],
            );
            let unit = h.book.units.get(leg.amount.unit).unwrap();
            let uvid =
                fa_model::unit_vid(h.book.book_id, &format!("{}@v{}", unit.code, unit.version));
            in_unit.add_edge(edge_id(relation::IN_UNIT, lvid, uvid), lvid, uvid, vec![]);
        }
        let period = period_vid(&h.book.calendar.id, &h.march);
        in_period.add_edge(
            edge_id(relation::IN_PERIOD, vid, period),
            vid,
            period,
            vec![],
        );
        supersedes.add_edge(
            edge_id(relation::SUPERSEDES, vid, target.vid),
            vid,
            target.vid,
            vec![],
        );
        evidence.add_edge(
            edge_id(relation::EVIDENCED_BY, vid, source),
            vid,
            source,
            vec![],
        );
    }
    let ctx = h.ctx();
    let mut txn = h.db.begin(&ctx.txn()).unwrap();
    txn.write_ordered(
        &mut h.db,
        vec![entries, posts_to, in_unit, in_period, supersedes, evidence],
    )
    .unwrap();
    let recorded_at = h
        .runtime
        .block_on(txn.commit(&mut h.db, &ctx.commit()))
        .unwrap();
    assert!(
        h.db.vertex(fa_journal::rows::replacement_vid(target.vid))
            .unwrap()
            .is_none()
    );
    let (reversed, replaced) = h.post_pair(reversal.clone(), replacement.clone()).unwrap();
    assert!(matches!(reversed, Posted::AlreadyRecorded { .. }));
    assert!(matches!(replaced, Posted::AlreadyRecorded { .. }));
    assert_eq!(replaced.entry_ref().vid, legacy_vid);
    assert_eq!(reversed.recorded_at(), recorded_at);
    assert_eq!(replaced.recorded_at(), recorded_at);
    assert_eq!(h.db.frontier().unwrap(), recorded_at);
    let mut resealed_reversal = reversal.clone();
    let mut resealed_replacement = replacement.clone();
    resealed_reversal.proposal.description = h.statement("March rent", 223);
    resealed_replacement.proposal.description = h.statement("March rent", 224);
    let (resealed_rev, resealed_rep) = h
        .post_pair(resealed_reversal, resealed_replacement)
        .unwrap();
    assert!(matches!(resealed_rev, Posted::AlreadyRecorded { .. }));
    assert!(matches!(resealed_rep, Posted::AlreadyRecorded { .. }));
    assert_eq!(resealed_rev.entry_ref(), reversed.entry_ref());
    assert_eq!(resealed_rep.entry_ref(), replaced.entry_ref());
    assert_eq!(resealed_rev.recorded_at(), recorded_at);
    assert_eq!(resealed_rep.recorded_at(), recorded_at);
    assert_eq!(h.db.frontier().unwrap(), recorded_at);
    let mut altered = replacement.clone();
    altered.proposal.idempotency_key = b"legacy-pair-different-key".to_vec();
    assert_eq!(
        h.post_pair(reversal.clone(), altered).unwrap_err().exit,
        exit::CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), recorded_at);
    let mut altered = replacement;
    altered
        .approvals
        .push(h.approve_transition(altered.proposal.proposal_digest().unwrap()));
    let head = h.db.frontier().unwrap();
    assert_eq!(
        h.post_pair(reversal, altered).unwrap_err().exit,
        exit::CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn unpaired_or_mismatched_replacement_is_refused_without_mutating_book() {
    let mut h = harness();
    let original = h
        .post(h.request(
            h.proposal(h.rent_legs(10_000), b"orig-unpaired", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("original post")
        .entry_ref();

    let mut rep_only = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 12_500)),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 12_500)),
        ],
        b"unpaired-rep",
        EntryClass::REPLACEMENT,
    );
    rep_only.supersession = vec![Supersession {
        target: original,
        kind: SupersessionKind::Replaces,
        reason_code: 1,
    }];

    // 1. Standalone single-entry post of a Replacement with Replaces supersession is refused.
    let before = h.db.frontier().unwrap();
    let r = h
        .post(h.request(rep_only.clone(), &["post"]))
        .expect_err("unpaired replacement must be refused");
    assert_eq!((r.code, r.exit), ("FA-REF-160", exit::REFUSAL), "{r}");
    assert!(
        r.cite.contains("FA-INV-08.replacement-paired"),
        "{}",
        r.cite
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    // 2. Paired batch where Replacement legs are identical to Original is refused.
    let rev_proposal = h.reversal_of(original, 10_000, b"pair-rev-ident");
    let mut ident_rep = h.proposal(
        h.rent_legs(10_000),
        b"pair-rep-ident",
        EntryClass::REPLACEMENT,
    );
    ident_rep.supersession = vec![Supersession {
        target: original,
        kind: SupersessionKind::Replaces,
        reason_code: 1,
    }];
    let rev_req = h.request(rev_proposal, &["post"]);
    let rep_req = h.request(ident_rep, &["post"]);
    let ctx = h.ctx();
    let r = h
        .runtime
        .block_on(fa_journal::post::post_replacement_pair(
            &mut h.db, &ctx, &h.book, rev_req, rep_req,
        ))
        .expect("kernel")
        .expect_err("identical replacement legs must be refused");
    assert_eq!((r.code, r.exit), ("FA-REF-051", exit::REFUSAL), "{r}");
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn chart_retry_keeps_its_birth_and_checks_semantics_and_authority() {
    let mut h = harness();
    let date = h.day();
    let chart = vec![AccountSpec {
        code: "1700".into(),
        name: "Equipment".into(),
        account_type: fa_model::AccountType::ASSET.0,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    }];
    let capability = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let install = |h: &mut Harness,
                   accounts: &[AccountSpec],
                   key: &[u8],
                   text: &str,
                   salt: u8,
                   cap: &Capability| {
        let cx = h.ctx();
        let description = Erasable::seal(
            &text.to_string(),
            None,
            &h.book.seal_key,
            [salt; 32],
            [salt; 24],
        );
        h.runtime.block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            accounts,
            PRINCIPAL,
            date,
            key,
            description,
            cap,
        ))
    };
    let first = install(
        &mut h,
        &chart,
        b"retry-chart",
        "equipment chart",
        30,
        &capability,
    )
    .unwrap()
    .unwrap();
    let cx = h.ctx();
    let role = AccountRoleSpec {
        account: account_vid(h.book.book_id, "1700"),
        role: "fixed_asset".into(),
        assigned: true,
    };
    let description = Erasable::seal(
        &"equipment role".to_string(),
        None,
        &h.book.seal_key,
        [31; 32],
        [31; 24],
    );
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &cx,
            &h.book,
            &role,
            PRINCIPAL,
            b"retry-chart-role",
            description,
            &capability,
        ))
        .unwrap()
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert!(head > first.recorded_at);
    // Different encryption nonces for the same semantic request still retry.
    let again = install(
        &mut h,
        &chart,
        b"retry-chart",
        "equipment chart",
        32,
        &capability,
    )
    .unwrap()
    .unwrap();
    assert_eq!(again, first);
    assert_eq!(h.db.frontier().unwrap(), head);

    let mut changed = chart.clone();
    changed[0].name = "Changed equipment".into();
    for (accounts, text) in [
        (changed.as_slice(), "equipment chart"),
        (chart.as_slice(), "a different reason"),
    ] {
        let refused = install(&mut h, accounts, b"retry-chart", text, 33, &capability)
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, refusal::code::IDEMPOTENCY_CONFLICT);
        assert_eq!(refused.exit, refusal::exit::CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    let duplicate = install(
        &mut h,
        &chart,
        b"fresh-chart-key",
        "equipment chart",
        34,
        &capability,
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(duplicate.code, refusal::code::STRUCTURE);
    assert_eq!(duplicate.exit, refusal::exit::USAGE);
    assert_eq!(h.db.frontier().unwrap(), head);

    let denied = install(
        &mut h,
        &chart,
        b"retry-chart",
        "equipment chart",
        35,
        &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(denied.exit, refusal::exit::SAFETY);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn account_lifecycle_open_close_promote_and_historical_chart_replay_match_oracle() {
    let mut h = harness();
    let mut oracle = fa_reference::Oracle::new(h.book.calendar.clone());
    oracle.create_periods(2026);
    oracle.transition(&h.march, PeriodTransition::Open).unwrap();
    oracle.add_account(fa_reference::Account {
        code: "1".into(),
        is_leaf: false,
        unit: Some(h.usd.0),
    });
    oracle.add_account(fa_reference::Account {
        code: "1000".into(),
        is_leaf: true,
        unit: Some(h.usd.0),
    });
    oracle.add_account(fa_reference::Account {
        code: "6000".into(),
        is_leaf: true,
        unit: Some(h.usd.0),
    });

    let cap = Capability::embedded(PRINCIPAL, &["schema_change", "post"]).expect("ops");
    let ctx = h.ctx();
    let seal_key = h.book.seal_key.clone();
    let seal = move |s: &str| Erasable::seal(&s.to_string(), None, &seal_key, [5; 32], [6; 24]);
    let mar10 = DateDay::from_ymd(2026, 3, 10).unwrap();
    let mar12 = DateDay::from_ymd(2026, 3, 12).unwrap();
    let mar15 = DateDay::from_ymd(2026, 3, 15).unwrap();
    let mar20 = DateDay::from_ymd(2026, 3, 20).unwrap();

    // 1. Open leaf account 6200 on 2026-03-10.
    let spec_6200 = AccountSpec {
        code: "6200".into(),
        name: "Utilities".into(),
        account_type: 5,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    };
    let desc_open_6200 = seal("open 6200");
    let opened_6200 = h
        .runtime
        .block_on(fa_journal::open_account(
            &mut h.db,
            &ctx,
            &h.book,
            &spec_6200,
            mar10,
            None,
            PRINCIPAL,
            mar10,
            b"open-6200",
            desc_open_6200.clone(),
            &cap,
        ))
        .unwrap()
        .expect("open 6200");
    assert!(!opened_6200.already_recorded);
    oracle
        .open_account(
            fa_reference::Account {
                code: "6200".into(),
                is_leaf: true,
                unit: Some(h.usd.0),
            },
            None,
            mar10,
            None,
        )
        .unwrap();

    // Idempotent retry returns already_recorded = true.
    let retry_6200 = h
        .runtime
        .block_on(fa_journal::open_account(
            &mut h.db,
            &ctx,
            &h.book,
            &spec_6200,
            mar10,
            None,
            PRINCIPAL,
            mar10,
            b"open-6200",
            desc_open_6200,
            &cap,
        ))
        .unwrap()
        .expect("idempotent retry");
    assert!(retry_6200.already_recorded);
    assert_eq!(retry_6200.recorded_at, opened_6200.recorded_at);

    // 2. Post to 6200 on 2026-03-10.
    let mut p1 = h.proposal(
        vec![
            LegPayload::simple(
                Side::Debit,
                opened_6200.account_vid,
                Amount::new(h.usd, 3_000),
            ),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 3_000)),
        ],
        b"post-6200-mar10",
        EntryClass::ORIGINAL,
    );
    p1.effective_date = mar10;
    h.post(h.request(p1, &["post"])).expect("post on mar10");
    assert_eq!(
        oracle.post(&fa_reference::Intent {
            class: "Original".into(),
            date: mar10,
            discriminator: None,
            legs: vec![
                fa_reference::Leg {
                    side: fa_reference::Side::Debit,
                    account: "6200".into(),
                    unit: h.usd.0,
                    mantissa: 3_000,
                    entity: None,
                },
                fa_reference::Leg {
                    side: fa_reference::Side::Credit,
                    account: "1000".into(),
                    unit: h.usd.0,
                    mantissa: 3_000,
                    entity: None,
                },
            ],
            reverses: None,
            supersession_reason: 0,
            resolves: None,
            settles: vec![],
            ops: vec!["post".into()],
            approvals: 0,
            key: b"post-6200-mar10".to_vec(),
        }),
        fa_reference::Verdict::Posted {
            index: 0,
            period: h.march.clone(),
        }
    );

    // 3. Promote 6200 to a summary on 2026-03-15, then open child leaf 6200.01 under 6200.
    let seq_before_promote = h.db.frontier().unwrap();
    let promoted = h
        .runtime
        .block_on(fa_journal::promote_to_summary(
            &mut h.db,
            &ctx,
            &h.book,
            "6200",
            mar15,
            PRINCIPAL,
            mar15,
            b"promote-6200",
            seal("promote 6200"),
            &cap,
        ))
        .unwrap()
        .expect("promote 6200");
    assert!(!promoted.already_recorded);
    oracle.promote_to_summary("6200", mar15).unwrap();

    let spec_6200_child = AccountSpec {
        code: "6200.01".into(),
        name: "Electric".into(),
        account_type: 5,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: Some("6200".into()),
        limit: None,
    };
    let opened_child = h
        .runtime
        .block_on(fa_journal::open_account(
            &mut h.db,
            &ctx,
            &h.book,
            &spec_6200_child,
            mar15,
            None,
            PRINCIPAL,
            mar15,
            b"open-6200-01",
            seal("open 6200.01"),
            &cap,
        ))
        .unwrap()
        .expect("open child under promoted summary");
    oracle
        .open_account(
            fa_reference::Account {
                code: "6200.01".into(),
                is_leaf: true,
                unit: Some(h.usd.0),
            },
            Some("6200"),
            mar15,
            None,
        )
        .unwrap();

    // 4. Open leaf 6300 on 2026-03-10, post and reverse to zero balance on 2026-03-12, and close on 2026-03-20.
    let spec_6300 = AccountSpec {
        code: "6300".into(),
        name: "Temp Clearing".into(),
        account_type: 5,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    };
    let opened_6300 = h
        .runtime
        .block_on(fa_journal::open_account(
            &mut h.db,
            &ctx,
            &h.book,
            &spec_6300,
            mar10,
            None,
            PRINCIPAL,
            mar10,
            b"open-6300",
            seal("open 6300"),
            &cap,
        ))
        .unwrap()
        .expect("open 6300");
    oracle
        .open_account(
            fa_reference::Account {
                code: "6300".into(),
                is_leaf: true,
                unit: Some(h.usd.0),
            },
            None,
            mar10,
            None,
        )
        .unwrap();

    let mut p_clear = h.proposal(
        vec![
            LegPayload::simple(
                Side::Debit,
                opened_6300.account_vid,
                Amount::new(h.usd, 1_500),
            ),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 1_500)),
        ],
        b"post-6300-dr",
        EntryClass::ORIGINAL,
    );
    p_clear.effective_date = mar12;
    let posted_clear = h.post(h.request(p_clear, &["post"])).expect("post 6300 dr");
    let (clear_ref, _) = committed(&posted_clear).expect("fresh commit");
    let mut p_rev = h.reversal_of_entry(clear_ref, b"post-6300-rev");
    p_rev.effective_date = mar12;
    h.post(h.request(p_rev, &["post"])).expect("reverse 6300");

    let closed_6300 = h
        .runtime
        .block_on(fa_journal::close_account(
            &mut h.db,
            &ctx,
            &h.book,
            "6300",
            mar20,
            PRINCIPAL,
            mar20,
            b"close-6300",
            seal("close 6300"),
            &cap,
        ))
        .unwrap()
        .expect("close 6300");
    assert!(!closed_6300.already_recorded);
    oracle.close_account("6300", mar20).unwrap();

    // 5. Historical chart replay (`chart::read_at`) at both pre-promote and head frontiers.
    let snap_before =
        fa_journal::chart::read_at(&h.db, &h.book, seq_before_promote).expect("snap before");
    assert!(snap_before.accounts()[&opened_6200.account_vid].is_leaf);
    assert_eq!(
        snap_before.account_effectivity(opened_6200.account_vid),
        Some(fa_journal::AccountEffectivity {
            opened: Some(mar10),
            closed: None,
            promoted_on: None,
        })
    );

    let head = h.db.frontier().unwrap();
    let snap_head = fa_journal::chart::read_at(&h.db, &h.book, head).expect("snap head");
    assert!(!snap_head.accounts()[&opened_6200.account_vid].is_leaf);
    assert_eq!(
        snap_head.account_effectivity(opened_6200.account_vid),
        Some(fa_journal::AccountEffectivity {
            opened: Some(mar10),
            closed: None,
            promoted_on: Some(mar15),
        })
    );
    assert_eq!(
        snap_head
            .leaves_under(opened_6200.account_vid)
            .expect("leaves under 6200"),
        std::collections::BTreeSet::from([opened_child.account_vid])
    );
    assert_eq!(
        snap_head.account_effectivity(opened_6300.account_vid),
        Some(fa_journal::AccountEffectivity {
            opened: Some(mar10),
            closed: Some(mar20),
            promoted_on: None,
        })
    );
}

#[test]
fn posting_outside_account_effective_interval_or_invalid_close_and_promote_is_refused() {
    let mut h = harness();
    let mut oracle = fa_reference::Oracle::new(h.book.calendar.clone());
    oracle.create_periods(2026);
    oracle.transition(&h.march, PeriodTransition::Open).unwrap();
    oracle.add_account(fa_reference::Account {
        code: "1000".into(),
        is_leaf: true,
        unit: Some(h.usd.0),
    });

    let cap = Capability::embedded(PRINCIPAL, &["schema_change", "post"]).expect("ops");
    let ctx = h.ctx();
    let seal_key = h.book.seal_key.clone();
    let seal = move |s: &str| Erasable::seal(&s.to_string(), None, &seal_key, [5; 32], [6; 24]);
    let mar05 = DateDay::from_ymd(2026, 3, 5).unwrap();
    let mar10 = DateDay::from_ymd(2026, 3, 10).unwrap();
    let mar12 = DateDay::from_ymd(2026, 3, 12).unwrap();
    let mar15 = DateDay::from_ymd(2026, 3, 15).unwrap();
    let mar20 = DateDay::from_ymd(2026, 3, 20).unwrap();
    let mar25 = DateDay::from_ymd(2026, 3, 25).unwrap();

    // Open account 6400 with half-open interval [2026-03-10, 2026-03-20).
    let spec_6400 = AccountSpec {
        code: "6400".into(),
        name: "Seasonal Account".into(),
        account_type: 5,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    };
    let opened_6400 = h
        .runtime
        .block_on(fa_journal::open_account(
            &mut h.db,
            &ctx,
            &h.book,
            &spec_6400,
            mar10,
            Some(mar20),
            PRINCIPAL,
            mar10,
            b"open-6400",
            seal("open 6400"),
            &cap,
        ))
        .unwrap()
        .expect("open 6400");
    oracle
        .open_account(
            fa_reference::Account {
                code: "6400".into(),
                is_leaf: true,
                unit: Some(h.usd.0),
            },
            None,
            mar10,
            Some(mar20),
        )
        .unwrap();

    // 1. Posting before opened (mar05 < mar10) is refused with FA-REF-002 in both kernel and oracle.
    let before = h.db.frontier().unwrap();
    let mut p_early = h.proposal(
        vec![
            LegPayload::simple(
                Side::Debit,
                opened_6400.account_vid,
                Amount::new(h.usd, 500),
            ),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 500)),
        ],
        b"post-6400-early",
        EntryClass::ORIGINAL,
    );
    p_early.effective_date = mar05;
    let r_early = h
        .post(h.request(p_early, &["post"]))
        .expect_err("posting before opened must be refused");
    assert_eq!((r_early.code, r_early.exit), ("FA-REF-002", exit::REFUSAL));
    assert!(r_early.cite.contains("FA-INV-01.account-effective"));
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(
        oracle.post(&fa_reference::Intent {
            class: "Original".into(),
            date: mar05,
            discriminator: None,
            legs: vec![
                fa_reference::Leg {
                    side: fa_reference::Side::Debit,
                    account: "6400".into(),
                    unit: h.usd.0,
                    mantissa: 500,
                    entity: None,
                },
                fa_reference::Leg {
                    side: fa_reference::Side::Credit,
                    account: "1000".into(),
                    unit: h.usd.0,
                    mantissa: 500,
                    entity: None,
                },
            ],
            reverses: None,
            supersession_reason: 0,
            resolves: None,
            settles: vec![],
            ops: vec!["post".into()],
            approvals: 0,
            key: b"post-6400-early".to_vec(),
        }),
        fa_reference::Verdict::Refused { code: "FA-REF-002" }
    );

    // 2. Posting at or after closed (mar20 and mar25) is refused with FA-REF-002 in both kernel and oracle.
    for (day, key) in [
        (mar20, &b"post-6400-at-close"[..]),
        (mar25, &b"post-6400-after"[..]),
    ] {
        let mut p_late = h.proposal(
            vec![
                LegPayload::simple(
                    Side::Debit,
                    opened_6400.account_vid,
                    Amount::new(h.usd, 500),
                ),
                LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 500)),
            ],
            key,
            EntryClass::ORIGINAL,
        );
        p_late.effective_date = day;
        let r_late = h
            .post(h.request(p_late, &["post"]))
            .expect_err("posting at/after closed must be refused");
        assert_eq!((r_late.code, r_late.exit), ("FA-REF-002", exit::REFUSAL));
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(
            oracle.post(&fa_reference::Intent {
                class: "Original".into(),
                date: day,
                discriminator: None,
                legs: vec![
                    fa_reference::Leg {
                        side: fa_reference::Side::Debit,
                        account: "6400".into(),
                        unit: h.usd.0,
                        mantissa: 500,
                        entity: None,
                    },
                    fa_reference::Leg {
                        side: fa_reference::Side::Credit,
                        account: "1000".into(),
                        unit: h.usd.0,
                        mantissa: 500,
                        entity: None,
                    },
                ],
                reverses: None,
                supersession_reason: 0,
                resolves: None,
                settles: vec![],
                ops: vec!["post".into()],
                approvals: 0,
                key: key.to_vec(),
            }),
            fa_reference::Verdict::Refused { code: "FA-REF-002" }
        );
    }

    // 3. Posting inside [mar10, mar20) on mar15 succeeds; then attempting to promote_to_summary
    //    on mar12 (< mar15) is refused naming the blocking entry VId.
    let mut p_ok = h.proposal(
        vec![
            LegPayload::simple(
                Side::Debit,
                opened_6400.account_vid,
                Amount::new(h.usd, 500),
            ),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 500)),
        ],
        b"post-6400-ok",
        EntryClass::ORIGINAL,
    );
    p_ok.effective_date = mar15;
    let posted_ok = h.post(h.request(p_ok, &["post"])).expect("post on mar15");
    let (ok_ref, _) = committed(&posted_ok).expect("fresh commit");
    let r_prom = h
        .runtime
        .block_on(fa_journal::promote_to_summary(
            &mut h.db,
            &ctx,
            &h.book,
            "6400",
            mar12,
            PRINCIPAL,
            mar15,
            b"bad-promote-6400",
            seal("bad promote"),
            &cap,
        ))
        .unwrap()
        .expect_err("promote before latest posting must be refused");
    assert_eq!((r_prom.code, r_prom.exit), ("FA-REF-002", exit::REFUSAL));
    assert!(r_prom.message.contains(&format!("{:032x}", ok_ref.vid.0)));

    // 4. Attempting to close_account on 6000 while it has a non-zero balance is refused.
    let mut p_rent = h.proposal(h.rent_legs(1_000), b"rent-nonzero", EntryClass::ORIGINAL);
    p_rent.effective_date = mar10;
    h.post(h.request(p_rent, &["post"])).expect("post rent");
    let r_close = h
        .runtime
        .block_on(fa_journal::close_account(
            &mut h.db,
            &ctx,
            &h.book,
            "6000",
            mar20,
            PRINCIPAL,
            mar20,
            b"bad-close-6000",
            seal("bad close"),
            &cap,
        ))
        .unwrap()
        .expect_err("closing non-zero account must be refused");
    assert_eq!((r_close.code, r_close.exit), ("FA-REF-002", exit::REFUSAL));
    assert!(r_close.message.contains("non-zero posted balance"));
}

// ---------------------------------------------------------------------------
// PostBatch (plan §5.8–5.9, bead fa-nl7)
// ---------------------------------------------------------------------------

impl Harness {
    fn batch(&self, key: &[u8], members: Vec<EntryPayload>) -> fa_intents::PostBatch {
        let intents = members
            .into_iter()
            .map(|p| fa_intents::PostIntent::new(p, Vec::new()).expect("typed intent"))
            .collect();
        fa_intents::PostBatch::new(key.to_vec(), intents).expect("a well-formed batch")
    }

    fn post_batch(
        &mut self,
        batch: fa_intents::PostBatch,
    ) -> Result<fa_journal::BatchPosted, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let capability = Capability::embedded(batch.principal(), &["post"]).unwrap();
        self.runtime
            .block_on(
                async move { fa_journal::post_batch(db, &ctx, book, capability, batch).await },
            )
            .expect("batch kernel")
    }

    /// The reference a batch member's settlement names for an earlier
    /// member: its identity-derived vid and its sealed digest.
    fn member_ref(&self, proposal: &EntryPayload) -> EntryRef {
        let sealed = proposal.clone().seal(Vec::new(), None).expect("seal");
        EntryRef {
            vid: entry_vid(
                self.book.book_id,
                &proposal.principal_ref.0.to_le_bytes(),
                &proposal.idempotency_key,
            ),
            entry_digest: sealed.entry_digest,
        }
    }
}

/// fa-nl7: an invoice and the receipt that settles it commit in one batch,
/// in one commit; the receipt sees the invoice's staged open item. The
/// IntentOutcome records both, in order, and the open amount is folded.
#[test]
fn a_batch_commits_an_invoice_and_its_application_atomically_in_one_commit() {
    let mut h = harness();
    let usd = h.usd;
    let invoice = h.invoice(50_000, b"batch-inv");
    let inv_ref = h.member_ref(&invoice);
    let receipt = h.receipt(20_000, vec![settle(inv_ref, 0, usd, 20_000)], b"batch-rcpt");
    let basis = h.db.frontier().unwrap();
    let batch = h.batch(b"batch-1", vec![invoice, receipt]);
    let posted = h.post_batch(batch).expect("the batch commits");
    eprintln!(
        "batch: outcome {:032x} at {} entries {:?}",
        posted.outcome.0,
        posted.recorded_at.0,
        posted.entries.iter().map(|e| e.vid.0).collect::<Vec<_>>()
    );
    assert!(!posted.already_recorded);
    assert_eq!(
        posted.recorded_at.0,
        basis.0 + 1,
        "one commit for the batch"
    );
    assert_eq!(posted.entries.len(), 2);
    assert_eq!(posted.entries[0], inv_ref);
    assert_eq!(posted.periods, vec![h.march.clone(), h.march.clone()]);
    for e in &posted.entries {
        let (_, seq) = read_entry(&h.db, e.vid).unwrap().expect("member recorded");
        assert_eq!(seq, posted.recorded_at);
    }
    assert_eq!(
        h.applied_to(inv_ref.vid, 0),
        20_000,
        "the application folded"
    );
    let (body, seq) = fa_journal::read_outcome(&h.db, &h.ctx().query(), posted.outcome)
        .unwrap()
        .expect("the IntentOutcome is recorded");
    assert_eq!(seq, posted.recorded_at);
    let vids: Vec<VId> = posted.entries.iter().map(|e| e.vid).collect();
    assert_eq!(body.request_digest, request_digest(b"batch-1", &vids));
    assert_eq!(body.entries, posted.entries);
}

/// The format permits more entries than one native scalar can hold. The
/// ordered outcome and its fragments must publish with all members and retry.
#[test]
fn large_batch_records_a_chunked_outcome_and_retries_without_another_commit() {
    let mut h = harness();
    let members = (0..350)
        .map(|index| {
            h.proposal(
                h.rent_legs(1),
                format!("large-member-{index}").as_bytes(),
                EntryClass::ORIGINAL,
            )
        })
        .collect();
    let batch = h.batch(b"large-outcome", members);
    let basis = h.db.frontier().unwrap();
    let posted = h.post_batch(batch.clone()).unwrap();
    assert_eq!(posted.recorded_at.0, basis.0 + 1);
    assert_eq!(posted.entries.len(), 350);
    let (body, seq) = read_outcome(&h.db, &h.ctx().query(), posted.outcome)
        .unwrap()
        .unwrap();
    assert!(body.canonical_bytes().unwrap().len() > 16_384);
    assert_eq!(body.entries, posted.entries);
    assert_eq!(seq, posted.recorded_at);
    let (coverage_rows, outcome_rows): (Vec<_>, Vec<_>) =
        h.db.vertices()
            .unwrap()
            .into_iter()
            .filter(|row| {
                row.labels
                    .contains(&fa_model::symbols::label::INTENT_OUTCOME)
            })
            .partition(|row| row.vid == fa_journal::outcome::coverage_vid(h.book.book_id));
    assert_eq!(coverage_rows.len(), 1);
    assert!(coverage_rows[0].created_at <= basis);
    assert_eq!(
        outcome_rows.len(),
        posted.entries.len() + 1 + body.canonical_bytes().unwrap().len().div_ceil(4096)
    );
    for entry in &posted.entries {
        let claims: Vec<_> = outcome_rows
            .iter()
            .filter(|row| {
                matches!(fa_journal::rows::prop(row, property::TARGET_REF),
                    Some(CanonicalScalar::Bytes(target))
                        if target.as_slice() == entry.vid.0.to_le_bytes())
            })
            .collect();
        assert_eq!(claims.len(), 1, "every batch member owns its atomic key");
    }
    assert!(
        outcome_rows
            .iter()
            .all(|row| row.created_at == posted.recorded_at)
    );
    let retry = h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at);
}

/// fa-nl7: a member refusal refuses the whole batch and names the member;
/// nothing of any member is recorded, and the same key is still free.
#[test]
fn a_refused_member_refuses_the_whole_batch_and_records_nothing() {
    let mut h = harness();
    let good = h.proposal(h.rent_legs(1_000), b"batch-good", EntryClass::ORIGINAL);
    let good_vid = h.member_ref(&good).vid;
    let unbalanced = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 100)),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 99)),
        ],
        b"batch-bad",
        EntryClass::ORIGINAL,
    );
    let basis = h.db.frontier().unwrap();
    let before = h.db.vertices().unwrap();
    let batch = h.batch(b"batch-2", vec![good.clone(), unbalanced]);
    let outcome = fa_journal::outcome_vid(&h.book, &batch);
    let r = h.post_batch(batch).unwrap_err();
    eprintln!("batch: refused -> {} {}", r.code, r.message);
    assert!(r.message.starts_with("batch member 1: "), "{}", r.message);
    assert_eq!(h.db.frontier().unwrap(), basis, "nothing was recorded");
    assert_eq!(h.db.vertices().unwrap(), before);
    assert!(h.db.vertex(good_vid).unwrap().is_none());
    assert!(h.db.vertex(outcome).unwrap().is_none());
    // A forward reference is a missing target: the second member settles the
    // third, which has not been staged yet.
    let usd = h.usd;
    let later = h.invoice(500, b"batch-later");
    let later_ref = h.member_ref(&later);
    let early = h.receipt(100, vec![settle(later_ref, 0, usd, 100)], b"batch-early");
    let r = h
        .post_batch(h.batch(b"batch-3", vec![good, early, later]))
        .unwrap_err();
    eprintln!("batch: forward reference -> {} {}", r.code, r.message);
    assert!(r.message.starts_with("batch member 1: "), "{}", r.message);
    assert_eq!(h.db.frontier().unwrap(), basis);
}

/// fa-nl7 (FA-INV-09): an identical batch retry returns the recorded
/// outcome and writes nothing; the same key with different members or a
/// different order is an idempotency conflict; a member already posted
/// outside any batch refuses the batch.
#[test]
fn an_identical_batch_retry_is_the_recorded_outcome_and_a_changed_one_conflicts() {
    let mut h = harness();
    let a = h.proposal(h.rent_legs(1_000), b"retry-a", EntryClass::ORIGINAL);
    let b = h.proposal(h.rent_legs(2_000), b"retry-b", EntryClass::ORIGINAL);
    let first = h
        .post_batch(h.batch(b"batch-retry", vec![a.clone(), b.clone()]))
        .expect("the batch commits");
    let head = h.db.frontier().unwrap();
    let again = h
        .post_batch(h.batch(b"batch-retry", vec![a.clone(), b.clone()]))
        .expect("an identical retry is the recorded outcome");
    assert!(again.already_recorded);
    assert_eq!(again.outcome, first.outcome);
    assert_eq!(again.entries, first.entries);
    assert_eq!(again.recorded_at, first.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), head, "nothing new was written");
    // A retry from another process re-seals each description with fresh
    // salts: the same request, so the same recorded outcome.
    let reseal = |p: &EntryPayload| {
        let mut p = p.clone();
        p.description = Erasable::seal(
            &"March rent".to_string(),
            None,
            &h.book.seal_key,
            [9; 32],
            [8; 24],
        );
        p
    };
    let resealed = h
        .post_batch(h.batch(b"batch-retry", vec![reseal(&a), reseal(&b)]))
        .expect("a resealed identical retry is the recorded outcome");
    assert!(resealed.already_recorded);
    assert_eq!(resealed.entries, first.entries);
    assert_eq!(h.db.frontier().unwrap(), head, "nothing new was written");

    let r = h
        .post_batch(h.batch(b"batch-retry", vec![b.clone(), a.clone()]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT), "{r}");
    let c = h.proposal(h.rent_legs(3_000), b"retry-c", EntryClass::ORIGINAL);
    let r = h
        .post_batch(h.batch(b"batch-retry", vec![c.clone()]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT), "{r}");
    assert!(r.message.contains("batch key reused"), "{}", r.message);
    assert_eq!(h.db.frontier().unwrap(), head);

    // A member posted on its own first: the batch is refused, nothing new.
    let solo = h
        .post(h.request(c.clone(), &["post"]))
        .expect("posted alone");
    let r = h.post_batch(h.batch(b"batch-other", vec![c])).unwrap_err();
    assert_eq!(r.exit, exit::CONFLICT, "{r}");
    assert!(
        r.message
            .contains(&format!("{:032x}", solo.entry_ref().vid.0)),
        "{}",
        r.message
    );
}

/// fa-nl7: the batch's own shape is checked before the kernel runs.
#[test]
fn a_batch_needs_members_of_one_principal_with_distinct_keys() {
    let h = harness();
    let a = h.proposal(h.rent_legs(1_000), b"shape-a", EntryClass::ORIGINAL);
    let intent = |p: EntryPayload| fa_intents::PostIntent::new(p, Vec::new()).unwrap();
    assert!(fa_intents::PostBatch::new(b"k".to_vec(), Vec::new()).is_err());
    assert!(fa_intents::PostBatch::new(Vec::new(), vec![intent(a.clone())]).is_err());
    assert!(
        fa_intents::PostBatch::new(b"k".to_vec(), vec![intent(a.clone()), intent(a.clone())])
            .is_err(),
        "two members with one key"
    );
    let mut other = h.proposal(h.rent_legs(1_000), b"shape-b", EntryClass::ORIGINAL);
    other.principal_ref = VId(31);
    assert!(
        fa_intents::PostBatch::new(b"k".to_vec(), vec![intent(a.clone()), intent(other)]).is_err(),
        "two principals"
    );
    let batch = fa_intents::PostBatch::new(b"k".to_vec(), vec![intent(a)]).unwrap();
    let bytes = batch.canonical_bytes().unwrap();
    assert_eq!(fa_intents::PostBatch::decode(&bytes).unwrap(), batch);
    for end in [0, 8, bytes.len() - 1] {
        assert!(
            fa_intents::PostBatch::decode(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
}

// ---------------------------------------------------------------------------
// Portable atomic batch plans (plan §5.8, §10.4)
// ---------------------------------------------------------------------------

impl Harness {
    fn planned_batch(
        &mut self,
        batch: fa_intents::PostBatch,
        capability: &Capability,
    ) -> Result<fa_intents::BatchPlan, Refusal> {
        let ctx = self.ctx();
        self.runtime
            .block_on(fa_journal::plan_batch_with_history(
                &mut self.db,
                &ctx,
                &self.book,
                capability.clone(),
                batch,
            ))
            .expect("batch planning kernel")
    }

    fn publish_batch_plan(
        &mut self,
        plan: fa_intents::BatchPlan,
        capability: &Capability,
    ) -> Result<fa_journal::BatchPosted, Refusal> {
        let ctx = self.ctx();
        self.runtime
            .block_on(fa_journal::commit_batch_plan(
                &mut self.db,
                &ctx,
                &self.book,
                capability.clone(),
                plan,
            ))
            .expect("batch plan commit kernel")
    }
}

#[test]
fn batch_plan_rehearses_an_invoice_and_application_then_retains_one_exact_retry() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let invoice = h.invoice(50_000, b"planned-batch-invoice");
    let target = h.member_ref(&invoice);
    let receipt = h.receipt(
        20_000,
        vec![settle(target, 0, h.usd, 20_000)],
        b"planned-batch-receipt",
    );
    let batch = h.batch(b"planned-batch", vec![invoice, receipt]);
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let plan = h.planned_batch(batch, &capability).unwrap();
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(
        h.db.vertices().unwrap(),
        vertices,
        "no accounting or certificate publication"
    );
    assert_eq!(plan.prepared_entries().len(), 2);
    assert_eq!(plan.periods(), [h.march.clone(), h.march.clone()]);
    assert_eq!(plan.certificate().snapshot_seq, before);
    let bytes = plan.canonical_bytes().unwrap();
    let restored = fa_intents::BatchPlan::decode(&bytes).unwrap();
    assert_eq!(restored, plan);
    let posted = h.publish_batch_plan(restored, &capability).unwrap();
    assert!(!posted.already_recorded);
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    assert_eq!(posted.entries[0], target);
    assert_eq!(h.applied_to(target.vid, 0), 20_000);
    let cvid = plan_certificate_vid(h.book.book_id, &plan.certificate_digest().unwrap());
    let certificate = h.db.vertex(cvid).unwrap().unwrap();
    assert_eq!(certificate.created_at, posted.recorded_at);
    for entry in &posted.entries {
        assert_eq!(
            read_entry(&h.db, entry.vid).unwrap().unwrap().1,
            posted.recorded_at
        );
        let edge =
            h.db.edge(edge_id(relation::CITES, entry.vid, cvid))
                .unwrap()
                .unwrap();
        assert_eq!(edge.entry.created_at, posted.recorded_at);
    }
    let unrelated = h.proposal(h.rent_legs(100), b"after-batch-plan", EntryClass::ORIGINAL);
    h.post(h.request(unrelated, &["post"])).unwrap();
    let head = h.db.frontier().unwrap();
    let retry = h.publish_batch_plan(plan, &capability).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn batch_plan_refuses_member_failure_forward_reference_and_stale_basis_without_writes() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let good = h.proposal(h.rent_legs(100), b"batch-plan-good", EntryClass::ORIGINAL);
    let mut bad = h.proposal(
        h.rent_legs(100),
        b"batch-plan-unbalanced",
        EntryClass::ORIGINAL,
    );
    bad.legs[1].amount.mantissa = 99;
    bad.unit_totals = EntryPayload::fold_unit_totals(&bad.legs).unwrap();
    let before = h.db.frontier().unwrap();
    let refusal = h
        .planned_batch(h.batch(b"bad-plan", vec![good.clone(), bad]), &capability)
        .unwrap_err();
    assert!(refusal.message.starts_with("batch member 1:"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    let later = h.invoice(500, b"batch-plan-later");
    let receipt = h.receipt(
        100,
        vec![settle(h.member_ref(&later), 0, h.usd, 100)],
        b"batch-plan-forward",
    );
    let refusal = h
        .planned_batch(h.batch(b"forward-plan", vec![receipt, later]), &capability)
        .unwrap_err();
    assert!(refusal.message.starts_with("batch member 0:"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    let plan = h
        .planned_batch(h.batch(b"stale-plan", vec![good]), &capability)
        .unwrap();
    let march = h.march.clone();
    h.transition(&march, PeriodTransition::Close, b"close-after-batch-plan")
        .unwrap();
    let closed = h.db.frontier().unwrap();
    let refusal = h.publish_batch_plan(plan, &capability).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-034", "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), closed);
}

#[test]
fn batch_plan_authentication_binds_order_previews_effects_and_current_authority() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let a = h.proposal(h.rent_legs(100), b"batch-auth-a", EntryClass::ORIGINAL);
    let b = h.proposal(h.rent_legs(200), b"batch-auth-b", EntryClass::ORIGINAL);
    let plan = h
        .planned_batch(h.batch(b"batch-auth", vec![a, b]), &capability)
        .unwrap();
    let before = h.db.frontier().unwrap();
    let mut changed = plan.certificate().clone();
    changed.effects_digest[0] ^= 1;
    let forged = fa_intents::BatchPlan::new(
        plan.batch().clone(),
        plan.prepared_entries().to_vec(),
        plan.periods().to_vec(),
        changed,
    )
    .unwrap();
    assert_eq!(
        h.publish_batch_plan(forged, &capability).unwrap_err().code,
        "FA-REF-034"
    );
    let mut members = plan.batch().members().to_vec();
    members.reverse();
    let reordered =
        fa_intents::PostBatch::new(plan.batch().idempotency_key().to_vec(), members).unwrap();
    let mut entries = plan.prepared_entries().to_vec();
    entries.reverse();
    let mut certificate = plan.certificate().clone();
    certificate.intent_digest = reordered.digest().unwrap();
    certificate.prepared_digest =
        fa_intents::BatchPlan::prepared_digest(&entries, plan.periods()).unwrap();
    let forged =
        fa_intents::BatchPlan::new(reordered, entries, plan.periods().to_vec(), certificate)
            .unwrap();
    assert_eq!(
        h.publish_batch_plan(forged, &capability).unwrap_err().code,
        "FA-REF-034"
    );
    let changed_capability = capability.clone().with_ceiling(h.usd, 1_000).unwrap();
    assert_eq!(
        h.publish_batch_plan(plan.clone(), &changed_capability)
            .unwrap_err()
            .code,
        "FA-REF-034"
    );
    let other = Capability::embedded(VId(99), &["post"]).unwrap();
    assert!(h.publish_batch_plan(plan.clone(), &other).is_err());
    assert_eq!(h.db.frontier().unwrap(), before);
    let bytes = plan.canonical_bytes().unwrap();
    for end in [0, 1, 13, 14, 18, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            fa_intents::BatchPlan::decode(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(fa_intents::BatchPlan::decode(&trailing).is_err());
    let mut future = bytes;
    future[14] = 2;
    assert!(fa_intents::BatchPlan::decode(&future).is_err());

    // A test issuer with the actual book key can authenticate a false
    // effects claim. Native re-staging, independently of authentication,
    // must still refuse it before a single member or certificate publishes.
    let mut certificate = plan.certificate().clone();
    certificate.effects_digest[0] ^= 1;
    let key = fgdb_crypto::derive_key("fa:batch-plan-authentication-key:v1", &h.book.seal_key.0);
    certificate.authentication =
        fgdb_crypto::keyed_hash(&key, &certificate.authentication_bytes().unwrap()).0;
    let forged = fa_intents::BatchPlan::new(
        plan.batch().clone(),
        plan.prepared_entries().to_vec(),
        plan.periods().to_vec(),
        certificate,
    )
    .unwrap();
    let refusal = h.publish_batch_plan(forged, &capability).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-034");
    assert!(refusal.message.contains("native effects"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn batch_plan_satisfies_required_dry_run_without_weakening_direct_commit_admission() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"])
        .unwrap()
        .with_requires_dry_run();
    let proposal = h.proposal(
        h.rent_legs(100),
        b"requires-batch-plan",
        EntryClass::ORIGINAL,
    );
    let batch = h.batch(b"requires-batch-review", vec![proposal]);
    let before = h.db.frontier().unwrap();
    let ctx = h.ctx();
    let refusal = h
        .runtime
        .block_on(fa_journal::post_batch(
            &mut h.db,
            &ctx,
            &h.book,
            capability.clone(),
            batch.clone(),
        ))
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("requires_dry_run"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);

    let plan = h.planned_batch(batch, &capability).unwrap();
    let mut certificate = plan.certificate().clone();
    certificate.authentication[0] ^= 1;
    let forged = fa_intents::BatchPlan::new(
        plan.batch().clone(),
        plan.prepared_entries().to_vec(),
        plan.periods().to_vec(),
        certificate,
    )
    .unwrap();
    assert_eq!(
        h.publish_batch_plan(forged, &capability).unwrap_err().code,
        "FA-REF-034"
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    let posted = h.publish_batch_plan(plan.clone(), &capability).unwrap();
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    assert!(
        h.publish_batch_plan(plan, &capability)
            .unwrap()
            .already_recorded
    );
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at);
}

#[test]
fn batch_plan_agent_rehearsal_cannot_publish_or_change_its_holder() {
    let mut h = harness();
    let agent = Capability::new(
        PRINCIPAL,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap();
    let proposal = h.proposal(h.rent_legs(100), b"agent-batch-plan", EntryClass::ORIGINAL);
    let before = h.db.frontier().unwrap();
    let plan = h
        .planned_batch(h.batch(b"agent-batch", vec![proposal]), &agent)
        .unwrap();
    assert_eq!(h.db.frontier().unwrap(), before);
    let refusal = h.publish_batch_plan(plan.clone(), &agent).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-013", "{refusal}");
    let human = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    assert_eq!(
        h.publish_batch_plan(plan, &human).unwrap_err().code,
        "FA-REF-034"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn batch_plan_rechecks_revocation_even_when_its_original_outcome_is_recorded() {
    for published in [false, true] {
        let mut h = harness();
        let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
        let proposal = h.proposal(
            h.rent_legs(100),
            b"revoked-batch-plan",
            EntryClass::ORIGINAL,
        );
        let plan = h
            .planned_batch(h.batch(b"revoked-batch", vec![proposal]), &capability)
            .unwrap();
        if published {
            h.publish_batch_plan(plan.clone(), &capability).unwrap();
        }
        let revoke = RevocationRequest {
            capability: Capability::embedded(VId(99), &["issue_capability"]).unwrap(),
            revoked: capability.commitment().unwrap(),
            effective_date: h.day(),
            idempotency_key: b"revoke-batch-authority".to_vec(),
            description: h.statement("revoke batch authority", 17),
        };
        let ctx = h.ctx();
        h.runtime
            .block_on(revoke_capability(&mut h.db, &ctx, &h.book, revoke))
            .unwrap()
            .unwrap();
        let before = h.db.frontier().unwrap();
        let refusal = h.publish_batch_plan(plan, &capability).unwrap_err();
        assert!(
            refusal.message.contains("revoked"),
            "{published}: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), before);
    }
}

#[test]
fn batch_plan_retains_large_transcripts_and_refuses_an_ordinary_batch_as_its_retry() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    // Each description sits just under max_description_bytes (1,020 of
    // 1,024); sixteen of them carry the plan past 16,384 bytes.
    let members = (0..16)
        .map(|index| {
            let mut proposal = h.proposal(
                h.rent_legs(100),
                format!("chunked-plan-{index}").as_bytes(),
                EntryClass::ORIGINAL,
            );
            proposal.description = h.statement(&"batch evidence ".repeat(68), index + 1);
            proposal
        })
        .collect();
    let batch = h.batch(b"chunked-batch-plan", members);
    let plan = h.planned_batch(batch.clone(), &capability).unwrap();
    assert!(plan.canonical_bytes().unwrap().len() > 16_384);
    let posted = h.publish_batch_plan(plan.clone(), &capability).unwrap();
    assert_eq!(posted.entries.len(), 16);
    assert!(
        h.publish_batch_plan(plan, &capability)
            .unwrap()
            .already_recorded
    );

    let mut h = harness();
    let member = h.proposal(
        h.rent_legs(100),
        b"ordinary-batch-member",
        EntryClass::ORIGINAL,
    );
    let batch = h.batch(b"ordinary-batch", vec![member]);
    let plan = h.planned_batch(batch.clone(), &capability).unwrap();
    h.post_batch(batch).unwrap();
    let before = h.db.frontier().unwrap();
    assert_eq!(
        h.publish_batch_plan(plan, &capability).unwrap_err().code,
        "FA-REF-034"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

/// A description one byte past max_description_bytes is refused as a
/// structure error before anything is written, and cannot become a batch
/// member: inside a batch it used to commit and then read back as Corrupt.
#[test]
fn an_unreadably_long_description_is_refused_before_commit() {
    let mut h = harness();
    let before = h.db.frontier().unwrap();
    let mut proposal = h.proposal(h.rent_legs(100), b"long-description", EntryClass::ORIGINAL);
    proposal.description = h.statement(&"d".repeat(1_025), 1);
    let r = h.post(h.request(proposal.clone(), &["post"])).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    assert!(r.message.contains("description"), "{r}");
    assert_eq!(h.db.frontier().unwrap(), before);

    assert!(matches!(
        fa_intents::PostIntent::new(proposal, Vec::new()).unwrap_err(),
        fa_intents::IntentError::Entry(fa_model::EntryError::Invalid {
            what: "description",
            ..
        })
    ));
}

#[test]
fn batch_plan_authenticates_chunked_outcomes_and_rejects_a_damaged_fragment() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let members = (0..90)
        .map(|index| {
            h.proposal(
                h.rent_legs(1),
                format!("planned-outcome-{index}").as_bytes(),
                EntryClass::ORIGINAL,
            )
        })
        .collect();
    let batch = h.batch(b"planned-chunked-outcome", members);
    let plan = h.planned_batch(batch, &capability).unwrap();
    let posted = h.publish_batch_plan(plan.clone(), &capability).unwrap();
    assert!(
        h.publish_batch_plan(plan.clone(), &capability)
            .unwrap()
            .already_recorded
    );
    let fragment =
        h.db.vertices()
            .unwrap()
            .into_iter()
            .find(|row| {
                row.labels.as_slice() == [fa_model::symbols::label::INTENT_OUTCOME]
                    && row.props.len() == 3
            })
            .unwrap();
    assert_eq!(fragment.created_at, posted.recorded_at);
    let mut damaged = fa_journal::rows::bytes(&fragment, property::FA_PAYLOAD, "fragment").unwrap();
    damaged[0] ^= 1;
    let mut corrupt = fgdb::WriteBatch::new(relation::IN_BATCH);
    corrupt.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(damaged).unwrap()),
    );
    h.write_raw(corrupt);
    let ctx = h.ctx();
    assert!(matches!(
        h.runtime.block_on(commit_batch_plan(
            &mut h.db, &ctx, &h.book, capability, plan
        )),
        Err(KernelError::Corrupt(_))
    ));
}

#[test]
fn batch_plan_retry_derives_member_identity_from_the_authenticated_request() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let proposal = h.proposal(h.rent_legs(100), b"batch-identity", EntryClass::ORIGINAL);
    let expected = h.member_ref(&proposal);
    let batch = h.batch(b"batch-identity-review", vec![proposal]);
    let plan = h.planned_batch(batch, &capability).unwrap();
    let digest = plan.certificate_digest().unwrap();
    let cvid = plan_certificate_vid(h.book.book_id, &digest);
    let ovid = outcome_vid(&h.book, plan.batch());
    let alternate = VId(0xfeed);
    assert_ne!(alternate, expected.vid);
    let body = OutcomeBody {
        request_digest: request_digest(plan.batch().idempotency_key(), &[alternate]),
        entries: vec![plan.prepared_entries()[0].entry_ref(alternate)],
    };
    // A corrupt raw publication reproduces the payloads, authentic plan and
    // all retaining edges at the expected birth, but substitutes another
    // entry identity. Its self-consistent outcome is not this plan's retry.
    let mut rows = fgdb::WriteBatch::new(relation::CITES);
    rows.create_vertex(
        alternate,
        vec![fa_model::symbols::label::ENTRY],
        fa_model::entry_mirrors(&plan.prepared_entries()[0]).unwrap(),
    );
    rows.create_vertex(
        ovid,
        vec![fa_model::symbols::label::INTENT_OUTCOME],
        vec![(
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(body.canonical_bytes().unwrap()).unwrap(),
        )],
    );
    let ctx = h.ctx();
    let bytes = plan.canonical_bytes().unwrap();
    fa_journal::object::stage(
        &ctx.query(),
        &mut rows,
        h.book.book_id,
        cvid,
        fa_model::symbols::label::CERTIFICATE,
        fa_journal::object::ObjectKind::BatchPlan,
        &bytes,
    )
    .unwrap();
    rows.create_vertex(
        cvid,
        vec![fa_model::symbols::label::CERTIFICATE],
        vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(
                    fa_journal::object::payload(fa_journal::object::ObjectKind::BatchPlan, &bytes)
                        .unwrap(),
                )
                .unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(digest.to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
            ),
        ],
    );
    for source in [alternate, ovid] {
        rows.add_edge(edge_id(relation::CITES, source, cvid), source, cvid, vec![]);
    }
    let mut membership = fgdb::WriteBatch::new(relation::IN_BATCH);
    membership.add_edge(
        edge_id(relation::IN_BATCH, alternate, ovid),
        alternate,
        ovid,
        vec![],
    );
    let mut txn = h.db.begin(&ctx.txn()).unwrap();
    txn.write_ordered(&mut h.db, vec![rows, membership])
        .unwrap();
    let written = h
        .runtime
        .block_on(txn.commit(&mut h.db, &ctx.commit()))
        .unwrap();
    assert_eq!(written.0, plan.certificate().snapshot_seq.0 + 1);
    let refusal = h.publish_batch_plan(plan, &capability).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-034", "{refusal}");
    assert!(h.db.vertex(expected.vid).unwrap().is_none());
    assert_eq!(h.db.frontier().unwrap(), written);
}

// ---------------------------------------------------------------------------
// Drafts (plan §15.2, bead fa-s7x)
// ---------------------------------------------------------------------------

const AGENT: VId = VId(31);
const APPROVER: VId = VId(70);

impl Harness {
    fn agent_capability(&self) -> Capability {
        fa_policy::Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Read, fa_policy::Op::Post],
            PRINCIPAL,
        )
        .expect("an agent may hold post")
    }

    fn approver_capability(&self) -> Capability {
        Capability::embedded(APPROVER, &["approve", "read"]).expect("approve")
    }

    fn draft_request(&self, capability: Capability) -> DraftRequest {
        DraftRequest {
            capability,
            effective_date: self.day(),
            description: self.statement("draft record", 9),
        }
    }

    fn agent_rent(&self, cents: i128, key: &[u8]) -> EntryPayload {
        let mut p = self.proposal(self.rent_legs(cents), key, EntryClass::ORIGINAL);
        p.principal_ref = AGENT;
        p
    }

    fn open_draft(&mut self, cap: Capability, name: &str) -> Result<DraftRecorded, Refusal> {
        let req = self.draft_request(cap);
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { open_draft(db, &ctx, book, name, req).await })
            .expect("draft kernel")
    }

    fn plan_draft(
        &mut self,
        cap: Capability,
        name: &str,
        proposal: EntryPayload,
    ) -> Result<DraftPlanned, Refusal> {
        let intent = fa_intents::PostIntent::new(proposal, Vec::new()).expect("typed intent");
        let req = self.draft_request(cap);
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { plan_into_draft(db, &ctx, book, name, intent, req).await })
            .expect("draft kernel")
    }

    fn promote(&mut self, cap: Capability, name: &str) -> Result<DraftPromoted, Refusal> {
        let req = self.draft_request(cap);
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { promote_draft(db, &ctx, book, name, req).await })
            .expect("draft kernel")
    }

    fn discard(&mut self, cap: Capability, name: &str) -> Result<DraftRecorded, Refusal> {
        let req = self.draft_request(cap);
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { discard_draft(db, &ctx, book, name, req).await })
            .expect("draft kernel")
    }

    fn draft(&self, name: &str) -> DraftView {
        read_draft(&self.db, &self.ctx().query(), &self.book, name)
            .expect("kernel")
            .expect("the draft exists")
    }
}

/// fa-s7x: an Agent opens a draft and plans two intents into it; each is
/// rehearsed under every posting law and journaled, and nothing reaches
/// trunk. The Agent cannot promote its own work; a Human holding `approve`
/// does, and both entries commit in one commit with the Agent as their
/// principal, exactly as the sealed intents state them. A retry is the
/// recorded promotion, and the promoted draft takes no further records.
#[test]
fn an_agent_drafts_and_a_human_promotes_the_intents_to_trunk_in_one_commit() {
    let mut h = harness();
    let agent = h.agent_capability();
    let opened = h
        .open_draft(agent.clone(), "close-03")
        .expect("an Agent opens its draft");
    assert!(!opened.already_recorded);
    let again = h
        .open_draft(agent.clone(), "close-03")
        .expect("the identical retry");
    assert!(again.already_recorded);
    assert_eq!(again.control_entry, opened.control_entry);

    let first = h.agent_rent(12_345, b"draft-rent-1");
    let second = h.agent_rent(500, b"draft-rent-2");
    let planned = h
        .plan_draft(agent.clone(), "close-03", first.clone())
        .expect("the first intent is rehearsed and journaled");
    let plan = planned.plan.expect("a fresh Plan carries its rehearsal");
    assert_eq!(plan.certificate().principal, AGENT);
    h.plan_draft(agent.clone(), "close-03", second.clone())
        .expect("the second intent");
    let retry = h
        .plan_draft(agent.clone(), "close-03", first.clone())
        .expect("the identical Plan is its recorded outcome");
    assert!(retry.recorded.already_recorded && retry.plan.is_none());
    let mut changed = first.clone();
    changed.legs = h.rent_legs(99);
    changed.unit_totals = EntryPayload::fold_unit_totals(&changed.legs).unwrap();
    let r = h
        .plan_draft(agent.clone(), "close-03", changed)
        .unwrap_err();
    assert_eq!(
        r.code, "FA-REF-032",
        "another intent under a planned key: {r}"
    );

    let first_ref = h.member_ref(&first);
    let second_ref = h.member_ref(&second);
    for r in [&first_ref, &second_ref] {
        assert!(
            read_entry(&h.db, r.vid).unwrap().is_none(),
            "a planned intent is not a trunk entry"
        );
    }
    let view = h.draft("close-03");
    eprintln!(
        "draft close-03: {:032x} state {} intents {}",
        view.vid.0,
        view.state.name(),
        view.intents.len()
    );
    assert_eq!(view.state, DraftState::Open);
    assert_eq!(view.body.owner, AGENT);
    assert_eq!(
        view.intents
            .iter()
            .map(|i| i.intent.proposal().idempotency_key.clone())
            .collect::<Vec<_>>(),
        vec![b"draft-rent-1".to_vec(), b"draft-rent-2".to_vec()],
        "planning order"
    );
    assert!(view.intents.iter().all(|i| i.capability == agent));

    // The Agent cannot promote (no `approve`), nor can its owner-Human.
    let r = h.promote(agent.clone(), "close-03").unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY), "{r}");
    let before = h.db.frontier().unwrap();
    let promoted = h
        .promote(h.approver_capability(), "close-03")
        .expect("a Human holding approve promotes");
    eprintln!(
        "promoted: outcome {:032x} at {} entries {:?}",
        promoted.outcome.0,
        promoted.recorded_at.0,
        promoted.entries.iter().map(|e| e.vid.0).collect::<Vec<_>>()
    );
    assert!(!promoted.already_recorded);
    assert_eq!(promoted.recorded_at.0, before.0 + 1, "one commit");
    assert_eq!(promoted.entries, vec![first_ref, second_ref]);
    assert_eq!(promoted.periods, vec![h.march.clone(), h.march.clone()]);
    for r in &promoted.entries {
        let (entry, at) = read_entry(&h.db, r.vid).unwrap().expect("promoted");
        assert_eq!(at, promoted.recorded_at);
        assert_eq!(
            entry.proposal.principal_ref, AGENT,
            "the planner stays the principal"
        );
    }
    let view = h.draft("close-03");
    assert_eq!(view.state, DraftState::Promoted);
    let closure = view.closed.expect("the Promote record");
    assert_eq!(closure.by, APPROVER);
    assert_eq!(
        closure.promoted,
        Some((promoted.outcome, promoted.entries.clone()))
    );

    let retry = h
        .promote(h.approver_capability(), "close-03")
        .expect("the recorded promotion");
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, promoted.entries);
    let r = h
        .plan_draft(agent.clone(), "close-03", h.agent_rent(1, b"late"))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-158", exit::REFUSAL), "{r}");
    let r = h.discard(agent, "close-03").unwrap_err();
    assert_eq!(r.code, "FA-REF-158", "{r}");
}

/// fa-s7x: the planted negatives. A refused intent never enters the draft;
/// only the owner plans into it; the owner never promotes it; an unknown
/// draft is FA-REF-157; a period closed after planning refuses the
/// promotion with the period law and leaves the draft open; a revoked
/// planner's capability refuses it with FA-REF-023; a discarded draft is
/// closed. Nothing of a refused promotion reaches trunk.
#[test]
fn draft_promotion_re_admits_every_intent_and_refuses_without_partial_effect() {
    let mut h = harness();
    let agent = h.agent_capability();
    h.open_draft(agent.clone(), "neg").expect("open");
    let basis = h.db.frontier().unwrap();
    let mut unbalanced = h.agent_rent(100, b"neg-unbalanced");
    unbalanced.legs[1] = LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 99));
    unbalanced.unit_totals = EntryPayload::fold_unit_totals(&unbalanced.legs).unwrap();
    let r = h.plan_draft(agent.clone(), "neg", unbalanced).unwrap_err();
    assert_eq!(r.exit, exit::REFUSAL, "{r}");
    assert_eq!(
        h.db.frontier().unwrap(),
        basis,
        "a refused intent is not journaled"
    );
    assert!(h.draft("neg").intents.is_empty());

    let human = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let r = h
        .plan_draft(
            human.clone(),
            "neg",
            h.proposal(h.rent_legs(10), b"neg-human", EntryClass::ORIGINAL),
        )
        .unwrap_err();
    assert_eq!(
        (r.code, r.exit),
        ("FA-REF-011", exit::SAFETY),
        "only the owner plans: {r}"
    );
    let r = h
        .plan_draft(agent.clone(), "nope", h.agent_rent(10, b"neg-nope"))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-157", exit::REFUSAL), "{r}");

    // A Human's own draft: holding approve does not let the owner promote it.
    let owner = Capability::embedded(APPROVER, &["post", "approve"]).unwrap();
    h.open_draft(owner.clone(), "mine")
        .expect("a Human opens a draft");
    let mut own = h.proposal(h.rent_legs(10), b"mine-1", EntryClass::ORIGINAL);
    own.principal_ref = APPROVER;
    h.plan_draft(owner.clone(), "mine", own).expect("planned");
    let r = h.promote(owner, "mine").unwrap_err();
    assert_eq!(
        (r.code, r.exit),
        ("FA-REF-008", exit::SAFETY),
        "self-promotion: {r}"
    );

    // Trunk moves after planning: March closes. The promotion re-admits
    // every intent against current trunk and refuses; the draft stays open.
    let planned = h.agent_rent(2_000, b"neg-march");
    let planned_ref = h.member_ref(&planned);
    h.plan_draft(agent.clone(), "neg", planned)
        .expect("planned while March is open");
    let march = h.march.clone();
    h.transition(&march, PeriodTransition::SoftClose, b"neg-sc")
        .expect("soft close");
    h.transition(&march, PeriodTransition::Close, b"neg-c")
        .expect("close");
    let before = h.db.frontier().unwrap();
    let r = h.promote(h.approver_capability(), "neg").unwrap_err();
    eprintln!("promotion after close: {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-010", exit::SAFETY), "{r}");
    assert!(r.message.contains("batch member 0"), "{r}");
    assert_eq!(h.db.frontier().unwrap(), before, "nothing was recorded");
    assert!(read_entry(&h.db, planned_ref.vid).unwrap().is_none());
    assert_eq!(h.draft("neg").state, DraftState::Open);

    // A revoked planner: its capability no longer admits the intent.
    h.open_draft(agent.clone(), "revoked").expect("open");
    let april = h.agent_rent(700, b"neg-revoked");
    let mut april = april;
    april.effective_date = DateDay::from_ymd(2026, 4, 2).unwrap();
    let april_code = h.april.clone();
    h.transition(&april_code, PeriodTransition::Open, b"neg-open-april")
        .expect("open April");
    h.plan_draft(agent.clone(), "revoked", april)
        .expect("planned");
    h.revoke(&agent, 31);
    let r = h.promote(h.approver_capability(), "revoked").unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-023", exit::SAFETY), "{r}");
    assert_eq!(h.draft("revoked").state, DraftState::Open);

    // Discard: the owner closes it; a closed draft never promotes.
    let r = h.discard(agent.clone(), "revoked").unwrap_err();
    assert_eq!(r.code, "FA-REF-023", "a revoked owner cannot discard: {r}");
    let discarder = Capability::embedded(APPROVER, &["post", "approve"]).unwrap();
    let discarded = h
        .discard(discarder.clone(), "neg")
        .expect("a reviewer discards");
    assert!(!discarded.already_recorded);
    assert!(h.discard(discarder, "neg").expect("retry").already_recorded);
    let r = h.promote(h.approver_capability(), "neg").unwrap_err();
    assert_eq!(r.code, "FA-REF-158", "{r}");
    let view = h.draft("neg");
    assert_eq!(view.state, DraftState::Discarded);
    assert_eq!(view.closed.expect("Discard record").by, APPROVER);
}

// Native mechanical YearEndClose (§7.5). These exercise the ordinary
// posting/plan/approval paths against real MemVfs transactions.
fn year_end_close_fixture() -> (Harness, VId) {
    let mut h = harness();
    let ctx = h.ctx();
    let cap = Capability::embedded(PRINCIPAL, &["schema_change", "read", "close"]).unwrap();
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    let spec = AccountSpec {
        code: "3000".into(),
        name: "Retained earnings".into(),
        account_type: fa_model::AccountType::EQUITY.0,
        normal_balance: 1,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    };
    let description = Erasable::seal(
        &"Year-end equity destination".to_string(),
        None,
        &h.book.seal_key,
        [51; 32],
        [52; 24],
    );
    let equity = h
        .runtime
        .block_on(open_account(
            &mut h.db,
            &ctx,
            &h.book,
            &spec,
            day,
            None,
            PRINCIPAL,
            day,
            b"year-close-equity",
            description,
            &cap,
        ))
        .unwrap()
        .unwrap()
        .account_vid;
    let routes = [(h.rent, equity), (h.revenue, equity)].into();
    year_end_close_routes(&mut h, routes, b"close-routes");
    h.transition("FY2026-CLOSE", PeriodTransition::Open, b"open-closing")
        .unwrap();
    let workpaper = h.document(21, HUMAN_UPLOAD, b"Reviewed fiscal-year closing workpaper");
    h.add_document(&workpaper).unwrap();
    h.evidence = vec![workpaper.evidence_ref(ROLE_SOURCE)];
    (h, equity)
}

fn year_end_close_routes(
    h: &mut Harness,
    routes: std::collections::BTreeMap<VId, VId>,
    key: &[u8],
) {
    let ctx = h.ctx();
    let request = fa_journal::chart::ClosingRoutesRequest {
        principal: PRINCIPAL,
        effective_from: DateDay::from_ymd(2026, 1, 1).unwrap(),
        routes,
        idempotency_key: key.to_vec(),
        description: Erasable::seal(
            &"Reviewed closing destinations".to_string(),
            None,
            &h.book.seal_key,
            [53; 32],
            [54; 24],
        ),
    };
    let cap = Capability::embedded(PRINCIPAL, &["schema_change", "read", "close"]).unwrap();
    h.runtime
        .block_on(fa_journal::chart::set_closing_routes(
            &mut h.db, &ctx, &h.book, &cap, request,
        ))
        .unwrap()
        .unwrap();
}

fn year_end_close_prepare(h: &Harness) -> fa_journal::closing::PreparedYearEndClose {
    let cap = Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap();
    fa_journal::closing::prepare_year_end_close(
        &h.db,
        &h.ctx(),
        &h.book,
        &cap,
        &fa_journal::closing::YearEndCloseRequest {
            fiscal_year: 2026,
            closing_period: "FY2026-CLOSE".into(),
        },
    )
    .unwrap()
    .unwrap()
}

fn year_end_close_proposal(
    h: &Harness,
    prepared: &fa_journal::closing::PreparedYearEndClose,
    key: &[u8],
) -> EntryPayload {
    let mut template = h.proposal(Vec::new(), key, EntryClass::CLOSING);
    template.effective_date = prepared.closing_date();
    template.effective_period = Some(fa_model::PeriodRef {
        calendar: h.book.calendar.id.clone(),
        code: prepared.request().closing_period.clone(),
    });
    prepared.proposal(template).unwrap()
}

fn year_end_close_verify(
    h: &Harness,
    at: Option<fgdb_types::CommitSeq>,
) -> fa_journal::closing::YearEndCloseVerification {
    let cap = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    fa_journal::closing::verify_year_end_close(&h.db, &h.ctx(), &h.book, &cap, 2026, at)
        .unwrap()
        .unwrap()
}

/// Independent debit-minus-credit fold over authoritative journal bytes.
fn year_end_close_net(h: &Harness, account: VId, at: fgdb_types::CommitSeq) -> i128 {
    let (start, end) = h.book.calendar.year_bounds(2026).unwrap();
    let mut net = 0_i128;
    for row in h.db.vertices_at(at).unwrap() {
        if !row.labels.contains(&fa_model::symbols::label::ENTRY) {
            continue;
        }
        let (entry, _) = fa_journal::post::read_entry_at(&h.db, row.vid, at)
            .unwrap()
            .unwrap();
        if entry.proposal.class == EntryClass::PENDING
            || entry.proposal.class.is_control()
            || entry.proposal.effective_date < start
            || entry.proposal.effective_date > end
        {
            continue;
        }
        for leg in &entry.proposal.legs {
            if leg.account_ref == account {
                net = match leg.side {
                    Side::Debit => net.checked_add(leg.amount.mantissa),
                    Side::Credit => net.checked_sub(leg.amount.mantissa),
                }
                .unwrap();
            }
        }
    }
    net
}

#[test]
fn year_end_close_first_delta_zero_and_historical_verification() {
    let (mut h, equity) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"year-income"), &["post"]))
        .unwrap();
    h.post(h.request(
        h.proposal(h.rent_legs(7_000), b"year-expense", EntryClass::ORIGINAL),
        &["post"],
    ))
    .unwrap();
    let before = h.db.frontier().unwrap();
    let prepared = year_end_close_prepare(&h);
    assert_eq!(h.db.frontier().unwrap(), before, "prepare is read-only");
    assert_eq!(prepared.legs().len(), 4);
    assert_eq!(
        prepared.closing_date(),
        DateDay::from_ymd(2026, 12, 31).unwrap()
    );
    let proposal = year_end_close_proposal(&h, &prepared, b"year-close-1");
    let cap = Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap();
    let plan = h
        .post_plan(h.request(proposal.clone(), &["read", "post", "close"]))
        .unwrap();
    assert_eq!(
        h.db.frontier().unwrap(),
        before,
        "planning publishes nothing"
    );
    let first = h.publish_plan(plan, &cap).unwrap();
    assert_eq!(
        first.recorded_at().0,
        before.0 + 1,
        "one native publication"
    );
    let first_at = first.recorded_at();
    assert_eq!(year_end_close_net(&h, h.rent, first_at), 0);
    assert_eq!(year_end_close_net(&h, h.revenue, first_at), 0);
    assert_eq!(year_end_close_net(&h, equity, first_at), -13_000);
    let retry = h
        .post(h.request(proposal, &["read", "post", "close"]))
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), first.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), first_at);
    let first_check = year_end_close_verify(&h, None);
    assert!(first_check.is_green());
    assert!(!first_check.needs_reclose);

    // Later backdated nominal activity leaves the historical close valid;
    // the next mechanical close transfers exactly the additional balance.
    h.post(h.request(h.invoice(3_000, b"late-income"), &["post"]))
        .unwrap();
    let historical = year_end_close_verify(&h, Some(first_at));
    assert!(historical.is_green());
    assert!(!historical.needs_reclose);
    let current = year_end_close_verify(&h, None);
    assert!(current.is_green());
    assert!(current.needs_reclose);
    let delta = year_end_close_prepare(&h);
    assert_eq!(delta.legs().len(), 2);
    assert!(
        delta
            .residuals()
            .iter()
            .any(|r| r.account == h.rent && r.net == 0)
    );
    assert!(
        delta
            .residuals()
            .iter()
            .any(|r| r.account == h.revenue && r.net == -3_000)
    );
    let second = h
        .post(h.request(
            year_end_close_proposal(&h, &delta, b"year-close-2"),
            &["read", "post", "close"],
        ))
        .unwrap();
    assert_eq!(year_end_close_net(&h, h.rent, second.recorded_at()), 0);
    assert_eq!(year_end_close_net(&h, h.revenue, second.recorded_at()), 0);
    assert_eq!(
        year_end_close_net(&h, equity, second.recorded_at()),
        -16_000
    );
    assert_eq!(year_end_close_net(&h, equity, first_at), -13_000);
    let head = h.db.frontier().unwrap();
    let noop = year_end_close_prepare(&h);
    assert!(noop.is_noop());
    assert!(noop.legs().is_empty());
    assert!(noop.residuals().iter().all(|r| r.net == 0));
    let empty = h.proposal(Vec::new(), b"zero-close", EntryClass::CLOSING);
    assert!(
        noop.proposal(empty).is_err(),
        "zero delta cannot become an empty entry"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(!year_end_close_verify(&h, None).needs_reclose);
}

#[test]
fn year_end_close_balanced_forgery_and_raw_closing_are_refused() {
    let (mut h, _) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"forgery-income"), &["post"]))
        .unwrap();
    h.post(h.request(
        h.proposal(h.rent_legs(7_000), b"forgery-expense", EntryClass::ORIGINAL),
        &["post"],
    ))
    .unwrap();
    let prepared = year_end_close_prepare(&h);
    let good = year_end_close_proposal(&h, &prepared, b"forged-close");
    let before = h.db.frontier().unwrap();
    let mut raw = good.clone();
    raw.extensions.clear();
    raw.schema_minor = 0;
    let refused = h
        .post(h.request(raw, &["read", "post", "close"]))
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-102");
    assert_eq!(h.db.frontier().unwrap(), before);

    // Removing a complete balanced account/destination pair still balances;
    // only full-source recomputation detects the omitted nominal account.
    let mut omitted = good.clone();
    omitted.legs.drain(0..2);
    omitted.unit_totals = EntryPayload::fold_unit_totals(&omitted.legs).unwrap();
    omitted.validate().unwrap();
    let refused = h
        .post(h.request(omitted, &["read", "post", "close"]))
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), before);
    h.post(h.request(good, &["read", "post", "close"])).unwrap();
}

#[test]
fn year_end_close_same_net_new_sources_invalidate_a_review() {
    let (mut h, _) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"basis-income"), &["post"]))
        .unwrap();
    let original = year_end_close_prepare(&h);
    let reviewed = year_end_close_proposal(&h, &original, b"reviewed-close");
    let extra = h
        .post(h.request(h.invoice(123, b"same-net-extra"), &["post"]))
        .unwrap();
    h.post(h.request(
        h.reversal_of_entry(extra.entry_ref(), b"same-net-reversal"),
        &["post"],
    ))
    .unwrap();
    let after = year_end_close_prepare(&h);
    assert_eq!(original.legs(), after.legs(), "the net money is unchanged");
    assert_ne!(
        original.source_digest(),
        after.source_digest(),
        "the source set changed"
    );
    let head = h.db.frontier().unwrap();
    let refused = h
        .post_plan(h.request(reviewed, &["read", "post", "close"]))
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn year_end_close_native_preparation_cannot_miss_an_appended_contribution() {
    let (mut h, _) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"race-income"), &["post"]))
        .unwrap();
    let calculation = year_end_close_prepare(&h);
    let proposal = year_end_close_proposal(&h, &calculation, b"race-close");
    let entry = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"race-close");
    let request = h.request(proposal, &["read", "post", "close"]);
    let ctx = h.ctx();
    let ready = match prepare_post(&mut h.db, &ctx, &h.book, request)
        .unwrap()
        .unwrap()
    {
        PostPreparation::Ready(ready) => ready,
        PostPreparation::AlreadyRecorded(_) => panic!("a new close must be fresh"),
    };
    h.post(h.request(h.invoice(99, b"racing-income"), &["post"]))
        .unwrap();
    let head = h.db.frontier().unwrap();
    let refused = h
        .runtime
        .block_on(ready.commit(&mut h.db, &ctx))
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(read_entry(&h.db, entry).unwrap().is_none());
    assert_eq!(year_end_close_net(&h, h.revenue, head), -20_099);
}

#[test]
fn aggregate_plan_invalidated_by_intervening_metadata_without_rebasing() {
    let (mut h, equity) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"aggregate-plan-income"), &["post"]))
        .unwrap();
    let calculation = year_end_close_prepare(&h);
    let proposal = year_end_close_proposal(&h, &calculation, b"aggregate-exact-prefix");
    let capability = Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap();
    let plan = h
        .post_plan(h.request(proposal.clone(), &["read", "post", "close"]))
        .unwrap();
    let basis = plan.certificate().snapshot_seq;
    let entry = entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        b"aggregate-exact-prefix",
    );

    // The same planted pure Certificate metadata as the point-only plan's
    // positive control. It changes no accounting source or point witness.
    let mut metadata = fgdb::WriteBatch::new(relation::IN_BOOK);
    metadata.create_vertex(
        VId(0xDEAD_BEEF_CAFE_0010),
        vec![fa_model::symbols::label::CERTIFICATE],
        vec![(
            property::FA_DIGEST,
            CanonicalScalar::bytes(vec![0xAC; 32]).unwrap(),
        )],
    );
    h.write_raw(metadata);
    let before = h.db.frontier().unwrap();
    assert_eq!(before.0, basis.0 + 1);
    let refusal = h.publish_plan(plan, &capability).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-034", exit::CONFLICT));
    assert!(refusal.message.contains(&basis.0.to_string()));
    assert!(refusal.message.contains(&before.0.to_string()));
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(read_entry(&h.db, entry).unwrap().is_none());
    assert_eq!(year_end_close_net(&h, h.revenue, before), -20_000);

    // A fresh committing basis can reuse the unchanged, fully revalidated
    // economic proposal. The stale artifact itself is never rebased.
    let fresh = h
        .post_plan(h.request(proposal, &["read", "post", "close"]))
        .unwrap();
    assert_eq!(fresh.certificate().snapshot_seq, before);
    let posted = h.publish_plan(fresh.clone(), &capability).unwrap();
    assert!(matches!(posted, Posted::Committed { .. }));
    assert_eq!(posted.recorded_at().0, before.0 + 1);
    assert_eq!(year_end_close_net(&h, h.revenue, posted.recorded_at()), 0);
    assert_eq!(
        year_end_close_net(&h, equity, posted.recorded_at()),
        -20_000
    );

    h.post(h.request(h.invoice(100, b"after-aggregate-plan"), &["post"]))
        .unwrap();
    let retry_head = h.db.frontier().unwrap();
    let retry = h.publish_plan(fresh, &capability).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.db.frontier().unwrap(), retry_head);
}

#[test]
fn year_end_close_closed_reclose_survives_review_then_exact_approval() {
    let (mut h, _) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"closed-income"), &["post"]))
        .unwrap();
    let initial = year_end_close_prepare(&h);
    h.post(h.request(
        year_end_close_proposal(&h, &initial, b"open-initial-close"),
        &["read", "post", "close"],
    ))
    .unwrap();
    h.transition(
        "FY2026-CLOSE",
        PeriodTransition::SoftClose,
        b"soft-close-closing",
    )
    .unwrap();
    h.transition("FY2026-CLOSE", PeriodTransition::Close, b"close-closing")
        .unwrap();
    h.post(h.request(h.invoice(777, b"closed-late-income"), &["post"]))
        .unwrap();
    let prepared = year_end_close_prepare(&h);
    let proposal = year_end_close_proposal(&h, &prepared, b"approved-reclose");
    let mut request = h.request(proposal, &["read", "post", "close", "post_closed"]);
    let before = h.db.frontier().unwrap();
    assert!(
        h.post_plan(request.clone()).is_err(),
        "Closed reclose requires an approval"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    let approval = h.approve_transition(request.proposal.proposal_digest().unwrap());
    request.approvals = vec![approval];
    assert!(h.db.frontier().unwrap() > prepared.known_at());
    let capability = request.capability.clone();
    let plan = h
        .post_plan(request)
        .expect("approval metadata preserves the reviewed source");
    h.publish_plan(plan, &capability).unwrap();
    let verified = year_end_close_verify(&h, None);
    assert!(verified.is_green());
    assert!(!verified.needs_reclose);
}

#[test]
fn year_end_close_requires_current_whole_book_authority_and_complete_routes() {
    let (mut h, equity) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"unrouted-income"), &["post"]))
        .unwrap();
    let request = fa_journal::closing::YearEndCloseRequest {
        fiscal_year: 2026,
        closing_period: "FY2026-CLOSE".into(),
    };
    let head = h.db.frontier().unwrap();
    for cap in [
        Capability::embedded(PRINCIPAL, &["post", "close"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read", "post", "close"])
            .unwrap()
            .for_periods(&["FY2026-CLOSE"])
            .unwrap(),
    ] {
        assert!(
            fa_journal::closing::prepare_year_end_close(&h.db, &h.ctx(), &h.book, &cap, &request,)
                .unwrap()
                .is_err()
        );
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    let routes = [(h.rent, equity)].into();
    year_end_close_routes(&mut h, routes, b"incomplete-close-routes");
    let head = h.db.frontier().unwrap();
    let cap = Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap();
    let refused =
        fa_journal::closing::prepare_year_end_close(&h.db, &h.ctx(), &h.book, &cap, &request)
            .unwrap()
            .unwrap_err();
    assert!(refused.message.contains("no reviewed closing destination"));
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn year_end_close_explicit_pin_observes_history_but_never_restores_revoked_authority() {
    let (mut h, _) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"pinned-close-income"), &["post"]))
        .unwrap();
    let calculation = year_end_close_prepare(&h);
    let first = h
        .post(h.request(
            year_end_close_proposal(&h, &calculation, b"pinned-close"),
            &["read", "post", "close"],
        ))
        .unwrap();
    let pin = first.recorded_at();
    let capability = Capability::embedded(PRINCIPAL, &["read"])
        .unwrap()
        .known_at_most(pin)
        .on_branch(Id128::TRUNK)
        .unwrap();
    let historical = fa_journal::closing::verify_year_end_close(
        &h.db,
        &h.ctx(),
        &h.book,
        &capability,
        2026,
        Some(pin),
    )
    .unwrap()
    .unwrap();
    assert_eq!(historical.known_at, pin);
    assert!(historical.is_green());
    assert!(!historical.needs_reclose);
    assert!(
        historical
            .residuals
            .iter()
            .all(|residual| residual.net == 0)
    );

    // An implicit HEAD read remains forbidden even while HEAD equals the
    // token's pin; selecting that same prefix explicitly is a separate act.
    assert_eq!(h.db.frontier().unwrap(), pin);
    let implicit = fa_journal::closing::verify_year_end_close(
        &h.db,
        &h.ctx(),
        &h.book,
        &capability,
        2026,
        None,
    )
    .unwrap()
    .unwrap_err();
    assert_eq!((implicit.code, implicit.exit), ("FA-REF-011", exit::SAFETY));
    assert!(implicit.message.contains("known_at"));

    h.post(h.request(h.invoice(777, b"after-pinned-close"), &["post"]))
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert!(head > pin);
    assert!(year_end_close_verify(&h, None).needs_reclose);
    let retained = fa_journal::closing::verify_year_end_close(
        &h.db,
        &h.ctx(),
        &h.book,
        &capability,
        2026,
        Some(pin),
    )
    .unwrap()
    .unwrap();
    assert_eq!(retained, historical, "later activity is outside the pin");
    for at in [Some(head), None] {
        let refusal = fa_journal::closing::verify_year_end_close(
            &h.db,
            &h.ctx(),
            &h.book,
            &capability,
            2026,
            at,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", exit::SAFETY));
        assert!(refusal.message.contains("known_at"));
    }
    assert_eq!(h.db.frontier().unwrap(), head, "verification never writes");

    // Revocation is checked at today's frontier, not at the selected
    // historical prefix, including before any later scope denial.
    h.revoke(&capability, 89);
    let revoked_at = h.db.frontier().unwrap();
    for at in [Some(pin), Some(head), None] {
        let refusal = fa_journal::closing::verify_year_end_close(
            &h.db,
            &h.ctx(),
            &h.book,
            &capability,
            2026,
            at,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", exit::SAFETY));
    }
    assert_eq!(h.db.frontier().unwrap(), revoked_at);
}

fn year_end_close_retire_rent(h: &mut Harness) {
    let ctx = h.ctx();
    let day = DateDay::from_ymd(2026, 6, 1).unwrap();
    let description = h.statement("Retire the zero-balance nominal account", 90);
    let capability = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let recorded = h
        .runtime
        .block_on(fa_journal::close_account(
            &mut h.db,
            &ctx,
            &h.book,
            "6000",
            day,
            PRINCIPAL,
            day,
            b"retire-year-close-rent",
            description,
            &capability,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(recorded.account_vid, h.rent);
}

#[test]
fn year_end_close_retired_zero_accounts_keep_source_and_lifecycle_dependencies() {
    let (mut h, equity) = year_end_close_fixture();
    let expense = h
        .post(h.request(
            h.proposal(h.rent_legs(500), b"retired-expense", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
    h.post(h.request(
        h.reversal_of_entry(expense.entry_ref(), b"retired-expense-reversal"),
        &["post"],
    ))
    .unwrap();
    h.post(h.request(h.invoice(13_000, b"retired-year-income"), &["post"]))
        .unwrap();
    let before_retirement = year_end_close_prepare(&h);
    let prior_review = year_end_close_proposal(&h, &before_retirement, b"pre-retirement-review");
    year_end_close_retire_rent(&mut h);
    let mapped = year_end_close_prepare(&h);
    assert_eq!(mapped.legs(), before_retirement.legs());
    assert_ne!(mapped.source_digest(), before_retirement.source_digest());
    assert!(
        mapped
            .residuals()
            .iter()
            .any(|row| row.account == h.rent && row.net == 0)
    );
    assert!(mapped.legs().iter().all(|leg| leg.account_ref != h.rent));
    let head = h.db.frontier().unwrap();
    let refusal = h
        .post_plan(h.request(prior_review, &["read", "post", "close"]))
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);

    // A revised complete map may omit the retired zero account. Its old
    // contributions still participate, and its lifecycle remains a dependency.
    let routes = [(h.revenue, equity)].into();
    year_end_close_routes(&mut h, routes, b"active-year-close-routes");
    let unmapped = year_end_close_prepare(&h);
    assert_eq!(unmapped.legs(), mapped.legs());
    assert_eq!(year_end_close_net(&h, h.rent, h.db.frontier().unwrap()), 0);
    let reviewed = year_end_close_proposal(&h, &unmapped, b"unrouted-zero-review");

    // Promotion is a native schema effect, not a test-only row mutation.
    // The nominal source stays zero and the map and monetary legs stay fixed.
    let ctx = h.ctx();
    let promoted_on = DateDay::from_ymd(2026, 4, 1).unwrap();
    let description = h.statement("Promote the retired zero account", 91);
    let capability = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    h.runtime
        .block_on(fa_journal::promote_to_summary(
            &mut h.db,
            &ctx,
            &h.book,
            "6000",
            promoted_on,
            PRINCIPAL,
            promoted_on,
            b"promote-retired-year-close-rent",
            description,
            &capability,
        ))
        .unwrap()
        .unwrap();
    let promoted = year_end_close_prepare(&h);
    assert_eq!(promoted.legs(), unmapped.legs());
    assert_eq!(promoted.routes_digest(), unmapped.routes_digest());
    assert_ne!(promoted.source_digest(), unmapped.source_digest());
    let head = h.db.frontier().unwrap();
    let refusal = h
        .post_plan(h.request(reviewed, &["read", "post", "close"]))
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);

    let posted = h
        .post(h.request(
            year_end_close_proposal(&h, &promoted, b"retired-zero-year-close"),
            &["read", "post", "close"],
        ))
        .unwrap();
    assert_eq!(year_end_close_net(&h, h.rent, posted.recorded_at()), 0);
    assert_eq!(year_end_close_net(&h, h.revenue, posted.recorded_at()), 0);
    assert_eq!(
        year_end_close_net(&h, equity, posted.recorded_at()),
        -13_000
    );
    let verified = year_end_close_verify(&h, None);
    assert!(verified.is_green());
    assert!(!verified.needs_reclose);
}

#[test]
fn year_end_close_refuses_nonzero_retired_accounts_with_or_without_a_route() {
    let (mut h, equity) = year_end_close_fixture();
    let expense = h
        .post(h.request(
            h.proposal(h.rent_legs(500), b"inactive-expense", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
    h.post(h.request(
        h.reversal_of_entry(expense.entry_ref(), b"inactive-expense-reversal"),
        &["post"],
    ))
    .unwrap();
    h.post(h.request(h.invoice(1_000, b"inactive-year-income"), &["post"]))
        .unwrap();
    year_end_close_retire_rent(&mut h);
    let zero = year_end_close_prepare(&h);
    let reviewed = year_end_close_proposal(&h, &zero, b"inactive-zero-review");

    // The late-recorded expense is still effective inside [opened, closed),
    // so the native posting law admits it. A December Closing leg is outside.
    h.post(h.request(
        h.proposal(
            h.rent_legs(1),
            b"late-retired-expense",
            EntryClass::ORIGINAL,
        ),
        &["post"],
    ))
    .unwrap();
    let request = fa_journal::closing::YearEndCloseRequest {
        fiscal_year: 2026,
        closing_period: "FY2026-CLOSE".into(),
    };
    let capability = Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap();
    for omit_route in [false, true] {
        if omit_route {
            let routes = [(h.revenue, equity)].into();
            year_end_close_routes(&mut h, routes, b"omit-nonzero-inactive-route");
        }
        let head = h.db.frontier().unwrap();
        let refusal = fa_journal::closing::prepare_year_end_close(
            &h.db,
            &h.ctx(),
            &h.book,
            &capability,
            &request,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-102", exit::REFUSAL));
        assert!(
            refusal
                .message
                .contains("nonzero fiscal-year balance at carrying value")
        );
        assert!(refusal.message.contains("6000"));
        assert!(
            h.post_plan(h.request(reviewed.clone(), &["read", "post", "close"]))
                .is_err()
        );
        assert_eq!(year_end_close_net(&h, h.rent, head), 1);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

/// fa-xvba (plan §8.2 `Reclassifies`): a Reclassification moves a positive
/// part of its target's legs to another account and cites the target; each
/// move is bounded by what the target's earlier live reclassifications left,
/// and a reversed reclassification gives its amount back. A move beyond what
/// remains, a move to no other account, a reversed target and a missing
/// reason are refused before anything is written.
#[test]
fn reclassification_partial_negation_balances() {
    let mut h = harness();
    let posted = h
        .post(h.request(
            h.proposal(h.rent_legs(1_000), b"rent", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("the original posts");
    let (target, _) = committed(&posted).expect("committed");
    let reclass = |h: &Harness, cents: i128, key: &[u8], from: VId, to: VId| {
        let legs = vec![
            LegPayload::simple(Side::Credit, from, Amount::new(h.usd, cents)),
            LegPayload::simple(Side::Debit, to, Amount::new(h.usd, cents)),
        ];
        let mut p = h.proposal(legs, key, EntryClass::RECLASSIFICATION);
        p.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reclassifies,
            reason_code: 1,
        }];
        p
    };
    let (rent, receivable) = (h.rent, h.receivable);

    // 300 of the rent leg's 1000 moves to receivable, citing the rent entry.
    let first = h
        .post(h.request(reclass(&h, 300, b"rc-300", rent, receivable), &["post"]))
        .expect("a partial move is admitted");
    let (first_ref, _) = committed(&first).expect("committed");
    let lineage = fa_journal::post::superseded_by(&h.db, &h.book, target.vid).unwrap();
    assert_eq!(lineage.len(), 1, "{lineage:?}");
    assert_eq!(lineage[0].kind, SupersessionKind::Reclassifies);
    assert_eq!(lineage[0].target.vid, first_ref.vid);

    // 800 more exceeds the 700 the first move left; nothing is written.
    let r = h
        .post(h.request(reclass(&h, 800, b"rc-800", rent, receivable), &["post"]))
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-185", exit::REFUSAL), "{r}");
    assert!(r.message.contains("exceeds"), "{r}");
    assert!(r.fix.contains("fa reclass"), "{r}");
    // Moving rent to rent moves it to no other account.
    let r = h
        .post(h.request(reclass(&h, 100, b"rc-self", rent, rent), &["post"]))
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-185", "{r}");
    // A reclassification names a registered reason.
    let mut unreasoned = reclass(&h, 100, b"rc-no-reason", rent, receivable);
    unreasoned.supersession[0].reason_code = 0;
    let r = h.post(h.request(unreasoned, &["post"])).unwrap_err();
    assert_eq!(r.code, "FA-REF-054", "{r}");

    // The remaining 700 moves; then nothing is left to move.
    h.post(h.request(reclass(&h, 700, b"rc-700", rent, receivable), &["post"]))
        .expect("what remains moves");
    let r = h
        .post(h.request(reclass(&h, 1, b"rc-1", rent, receivable), &["post"]))
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-185", "{r}");

    // Reversing the first reclassification gives its 300 back.
    let mut undo = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, rent, Amount::new(h.usd, 300)),
            LegPayload::simple(Side::Credit, receivable, Amount::new(h.usd, 300)),
        ],
        b"undo-rc-300",
        EntryClass::REVERSAL,
    );
    undo.supersession = vec![Supersession {
        target: first_ref,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    h.post(h.request(undo, &["post"]))
        .expect("a reclassification is reversible");
    h.post(h.request(reclass(&h, 300, b"rc-again", rent, receivable), &["post"]))
        .expect("the reversed move's amount is available again");

    // A reversed target leaves nothing to reclassify.
    let other = h
        .post(h.request(
            h.proposal(h.rent_legs(50), b"rent-2", EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("another original");
    let (other_ref, _) = committed(&other).expect("committed");
    h.post(h.request(h.reversal_of(other_ref, 50, b"rev-2"), &["post"]))
        .expect("reversed");
    let mut late = reclass(&h, 10, b"rc-reversed", rent, receivable);
    late.supersession[0].target = other_ref;
    let r = h.post(h.request(late, &["post"])).unwrap_err();
    assert_eq!(r.code, "FA-REF-185", "{r}");
    assert!(r.message.contains("reversed"), "{r}");
}
