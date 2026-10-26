use std::path::PathBuf;

use super::*;

pub(super) const OWNER: VId = VId(7);
pub(super) const AGENT: VId = VId(31);
pub(super) const APPROVER: VId = VId(70);
pub(super) const REVIEWER: VId = VId(93);

fn day() -> DateDay {
    DateDay::from_ymd(2026, 3, 15).unwrap()
}

pub(super) fn agent() -> Capability {
    Capability::new(AGENT, Profile::Agent, &[Op::Read, Op::Post], OWNER).unwrap()
}

pub(super) fn reader() -> Capability {
    Capability::embedded(REVIEWER, &["read"]).unwrap()
}

fn sealed(book: &BookContext, text: &str) -> Erasable<String> {
    Erasable::seal(&text.to_string(), None, &book.seal_key, [21; 32], [22; 24])
}

fn target_keys() -> DatabaseKeys {
    DatabaseKeys::new([131; 32], DatabaseSecurityNamespaceId([132; 32]), [133; 32])
}

pub(super) struct TargetStorage {
    vfs: MemVfs,
    path: PathBuf,
}

pub(super) struct Harness {
    runtime: Runtime,
    root: Cx,
    pub(super) db: Database<MemVfs>,
    pub(super) book: BookContext,
    pub(super) usd: UnitId,
    pub(super) cash: VId,
    rent: VId,
    pub(super) period: String,
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    pub(super) fn new(cash_limit: Option<BalanceLimit>) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &ctx.commit(),
                DatabaseKeys::new([121; 32], DatabaseSecurityNamespaceId([122; 32]), [123; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("draft-review", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: Id128([124; 16]),
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([125; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "Native draft rehearsal".into(),
            base_unit: usd,
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime
            .block_on(create_book(&mut db, &ctx, &spec, &units, &symbols))
            .unwrap();
        let schema = Capability::embedded(OWNER, &["schema_change"]).unwrap();
        let chart = [
            AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
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
        ];
        runtime
            .block_on(install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                OWNER,
                day(),
                b"chart",
                sealed(&book, "chart"),
                &schema,
            ))
            .unwrap()
            .unwrap();
        let (_, periods) = runtime
            .block_on(create_periods(
                &mut db,
                &ctx,
                &book,
                2026,
                OWNER,
                sealed(&book, "periods"),
                &schema,
            ))
            .unwrap()
            .unwrap();
        let period = periods
            .iter()
            .find(|period| period.kind == PeriodKind::Normal && period.contains(day()))
            .unwrap()
            .code
            .clone();
        let document = Document {
            book_id: book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: OWNER,
            bytes: b"Native draft rehearsal: retained source invoice".to_vec(),
        };
        runtime
            .block_on(add_document(&mut db, &ctx, &book, &document))
            .unwrap()
            .unwrap();
        let mut h = Self {
            runtime,
            root,
            db,
            cash: account_vid(book.book_id, "1000"),
            rent: account_vid(book.book_id, "6000"),
            book,
            usd,
            period,
            evidence: vec![document.evidence_ref(1)],
        };
        h.transition(PeriodTransition::Open, b"open");
        h
    }

    pub(super) fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    pub(super) fn head(&self) -> CommitSeq {
        self.db.frontier().unwrap()
    }

    pub(super) fn proposal(
        &self,
        amount: i128,
        key: &[u8],
        class: EntryClass,
        principal: VId,
    ) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, amount)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, amount)),
        ];
        let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: day(),
            document_date: None,
            description: sealed(&self.book, "draft member"),
            effective_period: None,
            legs,
            control: None,
            unit_totals,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([19; 32]),
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

    fn request(&self, capability: Capability) -> DraftRequest {
        DraftRequest {
            capability,
            effective_date: day(),
            description: sealed(&self.book, "draft control"),
        }
    }

    pub(super) fn open(&mut self, name: &str, capability: Capability) -> DraftRecorded {
        let request = self.request(capability);
        let ctx = self.ctx();
        self.runtime
            .block_on(open_draft(&mut self.db, &ctx, &self.book, name, request))
            .unwrap()
            .unwrap()
    }

    pub(super) fn plan(
        &mut self,
        name: &str,
        capability: Capability,
        intent: PostIntent,
    ) -> DraftPlanned {
        self.try_plan(name, capability, intent).unwrap()
    }

    pub(super) fn try_plan(
        &mut self,
        name: &str,
        capability: Capability,
        intent: PostIntent,
    ) -> Result<DraftPlanned, Refusal> {
        let request = self.request(capability);
        let ctx = self.ctx();
        self.runtime
            .block_on(plan_into_draft(
                &mut self.db,
                &ctx,
                &self.book,
                name,
                intent,
                request,
            ))
            .unwrap()
    }

    /// Write the authentic historical v1 Plan format, whose writer rehearsed
    /// only its new member. This fixture creates original immutable bytes;
    /// it never edits a journaled entry to manufacture an old version.
    pub(super) fn legacy_plan(
        &mut self,
        name: &str,
        capability: Capability,
        intent: PostIntent,
    ) -> DraftRecorded {
        let ctx = self.ctx();
        plan_post(
            &mut self.db,
            &ctx,
            &self.book,
            capability.clone(),
            intent.clone(),
        )
        .unwrap()
        .expect("the historical writer admitted this member individually");
        let view = self.draft(name);
        assert_eq!(view.state, DraftState::Open);
        assert_eq!(view.body.owner, capability.holder());
        let mut w = fa_model::Writer::new();
        w.u16(1)
            .bytes(&intent.canonical_bytes().unwrap())
            .bytes(&capability.canonical_bytes().unwrap());
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::DRAFT_CONTROL,
            effective_date: day(),
            document_date: None,
            description: sealed(&self.book, "draft control"),
            effective_period: None,
            legs: Vec::new(),
            control: Some(fa_model::ControlPayload::LifecycleTransition {
                object_ref: view.vid,
                from: 1,
                to: 1,
                proof_refs: Vec::new(),
                reason_code: 0,
            }),
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: fa_model::domain_digest(
                b"fa:draft-record-key:v1",
                &[
                    &[1],
                    &view.vid.0.to_le_bytes(),
                    &intent.proposal().idempotency_key,
                ],
            )
            .to_vec(),
            origin: EntryOrigin::Control {
                control_kind: fa_model::ControlKind::DRAFT_TRANSITION,
                spec_body_digest: view.body.digest().unwrap(),
            },
            principal_ref: capability.holder(),
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: vec![(fa_model::entry::DRAFT_INTENT_EXTENSION, w.finish().unwrap())],
            tags: Vec::new(),
        };
        let evid = entry_vid(
            self.book.book_id,
            &capability.holder().0.to_le_bytes(),
            &proposal.idempotency_key,
        );
        let entry = proposal.seal(Vec::new(), None).unwrap();
        let mut batch = WriteBatch::new(relation::IN_CASE);
        batch.create_vertex(
            evid,
            vec![label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        batch.add_edge(
            edge_id(relation::IN_CASE, evid, view.vid),
            evid,
            view.vid,
            Vec::new(),
        );
        self.write(batch);
        DraftRecorded {
            draft: view.vid,
            control_entry: evid,
            recorded_at: self.head(),
            already_recorded: false,
        }
    }

    pub(super) fn draft(&self, name: &str) -> DraftView {
        read_draft(&self.db, &self.ctx().query(), &self.book, name)
            .unwrap()
            .unwrap()
    }

    pub(super) fn approve(&mut self, proposal: &EntryPayload, principal: VId) -> ApprovalRef {
        let request = ApprovalRequest {
            capability: Capability::embedded(principal, &["approve"]).unwrap(),
            approved_proposal_digest: proposal.proposal_digest().unwrap(),
            role: 0,
        };
        let ctx = self.ctx();
        self.runtime
            .block_on(record_approval(&mut self.db, &ctx, &self.book, request))
            .unwrap()
            .unwrap()
            .approval()
    }

    pub(super) fn promote(&mut self, name: &str) -> DraftPromoted {
        self.try_promote(name).unwrap()
    }

    pub(super) fn try_promote(&mut self, name: &str) -> Result<DraftPromoted, Refusal> {
        let request = self.request(Capability::embedded(APPROVER, &["approve", "read"]).unwrap());
        let ctx = self.ctx();
        self.runtime
            .block_on(promote_draft(&mut self.db, &ctx, &self.book, name, request))
            .unwrap()
    }

    pub(super) fn transition(&mut self, transition: PeriodTransition, key: &[u8]) {
        let ctx = self.ctx();
        self.runtime
            .block_on(transition_period(
                &mut self.db,
                &ctx,
                &self.book,
                &self.period,
                transition,
                OWNER,
                1,
                key,
                sealed(&self.book, "period transition"),
                &Capability::embedded(OWNER, &["close"]).unwrap(),
                &[],
            ))
            .unwrap()
            .unwrap();
    }

    pub(super) fn post(&mut self, proposal: EntryPayload) -> EntryRef {
        let request = PostRequest {
            capability: Capability::embedded(proposal.principal_ref, &["post"]).unwrap(),
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
        };
        let ctx = self.ctx();
        self.runtime
            .block_on(post(&mut self.db, &ctx, &self.book, request))
            .unwrap()
            .unwrap()
            .entry_ref()
    }

    pub(super) fn revoke(&mut self, capability: &Capability, key: &[u8]) {
        let request = RevocationRequest {
            capability: Capability::embedded(OWNER, &["issue_capability"]).unwrap(),
            revoked: capability.commitment().unwrap(),
            effective_date: day(),
            idempotency_key: key.to_vec(),
            description: sealed(&self.book, "revoke capability"),
        };
        let ctx = self.ctx();
        self.runtime
            .block_on(revoke_capability(&mut self.db, &ctx, &self.book, request))
            .unwrap()
            .unwrap();
    }

    pub(super) fn write(&mut self, batch: WriteBatch) {
        let ctx = self.ctx();
        self.runtime
            .block_on(self.db.write(&ctx.commit(), batch))
            .unwrap();
    }

    pub(super) fn maintenance(&mut self, ordinal: u128) {
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(maintenance_vid(ordinal), vec![label::REGISTER], vec![]);
        self.write(batch);
    }

    pub(super) fn target(&self) -> (Database<MemVfs>, TargetStorage) {
        let ctx = self.ctx();
        let vfs = ctx.commit().with_restriction(MemVfs::new).unwrap();
        let path = vfs.database_dir();
        let db = self
            .runtime
            .block_on(Database::create_with_vfs(
                &ctx.commit(),
                vfs.clone(),
                &path,
                target_keys(),
            ))
            .unwrap();
        (db, TargetStorage { vfs, path })
    }

    pub(super) fn reopen(&self, storage: &TargetStorage) -> Database<MemVfs> {
        let ctx = self.ctx();
        self.runtime
            .block_on(Database::open_with_vfs(
                &ctx.commit(),
                storage.vfs.clone(),
                &storage.path,
                target_keys(),
            ))
            .unwrap()
    }

    pub(super) fn rehearse(
        &mut self,
        target: Database<MemVfs>,
        reviewer: &Capability,
        name: &str,
        known_at: CommitSeq,
    ) -> Outcome<(Database<MemVfs>, DraftRehearsal)> {
        let ctx = self.ctx();
        self.runtime.block_on(rehearse_draft_into(
            &mut self.db,
            target,
            &ctx,
            &self.book,
            reviewer,
            DraftRehearsalRequest {
                name: name.into(),
                known_at,
            },
        ))
    }
}

pub(super) fn maintenance_vid(ordinal: u128) -> VId {
    VId(0x6472_6166_742d_6d61_696e_7465_6e61_0000 + ordinal)
}

pub(super) fn member_ref(intent: &PostIntent) -> EntryRef {
    let proposal = intent.proposal();
    let sealed = proposal
        .clone()
        .seal(intent.approvals().to_vec(), None)
        .unwrap();
    EntryRef {
        vid: entry_vid(
            proposal.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        ),
        entry_digest: sealed.entry_digest,
    }
}

pub(super) fn recorded_ref(db: &Database<MemVfs>, vid: VId) -> EntryRef {
    let (entry, _) = read_entry(db, vid).unwrap().unwrap();
    EntryRef {
        vid,
        entry_digest: entry.entry_digest,
    }
}

pub(super) fn cash_balance(db: &Database<MemVfs>, cash: VId) -> i128 {
    db.vertices()
        .unwrap()
        .into_iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .map(|row| {
            let (entry, _) = read_entry(db, row.vid).unwrap().unwrap();
            if entry.proposal.class == EntryClass::PENDING {
                return 0;
            }
            entry
                .proposal
                .legs
                .iter()
                .filter(|leg| leg.account_ref == cash)
                .map(|leg| match leg.side {
                    Side::Debit => leg.amount.mantissa,
                    Side::Credit => -leg.amount.mantissa,
                })
                .sum::<i128>()
        })
        .sum()
}

pub(super) fn lawful_refusal<T>(outcome: Outcome<T>) -> Refusal {
    match outcome {
        Ok(Err(refusal)) => refusal,
        Ok(Ok(_)) => panic!("expected lawful refusal, operation succeeded"),
        Err(error) => panic!("expected lawful refusal, got foundation failure: {error}"),
    }
}
