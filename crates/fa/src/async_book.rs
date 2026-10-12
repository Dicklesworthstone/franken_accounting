//! A book executed by its caller's runtime and filesystem.
//!
//! This is the shared implementation for the embedded async API and the
//! synchronous production adapter. It owns no runtime or root context.
//! Ordinary books use clones of the same supplied VFS for database and
//! document bytes. Scratch books retain their source's blob store, so a
//! caller can keep both stores on the same lab-controlled I/O plane.

use core::fmt;
use std::path::{Path, PathBuf};

use asupersync::fs::{Vfs, VfsFile};
use fa_journal::blob::DurableDirectory;
use fa_journal::rows::{AccountRow, PeriodRow};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, KernelError, PostRequest, Posted,
    Transitioned,
};
use fa_model::{Entry, Erasable, SealKey, SymbolTable};
use fa_registers::{
    AvailabilityVerification, BalanceExplanation, Fold, OpenItem, OpenItemVerification,
    TrialBalance, Verification,
};
use fa_time::{DateDay, PeriodDef, PeriodTransition};
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::book::{BookError, BookKeys, Entropy, Outcome};

pub(crate) const BOOK_BLOB_STORE: u16 = 1;

fn seal(
    cx: &PurposeContexts,
    entropy: &Entropy,
    key: &SealKey,
    text: &str,
) -> Result<Erasable<String>, KernelError> {
    cx.commit()
        .checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)?;
    let mut salt = [0; 32];
    let mut nonce = [0; 24];
    entropy.fill(&mut salt)?;
    entropy.fill(&mut nonce)?;
    Ok(Erasable::seal(&text.to_string(), None, key, salt, nonce))
}

fn sweep_request(
    capability: &fa_journal::Capability,
    max_batch: usize,
) -> fa_journal::SweepRequest {
    fa_journal::SweepRequest {
        principal_ref: capability.holder(),
        capability: capability.clone(),
        max_batch,
    }
}

/// One book over caller-supplied filesystems. Ordinary constructors use
/// clones of the same VFS for both stores. The separate blob type permits
/// an in-memory scratch journal to retain its source's external evidence.
/// Each operation preserves the caller's cancellation and budget.
pub struct AsyncBook<V: Vfs + Clone, B: Vfs + Clone = V> {
    pub(crate) db: Database<V>,
    blobs: fa_journal::BlobStore<B>,
    context: BookContext,
    entropy: Entropy,
}

impl<V: Vfs + Clone> AsyncBook<V> {
    /// Create `<dir>/store` and use `<dir>/blobs` for external documents.
    /// The caller supplies the runtime, filesystem, keys and entropy.
    /// Confined filesystems use a namespace-relative `dir`. The resulting
    /// stores retain canonical paths independently of later cwd changes.
    pub async fn create_with_vfs(
        cx: &PurposeContexts,
        vfs: V,
        dir: &Path,
        keys: BookKeys,
        spec: BookSpec,
        entropy: Entropy,
    ) -> Result<Self, BookError> {
        let dir = rooted_path(dir);
        let commit = cx.commit();
        commit.checkpoint().map_err(BookError::Context)?;
        let directory = DurableDirectory::create(&commit, vfs.clone(), &dir)
            .await
            .map_err(|e| BookError::Io(dir.clone(), e))?;
        // Chronicle's process-local writer lease uses a host path. Resolve
        // through the supplied VFS so a memory filesystem's private shadow
        // namespace and the lease identify the same database directory.
        let database_dir = directory.path().join("store");
        let blob_directory = directory
            .child(&commit, "blobs")
            .await
            .map_err(|e| BookError::Io(directory.path().join("blobs"), e))?;
        let mut db =
            Database::create_with_vfs(&commit, vfs.clone(), database_dir, keys.inner.clone())
                .await?;
        let units = fa_money::UnitRegistry::embedded()?;
        let symbols = SymbolTable::compiled();
        fa_journal::create_book(&mut db, cx, &spec, &units, &symbols).await?;
        Ok(Self {
            db,
            blobs: fa_journal::BlobStore::open(BOOK_BLOB_STORE, blob_directory)?,
            context: BookContext {
                book_id: spec.book_id,
                calendar: spec.calendar,
                units,
                seal_key: keys.seal_key(),
                symbols,
            },
            entropy,
        })
    }

    /// Reopen the same book through the supplied filesystem, including its
    /// external documents. This does not construct a production runtime.
    /// Confined filesystems use the same namespace-relative `dir` as create.
    pub async fn open_with_vfs(
        cx: &PurposeContexts,
        vfs: V,
        dir: &Path,
        keys: BookKeys,
        entropy: Entropy,
    ) -> Result<Self, BookError> {
        let dir = rooted_path(dir);
        let commit = cx.commit();
        commit.checkpoint().map_err(BookError::Context)?;
        let directory = DurableDirectory::open_existing(&commit, vfs.clone(), &dir)
            .await
            .map_err(|e| BookError::Io(dir.clone(), e))?;
        let database_dir = directory.path().join("store");
        let db =
            Database::open_with_vfs(&commit, vfs.clone(), database_dir, keys.inner.clone()).await?;
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        let spec = query
            .with_restriction(|| fa_journal::genesis::read_book_spec(&db))?
            .ok_or(BookError::NoBook)?;
        let supported_units = fa_money::UnitRegistry::embedded()?;
        let units = query.with_restriction(|| {
            fa_journal::genesis::read_units(&db, spec.book_id, &supported_units)
        })?;
        if units.get(spec.base_unit).is_none() {
            return Err(KernelError::Corrupt(format!(
                "book.base_unit {} is absent from its journaled unit table",
                spec.base_unit.0
            ))
            .into());
        }
        let blob_directory = directory
            .child(&commit, "blobs")
            .await
            .map_err(|e| BookError::Io(directory.path().join("blobs"), e))?;
        Ok(Self {
            db,
            blobs: fa_journal::BlobStore::open(BOOK_BLOB_STORE, blob_directory)?,
            context: BookContext {
                book_id: spec.book_id,
                calendar: spec.calendar,
                units,
                seal_key: keys.seal_key(),
                symbols: SymbolTable::compiled(),
            },
            entropy,
        })
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    #[must_use]
    pub fn context(&self) -> &BookContext {
        &self.context
    }

    fn query<T>(
        &self,
        cx: &PurposeContexts,
        read: impl FnOnce(&Database<V>, &BookContext) -> Result<T, BookError>,
    ) -> Result<T, BookError> {
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| read(&self.db, &self.context))
    }

    /// The current committed frontier under the caller's read context.
    pub fn head(&self, cx: &PurposeContexts) -> Result<CommitSeq, BookError> {
        self.query(cx, |db, _| Ok(db.frontier().map_err(KernelError::from)?))
    }

    /// Seal text using this book's explicitly supplied entropy capability.
    pub fn seal_text(
        &self,
        cx: &PurposeContexts,
        text: &str,
    ) -> Result<Erasable<String>, BookError> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(seal(cx, &self.entropy, &self.context.seal_key, text)?)
    }

    pub async fn install_chart(
        &mut self,
        cx: &PurposeContexts,
        accounts: &[AccountSpec],
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<ChartInstalled> {
        let description =
            self.seal_text(cx, &format!("chart install: {} accounts", accounts.len()))?;
        Ok(fa_journal::install_chart(
            &mut self.db,
            cx,
            &self.context,
            accounts,
            principal,
            effective_date,
            idempotency_key,
            description,
        )
        .await?)
    }

    pub async fn create_periods(
        &mut self,
        cx: &PurposeContexts,
        fiscal_year: i32,
    ) -> Result<(CommitSeq, Vec<PeriodDef>), BookError> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::create_periods(&mut self.db, cx, &self.context, fiscal_year).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn transition_period(
        &mut self,
        cx: &PurposeContexts,
        period_code: &str,
        t: PeriodTransition,
        principal: VId,
        reason_code: u16,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<Transitioned> {
        let description = self.seal_text(cx, &format!("period {period_code}: {t:?}"))?;
        Ok(fa_journal::transition_period(
            &mut self.db,
            cx,
            &self.context,
            period_code,
            t,
            principal,
            reason_code,
            effective_date,
            idempotency_key,
            description,
            capability,
            &[],
        )
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_transition(
        &self,
        cx: &PurposeContexts,
        period_code: &str,
        t: PeriodTransition,
        principal: VId,
        reason_code: u16,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<fa_journal::TransitionPlan> {
        let description = self.seal_text(cx, &format!("period {period_code}: {t:?}"))?;
        self.query(cx, |db, book| {
            Ok(fa_journal::plan_transition(
                db,
                book,
                period_code,
                t,
                principal,
                reason_code,
                effective_date,
                idempotency_key,
                description,
            )?)
        })
    }

    pub fn plan_digest(&self, plan: &fa_journal::TransitionPlan) -> Result<[u8; 32], BookError> {
        Ok(plan.proposal_digest(&self.context)?)
    }

    pub async fn transition_planned(
        &mut self,
        cx: &PurposeContexts,
        plan: &fa_journal::TransitionPlan,
        t: PeriodTransition,
        capability: &fa_journal::Capability,
        approvals: &[fa_model::ApprovalRef],
    ) -> Outcome<Transitioned> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::transition_period(
            &mut self.db,
            cx,
            &self.context,
            &plan.period_code,
            t,
            plan.principal_ref,
            plan.reason_code,
            plan.effective_date,
            &plan.idempotency_key,
            plan.description.clone(),
            capability,
            approvals,
        )
        .await?)
    }

    pub async fn approve(
        &mut self,
        cx: &PurposeContexts,
        capability: fa_journal::Capability,
        proposal_digest: [u8; 32],
    ) -> Outcome<fa_journal::Approved> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::record_approval(
            &mut self.db,
            cx,
            &self.context,
            fa_journal::ApprovalRequest {
                capability,
                approved_proposal_digest: proposal_digest,
                role: 0,
            },
        )
        .await?)
    }

    pub async fn post(&mut self, cx: &PurposeContexts, req: PostRequest) -> Outcome<Posted> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::post(&mut self.db, cx, &self.context, req).await?)
    }

    /// Run the real posting preparation under the caller's transaction
    /// context, then abort it. No runtime or authority is created here.
    pub fn plan(
        &mut self,
        cx: &PurposeContexts,
        intent: fa_intents::PostIntent,
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_intents::PostPlan> {
        cx.txn().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::plan_post(
            &mut self.db,
            cx,
            &self.context,
            capability.clone(),
            intent,
        )?)
    }

    /// Revalidate and atomically publish a portable plan with its retained
    /// graph certificate. Authority is supplied by this caller, never taken
    /// from the artifact, and all I/O retains the caller's purpose contexts.
    pub async fn commit_plan(
        &mut self,
        cx: &PurposeContexts,
        plan: fa_intents::PostPlan,
        capability: &fa_journal::Capability,
    ) -> Outcome<Posted> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(
            fa_journal::commit_plan(&mut self.db, cx, &self.context, capability.clone(), plan)
                .await?,
        )
    }

    pub async fn post_balancing(
        &mut self,
        cx: &PurposeContexts,
        req: PostRequest,
        leg: u16,
    ) -> Outcome<fa_journal::Balanced> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::post_balancing(&mut self.db, cx, &self.context, req, leg).await?)
    }

    /// Holds due at the latest committed tick, still reserved until a
    /// resolution commits (plan §5.4).
    pub fn due_holds(&self, cx: &PurposeContexts) -> Result<Vec<fa_journal::DueHold>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::due_holds(db, None)?))
    }

    /// Live scheduled reversals and their `Due`, `Waiting`, or `Blocked`
    /// status under the latest committed tick (plan §7.6).
    pub fn due_reversals(
        &self,
        cx: &PurposeContexts,
    ) -> Result<Vec<fa_journal::DueReversal>, BookError> {
        self.query(cx, |db, book| Ok(fa_journal::due_reversals(db, book)?))
    }

    /// The book's latest committed TimeEvidence tick, if any (plan §7.1a).
    pub fn latest_tick(&self, cx: &PurposeContexts) -> Result<Option<fa_journal::Tick>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::latest_tick(db)?))
    }

    /// Journal the caller's daemon-clock observation as TimeEvidence.
    /// The capability's holder is the principal; the kernel enforces the
    /// `witness` authority and monotonicity law. This adapter reads no clock.
    /// Repeating the same observation returns its recorded outcome.
    pub async fn record_tick(
        &mut self,
        cx: &PurposeContexts,
        observed_utc_ns: u64,
        monotonic_ok: bool,
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::Ticked> {
        let description = self.seal_text(
            cx,
            &format!(
                "time evidence: the daemon clock observed {observed_utc_ns} ns (monotonic_ok {monotonic_ok})"
            ),
        )?;
        let req = fa_journal::TickRequest {
            observed_utc_ns,
            source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
            monotonic_ok,
            principal_ref: capability.holder(),
            capability: capability.clone(),
            idempotency_key: format!("tick:{observed_utc_ns}").into_bytes(),
            description,
        };
        Ok(fa_journal::record_tick(&mut self.db, cx, &self.context, req).await?)
    }

    /// Expire at most `max_batch` due holds in one transaction as the
    /// capability's System principal (plan §5.4). `Ok(Ok(None))` means no
    /// tick or nothing due. A sealing failure aborts the transaction.
    pub async fn sweep_expiry(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        max_batch: usize,
    ) -> Outcome<Option<fa_journal::SweepBatch>> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let req = sweep_request(capability, max_batch);
        let book = &self.context;
        let entropy = &self.entropy;
        let mut describe = |text: &str| seal(cx, entropy, &book.seal_key, text);
        Ok(fa_journal::sweep_batch(&mut self.db, cx, book, &req, &mut describe).await?)
    }

    /// Examine at most `max_batch` reached schedules in one transaction,
    /// minting admissible reversals and reporting blocked ones (plan §7.6).
    /// The kernel requires the System capability; `Ok(Ok(None))` means
    /// nothing reached. A sealing failure aborts the transaction.
    pub async fn sweep_reversals(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        max_batch: usize,
    ) -> Outcome<Option<fa_journal::ReversalBatch>> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let req = sweep_request(capability, max_batch);
        let book = &self.context;
        let entropy = &self.entropy;
        let mut describe = |text: &str| seal(cx, entropy, &book.seal_key, text);
        Ok(fa_journal::sweep_reversals_batch(&mut self.db, cx, book, &req, &mut describe).await?)
    }

    /// Sweep expiry batches, then scheduled-reversal batches, until nothing
    /// remains under the latest tick. Each transaction is bounded by
    /// `max_batch`. A refusal or failure stops the sweep; earlier committed
    /// batches remain journaled.
    pub async fn sweep(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        max_batch: usize,
    ) -> Outcome<fa_journal::Swept> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let req = sweep_request(capability, max_batch);
        let book = &self.context;
        let entropy = &self.entropy;
        let mut describe = |text: &str| seal(cx, entropy, &book.seal_key, text);
        Ok(fa_journal::sweep(&mut self.db, cx, book, &req, &mut describe).await?)
    }

    pub async fn open_migration_run(
        &mut self,
        cx: &PurposeContexts,
        body: &fa_journal::RunBody,
        req: fa_journal::RunControlRequest,
    ) -> Outcome<fa_journal::RunControlled> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::open_run(&mut self.db, cx, &self.context, body, req).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_migration_transition(
        &self,
        cx: &PurposeContexts,
        run: VId,
        control_kind: u8,
        principal: VId,
        idempotency_key: &[u8],
        description: Erasable<String>,
    ) -> Outcome<fa_model::EntryPayload> {
        self.query(cx, |db, book| {
            Ok(fa_journal::plan_run_transition(
                db,
                book,
                run,
                control_kind,
                principal,
                idempotency_key,
                description,
            )?)
        })
    }

    pub async fn transition_migration_run(
        &mut self,
        cx: &PurposeContexts,
        req: fa_journal::RunControlRequest,
    ) -> Outcome<fa_journal::RunControlled> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::transition_run(&mut self.db, cx, &self.context, req).await?)
    }

    pub fn migration_run(
        &self,
        cx: &PurposeContexts,
        run: VId,
        known_at: Option<CommitSeq>,
    ) -> Result<Option<fa_journal::Run>, BookError> {
        self.query(cx, |db, _| {
            Ok(fa_journal::migration::read_run(db, run, known_at)?)
        })
    }

    /// Replay the accounting prefix into a caller-created, empty database.
    /// Execution stays on the caller's runtime and context. The scratch
    /// book shares the source's immutable blob store, so its external
    /// documents remain readable while that store is available. Its sealed
    /// fields retain the source book's key; target database keys encrypt
    /// only the new substrate storage.
    pub async fn replay_into<W: Vfs + Clone>(
        &mut self,
        cx: &PurposeContexts,
        mut target: Database<W>,
        prefix: Option<CommitSeq>,
        entropy: Entropy,
    ) -> Outcome<(AsyncBook<W, B>, fa_journal::SeqMap)> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let map = match fa_journal::scratch::replay_into(
            &mut self.db,
            &mut target,
            cx,
            self.context.book_id,
            prefix,
        )
        .await?
        {
            Ok(map) => map,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok((
            AsyncBook {
                db: target,
                blobs: self.blobs.clone(),
                context: self.context.clone(),
                entropy,
            },
            map,
        )))
    }

    /// Independently verify a replay's mapped accounting history.
    pub fn verify_replay<W: Vfs + Clone, C: Vfs + Clone>(
        &self,
        cx: &PurposeContexts,
        scratch: &AsyncBook<W, C>,
        map: &fa_journal::SeqMap,
    ) -> Outcome<fa_registers::replay::ReplayVerification> {
        self.query(cx, |source, book| {
            Ok(fa_registers::replay::verify_replay(
                source,
                &scratch.db,
                book,
                map,
            )?)
        })
    }

    pub async fn add_document(
        &mut self,
        cx: &PurposeContexts,
        doc: &fa_journal::Document,
    ) -> Outcome<fa_journal::DocumentAdded> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let inline_bound =
            fa_registry::evidence_policy::EvidencePolicy::embedded()?.max_document_bytes;
        Ok(
            if u64::try_from(doc.bytes.len()).unwrap_or(u64::MAX) > inline_bound {
                fa_journal::add_document_external(&mut self.db, cx, &self.context, &self.blobs, doc)
                    .await?
            } else {
                fa_journal::add_document(&mut self.db, cx, &self.context, doc).await?
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn import_run(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        source: fa_model::IntakeSource,
        idempotency_key: &[u8],
        effective_date: DateDay,
        description: &str,
        documents: Vec<fa_journal::Document>,
    ) -> Outcome<fa_journal::ImportRecorded> {
        let req = fa_journal::ImportRequest {
            principal: capability.holder(),
            source,
            idempotency_key: idempotency_key.to_vec(),
            effective_date,
            description: self.seal_text(cx, description)?,
            documents,
        };
        Ok(fa_journal::import_run(&mut self.db, cx, &self.context, capability, req).await?)
    }

    pub fn read_run(
        &self,
        cx: &PurposeContexts,
        run: VId,
    ) -> Result<Option<fa_journal::RunReceipt>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::import::read_run(db, run)?))
    }

    pub async fn transfer_custody(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        document: &fa_model::Oid,
        to: VId,
    ) -> Outcome<fa_journal::CustodyMoved> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::transfer_custody(
            &mut self.db,
            cx,
            &self.context,
            capability,
            *document,
            capability.holder(),
            to,
        )
        .await?)
    }

    pub fn custody_chain(
        &self,
        cx: &PurposeContexts,
        document: &fa_model::Oid,
    ) -> Result<Vec<(fa_journal::CustodyEvent, CommitSeq)>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::custody_chain(db, document)?))
    }

    /// Place a legal hold under the caller's commit context and authority.
    #[allow(clippy::too_many_arguments)]
    pub async fn place_legal_hold(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        subjects: Vec<VId>,
        authority: &fa_model::Oid,
        idempotency_key: &[u8],
        effective_date: DateDay,
        description: &str,
    ) -> Outcome<fa_journal::LegalHoldPlaced> {
        let description = self.seal_text(cx, description)?;
        let request = fa_journal::LegalHoldRequest {
            principal: capability.holder(),
            subjects,
            authority: *authority,
            effective_date,
            idempotency_key: idempotency_key.to_vec(),
            description,
        };
        Ok(
            fa_journal::place_legal_hold(&mut self.db, cx, &self.context, capability, request)
                .await?,
        )
    }

    /// Plan a release without committing; approvals bind the returned plan.
    pub fn plan_legal_hold_release(
        &self,
        cx: &PurposeContexts,
        hold: VId,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<fa_journal::ReleasePlan> {
        let description = self.seal_text(cx, &format!("release of legal hold {:032x}", hold.0))?;
        self.query(cx, |db, book| {
            Ok(fa_journal::plan_release(
                db,
                book,
                hold,
                principal,
                effective_date,
                idempotency_key,
                description,
            )?)
        })
    }

    /// Compute the approval digest without observing storage.
    pub fn legal_hold_release_digest(
        &self,
        plan: &fa_journal::ReleasePlan,
    ) -> Result<[u8; 32], BookError> {
        Ok(plan.proposal_digest(&self.context)?)
    }

    /// Commit exactly the approved release under the caller's context.
    pub async fn release_legal_hold(
        &mut self,
        cx: &PurposeContexts,
        plan: &fa_journal::ReleasePlan,
        capability: &fa_journal::Capability,
        approvals: &[fa_model::ApprovalRef],
    ) -> Outcome<fa_journal::LegalHoldReleased> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::release_legal_hold(
            &mut self.db,
            cx,
            &self.context,
            capability,
            plan,
            approvals,
        )
        .await?)
    }

    pub fn legal_hold(
        &self,
        cx: &PurposeContexts,
        hold: VId,
    ) -> Result<Option<fa_journal::LegalHold>, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::read_legal_hold(db, book.book_id, hold)?)
        })
    }

    pub fn legal_holds_on(
        &self,
        cx: &PurposeContexts,
        subject: VId,
    ) -> Result<Vec<VId>, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::active_legal_holds(db, book.book_id, subject)?)
        })
    }

    /// Journal the authorized view using the caller's filesystem and context.
    pub async fn derive_redacted_view(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        oid: &fa_model::Oid,
    ) -> Outcome<fa_journal::ViewDerived> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::derive_redacted_view(
            &mut self.db,
            cx,
            &self.context,
            capability,
            &self.blobs,
            *oid,
        )
        .await?)
    }

    /// Read verified full or redacted evidence after capability admission.
    /// Document bytes have no ungated facade method (FA-INV-10, plan §9.6).
    ///
    /// ```
    /// let _ = fa::AsyncBook::<fgdb::MemVfs>::read_document_for;
    /// ```
    ///
    /// ```compile_fail,E0599
    /// let _ = fa::AsyncBook::<fgdb::MemVfs>::read_document;
    /// ```
    pub async fn read_document_for(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        oid: &fa_model::Oid,
    ) -> Outcome<fa_journal::DocumentRead> {
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        Ok(query
            .with_restriction_async(fa_journal::read_document_for(
                &mut self.db,
                cx,
                &self.context,
                capability,
                &self.blobs,
                *oid,
            ))
            .await?)
    }

    /// The public commitment mirror, bound to this book and document oid.
    /// Only public label/identity/digest fields are observed; inline bytes
    /// are neither read nor decoded. This does not verify the byte payload.
    ///
    /// ```
    /// let _ = fa::AsyncBook::<fgdb::MemVfs>::document_commitment;
    /// ```
    ///
    /// ```compile_fail,E0599
    /// let _ = fa::AsyncBook::<fgdb::MemVfs>::document_record;
    /// ```
    pub fn document_commitment(
        &mut self,
        cx: &PurposeContexts,
        oid: &fa_model::Oid,
    ) -> Result<Option<[u8; 32]>, BookError> {
        use fa_model::symbols::{label, property};
        use fgdb_types::CanonicalScalar;

        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            let db = &mut self.db;
            let book = &self.context;
            let txn_cx = cx.txn();
            let txn = db.begin(&txn_cx).map_err(KernelError::from)?;
            let vid = fa_journal::evidence::document_vid(oid);
            let is_document = txn.vertex_has_label(db, vid, label::DOCUMENT).map_err(KernelError::from)?;
            if is_document.is_none() {
                txn.abort();
                return Ok(None);
            }
            let book_id = txn.vertex_property(db, vid, property::BOOK_ID).map_err(KernelError::from)?;
            let digest = txn.vertex_property(db, vid, property::FA_DIGEST).map_err(KernelError::from)?;
            txn.abort();
            let malformed = || BookError::Kernel(KernelError::Corrupt(
                "FA-REF-085 document commitment mirror has invalid identity or digest".into(),
            ));
            if is_document != Some(true)
                || !matches!(book_id, Some(CanonicalScalar::Bytes(b)) if b.as_slice() == book.book_id.0)
            {
                return Err(malformed());
            }
            let Some(CanonicalScalar::Bytes(bytes)) = digest else {
                return Err(malformed());
            };
            let commit: [u8; 32] = bytes.as_slice().try_into().map_err(|_| malformed())?;
            if fa_journal::evidence::document_oid(book.book_id, &commit) != *oid {
                return Err(malformed());
            }
            Ok(Some(commit))
        })
    }

    pub async fn record_review(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        document: &fa_model::Oid,
        against: Vec<fa_model::Oid>,
    ) -> Outcome<fa_journal::Attested> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::record_review(
            &mut self.db,
            cx,
            &self.context,
            capability,
            capability.holder(),
            *document,
            against,
        )
        .await?)
    }

    pub async fn record_manual_assertion(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        proposal: &fa_model::EntryPayload,
        reason_code: u16,
        statement: &str,
    ) -> Outcome<fa_journal::Attested> {
        let statement = self.seal_text(cx, statement)?;
        Ok(fa_journal::record_manual_assertion(
            &mut self.db,
            cx,
            &self.context,
            capability,
            proposal,
            reason_code,
            statement,
        )
        .await?)
    }

    pub fn read_entry(
        &self,
        cx: &PurposeContexts,
        vid: VId,
    ) -> Result<Option<(Entry, CommitSeq)>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::post::read_entry(db, vid)?))
    }

    pub fn periods(&self, cx: &PurposeContexts) -> Result<Vec<PeriodRow>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::genesis::list_periods(db)?))
    }

    pub fn accounts(&self, cx: &PurposeContexts) -> Result<Vec<AccountRow>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::genesis::list_accounts(db)?))
    }

    pub fn fold_period(&self, cx: &PurposeContexts, period: &str) -> Result<Fold, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::fold_period(db, book, period)?)
        })
    }

    pub async fn materialize_registers(
        &mut self,
        cx: &PurposeContexts,
        period: &str,
    ) -> Result<(Fold, CommitSeq), BookError> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let fold = self.fold_period(cx, period)?;
        let seq = fa_registers::materialize(&mut self.db, cx, &self.context, &fold).await?;
        Ok((fold, seq))
    }

    pub fn verify_registers(
        &self,
        cx: &PurposeContexts,
        period: &str,
    ) -> Result<Verification, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::verify_period(db, book, period)?)
        })
    }

    pub async fn advance_registers(
        &mut self,
        cx: &PurposeContexts,
        period: &str,
    ) -> Result<fa_registers::Advance, BookError> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_registers::advance(&mut self.db, cx, &self.context, period).await?)
    }

    pub async fn rebuild_registers(
        &mut self,
        cx: &PurposeContexts,
        period: &str,
    ) -> Result<fa_registers::Advance, BookError> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_registers::rebuild(&mut self.db, cx, &self.context, period).await?)
    }

    pub async fn checkpoint(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
    ) -> Outcome<fa_notary::Checkpointed> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        if let Err(denial) = fa_policy::admit(
            capability,
            &fa_policy::Intent {
                principal,
                trunk: true,
                op: fa_policy::Op::Witness,
                book: self.context.book_id,
                legs: &[],
            },
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(denial) = fa_policy::current(capability, self.head(cx)?) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        // The exclusive book handle holds the single-writer admission
        // frontier while checking revocation and publishing the checkpoint.
        if let Err(refusal) = self.query(cx, |db, book| {
            Ok(fa_journal::policy::capability_admitted(
                db, book, capability,
            )?)
        })? {
            return Ok(Err(refusal));
        }
        Ok(fa_notary::checkpoint(&mut self.db, cx, &self.context).await?)
    }

    pub fn verify_accumulator(
        &self,
        cx: &PurposeContexts,
    ) -> Result<fa_notary::AccumulatorVerification, BookError> {
        self.query(cx, |db, book| Ok(fa_notary::verify_accumulator(db, book)?))
    }

    /// Export a portable proof from a supported recorded checkpoint, under
    /// current read and produce authority. Export never mutates the book.
    pub fn export_proof(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        request: crate::ProofRequest,
    ) -> Outcome<crate::ProofArtifact> {
        self.query(cx, |db, book| {
            crate::proof::export(db, book, principal, capability, request)
        })
    }

    pub fn open_items(
        &self,
        cx: &PurposeContexts,
        account: Option<VId>,
        known_at: Option<CommitSeq>,
    ) -> Result<Vec<OpenItem>, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::open_items(db, book, account, known_at)?)
        })
    }

    /// Resolve open items and their displayed account metadata at one sequence.
    pub fn open_items_report(
        &self,
        cx: &PurposeContexts,
        account: Option<VId>,
        known_at: Option<CommitSeq>,
    ) -> Result<crate::OpenItemsReport, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::open_items::open_items_report(
                db, book, account, known_at,
            )?)
        })
    }

    /// Verify the immutable leg projection at one committed prefix without writes.
    pub fn verify_projections(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_journal::ProjectionVerification, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::verify_projections(db, book, known_at)?)
        })
    }

    pub fn verify_open_items(
        &self,
        cx: &PurposeContexts,
    ) -> Result<OpenItemVerification, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::verify_open_items(db, book, None)?)
        })
    }

    pub fn verify_availability(
        &self,
        cx: &PurposeContexts,
    ) -> Result<AvailabilityVerification, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::verify_availability(db, book, None)?)
        })
    }

    pub fn explain_balance(
        &self,
        cx: &PurposeContexts,
        account: VId,
        period: &str,
        known_at: Option<CommitSeq>,
    ) -> Result<BalanceExplanation, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::explain_balance(
                db, book, account, period, known_at,
            )?)
        })
    }

    pub fn trial_balance(
        &self,
        cx: &PurposeContexts,
        periods: &[String],
    ) -> Result<TrialBalance, BookError> {
        self.trial_balance_at(cx, periods, None)
    }

    /// Certify a stock/activity trial balance at a fixed retained snapshot.
    /// The current whole-book embedded-owner authority is explicit in the
    /// certificate. Creating this artifact does not advance the journal.
    pub fn certify_trial_balance(
        &self,
        cx: &PurposeContexts,
        selection: crate::TrialBalanceSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedTrialBalance> {
        self.query(cx, |db, book| {
            crate::certificate::certify(db, &cx.query(), book, selection, known_at)
        })
    }

    /// Certify any supported report against one retained historical sequence.
    pub fn certify_report(
        &self,
        cx: &PurposeContexts,
        selection: crate::ReportSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedReport> {
        self.query(cx, |db, book| {
            crate::certificate::certify_report(db, &cx.query(), book, selection, known_at)
        })
    }

    /// Evaluate a registered statement from journal payloads at one snapshot.
    /// Current and comparative columns use the same known-at and definition.
    pub fn statement(
        &self,
        cx: &PurposeContexts,
        selection: crate::StatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::Statement> {
        self.query(cx, |db, book| {
            crate::statements::read(db, &cx.query(), book, selection, known_at)
        })
    }

    /// Bind a financial statement's definition, mapping and both columns to
    /// the retained historical journal and native input closure.
    pub fn certify_statement(
        &self,
        cx: &PurposeContexts,
        selection: crate::StatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedStatement> {
        Ok(self
            .certify_report(cx, selection.into(), known_at)?
            .and_then(crate::statements::certified))
    }

    pub fn certify_statement_at_instant(
        &self,
        cx: &PurposeContexts,
        selection: crate::StatementSelection,
        requested_utc_ns: u64,
    ) -> Outcome<crate::CertifiedStatement> {
        Ok(self
            .certify_report_at_instant(cx, selection.into(), requested_utc_ns)?
            .and_then(crate::statements::certified))
    }

    /// Resolve a UTC instant from the journal's retained TimeEvidence at HEAD.
    /// The returned frontier and brackets describe the precision of the read.
    pub fn resolve_known_at_instant(
        &self,
        cx: &PurposeContexts,
        requested_utc_ns: u64,
    ) -> Outcome<fa_journal::InstantSelection> {
        self.query(cx, |db, book| {
            Ok(fa_journal::resolve_instant_at(
                db,
                &cx.query(),
                book,
                requested_utc_ns,
                None,
            )?)
        })
    }

    /// Certify an instant-selected report, including its original tick brackets.
    pub fn certify_trial_balance_at_instant(
        &self,
        cx: &PurposeContexts,
        selection: crate::TrialBalanceSelection,
        requested_utc_ns: u64,
    ) -> Outcome<crate::CertifiedTrialBalance> {
        self.query(cx, |db, book| {
            crate::certificate::certify_instant(db, &cx.query(), book, selection, requested_utc_ns)
        })
    }

    /// Certify any supported report with its original TimeEvidence resolution.
    pub fn certify_report_at_instant(
        &self,
        cx: &PurposeContexts,
        selection: crate::ReportSelection,
        requested_utc_ns: u64,
    ) -> Outcome<crate::CertifiedReport> {
        self.query(cx, |db, book| {
            crate::certificate::certify_report_instant(
                db,
                &cx.query(),
                book,
                selection,
                requested_utc_ns,
            )
        })
    }

    /// Replay the exact historical output of any supported certificate family.
    pub fn replay_report(
        &self,
        cx: &PurposeContexts,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<crate::ReportOutput> {
        self.query(cx, |db, book| {
            crate::certificate::replay_report(db, &cx.query(), book, certificate)
        })
    }

    /// Replay every native input, then the exact accounting fold.
    pub fn replay_trial_balance(
        &self,
        cx: &PurposeContexts,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<TrialBalance> {
        self.query(cx, |db, book| {
            crate::certificate::replay(db, &cx.query(), book, certificate)
        })
    }

    /// Check whether later journal entries affect this report's selector.
    pub fn certificate_status(
        &self,
        cx: &PurposeContexts,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<crate::CertificateStatus> {
        self.query(cx, |db, book| {
            crate::certificate::status(db, &cx.query(), book, certificate)
        })
    }

    /// Retain verified canonical certificate bytes in this book's substrate.
    /// The public content digest resolves the immutable artifact after reopen.
    /// This lazy write has its own sequence; the report keeps its original
    /// known-at coordinate and no journal Entry is created.
    pub async fn retain_certificate(
        &mut self,
        cx: &PurposeContexts,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<crate::RetainedCertificate> {
        crate::certificate_store::retain(&mut self.db, cx, &self.context, certificate).await
    }

    /// Load a retained certificate by its full public content digest.
    /// Loading checks its immutable storage record; report replay separately
    /// verifies the historical input closure.
    pub fn read_certificate(
        &self,
        cx: &PurposeContexts,
        digest: &[u8; 32],
    ) -> Outcome<crate::ReportCertificate> {
        self.query(cx, |db, book| {
            crate::certificate_store::read(db, &cx.query(), book, digest)
        })
    }

    pub fn trial_balance_at(
        &self,
        cx: &PurposeContexts,
        periods: &[String],
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::trial_balance_at(db, book, periods, known_at)?)
        })
    }

    pub fn balance_as_of(
        &self,
        cx: &PurposeContexts,
        day: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::balance_as_of(db, book, day, known_at)?)
        })
    }

    pub fn period_activity(
        &self,
        cx: &PurposeContexts,
        periods: &[String],
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::period_activity(db, book, periods, known_at)?)
        })
    }
}

/// Give relative paths an explicit current-directory anchor. This keeps
/// directory-entry ownership consistent for fault-injecting VFSes while
/// avoiding an attempt to open the empty path on the host filesystem.
pub(crate) fn rooted_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(".").join(path)
    }
}

pub(crate) async fn sync_file<F: VfsFile>(file: &mut F) -> std::io::Result<()> {
    file.sync_all().await
}

impl<V: Vfs + Clone, B: Vfs + Clone> fmt::Debug for AsyncBook<V, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AsyncBook({:?}, calendar {})",
            self.context.book_id, self.context.calendar.id
        )
    }
}
