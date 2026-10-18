//! A book executed by its caller's runtime and filesystem.
//!
//! This is the shared implementation for the embedded async API and the
//! synchronous production adapter. It owns no runtime or root context.
//! Ordinary books use clones of the same supplied VFS for database and
//! document bytes. Scratch books retain their source's blob store, so a
//! caller can keep both stores on the same lab-controlled I/O plane.

use core::fmt;
use std::collections::BTreeMap;
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

use crate::book::{BookError, BookKeys, Entropy, Outcome, ProducedBundle};

pub(crate) const BOOK_BLOB_STORE: u16 = 1;

/// The journal prefix and the checkpoint a bundle is assembled over.
type BundleBasis = (fa_notary::Journal, fa_notary::StoredCheckpoint);

/// What a bundle against `state` (default: the latest journaled state) is
/// assembled over, or `None` when there is no such state.
fn bundle_basis_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    signer: &fa_notary::SigningKey,
    state: Option<fa_model::Oid>,
) -> Result<Option<Result<BundleBasis, fa_journal::Refusal>>, KernelError> {
    let chain = fa_notary::chain(db)?;
    let stored = match state {
        None => chain.first(),
        Some(oid) => chain.iter().find(|s| s.oid == oid),
    };
    match stored {
        None => Ok(None),
        Some(stored) => fa_notary::bundle_basis(db, cx, book, stored, signer).map(Some),
    }
}

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
    pub(crate) blobs: fa_journal::BlobStore<B>,
    context: BookContext,
    entropy: Entropy,
    /// Signs this book's transparency checkpoints (derived from its keys).
    signer: fa_notary::SigningKey,
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
            signer: keys.checkpoint_signing_key(),
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
            signer: keys.checkpoint_signing_key(),
        })
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    #[must_use]
    pub fn context(&self) -> &BookContext {
        &self.context
    }

    /// Run `read` under the caller's query context and its restriction:
    /// every facade read, the blocking [`crate::ReadScope`] included, goes
    /// through here.
    pub(crate) fn query<T>(
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

    /// The genesis spec journaled on the book root (base unit, calendar,
    /// opening date, entities): what `fa book info` reports.
    pub fn spec(&self, cx: &PurposeContexts) -> Result<BookSpec, BookError> {
        self.query(cx, |db, _| {
            fa_journal::genesis::read_book_spec(db)?.ok_or(BookError::NoBook)
        })
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

    #[allow(clippy::too_many_arguments)]
    pub async fn open_account(
        &mut self,
        cx: &PurposeContexts,
        spec: &AccountSpec,
        opened: DateDay,
        closed: Option<DateDay>,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::AccountLifecycleRecorded> {
        let description =
            self.seal_text(cx, &format!("open account `{}` on {opened}", spec.code))?;
        Ok(fa_journal::open_account(
            &mut self.db,
            cx,
            &self.context,
            spec,
            opened,
            closed,
            principal,
            effective_date,
            idempotency_key,
            description,
            capability,
        )
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn close_account(
        &mut self,
        cx: &PurposeContexts,
        code: &str,
        closed_on: DateDay,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::AccountLifecycleRecorded> {
        let description = self.seal_text(cx, &format!("close account `{code}` on {closed_on}"))?;
        Ok(fa_journal::close_account(
            &mut self.db,
            cx,
            &self.context,
            code,
            closed_on,
            principal,
            effective_date,
            idempotency_key,
            description,
            capability,
        )
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn promote_to_summary(
        &mut self,
        cx: &PurposeContexts,
        code: &str,
        promotion_date: DateDay,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::AccountLifecycleRecorded> {
        let description = self.seal_text(
            cx,
            &format!("promote account `{code}` to summary on {promotion_date}"),
        )?;
        Ok(fa_journal::promote_to_summary(
            &mut self.db,
            cx,
            &self.context,
            code,
            promotion_date,
            principal,
            effective_date,
            idempotency_key,
            description,
            capability,
        )
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_party(
        &mut self,
        cx: &PurposeContexts,
        spec: &fa_model::PartySpec,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::ReaControlRecorded> {
        let description = self.seal_text(cx, &format!("create party `{}`", spec.code))?;
        Ok(fa_journal::create_party(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            effective_date,
            idempotency_key,
            description,
            capability,
        )
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_instrument(
        &mut self,
        cx: &PurposeContexts,
        spec: &fa_model::InstrumentSpec,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::ReaControlRecorded> {
        let description = self.seal_text(cx, &format!("create instrument `{}`", spec.code))?;
        Ok(fa_journal::create_instrument(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            effective_date,
            idempotency_key,
            description,
            capability,
        )
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_event(
        &mut self,
        cx: &PurposeContexts,
        spec: &fa_model::EventSpec,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::ReaControlRecorded> {
        let description = self.seal_text(
            cx,
            &format!(
                "record event `{}` ({}) on {}",
                spec.code,
                spec.kind.name(),
                spec.occurred_on
            ),
        )?;
        Ok(fa_journal::record_event(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            effective_date,
            idempotency_key,
            description,
            capability,
        )
        .await?)
    }

    pub fn rea_snapshot(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_journal::ReaSnapshot, BookError> {
        let seq = match known_at {
            Some(s) => s,
            None => self.head(cx)?,
        };
        self.query(cx, |db, book| Ok(fa_journal::read_rea_at(db, book, seq)?))
    }

    pub fn events(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
    ) -> Result<Vec<fa_journal::EventRow>, BookError> {
        let snap = self.rea_snapshot(cx, known_at)?;
        let mut rows: Vec<fa_journal::EventRow> = snap.events.into_values().collect();
        rows.sort_by(|a, b| {
            a.spec
                .occurred_on
                .cmp(&b.spec.occurred_on)
                .then_with(|| a.spec.code.cmp(&b.spec.code))
        });
        Ok(rows)
    }

    pub fn read_event(
        &self,
        cx: &PurposeContexts,
        vid: VId,
        known_at: Option<CommitSeq>,
    ) -> Result<Option<fa_journal::EventRow>, BookError> {
        let mut snap = self.rea_snapshot(cx, known_at)?;
        Ok(snap.events.remove(&vid))
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

    pub async fn revoke_capability(
        &mut self,
        cx: &PurposeContexts,
        capability: fa_journal::Capability,
        revoked_commitment: [u8; 32],
        effective_date: DateDay,
        idempotency_key: &[u8],
        description: &str,
    ) -> Outcome<fa_journal::Revoked> {
        let description = self.seal_text(cx, description)?;
        Ok(fa_journal::revoke_capability(
            &mut self.db,
            cx,
            &self.context,
            fa_journal::RevocationRequest {
                capability,
                revoked: revoked_commitment,
                effective_date,
                idempotency_key: idempotency_key.to_vec(),
                description,
            },
        )
        .await?)
    }

    /// Issue a holder-bound capability under `capability` (plan §14.2,
    /// fa-v62): one `PolicyControl` entry carrying `CapabilityEvent { Issue }`
    /// and the issued capability's canonical body.
    pub async fn issue_capability(
        &mut self,
        cx: &PurposeContexts,
        capability: fa_journal::Capability,
        issued: fa_journal::Capability,
        effective_date: DateDay,
        idempotency_key: &[u8],
        description: &str,
    ) -> Outcome<fa_journal::Issued> {
        let description = self.seal_text(cx, description)?;
        Ok(fa_journal::issue_capability(
            &mut self.db,
            cx,
            &self.context,
            fa_journal::IssuanceRequest {
                capability,
                issued,
                effective_date,
                idempotency_key: idempotency_key.to_vec(),
                description,
            },
        )
        .await?)
    }

    /// Every capability this book issued, from the journal, with its
    /// revocation state.
    pub fn issued_capabilities(
        &self,
        cx: &PurposeContexts,
    ) -> Result<Vec<fa_journal::IssuedCapability>, BookError> {
        self.query(cx, |db, context| Ok(fa_journal::list_issued(db, context)?))
    }

    /// The capability issued at `commitment`, from the journal.
    pub fn issued_capability(
        &self,
        cx: &PurposeContexts,
        commitment: &[u8; 32],
    ) -> Result<Option<fa_journal::IssuedCapability>, BookError> {
        self.query(cx, |db, context| {
            Ok(fa_journal::read_issued(db, context, commitment)?)
        })
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

    /// Commit an atomic batch (plan §5.8) under the caller's capability:
    /// every member through the posting pipeline in one transaction, with
    /// the batch's IntentOutcome; an identical retry returns that outcome.
    pub async fn post_batch(
        &mut self,
        cx: &PurposeContexts,
        batch: fa_intents::PostBatch,
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::BatchPosted> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(
            fa_journal::post_batch(&mut self.db, cx, &self.context, capability.clone(), batch)
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

    #[allow(clippy::too_many_arguments)]
    pub fn open_migration_proposal(
        &self,
        principal: VId,
        body: &fa_journal::RunBody,
        citations: Vec<fa_model::EvidenceRef>,
        idempotency_key: &[u8],
        description: Erasable<String>,
    ) -> Result<fa_model::EntryPayload, BookError> {
        Ok(fa_journal::migration::open_proposal(
            &self.context,
            principal,
            body,
            citations,
            idempotency_key,
            description,
        )?)
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

    pub fn migration_tie_out(
        &self,
        cx: &PurposeContexts,
        run: &fa_journal::Run,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_journal::TieOut, BookError> {
        self.query(cx, |db, book| {
            let seq = fa_registers::resolve_known_at(db, known_at)?;
            Ok(fa_journal::migration::tie_out(db, book, run, seq)?)
        })
    }

    /// Replay the accounting prefix into a caller-created, empty database.
    /// Execution stays on the caller's runtime and context. The scratch
    /// book shares the source's immutable blob store, so its external
    /// documents remain readable while that store is available. Its sealed
    /// fields retain the source book's key; target database keys encrypt
    /// only the new substrate storage. `keys` are the keys `target` was
    /// opened with: the scratch book signs its own checkpoints with their
    /// checkpoint key, never with the source's unless the caller passes the
    /// source's keys, since a checkpoint over a scenario prefix is not the
    /// book's.
    pub async fn replay_into<W: Vfs + Clone>(
        &mut self,
        cx: &PurposeContexts,
        mut target: Database<W>,
        keys: &BookKeys,
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
                signer: keys.checkpoint_signing_key(),
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

    /// Keep the session intake path bound to this book's private blob store.
    /// Sibling facade modules must not accept a caller-selected store or fall
    /// back to the legacy owner-only intake when an upload exceeds inline size.
    pub(crate) async fn upload_in_configured_store(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        request: fa_journal::UploadRequest,
    ) -> Outcome<fa_journal::DocumentAdded> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::upload::upload_document_in_store(
            &mut self.db,
            cx,
            &self.context,
            capability,
            &self.blobs,
            request,
        )
        .await?)
    }

    pub async fn add_document(
        &mut self,
        cx: &PurposeContexts,
        doc: &fa_journal::Document,
    ) -> Outcome<fa_journal::DocumentAdded> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        let inline_bound = fa_journal::evidence::inline_document_bound(
            &fa_registry::evidence_policy::EvidencePolicy::embedded()?,
        );
        Ok(
            if u64::try_from(doc.bytes.len()).unwrap_or(u64::MAX) > inline_bound {
                fa_journal::add_document_external(&mut self.db, cx, &self.context, &self.blobs, doc)
                    .await?
            } else {
                fa_journal::add_document(&mut self.db, cx, &self.context, doc).await?
            },
        )
    }

    /// Import a mixed-size evidence batch through this book's configured
    /// private blob store. All document records, custody receipts and the run
    /// entry publish together, after external bytes are durable. Callers do
    /// not select a store or gain authority by choosing larger documents.
    /// An exact retry returns the original receipt; failed or cancelled
    /// imports can leave unreferenced blobs, never a partial recorded run.
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
        Ok(fa_journal::import::import_run_in_store(
            &mut self.db,
            cx,
            &self.context,
            capability,
            &self.blobs,
            req,
        )
        .await?)
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

    pub fn erasure_cut(
        &self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        subject: VId,
    ) -> Result<fa_journal::Refusal, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::evidence::erasure_cut(
                db, book, capability, subject,
            )?)
        })
    }

    pub fn evaluate_register_equals(
        &self,
        cx: &PurposeContexts,
        key: &fa_registers::EntityCellKey,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_registers::RegisterEquals, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::register_equals(db, book, key, known_at)?)
        })
    }

    pub async fn record_register_equals(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_journal::Capability,
        claim: &fa_registers::RegisterEquals,
        evidence: Vec<fa_model::Oid>,
    ) -> Outcome<fa_journal::Attested> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_registers::assertion::record_register_equals(
            &mut self.db,
            cx,
            &self.context,
            capability,
            claim,
            evidence,
        )
        .await?)
    }

    pub fn assertion_holds(
        &self,
        cx: &PurposeContexts,
        vid: VId,
    ) -> Result<Option<bool>, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::assertion::assertion_holds(db, book, vid)?)
        })
    }

    pub fn read_entry(
        &self,
        cx: &PurposeContexts,
        vid: VId,
    ) -> Result<Option<(Entry, CommitSeq)>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::post::read_entry(db, vid)?))
    }

    pub fn superseded_by(
        &self,
        cx: &PurposeContexts,
        vid: VId,
    ) -> Result<Vec<fa_model::Supersession>, BookError> {
        self.query(cx, |db, book| Ok(fa_journal::superseded_by(db, book, vid)?))
    }

    pub fn explain_entry_evidence(
        &self,
        cx: &PurposeContexts,
        entry_vid: VId,
    ) -> Result<Option<fa_journal::EvidenceExplanation>, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::explain_entry_evidence(db, book, entry_vid)?)
        })
    }

    pub fn explain_entry_lineage(
        &self,
        cx: &PurposeContexts,
        entry_vid: VId,
        known_at: Option<CommitSeq>,
    ) -> Result<Option<fa_journal::LineageReport>, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::explain_entry_lineage(
                db, book, entry_vid, known_at,
            )?)
        })
    }

    pub fn periods(&self, cx: &PurposeContexts) -> Result<Vec<PeriodRow>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::genesis::list_periods(db)?))
    }

    pub fn period_transitions(
        &self,
        cx: &PurposeContexts,
        period_code: &str,
    ) -> Result<Vec<fa_journal::PeriodTransitionRecord>, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::period_transitions(db, book, period_code)?)
        })
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
        // Not revoked at that frontier, before the journal is read. The
        // exclusive book handle is the single writer, so no revocation can
        // commit between this read and the checkpoint's transaction; with
        // concurrent writers the read moves inside that transaction as a
        // witness, as post's does.
        if let Err(refusal) = self.query(cx, |db, book| {
            Ok(fa_journal::policy::capability_admitted(
                db, book, capability,
            )?)
        })? {
            return Ok(Err(refusal));
        }
        Ok(fa_notary::checkpoint(&mut self.db, cx, &self.context, &self.signer).await?)
    }

    /// Recompute every accumulator state from its journal prefix, and every
    /// checkpoint from the same prefix and this book's key.
    pub fn verify_accumulator(
        &self,
        cx: &PurposeContexts,
    ) -> Result<fa_notary::AccumulatorVerification, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_notary::verify_accumulator(db, cx, book, &self.signer)?)
        })
    }

    /// The public key this book's transparency checkpoints are signed with
    /// (Ed25519, plan §13.2), for an outsider to verify them with.
    #[must_use]
    pub fn checkpoint_public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    /// Produce an evidence bundle against the journaled state `state`
    /// (default: the latest) and its detached production receipt
    /// ([`crate::Book::produce_bundle`] states the contract). `produce`
    /// admission, currency and revocation are checked before the journal is
    /// read; each cited document is read as `capability` may see it,
    /// decided before any read of its bytes.
    pub async fn produce_bundle(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        state: Option<fa_model::Oid>,
        request: &fa_notary::BundleRequest,
    ) -> Outcome<Option<ProducedBundle>> {
        cx.query().checkpoint().map_err(BookError::Context)?;
        // A production writes nothing, so it is admitted as a read: an
        // Agent-profile capability holding `produce` may produce.
        if let Err(denial) = fa_policy::admit(
            capability,
            &fa_policy::Intent {
                principal,
                trunk: false,
                op: fa_policy::Op::Produce,
                book: self.context.book_id,
                legs: &[],
            },
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        // A bundle discloses its scope's entries (every leaf of a Prefix
        // scope), so producing one also needs whole-book read authority, as
        // a proof export does: `produce` alone never discloses the journal.
        if let Err(denial) = fa_policy::admit_read(capability, principal, self.context.book_id) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let at = self.head(cx)?;
        if let Err(denial) = fa_policy::current(capability, at) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        // Not revoked (fa-bcd), before the journal is read.
        if let Err(refusal) = self.query(cx, |db, book| {
            Ok(fa_journal::policy::capability_admitted(
                db, book, capability,
            )?)
        })? {
            return Ok(Err(refusal));
        }
        let commitment = capability
            .commitment()
            .map_err(|e| KernelError::Corrupt(format!("capability commitment: {e}")))?;
        let basis = self.query(cx, |db, book| {
            Ok(bundle_basis_at(db, cx, book, &self.signer, state)?)
        })?;
        let (journal, checkpoint) = match basis {
            None => return Ok(Ok(None)),
            Some(Err(refusal)) => return Ok(Err(refusal)),
            Some(Ok(basis)) => basis,
        };
        let cited = match fa_notary::bundle::cited_documents(&journal, request)? {
            Ok(cited) => cited,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut documents = BTreeMap::new();
        let inline_documents = request.inline_documents;
        let query = cx.query();
        for oid in cited {
            query.checkpoint().map_err(BookError::Context)?;
            let read = query
                .with_restriction_async(fa_journal::read_document_for_with(
                    &mut self.db,
                    cx,
                    &self.context,
                    capability,
                    &self.blobs,
                    oid,
                    |record| {
                        if inline_documents
                            && record.size > fa_notary::MAX_INLINE_DOCUMENT_BYTES as u64
                        {
                            return Err(fa_notary::bundle::inline_document_limit(
                                &oid,
                                record.size,
                            ));
                        }
                        Ok(())
                    },
                ))
                .await?;
            match read {
                Ok(read) => {
                    documents.insert(oid, read);
                }
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        // A balance over migration-run entries is proved in v2, which needs
        // each run's immutable body (fa-e00).
        let run_bodies = match self.query(cx, |db, _book| {
            Ok(fa_notary::migration_balance::bundle_run_bodies(
                db, &journal, request,
            )?)
        })? {
            Ok(bodies) => bodies,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let bundle = match fa_notary::bundle::assemble_with_runs(
            &journal,
            &checkpoint,
            request,
            &documents,
            &run_bodies,
        )? {
            Ok(bundle) => bundle,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let receipt = fa_notary::ProductionReceipt::sign(
            fa_notary::ReceiptBody {
                bundle_digest: bundle.digest,
                producer_principal: principal,
                produced_at_seq: at,
                capability_commitment: commitment,
                time_evidence_oid: None,
            },
            &self.signer,
        )
        .map_err(|e| KernelError::Corrupt(e.to_string()))?
        .canonical_bytes()
        .map_err(|e| KernelError::Model(e.into()))?;
        Ok(Ok(Some(ProducedBundle { bundle, receipt })))
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
            crate::proof::export(db, cx, book, &self.signer, principal, capability, request)
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

    /// Fold cost-basis lots and `RELIEVES {quantity, cost}` edges for an `AnyUnit` account (plan §6.5, `fa-2ly`).
    pub fn lots(
        &self,
        cx: &PurposeContexts,
        account: VId,
        effective_through: Option<DateDay>,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_registers::LotsReport, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_registers::lots(
                db,
                book,
                account,
                effective_through,
                known_at,
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

    pub fn verify_schedules(
        &self,
        cx: &PurposeContexts,
    ) -> Result<fa_journal::ScheduleVerification, BookError> {
        self.query(cx, |db, book| Ok(fa_journal::verify_schedules(db, book)?))
    }

    pub fn verify_periods(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_journal::PeriodVerification, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_journal::verify_periods(db, book, known_at)?)
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

    /// A registered Lantern procedure over the trunk under the query
    /// context: the snapshot is read once, then the procedure folds it with
    /// no clock, entropy, network or filesystem capability.
    pub fn run_procedure(
        &self,
        cx: &PurposeContexts,
        procedure: &dyn fa_lantern::Procedure,
        known_at: Option<CommitSeq>,
        effective_through: Option<fa_time::DateDay>,
    ) -> Result<fa_lantern::ProcedureRun, BookError> {
        self.query(cx, |db, book| {
            Ok(fa_lantern::run(
                db,
                book,
                known_at,
                effective_through,
                procedure,
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
        crate::certificate_store::retain(&mut self.db, cx, &self.context, &self.blobs, certificate)
            .await
    }

    /// Retain verified canonical certificate bytes after verifying current
    /// `read` authority for this book (fa-1nx).
    pub async fn retain_certificate_authorized(
        &mut self,
        cx: &PurposeContexts,
        certificate: &crate::ReportCertificate,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::RetainedCertificate> {
        if let Err(denial) =
            fa_policy::admit_read(capability, capability.holder(), self.context.book_id)
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let at = self.head(cx)?;
        if let Err(denial) = fa_policy::current(capability, at) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = self.query(cx, |db, book| {
            Ok(fa_journal::policy::capability_admitted(
                db, book, capability,
            )?)
        })? {
            return Ok(Err(refusal));
        }
        self.retain_certificate(cx, certificate).await
    }

    /// Load a retained certificate by its full public content digest.
    /// Loading checks its immutable storage record (and fetches and verifies
    /// externally retained bytes); report replay separately verifies the
    /// historical input closure.
    pub async fn read_certificate(
        &self,
        cx: &PurposeContexts,
        digest: &[u8; 32],
    ) -> Outcome<crate::ReportCertificate> {
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query
            .with_restriction_async(crate::certificate_store::read(
                &self.db,
                &query,
                &self.context,
                &self.blobs,
                digest,
            ))
            .await
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
