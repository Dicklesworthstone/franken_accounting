//! A book executed by its caller's runtime and filesystem.
//!
//! This is the shared implementation for the embedded async API and the
//! synchronous production adapter. It owns no runtime or root context. Both
//! Ordinary books use clones of the same supplied VFS for database and
//! document bytes. Scratch books retain their source's blob store, so a
//! caller can keep both stores on the same lab-controlled I/O plane.

use core::fmt;
use std::path::{Path, PathBuf};

use asupersync::fs::{OpenOptions, Vfs, VfsFile};
use fa_journal::rows::{AccountRow, PeriodRow};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, KernelError, PostRequest, Posted,
    Transitioned,
};
use fa_model::{Entry, Erasable, SymbolTable};
use fa_registers::{
    AvailabilityVerification, BalanceExplanation, Fold, OpenItem, OpenItemVerification,
    TrialBalance, Verification,
};
use fa_time::{DateDay, PeriodDef, PeriodTransition};
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::book::{BookError, BookKeys, Entropy, Outcome};

const BOOK_BLOB_STORE: u16 = 1;

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
        commit
            .with_restriction_async(async {
                vfs.create_dir_all(&dir)
                    .await
                    .map_err(|e| BookError::Io(dir.to_path_buf(), e))?;
                // An earlier interrupted constructor may have created any of
                // these names. Fence every ancestor, not only newly made ones.
                for ancestor in dir.ancestors().filter(|p| !p.as_os_str().is_empty()) {
                    let mut handle = vfs
                        .open(ancestor, &OpenOptions::new().read(true))
                        .await
                        .map_err(|e| BookError::Io(ancestor.to_path_buf(), e))?;
                    sync_file(&mut handle)
                        .await
                        .map_err(|e| BookError::Io(ancestor.to_path_buf(), e))?;
                }
                Ok::<_, BookError>(())
            })
            .await?;
        let mut db =
            Database::create_with_vfs(&commit, vfs.clone(), dir.join("store"), keys.inner.clone())
                .await?;
        let units = fa_money::UnitRegistry::embedded()?;
        let symbols = SymbolTable::compiled();
        fa_journal::create_book(&mut db, cx, &spec, &units, &symbols).await?;
        Ok(Self {
            db,
            blobs: fa_journal::BlobStore::open(BOOK_BLOB_STORE, vfs, dir.join("blobs"))?,
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
        let db =
            Database::open_with_vfs(&commit, vfs.clone(), dir.join("store"), keys.inner.clone())
                .await?;
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        let spec = query
            .with_restriction(|| fa_journal::genesis::read_book_spec(&db))?
            .ok_or(BookError::NoBook)?;
        Ok(Self {
            db,
            blobs: fa_journal::BlobStore::open(BOOK_BLOB_STORE, vfs, dir.join("blobs"))?,
            context: BookContext {
                book_id: spec.book_id,
                calendar: spec.calendar,
                units: fa_money::UnitRegistry::embedded()?,
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
        let mut salt = [0; 32];
        let mut nonce = [0; 24];
        self.entropy.fill(&mut salt)?;
        self.entropy.fill(&mut nonce)?;
        Ok(Erasable::seal(
            &text.to_string(),
            None,
            &self.context.seal_key,
            salt,
            nonce,
        ))
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

    pub async fn post_balancing(
        &mut self,
        cx: &PurposeContexts,
        req: PostRequest,
        leg: u16,
    ) -> Outcome<fa_journal::Balanced> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        Ok(fa_journal::post_balancing(&mut self.db, cx, &self.context, req, leg).await?)
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

    pub async fn read_document(
        &self,
        cx: &PurposeContexts,
        oid: &fa_model::Oid,
    ) -> Outcome<Option<fa_journal::Document>> {
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        Ok(query
            .with_restriction_async(fa_journal::fetch_document(&self.db, cx, &self.blobs, oid))
            .await?)
    }

    pub fn document_record(
        &self,
        cx: &PurposeContexts,
        oid: &fa_model::Oid,
    ) -> Result<Option<fa_journal::DocumentRecord>, BookError> {
        self.query(cx, |db, _| Ok(fa_journal::document_record(db, oid)?))
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
fn rooted_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(".").join(path)
    }
}

async fn sync_file<F: VfsFile>(file: &mut F) -> std::io::Result<()> {
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
