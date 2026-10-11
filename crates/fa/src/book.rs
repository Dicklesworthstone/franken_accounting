//! `Book`: the handle to one FrankenAccounting book on FrankenGraphDB.
//!
//! The facade owns what the kernel (`fa-journal`) deliberately does not: the
//! asupersync runtime, the root `Cx` it was granted, the substrate
//! `Database` (in memory or in a directory), the book's seal key, and an
//! entropy capability. Every call narrows the root `Cx` to the substrate's
//! purpose contexts (plan §1 constraint 3) and runs the kernel's single
//! transaction to completion.
//!
//! A directory book is `<dir>/store` (the substrate's database directory)
//! plus the key file the operator keeps: three 64-hex lines, mode 0600.

use core::fmt;
use std::path::{Path, PathBuf};

use asupersync::fs::UnixVfs;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::rows::{AccountRow, PeriodRow};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, KernelError, PostRequest, Posted, Refusal,
    Transitioned,
};
use fa_model::{Entry, Erasable, SealKey, SymbolTable};
use fa_registers::{
    AvailabilityVerification, BalanceExplanation, Fold, OpenItem, OpenItemVerification,
    TrialBalance, Verification,
};
use fa_time::{DateDay, PeriodDef, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_crypto::{CryptoCx, DeterministicEntropy, EntropyError, SystemEntropy, derive_key};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

/// The three secrets a book directory needs: the object-identity key, the
/// security namespace, and the data-encryption key (the substrate's
/// `DatabaseKeys`). On disk these are the three 64-hex lines of the key file.
#[derive(Clone)]
pub struct BookKeys {
    inner: DatabaseKeys,
    namespace: [u8; 32],
}

impl BookKeys {
    /// Keys from raw material. The caller owns their entropy and custody.
    pub fn from_raw(k_oid: [u8; 32], namespace: [u8; 32], dek: [u8; 32]) -> Self {
        Self {
            inner: DatabaseKeys::new(k_oid, DatabaseSecurityNamespaceId(namespace), dek),
            namespace,
        }
    }

    /// Deterministic keys for examples and tests. **Never** for a real book:
    /// every byte of every key is `seed`.
    pub fn for_development(seed: u8) -> Self {
        Self::from_raw(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 32],
        )
    }

    /// Fresh keys from the entropy capability.
    pub fn generate(entropy: &Entropy) -> Result<Self, BookError> {
        let mut k = [0u8; 32];
        let mut n = [0u8; 32];
        let mut d = [0u8; 32];
        entropy.fill(&mut k)?;
        entropy.fill(&mut n)?;
        entropy.fill(&mut d)?;
        Ok(Self::from_raw(k, n, d))
    }

    /// Write the key file (three 64-hex lines) with mode 0600, refusing to
    /// overwrite an existing one.
    pub fn save(&self, path: &Path) -> Result<(), BookError> {
        use std::io::Write as _;
        if path.exists() {
            return Err(BookError::KeyFile(format!(
                "{} already exists; keys are never overwritten",
                path.display()
            )));
        }
        let text = format!(
            "{}\n{}\n{}\n",
            hex(self.inner.k_oid()),
            hex(&self.namespace()),
            hex(self.inner.dek())
        );
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .map_err(|e| BookError::Io(path.to_path_buf(), e))?;
        f.write_all(text.as_bytes())
            .map_err(|e| BookError::Io(path.to_path_buf(), e))?;
        f.sync_all()
            .map_err(|e| BookError::Io(path.to_path_buf(), e))?;
        Ok(())
    }

    /// Read a key file written by [`BookKeys::save`].
    pub fn load(path: &Path) -> Result<Self, BookError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| BookError::Io(path.to_path_buf(), e))?;
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        if lines.len() != 3 {
            return Err(BookError::KeyFile(format!(
                "{}: expected three 64-hex lines, found {}",
                path.display(),
                lines.len()
            )));
        }
        let parse = |l: &str, what: &str| {
            unhex(l).ok_or_else(|| {
                BookError::KeyFile(format!(
                    "{}: {what} is not 64 hex characters",
                    path.display()
                ))
            })
        };
        Ok(Self::from_raw(
            parse(lines[0], "k_oid")?,
            parse(lines[1], "namespace")?,
            parse(lines[2], "dek")?,
        ))
    }

    fn namespace(&self) -> [u8; 32] {
        self.namespace
    }

    /// The book key erasable fields without a subject are sealed under:
    /// `KDF(DEK, "fa:erasable:book:v1")`, domain-separated from every
    /// substrate use of the DEK.
    fn seal_key(&self) -> SealKey {
        SealKey(derive_key("fa:erasable:book:v1", self.inner.dek()))
    }
}

impl fmt::Debug for BookKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys are never printed, even in debug output.
        f.write_str("BookKeys(<redacted>)")
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Where a book's salts and nonces come from.
pub enum Entropy {
    /// The operating system's entropy: every real book.
    Production(CryptoCx<SystemEntropy>),
    /// A seeded stream: examples, tests, and the lab runtime.
    Deterministic(CryptoCx<DeterministicEntropy>),
}

impl Entropy {
    #[must_use]
    pub fn production() -> Self {
        Self::Production(CryptoCx::production())
    }

    #[must_use]
    pub fn deterministic(seed: u64) -> Self {
        Self::Deterministic(CryptoCx::new(DeterministicEntropy::for_test(seed)))
    }

    pub fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        match self {
            Self::Production(c) => c.fill_secret(dest),
            Self::Deterministic(c) => c.fill_secret(dest),
        }
    }
}

impl fmt::Debug for Entropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Production(_) => "Entropy::Production",
            Self::Deterministic(_) => "Entropy::Deterministic",
        })
    }
}

/// Errors a `Book` can return. Each maps to one exit-code class in the CLI
/// contract (plan Appendix D): `Runtime`, `Open`, `Io`, `KeyFile`, and
/// `NoBook` are environment errors (4); the rest are foundation failures
/// (5). Lawful refusals are not errors: they are the `Err` of the inner
/// result each method returns.
#[derive(Debug)]
pub enum BookError {
    Runtime(String),
    Open(fgdb::OpenError),
    Io(PathBuf, std::io::Error),
    KeyFile(String),
    /// The store opened but holds no book (genesis never ran).
    NoBook,
    Kernel(KernelError),
    Registers(fa_registers::RegisterError),
    Registry(fa_registry::RegistryError),
    Entropy(EntropyError),
}

impl BookError {
    /// The exit class (plan §15.3).
    #[must_use]
    pub fn exit(&self) -> u8 {
        match self {
            Self::Registers(fa_registers::RegisterError::InvalidSelection(_)) => {
                fa_journal::exit::USAGE
            }
            Self::Runtime(_) | Self::Open(_) | Self::Io(..) | Self::KeyFile(_) | Self::NoBook => {
                fa_journal::exit::ENVIRONMENT
            }
            Self::Kernel(_) | Self::Registers(_) | Self::Registry(_) | Self::Entropy(_) => {
                fa_journal::exit::FOUNDATION
            }
        }
    }
}

impl fmt::Display for BookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "runtime: {e}"),
            Self::Open(e) => write!(f, "open: {e:?}"),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
            Self::KeyFile(e) => write!(f, "key file: {e}"),
            Self::NoBook => write!(f, "the store holds no book; run `fa book create` first"),
            Self::Kernel(e) => write!(f, "{e}"),
            Self::Registers(e) => write!(f, "{e}"),
            Self::Registry(e) => write!(f, "registry: {e}"),
            Self::Entropy(e) => write!(f, "entropy: {e:?}"),
        }
    }
}

impl core::error::Error for BookError {}

impl From<fgdb::OpenError> for BookError {
    fn from(e: fgdb::OpenError) -> Self {
        Self::Open(e)
    }
}
impl From<KernelError> for BookError {
    fn from(e: KernelError) -> Self {
        Self::Kernel(e)
    }
}
impl From<fa_registers::RegisterError> for BookError {
    fn from(e: fa_registers::RegisterError) -> Self {
        Self::Registers(e)
    }
}
impl From<fa_registry::RegistryError> for BookError {
    fn from(e: fa_registry::RegistryError) -> Self {
        Self::Registry(e)
    }
}
impl From<EntropyError> for BookError {
    fn from(e: EntropyError) -> Self {
        Self::Entropy(e)
    }
}

/// The facade's result shape: a failure, or a lawful refusal, or the outcome.
pub type Outcome<T> = Result<Result<T, Refusal>, BookError>;

enum Store {
    Memory(Database<MemVfs>),
    Dir(Database<UnixVfs>),
}

/// The book's blob store (fa-txf part B): documents past the inline bound
/// keep their bytes here, content-addressed, beside the database. A clone
/// addresses the same store (a scratch book reads its source's blobs).
#[derive(Clone)]
enum Blobs {
    Memory(fa_journal::BlobStore<MemVfs>),
    Dir(fa_journal::BlobStore<UnixVfs>),
}

/// The registered store a book's own blobs live in (`document_stores.toml`).
const BOOK_BLOB_STORE: u16 = 1;

/// Run `$body` with `$bs` bound to the book's blob store, whichever VFS backs it.
macro_rules! with_blobs {
    ($blobs:expr, $bs:ident => $body:expr) => {
        match $blobs {
            Blobs::Memory($bs) => $body,
            Blobs::Dir($bs) => $body,
        }
    };
}

/// Run `$body` with `$db` bound to the store's database, whichever VFS backs it.
macro_rules! with_store {
    ($store:expr, $db:ident => $body:expr) => {
        match $store {
            Store::Memory($db) => $body,
            Store::Dir($db) => $body,
        }
    };
}

/// One open book.
pub struct Book {
    runtime: Runtime,
    root: Cx,
    store: Store,
    blobs: Blobs,
    ctx: BookContext,
    entropy: Entropy,
}

impl Book {
    fn runtime_and_root() -> Result<(Runtime, Cx), BookError> {
        let runtime = RuntimeBuilder::new()
            .build()
            .map_err(|e| BookError::Runtime(format!("{e:?}")))?;
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        Ok((runtime, root))
    }

    fn genesis(
        runtime: &Runtime,
        root: &Cx,
        store: &mut Store,
        keys: &BookKeys,
        spec: BookSpec,
    ) -> Result<BookContext, BookError> {
        let purposes = PurposeContexts::narrow_runtime_root(root);
        let units = fa_money::UnitRegistry::embedded()?;
        let symbols = SymbolTable::compiled();
        with_store!(store, db => runtime.block_on(async { fa_journal::create_book(db, &purposes, &spec, &units, &symbols).await }))?;
        Ok(BookContext {
            book_id: spec.book_id,
            calendar: spec.calendar,
            units,
            seal_key: keys.seal_key(),
            symbols,
        })
    }

    /// Create an in-memory book: open the substrate, journal the book vertex
    /// and its units, and return the handle.
    pub fn create_memory(
        keys: BookKeys,
        spec: BookSpec,
        entropy: Entropy,
    ) -> Result<Self, BookError> {
        let (runtime, root) = Self::runtime_and_root()?;
        let purposes = PurposeContexts::narrow_runtime_root(&root);
        let db = runtime.block_on(async {
            Database::open_memory(&purposes.commit(), keys.inner.clone()).await
        })?;
        let mut store = Store::Memory(db);
        let ctx = Self::genesis(&runtime, &root, &mut store, &keys, spec)?;
        let blob_vfs = MemVfs::new().map_err(|e| BookError::Io(PathBuf::from("blobs"), e))?;
        let blobs = Blobs::Memory(fa_journal::BlobStore::open(
            BOOK_BLOB_STORE,
            blob_vfs,
            // MemVfs anchors a relative path at its own private root.
            "blobs",
        )?);
        Ok(Self {
            runtime,
            root,
            store,
            blobs,
            ctx,
            entropy,
        })
    }

    /// Create a directory book at `<dir>/store` (`dir` is created if absent).
    pub fn create_dir(
        dir: &Path,
        keys: BookKeys,
        spec: BookSpec,
        entropy: Entropy,
    ) -> Result<Self, BookError> {
        std::fs::create_dir_all(dir).map_err(|e| BookError::Io(dir.to_path_buf(), e))?;
        let (runtime, root) = Self::runtime_and_root()?;
        let purposes = PurposeContexts::narrow_runtime_root(&root);
        let store_path = dir.join("store");
        let db = runtime.block_on(async {
            Database::create(&purposes.commit(), &store_path, keys.inner.clone()).await
        })?;
        let mut store = Store::Dir(db);
        let ctx = Self::genesis(&runtime, &root, &mut store, &keys, spec)?;
        let blobs = Blobs::Dir(fa_journal::BlobStore::open(
            BOOK_BLOB_STORE,
            UnixVfs::new(),
            dir.join("blobs"),
        )?);
        Ok(Self {
            runtime,
            root,
            store,
            blobs,
            ctx,
            entropy,
        })
    }

    /// Open the directory book at `<dir>/store`, rebuilding the context from
    /// the spec journaled at genesis.
    pub fn open_dir(dir: &Path, keys: BookKeys, entropy: Entropy) -> Result<Self, BookError> {
        let (runtime, root) = Self::runtime_and_root()?;
        let purposes = PurposeContexts::narrow_runtime_root(&root);
        let store_path = dir.join("store");
        let db = runtime.block_on(async {
            Database::open(&purposes.commit(), &store_path, keys.inner.clone()).await
        })?;
        let spec = fa_journal::genesis::read_book_spec(&db)?.ok_or(BookError::NoBook)?;
        let ctx = BookContext {
            book_id: spec.book_id,
            calendar: spec.calendar,
            units: fa_money::UnitRegistry::embedded()?,
            seal_key: keys.seal_key(),
            symbols: SymbolTable::compiled(),
        };
        let blobs = Blobs::Dir(fa_journal::BlobStore::open(
            BOOK_BLOB_STORE,
            UnixVfs::new(),
            dir.join("blobs"),
        )?);
        Ok(Self {
            runtime,
            root,
            store: Store::Dir(db),
            blobs,
            ctx,
            entropy,
        })
    }

    #[must_use]
    pub fn context(&self) -> &BookContext {
        &self.ctx
    }

    /// The book's head: the latest recorded sequence, which a read at head
    /// observes and a write's result follows (the robot envelope's
    /// `coordinate.known_at`, plan Appendix D). Read-only.
    pub fn head(&self) -> Result<CommitSeq, BookError> {
        Ok(with_store!(&self.store, db => db.frontier()).map_err(KernelError::from)?)
    }

    fn purposes(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn salt_and_nonce(&self) -> Result<([u8; 32], [u8; 24]), BookError> {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        self.entropy.fill(&mut salt)?;
        self.entropy.fill(&mut nonce)?;
        Ok((salt, nonce))
    }

    /// Seal a description or memo under the book key with fresh salt and nonce.
    pub fn seal_text(&self, text: &str) -> Result<Erasable<String>, BookError> {
        let (salt, nonce) = self.salt_and_nonce()?;
        Ok(Erasable::seal(
            &text.to_string(),
            None,
            &self.ctx.seal_key,
            salt,
            nonce,
        ))
    }

    /// Install a chart as one journaled schema effect (plan §4.3).
    pub fn install_chart(
        &mut self,
        accounts: &[AccountSpec],
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<ChartInstalled> {
        let description = self.seal_text(&format!("chart install: {} accounts", accounts.len()))?;
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(
            with_store!(&mut self.store, db => runtime.block_on(async { fa_journal::install_chart(db, &purposes, ctx, accounts, principal, effective_date, idempotency_key, description).await }))?,
        )
    }

    /// Create one fiscal year's periods in state `Future`.
    pub fn create_periods(
        &mut self,
        fiscal_year: i32,
    ) -> Result<(CommitSeq, Vec<PeriodDef>), BookError> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(
            with_store!(&mut self.store, db => runtime.block_on(async { fa_journal::create_periods(db, &purposes, ctx, fiscal_year).await }))?,
        )
    }

    /// Move a period along the state machine under `capability` (plan §14:
    /// it must be `principal`'s and hold the transition's op). The facade
    /// seals the description with fresh salt, so it cites no approvals:
    /// transitions that need approvers (Lock, SoftClosed→Reopen) are planned
    /// with [`Book::plan_transition`], approved with [`Book::approve`], and
    /// committed with [`Book::transition_planned`].
    #[allow(clippy::too_many_arguments)]
    pub fn transition_period(
        &mut self,
        period_code: &str,
        t: PeriodTransition,
        principal: VId,
        reason_code: u16,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<Transitioned> {
        let description = self.seal_text(&format!("period {period_code}: {t:?}"))?;
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::transition_period(db, &purposes, ctx, period_code, t, principal, reason_code, effective_date, idempotency_key, description, capability, &[]).await
        }))?)
    }

    /// Plan a transition without committing (R4): the description is sealed
    /// once, so approvers bind the plan's `proposal_digest` and
    /// [`Book::transition_planned`] commits exactly that proposal. The
    /// period is read at the head; authority is judged at the commit.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_transition(
        &self,
        period_code: &str,
        t: PeriodTransition,
        principal: VId,
        reason_code: u16,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<fa_journal::TransitionPlan> {
        let description = self.seal_text(&format!("period {period_code}: {t:?}"))?;
        Ok(
            with_store!(&self.store, db => fa_journal::plan_transition(db, &self.ctx, period_code, t, principal, reason_code, effective_date, idempotency_key, description))?,
        )
    }

    /// The digest an approval of `plan` binds.
    pub fn plan_digest(&self, plan: &fa_journal::TransitionPlan) -> Result<[u8; 32], BookError> {
        Ok(plan.proposal_digest(&self.ctx)?)
    }

    /// Commit a planned transition under `capability`, citing `approvals`
    /// of the plan's proposal digest. The kernel rebuilds the proposal from
    /// the plan's inputs and the period's current state, so a period that
    /// moved since the plan no longer matches its approvals (FA-REF-016).
    pub fn transition_planned(
        &mut self,
        plan: &fa_journal::TransitionPlan,
        t: PeriodTransition,
        capability: &fa_journal::Capability,
        approvals: &[fa_model::ApprovalRef],
    ) -> Outcome<Transitioned> {
        let description = plan.description.clone();
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::transition_period(db, &purposes, ctx, &plan.period_code, t, plan.principal_ref, plan.reason_code, plan.effective_date, &plan.idempotency_key, description, capability, approvals).await
        }))?)
    }

    /// Record an approval of `proposal_digest` under `capability` (plan
    /// §14.3): a journaled object bound to the digest and the current
    /// security policy epoch. The capability must hold `approve`.
    pub fn approve(
        &mut self,
        capability: fa_journal::Capability,
        proposal_digest: [u8; 32],
    ) -> Outcome<fa_journal::Approved> {
        let req = fa_journal::ApprovalRequest {
            capability,
            approved_proposal_digest: proposal_digest,
            role: 0,
        };
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::record_approval(db, &purposes, ctx, req).await
        }))?)
    }

    /// Post one entry under the accounting laws (plan §5).
    pub fn post(&mut self, req: PostRequest) -> Outcome<Posted> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(
            with_store!(&mut self.store, db => runtime.block_on(async { fa_journal::post(db, &purposes, ctx, req).await }))?,
        )
    }

    /// Post with a balancing leg (plan §5.5): leg `leg` moves at most what its
    /// account's limit admits, decided inside the posting transaction; the
    /// request is the entry's identity (`fa post --balancing`).
    pub fn post_balancing(&mut self, req: PostRequest, leg: u16) -> Outcome<fa_journal::Balanced> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(
            with_store!(&mut self.store, db => runtime.block_on(async { fa_journal::post_balancing(db, &purposes, ctx, req, leg).await }))?,
        )
    }

    /// Open a migration run (plan §8.6): journal its body — the legacy trial
    /// balance as typed lines — and its `Open` record citing the trial
    /// balance document. Chunks then post as `Migration` entries naming the
    /// run and stay invisible until the run is finalized.
    pub fn open_migration_run(
        &mut self,
        body: &fa_journal::RunBody,
        req: fa_journal::RunControlRequest,
    ) -> Outcome<fa_journal::RunControlled> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(
            with_store!(&mut self.store, db => runtime.block_on(async { fa_journal::open_run(db, &purposes, ctx, body, req).await }))?,
        )
    }

    /// Plan a run's `Finalize` (or `Abandon`) against the head: the proposal
    /// whose digest the approvers approve. Its `tie_out_digest` binds the
    /// chunks committed so far.
    pub fn plan_migration_transition(
        &self,
        run: VId,
        control_kind: u8,
        principal: VId,
        idempotency_key: &[u8],
        description: Erasable<String>,
    ) -> Outcome<fa_model::EntryPayload> {
        Ok(
            with_store!(&self.store, db => fa_journal::plan_run_transition(db, &self.ctx, run, control_kind, principal, idempotency_key, description))?,
        )
    }

    /// Finalize or abandon a migration run (one control record).
    pub fn transition_migration_run(
        &mut self,
        req: fa_journal::RunControlRequest,
    ) -> Outcome<fa_journal::RunControlled> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(
            with_store!(&mut self.store, db => runtime.block_on(async { fa_journal::transition_run(db, &purposes, ctx, req).await }))?,
        )
    }

    /// The migration run at `run`, as of `known_at` (head when `None`).
    pub fn migration_run(
        &self,
        run: VId,
        known_at: Option<CommitSeq>,
    ) -> Result<Option<fa_journal::Run>, BookError> {
        Ok(with_store!(&self.store, db => fa_journal::migration::read_run(db, run, known_at))?)
    }

    /// Replay this book's accounting history through `prefix` (head when
    /// `None`) into a fresh in-memory scratch book (plan §15.2): the same
    /// objects, byte for byte, one scratch commit per source commit that
    /// carries any, under the scratch book's own commit sequences. Returns
    /// the scratch book (its database opened with `keys`, sealing with
    /// `entropy`) and the [`fa_journal::SeqMap`] binding the two histories.
    pub fn replay_into_scratch(
        &mut self,
        prefix: Option<CommitSeq>,
        keys: BookKeys,
        entropy: Entropy,
    ) -> Outcome<(Book, fa_journal::SeqMap)> {
        let purposes = self.purposes();
        let runtime = &self.runtime;
        let read = with_store!(&mut self.store, db => runtime.block_on(async {
            match fa_journal::scratch::ensure_history(db, &purposes).await? {
                Ok(()) => fa_journal::scratch::source_batches(db, prefix),
                Err(r) => Ok(Err(r)),
            }
        }))?;
        let (prefix, batches) = match read {
            Ok(read) => read,
            Err(r) => return Ok(Err(r)),
        };
        let (scratch_runtime, scratch_root) = Self::runtime_and_root()?;
        let scratch_purposes = PurposeContexts::narrow_runtime_root(&scratch_root);
        let mut db = scratch_runtime.block_on(async {
            Database::open_memory(&scratch_purposes.commit(), keys.inner.clone()).await
        })?;
        let book_id = self.ctx.book_id;
        let replayed = scratch_runtime.block_on(async {
            fa_journal::scratch::replay_batches(
                &mut db,
                &scratch_purposes,
                book_id,
                prefix,
                &batches,
            )
            .await
        })?;
        let map = match replayed {
            Ok(map) => map,
            Err(r) => return Ok(Err(r)),
        };
        Ok(Ok((
            Book {
                runtime: scratch_runtime,
                root: scratch_root,
                store: Store::Memory(db),
                // A replayed external document row names bytes only the
                // source's blob store holds, so the scratch book reads that
                // store, verifying every read as the source does (WhiteCreek
                // 3482). Content-addressed: a past-bound intake in the
                // scratch book publishes a blob the source never names.
                blobs: self.blobs.clone(),
                ctx: self.ctx.clone(),
                entropy,
            },
            map,
        )))
    }

    /// Verify `scratch` against the [`fa_journal::SeqMap`] of its replay
    /// from this book (`fa_registers::replay::verify_replay`).
    pub fn verify_replay(
        &self,
        scratch: &Book,
        map: &fa_journal::SeqMap,
    ) -> Outcome<fa_registers::replay::ReplayVerification> {
        Ok(
            with_store!(&self.store, source => with_store!(&scratch.store, copy => {
                fa_registers::replay::verify_replay(source, copy, &self.ctx, map)
            }))?,
        )
    }

    /// Record a document (plan §9.1): content-addressed; the same bytes of
    /// the same kind are the recorded outcome. A document past the inline
    /// bound (`evidence_policy.toml max_document_bytes`) keeps its bytes in
    /// the book's blob store, its commitment inline.
    pub fn add_document(
        &mut self,
        doc: &fa_journal::Document,
    ) -> Outcome<fa_journal::DocumentAdded> {
        let inline_bound =
            fa_registry::evidence_policy::EvidencePolicy::embedded()?.max_document_bytes;
        let external = u64::try_from(doc.bytes.len()).unwrap_or(u64::MAX) > inline_bound;
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        let blobs = &self.blobs;
        Ok(if external {
            with_store!(&mut self.store, db => with_blobs!(blobs, bs => runtime.block_on(async {
                fa_journal::add_document_external(db, &purposes, ctx, bs, doc).await
            })))?
        } else {
            with_store!(&mut self.store, db => runtime.block_on(async { fa_journal::add_document(db, &purposes, ctx, doc).await }))?
        })
    }

    /// Record an import run (plan §9.3): the batch's documents and their
    /// receipts, and the run's `ImportControl` receipt, in one commit.
    /// `description` is sealed under the book key with fresh entropy.
    #[allow(clippy::too_many_arguments)]
    pub fn import_run(
        &mut self,
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
            description: self.seal_text(description)?,
            documents,
        };
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::import_run(db, &purposes, ctx, capability, req).await
        }))?)
    }

    /// The receipt of the import run whose control entry is `run`.
    pub fn read_run(&self, run: VId) -> Result<Option<fa_journal::RunReceipt>, BookError> {
        Ok(with_store!(&self.store, db => fa_journal::import::read_run(db, run))?)
    }

    /// Hand the document at `document` on from the capability's holder (its
    /// current custodian) to `to`, as a journaled custody event.
    pub fn transfer_custody(
        &mut self,
        capability: &fa_journal::Capability,
        document: &fa_model::Oid,
        to: VId,
    ) -> Outcome<fa_journal::CustodyMoved> {
        let from = capability.holder();
        let document = *document;
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::transfer_custody(db, &purposes, ctx, capability, document, from, to).await
        }))?)
    }

    /// The document's chain of custody, verified, oldest first.
    pub fn custody_chain(
        &self,
        document: &fa_model::Oid,
    ) -> Result<Vec<(fa_journal::CustodyEvent, CommitSeq)>, BookError> {
        Ok(with_store!(&self.store, db => fa_journal::custody_chain(db, document))?)
    }

    /// The document at `oid`, verified against its commitment.
    pub fn read_document(&self, oid: &fa_model::Oid) -> Outcome<Option<fa_journal::Document>> {
        let purposes = self.purposes();
        let runtime = &self.runtime;
        Ok(
            with_store!(&self.store, db => with_blobs!(&self.blobs, bs => runtime.block_on(async {
                fa_journal::fetch_document(db, &purposes, bs, oid).await
            })))?,
        )
    }

    /// The document's verified record (kind, grade, size, commitment, and
    /// where its bytes are) without fetching the bytes.
    pub fn document_record(
        &self,
        oid: &fa_model::Oid,
    ) -> Result<Option<fa_journal::DocumentRecord>, BookError> {
        Ok(with_store!(&self.store, db => fa_journal::document_record(db, oid))?)
    }

    /// Record a `Reviewed` attestation over the document at `document`
    /// (plan §9.3) by the capability's holder, who must hold `approve` and
    /// must not have uploaded it; a self-sourced document then counts toward
    /// the evidence minimum of entries posted after it.
    pub fn record_review(
        &mut self,
        capability: &fa_journal::Capability,
        document: &fa_model::Oid,
        against: Vec<fa_model::Oid>,
    ) -> Outcome<fa_journal::Attested> {
        let reviewer = capability.holder();
        let document = *document;
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::record_review(db, &purposes, ctx, capability, reviewer, document, against).await
        }))?)
    }

    /// Record the preparer's `ManualAssertion` over `proposal` (plan §9.2):
    /// no document exists, for a registered `reason_code`, as `statement`
    /// says (sealed under the book key with fresh entropy). Posting that
    /// exact proposal then meets the minimum where its class admits one.
    pub fn record_manual_assertion(
        &mut self,
        capability: &fa_journal::Capability,
        proposal: &fa_model::EntryPayload,
        reason_code: u16,
        statement: &str,
    ) -> Outcome<fa_journal::Attested> {
        let statement = self.seal_text(statement)?;
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::record_manual_assertion(db, &purposes, ctx, capability, proposal, reason_code, statement).await
        }))?)
    }

    /// Read a committed entry back by its derived identity, verifying its digests.
    pub fn read_entry(&self, vid: VId) -> Result<Option<(Entry, CommitSeq)>, BookError> {
        Ok(with_store!(&self.store, db => fa_journal::post::read_entry(db, vid))?)
    }

    /// Every period of the book in calendar order, with its current state.
    pub fn periods(&self) -> Result<Vec<PeriodRow>, BookError> {
        Ok(with_store!(&self.store, db => fa_journal::genesis::list_periods(db))?)
    }

    /// Every account of the chart, sorted by code.
    pub fn accounts(&self) -> Result<Vec<AccountRow>, BookError> {
        Ok(with_store!(&self.store, db => fa_journal::genesis::list_accounts(db))?)
    }

    /// The register fold of one period (plan §5.3).
    pub fn fold_period(&self, period_code: &str) -> Result<Fold, BookError> {
        Ok(with_store!(&self.store, db => fa_registers::fold_period(db, &self.ctx, period_code))?)
    }

    /// Materialize a period's registers from a fresh fold.
    pub fn materialize_registers(
        &mut self,
        period_code: &str,
    ) -> Result<(Fold, CommitSeq), BookError> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => {
            let fold = fa_registers::fold_period(db, ctx, period_code)?;
            let seq = runtime.block_on(async { fa_registers::materialize(db, &purposes, ctx, &fold).await })?;
            Ok::<_, fa_registers::RegisterError>((fold, seq))
        })?)
    }

    /// Refold a period and compare it to its stored registers (`fa verify registers`).
    pub fn verify_registers(&self, period_code: &str) -> Result<Verification, BookError> {
        Ok(with_store!(&self.store, db => fa_registers::verify_period(db, &self.ctx, period_code))?)
    }

    /// Incrementally maintain native posted/pending period registers from
    /// committed Entry payloads. Cells and the consumed cursor publish in
    /// one commit. A retired delta cursor rebuilds from the journal; detected
    /// cache drift is an error requiring an explicit rebuild.
    pub fn advance_registers(
        &mut self,
        period_code: &str,
    ) -> Result<fa_registers::Advance, BookError> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_registers::advance(db, &purposes, ctx, period_code).await
        }))?)
    }

    /// Replace native posted/pending period registers and their maintenance
    /// cursor by a fresh journal fold, atomically. Authoritative objects are
    /// never changed. Reports continue to use their independent literal fold.
    pub fn rebuild_registers(
        &mut self,
        period_code: &str,
    ) -> Result<fa_registers::Advance, BookError> {
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_registers::rebuild(db, &purposes, ctx, period_code).await
        }))?)
    }

    /// Publish an unsigned accumulator state for this book's entry prefix.
    /// `witness` authorizes publication, not changing its recomputed contents.
    /// Admission precedes storage observation; Agent profiles cannot publish
    /// on trunk. Expiry is checked at the single-writer admission frontier.
    pub fn checkpoint(
        &mut self,
        principal: VId,
        capability: &fa_policy::Capability,
    ) -> Outcome<fa_notary::Checkpointed> {
        if let Err(denial) = fa_policy::admit(
            capability,
            &fa_policy::Intent {
                principal,
                trunk: true,
                op: fa_policy::Op::Witness,
                book: self.ctx.book_id,
                legs: &[],
            },
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let at = with_store!(&self.store, db => db.frontier()).map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, at) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        // Not revoked at that frontier, before the journal is read; the
        // checkpoint refuses a basis that moved past it (BASIS_MOVED), so a
        // revocation committed in between is a conflict, never admitted.
        if let Err(r) = with_store!(&self.store, db => fa_journal::policy::capability_admitted(db, &self.ctx, capability))?
        {
            return Ok(Err(r));
        }
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_notary::checkpoint(db, &purposes, ctx).await
        }))?)
    }

    /// Recompute every accumulator state from its journal prefix.
    /// This reads the whole open embedded book, like the other current read
    /// methods; scoped session admission is not implemented here. The result
    /// verifies entry prefixes, without signatures or document-receipt claims.
    pub fn verify_accumulator(&self) -> Result<fa_notary::AccumulatorVerification, BookError> {
        Ok(with_store!(&self.store, db => fa_notary::verify_accumulator(db, &self.ctx))?)
    }

    /// Open items (plan §5.7): every leg of a live posted entry, optionally
    /// on one account, with its applications and open amount.
    pub fn open_items(
        &self,
        account: Option<VId>,
        known_at: Option<CommitSeq>,
    ) -> Result<Vec<OpenItem>, BookError> {
        Ok(
            with_store!(&self.store, db => fa_registers::open_items(db, &self.ctx, account, known_at))?,
        )
    }

    /// Compare every posted leg's `applied` mirror with the open-item fold.
    pub fn verify_open_items(&self) -> Result<OpenItemVerification, BookError> {
        Ok(with_store!(&self.store, db => fa_registers::verify_open_items(db, &self.ctx, None))?)
    }

    /// Refold every limited account's `LimitCell` from the journal and
    /// compare it with the stored cell (`fa verify availability`, plan
    /// §5.4–5.5). Drift is a finding, never a repair.
    pub fn verify_availability(&self) -> Result<AvailabilityVerification, BookError> {
        Ok(with_store!(&self.store, db => fa_registers::verify_availability(db, &self.ctx, None))?)
    }

    /// Explain an account's register cells in one period (`fa explain
    /// balance`): the cells, the fold they belong to, every contributing leg
    /// with its recorded sequence, and the cells' known-at history. `None`
    /// selects the current head; the result records the resolved sequence.
    pub fn explain_balance(
        &self,
        account: VId,
        period_code: &str,
        known_at: Option<CommitSeq>,
    ) -> Result<BalanceExplanation, BookError> {
        Ok(
            with_store!(&self.store, db => fa_registers::explain_balance(db, &self.ctx, account, period_code, known_at))?,
        )
    }

    /// Stock balances from inception through the latest selected period's end.
    pub fn trial_balance(&self, periods: &[String]) -> Result<TrialBalance, BookError> {
        self.trial_balance_at(periods, None)
    }

    /// Stock balances through the latest selected period, at a recorded frontier.
    /// `None` selects the current head; the result records the resolved sequence.
    pub fn trial_balance_at(
        &self,
        periods: &[String],
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        Ok(
            with_store!(&self.store, db => fa_registers::trial_balance_at(db, &self.ctx, periods, known_at))?,
        )
    }

    /// Stock balances through an inclusive civil date, including opening history.
    pub fn balance_as_of(
        &self,
        day: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        Ok(
            with_store!(&self.store, db => fa_registers::balance_as_of(db, &self.ctx, day, known_at))?,
        )
    }

    /// Literal movements in the selected periods, with each period counted once.
    /// This does not apply income-statement class exclusions.
    pub fn period_activity(
        &self,
        periods: &[String],
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        Ok(
            with_store!(&self.store, db => fa_registers::period_activity(db, &self.ctx, periods, known_at))?,
        )
    }
}

impl fmt::Debug for Book {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Book({:?}, calendar {})",
            self.ctx.book_id, self.ctx.calendar.id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_journal::{Capability, UnitPolicy};
    use fa_model::{EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid};
    use fa_money::{Amount, Side};
    use fa_time::{FiscalCalendar, PeriodKind};

    #[test]
    fn keys_never_print_and_round_trip_through_the_key_file() {
        assert_eq!(
            format!("{:?}", BookKeys::for_development(1)),
            "BookKeys(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", Entropy::deterministic(1)),
            "Entropy::Deterministic"
        );
        let dir = std::env::temp_dir().join(format!("fa-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("book.keys");
        let keys = BookKeys::generate(&Entropy::deterministic(3)).unwrap();
        keys.save(&path).unwrap();
        assert!(keys.save(&path).is_err(), "never overwritten");
        let back = BookKeys::load(&path).unwrap();
        assert_eq!(back.inner.k_oid(), keys.inner.k_oid());
        assert_eq!(back.inner.dek(), keys.inner.dek());
        assert_eq!(back.namespace(), keys.namespace());
        assert_eq!(unhex(&hex(&[0xab; 32])), Some([0xab; 32]));
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn checkpoint_requires_its_holder_witness_authority_and_current_capability() {
        use fa_policy::{Capability as PolicyCapability, Op, Profile};

        let (spec, _) = spec(Id128([0x45; 16]));
        let mut book = Book::create_memory(
            BookKeys::for_development(45),
            spec,
            Entropy::deterministic(45),
        )
        .unwrap();
        let before = with_store!(&book.store, db => db.frontier()).unwrap();
        let principal = VId(45);
        let witness = PolicyCapability::embedded(principal, &["witness"]).unwrap();
        let reader = PolicyCapability::embedded(principal, &["read"]).unwrap();
        let agent =
            PolicyCapability::new(principal, Profile::Agent, &[Op::Witness], VId(1)).unwrap();
        for (actor, cap, code) in [
            (principal, reader, "FA-REF-011"),
            (VId(46), witness.clone(), "FA-REF-011"),
            (principal, agent, "FA-REF-013"),
            (principal, witness.clone().expiring_at(before), "FA-REF-014"),
        ] {
            let refusal = book.checkpoint(actor, &cap).unwrap().unwrap_err();
            assert_eq!((refusal.code, refusal.exit), (code, 7));
            assert_eq!(
                with_store!(&book.store, db => db.frontier()).unwrap(),
                before
            );
        }
        assert!(book.verify_accumulator().unwrap().states.is_empty());
        let published = book.checkpoint(principal, &witness).unwrap().unwrap();
        assert!(published.stored.recorded_at > before);
        let checked = book.verify_accumulator().unwrap();
        assert!(checked.is_green());
        assert_eq!(checked.states.len(), 1);
        assert_eq!(checked.states[0].oid, published.stored.oid);

        // Revoked (fa-bcd): refused before the journal is read, nothing
        // written; another capability of the same principal still publishes.
        let req = fa_journal::RevocationRequest {
            capability: PolicyCapability::embedded(VId(47), &["issue_capability"]).unwrap(),
            revoked: witness.commitment().unwrap(),
            effective_date: fa_time::DateDay::from_ymd(2026, 1, 1).unwrap(),
            idempotency_key: b"revoke-witness".to_vec(),
            description: fa_model::Erasable::seal(
                &"revoke".to_string(),
                None,
                &book.ctx.seal_key,
                [0x47; 32],
                [0x47; 24],
            ),
        };
        let purposes = book.purposes();
        let (ctx, runtime) = (&book.ctx, &book.runtime);
        with_store!(&mut book.store, db => runtime.block_on(async {
            fa_journal::revoke_capability(db, &purposes, ctx, req).await
        }))
        .unwrap()
        .expect("revoked");
        let revoked_at = with_store!(&book.store, db => db.frontier()).unwrap();
        let refusal = book.checkpoint(principal, &witness).unwrap().unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", 7));
        assert_eq!(
            with_store!(&book.store, db => db.frontier()).unwrap(),
            revoked_at
        );
        let renewed = PolicyCapability::embedded(principal, &["witness", "read"]).unwrap();
        book.checkpoint(principal, &renewed).unwrap().unwrap();
        assert_eq!(book.verify_accumulator().unwrap().states.len(), 2);
    }

    fn spec(book_id: Id128) -> (BookSpec, fa_money::UnitId) {
        let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        (
            BookSpec {
                book_id,
                name: "Facade Co".into(),
                base_unit: usd,
                calendar,
                time_zone_policy: None,
                entities: Vec::new(),
            },
            usd,
        )
    }

    fn post_rent(
        book: &mut Book,
        usd: fa_money::UnitId,
        principal: VId,
        day: DateDay,
        key: &[u8],
        cents_credit: i128,
    ) -> Outcome<Posted> {
        let book_id = book.context().book_id;
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "6000"),
                Amount::new(usd, 150_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "1000"),
                Amount::new(usd, cents_credit),
            ),
        ];
        let source = fa_journal::Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: principal,
            bytes: b"INVOICE (facade fixture source document)".to_vec(),
        };
        book.add_document(&source)?
            .expect("the fixture document is admitted");
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day,
            document_date: None,
            description: book.seal_text("March rent")?,
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: principal,
            session_ref: None,
            evidence: vec![source.evidence_ref(1)],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        book.post(PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(principal, &["post"]).expect("post"),
        })
    }

    fn chart(usd: fa_money::UnitId) -> Vec<AccountSpec> {
        vec![
            AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
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
        ]
    }

    /// Plan §15.2 through the facade: the scratch book (its own runtime and
    /// database, the source's blob store) folds as the source does and
    /// verifies against its SeqMap; a past-bound document reads back in it
    /// verified (3482); a scenario post lands in the scratch book only; a
    /// map with a pair removed is FA-REF-135.
    #[test]
    fn a_scratch_replay_reproduces_the_book_and_scenario_posts_stay_in_it() {
        let book_id = Id128([0x5c; 16]);
        let (spec, usd) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x5c),
            spec,
            Entropy::deterministic(0x5c),
        )
        .expect("create");
        let principal = VId(1);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        book.install_chart(&chart(usd), principal, day, b"chart")
            .expect("kernel")
            .expect("installs");
        let (_, periods) = book.create_periods(2026).expect("periods");
        let march = periods
            .iter()
            .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
            .unwrap()
            .code
            .clone();
        book.transition_period(
            &march,
            PeriodTransition::Open,
            principal,
            1,
            day,
            b"open",
            &Capability::embedded(principal, &["close"]).expect("close"),
        )
        .expect("kernel")
        .expect("opens");
        for key in [&b"rent-1"[..], b"rent-2"] {
            post_rent(&mut book, usd, principal, day, key, 150_000)
                .expect("kernel")
                .expect("admitted");
        }
        // A past-bound document: its row replays, its bytes stay in the
        // source's blob store (WhiteCreek 3482).
        let big = fa_journal::Document {
            book_id,
            kind: 1,
            mime: "application/octet-stream".into(),
            grade: 3,
            retrieved_by: principal,
            bytes: vec![b'r'; 16 * 1024 * 1024 + 1],
        };
        let external = book.add_document(&big).expect("kernel").expect("admitted");
        assert!(matches!(
            book.document_record(&external.oid)
                .unwrap()
                .expect("held")
                .storage,
            fa_journal::Storage::External { .. }
        ));
        // Maintained registers are maintenance: never replayed.
        assert!(book.advance_registers(&march).expect("maintained").wrote);
        let source_head = with_store!(&book.store, db => db.frontier()).unwrap();

        // Before the book's genesis there is no book to replay (WhiteCreek
        // 3500): the facade path is refused like the kernel's.
        let early = book
            .replay_into_scratch(
                Some(CommitSeq(0)),
                BookKeys::for_development(0x5d),
                Entropy::deterministic(0x5d),
            )
            .expect("kernel")
            .expect_err("a pre-genesis prefix is refused");
        assert_eq!((early.code, early.exit), ("FA-REF-100", 2), "{early}");

        let (mut scratch, map) = book
            .replay_into_scratch(
                None,
                BookKeys::for_development(0x5d),
                Entropy::deterministic(0x5d),
            )
            .expect("kernel")
            .expect("replays");
        let verified = book
            .verify_replay(&scratch, &map)
            .expect("kernel")
            .expect("verifies");
        assert_eq!(verified.pairs_checked, map.pairs.len());
        assert!(verified.entries_checked >= 2, "{verified:?}");
        assert_eq!(
            scratch.read_document(&external.oid).unwrap().unwrap(),
            Some(big),
            "the replayed external row reads its verified bytes from the source's store"
        );
        assert_eq!(
            scratch.fold_period(&march).unwrap().cells,
            book.fold_period(&march).unwrap().cells
        );
        let scratch_rows =
            with_store!(&scratch.store, db => db.vertices_at(db.frontier().unwrap())).unwrap();
        assert!(
            scratch_rows
                .iter()
                .all(|v| !v.labels.contains(&fa_model::symbols::label::REGISTER_STATE)),
            "no maintainer state reaches the scratch book"
        );

        post_rent(&mut scratch, usd, principal, day, b"what-if", 150_000)
            .expect("kernel")
            .expect("a scenario post");
        assert_eq!(
            with_store!(&book.store, db => db.frontier()).unwrap(),
            source_head,
            "the source never sees a scenario"
        );
        assert_ne!(
            scratch.fold_period(&march).unwrap().cells,
            book.fold_period(&march).unwrap().cells
        );
        // The map still describes the replayed prefix; a removed pair does not.
        assert!(book.verify_replay(&scratch, &map).unwrap().is_ok());
        let mut gap = map.clone();
        gap.pairs.remove(1);
        let refused = book.verify_replay(&scratch, &gap).unwrap().unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-135", 8), "{refused}");
    }

    #[test]
    fn memory_book_creates_installs_opens_posts_folds_and_refuses() {
        let book_id = Id128([3; 16]);
        let (spec, usd) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x5a),
            spec,
            Entropy::deterministic(7),
        )
        .expect("create");
        let principal = VId(1);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        book.install_chart(&chart(usd), principal, day, b"chart")
            .expect("kernel")
            .expect("installs");
        let (_, periods) = book.create_periods(2026).expect("periods");
        let march = periods
            .iter()
            .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
            .unwrap()
            .code
            .clone();
        book.transition_period(
            &march,
            PeriodTransition::Open,
            principal,
            1,
            day,
            b"open",
            &Capability::embedded(principal, &["close"]).expect("close"),
        )
        .expect("kernel")
        .expect("opens");
        assert_eq!(
            book.periods()
                .unwrap()
                .iter()
                .filter(|p| p.state == fa_time::PeriodState::Open)
                .count(),
            1
        );

        let posted = post_rent(&mut book, usd, principal, day, b"rent-2026-03", 150_000)
            .expect("kernel")
            .expect("admitted");
        let (entry, seq) = book
            .read_entry(posted.entry_ref().vid)
            .unwrap()
            .expect("row");
        assert_eq!(entry.entry_digest, posted.entry_ref().entry_digest);
        assert_eq!(seq, posted.recorded_at());
        assert_eq!(
            entry
                .proposal
                .description
                .open(&book.context().seal_key, 1024)
                .unwrap(),
            "March rent"
        );

        let refusal = post_rent(&mut book, usd, principal, day, b"rent-bad", 149_999)
            .expect("kernel")
            .unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-001", fa_journal::exit::REFUSAL)
        );

        let (fold, _) = book.materialize_registers(&march).unwrap();
        assert_eq!(fold.entries, 1);
        assert!(book.verify_registers(&march).unwrap().is_green());
        let tb = book.trial_balance(&[march]).unwrap();
        assert!(tb.is_balanced());
        assert_eq!(
            book.accounts()
                .unwrap()
                .iter()
                .map(|a| a.code.as_str())
                .collect::<Vec<_>>(),
            vec!["1000", "6000"]
        );
    }

    #[test]
    fn attestations_through_the_facade_promote_an_upload_and_stand_in_for_a_document() {
        let book_id = Id128([0x47; 16]);
        let (spec, usd) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x47),
            spec,
            Entropy::deterministic(0x47),
        )
        .expect("create");
        let (preparer, reviewer) = (VId(1), VId(2));
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        book.install_chart(&chart(usd), preparer, day, b"chart")
            .expect("kernel")
            .expect("installs");
        let (_, periods) = book.create_periods(2026).expect("periods");
        let march = periods
            .iter()
            .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
            .unwrap()
            .code
            .clone();
        book.transition_period(
            &march,
            PeriodTransition::Open,
            preparer,
            1,
            day,
            b"open",
            &Capability::embedded(preparer, &["close"]).expect("close"),
        )
        .expect("kernel")
        .expect("opens");
        let upload = fa_journal::Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 4,
            retrieved_by: preparer,
            bytes: b"INVOICE (an agent's upload, facade fixture)".to_vec(),
        };
        book.add_document(&upload)
            .expect("kernel")
            .expect("admitted");
        let rent = |book: &Book, key: &[u8], evidence: Vec<fa_model::EvidenceRef>| {
            let legs = vec![
                LegPayload::simple(
                    Side::Debit,
                    account_vid(book_id, "6000"),
                    Amount::new(usd, 900),
                ),
                LegPayload::simple(
                    Side::Credit,
                    account_vid(book_id, "1000"),
                    Amount::new(usd, 900),
                ),
            ];
            EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: day,
                document_date: None,
                description: book.seal_text("rent").unwrap(),
                effective_period: None,
                unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
                legs,
                control: None,
                base_totals: None,
                idempotency_key: key.to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                principal_ref: preparer,
                session_ref: None,
                evidence,
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            }
        };
        let request = |proposal: EntryPayload| PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(preparer, &["post"]).expect("post"),
        };
        let cites_upload = rent(&book, b"reviewed", vec![upload.evidence_ref(1)]);
        let refused = book
            .post(request(cites_upload.clone()))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, "FA-REF-086");
        let approver = Capability::embedded(reviewer, &["approve"]).expect("approve");
        let reviewed = book
            .record_review(&approver, &upload.oid(), Vec::new())
            .expect("kernel")
            .expect("recorded");
        assert!(!reviewed.already_recorded);
        assert!(book.post(request(cites_upload)).unwrap().is_ok());

        let undocumented = rent(&book, b"asserted", Vec::new());
        let poster = Capability::embedded(preparer, &["post"]).expect("post");
        let refused = book
            .record_manual_assertion(&poster, &undocumented, 999, "no invoice is issued")
            .expect("kernel")
            .unwrap_err();
        assert_eq!(refused.code, "FA-REF-112");
        book.record_manual_assertion(&poster, &undocumented, 1, "no invoice is issued")
            .expect("kernel")
            .expect("recorded");
        assert!(book.post(request(undocumented)).unwrap().is_ok());
    }

    #[test]
    fn explain_balance_resolves_the_account_at_the_requested_sequence() {
        let book_id = Id128([4; 16]);
        let (spec, usd) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x5b),
            spec,
            Entropy::deterministic(7),
        )
        .expect("create");
        let principal = VId(1);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        // Periods first: as known at `before_chart` no account exists.
        let (before_chart, periods) = book.create_periods(2026).expect("periods");
        let march = periods
            .iter()
            .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
            .unwrap()
            .code
            .clone();
        let installed = book
            .install_chart(&chart(usd), principal, day, b"chart")
            .expect("kernel")
            .expect("installs");
        book.transition_period(
            &march,
            PeriodTransition::Open,
            principal,
            1,
            day,
            b"open",
            &Capability::embedded(principal, &["close"]).expect("close"),
        )
        .expect("kernel")
        .expect("opens");
        post_rent(&mut book, usd, principal, day, b"rent", 150_000)
            .expect("kernel")
            .expect("admitted");
        let cash = account_vid(book_id, "1000");
        let refused = book
            .explain_balance(cash, &march, Some(before_chart))
            .unwrap_err();
        assert!(
            matches!(
                refused,
                BookError::Registers(fa_registers::RegisterError::InvalidSelection(_))
            ),
            "{refused}"
        );
        assert_eq!(refused.exit(), fa_journal::exit::USAGE);
        let then = book
            .explain_balance(cash, &march, Some(installed.recorded_at))
            .unwrap();
        assert_eq!(then.account_row.name, "Cash");
        assert!(then.contributions.is_empty() && then.cells.is_empty());
        let now = book.explain_balance(cash, &march, None).unwrap();
        assert_eq!(now.contributions.len(), 1);
        assert_eq!(
            now.cells.iter().map(|c| c.credits).collect::<Vec<_>>(),
            vec![150_000]
        );
    }

    #[test]
    fn a_document_past_the_inline_bound_lives_in_the_blob_store_and_every_read_verifies() {
        let dir = std::env::temp_dir().join(format!("fa-blobs-{}", std::process::id()));
        let keys = BookKeys::generate(&Entropy::deterministic(11)).unwrap();
        let (spec, _usd) = spec(Id128([0x48; 16]));
        let principal = VId(3);
        let document = |bytes: Vec<u8>| fa_journal::Document {
            book_id: spec.book_id,
            kind: 1,
            mime: "application/octet-stream".into(),
            grade: 3,
            retrieved_by: principal,
            bytes,
        };
        let big = document(vec![b'q'; 16 * 1024 * 1024 + 1]);
        let small = document(b"INVOICE (stays inline)".to_vec());
        let (oid, locator) = {
            let mut book =
                Book::create_dir(&dir, keys.clone(), spec.clone(), Entropy::deterministic(11))
                    .expect("create_dir");
            let added = book.add_document(&big).expect("kernel").expect("admitted");
            let record = book.document_record(&added.oid).unwrap().expect("held");
            let locator = match record.storage {
                fa_journal::Storage::External { store, locator } => Some((store, locator)),
                fa_journal::Storage::Inline(_) => None,
            };
            let (store, locator) = locator.expect("routed to the blob store");
            assert_eq!(store, BOOK_BLOB_STORE);
            assert!(
                dir.join("blobs")
                    .join(&locator[..2])
                    .join(&locator)
                    .exists()
            );
            let inline = book
                .add_document(&small)
                .expect("kernel")
                .expect("admitted");
            assert!(matches!(
                book.document_record(&inline.oid)
                    .unwrap()
                    .expect("held")
                    .storage,
                fa_journal::Storage::Inline(_)
            ));
            (added.oid, locator)
        };
        // Reopened, the document reads back byte-identically.
        let book = Book::open_dir(&dir, keys, Entropy::deterministic(12)).expect("open_dir");
        assert_eq!(
            book.read_document(&oid).unwrap().unwrap(),
            Some(big.clone())
        );
        // A byte changed on disk: refused (exit 8), never the changed bytes.
        let path = dir.join("blobs").join(&locator[..2]).join(&locator);
        let mut changed = big.bytes.clone();
        changed[0] = b'Q';
        std::fs::write(&path, &changed).unwrap();
        let r = book.read_document(&oid).unwrap().unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-085", 8), "{r}");
        // The blob moved away: refused (exit 5), never a silent null.
        std::fs::rename(&path, path.with_extension("moved")).unwrap();
        let r = book.read_document(&oid).unwrap().unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-116", 5), "{r}");
    }

    #[test]
    fn directory_book_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("fa-book-{}", std::process::id()));
        let keys = BookKeys::generate(&Entropy::deterministic(9)).unwrap();
        let book_id = Id128([5; 16]);
        let (spec, usd) = spec(book_id);
        let principal = VId(2);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        let march;
        let entry_ref;
        {
            let mut book =
                Book::create_dir(&dir, keys.clone(), spec.clone(), Entropy::deterministic(7))
                    .expect("create_dir");
            book.install_chart(&chart(usd), principal, day, b"chart")
                .expect("kernel")
                .expect("installs");
            let (_, periods) = book.create_periods(2026).expect("periods");
            march = periods
                .iter()
                .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
                .unwrap()
                .code
                .clone();
            book.transition_period(
                &march,
                PeriodTransition::Open,
                principal,
                1,
                day,
                b"open",
                &Capability::embedded(principal, &["close"]).expect("close"),
            )
            .expect("kernel")
            .expect("opens");
            let empty = book
                .advance_registers(&march)
                .expect("initialize maintainer");
            assert!(empty.fold.cells.is_empty());
            entry_ref = post_rent(&mut book, usd, principal, day, b"rent", 150_000)
                .expect("kernel")
                .expect("admitted")
                .entry_ref();
        }
        // A wrong key does not open the store.
        assert!(
            Book::open_dir(
                &dir,
                BookKeys::for_development(1),
                Entropy::deterministic(7)
            )
            .is_err()
        );
        let mut book = Book::open_dir(&dir, keys, Entropy::deterministic(8)).expect("open_dir");
        assert_eq!(book.context().book_id, book_id);
        assert_eq!(book.context().calendar, spec.calendar);
        let (entry, _) = book
            .read_entry(entry_ref.vid)
            .unwrap()
            .expect("the entry survived reopen");
        assert_eq!(entry.entry_digest, entry_ref.entry_digest);
        let advanced = book
            .advance_registers(&march)
            .expect("advance after reopen");
        assert_eq!(advanced.entries_decoded, 1);
        assert_eq!(advanced.fold, book.fold_period(&march).unwrap());
        assert!(book.verify_registers(&march).unwrap().is_green());
        assert!(!book.advance_registers(&march).unwrap().wrote);
        let rebuilt = book
            .rebuild_registers(&march)
            .expect("rebuild through facade");
        assert_eq!(rebuilt.fold, advanced.fold);
        assert!(book.verify_registers(&march).unwrap().is_green());
        // The journal is still open for business, and the same key is still recorded.
        let again = post_rent(&mut book, usd, principal, day, b"rent", 150_000)
            .expect("kernel")
            .expect("recorded");
        assert!(matches!(again, Posted::AlreadyRecorded { .. }));
        assert!(book.trial_balance(&[march]).unwrap().is_balanced());
    }
}
