//! `Book`: the handle to one FrankenAccounting book on FrankenGraphDB.
//!
//! The synchronous production adapter owns an asupersync runtime and root
//! context. Every operation delegates to [`AsyncBook`], narrowing that root
//! to the same purpose contexts that an async or lab caller supplies itself.
//! Database, document storage, keys and entropy belong to the async core.
//!
//! A directory book is `<dir>/store` (the substrate's database directory)
//! plus the key file the operator keeps: three 64-hex lines, mode 0600.

use core::fmt;
use std::path::{Path, PathBuf};

use asupersync::fs::{OpenOptions, UnixVfs, Vfs};
use asupersync::io::AsyncWriteExt;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::blob::DurableDirectory;
use fa_journal::rows::{AccountRow, PeriodRow};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, KernelError, PostRequest, Posted, Refusal,
    Transitioned,
};
use fa_model::{Entry, Erasable, SealKey};
use fa_registers::{
    AvailabilityVerification, BalanceExplanation, Fold, OpenItem, OpenItemVerification,
    TrialBalance, Verification,
};
use fa_time::{DateDay, PeriodDef, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_crypto::{CryptoCx, DeterministicEntropy, EntropyError, SystemEntropy, derive_key};
use fgdb_types::context::{CommitCx, PurposeContexts, QueryCx};
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

use crate::AsyncBook;
use crate::async_book::{rooted_path, sync_file};

/// The three secrets a book directory needs: the object-identity key, the
/// security namespace, and the data-encryption key (the substrate's
/// `DatabaseKeys`). On disk these are the three 64-hex lines of the key file.
#[derive(Clone)]
pub struct BookKeys {
    pub(crate) inner: DatabaseKeys,
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
    /// overwrite an existing one. Both its bytes and its directory entry
    /// are durable before this returns.
    pub fn save(&self, path: &Path) -> Result<(), BookError> {
        let (runtime, root) = Book::runtime_and_root()?;
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(self.save_with_vfs(&cx.commit(), &UnixVfs, path))
    }

    /// Save through the caller's filesystem and commit context. The parent
    /// must exist; its whole ancestor chain is fenced, including directories
    /// the caller created before this operation. This also covers a key file
    /// kept outside the book directory.
    pub async fn save_with_vfs<V: Vfs + Clone>(
        &self,
        cx: &CommitCx,
        vfs: &V,
        path: &Path,
    ) -> Result<(), BookError> {
        cx.checkpoint().map_err(BookError::Context)?;
        let path = rooted_path(path);
        let parent = path.parent().ok_or_else(|| {
            BookError::Io(
                path.clone(),
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "key path has no parent"),
            )
        })?;
        let name = path.file_name().ok_or_else(|| {
            BookError::Io(
                path.clone(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "key path has no file name",
                ),
            )
        })?;
        // `file_name` normalizes trailing separators and `.` components. They
        // designate a directory to the filesystem and must not become a file
        // when we bind the parent to its canonical path.
        if !path
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(name.as_encoded_bytes())
        {
            return Err(BookError::Io(
                path.clone(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "key path must end with a file name",
                ),
            ));
        }
        let directory = DurableDirectory::open_existing(cx, vfs.clone(), parent)
            .await
            .map_err(|e| BookError::Io(parent.to_path_buf(), e))?;
        let path = directory.path().join(name);
        let text = format!(
            "{}\n{}\n{}\n",
            hex(self.inner.k_oid()),
            hex(&self.namespace()),
            hex(self.inner.dek())
        );
        let opts = OpenOptions::new().write(true).create_new(true);
        #[cfg(unix)]
        let opts = opts.mode(0o600);
        cx.with_restriction_async(async {
            let mut file = match vfs.open(&path, &opts).await {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(BookError::KeyFile(format!(
                        "{} already exists; keys are never overwritten",
                        path.display()
                    )));
                }
                Err(e) => return Err(BookError::Io(path.clone(), e)),
            };
            file.write_all(text.as_bytes())
                .await
                .map_err(|e| BookError::Io(path.clone(), e))?;
            sync_file(&mut file)
                .await
                .map_err(|e| BookError::Io(path.clone(), e))?;
            cx.checkpoint().map_err(BookError::Context)?;
            let mut handle = vfs
                .open(directory.path(), &OpenOptions::new().read(true))
                .await
                .map_err(|e| BookError::Io(directory.path().to_path_buf(), e))?;
            sync_file(&mut handle)
                .await
                .map_err(|e| BookError::Io(directory.path().to_path_buf(), e))?;
            Ok(())
        })
        .await
    }

    /// Read a key file written by [`BookKeys::save`].
    pub fn load(path: &Path) -> Result<Self, BookError> {
        let (runtime, root) = Book::runtime_and_root()?;
        let cx = PurposeContexts::narrow_runtime_root(&root);
        runtime.block_on(Self::load_with_vfs(&cx.query(), &UnixVfs, path))
    }

    /// Read keys through the caller's filesystem and read context.
    pub async fn load_with_vfs<V: Vfs>(
        cx: &QueryCx,
        vfs: &V,
        path: &Path,
    ) -> Result<Self, BookError> {
        cx.checkpoint().map_err(BookError::Context)?;
        let path = rooted_path(path);
        let text = cx
            .with_restriction_async(vfs.read_to_string(&path))
            .await
            .map_err(|e| BookError::Io(path.to_path_buf(), e))?;
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
    pub(crate) fn seal_key(&self) -> SealKey {
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
    Context(Box<asupersync::error::Error>),
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
            Self::Context(_)
            | Self::Kernel(_)
            | Self::Registers(_)
            | Self::Registry(_)
            | Self::Entropy(_) => fa_journal::exit::FOUNDATION,
        }
    }
}

impl fmt::Display for BookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "runtime: {e}"),
            Self::Context(e) => write!(f, "execution context: {e}"),
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
    Memory(AsyncBook<MemVfs>),
    Dir(AsyncBook<UnixVfs>),
    ScratchDir(AsyncBook<MemVfs, UnixVfs>),
}
/// Dispatch to the same async implementation for either production VFS.
macro_rules! with_store {
    ($store:expr, $db:ident => $body:expr) => {
        match $store {
            Store::Memory($db) => $body,
            Store::Dir($db) => $body,
            Store::ScratchDir($db) => $body,
        }
    };
}

/// One open book.
pub struct Book {
    runtime: Runtime,
    root: Cx,
    store: Store,
}

impl Book {
    fn runtime_and_root() -> Result<(Runtime, Cx), BookError> {
        let runtime = RuntimeBuilder::new()
            .build()
            .map_err(|e| BookError::Runtime(format!("{e:?}")))?;
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        Ok((runtime, root))
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
        let vfs = purposes
            .commit()
            .with_restriction(MemVfs::new)
            .map_err(|e| BookError::Io(PathBuf::from("book"), e))?;
        let core = runtime.block_on(AsyncBook::create_with_vfs(
            &purposes,
            vfs,
            Path::new("book"),
            keys,
            spec,
            entropy,
        ))?;
        Ok(Self {
            runtime,
            root,
            store: Store::Memory(core),
        })
    }

    /// Create a directory book at `<dir>/store` (`dir` is created if absent).
    pub fn create_dir(
        dir: &Path,
        keys: BookKeys,
        spec: BookSpec,
        entropy: Entropy,
    ) -> Result<Self, BookError> {
        let (runtime, root) = Self::runtime_and_root()?;
        let purposes = PurposeContexts::narrow_runtime_root(&root);
        let core = runtime.block_on(AsyncBook::create_with_vfs(
            &purposes,
            UnixVfs::new(),
            dir,
            keys,
            spec,
            entropy,
        ))?;
        Ok(Self {
            runtime,
            root,
            store: Store::Dir(core),
        })
    }

    /// Open the directory book at `<dir>/store`, rebuilding the context from
    /// the spec journaled at genesis.
    pub fn open_dir(dir: &Path, keys: BookKeys, entropy: Entropy) -> Result<Self, BookError> {
        let (runtime, root) = Self::runtime_and_root()?;
        let purposes = PurposeContexts::narrow_runtime_root(&root);
        let core = runtime.block_on(AsyncBook::open_with_vfs(
            &purposes,
            UnixVfs::new(),
            dir,
            keys,
            entropy,
        ))?;
        Ok(Self {
            runtime,
            root,
            store: Store::Dir(core),
        })
    }

    #[must_use]
    pub fn context(&self) -> &BookContext {
        with_store!(&self.store, core => core.context())
    }

    /// The book's head: the latest recorded sequence, which a read at head
    /// observes and a write's result follows (the robot envelope's
    /// `coordinate.known_at`, plan Appendix D). Read-only.
    pub fn head(&self) -> Result<CommitSeq, BookError> {
        with_store!(&self.store, core => core.head(&self.purposes()))
    }

    fn purposes(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    /// Seal a description or memo under the book key with fresh salt and nonce.
    pub fn seal_text(&self, text: &str) -> Result<Erasable<String>, BookError> {
        with_store!(&self.store, core => core.seal_text(&self.purposes(), text))
    }

    /// Install a chart as one journaled schema effect (plan §4.3).
    pub fn install_chart(
        &mut self,
        accounts: &[AccountSpec],
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<ChartInstalled> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.install_chart(
            &purposes, accounts, principal, effective_date, idempotency_key,
        )))
    }

    /// Create one fiscal year's periods in state `Future`.
    pub fn create_periods(
        &mut self,
        fiscal_year: i32,
    ) -> Result<(CommitSeq, Vec<PeriodDef>), BookError> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.create_periods(&purposes, fiscal_year)))
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
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.transition_period(
            &purposes, period_code, t, principal, reason_code, effective_date, idempotency_key, capability,
        )))
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
        with_store!(&self.store, core => core.plan_transition(
            &self.purposes(), period_code, t, principal, reason_code, effective_date, idempotency_key,
        ))
    }

    /// The digest an approval of `plan` binds.
    pub fn plan_digest(&self, plan: &fa_journal::TransitionPlan) -> Result<[u8; 32], BookError> {
        with_store!(&self.store, core => core.plan_digest(plan))
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
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.transition_planned(
            &purposes, plan, t, capability, approvals,
        )))
    }

    /// Record an approval of `proposal_digest` under `capability` (plan
    /// §14.3): a journaled object bound to the digest and the current
    /// security policy epoch. The capability must hold `approve`.
    pub fn approve(
        &mut self,
        capability: fa_journal::Capability,
        proposal_digest: [u8; 32],
    ) -> Outcome<fa_journal::Approved> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.approve(&purposes, capability, proposal_digest)))
    }

    /// Post one entry under the accounting laws (plan §5).
    pub fn post(&mut self, req: PostRequest) -> Outcome<Posted> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.post(&purposes, req)))
    }

    /// Post with a balancing leg (plan §5.5): leg `leg` moves at most what its
    /// account's limit admits, decided inside the posting transaction; the
    /// request is the entry's identity (`fa post --balancing`).
    pub fn post_balancing(&mut self, req: PostRequest, leg: u16) -> Outcome<fa_journal::Balanced> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.post_balancing(&purposes, req, leg)))
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
        with_store!(&mut self.store, core => self.runtime.block_on(core.open_migration_run(&purposes, body, req)))
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
        with_store!(&self.store, core => core.plan_migration_transition(
            &self.purposes(), run, control_kind, principal, idempotency_key, description,
        ))
    }

    /// Finalize or abandon a migration run (one control record).
    pub fn transition_migration_run(
        &mut self,
        req: fa_journal::RunControlRequest,
    ) -> Outcome<fa_journal::RunControlled> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.transition_migration_run(&purposes, req)))
    }

    /// The migration run at `run`, as of `known_at` (head when `None`).
    pub fn migration_run(
        &self,
        run: VId,
        known_at: Option<CommitSeq>,
    ) -> Result<Option<fa_journal::Run>, BookError> {
        with_store!(&self.store, core => core.migration_run(&self.purposes(), run, known_at))
    }

    /// Replay this book's accounting history through `prefix` (head when
    /// `None`) into a fresh in-memory scratch book (plan §15.2): the same
    /// objects, byte for byte, one scratch commit per source commit that
    /// carries any, under the scratch book's own commit sequences. Returns
    /// the scratch book (its database opened with `keys`, sealing with
    /// `entropy`) and the [`fa_journal::SeqMap`] binding the two histories.
    /// External documents remain in the source's immutable blob store;
    /// that store must remain available for subsequent scratch reads.
    pub fn replay_into_scratch(
        &mut self,
        prefix: Option<CommitSeq>,
        keys: BookKeys,
        entropy: Entropy,
    ) -> Outcome<(Book, fa_journal::SeqMap)> {
        let (scratch_runtime, scratch_root) = Self::runtime_and_root()?;
        let scratch_purposes = PurposeContexts::narrow_runtime_root(&scratch_root);
        let db = scratch_runtime.block_on(async {
            Database::open_memory(&scratch_purposes.commit(), keys.inner.clone()).await
        })?;
        let replayed = match &mut self.store {
            Store::Memory(core) => scratch_runtime
                .block_on(core.replay_into(&scratch_purposes, db, prefix, entropy))?
                .map(|(copy, map)| (Store::Memory(copy), map)),
            Store::Dir(core) => scratch_runtime
                .block_on(core.replay_into(&scratch_purposes, db, prefix, entropy))?
                .map(|(copy, map)| (Store::ScratchDir(copy), map)),
            Store::ScratchDir(core) => scratch_runtime
                .block_on(core.replay_into(&scratch_purposes, db, prefix, entropy))?
                .map(|(copy, map)| (Store::ScratchDir(copy), map)),
        };
        let (store, map) = match replayed {
            Ok(replayed) => replayed,
            Err(r) => return Ok(Err(r)),
        };
        Ok(Ok((
            Book {
                runtime: scratch_runtime,
                root: scratch_root,
                store,
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
        with_store!(&self.store, source => with_store!(&scratch.store, copy => {
            source.verify_replay(&self.purposes(), copy, map)
        }))
    }

    /// Record a document (plan §9.1): content-addressed; the same bytes of
    /// the same kind are the recorded outcome. A document past the inline
    /// bound (`evidence_policy.toml max_document_bytes`) keeps its bytes in
    /// the book's blob store, its commitment inline.
    pub fn add_document(
        &mut self,
        doc: &fa_journal::Document,
    ) -> Outcome<fa_journal::DocumentAdded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.add_document(&purposes, doc)))
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
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.import_run(
            &purposes, capability, source, idempotency_key, effective_date, description, documents,
        )))
    }

    /// The receipt of the import run whose control entry is `run`.
    pub fn read_run(&self, run: VId) -> Result<Option<fa_journal::RunReceipt>, BookError> {
        with_store!(&self.store, core => core.read_run(&self.purposes(), run))
    }

    /// Hand the document at `document` on from the capability's holder (its
    /// current custodian) to `to`, as a journaled custody event.
    pub fn transfer_custody(
        &mut self,
        capability: &fa_journal::Capability,
        document: &fa_model::Oid,
        to: VId,
    ) -> Outcome<fa_journal::CustodyMoved> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.transfer_custody(
            &purposes, capability, document, to,
        )))
    }

    /// The document's chain of custody, verified, oldest first.
    pub fn custody_chain(
        &self,
        document: &fa_model::Oid,
    ) -> Result<Vec<(fa_journal::CustodyEvent, CommitSeq)>, BookError> {
        with_store!(&self.store, core => core.custody_chain(&self.purposes(), document))
    }

    /// Place a legal hold (plan §8.5) over `subjects` — entries, documents or
    /// parties of this book — on the authority of the document `authority`,
    /// as the capability's holder. Each held subject is pinned against
    /// erasure, garbage collection and retention expiry until the hold is
    /// released.
    pub fn place_legal_hold(
        &mut self,
        capability: &fa_journal::Capability,
        subjects: Vec<VId>,
        authority: &fa_model::Oid,
        idempotency_key: &[u8],
        effective_date: DateDay,
        description: &str,
    ) -> Outcome<fa_journal::LegalHoldPlaced> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.place_legal_hold(
            &purposes, capability, subjects, authority, idempotency_key, effective_date, description,
        )))
    }

    /// Plan the release of `hold` by `principal` without committing: the
    /// hold must be active. Approvers bind [`Book::legal_hold_release_digest`];
    /// [`Book::release_legal_hold`] commits exactly the planned proposal.
    pub fn plan_legal_hold_release(
        &self,
        hold: VId,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<fa_journal::ReleasePlan> {
        with_store!(&self.store, core => core.plan_legal_hold_release(
            &self.purposes(), hold, principal, effective_date, idempotency_key,
        ))
    }

    /// The digest an approval of a planned release binds.
    pub fn legal_hold_release_digest(
        &self,
        plan: &fa_journal::ReleasePlan,
    ) -> Result<[u8; 32], BookError> {
        with_store!(&self.store, core => core.legal_hold_release_digest(plan))
    }

    /// Commit a planned release under `capability`, citing `approvals` of
    /// its digest (the `legal-hold-release` row: a Human other than the
    /// preparer).
    pub fn release_legal_hold(
        &mut self,
        plan: &fa_journal::ReleasePlan,
        capability: &fa_journal::Capability,
        approvals: &[fa_model::ApprovalRef],
    ) -> Outcome<fa_journal::LegalHoldReleased> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.release_legal_hold(
            &purposes, plan, capability, approvals,
        )))
    }

    /// The legal hold placed as `hold`, with its release if one is recorded.
    pub fn legal_hold(&self, hold: VId) -> Result<Option<fa_journal::LegalHold>, BookError> {
        with_store!(&self.store, core => core.legal_hold(&self.purposes(), hold))
    }

    /// Derive and record the redacted view of `oid` under the contract
    /// governing its kind (plan §9.6); the capability holds `privileged`.
    pub fn derive_redacted_view(
        &mut self,
        capability: &fa_journal::Capability,
        oid: &fa_model::Oid,
    ) -> Outcome<fa_journal::ViewDerived> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.derive_redacted_view(
            &purposes, capability, oid,
        )))
    }

    /// Read `oid` as `capability` may see it: the verified bytes when it
    /// reveals them or nothing is privileged, otherwise the redacted view.
    /// Document bytes have no ungated facade method (FA-INV-10, plan §9.6).
    ///
    /// ```
    /// let _ = fa::Book::read_document_for;
    /// ```
    ///
    /// ```compile_fail,E0599
    /// let _ = fa::Book::read_document;
    /// ```
    pub fn read_document_for(
        &mut self,
        capability: &fa_journal::Capability,
        oid: &fa_model::Oid,
    ) -> Outcome<fa_journal::DocumentRead> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.read_document_for(
            &purposes, capability, oid,
        )))
    }

    /// The legal holds active on `subject`, ascending.
    pub fn legal_holds_on(&self, subject: VId) -> Result<Vec<VId>, BookError> {
        with_store!(&self.store, core => core.legal_holds_on(&self.purposes(), subject))
    }

    /// The document's public commitment, without reading its byte payload.
    /// This is an identity-checked mirror for citation completion, not a
    /// payload verification; the posting kernel verifies cited documents.
    ///
    /// ```
    /// let _ = fa::Book::document_commitment;
    /// ```
    ///
    /// An ungated record would expose `Storage::Inline` bytes:
    ///
    /// ```compile_fail,E0599
    /// let _ = fa::Book::document_record;
    /// ```
    pub fn document_commitment(
        &mut self,
        oid: &fa_model::Oid,
    ) -> Result<Option<[u8; 32]>, BookError> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.document_commitment(&purposes, oid))
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
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.record_review(
            &purposes, capability, document, against,
        )))
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
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.record_manual_assertion(
            &purposes, capability, proposal, reason_code, statement,
        )))
    }

    /// Read a committed entry back by its derived identity, verifying its digests.
    pub fn read_entry(&self, vid: VId) -> Result<Option<(Entry, CommitSeq)>, BookError> {
        with_store!(&self.store, core => core.read_entry(&self.purposes(), vid))
    }

    /// Every period of the book in calendar order, with its current state.
    pub fn periods(&self) -> Result<Vec<PeriodRow>, BookError> {
        with_store!(&self.store, core => core.periods(&self.purposes()))
    }

    /// Timed holds reached by the latest committed tick and still pending.
    pub fn due_holds(&self) -> Result<Vec<fa_journal::DueHold>, BookError> {
        with_store!(&self.store, core => core.due_holds(&self.purposes()))
    }

    /// Scheduled reversals reached by the latest tick, with their status.
    pub fn due_reversals(&self) -> Result<Vec<fa_journal::DueReversal>, BookError> {
        with_store!(&self.store, core => core.due_reversals(&self.purposes()))
    }

    /// The latest committed TimeEvidence tick, if any.
    pub fn latest_tick(&self) -> Result<Option<fa_journal::Tick>, BookError> {
        with_store!(&self.store, core => core.latest_tick(&self.purposes()))
    }

    /// Journal the caller's clock observation under its context and
    /// capability. This adapter reads no clock and creates no runtime.
    pub async fn record_tick(
        &mut self,
        cx: &Cx,
        observed_utc_ns: u64,
        monotonic_ok: bool,
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::Ticked> {
        let purposes = PurposeContexts::narrow_runtime_root(cx);
        with_store!(&mut self.store, core => core.record_tick(
            &purposes, observed_utc_ns, monotonic_ok, capability,
        ).await)
    }

    /// Expire at most `max_batch` due holds under the caller's context and
    /// the book's System capability, through the shared async core.
    pub async fn sweep_expiry(
        &mut self,
        cx: &Cx,
        capability: &fa_journal::Capability,
        max_batch: usize,
    ) -> Outcome<Option<fa_journal::SweepBatch>> {
        let purposes = PurposeContexts::narrow_runtime_root(cx);
        with_store!(&mut self.store, core => core.sweep_expiry(&purposes, capability, max_batch).await)
    }

    /// Examine at most `max_batch` reached schedules under the caller's
    /// context, minting admissible reversals and reporting blocked ones.
    pub async fn sweep_reversals(
        &mut self,
        cx: &Cx,
        capability: &fa_journal::Capability,
        max_batch: usize,
    ) -> Outcome<Option<fa_journal::ReversalBatch>> {
        let purposes = PurposeContexts::narrow_runtime_root(cx);
        with_store!(&mut self.store, core => core.sweep_reversals(&purposes, capability, max_batch).await)
    }

    /// Drain expiry batches and then reversal batches under the latest
    /// tick. Each batch commits separately; a refusal stops further work.
    pub async fn sweep(
        &mut self,
        cx: &Cx,
        capability: &fa_journal::Capability,
        max_batch: usize,
    ) -> Outcome<fa_journal::Swept> {
        let purposes = PurposeContexts::narrow_runtime_root(cx);
        with_store!(&mut self.store, core => core.sweep(&purposes, capability, max_batch).await)
    }

    /// Every account of the chart, sorted by code.
    pub fn accounts(&self) -> Result<Vec<AccountRow>, BookError> {
        with_store!(&self.store, core => core.accounts(&self.purposes()))
    }

    /// The register fold of one period (plan §5.3).
    pub fn fold_period(&self, period_code: &str) -> Result<Fold, BookError> {
        with_store!(&self.store, core => core.fold_period(&self.purposes(), period_code))
    }

    /// Materialize a period's registers from a fresh fold.
    pub fn materialize_registers(
        &mut self,
        period_code: &str,
    ) -> Result<(Fold, CommitSeq), BookError> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.materialize_registers(&purposes, period_code)))
    }

    /// Refold a period and compare it to its stored registers (`fa verify registers`).
    pub fn verify_registers(&self, period_code: &str) -> Result<Verification, BookError> {
        with_store!(&self.store, core => core.verify_registers(&self.purposes(), period_code))
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
        with_store!(&mut self.store, core => self.runtime.block_on(core.advance_registers(&purposes, period_code)))
    }

    /// Replace native posted/pending period registers and their maintenance
    /// cursor by a fresh journal fold, atomically. Authoritative objects are
    /// never changed. Reports continue to use their independent literal fold.
    pub fn rebuild_registers(
        &mut self,
        period_code: &str,
    ) -> Result<fa_registers::Advance, BookError> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.rebuild_registers(&purposes, period_code)))
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
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.checkpoint(&purposes, principal, capability)))
    }

    /// Recompute every accumulator state from its journal prefix.
    /// This reads the whole open embedded book, like the other current read
    /// methods; scoped session admission is not implemented here. The result
    /// verifies entry prefixes, without signatures or document-receipt claims.
    pub fn verify_accumulator(&self) -> Result<fa_notary::AccumulatorVerification, BookError> {
        with_store!(&self.store, core => core.verify_accumulator(&self.purposes()))
    }

    /// Open items (plan §5.7): every leg of a live posted entry, optionally
    /// on one account, with its applications and open amount.
    pub fn open_items(
        &self,
        account: Option<VId>,
        known_at: Option<CommitSeq>,
    ) -> Result<Vec<OpenItem>, BookError> {
        with_store!(&self.store, core => core.open_items(&self.purposes(), account, known_at))
    }

    /// Compare every posted leg's `applied` mirror with the open-item fold.
    pub fn verify_open_items(&self) -> Result<OpenItemVerification, BookError> {
        with_store!(&self.store, core => core.verify_open_items(&self.purposes()))
    }

    /// Refold every limited account's `LimitCell` from the journal and
    /// compare it with the stored cell (`fa verify availability`, plan
    /// §5.4–5.5). Drift is a finding, never a repair.
    pub fn verify_availability(&self) -> Result<AvailabilityVerification, BookError> {
        with_store!(&self.store, core => core.verify_availability(&self.purposes()))
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
        with_store!(&self.store, core => core.explain_balance(&self.purposes(), account, period_code, known_at))
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
        with_store!(&self.store, core => core.trial_balance_at(&self.purposes(), periods, known_at))
    }

    /// Stock balances through an inclusive civil date, including opening history.
    pub fn balance_as_of(
        &self,
        day: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        with_store!(&self.store, core => core.balance_as_of(&self.purposes(), day, known_at))
    }

    /// Literal movements in the selected periods, with each period counted once.
    /// This does not apply income-statement class exclusions.
    pub fn period_activity(
        &self,
        periods: &[String],
        known_at: Option<CommitSeq>,
    ) -> Result<TrialBalance, BookError> {
        with_store!(&self.store, core => core.period_activity(&self.purposes(), periods, known_at))
    }
}

impl fmt::Debug for Book {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Book({:?}, calendar {})",
            self.context().book_id,
            self.context().calendar.id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_book::BOOK_BLOB_STORE;
    use asupersync::lab::{AutoAdvanceTermination, LabConfig, LabRuntime};
    use asupersync::types::CancelKind;
    use fa_journal::{Capability, UnitPolicy};
    use fa_model::{EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid};
    use fa_money::{Amount, Side};
    use fa_time::{FiscalCalendar, PeriodKind};
    use fgdb_sim::vfs::{FaultKind, FaultPlan, FaultVfs, Trigger};

    /// Storage-layout verification only: tests already own the book's keys
    /// and inspect its private database. Never exposed through the facade.
    fn storage_record(book: &Book, oid: &Oid) -> fa_journal::DocumentRecord {
        let query = book.purposes().query();
        query.checkpoint().unwrap();
        query.with_restriction(|| {
            with_store!(&book.store, core => fa_journal::document_record(&core.db, oid)
                .unwrap().expect("stored document"))
        })
    }

    fn under_lab<T, Fut>(seed: u64, test: impl FnOnce(Cx) -> Fut + Send + 'static) -> T
    where
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        lab_outcome(seed, test)
            .expect("join lab task")
            .expect("task finished")
    }

    fn under_cancelled_lab<Fut>(seed: u64, test: impl FnOnce(Cx) -> Fut + Send + 'static)
    where
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // The runtime gives cancellation precedence over a successful task
        // result. A cancelled join alone cannot prove that our assertions
        // ran: require the future to return after every assertion as well.
        let completed = Arc::new(AtomicBool::new(false));
        let completion = completed.clone();
        let outcome = lab_outcome(seed, move |root| async move {
            test(root).await;
            completion.store(true, Ordering::Release);
        });
        assert!(
            completed.load(Ordering::Acquire),
            "cancellation assertions did not finish"
        );
        assert!(
            matches!(outcome, Err(asupersync::runtime::JoinError::Cancelled(_))),
            "expected a cancelled task, got {outcome:?}"
        );
    }

    fn lab_outcome<T, Fut>(
        seed: u64,
        test: impl FnOnce(Cx) -> Fut + Send + 'static,
    ) -> Result<Option<T>, asupersync::runtime::JoinError>
    where
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).with_auto_advance());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, mut handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                test(Cx::current().expect("ambient lab context")).await
            })
            .expect("spawn lab task");
        runtime
            .scheduler
            .lock()
            .schedule(task, Budget::INFINITE.priority);
        let advanced = runtime.run_with_auto_advance();
        assert!(
            matches!(advanced.termination, AutoAdvanceTermination::Quiescent),
            "lab must quiesce: {advanced:?}"
        );
        let report = runtime.report();
        assert!(report.lab_test_passed(), "lab oracles: {report:?}");
        handle.try_join()
    }

    /// A bounded lifecycle smoke test of the real facade, not the full
    /// fa-0fl crash-point/DPOR campaign. Every filesystem sync is delayed by
    /// the lab timer, and every unfenced directory entry is lost at crash.
    fn lab_lifecycle(seed: u64) -> (Fold, [u8; 32], Vec<String>) {
        under_lab(seed, move |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let backing = cx.commit().with_restriction(MemVfs::new).unwrap();
            let vfs = FaultVfs::with_clock(
                backing,
                FaultPlan {
                    seed,
                    latency: Trigger::Always,
                    latency_micros: 7,
                    dirent_loss: Trigger::Always,
                    ..FaultPlan::faultless()
                },
                root,
            );
            let keys = BookKeys::for_development(0x61);
            let book_id = Id128([0x61; 16]);
            let (spec, usd) = spec(book_id);
            let dir = Path::new("nested/lab-book");
            let mut book = AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                dir,
                keys.clone(),
                spec,
                Entropy::deterministic(seed),
            )
            .await
            .expect("create under the caller's lab");
            let principal = VId(1);
            let day = DateDay::from_ymd(2026, 3, 15).unwrap();
            book.install_chart(&cx, &chart(usd), principal, day, b"chart")
                .await
                .unwrap()
                .unwrap();
            let (_, periods) = book.create_periods(&cx, 2026).await.unwrap();
            let march = periods
                .iter()
                .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
                .unwrap()
                .code
                .clone();
            book.transition_period(
                &cx,
                &march,
                PeriodTransition::Open,
                principal,
                1,
                day,
                b"open",
                &Capability::embedded(principal, &["close"]).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
            let inline_bound = fa_registry::evidence_policy::EvidencePolicy::embedded()
                .unwrap()
                .max_document_bytes;
            let source = fa_journal::Document {
                book_id,
                kind: 1,
                mime: "application/octet-stream".into(),
                grade: 3,
                retrieved_by: principal,
                bytes: vec![0x61; usize::try_from(inline_bound).unwrap() + 1],
            };
            book.add_document(&cx, &source).await.unwrap().unwrap();
            let evidence = source.evidence_ref(1);
            let legs = vec![
                LegPayload::simple(
                    Side::Debit,
                    account_vid(book_id, "6000"),
                    Amount::new(usd, 150_000),
                ),
                LegPayload::simple(
                    Side::Credit,
                    account_vid(book_id, "1000"),
                    Amount::new(usd, 150_000),
                ),
            ];
            let proposal = EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: day,
                document_date: None,
                description: book.seal_text(&cx, "lab rent").unwrap(),
                effective_period: None,
                unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
                legs,
                control: None,
                base_totals: None,
                idempotency_key: b"lab-rent".to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                principal_ref: principal,
                session_ref: None,
                evidence: vec![evidence],
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            let request = PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(principal, &["post"]).unwrap(),
            };
            let posted = book.post(&cx, request.clone()).await.unwrap().unwrap();
            let before = book.advance_registers(&cx, &march).await.unwrap().fold;
            assert_eq!(before.entries, 1);
            assert_eq!(before.period, march);
            assert_eq!(before.watermark, Some(posted.recorded_at()));
            assert!(before.pending.is_empty());
            let mut expected_cells = vec![
                fa_registers::Cell {
                    key: fa_registers::CellKey {
                        account: account_vid(book_id, "6000"),
                        unit_id: usd.0,
                        period: march.clone(),
                    },
                    debits: 150_000,
                    credits: 0,
                    entry_count: 1,
                },
                fa_registers::Cell {
                    key: fa_registers::CellKey {
                        account: account_vid(book_id, "1000"),
                        unit_id: usd.0,
                        period: march.clone(),
                    },
                    debits: 0,
                    credits: 150_000,
                    entry_count: 1,
                },
            ];
            expected_cells.sort_by(|a, b| a.key.cmp(&b.key));
            assert_eq!(before.cells, expected_cells);
            assert_eq!(before, book.fold_period(&cx, &march).unwrap());
            assert!(book.verify_registers(&cx, &march).unwrap().is_green());
            assert!(
                book.trial_balance(&cx, std::slice::from_ref(&march))
                    .unwrap()
                    .is_balanced()
            );
            drop(book);
            cx.commit()
                .with_restriction_async(vfs.crash())
                .await
                .unwrap();
            let mut book =
                AsyncBook::open_with_vfs(&cx, vfs.clone(), dir, keys, Entropy::deterministic(seed))
                    .await
                    .expect("reopen after losing every unfenced name");
            let (entry, _) = book
                .read_entry(&cx, posted.entry_ref().vid)
                .unwrap()
                .unwrap();
            assert_eq!(entry.entry_digest, posted.entry_ref().entry_digest);
            assert_eq!(book.fold_period(&cx, &march).unwrap(), before);
            assert!(book.verify_registers(&cx, &march).unwrap().is_green());
            let reader = Capability::embedded(principal, &["read", "privileged"]).unwrap();
            let document = book
                .read_document_for(&cx, &reader, &evidence.document_oid)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(document, fa_journal::DocumentRead::Full(source.clone()));
            assert!(matches!(
                book.post(&cx, request).await.unwrap().unwrap(),
                Posted::AlreadyRecorded { .. }
            ));
            assert!(!book.advance_registers(&cx, &march).await.unwrap().wrote);
            let source_head = book.head(&cx).unwrap();
            let scratch_path = cx
                .commit()
                .with_restriction_async(vfs.canonicalize(Path::new(".")))
                .await
                .unwrap()
                .join("scratch-store");
            let scratch_db = Database::create_with_vfs(
                &cx.commit(),
                vfs.clone(),
                scratch_path.clone(),
                BookKeys::for_development(0x63).inner,
            )
            .await
            .unwrap();
            let replay_events_start = vfs.events().len();
            let (mut scratch, map) = book
                .replay_into(&cx, scratch_db, None, Entropy::deterministic(seed + 1))
                .await
                .unwrap()
                .unwrap();
            let verified = book.verify_replay(&cx, &scratch, &map).unwrap().unwrap();
            assert_eq!(verified.pairs_checked, map.pairs.len());
            assert_eq!(
                scratch.fold_period(&cx, &march).unwrap().cells,
                expected_cells
            );
            assert_eq!(
                scratch
                    .read_document_for(&cx, &reader, &evidence.document_oid)
                    .await
                    .unwrap()
                    .unwrap(),
                fa_journal::DocumentRead::Full(source)
            );
            assert_eq!(book.head(&cx).unwrap(), source_head);
            let events = vfs.events();
            assert!(events[replay_events_start..].iter().any(|e| {
                matches!(e.kind, FaultKind::Latency { .. }) && e.path.starts_with(&scratch_path)
            }));
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e.kind, FaultKind::Latency { .. })
                        && e.path.to_string_lossy().contains("store"))
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e.kind, FaultKind::Latency { .. })
                        && e.path.to_string_lossy().contains("blobs"))
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e.kind, FaultKind::DirentLoss { .. }))
            );
            // Staging filenames deliberately carry a process-local unique
            // counter; compare fault kinds and durable accounting outputs.
            (
                before,
                entry.entry_digest,
                events.iter().map(|e| format!("{:?}", e.kind)).collect(),
            )
        })
    }

    #[test]
    fn async_book_runs_and_replays_under_the_callers_lab_and_fault_vfs() {
        assert_eq!(lab_lifecycle(19), lab_lifecycle(19));
    }

    type LabBook = AsyncBook<FaultVfs<MemVfs>>;

    struct PreparedFixture {
        book: LabBook,
        vfs: FaultVfs<MemVfs>,
        request: PostRequest,
        march: String,
        april: String,
        usd: fa_money::UnitId,
    }

    async fn prepared_fixture(root: &Cx, seed: u64) -> PreparedFixture {
        let cx = PurposeContexts::narrow_runtime_root(root);
        let backing = cx.commit().with_restriction(MemVfs::new).unwrap();
        let vfs = FaultVfs::with_clock(
            backing,
            FaultPlan {
                seed,
                latency: Trigger::Always,
                latency_micros: 1,
                ..FaultPlan::faultless()
            },
            root.clone(),
        );
        let book_id = Id128([0x69; 16]);
        let (mut spec, usd) = spec(book_id);
        spec.time_zone_policy = Some(fa_journal::TimeZonePolicy::Utc);
        let mut book = AsyncBook::create_with_vfs(
            &cx,
            vfs.clone(),
            Path::new("./prepared-book"),
            BookKeys::for_development(0x69),
            spec,
            Entropy::deterministic(seed),
        )
        .await
        .unwrap();
        let principal = VId(1);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        book.install_chart(&cx, &chart(usd), principal, day, b"chart")
            .await
            .unwrap()
            .unwrap();
        let (_, periods) = book.create_periods(&cx, 2026).await.unwrap();
        let period = |date| {
            periods
                .iter()
                .find(|p| p.kind == PeriodKind::Normal && p.contains(date))
                .unwrap()
                .code
                .clone()
        };
        let march = period(day);
        let april = period(DateDay::from_ymd(2026, 4, 1).unwrap());
        book.transition_period(
            &cx,
            &march,
            PeriodTransition::Open,
            principal,
            1,
            day,
            b"open-march",
            &Capability::embedded(principal, &["close"]).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let document = fa_journal::Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: principal,
            bytes: b"Invoice: March rent, USD 1500.00".to_vec(),
        };
        book.add_document(&cx, &document).await.unwrap().unwrap();
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "6000"),
                Amount::new(usd, 150_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "1000"),
                Amount::new(usd, 150_000),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day,
            document_date: None,
            description: book.seal_text(&cx, "prepared March rent").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: b"prepared-rent".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: principal,
            session_ref: None,
            evidence: vec![document.evidence_ref(1)],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        PreparedFixture {
            book,
            vfs,
            request: PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(principal, &["post"]).unwrap(),
            },
            march,
            april,
            usd,
        }
    }

    fn prepare_fixture_post(
        book: &mut LabBook,
        cx: &PurposeContexts,
        request: PostRequest,
    ) -> Box<fa_journal::post::PreparedPost> {
        let context = book.context().clone();
        match fa_journal::post::prepare_post(&mut book.db, cx, &context, request)
            .unwrap()
            .unwrap()
        {
            fa_journal::post::PostPreparation::Ready(prepared) => Some(prepared),
            fa_journal::post::PostPreparation::AlreadyRecorded(_) => None,
        }
        .expect("fixture must prepare a fresh transaction")
    }

    fn prepare_fixture_transition(
        book: &mut LabBook,
        cx: &PurposeContexts,
        period: &str,
        transition: PeriodTransition,
        capability: &Capability,
    ) -> fa_journal::period::PreparedTransition {
        let context = book.context().clone();
        let description = book.seal_text(cx, "prepared period transition").unwrap();
        fa_journal::period::prepare_transition(
            &mut book.db,
            cx,
            &context,
            period,
            transition,
            VId(1),
            1,
            DateDay::from_ymd(2026, 3, 15).unwrap(),
            b"prepared-transition",
            description,
            capability,
            &[],
        )
        .unwrap()
        .unwrap()
    }

    fn journal_entries(book: &LabBook, cx: &PurposeContexts) -> Vec<(VId, Entry, CommitSeq)> {
        let mut entries: Vec<_> = cx
            .query()
            .with_restriction(|| book.db.vertices())
            .unwrap()
            .into_iter()
            .filter(|row| row.labels.contains(&fa_model::symbols::label::ENTRY))
            .map(|row| {
                let (entry, at) = book.read_entry(cx, row.vid).unwrap().unwrap();
                (row.vid, entry, at)
            })
            .collect();
        entries.sort_by_key(|(vid, _, _)| *vid);
        entries
    }

    fn assert_rent_cells(fold: &Fold, book_id: Id128, usd: fa_money::UnitId, reversed: bool) {
        assert_eq!(fold.entries, 1);
        assert!(fold.pending.is_empty());
        let mut expected = vec![
            fa_registers::Cell {
                key: fa_registers::CellKey {
                    account: account_vid(book_id, "6000"),
                    unit_id: usd.0,
                    period: fold.period.clone(),
                },
                debits: if reversed { 0 } else { 150_000 },
                credits: if reversed { 150_000 } else { 0 },
                entry_count: 1,
            },
            fa_registers::Cell {
                key: fa_registers::CellKey {
                    account: account_vid(book_id, "1000"),
                    unit_id: usd.0,
                    period: fold.period.clone(),
                },
                debits: if reversed { 150_000 } else { 0 },
                credits: if reversed { 0 } else { 150_000 },
                entry_count: 1,
            },
        ];
        expected.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(fold.cells, expected);
    }

    fn drive_prepared_lab(runtime: &mut LabRuntime) {
        let advanced = runtime.run_with_auto_advance();
        assert!(
            matches!(advanced.termination, AutoAdvanceTermination::Quiescent),
            "prepared transaction lab must finish: {advanced:?}"
        );
        let report = runtime.report();
        assert!(report.lab_test_passed(), "prepared lab oracles: {report:?}");
    }

    /// Both original transactions survive the rendezvous. Only the database
    /// handle is serialized; neither witness set is refreshed before commit.
    fn prepared_post_close_race(runtime: &mut LabRuntime) -> bool {
        use asupersync::sync::{Barrier, Mutex, OwnedMutexGuard};
        use std::sync::Arc;

        let seed = runtime.config().seed;
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (setup, mut setup_handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let root = Cx::current().unwrap();
                let fixture = prepared_fixture(&root, seed).await;
                let cx = PurposeContexts::narrow_runtime_root(&root);
                let basis = fixture.book.head(&cx).unwrap();
                let entries = journal_entries(&fixture.book, &cx).len();
                (fixture, basis, entries)
            })
            .unwrap();
        runtime.scheduler.lock().schedule(setup, 0);
        drive_prepared_lab(runtime);
        let (fixture, basis, entries) = setup_handle.try_join().unwrap().unwrap();
        let PreparedFixture {
            book,
            vfs,
            request,
            march,
            usd,
            ..
        } = fixture;
        let store_path = book.db.path().to_path_buf();
        let race_events_start = vfs.events().len();
        let shared = Arc::new(Mutex::new(book));
        let barrier = Arc::new(Barrier::new(2));
        let post_book = Arc::clone(&shared);
        let post_barrier = Arc::clone(&barrier);
        let retry = request.clone();
        let (post_task, mut post_handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let root = Cx::current().unwrap();
                let cx = PurposeContexts::narrow_runtime_root(&root);
                let prepared = {
                    let mut book = post_book.lock(&root).await.unwrap();
                    prepare_fixture_post(&mut book, &cx, request)
                };
                let basis = prepared.basis();
                post_barrier.wait(&root).await.unwrap();
                asupersync::runtime::yield_now().await;
                let outcome = {
                    let mut book = OwnedMutexGuard::lock(post_book, &root).await.unwrap();
                    prepared.commit(&mut book.db, &cx).await.unwrap()
                };
                (basis, outcome)
            })
            .unwrap();
        let close_book = Arc::clone(&shared);
        let close_period = march.clone();
        let (close_task, mut close_handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let root = Cx::current().unwrap();
                let cx = PurposeContexts::narrow_runtime_root(&root);
                let prepared = {
                    let mut book = close_book.lock(&root).await.unwrap();
                    prepare_fixture_transition(
                        &mut book,
                        &cx,
                        &close_period,
                        PeriodTransition::SoftClose,
                        &Capability::embedded(VId(1), &["close"]).unwrap(),
                    )
                };
                let basis = prepared.basis();
                barrier.wait(&root).await.unwrap();
                asupersync::runtime::yield_now().await;
                let outcome = {
                    let mut book = OwnedMutexGuard::lock(close_book, &root).await.unwrap();
                    prepared.commit(&mut book.db, &cx).await.unwrap()
                };
                (basis, outcome)
            })
            .unwrap();
        {
            let mut scheduler = runtime.scheduler.lock();
            scheduler.schedule(post_task, 0);
            scheduler.schedule(close_task, 0);
        }
        drive_prepared_lab(runtime);
        assert!(vfs.events()[race_events_start..].iter().any(|event| {
            matches!(event.kind, FaultKind::Latency { .. }) && event.path.starts_with(&store_path)
        }));
        let (post_basis, post) = post_handle.try_join().unwrap().unwrap();
        let (close_basis, close) = close_handle.try_join().unwrap().unwrap();
        assert_eq!((post_basis, close_basis), (basis, basis));
        let post_won = match (&post, &close) {
            (Ok(Posted::Committed { recorded_at, .. }), Err(refusal)) => {
                assert_eq!(*recorded_at, CommitSeq(basis.0 + 1));
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-030", 6));
                Some(true)
            }
            (Err(refusal), Ok(closed)) => {
                assert_eq!(closed.recorded_at, CommitSeq(basis.0 + 1));
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-030", 6));
                Some(false)
            }
            _ => None,
        };
        assert!(
            post_won.is_some(),
            "seed {seed}: expected one commit and one witness conflict: {:?}",
            (&post, &close)
        );
        let post_won = post_won.expect("the asserted outcome identifies one winner");
        let (verify, mut verify_handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let root = Cx::current().unwrap();
                let cx = PurposeContexts::narrow_runtime_root(&root);
                let mut book = OwnedMutexGuard::lock(shared, &root).await.unwrap();
                assert_eq!(book.head(&cx).unwrap(), CommitSeq(basis.0 + 1));
                assert_eq!(journal_entries(&book, &cx).len(), entries + 1);
                let proposed_vid = fa_model::entry_vid(
                    retry.proposal.book_id,
                    &retry.proposal.principal_ref.0.to_le_bytes(),
                    &retry.proposal.idempotency_key,
                );
                let stored = book.read_entry(&cx, proposed_vid).unwrap();
                assert_eq!(stored.is_some(), post_won);
                if let Some((entry, at)) = stored {
                    assert_eq!(entry.proposal, retry.proposal);
                    assert_eq!(at, CommitSeq(basis.0 + 1));
                }
                if post_won {
                    let before = book.head(&cx).unwrap();
                    assert!(matches!(
                        book.post(&cx, retry).await.unwrap().unwrap(),
                        Posted::AlreadyRecorded { .. }
                    ));
                    assert_eq!(book.head(&cx).unwrap(), before);
                    // A new close after the posting is a legal serial history.
                    let fresh = prepare_fixture_transition(
                        &mut book,
                        &cx,
                        &march,
                        PeriodTransition::SoftClose,
                        &Capability::embedded(VId(1), &["close"]).unwrap(),
                    );
                    fresh.commit(&mut book.db, &cx).await.unwrap().unwrap();
                    assert_eq!(journal_entries(&book, &cx).len(), entries + 2);
                }
                assert_eq!(
                    book.periods(&cx)
                        .unwrap()
                        .iter()
                        .find(|p| p.code == march)
                        .unwrap()
                        .state,
                    fa_time::PeriodState::SoftClosed,
                );
                let fold = book.advance_registers(&cx, &march).await.unwrap().fold;
                if post_won {
                    assert_rent_cells(&fold, book.context().book_id, usd, false);
                    assert_eq!(fold.watermark, Some(CommitSeq(basis.0 + 1)));
                } else {
                    assert_eq!(fold.entries, 0);
                    assert!(fold.cells.is_empty() && fold.pending.is_empty());
                    assert_eq!(fold.watermark, None);
                }
                assert_eq!(fold, book.fold_period(&cx, &march).unwrap());
                assert!(book.verify_registers(&cx, &march).unwrap().is_green());
                let head = book.head(&cx).unwrap();
                let scratch_path = cx
                    .commit()
                    .with_restriction_async(vfs.canonicalize(Path::new(".")))
                    .await
                    .unwrap()
                    .join("race-replay");
                let scratch_db = Database::create_with_vfs(
                    &cx.commit(),
                    vfs.clone(),
                    scratch_path.clone(),
                    BookKeys::for_development(0x6a).inner,
                )
                .await
                .unwrap();
                let replay_events_start = vfs.events().len();
                let (scratch, map) = book
                    .replay_into(&cx, scratch_db, None, Entropy::deterministic(seed + 100))
                    .await
                    .unwrap()
                    .unwrap();
                let verified = book.verify_replay(&cx, &scratch, &map).unwrap().unwrap();
                assert!(!map.pairs.is_empty());
                assert_eq!(verified.pairs_checked, map.pairs.len());
                let replayed = scratch.fold_period(&cx, &march).unwrap();
                assert_eq!(replayed.cells, fold.cells);
                assert_eq!(replayed.pending, fold.pending);
                assert_eq!(replayed.entries, fold.entries);
                let source_entries = journal_entries(&book, &cx);
                let replay_entries = journal_entries(&scratch, &cx);
                assert_eq!(replay_entries.len(), source_entries.len());
                for ((source_vid, source, source_at), (replay_vid, replay, replay_at)) in
                    source_entries.iter().zip(&replay_entries)
                {
                    assert_eq!(replay_vid, source_vid);
                    assert_eq!(replay, source);
                    assert_eq!(
                        *replay_at,
                        map.pairs
                            .iter()
                            .find(|pair| pair.source_seq == *source_at)
                            .expect("every replayed entry has a mapped creating commit")
                            .scratch_seq,
                    );
                }
                assert_eq!(
                    replayed.watermark,
                    fold.watermark.map(|at| {
                        map.pairs
                            .iter()
                            .find(|pair| pair.source_seq == at)
                            .expect("the contributing commit must be replayed")
                            .scratch_seq
                    })
                );
                assert_eq!(book.head(&cx).unwrap(), head);
                let events = vfs.events();
                assert!(events[replay_events_start..].iter().any(|e| {
                    matches!(e.kind, FaultKind::Latency { .. }) && e.path.starts_with(&scratch_path)
                }));
            })
            .unwrap();
        runtime.scheduler.lock().schedule(verify, 0);
        drive_prepared_lab(runtime);
        verify_handle.try_join().unwrap().unwrap();
        post_won
    }

    #[test]
    fn prepared_post_and_close_preserve_witnesses_under_16_lab_schedules() {
        use asupersync::lab::{ExplorerConfig, ScheduleExplorer};
        use std::cell::RefCell;

        // A bounded seed sweep, not exhaustive DPOR. Coverage is observed
        // from real commit outcomes, not inferred from the number of runs.
        let winners = RefCell::new(std::collections::BTreeSet::new());
        let mut explorer = ScheduleExplorer::new(
            ExplorerConfig::new(0, 16)
                .worker_count(2)
                .max_steps(100_000),
        );
        let report = explorer.explore(|runtime| {
            winners
                .borrow_mut()
                .insert(prepared_post_close_race(runtime));
        });
        assert!(!report.has_violations(), "{report:?}");
        assert_eq!(report.total_runs, 16);
        assert_eq!(
            winners.into_inner(),
            std::collections::BTreeSet::from([false, true])
        );
    }

    async fn unrelated_document(book: &mut LabBook, cx: &PurposeContexts) {
        book.add_document(
            cx,
            &fa_journal::Document {
                book_id: book.context().book_id,
                kind: 1,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: VId(1),
                bytes: b"A different invoice, unrelated to the prepared transaction".to_vec(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[test]
    fn prepared_post_rechecks_its_capability_expiry_without_rejecting_unrelated_commits() {
        for expires_in in [1, 3] {
            under_lab(61 + expires_in, move |root| async move {
                let cx = PurposeContexts::narrow_runtime_root(&root);
                let mut fixture = prepared_fixture(&root, 61 + expires_in).await;
                let basis = fixture.book.head(&cx).unwrap();
                fixture.request.capability = fixture
                    .request
                    .capability
                    .expiring_at(CommitSeq(basis.0 + expires_in));
                let prepared = prepare_fixture_post(&mut fixture.book, &cx, fixture.request);
                assert_eq!(prepared.basis(), basis);
                unrelated_document(&mut fixture.book, &cx).await;
                let before = fixture.book.head(&cx).unwrap();
                assert_eq!(before, CommitSeq(basis.0 + 1));
                let entries = journal_entries(&fixture.book, &cx);
                let result = prepared.commit(&mut fixture.book.db, &cx).await.unwrap();
                if expires_in == 1 {
                    let refusal = result.unwrap_err();
                    assert_eq!((refusal.code, refusal.exit), ("FA-REF-014", 7));
                    assert_eq!(fixture.book.head(&cx).unwrap(), before);
                    assert_eq!(journal_entries(&fixture.book, &cx), entries);
                    assert!(
                        fixture
                            .book
                            .fold_period(&cx, &fixture.march)
                            .unwrap()
                            .cells
                            .is_empty()
                    );
                } else {
                    assert_eq!(result.unwrap().recorded_at(), CommitSeq(before.0 + 1));
                    assert_eq!(journal_entries(&fixture.book, &cx).len(), entries.len() + 1);
                    let fold = fixture
                        .book
                        .advance_registers(&cx, &fixture.march)
                        .await
                        .unwrap()
                        .fold;
                    assert_rent_cells(&fold, fixture.book.context().book_id, fixture.usd, false);
                    assert!(
                        fixture
                            .book
                            .verify_registers(&cx, &fixture.march)
                            .unwrap()
                            .is_green()
                    );
                }
            });
        }
    }

    #[test]
    fn prepared_transition_rechecks_its_capability_expiry_without_rejecting_unrelated_commits() {
        for expires_in in [1, 3] {
            under_lab(71 + expires_in, move |root| async move {
                let cx = PurposeContexts::narrow_runtime_root(&root);
                let mut fixture = prepared_fixture(&root, 71 + expires_in).await;
                let basis = fixture.book.head(&cx).unwrap();
                let capability = Capability::embedded(VId(1), &["close"])
                    .unwrap()
                    .expiring_at(CommitSeq(basis.0 + expires_in));
                let prepared = prepare_fixture_transition(
                    &mut fixture.book,
                    &cx,
                    &fixture.march,
                    PeriodTransition::SoftClose,
                    &capability,
                );
                assert_eq!(prepared.basis(), basis);
                unrelated_document(&mut fixture.book, &cx).await;
                let before = fixture.book.head(&cx).unwrap();
                assert_eq!(before, CommitSeq(basis.0 + 1));
                let entries = journal_entries(&fixture.book, &cx);
                let result = prepared.commit(&mut fixture.book.db, &cx).await.unwrap();
                let expected_state = if expires_in == 1 {
                    let refusal = result.unwrap_err();
                    assert_eq!((refusal.code, refusal.exit), ("FA-REF-014", 7));
                    assert_eq!(fixture.book.head(&cx).unwrap(), before);
                    assert_eq!(journal_entries(&fixture.book, &cx), entries);
                    fa_time::PeriodState::Open
                } else {
                    assert_eq!(result.unwrap().recorded_at, CommitSeq(before.0 + 1));
                    assert_eq!(journal_entries(&fixture.book, &cx).len(), entries.len() + 1);
                    fa_time::PeriodState::SoftClosed
                };
                assert_eq!(
                    fixture
                        .book
                        .periods(&cx)
                        .unwrap()
                        .iter()
                        .find(|p| p.code == fixture.march)
                        .unwrap()
                        .state,
                    expected_state
                );
            });
        }
    }

    #[test]
    fn prepared_post_and_transition_conflict_when_their_acting_capability_is_revoked() {
        under_lab(81, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let mut fixture = prepared_fixture(&root, 81).await;
            let capability = Capability::embedded(VId(1), &["post", "close"]).unwrap();
            fixture.request.capability = capability.clone();
            let request = fixture.request.clone();
            let basis = fixture.book.head(&cx).unwrap();
            let before_entries = journal_entries(&fixture.book, &cx);
            let post = prepare_fixture_post(&mut fixture.book, &cx, fixture.request);
            let transition = prepare_fixture_transition(
                &mut fixture.book,
                &cx,
                &fixture.march,
                PeriodTransition::SoftClose,
                &capability,
            );
            assert_eq!((post.basis(), transition.basis()), (basis, basis));
            let context = fixture.book.context().clone();
            let revocation = fa_journal::RevocationRequest {
                capability: Capability::embedded(VId(2), &["issue_capability"]).unwrap(),
                revoked: capability.commitment().unwrap(),
                effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
                idempotency_key: b"revoke-prepared-actor".to_vec(),
                description: fixture
                    .book
                    .seal_text(&cx, "revoke prepared actor")
                    .unwrap(),
            };
            let revoked =
                fa_journal::revoke_capability(&mut fixture.book.db, &cx, &context, revocation)
                    .await
                    .unwrap()
                    .unwrap();
            assert!(!revoked.already_recorded);
            assert_eq!(revoked.recorded_at, CommitSeq(basis.0 + 1));
            let after_revocation = journal_entries(&fixture.book, &cx);
            assert_eq!(after_revocation.len(), before_entries.len() + 1);
            assert!(after_revocation.iter().any(|(vid, entry, at)| {
                *vid == revoked.control_entry
                    && *at == revoked.recorded_at
                    && entry.proposal.class == EntryClass::POLICY_CONTROL
            }));

            // Both preparations retain the original absent-revocation
            // witness. Neither may silently adopt authority from a new basis.
            let post_refusal = post
                .commit(&mut fixture.book.db, &cx)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!((post_refusal.code, post_refusal.exit), ("FA-REF-030", 6));
            assert_eq!(fixture.book.head(&cx).unwrap(), revoked.recorded_at);
            assert_eq!(journal_entries(&fixture.book, &cx), after_revocation);
            let transition_refusal = transition
                .commit(&mut fixture.book.db, &cx)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(
                (transition_refusal.code, transition_refusal.exit),
                ("FA-REF-030", 6)
            );
            assert_eq!(fixture.book.head(&cx).unwrap(), revoked.recorded_at);
            assert_eq!(journal_entries(&fixture.book, &cx), after_revocation);

            // Fresh preparation observes the journaled revocation and names
            // that refusal, without appending either abandoned operation.
            let refusal =
                fa_journal::post::prepare_post(&mut fixture.book.db, &cx, &context, request)
                    .unwrap()
                    .unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", 7));
            assert_eq!(fixture.book.head(&cx).unwrap(), revoked.recorded_at);
            assert_eq!(journal_entries(&fixture.book, &cx), after_revocation);
            let description = fixture
                .book
                .seal_text(&cx, "fresh revoked transition")
                .unwrap();
            let refusal = fa_journal::period::prepare_transition(
                &mut fixture.book.db,
                &cx,
                &context,
                &fixture.march,
                PeriodTransition::SoftClose,
                VId(1),
                1,
                DateDay::from_ymd(2026, 3, 15).unwrap(),
                b"fresh-revoked-transition",
                description,
                &capability,
                &[],
            )
            .unwrap()
            .unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", 7));
            assert_eq!(fixture.book.head(&cx).unwrap(), revoked.recorded_at);
            assert_eq!(journal_entries(&fixture.book, &cx), after_revocation);
            assert_eq!(
                fixture
                    .book
                    .periods(&cx)
                    .unwrap()
                    .iter()
                    .find(|p| p.code == fixture.march)
                    .unwrap()
                    .state,
                fa_time::PeriodState::Open
            );
            let fold = fixture.book.fold_period(&cx, &fixture.march).unwrap();
            assert_eq!(fold.entries, 0);
            assert!(fold.cells.is_empty() && fold.pending.is_empty());
        });
    }

    #[test]
    fn prepared_open_conflicts_with_a_new_due_schedule_and_fresh_open_mints_once() {
        under_lab(83, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let mut fixture = prepared_fixture(&root, 83).await;
            let april_day = DateDay::from_ymd(2026, 4, 1).unwrap();
            let context = fixture.book.context().clone();
            let tick = fa_journal::TickRequest {
                observed_utc_ns: u64::try_from(april_day.0).unwrap() * 86_400_000_000_000,
                source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
                monotonic_ok: true,
                principal_ref: VId(1),
                capability: Capability::embedded(VId(1), &["witness"]).unwrap(),
                idempotency_key: b"april-tick".to_vec(),
                description: fixture.book.seal_text(&cx, "April begins").unwrap(),
            };
            fa_journal::record_tick(&mut fixture.book.db, &cx, &context, tick)
                .await
                .unwrap()
                .unwrap();
            let capability = Capability::embedded(VId(1), &["close"]).unwrap();
            let prepared = prepare_fixture_transition(
                &mut fixture.book,
                &cx,
                &fixture.april,
                PeriodTransition::Open,
                &capability,
            );
            let basis = prepared.basis();
            fixture.request.proposal.class = EntryClass::ADJUSTING;
            fixture.request.proposal =
                fa_journal::with_auto_reverse(fixture.request.proposal, april_day);
            let original = fixture
                .book
                .post(&cx, fixture.request)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(original.recorded_at(), CommitSeq(basis.0 + 1));
            let before = fixture.book.head(&cx).unwrap();
            let entries = journal_entries(&fixture.book, &cx);
            let refusal = prepared
                .commit(&mut fixture.book.db, &cx)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-030", 6));
            assert_eq!(fixture.book.head(&cx).unwrap(), before);
            assert_eq!(journal_entries(&fixture.book, &cx), entries);
            assert_eq!(
                fixture
                    .book
                    .periods(&cx)
                    .unwrap()
                    .iter()
                    .find(|p| p.code == fixture.april)
                    .unwrap()
                    .state,
                fa_time::PeriodState::Future
            );
            let fresh = prepare_fixture_transition(
                &mut fixture.book,
                &cx,
                &fixture.april,
                PeriodTransition::Open,
                &capability,
            );
            let opened = fresh
                .commit(&mut fixture.book.db, &cx)
                .await
                .unwrap()
                .unwrap();
            assert!(opened.blocked.is_empty());
            assert_eq!(opened.minted.len(), 1);
            assert_eq!(opened.minted[0].0, original.entry_ref());
            let (reversal, at) = fixture
                .book
                .read_entry(&cx, opened.minted[0].1.vid)
                .unwrap()
                .unwrap();
            assert_eq!(at, opened.recorded_at);
            assert_eq!(reversal.entry_digest, opened.minted[0].1.entry_digest);
            assert_eq!(reversal.proposal.class, EntryClass::REVERSAL);
            assert_eq!(reversal.proposal.effective_date, april_day);
            assert_eq!(reversal.proposal.supersession.len(), 1);
            assert_eq!(
                reversal.proposal.supersession[0].target,
                original.entry_ref()
            );
            assert_eq!(journal_entries(&fixture.book, &cx).len(), entries.len() + 2);
            for (period, reversed) in [(&fixture.march, false), (&fixture.april, true)] {
                let fold = fixture
                    .book
                    .advance_registers(&cx, period)
                    .await
                    .unwrap()
                    .fold;
                assert_rent_cells(&fold, context.book_id, fixture.usd, reversed);
                assert_eq!(
                    fold.watermark,
                    Some(if reversed {
                        opened.recorded_at
                    } else {
                        original.recorded_at()
                    })
                );
                assert_eq!(fold, fixture.book.fold_period(&cx, period).unwrap());
                assert!(
                    fixture
                        .book
                        .verify_registers(&cx, period)
                        .unwrap()
                        .is_green()
                );
            }
            let before = fixture.book.head(&cx).unwrap();
            assert!(
                fixture
                    .book
                    .transition_period(
                        &cx,
                        &fixture.april,
                        PeriodTransition::Open,
                        VId(1),
                        1,
                        april_day,
                        b"second-open",
                        &capability,
                    )
                    .await
                    .unwrap()
                    .is_err()
            );
            assert_eq!(fixture.book.head(&cx).unwrap(), before);
            assert_eq!(
                journal_entries(&fixture.book, &cx)
                    .iter()
                    .filter(|(_, entry, _)| entry.proposal.class == EntryClass::REVERSAL)
                    .count(),
                1
            );
        });
    }

    /// Declared ticks exercise committed-tick semantics in one lab runtime,
    /// without asserting the accuracy of a physical clock.
    #[test]
    fn async_timing_adapters_expire_and_reverse_under_the_callers_fault_vfs() {
        under_lab(89, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let mut fixture = prepared_fixture(&root, 89).await;
            let store_path = fixture.book.db.path().to_path_buf();
            let book_id = fixture.book.context().book_id;
            let witness = Capability::embedded(VId(1), &["witness"]).unwrap();
            let system = fa_journal::rows::system_principal(book_id);
            let sweeper = Capability::new(
                system,
                fa_policy::Profile::System,
                &[fa_policy::Op::Post],
                system,
            )
            .unwrap();
            let march_day = DateDay::from_ymd(2026, 3, 15).unwrap();
            let april_day = DateDay::from_ymd(2026, 4, 1).unwrap();
            let march_ns = u64::try_from(march_day.0).unwrap() * 86_400_000_000_000;
            let april_ns = u64::try_from(april_day.0).unwrap() * 86_400_000_000_000;
            assert_eq!(fixture.book.latest_tick(&cx).unwrap(), None);
            let tick_events_start = fixture.vfs.events().len();
            let anchor = fixture
                .book
                .record_tick(&cx, march_ns, true, &witness)
                .await
                .unwrap()
                .unwrap();
            assert!(!anchor.already_recorded);
            assert_eq!(fixture.book.latest_tick(&cx).unwrap(), Some(anchor.tick));
            assert!(
                fixture.vfs.events()[tick_events_start..]
                    .iter()
                    .any(|event| {
                        matches!(event.kind, FaultKind::Latency { .. })
                            && event.path.starts_with(&store_path)
                    })
            );

            let mut hold_request = fixture.request.clone();
            hold_request.proposal.class = EntryClass::PENDING;
            hold_request.proposal.idempotency_key = b"timing-hold".to_vec();
            hold_request.proposal.pending = Some(fa_model::Pending {
                timeout_ns: Some(5),
                resolution_of: None,
                disposition: None,
            });
            let hold = fixture.book.post(&cx, hold_request).await.unwrap().unwrap();
            fixture.request.proposal.class = EntryClass::ADJUSTING;
            fixture.request.proposal =
                fa_journal::with_auto_reverse(fixture.request.proposal, april_day);
            let adjustment = fixture
                .book
                .post(&cx, fixture.request)
                .await
                .unwrap()
                .unwrap();
            assert!(fixture.book.due_holds(&cx).unwrap().is_empty());
            assert!(fixture.book.due_reversals(&cx).unwrap().is_empty());

            let uncorroborated = fixture
                .book
                .record_tick(&cx, april_ns, false, &witness)
                .await
                .unwrap()
                .unwrap();
            assert!(!uncorroborated.already_recorded);
            assert_eq!(
                fixture.book.due_holds(&cx).unwrap(),
                vec![fa_journal::DueHold {
                    hold: hold.entry_ref(),
                    recorded_at: hold.recorded_at(),
                    deadline_ns: march_ns + 5,
                }]
            );
            let due = fixture.book.due_reversals(&cx).unwrap();
            assert_eq!(due.len(), 1);
            assert_eq!(due[0].schedule.target, adjustment.entry_ref());
            assert!(matches!(
                due[0].status,
                fa_journal::ReversalStatus::Waiting { .. }
            ));
            let before = fixture.book.head(&cx).unwrap();
            let entries = journal_entries(&fixture.book, &cx);
            for refusal in [
                fixture
                    .book
                    .sweep_expiry(&cx, &sweeper, 1)
                    .await
                    .unwrap()
                    .unwrap_err(),
                fixture
                    .book
                    .sweep_reversals(&cx, &sweeper, 1)
                    .await
                    .unwrap()
                    .unwrap_err(),
                fixture
                    .book
                    .sweep(&cx, &sweeper, 1)
                    .await
                    .unwrap()
                    .unwrap_err(),
            ] {
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-144", 3));
            }
            assert_eq!(fixture.book.head(&cx).unwrap(), before);
            assert_eq!(journal_entries(&fixture.book, &cx), entries);
            let opened = fixture
                .book
                .transition_period(
                    &cx,
                    &fixture.april,
                    PeriodTransition::Open,
                    VId(1),
                    1,
                    april_day,
                    b"timing-open-april",
                    &Capability::embedded(VId(1), &["close"]).unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(opened.minted.is_empty());

            let reached = fixture
                .book
                .record_tick(&cx, april_ns + 1, true, &witness)
                .await
                .unwrap()
                .unwrap();
            let before = fixture.book.head(&cx).unwrap();
            let repeated = fixture
                .book
                .record_tick(&cx, april_ns + 1, true, &witness)
                .await
                .unwrap()
                .unwrap();
            assert!(repeated.already_recorded);
            assert_eq!(repeated.entry_ref, reached.entry_ref);
            assert_eq!(repeated.recorded_at, reached.recorded_at);
            assert_eq!(fixture.book.head(&cx).unwrap(), before);
            let sweep_events_start = fixture.vfs.events().len();
            let swept = fixture.book.sweep(&cx, &sweeper, 1).await.unwrap().unwrap();
            assert!(
                fixture.vfs.events()[sweep_events_start..]
                    .iter()
                    .any(|event| {
                        matches!(event.kind, FaultKind::Latency { .. })
                            && event.path.starts_with(&store_path)
                    })
            );
            assert_eq!(swept.expiry.len(), 1);
            assert_eq!(swept.reversals.len(), 1);
            assert_eq!(swept.expiry[0].tick, reached.tick);
            assert_eq!(swept.expiry[0].expired.len(), 1);
            assert_eq!(swept.expiry[0].expired[0].0, hold.entry_ref());
            assert_eq!(swept.expiry[0].remaining_due, 0);
            assert_eq!(swept.reversals[0].minted.len(), 1);
            assert_eq!(swept.reversals[0].minted[0].0, adjustment.entry_ref());
            assert!(swept.reversals[0].blocked.is_empty());
            assert_eq!(swept.reversals[0].remaining, 0);
            assert_eq!(swept.expiry[0].recorded_at, CommitSeq(before.0 + 1));
            assert_eq!(swept.reversals[0].recorded_at, CommitSeq(before.0 + 2));
            assert!(fixture.book.due_holds(&cx).unwrap().is_empty());
            assert!(fixture.book.due_reversals(&cx).unwrap().is_empty());
            let before = fixture.book.head(&cx).unwrap();
            assert_eq!(
                fixture.book.sweep(&cx, &sweeper, 1).await.unwrap().unwrap(),
                fa_journal::Swept::default()
            );
            assert_eq!(fixture.book.head(&cx).unwrap(), before);
            for (period, reversed, watermark) in [
                (&fixture.march, false, swept.expiry[0].recorded_at),
                (&fixture.april, true, swept.reversals[0].recorded_at),
            ] {
                let fold = fixture
                    .book
                    .advance_registers(&cx, period)
                    .await
                    .unwrap()
                    .fold;
                assert_rent_cells(&fold, book_id, fixture.usd, reversed);
                assert_eq!(fold.watermark, Some(watermark));
                assert_eq!(fold, fixture.book.fold_period(&cx, period).unwrap());
                assert!(
                    fixture
                        .book
                        .verify_registers(&cx, period)
                        .unwrap()
                        .is_green()
                );
            }
        });
    }

    #[test]
    fn async_book_honors_caller_cancellation_before_reads_and_writes() {
        under_cancelled_lab(23, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let backing = cx.commit().with_restriction(MemVfs::new).unwrap();
            let vfs = FaultVfs::with_clock(
                backing,
                FaultPlan {
                    latency: Trigger::Always,
                    latency_micros: 1,
                    ..FaultPlan::faultless()
                },
                root.clone(),
            );
            let (spec, _) = spec(Id128([0x62; 16]));
            let mut book = AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("cancelled-book"),
                BookKeys::for_development(0x62),
                spec.clone(),
                Entropy::deterministic(23),
            )
            .await
            .unwrap();
            let witness = Capability::embedded(VId(1), &["witness"]).unwrap();
            let system = fa_journal::rows::system_principal(book.context().book_id);
            let sweeper = Capability::new(
                system,
                fa_policy::Profile::System,
                &[fa_policy::Op::Post],
                system,
            )
            .unwrap();
            // Real held evidence and an approved release ensure cancellation
            // prevents an otherwise admissible mutation, not merely a refusal.
            let counsel = Capability::embedded(VId(1), &["hold", "read", "privileged"]).unwrap();
            let day = DateDay::from_ymd(2026, 3, 20).unwrap();
            let order = fa_journal::Document {
                book_id: spec.book_id,
                kind: 15,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: VId(1),
                bytes: b"PRESERVATION ORDER (lab fixture)".to_vec(),
            };
            let order = book.add_document(&cx, &order).await.unwrap().unwrap();
            let statement = fa_journal::Document {
                book_id: spec.book_id,
                kind: 5,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: VId(1),
                bytes: b"ACCOUNT 0012-3456-7890 (lab fixture)\n".repeat(200),
            };
            let statement = book.add_document(&cx, &statement).await.unwrap().unwrap();
            let hold = book
                .place_legal_hold(
                    &cx,
                    &counsel,
                    vec![statement.vid],
                    &order.oid,
                    b"lab-hold",
                    day,
                    "preserve evidence",
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                book.legal_holds_on(&cx, statement.vid).unwrap(),
                vec![hold.hold]
            );
            assert!(book.legal_hold(&cx, hold.hold).unwrap().is_some());
            let release = book
                .plan_legal_hold_release(&cx, hold.hold, VId(1), day, b"lab-release")
                .unwrap()
                .unwrap();
            let digest = book.legal_hold_release_digest(&release).unwrap();
            let approval = book
                .approve(
                    &cx,
                    Capability::embedded(VId(2), &["approve"]).unwrap(),
                    digest,
                )
                .await
                .unwrap()
                .unwrap()
                .approval();
            let events = vfs.events().len();
            let head = book.head(&cx).unwrap();
            root.cancel_with(CancelKind::User, Some("caller cancelled"));
            assert!(matches!(book.head(&cx), Err(BookError::Context(_))));
            assert!(matches!(book.latest_tick(&cx), Err(BookError::Context(_))));
            assert!(matches!(book.due_holds(&cx), Err(BookError::Context(_))));
            assert!(matches!(
                book.due_reversals(&cx),
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.record_tick(&cx, 1, true, &witness).await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.sweep_expiry(&cx, &sweeper, 1).await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.sweep_reversals(&cx, &sweeper, 1).await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.sweep(&cx, &sweeper, 1).await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.legal_hold(&cx, hold.hold),
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.legal_holds_on(&cx, statement.vid),
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.plan_legal_hold_release(&cx, hold.hold, VId(1), day, b"cancelled-release"),
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.release_legal_hold(&cx, &release, &counsel, &[approval])
                    .await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.place_legal_hold(
                    &cx,
                    &counsel,
                    vec![statement.vid],
                    &order.oid,
                    b"cancelled-hold",
                    day,
                    "cancelled hold",
                )
                .await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.derive_redacted_view(&cx, &counsel, &statement.oid)
                    .await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.read_document_for(&cx, &counsel, &statement.oid).await,
                Err(BookError::Context(_))
            ));
            // Inspect directly only as the test oracle: the public read
            // path correctly refuses the cancelled caller above.
            assert_eq!(book.db.frontier().unwrap(), head);
            assert!(matches!(
                book.create_periods(&cx, 2026).await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                book.seal_text(&cx, "cancelled"),
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                AsyncBook::create_with_vfs(
                    &cx,
                    vfs.clone(),
                    Path::new("must-not-create"),
                    BookKeys::for_development(0x62),
                    spec,
                    Entropy::deterministic(23),
                )
                .await,
                Err(BookError::Context(_))
            ));
            assert_eq!(
                vfs.events().len(),
                events,
                "cancelled calls perform no syncs"
            );
        });
    }

    #[test]
    fn async_book_database_creation_observes_injected_write_failure() {
        under_lab(29, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let backing = cx.commit().with_restriction(MemVfs::new).unwrap();
            let vfs = FaultVfs::new(
                backing,
                FaultPlan {
                    write_enospc: Trigger::Always,
                    ..FaultPlan::faultless()
                },
            );
            let (spec, _) = spec(Id128([0x63; 16]));
            assert!(
                AsyncBook::create_with_vfs(
                    &cx,
                    vfs.clone(),
                    Path::new("enospc-book"),
                    BookKeys::for_development(0x63),
                    spec,
                    Entropy::deterministic(29),
                )
                .await
                .is_err()
            );
            assert!(
                vfs.events()
                    .iter()
                    .any(|e| matches!(e.kind, FaultKind::WriteEnospc { .. }))
            );
        });
    }

    #[test]
    fn directory_book_accepts_a_relative_host_path_without_changing_cwd() {
        // UnixVfs refuses `..` at rename. Run the relative-path operation
        // beneath a child-specific cwd. Only that child changes cwd after
        // create and again after reopen; external bytes must remain bound
        // to the original book. Absolute reads in the parent also prevent
        // a child invocation matching zero tests from satisfying the oracle.
        const CHILD: &str = "FA_RELATIVE_BOOK_ROOT_CHILD";
        let keys = BookKeys::for_development(0x64);
        let reader = Capability::embedded(VId(3), &["read", "privileged"]).unwrap();
        let document = |byte| fa_journal::Document {
            book_id: Id128([0x64; 16]),
            kind: 1,
            mime: "application/octet-stream".into(),
            grade: 3,
            retrieved_by: VId(3),
            bytes: vec![byte; 16 * 1024 * 1024 + 1],
        };
        if std::env::var_os(CHILD).is_some() {
            let original = std::env::current_dir().unwrap();
            let relative = Path::new("nested/book");
            let (spec, _) = spec(Id128([0x64; 16]));
            let mut book =
                Book::create_dir(relative, keys.clone(), spec, Entropy::deterministic(31)).unwrap();
            let moved = original.join("after-create");
            std::fs::create_dir(&moved).unwrap();
            std::env::set_current_dir(&moved).unwrap();
            let first = document(b'c');
            let added = book.add_document(&first).unwrap().unwrap();
            assert!(matches!(
                storage_record(&book, &added.oid).storage,
                fa_journal::Storage::External { .. }
            ));
            assert_eq!(
                book.read_document_for(&reader, &added.oid)
                    .unwrap()
                    .unwrap(),
                fa_journal::DocumentRead::Full(first)
            );
            let head = book.head().unwrap();
            drop(book);
            std::env::set_current_dir(&original).unwrap();
            let mut book = Book::open_dir(relative, keys, Entropy::deterministic(31)).unwrap();
            assert_eq!(book.head().unwrap(), head);
            let moved = original.join("after-open");
            std::fs::create_dir(&moved).unwrap();
            std::env::set_current_dir(&moved).unwrap();
            let second = document(b'o');
            let added = book.add_document(&second).unwrap().unwrap();
            assert!(matches!(
                storage_record(&book, &added.oid).storage,
                fa_journal::Storage::External { .. }
            ));
            assert_eq!(
                book.read_document_for(&reader, &added.oid)
                    .unwrap()
                    .unwrap(),
                fa_journal::DocumentRead::Full(second)
            );
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fa-relative-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "book::tests::directory_book_accepts_a_relative_host_path_without_changing_cwd",
                "--exact",
            ])
            .env(CHILD, "1")
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "the relative-book child failed:\n{}{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        let mut reopened =
            Book::open_dir(&dir.join("nested/book"), keys, Entropy::deterministic(31))
                .expect("the child created a reopenable book under its relative path");
        assert_eq!(reopened.context().book_id, Id128([0x64; 16]));
        assert!(reopened.head().unwrap().0 > 0);
        for byte in *b"co" {
            let source = document(byte);
            assert_eq!(
                reopened
                    .read_document_for(&reader, &source.oid())
                    .unwrap()
                    .unwrap(),
                fa_journal::DocumentRead::Full(source),
                "an absolute reopen reads bytes attached after a cwd change"
            );
        }
        for alternate in ["after-create", "after-open"] {
            assert!(dir.join(alternate).is_dir(), "the child reached this phase");
            assert!(
                !dir.join(alternate).join("nested").exists(),
                "no book files were written beneath the later cwd"
            );
        }
        assert_eq!(std::env::current_dir().unwrap(), cwd);
    }

    #[test]
    fn keys_outside_the_book_directory_survive_loss_of_unsynced_names() {
        under_lab(37, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let keys = BookKeys::for_development(0x65);
            for fence_directories in [false, true] {
                let backing = cx.commit().with_restriction(MemVfs::new).unwrap();
                let vfs = FaultVfs::new(
                    backing,
                    FaultPlan {
                        dirent_loss: Trigger::Always,
                        ..FaultPlan::faultless()
                    },
                );
                let path = Path::new("./separate-key-custody/nested/book.keys");
                cx.commit()
                    .with_restriction_async(vfs.create_dir_all(path.parent().unwrap()))
                    .await
                    .unwrap();
                if fence_directories {
                    keys.save_with_vfs(&cx.commit(), &vfs, path).await.unwrap();
                    assert_eq!(vfs.pending_dirent_ops(), 0);
                    assert!(matches!(
                        BookKeys::for_development(0x66)
                            .save_with_vfs(&cx.commit(), &vfs, path)
                            .await,
                        Err(BookError::KeyFile(_))
                    ));
                } else {
                    // Reproduce the old save sequence, including a real
                    // file sync. No book constructor touches this directory.
                    cx.commit()
                        .with_restriction_async(async {
                            let mut file = vfs
                                .open(path, &OpenOptions::new().write(true).create_new(true))
                                .await
                                .unwrap();
                            let text = format!(
                                "{}\n{}\n{}\n",
                                hex(keys.inner.k_oid()),
                                hex(&keys.namespace()),
                                hex(keys.inner.dek())
                            );
                            file.write_all(text.as_bytes()).await.unwrap();
                            sync_file(&mut file).await.unwrap();
                        })
                        .await;
                    assert!(vfs.pending_dirent_ops() > 0);
                }
                cx.commit()
                    .with_restriction_async(vfs.crash())
                    .await
                    .unwrap();
                let loaded = BookKeys::load_with_vfs(&cx.query(), &vfs, path).await;
                if fence_directories {
                    let loaded = loaded.unwrap();
                    assert_eq!(loaded.inner.k_oid(), keys.inner.k_oid());
                    assert_eq!(loaded.namespace(), keys.namespace());
                    assert_eq!(loaded.inner.dek(), keys.inner.dek());
                    assert!(
                        !vfs.events()
                            .iter()
                            .any(|event| { matches!(event.kind, FaultKind::DirentLoss { .. }) })
                    );
                } else {
                    assert!(matches!(loaded, Err(BookError::Io(_, _))));
                    assert!(
                        vfs.events()
                            .iter()
                            .any(|event| { matches!(event.kind, FaultKind::DirentLoss { .. }) })
                    );
                }
            }
        });
    }

    #[test]
    fn key_save_refuses_directory_spellings_without_creating_a_key_file() {
        under_lab(43, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
            let keys = BookKeys::for_development(0x69);
            for path in [
                "./new.keys/",
                "./new.keys/.",
                "./new.keys//./",
                ".",
                "..",
                "",
            ] {
                assert!(matches!(
                    keys.save_with_vfs(&cx.commit(), &vfs, Path::new(path)).await,
                    Err(BookError::Io(_, error))
                        if error.kind() == std::io::ErrorKind::InvalidInput
                ));
                assert_eq!(
                    cx.query()
                        .with_restriction_async(vfs.metadata(Path::new("./new.keys")))
                        .await
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::NotFound
                );
            }
            let path = Path::new("./new.keys");
            keys.save_with_vfs(&cx.commit(), &vfs, path).await.unwrap();
            let loaded = BookKeys::load_with_vfs(&cx.query(), &vfs, path)
                .await
                .unwrap();
            assert_eq!(loaded.inner.k_oid(), keys.inner.k_oid());
            assert_eq!(loaded.namespace(), keys.namespace());
            assert_eq!(loaded.inner.dek(), keys.inner.dek());
        });
    }

    #[cfg(unix)]
    #[test]
    fn key_save_fences_a_symlinked_directorys_canonical_ancestors() {
        let (runtime, root) = Book::runtime_and_root().unwrap();
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let keys = BookKeys::for_development(0x68);
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_dir =
            std::env::temp_dir().join(format!("fa-key-symlink-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(&root_dir).unwrap();
        let target = root_dir.join("real/deep");
        let alias = root_dir.join("alias");
        let path = alias.join("book.keys");
        let vfs = FaultVfs::new(
            UnixVfs::new(),
            FaultPlan {
                dirent_loss: Trigger::Always,
                ..FaultPlan::faultless()
            },
        );
        runtime.block_on(async {
            cx.commit()
                .with_restriction_async(vfs.create_dir_all(&target))
                .await
                .unwrap();
            assert_eq!(vfs.pending_dirent_ops(), 2);
            cx.commit()
                .with_restriction(|| std::os::unix::fs::symlink(&target, &alias))
                .unwrap();
            keys.save_with_vfs(&cx.commit(), &vfs, &path).await.unwrap();
            // Fencing only alias and its lexical ancestors misses real's
            // entry for deep. A key save must bind that target parent too.
            assert_eq!(vfs.pending_dirent_ops(), 0);
            cx.commit()
                .with_restriction_async(vfs.crash())
                .await
                .unwrap();
            let loaded = BookKeys::load_with_vfs(&cx.query(), &vfs, &path)
                .await
                .expect("the exact keys survive a directory-loss crash");
            assert_eq!(loaded.inner.k_oid(), keys.inner.k_oid());
            assert_eq!(loaded.namespace(), keys.namespace());
            assert_eq!(loaded.inner.dek(), keys.inner.dek());
        });
    }

    #[test]
    fn key_file_io_honors_caller_cancellation_before_observation() {
        under_cancelled_lab(41, |root| async move {
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
            root.cancel_with(CancelKind::User, Some("key custody cancelled"));
            // The paths deliberately do not exist: an I/O attempt would
            // produce a filesystem error, not the caller's cancellation.
            assert!(matches!(
                BookKeys::for_development(0x67)
                    .save_with_vfs(&cx.commit(), &vfs, Path::new("missing/book.keys"))
                    .await,
                Err(BookError::Context(_))
            ));
            assert!(matches!(
                BookKeys::load_with_vfs(&cx.query(), &vfs, Path::new("missing/book.keys")).await,
                Err(BookError::Context(_))
            ));
        });
    }

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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
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
        let before = book.head().unwrap();
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
            assert_eq!(book.head().unwrap(), before);
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
                &book.context().seal_key,
                [0x47; 32],
                [0x47; 24],
            ),
        };
        let purposes = book.purposes();
        let ctx = book.context().clone();
        with_store!(&mut book.store, core => book.runtime.block_on(async {
            fa_journal::revoke_capability(&mut core.db, &purposes, &ctx, req).await
        }))
        .unwrap()
        .expect("revoked");
        let revoked_at = book.head().unwrap();
        let refusal = book.checkpoint(principal, &witness).unwrap().unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", 7));
        assert_eq!(book.head().unwrap(), revoked_at);
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
                opening_date: None,
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
    /// store) folds as the source does and verifies against its SeqMap; a
    /// scenario post lands in the scratch book only; a map with a pair
    /// removed is FA-REF-135.
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
        // Maintained registers are maintenance: never replayed.
        assert!(book.advance_registers(&march).expect("maintained").wrote);
        let source_head = book.head().unwrap();

        let before_genesis = book
            .replay_into_scratch(
                Some(CommitSeq(0)),
                BookKeys::for_development(0x5c),
                Entropy::deterministic(0x5c),
            )
            .expect("kernel")
            .expect_err("a scratch Book requires its genesis");
        assert_eq!(
            (before_genesis.code, before_genesis.exit),
            (
                fa_journal::refusal::code::STRUCTURE,
                fa_journal::exit::USAGE
            )
        );
        assert_eq!(book.head().unwrap(), source_head);

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
            scratch.fold_period(&march).unwrap().cells,
            book.fold_period(&march).unwrap().cells
        );
        let scratch_rows = scratch.purposes().query().with_restriction(|| {
            with_store!(&scratch.store, core => core.db.vertices_at(core.db.frontier().unwrap()))
        }).unwrap();
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
            book.head().unwrap(),
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
            let record = storage_record(&book, &added.oid);
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
                storage_record(&book, &inline.oid).storage,
                fa_journal::Storage::Inline(_)
            ));
            (added.oid, locator)
        };
        // Reopened, the document reads back byte-identically.
        let mut book = Book::open_dir(&dir, keys, Entropy::deterministic(12)).expect("open_dir");
        let reader = Capability::embedded(principal, &["read", "privileged"]).unwrap();
        assert_eq!(
            book.read_document_for(&reader, &oid).unwrap().unwrap(),
            fa_journal::DocumentRead::Full(big.clone())
        );
        // A byte changed on disk: refused (exit 8), never the changed bytes.
        let path = dir.join("blobs").join(&locator[..2]).join(&locator);
        let mut changed = big.bytes.clone();
        changed[0] = b'Q';
        std::fs::write(&path, &changed).unwrap();
        let r = book.read_document_for(&reader, &oid).unwrap().unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-085", 8), "{r}");
        // The blob moved away: refused (exit 5), never a silent null.
        std::fs::rename(&path, path.with_extension("moved")).unwrap();
        let r = book.read_document_for(&reader, &oid).unwrap().unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-116", 5), "{r}");
    }

    #[test]
    fn a_legal_hold_through_the_facade_lifts_only_with_a_second_humans_approval() {
        let book_id = Id128([0x48; 16]);
        let (spec, _) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x48),
            spec,
            Entropy::deterministic(0x48),
        )
        .expect("create");
        let (counsel, approver) = (VId(1), VId(2));
        let day = DateDay::from_ymd(2026, 3, 20).unwrap();
        let doc = |bytes: &[u8]| fa_journal::Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: counsel,
            bytes: bytes.to_vec(),
        };
        let order = book
            .add_document(&doc(b"PRESERVATION ORDER (facade fixture)"))
            .expect("kernel")
            .expect("admitted");
        let ledger = book
            .add_document(&doc(b"GENERAL LEDGER EXPORT (facade fixture)"))
            .expect("kernel")
            .expect("admitted");
        let holder = Capability::embedded(counsel, &["hold"]).expect("hold");
        let placed = book
            .place_legal_hold(
                &holder,
                vec![ledger.vid],
                &order.oid,
                b"hold",
                day,
                "litigation hold",
            )
            .expect("kernel")
            .expect("placed");
        assert_eq!(book.legal_holds_on(ledger.vid).unwrap(), vec![placed.hold]);
        let plan = book
            .plan_legal_hold_release(placed.hold, counsel, day, b"release")
            .expect("kernel")
            .expect("planned");
        let digest = book.legal_hold_release_digest(&plan).unwrap();
        let r = book
            .release_legal_hold(&plan, &holder, &[])
            .expect("kernel")
            .unwrap_err();
        assert_eq!(r.code, "FA-REF-012", "{r}");
        let approval = book
            .approve(
                Capability::embedded(approver, &["approve"]).expect("approve"),
                digest,
            )
            .expect("kernel")
            .expect("approved")
            .approval();
        let released = book
            .release_legal_hold(&plan, &holder, &[approval])
            .expect("kernel")
            .expect("released");
        assert_eq!(book.legal_holds_on(ledger.vid).unwrap(), Vec::<VId>::new());
        assert_eq!(
            book.legal_hold(placed.hold)
                .unwrap()
                .expect("a hold")
                .released,
            Some((released.release, released.recorded_at))
        );
    }

    #[test]
    fn a_bank_statement_through_the_facade_reads_redacted_until_privileged() {
        let book_id = Id128([0x49; 16]);
        let (spec, _) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x49),
            spec,
            Entropy::deterministic(0x49),
        )
        .expect("create");
        let statement = fa_journal::Document {
            book_id,
            kind: 5,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: VId(1),
            bytes: b"ACCOUNT 0012-3456-7890 (facade fixture)
"
            .repeat(200),
        };
        let added = book
            .add_document(&statement)
            .expect("kernel")
            .expect("admitted");
        let reader = Capability::embedded(VId(2), &["read"]).expect("read");
        let counsel = Capability::embedded(VId(1), &["read", "privileged"]).expect("privileged");
        assert_eq!(
            book.document_commitment(&added.oid).unwrap(),
            Some(statement.doc_commit())
        );
        assert_eq!(book.document_commitment(&Oid([0xee; 32])).unwrap(), None);
        let r = book
            .read_document_for(&reader, &added.oid)
            .expect("kernel")
            .unwrap_err();
        assert_eq!(r.code, "FA-REF-142", "{r}");
        book.derive_redacted_view(&counsel, &added.oid)
            .expect("kernel")
            .expect("derived");
        let read = book
            .read_document_for(&reader, &added.oid)
            .expect("kernel")
            .expect("a view");
        assert!(
            matches!(&read, fa_journal::DocumentRead::Redacted(v) if v.verify().is_ok()),
            "{read:?}"
        );
        assert_eq!(
            book.read_document_for(&counsel, &added.oid)
                .expect("kernel")
                .expect("the bytes"),
            fa_journal::DocumentRead::Full(statement)
        );
    }

    #[test]
    fn public_document_commitment_does_not_decode_bytes_or_trust_a_rebound_digest() {
        use fa_model::symbols::{property, relation};
        use fgdb::WriteBatch;
        use fgdb_types::CanonicalScalar;

        let book_id = Id128([0x4b; 16]);
        let (spec, _) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x4b),
            spec,
            Entropy::deterministic(0x4b),
        )
        .unwrap();
        let document = fa_journal::Document {
            book_id,
            kind: 5,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: VId(1),
            bytes: b"privileged inline bytes".to_vec(),
        };
        let added = book.add_document(&document).unwrap().unwrap();
        assert_eq!(
            book.document_commitment(&added.oid).unwrap(),
            Some(document.doc_commit())
        );
        let ctx = book.purposes();
        let vid = fa_journal::evidence::document_vid(&added.oid);
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        batch.set_vertex_property(
            vid,
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(vec![0xff]).unwrap()),
        );
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&ctx.commit(), batch))).unwrap();
        // The public mirror lookup neither fetches nor decodes a private
        // payload. Its result is not a byte-verification certificate.
        assert_eq!(
            book.document_commitment(&added.oid).unwrap(),
            Some(document.doc_commit())
        );
        let counsel = Capability::embedded(VId(1), &["read", "privileged"]).unwrap();
        let refusal = book
            .read_document_for(&counsel, &added.oid)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, "FA-REF-085");
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        batch.set_vertex_property(
            vid,
            property::FA_DIGEST,
            Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
        );
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&ctx.commit(), batch))).unwrap();
        assert!(matches!(
            book.document_commitment(&added.oid),
            Err(BookError::Kernel(KernelError::Corrupt(_)))
        ));
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
