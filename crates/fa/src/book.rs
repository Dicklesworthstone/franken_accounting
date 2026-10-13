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

    /// The book's checkpoint signing key (plan §13.2): an Ed25519 seed
    /// `KDF(k_oid ‖ namespace, "fa:checkpoint-signing-seed:v1")`, so the key
    /// file format is unchanged and the signing key is domain-separated
    /// from every other use of the book's secrets.
    pub(crate) fn checkpoint_signing_key(&self) -> fa_notary::SigningKey {
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(self.inner.k_oid());
        material[32..].copy_from_slice(&self.namespace);
        let mut seed = derive_key("fa:checkpoint-signing-seed:v1", &material);
        let key = fa_notary::SigningKey::from_seed(&seed);
        fgdb_crypto::zeroize::scrub_slice(&mut material);
        fgdb_crypto::zeroize::scrub_slice(&mut seed);
        key
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
    /// The substrate refused a native read needed by a report certificate.
    CertifiedRead(fgdb::QueryError),
    /// A Lantern procedure refused or failed outside the kernel, registers
    /// and registry (those map to their own variants).
    Lantern(fa_lantern::LanternError),
}

impl BookError {
    /// The exit class (plan §15.3).
    #[must_use]
    pub fn exit(&self) -> u8 {
        match self {
            Self::Registers(fa_registers::RegisterError::InvalidSelection(_))
            | Self::Lantern(
                fa_lantern::LanternError::Unregistered { .. }
                | fa_lantern::LanternError::Parameter { .. },
            ) => fa_journal::exit::USAGE,
            Self::Runtime(_) | Self::Open(_) | Self::Io(..) | Self::KeyFile(_) | Self::NoBook => {
                fa_journal::exit::ENVIRONMENT
            }
            Self::Context(_)
            | Self::Kernel(_)
            | Self::Registers(_)
            | Self::Registry(_)
            | Self::Entropy(_)
            | Self::CertifiedRead(_)
            | Self::Lantern(_) => fa_journal::exit::FOUNDATION,
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
            Self::CertifiedRead(e) => write!(f, "certified report input: {e}"),
            Self::Lantern(e) => write!(f, "procedure: {e}"),
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
impl From<fa_lantern::LanternError> for BookError {
    fn from(e: fa_lantern::LanternError) -> Self {
        match e {
            fa_lantern::LanternError::Kernel(k) => Self::Kernel(k),
            fa_lantern::LanternError::Register(r) => Self::Registers(r),
            fa_lantern::LanternError::Registry(r) => Self::Registry(r),
            other => Self::Lantern(other),
        }
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

/// An evidence bundle and its detached production receipt (plan §13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducedBundle {
    /// The deterministic body (`.fab`) and its digest.
    pub bundle: fa_notary::Bundle,
    /// The `ProductionReceipt`'s canonical bytes, signed by the book's key.
    pub receipt: Vec<u8>,
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

    /// Rehearse an intent through the posting kernel without publishing.
    ///
    /// The portable plan retains the original sealed proposal and approvals,
    /// and binds the actual staged effects to this book's current sequence
    /// and the supplied capability. This first slice requires any necessary
    /// approvals to exist already; an intervening publication requires a new
    /// plan. Planning neither records an entry nor consumes its idempotency key.
    pub fn plan(
        &mut self,
        intent: fa_intents::PostIntent,
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_intents::PostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan(&purposes, intent, capability))
    }

    /// Commit the exact rehearsed intent under the caller's current authority.
    ///
    /// The kernel authenticates the plan, repeats its accounting and authority
    /// checks, and compares the staged effects before publishing. It retains
    /// the plan as an immutable graph certificate linked to the entry in the
    /// same transaction. Its public digest is a locator, not a native object
    /// ID; the entry's native `plan_certificate` envelope field remains absent.
    /// An exact retry returns the original recorded entry without writing.
    pub fn commit_plan(
        &mut self,
        plan: fa_intents::PostPlan,
        capability: &fa_journal::Capability,
    ) -> Outcome<Posted> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.commit_plan(
            &purposes, plan, capability,
        )))
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
    /// `entropy`, its checkpoints signed with `keys`' checkpoint key) and
    /// the [`fa_journal::SeqMap`] binding the two histories. External
    /// documents remain in the source's immutable blob store; that store
    /// must remain available for subsequent scratch reads.
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
                .block_on(core.replay_into(&scratch_purposes, db, &keys, prefix, entropy))?
                .map(|(copy, map)| (Store::Memory(copy), map)),
            Store::Dir(core) => scratch_runtime
                .block_on(core.replay_into(&scratch_purposes, db, &keys, prefix, entropy))?
                .map(|(copy, map)| (Store::ScratchDir(copy), map)),
            Store::ScratchDir(core) => scratch_runtime
                .block_on(core.replay_into(&scratch_purposes, db, &keys, prefix, entropy))?
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
    /// bound (`fa_journal::evidence::inline_document_bound`: what one
    /// substrate row holds, at most `evidence_policy.toml
    /// max_document_bytes`) keeps its bytes in the book's blob store, its
    /// commitment inline.
    pub fn add_document(
        &mut self,
        doc: &fa_journal::Document,
    ) -> Outcome<fa_journal::DocumentAdded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.add_document(&purposes, doc)))
    }

    /// Supply evidence under the calling session's capability. The kernel
    /// derives the uploader and provenance grade and checks current authority
    /// before observing an existing document or publishing its custody receipt.
    /// Inline and large documents use this book's configured storage, never
    /// the trusted owner intake path. A retry preserves the original provenance.
    /// Hosts bind the capability; this method does not authenticate a transport
    /// or grant an Agent monetary posting authority on trunk.
    pub fn upload_document(
        &mut self,
        capability: &fa_journal::Capability,
        request: fa_journal::UploadRequest,
    ) -> Outcome<fa_journal::DocumentAdded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.upload_document(
            &purposes, capability, request,
        )))
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

    /// Certify a trial balance without writing to the book. Retain the returned
    /// canonical certificate bytes to replay the exact historical report.
    pub fn certify_trial_balance(
        &self,
        selection: crate::TrialBalanceSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedTrialBalance> {
        with_store!(&self.store, core => core.certify_trial_balance(&self.purposes(), selection, known_at))
    }

    /// Certify a trial balance, balance explanation or open-item report at one
    /// retained sequence. Creating the certificate does not write to the book.
    pub fn certify_report(
        &self,
        selection: crate::ReportSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedReport> {
        with_store!(&self.store, core => core.certify_report(&self.purposes(), selection, known_at))
    }

    /// Evaluate an exact financial statement and optional comparative from
    /// authoritative journal payloads, without publishing any object.
    pub fn statement(
        &self,
        selection: crate::StatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::Statement> {
        with_store!(&self.store, core => core.statement(&self.purposes(), selection, known_at))
    }

    /// Certify the complete statement definition, chart partition, historical
    /// period columns and exact native-unit amounts without writing the book.
    pub fn certify_statement(
        &self,
        selection: crate::StatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedStatement> {
        with_store!(&self.store, core => core.certify_statement(&self.purposes(), selection, known_at))
    }

    pub fn certify_statement_at_instant(
        &self,
        selection: crate::StatementSelection,
        requested_utc_ns: u64,
    ) -> Outcome<crate::CertifiedStatement> {
        with_store!(&self.store, core => core.certify_statement_at_instant(&self.purposes(), selection, requested_utc_ns))
    }

    /// Resolve a UTC instant from retained ticks without reading a clock.
    /// Keep the returned frontier and brackets with the resolved sequence.
    pub fn resolve_known_at_instant(
        &self,
        requested_utc_ns: u64,
    ) -> Outcome<fa_journal::InstantSelection> {
        with_store!(&self.store, core => core.resolve_known_at_instant(&self.purposes(), requested_utc_ns))
    }

    /// Certify a trial balance selected by a TimeEvidence instant. Replay
    /// preserves its original resolution even after later ticks are recorded.
    pub fn certify_trial_balance_at_instant(
        &self,
        selection: crate::TrialBalanceSelection,
        requested_utc_ns: u64,
    ) -> Outcome<crate::CertifiedTrialBalance> {
        with_store!(&self.store, core => core.certify_trial_balance_at_instant(&self.purposes(), selection, requested_utc_ns))
    }

    /// Certify any supported report with the original TimeEvidence frontier
    /// and tick brackets attached to its resolved historical sequence.
    pub fn certify_report_at_instant(
        &self,
        selection: crate::ReportSelection,
        requested_utc_ns: u64,
    ) -> Outcome<crate::CertifiedReport> {
        with_store!(&self.store, core => core.certify_report_at_instant(&self.purposes(), selection, requested_utc_ns))
    }

    /// Replay the report family and exact historical output selected by a
    /// certificate, including its account metadata and any time resolution.
    pub fn replay_report(
        &self,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<crate::ReportOutput> {
        with_store!(&self.store, core => core.replay_report(&self.purposes(), certificate))
    }

    /// Reproduce the report at the certificate's fixed known-at sequence,
    /// refusing changed inputs, unavailable history or different output bytes.
    pub fn replay_trial_balance(
        &self,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<TrialBalance> {
        with_store!(&self.store, core => core.replay_trial_balance(&self.purposes(), certificate))
    }

    pub fn certificate_status(
        &self,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<crate::CertificateStatus> {
        with_store!(&self.store, core => core.certificate_status(&self.purposes(), certificate))
    }

    /// Persist a certificate lazily as an immutable object in this book.
    /// Exact retries return the original storage sequence without a write.
    /// The report's known-at coordinate does not change when it is retained.
    pub fn retain_certificate(
        &mut self,
        certificate: &crate::ReportCertificate,
    ) -> Outcome<crate::RetainedCertificate> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.retain_certificate(&purposes, certificate)))
    }

    /// Load a retained artifact by its full public certificate digest.
    pub fn read_certificate(&self, digest: &[u8; 32]) -> Outcome<crate::ReportCertificate> {
        let purposes = self.purposes();
        with_store!(&self.store, core => self.runtime.block_on(core.read_certificate(&purposes, digest)))
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

    /// The public key this book's transparency checkpoints are signed with
    /// (Ed25519, plan §13.2). An outsider is given it out of band and
    /// passes it to `fa_verify::verify_checkpoint`.
    #[must_use]
    pub fn checkpoint_public_key(&self) -> [u8; 32] {
        with_store!(&self.store, core => core.checkpoint_public_key())
    }

    /// Publish an accumulator state for this book's entry prefix and the
    /// transparency checkpoint beside it, signed with the book's key.
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

    /// Recompute every accumulator state from its journal prefix, and every
    /// checkpoint from the same prefix and the book's key.
    /// This reads the whole open embedded book, like the other current read
    /// methods; scoped session admission is not implemented here. The result
    /// verifies entry prefixes and the book's own checkpoint signatures, not
    /// witnesses or document-receipt claims.
    pub fn verify_accumulator(&self) -> Result<fa_notary::AccumulatorVerification, BookError> {
        with_store!(&self.store, core => core.verify_accumulator(&self.purposes()))
    }

    /// Export a raw Notary proof or 80-byte checkpoint for the independent
    /// `fa-verify` program. The holder must have current read and produce
    /// authority for this book. The selected checkpoint is recomputed from
    /// retained journal history; no new checkpoint or other write occurs.
    /// Outsiders establish trust in the unsigned checkpoint separately.
    pub fn export_proof(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: crate::ProofRequest,
    ) -> Outcome<crate::ProofArtifact> {
        with_store!(&self.store, core => core.export_proof(&self.purposes(), principal, capability, request))
    }

    /// Produce an evidence bundle (plan §13.2) and its detached production
    /// receipt. The bundle is produced against the journaled state `state`
    /// (default: the latest), whose checkpoint is recomputed from the
    /// journal and the book's key first; it is a pure function of the
    /// request and that checkpoint, so producing it again gives the same
    /// bytes. The receipt records `principal`, the recorded sequence the
    /// production was admitted at and `capability`'s commitment, signed
    /// with the book's key. `produce` authorizes the production, and
    /// admission (current, not revoked) precedes every read of the journal.
    /// Each cited document is read as `capability` may see it
    /// ([`Book::read_document_for`], decided before any read of its bytes):
    /// a document it sees only as a redacted view gets a stub without bytes,
    /// and inlining one is refused (FA-REF-128). `None` when the book has no
    /// published state to produce against (publish one with
    /// [`Book::checkpoint`]) or `state` is not on the chain.
    pub fn produce_bundle(
        &mut self,
        principal: VId,
        capability: &fa_policy::Capability,
        state: Option<fa_model::Oid>,
        request: &fa_notary::BundleRequest,
    ) -> Outcome<Option<ProducedBundle>> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.produce_bundle(
            &purposes, principal, capability, state, request,
        )))
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

    /// Fold open items together with the account metadata visible at the same
    /// sequence. The resolved coordinate and optional account filter are part
    /// of the report, so historical rendering never consults today's chart.
    pub fn open_items_report(
        &self,
        account: Option<VId>,
        known_at: Option<CommitSeq>,
    ) -> Result<crate::OpenItemsReport, BookError> {
        with_store!(&self.store, core => core.open_items_report(&self.purposes(), account, known_at))
    }

    /// Compare immutable leg mirrors and topology with canonical entry payloads.
    /// `None` selects the current head; an explicit sequence checks that prefix.
    /// Drift is reported without changing the book.
    pub fn verify_projections(
        &self,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_journal::ProjectionVerification, BookError> {
        with_store!(&self.store, core => core.verify_projections(&self.purposes(), known_at))
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

    /// Run a registered Lantern procedure over the trunk as known at
    /// `known_at` (the head when `None`) and, for the historical folds,
    /// through `effective_through`: a pure read (plan §11).
    pub fn run_procedure(
        &self,
        procedure: &dyn fa_lantern::Procedure,
        known_at: Option<CommitSeq>,
        effective_through: Option<fa_time::DateDay>,
    ) -> Result<fa_lantern::ProcedureRun, BookError> {
        with_store!(&self.store, core => core.run_procedure(&self.purposes(), procedure, known_at, effective_through))
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

    /// The genesis spec journaled on the book root (base unit, calendar,
    /// opening date, entities).
    pub fn spec(&self) -> Result<BookSpec, BookError> {
        with_store!(&self.store, core => core.spec(&self.purposes()))
    }

    /// Open reads under `capability` for `principal` (plan §14.2), through
    /// the kernel's [`fa_journal::policy::admit_reads`]: the capability is
    /// the principal's, holds `read`, its `books` caveat admits this book,
    /// and it is neither expired nor revoked at the head — before anything
    /// else is read. Historical selectors never resurrect authority: a token
    /// revoked or expired now is refused whatever `known_at` a read would
    /// select. Each [`ReadScope`] read is then judged by the scope caveats
    /// before its query is constructed; an `accounts` caveat is refused
    /// until whole-entry visibility lands, never filtered.
    pub fn read_scope(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
    ) -> Outcome<ReadScope<'_>> {
        let purposes = self.purposes();
        let admitted = with_store!(&self.store, core => core.query(&purposes, |db, book| {
            Ok(fa_journal::policy::admit_reads(db, book, principal, capability)?)
        }))?;
        Ok(admitted.map(|authority| ReadScope {
            book: self,
            authority,
        }))
    }
}

/// Reads of one book under one admitted capability (see [`Book::read_scope`]):
/// the blocking adapter over the kernel's [`fa_journal::policy::ReadAuthority`].
/// Every read resolves its recorded frontier first (`None` is the head) and
/// is refused before its query is constructed when a scope caveat does not
/// admit what it reaches; it never returns a filtered result.
pub struct ReadScope<'b> {
    book: &'b Book,
    authority: fa_journal::policy::ReadAuthority,
}

impl ReadScope<'_> {
    /// The capability these reads are admitted under.
    #[must_use]
    pub fn capability(&self) -> &fa_policy::Capability {
        self.authority.capability()
    }

    /// The recorded frontier a read selects: `known_at`, or the head.
    fn frontier(&self, known_at: Option<CommitSeq>) -> Result<CommitSeq, BookError> {
        match known_at {
            Some(seq) => Ok(seq),
            None => self.book.head(),
        }
    }

    /// [`Book::read_entry`] at a recorded frontier, through the kernel's
    /// [`fa_journal::policy::ReadAuthority::read_entry`]: a `periods` or
    /// `effective` caveat refuses it (the entry's period is known only once
    /// read), and the read goes through the snapshot at the frontier, so an
    /// entry recorded later is never loaded or decoded.
    pub fn read_entry(
        &self,
        vid: VId,
        known_at: Option<CommitSeq>,
    ) -> Outcome<Option<(Entry, CommitSeq)>> {
        let seq = self.frontier(known_at)?;
        let purposes = self.book.purposes();
        with_store!(&self.book.store, core => core.query(&purposes, |db, _| {
            Ok(self.authority.read_entry(db, vid, seq)?)
        }))
    }

    /// [`Book::explain_balance`] under the scope caveats: it reaches its one
    /// period.
    pub fn explain_balance(
        &self,
        account: VId,
        period_code: &str,
        known_at: Option<CommitSeq>,
    ) -> Outcome<BalanceExplanation> {
        let seq = self.frontier(known_at)?;
        if let Err(r) = self
            .authority
            .periods(self.book.context(), seq, &[period_code])
        {
            return Ok(Err(r));
        }
        Ok(Ok(self.book.explain_balance(
            account,
            period_code,
            Some(seq),
        )?))
    }

    /// [`Book::trial_balance_at`] under the scope caveats. Stock balances
    /// run from inception, so the read reaches every period before the
    /// latest selected one: a `periods` caveat refuses it, and an
    /// `effective` caveat admits it only through that period's last day.
    pub fn trial_balance_at(
        &self,
        periods: &[String],
        known_at: Option<CommitSeq>,
    ) -> Outcome<TrialBalance> {
        let seq = self.frontier(known_at)?;
        let codes: Vec<&str> = periods.iter().map(String::as_str).collect();
        if let Err(r) = self
            .authority
            .stock_through(self.book.context(), seq, &codes)
        {
            return Ok(Err(r));
        }
        Ok(Ok(self.book.trial_balance_at(periods, Some(seq))?))
    }

    /// [`Book::balance_as_of`] under the scope caveats: it reaches every
    /// period that starts by `day`, so a `periods` caveat refuses it.
    pub fn balance_as_of(
        &self,
        day: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Outcome<TrialBalance> {
        let seq = self.frontier(known_at)?;
        if let Err(r) = self.authority.as_of(seq, day) {
            return Ok(Err(r));
        }
        Ok(Ok(self.book.balance_as_of(day, Some(seq))?))
    }

    /// [`Book::period_activity`] under the scope caveats: it reaches exactly
    /// the selected periods.
    pub fn period_activity(
        &self,
        periods: &[String],
        known_at: Option<CommitSeq>,
    ) -> Outcome<TrialBalance> {
        let seq = self.frontier(known_at)?;
        let codes: Vec<&str> = periods.iter().map(String::as_str).collect();
        if let Err(r) = self.authority.periods(self.book.context(), seq, &codes) {
            return Ok(Err(r));
        }
        Ok(Ok(self.book.period_activity(periods, Some(seq))?))
    }
}

impl fmt::Debug for ReadScope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReadScope({:?}, {:?})", self.book, self.authority)
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
                .replay_into(
                    &cx,
                    scratch_db,
                    &BookKeys::for_development(0x63),
                    None,
                    Entropy::deterministic(seed + 1),
                )
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
                    .replay_into(
                        &cx,
                        scratch_db,
                        &BookKeys::for_development(0x6a),
                        None,
                        Entropy::deterministic(seed + 100),
                    )
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

    /// Reads under a capability (fa-llx; fa-t6m "historical read using a
    /// revoked token"): admitted once against current policy, then every
    /// read judged by the scope caveats before its query is constructed —
    /// refused, never filtered.
    #[test]
    fn scoped_reads_refuse_before_construction_and_a_revoked_token_never_reads_history() {
        let book_id = Id128([0x48; 16]);
        let (spec, usd) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x48),
            spec,
            Entropy::deterministic(0x48),
        )
        .unwrap();
        let principal = VId(48);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        book.install_chart(&chart(usd), principal, day, b"chart")
            .unwrap()
            .unwrap();
        let (_, periods) = book.create_periods(2026).unwrap();
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
            &Capability::embedded(principal, &["close"]).unwrap(),
        )
        .unwrap()
        .unwrap();
        let posted = post_rent(&mut book, usd, principal, day, b"rent", 150_000)
            .unwrap()
            .unwrap();
        let vid = posted.entry_ref().vid;
        let recorded = posted.recorded_at();
        let before = CommitSeq(recorded.0 - 1);
        let rent = account_vid(book_id, "6000");
        let months = [march.clone()];
        let reader = Capability::embedded(principal, &["read"]).unwrap();
        let caveat = |r: Refusal, caveat: &str| {
            assert_eq!((r.code, r.exit), ("FA-REF-011", 7), "{}", r.message);
            assert!(
                r.message.contains(&format!("`{caveat}` caveat")),
                "{}",
                r.message
            );
        };

        // Admission: the holder, `read`, and (until whole-entry visibility)
        // no `accounts` caveat.
        for (actor, cap) in [
            (VId(49), reader.clone()),
            (
                principal,
                Capability::embedded(principal, &["post"]).unwrap(),
            ),
            (principal, reader.clone().for_accounts(&["6000"]).unwrap()),
        ] {
            let r = book.read_scope(actor, &cap).unwrap().unwrap_err();
            assert_eq!((r.code, r.exit), ("FA-REF-011", 7), "{}", r.message);
        }

        // Unscoped: the facade's reads; a frontier before the entry selects
        // nothing.
        let scope = book.read_scope(principal, &reader).unwrap().unwrap();
        let (entry, seq) = scope.read_entry(vid, None).unwrap().unwrap().unwrap();
        assert_eq!(
            (entry.entry_digest, seq),
            (posted.entry_ref().entry_digest, recorded)
        );
        assert_eq!(scope.read_entry(vid, Some(before)).unwrap().unwrap(), None);
        assert_eq!(
            scope.trial_balance_at(&months, None).unwrap().unwrap(),
            book.trial_balance(&months).unwrap()
        );

        // known_at ≤ pin: the head and any later frontier refuse; the pin admits.
        let pinned = reader.clone().known_at_most(before);
        let scope = book.read_scope(principal, &pinned).unwrap().unwrap();
        for known_at in [None, Some(recorded)] {
            caveat(
                scope
                    .trial_balance_at(&months, known_at)
                    .unwrap()
                    .unwrap_err(),
                "known_at",
            );
        }
        caveat(
            scope.read_entry(vid, None).unwrap().unwrap_err(),
            "known_at",
        );
        assert_eq!(
            scope
                .trial_balance_at(&months, Some(before))
                .unwrap()
                .unwrap(),
            book.trial_balance_at(&months, Some(before)).unwrap()
        );

        // periods ⊆ {March}: March's activity and explanation admit; the
        // trial balance (stock from inception), the as-of, another period
        // and an entry read (its period is unknown before the read) refuse.
        let march_only = reader.clone().for_periods(&[march.as_str()]).unwrap();
        let scope = book.read_scope(principal, &march_only).unwrap().unwrap();
        scope.period_activity(&months, None).unwrap().unwrap();
        let explained = scope.explain_balance(rent, &march, None).unwrap().unwrap();
        assert_eq!(explained.contributions.len(), 1);
        caveat(
            scope.trial_balance_at(&months, None).unwrap().unwrap_err(),
            "periods",
        );
        caveat(
            scope.balance_as_of(day, None).unwrap().unwrap_err(),
            "periods",
        );
        caveat(
            scope
                .period_activity(&["FY2026-P04".to_string()], None)
                .unwrap()
                .unwrap_err(),
            "periods",
        );
        caveat(scope.read_entry(vid, None).unwrap().unwrap_err(), "periods");

        // effective ≤ March 31: through March admits; April refuses.
        let through_march = reader
            .clone()
            .effective_through(DateDay::from_ymd(2026, 3, 31).unwrap());
        let scope = book.read_scope(principal, &through_march).unwrap().unwrap();
        scope.trial_balance_at(&months, None).unwrap().unwrap();
        scope.balance_as_of(day, None).unwrap().unwrap();
        caveat(
            scope
                .balance_as_of(DateDay::from_ymd(2026, 4, 1).unwrap(), None)
                .unwrap()
                .unwrap_err(),
            "effective",
        );

        // branch = <draft>: no trunk read.
        let drafted = reader.clone().on_branch(Id128([0xd7; 16])).unwrap();
        let scope = book.read_scope(principal, &drafted).unwrap().unwrap();
        caveat(
            scope.trial_balance_at(&months, None).unwrap().unwrap_err(),
            "branch",
        );

        // Historical selectors never resurrect authority: expired or revoked
        // now, the token reads nothing, not even the frontier before its end.
        let head = book.head().unwrap();
        let expired = reader.clone().expiring_at(head);
        let r = book.read_scope(principal, &expired).unwrap().unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-014", 7));
        let req = fa_journal::RevocationRequest {
            capability: Capability::embedded(VId(47), &["issue_capability"]).unwrap(),
            revoked: reader.commitment().unwrap(),
            effective_date: day,
            idempotency_key: b"revoke-reader".to_vec(),
            description: book.seal_text("revoke").unwrap(),
        };
        let purposes = book.purposes();
        let ctx = book.context().clone();
        with_store!(&mut book.store, core => book.runtime.block_on(async {
            fa_journal::revoke_capability(&mut core.db, &purposes, &ctx, req).await
        }))
        .unwrap()
        .expect("revoked");
        let r = book.read_scope(principal, &reader).unwrap().unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-023", 7));
        book.read_scope(principal, &pinned)
            .unwrap()
            .expect("another capability of the same reader still reads");
    }

    /// `produce` authorizes a production and is checked before any read;
    /// the body names no producer (an Agent's production is the same bytes)
    /// while the receipt does; an outsider verifies both with the book's
    /// public key; with no published state there is nothing to produce.
    #[test]
    fn bundles_require_produce_and_verify_with_the_book_key() {
        use fa_policy::{Capability as PolicyCapability, Op, Profile};

        let (spec, _) = spec(Id128([0x47; 16]));
        let mut book = Book::create_memory(
            BookKeys::for_development(47),
            spec,
            Entropy::deterministic(47),
        )
        .unwrap();
        let principal = VId(47);
        let request = fa_notary::BundleRequest {
            scope: fa_notary::BundleScope::Prefix,
            balances: Vec::new(),
            inline_documents: true,
        };
        let producer = PolicyCapability::embedded(principal, &["produce", "read"]).unwrap();
        assert_eq!(
            book.produce_bundle(principal, &producer, None, &request)
                .unwrap()
                .unwrap(),
            None,
            "no published state"
        );
        let witness = PolicyCapability::embedded(principal, &["witness"]).unwrap();
        let published = book.checkpoint(principal, &witness).unwrap().unwrap();
        let at = book.head().unwrap();
        for (actor, cap, code) in [
            (principal, witness, "FA-REF-011"),
            (VId(48), producer.clone(), "FA-REF-011"),
            (principal, producer.clone().expiring_at(at), "FA-REF-014"),
        ] {
            let refusal = book
                .produce_bundle(actor, &cap, None, &request)
                .unwrap()
                .unwrap_err();
            assert_eq!((refusal.code, refusal.exit), (code, 7));
        }
        // `produce` alone never discloses the journal: a Prefix bundle lists
        // every leaf, so production also needs whole-book read (fa-ku9).
        let produce_only = PolicyCapability::embedded(principal, &["produce"]).unwrap();
        let refusal = book
            .produce_bundle(principal, &produce_only, None, &request)
            .unwrap()
            .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
        let agent =
            PolicyCapability::new(principal, Profile::Agent, &[Op::Produce, Op::Read], VId(1))
                .unwrap();
        let by_agent = book
            .produce_bundle(principal, &agent, None, &request)
            .unwrap()
            .unwrap()
            .expect("the latest state");
        let produced = book
            .produce_bundle(principal, &producer, Some(published.stored.oid), &request)
            .unwrap()
            .unwrap()
            .expect("the named state");
        assert_eq!(
            produced.bundle, by_agent.bundle,
            "the body names no producer"
        );
        assert_ne!(produced.receipt, by_agent.receipt, "the receipt does");
        let report = fa_verify::verify_bundle(
            &produced.bundle.bytes,
            &[book.checkpoint_public_key()],
            Some(&produced.receipt),
        )
        .unwrap();
        assert!(report.verified(), "{:#?}", report.checks);
        let facts = report.receipt.expect("the receipt verified");
        assert_eq!(
            (facts.producer_principal, facts.produced_at_seq),
            (principal.0, at.0)
        );
        assert_eq!(facts.capability_commitment, producer.commitment().unwrap());
        assert_eq!(
            book.produce_bundle(principal, &producer, Some(fa_model::Oid([9; 32])), &request)
                .unwrap()
                .unwrap(),
            None,
            "a state not on the chain"
        );
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
        let source = fa_journal::Document {
            book_id: book.context().book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: principal,
            bytes: b"INVOICE (facade fixture source document)".to_vec(),
        };
        post_rent_citing(book, usd, principal, day, key, cents_credit, &source)
    }

    /// [`post_rent`], citing `source` (added to the book first).
    fn post_rent_citing(
        book: &mut Book,
        usd: fa_money::UnitId,
        principal: VId,
        day: DateDay,
        key: &[u8],
        cents_credit: i128,
        source: &fa_journal::Document,
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
        book.add_document(source)?
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

    fn certified_fixture() -> (Book, fa_money::UnitId, DateDay, VId) {
        let (spec, usd) = spec(Id128([0xc1; 16]));
        let mut book = Book::create_memory(
            BookKeys::for_development(0xc1),
            spec,
            Entropy::deterministic(193),
        )
        .unwrap();
        let principal = VId(1);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        book.install_chart(&chart(usd), principal, day, b"cert-chart")
            .unwrap()
            .unwrap();
        book.create_periods(2026).unwrap();
        for (code, date) in [
            ("FY2026-P03", day),
            ("FY2026-P04", DateDay::from_ymd(2026, 4, 1).unwrap()),
        ] {
            book.transition_period(
                code,
                PeriodTransition::Open,
                principal,
                1,
                date,
                code.as_bytes(),
                &Capability::embedded(principal, &["close"]).unwrap(),
            )
            .unwrap()
            .unwrap();
        }
        let posted = post_rent(&mut book, usd, principal, day, b"cert-rent", 150_000)
            .unwrap()
            .unwrap();
        (book, usd, day, posted.entry_ref().vid)
    }

    fn certificate_tick(book: &mut Book, ns: u64, monotonic_ok: bool) -> fa_journal::Ticked {
        let (runtime, root) = Book::runtime_and_root().unwrap();
        let witness = Capability::embedded(VId(1), &["witness"]).unwrap();
        runtime
            .block_on(book.record_tick(&root, ns, monotonic_ok, &witness))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn instant_certificates_keep_their_original_frontier_and_tick_brackets() {
        use crate::{ReportCertificate, TrialBalanceSelection};
        let (mut book, usd, day, _) = certified_fixture();
        let selection = TrialBalanceSelection::Periods(vec!["FY2026-P03".into()]);
        let base = fa_time::UtcInstant::parse("2026-03-15T00:00:00Z")
            .unwrap()
            .unix_ns();
        let refused = book.resolve_known_at_instant(base).unwrap().unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-151", 3));

        let lower = certificate_tick(&mut book, base + 100, true);
        post_rent(&mut book, usd, VId(1), day, b"inside-first-bucket", 150_000)
            .unwrap()
            .unwrap();
        let frontier = book.head().unwrap();
        let open = book
            .certify_trial_balance_at_instant(selection.clone(), base + 105)
            .unwrap()
            .unwrap();
        let evidence = open.certificate.time_selection.as_ref().unwrap();
        assert_eq!(evidence.resolution.frontier, frontier.0);
        assert_eq!(evidence.resolution.resolved_seq, frontier.0);
        assert_eq!(evidence.lower_entry, lower.tick.entry);
        assert!(evidence.resolution.upper.is_none());
        assert!(evidence.upper_entry.is_none());
        assert_eq!(open.report.unit_totals[&usd.0], (300_000, 300_000));
        assert_eq!(book.head().unwrap(), frontier, "certification is read-only");

        // New commits can extend a still-open bucket. Its earlier certificate
        // must replay the old frontier, even after an upper tick later arrives.
        post_rent(&mut book, usd, VId(1), day, b"extend-open-bucket", 150_000)
            .unwrap()
            .unwrap();
        let before_upper = book.head().unwrap();
        let upper = certificate_tick(&mut book, base + 110, false);
        post_rent(&mut book, usd, VId(1), day, b"after-upper-tick", 150_000)
            .unwrap()
            .unwrap();
        let current = book.head().unwrap();
        let closed = book
            .certify_trial_balance_at_instant(selection.clone(), base + 105)
            .unwrap()
            .unwrap();
        let time = closed.certificate.time_selection.as_ref().unwrap();
        assert_eq!(time.resolution.frontier, current.0);
        assert_eq!(time.resolution.resolved_seq, before_upper.0);
        assert_eq!(time.upper_entry, Some(upper.tick.entry));
        assert_eq!(
            time.resolution.upper.unwrap().recorded_at,
            upper.recorded_at.0
        );
        assert_eq!(time.resolution.precision_grade(), "tick_bucket");
        assert_eq!(
            time.resolution.source_grade(),
            "uncorroborated_daemon_clock"
        );
        assert_eq!(closed.report.unit_totals[&usd.0], (450_000, 450_000));
        assert_eq!(
            book.trial_balance(&["FY2026-P03".into()])
                .unwrap()
                .unit_totals[&usd.0],
            (600_000, 600_000)
        );

        for saved in [&open, &closed] {
            let encoded = saved.certificate.canonical_bytes().unwrap();
            assert!(encoded.starts_with(crate::certificate::INSTANT_CERTIFICATE_FORMAT));
            let decoded = ReportCertificate::decode(&encoded).unwrap();
            assert_eq!(decoded, saved.certificate);
            assert_eq!(
                book.replay_trial_balance(&decoded).unwrap().unwrap(),
                saved.report
            );
        }
        assert_eq!(book.head().unwrap(), current, "replay appends nothing");
        let exact = book.resolve_known_at_instant(base + 110).unwrap().unwrap();
        assert_eq!(exact.lower_entry, upper.tick.entry);
        assert_eq!(exact.resolution.resolved_seq, current.0);
        assert!(exact.upper_entry.is_none());
        let before_first = book
            .resolve_known_at_instant(base + 99)
            .unwrap()
            .unwrap_err();
        assert_eq!((before_first.code, before_first.exit), ("FA-REF-151", 3));

        // A self-consistent rehash cannot substitute a different tick identity.
        let mut forged = closed.certificate.clone();
        forged.time_selection.as_mut().unwrap().lower_entry = VId(0xdead);
        let raw = forged.canonical_bytes().unwrap();
        let mut hasher = fgdb_crypto::Hasher::new();
        hasher.update(crate::certificate::INSTANT_CERTIFICATE_FORMAT);
        hasher.update(&raw[..raw.len() - 32]);
        forged.digest = hasher.finalize().0;
        let decoded = ReportCertificate::decode(&forged.canonical_bytes().unwrap()).unwrap();
        let refusal = book.replay_trial_balance(&decoded).unwrap().unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));

        let sequence = book
            .certify_trial_balance(selection, Some(frontier))
            .unwrap()
            .unwrap();
        assert!(sequence.certificate.time_selection.is_none());
        assert!(
            sequence
                .certificate
                .canonical_bytes()
                .unwrap()
                .starts_with(crate::certificate::CERTIFICATE_FORMAT)
        );
        assert_eq!(sequence.report, open.report);
    }

    #[test]
    fn instant_certificate_replay_checks_upper_tick_beyond_the_report_prefix() {
        use crate::TrialBalanceSelection;
        use fa_model::symbols::{property, relation};
        for retire in [false, true] {
            let (mut book, _, day, _) = certified_fixture();
            let base = fa_time::UtcInstant::parse("2026-03-15T00:00:00Z")
                .unwrap()
                .unix_ns();
            certificate_tick(&mut book, base + 100, true);
            let upper = certificate_tick(&mut book, base + 110, true);
            let certificate = book
                .certify_trial_balance_at_instant(TrialBalanceSelection::AsOf(day), base + 105)
                .unwrap()
                .unwrap()
                .certificate;
            let frontier = CommitSeq(
                certificate
                    .time_selection
                    .as_ref()
                    .unwrap()
                    .resolution
                    .frontier,
            );
            assert!(certificate.known_at < upper.recorded_at);
            assert!(book.replay_trial_balance(&certificate).unwrap().is_ok());

            // The upper bracket lies outside the report's native read closure.
            // Its later alteration must still invalidate the time interpretation.
            let contexts = book.purposes();
            let mut change = fgdb::WriteBatch::new(relation::HAS_LEG);
            if retire {
                change.delete_vertex(upper.entry_ref.vid);
            } else {
                change.set_vertex_property(
                    upper.entry_ref.vid,
                    property::FA_PAYLOAD,
                    Some(fgdb_types::CanonicalScalar::bytes(b"rewritten tick".to_vec()).unwrap()),
                );
            }
            with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&contexts.commit(), change))).unwrap();
            let historical =
                with_store!(&book.store, core => core.db.vertex_at(upper.entry_ref.vid, frontier))
                    .unwrap()
                    .unwrap();
            let old = Entry::decode(
                &fa_journal::rows::bytes(&historical, property::FA_PAYLOAD, "tick.payload")
                    .unwrap(),
            )
            .unwrap();
            assert!(matches!(
                old.proposal.control,
                Some(fa_model::ControlPayload::TimeTick { observed_utc_ns, .. })
                    if observed_utc_ns == base + 110
            ));
            let head = book.head().unwrap();
            let refusal = book
                .replay_trial_balance(&certificate)
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
            assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
            assert!(book.certificate_status(&certificate).unwrap().is_err());
            assert_eq!(
                book.head().unwrap(),
                head,
                "failed reads never repair or append"
            );
        }
    }

    #[test]
    fn certified_trial_balance_replays_after_later_and_backdated_postings() {
        use crate::{CertificateStatus, ReportCertificate, TrialBalanceSelection};
        let (mut book, usd, day, _) = certified_fixture();
        let before = book.head().unwrap();
        let selection = TrialBalanceSelection::Periods(vec!["FY2026-P03".into()]);
        let certified = book
            .certify_trial_balance(selection.clone(), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            book.head().unwrap(),
            before,
            "certification must not write to its input book"
        );
        assert_eq!(certified.report.known_at, before);
        assert_eq!(certified.report.unit_totals[&usd.0], (150_000, 150_000));
        assert_eq!(
            certified.certificate.inputs.len(),
            7,
            "metadata is part of the certified closure"
        );
        assert!(
            certified
                .certificate
                .inputs
                .iter()
                .all(|input| input.plan.snapshot_seq == before)
        );
        let serialized = certified.certificate.canonical_bytes().unwrap();
        let certificate = ReportCertificate::decode(&serialized).unwrap();
        assert_eq!(certificate, certified.certificate);
        assert_eq!(
            book.replay_trial_balance(&certificate).unwrap().unwrap(),
            certified.report
        );
        assert!(matches!(
            book.certificate_status(&certificate).unwrap().unwrap(),
            CertificateStatus::Current { .. }
        ));
        // Repeated selections normalize to exactly the same artifact at the
        // same sequence, independent of caller spelling/order.
        let duplicate = book
            .certify_trial_balance(
                TrialBalanceSelection::Periods(vec!["FY2026-P03".into(), "FY2026-P03".into()]),
                Some(before),
            )
            .unwrap()
            .unwrap();
        assert_eq!(duplicate.certificate.canonical_bytes().unwrap(), serialized);

        post_rent(
            &mut book,
            usd,
            VId(1),
            DateDay::from_ymd(2026, 4, 15).unwrap(),
            b"later-april",
            150_000,
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            book.certificate_status(&certificate).unwrap().unwrap(),
            CertificateStatus::Current { .. }
        ));
        assert_eq!(
            book.replay_trial_balance(&certificate)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            certificate.output
        );
        let backdated = post_rent(&mut book, usd, VId(1), day, b"backdated-march", 150_000)
            .unwrap()
            .unwrap();
        let superseded = match book.certificate_status(&certificate).unwrap().unwrap() {
            CertificateStatus::SupersededBy {
                later_entries,
                checked_at,
            } => Ok((later_entries, checked_at)),
            state => Err(format!(
                "backdated in-scope posting did not supersede report: {state:?}"
            )),
        };
        let (later_entries, checked_at) =
            superseded.expect("backdated in-scope posting did not supersede report");
        assert_eq!(later_entries, vec![backdated.entry_ref().vid]);
        assert_eq!(checked_at, book.head().unwrap());
        assert_eq!(
            book.trial_balance(&["FY2026-P03".into()])
                .unwrap()
                .unit_totals[&usd.0],
            (300_000, 300_000)
        );
        assert_eq!(
            book.replay_trial_balance(&certificate).unwrap().unwrap(),
            certified.report,
            "replay must never replace the certified coordinate with HEAD"
        );
        assert_eq!(
            book.certify_trial_balance(selection, Some(before))
                .unwrap()
                .unwrap()
                .certificate
                .canonical_bytes()
                .unwrap(),
            serialized
        );
    }

    #[test]
    fn generic_certificates_replay_exact_reports_and_retain_each_report_family() {
        use crate::{CertificateStatus, ReportCertificate, ReportOutput, ReportSelection};
        let (mut book, _, day, _) = certified_fixture();
        let cash = account_vid(book.context().book_id, "1000");
        let at = book.head().unwrap();
        let expected = [
            ReportOutput::ExplainBalance(Box::new(
                book.explain_balance(cash, "FY2026-P03", Some(at)).unwrap(),
            )),
            ReportOutput::OpenItems(book.open_items_report(Some(cash), Some(at)).unwrap()),
            ReportOutput::OpenItems(book.open_items_report(None, Some(at)).unwrap()),
        ];
        let selections = [
            ReportSelection::ExplainBalance {
                account: cash,
                period: "FY2026-P03".into(),
            },
            ReportSelection::OpenItems {
                account: Some(cash),
            },
            ReportSelection::OpenItems { account: None },
        ];
        let mut certified = Vec::new();
        for (selection, expected) in selections.into_iter().zip(expected) {
            let result = book
                .certify_report(selection.clone(), Some(at))
                .unwrap()
                .unwrap();
            assert_eq!(result.report, expected);
            assert_eq!(result.report.known_at(), at);
            assert_eq!(result.certificate.known_at, at);
            assert_eq!(result.certificate.selection, selection);
            assert_eq!(
                result.certificate.output,
                result.report.canonical_bytes().unwrap()
            );
            assert_eq!(
                result.certificate.output_format(),
                selection.output_format()
            );
            assert!(result.certificate.time_selection.is_none());
            let bytes = result.certificate.canonical_bytes().unwrap();
            assert!(bytes.starts_with(crate::certificate::REPORT_CERTIFICATE_FORMAT));
            assert_eq!(
                ReportCertificate::decode(&bytes).unwrap(),
                result.certificate
            );
            assert_eq!(
                book.replay_report(&result.certificate).unwrap().unwrap(),
                result.report
            );
            assert_eq!(
                book.replay_trial_balance(&result.certificate)
                    .unwrap()
                    .unwrap_err()
                    .code,
                crate::certificate::code::CERTIFICATE_INVALID,
                "the typed trial-balance API must refuse a different report family"
            );
            certified.push(result);
        }
        assert_eq!(
            book.head().unwrap(),
            at,
            "certification and replay are reads"
        );
        assert_ne!(
            certified[1].certificate.digest, certified[2].certificate.digest,
            "the account filter is part of the certificate identity"
        );
        for result in certified {
            let retained = book
                .retain_certificate(&result.certificate)
                .unwrap()
                .unwrap();
            let loaded = book.read_certificate(&retained.digest).unwrap().unwrap();
            assert_eq!(loaded, result.certificate);
            assert_eq!(book.replay_report(&loaded).unwrap().unwrap(), result.report);
            assert_eq!(book.retain_certificate(&loaded).unwrap().unwrap(), retained);
            assert_eq!(book.head().unwrap(), retained.recorded_at);
            assert_eq!(
                book.certificate_status(&loaded).unwrap().unwrap(),
                CertificateStatus::Current {
                    checked_at: retained.recorded_at,
                }
            );
        }
        // Trial-balance callers retain the original sequence wire version.
        let trial = book
            .certify_report(crate::TrialBalanceSelection::AsOf(day).into(), Some(at))
            .unwrap()
            .unwrap();
        assert!(
            trial
                .certificate
                .canonical_bytes()
                .unwrap()
                .starts_with(crate::certificate::CERTIFICATE_FORMAT)
        );
        assert_eq!(
            trial.report,
            ReportOutput::TrialBalance(book.balance_as_of(day, Some(at)).unwrap())
        );
    }

    #[test]
    fn report_status_respects_account_filters_and_the_complete_explanation_fold() {
        use crate::{CertificateStatus, ReportSelection};
        let (mut book, usd, day, original) = certified_fixture();
        let book_id = book.context().book_id;
        let cash = account_vid(book_id, "1000");
        let explanation = book
            .certify_report(
                ReportSelection::ExplainBalance {
                    account: cash,
                    period: "FY2026-P03".into(),
                },
                None,
            )
            .unwrap()
            .unwrap();
        let filtered = book
            .certify_report(
                ReportSelection::OpenItems {
                    account: Some(cash),
                },
                None,
            )
            .unwrap()
            .unwrap();
        let all = book
            .certify_report(ReportSelection::OpenItems { account: None }, None)
            .unwrap()
            .unwrap();
        let accounts = [
            AccountSpec {
                code: "2000".into(),
                name: "Other asset".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
            AccountSpec {
                code: "7000".into(),
                name: "Other expense".into(),
                account_type: 5,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
        ];
        book.install_chart(&accounts, VId(1), day, b"additional-report-accounts")
            .unwrap()
            .unwrap();
        for result in [&explanation, &filtered, &all] {
            assert!(
                matches!(
                    book.certificate_status(&result.certificate)
                        .unwrap()
                        .unwrap(),
                    CertificateStatus::Current { .. }
                ),
                "unrelated accounts with no contributions do not change rendered reports"
            );
        }
        let mut proposal = book.read_entry(original).unwrap().unwrap().0.proposal;
        proposal.idempotency_key = b"other-accounts-same-period".to_vec();
        for leg in &mut proposal.legs {
            leg.account_ref = if leg.account_ref == cash {
                account_vid(book_id, "2000")
            } else {
                account_vid(book_id, "7000")
            };
        }
        let later = book
            .post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(VId(1), &["post"]).unwrap(),
            })
            .unwrap()
            .unwrap()
            .entry_ref()
            .vid;
        assert!(
            matches!(
                book.certificate_status(&filtered.certificate)
                    .unwrap()
                    .unwrap(),
                CertificateStatus::Current { .. }
            ),
            "the filtered open-item report excludes other accounts"
        );
        for result in [&explanation, &all] {
            assert!(
                matches!(
                    book.certificate_status(&result.certificate).unwrap().unwrap(),
                    CertificateStatus::SupersededBy { later_entries, .. }
                        if later_entries == vec![later]
                ),
                "an explanation binds the whole period fold; unfiltered open items include every account"
            );
        }
        for result in [&explanation, &filtered, &all] {
            assert_eq!(
                book.replay_report(&result.certificate).unwrap().unwrap(),
                result.report,
                "a superseded report still replays its exact original output"
            );
        }
        let april = post_rent(
            &mut book,
            usd,
            VId(1),
            DateDay::from_ymd(2026, 4, 15).unwrap(),
            b"april-open-item",
            150_000,
        )
        .unwrap()
        .unwrap()
        .entry_ref()
        .vid;
        assert!(
            matches!(
                book.certificate_status(&explanation.certificate).unwrap().unwrap(),
                CertificateStatus::SupersededBy { later_entries, .. }
                    if later_entries == vec![later]
            ),
            "an April posting does not add to the March explanation's affected entries"
        );
        assert!(
            matches!(
                book.certificate_status(&filtered.certificate).unwrap().unwrap(),
                CertificateStatus::SupersededBy { later_entries, .. }
                    if later_entries == vec![april]
            ),
            "open items have no effective-date cutoff"
        );
    }

    #[test]
    fn report_replay_keeps_historical_account_metadata_and_status_refuses_rebinding() {
        use crate::{ReportOutput, ReportSelection};
        use fa_model::symbols::{property, relation};
        let (mut book, _, _, _) = certified_fixture();
        let cash = account_vid(book.context().book_id, "1000");
        let at = book.head().unwrap();
        let mut results = Vec::new();
        for selection in [
            ReportSelection::ExplainBalance {
                account: cash,
                period: "FY2026-P03".into(),
            },
            ReportSelection::OpenItems {
                account: Some(cash),
            },
            ReportSelection::OpenItems { account: None },
        ] {
            results.push(book.certify_report(selection, Some(at)).unwrap().unwrap());
        }
        // This raw rewrite plants corruption; no supported chart operation
        // currently changes an existing account's immutable identity.
        let contexts = book.purposes();
        let mut change = fgdb::WriteBatch::new(relation::HAS_LEG);
        change.set_vertex_property(
            cash,
            property::NAME,
            Some(fa_journal::rows::scalar_text("changed account name", "Changed Cash").unwrap()),
        );
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&contexts.commit(), change)))
            .unwrap();
        let after = book.head().unwrap();
        assert!(after > at);
        assert_eq!(
            book.open_items_report(Some(cash), None).unwrap().accounts[&cash].name,
            "Changed Cash"
        );
        assert_eq!(
            book.open_items_report(Some(cash), Some(at))
                .unwrap()
                .accounts[&cash]
                .name,
            "Cash"
        );
        assert_eq!(
            book.explain_balance(cash, "FY2026-P03", Some(at))
                .unwrap()
                .account_row
                .name,
            "Cash"
        );
        for result in results {
            let replayed = book.replay_report(&result.certificate).unwrap().unwrap();
            assert_eq!(replayed, result.report);
            assert!(
                matches!(
                    replayed,
                    ReportOutput::ExplainBalance(_) | ReportOutput::OpenItems(_)
                ),
                "selected an explanation or open-items report"
            );
            match &replayed {
                ReportOutput::ExplainBalance(report) => assert_eq!(report.account_row.name, "Cash"),
                ReportOutput::OpenItems(report) => assert_eq!(report.accounts[&cash].name, "Cash"),
                ReportOutput::TrialBalance(_) | ReportOutput::Statement(_) => {}
            }
            let refusal = book
                .certificate_status(&result.certificate)
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
            assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
        }
        assert_eq!(
            book.head().unwrap(),
            after,
            "replay and status do not repair the chart"
        );
    }

    #[test]
    fn certification_requires_genesis_and_the_historical_runtime_context() {
        use crate::{ReportSelection, TrialBalanceSelection};
        let (book, _, day, _) = certified_fixture();
        let cash = account_vid(book.context().book_id, "1000");
        let at = book.head().unwrap();
        for selection in [
            TrialBalanceSelection::AsOf(day).into(),
            ReportSelection::ExplainBalance {
                account: cash,
                period: "FY2026-P03".into(),
            },
            ReportSelection::OpenItems {
                account: Some(cash),
            },
            ReportSelection::OpenItems { account: None },
        ] {
            let error = book
                .certify_report(selection, Some(CommitSeq(0)))
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    BookError::Registers(fa_registers::RegisterError::InvalidSelection(_))
                ),
                "{error}"
            );
        }
        let certificate = book
            .certify_report(TrialBalanceSelection::AsOf(day).into(), Some(at))
            .unwrap()
            .unwrap()
            .certificate;
        let mut context = book.context().clone();
        context.calendar = FiscalCalendar::monthly("different-calendar", 1, 1).unwrap();
        let purposes = book.purposes();
        let error = with_store!(&book.store, core => crate::certificate::certify_report(
            &core.db,
            &purposes.query(),
            &context,
            TrialBalanceSelection::AsOf(day).into(),
            Some(at),
        ))
        .unwrap_err();
        assert!(error.to_string().contains("context differs"), "{error}");
        let refusal = with_store!(&book.store, core => crate::certificate::replay_report(
            &core.db,
            &purposes.query(),
            &context,
            &certificate,
        ))
        .unwrap()
        .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(book.head().unwrap(), at);
    }

    #[test]
    fn generic_instant_certificates_preserve_the_original_sequence_and_tick_brackets() {
        use crate::{ReportCertificate, ReportSelection};
        let (mut book, usd, day, _) = certified_fixture();
        let cash = account_vid(book.context().book_id, "1000");
        let base = fa_time::UtcInstant::parse("2026-03-15T00:00:00Z")
            .unwrap()
            .unix_ns();
        let lower = certificate_tick(&mut book, base + 100, true);
        post_rent(
            &mut book,
            usd,
            VId(1),
            day,
            b"generic-inside-bucket",
            150_000,
        )
        .unwrap()
        .unwrap();
        let selected_at = book.head().unwrap();
        let upper = certificate_tick(&mut book, base + 110, true);
        post_rent(
            &mut book,
            usd,
            VId(1),
            day,
            b"generic-after-bucket",
            150_000,
        )
        .unwrap()
        .unwrap();
        let frontier = book.head().unwrap();
        let mut results = Vec::new();
        for selection in [
            ReportSelection::ExplainBalance {
                account: cash,
                period: "FY2026-P03".into(),
            },
            ReportSelection::OpenItems {
                account: Some(cash),
            },
        ] {
            let result = book
                .certify_report_at_instant(selection.clone(), base + 105)
                .unwrap()
                .unwrap();
            let time = result.certificate.time_selection.as_ref().unwrap();
            assert_eq!(time.resolution.frontier, frontier.0);
            assert_eq!(time.resolution.resolved_seq, selected_at.0);
            assert_eq!(time.lower_entry, lower.tick.entry);
            assert_eq!(time.upper_entry, Some(upper.tick.entry));
            assert_eq!(result.certificate.known_at, selected_at);
            assert_eq!(
                result.report,
                book.certify_report(selection, Some(selected_at))
                    .unwrap()
                    .unwrap()
                    .report
            );
            let encoded = result.certificate.canonical_bytes().unwrap();
            assert!(encoded.starts_with(crate::certificate::REPORT_CERTIFICATE_FORMAT));
            assert_eq!(
                ReportCertificate::decode(&encoded).unwrap(),
                result.certificate
            );
            results.push(result);
        }
        assert_eq!(book.head().unwrap(), frontier);
        certificate_tick(&mut book, base + 120, true);
        for result in results {
            let retained = book
                .retain_certificate(&result.certificate)
                .unwrap()
                .unwrap();
            let loaded = book.read_certificate(&retained.digest).unwrap().unwrap();
            assert_eq!(loaded, result.certificate);
            assert_eq!(book.replay_report(&loaded).unwrap().unwrap(), result.report);
            let mut altered = loaded;
            altered
                .time_selection
                .as_mut()
                .unwrap()
                .resolution
                .requested_utc_ns += 1;
            let refusal = book.replay_report(&altered).unwrap().unwrap_err();
            assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
            assert_eq!(book.head().unwrap(), retained.recorded_at);
        }
    }

    #[test]
    fn certificate_status_detects_period_catalog_changes_without_a_new_entry() {
        use crate::{CertificateStatus, TrialBalanceSelection};
        let (mut book, _, day, _) = certified_fixture();
        let certified = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap();
        let original_at = certified.certificate.known_at;
        // Period creation is supported and commits metadata without an Entry.
        // An as-of report displays every discovered period through its cutoff.
        book.create_periods(2025).unwrap();
        let after = book.head().unwrap();
        assert!(after > original_at);
        let current = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap();
        assert_ne!(current.report.periods, certified.report.periods);
        assert_eq!(
            current.certificate.journal_root,
            certified.certificate.journal_root
        );
        assert_eq!(
            current.certificate.journal_leaves, certified.certificate.journal_leaves,
            "no later accounting Entry can explain this period-membership change"
        );
        let refusal = book
            .certificate_status(&certified.certificate)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
        assert_eq!(
            book.replay_trial_balance(&certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report,
            "metadata changes do not rewrite the original historical report"
        );
        assert_eq!(
            book.certificate_status(&current.certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::Current { checked_at: after }
        );
        assert_eq!(book.head().unwrap(), after);
    }

    #[test]
    fn retained_certificates_are_idempotent_without_changing_the_certified_report() {
        use crate::{CertificateStatus, TrialBalanceSelection};
        let (mut book, _, day, _) = certified_fixture();
        let certified = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap();
        let original_bytes = certified.certificate.canonical_bytes().unwrap();
        let original_at = certified.certificate.known_at;
        let retained = book
            .retain_certificate(&certified.certificate)
            .unwrap()
            .unwrap();
        assert_eq!(retained.digest, certified.certificate.digest);
        assert!(retained.recorded_at > original_at);
        assert_eq!(book.head().unwrap(), retained.recorded_at);
        assert_eq!(
            book.read_certificate(&retained.digest)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            original_bytes
        );
        assert_eq!(
            book.retain_certificate(&certified.certificate)
                .unwrap()
                .unwrap(),
            retained,
            "retention retries return the original storage outcome"
        );
        assert_eq!(book.head().unwrap(), retained.recorded_at);
        assert_eq!(
            book.replay_trial_balance(&certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
        assert_eq!(
            book.certificate_status(&certified.certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::Current {
                checked_at: retained.recorded_at,
            }
        );
        let after = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.certificate.journal_root,
            certified.certificate.journal_root
        );
        assert_eq!(
            after.certificate.journal_leaves, certified.certificate.journal_leaves,
            "retaining a report creates no accounting Entry"
        );
        let original_again = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), Some(original_at))
            .unwrap()
            .unwrap();
        assert_eq!(
            original_again.certificate.canonical_bytes().unwrap(),
            original_bytes
        );

        let before_refusal = book.head().unwrap();
        let mut altered = certified.certificate.clone();
        altered.output[0] ^= 1;
        let refusal = book.retain_certificate(&altered).unwrap().unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
        assert_eq!(book.head().unwrap(), before_refusal);
        assert_eq!(
            book.read_certificate(&[0xe7; 32])
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-150"
        );

        let (foreign_spec, _) = spec(Id128([0xd1; 16]));
        let mut foreign = Book::create_memory(
            BookKeys::for_development(0xd1),
            foreign_spec,
            Entropy::deterministic(209),
        )
        .unwrap();
        let foreign_head = foreign.head().unwrap();
        let refusal = foreign
            .retain_certificate(&certified.certificate)
            .unwrap()
            .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
        assert_eq!(foreign.head().unwrap(), foreign_head);
    }

    #[test]
    fn historical_inline_certificate_retries_do_not_reselect_placement() {
        use crate::TrialBalanceSelection;
        use fa_model::symbols::{label, property, relation};
        use fgdb_types::CanonicalScalar;

        let (mut book, usd, day, original) = certified_fixture();
        let template = book.read_entry(original).unwrap().unwrap().0.proposal;
        let mut selected = None;
        // Add distinct, posted leaf accounts: more entries on the same
        // accounts change totals, but do not add trial-balance rows. Do not
        // pad a certificate or alter its committed output to create a size.
        for n in 0..128 {
            let certified = book
                .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
                .unwrap()
                .unwrap();
            assert_eq!(certified.report.rows.len(), n + 2);
            let bytes = certified.certificate.canonical_bytes().unwrap();
            let payload = CanonicalScalar::bytes(bytes.clone()).unwrap();
            if payload.canonical_encoded_len().unwrap()
                > crate::certificate_store::MAX_INLINE_CERTIFICATE_BYTES
            {
                selected = Some((certified, bytes, payload));
                break;
            }
            let code = format!("7{n:03}");
            book.install_chart(
                &[AccountSpec {
                    code: code.clone(),
                    name: format!("Rent allocation {n}"),
                    account_type: 5,
                    normal_balance: 0,
                    is_leaf: true,
                    unit_policy: UnitPolicy::Single(usd),
                    parent_code: None,
                    limit: None,
                }],
                VId(1),
                day,
                format!("legacy-inline-chart-{n}").as_bytes(),
            )
            .unwrap()
            .unwrap();
            let mut proposal = template.clone();
            proposal.idempotency_key = format!("legacy-inline-rent-{n}").into_bytes();
            proposal.legs[0].account_ref = account_vid(book.context().book_id, &code);
            book.post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(VId(1), &["post"]).unwrap(),
            })
            .unwrap()
            .unwrap();
        }
        let (certified, bytes, payload) =
            selected.expect("the bounded real history crosses the inline policy cutoff");
        let certificate = certified.certificate;
        let vid =
            crate::certificate_store::certificate_vid(book.context().book_id, &certificate.digest);

        // Reproduce the historical producer's first retention, which always
        // stored canonical bytes inline. Native admission must accept the
        // complete row: a format-valid but oversized fixture is not enough.
        let mut properties = vec![
            (property::FA_PAYLOAD, payload),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(certificate.digest.to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(book.context().book_id.0.to_vec()).unwrap(),
            ),
        ];
        properties.sort_by_key(|(key, _)| key.0);
        let purposes = book.purposes();
        let mut create = fgdb::WriteBatch::new(relation::DERIVED_FROM);
        create.create_vertex(vid, vec![label::CERTIFICATE], properties);
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&purposes.commit(), create)))
            .expect("the historical inline representation fits the native row");
        let recorded_at = book.head().unwrap();
        assert!(recorded_at > certificate.known_at);

        assert_eq!(
            book.read_certificate(&certificate.digest).unwrap().unwrap(),
            certificate
        );
        assert_eq!(
            book.replay_trial_balance(&certificate).unwrap().unwrap(),
            certified.report
        );
        let retained = book.retain_certificate(&certificate).unwrap().unwrap();
        assert_eq!(retained.digest, certificate.digest);
        assert_eq!(retained.recorded_at, recorded_at);
        assert_eq!(book.head().unwrap(), recorded_at);
        let row = with_store!(&book.store, core => core.db.vertex(vid))
            .unwrap()
            .unwrap();
        assert_eq!(row.created_at, recorded_at);
        assert_eq!(
            fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "historical certificate").unwrap(),
            bytes,
            "retry preserves the original inline bytes despite the new placement policy"
        );
    }

    #[test]
    fn initial_certificate_retention_can_follow_unrelated_commits() {
        use crate::TrialBalanceSelection;

        let (mut book, _, day, _) = certified_fixture();
        let certified = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap();
        let original_bytes = certified.certificate.canonical_bytes().unwrap();
        let document = fa_journal::Document {
            book_id: book.context().book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: VId(1),
            bytes: b"Unrelated document recorded before delayed certificate retention".to_vec(),
        };
        book.add_document(&document).unwrap().unwrap();
        let after_unrelated = book.head().unwrap();
        assert!(after_unrelated > certified.certificate.known_at);
        let retained = book
            .retain_certificate(&certified.certificate)
            .unwrap()
            .unwrap();
        assert!(retained.recorded_at > after_unrelated);
        assert_eq!(
            book.read_certificate(&retained.digest)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            original_bytes
        );
        assert_eq!(
            book.retain_certificate(&certified.certificate)
                .unwrap()
                .unwrap(),
            retained
        );
        assert_eq!(
            book.replay_trial_balance(&certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report,
            "delayed retention preserves the original historical report"
        );
        assert_eq!(book.head().unwrap(), retained.recorded_at);
    }

    #[test]
    fn restored_certificate_bytes_do_not_hide_a_later_record_version() {
        use crate::{ReportCertificate, TrialBalanceSelection};
        use fa_model::symbols::{property, relation};
        use fgdb_types::CanonicalScalar;

        let (mut book, _, day, _) = certified_fixture();
        let certified = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap();
        let certificate = certified.certificate;
        let retained = book.retain_certificate(&certificate).unwrap().unwrap();
        let vid =
            crate::certificate_store::certificate_vid(book.context().book_id, &retained.digest);
        let original = with_store!(&book.store, core => core.db.vertex(vid))
            .unwrap()
            .unwrap();
        let purposes = book.purposes();
        let mut damage = fgdb::WriteBatch::new(relation::DERIVED_FROM);
        damage.set_vertex_property(
            vid,
            property::FA_DIGEST,
            Some(CanonicalScalar::bytes(vec![0x71; 32]).unwrap()),
        );
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&purposes.commit(), damage)))
            .unwrap();
        let mut restore = fgdb::WriteBatch::new(relation::DERIVED_FROM);
        restore.set_vertex_property(
            vid,
            property::FA_DIGEST,
            Some(
                fa_journal::rows::prop(&original, property::FA_DIGEST)
                    .unwrap()
                    .clone(),
            ),
        );
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&purposes.commit(), restore)))
            .unwrap();

        let current = with_store!(&book.store, core => core.db.vertex(vid))
            .unwrap()
            .unwrap();
        assert_eq!(
            current.props, original.props,
            "all exact bytes were restored"
        );
        assert_eq!(current.labels, original.labels);
        assert!(current.created_at > retained.recorded_at);
        let same_version =
            with_store!(&book.store, core => core.db.vertex_at(vid, current.created_at))
                .unwrap()
                .unwrap();
        assert_eq!(
            same_version, current,
            "comparing only the claimed creating snapshot cannot detect the rewrite"
        );
        let before_refusal = book.head().unwrap();
        let refusal = book
            .read_certificate(&retained.digest)
            .unwrap()
            .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
        assert!(refusal.message.contains("existed before"), "{refusal}");
        let refusal = book.retain_certificate(&certificate).unwrap().unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
        assert_eq!(
            book.head().unwrap(),
            before_refusal,
            "no silent repair or re-retention"
        );

        let historical =
            with_store!(&book.store, core => core.db.vertex_at(vid, retained.recorded_at))
                .unwrap()
                .unwrap();
        let original_bytes =
            fa_journal::rows::bytes(&historical, property::FA_PAYLOAD, "historical certificate")
                .unwrap();
        assert_eq!(
            ReportCertificate::decode(&original_bytes).unwrap(),
            certificate
        );
        assert_eq!(
            book.replay_trial_balance(&certificate).unwrap().unwrap(),
            certified.report,
            "the original report and certificate remain readable in history"
        );
        assert_eq!(book.head().unwrap(), before_refusal);
    }

    #[test]
    fn retained_certificate_rewrites_and_retirements_are_refused_without_repairing_history() {
        use crate::TrialBalanceSelection;
        use fa_model::symbols::{label, property, relation};
        use fgdb_types::CanonicalScalar;

        for mutation in 0..5 {
            let (mut book, _, day, _) = certified_fixture();
            let certificate = book
                .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
                .unwrap()
                .unwrap()
                .certificate;
            let retained = book.retain_certificate(&certificate).unwrap().unwrap();
            let vid =
                crate::certificate_store::certificate_vid(book.context().book_id, &retained.digest);
            let mut change = fgdb::WriteBatch::new(relation::HAS_LEG);
            match mutation {
                0 => change.set_vertex_property(
                    vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(b"rewritten certificate".to_vec()).unwrap()),
                ),
                1 => change.set_vertex_property(
                    vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0x71; 32]).unwrap()),
                ),
                2 => change.set_vertex_property(
                    vid,
                    property::BOOK_ID,
                    Some(CanonicalScalar::bytes(vec![0x72; 16]).unwrap()),
                ),
                3 => change.set_vertex_label(vid, label::CERTIFICATE, false),
                _ => change.delete_vertex(vid),
            };
            let purposes = book.purposes();
            with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&purposes.commit(), change)))
                .unwrap();
            let after_tamper = book.head().unwrap();
            let refusal = book
                .read_certificate(&retained.digest)
                .unwrap()
                .unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
            let refusal = book.retain_certificate(&certificate).unwrap().unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
            assert_eq!(book.head().unwrap(), after_tamper);
            let original =
                with_store!(&book.store, core => core.db.vertex_at(vid, retained.recorded_at))
                    .unwrap()
                    .unwrap();
            assert_eq!(
                fa_journal::rows::bytes(&original, property::FA_PAYLOAD, "retained certificate")
                    .unwrap(),
                certificate.canonical_bytes().unwrap()
            );
        }
    }

    #[test]
    fn retained_certificate_cannot_be_rebound_from_an_earlier_unrelated_record() {
        use crate::TrialBalanceSelection;
        use fa_model::symbols::{label, property, relation};
        use fgdb_types::CanonicalScalar;

        let (mut book, _, day, _) = certified_fixture();
        let certificate = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap()
            .certificate;
        let vid =
            crate::certificate_store::certificate_vid(book.context().book_id, &certificate.digest);
        let mut properties = vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(b"unrelated original payload".to_vec()).unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(certificate.digest.to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(book.context().book_id.0.to_vec()).unwrap(),
            ),
        ];
        properties.sort_by_key(|(key, _)| key.0);
        let purposes = book.purposes();
        let mut create = fgdb::WriteBatch::new(relation::DERIVED_FROM);
        create.create_vertex(vid, vec![label::CERTIFICATE], properties);
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&purposes.commit(), create)))
            .unwrap();
        let mut replace = fgdb::WriteBatch::new(relation::DERIVED_FROM);
        replace.set_vertex_property(
            vid,
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(certificate.canonical_bytes().unwrap()).unwrap()),
        );
        with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&purposes.commit(), replace)))
            .unwrap();
        let after_rebind = book.head().unwrap();
        let refusal = book
            .read_certificate(&certificate.digest)
            .unwrap()
            .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
        let refusal = book.retain_certificate(&certificate).unwrap().unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
        assert_eq!(book.head().unwrap(), after_rebind);
    }

    #[test]
    fn certificate_binds_selectors_registry_native_inputs_and_exact_amounts() {
        use crate::{ReportCertificate, TrialBalanceSelection};
        let (book, _, day, _) = certified_fixture();
        let certified = book
            .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap();
        let original = certified.certificate;
        let activity = book
            .certify_trial_balance(
                TrialBalanceSelection::Activity(vec!["FY2026-P03".into()]),
                None,
            )
            .unwrap()
            .unwrap();
        assert_ne!(activity.certificate.digest, original.digest);
        assert!(activity.report.activity);
        assert_eq!(
            book.replay_trial_balance(&activity.certificate)
                .unwrap()
                .unwrap(),
            activity.report
        );
        for tamper in 0..8 {
            let mut altered = original.clone();
            match tamper {
                0 => altered.known_at = CommitSeq(altered.known_at.0 + 1),
                1 => altered.selection = TrialBalanceSelection::AsOf(DateDay(day.0 - 1)).into(),
                2 => altered.registry_digest[0] ^= 1,
                3 => altered.inputs[0].result_digest.0[0] ^= 1,
                4 => {
                    altered.inputs.pop();
                }
                5 => altered.output[0] ^= 1,
                6 => altered.output_digest[0] ^= 1,
                _ => altered.journal_leaves += 1,
            }
            let refusal = book.replay_trial_balance(&altered).unwrap().unwrap_err();
            assert_eq!(
                refusal.code,
                crate::certificate::code::CERTIFICATE_INVALID,
                "tamper {tamper}"
            );
            assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
            assert!(ReportCertificate::decode(&altered.canonical_bytes().unwrap()).is_err());
        }
        let wire = original.canonical_bytes().unwrap();
        for length in [0, 1, 23, 24, wire.len() / 2, wire.len() - 1] {
            assert!(
                ReportCertificate::decode(&wire[..length]).is_err(),
                "truncation {length}"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(ReportCertificate::decode(&trailing).is_err());
        // Changing one exact amount by a single minor unit changes the output
        // commitment; display precision or a float tolerance cannot mask it.
        let mut changed_report = certified.report;
        changed_report.rows[0].debits += 1;
        assert_ne!(changed_report.canonical_bytes().unwrap(), original.output);
    }

    #[test]
    fn certificate_replay_detects_rewrites_and_retirements_after_its_snapshot() {
        use crate::TrialBalanceSelection;
        use fa_model::symbols::{property, relation};
        for retire in [false, true] {
            let (mut book, _, day, target) = certified_fixture();
            let certificate = book
                .certify_trial_balance(TrialBalanceSelection::AsOf(day), None)
                .unwrap()
                .unwrap()
                .certificate;
            let contexts = book.purposes();
            let mut change = fgdb::WriteBatch::new(relation::HAS_LEG);
            if retire {
                change.delete_vertex(target);
            } else {
                change.set_vertex_property(
                    target,
                    property::FA_PAYLOAD,
                    Some(fgdb_types::CanonicalScalar::bytes(b"rewritten".to_vec()).unwrap()),
                );
            }
            with_store!(&mut book.store, core => book.runtime.block_on(core.db.write(&contexts.commit(), change))).unwrap();
            // The historical snapshot remains readable, which is why checking
            // only its accumulator would overlook this later journal rewrite.
            let old_row =
                with_store!(&book.store, core => core.db.vertex_at(target, certificate.known_at))
                    .unwrap()
                    .unwrap();
            let old = Entry::decode(
                &fa_journal::rows::bytes(&old_row, property::FA_PAYLOAD, "entry.payload").unwrap(),
            )
            .unwrap();
            assert_eq!(old.proposal.effective_date, day);
            let refusal = book
                .replay_trial_balance(&certificate)
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
            assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
            assert!(book.certificate_status(&certificate).unwrap().is_err());
        }
    }

    fn certificate_migration_fixture(
        full_detail: bool,
    ) -> (
        Book,
        fa_money::UnitId,
        fa_model::EvidenceRef,
        fa_journal::RunBody,
    ) {
        let (mut spec, usd) = spec(Id128([0xc2; 16]));
        spec.opening_date = Some(DateDay::from_ymd(2026, 2, 1).unwrap());
        let mut book = Book::create_memory(
            BookKeys::for_development(0xc2),
            spec,
            Entropy::deterministic(194),
        )
        .unwrap();
        let day = DateDay::from_ymd(2026, 1, 1).unwrap();
        book.install_chart(&chart(usd), VId(1), day, b"migration-chart")
            .unwrap()
            .unwrap();
        book.create_periods(2025).unwrap();
        book.create_periods(2026).unwrap();
        let document = fa_journal::Document {
            book_id: book.context().book_id,
            kind: 18,
            mime: "text/csv".into(),
            grade: 3,
            retrieved_by: VId(1),
            bytes: b"account,USD debit balance\n1000,1000\n6000,-1000\n".to_vec(),
        };
        book.add_document(&document).unwrap().unwrap();
        let lines = vec![
            fa_journal::TrialBalanceLine {
                account_code: "1000".into(),
                unit: usd,
                mantissa: 1_000,
            },
            fa_journal::TrialBalanceLine {
                account_code: "6000".into(),
                unit: usd,
                mantissa: -1_000,
            },
        ];
        let body = fa_journal::RunBody {
            book_id: book.context().book_id,
            run_key: "certified-migration".into(),
            source_system: "certificate-legacy".into(),
            mode: if full_detail {
                fa_journal::RunMode::FullDetail
            } else {
                fa_journal::RunMode::OpeningOnly
            },
            trial_balance: document.oid(),
            opening_date: day,
            periods: if full_detail {
                ["FY2025-P12", "FY2026-P01"]
                    .into_iter()
                    .map(|period| fa_journal::PeriodBalance {
                        period_code: period.into(),
                        trial_balance: document.oid(),
                        lines: lines.clone(),
                    })
                    .collect()
            } else {
                Vec::new()
            },
            lines,
            detail_base: Vec::new(),
            sole_opening_source: false,
        };
        (book, usd, document.evidence_ref(1), body)
    }

    fn certificate_open_run(
        book: &mut Book,
        evidence: fa_model::EvidenceRef,
        body: &fa_journal::RunBody,
    ) -> VId {
        let proposal = fa_journal::migration::open_proposal(
            book.context(),
            VId(1),
            body,
            vec![evidence],
            b"certificate-open-run",
            book.seal_text("import legacy balances").unwrap(),
        )
        .unwrap();
        book.open_migration_run(
            body,
            fa_journal::RunControlRequest {
                proposal,
                capability: Capability::embedded(VId(1), &["post", "migrate"]).unwrap(),
                approvals: Vec::new(),
            },
        )
        .unwrap()
        .unwrap()
        .run
    }

    fn certificate_approvals(
        book: &mut Book,
        proposal: &EntryPayload,
    ) -> Vec<fa_model::ApprovalRef> {
        let digest = proposal.proposal_digest().unwrap();
        [VId(2), VId(3)]
            .into_iter()
            .map(|principal| {
                book.approve(
                    Capability::embedded(principal, &["approve"]).unwrap(),
                    digest,
                )
                .unwrap()
                .unwrap()
                .approval()
            })
            .collect()
    }

    fn certificate_stage_chunk(
        book: &mut Book,
        evidence: fa_model::EvidenceRef,
        body: &fa_journal::RunBody,
        period: &str,
        day: DateDay,
    ) -> VId {
        let usd = body.lines[0].unit;
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(body.book_id, "1000"),
                Amount::new(usd, 1_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(body.book_id, "6000"),
                Amount::new(usd, 1_000),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: body.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::MIGRATION,
            effective_date: day,
            document_date: None,
            description: book.seal_text("legacy chunk").unwrap(),
            effective_period: Some(fa_model::PeriodRef {
                calendar: book.context().calendar.id.clone(),
                code: period.into(),
            }),
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: period.as_bytes().to_vec(),
            origin: EntryOrigin::Migration {
                run_ref: body.vid(),
                source_system: body.source_system.clone(),
                source_id: book.seal_text(period).unwrap(),
                source_recorded_at_ns: None,
                source_entered_by: None,
                source_approved_by: None,
                batch_oid: body.trial_balance,
            },
            principal_ref: VId(1),
            session_ref: None,
            evidence: vec![evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let approvals = certificate_approvals(book, &proposal);
        book.post(PostRequest {
            proposal,
            approvals,
            plan_certificate: None,
            capability: Capability::embedded(VId(1), &["post", "migrate"]).unwrap(),
        })
        .unwrap()
        .unwrap()
        .entry_ref()
        .vid
    }

    fn certificate_transition_run(book: &mut Book, run: VId, kind: u8) -> VId {
        let proposal = book
            .plan_migration_transition(
                run,
                kind,
                VId(1),
                b"certificate-transition-run",
                book.seal_text("legacy run outcome").unwrap(),
            )
            .unwrap()
            .unwrap();
        let approvals = if kind == fa_journal::migration::kind::FINALIZE {
            certificate_approvals(book, &proposal)
        } else {
            Vec::new()
        };
        book.transition_migration_run(fa_journal::RunControlRequest {
            proposal,
            capability: Capability::embedded(VId(1), &["post", "migrate"]).unwrap(),
            approvals,
        })
        .unwrap()
        .unwrap()
        .control_entry
    }

    #[test]
    fn certificate_status_tracks_migration_activation_not_staging_or_abandonment() {
        use crate::{CertificateStatus, TrialBalanceSelection};
        use fa_journal::migration::kind;
        for outcome in [kind::ABANDON, kind::FINALIZE] {
            let (mut book, usd, evidence, body) = certificate_migration_fixture(false);
            let selection = TrialBalanceSelection::AsOf(body.opening_date);
            let before_run = book
                .certify_trial_balance(selection.clone(), None)
                .unwrap()
                .unwrap();
            let run = certificate_open_run(&mut book, evidence, &body);
            assert!(matches!(
                book.certificate_status(&before_run.certificate)
                    .unwrap()
                    .unwrap(),
                CertificateStatus::Current { .. }
            ));
            let chunk = certificate_stage_chunk(
                &mut book,
                evidence,
                &body,
                "FY2026-OPEN",
                body.opening_date,
            );
            assert!(
                matches!(
                    book.certificate_status(&before_run.certificate)
                        .unwrap()
                        .unwrap(),
                    CertificateStatus::Current { .. }
                ),
                "staging is invisible until the run finalizes"
            );
            let staged = book
                .certify_trial_balance(selection, None)
                .unwrap()
                .unwrap();
            assert!(staged.report.rows.is_empty());
            let control = certificate_transition_run(&mut book, run, outcome);
            let current = book.balance_as_of(body.opening_date, None).unwrap();
            if outcome == kind::FINALIZE {
                assert_eq!(current.unit_totals[&usd.0], (1_000, 1_000));
                assert!(matches!(
                    book.certificate_status(&before_run.certificate).unwrap().unwrap(),
                    CertificateStatus::SupersededBy { later_entries, .. }
                        if later_entries == vec![chunk, control]
                ));
                assert!(
                    matches!(
                        book.certificate_status(&staged.certificate).unwrap().unwrap(),
                        CertificateStatus::SupersededBy { later_entries, .. }
                            if later_entries == vec![control]
                    ),
                    "a finalize activates chunks recorded before certification too"
                );
            } else {
                assert!(current.rows.is_empty());
                for certified in [&before_run, &staged] {
                    assert!(
                        matches!(
                            book.certificate_status(&certified.certificate)
                                .unwrap()
                                .unwrap(),
                            CertificateStatus::Current { .. }
                        ),
                        "abandoned chunks never contribute"
                    );
                }
            }
            for certified in [&before_run, &staged] {
                assert_eq!(
                    book.replay_trial_balance(&certified.certificate)
                        .unwrap()
                        .unwrap(),
                    certified.report,
                    "the original known-at remains reproducible across lifecycle changes"
                );
            }
        }
    }

    #[test]
    fn certificate_status_excludes_full_detail_summarized_by_opening_balances() {
        use crate::{CertificateStatus, TrialBalanceSelection};
        let (mut book, usd, evidence, body) = certificate_migration_fixture(true);
        let prior_day = DateDay::from_ymd(2025, 12, 31).unwrap();
        let selections = [
            TrialBalanceSelection::AsOf(prior_day),
            TrialBalanceSelection::Activity(vec!["FY2025-P12".into()]),
        ];
        let mut excluded = Vec::new();
        for selection in &selections {
            excluded.push(
                book.certify_trial_balance(selection.clone(), None)
                    .unwrap()
                    .unwrap(),
            );
        }
        let run = certificate_open_run(&mut book, evidence, &body);
        certificate_stage_chunk(&mut book, evidence, &body, "FY2026-OPEN", body.opening_date);
        certificate_stage_chunk(&mut book, evidence, &body, "FY2025-P12", prior_day);
        for selection in &selections {
            excluded.push(
                book.certify_trial_balance(selection.clone(), None)
                    .unwrap()
                    .unwrap(),
            );
        }
        let opening = book
            .certify_trial_balance(
                TrialBalanceSelection::Activity(vec!["FY2026-OPEN".into()]),
                None,
            )
            .unwrap()
            .unwrap();
        let control =
            certificate_transition_run(&mut book, run, fa_journal::migration::kind::FINALIZE);
        for certified in &excluded {
            assert!(certified.report.rows.is_empty());
            assert!(
                matches!(
                    book.certificate_status(&certified.certificate)
                        .unwrap()
                        .unwrap(),
                    CertificateStatus::Current { .. }
                ),
                "FullDetail before the run's opening date stays excluded after finalization"
            );
            assert_eq!(
                book.replay_trial_balance(&certified.certificate)
                    .unwrap()
                    .unwrap(),
                certified.report
            );
        }
        assert!(book.balance_as_of(prior_day, None).unwrap().rows.is_empty());
        assert!(
            book.period_activity(&["FY2025-P12".into()], None)
                .unwrap()
                .rows
                .is_empty()
        );
        assert_eq!(
            book.period_activity(&["FY2026-OPEN".into()], None)
                .unwrap()
                .unit_totals[&usd.0],
            (1_000, 1_000)
        );
        assert!(matches!(
            book.certificate_status(&opening.certificate).unwrap().unwrap(),
            CertificateStatus::SupersededBy { later_entries, .. } if later_entries == vec![control]
        ));
    }

    #[test]
    fn certificate_status_ignores_period_controls_but_tracks_later_reservation_releases() {
        use crate::{CertificateStatus, TrialBalanceSelection};
        let (mut book, usd, day, rent) = certified_fixture();
        let mut pending = book.read_entry(rent).unwrap().unwrap().0.proposal;
        pending.class = EntryClass::PENDING;
        pending.idempotency_key = b"certified-pending".to_vec();
        pending.pending = Some(fa_model::Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        let target = book
            .post(PostRequest {
                proposal: pending.clone(),
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(VId(1), &["post"]).unwrap(),
            })
            .unwrap()
            .unwrap()
            .entry_ref();
        let mut certificates = Vec::new();
        for selection in [
            TrialBalanceSelection::AsOf(day),
            TrialBalanceSelection::Activity(vec!["FY2026-P03".into()]),
        ] {
            let certified = book
                .certify_trial_balance(selection, None)
                .unwrap()
                .unwrap();
            assert_eq!(
                certified.report.pending_unit_totals[&usd.0],
                (150_000, 150_000)
            );
            certificates.push(certified);
        }
        book.transition_period(
            "FY2026-P03",
            PeriodTransition::SoftClose,
            VId(1),
            1,
            day,
            b"certified-soft-close",
            &Capability::embedded(VId(1), &["close"]).unwrap(),
        )
        .unwrap()
        .unwrap();
        for certified in &certificates {
            assert!(
                matches!(
                    book.certificate_status(&certified.certificate)
                        .unwrap()
                        .unwrap(),
                    CertificateStatus::Current { .. }
                ),
                "period state alone changes no trial-balance contribution"
            );
        }
        let mut release = pending;
        release.class = EntryClass::RESOLUTION;
        release.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
        release.idempotency_key = b"certified-release".to_vec();
        release.legs.clear();
        release.unit_totals.clear();
        release.control = Some(fa_model::ControlPayload::ReservationRelease);
        release.pending = Some(fa_model::Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(fa_model::Disposition::Voids),
        });
        let resolution = book
            .post(PostRequest {
                proposal: release,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(VId(1), &["post"]).unwrap(),
            })
            .unwrap()
            .unwrap()
            .entry_ref()
            .vid;
        assert_eq!(
            book.balance_as_of(day, None).unwrap().pending_unit_totals[&usd.0],
            (0, 0)
        );
        for certified in certificates {
            assert!(
                matches!(
                    book.certificate_status(&certified.certificate).unwrap().unwrap(),
                    CertificateStatus::SupersededBy { later_entries, .. } if later_entries == vec![resolution]
                ),
                "the zero-leg April resolution releases March's selected reservation"
            );
            assert_eq!(
                book.replay_trial_balance(&certified.certificate)
                    .unwrap()
                    .unwrap(),
                certified.report
            );
        }
    }

    /// Plan §15.2 through the facade: the scratch book (its own runtime and
    /// store) folds as the source does and verifies against its SeqMap; a
    /// later checkpoint cannot invalidate a historical replay. A scenario
    /// post lands in the scratch book only; a map with a pair removed is
    /// FA-REF-135.
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
        let genesis = book.head().unwrap();
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
        let historical_prefix = book.head().unwrap();
        // Maintained registers and source-bound report artifacts are not
        // accounting inputs to a scratch book.
        assert!(book.advance_registers(&march).expect("maintained").wrote);
        let certificate = book
            .certify_trial_balance(crate::TrialBalanceSelection::AsOf(day), None)
            .unwrap()
            .unwrap()
            .certificate;
        let retained = book.retain_certificate(&certificate).unwrap().unwrap();
        let checkpoint = book
            .checkpoint(
                principal,
                &Capability::embedded(principal, &["witness"]).unwrap(),
            )
            .unwrap()
            .unwrap();
        let source_head = book.head().unwrap();
        let root_vid = fa_journal::rows::book_root();
        let current_root = with_store!(&book.store, core => core.db.vertex(root_vid))
            .unwrap()
            .unwrap();
        assert_eq!(current_root.created_at, checkpoint.stored.recorded_at);
        assert!(current_root.created_at > historical_prefix);

        // The root's current version starts at the checkpoint, but its
        // original creating commit still admits this earlier monetary prefix.
        let (historical, historical_map) = book
            .replay_into_scratch(
                Some(historical_prefix),
                BookKeys::for_development(0x5e),
                Entropy::deterministic(0x5e),
            )
            .unwrap()
            .expect("checkpoint maintenance cannot move genesis");
        book.verify_replay(&historical, &historical_map)
            .unwrap()
            .expect("the historical map still verifies after the checkpoint");
        assert_eq!(historical_map.source_prefix, historical_prefix);
        let first = historical_map.pairs.first().expect("the genesis pair");
        assert_eq!(first.source_seq, genesis);
        let genesis_marker = with_store!(&book.store, core => {
            core.db.delta_since(CommitSeq(0)).map(|mut history| {
                history
                    .find(|batch| batch.commit_seq() == genesis)
                    .expect("the authenticated genesis commit")
                    .commit_marker_identity()
                    .marker_oid
                    .0
            })
        })
        .unwrap();
        assert_eq!(first.source_marker, genesis_marker);
        let original_root = with_store!(&book.store, core => core.db.vertex_at(root_vid, genesis))
            .unwrap()
            .unwrap();
        // The replayed root as of its own genesis: later replayed controls
        // may re-version the root (a row's created_at starts its current
        // version), so its birth is read from the creating commit.
        let replayed_genesis =
            with_store!(&historical.store, core => fa_journal::scratch::source_genesis(&core.db))
                .unwrap()
                .expect("the scratch book has a genesis");
        assert_eq!(replayed_genesis, first.scratch_seq);
        // The replayed root is the source root as of the replayed prefix: the
        // same birth, the same properties, and its current version created by
        // the scratch commit that replays the source version's commit.
        let source_root_at_prefix =
            with_store!(&book.store, core => core.db.vertex_at(root_vid, historical_prefix))
                .unwrap()
                .unwrap();
        let replayed_root = with_store!(&historical.store, core => core.db.vertex(root_vid))
            .unwrap()
            .unwrap();
        let mapped = historical_map
            .pairs
            .iter()
            .find(|pair| pair.source_seq == source_root_at_prefix.created_at)
            .expect("the root's version at the prefix is a replayed commit")
            .scratch_seq;
        assert_eq!(replayed_root.created_at, mapped);
        assert_eq!(replayed_root.birth_ordinal, original_root.birth_ordinal);
        assert_eq!(replayed_root.props, source_root_at_prefix.props);
        assert_eq!(
            historical.fold_period(&march).unwrap().cells,
            book.fold_period(&march).unwrap().cells
        );

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
            map.pairs, historical_map.pairs,
            "only maintenance followed the historical accounting prefix"
        );
        assert_eq!(
            map.translate(checkpoint.stored.recorded_at),
            historical_map.translate(historical_prefix),
            "a checkpoint translates to the preceding accounting commit"
        );
        assert!(
            !map.pairs
                .iter()
                .any(|pair| pair.source_seq == retained.recorded_at),
            "retaining a source-bound certificate is not a scratch accounting commit"
        );
        let refusal = scratch
            .read_certificate(&retained.digest)
            .unwrap()
            .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-150", 8));
        assert_eq!(
            book.read_certificate(&retained.digest)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            certificate.canonical_bytes().unwrap(),
            "the source retains its original certificate"
        );
        assert_eq!(
            scratch.fold_period(&march).unwrap().cells,
            book.fold_period(&march).unwrap().cells
        );
        let scratch_rows = scratch.purposes().query().with_restriction(|| {
            with_store!(&scratch.store, core => core.db.vertices_at(core.db.frontier().unwrap()))
        }).unwrap();
        assert!(
            scratch_rows.iter().all(|v| {
                !v.labels.contains(&fa_model::symbols::label::REGISTER_STATE)
                    && !v.labels.contains(&fa_model::symbols::label::CERTIFICATE)
            }),
            "no maintainer state or source-bound certificate reaches the scratch book"
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
        let historical_items = book.open_items_report(Some(cash), Some(before_chart));
        assert!(matches!(
            historical_items,
            Err(BookError::Registers(
                fa_registers::RegisterError::InvalidSelection(_)
            ))
        ));
        for selection in [
            crate::ReportSelection::ExplainBalance {
                account: cash,
                period: march.clone(),
            },
            crate::ReportSelection::OpenItems {
                account: Some(cash),
            },
        ] {
            assert!(matches!(
                book.certify_report(selection, Some(before_chart)),
                Err(BookError::Registers(
                    fa_registers::RegisterError::InvalidSelection(_)
                ))
            ));
        }
        let empty_items = book
            .open_items_report(Some(cash), Some(installed.recorded_at))
            .unwrap();
        assert_eq!(empty_items.accounts[&cash].name, "Cash");
        assert!(empty_items.items.is_empty());
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

    /// A bundle reads each cited document as the producing capability may
    /// see it (plan §9.6, doctrine 8). A bank statement is governed by
    /// redaction contract 1. Before its view is derived, a reader without
    /// `privileged` produces nothing over it (142), and `produce` without
    /// `read` is refused at the document (011). With the view, the reader's
    /// stub-only bundle is byte for byte the privileged holder's (the view
    /// proves the kind, length and chunk root the bytes give) and carries
    /// none of the bytes, while inlining is refused (128). The privileged
    /// holder inlines the bytes, and both bundles verify. Once revoked, the
    /// reader is refused before the journal is read (023).
    #[test]
    fn a_bundle_inlines_a_governed_document_only_for_a_capability_that_reveals_it() {
        let book_id = Id128([0x4a; 16]);
        let (spec, usd) = spec(book_id);
        let mut book = Book::create_memory(
            BookKeys::for_development(0x4a),
            spec,
            Entropy::deterministic(0x4a),
        )
        .expect("create");
        let (counsel, reader) = (VId(1), VId(2));
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        book.install_chart(&chart(usd), counsel, day, b"chart")
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
            counsel,
            1,
            day,
            b"open",
            &Capability::embedded(counsel, &["close"]).expect("close"),
        )
        .expect("kernel")
        .expect("opens");
        let statement = fa_journal::Document {
            book_id,
            kind: 5,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: counsel,
            bytes: b"ACCOUNT 0012-3456-7890 (bundle fixture)\n".repeat(200),
        };
        post_rent_citing(&mut book, usd, counsel, day, b"rent", 150_000, &statement)
            .expect("kernel")
            .expect("admitted");
        let witness = Capability::embedded(counsel, &["witness"]).expect("witness");
        book.checkpoint(counsel, &witness).unwrap().unwrap();

        let produce = |book: &mut Book, who: VId, cap: &Capability, inline_documents: bool| {
            let request = fa_notary::BundleRequest {
                scope: fa_notary::BundleScope::Prefix,
                balances: Vec::new(),
                inline_documents,
            };
            book.produce_bundle(who, cap, None, &request)
                .expect("kernel")
                .map(|produced| produced.expect("the latest state"))
        };
        let revealing =
            Capability::embedded(counsel, &["produce", "read", "privileged"]).expect("privileged");
        let viewing = Capability::embedded(reader, &["produce", "read"]).expect("read");
        for inline in [true, false] {
            let r = produce(&mut book, reader, &viewing, inline).unwrap_err();
            assert_eq!((r.code, r.exit), ("FA-REF-142", 3), "{r}");
        }
        let unread = Capability::embedded(reader, &["produce"]).expect("produce");
        let r = produce(&mut book, reader, &unread, false).unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-011", 7), "{r}");

        book.derive_redacted_view(&revealing, &statement.oid())
            .expect("kernel")
            .expect("derived");
        let r = produce(&mut book, reader, &viewing, true).unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-128", 3), "{r}");
        let stubbed = produce(&mut book, reader, &viewing, false).expect("a stub-only bundle");
        let by_counsel = produce(&mut book, counsel, &revealing, false).expect("the same bundle");
        assert_eq!(
            stubbed.bundle, by_counsel.bundle,
            "the view proves the stub the bytes give"
        );
        let inlined = produce(&mut book, counsel, &revealing, true).expect("an inline bundle");
        let holds = |bytes: &[u8]| bytes.windows(22).any(|w| w == b"ACCOUNT 0012-3456-7890");
        assert!(holds(&inlined.bundle.bytes), "the statement is inlined");
        assert!(
            !holds(&stubbed.bundle.bytes),
            "a stub carries none of its bytes"
        );
        let key = book.checkpoint_public_key();
        for produced in [&stubbed, &inlined] {
            let report =
                fa_verify::verify_bundle(&produced.bundle.bytes, &[key], Some(&produced.receipt))
                    .unwrap();
            assert!(report.verified(), "{:#?}", report.checks);
        }

        let req = fa_journal::RevocationRequest {
            capability: Capability::embedded(counsel, &["issue_capability"]).unwrap(),
            revoked: viewing.commitment().unwrap(),
            effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
            idempotency_key: b"revoke-viewing".to_vec(),
            description: fa_model::Erasable::seal(
                &"revoke".to_string(),
                None,
                &book.context().seal_key,
                [0x4a; 32],
                [0x4a; 24],
            ),
        };
        let purposes = book.purposes();
        let ctx = book.context().clone();
        with_store!(&mut book.store, core => book.runtime.block_on(async {
            fa_journal::revoke_capability(&mut core.db, &purposes, &ctx, req).await
        }))
        .unwrap()
        .expect("revoked");
        let r = produce(&mut book, reader, &viewing, false).unwrap_err();
        assert_eq!((r.code, r.exit), ("FA-REF-023", 7), "{r}");
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
        let certified_report;
        let retained_certificate;
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
            certified_report = book
                .certify_trial_balance(crate::TrialBalanceSelection::AsOf(day), None)
                .unwrap()
                .unwrap();
            retained_certificate = book
                .retain_certificate(&certified_report.certificate)
                .unwrap()
                .unwrap();
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
        let certificate = book
            .read_certificate(&retained_certificate.digest)
            .unwrap()
            .expect("the retained certificate survived reopen");
        assert_eq!(certificate, certified_report.certificate);
        assert_eq!(
            book.replay_trial_balance(&certificate).unwrap().unwrap(),
            certified_report.report
        );
        assert_eq!(
            book.retain_certificate(&certificate).unwrap().unwrap(),
            retained_certificate
        );
        assert_eq!(book.head().unwrap(), retained_certificate.recorded_at);
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

    /// VFS calls in order: the operation and every path argument it was given.
    type Calls = Vec<(&'static str, Vec<PathBuf>)>;

    /// Real `UnixVfs` I/O with every path argument recorded in call order and
    /// no result special-cased (fa-40l (B), JadePeak 4047, CobaltGull 4048).
    #[derive(Clone)]
    struct RecordingVfs {
        inner: UnixVfs,
        calls: std::sync::Arc<std::sync::Mutex<Calls>>,
    }

    impl RecordingVfs {
        fn new() -> Self {
            Self {
                inner: UnixVfs::new(),
                calls: std::sync::Arc::default(),
            }
        }

        fn note(&self, op: &'static str, paths: &[&Path]) {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((op, paths.iter().map(|p| p.to_path_buf()).collect()));
        }

        /// Every call recorded since the last take, in order.
        fn take(&self) -> Calls {
            std::mem::take(&mut *self.calls.lock().expect("recorder lock"))
        }
    }

    impl Vfs for RecordingVfs {
        type File = <UnixVfs as Vfs>::File;

        fn open(
            &self,
            path: &Path,
            opts: &OpenOptions,
        ) -> impl std::future::Future<Output = std::io::Result<Self::File>> + Send {
            self.note("open", &[path]);
            self.inner.open(path, opts)
        }

        fn metadata(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<asupersync::fs::Metadata>> + Send
        {
            self.note("metadata", &[path]);
            self.inner.metadata(path)
        }

        fn symlink_metadata(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<asupersync::fs::Metadata>> + Send
        {
            self.note("symlink_metadata", &[path]);
            self.inner.symlink_metadata(path)
        }

        fn set_permissions(
            &self,
            path: &Path,
            perm: asupersync::fs::Permissions,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("set_permissions", &[path]);
            self.inner.set_permissions(path, perm)
        }

        fn create_dir(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("create_dir", &[path]);
            self.inner.create_dir(path)
        }

        fn create_dir_all(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("create_dir_all", &[path]);
            self.inner.create_dir_all(path)
        }

        fn remove_dir(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("remove_dir", &[path]);
            self.inner.remove_dir(path)
        }

        fn remove_dir_all(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("remove_dir_all", &[path]);
            self.inner.remove_dir_all(path)
        }

        fn read_dir(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<asupersync::fs::ReadDir>> + Send
        {
            self.note("read_dir", &[path]);
            self.inner.read_dir(path)
        }

        fn remove_file(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("remove_file", &[path]);
            self.inner.remove_file(path)
        }

        fn rename(
            &self,
            from: &Path,
            to: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("rename", &[from, to]);
            self.inner.rename(from, to)
        }

        fn copy(
            &self,
            src: &Path,
            dst: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<u64>> + Send {
            self.note("copy", &[src, dst]);
            self.inner.copy(src, dst)
        }

        fn hard_link(
            &self,
            original: &Path,
            link: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("hard_link", &[original, link]);
            self.inner.hard_link(original, link)
        }

        fn canonicalize(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<PathBuf>> + Send {
            self.note("canonicalize", &[path]);
            self.inner.canonicalize(path)
        }

        fn read_link(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<PathBuf>> + Send {
            self.note("read_link", &[path]);
            self.inner.read_link(path)
        }

        fn read(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<Vec<u8>>> + Send {
            self.note("read", &[path]);
            self.inner.read(path)
        }

        fn read_to_string(
            &self,
            path: &Path,
        ) -> impl std::future::Future<Output = std::io::Result<String>> + Send {
            self.note("read_to_string", &[path]);
            self.inner.read_to_string(path)
        }

        fn write(
            &self,
            path: &Path,
            contents: &[u8],
        ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
            self.note("write", &[path]);
            self.inner.write(path, contents)
        }
    }

    fn has_parent_dir(path: &Path) -> bool {
        path.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    }

    /// The records before and including the `canonicalize` of `spelled`
    /// (DurableDirectory's preflight on the caller's spelling), and the rest.
    fn split_preflight(calls: Calls, spelled: &Path) -> (Calls, Calls) {
        let end = calls
            .iter()
            .position(|(op, paths)| *op == "canonicalize" && paths[..] == [spelled.to_path_buf()]);
        assert!(end.is_some(), "no canonicalize of {spelled:?}: {calls:?}");
        let mut preflight = calls;
        let rest = preflight.split_off(end.map_or(0, |i| i + 1));
        (preflight, rest)
    }

    /// fa-40l acceptance (B), scoped to the 4046 boundary: a book spelled
    /// with a `..` component reaches the VFS with that spelling only in
    /// `DurableDirectory`'s preflight (create, metadata, the ancestor fence
    /// and `canonicalize`); every argument handed on afterwards — to
    /// `Database`, to the blob store, and by every later operation and the
    /// reopen — carries no `..` and lies on the canonical root's line. Real
    /// `UnixVfs` refuses a `..` at rename, so the renames recorded below
    /// passing is the same fact from the host's side. No claim that the
    /// substrate tolerates `..`: this pins where it stops.
    #[cfg(unix)]
    #[test]
    fn a_dotdot_book_spelling_stops_at_the_durable_directory_preflight() {
        let (runtime, root) = Book::runtime_and_root().unwrap();
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("fa-40l-dotdot-{}-{suffix}", std::process::id()));
        let caller = base.join("caller");
        std::fs::create_dir_all(&caller).unwrap();
        let spelled = caller.join("..").join("x");
        let caller_parent = caller.join("..");
        assert!(has_parent_dir(&spelled));
        let canonical = std::fs::canonicalize(&base).unwrap().join("x");
        let vfs = RecordingVfs::new();
        let keys = BookKeys::for_development(0x6b);
        let book_id = Id128([0x6b; 16]);
        let (spec, usd) = spec(book_id);
        let on_the_canonical_line =
            |p: &Path| p.starts_with(&canonical) || canonical.starts_with(p);
        runtime.block_on(async {
            let mut book = AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                &spelled,
                keys.clone(),
                spec,
                Entropy::deterministic(0x6b),
            )
            .await
            .expect("a `..` spelling creates the book");
            let (preflight, handed) = split_preflight(vfs.take(), &spelled);
            let dotdot = |calls: &Calls| -> Calls {
                calls
                    .iter()
                    .filter(|(_, paths)| paths.iter().any(|p| has_parent_dir(p)))
                    .cloned()
                    .collect()
            };
            assert_eq!(
                dotdot(&preflight),
                vec![
                    ("create_dir_all", vec![spelled.clone()]),
                    ("metadata", vec![spelled.clone()]),
                    ("symlink_metadata", vec![spelled.clone()]),
                    ("open", vec![spelled.clone()]),
                    ("symlink_metadata", vec![caller_parent.clone()]),
                    ("open", vec![caller_parent.clone()]),
                    ("canonicalize", vec![spelled.clone()]),
                ],
                "the preflight's `..` records are exactly these: {preflight:?}"
            );

            let principal = VId(1);
            let day = DateDay::from_ymd(2026, 3, 15).unwrap();
            book.install_chart(&cx, &chart(usd), principal, day, b"chart")
                .await
                .unwrap()
                .unwrap();
            let inline_bound = fa_registry::evidence_policy::EvidencePolicy::embedded()
                .unwrap()
                .max_document_bytes;
            let document = fa_journal::Document {
                book_id,
                kind: 1,
                mime: "application/octet-stream".into(),
                grade: 3,
                retrieved_by: principal,
                bytes: vec![0x62; usize::try_from(inline_bound).unwrap() + 1],
            };
            book.add_document(&cx, &document).await.unwrap().unwrap();
            let operated = vfs.take();
            drop(book);

            let reopened = AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                &spelled,
                keys,
                Entropy::deterministic(0x6c),
            )
            .await
            .expect("the same spelling reopens the book");
            assert_eq!(reopened.accounts(&cx).unwrap().len(), chart(usd).len());
            let (reopen_preflight, reopen_handed) = split_preflight(vfs.take(), &spelled);
            assert_eq!(
                dotdot(&reopen_preflight),
                vec![
                    ("metadata", vec![spelled.clone()]),
                    ("symlink_metadata", vec![spelled.clone()]),
                    ("open", vec![spelled.clone()]),
                    ("symlink_metadata", vec![caller_parent.clone()]),
                    ("open", vec![caller_parent.clone()]),
                    ("canonicalize", vec![spelled.clone()]),
                ],
                "reopen's preflight `..` records: {reopen_preflight:?}"
            );

            // Everything handed on after the preflight: no `..` anywhere,
            // and every path on the canonical root's line (the root, under
            // it, or one of its ancestors' fences).
            for (phase, calls) in [
                ("create", &handed),
                ("operations", &operated),
                ("reopen", &reopen_handed),
            ] {
                assert!(!calls.is_empty(), "{phase} recorded nothing");
                for (op, paths) in calls {
                    for p in paths {
                        assert!(!has_parent_dir(p), "{phase}: {op} {p:?} carries `..`");
                        assert!(
                            on_the_canonical_line(p),
                            "{phase}: {op} {p:?} is off the canonical root {canonical:?}"
                        );
                    }
                }
            }
            // Publication actually ran through the recorder: the external
            // document's bytes were renamed into the canonical blob store.
            let blobs = canonical.join("blobs");
            assert!(
                operated.iter().any(|(op, paths)| *op == "rename"
                    && paths.last().is_some_and(|to| to.starts_with(&blobs))),
                "no blob publication rename under {blobs:?}: {operated:?}"
            );
        });
    }
}
