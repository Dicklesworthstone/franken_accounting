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

    /// Validate that `(mode, file_uid)` satisfies the 0600 / same-UID key-file
    /// invariant (plan §15.3, Appendix H R-KEY; bead fa-1jcl).
    pub fn verify_mode_and_owner(
        path: &Path,
        mode: u32,
        file_uid: u32,
        process_uid: u32,
    ) -> Result<(), BookError> {
        let mode_bits = mode & 0o7777;
        if mode_bits & !0o600 != 0 || file_uid != process_uid {
            return Err(BookError::KeyFilePermissions {
                path: path.to_path_buf(),
                mode: mode_bits,
                file_uid,
                process_uid,
            });
        }
        Ok(())
    }

    /// Check that the key file at `path` has mode at most `0600` and is owned
    /// by the current process UID before any key bytes are read.
    pub fn check_permissions(path: &Path) -> Result<(), BookError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let meta = std::fs::metadata(path).map_err(|e| BookError::Io(path.to_path_buf(), e))?;
            let mode = meta.permissions().mode() & 0o7777;
            let file_uid = meta.uid();
            let process_uid =
                current_process_uid().map_err(|e| BookError::Io(path.to_path_buf(), e))?;
            Self::verify_mode_and_owner(path, mode, file_uid, process_uid)?;
        }
        Ok(())
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
        let raw_path = path;
        let path = rooted_path(path);
        let meta = cx
            .with_restriction_async(vfs.metadata(&path))
            .await
            .map_err(|e| BookError::Io(raw_path.to_path_buf(), e))?;
        #[cfg(unix)]
        {
            let mode = meta.permissions().mode() & 0o7777;
            let process_uid =
                current_process_uid().map_err(|e| BookError::Io(raw_path.to_path_buf(), e))?;
            let file_uid = std::fs::metadata(&path).map_or(process_uid, |os_meta| {
                use std::os::unix::fs::MetadataExt;
                os_meta.uid()
            });
            Self::verify_mode_and_owner(raw_path, mode, file_uid, process_uid)?;
        }
        let text = cx
            .with_restriction_async(vfs.read_to_string(&path))
            .await
            .map_err(|e| BookError::Io(raw_path.to_path_buf(), e))?;
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        if lines.len() != 3 {
            return Err(BookError::KeyFile(format!(
                "{}: expected three 64-hex lines, found {}",
                raw_path.display(),
                lines.len()
            )));
        }
        let parse = |l: &str, what: &str| {
            unhex(l).ok_or_else(|| {
                BookError::KeyFile(format!(
                    "{}: {what} is not 64 hex characters",
                    raw_path.display()
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

    /// Deterministic 32-byte owner-authority token derived from the book's keys
    /// (`KDF(k_oid ‖ namespace ‖ dek, "fa:fad-owner-token:v1")`), domain-separated
    /// from every other use of the book's secrets. Proves possession of the key
    /// file to a local `fad` without transmitting raw encryption keys (fa-een).
    #[must_use]
    pub fn owner_token(&self) -> [u8; 32] {
        let mut material = [0u8; 96];
        material[..32].copy_from_slice(self.inner.k_oid());
        material[32..64].copy_from_slice(&self.namespace);
        material[64..].copy_from_slice(self.inner.dek());
        let token = derive_key("fa:fad-owner-token:v1", &material);
        fgdb_crypto::zeroize::scrub_slice(&mut material);
        token
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

/// The refusal catalog code for an insecure key file (mode wider than 0600 or
/// owner UID mismatch; plan §15.3, Appendix H R-KEY; bead fa-1jcl).
pub const KEY_FILE_PERMISSIONS: &str = "FA-REF-155";

#[cfg(unix)]
fn current_process_uid() -> std::io::Result<u32> {
    use std::sync::OnceLock;
    static UID: OnceLock<u32> = OnceLock::new();
    if let Some(&uid) = UID.get() {
        return Ok(uid);
    }
    let (a, _b) = asupersync::net::unix::UnixStream::pair()?;
    let uid = a.peer_cred()?.uid;
    let _ = UID.set(uid);
    Ok(uid)
}

/// Errors a `Book` can return. Each maps to one exit-code class in the CLI
/// contract (plan Appendix D): `Runtime`, `Open`, `Io`, `KeyFile`,
/// `KeyFilePermissions`, and `NoBook` are environment errors (4); the rest are
/// foundation failures (5). Lawful refusals are not errors: they are the `Err`
/// of the inner result each method returns.
#[derive(Debug)]
pub enum BookError {
    Runtime(String),
    Context(Box<asupersync::error::Error>),
    Open(fgdb::OpenError),
    Io(PathBuf, std::io::Error),
    KeyFile(String),
    /// The key file has mode wider than 0600 or its owner UID differs from the
    /// process UID (plan §15.3, Appendix H R-KEY; bead fa-1jcl).
    KeyFilePermissions {
        path: PathBuf,
        mode: u32,
        file_uid: u32,
        process_uid: u32,
    },
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
            Self::Lantern(
                fa_lantern::LanternError::Overflow(_)
                | fa_lantern::LanternError::Money(_)
                | fa_lantern::LanternError::BudgetExhausted { .. },
            ) => fa_journal::exit::REFUSAL,
            Self::Runtime(_)
            | Self::Open(_)
            | Self::Io(..)
            | Self::KeyFile(_)
            | Self::KeyFilePermissions { .. }
            | Self::NoBook => fa_journal::exit::ENVIRONMENT,
            Self::Context(_)
            | Self::Kernel(_)
            | Self::Registers(_)
            | Self::Registry(_)
            | Self::Entropy(_)
            | Self::CertifiedRead(_)
            | Self::Lantern(_) => fa_journal::exit::FOUNDATION,
        }
    }

    /// When the error corresponds to a typed catalog refusal (e.g.
    /// `FA-REF-155` key-file permissions, exit 4), return the structured
    /// [`Refusal`].
    #[must_use]
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::KeyFilePermissions {
                path,
                mode,
                file_uid,
                process_uid,
            } => {
                let why = if mode & !0o600 != 0 && file_uid != process_uid {
                    format!(
                        "{}: mode 0{:03o} is wider than 0600 and owner uid {file_uid} differs from process uid {process_uid}",
                        path.display(),
                        mode & 0o7777
                    )
                } else if mode & !0o600 != 0 {
                    format!(
                        "{}: mode 0{:03o} is wider than 0600",
                        path.display(),
                        mode & 0o7777
                    )
                } else {
                    format!(
                        "{}: owner uid {file_uid} differs from process uid {process_uid} (mode 0{:03o})",
                        path.display(),
                        mode & 0o7777
                    )
                };
                Some(Refusal::new(
                    KEY_FILE_PERMISSIONS,
                    fa_journal::exit::ENVIRONMENT,
                    why,
                    "plan §15.3 (key-file permissions), Appendix H R-KEY (0600 key file)",
                    format!("chmod 600 {}", path.display()),
                ))
            }
            _ => None,
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
            Self::KeyFilePermissions { .. } => {
                if let Some(r) = self.refusal() {
                    write!(f, "{}: {} (fix: {})", r.code, r.message, r.fix)
                } else {
                    write!(f, "key file permissions")
                }
            }
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
    owner_token: [u8; 32],
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
        let owner_token = keys.owner_token();
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
            owner_token,
        })
    }

    /// Create a directory book at `<dir>/store` (`dir` is created if absent).
    pub fn create_dir(
        dir: &Path,
        keys: BookKeys,
        spec: BookSpec,
        entropy: Entropy,
    ) -> Result<Self, BookError> {
        let owner_token = keys.owner_token();
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            runtime,
            root,
            store: Store::Dir(core),
            owner_token,
        })
    }

    /// Open the directory book at `<dir>/store`, rebuilding the context from
    /// the spec journaled at genesis.
    pub fn open_dir(dir: &Path, keys: BookKeys, entropy: Entropy) -> Result<Self, BookError> {
        if dir.is_dir() && !dir.join("store").is_dir() {
            return Err(BookError::NoBook);
        }
        let owner_token = keys.owner_token();
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
            owner_token,
        })
    }

    /// The domain-separated 32-byte owner-authority token derived from the
    /// book's keys (`fa-een`).
    #[must_use]
    pub fn owner_token(&self) -> [u8; 32] {
        self.owner_token
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

    /// Open a new account as a journaled `SchemaChange` (`kind = 2`, plan §5.6).
    #[allow(clippy::too_many_arguments)]
    pub fn open_account(
        &mut self,
        spec: &AccountSpec,
        opened: DateDay,
        closed: Option<DateDay>,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::AccountLifecycleRecorded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.open_account(
            &purposes, spec, opened, closed, principal, effective_date, idempotency_key, capability,
        )))
    }

    /// Close an account at `closed_on` as a journaled `SchemaChange` (`kind = 3`, plan §5.6).
    #[allow(clippy::too_many_arguments)]
    pub fn close_account(
        &mut self,
        code: &str,
        closed_on: DateDay,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::AccountLifecycleRecorded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.close_account(
            &purposes, code, closed_on, principal, effective_date, idempotency_key, capability,
        )))
    }

    /// Promote a leaf account to a summary account at `promotion_date` as a
    /// journaled `SchemaChange` (`kind = 4`, plan §5.6).
    #[allow(clippy::too_many_arguments)]
    pub fn promote_to_summary(
        &mut self,
        code: &str,
        promotion_date: DateDay,
        principal: VId,
        effective_date: DateDay,
        idempotency_key: &[u8],
        capability: &fa_journal::Capability,
    ) -> Outcome<fa_journal::AccountLifecycleRecorded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.promote_to_summary(
            &purposes, code, promotion_date, principal, effective_date, idempotency_key, capability,
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

    /// Revoke a capability by its commitment under `capability` (plan §14.2):
    /// one `PolicyControl` entry carrying `ControlPayload::CapabilityEvent { Revoke }`.
    /// The capability must hold `issue_capability`.
    pub fn revoke_capability(
        &mut self,
        capability: fa_journal::Capability,
        revoked_commitment: [u8; 32],
        effective_date: DateDay,
        idempotency_key: &[u8],
        description: &str,
    ) -> Outcome<fa_journal::Revoked> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.revoke_capability(
            &purposes, capability, revoked_commitment, effective_date, idempotency_key, description,
        )))
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

    /// Build the `Open` control proposal for `body` (plan §8.6).
    #[allow(clippy::too_many_arguments)]
    pub fn open_migration_proposal(
        &self,
        principal: VId,
        body: &fa_journal::RunBody,
        citations: Vec<fa_model::EvidenceRef>,
        idempotency_key: &[u8],
        description: Erasable<String>,
    ) -> Result<fa_model::EntryPayload, BookError> {
        with_store!(&self.store, core => core.open_migration_proposal(
            principal, body, citations, idempotency_key, description,
        ))
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

    /// Fold `run`'s chunks as known at `known_at` (head when `None`) against
    /// its declared trial balance lines (plan §8.6).
    pub fn migration_tie_out(
        &self,
        run: &fa_journal::Run,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_journal::TieOut, BookError> {
        with_store!(&self.store, core => core.migration_tie_out(&self.purposes(), run, known_at))
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
        let owner_token = keys.owner_token();
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
                owner_token,
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

    /// Evaluate a lawful erasure request for `subject` (plan §8.5): admits
    /// `erase` before any read, checks capability currency and revocation,
    /// refuses active legal holds (`FA-REF-117`), and otherwise returns the
    /// registered interim absence (`FA-REF-088`).
    pub fn erasure_cut(
        &self,
        capability: &fa_journal::Capability,
        subject: VId,
    ) -> Result<Refusal, BookError> {
        with_store!(&self.store, core => core.erasure_cut(&self.purposes(), capability, subject))
    }

    /// Evaluate a `RegisterEquals` balance assertion for `key` at `known_at`
    /// (head when `None`; plan §9.4).
    pub fn evaluate_register_equals(
        &self,
        key: &fa_registers::EntityCellKey,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_registers::RegisterEquals, BookError> {
        with_store!(&self.store, core => core.evaluate_register_equals(&self.purposes(), key, known_at))
    }

    /// Record `claim` as an immutable `RegisterEquals` attestation resting on
    /// `evidence` (plan §9.4).
    pub fn record_register_equals(
        &mut self,
        capability: &fa_journal::Capability,
        claim: &fa_registers::RegisterEquals,
        evidence: Vec<fa_model::Oid>,
    ) -> Outcome<fa_journal::Attested> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.record_register_equals(
            &purposes, capability, claim, evidence,
        )))
    }

    /// Check whether the `RegisterEquals` attestation at `vid` holds at its
    /// recorded sequence (plan §9.4).
    pub fn assertion_holds(&self, vid: VId) -> Result<Option<bool>, BookError> {
        with_store!(&self.store, core => core.assertion_holds(&self.purposes(), vid))
    }

    /// Read a committed entry back by its derived identity, verifying its digests.
    pub fn read_entry(&self, vid: VId) -> Result<Option<(Entry, CommitSeq)>, BookError> {
        with_store!(&self.store, core => core.read_entry(&self.purposes(), vid))
    }

    /// Every committed entry in this book that supersedes `vid`, in recorded order.
    pub fn superseded_by(&self, vid: VId) -> Result<Vec<fa_model::Supersession>, BookError> {
        with_store!(&self.store, core => core.superseded_by(&self.purposes(), vid))
    }

    /// Explain the evidence closure for an entry without reading document payload bytes.
    pub fn explain_entry_evidence(
        &self,
        entry_vid: VId,
    ) -> Result<Option<fa_journal::EvidenceExplanation>, BookError> {
        with_store!(&self.store, core => core.explain_entry_evidence(&self.purposes(), entry_vid))
    }

    /// Explain the complete `SUPERSEDES` lineage component containing `entry_vid`
    /// and its net economic effect under `registries/supersession_kinds.toml` (`fa-oz3`).
    pub fn explain_entry_lineage(
        &self,
        entry_vid: VId,
        known_at: Option<CommitSeq>,
    ) -> Result<Option<fa_journal::LineageReport>, BookError> {
        with_store!(&self.store, core => core.explain_entry_lineage(&self.purposes(), entry_vid, known_at))
    }

    /// Every period of the book in calendar order, with its current state.
    pub fn periods(&self) -> Result<Vec<PeriodRow>, BookError> {
        with_store!(&self.store, core => core.periods(&self.purposes()))
    }

    /// Recorded period-state transitions for `period_code` in commit order.
    pub fn period_transitions(
        &self,
        period_code: &str,
    ) -> Result<Vec<fa_journal::PeriodTransitionRecord>, BookError> {
        with_store!(&self.store, core => core.period_transitions(&self.purposes(), period_code))
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

    /// Persist a certificate lazily after verifying current `read` authority
    /// for this book (fa-1nx).
    pub fn retain_certificate_authorized(
        &mut self,
        certificate: &crate::ReportCertificate,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::RetainedCertificate> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.retain_certificate_authorized(&purposes, certificate, capability)))
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

    /// Fold cost-basis lots and `RELIEVES {quantity, cost}` edges for an `AnyUnit` account (plan §6.5, `fa-2ly`).
    pub fn lots(
        &self,
        account: VId,
        effective_through: Option<DateDay>,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_registers::LotsReport, BookError> {
        with_store!(&self.store, core => core.lots(&self.purposes(), account, effective_through, known_at))
    }

    /// Read complete selected general-ledger detail at one retained prefix.
    /// This synchronous adapter delegates to the same AsyncBook implementation
    /// used by lab and embedded callers; no alternate report semantics exist.
    pub fn general_ledger(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::RollForwardRequest,
    ) -> Outcome<crate::GeneralLedger> {
        with_store!(&self.store, core => core.general_ledger(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Certify the native retained-history source before deriving ledger detail.
    /// The returned source certificate is the existing roll-forward certificate,
    /// not a second certificate format.
    pub fn certify_general_ledger(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::RollForwardRequest,
    ) -> Outcome<crate::general_ledger::CertifiedGeneralLedger> {
        with_store!(&self.store, core => core.certify_general_ledger(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Replay a certified ledger only after binding it to an independently
    /// supplied expected request under current read authority.
    pub fn replay_general_ledger(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        source: &crate::roll_forward::RollForwardCertificate,
        expected: &crate::RollForwardRequest,
    ) -> Outcome<crate::GeneralLedger> {
        with_store!(&self.store, core => core.replay_general_ledger(
            &self.purposes(), principal, capability, source, expected
        ))
    }

    /// Render the selected ledger as bounded JSONL after replaying the complete
    /// native source certificate. Produce authority is required by the async core.
    pub fn general_ledger_jsonl(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        source: &crate::roll_forward::RollForwardCertificate,
        expected: &crate::RollForwardRequest,
    ) -> Outcome<String> {
        with_store!(&self.store, core => core.general_ledger_jsonl(
            &self.purposes(), principal, capability, source, expected
        ))
    }

    /// Produce a historical account lead schedule under current whole-book read authority.
    pub fn roll_forward(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::RollForwardRequest,
    ) -> Outcome<crate::RollForward> {
        with_store!(&self.store, core => core.roll_forward(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Certify an exact lead schedule against its native chart, journal, migration and registry closure.
    pub fn certify_roll_forward(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::RollForwardRequest,
    ) -> Outcome<crate::CertifiedRollForward> {
        with_store!(&self.store, core => core.certify_roll_forward(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Replay a certified roll-forward at its original prefix under current read authority.
    pub fn replay_roll_forward(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        certificate: &crate::RollForwardCertificate,
    ) -> Outcome<crate::RollForward> {
        with_store!(&self.store, core => core.replay_roll_forward(
            &self.purposes(), principal, capability, certificate
        ))
    }

    /// Fold open items through an inclusive civil date at one known-at frontier.
    pub fn open_items_as_of(
        &self,
        account: Option<VId>,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Result<crate::OpenItemSnapshot, BookError> {
        with_store!(&self.store, core => core.open_items_as_of(
            &self.purposes(), account, effective_through, known_at
        ))
    }

    /// Group historical open amounts into explicit age bands by effective date.
    pub fn effective_date_aging(
        &self,
        account: Option<VId>,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
        buckets: &crate::AgingBuckets,
    ) -> Result<crate::EffectiveDateAging, BookError> {
        with_store!(&self.store, core => core.effective_date_aging(
            &self.purposes(), account, effective_through, known_at, buckets
        ))
    }

    /// Certify one explicit effective-date aging request under current read+produce authority.
    pub fn certify_effective_date_aging(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::AgingRequest,
    ) -> Outcome<crate::CertifiedAging> {
        with_store!(&self.store, core => core.certify_effective_date_aging(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Replay a certified effective-date aging report under current read authority.
    pub fn replay_effective_date_aging(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        certificate: &crate::AgingCertificate,
    ) -> Outcome<crate::EffectiveDateAging> {
        with_store!(&self.store, core => core.replay_effective_date_aging(
            &self.purposes(), principal, capability, certificate
        ))
    }

    /// Compare the historical open-item fold with the stock trial balance under current read authority.
    pub fn reconcile_effective_date_aging(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::AgingReconciliationRequest,
    ) -> Outcome<crate::AgingReconciliation> {
        with_store!(&self.store, core => core.reconcile_effective_date_aging(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Certify the exact aging/control comparison and retain both native source closures.
    pub fn certify_effective_date_aging_reconciliation(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::AgingReconciliationRequest,
    ) -> Outcome<crate::CertifiedAgingReconciliation> {
        with_store!(&self.store, core => core.certify_effective_date_aging_reconciliation(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Replay an aging/control certificate against independently fixed recipient expectations.
    pub fn replay_effective_date_aging_reconciliation(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        certificate: &crate::AgingReconciliationCertificate,
        expected: &crate::AgingReconciliationRequest,
    ) -> Outcome<crate::AgingReconciliation> {
        with_store!(&self.store, core => core.replay_effective_date_aging_reconciliation(
            &self.purposes(), principal, capability, certificate, expected
        ))
    }

    /// Replay any AsSupplied-supported report artifact under current authority.
    /// Families whose correctness depends on recipient-selected parameters
    /// (cash flow and aging reconciliation) intentionally refuse this shortcut.
    pub fn replay_report_artifact(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
    ) -> Outcome<crate::ReplayedReportArtifact> {
        with_store!(&self.store, core => core.replay_report_artifact(
            &self.purposes(), principal, capability, bytes, expected_digest
        ))
    }

    /// Replay a report artifact with the recipient's independently retained
    /// scope/classification expectations. The artifact never supplies authority.
    pub fn replay_report_artifact_for(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
        expected: crate::ReportArtifactExpectation<'_>,
    ) -> Outcome<crate::ReplayedReportArtifact> {
        with_store!(&self.store, core => core.replay_report_artifact_for(
            &self.purposes(), principal, capability, bytes, expected_digest, expected
        ))
    }

    /// Fold a summary trial balance by chart roots under current whole-book read authority.
    pub fn summary_trial_balance(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::SummaryRequest,
    ) -> Outcome<crate::SummaryTrialBalance> {
        with_store!(&self.store, core => core.summary_trial_balance(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Certify a summary trial balance under current read+produce authority.
    pub fn certify_summary_trial_balance(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::SummaryRequest,
    ) -> Outcome<crate::CertifiedSummaryTrialBalance> {
        with_store!(&self.store, core => core.certify_summary_trial_balance(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Read the same stock/activity statement at two fixed recorded frontiers.
    pub fn statement_diff(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::StatementDiffRequest,
    ) -> Outcome<crate::StatementDiff> {
        with_store!(&self.store, core => core.statement_diff(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Produce both native source certificates and the exact statement comparison bridge.
    pub fn certify_statement_diff(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::StatementDiffRequest,
    ) -> Outcome<crate::CertifiedStatementDiff> {
        with_store!(&self.store, core => core.certify_statement_diff(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Replay a certified statement comparison under current read authority.
    pub fn replay_statement_diff(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        certificate: &crate::StatementDiffCertificate,
    ) -> Outcome<crate::StatementDiff> {
        with_store!(&self.store, core => core.replay_statement_diff(
            &self.purposes(), principal, capability, certificate
        ))
    }

    /// Reconcile a complete adjacent-publication trace to its net statement comparison.
    pub fn statement_trace(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::StatementTraceRequest,
    ) -> Outcome<crate::StatementTrace> {
        with_store!(&self.store, core => core.statement_trace(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Retain a source certificate for every adjacent frontier in a statement trace.
    pub fn certify_statement_trace(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::StatementTraceRequest,
    ) -> Outcome<crate::CertifiedStatementTrace> {
        with_store!(&self.store, core => core.certify_statement_trace(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Replay a certified statement trace under current read authority.
    pub fn replay_statement_trace(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        certificate: &crate::StatementTraceCertificate,
    ) -> Outcome<crate::StatementTrace> {
        with_store!(&self.store, core => core.replay_statement_trace(
            &self.purposes(), principal, capability, certificate
        ))
    }

    /// Read and classify native cash movements under current read authority.
    pub fn cash_flow(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::RollForwardRequest,
        definition: &crate::CashFlowDefinition,
    ) -> Outcome<crate::CashFlow> {
        with_store!(&self.store, core => core.cash_flow(
            &self.purposes(), principal, capability, request, definition
        ))
    }

    /// Certify classified cash movements under current read+produce authority.
    pub fn certify_cash_flow(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::RollForwardRequest,
        definition: &crate::CashFlowDefinition,
    ) -> Outcome<crate::CertifiedCashFlow> {
        with_store!(&self.store, core => core.certify_cash_flow(
            &self.purposes(), principal, capability, request, definition
        ))
    }

    /// Read an indirect earnings-to-cash workpaper at one native prefix under current read authority.
    pub fn indirect_cash_flow(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::IndirectCashFlowRequest,
    ) -> Outcome<crate::IndirectCashFlow> {
        with_store!(&self.store, core => core.indirect_cash_flow(
            &self.purposes(), principal, capability, request
        ))
    }

    /// Certify an indirect earnings-to-cash workpaper under current read+produce authority.
    pub fn certify_indirect_cash_flow(
        &self,
        principal: VId,
        capability: &fa_policy::Capability,
        request: &crate::IndirectCashFlowRequest,
    ) -> Outcome<crate::CertifiedIndirectCashFlow> {
        with_store!(&self.store, core => core.certify_indirect_cash_flow(
            &self.purposes(), principal, capability, request
        ))
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

    /// Compare every `Schedule` vertex and `SCHEDULED_BY` mirror with the
    /// journal fold (`fa verify schedules`, plan §7.6). Drift is a finding,
    /// never a repair.
    pub fn verify_schedules(&self) -> Result<fa_journal::ScheduleVerification, BookError> {
        with_store!(&self.store, core => core.verify_schedules(&self.purposes()))
    }

    /// Refold every `Period` vertex's state from its birth state and its
    /// journaled `PeriodControl` transitions and compare it with the stored
    /// `Period.state` mirror (`fa verify periods`, plan §7.3, FA-INV-02).
    pub fn verify_periods(
        &self,
        known_at: Option<CommitSeq>,
    ) -> Result<fa_journal::PeriodVerification, BookError> {
        with_store!(&self.store, core => core.verify_periods(&self.purposes(), known_at))
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

    /// Derive a period-balance allocation instruction from the current immutable journal.
    pub fn prepare_balance_allocation(
        &self,
        request: &crate::BalanceAllocationRequest,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::PreparedBalanceAllocation> {
        let purposes = self.purposes();
        with_store!(&self.store, core => core.prepare_balance_allocation(&purposes, request, capability))
    }

    /// Revalidate a source-bound balance allocation review and rehearse through the real kernel.
    pub fn plan_balance_allocation(
        &mut self,
        review: &crate::BalanceAllocationReview,
        expected_digest: [u8; 32],
        approvals: Vec<fa_model::ApprovalRef>,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::PostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan_balance_allocation(
            &purposes,
            review,
            expected_digest,
            approvals,
            capability,
        ))
    }

    /// Record an approval from a restored source-bound balance allocation review.
    pub fn approve_balance_allocation(
        &mut self,
        review: &crate::BalanceAllocationReview,
        expected_digest: [u8; 32],
        capability: &fa_policy::Capability,
    ) -> Outcome<fa_journal::Approved> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.approve_balance_allocation(
            &purposes,
            review,
            expected_digest,
            capability,
        )))
    }

    /// Prepare a single-leg open-item settlement against the current HEAD snapshot.
    pub fn prepare_settlement(
        &self,
        request: crate::SettlementPostRequest,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::PreparedSettlement> {
        let purposes = self.purposes();
        with_store!(&self.store, core => core.prepare_settlement(&purposes, request, capability))
    }

    /// Prepare and rehearse a single-leg open-item settlement through the real kernel.
    pub fn plan_settlement(
        &mut self,
        request: crate::SettlementPostRequest,
        approvals: Vec<fa_model::ApprovalRef>,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::SettlementPostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan_settlement(
            &purposes,
            request,
            approvals,
            capability,
        ))
    }

    /// Rehearse an exact prepared single-leg settlement through the real kernel.
    pub fn plan_prepared_settlement(
        &mut self,
        prepared: crate::PreparedSettlement,
        approvals: Vec<fa_model::ApprovalRef>,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::SettlementPostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan_prepared_settlement(
            &purposes,
            prepared,
            approvals,
            capability,
        ))
    }

    /// Revalidate a saved single-leg settlement review against current HEAD.
    pub fn refresh_settlement_review(
        &self,
        review: &crate::SettlementReview,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::PreparedSettlement> {
        let purposes = self.purposes();
        with_store!(&self.store, core => core.refresh_settlement_review(&purposes, review, capability))
    }

    /// Revalidate a saved single-leg settlement review and rehearse through the real kernel.
    pub fn plan_settlement_review(
        &mut self,
        review: &crate::SettlementReview,
        approvals: Vec<fa_model::ApprovalRef>,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::SettlementPostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan_settlement_review(
            &purposes,
            review,
            approvals,
            capability,
        ))
    }

    /// Record an approval of an exact saved single-leg settlement review.
    pub fn approve_settlement_review(
        &mut self,
        review: &crate::SettlementReview,
        expected_review_digest: [u8; 32],
        capability: &fa_policy::Capability,
    ) -> Outcome<fa_journal::Approved> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.approve_settlement_review(
            &purposes,
            review,
            expected_review_digest,
            capability,
        )))
    }

    /// Prepare a multi-leg open-item settlement group against the current HEAD snapshot.
    pub fn prepare_settlement_group(
        &self,
        request: crate::SettlementGroupRequest,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::PreparedSettlementGroup> {
        let purposes = self.purposes();
        with_store!(&self.store, core => core.prepare_settlement_group(&purposes, request, capability))
    }

    /// Prepare and rehearse a multi-leg open-item settlement group through the real kernel.
    pub fn plan_settlement_group(
        &mut self,
        request: crate::SettlementGroupRequest,
        approvals: Vec<fa_model::ApprovalRef>,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::SettlementGroupPostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan_settlement_group(
            &purposes,
            request,
            approvals,
            capability,
        ))
    }

    /// Rehearse an exact prepared multi-leg settlement group through the real kernel.
    pub fn plan_prepared_settlement_group(
        &mut self,
        prepared: crate::PreparedSettlementGroup,
        approvals: Vec<fa_model::ApprovalRef>,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::SettlementGroupPostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan_prepared_settlement_group(
            &purposes,
            prepared,
            approvals,
            capability,
        ))
    }

    /// Revalidate a saved multi-leg settlement group review against current HEAD.
    pub fn refresh_settlement_group_review(
        &self,
        review: &crate::SettlementGroupReview,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::PreparedSettlementGroup> {
        let purposes = self.purposes();
        with_store!(&self.store, core => core.refresh_settlement_group_review(&purposes, review, capability))
    }

    /// Revalidate a saved multi-leg settlement group review and rehearse through the real kernel.
    pub fn plan_settlement_group_review(
        &mut self,
        review: &crate::SettlementGroupReview,
        approvals: Vec<fa_model::ApprovalRef>,
        capability: &fa_policy::Capability,
    ) -> Outcome<crate::SettlementGroupPostPlan> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => core.plan_settlement_group_review(
            &purposes,
            review,
            approvals,
            capability,
        ))
    }

    /// Record an approval of an exact saved multi-leg settlement group review.
    pub fn approve_settlement_group_review(
        &mut self,
        review: &crate::SettlementGroupReview,
        expected_review_digest: [u8; 32],
        capability: &fa_policy::Capability,
    ) -> Outcome<fa_journal::Approved> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(core.approve_settlement_group_review(
            &purposes,
            review,
            expected_review_digest,
            capability,
        )))
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

mod source_intake;

#[cfg(test)]
mod tests;
