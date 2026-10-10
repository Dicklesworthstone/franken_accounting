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
use fa_registers::{Fold, TrialBalance, Verification};
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
        let units = fa_registry::units_embedded()?;
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
        Ok(Self {
            runtime,
            root,
            store,
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
        Ok(Self {
            runtime,
            root,
            store,
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
            units: fa_registry::units_embedded()?,
            seal_key: keys.seal_key(),
            symbols: SymbolTable::compiled(),
        };
        Ok(Self {
            runtime,
            root,
            store: Store::Dir(db),
            ctx,
            entropy,
        })
    }

    #[must_use]
    pub fn context(&self) -> &BookContext {
        &self.ctx
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

    /// Move a period along the state machine, as a journaled control record.
    pub fn transition_period(
        &mut self,
        period_code: &str,
        t: PeriodTransition,
        principal: VId,
        reason_code: u16,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<Transitioned> {
        let description = self.seal_text(&format!("period {period_code}: {t:?}"))?;
        let purposes = self.purposes();
        let ctx = &self.ctx;
        let runtime = &self.runtime;
        Ok(with_store!(&mut self.store, db => runtime.block_on(async {
            fa_journal::transition_period(db, &purposes, ctx, period_code, t, principal, reason_code, effective_date, idempotency_key, description).await
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

    fn spec(book_id: Id128) -> (BookSpec, fa_money::UnitId) {
        let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let units = fa_registry::units_embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        (
            BookSpec {
                book_id,
                name: "Facade Co".into(),
                base_unit: usd,
                calendar,
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
            evidence: Vec::new(),
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
            capability: Capability::with_ops(&["post"]),
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
            },
            AccountSpec {
                code: "6000".into(),
                name: "Rent".into(),
                account_type: 5,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
            },
        ]
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
        book.transition_period(&march, PeriodTransition::Open, principal, 1, day, b"open")
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
            book.transition_period(&march, PeriodTransition::Open, principal, 1, day, b"open")
                .expect("kernel")
                .expect("opens");
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
        // The journal is still open for business, and the same key is still recorded.
        let again = post_rent(&mut book, usd, principal, day, b"rent", 150_000)
            .expect("kernel")
            .expect("recorded");
        assert!(matches!(again, Posted::AlreadyRecorded { .. }));
        assert!(book.trial_balance(&[march]).unwrap().is_balanced());
    }
}
