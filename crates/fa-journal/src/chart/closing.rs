//! Effective chart routes for incremental year-end closing (plan §7.5).
//!
//! Each SchemaChange kind 12 installs one complete map. It changes no Account
//! bytes or balance rows. Both recorded time and effective date select a map;
//! source/target account identities and the book are bound by its content digest.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, DecodeError, EncodeError, Entry, Erasable, Id128, Reader, Writer, domain_digest,
    entry_mirrors, entry_vid,
};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{AccountEffectivity, admit_schema_change, schema_control_proposal};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, book_root, bytes};

/// Kinds 5 through 11 belong to REA schema controls and retain their meanings.
pub const SCHEMA_CHANGE_CLOSING_ROUTES: u16 = 12;
pub const MAX_CLOSING_ROUTES: usize = 4096;

const MAGIC: &[u8; 17] = b"FA-CLOSING-ROUTES";
const VERSION: u16 = 1;
const DIGEST_DOMAIN: &[u8] = b"fa:closing-routes:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingRoutesRequest {
    pub principal: VId,
    pub effective_from: DateDay,
    pub routes: BTreeMap<VId, VId>,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

/// One immutable map version selected from the journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingRoutes {
    pub effective_from: DateDay,
    pub routes: BTreeMap<VId, VId>,
    pub digest: [u8; 32],
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingRoutesRecorded {
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub digest: [u8; 32],
    pub already_recorded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ClosingRoutesSpec {
    pub(super) effective_from: DateDay,
    pub(super) routes: BTreeMap<VId, VId>,
}

impl ClosingRoutesSpec {
    fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(VERSION)
            .i32(self.effective_from.0)
            .u32(self.routes.len() as u32);
        for (source, target) in &self.routes {
            w.u128(source.0).u128(target.0);
        }
        w.finish()
    }

    pub(super) fn decode(raw: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(raw);
        if r.fixed::<17>("closing_routes.magic")? != *MAGIC
            || r.u16("closing_routes.version")? != VERSION
        {
            return Err(r.invalid("closing_routes.version"));
        }
        let effective_from = DateDay(r.i32("closing_routes.effective_from")?);
        let pairs = r.list(MAX_CLOSING_ROUTES, "closing_routes.routes", |r| {
            Ok((
                VId(r.u128("closing_routes.source")?),
                VId(r.u128("closing_routes.target")?),
            ))
        })?;
        if pairs.is_empty() || pairs.iter().any(|(source, target)| source == target) {
            return Err(r.invalid("closing_routes.routes"));
        }
        if pairs.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(r.unsorted("closing_routes.routes"));
        }
        r.finish()?;
        Ok(Self {
            effective_from,
            routes: pairs.into_iter().collect(),
        })
    }

    fn digest(&self, book: Id128) -> Result<[u8; 32], KernelError> {
        let encoded = self.canonical_bytes().map_err(fa_model::EntryError::from)?;
        Ok(domain_digest(DIGEST_DOMAIN, &[&book.0, &encoded]))
    }

    pub(super) fn validate(
        &self,
        accounts: &BTreeMap<VId, AccountRow>,
        effectivity: &BTreeMap<VId, AccountEffectivity>,
    ) -> Result<(), String> {
        if self.routes.is_empty() || self.routes.len() > MAX_CLOSING_ROUTES {
            return Err(format!(
                "a closing map must contain 1..={MAX_CLOSING_ROUTES} routes"
            ));
        }
        for (source, target) in &self.routes {
            let from = accounts.get(source).ok_or_else(|| {
                format!("closing source {:032x} is not a declared account", source.0)
            })?;
            let to = accounts.get(target).ok_or_else(|| {
                format!("closing target {:032x} is not a declared account", target.0)
            })?;
            if !from.is_leaf
                || !matches!(
                    AccountType(from.account_type),
                    AccountType::REVENUE | AccountType::EXPENSE
                )
            {
                return Err(format!(
                    "closing source {} must be a Revenue or Expense posting leaf",
                    from.code
                ));
            }
            if !to.is_leaf || AccountType(to.account_type) != AccountType::EQUITY {
                return Err(format!(
                    "closing target {} must be an Equity posting leaf",
                    to.code
                ));
            }
            for account in [from, to] {
                if !effectivity
                    .get(&account.vid)
                    .copied()
                    .unwrap_or_default()
                    .is_effective_at(self.effective_from)
                {
                    return Err(format!(
                        "account {} is not effective on closing-map start {}",
                        account.code, self.effective_from
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn recorded(
        self,
        book: Id128,
        control_entry: VId,
        recorded_at: CommitSeq,
    ) -> Result<ClosingRoutes, KernelError> {
        let digest = self.digest(book)?;
        Ok(ClosingRoutes {
            effective_from: self.effective_from,
            routes: self.routes,
            digest,
            control_entry,
            recorded_at,
        })
    }
}

/// Select the greatest effective start at or before the requested date, then
/// the latest recorded version at that start. A later-recorded backdated map
/// does not displace a map that was explicitly made effective at a later date.
/// Callers admit read authority and enter their query context before this read.
pub fn closing_routes_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    effective_date: DateDay,
    known_at: CommitSeq,
) -> Result<Option<ClosingRoutes>, KernelError> {
    let chart = super::read_at(db, book, known_at)?;
    Ok(chart
        .closing_routes
        .into_iter()
        .filter(|map| map.effective_from <= effective_date)
        .max_by_key(|map| (map.effective_from, map.recorded_at, map.control_entry)))
}

fn invalid_routes(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        detail,
        "plan §7.5 (journaled nominal-account closes_to routes)",
        "declare a bounded complete map from Revenue/Expense leaves to Equity leaves, effective when every named account exists",
    )
}

fn conflict(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        detail,
        "FG-LAW-FCW-01 (account declarations and current schema authority)",
        "reload the journaled chart and retry the complete closing-map change",
    )
}

fn recorded_or_conflict(
    book: &BookContext,
    row: &VertexRow,
    proposal: &fa_model::EntryPayload,
    proposal_digest: &[u8; 32],
    digest: [u8; 32],
) -> Outcome<ClosingRoutesRecorded> {
    if !row.labels.contains(&label::ENTRY) {
        return Err(KernelError::Corrupt(
            "closing-map identity is not an Entry".into(),
        ));
    }
    let stored = Entry::decode(&bytes(row, property::FA_PAYLOAD, "closing map entry")?)?;
    let same = stored.proposal_digest == *proposal_digest
        || match (
            stored.proposal.semantic_digest(&book.seal_key),
            proposal.semantic_digest(&book.seal_key),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        };
    if !same {
        return Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "closing-map idempotency key was already used for different content",
            "plan §4.9 (the key binds one immutable schema-control proposal)",
            "retry the identical map or choose a new idempotency key",
        )));
    }
    Ok(Ok(ClosingRoutesRecorded {
        control_entry: row.vid,
        recorded_at: row.created_at,
        digest,
        already_recorded: true,
    }))
}

enum Preparation {
    Recorded(ClosingRoutesRecorded),
    Ready(Box<PreparedRoutes>),
}

struct PreparedRoutes {
    txn: WriteTxn,
    capability: Capability,
    control_entry: VId,
    digest: [u8; 32],
}

impl PreparedRoutes {
    async fn commit<V: Vfs + Clone>(
        mut self,
        db: &mut Database<V>,
        cx: &PurposeContexts,
    ) -> Outcome<ClosingRoutesRecorded> {
        if let Err(denial) = fa_policy::current(&self.capability, db.frontier()?) {
            self.txn.abort();
            return Ok(Err(crate::policy::refusal(&denial)));
        }
        match self.txn.commit(db, &cx.commit()).await {
            Ok(recorded_at) => Ok(Ok(ClosingRoutesRecorded {
                control_entry: self.control_entry,
                recorded_at,
                digest: self.digest,
                already_recorded: false,
            })),
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
                Ok(Err(conflict(format!(
                    "closing-map witness changed before publication: {detail}"
                ))))
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn prepare<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: ClosingRoutesRequest,
) -> Outcome<Preparation> {
    if let Some(refusal) = admit_schema_change(db, book, request.principal, capability)? {
        return Ok(Err(refusal));
    }
    let spec = ClosingRoutesSpec {
        effective_from: request.effective_from,
        routes: request.routes,
    };
    if spec.routes.is_empty() || spec.routes.len() > MAX_CLOSING_ROUTES {
        return Ok(Err(invalid_routes(format!(
            "a closing map must contain 1..={MAX_CLOSING_ROUTES} routes"
        ))));
    }
    let digest = spec.digest(book.book_id)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_CLOSING_ROUTES,
        spec.canonical_bytes().map_err(fa_model::EntryError::from)?,
        request.principal,
        request.effective_from,
        &request.idempotency_key,
        request.description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let control_entry = entry_vid(
        book.book_id,
        &request.principal.0.to_le_bytes(),
        &request.idempotency_key,
    );
    let mut txn = db.begin(&cx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, control_entry)? {
        txn.abort();
        return Ok(
            recorded_or_conflict(book, &row, &proposal, &proposal_digest, digest)?
                .map(Preparation::Recorded),
        );
    }
    let Some(root) = txn.vertex(db, book_root())? else {
        txn.abort();
        return Err(KernelError::Corrupt("closing map has no book root".into()));
    };
    if bytes(&root, property::BOOK_ID, "book.book_id")? != book.book_id.0 {
        txn.abort();
        return Err(KernelError::Corrupt(
            "closing map belongs to another book".into(),
        ));
    }
    let chart = super::read_at(db, book, txn.basis())?;
    if let Err(detail) = spec.validate(chart.accounts(), chart.effectivity()) {
        txn.abort();
        return Ok(Err(invalid_routes(detail)));
    }
    for (source, target) in &spec.routes {
        for vid in [source, target] {
            let Some(row) = txn.vertex(db, *vid)? else {
                txn.abort();
                return Ok(Err(conflict("a closing-map account disappeared")));
            };
            if !row.labels.contains(&label::ACCOUNT)
                || chart.accounts().get(vid) != Some(&AccountRow::decode(&row)?)
            {
                txn.abort();
                return Ok(Err(conflict("a closing-map account changed")));
            }
        }
    }
    // Bind the immutable schema declarations used by chart replay as well as
    // the referenced Account mirrors. New unrelated accounts are not a reason
    // to serialize chart changes through a mutable global schema counter.
    for row in db.vertices_at(txn.basis())? {
        if row.labels.contains(&label::ENTRY) {
            let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "schema witness")?)?;
            if entry.proposal.class == fa_model::EntryClass::SCHEMA_CONTROL {
                let _declaration = txn.vertex(db, row.vid)?;
            }
        }
    }
    let mut batch = WriteBatch::new(relation::CHILD_OF);
    batch.create_vertex(control_entry, vec![label::ENTRY], entry_mirrors(&entry)?);
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return Err(error.into());
    }
    Ok(Ok(Preparation::Ready(Box::new(PreparedRoutes {
        txn,
        capability: capability.clone(),
        control_entry,
        digest,
    }))))
}

/// Journal a complete closing map under current whole-book SchemaChange
/// authority. Exact retries preserve their original identity and sequence,
/// even when the caller seals the same description with fresh randomness.
pub async fn set_closing_routes<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: ClosingRoutesRequest,
) -> Outcome<ClosingRoutesRecorded> {
    match prepare(db, cx, book, capability, request)? {
        Err(refusal) => Ok(Err(refusal)),
        Ok(Preparation::Recorded(recorded)) => Ok(Ok(recorded)),
        Ok(Preparation::Ready(prepared)) => prepared.commit(db, cx).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::{Budget, Cx};
    use fa_model::{SealKey, SymbolTable, account_vid};
    use fa_money::UnitRegistry;
    use fa_policy::{Op, Profile};
    use fa_time::FiscalCalendar;
    use fgdb::{DatabaseKeys, MemVfs};
    use fgdb_types::CanonicalScalar;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    use crate::genesis::{AccountSpec, BookSpec, UnitPolicy, create_book, install_chart};

    const PRINCIPAL: VId = VId(7);

    fn day(month: u8, date: u8) -> DateDay {
        DateDay::from_ymd(2026, month, date).unwrap()
    }

    fn authority() -> Capability {
        Capability::new(PRINCIPAL, Profile::Human, &[Op::SchemaChange], PRINCIPAL).unwrap()
    }

    struct Harness {
        runtime: Runtime,
        root: Cx,
        db: Database<MemVfs>,
        book: BookContext,
    }

    impl Harness {
        fn ctx(&self) -> PurposeContexts {
            PurposeContexts::narrow_runtime_root(&self.root)
        }

        fn vid(&self, code: &str) -> VId {
            account_vid(self.book.book_id, code)
        }

        fn description(&self, nonce: u8) -> Erasable<String> {
            Erasable::seal(
                &"Year-end closing routes".to_string(),
                None,
                &self.book.seal_key,
                [nonce; 32],
                [nonce; 24],
            )
        }

        fn request(&self, start: DateDay, target: &str, key: &[u8]) -> ClosingRoutesRequest {
            ClosingRoutesRequest {
                principal: PRINCIPAL,
                effective_from: start,
                routes: BTreeMap::from([
                    (self.vid("4000"), self.vid(target)),
                    (self.vid("5000"), self.vid(target)),
                ]),
                idempotency_key: key.to_vec(),
                description: self.description(10),
            }
        }

        fn install(
            &mut self,
            request: ClosingRoutesRequest,
            capability: &Capability,
        ) -> Result<ClosingRoutesRecorded, Refusal> {
            let cx = self.ctx();
            self.runtime
                .block_on(set_closing_routes(
                    &mut self.db,
                    &cx,
                    &self.book,
                    capability,
                    request,
                ))
                .unwrap()
        }

        fn selected(&self, date: DateDay, known: CommitSeq) -> Option<ClosingRoutes> {
            closing_routes_at(&self.db, &self.book, date, known).unwrap()
        }

        fn promote_revenue(&mut self) {
            let cx = self.ctx();
            let description = self.description(99);
            self.runtime
                .block_on(super::super::promote_to_summary(
                    &mut self.db,
                    &cx,
                    &self.book,
                    "4000",
                    day(12, 31),
                    PRINCIPAL,
                    day(12, 31),
                    b"promote-revenue",
                    description,
                    &authority(),
                ))
                .unwrap()
                .unwrap();
        }
    }

    fn harness() -> Harness {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [0x5a; 32],
            DatabaseSecurityNamespaceId([0x5b; 32]),
            [0x5c; 32],
        );
        let mut db = runtime
            .block_on(Database::open_memory(&cx.commit(), keys))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let book_id = Id128([9; 16]);
        let spec = BookSpec {
            book_id,
            name: "Closing routes".into(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(create_book(&mut db, &cx, &spec, &units, &symbols))
            .unwrap();
        let book = BookContext {
            book_id,
            calendar,
            units,
            seal_key: SealKey([0x11; 32]),
            symbols,
        };
        let chart: Vec<AccountSpec> = [
            ("1000", AccountType::ASSET),
            ("3000", AccountType::EQUITY),
            ("3100", AccountType::EQUITY),
            ("4000", AccountType::REVENUE),
            ("5000", AccountType::EXPENSE),
        ]
        .into_iter()
        .map(|(code, account_type)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: account_type.0,
            normal_balance: u8::from(matches!(
                account_type,
                AccountType::EQUITY | AccountType::REVENUE
            )),
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        })
        .collect();
        let description = Erasable::seal(
            &"Initial chart".to_string(),
            None,
            &book.seal_key,
            [5; 32],
            [6; 24],
        );
        runtime
            .block_on(install_chart(
                &mut db,
                &cx,
                &book,
                &chart,
                PRINCIPAL,
                day(1, 1),
                b"initial-chart",
                description,
                &authority(),
            ))
            .unwrap()
            .unwrap();
        Harness {
            runtime,
            root,
            db,
            book,
        }
    }

    #[test]
    fn closing_routes_select_effective_versions_and_exact_retries_without_account_changes() {
        let mut h = harness();
        let authority = authority();
        let before = h.db.frontier().unwrap();
        let originals: BTreeMap<_, _> = ["1000", "3000", "3100", "4000", "5000"]
            .into_iter()
            .map(|code| {
                let vid = h.vid(code);
                (vid, h.db.vertex(vid).unwrap().unwrap().props)
            })
            .collect();
        let initial_request = h.request(day(1, 1), "3000", b"routes-jan");
        let first = h.install(initial_request.clone(), &authority).unwrap();
        assert!(!first.already_recorded);
        assert!(h.selected(day(12, 31), before).is_none());
        assert!(
            h.selected(DateDay::from_ymd(2025, 12, 31).unwrap(), first.recorded_at)
                .is_none()
        );
        for (vid, properties) in originals {
            assert_eq!(h.db.vertex(vid).unwrap().unwrap().props, properties);
        }
        crate::rea::read_rea_at(&h.db, &h.book, first.recorded_at).unwrap();

        let mut retry = initial_request;
        retry.description = h.description(20);
        let head = h.db.frontier().unwrap();
        let recorded = h.install(retry, &authority).unwrap();
        assert_eq!(
            recorded,
            ClosingRoutesRecorded {
                already_recorded: true,
                ..first.clone()
            }
        );
        assert_eq!(h.db.frontier().unwrap(), head);

        let conflicting = h.request(day(1, 1), "3100", b"routes-jan");
        assert_eq!(
            h.install(conflicting, &authority).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
        assert_eq!(h.db.frontier().unwrap(), head);

        let request = h.request(day(7, 1), "3100", b"routes-jul");
        let july = h.install(request, &authority).unwrap();
        let request = h.request(day(3, 1), "3000", b"routes-mar-backdated");
        let march = h.install(request, &authority).unwrap();
        let head = h.db.frontier().unwrap();
        assert_eq!(
            h.selected(day(4, 1), head).unwrap().control_entry,
            march.control_entry
        );
        assert_eq!(
            h.selected(day(8, 1), head).unwrap().control_entry,
            july.control_entry
        );
        assert_eq!(
            h.selected(day(8, 1), first.recorded_at)
                .unwrap()
                .control_entry,
            first.control_entry
        );
        let request = h.request(day(7, 1), "3000", b"routes-jul-revised");
        let revised = h.install(request, &authority).unwrap();
        assert_eq!(
            h.selected(day(8, 1), revised.recorded_at)
                .unwrap()
                .control_entry,
            revised.control_entry
        );
        assert_ne!(july.digest, revised.digest);
    }

    #[test]
    fn closing_routes_refuse_invalid_accounts_and_current_schema_authority_before_publication() {
        let mut h = harness();
        let head = h.db.frontier().unwrap();
        let no_schema = Capability::new(PRINCIPAL, Profile::Human, &[], PRINCIPAL).unwrap();
        let other_book = authority().for_books(&[Id128([8; 16])]).unwrap();
        let expired = authority().expiring_at(head);
        for capability in [&no_schema, &other_book, &expired] {
            let request = h.request(day(1, 1), "3000", b"denied");
            assert!(h.install(request, capability).is_err());
            assert_eq!(h.db.frontier().unwrap(), head);
        }
        for routes in [
            BTreeMap::new(),
            BTreeMap::from([(h.vid("1000"), h.vid("3000"))]),
            BTreeMap::from([(h.vid("4000"), h.vid("5000"))]),
            BTreeMap::from([(h.vid("missing"), h.vid("3000"))]),
            BTreeMap::from([(account_vid(Id128([8; 16]), "4000"), h.vid("3000"))]),
        ] {
            let mut request = h.request(day(1, 1), "3000", b"invalid-map");
            request.routes = routes;
            assert_eq!(
                h.install(request, &authority()).unwrap_err().code,
                code::STRUCTURE
            );
            assert_eq!(h.db.frontier().unwrap(), head);
        }
        let mut request = h.request(day(1, 1), "3000", b"wrong-principal");
        request.principal = VId(99);
        assert!(h.install(request, &authority()).is_err());
        assert_eq!(h.db.frontier().unwrap(), head);
    }

    #[test]
    fn closing_routes_keep_historical_declarations_when_accounts_later_change() {
        let mut h = harness();
        let request = h.request(day(1, 1), "3000", b"routes-before-promotion");
        let recorded = h.install(request, &authority()).unwrap();
        h.promote_revenue();
        let head = h.db.frontier().unwrap();
        let selected = h.selected(day(12, 31), head).unwrap();
        assert_eq!(selected.control_entry, recorded.control_entry);
        assert_eq!(selected.digest, recorded.digest);
        let mut retry = h.request(day(1, 1), "3000", b"routes-before-promotion");
        retry.description = h.description(21);
        assert!(h.install(retry, &authority()).unwrap().already_recorded);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert!(
            !super::super::read_at(&h.db, &h.book, head)
                .unwrap()
                .accounts()[&h.vid("4000")]
                .is_leaf
        );
        let request = h.request(day(1, 1), "3000", b"routes-after-promotion");
        assert_eq!(
            h.install(request, &authority()).unwrap_err().code,
            code::STRUCTURE
        );
        assert_eq!(h.db.frontier().unwrap(), head);
    }

    #[test]
    fn closing_routes_hold_account_and_policy_witnesses_until_the_original_commit() {
        for change_account in [true, false] {
            let mut h = harness();
            let cx = h.ctx();
            let request = h.request(day(1, 1), "3000", b"prepared-map");
            let prepared = match prepare(&mut h.db, &cx, &h.book, &authority(), request)
                .unwrap()
                .unwrap()
            {
                Preparation::Ready(prepared) => prepared,
                Preparation::Recorded(_) => panic!("new map unexpectedly already recorded"),
            };
            if change_account {
                h.promote_revenue();
            } else {
                // A real native write changes precisely the witnessed policy
                // cell; this is a FCW oracle, not a replacement policy service.
                let mut batch = WriteBatch::new(relation::IN_BOOK);
                batch.set_vertex_property(
                    book_root(),
                    property::SECURITY_POLICY_EPOCH,
                    Some(CanonicalScalar::Int(1)),
                );
                h.runtime.block_on(h.db.write(&cx.commit(), batch)).unwrap();
            }
            let head = h.db.frontier().unwrap();
            let result = h.runtime.block_on(prepared.commit(&mut h.db, &cx)).unwrap();
            assert_eq!(result.unwrap_err().code, code::CONFLICT);
            assert_eq!(h.db.frontier().unwrap(), head);
            assert!(h.selected(day(12, 31), head).is_none());
        }
    }

    // Independently constructs the documented wire layout, including cases
    // a BTreeMap-based writer cannot represent.
    fn wire(version: u16, date: DateDay, pairs: &[(VId, VId)]) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(b"FA-CLOSING-ROUTES").u16(version).i32(date.0);
        w.list(pairs, |w, (source, target)| {
            w.u128(source.0).u128(target.0);
        });
        w.finish().unwrap()
    }

    #[test]
    fn closing_routes_codec_rejects_noncanonical_and_unbounded_maps() {
        let valid = wire(1, day(1, 1), &[(VId(1), VId(3)), (VId(2), VId(3))]);
        assert_eq!(ClosingRoutesSpec::decode(&valid).unwrap().routes.len(), 2);
        for prefix in 0..valid.len() {
            assert!(ClosingRoutesSpec::decode(&valid[..prefix]).is_err());
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(ClosingRoutesSpec::decode(&trailing).is_err());
        for raw in [
            wire(2, day(1, 1), &[(VId(1), VId(2))]),
            wire(1, day(1, 1), &[]),
            wire(1, day(1, 1), &[(VId(1), VId(1))]),
            wire(1, day(1, 1), &[(VId(1), VId(3)), (VId(1), VId(4))]),
            wire(1, day(1, 1), &[(VId(2), VId(3)), (VId(1), VId(3))]),
        ] {
            assert!(ClosingRoutesSpec::decode(&raw).is_err());
        }
        let mut oversized = Writer::new();
        oversized
            .fixed(b"FA-CLOSING-ROUTES")
            .u16(1)
            .i32(day(1, 1).0)
            .u32((MAX_CLOSING_ROUTES + 1) as u32);
        assert!(ClosingRoutesSpec::decode(&oversized.finish().unwrap()).is_err());
        let mut spec = ClosingRoutesSpec::decode(&valid).unwrap();
        let digest = spec.digest(Id128([1; 16])).unwrap();
        assert_ne!(digest, spec.digest(Id128([2; 16])).unwrap());
        spec.effective_from = day(2, 1);
        assert_ne!(digest, spec.digest(Id128([1; 16])).unwrap());
    }

    #[test]
    fn closing_routes_chart_replay_refuses_malformed_payloads_and_date_mismatches() {
        for malformed in [true, false] {
            let mut h = harness();
            let request = h.request(day(1, 1), "3000", b"corrupt-map");
            let mut raw = ClosingRoutesSpec {
                effective_from: request.effective_from,
                routes: request.routes,
            }
            .canonical_bytes()
            .unwrap();
            if malformed {
                raw.push(0);
            }
            let proposal = schema_control_proposal(
                &h.book,
                SCHEMA_CHANGE_CLOSING_ROUTES,
                raw,
                PRINCIPAL,
                day(2, 1),
                b"corrupt-map",
                request.description,
            );
            let entry = proposal.seal(Vec::new(), None).unwrap();
            let vid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"corrupt-map");
            let mut batch = WriteBatch::new(relation::CHILD_OF);
            batch.create_vertex(vid, vec![label::ENTRY], entry_mirrors(&entry).unwrap());
            let cx = h.ctx();
            h.runtime.block_on(h.db.write(&cx.commit(), batch)).unwrap();
            assert!(super::super::read_at(&h.db, &h.book, h.db.frontier().unwrap()).is_err());
        }
    }

    #[test]
    fn closing_routes_survive_native_scratch_replay_with_the_same_identity_and_digest() {
        let mut h = harness();
        let request = h.request(day(1, 1), "3000", b"scratch-map");
        let first = h.install(request, &authority()).unwrap();
        let request = h.request(day(7, 1), "3100", b"scratch-map-revised");
        h.install(request, &authority()).unwrap();
        let cx = h.ctx();
        let keys = DatabaseKeys::new(
            [0x6a; 32],
            DatabaseSecurityNamespaceId([0x6b; 32]),
            [0x6c; 32],
        );
        let mut scratch = h
            .runtime
            .block_on(Database::open_memory(&cx.commit(), keys))
            .unwrap();
        let map = h
            .runtime
            .block_on(crate::scratch::replay_into(
                &mut h.db,
                &mut scratch,
                &cx,
                &h.book,
                None,
            ))
            .unwrap()
            .unwrap();
        let scratch_known = map.translate(first.recorded_at).unwrap();
        let selected = closing_routes_at(&scratch, &h.book, day(12, 31), scratch_known)
            .unwrap()
            .unwrap();
        assert_eq!(selected.control_entry, first.control_entry);
        assert_eq!(selected.digest, first.digest);
        assert_eq!(selected.recorded_at, scratch_known);
        assert_eq!(selected.routes[&h.vid("4000")], h.vid("3000"));
        let source_current = h.selected(day(12, 31), h.db.frontier().unwrap()).unwrap();
        let replay_current =
            closing_routes_at(&scratch, &h.book, day(12, 31), scratch.frontier().unwrap())
                .unwrap()
                .unwrap();
        assert_eq!(source_current.routes, replay_current.routes);
        assert_eq!(source_current.digest, replay_current.digest);
        assert_eq!(source_current.control_entry, replay_current.control_entry);
    }
}
