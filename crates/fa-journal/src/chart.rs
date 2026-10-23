//! Historical chart forests from immutable schema-control records (plan §4.3,
//! §5.6, fa-up7). Parentage is read from the canonical SchemaChange payload,
//! not inferred from account codes or trusted from mutable CHILD_OF edges.
//!
//! Supports chart installation (`kind = 1`) and journaled account lifecycle
//! controls (`kind = 2` open_account, `kind = 3` close_account, `kind = 4`
//! promote_to_summary), plus effective closing maps (`kind = 12`). Unknown
//! schema controls fail closed until their chart
//! effect is understood. The low-level reader follows the register-read
//! contract: callers admit authority and enter their query context before
//! invoking it.

mod closing;
mod fx;

pub use closing::{
    ClosingRoutes, ClosingRoutesRecorded, ClosingRoutesRequest, MAX_CLOSING_ROUTES,
    SCHEMA_CHANGE_CLOSING_ROUTES, closing_routes_at, set_closing_routes,
};
pub use fx::{
    FxRevaluationRoute, FxRevaluationRoutes, FxRevaluationRoutesRecorded,
    FxRevaluationRoutesRequest, MAX_FX_REVALUATION_ROUTES, SCHEMA_CHANGE_FX_REVALUATION_ROUTES,
    fx_revaluation_routes_at, set_fx_revaluation_routes,
};

use std::collections::{BTreeMap, BTreeSet};

use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ControlKind, ControlPayload, DecodeError, EncodeError, Entry, EntryClass,
    EntryOrigin, EntryPayload, Erasable, Id128, Reader, Writer, account_vid, entry_mirrors,
    entry_vid,
};
use fa_money::{Side, UnitId};
use fa_policy::{Capability, Intent, Op, Reach};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::KernelError;
use crate::genesis::{AccountSpec, BookContext, UnitPolicy, list_periods};
use crate::limit::{BalanceLimit, LimitCell, LimitScope, limit_cell_vid, period_cell_vid};
use crate::refusal::{Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, book_root, bytes, edge_id, prop, scalar_bytes, scalar_text};

/// Optional effectivity and lifecycle metadata for an Account vertex (plan §5.6, fa-up7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountEffectivity {
    pub opened: Option<DateDay>,
    pub closed: Option<DateDay>,
    pub promoted_on: Option<DateDay>,
}

impl AccountEffectivity {
    const DOMAIN: &'static [u8; 25] = b"fa:account-effectivity:v1";

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.opened.is_none() && self.closed.is_none() && self.promoted_on.is_none()
    }

    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        if let (Some(opened), Some(closed)) = (self.opened, self.closed)
            && opened >= closed
        {
            return false;
        }
        if let (Some(opened), Some(promoted)) = (self.opened, self.promoted_on)
            && opened > promoted
        {
            return false;
        }
        if let (Some(promoted), Some(closed)) = (self.promoted_on, self.closed)
            && promoted > closed
        {
            return false;
        }
        true
    }

    /// Half-open `[opened, closed)` effective-date admission check (`FA-INV-01.account-effective`).
    #[must_use]
    pub fn is_effective_at(&self, day: DateDay) -> bool {
        self.opened.is_none_or(|opened| day >= opened)
            && self.closed.is_none_or(|closed| day < closed)
    }

    pub fn encode_payload(&self) -> Result<Option<Vec<u8>>, EncodeError> {
        if self.is_empty() {
            return Ok(None);
        }
        let mut w = Writer::new();
        w.fixed(Self::DOMAIN)
            .opt(self.opened.as_ref(), |w, d| {
                w.i32(d.0);
            })
            .opt(self.closed.as_ref(), |w, d| {
                w.i32(d.0);
            })
            .opt(self.promoted_on.as_ref(), |w, d| {
                w.i32(d.0);
            });
        w.finish().map(Some)
    }

    pub fn decode_payload(raw: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(raw);
        let domain = r.fixed::<25>("account.effectivity_domain")?;
        if &domain != Self::DOMAIN {
            return Err(r.invalid("account.effectivity_domain"));
        }
        let effectivity = Self {
            opened: r.opt("account.opened", |r| Ok(DateDay(r.i32("account.opened")?)))?,
            closed: r.opt("account.closed", |r| Ok(DateDay(r.i32("account.closed")?)))?,
            promoted_on: r.opt("account.promoted_on", |r| {
                Ok(DateDay(r.i32("account.promoted_on")?))
            })?,
        };
        if effectivity.is_empty() || !effectivity.is_well_formed() {
            return Err(r.invalid("account.effectivity"));
        }
        r.finish()?;
        Ok(effectivity)
    }

    pub fn decode_from_row(row: &VertexRow) -> Result<Self, KernelError> {
        match prop(row, property::FA_PAYLOAD) {
            None => Ok(Self::default()),
            Some(CanonicalScalar::Bytes(raw)) => Self::decode_payload(raw.as_slice())
                .map_err(|e| KernelError::Corrupt(format!("account._fa_payload: {e}"))),
            Some(_) => Err(KernelError::Corrupt(
                "account._fa_payload must be bytes".into(),
            )),
        }
    }
}

/// A validated forest at one recorded frontier. Fields stay private so a
/// caller cannot introduce a cycle or an unjournaled parent after validation.
#[derive(Clone, Debug)]
pub struct ChartSnapshot {
    known_at: CommitSeq,
    accounts: BTreeMap<VId, AccountRow>,
    effectivity: BTreeMap<VId, AccountEffectivity>,
    parents: BTreeMap<VId, VId>,
    children: BTreeMap<VId, Vec<VId>>,
    closing_routes: Vec<ClosingRoutes>,
    fx_revaluation_routes: Vec<FxRevaluationRoutes>,
}

impl ChartSnapshot {
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.known_at
    }

    #[must_use]
    pub fn accounts(&self) -> &BTreeMap<VId, AccountRow> {
        &self.accounts
    }

    #[must_use]
    pub fn effectivity(&self) -> &BTreeMap<VId, AccountEffectivity> {
        &self.effectivity
    }

    #[must_use]
    pub fn account_effectivity(&self, vid: VId) -> Option<AccountEffectivity> {
        self.effectivity.get(&vid).copied()
    }

    #[must_use]
    pub fn parents(&self) -> &BTreeMap<VId, VId> {
        &self.parents
    }

    /// Each summary account's direct children.
    #[must_use]
    pub fn children(&self) -> &BTreeMap<VId, Vec<VId>> {
        &self.children
    }

    /// Every journaled FX revaluation routing version, in recorded order.
    #[must_use]
    pub(crate) fn fx_revaluation_routes(&self) -> &[FxRevaluationRoutes] {
        &self.fx_revaluation_routes
    }

    /// Exactly the posting leaves below `root`, including `root` itself if
    /// it is a leaf. An empty summary has an empty set, not a missing balance.
    /// The walk is iterative: valid deep charts never consume the call stack.
    pub fn leaves_under(&self, root: VId) -> Result<BTreeSet<VId>, KernelError> {
        if !self.accounts.contains_key(&root) {
            return Err(corrupt(format!("unknown chart account {:032x}", root.0)));
        }
        let mut leaves = BTreeSet::new();
        let mut pending = vec![root];
        while let Some(vid) = pending.pop() {
            let account = self
                .accounts
                .get(&vid)
                .ok_or_else(|| corrupt("validated chart lost an account"))?;
            if account.is_leaf {
                leaves.insert(vid);
            } else if let Some(children) = self.children.get(&vid) {
                pending.extend(children.iter().copied());
            }
        }
        Ok(leaves)
    }
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("journaled chart: {}", message.into()))
}

#[derive(Clone, Debug)]
enum ChartOp {
    Install(Vec<AccountSpec>),
    ClosingRoutes(closing::ClosingRoutesSpec),
    FxRevaluationRoutes(fx::FxRevaluationRoutesSpec),
    NativeSubledger(crate::subledger::NativeSubledgerSpec),
    OpenAccount {
        spec: AccountSpec,
        opened: DateDay,
        closed: Option<DateDay>,
    },
    CloseAccount {
        code: String,
        closed_on: DateDay,
    },
    PromoteToSummary {
        code: String,
        promotion_date: DateDay,
    },
}

/// Rebuild the journaled chart at `known_at` and check every Account
/// mirror against its journaled declaration and lifecycle state. Neither later
/// schema controls nor present-day metadata participate. Missing, extra, or
/// rebound account mirrors are corruption, not reasons to silently change
/// subtree membership.
pub fn read_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: CommitSeq,
) -> Result<ChartSnapshot, KernelError> {
    if known_at > db.frontier()? {
        return Err(corrupt("requested frontier is beyond the book head"));
    }
    let rows = db.vertices_at(known_at)?;
    let mut controls = Vec::new();
    for row in &rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "chart entry payload")?)?;
        if entry.proposal.class != EntryClass::SCHEMA_CONTROL {
            continue;
        }
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(corrupt(
                "a schema control belongs to another book or branch",
            ));
        }
        if matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::PERIOD_CREATION,
                ..
            }
        ) {
            let root = rows
                .iter()
                .find(|candidate| candidate.vid == book_root())
                .ok_or_else(|| corrupt("no book root for period creation"))?;
            let spec = crate::genesis::BookSpec::decode(&bytes(
                root,
                property::FA_PAYLOAD,
                "book payload",
            )?)?;
            crate::period_creation::declared_creation(row, book, &spec)?;
            continue;
        }
        if !matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::CHART_INSTALL,
                ..
            }
        ) {
            return Err(corrupt("unsupported schema-control origin"));
        }
        let op = match &entry.proposal.control {
            Some(ControlPayload::SchemaChange {
                kind: 1,
                canonical_bytes,
            }) => ChartOp::Install(
                decode_install(canonical_bytes)
                    .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?,
            ),
            Some(ControlPayload::SchemaChange {
                kind: 2,
                canonical_bytes,
            }) => {
                let (spec, opened, closed) = decode_open_account(canonical_bytes)
                    .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?;
                ChartOp::OpenAccount {
                    spec,
                    opened,
                    closed,
                }
            }
            Some(ControlPayload::SchemaChange {
                kind: 3,
                canonical_bytes,
            }) => {
                let (code, closed_on) = decode_close_account(canonical_bytes)
                    .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?;
                ChartOp::CloseAccount { code, closed_on }
            }
            Some(ControlPayload::SchemaChange {
                kind: 4,
                canonical_bytes,
            }) => {
                let (code, promotion_date) = decode_promote_to_summary(canonical_bytes)
                    .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?;
                ChartOp::PromoteToSummary {
                    code,
                    promotion_date,
                }
            }
            Some(ControlPayload::SchemaChange {
                kind: SCHEMA_CHANGE_CLOSING_ROUTES,
                canonical_bytes,
            }) => {
                let spec = closing::ClosingRoutesSpec::decode(canonical_bytes)
                    .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?;
                if spec.effective_from != entry.proposal.effective_date {
                    return Err(corrupt(
                        "closing-map start differs from its schema-control date",
                    ));
                }
                ChartOp::ClosingRoutes(spec)
            }
            Some(ControlPayload::SchemaChange {
                kind: SCHEMA_CHANGE_FX_REVALUATION_ROUTES,
                canonical_bytes,
            }) => {
                let spec = fx::FxRevaluationRoutesSpec::decode(canonical_bytes)
                    .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?;
                if spec.effective_from != entry.proposal.effective_date {
                    return Err(corrupt("FX-map start differs from its schema-control date"));
                }
                ChartOp::FxRevaluationRoutes(spec)
            }
            Some(ControlPayload::SchemaChange {
                kind: crate::subledger::SCHEMA_CHANGE_NATIVE_SUBLEDGER,
                canonical_bytes,
            }) => ChartOp::NativeSubledger(crate::subledger::NativeSubledgerSpec::decode(
                canonical_bytes,
            )?),
            // A role classifies an account without changing the chart; the
            // role fold (account_role) checks it names an account.
            Some(ControlPayload::SchemaChange {
                kind: crate::account_role::SCHEMA_CHANGE_ACCOUNT_ROLE,
                canonical_bytes,
            }) => {
                crate::account_role::AccountRoleSpec::decode(canonical_bytes)?;
                continue;
            }
            Some(ControlPayload::SchemaChange {
                kind,
                canonical_bytes,
            }) if fa_model::ReaControlOp::is_rea_schema_change_kind(*kind) => {
                fa_model::ReaControlOp::decode(*kind, canonical_bytes)
                    .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?;
                continue;
            }
            _ => {
                return Err(corrupt(
                    "unsupported schema change; its chart effect must be implemented before reporting",
                ));
            }
        };
        controls.push((row.created_at, row.vid, op));
    }
    controls.sort_by_key(|(created_at, vid, _)| (*created_at, *vid));
    let chart = replay_controls(book.book_id, known_at, controls)?;
    let mut observed = BTreeSet::new();
    for row in &rows {
        if !row.labels.contains(&label::ACCOUNT) {
            continue;
        }
        let expected = chart.accounts.get(&row.vid).ok_or_else(|| {
            corrupt(format!(
                "account {:032x} has no chart-install declaration",
                row.vid.0
            ))
        })?;
        let expected_eff = chart.account_effectivity(row.vid).unwrap_or_default();
        if bytes(row, property::BOOK_ID, "account.book_id")? != book.book_id.0
            || AccountRow::decode(row)? != *expected
            || AccountEffectivity::decode_from_row(row)? != expected_eff
        {
            return Err(corrupt(format!(
                "account `{}` differs from its immutable declaration",
                expected.code
            )));
        }
        if let UnitPolicy::Single(unit) = expected.unit_policy
            && book.units.get(unit).is_none()
        {
            return Err(corrupt(format!(
                "account `{}` names unregistered unit {}",
                expected.code, unit.0
            )));
        }
        observed.insert(row.vid);
    }
    for (vid, account) in &chart.accounts {
        if !observed.contains(vid) {
            return Err(corrupt(format!(
                "declared account `{}` is absent at {}",
                account.code, known_at.0
            )));
        }
    }
    Ok(chart)
}

fn insert_account_spec(
    book: Id128,
    known_at: CommitSeq,
    created_at: CommitSeq,
    spec: AccountSpec,
    accounts: &mut BTreeMap<VId, AccountRow>,
    parents: &mut BTreeMap<VId, VId>,
) -> Result<VId, KernelError> {
    if created_at > known_at {
        return Err(corrupt("a declaration lies after the selected frontier"));
    }
    if spec.code.is_empty()
        || spec.code.len() > 64
        || !AccountType(spec.account_type).is_registered()
        || spec.normal_balance > 1
    {
        return Err(corrupt(format!(
            "invalid account declaration `{}`",
            spec.code
        )));
    }
    if let Some(limit) = spec.limit
        && (!limit.is_well_formed()
            || !spec.is_leaf
            || !matches!(spec.unit_policy, UnitPolicy::Single(_)))
    {
        return Err(corrupt(format!("invalid balance limit on `{}`", spec.code)));
    }
    let vid = account_vid(book, &spec.code);
    if let Some(parent) = &spec.parent_code {
        parents.insert(vid, account_vid(book, parent));
    }
    let row = AccountRow {
        vid,
        code: spec.code,
        name: spec.name,
        account_type: spec.account_type,
        normal_balance: spec.normal_balance,
        is_leaf: spec.is_leaf,
        unit_policy: spec.unit_policy,
        limit: spec.limit,
        created_at,
    };
    if accounts.insert(vid, row).is_some() {
        return Err(corrupt(format!(
            "duplicate account identity {:032x}",
            vid.0
        )));
    }
    Ok(vid)
}

fn replay_controls(
    book: Id128,
    known_at: CommitSeq,
    controls: Vec<(CommitSeq, VId, ChartOp)>,
) -> Result<ChartSnapshot, KernelError> {
    let mut accounts: BTreeMap<VId, AccountRow> = BTreeMap::new();
    let mut effectivity: BTreeMap<VId, AccountEffectivity> = BTreeMap::new();
    let mut parents = BTreeMap::new();
    let mut closing_routes = Vec::new();
    let mut fx_revaluation_routes = Vec::new();
    let mut native_control_accounts = BTreeSet::new();
    let mut native_codes = BTreeSet::new();
    for (created_at, control_entry, op) in controls {
        match op {
            ChartOp::NativeSubledger(spec) => {
                if created_at > known_at
                    || !native_control_accounts.insert(spec.control_account)
                    || !native_codes.insert(spec.code.clone())
                {
                    return Err(corrupt("duplicate or future native subledger registration"));
                }
                let account = accounts
                    .get_mut(&spec.control_account)
                    .ok_or_else(|| corrupt("native subledger control account is absent"))?;
                if !account.is_leaf || AccountType(account.account_type) != spec.kind.account_type()
                {
                    return Err(corrupt(
                        "native subledger requires a correctly typed posting leaf",
                    ));
                }
                // control_of is a journaled account-row version change.
                account.created_at = created_at;
            }
            ChartOp::FxRevaluationRoutes(spec) => {
                if created_at > known_at {
                    return Err(corrupt("an FX route map lies after the selected frontier"));
                }
                spec.validate(&accounts, &effectivity, &fx_revaluation_routes)
                    .map_err(corrupt)?;
                fx_revaluation_routes.push(spec.recorded(book, control_entry, created_at)?);
            }
            ChartOp::ClosingRoutes(spec) => {
                if created_at > known_at {
                    return Err(corrupt("a closing map lies after the selected frontier"));
                }
                // Validate the declaration in its recorded chart state. A
                // subsequent lifecycle change cannot rewrite an older map.
                spec.validate(&accounts, &effectivity).map_err(corrupt)?;
                closing_routes.push(spec.recorded(book, control_entry, created_at)?);
            }
            ChartOp::Install(specs) => {
                let mut batch_vids = Vec::with_capacity(specs.len());
                for spec in specs {
                    let vid = insert_account_spec(
                        book,
                        known_at,
                        created_at,
                        spec,
                        &mut accounts,
                        &mut parents,
                    )?;
                    batch_vids.push(vid);
                }
                for vid in batch_vids {
                    if let Some(parent_vid) = parents.get(&vid) {
                        let parent = accounts.get(parent_vid).ok_or_else(|| {
                            corrupt(format!(
                                "account {:032x} has an absent parent {:032x}",
                                vid.0, parent_vid.0
                            ))
                        })?;
                        if parent.is_leaf {
                            return Err(corrupt(format!(
                                "posting leaf `{}` has a child",
                                parent.code
                            )));
                        }
                    }
                }
            }
            ChartOp::OpenAccount {
                spec,
                opened,
                closed,
            } => {
                let vid = insert_account_spec(
                    book,
                    known_at,
                    created_at,
                    spec,
                    &mut accounts,
                    &mut parents,
                )?;
                if let Some(parent_vid) = parents.get(&vid) {
                    let parent = accounts.get(parent_vid).ok_or_else(|| {
                        corrupt(format!(
                            "account {:032x} has an absent parent {:032x}",
                            vid.0, parent_vid.0
                        ))
                    })?;
                    if parent.is_leaf {
                        return Err(corrupt(format!(
                            "posting leaf `{}` has a child",
                            parent.code
                        )));
                    }
                }
                let eff = AccountEffectivity {
                    opened: Some(opened),
                    closed,
                    promoted_on: None,
                };
                if !eff.is_well_formed() {
                    return Err(corrupt(format!(
                        "invalid account effectivity on {:032x}",
                        vid.0
                    )));
                }
                effectivity.insert(vid, eff);
            }
            ChartOp::CloseAccount { code, closed_on } => {
                if created_at > known_at {
                    return Err(corrupt("a close control lies after the selected frontier"));
                }
                let vid = account_vid(book, &code);
                let account = accounts.get_mut(&vid).ok_or_else(|| {
                    corrupt(format!("close_account references absent account `{code}`"))
                })?;
                account.created_at = created_at;
                let eff = effectivity.entry(vid).or_default();
                if eff.closed.is_some() {
                    return Err(corrupt(format!("account `{code}` closed more than once")));
                }
                eff.closed = Some(closed_on);
                if !eff.is_well_formed() {
                    return Err(corrupt(format!("invalid close date on account `{code}`")));
                }
            }
            ChartOp::PromoteToSummary {
                code,
                promotion_date,
            } => {
                if created_at > known_at {
                    return Err(corrupt(
                        "a promote_to_summary control lies after the selected frontier",
                    ));
                }
                let vid = account_vid(book, &code);
                let account = accounts.get_mut(&vid).ok_or_else(|| {
                    corrupt(format!(
                        "promote_to_summary references absent account `{code}`"
                    ))
                })?;
                if !account.is_leaf
                    || account.limit.is_some()
                    || native_control_accounts.contains(&vid)
                {
                    return Err(corrupt(format!(
                        "promote_to_summary on non-leaf or limit-bearing account `{code}`"
                    )));
                }
                account.is_leaf = false;
                account.created_at = created_at;
                let eff = effectivity.entry(vid).or_default();
                if eff.promoted_on.is_some() {
                    return Err(corrupt(format!("account `{code}` promoted more than once")));
                }
                eff.promoted_on = Some(promotion_date);
                if !eff.is_well_formed() {
                    return Err(corrupt(format!(
                        "invalid promotion date on account `{code}`"
                    )));
                }
            }
        }
    }
    finalize_snapshot(
        known_at,
        accounts,
        effectivity,
        parents,
        closing_routes,
        fx_revaluation_routes,
    )
}

#[cfg(test)]
fn assemble(
    book: Id128,
    known_at: CommitSeq,
    definitions: Vec<(AccountSpec, CommitSeq)>,
) -> Result<ChartSnapshot, KernelError> {
    let mut accounts = BTreeMap::new();
    let mut parents = BTreeMap::new();
    for (spec, created_at) in definitions {
        insert_account_spec(
            book,
            known_at,
            created_at,
            spec,
            &mut accounts,
            &mut parents,
        )?;
    }
    finalize_snapshot(
        known_at,
        accounts,
        BTreeMap::new(),
        parents,
        Vec::new(),
        Vec::new(),
    )
}

fn finalize_snapshot(
    known_at: CommitSeq,
    accounts: BTreeMap<VId, AccountRow>,
    effectivity: BTreeMap<VId, AccountEffectivity>,
    parents: BTreeMap<VId, VId>,
    closing_routes: Vec<ClosingRoutes>,
    fx_revaluation_routes: Vec<FxRevaluationRoutes>,
) -> Result<ChartSnapshot, KernelError> {
    let mut children: BTreeMap<VId, Vec<VId>> = BTreeMap::new();
    for (child, parent) in &parents {
        let row = accounts.get(parent).ok_or_else(|| {
            corrupt(format!(
                "account {:032x} has an absent parent {:032x}",
                child.0, parent.0
            ))
        })?;
        if row.is_leaf {
            return Err(corrupt(format!("posting leaf `{}` has a child", row.code)));
        }
        children.entry(*parent).or_default().push(*child);
    }
    // Mark completed paths so an arbitrarily deep forest takes linear walks
    // rather than restarting at the root for every descendant.
    let mut complete = BTreeSet::new();
    for vid in accounts.keys() {
        let mut path = BTreeSet::new();
        let mut current = Some(*vid);
        while let Some(node) = current {
            if complete.contains(&node) {
                break;
            }
            if !path.insert(node) {
                return Err(corrupt(format!("parent cycle at account {:032x}", node.0)));
            }
            current = parents.get(&node).copied();
        }
        complete.extend(path);
    }
    Ok(ChartSnapshot {
        known_at,
        accounts,
        effectivity,
        parents,
        children,
        closing_routes,
        fx_revaluation_routes,
    })
}

// install_chart's existing canonical format: list(AccountSpec base fields),
// optionally list(code, lower?, upper?), optionally list(period-limit code).
// No new stored bytes and no reinterpretation of legacy lifetime limits.
fn decode_install(payload: &[u8]) -> Result<Vec<AccountSpec>, DecodeError> {
    let mut reader = Reader::new(payload);
    // Even an empty-name/code base row takes 20 bytes. Admission is bounded
    // by actual input size, not by an unrelated small-business chart limit.
    let mut accounts = reader.list(payload.len() / 20, "chart.accounts", |reader| {
        Ok(AccountSpec {
            code: reader.str(64, "account.code")?.to_string(),
            name: reader.str(payload.len(), "account.name")?.to_string(),
            account_type: reader.u8("account.type")?,
            normal_balance: reader.u8("account.normal_balance")?,
            is_leaf: reader.bool("account.is_leaf")?,
            unit_policy: {
                let value = reader.i64("account.unit_policy")?;
                UnitPolicy::from_mirror(value)
                    .ok_or_else(|| reader.invalid("account.unit_policy"))?
            },
            parent_code: reader.opt("account.parent", |reader| {
                Ok(reader.str(64, "account.parent_code")?.to_string())
            })?,
            limit: None,
        })
    })?;
    let mut by_code = BTreeMap::new();
    for (index, account) in accounts.iter().enumerate() {
        if by_code.insert(account.code.clone(), index).is_some() {
            return Err(reader.invalid("chart.duplicate_account"));
        }
    }
    if reader.remaining() != 0 {
        let count = reader.count(accounts.len(), "chart.limits")?;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let code = reader.str(64, "limit.account")?.to_string();
            let index = *by_code
                .get(&code)
                .ok_or_else(|| reader.invalid("limit.account"))?;
            if !seen.insert(index) {
                return Err(reader.invalid("chart.duplicate_limit"));
            }
            accounts[index].limit = Some(BalanceLimit {
                lower: reader.opt("limit.lower", |reader| reader.i128("limit.lower"))?,
                upper: reader.opt("limit.upper", |reader| reader.i128("limit.upper"))?,
                scope: LimitScope::Lifetime,
            });
        }
    }
    if reader.remaining() != 0 {
        let count = reader.count(accounts.len(), "chart.period_limits")?;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let code = reader.str(64, "period_limit.account")?.to_string();
            let index = *by_code
                .get(&code)
                .ok_or_else(|| reader.invalid("period_limit.account"))?;
            if !seen.insert(index) {
                return Err(reader.invalid("chart.duplicate_period_limit"));
            }
            let limit = accounts[index]
                .limit
                .as_mut()
                .ok_or_else(|| reader.invalid("period_limit.missing_limit"))?;
            limit.scope = LimitScope::Period;
        }
    }
    reader.finish()?;
    Ok(accounts)
}

pub(crate) fn encode_open_account(
    spec: &AccountSpec,
    opened: DateDay,
    closed: Option<DateDay>,
) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::new();
    w.str(&spec.code)
        .str(&spec.name)
        .u8(spec.account_type)
        .u8(spec.normal_balance)
        .bool(spec.is_leaf)
        .i64(spec.unit_policy.mirror())
        .opt(spec.parent_code.as_ref(), |w, parent| {
            w.str(parent);
        })
        .opt(spec.limit.as_ref(), |w, limit| {
            w.opt(limit.lower.as_ref(), |w, v| {
                w.i128(*v);
            })
            .opt(limit.upper.as_ref(), |w, v| {
                w.i128(*v);
            })
            .u8(match limit.scope {
                LimitScope::Lifetime => 0,
                LimitScope::Period => 1,
            });
        })
        .i32(opened.0)
        .opt(closed.as_ref(), |w, d| {
            w.i32(d.0);
        });
    w.finish()
}

fn decode_open_account(
    payload: &[u8],
) -> Result<(AccountSpec, DateDay, Option<DateDay>), DecodeError> {
    let mut r = Reader::new(payload);
    let spec = AccountSpec {
        code: r.str(64, "account.code")?.to_string(),
        name: r.str(payload.len(), "account.name")?.to_string(),
        account_type: r.u8("account.type")?,
        normal_balance: r.u8("account.normal_balance")?,
        is_leaf: r.bool("account.is_leaf")?,
        unit_policy: {
            let value = r.i64("account.unit_policy")?;
            UnitPolicy::from_mirror(value).ok_or_else(|| r.invalid("account.unit_policy"))?
        },
        parent_code: r.opt("account.parent", |r| {
            Ok(r.str(64, "account.parent_code")?.to_string())
        })?,
        limit: r.opt("account.limit", |r| {
            let lower = r.opt("limit.lower", |r| r.i128("limit.lower"))?;
            let upper = r.opt("limit.upper", |r| r.i128("limit.upper"))?;
            let scope = match r.u8("limit.scope")? {
                0 => LimitScope::Lifetime,
                1 => LimitScope::Period,
                tag => return Err(r.bad_tag("limit.scope", tag)),
            };
            Ok(BalanceLimit {
                lower,
                upper,
                scope,
            })
        })?,
    };
    let opened = DateDay(r.i32("account.opened")?);
    let closed = r.opt("account.closed", |r| Ok(DateDay(r.i32("account.closed")?)))?;
    r.finish()?;
    Ok((spec, opened, closed))
}

pub(crate) fn encode_close_account(code: &str, closed_on: DateDay) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::new();
    w.str(code).i32(closed_on.0);
    w.finish()
}

fn decode_close_account(payload: &[u8]) -> Result<(String, DateDay), DecodeError> {
    let mut r = Reader::new(payload);
    let code = r.str(64, "account.code")?.to_string();
    let closed_on = DateDay(r.i32("account.closed_on")?);
    r.finish()?;
    Ok((code, closed_on))
}

pub(crate) fn encode_promote_to_summary(
    code: &str,
    promotion_date: DateDay,
) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::new();
    w.str(code).i32(promotion_date.0);
    w.finish()
}

fn decode_promote_to_summary(payload: &[u8]) -> Result<(String, DateDay), DecodeError> {
    let mut r = Reader::new(payload);
    let code = r.str(64, "account.code")?.to_string();
    let promotion_date = DateDay(r.i32("account.promotion_date")?);
    r.finish()?;
    Ok((code, promotion_date))
}

/// Recorded outcome of a journaled chart lifecycle mutation (`open_account`,
/// `close_account`, or `promote_to_summary`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLifecycleRecorded {
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
    pub account_vid: VId,
    pub already_recorded: bool,
}

pub(crate) fn admit_schema_change<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    principal_ref: VId,
    capability: &Capability,
) -> Result<Option<Refusal>, KernelError> {
    if let Err(d) = fa_policy::admit_within(
        capability,
        &Intent {
            principal: principal_ref,
            trunk: true,
            op: Op::SchemaChange,
            book: book.book_id,
            legs: &[],
        },
        &Reach::whole_book(true),
        None,
    ) {
        return Ok(Some(crate::policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Some(crate::policy::refusal(&d)));
    }
    Ok(None)
}

pub(crate) fn schema_control_proposal(
    book: &BookContext,
    kind: u16,
    canonical_bytes: Vec<u8>,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> EntryPayload {
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SCHEMA_CONTROL,
        effective_date,
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::SchemaChange {
            kind,
            canonical_bytes,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::CHART_INSTALL,
            spec_body_digest: fgdb_crypto::hash(idempotency_key).0,
        },
        principal_ref,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

fn check_lifecycle_idempotency(
    book: &BookContext,
    row: &VertexRow,
    avid: VId,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
) -> Outcome<AccountLifecycleRecorded> {
    let stored = match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    let same = if &stored.proposal_digest == proposal_digest {
        true
    } else {
        match (
            stored.proposal.semantic_digest(&book.seal_key),
            proposal.semantic_digest(&book.seal_key),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    };
    if same {
        Ok(Ok(AccountLifecycleRecorded {
            recorded_at: row.created_at,
            control_entry: row.vid,
            account_vid: avid,
            already_recorded: true,
        }))
    } else {
        Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with different content; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical schema control to get the recorded outcome, or use a new idempotency key",
        )))
    }
}

/// Open a new account as a journaled `SchemaChange` (`kind = 2`) with an
/// explicit `opened` date and optional `closed` date (`[opened, closed)`,
/// plan §5.6, `FA-INV-01.account-effective`).
#[allow(clippy::too_many_arguments)]
pub async fn open_account<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &AccountSpec,
    opened: DateDay,
    closed: Option<DateDay>,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<AccountLifecycleRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if spec.code.is_empty() || spec.code.len() > 64 {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("account code `{}` must be 1..=64 bytes", spec.code),
            "Appendix A Account.code",
            "shorten the code",
        )));
    }
    if !AccountType(spec.account_type).is_registered() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "account `{}` has unregistered type {}",
                spec.code, spec.account_type
            ),
            "registries/account_types.toml",
            "use a registered account type tag (1 Asset … 7 Statistical)",
        )));
    }
    if spec.normal_balance > 1 {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "account `{}` has invalid normal_balance {}",
                spec.code, spec.normal_balance
            ),
            "Appendix A Account.normal_balance",
            "use 0 (Debit) or 1 (Credit)",
        )));
    }
    if let UnitPolicy::Single(unit) = spec.unit_policy
        && book.units.get(unit).is_none()
    {
        return Ok(Err(Refusal::new(
            code::UNIT_UNREGISTERED,
            exit::REFUSAL,
            format!(
                "account `{}` names unregistered unit id {}",
                spec.code, unit.0
            ),
            "plan §4.3, §4.4",
            "use a unit registered in the book",
        )));
    }
    if let Some(limit) = &spec.limit {
        let why = if !limit.is_well_formed() {
            Some("a balance limit names at least one bound, with lower ≤ upper")
        } else if !spec.is_leaf {
            Some("a balance limit belongs on a leaf (only leaves accept legs)")
        } else if !matches!(spec.unit_policy, UnitPolicy::Single(_)) {
            Some("a balance limit is stated in the account's single registered unit")
        } else {
            None
        };
        if let Some(why) = why {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!("account `{}`: {why}", spec.code),
                "plan §5.4–5.5 (balance limits)",
                "give the account one unit, make it a leaf, and name lower ≤ upper (or drop the limit)",
            )));
        }
    }
    let effectivity = AccountEffectivity {
        opened: Some(opened),
        closed,
        promoted_on: None,
    };
    if !effectivity.is_well_formed() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "account `{}` has invalid effective interval [opened: {opened}, closed: {closed:?})",
                spec.code
            ),
            "plan §4.3, §5.6 (half-open [opened, closed) requires opened < closed)",
            "set closed to None or a date strictly after opened",
        )));
    }
    let canonical_bytes =
        encode_open_account(spec, opened, closed).map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        2,
        canonical_bytes,
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let avid = account_vid(book.book_id, &spec.code);
    let existing_periods = if spec.limit.is_some_and(|l| l.scope == LimitScope::Period) {
        list_periods(db)?
    } else {
        Vec::new()
    };

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_lifecycle_idempotency(
            db_book_ref(book),
            &row,
            avid,
            &proposal,
            &proposal_digest,
        );
    }
    if txn.vertex(db, avid)?.is_some() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("account `{}` already exists in this book", spec.code),
            "plan §4.3, §5.6 (account codes are unique identities)",
            "use a distinct account code",
        )));
    }
    if let Some(parent_code) = &spec.parent_code {
        let parent_vid = account_vid(book.book_id, parent_code);
        let Some(parent_row) = txn.vertex(db, parent_vid)? else {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::UNKNOWN_ACCOUNT,
                exit::REFUSAL,
                format!(
                    "account `{}` names parent `{parent_code}` which does not exist in this book",
                    spec.code
                ),
                "plan §4.3, §5.6",
                "open the parent summary account first or drop parent_code",
            )));
        };
        if !parent_row.labels.contains(&label::ACCOUNT) {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::UNKNOWN_ACCOUNT,
                exit::REFUSAL,
                format!("parent `{parent_code}` is not an account vertex"),
                "plan §4.3, §5.6",
                "name an existing summary account",
            )));
        }
        let parent = AccountRow::decode(&parent_row)?;
        if parent.is_leaf {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::NOT_A_LEAF,
                exit::REFUSAL,
                format!(
                    "account `{}` names leaf `{parent_code}` as its parent; only summary accounts may have children",
                    spec.code
                ),
                "plan §4.3, §5.6 (only summaries have children)",
                "promote the parent to a summary first or choose a summary parent",
            )));
        }
    }

    let mut batch = WriteBatch::new(relation::CHILD_OF);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    let mut props = vec![
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("code", &spec.code)?),
        (property::NAME, scalar_text("name", &spec.name)?),
        (
            property::ACCOUNT_TYPE,
            CanonicalScalar::Int(i64::from(spec.account_type)),
        ),
        (
            property::NORMAL_BALANCE,
            CanonicalScalar::Int(i64::from(spec.normal_balance)),
        ),
        (
            property::POSTING,
            CanonicalScalar::Int(i64::from(spec.is_leaf)),
        ),
        (
            property::UNIT_POLICY,
            CanonicalScalar::Int(spec.unit_policy.mirror()),
        ),
    ];
    if let Some(eff_bytes) = effectivity
        .encode_payload()
        .map_err(fa_model::EntryError::from)?
    {
        props.push((
            property::FA_PAYLOAD,
            scalar_bytes("_fa_payload", eff_bytes)?,
        ));
    }
    if let Some(limit) = &spec.limit {
        props.extend(limit.props()?);
    }
    props.sort_by_key(|(k, _)| k.0);
    batch.create_vertex(avid, vec![label::ACCOUNT], props);
    match spec.limit.map(|l| l.scope) {
        None => {}
        Some(LimitScope::Lifetime) => {
            batch.create_vertex(
                limit_cell_vid(avid),
                vec![label::LIMIT_CELL],
                LimitCell::default().create_props(avid, None)?,
            );
        }
        Some(LimitScope::Period) => {
            for p in &existing_periods {
                batch.create_vertex(
                    period_cell_vid(avid, &p.code),
                    vec![label::LIMIT_CELL],
                    LimitCell::default().create_props(avid, Some(&p.code))?,
                );
            }
        }
    }
    if let Some(parent_code) = &spec.parent_code {
        let parent_vid = account_vid(book.book_id, parent_code);
        batch.add_edge(
            edge_id(relation::CHILD_OF, avid, parent_vid),
            avid,
            parent_vid,
            vec![],
        );
    }
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    let root = book_root();
    in_book.add_edge(edge_id(relation::IN_BOOK, avid, root), avid, root, vec![]);
    if let Err(e) = txn.write_ordered(db, vec![batch, in_book]) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(AccountLifecycleRecorded {
            recorded_at: seq,
            control_entry: evid,
            account_vid: avid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated open_account's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry open_account against the new frontier",
            )))
        }
        Err(e) => Err(e.into()),
    }
}

fn db_book_ref(book: &BookContext) -> &BookContext {
    book
}

#[deny(clippy::arithmetic_side_effects)]
fn close_balance_after(balance: i128, side: Side, magnitude: i128) -> Result<i128, KernelError> {
    let signed = match side {
        Side::Debit => magnitude,
        Side::Credit => magnitude.checked_neg().ok_or_else(|| {
            KernelError::Corrupt("account credit amount negation overflow".into())
        })?,
    };
    balance
        .checked_add(signed)
        .ok_or_else(|| KernelError::Corrupt("account balance overflow".into()))
}

/// Close an account at `closed_on` as a journaled `SchemaChange` (`kind = 3`,
/// plan §5.6, `FA-INV-01.account-effective`).
///
/// Refuses if:
/// - the account does not exist or is already closed,
/// - `closed_on` is not strictly after `opened` (or is before `promoted_on`),
/// - any committed leg on the account has `effective_date >= closed_on`,
/// - the account has an unresolved `Pending` hold,
/// - the account has a non-zero net posted balance in any unit, or
/// - the account participates in open-item settlements and has any unsettled
///   open items.
#[allow(clippy::too_many_arguments)]
pub async fn close_account<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    code_str: &str,
    closed_on: DateDay,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<AccountLifecycleRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if code_str.is_empty() || code_str.len() > 64 {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("account code `{code_str}` must be 1..=64 bytes"),
            "Appendix A Account.code",
            "provide a valid 1..=64 byte account code",
        )));
    }
    let canonical_bytes =
        encode_close_account(code_str, closed_on).map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        3,
        canonical_bytes,
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let avid = account_vid(book.book_id, code_str);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_lifecycle_idempotency(book, &row, avid, &proposal, &proposal_digest);
    }
    let Some(row) = txn.vertex(db, avid)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!("account `{code_str}` does not exist in this book"),
            "plan §4.3, §5.6",
            "fa chart list --json to inspect existing accounts",
        )));
    };
    if !row.labels.contains(&label::ACCOUNT) {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!("`{code_str}` is not an account vertex"),
            "plan §4.3, §5.6",
            "fa chart list --json to inspect existing accounts",
        )));
    }
    let _account = AccountRow::decode(&row)?;
    let mut eff = AccountEffectivity::decode_from_row(&row)?;
    if let Some(existing_close) = eff.closed {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!("account `{code_str}` is already closed on {existing_close}"),
            "plan §5.6 (an account may be closed once)",
            "inspect the chart snapshot or post to an open account",
        )));
    }
    eff.closed = Some(closed_on);
    if !eff.is_well_formed() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "account `{code_str}` cannot close on {closed_on} (opened: {:?}, promoted_on: {:?})",
                eff.opened, eff.promoted_on
            ),
            "plan §5.6 (half-open [opened, closed) requires opened < closed_on and promoted_on ≤ closed_on)",
            "choose a close date strictly after opened and on or after any promotion date",
        )));
    }

    // Check committed entries at txn.basis() for close preconditions.
    let basis = txn.basis();
    let snapshot_rows = db.vertices_at(basis)?;
    let mut all_entries: Vec<(VId, Entry)> = Vec::new();
    let mut resolved_holds: BTreeSet<VId> = BTreeSet::new();
    let mut reversed_targets: BTreeSet<VId> = BTreeSet::new();
    for vrow in &snapshot_rows {
        if !vrow.labels.contains(&label::ENTRY) {
            continue;
        }
        let e = Entry::decode(&bytes(vrow, property::FA_PAYLOAD, "entry.payload")?)?;
        if e.proposal.class == EntryClass::RESOLUTION
            && let Some(target) = e.proposal.pending.as_ref().and_then(|p| p.resolution_of)
        {
            resolved_holds.insert(target.vid);
        }
        if e.proposal.class == EntryClass::REVERSAL {
            for sup in &e.proposal.supersession {
                if sup.kind == fa_model::SupersessionKind::Reverses {
                    reversed_targets.insert(sup.target.vid);
                }
            }
        }
        all_entries.push((vrow.vid, e));
    }

    let mut net_balances: BTreeMap<UnitId, i128> = BTreeMap::new();
    let mut has_settlement_activity = false;
    let mut open_capacities: BTreeMap<(VId, u16), i128> = BTreeMap::new();
    let mut applied_in: BTreeMap<(VId, u16), i128> = BTreeMap::new();
    let mut runs = BTreeMap::new();

    for (vid, e) in &all_entries {
        let touches_account = e.proposal.legs.iter().any(|l| l.account_ref == avid);
        if !touches_account {
            continue;
        }
        if e.proposal.effective_date >= closed_on {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::NOT_A_LEAF,
                exit::REFUSAL,
                format!(
                    "cannot close account `{code_str}` on {closed_on}: entry {:032x} posts to `{code_str}` on {} (>= {closed_on})",
                    vid.0, e.proposal.effective_date
                ),
                "FA-INV-01.account-effective (plan §5.6: no leg may lie at or after closed_on)",
                "choose a close date strictly after all committed postings to this account, or reclassify later postings first",
            )));
        }
        if e.proposal.class == EntryClass::PENDING && !resolved_holds.contains(vid) {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::NOT_A_LEAF,
                exit::REFUSAL,
                format!(
                    "cannot close account `{code_str}`: pending hold {:032x} on `{code_str}` is unresolved",
                    vid.0
                ),
                "plan §5.4, §5.6 (an account with unresolved Pending holds cannot close)",
                "capture or void the pending hold before closing the account",
            )));
        }
        if e.proposal.class == EntryClass::PENDING || e.proposal.class.is_control() {
            continue;
        }
        if !crate::migration::visible_at(db, e, basis, &mut runs)? {
            continue;
        }
        for (idx, leg) in e.proposal.legs.iter().enumerate() {
            if leg.account_ref != avid {
                continue;
            }
            let bal = net_balances.entry(leg.amount.unit).or_insert(0);
            *bal = close_balance_after(*bal, leg.side, leg.amount.mantissa)?;

            if !leg.settles.is_empty() {
                has_settlement_activity = true;
            }
            if e.proposal.class.carries_open_items() && !reversed_targets.contains(vid) {
                let mut consumed: i128 = 0;
                for s in &leg.settles {
                    consumed = consumed
                        .checked_add(s.amount.mantissa)
                        .ok_or_else(|| KernelError::Corrupt("settlement overflow".into()))?;
                    let slot = applied_in.entry((s.target.vid, s.ordinal)).or_insert(0);
                    *slot = slot
                        .checked_add(s.amount.mantissa)
                        .ok_or_else(|| KernelError::Corrupt("settlement overflow".into()))?;
                }
                let cap = leg
                    .amount
                    .mantissa
                    .checked_sub(consumed)
                    .ok_or_else(|| KernelError::Corrupt("settlement underflow".into()))?;
                if let Ok(ord) = u16::try_from(idx) {
                    open_capacities.insert((*vid, ord), cap);
                }
            }
        }
    }

    for (unit, bal) in net_balances {
        if bal != 0 {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::NOT_A_LEAF,
                exit::REFUSAL,
                format!(
                    "cannot close account `{code_str}`: non-zero posted balance {bal} in unit {}",
                    unit.0
                ),
                "plan §5.6 (an account must have zero balance in every unit before closing)",
                "transfer or settle the remaining balance to zero before closing the account",
            )));
        }
    }

    if has_settlement_activity {
        for ((vid, ord), cap) in open_capacities {
            let applied = applied_in.get(&(vid, ord)).copied().unwrap_or(0);
            if cap > applied {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::NOT_A_LEAF,
                    exit::REFUSAL,
                    format!(
                        "cannot close account `{code_str}`: open item {:032x} leg {ord} has unsettled balance {}",
                        vid.0,
                        cap - applied
                    ),
                    "plan §5.6, §5.7 (an account with unsettled open items cannot close)",
                    "settle all open items on the account before closing it",
                )));
            }
        }
    }

    let witnessed_payload = txn.vertex_property(db, avid, property::FA_PAYLOAD)?;
    let new_payload = eff
        .encode_payload()
        .map_err(fa_model::EntryError::from)?
        .ok_or_else(|| KernelError::Corrupt("closed effectivity encoded empty".into()))?;
    let mut batch = WriteBatch::new(relation::CHILD_OF);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        avid,
        property::FA_PAYLOAD,
        witnessed_payload,
        scalar_bytes("_fa_payload", new_payload)?,
        WriteMismatchPolicy::AbortWrite,
    );
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(AccountLifecycleRecorded {
            recorded_at: seq,
            control_entry: evid,
            account_vid: avid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated close_account's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "re-verify the account's balance and retry close_account",
            )))
        }
        Err(e) => Err(e.into()),
    }
}

/// Promote a leaf account to a summary account at `promotion_date` as a
/// journaled `SchemaChange` (`kind = 4`, plan §5.6).
///
/// Refuses if:
/// - the account does not exist or is already a summary account,
/// - the account carries a balance limit (only leaves carry balance limits),
/// - `promotion_date` lies outside the account's `[opened, closed)` interval, or
/// - any committed entry has a leg on the account with
///   `effective_date > promotion_date` (naming the exact blocking `Entry` `VId`s).
#[allow(clippy::too_many_arguments)]
pub async fn promote_to_summary<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    code_str: &str,
    promotion_date: DateDay,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<AccountLifecycleRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if code_str.is_empty() || code_str.len() > 64 {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("account code `{code_str}` must be 1..=64 bytes"),
            "Appendix A Account.code",
            "provide a valid 1..=64 byte account code",
        )));
    }
    let canonical_bytes =
        encode_promote_to_summary(code_str, promotion_date).map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        4,
        canonical_bytes,
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let avid = account_vid(book.book_id, code_str);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_lifecycle_idempotency(book, &row, avid, &proposal, &proposal_digest);
    }
    let Some(row) = txn.vertex(db, avid)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!("account `{code_str}` does not exist in this book"),
            "plan §4.3, §5.6",
            "fa chart list --json to inspect existing accounts",
        )));
    };
    if !row.labels.contains(&label::ACCOUNT) {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!("`{code_str}` is not an account vertex"),
            "plan §4.3, §5.6",
            "fa chart list --json to inspect existing accounts",
        )));
    }
    let account = AccountRow::decode(&row)?;
    let mut eff = AccountEffectivity::decode_from_row(&row)?;
    if !account.is_leaf {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!("account `{code_str}` is already a summary account"),
            "plan §5.6 (promote_to_summary applies only to a leaf account)",
            "account is already a summary",
        )));
    }
    if crate::subledger::account_binding(&txn, db, book, &row)?.is_some() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!("native subledger control account '{code_str}' must remain a posting leaf"),
            "plan §5.6 (native subledger detail belongs to one control leaf)",
            "keep this control leaf and create a separate summary parent",
        )));
    }
    if account.limit.is_some() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "account `{code_str}` carries a balance limit and cannot be promoted to a summary"
            ),
            "plan §5.4–5.6 (only leaf accounts carry balance limits)",
            "promote an account without a balance limit",
        )));
    }
    eff.promoted_on = Some(promotion_date);
    if !eff.is_well_formed() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "account `{code_str}` cannot be promoted on {promotion_date} outside [opened: {:?}, closed: {:?}]",
                eff.opened, eff.closed
            ),
            "plan §5.6 (promotion_date must lie within [opened, closed])",
            "choose a promotion_date on or after opened and on or before closed",
        )));
    }

    let basis = txn.basis();
    let snapshot_rows = db.vertices_at(basis)?;
    let mut blocking_entries: Vec<(VId, DateDay)> = Vec::new();
    for vrow in &snapshot_rows {
        if !vrow.labels.contains(&label::ENTRY) {
            continue;
        }
        let e = Entry::decode(&bytes(vrow, property::FA_PAYLOAD, "entry.payload")?)?;
        if e.proposal.effective_date > promotion_date
            && e.proposal.legs.iter().any(|l| l.account_ref == avid)
        {
            blocking_entries.push((vrow.vid, e.proposal.effective_date));
        }
    }
    if !blocking_entries.is_empty() {
        blocking_entries.sort_by_key(|(vid, day)| (*day, *vid));
        let formatted: Vec<String> = blocking_entries
            .iter()
            .map(|(vid, day)| format!("{:032x}@{}", vid.0, day))
            .collect();
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!(
                "cannot promote `{code_str}` to summary on {promotion_date}: committed entries [{}] post to `{code_str}` after {promotion_date}",
                formatted.join(", ")
            ),
            "plan §5.6 (promote_to_summary requires no postings after promotion_date)",
            "open a child leaf account and reclassify postings after promotion_date to that child leaf first, or choose a later promotion_date",
        )));
    }

    let witnessed_posting = txn.vertex_property(db, avid, property::POSTING)?;
    let witnessed_payload = txn.vertex_property(db, avid, property::FA_PAYLOAD)?;
    let new_payload = eff
        .encode_payload()
        .map_err(fa_model::EntryError::from)?
        .ok_or_else(|| KernelError::Corrupt("promoted effectivity encoded empty".into()))?;
    let mut batch = WriteBatch::new(relation::CHILD_OF);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        avid,
        property::POSTING,
        witnessed_posting,
        CanonicalScalar::Int(0),
        WriteMismatchPolicy::AbortWrite,
    );
    batch.compare_and_set_vertex_property(
        avid,
        property::FA_PAYLOAD,
        witnessed_payload,
        scalar_bytes("_fa_payload", new_payload)?,
        WriteMismatchPolicy::AbortWrite,
    );
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(AccountLifecycleRecorded {
            recorded_at: seq,
            control_entry: evid,
            account_vid: avid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated promote_to_summary's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "re-verify the account's postings and retry promote_to_summary",
            )))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::Writer;
    use fa_money::UnitId;

    const BOOK: Id128 = Id128([0x42; 16]);

    fn account(code: &str, parent: Option<&str>, leaf: bool) -> AccountSpec {
        AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: leaf,
            unit_policy: UnitPolicy::Single(UnitId(1)),
            parent_code: parent.map(str::to_string),
            limit: None,
        }
    }

    fn forest(accounts: Vec<AccountSpec>) -> Result<ChartSnapshot, KernelError> {
        assemble(
            BOOK,
            CommitSeq(5),
            accounts.into_iter().map(|a| (a, CommitSeq(2))).collect(),
        )
    }

    #[test]
    fn account_close_balance_checks_signed_boundaries() {
        // A valid sequence may reach MIN and return to zero. Preserve that
        // domain while rejecting an overflowing prefix, even if later legs
        // would make the final balance representable again.
        let balance = close_balance_after(0, Side::Credit, i128::MAX).unwrap();
        let balance = close_balance_after(balance, Side::Credit, 1).unwrap();
        assert_eq!(balance, i128::MIN);
        assert!(matches!(
            close_balance_after(balance, Side::Credit, 1),
            Err(KernelError::Corrupt(message)) if message == "account balance overflow"
        ));
        let balance = close_balance_after(balance, Side::Debit, i128::MAX).unwrap();
        assert_eq!(close_balance_after(balance, Side::Debit, 1).unwrap(), 0);

        // A corrupt supplied magnitude must never panic before the checked
        // fold has a chance to report its typed foundation error.
        assert!(matches!(
            close_balance_after(0, Side::Credit, i128::MIN),
            Err(KernelError::Corrupt(message)) if message == "account credit amount negation overflow"
        ));
    }

    // Independent encoding of the documented base layout, not the reader's
    // inverse. Persisted CLI tests additionally exercise install_chart itself.
    fn wire(accounts: &[AccountSpec]) -> Writer {
        let mut w = Writer::new();
        w.list(accounts, |w, a| {
            w.str(&a.code)
                .str(&a.name)
                .u8(a.account_type)
                .u8(a.normal_balance)
                .bool(a.is_leaf)
                .i64(a.unit_policy.mirror())
                .opt(a.parent_code.as_ref(), |w, parent| {
                    w.str(parent);
                });
        });
        w
    }

    #[test]
    fn subtree_membership_uses_parentage_not_codes_and_never_includes_summaries() {
        let chart = forest(vec![
            account("assets", None, false),
            account("nested", Some("assets"), false),
            account("cash", Some("nested"), true),
            account("receivable", Some("assets"), true),
            account("assets-looking-but-unrelated", None, true),
            account("empty", None, false),
        ])
        .unwrap();
        assert_eq!(chart.known_at(), CommitSeq(5));
        assert_eq!(
            chart.leaves_under(account_vid(BOOK, "assets")).unwrap(),
            BTreeSet::from([account_vid(BOOK, "cash"), account_vid(BOOK, "receivable")])
        );
        assert_eq!(
            chart.leaves_under(account_vid(BOOK, "cash")).unwrap(),
            BTreeSet::from([account_vid(BOOK, "cash")])
        );
        assert!(
            chart
                .leaves_under(account_vid(BOOK, "empty"))
                .unwrap()
                .is_empty()
        );
        assert!(chart.leaves_under(account_vid(BOOK, "absent")).is_err());
        assert_eq!(
            chart.parents()[&account_vid(BOOK, "cash")],
            account_vid(BOOK, "nested")
        );
    }

    #[test]
    fn duplicate_or_missing_accounts_leaf_parents_and_cycles_are_refused() {
        for definitions in [
            vec![account("a", None, true), account("a", None, true)],
            vec![account("a", Some("missing"), true)],
            vec![account("a", None, true), account("b", Some("a"), true)],
            vec![account("a", Some("a"), false)],
            vec![
                account("a", Some("b"), false),
                account("b", Some("a"), false),
            ],
        ] {
            assert!(forest(definitions).is_err());
        }
        assert!(
            assemble(
                BOOK,
                CommitSeq(1),
                vec![(account("late", None, true), CommitSeq(2))]
            )
            .is_err()
        );
    }

    #[test]
    fn deep_forests_are_iterative_and_input_order_independent() {
        let mut accounts = vec![account("0", None, false)];
        for n in 1..2048 {
            accounts.push(account(
                &n.to_string(),
                Some(&(n - 1).to_string()),
                n == 2047,
            ));
        }
        let first = forest(accounts.clone()).unwrap();
        accounts.reverse();
        let second = forest(accounts).unwrap();
        let root = account_vid(BOOK, "0");
        assert_eq!(
            first.leaves_under(root).unwrap(),
            BTreeSet::from([account_vid(BOOK, "2047")])
        );
        assert_eq!(
            first.leaves_under(root).unwrap(),
            second.leaves_under(root).unwrap()
        );
    }

    #[test]
    fn installed_chart_codec_retains_lifetime_and_period_limits() {
        let accounts = vec![
            account("summary", None, false),
            account("cash", Some("summary"), true),
        ];
        let raw = wire(&accounts).finish().unwrap();
        assert_eq!(decode_install(&raw).unwrap(), accounts);
        for scope in [LimitScope::Lifetime, LimitScope::Period] {
            let mut w = wire(&accounts);
            w.u32(1)
                .str("cash")
                .u8(1)
                .i128(i128::MIN)
                .u8(1)
                .i128(i128::MAX);
            if scope == LimitScope::Period {
                w.u32(1).str("cash");
            }
            let mut expected = accounts.clone();
            expected[1].limit = Some(BalanceLimit {
                lower: Some(i128::MIN),
                upper: Some(i128::MAX),
                scope,
            });
            assert_eq!(decode_install(&w.finish().unwrap()).unwrap(), expected);
        }
        for end in 0..raw.len() {
            assert!(
                decode_install(&raw[..end]).is_err(),
                "truncated base at {end}"
            );
        }
        let mut trailing = raw;
        trailing.push(0xff);
        assert!(decode_install(&trailing).is_err());
    }

    #[test]
    fn malformed_optional_limit_lists_do_not_reassign_policy() {
        let accounts = vec![account("cash", None, true)];
        let mut duplicate = wire(&accounts);
        duplicate
            .u32(2)
            .str("cash")
            .u8(1)
            .i128(0)
            .u8(0)
            .str("cash")
            .u8(1)
            .i128(1)
            .u8(0);
        assert!(decode_install(&duplicate.finish().unwrap()).is_err());
        let mut unknown = wire(&accounts);
        unknown.u32(1).str("other").u8(1).i128(0).u8(0);
        assert!(decode_install(&unknown.finish().unwrap()).is_err());
        let mut unbounded = wire(&accounts);
        unbounded.u32(0).u32(1).str("cash");
        assert!(decode_install(&unbounded.finish().unwrap()).is_err());
    }
}
