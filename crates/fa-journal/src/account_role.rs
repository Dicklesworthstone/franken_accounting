//! Account roles (bead fa-kxc4): what an account is for, independently of
//! its code and name.
//!
//! A role is assigned to, or removed from, one posting leaf by an immutable
//! schema control. The roles held at a recorded prefix are the fold of those
//! controls in recorded order: for each (account, role), the latest control
//! decides. Nothing else stores a role, so a register, a report or a Lantern
//! population can only read it back from the journal. Admitted roles and the
//! account types each admits are `registries/account_roles.toml`.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property};
use fa_model::{
    AccountType, ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload,
    EntryRef, Erasable, Id128, Reader, Writer, entry_mirrors, entry_vid,
};
use fa_policy::Capability;
use fa_registry::account_roles::{AccountRoles as RoleRegistry, MAX_ROLE_NAME};
use fa_time::DateDay;
use fgdb::{Database, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::chart::{admit_schema_change, schema_control_proposal};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, bytes};

pub const SCHEMA_CHANGE_ACCOUNT_ROLE: u16 = 16;
const FORMAT: &[u8] = b"fa:account-role:v1";

/// One role control's canonical body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRoleSpec {
    pub account: VId,
    pub role: String,
    /// True assigns the role; false removes it.
    pub assigned: bool,
}

impl AccountRoleSpec {
    fn valid(&self) -> bool {
        !self.role.is_empty() && self.role.len() <= MAX_ROLE_NAME
    }

    pub fn encode(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(FORMAT)
            .u128(self.account.0)
            .str(&self.role)
            .bool(self.assigned);
        w.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        if r.fixed::<{ FORMAT.len() }>("account role format")
            .map_err(bad)?
            .as_slice()
            != FORMAT
        {
            return Err(corrupt("unknown account role encoding"));
        }
        let account = VId(r.u128("role account").map_err(bad)?);
        let role = r.str(MAX_ROLE_NAME, "role name").map_err(bad)?.to_string();
        let assigned = r.bool("role assigned").map_err(bad)?;
        r.finish().map_err(bad)?;
        let spec = Self {
            account,
            role,
            assigned,
        };
        if !spec.valid() {
            return Err(corrupt("empty role name"));
        }
        Ok(spec)
    }
}

/// A recorded role control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRoleControl {
    pub spec: AccountRoleSpec,
    pub entry: EntryRef,
    pub recorded_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRoleRecorded {
    pub control: AccountRoleControl,
    /// True when nothing was written: an identical retry, or the account
    /// already held (or already lacked) the role; `control` is then the
    /// control that set that state.
    pub already_recorded: bool,
}

/// The roles held at one recorded prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountRoles {
    /// The latest control for each (account, role).
    latest: BTreeMap<(VId, String), AccountRoleControl>,
    /// How many controls name each (account, role).
    controls: BTreeMap<(VId, String), u32>,
}

impl AccountRoles {
    /// Fold role controls in recorded order. Entries that are not role
    /// controls are skipped, so a caller may pass every entry of a prefix.
    pub fn fold<'a>(
        entries: impl IntoIterator<Item = (VId, &'a Entry, CommitSeq)>,
    ) -> Result<Self, KernelError> {
        let mut found = Vec::new();
        for (vid, entry, recorded_at) in entries {
            let Some(ControlPayload::SchemaChange {
                kind: SCHEMA_CHANGE_ACCOUNT_ROLE,
                canonical_bytes,
            }) = &entry.proposal.control
            else {
                continue;
            };
            if entry.proposal.class != EntryClass::SCHEMA_CONTROL
                || entry.proposal.branch_id != Id128::TRUNK
                || !entry.proposal.legs.is_empty()
                || !matches!(
                    entry.proposal.origin,
                    EntryOrigin::Control {
                        control_kind: ControlKind::CHART_INSTALL,
                        ..
                    }
                )
            {
                return Err(corrupt(
                    "a role control has another class, branch or origin",
                ));
            }
            found.push(AccountRoleControl {
                spec: AccountRoleSpec::decode(canonical_bytes)?,
                entry: entry.entry_ref(vid),
                recorded_at,
            });
        }
        found.sort_by_key(|c| (c.recorded_at, c.entry.vid));
        let mut roles = Self::default();
        for control in found {
            let pair = (control.spec.account, control.spec.role.clone());
            *roles.controls.entry(pair.clone()).or_default() += 1;
            roles.latest.insert(pair, control);
        }
        Ok(roles)
    }

    /// Whether `account` holds `role`.
    #[must_use]
    pub fn holds(&self, account: VId, role: &str) -> bool {
        self.latest
            .get(&(account, role.to_string()))
            .is_some_and(|c| c.spec.assigned)
    }

    /// The accounts holding `role`.
    #[must_use]
    pub fn accounts_with(&self, role: &str) -> BTreeSet<VId> {
        self.latest
            .values()
            .filter(|c| c.spec.assigned && c.spec.role == role)
            .map(|c| c.spec.account)
            .collect()
    }

    /// Every role held, as the control that assigned it, by account then role.
    pub fn assigned(&self) -> impl Iterator<Item = &AccountRoleControl> {
        self.latest.values().filter(|c| c.spec.assigned)
    }

    /// The control that last set (account, role), assigned or removed.
    #[must_use]
    pub fn latest(&self, account: VId, role: &str) -> Option<&AccountRoleControl> {
        self.latest.get(&(account, role.to_string()))
    }

    /// How many controls name (account, role): a fresh default key per change.
    #[must_use]
    pub fn controls(&self, account: VId, role: &str) -> u32 {
        self.controls
            .get(&(account, role.to_string()))
            .copied()
            .unwrap_or_default()
    }
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("account role: {}", message.into()))
}

/// The roles held at `at`, folded from the journal's role controls. Every
/// role names an Account of this book at that prefix.
pub fn account_roles_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<AccountRoles, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    let rows = db.vertices_at(at)?;
    let accounts: BTreeSet<VId> = rows
        .iter()
        .filter(|row| row.labels.contains(&label::ACCOUNT))
        .map(|row| row.vid)
        .collect();
    let mut entries = Vec::new();
    for row in &rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "entry payload")?)?;
        if !matches!(
            &entry.proposal.control,
            Some(ControlPayload::SchemaChange {
                kind: SCHEMA_CHANGE_ACCOUNT_ROLE,
                ..
            })
        ) {
            continue;
        }
        if entry.proposal.book_id != book.book_id || entry_mirrors(&entry)? != row.props {
            return Err(corrupt("a role control's book or mirrors differ"));
        }
        entries.push((row.vid, entry, row.created_at));
    }
    let roles = AccountRoles::fold(entries.iter().map(|(v, e, s)| (*v, e, *s)))?;
    if roles
        .latest
        .keys()
        .any(|(account, _)| !accounts.contains(account))
    {
        return Err(corrupt("a role names an account the book does not hold"));
    }
    Ok(roles)
}

/// The sealed role control `record_account_role` journals for `spec`: one
/// book-scoped SchemaControl with no legs, under the idempotency `key`.
pub fn role_control(
    book: &BookContext,
    spec: &AccountRoleSpec,
    principal: VId,
    key: &[u8],
    description: Erasable<String>,
) -> Result<(EntryPayload, Entry), KernelError> {
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_ACCOUNT_ROLE,
        spec.encode()?,
        principal,
        DateDay(0),
        key,
        description,
    );
    let entry = proposal.clone().seal(Vec::new(), None)?;
    Ok((proposal, entry))
}

fn usage_refusal(message: String, fix: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "registries/account_roles.toml (fa-kxc4)",
        fix,
    )
}

/// Assign `spec.role` to `spec.account`, or remove it, under current
/// whole-book SchemaChange authority. The role must be registered and admit
/// the account's type, and the account must be a posting leaf. An account
/// that already holds (or already lacks) the role writes nothing.
#[allow(clippy::too_many_arguments)]
pub async fn record_account_role<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &AccountRoleSpec,
    principal: VId,
    key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<AccountRoleRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal, capability)? {
        return Ok(Err(refusal));
    }
    let registry = RoleRegistry::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let Some(role) = registry.get(&spec.role) else {
        return Ok(Err(usage_refusal(
            format!("`{}` is not a registered account role", spec.role),
            format!("name one of: {}", registry.listing()),
        )));
    };
    let (proposal, entry) = role_control(book, spec, principal, key, description)?;
    let evid = entry_vid(book.book_id, &principal.0.to_le_bytes(), key);
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        let stored = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry payload")?)?;
        if stored.proposal.semantic_digest(&book.seal_key)?
            != proposal.semantic_digest(&book.seal_key)?
        {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "this idempotency key already records different content",
                "FA-INV-09",
                "retry the original role change or use a new key",
            )));
        }
        // The recorded control itself, even if a later one on the pair has
        // since changed the role.
        let Some(ControlPayload::SchemaChange {
            kind: SCHEMA_CHANGE_ACCOUNT_ROLE,
            canonical_bytes,
        }) = &stored.proposal.control
        else {
            return Err(corrupt("the retried key records another control"));
        };
        return Ok(Ok(AccountRoleRecorded {
            control: AccountRoleControl {
                spec: AccountRoleSpec::decode(canonical_bytes)?,
                entry: stored.entry_ref(evid),
                recorded_at: row.created_at,
            },
            already_recorded: true,
        }));
    }
    let Some(account) = txn.vertex(db, spec.account)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            "the account does not exist",
            "plan §4.3 (the chart of accounts)",
            "name an account of this book's chart (fa chart list)",
        )));
    };
    if !account.labels.contains(&label::ACCOUNT) {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            "the reference does not name an Account",
            "plan §4.3 (the chart of accounts)",
            "name an account of this book's chart (fa chart list)",
        )));
    }
    let decoded = AccountRow::decode(&account)?;
    if !decoded.is_leaf {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!(
                "account `{}` is a summary; a role selects the legs of posting leaves",
                decoded.code
            ),
            "plan §4.3 (only leaves accept legs)",
            "assign the role to each posting leaf under it",
        )));
    }
    let type_name = AccountType(decoded.account_type).name().unwrap_or("?");
    if spec.assigned && !role.admits(type_name) {
        txn.abort();
        return Ok(Err(usage_refusal(
            format!(
                "role `{}` admits {} accounts; `{}` is {type_name}",
                role.name,
                role.account_types.join(" or "),
                decoded.code
            ),
            "assign the role to an account of an admitted type",
        )));
    }
    let roles = account_roles_at(db, book, txn.basis())?;
    match roles.latest(spec.account, &spec.role) {
        Some(latest) if latest.spec.assigned == spec.assigned => {
            txn.abort();
            return Ok(Ok(AccountRoleRecorded {
                control: latest.clone(),
                already_recorded: true,
            }));
        }
        None if !spec.assigned => {
            txn.abort();
            return Ok(Err(usage_refusal(
                format!(
                    "account `{}` does not hold role `{}`; there is nothing to remove",
                    decoded.code, spec.role
                ),
                "fa chart roles lists the roles each account holds",
            )));
        }
        _ => {}
    }
    let mut batch = WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return Err(error.into());
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(AccountRoleRecorded {
            control: AccountRoleControl {
                spec: spec.clone(),
                entry: entry.entry_ref(evid),
                recorded_at,
            },
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("an account role witness changed: {detail}"),
                "FG-LAW-FCW-01",
                "retry against the current frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "an account role control collided on a derived identity",
            "FA-INV-09",
            "inspect the recorded role control and retry its original key",
        ))),
        Err(error) => Err(error.into()),
    }
}
