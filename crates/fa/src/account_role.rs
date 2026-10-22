//! Account roles (bead fa-kxc4): journaled per-account roles, read back as
//! the fold of their controls at a recorded prefix.

use asupersync::fs::Vfs;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, Outcome};

pub use fa_journal::account_role::{
    AccountRoleControl, AccountRoleRecorded, AccountRoleSpec, AccountRoles,
};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Assign or remove one account role under SchemaChange authority.
    pub async fn record_account_role(
        &mut self,
        cx: &PurposeContexts,
        spec: &AccountRoleSpec,
        principal: VId,
        key: &[u8],
        capability: &Capability,
    ) -> Outcome<AccountRoleRecorded> {
        let verb = if spec.assigned { "assign" } else { "remove" };
        let description = self.seal_text(cx, &format!("{verb} account role {}", spec.role))?;
        Ok(fa_journal::account_role::record_account_role(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            key,
            description,
            capability,
        )
        .await?)
    }

    /// The roles held at `known_at` (the head when `None`) under current
    /// whole-book read authority, with the prefix they were read at.
    pub fn account_roles(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<(CommitSeq, AccountRoles)> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok((at, fa_journal::account_roles_at(db, book, at)?)))
        })
    }
}
