use std::collections::BTreeSet;

use super::*;
use fa_journal::refusal::code;

fn role(
    h: &mut Harness,
    account: VId,
    role: &str,
    assigned: bool,
    key: &[u8],
    salt: u8,
    ops: &[&str],
) -> Result<AccountRoleRecorded, Refusal> {
    let cx = h.ctx();
    let description = Erasable::seal(
        &"account role".to_string(),
        None,
        &h.book.seal_key,
        [salt; 32],
        [salt; 24],
    );
    let spec = AccountRoleSpec {
        account,
        role: role.into(),
        assigned,
    };
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &cx,
            &h.book,
            &spec,
            PRINCIPAL,
            key,
            description,
            &Capability::embedded(PRINCIPAL, ops).unwrap(),
        ))
        .unwrap()
}

const SCHEMA: &[&str] = &["schema_change"];

/// A role is one immutable control; the roles at a prefix are the fold of
/// the controls recorded by then, the latest per (account, role) deciding.
#[test]
fn a_role_is_journaled_folded_at_its_prefix_and_retried_exactly() {
    let mut h = harness();
    let before = h.db.frontier().unwrap();
    let cash = h.cash;
    let first = role(&mut h, cash, "suspense", true, b"role-1", 1, SCHEMA).unwrap();
    assert!(!first.already_recorded);
    let at = first.control.recorded_at;
    assert!(
        !account_roles_at(&h.db, &h.book, before)
            .unwrap()
            .holds(cash, "suspense")
    );
    let roles = account_roles_at(&h.db, &h.book, at).unwrap();
    assert!(roles.holds(cash, "suspense"));
    assert_eq!(roles.accounts_with("suspense"), BTreeSet::from([cash]));
    assert!(roles.accounts_with("intercompany").is_empty());
    assert_eq!(roles.controls(cash, "suspense"), 1);
    assert!(fa_journal::chart::read_at(&h.db, &h.book, at).is_ok());

    // An exact retry, its description sealed afresh, is the recorded control.
    let retry = role(&mut h, cash, "suspense", true, b"role-1", 2, SCHEMA).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control, first.control);
    // The same state under another key writes nothing either.
    let again = role(&mut h, cash, "suspense", true, b"role-2", 3, SCHEMA).unwrap();
    assert!(again.already_recorded);
    assert_eq!(again.control, first.control);
    assert_eq!(h.db.frontier().unwrap(), at);
    // The same key with other content is a conflict.
    let receivable = h.receivable;
    let conflict = role(&mut h, receivable, "suspense", true, b"role-1", 4, SCHEMA).unwrap_err();
    assert_eq!(
        (conflict.code, conflict.exit),
        (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
    );

    // Removal, then assignment again: the latest control decides, and the
    // earlier prefix still reads the role as it stood then.
    let removed = role(&mut h, cash, "suspense", false, b"role-3", 5, SCHEMA).unwrap();
    assert!(!removed.already_recorded);
    let roles = account_roles_at(&h.db, &h.book, removed.control.recorded_at).unwrap();
    assert!(!roles.holds(cash, "suspense"));
    assert_eq!(roles.controls(cash, "suspense"), 2);
    assert!(
        account_roles_at(&h.db, &h.book, at)
            .unwrap()
            .holds(cash, "suspense")
    );
    let back = role(&mut h, cash, "suspense", true, b"role-4", 6, SCHEMA).unwrap();
    let roles = account_roles_at(&h.db, &h.book, back.control.recorded_at).unwrap();
    assert!(roles.holds(cash, "suspense"));
    assert_eq!(roles.controls(cash, "suspense"), 3);
    assert_eq!(roles.assigned().count(), 1);
    assert!(fa_journal::chart::read_at(&h.db, &h.book, back.control.recorded_at).is_ok());
}

/// Planted: an unregistered role, a type the role does not admit, a summary,
/// an absent account, removing a role not held, and a capability without
/// schema_change are each refused, and nothing is written.
#[test]
fn a_role_the_registry_or_the_account_does_not_admit_is_refused_and_writes_nothing() {
    let mut h = harness();
    let head = h.db.frontier().unwrap();
    let missing = account_vid(h.book.book_id, "9999");
    let cases = [
        (
            h.cash,
            "revenue",
            true,
            SCHEMA,
            "is not a registered account role",
        ),
        (
            h.rent,
            "suspense",
            true,
            SCHEMA,
            "admits Asset or Liability",
        ),
        (h.revenue, "intercompany", true, SCHEMA, "is Revenue"),
        (h.assets, "suspense", true, SCHEMA, "is a summary"),
        (missing, "suspense", true, SCHEMA, "does not exist"),
        (h.cash, "suspense", false, SCHEMA, "nothing to remove"),
    ];
    for (salt, (account, name, assigned, ops, expected)) in (10u8..).zip(cases) {
        let refusal = role(&mut h, account, name, assigned, b"planted", salt, ops).unwrap_err();
        assert!(
            refusal.message.contains(expected),
            "{expected}: {refusal:?}"
        );
        assert_eq!(h.db.frontier().unwrap(), head, "{expected}");
    }
    let cash = h.cash;
    let unauthorized = role(&mut h, cash, "suspense", true, b"read-only", 9, &["read"]);
    assert!(unauthorized.is_err(), "{unauthorized:?}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        account_roles_at(&h.db, &h.book, head)
            .unwrap()
            .assigned()
            .next()
            .is_none()
    );
}
