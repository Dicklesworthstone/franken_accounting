//! Account roles (bead fa-kxc4): `fa chart role <account> <role> [--remove]`
//! journals one role control, and `fa chart roles` lists every registered
//! role with the accounts holding it at a recorded prefix. Lantern selects
//! a role-selected procedure's population from these roles, never from an
//! account's code or name.

use std::collections::BTreeMap;

use fa::account_role::{AccountRoleControl, AccountRoleSpec};
use fa_model::account_vid;
use fa_registry::account_roles::AccountRoles as RoleRegistry;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, known_at_read_flag, usage};
use crate::json::{Json, obj, s};

const ROLE: &str = "fa chart role <account> <role> [--remove] [--key K]";

fn registry() -> Result<RoleRegistry, Fail> {
    RoleRegistry::embedded().map_err(|e| Fail::Internal(e.to_string()))
}

/// The idempotency key of a role control a chart import or account open
/// records under its own key `parent`: `plain` (the parent key extended with
/// the account and role) while it fits the model's key limit, else a digest
/// of `(parent, code, role)`, so a long role name or `--key` never makes the
/// role unrecordable. Either way a retried import or open records nothing
/// new.
pub(crate) fn seeded_role_key(plain: Vec<u8>, parent: &[u8], code: &str, role: &str) -> Vec<u8> {
    if plain.len() <= fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES {
        return plain;
    }
    let digest = fa_model::domain_digest(
        b"fa:seeded-role-key:v1",
        &[parent, code.as_bytes(), role.as_bytes()],
    );
    format!("role:{}", crate::cli::hex(&digest[..16])).into_bytes()
}

/// One `account_role` object (verbs.toml shape).
pub(crate) fn account_role_json(control: &AccountRoleControl, code: &str) -> Json {
    obj(vec![
        ("account", s(code)),
        ("account_vid", s(format!("{:032x}", control.spec.account.0))),
        ("role", s(&control.spec.role)),
        ("assigned", Json::Bool(control.spec.assigned)),
        ("control_entry", s(format!("{:032x}", control.entry.vid.0))),
        ("recorded_at", Json::Int(i128::from(control.recorded_at.0))),
    ])
}

/// The `"roles": ["suspense", …]` a chart document's accounts carry, as
/// `(code, role)` pairs in document order, checked before anything is
/// installed: each role is registered and admits its account's type, and the
/// account is a posting leaf, so the install never leaves a role refused.
pub(crate) fn chart_roles(
    path: &str,
    text: &str,
    accounts: &[fa_journal::AccountSpec],
) -> Result<Vec<(String, String)>, Fail> {
    let doc = crate::cli::parse_json(path, text)?;
    let rows = doc
        .get("accounts")
        .and_then(Json::as_arr)
        .unwrap_or_default();
    let registry = registry()?;
    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(value) = row.get("roles") else {
            continue;
        };
        let what = format!("accounts[{i}].roles");
        let names = value.as_arr().ok_or_else(|| {
            usage(
                format!("{what} must be an array of role names"),
                "\"roles\": [\"suspense\"] (fa chart roles --json lists the registered roles)",
            )
        })?;
        let spec = accounts.get(i).ok_or_else(|| {
            Fail::Internal(format!(
                "{what}: the chart parser and its accounts disagree"
            ))
        })?;
        for name in names {
            let Some(name) = name.as_str() else {
                return Err(usage(
                    format!("{what} holds a non-string"),
                    "\"roles\": [\"suspense\"]",
                ));
            };
            let Some(role) = registry.get(name) else {
                return Err(usage(
                    format!("{what}: `{name}` is not a registered account role"),
                    format!("name one of: {}", registry.listing()),
                ));
            };
            let type_name = fa_model::AccountType(spec.account_type)
                .name()
                .unwrap_or("?");
            if !spec.is_leaf || !role.admits(type_name) {
                return Err(usage(
                    format!(
                        "{what}: role `{name}` needs a posting leaf of type {}; `{}` is a {} {type_name} account",
                        role.account_types.join(" or "),
                        spec.code,
                        if spec.is_leaf { "leaf" } else { "summary" },
                    ),
                    "assign the role to a posting leaf of an admitted type",
                ));
            }
            if out.contains(&(spec.code.clone(), name.to_string())) {
                return Err(usage(
                    format!("{what}: `{name}` is listed twice"),
                    "list each role once per account",
                ));
            }
            out.push((spec.code.clone(), name.to_string()));
        }
    }
    Ok(out)
}

/// `fa chart role <account> <role> [--remove] [--key K]`.
pub(crate) fn role(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, account, role] = args.positional.as_slice() else {
        return Err(usage(
            "chart role names one account and one role",
            format!("{ROLE}  (fa chart roles --json lists the registered roles)"),
        ));
    };
    let registry = registry()?;
    if registry.get(role).is_none() {
        return Err(usage(
            format!("`{role}` is not a registered account role"),
            format!("name one of: {} ({ROLE})", registry.listing()),
        ));
    }
    let assigned = !args.switch("--remove");
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read", "schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &cap)??;
        crate::rea::admit_read(book, who, &cap)
    })?;
    let spec = AccountRoleSpec {
        account: account_vid(book.context().book_id, account),
        role: role.clone(),
        assigned,
    };
    let key = match args.flag("--key") {
        Some(key) => key.to_string(),
        None => {
            let (_, roles) = book.account_roles(None, &cap)??;
            format!(
                "role:{account}:{role}:{}",
                roles.controls(spec.account, role)
            )
        }
    };
    let recorded = book.record_account_role(&spec, who, key.as_bytes(), &cap)??;
    ctx.out.at_book(&book)?;
    let held = if recorded.control.spec.assigned {
        "holds"
    } else {
        "does not hold"
    };
    ctx.out.event(
        "account_role_recorded",
        vec![
            ("role", account_role_json(&recorded.control, account)),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!(
            "{account} {held} role {role}{} (control {:032x}, recorded at {})",
            if recorded.already_recorded {
                "; nothing was written"
            } else {
                ""
            },
            recorded.control.entry.vid.0,
            recorded.control.recorded_at.0,
        ),
    );
    Ok(())
}

/// `fa chart roles [--as-known-at …]`.
pub(crate) fn roles(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if let Some(extra) = args.positional.get(2) {
        return Err(usage(
            format!("chart roles takes no argument (got `{extra}`)"),
            "fa chart roles [--as-known-at HEAD|<seq>] --json",
        ));
    }
    let registry = registry()?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    let (at, roles) = book.account_roles(known_at, &cap)??;
    let codes: BTreeMap<VId, String> = book
        .accounts_at(at, &cap)??
        .into_iter()
        .map(|account| (account.vid, account.code))
        .collect();
    let code_of = |vid: VId| -> Result<String, Fail> {
        codes.get(&vid).cloned().ok_or_else(|| {
            Fail::Book(fa::BookError::Kernel(fa_journal::KernelError::Corrupt(
                "an account role names an account absent at its prefix".into(),
            )))
        })
    };
    // Registered roles in registry order; a role held that the registry no
    // longer lists is still shown, after them.
    let mut names: Vec<&str> = registry.rows.iter().map(|r| r.name.as_str()).collect();
    for control in roles.assigned() {
        if !names.contains(&control.spec.role.as_str()) {
            names.push(&control.spec.role);
        }
    }
    let mut items = Vec::with_capacity(names.len());
    let mut human = Vec::with_capacity(names.len());
    for name in names {
        let mut holders: Vec<(String, &AccountRoleControl)> = roles
            .assigned()
            .filter(|c| c.spec.role == name)
            .map(|c| Ok((code_of(c.spec.account)?, c)))
            .collect::<Result<_, Fail>>()?;
        holders.sort_by(|a, b| a.0.cmp(&b.0));
        let row = registry.get(name);
        let strings = |values: &[String]| Json::Arr(values.iter().map(s).collect());
        let no_strings: &[String] = &[];
        items.push(obj(vec![
            ("role", s(name)),
            (
                "meaning",
                s(row.map_or("not in registries/account_roles.toml", |r| {
                    r.meaning.as_str()
                })),
            ),
            (
                "account_types",
                strings(row.map_or(no_strings, |r| r.account_types.as_slice())),
            ),
            (
                "consumers",
                strings(row.map_or(no_strings, |r| r.consumers.as_slice())),
            ),
            (
                "accounts",
                Json::Arr(
                    holders
                        .iter()
                        .map(|(code, control)| account_role_json(control, code))
                        .collect(),
                ),
            ),
        ]));
        let held: Vec<&str> = holders.iter().map(|(code, _)| code.as_str()).collect();
        human.push(format!(
            "{:<14} {:<40} used by {}",
            name,
            if held.is_empty() {
                "(no account holds it)".to_string()
            } else {
                held.join(", ")
            },
            row.map_or_else(String::new, |r| r.consumers.join(", ")),
        ));
    }
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "account_roles",
        vec![
            ("known_at", Json::Int(i128::from(at.0))),
            ("roles", Json::Arr(items)),
        ],
        &human.join("\n"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::seeded_role_key;
    use fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES;

    /// A key that fits keeps its readable form; one that would exceed the
    /// model's limit (a 38-byte chart key and `investment_in_subsidiary`)
    /// becomes a bounded digest, the same on every retry and distinct per
    /// account and role.
    #[test]
    fn a_seeded_role_key_always_fits_the_idempotency_limit() {
        let chart = b"chart:0123456789abcdef0123456789abcdef";
        let short = [chart.as_slice(), b":role:1300:intercompany"].concat();
        assert_eq!(
            seeded_role_key(short.clone(), chart, "1300", "intercompany"),
            short
        );
        let long = |code: &str, role: &str| {
            let plain = [chart.as_slice(), format!(":role:{code}:{role}").as_bytes()].concat();
            assert!(plain.len() > MAX_IDEMPOTENCY_KEY_BYTES);
            seeded_role_key(plain, chart, code, role)
        };
        let key = long("1500", "investment_in_subsidiary");
        assert!(key.len() <= MAX_IDEMPOTENCY_KEY_BYTES && key.starts_with(b"role:"));
        assert_eq!(key, long("1500", "investment_in_subsidiary"));
        assert_ne!(key, long("1510", "investment_in_subsidiary"));
        assert_ne!(key, long("1500", "noncontrolling_interest_income"));
    }
}
