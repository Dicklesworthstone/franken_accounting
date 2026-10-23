//! `registries/account_roles.toml`: what an account is for, independently of
//! its code and name (bead fa-kxc4). The kernel refuses a role assignment the
//! registry does not admit, and Lantern selects populations by role.

use std::collections::BTreeSet;

use crate::procedures::Procedures;
use crate::toml::Value;
use crate::{RegistryError, account_types_embedded, invalid, load, req_int, req_str};

const ACCOUNT_ROLES: &str = include_str!("../../../registries/account_roles.toml");
const R: &str = "account_roles.toml";

/// The longest role name the canonical role control carries.
pub const MAX_ROLE_NAME: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRole {
    pub name: String,
    /// Account type names (`account_types.toml`) the role admits.
    pub account_types: Vec<String>,
    pub meaning: String,
    /// Procedures that select a population by this role.
    pub consumers: Vec<String>,
    /// Verbs (`verbs.toml`) that read accounts by this role outside Lantern.
    pub verbs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRoles {
    pub rows: Vec<AccountRole>,
}

fn strings(t: &crate::toml::Table, key: &str, role: &str) -> Result<Vec<String>, RegistryError> {
    let values = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(R, format!("role `{role}`: `{key}` must be an array")))?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let text = value
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| invalid(R, format!("role `{role}`: `{key}` holds a non-string")))?;
        out.push(text.to_string());
    }
    Ok(out)
}

impl AccountRoles {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(ACCOUNT_ROLES)
    }

    pub fn from_text(text: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let types: BTreeSet<String> = account_types_embedded()?
            .into_iter()
            .map(|row| row.name)
            .collect();
        let procedures = Procedures::embedded()?;
        let empty = Vec::new();
        let mut names = BTreeSet::new();
        let mut rows = Vec::new();
        for t in doc.arrays.get("role").unwrap_or(&empty) {
            let name = req_str(R, t, "name")?.to_string();
            if name.len() > MAX_ROLE_NAME
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                || !name.starts_with(|c: char| c.is_ascii_lowercase())
            {
                return Err(invalid(
                    R,
                    format!(
                        "role `{name}`: a name is lowercase snake_case of at most {MAX_ROLE_NAME} bytes"
                    ),
                ));
            }
            if !names.insert(name.clone()) {
                return Err(invalid(R, format!("role `{name}` is listed twice")));
            }
            let account_types = strings(t, "account_types", &name)?;
            if account_types.is_empty() {
                return Err(invalid(R, format!("role `{name}` admits no account type")));
            }
            for ty in &account_types {
                if !types.contains(ty) {
                    return Err(invalid(
                        R,
                        format!("role `{name}`: `{ty}` is not in account_types.toml"),
                    ));
                }
            }
            let meaning = req_str(R, t, "meaning")?.to_string();
            let consumers = strings(t, "consumers", &name)?;
            let verbs = if t.get("verbs").is_some() {
                strings(t, "verbs", &name)?
            } else {
                Vec::new()
            };
            if consumers.is_empty() && verbs.is_empty() {
                return Err(invalid(
                    R,
                    format!(
                        "role `{name}` has no consumer: list a role once a procedure or verb selects by it"
                    ),
                ));
            }
            for id in &consumers {
                if procedures.get(id).is_none() {
                    return Err(invalid(
                        R,
                        format!("role `{name}`: consumer `{id}` is not in procedures.toml"),
                    ));
                }
            }
            rows.push(AccountRole {
                name,
                account_types,
                meaning,
                consumers,
                verbs,
            });
        }
        if rows.is_empty() {
            return Err(invalid(R, "no roles"));
        }
        Ok(Self { rows })
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&AccountRole> {
        self.rows.iter().find(|r| r.name == name)
    }

    /// The registered role names, for refusal text.
    #[must_use]
    pub fn listing(&self) -> String {
        self.rows
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl AccountRole {
    /// Whether the role admits an account of the named type.
    #[must_use]
    pub fn admits(&self, account_type: &str) -> bool {
        self.account_types.iter().any(|t| t == account_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_roles_load_with_their_types_and_consumers() {
        let roles = AccountRoles::embedded().expect("account_roles.toml");
        let suspense = roles.get("suspense").expect("suspense");
        assert!(suspense.admits("Asset") && suspense.admits("Liability"));
        assert!(!suspense.admits("Revenue"));
        assert_eq!(suspense.consumers, vec!["jet.suspense_aging"]);
        assert!(roles.get("intercompany").is_some());
        assert!(
            roles.get("revenue").is_none(),
            "a role is listed once consumed"
        );
        assert_eq!(
            roles.listing(),
            "suspense, intercompany, receivable, payable, fixed_asset, accrued_expense, inventory, cash, investor_capital, payroll, intercompany_activity, investment_in_subsidiary, contributed_capital, noncontrolling_interest, noncontrolling_interest_income"
        );
        assert!(roles.get("payable").is_some_and(|r| !r.admits("Asset")));
        assert!(roles.get("cash").is_some_and(|r| r.consumers.len() == 7));
        // A role a verb reads outside Lantern lists the verb, not a procedure.
        let nci = roles
            .get("noncontrolling_interest_income")
            .expect("nci income");
        assert!(nci.consumers.is_empty() && nci.verbs == vec!["consolidate"]);
        assert!(nci.admits("Expense") && !nci.admits("Equity"));
        assert_eq!(
            roles.get("intercompany").map(|r| r.verbs.clone()),
            Some(vec!["consolidate".to_string()])
        );
        assert!(roles.get("suspense").is_some_and(|r| r.verbs.is_empty()));
    }

    #[test]
    fn planted_rows_are_refused_with_the_reason() {
        let row = |body: &str| format!("schema_version = 1\n\n[[role]]\n{body}\n");
        let base =
            "account_types = [\"Asset\"]\nmeaning = \"m\"\nconsumers = [\"jet.suspense_aging\"]";
        let cases = [
            (row(&format!("name = \"Cash\"\n{base}")), "snake_case"),
            (
                row(
                    "name = \"a\"\naccount_types = [\"Assets\"]\nmeaning = \"m\"\nconsumers = [\"jet.suspense_aging\"]",
                ),
                "not in account_types.toml",
            ),
            (
                row(
                    "name = \"a\"\naccount_types = []\nmeaning = \"m\"\nconsumers = [\"jet.suspense_aging\"]",
                ),
                "admits no account type",
            ),
            (
                row("name = \"a\"\naccount_types = [\"Asset\"]\nmeaning = \"m\"\nconsumers = []"),
                "has no consumer",
            ),
            (
                row(
                    "name = \"a\"\naccount_types = [\"Asset\"]\nmeaning = \"m\"\nconsumers = []\nverbs = []",
                ),
                "has no consumer",
            ),
            (
                row(
                    "name = \"a\"\naccount_types = [\"Asset\"]\nmeaning = \"m\"\nconsumers = []\nverbs = [\"\"]",
                ),
                "holds a non-string",
            ),
            (
                row(
                    "name = \"a\"\naccount_types = [\"Asset\"]\nmeaning = \"m\"\nconsumers = [\"jet.nope\"]",
                ),
                "not in procedures.toml",
            ),
            (
                format!(
                    "{}\n[[role]]\nname = \"a\"\n{base}\n",
                    row(&format!("name = \"a\"\n{base}"))
                ),
                "listed twice",
            ),
        ];
        for (text, expected) in cases {
            let error = AccountRoles::from_text(&text)
                .expect_err(expected)
                .to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }
}
