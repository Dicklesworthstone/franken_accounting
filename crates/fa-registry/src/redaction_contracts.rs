//! `registries/redaction_contracts.toml`: which byte ranges of a document
//! kind are privileged, and the op that reveals them (plan §9.6).

use std::collections::BTreeSet;

use crate::evidence_policy::EvidencePolicy;
use crate::toml::{Table, Value};
use crate::{RegistryError, invalid, load, req_int, req_str};

const REDACTION_CONTRACTS: &str = include_str!("../../../registries/redaction_contracts.toml");
const R: &str = "redaction_contracts.toml";

/// The ops a contract may name as revealing its privileged bytes.
pub const REVEAL_OPS: [&str; 1] = ["privileged"];

/// One contract: the kinds it governs and their privileged byte ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    pub id: u16,
    pub name: String,
    /// Document kind tags (`evidence_policy.toml`).
    pub kinds: Vec<u8>,
    /// `(offset, length)`, each length >= 1.
    pub privileged: Vec<(u64, u64)>,
    pub reveal_op: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionContracts {
    pub contracts: Vec<Contract>,
}

fn ints(t: &Table, key: &str, what: &str) -> Result<Vec<u64>, RegistryError> {
    t.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(R, format!("{what}: missing array `{key}`")))?
        .iter()
        .map(|v| {
            v.as_int()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or_else(|| invalid(R, format!("{what}: `{key}` holds a non-u64 value")))
        })
        .collect()
}

impl RedactionContracts {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(REDACTION_CONTRACTS, &EvidencePolicy::embedded()?)
    }

    pub fn from_text(text: &str, policy: &EvidencePolicy) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let empty = Vec::new();
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut governed = BTreeSet::new();
        let mut contracts = Vec::new();
        for t in doc.arrays.get("contract").unwrap_or(&empty) {
            let raw = req_int(R, t, "id")?;
            let id = u16::try_from(raw)
                .ok()
                .filter(|id| *id >= 1)
                .ok_or_else(|| invalid(R, format!("contract id {raw} is not in 1..=65535")))?;
            let what = format!("contract {id}");
            let name = req_str(R, t, "name")?.to_string();
            if !ids.insert(id) {
                return Err(invalid(R, format!("{what} is listed twice")));
            }
            if name.is_empty() || !names.insert(name.clone()) {
                return Err(invalid(
                    R,
                    format!("{what}: name `{name}` is empty or listed twice"),
                ));
            }
            let kind_names = t
                .get("kinds")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid(R, format!("{what}: missing array `kinds`")))?;
            if kind_names.is_empty() {
                return Err(invalid(R, format!("{what}: governs no kind")));
            }
            let mut kinds = Vec::new();
            for k in kind_names {
                let name = k
                    .as_str()
                    .ok_or_else(|| invalid(R, format!("{what}: a kind is not a string")))?;
                let tag = policy
                    .kinds
                    .iter()
                    .find(|d| d.name == name)
                    .map(|d| d.tag)
                    .ok_or_else(|| invalid(R, format!("{what}: unknown document kind `{name}`")))?;
                if !governed.insert(tag) {
                    return Err(invalid(
                        R,
                        format!("{what}: kind `{name}` is already governed by another contract"),
                    ));
                }
                kinds.push(tag);
            }
            let offsets = ints(t, "offsets", &what)?;
            let lengths = ints(t, "lengths", &what)?;
            if offsets.is_empty() || offsets.len() != lengths.len() {
                return Err(invalid(
                    R,
                    format!("{what}: `offsets` and `lengths` are parallel and non-empty"),
                ));
            }
            let mut privileged = Vec::with_capacity(offsets.len());
            for (offset, length) in offsets.into_iter().zip(lengths) {
                if length == 0 || offset.checked_add(length).is_none() {
                    return Err(invalid(
                        R,
                        format!("{what}: range ({offset}, {length}) is empty or past u64"),
                    ));
                }
                privileged.push((offset, length));
            }
            let reveal_op = req_str(R, t, "reveal_op")?.to_string();
            if !REVEAL_OPS.contains(&reveal_op.as_str()) {
                return Err(invalid(
                    R,
                    format!("{what}: unknown reveal_op `{reveal_op}`"),
                ));
            }
            if req_str(R, t, "meaning")?.trim().is_empty() {
                return Err(invalid(R, format!("{what}: meaning is required")));
            }
            contracts.push(Contract {
                id,
                name,
                kinds,
                privileged,
                reveal_op,
            });
        }
        if contracts.is_empty() {
            return Err(invalid(R, "at least one contract is registered"));
        }
        Ok(Self { contracts })
    }

    #[must_use]
    pub fn get(&self, id: u16) -> Option<&Contract> {
        self.contracts.iter().find(|c| c.id == id)
    }

    /// The contract governing documents of `kind`, if any.
    #[must_use]
    pub fn for_kind(&self, kind: u8) -> Option<&Contract> {
        self.contracts.iter().find(|c| c.kinds.contains(&kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_contracts_load() {
        let c = RedactionContracts::embedded().expect("redaction_contracts.toml");
        let statement = c.get(1).expect("contract 1");
        assert_eq!(statement.name, "statement-account-block");
        assert_eq!(statement.privileged, [(0, 4096)]);
        assert_eq!(statement.reveal_op, "privileged");
        let policy = EvidencePolicy::embedded().unwrap();
        let bank = policy
            .kinds
            .iter()
            .find(|k| k.name == "BankStatement")
            .unwrap()
            .tag;
        let invoice = policy
            .kinds
            .iter()
            .find(|k| k.name == "Invoice")
            .unwrap()
            .tag;
        assert_eq!(c.for_kind(bank).map(|x| x.id), Some(1));
        assert_eq!(c.for_kind(invoice), None);
    }

    #[test]
    fn malformed_contract_tables_are_refused() {
        let good = REDACTION_CONTRACTS;
        let policy = EvidencePolicy::embedded().unwrap();
        let second = "\n[[contract]]\nid = 2\nname = \"again\"\nkinds = [\"BankStatement\"]\noffsets = [0]\nlengths = [1]\nreveal_op = \"privileged\"\nmeaning = \"x\"\n";
        let planted = format!("{good}{second}");
        for (what, text, expect) in [
            (
                "a zero id",
                good.replacen("id = 1\n", "id = 0\n", 1),
                "not in 1..=65535",
            ),
            (
                "an unknown kind",
                good.replacen("[\"BankStatement\"]", "[\"Ledger\"]", 1),
                "unknown document kind",
            ),
            ("a kind under two contracts", planted, "already governed"),
            (
                "unparallel ranges",
                good.replacen("lengths = [4096]", "lengths = [4096, 1]", 1),
                "parallel",
            ),
            (
                "an empty range",
                good.replacen("lengths = [4096]", "lengths = [0]", 1),
                "empty or past u64",
            ),
            (
                "an unknown reveal op",
                good.replacen("reveal_op = \"privileged\"", "reveal_op = \"read\"", 1),
                "unknown reveal_op",
            ),
            (
                "no contracts",
                good.replacen("[[contract]]", "[[nocontract]]", 1),
                "at least one contract",
            ),
        ] {
            assert_ne!(text, good, "{what}: the planted edit did not apply");
            let err = RedactionContracts::from_text(&text, &policy).expect_err(what);
            assert!(err.to_string().contains(expect), "{what}: {err}");
        }
    }
}
