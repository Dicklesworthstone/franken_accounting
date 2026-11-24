//! The PAID projection from authenticated original leg dimensions.
//!
//! Party attribution precedes monetary allocation. Exactly one raw party
//! dimension names a node; absent or ambiguous attribution names the book.
//! Historical declarations supply dimension bindings and display codes, never
//! ownership conclusions or facts from a producer's native REA witness.

use std::collections::BTreeMap;

use super::{Entry, Registry, ReportError, failed, structuring};
use crate::report::{dimension, metadata, native_subledger};

#[derive(Clone, Default)]
pub(crate) struct Context {
    codes: BTreeMap<u128, String>,
    dimensions: BTreeMap<u128, u128>,
    pub(crate) legs: BTreeMap<u128, Vec<Vec<u128>>>,
}

impl Context {
    pub(crate) fn declare(&mut self, book: &[u8; 16], body: &[u8]) -> Result<(), ReportError> {
        let code = native_subledger::party_code(body)?;
        let party = metadata::framed_identity(b"fa:vid:party:v1", &[book, code.as_bytes()]);
        let dimension = dimension::value_vid(book, "party", &code);
        if self.codes.insert(party, code).is_some()
            || self.dimensions.insert(dimension, party).is_some()
        {
            return Err(invalid(
                "duplicate or ambiguous historical PAID Party declaration",
            ));
        }
        Ok(())
    }

    fn node(&self, dimensions: &[u128]) -> u128 {
        match dimensions {
            [value] => self.dimensions.get(value).copied().unwrap_or(*value),
            _ => 0,
        }
    }

    pub(super) fn label(&self, node: u128) -> String {
        if node == 0 {
            "book".into()
        } else {
            self.codes
                .get(&node)
                .cloned()
                .unwrap_or_else(|| format!("{node:032x}"))
        }
    }
}

fn invalid(detail: &str) -> ReportError {
    failed("procedure_profile", detail)
}

pub(super) fn context(registry: &Registry) -> Result<&Context, ReportError> {
    registry
        .trace
        .as_ref()
        .and_then(|trace| trace.paid.as_ref())
        .ok_or_else(|| {
            invalid("PAID replay lacks authenticated Party declarations and leg dimensions")
        })
}

pub(super) fn flow(
    live: &[&Entry],
    registry: &Registry,
) -> Result<Vec<structuring::Transfer>, ReportError> {
    let parties = context(registry)?;
    for entry in live {
        if !parties
            .legs
            .get(&entry.identity)
            .is_some_and(|legs| legs.len() == entry.legs.len())
        {
            return Err(invalid(
                "PAID original party dimension lists are incomplete",
            ));
        }
        if entry
            .leg_accounts
            .iter()
            .any(|(account, _)| !registry.account_types.contains_key(account))
        {
            return Err(invalid(
                "PAID original accounts lack authenticated declarations",
            ));
        }
    }
    // Keep the original leg margins and ordering until each leg has its PAID
    // node. Relabeling an already allocated account transfer changes ties and
    // capacities. Self flows still consume capacity, then leave the population.
    structuring::projected_flow(live, registry, false, |entry, index, _account| {
        parties.node(&parties.legs[&entry.identity][index])
    })
}

#[cfg(test)]
mod tests;
