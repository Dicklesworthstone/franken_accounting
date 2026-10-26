//! K-ORACLE (§2.1, §5.3; bead fa-yugf.8, A3b): an `oracle_output` fact (a
//! figure that is itself the reference method's result) in the closure of a
//! leg a T reads feeds that T only if the T names the fact in
//! `inputs_named`; otherwise the read is re-typed C, per target where the
//! reads sit on targets. Naming an intent in `inputs_named` does not name the
//! oracle facts its legs trace to.

use std::collections::BTreeSet;

use super::super::Case;
use super::super::EXPECTATIONS_FILE;
use super::super::expect::ExpectationType;
use super::super::trace::{Read, chain, posted_from, read_accounts, t_reads};
use super::{CheckReport, Context, Retype};

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let reads = case.expectations.as_ref().map(t_reads).unwrap_or_default();
    let mut r = CheckReport::new("K-ORACLE", reads.len());
    for read in reads {
        r.examined(read.row());
        match retype(case, &read) {
            Ok(Some(path)) => {
                r.retypes
                    .push(Retype::new(&read, ExpectationType::C, "K-ORACLE", path))
            }
            Ok(None) => {}
            Err(e) => r.fail(EXPECTATIONS_FILE, read.line(), &read.row(), e),
        }
    }
    r.finish()
}

/// Whether `fact` is a sourced fact marked `role = "oracle_output"`.
#[must_use]
pub fn is_oracle_output(case: &Case, fact: &str) -> bool {
    case.facts
        .iter()
        .find(|f| f.id == fact)
        .and_then(|f| f.sourced())
        .is_some_and(|s| s.role.as_deref() == Some("oracle_output"))
}

fn retype(case: &Case, read: &Read<'_>) -> Result<Option<Vec<String>>, String> {
    let variant = read.str("book_variant").unwrap_or_default();
    let book = case
        .books
        .get(variant)
        .ok_or_else(|| format!("book variant `{variant}` is not loaded"))?;
    let named: BTreeSet<&str> = read
        .expectation
        .fields
        .strs("inputs_named")
        .unwrap_or(&[])
        .iter()
        .map(String::as_str)
        .collect();
    let target = read.str("read_target").unwrap_or_default();
    for posted in posted_from(case, book, &read_accounts(book, target)) {
        let unnamed = posted
            .facts
            .iter()
            .find(|f| is_oracle_output(case, f) && !named.contains(f.as_str()));
        if let Some(oracle) = unnamed {
            let mut path = match &posted.named {
                Some(n) => chain(case, oracle, n),
                None => vec![oracle.clone()],
            };
            path.push(format!("leg {}#{}", posted.intent, posted.ordinal));
            return Ok(Some(path));
        }
    }
    Ok(None)
}
