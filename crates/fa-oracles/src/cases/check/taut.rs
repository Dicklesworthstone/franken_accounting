//! K-TAUT, the static half (§3.6, §3.8; bead fa-yugf.8, A3b): a tie-out
//! that reads back its own published value is a read-back, whatever its
//! declared type. For every T read, P is the published fact B and every
//! fact derived from it. When a leg on an account the read selects traces
//! to a fact in P (A1b's `value:`/`derived:` rules through A2's derivations,
//! `derived:negate` to its target leg), the row is re-typed R with the trace
//! as its path; so is a read whose line a `remainder` derivation in P
//! partitions. A re-type is a result, not a failure. The dynamic half (no
//! contributing posting carries B) is A11b's witness.

use std::collections::BTreeSet;

use super::super::Case;
use super::super::EXPECTATIONS_FILE;
use super::super::expect::ExpectationType;
use super::super::fact::Provenance;
use super::super::trace::{Read, chain, fact_closure, posted_from, read_accounts, t_reads};
use super::{CheckReport, Context, Retype};

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let reads = case.expectations.as_ref().map(t_reads).unwrap_or_default();
    let mut r = CheckReport::new("K-TAUT", reads.len());
    for read in reads {
        r.examined(read.row());
        match retype(case, &read) {
            Ok(Some(path)) => {
                r.retypes
                    .push(Retype::new(&read, ExpectationType::R, "K-TAUT", path))
            }
            Ok(None) => {}
            Err(e) => r.fail(EXPECTATIONS_FILE, read.line(), &read.row(), e),
        }
    }
    r.finish()
}

/// The facts that are `b` or derived from it.
#[must_use]
pub fn published_closure(case: &Case, b: &str) -> BTreeSet<String> {
    case.facts
        .iter()
        .filter(|f| f.id == b || fact_closure(case, &f.id).contains(b))
        .map(|f| f.id.clone())
        .collect()
}

/// The re-typing path, if the read reads back its published value.
fn retype(case: &Case, read: &Read<'_>) -> Result<Option<Vec<String>>, String> {
    let b = read
        .str("published")
        .ok_or("a T read names its `published` fact")?;
    let variant = read.str("book_variant").unwrap_or_default();
    let book = case
        .books
        .get(variant)
        .ok_or_else(|| format!("book variant `{variant}` is not loaded"))?;
    let target = read.str("read_target").unwrap_or_default();
    let p = published_closure(case, b);
    for posted in posted_from(case, book, &read_accounts(book, target)) {
        if posted.facts.is_disjoint(&p) {
            continue;
        }
        let mut path = match &posted.named {
            Some(named) => chain(case, b, named),
            None => vec![b.to_string()],
        };
        path.push(format!("leg {}#{}", posted.intent, posted.ordinal));
        return Ok(Some(path));
    }
    // A remainder that a B value fed partitions the line it names (§3.8).
    for f in case.facts.iter().filter(|f| p.contains(&f.id)) {
        let Provenance::Derived(d) = &f.provenance else {
            continue;
        };
        let line = d
            .params
            .iter()
            .flatten()
            .filter_map(|v| v.as_str()?.strip_prefix("line="))
            .next();
        if d.rule == "remainder" && line == Some(target) {
            let mut path = chain(case, b, &f.id);
            path.push(format!("remainder line={target}"));
            return Ok(Some(path));
        }
    }
    Ok(None)
}
