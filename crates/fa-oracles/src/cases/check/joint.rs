//! K-JOINT (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.6 rule 7; bead
//! fa-yugf.13, A5b): D and P expectations on one entry have disjoint branch
//! scopes. A refused branch removes the entry from every D population on
//! that branch, because procedures read `snapshot.live_postings()`, so every
//! D target names the admitted cell it runs on, `admitted_cell = ["<attr>=
//! <value>", ...]`, its evidence cell at least, and that cell may not lie in
//! a cell where a P on the same entry expects a refusal. An attribute the
//! admitted cell does not name takes its declared default's value (the
//! `[[default]]` rule names the value the encoding uses).

use std::collections::BTreeMap;

use super::{CheckReport, Context};
use crate::cases::EXPECTATIONS_FILE;
use crate::cases::book::BranchAttribute;
use crate::cases::expect::{Expectation, ExpectationType, Target};

pub const ID: &str = "K-JOINT";

/// The parsed `admitted_cell`, or why it is malformed.
fn admitted(t: &Target) -> Result<BTreeMap<String, String>, String> {
    let Some(cell) = t.fields.strs("admitted_cell").filter(|c| !c.is_empty()) else {
        return Err(
            "a D target names the admitted cell it runs on (`admitted_cell`, its evidence cell at least)"
                .into(),
        );
    };
    let mut out = BTreeMap::new();
    for part in cell {
        let Some((a, v)) = part.split_once('=') else {
            return Err(format!(
                "admitted_cell entry `{part}` is <attribute>=<value>"
            ));
        };
        if BranchAttribute::parse(a).is_none() {
            return Err(format!(
                "admitted_cell attribute `{a}` is outside the §2.6 enum"
            ));
        }
        if out.insert(a.to_string(), v.to_string()).is_some() {
            return Err(format!("admitted_cell names `{a}` twice"));
        }
    }
    if !out.contains_key(BranchAttribute::EvidenceAttached.as_str()) {
        return Err("admitted_cell names its evidence cell (evidence_attached=<value>)".into());
    }
    Ok(out)
}

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    if let Some(r) = super::branch::selftest_exempt(cx, ID) {
        return r;
    }
    let Some(set) = cx.case.expectations.as_ref() else {
        return CheckReport::new(ID, 0).finish();
    };
    let ds: Vec<(&Expectation, &Target)> = set
        .expectations
        .iter()
        .filter(|e| e.kind == ExpectationType::D)
        .flat_map(|e| set.targets_of(&e.id).map(move |t| (e, t)))
        .collect();
    let mut rep = CheckReport::new(ID, ds.len());
    for (d, t) in ds {
        let row = format!("{}/{}", d.id, t.fact);
        let line = t.fields.line;
        let cell = match admitted(t) {
            Ok(c) => c,
            Err(why) => {
                rep.fail(EXPECTATIONS_FILE, line, &row, why);
                rep.examined(row);
                continue;
            }
        };
        let variant = d.fields.str("book_variant");
        let book = variant.and_then(|v| cx.case.books.get(v));
        let value_of = |attr: &str| -> Option<String> {
            cell.get(attr).cloned().or_else(|| {
                book?
                    .defaults
                    .iter()
                    .find(|x| x.attribute == attr)
                    .map(|x| x.rule.clone())
            })
        };
        // Every P on the same entry and variant, and its refusal cells.
        for p in set
            .expectations
            .iter()
            .filter(|p| p.kind == ExpectationType::P && p.fields.str("book_variant") == variant)
        {
            for pt in set.targets_of(&p.id).filter(|pt| pt.fact == t.fact) {
                let attrs = pt.fields.strs("branch_attrs").unwrap_or(&[]);
                for pc in set
                    .branch_cells
                    .iter()
                    .filter(|c| c.expectation == p.id && c.target == pt.fact)
                    .filter(|c| c.fields.str("expect").is_some_and(|x| x != "admit"))
                {
                    let mut unknown = Vec::new();
                    let inside = attrs.iter().zip(&pc.cell).all(|(a, v)| match value_of(a) {
                        Some(mine) => mine == *v,
                        None => {
                            unknown.push(a.clone());
                            true
                        }
                    });
                    if !unknown.is_empty() {
                        rep.fail(
                            EXPECTATIONS_FILE,
                            line,
                            &row,
                            format!(
                                "the admitted cell does not name [{}], which {} branches, and the book declares no default for it: disjointness from its refusal cell [{}] is not shown",
                                unknown.join(", "),
                                p.id,
                                pc.cell.join(", ")
                            ),
                        );
                    } else if inside {
                        rep.fail(
                            EXPECTATIONS_FILE,
                            line,
                            &row,
                            format!(
                                "the admitted cell lies in {}'s refusal cell [{}] (expects {}): a refused entry is in no D population",
                                p.id,
                                pc.cell.join(", "),
                                pc.fields.str("expect").unwrap_or_default()
                            ),
                        );
                    }
                }
            }
        }
        rep.examined(format!(
            "{row} admitted=[{}]",
            cell.iter()
                .map(|(a, v)| format!("{a}={v}"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    rep.finish()
}
