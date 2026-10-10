//! The kernel's evidence minimum against the reference oracle, exhaustively
//! (fa-lp6; plan §9.2–§9.3, FA-INV-05 `evidence-minimum`).
//!
//! For every registered entry class and every set of up to two cited
//! documents drawn from 30 archetypes (6 kinds × all 5 provenance grades),
//! `fa_journal::evidence::check_minimum` and
//! `fa_reference::evidence::verdict` must return the same refusal code — the
//! kernel from its own code, the oracle from the plan's text and the
//! registry rows. The citation layer (role, held document, commitment) is
//! exercised against the real substrate in fa-journal's tests and in the
//! planted intents of `differential.rs`.

use std::collections::BTreeMap;

use fa_journal::evidence::{CitedDocument, check_minimum};
use fa_model::EntryClass;
use fa_reference::evidence::{Citation, Doc, embedded_policy, verdict};
use fgdb_types::VId;

const KINDS: [&str; 6] = [
    "Invoice",
    "Rate",
    "Memo",
    "Workpaper",
    "Spreadsheet",
    "Confirmation",
];

#[test]
fn kernel_and_oracle_agree_on_every_class_and_every_pair_of_documents() {
    let policy = embedded_policy().expect("evidence_policy.toml");
    let grades: Vec<String> = policy.grades.iter().map(|g| g.name.clone()).collect();
    assert_eq!(grades.len(), 5, "every provenance grade is exercised");
    let archetypes: Vec<(String, String)> = KINDS
        .iter()
        .flat_map(|k| grades.iter().map(move |g| ((*k).to_string(), g.clone())))
        .collect();
    let mut sets: Vec<Vec<usize>> = vec![Vec::new()];
    for a in 0..archetypes.len() {
        sets.push(vec![a]);
        for b in a + 1..archetypes.len() {
            sets.push(vec![a, b]);
        }
    }
    let mut compared = 0usize;
    let mut refusals: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut class_names: Vec<String> = EntryClass::ALL
        .iter()
        .map(|(_, name, _)| (*name).to_string())
        .collect();
    assert_eq!(class_names.len(), 20, "every registered class");
    class_names.push("NoSuchClass".into());
    for class in &class_names {
        for set in &sets {
            let mut docs = BTreeMap::new();
            let mut cited = Vec::new();
            let mut citations = Vec::new();
            for (i, a) in set.iter().enumerate() {
                let (kind, grade) = &archetypes[*a];
                let id = u64::try_from(i).unwrap() + 1;
                let commit = [u8::try_from(*a).unwrap(); 32];
                docs.insert(
                    id,
                    Doc {
                        kind: kind.clone(),
                        grade: grade.clone(),
                        commit,
                    },
                );
                citations.push(Citation {
                    doc: id,
                    commit,
                    role: 1,
                });
                cited.push(CitedDocument {
                    vid: VId(u128::from(id)),
                    kind: policy.kind_by_name(kind).unwrap().tag,
                    grade: policy.grade_by_name(grade).unwrap().tag,
                });
            }
            let kernel = check_minimum(&policy, class, &cited).err().map(|r| r.code);
            let oracle = verdict(&policy, class, &docs, &citations);
            assert_eq!(
                kernel,
                oracle,
                "class {class}, documents {:?}",
                set.iter().map(|a| &archetypes[*a]).collect::<Vec<_>>()
            );
            if let Some(code) = oracle {
                *refusals.entry(code).or_default() += 1;
            }
            compared += 1;
        }
    }
    // Coverage floors: the space is not vacuous, and every outcome the law
    // can reach is reached many times.
    assert_eq!(compared, class_names.len() * sets.len());
    assert!(compared > 8_000, "{compared}");
    for code in ["FA-REF-080", "FA-REF-086"] {
        assert!(
            refusals.get(code).copied().unwrap_or(0) > 100,
            "{code} reached only {:?} times",
            refusals.get(code)
        );
    }
    let admitted = compared - refusals.values().sum::<usize>();
    assert!(admitted > 1_000, "only {admitted} admitted");
}
