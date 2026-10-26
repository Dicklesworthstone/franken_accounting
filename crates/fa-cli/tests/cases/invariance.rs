//! The filler- and identifier-invariance witness through the binary
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.7 item 1; bead fa-yugf.25,
//! A11a).
//!
//! Every filler spec of a variant (A7c's combination rule: the seeded
//! variants, the empty variant and the extremal variant of each claimed
//! tier) gets a book of its own, with that variant posted at its
//! `filler_batch` step, and the empty variant runs a second time, so at
//! least two book ids are seen. Each run's rows are evaluated like the main
//! run's, and every row still waiting on this witness is compared across
//! them (`fa_oracles::cases::invariance::compare`): agreement makes it PASS
//! (`invariance=agree(variants=<n>,book_ids=<m>)`), a disagreement FAILs it,
//! naming the procedure, the component and the two runs. A book that
//! declares no `filler_batch` step cannot vary its filler, so its rows keep
//! waiting: never PASS on book ids alone.

use std::collections::BTreeMap;

use fa_oracles::cases::Case;
use fa_oracles::cases::book::{BookVariant, StepKind};
use fa_oracles::cases::expect::{ExpectationType, Status};
use fa_oracles::cases::filler::{self, FillerKind, FillerSpec};
use fa_oracles::cases::invariance::{InvarianceVerdict, Statuses, VariantObservation, compare};
use fa_oracles::cases::log::StepRecord;
use fa_oracles::cases::tiers::{self, Tiers};
use fa_oracles::cases::twin::TwinSpec;
use fa_oracles::cases::verdict::RowVerdict;

use super::evaluate::{self, Evaluated, FILLER};
use super::run::{BookRun, tmp};

/// The witness's extra runs, for the run log and the budget.
pub struct Applied {
    pub steps: Vec<StepRecord>,
    pub lines: Vec<String>,
}

/// A row's identity across runs.
fn key(ev: &Evaluated) -> String {
    format!(
        "{} {} {}",
        ev.row.id,
        ev.row.target.as_deref().unwrap_or("-"),
        ev.row.cell
    )
}

/// The components the witness compares for a row: a D row's single
/// statuses (its identity tokens always), every token of any other row.
fn statuses(case: &Case, ev: &Evaluated) -> Statuses {
    let set = case.expectations.as_ref();
    let e = set.and_then(|s| s.get(&ev.row.id));
    let target = ev.row.target.as_deref();
    let t = e.and_then(|e| {
        set.and_then(|s| {
            s.targets_of(&e.id)
                .find(|t| Some(t.fact.as_str()) == target)
        })
    });
    match (e.map(|e| e.kind), t) {
        (Some(ExpectationType::D), Some(t)) => {
            let mut out = Statuses {
                single: vec![
                    ("procedure".into(), vec!["procedure".into()]),
                    ("entry".into(), vec!["entry".into()]),
                ],
                relational: Vec::new(),
            };
            for (component, tokens) in [
                ("cite", vec!["cite"]),
                ("severity", vec!["severity"]),
                ("statistic", vec!["statistic_name", "statistic", "scale"]),
            ] {
                match t
                    .fields
                    .str(&format!("{component}_status"))
                    .and_then(Status::parse)
                {
                    Some(Status::S | Status::Sd | Status::Si) => out.single.push((
                        component.into(),
                        tokens.iter().map(|t| (*t).to_string()).collect(),
                    )),
                    Some(Status::Rel(_)) => out.relational.push(component.into()),
                    _ => {}
                }
            }
            out
        }
        _ => Statuses {
            single: ev
                .row
                .projection
                .iter()
                .map(|(k, _)| (k.clone(), vec![k.clone()]))
                .collect(),
            relational: Vec::new(),
        },
    }
}

/// Why a disagreeing row fails: the tier row its procedure rests on.
fn why(tiers: &Tiers, procedure: &str) -> String {
    let id = procedure.split_once('@').map_or(procedure, |(p, _)| p);
    match tiers.get(id) {
        Some(row) => format!(
            "tier row {}:{} declares {}",
            tiers::FILE,
            row.line.unwrap_or_default(),
            row.tier.as_str()
        ),
        None => format!("{procedure} has no tier row, and its projection moved"),
    }
}

/// Runs the witness for one variant over every filler spec of its variant
/// (`filler::specs`) and applies its verdicts to `rows`.
#[allow(clippy::too_many_arguments)]
pub fn apply<'c>(
    case: &'c Case,
    book: &'c BookVariant,
    texts: &'c [(&'c str, &'c str)],
    main: &BookRun<'c>,
    rows: &mut [Evaluated],
    specs: &[(String, Result<TwinSpec, String>)],
    twins: &BTreeMap<String, BookRun<'c>>,
    tiers: &Tiers,
) -> Applied {
    let fillers = match filler::specs(case, book, tiers) {
        Ok(f) => f,
        Err(e) => {
            return Applied {
                steps: Vec::new(),
                lines: vec![format!("INVARIANCE {} unrun: {e}", book.stem)],
            };
        }
    };
    apply_with(case, book, texts, main, rows, specs, twins, tiers, &fillers)
}

/// The witness over the given filler specs. The runner passes every spec
/// (`apply`); a test may pass fewer, and the agreement token counts the
/// variants that actually ran.
#[allow(clippy::too_many_arguments)]
pub fn apply_with<'c>(
    case: &'c Case,
    book: &'c BookVariant,
    texts: &'c [(&'c str, &'c str)],
    main: &BookRun<'c>,
    rows: &mut [Evaluated],
    specs: &[(String, Result<TwinSpec, String>)],
    twins: &BTreeMap<String, BookRun<'c>>,
    tiers: &Tiers,
    fillers: &[FillerSpec],
) -> Applied {
    let mut out = Applied {
        steps: Vec::new(),
        lines: Vec::new(),
    };
    let waiting: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, ev)| ev.row.reason.as_deref() == Some(FILLER))
        .map(|(i, _)| i)
        .collect();
    let varies = book
        .steps
        .iter()
        .any(|s| s.step_kind() == Some(StepKind::FillerBatch));
    if waiting.is_empty() || !varies || main.failure.is_some() {
        return out;
    }
    // The main run is the first empty run.
    let main_label = fillers
        .iter()
        .find(|s| s.kind == FillerKind::Empty)
        .map_or_else(|| "empty".to_string(), filler::FillerSpec::label);
    let mut observations: BTreeMap<String, Vec<VariantObservation>> = BTreeMap::new();
    let mut add = |run_rows: &[Evaluated], label: &str, book_id: &str| {
        for ev in run_rows {
            observations
                .entry(key(ev))
                .or_default()
                .push(VariantObservation {
                    variant: label.to_string(),
                    book_id: book_id.to_string(),
                    projection: ev.row.projection.clone(),
                });
        }
    };
    add(rows, &main_label, main.book_id.as_deref().unwrap_or("-"));
    let mut dirs: BTreeMap<String, String> = BTreeMap::new();
    dirs.insert(main_label.clone(), main.dir.display().to_string());
    for spec in fillers {
        let variant = if spec.kind == FillerKind::Empty {
            None
        } else {
            match filler::generate(case, book, spec) {
                Ok(v) => Some(v),
                Err(e) => {
                    out.lines.push(format!(
                        "INVARIANCE {} {} unrun: {e}",
                        book.stem,
                        spec.label()
                    ));
                    continue;
                }
            }
        };
        let label = spec.label();
        let work = tmp(&format!("{}-{}-inv", case.header.id, book.stem));
        let mut run = BookRun::new(case, book, work, texts);
        run.filler = variant;
        run.build();
        run.replay();
        run.self_procedure();
        let run_rows = evaluate::rows(&run, specs, twins);
        let book_id = run.book_id.clone().unwrap_or_else(|| "-".into());
        add(&run_rows, &label, &book_id);
        dirs.insert(format!("{label}/{book_id}"), run.dir.display().to_string());
        if let Some(why) = &run.failure {
            out.lines.push(format!(
                "INVARIANCE {} {label} build failed: {why}",
                book.stem
            ));
        }
        out.steps.append(&mut run.steps);
        out.lines
            .extend(run.lines.drain(..).filter(|l| !l.starts_with("PERIODS ")));
    }
    for i in waiting {
        let ev = &mut rows[i];
        let Some(obs) = observations.get(&key(ev)) else {
            continue;
        };
        let procedure = ev
            .row
            .projection
            .iter()
            .find(|(k, _)| k == "procedure")
            .map_or_else(|| ev.row.id.clone(), |(_, v)| v.clone());
        let statuses = statuses(case, ev);
        // A Rel component holds on a run when its rule's selection under
        // that run's account VIds (the `rel=<account>/<magnitude>` token the
        // run's D row carries, A5b) is what the run cited and capitalized:
        // the value may differ across book ids, the rule may not.
        let verdict = compare(&procedure, obs, &statuses, &|component, o| {
            let token = |k: &str| {
                o.projection
                    .iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.as_str())
            };
            evaluate::rel_holds(
                token("rel"),
                component,
                token("cite").unwrap_or("-"),
                token("statistic").unwrap_or("-"),
            )
            .unwrap_or(false)
        });
        let token = verdict.token();
        match &verdict {
            InvarianceVerdict::Agree { .. } => {
                ev.row.verdict = RowVerdict::Pass;
                ev.row.reason = None;
                ev.row.projection.push(("invariance".into(), token.clone()));
                ev.record.verdict = RowVerdict::Pass;
                ev.record.reason = None;
                ev.record
                    .projection
                    .push(("invariance".into(), token.clone()));
                ev.record.witnesses.push(("invariance".into(), token));
            }
            InvarianceVerdict::Disagree { a, b, .. } => {
                let reason = why(tiers, &procedure);
                ev.row.verdict = RowVerdict::Fail;
                ev.row.reason = Some(reason.clone());
                ev.row.projection.push(("invariance".into(), token.clone()));
                ev.record.verdict = RowVerdict::Fail;
                ev.record.reason = Some(reason);
                ev.record
                    .projection
                    .push(("invariance".into(), token.clone()));
                ev.record.witnesses.push(("invariance".into(), token));
                // The two runs' retained books, where the procedure's run
                // can be read back.
                let books: Vec<String> = [a, b]
                    .iter()
                    .filter_map(|l| {
                        dirs.get(l.as_str())
                            .or_else(|| dirs.get(l.split('/').next().unwrap_or_default()))
                            .map(|d| format!("BOOK {l} {d}"))
                    })
                    .collect();
                ev.reproduce = Some(books.join("\n"));
            }
            InvarianceVerdict::OneBookId => {}
        }
    }
    out
}

/// What a test sees of one witness run: every row after the witness, and
/// the witness's own lines.
pub struct Witnessed {
    pub rows: Vec<String>,
    pub lines: Vec<String>,
}

impl Witnessed {
    /// The row with this id, as its line.
    pub fn row(&self, id: &str) -> Option<&str> {
        self.rows
            .iter()
            .find(|r| r.split(' ').nth(1) == Some(id))
            .map(String::as_str)
    }

    pub fn text(&self) -> String {
        format!("{}\n{}", self.rows.join("\n"), self.lines.join("\n"))
    }
}

/// Builds the `native` variant of a fixture and runs the witness over the
/// filler specs `keep` admits, under `tiers`: the shared body of the
/// witness's tests at the plan's volume (every spec, `--test
/// cases_invariance`) and at small volume (no extremal, `--test cases`).
pub fn witness(
    id: &str,
    files: &[(&str, &str)],
    tiers: &Tiers,
    keep: &dyn Fn(&FillerSpec) -> bool,
) -> Witnessed {
    let case = fa_oracles::cases::load(&fa_oracles::cases::CaseFiles { id, files })
        .expect("the fixture loads");
    let book = &case.books["native"];
    let mut main = BookRun::new(&case, book, tmp(&format!("{id}-witness")), files);
    main.build();
    main.replay();
    main.self_procedure();
    let none = BTreeMap::new();
    let mut rows = evaluate::rows(&main, &[], &none);
    let fillers: Vec<FillerSpec> = filler::specs(&case, book, tiers)
        .expect("its filler specs")
        .into_iter()
        .filter(|s| keep(s))
        .collect();
    let applied = apply_with(
        &case,
        book,
        files,
        &main,
        &mut rows,
        &[],
        &none,
        tiers,
        &fillers,
    );
    let mut lines = main
        .failure
        .iter()
        .map(|f| format!("BUILD {f}"))
        .collect::<Vec<_>>();
    lines.extend(applied.lines);
    Witnessed {
        rows: rows.iter().map(|ev| ev.row.to_string()).collect(),
        lines,
    }
}

/// The negative fixture (`crates/fa-oracles/tests/fixtures/invariance_negative/`).
pub const NEGATIVE: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../../fa-oracles/tests/fixtures/invariance_negative/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../../fa-oracles/tests/fixtures/invariance_negative/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../../fa-oracles/tests/fixtures/invariance_negative/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../../fa-oracles/tests/fixtures/invariance_negative/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../../fa-oracles/tests/fixtures/invariance_negative/expectations.toml"),
    ),
];

/// A test-only tier table declaring numbers.round_amount_density tier L,
/// and the line of its row there. Its finding moves with the book's round
/// share, so the L-discipline filler changes the projection.
pub fn round_density_tier_l() -> (Tiers, usize) {
    const TIERS: &str = include_str!("../../../fa-oracles/data/case_procedure_tiers.toml");
    let row = "procedure = \"numbers.round_amount_density\"\nversion = 1\n";
    let at = TIERS.find(row).expect("its tier row");
    let block_end = at + TIERS[at..].find("\n\n").expect("the row's end");
    let block = TIERS[at..block_end]
        .replace("tier = \"P\"", "tier = \"L\"")
        .replace("reader_tier = \"P\"", "reader_tier = \"L\"");
    let edited = format!("{}{block}{}", &TIERS[..at], &TIERS[block_end..]);
    let tiers = Tiers::from_text(&edited).expect("the test tier table");
    let line = tiers
        .get("numbers.round_amount_density")
        .and_then(|r| r.line)
        .expect("its line");
    (tiers, line)
}
