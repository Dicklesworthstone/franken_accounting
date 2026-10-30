//! Cell evaluation plans (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.3, §2.6
//! rule 6, §16; bead fa-yugf.17, A7c).
//!
//! A P verdict is a first-refusal verdict over a branch table. A cell is
//! decided by `fa post --dry-run`, which runs the commit's admission
//! pipeline for a Human principal (planning skips only the Agent-on-trunk
//! check, `crates/fa-policy/src/admit.rs:153`), so one book per entry
//! suffices. [`sweep_plan`] groups an entry's P cells onto that book and
//! orders them by the period state each needs, so the book's period
//! advances Open → SoftClosed → Closed → Locked once; record-inconsistent
//! cells are swept like any other. Each cell carries its own idempotency
//! key ([`cell_key`]), so a committed representative never turns a later
//! cell's dry run into an idempotent retry. [`runs`] is the combination
//! rule: filler variants on the default cell only, branch cells on the
//! empty variant only.

use std::collections::BTreeSet;

use super::Case;
use super::amount::format_amount;
use super::book::{BookVariant, BranchAttribute, CELL_KEY_SUFFIX_BYTES, StepKind, VariantKind};
use super::branch::{Cell, CellPart, Enumeration, WitnessValue, witnesses};
use super::error::{LoadError, LoadErrorKind};
use super::expect::ExpectationType;
use super::filler::{self, FillerKind, FillerSpec};
use super::tiers::Tiers;
use crate::sha256;

closed_set! {
    /// A period's state at commit, in the order a sweep advances it.
    PeriodState {
        Future => "Future",
        Open => "Open",
        SoftClosed => "SoftClosed",
        Closed => "Closed",
        Locked => "Locked",
    }
}

/// A cell's own idempotency key: the authored intent key, `.`, and the
/// first 12 hex of SHA-256 of the cell's values joined by 0x00. A1b caps an
/// authored key at `max_idempotency_key_bytes` less these
/// [`CELL_KEY_SUFFIX_BYTES`], so every cell key fits.
#[must_use]
pub fn cell_key(intent_key: &str, cell: &[String]) -> String {
    let digest = sha256::digest(cell.join("\0").as_bytes());
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    let key = format!("{intent_key}.{hex}");
    debug_assert_eq!(key.len(), intent_key.len() + CELL_KEY_SUFFIX_BYTES);
    key
}

/// One P cell to decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepCell {
    pub expectation: String,
    /// The target's fact (or intent) id, A7a's `<target>`.
    pub target: String,
    /// The branched attributes, in `branch_attrs` order.
    pub attrs: Vec<BranchAttribute>,
    /// A1c's cell key (one value per attribute), A7a's `<cell>`.
    pub key: Vec<String>,
    /// The period state the cell is decided in: its `period_state_at_commit`
    /// value, or else the state the history leaves the entry's period in at
    /// the entry's step.
    pub state: PeriodState,
    pub record_consistent: bool,
    pub default: bool,
    /// [`cell_key`] of the entry's authored key.
    pub idempotency_key: String,
    /// The authored `[[branch_cell]] expect` (a refusal id or `admit`).
    pub expect: Option<String>,
    /// The authored `pending` reason: swept and logged, never PASS.
    pub pending: Option<String>,
}

/// All P cells of one entry, on one book, in sweep order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepGroup {
    pub variant: String,
    pub intent: String,
    /// The entry's authored idempotency key.
    pub intent_key: String,
    pub cells: Vec<SweepCell>,
}

impl SweepGroup {
    /// The distinct period states the sweep visits, in order.
    #[must_use]
    pub fn states(&self) -> Vec<PeriodState> {
        let mut out: Vec<PeriodState> = Vec::new();
        for c in &self.cells {
            if out.last() != Some(&c.state) {
                out.push(c.state);
            }
        }
        out
    }

    /// The first cell, in sweep order, of each distinct authored outcome:
    /// the one committed to show its dry run agrees with a commit. A cell
    /// with no authored outcome gets its representative from the outcome
    /// its dry run observes (the executor's choice).
    #[must_use]
    pub fn representatives(&self) -> Vec<usize> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        self.cells
            .iter()
            .enumerate()
            .filter(|(_, c)| c.expect.as_deref().is_some_and(|e| seen.insert(e)))
            .map(|(i, _)| i)
            .collect()
    }
}

/// One variant's sweep.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepPlan {
    pub groups: Vec<SweepGroup>,
}

impl SweepPlan {
    /// Refuses a plan before it runs if a cell would reuse a key: two cells
    /// with one key, or a cell with an intent key the history commits (its
    /// dry run would then return the recorded outcome as an idempotent
    /// retry, never decide the cell).
    ///
    /// # Errors
    ///
    /// The first reused key.
    pub fn check(&self, book: &BookVariant) -> Result<(), String> {
        let committed: BTreeSet<&str> = book
            .intents
            .iter()
            .filter_map(|i| i.idempotency_key.as_deref())
            .collect();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for g in &self.groups {
            for c in &g.cells {
                let key = c.idempotency_key.as_str();
                if committed.contains(key) {
                    return Err(format!(
                        "{} {}/{}: key `{key}` is an intent key the history commits, so its dry run would replay the recorded outcome; each cell carries cell_key",
                        c.expectation,
                        c.target,
                        c.key.join("/")
                    ));
                }
                if !seen.insert(key) {
                    return Err(format!(
                        "{} {}/{}: key `{key}` is another cell's",
                        c.expectation,
                        c.target,
                        c.key.join("/")
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The state the history leaves `intent`'s period in when the intent's step
/// runs (its first `intent` or `batch` step).
fn state_at(book: &BookVariant, intent: &str) -> PeriodState {
    let Some(it) = book.intents.iter().find(|i| i.id == intent) else {
        return PeriodState::Future;
    };
    let Some(period) = book.periods.iter().find(|p| p.contains(&it.effective_date)) else {
        return PeriodState::Future;
    };
    let mut state = PeriodState::Future;
    for s in &book.steps {
        let kind = s.step_kind();
        let posts_it = match kind {
            Some(StepKind::Intent) => s.reference == intent,
            Some(StepKind::Batch) => s.reference.split_once("..").is_some_and(|(a, b)| {
                let pos = |id: &str| book.intents.iter().position(|i| i.id == id);
                let me = pos(intent);
                me.is_some() && pos(a) <= me && me <= pos(b)
            }),
            _ => false,
        };
        if posts_it {
            break;
        }
        if s.reference != period.code {
            continue;
        }
        state = match kind {
            Some(StepKind::PeriodOpen) => PeriodState::Open,
            Some(StepKind::PeriodSoftClose) => PeriodState::SoftClosed,
            Some(StepKind::PeriodClose) => PeriodState::Closed,
            Some(StepKind::PeriodLock) => PeriodState::Locked,
            _ => state,
        };
    }
    state
}

/// One variant's P cells, grouped by entry and ordered by period state
/// (then by expectation and enumeration order). `enumerations` are A5a's
/// tables of the variant's P targets.
///
/// # Errors
///
/// A table whose target names no intent with an authored idempotency key,
/// a `period_state_at_commit` value outside [`PeriodState`], or a plan that
/// [`SweepPlan::check`] refuses.
pub fn sweep_plan(
    case: &Case,
    variant: &str,
    enumerations: &[Enumeration],
) -> Result<SweepPlan, LoadError> {
    let err = |row: &str, kind: LoadErrorKind, detail: String| LoadError {
        file: "expectations.toml".into(),
        line: None,
        kind,
        row: Some(row.to_string()),
        detail,
    };
    let book = case.books.get(variant).ok_or_else(|| {
        err(
            variant,
            LoadErrorKind::DanglingKey,
            format!("`{variant}` has no book"),
        )
    })?;
    let authored = case
        .expectations
        .as_ref()
        .map(|s| s.branch_cells.as_slice())
        .unwrap_or_default();
    let is_p = |id: &str| {
        case.expectations
            .as_ref()
            .and_then(|s| s.get(id))
            .is_some_and(|e| e.kind == ExpectationType::P)
    };
    let mut plan = SweepPlan::default();
    for e in enumerations.iter().filter(|e| is_p(&e.expectation)) {
        let intent = book
            .intents
            .iter()
            .find(|i| i.id == e.target)
            .or_else(|| {
                let mut by_fact = book.intents.iter().filter(|i| i.fact == e.target);
                let one = by_fact.next()?;
                by_fact.next().is_none().then_some(one)
            })
            .ok_or_else(|| {
                err(
                    &e.expectation,
                    LoadErrorKind::DanglingKey,
                    format!("target `{}` names no one intent of `{variant}`", e.target),
                )
            })?;
        let intent_key = intent.idempotency_key.clone().ok_or_else(|| {
            err(
                &e.expectation,
                LoadErrorKind::MissingField,
                format!(
                    "{} has no authored idempotency key to derive its cells' keys from",
                    intent.id
                ),
            )
        })?;
        let state_attr = e
            .attrs
            .iter()
            .position(|a| a.as_str() == "period_state_at_commit");
        let at_step = state_at(book, &intent.id);
        let mut cells = Vec::new();
        for c in &e.cells {
            let state = match state_attr {
                Some(i) => PeriodState::parse(&c.key[i]).ok_or_else(|| {
                    err(
                        &e.expectation,
                        LoadErrorKind::UnknownValue,
                        format!("`{}` is not a period state", c.key[i]),
                    )
                })?,
                None => at_step,
            };
            let row = authored.iter().find(|a| {
                a.expectation == e.expectation && a.target == e.target && a.cell == c.key
            });
            cells.push(SweepCell {
                expectation: e.expectation.clone(),
                target: e.target.clone(),
                attrs: e.attrs.clone(),
                key: c.key.clone(),
                state,
                record_consistent: c.record_consistent,
                default: c.default,
                idempotency_key: cell_key(&intent_key, &c.key),
                expect: row.and_then(|r| r.fields.str("expect")).map(str::to_string),
                pending: row.and_then(|r| r.pending()).map(str::to_string),
            });
        }
        match plan.groups.iter_mut().find(|g| g.intent == intent.id) {
            Some(g) => g.cells.extend(cells),
            None => plan.groups.push(SweepGroup {
                variant: variant.to_string(),
                intent: intent.id.clone(),
                intent_key,
                cells,
            }),
        }
    }
    // A CF row of a P parent (§2.6, A5b): the parent target's default cell
    // (the documented reading) with one branched attribute changed, decided
    // on the parent's entry book. It is a counterfactual, never the record,
    // and its key is its own.
    if let Some(set) = case.expectations.as_ref() {
        for cf in set
            .expectations
            .iter()
            .filter(|e| e.kind == ExpectationType::Cf)
        {
            let (Some(parent), Some(attr), Some(value)) = (
                cf.fields.str("parent"),
                cf.fields.str("changed_attribute"),
                cf.fields.str("changed_value"),
            ) else {
                continue;
            };
            let Some(table) = enumerations.iter().find(|e| e.expectation == parent) else {
                continue;
            };
            let Some(base) = table.cells.iter().find(|c| c.default) else {
                return Err(err(
                    &cf.id,
                    LoadErrorKind::MissingField,
                    format!(
                        "{parent}'s target {} marks no `default` cell for {} to change",
                        table.target, cf.id
                    ),
                ));
            };
            let Some(at) = table.attrs.iter().position(|a| a.as_str() == attr) else {
                return Err(err(
                    &cf.id,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`changed_attribute = \"{attr}\"` is not a branched attribute of {parent}"
                    ),
                ));
            };
            let mut key = base.key.clone();
            key[at] = value.to_string();
            let Some(group) = plan.groups.iter_mut().find(|g| {
                book.intents
                    .iter()
                    .any(|i| i.id == g.intent && (i.id == table.target || i.fact == table.target))
            }) else {
                continue;
            };
            let state = match table
                .attrs
                .iter()
                .position(|a| a.as_str() == "period_state_at_commit")
            {
                Some(i) => PeriodState::parse(&key[i]).ok_or_else(|| {
                    err(
                        &cf.id,
                        LoadErrorKind::UnknownValue,
                        format!("`{}` is not a period state", key[i]),
                    )
                })?,
                None => state_at(book, &group.intent),
            };
            let mut own = vec![cf.id.clone()];
            own.extend(key.iter().cloned());
            group.cells.push(SweepCell {
                expectation: cf.id.clone(),
                target: table.target.clone(),
                attrs: table.attrs.clone(),
                key,
                state,
                record_consistent: false,
                default: false,
                idempotency_key: cell_key(&group.intent_key, &own),
                expect: cf.fields.str("expect").map(str::to_string),
                pending: None,
            });
        }
    }
    for g in &mut plan.groups {
        // Stable: within a state, expectation and enumeration order stay.
        g.cells.sort_by_key(|c| c.state);
    }
    plan.check(book)
        .map_err(|d| err(variant, LoadErrorKind::DuplicateId, d))?;
    Ok(plan)
}

/// One co-resident D cell: the cell and the target copy that encodes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellCopy {
    pub cell: Cell,
    /// `<target intent>~c<n>`, n the cell's 1-based position in the table.
    pub intent: String,
}

/// A D target's cells as co-resident entries (§3.3): the variant's book
/// with, right after the target's step, one copy of the target per cell of
/// `table`, each encoding its cell by the cell's first seeded witness (A5a)
/// and posted under its own [`cell_key`]. The copies are each other's
/// filler; the target itself stays, since later steps may name it.
///
/// On a migration stem the target is staged by the `migrate_stage` step
/// whose range holds it, and each copy is staged as a chunk of its own by a
/// `migrate_stage` step right after that one (A8b); an `approvals_recorded`
/// cell sets the copy's legacy `source_approved_by` (rule
/// `legacy_approval_pair`).
///
/// # Errors
///
/// A target with no intent or stage step or no authored key, or a cell
/// attribute with no co-resident encoding.
pub fn coresident(
    case: &Case,
    variant: &str,
    table: &Enumeration,
) -> Result<(BookVariant, Vec<CellCopy>), LoadError> {
    let err = |kind: LoadErrorKind, detail: String| LoadError {
        file: "expectations.toml".into(),
        line: None,
        kind,
        row: Some(table.expectation.clone()),
        detail,
    };
    let mut book = case.books.get(variant).cloned().ok_or_else(|| {
        err(
            LoadErrorKind::DanglingKey,
            format!("`{variant}` has no book"),
        )
    })?;
    let target = book
        .intents
        .iter()
        .find(|i| i.id == table.target)
        .or_else(|| {
            let mut by_fact = book.intents.iter().filter(|i| i.fact == table.target);
            let one = by_fact.next()?;
            by_fact.next().is_none().then_some(one)
        })
        .cloned()
        .ok_or_else(|| {
            err(
                LoadErrorKind::DanglingKey,
                format!(
                    "target `{}` names no one intent of `{variant}`",
                    table.target
                ),
            )
        })?;
    let key = target.idempotency_key.clone().ok_or_else(|| {
        err(
            LoadErrorKind::MissingField,
            format!("{} has no authored idempotency key", target.id),
        )
    })?;
    let staged = book.kind == VariantKind::Migration;
    let target_pos = book.intents.iter().position(|i| i.id == target.id);
    let holds = |range: &str| {
        let Some((a, b)) = range.split_once("..") else {
            return false;
        };
        let pos = |id: &str| book.intents.iter().position(|i| i.id == id);
        matches!((pos(a), pos(b), target_pos), (Some(a), Some(b), Some(t)) if a <= t && t <= b)
    };
    let at = book
        .steps
        .iter()
        .position(|s| {
            if staged {
                s.step_kind() == Some(StepKind::MigrateStage) && holds(&s.reference)
            } else {
                s.step_kind() == Some(StepKind::Intent) && s.reference == target.id
            }
        })
        .ok_or_else(|| {
            err(
                LoadErrorKind::DanglingKey,
                format!(
                    "{} has no {} step to post its cells beside",
                    target.id,
                    if staged { "migrate_stage" } else { "intent" }
                ),
            )
        })?;
    let target_legs: Vec<_> = book
        .legs
        .iter()
        .filter(|l| l.intent == target.id)
        .cloned()
        .collect();
    let mut copies = Vec::new();
    for (n, cell) in table.cells.iter().enumerate() {
        let id = format!("{}~c{}", target.id, n + 1);
        let mut it = target.clone();
        it.id.clone_from(&id);
        it.idempotency_key = Some(cell_key(&key, &cell.key));
        let mut legs = target_legs.clone();
        for l in &mut legs {
            l.intent.clone_from(&id);
        }
        let witness = witnesses(&case.header.id, &table.expectation, cell, 1);
        let values = witness
            .first()
            .map(|w| w.values.as_slice())
            .unwrap_or_default();
        for ((attr, part), value) in table.attrs.iter().zip(&cell.parts).zip(values) {
            match (part, value) {
                (CellPart::Legs { .. }, WitnessValue::Legs(amounts)) => {
                    for (ordinal, minor) in amounts {
                        if let Some(l) = legs.iter_mut().find(|l| l.ordinal == *ordinal) {
                            l.amount_literal = format_amount(*minor, unit_scale(&l.unit));
                        }
                    }
                }
                (_, WitnessValue::Day(d)) if *attr == BranchAttribute::EffectiveDate => {
                    it.effective_date = d.to_string();
                }
                (_, WitnessValue::Day(d)) if *attr == BranchAttribute::DocumentDate => {
                    it.document_date = Some(d.to_string());
                }
                (_, WitnessValue::Class(v)) if *attr == BranchAttribute::EntryClass => {
                    it.class.clone_from(v);
                }
                (_, WitnessValue::Class(v))
                    if *attr == BranchAttribute::EvidenceAttached && v == "none" =>
                {
                    it.evidence = None;
                }
                (_, WitnessValue::Class(v))
                    if *attr == BranchAttribute::EvidenceAttached
                        && v == "placeholder_reviewed" => {}
                (_, WitnessValue::Class(v))
                    if staged
                        && *attr == BranchAttribute::ApprovalsRecorded
                        && v == "approved_by_is_entered_by" =>
                {
                    it.source_approved_by.clone_from(&it.source_entered_by);
                }
                (_, WitnessValue::Class(v))
                    if staged
                        && *attr == BranchAttribute::ApprovalsRecorded
                        && v == "entered_by_only" =>
                {
                    it.source_approved_by = None;
                }
                _ => {
                    return Err(err(
                        LoadErrorKind::UnknownValue,
                        format!(
                            "a D cell of `{}` has no co-resident encoding yet",
                            attr.as_str()
                        ),
                    ));
                }
            }
        }
        let mut step = book.steps[at].clone();
        step.reference = if staged {
            format!("{id}..{id}")
        } else {
            id.clone()
        };
        book.steps.insert(at + 1 + n, step);
        book.intents.push(it);
        book.legs.extend(legs);
        copies.push(CellCopy {
            cell: cell.clone(),
            intent: id,
        });
    }
    Ok((book, copies))
}

/// A registered unit's scale (2 when unknown, as A6 reads it).
fn unit_scale(unit: &str) -> u8 {
    fa_registry::units_embedded()
        .ok()
        .and_then(|units| units.into_iter().find(|u| u.code == unit))
        .map_or(2, |u| u.scale)
}

/// Which cells a run evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cells {
    /// The default branch cell only.
    DefaultOnly,
    /// The default cell and every branch cell.
    All,
}

/// One book build: a variant under one filler spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSpec {
    pub variant: String,
    pub filler: FillerSpec,
    pub cells: Cells,
}

/// The combination rule (§3.3): every filler spec (seeded, empty,
/// extremal) of every variant runs the default cell; the empty spec alone
/// also runs every branch cell. A tier's filler discipline does not depend
/// on target attributes, so this is sound; class equivalence is
/// property-tested separately (A5a).
///
/// # Errors
///
/// As [`filler::specs`].
pub fn runs(case: &Case, tiers: &Tiers) -> Result<Vec<RunSpec>, LoadError> {
    let mut out = Vec::new();
    for book in case.books.values() {
        // A book with several filler variants has an empty spec for each;
        // its branch cells run once, on the first.
        let mut branch_cells_run = false;
        for spec in filler::specs(case, book, tiers)? {
            let cells = if spec.kind == FillerKind::Empty && !branch_cells_run {
                branch_cells_run = true;
                Cells::All
            } else {
                Cells::DefaultOnly
            };
            out.push(RunSpec {
                variant: book.stem.clone(),
                filler: spec,
                cells,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "sweep_tests.rs"]
mod tests;
