//! Scenario materialization and ledger diffs (plan §15.2, §15.6.5; bead
//! fa-k07b).
//!
//! Until substrate branches ship, a scenario is materialized exactly as plan
//! §15.2 states: the trunk journal's accounting objects at the scenario's
//! fork sequence are replayed into a scratch book
//! ([`Book::replay_into_scratch`]), then every counterfactual intent is
//! posted, in planning order, through that scratch book's ordinary posting
//! pipeline, so every posting law runs again. Trunk never changes. A diff
//! compares trunk as known at the fork sequence with the materialization
//! over the same periods, per (account, unit).
//!
//! No-claim boundary: a diff binds the scenario body, its intent records, the
//! fork sequence and the replay's `SeqMap` digest, but it is not yet a
//! retained, replayable `DiffCertificate` (`fa replay`), and a read of the
//! materialization (`--branch scenario:<name>`) is not certified.

use std::collections::BTreeMap;

use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{PostRequest, ScenarioRecorded, ScenarioView, SeqMap};
use fa_model::{Oid, domain_digest};
use fa_registers::TrialBalance;
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::{Book, BookError, BookKeys, Entropy, Outcome};

const INTENTS_DOMAIN: &[u8] = b"fa:scenario-intents:v1";

/// A scenario's materialization: a scratch replay of its trunk prefix plus
/// its intents.
pub struct ScenarioBook {
    pub book: Book,
    pub map: SeqMap,
    pub view: ScenarioView,
    /// The scratch entry each intent posted, in planning order.
    pub entries: Vec<VId>,
}

/// A recorded counterfactual intent and the scratch entry its rehearsal
/// posted (absent on a recorded retry, which rehearses nothing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioRun {
    pub recorded: ScenarioRecorded,
    pub rehearsed: Option<VId>,
    /// The intent's position in the scenario, from 1.
    pub ordinal: usize,
}

/// One (account, unit) whose balance the scenario changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioDiffRow {
    pub account: VId,
    pub code: String,
    pub name: String,
    pub unit_id: u32,
    pub trunk_debits: i128,
    pub trunk_credits: i128,
    pub scenario_debits: i128,
    pub scenario_credits: i128,
    /// `(scenario debits − credits) − (trunk debits − credits)`.
    pub delta: i128,
}

/// The ledger-level difference a scenario makes (plan §15.6.5: the
/// damages schedule of a but-for scenario).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioDiff {
    pub name: String,
    pub scenario: VId,
    pub body_digest: [u8; 32],
    /// `H("fa:scenario-intents:v1" ‖ each Plan record vid, in order)`.
    pub intents_digest: [u8; 32],
    pub intents: usize,
    pub fork_at: CommitSeq,
    pub from: Option<DateDay>,
    pub assumptions: Vec<Oid>,
    pub periods: Vec<String>,
    pub activity: bool,
    pub seq_map_digest: [u8; 32],
    /// The materialization's head (the scratch book's own sequence).
    pub scenario_known_at: CommitSeq,
    /// Only the rows the scenario changes, by account code then unit.
    pub rows: Vec<ScenarioDiffRow>,
}

fn unknown(name: &str) -> Refusal {
    Refusal::new(
        code::SCENARIO_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no scenario named `{name}`"),
        "plan §15.2 (scenarios; bead fa-k07b)",
        "list the book's scenarios with `fa scenario list --json`, or fork one with `fa scenario fork <name>`",
    )
}

/// The refusal of the intent at `ordinal`, which its scenario names.
fn in_scenario(name: &str, ordinal: usize, refusal: Refusal) -> Refusal {
    Refusal {
        message: format!(
            "scenario `{name}` intent #{ordinal} does not post into the scenario's replay: {}",
            refusal.message
        ),
        ..refusal
    }
}

fn overflow(what: &str) -> BookError {
    BookError::Kernel(fa_journal::KernelError::Corrupt(format!(
        "scenario diff {what} exceeds the exact i128 range"
    )))
}

impl Book {
    /// Materialize the scenario `name` (plan §15.2): replay the trunk prefix
    /// at its fork sequence into a scratch book, then post its intents in
    /// order under their planners, each through every posting law of the
    /// scratch book. The scratch book keeps this book's seal key (its sealed
    /// text stays readable) under fresh storage keys.
    pub fn materialize_scenario(&mut self, name: &str) -> Outcome<ScenarioBook> {
        let Some(view) = self.scenario(name)? else {
            return Ok(Err(unknown(name)));
        };
        self.materialize(view)
    }

    fn materialize(&mut self, view: ScenarioView) -> Outcome<ScenarioBook> {
        let keys = BookKeys::generate(&Entropy::production())?;
        let (mut book, map) =
            match self.replay_into_scratch(Some(view.body.fork_at), keys, Entropy::production())? {
                Ok(replayed) => replayed,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let mut entries = Vec::with_capacity(view.intents.len());
        for (i, planned) in view.intents.iter().enumerate() {
            match book.post(scratch_request(planned.intent.clone())?)? {
                Ok(posted) => entries.push(posted.entry_ref().vid),
                Err(refusal) => return Ok(Err(in_scenario(&view.body.name, i + 1, refusal))),
            }
        }
        Ok(Ok(ScenarioBook {
            book,
            map,
            view,
            entries,
        }))
    }

    /// Run `intent` in the open scenario `name`: rehearse it on the
    /// scenario's materialization (after every earlier intent), then journal
    /// it as the scenario's next Plan record. A refused intent never enters
    /// the scenario; trunk receives the record only, never the entry.
    pub fn run_in_scenario(
        &mut self,
        capability: fa_journal::Capability,
        name: &str,
        intent: fa_journal::PostIntent,
    ) -> Outcome<ScenarioRun> {
        let Some(view) = self.scenario(name)? else {
            return Ok(Err(unknown(name)));
        };
        let ordinal = view.intents.len() + 1;
        let open = view.state == fa_journal::ScenarioState::Open;
        // An identical retry (or a closed scenario) is the kernel's to judge
        // before any rehearsal: the record is the outcome.
        let retry = view.intents.iter().position(|planned| {
            planned.intent.proposal().idempotency_key == intent.proposal().idempotency_key
                && planned.capability.holder() == capability.holder()
        });
        let rehearsed = if open && retry.is_none() {
            let mut scenario = match self.materialize(view)? {
                Ok(scenario) => scenario,
                Err(refusal) => return Ok(Err(refusal)),
            };
            match scenario.book.post(scratch_request(intent.clone())?)? {
                Ok(posted) => Some(posted.entry_ref().vid),
                Err(refusal) => return Ok(Err(in_scenario(name, ordinal, refusal))),
            }
        } else {
            None
        };
        Ok(self
            .record_scenario_intent(capability, name, intent)?
            .map(|recorded| ScenarioRun {
                ordinal: retry.map_or(ordinal, |i| i + 1),
                rehearsed: if recorded.already_recorded {
                    None
                } else {
                    rehearsed
                },
                recorded,
            }))
    }

    /// The ledger-level difference the scenario `name` makes over `periods`:
    /// trunk as known at the fork sequence against the materialization, per
    /// (account, unit), stock balances or (`activity`) period movement.
    /// Only changed rows are listed; amounts are exact.
    pub fn scenario_diff(
        &mut self,
        name: &str,
        periods: &[String],
        activity: bool,
    ) -> Outcome<ScenarioDiff> {
        let Some(view) = self.scenario(name)? else {
            return Ok(Err(unknown(name)));
        };
        let fork_at = view.body.fork_at;
        let trunk = if activity {
            self.period_activity(periods, Some(fork_at))?
        } else {
            self.trial_balance_at(periods, Some(fork_at))?
        };
        let scenario = match self.materialize(view)? {
            Ok(scenario) => scenario,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let other = if activity {
            scenario.book.period_activity(periods, None)?
        } else {
            scenario.book.trial_balance_at(periods, None)?
        };
        let rows = diff_rows(&trunk, &other)?;
        let view = &scenario.view;
        let records: Vec<[u8; 16]> = view
            .intents
            .iter()
            .map(|planned| planned.record.0.to_le_bytes())
            .collect();
        let parts: Vec<&[u8]> = records.iter().map(<[u8; 16]>::as_slice).collect();
        Ok(Ok(ScenarioDiff {
            name: view.body.name.clone(),
            scenario: view.vid,
            body_digest: view.body.digest()?,
            intents_digest: domain_digest(INTENTS_DOMAIN, &parts),
            intents: view.intents.len(),
            fork_at,
            from: view.body.from,
            assumptions: view.assumptions.clone(),
            periods: other.periods.clone(),
            activity,
            seq_map_digest: scenario.map.digest()?,
            scenario_known_at: other.known_at,
            rows,
        }))
    }
}

/// An intent as the scratch book posts it: under an embedded capability of
/// its planner holding `post`. The planner's own authority was admitted when
/// the intent was recorded; the scratch book is the scenario's review copy,
/// where an Agent's trunk-write denial (a rule about the real trunk) does not
/// apply, while every posting law does.
fn scratch_request(intent: fa_journal::PostIntent) -> Result<PostRequest, BookError> {
    let principal = intent.proposal().principal_ref;
    let capability = fa_journal::Capability::embedded(principal, &["post"])
        .map_err(|e| BookError::Kernel(fa_journal::KernelError::Corrupt(e.to_string())))?;
    let approvals = intent.approvals().to_vec();
    Ok(PostRequest {
        proposal: intent.proposal().clone(),
        approvals,
        capability,
        plan_certificate: None,
    })
}

/// Every (account, unit) whose debits or credits differ, by account code
/// then unit, with the exact change in its net balance.
fn diff_rows(
    trunk: &TrialBalance,
    scenario: &TrialBalance,
) -> Result<Vec<ScenarioDiffRow>, BookError> {
    let mut cells: BTreeMap<(String, u32, u128), ScenarioDiffRow> = BTreeMap::new();
    for (side, tb) in [(false, trunk), (true, scenario)] {
        for row in &tb.rows {
            let cell = cells
                .entry((row.code.clone(), row.unit_id, row.account.0))
                .or_insert_with(|| ScenarioDiffRow {
                    account: row.account,
                    code: row.code.clone(),
                    name: row.name.clone(),
                    unit_id: row.unit_id,
                    trunk_debits: 0,
                    trunk_credits: 0,
                    scenario_debits: 0,
                    scenario_credits: 0,
                    delta: 0,
                });
            if side {
                cell.scenario_debits = row.debits;
                cell.scenario_credits = row.credits;
            } else {
                cell.trunk_debits = row.debits;
                cell.trunk_credits = row.credits;
            }
        }
    }
    let mut rows = Vec::new();
    for mut cell in cells.into_values() {
        if (cell.trunk_debits, cell.trunk_credits) == (cell.scenario_debits, cell.scenario_credits)
        {
            continue;
        }
        let scenario_net = cell
            .scenario_debits
            .checked_sub(cell.scenario_credits)
            .ok_or_else(|| overflow("scenario net"))?;
        let trunk_net = cell
            .trunk_debits
            .checked_sub(cell.trunk_credits)
            .ok_or_else(|| overflow("trunk net"))?;
        cell.delta = scenario_net
            .checked_sub(trunk_net)
            .ok_or_else(|| overflow("delta"))?;
        rows.push(cell);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::AccountType;
    use fa_registers::TbRow;

    fn row(code: &str, unit: u32, debits: i128, credits: i128) -> TbRow {
        TbRow {
            account: VId(code.bytes().fold(0u128, |a, b| a * 256 + u128::from(b))),
            code: code.into(),
            name: code.into(),
            account_type: AccountType::ASSET,
            unit_id: unit,
            debits,
            credits,
            debits_pending: 0,
            credits_pending: 0,
        }
    }

    fn tb(rows: Vec<TbRow>) -> TrialBalance {
        TrialBalance {
            periods: vec!["FY2026-P03".into()],
            known_at: CommitSeq(9),
            effective_through: None,
            activity: false,
            rows,
            unit_totals: BTreeMap::new(),
            pending_unit_totals: BTreeMap::new(),
        }
    }

    #[test]
    fn a_diff_lists_exactly_the_changed_cells_with_their_signed_net_change() {
        let trunk = tb(vec![
            row("1000", 1, 500, 100),
            row("4000", 1, 0, 400),
            row("6000", 1, 70, 0),
        ]);
        let scenario = tb(vec![
            row("1000", 1, 750, 100),
            row("4000", 1, 0, 650),
            row("6000", 1, 70, 0),
            row("1000", 2, 5, 0),
        ]);
        let rows = diff_rows(&trunk, &scenario).unwrap();
        let summary: Vec<(&str, u32, i128)> = rows
            .iter()
            .map(|r| (r.code.as_str(), r.unit_id, r.delta))
            .collect();
        assert_eq!(
            summary,
            [("1000", 1, 250), ("1000", 2, 5), ("4000", 1, -250)]
        );
        assert_eq!(
            (rows[1].trunk_debits, rows[1].trunk_credits),
            (0, 0),
            "a cell only the scenario has starts from zero on trunk"
        );
        assert!(
            diff_rows(&trunk, &trunk).unwrap().is_empty(),
            "no intents, no difference"
        );
        let vanished = tb(vec![row("1000", 1, 500, 100), row("4000", 1, 0, 400)]);
        let rows = diff_rows(&trunk, &vanished).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].code.as_str(), rows[0].delta), ("6000", -70));
    }

    #[test]
    fn a_diff_refuses_rather_than_wraps_an_out_of_range_net() {
        let trunk = tb(vec![row("1000", 1, 0, 0)]);
        let scenario = tb(vec![row("1000", 1, i128::MIN, 1)]);
        assert!(diff_rows(&trunk, &scenario).is_err());
    }
}
