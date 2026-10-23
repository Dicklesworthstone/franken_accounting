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
//! A diff binds the scenario body, its intent records, the fork sequence and
//! the replay's `SeqMap` digest; [`ScenarioDiffCertificate`] makes it a
//! retained, replayable certificate (`fa scenario diff --certify`, `fa
//! replay`). No-claim boundary: a read of the materialization (`--branch
//! scenario:<name>`) is not certified.

use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{PostRequest, ScenarioRecorded, ScenarioView, SeqMap};
use fa_model::{Oid, domain_digest};
use fa_registers::TrialBalance;
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use fa_journal::scenario::{Coordinates, MaterializeRefusal};

use crate::{Book, BookError, Outcome};

mod certificate;

pub use certificate::{
    CERTIFICATE_FORMAT as SCENARIO_DIFF_CERTIFICATE_FORMAT, CertifiedScenarioDiff,
    LEGACY_CERTIFICATE_FORMAT as LEGACY_SCENARIO_DIFF_CERTIFICATE_FORMAT,
    OUTPUT_FORMAT as SCENARIO_DIFF_OUTPUT_FORMAT, ScenarioDiffCertificate,
};

const INTENTS_DOMAIN: &[u8] = b"fa:scenario-intents:v1";

/// The ordinary replay preserves the native coordinates needed by bank
/// closes. Compressed replay exists only to reproduce an older v1
/// certificate; it never selects the policy for a new scenario result.
#[derive(Clone, Copy)]
enum ScenarioReplay {
    Protected,
    LegacyCertificateV1,
}

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
    /// Pending (reserved, unposted) amounts, as the trial balance folds
    /// them apart from posted ones.
    pub trunk_debits_pending: i128,
    pub trunk_credits_pending: i128,
    pub scenario_debits_pending: i128,
    pub scenario_credits_pending: i128,
    /// The same signed change over the pending columns.
    pub pending_delta: i128,
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
        format!(
            "list the book's scenarios with `fa scenario list --json`, or fork this one with `fa scenario fork {}`",
            fa_journal::refusal::command_word(name)
        ),
    )
    .at("scenario", name)
}

/// The refusal of the intent at `ordinal`, which its scenario names. The
/// replay is fixed at the fork, so a fix that changes trunk (a document
/// added, a period reopened, authority issued) reaches only a scenario
/// forked after that change; the fix says so.
fn in_scenario(name: &str, fork_at: CommitSeq, ordinal: usize, refusal: Refusal) -> Refusal {
    Refusal {
        message: format!(
            "scenario `{name}` intent #{ordinal} does not post into the scenario's replay: {}",
            refusal.message
        ),
        fix: format!(
            "{} (the scenario replays trunk as known at sequence {}: a trunk change after that reaches only a scenario forked after it)",
            refusal.fix, fork_at.0
        ),
        ..refusal
    }
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
        let through = view.intents.len();
        self.materialize(view, through)
    }

    /// The scratch replay at the fork plus the scenario's first `through`
    /// intents, in planning order (all of them except when a certificate
    /// replays the prefix it covered).
    fn materialize(&mut self, view: ScenarioView, through: usize) -> Outcome<ScenarioBook> {
        self.materialize_with_replay(view, through, ScenarioReplay::Protected)
    }

    fn materialize_with_replay(
        &mut self,
        view: ScenarioView,
        through: usize,
        replay: ScenarioReplay,
    ) -> Outcome<ScenarioBook> {
        self.materialize_with(view, through, replay, None)
    }

    /// The materialization, through fa-journal's factory (so a case-bound
    /// class rehearses in scratch and nowhere else), plus `candidate` as
    /// the last request when given: its entry is then `entries`' last.
    fn materialize_with(
        &mut self,
        view: ScenarioView,
        through: usize,
        replay: ScenarioReplay,
        candidate: Option<PostRequest>,
    ) -> Outcome<ScenarioBook> {
        let mut requests = view
            .intents
            .iter()
            .take(through)
            .map(|planned| scratch_request(planned.intent.clone(), &planned.capability))
            .collect::<Result<Vec<_>, _>>()?;
        requests.extend(candidate);
        let coordinates = match replay {
            ScenarioReplay::Protected => Coordinates::Protected,
            ScenarioReplay::LegacyCertificateV1 => Coordinates::LegacyV1,
        };
        let fork_at = view.body.fork_at;
        let (book, map, entries) =
            match self.materialize_scenario_scratch(fork_at, coordinates, requests)? {
                Ok(materialized) => materialized,
                Err(MaterializeRefusal::Replay(refusal)) => return Ok(Err(refusal)),
                Err(MaterializeRefusal::Intent(i, refusal)) => {
                    return Ok(Err(in_scenario(&view.body.name, fork_at, i + 1, refusal)));
                }
            };
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
        // Authority before observation, and every other check before any
        // replay: the kernel admits the planner's authority over this intent
        // (as a dry run of it on trunk is admitted), the scenario's owner,
        // state and start date, or finds the identical retry, whose record is
        // the outcome. Nothing is replayed or rehearsed for a refused intent.
        let retry = match self.admit_scenario_intent(name, &intent, &capability)? {
            Ok(retry) => retry,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(view) = self.scenario(name)? else {
            return Ok(Err(unknown(name)));
        };
        let position = |record: VId, view: &ScenarioView| {
            view.intents
                .iter()
                .position(|planned| planned.record == record)
                .map_or(view.intents.len() + 1, |i| i + 1)
        };
        if let Some(recorded) = retry {
            return Ok(Ok(ScenarioRun {
                ordinal: position(recorded.control_entry, &view),
                rehearsed: None,
                recorded,
            }));
        }
        let ordinal = view.intents.len() + 1;
        let through = view.intents.len();
        let candidate = scratch_request(intent.clone(), &capability)?;
        let scenario = match self.materialize_with(
            view,
            through,
            ScenarioReplay::Protected,
            Some(candidate),
        )? {
            Ok(scenario) => scenario,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let rehearsed = *scenario.entries.last().ok_or_else(|| {
            BookError::Kernel(fa_journal::KernelError::Corrupt(
                "a scenario rehearsal posted no entry for its intent".into(),
            ))
        })?;
        Ok(self
            .record_scenario_intent(capability, name, intent)?
            .map(|recorded| ScenarioRun {
                ordinal,
                rehearsed: (!recorded.already_recorded).then_some(rehearsed),
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
        let through = view.intents.len();
        self.diff_view(view, through, &trunk, periods, activity)
    }

    /// The diff of `view`'s materialization through its first `through`
    /// intents against `trunk` (trunk as known at the fork, over the same
    /// periods): what [`Book::scenario_diff`] reports and a certificate
    /// replays.
    fn diff_view(
        &mut self,
        view: ScenarioView,
        through: usize,
        trunk: &TrialBalance,
        periods: &[String],
        activity: bool,
    ) -> Outcome<ScenarioDiff> {
        self.diff_view_with_replay(
            view,
            through,
            trunk,
            periods,
            activity,
            ScenarioReplay::Protected,
        )
    }

    fn diff_view_with_replay(
        &mut self,
        view: ScenarioView,
        through: usize,
        trunk: &TrialBalance,
        periods: &[String],
        activity: bool,
        replay: ScenarioReplay,
    ) -> Outcome<ScenarioDiff> {
        let fork_at = view.body.fork_at;
        let scenario = match self.materialize_with_replay(view, through, replay)? {
            Ok(scenario) => scenario,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let other = if activity {
            scenario.book.period_activity(periods, None)?
        } else {
            scenario.book.trial_balance_at(periods, None)?
        };
        let rows = diff_rows(trunk, &other)?;
        let view = &scenario.view;
        let records: Vec<[u8; 16]> = view
            .intents
            .iter()
            .take(through)
            .map(|planned| planned.record.0.to_le_bytes())
            .collect();
        let parts: Vec<&[u8]> = records.iter().map(<[u8; 16]>::as_slice).collect();
        Ok(Ok(ScenarioDiff {
            name: view.body.name.clone(),
            scenario: view.vid,
            body_digest: view.body.digest()?,
            intents_digest: domain_digest(INTENTS_DOMAIN, &parts),
            intents: through,
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
/// its planner holding only the posting operations that planner actually
/// carried: `post`, `post_softclosed`, `post_closed`, `reconcile` and, for a
/// Revision case's Revision entries, `restate`. Period exceptions and
/// protected cash therefore retain their native admission without granting
/// close or any unrelated authority. The
/// planner's own authority (ops, ceilings, scope caveats, currency and
/// revocation) was admitted on trunk when the
/// intent was recorded, as a dry run of it is. The scratch book is the
/// scenario's review copy, where an Agent's trunk-write denial (a rule about
/// the real trunk) does not apply; every posting law does, and the intent's
/// own approvals are evaluated there. Not re-applied: profile-dependent
/// separation of duties (an Agent preparer's extra Human approver on
/// trunk), since the embedded capability is a Human one.
fn scratch_request(
    intent: fa_journal::PostIntent,
    planner: &fa_journal::Capability,
) -> Result<PostRequest, BookError> {
    let principal = intent.proposal().principal_ref;
    // These are the only additional operations used by the batchable
    // posting classes and a Revision case's Revision entries (`restate`).
    // A Closing or Restatement intent cannot enter a scenario, so their
    // other operations are never copied.
    let ops: Vec<&str> = [
        fa_policy::Op::Post,
        fa_policy::Op::PostSoftclosed,
        fa_policy::Op::PostClosed,
        fa_policy::Op::Reconcile,
        fa_policy::Op::Restate,
    ]
    .into_iter()
    .filter(|op| planner.ops().contains(op))
    .map(fa_policy::Op::name)
    .collect();
    let capability = fa_journal::Capability::embedded(principal, &ops)
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
/// then unit, with the exact change in its net balance: trunk is the
/// before side and the scenario the after side of
/// [`crate::ledger_diff::trial_balance_changes`].
fn diff_rows(
    trunk: &TrialBalance,
    scenario: &TrialBalance,
) -> Result<Vec<ScenarioDiffRow>, BookError> {
    Ok(crate::ledger_diff::trial_balance_changes(trunk, scenario)?
        .into_iter()
        .map(|change| ScenarioDiffRow {
            account: change.account,
            code: change.code,
            name: change.name,
            unit_id: change.unit_id,
            trunk_debits: change.before_debits,
            trunk_credits: change.before_credits,
            scenario_debits: change.after_debits,
            scenario_credits: change.after_credits,
            delta: change.delta,
            trunk_debits_pending: change.before_debits_pending,
            trunk_credits_pending: change.before_credits_pending,
            scenario_debits_pending: change.after_debits_pending,
            scenario_credits_pending: change.after_credits_pending,
            pending_delta: change.pending_delta,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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
    fn a_pending_only_change_is_a_changed_row() {
        let trunk = tb(vec![row("1000", 1, 500, 100)]);
        let mut held = row("1000", 1, 500, 100);
        held.debits_pending = 40;
        let scenario = tb(vec![held]);
        let rows = diff_rows(&trunk, &scenario).unwrap();
        assert_eq!(
            rows.len(),
            1,
            "a reservation the scenario makes is a change"
        );
        assert_eq!((rows[0].delta, rows[0].pending_delta), (0, 40));
        assert_eq!(rows[0].scenario_debits_pending, 40);
    }

    #[test]
    fn a_diff_refuses_rather_than_wraps_an_out_of_range_net() {
        let trunk = tb(vec![row("1000", 1, 0, 0)]);
        let scenario = tb(vec![row("1000", 1, i128::MIN, 1)]);
        assert!(diff_rows(&trunk, &scenario).is_err());
    }
}
