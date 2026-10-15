//! Migration-aware balance proofs (plan §8.6/§13.3, fa-e00, fa-n6fh).
//!
//! V2 carries the complete envelope prefix, selected candidate records plus
//! EVERY MigrationControl record, and the bodies of only selected runs.
//! V3 additionally carries EVERY prefix record, allowing the independent
//! verifier to derive all scope selectors rather than trusting an index.
//! Each selected run body is bound to Open; projections never decide visibility.
//!
//! V3 is posted-balance recomputation, not proof of migration approval,
//! trial-balance tie-out, or economic truth. Its whole-prefix entry disclosure
//! requires whole-book read and production authority at the facade. Explicit
//! legacy producers retain v1/v2 bytes, but partial-payload proofs now have
//! only membership scope in the independent verifier.

mod transport;

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::migration::{RunBody, RunMode, kind};
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_journal::rows::bytes;
use fa_model::symbols::{label, property};
use fa_model::{ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin};
use fa_money::Side;
use fgdb::Database;
use fgdb_types::VId;

use crate::{AccumulatorState, Journal, Leaf, LeafEnvelope, code};

pub use transport::MAX_BALANCE_PROOF_BYTES;
pub const BALANCE_FORMAT_V2: &[u8] = b"fa:acc-balance-proof:v2";
pub const BALANCE_FORMAT_V3: &[u8] = b"fa:acc-balance-proof:v3";
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

type Selected<'a> = Vec<(usize, &'a Leaf, Entry)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProofMode {
    Automatic,
    Migration,
    Complete,
}

struct Run<'a> {
    open_index: usize,
    open_day: i32,
    body_digest: [u8; 32],
    terminal: Option<(usize, u8)>,
    body: Option<&'a RunBody>,
}

fn refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::MIGRATION_STAGED,
        exit::REFUSAL,
        message.into(),
        "plan §8.6 / §13.3 (migration visibility is authenticated by the journal)",
        "provide the canonical bodies committed by the selected runs' Open records; investigate inconsistent lifecycle records rather than trusting run-state projections",
    )
}

fn candidate(leaf: &Leaf, account: VId, unit: u32, through: Option<i32>) -> bool {
    let e = &leaf.envelope;
    e.class != EntryClass::PENDING
        && e.account_vids.binary_search(&account).is_ok()
        && e.unit_ids.binary_search(&unit).is_ok()
        && through.is_none_or(|day| e.effective_day.is_some_and(|d| d <= day))
}

fn select(
    journal: &Journal,
    account: VId,
    unit: u32,
    through: Option<i32>,
    complete: bool,
) -> Outcome<(Selected<'_>, BTreeSet<VId>)> {
    if complete && let Err(r) = transport::preflight(journal, through) {
        return Ok(Err(r));
    }
    let mut records = Vec::new();
    let mut needed = BTreeSet::new();
    for (index, leaf) in journal.leaves.iter().enumerate() {
        let selected = leaf.envelope.class == EntryClass::MIGRATION_CONTROL
            || candidate(leaf, account, unit, through);
        if !complete && !selected {
            continue;
        }
        let entry = Entry::decode(&leaf.payload)?;
        let p = &entry.proposal;
        let rebuilt = LeafEnvelope::of_entry(
            &entry,
            leaf.envelope.commit_seq,
            leaf.envelope.within_commit_ordinal,
        );
        if rebuilt != leaf.envelope
            || rebuilt
                .canonical_bytes()
                .map_err(fa_model::EntryError::Encode)?
                != leaf.envelope_bytes
            || p.canonical_bytes()?.len() != leaf.proposal_len
        {
            return Ok(Err(refusal(format!(
                "leaf {index} disagrees with its authoritative entry payload"
            ))));
        }
        // A complete proof authenticates exclusion too. The record stays in
        // v3's wire prefix but unrelated controls/holds do not enter the fold
        // and unrelated migration bodies are neither fetched nor disclosed.
        if !selected {
            continue;
        }
        match (&p.origin, p.class) {
            (EntryOrigin::Migration { run_ref, .. }, EntryClass::MIGRATION)
                if p.control.is_none() =>
            {
                needed.insert(*run_ref);
            }
            (EntryOrigin::Migration { .. }, _) | (_, EntryClass::MIGRATION) => {
                return Ok(Err(refusal(format!(
                    "leaf {index} has inconsistent migration class, origin, or control"
                ))));
            }
            (_, EntryClass::MIGRATION_CONTROL) => {}
            (EntryOrigin::Control { .. }, _) => {
                return Ok(Err(refusal(format!(
                    "posting candidate {index} has a control origin"
                ))));
            }
            _ if p.control.is_some() => {
                return Ok(Err(refusal(format!(
                    "posting candidate {index} has an unsupported control payload"
                ))));
            }
            _ => {}
        }
        records.push((index, leaf, entry));
    }
    Ok(Ok((records, needed)))
}

#[allow(clippy::too_many_arguments)]
fn encode(
    journal: &Journal,
    records: &Selected<'_>,
    needed: &BTreeSet<VId>,
    account: VId,
    unit: u32,
    through: Option<i32>,
    bodies: &[RunBody],
    complete: bool,
) -> Outcome<Vec<u8>> {
    let mut runs: BTreeMap<VId, Run<'_>> = BTreeMap::new();
    let mut open_order = Vec::new();
    for (index, leaf, entry) in records {
        if entry.proposal.class != EntryClass::MIGRATION_CONTROL {
            continue;
        }
        let p = &entry.proposal;
        let Some(ControlPayload::MigrationControl {
            run_ref,
            kind: transition,
            tie_out_digest,
        }) = &p.control
        else {
            return Ok(Err(refusal(format!(
                "leaf {index} lacks migration control data"
            ))));
        };
        let EntryOrigin::Control {
            control_kind,
            spec_body_digest,
        } = &p.origin
        else {
            return Ok(Err(refusal(format!("leaf {index} lacks a control origin"))));
        };
        if *control_kind != ControlKind::MIGRATION_RUN || !p.legs.is_empty() {
            return Ok(Err(refusal(format!(
                "leaf {index} is not a migration-run control"
            ))));
        }
        match *transition {
            kind::OPEN => {
                let Some(open_day) = leaf.envelope.effective_day else {
                    return Ok(Err(refusal(format!(
                        "Open leaf {index} has no opening day"
                    ))));
                };
                if runs.contains_key(run_ref) || spec_body_digest != tie_out_digest {
                    return Ok(Err(refusal(format!(
                        "duplicate or inconsistent Open at leaf {index}"
                    ))));
                }
                runs.insert(
                    *run_ref,
                    Run {
                        open_index: *index,
                        open_day,
                        body_digest: *tie_out_digest,
                        terminal: None,
                        body: None,
                    },
                );
                open_order.push((*index, *run_ref));
            }
            kind::FINALIZE | kind::ABANDON => {
                let Some(run) = runs.get_mut(run_ref) else {
                    return Ok(Err(refusal(format!(
                        "leaf {index} terminates an unopened run"
                    ))));
                };
                if run.terminal.is_some() {
                    return Ok(Err(refusal(format!("leaf {index} terminates a run twice"))));
                }
                // Finalize/Abandon bind the same immutable RunBody as Open.
                // Their tie-out digest is a different commitment and need not
                // equal the body digest. Check every control, even when this
                // run has no posting candidates in the requested cell.
                if spec_body_digest != &run.body_digest {
                    return Ok(Err(refusal(format!(
                        "terminal leaf {index} names a different run body than its Open at leaf {}",
                        run.open_index
                    ))));
                }
                run.terminal = Some((*index, *transition));
            }
            _ => {
                return Ok(Err(refusal(format!(
                    "leaf {index} has an unknown run transition"
                ))));
            }
        }
    }

    let mut supplied = BTreeSet::new();
    for body in bodies {
        let vid = body.vid();
        if body.book_id != journal.book_id || !needed.contains(&vid) || !supplied.insert(vid) {
            return Ok(Err(refusal(
                "foreign, unrelated, or duplicate migration body",
            )));
        }
        let Some(run) = runs.get_mut(&vid) else {
            return Ok(Err(refusal(
                "a selected migration run has no Open in this prefix",
            )));
        };
        if body.digest()? != run.body_digest || body.opening_date.0 != run.open_day {
            return Ok(Err(refusal(format!(
                "migration body does not match its Open at leaf {}",
                run.open_index
            ))));
        }
        run.body = Some(body);
    }
    if supplied != *needed {
        return Ok(Err(refusal(
            "a selected migration run's authenticated body is missing",
        )));
    }
    let mut witnesses = Vec::new();
    for (index, vid) in open_order {
        if !needed.contains(&vid) {
            continue;
        }
        let body = runs
            .get(&vid)
            .and_then(|run| run.body)
            .ok_or_else(|| KernelError::Corrupt("selected migration body disappeared".into()))?;
        let bytes = body.canonical_bytes()?;
        if bytes.len() > MAX_BODY_BYTES {
            return Ok(Err(refusal(
                "migration body exceeds the balance proof's 8 MiB limit",
            )));
        }
        // Public RunBody values must be representable by the bounded wire
        // decoder, including fields omitted by a mode's canonical encoding.
        // Never return a proof the independent reader cannot consume.
        if RunBody::decode(&bytes)? != *body {
            return Ok(Err(refusal(
                "migration body does not round-trip through its canonical format",
            )));
        }
        witnesses.push((index, bytes));
    }

    let (mut debits, mut credits) = (0i128, 0i128);
    for (index, _, entry) in records {
        let p = &entry.proposal;
        if p.class == EntryClass::MIGRATION_CONTROL {
            continue;
        }
        if let EntryOrigin::Migration { run_ref, .. } = &p.origin {
            let Some(run) = runs.get(run_ref) else {
                return Ok(Err(refusal(format!("chunk {index} names an unopened run"))));
            };
            if *index <= run.open_index
                || run.terminal.is_some_and(|(terminal, _)| *index >= terminal)
            {
                return Ok(Err(refusal(format!(
                    "chunk {index} is outside its run's staging window"
                ))));
            }
            let Some(body) = run.body else {
                return Ok(Err(refusal(format!(
                    "chunk {index} lacks an authenticated run body"
                ))));
            };
            let visible = run
                .terminal
                .is_some_and(|(_, state)| state == kind::FINALIZE)
                && (body.mode != RunMode::FullDetail
                    || body.sole_opening_source
                    || p.effective_date >= body.opening_date);
            if !visible {
                continue;
            }
        }
        for leg in p
            .legs
            .iter()
            .filter(|l| l.account_ref == account && l.amount.unit.0 == unit)
        {
            if leg.amount.mantissa < 0 {
                return Ok(Err(refusal("negative amount in a posted balance leg")));
            }
            let column = match leg.side {
                Side::Debit => &mut debits,
                Side::Credit => &mut credits,
            };
            *column = column
                .checked_add(leg.amount.mantissa)
                .ok_or_else(|| KernelError::Corrupt("a posted balance overflowed i128".into()))?;
        }
    }
    transport::encode(
        journal,
        records,
        witnesses,
        complete,
        transport::Claim {
            account,
            unit,
            through,
            debits,
            credits,
        },
    )
}

impl Journal {
    /// Produce v2 with exactly the run bodies required by this cell/cutoff.
    /// Body order is irrelevant; output follows Open-leaf order. Bodies are
    /// authenticated by Open records, never accepted as claims of run state.
    /// The journal's checkpoint must be trusted independently by the receiver.
    /// Use `balance_proof_complete` to independently prove scope derivation.
    pub fn balance_proof_with_migrations(
        &self,
        account: VId,
        unit: u32,
        through: Option<i32>,
        bodies: &[RunBody],
    ) -> Outcome<Vec<u8>> {
        let (records, needed) = match select(self, account, unit, through, false)? {
            Ok(selection) => selection,
            Err(r) => return Ok(Err(r)),
        };
        encode(
            self, &records, &needed, account, unit, through, bodies, false,
        )
    }

    /// Produce v3, including and checking every prefix entry payload.
    /// This deliberately discloses unrelated, pending and future-effective
    /// entries in the checkpoint; callers must authorize whole-book export.
    /// Run bodies remain restricted to selected migration candidates. This
    /// pure producer grants no authority and never weakens an oversized proof.
    pub fn balance_proof_complete(
        &self,
        account: VId,
        unit: u32,
        through: Option<i32>,
        bodies: &[RunBody],
    ) -> Outcome<Vec<u8>> {
        let (records, needed) = match select(self, account, unit, through, true)? {
            Ok(selection) => selection,
            Err(r) => return Ok(Err(r)),
        };
        encode(
            self, &records, &needed, account, unit, through, bodies, true,
        )
    }
}

/// Export a legacy automatically versioned balance proof. V1 bytes are
/// preserved when the selected cell and cutoff have no migration candidates;
/// otherwise v2 authenticates the supplied migration lifecycle. Partial
/// payloads do not independently prove scope derivation: for that guarantee
/// call `prove_balance_complete` with whole-book disclosure authorization.
pub fn prove_balance<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
    account: VId,
    unit: u32,
    through: Option<i32>,
) -> Outcome<Vec<u8>> {
    prove(
        db,
        book,
        state,
        account,
        unit,
        through,
        ProofMode::Automatic,
    )
}

/// Explicitly produce v2 at a fixed accumulator state, even for a scope
/// without migration candidates. Read historical body bytes at that prefix
/// and authenticate them against Open records; state mirrors are not read.
pub fn prove_balance_with_migrations<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
    account: VId,
    unit: u32,
    through: Option<i32>,
) -> Outcome<Vec<u8>> {
    prove(
        db,
        book,
        state,
        account,
        unit,
        through,
        ProofMode::Migration,
    )
}

/// Produce a payload-complete v3 balance proof at the selected checkpoint.
/// The caller must already hold whole-book read and production authority.
/// Historical migration bodies are still selected from authenticated entries,
/// never current projections, and the proof is refused rather than truncated.
pub fn prove_balance_complete<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
    account: VId,
    unit: u32,
    through: Option<i32>,
) -> Outcome<Vec<u8>> {
    prove(db, book, state, account, unit, through, ProofMode::Complete)
}

fn prove<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
    account: VId,
    unit: u32,
    through: Option<i32>,
    mode: ProofMode,
) -> Outcome<Vec<u8>> {
    let observed_at = db.frontier()?;
    let journal = match Journal::read(db, book, Some(state.through_seq))? {
        Ok(journal) => journal,
        Err(r) => return Ok(Err(r)),
    };
    if AccumulatorState::of_journal(&journal, state.prev_state_oid) != *state {
        return Ok(Err(Refusal::new(
            code::ACCUMULATOR_DRIFT,
            exit::VERIFICATION,
            "the journal does not reproduce the accumulator state",
            "FA-INV-14 (states are recomputed from their journal prefix)",
            "run `fa verify accumulator`; do not issue proofs against an unsupported state",
        )));
    }
    if let Err(r) = journal.verify_unchanged_at(db, observed_at)? {
        return Ok(Err(r));
    }
    let (records, needed) = match select(
        &journal,
        account,
        unit,
        through,
        mode == ProofMode::Complete,
    )? {
        Ok(selection) => selection,
        Err(r) => return Ok(Err(r)),
    };
    if mode == ProofMode::Automatic && needed.is_empty() {
        return journal.balance_proof(account, unit, through);
    }
    let bodies = match run_bodies(db, &journal, &needed)? {
        Ok(bodies) => bodies,
        Err(r) => return Ok(Err(r)),
    };
    encode(
        &journal,
        &records,
        &needed,
        account,
        unit,
        through,
        &bodies,
        mode == ProofMode::Complete,
    )
}

/// The migration runs whose candidates a balance cell and cutoff select:
/// empty exactly when a v1 proof is exact for it.
pub fn runs_needed(
    journal: &Journal,
    account: VId,
    unit: u32,
    through: Option<i32>,
) -> Outcome<BTreeSet<VId>> {
    Ok(select(journal, account, unit, through, false)?.map(|(_, needed)| needed))
}

/// The immutable bodies of `runs` as retained at the journal's prefix, in
/// `runs` order, each checked against the identity it must derive.
pub fn run_bodies<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    journal: &Journal,
    runs: &BTreeSet<VId>,
) -> Outcome<Vec<RunBody>> {
    let mut bodies = Vec::with_capacity(runs.len());
    for run in runs {
        // Only immutable body bytes are needed. read_run also decodes the
        // derived STATE mirror, so it is deliberately not used here: a
        // projection must neither authorize nor prevent the journal proof.
        let Some(row) = db.vertex_at(*run, journal.through_seq)? else {
            return Ok(Err(refusal(format!(
                "migration run {:032x} has no retained body",
                run.0
            ))));
        };
        if !row.labels.contains(&label::MIGRATION_RUN) {
            return Ok(Err(refusal(format!(
                "migration run {:032x} has no MigrationRun label",
                run.0
            ))));
        }
        let raw = bytes(&row, property::FA_PAYLOAD, "migration run body")?;
        if raw.len() > MAX_BODY_BYTES {
            return Ok(Err(refusal(
                "migration body exceeds the balance proof's 8 MiB limit",
            )));
        }
        let body = RunBody::decode(&raw)?;
        if body.vid() != *run {
            return Ok(Err(refusal(format!(
                "migration body does not derive run identity {:032x}",
                run.0
            ))));
        }
        bodies.push(body);
    }
    Ok(Ok(bodies))
}

/// Every run body the balances of a bundle request need, keyed by run, for
/// [`crate::bundle::assemble_with_runs`].
pub fn bundle_run_bodies<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    journal: &Journal,
    request: &crate::bundle::BundleRequest,
) -> Outcome<BTreeMap<VId, RunBody>> {
    let mut runs = BTreeSet::new();
    for b in &request.balances {
        match runs_needed(journal, b.account, b.unit, b.effective_through)? {
            Ok(needed) => runs.extend(needed),
            Err(r) => return Ok(Err(r)),
        }
    }
    let bodies = match run_bodies(db, journal, &runs)? {
        Ok(bodies) => bodies,
        Err(r) => return Ok(Err(r)),
    };
    Ok(Ok(runs.into_iter().zip(bodies).collect()))
}

impl Journal {
    /// The automatically versioned balance proof over this journal: exactly
    /// the v1 bytes when the cell and cutoff have no migration candidates,
    /// otherwise v2 with the needed run bodies taken from `bodies` (see
    /// [`bundle_run_bodies`]). A missing body is refused, never skipped.
    pub fn balance_proof_auto(
        &self,
        account: VId,
        unit: u32,
        through: Option<i32>,
        bodies: &BTreeMap<VId, RunBody>,
    ) -> Outcome<Vec<u8>> {
        let (records, needed) = match select(self, account, unit, through, false)? {
            Ok(selection) => selection,
            Err(r) => return Ok(Err(r)),
        };
        if needed.is_empty() {
            return self.balance_proof(account, unit, through);
        }
        let mut chosen = Vec::with_capacity(needed.len());
        for run in &needed {
            let Some(body) = bodies.get(run) else {
                return Ok(Err(refusal(format!(
                    "migration run {:032x}'s body was not supplied for this balance",
                    run.0
                ))));
            };
            chosen.push(body.clone());
        }
        encode(
            self, &records, &needed, account, unit, through, &chosen, false,
        )
    }
}
