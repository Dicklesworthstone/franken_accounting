//! Known-at instant selection from retained TimeEvidence (plan §7.1a).
//!
//! The journal supplies the tick facts; fa-time resolves their sequence
//! buckets without reading a clock. Every selection records the observed
//! frontier and both brackets. An open upper bracket never claims that a
//! physical commit happened at a particular UTC instant.

use fa_model::symbols::{label, property};
use fa_model::{ControlPayload, Entry, EntryClass, Id128};
use fa_time::{InstantResolution, InstantResolutionError, TimeObservation};
use fgdb::Database;
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, exit};
use crate::rows::bytes;

pub const INSTANT_UNAVAILABLE: &str = "FA-REF-151";

/// A retained tick-bucket selection and the identities of its evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstantSelection {
    pub resolution: InstantResolution,
    pub lower_entry: VId,
    pub upper_entry: Option<VId>,
}

impl InstantSelection {
    /// Check the self-contained bracket contract. Journal replay additionally
    /// compares this object with the complete tick history at its frontier.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        if self.upper_entry.is_some() != self.resolution.upper.is_some()
            || self.upper_entry == Some(self.lower_entry)
        {
            return false;
        }
        let mut observations = vec![self.resolution.lower];
        observations.extend(self.resolution.upper);
        fa_time::resolve_instant(
            &observations,
            self.resolution.requested_utc_ns,
            self.resolution.frontier,
        )
        .is_ok_and(|resolved| resolved == self.resolution)
    }
}

fn day_start_utc_ns(day: fa_time::DateDay) -> u64 {
    const NS_PER_DAY: i128 = 86_400_000_000_000;
    u64::try_from(i128::from(day.0).saturating_mul(NS_PER_DAY)).unwrap_or(0)
}

fn unavailable(error: InstantResolutionError) -> Refusal {
    let cite = match error {
        InstantResolutionError::BeforeBookGenesis { .. } => {
            "plan §7.1a, §8.6 / FA-INV-07 (instant selection before migration genesis returns BeforeBookGenesis; legacy known-at is never reconstructed)"
        }
        _ => "plan §7.1a / FA-INV-07 (instant selection requires retained TimeEvidence)",
    };
    Refusal::new(
        INSTANT_UNAVAILABLE,
        exit::REFUSAL,
        format!("known-at instant cannot be resolved: {error}"),
        cite,
        "select --as-known-at HEAD or an existing commit sequence; an instant before the first retained tick or before migration genesis cannot be reconstructed",
    )
    // HEAD answers as of now, a different question than the instant asked;
    // the caller chooses it knowingly.
    .or_field_change("as_known_at", vec!["HEAD".to_string()])
}

/// Resolve an instant using only ticks visible at the fixed observed frontier.
/// None observes the current frontier once. The reader neither samples a clock
/// nor appends a tick, and never substitutes HEAD when evidence is absent.
///
/// The supplied context is checked before observation and during the scan.
/// This is the whole-book embedded-owner read posture; scoped read authority
/// remains the separate fa-0x0 workstream.
pub fn resolve_instant_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    requested_utc_ns: u64,
    frontier: Option<CommitSeq>,
) -> Outcome<InstantSelection> {
    cx.checkpoint().map_err(fgdb::WriteTxnError::Interrupted)?;
    let head = db.frontier()?;
    let at = frontier.unwrap_or(head);
    if at > head {
        return Ok(Err(Refusal::new(
            INSTANT_UNAVAILABLE,
            exit::REFUSAL,
            format!(
                "TimeEvidence frontier {} is beyond book head {}",
                at.0, head.0
            ),
            "plan §7.1a (resolution uses an observed, retained frontier)",
            "resolve against the current book or retain the original certified history",
        )));
    }
    let mut genesis_utc_ns = crate::genesis::read_book_spec(db)?
        .and_then(|spec| spec.opening_date)
        .map(day_start_utc_ns);
    let mut migration_seq: Option<u64> = None;
    let mut ticks = Vec::new();
    for row in db.vertices_at(at)? {
        cx.checkpoint().map_err(fgdb::WriteTxnError::Interrupted)?;
        if row.labels.contains(&label::MIGRATION_RUN) {
            let payload = bytes(&row, property::FA_PAYLOAD, "MigrationRun payload")?;
            let run = crate::migration::RunBody::decode(&payload)?;
            let run_genesis = day_start_utc_ns(run.opening_date);
            genesis_utc_ns = Some(genesis_utc_ns.map_or(run_genesis, |g| g.max(run_genesis)));
            migration_seq =
                Some(migration_seq.map_or(row.created_at.0, |prev| prev.max(row.created_at.0)));
            continue;
        }
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let payload = bytes(&row, property::FA_PAYLOAD, "TimeEvidence entry payload")?;
        let entry = Entry::decode(&payload)?;
        if entry.proposal.class == EntryClass::MIGRATION
            || entry.proposal.class == EntryClass::MIGRATION_CONTROL
        {
            migration_seq =
                Some(migration_seq.map_or(row.created_at.0, |prev| prev.max(row.created_at.0)));
            continue;
        }
        let is_tick = matches!(
            &entry.proposal.control,
            Some(ControlPayload::TimeTick { .. })
        );
        if entry.proposal.class != EntryClass::TIME_CONTROL && !is_tick {
            continue;
        }
        let Some(ControlPayload::TimeTick {
            observed_utc_ns,
            source,
            monotonic_ok,
        }) = entry.proposal.control
        else {
            return Err(KernelError::Corrupt(
                "TimeControl entry does not carry TimeEvidence".into(),
            ));
        };
        if entry.proposal.class != EntryClass::TIME_CONTROL
            || entry.proposal.book_id != book.book_id
            || entry.proposal.branch_id != Id128::TRUNK
            || bytes(&row, property::FA_DIGEST, "TimeEvidence entry digest")? != entry.entry_digest
        {
            return Err(KernelError::Corrupt(format!(
                "TimeEvidence entry {:032x} has an invalid identity, coordinate or digest",
                row.vid.0
            )));
        }
        // A historical resolution must not hide a later rewrite or retirement
        // of the tick it is using. Compare at one fixed current frontier.
        let current = db.vertex_at(row.vid, head)?.ok_or_else(|| {
            KernelError::Corrupt(format!("TimeEvidence entry {:032x} was retired", row.vid.0))
        })?;
        if !current.labels.contains(&label::ENTRY)
            || current.created_at != row.created_at
            || bytes(
                &current,
                property::FA_PAYLOAD,
                "current TimeEvidence payload",
            )? != payload
            || bytes(&current, property::FA_DIGEST, "current TimeEvidence digest")?
                != entry.entry_digest
        {
            return Err(KernelError::Corrupt(format!(
                "TimeEvidence entry {:032x} was rewritten",
                row.vid.0
            )));
        }
        ticks.push((
            TimeObservation {
                recorded_at: row.created_at.0,
                observed_utc_ns,
                source,
                monotonic_ok,
            },
            row.vid,
        ));
    }
    ticks.sort_by_key(|(tick, vid)| (tick.recorded_at, *vid));
    let mut active_ticks: Vec<(TimeObservation, VId)> = Vec::with_capacity(ticks.len());
    for (i, &(tick, vid)) in ticks.iter().enumerate() {
        if !tick.monotonic_ok
            && ticks[i + 1..].iter().any(|(later, _)| {
                later.monotonic_ok && later.observed_utc_ns <= tick.observed_utc_ns
            })
        {
            continue;
        }
        active_ticks.push((tick, vid));
    }
    let ticks = active_ticks;
    if let Some(mig_seq) = migration_seq
        && let Some((first_post_mig, _)) =
            ticks.iter().find(|(tick, _)| tick.recorded_at >= mig_seq)
    {
        genesis_utc_ns = Some(genesis_utc_ns.map_or(first_post_mig.observed_utc_ns, |g| {
            g.max(first_post_mig.observed_utc_ns)
        }));
    }
    let observations: Vec<TimeObservation> = ticks.iter().map(|(tick, _)| *tick).collect();
    let resolution = match fa_time::resolve_instant_with_genesis(
        &observations,
        requested_utc_ns,
        at.0,
        genesis_utc_ns,
    ) {
        Ok(resolution) => resolution,
        Err(
            error @ (InstantResolutionError::NoTicks { .. }
            | InstantResolutionError::BeforeFirstTick { .. }
            | InstantResolutionError::BeforeBookGenesis { .. }),
        ) => {
            return Ok(Err(unavailable(error)));
        }
        Err(error) => {
            return Err(KernelError::Corrupt(format!(
                "invalid TimeEvidence history: {error}"
            )));
        }
    };
    let entry_at = |sequence| {
        ticks
            .iter()
            .find(|(tick, _)| tick.recorded_at == sequence)
            .map(|(_, vid)| *vid)
            .ok_or_else(|| KernelError::Corrupt("resolved tick has no journal entry".into()))
    };
    let lower_entry = entry_at(resolution.lower.recorded_at)?;
    let upper_entry = resolution
        .upper
        .map(|tick| entry_at(tick.recorded_at))
        .transpose()?;
    Ok(Ok(InstantSelection {
        resolution,
        lower_entry,
        upper_entry,
    }))
}
