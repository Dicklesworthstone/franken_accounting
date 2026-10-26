//! Independent tick-bucket resolution from every authenticated TimeControl
//! record at the certificate's retained observation frontier. These records
//! attest what the book observed, not physical commit times or external UTC.

use super::{ReportError, failed, metadata};
use crate::codec::Reader;
use crate::envelope::{KIND_ENTRY, LeafEnvelope};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeObservation {
    pub recorded_at: u64,
    pub observed_utc_ns: u64,
    pub source: u8,
    pub monotonic_ok: bool,
}

/// The independently reconstructed instant selector. A missing upper tick
/// means an open bucket at `frontier`, never at the exporting book's later head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedInstantSelection {
    pub requested_utc_ns: u64,
    pub frontier: u64,
    pub resolved_seq: u64,
    pub lower: TimeObservation,
    pub upper: Option<TimeObservation>,
    pub lower_entry: u128,
    pub upper_entry: Option<u128>,
}

impl VerifiedInstantSelection {
    pub fn source_grade(&self) -> &'static str {
        if self.lower.source != 0 || self.upper.is_some_and(|tick| tick.source != 0) {
            "unsupported_source"
        } else if self.lower.monotonic_ok && self.upper.is_none_or(|tick| tick.monotonic_ok) {
            "corroborated_daemon_clock"
        } else {
            "uncorroborated_daemon_clock"
        }
    }

    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, ReportError> {
        let requested_utc_ns = r.u64("time.requested_utc_ns")?;
        let frontier = r.u64("time.frontier")?;
        let resolved_seq = r.u64("time.resolved_seq")?;
        let lower = observation(r)?;
        let upper = if r.present("time.upper")? {
            Some(observation(r)?)
        } else {
            None
        };
        let lower_entry = r.u128("time.lower_entry")?;
        let upper_entry = if r.present("time.upper_entry")? {
            Some(r.u128("time.upper_entry")?)
        } else {
            None
        };
        Ok(Self {
            requested_utc_ns,
            frontier,
            resolved_seq,
            lower,
            upper,
            lower_entry,
            upper_entry,
        })
    }
}

fn observation(r: &mut Reader<'_>) -> Result<TimeObservation, ReportError> {
    Ok(TimeObservation {
        recorded_at: r.u64("time.tick.recorded_at")?,
        observed_utc_ns: r.u64("time.tick.observed_utc_ns")?,
        source: r.u8("time.tick.source")?,
        monotonic_ok: r.present("time.tick.monotonic_ok")?,
    })
}

/// Inputs have already passed complete-prefix membership and payload derivation.
/// No native read attestation or producer-supplied tick list is used here.
pub(super) fn verify(
    selection: &VerifiedInstantSelection,
    known_at: u64,
    checkpoint_through: u64,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
) -> Result<(), ReportError> {
    if selection.frontier > checkpoint_through || known_at > selection.frontier {
        return Err(failed(
            "time_frontier",
            "the authenticated checkpoint must cover the complete observed time frontier",
        ));
    }
    let mut ticks = Vec::new();
    let mut identities = BTreeSet::new();
    let mut periods = metadata::Schema::default();
    for (envelope, (len, payload)) in envelopes.iter().zip(records) {
        if envelope.kind != KIND_ENTRY || envelope.commit_seq > selection.frontier {
            continue;
        }
        // Migration/genesis admission also reads a BookSpec root which the
        // current complete-prefix format does not authenticate. Never turn
        // missing migration policy evidence into an unrestricted instant read.
        if matches!(envelope.class, 12 | 22) {
            return Err(failed(
                "time_genesis_policy",
                "instant report bundles do not yet authenticate migration/genesis policy; use a sequence-selected certificate",
            ));
        }
        let info = metadata::entry_info(&payload[..*len], envelope)?;
        if let Some((13, body)) = info.schema {
            periods.apply(13, body, &envelope.book_id, envelope.commit_seq)?;
        }
        if let Some(tick) = info.time_tick {
            if !identities.insert(info.identity) {
                return Err(failed(
                    "time_history",
                    "duplicate TimeControl entry identity",
                ));
            }
            ticks.push((tick, info.identity));
        }
    }
    if periods.has_historical_periods() {
        return Err(failed(
            "time_genesis_policy",
            "historical-period instant admission requires authenticated book-genesis policy; use a sequence-selected certificate",
        ));
    }

    // A later corroborated observation can retire an earlier uncorroborated
    // forward jump. Compute the suffix minimum in linear work, then validate
    // the entire remaining history, including ticks beyond the requested bucket.
    let mut later_corroborated: Option<u64> = None;
    let mut active = Vec::with_capacity(ticks.len());
    for &(tick, identity) in ticks.iter().rev() {
        if tick.monotonic_ok {
            later_corroborated = Some(later_corroborated.map_or(tick.observed_utc_ns, |later| {
                later.min(tick.observed_utc_ns)
            }));
        } else if later_corroborated.is_some_and(|later| later <= tick.observed_utc_ns) {
            continue;
        }
        active.push((tick, identity));
    }
    active.reverse();

    let mut previous: Option<TimeObservation> = None;
    let mut lower = None;
    let mut upper = None;
    for (tick, identity) in active {
        if tick.source != 0 {
            return Err(failed("time_history", "unsupported TimeEvidence source"));
        }
        if previous.is_some_and(|prior| {
            tick.recorded_at <= prior.recorded_at || tick.observed_utc_ns <= prior.observed_utc_ns
        }) {
            return Err(failed(
                "time_history",
                "active TimeEvidence sequences and observations must strictly increase",
            ));
        }
        previous = Some(tick);
        if tick.observed_utc_ns <= selection.requested_utc_ns {
            lower = Some((tick, identity));
        } else if upper.is_none() {
            upper = Some((tick, identity));
        }
    }
    let (lower, lower_entry) = lower.ok_or_else(|| {
        failed(
            "time_selection",
            "the requested instant has no retained lower TimeEvidence bracket",
        )
    })?;
    let resolved_seq = match upper {
        Some((tick, _)) => tick
            .recorded_at
            .checked_sub(1)
            .ok_or_else(|| failed("time_selection", "upper TimeEvidence sequence underflow"))?,
        None => selection.frontier,
    };
    if lower != selection.lower
        || lower_entry != selection.lower_entry
        || upper.map(|(tick, _)| tick) != selection.upper
        || upper.map(|(_, identity)| identity) != selection.upper_entry
        || resolved_seq != selection.resolved_seq
        || resolved_seq != known_at
    {
        return Err(failed(
            "time_selection",
            "the complete authenticated tick history does not reproduce the retained brackets and known-at sequence",
        ));
    }
    Ok(())
}
