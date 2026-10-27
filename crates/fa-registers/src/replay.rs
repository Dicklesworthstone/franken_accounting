//! Verifying a scratch-book replay (plan §15.2, bead fa-xo0 part 2).
//!
//! A scratch book is evidentiary only if its [`SeqMap`] is exactly the map
//! of the replay it describes. [`verify_replay`] re-derives that from the
//! source and refolds both sides:
//!
//! - the map names this book, and is strictly increasing on both sides;
//! - its prefix is not past the source's frontier, nor before the book's
//!   genesis;
//! - its pairs are exactly the source's commits through the prefix that
//!   carry accounting objects (no gap, no extra), each with that commit's
//!   marker;
//! - at every pair, the entries selected at the source sequence and at the
//!   scratch sequence are the same objects (vid and entry digest, under the
//!   same migration predicate), and every period they post into folds to the
//!   same cells on both sides.
//!
//! Any departure is FA-REF-135: a SeqMap is never edited, only re-made by a
//! fresh replay.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_journal::scratch::{Maintenance, SeqMap, replayable, source_genesis};
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::{PeriodOf, RegisterError, entries_at, folds_at, take_fold};

/// Refusal codes this module issues.
pub mod code {
    /// A SeqMap that does not describe the replay: wrong book, not monotone,
    /// a prefix past the source frontier or before its genesis, a gap or an
    /// extra pair, a wrong marker, or a pair at which the two books' entries
    /// or folds differ.
    pub const SEQ_MAP_INVALID: &str = "FA-REF-135";
}

/// What a verification checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayVerification {
    pub seq_map_digest: [u8; 32],
    pub pairs_checked: usize,
    pub entries_checked: usize,
    pub folds_checked: usize,
}

fn invalid(why: String) -> Refusal {
    Refusal::new(
        code::SEQ_MAP_INVALID,
        exit::VERIFICATION,
        why,
        "plan §15.2 (a scratch book's certificate carries its SeqMap; replay equals the source at every mapped sequence)",
        "replay again with fa_journal::scratch::replay_into and verify the fresh map; a SeqMap is never edited",
    )
}

/// Verify `map` as the replay of `source`'s accounting history into
/// `scratch` (see the module docs).
pub fn verify_replay<V, W>(
    source: &Database<V>,
    scratch: &Database<W>,
    book: &BookContext,
    map: &SeqMap,
) -> Result<Result<ReplayVerification, Refusal>, RegisterError>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
{
    if map.source_book != book.book_id {
        return Ok(Err(invalid(format!(
            "the map names book {}, not {}",
            map.source_book.to_hex(),
            book.book_id.to_hex()
        ))));
    }
    if !map.is_monotone() {
        return Ok(Err(invalid(
            "the map's pairs are not strictly increasing on both sides".into(),
        )));
    }
    // The verifier is the outsider's check: a prefix past the source's
    // frontier names history the source does not hold, refused here even
    // though `source_batches` refuses it when a replay is made.
    let frontier = source.frontier()?;
    if map.source_prefix > frontier {
        return Ok(Err(invalid(format!(
            "the map's source prefix {} is past the source frontier {}",
            map.source_prefix.0, frontier.0
        ))));
    }
    // Nor before the book's genesis: an empty map over an empty database is
    // not a scratch book.
    // Maintenance advances the root's content version. Only its original
    // CreateVertex in the authenticated history defines the book's genesis.
    let genesis = source_genesis(source)?;
    if genesis.is_none_or(|g| map.source_prefix < g) {
        return Ok(Err(invalid(format!(
            "the map's source prefix {} precedes the source book's genesis ({})",
            map.source_prefix.0,
            genesis.map_or_else(|| "no book".to_string(), |g| g.0.to_string())
        ))));
    }
    // The source commits a replay through the prefix must reproduce.
    let mut maintenance = Maintenance::default();
    let mut expected: Vec<(CommitSeq, [u8; 32])> = Vec::new();
    for batch in source
        .delta_since(CommitSeq(0))?
        .filter(|b| b.commit_seq() <= map.source_prefix)
    {
        match replayable(batch, &mut maintenance) {
            Ok(writes) if !writes.is_empty() => {
                expected.push((
                    batch.commit_seq(),
                    batch.commit_marker_identity().marker_oid.0,
                ));
            }
            Ok(_) => {}
            Err(r) => return Ok(Err(r)),
        }
    }
    let named: Vec<(CommitSeq, [u8; 32])> = map
        .pairs
        .iter()
        .map(|p| (p.source_seq, p.source_marker))
        .collect();
    if named != expected {
        let first = expected
            .iter()
            .zip(&named)
            .position(|(a, b)| a != b)
            .unwrap_or(expected.len().min(named.len()));
        return Ok(Err(invalid(format!(
            "the map does not name exactly the source's accounting commits through {}: {} expected, {} named, first difference at pair {first}",
            map.source_prefix.0,
            expected.len(),
            named.len()
        ))));
    }
    let digest = map.digest()?;
    let mut entries_checked = 0;
    let mut folds_checked = 0;
    let mut period_of = PeriodOf::new(book);
    for pair in &map.pairs {
        let src_entries = entries_at(source, book, pair.source_seq)?;
        let scr_entries = entries_at(scratch, book, pair.scratch_seq)?;
        let digests = |entries: &[(VId, fa_model::Entry, CommitSeq)]| {
            entries
                .iter()
                .map(|(v, e, _)| (*v, e.entry_digest))
                .collect::<BTreeMap<_, _>>()
        };
        let (src, scr) = (digests(&src_entries), digests(&scr_entries));
        if src != scr {
            return Ok(Err(invalid(format!(
                "at source {} / scratch {} the books select different entries ({} vs {})",
                pair.source_seq.0,
                pair.scratch_seq.0,
                src.len(),
                scr.len()
            ))));
        }
        entries_checked += src.len();
        let mut periods = BTreeSet::new();
        for (_, e, _) in &src_entries {
            if !e.proposal.legs.is_empty() {
                periods.insert(period_of.period(e)?.to_string());
            }
        }
        // Every period from the entry lists just read, not a fresh read and
        // decode of the prefix per period and side (fa-rbs3).
        // Each fold is the one fold_period_at returns, error included.
        let periods: BTreeSet<&str> = periods.iter().map(String::as_str).collect();
        let mut source_folds =
            folds_at(source, book, &periods, pair.source_seq, Some(&src_entries));
        let mut scratch_folds = folds_at(
            scratch,
            book,
            &periods,
            pair.scratch_seq,
            Some(&scr_entries),
        );
        for period in periods {
            let (a, _) = take_fold(&mut source_folds, period)?;
            let (b, _) = take_fold(&mut scratch_folds, period)?;
            if a.cells != b.cells || a.pending != b.pending || a.entries != b.entries {
                return Ok(Err(invalid(format!(
                    "at source {} / scratch {} period `{period}` folds differently",
                    pair.source_seq.0, pair.scratch_seq.0
                ))));
            }
            folds_checked += 1;
        }
    }
    Ok(Ok(ReplayVerification {
        seq_map_digest: digest,
        pairs_checked: map.pairs.len(),
        entries_checked,
        folds_checked,
    }))
}
