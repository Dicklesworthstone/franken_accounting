//! Number sequences (plan §11.3): gaps in the numeric tail of external ids,
//! per system and prefix — the completeness assertion's mechanical half.
//! External ids are erasable; the finding cites the two entries bounding a
//! gap and reports its size, never the ids themselves.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fgdb_types::VId;

use crate::jet::{finding, procedure_boilerplate};
use crate::{Cite, Finding, LanternError, Params, Procedure, Severity, Snapshot, Statistic, Work};

/// The most bytes an external id is opened to.
pub const MAX_EXTERNAL_ID_BYTES: usize = 256;

/// Split `id` into its non-numeric prefix and its numeric tail (at most 18
/// digits, so it fits a `u64`); `None` when there is no tail or it is too
/// long.
#[must_use]
pub fn split_sequence(id: &str) -> Option<(&str, u64)> {
    let tail_start = id
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_digit())
        .last()
        .map(|(i, _)| i)?;
    let (prefix, digits) = id.split_at(tail_start);
    if digits.len() > 18 {
        return None;
    }
    digits.parse().ok().map(|n| (prefix, n))
}

/// `numbers.sequence_gaps`.
pub struct SequenceGaps {
    params: Params,
}
procedure_boilerplate!(SequenceGaps, "numbers.sequence_gaps");

impl Procedure for SequenceGaps {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut sequences: BTreeMap<(String, String), Vec<(u64, VId)>> = BTreeMap::new();
        let mut population = 0u64;
        for e in snapshot.live_postings()? {
            work.entry();
            for ext in &e.entry.proposal.external_ids {
                let Ok(id) = ext.id.open(&book.seal_key, MAX_EXTERNAL_ID_BYTES) else {
                    continue;
                };
                let Some((prefix, number)) = split_sequence(&id) else {
                    continue;
                };
                population += 1;
                sequences
                    .entry((ext.system.clone(), prefix.to_string()))
                    .or_default()
                    .push((number, e.vid));
            }
        }
        let mut out = Vec::new();
        for ((system, _), list) in sequences.iter_mut() {
            list.sort_unstable();
            work.compare(list.len() as u64);
            for pair in list.windows(2) {
                let (prev, next) = (pair[0], pair[1]);
                let missing = next.0.saturating_sub(prev.0).saturating_sub(1);
                if missing == 0 {
                    continue;
                }
                let mut cites = vec![prev.1, next.1];
                cites.sort_unstable();
                cites.dedup();
                out.push(finding(
                    Self::ID,
                    if missing <= 2 {
                        Severity::Low
                    } else {
                        Severity::Medium
                    },
                    Statistic::count("missing_numbers", missing, population),
                    cites.into_iter().map(Cite::Entry).collect(),
                    format!(
                        "system `{system}`: {missing} number(s) missing between two cited entries"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::split_sequence;

    #[test]
    fn sequences_split_at_the_numeric_tail() {
        assert_eq!(split_sequence("INV-000123"), Some(("INV-", 123)));
        assert_eq!(split_sequence("7"), Some(("", 7)));
        assert_eq!(split_sequence("INV-"), None);
        assert_eq!(split_sequence(""), None);
        assert_eq!(split_sequence("A1B"), None);
        assert_eq!(split_sequence("X9999999999999999999"), None, "19 digits");
    }
}
