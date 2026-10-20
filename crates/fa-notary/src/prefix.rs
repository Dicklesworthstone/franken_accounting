//! Native payload-complete journal prefixes (plan §13.1–§13.3, fa-n6fh).
//!
//! Unlike a balance witness, this export requires no account, unit, migration
//! body, or posted-visibility decision. Every Entry, including controls and
//! staged migrations, and every accumulated evidence record is authenticated
//! as a journal record. No assertion of
//! accounting validity, authorization, document availability, or economic
//! truth follows. The caller must authorize disclosure of the WHOLE prefix.
//!
//! Wire: bytes("fa:acc-prefix-proof:v2") || Checkpoint || list(bytes(envelope))
//! || list(leaf_index u64 || proposal_len u32 || bytes(record_payload)).

use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::Writer;
use fgdb::Database;

use crate::tree::{Tree, leaf_hash};
use crate::{AccumulatorState, Journal, code};

pub const PREFIX_FORMAT_V2: &[u8] = b"fa:acc-prefix-proof:v2";
pub const MAX_PREFIX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PREFIX_LEAVES: usize = 65_536;
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_SELECTORS: usize = 4096;
const MAX_ENVELOPE_BYTES: usize = 92 + MAX_SELECTORS * 20;

fn limit(what: &'static str) -> Refusal {
    Refusal::new(
        "FA-REF-127",
        exit::USAGE,
        format!("payload-complete prefix exceeds its {what} limit"),
        "plan §13.1–§13.3 (bounded complete proofs include every required record)",
        "select an earlier checkpoint or an inclusion proof; never omit prefix records to fit a complete-proof transport",
    )
}

fn drift(what: impl Into<String>) -> Refusal {
    Refusal::new(
        code::ACCUMULATOR_DRIFT,
        exit::VERIFICATION,
        what,
        "FA-INV-14 (the authoritative journal must reproduce its accumulator)",
        "run fa verify accumulator and preserve the findings; do not export proofs over inconsistent history",
    )
}

fn add_bytes(total: &mut usize, length: usize) -> Result<(), Refusal> {
    *total = total
        .checked_add(length)
        .filter(|size| *size <= MAX_PREFIX_PROOF_BYTES)
        .ok_or_else(|| limit("64 MiB encoded-byte"))?;
    Ok(())
}

// Count framing before decoding entries or allocating the output. Repeated
// borrowed records still consume their full wire budget, not distinct bytes.
fn encoded_size(journal: &Journal) -> Result<usize, Refusal> {
    if journal.leaves.len() > MAX_PREFIX_LEAVES {
        return Err(limit("65,536-leaf"));
    }
    let mut size = 4 + PREFIX_FORMAT_V2.len() + 80 + 4 + 4;
    for leaf in &journal.leaves {
        if leaf.payload.len() > MAX_RECORD_BYTES {
            return Err(limit("8 MiB entry-payload"));
        }
        if leaf.envelope_bytes.len() > MAX_ENVELOPE_BYTES
            || leaf.envelope.account_vids.len() > MAX_SELECTORS
            || leaf.envelope.unit_ids.len() > MAX_SELECTORS
        {
            return Err(limit("envelope-selector"));
        }
        add_bytes(&mut size, 4 + leaf.envelope_bytes.len())?;
        add_bytes(&mut size, 8 + 4 + 4 + leaf.payload.len())?;
    }
    Ok(size)
}

impl Journal {
    /// Export every payload at this journal's exact checkpoint as prefix v2.
    /// The existing `prefix_proof` keeps its frozen envelope-only v1 bytes.
    /// This pure producer grants no read or disclosure authority. All records
    /// are included regardless of their kinds, effective dates, classes, or
    /// accounts.
    pub fn prefix_proof_with_records(&self) -> Outcome<Vec<u8>> {
        let size = match encoded_size(self) {
            Ok(size) => size,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut tree = Tree::new();
        let mut previous = None;
        for (index, leaf) in self.leaves.iter().enumerate() {
            let position = (
                leaf.envelope.commit_seq,
                leaf.envelope.within_commit_ordinal,
            );
            if leaf.envelope.book_id != self.book_id
                || leaf.envelope.branch_id != self.branch_id
                || leaf.envelope.commit_seq > self.through_seq
                || previous.is_some_and(|before| before >= position)
            {
                return Ok(Err(drift(format!(
                    "prefix leaf {index} has an invalid journal coordinate"
                ))));
            }
            previous = Some(position);
            if leaf.authenticated_record()?.is_none() {
                return Ok(Err(drift(format!(
                    "prefix leaf {index} disagrees with its canonical record payload"
                ))));
            }
            let hash = leaf_hash(&leaf.envelope_bytes);
            if hash != leaf.hash {
                return Ok(Err(drift(format!(
                    "prefix leaf {index} has an inconsistent cached hash"
                ))));
            }
            tree.push(hash);
        }
        if tree.root() != self.root() {
            return Ok(Err(drift(
                "the complete payload prefix does not reproduce its accumulator root",
            )));
        }
        let mut w = Writer::with_capacity(size);
        w.bytes(PREFIX_FORMAT_V2);
        self.statement().encode(&mut w);
        w.list(&self.leaves, |w, leaf| {
            w.bytes(&leaf.envelope_bytes);
        });
        // Count and split conversions are bounded by the preflight above and
        // the canonical proposal-length equality, not by unchecked wire hints.
        w.u32(self.leaves.len() as u32);
        for (index, leaf) in self.leaves.iter().enumerate() {
            w.u64(index as u64)
                .u32(leaf.proposal_len as u32)
                .bytes(&leaf.payload);
        }
        let bytes = w.finish().map_err(fa_model::EntryError::Encode)?;
        if bytes.len() != size {
            return Ok(Err(drift(
                "complete-prefix serialization disagrees with its framed size",
            )));
        }
        Ok(Ok(bytes))
    }
}

/// Export a payload-complete prefix at a fixed, journal-supported checkpoint.
/// Whole-book Read+Produce and current capability admission belong to the
/// caller. Historical retained versions cannot conceal a later rewrite.
pub fn prove_prefix_with_records<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
) -> Outcome<Vec<u8>> {
    let observed_at = db.frontier()?;
    let journal = match Journal::read(db, book, Some(state.through_seq), state.evidence_after)? {
        Ok(journal) => journal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if AccumulatorState::of_journal(&journal, state.prev_state_oid) != *state {
        return Ok(Err(drift(
            "the journal does not reproduce the selected accumulator state",
        )));
    }
    if let Err(refusal) = journal.verify_unchanged_at(db, observed_at)? {
        return Ok(Err(refusal));
    }
    journal.prefix_proof_with_records()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_budget_accepts_the_boundary_and_rejects_overflow_without_allocating() {
        let mut size = MAX_PREFIX_PROOF_BYTES - 16;
        add_bytes(&mut size, 16).unwrap();
        assert_eq!(size, MAX_PREFIX_PROOF_BYTES);
        assert_eq!(add_bytes(&mut size, 1).unwrap_err().code, "FA-REF-127");
        let mut size = usize::MAX;
        assert_eq!(add_bytes(&mut size, 1).unwrap_err().code, "FA-REF-127");
    }
}
