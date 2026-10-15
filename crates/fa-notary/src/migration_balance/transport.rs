//! Bounded balance-proof serialization shared by legacy v2 and complete v3.
//! Size accounting includes every length prefix before allocating the output.

use fa_journal::KernelError;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::Writer;
use fgdb_types::VId;

use super::{BALANCE_FORMAT_V2, BALANCE_FORMAT_V3, Selected};
use crate::{Journal, Leaf};

pub const MAX_BALANCE_PROOF_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_SELECTORS: usize = 4096;
const MAX_ENVELOPE_BYTES: usize = 92 + MAX_SELECTORS * 20;

pub(super) struct Claim {
    pub account: VId,
    pub unit: u32,
    pub through: Option<i32>,
    pub debits: i128,
    pub credits: i128,
}

fn limit(field: &str) -> Refusal {
    Refusal::new(
        "FA-REF-127",
        exit::USAGE,
        format!("balance proof {field} exceeds the portable verifier's bounds"),
        "plan §13.3 (bounded, complete proof transport)",
        "use an earlier trusted checkpoint or a transport with explicitly supported larger bounds; never omit required records to fit a balance proof",
    )
}

fn add(size: &mut usize, count: usize) -> Result<(), Refusal> {
    *size = size
        .checked_add(count)
        .filter(|total| *total <= MAX_BALANCE_PROOF_BYTES)
        .ok_or_else(|| limit("encoded size (64 MiB)"))?;
    Ok(())
}

fn measure<'a>(
    journal: &Journal,
    records: impl IntoIterator<Item = &'a Leaf>,
    witnesses: &[(usize, Vec<u8>)],
    through: Option<i32>,
) -> Result<usize, Refusal> {
    // format bytes, checkpoint, claim and the three list counts. V2 and v3
    // tags have equal lengths; include the optional day only when present.
    let mut size = 4 + BALANCE_FORMAT_V3.len() + 80 + 16 + 4 + 1 + 32 + 12;
    if through.is_some() {
        add(&mut size, 4)?;
    }
    for leaf in &journal.leaves {
        if leaf.envelope_bytes.len() > MAX_ENVELOPE_BYTES
            || leaf.envelope.account_vids.len() > MAX_SELECTORS
            || leaf.envelope.unit_ids.len() > MAX_SELECTORS
        {
            return Err(limit("envelope"));
        }
        add(&mut size, 4)?;
        add(&mut size, leaf.envelope_bytes.len())?;
    }
    for leaf in records {
        if leaf.payload.len() > MAX_RECORD_BYTES {
            return Err(limit("record (8 MiB)"));
        }
        add(&mut size, 16)?; // index, proposal length, payload length
        add(&mut size, leaf.payload.len())?;
    }
    for (_, body) in witnesses {
        if body.len() > MAX_RECORD_BYTES {
            return Err(limit("run body (8 MiB)"));
        }
        add(&mut size, 12)?; // Open index and body length
        add(&mut size, body.len())?;
    }
    Ok(size)
}

/// Refuse oversized complete prefixes before decoding all their entries.
pub(super) fn preflight(journal: &Journal, through: Option<i32>) -> Result<(), Refusal> {
    measure(journal, journal.leaves.iter(), &[], through).map(|_| ())
}

pub(super) fn encode(
    journal: &Journal,
    selected: &Selected<'_>,
    witnesses: Vec<(usize, Vec<u8>)>,
    complete: bool,
    claim: Claim,
) -> Outcome<Vec<u8>> {
    let leaves: Vec<_> = if complete {
        journal.leaves.iter().enumerate().collect()
    } else {
        selected
            .iter()
            .map(|(index, leaf, _)| (*index, *leaf))
            .collect()
    };
    let size = match measure(
        journal,
        leaves.iter().map(|(_, leaf)| *leaf),
        &witnesses,
        claim.through,
    ) {
        Ok(size) => size,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut wire_records = Vec::with_capacity(leaves.len());
    for (index, leaf) in leaves {
        let index = u64::try_from(index)
            .map_err(|_| KernelError::Corrupt("leaf index exceeds u64".into()))?;
        let len = u32::try_from(leaf.proposal_len)
            .map_err(|_| KernelError::Corrupt("proposal length exceeds u32".into()))?;
        wire_records.push((index, len, leaf.payload.as_slice()));
    }
    let witnesses = witnesses
        .into_iter()
        .map(|(index, body)| {
            u64::try_from(index)
                .map(|index| (index, body))
                .map_err(|_| KernelError::Corrupt("Open index exceeds u64".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut w = Writer::with_capacity(size);
    w.bytes(if complete {
        BALANCE_FORMAT_V3
    } else {
        BALANCE_FORMAT_V2
    });
    journal.statement().encode(&mut w);
    w.u128(claim.account.0)
        .u32(claim.unit)
        .opt(claim.through.as_ref(), |w, day| {
            w.i32(*day);
        })
        .i128(claim.debits)
        .i128(claim.credits)
        .list(&journal.leaves, |w, leaf| {
            w.bytes(&leaf.envelope_bytes);
        })
        .list(&wire_records, |w, (index, len, payload)| {
            w.u64(*index).u32(*len).bytes(payload);
        })
        .list(&witnesses, |w, (index, body)| {
            w.u64(*index).bytes(body);
        });
    let bytes = w.finish().map_err(fa_model::EntryError::Encode)?;
    if bytes.len() != size {
        return Err(KernelError::Corrupt(
            "balance proof size accounting drifted".into(),
        ));
    }
    Ok(Ok(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::Id128;
    use fgdb_types::CommitSeq;

    #[test]
    fn framing_size_is_exact_for_empty_proofs_and_both_cutoff_shapes() {
        let journal = Journal::from_records(Id128([1; 16]), CommitSeq(0), vec![]).unwrap();
        for complete in [false, true] {
            for through in [None, Some(i32::MIN), Some(i32::MAX)] {
                let expected = measure(&journal, journal.leaves.iter(), &[], through).unwrap();
                let bytes = encode(
                    &journal,
                    &vec![],
                    vec![],
                    complete,
                    Claim {
                        account: VId(10),
                        unit: 1,
                        through,
                        debits: 0,
                        credits: 0,
                    },
                )
                .unwrap()
                .unwrap();
                assert_eq!(bytes.len(), expected);
            }
        }
    }

    #[test]
    fn allocation_boundary_includes_framing_and_rejects_overflow() {
        let mut size = MAX_BALANCE_PROOF_BYTES - 1;
        add(&mut size, 1).unwrap();
        assert_eq!(size, MAX_BALANCE_PROOF_BYTES);
        assert_eq!(add(&mut size, 1).unwrap_err().code, "FA-REF-127");
        let mut overflowing = usize::MAX;
        assert!(add(&mut overflowing, 1).is_err());
        let mut framed = MAX_BALANCE_PROOF_BYTES - 12;
        add(&mut framed, 12).unwrap();
        assert!(add(&mut framed, 1).is_err());
    }
}
