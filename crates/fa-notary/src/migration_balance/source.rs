//! Producer closure for the native, immutable source population.
//!
//! The portable verifier independently repeats these membership checks. Neither
//! producer nor verifier reinterprets a retained CSV as an economic assertion.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::migration::{RunBody, SourceManifest, kind};
use fa_journal::refusal::Outcome;
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EvidenceRef, Writer,
    domain_digest, migration_entry_vid,
};
use fgdb_types::{CommitSeq, VId};

use super::refusal;
use crate::Journal;

struct Control {
    index: usize,
    sequence: CommitSeq,
    day: i32,
    body: [u8; 32],
    digest: [u8; 32],
    evidence: Vec<EvidenceRef>,
}

#[derive(Default)]
struct Run {
    open: Option<Control>,
    binding: Option<Control>,
    terminal: Option<(u8, Control)>,
    chunks: Vec<(CommitSeq, VId, [u8; 32])>,
}

/// Exact source witnesses needed by these runs at this historical frontier.
/// Includes every chunk of each selected run, regardless of account/date filters.
pub(crate) fn witnesses(
    journal: &Journal,
    known_at: CommitSeq,
    needed: &BTreeSet<VId>,
    bodies: &BTreeMap<VId, RunBody>,
    manifests: Option<&BTreeMap<VId, SourceManifest>>,
) -> Outcome<Vec<(usize, Vec<u8>)>> {
    let mut runs: BTreeMap<VId, Run> = BTreeMap::new();
    for (index, leaf) in journal.leaves.iter().enumerate() {
        if !leaf.envelope.is_entry() || leaf.envelope.commit_seq > known_at {
            continue;
        }
        if leaf.envelope.class != EntryClass::MIGRATION
            && leaf.envelope.class != EntryClass::MIGRATION_CONTROL
        {
            continue;
        }
        let entry = Entry::decode(&leaf.payload)?;
        let p = &entry.proposal;
        if let EntryOrigin::Migration { run_ref, .. } = &p.origin {
            if needed.contains(run_ref) {
                if p.class != EntryClass::MIGRATION || p.control.is_some() {
                    return Ok(Err(refusal(
                        "source member has inconsistent migration metadata",
                    )));
                }
                runs.entry(*run_ref).or_default().chunks.push((
                    leaf.envelope.commit_seq,
                    migration_entry_vid(journal.book_id, *run_ref, &p.idempotency_key),
                    entry.proposal_digest,
                ));
            }
            continue;
        }
        let Some(ControlPayload::MigrationControl {
            run_ref,
            kind: transition,
            tie_out_digest,
        }) = &p.control
        else {
            continue;
        };
        if !needed.contains(run_ref) {
            continue;
        }
        let EntryOrigin::Control {
            control_kind: ControlKind::MIGRATION_RUN,
            spec_body_digest,
        } = &p.origin
        else {
            return Ok(Err(refusal(
                "source lifecycle has an inconsistent control origin",
            )));
        };
        if p.class != EntryClass::MIGRATION_CONTROL || !p.legs.is_empty() {
            return Ok(Err(refusal(
                "source lifecycle is not a migration-run control",
            )));
        }
        let c = Control {
            index,
            sequence: leaf.envelope.commit_seq,
            day: p.effective_date.0,
            body: *spec_body_digest,
            digest: *tie_out_digest,
            evidence: p.evidence.clone(),
        };
        let run = runs.entry(*run_ref).or_default();
        if *transition == kind::OPEN {
            if run.open.is_some()
                || run.binding.is_some()
                || run.terminal.is_some()
                || !run.chunks.is_empty()
                || c.body != c.digest
            {
                return Ok(Err(refusal(
                    "source lifecycle has a duplicate or misplaced Open",
                )));
            }
            run.open = Some(c);
            continue;
        }
        let Some(open) = &run.open else {
            return Ok(Err(refusal("source lifecycle names an unopened run")));
        };
        if run.terminal.is_some() || c.body != open.body || c.index <= open.index {
            return Ok(Err(refusal(
                "source lifecycle changes its body or follows termination",
            )));
        }
        match *transition {
            kind::BIND_SOURCE
                if run.binding.is_none()
                    && run.chunks.is_empty()
                    && c.sequence > open.sequence
                    && c.day == open.day =>
            {
                run.binding = Some(c)
            }
            kind::FINALIZE | kind::ABANDON => run.terminal = Some((*transition, c)),
            _ => {
                return Ok(Err(refusal(
                    "source binding is duplicate, late, or unsupported",
                )));
            }
        }
    }
    let mut witnesses = Vec::new();
    for vid in needed {
        let manifest = manifests.and_then(|manifests| manifests.get(vid));
        let Some(run) = runs.get(vid) else {
            return Ok(Err(refusal(
                "selected migration run has no source lifecycle",
            )));
        };
        let Some(binding) = &run.binding else {
            if manifest.is_some() {
                return Ok(Err(refusal(
                    "source manifest has no authenticated BindSource control",
                )));
            }
            continue;
        };
        let Some(manifest) = manifest else {
            return Ok(Err(refusal(
                "source-bound run is missing its immutable source manifest",
            )));
        };
        let Some(body) = bodies.get(vid) else {
            return Ok(Err(refusal(
                "source-bound run is missing its immutable run body",
            )));
        };
        let bytes = manifest.canonical_bytes()?;
        if SourceManifest::decode(&bytes).map_err(|error| KernelError::Model(error.into()))?
            != *manifest
            || manifest.book_id != journal.book_id
            || manifest.run_ref != *vid
            || body.vid() != *vid
            || manifest.run_body_digest != body.digest()?
            || binding.body != manifest.run_body_digest
            || binding.digest != manifest.digest()?
            || domain_digest(
                b"fa:oid:document:v1",
                &[&journal.book_id.0, &manifest.source_commit],
            ) != manifest.source_oid.0
            || domain_digest(
                b"fa:oid:document:v1",
                &[&journal.book_id.0, &manifest.package_commit],
            ) != manifest.package_oid.0
        {
            return Ok(Err(refusal(
                "source manifest does not match its native control or document identities",
            )));
        }
        let mut evidence = vec![
            EvidenceRef {
                document_oid: manifest.source_oid,
                doc_commit: manifest.source_commit,
                role: 1,
            },
            EvidenceRef {
                document_oid: manifest.package_oid,
                doc_commit: manifest.package_commit,
                role: 1,
            },
        ];
        evidence.sort_unstable();
        if binding.evidence != evidence {
            return Ok(Err(refusal(
                "source control does not cite the exact source and package commitments",
            )));
        }
        let expected: BTreeMap<_, _> = manifest
            .chunks
            .iter()
            .map(|chunk| (chunk.entry_vid, chunk.proposal_digest))
            .collect();
        let mut seen = BTreeSet::new();
        for (sequence, entry, digest) in &run.chunks {
            if *sequence <= binding.sequence
                || expected.get(entry) != Some(digest)
                || !seen.insert(*entry)
                || run
                    .terminal
                    .as_ref()
                    .is_some_and(|(_, terminal)| *sequence >= terminal.sequence)
            {
                return Ok(Err(refusal(
                    "source population contains a duplicate, unexpected, changed, or misplaced chunk",
                )));
            }
        }
        if run
            .terminal
            .as_ref()
            .is_some_and(|(transition, _)| *transition == kind::FINALIZE)
            && seen.len() != expected.len()
        {
            return Ok(Err(refusal(
                "finalized migration omits declared source chunks",
            )));
        }
        if let Some((_, terminal)) = &run.terminal {
            let mut chunks = run.chunks.clone();
            chunks.sort_unstable_by_key(|(sequence, entry, _)| (*sequence, *entry));
            let mut list = Writer::new();
            list.list(&chunks, |writer, (_, entry, digest)| {
                writer.u128(entry.0).fixed(digest);
            });
            let digest = domain_digest(
                b"fa:migration-tie-out:v2",
                &[&manifest.run_body_digest, &binding.digest, &list.finish()?],
            );
            if terminal.digest != digest {
                return Ok(Err(refusal(
                    "source terminal does not bind its exact published chunk population",
                )));
            }
        }
        witnesses.push((binding.index, bytes));
    }
    witnesses.sort_unstable_by_key(|(index, _)| *index);
    Ok(Ok(witnesses))
}
