//! Independent closure for source-bound migration populations.
//!
//! The signed BindSource control commits this manifest. Its document locators
//! and public commitments identify the declared original and retained package;
//! this check proves exact admitted membership, not the accuracy of parsing
//! those documents or the economic truth of their contents.

use super::{Run, scope_error};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Reason, Writer};
use crate::envelope::LeafEnvelope;
use crate::proof::VerifyError;
use std::collections::{BTreeMap, BTreeSet};

const FORMAT: &[u8] = b"FA-MIGRATION-SOURCE\0";
const DOMAIN: &[u8] = b"fa:migration-source:v1";
const MAX_CHUNKS: usize = 4096;

pub(super) type Citation = ([u8; 32], [u8; 32], u8);

#[derive(Clone, Copy, Debug)]
pub(super) struct Binding {
    pub index: u64,
    pub digest: [u8; 32],
    pub evidence: [Citation; 2],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Chunk {
    pub index: u64,
    pub run: u128,
    pub vid: u128,
    pub digest: [u8; 32],
}

fn framed_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut framed = Writer::default();
    for part in parts {
        framed.bytes(part);
    }
    hash_parts(domain, &[&framed.buf])
}

pub(super) fn chunk_vid(book: &[u8; 16], run: u128, key: &[u8]) -> u128 {
    let hash = framed_hash(
        b"fa:vid:migration-entry:v1",
        &[book, &run.to_le_bytes(), key],
    );
    let mut low = [0; 16];
    low.copy_from_slice(&hash[..16]);
    u128::from_le_bytes(low)
}

struct Manifest {
    run: u128,
    body_digest: [u8; 32],
    evidence: [Citation; 2],
    members: BTreeMap<u128, [u8; 32]>,
}

fn manifest(bytes: &[u8], book: &[u8; 16]) -> Result<Manifest, VerifyError> {
    let Some(suffix) = bytes.strip_prefix(FORMAT) else {
        return Err(VerifyError::Format { expected: FORMAT });
    };
    let mut r = Reader::new(suffix);
    let version = r.u16("migration_source.version")?;
    if version != 1 {
        return Err(VerifyError::Decode(r.error(
            "migration_source.version",
            Reason::BadTag(version.to_le_bytes()[0]),
        )));
    }
    if r.fixed::<16>("migration_source.book")? != *book {
        return Err(VerifyError::Coordinate);
    }
    let run = r.u128("migration_source.run")?;
    let body_digest = r.fixed("migration_source.run_body")?;
    let source_oid = r.fixed("migration_source.source_oid")?;
    let source_commit = r.fixed("migration_source.source_commit")?;
    let package_oid = r.fixed("migration_source.package_oid")?;
    let package_commit = r.fixed("migration_source.package_commit")?;
    if framed_hash(b"fa:oid:document:v1", &[book, &source_commit]) != source_oid
        || framed_hash(b"fa:oid:document:v1", &[book, &package_commit]) != package_oid
    {
        return Err(VerifyError::Coordinate);
    }
    let rows = r.u64("migration_source.source_rows")?;
    let n = r.count(MAX_CHUNKS, 48, "migration_source.chunks")?;
    if n == 0 || rows < n as u64 {
        return Err(scope_error(0));
    }
    let mut members = BTreeMap::new();
    for _ in 0..n {
        let vid = r.u128("migration_source.chunk.vid")?;
        let digest = r.fixed("migration_source.chunk.proposal_digest")?;
        if members.insert(vid, digest).is_some() {
            return Err(scope_error(0));
        }
    }
    r.finish("migration source manifest")?;
    Ok(Manifest {
        run,
        body_digest,
        evidence: [
            (source_oid, source_commit, 1),
            (package_oid, package_commit, 1),
        ],
        members,
    })
}

/// Every bound population is checked in full, even when the requested account
/// or effective-date range would select only some of its entries. Open and
/// abandoned populations may be partial; Finalize requires exact membership.
pub(super) fn verify(
    envelopes: &[LeafEnvelope],
    runs: &BTreeMap<u128, Run>,
    needed: &BTreeSet<u128>,
    chunks: &[Chunk],
    witnesses: &[(u64, &[u8])],
) -> Result<(), VerifyError> {
    let mut required: Vec<_> = runs
        .iter()
        .filter(|(run, _)| needed.contains(run))
        .filter_map(|(run, state)| {
            state
                .binding
                .map(|binding| (binding.index, *run, state, binding))
        })
        .collect();
    required.sort_by_key(|(index, ..)| *index);
    if required.len() != witnesses.len() {
        return Err(scope_error(required.first().map_or(0, |item| item.0)));
    }
    for ((index, run, state, binding), (supplied, bytes)) in required.into_iter().zip(witnesses) {
        if index != *supplied || framed_hash(DOMAIN, &[bytes]) != binding.digest {
            return Err(scope_error(index.min(*supplied)));
        }
        let bound = envelopes
            .get(index as usize)
            .ok_or_else(|| scope_error(index))?;
        let opened = envelopes
            .get(state.open_index as usize)
            .ok_or_else(|| scope_error(index))?;
        if bound.commit_seq <= opened.commit_seq || bound.effective_day != Some(state.open_day) {
            return Err(scope_error(index));
        }
        let manifest = manifest(bytes, &bound.book_id)?;
        if manifest.run != run || manifest.body_digest != state.digest {
            return Err(scope_error(index));
        }
        let mut declared_evidence = manifest.evidence;
        let mut actual_evidence = binding.evidence;
        declared_evidence.sort_unstable();
        actual_evidence.sort_unstable();
        if declared_evidence != actual_evidence {
            return Err(scope_error(index));
        }
        let mut actual = Vec::new();
        let mut seen = BTreeSet::new();
        for chunk in chunks.iter().filter(|chunk| chunk.run == run) {
            let envelope = envelopes
                .get(chunk.index as usize)
                .ok_or_else(|| scope_error(chunk.index))?;
            if chunk.index <= index
                || envelope.commit_seq <= bound.commit_seq
                || manifest.members.get(&chunk.vid) != Some(&chunk.digest)
                || !seen.insert(chunk.vid)
            {
                return Err(scope_error(chunk.index));
            }
            if let Some((terminal, _)) = state.terminal {
                let terminal = envelopes
                    .get(terminal as usize)
                    .ok_or_else(|| scope_error(terminal))?;
                if envelope.commit_seq >= terminal.commit_seq {
                    return Err(scope_error(chunk.index));
                }
            }
            actual.push((envelope.commit_seq, chunk.vid, chunk.digest));
        }
        if state.terminal.is_some_and(|(_, kind)| kind == 1) && seen.len() != manifest.members.len()
        {
            return Err(scope_error(index));
        }
        if state.terminal.is_some() {
            // The manifest's source order is immutable, but grouped staging may
            // submit members in any order. Finalize binds actual publication
            // order separately, exactly as the legacy tie-out already did.
            actual.sort_unstable_by_key(|(sequence, vid, _)| (*sequence, *vid));
            let mut list = Writer::default();
            list.count(actual.len());
            for (_, vid, digest) in actual {
                list.u128(vid).fixed(&digest);
            }
            let digest = framed_hash(
                b"fa:migration-tie-out:v2",
                &[&state.digest, &binding.digest, &list.buf],
            );
            if state.terminal_digest != Some(digest) {
                return Err(scope_error(index));
            }
        }
    }
    Ok(())
}
