//! Portable native trial balances and statements over a payload-complete checkpoint.
//!
//! This is the linear complete-prefix fallback from plan §13.1/§13.3. The
//! independent verifier derives selectors from every record, reconstructs the
//! historical chart and periods from schema controls, and refolds the report.
//! Native FGDB read certificates are retained as part of the source certificate;
//! they are not substituted for outsider-authenticated accounting inputs.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::migration::RunBody;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin, Writer};
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::{Bundle, Journal, StoredCheckpoint, code};

pub const REPORT_BUNDLE_FORMAT: &[u8] = b"fa:report-bundle:v1";
pub const MAX_REPORT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

fn refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §13.1–13.3 (report recomputation needs its complete authenticated closure)",
        "use a native v1/v2 trial-balance or v4 statement certificate and a checkpoint covering its known-at and any retained time frontier; preserve the complete historical schema and migration bodies",
    )
}

/// Read only immutable migration bodies needed by this report's historical
/// prefix. Whole-book read and produce authority must be checked before this
/// function is called, as for every complete-prefix proof export.
pub fn run_bodies<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    journal: &Journal,
    known_at: CommitSeq,
) -> Outcome<BTreeMap<VId, RunBody>> {
    let mut needed = BTreeSet::new();
    for leaf in &journal.leaves {
        if !leaf.envelope.is_entry() || leaf.envelope.commit_seq > known_at {
            continue;
        }
        let entry = Entry::decode(&leaf.payload)?;
        if let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin {
            needed.insert(*run_ref);
        }
    }
    Ok(crate::migration_balance::run_bodies(db, journal, &needed)?
        .map(|bodies| needed.into_iter().zip(bodies).collect()))
}

/// Package an already replayed native trial balance or statement. For an
/// instant-selected certificate, the facade supplies its observed time frontier
/// as `known_at` so the complete upper-tick closure is retained as well.
/// Legacy v1 statements require the recipient to supply the complete unit-ID
/// universe; use `assemble_with_registries` for an authenticated registry closure.
/// The facade performs current authority and retained-history
/// checks first. The returned bytes are deterministic, and their digest can
/// be signed by the existing detached `ProductionReceipt` format.
///
/// Wire: bytes(domain), u16 major=1, u16 minor=0, bytes(certificate),
/// bytes(signed checkpoint), bytes(prefix proof), list(proposal_len u32,
/// bytes(record)), list(open_leaf_index u64, bytes(migration body)). Every
/// checkpoint leaf has exactly one payload, in prefix order.
pub fn assemble(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &BTreeMap<VId, RunBody>,
) -> Outcome<Bundle> {
    assemble_inner(journal, checkpoint, certificate, known_at, bodies, &[])
}

/// Package a native statement with the exact canonical
/// registry documents bound by its source certificate. The facade verifies
/// their closure and the book's complete unit table before calling this API.
/// V2 appends a list of (registry name, canonical registry document) frames;
/// existing v1 trial-balance bytes remain unchanged.
pub fn assemble_with_registries(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &BTreeMap<VId, RunBody>,
    registries: &[(String, Vec<u8>)],
) -> Outcome<Bundle> {
    if !certificate.starts_with(b"fa:report-certificate:v4")
        || registries.iter().map(|(name, _)| name.as_str()).ne([
            "account_types",
            "entry_classes",
            "units",
            "foundations",
        ])
        || registries
            .iter()
            .any(|(_, bytes)| bytes.len() > 1024 * 1024)
    {
        return Ok(Err(refused(
            "native statements require all four canonical registry documents in closure order",
        )));
    }
    assemble_inner(
        journal,
        checkpoint,
        certificate,
        known_at,
        bodies,
        registries,
    )
}

fn assemble_inner(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &BTreeMap<VId, RunBody>,
    registries: &[(String, Vec<u8>)],
) -> Outcome<Bundle> {
    let major = if registries.is_empty() { 1 } else { 2 };
    if !(major == 1
        && (certificate.starts_with(b"fa:report-certificate:v1")
            || certificate.starts_with(b"fa:report-certificate:v2")
            || certificate.starts_with(b"fa:report-certificate:v4"))
        || major == 2 && certificate.starts_with(b"fa:report-certificate:v4"))
    {
        return Ok(Err(refused(
            "offline report bundles require a native v1/v2 trial balance or v4 statement",
        )));
    }
    if known_at > journal.through_seq || checkpoint.checkpoint.body.statement != journal.statement()
    {
        return Ok(Err(refused(
            "the checkpoint must authenticate a complete prefix through the report's known-at and any retained time frontier",
        )));
    }
    let prefix = journal.prefix_proof()?;
    let mut budget = 4usize + REPORT_BUNDLE_FORMAT.len() + 4 + 4 * 3 + 4 * 2;
    for len in [certificate.len(), checkpoint.bytes.len(), prefix.len()] {
        budget = budget.saturating_add(len);
    }
    if major == 2 {
        budget = budget.saturating_add(4);
        for (name, canonical) in registries {
            budget = budget
                .saturating_add(8)
                .saturating_add(name.len())
                .saturating_add(canonical.len());
        }
    }
    let mut ordered = Vec::new();
    let mut supplied = BTreeSet::new();
    for (index, leaf) in journal.leaves.iter().enumerate() {
        budget = budget.saturating_add(8).saturating_add(leaf.payload.len());
        if budget > MAX_REPORT_BUNDLE_BYTES {
            return Ok(Err(refused("the complete report closure exceeds 64 MiB")));
        }
        if leaf.authenticated_record()?.is_none() {
            return Ok(Err(refused(format!(
                "checkpoint leaf {index} does not match its record"
            ))));
        }
        if !leaf.envelope.is_entry() || leaf.envelope.commit_seq > known_at {
            continue;
        }
        let entry = Entry::decode(&leaf.payload)?;
        if entry.proposal.class == EntryClass::MIGRATION_CONTROL
            && let Some(ControlPayload::MigrationControl {
                run_ref,
                kind: 0,
                tie_out_digest,
            }) = &entry.proposal.control
            && let Some(body) = bodies.get(run_ref)
        {
            if !supplied.insert(*run_ref)
                || body.vid() != *run_ref
                || body.digest()? != *tie_out_digest
            {
                return Ok(Err(refused(
                    "a migration body does not match its unique Open control",
                )));
            }
            let bytes = body.canonical_bytes()?;
            budget = budget.saturating_add(12).saturating_add(bytes.len());
            ordered.push((index as u64, bytes));
        }
    }
    if supplied.len() != bodies.len() || budget > MAX_REPORT_BUNDLE_BYTES {
        return Ok(Err(refused(
            "the migration closure is unmatched or exceeds 64 MiB",
        )));
    }
    let mut w = Writer::with_capacity(budget);
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(major)
        .u16(0)
        .bytes(certificate)
        .bytes(&checkpoint.bytes)
        .bytes(&prefix)
        .list(&journal.leaves, |w, leaf| {
            w.u32(u32::try_from(leaf.proposal_len).unwrap_or(u32::MAX))
                .bytes(&leaf.payload);
        })
        .list(&ordered, |w, (index, bytes)| {
            w.u64(*index).bytes(bytes);
        });
    if major == 2 {
        w.list(registries, |w, (name, canonical)| {
            w.str(name).bytes(canonical);
        });
    }
    let bytes = w.finish().map_err(fa_model::EntryError::from)?;
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Ok(Err(refused("the complete report closure exceeds 64 MiB")));
    }
    let mut hash = Hasher::new();
    hash.update(REPORT_BUNDLE_FORMAT);
    hash.update(&bytes);
    Ok(Ok(Bundle {
        bytes,
        digest: hash.finalize().0,
    }))
}
