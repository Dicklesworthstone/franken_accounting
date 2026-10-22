//! Independent decoding of the native Reconciled claim and its retained bank
//! interpretations. This checks canonical shape and the self-contained source
//! bindings. Inclusion authenticates the claim; decoding alone does not refold
//! cash or prove that its native confirmations and imports existed.

use std::collections::BTreeSet;

use super::MAX_RECORD_BYTES;
use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason};

mod csv_layout;

// Pinned wire limits and evidence kind from the public registries. The
// independent verifier does not link the kernel's model or registry decoder.
const MAX_BANK_LINES: usize = 1022;
const MAX_PREDECESSORS: usize = 4096;
const WORKPAPER_KIND: u8 = 21;

pub(super) struct Source {
    pub manifest_oid: [u8; 32],
    pub statement_oid: [u8; 32],
}

struct Predecessor {
    manifest_oid: [u8; 32],
    manifest_commit: [u8; 32],
    statement_oid: [u8; 32],
    statement_commit: [u8; 32],
    recorded_at: u64,
    sequence: u64,
    date: i32,
    closing: i128,
}

struct Manifest {
    book: [u8; 16],
    account: u128,
    unit: u32,
    oid: [u8; 32],
    commitment: [u8; 32],
    statement_oid: [u8; 32],
    statement_commit: [u8; 32],
    sequence: u64,
    date: i32,
    closing: i128,
    line_count: usize,
    predecessor: Option<Predecessor>,
}

fn document_oid(book: &[u8; 16], commitment: &[u8; 32]) -> [u8; 32] {
    hash_parts(
        b"fa:oid:document:v1",
        &[
            &16_u32.to_le_bytes(),
            book,
            &32_u32.to_le_bytes(),
            commitment,
        ],
    )
}

fn manifest(bytes: &[u8]) -> Result<Manifest, DecodeError> {
    let mut r = Reader::new(bytes);
    if r.fixed::<14>("bank_import.magic")? != *b"FA-BANK-IMPORT" {
        return Err(r.error("bank_import.magic", Reason::BadTag(0)));
    }
    let major = r.u16("bank_import.major")?;
    if !matches!(major, 1 | 2 | 3) || r.u16("bank_import.minor")? != 0 {
        return Err(r.error("bank_import.version", Reason::BadTag(0)));
    }
    let book = r.fixed("bank_import.book")?;
    let account = r.u128("bank_import.account")?;
    let parser = r.u8("bank_import.parser")?;
    if !(1..=6).contains(&parser) {
        return Err(r.error("bank_import.parser", Reason::BadTag(parser)));
    }
    if r.u16("bank_import.parser_revision")? != 1 {
        return Err(r.error("bank_import.parser_revision", Reason::BadTag(0)));
    }
    let statement_oid = r.fixed("bank_import.statement_oid")?;
    let statement_commit = r.fixed("bank_import.statement_commit")?;
    let unit = r.u32("bank_import.unit")?;
    let sequence = r.u64("bank_import.sequence")?;
    let date = r.i32("bank_import.statement_date")?;
    let opening = r.i128("bank_import.opening")?;
    let closing = r.i128("bank_import.closing")?;
    let line_count = r.count(MAX_BANK_LINES, 32, "bank_import.lines")?;
    let mut lines = BTreeSet::new();
    for _ in 0..line_count {
        if !lines.insert(r.fixed::<32>("bank_import.line_oid")?) {
            return Err(r.error("bank_import.duplicate_line", Reason::Unsorted));
        }
    }
    if major == 3 {
        if parser != 6 {
            return Err(r.error("bank_import.csv_layout_parser", Reason::BadTag(parser)));
        }
        csv_layout::validate(
            r.bytes(16 * 1024, "bank_import.csv_layout")?,
            sequence,
            date,
        )?;
    }
    let predecessor = if major == 2 || (major == 3 && r.present("bank_import.predecessor")?) {
        let manifest_oid = r.fixed("bank_predecessor.manifest_oid")?;
        let manifest_commit = r.fixed("bank_predecessor.manifest_commit")?;
        let statement_oid = r.fixed("bank_predecessor.statement_oid")?;
        let statement_commit = r.fixed("bank_predecessor.statement_commit")?;
        r.u128("bank_predecessor.import_run")?;
        r.fixed::<32>("bank_predecessor.receipt_hash")?;
        Some(Predecessor {
            manifest_oid,
            manifest_commit,
            statement_oid,
            statement_commit,
            recorded_at: r.u64("bank_predecessor.recorded_at")?,
            sequence: r.u64("bank_predecessor.sequence")?,
            date: r.i32("bank_predecessor.date")?,
            closing: r.i128("bank_predecessor.closing")?,
        })
    } else {
        None
    };
    if let Some(previous) = &predecessor
        && (previous.statement_oid == statement_oid
            || previous.sequence.checked_add(1) != Some(sequence)
            || previous.date > date
            || previous.closing != opening)
    {
        return Err(r.error("bank_import.predecessor_continuity", Reason::BadTag(0)));
    }
    r.finish("bank_import.manifest")?;
    let commitment = crate::document::doc_commit(WORKPAPER_KIND, bytes);
    Ok(Manifest {
        book,
        account,
        unit,
        oid: document_oid(&book, &commitment),
        commitment,
        statement_oid,
        statement_commit,
        sequence,
        date,
        closing,
        line_count,
        predecessor,
    })
}

pub(super) fn read(
    r: &mut Reader<'_>,
    book: [u8; 16],
    commit_seq: u64,
) -> Result<Source, DecodeError> {
    let manifest_oid = r.fixed::<32>("reconciled.manifest_oid")?;
    let current = manifest(r.bytes(MAX_RECORD_BYTES, "reconciled.manifest")?)?;
    if current.book != book || current.oid != manifest_oid {
        return Err(r.error("reconciled.manifest_identity", Reason::BadTag(0)));
    }
    let source = Source {
        manifest_oid,
        statement_oid: current.statement_oid,
    };
    let closing = current.closing;
    let line_count = current.line_count;
    let count = r.count(MAX_PREDECESSORS, 4, "reconciled.predecessors")?;
    let mut first_import = None;
    let mut previous_import = None;
    let mut seen = BTreeSet::from([current.statement_oid]);
    let mut newer = current;
    for _ in 0..count {
        let older = manifest(r.bytes(MAX_RECORD_BYTES, "reconciled.predecessor")?)?;
        let Some(binding) = &newer.predecessor else {
            return Err(r.error("reconciled.predecessor_closure", Reason::BadTag(0)));
        };
        if older.book != newer.book
            || older.account != newer.account
            || older.unit != newer.unit
            || older.oid != binding.manifest_oid
            || older.commitment != binding.manifest_commit
            || older.statement_oid != binding.statement_oid
            || older.statement_commit != binding.statement_commit
            || older.sequence != binding.sequence
            || older.date != binding.date
            || older.closing != binding.closing
            || binding.recorded_at == 0
            || previous_import.is_some_and(|newer| binding.recorded_at >= newer)
            || !seen.insert(older.statement_oid)
        {
            return Err(r.error("reconciled.predecessor_binding", Reason::BadTag(0)));
        }
        first_import.get_or_insert(binding.recorded_at);
        previous_import = Some(binding.recorded_at);
        newer = older;
    }
    if newer.predecessor.is_some() {
        return Err(r.error("reconciled.predecessor_closure", Reason::BadTag(0)));
    }
    r.u128("reconciled.import_run")?;
    r.fixed::<32>("reconciled.import_receipt_hash")?;
    let imported = r.u64("reconciled.import_recorded_at")?;
    let evaluated = r.u64("reconciled.evaluated_known_at")?;
    // The native close publishes immediately after the exact reviewed prefix.
    // This equality is self-contained in the claim and its authenticated leaf
    // position; it requires neither later state nor a cash refold.
    if evaluated.checked_add(1) != Some(commit_seq) {
        return Err(r.error("reconciled.recorded_at", Reason::BadTag(0)));
    }
    let cash = r.i128("reconciled.cash_balance")?;
    r.fixed::<32>("reconciled.cash_fold_digest")?;
    let count = r.count(MAX_BANK_LINES, 48, "reconciled.matches")?;
    if imported == 0
        || imported > evaluated
        || first_import.is_some_and(|previous| previous >= imported)
        || cash != closing
        || count != line_count
    {
        return Err(r.error("reconciled.exact_close", Reason::BadTag(0)));
    }
    let mut previous = None;
    for _ in 0..count {
        let matched = (
            r.u128("reconciled.match.vid")?,
            r.fixed::<32>("reconciled.match.digest")?,
        );
        if previous.is_some_and(|prior| prior >= matched) {
            return Err(r.error("reconciled.matches", Reason::Unsorted));
        }
        previous = Some(matched);
    }
    Ok(source)
}

#[cfg(test)]
mod tests;
