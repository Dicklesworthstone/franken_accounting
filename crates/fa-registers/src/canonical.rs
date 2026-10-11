//! Canonical bytes of a trial balance (plan §13.6, bead fa-cqk): the exact
//! values a report certificate's `output_digest` and per-row digests bind.
//!
//! The encoding is the Appendix A canonical codec over exact values only:
//! account vids and codes, names, account types, unit ids, mantissas, the
//! resolved selector and the known-at sequence. Rendering never enters it, so
//! a units table that formats an amount differently cannot move a digest,
//! while any amount, row or selector that differs always does. Rows keep the
//! report's own order (code, then unit), which the fold fixes.
//!
//! [`entries_at_seq`] and [`entry_period_code`] expose the fold's own entry
//! selection, so a certificate's status names later entries exactly as the
//! report would select them (migration visibility and special periods
//! included), never by a second, approximate rule.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_model::{EncodeError, Entry, Writer};
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::{RegisterError, TbRow, TrialBalance};

/// The visible trunk entries at `seq`, each with its creating sequence, as
/// every report folds them.
pub fn entries_at_seq<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    seq: CommitSeq,
) -> Result<Vec<(VId, Entry, CommitSeq)>, RegisterError> {
    crate::entries_at(db, book, seq)
}

/// The period code an entry posts into, as the period-activity report
/// resolves it.
pub fn entry_period_code(book: &BookContext, entry: &Entry) -> Result<String, RegisterError> {
    crate::entry_period(book, entry)
}

/// Domain of [`TrialBalance::output_digest`].
pub const TRIAL_BALANCE_DIGEST_DOMAIN: &[u8] = b"fa:trial-balance:v1";

/// Domain of [`TbRow::digest`].
pub const TB_ROW_DIGEST_DOMAIN: &[u8] = b"fa:trial-balance-row:v1";

impl TbRow {
    fn write(&self, w: &mut Writer) {
        w.u128(self.account.0)
            .str(&self.code)
            .str(&self.name)
            .u8(self.account_type.0)
            .u32(self.unit_id)
            .i128(self.debits)
            .i128(self.credits)
            .i128(self.debits_pending)
            .i128(self.credits_pending);
    }

    /// The row's canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.finish()
    }

    /// `BLAKE3("fa:trial-balance-row:v1" ‖ canonical_bytes)`.
    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        let mut h = Hasher::new();
        h.update(TB_ROW_DIGEST_DOMAIN);
        h.update(&self.canonical_bytes()?);
        Ok(h.finalize().0)
    }
}

fn totals(w: &mut Writer, totals: &BTreeMap<u32, (i128, i128)>) {
    let rows: Vec<(u32, i128, i128)> = totals.iter().map(|(u, (d, c))| (*u, *d, *c)).collect();
    w.list(&rows, |w, (unit, debits, credits)| {
        w.u32(*unit).i128(*debits).i128(*credits);
    });
}

impl TrialBalance {
    /// The report's canonical bytes: selector, known-at, mode, every row,
    /// and the posted and pending per-unit totals.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.list(&self.periods, |w, p| {
            w.str(p);
        })
        .u64(self.known_at.0)
        .opt(self.effective_through.as_ref(), |w, day| {
            w.i32(day.0);
        })
        .bool(self.activity)
        .list(&self.rows, |w, row| row.write(w));
        totals(&mut w, &self.unit_totals);
        totals(&mut w, &self.pending_unit_totals);
        w.finish()
    }

    /// `BLAKE3("fa:trial-balance:v1" ‖ canonical_bytes)`.
    pub fn output_digest(&self) -> Result<[u8; 32], EncodeError> {
        let mut h = Hasher::new();
        h.update(TRIAL_BALANCE_DIGEST_DOMAIN);
        h.update(&self.canonical_bytes()?);
        Ok(h.finalize().0)
    }

    /// One [`TbRow::digest`] per row, in report order: a replay that
    /// disagrees can name the first row that moved.
    pub fn row_digests(&self) -> Result<Vec<[u8; 32]>, EncodeError> {
        self.rows.iter().map(TbRow::digest).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::AccountType;
    use fa_time::DateDay;

    fn row(code: &str, debits: i128) -> TbRow {
        TbRow {
            account: VId(7),
            code: code.into(),
            name: "Cash".into(),
            account_type: AccountType(1),
            unit_id: 1,
            debits,
            credits: 0,
            debits_pending: 0,
            credits_pending: 0,
        }
    }

    fn tb(rows: Vec<TbRow>) -> TrialBalance {
        let mut unit_totals = BTreeMap::new();
        unit_totals.insert(1, (rows.iter().map(|r| r.debits).sum(), 0));
        TrialBalance {
            periods: vec!["FY2026-P03".into()],
            known_at: CommitSeq(9),
            effective_through: Some(DateDay(20_543)),
            activity: false,
            rows,
            unit_totals,
            pending_unit_totals: BTreeMap::new(),
        }
    }

    #[test]
    fn the_encoding_is_deterministic_and_binds_every_value() {
        let base = tb(vec![row("1000", 1_234), row("2000", 5)]);
        let digest = base.output_digest().expect("encode");
        assert_eq!(digest, base.clone().output_digest().expect("encode"));
        assert_eq!(base.row_digests().expect("rows").len(), 2);

        let mut moved = base.clone();
        moved.rows[0].debits = 1_235;
        assert_ne!(moved.output_digest().expect("encode"), digest);
        assert_ne!(
            moved.row_digests().expect("rows")[0],
            base.row_digests().expect("rows")[0]
        );
        assert_eq!(
            moved.row_digests().expect("rows")[1],
            base.row_digests().expect("rows")[1],
            "an untouched row keeps its digest, so a mismatch names the row that moved"
        );

        let mut renamed = base.clone();
        renamed.rows[1].name = "Cash (renamed)".into();
        assert_ne!(renamed.output_digest().expect("encode"), digest);

        let mut later = base.clone();
        later.known_at = CommitSeq(10);
        assert_ne!(later.output_digest().expect("encode"), digest);

        let mut cutoff = base.clone();
        cutoff.effective_through = None;
        assert_ne!(cutoff.output_digest().expect("encode"), digest);

        let mut reordered = base.clone();
        reordered.rows.swap(0, 1);
        assert_ne!(reordered.output_digest().expect("encode"), digest);

        let mut pending = base.clone();
        pending.pending_unit_totals.insert(1, (0, 0));
        assert_ne!(pending.output_digest().expect("encode"), digest);
    }
}
