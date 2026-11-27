//! Independently declared gross source deliveries for a bounded feed window.

use super::{VerifiedExternalFeed, framed_digest, identifier, invalid, source};
use crate::codec::Reader;
use crate::report::{ReportError, text};
use std::collections::{BTreeMap, BTreeSet};

const WORKPAPER_FORMAT: &[u8] = b"fa:external-feed-manifest:v1";

type Cell = (u128, u32, Vec<(u32, u128)>);

/// Recipient-held source extract declaration. See `docs/external_feed_manifest.md`.
#[derive(Debug)]
pub struct ExternalFeedManifest {
    book: [u8; 16],
    workpaper_commit: Option<[u8; 32]>,
    feed: String,
    pub(crate) extract: String,
    pub(crate) from: i32,
    pub(crate) through: i32,
    rows: u64,
    children: BTreeMap<String, [u8; 32]>,
    gross: BTreeMap<Cell, [i128; 2]>,
    pub(crate) digest: [u8; 32],
}

fn hex<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    if raw.len() != 2 * N
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("expected {} lowercase hex digits", 2 * N));
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).map_err(|_| "invalid hex")?;
    }
    Ok(out)
}

fn number<T: std::str::FromStr + std::fmt::Display>(raw: &str) -> Result<T, String> {
    raw.parse::<T>()
        .ok()
        .filter(|n| n.to_string() == raw)
        .ok_or_else(|| "expected a canonical, in-range decimal integer".into())
}

fn dimensions(raw: &str) -> Result<Vec<(u32, u128)>, String> {
    let mut dims = Vec::new();
    if raw != "-" {
        for pair in raw.split(',') {
            let (kind, value) = pair
                .split_once('=')
                .ok_or("expected kind=value in dimensions")?;
            let kind = number(kind)?;
            if dims.len() >= 64 || dims.last().is_some_and(|&(last, _)| last >= kind) {
                return Err("dimension kinds must increase within the 64-kind bound".into());
            }
            dims.push((kind, u128::from_be_bytes(hex(value)?)));
        }
    }
    Ok(dims)
}

fn fields(line: &str) -> Result<Vec<&str>, String> {
    // A full 64-kind dimension set with u32::MAX kinds fits within 4 KiB.
    if line.len() > 4096 {
        return Err("external-feed manifest line exceeds 4096 bytes".into());
    }
    Ok(line.split(' ').collect())
}

impl ExternalFeedManifest {
    /// Decode a bounded v1 source declaration supplied independently of the report.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.starts_with(WORKPAPER_FORMAT) {
            return Self::parse_workpaper(bytes).map_err(|error| error.detail);
        }
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("external-feed manifest exceeds 8 MiB".into());
        }
        let mut lines = std::str::from_utf8(bytes)
            .map_err(|_| "expected UTF-8 manifest")?
            .lines();
        if lines.next() != Some("fa:external-feed-population:v1") {
            return Err("unknown external-feed population format".into());
        }
        let header = fields(lines.next().unwrap_or_default())?;
        let [book, feed, extract, from, through, rows] = header.as_slice() else {
            return Err("expected book, feed, extract, from-day, through-day and row count".into());
        };
        let from = number(from)?;
        let through = number(through)?;
        if from > through || !identifier(feed, 64) || !identifier(extract, 128) {
            return Err("invalid source window, feed or extract identifier".into());
        }
        let mut manifest = Self {
            book: hex(book)?,
            workpaper_commit: None,
            feed: feed.to_string(),
            extract: extract.to_string(),
            from,
            through,
            rows: number(rows)?,
            children: BTreeMap::new(),
            gross: BTreeMap::new(),
            digest: crate::blake3::hash(bytes),
        };
        for line in lines {
            match fields(line)?.as_slice() {
                ["child", key, oid] if identifier(key, 128) => {
                    if manifest
                        .children
                        .insert(key.to_string(), hex(oid)?)
                        .is_some()
                    {
                        return Err(format!("duplicate declared child {key}"));
                    }
                }
                ["cell", account, unit, dims, debit, credit] => {
                    let key = (
                        u128::from_be_bytes(hex(account)?),
                        number(unit)?,
                        dimensions(dims)?,
                    );
                    let gross = [number::<i128>(debit)?, number::<i128>(credit)?];
                    if gross.iter().any(|v| *v < 0) || gross == [0, 0] {
                        return Err(
                            "gross amounts must be nonnegative with at least one nonzero side"
                                .into(),
                        );
                    }
                    if manifest.gross.insert(key, gross).is_some() {
                        return Err("duplicate declared gross cell".into());
                    }
                }
                _ => return Err("expected a child or cell declaration".into()),
            }
        }
        Ok(manifest)
    }

    /// Parse the exact binary declaration whose journaled review is required.
    pub fn parse_reviewed_workpaper(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(WORKPAPER_FORMAT) {
            return Err(
                "a reviewed population requires the canonical binary manifest Workpaper".into(),
            );
        }
        Self::parse_workpaper(bytes).map_err(|error| error.detail)
    }

    pub(super) fn workpaper_identity(&self) -> Result<([u8; 32], [u8; 32]), ReportError> {
        let commit = self.workpaper_commit.ok_or_else(|| {
            crate::report::failed(
                "external_feed_manifest_review",
                "a reviewed population requires the canonical binary manifest Workpaper",
            )
        })?;
        Ok((
            framed_digest(b"fa:oid:document:v1", &[&self.book, &commit]),
            commit,
        ))
    }

    /// Decode the canonical Workpaper emitted by `fa subledger manifest`.
    /// It carries book-independent commitments; scope each to the declared book
    /// using the same independent document identity law as source verification.
    fn parse_workpaper(bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > 1024 * 1024 {
            return Err(invalid("external-feed manifest Workpaper exceeds 1 MiB"));
        }
        let mut r = Reader::new(&bytes[WORKPAPER_FORMAT.len()..]);
        let book: [u8; 16] = r.fixed("manifest.book")?;
        let feed = text(&mut r, 64, "manifest.feed")?;
        let extract = text(&mut r, 128, "manifest.extract")?;
        let from = r.i32("manifest.from")?;
        let through = r.i32("manifest.through")?;
        if !identifier(feed, 64) || !identifier(extract, 128) || from > through {
            return Err(invalid("invalid manifest identifier or effective window"));
        }
        let rows = r.u64("manifest.rows")?;
        let child_count = r.count(4096, 37, "manifest.children")?;
        if rows < child_count as u64 || rows > (child_count * source::MAX_DETAIL_ROWS) as u64 {
            return Err(invalid(
                "source row count exceeds the declared child population's bounds",
            ));
        }
        let mut children = BTreeMap::<String, [u8; 32]>::new();
        for _ in 0..child_count {
            let key = text(&mut r, 128, "manifest.child.key")?;
            let commit: [u8; 32] = r.fixed("manifest.child.commit")?;
            if !identifier(key, 128) || commit == [0; 32] {
                return Err(invalid(
                    "manifest child needs a valid key and a nonzero Workpaper commitment",
                ));
            }
            if children
                .last_key_value()
                .is_some_and(|(last, _)| last.as_str() >= key)
            {
                return Err(invalid("manifest child keys must be strictly ordered"));
            }
            let oid = framed_digest(b"fa:oid:document:v1", &[&book, &commit]);
            children.insert(key.to_string(), oid);
        }
        let cells = r.count(4096, 56, "manifest.cells")?;
        if children.is_empty() != (cells == 0) {
            return Err(invalid(
                "manifest children and gross cells must both be empty or both populated",
            ));
        }
        let mut gross = BTreeMap::new();
        for _ in 0..cells {
            let key = (
                r.u128("manifest.cell.account")?,
                r.u32("manifest.cell.unit")?,
                source::dimensions(&mut r)?,
            );
            let amounts = [
                r.i128("manifest.cell.debits")?,
                r.i128("manifest.cell.credits")?,
            ];
            if amounts.iter().any(|v| *v < 0) || amounts == [0, 0] {
                return Err(invalid(
                    "manifest gross sides must be nonnegative with a nonzero amount",
                ));
            }
            if gross.last_key_value().is_some_and(|(last, _)| last >= &key) {
                return Err(invalid("manifest gross cells must be strictly ordered"));
            }
            gross.insert(key, amounts);
        }
        r.finish("external-feed manifest")?;
        Ok(Self {
            book,
            workpaper_commit: Some(crate::document::doc_commit(21, bytes)),
            feed: feed.to_string(),
            extract: extract.to_string(),
            from,
            through,
            rows,
            children,
            gross,
            digest: crate::blake3::hash(bytes),
        })
    }

    /// Compare original source deliveries in the window. Reversing a financial
    /// posting does not deliver a second copy of its source detail.
    pub fn verify(&self, report: &VerifiedExternalFeed) -> Result<(), String> {
        if report.book_id != self.book
            || report.feed != self.feed
            || report.effective_through != self.through
        {
            return Err(
                "manifest book, feed or through-day differs from the verified report".into(),
            );
        }
        let mut delivered = BTreeSet::new();
        let mut rows = 0u64;
        let mut gross = BTreeMap::<Cell, [i128; 2]>::new();
        for batch in &report.batches {
            if !(self.from..=self.through).contains(&batch.effective_date) {
                continue;
            }
            match self.children.get(&batch.batch_key) {
                None => return Err(format!("undeclared child {}", batch.batch_key)),
                Some(oid) if *oid != batch.document_oid => {
                    return Err(format!(
                        "detail Workpaper OID mismatch for child {}",
                        batch.batch_key
                    ));
                }
                _ => {}
            }
            if !batch.reconciled
                || batch.feed != self.feed
                || !delivered.insert(batch.batch_key.as_str())
            {
                return Err(format!("unverified or duplicate child {}", batch.batch_key));
            }
            rows = rows
                .checked_add(batch.detail_rows as u64)
                .ok_or("source row count overflow")?;
            for leg in &batch.summary_legs {
                let key = (leg.account, leg.unit, leg.dimension_set.clone());
                let value = &mut gross.entry(key).or_default()[usize::from(leg.credit)];
                *value = value
                    .checked_add(leg.amount)
                    .ok_or("source gross total overflow")?;
            }
        }
        if let Some(missing) = self
            .children
            .keys()
            .find(|key| !delivered.contains(key.as_str()))
        {
            return Err(format!("missing child {missing}"));
        }
        if self.rows != rows {
            return Err(format!(
                "declared {} source rows, verified {rows}",
                self.rows
            ));
        }
        for (cell, expected) in &self.gross {
            let actual = gross.remove(cell).unwrap_or_default();
            if actual != *expected {
                return Err(format!(
                    "gross mismatch at account {:032x}, unit {}, dimensions {:?}: declared {expected:?}, verified {actual:?}",
                    cell.0, cell.1, cell.2
                ));
            }
        }
        if let Some((cell, amounts)) = gross.first_key_value() {
            return Err(format!(
                "undeclared gross cell at account {:032x}, unit {}, dimensions {:?}: verified {amounts:?}",
                cell.0, cell.1, cell.2
            ));
        }
        Ok(())
    }
}
