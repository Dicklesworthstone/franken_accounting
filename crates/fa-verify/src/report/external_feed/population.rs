//! Independently declared gross source deliveries for a bounded feed window.

use super::{VerifiedExternalFeed, identifier};
use std::collections::{BTreeMap, BTreeSet};

type Cell = (u128, u32, Vec<(u32, u128)>);

/// Recipient-held source extract declaration. See `docs/external_feed_manifest.md`.
#[derive(Debug)]
pub struct ExternalFeedManifest {
    book: [u8; 16],
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
