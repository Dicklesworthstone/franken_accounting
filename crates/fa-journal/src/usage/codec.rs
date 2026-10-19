//! Canonical immutable spending receipts and their disposable usage cells.

use fa_model::symbols::{label, property};
use fa_model::{EntryRef, Id128, Reader, Writer, domain_digest};
use fa_money::UnitId;
use fa_time::DateDay;
use fgdb::VertexRow;
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalScalar, VId};

use crate::KernelError;
use crate::rows::{bytes, int, scalar_bytes};

const CELL_FORMAT: &[u8] = b"fa:usage-cell:v1";
const DEBIT_FORMAT: &[u8] = b"fa:usage-debit:v1";
const MAX_BYTES: usize = 512;

pub(super) fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("daily spending usage: {}", message.into()))
}

fn decoding(error: fa_model::DecodeError) -> KernelError {
    corrupt(error.to_string())
}

/// All descendants of one root issuance share this day and native unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsageKey {
    pub book_id: Id128,
    pub root_issuance: [u8; 32],
    pub day: DateDay,
    pub unit: UnitId,
}

impl UsageKey {
    fn encode(self, w: &mut Writer) {
        w.fixed(&self.book_id.0)
            .fixed(&self.root_issuance)
            .i32(self.day.0)
            .u32(self.unit.0);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, KernelError> {
        Ok(Self {
            book_id: Id128(r.fixed("usage.book").map_err(decoding)?),
            root_issuance: r.fixed("usage.root").map_err(decoding)?,
            day: DateDay(r.i32("usage.day").map_err(decoding)?),
            unit: UnitId(r.u32("usage.unit").map_err(decoding)?),
        })
    }

    fn identity(self, domain: &[u8], generation: Option<i64>) -> VId {
        let mut parts = vec![
            self.book_id.0.to_vec(),
            self.root_issuance.to_vec(),
            self.day.0.to_le_bytes().to_vec(),
            self.unit.0.to_le_bytes().to_vec(),
        ];
        if let Some(generation) = generation {
            parts.push(generation.to_le_bytes().to_vec());
        }
        let parts: Vec<_> = parts.iter().map(Vec::as_slice).collect();
        let digest = domain_digest(domain, &parts);
        let mut low = [0_u8; 16];
        low.copy_from_slice(&digest[..16]);
        VId(u128::from_le_bytes(low))
    }

    #[must_use]
    pub fn cell_vid(self) -> VId {
        self.identity(b"fa:vid:usage-cell:v1", None)
    }

    /// A generation can be consumed once only, even if its cell is lost or
    /// rolled back. The substrate never allows a spent identity to be reused.
    #[must_use]
    pub fn debit_vid(self, generation: i64) -> VId {
        self.identity(b"fa:vid:usage-debit:v1", Some(generation))
    }
}

/// Rebuildable reservation projection. Positive generations always have a
/// corresponding immutable receipt; absence is not a stored zero balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageCell {
    pub key: UsageKey,
    pub gross_debits: i128,
    pub generation: i64,
}

impl UsageCell {
    pub fn canonical_bytes(self) -> Result<Vec<u8>, KernelError> {
        if self.gross_debits <= 0 || self.generation <= 0 {
            return Err(corrupt("cell amounts and generation must be positive"));
        }
        let mut w = Writer::new();
        w.bytes(CELL_FORMAT);
        self.key.encode(&mut w);
        w.i128(self.gross_debits).i64(self.generation);
        w.finish().map_err(Into::into)
    }

    fn decode(input: &[u8]) -> Result<Self, KernelError> {
        if input.len() > MAX_BYTES {
            return Err(corrupt("oversize cell"));
        }
        let mut r = Reader::new(input);
        if r.bytes(64, "usage.cell.format").map_err(decoding)? != CELL_FORMAT {
            return Err(corrupt("unsupported cell format"));
        }
        let cell = Self {
            key: UsageKey::decode(&mut r)?,
            gross_debits: r.i128("usage.cell.gross").map_err(decoding)?,
            generation: r.i64("usage.cell.generation").map_err(decoding)?,
        };
        r.finish().map_err(decoding)?;
        if cell.canonical_bytes()?.as_slice() != input {
            return Err(corrupt("noncanonical cell"));
        }
        Ok(cell)
    }

    pub fn properties(self) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
        let payload = self.canonical_bytes()?;
        Ok(vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("usage.cell", payload.clone())?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes(
                    "usage.cell.digest",
                    domain_digest(b"fa:usage-cell-digest:v1", &[&payload]).to_vec(),
                )?,
            ),
            (property::GENERATION, CanonicalScalar::Int(self.generation)),
        ])
    }

    pub fn from_row(row: &VertexRow, key: UsageKey) -> Result<Self, KernelError> {
        let cell = Self::decode(&bytes(row, property::FA_PAYLOAD, "usage cell payload")?)?;
        if cell.key != key
            || row.vid != key.cell_vid()
            || row.labels.as_slice() != [label::USAGE_CELL]
            || row.retired_at.is_some()
            || int(row, property::GENERATION, "usage cell generation")? != cell.generation
            || row.props != cell.properties()?
        {
            return Err(corrupt(
                "cell identity, binding, generation or mirrors disagree",
            ));
        }
        Ok(cell)
    }
}

/// One immutable admission fact, created with the unchanged accounting Entry.
/// It consumes a positive gross debit; reversals and voids never refund it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageDebit {
    pub key: UsageKey,
    pub generation: i64,
    pub entry: EntryRef,
    pub capability: [u8; 32],
    pub tick: EntryRef,
    pub time_zone_policy: u8,
    pub gross_debits: i128,
    pub previous_gross_debits: i128,
    pub total_gross_debits: i128,
}

impl UsageDebit {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        if self.generation <= 0
            || self.gross_debits <= 0
            || self.previous_gross_debits < 0
            || self.previous_gross_debits.checked_add(self.gross_debits)
                != Some(self.total_gross_debits)
            || (self.generation == 1) != (self.previous_gross_debits == 0)
            || self.time_zone_policy != crate::TimeZonePolicy::Utc.tag()
        {
            return Err(corrupt(
                "invalid receipt amounts, generation or time policy",
            ));
        }
        let mut w = Writer::new();
        w.bytes(DEBIT_FORMAT);
        self.key.encode(&mut w);
        w.i64(self.generation);
        self.entry.encode(&mut w);
        w.fixed(&self.capability);
        self.tick.encode(&mut w);
        w.u8(self.time_zone_policy)
            .i128(self.gross_debits)
            .i128(self.previous_gross_debits)
            .i128(self.total_gross_debits);
        w.finish().map_err(Into::into)
    }

    fn decode(input: &[u8]) -> Result<Self, KernelError> {
        if input.len() > MAX_BYTES {
            return Err(corrupt("oversize receipt"));
        }
        let mut r = Reader::new(input);
        if r.bytes(64, "usage.debit.format").map_err(decoding)? != DEBIT_FORMAT {
            return Err(corrupt("unsupported receipt format"));
        }
        let debit = Self {
            key: UsageKey::decode(&mut r)?,
            generation: r.i64("usage.debit.generation").map_err(decoding)?,
            entry: EntryRef::decode(&mut r).map_err(decoding)?,
            capability: r.fixed("usage.debit.capability").map_err(decoding)?,
            tick: EntryRef::decode(&mut r).map_err(decoding)?,
            time_zone_policy: r.u8("usage.debit.time_zone_policy").map_err(decoding)?,
            gross_debits: r.i128("usage.debit.gross").map_err(decoding)?,
            previous_gross_debits: r.i128("usage.debit.previous").map_err(decoding)?,
            total_gross_debits: r.i128("usage.debit.total").map_err(decoding)?,
        };
        r.finish().map_err(decoding)?;
        if debit.canonical_bytes()?.as_slice() != input {
            return Err(corrupt("noncanonical receipt"));
        }
        Ok(debit)
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        self.key.debit_vid(self.generation)
    }

    pub fn properties(&self) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
        let payload = self.canonical_bytes()?;
        Ok(vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("usage.debit", payload.clone())?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes(
                    "usage.debit.digest",
                    domain_digest(b"fa:usage-debit-digest:v1", &[&payload]).to_vec(),
                )?,
            ),
        ])
    }

    pub fn from_row(row: &VertexRow) -> Result<Self, KernelError> {
        let debit = Self::decode(&bytes(row, property::FA_PAYLOAD, "usage debit payload")?)?;
        if row.vid != debit.vid()
            || row.labels.as_slice() != [label::USAGE_DEBIT]
            || row.retired_at.is_some()
            || row.props != debit.properties()?
        {
            return Err(corrupt("receipt identity, label or mirrors disagree"));
        }
        Ok(debit)
    }
}
