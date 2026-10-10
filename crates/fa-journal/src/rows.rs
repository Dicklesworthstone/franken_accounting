//! Typed views over stored vertices, and the identities the kernel derives
//! beyond fa-model's (legs, edges, the book vertex).

use fa_model::symbols::property;
use fa_model::{Id128, account_vid};
use fa_time::{DateDay, PeriodKind, PeriodState};
use fgdb::VertexRow;
use fgdb_crypto::Hasher;
use fgdb_delta_types::{PropertyKeyId, RelationId};
use fgdb_types::{CanonicalScalar, CommitSeq, EId, VId};

use crate::genesis::UnitPolicy;
use crate::refusal::KernelError;

pub fn prop<'a>(row: &'a VertexRow, key: PropertyKeyId) -> Option<&'a CanonicalScalar> {
    row.props.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

pub fn int(row: &VertexRow, key: PropertyKeyId, what: &str) -> Result<i64, KernelError> {
    match prop(row, key) {
        Some(CanonicalScalar::Int(i)) => Ok(*i),
        other => Err(KernelError::Corrupt(format!(
            "{what}: expected Int, found {other:?}"
        ))),
    }
}

pub fn text(row: &VertexRow, key: PropertyKeyId, what: &str) -> Result<String, KernelError> {
    match prop(row, key) {
        Some(CanonicalScalar::Text(t)) => core::str::from_utf8(t.as_bytes())
            .map(str::to_string)
            .map_err(|_| KernelError::Corrupt(format!("{what}: text is not UTF-8"))),
        other => Err(KernelError::Corrupt(format!(
            "{what}: expected Text, found {other:?}"
        ))),
    }
}

pub fn bytes(row: &VertexRow, key: PropertyKeyId, what: &str) -> Result<Vec<u8>, KernelError> {
    match prop(row, key) {
        Some(CanonicalScalar::Bytes(b)) => Ok(b.as_slice().to_vec()),
        other => Err(KernelError::Corrupt(format!(
            "{what}: expected Bytes, found {other:?}"
        ))),
    }
}

pub fn scalar_text(what: &'static str, s: &str) -> Result<CanonicalScalar, KernelError> {
    CanonicalScalar::ucs_basic_text(s).map_err(|_| KernelError::Scalar(what))
}

pub fn scalar_bytes(what: &'static str, b: Vec<u8>) -> Result<CanonicalScalar, KernelError> {
    CanonicalScalar::bytes(b).map_err(|_| KernelError::Scalar(what))
}

/// The root vertex of the one book a store holds:
/// `H("fa:vid:book-root:v1")`. Fixed so a reopened store finds its book
/// before it knows the book id.
#[must_use]
pub fn book_root() -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:book-root:v1");
    vid_from(h)
}

/// `vid(Leg) = H("fa:vid:leg:v1" ‖ entry_vid ‖ ordinal)`.
#[must_use]
pub fn leg_vid(entry: VId, ordinal: u16) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:leg:v1");
    h.update(&entry.0.to_le_bytes());
    h.update(&ordinal.to_le_bytes());
    vid_from(h)
}

/// `eid = H("fa:eid:v1" ‖ relation ‖ src ‖ dst)`: one edge per
/// (relation, src, dst), so a duplicate is a point conflict.
#[must_use]
pub fn edge_id(relation: RelationId, src: VId, dst: VId) -> EId {
    let mut h = Hasher::new();
    h.update(b"fa:eid:v1");
    h.update(&relation.0.to_le_bytes());
    h.update(&src.0.to_le_bytes());
    h.update(&dst.0.to_le_bytes());
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    EId(u128::from_le_bytes(lo))
}

fn vid_from(h: Hasher) -> VId {
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

/// An `Account` vertex as the kernel reads it (plan §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRow {
    pub vid: VId,
    pub code: String,
    pub name: String,
    pub account_type: u8,
    /// 0 = debit-normal, 1 = credit-normal.
    pub normal_balance: u8,
    pub is_leaf: bool,
    pub unit_policy: UnitPolicy,
    pub created_at: CommitSeq,
}

impl AccountRow {
    pub fn decode(row: &VertexRow) -> Result<Self, KernelError> {
        let code = text(row, property::CODE, "account.code")?;
        let policy = int(row, property::UNIT_POLICY, "account.unit_policy")?;
        Ok(Self {
            vid: row.vid,
            name: text(row, property::NAME, "account.name")?,
            account_type: u8::try_from(int(row, property::ACCOUNT_TYPE, "account.account_type")?)
                .map_err(|_| KernelError::Corrupt("account.account_type".into()))?,
            normal_balance: u8::try_from(int(
                row,
                property::NORMAL_BALANCE,
                "account.normal_balance",
            )?)
            .map_err(|_| KernelError::Corrupt("account.normal_balance".into()))?,
            is_leaf: int(row, property::POSTING, "account.posting")? == 1,
            unit_policy: UnitPolicy::from_mirror(policy)
                .ok_or_else(|| KernelError::Corrupt(format!("account.unit_policy {policy}")))?,
            created_at: row.created_at,
            code,
        })
    }

    #[must_use]
    pub fn vid_for(book: Id128, code: &str) -> VId {
        account_vid(book, code)
    }
}

/// A `Period` vertex as the kernel reads it (plan §7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodRow {
    pub vid: VId,
    pub calendar_id: String,
    pub code: String,
    pub fiscal_year: i32,
    pub ordinal: u16,
    pub kind: PeriodKind,
    pub start: DateDay,
    pub end: DateDay,
    pub state: PeriodState,
    pub created_at: CommitSeq,
}

pub(crate) fn kind_tag(k: PeriodKind) -> i64 {
    match k {
        PeriodKind::Normal => 0,
        PeriodKind::Adjustment => 1,
        PeriodKind::Opening => 2,
        PeriodKind::Closing => 3,
        PeriodKind::Historical => 4,
    }
}

fn kind_from_tag(t: i64) -> Option<PeriodKind> {
    Some(match t {
        0 => PeriodKind::Normal,
        1 => PeriodKind::Adjustment,
        2 => PeriodKind::Opening,
        3 => PeriodKind::Closing,
        4 => PeriodKind::Historical,
        _ => return None,
    })
}

impl PeriodRow {
    pub fn decode(row: &VertexRow) -> Result<Self, KernelError> {
        let state_tag = int(row, property::STATE, "period.state")?;
        let kind = int(row, property::PERIOD_KIND, "period.period_kind")?;
        Ok(Self {
            vid: row.vid,
            calendar_id: text(row, property::CALENDAR_ID, "period.calendar_id")?,
            code: text(row, property::CODE, "period.code")?,
            fiscal_year: i32::try_from(int(row, property::FISCAL_YEAR, "period.fiscal_year")?)
                .map_err(|_| KernelError::Corrupt("period.fiscal_year".into()))?,
            ordinal: u16::try_from(int(row, property::ORDINAL, "period.ordinal")?)
                .map_err(|_| KernelError::Corrupt("period.ordinal".into()))?,
            kind: kind_from_tag(kind)
                .ok_or_else(|| KernelError::Corrupt(format!("period.period_kind {kind}")))?,
            start: DateDay(
                i32::try_from(int(row, property::PERIOD_START, "period.period_start")?)
                    .map_err(|_| KernelError::Corrupt("period.period_start".into()))?,
            ),
            end: DateDay(
                i32::try_from(int(row, property::PERIOD_END, "period.period_end")?)
                    .map_err(|_| KernelError::Corrupt("period.period_end".into()))?,
            ),
            state: state_from_scalar(Some(&CanonicalScalar::Int(state_tag)))
                .ok_or_else(|| KernelError::Corrupt(format!("period.state {state_tag}")))?,
            created_at: row.created_at,
        })
    }
}

/// The period state a `state` property holds; `None` (no vertex / no
/// property) reads as `Future`, which the matrix refuses for every posting
/// class — a period that was never created admits nothing.
pub(crate) fn state_from_scalar(v: Option<&CanonicalScalar>) -> Option<PeriodState> {
    match v {
        None => Some(PeriodState::Future),
        Some(CanonicalScalar::Int(i)) => u8::try_from(*i).ok().and_then(PeriodState::from_tag),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_identities_are_distinct_and_stable() {
        let b = Id128([1; 16]);
        assert_eq!(book_root(), book_root());
        let _ = b;
        assert_ne!(leg_vid(VId(1), 0), leg_vid(VId(1), 1));
        assert_ne!(
            edge_id(RelationId(1), VId(1), VId(2)),
            edge_id(RelationId(2), VId(1), VId(2))
        );
        assert_ne!(
            edge_id(RelationId(1), VId(1), VId(2)),
            edge_id(RelationId(1), VId(2), VId(1))
        );
        for k in [
            PeriodKind::Normal,
            PeriodKind::Adjustment,
            PeriodKind::Opening,
            PeriodKind::Closing,
            PeriodKind::Historical,
        ] {
            assert_eq!(kind_from_tag(kind_tag(k)), Some(k));
        }
        assert_eq!(state_from_scalar(None), Some(PeriodState::Future));
        assert_eq!(state_from_scalar(Some(&CanonicalScalar::Null)), None);
    }
}
