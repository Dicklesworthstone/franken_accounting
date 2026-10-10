//! Balance limits and reserved availability (plan §5.4 second half, §5.5;
//! Appendix H R-ESC interim posture).
//!
//! An account may carry a [`BalanceLimit`]: a lower and/or upper bound on its
//! net balance, in its single registered unit and in its normal-balance sign
//! (for a debit-normal account `net = debits_posted − credits_posted`, exactly
//! plan §5.4; a credit-normal account is the mirror image). Availability is
//! defined by equations, not by a head read:
//!
//! * an entry that moves `x` out (`ΔL < 0`, `L = net − pending_out`) is
//!   admissible iff `net′ − pending_out′ ≥ lower_bound`;
//! * an entry that moves `x` in against the cap (`ΔU > 0`,
//!   `U = net + pending_in`) is admissible iff `net′ + pending_in′ ≤ upper_bound`.
//!
//! Pending outflows reserve, pending inflows never finance, posted flows are
//! final, and a resolution releases its hold's full original legs, so a
//! `Posts`/`Voids` resolution never reduces availability. An entry is judged
//! by its aggregate movement on each limited account; an entry that does not
//! worsen a side is never refused on that side, even when the account sits
//! outside its bound (an account born with `lower_bound > 0`).
//!
//! **Interim posture (R-ESC).** Until FrankenGraphDB escrow domains land,
//! each limited account owns one `LimitCell` vertex carrying the four
//! TigerBeetle fields (posted and pending, each side) and a `generation`.
//! The kernel reads the cell through the posting transaction (a point-read
//! witness) and stages a compare-and-set on `generation`, so two
//! interleaved posts to one limited account are a first-committer-wins
//! conflict, never an overdraft. The cell is a witness, never truth: `fa
//! verify availability` refolds it from the journal, and a missing or
//! malformed cell is corruption to the kernel (fail closed), never a zero.

use fa_model::symbols::property;
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fgdb::{VertexRow, WriteBatch, WriteMismatchPolicy};
use fgdb_crypto::Hasher;
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalScalar, VId};

use crate::refusal::{KernelError, Refusal, code, exit};
use crate::rows::{mantissa_scalar, prop, scalar_bytes};

/// A per-account limit in the account's registered unit and normal-balance
/// sign. At least one bound is named, and `lower ≤ upper` when both are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceLimit {
    pub lower: Option<i128>,
    pub upper: Option<i128>,
}

impl BalanceLimit {
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match (self.lower, self.upper) {
            (None, None) => false,
            (Some(l), Some(u)) => l <= u,
            _ => true,
        }
    }

    /// The Account vertex properties that carry the bounds.
    pub fn props(&self) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
        let mut out = Vec::new();
        if let Some(l) = self.lower {
            out.push((property::LOWER_BOUND, mantissa_scalar("lower_bound", l)?));
        }
        if let Some(u) = self.upper {
            out.push((property::UPPER_BOUND, mantissa_scalar("upper_bound", u)?));
        }
        Ok(out)
    }

    /// The limit an Account vertex carries; `None` when it names no bound.
    pub fn decode(row: &VertexRow) -> Result<Option<Self>, KernelError> {
        let limit = Self {
            lower: i128_of(row, property::LOWER_BOUND, "account.lower_bound")?,
            upper: i128_of(row, property::UPPER_BOUND, "account.upper_bound")?,
        };
        if limit.lower.is_none() && limit.upper.is_none() {
            return Ok(None);
        }
        if !limit.is_well_formed() {
            return Err(KernelError::Corrupt(format!(
                "account {:032x}: lower bound above upper bound",
                row.vid.0
            )));
        }
        Ok(Some(limit))
    }
}

fn i128_of(row: &VertexRow, key: PropertyKeyId, what: &str) -> Result<Option<i128>, KernelError> {
    match prop(row, key) {
        None => Ok(None),
        Some(CanonicalScalar::Bytes(b)) => {
            let raw: [u8; 16] = b
                .as_slice()
                .try_into()
                .map_err(|_| KernelError::Corrupt(format!("{what}: width")))?;
            Ok(Some(i128::from_le_bytes(raw)))
        }
        other => Err(KernelError::Corrupt(format!("{what}: {other:?}"))),
    }
}

/// `vid(LimitCell) = H("fa:vid:limit-cell:v1" ‖ account_vid)`: one cell per
/// limited account, found by identity.
#[must_use]
pub fn limit_cell_vid(account: VId) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:limit-cell:v1");
    h.update(&account.0.to_le_bytes());
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

/// The reservation cell of one limited account: monotone posted sums and
/// outstanding reservations per side, as mantissas in the account's unit,
/// and the number of entries that moved it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LimitCell {
    pub debits_posted: i128,
    pub credits_posted: i128,
    pub debits_pending: i128,
    pub credits_pending: i128,
    pub generation: i64,
}

/// The account a stored cell claims (its `account_ref`); `None` when the
/// property is absent. A wrong type or width is corruption.
pub fn cell_account(row: &VertexRow) -> Result<Option<VId>, KernelError> {
    match prop(row, property::ACCOUNT_REF) {
        None => Ok(None),
        Some(CanonicalScalar::Bytes(b)) => {
            let raw: [u8; 16] = b.as_slice().try_into().map_err(|_| {
                KernelError::Corrupt(format!(
                    "limit cell {:032x}: account_ref width; `fa verify availability` names it",
                    row.vid.0
                ))
            })?;
            Ok(Some(VId(u128::from_le_bytes(raw))))
        }
        other => Err(KernelError::Corrupt(format!(
            "limit cell {:032x}: account_ref {other:?}; `fa verify availability` names it",
            row.vid.0
        ))),
    }
}

impl LimitCell {
    /// Decode the cell of `account` as the kernel witnesses it: the stored
    /// `account_ref` must be present and name `account` (the cell's identity
    /// is derived from it), then the sums decode as [`Self::decode`]. A cell
    /// bound to another account, or to none, is corruption: nothing is
    /// admitted on the account until `fa verify availability` is green again.
    pub fn decode_for(row: &VertexRow, account: VId) -> Result<Self, KernelError> {
        match cell_account(row)? {
            Some(a) if a == account => Self::decode(row),
            Some(a) => Err(KernelError::Corrupt(format!(
                "limit cell {:032x} of account {:032x} names account {:032x}; `fa verify availability` names it; nothing is admitted on the account",
                row.vid.0, account.0, a.0
            ))),
            None => Err(KernelError::Corrupt(format!(
                "limit cell {:032x} of account {:032x} has no account_ref; `fa verify availability` names it; nothing is admitted on the account",
                row.vid.0, account.0
            ))),
        }
    }

    /// Decode a stored cell's sums and generation (not its account binding:
    /// see [`Self::decode_for`]). A missing field, a negative sum, or a wrong
    /// width is corruption: the kernel admits nothing against such a cell
    /// and `fa verify availability` names it.
    pub fn decode(row: &VertexRow) -> Result<Self, KernelError> {
        let field = |key, what: &str| -> Result<i128, KernelError> {
            match i128_of(row, key, what)? {
                Some(v) if v >= 0 => Ok(v),
                Some(v) => Err(KernelError::Corrupt(format!(
                    "limit cell {:032x}: {what} is negative ({v}); `fa verify availability` names it",
                    row.vid.0
                ))),
                None => Err(KernelError::Corrupt(format!(
                    "limit cell {:032x} has no {what}; `fa verify availability` names it",
                    row.vid.0
                ))),
            }
        };
        let generation = match prop(row, property::GENERATION) {
            Some(CanonicalScalar::Int(g)) if *g >= 0 => *g,
            other => {
                return Err(KernelError::Corrupt(format!(
                    "limit cell {:032x}: generation {other:?}; `fa verify availability` names it",
                    row.vid.0
                )));
            }
        };
        Ok(Self {
            debits_posted: field(property::DEBITS_POSTED, "debits_posted")?,
            credits_posted: field(property::CREDITS_POSTED, "credits_posted")?,
            debits_pending: field(property::DEBITS_PENDING, "debits_pending")?,
            credits_pending: field(property::CREDITS_PENDING, "credits_pending")?,
            generation,
        })
    }

    /// The properties of a fresh cell for `account`, sorted by key id.
    pub fn create_props(
        &self,
        account: VId,
    ) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
        let mut props = vec![
            (
                property::ACCOUNT_REF,
                scalar_bytes("account_ref", account.0.to_le_bytes().to_vec())?,
            ),
            (property::GENERATION, CanonicalScalar::Int(self.generation)),
        ];
        props.extend(self.sums()?);
        props.sort_by_key(|(k, _)| k.0);
        Ok(props)
    }

    fn sums(&self) -> Result<[(PropertyKeyId, CanonicalScalar); 4], KernelError> {
        Ok([
            (
                property::DEBITS_POSTED,
                mantissa_scalar("debits_posted", self.debits_posted)?,
            ),
            (
                property::CREDITS_POSTED,
                mantissa_scalar("credits_posted", self.credits_posted)?,
            ),
            (
                property::DEBITS_PENDING,
                mantissa_scalar("debits_pending", self.debits_pending)?,
            ),
            (
                property::CREDITS_PENDING,
                mantissa_scalar("credits_pending", self.credits_pending)?,
            ),
        ])
    }

    /// Stage `self → next` inside the posting transaction: a compare-and-set
    /// on the witnessed generation (a mismatch aborts the write), then the
    /// four sums.
    pub fn stage(&self, next: &Self, cell: VId, batch: &mut WriteBatch) -> Result<(), KernelError> {
        batch.compare_and_set_vertex_property(
            cell,
            property::GENERATION,
            Some(CanonicalScalar::Int(self.generation)),
            CanonicalScalar::Int(next.generation),
            WriteMismatchPolicy::AbortWrite,
        );
        for (key, value) in next.sums()? {
            batch.set_vertex_property(cell, key, Some(value));
        }
        Ok(())
    }

    /// `(net, pending_out, pending_in)` in the normal-balance sign. A cell
    /// with a negative sum is corruption; otherwise every value fits `i128`.
    pub fn availability(&self, normal: Side) -> Result<(i128, i128, i128), KernelError> {
        if [
            self.debits_posted,
            self.credits_posted,
            self.debits_pending,
            self.credits_pending,
        ]
        .iter()
        .any(|v| *v < 0)
        {
            return Err(KernelError::Corrupt(
                "a limit cell sum is negative; `fa verify availability` names it".into(),
            ));
        }
        let (normal_posted, opposite_posted, pending_in, pending_out) = match normal {
            Side::Debit => (
                self.debits_posted,
                self.credits_posted,
                self.debits_pending,
                self.credits_pending,
            ),
            Side::Credit => (
                self.credits_posted,
                self.debits_posted,
                self.credits_pending,
                self.debits_pending,
            ),
        };
        let net = normal_posted
            .checked_sub(opposite_posted)
            .ok_or_else(|| KernelError::Corrupt("limit cell net".into()))?;
        Ok((net, pending_out, pending_in))
    }
}

/// One entry's movement on one limited account: non-negative sums of the
/// legs it posts, the legs it reserves (a `Pending`), and the original
/// pending legs it releases (a `Resolution`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Movement {
    pub posted_debits: i128,
    pub posted_credits: i128,
    pub reserved_debits: i128,
    pub reserved_credits: i128,
    pub released_debits: i128,
    pub released_credits: i128,
}

impl Movement {
    fn add(slot: &mut i128, m: i128) -> Result<(), KernelError> {
        *slot = slot
            .checked_add(m)
            .filter(|v| *v >= 0 && m >= 0)
            .ok_or_else(|| {
                KernelError::Corrupt("an entry's per-account movement left the i128 domain".into())
            })?;
        Ok(())
    }

    pub fn post(&mut self, side: Side, m: i128) -> Result<(), KernelError> {
        match side {
            Side::Debit => Self::add(&mut self.posted_debits, m),
            Side::Credit => Self::add(&mut self.posted_credits, m),
        }
    }

    pub fn reserve(&mut self, side: Side, m: i128) -> Result<(), KernelError> {
        match side {
            Side::Debit => Self::add(&mut self.reserved_debits, m),
            Side::Credit => Self::add(&mut self.reserved_credits, m),
        }
    }

    pub fn release(&mut self, side: Side, m: i128) -> Result<(), KernelError> {
        match side {
            Side::Debit => Self::add(&mut self.released_debits, m),
            Side::Credit => Self::add(&mut self.released_credits, m),
        }
    }
}

/// Why an entry is refused on a limited account. Amounts are mantissas in
/// the account's unit, in its normal-balance sign; `None` is a value beyond
/// the `i128` domain (which is itself beyond every bound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Breach {
    Lower {
        bound: i128,
        net: i128,
        pending_out: i128,
        outflow: u128,
        after: Option<i128>,
    },
    Upper {
        bound: i128,
        net: i128,
        pending_in: i128,
        inflow: u128,
        after: Option<i128>,
    },
    /// A posted or reserved sum would leave the `i128` register ceiling.
    Ceiling,
}

/// The law: `before` moved by `m` under `limit`. `Ok(Ok(next))` is the cell
/// to stage; `Ok(Err(breach))` is a refusal; `Err` is corruption (a release
/// larger than what the cell holds reserved).
pub fn apply(
    before: &LimitCell,
    normal: Side,
    limit: &BalanceLimit,
    m: &Movement,
) -> Result<Result<LimitCell, Breach>, KernelError> {
    let pending = |held: i128,
                   reserved: i128,
                   released: i128|
     -> Result<Option<i128>, KernelError> {
        let Some(with) = held.checked_add(reserved) else {
            return Ok(None);
        };
        with.checked_sub(released)
            .filter(|v| *v >= 0)
            .map(Some)
            .ok_or_else(|| {
                KernelError::Corrupt(format!(
                    "the limit cell holds {held} reserved but a resolution releases {released}; `fa verify availability` names it"
                ))
            })
    };
    let next = (
        before.debits_posted.checked_add(m.posted_debits),
        before.credits_posted.checked_add(m.posted_credits),
        pending(before.debits_pending, m.reserved_debits, m.released_debits)?,
        pending(
            before.credits_pending,
            m.reserved_credits,
            m.released_credits,
        )?,
    );
    let (Some(dp), Some(cp), Some(dr), Some(cr)) = next else {
        return Ok(Err(Breach::Ceiling));
    };
    let generation = before
        .generation
        .checked_add(1)
        .ok_or_else(|| KernelError::Corrupt("limit cell generation overflow".into()))?;
    let next = LimitCell {
        debits_posted: dp,
        credits_posted: cp,
        debits_pending: dr,
        credits_pending: cr,
        generation,
    };
    // The movement's direction, in the normal-balance sign, as non-negative
    // u128 sums (two i128 sums of non-negatives never overflow u128).
    let (in_posted, out_posted, in_reserved, out_reserved, in_released, out_released) = match normal
    {
        Side::Debit => (
            m.posted_debits,
            m.posted_credits,
            m.reserved_debits,
            m.reserved_credits,
            m.released_debits,
            m.released_credits,
        ),
        Side::Credit => (
            m.posted_credits,
            m.posted_debits,
            m.reserved_credits,
            m.reserved_debits,
            m.released_credits,
            m.released_debits,
        ),
    };
    let u = |v: i128| v.unsigned_abs();
    // ΔL = in_posted + out_released − out_posted − out_reserved.
    let l_gain = u(in_posted) + u(out_released);
    let l_loss = u(out_posted) + u(out_reserved);
    // ΔU = in_posted + in_reserved − out_posted − in_released.
    let u_gain = u(in_posted) + u(in_reserved);
    let u_loss = u(out_posted) + u(in_released);
    let (net, pending_out, pending_in) = before.availability(normal)?;
    let (net_after, out_after, in_after) = next.availability(normal)?;
    if l_loss > l_gain
        && let Some(lower) = limit.lower
    {
        // net′ − pending_out′: net′ ∈ (−MAX, MAX) and pending_out′ ≥ 0, so a
        // checked underflow means a value below i128::MIN, below every bound.
        let after = net_after.checked_sub(out_after);
        if after.is_none_or(|a| a < lower) {
            return Ok(Err(Breach::Lower {
                bound: lower,
                net,
                pending_out,
                outflow: l_loss - l_gain,
                after,
            }));
        }
    }
    if u_gain > u_loss
        && let Some(upper) = limit.upper
    {
        // net′ + pending_in′: a checked overflow is above i128::MAX.
        let after = net_after.checked_add(in_after);
        if after.is_none_or(|a| a > upper) {
            return Ok(Err(Breach::Upper {
                bound: upper,
                net,
                pending_in,
                inflow: u_gain - u_loss,
                after,
            }));
        }
    }
    Ok(Ok(next))
}

/// An amount in `unit` at its registered scale (`"1.00 USD"`), so a refusal
/// names amounts the caller can post as written. A unit the registry does
/// not hold cannot be rendered; it is named, never panicked on.
fn render(units: &UnitRegistry, unit: UnitId, v: i128) -> String {
    if units.get(unit).is_some() {
        Amount::new(unit, v).render(units)
    } else {
        format!("{v} (mantissa of unregistered unit {})", unit.0)
    }
}

/// The typed refusal for a breach on account `account`, whose limit is in
/// `unit`: what failed, the bound, the net, the reservations, and the fix
/// with the exact admissible amount — every amount rendered at the unit's
/// scale.
#[must_use]
pub fn refusal(breach: &Breach, account: &str, unit: UnitId, units: &UnitRegistry) -> Refusal {
    let show = |v: i128| render(units, unit, v);
    let show_flow = |v: u128| {
        i128::try_from(v).map_or_else(|_| "an amount beyond the i128 domain".to_string(), show)
    };
    match breach {
        Breach::Lower {
            bound,
            net,
            pending_out,
            outflow,
            after,
        } => {
            let available = net
                .checked_sub(*pending_out)
                .and_then(|l| l.checked_sub(*bound));
            let fix = match available {
                Some(a) if a > 0 => format!(
                    "move at most {} out of `{account}` (net − reserved outflows − lower bound), fund it first, or release one of its holds with a Resolution(Voids); a pending inflow never finances an outflow",
                    show(a)
                ),
                _ => format!(
                    "nothing above the lower bound is available on `{account}`: fund it with a posted inflow first, or release one of its holds with a Resolution(Voids)"
                ),
            };
            Refusal::new(
                code::AVAILABILITY_LOWER,
                exit::REFUSAL,
                format!(
                    "account `{account}`: this entry moves {} out; net {} − reserved outflows {} − {} = {} is below the lower bound {}",
                    show_flow(*outflow),
                    show(*net),
                    show(*pending_out),
                    show_flow(*outflow),
                    after.map_or_else(|| "a value below the i128 domain".to_string(), show),
                    show(*bound)
                ),
                "plan §5.4 reserved availability (net − pending_out − x ≥ lower_bound; FA-INV-15 availability)",
                fix,
            )
        }
        Breach::Upper {
            bound,
            net,
            pending_in,
            inflow,
            after,
        } => {
            let room = bound
                .checked_sub(*net)
                .and_then(|r| r.checked_sub(*pending_in));
            let fix = match room {
                Some(r) if r > 0 => format!(
                    "move at most {} into `{account}` (upper bound − net − reserved inflows), or release one of its pending inflows with a Resolution(Voids) first",
                    show(r)
                ),
                _ => format!(
                    "`{account}` has no room under its upper bound: post an outflow first, or release one of its pending inflows with a Resolution(Voids)"
                ),
            };
            Refusal::new(
                code::AVAILABILITY_UPPER,
                exit::REFUSAL,
                format!(
                    "account `{account}`: this entry moves {} in; net {} + reserved inflows {} + {} = {} is above the upper bound {}",
                    show_flow(*inflow),
                    show(*net),
                    show(*pending_in),
                    show_flow(*inflow),
                    after.map_or_else(|| "a value above the i128 domain".to_string(), show),
                    show(*bound)
                ),
                "plan §5.4 reserved availability (net + pending_in + x ≤ upper_bound; FA-INV-15 availability)",
                fix,
            )
        }
        Breach::Ceiling => Refusal::new(
            code::LIMIT_CEILING,
            exit::REFUSAL,
            format!(
                "account `{account}`: a posted or reserved total would leave the i128 register ceiling"
            ),
            "plan §6.1 (checked exact arithmetic; the register ceiling)",
            format!(
                "split `{account}`'s activity across accounts; no total beyond the ceiling is representable"
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(dp: i128, cp: i128, dr: i128, cr: i128) -> LimitCell {
        LimitCell {
            debits_posted: dp,
            credits_posted: cp,
            debits_pending: dr,
            credits_pending: cr,
            generation: 0,
        }
    }

    const FLOOR: BalanceLimit = BalanceLimit {
        lower: Some(0),
        upper: None,
    };

    /// The fa-ctf example: cash 100; a pending outflow of 80 blocks a second
    /// 80 and an unrelated posted 30; a pending inflow never finances.
    #[test]
    fn pending_outflows_reserve_and_pending_inflows_never_finance() {
        let funded = cell(100, 0, 0, 0);
        let mut hold = Movement::default();
        hold.reserve(Side::Credit, 80).unwrap();
        let held = apply(&funded, Side::Debit, &FLOOR, &hold).unwrap().unwrap();
        assert_eq!(
            held,
            LimitCell {
                credits_pending: 80,
                generation: 1,
                ..funded
            }
        );
        assert!(matches!(
            apply(&held, Side::Debit, &FLOOR, &hold).unwrap(),
            Err(Breach::Lower {
                bound: 0,
                net: 100,
                pending_out: 80,
                outflow: 80,
                after: Some(-60)
            })
        ));
        let mut spend = Movement::default();
        spend.post(Side::Credit, 30).unwrap();
        assert!(matches!(
            apply(&held, Side::Debit, &FLOOR, &spend).unwrap(),
            Err(Breach::Lower {
                outflow: 30,
                after: Some(-10),
                ..
            })
        ));
        let mut inflow_hold = Movement::default();
        inflow_hold.reserve(Side::Debit, 1_000).unwrap();
        let with_inflow = apply(&held, Side::Debit, &FLOOR, &inflow_hold)
            .unwrap()
            .unwrap();
        assert!(
            apply(&with_inflow, Side::Debit, &FLOOR, &spend)
                .unwrap()
                .is_err()
        );
        let mut twenty = Movement::default();
        twenty.post(Side::Credit, 20).unwrap();
        assert!(
            apply(&with_inflow, Side::Debit, &FLOOR, &twenty)
                .unwrap()
                .is_ok()
        );
    }

    /// Posting 60 of an 80 hold releases the full 80: pending −80, posted +60.
    #[test]
    fn a_resolution_releases_the_full_hold_and_never_reduces_availability() {
        let held = cell(100, 0, 0, 80);
        let mut posts = Movement::default();
        posts.release(Side::Credit, 80).unwrap();
        posts.post(Side::Credit, 60).unwrap();
        let next = apply(&held, Side::Debit, &FLOOR, &posts).unwrap().unwrap();
        assert_eq!((next.credits_posted, next.credits_pending), (60, 0));
        let mut over = Movement::default();
        over.release(Side::Credit, 81).unwrap();
        assert!(matches!(
            apply(&held, Side::Debit, &FLOOR, &over),
            Err(KernelError::Corrupt(_))
        ));
    }

    /// An entry that does not worsen a side is admitted on it even when the
    /// account sits outside the bound; an upper bound refuses only inflows.
    #[test]
    fn only_a_worsening_side_is_judged() {
        let floor_100 = BalanceLimit {
            lower: Some(100),
            upper: Some(150),
        };
        let mut deposit = Movement::default();
        deposit.post(Side::Debit, 50).unwrap();
        let after = apply(&LimitCell::default(), Side::Debit, &floor_100, &deposit)
            .unwrap()
            .unwrap();
        let mut big = Movement::default();
        big.post(Side::Debit, 101).unwrap();
        assert!(matches!(
            apply(&after, Side::Debit, &floor_100, &big).unwrap(),
            Err(Breach::Upper {
                inflow: 101,
                after: Some(151),
                ..
            })
        ));
        let mut pending_in = Movement::default();
        pending_in.reserve(Side::Debit, 101).unwrap();
        assert!(
            apply(&after, Side::Debit, &floor_100, &pending_in)
                .unwrap()
                .is_err()
        );
        // Credit-normal: a loan facility capped at 500 drawn.
        let facility = BalanceLimit {
            lower: None,
            upper: Some(500),
        };
        let mut draw = Movement::default();
        draw.post(Side::Credit, 500).unwrap();
        let drawn = apply(&LimitCell::default(), Side::Credit, &facility, &draw)
            .unwrap()
            .unwrap();
        let mut one = Movement::default();
        one.post(Side::Credit, 1).unwrap();
        assert!(
            apply(&drawn, Side::Credit, &facility, &one)
                .unwrap()
                .is_err()
        );
        let mut repay = Movement::default();
        repay.post(Side::Debit, 1).unwrap();
        assert!(
            apply(&drawn, Side::Credit, &facility, &repay)
                .unwrap()
                .is_ok()
        );
    }

    /// Plan §6.1 / review D2: a refusal renders amounts at the unit's scale,
    /// never a raw mantissa as whole units; the fix is postable as written.
    #[test]
    fn refusals_render_amounts_at_the_units_scale() {
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let held = cell(100, 0, 0, 80);
        let mut spend = Movement::default();
        spend.post(Side::Credit, 30).unwrap();
        let breach = apply(&held, Side::Debit, &FLOOR, &spend)
            .unwrap()
            .unwrap_err();
        let r = refusal(&breach, "1000", usd, &units);
        assert_eq!(r.code, "FA-REF-090");
        assert!(r.message.contains("moves 0.30 USD out"), "{r}");
        assert!(r.message.contains("net 1.00 USD"), "{r}");
        assert!(r.message.contains("reserved outflows 0.80 USD"), "{r}");
        assert!(r.message.contains("= -0.10 USD"), "{r}");
        assert!(r.message.contains("lower bound 0.00 USD"), "{r}");
        assert!(r.fix.contains("at most 0.20 USD"), "{r}");
        let unregistered = refusal(&breach, "1000", UnitId(u32::MAX), &units);
        assert!(
            unregistered.fix.contains("mantissa of unregistered unit"),
            "{unregistered}"
        );
    }

    #[test]
    fn the_i128_edges_are_exact() {
        let max = i128::MAX;
        let mut spend = Movement::default();
        spend.post(Side::Credit, max).unwrap();
        let low = BalanceLimit {
            lower: Some(i128::MIN),
            upper: None,
        };
        // net 0 − pending max − max is below i128::MIN, below the lowest bound.
        assert!(matches!(
            apply(&cell(0, 0, 0, max), Side::Debit, &low, &spend).unwrap(),
            Err(Breach::Lower { after: None, .. })
        ));
        assert!(matches!(
            apply(&cell(0, max, 0, 0), Side::Debit, &low, &spend).unwrap(),
            Err(Breach::Ceiling)
        ));
        assert_ne!(limit_cell_vid(VId(1)), limit_cell_vid(VId(2)));
        assert!(
            !BalanceLimit {
                lower: None,
                upper: None
            }
            .is_well_formed()
        );
        assert!(
            !BalanceLimit {
                lower: Some(2),
                upper: Some(1)
            }
            .is_well_formed()
        );
    }
}
