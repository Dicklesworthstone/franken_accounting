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
//!
//! **Budget caps (plan §5.5: "a budget cap ≡ upper bound on an expense
//! account's period cell").** A limit has a [`LimitScope`]: `Lifetime` judges
//! the account's whole history; `Period` judges one cell per fiscal period —
//! the entry's own period for posted and reserved legs, and the *hold's*
//! period for released legs (plan §5.4 keying), so a March encumbrance posted
//! in April releases March's cap and charges April's. Period cells are
//! created eagerly (chart install for existing periods, period creation for
//! limited accounts), so an absent cell is still corruption.
//!
//! **Balancing legs (plan §5.5, TigerBeetle `balancing_debit/credit`).**
//! [`post_balancing`] records the request — which leg balances and the
//! requested amount `R` — as entry extension `fa:balancing:v1`, and the
//! posting transaction itself ([`judge`], step 7d) resolves the two legs to
//! `min(R, admissible)` from the balancing leg's witnessed cell, so the
//! amount is computed under the same witness that commits it; the recorded
//! legs are what moved. When nothing is admissible the request stays at `R`
//! and the law refuses it with the shortfall — a balancing leg never invents
//! a zero posting. The identity binds the request, not the outcome: a retry
//! with the same key, `R`, and leg is the recorded outcome; another `R` or
//! leg under that key is a conflict ([`request_form`]).

use std::collections::BTreeMap;
use std::collections::btree_map::Entry as MapEntry;

use fa_model::entry::BALANCING_EXTENSION;
use fa_model::symbols::{label, property};
use fa_model::{EntryClass, EntryPayload, LegPayload};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::resolve_period;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn};
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, VId};

use crate::genesis::{BookContext, UnitPolicy};
use crate::post::{PostRequest, Posted, post, read_entry};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, mantissa_scalar, prop, scalar_bytes, scalar_text};

pub use fa_escrow::{
    Breach, LimitScope, admissible_balancing_amount, availability_of, balancing_bytes,
    balancing_request, cell_vid, limit_cell_vid, period_cell_vid,
};

/// A per-account limit in the account's registered unit and normal-balance
/// sign. At least one bound is named, and `lower ≤ upper` when both are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceLimit {
    pub lower: Option<i128>,
    pub upper: Option<i128>,
    pub scope: LimitScope,
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
        // Absent = Lifetime, so lifetime limits keep their d66413e properties.
        if self.scope == LimitScope::Period {
            out.push((property::LIMIT_SCOPE, CanonicalScalar::Int(1)));
        }
        Ok(out)
    }

    /// The limit an Account vertex carries; `None` when it names no bound.
    pub fn decode(row: &VertexRow) -> Result<Option<Self>, KernelError> {
        let scope = match prop(row, property::LIMIT_SCOPE) {
            None => LimitScope::Lifetime,
            Some(CanonicalScalar::Int(1)) => LimitScope::Period,
            other => {
                return Err(KernelError::Corrupt(format!(
                    "account {:032x}: limit_scope {other:?}",
                    row.vid.0
                )));
            }
        };
        let limit = Self {
            lower: i128_of(row, property::LOWER_BOUND, "account.lower_bound")?,
            upper: i128_of(row, property::UPPER_BOUND, "account.upper_bound")?,
            scope,
        };
        if limit.lower.is_none() && limit.upper.is_none() {
            if scope == LimitScope::Period {
                return Err(KernelError::Corrupt(format!(
                    "account {:032x}: a period limit scope without a bound",
                    row.vid.0
                )));
            }
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

/// The period a stored cell claims (`effective_period`); `None` when absent.
pub fn cell_period(row: &VertexRow) -> Result<Option<String>, KernelError> {
    match prop(row, property::EFFECTIVE_PERIOD) {
        None => Ok(None),
        Some(CanonicalScalar::Text(t)) => core::str::from_utf8(t.as_bytes())
            .map(|p| Some(p.to_string()))
            .map_err(|_| {
                KernelError::Corrupt(format!(
                    "limit cell {:032x}: effective_period is not UTF-8",
                    row.vid.0
                ))
            }),
        other => Err(KernelError::Corrupt(format!(
            "limit cell {:032x}: effective_period {other:?}",
            row.vid.0
        ))),
    }
}

/// The period code an entry's effective date resolves to (plan §7.3).
pub fn period_code(book: &BookContext, p: &EntryPayload) -> Result<String, KernelError> {
    let fy = book.calendar.fiscal_year_of(p.effective_date)?;
    let periods = book.calendar.periods_for_year(fy)?;
    resolve_period(
        &periods,
        p.effective_date,
        p.effective_period.as_ref().map(|x| x.code.as_str()),
    )
    .map(|d| d.code.clone())
    .map_err(|e| KernelError::Corrupt(format!("entry period: {e:?}")))
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
    /// [`Self::decode_for`] plus, for a period cell, the stored
    /// `effective_period` must name `period`: a cell found at a derived
    /// identity must also be bound to what that identity encodes.
    pub fn decode_bound(
        row: &VertexRow,
        account: VId,
        period: Option<&str>,
    ) -> Result<Self, KernelError> {
        let cell = Self::decode_for(row, account)?;
        if let Some(p) = period {
            match cell_period(row)? {
                Some(q) if q == p => {}
                other => {
                    return Err(KernelError::Corrupt(format!(
                        "limit cell {:032x} of account {:032x} for period `{p}` is bound to period {other:?}; `fa verify availability` names it; nothing is admitted on the account in that period",
                        row.vid.0, account.0
                    )));
                }
            }
        }
        Ok(cell)
    }

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

    /// The properties of a fresh cell for `account` (and, for a period
    /// cell, its period), sorted by key id.
    pub fn create_props(
        &self,
        account: VId,
        period: Option<&str>,
    ) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
        let mut props = vec![
            (
                property::ACCOUNT_REF,
                scalar_bytes("account_ref", account.0.to_le_bytes().to_vec())?,
            ),
            (property::GENERATION, CanonicalScalar::Int(self.generation)),
        ];
        if let Some(p) = period {
            props.push((
                property::EFFECTIVE_PERIOD,
                scalar_text("effective_period", p)?,
            ));
        }
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
        availability_of(
            self.debits_posted,
            self.credits_posted,
            self.debits_pending,
            self.credits_pending,
            normal,
        )
        .map_err(KernelError::Corrupt)
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

/// One limit cell an entry moves: its identity, the witnessed state, and
/// the state to stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellMove {
    pub cell: VId,
    pub before: LimitCell,
    pub after: LimitCell,
}

/// What step 7d decided: the cells to stage and, for a balancing request,
/// the legs as resolved (the amounts that move, which the entry records).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judged {
    pub moves: Vec<CellMove>,
    pub resolved_legs: Option<Vec<LegPayload>>,
}

/// The request form of a balancing entry (identity, plan §5.5): its legs at
/// the requested amount, which is what the poster submitted and what a retry
/// resubmits. `None` for an entry without the extension.
pub fn request_form(p: &EntryPayload) -> Result<Option<EntryPayload>, KernelError> {
    let Some((_, requested)) = balancing_request(p).map_err(KernelError::Corrupt)? else {
        return Ok(None);
    };
    let mut q = p.clone();
    for l in &mut q.legs {
        l.amount = Amount::new(l.amount.unit, requested);
    }
    q.unit_totals = EntryPayload::fold_unit_totals(&q.legs)
        .map_err(|e| KernelError::Corrupt(format!("balancing request totals: {e:?}")))?;
    Ok(Some(q))
}

fn shape_refusal(why: String) -> Refusal {
    Refusal::new(
        code::BALANCING_SHAPE,
        exit::USAGE,
        why,
        "plan §5.5 (Balancing leg: the two-leg TigerBeetle option)",
        "post two legs of one unit and one positive amount (a debit and a credit on different accounts), class Original/Adjusting/Pending, and name leg 0 or 1 as balancing; an N-leg entry states its amounts",
    )
}

/// Step 7d of the posting pipeline (plan §5.4–5.5): judge every limited
/// account the entry moves, keyed by the cell its limit judges — in order
/// of first appearance (the entry's legs, then a resolved hold's legs).
/// Each cell is read through `txn` (a point-read witness) and must be bound
/// to its account (and period). Pending legs reserve, a resolution releases
/// the hold's full original legs (in the hold's period), and every other leg
/// posts (in the entry's period). `Ok(Ok(moves))` are the cells to stage.
pub fn judge<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    accounts: &[AccountRow],
    proposal: &EntryPayload,
    period: &str,
    hold: Option<&EntryPayload>,
) -> Result<Result<Judged, Refusal>, KernelError> {
    let hold_period = match hold {
        Some(h) => Some(period_code(book, h)?),
        None => None,
    };
    let mut rows: BTreeMap<VId, AccountRow> = accounts.iter().map(|a| (a.vid, a.clone())).collect();
    // A balancing request resolves its two legs to min(R, admissible) from
    // the balancing leg's cell, read here through the transaction — the
    // same witness the move below stages against.
    let resolved_legs = match balancing_request(proposal) {
        Err(why) => return Ok(Err(shape_refusal(why))),
        Ok(None) => None,
        Ok(Some((leg, requested))) => {
            if let Some(why) = balancing_shape(proposal, leg) {
                return Ok(Err(shape_refusal(why)));
            }
            if proposal.legs.iter().any(|l| l.amount.mantissa != requested) {
                return Ok(Err(shape_refusal(
                    "the legs carry the requested amount the fa:balancing:v1 extension names"
                        .into(),
                )));
            }
            let target = &proposal.legs[usize::from(leg)];
            let account = rows
                .get(&target.account_ref)
                .ok_or_else(|| KernelError::Corrupt("balancing leg account row".into()))?;
            let admissible_amount = match account.limit {
                None => None,
                Some(limit) => {
                    let cell_period = match limit.scope {
                        LimitScope::Lifetime => None,
                        LimitScope::Period => Some(period),
                    };
                    let cvid = cell_vid(account.vid, cell_period);
                    let row = txn
                        .vertex(db, cvid)?
                        .filter(|r| r.labels.contains(&label::LIMIT_CELL))
                        .ok_or_else(|| {
                            KernelError::Corrupt(format!(
                                "limited account `{}` has no limit cell; `fa verify availability` names it; nothing is admitted on it",
                                account.code
                            ))
                        })?;
                    let cell = LimitCell::decode_bound(&row, account.vid, cell_period)?;
                    let normal = if account.normal_balance == 0 {
                        Side::Debit
                    } else {
                        Side::Credit
                    };
                    admissible(&cell, normal, &limit, target.side)?
                }
            };
            let moved = match admissible_amount {
                Some(a) if a > 0 => a.min(requested),
                _ => requested,
            };
            Some(
                proposal
                    .legs
                    .iter()
                    .map(|l| LegPayload {
                        amount: Amount::new(l.amount.unit, moved),
                        ..l.clone()
                    })
                    .collect::<Vec<_>>(),
            )
        }
    };
    let legs = resolved_legs.as_deref().unwrap_or(&proposal.legs);
    let mut moves: Vec<((VId, Option<String>), Movement)> = Vec::new();
    let effects = legs.iter().map(|l| (l, false)).chain(
        hold.into_iter()
            .flat_map(|h| h.legs.iter())
            .map(|l| (l, true)),
    );
    for (leg, is_release) in effects {
        let account = match rows.entry(leg.account_ref) {
            MapEntry::Occupied(o) => o.into_mut(),
            MapEntry::Vacant(v) => {
                let row = txn.vertex(db, leg.account_ref)?.ok_or_else(|| {
                    KernelError::Corrupt(format!(
                        "the hold's account {:032x} is missing",
                        leg.account_ref.0
                    ))
                })?;
                v.insert(AccountRow::decode(&row)?)
            }
        };
        let Some(limit) = account.limit else {
            continue;
        };
        let cell_period = match (limit.scope, is_release) {
            (LimitScope::Lifetime, _) => None,
            (LimitScope::Period, false) => Some(period.to_string()),
            (LimitScope::Period, true) => Some(
                hold_period
                    .clone()
                    .ok_or_else(|| KernelError::Corrupt("released legs without a hold".into()))?,
            ),
        };
        let key = (leg.account_ref, cell_period);
        let at = match moves.iter().position(|(k, _)| *k == key) {
            Some(at) => at,
            None => {
                moves.push((key, Movement::default()));
                moves.len() - 1
            }
        };
        let m = &mut moves[at].1;
        if is_release {
            m.release(leg.side, leg.amount.mantissa)?;
        } else if proposal.class == EntryClass::PENDING {
            m.reserve(leg.side, leg.amount.mantissa)?;
        } else {
            m.post(leg.side, leg.amount.mantissa)?;
        }
    }
    let mut out = Vec::with_capacity(moves.len());
    for ((account_vid, cell_period), m) in &moves {
        let account = rows
            .get(account_vid)
            .ok_or_else(|| KernelError::Corrupt("judged account row".into()))?;
        let limit = account
            .limit
            .ok_or_else(|| KernelError::Corrupt("judged account has no limit".into()))?;
        let cvid = cell_vid(*account_vid, cell_period.as_deref());
        let row = txn
            .vertex(db, cvid)?
            .filter(|r| r.labels.contains(&label::LIMIT_CELL))
            .ok_or_else(|| {
                KernelError::Corrupt(format!(
                    "limited account `{}` has no limit cell{}; `fa verify availability` names it; nothing is admitted on it",
                    account.code,
                    cell_period
                        .as_deref()
                        .map_or_else(String::new, |p| format!(" for period `{p}`"))
                ))
            })?;
        // The cell must be bound to this account (and period), not merely
        // found at the derived identity.
        let before = LimitCell::decode_bound(&row, *account_vid, cell_period.as_deref())?;
        let normal = if account.normal_balance == 0 {
            Side::Debit
        } else {
            Side::Credit
        };
        match apply(&before, normal, &limit, m)? {
            Ok(after) => out.push(CellMove {
                cell: cvid,
                before,
                after,
            }),
            Err(breach) => {
                // install_chart admits a limit only on a single-unit account.
                let UnitPolicy::Single(unit) = account.unit_policy else {
                    return Err(KernelError::Corrupt(format!(
                        "limited account `{}` has no single unit",
                        account.code
                    )));
                };
                return Ok(Err(refusal(
                    &breach,
                    &account.code,
                    cell_period.as_deref(),
                    unit,
                    &book.units,
                )));
            }
        }
    }
    Ok(Ok(Judged {
        moves: out,
        resolved_legs,
    }))
}

/// The largest amount one leg on `side` may move against `cell` under
/// `limit` (plan §5.5 Balancing): `None` when that direction is unbounded,
/// else `Some(a)` with `a ≥ 0` (`0` = nothing available). An outflow is
/// bounded by `net − pending_out − lower`, an inflow by `upper − net −
/// pending_in`; saturation at the `i128` edges is exact for any request,
/// which is itself an `i128`.
pub fn admissible(
    cell: &LimitCell,
    normal: Side,
    limit: &BalanceLimit,
    side: Side,
) -> Result<Option<i128>, KernelError> {
    let (net, pending_out, pending_in) = cell.availability(normal)?;
    let a = if side == normal {
        let Some(upper) = limit.upper else {
            return Ok(None);
        };
        inflow_room(upper, net, pending_in)
    } else {
        let Some(lower) = limit.lower else {
            return Ok(None);
        };
        outflow_room(lower, net, pending_out)
    };
    Ok(Some(a))
}

// Reservations are nonnegative. Combine them with the net first: an
// overflow then lies beyond every representable bound. Clamp only the
// resulting capacity to the domain of an individual requested amount.
fn inflow_room(upper: i128, net: i128, pending_in: i128) -> i128 {
    net.checked_add(pending_in)
        .map_or(0, |occupied| upper.saturating_sub(occupied).max(0))
}

fn outflow_room(lower: i128, net: i128, pending_out: i128) -> i128 {
    net.checked_sub(pending_out)
        .map_or(0, |available| available.saturating_sub(lower).max(0))
}

/// What a balancing post moved (plan §5.5): the requested amount and the
/// amount actually recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balanced {
    pub posted: Posted,
    pub requested: i128,
    pub moved: i128,
}

fn balancing_shape(p: &EntryPayload, leg: u16) -> Option<String> {
    if !matches!(
        p.class,
        EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::PENDING
    ) {
        return Some(format!(
            "a balancing leg posts an Original, Adjusting, or Pending, not a {}",
            p.class.name().unwrap_or("?")
        ));
    }
    let [a, b] = p.legs.as_slice() else {
        return Some(format!(
            "a balancing entry has exactly two legs, not {}",
            p.legs.len()
        ));
    };
    if leg > 1 {
        return Some(format!("the balancing leg is 0 or 1, not {leg}"));
    }
    if a.amount.unit != b.amount.unit || a.amount.mantissa != b.amount.mantissa {
        return Some("the two legs carry one amount in one unit".into());
    }
    if a.amount.mantissa <= 0 {
        return Some("the requested amount is positive".into());
    }
    if a.side == b.side || a.account_ref == b.account_ref {
        return Some("one debit and one credit on two different accounts".into());
    }
    // A legal entity is a leg's balancing dimension (plan §5.2): the two
    // legs may name theirs, and the per-entity law then judges the request
    // (a request across entities is unbalanced per entity, FA-REF-001).
    if [a, b].iter().any(|l| {
        !l.settles.is_empty()
            || l.base_amount.is_some()
            || l.dimension_set
                .iter()
                .any(|(d, _)| *d != fa_model::LEGAL_ENTITY_DIMENSION)
    }) {
        return Some(
            "balancing legs carry no settles, base amount, or dimensions other than the legal entity"
                .into(),
        );
    }
    None
}

/// Post a two-leg single-unit entry with leg `leg` balancing (plan §5.5,
/// TigerBeetle's `balancing_debit/credit`). The request — `leg` and the
/// requested amount `R` the two legs carry — is recorded as the entry's
/// `fa:balancing:v1` extension; the posting transaction resolves the legs to
/// `min(R, admissible)` from that leg's witnessed cell (its period cell for a
/// budget limit) and runs the full law on them, so the other leg's account
/// is judged too and nothing is silently exceeded. The identity binds the
/// request: a retry with the same key, `R`, and leg returns the recorded
/// outcome whatever availability is now; another `R` or leg is a conflict.
/// Approvals bind the resolved proposal: its actual leg amounts and the
/// original `fa:balancing:v1` request extension. A different resolved amount
/// requires a new approval before it can be committed.
pub async fn post_balancing<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    mut req: PostRequest,
    leg: u16,
) -> Outcome<Balanced> {
    if let Some(why) = balancing_shape(&req.proposal, leg) {
        return Ok(Err(shape_refusal(why)));
    }
    let p = &mut req.proposal;
    if p.extensions.iter().any(|(t, _)| *t == BALANCING_EXTENSION) {
        return Ok(Err(shape_refusal(
            "the request already carries a fa:balancing:v1 extension".into(),
        )));
    }
    let requested = p.legs[0].amount.mantissa;
    p.schema_minor = p.schema_minor.max(fa_model::entry::EXTENSIONS_MINOR);
    p.extensions
        .push((BALANCING_EXTENSION, balancing_bytes(leg, requested)));
    p.extensions.sort_by_key(|(t, _)| *t);
    let posted = match post(db, ctx, book, req).await? {
        Ok(posted) => posted,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let (entry, _) = read_entry(db, posted.entry_ref().vid)?
        .ok_or_else(|| KernelError::Corrupt("the posted entry is not readable".into()))?;
    let moved = entry
        .proposal
        .legs
        .get(usize::from(leg))
        .map(|l| l.amount.mantissa)
        .ok_or_else(|| KernelError::Corrupt("the posted balancing entry lost a leg".into()))?;
    Ok(Ok(Balanced {
        posted,
        requested,
        moved,
    }))
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
pub fn refusal(
    breach: &Breach,
    account: &str,
    period: Option<&str>,
    unit: UnitId,
    units: &UnitRegistry,
) -> Refusal {
    let show = |v: i128| render(units, unit, v);
    let account = &match period {
        None => format!("`{account}`"),
        Some(p) => format!("`{account}` in period `{p}`"),
    };
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
            let available = outflow_room(*bound, *net, *pending_out);
            let fix = match available {
                a if a > 0 => format!(
                    "move at most {} out of {account} (net − reserved outflows − lower bound), fund it first, or release one of its holds with a Resolution(Voids); a pending inflow never finances an outflow",
                    show(a)
                ),
                _ => format!(
                    "nothing above the lower bound is available on {account}: fund it with a posted inflow first, or release one of its holds with a Resolution(Voids)"
                ),
            };
            Refusal::new(
                code::AVAILABILITY_LOWER,
                exit::REFUSAL,
                format!(
                    "account {account}: this entry moves {} out; net {} − reserved outflows {} − {} = {} is below the lower bound {}",
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
            let room = inflow_room(*bound, *net, *pending_in);
            let fix = match room {
                r if r > 0 => format!(
                    "move at most {} into {account} (upper bound − net − reserved inflows), or release one of its pending inflows with a Resolution(Voids) first",
                    show(r)
                ),
                _ => format!(
                    "{account} has no room under its upper bound: post an outflow first, or release one of its pending inflows with a Resolution(Voids)"
                ),
            };
            Refusal::new(
                code::AVAILABILITY_UPPER,
                exit::REFUSAL,
                format!(
                    "account {account}: this entry moves {} in; net {} + reserved inflows {} + {} = {} is above the upper bound {}",
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
                "account {account}: a posted or reserved total would leave the i128 register ceiling"
            ),
            "plan §6.1 (checked exact arithmetic; the register ceiling)",
            format!(
                "split {account}'s activity across accounts; no total beyond the ceiling is representable"
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
        scope: LimitScope::Lifetime,
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
            scope: LimitScope::Lifetime,
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
            scope: LimitScope::Lifetime,
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
        let r = refusal(&breach, "1000", None, usd, &units);
        assert_eq!(r.code, "FA-REF-090");
        assert!(r.message.contains("moves 0.30 USD out"), "{r}");
        assert!(r.message.contains("net 1.00 USD"), "{r}");
        assert!(r.message.contains("reserved outflows 0.80 USD"), "{r}");
        assert!(r.message.contains("= -0.10 USD"), "{r}");
        assert!(r.message.contains("lower bound 0.00 USD"), "{r}");
        assert!(r.fix.contains("at most 0.20 USD"), "{r}");
        let unregistered = refusal(&breach, "1000", None, UnitId(u32::MAX), &units);
        assert!(
            unregistered.fix.contains("mantissa of unregistered unit"),
            "{unregistered}"
        );
    }

    /// Plan §5.5 Balancing: an outflow may move `net − pending_out − lower`,
    /// an inflow `upper − net − pending_in`; an unbounded direction is
    /// `None`; nothing available is `0`, never negative.
    #[test]
    fn admissible_is_the_room_on_the_legs_side() {
        let cap = BalanceLimit {
            lower: Some(0),
            upper: Some(1_000),
            scope: LimitScope::Period,
        };
        let held = cell(100, 0, 500, 80);
        assert_eq!(
            admissible(&held, Side::Debit, &cap, Side::Credit).unwrap(),
            Some(20)
        );
        assert_eq!(
            admissible(&held, Side::Debit, &cap, Side::Debit).unwrap(),
            Some(400)
        );
        assert_eq!(
            admissible(&cell(0, 0, 0, 80), Side::Debit, &cap, Side::Credit).unwrap(),
            Some(0)
        );
        assert_eq!(
            admissible(&held, Side::Debit, &FLOOR, Side::Debit).unwrap(),
            None
        );
        // Credit-normal: a facility drawn 500 of 500 has no room to draw.
        let facility = BalanceLimit {
            lower: None,
            upper: Some(500),
            scope: LimitScope::Lifetime,
        };
        assert_eq!(
            admissible(&cell(0, 500, 0, 0), Side::Credit, &facility, Side::Credit).unwrap(),
            Some(0)
        );
        assert_eq!(
            admissible(&cell(0, 500, 0, 0), Side::Credit, &facility, Side::Debit).unwrap(),
            None
        );
        // The i128 edges saturate exactly: a floor of i128::MIN is room for
        // any request.
        let low = BalanceLimit {
            lower: Some(i128::MIN),
            upper: None,
            scope: LimitScope::Lifetime,
        };
        assert_eq!(
            admissible(&cell(i128::MAX, 0, 0, 0), Side::Debit, &low, Side::Credit).unwrap(),
            Some(i128::MAX)
        );
        assert_ne!(
            period_cell_vid(VId(1), "P01"),
            period_cell_vid(VId(1), "P02")
        );
        assert_ne!(period_cell_vid(VId(1), "P01"), limit_cell_vid(VId(1)));
    }

    #[test]
    fn upper_refusal_names_the_exact_room_after_reserved_inflows() {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let upper = BalanceLimit {
            lower: None,
            upper: Some(i128::MAX),
            scope: LimitScope::Lifetime,
        };
        // Upper - net would overflow, although subtracting the reserved
        // inflows afterwards gives MAX - 10, a representable capacity.
        let before = cell(0, 10, 20, 0);
        let room = i128::MAX - 10;
        assert_eq!(
            admissible(&before, Side::Debit, &upper, Side::Debit).unwrap(),
            Some(room)
        );
        let mut too_much = Movement::default();
        too_much.post(Side::Debit, room + 1).unwrap();
        let breach = apply(&before, Side::Debit, &upper, &too_much)
            .unwrap()
            .unwrap_err();
        assert!(matches!(breach, Breach::Upper { .. }));
        let refusal = refusal(&breach, "cash", None, usd, &units);
        assert!(refusal.fix.contains(&format!(
            "move at most {} into `cash`",
            Amount::new(usd, room).render(&units)
        )));
        // The amount the refusal names is actually admissible, with the
        // resulting net plus reservations exactly equal to the bound.
        let mut corrected = Movement::default();
        corrected.post(Side::Debit, room).unwrap();
        let after = apply(&before, Side::Debit, &upper, &corrected)
            .unwrap()
            .unwrap();
        let (net, _, pending_in) = after.availability(Side::Debit).unwrap();
        assert_eq!(net.checked_add(pending_in), Some(i128::MAX));
    }

    #[test]
    fn the_i128_edges_are_exact() {
        let max = i128::MAX;
        let mut spend = Movement::default();
        spend.post(Side::Credit, max).unwrap();
        let low = BalanceLimit {
            lower: Some(i128::MIN),
            upper: None,
            scope: LimitScope::Lifetime,
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
                upper: None,
                scope: LimitScope::Period,
            }
            .is_well_formed()
        );
        assert!(
            !BalanceLimit {
                lower: Some(2),
                upper: Some(1),
                scope: LimitScope::Lifetime,
            }
            .is_well_formed()
        );
    }
}
