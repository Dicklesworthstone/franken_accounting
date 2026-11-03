#![forbid(unsafe_code)]
//! Two-phase holds, balance limits, budget-cap period cells, and balancing-leg
//! availability equations (plan §5.4–§5.5; Appendix H R-ESC interim posture).
//!
//! `fa-escrow` owns the deterministic cell identities (`limit_cell_vid`,
//! `period_cell_vid`, `cell_vid`), the `fa:balancing:v1` extension wire format,
//! `LimitScope`, `Breach`, and the exact availability equations that govern
//! posted and pending movements on bounded accounts.

use fa_model::EntryPayload;
use fa_model::entry::BALANCING_EXTENSION;
use fa_money::Side;
use fgdb_crypto::Hasher;
use fgdb_types::VId;

/// What a limit's bounds apply to (plan §5.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LimitScope {
    /// The account's whole history (an overdraft floor, a facility cap).
    #[default]
    Lifetime,
    /// Each fiscal period separately (a budget cap on an expense account).
    Period,
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

/// `vid(period LimitCell) = H("fa:vid:limit-period-cell:v1" ‖ account_vid ‖
/// len ‖ period)`: one cell per period of a period-scoped (budget) limit.
#[must_use]
pub fn period_cell_vid(account: VId, period: &str) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:limit-period-cell:v1");
    h.update(&account.0.to_le_bytes());
    h.update(
        &u32::try_from(period.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    h.update(period.as_bytes());
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

/// The cell a limit judges: the lifetime cell, or the named period's cell.
#[must_use]
pub fn cell_vid(account: VId, period: Option<&str>) -> VId {
    match period {
        None => limit_cell_vid(account),
        Some(p) => period_cell_vid(account, p),
    }
}

/// The `fa:balancing:v1` extension bytes: `leg ‖ requested`.
#[must_use]
pub fn balancing_bytes(leg: u16, requested: i128) -> Vec<u8> {
    let mut b = Vec::with_capacity(18);
    b.extend_from_slice(&leg.to_le_bytes());
    b.extend_from_slice(&requested.to_le_bytes());
    b
}

/// The balancing request an entry carries: `Ok(None)` without the
/// extension, `Err(why)` when its bytes are malformed.
pub fn balancing_request(p: &EntryPayload) -> Result<Option<(u16, i128)>, String> {
    let Some((_, b)) = p.extensions.iter().find(|(t, _)| *t == BALANCING_EXTENSION) else {
        return Ok(None);
    };
    let (Ok(leg), Ok(req)) = (
        <[u8; 2]>::try_from(b.get(..2).unwrap_or_default()),
        <[u8; 16]>::try_from(b.get(2..).unwrap_or_default()),
    ) else {
        return Err(format!(
            "the fa:balancing:v1 extension is {} bytes, not 18",
            b.len()
        ));
    };
    Ok(Some((u16::from_le_bytes(leg), i128::from_le_bytes(req))))
}

/// Compute `(net, pending_out, pending_in)` in the normal-balance sign from
/// the four non-negative TigerBeetle cell sums.
pub fn availability_of(
    debits_posted: i128,
    credits_posted: i128,
    debits_pending: i128,
    credits_pending: i128,
    normal: Side,
) -> Result<(i128, i128, i128), String> {
    if [
        debits_posted,
        credits_posted,
        debits_pending,
        credits_pending,
    ]
    .iter()
    .any(|v| *v < 0)
    {
        return Err("a limit cell sum is negative; `fa verify availability` names it".into());
    }
    let (normal_posted, opposite_posted, pending_in, pending_out) = match normal {
        Side::Debit => (
            debits_posted,
            credits_posted,
            debits_pending,
            credits_pending,
        ),
        Side::Credit => (
            credits_posted,
            debits_posted,
            credits_pending,
            debits_pending,
        ),
    };
    let net = normal_posted
        .checked_sub(opposite_posted)
        .ok_or_else(|| "limit cell net".to_string())?;
    Ok((net, pending_out, pending_in))
}

/// Maximum admissible movement on `side` for a balancing leg against `(lower, upper)`
/// bounds in the account's normal-balance sign (plan §5.5).
/// `None` means the direction has no bound; bounded arithmetic overflow
/// never grants unbounded movement. Reservations must be nonnegative.
#[must_use]
pub fn admissible_balancing_amount(
    net: i128,
    pending_out: i128,
    pending_in: i128,
    normal: Side,
    leg_side: Side,
    lower: Option<i128>,
    upper: Option<i128>,
) -> Option<i128> {
    if leg_side != normal {
        Some(outflow_room(lower?, net, pending_out))
    } else {
        Some(inflow_room(upper?, net, pending_in))
    }
}

/// Inflow capacity under an upper bound, with nonnegative reservations.
/// Combine net and reservations before subtracting from the bound: an
/// occupied sum above `i128::MAX` has no capacity under any valid bound.
/// Clamp only the final capacity to the domain of one requested amount.
#[must_use]
pub fn inflow_room(upper: i128, net: i128, pending_in: i128) -> i128 {
    net.checked_add(pending_in)
        .map_or(0, |occupied| upper.saturating_sub(occupied).max(0))
}

/// Outflow capacity under a lower bound, with nonnegative reservations.
/// A net less reservations below `i128::MIN` lies below every valid bound;
/// a capacity above `i128::MAX` admits every representable request.
#[must_use]
pub fn outflow_room(lower: i128, net: i128, pending_out: i128) -> i128 {
    net.checked_sub(pending_out)
        .map_or(0, |available| available.saturating_sub(lower).max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn balancing_fixture() -> EntryPayload {
        use fa_model::{EntryClass, EntryOrigin, Erasable, Id128, LegPayload, Oid, SealKey};
        use fa_money::{Amount, UnitId};
        let legs = vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(UnitId(1), 42_500)),
            LegPayload::simple(Side::Credit, VId(2), Amount::new(UnitId(1), 42_500)),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: Id128([9; 16]),
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: fa_time::DateDay(20_000),
            document_date: None,
            description: Erasable::seal(
                &"balancing decoder fixture".to_string(),
                None,
                &SealKey([7; 32]),
                [1; 32],
                [2; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).expect("balanced totals"),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: b"balancing-decoder".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(77),
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn escrow_cell_vids_are_domain_separated_and_deterministic() {
        let acct_a = VId(101);
        let acct_b = VId(102);
        assert_eq!(limit_cell_vid(acct_a), cell_vid(acct_a, None));
        assert_ne!(limit_cell_vid(acct_a), limit_cell_vid(acct_b));
        assert_ne!(
            limit_cell_vid(acct_a),
            period_cell_vid(acct_a, "FY2026-P01")
        );
        assert_ne!(
            period_cell_vid(acct_a, "FY2026-P01"),
            period_cell_vid(acct_a, "FY2026-P02")
        );
    }

    #[test]
    fn escrow_availability_and_balancing_headroom_follow_normal_sign() {
        let (net, pending_out, pending_in) =
            availability_of(1_000, 250, 100, 150, Side::Debit).expect("valid sums");
        assert_eq!((net, pending_out, pending_in), (750, 150, 100));
        // Available above a 0 floor: 750 - 150 = 600.
        assert_eq!(
            admissible_balancing_amount(
                net,
                pending_out,
                pending_in,
                Side::Debit,
                Side::Credit,
                Some(0),
                None,
            ),
            Some(600)
        );
        // Available below a 1_000 cap: 1_000 - (750 + 100) = 150.
        assert_eq!(
            admissible_balancing_amount(
                net,
                pending_out,
                pending_in,
                Side::Debit,
                Side::Debit,
                None,
                Some(1_000),
            ),
            Some(150)
        );
    }

    #[test]
    fn escrow_balancing_bytes_round_trip() {
        let raw = balancing_bytes(1, 42_500);
        assert_eq!(raw.len(), 18);
        let mut proposal = balancing_fixture();
        proposal.extensions.push((BALANCING_EXTENSION, raw));
        assert_eq!(balancing_request(&proposal), Ok(Some((1, 42_500))));
    }

    #[test]
    fn escrow_balancing_bytes_round_trip_through_balancing_request() {
        let mut proposal = balancing_fixture();
        assert_eq!(balancing_request(&proposal), Ok(None));
        // The decoder preserves wire values; posting separately validates
        // the requested amount and selected leg against the entry's shape.
        for leg in [0, 1, u16::MAX] {
            for requested in [i128::MIN, -1, 0, 42_500, i128::MAX] {
                proposal.extensions = vec![(BALANCING_EXTENSION, balancing_bytes(leg, requested))];
                assert_eq!(balancing_request(&proposal), Ok(Some((leg, requested))));
            }
        }
        for len in (0..18).chain([19, 20, 255]) {
            proposal.extensions = vec![(BALANCING_EXTENSION, vec![0; len])];
            let error = balancing_request(&proposal).expect_err("malformed extension refused");
            assert!(error.contains(&format!("{len} bytes, not 18")), "{error}");
        }
    }

    #[test]
    fn bounded_balancing_overflow_never_means_unbounded() {
        for (normal, opposite) in [(Side::Debit, Side::Credit), (Side::Credit, Side::Debit)] {
            assert_eq!(
                admissible_balancing_amount(i128::MAX, 0, 1, normal, normal, None, Some(i128::MAX)),
                Some(0),
            );
            assert_eq!(
                admissible_balancing_amount(
                    i128::MIN + 1,
                    i128::MAX,
                    0,
                    normal,
                    opposite,
                    Some(i128::MIN),
                    None
                ),
                Some(0),
            );
            assert_eq!(
                admissible_balancing_amount(
                    i128::MAX,
                    0,
                    0,
                    normal,
                    opposite,
                    Some(i128::MIN),
                    None
                ),
                Some(i128::MAX),
            );
            assert_eq!(
                admissible_balancing_amount(
                    i128::MIN + 1,
                    0,
                    0,
                    normal,
                    normal,
                    None,
                    Some(i128::MAX)
                ),
                Some(i128::MAX),
            );
            // Cancellation must precede clamping the final capacity.
            assert_eq!(
                admissible_balancing_amount(-10, 0, 20, normal, normal, None, Some(i128::MAX)),
                Some(i128::MAX - 10),
            );
            assert_eq!(
                admissible_balancing_amount(10, 20, 0, normal, opposite, Some(i128::MIN), None),
                Some(i128::MAX - 9),
            );
            assert_eq!(
                admissible_balancing_amount(i128::MAX, 0, 1, normal, normal, None, None),
                None,
            );
            assert_eq!(
                admissible_balancing_amount(
                    i128::MIN + 1,
                    i128::MAX,
                    0,
                    normal,
                    opposite,
                    None,
                    None
                ),
                None,
            );
        }
    }
}
