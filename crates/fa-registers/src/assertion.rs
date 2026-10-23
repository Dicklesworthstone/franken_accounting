//! Balance assertions as attestations (plan §9.4; fa-g21 part 2).
//!
//! A [`RegisterEquals`] claim (fa-bvx: the posted net of one per-entity
//! cell, bound to the fold digest at the sequence it was evaluated at)
//! becomes an immutable `Attestation` (claim tag 4) by the principal that
//! attests it, resting on the documents it cites (a bank statement). The
//! claim's bytes live in `fa_journal::attestation`; the law that a claim may
//! be recorded only if it is exactly what the book evaluates at its own
//! sequence lives here, beside the fold.
//!
//! [`record_register_equals`] decides authority first (`reconcile`, before
//! any read), then re-evaluates the cell at the claim's sequence and refuses
//! any difference — value, unit, as-of day, sequence or fold digest — with
//! FA-REF-140, then commits. [`assertion_holds`] re-evaluates a stored claim
//! the same way, so a claim written outside the recorder is caught wherever
//! it is relied on. A later entry into the attested period never makes a
//! claim false: the claim names its sequence, and drift at head is a
//! separate comparison.

use fa_journal::Capability;
use fa_journal::attestation::{
    AttestationClaim, Attested, RegisterEqualsClaim, admit_reconciler, commit_register_equals,
    read_attestation,
};
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, code, exit};
use fa_model::Oid;
use fa_money::{Amount, UnitId};
use fgdb::Database;
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use crate::RegisterError;
use crate::entity::{EntityCellKey, RegisterEquals, register_equals};

/// The attestation bytes of a claim.
#[must_use]
pub fn claim_of(r: &RegisterEquals) -> RegisterEqualsClaim {
    RegisterEqualsClaim {
        account: r.cell_key.account,
        unit_id: r.cell_key.unit_id,
        period: r.cell_key.period.clone(),
        entity: r.cell_key.entity.clone(),
        mantissa: r.amount.mantissa,
        as_of_effective: r.as_of_effective,
        evaluated_known_at: r.evaluated_known_at,
        fold_digest: r.fold_digest,
    }
}

/// The claim an attestation's bytes state (its unit is the cell's).
#[must_use]
pub fn register_equals_of(c: &RegisterEqualsClaim) -> RegisterEquals {
    RegisterEquals {
        cell_key: EntityCellKey {
            account: c.account,
            unit_id: c.unit_id,
            period: c.period.clone(),
            entity: c.entity.clone(),
        },
        amount: Amount::new(UnitId(c.unit_id), c.mantissa),
        as_of_effective: c.as_of_effective,
        evaluated_known_at: c.evaluated_known_at,
        fold_digest: c.fold_digest,
    }
}

fn claim_false(why: String) -> Refusal {
    Refusal::new(
        code::REGISTER_CLAIM_FALSE,
        exit::REFUSAL,
        why,
        "plan §9.4 (a RegisterEquals binds the cell's value and fold digest at the sequence it was evaluated at)",
        "evaluate the claim from the book (fa-registers register_equals) at the sequence you attest, and attest exactly that",
    )
}

/// What the book evaluates for `claim`'s cell at `claim`'s sequence, or why
/// that is not the claim.
fn differences<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    claim: &RegisterEquals,
) -> Result<Option<String>, RegisterError> {
    if claim.amount.unit != UnitId(claim.cell_key.unit_id) {
        return Ok(Some(format!(
            "the claim's amount is in unit {}, but the cell is unit {}",
            claim.amount.unit.0, claim.cell_key.unit_id
        )));
    }
    let expected = match register_equals(db, book, &claim.cell_key, Some(claim.evaluated_known_at))
    {
        Ok(expected) => expected,
        Err(RegisterError::InvalidSelection(why)) => {
            return Ok(Some(format!(
                "the claim's cell or sequence cannot be evaluated: {why}"
            )));
        }
        Err(e) => return Err(e),
    };
    let mut diffs = Vec::new();
    if expected.amount != claim.amount {
        let difference = claim
            .amount
            .mantissa
            .checked_sub(expected.amount.mantissa)
            .map_or_else(String::new, |d| {
                format!(
                    " (off by {})",
                    Amount::new(expected.amount.unit, d).render(&book.units)
                )
            });
        diffs.push(format!(
            "the cell's net (debits minus credits) is {}, not {}{difference}",
            expected.amount.render(&book.units),
            claim.amount.render(&book.units)
        ));
    }
    if expected.evaluated_known_at != claim.evaluated_known_at {
        diffs.push(format!(
            "the sequence resolves to {}, not {}",
            expected.evaluated_known_at.0, claim.evaluated_known_at.0
        ));
    }
    if expected.as_of_effective != claim.as_of_effective {
        diffs.push(format!(
            "the period ends on day {}, not {}",
            expected.as_of_effective.0, claim.as_of_effective.0
        ));
    }
    if expected.fold_digest != claim.fold_digest {
        diffs.push("the fold digest at that sequence differs".into());
    }
    Ok((!diffs.is_empty()).then(|| {
        format!(
            "RegisterEquals for cell ({:032x}, unit {}, {}, {:?}) at sequence {}: {}",
            claim.cell_key.account.0,
            claim.cell_key.unit_id,
            claim.cell_key.period,
            claim.cell_key.entity,
            claim.evaluated_known_at.0,
            diffs.join("; ")
        )
    }))
}

/// Record `claim` as a `RegisterEquals` attestation by the capability's
/// holder, resting on `evidence` (documents this book holds, strictly
/// ascending): authority before any read, then the claim must be exactly
/// what the book evaluates at its sequence (else FA-REF-140), then the
/// commit (fa-journal: evidence held, identity per attester, cell and
/// sequence; the same claim again is its recorded outcome).
pub async fn record_register_equals<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    claim: &RegisterEquals,
    evidence: Vec<Oid>,
) -> Result<Result<Attested, Refusal>, RegisterError> {
    if let Err(r) = admit_reconciler(capability, book.book_id) {
        return Ok(Err(r));
    }
    if let Some(why) = differences(db, book, claim)? {
        return Ok(Err(claim_false(why)));
    }
    Ok(commit_register_equals(db, ctx, book, capability, claim_of(claim), evidence).await?)
}

/// Whether the RegisterEquals attestation at `vid` is exactly what the book
/// evaluates at its sequence (`None` when there is no such attestation).
pub fn assertion_holds<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    vid: VId,
) -> Result<Option<bool>, RegisterError> {
    let Some((stored, _)) = read_attestation(db, vid)? else {
        return Ok(None);
    };
    match &stored.attestation.claim {
        AttestationClaim::RegisterEquals(c) => Ok(Some(
            differences(db, book, &register_equals_of(c))?.is_none(),
        )),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_time::DateDay;
    use fgdb_types::CommitSeq;

    #[test]
    fn claims_convert_both_ways_without_loss() {
        let r = RegisterEquals {
            cell_key: EntityCellKey {
                account: VId(42),
                unit_id: 1,
                period: "FY2026-P03".into(),
                entity: Some("US".into()),
            },
            amount: Amount::new(UnitId(1), -150_000),
            as_of_effective: DateDay(20_543),
            evaluated_known_at: CommitSeq(9),
            fold_digest: [7; 32],
        };
        assert_eq!(register_equals_of(&claim_of(&r)), r);
    }
}
