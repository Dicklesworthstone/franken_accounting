//! Static declarations in a journaled Plan's retained capability (plan §14.2).
//! The checkpoint authenticates these bytes, not issuance, revocation or SoD.

use std::collections::BTreeMap;

use super::{ReportError, failed, framed};
use crate::codec::Reader;
use crate::envelope::Leg;

/// A Plan's declared holder, posting operation and per-leg ceilings were
/// consistent with its assumed entry. The remaining authorization predicates
/// are outside this mathematical replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioPlannerDeclaration {
    pub plan_record: u128,
    pub recorded_at: u64,
    pub holder: u128,
    pub issuer: u128,
    pub capability_commitment: [u8; 32],
}

pub(super) fn check(
    bytes: &[u8],
    owner: u128,
    plan_record: u128,
    recorded_at: u64,
    legs: &[Leg],
) -> Result<ScenarioPlannerDeclaration, ReportError> {
    let refuse = |detail| failed("scenario_planner_declaration", detail);
    let mut r = Reader::new(bytes);
    let version = r.u16("capability.version")?;
    if !matches!(version, 1 | 2) {
        return Err(refuse("unsupported historical capability version"));
    }
    let holder = r.u128("capability.holder")?;
    if holder != owner || r.u8("capability.profile")? > 2 {
        return Err(refuse(
            "planner holder or profile differs from the supported declaration",
        ));
    }
    let count = r.count(22, 1, "capability.ops")?;
    let mut previous = None;
    let mut can_post = false;
    for _ in 0..count {
        let op = r.u8("capability.op")?;
        if op >= 22 || previous.is_some_and(|last| last >= op) {
            return Err(refuse("unsupported or unordered planner operation"));
        }
        can_post |= op == 1; // Op::Post, stable wire tag.
        previous = Some(op);
    }
    if !can_post {
        return Err(refuse("planner capability omits the post operation"));
    }

    let count = r.count(256, 20, "capability.ceilings")?;
    let mut ceilings = BTreeMap::new();
    for _ in 0..count {
        let unit = r.u32("capability.ceiling.unit")?;
        let maximum = r.i128("capability.ceiling.maximum")?;
        if maximum <= 0
            || ceilings
                .last_key_value()
                .is_some_and(|(last, _)| *last >= unit)
        {
            return Err(refuse(
                "planner ceilings must be positive and strictly ordered by unit",
            ));
        }
        ceilings.insert(unit, maximum);
    }
    if !ceilings.is_empty()
        && legs.iter().any(|leg| {
            ceilings
                .get(&leg.unit)
                .is_none_or(|maximum| leg.mantissa > *maximum)
        })
    {
        return Err(refuse(
            "an assumed leg exceeds its declared ceiling or uses an unlisted unit",
        ));
    }
    if r.present("capability.expires")? {
        r.u64("capability.expires_at")?;
    }
    let issuer = r.u128("capability.issuer")?;
    if version == 2 {
        let count = r.count(16, 5, "capability.caveats")?;
        if count == 0 {
            return Err(refuse("version 2 requires a nonempty caveat list"));
        }
        let mut previous = 0;
        for _ in 0..count {
            let tag = r.u8("capability.caveat.tag")?;
            if tag <= previous || tag > 13 {
                return Err(refuse("unsupported or unordered planner caveat"));
            }
            // Caveat bodies are authenticated by the commitment, but are
            // deliberately not interpreted as proof of historical admission.
            r.bytes(8192, "capability.caveat.payload")?;
            previous = tag;
        }
    }
    r.finish("planner capability")?;
    Ok(ScenarioPlannerDeclaration {
        plan_record,
        recorded_at,
        holder,
        issuer,
        capability_commitment: framed(b"fa:capability:v1", &[bytes]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    fn capability(holder: u128, ops: &[u8], ceilings: &[(u32, i128)], caveats: bool) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(if caveats { 2 } else { 1 })
            .u128(holder)
            .u8(0)
            .count(ops.len());
        for op in ops {
            w.u8(*op);
        }
        w.count(ceilings.len());
        for (unit, limit) in ceilings {
            w.u32(*unit).i128(*limit);
        }
        w.u8(0).u128(9);
        if caveats {
            w.count(1).u8(5).bytes(&100i32.to_le_bytes());
        }
        w.buf
    }

    #[test]
    fn planner_declaration_binds_holder_op_and_each_leg_even_with_caveats() {
        let leg = Leg {
            debit: true,
            account: 33,
            unit: 2,
            mantissa: 87,
        };
        let legs = [leg.clone(), leg];
        for version_two in [false, true] {
            let bytes = capability(7, &[0, 1], &[(2, 87)], version_two);
            let verified = check(&bytes, 7, 8, 10, &legs).unwrap();
            assert_eq!(
                (
                    verified.holder,
                    verified.issuer,
                    verified.plan_record,
                    verified.recorded_at
                ),
                (7, 9, 8, 10)
            );
            for invalid in [
                capability(6, &[1], &[], version_two),
                capability(7, &[0], &[], version_two),
                capability(7, &[1], &[(2, 86)], version_two),
                capability(7, &[1], &[(1, 100)], version_two),
                capability(7, &[1, 1], &[], version_two),
                capability(7, &[1], &[(2, 87), (2, 88)], version_two),
            ] {
                assert_eq!(
                    check(&invalid, 7, 8, 10, &legs).unwrap_err().predicate,
                    "scenario_planner_declaration"
                );
            }
            assert!(check(&bytes[..bytes.len() - 1], 7, 8, 10, &legs).is_err());
            let mut trailing = bytes;
            trailing.push(0);
            assert!(check(&trailing, 7, 8, 10, &legs).is_err());
        }
    }
}
