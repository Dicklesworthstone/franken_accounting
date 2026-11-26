//! Static declarations in a journaled Plan's retained capability (plan §14.2).
//! The checkpoint authenticates these bytes, not issuance, revocation or SoD.

use std::collections::{BTreeMap, BTreeSet};

use super::{ReportError, failed, framed};
use crate::codec::Reader;
use crate::envelope::Leg;
use crate::report::{metadata::Schema, text};

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
    /// Declared scope caveats independently checked against the assumed effects.
    pub checked_effect_scopes: Vec<&'static str>,
}

/// Original entries in this portable method always address trunk. The chart
/// and calendar come from replay of the signed fork prefix.
pub(super) struct Effect<'a> {
    pub book: [u8; 16],
    pub day: i32,
    pub period: &'a str,
    pub legs: &'a [Leg],
    pub schema: &'a Schema,
}

fn scope_error(detail: &str) -> ReportError {
    failed("scenario_planner_scope", detail)
}

/// Capability set payloads are nonempty and strictly increasing on the wire.
fn ordered_set<'a, T: Ord>(
    reader: &mut Reader<'a>,
    maximum: usize,
    width: usize,
    mut element: impl FnMut(&mut Reader<'a>) -> Result<T, ReportError>,
) -> Result<BTreeSet<T>, ReportError> {
    let count = reader.count(maximum, width, "scope.items")?;
    if count == 0 {
        return Err(scope_error("empty capability scope"));
    }
    let mut values = BTreeSet::new();
    for _ in 0..count {
        let item = element(reader)?;
        if values.last().is_some_and(|last| last >= &item) {
            return Err(scope_error("capability scope is not strictly ascending"));
        }
        values.insert(item);
    }
    Ok(values)
}

fn code<'a>(reader: &mut Reader<'a>) -> Result<&'a str, ReportError> {
    let value = text(reader, 64, "scope.code")?;
    if value.is_empty() {
        return Err(scope_error("empty account or period code"));
    }
    Ok(value)
}

/// Match exact account codes and their descendants in the authenticated
/// chart. Shared ancestors need only be walked once per declaration.
fn check_accounts(effect: &Effect<'_>, roots: &BTreeSet<&str>) -> Result<(), ReportError> {
    let mut admitted = BTreeSet::new();
    for leg in effect.legs {
        let mut id = leg.account;
        let mut path = BTreeSet::new();
        while !admitted.contains(&id) {
            let account = effect.schema.accounts.get(&id)
                .ok_or_else(|| scope_error("account is missing from fork chart"))?;
            if !path.insert(id) {
                return Err(scope_error("cycle in account scope ancestry"));
            }
            if roots.contains(account.code.as_str()) {
                break;
            }
            id = *effect.schema.parents.get(&id)
                .ok_or_else(|| scope_error("assumed leg lies outside declared account roots"))?;
        }
        admitted.extend(path);
    }
    Ok(())
}

fn check_effect_scope(
    tag: u8,
    bytes: &[u8],
    effect: &Effect<'_>,
) -> Result<Option<&'static str>, ReportError> {
    let mut r = Reader::new(bytes);
    let name = match tag {
        1 => {
            let books = ordered_set(&mut r, 256, 16, |r| Ok(r.fixed::<16>("scope.book")?))?;
            if !books.contains(&effect.book) {
                return Err(scope_error("assumed entry belongs to an unlisted book"));
            }
            "books"
        }
        3 => {
            check_accounts(effect, &ordered_set(&mut r, 64, 4, code)?)?;
            "accounts"
        }
        4 => {
            if !ordered_set(&mut r, 256, 4, code)?.contains(effect.period) {
                return Err(scope_error("assumed entry belongs to an unlisted period"));
            }
            "periods"
        }
        5 => {
            if effect.day > r.i32("scope.effective_through")? {
                return Err(scope_error("assumed effective date exceeds declared bound"));
            }
            "effective"
        }
        6 => {
            // Posting plans observe the head. A read pinned at, or before,
            // any known-at sequence cannot authorize that observation.
            return Err(scope_error("known-at-pinned capability cannot plan a posting"));
        }
        7 => {
            if r.fixed::<16>("scope.branch")? != [0; 16] {
                return Err(scope_error("declared branch differs from assumed trunk entry"));
            }
            "branch"
        }
        13 => {
            let classes = ordered_set(&mut r, 64, 2, |r| {
                let class = r.u16("scope.class")?;
                if !(1..=31).contains(&class) {
                    return Err(scope_error("unsupported entry class scope"));
                }
                Ok(class)
            })?;
            if !classes.contains(&1) {
                return Err(scope_error("assumed Original is outside declared classes"));
            }
            "classes"
        }
        // Other caveats require additional evidence or concern a different
        // operation. Their retained bytes remain bound to the commitment.
        _ => return Ok(None),
    };
    r.finish("planner scope")?;
    Ok(Some(name))
}

pub(super) fn check(
    bytes: &[u8],
    owner: u128,
    plan_record: u128,
    recorded_at: u64,
    effect: &Effect<'_>,
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
        && effect.legs.iter().any(|leg| {
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
    let mut checked_effect_scopes = Vec::new();
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
            let payload = r.bytes(8192, "capability.caveat.payload")?;
            if let Some(name) = check_effect_scope(tag, payload, effect)? {
                checked_effect_scopes.push(name);
            }
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
        checked_effect_scopes,
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
        let legs = [leg, leg];
        let effect = Effect {
            book: [17; 16],
            day: 100,
            period: "FY2026-P01",
            legs: &legs,
            schema: &Schema::default(),
        };
        for version_two in [false, true] {
            let bytes = capability(7, &[0, 1], &[(2, 87)], version_two);
            let verified = check(&bytes, 7, 8, 10, &effect).unwrap();
            assert_eq!(
                verified.checked_effect_scopes.contains(&"effective"),
                version_two
            );
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
                    check(&invalid, 7, 8, 10, &effect).unwrap_err().predicate,
                    "scenario_planner_declaration"
                );
            }
            assert!(check(&bytes[..bytes.len() - 1], 7, 8, 10, &effect).is_err());
            let mut trailing = bytes;
            trailing.push(0);
            assert!(check(&trailing, 7, 8, 10, &effect).is_err());
        }
    }

    #[test]
    fn declared_scope_binds_every_assumed_leg_and_the_exact_fork_coordinates() {
        use crate::report::metadata::Account;

        let mut schema = Schema::default();
        for (id, code, is_leaf) in [(1, "Assets", false), (2, "Cash", true), (3, "AssetSales", true)] {
            schema.accounts.insert(id, Account {
                code: code.into(),
                name: code.into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf,
                unit_policy: -1,
                limit: None,
                created_at: 1,
            });
        }
        schema.parents.insert(2, 1);
        let cash = Leg {
            account: 2,
            unit: 1,
            debit: true,
            mantissa: 20,
        };
        let legs = [cash, Leg { account: 3, debit: false, ..cash }];
        let effect = Effect {
            book: [9; 16],
            day: 31,
            period: "January",
            legs: &legs,
            schema: &schema,
        };
        let codes = |items: &[&str]| {
            let mut w = Writer::default();
            w.count(items.len());
            for item in items {
                w.bytes(item.as_bytes());
            }
            w.buf
        };
        let mut books = Writer::default();
        books.count(1).fixed(&effect.book);
        let mut classes = Writer::default();
        classes.count(2).u16(1).u16(26);
        for (tag, valid) in [
            (1, books.buf),
            (3, codes(&["AssetSales", "Assets"])),
            (4, codes(&["January"])),
            (5, 31i32.to_le_bytes().to_vec()),
            (7, vec![0; 16]),
            (13, classes.buf),
        ] {
            assert!(check_effect_scope(tag, &valid, &effect).unwrap().is_some());
            let mut trailing = valid;
            trailing.push(0);
            assert!(check_effect_scope(tag, &trailing, &effect).is_err());
        }
        let mut other_book = Writer::default();
        other_book.count(1).fixed(&[8; 16]);
        let mut only_control = Writer::default();
        only_control.count(1).u16(26);
        for (tag, invalid) in [
            (1, other_book.buf),
            (3, codes(&["Assets"])), // The opposite leg needs a separate root.
            (3, codes(&["Asset"])), // No account-code prefix matching.
            (3, codes(&["Cash", "Cash"])),
            (3, codes(&["Cash", "AssetSales"])),
            (4, codes(&["February"])),
            (4, codes(&[])),
            (4, codes(&[""])),
            (5, 30i32.to_le_bytes().to_vec()),
            (6, u64::MAX.to_le_bytes().to_vec()),
            (7, vec![1; 16]),
            (13, only_control.buf),
        ] {
            assert_eq!(
                check_effect_scope(tag, &invalid, &effect).unwrap_err().predicate,
                "scenario_planner_scope"
            );
        }
    }
}
