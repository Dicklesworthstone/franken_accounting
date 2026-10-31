//! Independent one-book consolidation from a complete authenticated journal.
//!
//! Roles and valid-time ownership are replayed from schema controls, while
//! legal-entity declarations are explicit Book parameters. Eliminations and
//! noncontrolling interests are derived here; no producer-supplied elimination
//! or statement amount is used as an input. Cross-book translation, goodwill,
//! inventory-profit elimination are outside this method. In a single-parent
//! ownership tree, each subsidiary's controlling earnings and reserves flow
//! to its parent before that parent's noncontrolling share is calculated.

mod math;
mod statements;

use super::{Certificate, ReportError, failed, functional, metadata, statement, text};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg, proposal_leg_details};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const OUTPUT_FORMAT: &[u8] = b"fa:consolidation:v1";
pub(super) const FUNCTIONAL_OUTPUT_FORMAT: &[u8] = b"fa:functional-consolidation:v1";
const RUN_FORMAT: &[u8] = b"fa:consolidation-run:v1";
const PARAMETERS_SOURCE: &str =
    "certificate-bound-report-parameters; genesis-registration-not-proved";
const ROLE_FORMAT: &[u8] = b"fa:account-role:v1";
const ROLES: &[&str] = &[
    "contributed_capital",
    "intercompany",
    "intercompany_activity",
    "investment_in_subsidiary",
    "noncontrolling_interest",
    "noncontrolling_interest_income",
];

type Entity = [u8; 16];
type Balances = BTreeMap<(Entity, u128, u32), (i128, i128)>;
type Totals = BTreeMap<(u128, u32), (i128, i128)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationMember {
    pub code: String,
    pub name: String,
    pub parent: Option<String>,
    pub ownership_bps: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationLeg {
    pub entity_id: Entity,
    pub account_id: u128,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationElimination {
    pub code: String,
    pub description: String,
    pub unit_id: u32,
    pub legs: Vec<ConsolidationLeg>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationEquity {
    pub unit_id: u32,
    pub parent_total_equity: i128,
    pub subsidiaries_total_equity: i128,
    pub equity_eliminations: i128,
    pub non_controlling_interest_equity: i128,
    pub controlling_interest_equity: i128,
    pub consolidated_total_equity: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedConsolidation {
    pub book_id: [u8; 16],
    pub branch_id: [u8; 16],
    pub known_at: u64,
    pub period: String,
    pub effective_through: i32,
    /// None means native units; Some identifies retained functional amounts.
    pub base_unit: Option<u32>,
    pub rounding_law: &'static str,
    pub members: Vec<ConsolidationMember>,
    pub eliminations: Vec<ConsolidationElimination>,
    pub income_eliminations: Vec<ConsolidationElimination>,
    pub equity_reconciliations: Vec<ConsolidationEquity>,
    pub balance_sheet: statement::VerifiedStatement,
    pub income_statement: statement::VerifiedStatement,
    pub run_digest: [u8; 32],
    pub book_parameters_source: &'static str,
}

struct Ownership {
    parent: Entity,
    subsidiary: Entity,
    bps: u16,
    investment: u128,
    capital: Vec<u128>,
    nci: Option<u128>,
    nci_income: Option<u128>,
}

fn invalid(why: impl Into<String>) -> ReportError {
    failed("consolidation_recomputation", why)
}
fn add(left: i128, right: i128) -> Result<i128, ReportError> {
    left.checked_add(right)
        .ok_or_else(|| invalid("consolidation amount overflow"))
}
fn subtract(left: i128, right: i128) -> Result<i128, ReportError> {
    left.checked_sub(right)
        .ok_or_else(|| invalid("consolidation amount overflow"))
}
fn negate(value: i128) -> Result<i128, ReportError> {
    value
        .checked_neg()
        .ok_or_else(|| invalid("consolidation amount cannot be negated"))
}
fn framed_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Writer::default();
    for part in parts {
        bytes.bytes(part);
    }
    hash_parts(domain, &[&bytes.buf])
}
fn legal_entity(book: &[u8; 16], code: &str) -> Entity {
    let digest = framed_hash(b"fa:vid:legal-entity:v1", &[book, code.as_bytes()]);
    u128::from_le_bytes(digest[..16].try_into().expect("sixteen bytes")).to_be_bytes()
}
fn entity_hex(entity: &Entity) -> String {
    format!("{:032x}", u128::from_be_bytes(*entity))
}
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

struct History {
    parents: BTreeMap<String, (String, u16)>,
    roles: BTreeMap<String, Vec<u128>>,
}

fn controls(
    book: &[u8; 16],
    members: &BTreeMap<String, Entity>,
    through: i32,
    role_types: &BTreeMap<String, Vec<u8>>,
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
) -> Result<History, ReportError> {
    let codes: BTreeMap<_, _> = members
        .iter()
        .map(|(code, entity)| (u128::from_be_bytes(*entity), code.as_str()))
        .collect();
    if codes.len() != members.len() {
        return Err(invalid("legal-entity identities collide"));
    }
    // Same-publication controls are ordered by their intrinsic Entry identity.
    let mut ordered: Vec<_> = infos.iter().collect();
    ordered.sort_by_key(|(index, info)| (envelopes[**index].commit_seq, info.identity));
    let mut latest = BTreeMap::new();
    let mut parents = BTreeMap::new();
    let mut relationships = BTreeSet::new();
    for (_, info) in ordered {
        let Some((kind, raw)) = info.schema else {
            continue;
        };
        let mut r = Reader::new(raw);
        if kind == 16 {
            if r.fixed::<{ ROLE_FORMAT.len() }>("consolidation.role_format")?
                .as_slice()
                != ROLE_FORMAT
            {
                return Err(invalid("unsupported account-role control"));
            }
            let account = r.u128("consolidation.role_account")?;
            let role = text(&mut r, 64, "consolidation.role_name")?.to_string();
            let assigned = r.present("consolidation.role_assigned")?;
            r.finish("consolidation role control")?;
            if !schema.accounts.contains_key(&account) || !role_types.contains_key(&role) {
                return Err(invalid("role control names an unknown account or role"));
            }
            latest.insert((role, account), assigned);
        } else if kind == 9 {
            let from = r.u128("consolidation.relationship_from")?;
            let to = r.u128("consolidation.relationship_to")?;
            let tag = r.u8("consolidation.relationship_kind")?;
            let fraction = match tag {
                1 => {
                    let numerator = r.i128("consolidation.ownership_numerator")?;
                    let denominator = r.u128("consolidation.ownership_denominator")?;
                    if numerator <= 0
                        || denominator == 0
                        || numerator as u128 > denominator
                        || gcd(numerator as u128, denominator) != 1
                    {
                        return Err(invalid("ownership must be a reduced fraction in (0, 1]"));
                    }
                    Some((numerator as u128, denominator))
                }
                2 | 3 => None,
                _ => return Err(invalid("unknown relationship kind")),
            };
            let basis = text(&mut r, 64, "consolidation.relationship_basis")?.to_string();
            let start = r.i32("consolidation.relationship_from_date")?;
            let end = r
                .present("consolidation.relationship_to_date")?
                .then(|| r.i32("consolidation.relationship_to_date"))
                .transpose()?;
            r.finish("consolidation relationship control")?;
            if from == to {
                return Err(invalid("ownership or relationship contains a self-cycle"));
            }
            if basis.is_empty() || end.is_some_and(|end| end <= start) {
                return Err(invalid("invalid relationship basis or validity interval"));
            }
            if !relationships.insert((tag, from, to, basis, start)) {
                return Err(invalid("duplicate relationship identity"));
            }
            let Some((numerator, denominator)) = fraction else {
                continue;
            };
            if start > through || end.is_some_and(|end| through >= end) {
                continue;
            }
            let (Some(owner), Some(owned)) = (codes.get(&from), codes.get(&to)) else {
                // External owners and other parties do not become group members.
                continue;
            };
            if 10_000 % denominator != 0 {
                return Err(invalid(
                    "ownership is not an integral number of basis points",
                ));
            }
            let bps = numerator * (10_000 / denominator);
            let bps = u16::try_from(bps).map_err(|_| invalid("ownership basis points overflow"))?;
            if !(1..=10_000).contains(&bps)
                || parents
                    .insert((*owned).to_string(), ((*owner).to_string(), bps))
                    .is_some()
            {
                return Err(invalid(
                    "a subsidiary requires exactly one active group parent",
                ));
            }
        }
    }
    for start in parents.keys() {
        let mut seen = BTreeSet::new();
        let mut cursor = start;
        while let Some((parent, _)) = parents.get(cursor) {
            if !seen.insert(cursor) {
                return Err(invalid("ownership contains a cycle"));
            }
            cursor = parent;
        }
    }
    let mut roles: BTreeMap<String, Vec<u128>> = BTreeMap::new();
    for ((role, account), assigned) in latest {
        if !assigned || !ROLES.contains(&role.as_str()) {
            continue;
        }
        let metadata = &schema.accounts[&account];
        if !metadata.is_leaf || !role_types[&role].contains(&metadata.account_type) {
            return Err(invalid(format!(
                "active {role} role requires an admitted posting account"
            )));
        }
        roles.entry(role).or_default().push(account);
    }
    // Membership is derived from this book's own declared entity codes.
    if members
        .iter()
        .any(|(code, id)| *id != legal_entity(book, code))
    {
        return Err(invalid(
            "group member identity differs from the declared book",
        ));
    }
    Ok(History { parents, roles })
}

fn role<'a>(history: &'a History, name: &str) -> &'a [u128] {
    history.roles.get(name).map_or(&[], Vec::as_slice)
}
fn single_role(history: &History, name: &str, needed: bool) -> Result<Option<u128>, ReportError> {
    match role(history, name) {
        [] if !needed => Ok(None),
        [only] => Ok(Some(*only)),
        _ => Err(invalid(format!(
            "consolidation needs one unambiguous {name} account"
        ))),
    }
}

fn ownership(
    history: &History,
    members: &BTreeMap<String, Entity>,
    stock: &Balances,
) -> Result<Vec<Ownership>, ReportError> {
    let partial = history.parents.values().any(|(_, bps)| *bps < 10_000);
    let nci = single_role(history, "noncontrolling_interest", partial)?;
    let nci_income = single_role(history, "noncontrolling_interest_income", partial)?;
    let capital = role(history, "contributed_capital");
    let investments = role(history, "investment_in_subsidiary");
    if !history.parents.is_empty() && (capital.is_empty() || investments.is_empty()) {
        return Err(invalid(
            "subsidiaries require capital and investment account roles",
        ));
    }
    let investment_accounts: BTreeSet<_> = investments.iter().copied().collect();
    let mut carried: BTreeMap<Entity, BTreeSet<u128>> = BTreeMap::new();
    for (&(entity, account, _), &(debits, credits)) in stock {
        if debits != credits && investment_accounts.contains(&account) {
            carried.entry(entity).or_default().insert(account);
        }
    }
    let mut links = Vec::with_capacity(history.parents.len());
    for (subsidiary, (parent, bps)) in &history.parents {
        let parent = members[parent];
        let investment = match carried.get(&parent) {
            None => investments[0],
            Some(accounts) if accounts.len() == 1 => *accounts.first().expect("one account"),
            _ => return Err(invalid("one parent carries several investment accounts")),
        };
        links.push(Ownership {
            parent,
            subsidiary: members[subsidiary],
            bps: *bps,
            investment,
            capital: capital.to_vec(),
            nci,
            nci_income,
        });
    }
    links.sort_by_key(|link| (link.parent, link.subsidiary));
    Ok(links)
}

fn add_balance(
    balances: &mut Balances,
    key: (Entity, u128, u32),
    debit: bool,
    amount: i128,
) -> Result<(), ReportError> {
    if amount < 0 {
        return Err(invalid("negative source amount"));
    }
    let cell = balances.entry(key).or_default();
    if debit {
        cell.0 = add(cell.0, amount)?;
    } else {
        cell.1 = add(cell.1, amount)?;
    }
    if balances.len() > 2_000_000 {
        return Err(failed(
            "bounded_input",
            "consolidation source exceeds two million cells",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    cert: &Certificate<'_>,
    period: &str,
    units: &[u32],
    role_types: &BTreeMap<String, Vec<u8>>,
    book_bytes: &[u8],
    functional_amounts: Option<&BTreeMap<usize, Vec<i128>>>,
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    visible_migrations: &BTreeSet<u64>,
) -> Result<(VerifiedConsolidation, Vec<u8>), ReportError> {
    if cert.branch != [0; 16]
        || cert.time_selection.is_some()
        || cert.functional != functional_amounts.is_some()
    {
        return Err(invalid(
            "consolidation requires a sequence-selected trunk and its exact valuation basis",
        ));
    }
    if units.is_empty() || units.len() > 4096 || !units.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid(
            "consolidation requires the canonical complete unit universe",
        ));
    }
    let spec = functional::BookParameters::read(book_bytes, &cert.book)?;
    if spec.entities.len() < 2
        || spec.entities.len() != spec.entity_names.len()
        || !schema.calendar_matches(&spec.calendar)
        || !units.contains(&spec.base)
    {
        return Err(invalid(
            "Book parameters do not describe a supported multi-entity book",
        ));
    }
    let members: BTreeMap<_, _> = spec
        .entity_names
        .keys()
        .map(|code| (code.clone(), legal_entity(&cert.book, code)))
        .collect();
    if spec
        .entities
        .values()
        .any(|code| !members.contains_key(code))
    {
        return Err(invalid("entity names and dimension identities disagree"));
    }
    let (from, through) = schema.bounds(&[period.to_string()])?;
    let selected_units = if cert.functional {
        vec![spec.base]
    } else {
        units.to_vec()
    };
    let unit_set: BTreeSet<_> = units.iter().copied().collect();
    let mut identities = BTreeMap::new();
    for (&index, info) in infos {
        let envelope = envelopes
            .get(index)
            .ok_or_else(|| invalid("source envelope is absent"))?;
        if envelope.commit_seq > cert.known_at {
            return Err(invalid(
                "consolidation source extends beyond its certificate",
            ));
        }
        if envelope.class == 12 && !visible_migrations.contains(&(index as u64)) {
            continue;
        }
        for identity in info.identities() {
            if identities
                .insert(identity, index)
                .is_some_and(|previous| previous != index)
            {
                return Err(invalid("duplicate source identity"));
            }
        }
    }
    let history = controls(
        &cert.book, &members, through, role_types, schema, envelopes, infos,
    )?;
    let mut stock = Balances::new();
    let mut activity = Balances::new();
    let mut lineage = statement::Lineage::default();
    let mut ordered: Vec<_> = infos.iter().collect();
    ordered.sort_by_key(|(index, info)| (envelopes[**index].commit_seq, info.identity));
    for (&index, info) in ordered {
        let envelope = &envelopes[index];
        let source_legs = legs
            .get(index)
            .ok_or_else(|| invalid("source legs are absent"))?;
        if source_legs.is_empty()
            || envelope.class == 2
            || envelope.class == 12 && !visible_migrations.contains(&(index as u64))
        {
            continue;
        }
        let day = envelope
            .effective_day
            .ok_or_else(|| invalid("monetary source has no effective date"))?;
        if day > through {
            continue;
        }
        let (length, record) = records
            .get(index)
            .ok_or_else(|| invalid("source record is absent"))?;
        let proposal = record
            .get(..*length)
            .ok_or_else(|| invalid("source proposal length differs"))?;
        let details = proposal_leg_details(proposal)?;
        if details.len() != source_legs.len() {
            return Err(invalid("source dimensions and legs differ"));
        }
        let valued = functional_amounts
            .map(|amounts| {
                amounts
                    .get(&index)
                    .filter(|values| values.len() == source_legs.len())
                    .ok_or_else(|| invalid("independently checked functional source is absent"))
            })
            .transpose()?;
        let in_period = schema.entry_period(info, day)? == period;
        let original = if in_period {
            statement::origin(index, envelopes, infos, &identities, &mut lineage)?
        } else {
            index
        };
        let include_income = in_period && envelope.class != 8 && envelopes[original].class != 8;
        if include_income && envelopes[original].class == 12 {
            let original_day = envelopes[original]
                .effective_day
                .ok_or_else(|| invalid("migration source has no date"))?;
            let original_period = schema.entry_period(&infos[&original], original_day)?;
            if schema.period_kind(&original_period)? == 3 {
                return Err(invalid(
                    "a migrated Closing-period source does not retain its original accounting class",
                ));
            }
        }
        let mut entry_totals: BTreeMap<(Entity, u32), (i128, i128)> = BTreeMap::new();
        for (ordinal, (leg, detail)) in source_legs.iter().zip(&details).enumerate() {
            let account = schema
                .accounts
                .get(&leg.account)
                .ok_or_else(|| invalid("source names an undeclared account"))?;
            if !account.is_leaf || !unit_set.contains(&leg.unit) {
                return Err(invalid(
                    "source names a summary account or unregistered unit",
                ));
            }
            let value = detail
                .dimensions
                .iter()
                .find(|(kind, _)| *kind == 1)
                .map(|(_, value)| value)
                .ok_or_else(|| invalid("multi-entity source has no legal-entity dimension"))?;
            let code = spec
                .entities
                .get(value)
                .ok_or_else(|| invalid("source names an undeclared legal entity"))?;
            let entity = members[code];
            let (unit, amount) = if let Some(values) = valued {
                (spec.base, values[ordinal])
            } else {
                (leg.unit, leg.mantissa)
            };
            if amount < 0 {
                return Err(invalid("source has a negative amount"));
            }
            add_balance(&mut stock, (entity, leg.account, unit), leg.debit, amount)?;
            if include_income {
                add_balance(
                    &mut activity,
                    (entity, leg.account, unit),
                    leg.debit,
                    amount,
                )?;
            }
            if account.account_type <= 5 {
                let total = entry_totals.entry((entity, unit)).or_default();
                if leg.debit {
                    total.0 = add(total.0, amount)?;
                } else {
                    total.1 = add(total.1, amount)?;
                }
            }
        }
        if entry_totals
            .values()
            .any(|(debits, credits)| debits != credits)
        {
            return Err(invalid(
                "source entry fails monetary balance by legal entity and unit",
            ));
        }
    }
    let links = ownership(&history, &members, &stock)?;
    // Bound the product of independently bounded inputs before deriving any
    // ownership allocations. A small book with many zero-valued units and
    // capital-role accounts must not create an unbounded verification loop.
    let work = selected_units
        .len()
        .checked_mul(links.len())
        .and_then(|value| {
            value.checked_mul(
                role(&history, "contributed_capital")
                    .len()
                    .saturating_add(8),
            )
        });
    if work.is_none_or(|work| work > 2_000_000) {
        return Err(failed(
            "bounded_input",
            "consolidation ownership expansion exceeds two million terms",
        ));
    }
    let intercompany: BTreeSet<_> = role(&history, "intercompany")
        .iter()
        .chain(role(&history, "intercompany_activity"))
        .copied()
        .collect();
    let mut calculated = math::derive(
        schema,
        &selected_units,
        &members,
        &links,
        &intercompany,
        &stock,
        &activity,
    )?;
    let (balance_sheet, bs_bytes) = statements::build(
        false,
        cert,
        period,
        from,
        through,
        &selected_units,
        schema,
        &calculated.stock,
    )?;
    let (income_statement, is_bytes) = statements::build(
        true,
        cert,
        period,
        from,
        through,
        &selected_units,
        schema,
        &calculated.activity,
    )?;
    for equity in &mut calculated.equity {
        let actual = balance_sheet
            .lines
            .iter()
            .find(|line| line.code == "total_equity" && line.unit == equity.unit_id)
            .and_then(|line| line.amounts.first())
            .copied()
            .ok_or_else(|| invalid("consolidated balance sheet omits total equity"))?;
        if actual != equity.consolidated_total_equity {
            return Err(invalid(
                "consolidated equity does not reconcile to its member and elimination sources",
            ));
        }
        equity.controlling_interest_equity =
            subtract(actual, equity.non_controlling_interest_equity)?;
    }
    let mut report = VerifiedConsolidation {
        book_id: cert.book,
        branch_id: cert.branch,
        known_at: cert.known_at,
        period: period.to_string(),
        effective_through: through,
        base_unit: cert.functional.then_some(spec.base),
        rounding_law: "HalfEven",
        members: spec
            .entity_names
            .into_iter()
            .map(|(code, name)| {
                let (parent, ownership_bps) = history
                    .parents
                    .get(&code)
                    .map_or((None, None), |(parent, bps)| {
                        (Some(parent.clone()), Some(*bps))
                    });
                ConsolidationMember {
                    code,
                    name,
                    parent,
                    ownership_bps,
                }
            })
            .collect(),
        eliminations: calculated.eliminations,
        income_eliminations: calculated.income_eliminations,
        equity_reconciliations: calculated.equity,
        balance_sheet,
        income_statement,
        run_digest: [0; 32],
        book_parameters_source: PARAMETERS_SOURCE,
    };
    let run = run_bytes(&report, &bs_bytes, &is_bytes)?;
    report.run_digest = framed_hash(RUN_FORMAT, &[&run]);
    let mut output = Writer::default();
    output
        .fixed(OUTPUT_FORMAT)
        .bytes(period.as_bytes())
        .u64(cert.known_at)
        .i32(through)
        .count(report.members.len());
    for member in &report.members {
        output
            .bytes(member.code.as_bytes())
            .bytes(member.name.as_bytes())
            .u8(u8::from(member.parent.is_some()));
        if let Some(parent) = &member.parent {
            output.bytes(parent.as_bytes());
        }
        output.u8(u8::from(member.ownership_bps.is_some()));
        if let Some(bps) = member.ownership_bps {
            output.u16(bps);
        }
    }
    output.bytes(b"HalfEven").bytes(&run);
    if cert.functional {
        let mut wrapper = Writer::default();
        wrapper
            .fixed(FUNCTIONAL_OUTPUT_FORMAT)
            .u32(spec.base)
            .bytes(b"retained-base-amounts")
            .bytes(&output.buf);
        output = wrapper;
    }
    if output.buf.len() > super::MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "consolidated output exceeds 64 MiB",
        ));
    }
    Ok((report, output.buf))
}

fn run_bytes(
    report: &VerifiedConsolidation,
    balance_sheet: &[u8],
    income_statement: &[u8],
) -> Result<Vec<u8>, ReportError> {
    let mut w = Writer::default();
    w.fixed(RUN_FORMAT)
        .fixed(&report.book_id)
        .fixed(&report.branch_id)
        .u64(report.known_at)
        .bytes(report.period.as_bytes())
        // This method derives group role-account eliminations, not declared
        // cross-book pairs. A nonempty pair transcript cannot be substituted.
        .count(0);
    for entries in [&report.eliminations, &report.income_eliminations] {
        w.count(entries.len());
        for entry in entries {
            w.bytes(entry.code.as_bytes())
                .bytes(entry.description.as_bytes())
                .u32(entry.unit_id)
                .count(entry.legs.len());
            for leg in &entry.legs {
                w.fixed(&leg.entity_id)
                    .u128(leg.account_id)
                    .u32(leg.unit_id)
                    .i128(leg.debits)
                    .i128(leg.credits);
            }
            if w.buf.len() > super::MAX_REPORT_BUNDLE_BYTES {
                return Err(failed(
                    "bounded_input",
                    "consolidation eliminations exceed 64 MiB",
                ));
            }
        }
    }
    w.count(report.equity_reconciliations.len());
    for equity in &report.equity_reconciliations {
        w.u32(equity.unit_id)
            .i128(equity.parent_total_equity)
            .i128(equity.subsidiaries_total_equity)
            .i128(equity.equity_eliminations)
            .i128(equity.non_controlling_interest_equity)
            .i128(equity.controlling_interest_equity)
            .i128(equity.consolidated_total_equity);
    }
    w.bytes(balance_sheet).bytes(income_statement);
    Ok(w.buf)
}
