//! Native open items reconstructed from authenticated entry and chart controls.
//! Applications are payload facts, never SETTLES edges or applied mirrors. Each
//! reversal chain determines liveness; capacity is checked at every committed
//! frontier so a later undo cannot conceal an earlier over-application.

use super::{ReportError, failed, metadata};
use crate::codec::Writer;
use crate::envelope::{LeafEnvelope, Leg, LegDetails, proposal_leg_details};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenItemUnitPolicy {
    Single(u32),
    AnyCurrency,
    AnyUnit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenItemBalanceLimit {
    pub lower: Option<i128>,
    pub upper: Option<i128>,
    pub period_scoped: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOpenItemAccount {
    pub account: u128,
    pub code: String,
    pub name: String,
    pub account_type: u8,
    /// 0 is debit-normal; 1 is credit-normal.
    pub normal_balance: u8,
    pub is_leaf: bool,
    pub unit_policy: OpenItemUnitPolicy,
    pub limit: Option<OpenItemBalanceLimit>,
    /// The authenticated account version used by the historical report.
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedApplication {
    pub entry: u128,
    pub ordinal: u16,
    pub amount: i128,
    pub recorded_at: u64,
    pub live: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOpenItem {
    pub entry: u128,
    pub ordinal: u16,
    pub account: u128,
    pub unit_id: u32,
    pub debit: bool,
    pub effective_date: i32,
    pub recorded_at: u64,
    pub original: i128,
    pub applied: i128,
    pub applied_out: i128,
    pub open: i128,
    /// Complete history, including applications undone by reversal.
    pub applications: Vec<VerifiedApplication>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOpenItems {
    pub account_filter: Option<u128>,
    pub accounts: BTreeMap<u128, VerifiedOpenItemAccount>,
    pub items: Vec<VerifiedOpenItem>,
}

fn carries(class: u16, legs: &[Leg]) -> bool {
    matches!(class, 1 | 3 | 5..=15) && !legs.is_empty()
}

fn add(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_add(b)
        .ok_or_else(|| failed("exact_arithmetic", "open-item application sum overflow"))
}

fn absent_identity(
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    identity: u128,
    predicate: &'static str,
) -> ReportError {
    if infos
        .values()
        .any(|info| info.legacy_identity == Some(identity))
    {
        failed(
            "supported_report",
            "legacy key-derived replacement identities are not unambiguously authenticated by the portable OpenItems format",
        )
    } else {
        failed(
            predicate,
            "target identity is absent from the visible prefix",
        )
    }
}

pub(super) fn account(
    id: u128,
    schema: &metadata::Schema,
) -> Result<VerifiedOpenItemAccount, ReportError> {
    let row = schema.accounts.get(&id).ok_or_else(|| {
        failed(
            "account_metadata",
            format!("account {id:032x} has no authenticated declaration"),
        )
    })?;
    Ok(VerifiedOpenItemAccount {
        account: id,
        code: row.code.clone(),
        name: row.name.clone(),
        account_type: row.account_type,
        normal_balance: row.normal_balance,
        is_leaf: row.is_leaf,
        unit_policy: match row.unit_policy {
            -2 => OpenItemUnitPolicy::AnyUnit,
            -1 => OpenItemUnitPolicy::AnyCurrency,
            unit => OpenItemUnitPolicy::Single(
                u32::try_from(unit)
                    .map_err(|_| failed("account_metadata", "invalid account unit policy"))?,
            ),
        },
        limit: row.limit.as_ref().map(|limit| OpenItemBalanceLimit {
            lower: limit.lower,
            upper: limit.upper,
            period_scoped: limit.period_scoped,
        }),
        created_at: row.created_at,
    })
}

/// Each root owns its entire reversal chain. Walking roots once avoids the
/// quadratic repeated-ancestry scan, and the visited set rejects cycles.
fn timelines(
    selected: &BTreeSet<usize>,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    details: &BTreeMap<usize, Vec<LegDetails>>,
    migration_activations: &BTreeMap<u64, u64>,
) -> Result<BTreeMap<usize, Vec<(u64, bool)>>, ReportError> {
    let mut identities = BTreeMap::new();
    for &index in selected {
        if identities.insert(infos[&index].identity, index).is_some() {
            return Err(failed("entry_identity", "duplicate derived entry identity"));
        }
    }
    let mut children = BTreeMap::new();
    for &index in selected {
        if envelopes[index].class != 4 {
            continue;
        }
        let [(identity, digest, 1)] = infos[&index].supersession.as_slice() else {
            return Err(failed(
                "entry_lineage",
                "reversal requires one Reverses target",
            ));
        };
        let target = *identities
            .get(identity)
            .ok_or_else(|| absent_identity(infos, *identity, "entry_lineage"))?;
        if envelopes[target].record_digest != *digest
            || envelopes[target].commit_seq > envelopes[index].commit_seq
            || migration_activations
                .get(&(target as u64))
                .is_some_and(|seq| *seq > envelopes[index].commit_seq)
            || (!carries(envelopes[target].class, &legs[target]) && envelopes[target].class != 4)
        {
            return Err(failed(
                "entry_lineage",
                "reversal target digest, time, or posted class is invalid",
            ));
        }
        if children.insert(target, index).is_some() {
            return Err(failed("entry_lineage", "entry has more than one reversal"));
        }
        if legs[index].len() != legs[target].len()
            || legs[index].iter().zip(&legs[target]).any(|(a, b)| {
                a.account != b.account
                    || a.unit != b.unit
                    || a.mantissa != b.mantissa
                    || a.debit == b.debit
            })
            || details[&index]
                .iter()
                .zip(&details[&target])
                .any(|(a, b)| a.base_amount != b.base_amount || a.dimensions != b.dimensions)
        {
            return Err(failed(
                "entry_lineage",
                "reversal does not exactly swap its target legs",
            ));
        }
    }
    let mut visited = BTreeSet::new();
    let mut result = BTreeMap::new();
    for &root in selected {
        if envelopes[root].class == 4 {
            continue;
        }
        let mut at = root;
        let mut live = true;
        let born = migration_activations
            .get(&(root as u64))
            .copied()
            .unwrap_or(envelopes[root].commit_seq);
        let mut events = vec![(born, live)];
        loop {
            if !visited.insert(at) {
                return Err(failed("entry_lineage", "reversal lineage contains a cycle"));
            }
            let Some(&child) = children.get(&at) else {
                break;
            };
            live = !live;
            let seq = envelopes[child].commit_seq;
            if events.last().is_some_and(|event| event.0 == seq) {
                events.last_mut().expect("root event exists").1 = live;
            } else {
                events.push((seq, live));
            }
            at = child;
        }
        if carries(envelopes[root].class, &legs[root]) {
            result.insert(root, events);
        }
    }
    if visited != *selected {
        return Err(failed(
            "entry_lineage",
            "reversal lineage has no authenticated root",
        ));
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    known_at: u64,
    account_filter: Option<u128>,
    units: &[u32],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    records: &[(usize, &[u8])],
    visible_migrations: &BTreeSet<u64>,
    migration_activations: &BTreeMap<u64, u64>,
) -> Result<(VerifiedOpenItems, Vec<u8>), ReportError> {
    let report = replay_inner(
        known_at,
        account_filter,
        None,
        units,
        schema,
        envelopes,
        infos,
        legs,
        records,
        visible_migrations,
        migration_activations,
    )?;
    let output = encode(known_at, &report);
    Ok((report, output))
}

/// Re-select authenticated entries before lineage and application netting.
/// The caller first verifies the complete, all-effective native source through
/// replay(). A partial effective-time history is not a committed prefix, so
/// its intermediate capacity states must not be mistaken for admitted states.
#[allow(clippy::too_many_arguments)]
pub(super) fn replay_as_of(
    known_at: u64,
    account_filter: Option<u128>,
    effective_through: i32,
    units: &[u32],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    records: &[(usize, &[u8])],
    visible_migrations: &BTreeSet<u64>,
    migration_activations: &BTreeMap<u64, u64>,
) -> Result<VerifiedOpenItems, ReportError> {
    replay_inner(
        known_at,
        account_filter,
        Some(effective_through),
        units,
        schema,
        envelopes,
        infos,
        legs,
        records,
        visible_migrations,
        migration_activations,
    )
}

#[allow(clippy::too_many_arguments)]
fn replay_inner(
    _known_at: u64,
    account_filter: Option<u128>,
    effective_through: Option<i32>,
    units: &[u32],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    records: &[(usize, &[u8])],
    visible_migrations: &BTreeSet<u64>,
    migration_activations: &BTreeMap<u64, u64>,
) -> Result<VerifiedOpenItems, ReportError> {
    let selected: BTreeSet<_> = infos
        .keys()
        .copied()
        .filter(|index| {
            (envelopes[*index].class != 12 || visible_migrations.contains(&(*index as u64)))
                && effective_through.is_none_or(|cutoff| {
                    envelopes[*index]
                        .effective_day
                        .is_some_and(|day| day <= cutoff)
                        && account_filter.is_none_or(|account| {
                            legs[*index].iter().any(|leg| leg.account == account)
                        })
                })
        })
        .collect();
    let mut details = BTreeMap::new();
    for &index in &selected {
        let class = envelopes[index].class;
        if !(1..=30).contains(&class) || (class >= 16 && !legs[index].is_empty()) {
            return Err(failed(
                "registry_closure",
                "unsupported entry class or control carrying legs",
            ));
        }
        let (len, bytes) = records[index];
        let parsed = proposal_leg_details(&bytes[..len])?;
        for (leg, detail) in legs[index].iter().zip(&parsed) {
            if leg.mantissa < 0 {
                return Err(failed(
                    "exact_arithmetic",
                    "an open-item leg has a negative mantissa",
                ));
            }
            if units.binary_search(&leg.unit).is_err() {
                return Err(failed(
                    "registry_closure",
                    "open-item leg uses an unregistered unit",
                ));
            }
            if !schema.accounts.contains_key(&leg.account) {
                return Err(failed(
                    "account_metadata",
                    "open-item leg has no authenticated account declaration",
                ));
            }
            if !detail
                .dimensions
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
            {
                return Err(failed(
                    "application_shape",
                    "leg dimensions are not strictly ordered",
                ));
            }
            if !detail.settlements.is_empty() && !matches!(class, 1 | 3 | 5 | 7) {
                return Err(failed(
                    "application_shape",
                    "entry class cannot originate settlements",
                ));
            }
        }
        details.insert(index, parsed);
    }
    if effective_through.is_some() {
        let all_identities: BTreeMap<_, _> = infos
            .iter()
            .map(|(&index, info)| (info.identity, index))
            .collect();
        for &index in &selected {
            if envelopes[index].class == 4 {
                for (target, _, kind) in &infos[&index].supersession {
                    if *kind == 1
                        && all_identities
                            .get(target)
                            .is_some_and(|target| !selected.contains(target))
                    {
                        return Err(failed(
                            "aging_effective_selection",
                            "effective cutoff splits a reversal from its later-effective target",
                        ));
                    }
                }
            }
        }
    }
    let timelines = timelines(
        &selected,
        envelopes,
        infos,
        legs,
        &details,
        migration_activations,
    )?;
    let identities: BTreeMap<_, _> = selected.iter().map(|&i| (infos[&i].identity, i)).collect();
    let mut outbound = BTreeMap::new();
    let mut applications: BTreeMap<(usize, u16), Vec<VerifiedApplication>> = BTreeMap::new();
    let mut changes: BTreeMap<(usize, u16), BTreeMap<u64, i128>> = BTreeMap::new();
    // Repeated application revival can expand a small lineage into many amount
    // events. Bound that work explicitly instead of permitting an adversarial
    // product of chain length and application count to exhaust the verifier.
    let mut remaining_events = 16 * super::MAX_ROWS;
    for (&index, timeline) in &timelines {
        for (ordinal, (leg, detail)) in legs[index].iter().zip(&details[&index]).enumerate() {
            if effective_through.is_some()
                && account_filter.is_some_and(|account| account != leg.account)
            {
                continue;
            }
            let ordinal = u16::try_from(ordinal)
                .map_err(|_| failed("bounded_input", "open-item ordinal exceeds u16"))?;
            let mut sum = 0;
            let mut named = BTreeSet::new();
            for reference in &detail.settlements {
                if reference.amount <= 0
                    || reference.unit != leg.unit
                    || !named.insert((reference.target, reference.ordinal))
                {
                    return Err(failed(
                        "application_shape",
                        "settlements must be positive, in the source unit, and name each target leg once",
                    ));
                }
                sum = add(sum, reference.amount)?;
                let target = *identities.get(&reference.target).ok_or_else(|| {
                    if effective_through.is_some() {
                        failed(
                            "aging_effective_selection",
                            "effective cutoff splits a settlement from its later-effective target",
                        )
                    } else {
                        absent_identity(infos, reference.target, "application_target")
                    }
                })?;
                let target_leg = legs[target]
                    .get(usize::from(reference.ordinal))
                    .ok_or_else(|| {
                        failed("application_target", "settlement target ordinal is absent")
                    })?;
                if envelopes[target].record_digest != reference.digest
                    || envelopes[target].commit_seq > envelopes[index].commit_seq
                    || migration_activations
                        .get(&(target as u64))
                        .is_some_and(|seq| *seq > envelopes[index].commit_seq)
                    || target == index
                    || !timelines.contains_key(&target)
                    || target_leg.account != leg.account
                    || target_leg.unit != leg.unit
                    || target_leg.debit == leg.debit
                {
                    return Err(failed(
                        "application_target",
                        "target digest, activation time, posted class, account, unit, or side disagree",
                    ));
                }
                let target_dimensions =
                    &details[&target][usize::from(reference.ordinal)].dimensions;
                if target_dimensions != &detail.dimensions {
                    let same_other_dimensions = target_dimensions
                        .iter()
                        .filter(|(kind, _)| *kind != 1)
                        .eq(detail.dimensions.iter().filter(|(kind, _)| *kind != 1));
                    let explicit_target = target_dimensions.iter().any(|(kind, _)| *kind == 1);
                    let explicit_source = detail.dimensions.iter().any(|(kind, _)| *kind == 1);
                    if same_other_dimensions && explicit_target != explicit_source {
                        return Err(failed(
                            "supported_report",
                            "implicit BookSpec legal-entity normalization is not authenticated; application source and target must use the same explicit dimension representation",
                        ));
                    }
                    return Err(failed(
                        "application_target",
                        "application source and target dimensions disagree",
                    ));
                }
                let key = (target, reference.ordinal);
                applications
                    .entry(key)
                    .or_default()
                    .push(VerifiedApplication {
                        entry: infos[&index].identity,
                        ordinal,
                        amount: reference.amount,
                        recorded_at: envelopes[index].commit_seq,
                        live: timeline.last().is_some_and(|event| event.1),
                    });
                if effective_through.is_none() {
                    let events = changes.entry(key).or_default();
                    let mut was_live = false;
                    for &(seq, live) in timeline {
                        if live == was_live {
                            continue;
                        }
                        remaining_events = remaining_events.checked_sub(1).ok_or_else(|| {
                            failed(
                                "bounded_input",
                                "application replay exceeds its event bound",
                            )
                        })?;
                        let delta = if live {
                            reference.amount
                        } else {
                            -reference.amount
                        };
                        let previous = events.get(&seq).copied().unwrap_or(0);
                        events.insert(seq, add(previous, delta)?);
                        was_live = live;
                    }
                }
            }
            if sum > leg.mantissa {
                return Err(failed(
                    "application_capacity",
                    "outgoing applications exceed their source leg",
                ));
            }
            outbound.insert((index, ordinal), sum);
        }
    }
    let mut items = Vec::new();
    for (&index, timeline) in &timelines {
        for (ordinal, leg) in legs[index].iter().enumerate() {
            if effective_through.is_some()
                && account_filter.is_some_and(|account| account != leg.account)
            {
                continue;
            }
            let ordinal = u16::try_from(ordinal)
                .map_err(|_| failed("bounded_input", "open-item ordinal exceeds u16"))?;
            let key = (index, ordinal);
            let applied_out = outbound[&key];
            let capacity = leg
                .mantissa
                .checked_sub(applied_out)
                .ok_or_else(|| failed("exact_arithmetic", "open-item capacity underflow"))?;
            let (live, applied) = if effective_through.is_some() {
                // Only final liveness belongs to this effective-date projection.
                // The complete source has already checked actual commit history.
                let applied = applications
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .filter(|application| application.live)
                    .try_fold(0, |sum, application| add(sum, application.amount))?;
                (timeline.last().is_some_and(|event| event.1), applied)
            } else {
                let mut frontiers: BTreeMap<u64, (Option<bool>, i128)> = timeline
                    .iter()
                    .map(|&(seq, live)| (seq, (Some(live), 0)))
                    .collect();
                for (seq, delta) in changes.remove(&key).unwrap_or_default() {
                    frontiers.entry(seq).or_insert((None, 0)).1 = delta;
                }
                let mut live = false;
                let mut applied = 0;
                for (_, (state, delta)) in frontiers {
                    if let Some(state) = state {
                        live = state;
                    }
                    applied = add(applied, delta)?;
                    if applied < 0 || applied > capacity || (!live && applied != 0) {
                        return Err(failed(
                            "application_capacity",
                            "a committed frontier over-applies or strands an application on a reversed item",
                        ));
                    }
                }
                (live, applied)
            };
            if effective_through.is_some() && !live && applied != 0 {
                return Err(failed(
                    "aging_effective_selection",
                    "effective cutoff strands a live settlement on a reversed target item",
                ));
            }
            if !live || account_filter.is_some_and(|account| account != leg.account) {
                continue;
            }
            let mut history = applications.remove(&key).unwrap_or_default();
            history.sort_by_key(|a| (a.recorded_at, a.entry, a.ordinal));
            items.push(VerifiedOpenItem {
                entry: infos[&index].identity,
                ordinal,
                account: leg.account,
                unit_id: leg.unit,
                debit: leg.debit,
                effective_date: envelopes[index].effective_day.ok_or_else(|| {
                    failed("report_selector", "open-item entry has no effective date")
                })?,
                recorded_at: envelopes[index].commit_seq,
                original: leg.mantissa,
                applied,
                applied_out,
                open: capacity
                    .checked_sub(applied)
                    .ok_or_else(|| failed("exact_arithmetic", "open amount underflow"))?,
                applications: history,
            });
        }
    }
    items.sort_by_key(|item| (item.account, item.recorded_at, item.entry, item.ordinal));
    let accounts: BTreeMap<_, _> = items
        .iter()
        .map(|item| item.account)
        .chain(account_filter)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| account(id, schema).map(|row| (id, row)))
        .collect::<Result<_, _>>()?;
    for account in accounts.values() {
        if let OpenItemUnitPolicy::Single(unit) = account.unit_policy
            && units.binary_search(&unit).is_err()
        {
            return Err(failed(
                "registry_closure",
                "selected account declares an unregistered unit",
            ));
        }
    }
    let report = VerifiedOpenItems {
        account_filter,
        accounts,
        items,
    };
    Ok(report)
}

fn encode(known_at: u64, report: &VerifiedOpenItems) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:open-items:v1")
        .u64(known_at)
        .u8(u8::from(report.account_filter.is_some()));
    if let Some(account) = report.account_filter {
        w.u128(account);
    }
    w.count(report.accounts.len());
    for (id, account) in &report.accounts {
        w.u128(*id)
            .u128(account.account)
            .bytes(account.code.as_bytes())
            .bytes(account.name.as_bytes())
            .u8(account.account_type)
            .u8(account.normal_balance)
            .u8(u8::from(account.is_leaf));
        match account.unit_policy {
            OpenItemUnitPolicy::Single(unit) => {
                w.u8(0).u32(unit);
            }
            OpenItemUnitPolicy::AnyCurrency => {
                w.u8(1);
            }
            OpenItemUnitPolicy::AnyUnit => {
                w.u8(2);
            }
        }
        w.u8(u8::from(account.limit.is_some()));
        if let Some(limit) = &account.limit {
            for bound in [limit.lower, limit.upper] {
                w.u8(u8::from(bound.is_some()));
                if let Some(bound) = bound {
                    w.i128(bound);
                }
            }
            w.u8(u8::from(limit.period_scoped));
        }
        w.u64(account.created_at);
    }
    w.count(report.items.len());
    for item in &report.items {
        w.u128(item.entry)
            .u16(item.ordinal)
            .u128(item.account)
            .u32(item.unit_id)
            .u8(u8::from(!item.debit))
            .i32(item.effective_date)
            .u64(item.recorded_at)
            .i128(item.original)
            .i128(item.applied)
            .i128(item.applied_out)
            .i128(item.open)
            .count(item.applications.len());
        for application in &item.applications {
            w.u128(application.entry)
                .u16(application.ordinal)
                .i128(application.amount)
                .u64(application.recorded_at)
                .u8(u8::from(application.live));
        }
    }
    w.buf
}
