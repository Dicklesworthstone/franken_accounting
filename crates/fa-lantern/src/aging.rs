//! Aging (plan §11.7): fa-registers' historical open-item fold at the
//! coordinate's effective date, bucketed by civil days from each item's
//! effective date, per account, unit and side. The fold and its cutoff
//! refusals belong to fa-registers (`open_items_as_of`, `age_snapshot`);
//! this procedure owns only the registered bucket edges and the score.
//! Debits and credits are never netted. The date is a coordinate the
//! caller declares; a procedure never reads a clock.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_money::Side;
use fa_registers::open_items::aging::{AgingBuckets, age_snapshot};
use fgdb_types::VId;

use crate::jet::{finding, procedure_boilerplate};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
};
use fa_model::AccountType;
use fa_time::DateDay;

/// `aging.open_items`.
pub struct OpenItemsAging {
    params: Params,
}

impl OpenItemsAging {
    pub const ID: &'static str = "aging.open_items";

    /// With the registry's pinned bucket edges.
    pub fn new() -> Result<Self, LanternError> {
        Ok(Self {
            params: Params::defaults(Self::ID)?,
        })
    }

    #[must_use]
    pub fn with(params: Params) -> Self {
        Self { params }
    }
}

/// One side of one account and unit: the open amount per bucket, never
/// netted against the other side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Column {
    totals: [i128; 4],
    oldest: Vec<(VId, u16)>,
    items: u64,
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Debit => "debit",
        Side::Credit => "credit",
    }
}

impl Procedure for OpenItemsAging {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let edges = [
            self.params.get_u32("bucket_1")?,
            self.params.get_u32("bucket_2")?,
            self.params.get_u32("bucket_3")?,
        ];
        if edges[0] >= edges[1] || edges[1] >= edges[2] {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "bucket_3".into(),
                message: "bucket edges must be strictly ascending".into(),
            });
        }
        let Some(fold) = &snapshot.open_items_as_of else {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "effective_through".into(),
                message: "aging is a historical fold: read the snapshot with an effective date \
                          (the coordinate's effective_through)"
                    .into(),
            });
        };
        let buckets = AgingBuckets::new(edges.to_vec())?;
        let aged = age_snapshot(fold.clone(), &buckets)?;
        let population = aged.items.len() as u64;
        // Keyed by (account, unit, side tag) so the two sides never meet.
        let mut columns: BTreeMap<(u128, u32, u8), Column> = BTreeMap::new();
        for row in &aged.items {
            work.leg();
            let tag = match row.item.side {
                Side::Debit => 0u8,
                Side::Credit => 1u8,
            };
            let c = columns
                .entry((row.item.account.0, row.item.unit_id, tag))
                .or_default();
            c.totals[row.bucket] = c.totals[row.bucket]
                .checked_add(row.item.open)
                .ok_or(LanternError::Overflow("aging bucket"))?;
            c.items += 1;
            if row.bucket == 3 && c.oldest.len() < MAX_CITES - 1 {
                c.oldest.push((row.item.entry, row.item.ordinal));
            }
        }
        let mut out = Vec::new();
        for ((account, unit_id, tag), c) in columns {
            let side = if tag == 0 { Side::Debit } else { Side::Credit };
            let total: i128 = c
                .totals
                .iter()
                .try_fold(0i128, |acc, t| acc.checked_add(*t))
                .ok_or(LanternError::Overflow("aging total"))?;
            let past = c.totals[3];
            let severity = if past == 0 {
                Severity::Info
            } else if past.unsigned_abs() >= total.unsigned_abs().div_ceil(2) {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut cites = vec![Cite::Account(VId(account))];
            let mut oldest = c.oldest;
            oldest.sort_unstable();
            cites.extend(
                oldest
                    .into_iter()
                    .map(|(entry, ordinal)| Cite::Leg { entry, ordinal }),
            );
            out.push(finding(
                Self::ID,
                severity,
                Statistic {
                    name: format!("open_past_{}_days", edges[2]),
                    value: past,
                    scale: crate::unit_scale(book, unit_id)?,
                    population,
                },
                cites,
                format!(
                    "unit {unit_id} {}: {} open item(s); buckets 0..={}: {}, ..={}: {}, ..={}: {}, older: {} (mantissas, never netted)",
                    side_name(side),
                    c.items,
                    edges[0],
                    c.totals[0],
                    edges[1],
                    c.totals[1],
                    edges[2],
                    c.totals[2],
                    past
                ),
            ));
        }
        Ok(out)
    }
}

/// `aging.inventory` (plan §11.7; ASC 330 / IAS 2): slow-moving and obsolete
/// inventory aging. Flags inventory asset accounts whose net debit balance has
/// had no credit relief movement for more than `stale_days` civil days through
/// the coordinate's effective date.
pub struct InventoryAging {
    params: Params,
}
procedure_boilerplate!(InventoryAging, "aging.inventory");

fn is_inventory_account(code: &str, name: &str, account_type: AccountType) -> bool {
    if account_type != AccountType::ASSET {
        return false;
    }
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl.starts_with("13")
        || cl.starts_with("14")
        || cl.contains("inv")
        || nl.contains("inventory")
        || nl.contains("merchandise")
        || nl.contains("raw material")
        || nl.contains("finished good")
        || nl.contains("work in process")
        || nl.contains("wip")
}

#[derive(Clone, Debug, Default)]
struct InventoryPosition {
    net_debit: i128,
    earliest_debit: Option<DateDay>,
    latest_credit: Option<DateDay>,
    debit_legs: Vec<(VId, u16)>,
}

impl Procedure for InventoryAging {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let stale_days = self.params.get_u32("stale_days")?;
        if stale_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "stale_days".into(),
                message: "must be >= 1".into(),
            });
        }
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| (e.entry.proposal.effective_date, e.vid));

        let as_of = snapshot
            .coordinate
            .effective_through
            .or_else(|| live.iter().map(|e| e.entry.proposal.effective_date).max());
        let Some(as_of) = as_of else {
            return Ok(Vec::new());
        };

        let mut positions: BTreeMap<(VId, u32), InventoryPosition> = BTreeMap::new();
        let mut population = 0u64;
        for e in &live {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            if eff > as_of {
                continue;
            }
            for (ordinal, leg) in e.entry.proposal.legs.iter().enumerate() {
                work.leg();
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                if !is_inventory_account(&acct.code, &acct.name, AccountType(acct.account_type)) {
                    continue;
                }
                population += 1;
                let pos = positions
                    .entry((leg.account_ref, leg.amount.unit.0))
                    .or_default();
                let mag = leg.amount.mantissa.unsigned_abs() as i128;
                match leg.side {
                    Side::Debit => {
                        pos.net_debit = pos
                            .net_debit
                            .checked_add(mag)
                            .ok_or(LanternError::Overflow("inventory debit sum"))?;
                        pos.earliest_debit = Some(match pos.earliest_debit {
                            Some(prev) if prev <= eff => prev,
                            _ => eff,
                        });
                        if pos.debit_legs.len() < MAX_CITES - 1 {
                            pos.debit_legs.push((e.vid, ordinal as u16));
                        }
                    }
                    Side::Credit => {
                        pos.net_debit = pos
                            .net_debit
                            .checked_sub(mag)
                            .ok_or(LanternError::Overflow("inventory credit sum"))?;
                        pos.latest_credit = Some(match pos.latest_credit {
                            Some(prev) if prev >= eff => prev,
                            _ => eff,
                        });
                    }
                }
            }
        }

        let mut out = Vec::new();
        for ((acct_vid, unit_id), mut pos) in positions {
            work.compare(1);
            if pos.net_debit <= 0 {
                continue;
            }
            let Some(ref_date) = pos.latest_credit.or(pos.earliest_debit) else {
                continue;
            };
            let days_stale = (as_of.0 - ref_date.0).max(0) as u32;
            if days_stale > stale_days {
                pos.debit_legs.sort_unstable();
                let mut cites = vec![Cite::Account(acct_vid)];
                for (entry, ordinal) in pos.debit_legs.into_iter().take(MAX_CITES - 1) {
                    cites.push(Cite::Leg { entry, ordinal });
                }
                let code = snapshot
                    .accounts
                    .get(&acct_vid)
                    .map_or("?", |a| a.code.as_str());
                let scale = crate::unit_scale(book, unit_id)?;
                let severity = if days_stale >= stale_days.saturating_mul(2) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic {
                        name: "stale_inventory_balance".into(),
                        value: pos.net_debit,
                        scale,
                        population,
                    },
                    cites,
                    format!(
                        "inventory account {code} carries net debit {} in unit {unit_id} with {days_stale} day(s) since last relief movement (threshold {stale_days})",
                        pos.net_debit
                    ),
                ));
            }
        }
        Ok(out)
    }
}
