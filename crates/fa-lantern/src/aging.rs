//! Aging (plan §11.7): open items from fa-registers' settlement fold,
//! bucketed by days from the item's effective date to a declared `as_of`
//! date, per account and unit. The date is an input the caller declares;
//! a procedure never reads a clock.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_time::DateDay;
use fgdb_types::VId;

use crate::jet::finding;
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
};

/// `aging.open_items`.
pub struct OpenItemsAging {
    params: Params,
    as_of: DateDay,
}

impl OpenItemsAging {
    pub const ID: &'static str = "aging.open_items";

    /// With the registry's pinned bucket edges, aged to `as_of`.
    pub fn new(as_of: DateDay) -> Result<Self, LanternError> {
        Ok(Self {
            params: Params::defaults(Self::ID)?,
            as_of,
        })
    }

    #[must_use]
    pub fn with(params: Params, as_of: DateDay) -> Self {
        Self { params, as_of }
    }
}

/// One account's open amount per bucket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Buckets {
    totals: [i128; 4],
    oldest: Vec<(VId, u16)>,
    items: u64,
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
    fn inputs(&self) -> Vec<(String, String)> {
        vec![(
            "as_of".into(),
            format!(
                "{:04}-{:02}-{:02}",
                self.as_of.year(),
                self.as_of.month(),
                self.as_of.day()
            ),
        )]
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
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
        let mut per_account: BTreeMap<(u128, u32), Buckets> = BTreeMap::new();
        let mut population = 0u64;
        for item in snapshot.open_items.iter().filter(|i| i.open != 0) {
            work.leg();
            population += 1;
            let age = (self.as_of.0 - item.effective_date.0).max(0) as u32;
            let bucket = edges.iter().position(|edge| age <= *edge).unwrap_or(3);
            let b = per_account
                .entry((item.account.0, item.unit_id))
                .or_default();
            b.totals[bucket] = b.totals[bucket]
                .checked_add(item.open)
                .ok_or(LanternError::Overflow("aging bucket"))?;
            b.items += 1;
            if bucket == 3 && b.oldest.len() < MAX_CITES - 1 {
                b.oldest.push((item.entry, item.ordinal));
            }
        }
        let mut out = Vec::new();
        for ((account, unit_id), b) in per_account {
            let total: i128 = b
                .totals
                .iter()
                .try_fold(0i128, |acc, t| acc.checked_add(*t))
                .ok_or(LanternError::Overflow("aging total"))?;
            let past = b.totals[3];
            let severity = if past == 0 {
                Severity::Info
            } else if past.unsigned_abs().saturating_mul(2) >= total.unsigned_abs() {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut cites = vec![Cite::Account(VId(account))];
            let mut oldest = b.oldest;
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
                    scale: 0,
                    population,
                },
                cites,
                format!(
                    "unit {unit_id}: {} open item(s); buckets 0..={}: {}, ..={}: {}, ..={}: {}, older: {} (mantissas)",
                    b.items, edges[0], b.totals[0], edges[1], b.totals[1], edges[2], b.totals[2], past
                ),
            ));
        }
        Ok(out)
    }
}
