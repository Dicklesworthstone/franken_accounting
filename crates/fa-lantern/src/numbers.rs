//! Number sequences (plan §11.3): gaps in the numeric tail of external ids,
//! per system and prefix — the completeness assertion's mechanical half.
//! External ids are erasable; the finding cites the two entries bounding a
//! gap and reports its size, never the ids themselves.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fgdb_types::VId;

use crate::jet::{finding, procedure_boilerplate};
use crate::{Cite, Finding, LanternError, Params, Procedure, Severity, Snapshot, Statistic, Work};

/// The most bytes an external id is opened to.
pub const MAX_EXTERNAL_ID_BYTES: usize = 256;

/// Split `id` into its non-numeric prefix and its numeric tail (at most 18
/// digits, so it fits a `u64`); `None` when there is no tail or it is too
/// long.
#[must_use]
pub fn split_sequence(id: &str) -> Option<(&str, u64)> {
    let tail_start = id
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_digit())
        .last()
        .map(|(i, _)| i)?;
    let (prefix, digits) = id.split_at(tail_start);
    if digits.len() > 18 {
        return None;
    }
    digits.parse().ok().map(|n| (prefix, n))
}

/// `numbers.sequence_gaps`.
pub struct SequenceGaps {
    params: Params,
}
procedure_boilerplate!(SequenceGaps, "numbers.sequence_gaps");

impl Procedure for SequenceGaps {
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
        let mut sequences: BTreeMap<(String, String), Vec<(u64, VId)>> = BTreeMap::new();
        let mut population = 0u64;
        for e in snapshot.live_postings()? {
            work.entry();
            for ext in &e.entry.proposal.external_ids {
                let Ok(id) = ext.id.open(&book.seal_key, MAX_EXTERNAL_ID_BYTES) else {
                    continue;
                };
                let Some((prefix, number)) = split_sequence(&id) else {
                    continue;
                };
                population += 1;
                sequences
                    .entry((ext.system.clone(), prefix.to_string()))
                    .or_default()
                    .push((number, e.vid));
            }
        }
        let mut out = Vec::new();
        for ((system, _), list) in sequences.iter_mut() {
            list.sort_unstable();
            work.compare(list.len() as u64);
            for pair in list.windows(2) {
                let (prev, next) = (pair[0], pair[1]);
                let missing = next.0.saturating_sub(prev.0).saturating_sub(1);
                if missing == 0 {
                    continue;
                }
                let mut cites = vec![prev.1, next.1];
                cites.sort_unstable();
                cites.dedup();
                out.push(finding(
                    Self::ID,
                    if missing <= 2 {
                        Severity::Low
                    } else {
                        Severity::Medium
                    },
                    Statistic::count("missing_numbers", missing, population),
                    cites.into_iter().map(Cite::Entry).collect(),
                    format!(
                        "system `{system}`: {missing} number(s) missing between two cited entries"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `numbers.relative_size_factor`: ratio of the largest to the second-largest
/// live debit leg magnitude per party (or account) and unit (Nigrini RSF).
pub struct RelativeSizeFactor {
    params: Params,
}
procedure_boilerplate!(RelativeSizeFactor, "numbers.relative_size_factor");

impl Procedure for RelativeSizeFactor {
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
        _book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let min_rsf_bps = i128::from(self.params.get_u32("min_rsf_bps")?);
        let min_subset_size = self.params.get_u32("min_subset_size")? as usize;
        if min_subset_size < 2 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "min_subset_size".into(),
                message: "must be at least 2".into(),
            });
        }
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let mut groups: BTreeMap<(u8, u128, fa_money::UnitId), Vec<(i128, VId)>> = BTreeMap::new();
        let mut population = 0u64;
        for e in &live {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                if leg.side != fa_money::Side::Debit || leg.amount.mantissa <= 0 {
                    continue;
                }
                population += 1;
                let party_val = leg
                    .dimension_set
                    .iter()
                    .find(|(d, _)| *d == fa_model::PARTY_DIMENSION)
                    .map(|(_, v)| v.0);
                let key = match party_val {
                    Some(p) => (1u8, p, leg.amount.unit),
                    None => (0u8, leg.account_ref.0, leg.amount.unit),
                };
                groups
                    .entry(key)
                    .or_default()
                    .push((leg.amount.mantissa, e.vid));
            }
        }
        let mut out = Vec::new();
        for ((kind, id_raw, _unit), mut list) in groups {
            work.compare(list.len() as u64);
            if list.len() < min_subset_size {
                continue;
            }
            list.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            let (top_mag, top_vid) = list[0];
            let (second_mag, second_vid) = list[1];
            if second_mag <= 0 {
                continue;
            }
            let rsf_bps = top_mag
                .checked_mul(10_000)
                .ok_or(LanternError::Overflow("rsf numerator"))?
                / second_mag;
            if rsf_bps >= min_rsf_bps {
                let mut cites = vec![Cite::Entry(top_vid)];
                if second_vid != top_vid {
                    cites.push(Cite::Entry(second_vid));
                }
                if kind == 0 && snapshot.accounts.contains_key(&VId(id_raw)) {
                    cites.push(Cite::Account(VId(id_raw)));
                }
                let severity = if rsf_bps >= min_rsf_bps.saturating_mul(2) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic {
                        name: "rsf_bps".into(),
                        value: rsf_bps,
                        scale: 0,
                        population,
                    },
                    cites,
                    format!(
                        "largest debit {top_mag} vs second-largest {second_mag} across {} postings yields RSF {rsf_bps} bps (min_rsf_bps {min_rsf_bps})",
                        list.len()
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `numbers.threshold_splitting`: regulatory and approval threshold splitting
/// (including 31 CFR 1010.311 $10,000.00 USD CTR rule).
pub struct ThresholdSplitting {
    params: Params,
}
procedure_boilerplate!(ThresholdSplitting, "numbers.threshold_splitting");

impl Procedure for ThresholdSplitting {
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
        let threshold = self.params.get("threshold")?;
        let floor = self.params.get("floor")?;
        if floor <= 0 || floor >= threshold {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "floor".into(),
                message: "must be positive and strictly below threshold".into(),
            });
        }
        let window_days = i32::try_from(self.params.get_u32("window_days")?)
            .map_err(|_| LanternError::Overflow("window_days"))?;
        let min_count = self.params.get_u32("min_count")? as usize;
        if min_count < 2 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "min_count".into(),
                message: "must be at least 2".into(),
            });
        }
        let currency = u16::try_from(self.params.get_u32("currency_iso4217")?).map_err(|_| {
            LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be in 1..=999".into(),
            }
        })?;
        if !(1..=999).contains(&currency) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be in 1..=999".into(),
            });
        }
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| (e.entry.proposal.effective_date, e.vid));
        let population = live.len() as u64;
        let mut by_key: BTreeMap<(u8, u128, u128, u8), Vec<(fa_time::DateDay, i128, VId)>> =
            BTreeMap::new();
        for e in &live {
            work.entry();
            let mut total_debit = 0i128;
            let mut scale = 2u8;
            let mut party_dim: Option<u128> = None;
            let mut accts: Vec<u128> = Vec::new();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(unit) = book.units.get(leg.amount.unit) else {
                    continue;
                };
                if !matches!(unit.kind, fa_money::UnitKind::Currency { iso4217 } if iso4217 == currency)
                {
                    continue;
                }
                scale = unit.scale;
                if let Some((_, v)) = leg
                    .dimension_set
                    .iter()
                    .find(|(d, _)| *d == fa_model::PARTY_DIMENSION)
                {
                    party_dim = Some(v.0);
                }
                accts.push(leg.account_ref.0);
                if leg.side == fa_money::Side::Debit {
                    total_debit = total_debit
                        .checked_add(leg.amount.mantissa)
                        .ok_or(LanternError::Overflow("threshold_splitting debit sum"))?;
                }
            }
            if total_debit >= floor && total_debit < threshold {
                accts.sort_unstable();
                accts.dedup();
                let key = match party_dim {
                    Some(p) => (1u8, p, 0u128, scale),
                    None => {
                        let a0 = accts.first().copied().unwrap_or(0);
                        let a1 = accts.last().copied().unwrap_or(0);
                        (0u8, a0, a1, scale)
                    }
                };
                by_key
                    .entry(key)
                    .or_default()
                    .push((e.entry.proposal.effective_date, total_debit, e.vid));
            }
        }
        let mut out = Vec::new();
        for ((_kind, _k0, _k1, scale), list) in by_key {
            work.compare(list.len() as u64);
            if list.len() < min_count {
                continue;
            }
            let mut i = 0;
            while i < list.len() {
                let start_date = list[i].0;
                let mut j = i;
                let mut sum = 0i128;
                let mut vids = Vec::new();
                while j < list.len() && (list[j].0.0 - start_date.0) <= window_days {
                    sum = sum
                        .checked_add(list[j].1)
                        .ok_or(LanternError::Overflow("split window sum"))?;
                    vids.push(list[j].2);
                    j += 1;
                }
                if vids.len() >= min_count && sum >= threshold {
                    vids.sort_unstable();
                    vids.dedup();
                    out.push(finding(
                        Self::ID,
                        Severity::High,
                        Statistic {
                            name: "split_total".into(),
                            value: sum,
                            scale,
                            population,
                        },
                        vids.iter().copied().map(Cite::Entry).collect(),
                        format!(
                            "{} sub-threshold postings in [{floor}, {threshold}) within {window_days} day(s) sum to {sum} (>= threshold {threshold}; 31 CFR 1010.311 CTR / threshold rule)",
                            vids.len()
                        ),
                    ));
                    i = j;
                } else {
                    i += 1;
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::split_sequence;

    #[test]
    fn sequences_split_at_the_numeric_tail() {
        assert_eq!(split_sequence("INV-000123"), Some(("INV-", 123)));
        assert_eq!(split_sequence("7"), Some(("", 7)));
        assert_eq!(split_sequence("INV-"), None);
        assert_eq!(split_sequence(""), None);
        assert_eq!(split_sequence("A1B"), None);
        assert_eq!(split_sequence("X9999999999999999999"), None, "19 digits");
    }
}
