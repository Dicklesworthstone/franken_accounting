//! Cutoff, reconciliation, completeness, and audit procedures (plan §11.4, §11.7;
//! beads fa-nlu, fa-g6rj).

mod reconciliation_arithmetic;

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::attestation::{AttestationClaim, review_vid};
use fa_journal::genesis::BookContext;
use fa_model::rea::SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS;
use fa_model::{AccountType, ControlPayload, EntryClass, PartyIdentifierUpdate};
use fa_money::Side;
use fa_time::{DateDay, Weekday};
use fgdb_types::VId;

use crate::amount::{
    amount_difference, amount_magnitude, amount_negated, amount_scaled_bps, amount_share_bps,
    amount_sum, largest_remainder, ratio_cmp, signed_leg, wide_product,
};
use crate::jet::{finding, procedure_boilerplate};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
};

/// `cutoff.period_boundary`.
pub struct PeriodBoundary {
    params: Params,
}
procedure_boilerplate!(PeriodBoundary, "cutoff.period_boundary");

impl Procedure for PeriodBoundary {
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
        let mut population = 0u64;
        let mut hits = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry();
            let Some(document_date) = e.entry.proposal.document_date else {
                continue;
            };
            population += 1;
            let document_period = snapshot.document_period_code_of(
                book,
                document_date,
                e.entry
                    .proposal
                    .effective_period
                    .as_ref()
                    .map(|p| p.code.as_str()),
            )?;
            if document_period != e.period {
                let days = (document_date.0 - e.entry.proposal.effective_date.0).unsigned_abs();
                hits.push((e.vid, e.period.clone(), document_period, days));
            }
        }
        Ok(hits
            .into_iter()
            .map(|(vid, effective_period, document_period, days)| {
                let mut cites = vec![Cite::Entry(vid), Cite::Period(effective_period.clone())];
                // The document's period is cited only when the calendar has
                // generated it; otherwise it is named in the narrative only.
                if snapshot.periods.contains_key(&document_period) {
                    cites.push(Cite::Period(document_period.clone()));
                }
                finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic::count("days_between_dates", u64::from(days), population),
                    cites,
                    format!(
                        "document dated in period {document_period}, effective in period {effective_period}, {days} day(s) apart"
                    ),
                )
            })
            .collect())
    }
}

fn is_ic_account(code: &str, name: &str) -> bool {
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl.starts_with("ic")
        || nl.contains("intercompany")
        || nl.contains("due to")
        || nl.contains("due from")
}

/// `recon.intercompany` (plan §11.4, `FA-EVID-L41`, `claim = "invariant"`):
/// exact intercompany reciprocal balance reconciliation across legal entities
/// and intercompany accounts per period and unit. Any non-zero net reciprocal
/// imbalance is an invariant violation.
pub struct ReconIntercompany {
    params: Params,
}
procedure_boilerplate!(ReconIntercompany, "recon.intercompany");

impl Procedure for ReconIntercompany {
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
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);

        // Key: (period, unit_id) -> (signed_net, BTreeSet<Account VId>, BTreeSet<Entry VId>)
        type Bucket = (i128, BTreeSet<VId>, BTreeSet<VId>);
        let mut buckets: BTreeMap<(String, u32), Bucket> = BTreeMap::new();
        let mut population = 0u64;

        for e in &live {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                if !is_ic_account(&acct.code, &acct.name) {
                    continue;
                }
                population += 1;
                let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                let b = buckets
                    .entry((e.period.clone(), leg.amount.unit.0))
                    .or_default();
                b.0 =
                    b.0.checked_add(signed)
                        .ok_or(LanternError::Overflow("intercompany balance sum"))?;
                b.1.insert(leg.account_ref);
                b.2.insert(e.vid);
            }
        }

        let mut out = Vec::new();
        for ((period, unit_id), (net, accts, entries)) in buckets {
            work.compare(1);
            if net == 0 {
                continue;
            }
            let mut cites: Vec<Cite> = accts.into_iter().map(Cite::Account).collect();
            if snapshot.periods.contains_key(&period) {
                cites.push(Cite::Period(period.clone()));
            }
            for evid in entries {
                if cites.len() < MAX_CITES {
                    cites.push(Cite::Entry(evid));
                }
            }
            let scale = crate::unit_scale(book, unit_id)?;
            let mag = reconciliation_arithmetic::discrepancy(net, 0)
                .ok_or(LanternError::Overflow("intercompany imbalance magnitude"))?;
            out.push(finding(
                Self::ID,
                Severity::Critical,
                Statistic {
                    name: "intercompany_imbalance".into(),
                    value: mag,
                    scale,
                    population,
                },
                cites,
                format!(
                    "intercompany reciprocal balance in period {period} unit {unit_id} is out of balance by signed net {net}"
                ),
            ));
        }
        Ok(out)
    }
}

/// `recon.lapping` (plan §11.4, `FA-EVID-L42`): receivables/payables lapping
/// detector. Flags sequential settlements on a control or receivable/payable
/// account where party B's receipt/credit is recorded within `window_days` of
/// party A's open item while party A's settlement is delayed and applied after
/// party B's receipt.
pub struct ReconLapping {
    params: Params,
}
procedure_boilerplate!(ReconLapping, "recon.lapping");

fn is_ar_ap_account(code: &str, name: &str) -> bool {
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl.starts_with("11")
        || cl.starts_with("12")
        || cl.starts_with("20")
        || nl.contains("receivable")
        || nl.contains("payable")
}

impl Procedure for ReconLapping {
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
        let window_days = self.params.get_u32("window_days")?;
        if window_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "window_days".into(),
                message: "must be >= 1".into(),
            });
        }

        let mut pval_to_party: BTreeMap<VId, VId> = BTreeMap::new();
        for p in snapshot.rea.parties.values() {
            pval_to_party.insert(p.dimension_value_vid, p.vid);
            pval_to_party.insert(p.vid, p.vid);
        }

        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| (e.entry.proposal.effective_date, e.vid));

        // Track per (account_vid, unit_id): sequence of (effective_date, entry_vid, side, party_vid, mag)
        #[derive(Clone, Copy)]
        struct ControlMovement {
            date: DateDay,
            entry: VId,
            side: Side,
            party: VId,
            mag: i128,
        }
        let mut streams: BTreeMap<(VId, u32), Vec<ControlMovement>> = BTreeMap::new();
        let mut population = 0u64;

        for e in &live {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                if !is_ar_ap_account(&acct.code, &acct.name) {
                    continue;
                }
                let party = leg
                    .dimension_set
                    .iter()
                    .find_map(|(_, d)| pval_to_party.get(d).copied());
                let Some(party) = party else {
                    continue;
                };
                population += 1;
                streams
                    .entry((leg.account_ref, leg.amount.unit.0))
                    .or_default()
                    .push(ControlMovement {
                        date: eff,
                        entry: e.vid,
                        side: leg.side,
                        party,
                        mag: leg.amount.mantissa.unsigned_abs() as i128,
                    });
            }
        }

        let mut out = Vec::new();
        let mut seen_triples: BTreeSet<(VId, VId, VId)> = BTreeSet::new();
        for ((acct_vid, _unit_id), movs) in &streams {
            // Look for lapping wave:
            // 1) Party A debit (invoice) at index i
            // 2) Party B (B != A) credit (cash receipt) at index j > i within window_days
            // 3) Party A credit (delayed settlement of A's invoice) at index k > j within window_days of j
            for i in 0..movs.len() {
                work.compare(1);
                if movs[i].side != Side::Debit {
                    continue;
                }
                let a = movs[i];
                for j in (i + 1)..movs.len() {
                    if (movs[j].date.0 - a.date.0) > window_days as i32 {
                        break;
                    }
                    if movs[j].side != Side::Credit || movs[j].party == a.party {
                        continue;
                    }
                    let b = movs[j];
                    for mov_k in movs.iter().skip(j + 1) {
                        if (mov_k.date.0 - b.date.0) > window_days as i32 {
                            break;
                        }
                        if mov_k.side == Side::Credit
                            && mov_k.party == a.party
                            && mov_k.date > b.date
                            && mov_k.mag == a.mag
                        {
                            let triple = (a.entry, b.entry, mov_k.entry);
                            if seen_triples.insert(triple) {
                                let delay_days = (mov_k.date.0 - a.date.0).max(1) as u64;
                                let mut cites = vec![
                                    Cite::Account(*acct_vid),
                                    Cite::Entry(a.entry),
                                    Cite::Entry(b.entry),
                                    Cite::Entry(mov_k.entry),
                                ];
                                cites.dedup();
                                let code = snapshot
                                    .accounts
                                    .get(acct_vid)
                                    .map_or("?", |ac| ac.code.as_str());
                                out.push(finding(
                                    Self::ID,
                                    Severity::High,
                                    Statistic::count("settlement_delay_days", delay_days, population),
                                    cites,
                                    format!(
                                        "control account {code}: party open item settled {delay_days} day(s) after creation following an intervening credit from another party"
                                    ),
                                ));
                            }
                            break;
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

/// `recon.book_to_book` (plan §11.4, `FA-EVID-L43`, `claim = "invariant"`):
/// exact reconciliation between `RegisterEquals` attestations / mirrored
/// `Instrument` vertices and the posted journal fold at the snapshot coordinate.
pub struct ReconBookToBook {
    params: Params,
}
procedure_boilerplate!(ReconBookToBook, "recon.book_to_book");

impl Procedure for ReconBookToBook {
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
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);

        // Map entity code -> dimension_value_vid
        let mut entity_code_to_dvid: BTreeMap<String, VId> = BTreeMap::new();
        for le in snapshot.rea.legal_entities.values() {
            entity_code_to_dvid.insert(le.code.clone(), le.dimension_value_vid);
        }

        let mut out = Vec::new();
        let population = (snapshot.attestations.len() + snapshot.rea.instruments.len()) as u64;

        // 1. Check every stored RegisterEquals attestation against the posted journal fold
        for att in snapshot.attestations.values() {
            work.compare(1);
            let AttestationClaim::RegisterEquals(claim) = &att.attestation.claim else {
                continue;
            };
            let entity_dvid = claim
                .entity
                .as_ref()
                .and_then(|c| entity_code_to_dvid.get(c).copied());
            let mut fold_net = 0i128;
            let mut matching_entries = Vec::new();
            for e in &live {
                if e.period != claim.period
                    || e.entry.proposal.effective_date > claim.as_of_effective
                {
                    continue;
                }
                for leg in &e.entry.proposal.legs {
                    if leg.account_ref != claim.account || leg.amount.unit.0 != claim.unit_id {
                        continue;
                    }
                    if let Some(req_dvid) = entity_dvid
                        && !leg.dimension_set.iter().any(|(_, d)| *d == req_dvid)
                    {
                        continue;
                    }
                    let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                    fold_net = fold_net
                        .checked_add(signed)
                        .ok_or(LanternError::Overflow("book_to_book fold sum"))?;
                    matching_entries.push(e.vid);
                }
            }
            if fold_net != claim.mantissa {
                let diff = reconciliation_arithmetic::discrepancy(fold_net, claim.mantissa)
                    .ok_or(LanternError::Overflow("book_to_book discrepancy magnitude"))?;
                let mut cites = vec![Cite::Account(claim.account)];
                if snapshot.periods.contains_key(&claim.period) {
                    cites.push(Cite::Period(claim.period.clone()));
                }
                matching_entries.sort_unstable();
                matching_entries.dedup();
                for evid in matching_entries.into_iter().take(MAX_CITES - 2) {
                    cites.push(Cite::Entry(evid));
                }
                let scale = crate::unit_scale(book, claim.unit_id)?;
                let code = snapshot
                    .accounts
                    .get(&claim.account)
                    .map_or("?", |a| a.code.as_str());
                out.push(finding(
                    Self::ID,
                    Severity::Critical,
                    Statistic {
                        name: "book_to_book_discrepancy".into(),
                        value: diff,
                        scale,
                        population: population.max(1),
                    },
                    cites,
                    format!(
                        "account {code} period {} unit {}: RegisterEquals attested {} but posted journal fold is {fold_net} (discrepancy {diff})",
                        claim.period, claim.unit_id, claim.mantissa
                    ),
                ));
            }
        }

        // 2. Check every Instrument vertex mirroring an account for unit consistency
        for inst in snapshot.rea.instruments.values() {
            work.compare(1);
            let mut mismatched_entries = Vec::new();
            for e in &live {
                for leg in &e.entry.proposal.legs {
                    if leg.account_ref == inst.mirrors_account && leg.amount.unit != inst.unit {
                        mismatched_entries.push(e.vid);
                    }
                }
            }
            if !mismatched_entries.is_empty() {
                mismatched_entries.sort_unstable();
                mismatched_entries.dedup();
                let count = mismatched_entries.len() as u64;
                let mut cites = vec![Cite::Account(inst.mirrors_account)];
                for evid in mismatched_entries.into_iter().take(MAX_CITES - 1) {
                    cites.push(Cite::Entry(evid));
                }
                out.push(finding(
                    Self::ID,
                    Severity::Critical,
                    Statistic::count("instrument_unit_mismatch_entries", count, population.max(1)),
                    cites,
                    format!(
                        "instrument {} mirrors account in unit {}, but {count} posting(s) use a different unit",
                        inst.code, inst.unit.0
                    ),
                ));
            }
        }

        Ok(out)
    }
}

/// `completeness.unrecorded_liabilities` (plan §11.7, `FA-EVID-L44`, AU-C 500 / ISA 500):
/// cash disbursements or payable/expense entries recorded in a subsequent period
/// within `window_days` whose document date lies in an earlier period.
pub struct UnrecordedLiabilities {
    params: Params,
}
procedure_boilerplate!(UnrecordedLiabilities, "completeness.unrecorded_liabilities");

impl Procedure for UnrecordedLiabilities {
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
        let window_days = self.params.get_u32("window_days")?;
        if window_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "window_days".into(),
                message: "must be >= 1".into(),
            });
        }
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let population = live.len() as u64;
        let mut out = Vec::new();

        for e in &live {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            let Some(doc_date) = e.entry.proposal.document_date else {
                continue;
            };
            if doc_date >= eff {
                continue;
            }
            let lag_days = (eff.0 - doc_date.0) as u32;
            if lag_days > window_days {
                continue;
            }
            let doc_period = snapshot.document_period_code_of(
                book,
                doc_date,
                e.entry
                    .proposal
                    .effective_period
                    .as_ref()
                    .map(|p| p.code.as_str()),
            )?;
            if doc_period == e.period {
                continue;
            }
            // Must touch an expense or liability account (or credit cash for an obligation)
            let mut max_expense_or_liab: Option<(u32, i128, VId)> = None;
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                if matches!(
                    AccountType(acct.account_type),
                    AccountType::EXPENSE | AccountType::LIABILITY
                ) {
                    let mag = leg.amount.mantissa.unsigned_abs() as i128;
                    if max_expense_or_liab.is_none_or(|(_, m, _)| mag > m) {
                        max_expense_or_liab = Some((leg.amount.unit.0, mag, leg.account_ref));
                    }
                }
            }
            let Some((unit_id, mag, acct_vid)) = max_expense_or_liab else {
                continue;
            };
            let mut cites = vec![
                Cite::Entry(e.vid),
                Cite::Account(acct_vid),
                Cite::Period(e.period.clone()),
            ];
            if snapshot.periods.contains_key(&doc_period) {
                cites.push(Cite::Period(doc_period.clone()));
            }
            let scale = crate::unit_scale(book, unit_id)?;
            out.push(finding(
                Self::ID,
                Severity::High,
                Statistic {
                    name: "unrecorded_liability_amount".into(),
                    value: mag,
                    scale,
                    population,
                },
                cites,
                format!(
                    "obligation dated in prior period {doc_period} recorded in subsequent period {} ({lag_days} day(s) later, amount {mag})",
                    e.period
                ),
            ));
        }
        Ok(out)
    }
}

/// `events.subsequent` (plan §11.7, `FA-EVID-L45`, AS 2801 / IAS 10):
/// material postings, reversals, or restatements effective within `window_days`
/// after a closed or soft-closed period boundary (or superseding an entry in an
/// earlier period).
pub struct SubsequentEvents {
    params: Params,
}
procedure_boilerplate!(SubsequentEvents, "events.subsequent");

impl Procedure for SubsequentEvents {
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
        let window_days = self.params.get_u32("window_days")?;
        if window_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "window_days".into(),
                message: "must be >= 1".into(),
            });
        }
        let min_amount = self.params.get("min_amount")?;
        if min_amount < 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "min_amount".into(),
                message: "must be >= 0".into(),
            });
        }

        // Index all entries by vid for prior-period supersession lookup
        let mut by_vid: BTreeMap<VId, &crate::SnapshotEntry> = BTreeMap::new();
        for e in &snapshot.entries {
            by_vid.insert(e.vid, e);
        }

        // Identify closed/soft-closed periods and their end dates
        let mut closed_periods: Vec<(String, DateDay)> = Vec::new();
        for (pcode, trs) in &snapshot.transitions {
            if !trs.is_empty()
                && let Some(p) = snapshot.periods.get(pcode)
            {
                closed_periods.push((pcode.clone(), p.end));
            }
        }
        closed_periods.sort_by(|a, b| a.0.cmp(&b.0));

        let mut postings: Vec<&crate::SnapshotEntry> =
            snapshot.entries.iter().filter(|e| e.posts()).collect();
        postings.sort_by_key(|e| e.vid);
        let population = postings.len() as u64;
        let mut out = Vec::new();

        for e in &postings {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            let mut max_leg: Option<(u32, i128)> = None;
            for leg in &e.entry.proposal.legs {
                work.leg();
                let mag = leg.amount.mantissa.unsigned_abs() as i128;
                if max_leg.is_none_or(|(_, m)| mag > m) {
                    max_leg = Some((leg.amount.unit.0, mag));
                }
            }
            let Some((unit_id, mag)) = max_leg else {
                continue;
            };
            if mag < min_amount {
                continue;
            }

            let prior_superseded = e
                .entry
                .proposal
                .supersession
                .iter()
                .find_map(|s| by_vid.get(&s.target.vid).copied())
                .filter(|orig| orig.period != e.period);

            let is_subsequent_class = matches!(
                e.entry.proposal.class,
                EntryClass::REVERSAL
                    | EntryClass::REPLACEMENT
                    | EntryClass::RESTATEMENT
                    | EntryClass::PRIOR_PERIOD_ADJUSTMENT
                    | EntryClass::ADJUSTING
            );

            let mut matched_closed_period: Option<(String, u32)> = None;
            if let Some(orig) = prior_superseded {
                let days = (eff.0 - orig.entry.proposal.effective_date.0).unsigned_abs();
                if days <= window_days {
                    matched_closed_period = Some((orig.period.clone(), days));
                }
            }
            if matched_closed_period.is_none() && is_subsequent_class {
                for (pcode, pend) in &closed_periods {
                    if *pcode != e.period && eff > *pend {
                        let days = (eff.0 - pend.0) as u32;
                        if days <= window_days {
                            matched_closed_period = Some((pcode.clone(), days));
                            break;
                        }
                    }
                }
            }

            if let Some((prior_period, days)) = matched_closed_period {
                let mut cites = vec![Cite::Entry(e.vid), Cite::Period(e.period.clone())];
                if snapshot.periods.contains_key(&prior_period) && prior_period != e.period {
                    cites.push(Cite::Period(prior_period.clone()));
                }
                if let Some(orig) = prior_superseded {
                    cites.push(Cite::Entry(orig.vid));
                }
                let scale = crate::unit_scale(book, unit_id)?;
                out.push(finding(
                    Self::ID,
                    Severity::High,
                    Statistic {
                        name: "subsequent_event_amount".into(),
                        value: mag,
                        scale,
                        population,
                    },
                    cites,
                    format!(
                        "subsequent event in period {} ({days} day(s) after prior period {prior_period}) of magnitude {mag}",
                        e.period
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `party.master_changes` (plan §11.7, `FA-EVID-L46`): vendor/party master-data
/// changes (`UpdatePartyIdentifiers` schema controls) followed by postings to
/// that party within `window_commits` commits.
pub struct PartyMasterChanges {
    params: Params,
}
procedure_boilerplate!(PartyMasterChanges, "party.master_changes");

impl Procedure for PartyMasterChanges {
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
        let window_commits = self.params.get_u32("window_commits")?;
        if window_commits == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "window_commits".into(),
                message: "must be >= 1".into(),
            });
        }

        // Collect all UpdatePartyIdentifiers schema controls
        let mut updates: Vec<(VId, u64, String, VId, VId)> = Vec::new();
        for e in &snapshot.entries {
            work.entry();
            if let Some(ControlPayload::SchemaChange {
                kind: SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS,
                canonical_bytes,
            }) = &e.entry.proposal.control
                && let Ok(upd) = PartyIdentifierUpdate::decode(canonical_bytes)
            {
                let pvid = upd.party_vid;
                let (pval_vid, code) = snapshot.rea.parties.get(&pvid).map_or_else(
                    || (pvid, format!("{:032x}", pvid.0)),
                    |p| (p.dimension_value_vid, p.code.clone()),
                );
                updates.push((e.vid, e.recorded_at.0, code, pvid, pval_vid));
            }
        }
        updates.sort_by_key(|(vid, seq, _, _, _)| (*seq, *vid));

        if updates.is_empty() {
            return Ok(Vec::new());
        }

        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| (e.recorded_at, e.vid));
        let population = live.len() as u64;
        let mut out = Vec::new();

        for e in &live {
            for leg in &e.entry.proposal.legs {
                work.leg();
                for (ctrl_vid, ctrl_seq, code, pvid, pval_vid) in &updates {
                    work.compare(1);
                    if leg
                        .dimension_set
                        .iter()
                        .any(|(_, d)| d == pval_vid || d == pvid)
                        && e.recorded_at.0 >= *ctrl_seq
                        && e.recorded_at.0 - *ctrl_seq <= u64::from(window_commits)
                    {
                        let dist = e.recorded_at.0 - *ctrl_seq;
                        let mut cites = vec![Cite::Entry(e.vid), Cite::Entry(*ctrl_vid)];
                        if snapshot.rea.parties.contains_key(pvid) {
                            cites.push(Cite::Principal(*pvid));
                        }
                        out.push(finding(
                            Self::ID,
                            Severity::High,
                            Statistic::count("commits_after_master_change", dist, population),
                            cites,
                            format!(
                                "posting to party {code} recorded {dist} commit(s) after party identifier change"
                            ),
                        ));
                    }
                }
            }
        }
        Ok(out)
    }
}

/// `payroll.ghost` (plan §11.7, `FA-EVID-L47`, `calibration = "corpus"`):
/// ghost-employee and anomalous payroll detector. Flags payroll postings that:
/// (1) share an identical disbursement amount with another payroll posting in
///     the same period,
/// (2) pay a party whose bank or tax identifier is shared with another party, or
/// (3) occur off-cycle on a weekend or under self-approval.
pub struct PayrollGhost {
    params: Params,
}
procedure_boilerplate!(PayrollGhost, "payroll.ghost");

fn is_payroll_account(code: &str, name: &str) -> bool {
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl == "1050"
        || cl == "2200"
        || cl == "6300"
        || nl.contains("payroll")
        || nl.contains("wage")
        || nl.contains("salary")
        || nl.contains("salaries")
}

impl Procedure for PayrollGhost {
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
        // Identify parties that share an opened identifier (e.g. bank_account, tax_id)
        let mut id_to_parties: BTreeMap<(String, String), BTreeSet<VId>> = BTreeMap::new();
        let mut pval_to_party: BTreeMap<VId, VId> = BTreeMap::new();
        for p in snapshot.rea.parties.values() {
            pval_to_party.insert(p.dimension_value_vid, p.vid);
            pval_to_party.insert(p.vid, p.vid);
            for (k, v) in &p.identifiers {
                if let Ok(val) = v.open(&book.seal_key, 256) {
                    let norm = val.trim().to_ascii_uppercase();
                    if !norm.is_empty() {
                        id_to_parties
                            .entry((k.to_ascii_lowercase(), norm))
                            .or_default()
                            .insert(p.vid);
                    }
                }
            }
        }
        let shared_id_parties: BTreeSet<VId> = id_to_parties
            .values()
            .filter(|set| set.len() >= 2)
            .flat_map(|set| set.iter().copied())
            .collect();

        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);

        #[derive(Clone)]
        struct PayrollEntryInfo {
            vid: VId,
            period: String,
            date: DateDay,
            unit_id: u32,
            mag: i128,
            party: Option<VId>,
            weekend_or_self_approved: bool,
        }

        let mut payroll_entries: Vec<PayrollEntryInfo> = Vec::new();
        for e in &live {
            work.entry();
            let mut is_payroll = e
                .entry
                .proposal
                .external_ids
                .iter()
                .any(|x| x.system.to_ascii_lowercase().contains("payroll"));
            let mut max_leg: Option<(u32, i128)> = None;
            let mut party: Option<VId> = None;
            for leg in &e.entry.proposal.legs {
                work.leg();
                if let Some(acct) = snapshot.accounts.get(&leg.account_ref)
                    && is_payroll_account(&acct.code, &acct.name)
                {
                    is_payroll = true;
                }
                let mag = leg.amount.mantissa.unsigned_abs() as i128;
                if max_leg.is_none_or(|(_, m)| mag > m) {
                    max_leg = Some((leg.amount.unit.0, mag));
                }
                if party.is_none() {
                    party = leg
                        .dimension_set
                        .iter()
                        .find_map(|(_, d)| pval_to_party.get(d).copied());
                }
            }
            if !is_payroll {
                continue;
            }
            let Some((unit_id, mag)) = max_leg else {
                continue;
            };
            let eff = e.entry.proposal.effective_date;
            let is_weekend = matches!(eff.weekday(), Weekday::Saturday | Weekday::Sunday);
            let is_self_app = e
                .approvals
                .iter()
                .any(|(_, p)| *p == e.entry.proposal.principal_ref);
            payroll_entries.push(PayrollEntryInfo {
                vid: e.vid,
                period: e.period.clone(),
                date: eff,
                unit_id,
                mag,
                party,
                weekend_or_self_approved: is_weekend || is_self_app,
            });
        }

        let population = payroll_entries.len() as u64;
        if payroll_entries.is_empty() {
            return Ok(Vec::new());
        }

        // Group by (period, unit_id, mag) to find duplicate net-pay runs
        let mut by_amount: BTreeMap<(String, u32, i128), Vec<&PayrollEntryInfo>> = BTreeMap::new();
        for pe in &payroll_entries {
            by_amount
                .entry((pe.period.clone(), pe.unit_id, pe.mag))
                .or_default()
                .push(pe);
        }

        let mut flagged: BTreeSet<VId> = BTreeSet::new();
        let mut out = Vec::new();

        for ((period, unit_id, mag), group) in &by_amount {
            work.compare(1);
            if group.len() >= 2 {
                let mut cites: Vec<Cite> = group.iter().map(|pe| Cite::Entry(pe.vid)).collect();
                for pe in group {
                    flagged.insert(pe.vid);
                    if let Some(pvid) = pe.party
                        && snapshot.rea.parties.contains_key(&pvid)
                    {
                        cites.push(Cite::Principal(pvid));
                    }
                }
                cites.dedup();
                let scale = crate::unit_scale(book, *unit_id)?;
                out.push(finding(
                    Self::ID,
                    Severity::High,
                    Statistic {
                        name: "duplicate_payroll_amount".into(),
                        value: *mag,
                        scale,
                        population,
                    },
                    cites,
                    format!(
                        "{} payroll postings in period {period} share identical net pay {mag} in unit {unit_id}",
                        group.len()
                    ),
                ));
            }
        }

        for pe in &payroll_entries {
            work.compare(1);
            let has_shared_id = pe.party.is_some_and(|p| shared_id_parties.contains(&p));
            if (has_shared_id || pe.weekend_or_self_approved) && flagged.insert(pe.vid) {
                let mut cites = vec![Cite::Entry(pe.vid)];
                if let Some(pvid) = pe.party
                    && snapshot.rea.parties.contains_key(&pvid)
                {
                    cites.push(Cite::Principal(pvid));
                }
                let scale = crate::unit_scale(book, pe.unit_id)?;
                out.push(finding(
                    Self::ID,
                    Severity::High,
                    Statistic {
                        name: "anomalous_payroll_amount".into(),
                        value: pe.mag,
                        scale,
                        population,
                    },
                    cites,
                    format!(
                        "anomalous payroll disbursement on {:?} of {} in unit {} (shared identifier={}, offcycle_or_self_approved={})",
                        pe.date, pe.mag, pe.unit_id, has_shared_id, pe.weekend_or_self_approved
                    ),
                ));
            }
        }

        Ok(out)
    }
}

/// `expense.capitalization` (plan §11.7, `FA-EVID-L48`, `calibration = "corpus"`):
/// improper expense capitalization detector (WorldCom motif). Flags entries that
/// debit a fixed/capital asset account while crediting an operating expense or
/// accrued line-cost / operating cost liability account.
pub struct ExpenseCapitalization {
    params: Params,
}
procedure_boilerplate!(ExpenseCapitalization, "expense.capitalization");

fn is_capex_asset(code: &str, name: &str, account_type: AccountType) -> bool {
    if account_type != AccountType::ASSET {
        return false;
    }
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl.starts_with("15")
        || cl.starts_with("16")
        || cl.starts_with("17")
        || cl.contains("capex")
        || nl.contains("capex")
        || nl.contains("property")
        || nl.contains("plant")
        || nl.contains("equipment")
        || nl.contains("fixed asset")
        || nl.contains("capital")
}

fn is_operating_cost_credit(code: &str, name: &str, account_type: AccountType) -> bool {
    if account_type == AccountType::EXPENSE {
        return true;
    }
    if account_type == AccountType::LIABILITY {
        let cl = code.to_ascii_lowercase();
        let nl = name.to_ascii_lowercase();
        return cl == "2100"
            || nl.contains("accrued line")
            || nl.contains("line cost")
            || nl.contains("accrued expense")
            || nl.contains("accrued operating");
    }
    false
}

impl Procedure for ExpenseCapitalization {
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
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let population = live.len() as u64;
        let mut out = Vec::new();

        for e in &live {
            work.entry();
            let mut capex_debits: Vec<(VId, u32, i128)> = Vec::new();
            let mut cost_credits: Vec<VId> = Vec::new();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                let atype = AccountType(acct.account_type);
                match leg.side {
                    Side::Debit if is_capex_asset(&acct.code, &acct.name, atype) => {
                        capex_debits.push((
                            leg.account_ref,
                            leg.amount.unit.0,
                            leg.amount.mantissa.unsigned_abs() as i128,
                        ));
                    }
                    Side::Credit if is_operating_cost_credit(&acct.code, &acct.name, atype) => {
                        cost_credits.push(leg.account_ref);
                    }
                    _ => {}
                }
            }
            if !capex_debits.is_empty() && !cost_credits.is_empty() {
                capex_debits.sort_by_key(|(a, u, m)| (*a, *u, *m));
                cost_credits.sort_unstable();
                cost_credits.dedup();
                let (capex_acct, unit_id, capex_mag) = capex_debits[0];
                let mut cites = vec![Cite::Entry(e.vid), Cite::Account(capex_acct)];
                for c in &cost_credits {
                    cites.push(Cite::Account(*c));
                }
                let scale = crate::unit_scale(book, unit_id)?;
                let capex_code = snapshot
                    .accounts
                    .get(&capex_acct)
                    .map_or("?", |a| a.code.as_str());
                let credit_code = snapshot
                    .accounts
                    .get(&cost_credits[0])
                    .map_or("?", |a| a.code.as_str());
                out.push(finding(
                    Self::ID,
                    Severity::High,
                    Statistic {
                        name: "capitalized_expense_amount".into(),
                        value: capex_mag,
                        scale,
                        population,
                    },
                    cites,
                    format!(
                        "entry capitalizes {capex_mag} in unit {unit_id} by debiting capital asset {capex_code} and crediting operating cost {credit_code}"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `reversal.patterns` (plan §11.7, `FA-EVID-L50`): systematic reversal and
/// re-aging patterns (chains of Reversal/Replacement entries or cross-period
/// reversals).
pub struct ReversalPatterns {
    params: Params,
}
procedure_boilerplate!(ReversalPatterns, "reversal.patterns");

impl Procedure for ReversalPatterns {
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
        let mut by_vid: BTreeMap<VId, &crate::SnapshotEntry> = BTreeMap::new();
        let mut superseded_by_map: BTreeMap<VId, VId> = BTreeMap::new();
        for e in &snapshot.entries {
            by_vid.insert(e.vid, e);
            for s in &e.entry.proposal.supersession {
                superseded_by_map.insert(s.target.vid, e.vid);
            }
        }

        let population = snapshot.entries.len() as u64;
        let mut out = Vec::new();

        for e in &snapshot.entries {
            work.entry();
            let Some(s) = e.entry.proposal.supersession.first() else {
                continue;
            };
            let target_vid = s.target.vid;
            work.compare(1);
            let Some(orig) = by_vid.get(&target_vid).copied() else {
                continue;
            };
            let cross_period = e.period != orig.period;
            let next_vid = superseded_by_map.get(&e.vid).copied();
            let chained = !orig.entry.proposal.supersession.is_empty() || next_vid.is_some();

            if cross_period || chained {
                let mut cites = vec![Cite::Entry(e.vid), Cite::Entry(orig.vid)];
                if let Some(nvid) = next_vid {
                    cites.push(Cite::Entry(nvid));
                }
                cites.dedup();
                let pattern_len = cites.len() as u64;
                let severity = if chained {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic::count("reversal_chain_entries", pattern_len, population),
                    cites,
                    format!(
                        "reversal/replacement pattern across {pattern_len} entries (cross_period={cross_period}, chained={chained}, {} -> {})",
                        orig.period, e.period
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `confirm.coverage` (plan §11.7, `FA-EVID-L51`, AS 2310 / ISA 505):
/// external confirmation and attestation coverage over cash and receivable
/// accounts. Flags accounts whose corroborated debit share in basis points falls
/// below `min_coverage_bps`.
pub struct ConfirmCoverage {
    params: Params,
}
procedure_boilerplate!(ConfirmCoverage, "confirm.coverage");

fn is_confirmable_asset(code: &str, name: &str, account_type: AccountType) -> bool {
    if account_type != AccountType::ASSET {
        return false;
    }
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl.starts_with("10")
        || cl.starts_with("11")
        || cl.starts_with("12")
        || nl.contains("cash")
        || nl.contains("bank")
        || nl.contains("receivable")
}

impl Procedure for ConfirmCoverage {
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
        let min_coverage_bps = self.params.get("min_coverage_bps")?;
        if !(0..=10_000).contains(&min_coverage_bps) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "min_coverage_bps".into(),
                message: "must be in 0..=10000".into(),
            });
        }

        // Collect accounts/periods covered by a RegisterEquals attestation
        let mut attested_cells: BTreeSet<(VId, u32, String)> = BTreeSet::new();
        for att in snapshot.attestations.values() {
            if let AttestationClaim::RegisterEquals(c) = &att.attestation.claim {
                attested_cells.insert((c.account, c.unit_id, c.period.clone()));
            }
        }

        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);

        // Per (account_vid, unit_id): (total_debit, corroborated_debit, uncorroborated_entries)
        let mut coverage: BTreeMap<(VId, u32), (i128, i128, Vec<VId>)> = BTreeMap::new();
        let mut population = 0u64;

        for e in &live {
            work.entry();
            let entry_reviewed = e.entry.proposal.evidence.iter().any(|ev| {
                let rvid = review_vid(book.book_id, &ev.document_oid);
                snapshot.attestations.contains_key(&rvid)
            });
            for leg in &e.entry.proposal.legs {
                work.leg();
                if leg.side != Side::Debit {
                    continue;
                }
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                if !is_confirmable_asset(&acct.code, &acct.name, AccountType(acct.account_type)) {
                    continue;
                }
                population += 1;
                let mag = leg.amount.mantissa.unsigned_abs() as i128;
                let cell_attested = attested_cells.contains(&(
                    leg.account_ref,
                    leg.amount.unit.0,
                    e.period.clone(),
                ));
                let row = coverage
                    .entry((leg.account_ref, leg.amount.unit.0))
                    .or_default();
                row.0 = row
                    .0
                    .checked_add(mag)
                    .ok_or(LanternError::Overflow("confirm coverage total sum"))?;
                if entry_reviewed || cell_attested {
                    row.1 = row
                        .1
                        .checked_add(mag)
                        .ok_or(LanternError::Overflow("confirm coverage corroborated sum"))?;
                } else if row.2.len() < MAX_CITES - 1 {
                    row.2.push(e.vid);
                }
            }
        }

        let mut out = Vec::new();
        for ((acct_vid, unit_id), (total, corroborated, mut uncorroborated)) in coverage {
            work.compare(1);
            if total <= 0 {
                continue;
            }
            let cov_bps = amount_share_bps(corroborated, total, "confirm coverage bps")?;
            if cov_bps < min_coverage_bps {
                uncorroborated.sort_unstable();
                uncorroborated.dedup();
                let mut cites = vec![Cite::Account(acct_vid)];
                for evid in uncorroborated.into_iter().take(MAX_CITES - 1) {
                    cites.push(Cite::Entry(evid));
                }
                let code = snapshot
                    .accounts
                    .get(&acct_vid)
                    .map_or("?", |a| a.code.as_str());
                let unconfirmed_bps =
                    amount_difference(10_000, cov_bps, "confirm unconfirmed bps")?;
                let severity = if cov_bps
                    .checked_mul(2)
                    .is_some_and(|twice| twice < min_coverage_bps)
                {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic {
                        name: "unconfirmed_share_bps".into(),
                        value: unconfirmed_bps,
                        scale: 0,
                        population,
                    },
                    cites,
                    format!(
                        "account {code} unit {unit_id} has {cov_bps} bps corroborated coverage ({corroborated}/{total}), below threshold {min_coverage_bps} bps"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

fn is_liquid_cash_account(code: &str, name: &str, account_type: AccountType) -> bool {
    if account_type != AccountType::ASSET {
        return false;
    }
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl.starts_with("10")
        || nl.contains("cash")
        || nl.contains("bank")
        || nl.contains("checking")
        || nl.contains("operating")
        || nl.contains("treasury")
        || nl.contains("trust")
}

/// `solvency.balance_sheet_test` (plan §11.6, `FA-EVID-L52`):
/// A balance-sheet screen over the signed native asset and liability basis.
/// Version 2 preserves contra-accounts and applies the declared haircut once
/// to each unit's positive net asset basis, truncating toward zero. A negative
/// asset basis remains negative. `RegisterEquals` records are reconciliation
/// assertions, never valuation instructions. Explicit documented valuations
/// remain unsupported; this screen makes no fair-value or legal conclusion.
pub struct SolvencyBalanceSheetTest {
    params: Params,
}
procedure_boilerplate!(SolvencyBalanceSheetTest, "solvency.balance_sheet_test");

impl Procedure for SolvencyBalanceSheetTest {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        2
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
        let haircut_bps = self.params.get("fair_value_haircut_bps")?;
        if !(0..=10_000).contains(&haircut_bps) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "fair_value_haircut_bps".into(),
                message: "must be in 0..=10000".into(),
            });
        }

        let through = snapshot.coordinate.effective_through;
        let mut live = snapshot.live_postings_through(through)?;
        live.sort_by_key(|e| e.vid);

        // Accumulate posted net debit-minus-credit per (account_vid, unit_id)
        let mut acct_net: BTreeMap<(VId, u32), i128> = BTreeMap::new();
        let mut unit_entries: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();
        let mut population = 0u64;

        for e in &live {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                let at = AccountType(acct.account_type);
                if !matches!(at, AccountType::ASSET | AccountType::LIABILITY) {
                    continue;
                }
                population += 1;
                let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                let cell = acct_net
                    .entry((leg.account_ref, leg.amount.unit.0))
                    .or_default();
                *cell = cell
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("solvency balance sheet fold"))?;
                unit_entries
                    .entry(leg.amount.unit.0)
                    .or_default()
                    .insert(e.vid);
            }
        }

        // Aggregate signed bases before applying any haircut. Clamping one
        // credit Asset or debit Liability would erase a contra-account.
        // Per unit: (net assets, credit-minus-debit liabilities, citations).
        type UnitSolvency = (i128, i128, BTreeSet<VId>);
        let mut by_unit: BTreeMap<u32, UnitSolvency> = BTreeMap::new();
        for ((acct_vid, unit_id), posted_net) in acct_net {
            work.compare(1);
            let Some(acct) = snapshot.accounts.get(&acct_vid) else {
                continue;
            };
            let at = AccountType(acct.account_type);
            let row = by_unit.entry(unit_id).or_default();
            match at {
                AccountType::ASSET => {
                    row.0 = row
                        .0
                        .checked_add(posted_net)
                        .ok_or(LanternError::Overflow("solvency signed assets sum"))?;
                    row.2.insert(acct_vid);
                }
                AccountType::LIABILITY => {
                    row.1 = row
                        .1
                        .checked_sub(posted_net)
                        .ok_or(LanternError::Overflow("solvency liabilities sum"))?;
                    row.2.insert(acct_vid);
                }
                _ => {}
            }
        }

        let mut out = Vec::new();
        for (unit_id, (asset_basis, total_liabilities, accts)) in by_unit {
            let adjusted_assets = if asset_basis > 0 {
                let kept_bps = amount_difference(10_000, haircut_bps, "solvency asset haircut")?;
                amount_scaled_bps(asset_basis, kept_bps, "solvency asset haircut")?
            } else {
                asset_basis
            };
            if total_liabilities <= adjusted_assets {
                continue;
            }
            let deficit = total_liabilities
                .checked_sub(adjusted_assets)
                .ok_or(LanternError::Overflow("solvency deficit"))?;
            let mut cites: Vec<Cite> = accts.into_iter().map(Cite::Account).collect();
            if let Some(entries) = unit_entries.get(&unit_id) {
                if cites.len() > MAX_CITES || entries.len() > MAX_CITES - cites.len() {
                    return Err(LanternError::Parameter {
                        procedure: Self::ID.into(),
                        name: "scope".into(),
                        message: format!(
                            "the complete signed solvency basis exceeds {MAX_CITES} citations; narrow the recorded/effective scope; no contributing account or entry is omitted"
                        ),
                    });
                }
                cites.extend(entries.iter().copied().map(Cite::Entry));
            }
            let scale = crate::unit_scale(book, unit_id)?;
            out.push(finding(
                Self::ID,
                Severity::Critical,
                Statistic {
                    name: "insolvency_deficit".into(),
                    value: deficit,
                    scale,
                    population: population.max(1),
                },
                cites,
                format!(
                    "unit {unit_id} signed balance-sheet deficit: asset_basis={asset_basis}, adjusted_assets={adjusted_assets}, total_liabilities={total_liabilities}, insolvency_deficit={deficit} (haircut_bps={haircut_bps}; declared book-basis screen, not a fair-value or legal conclusion)"
                ),
            ));
        }
        Ok(out)
    }
}

/// `solvency.cash_flow_test` (plan §11.6, `FA-EVID-L53`):
/// Equitable cash-flow solvency test (ability to pay debts as they come due).
/// Compares liquid cash and cash-equivalent asset balances against unpaid
/// liabilities and pending commitments maturing within `horizon_days` of the
/// coordinate's effective date.
pub struct SolvencyCashFlowTest {
    params: Params,
}
procedure_boilerplate!(SolvencyCashFlowTest, "solvency.cash_flow_test");

impl Procedure for SolvencyCashFlowTest {
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
        let horizon_days = self.params.get_u32("horizon_days")?;
        if horizon_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "horizon_days".into(),
                message: "must be >= 1".into(),
            });
        }

        let mut all_live = snapshot.live_postings()?;
        all_live.sort_by_key(|e| e.vid);
        let ref_date = snapshot.coordinate.effective_through.unwrap_or_else(|| {
            all_live
                .iter()
                .map(|e| e.entry.proposal.effective_date)
                .max()
                .unwrap_or(DateDay(0))
        });
        let horizon_end = DateDay(ref_date.0.saturating_add(horizon_days as i32));

        let mut cash_net: BTreeMap<(VId, u32), i128> = BTreeMap::new();
        let mut liab_net: BTreeMap<(VId, u32), i128> = BTreeMap::new();
        let mut unit_accts: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();
        let mut unit_entries: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();
        let mut population = 0u64;

        for e in &all_live {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            if eff > horizon_end {
                continue;
            }
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                let at = AccountType(acct.account_type);
                let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                if eff <= ref_date && is_liquid_cash_account(&acct.code, &acct.name, at) {
                    population += 1;
                    let c = cash_net
                        .entry((leg.account_ref, leg.amount.unit.0))
                        .or_default();
                    *c = c
                        .checked_add(signed)
                        .ok_or(LanternError::Overflow("cash_flow_test cash fold"))?;
                    unit_accts
                        .entry(leg.amount.unit.0)
                        .or_default()
                        .insert(leg.account_ref);
                    unit_entries
                        .entry(leg.amount.unit.0)
                        .or_default()
                        .insert(e.vid);
                } else if at == AccountType::LIABILITY {
                    population += 1;
                    let l = liab_net
                        .entry((leg.account_ref, leg.amount.unit.0))
                        .or_default();
                    *l = l
                        .checked_add(signed)
                        .ok_or(LanternError::Overflow("cash_flow_test liability fold"))?;
                    unit_accts
                        .entry(leg.amount.unit.0)
                        .or_default()
                        .insert(leg.account_ref);
                    unit_entries
                        .entry(leg.amount.unit.0)
                        .or_default()
                        .insert(e.vid);
                }
            }
        }

        let mut units: BTreeSet<u32> = BTreeSet::new();
        for &(_, u) in cash_net.keys().chain(liab_net.keys()) {
            units.insert(u);
        }

        let mut out = Vec::new();
        for unit_id in units {
            work.compare(1);
            let mut liquid_cash = 0i128;
            for (&(_, u), &net) in &cash_net {
                if u == unit_id && net > 0 {
                    liquid_cash = liquid_cash
                        .checked_add(net)
                        .ok_or(LanternError::Overflow("cash_flow_test liquid_cash sum"))?;
                }
            }
            let mut maturing_obligations = 0i128;
            for (&(_, u), &net) in &liab_net {
                if u == unit_id && net < 0 {
                    maturing_obligations = maturing_obligations
                        .checked_add(amount_negated(net, "cash_flow_test obligation")?)
                        .ok_or(LanternError::Overflow("cash_flow_test obligations sum"))?;
                }
            }
            if maturing_obligations > liquid_cash {
                let shortfall = maturing_obligations
                    .checked_sub(liquid_cash)
                    .ok_or(LanternError::Overflow("cash_flow_test shortfall"))?;
                let mut cites: Vec<Cite> = unit_accts
                    .remove(&unit_id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(Cite::Account)
                    .collect();
                if let Some(entries) = unit_entries.remove(&unit_id) {
                    for evid in entries {
                        if cites.len() < MAX_CITES {
                            cites.push(Cite::Entry(evid));
                        }
                    }
                }
                let scale = crate::unit_scale(book, unit_id)?;
                out.push(finding(
                    Self::ID,
                    Severity::High,
                    Statistic {
                        name: "cash_flow_shortfall".into(),
                        value: shortfall,
                        scale,
                        population: population.max(1),
                    },
                    cites,
                    format!(
                        "unit {unit_id} cash-flow insolvent over {horizon_days}-day horizon: liquid_cash={liquid_cash}, maturing_obligations={maturing_obligations}, shortfall={shortfall}"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

fn party_lookup_tables(snapshot: &Snapshot) -> (BTreeMap<VId, VId>, BTreeMap<VId, String>) {
    let mut pval_to_party = BTreeMap::new();
    let mut party_codes = BTreeMap::new();
    for p in snapshot.rea.parties.values() {
        pval_to_party.insert(p.dimension_value_vid, p.vid);
        pval_to_party.insert(p.vid, p.vid);
        party_codes.insert(p.vid, p.code.clone());
    }
    (pval_to_party, party_codes)
}

fn is_insider_at(snapshot: &Snapshot, party_vid: VId, as_of: DateDay) -> bool {
    if let Some(p) = snapshot.rea.parties.get(&party_vid)
        && matches!(
            p.kind,
            fa_model::PartyKind::RelatedEntity | fa_model::PartyKind::BeneficialOwner
        )
    {
        return true;
    }
    for &root in snapshot.rea.legal_entities.keys() {
        if snapshot
            .rea
            .related_as_of(root, as_of, 4)
            .iter()
            .any(|h| h.vid == party_vid)
        {
            return true;
        }
    }
    snapshot
        .rea
        .relationships
        .iter()
        .any(|r| r.spec.is_active_on(as_of) && (r.spec.from == party_vid || r.spec.to == party_vid))
}

/// `lookback.preferences` (plan §11.6, `FA-EVID-L54`):
/// Avoidable preference lookback under 11 U.S.C. §547(b)-(c). Identifies
/// transfers to creditors within `window_days` (or `insider_window_days` for
/// insiders under §101(31) via `RELATED_TO`/`OWNS`/`CONTROLS`) and computes:
/// - §547(c)(1) contemporaneous exchange (`days_to_pay <= contemporaneous_days`),
/// - §547(c)(2) ordinary course of business (`|days_to_pay - baseline_avg| <= ordinary_course_tolerance_days`),
/// - §547(c)(4) subsequent new value (unpaid subsequent credit extended after a preference transfer),
///
/// emitting net avoidable preference exposure per creditor.
pub struct LookbackPreferences {
    params: Params,
}
procedure_boilerplate!(LookbackPreferences, "lookback.preferences");

impl Procedure for LookbackPreferences {
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
        let window_days = self.params.get_u32("window_days")?;
        let insider_window_days = self.params.get_u32("insider_window_days")?;
        let baseline_days = self.params.get_u32("baseline_days")?;
        let ordinary_tol = self.params.get("ordinary_course_tolerance_days")?;
        let contemp_days = self.params.get("contemporaneous_days")?;

        if window_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "window_days".into(),
                message: "must be >= 1".into(),
            });
        }
        if insider_window_days < window_days {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "insider_window_days".into(),
                message: "must be >= window_days".into(),
            });
        }
        if baseline_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "baseline_days".into(),
                message: "must be >= 1".into(),
            });
        }
        if ordinary_tol < 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "ordinary_course_tolerance_days".into(),
                message: "must be >= 0".into(),
            });
        }
        if contemp_days < 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "contemporaneous_days".into(),
                message: "must be >= 0".into(),
            });
        }

        let through = snapshot.coordinate.effective_through;
        let mut live = snapshot.live_postings_through(through)?;
        live.sort_by_key(|e| (e.entry.proposal.effective_date, e.vid));
        if live.is_empty() {
            return Ok(Vec::new());
        }

        let petition_date = through.unwrap_or_else(|| {
            live.iter()
                .map(|e| e.entry.proposal.effective_date)
                .max()
                .unwrap_or(DateDay(0))
        });

        let mut by_vid: BTreeMap<VId, &crate::SnapshotEntry> = BTreeMap::new();
        for e in &snapshot.entries {
            by_vid.insert(e.vid, e);
        }

        let (pval_to_party, party_codes) = party_lookup_tables(snapshot);

        #[derive(Clone, Debug)]
        enum CreditorEventKind {
            Payment {
                amount: i128,
                days_to_pay: Option<i128>,
            },
            NewValue {
                amount: i128,
            },
        }

        #[derive(Clone, Debug)]
        struct CreditorEvent {
            date: DateDay,
            vid: VId,
            kind: CreditorEventKind,
            accounts: BTreeSet<VId>,
        }

        // Per (party_vid, unit_id): chronological creditor events + latest unpaid invoice date
        let mut events_by_creditor: BTreeMap<(VId, u32), Vec<CreditorEvent>> = BTreeMap::new();
        let mut open_invoice_date: BTreeMap<(VId, u32), DateDay> = BTreeMap::new();
        let mut population = 0u64;

        for e in &live {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            let mut parties_in_entry: BTreeSet<VId> = BTreeSet::new();
            let mut cash_credit_by_unit: BTreeMap<u32, i128> = BTreeMap::new();
            let mut ob_debit_by_unit: BTreeMap<u32, i128> = BTreeMap::new();
            let mut liab_credit_by_unit: BTreeMap<u32, i128> = BTreeMap::new();
            let mut accts_by_unit: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();

            for leg in &e.entry.proposal.legs {
                work.leg();
                for &(_, d) in &leg.dimension_set {
                    if let Some(&pvid) = pval_to_party.get(&d) {
                        parties_in_entry.insert(pvid);
                    }
                }
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                let at = AccountType(acct.account_type);
                let mag = amount_magnitude(leg.amount.mantissa, "leg magnitude")?;
                let u = leg.amount.unit.0;
                accts_by_unit.entry(u).or_default().insert(leg.account_ref);

                let total = match (leg.side, at) {
                    (Side::Credit, AccountType::ASSET)
                        if is_liquid_cash_account(&acct.code, &acct.name, at) =>
                    {
                        cash_credit_by_unit.entry(u).or_default()
                    }
                    (Side::Debit, AccountType::LIABILITY | AccountType::EXPENSE) => {
                        ob_debit_by_unit.entry(u).or_default()
                    }
                    (Side::Credit, AccountType::LIABILITY) => {
                        liab_credit_by_unit.entry(u).or_default()
                    }
                    _ => continue,
                };
                *total = amount_sum(*total, mag, "preference entry sum")?;
            }

            if parties_in_entry.is_empty() {
                continue;
            }

            let settled_date = e
                .entry
                .proposal
                .legs
                .iter()
                .flat_map(|l| l.settles.iter())
                .filter_map(|s| {
                    by_vid
                        .get(&s.target.vid)
                        .map(|t| t.entry.proposal.effective_date)
                })
                .min();

            for &party_vid in &parties_in_entry {
                for (&unit_id, accts) in &accts_by_unit {
                    let cash_cr = cash_credit_by_unit.get(&unit_id).copied().unwrap_or(0);
                    let ob_dr = ob_debit_by_unit.get(&unit_id).copied().unwrap_or(0);
                    let liab_cr = liab_credit_by_unit.get(&unit_id).copied().unwrap_or(0);

                    if cash_cr > 0 && ob_dr > 0 {
                        population += 1;
                        let amt = cash_cr.min(ob_dr);
                        let inv_date = settled_date
                            .or(e.entry.proposal.document_date)
                            .or_else(|| open_invoice_date.get(&(party_vid, unit_id)).copied());
                        let dtp = inv_date.map(|d| i128::from((eff.0 - d.0).max(0)));
                        open_invoice_date.remove(&(party_vid, unit_id));
                        events_by_creditor
                            .entry((party_vid, unit_id))
                            .or_default()
                            .push(CreditorEvent {
                                date: eff,
                                vid: e.vid,
                                kind: CreditorEventKind::Payment {
                                    amount: amt,
                                    days_to_pay: dtp,
                                },
                                accounts: accts.clone(),
                            });
                    } else if liab_cr > 0 && cash_cr == 0 {
                        population += 1;
                        let inv_d = e.entry.proposal.document_date.unwrap_or(eff);
                        open_invoice_date
                            .entry((party_vid, unit_id))
                            .and_modify(|d| {
                                if inv_d < *d {
                                    *d = inv_d;
                                }
                            })
                            .or_insert(inv_d);
                        events_by_creditor
                            .entry((party_vid, unit_id))
                            .or_default()
                            .push(CreditorEvent {
                                date: eff,
                                vid: e.vid,
                                kind: CreditorEventKind::NewValue { amount: liab_cr },
                                accounts: accts.clone(),
                            });
                    }
                }
            }
        }

        let mut out = Vec::new();
        for ((party_vid, unit_id), evs) in events_by_creditor {
            work.compare(1);
            let insider = evs
                .iter()
                .any(|ev| is_insider_at(snapshot, party_vid, ev.date))
                || is_insider_at(snapshot, party_vid, petition_date);
            let lookback = if insider {
                insider_window_days
            } else {
                window_days
            };
            let pref_start = DateDay(petition_date.0.saturating_sub(lookback as i32));
            let base_start = DateDay(pref_start.0.saturating_sub(baseline_days as i32));

            // Compute baseline average days-to-pay in [base_start, pref_start)
            let mut base_sum = 0i128;
            let mut base_cnt = 0i128;
            for ev in &evs {
                if ev.date >= base_start
                    && ev.date < pref_start
                    && let CreditorEventKind::Payment {
                        days_to_pay: Some(dtp),
                        ..
                    } = ev.kind
                {
                    base_sum = amount_sum(base_sum, dtp, "preference baseline days")?;
                    base_cnt = amount_sum(base_cnt, 1, "preference baseline count")?;
                }
            }
            let baseline_avg = base_sum.checked_div(base_cnt);

            let mut gross_preference = 0i128;
            let mut c1_contemporaneous = 0i128;
            let mut c2_ordinary_course = 0i128;
            let mut c4_new_value = 0i128;
            let mut unprotected_running = 0i128;
            let mut seen_pref_payment = false;
            let mut cited_accts: BTreeSet<VId> = BTreeSet::new();
            let mut cited_entries: BTreeSet<VId> = BTreeSet::new();

            for ev in &evs {
                if ev.date < pref_start || ev.date > petition_date {
                    continue;
                }
                match ev.kind {
                    CreditorEventKind::Payment {
                        amount,
                        days_to_pay,
                    } => {
                        seen_pref_payment = true;
                        gross_preference = gross_preference
                            .checked_add(amount)
                            .ok_or(LanternError::Overflow("preference gross sum"))?;
                        cited_entries.insert(ev.vid);
                        cited_accts.extend(ev.accounts.iter().copied());

                        if days_to_pay.is_some_and(|d| d <= contemp_days) {
                            c1_contemporaneous = c1_contemporaneous
                                .checked_add(amount)
                                .ok_or(LanternError::Overflow("preference c1 sum"))?;
                        } else if let (Some(d), Some(avg)) = (days_to_pay, baseline_avg)
                            && u128::try_from(ordinary_tol).is_ok_and(|tol| d.abs_diff(avg) <= tol)
                        {
                            c2_ordinary_course = c2_ordinary_course
                                .checked_add(amount)
                                .ok_or(LanternError::Overflow("preference c2 sum"))?;
                        } else {
                            unprotected_running = unprotected_running
                                .checked_add(amount)
                                .ok_or(LanternError::Overflow("preference unprotected sum"))?;
                        }
                    }
                    CreditorEventKind::NewValue { amount } if seen_pref_payment => {
                        let offset = amount.min(unprotected_running);
                        if offset > 0 {
                            unprotected_running = amount_difference(
                                unprotected_running,
                                offset,
                                "preference new value",
                            )?;
                            c4_new_value = c4_new_value
                                .checked_add(offset)
                                .ok_or(LanternError::Overflow("preference c4 sum"))?;
                            cited_entries.insert(ev.vid);
                            cited_accts.extend(ev.accounts.iter().copied());
                        }
                    }
                    CreditorEventKind::NewValue { .. } => {}
                }
            }

            if gross_preference == 0 || unprotected_running == 0 {
                continue;
            }

            let mut cites: Vec<Cite> = cited_accts.into_iter().map(Cite::Account).collect();
            for evid in cited_entries {
                if cites.len() < MAX_CITES {
                    cites.push(Cite::Entry(evid));
                }
            }
            let party_code = party_codes
                .get(&party_vid)
                .cloned()
                .unwrap_or_else(|| format!("{:032x}", party_vid.0));
            let scale = crate::unit_scale(book, unit_id)?;
            out.push(finding(
                Self::ID,
                Severity::High,
                Statistic {
                    name: "net_preference_exposure".into(),
                    value: unprotected_running,
                    scale,
                    population: population.max(1),
                },
                cites,
                format!(
                    "creditor {party_code} (insider={insider}): gross_preference={gross_preference}, c1_contemporaneous={c1_contemporaneous}, c2_ordinary_course={c2_ordinary_course}, c4_new_value={c4_new_value}, net_exposure={unprotected_running}"
                ),
            ));
        }
        Ok(out)
    }
}

/// `lookback.fraudulent_transfer` (plan §11.6, `FA-EVID-L55`):
/// Constructive and actual fraudulent transfer lookback under 11 U.S.C. §548
/// (`section_548_days`) and UVTA §9 (`uvta_days`). Scans asset outflows for
/// badges of fraud:
/// 1. Transfer to an insider/related party (`RELATED_TO`/`OWNS`/`CONTROLS`),
/// 2. Transfer while balance-sheet insolvent,
/// 3. Absence of corroborating evidence (`evidence` empty),
/// 4. Manual/concealed or round-amount outflow.
pub struct LookbackFraudulentTransfer {
    params: Params,
}
procedure_boilerplate!(LookbackFraudulentTransfer, "lookback.fraudulent_transfer");

impl Procedure for LookbackFraudulentTransfer {
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
        let s548_days = self.params.get_u32("section_548_days")?;
        let uvta_days = self.params.get_u32("uvta_days")?;
        if s548_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "section_548_days".into(),
                message: "must be >= 1".into(),
            });
        }
        if uvta_days < s548_days {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "uvta_days".into(),
                message: "must be >= section_548_days".into(),
            });
        }

        let through = snapshot.coordinate.effective_through;
        let mut live = snapshot.live_postings_through(through)?;
        live.sort_by_key(|e| (e.entry.proposal.effective_date, e.vid));
        if live.is_empty() {
            return Ok(Vec::new());
        }

        let petition_date = through.unwrap_or_else(|| {
            live.iter()
                .map(|e| e.entry.proposal.effective_date)
                .max()
                .unwrap_or(DateDay(0))
        });
        let uvta_start = DateDay(petition_date.0.saturating_sub(uvta_days as i32));
        let s548_start = DateDay(petition_date.0.saturating_sub(s548_days as i32));

        let (pval_to_party, _) = party_lookup_tables(snapshot);
        let mut running_assets: BTreeMap<u32, i128> = BTreeMap::new();
        let mut running_liabs: BTreeMap<u32, i128> = BTreeMap::new();
        let population = live.len() as u64;
        let mut out = Vec::new();

        for e in &live {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            let mut asset_cr: BTreeMap<u32, i128> = BTreeMap::new();
            let mut asset_dr: BTreeMap<u32, i128> = BTreeMap::new();
            let mut liab_dr: BTreeMap<u32, i128> = BTreeMap::new();
            let mut liab_cr: BTreeMap<u32, i128> = BTreeMap::new();
            let mut accts_by_unit: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();
            let mut parties: BTreeSet<VId> = BTreeSet::new();

            for leg in &e.entry.proposal.legs {
                work.leg();
                for &(_, d) in &leg.dimension_set {
                    if let Some(&pvid) = pval_to_party.get(&d) {
                        parties.insert(pvid);
                    }
                }
                let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                    continue;
                };
                let at = AccountType(acct.account_type);
                let mag = amount_magnitude(leg.amount.mantissa, "leg magnitude")?;
                let u = leg.amount.unit.0;
                accts_by_unit.entry(u).or_default().insert(leg.account_ref);

                // (this entry's side total, the running balance, increases?)
                let (side_total, running, increases) = match (leg.side, at) {
                    (Side::Debit, AccountType::ASSET) => (&mut asset_dr, &mut running_assets, true),
                    (Side::Credit, AccountType::ASSET) => {
                        (&mut asset_cr, &mut running_assets, false)
                    }
                    (Side::Credit, AccountType::LIABILITY) => {
                        (&mut liab_cr, &mut running_liabs, true)
                    }
                    (Side::Debit, AccountType::LIABILITY) => {
                        (&mut liab_dr, &mut running_liabs, false)
                    }
                    _ => continue,
                };
                let total = side_total.entry(u).or_default();
                *total = amount_sum(*total, mag, "fraudulent transfer entry sum")?;
                let balance = running.entry(u).or_default();
                *balance = if increases {
                    amount_sum(*balance, mag, "fraudulent transfer running balance")?
                } else {
                    amount_difference(*balance, mag, "fraudulent transfer running balance")?
                };
            }

            if eff < uvta_start || eff > petition_date {
                continue;
            }

            let insider = parties
                .iter()
                .any(|&pvid| is_insider_at(snapshot, pvid, eff));
            let uncorroborated = e.entry.proposal.evidence.is_empty();
            let opened_desc = e
                .entry
                .proposal
                .description
                .open(&book.seal_key, fa_model::limits::MAX_DESCRIPTION_BYTES)
                .unwrap_or_default();
            let thin_desc = opened_desc.trim().len() < 12;

            for (&unit_id, &cr) in &asset_cr {
                work.compare(1);
                let dr = asset_dr.get(&unit_id).copied().unwrap_or(0);
                let l_dr = liab_dr.get(&unit_id).copied().unwrap_or(0);
                // Net value leaving the estate without commensurate asset receipt or
                // debt reduction. All three are nonnegative, so each step that
                // remains positive is exact.
                if cr <= dr {
                    continue;
                }
                let after_receipts = amount_difference(cr, dr, "fraudulent transfer outflow")?;
                if after_receipts <= l_dr {
                    continue;
                }
                let uncompensated_outflow =
                    amount_difference(after_receipts, l_dr, "fraudulent transfer outflow")?;
                let cur_assets = running_assets.get(&unit_id).copied().unwrap_or(0);
                let cur_liabs = running_liabs.get(&unit_id).copied().unwrap_or(0);
                let insolvent = cur_liabs > cur_assets;
                let round_or_thin = thin_desc || (uncompensated_outflow % 100_000 == 0);

                // Require either insider transfer OR insolvency as an anchor badge, plus >= 2 total badges
                if !insider && !insolvent {
                    continue;
                }
                let badge_count = u8::from(insider)
                    + u8::from(insolvent)
                    + u8::from(uncorroborated)
                    + u8::from(round_or_thin);
                if badge_count < 2 {
                    continue;
                }

                let window = if eff >= s548_start {
                    "11_usc_548"
                } else {
                    "uvta_section_9"
                };
                let severity = if eff >= s548_start && insider && insolvent {
                    Severity::Critical
                } else {
                    Severity::High
                };
                let mut cites: Vec<Cite> = accts_by_unit
                    .get(&unit_id)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(Cite::Account)
                    .collect();
                cites.push(Cite::Entry(e.vid));
                if snapshot.periods.contains_key(&e.period) {
                    cites.push(Cite::Period(e.period.clone()));
                }
                let scale = crate::unit_scale(book, unit_id)?;
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic {
                        name: "fraudulent_transfer_amount".into(),
                        value: uncompensated_outflow,
                        scale,
                        population: population.max(1),
                    },
                    cites,
                    format!(
                        "window {window}: asset outflow {uncompensated_outflow} with {badge_count} badge(s) of fraud (insider={insider}, insolvent={insolvent}, uncorroborated={uncorroborated}, round_or_thin={round_or_thin})"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug)]
struct InvestorPosition {
    party_vid: VId,
    party_code: String,
    unit_id: u32,
    cash_in: i128,
    cash_out: i128,
    first_inflow_date: Option<DateDay>,
    first_entry_vid: VId,
    accounts: BTreeSet<VId>,
    entries: BTreeSet<VId>,
}

fn is_investor_contra_account(code: &str, name: &str, account_type: AccountType) -> bool {
    if account_type == AccountType::EQUITY {
        return true;
    }
    let cl = code.to_ascii_lowercase();
    let nl = name.to_ascii_lowercase();
    cl.starts_with("21")
        || cl.starts_with("25")
        || cl.starts_with("30")
        || nl.contains("investor")
        || nl.contains("capital")
        || nl.contains("subscription")
        || nl.contains("redemption")
        || nl.contains("distribution")
        || nl.contains("deposit")
        || nl.contains("ponzi")
        || nl.contains("partner")
}

type InvestorPopulation = (Vec<InvestorPosition>, BTreeMap<u32, i128>, u64);

/// Collect investor cash-in and cash-out positions per `(party_vid, unit_id)`,
/// plus ending positive cash balance per `unit_id`.
fn collect_investor_positions(
    snapshot: &Snapshot,
    book: &BookContext,
    work: &mut Work,
) -> Result<InvestorPopulation, LanternError> {
    let through = snapshot.coordinate.effective_through;
    let mut live = snapshot.live_postings_through(through)?;
    live.sort_by_key(|e| (e.entry.proposal.effective_date, e.vid));

    let (pval_to_party, party_codes) = party_lookup_tables(snapshot);
    let mut positions: BTreeMap<(VId, u32), InvestorPosition> = BTreeMap::new();
    let mut explicit_investor_party: BTreeSet<(VId, u32)> = BTreeSet::new();
    let mut cash_balance_by_unit: BTreeMap<u32, i128> = BTreeMap::new();
    let mut population = 0u64;

    for e in &live {
        work.entry();
        let eff = e.entry.proposal.effective_date;
        let desc_lower = e
            .entry
            .proposal
            .description
            .open(&book.seal_key, fa_model::limits::MAX_DESCRIPTION_BYTES)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let desc_investor = desc_lower.contains("investor")
            || desc_lower.contains("subscription")
            || desc_lower.contains("redemption")
            || desc_lower.contains("distribution")
            || desc_lower.contains("ponzi");

        let mut parties_in_entry: BTreeSet<VId> = BTreeSet::new();
        let mut cash_dr_by_unit: BTreeMap<u32, i128> = BTreeMap::new();
        let mut cash_cr_by_unit: BTreeMap<u32, i128> = BTreeMap::new();
        let mut contra_investor_flag: BTreeMap<u32, bool> = BTreeMap::new();
        let mut accts_by_unit: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();

        for leg in &e.entry.proposal.legs {
            work.leg();
            for &(_, d) in &leg.dimension_set {
                let pvid = pval_to_party.get(&d).copied().unwrap_or(d);
                parties_in_entry.insert(pvid);
            }
            let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                continue;
            };
            let at = AccountType(acct.account_type);
            let mag = amount_magnitude(leg.amount.mantissa, "leg magnitude")?;
            let u = leg.amount.unit.0;
            accts_by_unit.entry(u).or_default().insert(leg.account_ref);

            if is_liquid_cash_account(&acct.code, &acct.name, at) {
                let balance = cash_balance_by_unit.entry(u).or_default();
                match leg.side {
                    Side::Debit => {
                        let total = cash_dr_by_unit.entry(u).or_default();
                        *total = amount_sum(*total, mag, "investor entry cash in")?;
                        *balance = amount_sum(*balance, mag, "investor cash balance")?;
                    }
                    Side::Credit => {
                        let total = cash_cr_by_unit.entry(u).or_default();
                        *total = amount_sum(*total, mag, "investor entry cash out")?;
                        *balance = amount_difference(*balance, mag, "investor cash balance")?;
                    }
                }
            } else if is_investor_contra_account(&acct.code, &acct.name, at) || desc_investor {
                contra_investor_flag.insert(u, true);
            }
        }

        if parties_in_entry.is_empty() {
            continue;
        }

        for &party_vid in &parties_in_entry {
            let code = party_codes
                .get(&party_vid)
                .cloned()
                .unwrap_or_else(|| format!("{:032x}", party_vid.0));
            for (&unit_id, accts) in &accts_by_unit {
                let dr = cash_dr_by_unit.get(&unit_id).copied().unwrap_or(0);
                let cr = cash_cr_by_unit.get(&unit_id).copied().unwrap_or(0);
                if dr == 0 && cr == 0 {
                    continue;
                }
                if contra_investor_flag.get(&unit_id).copied().unwrap_or(false) {
                    explicit_investor_party.insert((party_vid, unit_id));
                }
                population += 1;
                let pos =
                    positions
                        .entry((party_vid, unit_id))
                        .or_insert_with(|| InvestorPosition {
                            party_vid,
                            party_code: code.clone(),
                            unit_id,
                            cash_in: 0,
                            cash_out: 0,
                            first_inflow_date: None,
                            first_entry_vid: e.vid,
                            accounts: BTreeSet::new(),
                            entries: BTreeSet::new(),
                        });
                if e.vid < pos.first_entry_vid {
                    pos.first_entry_vid = e.vid;
                }
                if dr > 0 {
                    pos.cash_in = pos
                        .cash_in
                        .checked_add(dr)
                        .ok_or(LanternError::Overflow("investor cash_in sum"))?;
                    if pos.first_inflow_date.is_none_or(|d| eff < d) {
                        pos.first_inflow_date = Some(eff);
                    }
                }
                if cr > 0 {
                    pos.cash_out = pos
                        .cash_out
                        .checked_add(cr)
                        .ok_or(LanternError::Overflow("investor cash_out sum"))?;
                }
                pos.accounts.extend(accts.iter().copied());
                pos.entries.insert(e.vid);
            }
        }
    }

    // Retain parties that invested principal (cash_in > 0) or touched an explicit investor account
    let filtered: Vec<InvestorPosition> = positions
        .into_iter()
        .filter(|(k, p)| p.cash_in > 0 || explicit_investor_party.contains(k))
        .map(|(_, p)| p)
        .collect();

    Ok((filtered, cash_balance_by_unit, population))
}

/// The net losers' total unrecovered principal, `sum(cash_in - cash_out)`.
fn unrecovered_total(
    losers: &[InvestorPosition],
    accumulator: &'static str,
) -> Result<i128, LanternError> {
    losers.iter().try_fold(0i128, |total, p| {
        amount_sum(
            total,
            amount_difference(p.cash_in, p.cash_out, accumulator)?,
            accumulator,
        )
    })
}

/// `ponzi.net_investment` (plan §11.5, `FA-EVID-L56`):
/// Madoff net-equity Ponzi schedule (*In re Bernard L. Madoff Investment
/// Securities LLC*, 654 F.3d 229). Computes per-investor `cash_in - cash_out`,
/// assigns investor cohorts by first-inflow date (`cohort_window_days`), and
/// classifies net losers (net equity claims) and net winners (fictitious
/// profits subject to clawback).
pub struct PonziNetInvestment {
    params: Params,
}
procedure_boilerplate!(PonziNetInvestment, "ponzi.net_investment");

impl Procedure for PonziNetInvestment {
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
        let cohort_window_days = self.params.get_u32("cohort_window_days")?;
        if cohort_window_days == 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "cohort_window_days".into(),
                message: "must be >= 1".into(),
            });
        }

        let (investors, _, population) = collect_investor_positions(snapshot, book, work)?;
        if investors.is_empty() {
            return Ok(Vec::new());
        }

        let earliest_inflow = investors
            .iter()
            .filter_map(|p| p.first_inflow_date)
            .min()
            .unwrap_or(DateDay(0));

        let mut out = Vec::new();
        for pos in investors {
            work.compare(1);
            let cohort = pos.first_inflow_date.map_or(1, |d| {
                ((d.0 - earliest_inflow.0).max(0) as u32 / cohort_window_days) + 1
            });
            let mut cites: Vec<Cite> = pos.accounts.into_iter().map(Cite::Account).collect();
            for evid in pos.entries {
                if cites.len() < MAX_CITES {
                    cites.push(Cite::Entry(evid));
                }
            }
            let scale = crate::unit_scale(book, pos.unit_id)?;
            if pos.cash_out > pos.cash_in {
                let clawback = amount_difference(pos.cash_out, pos.cash_in, "ponzi clawback")?;
                out.push(finding(
                    Self::ID,
                    Severity::High,
                    Statistic {
                        name: "fictitious_profit_clawback".into(),
                        value: clawback,
                        scale,
                        population: population.max(1),
                    },
                    cites,
                    format!(
                        "investor {} (cohort {cohort}, status=net_winner): cash_in={}, cash_out={}, fictitious_profit_clawback={clawback}",
                        pos.party_code, pos.cash_in, pos.cash_out
                    ),
                ));
            } else if pos.cash_in > pos.cash_out {
                let claim = amount_difference(pos.cash_in, pos.cash_out, "ponzi net equity")?;
                out.push(finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic {
                        name: "net_equity_claim".into(),
                        value: claim,
                        scale,
                        population: population.max(1),
                    },
                    cites,
                    format!(
                        "investor {} (cohort {cohort}, status=net_loser): cash_in={}, cash_out={}, net_equity_claim={claim}",
                        pos.party_code, pos.cash_in, pos.cash_out
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `distribution.rising_tide` (plan §11.5, `FA-EVID-L57`):
/// Rising-tide receivership distribution (*SEC v. Huber*, 702 F.3d 903).
/// Equalizes cumulative recovery rates `(cash_out + distribution) / cash_in`
/// across net-loser investors up to the exact rational water level supported
/// by the distributable pool under `LargestRemainder`.
pub struct DistributionRisingTide {
    params: Params,
}
procedure_boilerplate!(DistributionRisingTide, "distribution.rising_tide");

impl Procedure for DistributionRisingTide {
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
        let explicit_pool = self.params.get("distributable_pool")?;
        if explicit_pool < 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "distributable_pool".into(),
                message: "must be >= 0".into(),
            });
        }

        let (investors, cash_by_unit, population) =
            collect_investor_positions(snapshot, book, work)?;
        let mut by_unit: BTreeMap<u32, Vec<InvestorPosition>> = BTreeMap::new();
        for pos in investors {
            if pos.cash_in > pos.cash_out {
                by_unit.entry(pos.unit_id).or_default().push(pos);
            }
        }

        let mut out = Vec::new();
        for (unit_id, mut losers) in by_unit {
            work.compare(1);
            if losers.is_empty() {
                continue;
            }
            // Sort ascending by pre-receivership recovery ratio w_i / p_i via exact
            // cross-multiplication (cash_in > cash_out >= 0 for a net loser).
            losers.sort_by(|a, b| {
                ratio_cmp(
                    a.cash_out.unsigned_abs(),
                    a.cash_in.unsigned_abs(),
                    b.cash_out.unsigned_abs(),
                    b.cash_in.unsigned_abs(),
                )
                .then_with(|| a.first_entry_vid.cmp(&b.first_entry_vid))
            });

            let total_unrecovered = unrecovered_total(&losers, "rising_tide unrecovered")?;
            let raw_pool = if explicit_pool > 0 {
                explicit_pool
            } else {
                cash_by_unit.get(&unit_id).copied().unwrap_or(0).max(0)
            };
            let pool_eff = raw_pool.min(total_unrecovered);
            if pool_eff <= 0 {
                continue;
            }

            // Find the active prefix 0..k whose recovery rate is raised to the water level
            let mut k = 0usize;
            let mut p_sum = 0i128;
            let mut w_sum = 0i128;
            for (idx, pos) in losers.iter().enumerate() {
                if idx > 0 {
                    // Pool needed to raise 0..idx to pos's recovery rate w_idx / p_idx:
                    // need = (w_idx * p_sum - p_idx * w_sum) / p_idx, nonnegative
                    // because the losers are sorted by that rate.
                    let need_num = wide_product(pos.cash_out, p_sum, "rising_tide need_num")?
                        .checked_sub(wide_product(pos.cash_in, w_sum, "rising_tide need_sub")?)
                        .ok_or(LanternError::Overflow("rising_tide need diff"))?;
                    let cap_num = wide_product(pool_eff, pos.cash_in, "rising_tide cap_num")?;
                    if need_num >= cap_num {
                        break;
                    }
                }
                p_sum = p_sum
                    .checked_add(pos.cash_in)
                    .ok_or(LanternError::Overflow("rising_tide p_sum"))?;
                w_sum = w_sum
                    .checked_add(pos.cash_out)
                    .ok_or(LanternError::Overflow("rising_tide w_sum"))?;
                k = idx + 1;
            }

            // Every active investor sits at or below the water level
            // (pool + w_sum) / p_sum, so each numerator is nonnegative.
            let level = amount_sum(pool_eff, w_sum, "rising_tide water level")?;
            let mut numerators = Vec::with_capacity(k);
            let mut tie_breaks = Vec::with_capacity(k);
            for pos in losers.iter().take(k) {
                let num = wide_product(level, pos.cash_in, "rising_tide numerator")?
                    .checked_sub(wide_product(
                        p_sum,
                        pos.cash_out,
                        "rising_tide numerator sub",
                    )?)
                    .ok_or(LanternError::Overflow("rising_tide numerator diff"))?;
                numerators.push(num);
                tie_breaks.push(pos.first_entry_vid);
            }
            let active_allocs = largest_remainder(pool_eff, &numerators, p_sum, &tie_breaks)?;
            let water_bps = amount_share_bps(level, p_sum, "rising_tide water_bps")?;
            let scale = crate::unit_scale(book, unit_id)?;

            for (idx, pos) in losers.into_iter().enumerate() {
                let dist = active_allocs.get(idx).copied().unwrap_or(0);
                let mut cites: Vec<Cite> = pos.accounts.into_iter().map(Cite::Account).collect();
                for evid in pos.entries {
                    if cites.len() < MAX_CITES {
                        cites.push(Cite::Entry(evid));
                    }
                }
                let severity = if dist > 0 {
                    Severity::Medium
                } else {
                    Severity::Info
                };
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic {
                        name: "rising_tide_distribution".into(),
                        value: dist,
                        scale,
                        population: population.max(1),
                    },
                    cites,
                    format!(
                        "investor {}: principal={}, prior_withdrawals={}, rising_tide_distribution={dist} (water_level_bps={water_bps})",
                        pos.party_code, pos.cash_in, pos.cash_out
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `distribution.pro_rata` (plan §11.5, `FA-EVID-L58`):
/// *Cunningham v. Brown* pro-rata receivership distribution. Allocates the
/// distributable pool across net-loser investors in exact proportion to their
/// net unrecovered principal (`cash_in - cash_out`) under `LargestRemainder`.
pub struct DistributionProRata {
    params: Params,
}
procedure_boilerplate!(DistributionProRata, "distribution.pro_rata");

impl Procedure for DistributionProRata {
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
        let explicit_pool = self.params.get("distributable_pool")?;
        if explicit_pool < 0 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "distributable_pool".into(),
                message: "must be >= 0".into(),
            });
        }

        let (investors, cash_by_unit, population) =
            collect_investor_positions(snapshot, book, work)?;
        let mut by_unit: BTreeMap<u32, Vec<InvestorPosition>> = BTreeMap::new();
        for pos in investors {
            if pos.cash_in > pos.cash_out {
                by_unit.entry(pos.unit_id).or_default().push(pos);
            }
        }

        let mut out = Vec::new();
        for (unit_id, mut losers) in by_unit {
            work.compare(1);
            if losers.is_empty() {
                continue;
            }
            losers.sort_by_key(|p| (p.first_entry_vid, p.party_vid));

            let total_unrecovered = unrecovered_total(&losers, "pro_rata unrecovered")?;
            let raw_pool = if explicit_pool > 0 {
                explicit_pool
            } else {
                cash_by_unit.get(&unit_id).copied().unwrap_or(0).max(0)
            };
            let pool_eff = raw_pool.min(total_unrecovered);
            if pool_eff <= 0 {
                continue;
            }

            let mut numerators = Vec::with_capacity(losers.len());
            let mut tie_breaks = Vec::with_capacity(losers.len());
            for pos in &losers {
                let claim = amount_difference(pos.cash_in, pos.cash_out, "pro_rata claim")?;
                numerators.push(wide_product(pool_eff, claim, "pro_rata numerator")?);
                tie_breaks.push(pos.first_entry_vid);
            }
            let allocs = largest_remainder(pool_eff, &numerators, total_unrecovered, &tie_breaks)?;
            let scale = crate::unit_scale(book, unit_id)?;

            for (pos, dist) in losers.into_iter().zip(allocs) {
                let claim = amount_difference(pos.cash_in, pos.cash_out, "pro_rata claim")?;
                let mut cites: Vec<Cite> = pos.accounts.into_iter().map(Cite::Account).collect();
                for evid in pos.entries {
                    if cites.len() < MAX_CITES {
                        cites.push(Cite::Entry(evid));
                    }
                }
                out.push(finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic {
                        name: "pro_rata_distribution".into(),
                        value: dist,
                        scale,
                        population: population.max(1),
                    },
                    cites,
                    format!(
                        "investor {}: principal={}, prior_withdrawals={}, net_claim={claim}, pro_rata_distribution={dist}",
                        pos.party_code, pos.cash_in, pos.cash_out
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `damages.but_for` (plan §11.6, `FA-EVID-L59`):
/// But-for damages schedule. Computes per-account and per-period damages deltas
/// between the actual live posted fold and counterfactual baseline expectations
/// (from `RegisterEquals` baseline attestations or pre-supersession / restated
/// entry lineages). See also [`compute_scenario_but_for_damages`] for comparing
/// a trunk snapshot directly against a counterfactual scenario scratch-book snapshot.
pub struct DamagesButFor {
    params: Params,
}
procedure_boilerplate!(DamagesButFor, "damages.but_for");

impl Procedure for DamagesButFor {
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
        let through = snapshot.coordinate.effective_through;
        let mut live = snapshot.live_postings_through(through)?;
        live.sort_by_key(|e| e.vid);

        // Actual live fold per (account_vid, period, unit_id)
        type CellKey = (VId, String, u32);
        let mut actual_fold: BTreeMap<CellKey, (i128, BTreeSet<VId>)> = BTreeMap::new();
        for e in &live {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                let cell = actual_fold
                    .entry((leg.account_ref, e.period.clone(), leg.amount.unit.0))
                    .or_default();
                cell.0 = cell
                    .0
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("damages.but_for actual fold"))?;
                cell.1.insert(e.vid);
            }
        }

        // Counterfactual baseline from RegisterEquals attestations
        let mut but_for_cells: BTreeMap<CellKey, (i128, BTreeSet<VId>)> = BTreeMap::new();
        for att in snapshot.attestations.values() {
            if let AttestationClaim::RegisterEquals(c) = &att.attestation.claim {
                if through.is_some_and(|d| c.as_of_effective > d) {
                    continue;
                }
                let key = (c.account, c.period.clone(), c.unit_id);
                let entries = actual_fold
                    .get(&key)
                    .map(|(_, es)| es.clone())
                    .unwrap_or_default();
                but_for_cells.insert(key, (c.mantissa, entries));
            }
        }

        // Also include cells whereOriginal postings were superseded/reversed by restatement
        let live_vids: BTreeSet<VId> = live.iter().map(|e| e.vid).collect();
        let mut original_fold: BTreeMap<CellKey, (i128, BTreeSet<VId>)> = BTreeMap::new();
        let mut has_superseded_cell: BTreeSet<CellKey> = BTreeSet::new();
        for e in &snapshot.entries {
            if !e.posts() || through.is_some_and(|d| e.entry.proposal.effective_date > d) {
                continue;
            }
            let is_original = e.entry.proposal.class == EntryClass::ORIGINAL
                && e.entry.proposal.supersession.is_empty();
            let was_superseded = is_original && !live_vids.contains(&e.vid);
            if is_original {
                for leg in &e.entry.proposal.legs {
                    let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                    let key = (leg.account_ref, e.period.clone(), leg.amount.unit.0);
                    let cell = original_fold.entry(key.clone()).or_default();
                    cell.0 = cell
                        .0
                        .checked_add(signed)
                        .ok_or(LanternError::Overflow("damages.but_for original fold"))?;
                    cell.1.insert(e.vid);
                    if was_superseded {
                        has_superseded_cell.insert(key);
                    }
                }
            }
        }
        for key in has_superseded_cell {
            if !but_for_cells.contains_key(&key)
                && let Some(orig) = original_fold.remove(&key)
            {
                but_for_cells.insert(key, orig);
            }
        }

        let population = (live.len() + snapshot.attestations.len()).max(1) as u64;
        let mut out = Vec::new();
        for ((acct_vid, period, unit_id), (but_for_net, mut cites_set)) in but_for_cells {
            work.compare(1);
            let actual_net = actual_fold
                .get(&(acct_vid, period.clone(), unit_id))
                .map_or(0, |(v, _)| *v);
            if let Some((_, act_entries)) = actual_fold.get(&(acct_vid, period.clone(), unit_id)) {
                cites_set.extend(act_entries.iter().copied());
            }
            if actual_net == but_for_net {
                continue;
            }
            let delta = reconciliation_arithmetic::discrepancy(actual_net, but_for_net)
                .ok_or(LanternError::Overflow("damages.but_for delta"))?;
            let mut cites = vec![Cite::Account(acct_vid)];
            if snapshot.periods.contains_key(&period) {
                cites.push(Cite::Period(period.clone()));
            }
            for evid in cites_set {
                if cites.len() < MAX_CITES {
                    cites.push(Cite::Entry(evid));
                }
            }
            let code = snapshot
                .accounts
                .get(&acct_vid)
                .map_or("?", |a| a.code.as_str());
            let scale = crate::unit_scale(book, unit_id)?;
            out.push(finding(
                Self::ID,
                Severity::High,
                Statistic {
                    name: "but_for_damages_delta".into(),
                    value: delta,
                    scale,
                    population,
                },
                cites,
                format!(
                    "account {code} period {period} unit {unit_id}: actual_net={actual_net}, but_for_net={but_for_net}, damages_delta={delta}"
                ),
            ));
        }
        Ok(out)
    }
}

/// Compute a certified `damages.but_for` schedule by comparing an actual trunk
/// [`Snapshot`] directly against a counterfactual scenario scratch-book [`Snapshot`]
/// (plan §11.6).
pub fn compute_scenario_but_for_damages(
    actual: &Snapshot,
    but_for_scenario: &Snapshot,
    book: &BookContext,
) -> Result<Vec<Finding>, LanternError> {
    type CellKey = (VId, String, u32);
    let fold_snapshot =
        |snap: &Snapshot| -> Result<BTreeMap<CellKey, (i128, BTreeSet<VId>)>, LanternError> {
            let mut live = snap.live_postings_through(snap.coordinate.effective_through)?;
            live.sort_by_key(|e| e.vid);
            let mut map: BTreeMap<CellKey, (i128, BTreeSet<VId>)> = BTreeMap::new();
            for e in &live {
                for leg in &e.entry.proposal.legs {
                    let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                    let cell = map
                        .entry((leg.account_ref, e.period.clone(), leg.amount.unit.0))
                        .or_default();
                    cell.0 = cell
                        .0
                        .checked_add(signed)
                        .ok_or(LanternError::Overflow("scenario but_for fold"))?;
                    cell.1.insert(e.vid);
                }
            }
            Ok(map)
        };

    let actual_map = fold_snapshot(actual)?;
    let scenario_map = fold_snapshot(but_for_scenario)?;
    let mut keys: BTreeSet<CellKey> = BTreeSet::new();
    for k in actual_map.keys().chain(scenario_map.keys()) {
        keys.insert(k.clone());
    }

    let population = (actual.entries.len() + but_for_scenario.entries.len()).max(1) as u64;
    let mut out = Vec::new();
    for key in keys {
        let (acct_vid, period, unit_id) = &key;
        let actual_net = actual_map.get(&key).map_or(0, |(v, _)| *v);
        let but_for_net = scenario_map.get(&key).map_or(0, |(v, _)| *v);
        if actual_net == but_for_net {
            continue;
        }
        let delta = reconciliation_arithmetic::discrepancy(actual_net, but_for_net)
            .ok_or(LanternError::Overflow("scenario but_for delta"))?;
        let mut cites = vec![Cite::Account(*acct_vid)];
        if actual.periods.contains_key(period) {
            cites.push(Cite::Period(period.clone()));
        }
        if let Some((_, act_entries)) = actual_map.get(&key) {
            for &evid in act_entries {
                if cites.len() < MAX_CITES {
                    cites.push(Cite::Entry(evid));
                }
            }
        }
        let code = actual
            .accounts
            .get(acct_vid)
            .or_else(|| but_for_scenario.accounts.get(acct_vid))
            .map_or("?", |a| a.code.as_str());
        let scale = crate::unit_scale(book, *unit_id)?;
        out.push(finding(
            DamagesButFor::ID,
            Severity::High,
            Statistic {
                name: "but_for_damages_delta".into(),
                value: delta,
                scale,
                population,
            },
            cites,
            format!(
                "account {code} period {period} unit {unit_id}: actual_net={actual_net}, scenario_but_for_net={but_for_net}, damages_delta={delta}"
            ),
        ));
    }
    Ok(out)
}
