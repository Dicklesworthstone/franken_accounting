//! Cutoff, reconciliation, completeness, and audit procedures (plan §11.4, §11.7;
//! beads fa-nlu, fa-g6rj).

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::attestation::{AttestationClaim, review_vid};
use fa_journal::genesis::BookContext;
use fa_model::rea::SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS;
use fa_model::{
    AccountType, ControlPayload, EntryClass, Erasable, PartyIdentifierUpdate, party_value_vid,
    party_vid,
};
use fa_money::Side;
use fa_time::{DateDay, Weekday};
use fgdb_types::VId;

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
        let mut buckets: BTreeMap<(String, u32), (i128, BTreeSet<VId>, BTreeSet<VId>)> =
            BTreeMap::new();
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
                let signed = match leg.side {
                    Side::Debit => leg.amount.mantissa.unsigned_abs() as i128,
                    Side::Credit => -(leg.amount.mantissa.unsigned_abs() as i128),
                };
                let b = buckets
                    .entry((e.period.clone(), leg.amount.unit.0))
                    .or_default();
                b.0 = b
                    .0
                    .checked_add(signed)
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
            let mag = net.unsigned_abs() as i128;
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
                    let signed = match leg.side {
                        Side::Debit => leg.amount.mantissa.unsigned_abs() as i128,
                        Side::Credit => -(leg.amount.mantissa.unsigned_abs() as i128),
                    };
                    fold_net = fold_net
                        .checked_add(signed)
                        .ok_or(LanternError::Overflow("book_to_book fold sum"))?;
                    matching_entries.push(e.vid);
                }
            }
            if fold_net != claim.mantissa {
                let diff = (fold_net - claim.mantissa).unsigned_abs() as i128;
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

        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let population = live.len() as u64;
        let mut out = Vec::new();

        for e in &live {
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
                    | EntryClass::PRIOR_PERIOD
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
        book: &BookContext,
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
                let pvid = party_vid(book.book_id, &upd.code);
                let pval_vid = party_value_vid(book.book_id, &upd.code);
                updates.push((e.vid, e.recorded_at.0, upd.code, pvid, pval_vid));
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
                if let Erasable::Present(val) = v {
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
                let rvid = review_vid(book.book_id, &ev.document);
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
            let cov_bps = corroborated
                .checked_mul(10_000)
                .ok_or(LanternError::Overflow("confirm coverage bps"))?
                / total;
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
                let unconfirmed_bps = (10_000 - cov_bps) as u64;
                let severity = if cov_bps * 2 < min_coverage_bps {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic::bps("unconfirmed_share_bps", unconfirmed_bps, population),
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

