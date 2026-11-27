//! Retained confirmation of a replayed, exact bank-line proposal.

use super::*;
use fa_journal::bank::{self as native, BankMatchRecorded};
use fa_registers::reconciliation::normalize_reference;

/// Counts for one statement line before any tentative match consumes a leg.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BankLineEligibility {
    pub cash_legs: usize,
    pub competing_lines: bool,
}

#[derive(Default)]
struct ReviewRow {
    day: i32,
    line_index: usize,
    starts: usize,
    ends: usize,
    contested_starts: usize,
    contested_ends: usize,
}

fn pinned_eligibility<'a>(
    lines: &[BankStatementLine],
    occupied_lines: &BTreeSet<(Oid, u32)>,
    cash_legs: impl Iterator<Item = &'a BookCandidateEntry>,
    unit: UnitId,
    window: i32,
) -> Result<Vec<BankLineEligibility>, BookError> {
    let mut result = vec![BankLineEligibility::default(); lines.len()];
    let mut groups = BTreeMap::<(i128, u8), BTreeMap<String, Vec<ReviewRow>>>::new();
    for (index, line) in lines.iter().enumerate() {
        if occupied_lines.contains(&(line.statement_oid, line.line_ordinal)) {
            continue;
        }
        if line.amount.unit != unit {
            return Err(corrupt(
                "a bank review line has a different unit from the statement",
            ));
        }
        let side = match line.side {
            Side::Credit => Side::Debit,
            Side::Debit => Side::Credit,
        };
        groups
            .entry((line.amount.mantissa, side as u8))
            .or_default()
            .entry(normalize_reference(&line.reference))
            .or_default()
            .push(ReviewRow {
                day: line.booking_date.0,
                line_index: index,
                ..ReviewRow::default()
            });
    }
    for group in groups.values_mut().flat_map(BTreeMap::values_mut) {
        group.sort_unstable_by_key(|row| (row.day, row.line_index));
    }
    for leg in cash_legs {
        if leg.amount.unit != unit {
            return Err(corrupt(
                "a cash review leg has a different unit from the statement",
            ));
        }
        let Some(references) = groups.get_mut(&(leg.amount.mantissa, leg.side as u8)) else {
            continue;
        };
        let reference = normalize_reference(&leg.reference);
        let from = leg.effective_date.0.saturating_sub(window);
        let through = leg.effective_date.0.saturating_add(window);
        // A blank statement reference accepts any cash reference. A named
        // statement reference requires equality; the two sets are disjoint.
        let ranges = [
            Some(""),
            (!reference.is_empty()).then_some(reference.as_str()),
        ]
        .map(|key| {
            let key = key?;
            let rows = references.get(key)?;
            let range = rows.partition_point(|row| row.day < from)
                ..rows.partition_point(|row| row.day <= through);
            (!range.is_empty()).then_some((key, range))
        });
        let competing = ranges
            .iter()
            .flatten()
            .map(|(_, range)| range.len())
            .sum::<usize>()
            > 1;
        // Inclusive start/end counters represent every eligible incidence
        // with two updates, even if all statement lines have the same amount.
        for (key, range) in ranges.into_iter().flatten() {
            let rows = references
                .get_mut(key)
                .ok_or_else(|| corrupt("bank review group disappeared"))?;
            rows[range.start].starts += 1;
            rows[range.end - 1].ends += 1;
            if competing {
                rows[range.start].contested_starts += 1;
                rows[range.end - 1].contested_ends += 1;
            }
        }
    }
    for group in groups.into_values().flat_map(BTreeMap::into_values) {
        let (mut eligible, mut competing) = (0, 0);
        for row in group {
            eligible += row.starts;
            competing += row.contested_starts;
            result[row.line_index] = BankLineEligibility {
                cash_legs: eligible,
                competing_lines: competing > 0,
            };
            eligible -= row.ends;
            competing -= row.contested_ends;
        }
    }
    Ok(result)
}

impl BankMatchReport {
    /// Apply the exact amount, opposite direction, inclusive date window and
    /// normalized reference law to the unoccupied population. Both display
    /// and confirmation evaluate competition before greedy proposal selection.
    pub fn pinned_eligibility(&self) -> Result<Vec<BankLineEligibility>, BookError> {
        let window = i32::try_from(self.date_window_days)
            .map_err(|_| corrupt("the admitted bank date window exceeds i32"))?;
        let consumed: BTreeSet<_> = self.consumed_cash_legs.iter().copied().collect();
        let occupied = self.occupied_bank_lines.iter().copied().collect();
        pinned_eligibility(
            &self.lines,
            &occupied,
            self.candidates
                .iter()
                .filter(|item| {
                    !consumed.contains(&(item.candidate.entry_ref.vid, item.leg_ordinal))
                })
                .map(|item| &item.candidate),
            self.manifest.unit,
            window,
        )
    }
}

/// Select the exact bytes emitted by `match_bank_statement`. The proposer is
/// part of those bytes; current authority and confirmation attribution belong
/// to the capability supplied to `confirm_bank_statement_match`.
#[derive(Clone, Debug)]
pub struct BankConfirmationRequest {
    pub manifest_oid: Oid,
    pub line_ordinal: u32,
    pub proposal_digest: [u8; 32],
    pub source_known_at: CommitSeq,
    pub date_window_days: u32,
    pub proposer: VId,
}

#[derive(Clone, Debug)]
pub struct BankStatusRequest {
    pub manifest_oid: Oid,
    pub known_at: Option<CommitSeq>,
}

/// An inventory of immutable confirmation facts for one retained statement.
/// A later reversal does not erase a confirmation. This is not a complete
/// reconciliation fold or an assertion of the account's closing balance.
#[derive(Clone, Debug)]
pub struct BankConfirmationStatus {
    pub manifest_oid: Oid,
    pub manifest: BankImportManifest,
    pub known_at: CommitSeq,
    pub confirmations: Vec<BankMatchRecorded>,
}

fn selection_refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::BANK_MATCH,
        exit::REFUSAL,
        message,
        "plan §5.7 (a confirmed bank match binds the exact retained source and actual cash leg)",
        "run fa bank match under current full-source authority, review an unambiguous proposal, and pass its exact confirmation_command; an occupied line or leg requires an explicit authorized unmatch before a fresh review can reuse it",
    )
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay the original source closure of every active claim that affects
    /// this statement or its cash search. A claim from another interpretation
    /// remains occupied; it is verified against its own retained manifest.
    /// Released generations do not require source bytes to make a cash leg
    /// available again, while historical reads still verify claims active at
    /// their selected prefix.
    pub(super) async fn verify_bank_match_claim_sources(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        selected_import: (Oid, &BankImportManifest),
        candidates: &[BankMatchCandidate],
        claims: &[BankMatchRecorded],
        seq: CommitSeq,
    ) -> Outcome<()> {
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        let (manifest_oid, manifest) = selected_import;
        let context = self.context().clone();
        let candidate_legs: BTreeSet<_> = candidates
            .iter()
            .map(|candidate| (candidate.candidate.entry_ref.vid, candidate.leg_ordinal))
            .collect();
        // The selected import and its predecessor chain were already fully
        // replayed by match_bank_statement_for before collecting candidates.
        let mut manifests = BTreeMap::from([(manifest_oid, manifest.clone())]);
        let mut selected = Vec::new();
        for claim in claims {
            let confirmation = &claim.confirmation;
            if confirmation.statement_oid != manifest.statement_oid
                && !candidate_legs.contains(&(confirmation.entry_ref.vid, confirmation.leg_ordinal))
            {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(slot) =
                manifests.entry(confirmation.manifest_oid)
            {
                let verified = match self
                    .load_bank_import(cx, capability, confirmation.manifest_oid, seq)
                    .await?
                {
                    Ok(verified) => verified,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                if let Err(refusal) = self
                    .verify_bank_predecessors(cx, capability, &verified, seq)
                    .await?
                {
                    return Ok(Err(refusal));
                }
                slot.insert(verified.manifest);
            }
            selected.push(claim);
        }
        let requests = selected
            .into_iter()
            .map(|claim| {
                manifests
                    .get(&claim.confirmation.manifest_oid)
                    .map(|manifest| (claim, manifest))
                    .ok_or_else(|| corrupt("an active bank claim's original manifest was not loaded"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Err(refusal) = native::verify_bank_match_sources(
            &mut self.db, cx, &context, capability, seq, &requests,
        )
        .await?
        {
            return Ok(Err(refusal));
        }
        self.authorize_bank(cx, capability)
    }

    /// Reopen the retained source, reconstruct the complete pinned proposal,
    /// and publish one native line-to-leg confirmation under current authority.
    /// Exact retries return the original fact even after later journal activity.
    pub async fn confirm_bank_statement_match(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankConfirmationRequest,
    ) -> Outcome<BankMatchRecorded> {
        if let Err(denial) = fa_policy::admit_direct_write(capability) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        let profile = capability.sod_profile();
        if profile != Profile::Human {
            return Ok(Err(fa_journal::policy::refusal(
                &fa_policy::Denial::ApproverProfile {
                    rule: "bank_match_confirmer".into(),
                    approver: capability.holder(),
                    profile,
                    allowed: vec!["Human".into()],
                },
            )));
        }
        let seq = self.query(cx, |db, _| {
            Ok(fa_registers::resolve_known_at(
                db,
                Some(request.source_known_at),
            )?)
        })?;
        let verified = match self
            .load_bank_import(cx, capability, request.manifest_oid, seq)
            .await?
        {
            Ok(verified) => verified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let predecessors = match self
            .verify_bank_predecessors(cx, capability, &verified, seq)
            .await?
        {
            Ok(witnesses) => witnesses,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(index) = verified
            .lines
            .iter()
            .position(|line| line.line_ordinal == request.line_ordinal)
        else {
            return Ok(Err(selection_refusal(
                "the selected line ordinal is absent from the retained statement",
            )));
        };
        let context = self.context().clone();
        let history = match native::bank_match_history(
            &mut self.db,
            cx,
            &context,
            capability,
            None,
            Some(verified.manifest.statement_oid),
        )
        .await?
        {
            Err(refusal) => return Ok(Err(refusal)),
            Ok(history) => history,
        };
        // Search every immutable generation before replaying a fresh report.
        // Retrying an old review after its explicit unmatch returns that same
        // historical fact; it cannot reactivate the released claims.
        if let Some(recorded) = history.confirmations.iter().find(|recorded| {
            let prior = &recorded.confirmation;
            prior.manifest_oid == request.manifest_oid
                && prior.line_ordinal == request.line_ordinal
                && prior.proposal_digest == request.proposal_digest
                && prior.source_known_at == request.source_known_at
                && prior.date_window_days == request.date_window_days
                && prior.proposer == request.proposer
        }) {
            match native::read_bank_match(
                &mut self.db,
                cx,
                &context,
                capability,
                recorded.match_vid,
                None,
                Some(&verified.manifest),
            )
            .await?
            {
                Err(refusal) => return Ok(Err(refusal)),
                Ok(Some(mut original)) => {
                    original.already_recorded = true;
                    return Ok(Ok(original));
                }
                Ok(None) => {
                    return Ok(Err(closure_drift(
                        "an immutable confirmation disappeared during exact retry",
                    )));
                }
            }
        }
        if history.active.iter().any(|recorded| {
            recorded.confirmation.statement_oid == verified.manifest.statement_oid
                && recorded.confirmation.line_ordinal == request.line_ordinal
        }) {
            return Ok(Err(selection_refusal(
                "this bank line still has a different active confirmation; explicitly unmatch it before selecting a fresh proposal",
            )));
        }
        let report = match self
            .match_bank_statement_for(
                cx,
                capability,
                BankMatchRequest {
                    manifest_oid: request.manifest_oid,
                    known_at: Some(seq),
                    date_window_days: request.date_window_days,
                },
                request.proposer,
            )
            .await?
        {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if report.manifest != verified.manifest || report.lines != verified.lines {
            return Ok(Err(closure_drift(
                "the retained source changed while its confirmation was being prepared",
            )));
        }
        let proposal = &report.proposals[index];
        let Some(candidate_ordinal) = proposal.matched_entry_ordinal else {
            return Ok(Err(selection_refusal(
                "the selected bank line has no exact cash-leg proposal",
            )));
        };
        if proposal
            .oid()
            .map_err(|error| corrupt(error.to_string()))?
            .0
            != request.proposal_digest
        {
            return Ok(Err(selection_refusal(
                "the selected proposal digest does not replay at its source coordinate and current policy",
            )));
        }
        let Some(candidate) = usize::try_from(candidate_ordinal)
            .ok()
            .and_then(|ordinal| report.candidates.get(ordinal))
        else {
            return Err(corrupt(
                "the replayed proposal has an invalid cash-leg ordinal",
            ));
        };
        let eligibility = report.pinned_eligibility()?[index];
        if eligibility.cash_legs != 1 || eligibility.competing_lines {
            return Ok(Err(selection_refusal(
                "this proposal is ambiguous before candidate consumption; exact confirmation requires one eligible cash leg and one eligible bank line",
            )));
        }
        let mut line_documents = Vec::with_capacity(verified.manifest.line_oids.len());
        for oid in &verified.manifest.line_oids {
            match self.full_bank_document(cx, capability, *oid).await? {
                Ok(document) => line_documents.push(document),
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        let line_document = line_documents[index].clone();
        // Capture precedes source replay; the kernel retains these original
        // point witnesses through the transaction that publishes the match.
        Ok(native::confirm_bank_match(
            &mut self.db,
            cx,
            &context,
            capability,
            native::BankMatchRequest {
                import: verified.witness,
                predecessors: predecessors.into_iter().skip(1).collect(),
                line: line_document,
                lines: line_documents,
                entry_ref: candidate.candidate.entry_ref,
                leg_ordinal: candidate.leg_ordinal,
                source_known_at: seq,
                date_window_days: request.date_window_days,
                candidate_ordinal,
                proposer: request.proposer,
                proposal_digest: request.proposal_digest,
                decision_card: proposal.decision_card.clone(),
            },
        )
        .await?)
    }

    /// Read the recorded confirmations for every retained line, including
    /// explicit absence at the selected prefix. Native birth checks detect
    /// deleted or relabelled facts; a current-label scan cannot drop them.
    pub async fn bank_confirmation_status(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankStatusRequest,
    ) -> Outcome<BankConfirmationStatus> {
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        let seq = self.query(cx, |db, _| {
            Ok(fa_registers::resolve_known_at(db, request.known_at)?)
        })?;
        let verified = match self
            .load_bank_import(cx, capability, request.manifest_oid, seq)
            .await?
        {
            Ok(verified) => verified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = self
            .verify_bank_predecessors(cx, capability, &verified, seq)
            .await?
        {
            return Ok(Err(refusal));
        }
        let context = self.context().clone();
        let history = match self
            .bank_match_history(
                cx,
                capability,
                Some(seq),
                Some(verified.manifest.statement_oid),
            )
            .await?
        {
            Ok(history) => history,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let confirmations = history.confirmations;
        let requests: Vec<_> = confirmations
            .iter()
            .map(|recorded| (recorded, &verified.manifest))
            .collect();
        if let Err(refusal) = native::verify_bank_match_sources(
            &mut self.db, cx, &context, capability, seq, &requests,
        )
        .await?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(BankConfirmationStatus {
            manifest_oid: request.manifest_oid,
            manifest: verified.manifest,
            known_at: seq,
            confirmations,
        }))
    }

    /// Admit a metadata-only history selector without loading retained
    /// history. Hosts use this before observing or stamping book metadata.
    pub fn admit_bank_match_history(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        known_at: Option<CommitSeq>,
    ) -> Outcome<CommitSeq> {
        self.query(cx, |db, book| {
            Ok(native::admit_bank_match_history(
                db, book, capability, known_at,
            )?)
        })
    }

    /// Verify immutable confirmation and unmatch history at one journal
    /// prefix. This metadata-only read requires current Read and Reconcile
    /// authority, including reach to the explicit prefix, before hydration.
    /// It neither opens governed source bytes nor claims full reconciliation.
    pub async fn bank_match_history(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        known_at: Option<CommitSeq>,
        statement_oid: Option<Oid>,
    ) -> Outcome<BankMatchHistory> {
        let context = self.context().clone();
        Ok(native::bank_match_history(
            &mut self.db,
            cx,
            &context,
            capability,
            known_at,
            statement_oid,
        )
        .await?)
    }

    /// Release exactly one active confirmation through a new immutable
    /// decision. The original match, its source bindings and every monetary
    /// Entry remain retained. Exact retries return the original release.
    pub async fn unmatch_bank_match(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankUnmatchRequest,
    ) -> Outcome<BankUnmatchRecorded> {
        let context = self.context().clone();
        Ok(native::unmatch_bank_match(&mut self.db, cx, &context, capability, request).await?)
    }
}

#[cfg(test)]
mod eligibility_tests {
    use super::*;
    use fa_model::EntryRef;
    use fa_money::Amount;
    use fa_registers::reconciliation::pinned_bank_candidate;

    fn line(index: u32, day: i32, side: Side, value: i128, reference: &str) -> BankStatementLine {
        BankStatementLine {
            statement_oid: Oid([5; 32]),
            statement_seq: 1,
            line_ordinal: index,
            booking_date: DateDay(day),
            value_date: DateDay(day),
            side,
            amount: Amount::new(UnitId(1), value),
            counterparty: String::new(),
            reference: reference.into(),
        }
    }

    fn leg(index: u64, day: i32, side: Side, value: i128, reference: &str) -> BookCandidateEntry {
        BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(u128::from(index)),
                entry_digest: [9; 32],
            },
            entry_ordinal: index,
            effective_date: DateDay(day),
            side,
            amount: Amount::new(UnitId(1), value),
            counterparty: String::new(),
            reference: reference.into(),
        }
    }

    #[test]
    fn review_eligibility_matches_literal_before_consumption_with_wildcards_and_occupied_lines() {
        let days = [i32::MIN, i32::MIN + 1, -2, 0, 1, 3, i32::MAX - 1, i32::MAX];
        let refs = ["", " A ", "a", "b"];
        let lines: Vec<_> = (0..96)
            .map(|i| {
                line(
                    i as u32,
                    days[i % days.len()],
                    if i % 3 == 0 {
                        Side::Debit
                    } else {
                        Side::Credit
                    },
                    5 + (i % 5) as i128,
                    refs[(i / 3) % refs.len()],
                )
            })
            .collect();
        let legs: Vec<_> = (0..150)
            .map(|i| {
                leg(
                    i as u64,
                    days[(i / 3) % days.len()],
                    if i % 4 == 0 {
                        Side::Credit
                    } else {
                        Side::Debit
                    },
                    5 + (i % 7) as i128,
                    refs[i % refs.len()],
                )
            })
            .collect();
        let occupied: BTreeSet<_> = lines
            .iter()
            .step_by(5)
            .map(|line| (line.statement_oid, line.line_ordinal))
            .collect();
        for window in [0, 1, 3, i32::MAX] {
            let got =
                pinned_eligibility(&lines, &occupied, legs.iter(), UnitId(1), window).unwrap();
            let mut expected = vec![BankLineEligibility::default(); lines.len()];
            for leg in &legs {
                let eligible: Vec<_> = lines
                    .iter()
                    .enumerate()
                    .filter(|(_, line)| {
                        !occupied.contains(&(line.statement_oid, line.line_ordinal))
                            && pinned_bank_candidate(line, leg, window).unwrap()
                    })
                    .map(|(index, _)| index)
                    .collect();
                for index in &eligible {
                    expected[*index].cash_legs += 1;
                    expected[*index].competing_lines |= eligible.len() > 1;
                }
            }
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn dense_review_counts_every_eligible_pair_without_materializing_the_pairs() {
        let lines: Vec<_> = (0..1000)
            .map(|i| {
                line(
                    i,
                    15,
                    Side::Credit,
                    100,
                    if i % 2 == 0 { "" } else { "Invoice" },
                )
            })
            .collect();
        let leg = leg(0, 15, Side::Debit, 100, "INVOICE");
        let result = pinned_eligibility(
            &lines,
            &BTreeSet::new(),
            std::iter::repeat_n(&leg, 100_000),
            UnitId(1),
            0,
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                BankLineEligibility {
                    cash_legs: 100_000,
                    competing_lines: true
                };
                1000
            ]
        );
    }
}
