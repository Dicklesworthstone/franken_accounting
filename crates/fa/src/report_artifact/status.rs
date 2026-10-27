//! Freshness of a retained report's accounting selection, after full replay.
//!
//! A roll-forward's native input is a whole-book closing balance. Its own
//! selection is narrower: selected posted accounts/units through the closing
//! date, including postings before the activity window that change opening
//! stock. Cash-flow families retain that same source schedule. A later entry
//! outside those coordinates does not supersede the selected report merely
//! because the native evidence closure also contains it.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin};
use fa_notary::Journal;

use super::*;
use crate::aging::portfolio::{AgingAccountScope, AgingPortfolio};
use crate::{
    CashFlowBasis, CertificateStatus, GeneralLedger, IndirectCashFlow, ReportOutput,
    ReportSelection,
};

/// Only metadata actually emitted by the selected report can supersede it.
/// Portfolio coverage includes unselected leaves; an indirect report includes
/// every monetary leaf in its cash, income or non-cash source headers.
#[derive(Clone, Copy)]
enum MetadataScope {
    None,
    Account(VId),
    PostingLeaves,
    MonetaryLeaves,
    EquityLeaves,
}

fn stock_selected(
    entry: &Entry,
    through: fa_time::DateDay,
    account_selected: impl Fn(VId) -> bool,
) -> bool {
    !entry.proposal.class.is_control()
        && entry.proposal.effective_date <= through
        && entry
            .proposal
            .legs
            .iter()
            .any(|leg| account_selected(leg.account_ref))
}

fn unchanged(head: CommitSeq, same: bool) -> Result<CertificateStatus, Refusal> {
    if same {
        Ok(CertificateStatus::Current { checked_at: head })
    } else {
        Err(invalid(
            "the selected report changed outside later contributing entries; its metadata or historical inputs differ",
        ))
    }
}

fn same_aging(original: &crate::EffectiveDateAging, current: &crate::EffectiveDateAging) -> bool {
    let mut current = current.clone();
    current.known_at = original.known_at;
    *original == current
}

fn same_reconciliation(
    original: &crate::AgingReconciliation,
    current: &crate::AgingReconciliation,
) -> bool {
    original.account() == current.account()
        && original.control_rows() == current.control_rows()
        && original.rows() == current.rows()
        && same_aging(original.aging(), current.aging())
}

fn same_portfolio(original: &AgingPortfolio, current: &AgingPortfolio) -> bool {
    let mut request = current.request().clone();
    request.known_at = original.request().known_at;
    original.book_id() == current.book_id()
        && original.request() == &request
        && original.uncovered_accounts() == current.uncovered_accounts()
        && original.accounts().len() == current.accounts().len()
        && original
            .accounts()
            .iter()
            .zip(current.accounts())
            .all(|(before, after)| same_reconciliation(before, after))
}

fn same_ledger(original: &GeneralLedger, current: &GeneralLedger) -> bool {
    original.book_id() == current.book_id()
        && original.branch_id() == current.branch_id()
        && original.label() == current.label()
        && original.effective_from() == current.effective_from()
        && original.effective_through() == current.effective_through()
        && original.accounts() == current.accounts()
        && original.units() == current.units()
        && original.buckets() == current.buckets()
        && original.cells() == current.cells()
        && original.lines() == current.lines()
}

/// Compare every original basis field, ignoring only the native known-at.
fn same_cash_basis(original: &CashFlowBasis, current: &CashFlowBasis) -> bool {
    if !same_ledger(original.source(), current.source()) {
        return false;
    }
    match (original, current) {
        (CashFlowBasis::Explicit(before), CashFlowBasis::Explicit(after)) => {
            before.definition() == after.definition() && before.units() == after.units()
        }
        (CashFlowBasis::Policy(before), CashFlowBasis::Policy(after)) => {
            before.policy() == after.policy()
                && before.decisions() == after.decisions()
                && before.report().definition() == after.report().definition()
                && before.report().units() == after.report().units()
        }
        (CashFlowBasis::Split(before), CashFlowBasis::Split(after)) => {
            before.definition() == after.definition() && before.units() == after.units()
        }
        _ => false,
    }
}

fn same_indirect(original: &IndirectCashFlow, current: &IndirectCashFlow) -> bool {
    let mut income = current.income().clone();
    income.known_at = original.income().known_at;
    same_cash_basis(original.cash(), current.cash())
        && original.income() == &income
        && match (original.non_cash_source(), current.non_cash_source()) {
            (Some(before), Some(after)) => same_ledger(before, after),
            (None, None) => true,
            _ => false,
        }
        && original.definition() == current.definition()
        && original.contributions() == current.contributions()
        && original.units() == current.units()
}

#[derive(PartialEq, Eq)]
enum AccountMetadata {
    Complete(fa_journal::rows::AccountRow),
    Presentation(fa_statements::Account),
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Verify the complete artifact under current read authority, then identify
    /// later journal entries affecting its accounting selection. Historical
    /// replay remains valid when a report is SupersededBy; this method writes
    /// nothing. Recipient-dependent families require the same independently
    /// retained request/definition as replay, even when a digest is supplied.
    ///
    /// Supports native reports, statement comparisons/traces, roll-forwards
    /// (including their GL detail view), effective-date aging and its control
    /// reconciliations/portfolios, and direct, indirect, split and policy cash flow.
    /// Other families refuse until their distinct relevance law is implemented.
    /// In particular, a historical draft rehearsal is never declared Current
    /// from its trunk trial-balance certificate alone; its full replay uses the
    /// sync facade and this slice supplies no draft freshness verdict.
    pub fn report_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
        expected: ReportArtifactExpectation<'_>,
    ) -> Outcome<CertificateStatus> {
        if let Err(refusal) = self.replay_report_artifact_for(
            cx,
            principal,
            capability,
            bytes,
            expected_digest,
            expected,
        )? {
            return Ok(Err(refusal));
        }
        let artifact = match ReportArtifact::decode(bytes) {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = match &artifact.inner {
            Artifact::Native(_) | Artifact::StatementDiff(_) | Artifact::StatementTrace(_) => {
                return self.certificate_status(cx, artifact.source_certificate());
            }
            Artifact::RollForward(c) => c.as_ref(),
            Artifact::CashFlow(c) => c.source_certificate(),
            Artifact::SplitCashFlow(c) => c.source_certificate(),
            Artifact::PolicyCashFlow(c) => c.certificate.source_certificate().source_certificate(),
            Artifact::Aging(c) => {
                return self.aging_artifact_status(cx, principal, capability, c);
            }
            Artifact::DueDateAging(c) => {
                return self.due_date_aging_artifact_status(cx, principal, capability, c);
            }
            Artifact::AgingReconciliation(c) => {
                return self.aging_reconciliation_artifact_status(cx, principal, capability, c);
            }
            Artifact::AgingPortfolio(c) => {
                return self.aging_portfolio_artifact_status(cx, principal, capability, c);
            }
            Artifact::EquityRollForward(c) => {
                return self.equity_artifact_status(cx, principal, capability, c);
            }
            Artifact::ExternalFeed(c) => {
                return self.external_feed_certificate_status(cx, principal, capability, c);
            }
            Artifact::NativeSubledger(c) => {
                return self.native_subledger_certificate_status(cx, principal, capability, c);
            }
            Artifact::IndirectCashFlow(c) => {
                let ReportArtifactExpectation::IndirectCashFlow(request) = expected else {
                    return Ok(Err(expectation_required(artifact.family())));
                };
                return self
                    .indirect_cash_flow_artifact_status(cx, principal, capability, c, request);
            }
            Artifact::Query(_) => {
                return Ok(Err(invalid(
                    "a query certificate replayed; its freshness compares the statement's result at the head, which query_certificate_status reports (fa certificate status)",
                )));
            }
            _ => {
                return Ok(Err(invalid(format!(
                    "{} certificate replayed, but its accounting-selection freshness law is not implemented; use its historical replay result",
                    artifact.family().name(),
                ))));
            }
        };
        self.roll_forward_artifact_status(cx, principal, capability, source)
    }

    fn equity_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &crate::EquityRollForwardCertificate,
    ) -> Outcome<CertificateStatus> {
        let head = self.head(cx)?;
        let mut request = certificate.request().clone();
        let accounts: BTreeSet<_> = certificate
            .source_certificate()
            .request()
            .accounts
            .iter()
            .copied()
            .collect();
        let units: BTreeSet<_> = request.units.iter().copied().collect();
        let later_entries = match self.later_artifact_entries(
            cx,
            certificate.known_at(),
            head,
            MetadataScope::EquityLeaves,
            |entry, _| {
                Ok(entry.proposal.class != EntryClass::PENDING
                    && stock_selected(entry, request.effective_through, |account| {
                        accounts.contains(&account)
                    })
                    && entry.proposal.legs.iter().any(|leg| {
                        accounts.contains(&leg.account_ref)
                            && units.contains(&leg.amount.unit.0)
                            && leg.amount.mantissa != 0
                    }))
            },
        )? {
            Ok(entries) => entries,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !later_entries.is_empty() {
            return Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries,
            }));
        }
        request.known_at = Some(head);
        let mut current = match self.equity_roll_forward(cx, principal, capability, &request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(invalid(refusal.message))),
        };
        current.statement.known_at = certificate.known_at().0;
        let bytes = match current.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(unchanged(head, bytes == certificate.output()))
    }

    fn aging_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingCertificate,
    ) -> Outcome<CertificateStatus> {
        let request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let head = self.head(cx)?;
        let later_entries = match self.later_artifact_entries(
            cx,
            certificate.source().known_at,
            head,
            MetadataScope::None,
            |entry, entries| {
                if entry.proposal.effective_date > request.effective_through {
                    return Ok(false);
                }
                crate::certificate::open_item_selected(entry, entries, request.account)
            },
        )? {
            Ok(entries) => entries,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !later_entries.is_empty() {
            return Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries,
            }));
        }
        let original =
            match self.replay_effective_date_aging(cx, principal, capability, certificate)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let current = self.effective_date_aging(
            cx,
            request.account,
            request.effective_through,
            Some(head),
            &request.buckets,
        )?;
        Ok(unchanged(head, same_aging(&original, &current)))
    }

    fn due_date_aging_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &DueDateAgingCertificate,
    ) -> Outcome<CertificateStatus> {
        let request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let head = self.head(cx)?;
        let later_entries = match self.later_artifact_entries(
            cx,
            certificate.source().known_at,
            head,
            MetadataScope::None,
            |entry, entries| {
                if entry.proposal.effective_date > request.effective_through {
                    return Ok(false);
                }
                crate::certificate::open_item_selected(entry, entries, request.account)
            },
        )? {
            Ok(entries) => entries,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !later_entries.is_empty() {
            return Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries,
            }));
        }
        let original = match self.replay_due_date_aging(cx, principal, capability, certificate)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut current = self.due_date_aging(
            cx,
            request.account,
            request.effective_through,
            Some(head),
            &request.buckets,
        )?;
        current.known_at = original.known_at;
        Ok(unchanged(head, original == current))
    }

    fn aging_reconciliation_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingReconciliationCertificate,
    ) -> Outcome<CertificateStatus> {
        let mut request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let head = self.head(cx)?;
        let later_entries = match self.later_artifact_entries(
            cx,
            certificate.control_source().known_at,
            head,
            MetadataScope::Account(request.account),
            |entry, _| {
                Ok(stock_selected(
                    entry,
                    request.effective_through,
                    |account| account == request.account,
                ))
            },
        )? {
            Ok(entries) => entries,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !later_entries.is_empty() {
            return Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries,
            }));
        }
        let original = match self.replay_effective_date_aging_reconciliation(
            cx,
            principal,
            capability,
            certificate,
            &request,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        request.known_at = Some(head);
        let current =
            match self.reconcile_effective_date_aging(cx, principal, capability, &request)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(invalid(refusal.message))),
            };
        Ok(unchanged(head, same_reconciliation(&original, &current)))
    }

    fn aging_portfolio_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingPortfolioCertificate,
    ) -> Outcome<CertificateStatus> {
        let mut request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let head = self.head(cx)?;
        let later_entries = match self.later_artifact_entries(
            cx,
            certificate.control_source().known_at,
            head,
            MetadataScope::PostingLeaves,
            |entry, _| {
                Ok(stock_selected(
                    entry,
                    request.effective_through,
                    |account| match &request.scope {
                        AgingAccountScope::AllPosting => true,
                        AgingAccountScope::Selected(accounts) => accounts.contains(&account),
                    },
                ))
            },
        )? {
            Ok(entries) => entries,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !later_entries.is_empty() {
            return Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries,
            }));
        }
        let original =
            match self.replay_aging_portfolio(cx, principal, capability, certificate, &request)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        request.known_at = Some(head);
        let current = match self.reconcile_aging_portfolio(cx, principal, capability, &request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(invalid(refusal.message))),
        };
        Ok(unchanged(head, same_portfolio(&original, &current)))
    }

    fn indirect_cash_flow_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &IndirectCashFlowCertificate,
        request: &IndirectCashFlowRequest,
    ) -> Outcome<CertificateStatus> {
        let original = match self.replay_indirect_cash_flow(
            cx,
            principal,
            capability,
            certificate,
            request,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let head = self.head(cx)?;
        let source = original.cash().source();
        let accounts: BTreeSet<_> = source
            .accounts()
            .iter()
            .chain(
                original
                    .non_cash_source()
                    .into_iter()
                    .flat_map(|detail| detail.accounts()),
            )
            .map(|account| VId(account.id))
            .collect();
        let units: BTreeSet<_> = source.units().iter().copied().collect();
        let income_selection = ReportSelection::Statement(Box::new(crate::StatementSelection {
            definition: match crate::StatementDefinition::decode(
                &original.income().definition_bytes,
            ) {
                Ok(definition) => definition,
                Err(error) => return Ok(Err(invalid(error.to_string()))),
            },
            periods: certificate.income_periods().to_vec(),
            comparative: Vec::new(),
        }));
        let income = ReportOutput::Statement(Box::new(original.income().clone()));
        let later_entries = match self.later_artifact_entries(
            cx,
            certificate.known_at(),
            head,
            MetadataScope::MonetaryLeaves,
            |entry, entries| {
                // The indirect output retains opening stock and all non-cash
                // source detail, even legs not chosen as explicit adjustments.
                let detail = entry.proposal.class != EntryClass::PENDING
                    && stock_selected(entry, request.cash.effective_through, |account| {
                        accounts.contains(&account)
                    })
                    && entry.proposal.legs.iter().any(|leg| {
                        accounts.contains(&leg.account_ref)
                            && units.contains(&leg.amount.unit.0)
                            && leg.amount.mantissa != 0
                    });
                Ok(detail
                    || crate::certificate::selected(
                        self.context(),
                        &income_selection,
                        &income,
                        entry,
                        entries,
                    )?)
            },
        )? {
            Ok(entries) => entries,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !later_entries.is_empty() {
            return Ok(Ok(CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries,
            }));
        }
        let mut current_request = request.clone();
        current_request.cash.known_at = Some(head);
        let current = match self.indirect_cash_flow(cx, principal, capability, &current_request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(invalid(refusal.message))),
        };
        Ok(unchanged(head, same_indirect(&original, &current)))
    }

    /// The whole artifact has already replayed under current whole-book read
    /// authority. Attribute changes to immutable publications, not mutable
    /// projections, the size of its native closure, or its current net total.
    fn later_artifact_entries(
        &self,
        cx: &PurposeContexts,
        known_at: CommitSeq,
        head: CommitSeq,
        metadata_scope: MetadataScope,
        selected: impl Fn(&Entry, &BTreeMap<VId, Entry>) -> Result<bool, BookError>,
    ) -> Outcome<Vec<VId>> {
        self.query(cx, |db, book| {
            let query = cx.query();
            let journal = match Journal::read(db, book, Some(head), None)? {
                Ok(journal) => journal,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let mut entries = BTreeMap::new();
            for leaf in &journal.leaves {
                query.checkpoint().map_err(BookError::Context)?;
                entries.insert(
                    leaf.vid,
                    Entry::decode(&leaf.payload).map_err(KernelError::from)?,
                );
            }
            let metadata = |at| -> Result<Vec<AccountMetadata>, BookError> {
                if matches!(metadata_scope, MetadataScope::None) {
                    return Ok(Vec::new());
                }
                let chart = fa_journal::chart::read_at(db, book, at)?;
                let mut projected = Vec::new();
                for account in chart.accounts().values() {
                    query.checkpoint().map_err(BookError::Context)?;
                    let include = match metadata_scope {
                        MetadataScope::None => false,
                        MetadataScope::Account(id) => account.vid == id,
                        MetadataScope::PostingLeaves => account.is_leaf,
                        MetadataScope::MonetaryLeaves => {
                            account.is_leaf && (1..=5).contains(&account.account_type)
                        }
                        MetadataScope::EquityLeaves => {
                            account.is_leaf && (3..=5).contains(&account.account_type)
                        }
                    };
                    if include {
                        projected.push(
                            if matches!(
                                metadata_scope,
                                MetadataScope::MonetaryLeaves | MetadataScope::EquityLeaves
                            ) {
                                AccountMetadata::Presentation(fa_statements::Account {
                                    id: account.vid.0,
                                    code: account.code.clone(),
                                    name: account.name.clone(),
                                    account_type: account.account_type,
                                    is_leaf: account.is_leaf,
                                })
                            } else {
                                AccountMetadata::Complete(account.clone())
                            },
                        );
                    }
                }
                Ok(projected)
            };
            let mut previous_metadata = metadata(known_at)?;
            let mut metadata_changes = BTreeMap::new();
            let mut visibility = BTreeMap::new();
            let mut later_entries = Vec::new();
            for leaf in &journal.leaves {
                query.checkpoint().map_err(BookError::Context)?;
                if leaf.envelope.commit_seq <= known_at {
                    continue;
                }
                let entry = &entries[&leaf.vid];
                let mut relevant = selected(entry, &entries)?
                    && fa_journal::migration::visible_at(db, entry, head, &mut visibility)?;
                if entry.proposal.class == EntryClass::RESOLUTION
                    && let Some(target) = entry
                        .proposal
                        .pending
                        .as_ref()
                        .and_then(|pending| pending.resolution_of)
                    && let Some(original) = entries.get(&target.vid)
                {
                    relevant |= selected(original, &entries)?;
                }
                if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) =
                    &entry.proposal.control
                    && *kind == fa_journal::migration::kind::FINALIZE
                {
                    for migrated in entries.values() {
                        query.checkpoint().map_err(BookError::Context)?;
                        if matches!(&migrated.proposal.origin,
                            EntryOrigin::Migration { run_ref: origin, .. } if origin == run_ref)
                            && selected(migrated, &entries)?
                            && fa_journal::migration::visible_at(
                                db,
                                migrated,
                                head,
                                &mut visibility,
                            )?
                        {
                            relevant = true;
                        }
                    }
                }
                if entry.proposal.class == EntryClass::SCHEMA_CONTROL {
                    let changed =
                        if let Some(changed) = metadata_changes.get(&leaf.envelope.commit_seq) {
                            *changed
                        } else {
                            let current = metadata(leaf.envelope.commit_seq)?;
                            let changed = current != previous_metadata;
                            previous_metadata = current;
                            metadata_changes.insert(leaf.envelope.commit_seq, changed);
                            changed
                        };
                    relevant |= changed;
                }
                if relevant {
                    later_entries.push(leaf.vid);
                }
            }
            Ok(Ok(later_entries))
        })
    }

    /// `certificate` belongs to an artifact already replayed in full. Compare
    /// the actual selected schedule as well as enumerating its new causes, so
    /// an unexplained metadata or historical-row change cannot return Current.
    fn roll_forward_artifact_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &RollForwardCertificate,
    ) -> Outcome<CertificateStatus> {
        let head = self.head(cx)?;
        let mut request = certificate.request().clone();
        request.known_at = Some(head);
        let mut current = match self.roll_forward(cx, principal, capability, &request)? {
            Ok(report) => report,
            Err(refusal) => {
                return Ok(Err(invalid(format!(
                    "the current selected account schedule no longer evaluates: {}",
                    refusal.message,
                ))));
            }
        };
        // Recorded time is the one expected difference in an unchanged report.
        // Do not normalize dates, scope, account metadata, amounts or citations.
        current.known_at = certificate.known_at().0;
        let current_bytes = current
            .canonical_bytes()
            .map_err(|error| BookError::Kernel(KernelError::Model(error.into())))?;
        self.query(cx, |db, book| {
            let query = cx.query();
            let journal = match Journal::read(db, book, Some(head), None)? {
                Ok(journal) => journal,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let mut entries = BTreeMap::new();
            for leaf in &journal.leaves {
                query.checkpoint().map_err(BookError::Context)?;
                entries.insert(leaf.vid, Entry::decode(&leaf.payload).map_err(KernelError::from)?);
            }
            let accounts: BTreeSet<_> = request.accounts.iter().copied().collect();
            let units: BTreeSet<_> = request.units.iter().copied().collect();
            let selected = |entry: &Entry| {
                let proposal = &entry.proposal;
                !proposal.class.is_control()
                    && proposal.class != EntryClass::PENDING
                    && proposal.effective_date <= request.effective_through
                    && proposal.legs.iter().any(|leg| {
                        accounts.contains(&leg.account_ref)
                            && units.contains(&leg.amount.unit.0)
                            && leg.amount.mantissa != 0
                    })
            };
            let mut visibility = BTreeMap::new();
            let mut later_entries = Vec::new();
            for leaf in &journal.leaves {
                query.checkpoint().map_err(BookError::Context)?;
                if leaf.envelope.commit_seq <= certificate.known_at() {
                    continue;
                }
                let entry = &entries[&leaf.vid];
                let mut relevant = selected(entry)
                    && fa_journal::migration::visible_at(db, entry, head, &mut visibility)?;
                // Staging a migration is invisible. Finalization can make an
                // older staged entry contribute, so the later cause is the
                // immutable finalization control, not the staging sequence.
                if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) =
                    &entry.proposal.control
                    && *kind == fa_journal::migration::kind::FINALIZE
                {
                    for migrated in entries.values() {
                        query.checkpoint().map_err(BookError::Context)?;
                        if matches!(&migrated.proposal.origin,
                            EntryOrigin::Migration { run_ref: origin, .. } if origin == run_ref)
                            && selected(migrated)
                            && fa_journal::migration::visible_at(db, migrated, head, &mut visibility)?
                        {
                            relevant = true;
                        }
                    }
                }
                if relevant {
                    later_entries.push(leaf.vid);
                }
            }
            if !later_entries.is_empty() {
                return Ok(Ok(CertificateStatus::SupersededBy {
                    checked_at: head,
                    later_entries,
                }));
            }
            if current_bytes != certificate.output() {
                return Ok(Err(invalid(
                    "the selected account schedule changed outside later contributing entries; its metadata or historical contributions differ",
                )));
            }
            Ok(Ok(CertificateStatus::Current { checked_at: head }))
        })
    }
}
