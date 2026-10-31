//! Foreign-currency valuation from retained Rate evidence (plan §5.2 / §6.4).
//!
//! Rates enter through the authenticated evidence-upload path. Their source
//! and retrieval metadata are the uploader's assertions, not a verified
//! provider transcript. Valuation reads the exact retained documents under
//! current authority and writes nothing; ordinary posting independently
//! re-verifies the resulting amounts and evidence inside its transaction.
//! Functional period activity folds those immutable committed valuations.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_journal::fx::RATE_DOCUMENT_KIND;
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{DocumentAdded, DocumentRead, UploadRequest};
use fa_model::{EntryPayload, Oid};
use fa_money::rate::ArithmeticBudget;
use fa_money::{UnitKind, UnitRegistry};
use fa_policy::{Capability, Observes, Op, Reach};
use fa_registers::{FunctionalFold, FunctionalStockFold};
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, IntakeAction, Outcome};

pub use fa_journal::carrying::{
    FxSettlementItem, FxSettlementRequest, MAX_FX_SETTLEMENT_ITEMS, PreparedFxSettlement,
    PreparedFxSettlementGroup,
};
pub use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms};

/// The canonical Rate document's media type; its bytes use the native codec.
pub const FX_RATE_MIME: &str = "application/vnd.franken.fx-rate.v1";

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §5.2 / §6.4; registries/fx_laws.toml (rates are retained evidence)",
        "upload a canonical Rate document, then name its D:oid under SpotClose or PeriodAverage; do not supply base amounts or an unretained rate",
    )
}

fn currency_units(rate: &FxRateDocument, units: &UnitRegistry) -> Result<(), Refusal> {
    for (name, id) in [
        ("base_unit", rate.base_unit),
        ("quote_unit", rate.quote_unit),
    ] {
        if !units
            .get(id)
            .is_some_and(|unit| matches!(unit.kind, UnitKind::Currency { .. }))
        {
            return Err(invalid(format!(
                "FX rate {name} {} must name a currency in this book's unit table",
                id.0
            )));
        }
    }
    Ok(())
}

fn average_date(proposal: &EntryPayload, calendar: &FiscalCalendar) -> Result<DateDay, Refusal> {
    if proposal
        .effective_period
        .as_ref()
        .is_some_and(|period| period.calendar != calendar.id)
    {
        return Err(invalid("the FX proposal names a different fiscal calendar"));
    }
    let fiscal_year = calendar
        .fiscal_year_of(proposal.effective_date)
        .map_err(|error| {
            invalid(format!(
                "cannot resolve the FX posting fiscal year: {error}"
            ))
        })?;
    let periods = calendar
        .periods_for_year(fiscal_year)
        .map_err(|error| invalid(format!("cannot resolve the FX posting periods: {error}")))?;
    let period = fa_time::resolve_period(
        &periods,
        proposal.effective_date,
        proposal
            .effective_period
            .as_ref()
            .map(|period| period.code.as_str()),
    )
    .map_err(|error| invalid(format!("cannot resolve the FX posting period: {error}")))?;
    period.end.pred().map_err(|error| {
        invalid(format!(
            "cannot resolve the FX period's last civil day: {error}"
        ))
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Recompute retained FX laws at one captured prefix, loading the native
    /// history needed by source-bound carrying and revaluation after reopen.
    /// Current whole-book Read and Verify authority precede that loading and
    /// are checked again before disclosing the result. No journal row changes.
    pub async fn verify_fx_conversions_with_history(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        known_at: Option<CommitSeq>,
    ) -> Outcome<fa_journal::FxConversionVerification> {
        if let Err(denial) = fa_policy::require(capability, Op::Verify, "verifying FX conversions")
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let selected = match self
            .prepare_functional_report(cx, capability.holder(), capability, known_at, false)
            .await?
        {
            Ok(selected) => selected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = self.verify_fx_conversions(cx, Some(selected))?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), false, Some(selected))?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(result))
    }

    /// Read one functional trial balance with its historical display accounts.
    /// Like the existing functional folds, this uses committed base amounts;
    /// it does not require the original Rate bodies to remain disclosed. Use
    /// certification to independently verify those retained valuation sources.
    pub async fn functional_trial_balance(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        selection: crate::TrialBalanceSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::FunctionalTrialBalance> {
        let at = match self
            .prepare_functional_report(cx, capability.holder(), capability, known_at, false)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, at)?;
            fa_journal::entry_history::verify_entry_history(db, cx, book, Some(at))?;
            crate::functional_trial_balance::report_at(db, book, &selection, at)
        })?;
        if let Err(refusal) =
            self.admit_functional_report(cx, capability.holder(), capability, Some(at), false)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Certify one functional stock or activity trial balance under current
    /// whole-book Read and Produce authority. Every original Rate document and
    /// registered valuation is independently replayed before output is sealed.
    pub async fn certify_functional_trial_balance(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        selection: crate::TrialBalanceSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedReport> {
        let at = match self
            .prepare_functional_report(cx, capability.holder(), capability, known_at, true)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !crate::functional_trial_balance::supported_selection(&selection) {
            return Ok(Err(crate::functional_trial_balance::invalid_selection()));
        }
        let result = self.certify_report(
            cx,
            crate::ReportSelection::FunctionalTrialBalance(selection),
            Some(at),
        )?;
        if let Err(refusal) =
            self.admit_functional_report(cx, capability.holder(), capability, Some(at), true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Certify the original TimeEvidence brackets as well as the resolved
    /// functional trial-balance prefix. Replay never substitutes today's clock.
    pub async fn certify_functional_trial_balance_at_instant(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        selection: crate::TrialBalanceSelection,
        requested_utc_ns: u64,
    ) -> Outcome<crate::CertifiedReport> {
        if let Err(refusal) = self
            .prepare_functional_report(cx, capability.holder(), capability, None, true)
            .await?
        {
            return Ok(Err(refusal));
        }
        if !crate::functional_trial_balance::supported_selection(&selection) {
            return Ok(Err(crate::functional_trial_balance::invalid_selection()));
        }
        let result = self.certify_report_at_instant(
            cx,
            crate::ReportSelection::FunctionalTrialBalance(selection),
            requested_utc_ns,
        )?;
        if let Err(refusal) =
            self.admit_functional_report(cx, capability.holder(), capability, None, true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    fn authorize_fx_read(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        principal: VId,
        valuation: bool,
        known_at: Option<CommitSeq>,
    ) -> Outcome<CommitSeq> {
        let mut reach = Reach::whole_book(true);
        if let Some(selected) = known_at {
            reach.observes = Observes::At(selected);
        }
        let admission = fa_policy::admit_read(capability, principal, self.context().book_id)
            .and_then(|()| {
                if valuation {
                    fa_policy::require(capability, Op::Post, "preparing an FX-valued posting")
                } else {
                    Ok(())
                }
            })
            .and_then(|()| fa_policy::reach(capability, &reach, None));
        if let Err(denial) = admission {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        self.query(cx, |db, book| {
            Ok(fa_journal::policy::current_at(db, book, capability)?.map(|current| current.at()))
        })
    }

    /// Upload a typed Rate document as the authenticated session holder.
    /// The existing intake kernel derives HumanUpload or AgentUpload from
    /// that holder's profile and retains the original grade on exact retries.
    /// A source name and retrieval instant never confer connector provenance.
    pub async fn upload_fx_rate(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        rate: &FxRateDocument,
    ) -> Outcome<DocumentAdded> {
        if let Err(refusal) = self.preflight_intake(cx, capability, IntakeAction::Upload)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = currency_units(rate, &self.context().units) {
            return Ok(Err(refusal));
        }
        let bytes = match rate.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.upload_document(
            cx,
            capability,
            UploadRequest {
                kind: RATE_DOCUMENT_KIND,
                mime: FX_RATE_MIME.into(),
                bytes,
                asserted_grade: None,
            },
        )
        .await
    }

    /// Compute base valuations exclusively from fully retained Rate documents.
    /// The caller owns the exact-arithmetic meter and its cancellation context.
    /// This does not post, approve, or reserve authority: `post` and `plan`
    /// still run the ordinary kernel, including transactional rate replay.
    /// Existing base amounts are refused rather than silently overwritten.
    #[allow(clippy::too_many_arguments)]
    pub async fn value_fx_proposal(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        proposal: EntryPayload,
        law: FxLawId,
        rate_oids: &[Oid],
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<EntryPayload> {
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, proposal.principal_ref, true, None)?
        {
            return Ok(Err(refusal));
        }
        if proposal.book_id != self.context().book_id {
            return Ok(Err(invalid("the FX proposal names a different book")));
        }
        if !matches!(
            law,
            FxLawId::SpotClose | FxLawId::PeriodAverage | FxLawId::SettlementSpotCarrying
        ) {
            return Ok(Err(invalid(
                "this valuation path supports SpotClose, PeriodAverage and SettlementSpotCarrying; carrying agreement is checked by the posting kernel",
            )));
        }
        if proposal.base_totals.is_some()
            || proposal.legs.iter().any(|leg| leg.base_amount.is_some())
        {
            return Ok(Err(invalid(
                "an FX proposal must omit caller-supplied base_amount and base_totals",
            )));
        }
        let classes = fa_registry::EntryClasses::embedded()?;
        let laws = fa_registry::FxLaws::embedded(&classes)?;
        let class = proposal.class.name().unwrap_or("unregistered");
        let Some(registered_law) = laws.laws.iter().find(|row| {
            row.id == law.id()
                && row.version == law.version()
                && row.status == "live"
                && row.admitted_classes.iter().any(|allowed| allowed == class)
        }) else {
            return Ok(Err(invalid(format!(
                "FX law {} does not admit entry class {class}",
                law.name()
            ))));
        };
        if rate_oids.is_empty() || rate_oids.len() > fa_model::limits::MAX_RATE_DOCS {
            return Ok(Err(invalid(format!(
                "FX valuation requires between 1 and {} retained Rate documents",
                fa_model::limits::MAX_RATE_DOCS
            ))));
        }
        let unique: BTreeSet<_> = rate_oids.iter().copied().collect();
        if unique.len() != rate_oids.len() {
            return Ok(Err(invalid("a Rate document was selected more than once")));
        }

        // Context compatibility can require the retained Book creation when
        // a book predates additive registry rows. The loader publishes nothing.
        if let Err(refusal) = self
            .prepare_report_history(cx, capability.holder(), capability, None)
            .await?
        {
            return Ok(Err(refusal));
        }
        let selected =
            match self.authorize_fx_read(cx, capability, proposal.principal_ref, true, None)? {
                Ok(selected) => selected,
                Err(refusal) => return Ok(Err(refusal)),
            };
        self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, selected)
        })?;
        let spec = self.spec(cx)?;
        let average_as_of = if law == FxLawId::PeriodAverage {
            match average_date(&proposal, &spec.calendar) {
                Ok(date) => Some(date),
                Err(refusal) => return Ok(Err(refusal)),
            }
        } else {
            None
        };
        let mut rates = Vec::with_capacity(unique.len());
        for oid in unique {
            let document = match self.read_document_for(cx, capability, &oid).await? {
                Ok(DocumentRead::Full(document)) => document,
                Ok(DocumentRead::Redacted(_)) => {
                    return Ok(Err(Refusal::new(
                        code::CAPABILITY,
                        exit::SAFETY,
                        "FX valuation requires the complete retained Rate document",
                        "plan §6.4 / §9.6 (governed source bytes, never a redacted-rate inference)",
                        "use a capability permitted to read the complete Rate document under its governing redaction contract",
                    )));
                }
                Err(refusal) => return Ok(Err(refusal)),
            };
            if document.book_id != self.context().book_id
                || document.kind != RATE_DOCUMENT_KIND
                || document.mime != FX_RATE_MIME
                || document.oid() != oid
            {
                return Ok(Err(invalid(
                    "the selected document is not this book's canonical Rate evidence",
                )));
            }
            let rate = match FxRateDocument::decode(&document.bytes) {
                Ok(rate) => rate,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = currency_units(&rate, &self.context().units) {
                return Ok(Err(refusal));
            }
            if rate.rounding.name() != registered_law.rounding_law {
                return Ok(Err(invalid(format!(
                    "FX law {} requires {} rounding; the selected Rate document uses {}",
                    law.name(),
                    registered_law.rounding_law,
                    rate.rounding.name()
                ))));
            }
            if let Some(expected) = average_as_of
                && rate.as_of != expected
            {
                return Ok(Err(invalid(format!(
                    "PeriodAverage Rate as_of {} must equal the posting period's last included day {}",
                    rate.as_of.render(),
                    expected.render()
                ))));
            }
            match rate.oid(self.context().book_id) {
                Ok(expected) if expected == oid => {}
                Ok(_) => {
                    return Ok(Err(invalid(
                        "Rate evidence has a different canonical identity",
                    )));
                }
                Err(refusal) => return Ok(Err(refusal)),
            }
            rates.push(rate);
        }
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, proposal.principal_ref, true, None)?
        {
            return Ok(Err(refusal));
        }
        let evaluation = cx.merge_eval();
        evaluation.checkpoint().map_err(BookError::Context)?;
        let result = evaluation.with_restriction(|| {
            fa_journal::fx::value_proposal(
                budget,
                proposal,
                &spec,
                &self.context().units,
                law,
                &rates,
            )
        });
        evaluation.checkpoint().map_err(BookError::Context)?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), true, None)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Prepare a foreign open-item settlement from its retained carrying
    /// history and an explicitly selected Rate document. The cash amount is
    /// an assertion checked against that rate, never a balancing plug.
    /// Current whole-book Read and Post authority precede source observation;
    /// the ordinary posting kernel independently repeats the relief check.
    pub async fn prepare_fx_settlement(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: &FxSettlementRequest,
        template: EntryPayload,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<PreparedFxSettlement> {
        if let Err(refusal) = self
            .prepare_fx_settlement_source(cx, capability, request.rate_document, &template)
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = fa_journal::carrying::prepare_fx_settlement(
            &self.db,
            cx,
            &self.context,
            capability,
            request,
            template,
            budget,
        )?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), true, None)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Rehearse several distinct foreign items as one entry, using one
    /// explicitly shared retained rate and each item's exact carrying basis.
    pub async fn prepare_fx_settlement_group(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        requests: &[FxSettlementRequest],
        template: EntryPayload,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<PreparedFxSettlementGroup> {
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, template.principal_ref, true, None)?
        {
            return Ok(Err(refusal));
        }
        if requests.is_empty() || requests.len() > MAX_FX_SETTLEMENT_ITEMS {
            return Ok(Err(invalid(
                "FX group is empty or exceeds the entry leg work bound",
            )));
        }
        if requests
            .iter()
            .any(|request| request.rate_document != requests[0].rate_document)
        {
            return Ok(Err(invalid(
                "FX group requires one shared Settlement Rate document",
            )));
        }
        if let Err(refusal) = self
            .prepare_fx_settlement_source(cx, capability, requests[0].rate_document, &template)
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = fa_journal::carrying::prepare_fx_settlement_group(
            &self.db,
            cx,
            &self.context,
            capability,
            requests,
            template,
            budget,
        )?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), true, None)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    async fn prepare_fx_settlement_source(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        rate_document: Oid,
        template: &EntryPayload,
    ) -> Outcome<()> {
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, template.principal_ref, true, None)?
        {
            return Ok(Err(refusal));
        }
        if template.book_id != self.context().book_id {
            return Ok(Err(invalid(
                "the settlement template names a different book",
            )));
        }
        // Allocated carrying reproduces each revaluation at its original
        // observation and publication prefixes. A current-snapshot report
        // preparation may leave the native delta history unloaded after open.
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, template.principal_ref, true, None)?
        {
            return Ok(Err(refusal));
        }
        let document = match self
            .read_document_for(cx, capability, &rate_document)
            .await?
        {
            Ok(DocumentRead::Full(document)) => document,
            Ok(DocumentRead::Redacted(_)) => {
                return Ok(Err(Refusal::new(
                    code::CAPABILITY,
                    exit::SAFETY,
                    "FX settlement requires the complete retained Rate document",
                    "plan §5.7 / §6.4 (governed settlement evidence)",
                    "use a capability permitted to read the complete Settlement Rate document",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        if document.book_id != self.context().book_id
            || document.kind != RATE_DOCUMENT_KIND
            || document.mime != FX_RATE_MIME
            || document.oid() != rate_document
        {
            return Ok(Err(invalid(
                "the settlement source is not this book's canonical Rate document",
            )));
        }
        let rate = match FxRateDocument::decode(&document.bytes) {
            Ok(rate) => rate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = currency_units(&rate, &self.context().units) {
            return Ok(Err(refusal));
        }
        let selected =
            match self.authorize_fx_read(cx, capability, template.principal_ref, true, None)? {
                Ok(selected) => selected,
                Err(refusal) => return Ok(Err(refusal)),
            };
        self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, selected)
        })?;
        Ok(Ok(()))
    }

    /// Functional-currency activity in one period at one retained prefix.
    /// This is activity, not cumulative stock or a replay certificate. It
    /// folds committed base valuations, keeps pending holds separate, and
    /// refuses unvalued foreign legs. It does not assert that source Rate
    /// bytes remain disclosed or currently available to this reporting reader.
    /// Current whole-book Read authority precedes all history observation.
    pub async fn functional_period_activity(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        period_code: &str,
        known_at: Option<CommitSeq>,
    ) -> Outcome<FunctionalFold> {
        let head =
            match self.authorize_fx_read(cx, capability, capability.holder(), false, known_at)? {
                Ok(head) => head,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let selected = known_at.unwrap_or(head);
        if selected > head {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "functional activity prefix {} exceeds the current head {}",
                    selected.0, head.0
                ),
                "plan §7.1 (a report selects one retained prefix)",
                format!("select a recorded sequence at or before {}", head.0),
            )));
        }
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), false, Some(selected))?
        {
            return Ok(Err(refusal));
        }
        let result = self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, selected)?;
            fa_journal::entry_history::verify_entry_history(db, cx, book, Some(selected))?;
            Ok(fa_registers::fold_period_functional(
                db,
                book,
                period_code,
                Some(selected),
            )?)
        })?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), false, Some(selected))?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(result))
    }

    /// Cumulative functional-currency balances through a civil date at one
    /// retained prefix. Includes opening history across fiscal years and
    /// preserves the journal's committed valuations. Outstanding holds remain
    /// separate; this read neither revalues entries nor issues a certificate.
    pub async fn functional_balance_as_of(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Outcome<FunctionalStockFold> {
        let head =
            match self.authorize_fx_read(cx, capability, capability.holder(), false, known_at)? {
                Ok(head) => head,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let selected = known_at.unwrap_or(head);
        if selected > head {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "functional stock prefix {} exceeds the current head {}",
                    selected.0, head.0
                ),
                "plan §5.3 / §7.1 (cumulative balances at one retained prefix)",
                format!("select a recorded sequence at or before {}", head.0),
            )));
        }
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), false, Some(selected))?
        {
            return Ok(Err(refusal));
        }
        let result = self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, selected)?;
            fa_journal::entry_history::verify_entry_history(db, cx, book, Some(selected))?;
            Ok(fa_registers::fold_functional_stock(
                db,
                book,
                effective_through,
                Some(selected),
            )?)
        })?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), false, Some(selected))?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(result))
    }
}
