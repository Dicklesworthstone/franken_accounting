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
use fa_registers::FunctionalFold;
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, IntakeAction, Outcome};

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
        if !matches!(law, FxLawId::SpotClose | FxLawId::PeriodAverage) {
            return Ok(Err(invalid(
                "this valuation path supports only SpotClose and PeriodAverage",
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
}
