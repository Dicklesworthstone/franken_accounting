//! Governed source access and journaled routes for period-end FX revaluation.
//!
//! The native kernel derives the exposure, carrying value and adjustment from
//! immutable entries. This facade adds current authorization, cold-history
//! loading and full governed Rate access before native preparation.

use asupersync::fs::Vfs;
use fa_journal::DocumentRead;
use fa_journal::refusal::{Refusal, code, exit};
use fa_money::rate::ArithmeticBudget;
use fa_policy::{Capability, Observes, Op, Reach};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, FX_RATE_MIME, Outcome};

pub use fa_journal::chart::{
    FxRevaluationRoute, FxRevaluationRoutes, FxRevaluationRoutesRecorded,
    FxRevaluationRoutesRequest,
};
pub use fa_journal::revaluation::{FxRevaluationRequest, PreparedFxRevaluation};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    fn authorize_revaluation_source(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        additional_op: Option<Op>,
        known_at: Option<CommitSeq>,
    ) -> Outcome<CommitSeq> {
        let mut reach = Reach::whole_book(true);
        if let Some(at) = known_at {
            reach.observes = Observes::At(at);
        }
        if let Err(denial) = fa_policy::admit_read(capability, principal, self.context().book_id)
            .and_then(|()| {
                additional_op.map_or(Ok(()), |op| {
                    fa_policy::require(capability, op, "FX revaluation")
                })
            })
            .and_then(|()| fa_policy::reach(capability, &reach, None))
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        self.query(cx, |db, book| {
            Ok(fa_journal::policy::current_at(db, book, capability)?.map(|current| current.at()))
        })
    }

    /// Register complete additive routes to dedicated valuation leaves.
    pub async fn set_fx_revaluation_routes(
        &mut self,
        cx: &PurposeContexts,
        request: FxRevaluationRoutesRequest,
        capability: &Capability,
    ) -> Outcome<FxRevaluationRoutesRecorded> {
        if let Err(refusal) = self.authorize_revaluation_source(
            cx,
            request.principal,
            capability,
            Some(Op::SchemaChange),
            None,
        )? {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::chart::set_fx_revaluation_routes(
            &mut self.db,
            cx,
            &self.context,
            capability,
            request,
        )
        .await?)
    }

    /// Read effective routing history at a fixed recorded prefix. A historical
    /// selection never revives expired, revoked or out-of-scope authority.
    pub async fn fx_revaluation_routes_at(
        &mut self,
        cx: &PurposeContexts,
        effective_date: DateDay,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<Option<FxRevaluationRoutes>> {
        let head = match self.authorize_revaluation_source(
            cx,
            capability.holder(),
            capability,
            None,
            known_at,
        )? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let selected = known_at.unwrap_or(head);
        if selected > head {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                "FX route history cannot select a future recorded sequence",
                "plan §7.1 (recorded prefixes)",
                "select HEAD or an existing recorded sequence",
            )));
        }
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self.authorize_revaluation_source(
            cx,
            capability.holder(),
            capability,
            None,
            Some(selected),
        )? {
            return Ok(Err(refusal));
        }
        let result = self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, selected)?;
            fa_journal::entry_history::verify_entry_history(db, cx, book, Some(selected))?;
            Ok(fa_journal::chart::fx_revaluation_routes_at(
                db,
                book,
                effective_date,
                selected,
            )?)
        })?;
        if let Err(refusal) = self.authorize_revaluation_source(
            cx,
            capability.holder(),
            capability,
            None,
            Some(selected),
        )? {
            return Ok(Err(refusal));
        }
        Ok(Ok(result))
    }

    /// Derive a delta-only revaluation from cumulative foreign exposure and
    /// committed functional carrying values, after governed Rate access.
    /// Preparation publishes nothing; use its proposal with the ordinary
    /// PostIntent/plan/commit path for independent native admission.
    pub async fn prepare_fx_revaluation(
        &mut self,
        cx: &PurposeContexts,
        request: &FxRevaluationRequest,
        capability: &Capability,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<PreparedFxRevaluation> {
        if let Err(refusal) = self.authorize_revaluation_source(
            cx,
            capability.holder(),
            capability,
            Some(Op::Post),
            None,
        )? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        let document = match self
            .read_document_for(cx, capability, &request.rate_document)
            .await?
        {
            Ok(DocumentRead::Full(document)) => document,
            Ok(DocumentRead::Redacted(_)) => {
                return Ok(Err(Refusal::new(
                    code::CAPABILITY,
                    exit::SAFETY,
                    "FX revaluation requires the complete retained Rate document",
                    "plan §6.4 / §9.6 (governed source bytes)",
                    "use a capability permitted to read the complete Rate under its governing redaction contract",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        if document.book_id != self.context().book_id
            || document.kind != fa_journal::fx::RATE_DOCUMENT_KIND
            || document.mime != FX_RATE_MIME
            || document.oid() != request.rate_document
        {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                "the selected source is not this book's canonical Rate document",
                "plan §6.4 (retained FX evidence)",
                "retain a canonical PeriodClose Rate document and select its D:oid",
            )));
        }
        if let Err(refusal) = crate::FxRateDocument::decode(&document.bytes) {
            return Ok(Err(refusal));
        }
        let selected = match self.authorize_revaluation_source(
            cx,
            capability.holder(),
            capability,
            Some(Op::Post),
            None,
        )? {
            Ok(selected) => selected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, selected)
        })?;
        let prepared = fa_journal::revaluation::prepare_fx_revaluation(
            &self.db,
            cx,
            &self.context,
            capability,
            request,
            budget,
        )?;
        if let Err(refusal) = self.authorize_revaluation_source(
            cx,
            capability.holder(),
            capability,
            Some(Op::Post),
            None,
        )? {
            return Ok(Err(refusal));
        }
        Ok(prepared)
    }
}
