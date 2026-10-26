//! Company-defined statements over the same historical journal folds as the
//! built-in reports. The selection pins the reviewed activation, exact layout,
//! comparative columns and optional presentation law for native replay.

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_model::{DecodeError, EncodeError, Reader, Writer};
use fa_statements::Statement;
use fa_statements::custom::{
    CustomStatementDefinition, PresentationRoundingSpec, PresentedStatement,
    apply_presentation_rounding, evaluate_custom,
};
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::{AsyncBook, BookError, Outcome};

pub const OUTPUT_FORMAT: &str = "fa:custom-statement-report:v1";

/// One approved layout applied to current and optional comparative columns.
/// The current column's cutoff selects the activation's effective date. A
/// comparative uses the same layout, with its own independently folded column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomStatementSelection {
    pub definition: CustomStatementDefinition,
    pub activation: VId,
    /// The activation's original native commit, which selects its approval
    /// and chart evidence independently of the report's later known-at.
    pub activated_at: CommitSeq,
    pub periods: Vec<String>,
    pub comparative: Vec<String>,
    pub presentation: Option<PresentationRoundingSpec>,
}

impl CustomStatementSelection {
    pub(crate) fn normalize(mut self) -> Self {
        self.periods.sort();
        self.periods.dedup();
        self.comparative.sort();
        self.comparative.dedup();
        self
    }

    pub(crate) fn is_canonical(&self) -> bool {
        let periods = |values: &[String]| {
            values.len() <= 65_536
                && values.iter().all(|v| !v.is_empty() && v.len() <= 128)
                && values.windows(2).all(|p| p[0] < p[1])
        };
        self.activated_at.0 > 0
            && !self.periods.is_empty()
            && periods(&self.periods)
            && periods(&self.comparative)
            && self.definition.validate().is_ok()
            && self
                .definition
                .canonical_bytes()
                .is_ok_and(|b| b.len() <= fa_statements::MAX_DEFINITION_BYTES)
            && self
                .presentation
                .as_ref()
                .is_none_or(|p| p.validate().is_ok())
    }

    pub(crate) fn write(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.bytes(&self.definition.canonical_bytes()?)
            .u128(self.activation.0)
            .u64(self.activated_at.0)
            .list(&self.periods, |w, p| {
                w.str(p);
            })
            .list(&self.comparative, |w, p| {
                w.str(p);
            });
        match &self.presentation {
            None => {
                w.u8(0);
            }
            Some(spec) => {
                w.u8(1).bytes(&spec.canonical_bytes()?);
            }
        }
        Ok(())
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let definition = CustomStatementDefinition::decode(r.bytes(
            fa_statements::MAX_DEFINITION_BYTES,
            "custom statement definition",
        )?)
        .map_err(|_| r.invalid("custom statement definition"))?;
        let activation = VId(r.u128("statement activation")?);
        let activated_at = CommitSeq(r.u64("statement activated-at")?);
        let periods = r.list(65_536, "statement periods", |r| {
            Ok(r.str(128, "period")?.to_string())
        })?;
        let comparative = r.list(65_536, "statement comparative", |r| {
            Ok(r.str(128, "period")?.to_string())
        })?;
        let presentation = r.opt("presentation rounding", |r| {
            PresentationRoundingSpec::decode(r.bytes(1024, "presentation spec")?)
                .map_err(|_| r.invalid("presentation rounding spec"))
        })?;
        let selection = Self {
            definition,
            activation,
            activated_at,
            periods,
            comparative,
            presentation,
        };
        if !selection.is_canonical() {
            return Err(r.invalid("canonical custom statement selection"));
        }
        Ok(selection)
    }
}

/// Exact accounting rows and, when requested, their explicitly rounded view.
/// Both outputs are covered by the certificate; presentation never changes the
/// exact amounts or hides a rounding residual.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomStatementReport {
    pub activation: VId,
    pub statement: Statement,
    pub presented: Option<PresentedStatement>,
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read an explicitly approved layout under current whole-book authority.
    /// The layout remains pinned when another version is later activated.
    pub fn custom_statement(
        &self,
        cx: &PurposeContexts,
        capability: &fa_policy::Capability,
        selection: CustomStatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<CustomStatementReport> {
        self.query(cx, |db, book| {
            let at = match admit(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            crate::certificate::context_at(db, book, at)?;
            report_at(db, &cx.query(), book, &selection.normalize(), at)
        })
    }

    /// Certify both exact rows and any requested presentation rounding.
    pub fn certify_custom_statement(
        &self,
        cx: &PurposeContexts,
        capability: &fa_policy::Capability,
        selection: CustomStatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedReport> {
        if let Err(denial) = fa_policy::require(
            capability,
            fa_policy::Op::Produce,
            "certify custom statement",
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        self.query(cx, |db, book| {
            let at = match admit(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            crate::certificate::certify_report(
                db,
                cx,
                book,
                crate::ReportSelection::CustomStatement(Box::new(selection)),
                Some(at),
            )
        })
    }
}

fn admit<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &fa_policy::Capability,
    known_at: Option<CommitSeq>,
) -> Outcome<CommitSeq> {
    let authority =
        match fa_journal::policy::admit_reads(db, book, capability.holder(), capability)? {
            Ok(authority) => authority,
            Err(refusal) => return Ok(Err(refusal)),
        };
    let head = db.frontier().map_err(fa_journal::KernelError::from)?;
    let at = known_at.unwrap_or(head);
    if let Err(refusal) = authority.whole_book(at) {
        return Ok(Err(refusal));
    }
    if at > head {
        return Ok(Err(crate::statements::invalid(
            "custom statement known-at is beyond the book head",
        )));
    }
    Ok(Ok(at))
}

impl CustomStatementReport {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(OUTPUT_FORMAT.as_bytes())
            .u128(self.activation.0)
            .bytes(&self.statement.canonical_bytes()?);
        match &self.presented {
            None => {
                w.u8(0);
            }
            Some(statement) => {
                w.u8(1).bytes(&statement.canonical_bytes()?);
            }
        }
        w.finish()
    }

    pub(crate) fn set_known_at(&mut self, at: CommitSeq) {
        self.statement.known_at = at.0;
        if let Some(presented) = &mut self.presented {
            presented.known_at = at.0;
        }
    }
}

pub(crate) fn report_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    selection: &CustomStatementSelection,
    at: CommitSeq,
) -> Outcome<CustomStatementReport> {
    cx.checkpoint().map_err(BookError::Context)?;
    if !selection.is_canonical() {
        return Ok(Err(crate::statements::invalid(
            "invalid custom statement selection",
        )));
    }
    let input = match crate::statements::statement_input(
        db,
        book,
        selection.definition.kind,
        [&selection.periods, &selection.comparative],
        at,
        false,
    )? {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(current) = input.columns.first() else {
        return Ok(Err(crate::statements::invalid(
            "custom statement needs a current column",
        )));
    };
    let activated = match crate::statement_definition::validate_active_at(
        db,
        cx,
        book,
        &selection.definition,
        selection.activation,
        current.effective_through,
        at,
    )? {
        Ok(activated) => activated,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if activated.recorded_at != selection.activated_at {
        return Ok(Err(crate::statements::invalid(
            "the selected activation does not have the declared original commit",
        )));
    }
    let statement = match evaluate_custom(&selection.definition, &input) {
        Ok(statement) => statement,
        Err(error) => return Ok(Err(crate::statements::invalid(error.to_string()))),
    };
    let presented = match &selection.presentation {
        None => None,
        Some(spec) => match apply_presentation_rounding(&statement, &selection.definition, spec) {
            Ok(statement) => Some(statement),
            Err(error) => return Ok(Err(crate::statements::invalid(error.to_string()))),
        },
    };
    Ok(Ok(CustomStatementReport {
        activation: selection.activation,
        statement,
        presented,
    }))
}
