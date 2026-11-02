//! Company-defined reports retain the native exact definition, activation
//! citation and presentation parameters. Independent replay proves their
//! computation and authenticated journal bindings; it does not prove database
//! object birth, historical approval admission or Human separation of duties.

mod activation;
pub(super) mod definition;
mod presentation;
#[cfg(test)]
mod tests;

pub use activation::VerifiedCustomActivation;
use presentation::PresentationSpec;
pub use presentation::{PresentedStatementLine, VerifiedPresentedStatement};

use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, metadata, statement, strings};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const NATIVE_FORMAT: &[u8] = b"fa:report-certificate:v11";
pub(super) const FUNCTIONAL_FORMAT: &[u8] = b"fa:report-certificate:v12";
pub(super) const NATIVE_OUTPUT_FORMAT: &[u8] = b"fa:custom-statement-report:v1";
pub(super) const FUNCTIONAL_OUTPUT_FORMAT: &[u8] = b"fa:functional-custom-statement:v1";

/// Extract only after the complete custom source has been independently
/// recomputed. Comparisons commit its exact inner Statement, while retaining
/// and checking the full presentation and activation wrapper in each source.
pub(super) fn statement_bytes(bytes: &[u8]) -> Result<&[u8], ReportError> {
    let mut r = Reader::new(bytes);
    if bytes.starts_with(FUNCTIONAL_OUTPUT_FORMAT) {
        r.fixed::<{ FUNCTIONAL_OUTPUT_FORMAT.len() }>("custom statement format")?;
        if r.bytes(64, "custom statement valuation")? != b"retained-base-amounts" {
            return Err(failed(
                "statement_diff_selection",
                "invalid custom valuation basis",
            ));
        }
        r.u32("custom functional unit")?;
    } else if r.fixed::<{ NATIVE_OUTPUT_FORMAT.len() }>("custom statement format")?
        != NATIVE_OUTPUT_FORMAT
    {
        return Err(failed(
            "statement_diff_selection",
            "invalid custom source wrapper",
        ));
    }
    r.u128("custom activation")?;
    let inner = r.bytes(MAX_REPORT_BUNDLE_BYTES, "custom exact statement")?;
    if r.present("custom presentation")? {
        r.bytes(MAX_REPORT_BUNDLE_BYTES, "custom presented statement")?;
    }
    r.finish("custom statement output")?;
    Ok(inner)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Selection {
    pub source: statement::Selection,
    pub activation: u128,
    pub activated_at: u64,
    pub functional: bool,
    presentation: Option<PresentationSpec>,
}

impl Selection {
    pub fn read(r: &mut Reader<'_>, functional: bool) -> Result<Self, ReportError> {
        let definition = definition::decode(r.bytes(64 * 1024, "custom.definition")?)?;
        let activation = r.u128("custom.activation")?;
        let activated_at = r.u64("custom.activated_at")?;
        if activated_at == 0 {
            return Err(failed(
                "custom_statement_activation",
                "activation requires an original positive commit sequence",
            ));
        }
        let periods = strings(r, "custom.periods")?;
        let comparative = strings(r, "custom.comparative")?;
        let source = statement::Selection::from_definition(definition, periods, comparative)?;
        let presentation = r
            .present("custom.presentation")?
            .then(|| PresentationSpec::decode(r.bytes(1024, "custom.presentation.spec")?))
            .transpose()?;
        Ok(Self {
            source,
            activation,
            activated_at,
            functional,
            presentation,
        })
    }

    pub fn activity(&self) -> bool {
        self.source.activity()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCustomStatement {
    pub activation: VerifiedCustomActivation,
    pub statement: statement::VerifiedStatement,
    pub functional_unit: Option<u32>,
    pub presented: Option<VerifiedPresentedStatement>,
    /// The same recipient pin or production receipt premise used by ordinary
    /// functional statement replay. Genesis is not independently established.
    pub book_parameters_source: Option<&'static str>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    selection: &Selection,
    book: &[u8; 16],
    branch: &[u8; 16],
    known_at: u64,
    units: &[u32],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    resolved: &BTreeSet<usize>,
) -> Result<(VerifiedCustomStatement, Vec<u8>), ReportError> {
    if selection.functional && units.len() != 1 {
        return Err(failed(
            "functional_book",
            "a functional custom statement requires exactly its verified base unit",
        ));
    }
    let definition = &selection.source.definition;
    let definition_digest = hash_parts(
        definition::FORMAT,
        &[
            &(definition.bytes.len() as u32).to_le_bytes(),
            &definition.bytes,
        ],
    );
    let (_, current_cutoff) = schema.bounds(&selection.source.periods)?;
    let request = activation::ActivationSelection {
        activation: selection.activation,
        activated_at: selection.activated_at,
        definition_digest,
        current_cutoff,
    };
    let (activation, reviewed_schema) =
        activation::verify(envelopes, records, book, known_at, &request)?;
    // The reviewed chart and the report chart are separate historical inputs.
    // A new zero-balance account must not silently disappear from either one.
    definition::mappings(definition, &reviewed_schema)?;
    let (statement, inner) = statement::replay(
        &selection.source,
        book,
        branch,
        known_at,
        units,
        schema,
        envelopes,
        infos,
        legs,
        visible_migrations,
        resolved,
    )?;
    let functional_unit = selection.functional.then(|| units[0]);
    let mut w = Writer::default();
    w.fixed(if selection.functional {
        FUNCTIONAL_OUTPUT_FORMAT
    } else {
        NATIVE_OUTPUT_FORMAT
    });
    if let Some(unit) = functional_unit {
        w.bytes(b"retained-base-amounts").u32(unit);
    }
    w.u128(selection.activation)
        .bytes(&inner)
        .u8(u8::from(selection.presentation.is_some()));
    let presented = if let Some(spec) = &selection.presentation {
        let (presented, output) = presentation::replay(
            spec,
            definition,
            &statement,
            book,
            branch,
            known_at,
            w.buf.len() + 4,
        )?;
        w.bytes(&output);
        Some(presented)
    } else {
        None
    };
    if w.buf.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "reconstructed custom statement exceeds 64 MiB",
        ));
    }
    Ok((
        VerifiedCustomStatement {
            activation,
            statement,
            functional_unit,
            presented,
            book_parameters_source: selection
                .functional
                .then_some(super::functional::BOOK_PARAMETERS_SOURCE),
        },
        w.buf,
    ))
}
