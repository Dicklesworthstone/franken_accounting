//! Independent replay of the native regulatory schedule's general-ledger
//! projection. The complete schedule definition and declared Instrument inputs
//! are authenticated parameters; Instrument attributes and filing compliance
//! are not established by this report family.

use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, metadata, statement, strings, text};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v9";
pub(super) const OUTPUT_FORMAT: &str = "fa:regulatory-schedule:v1";
const DEFINITION_FORMAT: &[u8] = b"fa:regulatory-schedule-def:v1";
const MAX_SCHEDULE_BYTES: usize = 131_072;

/// A retained requirement of the schedule, not proof that an Instrument value
/// was supplied or used in the general-ledger projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegulatoryInstrumentInput {
    pub line_code: String,
    pub instrument_kind: String,
    pub attribute_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRegulatorySchedule {
    pub form: &'static str,
    pub schedule_code: String,
    pub instruction_version: String,
    /// Identity of the complete canonical schedule, including its declarations.
    pub schedule_digest: [u8; 32],
    pub declared_instrument_inputs: Vec<RegulatoryInstrumentInput>,
    /// Always false for native v9: only the general-ledger projection is replayed.
    pub instrument_inputs_read: bool,
    pub statement: statement::VerifiedStatement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Selection {
    pub source: statement::Selection,
    form: &'static str,
    schedule_code: String,
    instruction_version: String,
    schedule_digest: [u8; 32],
    declared_instrument_inputs: Vec<RegulatoryInstrumentInput>,
}

impl Selection {
    pub fn read(r: &mut Reader<'_>) -> Result<Self, ReportError> {
        let bytes = r.bytes(MAX_SCHEDULE_BYTES, "regulatory.schedule")?;
        let mut schedule = Reader::new(bytes);
        if schedule.fixed::<{ DEFINITION_FORMAT.len() }>("regulatory.format")? != DEFINITION_FORMAT
        {
            return Err(failed(
                "regulatory_definition",
                "unknown regulatory schedule definition format",
            ));
        }
        let form = match schedule.u8("regulatory.form")? {
            0 => "FFIEC031",
            1 => "FFIEC041",
            2 => "FRY9C",
            _ => return Err(failed("regulatory_definition", "unknown regulatory form")),
        };
        let schedule_code = text(&mut schedule, 32, "regulatory.schedule_code")?.to_string();
        let instruction_version =
            text(&mut schedule, 64, "regulatory.instruction_version")?.to_string();
        if schedule_code.trim().is_empty() || instruction_version.trim().is_empty() {
            return Err(failed(
                "regulatory_definition",
                "schedule code and instruction version must be nonempty",
            ));
        }
        let definition = super::custom_statement::definition::decode(
            schedule.bytes(65_536, "regulatory.statement_definition")?,
        )?;
        let count = schedule.count(64, 12, "regulatory.declared_instrument_inputs")?;
        let mut declared_instrument_inputs = Vec::with_capacity(count);
        for _ in 0..count {
            let input = RegulatoryInstrumentInput {
                line_code: text(&mut schedule, 64, "regulatory.line_code")?.to_string(),
                instrument_kind: text(&mut schedule, 64, "regulatory.instrument_kind")?.to_string(),
                attribute_name: text(&mut schedule, 64, "regulatory.attribute_name")?.to_string(),
            };
            if !definition
                .lines
                .iter()
                .any(|line| line.code == input.line_code)
                || input.instrument_kind.trim().is_empty()
                || input.attribute_name.trim().is_empty()
            {
                return Err(failed(
                    "regulatory_definition",
                    "declared Instrument inputs must name an existing line and nonempty kind and attribute",
                ));
            }
            declared_instrument_inputs.push(input);
        }
        schedule.finish("regulatory schedule definition")?;
        let periods = strings(r, "regulatory.periods")?;
        let comparative = strings(r, "regulatory.comparative")?;
        Ok(Self {
            source: statement::Selection::from_definition(definition, periods, comparative)?,
            form,
            schedule_code,
            instruction_version,
            schedule_digest: hash_parts(
                DEFINITION_FORMAT,
                &[&(bytes.len() as u32).to_le_bytes(), bytes],
            ),
            declared_instrument_inputs,
        })
    }
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
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    resolved: &BTreeSet<usize>,
) -> Result<(VerifiedRegulatorySchedule, Vec<u8>), ReportError> {
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
    if inner.len() > MAX_REPORT_BUNDLE_BYTES - OUTPUT_FORMAT.len() - 4 {
        return Err(failed(
            "bounded_input",
            "regulatory schedule output exceeds 64 MiB",
        ));
    }
    let mut output = Writer::default();
    output.fixed(OUTPUT_FORMAT.as_bytes()).bytes(&inner);
    Ok((
        VerifiedRegulatorySchedule {
            form: selection.form,
            schedule_code: selection.schedule_code.clone(),
            instruction_version: selection.instruction_version.clone(),
            schedule_digest: selection.schedule_digest,
            declared_instrument_inputs: selection.declared_instrument_inputs.clone(),
            instrument_inputs_read: false,
            statement,
        },
        output.buf,
    ))
}
