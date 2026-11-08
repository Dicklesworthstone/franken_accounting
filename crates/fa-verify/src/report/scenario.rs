//! Conditional additive scenario mathematics, independently of the producer.
//!
//! The complete signed journal proves the fork fold and the exact Open/Plan
//! records. Plans describe assumed effects, never trunk postings. This module
//! checks their bounded native Original arithmetic and every diff byte. It does
//! not reproduce historical permission/SoD admission or prove membership and
//! completeness of nonjournal accounting commits named by the native SeqMap.

mod history;

use std::collections::{BTreeMap, BTreeSet};

use super::{ReportError, ReportRow, Selection, failed, text};
use crate::blake3::hash_parts;
use crate::bundle::ReceiptFacts;
use crate::checkpoint::SignedCheckpoint;
use crate::codec::{Reader, Writer};
use crate::envelope::MAX_RECORD_BYTES;
use crate::proof::{Checkpoint, verify_prefix};

pub const SCENARIO_MATH_BUNDLE_FORMAT: &[u8] = b"fa:scenario-math-bundle:v1";
pub const SCENARIO_MATH_REQUEST_FORMAT: &[u8] = b"fa:scenario-math-request:v1";
pub const NATIVE_ORIGINAL_ADDITIVE_METHOD: &str = "native-original-additive:v1";
pub const MAX_SCENARIO_MATH_BYTES: usize = 64 * 1024 * 1024;
const MAX_INTENTS: usize = 8190;
const MAX_DOCUMENTS: usize = 65_536;

/// An independently retained recipient question. Never obtain this value from
/// the untrusted delivery and then present it as the recipient's selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioExpectation {
    pub method: String,
    pub book_id: [u8; 16],
    pub name: String,
    pub fork_at: u64,
    pub from: Option<i32>,
    pub periods: Vec<String>,
    pub activity: bool,
    pub assumptions: Vec<[u8; 32]>,
    /// The exact ordered Plan prefix selected when the question was retained.
    pub intents: u64,
    pub intents_digest: [u8; 32],
}

impl ScenarioExpectation {
    fn validate(&self) -> Result<(), ReportError> {
        if self.method != NATIVE_ORIGINAL_ADDITIVE_METHOD
            || self.name.is_empty()
            || self.name.len() > 128
            || self.fork_at == 0
            || self.periods.is_empty()
            || self.periods.len() > 4096
            || self.periods.iter().any(|p| p.is_empty() || p.len() > 128)
            || self.periods.windows(2).any(|p| p[0] >= p[1])
            || self.assumptions.len() > 256
            || self.assumptions.windows(2).any(|p| p[0] >= p[1])
            || self.intents > MAX_INTENTS as u64
        {
            return Err(failed(
                "scenario_request",
                "unsupported method or noncanonical scenario question",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ReportError> {
        self.validate()?;
        let mut w = Writer::default();
        w.bytes(SCENARIO_MATH_REQUEST_FORMAT)
            .bytes(self.method.as_bytes())
            .fixed(&self.book_id)
            .bytes(self.name.as_bytes())
            .u64(self.fork_at)
            .u8(u8::from(self.from.is_some()));
        if let Some(day) = self.from {
            w.i32(day);
        }
        w.count(self.periods.len());
        for period in &self.periods {
            w.bytes(period.as_bytes());
        }
        w.u8(u8::from(self.activity)).count(self.assumptions.len());
        for oid in &self.assumptions {
            w.fixed(oid);
        }
        w.u64(self.intents).fixed(&self.intents_digest);
        Ok(w.buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > 1024 * 1024 {
            return Err(failed("scenario_request", "scenario question exceeds 1 MiB"));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(64, "request.format")? != SCENARIO_MATH_REQUEST_FORMAT {
            return Err(failed("scenario_request", "unknown scenario question format"));
        }
        let method = text(&mut r, 64, "request.method")?.to_string();
        let book_id = r.fixed("request.book")?;
        let name = text(&mut r, 128, "request.name")?.to_string();
        let fork_at = r.u64("request.fork")?;
        let from = if r.present("request.from")? {
            Some(r.i32("request.from")?)
        } else {
            None
        };
        let n = r.count(4096, 4, "request.periods")?;
        let mut periods = Vec::with_capacity(n);
        for _ in 0..n {
            periods.push(text(&mut r, 128, "request.period")?.to_string());
        }
        let activity = r.present("request.activity")?;
        let n = r.count(256, 32, "request.assumptions")?;
        let mut assumptions = Vec::with_capacity(n);
        for _ in 0..n {
            assumptions.push(r.fixed("request.assumption")?);
        }
        let intents = r.u64("request.intents")?;
        let intents_digest = r.fixed("request.intents_digest")?;
        r.finish("scenario question")?;
        let value = Self {
            method,
            book_id,
            name,
            fork_at,
            from,
            periods,
            activity,
            assumptions,
            intents,
            intents_digest,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioMathRow {
    pub account: u128,
    pub code: String,
    pub name: String,
    pub unit: u32,
    pub trunk_debits: i128,
    pub trunk_credits: i128,
    pub scenario_debits: i128,
    pub scenario_credits: i128,
    pub delta: i128,
    pub trunk_debits_pending: i128,
    pub trunk_credits_pending: i128,
    pub scenario_debits_pending: i128,
    pub scenario_credits_pending: i128,
    pub pending_delta: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedScenarioMath {
    pub scope: &'static str,
    pub method: &'static str,
    pub expectation: ScenarioExpectation,
    pub bundle_digest: [u8; 32],
    pub certificate_digest: [u8; 32],
    pub checkpoint: SignedCheckpoint,
    pub rows: Vec<ScenarioMathRow>,
    /// Independently reconstructed original fa:scenario-diff:v1 output bytes.
    pub output: Vec<u8>,
    pub checked_records: usize,
    pub checked_intents: usize,
    pub checked_documents: usize,
    pub receipt: Option<ReceiptFacts>,
    /// Planner capability and Approval/SoD admission remain outside this claim.
    pub historical_admission: &'static str,
    /// Canonical/digest/coordinate consistency is checked; native marker
    /// membership and nonjournal accounting-commit completeness are unjudged.
    pub native_marker_membership: &'static str,
}

struct ScenarioCertificate<'a> {
    trunk: &'a [u8],
    scenario: u128,
    name: &'a str,
    body_digest: [u8; 32],
    intents: Vec<u128>,
    map_digest: [u8; 32],
    head: u64,
    output: &'a [u8],
    digest: [u8; 32],
}

fn framed(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u32).to_le_bytes());
        bytes.extend_from_slice(part);
    }
    hash_parts(domain, &[&bytes])
}

fn intents_digest(intents: &[u128]) -> [u8; 32] {
    let records: Vec<[u8; 16]> = intents.iter().map(|id| id.to_le_bytes()).collect();
    let parts: Vec<&[u8]> = records.iter().map(<[u8; 16]>::as_slice).collect();
    framed(b"fa:scenario-intents:v1", &parts)
}

fn certificate(bytes: &[u8]) -> Result<ScenarioCertificate<'_>, ReportError> {
    let mut r = Reader::new(bytes);
    if r.bytes(64, "scenario.certificate.format")? != b"fa:scenario-diff-certificate:v2" {
        return Err(failed(
            "scenario_profile",
            "portable scenario mathematics requires native certificate v2",
        ));
    }
    let trunk = r.bytes(MAX_SCENARIO_MATH_BYTES, "scenario.trunk")?;
    let scenario = r.u128("scenario.identity")?;
    let name = text(&mut r, 128, "scenario.name")?;
    let body_digest = r.fixed("scenario.body_digest")?;
    let n = r.count(MAX_INTENTS, 16, "scenario.intents")?;
    let mut intents = Vec::with_capacity(n);
    let mut distinct = BTreeSet::new();
    for _ in 0..n {
        let id = r.u128("scenario.plan")?;
        if !distinct.insert(id) {
            return Err(failed("scenario_intents", "duplicate selected Plan record"));
        }
        intents.push(id);
    }
    let map_digest = r.fixed("scenario.map_digest")?;
    let head = r.u64("scenario.head")?;
    r.u128("scenario.producer_provenance")?;
    r.fixed::<32>("scenario.capability_provenance")?;
    let output = r.bytes(MAX_SCENARIO_MATH_BYTES, "scenario.output")?;
    let digest = r.fixed("scenario.digest")?;
    r.finish("scenario certificate")?;
    if framed(
        b"fa:scenario-diff-certificate-digest:v2",
        &[&bytes[..bytes.len() - 32]],
    ) != digest
    {
        return Err(failed(
            "certificate_digest",
            "scenario certificate digest mismatch",
        ));
    }
    Ok(ScenarioCertificate {
        trunk,
        scenario,
        name,
        body_digest,
        intents,
        map_digest,
        head,
        output,
        digest,
    })
}

struct Document<'a> {
    oid: [u8; 32],
    kind: u8,
    bytes: &'a [u8],
}

/// Verify a recipient-selected, conditional additive scenario. A trusted
/// checkpoint authenticates the journal; a valid outer receipt or independently
/// retained scenario certificate pin additionally binds the selected computation.
/// Never derive that pin or `expected` from the untrusted bundle itself.
pub fn verify_scenario_math_expected(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    expected: &ScenarioExpectation,
    expected_certificate: Option<&[u8; 32]>,
) -> Result<VerifiedScenarioMath, ReportError> {
    expected.validate()?;
    if bundle.len() > MAX_SCENARIO_MATH_BYTES {
        return Err(failed(
            "scenario_profile",
            "scenario mathematical closure exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bundle);
    if r.bytes(64, "scenario_bundle.format")? != SCENARIO_MATH_BUNDLE_FORMAT
        || text(&mut r, 64, "scenario_bundle.method")? != expected.method
    {
        return Err(failed(
            "scenario_profile",
            "unsupported transport or recipient method mismatch",
        ));
    }
    let cert = certificate(r.bytes(MAX_SCENARIO_MATH_BYTES, "scenario_bundle.certificate")?)?;
    if cert.intents.len() as u64 != expected.intents
        || intents_digest(&cert.intents) != expected.intents_digest
    {
        return Err(failed(
            "scenario_request",
            "ordered Plan prefix differs from the recipient's exact scenario question",
        ));
    }
    let trunk_bundle = r.bytes(MAX_SCENARIO_MATH_BYTES, "scenario_bundle.trunk")?;
    let map = r.bytes(MAX_SCENARIO_MATH_BYTES, "scenario_bundle.seq_map")?;
    let n = r.count(MAX_DOCUMENTS, 37, "scenario_bundle.documents")?;
    let mut documents = Vec::with_capacity(n);
    for _ in 0..n {
        let oid = r.fixed("document.oid")?;
        if documents
            .last()
            .is_some_and(|previous: &Document<'_>| previous.oid >= oid)
        {
            return Err(failed(
                "scenario_documents",
                "document identities are not strictly ascending",
            ));
        }
        documents.push(Document {
            oid,
            kind: r.u8("document.kind")?,
            bytes: r.bytes(MAX_SCENARIO_MATH_BYTES, "document.bytes")?,
        });
    }
    r.finish("scenario mathematical bundle")?;
    if expected_certificate.is_some_and(|pin| *pin != cert.digest) {
        return Err(failed(
            "recipient_certificate",
            "scenario certificate differs from the recipient pin",
        ));
    }
    let digest = hash_parts(SCENARIO_MATH_BUNDLE_FORMAT, &[bundle]);
    let receipt = receipt
        .map(|raw| {
            crate::bundle::receipt_grade(raw, &digest, trusted_keys)
                .map_err(|detail| failed("production_receipt", detail))
        })
        .transpose()?;
    if receipt.is_none() && expected_certificate.is_none() {
        return Err(failed(
            "scenario_input_authority",
            "scenario mathematics requires an outer production receipt or independent certificate pin",
        ));
    }
    let source = super::certificate(cert.trunk)?;
    let source_periods = match &source.selection {
        Selection::Periods(periods) if !expected.activity => periods,
        Selection::Activity(periods) if expected.activity => periods,
        _ => {
            return Err(failed(
                "scenario_request",
                "scenario source must ask the recipient's native period question",
            ));
        }
    };
    if source.book != expected.book_id
        || source.known_at != expected.fork_at
        || source_periods != &expected.periods
        || cert.name != expected.name
        || source.branch != [0; 16]
        || source.functional
        || source.dimension.is_some()
        || source.time_selection.is_some()
    {
        return Err(failed(
            "scenario_request",
            "scenario fork, source scope or name differs from the recipient question",
        ));
    }
    // The source pin is trustworthy only after the original outer certificate
    // was selected by the recipient or authenticated by the outer receipt above.
    let baseline = super::verify_report_expected(
        trunk_bundle,
        trusted_keys,
        expected_checkpoint,
        None,
        Some(&source.digest),
    )?;
    let mut input = Reader::new(trunk_bundle);
    if input.bytes(64, "trunk.format")? != super::REPORT_BUNDLE_FORMAT
        || input.u16("trunk.major")? != 1
    {
        return Err(failed(
            "scenario_profile",
            "scenario baseline requires the complete native report transport",
        ));
    }
    let minor = input.u16("trunk.minor")?;
    if minor > 1 || input.bytes(MAX_SCENARIO_MATH_BYTES, "trunk.certificate")? != cert.trunk {
        return Err(failed(
            "scenario_source",
            "nested baseline does not retain the exact scenario trunk certificate",
        ));
    }
    input.bytes(1024 * 1024, "trunk.checkpoint")?;
    let prefix = verify_prefix(
        input.bytes(MAX_SCENARIO_MATH_BYTES, "trunk.prefix")?,
        &baseline.checkpoint.checkpoint,
    )?;
    let n = input.count(super::MAX_ROWS, 8, "trunk.records")?;
    if n != prefix.envelopes.len() {
        return Err(failed(
            "record_completeness",
            "scenario baseline payload count mismatch",
        ));
    }
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        records.push((
            input.u32("trunk.proposal_len")? as usize,
            input.bytes(MAX_RECORD_BYTES, "trunk.payload")?,
        ));
    }
    let n = input.count(records.len(), 12, "trunk.migrations")?;
    let mut bodies = Vec::with_capacity(n);
    for _ in 0..n {
        bodies.push((
            input.u64("migration.index")?,
            input.bytes(MAX_RECORD_BYTES, "migration.body")?,
        ));
    }
    if minor == 1 {
        let n = input.count(records.len(), 12, "trunk.source_manifests")?;
        for _ in 0..n {
            input.u64("source.index")?;
            input.bytes(MAX_RECORD_BYTES, "source.manifest")?;
        }
    }
    input.finish("scenario trunk transport")?;
    let historical = super::historical_inputs(&source, &prefix.envelopes, &records, &bodies)?;
    let assumed = history::plans(&cert, expected, &prefix.envelopes, &records)?;
    history::seq_map(map, &cert, expected, &prefix.envelopes)?;
    history::documents(&documents, expected, &assumed)?;
    let (rows, output) = recompute(
        &cert,
        expected,
        &baseline.rows,
        &historical.schema,
        &historical.infos,
        &assumed,
    )?;
    if output != cert.output {
        return Err(failed(
            "scenario_recomputation",
            "assumed additive effects, gross differences or canonical output differ from independent replay",
        ));
    }
    Ok(VerifiedScenarioMath {
        scope: "conditional_additive_scenario_math",
        method: NATIVE_ORIGINAL_ADDITIVE_METHOD,
        expectation: expected.clone(),
        bundle_digest: digest,
        certificate_digest: cert.digest,
        checkpoint: baseline.checkpoint,
        rows,
        output,
        checked_records: records.len(),
        checked_intents: assumed.len(),
        checked_documents: documents.len(),
        receipt,
        historical_admission: "not_judged",
        native_marker_membership: "not_judged",
    })
}

fn arithmetic() -> ReportError {
    failed(
        "exact_arithmetic",
        "scenario gross column or signed difference overflow",
    )
}

fn recompute(
    cert: &ScenarioCertificate<'_>,
    expected: &ScenarioExpectation,
    baseline: &[ReportRow],
    schema: &super::metadata::Schema,
    historical: &BTreeMap<usize, super::metadata::EntryInfo<'_>>,
    assumed: &[history::AssumedEntry<'_>],
) -> Result<(Vec<ScenarioMathRow>, Vec<u8>), ReportError> {
    let selection = if expected.activity {
        Selection::Activity(expected.periods.clone())
    } else {
        Selection::Periods(expected.periods.clone())
    };
    let (_, cutoff, _) = schema.selection(&selection)?;
    let mut identities: BTreeSet<u128> = historical
        .values()
        .flat_map(|info| info.identities())
        .collect();
    let before: BTreeMap<(u128, u32), [i128; 4]> = baseline
        .iter()
        .map(|row| {
            (
                (row.account, row.unit),
                [row.debits, row.credits, row.debits_pending, row.credits_pending],
            )
        })
        .collect();
    let mut after = before.clone();
    for assumption in assumed {
        if !identities.insert(assumption.info.identity) {
            return Err(failed(
                "scenario_intents",
                "assumed posting identity is already present at the fork or in an earlier Plan",
            ));
        }
        let period = schema.entry_period(&assumption.info, assumption.day)?;
        let selected = cutoff.map_or_else(
            || expected.periods.binary_search(&period).is_ok(),
            |through| assumption.day <= through,
        );
        for leg in &assumption.legs {
            let account = schema.accounts.get(&leg.account).ok_or_else(|| {
                failed(
                    "scenario_accounts",
                    "assumed posting account is absent from the authenticated fork chart",
                )
            })?;
            if !account.is_leaf
                || account.unit_policy >= 0 && account.unit_policy != i64::from(leg.unit)
            {
                return Err(failed(
                    "scenario_accounts",
                    "assumed posting does not match the fork account's leaf/unit declaration",
                ));
            }
            if selected {
                let cell = after.entry((leg.account, leg.unit)).or_insert([0; 4]);
                let column = usize::from(!leg.debit);
                cell[column] = cell[column]
                    .checked_add(leg.mantissa)
                    .ok_or_else(arithmetic)?;
            }
        }
    }
    let mut rows = Vec::new();
    for ((account, unit), values) in after {
        let original = before.get(&(account, unit)).copied().unwrap_or([0; 4]);
        if values == original {
            continue;
        }
        let metadata = &schema.accounts[&account];
        let delta = values[0]
            .checked_sub(values[1])
            .and_then(|net| {
                original[0]
                    .checked_sub(original[1])
                    .and_then(|old| net.checked_sub(old))
            })
            .ok_or_else(arithmetic)?;
        rows.push(ScenarioMathRow {
            account,
            code: metadata.code.clone(),
            name: metadata.name.clone(),
            unit,
            trunk_debits: original[0],
            trunk_credits: original[1],
            scenario_debits: values[0],
            scenario_credits: values[1],
            delta,
            trunk_debits_pending: original[2],
            trunk_credits_pending: original[3],
            scenario_debits_pending: values[2],
            scenario_credits_pending: values[3],
            pending_delta: 0,
        });
    }
    rows.sort_by(|a, b| (&a.code, a.unit, a.account).cmp(&(&b.code, b.unit, b.account)));
    let mut w = Writer::default();
    w.bytes(b"fa:scenario-diff:v1")
        .bytes(expected.name.as_bytes())
        .u128(cert.scenario)
        .fixed(&cert.body_digest)
        .fixed(&intents_digest(&cert.intents))
        .u64(cert.intents.len() as u64)
        .u64(expected.fork_at)
        .u8(u8::from(expected.from.is_some()));
    if let Some(day) = expected.from {
        w.i32(day);
    }
    w.count(expected.assumptions.len());
    for oid in &expected.assumptions {
        w.fixed(oid);
    }
    w.count(expected.periods.len());
    for period in &expected.periods {
        w.bytes(period.as_bytes());
    }
    w.u8(u8::from(expected.activity))
        .fixed(&cert.map_digest)
        .u64(cert.head)
        .count(rows.len());
    for row in &rows {
        w.u128(row.account)
            .bytes(row.code.as_bytes())
            .bytes(row.name.as_bytes())
            .u32(row.unit)
            .i128(row.trunk_debits)
            .i128(row.trunk_credits)
            .i128(row.scenario_debits)
            .i128(row.scenario_credits)
            .i128(row.delta)
            .i128(row.trunk_debits_pending)
            .i128(row.trunk_credits_pending)
            .i128(row.scenario_debits_pending)
            .i128(row.scenario_credits_pending)
            .i128(row.pending_delta);
    }
    Ok((rows, w.buf))
}
