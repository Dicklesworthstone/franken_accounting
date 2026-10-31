//! Canonical registry inputs bound by a native statement certificate.
//!
//! The producer supplies the parsed canonical document, not executable code or
//! a mutable registry lookup. This independent decoder checks framing and order,
//! binds the selector's four- or five-document certificate closure, and accepts
//! only the accounting tags interpreted by this version. It does not attest
//! journaled RegistryEpoch activation or reinterpret unknown future semantics.

use std::collections::{BTreeMap, BTreeSet};

use super::{ReportError, failed};
use crate::blake3::hash_parts;

const NAMES: [&str; 4] = ["account_types", "entry_classes", "units", "foundations"];
const EXPLANATION_NAMES: [&str; 5] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "reason_codes",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    pub code: u16,
    pub name: String,
    pub meaning: String,
}
const MAGIC: &[u8] = b"fa:registry-document:v1";
const MAX_DOCUMENT: usize = 1024 * 1024;

#[derive(Debug)]
enum Value {
    Text(String),
    Int(i128),
    Bool(bool),
    Array(Vec<Value>),
}
type Table = BTreeMap<String, Value>;
struct Document {
    root: Table,
    named_tables: usize,
    arrays: BTreeMap<String, Vec<Table>>,
}
fn invalid(message: impl Into<String>) -> ReportError {
    failed("registry_closure", message)
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReportError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| invalid("truncated canonical registry document"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8, ReportError> {
        Ok(self.take(1)?[0])
    }
    fn count(&mut self, max: usize, minimum_bytes: usize) -> Result<usize, ReportError> {
        let n = u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes"));
        let n =
            usize::try_from(n).map_err(|_| invalid("registry length exceeds platform bound"))?;
        if n > max || n > (self.bytes.len() - self.at) / minimum_bytes.max(1) {
            return Err(invalid(
                "registry length exceeds its input or interpretation bound",
            ));
        }
        Ok(n)
    }
    fn text(&mut self) -> Result<String, ReportError> {
        let n = self.count(MAX_DOCUMENT, 1)?;
        std::str::from_utf8(self.take(n)?)
            .map(str::to_string)
            .map_err(|_| invalid("registry string is not UTF-8"))
    }
    fn value(&mut self, depth: u8) -> Result<Value, ReportError> {
        if depth > 8 {
            return Err(invalid("registry array nesting exceeds the bound"));
        }
        Ok(match self.byte()? {
            1 => Value::Text(self.text()?),
            2 => Value::Int(i128::from_le_bytes(
                self.take(16)?.try_into().expect("sixteen bytes"),
            )),
            3 => Value::Bool(match self.byte()? {
                0 => false,
                1 => true,
                _ => return Err(invalid("noncanonical registry boolean")),
            }),
            4 => {
                let n = self.count(65_536, 1)?;
                let mut values = Vec::with_capacity(n);
                for _ in 0..n {
                    values.push(self.value(depth + 1)?);
                }
                Value::Array(values)
            }
            _ => return Err(invalid("unsupported canonical registry value tag")),
        })
    }
    fn table(&mut self) -> Result<Table, ReportError> {
        let n = self.count(256, 9)?;
        let mut table = Table::new();
        let mut previous: Option<String> = None;
        for _ in 0..n {
            let name = self.text()?;
            ordered(&mut previous, &name)?;
            table.insert(name, self.value(0)?);
        }
        Ok(table)
    }
}
fn ordered(previous: &mut Option<String>, name: &str) -> Result<(), ReportError> {
    if name.is_empty() || previous.as_deref().is_some_and(|p| p >= name) {
        return Err(invalid(
            "canonical registry keys must be nonempty and strictly ordered",
        ));
    }
    *previous = Some(name.into());
    Ok(())
}
fn document(bytes: &[u8]) -> Result<Document, ReportError> {
    if bytes.len() > MAX_DOCUMENT {
        return Err(invalid("canonical registry document exceeds 1 MiB"));
    }
    let mut r = Cursor { bytes, at: 0 };
    if r.take(MAGIC.len())? != MAGIC {
        return Err(invalid("unknown canonical registry document major"));
    }
    let root = r.table()?;
    let n = r.count(256, 16)?;
    let named_tables = n;
    let mut previous = None;
    for _ in 0..n {
        ordered(&mut previous, &r.text()?)?;
        r.table()?;
    }
    let n = r.count(256, 16)?;
    let mut previous = None;
    let mut arrays = BTreeMap::new();
    for _ in 0..n {
        let name = r.text()?;
        ordered(&mut previous, &name)?;
        let rows = r.count(4096, 8)?;
        let mut values = Vec::with_capacity(rows);
        for _ in 0..rows {
            values.push(r.table()?);
        }
        arrays.insert(name, values);
    }
    if r.at != bytes.len() {
        return Err(invalid("trailing canonical registry bytes"));
    }
    if integer(&root, "schema_version")? != 1 {
        return Err(invalid("unsupported registry schema_version"));
    }
    Ok(Document {
        root,
        named_tables,
        arrays,
    })
}
fn integer(row: &Table, key: &str) -> Result<i128, ReportError> {
    match row.get(key) {
        Some(Value::Int(n)) => Ok(*n),
        _ => Err(invalid(format!("registry field {key} must be an integer"))),
    }
}
fn string<'a>(row: &'a Table, key: &str) -> Result<&'a str, ReportError> {
    match row.get(key) {
        Some(Value::Text(s)) => Ok(s),
        _ => Err(invalid(format!("registry field {key} must be text"))),
    }
}
fn boolean(row: &Table, key: &str) -> Result<bool, ReportError> {
    match row.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(invalid(format!("registry field {key} must be a boolean"))),
    }
}
fn rows<'a>(doc: &'a Document, table: &str) -> Result<&'a [Table], ReportError> {
    doc.arrays
        .get(table)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("registry omits {table} definitions")))
}
fn account_types(doc: &Document) -> Result<(), ReportError> {
    let expected = [
        (1, "Asset", "stock", 0),
        (2, "Liability", "stock", 1),
        (3, "Equity", "stock", 1),
        (4, "Revenue", "flow", 1),
        (5, "Expense", "flow", 0),
        (6, "Memo", "memo", 0),
        (7, "Statistical", "memo", 0),
        (8, "OffBalance", "memo", 0),
    ];
    let values = rows(doc, "account_type")?;
    if values.len() != expected.len()
        || doc.arrays.len() != 1
        || doc.root.len() != 1
        || doc.named_tables != 0
    {
        return Err(invalid("unsupported account-type registry vocabulary"));
    }
    for (row, (tag, name, kind, normal)) in values.iter().zip(expected) {
        if row.len() != 4
            || integer(row, "tag")? != tag
            || string(row, "name")? != name
            || string(row, "kind")? != kind
            || integer(row, "normal_balance")? != normal
        {
            return Err(invalid(
                "account-type semantics differ from this verifier's supported version",
            ));
        }
    }
    Ok(())
}
fn entry_classes(doc: &Document) -> Result<(), ReportError> {
    let names = [
        "Original",
        "Pending",
        "Resolution",
        "Reversal",
        "Replacement",
        "Reclassification",
        "Adjusting",
        "Closing",
        "Allocation",
        "Revaluation",
        "Elimination",
        "Migration",
        "Revision",
        "Restatement",
        "PriorPeriodAdjustment",
        "PeriodControl",
        "SchemaControl",
        "PolicyControl",
        "TimeControl",
        "SweepControl",
        "ScheduleControl",
        "MigrationControl",
        "ImportControl",
        "HoldControl",
        "DraftControl",
        "ScenarioControl",
        "ProductionControl",
        "IssuanceControl",
        "EngagementControl",
        "CaseControl",
    ];
    let values = rows(doc, "class")?;
    if values.len() != names.len()
        || doc.root.len() != 1
        || doc.named_tables != 0
        || doc.arrays.len() != 2
    {
        return Err(invalid("unsupported entry-class registry vocabulary"));
    }
    for (i, (row, name)) in values.iter().zip(names).enumerate() {
        // These fields describe the posting and visibility law, not just
        // presentation labels. An authenticated hash of different semantics
        // cannot authorize this verifier to apply its built-in interpretation.
        let supersession = match i + 1 {
            3 => "resolves",
            4 => "reverses",
            5 => "replaces",
            6 => "reclassifies",
            7 => "optional",
            13 => "revises",
            14 => "restates",
            _ => "none",
        };
        if row.len() != if i < 15 { 5 } else { 4 }
            || integer(row, "tag")? != (i + 1) as i128
            || string(row, "name")? != name
            || string(row, "kind")? != if i < 15 { "posting" } else { "control" }
            || string(row, "supersession")? != supersession
            || (i < 15 && boolean(row, "carries_open_items")? != !matches!(i + 1, 2 | 4))
        {
            return Err(invalid(
                "entry-class semantics differ from this verifier's supported version",
            ));
        }
    }
    // These are the control origins that supply chart/period metadata and
    // migration visibility. Their numeric identities cannot be reinterpreted.
    let controls = rows(doc, "control_kind")?;
    let mut ids = BTreeSet::new();
    let mut control_names = BTreeSet::new();
    for row in controls {
        let id = integer(row, "id")?;
        let name = string(row, "name")?;
        if row.len() != 4
            || !(1..=u16::MAX as i128).contains(&id)
            || name.is_empty()
            || !ids.insert(id)
            || !control_names.insert(name)
            || !names[15..].contains(&string(row, "class")?)
            || string(row, "minted_by")?.is_empty()
        {
            return Err(invalid("ambiguous or unsupported control-kind registry"));
        }
    }
    for (id, name, class) in [
        (1, "chart_install", "SchemaControl"),
        (9, "migration_run", "MigrationControl"),
        (13, "period_creation", "SchemaControl"),
    ] {
        let found: Vec<_> = controls
            .iter()
            .filter(|row| matches!(row.get("id"), Some(Value::Int(actual)) if *actual == id))
            .collect();
        if found.len() != 1
            || string(found[0], "name")? != name
            || string(found[0], "class")? != class
        {
            return Err(invalid(
                "schema/migration control identities differ from supported semantics",
            ));
        }
    }
    Ok(())
}
fn units(doc: &Document) -> Result<Vec<u32>, ReportError> {
    let rows = rows(doc, "unit")?;
    if rows.is_empty()
        || rows.len() > 4096
        || doc.root.len() != 1
        || doc.named_tables != 0
        || doc.arrays.len() != 1
    {
        return Err(invalid("statement units must be nonempty and bounded"));
    }
    let mut ids = Vec::with_capacity(rows.len());
    let mut identities = BTreeSet::new();
    for row in rows {
        let id = u32::try_from(integer(row, "id")?).map_err(|_| invalid("invalid unit id"))?;
        let version =
            u32::try_from(integer(row, "version")?).map_err(|_| invalid("invalid unit version"))?;
        let scale = integer(row, "scale")?;
        let code = string(row, "code")?;
        if ids.last().is_some_and(|last| *last >= id)
            || code.is_empty()
            || code.len() > 64
            || !(0..=38).contains(&scale)
            || !identities.insert((code, version))
            || !matches!(
                string(row, "kind")?,
                "currency" | "commodity" | "share" | "time" | "count"
            )
        {
            return Err(invalid(
                "unit registry has duplicate, unordered or unsupported definitions",
            ));
        }
        ids.push(id);
    }
    Ok(ids)
}

fn reasons(doc: &Document) -> Result<BTreeMap<u16, Reason>, ReportError> {
    const SCOPES: [&str; 5] = [
        "manual_assertion",
        "supersession",
        "period_control",
        "period_reopen",
        "adjustment_pass",
    ];
    if doc.root.len() != 1 || doc.named_tables != 0 || doc.arrays.len() != 1 {
        return Err(invalid("unsupported reason-code registry shape"));
    }
    let mut codes = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut scopes = BTreeSet::new();
    let mut supersession = BTreeMap::new();
    for row in rows(doc, "reason")? {
        let code = u16::try_from(integer(row, "code")?)
            .ok()
            .filter(|n| *n != 0)
            .ok_or_else(|| invalid("reason code must be in 1..=65535"))?;
        let scope = string(row, "scope")?;
        let name = string(row, "name")?;
        let meaning = string(row, "meaning")?;
        if row.len() != 4
            || !SCOPES.contains(&scope)
            || name.is_empty()
            || meaning.trim().is_empty()
            || !codes.insert((scope.to_string(), code))
            || !names.insert((scope.to_string(), name.to_string()))
        {
            return Err(invalid(
                "reason registry has an unknown scope, duplicate code/name, or empty definition",
            ));
        }
        scopes.insert(scope);
        if scope == "supersession" {
            supersession.insert(
                code,
                Reason {
                    code,
                    name: name.into(),
                    meaning: meaning.into(),
                },
            );
        }
    }
    if SCOPES.iter().any(|scope| !scopes.contains(scope)) {
        return Err(invalid("reason registry omits a required scope"));
    }
    Ok(supersession)
}

pub(super) fn verify(
    inputs: &[(&str, &[u8])],
    expected: &[u8; 32],
    explanation: bool,
) -> Result<(Vec<u32>, BTreeMap<u16, Reason>), ReportError> {
    let names = if explanation {
        EXPLANATION_NAMES.as_slice()
    } else {
        NAMES.as_slice()
    };
    if inputs
        .iter()
        .map(|(name, _)| *name)
        .ne(names.iter().copied())
    {
        return Err(invalid(
            "every registry document is required in the report selector's exact certificate closure order",
        ));
    }
    let mut transcript = Vec::new();
    let mut docs = Vec::with_capacity(inputs.len());
    for (name, bytes) in inputs {
        docs.push(document(bytes)?);
        transcript.extend_from_slice(name.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[bytes]));
    }
    if hash_parts(b"fa:report-registry-closure:v2", &[&transcript]) != *expected {
        return Err(invalid(
            "bundled registry inputs do not reproduce the certificate's closure",
        ));
    }
    account_types(&docs[0])?;
    entry_classes(&docs[1])?;
    Ok((
        units(&docs[2])?,
        if explanation {
            reasons(&docs[4])?
        } else {
            BTreeMap::new()
        },
    ))
}

/// Authenticated unit kinds used by the native-cost lot schedule profile.
pub(super) struct LotUnits {
    pub currencies: BTreeSet<u32>,
    pub quantities: BTreeSet<u32>,
}

/// Called only after verify() has authenticated the exact four-document
/// registry closure. A kind label cannot override its registered balance law.
pub(super) fn lot_units(inputs: &[(&str, &[u8])]) -> Result<LotUnits, ReportError> {
    let bytes = inputs
        .iter()
        .find(|(name, _)| *name == "units")
        .map(|(_, bytes)| *bytes)
        .ok_or_else(|| invalid("lot report omits its unit registry"))?;
    let doc = document(bytes)?;
    units(&doc)?;
    let mut currencies = BTreeSet::new();
    let mut quantities = BTreeSet::new();
    for row in rows(&doc, "unit")? {
        let id = u32::try_from(integer(row, "id")?).map_err(|_| invalid("invalid lot unit id"))?;
        let kind = string(row, "kind")?;
        let balance = match row.get("balance_policy") {
            None => "balanced",
            Some(Value::Text(value)) => value.as_str(),
            _ => return Err(invalid("unit balance policy must be text")),
        };
        let expected = if matches!(kind, "time" | "count") {
            "single_sided"
        } else {
            "balanced"
        };
        if balance != expected {
            return Err(invalid("unit kind and balance policy disagree"));
        }
        match kind {
            "currency" => {
                currencies.insert(id);
            }
            "commodity" | "share" => {
                quantities.insert(id);
            }
            _ => {}
        }
    }
    Ok(LotUnits {
        currencies,
        quantities,
    })
}

/// Decimal scales and currency kinds are valuation inputs, not display labels.
#[derive(Clone, Copy, Debug)]
pub(super) struct FunctionalUnit {
    pub scale: u8,
    pub currency: bool,
}
pub(super) struct FunctionalRegistry {
    pub units: BTreeMap<u32, FunctionalUnit>,
    /// Complete immutable unit definitions used by carrying-close sources.
    pub unit_table_digest: [u8; 32],
    pub spot_carrying: bool,
}

/// Add an independently encoded additive row to the retained legacy fixture.
/// Its old rows remain byte-for-byte unchanged, including their negative controls.
#[cfg(test)]
pub(super) fn spot_law_fixture(bytes: &[u8]) -> Vec<u8> {
    let mut r = Cursor {
        bytes,
        at: MAGIC.len(),
    };
    r.table().unwrap();
    let tables = r.count(256, 16).unwrap();
    for _ in 0..tables {
        r.text().unwrap();
        r.table().unwrap();
    }
    let arrays = r.count(256, 16).unwrap();
    for _ in 0..arrays {
        let name = r.text().unwrap();
        let count_at = r.at;
        let count = r.count(4096, 8).unwrap();
        for _ in 0..count {
            r.table().unwrap();
        }
        if name != "law" {
            continue;
        }
        fn text(out: &mut Vec<u8>, value: &str) {
            out.extend_from_slice(&(value.len() as u64).to_le_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        let mut row = 12_u64.to_le_bytes().to_vec();
        text(&mut row, "admitted_classes");
        row.push(4);
        row.extend_from_slice(&3_u64.to_le_bytes());
        for value in ["Original", "Adjusting", "Reversal"] {
            row.push(1);
            text(&mut row, value);
        }
        for (key, value) in [
            ("code", "settlement_spot_carrying"),
            ("date_selector", "entry_effective_date"),
        ] {
            text(&mut row, key);
            row.push(1);
            text(&mut row, value);
        }
        text(&mut row, "id");
        row.push(2);
        row.extend_from_slice(&11_i128.to_le_bytes());
        for (key, value) in [
            (
                "meaning",
                "Same-unit settlement: current quote equals remaining carrying relief, with no residual absorption",
            ),
            ("name", "SettlementSpotCarrying"),
            ("rate_purpose", "Settlement"),
            ("residual_mode", "none"),
            ("rounding_law", "HalfEven"),
            ("standard_ref", "plan 5.2 and 5.7"),
            ("status", "live"),
        ] {
            text(&mut row, key);
            row.push(1);
            text(&mut row, value);
        }
        text(&mut row, "version");
        row.push(2);
        row.extend_from_slice(&1_i128.to_le_bytes());
        let mut result = bytes[..count_at].to_vec();
        result.extend_from_slice(&((count + 1) as u64).to_le_bytes());
        result.extend_from_slice(&bytes[count_at + 8..r.at]);
        result.extend_from_slice(&row);
        result.extend_from_slice(&bytes[r.at..]);
        return result;
    }
    panic!("legacy FX fixture has no law table");
}
fn text_array(row: &Table, key: &str) -> Result<Vec<String>, ReportError> {
    let Some(Value::Array(values)) = row.get(key) else {
        return Err(invalid(format!("registry field {key} must be an array")));
    };
    values
        .iter()
        .map(|value| match value {
            Value::Text(value) => Ok(value.clone()),
            _ => Err(invalid(format!("registry field {key} must contain text"))),
        })
        .collect()
}
fn functional_laws(doc: &Document) -> Result<(), ReportError> {
    if doc.root.len() != 4
        || doc.named_tables != 0
        || doc.arrays.len() != 2
        || string(&doc.root, "ad_hoc_rate_admission")? != "forbidden"
        || string(&doc.root, "residual_bound_law")?
            != "strictly_less_than_one_base_minor_unit_times_foreign_leg_count"
        || string(&doc.root, "realized_fx_mode")? != "paired_conversion_account"
    {
        return Err(invalid("unsupported FX registry policy"));
    }
    let laws = rows(doc, "law")?;
    let mut identities = BTreeSet::new();
    let mut names = BTreeSet::new();
    for row in laws {
        let id = integer(row, "id")?;
        let version = integer(row, "version")?;
        if row.len() != 12
            || !(1..=u16::MAX as i128).contains(&id)
            || !(1..=u16::MAX as i128).contains(&version)
            || !identities.insert((id, version))
            || !names.insert(string(row, "name")?)
            || !matches!(string(row, "status")?, "live" | "reserved")
            || string(row, "code")?.is_empty()
            || string(row, "meaning")?.is_empty()
            || string(row, "standard_ref")?.is_empty()
        {
            return Err(invalid("ambiguous or unsupported FX law identity"));
        }
        text_array(row, "admitted_classes")?;
    }
    for (id, code, name, purpose, date, classes) in [
        (
            1,
            "spot_close",
            "SpotClose",
            "SpotClose",
            "entry_effective_date",
            [
                "Original",
                "Adjusting",
                "Reversal",
                "Pending",
                "Resolution",
                "Migration",
            ]
            .as_slice(),
        ),
        (
            2,
            "period_end_revaluation",
            "PeriodEndRevaluation",
            "PeriodClose",
            "period_end_date",
            ["Revaluation", "Reversal"].as_slice(),
        ),
        (
            3,
            "period_average",
            "PeriodAverage",
            "PeriodAverage",
            "period_end_date",
            ["Original", "Adjusting", "Reversal"].as_slice(),
        ),
        (
            4,
            "settlement_carrying_basis",
            "SettlementCarryingBasis",
            "Settlement",
            "settlement_and_settled_item_dates",
            ["Original", "Adjusting", "Reversal", "Resolution"].as_slice(),
        ),
        (
            8,
            "year_end_close_carrying",
            "YearEndCloseCarrying",
            "None",
            "fiscal_year_source_prefix",
            ["Closing", "Reversal"].as_slice(),
        ),
        (
            11,
            "settlement_spot_carrying",
            "SettlementSpotCarrying",
            "Settlement",
            "entry_effective_date",
            ["Original", "Adjusting", "Reversal"].as_slice(),
        ),
    ] {
        // Older retained registry closures precede the additive law11. They
        // stay readable, but cannot authorize a claim under that newer law.
        if id == 11
            && !laws
                .iter()
                .any(|row| matches!(row.get("id"), Some(Value::Int(11))))
        {
            continue;
        }
        let row = laws
            .iter()
            .find(|row| {
                matches!(row.get("id"), Some(Value::Int(value)) if *value == id)
                    && matches!(row.get("version"), Some(Value::Int(1)))
            })
            .ok_or_else(|| invalid("missing supported FX law version"))?;
        if string(row, "code")? != code
            || string(row, "name")? != name
            || string(row, "rate_purpose")? != purpose
            || string(row, "date_selector")? != date
            || string(row, "rounding_law")? != if id == 8 { "None" } else { "HalfEven" }
            || string(row, "residual_mode")?
                != if matches!(id, 2 | 8 | 11) {
                    "none"
                } else {
                    "designated_leg"
                }
            || string(row, "status")? != "live"
            || text_array(row, "admitted_classes")?
                .iter()
                .map(String::as_str)
                .ne(classes.iter().copied())
        {
            return Err(invalid(
                "FX law semantics differ from this verifier's supported version",
            ));
        }
    }
    Ok(())
}
fn functional_rounding(doc: &Document) -> Result<(), ReportError> {
    let names = [
        "HalfUp",
        "HalfDown",
        "HalfEven",
        "HalfAwayFromZero",
        "HalfTowardZero",
        "Ceiling",
        "Floor",
        "TowardZero",
        "AwayFromZero",
    ];
    let laws = rows(doc, "law")?;
    if doc.root.len() != 1
        || doc.named_tables != 0
        || doc.arrays.len() != 1
        || laws.len() != names.len()
    {
        return Err(invalid("unsupported rounding registry vocabulary"));
    }
    for (index, (row, name)) in laws.iter().zip(names).enumerate() {
        if row.len() != 3
            || integer(row, "id")? != (index + 1) as i128
            || string(row, "name")? != name
            || string(row, "definition")?.is_empty()
        {
            return Err(invalid("rounding law identifiers have changed semantics"));
        }
    }
    if string(&laws[2], "definition")?
        != "Banker's rounding: ties to the even neighbour (sign-symmetric)."
    {
        return Err(invalid("unsupported HalfEven definition"));
    }
    Ok(())
}
pub(super) fn verify_functional(
    inputs: &[(&str, &[u8])],
    expected: &[u8; 32],
) -> Result<FunctionalRegistry, ReportError> {
    const NAMES: [&str; 6] = [
        "account_types",
        "entry_classes",
        "units",
        "foundations",
        "fx_laws",
        "rounding_laws",
    ];
    if inputs.iter().map(|(name, _)| *name).ne(NAMES) {
        return Err(invalid(
            "functional reports require all six canonical registries in certificate order",
        ));
    }
    let mut transcript = Vec::new();
    let mut docs = Vec::with_capacity(inputs.len());
    for (name, bytes) in inputs {
        docs.push(document(bytes)?);
        transcript.extend_from_slice(name.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[bytes]));
    }
    if hash_parts(b"fa:report-registry-closure:v2", &[&transcript]) != *expected {
        return Err(invalid(
            "functional registry inputs differ from the certificate's exact closure",
        ));
    }
    account_types(&docs[0])?;
    entry_classes(&docs[1])?;
    units(&docs[2])?;
    functional_laws(&docs[4])?;
    functional_rounding(&docs[5])?;
    let mut definitions = functional_definitions(&docs[2])?;
    definitions.spot_carrying = rows(&docs[4], "law")?
        .iter()
        .any(|row| matches!(row.get("id"), Some(Value::Int(11))));
    Ok(definitions)
}

fn functional_definitions(doc: &Document) -> Result<FunctionalRegistry, ReportError> {
    let mut definitions = BTreeMap::new();
    for row in rows(doc, "unit")? {
        let id = u32::try_from(integer(row, "id")?).map_err(|_| invalid("invalid unit id"))?;
        let scale =
            u8::try_from(integer(row, "scale")?).map_err(|_| invalid("invalid decimal scale"))?;
        definitions.insert(
            id,
            FunctionalUnit {
                scale,
                currency: string(row, "kind")? == "currency",
            },
        );
    }
    Ok(FunctionalRegistry {
        units: definitions,
        unit_table_digest: functional_unit_table_digest(doc)?,
        spot_carrying: false,
    })
}

// Independently reproduce the FAU v1 immutable definitions and the complete
// ordered table commitment. A retained carrying close cannot substitute a
// registry that merely shares the currency identifiers and decimal scales.
fn functional_unit_table_digest(doc: &Document) -> Result<[u8; 32], ReportError> {
    use crate::codec::Writer;

    let rows = rows(doc, "unit")?;
    let mut table = Writer::default();
    table.count(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let id = u32::try_from(integer(row, "id")?)
            .map_err(|_| invalid("invalid unit-table identity"))?;
        let version = u16::try_from(integer(row, "version")?)
            .map_err(|_| invalid("unit version exceeds immutable definition bounds"))?;
        let scale = u8::try_from(integer(row, "scale")?)
            .map_err(|_| invalid("invalid unit-table scale"))?;
        let rounding = u16::try_from(integer(row, "rounding_default")?)
            .map_err(|_| invalid("invalid unit default rounding law"))?;
        if usize::try_from(id).ok() != Some(index) || !(1..=9).contains(&rounding) {
            return Err(invalid(
                "unit-table identities must be dense and default rounding registered",
            ));
        }
        let kind = match string(row, "kind")? {
            "currency" => 1,
            "commodity" => 2,
            "share" => 3,
            "time" => 4,
            "count" => 5,
            _ => return Err(invalid("unsupported immutable unit kind")),
        };
        let mut definition = Writer::default();
        definition
            .fixed(b"FAU\0")
            .u16(1)
            .u16(0)
            .u32(id)
            .bytes(string(row, "code")?.as_bytes())
            .u16(version)
            .u8(scale)
            .u8(kind);
        if kind == 1 {
            let iso = u16::try_from(integer(row, "iso4217")?)
                .map_err(|_| invalid("currency ISO code exceeds immutable definition bounds"))?;
            definition.u8(1).u16(iso);
        } else {
            if row.contains_key("iso4217") {
                return Err(invalid(
                    "a noncurrency unit cannot carry an ISO currency code",
                ));
            }
            definition.u8(0);
        }
        definition.u16(rounding);
        table.bytes(&definition.buf);
    }
    let mut framed = Writer::default();
    framed.bytes(&table.buf);
    Ok(hash_parts(b"fa:unit-table:v1", &[&framed.buf]))
}

/// Consolidation binds its own registry closure. Its account-role semantics
/// cannot be borrowed from an ordinary statement or functional report closure.
pub(super) struct ConsolidationRegistry {
    pub units: Vec<u32>,
    pub role_types: BTreeMap<String, Vec<u8>>,
    pub functional: Option<FunctionalRegistry>,
}

fn consolidation_roles(doc: &Document) -> Result<BTreeMap<String, Vec<u8>>, ReportError> {
    if doc.root.len() != 1 || doc.named_tables != 0 || doc.arrays.len() != 1 {
        return Err(invalid("unsupported account-role registry vocabulary"));
    }
    let type_names = [
        "Asset",
        "Liability",
        "Equity",
        "Revenue",
        "Expense",
        "Memo",
        "Statistical",
        "OffBalance",
    ];
    let mut roles = BTreeMap::new();
    for row in rows(doc, "role")? {
        let name = string(row, "name")?;
        if name.is_empty()
            || row.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "name" | "account_types" | "meaning" | "consumers" | "verbs"
                )
            })
            || string(row, "meaning")?.is_empty()
        {
            return Err(invalid("invalid account-role definition"));
        }
        text_array(row, "consumers")?;
        if row.contains_key("verbs") {
            text_array(row, "verbs")?;
        }
        let mut types = Vec::new();
        for name in text_array(row, "account_types")? {
            let tag = type_names
                .iter()
                .position(|expected| *expected == name)
                .ok_or_else(|| invalid("account role names an unsupported account type"))?;
            types.push((tag + 1) as u8);
        }
        types.sort_unstable();
        if types.is_empty()
            || !types.windows(2).all(|pair| pair[0] < pair[1])
            || roles.insert(name.to_string(), types).is_some()
        {
            return Err(invalid(
                "account roles and their permitted types must be unique",
            ));
        }
    }
    for (name, types) in [
        ("intercompany", vec![1, 2]),
        ("intercompany_activity", vec![4, 5]),
        ("investment_in_subsidiary", vec![1]),
        ("contributed_capital", vec![3]),
        ("noncontrolling_interest", vec![3]),
        ("noncontrolling_interest_income", vec![5]),
    ] {
        if roles.get(name) != Some(&types) {
            return Err(invalid(format!(
                "unsupported consolidation role semantics: {name}"
            )));
        }
    }
    Ok(roles)
}

pub(super) fn verify_consolidation(
    inputs: &[(&str, &[u8])],
    expected: &[u8; 32],
    functional: bool,
) -> Result<ConsolidationRegistry, ReportError> {
    let names: &[&str] = if functional {
        &[
            "account_types",
            "entry_classes",
            "units",
            "foundations",
            "account_roles",
            "fx_laws",
            "rounding_laws",
        ]
    } else {
        &[
            "account_types",
            "entry_classes",
            "units",
            "foundations",
            "account_roles",
            "rounding_laws",
        ]
    };
    if inputs
        .iter()
        .map(|(name, _)| *name)
        .ne(names.iter().copied())
    {
        return Err(invalid(
            "consolidation requires its complete native or functional registry closure in certificate order",
        ));
    }
    let mut transcript = Vec::new();
    let mut docs = Vec::with_capacity(inputs.len());
    for (name, bytes) in inputs {
        docs.push(document(bytes)?);
        transcript.extend_from_slice(name.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[bytes]));
    }
    if hash_parts(b"fa:report-registry-closure:v2", &[&transcript]) != *expected {
        return Err(invalid(
            "consolidation registry inputs differ from the certificate's exact closure",
        ));
    }
    account_types(&docs[0])?;
    entry_classes(&docs[1])?;
    let units = units(&docs[2])?;
    let role_types = consolidation_roles(&docs[4])?;
    functional_rounding(&docs[if functional { 6 } else { 5 }])?;
    let functional = if functional {
        functional_laws(&docs[5])?;
        Some(functional_definitions(&docs[2])?)
    } else {
        None
    };
    Ok(ConsolidationRegistry {
        units,
        role_types,
        functional,
    })
}
