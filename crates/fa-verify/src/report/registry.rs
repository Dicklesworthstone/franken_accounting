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
    ] {
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
            || string(row, "rounding_law")? != "HalfEven"
            || string(row, "residual_mode")? != if id == 2 { "none" } else { "designated_leg" }
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
    let mut definitions = BTreeMap::new();
    for row in rows(&docs[2], "unit")? {
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
    Ok(FunctionalRegistry { units: definitions })
}
