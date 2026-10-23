//! Canonical registry inputs bound by a native statement certificate.
//!
//! The producer supplies the parsed canonical document, not executable code or
//! a mutable registry lookup. This independent decoder checks framing and order,
//! binds all four documents to the certificate's registry closure, and accepts
//! only the accounting tags interpreted by this version. It does not attest
//! journaled RegistryEpoch activation or reinterpret unknown future semantics.

use std::collections::{BTreeMap, BTreeSet};

use super::{ReportError, failed};
use crate::blake3::hash_parts;

const NAMES: [&str; 4] = ["account_types", "entry_classes", "units", "foundations"];
const MAGIC: &[u8] = b"fa:registry-document:v1";
const MAX_DOCUMENT: usize = 1024 * 1024;

#[derive(Debug)]
enum Value {
    Text(String),
    Int(i128),
    Bool,
    Array,
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
            3 => {
                if self.byte()? > 1 {
                    return Err(invalid("noncanonical registry boolean"));
                }
                Value::Bool
            }
            4 => {
                let n = self.count(65_536, 1)?;
                for _ in 0..n {
                    self.value(depth + 1)?;
                }
                Value::Array
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
        if integer(row, "tag")? != (i + 1) as i128
            || string(row, "name")? != name
            || string(row, "kind")? != if i < 15 { "posting" } else { "control" }
        {
            return Err(invalid(
                "entry-class semantics differ from this verifier's supported version",
            ));
        }
    }
    // These are the control origins that supply chart/period metadata and
    // migration visibility. Their numeric identities cannot be reinterpreted.
    let controls = rows(doc, "control_kind")?;
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
    if string(&values[3], "supersession")? != "reverses"
        || string(&values[2], "supersession")? != "resolves"
    {
        return Err(invalid(
            "entry resolution/reversal semantics are unsupported",
        ));
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

pub(super) fn verify(
    inputs: &[(&str, &[u8])],
    expected: &[u8; 32],
) -> Result<Vec<u32>, ReportError> {
    if inputs.iter().map(|(name, _)| *name).ne(NAMES) {
        return Err(invalid(
            "all four registry documents are required in certificate closure order",
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
    units(&docs[2])
}
