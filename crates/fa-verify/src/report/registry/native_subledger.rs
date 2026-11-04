//! The native AR/AP wrapper's original registry closure, independently bound
//! alongside the nested stock report's four canonical registry documents.

use std::collections::BTreeSet;

use super::{ReportError, Value, boolean, document, hash_parts, integer, invalid, rows, string};

const NAMES: [&str; 6] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "control_payload",
    "symbols",
];

pub(in crate::report) fn verify(
    inputs: &[(&str, &[u8])],
    native_digest: &[u8; 32],
    subledger_digest: &[u8; 32],
) -> Result<Vec<u32>, ReportError> {
    if inputs.iter().map(|(name, _)| *name).ne(NAMES) {
        return Err(invalid(
            "native subledger bundles require all six registry documents in exact closure order",
        ));
    }
    let (units, _) = super::verify(&inputs[..4], native_digest, false)?;
    let mut transcript = Vec::new();
    for index in [4, 1, 5] {
        let (name, bytes) = inputs[index];
        transcript.extend_from_slice(name.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[bytes]));
    }
    if hash_parts(b"fa:native-subledger-registry:v1", &[&transcript]) != *subledger_digest {
        return Err(invalid(
            "control-payload, entry-class or symbol registry differs from the native subledger certificate closure",
        ));
    }
    let control = document(inputs[4].1)?;
    if string(&control.root, "name")? != "ControlPayload"
        || integer(&control.root, "major")? != 1
        || !(0..=1).contains(&integer(&control.root, "minor")?)
        || !boolean(&control.root, "externally_verifiable")?
    {
        return Err(invalid("unsupported control-payload registry version"));
    }
    let Some(Value::Array(tags)) = control.root.get("variant_tags") else {
        return Err(invalid(
            "control-payload registry omits its closed variant tags",
        ));
    };
    let mut seen = BTreeSet::new();
    for tag in tags {
        let Value::Text(tag) = tag else {
            return Err(invalid("control-payload variant tags must be text"));
        };
        if !seen.insert(tag.as_str()) {
            return Err(invalid("control-payload registry repeats a variant tag"));
        }
    }
    if !seen.contains("1:SchemaChange") {
        return Err(invalid("control-payload registry omits SchemaChange tag 1"));
    }
    let declarations: Vec<_> = rows(&control, "decision")?.iter()
        .filter(|row| matches!(row.get("field"), Some(Value::Text(field)) if field == "SchemaChange.kind=15"))
        .collect();
    let [declaration] = declarations.as_slice() else {
        return Err(invalid(
            "control-payload registry must identify native subledger kind 15 exactly once",
        ));
    };
    if string(declaration, "code_type")?
        != "fa-journal::subledger::NativeSubledgerSpec; SchemaChange subkind 15"
    {
        return Err(invalid(
            "unsupported native subledger designation semantics",
        ));
    }

    let symbols = document(inputs[5].1)?;
    if symbols.root.len() != 1 || symbols.named_tables != 0 || symbols.arrays.len() != 3 {
        return Err(invalid(
            "unsupported native subledger symbol registry shape",
        ));
    }
    for table in ["label", "property", "relation"] {
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for row in rows(&symbols, table)? {
            let id = integer(row, "id")?;
            let name = string(row, "name")?;
            if row.len() != 2
                || id <= 0
                || id > u32::MAX as i128
                || name.is_empty()
                || !ids.insert(id)
                || !names.insert(name)
            {
                return Err(invalid(
                    "symbol registry has invalid or duplicate identifiers",
                ));
            }
        }
    }
    for (table, id, name) in [
        ("label", 3, "Account"),
        ("label", 5, "DimensionValue"),
        ("label", 9, "Entry"),
        ("label", 10, "Leg"),
        ("label", 12, "Party"),
        ("label", 15, "Subledger"),
        ("relation", 3, "FOR"),
        ("relation", 18, "CONTROLS"),
        ("relation", 28, "IN_BOOK"),
    ] {
        if !rows(&symbols, table)?.iter().any(|row| {
            matches!(row.get("id"), Some(Value::Int(value)) if *value == id)
                && matches!(row.get("name"), Some(Value::Text(value)) if value == name)
        }) {
            return Err(invalid(
                "native subledger symbols differ from the supported fixed identities",
            ));
        }
    }
    Ok(units)
}
