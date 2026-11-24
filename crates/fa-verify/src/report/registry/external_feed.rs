//! Separate native-control and external-feed registry closures. Hash agreement
//! alone does not authorize changed detail, document, role or review semantics.
//! Evidence admission and historical authority policy are not replayed here.

use std::collections::BTreeSet;

use super::{
    ReportError, Table, Value, boolean, document, hash_parts, integer, invalid, rows, string,
};

const NAMES: [&str; 8] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "external_subledger",
    "attestation",
    "evidence_policy",
    "redaction_contracts",
];
const ATTESTATION_FIELDS: [&str; 7] = [
    "version:u16",
    "claim:tagged_claim",
    "subject_refs:list<subject_ref>",
    "principal_ref:u128",
    "evidence_refs:list<bytes32>",
    "signed_digest:bytes32",
    "auth_trailer:capability_or_signature",
];

pub(in crate::report) fn verify(
    inputs: &[(&str, &[u8])],
    native_digest: &[u8; 32],
    external_digest: &[u8; 32],
) -> Result<Vec<u32>, ReportError> {
    if inputs.iter().map(|(name, _)| *name).ne(NAMES) {
        return Err(invalid(
            "external-feed bundles require all eight registry documents in exact closure order",
        ));
    }
    let (units, _) = super::verify(&inputs[..4], native_digest, false)?;
    let mut transcript = Vec::new();
    for (name, bytes) in &inputs[4..] {
        transcript.extend_from_slice(name.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[bytes]));
    }
    if hash_parts(b"fa:external-feed-registry:v1", &[&transcript]) != *external_digest {
        return Err(invalid(
            "external-feed, attestation, evidence or redaction registry differs from the original external-feed closure",
        ));
    }

    let detail = document(inputs[4].1)?;
    if detail.root.len() != 10 || detail.named_tables != 0 || !detail.arrays.is_empty() {
        return Err(invalid("unsupported external-feed detail registry shape"));
    }
    for (key, value) in [
        ("entry_extension_tag", 30),
        ("entry_schema_minor", 1),
        ("document_kind", 21),
        ("evidence_role", 1),
        ("max_detail_rows", 128),
        ("max_detail_bytes", 8192),
        ("max_summary_legs", 32),
    ] {
        if integer(&detail.root, key)? != value {
            return Err(invalid(format!(
                "external-feed detail registry changes the supported {key} semantics",
            )));
        }
    }
    if string(&detail.root, "name")? != "fa:external-subledger-detail:v1"
        || string(&detail.root, "scope")?
            != "complete-native-gross-effects-of-one-reviewed-source-batch"
    {
        return Err(invalid("unsupported external-feed detail format or scope"));
    }

    let attestation = document(inputs[5].1)?;
    if string(&attestation.root, "name")? != "Attestation"
        || string(&attestation.root, "owner")? != "fa-journal::attestation"
        || integer(&attestation.root, "major")? != 1
        || !(0..=2).contains(&integer(&attestation.root, "minor")?)
        || string(&attestation.root, "signed_digest_domain")? != "fa:attestation:v1"
        || boolean(&attestation.root, "externally_verifiable")?
        || text_array(&attestation.root, "fields")? != ATTESTATION_FIELDS
    {
        return Err(invalid(
            "unsupported external-feed review attestation schema",
        ));
    }
    let mut tags = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut reviewed = false;
    for claim in text_array(&attestation.root, "claim_tags")? {
        let (raw, name) = claim
            .split_once(':')
            .ok_or_else(|| invalid("attestation claim tag lacks its numeric identity"))?;
        let tag = raw
            .parse::<u8>()
            .ok()
            .filter(|tag| *tag != 0 && tag.to_string() == raw)
            .ok_or_else(|| invalid("attestation claim identity is not a canonical u8"))?;
        if name.is_empty() || !tags.insert(tag) || !names.insert(name) {
            return Err(invalid("attestation registry repeats a claim identity"));
        }
        reviewed |= tag == 2 && name == "Reviewed";
    }
    if !reviewed {
        return Err(invalid(
            "attestation registry must preserve Reviewed claim tag 2",
        ));
    }

    let evidence = document(inputs[6].1)?;
    if integer(&evidence.root, "max_document_bytes")? != 16_777_216
        || integer(&evidence.root, "max_mime_bytes")? != 128
    {
        return Err(invalid(
            "unsupported external-feed evidence document bounds",
        ));
    }
    let kinds = tagged_names(rows(&evidence, "kind")?, 21, "Workpaper")?;
    tagged_names(rows(&evidence, "role")?, 1, "Source")?;

    let redaction = document(inputs[7].1)?;
    if redaction.root.len() != 1
        || redaction.named_tables != 0
        || redaction.arrays.keys().any(|name| name != "contract")
    {
        return Err(invalid(
            "unsupported external-feed redaction registry shape",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut governed = BTreeSet::new();
    for contract in redaction.arrays.get("contract").into_iter().flatten() {
        let id = integer(contract, "id")?;
        let name = string(contract, "name")?;
        if !(1..=u16::MAX as i128).contains(&id)
            || !ids.insert(id)
            || name.is_empty()
            || !names.insert(name)
            || string(contract, "reveal_op")? != "privileged"
            || string(contract, "meaning")?.trim().is_empty()
        {
            return Err(invalid("unsupported or duplicate redaction contract"));
        }
        let contract_kinds = text_array(contract, "kinds")?;
        if contract_kinds.is_empty() {
            return Err(invalid("redaction contract governs no document kind"));
        }
        for kind in contract_kinds {
            if !kinds.contains(kind) || !governed.insert(kind) {
                return Err(invalid(
                    "redaction contract repeats or invents a document kind",
                ));
            }
            if kind == "Workpaper" {
                return Err(invalid(
                    "external-feed portability requires fully disclosed Workpaper detail; governed Workpaper profiles are unsupported",
                ));
            }
        }
        let offsets = integer_array(contract, "offsets")?;
        let lengths = integer_array(contract, "lengths")?;
        if offsets.is_empty()
            || offsets.len() != lengths.len()
            || offsets
                .iter()
                .zip(lengths)
                .any(|(offset, length)| length == 0 || offset.checked_add(length).is_none())
        {
            return Err(invalid("redaction contract has invalid byte ranges"));
        }
    }
    Ok(units)
}

fn text_array<'a>(table: &'a Table, key: &str) -> Result<Vec<&'a str>, ReportError> {
    let Some(Value::Array(values)) = table.get(key) else {
        return Err(invalid(format!("registry field {key} must be an array")));
    };
    values
        .iter()
        .map(|value| match value {
            Value::Text(value) => Ok(value.as_str()),
            _ => Err(invalid(format!("registry field {key} must contain text"))),
        })
        .collect()
}

fn integer_array(table: &Table, key: &str) -> Result<Vec<u64>, ReportError> {
    let Some(Value::Array(values)) = table.get(key) else {
        return Err(invalid(format!("registry field {key} must be an array")));
    };
    values
        .iter()
        .map(|value| match value {
            Value::Int(value) => u64::try_from(*value)
                .map_err(|_| invalid(format!("registry field {key} is outside u64"))),
            _ => Err(invalid(format!(
                "registry field {key} must contain integers"
            ))),
        })
        .collect()
}

fn tagged_names<'a>(
    rows: &'a [Table],
    required_tag: i128,
    required_name: &str,
) -> Result<BTreeSet<&'a str>, ReportError> {
    let mut tags = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut required = false;
    for row in rows {
        let tag = integer(row, "tag")?;
        let name = string(row, "name")?;
        if !(1..=u8::MAX as i128).contains(&tag)
            || name.is_empty()
            || !tags.insert(tag)
            || !names.insert(name)
        {
            return Err(invalid(
                "evidence registry repeats or invalidates a tag identity",
            ));
        }
        required |= tag == required_tag && name == required_name;
    }
    if !required {
        return Err(invalid(format!(
            "evidence registry must preserve {required_name} tag {required_tag}",
        )));
    }
    Ok(names)
}

#[cfg(test)]
pub(in crate::report) mod tests;
