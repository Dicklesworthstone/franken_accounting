//! Literal supported semantic inputs, independently encoded rather than using
//! the producer TOML parser. Hostile edits repair both public registry closures.

use super::super::{Document, MAGIC};
use super::*;
use crate::codec::Reader;
use std::collections::BTreeMap;

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn texts(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|value| text(value)).collect())
}

fn document_with(root: Table, arrays: BTreeMap<String, Vec<Table>>) -> Document {
    Document {
        root,
        named_tables: 0,
        tables: BTreeMap::new(),
        arrays,
    }
}

fn tag_rows(names: &[&str]) -> Vec<Table> {
    names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            BTreeMap::from([
                ("tag".into(), Value::Int(index as i128 + 1)),
                ("name".into(), text(name)),
            ])
        })
        .collect()
}

fn supplemental() -> [Document; 4] {
    let detail = document_with(
        BTreeMap::from([
            ("schema_version".into(), Value::Int(1)),
            ("name".into(), text("fa:external-subledger-detail:v1")),
            ("entry_extension_tag".into(), Value::Int(30)),
            ("entry_schema_minor".into(), Value::Int(1)),
            ("document_kind".into(), Value::Int(21)),
            ("evidence_role".into(), Value::Int(1)),
            ("max_detail_rows".into(), Value::Int(128)),
            ("max_detail_bytes".into(), Value::Int(8192)),
            ("max_summary_legs".into(), Value::Int(32)),
            (
                "scope".into(),
                text("complete-native-gross-effects-of-one-reviewed-source-batch"),
            ),
        ]),
        BTreeMap::new(),
    );
    let attestation = document_with(
        BTreeMap::from([
            ("schema_version".into(), Value::Int(1)),
            ("name".into(), text("Attestation")),
            ("owner".into(), text("fa-journal::attestation")),
            ("major".into(), Value::Int(1)),
            ("minor".into(), Value::Int(2)),
            ("signed_digest_domain".into(), text("fa:attestation:v1")),
            ("externally_verifiable".into(), Value::Bool(false)),
            ("fields".into(), texts(&ATTESTATION_FIELDS)),
            (
                "claim_tags".into(),
                texts(&[
                    "1:Prepared",
                    "2:Reviewed",
                    "3:Reconciled",
                    "4:RegisterEquals",
                    "5:Confirmed",
                    "6:Examined",
                    "7:Custom",
                    "8:ManualAssertion",
                    "11:ReconciledOutstanding",
                ]),
            ),
        ]),
        BTreeMap::new(),
    );
    let evidence = document_with(
        BTreeMap::from([
            ("schema_version".into(), Value::Int(1)),
            ("max_document_bytes".into(), Value::Int(16_777_216)),
            ("max_mime_bytes".into(), Value::Int(128)),
        ]),
        BTreeMap::from([
            (
                "kind".into(),
                tag_rows(&[
                    "Invoice",
                    "Bill",
                    "Receipt",
                    "Contract",
                    "BankStatement",
                    "Check",
                    "WireConfirmation",
                    "Remittance",
                    "PurchaseOrder",
                    "ReceivingReport",
                    "Rate",
                    "Confirmation",
                    "Representation",
                    "BoardMinutes",
                    "CourtOrder",
                    "Memo",
                    "Email",
                    "Spreadsheet",
                    "Image",
                    "Disclosure",
                    "Workpaper",
                    "Other",
                ]),
            ),
            (
                "role".into(),
                tag_rows(&[
                    "Source",
                    "Support",
                    "Rate",
                    "Contract",
                    "Statement",
                    "Approval",
                    "Other",
                ]),
            ),
        ]),
    );
    let redaction = document_with(
        BTreeMap::from([("schema_version".into(), Value::Int(1))]),
        BTreeMap::from([(
            "contract".into(),
            vec![BTreeMap::from([
                ("id".into(), Value::Int(1)),
                ("name".into(), text("statement-account-block")),
                ("kinds".into(), texts(&["BankStatement"])),
                ("offsets".into(), Value::Array(vec![Value::Int(0)])),
                ("lengths".into(), Value::Array(vec![Value::Int(4096)])),
                ("reveal_op".into(), text("privileged")),
                (
                    "meaning".into(),
                    text(
                        "a bank statement's first page: the account holder, the account and routing numbers",
                    ),
                ),
            ])],
        )]),
    );
    [detail, attestation, evidence, redaction]
}

fn encode(document: &Document) -> Vec<u8> {
    fn length(bytes: &mut Vec<u8>, length: usize) {
        bytes.extend_from_slice(&(length as u64).to_le_bytes());
    }
    fn string(bytes: &mut Vec<u8>, value: &str) {
        length(bytes, value.len());
        bytes.extend_from_slice(value.as_bytes());
    }
    fn value(bytes: &mut Vec<u8>, entry: &Value) {
        match entry {
            Value::Text(value) => {
                bytes.push(1);
                string(bytes, value);
            }
            Value::Int(value) => {
                bytes.push(2);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            Value::Bool(value) => bytes.extend_from_slice(&[3, u8::from(*value)]),
            Value::Array(values) => {
                bytes.push(4);
                length(bytes, values.len());
                for entry in values {
                    value(bytes, entry);
                }
            }
        }
    }
    fn table(bytes: &mut Vec<u8>, table: &Table) {
        length(bytes, table.len());
        for (name, entry) in table {
            string(bytes, name);
            value(bytes, entry);
        }
    }
    let mut bytes = MAGIC.to_vec();
    table(&mut bytes, &document.root);
    length(&mut bytes, document.tables.len());
    for (name, entries) in &document.tables {
        string(&mut bytes, name);
        table(&mut bytes, entries);
    }
    length(&mut bytes, document.arrays.len());
    for (name, entries) in &document.arrays {
        string(&mut bytes, name);
        length(&mut bytes, entries.len());
        for entry in entries {
            table(&mut bytes, entry);
        }
    }
    bytes
}

/// Four supplemental semantic-profile documents for offline replay fixtures.
/// Native admission policy rows are deliberately outside this verifier's claim.
pub(in crate::report) fn fixture_documents() -> Vec<(String, Vec<u8>)> {
    NAMES[4..]
        .iter()
        .zip(supplemental())
        .map(|(name, document)| ((*name).into(), encode(&document)))
        .collect()
}

fn all_documents() -> Vec<(String, Vec<u8>)> {
    let hex: Vec<_> = include_str!("../../tests/registries.hex")
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(hex.len() % 2, 0);
    let bytes: Vec<_> = hex
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.count(4, 8, "native registries").unwrap(), 4);
    let mut documents = Vec::new();
    for expected in &NAMES[..4] {
        let name = std::str::from_utf8(reader.bytes(64, "registry name").unwrap()).unwrap();
        assert_eq!(&name, expected);
        documents.push((
            name.into(),
            reader
                .bytes(1024 * 1024, "registry bytes")
                .unwrap()
                .to_vec(),
        ));
    }
    reader.finish("native registries").unwrap();
    documents.extend(fixture_documents());
    documents
}

fn closure(documents: &[(String, Vec<u8>)], domain: &[u8]) -> [u8; 32] {
    let mut transcript = Vec::new();
    for (name, bytes) in documents {
        transcript.extend_from_slice(name.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[bytes]));
    }
    hash_parts(domain, &[&transcript])
}

fn verify_resealed(documents: &[(String, Vec<u8>)]) -> Result<Vec<u32>, ReportError> {
    let inputs: Vec<_> = documents
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    verify(
        &inputs,
        &closure(&documents[..4], b"fa:report-registry-closure:v2"),
        &closure(&documents[4..], b"fa:external-feed-registry:v1"),
    )
}

#[test]
fn complete_independent_closures_accept_supported_semantics_only_in_order() {
    let mut documents = all_documents();
    assert!(!verify_resealed(&documents).unwrap().is_empty());
    documents.swap(4, 5);
    assert!(verify_resealed(&documents).is_err());
    documents.swap(4, 5);
    documents.pop();
    assert!(verify_resealed(&documents).is_err());
    let mut documents = all_documents();
    documents[7].0 = "evidence_policy".into();
    assert!(verify_resealed(&documents).is_err());
}

#[test]
fn repaired_closures_cannot_change_detail_schema_or_evidence_interpretation() {
    for (index, key, value) in [
        (4, "schema_version", Value::Int(2)),
        (4, "entry_extension_tag", Value::Int(31)),
        (4, "entry_schema_minor", Value::Int(2)),
        (4, "document_kind", Value::Int(22)),
        (4, "evidence_role", Value::Int(2)),
        (4, "max_detail_rows", Value::Int(129)),
        (4, "max_detail_bytes", Value::Int(8193)),
        (4, "max_summary_legs", Value::Int(33)),
        (4, "scope", text("netted-effects")),
        (5, "minor", Value::Int(3)),
        (5, "signed_digest_domain", text("changed:attestation:v1")),
        (5, "externally_verifiable", Value::Bool(true)),
        (5, "fields", texts(&["claim:tagged_claim"])),
        (5, "claim_tags", texts(&["1:Prepared", "2:Confirmed"])),
        (5, "claim_tags", texts(&["2:Reviewed", "2:Renamed"])),
        (6, "max_document_bytes", Value::Int(16_777_217)),
        (6, "max_mime_bytes", Value::Int(129)),
    ] {
        let mut documents = all_documents();
        let mut changed = document(&documents[index].1).unwrap();
        changed.root.insert(key.into(), value);
        documents[index].1 = encode(&changed);
        assert!(
            verify_resealed(&documents).is_err(),
            "document {index}: {key}"
        );
    }
    for (table, index) in [("kind", 20), ("role", 0)] {
        let mut documents = all_documents();
        let mut changed = document(&documents[6].1).unwrap();
        changed.arrays.get_mut(table).unwrap()[index].insert("name".into(), text("Renamed"));
        documents[6].1 = encode(&changed);
        assert!(verify_resealed(&documents).is_err(), "{table}");
    }
}

#[test]
fn redaction_cannot_silently_change_full_disclosure_of_source_detail() {
    for (key, value) in [
        ("kinds", texts(&["Workpaper"])),
        ("kinds", texts(&["Unknown"])),
        ("kinds", texts(&["BankStatement", "BankStatement"])),
        ("offsets", Value::Array(vec![Value::Int(u64::MAX as i128)])),
        ("lengths", Value::Array(vec![Value::Int(0)])),
        ("reveal_op", text("read")),
    ] {
        let mut documents = all_documents();
        let mut changed = document(&documents[7].1).unwrap();
        changed.arrays.get_mut("contract").unwrap()[0].insert(key.into(), value);
        documents[7].1 = encode(&changed);
        assert!(verify_resealed(&documents).is_err(), "{key}");
    }
}

#[test]
fn both_registry_closures_are_independently_required() {
    let documents = all_documents();
    let inputs: Vec<_> = documents
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let native = closure(&documents[..4], b"fa:report-registry-closure:v2");
    let external = closure(&documents[4..], b"fa:external-feed-registry:v1");
    for (native, external) in [([0; 32], external), (native, [0; 32])] {
        assert!(verify(&inputs, &native, &external).is_err());
    }
}
