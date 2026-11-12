//! The independent registry gate must reject changed tracing laws even when
//! every public registry checksum has been repaired. Native registry bytes are
//! retained from the existing statement fixture. The selected procedure and
//! small SoD fixture below are literal rows from the published source registries,
//! encoded here without importing the producer parser or registry crate.

use super::*;
use crate::codec::Reader;
use crate::report::procedure::{Registry, VerifiedProcedureParameters};

fn trace_profile() -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::TraceLibr {
        intraday_order: 0,
        replenishment: 1,
        account: 10,
        source: 20,
    }
}

fn procedure_row() -> Table {
    BTreeMap::from([
        ("calibration".into(), Value::Text("uncalibrated".into())),
        ("claim".into(), Value::Text("statistical".into())),
        ("complexity".into(), Value::Text("O(posting_legs log entities + movements log movements)".into())),
        ("effective_through".into(), Value::Text("required".into())),
        ("evidence".into(), Value::Text("FA-EVID-L15".into())),
        ("id".into(), Value::Text("trace.libr".into())),
        ("summary".into(), Value::Text("Lowest intermediate balance rule (Restatement (Third) of Restitution §59): the traceable amount never exceeds the lowest balance of the account between the deposit and the claim date, and later deposits never replenish it.".into())),
        ("tie_break".into(), Value::Text("entry_vid".into())),
        ("version".into(), Value::Int(2)),
    ])
}

fn intraday_parameter() -> Table {
    BTreeMap::from([
        ("default".into(), Value::Int(0)),
        ("meaning".into(), Value::Text("How same-day movements are sequenced: 0 StatementOrdinal (recorded order), 2 WithdrawalsFirst, 3 DepositsFirst; 1 ValueDate is reserved until value dates are retained.".into())),
        ("name".into(), Value::Text("intraday_order".into())),
        ("procedure".into(), Value::Text("trace.libr".into())),
    ])
}

fn replenishment_parameter() -> Table {
    BTreeMap::from([
        ("default".into(), Value::Int(0)),
        ("meaning".into(), Value::Text("0 Never (Restatement §59(2)(c) default); 1 OnEvidence (inflows sharing cited evidence or supersession with the source replenish up to initial deposit).".into())),
        ("name".into(), Value::Text("replenishment".into())),
        ("procedure".into(), Value::Text("trace.libr".into())),
    ])
}

fn account_input() -> Table {
    BTreeMap::from([
        ("kind".into(), Value::Text("account".into())),
        (
            "meaning".into(),
            Value::Text("The commingled account the deposit went into.".into()),
        ),
        ("name".into(), Value::Text("account".into())),
        ("procedure".into(), Value::Text("trace.libr".into())),
    ])
}

fn source_input() -> Table {
    BTreeMap::from([
        ("kind".into(), Value::Text("entry".into())),
        (
            "meaning".into(),
            Value::Text("The entry whose inflow to the account is the claimant's deposit.".into()),
        ),
        ("name".into(), Value::Text("source".into())),
        ("procedure".into(), Value::Text("trace.libr".into())),
    ])
}

fn policy_default() -> Table {
    BTreeMap::from([
        ("agent_prepared_human_approvers".into(), Value::Int(0)),
        ("approver_op".into(), Value::Text("approve".into())),
        (
            "approver_profiles".into(),
            Value::Array(vec![Value::Text("Human".into())]),
        ),
        ("approvers".into(), Value::Int(0)),
        (
            "cite".into(),
            Value::Text("plan §14.3, Appendix C universal rules".into()),
        ),
        (
            "exclusions".into(),
            Value::Array(vec![
                Value::Text("preparer".into()),
                Value::Text("duplicate".into()),
            ]),
        ),
    ])
}

fn policy_rule() -> Table {
    BTreeMap::from([
        ("agent_prepared_human_approvers".into(), Value::Int(0)),
        ("approver_op".into(), Value::Text("approve".into())),
        (
            "approver_profiles".into(),
            Value::Array(vec![Value::Text("Human".into())]),
        ),
        ("approvers".into(), Value::Int(0)),
        (
            "cite".into(),
            Value::Text("plan §7.2, §14.3; fa-ehd".into()),
        ),
        ("class".into(), Value::Text("SchemaControl".into())),
        (
            "exclusions".into(),
            Value::Array(vec![
                Value::Text("preparer".into()),
                Value::Text("duplicate".into()),
            ]),
        ),
        ("name".into(), Value::Text("schema-period-create".into())),
        ("preparer_op".into(), Value::Text("schema_change".into())),
        ("transition".into(), Value::Text("CreatePeriods".into())),
    ])
}

fn procedure_document() -> Document {
    Document {
        root: BTreeMap::from([("schema_version".into(), Value::Int(1))]),
        named_tables: 0,
        tables: BTreeMap::new(),
        arrays: BTreeMap::from([
            ("procedure".into(), vec![procedure_row()]),
            (
                "parameter".into(),
                vec![intraday_parameter(), replenishment_parameter()],
            ),
            ("input".into(), vec![account_input(), source_input()]),
        ]),
    }
}

fn policy_document() -> Document {
    Document {
        root: BTreeMap::from([("schema_version".into(), Value::Int(1))]),
        named_tables: 1,
        tables: BTreeMap::from([("default".into(), policy_default())]),
        arrays: BTreeMap::from([("rule".into(), vec![policy_rule()])]),
    }
}

/// Independent canonical registry encoder used only to construct hostile
/// disclosed inputs. The production verifier must decode and interpret them.
fn encode_document(document: &Document) -> Vec<u8> {
    fn length(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend_from_slice(&(value as u64).to_le_bytes());
    }
    fn text(bytes: &mut Vec<u8>, value: &str) {
        length(bytes, value.len());
        bytes.extend_from_slice(value.as_bytes());
    }
    fn value(bytes: &mut Vec<u8>, entry: &Value) {
        match entry {
            Value::Text(entry) => {
                bytes.push(1);
                text(bytes, entry);
            }
            Value::Int(entry) => {
                bytes.push(2);
                bytes.extend_from_slice(&entry.to_le_bytes());
            }
            Value::Bool(entry) => bytes.extend_from_slice(&[3, u8::from(*entry)]),
            Value::Array(entries) => {
                bytes.push(4);
                length(bytes, entries.len());
                for entry in entries {
                    value(bytes, entry);
                }
            }
        }
    }
    fn table(bytes: &mut Vec<u8>, entries: &Table) {
        length(bytes, entries.len());
        for (name, entry) in entries {
            text(bytes, name);
            value(bytes, entry);
        }
    }
    let mut bytes = MAGIC.to_vec();
    table(&mut bytes, &document.root);
    length(&mut bytes, document.tables.len());
    for (name, entries) in &document.tables {
        text(&mut bytes, name);
        table(&mut bytes, entries);
    }
    length(&mut bytes, document.arrays.len());
    for (name, entries) in &document.arrays {
        text(&mut bytes, name);
        length(&mut bytes, entries.len());
        for entry in entries {
            table(&mut bytes, entry);
        }
    }
    bytes
}

fn registry_inputs(procedures: &Document) -> Vec<(String, Vec<u8>)> {
    let hex: Vec<_> = include_str!("../tests/registries.hex")
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
    for expected in NAMES {
        let name = std::str::from_utf8(reader.bytes(64, "registry name").unwrap()).unwrap();
        assert_eq!(name, expected);
        documents.push((
            name.into(),
            reader
                .bytes(MAX_DOCUMENT, "registry bytes")
                .unwrap()
                .to_vec(),
        ));
    }
    reader.finish("native registries").unwrap();
    documents.push(("procedures".into(), encode_document(procedures)));
    documents.push(("sod_policy".into(), encode_document(&policy_document())));
    documents
}

fn closure(documents: &[(String, Vec<u8>)], indices: &[usize], domain: &[u8]) -> [u8; 32] {
    let mut transcript = Vec::new();
    for &index in indices {
        let (name, bytes) = &documents[index];
        transcript.extend_from_slice(name.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[bytes]));
    }
    hash_parts(domain, &[&transcript])
}

fn verify_bound(
    documents: &[(String, Vec<u8>)],
    profile: VerifiedProcedureParameters,
    version: u16,
    native: [u8; 32],
    procedure: [u8; 32],
) -> Result<Registry, ReportError> {
    let inputs: Vec<_> = documents
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    verify_procedure(&inputs, &native, &procedure, profile, version)
}

fn verify_rehashed(procedures: &Document) -> Result<Registry, ReportError> {
    let documents = registry_inputs(procedures);
    let native = closure(&documents, &[0, 1, 2, 3], b"fa:report-registry-closure:v2");
    let procedure = closure(&documents, &[4, 3], b"fa:procedure-registry:v2");
    verify_bound(&documents, trace_profile(), 2, native, procedure)
}

#[test]
fn libr_registry_accepts_its_source_derived_contract_and_canonical_input_inventory() {
    let mut procedures = procedure_document();
    let verified = verify_rehashed(&procedures).unwrap();
    assert!(!verified.unit_scales.is_empty());
    assert!(
        verified.trace.is_none(),
        "chart and entry facts still require source replay"
    );
    let policy = concat!(
        "fa:sod-policy:v1\n",
        "default|approvers=0|approver_op=approve|approver_profiles=Human|agent_prepared_human_approvers=0|exclusions=duplicate,preparer\n",
        "rule:schema-period-create|class=SchemaControl|state=-|disposition=-|transition=CreatePeriods|preparer_op=schema_change|approvers=0|approver_op=approve|approver_profiles=Human|agent_prepared_human_approvers=0|exclusions=duplicate,preparer\n",
    );
    assert_eq!(
        verified.policy_oid,
        hash_parts(
            b"fa:policy:v1",
            &[&(policy.len() as u32).to_le_bytes(), policy.as_bytes()]
        )
    );
    // Declaration order is not parameter/input identity. Both complete arrays
    // can be reordered when their new canonical bytes are properly committed.
    procedures.arrays.get_mut("input").unwrap().reverse();
    procedures.arrays.get_mut("parameter").unwrap().reverse();
    assert_eq!(
        verify_rehashed(&procedures).unwrap().policy_oid,
        verified.policy_oid
    );
}

#[test]
fn libr_registry_rejects_rehashed_changes_to_the_registered_law() {
    for variant in [
        "version",
        "claim",
        "evidence",
        "tie break",
        "complexity",
        "calibration",
        "artifact",
        "optional cutoff",
        "missing cutoff",
        "duplicate procedure",
        "missing procedure",
    ] {
        let mut procedures = procedure_document();
        let rows = procedures.arrays.get_mut("procedure").unwrap();
        let row = &mut rows[0];
        match variant {
            "version" => {
                row.insert("version".into(), Value::Int(1));
            }
            "claim" => {
                row.insert("claim".into(), Value::Text("invariant".into()));
            }
            "evidence" => {
                row.insert("evidence".into(), Value::Text("FA-EVID-L01".into()));
            }
            "tie break" => {
                row.insert("tie_break".into(), Value::Text("none".into()));
            }
            "complexity" => {
                row.insert("complexity".into(), Value::Text("O(entries)".into()));
            }
            "calibration" => {
                row.insert("calibration".into(), Value::Text("corpus".into()));
            }
            "artifact" => {
                row.insert("artifact".into(), Value::Text("FA-ART-CAL-01".into()));
            }
            "optional cutoff" => {
                row.insert("effective_through".into(), Value::Text("optional".into()));
            }
            "missing cutoff" => {
                row.remove("effective_through");
            }
            "duplicate procedure" => rows.push(procedure_row()),
            "missing procedure" => rows.clear(),
            _ => unreachable!(),
        }
        let error = verify_rehashed(&procedures).err().expect(variant);
        assert_eq!(error.predicate, "registry_closure", "{variant}: {error}");
    }
}

#[test]
fn libr_registry_rejects_rehashed_missing_duplicated_or_reinterpreted_inputs_and_parameters() {
    for variant in [
        "missing account",
        "missing source",
        "duplicate input",
        "wrong input kind",
        "renamed input",
        "extra input",
        "missing parameter",
        "duplicate parameter",
        "changed default",
        "renamed parameter",
        "extra declaration",
    ] {
        let mut procedures = procedure_document();
        match variant {
            "missing account" => {
                procedures.arrays.get_mut("input").unwrap().remove(0);
            }
            "missing source" => {
                procedures.arrays.get_mut("input").unwrap().pop();
            }
            "duplicate input" => {
                procedures.arrays.get_mut("input").unwrap()[1] = account_input();
            }
            "wrong input kind" => {
                procedures.arrays.get_mut("input").unwrap()[1]
                    .insert("kind".into(), Value::Text("account".into()));
            }
            "renamed input" => {
                procedures.arrays.get_mut("input").unwrap()[1]
                    .insert("name".into(), Value::Text("target".into()));
            }
            "extra input" => {
                procedures
                    .arrays
                    .get_mut("input")
                    .unwrap()
                    .push(source_input());
            }
            "missing parameter" => {
                procedures.arrays.get_mut("parameter").unwrap().pop();
            }
            "duplicate parameter" => {
                procedures.arrays.get_mut("parameter").unwrap()[1] = intraday_parameter();
            }
            "changed default" => {
                procedures.arrays.get_mut("parameter").unwrap()[0]
                    .insert("default".into(), Value::Int(2));
            }
            "renamed parameter" => {
                procedures.arrays.get_mut("parameter").unwrap()[1]
                    .insert("name".into(), Value::Text("unregistered_law".into()));
            }
            "extra declaration" => {
                procedures
                    .arrays
                    .insert("future_semantics".into(), vec![source_input()]);
            }
            _ => unreachable!(),
        }
        let error = verify_rehashed(&procedures).err().expect(variant);
        assert_eq!(error.predicate, "registry_closure", "{variant}: {error}");
    }
}

#[test]
fn libr_registry_binds_both_closures_and_the_six_document_order() {
    let mut procedures = procedure_document();
    let documents = registry_inputs(&procedures);
    let native = closure(&documents, &[0, 1, 2, 3], b"fa:report-registry-closure:v2");
    let procedure = closure(&documents, &[4, 3], b"fa:procedure-registry:v2");
    for (native, procedure, version) in [
        ([0; 32], procedure, 2),
        (native, [0; 32], 2),
        (native, procedure, 1),
    ] {
        let error = verify_bound(&documents, trace_profile(), version, native, procedure)
            .err()
            .unwrap();
        assert_eq!(error.predicate, "registry_closure");
    }
    let mut reordered = registry_inputs(&procedures);
    reordered.swap(4, 5);
    assert_eq!(
        verify_bound(&reordered, trace_profile(), 2, native, procedure)
            .err()
            .unwrap()
            .predicate,
        "registry_closure"
    );
    // A harmless summary change still moves the committed registry bytes;
    // repairing that checksum is necessary but cannot bless changed laws.
    procedures.arrays.get_mut("procedure").unwrap()[0].insert(
        "summary".into(),
        Value::Text("A different description of the same registered law".into()),
    );
    let changed = registry_inputs(&procedures);
    assert_eq!(
        verify_bound(&changed, trace_profile(), 2, native, procedure)
            .err()
            .unwrap()
            .predicate,
        "registry_closure"
    );
    assert!(verify_rehashed(&procedures).is_ok());
}
