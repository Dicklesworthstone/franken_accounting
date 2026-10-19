//! Durable provenance tests use the public bank wire and the real import transaction.

use super::*;
use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::import::{ImportPreparation, document_sources, encode_derivation};
use fa_journal::{AccountSpec, BookSpec};
use fa_model::account_vid;
use fa_money::{Amount, UnitRegistry};
use fa_time::FiscalCalendar;
use fgdb::MemVfs;

use crate::{BookKeys, Entropy};

const PRINCIPAL: VId = VId(717);
const PATH: &str = "bank-provenance-book";
const CSV: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n1,BANK-OPER-01,USD,2026-03-31,1000.00,1450.00,2026-03-05,2026-03-05,CRDT,600.00,Acme Customer,WIRE-IN-1\n1,BANK-OPER-01,USD,2026-03-31,1000.00,1450.00,2026-03-10,2026-03-10,DBIT,150.00,Cloud Vendor,ACH-OUT-1\n";

fn day() -> DateDay {
    DateDay::from_ymd(2026, 3, 31).unwrap()
}

fn cap(principal: VId) -> Capability {
    Capability::embedded(principal, &["read", "post", "reconcile"]).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    keys: BookKeys,
}

impl Harness {
    fn new(seed: u8) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let unit = units.lookup("USD").unwrap();
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let keys = BookKeys::for_development(seed);
        let mut book = runtime.block_on(AsyncBook::create_with_vfs(
            &cx,
            vfs.clone(),
            Path::new(PATH),
            keys.clone(),
            BookSpec {
                book_id: Id128([seed; 16]),
                name: "Bank provenance".into(),
                base_unit: unit,
                calendar: FiscalCalendar::monthly("bank", 1, 0).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(u64::from(seed)),
        )).unwrap();
        runtime.block_on(book.install_chart(
            &cx,
            &[AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(unit),
                parent_code: None,
                limit: None,
            }],
            PRINCIPAL,
            day(),
            b"chart",
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )).unwrap().unwrap();
        Self { runtime, root, book, vfs, keys }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn import(&mut self, principal: VId) -> BankImportRecorded {
        let cx = self.cx();
        let account = account_vid(self.book.context().book_id, "1000");
        self.runtime.block_on(self.book.import_bank_statement(
            &cx, &cap(principal), BankImportRequest {
                account,
                format: BankFormat::Csv,
                bytes: CSV.as_bytes().to_vec(),
            },
        )).unwrap().unwrap()
    }

    fn document(&self, kind: &str, bytes: Vec<u8>) -> Document {
        let policy = EvidencePolicy::embedded().unwrap();
        Document {
            book_id: self.book.context().book_id,
            kind: policy_kind(&policy, kind).unwrap(),
            mime: "application/octet-stream".into(),
            grade: fa_journal::upload::upload_grade(&policy, Profile::Agent).unwrap(),
            retrieved_by: PRINCIPAL,
            bytes,
        }
    }

    fn line(&self, statement_oid: Oid) -> Document {
        let line = BankStatementLine {
            statement_oid,
            statement_seq: 1,
            line_ordinal: 0,
            booking_date: day(),
            value_date: day(),
            side: Side::Credit,
            amount: Amount::new(self.book.context().units.lookup("USD").unwrap(), 50),
            counterparty: "Customer".into(),
            reference: "reference".into(),
        };
        let mut document = self.document("Other", line.canonical_bytes().unwrap());
        document.mime = LINE_MIME.into();
        document
    }

    fn prepare(&mut self, key: &[u8], documents: Vec<Document>) -> Box<fa_journal::import::PreparedImport> {
        let cx = self.cx();
        let request = fa_journal::ImportRequest {
            principal: PRINCIPAL,
            source: IntakeSource::Upload { principal: PRINCIPAL },
            idempotency_key: key.to_vec(),
            effective_date: day(),
            description: self.book.seal_text(&cx, "provenance transaction").unwrap(),
            documents,
        };
        let context = self.book.context().clone();
        let preparation = self.runtime.block_on(
            fa_journal::import::prepare_import_in_store(
                &mut self.book.db,
                &cx,
                &context,
                &cap(PRINCIPAL),
                &self.book.blobs,
                request,
            ),
        ).unwrap().unwrap();
        match preparation {
            ImportPreparation::Ready(prepared) => prepared,
            ImportPreparation::AlreadyRecorded(_) => panic!("fresh transaction expected"),
        }
    }
}

#[test]
fn bank_import_projects_native_sources_in_one_counted_publication() {
    let mut h = Harness::new(121);
    let before = h.head();
    let vertices_before = h.book.db.vertices_at(before).unwrap().len();
    let edges_before = h.book.db.edges_at(before).unwrap().len();
    let imported = h.import(PRINCIPAL);
    let after = h.head();
    let costs = fa_registry::g0::OperationCosts::embedded().unwrap();
    let operation = costs.class("bank_statement_import").unwrap();
    assert_eq!(after.0 - before.0, u64::from(operation.today_transactions));
    assert_eq!(after.0, before.0 + 1);
    assert_eq!(imported.receipt.receipt.document_count, 4);
    assert_eq!(h.book.db.vertices_at(after).unwrap().len() - vertices_before, 9);
    assert_eq!(h.book.db.edges_at(after).unwrap().len() - edges_before, 13);

    let edges = h.book.db.edges_at(after).unwrap();
    let derived: Vec<_> = edges.iter().filter(|edge| {
        edge.entry.relation == fa_model::symbols::relation::DERIVED_FROM
    }).collect();
    assert_eq!(derived.len(), 5);
    for line in &imported.manifest.line_oids {
        assert!(derived.iter().any(|edge| {
            edge.entry.src == fa_journal::evidence::document_vid(line)
                && edge.entry.dst == fa_journal::evidence::document_vid(&imported.manifest.statement_oid)
        }));
    }
    for parent in imported.manifest.line_oids.iter()
        .chain(std::iter::once(&imported.manifest.statement_oid))
    {
        assert!(derived.iter().any(|edge| {
            edge.entry.src == fa_journal::evidence::document_vid(&imported.manifest_oid)
                && edge.entry.dst == fa_journal::evidence::document_vid(parent)
        }));
    }
    let same = h.import(VId(718));
    assert!(same.receipt.already_recorded);
    assert_eq!(same.receipt.receipt, imported.receipt.receipt);
    assert_eq!(h.head(), after);

    let cx = h.cx();
    drop(h.book);
    h.book = h.runtime.block_on(AsyncBook::open_with_vfs(
        &cx, h.vfs.clone(), Path::new(PATH), h.keys.clone(), Entropy::deterministic(122),
    )).unwrap();
    let match_capability = Capability::embedded(
        PRINCIPAL,
        &["read", "reconcile", "privileged"],
    ).unwrap();
    let replay = h.runtime.block_on(h.book.match_bank_statement(
        &cx, &match_capability, BankMatchRequest {
            manifest_oid: imported.manifest_oid,
            known_at: Some(after),
            date_window_days: 3,
        },
    )).unwrap().unwrap();
    assert_eq!(replay.manifest, imported.manifest);
    assert_eq!(replay.lines.len(), 2);
    assert_eq!(h.head(), after, "replaying native sources stays read-only");
}

#[test]
fn unsupported_or_forged_sources_abort_every_import_graph_effect() {
    let mut h = Harness::new(123);
    let cx = h.cx();
    let source = h.document("BankStatement", b"source".to_vec());
    let mut trailing = h.line(source.oid());
    trailing.bytes.push(0);
    let invalid = [
        h.line(Oid([255; 32])),
        h.document("Other", b"ordinary bytes do not declare provenance".to_vec()),
        trailing,
    ];
    for (index, child) in invalid.into_iter().enumerate() {
        let head = h.head();
        let vertices = h.book.db.vertices_at(head).unwrap().len();
        let prepared = h.prepare(&[u8::try_from(index).unwrap()], vec![source.clone(), child.clone()]);
        let refusal = prepared.with_document_derivations(
            &mut h.book.db, &cx, std::slice::from_ref(&child),
        ).unwrap().unwrap_err();
        assert_eq!(refusal.code, code::DOCUMENT_INTAKE);
        assert_eq!(h.head(), head);
        assert_eq!(h.book.db.vertices_at(head).unwrap().len(), vertices);
        assert!(fa_journal::document_record(&h.book.db, &child.oid()).unwrap().is_none());
    }
}

#[test]
fn existing_native_documents_cannot_gain_unrecorded_source_edges() {
    let mut h = Harness::new(124);
    let cx = h.cx();
    let source = h.document("BankStatement", b"held source".to_vec());
    let child = h.line(source.oid());
    for document in [&source, &child] {
        h.runtime.block_on(h.book.add_document(&cx, document)).unwrap().unwrap();
    }
    let head = h.head();
    let prepared = h.prepare(b"held-source", vec![source, child.clone()]);
    let refusal = prepared.with_document_derivations(
        &mut h.book.db, &cx, &[child],
    ).unwrap().unwrap_err();
    assert_eq!(refusal.code, code::DOCUMENT_INTAKE);
    assert_eq!(h.head(), head);
    assert!(h.book.db.edges_at(head).unwrap().iter().all(|edge| {
        edge.entry.relation != fa_model::symbols::relation::DERIVED_FROM
    }));
}

#[test]
fn native_source_reader_preserves_kind_version_book_and_complete_wire_checks() {
    let h = Harness::new(125);
    let source = h.document("BankStatement", b"bank source".to_vec());
    let child = h.line(source.oid());
    assert_eq!(document_sources(&child).unwrap(), [source.oid()]);
    let mut wrong_kind = child.clone();
    wrong_kind.kind = policy_kind(&EvidencePolicy::embedded().unwrap(), "Invoice").unwrap();
    assert!(document_sources(&wrong_kind).is_err());
    for end in 0..child.bytes.len() {
        let mut truncated = child.clone();
        truncated.bytes.truncate(end);
        assert!(document_sources(&truncated).is_err());
    }
    let manifest = BankImportManifest {
        book_id: h.book.context().book_id,
        account: account_vid(h.book.context().book_id, "1000"),
        format: BankFormat::Csv,
        statement_oid: source.oid(),
        statement_commit: source.doc_commit(),
        unit: h.book.context().units.lookup("USD").unwrap(),
        sequence_number: 1,
        statement_date: day(),
        opening_balance: 0,
        closing_balance: 50,
        line_oids: vec![child.oid()],
    };
    let mut document = h.document("Workpaper", manifest.canonical_bytes().unwrap());
    let mut expected = vec![source.oid(), child.oid()];
    expected.sort();
    assert_eq!(document_sources(&document).unwrap(), expected);
    document.bytes[14] = 2;
    assert!(document_sources(&document).is_err());
    document.bytes = manifest.canonical_bytes().unwrap();
    document.book_id = Id128([126; 16]);
    assert!(document_sources(&document).is_err());
}

#[test]
fn generic_content_bound_sources_share_the_same_atomic_publication_path() {
    let mut h = Harness::new(127);
    let cx = h.cx();
    let source = h.document("Other", b"original evidence".to_vec());
    let child = h.document("Workpaper", encode_derivation(
        &[source.oid()], b"derived evidence",
    ).unwrap());
    let head = h.head();
    let prepared = h.prepare(b"generic", vec![source, child.clone()]);
    let prepared = prepared.with_document_derivations(
        &mut h.book.db, &cx, &[child],
    ).unwrap().unwrap();
    let recorded = h.runtime.block_on(prepared.commit(&mut h.book.db, &cx)).unwrap().unwrap();
    assert!(!recorded.already_recorded);
    assert_eq!(h.head().0, head.0 + 1);
    assert_eq!(h.book.db.edges_at(h.head()).unwrap().iter().filter(|edge| {
        edge.entry.relation == fa_model::symbols::relation::DERIVED_FROM
    }).count(), 1);
}
