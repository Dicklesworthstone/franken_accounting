//! Public-facade tests for capability-bound inline and external evidence.
//! No raw database or owner-only intake is used to insert test documents.
#![forbid(unsafe_code)]

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::{AsyncBook, BookKeys, Capability, Entropy, Op, Profile, UploadRequest};
use fa_journal::{AccountSpec, BookSpec, Document, DocumentRead, PostRequest, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid};
use fa_money::{Amount, Side, UnitRegistry};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

fn runtime() -> (Runtime, Cx) {
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    (runtime, root)
}

fn policy() -> EvidencePolicy {
    EvidencePolicy::embedded().unwrap()
}

fn request(bytes: Vec<u8>) -> UploadRequest {
    UploadRequest {
        kind: policy().kind_by_name("Invoice").unwrap().tag,
        mime: "application/octet-stream".into(),
        bytes,
        asserted_grade: None,
    }
}

fn agent(holder: u128) -> Capability {
    Capability::new(VId(holder), Profile::Agent, &[Op::Post], VId(1)).unwrap()
}

fn reader() -> Capability {
    Capability::embedded(VId(900), &["read", "privileged"]).unwrap()
}

fn full(read: DocumentRead) -> Document {
    match read {
        DocumentRead::Full(document) => document,
        other => panic!("privileged reader must see verified full bytes: {other:?}"),
    }
}

fn spec(seed: u8) -> BookSpec {
    BookSpec {
        book_id: Id128([seed; 16]),
        name: format!("Upload facade {seed}"),
        base_unit: UnitRegistry::with_defaults().lookup("USD").unwrap(),
        calendar: FiscalCalendar::monthly(&format!("upload-{seed}"), 1, 1).unwrap(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    }
}

async fn create(cx: &PurposeContexts, vfs: MemVfs, path: &Path, seed: u8) -> AsyncBook<MemVfs> {
    AsyncBook::create_with_vfs(
        cx,
        vfs,
        path,
        BookKeys::for_development(seed),
        spec(seed),
        Entropy::deterministic(u64::from(seed)),
    )
    .await
    .unwrap()
}

#[test]
fn facade_routes_to_its_own_store_and_reopens_exact_large_document() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let path = Path::new("book");
        let mut book = create(&cx, vfs.clone(), path, 91).await;
        let cap = agent(11);
        let size = usize::try_from(policy().max_document_bytes.checked_add(1).unwrap()).unwrap();
        let mut bytes = vec![0x73; size];
        bytes[size - 1] = 0x21;
        let before = book.head(&cx).unwrap();
        let added = book
            .upload_document(&cx, &cap, request(bytes.clone()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(added.recorded_at.0, before.0 + 1);
        assert_eq!(
            added.grade,
            policy().grade_by_name("AgentUpload").unwrap().tag
        );
        assert_eq!(added.size, u64::try_from(size).unwrap());
        let read = full(
            book.read_document_for(&cx, &reader(), &added.oid)
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(read.bytes, bytes);
        assert_eq!(read.retrieved_by, cap.holder());
        drop(read);
        let chain = book.custody_chain(&cx, &added.oid).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].1, added.recorded_at);
        let before_reopen = book.head(&cx).unwrap();
        drop(book);

        let mut reopened = AsyncBook::open_with_vfs(
            &cx,
            vfs,
            path,
            BookKeys::for_development(91),
            Entropy::deterministic(92),
        )
        .await
        .unwrap();
        assert_eq!(reopened.head(&cx).unwrap(), before_reopen);
        let read = full(
            reopened
                .read_document_for(&cx, &reader(), &added.oid)
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(read.bytes, bytes);
        assert_eq!(read.doc_commit(), added.doc_commit);
        assert_eq!(read.retrieved_by, cap.holder());
        drop(read);
        let human = Capability::embedded(VId(12), &["post"]).unwrap();
        let retry = reopened
            .upload_document(&cx, &human, request(bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(retry.already_recorded);
        assert_eq!(
            (retry.oid, retry.grade, retry.recorded_at),
            (added.oid, added.grade, added.recorded_at)
        );
        assert_eq!(reopened.head(&cx).unwrap(), before_reopen);
        assert_eq!(reopened.custody_chain(&cx, &added.oid).unwrap(), chain);
    });
}

#[test]
fn uploaded_agent_evidence_cannot_post_until_a_different_human_reviews_it() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = create(&cx, vfs, Path::new("book"), 93).await;
        let usd = book.context().units.lookup("USD").unwrap();
        let principal = VId(101);
        let date = DateDay::from_ymd(2026, 3, 15).unwrap();
        let chart: Vec<_> = [("1000", "Cash", 1), ("6000", "Expense", 5)]
            .into_iter()
            .map(|(code, name, account_type)| AccountSpec {
                code: code.into(),
                name: name.into(),
                account_type,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            })
            .collect();
        book.install_chart(
            &cx,
            &chart,
            principal,
            date,
            b"chart",
            &fa_journal::Capability::embedded(principal, &["schema_change"]).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        book.create_periods(
            &cx,
            2026,
            principal,
            &Capability::embedded(principal, &["schema_change"]).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let controller = Capability::embedded(principal, &["post", "close"]).unwrap();
        book.transition_period(
            &cx,
            "FY2026-P03",
            PeriodTransition::Open,
            principal,
            1,
            b"open",
            &controller,
        )
        .await
        .unwrap()
        .unwrap();
        let accounts = book.accounts(&cx).unwrap();
        let account = |code: &str| accounts.iter().find(|row| row.code == code).unwrap().vid;
        let bytes = b"agent-collected invoice".to_vec();
        let uploaded = book
            .upload_document(&cx, &agent(102), request(bytes.clone()))
            .await
            .unwrap()
            .unwrap();
        let legs = vec![
            LegPayload::simple(Side::Debit, account("6000"), Amount::new(usd, 12_345)),
            LegPayload::simple(Side::Credit, account("1000"), Amount::new(usd, 12_345)),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: date,
            document_date: Some(date),
            description: book
                .seal_text(&cx, "expense supported by reviewed evidence")
                .unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: b"reviewed-expense".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([7; 32]),
                intent_kind: 1,
            },
            principal_ref: principal,
            session_ref: None,
            evidence: vec![EvidenceRef {
                document_oid: uploaded.oid,
                doc_commit: uploaded.doc_commit,
                role: policy()
                    .roles
                    .iter()
                    .find(|role| role.name == "Source")
                    .unwrap()
                    .tag,
            }],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        };
        let post = || PostRequest {
            proposal: proposal.clone(),
            approvals: Vec::new(),
            capability: controller.clone(),
            plan_certificate: None,
        };
        let head = book.head(&cx).unwrap();
        assert_eq!(
            book.post(&cx, post()).await.unwrap().unwrap_err().code,
            "FA-REF-086"
        );
        assert_eq!(book.head(&cx).unwrap(), head);
        let reupload = book
            .upload_document(&cx, &controller, request(bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reupload.grade, uploaded.grade);
        assert!(reupload.already_recorded);
        assert_eq!(
            book.post(&cx, post()).await.unwrap().unwrap_err().code,
            "FA-REF-086"
        );
        let same_identity = Capability::embedded(VId(102), &["approve"]).unwrap();
        assert_eq!(
            book.record_review(&cx, &same_identity, &uploaded.oid, Vec::new())
                .await
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-111"
        );
        assert_eq!(book.head(&cx).unwrap(), head);
        let reviewer = Capability::embedded(VId(103), &["approve"]).unwrap();
        book.record_review(&cx, &reviewer, &uploaded.oid, Vec::new())
            .await
            .unwrap()
            .unwrap();
        let posted = book.post(&cx, post()).await.unwrap().unwrap();
        let stored = book
            .read_entry(&cx, posted.entry_ref().vid)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(stored.proposal.evidence, proposal.evidence);
        let fold = book.fold_period(&cx, "FY2026-P03").unwrap();
        assert_eq!(fold.entries, 1);
        assert_eq!(fold.cells.len(), 2);
        let cash = fold
            .cells
            .iter()
            .find(|cell| cell.key.account == account("1000"))
            .unwrap();
        let expense = fold
            .cells
            .iter()
            .find(|cell| cell.key.account == account("6000"))
            .unwrap();
        assert_eq!(
            (cash.debits, cash.credits, cash.entry_count),
            (0, 12_345, 1)
        );
        assert_eq!(
            (expense.debits, expense.credits, expense.entry_count),
            (12_345, 0, 1)
        );
        let document = full(
            book.read_document_for(&cx, &reader(), &uploaded.oid)
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(
            document.grade, uploaded.grade,
            "review is evidence, never a metadata rewrite"
        );
        assert_eq!(document.retrieved_by, VId(102));
    });
}

#[test]
fn facade_refuses_wrong_book_expired_and_forged_uploads_without_advancing() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut first = create(&cx, vfs.clone(), Path::new("first"), 94).await;
        let mut second = create(&cx, vfs, Path::new("second"), 95).await;
        let cap = agent(201).for_books(&[first.context().book_id]).unwrap();
        let req = request(b"confined evidence".to_vec());
        let recorded = first
            .upload_document(&cx, &cap, req.clone())
            .await
            .unwrap()
            .unwrap();
        let second_head = second.head(&cx).unwrap();
        assert_eq!(
            second
                .upload_document(&cx, &cap, req.clone())
                .await
                .unwrap()
                .unwrap_err()
                .exit,
            7
        );
        assert_eq!(second.head(&cx).unwrap(), second_head);
        let head = first.head(&cx).unwrap();
        let mut forged = req.clone();
        forged.asserted_grade = Some(policy().grade_by_name("HumanUpload").unwrap().tag);
        assert_eq!(
            first
                .upload_document(&cx, &cap, forged)
                .await
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-084"
        );
        assert_eq!(
            first
                .upload_document(&cx, &cap.clone().expiring_at(head), req)
                .await
                .unwrap()
                .unwrap_err()
                .exit,
            7
        );
        let read_only = Capability::embedded(VId(202), &["read"]).unwrap();
        assert_eq!(
            first
                .upload_document(&cx, &read_only, request(Vec::new()))
                .await
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011"
        );
        assert_eq!(first.head(&cx).unwrap(), head);
        assert_eq!(first.custody_chain(&cx, &recorded.oid).unwrap().len(), 1);
    });
}

#[test]
fn scratch_upload_uses_retained_blob_store_without_publishing_to_source_journal() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut source = create(&cx, vfs, Path::new("source"), 96).await;
        let cap = agent(301);
        let original = source
            .upload_document(&cx, &cap, request(b"source evidence".to_vec()))
            .await
            .unwrap()
            .unwrap();
        let target = Database::open_memory(
            &cx.commit(),
            DatabaseKeys::new([81; 32], DatabaseSecurityNamespaceId([82; 32]), [83; 32]),
        )
        .await
        .unwrap();
        let source_head = source.head(&cx).unwrap();
        let (mut scratch, map) = source
            .replay_into(
                &cx,
                target,
                // The keys `target` was opened with: the scratch book signs
                // its own checkpoints with them, never with the source's.
                &BookKeys::from_raw([81; 32], [82; 32], [83; 32]),
                Some(source_head),
                Entropy::deterministic(97),
            )
            .await
            .unwrap()
            .unwrap();
        let before = full(
            scratch
                .read_document_for(&cx, &reader(), &original.oid)
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(before.bytes, b"source evidence");
        let checked = source.verify_replay(&cx, &scratch, &map).unwrap().unwrap();
        assert_eq!(checked.pairs_checked, map.pairs.len());
        assert!(
            checked.pairs_checked >= 2,
            "genesis and evidence were checked"
        );
        let size = usize::try_from(policy().max_document_bytes.checked_add(1).unwrap()).unwrap();
        let bytes = vec![0x5c; size];
        let added = scratch
            .upload_document(&cx, &cap, request(bytes.clone()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            full(
                scratch
                    .read_document_for(&cx, &reader(), &added.oid)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .bytes,
            bytes
        );
        assert_eq!(source.head(&cx).unwrap(), source_head);
        assert!(
            source
                .document_commitment(&cx, &added.oid)
                .unwrap()
                .is_none()
        );
        // Both journals address the same immutable blob storage, but a blob
        // alone is not an evidence record in the source journal.
        let source_added = source
            .upload_document(&cx, &cap, request(bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(!source_added.already_recorded);
        assert_eq!(source_added.oid, added.oid);
        assert_eq!(source_added.recorded_at.0, source_head.0 + 1);
        assert_eq!(source.custody_chain(&cx, &added.oid).unwrap().len(), 1);
        assert_eq!(scratch.custody_chain(&cx, &added.oid).unwrap().len(), 1);
    });
}
