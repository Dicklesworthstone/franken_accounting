use super::*;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use asupersync::io::{AsyncWriteExt, ReadBuf};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{BookSpec, DocumentRead};
use fa_model::Id128;
use fa_money::UnitRegistry;
use fa_policy::{Op, Profile};
use fa_time::FiscalCalendar;
use fgdb::MemVfs;
use fgdb_types::VId;

use crate::{BookKeys, Entropy};

fn runtime() -> (Runtime, Cx) {
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    (runtime, root)
}

async fn create(cx: &PurposeContexts, seed: u8) -> (AsyncBook<MemVfs>, MemVfs) {
    let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
    let book = AsyncBook::create_with_vfs(
        cx,
        vfs.clone(),
        Path::new("book"),
        BookKeys::for_development(seed),
        BookSpec {
            book_id: Id128([seed; 16]),
            name: "Source intake".into(),
            base_unit: UnitRegistry::with_defaults().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("source", 1, 0).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(seed)),
    )
    .await
    .unwrap();
    (book, vfs)
}

fn request(max_bytes: u64) -> SourceUploadRequest {
    SourceUploadRequest {
        kind: 1,
        mime: "application/octet-stream".into(),
        asserted_grade: None,
        max_bytes,
    }
}

fn agent() -> Capability {
    Capability::new(VId(301), Profile::Agent, &[Op::Post], VId(1)).unwrap()
}

#[test]
fn eof_boundaries_never_return_a_truncated_success_or_overread() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let query = cx.query();
        for limit in 0..=32_u64 {
            for length in 0..=48_usize {
                let bytes: Vec<u8> = (0..length)
                    .map(|index| u8::try_from(index).unwrap())
                    .collect();
                let mut reader = bytes.as_slice();
                let result = query
                    .with_restriction_async(read_bounded(
                        &query,
                        &mut reader,
                        limit,
                        Path::new("boundary"),
                    ))
                    .await
                    .unwrap();
                if u64::try_from(length).unwrap() <= limit {
                    assert_eq!(result.unwrap(), bytes);
                    assert!(reader.is_empty());
                } else {
                    assert_eq!(result.unwrap_err().code, code::DOCUMENT_INTAKE);
                    assert_eq!(length - reader.len(), usize::try_from(limit + 1).unwrap());
                }
            }
        }
    });
}

struct Choppy {
    bytes: Vec<u8>,
    offset: usize,
    polls: usize,
    interrupt: bool,
    infinite: bool,
    fail_after: Option<usize>,
    pending_after: Option<usize>,
}

impl Choppy {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            offset: 0,
            polls: 0,
            interrupt: false,
            infinite: false,
            fail_after: None,
            pending_after: None,
        }
    }
}

impl AsyncRead for Choppy {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls += 1;
        if this.pending_after.is_some_and(|at| this.offset >= at) {
            return Poll::Pending;
        }
        if this.fail_after.is_some_and(|at| this.offset >= at) {
            return Poll::Ready(Err(io::Error::other("injected source failure")));
        }
        if this.interrupt && this.polls % 2 == 1 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::Interrupted)));
        }
        let count = buffer.remaining().min(3);
        if this.infinite {
            buffer.put_slice(&[0x91; 3][..count]);
            this.offset += count;
        } else {
            let count = count.min(this.bytes.len() - this.offset);
            buffer.put_slice(&this.bytes[this.offset..this.offset + count]);
            this.offset += count;
        }
        Poll::Ready(Ok(()))
    }
}

#[test]
fn interrupted_short_reads_preserve_binary_bytes() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let query = cx.query();
        let bytes = [0x00, 0xff, 0x80, 0x7f, b'\n', b'\r', 0x00];
        let mut reader = Choppy::new(&bytes);
        reader.interrupt = true;
        let result = query
            .with_restriction_async(read_bounded(&query, &mut reader, 7, Path::new("binary")))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, bytes);
        assert!(reader.polls > 3);
    });
}

#[test]
fn an_infinite_source_stops_at_the_budget_plus_one_byte() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let query = cx.query();
        let mut reader = Choppy::new(&[]);
        reader.infinite = true;
        assert!(
            query
                .with_restriction_async(read_bounded(
                    &query,
                    &mut reader,
                    17,
                    Path::new("infinite"),
                ))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(reader.offset, 18);
    });
}

#[test]
fn failed_input_never_publishes_its_successful_prefix() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _) = create(&cx, 221).await;
        let before = book.head(&cx).unwrap();
        let mut reader = Choppy::new(b"source fails after a prefix");
        reader.fail_after = Some(3);
        let failed = book
            .upload_document_from_reader(&cx, &agent(), &mut reader, request(64))
            .await;
        assert!(matches!(failed, Err(BookError::Io(_, _))));
        assert_eq!(reader.offset, 3);
        assert_eq!(book.head(&cx).unwrap(), before);
    });
}

#[test]
fn refused_authority_or_metadata_never_polls_the_reader() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _) = create(&cx, 222).await;
        let before = book.head(&cx).unwrap();
        let read_only = Capability::embedded(VId(302), &["read"]).unwrap();
        let mut reader = Choppy::new(b"must stay unread");
        assert!(
            book.upload_document_from_reader(&cx, &read_only, &mut reader, request(64))
                .await
                .unwrap()
                .is_err()
        );
        let mut wrong_grade = request(64);
        wrong_grade.asserted_grade = Some(
            EvidencePolicy::embedded()
                .unwrap()
                .grade_by_name("HumanUpload")
                .unwrap()
                .tag,
        );
        for req in [wrong_grade, request(0), request(u64::MAX)] {
            assert!(
                book.upload_document_from_reader(&cx, &agent(), &mut reader, req)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        assert_eq!(reader.polls, 0);
        assert_eq!(book.head(&cx).unwrap(), before);
    });
}

#[test]
fn vfs_admission_precedes_opening_a_nonexistent_source() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _) = create(&cx, 223).await;
        let source = cx.commit().with_restriction(MemVfs::new).unwrap();
        let cap = Capability::embedded(VId(303), &["read"]).unwrap();
        let refused = book
            .upload_document_from_vfs(&cx, &cap, &source, Path::new("not-present"), request(64))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, "FA-REF-011");
        assert!(matches!(
            book.upload_document_from_vfs(
                &cx,
                &agent(),
                &source,
                Path::new("not-present"),
                request(64),
            )
            .await,
            Err(BookError::Io(_, _))
        ));
    });
}

#[test]
fn source_upload_preserves_original_provenance_on_retry() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _) = create(&cx, 224).await;
        let input = [0, 0xff, 0xfe, 0x01];
        let first = book
            .upload_document_from_reader(&cx, &agent(), &mut input.as_slice(), request(4))
            .await
            .unwrap()
            .unwrap();
        let head = book.head(&cx).unwrap();
        let human = Capability::embedded(VId(304), &["post"]).unwrap();
        let retry = book
            .upload_document_from_reader(&cx, &human, &mut input.as_slice(), request(4))
            .await
            .unwrap()
            .unwrap();
        assert!(retry.already_recorded);
        assert_eq!(
            (retry.oid, retry.grade, retry.recorded_at),
            (first.oid, first.grade, first.recorded_at)
        );
        assert_eq!(book.head(&cx).unwrap(), head);
        assert_eq!(book.custody_chain(&cx, &first.oid).unwrap().len(), 1);
    });
}

#[test]
fn dropping_a_pending_source_future_publishes_nothing() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _) = create(&cx, 225).await;
        let before = book.head(&cx).unwrap();
        let cap = agent();
        let mut reader = Choppy::new(b"a partial stream");
        reader.pending_after = Some(3);
        let mut future =
            Box::pin(book.upload_document_from_reader(&cx, &cap, &mut reader, request(64)));
        let waker = Waker::noop();
        assert!(matches!(
            future.as_mut().poll(&mut Context::from_waker(waker)),
            Poll::Pending
        ));
        drop(future);
        assert_eq!(reader.offset, 3);
        assert_eq!(book.head(&cx).unwrap(), before);
    });
}

#[test]
fn vfs_source_routes_large_evidence_to_the_book_store_and_reopens() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, destination) = create(&cx, 226).await;
        let source = cx.commit().with_restriction(MemVfs::new).unwrap();
        let size = EvidencePolicy::embedded().unwrap().max_document_bytes + 1;
        let mut bytes = vec![0x96; usize::try_from(size).unwrap()];
        *bytes.last_mut().unwrap() = 0xff;
        cx.commit()
            .with_restriction_async(async {
                let mut file = source
                    .open(
                        Path::new("invoice.bin"),
                        &OpenOptions::new().write(true).create_new(true),
                    )
                    .await
                    .unwrap();
                file.write_all(&bytes).await.unwrap();
            })
            .await;
        let added = book
            .upload_document_from_vfs(
                &cx,
                &agent(),
                &source,
                Path::new("invoice.bin"),
                request(size),
            )
            .await
            .unwrap()
            .unwrap();
        drop(book);
        let mut book = AsyncBook::open_with_vfs(
            &cx,
            destination,
            Path::new("book"),
            BookKeys::for_development(226),
            Entropy::deterministic(227),
        )
        .await
        .unwrap();
        let read = Capability::embedded(VId(305), &["read", "privileged"]).unwrap();
        let DocumentRead::Full(document) = book
            .read_document_for(&cx, &read, &added.oid)
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("expected full evidence")
        };
        assert_eq!(document.bytes, bytes);
        assert_eq!(document.retrieved_by, agent().holder());
        assert_eq!(document.doc_commit(), added.doc_commit);
    });
}
