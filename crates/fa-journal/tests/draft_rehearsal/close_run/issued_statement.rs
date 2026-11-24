//! Native identity, retention and freshness checks for issued-statement close tasks.
//! These framed certificate fixtures exercise the kernel contract only;
//! facade tests produce real reports and independently replay their arithmetic.

use super::*;
use fa_journal::close_run::{
    CloseTaskReview, StatementIssuanceCheckpoint, verify_close_run_checkpoints,
    verify_statement_issuance_checkpoint,
};
use fa_journal::issuance::{
    IssuanceRecord, IssuedTo, StatementIssuance, issue_statements, plan_issuance,
};
use fa_model::{Writer, domain_digest, report_certificate_vid};
use fgdb_crypto::Hasher;

const RUN: &str = "issued-statement";
const CHUNK_BYTES: usize = 12 * 1024;

struct NativeStatement {
    bytes: Vec<u8>,
    certificate: [u8; 32],
    definition_digest: [u8; 32],
    certified_at: CommitSeq,
}

fn native_definition(custom: bool, version: u32) -> Vec<u8> {
    let mut w = Writer::new();
    if custom {
        w.fixed(b"fa:custom-statement-def:v1");
    } else {
        w.fixed(b"FA-STATEMENT-DEF\0").u16(1).u16(0);
    }
    w.str("native-close-statement")
        .str("Native statement identity fixture")
        .u32(version);
    w.finish().unwrap()
}

fn native_statement(h: &Harness, version: u8, damage: &str, output_len: usize) -> NativeStatement {
    let (format, selector, output_format, custom, functional): (&[u8], u8, &str, bool, bool) =
        match version {
            4 => (
                b"fa:report-certificate:v4",
                2,
                "fa:statement:v1",
                false,
                false,
            ),
            5 => (
                b"fa:report-certificate:v5",
                3,
                "fa:functional-statement:v1",
                false,
                true,
            ),
            11 => (
                b"fa:report-certificate:v11",
                9,
                "fa:custom-statement-report:v1",
                true,
                false,
            ),
            12 => (
                b"fa:report-certificate:v12",
                10,
                "fa:functional-custom-statement:v1",
                true,
                true,
            ),
            _ => panic!("not a native statement family"),
        };
    let certified_at = h.head();
    let definition = native_definition(custom, 1);
    let definition_digest = domain_digest(
        if custom {
            b"fa:custom-statement-def:v1"
        } else {
            b"fa:statement-definition:v1"
        },
        &[&definition],
    );
    let format = if damage == "trial-balance" {
        b"fa:report-certificate:v1".as_slice()
    } else {
        format
    };
    let mut w = Writer::new();
    w.fixed(format)
        .str("fa-fold-over-prefix")
        .str("embedded-owner")
        .str(if damage == "trial-balance" {
            "fa:trial-balance:v1"
        } else {
            output_format
        })
        .fixed(&if damage == "book" {
            [99; 16]
        } else {
            h.book.book_id.0
        })
        .fixed(&if damage == "branch" {
            [98; 16]
        } else {
            Id128::TRUNK.0
        })
        .u64(if damage == "prefix" {
            certified_at.0 - 1
        } else {
            certified_at.0
        })
        .u8(selector)
        .bytes(&if damage == "definition" {
            native_definition(custom, 2)
        } else {
            definition
        });
    if custom {
        w.u128(123).u64(certified_at.0);
    }
    w.u32(1).str(if damage == "period" {
        "another-period"
    } else {
        &h.period
    });
    if damage != "truncated" {
        w.u32(0); // No comparative periods.
        if custom {
            w.u8(0); // No presentation override.
        }
        w.fixed(&[11; 32]).fixed(&[12; 32]).u64(1);
        // Full native framing with bounded opaque inputs. Their semantic
        // replay belongs to the facade, as for the parent combined-review fixture.
        let count = 7 + usize::from(functional) + 5 * usize::from(custom);
        w.u32(count as u32);
        for _ in 0..count {
            w.bytes(b"opaque native input frame");
        }
        let output = vec![b'x'; output_len];
        let mut output_hash = Hasher::new();
        output_hash.update(b"fa:report-output:v1");
        output_hash.update(&output);
        let output_digest = if damage == "output-digest" {
            [0; 32]
        } else {
            output_hash.finalize().0
        };
        w.bytes(&output).fixed(&output_digest).u8(0); // No time selection.
    }
    let mut bytes = w.finish().unwrap();
    let mut hash = Hasher::new();
    hash.update(format);
    hash.update(&bytes);
    let certificate = hash.finalize().0;
    bytes.extend_from_slice(&certificate);
    NativeStatement {
        bytes,
        certificate,
        definition_digest,
        certified_at,
    }
}

fn stage_certificate(
    h: &Harness,
    batch: &mut WriteBatch,
    vid: VId,
    digest: [u8; 32],
    bytes: Vec<u8>,
) {
    let mut props = vec![
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(digest.to_vec()).unwrap(),
        ),
        (property::FA_PAYLOAD, CanonicalScalar::bytes(bytes).unwrap()),
    ];
    props.sort_by_key(|(key, _)| key.0);
    batch.create_vertex(vid, vec![label::CERTIFICATE], props);
}

fn retain_statement(h: &mut Harness, statement: &NativeStatement) -> Vec<VId> {
    let root = report_certificate_vid(h.book.book_id, &statement.certificate);
    let mut retained = vec![root];
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    if statement.bytes.len() <= CHUNK_BYTES {
        stage_certificate(
            h,
            &mut batch,
            root,
            statement.certificate,
            statement.bytes.clone(),
        );
    } else {
        let count = statement.bytes.len().div_ceil(CHUNK_BYTES);
        let mut manifest = Writer::new();
        manifest
            .fixed(b"fa:certificate-chunks:v1")
            .u64(statement.bytes.len() as u64)
            .u32(CHUNK_BYTES as u32)
            .u32(count as u32);
        stage_certificate(
            h,
            &mut batch,
            root,
            statement.certificate,
            manifest.finish().unwrap(),
        );
        for (index, bytes) in statement.bytes.chunks(CHUNK_BYTES).enumerate() {
            let index = index as u32;
            let hash = domain_digest(
                b"fa:vid:report-certificate-fragment:v1",
                &[
                    &h.book.book_id.0,
                    &statement.certificate,
                    &index.to_le_bytes(),
                ],
            );
            let vid = VId(u128::from_le_bytes(hash[..16].try_into().unwrap()));
            let mut payload = Writer::new();
            payload
                .fixed(b"fa:certificate-fragment:v1")
                .u32(index)
                .bytes(bytes);
            stage_certificate(
                h,
                &mut batch,
                vid,
                statement.certificate,
                payload.finish().unwrap(),
            );
            retained.push(vid);
        }
    }
    h.write(batch);
    retained
}

fn issue(h: &mut Harness, statement: &NativeStatement) -> IssuanceRecord {
    let capability = Capability::embedded(OWNER, &["close"]).unwrap();
    let plan = plan_issuance(
        &h.db,
        &h.book,
        &capability,
        StatementIssuance {
            book_id: h.book.book_id,
            period: h.period.clone(),
            ordinal: 1,
            definition_digest: statement.definition_digest,
            definition_name: "native-close-statement".into(),
            definition_version: 1,
            certificate: statement.certificate,
            certified_at: statement.certified_at,
            issued_to: IssuedTo::Auditor,
            document: None,
        },
        DateDay::from_ymd(2026, 3, 31).unwrap(),
        b"issue-statement",
        description(h),
    )
    .unwrap()
    .unwrap();
    let approval = h.approve(&plan.proposal(&h.book).unwrap(), APPROVER);
    let cx = h.ctx();
    h.runtime
        .block_on(issue_statements(
            &mut h.db,
            &cx,
            &h.book,
            &capability,
            plan,
            vec![approval],
        ))
        .unwrap()
        .unwrap()
        .record
}

fn checkpoint(h: &Harness, at: Option<CommitSeq>) -> Outcome<StatementIssuanceCheckpoint> {
    verify_statement_issuance_checkpoint(&h.db, &h.ctx(), &h.book, &reader(), &h.period, 1, at)
}

fn open_run(h: &mut Harness) -> CloseRunView {
    let declaration = definition(
        h,
        RUN,
        vec![
            task(
                "statement",
                &[],
                CloseTaskAction::RequireCurrentStatementIssuance { ordinal: 1 },
            ),
            task(
                "final",
                &["statement"],
                CloseTaskAction::PeriodTransition(PeriodTransition::Close),
            ),
        ],
    );
    start(h, &declaration).unwrap()
}

fn selected_review(h: &mut Harness, opened: &CloseRunView) -> CloseTaskReview {
    retain_combined_review(h, combined_review_bytes(opened, 71)).0
}

fn statement_step(
    h: &mut Harness,
    selected: Option<&CloseTaskReview>,
) -> Outcome<CloseTaskRecorded> {
    let mut req = request(h, closer());
    req.review = selected.map(|review| review.at_frontier(h.head()));
    let cx = h.ctx();
    h.runtime.block_on(execute_close_task(
        &mut h.db,
        &cx,
        &h.book,
        RUN,
        "statement",
        req,
    ))
}

fn assert_blocked<T: std::fmt::Debug>(result: Outcome<T>) {
    match result {
        Ok(Err(refusal)) => assert_eq!(refusal.code, code::PLAN_INVALIDATED, "{refusal:?}"),
        Err(KernelError::Corrupt(_)) => {}
        other => panic!("expected a statement identity/freshness refusal, got {other:?}"),
    }
}

#[test]
fn native_statement_families_bind_real_issuances_and_metadata_preserves_the_source() {
    for version in [4, 5, 11, 12] {
        let mut h = Harness::new(None);
        let statement = native_statement(&h, version, "", if version == 12 { 20_000 } else { 32 });
        let retained = retain_statement(&mut h, &statement);
        assert_eq!(retained.len() > 1, version == 12);
        let record = issue(&mut h, &statement);
        let head = h.head();
        let rows = h.db.vertices().unwrap();
        let verified = checkpoint(&h, None).unwrap().unwrap();
        assert_eq!(verified.issuance(), &record);
        assert_eq!(verified.known_at(), head);
        assert_blocked(checkpoint(&h, Some(CommitSeq(record.recorded_at.0 - 1))));
        assert_eq!(h.head(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);

        for denied in [
            Capability::embedded(REVIEWER, &["close"]).unwrap(),
            reader().for_accounts(&["1000"]).unwrap(),
        ] {
            let refuse = |ordinal| {
                verify_statement_issuance_checkpoint(
                    &h.db,
                    &h.ctx(),
                    &h.book,
                    &denied,
                    &h.period,
                    ordinal,
                    None,
                )
                .unwrap()
                .unwrap_err()
            };
            assert_eq!(
                refuse(1),
                refuse(999),
                "authority precedes issuance observation"
            );
        }

        let unposted = h.proposal(50, b"unposted-review", EntryClass::ORIGINAL, OWNER);
        h.approve(&unposted, REVIEWER);
        h.maintenance(81);
        open_run(&mut h);
        let after_metadata = checkpoint(&h, None).unwrap().unwrap();
        assert!(after_metadata.known_at() > verified.known_at());
        assert_eq!(after_metadata.issuance(), verified.issuance());
        assert_eq!(after_metadata.source_digest(), verified.source_digest());
    }
}

#[test]
fn native_statement_checkpoint_rejects_mismatched_and_truncated_certificate_bindings() {
    for damage in [
        "period",
        "definition",
        "prefix",
        "book",
        "branch",
        "trial-balance",
        "output-digest",
        "truncated",
    ] {
        let mut h = Harness::new(None);
        let statement = native_statement(&h, 4, damage, 32);
        retain_statement(&mut h, &statement);
        issue(&mut h, &statement);
        let opened = open_run(&mut h);
        let review = selected_review(&mut h, &opened);
        let head = h.head();
        let rows = h.db.vertices().unwrap();
        assert_blocked(checkpoint(&h, None));
        assert_blocked(statement_step(&mut h, Some(&review)));
        assert_eq!(h.head(), head, "{damage}");
        assert_eq!(h.db.vertices().unwrap(), rows, "{damage}");
        assert!(
            status(&h, RUN)
                .tasks
                .iter()
                .find(|task| task.id == "statement")
                .unwrap()
                .completion
                .is_none()
        );
    }
}

#[test]
fn statement_storage_corruption_blocks_completion_but_preserves_historical_verification() {
    for damage in [
        "missing-root",
        "missing-fragment",
        "fragment-bytes",
        "issuance-bytes",
        "missing-claim",
        "claim-bytes",
    ] {
        let mut h = Harness::new(None);
        let statement = native_statement(&h, 4, "", 20_000);
        let retained = retain_statement(&mut h, &statement);
        let record = issue(&mut h, &statement);
        let opened = open_run(&mut h);
        let review = selected_review(&mut h, &opened);
        let verified = checkpoint(&h, None).unwrap().unwrap();
        let basis = h.head();
        let vid = match damage {
            "missing-root" => retained[0],
            "issuance-bytes" => record.vid,
            "missing-claim" | "claim-bytes" => {
                let claims: Vec<_> =
                    h.db.vertices()
                        .unwrap()
                        .into_iter()
                        .filter(|row| {
                            row.labels.as_slice() == [label::INTENT_OUTCOME]
                                && row.created_at == record.recorded_at
                        })
                        .map(|row| row.vid)
                        .collect();
                assert_eq!(claims.len(), 1, "the issuance has one atomic key claim");
                claims[0]
            }
            _ => retained[1],
        };
        let original = prop(&h.db.vertex(vid).unwrap().unwrap(), property::FA_PAYLOAD)
            .unwrap()
            .clone();
        let deleting = damage.starts_with("missing");
        let mut change = WriteBatch::new(relation::IN_BOOK);
        if deleting {
            change.delete_vertex(vid);
        } else {
            let CanonicalScalar::Bytes(bytes) = &original else {
                panic!("native byte payload")
            };
            let mut bytes = bytes.as_slice().to_vec();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            change.set_vertex_property(
                vid,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(bytes).unwrap()),
            );
        }
        h.write(change);
        for restored in [false, true] {
            if restored {
                if deleting {
                    break;
                }
                let mut restore = WriteBatch::new(relation::IN_BOOK);
                restore.set_vertex_property(vid, property::FA_PAYLOAD, Some(original.clone()));
                h.write(restore);
            }
            let head = h.head();
            let rows = h.db.vertices().unwrap();
            assert_blocked(checkpoint(&h, None));
            assert_blocked(statement_step(&mut h, Some(&review)));
            assert_eq!(checkpoint(&h, Some(basis)).unwrap().unwrap(), verified);
            assert_eq!(h.head(), head, "{damage}, restored={restored}");
            assert_eq!(
                h.db.vertices().unwrap(),
                rows,
                "{damage}, restored={restored}"
            );
        }
    }
}

#[test]
fn statement_close_requires_review_and_retains_original_receipts_after_retention_changes() {
    let mut h = Harness::new(None);
    let statement = native_statement(&h, 4, "", 20_000);
    let retained = retain_statement(&mut h, &statement);
    let issuance = issue(&mut h, &statement);
    let opened = open_run(&mut h);
    let before = h.head();
    let rows = h.db.vertices().unwrap();
    assert_blocked(statement_step(&mut h, None));
    assert_eq!(h.head(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
    let review = selected_review(&mut h, &opened);
    let before = h.head();
    let completed = statement_step(&mut h, Some(&review)).unwrap().unwrap();
    assert_eq!(h.head().0, before.0 + 1);
    assert_eq!(completed.receipt.effect, issuance.control_entry);
    assert_eq!(completed.receipt.recorded_at, h.head());
    assert!(!completed.run.complete);
    assert_eq!(completed.run.reviews.len(), 1);
    verify_close_run_checkpoints(&h.db, &h.ctx(), &h.book, RUN, &reader(), h.head())
        .unwrap()
        .unwrap();
    let reviewed = plan(&h, RUN, "final", b"close-after-issued-statement").unwrap();
    let mut req = request(&h, closer());
    req.transition_plan = Some(reviewed);
    req.review = Some(review.at_frontier(h.head()));
    let final_task = step(&mut h, RUN, "final", req).unwrap();
    assert!(final_task.run.complete);

    // Later retention loss invalidates a new check, never an already recorded
    // completion whose evidence is still authentic at its original prefix.
    let mut remove = WriteBatch::new(relation::IN_BOOK);
    remove.delete_vertex(retained[1]);
    h.write(remove);
    let head = h.head();
    let rows = h.db.vertices().unwrap();
    assert_blocked(checkpoint(&h, None));
    assert_eq!(
        status(&h, RUN)
            .tasks
            .iter()
            .find(|task| task.id == "statement")
            .unwrap()
            .completion
            .as_ref(),
        Some(&completed.receipt)
    );
    let retry = statement_step(&mut h, None).unwrap().unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, completed.receipt);
    verify_close_run_checkpoints(&h.db, &h.ctx(), &h.book, RUN, &reader(), head)
        .unwrap()
        .unwrap();
    assert_eq!(h.head(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn zero_net_post_invalidates_statement_source_and_an_already_prepared_terminal_plan() {
    let mut h = Harness::new(None);
    let statement = native_statement(&h, 4, "", 32);
    retain_statement(&mut h, &statement);
    issue(&mut h, &statement);
    let opened = open_run(&mut h);
    let review = selected_review(&mut h, &opened);
    let completed = statement_step(&mut h, Some(&review)).unwrap().unwrap();
    let prepared = plan(&h, RUN, "final", b"close-before-zero-net-post").unwrap();
    let basis = h.head();
    let verified = checkpoint(&h, Some(basis)).unwrap().unwrap();
    let balance = cash_balance(&h.db, h.cash);
    let mut neutral = h.proposal(
        100,
        b"new-zero-net-contribution",
        EntryClass::ORIGINAL,
        OWNER,
    );
    neutral.legs = vec![
        LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 100)),
    ];
    neutral.unit_totals = EntryPayload::fold_unit_totals(&neutral.legs).unwrap();
    h.post(neutral);
    assert_eq!(cash_balance(&h.db, h.cash), balance);

    let head = h.head();
    let rows = h.db.vertices().unwrap();
    assert_blocked(checkpoint(&h, None));
    assert_eq!(checkpoint(&h, Some(basis)).unwrap().unwrap(), verified);
    assert_blocked(verify_close_run_checkpoints(
        &h.db,
        &h.ctx(),
        &h.book,
        RUN,
        &reader(),
        head,
    ));
    assert!(plan(&h, RUN, "final", b"new-plan-after-zero-net-post").is_err());
    let mut req = request(&h, closer());
    req.transition_plan = Some(prepared);
    req.review = Some(review.at_frontier(head));
    assert_eq!(
        step(&mut h, RUN, "final", req).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    let view = status(&h, RUN);
    assert!(!view.complete);
    assert_eq!(
        view.tasks
            .iter()
            .find(|task| task.id == "statement")
            .unwrap()
            .completion
            .as_ref(),
        Some(&completed.receipt)
    );
    assert!(
        view.tasks
            .iter()
            .find(|task| task.id == "final")
            .unwrap()
            .completion
            .is_none()
    );
    let retry = statement_step(&mut h, None).unwrap().unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, completed.receipt);
    assert_eq!(h.head(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}
