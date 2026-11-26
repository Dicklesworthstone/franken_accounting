use super::*;
use crate::external_subledger::{ExternalSubledgerBatch, ExternalSubledgerDetail};
use fa_money::Amount;

fn child(number: u8) -> ExternalSubledgerReconciliation {
    let rows = (1u8..=100)
        .map(|row| {
            let mut source_digest = [0; 32];
            source_digest[0] = row;
            source_digest[1] = number;
            ExternalSubledgerDetail {
                source_digest,
                account: if row <= 50 { VId(10) } else { VId(20) },
                side: if row <= 50 { Side::Debit } else { Side::Credit },
                amount: Amount::new(UnitId(1), 100),
                dimensions: vec![],
            }
        })
        .collect();
    let batch = ExternalSubledgerBatch {
        book_id: Id128([1; 16]),
        feed: "daily-sales".into(),
        batch_key: format!("child-{number:02}"),
        effective_date: DateDay(100),
        rows,
    };
    assert!(batch.canonical_bytes().unwrap().len() <= super::super::MAX_EXTERNAL_DETAIL_BYTES);
    ExternalSubledgerReconciliation {
        entry: EntryRef {
            vid: VId(u128::from(number) + 100),
            entry_digest: [number + 1; 32],
        },
        recorded_at: CommitSeq(u64::from(number) + 100),
        feed: batch.feed.clone(),
        batch_key: batch.batch_key.clone(),
        effective_date: batch.effective_date,
        evidence: batch.evidence().unwrap(),
        review: Review {
            attestation: VId(u128::from(number) + 200),
            reviewer: VId(300),
        },
        detail_rows: batch.rows.len(),
        summary_legs: batch.summary_legs().unwrap(),
        reconciled: true,
    }
}

fn population() -> (ExternalFeedManifest, Vec<ExternalSubledgerReconciliation>) {
    let children: Vec<_> = (0..10).map(child).collect();
    let manifest = ExternalFeedManifest {
        book_id: Id128([1; 16]),
        feed: "daily-sales".into(),
        extract_id: "extract-100".into(),
        effective_from: DateDay(100),
        effective_through: DateDay(100),
        children: children
            .iter()
            .map(|child| ExternalFeedManifestChild {
                batch_key: child.batch_key.clone(),
                detail_commit: child.evidence.doc_commit,
            })
            .collect(),
        detail_rows: 1000,
        totals: vec![
            ExternalFeedManifestTotal {
                account: VId(10),
                unit: UnitId(1),
                dimensions: vec![],
                debits: 50_000,
                credits: 0,
            },
            ExternalFeedManifestTotal {
                account: VId(20),
                unit: UnitId(1),
                dimensions: vec![],
                debits: 0,
                credits: 50_000,
            },
        ],
    };
    (manifest, children)
}

#[test]
fn manifest_proves_one_thousand_rows_without_relaxing_child_byte_bounds() {
    // Even dimensionless detail needs >=65 header bytes and 73 bytes/row.
    // Nine 8 KiB children can hold at most 999 rows; use ten complete children.
    let (manifest, mut children) = population();
    let bytes = manifest.canonical_bytes().unwrap();
    assert_eq!(ExternalFeedManifest::decode(&bytes).unwrap(), manifest);
    let report = manifest.verify(&children).unwrap();
    assert_eq!(report.status, ExternalFeedManifestStatus::Complete);
    assert_eq!(report.actual_detail_rows, 1000);
    assert_eq!(report.totals[0].actual_debits, 50_000);
    assert_eq!(report.totals[1].actual_credits, 50_000);
    assert!(report.missing.is_empty());
    assert!(report.unexpected.is_empty());
    children.reverse();
    assert_eq!(
        manifest
            .verify(&children)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        report.canonical_bytes().unwrap()
    );
}

#[test]
fn manifest_names_an_omitted_balanced_child_and_an_unexpected_child() {
    let (manifest, mut children) = population();
    let missing = children.remove(7);
    let report = manifest.verify(&children).unwrap();
    assert_eq!(report.status, ExternalFeedManifestStatus::Incomplete);
    assert_eq!(report.missing, vec!["child-07"]);
    assert_eq!(report.actual_detail_rows, 900);
    assert_eq!(
        report.totals[0].actual_debits,
        report.totals[1].actual_credits
    );
    children.push(missing);
    children.push(child(10));
    let report = manifest.verify(&children).unwrap();
    assert_eq!(report.status, ExternalFeedManifestStatus::Incomplete);
    assert_eq!(report.unexpected, vec!["child-10"]);
    assert!(report.missing.is_empty());
    assert_eq!(report.actual_detail_rows, 1100);
}

#[test]
fn manifest_distinguishes_changed_identity_one_cent_and_row_count_mismatches() {
    let (manifest, children) = population();
    let mut changed = manifest.clone();
    changed.children[3].detail_commit = [99; 32];
    let report = changed.verify(&children).unwrap();
    assert_eq!(report.status, ExternalFeedManifestStatus::Mismatch);
    assert_eq!(report.digest_mismatches[0].batch_key, "child-03");
    assert_eq!(report.digest_mismatches[0].expected_commit, [99; 32]);
    assert_eq!(
        report.digest_mismatches[0].actual_commit,
        children[3].evidence.doc_commit
    );
    assert!(
        report
            .totals
            .iter()
            .all(ExternalFeedManifestTotalComparison::matches)
    );
    changed = manifest.clone();
    changed.totals[0].debits += 1;
    let report = changed.verify(&children).unwrap();
    assert_eq!(report.status, ExternalFeedManifestStatus::Mismatch);
    assert_eq!(report.totals[0].account, VId(10));
    assert_eq!(report.totals[0].expected_debits, 50_001);
    assert_eq!(report.totals[0].actual_debits, 50_000);
    changed = manifest;
    changed.detail_rows -= 1;
    assert_eq!(
        changed.verify(&children).unwrap().status,
        ExternalFeedManifestStatus::Mismatch
    );
}

#[test]
fn manifest_does_not_net_gross_sides_or_erase_dimension_cells() {
    let (mut manifest, mut children) = population();
    for child in &mut children {
        child.summary_legs[1].account_ref = VId(10);
    }
    manifest.totals = vec![ExternalFeedManifestTotal {
        account: VId(10),
        unit: UnitId(1),
        dimensions: vec![],
        debits: 50_000,
        credits: 50_000,
    }];
    assert_eq!(
        manifest.verify(&children).unwrap().status,
        ExternalFeedManifestStatus::Complete
    );
    manifest.totals[0].debits -= 1;
    manifest.totals[0].credits -= 1;
    assert_eq!(
        manifest.verify(&children).unwrap().status,
        ExternalFeedManifestStatus::Mismatch
    );
    manifest.totals[0].debits += 1;
    manifest.totals[0].credits += 1;
    children[0].summary_legs[0].dimension_set = vec![(1, VId(9))];
    let report = manifest.verify(&children).unwrap();
    assert_eq!(report.status, ExternalFeedManifestStatus::Mismatch);
    assert_eq!(report.totals.len(), 2);
    assert_eq!(report.totals[1].dimensions, vec![(1, VId(9))]);
    assert_eq!(report.totals[1].actual_debits, 5000);
    assert_eq!(report.totals[1].expected_debits, 0);
}

#[test]
fn manifest_refuses_duplicate_or_unverified_or_wrong_scope_children_and_overflow() {
    let (manifest, children) = population();
    let mut changed = children.clone();
    changed.push(children[0].clone());
    assert!(
        manifest
            .verify(&changed)
            .unwrap_err()
            .message
            .contains("same manifest child")
    );
    changed = children.clone();
    changed[0].reconciled = false;
    assert!(manifest.verify(&changed).is_err());
    changed = children.clone();
    changed[0].effective_date = DateDay(99);
    assert!(manifest.verify(&changed).is_err());
    changed = children.clone();
    changed[0].feed = "another-feed".into();
    assert!(manifest.verify(&changed).is_err());
    changed = children.clone();
    changed[0].evidence.document_oid = Oid([2; 32]);
    assert!(manifest.verify(&changed).is_err());
    changed = children;
    changed[0].summary_legs[0].amount.mantissa = i128::MAX;
    assert!(
        manifest
            .verify(&changed)
            .unwrap_err()
            .message
            .contains("overflows")
    );
}

#[test]
fn manifest_codec_refuses_noncanonical_and_unbounded_source_declarations() {
    let (manifest, _) = population();
    let mut changed = manifest.clone();
    changed.children.swap(0, 1);
    assert!(changed.canonical_bytes().is_err());
    changed = manifest.clone();
    changed.children[1] = changed.children[0].clone();
    assert!(changed.canonical_bytes().is_err());
    changed = manifest.clone();
    changed.totals[1] = changed.totals[0].clone();
    assert!(changed.canonical_bytes().is_err());
    changed = manifest.clone();
    changed.totals[0].dimensions = vec![(2, VId(1)), (1, VId(2))];
    assert!(changed.canonical_bytes().is_err());
    changed = manifest.clone();
    changed.totals[0].debits = -1;
    assert!(changed.canonical_bytes().is_err());
    changed = manifest.clone();
    changed.effective_from = DateDay(101);
    assert!(changed.canonical_bytes().is_err());
    changed = manifest.clone();
    changed.detail_rows = u64::MAX;
    assert!(changed.canonical_bytes().is_err());
    let mut bytes = manifest.canonical_bytes().unwrap();
    bytes.push(0);
    assert!(ExternalFeedManifest::decode(&bytes).is_err());
    let count_offset = EXTERNAL_FEED_MANIFEST_FORMAT.len()
        + 16
        + 4
        + manifest.feed.len()
        + 4
        + manifest.extract_id.len()
        + 4
        + 4
        + 8;
    bytes = manifest.canonical_bytes().unwrap();
    bytes[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(ExternalFeedManifest::decode(&bytes).is_err());
    assert!(ExternalFeedManifest::decode(&vec![0; MAX_EXTERNAL_MANIFEST_BYTES + 1]).is_err());
    changed = manifest;
    changed.totals = (0..MAX_EXTERNAL_MANIFEST_TOTALS)
        .map(|cell| ExternalFeedManifestTotal {
            account: VId(cell as u128 + 1),
            unit: UnitId(1),
            dimensions: (0..MAX_DIMENSIONS_PER_LEG)
                .map(|kind| (kind as u32, VId(1)))
                .collect(),
            debits: 1,
            credits: 0,
        })
        .collect();
    assert!(
        changed
            .canonical_bytes()
            .unwrap_err()
            .message
            .contains("byte bound")
    );
}

#[test]
fn manifest_empty_window_and_output_bind_every_child_citation_and_verdict() {
    let (mut manifest, children) = population();
    let report = manifest.verify(&children).unwrap();
    let original = report.canonical_bytes().unwrap();
    let mut changed = report.clone();
    changed.children[0].entry.entry_digest = [88; 32];
    assert_ne!(changed.canonical_bytes().unwrap(), original);
    changed = report.clone();
    changed.children[0].recorded_at.0 += 1;
    assert_ne!(changed.canonical_bytes().unwrap(), original);
    changed = report.clone();
    changed.children[0].review.reviewer = VId(1234);
    assert_ne!(changed.canonical_bytes().unwrap(), original);
    changed = report;
    changed.status = ExternalFeedManifestStatus::Incomplete;
    assert_ne!(changed.canonical_bytes().unwrap(), original);
    manifest.children.clear();
    manifest.totals.clear();
    manifest.detail_rows = 0;
    assert_eq!(
        manifest.verify(&[]).unwrap().status,
        ExternalFeedManifestStatus::Complete
    );
    assert_eq!(
        manifest.verify(&children).unwrap().status,
        ExternalFeedManifestStatus::Incomplete
    );
}
