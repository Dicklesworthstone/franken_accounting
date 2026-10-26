//! Full-prefix regressions: every malformed proposal and record is resealed,
//! and bundle() rebuilds the checkpoint root and source certificate. Failures
//! therefore exercise class semantics rather than stale hashes or signatures.
use super::*;
use crate::envelope::{Leg, UNDATED_CLASSES, entry_record_digest};

fn reclassified(mut original: Record, class: u16) -> Record {
    // The native wire header puts the u16 class after version/book/branch.
    original.bytes[36..38].copy_from_slice(&class.to_le_bytes());
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&original.bytes[..original.len]]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    assert_eq!(original.bytes.len(), original.len + 64);
    original.bytes[original.len..original.len + 32].copy_from_slice(&proposal);
    original.bytes[original.len + 32..].copy_from_slice(&digest);
    original.envelope.class = class;
    original.envelope.record_digest = digest;
    let day = i32::from_le_bytes(original.bytes[38..42].try_into().unwrap());
    original.envelope.effective_day = (!UNDATED_CLASSES.contains(&class)).then_some(day);
    // Check both hashes independently; do not call the guarded constructor to
    // manufacture the hostile envelope the recipient must reject.
    assert_eq!(
        entry_record_digest(&original.bytes, original.len).unwrap(),
        digest,
    );
    original
}

#[test]
fn resealed_unknown_classes_are_refused_even_when_reports_exclude_the_record() {
    for class in [0, 31, 256, 999, u16::MAX] {
        for amount in [0, 100] {
            for (known_at, day) in [(3, 10), (3, 40), (2, 10)] {
                let mut records = schema();
                records.push(reclassified(
                    record(1, 3, day, b"unknown-class", amount, None, None, None),
                    class,
                ));
                let expected = if known_at == 3 && day <= 20 && amount != 0 {
                    rows(amount, 0)
                } else {
                    Vec::new()
                };
                let (bytes, anchor) = bundle(&records, known_at, Selection::AsOf(20), &expected);
                let error = verify_fixture(&bytes, anchor).unwrap_err();
                assert_eq!(
                    error.predicate, "record_derivation",
                    "class {class}, amount {amount}, known_at {known_at}, day {day}: {error}",
                );
                assert!(error.detail.contains("entry.class"), "{error}");
            }
        }
    }
}

#[test]
fn resealed_monetary_controls_are_refused_before_date_or_prefix_selection() {
    for class in 16..=30 {
        for (known_at, day) in [(3, 10), (3, 40), (2, 10)] {
            let mut records = schema();
            records.push(reclassified(
                record(1, 3, day, b"monetary-control", 100, None, None, None),
                class,
            ));
            let expected = if known_at == 3 && day <= 20 {
                rows(100, 0)
            } else {
                Vec::new()
            };
            let (bytes, anchor) = bundle(&records, known_at, Selection::AsOf(20), &expected);
            let error = verify_fixture(&bytes, anchor).unwrap_err();
            assert_eq!(
                error.predicate, "record_derivation",
                "class {class}, known_at {known_at}, day {day}: {error}",
            );
            assert!(error.detail.contains("entry.legs"), "{error}");
        }
    }
}

#[test]
fn registered_postings_pending_and_legless_controls_keep_their_fold_semantics() {
    // Chart and period declarations are legless SchemaControl records.
    let mut records = schema();
    records.push(record(1, 3, 10, b"posted", 100, None, None, None));
    let pending = record(2, 4, 10, b"pending", 25, None, None, None);
    let info = metadata::entry_info(&pending.bytes[..pending.len], &pending.envelope).unwrap();
    let target = (info.identity, pending.envelope.record_digest);
    records.push(pending);
    records.push(record(8, 5, 20, b"closing", 10, None, None, None));
    records.push(record(3, 6, 40, b"void", 0, None, Some(target), None));
    for (known_at, expected) in [(2, Vec::new()), (5, rows(110, 25)), (6, rows(110, 0))] {
        let (bytes, anchor) = bundle(&records, known_at, Selection::AsOf(20), &expected);
        assert_eq!(verify_fixture(&bytes, anchor).unwrap().rows, expected);
    }
}

#[test]
fn registered_migration_posts_and_legless_lifecycle_controls_remain_supported() {
    let (run, body, digest) = explain::migration_body(0, false);
    let mut records = schema();
    let legs = [
        Leg {
            account: account_id("1000"),
            debit: true,
            unit: 1,
            mantissa: 35,
        },
        Leg {
            account: account_id("3000"),
            debit: false,
            unit: 1,
            mantissa: 35,
        },
    ];
    records.extend([
        explain::migration_record(run, digest, Some(0), 3, 10, &[]),
        explain::migration_record(run, digest, None, 4, 9, &legs),
        explain::migration_record(run, digest, Some(1), 6, 10, &[]),
    ]);
    for (known_at, expected) in [(4, Vec::new()), (6, rows(35, 0))] {
        let (bytes, anchor) = bundle(&records, known_at, Selection::AsOf(20), &expected);
        // bundle() ends with the migration-body list count. Supply the real,
        // committed Open body at its authenticated checkpoint leaf index.
        assert_eq!(&bytes[bytes.len() - 4..], &0u32.to_le_bytes());
        let mut complete = Writer::default();
        complete
            .fixed(&bytes[..bytes.len() - 4])
            .count(1)
            .u64(2)
            .bytes(&body);
        assert_eq!(
            verify_fixture(&complete.buf, anchor).unwrap().rows,
            expected
        );
    }
}
