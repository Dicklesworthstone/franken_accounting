//! Independently framed adjusted-bank claims. The referenced cash entries are
//! deliberately absent: these tests establish inclusion decoding and equation
//! checks, never native cash folding or outstanding-item eligibility.

use super::*;

fn adjusted(linked: bool) -> Fixture {
    let mut fixture = Fixture::new(linked);
    fixture.claim_tag = 11;
    fixture.cash = 62_500;
    fixture.outstanding = vec![(200, [0x61; 32], 1, 4_000), (201, [0x62; 32], 0, -1_500)];
    fixture
}

#[test]
fn legacy_exact_close_keeps_its_old_bytes_and_no_outstanding_count() {
    let legacy = Fixture::new(false);
    let (record, split) = legacy.record();
    // Fixed independent v1 fixture: matches end at byte 504, immediately
    // followed by the subject count. No empty outstanding list is inserted.
    assert_eq!(record[18], 3);
    assert_eq!(split, 625);
    assert_eq!(record.len(), 691);
    assert_eq!(&record[504..508], &1_u32.to_le_bytes());
    assert_eq!(legacy.verify().unwrap().class, 3);

    let mut empty_adjusted = legacy.clone();
    empty_adjusted.claim_tag = 11;
    assert!(matches!(
        empty_adjusted.verify(),
        Err(RecordError::Decode(DecodeError {
            what: "reconciled.outstanding",
            ..
        }))
    ));

    // A nonempty zero-net selection still has its own tag and immutable list.
    let mut net_zero = adjusted(false);
    net_zero.cash = legacy.cash;
    net_zero.outstanding[1].3 = -4_000;
    let (adjusted_record, adjusted_split) = net_zero.record();
    assert_eq!(adjusted_record[18], 11);
    assert_eq!(adjusted_split, split + 4 + 2 * 66);
    assert_eq!(net_zero.verify().unwrap().class, 11);
}

#[test]
fn adjusted_inclusion_accepts_deposits_checks_and_existing_manifest_profiles() {
    for linked in [false, true] {
        for declared in [false, true] {
            let mut fixture = adjusted(linked);
            if declared {
                let layout = declared_layout_bytes(if linked { 8 } else { 7 });
                declare_layout(&mut fixture, &layout);
            }
            let (record, split) = fixture.record();
            let envelope = fixture.verify().unwrap();
            assert_eq!(envelope.kind, KIND_ATTESTATION);
            assert_eq!(envelope.class, 11);
            assert_eq!(envelope.book_id, BOOK);
            assert_eq!(envelope.commit_seq, 9);
            assert!(envelope.account_vids.is_empty());
            assert!(envelope.unit_ids.is_empty());
            assert!(check_record(&envelope, &record, split).unwrap().is_empty());

            let mut wrong = envelope;
            wrong.class = 3;
            assert_eq!(
                check_record(&wrong, &record, split),
                Err(RecordError::Envelope)
            );
        }
    }
    // One entry may have several distinct cash legs. Identity includes the
    // ordinal, while a repeated ordinal cannot be hidden by another digest.
    let mut same_entry = adjusted(false);
    same_entry.outstanding[0].2 = 0;
    same_entry.outstanding[1].0 = same_entry.outstanding[0].0;
    same_entry.outstanding[1].1 = same_entry.outstanding[0].1;
    same_entry.outstanding[1].2 = 1;
    assert!(same_entry.verify().is_ok());
}

#[test]
fn adjusted_inclusion_rejects_duplicate_legs_unordered_rows_and_invalid_amounts() {
    let good = adjusted(false);
    let mut reversed = good.clone();
    reversed.outstanding.reverse();
    let mut duplicate = good.clone();
    duplicate.outstanding[1].0 = duplicate.outstanding[0].0;
    duplicate.outstanding[1].2 = duplicate.outstanding[0].2;
    assert_ne!(duplicate.outstanding[0].1, duplicate.outstanding[1].1);
    for fixture in [reversed, duplicate] {
        assert!(matches!(
            fixture.verify(),
            Err(RecordError::Decode(DecodeError {
                what: "reconciled.outstanding",
                reason: Reason::Unsorted,
                ..
            }))
        ));
    }
    for invalid_amount in [0, i128::MIN] {
        let mut wrong = good.clone();
        wrong.outstanding[0].3 = invalid_amount;
        assert!(matches!(
            wrong.verify(),
            Err(RecordError::Decode(DecodeError {
                what: "reconciled.outstanding.signed_amount",
                ..
            }))
        ));
    }
}

#[test]
fn adjusted_inclusion_uses_checked_sums_and_the_exact_statement_equation() {
    for amounts in [[i128::MAX, 1], [-i128::MAX, -2]] {
        let mut wrong = adjusted(false);
        wrong.outstanding[0].3 = amounts[0];
        wrong.outstanding[1].3 = amounts[1];
        assert!(matches!(
            wrong.verify(),
            Err(RecordError::Decode(DecodeError {
                what: "reconciled.outstanding.sum",
                ..
            }))
        ));
    }
    for (cash, amount) in [(i128::MIN, 1), (i128::MAX, -1), (60_000, 1)] {
        let mut wrong = adjusted(false);
        wrong.cash = cash;
        wrong.outstanding = vec![(200, [0x61; 32], 0, amount)];
        assert!(matches!(
            wrong.verify(),
            Err(RecordError::Decode(DecodeError {
                what: "reconciled.adjusted_close",
                ..
            }))
        ));
    }
}

#[test]
fn adjusted_inclusion_keeps_all_source_evidence_and_publication_bindings() {
    let good = adjusted(false);
    let mut cases = Vec::new();
    let mut wrong = good.clone();
    wrong.manifest_oid[0] ^= 1;
    cases.push(("manifest identity", wrong));
    let mut wrong = good.clone();
    wrong.subject[0] ^= 1;
    cases.push(("subject", wrong));
    let mut wrong = good.clone();
    wrong.evidence.pop();
    cases.push(("statement evidence", wrong));
    let mut wrong = good.clone();
    wrong.profile = 1;
    cases.push(("Human profile", wrong));
    let mut wrong = good.clone();
    wrong.matches.pop();
    cases.push(("complete confirmations", wrong));
    let mut wrong = good.clone();
    wrong.imported = good.evaluated + 1;
    cases.push(("import frontier", wrong));
    for (case, fixture) in cases {
        // The independent builder recomputes the entire attestation digest.
        assert!(fixture.verify().is_err(), "accepted changed {case}");
    }
    let (record, split) = good.record();
    for seq in [0, 8, 10, u64::MAX] {
        assert!(matches!(
            envelope_of_record(KIND_ATTESTATION, &record, split, seq, 2),
            Err(RecordError::Decode(DecodeError {
                what: "reconciled.recorded_at",
                ..
            }))
        ));
    }
}

#[test]
fn outstanding_wire_count_is_bounded_without_claiming_inline_storage_admission() {
    // The independent wire bound is distinct from native new-publication
    // payload admission. Passing this decoder does not promise a row will fit.
    for count in [MAX_BANK_OUTSTANDING_ITEMS - 1, MAX_BANK_OUTSTANDING_ITEMS] {
        let mut fixture = adjusted(false);
        fixture.cash = 60_000 + count as i128;
        fixture.outstanding = (0..count)
            .map(|i| (200 + i as u128, [0x61; 32], 0, 1))
            .collect();
        assert!(fixture.verify().is_ok(), "wire count {count}");
        fixture
            .outstanding
            .push((200 + count as u128, [0x61; 32], 0, 1));
        fixture.cash += 1;
        if count == MAX_BANK_OUTSTANDING_ITEMS {
            assert!(matches!(
                fixture.verify(),
                Err(RecordError::Decode(DecodeError {
                    what: "reconciled.outstanding",
                    reason: Reason::TooLong {
                        max: MAX_BANK_OUTSTANDING_ITEMS,
                        actual: 1025,
                    },
                    ..
                }))
            ));
        }
    }
}

#[test]
fn truncated_outstanding_fields_refuse_even_with_a_recomputed_body_digest() {
    let fixture = adjusted(false);
    let (record, _) = fixture.record();
    // The two outstanding records occupy [508,640); their four-byte count
    // starts at 504. Each shortened body receives a fresh, valid trailer.
    for end in 504..640 {
        let body = &record[..end];
        let digest = framed_digest(ATTESTATION_DIGEST_DOMAIN, body);
        let mut w = Writer::default();
        w.fixed(body).fixed(&digest).u8(0).u8(0).fixed(&[0x55; 32]);
        assert!(
            matches!(
                envelope_of_record(KIND_ATTESTATION, &w.buf, end, 9, 2),
                Err(RecordError::Decode(_))
            ),
            "accepted truncated outstanding body at {end}"
        );
    }
}
