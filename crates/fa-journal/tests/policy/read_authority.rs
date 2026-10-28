//! A reusable read admission never preserves authority after revocation or
//! expiry, and cannot be retargeted to another book's database.

use super::*;
use fa_journal::policy::ReadAuthority;

const CORRUPT: VId = VId(0x5eed_1001);
const ABSENT: VId = VId(0x5eed_1002);

fn historical_entries(h: &mut Harness) -> (VId, CommitSeq) {
    h.post_ok(
        h.proposal(
            PREPARER,
            1_000,
            b"read-authority-history",
            EntryClass::ORIGINAL,
        ),
        controller(),
    );
    let valid = fa_model::entry_vid(
        h.book.book_id,
        &PREPARER.0.to_le_bytes(),
        b"read-authority-history",
    );
    let ctx = h.ctx();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        CORRUPT,
        vec![label::ENTRY],
        vec![(
            property::FA_PAYLOAD,
            fa_journal::rows::scalar_bytes("planted payload", vec![0xff; 8]).unwrap(),
        )],
    );
    h.runtime
        .block_on(h.db.write(&ctx.commit(), batch))
        .unwrap();
    (valid, h.db.frontier().unwrap())
}

fn assert_refused_before_payload(
    h: &Harness,
    reads: &ReadAuthority,
    valid: VId,
    history: CommitSeq,
    code: &str,
) {
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let expected = reads
        .read_entry(&h.db, ABSENT, history)
        .unwrap()
        .expect_err("even an absent target requires current authority");
    assert_eq!((expected.code, expected.exit), (code, exit::SAFETY));
    for target in [valid, CORRUPT] {
        let refusal = reads
            .read_entry(&h.db, target, history)
            .expect("refusal precedes decoding the corrupt historical payload")
            .unwrap_err();
        assert_eq!(refusal, expected, "target contents are not observed");
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn read_authority_rechecks_revocation_before_historical_payloads() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let capability = human(PREPARER, &["read"]).known_at_most(history);
    let reads = admit_reads(&h.db, &h.book, PREPARER, &capability)
        .unwrap()
        .unwrap();
    assert!(
        reads
            .read_entry(&h.db, valid, history)
            .unwrap()
            .unwrap()
            .is_some()
    );
    assert!(
        reads.read_entry(&h.db, CORRUPT, history).is_err(),
        "the corrupt-payload trap is live while authority is current",
    );
    let cloned = reads.clone();
    h.revoke(
        &human(ALICE, &["issue_capability"]),
        &capability,
        b"revoke-admitted-reader",
    )
    .unwrap();
    for authority in [&reads, &cloned] {
        assert_refused_before_payload(&h, authority, valid, history, "FA-REF-023");
    }
}

#[test]
fn read_authority_rechecks_expiry_before_historical_payloads() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let expires_at = CommitSeq(history.0 + 1);
    let capability = human(PREPARER, &["read"])
        .known_at_most(history)
        .expiring_at(expires_at);
    let reads = admit_reads(&h.db, &h.book, PREPARER, &capability)
        .unwrap()
        .unwrap();
    assert!(
        reads
            .read_entry(&h.db, valid, history)
            .unwrap()
            .unwrap()
            .is_some()
    );
    h.revoke(
        &human(ALICE, &["issue_capability"]),
        &human(CAROL, &["read"]),
        b"advance-past-read-expiry",
    )
    .unwrap();
    assert_eq!(h.db.frontier().unwrap(), expires_at);
    assert_refused_before_payload(&h, &reads, valid, history, "FA-REF-014");
}

#[test]
fn read_authority_rechecks_issuance_ancestor_revocation() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let root = human(PREPARER, &["read", "issue_capability"]);
    let capability = Capability::new(ALICE, Profile::Human, &[Op::Read], PREPARER)
        .unwrap()
        .holder_bound(possession_digest(&[0x73; 32]));
    h.issue(&root, &capability, b"issue-admitted-reader")
        .unwrap();
    let reads = admit_reads(&h.db, &h.book, ALICE, &capability)
        .unwrap()
        .unwrap();
    assert!(
        reads
            .read_entry(&h.db, valid, history)
            .unwrap()
            .unwrap()
            .is_some()
    );
    h.revoke(
        &human(BOB, &["issue_capability"]),
        &root,
        b"revoke-admitted-reader-ancestor",
    )
    .unwrap();
    assert_refused_before_payload(&h, &reads, valid, history, "FA-REF-023");
}

#[test]
fn read_authority_remains_usable_after_unrelated_commits() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let reads = admit_reads(&h.db, &h.book, PREPARER, &human(PREPARER, &["read"]))
        .unwrap()
        .unwrap();
    let original = reads.read_entry(&h.db, valid, history).unwrap().unwrap();
    assert!(original.is_some());
    let later = h
        .revoke(
            &human(ALICE, &["issue_capability"]),
            &human(CAROL, &["read"]),
            b"later-read-authority-entry",
        )
        .unwrap()
        .control_entry;
    assert_eq!(
        reads.read_entry(&h.db, valid, history).unwrap().unwrap(),
        original
    );
    assert_eq!(
        reads.read_entry(&h.db, later, history).unwrap().unwrap(),
        None
    );
    assert!(
        reads
            .read_entry(&h.db, later, h.db.frontier().unwrap())
            .unwrap()
            .unwrap()
            .is_some(),
    );
    assert!(
        reads.read_entry(&h.db, CORRUPT, history).is_err(),
        "a current reader still reaches the payload decoder",
    );
}

#[test]
fn read_authority_cannot_be_retargeted_to_another_books_database() {
    let h = harness();
    let capability = human(PREPARER, &["read"])
        .for_books(&[h.book.book_id])
        .unwrap();
    let reads = admit_reads(&h.db, &h.book, PREPARER, &capability)
        .unwrap()
        .unwrap();
    let ctx = h.ctx();
    let keys = DatabaseKeys::new(
        [0x6a; 32],
        DatabaseSecurityNamespaceId([0x6b; 32]),
        [0x6c; 32],
    );
    let mut other = h
        .runtime
        .block_on(Database::open_memory(&ctx.commit(), keys))
        .unwrap();
    let mut spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    spec.book_id = Id128([0x6d; 16]);
    h.runtime
        .block_on(create_book(
            &mut other,
            &ctx,
            &spec,
            &h.book.units,
            &h.book.symbols,
        ))
        .unwrap();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        CORRUPT,
        vec![label::ENTRY],
        vec![(
            property::FA_PAYLOAD,
            fa_journal::rows::scalar_bytes("foreign payload", vec![0xff; 8]).unwrap(),
        )],
    );
    h.runtime
        .block_on(other.write(&ctx.commit(), batch))
        .unwrap();
    let head = other.frontier().unwrap();
    let absent = reads.read_entry(&other, ABSENT, head).unwrap().unwrap_err();
    assert_eq!((absent.code, absent.exit), ("FA-REF-011", exit::SAFETY));
    let planted = reads
        .read_entry(&other, CORRUPT, head)
        .expect("another book's payload is never decoded")
        .unwrap_err();
    assert_eq!(planted, absent);
    let mismatched_context = admit_reads(&other, &h.book, PREPARER, &capability)
        .unwrap()
        .expect_err("a caller-supplied context cannot misidentify the database");
    assert_eq!(mismatched_context, absent);
    assert_eq!(other.frontier().unwrap(), head);
}
