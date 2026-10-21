use super::*;
use crate::bundle::{
    BUNDLE_FORMAT, Completeness, FORMAT_MAJOR, FORMAT_MINOR, Manifest, Summary, manifest_md,
};
use crate::checkpoint::witness::{RecipientWitnessPolicy, verify_witnessed_checkpoint};
use crate::checkpoint::{signer_key_id, verify_checkpoint};
use crate::codec::Writer;

fn fixture(file: &str, name: &str) -> Vec<u8> {
    let text = match file {
        "initial" => include_str!("../../../../tests/fixtures/checkpoint_witness_v1.txt"),
        _ => include_str!("../../../../tests/fixtures/checkpoint_witness_advance_v1.txt"),
    };
    let hex = text
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn key(name: &str) -> [u8; 32] {
    fixture("initial", name).try_into().unwrap()
}

fn anchor(bytes: &[u8]) -> WitnessedCheckpoint {
    let policy = RecipientWitnessPolicy::new(
        [0x11; 16],
        [0; 16],
        [0x55; 32],
        key("publisher"),
        &[key("witness_a"), key("witness_b"), key("witness_c")],
        2,
    )
    .unwrap();
    verify_witnessed_checkpoint(bytes, &policy).unwrap()
}

fn request() -> BundleExpectation {
    BundleExpectation {
        scope: BundleScope::Entries(vec![]),
        inline_documents: true,
        publisher_receipt: false,
    }
}

// No accounting or document claim: this is a genuine empty membership set
// under a fixed, signed checkpoint, useful for isolating anchor/scope binding.
fn bundle(bytes: &[u8]) -> Vec<u8> {
    let signed = verify_checkpoint(bytes, &[key("publisher")]).unwrap();
    let cp = signed.checkpoint;
    let manifest = Manifest {
        book_id: cp.book_id,
        branch_id: cp.branch_id,
        through_seq: cp.through_seq,
        leaf_count: cp.leaf_count,
        checkpoint_oid: signed.oid,
        scope: BundleScope::Entries(vec![]),
        completeness: Completeness::FilterAttested,
    };
    let summary = Summary {
        format: (FORMAT_MAJOR, FORMAT_MINOR),
        entries: 0,
        documents: 0,
        inline: 0,
        balances: vec![],
    };
    let mut w = Writer::default();
    w.bytes(BUNDLE_FORMAT)
        .u16(FORMAT_MAJOR)
        .u16(FORMAT_MINOR)
        .fixed(&cp.book_id)
        .fixed(&cp.branch_id)
        .u64(cp.through_seq)
        .u64(cp.leaf_count)
        .fixed(&signed.oid)
        .u8(3)
        .count(0)
        .u8(3)
        .bytes(bytes)
        .count(0)
        .count(0)
        .count(0)
        .bytes(manifest_md(&manifest, &summary).as_bytes());
    w.buf
}

fn check<'a>(report: &'a BundleReport, name: &str) -> &'a Grade {
    &report
        .checks
        .iter()
        .find(|check| check.check == name)
        .unwrap()
        .grade
}

#[test]
fn a_matching_witnessed_artifact_and_recipient_request_do_not_upgrade_membership() {
    let cp = fixture("initial", "initial");
    let pin = anchor(&cp);
    let retained = pin.clone();
    let bytes = bundle(&cp);
    let report = verify_witnessed_bundle_for(&bytes, &pin, &request(), None).unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(report.manifest.completeness.label(), "membership_only");
    assert_eq!(check(&report, "witnessed_checkpoint_binding"), &Grade::Pass);
    assert_eq!(pin, retained);
    assert!(report.receipt.is_none());
}

#[test]
fn genuine_bundles_for_other_checkpoints_cannot_borrow_the_retained_quorum() {
    let cp = fixture("initial", "initial");
    let pin = anchor(&cp);
    for other in [
        fixture("advance", "extended"),
        fixture("initial", "foreign_book"),
    ] {
        let bytes = bundle(&other);
        assert!(
            verify_bundle(&bytes, &[key("publisher")], None)
                .unwrap()
                .verified()
        );
        let report = verify_witnessed_bundle_for(&bytes, &pin, &request(), None).unwrap();
        assert!(!report.verified());
        assert!(matches!(
            check(&report, "witnessed_checkpoint_binding"),
            Grade::Fail(_)
        ));
        assert!(matches!(
            check(&report, "requested_bundle_scope"),
            Grade::Unrun(_)
        ));
    }
}

#[test]
fn stripping_witnesses_cannot_reuse_a_quorum_for_the_same_signed_body() {
    let cp = fixture("initial", "initial");
    let pin = anchor(&cp);
    let id = signer_key_id(&key("publisher"));
    let publisher = cp[218..]
        .as_chunks::<102>()
        .0
        .iter()
        .find(|row| row[..32] == id)
        .unwrap();
    let mut stripped = cp[..214].to_vec();
    stripped.extend_from_slice(&1u32.to_le_bytes());
    stripped.extend_from_slice(publisher);
    let signed = verify_checkpoint(&stripped, &[key("publisher")]).unwrap();
    assert_eq!(signed.body_digest, pin.signed_checkpoint().body_digest);
    assert_ne!(signed.oid, pin.signed_checkpoint().oid);
    let bytes = bundle(&stripped);
    assert!(
        verify_bundle(&bytes, &[key("publisher")], None)
            .unwrap()
            .verified()
    );
    let report = verify_witnessed_bundle_for(&bytes, &pin, &request(), None).unwrap();
    assert!(matches!(
        check(&report, "witnessed_checkpoint_binding"),
        Grade::Fail(_)
    ));
}

#[test]
fn valid_scope_substitution_is_not_the_recipients_question() {
    let cp = fixture("initial", "initial");
    let pin = anchor(&cp);
    let bytes = bundle(&cp);
    for scope in [
        BundleScope::Prefix,
        BundleScope::Entries(vec![0]),
        BundleScope::Account(crate::ScopeClaim {
            account: 1,
            from: i32::MIN,
            to: i32::MAX,
        }),
    ] {
        let expected = BundleExpectation { scope, ..request() };
        let report = verify_witnessed_bundle_for(&bytes, &pin, &expected, None).unwrap();
        assert_eq!(check(&report, "witnessed_checkpoint_binding"), &Grade::Pass);
        assert!(matches!(
            check(&report, "requested_bundle_scope"),
            Grade::Fail(_)
        ));
        assert!(!report.verified());
    }
}

#[test]
fn a_required_receipt_cannot_be_omitted_or_replaced_with_an_invalid_one() {
    let cp = fixture("initial", "initial");
    let pin = anchor(&cp);
    let bytes = bundle(&cp);
    let expected = BundleExpectation {
        publisher_receipt: true,
        ..request()
    };
    for receipt in [None, Some(b"not a receipt".as_slice())] {
        let report = verify_witnessed_bundle_for(&bytes, &pin, &expected, receipt).unwrap();
        assert!(!report.verified());
        assert!(matches!(
            check(&report, "requested_publisher_receipt"),
            Grade::Fail(_)
        ));
    }
    // Even an optional receipt is checked once supplied; invalid is not absent.
    assert!(
        !verify_witnessed_bundle_for(&bytes, &pin, &request(), Some(b"bad"))
            .unwrap()
            .verified()
    );
}

#[test]
fn malformed_requests_and_resource_bounds_are_checked_before_bundle_decoding() {
    let pin = anchor(&fixture("initial", "initial"));
    for scope in [
        BundleScope::Entries(vec![0, 0]),
        BundleScope::Entries(vec![1]),
        BundleScope::Entries(vec![u64::MAX, 0]),
        BundleScope::Account(crate::ScopeClaim {
            account: 0,
            from: 2,
            to: 1,
        }),
        BundleScope::Entries(vec![0; MAX_REQUESTED_BUNDLE_LEAVES + 1]),
    ] {
        let expected = BundleExpectation { scope, ..request() };
        assert!(matches!(
            verify_witnessed_bundle_for(b"bad", &pin, &expected, None),
            Err(WitnessBundleError::Request(_))
        ));
    }
    let large_receipt = vec![0; MAX_WITNESSED_RECEIPT_BYTES + 1];
    assert!(matches!(
        verify_witnessed_bundle_for(b"bad", &pin, &request(), Some(&large_receipt)),
        Err(WitnessBundleError::InputLimit("receipt bytes"))
    ));
    let large_bundle = vec![0; MAX_WITNESSED_BUNDLE_BYTES];
    assert!(matches!(
        verify_witnessed_bundle_for(&large_bundle, &pin, &request(), Some(b"x")),
        Err(WitnessBundleError::InputLimit(
            "aggregate bundle and receipt bytes"
        ))
    ));
}

#[test]
fn changing_the_manifest_anchor_or_corrupting_the_frame_never_inherits_verified_grades() {
    let cp = fixture("initial", "initial");
    let pin = anchor(&cp);
    let good = bundle(&cp);
    let mut changed = good.clone();
    // Format framing + major/minor + book/branch/seq/count precede the OID.
    let oid_offset = 4 + BUNDLE_FORMAT.len() + 4 + 16 + 16 + 8 + 8;
    changed[oid_offset] ^= 1;
    let report = verify_witnessed_bundle_for(&changed, &pin, &request(), None).unwrap();
    assert!(!report.verified());
    assert!(matches!(
        check(&report, "witnessed_checkpoint_binding"),
        Grade::Unrun(_)
    ));
    for end in [0, 1, good.len() - 1] {
        assert!(verify_witnessed_bundle_for(&good[..end], &pin, &request(), None).is_err());
    }
    let mut trailing = good;
    trailing.push(0);
    assert!(verify_witnessed_bundle_for(&trailing, &pin, &request(), None).is_err());
}
