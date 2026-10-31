//! Balance assurance must survive bundle composition, not just proof decoding.
//! Use fixed, genuinely signed producer fixtures; never regenerate a golden.

use super::*;
use crate::balance::{BALANCE_FORMAT, SCOPE_MEMBERSHIP_ONLY, SCOPE_RECOMPUTATION};
use crate::codec::Writer;
use crate::migration_balance::{BALANCE_FORMAT_V2, BALANCE_FORMAT_V3};

fn vector(text: &str, name: &str) -> Vec<u8> {
    let hex = text
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .expect("fixed vector");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture(name: &str) -> Vec<u8> {
    vector(include_str!("../../tests/fixtures/bundle_v1.txt"), name)
}

fn key() -> [u8; 32] {
    fixture("public_key").try_into().unwrap()
}

// Empty member selection is a valid membership-only bundle. It does NOT
// discharge the from-inception closure of its separately supplied stock claim.
fn filtered(checkpoint: &[u8], balances: &[&[u8]]) -> Vec<u8> {
    let signed = verify_checkpoint(checkpoint, &[key()]).unwrap();
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
        balances: balances
            .iter()
            .map(|_| (FOLD_DOMAIN.to_vec(), FOLD_VERSION))
            .collect(),
        approvals: None,
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
        .u8(SCOPE_ENTRIES)
        .count(0)
        .u8(COMPLETENESS_FILTER_ATTESTED)
        .bytes(checkpoint)
        .count(0)
        .count(0)
        .count(balances.len());
    for proof in balances {
        w.bytes(FOLD_DOMAIN).u16(FOLD_VERSION).bytes(proof);
    }
    w.bytes(manifest_md(&manifest, &summary).as_bytes());
    w.buf
}

// Re-encode the SAME signed full-prefix production, selecting which payloads
// to supply. No checkpoint, root, golden file or stored digest is modified.
fn prefix_with_records(p: &Parsed<'_>, indexes: &[usize], corrupt: Option<usize>) -> Vec<u8> {
    let ProofSection::Prefix(prefix) = &p.proof else {
        panic!("prefix fixture")
    };
    let m = &p.manifest;
    let mut summary = Summary {
        format: p.format,
        entries: indexes.len() as u64,
        documents: 0,
        inline: 0,
        balances: p
            .balances
            .iter()
            .map(|b| (b.domain.to_vec(), b.version))
            .collect(),
        approvals: None,
    };
    let mut w = Writer::default();
    w.bytes(BUNDLE_FORMAT)
        .u16(p.format.0)
        .u16(p.format.1)
        .fixed(&m.book_id)
        .fixed(&m.branch_id)
        .u64(m.through_seq)
        .u64(m.leaf_count)
        .fixed(&m.checkpoint_oid)
        .u8(SCOPE_PREFIX)
        .u8(COMPLETENESS_SEQ_RANGE)
        .u64(0)
        .u64(m.leaf_count)
        .bytes(p.checkpoint)
        .bytes(prefix)
        .count(indexes.len());
    for index in indexes {
        let item = &p.entries[*index];
        let mut record = item.record.to_vec();
        if corrupt == Some(*index) {
            record[0] ^= 1;
        }
        w.u64(item.leaf_index)
            .u32(u32::try_from(item.proposal_len).unwrap())
            .bytes(&record)
            .count(item.stubs.len());
        for stub in &item.stubs {
            summary.documents += 1;
            w.fixed(&stub.doc_commit)
                .u8(stub.kind)
                .u64(stub.length)
                .fixed(&stub.chunk_root);
            if let Some(bytes) = stub.inline {
                summary.inline += 1;
                w.u8(1).bytes(bytes);
            } else {
                w.u8(0);
            }
        }
    }
    w.count(p.balances.len());
    for b in &p.balances {
        w.bytes(b.domain).u16(b.version).bytes(b.proof);
    }
    w.bytes(manifest_md(m, &summary).as_bytes());
    w.buf
}

fn balance_check(report: &BundleReport) -> &BundleCheck {
    report
        .checks
        .iter()
        .find(|c| c.check == "recomputation")
        .expect("balance predicate")
}

#[test]
fn genuine_prefix_closure_preserves_the_pinned_bundle_and_detached_receipt() {
    let bytes = fixture("bundle_prefix");
    let p = parse(&bytes).unwrap();
    let cp = verify_checkpoint(p.checkpoint, &[key()])
        .unwrap()
        .checkpoint;
    assert_eq!(p.balances.len(), 1);
    assert_eq!(
        verify_balance(p.balances[0].proof, &cp).unwrap().scope,
        SCOPE_MEMBERSHIP_ONLY
    );
    let report = verify_bundle(&bytes, &[key()], Some(&fixture("receipt"))).unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(balance_check(&report).scope, SCOPE_RECOMPUTATION);
    assert!(
        balance_check(&report)
            .subject
            .contains("every prefix selector")
    );
    assert!(report.receipt.is_some());
}

#[test]
fn partial_v1_or_v2_inside_a_filtered_bundle_never_becomes_recomputation() {
    let original = fixture("bundle_prefix");
    let p = parse(&original).unwrap();
    let cp = verify_checkpoint(p.checkpoint, &[key()])
        .unwrap()
        .checkpoint;
    let v1 = p.balances[0].proof;
    let mut r = Reader::new(v1);
    assert_eq!(r.bytes(64, "format").unwrap(), BALANCE_FORMAT);
    let suffix = &v1[v1.len() - r.remaining()..];
    let mut w = Writer::default();
    w.bytes(BALANCE_FORMAT_V2).fixed(suffix).count(0); // no migration runs in the fixture
    for proof in [v1, w.buf.as_slice()] {
        assert_eq!(
            verify_balance(proof, &cp).unwrap().scope,
            SCOPE_MEMBERSHIP_ONLY
        );
        let bytes = filtered(p.checkpoint, &[proof]);
        let report = verify_bundle(&bytes, &[key()], None).unwrap();
        assert!(!report.verified());
        assert!(matches!(&balance_check(&report).grade, Grade::Fail(why)
            if why.contains("membership_only") && why.contains("completeness")));
        assert!(
            report
                .checks
                .iter()
                .filter(|c| c.check != "recomputation")
                .all(|c| matches!(c.grade, Grade::Pass)),
            "{:?}",
            report.checks
        );
    }
    // An extract without a stock claim needs no unrelated opening history.
    assert!(
        verify_bundle(&filtered(p.checkpoint, &[]), &[key()], None)
            .unwrap()
            .verified()
    );
}

#[test]
fn omitted_or_corrupt_excluded_records_cannot_supply_the_missing_derivation() {
    let bytes = fixture("bundle_prefix");
    let p = parse(&bytes).unwrap();
    let cp = verify_checkpoint(p.checkpoint, &[key()])
        .unwrap()
        .checkpoint;
    let balance = verify_balance(p.balances[0].proof, &cp).unwrap();
    let excluded = p
        .entries
        .iter()
        .position(|e| !balance.contributing.contains(&e.leaf_index))
        .expect("legacy fixture excludes a payload");
    let all: Vec<_> = (0..p.entries.len()).collect();
    assert_eq!(
        prefix_with_records(&p, &all, None),
        bytes,
        "independent encoder agrees"
    );
    let missing: Vec<_> = all
        .iter()
        .copied()
        .filter(|index| *index != excluded)
        .collect();
    for variant in [
        prefix_with_records(&p, &missing, None),
        prefix_with_records(&p, &all, Some(excluded)),
    ] {
        let report = verify_bundle(&variant, &[key()], None).unwrap();
        assert!(!report.verified());
        assert!(
            matches!(&balance_check(&report).grade, Grade::Fail(why) if why.contains("completeness"))
        );
    }
}

#[test]
fn payload_complete_v3_is_sufficient_even_when_the_bundle_scope_is_filtered() {
    let bytes = fixture("bundle_prefix");
    let p = parse(&bytes).unwrap();
    let cp = verify_checkpoint(p.checkpoint, &[key()])
        .unwrap()
        .checkpoint;
    let claim = verify_balance(p.balances[0].proof, &cp).unwrap().claim;
    let ProofSection::Prefix(prefix) = &p.proof else {
        panic!("prefix fixture")
    };
    let prefix = verify_prefix(prefix, &cp).unwrap();
    let mut w = Writer::default();
    w.bytes(BALANCE_FORMAT_V3)
        .fixed(&cp.encode())
        .u128(claim.account)
        .u32(claim.unit);
    match claim.effective_through {
        Some(day) => {
            w.u8(1).i32(day);
        }
        None => {
            w.u8(0);
        }
    }
    w.i128(claim.debits)
        .i128(claim.credits)
        .count(prefix.envelopes.len());
    for envelope in prefix.envelopes {
        w.bytes(&envelope.encode());
    }
    w.count(p.entries.len());
    for item in &p.entries {
        w.u64(item.leaf_index)
            .u32(u32::try_from(item.proposal_len).unwrap())
            .bytes(item.record);
    }
    w.count(0); // no migration controls
    assert_eq!(
        verify_balance(&w.buf, &cp).unwrap().scope,
        SCOPE_RECOMPUTATION
    );
    let report = verify_bundle(&filtered(p.checkpoint, &[&w.buf]), &[key()], None).unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(balance_check(&report).grade, Grade::Pass);
}

#[test]
fn malformed_balance_or_unsupported_fold_never_inherits_a_valid_prefixs_assurance() {
    let bytes = fixture("bundle_prefix");
    let p = parse(&bytes).unwrap();
    let proof = p.balances[0].proof;
    let mut damaged = bytes.clone();
    let start = bytes
        .windows(proof.len())
        .position(|part| part == proof)
        .unwrap();
    damaged[start] ^= 1;
    let report = verify_bundle(&damaged, &[key()], None).unwrap();
    assert!(matches!(balance_check(&report).grade, Grade::Fail(_)));
    let mut law = bytes.clone();
    let domain = p.balances[0].domain;
    let start = bytes
        .windows(domain.len())
        .position(|part| part == domain)
        .unwrap();
    law[start] ^= 1;
    let report = verify_bundle(&law, &[key()], None).unwrap();
    assert!(matches!(balance_check(&report).grade, Grade::Fail(_)));
}
