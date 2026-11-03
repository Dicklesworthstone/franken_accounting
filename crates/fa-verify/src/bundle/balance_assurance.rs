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
    let minor = if balances.is_empty() {
        FORMAT_MINOR
    } else {
        FORMAT_MINOR_DISCLOSURE
    };
    filtered_format(checkpoint, balances, minor, &[])
}

fn filtered_format(
    checkpoint: &[u8],
    balances: &[&[u8]],
    minor: u16,
    approvals: &[&[u8]],
) -> Vec<u8> {
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
        format: (FORMAT_MAJOR, minor),
        entries: 0,
        documents: 0,
        inline: 0,
        balances: balances
            .iter()
            .map(|_| (FOLD_DOMAIN.to_vec(), FOLD_VERSION))
            .collect(),
        approvals: (minor != FORMAT_MINOR).then_some(ApprovalSummary {
            records: approvals.len() as u64,
            signed: approvals
                .iter()
                .filter(|a| super::approvals::is_signed(a))
                .count() as u64,
            key_records: 0,
        }),
    };
    let mut w = Writer::default();
    w.bytes(BUNDLE_FORMAT)
        .u16(FORMAT_MAJOR)
        .u16(minor)
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
    if minor != FORMAT_MINOR {
        w.count(approvals.len());
        for approval in approvals {
            w.bytes(approval);
        }
        w.count(0);
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
    let subject = &balance_check(&report).subject;
    assert!(
        subject.contains("every prefix entry selector independently rebuilt from its payload"),
        "{subject}"
    );
    assert!(
        subject.contains("non-entry leaves rest on their signed kind"),
        "the premise the recomputation rests on is named: {subject}"
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
        assert!(matches!(disclosure_check(&report).grade, Grade::Unrun(_)));
        assert!(
            report
                .checks
                .iter()
                .filter(|c| !matches!(c.check, "recomputation" | "payload_disclosure"))
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

fn complete_balance(p: &Parsed<'_>, cp: &crate::Checkpoint, claim: crate::BalanceClaim) -> Vec<u8> {
    let ProofSection::Prefix(prefix) = &p.proof else {
        panic!("prefix fixture")
    };
    let prefix = verify_prefix(prefix, cp).unwrap();
    assert_eq!(
        p.entries.len(),
        prefix.envelopes.len(),
        "fixture carries every record"
    );
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
    w.buf
}

fn complete_fixture_balance() -> (Vec<u8>, Vec<u8>) {
    let bytes = fixture("bundle_prefix");
    let p = parse(&bytes).unwrap();
    let cp = verify_checkpoint(p.checkpoint, &[key()])
        .unwrap()
        .checkpoint;
    let claim = verify_balance(p.balances[0].proof, &cp).unwrap().claim;
    (p.checkpoint.to_vec(), complete_balance(&p, &cp, claim))
}

fn disclosure_check(report: &BundleReport) -> &BundleCheck {
    report
        .checks
        .iter()
        .find(|c| c.check == "payload_disclosure")
        .expect("disclosure predicate")
}

#[test]
fn payload_complete_v3_is_sufficient_even_when_the_bundle_scope_is_filtered() {
    let (checkpoint, proof) = complete_fixture_balance();
    let cp = verify_checkpoint(&checkpoint, &[key()]).unwrap().checkpoint;
    assert_eq!(
        verify_balance(&proof, &cp).unwrap().scope,
        SCOPE_RECOMPUTATION
    );
    let report = verify_bundle(&filtered(&checkpoint, &[&proof]), &[key()], None).unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(balance_check(&report).grade, Grade::Pass);
    assert_eq!(report.summary.format, (1, 2));
    assert_eq!(report.summary.entries, 0);
    assert_eq!(report.manifest.leaf_count, 5);
    assert_eq!(disclosure_check(&report).grade, Grade::Pass);
    assert_eq!(disclosure_check(&report).scope, "whole_checkpoint_prefix");
    let md = manifest_md(&report.manifest, &report.summary);
    assert!(
        md.contains("all 5 distinct checkpoint journal record payloads"),
        "{md}"
    );
    assert!(md.contains("records outside the entry selection"), "{md}");
}

#[test]
fn a_scoped_balance_cannot_strip_its_disclosure_by_downgrading_the_format() {
    let (checkpoint, proof) = complete_fixture_balance();
    for minor in [FORMAT_MINOR, FORMAT_MINOR_APPROVALS] {
        // Same genuine signed checkpoint and complete balance proof. Only
        // the declared version and its exact canonical sections/text change.
        let bytes = filtered_format(&checkpoint, &[&proof], minor, &[]);
        let report = verify_bundle(&bytes, &[key()], None).unwrap();
        assert!(
            !report.verified(),
            "format 1.{minor} hides five payloads behind zero entries"
        );
        assert_eq!(balance_check(&report).grade, Grade::Pass);
        let failed: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.grade != Grade::Pass)
            .collect();
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0].check, "format");
        assert!(
            matches!(&failed[0].grade, Grade::Fail(why) if why.contains("whole_checkpoint_prefix"))
        );
    }
}

fn replace_manifest(bytes: &[u8], text: &str) -> Vec<u8> {
    let p = parse(bytes).unwrap();
    let mut w = Writer::default();
    w.fixed(&bytes[..bytes.len() - p.manifest_md.len() - 4])
        .bytes(text.as_bytes());
    w.buf
}

#[test]
fn disclosure_text_cannot_be_omitted_understated_or_inferred_from_a_failed_proof() {
    let (checkpoint, proof) = complete_fixture_balance();
    let bytes = filtered(&checkpoint, &[&proof]);
    let p = parse(&bytes).unwrap();
    let md = std::str::from_utf8(p.manifest_md).unwrap();
    let omitted = md
        .lines()
        .filter(|line| !line.starts_with("- Payload disclosure:"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    for text in [omitted, md.replace("all 5 distinct", "all 0 distinct")] {
        let report = verify_bundle(&replace_manifest(&bytes, &text), &[key()], None).unwrap();
        assert!(!report.verified());
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.check == "manifest" && matches!(c.grade, Grade::Fail(_)))
        );
        assert!(matches!(disclosure_check(&report).grade, Grade::Unrun(_)));
        assert_eq!(balance_check(&report).grade, Grade::Pass);
    }
    let mut corrupted = proof.clone();
    *corrupted.last_mut().unwrap() = 1; // invalid run-body count; no changed trust anchor
    let report = verify_bundle(&filtered(&checkpoint, &[&corrupted]), &[key()], None).unwrap();
    assert!(matches!(balance_check(&report).grade, Grade::Fail(_)));
    assert!(matches!(disclosure_check(&report).grade, Grade::Unrun(_)));
    let wrong_key = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let report = verify_bundle(&bytes, &[wrong_key], None).unwrap();
    assert!(matches!(disclosure_check(&report).grade, Grade::Unrun(_)));
}

#[test]
fn disclosure_format_is_not_an_optional_label_for_an_empty_selection_without_balances() {
    let (checkpoint, _) = complete_fixture_balance();
    let normal = verify_bundle(&filtered(&checkpoint, &[]), &[key()], None).unwrap();
    assert!(normal.verified());
    assert_eq!(normal.summary.format, (1, 0));
    let report = verify_bundle(
        &filtered_format(&checkpoint, &[], FORMAT_MINOR_DISCLOSURE, &[]),
        &[key()],
        None,
    )
    .unwrap();
    assert!(!report.verified());
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.check == "format" && matches!(c.grade, Grade::Fail(_)))
    );
}

#[test]
fn disclosure_cli_reports_distinct_records_with_the_disclosure_predicates_grade() {
    let (checkpoint, proof) = complete_fixture_balance();
    // Two stock claims repeat the same five payloads, never ten distinct records.
    let bytes = filtered(&checkpoint, &[&proof, &proof]);
    let run = |bytes: &[u8], json: bool| {
        let mut args = vec!["bundle".into(), "input".into(), "--key".into(), hex(&key())];
        if json {
            args.push("--json".into());
        }
        crate::cli::run(&args, &|path| {
            assert_eq!(path, "input");
            Ok(bytes.to_vec())
        })
    };
    let json = run(&bytes, true);
    assert_eq!(json.exit, 0, "{}", json.stdout);
    assert!(
        json.stdout
            .contains("\"scope\":\"whole_checkpoint_prefix\""),
        "{}",
        json.stdout
    );
    assert!(
        json.stdout.contains("\"distinct_journal_records\":5"),
        "{}",
        json.stdout
    );
    assert!(
        json.stdout.contains("\"selected_entries\":0"),
        "{}",
        json.stdout
    );
    assert!(
        json.stdout.contains("\"balance_proofs\":2"),
        "{}",
        json.stdout
    );
    assert_eq!(run(&bytes, true), json, "deterministic output");
    let human = run(&bytes, false);
    assert_eq!(human.exit, 0, "{}", human.stdout);
    assert!(
        human
            .stdout
            .contains("PASS payload_disclosure (whole_checkpoint_prefix)"),
        "{}",
        human.stdout
    );
    assert!(
        human.stdout.contains("distinct_journal_records: 5"),
        "{}",
        human.stdout
    );
    let broken = replace_manifest(&bytes, "entries only\n");
    let refused = run(&broken, false);
    assert_eq!(refused.exit, 8, "{}", refused.stdout);
    assert!(
        refused.stdout.contains("UNRUN payload_disclosure"),
        "{}",
        refused.stdout
    );
}

fn approval_fixture(name: &str) -> Vec<u8> {
    vector(
        include_str!("../../tests/fixtures/bundle_approvals_v1_1.txt"),
        name,
    )
}

// Add a stock proof to an otherwise unchanged, genuinely signed 1.1
// fixture. Copy the exact scope proof and selected entry bytes, then write
// the new sections. Neither the checkpoint nor an approval is re-signed.
fn approval_bundle_with_balance(
    original: &[u8],
    proof: &[u8],
    minor: u16,
    records: &[&[u8]],
) -> Vec<u8> {
    let key: [u8; 32] = approval_fixture("public_key").try_into().unwrap();
    let original_report = verify_bundle(original, &[key], None).unwrap();
    assert!(original_report.verified());
    let p = parse(original).unwrap();
    assert!(p.balances.is_empty());
    assert_eq!(p.approvals.len(), 1);
    let first = original
        .windows(p.approvals[0].len())
        .position(|part| part == p.approvals[0])
        .unwrap();
    let body_end = first - 12; // empty balance count, approval count, approval byte length
    assert_eq!(&original[body_end..body_end + 4], &[0; 4]);
    assert_eq!(&original[body_end + 4..body_end + 8], &1u32.to_le_bytes());
    let mut w = Writer::default();
    w.fixed(&original[..body_end]);
    let minor_at = 4 + BUNDLE_FORMAT.len() + 2;
    w.buf[minor_at..minor_at + 2].copy_from_slice(&minor.to_le_bytes());
    w.count(1).bytes(FOLD_DOMAIN).u16(FOLD_VERSION).bytes(proof);
    if minor != FORMAT_MINOR {
        w.count(records.len());
        for record in records {
            w.bytes(record);
        }
        w.count(p.key_leaves.len());
        for leaf in &p.key_leaves {
            w.u64(leaf.leaf_index)
                .bytes(leaf.envelope)
                .count(leaf.path.len());
            for node in &leaf.path {
                w.fixed(node);
            }
            w.u32(u32::try_from(leaf.proposal_len).unwrap())
                .bytes(leaf.record);
        }
    }
    let mut summary = original_report.summary;
    summary.format.1 = minor;
    summary.balances = vec![(FOLD_DOMAIN.to_vec(), FOLD_VERSION)];
    summary.approvals = (minor != FORMAT_MINOR).then_some(ApprovalSummary {
        records: records.len() as u64,
        signed: records
            .iter()
            .filter(|r| super::approvals::is_signed(r))
            .count() as u64,
        key_records: p.key_leaves.len() as u64,
    });
    w.bytes(manifest_md(&p.manifest, &summary).as_bytes());
    w.buf
}

#[test]
fn scoped_balance_disclosure_preserves_approval_set_key_chain_and_signature_checks() {
    let key: [u8; 32] = approval_fixture("public_key").try_into().unwrap();
    let original = approval_fixture("bundle_entries");
    let whole = approval_fixture("bundle_prefix");
    let p = parse(&whole).unwrap();
    let cp = verify_checkpoint(p.checkpoint, &[key]).unwrap().checkpoint;
    let claim = crate::BalanceClaim {
        account: u128::MAX,
        unit: u32::MAX,
        effective_through: None,
        debits: 0,
        credits: 0,
    };
    let proof = complete_balance(&p, &cp, claim);
    assert_eq!(
        verify_balance(&proof, &cp).unwrap().scope,
        SCOPE_RECOMPUTATION
    );
    let approval = approval_fixture("approval_record");
    let valid =
        approval_bundle_with_balance(&original, &proof, FORMAT_MINOR_DISCLOSURE, &[&approval]);
    let report = verify_bundle(&valid, &[key], None).unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(report.summary.entries, 1);
    assert_eq!(report.manifest.leaf_count, 7);
    assert_eq!(
        report.summary.approvals,
        Some(ApprovalSummary {
            records: 1,
            signed: 1,
            key_records: 1
        })
    );
    for predicate in [
        "approvals",
        "key_record",
        "key_chain",
        "approval",
        "payload_disclosure",
    ] {
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.check == predicate && c.grade == Grade::Pass),
            "{predicate}: {:?}",
            report.checks
        );
    }
    let mut bad_signature = approval.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let broken = approval_bundle_with_balance(
        &original,
        &proof,
        FORMAT_MINOR_DISCLOSURE,
        &[&bad_signature],
    );
    let report = verify_bundle(&broken, &[key], None).unwrap();
    assert!(!report.verified());
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.check == "approval" && matches!(c.grade, Grade::Fail(_)))
    );
    let omitted = approval_bundle_with_balance(&original, &proof, FORMAT_MINOR_DISCLOSURE, &[]);
    let report = verify_bundle(&omitted, &[key], None).unwrap();
    assert!(!report.verified());
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.check == "approvals" && matches!(c.grade, Grade::Fail(_)))
    );
    for minor in [FORMAT_MINOR, FORMAT_MINOR_APPROVALS] {
        let downgraded = approval_bundle_with_balance(&original, &proof, minor, &[&approval]);
        let report = verify_bundle(&downgraded, &[key], None).unwrap();
        assert!(!report.verified());
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.check == "format" && matches!(c.grade, Grade::Fail(_)))
        );
    }

    // Broader transport does not change a Prefix bundle's canonical minor.
    let padded =
        approval_bundle_with_balance(&whole, &proof, FORMAT_MINOR_DISCLOSURE, &[&approval]);
    let report = verify_bundle(&padded, &[key], None).unwrap();
    assert!(!report.verified());
    assert_eq!(balance_check(&report).grade, Grade::Pass);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.check == "format" && matches!(c.grade, Grade::Fail(_)))
    );
}

#[test]
fn disclosure_format_with_no_citations_still_rejects_padded_approval_records() {
    let (checkpoint, proof) = complete_fixture_balance();
    let approval = approval_fixture("approval_record");
    let padded = filtered_format(
        &checkpoint,
        &[&proof],
        FORMAT_MINOR_DISCLOSURE,
        &[&approval],
    );
    let report = verify_bundle(&padded, &[key()], None).unwrap();
    assert!(!report.verified());
    assert_eq!(balance_check(&report).grade, Grade::Pass);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.check == "approvals" && matches!(c.grade, Grade::Fail(_)))
    );
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
