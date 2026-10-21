use super::*;
use crate::bundle::{
    BUNDLE_FORMAT, Completeness, FOLD_DOMAIN, FOLD_VERSION, FORMAT_MAJOR, FORMAT_MINOR, Manifest,
    Summary, manifest_md,
};
use crate::checkpoint::witness::{RecipientWitnessPolicy, verify_witnessed_checkpoint};
use crate::checkpoint::{signer_key_id, verify_checkpoint};
use crate::codec::Writer;
use crate::proof::PREFIX_FORMAT;

fn vector(file: &str, name: &str) -> Vec<u8> {
    let text = match file {
        "keys" => include_str!("../../../../../tests/fixtures/checkpoint_witness_v1.txt"),
        _ => include_str!("../../../../../tests/fixtures/checkpoint_witness_advance_v1.txt"),
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
    vector("keys", name).try_into().unwrap()
}

fn pin(bytes: &[u8]) -> WitnessedCheckpoint {
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
        scope: crate::bundle::BundleScope::Prefix,
        inline_documents: true,
        publisher_receipt: false,
    }
}

fn balance(account: u128, unit: u32, through: Option<i32>) -> BalanceExpectation {
    BalanceExpectation {
        scope: BalanceScope {
            account,
            unit,
            effective_through: through,
        },
        amounts: Some(BalanceAmounts {
            debits: 0,
            credits: 0,
        }),
    }
}

fn proof(cp: &crate::Checkpoint, request: BalanceExpectation, format: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(format)
        .fixed(&cp.encode())
        .u128(request.scope.account)
        .u32(request.scope.unit);
    if let Some(day) = request.scope.effective_through {
        w.u8(1).i32(day);
    } else {
        w.u8(0);
    }
    w.i128(0).i128(0).count(0).count(0);
    if format != crate::balance::BALANCE_FORMAT {
        w.count(0);
    }
    w.buf
}

fn bundle(cp: &[u8], proofs: &[Vec<u8>], prefix: bool) -> Vec<u8> {
    let signed = verify_checkpoint(cp, &[key("publisher")]).unwrap();
    let c = signed.checkpoint;
    let scope = if prefix {
        crate::BundleScope::Prefix
    } else {
        crate::BundleScope::Entries(vec![])
    };
    let manifest = Manifest {
        book_id: c.book_id,
        branch_id: c.branch_id,
        through_seq: c.through_seq,
        leaf_count: c.leaf_count,
        checkpoint_oid: signed.oid,
        completeness: scope.admissible(c.leaf_count),
        scope,
    };
    let summary = Summary {
        format: (FORMAT_MAJOR, FORMAT_MINOR),
        entries: 0,
        documents: 0,
        inline: 0,
        balances: vec![(FOLD_DOMAIN.to_vec(), FOLD_VERSION); proofs.len()],
    };
    let mut w = Writer::default();
    w.bytes(BUNDLE_FORMAT)
        .u16(FORMAT_MAJOR)
        .u16(FORMAT_MINOR)
        .fixed(&c.book_id)
        .fixed(&c.branch_id)
        .u64(c.through_seq)
        .u64(c.leaf_count)
        .fixed(&signed.oid);
    if prefix {
        w.u8(1).u8(1).u64(0).u64(c.leaf_count).bytes(cp);
        let mut p = Writer::default();
        p.bytes(PREFIX_FORMAT).fixed(&c.encode()).count(0);
        w.bytes(&p.buf);
    } else {
        w.u8(3).count(0).u8(3).bytes(cp).count(0);
    }
    w.count(0).count(proofs.len());
    for proof in proofs {
        w.bytes(FOLD_DOMAIN).u16(FOLD_VERSION).bytes(proof);
    }
    w.bytes(manifest_md(&manifest, &summary).as_bytes());
    w.buf
}

fn grade<'a>(report: &'a BundleReport, name: &str) -> &'a Grade {
    &report
        .checks
        .iter()
        .find(|check| check.check == name)
        .unwrap()
        .grade
}

#[test]
fn exact_cells_and_amounts_work_for_all_balance_versions_without_changing_old_grades() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let retained = anchor.clone();
    let wanted = balance(10, 1, None);
    for format in [
        crate::balance::BALANCE_FORMAT,
        crate::migration_balance::BALANCE_FORMAT_V2,
        crate::migration_balance::BALANCE_FORMAT_V3,
    ] {
        let bytes = bundle(
            &cp,
            &[proof(
                &anchor.signed_checkpoint().checkpoint,
                wanted,
                format,
            )],
            true,
        );
        let legacy =
            super::super::verify_witnessed_bundle_for(&bytes, &anchor, &request(), None).unwrap();
        assert!(legacy.verified(), "{:?}", legacy.checks);
        let mut exact =
            verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &[wanted], None)
                .unwrap();
        assert!(exact.verified(), "{:?}", exact.checks);
        assert_eq!(grade(&exact, "requested_balance_set"), &Grade::Pass);
        exact.checks.truncate(exact.checks.len() - 2);
        assert_eq!(exact, legacy);
    }
    assert_eq!(anchor, retained);
}

#[test]
fn proof_and_request_order_are_independent_but_no_requested_cell_may_be_omitted() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let wanted = [balance(20, 2, Some(100)), balance(10, 1, None)];
    let proofs: Vec<_> = wanted
        .iter()
        .rev()
        .map(|w| {
            proof(
                &anchor.signed_checkpoint().checkpoint,
                *w,
                crate::migration_balance::BALANCE_FORMAT_V3,
            )
        })
        .collect();
    let bytes = bundle(&cp, &proofs, true);
    assert!(
        verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &wanted, None)
            .unwrap()
            .verified()
    );
    for expected in [
        wanted[..1].to_vec(),
        vec![],
        vec![wanted[0], wanted[1], balance(30, 1, None)],
    ] {
        let result =
            verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &expected, None)
                .unwrap();
        assert!(matches!(
            grade(&result, "requested_balance_set"),
            Grade::Fail(_)
        ));
        assert!(!result.verified());
    }
    let missing = bundle(&cp, &proofs[..1], true);
    assert!(
        !verify_witnessed_bundle_balances_for(&missing, &anchor, &request(), &wanted, None)
            .unwrap()
            .verified()
    );
}

#[test]
fn genuinely_verified_other_accounts_units_or_cutoffs_cannot_answer_the_request() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let wanted = balance(10, 1, None);
    for other in [
        balance(11, 1, None),
        balance(10, 2, None),
        balance(10, 1, Some(i32::MIN)),
        balance(10, 1, Some(i32::MAX)),
    ] {
        let bytes = bundle(
            &cp,
            &[proof(
                &anchor.signed_checkpoint().checkpoint,
                other,
                crate::migration_balance::BALANCE_FORMAT_V3,
            )],
            true,
        );
        assert!(
            super::super::verify_witnessed_bundle_for(&bytes, &anchor, &request(), None)
                .unwrap()
                .verified()
        );
        let result =
            verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &[wanted], None)
                .unwrap();
        assert!(matches!(
            grade(&result, "requested_balance_set"),
            Grade::Fail(_)
        ));
    }
}

#[test]
fn duplicate_valid_proofs_cannot_replace_a_missing_cell_even_when_counts_match() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let wanted = [balance(10, 1, None), balance(20, 1, None)];
    let p = proof(
        &anchor.signed_checkpoint().checkpoint,
        wanted[0],
        crate::balance::BALANCE_FORMAT,
    );
    let bytes = bundle(&cp, &[p.clone(), p], true);
    assert!(
        super::super::verify_witnessed_bundle_for(&bytes, &anchor, &request(), None)
            .unwrap()
            .verified()
    );
    let result =
        verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &wanted, None).unwrap();
    assert!(matches!(
        grade(&result, "requested_balance_set"),
        Grade::Fail(_)
    ));
    assert!(matches!(
        grade(&result, "requested_balance_amounts"),
        Grade::Unrun(_)
    ));
}

#[test]
fn equal_net_is_not_equal_gross_and_unspecified_amounts_do_not_widen_scope() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let actual = balance(u128::MAX, u32::MAX, Some(i32::MAX));
    let bytes = bundle(
        &cp,
        &[proof(
            &anchor.signed_checkpoint().checkpoint,
            actual,
            crate::migration_balance::BALANCE_FORMAT_V3,
        )],
        true,
    );
    let learned = BalanceExpectation {
        amounts: None,
        ..actual
    };
    assert!(
        verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &[learned], None)
            .unwrap()
            .verified()
    );
    for amounts in [
        BalanceAmounts {
            debits: 1,
            credits: 1,
        },
        BalanceAmounts {
            debits: i128::MAX,
            credits: i128::MAX,
        },
        BalanceAmounts {
            debits: 1,
            credits: 0,
        },
        BalanceAmounts {
            debits: 0,
            credits: 1,
        },
    ] {
        let wanted = BalanceExpectation {
            amounts: Some(amounts),
            ..actual
        };
        let result =
            verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &[wanted], None)
                .unwrap();
        assert_eq!(grade(&result, "requested_balance_set"), &Grade::Pass);
        assert!(matches!(
            grade(&result, "requested_balance_amounts"),
            Grade::Fail(_)
        ));
        assert!(!result.verified());
    }
}

#[test]
fn explicitly_empty_set_is_distinct_from_not_requesting_balances() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let empty = bundle(&cp, &[], true);
    assert!(
        verify_witnessed_bundle_balances_for(&empty, &anchor, &request(), &[], None)
            .unwrap()
            .verified()
    );
    let wanted = balance(10, 1, None);
    assert!(
        !verify_witnessed_bundle_balances_for(&empty, &anchor, &request(), &[wanted], None)
            .unwrap()
            .verified()
    );
    let nonempty = bundle(
        &cp,
        &[proof(
            &anchor.signed_checkpoint().checkpoint,
            wanted,
            crate::balance::BALANCE_FORMAT,
        )],
        true,
    );
    assert!(
        !verify_witnessed_bundle_balances_for(&nonempty, &anchor, &request(), &[], None)
            .unwrap()
            .verified()
    );
}

#[test]
fn malformed_requests_fail_before_any_bundle_decode_and_counts_have_a_shared_bound() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let wanted = balance(10, 1, None);
    let mut different_amounts = wanted;
    different_amounts.amounts = None;
    let mut negative = wanted;
    negative.amounts = Some(BalanceAmounts {
        debits: -1,
        credits: 0,
    });
    for values in [
        vec![wanted, different_amounts],
        vec![negative],
        vec![wanted; MAX_REQUESTED_BUNDLE_BALANCES + 1],
    ] {
        assert!(matches!(
            verify_witnessed_bundle_balances_for(b"bad", &anchor, &request(), &values, None),
            Err(WitnessBundleError::Request(_))
        ));
    }
    let maximum: Vec<_> = (0..MAX_REQUESTED_BUNDLE_BALANCES)
        .map(|i| balance(i as u128, 1, None))
        .collect();
    assert!(validate_balance_expectations(&maximum).is_ok());
    assert!(
        validate_balance_expectations(&[balance(10, 1, None), balance(10, 1, Some(i32::MAX))])
            .is_ok()
    );
}

#[test]
fn malformed_balance_or_failed_receipt_never_gets_successful_request_grades() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let wanted = balance(10, 1, None);
    let good = proof(
        &anchor.signed_checkpoint().checkpoint,
        wanted,
        crate::balance::BALANCE_FORMAT,
    );
    let mut malformed = good.clone();
    malformed.pop();
    for bytes in [
        bundle(&cp, &[malformed], true),
        bundle(&cp, &[b"unknown format".to_vec()], true),
    ] {
        let result =
            verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &[wanted], None)
                .unwrap();
        assert!(!result.verified());
        assert!(matches!(
            grade(&result, "requested_balance_set"),
            Grade::Unrun(_)
        ));
    }
    let bytes = bundle(&cp, &[good], true);
    let result = verify_witnessed_bundle_balances_for(
        &bytes,
        &anchor,
        &request(),
        &[wanted],
        Some(b"invalid optional receipt"),
    )
    .unwrap();
    assert!(matches!(
        grade(&result, "requested_balance_set"),
        Grade::Unrun(_)
    ));
}

#[test]
fn stripping_witness_signatures_cannot_make_exact_balance_requests_green() {
    let cp = vector("advance", "empty");
    let anchor = pin(&cp);
    let id = signer_key_id(&key("publisher"));
    let row = cp[218..]
        .as_chunks::<102>()
        .0
        .iter()
        .find(|row| row[..32] == id)
        .unwrap();
    let mut stripped = cp[..214].to_vec();
    stripped.extend_from_slice(&1u32.to_le_bytes());
    stripped.extend_from_slice(row);
    let bytes = bundle(&stripped, &[], true);
    let result =
        verify_witnessed_bundle_balances_for(&bytes, &anchor, &request(), &[], None).unwrap();
    assert!(matches!(
        grade(&result, "witnessed_checkpoint_binding"),
        Grade::Fail(_)
    ));
    assert!(matches!(
        grade(&result, "requested_balance_set"),
        Grade::Unrun(_)
    ));
    assert_eq!(
        result.manifest.completeness,
        Completeness::SeqRangeComplete { from: 0, to: 0 }
    );
}
