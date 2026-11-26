//! Public offline verification of independently encoded, genuinely signed
//! external-feed fixtures. No producer crate, fake checkpoint authenticator,
//! signing dependency or private report-fold entry point is used here.
//!
//! The deterministic PUBLIC TEST signer seed is 32 copies of byte 71. Fixtures
//! encode Cash D100/C40 and Equity C60 in one reviewed Workpaper; hostile
//! variants recompute all public commitments and checkpoint signatures.

#![forbid(unsafe_code)]

use fa_verify::report::{
    ExternalFeedRequest, verify_report_expected, verify_report_external_feed_expected,
};

const KEY: &str = include_str!("external_feed/key.hex");
const ANCHOR: &str = include_str!("external_feed/checkpoint.hex");
const VALID: &str = include_str!("external_feed/valid.bundle.hex");
const VALID_DIGEST: &str = include_str!("external_feed/valid.digest");

fn unhex(text: &str) -> Vec<u8> {
    let bytes: Vec<_> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixed(text: &str) -> [u8; 32] {
    unhex(text).try_into().unwrap()
}

fn question() -> ExternalFeedRequest {
    ExternalFeedRequest {
        feed: "ERP:AR".into(),
        control_account: fa_verify::ads::account_vid(&[3; 16], "1000"),
        effective_through: 20,
        known_at: 5,
    }
}

fn refusal(bundle: &str, digest: &str) -> &'static str {
    verify_report_external_feed_expected(
        &unhex(bundle),
        &[fixed(KEY)],
        None,
        None,
        &question(),
        Some(&fixed(digest)),
    )
    .unwrap_err()
    .predicate
}

#[test]
fn external_feed_public_signed_round_trip_reconstructs_original_review_and_gross_detail() {
    let key = fixed(KEY);
    let checkpoint = fa_verify::verify_checkpoint(&unhex(ANCHOR), &[key]).unwrap();
    let verified = verify_report_external_feed_expected(
        &unhex(VALID),
        &[key],
        Some(&checkpoint.checkpoint),
        None,
        &question(),
        Some(&fixed(VALID_DIGEST)),
    )
    .unwrap();
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert_eq!(verified.checked_records, 5);
    let report = verified.external_feed.unwrap();
    assert_eq!(report.feed, "ERP:AR");
    assert_eq!(report.known_at, 5);
    assert_eq!(report.batches.len(), 1);
    assert_eq!(report.batches[0].reviewer, 8);
    assert_eq!(report.batches[0].detail_rows, 3);
    assert_eq!(report.contributions.len(), 1);
    assert!(report.unattributed.is_empty());
    assert_eq!(
        (report.rows[0].detail_debits, report.rows[0].detail_credits),
        (100, 40)
    );
    assert_eq!(
        (
            report.rows[0].control_debits,
            report.rows[0].control_credits
        ),
        (100, 40)
    );
    assert_eq!(
        (
            report.totals[0].register_debits,
            report.totals[0].register_credits
        ),
        (100, 40)
    );
    assert!(report.reconciled);
}

#[test]
fn external_feed_public_rejects_resealed_equal_net_source_substitution() {
    assert_eq!(
        refusal(
            include_str!("external_feed/same-net-gross-edit.bundle.hex"),
            include_str!("external_feed/same-net-gross-edit.digest"),
        ),
        "external_feed_source"
    );
}

#[test]
fn external_feed_public_requires_original_distinct_review_at_the_selected_prefix() {
    for (bundle, digest) in [
        (
            include_str!("external_feed/late-review.bundle.hex"),
            include_str!("external_feed/late-review.digest"),
        ),
        (
            include_str!("external_feed/self-review.bundle.hex"),
            include_str!("external_feed/self-review.digest"),
        ),
    ] {
        assert_eq!(refusal(bundle, digest), "external_feed_source");
    }
}

#[test]
fn external_feed_public_rejects_resealed_output_and_missing_registry() {
    assert_eq!(
        refusal(
            include_str!("external_feed/wrong-output.bundle.hex"),
            include_str!("external_feed/wrong-output.digest"),
        ),
        "report_recomputation"
    );
    assert_eq!(
        refusal(
            include_str!("external_feed/missing-registry.bundle.hex"),
            include_str!("external_feed/missing-registry.digest"),
        ),
        "registry_closure"
    );
}

#[test]
fn external_feed_public_requires_an_independent_question_and_outer_input_authority() {
    let bundle = unhex(VALID);
    let key = fixed(KEY);
    let digest = fixed(VALID_DIGEST);
    let expected = question();
    assert_eq!(
        verify_report_expected(&bundle, &[key], None, None, Some(&digest))
            .unwrap_err()
            .predicate,
        "external_feed_request"
    );
    assert_eq!(
        verify_report_external_feed_expected(&bundle, &[key], None, None, &expected, None)
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );
    for changed in [
        ExternalFeedRequest {
            feed: "ERP:AP".into(),
            ..expected.clone()
        },
        ExternalFeedRequest {
            control_account: fa_verify::ads::account_vid(&[3; 16], "3000"),
            ..expected.clone()
        },
        ExternalFeedRequest {
            effective_through: 19,
            ..expected.clone()
        },
        ExternalFeedRequest {
            known_at: 4,
            ..expected.clone()
        },
    ] {
        assert_eq!(
            verify_report_external_feed_expected(
                &bundle,
                &[key],
                None,
                None,
                &changed,
                Some(&digest)
            )
            .unwrap_err()
            .predicate,
            "external_feed_request"
        );
    }
}

#[test]
fn external_feed_public_cli_names_verified_and_unjudged_claims() {
    let args = [
        "report".into(),
        "bundle".into(),
        "--key".into(),
        KEY.trim().into(),
        "--checkpoint".into(),
        "checkpoint".into(),
        "--expect".into(),
        VALID_DIGEST.trim().into(),
        "--external-feed".into(),
        "ERP:AR".into(),
        "--control-account".into(),
        question().control_account.to_string(),
        "--through".into(),
        "20".into(),
        "--known-at".into(),
        "5".into(),
        "--json".into(),
    ];
    let result = fa_verify::cli::run(&args, &|path| match path {
        "bundle" => Ok(unhex(VALID)),
        "checkpoint" => Ok(unhex(ANCHOR)),
        _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, path)),
    });
    assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    for claim in [
        "\"report_mode\":\"external_feed_reconciliation\"",
        "\"review_citations\":\"authenticated_journal_at_summary_birth\"",
        "\"native_graph_mirrors\":\"not_judged\"",
        "\"source_system_completeness\":\"not_judged\"",
        "\"human_review_independence\":\"not_judged\"",
    ] {
        assert!(result.stdout.contains(claim), "{claim}: {}", result.stdout);
    }
}

/// Reuse the existing eight canonical registry documents verbatim. The new
/// compact fixture contains the complete replacement certificate, signed
/// checkpoint, prefix and record payloads, ending after migration witnesses.
fn attach_existing_registries(mut head: Vec<u8>) -> Vec<u8> {
    fn count(bytes: &[u8], at: &mut usize) -> usize {
        let value = u32::from_le_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
        *at += 4;
        value
    }
    fn skip_frame(bytes: &[u8], at: &mut usize) {
        let length = count(bytes, at);
        *at += length;
        assert!(*at <= bytes.len());
    }
    let original = unhex(VALID);
    let mut at = 0;
    skip_frame(&original, &mut at); // Bundle format.
    at += 4; // Bundle major/minor.
    for _ in 0..3 {
        skip_frame(&original, &mut at); // Certificate, checkpoint and prefix.
    }
    for _ in 0..count(&original, &mut at) {
        at += 4; // Record proposal length.
        skip_frame(&original, &mut at);
    }
    assert_eq!(count(&original, &mut at), 0); // Migration witnesses.
    head.extend_from_slice(&original[at..]);
    head
}

#[test]
fn external_feed_public_accepts_atomic_reversal_before_its_target_leaf() {
    let bundle = attach_existing_registries(unhex(include_str!(
        "external_feed/same-commit-reversal.head.hex"
    )));
    let digest = fixed(include_str!("external_feed/same-commit-reversal.digest"));
    let verified = verify_report_external_feed_expected(
        &bundle,
        &[fixed(KEY)],
        None,
        None,
        &question(),
        Some(&digest),
    )
    .unwrap();
    assert_eq!(verified.checked_records, 6);
    assert_eq!(verified.checkpoint.checkpoint.through_seq, 5);
    assert_eq!(verified.checkpoint.checkpoint.leaf_count, 6);
    let report = verified.external_feed.unwrap();
    assert!(report.reconciled);
    assert_eq!(report.batches.len(), 1);
    assert_eq!(report.batches[0].recorded_at, 5);
    assert_eq!(report.contributions.len(), 2);
    let reversal = &report.contributions[0];
    let original = &report.contributions[1];
    assert!(reversal.reversed);
    assert!(!original.reversed);
    assert!(reversal.entry < original.entry);
    assert_eq!(reversal.source, original.entry);
    assert_eq!(reversal.source_digest, original.entry_digest);
    assert_eq!((reversal.recorded_at, original.recorded_at), (5, 5));
    assert_eq!(report.batches[0].entry, original.entry);
    assert!(report.unattributed.is_empty());
    assert_eq!(
        (
            report.totals[0].detail_debits,
            report.totals[0].detail_credits
        ),
        (140, 140)
    );
    assert_eq!(
        (
            report.totals[0].control_debits,
            report.totals[0].control_credits
        ),
        (140, 140)
    );
    assert_eq!(
        (
            report.totals[0].register_debits,
            report.totals[0].register_credits
        ),
        (140, 140)
    );
}

const MANIFEST: &str = concat!(
    "fa:external-feed-population:v1\n",
    "03030303030303030303030303030303 ERP:AR extract-1 10 20 3\n",
    "child batch-1 90e026c4b6367161fc9b8d5681f00d09c0d6eabcce3dad67ac8f2292a53a03a7\n",
    "cell 5706e80e281fc21c8fd6647d5ccb5a06 0 - 100 40\n",
    "cell a9aee1fc6b7f3cbc8738d312e5c540c5 0 - 0 60\n",
);

fn population_result(
    manifest: &str,
    bundle: &[u8],
    digest: &str,
    hex_bundle: bool,
) -> fa_verify::cli::Output {
    let mut args = vec![
        "report".into(),
        "bundle".into(),
        "--key".into(),
        KEY.trim().into(),
        "--expect".into(),
        digest.trim().into(),
        "--external-feed".into(),
        "ERP:AR".into(),
        "--control-account".into(),
        question().control_account.to_string(),
        "--through".into(),
        "20".into(),
        "--known-at".into(),
        "5".into(),
        "--population-manifest".into(),
        "source.manifest".into(),
        "--json".into(),
    ];
    if hex_bundle {
        args.push("--hex".into());
    }
    fa_verify::cli::run(&args, &|path| match path {
        "bundle" => Ok(bundle.to_vec()),
        "source.manifest" => Ok(manifest.as_bytes().to_vec()),
        _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, path)),
    })
}

#[test]
fn external_feed_cli_compares_a_recipient_manifest_with_original_source_deliveries() {
    // Independently pinned declarations for the signed fixture, including its
    // non-control Equity leg. The manifest remains plain text with --hex.
    let valid = population_result(MANIFEST, VALID.as_bytes(), VALID_DIGEST, true);
    assert_eq!(valid.exit, 0, "{}{}", valid.stdout, valid.stderr);
    assert!(
        valid
            .stdout
            .contains("\"check\":\"external_feed_population\"")
    );

    for (manifest, reason) in [
        (
            MANIFEST.replace("child batch-1", "child batch-2"),
            "undeclared child",
        ),
        (
            format!("{MANIFEST}child batch-2 {}\n", "ab".repeat(32)),
            "missing child",
        ),
        (MANIFEST.replace("90e026c4", "91e026c4"), "Workpaper OID"),
        (MANIFEST.replace("100 40", "101 41"), "gross mismatch"),
        (MANIFEST.replace("10 20 3", "10 20 2"), "source rows"),
        (MANIFEST.replace(" 0 - 0 60", " 1 - 0 60"), "gross mismatch"),
    ] {
        let result = population_result(&manifest, VALID.as_bytes(), VALID_DIGEST, true);
        assert_eq!(result.exit, 8, "{}{}", result.stdout, result.stderr);
        assert!(
            result
                .stdout
                .contains("\"check\":\"external_feed_population\"")
        );
        assert!(result.stdout.contains(reason), "{}", result.stdout);
    }
}

#[test]
fn external_feed_cli_selects_source_batches_by_inclusive_effective_window() {
    // The only source batch is effective on day 10. An empty population
    // declaration is true after that date and false on the boundary itself.
    let empty = concat!(
        "fa:external-feed-population:v1\n",
        "03030303030303030303030303030303 ERP:AR extract-empty 11 20 0\n",
    );
    let after = population_result(empty, VALID.as_bytes(), VALID_DIGEST, true);
    assert_eq!(after.exit, 0, "{}{}", after.stdout, after.stderr);
    let at = population_result(
        &empty.replace("11 20", "10 20"),
        VALID.as_bytes(),
        VALID_DIGEST,
        true,
    );
    assert_eq!(at.exit, 8, "{}{}", at.stdout, at.stderr);
    assert!(at.stdout.contains("undeclared child"));
}

#[test]
fn external_feed_cli_counts_an_atomic_reversal_as_one_original_source_delivery() {
    let bundle = attach_existing_registries(unhex(include_str!(
        "external_feed/same-commit-reversal.head.hex"
    )));
    let digest = include_str!("external_feed/same-commit-reversal.digest");
    // One three-row delivery still has gross 100/40 in Cash even though the
    // proved posting and reversal together have register turnover 140/140.
    let result = population_result(MANIFEST, &bundle, digest, false);
    assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    assert!(
        result
            .stdout
            .contains("\"check\":\"external_feed_population\"")
    );
    let turnover = MANIFEST.replace("100 40", "140 140");
    let wrong = population_result(&turnover, &bundle, digest, false);
    assert_eq!(wrong.exit, 8, "{}{}", wrong.stdout, wrong.stderr);
    assert!(wrong.stdout.contains("gross mismatch"));
}
