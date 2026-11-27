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
    manifest: impl AsRef<[u8]>,
    bundle: &[u8],
    digest: &str,
    hex_bundle: bool,
) -> fa_verify::cli::Output {
    manifest_result(
        manifest,
        bundle,
        digest,
        hex_bundle,
        "--population-manifest",
    )
}

fn manifest_result(
    manifest: impl AsRef<[u8]>,
    bundle: &[u8],
    digest: &str,
    hex_bundle: bool,
    option: &str,
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
        option.into(),
        "source.manifest".into(),
        "--json".into(),
    ];
    if hex_bundle {
        args.push("--hex".into());
    }
    fa_verify::cli::run(&args, &|path| match path {
        "bundle" => Ok(bundle.to_vec()),
        "source.manifest" => Ok(manifest.as_ref().to_vec()),
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

fn workpaper_header(rows: u64) -> fa_verify::codec::Writer {
    let mut w = fa_verify::codec::Writer::default();
    w.fixed(b"fa:external-feed-manifest:v1")
        .fixed(&[3; 16])
        .bytes(b"ERP:AR")
        .bytes(b"extract-1")
        .i32(10)
        .i32(20)
        .u64(rows);
    w
}

fn workpaper(commit: [u8; 32], rows: u64, debit: i128) -> Vec<u8> {
    let mut w = workpaper_header(rows);
    w.count(1)
        .bytes(b"batch-1")
        .fixed(&commit)
        .count(2)
        .u128(0x5706e80e281fc21c8fd6647d5ccb5a06)
        .u32(0)
        .count(0)
        .i128(debit)
        .i128(40)
        .u128(0xa9aee1fc6b7f3cbc8738d312e5c540c5)
        .u32(0)
        .count(0)
        .i128(0)
        .i128(60);
    w.buf
}

#[test]
fn external_feed_cli_verifies_native_source_workpaper_and_distinguishes_commitments_from_oids() {
    let commit = fixed("007c73d2365a9465bb0874d13e8ce3cf6a2e2c592d9a57838a4be17bea9d6f10");
    let check = |bytes: &[u8]| population_result(bytes, VALID.as_bytes(), VALID_DIGEST, true);
    let bytes = workpaper(commit, 3, 100);
    let verified = check(&bytes);
    assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
    assert!(
        verified
            .stdout
            .contains("\"check\":\"external_feed_population\"")
    );
    // The document OID is valid for the text form but is not the Workpaper's
    // raw commitment, even though each occupies exactly 32 bytes.
    let oid = fixed("90e026c4b6367161fc9b8d5681f00d09c0d6eabcce3dad67ac8f2292a53a03a7");
    for (changed, reason) in [
        (workpaper(oid, 3, 100), "Workpaper OID"),
        (workpaper(commit, 2, 100), "source rows"),
        (workpaper(commit, 3, 101), "gross mismatch"),
    ] {
        let result = check(&changed);
        assert_eq!(result.exit, 8, "{}{}", result.stdout, result.stderr);
        assert!(result.stdout.contains(reason), "{}", result.stdout);
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut unsorted = bytes.clone();
    let cell_bytes = 56;
    let start = unsorted.len() - 2 * cell_bytes;
    unsorted[start..].rotate_left(cell_bytes);
    let mut duplicate = workpaper_header(3);
    duplicate.count(2);
    for _ in 0..2 {
        duplicate.bytes(b"batch-1").fixed(&commit);
    }
    duplicate.count(0);
    let mut kinds = bytes.clone();
    // First total starts with account (16), unit (4), dimension count (4).
    let count_at = start + 20;
    kinds[count_at..count_at + 4].copy_from_slice(&2u32.to_le_bytes());
    let mut dimensions = fa_verify::codec::Writer::default();
    dimensions.u32(7).u128(5).u32(7).u128(6);
    kinds.splice(count_at + 4..count_at + 4, dimensions.buf);
    let mut oversized = bytes.clone();
    oversized.resize(1024 * 1024 + 1, 0);
    for malformed in [
        trailing,
        bytes[..bytes.len() - 1].to_vec(),
        kinds,
        oversized,
        unsorted,
        duplicate.buf,
        workpaper([0; 32], 3, 100),
        workpaper(commit, 129, 100),
        workpaper(commit, 3, -1),
    ] {
        let result = check(&malformed);
        assert_eq!(result.exit, 2, "{}{}", result.stdout, result.stderr);
    }
}

#[test]
fn signed_prefix_authenticates_the_exact_parent_and_distinct_review_at_its_ordinal() {
    // The public test signer commits to two additional leaves of sequence 5.
    // The report, registry closure, certificate digest and child stay identical.
    let bundle = attach_existing_registries(unhex(include_str!(
        "external_feed/reviewed-parent.head.hex"
    )));
    let commit = fixed("007c73d2365a9465bb0874d13e8ce3cf6a2e2c592d9a57838a4be17bea9d6f10");
    let bytes = workpaper(commit, 3, 100);
    let reviewed = |manifest: &[u8], bundle: &[u8]| {
        manifest_result(
            manifest,
            bundle,
            VALID_DIGEST,
            false,
            "--reviewed-population-manifest",
        )
    };
    let valid = reviewed(&bytes, &bundle);
    assert_eq!(valid.exit, 0, "{}{}", valid.stdout, valid.stderr);
    for evidence in [
        r#""check":"external_feed_manifest_review""#,
        "92c859af5fc5dafcec7c82cbaa3d4fbb4b26fd07803d0d2ea51d81dc830edfd7",
        r#""intake_ordinal":1"#,
        r#""review_ordinal":2"#,
        r#""received_by":"00000000000000000000000000000007""#,
        r#""reviewed_by":"00000000000000000000000000000008""#,
    ] {
        assert!(valid.stdout.contains(evidence), "{}", valid.stdout);
    }
    let no_parent = reviewed(&bytes, &unhex(VALID));
    assert_eq!(no_parent.exit, 8, "{}", no_parent.stdout);
    assert!(no_parent.stdout.contains("external_feed_manifest_review"));
    let mut renamed = bytes.clone();
    let i = renamed
        .windows(9)
        .position(|label| label == b"extract-1")
        .unwrap();
    renamed[i] = b'E';
    assert_eq!(
        population_result(&renamed, &bundle, VALID_DIGEST, false).exit,
        0
    );
    let changed = reviewed(&renamed, &bundle);
    assert_eq!(changed.exit, 8, "{}", changed.stdout);
    assert!(changed.stdout.contains("external_feed_manifest_review"));
    let mismatched = reviewed(&workpaper(commit, 3, 101), &bundle);
    assert_eq!(mismatched.exit, 8, "{}", mismatched.stdout);
    assert!(mismatched.stdout.contains("external_feed_population"));
    assert_eq!(reviewed(MANIFEST.as_bytes(), &bundle).exit, 2);
}
