//! Public offline verification of independently encoded, genuinely signed
//! external-feed fixtures. No producer crate, fake checkpoint authenticator,
//! signing dependency or private report-fold entry point is used here.
//!
//! The deterministic PUBLIC TEST signer seed is 32 copies of byte 71. Fixtures
//! encode Cash D100/C40 and Equity C60 in one reviewed Workpaper; hostile
//! variants recompute all public commitments and checkpoint signatures.

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
