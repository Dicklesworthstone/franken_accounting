//! Native prefix verification reports, with payload assurance kept explicit.

use fa_verify::proof::production::derivation::verify_prefix_with_status;
use fa_verify::{Checkpoint, RecordCheck, verify_attestation_signatures};

use crate::{Failure, Report, object, quote};

pub(super) fn verify(
    proof: &[u8],
    checkpoint: &Checkpoint,
    report: &mut Report,
) -> Result<(), Failure> {
    let verified = verify_prefix_with_status(proof, checkpoint)?;
    let complete = verified.record_check == RecordCheck::Recomputed;
    let prefix = verified.prefix;
    report.scope = prefix.scope;
    report
        .checks
        .extend(["complete_prefix", "journal_order", "recorded_coordinates"]);
    // A complete prefix also re-checks every attestation signature against
    // the key chains it holds (plan §14.5, fa-kae).
    let signatures = if complete {
        report
            .checks
            .extend(["record_recomputation", "scope_derivation"]);
        let signatures =
            verify_attestation_signatures(proof, checkpoint)?.map_err(Failure::verification)?;
        report.checks.push("attestation_signatures");
        object([
            ("attestations", signatures.attestations.to_string()),
            ("key_generations", signatures.key_generations.to_string()),
            ("keyed_principals", signatures.keyed_principals.to_string()),
            ("signed", signatures.signed.to_string()),
        ])
    } else {
        quote("not_verified")
    };
    report.data = object([
        ("attestation_signatures", signatures),
        ("envelopes", prefix.envelopes.len().to_string()),
        (
            "record_check",
            quote(if complete {
                "recomputed"
            } else {
                "not_supplied"
            }),
        ),
        (
            "scope_derivation",
            quote(if complete {
                "all_prefix_payloads_checked"
            } else {
                "not_verified"
            }),
        ),
    ]);
    report.detail = if complete {
        format!(
            "all {} leaf envelopes in journal order; every entry payload and scope selector was recomputed; every attestation signature matched its principal's then-current key; no accounting-validity or posted-balance claim",
            prefix.envelopes.len()
        )
    } else {
        format!(
            "all {} leaf envelopes in journal order; payloads were not recomputed; selector derivation was not verified",
            prefix.envelopes.len()
        )
    };
    Ok(())
}
