//! Native prefix verification reports, with payload assurance kept explicit.

use fa_verify::proof::production::derivation::verify_prefix_with_status;
use fa_verify::{Checkpoint, RecordCheck};

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
    report.checks.extend([
        "complete_prefix",
        "journal_order",
        "recorded_coordinates",
    ]);
    if complete {
        report.checks.extend(["record_recomputation", "scope_derivation"]);
    }
    report.data = object([
        ("envelopes", prefix.envelopes.len().to_string()),
        ("record_check", quote(if complete { "recomputed" } else { "not_supplied" })),
        (
            "scope_derivation",
            quote(if complete { "all_prefix_payloads_checked" } else { "not_verified" }),
        ),
    ]);
    report.detail = if complete {
        format!(
            "all {} leaf envelopes in journal order; every entry payload and scope selector was recomputed; no accounting-validity or posted-balance claim",
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
