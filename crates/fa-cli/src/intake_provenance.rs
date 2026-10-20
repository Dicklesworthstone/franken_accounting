//! Public intake assertions are checked before any source bytes are consumed.
//!
//! A launch-bound request supplies uploads, not authenticated connector, mail
//! or scanner transcripts. The explicit embedded-owner import path remains a
//! separate posture. The kernel still checks authority and provenance again
//! when it publishes the run; none of these checks reserves authority.

use fa_journal::Capability;
use fa_journal::refusal::{Refusal, code, exit};
use fa_model::IntakeSource;
use fa_registry::evidence_policy::EvidencePolicy;

use crate::cli::{Fail, usage};

fn invalid(message: impl Into<String>) -> Fail {
    Fail::Refusal(Refusal::new(
        code::DOCUMENT_INTAKE,
        exit::USAGE,
        message,
        "plan §9.1–§9.3; bounded evidence intake metadata",
        "supply bounded metadata before retrying; no evidence or import receipt was recorded",
    ))
}

pub(crate) fn check_mime(policy: &EvidencePolicy, mime: &str) -> Result<(), Fail> {
    if mime.is_empty() || mime.len() > policy.max_mime_bytes {
        return Err(invalid(format!(
            "document MIME type must contain 1..={} bytes",
            policy.max_mime_bytes,
        )));
    }
    Ok(())
}

pub(crate) fn check_import_header(key: Option<&str>, description: &str) -> Result<(), Fail> {
    if key.is_some_and(|key| {
        key.is_empty() || key.len() > fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES
    }) {
        return Err(invalid(format!(
            "import idempotency key must contain 1..={} bytes",
            fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES,
        )));
    }
    if description.len() > fa_model::limits::MAX_DESCRIPTION_BYTES {
        return Err(invalid(format!(
            "import description exceeds {} bytes",
            fa_model::limits::MAX_DESCRIPTION_BYTES,
        )));
    }
    Ok(())
}

/// The same profile-to-grade function used by the upload kernel. A grade flag
/// is only an assertion, never an override or a way to relabel held evidence.
pub(crate) fn session_import(
    policy: &EvidencePolicy,
    capability: &Capability,
    asserted_source: Option<&str>,
    asserted_grade: Option<u8>,
) -> Result<(IntakeSource, u8), Fail> {
    if !matches!(asserted_source, None | Some("Upload")) {
        return Err(usage(
            "launch-bound evidence imports are uploads; --source cannot assert connector, email or scanner provenance",
            "omit --source or use --source Upload; verified connector intake requires its own authenticated adapter",
        ));
    }
    let grade = fa_journal::upload::upload_grade(policy, capability.sod_profile())
        .map_err(fa::BookError::Kernel)?;
    if asserted_grade.is_some_and(|asserted| asserted != grade) {
        return Err(Fail::Refusal(Refusal::new(
            code::GRADE_UNVERIFIED,
            exit::REFUSAL,
            "import provenance assertion differs from the session's upload grade",
            "plan §9.3; FA-INV-05; fa-vwf",
            "omit --grade; independent review is an attestation, not an intake relabel",
        )));
    }
    Ok((
        IntakeSource::Upload {
            principal: capability.holder(),
        },
        grade,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_policy::{Op, Profile};
    use fgdb_types::VId;

    #[test]
    fn source_and_grade_are_bound_to_the_profile_not_caller_labels() {
        let policy = EvidencePolicy::embedded().unwrap();
        for profile in [Profile::Human, Profile::Agent, Profile::System] {
            let capability = Capability::new(VId(501), profile, &[Op::Post], VId(1)).unwrap();
            let expected = fa_journal::upload::upload_grade(&policy, profile).unwrap();
            for source in [None, Some("Upload")] {
                let result = session_import(&policy, &capability, source, Some(expected));
                assert!(matches!(result,
                    Ok((IntakeSource::Upload { principal: VId(501) }, grade)) if grade == expected
                ));
            }
            for source in [
                "Connector",
                "Connector:fa-import:1",
                "Email:message",
                "Scan:scanner",
            ] {
                assert!(matches!(
                    session_import(&policy, &capability, Some(source), None),
                    Err(Fail::Usage(_))
                ));
            }
            for grade in &policy.grades {
                if grade.tag != expected {
                    assert!(matches!(
                        session_import(&policy, &capability, None, Some(grade.tag)),
                        Err(Fail::Refusal(_))
                    ));
                }
            }
        }
    }

    #[test]
    fn input_header_bounds_count_bytes_and_allow_content_derived_keys() {
        let policy = EvidencePolicy::embedded().unwrap();
        assert!(check_mime(&policy, "application/octet-stream").is_ok());
        assert!(check_mime(&policy, "").is_err());
        assert!(check_mime(&policy, &"m".repeat(policy.max_mime_bytes)).is_ok());
        assert!(check_mime(&policy, &"m".repeat(policy.max_mime_bytes + 1)).is_err());
        assert!(check_import_header(None, "").is_ok());
        assert!(check_import_header(Some(""), "").is_err());
        let key = "k".repeat(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES);
        let description = "d".repeat(fa_model::limits::MAX_DESCRIPTION_BYTES);
        assert!(check_import_header(Some(&key), &description).is_ok());
        assert!(check_import_header(Some(&(key + "x")), "").is_err());
        assert!(check_import_header(None, &(description + "x")).is_err());
        // Multi-byte text must not bypass an encoded-byte boundary.
        let key = "é".repeat(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES);
        assert!(check_import_header(Some(&key), "").is_err());
    }
}
