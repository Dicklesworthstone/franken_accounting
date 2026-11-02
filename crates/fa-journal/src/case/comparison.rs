//! The posting kernel's bounded artifact-to-Post binding.
//!
//! These are the native/functional built-in and custom statement-diff v1
//! containers and their exact v4/v5 or v11/v12 source headers
//! (`fa::statement_diff::certificate` and
//! `fa::certificate`). The kernel needs no upward dependency on report folds:
//! it checks the complete outer digest, the two identical statement questions,
//! their valuation measure, and the exact Post frontier. Native proof payloads,
//! statement definitions and amount vectors remain opaque here. Retention and
//! the facade must independently replay those contents and establish the case's
//! complete expected question set before this token is used in a transaction.

use fa_model::{DecodeError, Id128, Reader, domain_digest};
use fgdb_types::CommitSeq;

use super::{DisclosurePost, comparison_refused};
use crate::Refusal;

const NATIVE_FORMAT: &[u8] = b"fa:statement-diff-certificate:v1";
const FUNCTIONAL_FORMAT: &[u8] = b"fa:functional-statement-diff-certificate:v1";
const CUSTOM_FORMAT: &[u8] = b"fa:custom-statement-diff-certificate:v1";
const FUNCTIONAL_CUSTOM_FORMAT: &[u8] = b"fa:functional-custom-statement-diff-certificate:v1";
const NATIVE_DOMAIN: &[u8] = b"fa:statement-diff-certificate-digest:v1";
const FUNCTIONAL_DOMAIN: &[u8] = b"fa:functional-statement-diff-certificate-digest:v1";
const CUSTOM_DOMAIN: &[u8] = b"fa:custom-statement-diff-certificate-digest:v1";
const FUNCTIONAL_CUSTOM_DOMAIN: &[u8] =
    b"fa:functional-custom-statement-diff-certificate-digest:v1";
const NATIVE_SOURCE: &[u8] = b"fa:report-certificate:v4";
const FUNCTIONAL_SOURCE: &[u8] = b"fa:report-certificate:v5";
const CUSTOM_SOURCE: &[u8] = b"fa:report-certificate:v11";
const FUNCTIONAL_CUSTOM_SOURCE: &[u8] = b"fa:report-certificate:v12";
const PRESENTATION_SPEC: &[u8] = b"fa:presentation-rounding-spec:v1";
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_DEFINITION_BYTES: usize = 64 * 1024;
const MAX_PERIODS: usize = 65_536;
const MAX_NATIVE_BYTES: usize = 1024 * 1024;

/// A content-addressed comparison whose two source headers bind one statement
/// question to this book's exact case Post. This is not a replay-success or
/// case-question-completeness claim. Only the pure bounded validator can create
/// a token; the journal still witnesses its retained root inside the commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDisclosureComparison {
    book: Id128,
    post: DisclosurePost,
    digest: [u8; 32],
}

impl ValidatedDisclosureComparison {
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn matches(&self, book: Id128, post: DisclosurePost) -> bool {
        self.book == book && self.post == post
    }
}

struct Source<'a> {
    book: Id128,
    branch: Id128,
    at: CommitSeq,
    selection: &'a [u8],
}

fn periods(r: &mut Reader<'_>, required: bool) -> Result<(), DecodeError> {
    let count = r.count(MAX_PERIODS, "statement periods")?;
    if required && count == 0 {
        return Err(r.invalid("nonempty statement periods"));
    }
    let mut prior = None;
    for _ in 0..count {
        let period = r.str(128, "statement period")?;
        if period.is_empty() || prior.is_some_and(|prior| prior >= period) {
            return Err(r.invalid("sorted distinct statement periods"));
        }
        prior = Some(period);
    }
    Ok(())
}

fn presentation(bytes: &[u8]) -> Result<(), DecodeError> {
    let mut r = Reader::new(bytes);
    if r.fixed::<{ PRESENTATION_SPEC.len() }>("presentation format")? != PRESENTATION_SPEC {
        return Err(r.invalid("presentation rounding specification format"));
    }
    if fa_money::RoundingLaw::from_id(r.u16("presentation rounding law")?).is_none()
        || r.u8("presentation scale reduction")? > 38
    {
        return Err(r.invalid("registered presentation rounding law and bounded scale"));
    }
    let code = r.str(64, "presentation residual code")?;
    if code.is_empty()
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || r.str(256, "presentation residual label")?.trim().is_empty()
    {
        return Err(r.invalid("presentation residual identity"));
    }
    r.finish()
}

fn source(bytes: &[u8], functional: bool, custom: bool) -> Result<Source<'_>, DecodeError> {
    let mut r = Reader::new(bytes);
    let expected = match (functional, custom) {
        (false, false) => NATIVE_SOURCE,
        (true, false) => FUNCTIONAL_SOURCE,
        (false, true) => CUSTOM_SOURCE,
        (true, true) => FUNCTIONAL_CUSTOM_SOURCE,
    };
    let source_format_matches = if custom {
        r.fixed::<{ CUSTOM_SOURCE.len() }>("statement source format")? == expected
    } else {
        r.fixed::<{ NATIVE_SOURCE.len() }>("statement source format")? == expected
    };
    if !source_format_matches {
        return Err(r.invalid("statement source valuation measure"));
    }
    for (field, value) in [
        ("replay scope", "fa-fold-over-prefix"),
        ("authority", "embedded-owner"),
        (
            "statement output format",
            match (functional, custom) {
                (false, false) => "fa:statement:v1",
                (true, false) => "fa:functional-statement:v1",
                (false, true) => "fa:custom-statement-report:v1",
                (true, true) => "fa:functional-custom-statement:v1",
            },
        ),
    ] {
        if r.str(64, field)? != value {
            return Err(r.invalid(field));
        }
    }
    let book = Id128(r.fixed("statement book")?);
    let branch = Id128(r.fixed("statement branch")?);
    let at = CommitSeq(r.u64("statement frontier")?);
    let start = r.offset();
    let selector = match (functional, custom) {
        (false, false) => 2,
        (true, false) => 3,
        (false, true) => 9,
        (true, true) => 10,
    };
    if r.u8("statement selector")? != selector {
        return Err(r.invalid("statement selector valuation measure"));
    }
    if r.bytes(MAX_DEFINITION_BYTES, "statement definition")?
        .is_empty()
    {
        return Err(r.invalid("nonempty statement definition"));
    }
    if custom {
        r.u128("statement activation")?;
        let activated_at = r.u64("statement activated-at")?;
        if activated_at == 0 || activated_at > at.0 {
            return Err(r.invalid("activation at a positive commit no later than the source"));
        }
    }
    periods(&mut r, true)?;
    periods(&mut r, false)?;
    if custom {
        match r.u8("presentation rounding")? {
            0 => {}
            1 => presentation(r.bytes(1024, "presentation specification")?)?,
            _ => return Err(r.invalid("canonical presentation option")),
        }
    }
    let selection = &bytes[start..r.offset()];

    // Walk the remaining envelope without copying or interpreting proof/amount
    // payloads. In v4/v5 there are seven native input families, plus Rates for
    // functional statements. Custom sources add five activation/definition
    // input families. None admits an instant-selected source in a comparison.
    r.fixed::<32>("registry closure")?;
    r.fixed::<32>("journal root")?;
    r.u64("journal leaves")?;
    let required_inputs = 7 + usize::from(functional) + 5 * usize::from(custom);
    if r.count(required_inputs, "native inputs")? != required_inputs {
        return Err(r.invalid("complete statement input framing"));
    }
    for _ in 0..required_inputs {
        r.bytes(MAX_NATIVE_BYTES, "native input")?;
    }
    r.bytes(MAX_BYTES, "statement output")?;
    r.fixed::<32>("statement output digest")?;
    if r.u8("TimeEvidence selection")? != 0 {
        return Err(r.invalid("sequence-selected statement source"));
    }
    r.fixed::<32>("statement source digest")?;
    r.finish()?;
    Ok(Source {
        book,
        branch,
        at,
        selection,
    })
}

fn output_header(
    bytes: &[u8],
    functional: bool,
    custom: bool,
    before: &Source<'_>,
    after: &Source<'_>,
) -> Result<(), DecodeError> {
    let mut r = Reader::new(bytes);
    let format: &[u8] = match (functional, custom) {
        (false, false) => b"fa:statement-diff:v1",
        (true, false) => b"fa:functional-statement-diff:v1",
        (false, true) => b"fa:custom-statement-diff:v1",
        (true, true) => b"fa:functional-custom-statement-diff:v1",
    };
    if r.bytes(64, "comparison output format")? != format {
        return Err(r.invalid("comparison output valuation measure"));
    }
    if functional {
        r.u32("functional unit")?;
        if r.str(64, "functional valuation basis")? != "retained-base-amounts" {
            return Err(r.invalid("functional valuation basis"));
        }
    }
    if Id128(r.fixed("comparison output book")?) != before.book
        || Id128(r.fixed("comparison output branch")?) != Id128::TRUNK
        || CommitSeq(r.u64("comparison output before")?) != before.at
        || CommitSeq(r.u64("comparison output after")?) != after.at
    {
        return Err(r.invalid("comparison output coordinates"));
    }
    // Amount vectors and their source digests are checked by the report replay.
    Ok(())
}

/// Bind native/functional built-in or custom statement-diff bytes to the exact case Post
/// without storage access or allocating copies of either source certificate.
/// The returned token carries no authority to read or retain an artifact.
pub fn validate_disclosure_comparison(
    book: Id128,
    post: DisclosurePost,
    digest: [u8; 32],
    bytes: &[u8],
) -> Result<ValidatedDisclosureComparison, Refusal> {
    if bytes.len() > MAX_BYTES || post.recorded_at.0 == 0 || digest == [0; 32] {
        return Err(comparison_refused(
            "disclosure comparison exceeds its byte bound or has an empty Post/digest",
        ));
    }
    let parse = || -> Result<(), DecodeError> {
        let mut r = Reader::new(bytes);
        let format = r.bytes(64, "comparison format")?;
        let (functional, custom) = match format {
            NATIVE_FORMAT => (false, false),
            FUNCTIONAL_FORMAT => (true, false),
            CUSTOM_FORMAT => (false, true),
            FUNCTIONAL_CUSTOM_FORMAT => (true, true),
            _ => return Err(r.invalid("statement comparison family")),
        };
        r.u128("comparison producer")?;
        r.fixed::<32>("comparison capability commitment")?;
        let before = source(r.bytes(MAX_BYTES, "before source")?, functional, custom)?;
        let after = source(r.bytes(MAX_BYTES, "after source")?, functional, custom)?;
        if before.book != book
            || after.book != book
            || before.branch != Id128::TRUNK
            || after.branch != Id128::TRUNK
            || before.selection != after.selection
            || before.at >= after.at
            || after.at != post.recorded_at
        {
            return Err(r.invalid("same statement question ending at the exact case Post"));
        }
        output_header(
            r.bytes(MAX_BYTES, "comparison output")?,
            functional,
            custom,
            &before,
            &after,
        )?;
        let body_len = r.offset();
        let retained_digest = r.fixed::<32>("comparison digest")?;
        r.finish()?;
        let domain = match (functional, custom) {
            (false, false) => NATIVE_DOMAIN,
            (true, false) => FUNCTIONAL_DOMAIN,
            (false, true) => CUSTOM_DOMAIN,
            (true, true) => FUNCTIONAL_CUSTOM_DOMAIN,
        };
        if retained_digest != digest || domain_digest(domain, &[&bytes[..body_len]]) != digest {
            return Err(Reader::new(bytes).invalid("comparison content digest"));
        }
        Ok(())
    };
    parse()
        .map_err(|error| comparison_refused(format!("invalid disclosure comparison: {error}")))?;
    Ok(ValidatedDisclosureComparison { book, post, digest })
}

#[cfg(test)]
mod tests {
    use fa_model::Writer;
    use fgdb_types::VId;

    use super::*;

    const BOOK: Id128 = Id128([9; 16]);
    const POST: DisclosurePost = DisclosurePost {
        entry: VId(27),
        recorded_at: CommitSeq(30),
    };

    // These deliberately synthetic opaque proofs/definitions test only the
    // kernel's framing and binding contract. They cannot pass artifact replay
    // or retention. Facade integration tests exercise actual issued sources.
    fn framed_source(
        functional: bool,
        book: Id128,
        branch: Id128,
        at: u64,
        definition: &[u8],
        selected: &[&str],
        comparative: &[&str],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(if functional {
            FUNCTIONAL_SOURCE
        } else {
            NATIVE_SOURCE
        })
        .str("fa-fold-over-prefix")
        .str("embedded-owner")
        .str(if functional {
            "fa:functional-statement:v1"
        } else {
            "fa:statement:v1"
        })
        .fixed(&book.0)
        .fixed(&branch.0)
        .u64(at)
        .u8(if functional { 3 } else { 2 })
        .bytes(definition)
        .list(selected, |w, period| {
            w.str(period);
        })
        .list(comparative, |w, period| {
            w.str(period);
        })
        .fixed(&[1; 32])
        .fixed(&[2; 32])
        .u64(10)
        .u32(if functional { 8 } else { 7 });
        for _ in 0..if functional { 8 } else { 7 } {
            w.bytes(b"opaque native proof");
        }
        w.bytes(b"opaque report output")
            .fixed(&[3; 32])
            .u8(0)
            .fixed(&[4; 32]);
        w.finish().unwrap()
    }

    fn source_at(functional: bool, at: u64) -> Vec<u8> {
        framed_source(
            functional,
            BOOK,
            Id128::TRUNK,
            at,
            b"income",
            &["2026-02"],
            &["2026-01"],
        )
    }

    fn framed_output(functional: bool, book: Id128, before: u64, after: u64) -> Vec<u8> {
        framed_output_family(functional, false, book, before, after)
    }

    fn framed_output_family(
        functional: bool,
        custom: bool,
        book: Id128,
        before: u64,
        after: u64,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.str(match (functional, custom) {
            (false, false) => "fa:statement-diff:v1",
            (true, false) => "fa:functional-statement-diff:v1",
            (false, true) => "fa:custom-statement-diff:v1",
            (true, true) => "fa:functional-custom-statement-diff:v1",
        });
        if functional {
            w.u32(1).str("retained-base-amounts");
        }
        w.fixed(&book.0)
            .fixed(&Id128::TRUNK.0)
            .u64(before)
            .u64(after)
            .fixed(b"opaque bridge");
        w.finish().unwrap()
    }

    fn comparison(
        functional: bool,
        before: &[u8],
        after: &[u8],
        output: &[u8],
    ) -> ([u8; 32], Vec<u8>) {
        comparison_family(functional, false, before, after, output)
    }

    fn comparison_family(
        functional: bool,
        custom: bool,
        before: &[u8],
        after: &[u8],
        output: &[u8],
    ) -> ([u8; 32], Vec<u8>) {
        let mut w = Writer::new();
        w.bytes(match (functional, custom) {
            (false, false) => NATIVE_FORMAT,
            (true, false) => FUNCTIONAL_FORMAT,
            (false, true) => CUSTOM_FORMAT,
            (true, true) => FUNCTIONAL_CUSTOM_FORMAT,
        })
        .u128(101)
        .fixed(&[5; 32])
        .bytes(before)
        .bytes(after)
        .bytes(output);
        let mut bytes = w.finish().unwrap();
        let digest = domain_digest(
            match (functional, custom) {
                (false, false) => NATIVE_DOMAIN,
                (true, false) => FUNCTIONAL_DOMAIN,
                (false, true) => CUSTOM_DOMAIN,
                (true, true) => FUNCTIONAL_CUSTOM_DOMAIN,
            },
            &[&bytes],
        );
        bytes.extend_from_slice(&digest);
        (digest, bytes)
    }

    fn valid(functional: bool) -> ([u8; 32], Vec<u8>) {
        comparison(
            functional,
            &source_at(functional, 10),
            &source_at(functional, 30),
            &framed_output(functional, BOOK, 10, 30),
        )
    }

    #[derive(Clone, Copy)]
    struct CustomQuestion<'a> {
        definition: &'a [u8],
        activation: u128,
        activated_at: u64,
        selected: &'a [&'a str],
        comparative: &'a [&'a str],
        presentation: Option<&'a [u8]>,
    }

    fn custom_question(presentation: Option<&[u8]>) -> CustomQuestion<'_> {
        CustomQuestion {
            definition: b"opaque approved company layout",
            activation: 101,
            activated_at: 5,
            selected: &["2026-02"],
            comparative: &["2026-01"],
            presentation,
        }
    }

    fn presentation_spec(law: u16, digits: u8, code: &str, label: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(PRESENTATION_SPEC)
            .u16(law)
            .u8(digits)
            .str(code)
            .str(label);
        w.finish().unwrap()
    }

    fn custom_source(functional: bool, at: u64, question: CustomQuestion<'_>) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(if functional {
            FUNCTIONAL_CUSTOM_SOURCE
        } else {
            CUSTOM_SOURCE
        })
        .str("fa-fold-over-prefix")
        .str("embedded-owner")
        .str(if functional {
            "fa:functional-custom-statement:v1"
        } else {
            "fa:custom-statement-report:v1"
        })
        .fixed(&BOOK.0)
        .fixed(&Id128::TRUNK.0)
        .u64(at)
        .u8(if functional { 10 } else { 9 })
        .bytes(question.definition)
        .u128(question.activation)
        .u64(question.activated_at)
        .list(question.selected, |w, period| {
            w.str(period);
        })
        .list(question.comparative, |w, period| {
            w.str(period);
        });
        match question.presentation {
            None => {
                w.u8(0);
            }
            Some(spec) => {
                w.u8(1).bytes(spec);
            }
        }
        let inputs = 12 + u32::from(functional);
        w.fixed(&[1; 32]).fixed(&[2; 32]).u64(10).u32(inputs);
        for _ in 0..inputs {
            w.bytes(b"opaque native proof");
        }
        w.bytes(b"opaque custom report output")
            .fixed(&[3; 32])
            .u8(0)
            .fixed(&[4; 32]);
        w.finish().unwrap()
    }

    #[test]
    fn custom_native_and_functional_tokens_bind_exact_post_with_optional_presentation() {
        let spec = presentation_spec(3, 2, "rounding", "Presentation rounding");
        for functional in [false, true] {
            for presented in [None, Some(spec.as_slice())] {
                let question = custom_question(presented);
                let (digest, bytes) = comparison_family(
                    functional,
                    true,
                    &custom_source(functional, 10, question),
                    &custom_source(functional, 30, question),
                    &framed_output_family(functional, true, BOOK, 10, 30),
                );
                let token = validate_disclosure_comparison(BOOK, POST, digest, &bytes).unwrap();
                assert_eq!(token.digest(), &digest);
                assert!(token.matches(BOOK, POST));
                assert!(
                    validate_disclosure_comparison(Id128([8; 16]), POST, digest, &bytes).is_err()
                );
                assert!(
                    validate_disclosure_comparison(
                        BOOK,
                        DisclosurePost {
                            recorded_at: CommitSeq(31),
                            ..POST
                        },
                        digest,
                        &bytes,
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn custom_activation_definition_periods_and_complete_presentation_are_one_question() {
        let spec = presentation_spec(3, 2, "rounding", "Presentation rounding");
        let other_law = presentation_spec(1, 2, "rounding", "Presentation rounding");
        let other_scale = presentation_spec(3, 3, "rounding", "Presentation rounding");
        let other_code = presentation_spec(3, 2, "residual", "Presentation rounding");
        let other_label = presentation_spec(3, 2, "rounding", "Another residual label");
        let question = custom_question(Some(&spec));
        for functional in [false, true] {
            let before = custom_source(functional, 10, question);
            let output = framed_output_family(functional, true, BOOK, 10, 30);
            for changed in [
                CustomQuestion {
                    definition: b"another layout",
                    ..question
                },
                CustomQuestion {
                    activation: 102,
                    ..question
                },
                CustomQuestion {
                    activated_at: 6,
                    ..question
                },
                CustomQuestion {
                    selected: &["2026-03"],
                    ..question
                },
                CustomQuestion {
                    comparative: &[],
                    ..question
                },
                CustomQuestion {
                    presentation: None,
                    ..question
                },
                CustomQuestion {
                    presentation: Some(&other_law),
                    ..question
                },
                CustomQuestion {
                    presentation: Some(&other_scale),
                    ..question
                },
                CustomQuestion {
                    presentation: Some(&other_code),
                    ..question
                },
                CustomQuestion {
                    presentation: Some(&other_label),
                    ..question
                },
            ] {
                let (digest, bytes) = comparison_family(
                    functional,
                    true,
                    &before,
                    &custom_source(functional, 30, changed),
                    &output,
                );
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
            }
        }
    }

    #[test]
    fn custom_families_cannot_substitute_builtins_valuation_measures_or_digest_domains() {
        let question = custom_question(None);
        for functional in [false, true] {
            let before = custom_source(functional, 10, question);
            let after = custom_source(functional, 30, question);
            let output = framed_output_family(functional, true, BOOK, 10, 30);
            for changed in [
                custom_source(!functional, 30, question),
                source_at(functional, 30),
            ] {
                let (digest, bytes) =
                    comparison_family(functional, true, &before, &changed, &output);
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
            }
            let (digest, bytes) = comparison(functional, &before, &after, &output);
            assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
            for changed in [
                framed_output(functional, BOOK, 10, 30),
                framed_output_family(!functional, true, BOOK, 10, 30),
                framed_output_family(functional, true, BOOK, 11, 30),
                framed_output_family(functional, true, BOOK, 10, 31),
            ] {
                let (digest, bytes) =
                    comparison_family(functional, true, &before, &after, &changed);
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
            }
            let (digest, bytes) = comparison_family(functional, true, &before, &after, &output);
            for end in 0..bytes.len() {
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes[..end]).is_err());
            }
            for domain in [
                NATIVE_DOMAIN,
                FUNCTIONAL_DOMAIN,
                if functional {
                    CUSTOM_DOMAIN
                } else {
                    FUNCTIONAL_CUSTOM_DOMAIN
                },
            ] {
                let mut changed = bytes.clone();
                let end = changed.len() - 32;
                let wrong = domain_digest(domain, &[&changed[..end]]);
                changed[end..].copy_from_slice(&wrong);
                assert!(validate_disclosure_comparison(BOOK, POST, wrong, &changed).is_err());
            }
        }
    }

    #[test]
    fn custom_source_framing_rejects_incomplete_inputs_instants_and_invalid_presentation() {
        let spec = presentation_spec(3, 2, "rounding", "Presentation rounding");
        for functional in [false, true] {
            let question = custom_question(Some(&spec));
            let before = custom_source(functional, 10, question);
            let after = custom_source(functional, 30, question);
            let output = framed_output_family(functional, true, BOOK, 10, 30);
            let mut incomplete = after.clone();
            let first_proof = incomplete
                .windows(b"opaque native proof".len())
                .position(|window| window == b"opaque native proof")
                .unwrap();
            incomplete[first_proof - 8..first_proof - 4]
                .copy_from_slice(&(7 + u32::from(functional)).to_le_bytes());
            let mut instant = after.clone();
            let time_tag = instant.len() - 33;
            instant[time_tag] = 1;
            let mut bad_option = after;
            let presentation = bad_option
                .windows(PRESENTATION_SPEC.len())
                .position(|window| window == PRESENTATION_SPEC)
                .unwrap();
            bad_option[presentation - 5] = 2;
            for changed in [incomplete, instant, bad_option] {
                let (digest, bytes) =
                    comparison_family(functional, true, &before, &changed, &output);
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
            }
            for changed in [
                CustomQuestion {
                    activated_at: 0,
                    ..question
                },
                CustomQuestion {
                    activated_at: 11,
                    ..question
                },
                CustomQuestion {
                    selected: &[],
                    ..question
                },
                CustomQuestion {
                    selected: &["2026-02", "2026-01"],
                    ..question
                },
                CustomQuestion {
                    comparative: &["2026-01", "2026-01"],
                    ..question
                },
            ] {
                let (digest, bytes) = comparison_family(
                    functional,
                    true,
                    &custom_source(functional, 10, changed),
                    &custom_source(functional, 30, changed),
                    &output,
                );
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
            }
            let mut trailing = spec.clone();
            trailing.push(0);
            for malformed in [
                presentation_spec(0, 2, "rounding", "Residual"),
                presentation_spec(3, 39, "rounding", "Residual"),
                presentation_spec(3, 2, "", "Residual"),
                presentation_spec(3, 2, "bad code", "Residual"),
                presentation_spec(3, 2, "rounding", " "),
                Vec::new(),
                trailing,
            ] {
                let changed = custom_question(Some(&malformed));
                let (digest, bytes) = comparison_family(
                    functional,
                    true,
                    &custom_source(functional, 10, changed),
                    &custom_source(functional, 30, changed),
                    &output,
                );
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
            }
        }
    }

    #[test]
    fn native_and_functional_tokens_bind_the_exact_book_post_and_digest() {
        for functional in [false, true] {
            let (digest, bytes) = valid(functional);
            let token = validate_disclosure_comparison(BOOK, POST, digest, &bytes).unwrap();
            assert_eq!(token.digest(), &digest);
            assert!(token.matches(BOOK, POST));
            assert!(!token.matches(Id128([8; 16]), POST));
            assert!(!token.matches(
                BOOK,
                DisclosurePost {
                    entry: VId(28),
                    ..POST
                }
            ));
            assert!(!token.matches(
                BOOK,
                DisclosurePost {
                    recorded_at: CommitSeq(31),
                    ..POST
                }
            ));
        }
    }

    #[test]
    fn unrelated_report_measures_questions_and_coordinates_are_refused() {
        let native_before = source_at(false, 10);
        let native_after = source_at(false, 30);
        let output = framed_output(false, BOOK, 10, 30);
        assert!(validate_disclosure_comparison(BOOK, POST, [1; 32], &native_after).is_err());
        for after in [
            source_at(true, 30),
            framed_source(
                false,
                Id128([8; 16]),
                Id128::TRUNK,
                30,
                b"income",
                &["2026-02"],
                &["2026-01"],
            ),
            framed_source(
                false,
                BOOK,
                Id128([7; 16]),
                30,
                b"income",
                &["2026-02"],
                &["2026-01"],
            ),
            framed_source(
                false,
                BOOK,
                Id128::TRUNK,
                30,
                b"balance-sheet",
                &["2026-02"],
                &["2026-01"],
            ),
            framed_source(
                false,
                BOOK,
                Id128::TRUNK,
                30,
                b"income",
                &["2026-03"],
                &["2026-01"],
            ),
            framed_source(false, BOOK, Id128::TRUNK, 30, b"income", &["2026-02"], &[]),
            source_at(false, 29),
            source_at(false, 31),
        ] {
            let (digest, bytes) = comparison(false, &native_before, &after, &output);
            assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
        }
        for before in [source_at(false, 30), source_at(false, 31)] {
            let (digest, bytes) = comparison(false, &before, &native_after, &output);
            assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
        }
        for changed_output in [
            framed_output(true, BOOK, 10, 30),
            framed_output(false, Id128([8; 16]), 10, 30),
            framed_output(false, BOOK, 11, 30),
            framed_output(false, BOOK, 10, 31),
        ] {
            let (digest, bytes) = comparison(false, &native_before, &native_after, &changed_output);
            assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
        }
    }

    #[test]
    fn full_outer_digest_domain_and_exact_framing_are_required() {
        for functional in [false, true] {
            let (digest, bytes) = valid(functional);
            for end in 0..bytes.len() {
                assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes[..end]).is_err());
            }
            let mut changed = bytes.clone();
            let output_byte = changed.len() - 33;
            changed[output_byte] ^= 1;
            assert!(validate_disclosure_comparison(BOOK, POST, digest, &changed).is_err());
            assert!(validate_disclosure_comparison(BOOK, POST, [1; 32], &bytes).is_err());
            let wrong_domain = if functional {
                NATIVE_DOMAIN
            } else {
                FUNCTIONAL_DOMAIN
            };
            let forged = domain_digest(wrong_domain, &[&bytes[..bytes.len() - 32]]);
            changed = bytes.clone();
            let end = changed.len();
            changed[end - 32..].copy_from_slice(&forged);
            assert!(validate_disclosure_comparison(BOOK, POST, forged, &changed).is_err());
            changed = bytes;
            changed.push(0);
            assert!(validate_disclosure_comparison(BOOK, POST, digest, &changed).is_err());
        }
    }

    #[test]
    fn noncanonical_periods_instant_sources_and_hostile_lengths_are_refused() {
        let output = framed_output(false, BOOK, 10, 30);
        for periods in [
            &[][..],
            &[""][..],
            &["2026-02", "2026-01"][..],
            &["2026-02", "2026-02"][..],
        ] {
            let before = framed_source(false, BOOK, Id128::TRUNK, 10, b"income", periods, &[]);
            let after = framed_source(false, BOOK, Id128::TRUNK, 30, b"income", periods, &[]);
            let (digest, bytes) = comparison(false, &before, &after, &output);
            assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
        }
        let mut after = source_at(false, 30);
        let time_tag = after.len() - 33;
        after[time_tag] = 1;
        let (digest, bytes) = comparison(false, &source_at(false, 10), &after, &output);
        assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
        let (digest, mut bytes) = valid(false);
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err());
        assert!(
            validate_disclosure_comparison(BOOK, POST, digest, &vec![0; MAX_BYTES + 1]).is_err()
        );
        let (digest, bytes) = valid(false);
        assert!(
            validate_disclosure_comparison(
                BOOK,
                DisclosurePost {
                    recorded_at: CommitSeq(0),
                    ..POST
                },
                digest,
                &bytes
            )
            .is_err()
        );
        assert!(validate_disclosure_comparison(BOOK, POST, [0; 32], &bytes).is_err());
    }
}
