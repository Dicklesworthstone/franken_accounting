//! Adversarial document-period resolution from original declaration bytes.
//! Dates and boundaries are explicit so these checks assume no calendar
//! generator, naming convention, month length, or current period projection.

use super::{ReportError, Schema};
use crate::codec::Writer;

const BOOK: [u8; 16] = [0x53; 16];

fn declare(
    schema: &mut Schema,
    fiscal_year: i32,
    periods: &[(&str, u8, i32, i32)],
) -> Result<(), ReportError> {
    let mut body = Writer::default();
    body.fixed(b"fa:period-creation:v1")
        .bytes(b"calendar")
        .i32(fiscal_year)
        .count(periods.len());
    for (ordinal, &(code, kind, start, end)) in periods.iter().enumerate() {
        body.bytes(code.as_bytes())
            .i32(fiscal_year)
            .u16(u16::try_from(ordinal).unwrap())
            .u8(kind)
            .i32(start)
            .i32(end)
            .u8(if kind == 4 { 4 } else { 0 });
    }
    schema.apply(13, &body.buf, &BOOK, 1)
}

fn calendar() -> Schema {
    let mut schema = Schema::default();
    declare(
        &mut schema,
        2026,
        &[
            ("start", 2, 100, 101),
            ("first", 0, 100, 128),
            ("second", 0, 128, 163),
            ("adjustment", 1, 162, 163),
            ("close", 3, 162, 163),
        ],
    )
    .unwrap();
    schema
}

#[test]
fn cutoff_document_dates_follow_declared_exclusive_boundaries() {
    let schema = calendar();
    for (day, expected) in [
        (99, None),
        (100, Some("first")),
        (127, Some("first")),
        (128, Some("second")),
        (162, Some("second")),
        (163, None),
    ] {
        assert_eq!(
            schema.document_period(None, day).unwrap().as_deref(),
            expected,
            "document date {day}",
        );
    }
}

#[test]
fn cutoff_explicit_special_hint_applies_only_when_it_contains_the_document() {
    let schema = calendar();
    for (hint, day, expected) in [
        ("start", 100, "start"),
        ("start", 101, "first"),
        ("adjustment", 162, "adjustment"),
        ("close", 162, "close"),
        ("adjustment", 161, "second"),
        ("close", 127, "first"),
        ("first", 128, "second"),
        ("second", 127, "first"),
    ] {
        assert_eq!(
            schema
                .document_period(Some(("calendar", hint)), day)
                .unwrap()
                .as_deref(),
            Some(expected),
            "hint {hint}, document date {day}",
        );
    }
}

#[test]
fn cutoff_historical_normal_periods_keep_their_original_calendar_identity() {
    let mut schema = Schema::default();
    declare(
        &mut schema,
        2025,
        &[
            ("prior-open", 2, 0, 1),
            ("prior-first", 4, 0, 28),
            ("prior-last", 4, 28, 63),
            ("prior-adjustment", 1, 62, 63),
            ("prior-close", 3, 62, 63),
        ],
    )
    .unwrap();
    for (hint, day, expected) in [
        (None, 0, "prior-first"),
        (None, 28, "prior-last"),
        (None, 62, "prior-last"),
        (Some("prior-first"), 0, "prior-first"),
        (Some("prior-first"), 62, "prior-last"),
        (Some("prior-open"), 0, "prior-open"),
        (Some("prior-adjustment"), 62, "prior-adjustment"),
        (Some("prior-close"), 62, "prior-close"),
    ] {
        assert_eq!(
            schema
                .document_period(hint.map(|code| ("calendar", code)), day)
                .unwrap()
                .as_deref(),
            Some(expected),
        );
    }
}

#[test]
fn cutoff_unknown_years_and_special_rows_do_not_invent_normal_coverage() {
    let mut schema = calendar();
    declare(&mut schema, 2027, &[("future-open", 2, 200, 201)]).unwrap();
    assert_eq!(schema.document_period(None, 200).unwrap(), None);
    assert_eq!(
        schema
            .document_period(Some(("calendar", "future-open")), 200)
            .unwrap(),
        None,
    );
    // A declaration for another fiscal year extends coverage by its original
    // boundaries; a code's text is never used as a calendar formula.
    declare(&mut schema, 2027, &[("future-normal", 0, 200, 235)]).unwrap();
    assert_eq!(
        schema.document_period(None, 200).unwrap().as_deref(),
        Some("future-normal"),
    );
    assert_eq!(schema.document_period(None, 235).unwrap(), None);
}

#[test]
fn cutoff_rejects_ambiguous_normal_coverage_even_with_a_special_hint() {
    for kind in [0, 4] {
        let mut schema = calendar();
        declare(&mut schema, 2026, &[("overlap", kind, 127, 163)]).unwrap();
        for hint in [None, Some(("calendar", "adjustment"))] {
            assert_eq!(
                schema.document_period(hint, 162).unwrap_err().predicate,
                "procedure_period",
            );
        }
    }
}

#[test]
fn cutoff_hints_cannot_change_calendar_or_cross_fiscal_year_identity() {
    let mut schema = calendar();
    for hint in [("unrelated", "first"), ("calendar", "missing")] {
        assert_eq!(
            schema
                .document_period(Some(hint), 100)
                .unwrap_err()
                .predicate,
            "procedure_period",
        );
    }
    // A special from a different fiscal year cannot claim a same-day normal
    // from this year, even if malformed declarations make the dates overlap.
    declare(&mut schema, 2027, &[("wrong-year-close", 3, 162, 163)]).unwrap();
    assert_eq!(
        schema
            .document_period(Some(("calendar", "wrong-year-close")), 162)
            .unwrap_err()
            .predicate,
        "procedure_period",
    );
}

#[test]
fn cutoff_declared_dates_work_at_the_signed_day_extremes() {
    let mut schema = Schema::default();
    declare(
        &mut schema,
        i32::MIN,
        &[("earliest", 0, i32::MIN, i32::MIN + 1)],
    )
    .unwrap();
    declare(
        &mut schema,
        i32::MAX,
        &[("latest", 0, i32::MAX - 1, i32::MAX)],
    )
    .unwrap();
    assert_eq!(
        schema.document_period(None, i32::MIN).unwrap().as_deref(),
        Some("earliest"),
    );
    assert_eq!(
        schema
            .document_period(None, i32::MAX - 1)
            .unwrap()
            .as_deref(),
        Some("latest"),
    );
    assert_eq!(schema.document_period(None, i32::MAX).unwrap(), None);
}
