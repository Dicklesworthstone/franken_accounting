//! K-ANCHOR (§4.1, §4.4): a sourced fact's anchor is one its source's
//! `anchor_scheme` names and its `format` can carry, parses under A1a's
//! grammar, and is witnessed by the receipt: for a prose anchor the range
//! the quote was found at lies inside the declared anchor (same page, found
//! lines within the declared lines; `verify` searches at the declared
//! anchor, so a coarse declared anchor with a precise found range is
//! correct), and for a value-bound anchor the receipt's anchor is the
//! fact's. An `exhibit` anchor (`<label>|p<first>-<last>`) belongs only to a
//! `rows_file` fact bound by value, and its receipt's anchor is the page
//! range.

use super::super::fact::check_anchor;
use super::super::source::{AnchorKind, SourceFormat};
use super::{CheckReport, Context, FACTS};

/// Whether a source of `format` can carry anchors of `kind`.
#[must_use]
pub const fn suits(kind: AnchorKind, format: SourceFormat) -> bool {
    match kind {
        AnchorKind::Xbrl => matches!(
            format,
            SourceFormat::Xml | SourceFormat::Htm | SourceFormat::Json
        ),
        AnchorKind::Page
        | AnchorKind::Line
        | AnchorKind::Paragraph
        | AnchorKind::TableCell
        | AnchorKind::Exhibit => matches!(
            format,
            SourceFormat::Pdf | SourceFormat::Htm | SourceFormat::Txt
        ),
    }
}

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let sourced: Vec<_> = case
        .facts
        .iter()
        .filter_map(|f| Some((f, f.sourced()?)))
        .collect();
    let mut r = CheckReport::new("K-ANCHOR", sourced.len());
    for (f, s) in sourced {
        let mut problems = Vec::new();
        let kind = s.anchor_kind;
        match case.sources.iter().find(|src| src.id == s.source) {
            None => problems.push(format!("source `{}` is not in sources.toml", s.source)),
            Some(src) => {
                if !src.anchor_scheme.contains(&kind) {
                    let scheme: Vec<&str> = src.anchor_scheme.iter().map(|k| k.as_str()).collect();
                    problems.push(format!(
                        "`{}` is not in source {}'s anchor_scheme {scheme:?}",
                        kind.as_str(),
                        src.id
                    ));
                }
                if !suits(kind, src.format) {
                    problems.push(format!(
                        "a `{}` anchor does not suit source {}'s format `{}`",
                        kind.as_str(),
                        src.id,
                        src.format.as_str()
                    ));
                }
            }
        }
        if let Err(e) = check_anchor(kind, &s.anchor) {
            problems.push(format!("anchor `{}`: {e}", s.anchor));
        }
        if kind == AnchorKind::Exhibit && s.rows_file.is_none() {
            problems.push("an `exhibit` anchor belongs only to a `rows_file` fact".into());
        }
        match cx.receipt(&f.id) {
            None => problems.push("no receipt witnesses the anchor".into()),
            Some(rc) => {
                if kind == AnchorKind::Exhibit && rc.alignment.as_str() != "value" {
                    problems
                        .push("an `exhibit` fact's receipt binds by value, not sentence".into());
                }
                if let Err(e) = witnessed(kind, &s.anchor, &rc.anchor) {
                    problems.push(e);
                }
            }
        }
        r.examined(f.id.clone());
        for p in problems {
            r.fail(FACTS, f.line, &f.id, p);
        }
    }
    r.finish()
}

/// `p<first>-<last>` or `l<first>-<last>` as a pair.
fn range(s: &str, prefix: char) -> Option<(u32, u32)> {
    let (a, b) = s.strip_prefix(prefix)?.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// The receipt's anchor `found` lies inside the fact's `declared` anchor.
///
/// # Errors
///
/// Names how it does not.
pub fn witnessed(kind: AnchorKind, declared: &str, found: &str) -> Result<(), String> {
    let outside = || {
        format!("the receipt found the quote at `{found}`, outside the fact's anchor `{declared}`")
    };
    match kind {
        AnchorKind::Page => {
            let (dp, dl) = declared.split_once(':').ok_or_else(outside)?;
            let (fp, fl) = found.split_once(':').ok_or_else(outside)?;
            let (d, f) = (
                range(dl, 'l').ok_or_else(outside)?,
                range(fl, 'l').ok_or_else(outside)?,
            );
            (dp == fp && d.0 <= f.0 && f.1 <= d.1)
                .then_some(())
                .ok_or_else(outside)
        }
        AnchorKind::Line => {
            let (d, f) = (
                range(declared, 'l').ok_or_else(outside)?,
                range(found, 'l').ok_or_else(outside)?,
            );
            (d.0 <= f.0 && f.1 <= d.1).then_some(()).ok_or_else(outside)
        }
        AnchorKind::Paragraph | AnchorKind::TableCell | AnchorKind::Xbrl => {
            (declared == found).then_some(()).ok_or_else(outside)
        }
        AnchorKind::Exhibit => {
            let pages = declared.rsplit_once('|').map_or("", |(_, p)| p);
            (pages == found).then_some(()).ok_or_else(|| {
                format!(
                    "an exhibit receipt's anchor is the fact's page range `{pages}`, not `{found}`"
                )
            })
        }
    }
}
