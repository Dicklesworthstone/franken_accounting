//! K-ASSERT (§2.2, §3.6, §5.3; bead fa-yugf.9, A3c): every source in an
//! expectation's basis closure has a phrase for the status its sentence
//! carries, and no assurance claims more than the filing gives it.
//!
//! The status is, in precedence order, a T's own `assurance` for its
//! published source, a fact's own `assurance` for that fact, then the source
//! row's `assertion_status` ([`Expectation::source_statuses`]). A T's
//! `assurance` is one of the four filer statuses, and neither it nor a
//! fact's mapped `assurance` is stronger than the status it replaces
//! (`filer_audited` > `filer_reviewed` > `filer_unaudited` =
//! `filer_not_from_audited_statements`). Why a weaker status holds is the
//! case's own rule; K-ASSERT does not check it.
//!
//! [`Expectation::source_statuses`]: super::super::expect::Expectation::source_statuses

use super::super::expect::ExpectationType;
use super::super::phrases::{assurance_status, phrase_table, source_phrase, strength};
use super::super::source::AssertionStatus;
use super::super::{EXPECTATIONS_FILE, FACTS_FILE, SOURCES_FILE};
use super::{CheckReport, Context};

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    check_with(cx, &phrase_table)
}

/// Whether `status` claims more than `replaced`: always when `replaced` is
/// not a filer's own statement, which carries no assurance (§4.1).
fn stronger(status: AssertionStatus, replaced: AssertionStatus) -> bool {
    match (strength(status), strength(replaced)) {
        (Some(a), Some(b)) => a > b,
        _ => true,
    }
}

/// K-ASSERT under a given phrase table (tests pass a copy without a row).
#[must_use]
pub fn check_with(
    cx: &Context<'_>,
    table: &dyn Fn(AssertionStatus) -> Option<&'static str>,
) -> CheckReport {
    let case = cx.case;
    let expectations: Vec<_> = case
        .expectations
        .iter()
        .flat_map(|s| s.expectations.iter())
        .collect();
    let mut r = CheckReport::new("K-ASSERT", expectations.len());
    // A fact's own assurance narrows its row, never widens it.
    for f in &case.facts {
        let Some(s) = f.sourced() else { continue };
        let Some(status) = s.assurance.and_then(assurance_status) else {
            continue;
        };
        let Some(source) = case.sources.iter().find(|x| x.id == s.source) else {
            continue;
        };
        if stronger(status, source.assertion_status) {
            r.fail(
                FACTS_FILE,
                f.line,
                &f.id,
                format!(
                    "fact `assurance` reads {} on a {} row of {}; a fact may narrow its filing's status, never widen it",
                    status.as_str(),
                    source.assertion_status.as_str(),
                    source.id
                ),
            );
        }
    }
    for e in expectations {
        if e.kind == ExpectationType::T
            && let Some(raw) = e.fields.str("assurance")
        {
            match AssertionStatus::parse(raw).filter(|s| s.is_filer_statement()) {
                None => r.fail(
                    EXPECTATIONS_FILE,
                    e.fields.line,
                    &e.id,
                    format!(
                        "`assurance = \"{raw}\"` is one of filer_audited, filer_reviewed, filer_unaudited, filer_not_from_audited_statements"
                    ),
                ),
                Some(status) => {
                    // A T reading once per target publishes one fact per
                    // target; its `assurance` replaces each one's status.
                    let published = e.published_facts(case);
                    let mut problems = std::collections::BTreeSet::new();
                    if published.is_empty() {
                        problems.insert("a T's `assurance` replaces its published fact's status; `published` names no sourced fact".to_string());
                    }
                    for p in published {
                        let replaced = case
                            .facts
                            .iter()
                            .find(|f| f.id == p)
                            .and_then(|f| f.sourced())
                            .and_then(|s| {
                                s.assurance.and_then(assurance_status).or_else(|| {
                                    case.sources
                                        .iter()
                                        .find(|x| x.id == s.source)
                                        .map(|x| x.assertion_status)
                                })
                            });
                        match replaced {
                            Some(replaced) if strength(replaced).is_none() => problems.insert(format!(
                                "`assurance = \"{raw}\"` narrows a filer's own statement, and the published source is {}",
                                replaced.as_str()
                            )),
                            Some(replaced) if stronger(status, replaced) => problems.insert(format!(
                                "`assurance = \"{raw}\"` is stronger than the {} it replaces",
                                replaced.as_str()
                            )),
                            Some(_) => false,
                            None => problems.insert(format!(
                                "a T's `assurance` replaces its published fact's status; `published = \"{p}\"` names no sourced fact"
                            )),
                        };
                    }
                    for p in problems {
                        r.fail(EXPECTATIONS_FILE, e.fields.line, &e.id, p);
                    }
                }
            }
        }
        let mut phrases = Vec::new();
        for s in e.source_statuses(case) {
            let Some(source) = case.sources.iter().find(|x| x.id == s.source) else {
                continue;
            };
            match source_phrase(source, s.status, table) {
                Some(p) => phrases.push(format!("{} \"{p}\"", s.source)),
                None => r.fail(
                    SOURCES_FILE,
                    source.line,
                    &source.id,
                    format!(
                        "status `{}` has no phrase (in the basis closure of {})",
                        s.status.as_str(),
                        e.id
                    ),
                ),
            }
        }
        r.examined(format!("{} [{}]", e.id, phrases.join("; ")));
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::super::super::Case;
    use super::super::super::expect::Field;
    use super::super::super::fact::Provenance;
    use super::super::super::phrases::assertion_phrase;
    use super::super::super::source::Assurance;
    use super::super::super::tests::pilot_planted;
    use super::super::Verdict;
    use super::super::t_tests::t_kinds;
    use super::*;

    fn set_status(case: &mut Case, source: &str, status: AssertionStatus) {
        case.sources
            .iter_mut()
            .find(|s| s.id == source)
            .expect("a source")
            .assertion_status = status;
    }

    fn set_t_assurance(case: &mut Case, id: &str, value: &str) {
        case.expectations
            .as_mut()
            .and_then(|s| s.expectations.iter_mut().find(|e| e.id == id))
            .expect("an expectation")
            .fields
            .map
            .insert("assurance".into(), Field::Str(value.into()));
    }

    fn set_fact_assurance(case: &mut Case, fact: &str, a: Assurance) {
        let f = case
            .facts
            .iter_mut()
            .find(|f| f.id == fact)
            .expect("a fact");
        if let Provenance::Sourced(s) = &mut f.provenance {
            s.assurance = Some(a);
        }
    }

    fn line(l: Option<usize>) -> String {
        l.map_or_else(|| "-".into(), |l| l.to_string())
    }

    fn exp_line(case: &Case, id: &str) -> String {
        line(
            case.expectations
                .as_ref()
                .and_then(|s| s.get(id))
                .and_then(|e| e.fields.line),
        )
    }

    fn phrases_of(case: &Case, id: &str) -> Vec<(String, &'static str)> {
        case.expectations
            .as_ref()
            .and_then(|s| s.get(id))
            .expect("an expectation")
            .phrases(case)
    }

    #[test]
    fn pilot_gives_its_committee_report_the_committee_phrase() {
        let case = pilot_planted(&[]);
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Pass, "{text}");
        assert!(
            text.contains("SRC-WC-001 \"the committee found\""),
            "{text}"
        );
        assert!(
            phrases_of(&case, "W-D-01").contains(&("SRC-WC-001".into(), "the committee found")),
            "{:?}",
            phrases_of(&case, "W-D-01")
        );
    }

    #[test]
    fn basis_source_whose_status_has_no_phrase_fails_k_assert() {
        let mut case = pilot_planted(&[]);
        set_status(&mut case, "SRC-WC-001", AssertionStatus::Allegation);
        let without_allegation = |s: AssertionStatus| match s {
            AssertionStatus::Allegation => None,
            other => Some(assertion_phrase(other)),
        };
        let r = check_with(&Context::new(&case), &without_allegation);
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let src_line = line(
            case.sources
                .iter()
                .find(|s| s.id == "SRC-WC-001")
                .and_then(|s| s.line),
        );
        let want = format!(
            "FAIL K-ASSERT sources.toml:{src_line} SRC-WC-001: status `allegation` has no phrase (in the basis closure of W-D-01)"
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }

    #[test]
    fn t_assurance_stronger_than_its_source_fails_k_assert() {
        let mut case = t_kinds();
        set_status(&mut case, "SRC-TK-S", AssertionStatus::FilerUnaudited);
        set_t_assurance(&mut case, "X-T-04", "filer_audited");
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let want = format!(
            "FAIL K-ASSERT expectations.toml:{} X-T-04: `assurance = \"filer_audited\"` is stronger than the filer_unaudited it replaces",
            exp_line(&case, "X-T-04")
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }

    #[test]
    fn t_assurance_holds_for_every_targets_published_fact() {
        // X-T-01 publishes one B per target and states filer_unaudited.
        let mut case = crate::cases::load(&crate::cases::embedded::XBRL.case_files())
            .expect("the xbrl case loads");
        let r = check(&Context::new(&case));
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
        assert!(
            phrases_of(&case, "X-T-01")
                .contains(&("SRC-SPWR-10KA-2022".into(), "reported (unaudited)")),
            "{:?}",
            phrases_of(&case, "X-T-01")
        );
        // Stronger than every target's source: one failure, not one per target.
        set_status(
            &mut case,
            "SRC-SPWR-10KA-2022",
            AssertionStatus::FilerUnaudited,
        );
        set_t_assurance(&mut case, "X-T-01", "filer_audited");
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let want = format!(
            "FAIL K-ASSERT expectations.toml:{} X-T-01: `assurance = \"filer_audited\"` is stronger than the filer_unaudited it replaces",
            exp_line(&case, "X-T-01")
        );
        assert_eq!(
            text.lines().filter(|l| *l == want).count(),
            1,
            "{want}\n{text}"
        );
    }

    #[test]
    fn t_assurance_outside_the_filer_statuses_fails_k_assert() {
        let mut case = t_kinds();
        set_t_assurance(&mut case, "X-T-04", "allegation");
        let r = check(&Context::new(&case));
        let text = r.render(None);
        let want = format!(
            "FAIL K-ASSERT expectations.toml:{} X-T-04: `assurance = \"allegation\"` is one of filer_audited, filer_reviewed, filer_unaudited, filer_not_from_audited_statements",
            exp_line(&case, "X-T-04")
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }

    #[test]
    fn fact_assurance_stronger_than_its_row_fails_k_assert() {
        let mut case = t_kinds();
        set_status(&mut case, "SRC-TK-S", AssertionStatus::FilerUnaudited);
        set_fact_assurance(&mut case, "F-S1", Assurance::Audited);
        let r = check(&Context::new(&case));
        let text = r.render(None);
        let fact_line = line(
            case.facts
                .iter()
                .find(|f| f.id == "F-S1")
                .and_then(|f| f.line),
        );
        let want = format!(
            "FAIL K-ASSERT facts.toml:{fact_line} F-S1: fact `assurance` reads filer_audited on a filer_unaudited row of SRC-TK-S; a fact may narrow its filing's status, never widen it"
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }

    #[test]
    fn t_assurance_replaces_its_source_status_in_phrases() {
        let mut case = t_kinds();
        set_t_assurance(&mut case, "X-T-04", "filer_unaudited");
        let r = check(&Context::new(&case));
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
        let narrowed = phrases_of(&case, "X-T-04");
        assert!(
            narrowed.contains(&("SRC-TK-S".into(), "reported (unaudited)")),
            "{narrowed:?}"
        );
        assert!(
            !narrowed.contains(&("SRC-TK-S".into(), "reported (audited)")),
            "{narrowed:?}"
        );
        let sibling = phrases_of(&case, "X-T-06");
        assert!(
            sibling.contains(&("SRC-TK-S".into(), "reported (audited)")),
            "{sibling:?}"
        );
    }

    #[test]
    fn fact_assurance_narrows_its_row_in_phrases() {
        let mut case = t_kinds();
        set_fact_assurance(&mut case, "F-S1", Assurance::NotFromAudited);
        let r = check(&Context::new(&case));
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
        let p = phrases_of(&case, "X-T-04");
        assert!(
            p.contains(&(
                "SRC-TK-S".into(),
                "reported (selected data; not derived from audited statements)"
            )),
            "{p:?}"
        );
        assert!(
            p.contains(&("SRC-TK-S".into(), "reported (audited)")),
            "the siblings keep the row's: {p:?}"
        );
    }
}
