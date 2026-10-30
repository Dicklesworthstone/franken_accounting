//! One fixed text per `statement_template` id (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §0.3, §12.3; bead fa-yugf.31, A14). A text's `{slot}`s are drawn from
//! [`SLOTS`]: each takes a data-file or run-invariant value the renderer
//! computes, never free text. The wording follows §0.3's predicate forms.

/// The slots a template may name, and what fills each.
pub const SLOTS: [(&str, &str); 14] = [
    ("id", "the expectation id"),
    ("variant", "the book variant the row reads"),
    ("inputs", "the expectation's basis facts"),
    ("procedure", "the D or N procedure id"),
    ("version", "the procedure version"),
    ("kind", "the T or N kind"),
    ("refusal", "the authored first refusal"),
    ("attribute", "the documented attribute a P row varies"),
    ("law_row", "the law or policy row a P refusal names"),
    ("mechanism", "the N row's mechanism (file:line)"),
    ("parent", "a CF row's parent expectation"),
    ("changed", "a CF row's changed attribute and value"),
    ("expect", "a CF row's authored outcome"),
    ("rule", "a rule T's derivation"),
];

/// Every template id's text.
pub const TEXTS: [(&str, &str); 17] = [
    (
        "D.detection",
        "Given the documented entries {inputs} encoded as the book `{variant}` posts them, procedure `{procedure}` v{version} reports a finding citing each of them.",
    ),
    (
        "D.restates_characterization",
        "Procedure `{procedure}` v{version} reports, on the book `{variant}`, a finding that restates the record's own characterization of {inputs}.",
    ),
    (
        "P.first_refusal",
        "Given the documented entry {inputs} posted on the book `{variant}`, with `{attribute}` in each cell below, the kernel's first refusal is the one each row lists; on the record's cell the authored first refusal is `{refusal}` ({law_row}).",
    ),
    (
        "T.bridge",
        "On the book `{variant}`, franken_accounting's certified read of each line below equals the published B exactly at its declared precision, computed from separately sourced A and adjustments ({inputs}) that were posted: it reproduces the published bridge.",
    ),
    (
        "T.footing",
        "On the book `{variant}`, the posted lines ({inputs}) fold to each printed total below exactly.",
    ),
    (
        "T.per_account",
        "On the book `{variant}`, franken_accounting's certified balance of each account below equals the published balance exactly, from the posted facts {inputs}.",
    ),
    (
        "T.allocation",
        "On the book `{variant}`, the allocation of {inputs} under its registered law yields exactly the published legs below.",
    ),
    (
        "T.delta",
        "On the book `{variant}`, the certified change below equals the published adjustment exactly, from the posted adjustments {inputs}.",
    ),
    (
        "T.rule",
        "On the book `{variant}`, the derivation `{rule}` over {inputs} yields exactly the published value below.",
    ),
    (
        "T.round_trip",
        "On the book `{variant}`, the export and re-import of each line below returns the published value exactly.",
    ),
    (
        "C.band",
        "On the book `{variant}`, each line below agrees with the published value within its stated display precision, from {inputs}.",
    ),
    (
        "R.read_back",
        "On the book `{variant}`, each read below returns the posted value it names ({inputs}).",
    ),
    (
        "N.no_refusal",
        "Given the documented entry {inputs} encoded as the book `{variant}` posts it, no registered law refuses it, because of {mechanism}.",
    ),
    (
        "N.no_finding",
        "Given the documented entry {inputs} encoded as the book `{variant}` posts it, procedure `{procedure}` v{version} does not report it, because of {mechanism}.",
    ),
    (
        "N.exact_gap",
        "Given the documented entry {inputs} on the book `{variant}`, the gap below is exactly the amount {mechanism} accounts for.",
    ),
    (
        "CF.counterfactual",
        "If {changed}, the row {parent} reads as below (authored outcome: {expect}). This is a counterfactual, never a claim about what happened.",
    ),
    (
        "NOTE.observation",
        "An observation on {inputs}, recorded with no verdict.",
    ),
];

/// The text of a template id.
#[must_use]
pub fn text(id: &str) -> Option<&'static str> {
    TEXTS.iter().find(|(t, _)| *t == id).map(|(_, x)| *x)
}

/// The `{slot}` names a text uses, in order.
#[must_use]
pub fn slots(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        out.push(&after[..close]);
        rest = &after[close + 1..];
    }
    out
}

/// Fills `text`'s slots from `values`.
///
/// # Errors
///
/// A slot that [`SLOTS`] does not declare, or that `values` does not fill.
pub fn fill(text: &str, values: &[(&str, String)]) -> Result<String, String> {
    let mut out = text.to_string();
    for slot in slots(text) {
        if !SLOTS.iter().any(|(s, _)| *s == slot) {
            return Err(format!("slot `{{{slot}}}` is not a declared slot"));
        }
        let value = values
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| format!("slot `{{{slot}}}` has no value"))?;
        out = out.replacen(&format!("{{{slot}}}"), value, 1);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::super::templates::TEMPLATE_IDS;
    use super::*;

    #[test]
    fn every_template_id_has_one_text_and_only_typed_slots() {
        for id in TEMPLATE_IDS {
            assert_eq!(
                TEXTS.iter().filter(|(t, _)| *t == id).count(),
                1,
                "{id} needs exactly one text"
            );
        }
        for (id, text) in TEXTS {
            assert!(TEMPLATE_IDS.contains(&id), "{id} is not a template id");
            for slot in slots(text) {
                assert!(
                    SLOTS.iter().any(|(s, _)| *s == slot),
                    "{id}: `{{{slot}}}` is not a declared slot"
                );
            }
        }
    }

    #[test]
    fn an_undeclared_or_unfilled_slot_is_refused() {
        assert_eq!(
            fill("A {free_text} here.", &[]),
            Err("slot `{free_text}` is not a declared slot".into())
        );
        assert_eq!(
            fill("On `{variant}`.", &[]),
            Err("slot `{variant}` has no value".into())
        );
        assert_eq!(
            fill("On `{variant}`.", &[("variant", "native".into())]),
            Ok("On `native`.".into())
        );
    }
}
