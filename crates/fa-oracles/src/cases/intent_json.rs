//! A book variant's `[[intent]]` rendered as the JSON `fa post --intent`
//! reads (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.1; bead fa-yugf.15, A7a):
//! derived at run time, never committed.
//!
//! The shape is the CLI's: `class`, `effective_date`, `document_date`,
//! `idempotency_key`, `description`, the target field of a correction
//! (`reverses`, `restates`, `revises`, `reclassifies`) with its `reason`, and
//! `legs` as `{side, account, amount, party?, entity?}`, where `amount` is
//! `"<literal> <unit>"`. Legs are rendered in `[[leg]] ordinal` order: the
//! post path keeps that order, so a finding's leg cite `(intent, n)` is the
//! leg with `ordinal = n`. Evidence travels as `--evidence <oid>` flags, not
//! in the document.

use crate::json::Json;

use super::book::{BookVariant, IntentDef};

/// Why an intent does not render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// A correction's target has no vid in this run yet.
    UnboundTarget { intent: String, target: String },
    /// The intent has no legs.
    NoLegs(String),
    /// A leg's side is not `Dr` or `Cr`.
    Side { intent: String, side: String },
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnboundTarget { intent, target } => {
                write!(
                    f,
                    "intent {intent}: its target {target} has not posted in this run"
                )
            }
            Self::NoLegs(intent) => write!(f, "intent {intent} has no [[leg]] rows"),
            Self::Side { intent, side } => {
                write!(f, "intent {intent}: leg side `{side}` is Dr or Cr")
            }
        }
    }
}

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}

/// The intent document for `it`. `vid_of` maps an intent id to the entry
/// vid it posted as in this run (for a correction's target).
///
/// # Errors
///
/// [`RenderError`]: an unbound target, no legs, or a bad side.
pub fn render(
    book: &BookVariant,
    it: &IntentDef,
    vid_of: &dyn Fn(&str) -> Option<String>,
) -> Result<Json, RenderError> {
    let mut legs: Vec<_> = book.legs.iter().filter(|l| l.intent == it.id).collect();
    if legs.is_empty() {
        return Err(RenderError::NoLegs(it.id.clone()));
    }
    legs.sort_by_key(|l| l.ordinal);
    let mut rendered = Vec::with_capacity(legs.len());
    for l in legs {
        let side = match l.side.as_str() {
            "Dr" => "debit",
            "Cr" => "credit",
            other => {
                return Err(RenderError::Side {
                    intent: it.id.clone(),
                    side: other.to_string(),
                });
            }
        };
        let mut leg = vec![
            ("side".to_string(), s(side)),
            ("account".to_string(), s(&l.account)),
            (
                "amount".to_string(),
                s(&format!("{} {}", l.amount_literal, l.unit)),
            ),
        ];
        if let Some(p) = l.party.as_deref().filter(|p| !p.is_empty()) {
            leg.push(("party".to_string(), s(p)));
        }
        if let Some(e) = l.entity.as_deref().filter(|e| !e.is_empty()) {
            leg.push(("entity".to_string(), s(e)));
        }
        rendered.push(Json::Object(leg));
    }
    let mut doc = vec![
        ("class".to_string(), s(&it.class)),
        ("effective_date".to_string(), s(&it.effective_date)),
    ];
    if let Some(d) = it.document_date.as_deref().filter(|d| !d.is_empty()) {
        doc.push(("document_date".to_string(), s(d)));
    }
    let key = it
        .idempotency_key
        .clone()
        .unwrap_or_else(|| format!("case-{}", it.id));
    doc.push(("idempotency_key".to_string(), s(&key)));
    if let Some(memo) = it.memo.as_deref().filter(|m| !m.is_empty()) {
        doc.push(("description".to_string(), s(memo)));
    }
    if let (Some(target), Some(kind)) = (it.target.as_deref(), it.target_kind.as_deref()) {
        let vid = vid_of(target).ok_or_else(|| RenderError::UnboundTarget {
            intent: it.id.clone(),
            target: target.to_string(),
        })?;
        doc.push((kind.to_string(), s(&vid)));
        if let Some(reason) = it.reason.as_deref().filter(|r| !r.is_empty()) {
            doc.push(("reason".to_string(), s(reason)));
        }
    }
    doc.push(("legs".to_string(), Json::Array(rendered)));
    Ok(Json::Object(doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::CASE_EXTENSIONS;
    use crate::cases::tests::{load_files, pilot};

    #[test]
    fn intent_json_matches_the_cli_intent_shape() {
        let case = load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("the pilot loads");
        let book = &case.books["native"];
        let f4 = book.intents.iter().find(|i| i.id == "F4").expect("F4");
        let doc = render(book, f4, &|_| None).expect("F4 renders");
        assert_eq!(
            doc.to_string(),
            r#"{"class":"Original","effective_date":"2001-06-30","idempotency_key":"wc-pilot-F4","description":"line costs to CIP (pilot fixture)","legs":[{"side":"debit","account":"1500","amount":"560000000.00 USD"},{"side":"credit","account":"6100","amount":"186666666.67 USD"},{"side":"credit","account":"6110","amount":"186666666.67 USD"},{"side":"credit","account":"6120","amount":"186666666.66 USD"}]}"#
        );
        // Every key is one the CLI's intent reader accepts
        // (crates/fa-cli/src/cli.rs post_timing FIELDS), and legs carry
        // side, account and amount.
        const CLI_FIELDS: [&str; 7] = [
            "class",
            "effective_date",
            "document_date",
            "idempotency_key",
            "description",
            "legs",
            "restates",
        ];
        let delta = book
            .intents
            .iter()
            .find(|i| i.id == "delta-F4")
            .expect("delta-F4");
        assert_eq!(
            render(book, delta, &|_| None),
            Err(RenderError::UnboundTarget {
                intent: "delta-F4".into(),
                target: "F4".into()
            })
        );
        let rendered =
            render(book, delta, &|t| (t == "F4").then(|| "7e2b".to_string())).expect("bound");
        for (k, _) in rendered.as_object().expect("an object") {
            assert!(
                CLI_FIELDS.contains(&k.as_str()) || k == "reason",
                "unknown intent field {k}"
            );
        }
        assert_eq!(
            rendered.get("restates").and_then(Json::as_str),
            Some("7e2b")
        );
        assert_eq!(
            rendered.get("reason").and_then(Json::as_str),
            Some("WrongAccount")
        );
        let legs = rendered.get("legs").and_then(Json::as_array).expect("legs");
        assert_eq!(
            legs.iter()
                .filter_map(|l| l.get("side").and_then(Json::as_str))
                .collect::<Vec<_>>(),
            ["credit", "debit", "debit", "debit"],
            "delta-F4 negates F4: Cr 1500 at ordinal 0, Dr 6100, 6110 and 6120 at ordinals 1-3"
        );
    }
}
