//! A real activated Canon rule supplies the Rule-origin population. The
//! verifier must recover origins from canonical source entries, not infer
//! them from a fixture label or from the producer's aggregate counts.

use super::*;
use fa_canon::Inputs;
use fa_model::{EventKind, EventResource, EventSpec};

pub(super) fn post_rule_population(f: &mut Fixture) -> Vec<VId> {
    let cx = f.cx();
    let authority = cap(&["read", "post", "rule_change"]);
    let source = r#"rule offline_jet_share v1 for event Sale {
  authority {
    debit "1000" upto "100.00 USD"
    credit "3000" upto "100.00 USD"
  }
  let net = event.resource("net", "USD")
  debit "1000" net
  credit "3000" net
}"#;
    let recorded = f
        .runtime
        .block_on(f.book.propose_rule_version(
            &cx,
            source,
            PRINCIPAL,
            b"offline-jet-rule",
            &authority,
        ))
        .unwrap()
        .unwrap();
    let digest = recorded.version.rule.ir_digest();
    let plan = f
        .book
        .plan_rule_activation(
            &cx,
            &authority,
            &digest,
            day(1),
            b"offline-jet-rule-activation",
        )
        .unwrap()
        .unwrap();
    let proposal_digest = plan.proposal_digest(f.book.context()).unwrap();
    let mut approvals = Vec::new();
    for approver in [VId(74), VId(75)] {
        let approved = f
            .runtime
            .block_on(f.book.approve(
                &cx,
                Capability::embedded(approver, &["approve"]).unwrap(),
                proposal_digest,
            ))
            .unwrap()
            .unwrap();
        approvals.push(match approved {
            fa_journal::Approved::Recorded { approval, .. }
            | fa_journal::Approved::AlreadyRecorded { approval, .. } => approval,
        });
    }
    f.runtime
        .block_on(
            f.book
                .activate_rule_version(&cx, &authority, plan, approvals),
        )
        .unwrap()
        .unwrap();

    let mut entries = Vec::new();
    for date in [3, 4] {
        let code = format!("offline-jet-event-{date}");
        let event = EventSpec {
            code: code.clone(),
            kind: EventKind::Sale,
            occurred_on: day(date),
            description: f.book.seal_text(&cx, &code).unwrap(),
            participants: Vec::new(),
            resources: vec![EventResource {
                label: "net".into(),
                amount: Amount::new(f.unit, 100),
                instrument: None,
            }],
            evidence: f.evidence.clone(),
            external_ids: Vec::new(),
        };
        f.runtime
            .block_on(f.book.record_event(
                &cx,
                &event,
                PRINCIPAL,
                day(date),
                code.as_bytes(),
                &authority,
            ))
            .unwrap()
            .unwrap();
        let key = format!("offline-jet-rule-post-{date}");
        let event_id = fa_model::event_vid(f.book.context().book_id, &code);
        let posted = f
            .runtime
            .block_on(f.book.derive_rule_entry(
                &cx,
                &authority,
                &digest,
                event_id,
                &Inputs::new(),
                key.as_bytes(),
            ))
            .unwrap()
            .unwrap();
        entries.push(posted.entry_ref().vid);
    }
    entries
}
