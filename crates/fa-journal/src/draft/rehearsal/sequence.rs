//! A sequence of whole drafts in one owned scratch database. The current
//! reader is admitted on the original source once; it is never looked up in
//! the older hypothetical database as though that were the authority frontier.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftSequenceRehearsalRequest {
    /// Execution order selected by the caller's bounded dependency graph.
    pub names: Vec<String>,
    pub known_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftRehearsalStep {
    /// Original control records at the scratch coordinate just before this
    /// step. Only `known_at` advances; source identities and bytes stay intact.
    pub source: DraftRehearsalSource,
    pub view: DraftView,
    pub batch: BatchPosted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftSequenceRehearsal {
    pub seq_map: SeqMap,
    pub steps: Vec<DraftRehearsalStep>,
}

fn at_draft(index: usize, name: &str, refusal: Refusal) -> Refusal {
    Refusal {
        message: format!("draft sequence `{name}`: {}", refusal.message),
        ..refusal
    }
    .at("draft", name)
    .at("draft_index", index)
}

/// Rehearse a bounded sequence of distinct open drafts. Each uses its original
/// planner capabilities and approvals in one fresh atomic native publication,
/// observing all preceding hypothetical effects. A refusal drops the owned
/// target; the source is never partially promoted or changed.
pub async fn rehearse_drafts_into<V: Vfs + Clone>(
    source: &mut Database<V>,
    target: Database<MemVfs>,
    cx: &PurposeContexts,
    book: &BookContext,
    reviewer: &Capability,
    request: DraftSequenceRehearsalRequest,
) -> Outcome<(Database<MemVfs>, DraftSequenceRehearsal)> {
    if request.names.is_empty()
        || request.names.len() > fa_model::limits::MAX_CLOSE_RUN_TASKS
        || request.names.iter().collect::<BTreeSet<_>>().len() != request.names.len()
    {
        return Ok(Err(usage(
            "a combined rehearsal requires a bounded nonempty sequence of distinct drafts",
            "select each open draft at most once in dependency order",
        )));
    }
    for name in &request.names {
        if let Err(refusal) = check_name(name) {
            return Ok(Err(refusal));
        }
    }
    // This existing factory owns and checks the empty target, admits current
    // original-source reads, validates all first-draft history, replays exactly
    // one source prefix and runs the unchanged native atomic posting path.
    let first_name = &request.names[0];
    let (mut target, first) = match rehearse_draft_into(
        source,
        target,
        cx,
        book,
        reviewer,
        DraftRehearsalRequest {
            name: first_name.clone(),
            known_at: request.known_at,
        },
    )
    .await?
    {
        Ok(rehearsed) => rehearsed,
        Err(refusal) => return Ok(Err(at_draft(0, first_name, refusal))),
    };
    let mut sequence = DraftSequenceRehearsal {
        seq_map: first.seq_map,
        steps: vec![DraftRehearsalStep {
            source: first.source,
            view: first.view,
            batch: first.batch,
        }],
    };
    for (index, name) in request.names.iter().enumerate().skip(1) {
        // Original history is validated before looking at a copied draft. A
        // removed/restored source mirror cannot be hidden by scratch filtering.
        let original_request = DraftRehearsalRequest {
            name: name.clone(),
            known_at: request.known_at,
        };
        let (original_source, original_view) = match capture(source, cx, book, &original_request)? {
            Ok(captured) => captured,
            Err(refusal) => return Ok(Err(at_draft(index, name, refusal))),
        };
        let before = target.frontier()?;
        let current_request = DraftRehearsalRequest {
            name: name.clone(),
            known_at: before,
        };
        let (copied_source, copied_view) = match capture(&target, cx, book, &current_request)? {
            Ok(captured) => captured,
            Err(refusal) => return Ok(Err(at_draft(index, name, refusal))),
        };
        let mut normalized_source = copied_source.clone();
        normalized_source.known_at = request.known_at;
        if normalized_source != original_source || copied_view != original_view {
            return Err(corrupt(
                "combined scratch draft differs from its complete original source",
            ));
        }
        let batch = match apply_reviewed_draft(&mut target, cx, book, &copied_view, before).await? {
            Ok(batch) => batch,
            Err(refusal) => return Ok(Err(at_draft(index, name, refusal))),
        };
        sequence.steps.push(DraftRehearsalStep {
            source: copied_source,
            view: copied_view,
            batch,
        });
    }
    Ok(Ok((target, sequence)))
}
