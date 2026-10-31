//! Case attribution for report freshness, from the same authenticated journal
//! prefix that supplied the relevant later entries. No mutable case projection
//! or second HEAD read can move a disclosure beyond `checked_at`.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{CaseBody, CaseMember, CaseState, Disclosure, KernelError, PostedEntry};
use fa_model::entry::{
    CASE_DISCLOSURE_EXTENSION, CASE_MEMBER_EXTENSION, CASE_POSTED_EXTENSION,
    RESTATEMENT_CASE_EXTENSION,
};
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, Id128, Reader, SupersessionKind,
    TypedRef, restatement_case_vid,
};
use fgdb_types::{CommitSeq, VId};

use crate::{BookError, CertificateSupersedingCase};

type Records<'a> = BTreeMap<VId, (CommitSeq, &'a Entry)>;

fn corrupt(message: impl Into<String>) -> BookError {
    KernelError::Corrupt(format!("certificate case attribution: {}", message.into())).into()
}

fn extension(entry: &Entry, tag: u16) -> Option<&[u8]> {
    entry
        .proposal
        .extensions
        .iter()
        .find(|(actual, _)| *actual == tag)
        .map(|(_, bytes)| bytes.as_slice())
}

/// A later reversal can remove an earlier case member from the report. Its
/// lineage is still the original case, but only through exact authenticated
/// Reverses links; an arbitrary reference to the same target is insufficient.
fn member_origin(
    records: &Records<'_>,
    start: VId,
) -> Result<Option<(VId, CaseMember)>, BookError> {
    let mut current = start;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current) {
            return Err(corrupt("cyclic reversal lineage"));
        }
        let (at, entry) = records
            .get(&current)
            .ok_or_else(|| corrupt("a relevant entry or its reversal target is absent"))?;
        if let Some(bytes) = extension(entry, CASE_MEMBER_EXTENSION) {
            let member = CaseMember::decode(bytes)?;
            if member.ordinal == 0 {
                return Err(corrupt("a case member claims ordinal zero"));
            }
            return Ok(Some((current, member)));
        }
        if entry.proposal.class != EntryClass::REVERSAL {
            return Ok(None);
        }
        let [link] = entry.proposal.supersession.as_slice() else {
            return Err(corrupt("a reversal does not name exactly one target"));
        };
        if link.kind != SupersessionKind::Reverses {
            return Err(corrupt("a reversal names another supersession law"));
        }
        let (target_at, target) = records
            .get(&link.target.vid)
            .ok_or_else(|| corrupt("a reversal target is absent from the checked prefix"))?;
        if target_at > at || target.entry_digest != link.target.entry_digest {
            return Err(corrupt("a reversal target's sequence or digest disagrees"));
        }
        current = link.target.vid;
    }
}

fn posted_entries(bytes: &[u8]) -> Result<Vec<PostedEntry>, BookError> {
    let mut reader = Reader::new(bytes);
    let decode = |error| BookError::from(KernelError::Model(fa_model::EntryError::from(error)));
    if reader.u16("case.posted.version").map_err(decode)? != fa_journal::case::POSTED_VERSION {
        return Err(corrupt("unsupported posted case version"));
    }
    let entries = reader
        .list(
            fa_model::limits::MAX_BATCH_ENTRIES,
            "case.posted.entries",
            |reader| {
                Ok(PostedEntry {
                    plan: VId(reader.u128("case.posted.plan")?),
                    entry: VId(reader.u128("case.posted.entry")?),
                    entry_digest: reader.fixed("case.posted.digest")?,
                })
            },
        )
        .map_err(decode)?;
    reader.finish().map_err(decode)?;
    Ok(entries)
}

/// Attribute only actual contributors. Opening, approving or disclosing an
/// unrelated case never makes a report stale, even when its period overlaps.
/// Callers have already admitted the read and selected `later_entries`; the
/// records must be exactly the journal prefix used for that selection.
pub(crate) fn superseding_cases<'a>(
    book: Id128,
    records: impl IntoIterator<Item = (VId, CommitSeq, &'a Entry)>,
    later_entries: &[VId],
) -> Result<Vec<CertificateSupersedingCase>, BookError> {
    if later_entries.is_empty() {
        return Ok(Vec::new());
    }
    let records: Records<'_> = records
        .into_iter()
        .map(|(vid, at, entry)| (vid, (at, entry)))
        .collect();
    let mut affected: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();
    for vid in later_entries {
        if let Some((origin, member)) = member_origin(&records, *vid)? {
            affected.entry(member.ordinal).or_default().insert(origin);
        }
    }
    let case_ids: BTreeMap<_, _> = affected
        .keys()
        .map(|ordinal| (restatement_case_vid(book, *ordinal), *ordinal))
        .collect();
    let mut controls = BTreeMap::<u32, Vec<_>>::new();
    for (vid, (at, entry)) in &records {
        if entry.proposal.class == EntryClass::CASE_CONTROL
            && let Some(ControlPayload::LifecycleTransition { object_ref, .. }) =
                &entry.proposal.control
            && let Some(ordinal) = case_ids.get(object_ref)
        {
            controls
                .entry(*ordinal)
                .or_default()
                .push((*at, *vid, *entry));
        }
    }
    let mut result = Vec::with_capacity(affected.len());
    for (ordinal, members) in affected {
        let case = restatement_case_vid(book, ordinal);
        let mut transitions = controls.remove(&ordinal).unwrap_or_default();
        transitions.sort_by_key(|(at, vid, _)| (*at, *vid));
        let mut previous = 0;
        let mut previous_at = None;
        let mut body = None;
        let mut posted = BTreeSet::new();
        let mut post_anchor = None;
        let mut disclosure_document = None;
        let mut disclosure_digest = None;
        for (at, vid, entry) in transitions {
            let Some(ControlPayload::LifecycleTransition {
                from,
                to,
                proof_refs,
                ..
            }) = &entry.proposal.control
            else {
                return Err(corrupt("case control lacks a lifecycle transition"));
            };
            if entry.proposal.book_id != book
                || entry.proposal.branch_id != Id128::TRUNK
                || !matches!(
                    entry.proposal.origin,
                    EntryOrigin::Control {
                        control_kind: ControlKind::CASE_TRANSITION,
                        ..
                    }
                )
                || *from != previous
                || previous_at.is_some_and(|before| at <= before)
                || !((*from == 0 && matches!(*to, 1 | 2))
                    || (*from > 0 && *from < CaseState::Closed.tag() && *to == *from + 1))
            {
                return Err(corrupt(format!(
                    "case {ordinal} has a broken immutable lifecycle"
                )));
            }
            if *from == 0 {
                let bytes = extension(entry, RESTATEMENT_CASE_EXTENSION)
                    .ok_or_else(|| corrupt("the Open record omits its case body"))?;
                let opened = CaseBody::decode(bytes)?;
                if opened.book_id != book
                    || opened.ordinal != ordinal
                    || opened.vid() != case
                    || ((*to == CaseState::Determined.tag()) != opened.determination.is_some())
                {
                    return Err(corrupt("the Open record names another case"));
                }
                body = Some(opened);
            }
            if *to == CaseState::Posted.tag() {
                post_anchor = Some(fa_journal::DisclosurePost {
                    entry: vid,
                    recorded_at: at,
                });
                let bytes = extension(entry, CASE_POSTED_EXTENSION)
                    .ok_or_else(|| corrupt("the Post record omits its committed members"))?;
                let declared = posted_entries(bytes)?;
                if declared.is_empty() {
                    return Err(corrupt("the Post record has no committed members"));
                }
                let kind = body
                    .as_ref()
                    .ok_or_else(|| corrupt("the case has no Open record"))?
                    .kind;
                for declared in declared {
                    let (member_at, member_entry) = records
                        .get(&declared.entry)
                        .ok_or_else(|| corrupt("a posted case member is absent"))?;
                    let member = extension(member_entry, CASE_MEMBER_EXTENSION)
                        .ok_or_else(|| corrupt("a posted entry omits its case membership"))?;
                    let member = CaseMember::decode(member)?;
                    if !posted.insert(declared.entry)
                        || *member_at != at
                        || member_entry.proposal.book_id != book
                        || member_entry.proposal.branch_id != Id128::TRUNK
                        || Some(member_entry.proposal.class)
                            != fa_journal::case::posting_class(kind)
                        || member_entry.entry_digest != declared.entry_digest
                        || member.ordinal != ordinal
                        || member.plan != declared.plan
                        || !proof_refs.contains(&TypedRef::Vertex(declared.entry))
                    {
                        return Err(corrupt("the case Post and its committed member disagree"));
                    }
                }
            }
            if *to == CaseState::Disclosed.tag() {
                let bytes = extension(entry, CASE_DISCLOSURE_EXTENSION)
                    .ok_or_else(|| corrupt("the Disclose record omits its disclosure"))?;
                let disclosure = Disclosure::decode(bytes)?;
                if !proof_refs.contains(&TypedRef::Object(disclosure.document))
                    || !proof_refs.contains(&TypedRef::Vertex(disclosure.attestation))
                    || disclosure
                        .post
                        .is_some_and(|post| Some(post) != post_anchor)
                    || disclosure.comparisons.iter().any(|digest| {
                        !proof_refs.contains(&TypedRef::Object(fa_model::Oid(*digest)))
                    })
                {
                    return Err(corrupt(
                        "the Disclose record does not bind its document, review, Post and comparisons",
                    ));
                }
                disclosure_document = Some(disclosure.document);
                disclosure_digest = Some(entry.entry_digest);
            }
            previous = *to;
            previous_at = Some(at);
        }
        let body =
            body.ok_or_else(|| corrupt(format!("case {ordinal} has no immutable Open record")))?;
        if previous < CaseState::Posted.tag() || !members.is_subset(&posted) {
            return Err(corrupt(format!(
                "case {ordinal} did not publish the selected members"
            )));
        }
        result.push(CertificateSupersedingCase {
            ordinal,
            kind: body.kind,
            disclosure_document,
            disclosure_digest,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_journal::{CaseKind, Determination};
    use fa_model::{EntryPayload, Erasable, LegPayload, Oid, SealKey, Supersession, Writer};
    use fa_money::{Amount, Side, UnitId};
    use fa_time::DateDay;

    const BOOK: Id128 = Id128([49; 16]);
    const MEMBER: VId = VId(10);
    const PLAN: VId = VId(99);

    fn proposal(marker: u8) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Debit, VId(80), Amount::new(UnitId(1), 30)),
            LegPayload::simple(Side::Credit, VId(81), Amount::new(UnitId(1), 30)),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay(20_000),
            document_date: None,
            description: Erasable::seal(
                &"case status fixture".to_string(),
                None,
                &SealKey([marker; 32]),
                [marker; 32],
                [marker; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: vec![marker],
            origin: EntryOrigin::Intent {
                intent_oid: Oid([marker; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(50),
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn control(
        marker: u8,
        from: u8,
        to: u8,
        extension: Option<(u16, Vec<u8>)>,
        proof_refs: Vec<TypedRef>,
    ) -> Entry {
        let mut proposal = proposal(marker);
        proposal.class = EntryClass::CASE_CONTROL;
        proposal.legs.clear();
        proposal.unit_totals.clear();
        proposal.origin = EntryOrigin::Control {
            control_kind: ControlKind::CASE_TRANSITION,
            spec_body_digest: [marker; 32],
        };
        proposal.control = Some(ControlPayload::LifecycleTransition {
            object_ref: restatement_case_vid(BOOK, 1),
            from,
            to,
            proof_refs,
            reason_code: 0,
        });
        proposal.extensions = extension.into_iter().collect();
        proposal.seal(Vec::new(), None).unwrap()
    }

    fn posted(digest: [u8; 32]) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u16(fa_journal::case::POSTED_VERSION)
            .u32(1)
            .u128(PLAN.0)
            .u128(MEMBER.0)
            .fixed(&digest);
        writer.finish().unwrap()
    }

    /// Sealed journal-shaped inputs for the pure attribution boundary. The
    /// real kernel lifecycle is covered by restatement_case integration tests.
    fn history() -> Vec<(VId, CommitSeq, Entry)> {
        let body = CaseBody {
            book_id: BOOK,
            ordinal: 1,
            kind: CaseKind::Revision,
            periods: vec!["FY2025-P12".into()],
            narrative: None,
            determination: Some(Determination {
                day: DateDay(20_000),
                authority: Oid([2; 32]),
            }),
        };
        let mut member = proposal(10);
        member.class = EntryClass::REVISION;
        member.extensions.push((
            CASE_MEMBER_EXTENSION,
            CaseMember {
                ordinal: 1,
                plan: PLAN,
            }
            .canonical_bytes()
            .unwrap(),
        ));
        let member = member.seal(Vec::new(), None).unwrap();
        let posting = control(
            4,
            4,
            5,
            Some((CASE_POSTED_EXTENSION, posted(member.entry_digest))),
            vec![TypedRef::Vertex(MEMBER)],
        );
        let disclosure = Disclosure {
            document: Oid([3; 32]),
            attestation: VId(77),
            post: None,
            comparisons: Vec::new(),
        };
        vec![
            (
                VId(1),
                CommitSeq(1),
                control(
                    1,
                    0,
                    2,
                    Some((RESTATEMENT_CASE_EXTENSION, body.canonical_bytes().unwrap())),
                    Vec::new(),
                ),
            ),
            (VId(2), CommitSeq(2), control(2, 2, 3, None, Vec::new())),
            (VId(3), CommitSeq(3), control(3, 3, 4, None, Vec::new())),
            (MEMBER, CommitSeq(4), member),
            (VId(4), CommitSeq(4), posting),
            (
                VId(5),
                CommitSeq(5),
                control(
                    5,
                    5,
                    6,
                    Some((
                        CASE_DISCLOSURE_EXTENSION,
                        disclosure.canonical_bytes().unwrap(),
                    )),
                    vec![
                        TypedRef::Object(disclosure.document),
                        TypedRef::Vertex(disclosure.attestation),
                    ],
                ),
            ),
            (VId(6), CommitSeq(6), control(6, 6, 7, None, Vec::new())),
            (
                VId(20),
                CommitSeq(7),
                proposal(20).seal(Vec::new(), None).unwrap(),
            ),
        ]
    }

    fn attribute(
        history: &[(VId, CommitSeq, Entry)],
        selected: &[VId],
    ) -> Result<Vec<CertificateSupersedingCase>, BookError> {
        superseding_cases(
            BOOK,
            history.iter().map(|(vid, at, entry)| (*vid, *at, entry)),
            selected,
        )
    }

    #[test]
    fn case_attribution_uses_only_relevant_entries_and_the_checked_prefix() {
        let records = history();
        assert!(attribute(&records, &[VId(20)]).unwrap().is_empty());
        assert!(
            attribute(&records, &[VId(5)]).unwrap().is_empty(),
            "the disclosure alone is not a monetary cause"
        );
        let prefix: Vec<_> = records
            .iter()
            .filter(|(_, at, _)| at.0 <= 4)
            .cloned()
            .collect();
        assert_eq!(
            attribute(&prefix, &[MEMBER]).unwrap(),
            vec![CertificateSupersedingCase {
                ordinal: 1,
                kind: CaseKind::Revision,
                disclosure_document: None,
                disclosure_digest: None,
            }]
        );
        let disclose = records.iter().find(|(vid, _, _)| *vid == VId(5)).unwrap();
        assert_eq!(
            attribute(&records, &[MEMBER, MEMBER]).unwrap(),
            vec![CertificateSupersedingCase {
                ordinal: 1,
                kind: CaseKind::Revision,
                disclosure_document: Some(Oid([3; 32])),
                disclosure_digest: Some(disclose.2.entry_digest),
            }]
        );
    }

    #[test]
    fn case_attribution_refuses_missing_history_and_false_post_membership() {
        let records = history();
        for missing in [VId(1), VId(2), VId(3), VId(4)] {
            let incomplete: Vec<_> = records
                .iter()
                .filter(|(vid, _, _)| *vid != missing)
                .cloned()
                .collect();
            assert!(
                attribute(&incomplete, &[MEMBER]).is_err(),
                "missing {missing:?}"
            );
        }
        let mut wrong_commit = records.clone();
        wrong_commit
            .iter_mut()
            .find(|(vid, _, _)| *vid == MEMBER)
            .unwrap()
            .1 = CommitSeq(3);
        assert!(attribute(&wrong_commit, &[MEMBER]).is_err());
        let mut wrong_digest = records.clone();
        let posting = &mut wrong_digest
            .iter_mut()
            .find(|(vid, _, _)| *vid == VId(4))
            .unwrap()
            .2;
        *posting = control(
            4,
            4,
            5,
            Some((CASE_POSTED_EXTENSION, posted([0; 32]))),
            vec![TypedRef::Vertex(MEMBER)],
        );
        assert!(attribute(&wrong_digest, &[MEMBER]).is_err());
        let mut wrong_plan = records.clone();
        let member = &mut wrong_plan
            .iter_mut()
            .find(|(vid, _, _)| *vid == MEMBER)
            .unwrap()
            .2;
        let mut changed = member.proposal.clone();
        changed.extensions = vec![(
            CASE_MEMBER_EXTENSION,
            CaseMember {
                ordinal: 1,
                plan: VId(98),
            }
            .canonical_bytes()
            .unwrap(),
        )];
        *member = changed.seal(Vec::new(), None).unwrap();
        assert!(attribute(&wrong_plan, &[MEMBER]).is_err());
    }

    #[test]
    fn case_attribution_follows_exact_reversals_and_rejects_changed_ancestry() {
        let mut records = history();
        let member = records
            .iter()
            .find(|(vid, _, _)| *vid == MEMBER)
            .unwrap()
            .2
            .clone();
        let mut reverse = proposal(30);
        reverse.class = EntryClass::REVERSAL;
        reverse.supersession.push(Supersession {
            target: member.entry_ref(MEMBER),
            kind: SupersessionKind::Reverses,
            reason_code: 2,
        });
        let reverse = reverse.seal(Vec::new(), None).unwrap();
        let mut restore = proposal(31);
        restore.class = EntryClass::REVERSAL;
        restore.supersession.push(Supersession {
            target: reverse.entry_ref(VId(30)),
            kind: SupersessionKind::Reverses,
            reason_code: 2,
        });
        records.push((VId(30), CommitSeq(8), reverse));
        records.push((
            VId(31),
            CommitSeq(9),
            restore.seal(Vec::new(), None).unwrap(),
        ));
        assert_eq!(
            attribute(&records, &[VId(30), VId(31)]).unwrap(),
            attribute(&records, &[MEMBER]).unwrap()
        );
        let mut changed = records.clone();
        let reversed = &mut changed
            .iter_mut()
            .find(|(vid, _, _)| *vid == VId(30))
            .unwrap()
            .2;
        let mut proposal = reversed.proposal.clone();
        proposal.supersession[0].target.entry_digest[0] ^= 1;
        *reversed = proposal.seal(Vec::new(), None).unwrap();
        assert!(attribute(&changed, &[VId(30)]).is_err());
        let missing: Vec<_> = records
            .into_iter()
            .filter(|(vid, _, _)| *vid != MEMBER)
            .collect();
        assert!(attribute(&missing, &[VId(31)]).is_err());
    }
}
