//! Independently decode the journaled scenario and its assumed postings. The
//! producer's scenario, policy and intent libraries are not dependencies here.

use std::collections::{BTreeMap, BTreeSet};

use super::{Document, ScenarioCertificate, ScenarioExpectation, failed, framed};
use crate::codec::Reader;
use crate::envelope::{
    KIND_ENTRY, LeafEnvelope, Leg, MAX_RECORD_BYTES, check_record, envelope_of_entry,
    proposal_after_legs, proposal_leg_details, skip_erasable,
};
use crate::report::{ReportError, metadata, text};

pub(super) struct AssumedEntry<'a> {
    pub info: metadata::EntryInfo<'a>,
    pub day: i32,
    pub legs: Vec<Leg>,
    key: &'a [u8],
}

fn identity(domain: &[u8], parts: &[&[u8]]) -> u128 {
    let hash = framed(domain, parts);
    let mut low = [0; 16];
    low.copy_from_slice(&hash[..16]);
    u128::from_le_bytes(low)
}

fn control_key(object: u128, kind: u8, discriminator: &[u8]) -> [u8; 32] {
    framed(
        b"fa:scenario-record-key:v1",
        &[&[kind], &object.to_le_bytes(), discriminator],
    )
}

struct Control<'a> {
    object: u128,
    from: u8,
    to: u8,
    refs: Vec<[u8; 32]>,
    key: &'a [u8],
    body_digest: [u8; 32],
    principal: u128,
    extension: Option<(u16, &'a [u8])>,
}

/// Read only the selected Scenario's controls; unrelated scenarios can retain
/// later semantics without changing a previously certified prefix.
fn control<'a>(
    proposal: &'a [u8],
    selected: u128,
) -> Result<Option<Control<'a>>, ReportError> {
    let mut r = proposal_after_legs(proposal)?;
    if !r.present("scenario.control")? || r.u8("scenario.control.tag")? != 3 {
        return Err(failed("scenario_records", "ScenarioControl lacks its lifecycle payload"));
    }
    let object = r.u128("scenario.object")?;
    if object != selected {
        return Ok(None);
    }
    let mut header = Reader::new(proposal);
    if header.u16("scenario.major")? != 1 || header.u16("scenario.minor")? != 1 {
        return Err(failed("scenario_profile", "unsupported ScenarioControl schema"));
    }
    header.fixed::<16>("scenario.book")?;
    header.fixed::<16>("scenario.branch")?;
    header.u16("scenario.class")?;
    header.i32("scenario.undated_placeholder")?;
    if header.present("scenario.document_date")? {
        return Err(failed("scenario_records", "ScenarioControl has a document date"));
    }
    skip_erasable(&mut header, "scenario.description")?;
    if header.present("scenario.period")? {
        return Err(failed("scenario_records", "ScenarioControl has an effective period"));
    }
    let from = r.u8("scenario.from")?;
    let to = r.u8("scenario.to")?;
    let n = r.count(256, 17, "scenario.proof_refs")?;
    let mut refs = Vec::with_capacity(n);
    for _ in 0..n {
        if r.u8("scenario.reference.tag")? != 1 {
            return Err(failed(
                "scenario_records",
                "scenario assumptions must be document identities",
            ));
        }
        let oid = r.fixed("scenario.reference.oid")?;
        if refs.last().is_some_and(|previous| *previous >= oid) {
            return Err(failed(
                "scenario_records",
                "assumption identities are not strictly ascending",
            ));
        }
        refs.push(oid);
    }
    if r.u16("scenario.reason")? != 0 {
        return Err(failed("scenario_records", "unsupported scenario reason code"));
    }
    r.count(0, 36, "scenario.unit_totals")?;
    if r.present("scenario.base_totals")? {
        return Err(failed("scenario_records", "scenario control has base valuation"));
    }
    let key = r.bytes(64, "scenario.key")?;
    if r.u8("scenario.origin")? != 3 || r.u16("scenario.control_kind")? != 12 {
        return Err(failed("scenario_records", "scenario control has an unrelated origin"));
    }
    let body_digest = r.fixed("scenario.body_digest")?;
    let principal = r.u128("scenario.principal")?;
    if r.present("scenario.session")? {
        return Err(failed("scenario_records", "scenario control has a session"));
    }
    r.count(0, 65, "scenario.evidence")?;
    r.count(0, 51, "scenario.supersession")?;
    if r.present("scenario.pending")? {
        return Err(failed("scenario_records", "scenario control has pending effects"));
    }
    r.count(0, 65, "scenario.external_ids")?;
    r.count(0, 65, "scenario.tags")?;
    let extension = match r.count(1, 6, "scenario.extensions")? {
        0 => None,
        _ => Some((
            r.u16("scenario.extension")?,
            r.bytes(MAX_RECORD_BYTES, "scenario.extension.bytes")?,
        )),
    };
    r.finish("scenario control")?;
    Ok(Some(Control {
        object,
        from,
        to,
        refs,
        key,
        body_digest,
        principal,
        extension,
    }))
}

pub(super) fn plans<'a>(
    cert: &ScenarioCertificate<'_>,
    expected: &ScenarioExpectation,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &'a [u8])],
) -> Result<Vec<AssumedEntry<'a>>, ReportError> {
    let expected_id = identity(
        b"fa:vid:scenario:v1",
        &[&expected.book_id, expected.name.as_bytes()],
    );
    if cert.scenario != expected_id {
        return Err(failed(
            "scenario_records",
            "scenario identity is not derived from the selected book and name",
        ));
    }
    let mut owner = None;
    let mut discarded = false;
    let mut assumed = Vec::with_capacity(cert.intents.len());
    for (envelope, (len, payload)) in envelopes.iter().zip(records) {
        if envelope.kind != KIND_ENTRY || envelope.class != 26 {
            continue;
        }
        let Some(record) = control(&payload[..*len], expected_id)? else {
            continue;
        };
        if record.body_digest != cert.body_digest {
            return Err(failed("scenario_records", "scenario control binds another immutable body"));
        }
        match (record.from, record.to, record.extension) {
            (0, 1, Some((10, body))) => {
                if owner.is_some() || envelope.commit_seq <= expected.fork_at {
                    return Err(failed(
                        "scenario_records",
                        "scenario Open is duplicated or does not follow its fork",
                    ));
                }
                let mut r = Reader::new(body);
                if r.u16("scenario_body.version")? != 1
                    || r.fixed::<16>("scenario_body.book")? != expected.book_id
                    || text(&mut r, 128, "scenario_body.name")? != expected.name
                {
                    return Err(failed(
                        "scenario_request",
                        "scenario Open differs from the recipient book/name",
                    ));
                }
                let opened_by = r.u128("scenario_body.owner")?;
                let fork_at = r.u64("scenario_body.fork")?;
                let from = if r.present("scenario_body.from")? {
                    Some(r.i32("scenario_body.from")?)
                } else {
                    None
                };
                r.finish("scenario body")?;
                if fork_at != expected.fork_at
                    || from != expected.from
                    || record.refs != expected.assumptions
                {
                    return Err(failed(
                        "scenario_request",
                        "scenario fork, start date or assumptions differ from the recipient question",
                    ));
                }
                if opened_by != record.principal
                    || framed(b"fa:scenario-body:v1", &[body]) != cert.body_digest
                    || record.key != control_key(record.object, 0, &[]).as_slice()
                {
                    return Err(failed(
                        "scenario_records",
                        "scenario Open body, owner or deterministic record key disagrees",
                    ));
                }
                owner = Some(opened_by);
            }
            (1, 1, Some((11, bytes))) => {
                let owner = owner.ok_or_else(|| {
                    failed("scenario_records", "scenario Plan precedes its Open")
                })?;
                if discarded || !record.refs.is_empty() || record.principal != owner {
                    return Err(failed(
                        "scenario_records",
                        "scenario Plan is not an open owner's record",
                    ));
                }
                // A later Plan is not part of this certificate's pinned prefix.
                // It must not make an older portable computation change scope.
                if assumed.len() == cert.intents.len() {
                    continue;
                }
                let record_id = identity(
                    b"fa:vid:entry:v1",
                    &[&expected.book_id, &record.principal.to_le_bytes(), record.key],
                );
                if record_id != cert.intents[assumed.len()] {
                    return Err(failed(
                        "scenario_intents",
                        "selected Plan records are not the exact ordered journal prefix",
                    ));
                }
                let mut r = Reader::new(bytes);
                if r.u16("scenario_plan.version")? != 1 {
                    return Err(failed("scenario_profile", "unsupported scenario Plan version"));
                }
                let intent = r.bytes(MAX_RECORD_BYTES, "scenario_plan.intent")?;
                let capability = r.bytes(64 * 1024, "scenario_plan.historical_capability")?;
                r.finish("scenario Plan")?;
                if capability.is_empty() {
                    return Err(failed(
                        "scenario_records",
                        "scenario Plan omits its historical capability bytes",
                    ));
                }
                let assumption = assumed_entry(intent, expected, owner)?;
                if record.key != control_key(record.object, 1, assumption.key).as_slice() {
                    return Err(failed(
                        "scenario_records",
                        "scenario Plan key does not bind its exact intent key",
                    ));
                }
                assumed.push(assumption);
            }
            (1, 2, None) => {
                if discarded
                    || owner != Some(record.principal)
                    || !record.refs.is_empty()
                    || record.key != control_key(record.object, 2, &[]).as_slice()
                {
                    return Err(failed("scenario_records", "invalid scenario Discard record"));
                }
                discarded = true;
            }
            _ => {
                return Err(failed(
                    "scenario_profile",
                    "unsupported scenario lifecycle or extension inventory",
                ));
            }
        }
    }
    if owner.is_none() || assumed.len() != cert.intents.len() {
        return Err(failed(
            "scenario_intents",
            "complete checkpoint omits the scenario Open or selected Plan prefix",
        ));
    }
    Ok(assumed)
}

fn assumed_entry<'a>(
    bytes: &'a [u8],
    expected: &ScenarioExpectation,
    owner: u128,
) -> Result<AssumedEntry<'a>, ReportError> {
    let mut intent = Reader::new(bytes);
    if &intent.fixed::<10>("intent.magic")? != b"FA-INTENT\0"
        || intent.u16("intent.major")? != 1
        || intent.u16("intent.minor")? != 0
        || intent.u8("intent.verb")? != 0
    {
        return Err(failed(
            "scenario_profile",
            "assumptions require canonical PostEntry v1 intents",
        ));
    }
    let payload = intent.bytes(MAX_RECORD_BYTES, "intent.entry")?;
    intent.finish("scenario PostIntent")?;
    let mut first = Reader::new(payload);
    let major = first.u16("assumption.major")?;
    let minor = first.u16("assumption.minor")?;
    let book = first.fixed::<16>("assumption.book")?;
    let branch = first.fixed::<16>("assumption.branch")?;
    let class = first.u16("assumption.class")?;
    let day = first.i32("assumption.day")?;
    if major != 1
        || minor > 1
        || book != expected.book_id
        || branch != [0; 16]
        || class != 1
        || expected.from.is_some_and(|from| day < from)
    {
        return Err(failed(
            "scenario_profile",
            "assumed entry must be a native Original for the fork book on or after the declared start",
        ));
    }
    let mut r = proposal_after_legs(payload)?;
    if r.present("assumption.control")? {
        return Err(failed("scenario_profile", "assumed Original cannot carry a control"));
    }
    let n = r.count(4096, 36, "assumption.unit_totals")?;
    let mut totals = BTreeMap::new();
    let mut previous = None;
    for _ in 0..n {
        let unit = r.u32("assumption.unit")?;
        if previous.is_some_and(|last| last >= unit) {
            return Err(failed(
                "scenario_profile",
                "assumed unit totals are not canonical",
            ));
        }
        previous = Some(unit);
        totals.insert(
            unit,
            [r.i128("assumption.debits")?, r.i128("assumption.credits")?],
        );
    }
    if r.present("assumption.base_totals")? {
        return Err(failed(
            "scenario_profile",
            "base valuation is outside additive native mathematics",
        ));
    }
    let key = r.bytes(64, "assumption.key")?;
    if key.is_empty() || r.u8("assumption.origin")? != 0 {
        return Err(failed(
            "scenario_profile",
            "assumed Original requires its explicit PostEntry identity",
        ));
    }
    r.fixed::<32>("assumption.intent_oid")?;
    if r.u16("assumption.intent_kind")? != 1 || r.u128("assumption.principal")? != owner {
        return Err(failed("scenario_profile", "assumed Original is not the owner's PostEntry"));
    }
    if r.present("assumption.session")? {
        r.u128("assumption.session")?;
    }
    let n = r.count(1024, 65, "assumption.evidence")?;
    let mut previous = None;
    for _ in 0..n {
        let value = (
            r.fixed::<32>("assumption.document")?,
            r.fixed::<32>("assumption.commitment")?,
            r.u8("assumption.role")?,
        );
        if previous.is_some_and(|last| last >= value) {
            return Err(failed(
                "scenario_documents",
                "intent evidence references are not canonical",
            ));
        }
        previous = Some(value);
    }
    r.count(0, 51, "assumption.supersession")?;
    if r.present("assumption.pending")? {
        return Err(failed(
            "scenario_profile",
            "pending and resolution effects are outside additive Original mathematics",
        ));
    }
    let n = r.count(256, 65, "assumption.external_ids")?;
    let mut previous = None;
    for _ in 0..n {
        let system = text(&mut r, 64, "assumption.external_system")?;
        let mut probe = Reader::new(&payload[payload.len() - r.remaining()..]);
        let field_digest = probe.fixed::<32>("assumption.external_digest")?;
        let order = (system, field_digest);
        if system.is_empty() || previous.is_some_and(|last| last >= order) {
            return Err(failed(
                "scenario_profile",
                "assumed external identifiers are not canonical",
            ));
        }
        previous = Some(order);
        skip_erasable(&mut r, "assumption.external_value")?;
    }
    let n = r.count(32, 65, "assumption.tags")?;
    let mut previous = None;
    for _ in 0..n {
        let key = text(&mut r, 64, "assumption.tag")?;
        if key.is_empty() || previous.is_some_and(|last| last >= key) {
            return Err(failed("scenario_profile", "assumed tag keys are not canonical"));
        }
        previous = Some(key);
        skip_erasable(&mut r, "assumption.tag.value")?;
    }
    if minor == 1 {
        r.count(0, 6, "assumption.extensions")?;
    }
    let proposal_len = payload.len() - r.remaining();
    if r.present("assumption.plan_certificate")? {
        return Err(failed("scenario_profile", "PostIntent cannot carry a plan certificate"));
    }
    r.count(0, 48, "assumption.approvals")?;
    r.fixed::<32>("assumption.proposal_digest")?;
    r.fixed::<32>("assumption.entry_digest")?;
    r.finish("assumed entry")?;
    let envelope = envelope_of_entry(payload, proposal_len, 0, 0).map_err(|error| {
        failed(
            "scenario_intents",
            format!("assumed entry framing/digest: {error:?}"),
        )
    })?;
    let legs = check_record(&envelope, payload, proposal_len).map_err(|error| {
        failed(
            "scenario_intents",
            format!("assumed entry derivation: {error:?}"),
        )
    })?;
    let proposal = &payload[..proposal_len];
    let details = proposal_leg_details(proposal)?;
    if legs.len() < 2
        || details.iter().any(|leg| {
            leg.base_amount.is_some()
                || !leg.dimensions.is_empty()
                || !leg.settlements.is_empty()
        })
    {
        return Err(failed(
            "scenario_profile",
            "assumed Original requires at least two native, dimensionless legs without settlements",
        ));
    }
    let mut computed = BTreeMap::<u32, [i128; 2]>::new();
    for leg in &legs {
        if leg.mantissa < 0 {
            return Err(failed("exact_arithmetic", "negative assumed leg"));
        }
        let cell = computed.entry(leg.unit).or_insert([0; 2]);
        let column = usize::from(!leg.debit);
        cell[column] = cell[column]
            .checked_add(leg.mantissa)
            .ok_or_else(super::arithmetic)?;
    }
    if computed != totals || computed.values().any(|total| total[0] != total[1]) {
        return Err(failed(
            "scenario_footing",
            "assumed native legs do not reproduce balanced declared unit totals",
        ));
    }
    let info = metadata::entry_info(proposal, &envelope)?;
    Ok(AssumedEntry {
        info,
        day,
        legs,
        key,
    })
}

pub(super) fn seq_map(
    bytes: &[u8],
    cert: &ScenarioCertificate<'_>,
    expected: &ScenarioExpectation,
    envelopes: &[LeafEnvelope],
) -> Result<(), ReportError> {
    if framed(b"fa:seq-map:v1", &[bytes]) != cert.map_digest {
        return Err(failed(
            "scenario_seq_map",
            "native SeqMap differs from the certificate commitment",
        ));
    }
    let fork_head = cert
        .head
        .checked_sub(cert.intents.len() as u64)
        .filter(|head| *head > 0 && *head <= expected.fork_at)
        .ok_or_else(|| {
            failed(
                "scenario_seq_map",
                "scenario head cannot follow the declared additive fork",
            )
        })?;
    let mut r = Reader::new(bytes);
    if r.u16("seq_map.version")? != 1
        || r.fixed::<16>("seq_map.book")? != expected.book_id
        || r.u64("seq_map.prefix")? != expected.fork_at
        || r.u8("seq_map.scope")? != 1
    {
        return Err(failed(
            "scenario_seq_map",
            "SeqMap has another source coordinate or unsupported scope",
        ));
    }
    let n = r.count(super::super::MAX_ROWS, 48, "seq_map.pairs")?;
    let mut sources = BTreeSet::new();
    let mut previous = (0, 0);
    for _ in 0..n {
        let source = r.u64("seq_map.source")?;
        r.fixed::<32>("seq_map.native_marker_not_judged")?;
        let scratch = r.u64("seq_map.scratch")?;
        if source <= previous.0
            || scratch <= previous.1
            || source > expected.fork_at
            || scratch > fork_head
            || scratch > source
        {
            return Err(failed(
                "scenario_seq_map",
                "SeqMap coordinates are nonmonotone or outside the additive fork",
            ));
        }
        previous = (source, scratch);
        sources.insert(source);
    }
    r.finish("scenario SeqMap")?;
    if n == 0
        || envelopes.iter().any(|envelope| {
            envelope.kind == KIND_ENTRY
                && envelope.commit_seq <= expected.fork_at
                && !sources.contains(&envelope.commit_seq)
        })
    {
        return Err(failed(
            "scenario_seq_map",
            "SeqMap omits a journaled publication in the authenticated fork",
        ));
    }
    Ok(())
}

pub(super) fn documents(
    documents: &[Document<'_>],
    expected: &ScenarioExpectation,
    assumed: &[AssumedEntry<'_>],
) -> Result<(), ReportError> {
    let mut needed: BTreeSet<[u8; 32]> = expected.assumptions.iter().copied().collect();
    let mut evidence = BTreeMap::new();
    for assumption in assumed {
        for (oid, commitment, _) in &assumption.info.evidence {
            needed.insert(*oid);
            if evidence
                .insert(*oid, *commitment)
                .is_some_and(|before| before != *commitment)
            {
                return Err(failed(
                    "scenario_documents",
                    "one cited document identity has conflicting commitments",
                ));
            }
        }
    }
    if documents.len() != needed.len()
        || documents.iter().map(|document| document.oid).ne(needed)
    {
        return Err(failed(
            "scenario_documents",
            "disclosure is not the exact assumption and selected-intent evidence closure",
        ));
    }
    for document in documents {
        let commitment = crate::document::doc_commit(document.kind, document.bytes);
        let oid = framed(b"fa:oid:document:v1", &[&expected.book_id, &commitment]);
        if oid != document.oid
            || evidence.get(&oid).is_some_and(|expected| *expected != commitment)
        {
            return Err(failed(
                "scenario_documents",
                "document kind/bytes do not reproduce the journaled assumption or evidence identity",
            ));
        }
    }
    Ok(())
}
