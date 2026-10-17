//! REA graph objects and relationship controls (bet A4, plan §4.1, §4.5, bead `fa-l2h`).
//!
//! Journals and materializes `Party`, `Instrument`, `LegalEntity`, and `ExternalId`
//! vertices, binds `Party` and `LegalEntity` vertices to their `DimensionValue`
//! counterparts via `REPRESENTS`, links `Instrument` vertices via `HELD_AT` (to
//! `Party`) and `MIRRORS` (to `Account`), and records valid-time `[valid_from, valid_to)`
//! `OWNS`, `CONTROLS`, and `RELATED_TO` edges governed by `registries/relationship_bases.toml`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fa_model::limits::{MAX_EVIDENCE_PER_ENTRY, MAX_EXTERNAL_ID_BYTES};
use fa_model::rea::{
    MAX_EVENT_PARTICIPANTS, MAX_EVENT_RESOURCE_LABEL_BYTES, MAX_EVENT_RESOURCES,
    MAX_IDENTIFIER_KEY_BYTES, MAX_JURISDICTION_BYTES, MAX_PARTY_IDENTIFIERS, MAX_REA_CODE_BYTES,
    MAX_REA_NAME_BYTES, SCHEMA_CHANGE_BIND_EXTERNAL_ID, SCHEMA_CHANGE_CREATE_INSTRUMENT,
    SCHEMA_CHANGE_CREATE_LEGAL_ENTITY, SCHEMA_CHANGE_CREATE_PARTY, SCHEMA_CHANGE_RECORD_EVENT,
    SCHEMA_CHANGE_RECORD_RELATIONSHIP, SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, EventSpec,
    ExternalId, ExternalIdBinding, Id128, InstrumentKind, InstrumentSpec, LEGAL_ENTITY_DIMENSION,
    LEGAL_ENTITY_DIMENSION_CODE, LegalEntityFullSpec, OwnershipPct, PARTY_DIMENSION,
    PARTY_DIMENSION_CODE, PartyIdentifierUpdate, PartyKind, PartySpec, ReaControlOp,
    RelationshipKind, RelationshipSpec, dimension_vid, entity_value_vid, entry_mirrors, entry_vid,
    event_vid, external_id_vid, instrument_vid, legal_entity_vid, party_value_vid, party_vid,
};
use fa_money::UnitId;
use fa_policy::Capability;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::g0::RelationshipBases;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_delta_types::RelationId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, EId, VId};

use crate::KernelError;
use crate::chart::{admit_schema_change, schema_control_proposal};
use crate::genesis::{BookContext, DIMENSION_KIND_LEGAL_ENTITY, UnitPolicy, read_book_spec};
use crate::refusal::{Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, book_root, bytes, edge_id, prop, scalar_bytes, scalar_text, text};

/// `Dimension.kind` of the party dimension (plan §4.1 `Dimension` row: counterparty).
pub const DIMENSION_KIND_PARTY: i64 = 2;

/// Recorded outcome of a journaled REA schema-control operation (`kind = 5..=11`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaControlRecorded {
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
    pub target_vid: VId,
    pub already_recorded: bool,
}

/// A `Party` vertex reconstructed from the journaled REA control stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyRow {
    pub vid: VId,
    pub dimension_value_vid: VId,
    pub code: String,
    pub kind: PartyKind,
    pub name: Erasable<String>,
    pub identifiers: Vec<(String, Erasable<String>)>,
    pub external_ids: Vec<ExternalId>,
    pub created_at: CommitSeq,
}

/// An `Instrument` vertex reconstructed from the journaled REA control stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstrumentRow {
    pub vid: VId,
    pub code: String,
    pub name: String,
    pub kind: InstrumentKind,
    pub unit: UnitId,
    pub held_at_party: VId,
    pub mirrors_account: VId,
    pub external_ids: Vec<ExternalId>,
    pub created_at: CommitSeq,
}

/// A `LegalEntity` vertex reconstructed from genesis + the journaled REA control stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalEntityRow {
    pub vid: VId,
    pub dimension_value_vid: VId,
    pub code: String,
    pub name: String,
    pub jurisdiction: String,
    pub functional_unit: UnitId,
    pub formed: Option<DateDay>,
    pub dissolved: Option<DateDay>,
    pub external_ids: Vec<ExternalId>,
    pub created_at: CommitSeq,
}

/// An `ExternalId` vertex reconstructed from the journaled REA control stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalIdRow {
    pub vid: VId,
    pub target_vid: VId,
    pub target_code: String,
    pub external_id: ExternalId,
    pub plain_id: String,
    pub created_at: CommitSeq,
}

/// A valid-time relationship edge (`OWNS`, `CONTROLS`, `RELATED_TO`) in the REA snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationshipRow {
    pub eid: EId,
    pub spec: RelationshipSpec,
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
}

/// An economic `Event` vertex reconstructed from the journaled REA control stream (plan §4.1 `Event`, §4.5, bead `fa-f3bo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    pub vid: VId,
    pub spec: EventSpec,
    pub event_digest: [u8; 32],
    pub created_at: CommitSeq,
    pub control_entry: VId,
}

/// One party/entity reached by [`ReaSnapshot::related_as_of`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelatedPartyHit {
    pub vid: VId,
    pub code: String,
    pub depth: usize,
    pub via: VId,
    pub kind: RelationshipKind,
    pub basis: String,
}

/// Validated REA graph snapshot at one recorded frontier `known_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaSnapshot {
    pub known_at: CommitSeq,
    pub parties: BTreeMap<VId, PartyRow>,
    pub instruments: BTreeMap<VId, InstrumentRow>,
    pub legal_entities: BTreeMap<VId, LegalEntityRow>,
    pub external_ids: BTreeMap<VId, ExternalIdRow>,
    pub relationships: Vec<RelationshipRow>,
    pub events: BTreeMap<VId, EventRow>,
}

impl ReaSnapshot {
    /// Code of a `Party`, `LegalEntity`, `Instrument`, or `Event` vertex in this snapshot, if present.
    #[must_use]
    pub fn endpoint_code(&self, vid: VId) -> Option<&str> {
        if let Some(p) = self.parties.get(&vid) {
            return Some(&p.code);
        }
        if let Some(le) = self.legal_entities.get(&vid) {
            return Some(&le.code);
        }
        if let Some(inst) = self.instruments.get(&vid) {
            return Some(&inst.code);
        }
        if let Some(ev) = self.events.get(&vid) {
            return Some(&ev.spec.code);
        }
        None
    }

    /// Pure temporal closure over active `[valid_from, valid_to)` `OWNS`,
    /// `CONTROLS`, and `RELATED_TO` edges as of civil date `as_of` up to
    /// `max_depth` hops from `root` (plan §4.5).
    ///
    /// Relatedness under ASC 850 / IAS 24 traverses declared ownership, control,
    /// and related-party edges in both directions (parent, subsidiary, common
    /// control, and sister entities) and returns hits ordered deterministically
    /// by `(depth, vid)`.
    #[must_use]
    pub fn related_as_of(
        &self,
        root: VId,
        as_of: DateDay,
        max_depth: usize,
    ) -> Vec<RelatedPartyHit> {
        if max_depth == 0
            || (!self.parties.contains_key(&root) && !self.legal_entities.contains_key(&root))
        {
            return Vec::new();
        }
        let active: Vec<&RelationshipSpec> = self
            .relationships
            .iter()
            .map(|r| &r.spec)
            .filter(|spec| spec.is_active_on(as_of))
            .collect();

        let mut visited: BTreeSet<VId> = BTreeSet::new();
        visited.insert(root);
        let mut queue: VecDeque<(VId, usize)> = VecDeque::new();
        queue.push_back((root, 0));
        let mut hits: Vec<RelatedPartyHit> = Vec::new();

        while let Some((cur, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            // Collect neighbors deterministically by (neighbor_vid, edge_kind_name, basis).
            let mut step_candidates: Vec<(VId, RelationshipKind, String)> = Vec::new();
            for edge in &active {
                if edge.from == cur {
                    step_candidates.push((edge.to, edge.kind, edge.basis.clone()));
                } else if edge.to == cur {
                    step_candidates.push((edge.from, edge.kind, edge.basis.clone()));
                }
            }
            step_candidates.sort_by(|a, b| {
                a.0.cmp(&b.0)
                    .then_with(|| a.1.edge_kind_name().cmp(b.1.edge_kind_name()))
                    .then_with(|| a.2.cmp(&b.2))
            });
            for (next, kind, basis) in step_candidates {
                if !visited.insert(next) {
                    continue;
                }
                let code = self.endpoint_code(next).unwrap_or("").to_string();
                hits.push(RelatedPartyHit {
                    vid: next,
                    code,
                    depth: depth + 1,
                    via: cur,
                    kind,
                    basis,
                });
                queue.push_back((next, depth + 1));
            }
        }
        hits.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.vid.cmp(&b.vid)));
        hits
    }

    /// Effective directed ownership stake from `owner` to `target` as of `as_of`
    /// across simple directed `OWNS` paths of length `1..=max_depth`.
    #[must_use]
    pub fn effective_ownership_as_of(
        &self,
        owner: VId,
        target: VId,
        as_of: DateDay,
        max_depth: usize,
    ) -> Option<OwnershipPct> {
        if max_depth == 0 || owner == target {
            return OwnershipPct::new(0, 1);
        }
        let active_owns: Vec<(VId, VId, OwnershipPct)> = self
            .relationships
            .iter()
            .filter(|r| r.spec.is_active_on(as_of))
            .filter_map(|r| match r.spec.kind {
                RelationshipKind::Owns { pct } => Some((r.spec.from, r.spec.to, pct)),
                RelationshipKind::Controls | RelationshipKind::RelatedTo => None,
            })
            .collect();

        let mut total = OwnershipPct::new(0, 1)?;
        let mut stack: Vec<(VId, OwnershipPct, BTreeSet<VId>)> = Vec::new();
        let mut init_path = BTreeSet::new();
        init_path.insert(owner);
        stack.push((owner, OwnershipPct::new(1, 1)?, init_path));

        while let Some((cur, prod, path)) = stack.pop() {
            let depth = path.len() - 1;
            if depth >= max_depth {
                continue;
            }
            for &(from, to, pct) in &active_owns {
                if from != cur || path.contains(&to) {
                    continue;
                }
                let step_rate = prod.checked_mul(pct)?;
                if to == target {
                    total = total.checked_add(step_rate)?;
                } else if depth + 1 < max_depth {
                    let mut next_path = path.clone();
                    next_path.insert(to);
                    stack.push((to, step_rate, next_path));
                }
            }
        }
        Some(total)
    }
}

/// Deterministic edge identity for a valid-time relationship edge:
/// `H("fa:eid:relationship:v1" ‖ relation ‖ from ‖ to ‖ len(basis) ‖ basis ‖ valid_from)`.
#[must_use]
pub fn relationship_edge_id(
    relation: RelationId,
    from: VId,
    to: VId,
    basis: &str,
    valid_from: DateDay,
) -> EId {
    let mut h = Hasher::new();
    h.update(b"fa:eid:relationship:v1");
    h.update(&relation.0.to_le_bytes());
    h.update(&from.0.to_le_bytes());
    h.update(&to.0.to_le_bytes());
    let len = u32::try_from(basis.len()).unwrap_or(u32::MAX);
    h.update(&len.to_le_bytes());
    h.update(basis.as_bytes());
    h.update(&valid_from.0.to_le_bytes());
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    EId(u128::from_le_bytes(lo))
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("journaled rea: {}", message.into()))
}

fn check_rea_idempotency(
    book: &BookContext,
    row: &VertexRow,
    target_vid: VId,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
) -> Outcome<ReaControlRecorded> {
    let stored = match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    let same = if &stored.proposal_digest == proposal_digest {
        true
    } else {
        match (
            stored.proposal.semantic_digest(&book.seal_key),
            proposal.semantic_digest(&book.seal_key),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    };
    if same {
        Ok(Ok(ReaControlRecorded {
            recorded_at: row.created_at,
            control_entry: row.vid,
            target_vid,
            already_recorded: true,
        }))
    } else {
        Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with different content; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical REA schema control to get the recorded outcome, or use a new idempotency key",
        )))
    }
}

fn open_external_ids(
    book: &BookContext,
    ext_ids: &[ExternalId],
) -> Outcome<Vec<(VId, String, ExternalId)>> {
    if ext_ids.len() > fa_model::limits::MAX_EXTERNAL_IDS {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "external_ids length {} exceeds max {}",
                ext_ids.len(),
                fa_model::limits::MAX_EXTERNAL_IDS
            ),
            "Appendix A ExternalId",
            "reduce the number of external_ids",
        )));
    }
    for pair in ext_ids.windows(2) {
        let a = (&pair[0].system, pair[0].id.field_digest());
        let b = (&pair[1].system, pair[1].id.field_digest());
        if a >= b {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                "external_ids must be strictly ascending by (system, id.field_digest)",
                "Appendix A ExternalId",
                "sort external_ids by (system, id.field_digest)",
            )));
        }
    }
    let mut resolved = Vec::with_capacity(ext_ids.len());
    let mut seen_vids = BTreeSet::new();
    for ext in ext_ids {
        if ext.system.is_empty() || ext.system.len() > fa_model::limits::MAX_SYSTEM_BYTES {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!("external_id.system `{}` must be 1..=64 bytes", ext.system),
                "Appendix A ExternalId.system",
                "provide a non-empty system name of at most 64 bytes",
            )));
        }
        let Ok(plain) = ext.id.open(&book.seal_key, MAX_EXTERNAL_ID_BYTES) else {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "external_id in system `{}` must be sealed under this book's seal_key",
                    ext.system
                ),
                "plan §4.5, §4.9 (ExternalId derivation requires opening the id under the book seal_key)",
                "seal the ExternalId.id under book.seal_key with a 1..=256 byte string",
            )));
        };
        if plain.is_empty() || plain.len() > MAX_EXTERNAL_ID_BYTES {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "external_id in system `{}` must be 1..={MAX_EXTERNAL_ID_BYTES} bytes",
                    ext.system
                ),
                "Appendix A ExternalId.id",
                "provide a non-empty external identifier string",
            )));
        }
        let evid = external_id_vid(book.book_id, &ext.system, &plain);
        if !seen_vids.insert(evid) {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                format!(
                    "duplicate external_id (`{}`, `{plain}`) in the same request",
                    ext.system
                ),
                "plan §4.9, FA-INV-09 (ExternalId uniqueness)",
                "remove the duplicate external_id entry",
            )));
        }
        resolved.push((evid, plain, ext.clone()));
    }
    Ok(Ok(resolved))
}

fn check_external_id_conflicts<V: asupersync::fs::Vfs + Clone>(
    txn: &fgdb::WriteTxn,
    db: &Database<V>,
    resolved: &[(VId, String, ExternalId)],
) -> Result<Option<Refusal>, KernelError> {
    for (ext_vid, plain, ext) in resolved {
        if let Some(existing_row) = txn.vertex(db, *ext_vid)? {
            let owner_vid = match prop(&existing_row, property::TARGET_REF) {
                Some(CanonicalScalar::Bytes(b)) if b.as_slice().len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(b.as_slice());
                    Some(VId(u128::from_le_bytes(arr)))
                }
                _ => None,
            };
            let owner_desc = if let Some(ovid) = owner_vid {
                if let Some(orow) = txn.vertex(db, ovid)? {
                    let code_str = text(&orow, property::CODE, "owner.code")
                        .unwrap_or_else(|_| format!("{:032x}", ovid.0));
                    format!("`{code_str}` ({:032x})", ovid.0)
                } else {
                    format!("{:032x}", ovid.0)
                }
            } else {
                format!("{:032x}", existing_row.vid.0)
            };
            return Ok(Some(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                format!(
                    "external id (`{}`, `{plain}`) already exists at {:032x}, bound to {owner_desc}",
                    ext.system, ext_vid.0
                ),
                "plan §4.5, §4.9 (ExternalId vertex identity is derived from (book, system, id); duplicate is an AlreadyLive conflict; FA-INV-09)",
                format!(
                    "reuse the existing party/object {owner_desc} or provide a distinct external id"
                ),
            )));
        }
    }
    Ok(None)
}

fn stage_external_id_vertices(
    book: &BookContext,
    target_vid: VId,
    resolved: &[(VId, String, ExternalId)],
    in_book: &mut WriteBatch,
) -> Result<(), KernelError> {
    let root = book_root();
    for (ext_vid, _, ext) in resolved {
        let binding = ExternalIdBinding {
            target_vid,
            external_id: ext.clone(),
        };
        let payload = binding.encode().map_err(fa_model::EntryError::from)?;
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("external_id._fa_payload", payload)?,
            ),
            (
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            ),
            (property::CODE, scalar_text("code", &ext.system)?),
            (
                property::TARGET_REF,
                scalar_bytes("target_ref", target_vid.0.to_le_bytes().to_vec())?,
            ),
        ];
        props.sort_by_key(|(k, _)| k.0);
        in_book.create_vertex(*ext_vid, vec![label::EXTERNAL_ID], props);
        in_book.add_edge(
            edge_id(relation::IN_BOOK, *ext_vid, root),
            *ext_vid,
            root,
            vec![],
        );
    }
    Ok(())
}

/// Journal and materialize a `Party` vertex (`SchemaChange` `kind = 5`, plan §4.5,
/// bead `fa-l2h`), its `DimensionValue` vertex (`PARTY_DIMENSION`), `REPRESENTS`
/// binding edge, and any declared `ExternalId` vertices.
#[allow(clippy::too_many_arguments)]
pub async fn create_party<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &PartySpec,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if spec.code.is_empty() || spec.code.len() > MAX_REA_CODE_BYTES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "party code `{}` must be 1..={MAX_REA_CODE_BYTES} bytes",
                spec.code
            ),
            "Appendix A Party.code",
            "provide a non-empty party code of at most 64 bytes",
        )));
    }
    if spec.identifiers.len() > MAX_PARTY_IDENTIFIERS {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "party `{}` has {} identifiers (max {MAX_PARTY_IDENTIFIERS})",
                spec.code,
                spec.identifiers.len()
            ),
            "Appendix A Party.identifiers",
            "reduce the number of party identifiers",
        )));
    }
    for (k, _) in &spec.identifiers {
        if k.is_empty() || k.len() > MAX_IDENTIFIER_KEY_BYTES {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "party `{}` identifier key `{k}` must be 1..=64 bytes",
                    spec.code
                ),
                "Appendix A Party.identifiers",
                "use a non-empty identifier key of at most 64 bytes",
            )));
        }
    }
    for pair in spec.identifiers.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "party `{}` identifiers must be strictly ascending by key",
                    spec.code
                ),
                "Appendix A Party.identifiers",
                "sort party identifiers strictly ascending by key",
            )));
        }
    }
    let resolved_ext = match open_external_ids(book, &spec.external_ids)? {
        Ok(v) => v,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let canonical_bytes = spec.encode().map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_CREATE_PARTY,
        canonical_bytes.clone(),
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let pvid = party_vid(book.book_id, &spec.code);
    let pval_vid = party_value_vid(book.book_id, &spec.code);
    let dim_vid = dimension_vid(book.book_id, PARTY_DIMENSION_CODE);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_rea_idempotency(book, &row, pvid, &proposal, &proposal_digest);
    }
    if txn.vertex(db, pvid)?.is_some() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("party `{}` already exists in this book", spec.code),
            "plan §4.5, §4.9 (Party codes are unique derived identities)",
            "use a distinct party code or reference the existing Party vertex",
        )));
    }
    if let Some(refusal) = check_external_id_conflicts(&txn, db, &resolved_ext)? {
        txn.abort();
        return Ok(Err(refusal));
    }

    let need_dim = txn.vertex(db, dim_vid)?.is_none();
    let root = book_root();
    let book_id_scalar = scalar_bytes("book_id", book.book_id.0.to_vec())?;
    let dim_id_scalar = CanonicalScalar::Int(i64::from(PARTY_DIMENSION));

    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    if need_dim {
        let mut dim_props = vec![
            (property::BOOK_ID, book_id_scalar.clone()),
            (property::CODE, scalar_text("code", PARTY_DIMENSION_CODE)?),
            (property::NAME, scalar_text("name", "Counterparty")?),
            (property::DIMENSION_ID, dim_id_scalar.clone()),
            (
                property::DIMENSION_KIND,
                CanonicalScalar::Int(DIMENSION_KIND_PARTY),
            ),
        ];
        dim_props.sort_by_key(|(k, _)| k.0);
        in_book.create_vertex(dim_vid, vec![label::DIMENSION], dim_props);
        in_book.add_edge(
            edge_id(relation::IN_BOOK, dim_vid, root),
            dim_vid,
            root,
            vec![],
        );
    }

    let mut party_props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("party._fa_payload", canonical_bytes)?,
        ),
        (property::BOOK_ID, book_id_scalar.clone()),
        (property::CODE, scalar_text("code", &spec.code)?),
    ];
    party_props.sort_by_key(|(k, _)| k.0);
    in_book.create_vertex(pvid, vec![label::PARTY], party_props);
    in_book.add_edge(edge_id(relation::IN_BOOK, pvid, root), pvid, root, vec![]);

    let mut dval_props = vec![
        (property::BOOK_ID, book_id_scalar),
        (property::CODE, scalar_text("code", &spec.code)?),
        (property::DIMENSION_ID, dim_id_scalar),
    ];
    dval_props.sort_by_key(|(k, _)| k.0);
    in_book.create_vertex(pval_vid, vec![label::DIMENSION_VALUE], dval_props);
    in_book.add_edge(
        edge_id(relation::IN_BOOK, pval_vid, root),
        pval_vid,
        root,
        vec![],
    );

    stage_external_id_vertices(book, pvid, &resolved_ext, &mut in_book)?;

    let mut represents = WriteBatch::new(relation::REPRESENTS);
    represents.add_edge(
        edge_id(relation::REPRESENTS, pvid, pval_vid),
        pvid,
        pval_vid,
        vec![],
    );

    if let Err(e) = txn.write_ordered(db, vec![in_book, represents]) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ReaControlRecorded {
            recorded_at: seq,
            control_entry: evid,
            target_vid: pvid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated create_party's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry create_party against the new frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "concurrent create_party collided on a derived Party or ExternalId vertex",
            "plan §4.9 (derived identity uniqueness; FA-INV-09)",
            "inspect existing parties and external_ids before retrying",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Journal and materialize an `Instrument` vertex (`SchemaChange` `kind = 6`,
/// plan §4.5, bead `fa-l2h`) with `HELD_AT` (`Instrument -> Party`), `MIRRORS`
/// (`Instrument -> Account`), `IN_UNIT` (`Instrument -> Unit`), and any declared
/// `ExternalId` vertices.
#[allow(clippy::too_many_arguments)]
pub async fn create_instrument<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &InstrumentSpec,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if spec.code.is_empty() || spec.code.len() > MAX_REA_CODE_BYTES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "instrument code `{}` must be 1..={MAX_REA_CODE_BYTES} bytes",
                spec.code
            ),
            "Appendix A Instrument.code",
            "provide a non-empty instrument code of at most 64 bytes",
        )));
    }
    if spec.name.is_empty() || spec.name.len() > MAX_REA_NAME_BYTES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "instrument `{}` name must be 1..={MAX_REA_NAME_BYTES} bytes",
                spec.code
            ),
            "Appendix A Instrument.name",
            "provide a non-empty instrument name of at most 256 bytes",
        )));
    }
    let Some(unit_def) = book.units.get(spec.unit) else {
        return Ok(Err(Refusal::new(
            code::UNIT_UNREGISTERED,
            exit::REFUSAL,
            format!(
                "instrument `{}` names unregistered unit id {}",
                spec.code, spec.unit.0
            ),
            "plan §4.4, §4.5",
            "use a unit registered in the book",
        )));
    };
    let resolved_ext = match open_external_ids(book, &spec.external_ids)? {
        Ok(v) => v,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let canonical_bytes = spec.encode().map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_CREATE_INSTRUMENT,
        canonical_bytes.clone(),
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let ivid = instrument_vid(book.book_id, &spec.code);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_rea_idempotency(book, &row, ivid, &proposal, &proposal_digest);
    }
    if txn.vertex(db, ivid)?.is_some() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("instrument `{}` already exists in this book", spec.code),
            "plan §4.5, §4.9 (Instrument codes are unique derived identities)",
            "use a distinct instrument code",
        )));
    }
    let party_ok = txn
        .vertex(db, spec.held_at_party)?
        .is_some_and(|row| row.labels.contains(&label::PARTY));
    if !party_ok {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "instrument `{}` names held_at_party {:032x}, which is not a Party in this book",
                spec.code, spec.held_at_party.0
            ),
            "plan §4.5 (Instrument HELD_AT Party)",
            "create the custodian/bank Party first (`fa party create`) and cite its VId",
        )));
    }
    let Some(acct_row) = txn.vertex(db, spec.mirrors_account)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!(
                "instrument `{}` names mirrors_account {:032x}, which does not exist in this book",
                spec.code, spec.mirrors_account.0
            ),
            "plan §4.5 (Instrument MIRRORS Account)",
            "open or install the mirrored GL leaf account first",
        )));
    };
    if !acct_row.labels.contains(&label::ACCOUNT) {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!(
                "instrument `{}` names mirrors_account {:032x}, which is not an Account vertex",
                spec.code, spec.mirrors_account.0
            ),
            "plan §4.5 (Instrument MIRRORS Account)",
            "cite a GL leaf Account vertex",
        )));
    }
    let acct = AccountRow::decode(&acct_row)?;
    if !acct.is_leaf {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!(
                "instrument `{}` mirrors summary account `{}`; an instrument must mirror a posting leaf",
                spec.code, acct.code
            ),
            "plan §4.3, §4.5 (only leaf accounts accept postings and mirror instruments)",
            "mirror a leaf account under the summary",
        )));
    }
    let unit_ok = match acct.unit_policy {
        UnitPolicy::Single(u) => u == spec.unit,
        UnitPolicy::AnyCurrency => matches!(unit_def.kind, fa_money::UnitKind::Currency { .. }),
        UnitPolicy::AnyUnit => true,
    };
    if !unit_ok {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNIT_POLICY,
            exit::REFUSAL,
            format!(
                "instrument `{}` has unit {}, which is rejected by mirrored account `{}`",
                spec.code, unit_def.code, acct.code
            ),
            "plan §4.3, §4.5 (Instrument.unit must be admitted by its mirrored account's unit_policy)",
            "match the instrument's unit to the mirrored account's unit policy",
        )));
    }
    if let Some(refusal) = check_external_id_conflicts(&txn, db, &resolved_ext)? {
        txn.abort();
        return Ok(Err(refusal));
    }

    let root = book_root();
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);

    let mut inst_props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("instrument._fa_payload", canonical_bytes)?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("code", &spec.code)?),
        (property::NAME, scalar_text("name", &spec.name)?),
        (
            property::UNIT_ID,
            CanonicalScalar::Int(i64::from(spec.unit.0)),
        ),
    ];
    inst_props.sort_by_key(|(k, _)| k.0);
    in_book.create_vertex(ivid, vec![label::INSTRUMENT], inst_props);
    in_book.add_edge(edge_id(relation::IN_BOOK, ivid, root), ivid, root, vec![]);

    stage_external_id_vertices(book, ivid, &resolved_ext, &mut in_book)?;

    let mut held_at = WriteBatch::new(relation::HELD_AT);
    held_at.add_edge(
        edge_id(relation::HELD_AT, ivid, spec.held_at_party),
        ivid,
        spec.held_at_party,
        vec![],
    );
    let mut mirrors = WriteBatch::new(relation::MIRRORS);
    mirrors.add_edge(
        edge_id(relation::MIRRORS, ivid, spec.mirrors_account),
        ivid,
        spec.mirrors_account,
        vec![],
    );

    if let Err(e) = txn.write_ordered(db, vec![in_book, held_at, mirrors]) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ReaControlRecorded {
            recorded_at: seq,
            control_entry: evid,
            target_vid: ivid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated create_instrument's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry create_instrument against the new frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "concurrent create_instrument collided on a derived Instrument or ExternalId vertex",
            "plan §4.9 (derived identity uniqueness; FA-INV-09)",
            "inspect existing instruments and external_ids before retrying",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Journal and materialize or enrich a `LegalEntity` vertex (`SchemaChange`
/// `kind = 7`, plan §4.1, §4.5, bead `fa-l2h`), its `DimensionValue` vertex
/// (`LEGAL_ENTITY_DIMENSION`), `REPRESENTS` binding edge, and any declared
/// `ExternalId` vertices.
#[allow(clippy::too_many_arguments)]
pub async fn create_legal_entity<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &LegalEntityFullSpec,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if spec.code.is_empty() || spec.code.len() > 32 {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("legal entity code `{}` must be 1..=32 bytes", spec.code),
            "Appendix A LegalEntity.code",
            "provide a non-empty legal entity code of at most 32 bytes",
        )));
    }
    if spec.name.is_empty() || spec.name.len() > MAX_REA_NAME_BYTES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "legal entity `{}` name must be 1..={MAX_REA_NAME_BYTES} bytes",
                spec.code
            ),
            "Appendix A LegalEntity.name",
            "provide a non-empty legal entity name of at most 256 bytes",
        )));
    }
    if spec.jurisdiction.is_empty() || spec.jurisdiction.len() > MAX_JURISDICTION_BYTES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "legal entity `{}` jurisdiction must be 1..={MAX_JURISDICTION_BYTES} bytes",
                spec.code
            ),
            "Appendix A LegalEntity.jurisdiction",
            "provide a non-empty jurisdiction code (e.g. `US-DE`, `GB`)",
        )));
    }
    if let (Some(formed), Some(dissolved)) = (spec.formed, spec.dissolved)
        && formed >= dissolved
    {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "legal entity `{}` has formed date {formed} >= dissolved date {dissolved}",
                spec.code
            ),
            "Appendix A LegalEntity (formed < dissolved)",
            "set dissolved to None or a date strictly after formed",
        )));
    }
    let base_unit = match db
        .vertex(book_root())?
        .and_then(|r| prop(&r, property::BASE_UNIT).cloned())
    {
        Some(CanonicalScalar::Int(u)) => u32::try_from(u)
            .map(fa_money::UnitId)
            .map_err(|_| KernelError::Corrupt(format!("book.base_unit {u} out of u32 range")))?,
        other => {
            return Err(KernelError::Corrupt(format!(
                "book.base_unit missing or invalid on book root: {other:?}"
            )));
        }
    };
    if let Err(refusal) = crate::genesis::check_entity_functional_unit(
        &spec.code,
        spec.functional_unit,
        base_unit,
        &book.units,
    ) {
        return Ok(Err(refusal));
    }
    let resolved_ext = match open_external_ids(book, &spec.external_ids)? {
        Ok(v) => v,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let canonical_bytes = spec.encode().map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_CREATE_LEGAL_ENTITY,
        canonical_bytes.clone(),
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let levid = legal_entity_vid(book.book_id, &spec.code);
    let eval_vid = entity_value_vid(book.book_id, &spec.code);
    let dim_vid = dimension_vid(book.book_id, LEGAL_ENTITY_DIMENSION_CODE);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_rea_idempotency(book, &row, levid, &proposal, &proposal_digest);
    }
    if let Some(refusal) = check_external_id_conflicts(&txn, db, &resolved_ext)? {
        txn.abort();
        return Ok(Err(refusal));
    }

    let existing_le = txn.vertex(db, levid)?;
    if let Some(ref row) = existing_le {
        if prop(row, property::FA_PAYLOAD).is_some() {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!("legal entity `{}` already exists in this book", spec.code),
                "plan §4.1, §4.9 (LegalEntity codes are unique derived identities)",
                "use a distinct legal entity code",
            )));
        }
        let existing_name = text(row, property::NAME, "legal_entity.name")?;
        if existing_name != spec.name {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "legal entity `{}` was declared at genesis with name `{existing_name}`, not `{}`",
                    spec.code, spec.name
                ),
                "plan §4.1 (lifting a genesis LegalEntity preserves its declared name)",
                "keep the genesis LegalEntity's declared name when enriching its REA specification",
            )));
        }
    }

    let need_dim = txn.vertex(db, dim_vid)?.is_none();
    let root = book_root();
    let book_id_scalar = scalar_bytes("book_id", book.book_id.0.to_vec())?;
    let dim_id_scalar = CanonicalScalar::Int(i64::from(LEGAL_ENTITY_DIMENSION));

    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    if need_dim {
        let mut dim_props = vec![
            (property::BOOK_ID, book_id_scalar.clone()),
            (
                property::CODE,
                scalar_text("code", LEGAL_ENTITY_DIMENSION_CODE)?,
            ),
            (property::NAME, scalar_text("name", "Legal entity")?),
            (property::DIMENSION_ID, dim_id_scalar.clone()),
            (
                property::DIMENSION_KIND,
                CanonicalScalar::Int(DIMENSION_KIND_LEGAL_ENTITY),
            ),
        ];
        dim_props.sort_by_key(|(k, _)| k.0);
        in_book.create_vertex(dim_vid, vec![label::DIMENSION], dim_props);
        in_book.add_edge(
            edge_id(relation::IN_BOOK, dim_vid, root),
            dim_vid,
            root,
            vec![],
        );
    }

    let mut represents = WriteBatch::new(relation::REPRESENTS);
    if existing_le.is_some() {
        in_book.compare_and_set_vertex_property(
            levid,
            property::FA_PAYLOAD,
            None,
            scalar_bytes("legal_entity._fa_payload", canonical_bytes)?,
            WriteMismatchPolicy::AbortWrite,
        );
    } else {
        let mut le_props = vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("legal_entity._fa_payload", canonical_bytes)?,
            ),
            (property::BOOK_ID, book_id_scalar.clone()),
            (property::CODE, scalar_text("code", &spec.code)?),
            (property::NAME, scalar_text("name", &spec.name)?),
            (
                property::UNIT_ID,
                CanonicalScalar::Int(i64::from(spec.functional_unit.0)),
            ),
        ];
        le_props.sort_by_key(|(k, _)| k.0);
        in_book.create_vertex(levid, vec![label::LEGAL_ENTITY], le_props);
        in_book.add_edge(edge_id(relation::IN_BOOK, levid, root), levid, root, vec![]);

        let mut dval_props = vec![
            (property::BOOK_ID, book_id_scalar),
            (property::CODE, scalar_text("code", &spec.code)?),
            (property::DIMENSION_ID, dim_id_scalar),
        ];
        dval_props.sort_by_key(|(k, _)| k.0);
        in_book.create_vertex(eval_vid, vec![label::DIMENSION_VALUE], dval_props);
        in_book.add_edge(
            edge_id(relation::IN_BOOK, eval_vid, root),
            eval_vid,
            root,
            vec![],
        );
        represents.add_edge(
            edge_id(relation::REPRESENTS, levid, eval_vid),
            levid,
            eval_vid,
            vec![],
        );
    }

    stage_external_id_vertices(book, levid, &resolved_ext, &mut in_book)?;

    let mut batches = vec![in_book];
    if !represents.is_empty() {
        batches.push(represents);
    }
    if let Err(e) = txn.write_ordered(db, batches) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ReaControlRecorded {
            recorded_at: seq,
            control_entry: evid,
            target_vid: levid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated create_legal_entity's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry create_legal_entity against the new frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "concurrent create_legal_entity collided on a derived LegalEntity or ExternalId vertex",
            "plan §4.9 (derived identity uniqueness; FA-INV-09)",
            "inspect existing legal entities and external_ids before retrying",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Bind an `ExternalId` vertex (`SchemaChange` `kind = 8`, plan §4.5, §4.9,
/// bead `fa-l2h`) to an existing `Party`, `Instrument`, or `LegalEntity`.
#[allow(clippy::too_many_arguments)]
pub async fn bind_external_id<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    binding: &ExternalIdBinding,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    let resolved_ext = match open_external_ids(book, std::slice::from_ref(&binding.external_id))? {
        Ok(v) => v,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let ext_vid = resolved_ext[0].0;

    let canonical_bytes = binding.encode().map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_BIND_EXTERNAL_ID,
        canonical_bytes,
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_rea_idempotency(book, &row, ext_vid, &proposal, &proposal_digest);
    }
    let target_ok = txn.vertex(db, binding.target_vid)?.is_some_and(|row| {
        row.labels.contains(&label::PARTY)
            || row.labels.contains(&label::INSTRUMENT)
            || row.labels.contains(&label::LEGAL_ENTITY)
            || row.labels.contains(&label::EVENT)
    });
    if !target_ok {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "bind_external_id target {:032x} is not an existing Party, Instrument, LegalEntity, or Event in this book",
                binding.target_vid.0
            ),
            "plan §4.5, §4.9",
            "create the target Party, Instrument, LegalEntity, or Event before binding an ExternalId to it",
        )));
    }
    if let Some(refusal) = check_external_id_conflicts(&txn, db, &resolved_ext)? {
        txn.abort();
        return Ok(Err(refusal));
    }

    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    stage_external_id_vertices(book, binding.target_vid, &resolved_ext, &mut in_book)?;

    if let Err(e) = txn.write_ordered(db, vec![in_book]) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ReaControlRecorded {
            recorded_at: seq,
            control_entry: evid,
            target_vid: ext_vid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated bind_external_id's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry bind_external_id against the new frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "concurrent bind_external_id collided on the derived ExternalId vertex",
            "plan §4.9 (derived identity uniqueness; FA-INV-09)",
            "inspect existing external_ids before retrying",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Journal and materialize a valid-time `[valid_from, valid_to)` relationship
/// edge (`OWNS`, `CONTROLS`, or `RELATED_TO`, `SchemaChange` `kind = 9`, plan §4.5,
/// bead `fa-l2h`) between two `Party` / `LegalEntity` vertices under a basis
/// registered in `registries/relationship_bases.toml`.
#[allow(clippy::too_many_arguments)]
pub async fn record_relationship<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &RelationshipSpec,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if spec.from == spec.to {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "relationship endpoint {:032x} cannot relate to itself",
                spec.from.0
            ),
            "plan §4.5 (OWNS, CONTROLS, and RELATED_TO connect two distinct Party/LegalEntity vertices)",
            "specify two distinct endpoints (`from != to`)",
        )));
    }
    if !spec.kind.is_valid_pct() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "OWNS relationship pct {:?} must satisfy 0 < pct <= 1",
                spec.kind
            ),
            "plan §4.5, registries/relationship_bases.toml (OWNS pct is an exact rational in (0, 1])",
            "supply an exact Rate with 0 < num <= den",
        )));
    }
    if let Some(valid_to) = spec.valid_to
        && spec.valid_from >= valid_to
    {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "relationship valid-time interval [{}, {valid_to}) requires valid_from < valid_to",
                spec.valid_from
            ),
            "plan §4.5 (half-open valid-time interval [from, to))",
            "set valid_to to None or a date strictly after valid_from",
        )));
    }
    let bases = RelationshipBases::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let expected_edge_kind = spec.kind.edge_kind_name();
    let Some(basis_row) = bases.rows.iter().find(|r| r.code == spec.basis) else {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "relationship basis `{}` is not registered in registries/relationship_bases.toml",
                spec.basis
            ),
            "plan §4.5, registries/relationship_bases.toml",
            "use a registered relationship basis code (e.g. `equity_voting`, `beneficial_ownership`, `majority_voting_control`, `common_control`)",
        )));
    };
    if basis_row.edge_kind != expected_edge_kind {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "relationship basis `{}` is registered for `{}` edges, not `{expected_edge_kind}`",
                spec.basis, basis_row.edge_kind
            ),
            "plan §4.5, registries/relationship_bases.toml",
            format!(
                "use a basis registered for `{expected_edge_kind}` or change the relationship kind to `{}`",
                basis_row.edge_kind
            ),
        )));
    }

    let canonical_bytes = spec.encode().map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_RECORD_RELATIONSHIP,
        canonical_bytes.clone(),
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_rea_idempotency(book, &row, spec.from, &proposal, &proposal_digest);
    }
    for (role_label, endpoint) in [("from", spec.from), ("to", spec.to)] {
        let ok = txn.vertex(db, endpoint)?.is_some_and(|row| {
            row.labels.contains(&label::PARTY) || row.labels.contains(&label::LEGAL_ENTITY)
        });
        if !ok {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "relationship `{role_label}` endpoint {:032x} is not an existing Party or LegalEntity in this book",
                    endpoint.0
                ),
                "plan §4.5 (OWNS, CONTROLS, and RELATED_TO connect Party and LegalEntity vertices)",
                "create both endpoint Party/LegalEntity vertices before recording a relationship edge",
            )));
        }
    }

    let rel_id = spec.kind.relation_id();
    let rel_eid = relationship_edge_id(rel_id, spec.from, spec.to, &spec.basis, spec.valid_from);
    let mut rel_batch = WriteBatch::new(rel_id);
    rel_batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    rel_batch.add_edge(
        rel_eid,
        spec.from,
        spec.to,
        vec![(
            property::FA_PAYLOAD,
            scalar_bytes("relationship._fa_payload", canonical_bytes)?,
        )],
    );

    if let Err(e) = txn.write_ordered(db, vec![rel_batch]) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ReaControlRecorded {
            recorded_at: seq,
            control_entry: evid,
            target_vid: spec.from,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated record_relationship's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry record_relationship against the new frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "relationship edge with the same (kind, from, to, basis, valid_from) is already recorded",
            "plan §4.5, §4.9 (relationship edge identity uniqueness; FA-INV-09)",
            "use a distinct valid_from or basis if recording a new relationship period",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Journal an update to a `Party`'s identifiers (e.g. bank routing/account
/// metadata, `SchemaChange` `kind = 10`, plan §4.5, §14.4 BEC vector, bead `fa-l2h`).
#[allow(clippy::too_many_arguments)]
pub async fn update_party_identifiers<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    update: &PartyIdentifierUpdate,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if update.identifiers.len() > MAX_PARTY_IDENTIFIERS {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "party identifier update has {} identifiers (max {MAX_PARTY_IDENTIFIERS})",
                update.identifiers.len()
            ),
            "Appendix A Party.identifiers",
            "reduce the number of party identifiers",
        )));
    }
    for (k, _) in &update.identifiers {
        if k.is_empty() || k.len() > MAX_IDENTIFIER_KEY_BYTES {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!("party identifier key `{k}` must be 1..=64 bytes"),
                "Appendix A Party.identifiers",
                "use a non-empty identifier key of at most 64 bytes",
            )));
        }
    }
    for pair in update.identifiers.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                "party identifiers must be strictly ascending by key",
                "Appendix A Party.identifiers",
                "sort party identifiers strictly ascending by key",
            )));
        }
    }

    let canonical_bytes = update.encode().map_err(fa_model::EntryError::from)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS,
        canonical_bytes,
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_rea_idempotency(book, &row, update.party_vid, &proposal, &proposal_digest);
    }
    let Some(party_row) = txn.vertex(db, update.party_vid)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "party {:032x} does not exist in this book",
                update.party_vid.0
            ),
            "plan §4.5",
            "create the Party first (`fa party create`)",
        )));
    };
    if !party_row.labels.contains(&label::PARTY) {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("vertex {:032x} is not a Party", update.party_vid.0),
            "plan §4.5",
            "cite an existing Party vertex",
        )));
    }
    let old_payload = bytes(&party_row, property::FA_PAYLOAD, "party._fa_payload")?;
    let mut updated_spec = PartySpec::decode(&old_payload)
        .map_err(|e| KernelError::Corrupt(format!("party._fa_payload: {e}")))?;
    updated_spec.identifiers.clone_from(&update.identifiers);
    let new_payload = updated_spec.encode().map_err(fa_model::EntryError::from)?;

    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        update.party_vid,
        property::FA_PAYLOAD,
        Some(scalar_bytes("party._fa_payload", old_payload)?),
        scalar_bytes("party._fa_payload", new_payload)?,
        WriteMismatchPolicy::AbortWrite,
    );

    if let Err(e) = txn.write_ordered(db, vec![batch]) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ReaControlRecorded {
            recorded_at: seq,
            control_entry: evid,
            target_vid: update.party_vid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!(
                    "a concurrent commit invalidated update_party_identifiers's witness: {detail}"
                ),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry update_party_identifiers against the new frontier",
            )))
        }
        Err(e) => Err(e.into()),
    }
}

fn admit_event_record<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    principal_ref: VId,
    capability: &Capability,
) -> Result<Option<Refusal>, KernelError> {
    let post_ok = fa_policy::admit_within(
        capability,
        &fa_policy::Intent {
            principal: principal_ref,
            trunk: true,
            op: fa_policy::Op::Post,
            book: book.book_id,
            legs: &[],
        },
        &fa_policy::Reach::whole_book(true),
        None,
    );
    if let Err(post_denial) = post_ok {
        let schema_ok = fa_policy::admit_within(
            capability,
            &fa_policy::Intent {
                principal: principal_ref,
                trunk: true,
                op: fa_policy::Op::SchemaChange,
                book: book.book_id,
                legs: &[],
            },
            &fa_policy::Reach::whole_book(true),
            None,
        );
        if schema_ok.is_err() {
            return Ok(Some(crate::policy::refusal(&post_denial)));
        }
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Some(crate::policy::refusal(&d)));
    }
    Ok(None)
}

/// Journal and materialize an REA economic `Event` vertex (`SchemaChange` `kind = 11`,
/// plan §4.1 `Event`, §4.5, FA-INV-05, bead `fa-f3bo`), witness its cited `evidence`
/// documents, `participants`, and `resources`, and stage `EVIDENCED_BY` edges and any
/// declared `ExternalId` vertices.
#[allow(clippy::too_many_arguments)]
pub async fn record_event<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &EventSpec,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    if let Some(refusal) = admit_event_record(db, book, principal_ref, capability)? {
        return Ok(Err(refusal));
    }
    if spec.code.is_empty() || spec.code.len() > MAX_REA_CODE_BYTES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "event code `{}` must be 1..={MAX_REA_CODE_BYTES} bytes",
                spec.code
            ),
            "Appendix A Event.code",
            "provide a non-empty event code of at most 64 bytes",
        )));
    }
    if spec.participants.len() > MAX_EVENT_PARTICIPANTS {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "event `{}` has {} participants (max {MAX_EVENT_PARTICIPANTS})",
                spec.code,
                spec.participants.len()
            ),
            "Appendix A Event.participants",
            "reduce the number of event participants",
        )));
    }
    for pair in spec.participants.windows(2) {
        if pair[0] >= pair[1] {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "event `{}` participants must be distinct and strictly ascending by VId",
                    spec.code
                ),
                "Appendix A Event.participants",
                "sort and deduplicate event participants by VId",
            )));
        }
    }
    if spec.resources.len() > MAX_EVENT_RESOURCES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "event `{}` has {} resources (max {MAX_EVENT_RESOURCES})",
                spec.code,
                spec.resources.len()
            ),
            "Appendix A Event.resources",
            "reduce the number of event resources",
        )));
    }
    for (idx, res) in spec.resources.iter().enumerate() {
        if res.label.is_empty() || res.label.len() > MAX_EVENT_RESOURCE_LABEL_BYTES {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "event `{}` resource[{idx}] label `{}` must be 1..={MAX_EVENT_RESOURCE_LABEL_BYTES} bytes",
                    spec.code, res.label
                ),
                "Appendix A Event.resources",
                "provide a non-empty resource label of at most 64 bytes",
            )));
        }
        if book.units.get(res.amount.unit).is_none() {
            return Ok(Err(Refusal::new(
                code::UNIT_UNREGISTERED,
                exit::REFUSAL,
                format!(
                    "event `{}` resource[{idx}] (`{}`) names unregistered unit id {}",
                    spec.code, res.label, res.amount.unit.0
                ),
                "plan §4.1 Event, §4.4",
                "use a unit registered in the book",
            )));
        }
        if res.amount.mantissa <= 0 {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "event `{}` resource[{idx}] (`{}`) amount must be strictly positive (got {})",
                    spec.code, res.label, res.amount.mantissa
                ),
                "Appendix A Event.resources",
                "provide a positive resource amount",
            )));
        }
    }
    if spec.evidence.is_empty() {
        return Ok(Err(Refusal::new(
            code::EVIDENCE_MINIMUM,
            exit::REFUSAL,
            format!(
                "event `{}` cites no evidence documents; every Event requires at least 1 evidence document",
                spec.code
            ),
            "plan §4.1 Event, §4.5, FA-INV-05 (every Event vertex cites non-empty evidence)",
            "record the source document with `fa document add <file> --kind <Kind> --json` and cite it on the event",
        )));
    }
    if spec.evidence.len() > MAX_EVIDENCE_PER_ENTRY {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "event `{}` cites {} evidence items (max {MAX_EVIDENCE_PER_ENTRY})",
                spec.code,
                spec.evidence.len()
            ),
            "Appendix A Event.evidence",
            "reduce the number of evidence citations",
        )));
    }
    for pair in spec.evidence.windows(2) {
        if pair[0] >= pair[1] {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "event `{}` evidence citations must be strictly ascending by (document_oid, doc_commit, role)",
                    spec.code
                ),
                "Appendix A Event.evidence",
                "sort and deduplicate evidence citations",
            )));
        }
    }
    let resolved_ext = match open_external_ids(book, &spec.external_ids)? {
        Ok(v) => v,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let canonical_bytes = spec.encode().map_err(fa_model::EntryError::from)?;
    let event_digest = spec.event_digest().map_err(fa_model::EntryError::from)?;
    let mut proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_RECORD_EVENT,
        canonical_bytes.clone(),
        principal_ref,
        effective_date,
        idempotency_key,
        description,
    );
    proposal.evidence.clone_from(&spec.evidence);
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let ev_vid = event_vid(book.book_id, &spec.code);

    let evidence_policy =
        EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return check_rea_idempotency(book, &row, ev_vid, &proposal, &proposal_digest);
    }
    if txn.vertex(db, ev_vid)?.is_some() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("event `{}` already exists in this book", spec.code),
            "plan §4.1 Event, §4.9 (Event codes are unique derived identities)",
            "use a distinct event code or cite the existing Event vertex",
        )));
    }
    for participant in &spec.participants {
        let ok = txn.vertex(db, *participant)?.is_some_and(|row| {
            row.labels.contains(&label::PARTY)
                || row.labels.contains(&label::INSTRUMENT)
                || row.labels.contains(&label::LEGAL_ENTITY)
        });
        if !ok {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "event `{}` participant {:032x} is not an existing Party, Instrument, or LegalEntity in this book",
                    spec.code, participant.0
                ),
                "plan §4.1 Event, §4.5",
                "create all participant Party/Instrument/LegalEntity vertices before recording the event",
            )));
        }
    }
    for (idx, res) in spec.resources.iter().enumerate() {
        if let Some(inst) = res.instrument {
            let ok = txn
                .vertex(db, inst)?
                .is_some_and(|row| row.labels.contains(&label::INSTRUMENT));
            if !ok {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::STRUCTURE,
                    exit::USAGE,
                    format!(
                        "event `{}` resource[{idx}] (`{}`) instrument {:032x} is not an existing Instrument in this book",
                        spec.code, res.label, inst.0
                    ),
                    "plan §4.1 Event, §4.5",
                    "create the Instrument first (`fa instrument create`) before citing it on an event resource",
                )));
            }
        }
    }
    let cited_docs =
        match crate::evidence::resolve_documents(&txn, db, &evidence_policy, &spec.evidence)? {
            Ok(docs) => docs,
            Err(r) => {
                txn.abort();
                return Ok(Err(r));
            }
        };
    for c in &cited_docs {
        let is_self_sourced = evidence_policy
            .grade_by_tag(c.grade)
            .is_some_and(|g| g.self_sourced);
        if is_self_sourced {
            let review = match crate::attestation::witness_review(&txn, db, book.book_id, &c.oid)? {
                Ok(r) => r,
                Err(r) => {
                    txn.abort();
                    return Ok(Err(r));
                }
            };
            match review {
                Some(r) if r.reviewer == c.uploader => {
                    txn.abort();
                    return Ok(Err(crate::attestation::self_review_refusal(
                        &c.oid, r.reviewer,
                    )));
                }
                Some(_) => {}
                None => {
                    txn.abort();
                    return Ok(Err(Refusal::new(
                        code::SELF_SOURCED,
                        exit::REFUSAL,
                        format!(
                            "event `{}` cites self-sourced document {:064x} which has not been reviewed by a distinct principal",
                            spec.code,
                            u128::from_be_bytes(c.oid.0[..16].try_into().unwrap_or([0; 16]))
                        ),
                        "plan §9.3 (self-sourced evidence counts only once an approver other than the uploader records a Reviewed attestation)",
                        "record a Reviewed attestation over the document from a distinct principal with `approve`, or cite a HumanUpload document",
                    )));
                }
            }
        }
    }
    if let Some(refusal) = check_external_id_conflicts(&txn, db, &resolved_ext)? {
        txn.abort();
        return Ok(Err(refusal));
    }

    let root = book_root();
    let book_id_scalar = scalar_bytes("book_id", book.book_id.0.to_vec())?;
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);

    let mut ev_props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("event._fa_payload", canonical_bytes)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("event._fa_digest", event_digest.to_vec())?,
        ),
        (property::BOOK_ID, book_id_scalar),
        (property::CODE, scalar_text("code", &spec.code)?),
        (
            property::FA_EFFECTIVE_DAY,
            CanonicalScalar::Int(i64::from(spec.occurred_on.0)),
        ),
    ];
    ev_props.sort_by_key(|(k, _)| k.0);
    in_book.create_vertex(ev_vid, vec![label::EVENT], ev_props);
    in_book.add_edge(
        edge_id(relation::IN_BOOK, ev_vid, root),
        ev_vid,
        root,
        vec![],
    );
    stage_external_id_vertices(book, ev_vid, &resolved_ext, &mut in_book)?;

    let mut doc_vids: Vec<VId> = cited_docs.iter().map(|c| c.vid).collect();
    doc_vids.sort_unstable();
    doc_vids.dedup();
    let mut evidenced = WriteBatch::new(relation::EVIDENCED_BY);
    for dvid in &doc_vids {
        evidenced.add_edge(
            edge_id(relation::EVIDENCED_BY, ev_vid, *dvid),
            ev_vid,
            *dvid,
            vec![],
        );
        evidenced.add_edge(
            edge_id(relation::EVIDENCED_BY, evid, *dvid),
            evid,
            *dvid,
            vec![],
        );
    }

    let mut batches = vec![in_book];
    if !evidenced.is_empty() {
        batches.push(evidenced);
    }
    if let Err(e) = txn.write_ordered(db, batches) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ReaControlRecorded {
            recorded_at: seq,
            control_entry: evid,
            target_vid: ev_vid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated record_event's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry record_event against the new frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "concurrent record_event collided on a derived Event or ExternalId vertex",
            "plan §4.9 (derived identity uniqueness; FA-INV-09)",
            "inspect existing events and external_ids before retrying",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Rebuild the journaled REA graph snapshot at `known_at` from genesis +
/// `SchemaChange` controls (`kind = 5..=11`), and verify stored `Party`,
/// `Instrument`, `LegalEntity`, `ExternalId`, `Event`, and `CONTROLS` edges against it.
pub fn read_rea_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: CommitSeq,
) -> Result<ReaSnapshot, KernelError> {
    if known_at > db.frontier()? {
        return Err(corrupt("requested frontier is beyond the book head"));
    }
    let book_spec =
        read_book_spec(db)?.ok_or_else(|| corrupt("no book spec on the root vertex"))?;
    let rows = db.vertices_at(known_at)?;
    let stored_edges = db.edges_at(known_at)?;
    let vertices_by_vid: BTreeMap<VId, &VertexRow> = rows.iter().map(|r| (r.vid, r)).collect();

    let mut legal_entities: BTreeMap<VId, LegalEntityRow> = BTreeMap::new();
    for e in &book_spec.entities {
        if e.functional_unit != book_spec.base_unit {
            return Err(corrupt(format!(
                "genesis legal entity `{}` has functional_unit {} != book base_unit {}",
                e.code, e.functional_unit.0, book_spec.base_unit.0
            )));
        }
        let vid = legal_entity_vid(book.book_id, &e.code);
        let dval = entity_value_vid(book.book_id, &e.code);
        let created_at = vertices_by_vid
            .get(&vid)
            .map_or(CommitSeq(1), |r| r.created_at);
        legal_entities.insert(
            vid,
            LegalEntityRow {
                vid,
                dimension_value_vid: dval,
                code: e.code.clone(),
                name: e.name.clone(),
                jurisdiction: String::new(),
                functional_unit: e.functional_unit,
                formed: None,
                dissolved: None,
                external_ids: Vec::new(),
                created_at,
            },
        );
    }

    let mut controls = Vec::new();
    for row in &rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "rea entry payload")?)?;
        if entry.proposal.class != EntryClass::SCHEMA_CONTROL {
            continue;
        }
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(corrupt(
                "a schema control belongs to another book or branch",
            ));
        }
        if !matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::CHART_INSTALL,
                ..
            }
        ) {
            return Err(corrupt("unsupported schema-control origin"));
        }
        if let Some(ControlPayload::SchemaChange {
            kind,
            canonical_bytes,
        }) = &entry.proposal.control
            && ReaControlOp::is_rea_schema_change_kind(*kind)
        {
            let op = ReaControlOp::decode(*kind, canonical_bytes)
                .map_err(|e| corrupt(format!("rea control {:032x}: {e}", row.vid.0)))?;
            controls.push((row.created_at, row.vid, op));
        }
    }
    controls.sort_by_key(|(created_at, vid, _)| (*created_at, *vid));

    let mut parties: BTreeMap<VId, PartyRow> = BTreeMap::new();
    let mut instruments: BTreeMap<VId, InstrumentRow> = BTreeMap::new();
    let mut external_ids: BTreeMap<VId, ExternalIdRow> = BTreeMap::new();
    let mut relationships: Vec<RelationshipRow> = Vec::new();
    let mut events: BTreeMap<VId, EventRow> = BTreeMap::new();

    let register_ext = |target_vid: VId,
                        target_code: &str,
                        ext: &ExternalId,
                        created_at: CommitSeq,
                        external_ids: &mut BTreeMap<VId, ExternalIdRow>|
     -> Result<(), KernelError> {
        let plain = ext
            .id
            .open(&book.seal_key, MAX_EXTERNAL_ID_BYTES)
            .map_err(|e| corrupt(format!("external_id on `{target_code}`: {e}")))?;
        let ext_vid = external_id_vid(book.book_id, &ext.system, &plain);
        if external_ids
            .insert(
                ext_vid,
                ExternalIdRow {
                    vid: ext_vid,
                    target_vid,
                    target_code: target_code.to_string(),
                    external_id: ext.clone(),
                    plain_id: plain,
                    created_at,
                },
            )
            .is_some()
        {
            return Err(corrupt(format!(
                "duplicate ExternalId {:032x} in control replay",
                ext_vid.0
            )));
        }
        Ok(())
    };

    for (created_at, control_vid, op) in controls {
        match op {
            ReaControlOp::CreateParty(spec) => {
                let vid = party_vid(book.book_id, &spec.code);
                let dval = party_value_vid(book.book_id, &spec.code);
                for ext in &spec.external_ids {
                    register_ext(vid, &spec.code, ext, created_at, &mut external_ids)?;
                }
                if parties
                    .insert(
                        vid,
                        PartyRow {
                            vid,
                            dimension_value_vid: dval,
                            code: spec.code,
                            kind: spec.kind,
                            name: spec.name,
                            identifiers: spec.identifiers,
                            external_ids: spec.external_ids,
                            created_at,
                        },
                    )
                    .is_some()
                {
                    return Err(corrupt(format!("duplicate Party {:032x}", vid.0)));
                }
            }
            ReaControlOp::CreateInstrument(spec) => {
                let vid = instrument_vid(book.book_id, &spec.code);
                for ext in &spec.external_ids {
                    register_ext(vid, &spec.code, ext, created_at, &mut external_ids)?;
                }
                if instruments
                    .insert(
                        vid,
                        InstrumentRow {
                            vid,
                            code: spec.code,
                            name: spec.name,
                            kind: spec.kind,
                            unit: spec.unit,
                            held_at_party: spec.held_at_party,
                            mirrors_account: spec.mirrors_account,
                            external_ids: spec.external_ids,
                            created_at,
                        },
                    )
                    .is_some()
                {
                    return Err(corrupt(format!("duplicate Instrument {:032x}", vid.0)));
                }
            }
            ReaControlOp::CreateLegalEntity(spec) => {
                if spec.functional_unit != book_spec.base_unit {
                    return Err(corrupt(format!(
                        "journaled LegalEntity `{}` has functional_unit {} != book base_unit {}",
                        spec.code, spec.functional_unit.0, book_spec.base_unit.0
                    )));
                }
                let vid = legal_entity_vid(book.book_id, &spec.code);
                let dval = entity_value_vid(book.book_id, &spec.code);
                for ext in &spec.external_ids {
                    register_ext(vid, &spec.code, ext, created_at, &mut external_ids)?;
                }
                legal_entities.insert(
                    vid,
                    LegalEntityRow {
                        vid,
                        dimension_value_vid: dval,
                        code: spec.code,
                        name: spec.name,
                        jurisdiction: spec.jurisdiction,
                        functional_unit: spec.functional_unit,
                        formed: spec.formed,
                        dissolved: spec.dissolved,
                        external_ids: spec.external_ids,
                        created_at,
                    },
                );
            }
            ReaControlOp::BindExternalId(binding) => {
                let target_code = parties
                    .get(&binding.target_vid)
                    .map(|p| p.code.clone())
                    .or_else(|| {
                        legal_entities
                            .get(&binding.target_vid)
                            .map(|le| le.code.clone())
                    })
                    .or_else(|| instruments.get(&binding.target_vid).map(|i| i.code.clone()))
                    .or_else(|| {
                        events
                            .get(&binding.target_vid)
                            .map(|ev| ev.spec.code.clone())
                    })
                    .ok_or_else(|| {
                        corrupt(format!(
                            "BindExternalId references absent target {:032x}",
                            binding.target_vid.0
                        ))
                    })?;
                register_ext(
                    binding.target_vid,
                    &target_code,
                    &binding.external_id,
                    created_at,
                    &mut external_ids,
                )?;
                if let Some(p) = parties.get_mut(&binding.target_vid) {
                    p.external_ids.push(binding.external_id);
                } else if let Some(le) = legal_entities.get_mut(&binding.target_vid) {
                    le.external_ids.push(binding.external_id);
                } else if let Some(inst) = instruments.get_mut(&binding.target_vid) {
                    inst.external_ids.push(binding.external_id);
                } else if let Some(ev) = events.get_mut(&binding.target_vid) {
                    ev.spec.external_ids.push(binding.external_id);
                }
            }
            ReaControlOp::RecordRelationship(spec) => {
                let eid = relationship_edge_id(
                    spec.kind.relation_id(),
                    spec.from,
                    spec.to,
                    &spec.basis,
                    spec.valid_from,
                );
                relationships.push(RelationshipRow {
                    eid,
                    spec,
                    recorded_at: created_at,
                    control_entry: control_vid,
                });
            }
            ReaControlOp::UpdatePartyIdentifiers(update) => {
                let party = parties.get_mut(&update.party_vid).ok_or_else(|| {
                    corrupt(format!(
                        "UpdatePartyIdentifiers references absent party {:032x}",
                        update.party_vid.0
                    ))
                })?;
                party.identifiers = update.identifiers;
            }
            ReaControlOp::RecordEvent(spec) => {
                let vid = event_vid(book.book_id, &spec.code);
                let event_digest = spec
                    .event_digest()
                    .map_err(|e| corrupt(format!("event `{}` digest: {e}", spec.code)))?;
                for ext in &spec.external_ids {
                    register_ext(vid, &spec.code, ext, created_at, &mut external_ids)?;
                }
                if events
                    .insert(
                        vid,
                        EventRow {
                            vid,
                            spec,
                            event_digest,
                            created_at,
                            control_entry: control_vid,
                        },
                    )
                    .is_some()
                {
                    return Err(corrupt(format!("duplicate Event {:032x}", vid.0)));
                }
            }
        }
    }

    // Verify stored PARTY, INSTRUMENT, EXTERNAL_ID, EVENT vertices and CONTROLS edge discipline.
    for row in &rows {
        if row.labels.contains(&label::PARTY) && !parties.contains_key(&row.vid) {
            return Err(corrupt(format!(
                "Party vertex {:032x} has no journaled CreateParty declaration",
                row.vid.0
            )));
        }
        if row.labels.contains(&label::INSTRUMENT) && !instruments.contains_key(&row.vid) {
            return Err(corrupt(format!(
                "Instrument vertex {:032x} has no journaled CreateInstrument declaration",
                row.vid.0
            )));
        }
        if row.labels.contains(&label::EXTERNAL_ID) && !external_ids.contains_key(&row.vid) {
            return Err(corrupt(format!(
                "ExternalId vertex {:032x} has no journaled declaration",
                row.vid.0
            )));
        }
        if row.labels.contains(&label::EVENT) {
            let Some(expected) = events.get(&row.vid) else {
                return Err(corrupt(format!(
                    "Event vertex {:032x} has no journaled RecordEvent declaration",
                    row.vid.0
                )));
            };
            let stored_digest = bytes(row, property::FA_DIGEST, "event._fa_digest")?;
            if stored_digest.as_slice() != expected.event_digest.as_slice() {
                return Err(corrupt(format!(
                    "Event vertex {:032x} _fa_digest does not match journaled RecordEvent",
                    row.vid.0
                )));
            }
        }
    }
    for (ev_vid, ev_row) in &events {
        if !vertices_by_vid
            .get(ev_vid)
            .is_some_and(|r| r.labels.contains(&label::EVENT))
        {
            return Err(corrupt(format!(
                "journaled Event `{}` ({:032x}) is missing its Event vertex",
                ev_row.spec.code, ev_vid.0
            )));
        }
    }
    for edge in &stored_edges {
        if edge.entry.relation == relation::CONTROLS {
            let src = vertices_by_vid.get(&edge.entry.src);
            let dst = vertices_by_vid.get(&edge.entry.dst);
            let is_legacy_migration = dst.is_some_and(|r| r.labels.contains(&label::MIGRATION_RUN));
            let is_subledger_control = src.is_some_and(|r| r.labels.contains(&label::SUBLEDGER))
                && dst.is_some_and(|r| r.labels.contains(&label::ACCOUNT));
            let is_rea_control = src.is_some_and(|r| {
                r.labels.contains(&label::PARTY) || r.labels.contains(&label::LEGAL_ENTITY)
            }) && dst.is_some_and(|r| {
                r.labels.contains(&label::PARTY) || r.labels.contains(&label::LEGAL_ENTITY)
            });
            if !is_legacy_migration && !is_subledger_control && !is_rea_control {
                return Err(corrupt(format!(
                    "CONTROLS edge {:032x} ({:032x} -> {:032x}) violates control-edge semantics",
                    edge.entry.eid.0, edge.entry.src.0, edge.entry.dst.0
                )));
            }
        }
    }

    Ok(ReaSnapshot {
        known_at,
        parties,
        instruments,
        legal_entities,
        external_ids,
        relationships,
        events,
    })
}
