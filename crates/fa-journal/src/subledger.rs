//! Native AR/AP subledgers (plan §4.1/§5.6, fa-03s).
//!
//! A native subledger is a journaled designation of one posting leaf. Its
//! detail is the same immutable legs grouped by the declared party dimension;
//! it never creates customer accounts or maintains a second balance.
//! External-detail feeds and their reconciliation are not implemented here.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryRef, Erasable,
    Id128, LegPayload, PARTY_DIMENSION, Reader, Writer, domain_digest, entry_mirrors, entry_vid,
    party_value_vid, party_vid,
};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::chart::{admit_schema_change, schema_control_proposal};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, Why, code, exit};
use crate::rows::{AccountRow, book_root, bytes, edge_id, prop, scalar_bytes, scalar_text, text};

pub const SCHEMA_CHANGE_NATIVE_SUBLEDGER: u16 = 15;
const FORMAT: &[u8] = b"fa:native-subledger:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NativeSubledgerKind {
    Receivables = 1,
    Payables = 2,
}

impl NativeSubledgerKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Receivables => "AR",
            Self::Payables => "AP",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "AR" | "ar" | "receivables" => Some(Self::Receivables),
            "AP" | "ap" | "payables" => Some(Self::Payables),
            _ => None,
        }
    }

    pub(crate) const fn account_type(self) -> AccountType {
        match self {
            Self::Receivables => AccountType::ASSET,
            Self::Payables => AccountType::LIABILITY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledgerSpec {
    pub code: String,
    pub name: String,
    pub kind: NativeSubledgerKind,
    pub control_account: VId,
}

impl NativeSubledgerSpec {
    fn valid(&self) -> bool {
        !self.code.is_empty()
            && self.code.len() <= 64
            && !self.name.is_empty()
            && self.name.len() <= 256
    }

    pub fn encode(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(FORMAT)
            .str(&self.code)
            .str(&self.name)
            .u8(self.kind as u8)
            .u128(self.control_account.0);
        w.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        if r.fixed::<{ FORMAT.len() }>("native subledger format")
            .map_err(bad)?
            .as_slice()
            != FORMAT
        {
            return Err(corrupt("unknown native subledger encoding"));
        }
        let code = r.str(64, "subledger code").map_err(bad)?.to_string();
        let name = r.str(256, "subledger name").map_err(bad)?.to_string();
        let kind = match r.u8("subledger kind").map_err(bad)? {
            1 => NativeSubledgerKind::Receivables,
            2 => NativeSubledgerKind::Payables,
            _ => return Err(corrupt("unknown native subledger kind")),
        };
        let control_account = VId(r.u128("control account").map_err(bad)?);
        r.finish().map_err(bad)?;
        let spec = Self {
            code,
            name,
            kind,
            control_account,
        };
        if !spec.valid() {
            return Err(corrupt("invalid native subledger specification"));
        }
        Ok(spec)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledger {
    pub vid: VId,
    pub spec: NativeSubledgerSpec,
    pub entry: EntryRef,
    pub recorded_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledgerRecorded {
    pub subledger: NativeSubledger,
    pub already_recorded: bool,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("native subledger: {}", message.into()))
}

/// One subledger per control account. This identity also gives every posting
/// a point witness for an absent designation, independent of a mutable mirror.
#[must_use]
pub fn native_subledger_vid(book: Id128, account: VId) -> VId {
    let digest = domain_digest(
        b"fa:vid:native-subledger:v1",
        &[&book.0, &account.0.to_le_bytes()],
    );
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

fn target(row: &VertexRow) -> Result<Option<VId>, KernelError> {
    match prop(row, property::TARGET_REF) {
        None => Ok(None),
        Some(CanonicalScalar::Bytes(value)) => {
            let raw = value
                .as_slice()
                .try_into()
                .map_err(|_| corrupt("target reference is not 16 bytes"))?;
            Ok(Some(VId(u128::from_le_bytes(raw))))
        }
        _ => Err(corrupt("target reference is not bytes")),
    }
}

fn declared(row: &VertexRow, book: &BookContext) -> Result<NativeSubledger, KernelError> {
    let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "subledger control")?)?;
    if !row.labels.contains(&label::ENTRY)
        || entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || entry.proposal.class != EntryClass::SCHEMA_CONTROL
        || !entry.proposal.legs.is_empty()
        || !matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::CHART_INSTALL,
                ..
            }
        )
        || entry_vid(
            book.book_id,
            &entry.proposal.principal_ref.0.to_le_bytes(),
            &entry.proposal.idempotency_key,
        ) != row.vid
        || entry_mirrors(&entry)? != row.props
    {
        return Err(corrupt(
            "registration control identity, coordinate, or mirrors differ",
        ));
    }
    let Some(ControlPayload::SchemaChange {
        kind: SCHEMA_CHANGE_NATIVE_SUBLEDGER,
        canonical_bytes,
    }) = &entry.proposal.control
    else {
        return Err(corrupt(
            "registration source is not a native subledger control",
        ));
    };
    let spec = NativeSubledgerSpec::decode(canonical_bytes)?;
    Ok(NativeSubledger {
        vid: native_subledger_vid(book.book_id, spec.control_account),
        spec,
        entry: entry.entry_ref(row.vid),
        recorded_at: row.created_at,
    })
}

fn projection(
    book: &BookContext,
    record: &NativeSubledger,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, CanonicalScalar)>, KernelError> {
    let encoded = record.spec.encode()?;
    let digest = domain_digest(b"fa:native-subledger-spec:v1", &[&encoded]);
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("subledger payload", encoded)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("subledger digest", digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book id", book.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("subledger code", &record.spec.code)?,
        ),
        (
            property::NAME,
            scalar_text("subledger name", &record.spec.name)?,
        ),
        (
            property::ACCOUNT_REF,
            scalar_bytes(
                "control account",
                record.spec.control_account.0.to_le_bytes().to_vec(),
            )?,
        ),
        (
            property::TARGET_REF,
            scalar_bytes(
                "registration control",
                record.entry.vid.0.to_le_bytes().to_vec(),
            )?,
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

fn validate_projection(
    book: &BookContext,
    record: &NativeSubledger,
    row: &VertexRow,
) -> Result<(), KernelError> {
    if row.vid != record.vid
        || row.labels != vec![label::SUBLEDGER]
        || row.created_at != record.recorded_at
        || row.props != projection(book, record)?
    {
        return Err(corrupt(
            "subledger projection differs from its immutable registration",
        ));
    }
    Ok(())
}

/// Reconstruct definitions from immutable controls and validate the graph
/// projections at the same retained prefix. Never trust a lone control_of
/// pointer, a graph edge, or a caller's claimed specification.
pub fn native_subledgers_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<NativeSubledger>, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    let rows = db.vertices_at(at)?;
    let by_id: BTreeMap<_, _> = rows.iter().map(|row| (row.vid, row)).collect();
    let mut records = BTreeMap::new();
    let mut codes = BTreeSet::new();
    for row in &rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "entry payload")?)?;
        if !matches!(
            &entry.proposal.control,
            Some(ControlPayload::SchemaChange {
                kind: SCHEMA_CHANGE_NATIVE_SUBLEDGER,
                ..
            })
        ) {
            continue;
        }
        let record = declared(row, book)?;
        if !codes.insert(record.spec.code.clone()) || records.contains_key(&record.vid) {
            return Err(corrupt(
                "duplicate native subledger code or control account",
            ));
        }
        let root = by_id
            .get(&record.vid)
            .ok_or_else(|| corrupt("registered subledger projection is missing"))?;
        validate_projection(book, &record, root)?;
        let account = by_id
            .get(&record.spec.control_account)
            .ok_or_else(|| corrupt("control account is missing"))?;
        if !account.labels.contains(&label::ACCOUNT) {
            return Err(corrupt("control reference no longer names an Account"));
        }
        let decoded = AccountRow::decode(account)?;
        if !decoded.is_leaf
            || AccountType(decoded.account_type) != record.spec.kind.account_type()
            || target(account)? != Some(record.vid)
        {
            return Err(corrupt(
                "control account type, leaf status, or control_of differs",
            ));
        }
        records.insert(record.vid, record);
    }
    for row in &rows {
        if row.labels.contains(&label::SUBLEDGER) && !records.contains_key(&row.vid) {
            return Err(corrupt(
                "subledger projection has no immutable registration",
            ));
        }
        if row.labels.contains(&label::ACCOUNT)
            && let Some(vid) = target(row)?
            && records
                .get(&vid)
                .is_none_or(|record| record.spec.control_account != row.vid)
        {
            return Err(corrupt("account control_of has no matching registration"));
        }
    }
    let edges = db.edges_at(at)?;
    for record in records.values() {
        let controls: Vec<_> = edges
            .iter()
            .filter(|edge| {
                edge.entry.relation == relation::CONTROLS && edge.entry.src == record.vid
            })
            .collect();
        if controls.len() != 1
            || controls[0].entry.dst != record.spec.control_account
            || controls[0].entry.eid
                != edge_id(relation::CONTROLS, record.vid, record.spec.control_account)
            || !controls[0].props.is_empty()
            || !edges.iter().any(|edge| {
                edge.entry.relation == relation::IN_BOOK
                    && edge.entry.src == record.vid
                    && edge.entry.dst == book_root()
                    && edge.entry.eid == edge_id(relation::IN_BOOK, record.vid, book_root())
                    && edge.props.is_empty()
            })
        {
            return Err(corrupt(
                "CONTROLS or IN_BOOK projection differs from registration",
            ));
        }
    }
    let mut out: Vec<_> = records.into_values().collect();
    out.sort_by(|a, b| a.spec.code.cmp(&b.spec.code));
    Ok(out)
}

/// Validate the deterministic registration and the account mirror using
/// point witnesses only. Called even if the account has no control_of mirror.
pub(crate) fn account_binding<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    account: &VertexRow,
) -> Result<Option<NativeSubledger>, KernelError> {
    account_binding_with(&mut |vid| Ok(txn.vertex(db, vid)?), book, account)
}

fn account_binding_with(
    read_vertex: &mut impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
    book: &BookContext,
    account: &VertexRow,
) -> Result<Option<NativeSubledger>, KernelError> {
    let vid = native_subledger_vid(book.book_id, account.vid);
    let Some(root) = read_vertex(vid)? else {
        if target(account)?.is_some() {
            return Err(corrupt(
                "account control_of references a missing designation",
            ));
        }
        return Ok(None);
    };
    if target(account)? != Some(vid) {
        return Err(corrupt(
            "registered control account has a missing or redirected control_of",
        ));
    }
    let source = target(&root)?.ok_or_else(|| corrupt("subledger has no registration source"))?;
    let source =
        read_vertex(source)?.ok_or_else(|| corrupt("subledger registration source is missing"))?;
    let record = declared(&source, book)?;
    validate_projection(book, &record, &root)?;
    if record.spec.control_account != account.vid {
        return Err(corrupt(
            "subledger designation refers to another control account",
        ));
    }
    let decoded = AccountRow::decode(account)?;
    if !decoded.is_leaf || AccountType(decoded.account_type) != record.spec.kind.account_type() {
        return Err(corrupt(
            "registered control account no longer has its declared type",
        ));
    }
    Ok(Some(record))
}

fn valid_party<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    value: VId,
) -> Result<bool, KernelError> {
    valid_party_with(&mut |vid| Ok(txn.vertex(db, vid)?), book, value)
}

fn valid_party_with(
    read_vertex: &mut impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
    book: &BookContext,
    value: VId,
) -> Result<bool, KernelError> {
    let Some(row) = read_vertex(value)? else {
        return Ok(false);
    };
    if !row.labels.contains(&label::DIMENSION_VALUE)
        || prop(&row, property::DIMENSION_ID)
            != Some(&CanonicalScalar::Int(i64::from(PARTY_DIMENSION)))
        || bytes(&row, property::BOOK_ID, "party book")? != book.book_id.0
    {
        return Ok(false);
    }
    let code = text(&row, property::CODE, "party code")?;
    if party_value_vid(book.book_id, &code) != value {
        return Ok(false);
    }
    let Some(party) = read_vertex(party_vid(book.book_id, &code))? else {
        return Ok(false);
    };
    Ok(party.labels.contains(&label::PARTY)
        && bytes(&party, property::BOOK_ID, "party book")? == book.book_id.0
        && text(&party, property::CODE, "party code")? == code)
}

fn missing_party(code_str: &str, account: VId, ordinal: usize) -> Refusal {
    Refusal::new(
        code::DIMENSION_MISSING, exit::REFUSAL,
        format!("leg {ordinal} on native subledger '{code_str}' requires a declared party"),
        "plan §5.6 (native subledger detail is the control leaf grouped by party)",
        "create or select a Party, then supply its party dimension value on this control-account leg",
    ).at("leg", ordinal).at("account", format!("{:032x}", account.0))
        .because(Why::Law("FA-INV-12.core".into()))
}

/// Shared native admission at either transaction witnesses or a retained
/// prefix. Historical schedule retries run exactly the same party law.
pub(crate) fn validate_leg_with(
    read_vertex: &mut impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
    book: &BookContext,
    account: &VertexRow,
    leg: &LegPayload,
    ordinal: usize,
) -> Result<Option<Refusal>, KernelError> {
    let Some(record) = account_binding_with(read_vertex, book, account)? else {
        return Ok(None);
    };
    let party = leg
        .dimension_set
        .iter()
        .find(|(kind, _)| *kind == PARTY_DIMENSION);
    if let Some((_, value)) = party
        && valid_party_with(read_vertex, book, *value)?
    {
        return Ok(None);
    }
    Ok(Some(missing_party(&record.spec.code, account.vid, ordinal)))
}

/// Adopt a leaf atomically with its immutable declaration and rebuildable
/// projections. Existing history must already have party-complete detail,
/// including staged migration chunks that may become visible later.
#[allow(clippy::too_many_arguments)]
pub async fn create_native_subledger<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &NativeSubledgerSpec,
    principal: VId,
    effective_date: DateDay,
    key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<NativeSubledgerRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal, capability)? {
        return Ok(Err(refusal));
    }
    if !spec.valid() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "native subledger code must be 1..=64 bytes and name 1..=256 bytes",
            "plan §4.1 Subledger",
            "supply a non-empty bounded code and name",
        )));
    }
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_NATIVE_SUBLEDGER,
        spec.encode()?,
        principal,
        effective_date,
        key,
        description,
    );
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(book.book_id, &principal.0.to_le_bytes(), key);
    let vid = native_subledger_vid(book.book_id, spec.control_account);
    if let Err(refusal) = crate::policy::capability_admitted(db, book, capability)? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Err(refusal) =
        crate::outcome::witness_named_key(&txn, db, book.book_id, principal, key, evid)?
    {
        txn.abort();
        return Ok(Err(refusal));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        let stored = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry payload")?)?;
        if row.labels.as_slice() != [label::ENTRY]
            || row.props != entry_mirrors(&stored)?
            || !stored.approvals.is_empty()
            || stored.plan_certificate.is_some()
            || !crate::outcome::verify_control_recorded(db, &row, &stored)?
        {
            return Ok(Err(crate::outcome::key_conflict()));
        }
        if stored.proposal_digest != entry.proposal_digest
            && stored.proposal.semantic_digest(&book.seal_key)?
                != proposal.semantic_digest(&book.seal_key)?
        {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "this idempotency key already records different content",
                "FA-INV-09",
                "retry the original specification or use a new key",
            )));
        }
        let subledger = declared(&row, book)?;
        let existing = native_subledgers_at(db, book, db.frontier()?)?;
        if !existing.iter().any(|item| item == &subledger) {
            return Err(corrupt(
                "retry could not authenticate the registered subledger",
            ));
        }
        return Ok(Ok(NativeSubledgerRecorded {
            subledger,
            already_recorded: true,
        }));
    }
    if let Err(refusal) = crate::outcome::require_unused_legacy_key(
        &txn,
        db,
        book,
        crate::outcome::entry_outcome_vid(&proposal),
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let existing = native_subledgers_at(db, book, txn.basis())?;
    if existing
        .iter()
        .any(|item| item.spec.code == spec.code || item.vid == vid)
    {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "native subledger code or control account is already registered",
            "plan §5.6 (one designation per control leaf)",
            "use the existing subledger or choose a distinct code and control account",
        )));
    }
    let Some(account) = txn.vertex(db, spec.control_account)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            "native subledger control account does not exist",
            "plan §4.1 Subledger.control_account_ref",
            "select an existing posting account",
        )));
    };
    if !account.labels.contains(&label::ACCOUNT) {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            "native subledger control reference does not name an Account",
            "plan §4.1 Subledger.control_account_ref",
            "select an existing posting account",
        )));
    }
    let decoded = AccountRow::decode(&account)?;
    if !decoded.is_leaf || AccountType(decoded.account_type) != spec.kind.account_type() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "AR requires an Asset posting leaf; AP requires a Liability posting leaf",
            "plan §4.1/§5.6 native control accounts",
            "select a posting leaf with the account type required by this subledger kind",
        )));
    }
    if account_binding(&txn, db, book, &account)?.is_some() {
        txn.abort();
        return Err(corrupt("unlisted account designation"));
    }
    // There is no await between this scan and staging. The single-writer
    // database handle remains exclusively borrowed through publication.
    // A prepared posting witnesses this account and the negative root lookup.
    let query = ctx.query();
    for row in db.vertices_at(txn.basis())? {
        query.checkpoint().map_err(WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let historical = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry payload")?)?;
        for (ordinal, leg) in historical.proposal.legs.iter().enumerate() {
            if leg.account_ref != spec.control_account {
                continue;
            }
            let party = leg
                .dimension_set
                .iter()
                .find(|(kind, _)| *kind == PARTY_DIMENSION);
            if let Some((_, value)) = party
                && valid_party(&txn, db, book, *value)?
            {
                continue;
            }
            txn.abort();
            return Ok(Err(missing_party(
                &spec.code,
                spec.control_account,
                ordinal,
            )
            .at("entry", format!("{:032x}", row.vid.0))
            .or_field_change(
                "control_account",
                vec!["a clean posting leaf whose entire history carries party detail".into()],
            )));
        }
    }
    let record = NativeSubledger {
        vid,
        spec: spec.clone(),
        entry: entry.entry_ref(evid),
        recorded_at: CommitSeq(0),
    };
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    crate::outcome::stage_control(&mut in_book, &entry, evid)?;
    in_book.create_vertex(vid, vec![label::SUBLEDGER], projection(book, &record)?);
    in_book.compare_and_set_vertex_property(
        spec.control_account,
        property::TARGET_REF,
        None,
        scalar_bytes("control_of", vid.0.to_le_bytes().to_vec())?,
        WriteMismatchPolicy::AbortWrite,
    );
    in_book.add_edge(
        edge_id(relation::IN_BOOK, vid, book_root()),
        vid,
        book_root(),
        vec![],
    );
    let mut controls = WriteBatch::new(relation::CONTROLS);
    controls.add_edge(
        edge_id(relation::CONTROLS, vid, spec.control_account),
        vid,
        spec.control_account,
        vec![],
    );
    if let Err(error) = txn.write_ordered(db, vec![in_book, controls]) {
        txn.abort();
        return Err(error.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(at) => Ok(Ok(NativeSubledgerRecorded {
            subledger: NativeSubledger {
                recorded_at: at,
                ..record
            },
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("native subledger registration witness changed: {detail}"),
                "FG-LAW-FCW-01",
                "retry against the current frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "native subledger registration collided on a derived identity",
            "FA-INV-09",
            "inspect the existing registration and retry its original key",
        ))),
        Err(error) => Err(error.into()),
    }
}
