//! Account-specific value restrictions for registered dimensions (fa-ficc).
//!
//! Each immutable schema control replaces one account-and-kind policy. A
//! separate, witnessed projection points to its latest control; the original
//! dimension requirement remains independent. Values match exact codes, with
//! no implicit expansion to descendants. Dictated legs are exempt at the
//! shared posting admission boundary, as they are from current requirements.

use asupersync::fs::Vfs;
use fa_model::rea::MAX_REA_CODE_BYTES;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, Entry, EntryClass, Erasable, LegPayload, Reader, Writer,
    dimension_constraint_vid, dimension_kind, dimension_kind_of, dimension_value_vid,
    entry_mirrors, entry_vid,
};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use super::DimensionValueRow;
use crate::chart::{admit_schema_change, schema_control_proposal};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, book_root, bytes, edge_id, prop, scalar_bytes};

pub const SCHEMA_CHANGE_DIMENSION_CONSTRAINT: u16 = 25;
pub const MAX_DIMENSION_CONSTRAINT_VALUES: usize = 128;
pub const MAX_DIMENSION_CONSTRAINT_BYTES: usize = 8192;
const FORMAT: &[u8] = b"fa:dimension-constraint:v1";
// The native row limit is 16 KiB. This leaves room for the control's fixed
// mirrors and row envelope, while retaining a single witnessed control read.
const MAX_CONTROL_BYTES: usize = 12 * 1024;

/// A complete replacement for one posting account's dimension value policy.
/// Lists are strictly ascending, unique, and disjoint, with at most 128 codes
/// combined. The encoded policy is at most 8192 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionConstraintSpec {
    pub dimension: String,
    pub account: VId,
    /// None admits every otherwise valid value except those forbidden below.
    /// Some(empty) admits no tagged value. Neither form requires a tag.
    pub allowed: Option<Vec<String>>,
    pub forbidden: Vec<String>,
}

impl DimensionConstraintSpec {
    pub fn encode(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(FORMAT)
            .str(&self.dimension)
            .u128(self.account.0)
            .opt(self.allowed.as_ref(), |w, values| {
                w.list(values, |w, value| {
                    w.str(value);
                });
            })
            .list(&self.forbidden, |w, value| {
                w.str(value);
            });
        w.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        if encoded.len() > MAX_DIMENSION_CONSTRAINT_BYTES {
            return Err(corrupt("policy exceeds its encoded byte bound"));
        }
        let mut r = Reader::new(encoded);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        if r.fixed::<{ FORMAT.len() }>("dimension constraint format")
            .map_err(bad)?
            .as_slice()
            != FORMAT
        {
            return Err(corrupt("unknown policy encoding"));
        }
        let dimension = r
            .str(MAX_REA_CODE_BYTES, "constrained dimension")
            .map_err(bad)?
            .to_string();
        let account = VId(r.u128("constrained account").map_err(bad)?);
        let allowed = r
            .opt("allowed dimension values", |r| {
                r.list(MAX_DIMENSION_CONSTRAINT_VALUES, "allowed values", |r| {
                    Ok(r.str(MAX_REA_CODE_BYTES, "allowed value")?.to_string())
                })
            })
            .map_err(bad)?;
        let forbidden = r
            .list(
                MAX_DIMENSION_CONSTRAINT_VALUES,
                "forbidden dimension values",
                |r| Ok(r.str(MAX_REA_CODE_BYTES, "forbidden value")?.to_string()),
            )
            .map_err(bad)?;
        r.finish().map_err(bad)?;
        let spec = Self {
            dimension,
            account,
            allowed,
            forbidden,
        };
        if let Some(problem) = spec.problem() {
            return Err(corrupt(problem));
        }
        Ok(spec)
    }

    /// Reject ambiguous or oversized policies before any account/value reads.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        if dimension_kind(&self.dimension).is_none() {
            return Some(format!(
                "`{}` is not a registered dimension; the dimensions are {}",
                self.dimension,
                super::kinds_listing()
            ));
        }
        let allowed = self.allowed.as_deref().unwrap_or_default();
        if allowed.len() > MAX_DIMENSION_CONSTRAINT_VALUES
            || self.forbidden.len() > MAX_DIMENSION_CONSTRAINT_VALUES
            || allowed.len() + self.forbidden.len() > MAX_DIMENSION_CONSTRAINT_VALUES
        {
            return Some(format!(
                "a policy may name at most {MAX_DIMENSION_CONSTRAINT_VALUES} values combined"
            ));
        }
        for (name, values) in [("allowed", allowed), ("forbidden", &self.forbidden[..])] {
            if values.iter().any(|value| {
                value.is_empty()
                    || value.len() > MAX_REA_CODE_BYTES
                    || !value.chars().all(|c| c.is_ascii_graphic())
            }) {
                return Some(format!(
                    "{name} value codes must be 1..={MAX_REA_CODE_BYTES} printable ASCII bytes without spaces"
                ));
            }
            if !values.windows(2).all(|pair| pair[0] < pair[1]) {
                return Some(format!("{name} value codes must be unique and ascending"));
            }
        }
        if allowed
            .iter()
            .any(|value| self.forbidden.binary_search(value).is_ok())
        {
            return Some("a value cannot be both allowed and forbidden".into());
        }
        // Every length is bounded above before this arithmetic. This is the
        // exact Writer representation, including the optional-list tag.
        let encoded_len = FORMAT.len()
            + 4
            + self.dimension.len()
            + 16
            + 1
            + usize::from(self.allowed.is_some()) * 4
            + 4
            + allowed
                .iter()
                .chain(&self.forbidden)
                .map(|value| 4 + value.len())
                .sum::<usize>();
        if encoded_len > MAX_DIMENSION_CONSTRAINT_BYTES {
            return Some(format!(
                "the encoded policy exceeds {MAX_DIMENSION_CONSTRAINT_BYTES} bytes"
            ));
        }
        None
    }

    #[must_use]
    fn permits(&self, value: &str) -> bool {
        self.allowed
            .as_ref()
            .is_none_or(|values| values.binary_search_by(|code| code.as_str().cmp(value)).is_ok())
            && self
                .forbidden
                .binary_search_by(|code| code.as_str().cmp(value))
                .is_err()
    }

    fn is_clear(&self) -> bool {
        self.allowed.is_none() && self.forbidden.is_empty()
    }
}

/// One policy revision, including an explicit journaled clear. recorded_at is
/// the revision control's commit, not the mutable projection's creation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionConstraintRow {
    pub vid: VId,
    pub spec: DimensionConstraintSpec,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionConstraintRecorded {
    pub spec: DimensionConstraintSpec,
    /// None only when clearing a policy that has never been configured.
    pub control_entry: Option<VId>,
    pub recorded_at: Option<CommitSeq>,
    /// A same-key retry or an unchanged state publishes nothing.
    pub already_recorded: bool,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("dimension constraint: {}", message.into()))
}

fn usage(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §4.3; fa-ficc (account dimension value restrictions)",
        "fa dimension constrain <dimension> <account> [--allow CODE] [--forbid CODE] [--allow-none | --clear]",
    )
}

fn projection(
    book: &BookContext,
    spec: &DimensionConstraintSpec,
    control: VId,
) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
    let kind = dimension_kind(&spec.dimension)
        .ok_or_else(|| corrupt("projection names an unregistered dimension"))?;
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("dimension constraint payload", spec.encode()?)?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("dimension constraint book", book.book_id.0.to_vec())?,
        ),
        (
            property::ACCOUNT_REF,
            scalar_bytes(
                "dimension constraint account",
                spec.account.0.to_le_bytes().to_vec(),
            )?,
        ),
        (
            property::DIMENSION_ID,
            CanonicalScalar::Int(i64::from(kind.id)),
        ),
        (
            property::TARGET_REF,
            scalar_bytes("dimension constraint control", control.0.to_le_bytes().to_vec())?,
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

fn declared(
    book: &BookContext,
    row: &VertexRow,
) -> Result<DimensionConstraintRow, KernelError> {
    if !crate::entry_storage::has_class_mirror(row, EntryClass::SCHEMA_CONTROL) {
        return Err(corrupt("policy source is not a schema control"));
    }
    let encoded = bytes(row, property::FA_PAYLOAD, "dimension constraint control")?;
    if encoded.len() > MAX_CONTROL_BYTES {
        return Err(corrupt("policy control exceeds its inline row bound"));
    }
    let entry = Entry::decode(&encoded)?;
    let Some(ControlPayload::SchemaChange {
        kind: SCHEMA_CHANGE_DIMENSION_CONSTRAINT,
        canonical_bytes,
    }) = &entry.proposal.control
    else {
        return Err(corrupt("policy source is another schema control"));
    };
    let spec = DimensionConstraintSpec::decode(canonical_bytes)?;
    let expected = schema_control_proposal(
        book,
        SCHEMA_CHANGE_DIMENSION_CONSTRAINT,
        canonical_bytes.clone(),
        entry.proposal.principal_ref,
        DateDay(0),
        &entry.proposal.idempotency_key,
        entry.proposal.description.clone(),
    );
    if entry.proposal != expected
        || !entry.approvals.is_empty()
        || entry.plan_certificate.is_some()
        || entry_vid(
            book.book_id,
            &entry.proposal.principal_ref.0.to_le_bytes(),
            &entry.proposal.idempotency_key,
        ) != row.vid
        || entry_mirrors(&entry)? != row.props
    {
        return Err(corrupt("policy control identity, coordinate, or mirrors differ"));
    }
    Ok(DimensionConstraintRow {
        vid: dimension_constraint_vid(book.book_id, &spec.dimension, spec.account),
        spec,
        control_entry: row.vid,
        recorded_at: row.created_at,
    })
}

/// Authenticate the mutable mirror against the immutable control it names.
/// Both are point reads from the caller's selected prefix/transaction.
fn read_constraint(
    book: &BookContext,
    row: &VertexRow,
    mut read_vertex: impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
) -> Result<DimensionConstraintRow, KernelError> {
    if row.labels.as_slice() != [label::DIMENSION_CONSTRAINT] {
        return Err(corrupt("policy projection has another label"));
    }
    let payload = match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(value)) => value.as_slice(),
        _ => return Err(corrupt("policy projection has no canonical payload")),
    };
    let spec = DimensionConstraintSpec::decode(payload)?;
    let target: [u8; 16] = bytes(row, property::TARGET_REF, "dimension constraint source")?
        .try_into()
        .map_err(|_| corrupt("policy source reference is not 16 bytes"))?;
    let target = VId(u128::from_le_bytes(target));
    if row.vid != dimension_constraint_vid(book.book_id, &spec.dimension, spec.account)
        || row.props != projection(book, &spec, target)?
    {
        return Err(corrupt("policy projection identity or mirrors differ"));
    }
    let source = read_vertex(target)?
        .ok_or_else(|| corrupt("policy projection names an absent control"))?;
    let recorded = declared(book, &source)?;
    if recorded.vid != row.vid
        || recorded.spec != spec
        || recorded.recorded_at < row.created_at
    {
        return Err(corrupt("policy projection differs from its immutable control"));
    }
    Ok(recorded)
}

/// Policies, including explicit clears, at one known-at prefix, by registered
/// dimension id then account. The facade admits the read scope before calling.
pub fn constraints_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<DimensionConstraintRow>, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    let mut policies = Vec::new();
    for vid in db.in_neighbours_at(book_root(), relation::IN_BOOK, at)? {
        let Some(row) = db.vertex_at(vid, at)? else {
            continue;
        };
        if row.labels.contains(&label::DIMENSION_CONSTRAINT) {
            policies.push(read_constraint(book, &row, |source| {
                Ok(db.vertex_at(source, at)?)
            })?);
        }
    }
    policies.sort_by_key(|policy| {
        (
            dimension_kind(&policy.spec.dimension).map_or(0, |kind| kind.id),
            policy.spec.account,
        )
    });
    Ok(policies)
}


/// Replace one account's exact-code policy under current whole-book
/// SchemaChange authority. Same-key retries return the original control even
/// after later revisions; they never restore that old policy. A clear is an
/// ordinary journaled revision when a policy already exists.
#[allow(clippy::too_many_arguments)]
pub async fn record_dimension_constraint<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &DimensionConstraintSpec,
    principal: VId,
    key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<DimensionConstraintRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal, capability)? {
        return Ok(Err(refusal));
    }
    if let Some(problem) = spec.problem() {
        return Ok(Err(usage(problem)));
    }
    let kind = dimension_kind(&spec.dimension)
        .ok_or_else(|| corrupt("an admitted policy names no registered dimension"))?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_DIMENSION_CONSTRAINT,
        spec.encode()?,
        principal,
        DateDay(0),
        key,
        description,
    );
    let entry = proposal.clone().seal(Vec::new(), None)?;
    if entry.encode()?.len() > MAX_CONTROL_BYTES {
        return Ok(Err(usage("the policy control exceeds its bounded inline storage")));
    }
    let evid = entry_vid(book.book_id, &principal.0.to_le_bytes(), key);
    let vid = dimension_constraint_vid(book.book_id, kind.code, spec.account);
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
        if !crate::entry_storage::has_class_mirror(&row, proposal.class) {
            return Ok(Err(crate::outcome::key_conflict()));
        }
        let stored = crate::entry_storage::decode_at(db, &row, db.frontier()?)?;
        if row.props != entry_mirrors(&stored)?
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
                "retry the original dimension policy or use a new key",
            )));
        }
        let recorded = declared(book, &row)?;
        return Ok(Ok(DimensionConstraintRecorded {
            spec: recorded.spec,
            control_entry: Some(recorded.control_entry),
            recorded_at: Some(recorded.recorded_at),
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
    let account_row = match txn.vertex(db, spec.account)? {
        Some(row) if row.labels.contains(&label::ACCOUNT) => row,
        _ => {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::UNKNOWN_ACCOUNT,
                exit::REFUSAL,
                "the constrained account does not exist",
                "plan §4.3 (the chart of accounts)",
                "name an account of this book's chart (fa chart list)",
            )));
        }
    };
    let account = AccountRow::decode(&account_row)?;
    if bytes(&account_row, property::BOOK_ID, "constrained account book")?
        != book.book_id.0
        || account.vid != AccountRow::vid_for(book.book_id, &account.code)
    {
        txn.abort();
        return Err(corrupt("the constrained account's book or identity differs"));
    }
    if !account.is_leaf {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!(
                "account `{}` is a summary; dimension policies bind posting leaves",
                account.code
            ),
            "plan §4.3 (only leaves accept legs)",
            "constrain the dimension on each posting leaf under it",
        )));
    }
    for value_code in spec.allowed.iter().flatten().chain(&spec.forbidden) {
        let value_vid = dimension_value_vid(book.book_id, kind.code, value_code);
        let value_row = txn.vertex(db, value_vid)?;
        let value = match &value_row {
            Some(row) => DimensionValueRow::decode(row)?,
            None => None,
        };
        let Some(value) = value.filter(|value| {
            value.dimension_id == kind.id
                && value.spec.dimension == kind.code
                && value.spec.code == *value_code
        }) else {
            txn.abort();
            return Ok(Err(usage(format!(
                "{} value `{value_code}` does not exist in this book",
                kind.code
            ))
            .at(kind.code, value_code.clone())));
        };
        let stored = value_row
            .as_ref()
            .ok_or_else(|| corrupt("an admitted value has no source row"))?;
        if value.vid != value_vid
            || stored.labels.as_slice() != [label::DIMENSION_VALUE]
            || bytes(stored, property::BOOK_ID, "constrained value book")? != book.book_id.0
        {
            txn.abort();
            return Err(corrupt("a constrained value's book or identity differs"));
        }
    }
    // Even an unconfigured policy is a witnessed point read: installing one
    // later invalidates a prepared posting that observed its absence.
    let current = txn.vertex(db, vid)?;
    if let Some(row) = &current {
        let recorded = read_constraint(book, row, |source| Ok(txn.vertex(db, source)?))?;
        if recorded.spec == *spec {
            txn.abort();
            return Ok(Ok(DimensionConstraintRecorded {
                spec: recorded.spec,
                control_entry: Some(recorded.control_entry),
                recorded_at: Some(recorded.recorded_at),
                already_recorded: true,
            }));
        }
    } else if spec.is_clear() {
        txn.abort();
        return Ok(Ok(DimensionConstraintRecorded {
            spec: spec.clone(),
            control_entry: None,
            recorded_at: None,
            already_recorded: true,
        }));
    }
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    crate::outcome::stage_control(&mut batch, &entry, evid)?;
    if current.is_some() {
        let payload = txn.vertex_property(db, vid, property::FA_PAYLOAD)?;
        let target = txn.vertex_property(db, vid, property::TARGET_REF)?;
        batch.compare_and_set_vertex_property(
            vid,
            property::FA_PAYLOAD,
            payload,
            scalar_bytes("dimension constraint payload", spec.encode()?)?,
            WriteMismatchPolicy::AbortWrite,
        );
        batch.compare_and_set_vertex_property(
            vid,
            property::TARGET_REF,
            target,
            scalar_bytes("dimension constraint control", evid.0.to_le_bytes().to_vec())?,
            WriteMismatchPolicy::AbortWrite,
        );
    } else {
        batch.create_vertex(
            vid,
            vec![label::DIMENSION_CONSTRAINT],
            projection(book, spec, evid)?,
        );
        batch.add_edge(
            edge_id(relation::IN_BOOK, vid, book_root()),
            vid,
            book_root(),
            vec![],
        );
    }
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return Err(error.into());
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(DimensionConstraintRecorded {
            spec: spec.clone(),
            control_entry: Some(evid),
            recorded_at: Some(recorded_at),
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a dimension constraint witness changed: {detail}"),
                "FG-LAW-FCW-01",
                "retry against the current frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "a dimension constraint control collided on a derived identity",
            "FA-INV-09",
            "retry its original key",
        ))),
        Err(error) => Err(error.into()),
    }
}

/// Judge only preparer-chosen legs. The caller preserves the existing dictated
/// class and settlement exemptions. Missing tags remain governed exclusively
/// by the separate required-dimension law.
pub(crate) fn admit_dimension_constraints(
    book: &BookContext,
    leg: &LegPayload,
    ordinal: usize,
    account_code: &str,
    mut read_vertex: impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
) -> Result<Option<Refusal>, KernelError> {
    for (dimension_id, value_vid) in &leg.dimension_set {
        let Some(kind) = dimension_kind_of(*dimension_id) else {
            continue;
        };
        let vid = dimension_constraint_vid(book.book_id, kind.code, leg.account_ref);
        let Some(row) = read_vertex(vid)? else {
            continue;
        };
        let policy = read_constraint(book, &row, &mut read_vertex)?;
        if policy.spec.account != leg.account_ref || policy.spec.dimension != kind.code {
            return Err(corrupt("a leg observed another account or dimension's policy"));
        }
        let Some(value_row) = read_vertex(*value_vid)? else {
            return Ok(Some(super::unknown_value(kind, *value_vid, ordinal)));
        };
        let Some(value) = DimensionValueRow::decode(&value_row)?
            .filter(|value| value.dimension_id == kind.id)
        else {
            return Ok(Some(super::unknown_value(kind, *value_vid, ordinal)));
        };
        if value.vid != dimension_value_vid(book.book_id, kind.code, &value.spec.code)
            || value_row.labels.as_slice() != [label::DIMENSION_VALUE]
            || bytes(&value_row, property::BOOK_ID, "leg dimension value book")? != book.book_id.0
        {
            return Err(corrupt("a leg's constrained value has another book or identity"));
        }
        if !policy.spec.permits(&value.spec.code) {
            return Ok(Some(
                Refusal::new(
                    code::DIMENSION_FORBIDDEN,
                    exit::REFUSAL,
                    format!(
                        "leg {ordinal}: account `{account_code}` does not permit {} value `{}`",
                        kind.code, value.spec.code
                    ),
                    "plan §4.3; fa-ficc (account dimension value restrictions)",
                    format!(
                        "choose a value permitted by this account's policy (fa dimension constraints {}); changing a policy requires SchemaChange authority",
                        kind.code
                    ),
                )
                .at("leg", ordinal)
                .at("account", account_code)
                .at(kind.code, value.spec.code),
            ));
        }
    }
    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> DimensionConstraintSpec {
        DimensionConstraintSpec {
            dimension: "cost_center".into(),
            account: VId(17),
            allowed: Some(vec!["ENG".into(), "SALES".into()]),
            forbidden: vec!["SHARED".into()],
        }
    }

    #[test]
    fn canonical_policy_round_trips_without_collapsing_clear_and_deny_all() {
        let restricted = spec();
        let clear = DimensionConstraintSpec {
            allowed: None,
            forbidden: Vec::new(),
            ..spec()
        };
        let deny_all = DimensionConstraintSpec {
            allowed: Some(Vec::new()),
            forbidden: Vec::new(),
            ..spec()
        };
        for policy in [&restricted, &clear, &deny_all] {
            assert!(policy.problem().is_none());
            assert_eq!(
                DimensionConstraintSpec::decode(&policy.encode().unwrap()).unwrap(),
                *policy
            );
        }
        assert_ne!(clear.encode().unwrap(), deny_all.encode().unwrap());
        assert!(clear.is_clear());
        assert!(!deny_all.is_clear());
        assert!(clear.permits("ENG"));
        assert!(!deny_all.permits("ENG"));
    }

    #[test]
    fn exact_membership_does_not_grant_descendants_or_fold_case() {
        let policy = spec();
        assert!(policy.permits("ENG"));
        assert!(policy.permits("SALES"));
        assert!(!policy.permits("SHARED"));
        assert!(!policy.permits("OTHER"));
        assert!(!policy.permits("ENG/CHILD"));
        assert!(!policy.permits("eng"));
        let deny_only = DimensionConstraintSpec {
            allowed: None,
            ..policy
        };
        assert!(deny_only.permits("OTHER"));
        assert!(!deny_only.permits("SHARED"));
    }

    #[test]
    fn canonical_decoder_refuses_ambiguous_codes_and_noncanonical_sets() {
        let invalid = [
            DimensionConstraintSpec {
                dimension: "party".into(),
                ..spec()
            },
            DimensionConstraintSpec {
                allowed: Some(vec!["SALES".into(), "ENG".into()]),
                ..spec()
            },
            DimensionConstraintSpec {
                allowed: Some(vec!["ENG".into(), "ENG".into()]),
                ..spec()
            },
            DimensionConstraintSpec {
                forbidden: vec!["Z".into(), "A".into()],
                ..spec()
            },
            DimensionConstraintSpec {
                forbidden: vec!["SHARED".into(), "SHARED".into()],
                ..spec()
            },
            DimensionConstraintSpec {
                forbidden: vec!["ENG".into()],
                ..spec()
            },
            DimensionConstraintSpec {
                allowed: Some(vec!["".into()]),
                ..spec()
            },
            DimensionConstraintSpec {
                allowed: Some(vec!["BAD CODE".into()]),
                ..spec()
            },
            DimensionConstraintSpec {
                allowed: Some(vec!["Café".into()]),
                ..spec()
            },
        ];
        for policy in invalid {
            assert!(policy.problem().is_some(), "{policy:?}");
            assert!(DimensionConstraintSpec::decode(&policy.encode().unwrap()).is_err());
        }
        let mut extra = spec().encode().unwrap();
        extra.push(0);
        assert!(DimensionConstraintSpec::decode(&extra).is_err());
        let mut wrong_format = spec().encode().unwrap();
        wrong_format[0] ^= 1;
        assert!(DimensionConstraintSpec::decode(&wrong_format).is_err());
    }

    #[test]
    fn both_lists_share_the_value_budget_and_the_encoded_byte_budget() {
        let valid = DimensionConstraintSpec {
            allowed: Some((0..64).map(|i| format!("A{i:03}")).collect()),
            forbidden: (0..64).map(|i| format!("B{i:03}")).collect(),
            ..spec()
        };
        assert!(valid.problem().is_none());
        assert_eq!(
            DimensionConstraintSpec::decode(&valid.encode().unwrap()).unwrap(),
            valid
        );
        let mut too_many = valid;
        too_many.forbidden.push("B999".into());
        assert!(too_many.problem().is_some());
        assert!(DimensionConstraintSpec::decode(&too_many.encode().unwrap()).is_err());

        let too_large = DimensionConstraintSpec {
            allowed: Some(
                (0..MAX_DIMENSION_CONSTRAINT_VALUES)
                    .map(|i| format!("{i:03}{}", "X".repeat(MAX_REA_CODE_BYTES - 3)))
                    .collect(),
            ),
            forbidden: Vec::new(),
            ..spec()
        };
        let encoded = too_large.encode().unwrap();
        assert!(encoded.len() > MAX_DIMENSION_CONSTRAINT_BYTES);
        assert!(too_large.problem().is_some());
        assert!(DimensionConstraintSpec::decode(&encoded).is_err());
    }
}
