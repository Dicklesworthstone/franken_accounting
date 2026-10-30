//! Recorded-version lot policies and their guarded admission projection.
//!
//! Immutable SchemaChange controls are authoritative. The per-account pointer
//! makes ordinary posting admission a bounded point read, including absence,
//! and is updated atomically with the control. Fixed-prefix readers reconstruct
//! the selected control and compare the pointer against it. The date on a
//! policy control never selects a historical law for a new backdated posting.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
pub use fa_model::LotPolicy;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ApprovalRef, ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin,
    EntryPayload, EntryRef, Erasable, Id128, Reader, Writer, domain_digest, entry_mirrors,
    entry_vid,
};
use fa_policy::{Capability, Reach};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{admit_schema_change, schema_control_proposal};
use crate::genesis::{BookContext, UnitPolicy};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, bytes, scalar_bytes};

pub const SCHEMA_CHANGE_LOT_POLICY: u16 = 21;
const HEAD_FORMAT: &[u8] = b"fa:lot-policy-head:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredLotPolicy {
    pub entry: EntryRef,
    pub policy: LotPolicy,
    pub recorded_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotPolicyRecorded {
    pub entry: EntryRef,
    pub policy: LotPolicy,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotPolicyRequest {
    pub principal: VId,
    pub policy: LotPolicy,
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
    pub approvals: Vec<ApprovalRef>,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("lot policy: {}", message.into()))
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §6.5 / §14.3 (journaled lot policy)",
        "select a debit-normal AnyUnit Asset posting leaf and a permitted registered lot law; a policy change needs two independent approvals over the exact proposal",
    )
}

/// Identity of the projection; an absent read witnesses first activation.
#[must_use]
pub fn policy_vid(book: Id128, account: VId) -> VId {
    let digest = domain_digest(
        b"fa:vid:lot-policy:v1",
        &[&book.0, &account.0.to_le_bytes()],
    );
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(id))
}

/// Append-only first-activation witness, independent of the mutable head.
#[must_use]
pub fn activation_vid(book: Id128, account: VId) -> VId {
    let digest = domain_digest(
        b"fa:vid:lot-policy-activation:v1",
        &[&book.0, &account.0.to_le_bytes()],
    );
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(id))
}

fn head_bytes(book: Id128, policy: &LotPolicy, entry: EntryRef) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.bytes(HEAD_FORMAT)
        .fixed(&book.0)
        .bytes(&policy.encode().map_err(fa_model::EntryError::from)?)
        .u128(entry.vid.0)
        .fixed(&entry.entry_digest);
    Ok(w.finish().map_err(fa_model::EntryError::from)?)
}

fn pointer(
    row: &VertexRow,
    book: Id128,
    account: VId,
    expected_vid: VId,
) -> Result<(LotPolicy, EntryRef), KernelError> {
    if row.vid != expected_vid || row.labels != [label::LOT_POLICY] {
        return Err(corrupt("projection identity or label differs"));
    }
    let raw = bytes(row, property::FA_PAYLOAD, "lot policy head")?;
    let mut r = Reader::new(&raw);
    let malformed = |e: fa_model::DecodeError| corrupt(e.to_string());
    if r.bytes(64, "lot_policy_head.format").map_err(malformed)? != HEAD_FORMAT
        || r.fixed::<16>("lot_policy_head.book").map_err(malformed)? != book.0
    {
        return Err(corrupt("projection framing or book differs"));
    }
    let policy = LotPolicy::decode(r.bytes(128, "lot_policy_head.policy").map_err(malformed)?)
        .map_err(malformed)?;
    let entry = EntryRef {
        vid: VId(r.u128("lot_policy_head.entry").map_err(malformed)?),
        entry_digest: r.fixed("lot_policy_head.entry_digest").map_err(malformed)?,
    };
    r.finish().map_err(malformed)?;
    if policy.account != account {
        return Err(corrupt("projection account differs"));
    }
    Ok((policy, entry))
}

fn from_control(row: &VertexRow, book: Id128) -> Result<Option<StoredLotPolicy>, KernelError> {
    if !row.labels.contains(&label::ENTRY) {
        return Ok(None);
    }
    let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "lot policy control")?)?;
    let Some(ControlPayload::SchemaChange {
        kind: SCHEMA_CHANGE_LOT_POLICY,
        canonical_bytes,
    }) = &entry.proposal.control
    else {
        return Ok(None);
    };
    if entry.proposal.class != EntryClass::SCHEMA_CONTROL
        || entry.proposal.book_id != book
        || entry.proposal.branch_id != Id128::TRUNK
        || !matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::CHART_INSTALL,
                ..
            }
        )
        || entry_mirrors(&entry)? != row.props
    {
        return Err(corrupt("immutable source control or mirrors differ"));
    }
    let policy = LotPolicy::decode(canonical_bytes).map_err(|e| corrupt(e.to_string()))?;
    Ok(Some(StoredLotPolicy {
        entry: EntryRef {
            vid: row.vid,
            entry_digest: entry.entry_digest,
        },
        policy,
        recorded_at: row.created_at,
    }))
}

/// Bounded current admission read, before any lot population is folded.
pub fn witness_policy<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    account: VId,
) -> Result<Option<StoredLotPolicy>, KernelError> {
    let row = txn.vertex(db, policy_vid(book.book_id, account))?;
    let activation = txn.vertex(db, activation_vid(book.book_id, account))?;
    let (Some(row), Some(activation)) = (&row, &activation) else {
        return if row.is_none() && activation.is_none() {
            Ok(None)
        } else {
            Err(corrupt(
                "activation marker and current head membership differ",
            ))
        };
    };
    let (first_policy, first_ref) = pointer(
        activation,
        book.book_id,
        account,
        activation_vid(book.book_id, account),
    )?;
    let first_row = txn
        .vertex(db, first_ref.vid)?
        .ok_or_else(|| corrupt("activation source is absent"))?;
    let first = from_control(&first_row, book.book_id)?
        .ok_or_else(|| corrupt("activation source is not a lot policy"))?;
    if first.entry != first_ref
        || first.policy != first_policy
        || activation.created_at != first.recorded_at
    {
        return Err(corrupt(
            "activation marker differs from its immutable source",
        ));
    }
    let (policy, expected) = pointer(
        row,
        book.book_id,
        account,
        policy_vid(book.book_id, account),
    )?;
    let source = txn
        .vertex(db, expected.vid)?
        .ok_or_else(|| corrupt("projection source is absent"))?;
    let stored = from_control(&source, book.book_id)?
        .ok_or_else(|| corrupt("projection source is not a lot policy"))?;
    if stored.entry != expected
        || stored.policy != policy
        || stored.recorded_at > txn.basis()
        || stored.recorded_at < first.recorded_at
        || row.created_at != stored.recorded_at
    {
        return Err(corrupt("projection differs from its immutable source"));
    }
    Ok(Some(stored))
}

/// Reconstruct the latest immutable policy at a selected recorded prefix.
/// A later control's effective date cannot replace an older selected policy.
pub fn policy_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: VId,
    known_at: CommitSeq,
) -> Result<Option<StoredLotPolicy>, KernelError> {
    if known_at > db.frontier()? {
        return Err(corrupt("selected prefix exceeds the head"));
    }
    let rows = db.vertices_at(known_at)?;
    let mut policies = Vec::new();
    for row in &rows {
        if let Some(policy) = from_control(row, book.book_id)?
            && policy.policy.account == account
        {
            policies.push(policy);
        }
    }
    let selected = policies.iter().max_by_key(|p| p.recorded_at).cloned();
    let head_vid = policy_vid(book.book_id, account);
    let first_vid = activation_vid(book.book_id, account);
    let relevant: Vec<_> = rows
        .into_iter()
        .filter(|row| row.vid == head_vid || row.vid == first_vid)
        .collect();
    verify_projection_records(book.book_id, &policies, &relevant)?;
    Ok(selected)
}

/// Verify both derived pointers against the complete immutable control prefix.
/// Deletion of both cannot hide a governed account during chart verification.
pub(super) fn verify_projection_records(
    book: Id128,
    controls: &[StoredLotPolicy],
    rows: &[VertexRow],
) -> Result<(), KernelError> {
    let mut histories: BTreeMap<VId, Vec<&StoredLotPolicy>> = BTreeMap::new();
    for control in controls {
        histories
            .entry(control.policy.account)
            .or_default()
            .push(control);
    }
    let by_vid: BTreeMap<_, _> = rows
        .iter()
        .filter(|row| row.labels.contains(&label::LOT_POLICY))
        .map(|row| (row.vid, row))
        .collect();
    let mut expected = BTreeSet::new();
    for (account, mut history) in histories {
        history.sort_by_key(|policy| policy.recorded_at);
        if history
            .windows(2)
            .any(|pair| pair[0].recorded_at == pair[1].recorded_at)
        {
            return Err(corrupt(
                "multiple policy controls for one account in a publication",
            ));
        }
        for (vid, source) in [
            (activation_vid(book, account), history[0]),
            (policy_vid(book, account), history[history.len() - 1]),
        ] {
            expected.insert(vid);
            let row = by_vid
                .get(&vid)
                .ok_or_else(|| corrupt("policy control lacks its activation marker or head"))?;
            let (policy, entry) = pointer(row, book, account, vid)?;
            if policy != source.policy
                || entry != source.entry
                || row.created_at != source.recorded_at
            {
                return Err(corrupt(
                    "historical projection differs from its selected control",
                ));
            }
        }
    }
    if rows
        .iter()
        .any(|row| row.labels.contains(&label::LOT_POLICY) && !expected.contains(&row.vid))
    {
        return Err(corrupt(
            "lot-policy projection has no immutable source history",
        ));
    }
    Ok(())
}

/// Pure proposal construction. Retain these exact bytes before asking for
/// approvals; resealing the description would change the approved digest.
pub fn lot_policy_proposal(
    book: &BookContext,
    principal: VId,
    policy: &LotPolicy,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    let mut proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_LOT_POLICY,
        policy.encode().map_err(fa_model::EntryError::from)?,
        principal,
        effective_date,
        idempotency_key,
        description,
    );
    proposal.schema_minor = fa_model::entry::LOT_DISPOSAL_SCHEMA_MINOR;
    proposal.canonical_bytes()?;
    Ok(proposal)
}

fn authorize<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    cap: &Capability,
    principal: VId,
) -> Outcome<()> {
    if let Err(d) = fa_policy::admit_read(cap, principal, book.book_id)
        .and_then(|()| fa_policy::reach(cap, &Reach::whole_book(true), None))
    {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    if let Err(r) = crate::policy::current_at(db, book, cap)? {
        return Ok(Err(r));
    }
    if let Some(r) = admit_schema_change(db, book, principal, cap)? {
        return Ok(Err(r));
    }
    Ok(Ok(()))
}

pub async fn set_lot_policy<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    request: LotPolicyRequest,
) -> Outcome<LotPolicyRecorded> {
    if let Err(r) = authorize(db, book, cap, request.principal)? {
        return Ok(Err(r));
    }
    let proposal = lot_policy_proposal(
        book,
        request.principal,
        &request.policy,
        request.effective_date,
        &request.idempotency_key,
        request.description,
    )?;
    set_lot_policy_proposal(db, cx, book, cap, proposal, request.approvals).await
}

/// Publish a new policy and its point-read projection in the same transaction.
/// First registration follows schema authority. Every subsequent declaration,
/// including a return to an old law, requires two current bound approvals.
pub async fn set_lot_policy_proposal<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    proposal: EntryPayload,
    approvals: Vec<ApprovalRef>,
) -> Outcome<LotPolicyRecorded> {
    if let Err(r) = authorize(db, book, cap, proposal.principal_ref)? {
        return Ok(Err(r));
    }
    let Some(ControlPayload::SchemaChange {
        kind: SCHEMA_CHANGE_LOT_POLICY,
        canonical_bytes,
    }) = &proposal.control
    else {
        return Ok(Err(invalid(
            "the reviewed proposal is not a lot-policy control",
        )));
    };
    let policy = LotPolicy::decode(canonical_bytes).map_err(|e| corrupt(e.to_string()))?;
    let expected = lot_policy_proposal(
        book,
        proposal.principal_ref,
        &policy,
        proposal.effective_date,
        &proposal.idempotency_key,
        proposal.description.clone(),
    )?;
    if proposal != expected {
        return Ok(Err(invalid(
            "the reviewed lot-policy proposal has altered structure",
        )));
    }
    if let Err(error) = policy.law.admit_for_regime(policy.regime) {
        return Ok(Err(invalid(error.to_string())));
    }
    if let Err(r) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(r));
    }
    let mut txn = db.begin(&cx.txn())?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, cap)? {
        txn.abort();
        return Ok(Err(r));
    }
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    let proposal_digest = proposal.proposal_digest()?;
    let vid = entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        let stored = from_control(&row, book.book_id)?
            .ok_or_else(|| corrupt("retry identity is not a lot policy"))?;
        let prior = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "lot policy retry")?)?;
        let same = prior.proposal_digest == proposal_digest
            || matches!(
            (prior.proposal.semantic_digest(&book.seal_key), proposal.semantic_digest(&book.seal_key)),
            (Ok(a), Ok(b)) if a == b);
        if !same || prior.approvals != approvals {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "lot-policy key already names different content or approvals",
                "FA-INV-09",
                "retry the exact retained proposal and approvals or choose a new key",
            )));
        }
        return Ok(Ok(LotPolicyRecorded {
            entry: stored.entry,
            policy: stored.policy,
            recorded_at: stored.recorded_at,
            already_recorded: true,
        }));
    }
    let Some(row) = txn.vertex(db, policy.account)? else {
        txn.abort();
        return Ok(Err(invalid("the selected lot account is absent")));
    };
    let account = AccountRow::decode(&row)?;
    if !row.labels.contains(&label::ACCOUNT)
        || account.account_type != AccountType::ASSET.0
        || !account.is_leaf
        || account.normal_balance != 0
        || account.unit_policy != UnitPolicy::AnyUnit
    {
        txn.abort();
        return Ok(Err(invalid(
            "lot policy requires a debit-normal AnyUnit Asset posting leaf",
        )));
    }
    let current = witness_policy(&txn, db, book, policy.account)?;
    // A declaration is rare and validates the complete source history. Normal
    // postings only pay the bounded point-read witness above.
    crate::entry_history::verify_entry_history(db, cx, book, Some(txn.basis()))?;
    if policy_at(db, book, policy.account, txn.basis())? != current {
        txn.abort();
        return Err(corrupt(
            "current policy witness differs from historical reconstruction",
        ));
    }
    let transition = if current.is_some() {
        "ChangeLotPolicy"
    } else {
        "ChartInstall"
    };
    let key = fa_policy::sod::control_key("SchemaControl", None, transition);
    if let Err(r) = crate::policy::authorize_approvals(
        &txn,
        db,
        book,
        &approvals,
        &proposal_digest,
        epoch,
        &key,
        0,
        fa_policy::Party::for_capability(proposal.principal_ref, cap),
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.seal(approvals, None)?;
    let entry_ref = EntryRef {
        vid,
        entry_digest: entry.entry_digest,
    };
    let pointer_vid = policy_vid(book.book_id, policy.account);
    let pointer = head_bytes(book.book_id, &policy, entry_ref)?;
    let old = txn.vertex_property(db, pointer_vid, property::FA_PAYLOAD)?;
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(vid, vec![label::ENTRY], entry_mirrors(&entry)?);
    if current.is_some() {
        batch.compare_and_set_vertex_property(
            pointer_vid,
            property::FA_PAYLOAD,
            old,
            scalar_bytes("lot policy head", pointer)?,
            WriteMismatchPolicy::AbortWrite,
        );
    } else {
        batch.create_vertex(
            activation_vid(book.book_id, policy.account),
            vec![label::LOT_POLICY],
            vec![(
                property::FA_PAYLOAD,
                scalar_bytes("lot policy activation", pointer.clone())?,
            )],
        );
        batch.create_vertex(
            pointer_vid,
            vec![label::LOT_POLICY],
            vec![(
                property::FA_PAYLOAD,
                scalar_bytes("lot policy head", pointer)?,
            )],
        );
    }
    txn.write(db, batch)?;
    if let Err(d) = fa_policy::current(cap, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&d)));
    }
    if db.frontier()? != txn.basis() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            "the journal moved after lot-policy validation",
            "FG-LAW-FCW-01",
            "recheck the lot policy and retry the reviewed proposal",
        )));
    }
    match txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(LotPolicyRecorded {
            entry: entry_ref,
            policy,
            recorded_at,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                detail,
                "FG-LAW-FCW-01",
                "recheck the lot policy and retry the reviewed proposal",
            )))
        }
        Err(error) => Err(error.into()),
    }
}
